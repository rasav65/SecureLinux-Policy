#!/usr/bin/env python3
# Read-only adapter SRC-0009: startup rc files and systemd .service unit files must not be other-writable.
import base64
import json
import re

SEMANTIC_CONTRACT_ID = "startup-files-write-protection-check-semantic-v1"
ADAPTER_ID = "product-startup-files-write-protection-check-v1"
ADAPTER_CONTRACT_VERSION = "product-startup-files-write-protection-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "startup-files-write-protection"
SUPPORTED_OPS = ("bits-clear",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/etc/rc[0-6].d|systemd-unit-paths"
CANONICAL_KEY = "other-write"
CANONICAL_OP = "bits-clear"
CANONICAL_EXPECTED = "0002"
CANONICAL_RC_ROOTS = tuple(f"/etc/rc{i}.d" for i in range(7))
DEFAULT_SYSTEMD_ANALYZE = "/usr/bin/systemd-analyze"

_PY = r'''import json, os, stat, subprocess, sys

rc_roots = json.loads(sys.argv[1])
unit_paths_override = json.loads(sys.argv[2])
systemd_analyze = sys.argv[3]
expected_mask = int(sys.argv[4], 8)


def emit_error():
    print("ERROR")
    raise SystemExit(0)


def state_lstat(path):
    st = os.lstat(path)
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def state_stat(path):
    st = os.stat(path, follow_symlinks=True)
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def dir_identity(path):
    st = os.stat(path, follow_symlinks=True)
    if not stat.S_ISDIR(st.st_mode):
        emit_error()
    return (st.st_dev, st.st_ino)


def direct_names(root):
    try:
        names = []
        with os.scandir(root) as it:
            for ent in it:
                names.append(ent.name)
        names.sort(key=os.fsencode)
        return tuple(names)
    except Exception:
        emit_error()


def direct_service_names(root):
    return tuple(x for x in direct_names(root) if x.endswith(".service"))


def resolve_candidate(path, service_role):
    try:
        first_l = state_lstat(path)
    except Exception:
        emit_error()
    mode_type = first_l[4]
    if stat.S_ISDIR(mode_type):
        if service_role:
            emit_error()
        return ("directory", None, first_l, None)
    if stat.S_ISLNK(mode_type):
        try:
            target = os.path.realpath(path)
        except Exception:
            emit_error()
        if service_role and os.path.normpath(target) == "/dev/null":
            try:
                if state_lstat(path) != first_l:
                    emit_error()
            except Exception:
                emit_error()
            resolution_snapshots[path] = target
            return ("masked", None, first_l, None)
        try:
            target_state = state_stat(target)
        except Exception:
            emit_error()
        if not stat.S_ISREG(target_state[4]):
            emit_error()
        resolution_snapshots[path] = target
        return ("regular", target, first_l, target_state)
    if stat.S_ISREG(mode_type):
        try:
            target_state = state_stat(path)
        except Exception:
            emit_error()
        return ("regular", path, first_l, target_state)
    emit_error()


def read_unit_paths():
    if unit_paths_override is not None:
        if not isinstance(unit_paths_override, list) or any(not isinstance(x, str) for x in unit_paths_override):
            emit_error()
        return tuple(unit_paths_override), None
    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        proc = subprocess.run([systemd_analyze, "unit-paths"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    except Exception:
        emit_error()
    if proc.returncode != 0 or proc.stderr or not proc.stdout or b"\x00" in proc.stdout or b"\r" in proc.stdout:
        emit_error()
    try:
        text = proc.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        emit_error()
    paths = []
    for line in text.splitlines():
        if not line.startswith("/") or "\x00" in line or "\r" in line or "\n" in line:
            emit_error()
        paths.append(line)
    if not paths:
        emit_error()
    return tuple(paths), proc.stdout


unit_paths, unit_paths_raw = read_unit_paths()
initial_unit_paths = unit_paths
root_snapshots = {}
pop_snapshots = {}
entry_snapshots = {}
target_snapshots = {}
resolution_snapshots = {}
seen_root_ids = set()
seen_target_ids = set()

rc_roots_present = 0
rc_roots_absent = 0
rc_entries = 0
rc_directories = 0
rc_targets = 0
service_roots_present = 0
service_roots_absent = 0
service_root_aliases = 0
service_entries = 0
service_masked = 0
service_targets = 0
checked = 0
violations = 0


def remember_root_state(logical, resolved):
    try:
        root_snapshots[logical] = (os.path.lexists(logical), state_lstat(logical) if os.path.lexists(logical) else None, resolved, state_stat(resolved))
    except Exception:
        emit_error()


def remember_population(resolved, names, service_only):
    pop_snapshots[resolved] = (names, service_only)


def check_target(path, entry_path, entry_state, target_state, role):
    global checked, violations, rc_targets, service_targets
    ident = (target_state[0], target_state[1])
    if role == "rc":
        rc_targets += 1
    else:
        service_targets += 1
    entry_snapshots[entry_path] = entry_state
    target_snapshots[path] = target_state
    if ident in seen_target_ids:
        return
    seen_target_ids.add(ident)
    checked += 1
    if target_state[5] & expected_mask:
        violations += 1


# /etc/rc0.d ... /etc/rc6.d: direct file-like entries only; rcS.d is intentionally not in this population.
for logical in rc_roots:
    if not isinstance(logical, str) or not logical.startswith("/"):
        emit_error()
    exists = os.path.lexists(logical)
    if not exists:
        rc_roots_absent += 1
        root_snapshots[logical] = (False, None, None, None)
        continue
    try:
        resolved = os.path.realpath(logical)
        ident = dir_identity(resolved)
    except Exception:
        emit_error()
    rc_roots_present += 1
    names = direct_names(resolved)
    remember_root_state(logical, resolved)
    remember_population(resolved, names, False)
    # rc roots are fixed distinct runlevel directories; aliasing two roots would make the source population ambiguous.
    if ident in seen_root_ids:
        emit_error()
    seen_root_ids.add(ident)
    for name in names:
        path = os.path.join(resolved, name)
        kind, target, entry_state, target_state = resolve_candidate(path, False)
        if kind == "directory":
            rc_directories += 1
            continue
        rc_entries += 1
        check_target(target, path, entry_state, target_state, "rc")

# systemd unit load paths: scan only direct *.service entries. Dependency directories are references, not extra unit-file population.
for logical in unit_paths:
    if not isinstance(logical, str) or not logical.startswith("/"):
        emit_error()
    if not os.path.lexists(logical):
        service_roots_absent += 1
        root_snapshots.setdefault(logical, (False, None, None, None))
        continue
    try:
        resolved = os.path.realpath(logical)
        ident = dir_identity(resolved)
    except Exception:
        emit_error()
    service_roots_present += 1
    remember_root_state(logical, resolved)
    if ident in seen_root_ids:
        service_root_aliases += 1
        continue
    seen_root_ids.add(ident)
    names = direct_service_names(resolved)
    remember_population(resolved, names, True)
    for name in names:
        service_entries += 1
        path = os.path.join(resolved, name)
        kind, target, entry_state, target_state = resolve_candidate(path, True)
        if kind == "masked":
            service_masked += 1
            entry_snapshots[path] = entry_state
            continue
        check_target(target, path, entry_state, target_state, "service")

# A fully observed empty .service population is vacuously compliant; discovery failures above are ERROR.

# End-of-observation stability: unit-path authority, roots, direct populations, entries and final targets must be unchanged.
if unit_paths_override is None:
    final_paths, final_raw = read_unit_paths()
    if final_paths != initial_unit_paths or final_raw != unit_paths_raw:
        emit_error()

for logical, snap in root_snapshots.items():
    was_present, logical_state, resolved, resolved_state = snap
    if not was_present:
        if os.path.lexists(logical):
            emit_error()
        continue
    try:
        if not os.path.lexists(logical) or state_lstat(logical) != logical_state or os.path.realpath(logical) != resolved or state_stat(resolved) != resolved_state:
            emit_error()
    except Exception:
        emit_error()

for resolved, snap in pop_snapshots.items():
    names, service_only = snap
    current = direct_service_names(resolved) if service_only else direct_names(resolved)
    if current != names:
        emit_error()

for path, snap in entry_snapshots.items():
    try:
        if state_lstat(path) != snap:
            emit_error()
    except Exception:
        emit_error()
for path, resolved in resolution_snapshots.items():
    try:
        if os.path.realpath(path) != resolved:
            emit_error()
    except Exception:
        emit_error()
for path, snap in target_snapshots.items():
    try:
        if state_stat(path) != snap:
            emit_error()
    except Exception:
        emit_error()

value = (
    f"rc_roots_present={rc_roots_present};rc_roots_absent={rc_roots_absent};rc_entries={rc_entries};"
    f"rc_directories={rc_directories};rc_targets={rc_targets};service_roots_present={service_roots_present};"
    f"service_roots_absent={service_roots_absent};service_root_aliases={service_root_aliases};"
    f"service_entries={service_entries};service_masked={service_masked};service_targets={service_targets};"
    f"checked={checked};violations={violations}"
)
print("VALUE\t" + value + "\t" + ("PASS" if violations == 0 else "FAIL"))
'''


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, rc_roots, unit_paths_override, systemd_analyze, expected):
    args = " ".join([
        _sh_single(json.dumps(list(rc_roots), ensure_ascii=True, separators=(",", ":"))),
        _sh_single(json.dumps(None if unit_paths_override is None else list(unit_paths_override), ensure_ascii=True, separators=(",", ":"))),
        _sh_single(systemd_analyze),
        _sh_single(expected),
    ])
    cid = _sh_single(control_id)
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    return "\n".join([
        fn + "() {",
        "  local _slp_obs _slp_status _slp_value _slp_compliance _slp_extra",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - " + args + " <<'SLP_STARTUP_FILES_PY'",
        _PY,
        "SLP_STARTUP_FILES_PY",
        "  ) || { printf \"%s\\t%s\\tERROR\\t-\\tERROR\\n\" " + _sh_single(WIRE_RECORD_ID) + " " + cid + "; return 0; }",
        "  if [[ $_slp_obs == ERROR ]]; then",
        "    printf \"%s\\t%s\\tERROR\\t-\\tERROR\\n\" " + _sh_single(WIRE_RECORD_ID) + " " + cid,
        "    return 0",
        "  fi",
        "  IFS=$'\\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<<\"$_slp_obs\"",
        "  if [[ $_slp_status != VALUE || -n $_slp_extra || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) ]]; then",
        "    printf \"%s\\t%s\\tERROR\\t-\\tERROR\\n\" " + _sh_single(WIRE_RECORD_ID) + " " + cid,
        "    return 0",
        "  fi",
        "  printf \"%s\\t%s\\tVALUE\\t%s\\t%s\\n\" " + _sh_single(WIRE_RECORD_ID) + " " + cid + " \"$_slp_value\" \"$_slp_compliance\"",
        "  return 0",
        "}",
        "",
    ])


def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if locator != CANONICAL_LOCATOR or key != CANONICAL_KEY or op != CANONICAL_OP or expected != CANONICAL_EXPECTED:
        raise ValueError("only canonical SRC-0009 startup-files contract is supported")
    return _render(control_id, CANONICAL_RC_ROOTS, None, DEFAULT_SYSTEMD_ANALYZE, expected)


def _shell_function_for_layout(control_id, rc_roots, unit_paths, expected=CANONICAL_EXPECTED):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    roots = tuple(rc_roots) + tuple(unit_paths)
    if any(not isinstance(x, str) or not x.startswith("/") for x in roots):
        raise ValueError("absolute test roots required")
    return _render(control_id, tuple(rc_roots), tuple(unit_paths), DEFAULT_SYSTEMD_ANALYZE, expected)


MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ", "chgrp ",
    "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)


def _selftest():
    src = shell_function("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED)
    assert "command /usr/bin/python3 -I -S -B" in src
    assert "systemd-analyze" in src and "unit-paths" in src
    assert "/etc/rc0.d" in src and "/etc/rc6.d" in src and "/etc/rcS.d" not in src
    assert "service_masked=" in src and "violations=" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    bad = (
        ("CTRL", "/etc/rc#.d", CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, "mode", CANONICAL_OP, CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "eq", CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, "0003"),
    )
    for args in bad:
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
