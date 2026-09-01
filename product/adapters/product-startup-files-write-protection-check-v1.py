#!/usr/bin/env python3
# Read-only adapter SRC-0009: startup rc files and systemd .service unit files must not be other-writable.
import base64
import json
import re

SEMANTIC_CONTRACT_ID = "startup-files-write-protection-check-semantic-v1"
ADAPTER_ID = "product-startup-files-write-protection-check-v1"
ADAPTER_CONTRACT_VERSION = "product-startup-files-write-protection-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
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

_PY = 'import json, os, stat, subprocess, sys\n\nrc_roots = json.loads(sys.argv[1])\nunit_paths_override = json.loads(sys.argv[2])\nsystemd_analyze = sys.argv[3]\nexpected_mask = int(sys.argv[4], 8)\n\n\ndef emit_error(reason):\n    print("ERROR\\t" + reason)\n    raise SystemExit(0)\n\n\ndef state_lstat(path):\n    st = os.lstat(path)\n    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)\n\n\ndef state_stat(path):\n    st = os.stat(path, follow_symlinks=True)\n    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)\n\n\ndef dir_identity(path):\n    st = os.stat(path, follow_symlinks=True)\n    if not stat.S_ISDIR(st.st_mode):\n        emit_error("directory:invalid-type")\n    return (st.st_dev, st.st_ino)\n\n\ndef direct_names(root):\n    try:\n        names = []\n        with os.scandir(root) as it:\n            for ent in it:\n                names.append(ent.name)\n        names.sort(key=os.fsencode)\n        return tuple(names)\n    except Exception:\n        emit_error("directory:scan-failed")\n\n\ndef direct_service_names(root):\n    return tuple(x for x in direct_names(root) if x.endswith(".service"))\n\n\ndef resolve_candidate(path, service_role):\n    try:\n        first_l = state_lstat(path)\n    except Exception:\n        emit_error("target:lstat-failed")\n    mode_type = first_l[4]\n    if stat.S_ISDIR(mode_type):\n        if service_role:\n            emit_error("target:invalid-type")\n        return ("directory", None, first_l, None)\n    if stat.S_ISLNK(mode_type):\n        try:\n            target = os.path.realpath(path)\n        except Exception:\n            emit_error("target:resolve-failed")\n        if service_role and os.path.normpath(target) == "/dev/null":\n            try:\n                if state_lstat(path) != first_l:\n                    emit_error("target:changed-during-check")\n            except Exception:\n                emit_error("target:lstat-failed")\n            resolution_snapshots[path] = target\n            return ("masked", None, first_l, None)\n        try:\n            target_state = state_stat(target)\n        except Exception:\n            emit_error("target:stat-failed")\n        if not stat.S_ISREG(target_state[4]):\n            emit_error("target:invalid-type")\n        resolution_snapshots[path] = target\n        return ("regular", target, first_l, target_state)\n    if stat.S_ISREG(mode_type):\n        try:\n            target_state = state_stat(path)\n        except Exception:\n            emit_error("target:stat-failed")\n        return ("regular", path, first_l, target_state)\n    emit_error("target:invalid-type")\n\n\ndef read_unit_paths():\n    if unit_paths_override is not None:\n        if not isinstance(unit_paths_override, list) or any(not isinstance(x, str) for x in unit_paths_override):\n            emit_error("systemd:invalid-unit-paths")\n        return tuple(unit_paths_override), None\n    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}\n    try:\n        proc = subprocess.run([systemd_analyze, "unit-paths"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)\n    except Exception:\n        emit_error("systemd:execution-failed")\n    if proc.returncode != 0:\n        emit_error("systemd:execution-failed")\n    if proc.stderr:\n        emit_error("systemd:stderr-output")\n    if not proc.stdout:\n        emit_error("systemd:empty-output")\n    if b"\\x00" in proc.stdout or b"\\r" in proc.stdout:\n        emit_error("systemd:invalid-bytes")\n    try:\n        text = proc.stdout.decode("utf-8", errors="strict")\n    except UnicodeDecodeError:\n        emit_error("systemd:invalid-utf8")\n    paths = []\n    for line in text.splitlines():\n        if not line.startswith("/") or "\\x00" in line or "\\r" in line or "\\n" in line:\n            emit_error("systemd:invalid-path")\n        paths.append(line)\n    if not paths:\n        emit_error("systemd:empty-population")\n    return tuple(paths), proc.stdout\n\n\nunit_paths, unit_paths_raw = read_unit_paths()\ninitial_unit_paths = unit_paths\nroot_snapshots = {}\npop_snapshots = {}\nentry_snapshots = {}\ntarget_snapshots = {}\nresolution_snapshots = {}\nseen_root_ids = set()\nseen_target_ids = set()\n\nrc_roots_present = 0\nrc_roots_absent = 0\nrc_entries = 0\nrc_directories = 0\nrc_targets = 0\nservice_roots_present = 0\nservice_roots_absent = 0\nservice_root_aliases = 0\nservice_entries = 0\nservice_masked = 0\nservice_targets = 0\nchecked = 0\nviolations = 0\n\n\ndef remember_root_state(logical, resolved):\n    try:\n        root_snapshots[logical] = (os.path.lexists(logical), state_lstat(logical) if os.path.lexists(logical) else None, resolved, state_stat(resolved))\n    except Exception:\n        emit_error("root:snapshot-failed")\n\n\ndef remember_population(resolved, names, service_only):\n    pop_snapshots[resolved] = (names, service_only)\n\n\ndef check_target(path, entry_path, entry_state, target_state, role):\n    global checked, violations, rc_targets, service_targets\n    ident = (target_state[0], target_state[1])\n    if role == "rc":\n        rc_targets += 1\n    else:\n        service_targets += 1\n    entry_snapshots[entry_path] = entry_state\n    target_snapshots[path] = target_state\n    if ident in seen_target_ids:\n        return\n    seen_target_ids.add(ident)\n    checked += 1\n    if target_state[5] & expected_mask:\n        violations += 1\n\n\n# /etc/rc0.d ... /etc/rc6.d: direct file-like entries only; rcS.d is intentionally not in this population.\nfor logical in rc_roots:\n    if not isinstance(logical, str) or not logical.startswith("/"):\n        emit_error("root:invalid-path")\n    exists = os.path.lexists(logical)\n    if not exists:\n        rc_roots_absent += 1\n        root_snapshots[logical] = (False, None, None, None)\n        continue\n    try:\n        resolved = os.path.realpath(logical)\n        ident = dir_identity(resolved)\n    except Exception:\n        emit_error("root:resolve-failed")\n    rc_roots_present += 1\n    names = direct_names(resolved)\n    remember_root_state(logical, resolved)\n    remember_population(resolved, names, False)\n    # rc roots are fixed distinct runlevel directories; aliasing two roots would make the source population ambiguous.\n    if ident in seen_root_ids:\n        emit_error("root:ambiguous-alias")\n    seen_root_ids.add(ident)\n    for name in names:\n        path = os.path.join(resolved, name)\n        kind, target, entry_state, target_state = resolve_candidate(path, False)\n        if kind == "directory":\n            rc_directories += 1\n            continue\n        rc_entries += 1\n        check_target(target, path, entry_state, target_state, "rc")\n\n# systemd unit load paths: scan only direct *.service entries. Dependency directories are references, not extra unit-file population.\nfor logical in unit_paths:\n    if not isinstance(logical, str) or not logical.startswith("/"):\n        emit_error("systemd:invalid-path")\n    if not os.path.lexists(logical):\n        service_roots_absent += 1\n        root_snapshots.setdefault(logical, (False, None, None, None))\n        continue\n    try:\n        resolved = os.path.realpath(logical)\n        ident = dir_identity(resolved)\n    except Exception:\n        emit_error("root:resolve-failed")\n    service_roots_present += 1\n    remember_root_state(logical, resolved)\n    if ident in seen_root_ids:\n        service_root_aliases += 1\n        continue\n    seen_root_ids.add(ident)\n    names = direct_service_names(resolved)\n    remember_population(resolved, names, True)\n    for name in names:\n        service_entries += 1\n        path = os.path.join(resolved, name)\n        kind, target, entry_state, target_state = resolve_candidate(path, True)\n        if kind == "masked":\n            service_masked += 1\n            entry_snapshots[path] = entry_state\n            continue\n        check_target(target, path, entry_state, target_state, "service")\n\n# A fully observed empty .service population is vacuously compliant; discovery failures above are ERROR.\n\n# End-of-observation stability: unit-path authority, roots, direct populations, entries and final targets must be unchanged.\nif unit_paths_override is None:\n    final_paths, final_raw = read_unit_paths()\n    if final_paths != initial_unit_paths or final_raw != unit_paths_raw:\n        emit_error("observation:unit-paths-changed")\n\nfor logical, snap in root_snapshots.items():\n    was_present, logical_state, resolved, resolved_state = snap\n    if not was_present:\n        if os.path.lexists(logical):\n            emit_error("observation:root-changed")\n        continue\n    try:\n        if not os.path.lexists(logical) or state_lstat(logical) != logical_state or os.path.realpath(logical) != resolved or state_stat(resolved) != resolved_state:\n            emit_error("observation:root-changed")\n    except Exception:\n        emit_error("observation:root-unreadable")\n\nfor resolved, snap in pop_snapshots.items():\n    names, service_only = snap\n    current = direct_service_names(resolved) if service_only else direct_names(resolved)\n    if current != names:\n        emit_error("observation:population-changed")\n\nfor path, snap in entry_snapshots.items():\n    try:\n        if state_lstat(path) != snap:\n            emit_error("observation:entry-changed")\n    except Exception:\n        emit_error("observation:entry-unreadable")\nfor path, resolved in resolution_snapshots.items():\n    try:\n        if os.path.realpath(path) != resolved:\n            emit_error("observation:resolution-changed")\n    except Exception:\n        emit_error("observation:resolution-failed")\nfor path, snap in target_snapshots.items():\n    try:\n        if state_stat(path) != snap:\n            emit_error("observation:target-changed")\n    except Exception:\n        emit_error("observation:target-unreadable")\n\nvalue = (\n    f"rc_roots_present={rc_roots_present};rc_roots_absent={rc_roots_absent};rc_entries={rc_entries};"\n    f"rc_directories={rc_directories};rc_targets={rc_targets};service_roots_present={service_roots_present};"\n    f"service_roots_absent={service_roots_absent};service_root_aliases={service_root_aliases};"\n    f"service_entries={service_entries};service_masked={service_masked};service_targets={service_targets};"\n    f"checked={checked};violations={violations}"\n)\nprint("VALUE\\t" + value + "\\t" + ("PASS" if violations == 0 else "FAIL"))\n'


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
        "  ) || { printf \"%s\\t%s\\tERROR\\tobserver:execution-failed\\tERROR\\n\" " + _sh_single(WIRE_RECORD_ID) + " " + cid + "; return 0; }",
        "  if [[ $_slp_obs == ERROR$'\t'* ]]; then",
        "    printf \"%s\\t%s\\tERROR\\t%s\\tERROR\\n\" " + _sh_single(WIRE_RECORD_ID) + " " + cid + " \"${_slp_obs#*$\'\\t\'}\"",
        "    return 0",
        "  fi",
        "  IFS=$'\\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<<\"$_slp_obs\"",
        "  if [[ $_slp_status != VALUE || -n $_slp_extra || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) ]]; then",
        "    printf \"%s\\t%s\\tERROR\\tobserver:invalid-output\\tERROR\\n\" " + _sh_single(WIRE_RECORD_ID) + " " + cid,
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
