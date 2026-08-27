#!/usr/bin/env python3
# Read-only adapter SRC-0008: sudo-root command files must be root-owned and not group/other writable.
import re

SEMANTIC_CONTRACT_ID = "sudo-root-command-files-protection-check-semantic-v1"
ADAPTER_ID = "product-sudo-root-command-files-protection-check-v1"
ADAPTER_CONTRACT_VERSION = "product-sudo-root-command-files-protection-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "sudo-root-command-files-protection"
SUPPORTED_OPS = ("root-owned-go-w",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/etc/sudoers|/etc/securelinux-policy/sudoers-reviewed-policy-v1"
CANONICAL_KEY = "root-command-files"
CANONICAL_OP = "root-owned-go-w"
CANONICAL_EXPECTED = "uid0;bits-clear-0022"
DEFAULT_VISUDO = "/usr/sbin/visudo"
DEFAULT_CVTSUDOERS = "/usr/bin/cvtsudoers"
DEFAULT_REVIEWED_AUTHORITY = "/etc/securelinux-policy/sudoers-reviewed-policy-v1"

_PY = r'''import hashlib, json, os, re, stat, subprocess, sys
from pathlib import Path

fsroot = Path(sys.argv[1])
logical_root_uid = int(sys.argv[2], 10)
sudoers_path = Path(sys.argv[3])
authority_path = Path(sys.argv[4])
visudo_path = sys.argv[5]
cvtsudoers_path = sys.argv[6]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_COMMAND_KEYS = {"command", "negated", "sha224", "sha256", "sha384", "sha512"}
WILDCARD_CHARS = set("*?[")
EXECUTION_FRONTENDS = {
    "env", "nice", "nohup", "timeout", "sudo", "su", "runuser", "chroot", "xargs", "find",
    "flock", "setsid", "stdbuf", "taskset", "ionice", "systemd-run", "start-stop-daemon",
    "busybox", "toybox", "time", "setpriv", "unshare", "nsenter", "prlimit", "setarch",
    "linux32", "linux64", "chrt", "watch", "strace", "ltrace", "gdb", "valgrind", "perf",
    "script", "daemon", "daemonize", "parallel", "numactl", "capsh", "firejail", "bwrap",
    "fakeroot", "torsocks", "proxychains", "proxychains4", "eatmydata", "sg", "newgrp",
    "docker", "podman", "systemd-nspawn", "machinectl", "run-parts",
}
INTERPRETER_NAME = re.compile(
    r"^(?:sh|ash|bash|dash|ksh|mksh|zsh|python(?:[0-9]+(?:\.[0-9]+)*)?|"
    r"perl(?:[0-9.]+)?|ruby(?:[0-9.]+)?|node(?:js)?(?:[0-9.]+)?|php(?:[0-9.]+)?|"
    r"lua(?:[0-9.]+)?|tclsh(?:[0-9.]+)?|wish(?:[0-9.]+)?|java|javaw|dotnet|mono|Rscript)$"
)


def error():
    print("ERROR")
    raise SystemExit(0)


def obj_state(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)


def stable_regular_bytes(path):
    try:
        first = os.lstat(path)
    except Exception:
        error()
    if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):
        error()
    try:
        raw = path.read_bytes()
        second = os.lstat(path)
    except Exception:
        error()
    if obj_state(first) != obj_state(second):
        error()
    return obj_state(first), raw


def parse_authority(raw):
    if not raw.endswith(b"\n") or b"\x00" in raw or b"\r" in raw:
        error()
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error()
    lines = text.splitlines()
    if not lines or lines[0] != "SLP-SUDOERS-REVIEWED-POLICY-V1":
        error()
    out = {}
    for line in lines[1:]:
        if not line or line.count("\t") != 1:
            error()
        digest, path = line.split("\t", 1)
        if HEX64.fullmatch(digest) is None or not path.startswith("/") or any(c in path for c in "\x00\r\n\t") or path in out:
            error()
        out[path] = digest
    if not out or str(sudoers_path) not in out:
        error()
    return out


def policy_snapshot():
    authority_state, authority_raw = stable_regular_bytes(authority_path)
    approved = parse_authority(authority_raw)
    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        proc = subprocess.run([visudo_path, "-c", "-f", str(sudoers_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, check=False)
    except Exception:
        error()
    if proc.returncode != 0 or not proc.stdout or b"\x00" in proc.stdout or b"\r" in proc.stdout:
        error()
    try:
        text = proc.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error()
    actual = {}
    states = {}
    for line in text.splitlines():
        suffix = ": parsed OK"
        if not line.endswith(suffix):
            error()
        path_text = line[:-len(suffix)]
        if not path_text.startswith("/") or any(c in path_text for c in "\x00\r\n\t") or path_text in actual:
            error()
        path = Path(path_text)
        state, raw = stable_regular_bytes(path)
        actual[path_text] = hashlib.sha256(raw).hexdigest()
        states[path_text] = state
    if not actual or str(sudoers_path) not in actual or actual != approved:
        error()
    return (authority_state, hashlib.sha256(authority_raw).hexdigest(), tuple(sorted(actual.items())), tuple(sorted(states.items())))


def cvt_snapshot():
    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        proc = subprocess.run(
            [cvtsudoers_path, "-c", "/dev/null", "-e", "-s", "aliases", "-f", "json", str(sudoers_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False,
        )
    except Exception:
        error()
    if proc.returncode != 0 or proc.stderr or not proc.stdout or b"\x00" in proc.stdout:
        error()
    try:
        data = json.loads(proc.stdout.decode("utf-8", errors="strict"))
    except Exception:
        error()
    if not isinstance(data, dict) or set(data) - {"Defaults", "User_Specs"}:
        error()
    defaults = data.get("Defaults", [])
    specs = data.get("User_Specs", [])
    if not isinstance(defaults, list) or not isinstance(specs, list):
        error()
    return proc.stdout, defaults, specs


def reject_enabled_runchroot_options(options):
    if options is None:
        return
    if not isinstance(options, list):
        error()
    for obj in options:
        if not isinstance(obj, dict):
            error()
        if "runchroot" in obj:
            if set(obj) != {"runchroot"}:
                error()
            value = obj["runchroot"]
            if value is False:
                continue
            error()


def validate_defaults(defaults):
    for entry in defaults:
        if not isinstance(entry, dict) or set(entry) - {"Binding", "Options"} or "Options" not in entry:
            error()
        binding = entry.get("Binding")
        if binding is not None and (not isinstance(binding, list) or not binding):
            error()
        options = entry["Options"]
        reject_enabled_runchroot_options(options)
        if not isinstance(options, list):
            error()
        for obj in options:
            if not isinstance(obj, dict):
                error()
            # sudoers runas_default changes the effective target user whenever a
            # Cmnd_Spec omits an explicit Runas_Spec.  v1 does not evaluate
            # Defaults binding precedence, so accepting such a policy could
            # classify a non-root command as root-runnable and false-FAIL its file.
            if "runas_default" in obj or "case_insensitive_user" in obj:
                error()


def one_selector(obj, allowed):
    if not isinstance(obj, dict) or set(obj) - (allowed | {"negated"}):
        error()
    keys = [k for k in obj if k != "negated"]
    if len(keys) != 1 or not isinstance(obj.get("negated", False), bool):
        error()
    return keys[0], obj[keys[0]], obj.get("negated", False)


def ordinary_invoker_possible(user_list):
    if not isinstance(user_list, list) or not user_list:
        error()
    ordinary = False
    allowed = {"netgroup", "nonunixgid", "nonunixgroup", "usergid", "usergroup", "userid", "username"}
    for obj in user_list:
        key, value, neg = one_selector(obj, allowed)
        # Membership- and negation-dependent selectors cannot be over-approximated
        # into a VALUE/FAIL population without risking a false FAIL.
        if neg or key not in {"username", "userid"}:
            error()
        if key == "username":
            if not isinstance(value, str) or not value:
                error()
            if value.casefold() == "root":
                continue
            ordinary = True
            continue
        text = str(value)
        if not text.isdigit():
            error()
        if int(text, 10) != 0:
            ordinary = True
    return ordinary


def host_scope_supported(host_list):
    if not isinstance(host_list, list) or not host_list:
        error()
    # v1 deliberately supports only an unconditional ALL host selector.  Correct
    # sudo hostname/network/netgroup matching depends on local host/network state;
    # treating a non-ALL selector as applicable would over-check another host and
    # could return a false FAIL.  Unsupported host qualification is therefore ERROR.
    if len(host_list) != 1:
        error()
    key, value, neg = one_selector(host_list[0], {"hostname", "networkaddr", "netgroup"})
    if neg or key != "hostname" or value != "ALL":
        error()
    return True


def root_runas_possible(spec):
    if "runasusers" not in spec:
        return True
    runas = spec["runasusers"]
    if not isinstance(runas, list) or not runas:
        error()
    allowed = {"netgroup", "nonunixgid", "nonunixgroup", "runasalias", "usergid", "usergroup", "userid", "username"}
    root_possible = False
    for obj in runas:
        key, value, neg = one_selector(obj, allowed)
        # Group/netgroup membership and negated runas selectors are not resolved by
        # this adapter.  Do not over-approximate them into a FAIL-able population.
        if neg or key not in {"username", "userid"}:
            error()
        if key == "username":
            if not isinstance(value, str) or not value:
                error()
            if value == "ALL" or value.casefold() == "root":
                root_possible = True
            continue
        text = str(value)
        if not text.isdigit():
            error()
        if int(text, 10) == 0:
            root_possible = True
    return root_possible


def path_shape_ok(path):
    if not path.startswith("/") or path.endswith("/") or "\\" in path or any(c in path for c in WILDCARD_CHARS):
        return False
    parts = path.split("/")
    return not any(part in {".", ".."} for part in parts)


def executable_candidate(logical):
    if not path_shape_ok(logical):
        return False
    path = map_target(logical)
    try:
        st = os.stat(path, follow_symlinks=True)
    except FileNotFoundError:
        return False
    except Exception:
        error()
    return stat.S_ISREG(st.st_mode) and (stat.S_IMODE(st.st_mode) & 0o111) != 0


def logical_target(command):
    if not isinstance(command, str) or not command or any(c in command for c in "\x00\r\n"):
        error()
    if command == "sudoedit" or command.startswith("sudoedit "):
        return None
    if command == "ALL" or command.startswith("^"):
        error()
    if not command.startswith("/"):
        error()

    # cvtsudoers JSON returns command path and arguments in one string and
    # unescapes whitespace inside a pathname.  Never split at the first blank:
    # enumerate every whitespace boundary plus the full string and accept only
    # one existing executable path prefix.  Zero or multiple candidates are
    # ambiguous and therefore ERROR.
    candidates = []
    boundaries = [i for i, ch in enumerate(command) if ch.isspace()] + [len(command)]
    for end in boundaries:
        candidate = command[:end]
        if candidate and executable_candidate(candidate):
            candidates.append(candidate)
    candidates = sorted(set(candidates), key=os.fsencode)
    if len(candidates) != 1:
        error()
    return candidates[0]


def collect_targets(specs):
    targets = set()
    for user_spec in specs:
        if not isinstance(user_spec, dict) or set(user_spec) != {"User_List", "Host_List", "Cmnd_Specs"}:
            error()
        if not ordinary_invoker_possible(user_spec["User_List"]):
            continue
        host_scope_supported(user_spec["Host_List"])
        cmnd_specs = user_spec["Cmnd_Specs"]
        if not isinstance(cmnd_specs, list):
            error()
        for spec in cmnd_specs:
            if not isinstance(spec, dict) or "Commands" not in spec or set(spec) - {"Commands", "runasusers", "runasgroups", "Options"}:
                error()
            options = spec.get("Options")
            reject_enabled_runchroot_options(options)
            if options is not None:
                if not isinstance(options, list):
                    error()
                for obj in options:
                    if not isinstance(obj, dict):
                        error()
                    # NOTBEFORE/NOTAFTER are direct applicability predicates.
                    # v1 does not evaluate sudo generalized-time windows, so an
                    # inactive rule must never be over-checked into VALUE/FAIL.
                    if "notbefore" in obj or "notafter" in obj:
                        error()
            if not root_runas_possible(spec):
                continue
            commands = spec["Commands"]
            if not isinstance(commands, list) or not commands:
                error()
            for obj in commands:
                if not isinstance(obj, dict) or set(obj) - ALLOWED_COMMAND_KEYS:
                    error()
                if "command" not in obj or not isinstance(obj.get("negated", False), bool):
                    error()
                if any(key in obj for key in ("sha224", "sha256", "sha384", "sha512")):
                    # A sudo command digest is an applicability predicate.  v1 does
                    # not reimplement sudo digest syntax/matching, so including the
                    # pathname regardless of digest could over-check a command that
                    # is not runnable with the current bytes.
                    error()
                if obj.get("negated", False):
                    # Correct command-list override semantics are not reimplemented
                    # here; silently dropping a negation can over-check a target.
                    error()
                target = logical_target(obj["command"])
                if target is not None:
                    targets.add(target)
    return tuple(sorted(targets, key=os.fsencode))


def map_target(logical):
    return fsroot / logical.lstrip("/")


def stable_target(logical):
    path = map_target(logical)
    try:
        link_first = os.lstat(path)
        target_first = os.stat(path, follow_symlinks=True)
        resolved = os.path.realpath(path)
        link_second = os.lstat(path)
        target_second = os.stat(path, follow_symlinks=True)
    except Exception:
        error()
    if obj_state(link_first) != obj_state(link_second) or obj_state(target_first) != obj_state(target_second):
        error()
    if not stat.S_ISREG(target_first.st_mode) or (stat.S_IMODE(target_first.st_mode) & 0o111) == 0:
        error()
    if fsroot != Path("/"):
        try:
            Path(resolved).relative_to(fsroot.resolve())
        except Exception:
            error()
    canonical_base = Path(resolved).name
    if target_first.st_nlink != 1 or canonical_base in EXECUTION_FRONTENDS or INTERPRETER_NAME.fullmatch(canonical_base) is not None:
        error()
    # A shebang script delegates privileged execution to another executable.
    # This v1 checker intentionally does not model recursive interpreter chains;
    # fail closed rather than returning PASS after checking only the script inode.
    fd = None
    try:
        fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        fd_state = os.fstat(fd)
        prefix = os.read(fd, 2)
    except Exception:
        error()
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                error()
    if obj_state(fd_state) != obj_state(target_first) or prefix == b"#!":
        error()
    return (logical, resolved, obj_state(link_first), obj_state(target_first))


policy_before = policy_snapshot()
cvt_before, defaults, specs = cvt_snapshot()
validate_defaults(defaults)
targets = collect_targets(specs)
records = {logical: stable_target(logical) for logical in targets}
owner_bad = 0
mode_bad = 0
for rec in records.values():
    state = rec[3]
    if state[2] != logical_root_uid:
        owner_bad += 1
    if state[4] & 0o022:
        mode_bad += 1
policy_after = policy_snapshot()
cvt_after, defaults_after, specs_after = cvt_snapshot()
validate_defaults(defaults_after)
if policy_after != policy_before or cvt_after != cvt_before or collect_targets(specs_after) != targets:
    error()
for logical, before in records.items():
    if stable_target(logical) != before:
        error()
print(f"VALUE\tfiles={len(targets)};owner_violations={owner_bad};mode_violations={mode_bad}\t" + ("PASS" if owner_bad == 0 and mode_bad == 0 else "FAIL"))
'''


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _fn_name(control_id):
    return "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)


def _render(control_id, fsroot, logical_root_uid, sudoers_path, authority_path, visudo_path, cvtsudoers_path):
    fn = _fn_name(control_id)
    args = " ".join(_sh_single(str(x)) for x in (fsroot, logical_root_uid, sudoers_path, authority_path, visudo_path, cvtsudoers_path))
    return "\n".join([
        f"{fn}() {{",
        f"  local _slp_cid={_sh_single(control_id)} _slp_obs _slp_rc _slp_kind _slp_value _slp_compliance _slp_extra",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - " + args + " <<'SLP_SUDO_ROOT_FILES_PY'",
        _PY,
        "SLP_SUDO_ROOT_FILES_PY",
        "  )",
        "  _slp_rc=$?",
        "  if (( _slp_rc != 0 )); then printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"; return 0; fi",
        "  if [[ \"$_slp_obs\" == ERROR ]]; then printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"; return 0; fi",
        "  IFS=$'\\t' read -r _slp_kind _slp_value _slp_compliance _slp_extra <<< \"$_slp_obs\"",
        "  if [[ \"$_slp_kind\" != VALUE || -z \"$_slp_value\" || -n \"$_slp_extra\" || ( \"$_slp_compliance\" != PASS && \"$_slp_compliance\" != FAIL ) ]]; then printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"; return 0; fi",
        "  printf 'SLP-CHECK-V1\\t%s\\tVALUE\\t%s\\t%s\\n' \"$_slp_cid\" \"$_slp_value\" \"$_slp_compliance\"",
        "}",
        "",
    ])


def shell_function_for_fixture(control_id, locator, key, op, expected, fsroot, logical_root_uid, sudoers_path, authority_path, visudo_path, cvtsudoers_path):
    if (locator, key, op, expected) != (CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED):
        raise ValueError("unsupported SRC-0008 sudo-root-command-files-protection contract")
    return _render(control_id, fsroot, logical_root_uid, sudoers_path, authority_path, visudo_path, cvtsudoers_path)


def shell_function(control_id, locator, key, op, expected):
    return shell_function_for_fixture(control_id, locator, key, op, expected, "/", 0, "/etc/sudoers", DEFAULT_REVIEWED_AUTHORITY, DEFAULT_VISUDO, DEFAULT_CVTSUDOERS)


MUTATING_TOKENS = ("chmod ", "chown ", "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "tee ", "install ", "truncate ", "dd ", "sysctl -w", "sed -i", ">>")


def _selftest():
    src = shell_function("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED)
    assert "command /usr/bin/python3 -I -S -B" in src
    assert "cvtsudoers" in src and "visudo" in src and "st_uid" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    for args in (
        ("/etc/sudoers", CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED),
        (CANONICAL_LOCATOR, "mode", CANONICAL_OP, CANONICAL_EXPECTED),
        (CANONICAL_LOCATOR, CANONICAL_KEY, "eq", CANONICAL_EXPECTED),
        (CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, "0022"),
    ):
        try:
            shell_function("CTRL", *args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
