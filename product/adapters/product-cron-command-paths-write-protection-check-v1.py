#!/usr/bin/env python3
# Read-only adapter SRC-0007: files/commands invoked by cron must have group/other write bits clear.
import re

SEMANTIC_CONTRACT_ID = "cron-command-paths-write-protection-check-semantic-v1"
ADAPTER_ID = "product-cron-command-paths-write-protection-check-v1"
ADAPTER_CONTRACT_VERSION = "product-cron-command-paths-write-protection-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "cron-command-paths-write-protection"
SUPPORTED_OPS = ("cron-command-paths-safe",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/etc/crontab|/etc/cron.d|/var/spool/cron/crontabs"
CANONICAL_KEY = "write-protection"
CANONICAL_OP = "cron-command-paths-safe"
CANONICAL_EXPECTED = "file-go-w"

_PY = r'''import hashlib, os, re, shlex, stat, sys
from pathlib import Path

fsroot = Path(sys.argv[1])
logical_root_uid = int(sys.argv[2], 10)
ASCII_DECIMAL = re.compile(r"^[0-9]+$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CROND_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", re.S)
SCHEDULE_FIELD = re.compile(r"^[A-Za-z0-9*?,/\-]+$")
SPECIAL = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}
SAFE_BUILTINS = {"cd", "test", "[", ":", "true", "false", "echo", "printf", "pwd"}
UNSUPPORTED_COMMANDS = {
    ".", "source", "eval", "exec", "command", "export", "unset", "read", "set", "shift", "trap",
    "env", "nice", "nohup", "timeout", "sudo", "su", "runuser", "chroot", "xargs", "find",
    "flock", "setsid", "stdbuf", "taskset", "ionice", "systemd-run", "start-stop-daemon",
    "busybox", "toybox",
    "time", "setpriv", "unshare", "nsenter", "prlimit", "setarch", "linux32", "linux64",
    "chrt", "watch", "strace", "ltrace", "gdb", "valgrind", "perf", "script",
    "daemon", "daemonize", "parallel", "numactl", "capsh", "firejail", "bwrap",
    "fakeroot", "torsocks", "proxychains", "proxychains4", "eatmydata", "sg", "newgrp",
    "docker", "podman", "systemd-nspawn", "machinectl",
}
INTERPRETER_NAME = re.compile(
    r"^(?:sh|ash|bash|dash|ksh|mksh|zsh|python(?:[0-9]+(?:\.[0-9]+)*)?|"
    r"perl(?:[0-9.]+)?|ruby(?:[0-9.]+)?|node(?:js)?(?:[0-9.]+)?|php(?:[0-9.]+)?|"
    r"lua(?:[0-9.]+)?|tclsh(?:[0-9.]+)?|wish(?:[0-9.]+)?|java|javaw|dotnet|mono|Rscript)$"
)
CONTROL_OPS = {"&&", "||", ";", "|", "&", "(", ")"}


def error():
    print("ERROR")
    raise SystemExit(0)


def map_abs(path_text):
    if not isinstance(path_text, str) or not path_text.startswith("/") or "\x00" in path_text or "\r" in path_text or "\n" in path_text:
        error()
    return fsroot / path_text.lstrip("/")


def obj_state(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)


def stable_regular(path, allow_symlink=False):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        return None
    except Exception:
        error()
    if stat.S_ISLNK(first.st_mode):
        if not allow_symlink:
            error()
        try:
            real = os.path.realpath(path)
            target = os.stat(real, follow_symlinks=True)
            second = os.lstat(path)
        except Exception:
            error()
        if obj_state(first) != obj_state(second) or not stat.S_ISREG(target.st_mode):
            error()
        return (str(path), real, obj_state(first), obj_state(target))
    if not stat.S_ISREG(first.st_mode):
        error()
    try:
        second = os.lstat(path)
    except Exception:
        error()
    if obj_state(first) != obj_state(second):
        error()
    return (str(path), str(path), obj_state(first), obj_state(first))


def stable_text(path, optional=False, allow_symlink=False):
    rec = stable_regular(path, allow_symlink=allow_symlink)
    if rec is None:
        if optional:
            return None
        error()
    try:
        raw = path.read_bytes()
        after = stable_regular(path, allow_symlink=allow_symlink)
    except Exception:
        error()
    if after != rec or b"\x00" in raw or b"\r" in raw:
        error()
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error()
    return rec, hashlib.sha256(raw).hexdigest(), text


def stable_dir(path, optional=False):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        if optional:
            return None
        error()
    except Exception:
        error()
    if stat.S_ISLNK(first.st_mode) or not stat.S_ISDIR(first.st_mode):
        error()
    try:
        names = sorted(os.listdir(path), key=os.fsencode)
        second = os.lstat(path)
    except Exception:
        error()
    if obj_state(first) != obj_state(second):
        error()
    return obj_state(first), tuple(names)


def parse_passwd():
    observed = stable_text(map_abs("/etc/passwd"), optional=False)
    users = {}
    for line in observed[2].splitlines():
        if not line:
            error()
        parts = line.split(":")
        if len(parts) != 7:
            error()
        name, _, uid_text, gid_text, _, home, _ = parts
        if not name or name in users or ASCII_DECIMAL.fullmatch(uid_text) is None or ASCII_DECIMAL.fullmatch(gid_text) is None:
            error()
        if not home.startswith("/"):
            error()
        users[name] = (int(uid_text), int(gid_text), home)
    if "root" not in users or users["root"][0] != 0:
        error()
    return observed, users


def parse_env_value(raw):
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    if any(ch in value for ch in "\x00\r\n`$"):
        error()
    return value


def parse_path_value(raw):
    value = parse_env_value(raw)
    parts = value.split(":")
    if not parts or any(not p.startswith("/") or p == "/" and False for p in parts) or any(p == "" for p in parts):
        error()
    return tuple(parts)


def split_percent(command):
    out = []
    escaped = False
    for ch in command:
        if escaped:
            if ch == "%":
                out.append("%")
            else:
                out.append("\\")
                out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "%":
            break
        out.append(ch)
    if escaped:
        out.append("\\")
    result = "".join(out).strip()
    if not result:
        error()
    return result


def cron_job(line, system_file, owner_user, users):
    parts = line.split()
    if not parts:
        error()
    if parts[0].startswith("@"):
        if parts[0] not in SPECIAL:
            error()
        needed = 3 if system_file else 2
        if len(parts) < needed:
            error()
        user = parts[1] if system_file else owner_user
        command = line.split(None, 2 if system_file else 1)[2 if system_file else 1]
    else:
        if len(parts) < (7 if system_file else 6):
            error()
        for field in parts[:5]:
            if SCHEDULE_FIELD.fullmatch(field) is None:
                error()
        user = parts[5] if system_file else owner_user
        command = line.split(None, 6 if system_file else 5)[6 if system_file else 5]
    if user not in users:
        error()
    return user, split_percent(command)


def lex_command(command):
    if any(ch in command for ch in "\x00\r\n`$"):
        error()
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except Exception:
        error()
    if not tokens:
        error()
    for tok in tokens:
        if "<" in tok or ">" in tok:
            error()
    return tokens


def resolve_root_command(word, path_env, uid, dir_records):
    if "/" in word:
        if not word.startswith("/"):
            error()
        return word
    if uid != 0 or path_env is None:
        error()
    for d in path_env:
        dpath = map_abs(d)
        drec = stable_dir(dpath, optional=False)
        dir_records[("path", d)] = drec
        candidate_text = d.rstrip("/") + "/" + word
        candidate = map_abs(candidate_text)
        try:
            st = os.stat(candidate, follow_symlinks=True)
        except FileNotFoundError:
            continue
        except Exception:
            error()
        if stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) & 0o111:
            return candidate_text
    error()


def resolved_command_record(path_text):
    mapped = map_abs(path_text)
    rec = stable_regular(mapped, allow_symlink=True)
    if rec is None:
        error()
    target_state = rec[3]
    if target_state[8] != 1:
        error()
    if (target_state[4] & 0o111) == 0:
        error()
    canonical_base = os.path.basename(rec[1])
    if not canonical_base or canonical_base in {".", ".."}:
        error()
    return rec, canonical_base


def add_target(path_text, targets, allow_nonexec=False):
    mapped = map_abs(path_text)
    rec = stable_regular(mapped, allow_symlink=True)
    if rec is None:
        error()
    target_state = rec[3]
    if not allow_nonexec and (target_state[4] & 0o111) == 0:
        error()
    previous = targets.get(path_text)
    if previous is not None and previous != rec:
        error()
    targets[path_text] = rec


def expand_run_parts(args, targets, dir_records):
    directory = None
    for arg in args:
        if arg in {"--report", "--verbose"}:
            continue
        if arg.startswith("-"):
            error()
        if directory is not None:
            error()
        directory = arg
    if directory is None or not directory.startswith("/"):
        error()
    dpath = map_abs(directory)
    drec = stable_dir(dpath, optional=False)
    dir_records[("run-parts", directory)] = drec
    for name in drec[1]:
        if CROND_NAME.fullmatch(name) is None:
            continue
        child_text = directory.rstrip("/") + "/" + name
        child = map_abs(child_text)
        try:
            st = os.stat(child, follow_symlinks=True)
        except FileNotFoundError:
            error()
        except Exception:
            error()
        if not stat.S_ISREG(st.st_mode):
            continue
        if stat.S_IMODE(st.st_mode) & 0o111:
            add_target(child_text, targets, allow_nonexec=False)


def parse_shell(command, user, users, path_env, targets, dir_records):
    tokens = lex_command(command)
    segments = []
    current = []
    depth = 0
    for tok in tokens:
        if tok == "(":
            if current:
                error()
            depth += 1
            continue
        if tok == ")":
            if current:
                segments.append(current); current = []
            depth -= 1
            if depth < 0:
                error()
            continue
        if tok in CONTROL_OPS:
            if tok in {"(", ")"}:
                error()
            if current:
                segments.append(current); current = []
            continue
        current.append(tok)
    if current:
        segments.append(current)
    if depth != 0 or not segments:
        error()

    uid = users[user][0]
    for seg in segments:
        local_path = path_env
        i = 0
        while i < len(seg) and ASSIGNMENT.fullmatch(seg[i]):
            name, value = seg[i].split("=", 1)
            if name == "PATH":
                local_path = parse_path_value(value)
            i += 1
        if i >= len(seg):
            continue
        command_word = seg[i]
        args = seg[i + 1:]
        if command_word in SAFE_BUILTINS:
            continue
        if command_word in UNSUPPORTED_COMMANDS:
            error()
        resolved = resolve_root_command(command_word, local_path, uid, dir_records)
        _resolved_rec, canonical_base = resolved_command_record(resolved)
        if canonical_base in UNSUPPORTED_COMMANDS or INTERPRETER_NAME.fullmatch(canonical_base) is not None:
            error()
        add_target(resolved, targets, allow_nonexec=False)
        if canonical_base == "run-parts":
            expand_run_parts(args, targets, dir_records)


def parse_crontab(path, system_file, owner_user, users, sources, targets, dir_records):
    observed = stable_text(path, optional=False, allow_symlink=False)
    if observed[2] and not observed[2].endswith("\n"):
        error()
    sources[str(path)] = observed[:2]
    path_env = None
    jobs = 0
    for raw_line in observed[2].splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", raw_line)
        if m:
            name, value = m.group(1), m.group(2)
            if not ENV_NAME.fullmatch(name):
                error()
            if name == "PATH":
                path_env = parse_path_value(value)
            elif name == "SHELL":
                if parse_env_value(value) != "/bin/sh":
                    error()
            continue
        user, command = cron_job(raw_line, system_file, owner_user, users)
        parse_shell(command, user, users, path_env, targets, dir_records)
        jobs += 1
    return jobs


def discover():
    passwd_obs, users = parse_passwd()
    sources = {str(map_abs("/etc/passwd")): passwd_obs[:2]}
    targets = {}
    dir_records = {}
    jobs = 0
    configs = 0

    etc_dir = stable_dir(map_abs("/etc"), optional=False)
    dir_records[("root", "/etc")] = etc_dir

    crontab_path = map_abs("/etc/crontab")
    if stable_regular(crontab_path, allow_symlink=False) is not None:
        jobs += parse_crontab(crontab_path, True, None, users, sources, targets, dir_records)
        configs += 1

    cron_d_path = map_abs("/etc/cron.d")
    cron_d = stable_dir(cron_d_path, optional=True)
    if cron_d is not None:
        dir_records[("root", "/etc/cron.d")] = cron_d
        for name in cron_d[1]:
            if CROND_NAME.fullmatch(name) is None:
                continue
            cfg = cron_d_path / name
            rec = stable_regular(cfg, allow_symlink=False)
            if rec is None:
                error()
            st = os.stat(cfg, follow_symlinks=False)
            if st.st_uid != logical_root_uid or stat.S_IMODE(st.st_mode) & 0o022:
                error()
            jobs += parse_crontab(cfg, True, None, users, sources, targets, dir_records)
            configs += 1

    spool_path = map_abs("/var/spool/cron/crontabs")
    spool = stable_dir(spool_path, optional=True)
    if spool is not None:
        dir_records[("root", "/var/spool/cron/crontabs")] = spool
        for name in spool[1]:
            if name not in users:
                continue
            cfg = spool_path / name
            rec = stable_regular(cfg, allow_symlink=False)
            if rec is None:
                error()
            st = os.stat(cfg, follow_symlinks=False)
            if st.st_uid != users[name][0] or stat.S_IMODE(st.st_mode) & 0o022:
                error()
            jobs += parse_crontab(cfg, False, name, users, sources, targets, dir_records)
            configs += 1

    violations = sum(1 for rec in targets.values() if rec[3][4] & 0o022)
    periodic = sum(1 for key in dir_records if key[0] == "run-parts")
    return sources, targets, dir_records, configs, jobs, periodic, violations


try:
    rst = os.lstat(fsroot)
except Exception:
    error()
if stat.S_ISLNK(rst.st_mode) or not stat.S_ISDIR(rst.st_mode):
    error()

first = discover()
second = discover()
if first != second:
    error()
_, targets, _, configs, jobs, periodic, violations = first
value = f"configs={configs};jobs={jobs};targets={len(targets)};periodic_dirs={periodic};violations={violations};ambiguous=0"
print("VALUE\t" + value + "\t" + ("PASS" if violations == 0 else "FAIL"))
'''


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, fsroot="/", logical_root_uid=0):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if not isinstance(fsroot, str) or not fsroot.startswith("/") or "\n" in fsroot or "\r" in fsroot:
        raise ValueError("absolute fs root required")
    if not isinstance(logical_root_uid, int) or isinstance(logical_root_uid, bool) or logical_root_uid < 0:
        raise ValueError("non-negative logical root uid required")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    cid = _sh_single(control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    return "\n".join([
        fn + "() {",
        "  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - " + _sh_single(fsroot) + " " + _sh_single(str(logical_root_uid)) + " <<'SLP_CRON_PATHS_PY'",
        _PY.rstrip("\n"),
        "SLP_CRON_PATHS_PY",
        "  )",
        "  _slp_rc=$?",
        "  if (( _slp_rc != 0 )) || [[ -z $_slp_obs || $_slp_obs == *$'\\n'* || $_slp_obs == *$'\\r'* ]]; then",
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        "  if [[ $_slp_obs == ERROR ]]; then",
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        "  IFS=$'\\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< \"$_slp_obs\"",
        "  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then",
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        emit + ' "VALUE" "$_slp_value" "$_slp_compliance"',
        "  return 0",
        "}",
        "",
    ])


def shell_function(control_id, locator, key, op, expected):
    if locator != CANONICAL_LOCATOR or key != CANONICAL_KEY or op != CANONICAL_OP or expected != CANONICAL_EXPECTED:
        raise ValueError("only canonical SRC-0007 cron command path contract is supported")
    return _render(control_id)


def _shell_function_for_root(control_id, fsroot, logical_root_uid=0):
    return _render(control_id, fsroot, logical_root_uid)


MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ",
)


def _selftest():
    src = shell_function("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED)
    assert "command /usr/bin/python3 -I -S -B" in src
    assert "/etc/crontab" in src and "/etc/cron.d" in src and "/var/spool/cron/crontabs" in src
    assert "split_percent" in src and "lex_command" in src and "expand_run_parts" in src
    assert "discover()" in src and "first != second" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    for args in (
        ("CTRL", "/etc/crontab", CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, "mode", CANONICAL_OP, CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "bits-clear", CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, "0022"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
