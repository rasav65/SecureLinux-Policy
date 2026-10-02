#!/usr/bin/env python3
"""product-cron-command-paths-write-protection-apply-v1.

APPLY-адаптер механизма cron-command-paths-write-protection-v1 (fstec-linux-2022 2.3.3, SRC-0007).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-cron-command-paths-write-protection-v1.json

Решение пользователя 29.09.2026: APPLY снимает биты записи группы и прочих (chmod go-w) у всей
популяции CHECK при любом владельце файла.

* Популяция — та же, что у CHECK product-cron-command-paths-write-protection-check-v1: код
  обнаружения (DISCOVERY_SOURCE) — байтовая копия начала наблюдателя CHECK (совпадение проверяет
  тест) и выполняется дважды; различие наблюдений или любой отказ наблюдателя — отказ без
  мутаций с причиной наблюдателя.
* Объект — конечный обычный файл (после разрешения ссылок), один на dev:ino. Файл без битов
  0022 соответствует требованию. Больше одной жёсткой ссылки или управляющие байты в пути —
  решение администратора без изменений.
* План строится до мутаций. Файл открывается по разрешённому пути с O_NOFOLLOW | O_NONBLOCK;
  на дескрипторе сверяются dev:ino, тип, владелец, группа, режим и число ссылок с наблюдением.
  Мутация — `fchmod(fd, mode & ~0o022)`: только снятие битов; компенсации нет (возврат прежнего
  режима ослабил бы защиту). Ошибка одного объекта не останавливает остальные
  (APPLIED_PARTIAL); EROFS останавливает сразу.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import sys

ADAPTER_ID = "product-cron-command-paths-write-protection-apply-v1"
MECHANISM_ID = "cron-command-paths-write-protection-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "cron-command-paths-write-protection"
SEMANTIC_CONTRACT_ID = "cron-command-paths-write-protection-apply-semantic-v1"

SUPPORTED_KEYS = ("write-protection",)
SUPPORTED_OPS = ("cron-command-paths-safe",)
EXPECTED_VALUE = "file-go-w"
CANONICAL_LOCATOR = "/etc/crontab|/etc/cron.d|/var/spool/cron/crontabs"
CLEAR_BITS = 0o022

OUTCOMES = (
    "APPLIED",
    "APPLIED_PARTIAL",
    "ALREADY_COMPLIANT",
    "DRY_RUN_WOULD_APPLY",
    "NOT_ELIGIBLE_APPLY_UNSUPPORTED",
    "ABORTED_PRECONDITION_CONFLICT",
    "ABORTED_PRECONDITION_OTHER",
    "FAILED_NOT_COMMITTED",
)

COMMIT_COMMITTED = "COMMITTED"
COMMIT_NOT_COMMITTED = "NOT_COMMITTED"
COMMIT_NOT_STARTED = "NOT_STARTED"

CONTROLS = ("FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION",)
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
INVALID_NAME = "<invalid-name>"
ADMIN_ACTION = ("Проверить файл, вызываемый из заданий cron, и его жёсткие ссылки; при "
                "необходимости выполнить chmod go-w вручную.")

_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC

# Байтовая копия начала наблюдателя CHECK (до запуска discover()).
DISCOVERY_SOURCE = (
    'import hashlib, os, re, shlex, stat, sys\n'
    'from pathlib import Path\n'
    '\n'
    'fsroot = Path(sys.argv[1])\n'
    'logical_root_uid = int(sys.argv[2], 10)\n'
    'ASCII_DECIMAL = re.compile(r"^[0-9]+$")\n'
    'ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")\n'
    'CROND_NAME = re.compile(r"^[A-Za-z0-9_-]+$")\n'
    'ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", re.S)\n'
    'SCHEDULE_FIELD = re.compile(r"^[A-Za-z0-9*?,/\\-]+$")\n'
    'SPECIAL = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}\n'
    'SAFE_BUILTINS = {"cd", "test", "[", ":", "true", "false", "echo", "printf", "pwd"}\n'
    'UNSUPPORTED_COMMANDS = {\n'
    '    ".", "source", "eval", "exec", "command", "export", "unset", "read", "set", "shift", "trap",\n'
    '    "env", "nice", "nohup", "timeout", "sudo", "su", "runuser", "chroot", "xargs", "find",\n'
    '    "flock", "setsid", "stdbuf", "taskset", "ionice", "systemd-run", "start-stop-daemon",\n'
    '    "busybox", "toybox",\n'
    '    "time", "setpriv", "unshare", "nsenter", "prlimit", "setarch", "linux32", "linux64",\n'
    '    "chrt", "watch", "strace", "ltrace", "gdb", "valgrind", "perf", "script",\n'
    '    "daemon", "daemonize", "parallel", "numactl", "capsh", "firejail", "bwrap",\n'
    '    "fakeroot", "torsocks", "proxychains", "proxychains4", "eatmydata", "sg", "newgrp",\n'
    '    "docker", "podman", "systemd-nspawn", "machinectl",\n'
    '}\n'
    'INTERPRETER_NAME = re.compile(\n'
    '    r"^(?:sh|ash|bash|dash|ksh|mksh|zsh|python(?:[0-9]+(?:\\.[0-9]+)*)?|"\n'
    '    r"perl(?:[0-9.]+)?|ruby(?:[0-9.]+)?|node(?:js)?(?:[0-9.]+)?|php(?:[0-9.]+)?|"\n'
    '    r"lua(?:[0-9.]+)?|tclsh(?:[0-9.]+)?|wish(?:[0-9.]+)?|java|javaw|dotnet|mono|Rscript)$"\n'
    ')\n'
    'CONTROL_OPS = {"&&", "||", ";", "|", "&", "(", ")"}\n'
    '# No PATH= in the crontab: every executable match in these directories is a target.\n'
    'DEFAULT_SEARCH_PATH = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/snap/bin")\n'
    'UNSUPPORTED_COMPOUND = {"while", "until", "for", "case", "select", "function", "coproc", "do", "done", "esac", "[[", "]]"}\n'
    'FD_WORDS = {"1", "2"}\n'
    '\n'
    '\n'
    'def error(reason):\n'
    '    print("ERROR\\t" + reason)\n'
    '    raise SystemExit(0)\n'
    '\n'
    '\n'
    'def map_abs(path_text):\n'
    '    if not isinstance(path_text, str) or not path_text.startswith("/") or "\\x00" in path_text or "\\r" in path_text or "\\n" in path_text:\n'
    '        error("path:invalid-absolute")\n'
    '    return fsroot / path_text.lstrip("/")\n'
    '\n'
    '\n'
    'def obj_state(st):\n'
    '    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)\n'
    '\n'
    '\n'
    'def stable_regular(path, allow_symlink=False):\n'
    '    try:\n'
    '        first = os.lstat(path)\n'
    '    except FileNotFoundError:\n'
    '        return None\n'
    '    except Exception:\n'
    '        error("file:lstat-failed")\n'
    '    if stat.S_ISLNK(first.st_mode):\n'
    '        if not allow_symlink:\n'
    '            error("file:symlink")\n'
    '        try:\n'
    '            real = os.path.realpath(path)\n'
    '            target = os.stat(real, follow_symlinks=True)\n'
    '            second = os.lstat(path)\n'
    '        except Exception:\n'
    '            error("file:resolve-failed")\n'
    '        if obj_state(first) != obj_state(second):\n'
    '            error("file:changed-during-check")\n'
    '        if not stat.S_ISREG(target.st_mode):\n'
    '            error("file:invalid-type")\n'
    '        return (str(path), real, obj_state(first), obj_state(target))\n'
    '    if not stat.S_ISREG(first.st_mode):\n'
    '        error("file:invalid-type")\n'
    '    try:\n'
    '        second = os.lstat(path)\n'
    '    except Exception:\n'
    '        error("file:lstat-failed")\n'
    '    if obj_state(first) != obj_state(second):\n'
    '        error("file:changed-during-check")\n'
    '    return (str(path), str(path), obj_state(first), obj_state(first))\n'
    '\n'
    '\n'
    'def stable_text(path, optional=False, allow_symlink=False):\n'
    '    rec = stable_regular(path, allow_symlink=allow_symlink)\n'
    '    if rec is None:\n'
    '        if optional:\n'
    '            return None\n'
    '        error("file:not-found")\n'
    '    try:\n'
    '        raw = path.read_bytes()\n'
    '        after = stable_regular(path, allow_symlink=allow_symlink)\n'
    '    except Exception:\n'
    '        error("file:read-failed")\n'
    '    if after != rec:\n'
    '        error("file:changed-during-check")\n'
    '    if b"\\x00" in raw or b"\\r" in raw:\n'
    '        error("file:invalid-bytes")\n'
    '    try:\n'
    '        text = raw.decode("utf-8", errors="strict")\n'
    '    except UnicodeDecodeError:\n'
    '        error("file:invalid-utf8")\n'
    '    return rec, hashlib.sha256(raw).hexdigest(), text\n'
    '\n'
    '\n'
    'def stable_dir(path, optional=False):\n'
    '    try:\n'
    '        first = os.lstat(path)\n'
    '    except FileNotFoundError:\n'
    '        if optional:\n'
    '            return None\n'
    '        error("directory:not-found")\n'
    '    except Exception:\n'
    '        error("directory:lstat-failed")\n'
    '    if stat.S_ISLNK(first.st_mode):\n'
    '        error("directory:symlink")\n'
    '    if not stat.S_ISDIR(first.st_mode):\n'
    '        error("directory:invalid-type")\n'
    '    try:\n'
    '        names = sorted(os.listdir(path), key=os.fsencode)\n'
    '        second = os.lstat(path)\n'
    '    except Exception:\n'
    '        error("directory:scan-failed")\n'
    '    if obj_state(first) != obj_state(second):\n'
    '        error("directory:changed-during-check")\n'
    '    return obj_state(first), tuple(names)\n'
    '\n'
    '\n'
    'def stable_search_dir(path, optional):\n'
    '    try:\n'
    '        first = os.lstat(path)\n'
    '    except FileNotFoundError:\n'
    '        if optional:\n'
    '            return None\n'
    '        error("directory:not-found")\n'
    '    except Exception:\n'
    '        error("directory:lstat-failed")\n'
    '    if not stat.S_ISLNK(first.st_mode):\n'
    '        return stable_dir(path, optional=optional)\n'
    '    try:\n'
    '        real = os.path.realpath(path)\n'
    '        target = os.stat(real, follow_symlinks=True)\n'
    '        second = os.lstat(path)\n'
    '    except FileNotFoundError:\n'
    '        if optional:\n'
    '            return None\n'
    '        error("directory:not-found")\n'
    '    except Exception:\n'
    '        error("directory:resolve-failed")\n'
    '    if obj_state(first) != obj_state(second):\n'
    '        error("directory:changed-during-check")\n'
    '    if not stat.S_ISDIR(target.st_mode):\n'
    '        error("directory:invalid-type")\n'
    '    return obj_state(first), real, obj_state(target)\n'
    '\n'
    '\n'
    'def parse_passwd():\n'
    '    observed = stable_text(map_abs("/etc/passwd"), optional=False)\n'
    '    users = {}\n'
    '    for line in observed[2].splitlines():\n'
    '        if not line:\n'
    '            error("passwd:empty-record")\n'
    '        parts = line.split(":")\n'
    '        if len(parts) != 7:\n'
    '            error("passwd:invalid-fields")\n'
    '        name, _, uid_text, gid_text, _, home, _ = parts\n'
    '        if not name:\n'
    '            error("passwd:invalid-account")\n'
    '        if name in users:\n'
    '            error("passwd:duplicate-account")\n'
    '        if ASCII_DECIMAL.fullmatch(uid_text) is None or ASCII_DECIMAL.fullmatch(gid_text) is None:\n'
    '            error("passwd:invalid-id")\n'
    '        if not home.startswith("/"):\n'
    '            error("passwd:invalid-home")\n'
    '        users[name] = (int(uid_text), int(gid_text), home)\n'
    '    if "root" not in users or users["root"][0] != 0:\n'
    '        error("passwd:invalid-root")\n'
    '    return observed, users\n'
    '\n'
    '\n'
    'def parse_env_value(raw):\n'
    '    value = raw.strip()\n'
    '    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\'", \'"\'}:\n'
    '        value = value[1:-1]\n'
    '    if any(ch in value for ch in "\\x00\\r\\n`$"):\n'
    '        error("cron:invalid-environment-value")\n'
    '    return value\n'
    '\n'
    '\n'
    'def parse_path_value(raw):\n'
    '    value = parse_env_value(raw)\n'
    '    parts = value.split(":")\n'
    '    if not parts or any(not p.startswith("/") or p == "/" and False for p in parts) or any(p == "" for p in parts):\n'
    '        error("cron:invalid-path")\n'
    '    return tuple(parts)\n'
    '\n'
    '\n'
    'def split_percent(command):\n'
    '    out = []\n'
    '    escaped = False\n'
    '    for ch in command:\n'
    '        if escaped:\n'
    '            if ch == "%":\n'
    '                out.append("%")\n'
    '            else:\n'
    '                out.append("\\\\")\n'
    '                out.append(ch)\n'
    '            escaped = False\n'
    '            continue\n'
    '        if ch == "\\\\":\n'
    '            escaped = True\n'
    '            continue\n'
    '        if ch == "%":\n'
    '            break\n'
    '        out.append(ch)\n'
    '    if escaped:\n'
    '        out.append("\\\\")\n'
    '    result = "".join(out).strip()\n'
    '    if not result:\n'
    '        error("cron:empty-command")\n'
    '    return result\n'
    '\n'
    '\n'
    'def cron_job(line, system_file, owner_user, users):\n'
    '    parts = line.split()\n'
    '    if not parts:\n'
    '        error("cron:empty-record")\n'
    '    if parts[0].startswith("@"):\n'
    '        if parts[0] not in SPECIAL:\n'
    '            error("cron:invalid-schedule")\n'
    '        needed = 3 if system_file else 2\n'
    '        if len(parts) < needed:\n'
    '            error("cron:invalid-fields")\n'
    '        user = parts[1] if system_file else owner_user\n'
    '        command = line.split(None, 2 if system_file else 1)[2 if system_file else 1]\n'
    '    else:\n'
    '        if len(parts) < (7 if system_file else 6):\n'
    '            error("cron:invalid-fields")\n'
    '        for field in parts[:5]:\n'
    '            if SCHEDULE_FIELD.fullmatch(field) is None:\n'
    '                error("cron:invalid-schedule")\n'
    '        user = parts[5] if system_file else owner_user\n'
    '        command = line.split(None, 6 if system_file else 5)[6 if system_file else 5]\n'
    '    if user not in users:\n'
    '        error("cron:unknown-user")\n'
    '    return user, split_percent(command)\n'
    '\n'
    '\n'
    'def lex_command(command):\n'
    '    if any(ch in command for ch in "\\x00\\r\\n`$"):\n'
    '        error("command:invalid-bytes")\n'
    '    try:\n'
    '        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")\n'
    '        lexer.whitespace_split = True\n'
    '        lexer.commenters = ""\n'
    '        tokens = list(lexer)\n'
    '    except Exception:\n'
    '        error("command:parse-failed")\n'
    '    if not tokens:\n'
    '        error("command:empty")\n'
    '    for tok in tokens:\n'
    '        if ("<" in tok or ">" in tok) and tok not in {">", ">&"}:\n'
    '            error("command:unsupported-redirection")\n'
    '    return tokens\n'
    '\n'
    '\n'
    'def resolve_root_command(word, path_env, uid, dir_records):\n'
    '    if "/" in word:\n'
    '        if not word.startswith("/"):\n'
    '            error("command:relative-path")\n'
    '        return [word]\n'
    '    if uid != 0:\n'
    '        error("command:unresolved-name")\n'
    '    search = DEFAULT_SEARCH_PATH if path_env is None else path_env\n'
    '    found = []\n'
    '    for d in search:\n'
    '        drec = stable_search_dir(map_abs(d), optional=path_env is None)\n'
    '        dir_records[("path", d)] = drec\n'
    '        if drec is None:\n'
    '            continue\n'
    '        candidate_text = d.rstrip("/") + "/" + word\n'
    '        candidate = map_abs(candidate_text)\n'
    '        try:\n'
    '            st = os.stat(candidate, follow_symlinks=True)\n'
    '        except FileNotFoundError:\n'
    '            continue\n'
    '        except Exception:\n'
    '            error("command:stat-failed")\n'
    '        if stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) & 0o111:\n'
    '            if path_env is not None:\n'
    '                return [candidate_text]\n'
    '            found.append(candidate_text)\n'
    '    if not found:\n'
    '        error("command:not-found")\n'
    '    return found\n'
    '\n'
    '\n'
    'def resolved_command_record(path_text):\n'
    '    mapped = map_abs(path_text)\n'
    '    rec = stable_regular(mapped, allow_symlink=True)\n'
    '    if rec is None:\n'
    '        error("target:not-found")\n'
    '    target_state = rec[3]\n'
    '    if target_state[8] != 1:\n'
    '        error("target:hardlink")\n'
    '    if (target_state[4] & 0o111) == 0:\n'
    '        error("target:not-executable")\n'
    '    canonical_base = os.path.basename(rec[1])\n'
    '    if not canonical_base or canonical_base in {".", ".."}:\n'
    '        error("target:invalid-name")\n'
    '    return rec, canonical_base\n'
    '\n'
    '\n'
    'def add_target(path_text, targets, allow_nonexec=False):\n'
    '    mapped = map_abs(path_text)\n'
    '    rec = stable_regular(mapped, allow_symlink=True)\n'
    '    if rec is None:\n'
    '        error("target:not-found")\n'
    '    target_state = rec[3]\n'
    '    if not allow_nonexec and (target_state[4] & 0o111) == 0:\n'
    '        error("target:not-executable")\n'
    '    previous = targets.get(path_text)\n'
    '    if previous is not None and previous != rec:\n'
    '        error("target:changed-during-check")\n'
    '    targets[path_text] = rec\n'
    '\n'
    '\n'
    'def expand_run_parts(args, targets, dir_records):\n'
    '    directory = None\n'
    '    for arg in args:\n'
    '        if arg in {"--report", "--verbose"}:\n'
    '            continue\n'
    '        if arg.startswith("-"):\n'
    '            error("run-parts:unsupported-option")\n'
    '        if directory is not None:\n'
    '            error("run-parts:ambiguous-directory")\n'
    '        directory = arg\n'
    '    if directory is None or not directory.startswith("/"):\n'
    '        error("run-parts:invalid-directory")\n'
    '    dpath = map_abs(directory)\n'
    '    drec = stable_dir(dpath, optional=False)\n'
    '    dir_records[("run-parts", directory)] = drec\n'
    '    for name in drec[1]:\n'
    '        if CROND_NAME.fullmatch(name) is None:\n'
    '            continue\n'
    '        child_text = directory.rstrip("/") + "/" + name\n'
    '        child = map_abs(child_text)\n'
    '        try:\n'
    '            st = os.stat(child, follow_symlinks=True)\n'
    '        except FileNotFoundError:\n'
    '            error("run-parts:child-not-found")\n'
    '        except Exception:\n'
    '            error("run-parts:child-stat-failed")\n'
    '        if not stat.S_ISREG(st.st_mode):\n'
    '            continue\n'
    '        if stat.S_IMODE(st.st_mode) & 0o111:\n'
    '            add_target(child_text, targets, allow_nonexec=False)\n'
    '\n'
    '\n'
    'def parse_shell(command, user, users, path_env, targets, dir_records):\n'
    '    tokens = lex_command(command)\n'
    '    segments = []\n'
    '    current = []\n'
    '    stack = []\n'
    '    closed = False\n'
    '    i = 0\n'
    '    while i < len(tokens):\n'
    '        tok = tokens[i]\n'
    '        if tok in {">", ">&"}:\n'
    '            if i + 1 >= len(tokens):\n'
    '                error("command:unsupported-redirection")\n'
    '            sink = tokens[i + 1]\n'
    '            if not ((tok == ">" and sink == "/dev/null") or (tok == ">&" and sink in FD_WORDS)):\n'
    '                error("command:unsupported-redirection")\n'
    '            if len(current) >= 2 and current[-1] in FD_WORDS:\n'
    '                current.pop()\n'
    '            if not current:\n'
    '                error("command:unsupported-redirection")\n'
    '            i += 2\n'
    '            continue\n'
    '        i += 1\n'
    '        if closed:\n'
    '            if tok not in CONTROL_OPS or tok == "(":\n'
    '                error("command:unsupported-grouping")\n'
    '            closed = False\n'
    '        if not current:\n'
    '            if tok in {"(", "{", "if"}:\n'
    '                stack.append(tok)\n'
    '                continue\n'
    '            if tok == "}":\n'
    '                if not stack or stack[-1] != "{":\n'
    '                    error("command:unbalanced-group")\n'
    '                stack.pop()\n'
    '                closed = True\n'
    '                continue\n'
    '            if tok == "then":\n'
    '                if not stack or stack[-1] not in {"if", "elif"}:\n'
    '                    error("command:unbalanced-group")\n'
    '                stack[-1] = "then"\n'
    '                continue\n'
    '            if tok in {"elif", "else"}:\n'
    '                if not stack or stack[-1] != "then":\n'
    '                    error("command:unbalanced-group")\n'
    '                stack[-1] = tok\n'
    '                continue\n'
    '            if tok == "fi":\n'
    '                if not stack or stack[-1] not in {"then", "else"}:\n'
    '                    error("command:unbalanced-group")\n'
    '                stack.pop()\n'
    '                closed = True\n'
    '                continue\n'
    '            if tok == "!":\n'
    '                continue\n'
    '        if tok == ")":\n'
    '            if current:\n'
    '                segments.append(current); current = []\n'
    '            if not stack or stack[-1] != "(":\n'
    '                error("command:unbalanced-group")\n'
    '            stack.pop()\n'
    '            closed = True\n'
    '            continue\n'
    '        if tok in CONTROL_OPS:\n'
    '            if tok == "(":\n'
    '                error("command:unsupported-grouping")\n'
    '            if current:\n'
    '                segments.append(current); current = []\n'
    '            continue\n'
    '        current.append(tok)\n'
    '    if current:\n'
    '        segments.append(current)\n'
    '    if stack or not segments:\n'
    '        error("command:unbalanced-group")\n'
    '\n'
    '    uid = users[user][0]\n'
    '    for seg in segments:\n'
    '        local_path = path_env\n'
    '        i = 0\n'
    '        while i < len(seg) and ASSIGNMENT.fullmatch(seg[i]):\n'
    '            name, value = seg[i].split("=", 1)\n'
    '            if name == "PATH":\n'
    '                local_path = parse_path_value(value)\n'
    '            i += 1\n'
    '        if i >= len(seg):\n'
    '            continue\n'
    '        command_word = seg[i]\n'
    '        args = seg[i + 1:]\n'
    '        if command_word == "exec":\n'
    '            if not args or args[0].startswith("-") or ASSIGNMENT.fullmatch(args[0]):\n'
    '                error("command:unsupported-wrapper")\n'
    '            command_word, args = args[0], args[1:]\n'
    '        if command_word in SAFE_BUILTINS:\n'
    '            continue\n'
    '        # command -v/-V only reports the lookup result and runs nothing.\n'
    '        if command_word == "command" and len(args) == 2 and args[0] in {"-v", "-V"}:\n'
    '            continue\n'
    '        if command_word in UNSUPPORTED_COMPOUND:\n'
    '            error("command:unsupported-compound")\n'
    '        if command_word in UNSUPPORTED_COMMANDS:\n'
    '            error("command:unsupported-wrapper")\n'
    '        periodic = False\n'
    '        for resolved in resolve_root_command(command_word, local_path, uid, dir_records):\n'
    '            _resolved_rec, canonical_base = resolved_command_record(resolved)\n'
    '            if canonical_base in UNSUPPORTED_COMMANDS or INTERPRETER_NAME.fullmatch(canonical_base) is not None:\n'
    '                error("command:unsupported-execution-chain")\n'
    '            add_target(resolved, targets, allow_nonexec=False)\n'
    '            if canonical_base == "run-parts":\n'
    '                periodic = True\n'
    '        if periodic:\n'
    '            expand_run_parts(args, targets, dir_records)\n'
    '\n'
    '\n'
    'def parse_crontab(path, system_file, owner_user, users, sources, targets, dir_records):\n'
    '    observed = stable_text(path, optional=False, allow_symlink=False)\n'
    '    if observed[2] and not observed[2].endswith("\\n"):\n'
    '        error("cron:invalid-line-ending")\n'
    '    sources[str(path)] = observed[:2]\n'
    '    path_env = None\n'
    '    jobs = 0\n'
    '    for raw_line in observed[2].splitlines():\n'
    '        if not raw_line.strip() or raw_line.lstrip().startswith("#"):\n'
    '            continue\n'
    '        m = re.match(r"^\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(.*)$", raw_line)\n'
    '        if m:\n'
    '            name, value = m.group(1), m.group(2)\n'
    '            if not ENV_NAME.fullmatch(name):\n'
    '                error("cron:invalid-environment-name")\n'
    '            if name == "PATH":\n'
    '                path_env = parse_path_value(value)\n'
    '            elif name == "SHELL":\n'
    '                if parse_env_value(value) != "/bin/sh":\n'
    '                    error("cron:unsupported-shell")\n'
    '            continue\n'
    '        user, command = cron_job(raw_line, system_file, owner_user, users)\n'
    '        parse_shell(command, user, users, path_env, targets, dir_records)\n'
    '        jobs += 1\n'
    '    return jobs\n'
    '\n'
    '\n'
    'def discover():\n'
    '    passwd_obs, users = parse_passwd()\n'
    '    sources = {str(map_abs("/etc/passwd")): passwd_obs[:2]}\n'
    '    targets = {}\n'
    '    dir_records = {}\n'
    '    jobs = 0\n'
    '    configs = 0\n'
    '\n'
    '    etc_dir = stable_dir(map_abs("/etc"), optional=False)\n'
    '    dir_records[("root", "/etc")] = etc_dir\n'
    '\n'
    '    crontab_path = map_abs("/etc/crontab")\n'
    '    if stable_regular(crontab_path, allow_symlink=False) is not None:\n'
    '        jobs += parse_crontab(crontab_path, True, None, users, sources, targets, dir_records)\n'
    '        configs += 1\n'
    '\n'
    '    cron_d_path = map_abs("/etc/cron.d")\n'
    '    cron_d = stable_dir(cron_d_path, optional=True)\n'
    '    if cron_d is not None:\n'
    '        dir_records[("root", "/etc/cron.d")] = cron_d\n'
    '        for name in cron_d[1]:\n'
    '            if CROND_NAME.fullmatch(name) is None:\n'
    '                continue\n'
    '            cfg = cron_d_path / name\n'
    '            rec = stable_regular(cfg, allow_symlink=False)\n'
    '            if rec is None:\n'
    '                error("cron:config-disappeared")\n'
    '            st = os.stat(cfg, follow_symlinks=False)\n'
    '            if st.st_uid != logical_root_uid or stat.S_IMODE(st.st_mode) & 0o022:\n'
    '                error("cron:config-untrusted")\n'
    '            jobs += parse_crontab(cfg, True, None, users, sources, targets, dir_records)\n'
    '            configs += 1\n'
    '\n'
    '    spool_path = map_abs("/var/spool/cron/crontabs")\n'
    '    spool = stable_dir(spool_path, optional=True)\n'
    '    if spool is not None:\n'
    '        dir_records[("root", "/var/spool/cron/crontabs")] = spool\n'
    '        for name in spool[1]:\n'
    '            if name not in users:\n'
    '                continue\n'
    '            cfg = spool_path / name\n'
    '            rec = stable_regular(cfg, allow_symlink=False)\n'
    '            if rec is None:\n'
    '                error("cron:spool-disappeared")\n'
    '            st = os.stat(cfg, follow_symlinks=False)\n'
    '            if st.st_uid != users[name][0] or stat.S_IMODE(st.st_mode) & 0o022:\n'
    '                error("cron:spool-untrusted")\n'
    '            jobs += parse_crontab(cfg, False, name, users, sources, targets, dir_records)\n'
    '            configs += 1\n'
    '\n'
    '    # One file reached by several paths (/usr/bin/run-parts and /bin/run-parts on merged /usr)\n'
    '    # is counted once: identity is dev:ino of the final regular file.\n'
    '    unique = {rec[3][:2]: rec for rec in targets.values()}\n'
    '    violations = sum(1 for rec in unique.values() if rec[3][4] & 0o022)\n'
    '    periodic = sum(1 for key in dir_records if key[0] == "run-parts")\n'
    '    return sources, targets, dir_records, configs, jobs, periodic, violations\n'
    '\n'
)


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if key not in SUPPORTED_KEYS:
        raise ValueError("unsupported key: %r" % (key,))
    if op not in SUPPORTED_OPS:
        raise ValueError("unsupported op: %r" % (op,))
    if expected != EXPECTED_VALUE:
        raise ValueError("only file-go-w is supported")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _errname(exc):
    return errno.errorcode.get(exc.errno, str(exc.errno))


def _bad_bytes(text):
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in text)


def discover(fsroot="/", logical_root_uid=0):
    """(error_reason|None, targets): targets — {путь из cron: запись наблюдателя CHECK}."""
    try:
        rst = os.lstat(fsroot)
    except OSError:
        return "root:lstat-failed", None
    if stat.S_ISLNK(rst.st_mode):
        return "root:symlink", None
    if not stat.S_ISDIR(rst.st_mode):
        return "root:invalid-type", None
    captured = []

    def capture(*args, **_kw):
        captured.append(" ".join(str(a) for a in args))

    saved = sys.argv
    sys.argv = ["slp-cron-discovery", fsroot, str(logical_root_uid)]
    try:
        ns = {"__name__": "slp_cron_discovery", "print": capture}
        exec(compile(DISCOVERY_SOURCE, "<cron-discovery>", "exec"), ns)
        first = ns["discover"]()
        second = ns["discover"]()
    except SystemExit:
        last = captured[-1] if captured else ""
        reason = last.split("\t", 1)[1] if last.startswith("ERROR\t") else "observer:exit"
        return reason, None
    finally:
        sys.argv = saved
    if first != second:
        return "observation:changed-during-check", None
    return None, first[1]


def plan(fsroot="/", logical_root_uid=0):
    """(error_reason|None, objects): по одному словарю на конечный файл (dev:ino)."""
    error, targets = discover(fsroot, logical_root_uid)
    if error is not None:
        return error, []
    objects, seen = [], {}
    for path_text in sorted(targets):
        rec = targets[path_text]
        state = rec[3]
        key = state[:2]
        if key in seen:
            continue
        mode = state[4]
        shown = INVALID_NAME if _bad_bytes(path_text) or _bad_bytes(rec[1]) else path_text
        if mode & CLEAR_BITS == 0:
            kind, reason = "ok", None
        elif shown == INVALID_NAME:
            kind, reason = "admin", "target:invalid-name"
        elif state[8] != 1:
            kind, reason = "admin", "target:hardlink"
        else:
            kind, reason = "plan", None
        item = {"kind": kind, "path": shown, "real": rec[1], "reason": reason, "state": state}
        seen[key] = item
        objects.append(item)
    return None, objects


def _default_privilege_check() -> bool:
    return os.geteuid() == 0


def _default_fchmod(fd, mode, path):
    os.fchmod(fd, mode)


def _commit_state(outcome, dry_run, mutation):
    """Те же значения, что у file-mode-owner."""
    if outcome == "APPLIED" or (outcome == "ALREADY_COMPLIANT" and not dry_run):
        return COMMIT_COMMITTED
    if mutation:
        return COMMIT_NOT_COMMITTED
    return COMMIT_NOT_STARTED


def outcome_rc_contribution(outcome, dry_run=False):
    """"0" для успешных исходов, иначе "nonzero"; APPLIED_PARTIAL — nonzero."""
    if outcome in ("APPLIED", "ALREADY_COMPLIANT", "NOT_ELIGIBLE_APPLY_UNSUPPORTED"):
        return "0"
    if dry_run and outcome == "DRY_RUN_WOULD_APPLY":
        return "0"
    return "nonzero"


def _result(control_id, outcome, *, actions, dry_run, mutation=False, **extra):
    record = {
        "adapter_id": ADAPTER_ID,
        "mechanism_id": MECHANISM_ID,
        "control_id": control_id,
        "target": CANONICAL_LOCATOR,
        "outcome": outcome,
        "reason": None,
        "current_mode": None,
        "violators": [],
        "applied": [],
        "skipped": [],
        "failed": [],
        "operator_decision": None,
        "actions_attempted": list(actions),
        "mutation_performed": bool(mutation),
        "transaction_commit": _commit_state(outcome, dry_run, mutation),
        "dry_run": bool(dry_run),
    }
    record.update(extra)
    if record["outcome"] not in OUTCOMES:
        raise ValueError("outcome outside closed vocabulary")
    return record


def _apply_one(item, fchmod):
    """Снять биты 0022 одного файла. Возвращает (mutated, failure_reason|None).

    OSError наружу выходит только из самого fchmod (мутации не было). Любая ошибка после
    успешного fchmod (fstat, close) возвращается с mutated=True: факт мутации не теряется.
    """
    try:
        fd = os.open(item["real"], _FILE_FLAGS)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return False, "type-drift"
        return False, "open:%s" % _errname(exc)
    state = {"mutated": False}
    try:
        result = _apply_fd(fd, item["state"], item["path"], fchmod, state)
    except OSError as exc:
        if state["mutated"]:
            result = (True, "postcheck:%s" % _errname(exc))
        elif exc.errno == errno.EROFS or getattr(exc, "_slp_fchmod", False):
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        else:
            result = (False, "precheck:%s" % _errname(exc))
    try:
        os.close(fd)
    except OSError as exc:
        if result[1] is None:
            result = (result[0], "close:%s" % _errname(exc))
    return result


def _apply_fd(fd, observed, path, fchmod, state):
    """Проверки на дескрипторе, fchmod и итоговая проверка одного файла."""
    now = os.fstat(fd)
    if (now.st_dev, now.st_ino) != observed[:2]:
        return False, "identity-drift"
    if not stat.S_ISREG(now.st_mode):
        return False, "type-drift"
    if (now.st_uid, now.st_gid) != observed[2:4]:
        return False, "ownership-drift"
    if now.st_nlink != 1:
        return False, "hardlink-drift"
    current = stat.S_IMODE(now.st_mode)
    if current != observed[4]:
        return False, "mode-drift"
    target = current & ~CLEAR_BITS
    try:
        fchmod(fd, target, path)
    except OSError as exc:
        exc._slp_fchmod = True
        raise
    state["mutated"] = True
    post = os.fstat(fd)
    if (
        stat.S_IMODE(post.st_mode) != target
        or (post.st_uid, post.st_gid) != (now.st_uid, now.st_gid)
        or (post.st_dev, post.st_ino) != (now.st_dev, now.st_ino)
    ):
        return True, "post-state-mismatch"
    return True, None


def execute_control(
    control_id,
    key,
    op,
    expected,
    apply_supported,
    *,
    dry_run,
    fsroot="/",
    logical_root_uid=0,
    privilege_check=None,
    _fchmod=None,
):
    """Снять биты записи группы и прочих у файлов, вызываемых из заданий cron."""
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if control_id not in CONTROLS:
        return done("ABORTED_PRECONDITION_OTHER", reason="target:unmapped-control")

    actions.append("P1_POPULATION")
    error, objects = plan(fsroot, logical_root_uid)
    if error is not None:
        return done("ABORTED_PRECONDITION_OTHER", reason="check:" + error)

    actions.append("P2_PLAN")
    planned = [item for item in objects if item["kind"] == "plan"]
    admin = [item for item in objects if item["kind"] == "admin"]
    skipped = [{"path": item["path"], "reason": item["reason"]} for item in admin]
    current = "targets=%d;violations=%d;admin=%d" % (len(objects), len(planned), len(admin))
    violators = [item["path"] for item in planned]
    decision = None
    if admin:
        decision = {"required": True, "class": "ADMIN_ACTION_REQUIRED", "action": ADMIN_ACTION}
    if not planned and not admin:
        return done("ALREADY_COMPLIANT", current_mode=current)
    if not planned:
        first = admin[0]
        return done("ABORTED_PRECONDITION_CONFLICT", reason="%s:%s" % (first["reason"], first["path"]),
                    current_mode=current, skipped=skipped, operator_decision=decision)
    if dry_run:
        return done("DRY_RUN_WOULD_APPLY", current_mode=current, violators=violators,
                    skipped=skipped, operator_decision=decision)

    actions.append("P3_PRIVILEGE")
    check = privilege_check if privilege_check is not None else _default_privilege_check
    if not check():
        return done("ABORTED_PRECONDITION_OTHER", reason="privilege", current_mode=current,
                    violators=violators, skipped=skipped, operator_decision=decision)

    actions.append("PHASE1_MODE")
    fchmod = _fchmod if _fchmod is not None else _default_fchmod
    applied, failed = [], []
    mutated = False
    for item in planned:
        try:
            changed, failure = _apply_one(item, fchmod)
        except OSError as exc:
            if exc.errno == errno.EROFS:
                outcome = "APPLIED_PARTIAL" if mutated else "ABORTED_PRECONDITION_OTHER"
                return done(outcome, reason="erofs", mutation=mutated, current_mode=current,
                            violators=violators, applied=applied, skipped=skipped,
                            failed=failed + [{"path": item["path"], "reason": "erofs"}],
                            operator_decision=decision)
            changed, failure = False, "fchmod:%s" % _errname(exc)
        mutated = mutated or changed
        if failure is None:
            applied.append(item["path"])
        else:
            failed.append({"path": item["path"], "reason": failure})

    actions.append("FINAL_POSTCHECK")
    extra = dict(current_mode=current, violators=violators, applied=applied, skipped=skipped,
                 failed=failed, operator_decision=decision)
    if not failed and not skipped:
        return done("APPLIED", mutation=mutated, **extra)
    if applied:
        return done("APPLIED_PARTIAL", reason="partial", mutation=mutated, **extra)
    return done("FAILED_NOT_COMMITTED", reason="no-object-applied", mutation=mutated, **extra)


def control_result_to_report(result, started_at, finished_at):
    return {
        "adapter_id": result["adapter_id"],
        "mechanism_id": result["mechanism_id"],
        "control_id": result["control_id"],
        "target": result["target"],
        "outcome": result["outcome"],
        "reason": result["reason"],
        "current_mode": result["current_mode"],
        "violators": list(result["violators"]),
        "applied": list(result["applied"]),
        "skipped": [dict(item) for item in result["skipped"]],
        "failed": [dict(item) for item in result["failed"]],
        "operator_decision": None if result["operator_decision"] is None else dict(result["operator_decision"]),
        "started_at": started_at,
        "finished_at": finished_at,
        "actions_attempted": list(result["actions_attempted"]),
        "step_rc": outcome_rc_contribution(result["outcome"], result["dry_run"]),
        "mutation_performed": result["mutation_performed"],
        "transaction_commit": result["transaction_commit"],
    }
