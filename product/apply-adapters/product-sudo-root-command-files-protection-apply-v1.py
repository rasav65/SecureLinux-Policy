#!/usr/bin/env python3
"""product-sudo-root-command-files-protection-apply-v1.

APPLY-адаптер механизма sudo-root-command-files-protection-v1 (fstec-linux-2022 2.3.4, SRC-0008).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-sudo-root-command-files-protection-v1.json

Решение пользователя 29.09.2026: APPLY снимает биты записи группы и прочих (chmod go-w) у файлов
популяции CHECK с битом записи для прочих при любом владельце; смена владельца (chown root для
файла обычного пользователя) — решение администратора с готовой командой; новый класс мутации
(смена владельца) не вводится.

* Популяция и классификация — наблюдатель CHECK product-sudo-root-command-files-protection-
  check-v2: OBSERVER_SOURCE — байтовая копия его целиком (совпадение проверяет тест), выполняется
  с подменой print и sys.argv. NOT_APPLICABLE наблюдателя — популяции нет; ERROR — отказ без
  мутаций с причиной наблюдателя. Объекты — записи наблюдателя (разрешённый путь, dev:ino, одна
  жёсткая ссылка — условие CHECK); владелец «обычный пользователь» — функция owner_condition
  наблюдателя на его же снимке.
* Файл с битом 0002 — снятие битов 0022 (`fchmod(fd, mode & ~0o022)`) на дескрипторе файла,
  открытого по разрешённому пути с O_NOFOLLOW | O_NONBLOCK, после сверки dev:ino, типа,
  владельца, группы, режима и числа ссылок; компенсации нет. Владелец — обычный пользователь:
  решение администратора (chown root) независимо от режима. Управляющие байты в пути — решение
  администратора с маркером <invalid-name>.
* Расширенный POSIX ACL (xattr system.posix_acl_access) у любого файла, требующего chmod,
  останавливает весь APPLY контроля до первой мутации (контракт CHECK, acl_policy.future_apply):
  ABORTED_PRECONDITION_CONFLICT и решение администратора. Перед fchmod ACL проверяется повторно
  на дескрипторе (acl-drift). ENOTSUP/EOPNOTSUPP файловой системы — ACL нет.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import sys

ADAPTER_ID = "product-sudo-root-command-files-protection-apply-v1"
MECHANISM_ID = "sudo-root-command-files-protection-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "sudo-root-command-files-protection"
SEMANTIC_CONTRACT_ID = "sudo-root-command-files-protection-apply-semantic-v1"

SUPPORTED_KEYS = ("root-command-files",)
SUPPORTED_OPS = ("root-owned-go-w-conditional",)
EXPECTED_VALUE = "owner-if-regular-user;go-w-if-other-write"
CANONICAL_LOCATOR = "/etc/sudoers"
DEFAULT_VISUDO = "/usr/sbin/visudo"
DEFAULT_CVTSUDOERS = "/usr/bin/cvtsudoers"
DEFAULT_LOGIN_DEFS = "/etc/login.defs"
DEFAULT_ADDUSER_CONF = "/etc/adduser.conf"
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

CONTROLS = ("FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION",)
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
INVALID_NAME = "<invalid-name>"
ADMIN_ACTION = ("Файл, запускаемый через sudo от root, принадлежит обычному пользователю: проверить "
                "назначение и выполнить chown root путь_к_файлу.")

ACL_XATTR = "system.posix_acl_access"
ACL_ACTION = ("У файла, запускаемого через sudo от root, расширенный POSIX ACL: проверить getfacl "
              "путь_к_файлу и снять запись группы и прочих вручную.")

_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC

# Байтовая копия наблюдателя CHECK целиком.
OBSERVER_SOURCE = (
    'import hashlib, json, os, re, stat, subprocess, sys\n'
    'from pathlib import Path\n'
    '\n'
    'fsroot = Path(sys.argv[1])\n'
    'sudoers_path = Path(sys.argv[2])\n'
    'visudo_path = sys.argv[3]\n'
    'cvtsudoers_path = sys.argv[4]\n'
    'login_defs_path = Path(sys.argv[5])\n'
    'adduser_conf_path = Path(sys.argv[6])\n'
    'ALLOWED_COMMAND_KEYS = {"command", "negated", "sha224", "sha256", "sha384", "sha512"}\n'
    'WILDCARD_CHARS = set("*?[")\n'
    'UID_RANGE_LINE = re.compile(r"^\\s*([A-Z_]+)\\s+([0-9]+)\\s*$")\n'
    'CONF_RANGE_LINE = re.compile(r"^\\s*([A-Z_]+)\\s*=\\s*\\"?([0-9]+)\\"?\\s*$")\n'
    'RANGE_KEY_HEAD = re.compile(r"^\\s*([A-Za-z_][A-Za-z0-9_]*)")\n'
    '\n'
    '\n'
    'def error(reason):\n'
    '    print("ERROR\\t" + reason)\n'
    '    raise SystemExit(0)\n'
    '\n'
    '\n'
    'def resolve_cvtsudoers(primary):\n'
    '    # Ubuntu 26.04 with sudo-rs active: package sudo installs cvtsudoers as cvtsudoers.ws.\n'
    '    if os.path.lexists(primary):\n'
    '        return primary\n'
    '    fallback = primary + ".ws"\n'
    '    try:\n'
    '        st = os.stat(fallback)\n'
    '    except FileNotFoundError:\n'
    '        return primary\n'
    '    except Exception:\n'
    '        error("cvtsudoers:fallback-stat-failed")\n'
    '    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.geteuid()) or stat.S_IMODE(st.st_mode) & 0o022:\n'
    '        error("cvtsudoers:untrusted-fallback")\n'
    '    return fallback\n'
    '\n'
    '\n'
    'def obj_state(st):\n'
    '    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)\n'
    '\n'
    '\n'
    'def map_target(logical):\n'
    '    return fsroot / logical.lstrip("/")\n'
    '\n'
    '\n'
    'def stable_regular_bytes(path, domain):\n'
    '    try:\n'
    '        first = os.lstat(path)\n'
    '    except Exception:\n'
    '        error(domain + ":lstat-failed")\n'
    '    if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):\n'
    '        error(domain + ":invalid-type")\n'
    '    try:\n'
    '        raw = path.read_bytes()\n'
    '        second = os.lstat(path)\n'
    '    except Exception:\n'
    '        error(domain + ":read-failed")\n'
    '    if obj_state(first) != obj_state(second):\n'
    '        error(domain + ":changed-during-check")\n'
    '    return obj_state(first), raw\n'
    '\n'
    '\n'
    'def observe_pathset(paths, domain):\n'
    '    out = {}\n'
    '    for path_text in sorted(paths):\n'
    '        state, raw = stable_regular_bytes(Path(path_text), domain)\n'
    '        out[path_text] = (state, hashlib.sha256(raw).hexdigest())\n'
    '    return out\n'
    '\n'
    '\n'
    'def policy_snapshot():\n'
    '    # The sudoers pathset is the closure that visudo reports after validating the\n'
    '    # active tree; no reviewed-policy file is read.  Identities and bytes of that\n'
    '    # pathset are part of the snapshot, and the whole snapshot is compared\n'
    '    # between the two policy observations of one check.\n'
    '    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}\n'
    '    try:\n'
    '        proc = subprocess.run([visudo_path, "-c", "-f", str(sudoers_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, check=False)\n'
    '    except Exception:\n'
    '        error("visudo:execution-failed")\n'
    '    if proc.returncode != 0:\n'
    '        error("visudo:validation-failed")\n'
    '    if not proc.stdout:\n'
    '        error("visudo:invalid-output")\n'
    '    if b"\\x00" in proc.stdout or b"\\r" in proc.stdout:\n'
    '        error("visudo:invalid-bytes")\n'
    '    try:\n'
    '        text = proc.stdout.decode("utf-8", errors="strict")\n'
    '    except UnicodeDecodeError:\n'
    '        error("visudo:invalid-bytes")\n'
    '    closure = []\n'
    '    for line in text.splitlines():\n'
    '        suffix = ": parsed OK"\n'
    '        if not line.endswith(suffix):\n'
    '            error("visudo:invalid-output")\n'
    '        path_text = line[:-len(suffix)]\n'
    '        if not path_text.startswith("/") or any(c in path_text for c in "\\x00\\r\\n\\t") or path_text in closure:\n'
    '            error("visudo:invalid-output")\n'
    '        closure.append(path_text)\n'
    '    if not closure or str(sudoers_path) not in closure:\n'
    '        error("visudo:invalid-output")\n'
    '    return tuple(sorted(observe_pathset(closure, "sudoers").items()))\n'
    '\n'
    '\n'
    'def cvt_snapshot():\n'
    '    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}\n'
    '    try:\n'
    '        proc = subprocess.run(\n'
    '            [cvtsudoers_path, "-c", "/dev/null", "-e", "-s", "aliases", "-f", "json", str(sudoers_path)],\n'
    '            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False,\n'
    '        )\n'
    '    except Exception:\n'
    '        error("cvtsudoers:execution-failed")\n'
    '    if proc.returncode != 0 or proc.stderr:\n'
    '        error("cvtsudoers:execution-failed")\n'
    '    if not proc.stdout:\n'
    '        error("cvtsudoers:invalid-output")\n'
    '    if b"\\x00" in proc.stdout:\n'
    '        error("cvtsudoers:invalid-bytes")\n'
    '    try:\n'
    '        data = json.loads(proc.stdout.decode("utf-8", errors="strict"))\n'
    '    except Exception:\n'
    '        error("cvtsudoers:invalid-output")\n'
    '    if not isinstance(data, dict) or set(data) - {"Defaults", "User_Specs"}:\n'
    '        error("cvtsudoers:invalid-output")\n'
    '    defaults = data.get("Defaults", [])\n'
    '    specs = data.get("User_Specs", [])\n'
    '    if not isinstance(defaults, list) or not isinstance(specs, list):\n'
    '        error("cvtsudoers:invalid-output")\n'
    '    return proc.stdout, defaults, specs\n'
    '\n'
    '\n'
    'def reject_enabled_runchroot_options(options):\n'
    '    if options is None:\n'
    '        return\n'
    '    if not isinstance(options, list):\n'
    '        error("sudo-policy:invalid-options")\n'
    '    for obj in options:\n'
    '        if not isinstance(obj, dict):\n'
    '            error("sudo-policy:invalid-options")\n'
    '        if "runchroot" in obj:\n'
    '            if set(obj) != {"runchroot"}:\n'
    '                error("sudo-policy:runchroot-mixed-option")\n'
    '            if obj["runchroot"] is False:\n'
    '                continue\n'
    '            error("sudo-policy:runchroot-enabled")\n'
    '\n'
    '\n'
    'def validate_defaults_shape(defaults):\n'
    '    # Shape validation never depends on admission: an unmodelled Defaults document\n'
    '    # means the policy was not observed completely, and an incompletely observed\n'
    '    # policy cannot yield the determinate NOT_APPLICABLE result.\n'
    '    if not isinstance(defaults, list):\n'
    '        error("sudo-policy:invalid-defaults")\n'
    '    for entry in defaults:\n'
    '        if not isinstance(entry, dict) or set(entry) - {"Binding", "Options"} or "Options" not in entry:\n'
    '            error("sudo-policy:invalid-defaults")\n'
    '        binding = entry.get("Binding")\n'
    '        if binding is not None and (not isinstance(binding, list) or not binding):\n'
    '            error("sudo-policy:invalid-default-binding")\n'
    '        options = entry["Options"]\n'
    '        if not isinstance(options, list):\n'
    '            error("sudo-policy:invalid-options")\n'
    '        for obj in options:\n'
    '            if not isinstance(obj, dict):\n'
    '                error("sudo-policy:invalid-options")\n'
    '            if "runchroot" in obj and set(obj) != {"runchroot"}:\n'
    '                error("sudo-policy:runchroot-mixed-option")\n'
    '\n'
    '\n'
    'def validate_defaults_applicability(defaults):\n'
    '    # Applicability is evaluated only when the population is non-empty: Defaults\n'
    '    # that cannot affect an explicit non-root-only Runas_Spec are out of scope.\n'
    '    for entry in defaults:\n'
    '        options = entry["Options"]\n'
    '        reject_enabled_runchroot_options(options)\n'
    '        for obj in options:\n'
    '            # runas_default changes the implicit Runas_Spec; this adapter does not\n'
    '            # evaluate Defaults binding precedence, so applicability is ambiguous.\n'
    '            if "runas_default" in obj:\n'
    '                error("sudo-policy:runas-default-unsupported")\n'
    '            if "case_insensitive_user" in obj:\n'
    '                error("sudo-policy:case-insensitive-user-unsupported")\n'
    '\n'
    '\n'
    'def one_selector(obj, allowed):\n'
    '    if not isinstance(obj, dict) or set(obj) - (allowed | {"negated"}):\n'
    '        error("sudo-policy:ambiguous-selector")\n'
    '    keys = [k for k in obj if k != "negated"]\n'
    '    if len(keys) != 1 or not isinstance(obj.get("negated", False), bool):\n'
    '        error("sudo-policy:ambiguous-selector")\n'
    '    return keys[0], obj[keys[0]], obj.get("negated", False)\n'
    '\n'
    '\n'
    'def validate_user_list(user_list):\n'
    '    # Invoker identity does not narrow the population: any invoker able to run the\n'
    '    # rule is out of scope for SRC-0008.  Only structural validity is required.\n'
    '    if not isinstance(user_list, list) or not user_list:\n'
    '        error("sudo-policy:invalid-user-list")\n'
    '    for obj in user_list:\n'
    '        if not isinstance(obj, dict) or not obj:\n'
    '            error("sudo-policy:invalid-user-list")\n'
    '\n'
    '\n'
    'def host_scope_supported(host_list):\n'
    '    if not isinstance(host_list, list) or not host_list:\n'
    '        error("sudo-policy:invalid-host-list")\n'
    '    if len(host_list) != 1:\n'
    '        error("sudo-policy:ambiguous-host-selector")\n'
    '    key, value, neg = one_selector(host_list[0], {"hostname", "networkaddr", "netgroup"})\n'
    '    if neg or key != "hostname" or value != "ALL":\n'
    '        error("sudo-policy:unsupported-host-selector")\n'
    '    return True\n'
    '\n'
    '\n'
    'def root_runas_possible(spec):\n'
    '    groups = spec.get("runasgroups")\n'
    '    if groups is not None:\n'
    '        if not isinstance(groups, list):\n'
    '            error("sudo-policy:invalid-runas-list")\n'
    '        # A group part next to a user part, as in (ALL:ALL), only selects the\n'
    '        # target group; admission is decided by the user part below.  A\n'
    '        # group-only Runas_Spec runs the command as the invoking user, which the\n'
    '        # user-part rules below do not model, so it stays fail-closed.\n'
    '        if groups and "runasusers" not in spec:\n'
    '            error("sudo-policy:unsupported-runas-group")\n'
    '    if "runasusers" not in spec:\n'
    '        return True\n'
    '    runas = spec["runasusers"]\n'
    '    if not isinstance(runas, list) or not runas:\n'
    '        error("sudo-policy:invalid-runas-list")\n'
    '    allowed = {"netgroup", "nonunixgid", "nonunixgroup", "runasalias", "usergid", "usergroup", "userid", "username"}\n'
    '    root_possible = False\n'
    '    for obj in runas:\n'
    '        key, value, neg = one_selector(obj, allowed)\n'
    '        if neg or key not in {"username", "userid"}:\n'
    '            error("sudo-policy:unsupported-runas-selector")\n'
    '        if key == "username":\n'
    '            if not isinstance(value, str) or not value:\n'
    '                error("sudo-policy:invalid-runas-selector")\n'
    '            if value == "ALL" or value.casefold() == "root":\n'
    '                root_possible = True\n'
    '            continue\n'
    '        text = str(value)\n'
    '        if not text.isdigit():\n'
    '            error("sudo-policy:invalid-runas-selector")\n'
    '        if int(text, 10) == 0:\n'
    '            root_possible = True\n'
    '    return root_possible\n'
    '\n'
    '\n'
    'def logical_target(command):\n'
    '    if not isinstance(command, str) or not command or any(c in command for c in "\\x00\\r\\n"):\n'
    '        error("sudo-policy:invalid-command")\n'
    '    # sudoedit does not name an executable target of this control; it is excluded\n'
    '    # before any other command-form check.\n'
    '    if command == "sudoedit" or command.startswith("sudoedit "):\n'
    '        return None\n'
    '    # ALL names no concrete executable file of this control; the rights of\n'
    '    # system programs are checked by 2.3.8.  Only explicit absolute pathnames\n'
    '    # enter the population.\n'
    '    if command == "ALL":\n'
    '        return None\n'
    '    if command.startswith("^"):\n'
    '        error("sudo-policy:regex-command")\n'
    '    if not command.startswith("/"):\n'
    '        error("sudo-policy:nonabsolute-command")\n'
    '    if any(c in command for c in WILDCARD_CHARS):\n'
    '        error("sudo-policy:wildcard-command")\n'
    '    if command.endswith("/"):\n'
    '        error("sudo-policy:directory-command")\n'
    '    # cvtsudoers JSON merges pathname and arguments into one string and unescapes\n'
    '    # escaped whitespace inside a pathname, so a command string containing any\n'
    '    # whitespace has no provable pathname boundary.  The filesystem is never used\n'
    '    # as an oracle for that boundary.\n'
    '    if any(ch.isspace() for ch in command):\n'
    '        error("sudo-policy:unprovable-command-path")\n'
    '    parts = command.split("/")\n'
    '    if any(part in {".", ".."} for part in parts) or "\\\\" in command:\n'
    '        error("sudo-policy:nonabsolute-command")\n'
    '    return command\n'
    '\n'
    '\n'
    'def collect_targets(specs):\n'
    '    targets = set()\n'
    '    for user_spec in specs:\n'
    '        if not isinstance(user_spec, dict) or set(user_spec) != {"User_List", "Host_List", "Cmnd_Specs"}:\n'
    '            error("sudo-policy:invalid-user-spec")\n'
    '        validate_user_list(user_spec["User_List"])\n'
    '        host_list = user_spec["Host_List"]\n'
    '        if not isinstance(host_list, list) or not host_list:\n'
    '            error("sudo-policy:invalid-host-list")\n'
    '        cmnd_specs = user_spec["Cmnd_Specs"]\n'
    '        if not isinstance(cmnd_specs, list):\n'
    '            error("sudo-policy:invalid-command-specs")\n'
    '        # Admission by runas is decided first: a rule whose targets can only run as\n'
    '        # explicit non-root accounts is outside SRC-0008 and must not be rejected\n'
    '        # because of an unsupported host scope or command option.\n'
    '        admitted = []\n'
    '        for spec in cmnd_specs:\n'
    '            if not isinstance(spec, dict) or "Commands" not in spec or set(spec) - {"Commands", "runasusers", "runasgroups", "Options"}:\n'
    '                error("sudo-policy:invalid-command-spec")\n'
    '            if root_runas_possible(spec):\n'
    '                admitted.append(spec)\n'
    '        if not admitted:\n'
    '            continue\n'
    '        host_scope_supported(host_list)\n'
    '        for spec in admitted:\n'
    '            options = spec.get("Options")\n'
    '            reject_enabled_runchroot_options(options)\n'
    '            if options is not None:\n'
    '                if not isinstance(options, list):\n'
    '                    error("sudo-policy:invalid-command-options")\n'
    '                for obj in options:\n'
    '                    if not isinstance(obj, dict):\n'
    '                        error("sudo-policy:invalid-command-options")\n'
    '                    if "notbefore" in obj or "notafter" in obj:\n'
    '                        error("sudo-policy:time-qualified-command")\n'
    '            commands = spec["Commands"]\n'
    '            if not isinstance(commands, list) or not commands:\n'
    '                error("sudo-policy:invalid-command-list")\n'
    '            for obj in commands:\n'
    '                if not isinstance(obj, dict) or set(obj) - ALLOWED_COMMAND_KEYS:\n'
    '                    error("sudo-policy:invalid-command-entry")\n'
    '                if "command" not in obj or not isinstance(obj.get("negated", False), bool):\n'
    '                    error("sudo-policy:invalid-command-entry")\n'
    '                if any(key in obj for key in ("sha224", "sha256", "sha384", "sha512")):\n'
    '                    error("sudo-policy:digest-qualified-command")\n'
    '                if obj.get("negated", False):\n'
    '                    error("sudo-policy:negated-command")\n'
    '                target = logical_target(obj["command"])\n'
    '                if target is not None:\n'
    '                    targets.add(target)\n'
    '    return tuple(sorted(targets, key=os.fsencode))\n'
    '\n'
    '\n'
    'def stable_target(logical):\n'
    '    path = map_target(logical)\n'
    '    try:\n'
    '        link_first = os.lstat(path)\n'
    '        target_first = os.stat(path, follow_symlinks=True)\n'
    '        resolved = os.path.realpath(path)\n'
    '        link_second = os.lstat(path)\n'
    '        target_second = os.stat(path, follow_symlinks=True)\n'
    '    except Exception:\n'
    '        error("target:snapshot-failed")\n'
    '    if obj_state(link_first) != obj_state(link_second) or obj_state(target_first) != obj_state(target_second):\n'
    '        error("target:changed-during-check")\n'
    '    if not stat.S_ISREG(target_first.st_mode) or (stat.S_IMODE(target_first.st_mode) & 0o111) == 0:\n'
    '        error("target:invalid-type")\n'
    '    if fsroot != Path("/"):\n'
    '        try:\n'
    '            Path(resolved).relative_to(fsroot.resolve())\n'
    '        except Exception:\n'
    '            error("target:outside-root")\n'
    '    if target_first.st_nlink != 1:\n'
    '        error("target:ambiguous-identity")\n'
    '    return (logical, resolved, obj_state(link_first), obj_state(target_first))\n'
    '\n'
    '\n'
    'def stable_optional_regular_bytes(path, domain):\n'
    '    try:\n'
    '        first = os.lstat(path)\n'
    '    except FileNotFoundError:\n'
    '        # Absence is a legitimate state for the two optional UID-range sources.\n'
    '        # It is recorded so that the final owner-authority revalidation can detect\n'
    '        # an absent->present transition.\n'
    '        try:\n'
    '            os.lstat(path)\n'
    '        except FileNotFoundError:\n'
    '            return ("ABSENT",), None\n'
    '        except Exception:\n'
    '            error(domain + ":stat-failed")\n'
    '        error(domain + ":changed-during-check")\n'
    '    except Exception:\n'
    '        error(domain + ":stat-failed")\n'
    '    if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):\n'
    '        error(domain + ":invalid-type")\n'
    '    try:\n'
    '        raw = path.read_bytes()\n'
    '        second = os.lstat(path)\n'
    '    except Exception:\n'
    '        error(domain + ":read-failed")\n'
    '    if obj_state(first) != obj_state(second):\n'
    '        error(domain + ":changed-during-check")\n'
    '    return ("PRESENT", obj_state(first), hashlib.sha256(raw).hexdigest()), raw\n'
    '\n'
    '\n'
    'def read_uid_range(path, pattern, keys, domain):\n'
    '    mapped = map_target(str(path))\n'
    '    snapshot, raw = stable_optional_regular_bytes(mapped, domain)\n'
    '    if raw is None:\n'
    '        return None, snapshot\n'
    '    if b"\\x00" in raw:\n'
    '        error(domain + ":invalid-bytes")\n'
    '    try:\n'
    '        text = raw.decode("utf-8", errors="strict")\n'
    '    except UnicodeDecodeError:\n'
    '        error(domain + ":invalid-bytes")\n'
    '    found = {}\n'
    '    named = False\n'
    '    for line in text.splitlines():\n'
    '        if not line or line.lstrip().startswith("#"):\n'
    '            continue\n'
    '        head = RANGE_KEY_HEAD.match(line)\n'
    '        if head is not None and head.group(1).upper() in keys:\n'
    '            named = True\n'
    '        match = pattern.match(line)\n'
    '        if match is None:\n'
    '            continue\n'
    '        name, value = match.group(1), match.group(2)\n'
    '        if name not in keys:\n'
    '            continue\n'
    '        if name in found:\n'
    '            error(domain + ":duplicate-key")\n'
    '        found[name] = int(value, 10)\n'
    '    # An existing source without any active line that names a key of the pair (for\n'
    '    # example, adduser.conf of newer adduser versions with the defaults commented out)\n'
    '    # gives no range and is treated like an absent source. A named key with a value that\n'
    '    # does not match the range line, or one key of the pair without the other, makes the\n'
    '    # source unusable, and an unusable source is an error rather than an absent one.\n'
    '    if not found and not named:\n'
    '        return None, snapshot\n'
    '    if set(found) != set(keys):\n'
    '        error(domain + ":incomplete-range")\n'
    '    low, high = found[keys[0]], found[keys[1]]\n'
    '    if low > high:\n'
    '        error(domain + ":invalid-range")\n'
    '    return (low, high), snapshot\n'
    '\n'
    '\n'
    'def passwd_snapshot():\n'
    '    mapped = map_target("/etc/passwd")\n'
    '    state, raw = stable_regular_bytes(mapped, "passwd")\n'
    '    if b"\\x00" in raw or b"\\r" in raw:\n'
    '        error("passwd:invalid-bytes")\n'
    '    try:\n'
    '        text = raw.decode("utf-8", errors="strict")\n'
    '    except UnicodeDecodeError:\n'
    '        error("passwd:invalid-bytes")\n'
    '    by_uid = {}\n'
    '    for line in text.splitlines():\n'
    '        if not line:\n'
    '            continue\n'
    '        fields = line.split(":")\n'
    '        if len(fields) != 7:\n'
    '            error("passwd:invalid-record")\n'
    '        if not fields[2].isdigit():\n'
    '            error("passwd:invalid-record")\n'
    '        uid = int(fields[2], 10)\n'
    '        by_uid.setdefault(uid, set()).add(fields[0])\n'
    '    names = {uid: tuple(sorted(values)) for uid, values in by_uid.items()}\n'
    '    snapshot = (state, hashlib.sha256(raw).hexdigest())\n'
    '    return snapshot, names\n'
    '\n'
    '\n'
    'def owner_sources():\n'
    '    ranges = []\n'
    '    tokens = []\n'
    '\n'
    '    login, login_token = read_uid_range(\n'
    '        login_defs_path, UID_RANGE_LINE, ("UID_MIN", "UID_MAX"), "login-defs")\n'
    '    tokens.append(("login-defs", login_token))\n'
    '    if login is not None:\n'
    '        ranges.append(login)\n'
    '\n'
    '    adduser, adduser_token = read_uid_range(\n'
    '        adduser_conf_path, CONF_RANGE_LINE, ("FIRST_UID", "LAST_UID"), "adduser-conf")\n'
    '    tokens.append(("adduser-conf", adduser_token))\n'
    '    if adduser is not None:\n'
    '        ranges.append(adduser)\n'
    '\n'
    '    if not ranges:\n'
    '        # Without any usable range source a non-root owner cannot be classified as\n'
    '        # regular or non-regular, and a fallback default would invent authority.\n'
    '        error("owner-classification:no-source")\n'
    '\n'
    '    passwd_token, passwd_names = passwd_snapshot()\n'
    '    tokens.append(("passwd", passwd_token))\n'
    '    return tuple(ranges), passwd_names, tuple(tokens)\n'
    '\n'
    '\n'
    'def owner_condition(uid, ranges, passwd_names):\n'
    '    if uid == 0:\n'
    '        return False\n'
    '    names = passwd_names.get(uid, ())\n'
    '    if not names:\n'
    '        error("owner-classification:unknown-uid")\n'
    '    if len(names) != 1:\n'
    '        error("owner-classification:ambiguous-uid")\n'
    '    verdicts = {low <= uid <= high for (low, high) in ranges}\n'
    '    if len(verdicts) != 1:\n'
    '        error("owner-classification:conflicting-sources")\n'
    '    return verdicts.pop()\n'
    '\n'
    '\n'
    'cvtsudoers_path = resolve_cvtsudoers(cvtsudoers_path)\n'
    'policy_before = policy_snapshot()\n'
    'cvt_before, defaults, specs = cvt_snapshot()\n'
    '\n'
    '# Population admission is decided before semantic Defaults validation.  Defaults\n'
    '# that cannot affect an explicit non-root-only Runas_Spec are outside SRC-0008 and\n'
    '# must not turn a clean empty population into ERROR.  When at least one target is\n'
    '# admitted, the current fail-closed Defaults boundary remains unchanged.\n'
    'validate_defaults_shape(defaults)\n'
    'targets = collect_targets(specs)\n'
    'if not targets:\n'
    '    policy_after = policy_snapshot()\n'
    '    cvt_after, defaults_after, specs_after = cvt_snapshot()\n'
    '    validate_defaults_shape(defaults_after)\n'
    '    if policy_after != policy_before or cvt_after != cvt_before or collect_targets(specs_after) != ():\n'
    '        error("observation:policy-changed")\n'
    '    print("NOT_APPLICABLE\\tfiles=0;owner_violations=0;mode_violations=0\\tNOT_APPLICABLE")\n'
    '    raise SystemExit(0)\n'
    '\n'
    'validate_defaults_applicability(defaults)\n'
    'records = {logical: stable_target(logical) for logical in targets}\n'
    '\n'
    '# UID 0 is decided without OWNER classification sources.  For any non-root owner,\n'
    '# capture all OWNER-authority inputs once, classify only from that snapshot, then\n'
    '# re-read and compare those inputs after the second policy/cvtsudoers snapshot.\n'
    'owner_before = None\n'
    'ranges = ()\n'
    'passwd_names = {}\n'
    'if any(rec[3][2] != 0 for rec in records.values()):\n'
    '    ranges, passwd_names, owner_before = owner_sources()\n'
    '\n'
    'owner_bad = 0\n'
    'mode_bad = 0\n'
    'for rec in records.values():\n'
    '    state = rec[3]\n'
    '    if owner_condition(state[2], ranges, passwd_names):\n'
    '        owner_bad += 1\n'
    '    if state[4] & 0o002:\n'
    '        mode_bad += 1\n'
    '\n'
    'policy_after = policy_snapshot()\n'
    'cvt_after, defaults_after, specs_after = cvt_snapshot()\n'
    'validate_defaults_shape(defaults_after)\n'
    'validate_defaults_applicability(defaults_after)\n'
    'if policy_after != policy_before or cvt_after != cvt_before or collect_targets(specs_after) != targets:\n'
    '    error("observation:policy-changed")\n'
    '\n'
    'if owner_before is not None:\n'
    '    ranges_after, passwd_names_after, owner_after = owner_sources()\n'
    '    if owner_after != owner_before:\n'
    '        error("owner-authority:changed-during-check")\n'
    '\n'
    'for logical, before in records.items():\n'
    '    if stable_target(logical) != before:\n'
    '        error("observation:target-changed")\n'
    '\n'
    'print("VALUE\\tfiles=%d;owner_violations=%d;mode_violations=%d\\t%s" % (\n'
    '    len(targets), owner_bad, mode_bad, "PASS" if owner_bad == 0 and mode_bad == 0 else "FAIL"))\n'
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
        raise ValueError("unsupported expected value")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _errname(exc):
    return errno.errorcode.get(exc.errno, str(exc.errno))


def _bad_bytes(text):
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in text)


def observe(fsroot="/", sudoers=CANONICAL_LOCATOR, visudo=DEFAULT_VISUDO, cvtsudoers=DEFAULT_CVTSUDOERS,
            login_defs=DEFAULT_LOGIN_DEFS, adduser_conf=DEFAULT_ADDUSER_CONF):
    """(error_reason|None, items): items — (логический путь, запись, owner_bad, other_write)."""
    captured = []

    def capture(*args, **_kw):
        captured.append(" ".join(str(a) for a in args))

    saved = sys.argv
    sys.argv = ["slp-sudo-observer", str(fsroot), str(sudoers), visudo, cvtsudoers, str(login_defs),
                str(adduser_conf)]
    ns = {"__name__": "slp_sudo_observer", "print": capture}
    try:
        exec(compile(OBSERVER_SOURCE, "<sudo-observer>", "exec"), ns)
    except SystemExit:
        last = captured[-1] if captured else ""
        if last.startswith("NOT_APPLICABLE\t"):
            return None, []
        if last.startswith("ERROR\t"):
            return last.split("\t", 1)[1], None
        return "observer:exit", None
    finally:
        sys.argv = saved
    last = captured[-1] if captured else ""
    if not last.startswith("VALUE\t") or "records" not in ns:
        return "observer:invalid-output", None
    items = []
    for logical in sorted(ns["records"]):
        rec = ns["records"][logical]
        try:
            owner_bad = bool(ns["owner_condition"](rec[3][2], ns["ranges"], ns["passwd_names"]))
        except SystemExit:
            return "owner-classification:failed", None
        items.append((logical, rec, owner_bad, bool(rec[3][4] & 0o002)))
    return None, items


def plan(observer=None):
    """(error_reason|None, objects): объекты по записям наблюдателя; действие — chmod и/или решение."""
    error, items = (observer or observe)()
    if error is not None:
        return error, []
    objects = []
    for logical, rec, owner_bad, other_write in items:
        shown = INVALID_NAME if _bad_bytes(logical) or _bad_bytes(rec[1]) else logical
        state = rec[3]
        if shown == INVALID_NAME and (owner_bad or other_write):
            objects.append({"kind": "admin", "path": shown, "real": rec[1], "reason": "target:invalid-name",
                            "state": state})
            continue
        if other_write:
            objects.append({"kind": "plan", "path": shown, "real": rec[1], "reason": None, "state": state})
        if owner_bad:
            objects.append({"kind": "admin", "path": shown, "real": rec[1], "reason": "owner:regular-user",
                            "state": state})
        if not other_write and not owner_bad:
            objects.append({"kind": "ok", "path": shown, "real": rec[1], "reason": None, "state": state})
    return None, objects


def _acl_names(fd, listxattr):
    """Имена xattr дескриптора; ENOTSUP/EOPNOTSUPP — ACL нет."""
    try:
        return listxattr(fd)
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return []
        raise


def _acl_blocker(planned, listxattr):
    """(outcome, reason) первого препятствия по ACL среди файлов плана или None."""
    for item in planned:
        try:
            fd = os.open(item["real"], _FILE_FLAGS)
        except OSError as exc:
            return "ABORTED_PRECONDITION_OTHER", "acl:open:%s:%s" % (_errname(exc), item["path"])
        try:
            names = _acl_names(fd, listxattr)
        except OSError as exc:
            return "ABORTED_PRECONDITION_OTHER", "acl:read:%s:%s" % (_errname(exc), item["path"])
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        if ACL_XATTR in names:
            return "ABORTED_PRECONDITION_CONFLICT", "acl:extended:%s" % item["path"]
    return None


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


def _apply_one(item, fchmod, listxattr=os.listxattr):
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
        result = _apply_fd(fd, item["state"], item["path"], fchmod, state, listxattr)
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


def _apply_fd(fd, observed, path, fchmod, state, listxattr=os.listxattr):
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
    if ACL_XATTR in _acl_names(fd, listxattr):
        return False, "acl-drift"
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
    _observer=None,
    privilege_check=None,
    _fchmod=None,
    _listxattr=None,
):
    """chmod go-w файлов, запускаемых через sudo от root; смена владельца — администратору."""
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if control_id not in CONTROLS:
        return done("ABORTED_PRECONDITION_OTHER", reason="target:unmapped-control")

    actions.append("P1_POPULATION")
    error, objects = plan(_observer)
    if error is not None:
        return done("ABORTED_PRECONDITION_OTHER", reason="check:" + error)

    actions.append("P2_PLAN")
    planned = [item for item in objects if item["kind"] == "plan"]
    admin = [item for item in objects if item["kind"] == "admin"]
    skipped = [{"path": item["path"], "reason": item["reason"]} for item in admin]
    files = len({item["path"] for item in objects})
    current = "files=%d;mode_violations=%d;admin=%d" % (files, len(planned), len(admin))
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

    actions.append("P2_ACL")
    listxattr = _listxattr if _listxattr is not None else os.listxattr
    blocker = _acl_blocker(planned, listxattr)
    if blocker is not None:
        return done(blocker[0], reason=blocker[1], current_mode=current, violators=violators, skipped=skipped,
                    operator_decision={"required": True, "class": "ADMIN_ACTION_REQUIRED", "action": ACL_ACTION})
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
            changed, failure = _apply_one(item, fchmod, listxattr)
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
