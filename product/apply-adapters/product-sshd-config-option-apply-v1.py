#!/usr/bin/env python3
"""product-sshd-config-option-apply-v1.

APPLY adapter for mechanism `sshd-config-option-v1` (fstec-configuration-2026 п.9.1,
SRC-0088): `PermitEmptyPasswords no`, `PermitRootLogin no`, `PasswordAuthentication no`
в основном `/etc/ssh/sshd_config`.

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-sshd-config-option-v1.json

Решения пользователя: APPLY для трёх директив п.9.1 выполняется (25.09.2026, требование
политики компании); правка на месте, без дублирования строк (схема 1–4, 26.09.2026):

1. Действующая глобальная строка ключа в основном файле — значение меняется на `no`.
2. Действующей нет, есть закомментированный шаблон `#<Key> …` в глобальной области —
   он заменяется строкой `<Key> no` на том же месте.
3. Нет ни того, ни другого — `<Key> no` добавляется перед первым `Match` или в конец.
4. Включаемые файлы (`Include`, глобальная область), где ключ задан не `no`, правятся
   на месте: значение меняется на `no` — иначе они перекрыли бы основной файл
   (sshd берёт первое прочитанное значение).

Изменённые файлы пишутся через временный файл (режим и владелец прежние), затем
`sshd -t`, `systemctl try-reload-or-restart ssh.service` и итоговая проверка `sshd -T`.
Ошибка проверки, перезагрузки или итоговой проверки — прежние байты всех изменённых
файлов возвращаются (после попытки перезагрузки sshd перезагружается повторно).

Отказ с блоком «решение администратора», без записи:
- изменяемый файл не является обычным файлом root без записи для группы и прочих;
- в области `Match` (основной файл или включаемые) директива задана не `no`;
- `PermitRootLogin`: в группах `sudo` и `admin` нет пользователя, кроме root;
- `PasswordAuthentication`: ни у одного такого пользователя нет непустого
  `~/.ssh/authorized_keys` (или `authorized_keys2`), либо `AuthorizedKeysFile`/
  `PubkeyAuthentication` отличаются от значений по умолчанию.
"""

from __future__ import annotations

import glob
import os
import re
import shlex
import stat
import subprocess

ADAPTER_ID = "product-sshd-config-option-apply-v1"
MECHANISM_ID = "sshd-config-option-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "sshd-config-option"

CONTROL_KEYS = {
    "FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION": "PasswordAuthentication",
    "FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS": "PermitEmptyPasswords",
    "FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN": "PermitRootLogin",
}
EXPECTED_OP = "eq"
EXPECTED_VALUE = "no"

SSHD_CONFIG = "/etc/ssh/sshd_config"
SSH_DIR = "/etc/ssh"
GROUP = "/etc/group"
PASSWD = "/etc/passwd"
SSHD = "/usr/sbin/sshd"
SYSTEMCTL = "/usr/bin/systemctl"
SSH_UNIT = "ssh.service"
EFFECTIVE_SPEC = "user=root,host=localhost,addr=127.0.0.1"
TOOL_TIMEOUT = 60
MAX_INCLUDE_DEPTH = 16
SUDO_GROUPS = ("sudo", "admin")
DEFAULT_AUTHORIZED_KEYS = (
    (".ssh/authorized_keys", ".ssh/authorized_keys2"),
    (".ssh/authorized_keys",),
)

ACTION_FILE = ("{path} не является обычным файлом root без записи для группы и прочих: задайте "
               "«{key} no» в /etc/ssh/sshd_config и уберите иные значения {key} вручную.")
ACTION_MATCH = ("в блоке Match файла sshd_config или включаемого файла {key} задан не «no»: глобальное "
                "значение его не перекрывает; исправьте блок Match вручную.")
ACTION_NO_SUDO = ("в группах sudo и admin нет пользователя, кроме root: после запрета входа root по SSH "
                  "удалённо администрировать сервер будет некому; назначьте администратора в группу sudo "
                  "или задайте «PermitRootLogin no» вручную.")
ACTION_NO_KEY = ("ни у одного пользователя групп sudo и admin нет ключа в ~/.ssh/authorized_keys: после "
                 "запрета входа по паролю вход по SSH станет невозможен; добавьте ключ администратору или "
                 "задайте «PasswordAuthentication no» вручную.")
ACTION_KEYS_SETUP = ("AuthorizedKeysFile или PubkeyAuthentication отличаются от значений по умолчанию: наличие "
                     "ключей администраторов не проверено; задайте «PasswordAuthentication no» вручную.")

OUTCOMES = (
    "APPLIED",
    "ALREADY_COMPLIANT",
    "DRY_RUN_WOULD_APPLY",
    "NOT_ELIGIBLE_APPLY_UNSUPPORTED",
    "ABORTED_PRECONDITION_CONFLICT",
    "ABORTED_PRECONDITION_OTHER",
    "FAILED_NOT_COMMITTED",
    "FAILED_COMPENSATION",
)
COMMIT_COMMITTED = "COMMITTED"
COMMIT_NOT_COMMITTED = "NOT_COMMITTED"
COMMIT_NOT_STARTED = "NOT_STARTED"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
DIRECTIVE_RE = re.compile(r"^[ \t]*([^ \t=]+)(?:[ \t]*=[ \t]*|[ \t]+)(.*)$")
BARE_DIRECTIVE_RE = re.compile(r"^[ \t]*([^ \t=]+)[ \t]*$")
VALUE_RE = re.compile(r"^([ \t]*[^ \t=]+(?:[ \t]*=[ \t]*|[ \t]+))(\S+)(.*)$")
GLOB_CHARS = ("*", "?", "[")


class _Refused(Exception):
    def __init__(self, outcome, reason, decision=None):
        super().__init__(reason)
        self.outcome = outcome
        self.reason = reason
        self.decision = decision


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not isinstance(key, str) or not isinstance(op, str) or not isinstance(expected, str):
        raise ValueError("key, op and expected must be strings")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _p(root, path):
    return path if root is None else os.path.join(root, path.lstrip("/"))


def _admin(action):
    return {"class": "ADMIN_ACTION_REQUIRED", "required": True, "action": action}


def _other(reason):
    return _Refused("ABORTED_PRECONDITION_OTHER", reason)


def _read_regular(path, refuse):
    """(байты, stat) обычного файла без перехода по ссылке; не обычный файл — `refuse`."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise _other("sshd-config:read-failed")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise refuse
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks), st


def _trusted(st, root):
    return not stat.S_IMODE(st.st_mode) & 0o022 and (root is not None or st.st_uid == 0)


def _text(raw):
    if b"\x00" in raw or re.search(rb"\r(?!\n)", raw):
        raise _other("sshd-config:invalid-bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _other("sshd-config:invalid-bytes")


def _body(line):
    """Строка без окончания (\\n или \\r\\n)."""
    if line.endswith("\r\n"):
        return line[:-2]
    return line[:-1] if line.endswith("\n") else line


def _eol(line):
    if line.endswith("\r\n"):
        return "\r\n"
    return "\n" if line.endswith("\n") else ""


def _directive(line):
    """(ключ в нижнем регистре, аргументы) значимой строки или None."""
    body = _body(line)
    if not body.strip() or body.lstrip(" \t").startswith("#"):
        return None
    m = DIRECTIVE_RE.match(body) or BARE_DIRECTIVE_RE.match(body)
    if m is None:
        return None
    rest = m.group(2) if m.re is DIRECTIVE_RE else ""
    try:
        args = shlex.split(rest, comments=True, posix=True)
    except ValueError:
        raise _other("sshd-config:invalid-arguments")
    return m.group(1).lower(), args


def _include_targets(root, pattern):
    path = pattern if pattern.startswith("/") else SSH_DIR + "/" + pattern
    if any(ch in path for ch in GLOB_CHARS):
        return sorted(glob.glob(_p(root, path)))
    real = _p(root, path)
    return [real] if os.path.lexists(real) else []


class Config:
    """Разобранное дерево sshd_config для одного ключа.

    Семантика та же, что у CHECK sshd-config-option: `Match` открывает область до
    конца файла; включаемый файл наследует область строки `Include`; глобальные `no`
    считаются только в основном файле.
    """

    def __init__(self, root, lkey):
        self.root = root
        self.lkey = lkey
        self.main = _p(root, SSHD_CONFIG)
        self.files = {}      # путь -> (байты, stat, строки с окончаниями)
        self.occurrences = []  # (путь, индекс строки, область, основной файл, значение)
        self.main_match_index = None
        self.main_template_index = None
        self._stack = set()
        self._parse(self.main, 0, True, "GLOBAL")

    def _load(self, path, main):
        if path not in self.files:
            refuse = (_Refused("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted", None) if main
                      else _other("sshd-config:include-invalid-type"))
            raw, st = _read_regular(path, refuse)
            self.files[path] = (raw, st, _text(raw).splitlines(keepends=True))
        return self.files[path][2]

    def _parse(self, path, depth, main, scope):
        if depth > MAX_INCLUDE_DEPTH:
            raise _other("sshd-config:include-depth")
        ident = os.path.realpath(path)
        if ident in self._stack:
            raise _other("sshd-config:include-cycle")
        self._stack.add(ident)
        template = re.compile(r"^[ \t]*#[ \t]*" + re.escape(self.lkey) + r"(?:[ \t=]|$)", re.IGNORECASE)
        for index, line in enumerate(self._load(path, main)):
            if main and scope == "GLOBAL" and self.main_template_index is None and template.match(_body(line)):
                self.main_template_index = index
            parsed = _directive(line)
            if parsed is None:
                continue
            key, args = parsed
            if key == "match":
                if not args:
                    raise _other("sshd-config:invalid-match")
                if main and self.main_match_index is None:
                    self.main_match_index = index
                scope = "MATCH"
            elif key == "include":
                if not args:
                    raise _other("sshd-config:invalid-include")
                for pattern in args:
                    for item in _include_targets(self.root, pattern):
                        if os.path.islink(item):
                            raise _other("sshd-config:include-symlink")
                        self._parse(item, depth + 1, False, scope)
            elif key == self.lkey:
                if len(args) != 1 or "=" in args[0]:
                    raise _other("sshd-config:invalid-directive")
                self.occurrences.append((path, index, scope, main, args[0].lower()))
        self._stack.discard(ident)

    @property
    def main_global_no(self):
        return sum(1 for o in self.occurrences if o[3] and o[2] == "GLOBAL" and o[4] == EXPECTED_VALUE)

    @property
    def match_non_no(self):
        return sum(1 for o in self.occurrences if o[2] == "MATCH" and o[4] != EXPECTED_VALUE)

    def plan(self, key):
        """{путь: новые байты} по схеме 1–4; пустой план невозможен при несоответствии."""
        lines = {path: list(rec[2]) for path, rec in self.files.items()}
        changed = set()
        main_global = False
        for path, index, scope, main, value in self.occurrences:
            if scope != "GLOBAL":
                continue
            main_global = main_global or main
            if value == EXPECTED_VALUE:
                continue
            line = lines[path][index]
            m = VALUE_RE.match(_body(line))
            if m is None:
                raise _other("sshd-config:invalid-directive")
            lines[path][index] = m.group(1) + EXPECTED_VALUE + m.group(3) + _eol(line)
            changed.add(path)
        if not main_global:
            main_lines = lines[self.main]
            new_line = key + " " + EXPECTED_VALUE
            if self.main_template_index is not None:
                old = main_lines[self.main_template_index]
                main_lines[self.main_template_index] = new_line + (_eol(old) or "\n")
            elif self.main_match_index is not None:
                main_lines.insert(self.main_match_index, new_line + "\n")
            else:
                if main_lines and not _eol(main_lines[-1]):
                    main_lines[-1] += "\n"
                main_lines.append(new_line + "\n")
            changed.add(self.main)
        return {path: "".join(lines[path]).encode("utf-8") for path in sorted(changed)}


def _default_run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def _call(run, argv):
    try:
        return run(argv, TOOL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _check_tools(root, paths):
    for path in paths:
        try:
            st = os.stat(_p(root, path))
        except OSError:
            raise _other("tools:missing:" + os.path.basename(path))
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            raise _other("tools:missing:" + os.path.basename(path))


def _syntax_ok(root, run):
    cp = _call(run, [_p(root, SSHD), "-t", "-f", _p(root, SSHD_CONFIG)])
    return cp is not None and cp.returncode == 0


def effective_settings(root, run):
    """Действующие значения `sshd -T` (ключи в нижнем регистре; повтор ключа — None)."""
    cp = _call(run, [_p(root, SSHD), "-T", "-C", EFFECTIVE_SPEC, "-f", _p(root, SSHD_CONFIG)])
    if cp is None or cp.returncode != 0:
        raise _other("sshd-effective:query-failed")
    try:
        out = cp.stdout.decode("utf-8") if isinstance(cp.stdout, bytes) else cp.stdout
    except UnicodeDecodeError:
        raise _other("sshd-effective:query-failed")
    values = {}
    for line in out.split("\n"):
        parts = line.rstrip("\r").split(None, 1)
        if not parts:
            continue
        name = parts[0].lower()
        values[name] = None if name in values else (parts[1].strip() if len(parts) == 2 else "")
    return values


def _effective_value(values, lkey):
    value = values.get(lkey)
    if value is None or not value or len(value.split()) != 1:
        raise _other("sshd-effective:ambiguous-value")
    return value.lower()


def policy_current(main_no, effective):
    return "main_global_no=%d;effective=%s" % (main_no, effective)


def _read_groups(root):
    try:
        with open(_p(root, GROUP), "r", encoding="utf-8", errors="strict") as stream:
            lines = stream.read().split("\n")
    except (OSError, UnicodeDecodeError):
        raise _other("group:read-failed")
    groups = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 4:
            raise _other("group:invalid-line")
        groups.setdefault(fields[0], [m for m in fields[3].split(",") if m])
    return groups


def _read_homes(root):
    try:
        with open(_p(root, PASSWD), "r", encoding="utf-8", errors="strict") as stream:
            lines = stream.read().split("\n")
    except (OSError, UnicodeDecodeError):
        raise _other("passwd:read-failed")
    homes = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 7:
            raise _other("passwd:invalid-line")
        homes.setdefault(fields[0], fields[5])
    return homes


def admin_users(groups):
    """Участники групп sudo и admin (поле участников /etc/group), кроме root."""
    users = []
    for name in SUDO_GROUPS:
        for member in groups.get(name, []):
            if member != "root" and member not in users:
                users.append(member)
    return users


def _has_key(root, home, rel):
    if not home.startswith("/"):
        return False
    try:
        raw, _st = _read_regular(_p(root, home.rstrip("/") + "/" + rel), _other("keys:invalid-type"))
    except _Refused:
        return False
    return any(l.strip() and not l.strip().startswith("#")
               for l in raw.decode("utf-8", errors="replace").split("\n"))


def keyed_admins(root, users, key_files):
    homes = _read_homes(root)
    return [u for u in users if u in homes and any(_has_key(root, homes[u], rel) for rel in key_files)]


def _write_file(path, raw, st):
    """Замена файла через временный файл в том же каталоге; режим и владелец прежние."""
    tmp = path + ".slp-tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, raw)
        os.fchmod(fd, stat.S_IMODE(st.st_mode))
        if os.geteuid() == 0:
            os.fchown(fd, st.st_uid, st.st_gid)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(tmp)
        raise
    os.close(fd)
    os.replace(tmp, path)


def _reload(root, run):
    cp = _call(run, [_p(root, SYSTEMCTL), "try-reload-or-restart", SSH_UNIT])
    return cp is not None and cp.returncode == 0


def _default_privilege_check() -> bool:
    return os.geteuid() == 0


def _commit_state(outcome, dry_run, mutation):
    if outcome == "APPLIED" or (outcome == "ALREADY_COMPLIANT" and not dry_run):
        return COMMIT_COMMITTED
    if mutation:
        return COMMIT_NOT_COMMITTED
    return COMMIT_NOT_STARTED


def _result(control_id, outcome, *, actions, dry_run, mutation=False, **extra):
    record = {
        "adapter_id": ADAPTER_ID,
        "mechanism_id": MECHANISM_ID,
        "control_id": control_id,
        "target": SSHD_CONFIG,
        "outcome": outcome,
        "reason": None,
        "policy_current": None,
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


def outcome_rc_contribution(outcome, dry_run=False):
    """"0" для успешных исходов, иначе "nonzero"."""
    if outcome in ("APPLIED", "ALREADY_COMPLIANT", "NOT_ELIGIBLE_APPLY_UNSUPPORTED"):
        return "0"
    if dry_run and outcome == "DRY_RUN_WOULD_APPLY":
        return "0"
    return "nonzero"


def _observe(root, run, key):
    """(Config, действующее значение, все значения sshd -T)."""
    lkey = key.lower()
    try:
        cfg = Config(root, lkey)
    except _Refused as exc:
        if exc.reason == "sshd-config:untrusted":
            raise _Refused(exc.outcome, exc.reason, _admin(ACTION_FILE.format(path=SSHD_CONFIG, key=key)))
        raise
    if cfg.match_non_no:
        raise _Refused("ABORTED_PRECONDITION_CONFLICT", "sshd-config:ambiguous-match",
                       _admin(ACTION_MATCH.format(key=key)))
    if not _syntax_ok(root, run):
        raise _other("sshd-config:validation-failed")
    values = effective_settings(root, run)
    return cfg, _effective_value(values, lkey), values


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None, _write=None):
    """Set `<key> no` in /etc/ssh/sshd_config in place (scheme 1–4) and reload sshd.

    `_root`, `_run` и `_write` — только для тестов: корень файловой системы, запуск
    команд и запись файла (`_write(путь, байты, stat)`).
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run
    write = _write if _write is not None else _write_file
    current = None

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, policy_current=current, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if CONTROL_KEYS.get(control_id) != key or op != EXPECTED_OP or expected != EXPECTED_VALUE:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    try:
        actions.append("P1_OBSERVE")
        _check_tools(_root, [SSHD, SYSTEMCTL])
        cfg, effective, values = _observe(_root, run, key)
        current = policy_current(cfg.main_global_no, effective)
        if cfg.main_global_no > 0 and effective == EXPECTED_VALUE:
            return done("ALREADY_COMPLIANT")

        actions.append("P2_PLAN")
        users = admin_users(_read_groups(_root))
        if key == "PermitRootLogin" and not users:
            raise _Refused("ABORTED_PRECONDITION_CONFLICT", "ssh:no-sudo-members", _admin(ACTION_NO_SUDO))
        if key == "PasswordAuthentication":
            key_files = tuple((values.get("authorizedkeysfile") or "").split())
            if key_files not in DEFAULT_AUTHORIZED_KEYS or (values.get("pubkeyauthentication") or "").lower() != "yes":
                raise _Refused("ABORTED_PRECONDITION_CONFLICT", "ssh:keys-setup-nondefault", _admin(ACTION_KEYS_SETUP))
            if not keyed_admins(_root, users, key_files):
                raise _Refused("ABORTED_PRECONDITION_CONFLICT", "ssh:no-keyed-admin", _admin(ACTION_NO_KEY))
        planned = cfg.plan(key)
        for path in planned:
            if not _trusted(cfg.files[path][1], _root):
                shown = SSHD_CONFIG if path == cfg.main else (
                    path if _root is None else "/" + os.path.relpath(path, _root))
                raise _Refused("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted",
                               _admin(ACTION_FILE.format(path=shown, key=key)))
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY")

        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            return done("ABORTED_PRECONDITION_OTHER", reason="privilege")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, operator_decision=exc.decision)

    written = []
    reload_attempted = False

    def compensate(reason):
        actions.append("COMPENSATION")
        ok = True
        for path in reversed(written):
            raw, st, _lines = cfg.files[path]
            try:
                write(path, raw, st)
            except OSError:
                ok = False
        if reload_attempted:
            ok = _reload(_root, run) and ok
        mutated = bool(written)
        if ok:
            return done("FAILED_NOT_COMMITTED", reason=reason, mutation=mutated)
        return done("FAILED_COMPENSATION", reason=reason, mutation=mutated)

    actions.append("PHASE1_CONFIG")
    for path, raw in planned.items():
        try:
            write(path, raw, cfg.files[path][1])
        except OSError:
            return compensate("sshd-config:write-failed")
        written.append(path)
    if not _syntax_ok(_root, run):
        return compensate("sshd-config:validation-failed")
    actions.append("PHASE2_RELOAD")
    reload_attempted = True
    if not _reload(_root, run):
        return compensate("reload:failed")
    actions.append("FINAL_POSTCHECK")
    try:
        after, after_effective, _values = _observe(_root, run, key)
    except _Refused:
        return compensate("postcheck:read-failed")
    current = policy_current(after.main_global_no, after_effective)
    if (any(after.files.get(path, (None,))[0] != raw for path, raw in planned.items())
            or after.main_global_no < 1 or after_effective != EXPECTED_VALUE):
        return compensate("postcheck:not-compliant")
    return done("APPLIED", mutation=True)


def control_result_to_report(result, started_at, finished_at):
    return {
        "adapter_id": result["adapter_id"],
        "mechanism_id": result["mechanism_id"],
        "control_id": result["control_id"],
        "target": result["target"],
        "outcome": result["outcome"],
        "reason": result["reason"],
        "policy_current": result["policy_current"],
        "operator_decision": None if result["operator_decision"] is None else dict(result["operator_decision"]),
        "started_at": started_at,
        "finished_at": finished_at,
        "actions_attempted": list(result["actions_attempted"]),
        "step_rc": outcome_rc_contribution(result["outcome"], result["dry_run"]),
        "mutation_performed": result["mutation_performed"],
        "transaction_commit": result["transaction_commit"],
    }
