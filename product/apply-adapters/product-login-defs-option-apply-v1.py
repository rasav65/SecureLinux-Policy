#!/usr/bin/env python3
"""APPLY-адаптер механизма login-defs-option-v1 (fstec-configuration-2026 п.1.1, таблица 2; SRC-0055).

Решение пользователя 26.09.2026: `PASS_MAX_DAYS 90`, `PASS_MIN_DAYS 1`, `PASS_WARN_AGE 7`,
`ENCRYPT_METHOD` — SHA512 или YESCRYPT (при несоответствии пишется SHA512).

* Наблюдение — как у CHECK `login-defs-option-check-semantic-v1`: последняя действующая строка
  ключа в `/etc/login.defs`.
* Правка на месте, без дублирования строк: значение каждой действующей строки ключа меняется;
  нет действующей — закомментированный шаблон `#KEY …` заменяется строкой `KEY<TAB>значение`;
  нет и шаблона — строка добавляется в конец файла.
* Запись — временный файл в том же каталоге с прежними владельцем и режимом, fsync, rename;
  итоговая проверка — повторное чтение и оценка. Ошибка — прежние байты возвращаются;
  подтверждены — FAILED_NOT_COMMITTED, иначе FAILED_COMPENSATION.
* Файл не обычный, ссылка, не root или с записью для группы/прочих — блок «требуется решение
  администратора» без изменений.

Параметры действуют для новых паролей и учётных записей; сроки существующих записей
`/etc/shadow` не меняются (решение 26.09.2026: `chage` — решение администратора).
"""

from __future__ import annotations

import os
import re
import stat

ADAPTER_ID = "product-login-defs-option-apply-v1"
MECHANISM_ID = "login-defs-option-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "login-defs-option"
LOGIN_DEFS = "/etc/login.defs"
TMP_SUFFIX = ".slp-tmp"

# Совпадает с CHECK-адаптером (проверяется тестом); WRITE — значение, которое пишет APPLY.
SPECS = {
    "ENCRYPT_METHOD": ("one-of", "SHA512|YESCRYPT"),
    "HOME_MODE": ("eq", "0700"),
    "PASS_MAX_DAYS": ("eq", "90"),
    "PASS_MIN_DAYS": ("eq", "1"),
    "PASS_WARN_AGE": ("eq", "7"),
}
WRITE = {"ENCRYPT_METHOD": "SHA512", "HOME_MODE": "0700", "PASS_MAX_DAYS": "90", "PASS_MIN_DAYS": "1", "PASS_WARN_AGE": "7"}

ACTION_FILE = ("{path} не является обычным файлом root без записи для группы и прочих: исправьте "
               "владельца и права файла или задайте {key} {value} вручную")

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


def _other(reason):
    return _Refused("ABORTED_PRECONDITION_OTHER", reason)


def read_file(path):
    """(байты, stat) обычного файла без перехода по ссылке; ошибка — _Refused."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise _other("login-defs:missing")
    except OSError as exc:
        if exc.errno == 40:  # ELOOP: символическая ссылка
            raise _Refused("ABORTED_PRECONDITION_CONFLICT", "login-defs:untrusted")
        raise _other("login-defs:open-failed")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _Refused("ABORTED_PRECONDITION_CONFLICT", "login-defs:untrusted")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        raise _other("login-defs:read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks), st


def _decode(raw):
    if b"\x00" in raw:
        raise _other("login-defs:invalid-bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _other("login-defs:invalid-bytes")


LINE_RE = re.compile(r"[ \t]*([^ \t]+)(?:[ \t]+([^ \t]+))?")


def _bad_char(c):
    return (c != "\t" and (ord(c) < 32 or ord(c) == 127)) or (c.isspace() and c not in " \t")


def _active(line, key):
    """(начало значения, конец значения) действующей строки ключа или None.

    Разбор совпадает с CHECK: разделители — только пробел и табуляция, один завершающий CR
    допускается; иной управляющий или пробельный символ в любой строке — login-defs:invalid-line.
    """
    core = line[:-1] if line.endswith("\r") else line
    if any(_bad_char(c) for c in core):
        raise _other("login-defs:invalid-line")
    body = core.strip(" \t")
    if not body or body.startswith("#"):
        return None
    m = LINE_RE.match(core)
    if m.group(1) != key:
        return None
    if m.group(2) is None:
        raise _other("login-defs:invalid-line")
    return m.start(2), m.end(2)


def current_value(text, key):
    """Последняя действующая строка ключа, как у CHECK; None — ключа нет."""
    value = None
    for line in text.split("\n"):
        span = _active(line, key)
        if span is None:
            continue
        token = line[span[0]:span[1]]
        if len(token) >= 2 and token[0] == token[-1] == '"':
            token = token[1:-1]
        if not token:
            raise _other("login-defs:invalid-line")
        value = token
    return value


def compliant(key, value):
    op, expected = SPECS[key]
    if value is None:
        return False
    if op == "eq":
        return re.fullmatch(r"-?[0-9]{1,9}", value) is not None and int(value) == int(expected)
    return value in expected.split("|")


def plan(text, key):
    """Новый текст по схеме: действующие строки → шаблон `#KEY` → конец файла."""
    value = WRITE[key]
    lines = text.split("\n")
    for line in lines:
        _active(line, key)  # недопустимый символ в любой строке — отказ до правки
    changed = False
    for i, line in enumerate(lines):
        span = _active(line, key)
        if span is not None:
            lines[i] = line[:span[0]] + value + line[span[1]:]
            changed = True
    if changed:
        return "\n".join(lines)
    template = re.compile(r"^#[ \t]*" + re.escape(key) + r"([ \t]|$)")
    for i, line in enumerate(lines):
        if template.match(line):
            lines[i] = key + "\t" + value
            return "\n".join(lines)
    body = text if text.endswith("\n") or not text else text + "\n"
    return body + key + "\t" + value + "\n"


def _trusted(st, root):
    owner_ok = st.st_uid == 0 or (root is not None and st.st_uid == os.geteuid())
    return owner_ok and not stat.S_IMODE(st.st_mode) & 0o022


def _write(path, raw, st):
    tmp = path + TMP_SUFFIX
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fchown(fd, st.st_uid, st.st_gid)
        os.fchmod(fd, stat.S_IMODE(st.st_mode))
        os.fsync(fd)
    except OSError:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(fd)
    try:
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _default_privilege_check() -> bool:
    return os.geteuid() == 0


def _result(control_id, outcome, *, actions, dry_run, mutation=False, **extra):
    record = {
        "adapter_id": ADAPTER_ID,
        "mechanism_id": MECHANISM_ID,
        "control_id": control_id,
        "target": LOGIN_DEFS,
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


def _commit_state(outcome, dry_run, mutation):
    if outcome == "APPLIED" or (outcome == "ALREADY_COMPLIANT" and not dry_run):
        return COMMIT_COMMITTED
    if mutation:
        return COMMIT_NOT_COMMITTED
    return COMMIT_NOT_STARTED


def outcome_rc_contribution(outcome, dry_run=False):
    """"0" для успешных исходов, иначе "nonzero"."""
    if outcome in ("APPLIED", "ALREADY_COMPLIANT", "NOT_ELIGIBLE_APPLY_UNSUPPORTED"):
        return "0"
    if dry_run and outcome == "DRY_RUN_WOULD_APPLY":
        return "0"
    return "nonzero"


def _shown(value):
    return "<absent>" if value is None else value


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _write_file=None):
    """Установить значение параметра парольной политики в /etc/login.defs.

    `_root` и `_write_file` — только для тестов: корень файловой системы и запись файла.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    write = _write_file if _write_file is not None else _write
    path = _p(_root, LOGIN_DEFS)

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if SPECS.get(key) != (op, expected):
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    current = None
    try:
        actions.append("P1_OBSERVE")
        raw, st = read_file(path)
        text = _decode(raw)
        value = current_value(text, key)
        current = _shown(value)
        if compliant(key, value):
            return done("ALREADY_COMPLIANT", policy_current=current)
        if not _trusted(st, _root):
            raise _Refused("ABORTED_PRECONDITION_CONFLICT", "login-defs:untrusted",
                           {"class": "ADMIN_ACTION_REQUIRED", "required": True,
                            "action": ACTION_FILE.format(path=LOGIN_DEFS, key=key, value=WRITE[key])})
        new_text = plan(text, key)
        if not compliant(key, current_value(new_text, key)):
            raise _other("login-defs:plan-not-compliant")
        actions.append("P2_PLAN")
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY", policy_current=current)
        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            raise _other("privilege")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, policy_current=current, operator_decision=exc.decision)

    actions.append("PHASE1_WRITE")
    reason = None
    try:
        write(path, new_text.encode("utf-8"), st)
    except OSError:
        reason = "login-defs:write-failed"
    if reason is None:
        actions.append("FINAL_POSTCHECK")
        try:
            after_raw, _after_st = read_file(path)
            after = current_value(_decode(after_raw), key)
        except _Refused:
            reason = "login-defs:postcheck-failed"
        else:
            if after_raw == new_text.encode("utf-8") and compliant(key, after):
                return done("APPLIED", mutation=True, policy_current=after)
            reason = "login-defs:postcheck-failed"
    actions.append("COMPENSATION")
    try:
        now_raw, _now_st = read_file(path)
    except _Refused:
        now_raw = None
    if now_raw != raw:
        try:
            write(path, raw, st)
            now_raw, _now_st = read_file(path)
        except (OSError, _Refused):
            now_raw = None
    if now_raw == raw:
        return done("FAILED_NOT_COMMITTED", reason=reason, mutation=True, policy_current=current)
    return done("FAILED_COMPENSATION", reason=reason, mutation=True, policy_current=current)


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
