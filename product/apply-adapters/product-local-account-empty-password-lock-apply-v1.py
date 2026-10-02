#!/usr/bin/env python3
"""APPLY-адаптер механизма local-account-empty-password-lock-v1 (fstec-linux-2022 п.2.1.1; SRC-0001).

Требование: каждый пользователь системы либо имеет пароль, либо заблокирован по паролю
(/etc/shadow). Решение пользователя 01.10.2026: блокируются все учётные записи с пустым паролем,
без исключений (в том числе root и члены sudo/admin/wheel); решение 26.09.2026 об исключениях
отменено.

* Наблюдение — как у CHECK `local-account-password-state-check-semantic-v2`: учётные записи —
  строки /etc/passwd; пустое поле пароля /etc/shadow — несоответствие. Файлы — обычные (lstat,
  без перехода по ссылке), владелец uid 0, без записи для прочих; без NUL и CR. Разбор — тот же,
  что у CHECK, в том же порядке (файл shadow целиком, затем строки passwd по порядку): пустой файл,
  пустая строка, иное число полей (passwd 7, shadow 9), недопустимое имя или повтор имени — отказ
  до мутации (CHECK в этих случаях даёт ERROR).
* Предусловия (нарушение — решение администратора, ничего не меняется): у каждой учётной записи
  /etc/passwd есть строка /etc/shadow (иначе блокировать нечего — `pwconv`; проверяется при разборе
  строки passwd, как в CHECK); имя учётной записи с пустым паролем — допустимое имя shadow-utils.
* Мутация: `usermod -L <имя>` для каждой учётной записи с пустым паролем (штатная утилита держит
  блокировку файлов теневых паролей); пустое поле становится `!`. Перед вызовом поле
  перечитывается: если оно уже не пустое, учётная запись не трогается.
* Итог: после каждого вызова поле равно `!`; итоговое наблюдение — пустых полей нет.
* Откат при ошибке: для уже заблокированных — `usermod -p '' <имя>`; затем итоговое
  наблюдение: поля всех затронутых учётных записей снова пустые и ни одно чтение или команда
  отката не дали ошибки — FAILED_NOT_COMMITTED; иначе FAILED_COMPENSATION.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess

ADAPTER_ID = "product-local-account-empty-password-lock-apply-v1"
MECHANISM_ID = "local-account-empty-password-lock-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "local-account-password-state"
PASSWD = "/etc/passwd"
SHADOW = "/etc/shadow"
USERMOD = "/usr/sbin/usermod"
CANONICAL_LOCATOR = "/etc/shadow"
CANONICAL_KEY = "password-field"
LOCKED = "!"
TOOL_TIMEOUT = 120
NAME_RE = re.compile(r"[a-z_][a-z0-9_.-]{0,31}\$?")
# Имя учётной записи, которое принимает CHECK v2.
ACCOUNT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\$?")
PASSWD_FIELDS = 7
SHADOW_FIELDS = 9

ACTION_MISSING = ("учётные записи {names} есть в /etc/passwd, но не в /etc/shadow: восстановите "
                  "теневые записи (pwconv) и задайте пароль или заблокируйте учётную запись")
ACTION_NAME = ("имя учётной записи {name} с пустым паролем не поддерживается: задайте пароль или "
               "заблокируйте учётную запись вручную (passwd -l)")
ACTION_FILE = ("{path} не является обычным файлом root без записи для прочих: исправьте владельца и "
               "права файла")

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


def _other(reason):
    return _Refused("ABORTED_PRECONDITION_OTHER", reason)


def _admin(reason, action):
    return _Refused("ABORTED_PRECONDITION_CONFLICT", reason,
                    {"class": "ADMIN_ACTION_REQUIRED", "required": True, "action": action})


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not isinstance(key, str) or not isinstance(op, str):
        raise ValueError("key and op must be strings")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _p(root, path):
    return path if root is None else os.path.join(root, path.lstrip("/"))


def _uid_ok(st, root):
    return st.st_uid == 0 or (root is not None and st.st_uid == os.geteuid())


def _read(root, path, domain):
    """Байты обычного файла root без записи для прочих; отказ — _Refused."""
    full = _p(root, path)
    try:
        st = os.lstat(full)
    except FileNotFoundError:
        raise _other(domain + ":not-found")
    except OSError:
        raise _other(domain + ":stat-failed")
    if not stat.S_ISREG(st.st_mode) or not _uid_ok(st, root) or stat.S_IMODE(st.st_mode) & 0o002:
        raise _admin(domain + ":untrusted", ACTION_FILE.format(path=path))
    try:
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise _other(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        raise _other(domain + ":read-failed")
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if b"\x00" in raw or b"\r" in raw:
        raise _other(domain + ":invalid-bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _other(domain + ":invalid-bytes")


def _records(text):
    """Строки файла; завершающий перевод строки не даёт пустой записи (как в CHECK v2)."""
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def _parse(lines, domain, count, seen, shadow=None):
    """Имя и поле пароля каждой строки; для passwd (`shadow` задан) — и наличие строки shadow."""
    for line in lines:
        if not line:
            raise _other(domain + ":empty-record")
        parts = line.split(":")
        if len(parts) != count:
            raise _other(domain + ":invalid-fields")
        if ACCOUNT_RE.fullmatch(parts[0]) is None:
            raise _other(domain + ":invalid-account")
        if parts[0] in seen:
            raise _other(domain + ":duplicate-account")
        if shadow is not None and parts[0] not in shadow:
            raise _admin("shadow:entry-missing", ACTION_MISSING.format(names=parts[0]))
        seen[parts[0]] = parts[1]


def observe(root):
    """(имена /etc/passwd по порядку, {имя: поле пароля /etc/shadow}); отказ — _Refused."""
    passwd_lines = _records(_read(root, PASSWD, "passwd"))
    shadow_lines = _records(_read(root, SHADOW, "shadow"))
    if not passwd_lines:
        raise _other("passwd:empty-file")
    if not shadow_lines:
        raise _other("shadow:empty-file")
    fields, accounts = {}, {}
    _parse(shadow_lines, "shadow", SHADOW_FIELDS, fields)
    _parse(passwd_lines, "passwd", PASSWD_FIELDS, accounts, fields)
    return list(accounts), fields


def empty_accounts(names, fields):
    """(имена с пустым полем пароля, имена без строки /etc/shadow) — по порядку /etc/passwd."""
    empty, missing = [], []
    for name in names:
        if name not in fields:
            missing.append(name)
        elif fields[name] == "":
            empty.append(name)
    return empty, missing


def _default_run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def _call(run, argv):
    try:
        cp = run(argv, TOOL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return cp.returncode


def _field(root, name):
    try:
        return observe(root)[1].get(name)
    except _Refused:
        return None


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
        "target": SHADOW,
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


def _shown(accounts, empty):
    return "accounts=%d empty=%d" % (accounts, empty)


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None):
    """Заблокировать по паролю учётные записи с пустым паролем.

    `_root` и `_run` — только для тестов: корень файловой системы и запуск usermod.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run
    mutation = False

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, mutation=mutation, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if key != CANONICAL_KEY or op != "all-nonempty" or expected is not True:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    current = None
    try:
        actions.append("P1_OBSERVE")
        names, fields = observe(_root)
        empty, missing = empty_accounts(names, fields)
        current = _shown(len(names), len(empty) + len(missing))
        if not empty and not missing:
            return done("ALREADY_COMPLIANT", policy_current=current)
        if missing:
            raise _admin("shadow:entry-missing", ACTION_MISSING.format(names=", ".join(missing)))
        for name in empty:
            if NAME_RE.fullmatch(name) is None:
                raise _admin("account:unsupported-name", ACTION_NAME.format(name=name))
        tool = _p(_root, USERMOD)
        if not os.path.isfile(tool) or not os.access(tool, os.X_OK):
            raise _other("tools:missing:usermod")
        actions.append("P2_PLAN")
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY", policy_current=current)
        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            raise _other("privilege")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, policy_current=current, operator_decision=exc.decision)

    actions.append("PHASE1_LOCK")
    locked = []
    reason = None
    for name in empty:
        if _field(_root, name) != "":
            continue
        mutation = True
        rc = _call(run, [USERMOD, "-L", name])
        if rc != 0:
            reason = "usermod:lock-failed"
            locked.append(name)
            break
        locked.append(name)
        if _field(_root, name) != LOCKED:
            reason = "shadow:lock-not-applied"
            break
    if reason is None:
        actions.append("FINAL_POSTCHECK")
        try:
            names, fields = observe(_root)
            empty_now, missing_now = empty_accounts(names, fields)
        except _Refused:
            empty_now, missing_now = [None], []
        if not empty_now and not missing_now and all(fields.get(n) == LOCKED for n in locked):
            return done("APPLIED", policy_current=_shown(len(names), 0))
        reason = "shadow:postcheck-failed"
    actions.append("COMPENSATION")
    restored = True
    for name in reversed(locked):
        value = _field(_root, name)
        if value is None:
            # Ошибка чтения или запись пропала: откат этой записи не подтверждён.
            restored = False
        elif value == LOCKED and _call(run, [USERMOD, "-p", "", name]) != 0:
            restored = False
    # Итоговая сверка после всех команд отката: поля всех затронутых записей пустые.
    try:
        fields = observe(_root)[1]
    except _Refused:
        restored = False
    else:
        if any(fields.get(name) != "" for name in locked):
            restored = False
    if restored:
        return done("FAILED_NOT_COMMITTED", reason=reason, policy_current=current)
    return done("FAILED_COMPENSATION", reason=reason, policy_current=current)


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
