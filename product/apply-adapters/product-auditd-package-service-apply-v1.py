#!/usr/bin/env python3
"""APPLY-адаптер механизма auditd-package-service-v1 (fstec-logging-2025 приложение 2, п.1 и п.2;
SRC-0050, SRC-0051).

Решение пользователя 30.09.2026 (вариант B, карта разбиения auditd v5): пакет auditd ставится,
служба auditd.service включается и запускается.

* Наблюдение — тот же разбор, что у CHECK `auditd-package-service-check-semantic-v1` (текст PARSER
  совпадает побайтно, сверяется тестом): `dpkg-query -W -f=${Status} auditd` и
  `systemctl show --property=LoadState,ActiveState,UnitFileState -- auditd.service`.
* Пакет не установлен (оба контроля) — `apt-get install auditd` (при отказе — `apt-get update` и
  повтор). Установленный пакет не удаляется ни при каком исходе. Контроль пакета: итог —
  повторное наблюдение Status `install ok installed`.
* Служба: после установки пакета (или если он уже был) — повторное наблюдение юнита; включена и
  активна — APPLIED (пакет сам включает службу). Иначе `systemctl enable --now auditd.service`,
  итоговая проверка: LoadState=loaded, UnitFileState=enabled, ActiveState=active.
* Юнит замаскирован, отсутствует при установленном пакете или в UnitFileState, отличном от
  enabled, enabled-runtime и disabled (static, indirect, linked, generated, alias…) — решение
  администратора без изменений; для обоих контролей проверяется до установки пакета.
* Status dpkg и состояния юнита вне закрытых перечней — отказ без изменений.
* Ошибка `enable --now` или итоговой проверки — компенсация к состоянию перед `enable --now`:
  прежний UnitFileState (`systemctl disable`, для enabled-runtime затем `enable --runtime`) и
  прежняя активность (`systemctl stop` для службы, которая была остановлена). Прежние
  UnitFileState и активность совпали — FAILED_NOT_COMMITTED, иначе FAILED_COMPENSATION (юнит
  auditd.service обычно запрещает ручную остановку — RefuseManualStop, — поэтому запущенную
  службу компенсация может не остановить).
"""

from __future__ import annotations

import os
import re
import subprocess

ADAPTER_ID = "product-auditd-package-service-apply-v1"
MECHANISM_ID = "auditd-package-service-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "auditd-package-service"
PACKAGE = "auditd"
UNIT = "auditd.service"
# Механизм ставит пакеты: его контроли в APPLY выполняются первыми (генератор).
INSTALLS_PACKAGES = True
TOOL_TIMEOUT = 120
APT_TIMEOUT = 900
DPKG_QUERY = "/usr/bin/dpkg-query"
APT_GET = "/usr/bin/apt-get"
SYSTEMCTL = "/usr/bin/systemctl"

# Совпадает с CHECK-адаптером (проверяется тестом).
SPECS = {"package": "installed", "service": "enabled-active"}
# UnitFileState, из которого `systemctl enable` даёт enabled.
ENABLEABLE_STATES = ("enabled", "enabled-runtime", "disabled")

# Разбор вывода — общий с CHECK (product-auditd-package-service-check-v1.py, PARSER; сверяется тестом).
PARSER = r'''
# Значения полей Status dpkg (want, eflag, status) и состояний systemd — закрытые перечни;
# иное значение — ERROR, а не несоответствие.
DPKG_WANT = ("unknown", "install", "hold", "deinstall", "purge")
DPKG_EFLAG = ("ok", "reinstreq")
DPKG_STATUS = ("not-installed", "config-files", "half-installed", "unpacked", "half-configured",
               "triggers-awaited", "triggers-pending", "installed")
UNIT_PROPS = ("LoadState", "ActiveState", "UnitFileState")
LOAD_STATES = ("loaded", "not-found", "masked", "bad-setting", "error", "merged", "stub")
ACTIVE_STATES = ("active", "reloading", "inactive", "failed", "activating", "deactivating",
                 "maintenance", "refreshing")
UNIT_FILE_STATES = ("enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked",
                    "masked-runtime", "static", "indirect", "disabled", "generated", "transient", "bad")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def package_state(rc, out):
    """(VALUE, соответствие) по коду возврата и stdout `dpkg-query -W -f=${Status}`."""
    if rc == 1 and not out:
        return "not-installed", False
    if rc != 0:
        raise ParseError("dpkg:query-failed")
    try:
        text = out.decode("ascii")
    except UnicodeDecodeError:
        raise ParseError("dpkg:invalid-output")
    parts = text.split(" ")
    if (len(parts) != 3 or parts[0] not in DPKG_WANT or parts[1] not in DPKG_EFLAG
            or parts[2] not in DPKG_STATUS):
        raise ParseError("dpkg:invalid-output")
    if text == "install ok installed":
        return "installed", True
    if text.endswith(" not-installed"):
        return "not-installed", False
    return text, False


def unit_props(rc, out):
    """(LoadState, ActiveState, UnitFileState) по выводу `systemctl show`."""
    if rc != 0:
        raise ParseError("systemd:query-failed")
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        raise ParseError("systemd:invalid-output")
    props = {}
    for line in text.split("\n"):
        if not line:
            continue
        name, sep, value = line.partition("=")
        if not sep or name not in UNIT_PROPS or name in props:
            raise ParseError("systemd:invalid-output")
        props[name] = value
    if set(props) != set(UNIT_PROPS):
        raise ParseError("systemd:invalid-output")
    load, active, file_state = props["LoadState"], props["ActiveState"], props["UnitFileState"]
    if load not in LOAD_STATES or active not in ACTIVE_STATES:
        raise ParseError("systemd:invalid-output")
    # Пустой UnitFileState допустим только у юнита без файла (not-found).
    if file_state not in UNIT_FILE_STATES and not (file_state == "" and load == "not-found"):
        raise ParseError("systemd:invalid-output")
    return load, active, file_state


def service_state(load, active, file_state):
    """(VALUE, соответствие) службы по свойствам юнита."""
    if load == "not-found":
        return "not-found", False
    if load == "masked":
        return "masked/" + active, False
    if load != "loaded":
        raise ParseError("systemd:unit-load-" + load)
    return file_state + "/" + active, file_state == "enabled" and active == "active"
'''
exec(PARSER, globals())  # noqa: S102 — один текст разбора с CHECK

ACTION_MASKED = ("служба auditd.service замаскирована: снимите маску (systemctl unmask auditd.service), "
                 "если маскирование не намеренное, затем включите службу")
ACTION_UNIT_MISSING = ("пакет auditd установлен, но юнита auditd.service нет: проверьте установку пакета "
                       "(apt-get install --reinstall auditd)")
ACTION_UNIT_STATE = ("юнит auditd.service в состоянии {state}: systemctl enable не сделает его включённым; "
                     "включите службу вручную")

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
    if not isinstance(key, str) or not isinstance(op, str) or not isinstance(expected, str):
        raise ValueError("key, op and expected must be strings")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _p(root, path):
    return path if root is None else os.path.join(root, path.lstrip("/"))


def _default_run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                                                "DEBIAN_FRONTEND": "noninteractive"})


def _call(run, argv, timeout=TOOL_TIMEOUT):
    """Код возврата и stdout; ошибка запуска — (None, b"")."""
    try:
        cp = run(argv, timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None, b""
    return cp.returncode, cp.stdout


def observe_package(run):
    rc, out = _call(run, [DPKG_QUERY, "-W", "-f=${Status}", PACKAGE])
    if rc is None:
        raise _other("dpkg:query-failed")
    try:
        return package_state(rc, out)
    except ParseError as exc:
        raise _other(exc.reason)


def observe_unit(run):
    """(LoadState, ActiveState, UnitFileState) юнита auditd.service."""
    rc, out = _call(run, [SYSTEMCTL, "show", "--property=" + ",".join(UNIT_PROPS), "--", UNIT])
    try:
        return unit_props(rc if rc is not None else -1, out)
    except ParseError as exc:
        raise _other(exc.reason)


def unit_value(state):
    try:
        return service_state(*state)
    except ParseError as exc:
        raise _other(exc.reason)


def unit_refusal(state, package_ok):
    """Отказ «решение администратора» для юнита, который enable не приведёт к норме, или None."""
    load, _active, file_state = state
    if load == "masked":
        return _admin("service:masked", ACTION_MASKED)
    if load == "not-found":
        return _admin("service:unit-missing", ACTION_UNIT_MISSING) if package_ok else None
    if file_state not in ENABLEABLE_STATES:
        return _admin("service:unit-file-state", ACTION_UNIT_STATE.format(state=file_state or "-"))
    return None


def install_package(run):
    """True — пакет установлен после попытки; порядок: install, при отказе update и install."""
    install = [APT_GET, "-q", "-y", "-o", "DPkg::Lock::Timeout=300", "--no-install-recommends",
               "install", PACKAGE]
    rc, _out = _call(run, install, APT_TIMEOUT)
    if rc != 0:
        _call(run, [APT_GET, "-q", "-o", "DPkg::Lock::Timeout=300", "update"], APT_TIMEOUT)
        _call(run, install, APT_TIMEOUT)
    try:
        return observe_package(run)[1]
    except _Refused:
        return False


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
        "target": PACKAGE,
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


def _compensate(run, before):
    """Возврат UnitFileState и активности юнита к состоянию перед `enable --now`.

    True — прежние UnitFileState (точно) и активность совпали."""
    _load, active, file_state = before
    if file_state in ("disabled", "enabled-runtime"):
        _call(run, [SYSTEMCTL, "disable", "--", UNIT])
        if file_state == "enabled-runtime":
            _call(run, [SYSTEMCTL, "enable", "--runtime", "--", UNIT])
    if active != "active":
        _call(run, [SYSTEMCTL, "stop", "--", UNIT])
    try:
        now = observe_unit(run)
    except _Refused:
        return False
    return now[2] == file_state and (now[1] == "active") == (active == "active")


def _check_tools(root, paths):
    for path in paths:
        full = _p(root, path)
        if not os.path.isfile(full) or not os.access(full, os.X_OK):
            raise _other("tools:missing:" + os.path.basename(path))


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None):
    """Установить пакет auditd; включить и запустить службу auditd.service.

    `_root` и `_run` — только для тестов: корень файловой системы (проверка инструментов) и
    запуск dpkg-query, apt-get и systemctl.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run
    mutation = False

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, mutation=mutation, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if key not in SPECS or op != "eq" or expected != SPECS[key]:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    current = None
    try:
        actions.append("P1_OBSERVE")
        _check_tools(_root, (DPKG_QUERY, APT_GET, SYSTEMCTL))
        package_value, package_ok = observe_package(run)
        if key == "package":
            current = package_value
            if package_ok:
                return done("ALREADY_COMPLIANT", policy_current=current)
        # До любой мутации (установки пакета или enable) — состояние юнита для обоих ключей:
        # установка пакета включает и запускает службу, поэтому замаскированный или
        # нестандартный юнит — решение администратора и для контроля пакета .
        state = observe_unit(run)
        unit_current, ok = unit_value(state)
        if key == "service":
            current = unit_current
            if ok and package_ok:
                return done("ALREADY_COMPLIANT", policy_current=current)
        refusal = unit_refusal(state, package_ok)
        if refusal is not None:
            raise refusal
        actions.append("P2_PLAN")
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY", policy_current=current)
        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            raise _other("privilege")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, policy_current=current, operator_decision=exc.decision)

    if not package_ok:
        actions.append("PHASE0_INSTALL_PACKAGE")
        mutation = True
        if not install_package(run):
            return done("FAILED_NOT_COMMITTED", reason="pkg:install-failed", policy_current=current)
        if key == "package":
            return done("APPLIED", policy_current="installed")
        try:
            state = observe_unit(run)
            value, ok = unit_value(state)
        except _Refused:
            return done("FAILED_NOT_COMMITTED", reason="service:observe-after-install-failed",
                        policy_current=current)
        if ok:
            return done("APPLIED", policy_current=value)
        refusal = unit_refusal(state, True)
        if refusal is not None:
            return done("FAILED_NOT_COMMITTED", reason=refusal.reason, policy_current=value,
                        operator_decision=refusal.decision)

    before = state
    actions.append("PHASE1_ENABLE_START")
    mutation = True
    rc, _out = _call(run, [SYSTEMCTL, "enable", "--now", "--", UNIT])
    reason = None if rc == 0 else "systemctl:enable-failed"
    if reason is None:
        actions.append("FINAL_POSTCHECK")
        try:
            after = observe_unit(run)
            value, ok = unit_value(after)
            package_ok = observe_package(run)[1]
        except _Refused:
            reason = "service:postcheck-failed"
        else:
            if ok and package_ok:
                return done("APPLIED", policy_current=value)
            reason = "service:postcheck-failed"
    actions.append("COMPENSATION")
    if _compensate(run, before):
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
