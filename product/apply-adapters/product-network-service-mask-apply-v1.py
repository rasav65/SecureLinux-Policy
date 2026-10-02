#!/usr/bin/env python3
"""APPLY-адаптер механизма network-service-mask-v1 (fstec-configuration-2026 п.11.2, SRC-0098).

Решение пользователя 26.09.2026: службы Telnet, FTP и SNMP останавливаются и маскируются.

* Наблюдение — как у CHECK `network-service-disabled-check-semantic-v1`: известные юниты
  службы (`systemctl show`) и прослушиваемый порт (`/proc/net/{tcp,udp}[6]`).
* Цели — известные юниты в состоянии `loaded`, активные или включённые, и замаскированные, но
  активные, и юниты без файла (`not-found`), но активные. Для каждого: `systemctl disable --now`,
  затем `systemctl mask`; замаскированный или без файла — `systemctl stop`. Итоговая проверка: каждый юнит-цель
  `masked` и не активен.
* Порт прослушивается, а активных или включённых известных юнитов нет (например, telnet
  через inetd) — блок «требуется решение администратора» без изменений.
* Юнит задан файлом в `/etc/systemd/system` — `systemctl mask` его не заменит: блок
  «требуется решение администратора» без изменений.
* Ошибка команды или итоговой проверки — для затронутых юнитов `systemctl unmask`, затем
  `enable` (`enable --runtime` для прежнего `*-runtime`) и `start`, если юнит был включён и
  активен; прежние LoadState и UnitFileState совпали точно, активность — та же:
  FAILED_NOT_COMMITTED, иначе FAILED_COMPENSATION (например, `linked`/`alias` точно не
  восстанавливаются).

Порт, который после маскирования продолжает прослушивать другой процесс, в исход APPLIED не
входит: он виден в `policy_current` и в следующем CHECK; повторный APPLY вернёт блок решения
администратора. Откат администратором: `systemctl unmask <юнит>`, `systemctl enable --now <юнит>`.
"""

from __future__ import annotations

import os
import re
import subprocess

ADAPTER_ID = "product-network-service-mask-apply-v1"
MECHANISM_ID = "network-service-mask-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "network-service-disabled"
EXPECTED_OP = "eq"
EXPECTED_VALUE = "disabled"

SYSTEMCTL = "/usr/bin/systemctl"
PROC = "/proc"
TOOL_TIMEOUT = 120
ADMIN_UNIT_DIR = "/etc/systemd/system/"

# Совпадает с CHECK-адаптером (проверяется тестом).
SERVICES = {
    "ftp": (("vsftpd.service", "proftpd.service", "pure-ftpd.service"), (("tcp", 21),)),
    "snmp": (("snmpd.service",), (("udp", 161),)),
    "telnet": (("telnet.socket", "telnetd.socket", "telnetd.service", "inetutils-telnetd.service"), (("tcp", 23),)),
}
ACTIVE_STATES = ("active", "activating", "reloading", "refreshing")
ENABLED_STATES = ("enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "indirect")
UNIT_PROPS = ("LoadState", "ActiveState", "UnitFileState", "FragmentPath")
# Юнит в этих LoadState только останавливается: маскировать и выключать нечего или уже сделано.
STOP_ONLY_LOADS = ("masked", "not-found")
# Включение до APPLY, которое восстанавливается `enable --runtime` (до перезагрузки).
RUNTIME_ENABLED_STATES = ("enabled-runtime", "linked-runtime")

ACTION_LISTENER = ("порт {ports} прослушивает процесс вне известных юнитов службы ({units}), например "
                   "inetd или xinetd: отключите службу вручную")
ACTION_ADMIN_UNIT = ("юнит {unit} задан файлом {path}: маскирование его не заменит — отключите службу "
                     "вручную (systemctl disable --now, удаление или переименование файла юнита)")

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
LOCAL_RE = re.compile(r"^[0-9A-F]+:([0-9A-F]{4})$")
STATE_RE = re.compile(r"^[0-9A-F]{2}$")


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


def _admin(reason, action):
    return _Refused("ABORTED_PRECONDITION_CONFLICT", reason,
                    {"class": "ADMIN_ACTION_REQUIRED", "required": True, "action": action})


def _default_run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def _call(run, argv):
    """Код возврата и stdout; ошибка запуска — (None, b"")."""
    try:
        cp = run(argv, TOOL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None, b""
    return cp.returncode, cp.stdout


def unit_state(run, unit):
    """(LoadState, ActiveState, UnitFileState, FragmentPath) юнита; ошибка — ABORTED_PRECONDITION_OTHER."""
    rc, out = _call(run, [SYSTEMCTL, "show", "--property=" + ",".join(UNIT_PROPS), "--", unit])
    if rc != 0:
        raise _other("systemd:query-failed")
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        raise _other("systemd:invalid-output")
    props = {}
    for line in text.split("\n"):
        if not line:
            continue
        name, sep, value = line.partition("=")
        if not sep or name not in UNIT_PROPS or name in props:
            raise _other("systemd:invalid-output")
        props[name] = value
    if set(props) != set(UNIT_PROPS):
        raise _other("systemd:invalid-output")
    return tuple(props[name] for name in UNIT_PROPS)


def listeners(root, proto, port):
    """Число прослушивающих сокетов порта: TCP — LISTEN (0A), UDP — привязанный (07)."""
    found = 0
    for suffix in ("", "6"):
        path = _p(root, "%s/net/%s%s" % (PROC, proto, suffix))
        try:
            with open(path, "rb") as stream:
                raw = stream.read()
        except FileNotFoundError:
            if suffix == "6":
                continue
            raise _other("proc-net:read-failed")
        except OSError:
            raise _other("proc-net:read-failed")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            raise _other("proc-net:invalid-bytes")
        lines = text.split("\n")
        head = lines[0].split()
        # Обязательные поля заголовка: номер, локальный и удалённый адрес, состояние; у tcp6/udp6
        # удалённый адрес называется remote_address (ВМ-прогон 27.09.2026), у tcp/udp — rem_address.
        if head[:4] != ["sl", "local_address", "remote_address" if suffix == "6" else "rem_address", "st"]:
            raise _other("proc-net:invalid-header")
        for line in lines[1:]:
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) < 10:
                raise _other("proc-net:invalid-row")
            local, state = LOCAL_RE.fullmatch(fields[1]), fields[3]
            if local is None or STATE_RE.fullmatch(state) is None:
                raise _other("proc-net:invalid-row")
            if int(local.group(1), 16) == port and state == ("0A" if proto == "tcp" else "07"):
                found += 1
    return found


def _violates(state):
    load, active, file_state, _fragment = state
    if load in STOP_ONLY_LOADS:
        # Замаскирован или без файла юнита, но ещё работает: нужна остановка.
        return active in ACTIVE_STATES
    if load != "loaded":
        raise _other("systemd:unit-load-" + (load if re.fullmatch(r"[a-z-]{1,32}", load) else "invalid"))
    return active in ACTIVE_STATES or file_state in ENABLED_STATES


def observe(root, run, key):
    """Состояния известных юнитов, юниты-цели и прослушиваемые порты службы."""
    units, ports = SERVICES[key]
    states = {unit: unit_state(run, unit) for unit in units}
    targets = [unit for unit in units if _violates(states[unit])]
    open_ports = ["%d/%s" % (port, proto) for proto, port in ports if listeners(root, proto, port)]
    return states, targets, open_ports


def policy_current(states, targets, open_ports):
    units = ",".join("%s:%s/%s" % (u, states[u][1] or "-", states[u][2] or "-") for u in targets)
    return "units=%s;listeners=%s" % (units or "-", ",".join(open_ports) or "-")


def _default_privilege_check() -> bool:
    return os.geteuid() == 0


def _result(control_id, outcome, *, actions, dry_run, mutation=False, **extra):
    record = {
        "adapter_id": ADAPTER_ID,
        "mechanism_id": MECHANISM_ID,
        "control_id": control_id,
        "target": "systemd",
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


def _target_done(before, after):
    """Цель выполнена: юнит остановлен и замаскирован (без файла или замаскированный — остановлен)."""
    if after[1] in ACTIVE_STATES:
        return False
    return after[0] == ("masked" if before[0] not in STOP_ONLY_LOADS else before[0])


def _compensate(run, touched, before):
    """Возврат затронутых юнитов: unmask, затем enable и start по прежнему состоянию.

    True — у каждого юнита прежние LoadState и UnitFileState (точно) и та же активность."""
    for unit in reversed(touched):
        if before[unit][0] in STOP_ONLY_LOADS:
            if before[unit][1] in ACTIVE_STATES:
                _call(run, [SYSTEMCTL, "start", "--", unit])
            continue
        _call(run, [SYSTEMCTL, "unmask", "--", unit])
        if before[unit][2] in RUNTIME_ENABLED_STATES:
            _call(run, [SYSTEMCTL, "enable", "--runtime", "--", unit])
        elif before[unit][2] in ENABLED_STATES:
            _call(run, [SYSTEMCTL, "enable", "--", unit])
        if before[unit][1] in ACTIVE_STATES:
            _call(run, [SYSTEMCTL, "start", "--", unit])
    for unit in touched:
        try:
            now = unit_state(run, unit)
        except _Refused:
            return False
        if now[0] != before[unit][0]:
            return False
        if (now[1] in ACTIVE_STATES) != (before[unit][1] in ACTIVE_STATES):
            return False
        if now[2] != before[unit][2]:
            return False
    return True


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None):
    """Остановить и замаскировать известные юниты службы Telnet, FTP или SNMP.

    `_root` и `_run` — только для тестов: корень файловой системы (/proc) и запуск команд.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if key not in SERVICES or op != EXPECTED_OP or expected != EXPECTED_VALUE:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    current = None
    try:
        actions.append("P1_OBSERVE")
        if not os.path.isfile(_p(_root, SYSTEMCTL)) or not os.access(_p(_root, SYSTEMCTL), os.X_OK):
            raise _other("tools:missing:systemctl")
        before, targets, open_ports = observe(_root, run, key)
        current = policy_current(before, targets, open_ports)
        if not targets and not open_ports:
            return done("ALREADY_COMPLIANT", policy_current=current)
        if not targets:
            raise _admin("service:unmanaged-listener", ACTION_LISTENER.format(
                ports=", ".join(open_ports), units=", ".join(SERVICES[key][0])))
        for unit in targets:
            fragment = before[unit][3]
            if fragment.startswith(ADMIN_UNIT_DIR):
                raise _admin("service:admin-unit-file", ACTION_ADMIN_UNIT.format(unit=unit, path=fragment))

        actions.append("P2_PLAN")
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY", policy_current=current)

        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            raise _other("privilege")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, policy_current=current, operator_decision=exc.decision)

    actions.append("PHASE1_DISABLE_MASK")
    touched = []
    reason = None
    for unit in targets:
        touched.append(unit)
        if before[unit][0] in STOP_ONLY_LOADS:
            rc, _out = _call(run, [SYSTEMCTL, "stop", "--", unit])
            if rc != 0:
                reason = "systemctl:stop-failed"
                break
            continue
        rc, _out = _call(run, [SYSTEMCTL, "disable", "--now", "--", unit])
        if rc != 0:
            reason = "systemctl:disable-failed"
            break
        rc, _out = _call(run, [SYSTEMCTL, "mask", "--", unit])
        if rc != 0:
            reason = "systemctl:mask-failed"
            break
    if reason is None:
        actions.append("FINAL_POSTCHECK")
        try:
            after, after_targets, after_ports = observe(_root, run, key)
        except _Refused:
            reason = "service:postcheck-failed"
        else:
            if all(_target_done(before[unit], after[unit]) for unit in targets):
                return done("APPLIED", mutation=True,
                            policy_current=policy_current(after, after_targets, after_ports))
            reason = "service:postcheck-failed"
    actions.append("COMPENSATION")
    if _compensate(run, touched, before):
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
