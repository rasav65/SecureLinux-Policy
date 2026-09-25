#!/usr/bin/env python3
"""product-pam-wheel-su-apply-v1.

APPLY adapter for mechanism `pam-wheel-su-v1` (2.2.1 `su-wheel-access`, SRC-0003).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-pam-wheel-su-v1.json

Решения человека 25.09.2026:

1. `/etc/pam.d/su` меняется только если он побайтно равен файлу пакета util-linux
   (`PAM_PACKAGE_SHA256`, одинаков на всех семи эталонных средах): закомментированная
   строка `# auth       required   pam_wheel.so` заменяется на
   `auth       required   pam_wheel.so use_uid` (tmp + rename, режим и владелец
   прежние). Любое другое содержимое — ABORTED_PRECONDITION_CONFLICT, блок
   «решение администратора» с готовой строкой.
2. Нет группы `wheel` — `groupadd --system wheel` (GID выбирает система), затем
   `gpasswd -a root wheel`; есть — только добавляется `root`, прочие участники не
   меняются. `<user list>` источника — решение администратора.
3. После записи `su` доступен только участникам `wheel`, то есть `root`: запись
   выполняется, только если в группе `sudo` или `admin` (поле участников
   `/etc/group`) есть хотя бы один пользователь; иначе — блок «решение администратора».
4. Сначала группа, затем PAM. Ошибка записи PAM или итоговой проверки — созданная
   этим запуском группа удаляется (`groupdel`), добавленный `root` убирается
   (`gpasswd -d`), прежние байты PAM возвращаются.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess

ADAPTER_ID = "product-pam-wheel-su-apply-v1"
MECHANISM_ID = "pam-wheel-su-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "pam-wheel-access"

CONTROL_ID = "FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS"
CONTROL_SPEC = ("policy", "pam-wheel-root-member", "auth required pam_wheel.so use_uid;wheel:root")

PAM_SU = "/etc/pam.d/su"
GROUP = "/etc/group"
GROUPADD = "/usr/sbin/groupadd"
GROUPDEL = "/usr/sbin/groupdel"
GPASSWD = "/usr/bin/gpasswd"
TOOL_TIMEOUT = 60

PAM_PACKAGE_SHA256 = "fda16622dc6198eae5d6ae522bb820b7b68dbf2e73899295c4cac9744f7c7904"
PAM_APPLIED_SHA256 = "8c3bc9e563b6d5337980e5a1646bb36b00e803dfe61d1f98a31ca0cdfb5a054c"
PAM_LINE_OLD = b"# auth       required   pam_wheel.so\n"
PAM_LINE_NEW = b"auth       required   pam_wheel.so use_uid\n"
SUDO_GROUPS = ("sudo", "admin")

ACTION_PAM = ("/etc/pam.d/su отличается от файла пакета: добавьте строку «auth required pam_wheel.so use_uid» "
              "после «auth sufficient pam_rootok.so», создайте группу wheel и включите в неё root.")
ACTION_NO_SUDO = ("в группах sudo и admin нет пользователей: после ограничения su повысить права сможет только "
                  "root; назначьте администратора в группу sudo или выполните настройку вручную.")

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


def _admin(action):
    return {"class": "ADMIN_ACTION_REQUIRED", "required": True, "action": action}


def _read_pam(root):
    """(байты, stat) /etc/pam.d/su; не обычный файл, чужой владелец или запись для группы — отказ."""
    path = _p(root, PAM_SU)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise _Refused("ABORTED_PRECONDITION_OTHER", "pam:read-failed")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o022 or (root is None and st.st_uid != 0):
            raise _Refused("ABORTED_PRECONDITION_CONFLICT", "pam:untrusted", _admin(ACTION_PAM))
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks), st


def pam_state(raw):
    digest = hashlib.sha256(raw).hexdigest()
    if digest == PAM_APPLIED_SHA256:
        return "applied"
    if digest == PAM_PACKAGE_SHA256 and raw.count(PAM_LINE_OLD) == 1:
        return "package"
    return "foreign"


def _read_groups(root):
    try:
        with open(_p(root, GROUP), "r", encoding="utf-8", errors="strict") as stream:
            lines = stream.read().split("\n")
    except (OSError, UnicodeDecodeError):
        raise _Refused("ABORTED_PRECONDITION_OTHER", "group:read-failed")
    groups = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 4:
            raise _Refused("ABORTED_PRECONDITION_OTHER", "group:invalid-line")
        if fields[0] in groups:
            if fields[0] == "wheel":
                raise _Refused("ABORTED_PRECONDITION_CONFLICT", "group:duplicate-wheel", _admin(ACTION_PAM))
            continue
        groups[fields[0]] = (fields[2], [m for m in fields[3].split(",") if m])
    return groups


def policy_current(state, groups):
    pam = {"applied": "present", "package": "absent"}.get(state, "not-determined")
    wheel = groups.get("wheel")
    return "pam_wheel=%s;wheel=%s;root=%s" % (
        pam, "absent" if wheel is None else "gid " + wheel[0],
        "member" if wheel is not None and "root" in wheel[1] else "missing")


def _default_run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def _tool(root, run, path, *args):
    try:
        cp = run([_p(root, path), *args], TOOL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return cp.returncode == 0


def _check_tools(root, paths):
    for path in paths:
        try:
            st = os.stat(_p(root, path))
        except OSError:
            raise _Refused("ABORTED_PRECONDITION_OTHER", "tools:missing:" + os.path.basename(path))
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            raise _Refused("ABORTED_PRECONDITION_OTHER", "tools:missing:" + os.path.basename(path))


def _write_pam(root, raw, st):
    path = _p(root, PAM_SU)
    tmp = path + ".slp-tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, raw)
        os.fchmod(fd, stat.S_IMODE(st.st_mode))
        if root is None:
            os.fchown(fd, st.st_uid, st.st_gid)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(tmp)
        raise
    os.close(fd)
    os.replace(tmp, path)


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
        "target": PAM_SU,
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


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None, _write=None):
    """Restrict su to the wheel group through /etc/pam.d/su and /etc/group.

    `_root`, `_run` и `_write` — только для тестов: корень файловой системы, запуск
    команд и запись PAM-файла.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run
    write = _write if _write is not None else _write_pam
    current = None

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, policy_current=current, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if control_id != CONTROL_ID or (key, op, expected) != CONTROL_SPEC:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    try:
        actions.append("P1_OBSERVE")
        raw, st = _read_pam(_root)
        state = pam_state(raw)
        groups = _read_groups(_root)
        current = policy_current(state, groups)
        if state == "foreign":
            raise _Refused("ABORTED_PRECONDITION_CONFLICT", "pam:foreign-content", _admin(ACTION_PAM))
        wheel = groups.get("wheel")
        create = wheel is None
        add_root = create or "root" not in wheel[1]
        if state == "applied" and not add_root:
            return done("ALREADY_COMPLIANT")

        actions.append("P2_PLAN")
        if not any(groups.get(name, ("", []))[1] for name in SUDO_GROUPS):
            raise _Refused("ABORTED_PRECONDITION_CONFLICT", "su:no-sudo-members", _admin(ACTION_NO_SUDO))
        _check_tools(_root, ([GROUPADD, GROUPDEL] if create else []) + ([GPASSWD] if add_root else []))
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY")

        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            return done("ABORTED_PRECONDITION_OTHER", reason="privilege")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, operator_decision=exc.decision)

    created = root_added = pam_written = False

    def compensate(reason):
        actions.append("COMPENSATION")
        ok = True
        if pam_written:
            try:
                write(_root, raw, st)
            except OSError:
                ok = False
        if created:
            ok = _tool(_root, run, GROUPDEL, "wheel") and ok
        elif root_added:
            ok = _tool(_root, run, GPASSWD, "-d", "root", "wheel") and ok
        mutated = created or root_added or pam_written
        if ok:
            return done("FAILED_NOT_COMMITTED", reason=reason, mutation=mutated)
        return done("FAILED_COMPENSATION", reason=reason, mutation=mutated)

    actions.append("PHASE1_GROUP")
    if create:
        if not _tool(_root, run, GROUPADD, "--system", "wheel"):
            return compensate("group:groupadd-failed")
        created = True
    if add_root:
        if not _tool(_root, run, GPASSWD, "-a", "root", "wheel"):
            return compensate("group:gpasswd-failed")
        root_added = True
    if state == "package":
        actions.append("PHASE2_PAM")
        try:
            write(_root, raw.replace(PAM_LINE_OLD, PAM_LINE_NEW), st)
            pam_written = True
        except OSError:
            return compensate("pam:write-failed")
    actions.append("FINAL_POSTCHECK")
    try:
        after_state = pam_state(_read_pam(_root)[0])
        after_wheel = _read_groups(_root).get("wheel")
    except _Refused:
        return compensate("postcheck:read-failed")
    if after_state != "applied" or after_wheel is None or "root" not in after_wheel[1]:
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
