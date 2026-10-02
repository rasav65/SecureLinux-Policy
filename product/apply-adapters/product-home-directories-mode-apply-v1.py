#!/usr/bin/env python3
"""product-home-directories-mode-apply-v1.

APPLY-адаптер механизма home-directories-mode-v1 (fstec-linux-2022 2.3.11, SRC-0015).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-home-directories-mode-v1.json

Решение пользователя 29.09.2026: APPLY исправляет только домашние каталоги пользователей с
UID ≥ 1000 из /etc/passwd; прочие случаи — решение администратора. CHECK сохраняет проверку
непосредственных подкаталогов /home; популяции различаются намеренно, расширение APPLY до всех
подкаталогов /home — только отдельным решением.

* Популяция: строки /etc/passwd (файл, не NSS) с UID ≥ 1000 и абсолютным полем home.
  Отсутствующий home — вне популяции (создавать каталог источник не требует).
* Каталог открывается с O_DIRECTORY | O_NOFOLLOW; последний компонент — ссылка, не каталог,
  владелец не UID учётной записи (например, `/`, `/home` или общий каталог) или у владельца нет
  битов rwx — объект не меняется, решение администратора. Один каталог у нескольких записей —
  один объект (dev:ino).
* План строится до мутаций. Мутация — `fchmod(fd, 0700)` на проверенном дескрипторе: только
  снятие битов группы, прочих и специальных битов; компенсации нет (возврат прежнего режима
  ослабил бы защиту). Ошибка одного объекта не останавливает остальные (APPLIED_PARTIAL);
  EROFS останавливает сразу.
* Объекты решения администратора при исправленных прочих — APPLIED_PARTIAL; без исправленных —
  ABORTED_PRECONDITION_CONFLICT с готовым действием администратора.
"""

from __future__ import annotations

import errno
import os
import re
import stat

ADAPTER_ID = "product-home-directories-mode-apply-v1"
MECHANISM_ID = "home-directories-mode-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "home-directories-mode"
SEMANTIC_CONTRACT_ID = "home-directories-mode-apply-semantic-v1"

SUPPORTED_KEYS = ("mode",)
SUPPORTED_OPS = ("eq",)
EXPECTED_MODE = "0700"
UID_FLOOR = 1000
PASSWD_PATH = "/etc/passwd"
ID_MAX = 4294967294
ID_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,9})")

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

CONTROLS = ("FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE",)
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
ADMIN_ACTION = ("Проверить назначение каталога и владельца; при необходимости выполнить "
                "chmod 700 вручную.")


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if key not in SUPPORTED_KEYS:
        raise ValueError("unsupported key: %r" % (key,))
    if op not in SUPPORTED_OPS:
        raise ValueError("unsupported op: %r" % (op,))
    if expected != EXPECTED_MODE:
        raise ValueError("only eq 0700 is supported")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _mode_text(mode: int) -> str:
    return format(stat.S_IMODE(mode), "04o")


def parse_passwd(raw: bytes):
    """[(name, uid, home)] строк с UID ≥ UID_FLOOR; ValueError — файл не разобран."""
    if b"\x00" in raw or b"\r" in raw:
        raise ValueError("passwd:invalid-bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ValueError("passwd:invalid-bytes")
    rows = []
    for line in text.split("\n"):
        if not line:
            continue
        fields = line.split(":")
        if len(fields) != 7 or not fields[0]:
            raise ValueError("passwd:invalid-record")
        # UID и GID — только ASCII-цифры без ведущих нулей в диапазоне 0..ID_MAX.
        for value in (fields[2], fields[3]):
            if ID_PATTERN.fullmatch(value) is None or int(value, 10) > ID_MAX:
                raise ValueError("passwd:invalid-record")
        uid = int(fields[2], 10)
        if uid >= UID_FLOOR:
            rows.append((fields[0], uid, fields[5]))
    return rows


def _read_passwd(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("passwd:invalid-type")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _classify(name, uid, home):
    """("absent"|"admin"|"ok"|"plan", path, reason|None, stat|None) без мутаций."""
    if not home.startswith("/") or any(c in home for c in "\t\n\r"):
        return "admin", home, "home:not-absolute", None
    try:
        fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return "absent", home, None, None
        if exc.errno == errno.ELOOP:
            return "admin", home, "home:symlink", None
        if exc.errno == errno.ENOTDIR:
            try:
                st = os.lstat(home)
            except OSError:
                return "admin", home, "home:stat-failed", None
            return "admin", home, "home:symlink" if stat.S_ISLNK(st.st_mode) else "home:not-directory", None
        return "admin", home, "home:open:%s" % errno.errorcode.get(exc.errno, exc.errno), None
    try:
        st = os.fstat(fd)
    finally:
        os.close(fd)
    if st.st_uid != uid:
        return "admin", home, "home:owner-mismatch", st
    mode = stat.S_IMODE(st.st_mode)
    if mode == 0o700:
        return "ok", home, None, st
    if mode & 0o700 != 0o700:
        return "admin", home, "home:owner-bits-missing", st
    return "plan", home, None, st


def plan(passwd_path=PASSWD_PATH):
    """(error_reason|None, objects): objects — список словарей по одному на каталог (dev:ino)."""
    try:
        raw = _read_passwd(passwd_path)
        rows = parse_passwd(raw)
    except ValueError as exc:
        return str(exc), []
    except OSError as exc:
        return "passwd:open:%s" % errno.errorcode.get(exc.errno, exc.errno), []
    objects, seen = [], {}
    for name, uid, home in rows:
        kind, path, reason, st = _classify(name, uid, home)
        if kind == "absent":
            continue
        key = (st.st_dev, st.st_ino) if st is not None else ("path", path)
        if key in seen:
            prior = seen[key]
            if prior["kind"] != kind or prior["reason"] != reason:
                prior["kind"], prior["reason"] = "admin", "home:shared-conflict"
            continue
        item = {"kind": kind, "path": path, "reason": reason, "stat": st, "uid": uid}
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
        "target": PASSWD_PATH,
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


def _errname(exc):
    return errno.errorcode.get(exc.errno, str(exc.errno))


def _apply_one(item, fchmod):
    """Установить 0700 одному каталогу. Возвращает (mutated, failure_reason|None).

    OSError наружу выходит только из самого fchmod (мутации не было). Любая ошибка после
    успешного fchmod (fstat, close) возвращается с mutated=True: факт мутации не теряется.
    """
    path, observed = item["path"], item["stat"]
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return False, "type-drift"
        return False, "open:%s" % _errname(exc)
    state = {"mutated": False}
    try:
        result = _apply_fd(fd, observed, path, fchmod, state)
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
    """Проверки на дескрипторе, fchmod и итоговая проверка одного каталога."""
    now = os.fstat(fd)
    if (now.st_dev, now.st_ino) != (observed.st_dev, observed.st_ino):
        return False, "identity-drift"
    if not stat.S_ISDIR(now.st_mode):
        return False, "type-drift"
    if (now.st_uid, now.st_gid) != (observed.st_uid, observed.st_gid):
        return False, "ownership-drift"
    current = stat.S_IMODE(now.st_mode)
    if current != stat.S_IMODE(observed.st_mode):
        return False, "mode-drift"
    if 0o700 & ~current:
        return False, "mode-relaxation-forbidden"
    try:
        fchmod(fd, 0o700, path)
    except OSError as exc:
        exc._slp_fchmod = True
        raise
    state["mutated"] = True
    post = os.fstat(fd)
    if (
        stat.S_IMODE(post.st_mode) != 0o700
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
    passwd_path=PASSWD_PATH,
    privilege_check=None,
    _fchmod=None,
):
    """Установить 0700 домашним каталогам пользователей с UID ≥ 1000. Ссылки не разрешаются."""
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if control_id not in CONTROLS:
        return done("ABORTED_PRECONDITION_OTHER", reason="target:unmapped-control")

    actions.append("P1_POPULATION")
    error, objects = plan(passwd_path)
    if error is not None:
        return done("ABORTED_PRECONDITION_OTHER", reason=error)

    actions.append("P2_PLAN")
    planned = [item for item in objects if item["kind"] == "plan"]
    admin = [item for item in objects if item["kind"] == "admin"]
    skipped = [{"path": item["path"], "reason": item["reason"]} for item in admin]
    current = "checked=%d;violations=%d;admin=%d" % (len(objects), len(planned), len(admin))
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
