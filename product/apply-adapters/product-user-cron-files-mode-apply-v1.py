#!/usr/bin/env python3
"""product-user-cron-files-mode-apply-v1.

APPLY-адаптер механизма user-cron-files-mode-v1 (fstec-linux-2022 2.3.7, SRC-0011).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-user-cron-files-mode-v1.json

Решение ведущего 29.09.2026 по образцу решения пользователя для 2.3.3 (та же форма источника
«chmod go-w путь_к_файлу»): APPLY снимает биты записи группы и прочих у всей популяции CHECK при
любом владельце файла.

* Популяция — та же, что у CHECK product-user-cron-files-mode-check-v2: непосредственные
  элементы /var/spool/cron/crontabs. Нет каталога (или предка) — популяции нет. Ссылка или не
  каталог на месте каталога или его предка — отказ без изменений.
* Каталог открывается с O_DIRECTORY | O_NOFOLLOW, элемент — относительно его дескриптора с
  O_NOFOLLOW | O_NONBLOCK. Объект — каждое имя в каталоге (как у CHECK). Обычный файл без битов
  0022 соответствует требованию при любом имени и числе ссылок (действие не нужно). Ссылка, не
  обычный файл, а для несоответствующего файла — больше одной жёсткой ссылки или управляющие
  байты в имени — решение администратора без изменений.
* План строится до мутаций. Мутация — `fchmod(fd, mode & ~0o022)` на проверенном дескрипторе:
  только снятие битов; компенсации нет (возврат прежнего режима ослабил бы защиту). Ошибка
  одного объекта не останавливает остальные (APPLIED_PARTIAL); EROFS останавливает сразу.
"""

from __future__ import annotations

import errno
import os
import re
import stat

ADAPTER_ID = "product-user-cron-files-mode-apply-v1"
MECHANISM_ID = "user-cron-files-mode-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "user-cron-files-mode"
SEMANTIC_CONTRACT_ID = "user-cron-files-mode-apply-semantic-v1"

SUPPORTED_KEYS = ("mode",)
SUPPORTED_OPS = ("bits-clear",)
EXPECTED_MASK = "0022"
CLEAR_BITS = 0o022
CANONICAL_ROOT = "/var/spool/cron/crontabs"

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

CONTROLS = ("FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE",)
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
INVALID_NAME = "<invalid-name>"
ADMIN_ACTION = ("Проверить файл заданий cron пользователя и его жёсткие ссылки; при "
                "необходимости выполнить chmod go-w вручную.")

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if key not in SUPPORTED_KEYS:
        raise ValueError("unsupported key: %r" % (key,))
    if op not in SUPPORTED_OPS:
        raise ValueError("unsupported op: %r" % (op,))
    if expected != EXPECTED_MASK:
        raise ValueError("only bits-clear 0022 is supported")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _errname(exc):
    return errno.errorcode.get(exc.errno, str(exc.errno))


def _bad_bytes(text):
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in text)


def _root_state(root):
    """("absent"|"ok", None) или ("error", reason) для каталога и его предков."""
    parts = [p for p in root.split("/") if p]
    path = ""
    for index, part in enumerate(parts):
        path += "/" + part
        last = index == len(parts) - 1
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return "absent", None
        except OSError as exc:
            return "error", ("cron-root:stat:%s" if last else "cron-root:ancestor-stat:%s") % _errname(exc)
        if stat.S_ISLNK(st.st_mode):
            return "error", "cron-root:symlink" if last else "cron-root:ancestor-symlink"
        if not stat.S_ISDIR(st.st_mode):
            return "error", "cron-root:invalid-type" if last else "cron-root:ancestor-invalid-type"
    return "ok", None


def plan(root=CANONICAL_ROOT):
    """(error_reason|None, objects, root_stat): по одному словарю на каждый элемент каталога.

    Как у CHECK, объект — имя в каталоге, а не inode: два имени одного файла — два объекта.
    Соответствующий требованию файл не требует действий при любом имени и числе ссылок.
    """
    state, reason = _root_state(root)
    if state == "error":
        return reason, [], None
    if state == "absent":
        return None, [], None
    try:
        dfd = os.open(root, _DIR_FLAGS)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None, [], None
        return "cron-root:open:%s" % _errname(exc), [], None
    objects = []
    try:
        rst = os.fstat(dfd)
        names = sorted(os.listdir(dfd), key=os.fsencode)
        for name in names:
            path = root.rstrip("/") + "/" + name
            shown = INVALID_NAME if _bad_bytes(name) else path
            try:
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                objects.append({"kind": "admin", "path": shown, "name": name,
                                "reason": "cron-file:stat:%s" % _errname(exc), "stat": None})
                continue
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                kind, why = "admin", "cron-file:symlink"
            elif not stat.S_ISREG(st.st_mode):
                kind, why = "admin", "cron-file:invalid-type"
            elif mode & CLEAR_BITS == 0:
                kind, why = "ok", None
            elif shown == INVALID_NAME:
                kind, why = "admin", "cron-file:invalid-name"
            elif st.st_nlink != 1:
                kind, why = "admin", "cron-file:hardlink"
            else:
                kind, why = "plan", None
            objects.append({"kind": kind, "path": shown, "name": name, "reason": why, "stat": st})
    except OSError as exc:
        return "cron-root:scan:%s" % _errname(exc), [], None
    finally:
        os.close(dfd)
    return None, objects, rst


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
        "target": CANONICAL_ROOT,
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


def _apply_one(item, root, rst, fchmod):
    """Снять биты 0022 одного файла. Возвращает (mutated, failure_reason|None).

    OSError наружу выходит только из самого fchmod (мутации не было). Любая ошибка после
    успешного fchmod (fstat, close) возвращается с mutated=True: факт мутации не теряется.
    Ошибка закрытия каталога не выходит наружу; дескриптор файла закрывается всегда.
    """
    try:
        dfd = os.open(root, _DIR_FLAGS)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return False, "root-type-drift"
        return False, "root-open:%s" % _errname(exc)
    fd = None
    early = None
    try:
        try:
            now = os.fstat(dfd)
        except OSError as exc:
            early = (False, "root-stat:%s" % _errname(exc))
        else:
            if (now.st_dev, now.st_ino) != (rst.st_dev, rst.st_ino):
                early = (False, "root-identity-drift")
            else:
                try:
                    fd = os.open(item["name"], _FILE_FLAGS, dir_fd=dfd)
                except OSError as exc:
                    early = (False, "type-drift" if exc.errno == errno.ELOOP else "open:%s" % _errname(exc))
    finally:
        try:
            os.close(dfd)
        except OSError as exc:
            if early is None:
                early = (False, "root-close:%s" % _errname(exc))
    if early is not None:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        return early
    state = {"mutated": False}
    try:
        result = _apply_fd(fd, item["stat"], item["path"], fchmod, state)
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
    if (now.st_dev, now.st_ino) != (observed.st_dev, observed.st_ino):
        return False, "identity-drift"
    if not stat.S_ISREG(now.st_mode):
        return False, "type-drift"
    if (now.st_uid, now.st_gid) != (observed.st_uid, observed.st_gid):
        return False, "ownership-drift"
    if now.st_nlink != 1:
        return False, "hardlink-drift"
    current = stat.S_IMODE(now.st_mode)
    if current != stat.S_IMODE(observed.st_mode):
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
    root=CANONICAL_ROOT,
    privilege_check=None,
    _fchmod=None,
):
    """Снять биты записи группы и прочих у пользовательских файлов заданий cron."""
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if control_id not in CONTROLS:
        return done("ABORTED_PRECONDITION_OTHER", reason="target:unmapped-control")

    actions.append("P1_POPULATION")
    error, objects, rst = plan(root)
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
            changed, failure = _apply_one(item, root, rst, fchmod)
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
