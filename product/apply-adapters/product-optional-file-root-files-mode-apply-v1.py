#!/usr/bin/env python3
"""product-optional-file-root-files-mode-apply-v1.

APPLY adapter for mechanism `optional-file-root-files-mode-v1` (2.3.6 cron roots).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-optional-file-root-files-mode-v1.json

Population is the one of CHECK adapter product-optional-file-root-files-mode-check-v1:
the root itself plus its direct entries, which must all be regular files. The
enumerator below is a Python copy of that shell observer; parity is checked by
tests/product-v1/test_optional_file_root_files_mode_apply_adapter.py.

The plan is built before any mutation. A symlink or a non-regular entry in the
population refuses the control without mutation. A violator with st_nlink > 1
is skipped and recorded. Each mutation is one `fchmod` on a descriptor opened
with O_NOFOLLOW and only clears bits; there is no compensation. An error on one
object does not stop the others (APPLIED_PARTIAL); EROFS stops immediately.
"""

from __future__ import annotations

import errno
import os
import re
import stat

ADAPTER_ID = "product-optional-file-root-files-mode-apply-v1"
MECHANISM_ID = "optional-file-root-files-mode-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "optional-file-root-files-mode"
SEMANTIC_CONTRACT_ID = "optional-file-root-files-mode-apply-semantic-v1"

SUPPORTED_KEYS = ("mode",)
SUPPORTED_OPS = ("bits-clear",)
EXPECTED_MASK = "0033"

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

# Корень каждого контроля. Совпадение с parameter.locator контролей проверяет
# test_optional_file_root_files_mode_apply_adapter.py.
TARGETS = {
    "FSTEC-LINUX-2022-2.3.6-CRONTAB": "/etc/crontab",
    "FSTEC-LINUX-2022-2.3.6-CRON-D": "/etc/cron.d",
    "FSTEC-LINUX-2022-2.3.6-CRON-HOURLY": "/etc/cron.hourly",
    "FSTEC-LINUX-2022-2.3.6-CRON-DAILY": "/etc/cron.daily",
    "FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY": "/etc/cron.weekly",
    "FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY": "/etc/cron.monthly",
}

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"

# Причины CHECK, которые означают объект не того типа в популяции.
CONFLICT_REASONS = ("root:symlink", "root:invalid-type", "target:symlink", "target:invalid-type")


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if key not in SUPPORTED_KEYS:
        raise ValueError("unsupported key: %r" % (key,))
    if op not in SUPPORTED_OPS:
        raise ValueError("unsupported op: %r" % (op,))
    if expected != EXPECTED_MASK:
        raise ValueError("only bits-clear 0033 is supported")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _mode_text(mode: int) -> str:
    return format(stat.S_IMODE(mode), "04o")


def _population(root, mask):
    """Копия CHECK-наблюдателя: ("ERROR", reason) | ("ABSENT", None) | ("VALUE", [(path, lstat)])."""
    if os.path.islink(root):
        return "ERROR", "root:symlink"
    if not os.path.exists(root):
        parent = root.rsplit("/", 1)[0] or "/"
        if not os.path.lexists(parent):
            return "ERROR", "root:parent-not-found"
        if not os.path.isdir(parent):
            return "ERROR", "root:parent-invalid-type"
        if not os.access(parent, os.X_OK):
            return "ERROR", "root:parent-unsearchable"
        return "ABSENT", None
    try:
        root_st = os.lstat(root)
    except OSError:
        return "ERROR", "root:mode-read-failed"
    items = [(root, root_st)]
    if stat.S_ISREG(root_st.st_mode):
        return "VALUE", items
    if not stat.S_ISDIR(root_st.st_mode):
        return "ERROR", "root:invalid-type"
    try:
        with os.scandir(root) as it:
            names = sorted((entry.name for entry in it), key=os.fsencode)
    except OSError:
        return "ERROR", "scan:find-failed"
    for name in names:
        path = os.path.join(root, name)
        try:
            st = os.lstat(path)
        except OSError:
            return "ERROR", "target:mode-read-failed"
        if stat.S_ISLNK(st.st_mode):
            return "ERROR", "target:symlink"
        if not stat.S_ISREG(st.st_mode):
            return "ERROR", "target:invalid-type"
        items.append((path, st))
    return "VALUE", items


def observe(root, expected=EXPECTED_MASK):
    """(status, value) в формате CHECK-адаптера для корня root."""
    mask = int(expected, 8)
    status, data = _population(root, mask)
    if status == "ERROR":
        return "ERROR", data
    if status == "ABSENT":
        return "VALUE", "<absent>"
    violations = sum(1 for _path, st in data if stat.S_IMODE(st.st_mode) & mask)
    return "VALUE", "checked=%d;violations=%d" % (len(data), violations)


def _default_privilege_check() -> bool:
    return os.geteuid() == 0


def _default_fchmod(fd, mode, path):
    os.fchmod(fd, mode)


def _result(control_id, target, outcome, *, actions, dry_run, mutation=False, **extra):
    record = {
        "adapter_id": ADAPTER_ID,
        "mechanism_id": MECHANISM_ID,
        "control_id": control_id,
        "target": target,
        "outcome": outcome,
        "reason": None,
        "current_mode": None,
        "violators": [],
        "applied": [],
        "skipped": [],
        "failed": [],
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


def _apply_one(path, observed, mask, fchmod):
    """Снять биты mask у одного объекта. Возвращает (mutated, failure_reason|None)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return False, "symlink"
        return False, "open:%s" % errno.errorcode.get(exc.errno, exc.errno)
    try:
        now = os.fstat(fd)
        if (now.st_dev, now.st_ino) != (observed.st_dev, observed.st_ino):
            return False, "identity-drift"
        if stat.S_IFMT(now.st_mode) != stat.S_IFMT(observed.st_mode):
            return False, "type-drift"
        if stat.S_ISREG(now.st_mode) and now.st_nlink != 1:
            return False, "st_nlink"
        if (now.st_uid, now.st_gid) != (observed.st_uid, observed.st_gid):
            return False, "ownership-drift"
        current = stat.S_IMODE(now.st_mode)
        if current != stat.S_IMODE(observed.st_mode):
            return False, "mode-drift"
        planned = current & ~mask
        fchmod(fd, planned, path)
        post = os.fstat(fd)
        if (
            stat.S_IMODE(post.st_mode) != planned
            or (post.st_uid, post.st_gid) != (now.st_uid, now.st_gid)
            or (post.st_dev, post.st_ino) != (now.st_dev, now.st_ino)
            or post.st_size != now.st_size
        ):
            return True, "post-state-mismatch"
        return True, None
    finally:
        os.close(fd)


def execute_control(
    control_id,
    key,
    op,
    expected,
    apply_supported,
    *,
    target=None,
    dry_run,
    privilege_check=None,
    _fchmod=None,
):
    """Apply one optional root control. Never follows a symlink, never relaxes."""
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]

    def done(outcome, **extra):
        return _result(control_id, target, outcome, actions=actions, dry_run=dry_run, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")

    if target is None:
        target = TARGETS.get(control_id)
        if target is None:
            return done("ABORTED_PRECONDITION_OTHER", reason="target:unmapped-control")

    mask = int(expected, 8)
    actions.append("P1_POPULATION")
    status, data = _population(target, mask)
    if status == "ERROR":
        outcome = "ABORTED_PRECONDITION_CONFLICT" if data in CONFLICT_REASONS else "ABORTED_PRECONDITION_OTHER"
        return done(outcome, reason=data)
    if status == "ABSENT":
        return done("ALREADY_COMPLIANT", reason="absent", current_mode="<absent>")

    actions.append("P2_PLAN")
    violators = [(path, st) for path, st in data if stat.S_IMODE(st.st_mode) & mask]
    current = "checked=%d;violations=%d" % (len(data), len(violators))
    if not violators:
        return done("ALREADY_COMPLIANT", current_mode=current)
    skipped = [
        {"path": path, "reason": "st_nlink"}
        for path, st in violators
        if stat.S_ISREG(st.st_mode) and st.st_nlink != 1
    ]
    skipped_paths = {item["path"] for item in skipped}
    planned = [(path, st) for path, st in violators if path not in skipped_paths]
    violator_paths = [path for path, _st in violators]
    if not planned:
        return done("ABORTED_PRECONDITION_CONFLICT", reason="st_nlink", current_mode=current,
                    violators=violator_paths, skipped=skipped)
    if dry_run:
        return done("DRY_RUN_WOULD_APPLY", current_mode=current,
                    violators=violator_paths, skipped=skipped)

    actions.append("P3_PRIVILEGE")
    check = privilege_check if privilege_check is not None else _default_privilege_check
    if not check():
        return done("ABORTED_PRECONDITION_OTHER", reason="privilege", current_mode=current,
                    violators=violator_paths, skipped=skipped)

    actions.append("PHASE1_MODE")
    fchmod = _fchmod if _fchmod is not None else _default_fchmod
    applied, failed = [], []
    mutated = False
    for path, st in planned:
        try:
            changed, failure = _apply_one(path, st, mask, fchmod)
        except OSError as exc:
            if exc.errno == errno.EROFS:
                outcome = "APPLIED_PARTIAL" if mutated else "ABORTED_PRECONDITION_OTHER"
                return done(outcome, reason="erofs", mutation=mutated, current_mode=current,
                            violators=violator_paths, applied=applied, skipped=skipped,
                            failed=failed + [{"path": path, "reason": "erofs"}])
            changed, failure = False, "fchmod:%s" % errno.errorcode.get(exc.errno, exc.errno)
        mutated = mutated or changed
        if failure is None:
            applied.append(path)
        else:
            failed.append({"path": path, "reason": failure})

    actions.append("FINAL_POSTCHECK")
    extra = dict(current_mode=current, violators=violator_paths, applied=applied,
                 skipped=skipped, failed=failed)
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
        "started_at": started_at,
        "finished_at": finished_at,
        "actions_attempted": list(result["actions_attempted"]),
        "step_rc": outcome_rc_contribution(result["outcome"], result["dry_run"]),
        "mutation_performed": result["mutation_performed"],
        "transaction_commit": result["transaction_commit"],
    }
