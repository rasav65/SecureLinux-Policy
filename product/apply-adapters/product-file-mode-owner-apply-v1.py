#!/usr/bin/env python3
"""product-file-mode-owner-apply-v1.

APPLY adapter for mechanism `file-mode-owner-v1`.

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-file-mode-owner-v1.json

Mutation is a single `fchmod` on a file descriptor opened with O_NOFOLLOW.
The mechanism only clears permission bits: any planned mode that would add a
bit absent from the current mode is refused before the syscall. There is no
compensation path, because restoring a weaker prior mode is a security
weakening and the authority forbids it.
"""

from __future__ import annotations

import errno
import os
import re
import stat

ADAPTER_ID = "product-file-mode-owner-apply-v1"
MECHANISM_ID = "file-mode-owner-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "file-mode-owner"
SEMANTIC_CONTRACT_ID = "file-mode-owner-apply-semantic-v1"

SUPPORTED_KEYS = ("mode",)
SUPPORTED_OPS = ("eq", "bits-clear")

OUTCOMES = (
    "APPLIED",
    "ALREADY_COMPLIANT",
    "DRY_RUN_WOULD_APPLY",
    "NOT_ELIGIBLE_APPLY_UNSUPPORTED",
    "ABORTED_PRECONDITION_CONFLICT",
    "ABORTED_PRECONDITION_OTHER",
    "FAILED_NOT_COMMITTED",
)

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
MODE4_PATTERN = r"^[0-7]{4}$"


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if key not in SUPPORTED_KEYS:
        raise ValueError("unsupported key: %r" % (key,))
    if op not in SUPPORTED_OPS:
        raise ValueError("unsupported op: %r" % (op,))
    if not isinstance(expected, str) or not re.fullmatch(MODE4_PATTERN, expected):
        raise ValueError("expected must be exactly four octal digits")
    if op == "bits-clear" and expected == "0000":
        raise ValueError("bits-clear mask 0000 is forbidden")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _mode_text(mode: int) -> str:
    return format(stat.S_IMODE(mode), "04o")


def _default_privilege_check(fd: int) -> bool:
    """Root, or the caller already owns the object. Anything else is refused."""
    euid = os.geteuid()
    return euid == 0 or os.fstat(fd).st_uid == euid


def _result(control_id, target, outcome, **extra):
    record = {
        "adapter_id": ADAPTER_ID,
        "mechanism_id": MECHANISM_ID,
        "control_id": control_id,
        "target": target,
        "outcome": outcome,
        "reason": None,
        "current_mode": None,
        "planned_mode": None,
        "resulting_mode": None,
    }
    record.update(extra)
    if record["outcome"] not in OUTCOMES:
        raise ValueError("outcome outside closed vocabulary")
    return record


def compute_planned_mode(op: str, current: int, expected: str) -> int:
    value = int(expected, 8)
    if op == "eq":
        return value
    return stat.S_IMODE(current) & ~value


def is_compliant(op: str, current: int, expected: str) -> bool:
    value = int(expected, 8)
    mode = stat.S_IMODE(current)
    return mode == value if op == "eq" else (mode & value) == 0


def execute_control(
    control_id,
    key,
    op,
    expected,
    apply_supported,
    *,
    target,
    dry_run,
    privilege_check=None,
    _pre_syscall_hook=None,
):
    """Apply one file-mode control. Never follows a symlink, never relaxes."""
    validate_control_input(control_id, key, op, expected, apply_supported)

    if not apply_supported:
        return _result(control_id, target, "NOT_ELIGIBLE_APPLY_UNSUPPORTED",
                       reason="apply-unsupported")

    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            return _result(control_id, target, "ABORTED_PRECONDITION_CONFLICT",
                           reason="symlink")
        if exc.errno == errno.ENOENT:
            return _result(control_id, target, "ABORTED_PRECONDITION_OTHER",
                           reason="absent")
        return _result(control_id, target, "ABORTED_PRECONDITION_OTHER",
                       reason="open:%s" % errno.errorcode.get(exc.errno, exc.errno))

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return _result(control_id, target, "ABORTED_PRECONDITION_CONFLICT",
                           reason="not-regular")
        if st.st_nlink != 1:
            return _result(control_id, target, "ABORTED_PRECONDITION_CONFLICT",
                           reason="st_nlink")

        current = stat.S_IMODE(st.st_mode)
        if is_compliant(op, current, expected):
            return _result(control_id, target, "ALREADY_COMPLIANT",
                           current_mode=_mode_text(current),
                           resulting_mode=_mode_text(current))

        planned = compute_planned_mode(op, current, expected)
        if planned & ~current:
            return _result(control_id, target, "ABORTED_PRECONDITION_CONFLICT",
                           reason="mode-relaxation-forbidden",
                           current_mode=_mode_text(current),
                           planned_mode=_mode_text(planned))

        if dry_run:
            return _result(control_id, target, "DRY_RUN_WOULD_APPLY",
                           current_mode=_mode_text(current),
                           planned_mode=_mode_text(planned))

        check = privilege_check if privilege_check is not None else (lambda: _default_privilege_check(fd))
        if not check():
            return _result(control_id, target, "ABORTED_PRECONDITION_OTHER",
                           reason="privilege",
                           current_mode=_mode_text(current),
                           planned_mode=_mode_text(planned))

        if _pre_syscall_hook is not None:
            _pre_syscall_hook()

        drift = _revalidate(fd, target, st, op, expected, planned)
        if drift is not None:
            return _result(control_id, target, "ABORTED_PRECONDITION_CONFLICT",
                           reason=drift,
                           current_mode=_mode_text(current),
                           planned_mode=_mode_text(planned))

        os.fchmod(fd, planned)

        post = os.fstat(fd)
        resulting = stat.S_IMODE(post.st_mode)
        if (
            resulting != planned
            or post.st_uid != st.st_uid
            or post.st_gid != st.st_gid
            or post.st_ino != st.st_ino
            or post.st_dev != st.st_dev
            or post.st_size != st.st_size
        ):
            return _result(control_id, target, "FAILED_NOT_COMMITTED",
                           reason="post-state-mismatch",
                           current_mode=_mode_text(current),
                           planned_mode=_mode_text(planned),
                           resulting_mode=_mode_text(resulting))

        return _result(control_id, target, "APPLIED",
                       current_mode=_mode_text(current),
                       planned_mode=_mode_text(planned),
                       resulting_mode=_mode_text(resulting))
    finally:
        os.close(fd)


def _revalidate(fd, target, observed, op, expected, planned):
    """Return a drift reason, or None when the object is still the planned one."""
    try:
        path_st = os.lstat(target)
    except OSError:
        return "identity-drift"
    if (path_st.st_dev, path_st.st_ino) != (observed.st_dev, observed.st_ino):
        return "identity-drift"
    now = os.fstat(fd)
    if not stat.S_ISREG(now.st_mode):
        return "not-regular"
    if now.st_nlink != 1:
        return "st_nlink"
    if (now.st_uid, now.st_gid) != (observed.st_uid, observed.st_gid):
        return "ownership-drift"
    if stat.S_IMODE(now.st_mode) != stat.S_IMODE(observed.st_mode):
        return "mode-drift"
    if is_compliant(op, stat.S_IMODE(now.st_mode), expected):
        return "mode-drift"
    if planned & ~stat.S_IMODE(now.st_mode):
        return "mode-relaxation-forbidden"
    return None


def control_result_to_report(result, started_at, finished_at):
    report = {
        "adapter_id": result["adapter_id"],
        "mechanism_id": result["mechanism_id"],
        "control_id": result["control_id"],
        "target": result["target"],
        "outcome": result["outcome"],
        "reason": result["reason"],
        "current_mode": result["current_mode"],
        "planned_mode": result["planned_mode"],
        "resulting_mode": result["resulting_mode"],
        "started_at": started_at,
        "finished_at": finished_at,
    }
    return report
