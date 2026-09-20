#!/usr/bin/env python3
"""product-suid-sgid-applications-mode-apply-v1.

APPLY adapter for mechanism `suid-sgid-applications-mode-v1` (2.3.9 SUID/SGID mode).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-suid-sgid-applications-mode-v1.json

Механизм обслуживает parameter_kind `suid-sgid-applications`, но только контроль
`FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE` (`mode` / `bits-clear` / `0022`). Контроль
`…-ALLOWLIST` (`approved-set` / `subset-of-file`) решается администратором:
любая иная тройка (key, op, expected) даёт `NOT_ELIGIBLE_APPLY_UNSUPPORTED`.

Population is the one of CHECK adapter product-suid-sgid-applications-check-v2:
`find -P <mountpoint> -xdev -type f -perm /6000` по всем непсевдо-точкам
монтирования из mountinfo, с дедупликацией точек и файлов по `dev:ino`.
Перечислитель ниже — Python-копия того shell-наблюдателя; паритет проверяется
tests/product-v1/test_suid_sgid_applications_mode_apply_adapter.py.

The plan is built before any mutation. A violator with st_nlink > 1 is skipped
and recorded. Перед мутацией объект ревалидируется на уже открытом дескрипторе
строго в порядке `S_ISREG` → `dev/ino` из плана → наличие битов `06000`;
несовпадение любого шага — пропуск объекта с причиной. Each mutation is one
`fchmod` on a descriptor opened with O_NOFOLLOW and only clears bits; there is
no compensation. An error on one object does not stop the others
(APPLIED_PARTIAL); EROFS stops immediately.
"""

from __future__ import annotations

import errno
import os
import re
import stat

ADAPTER_ID = "product-suid-sgid-applications-mode-apply-v1"
MECHANISM_ID = "suid-sgid-applications-mode-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "suid-sgid-applications"
SEMANTIC_CONTRACT_ID = "suid-sgid-applications-mode-apply-semantic-v1"

SUPPORTED_KEYS = ("mode",)
SUPPORTED_OPS = ("bits-clear",)
EXPECTED_MASK = "0022"

# Биты, по которым CHECK отбирает популяцию (SUID/SGID).
SELECT_BITS = 0o6000

CANONICAL_LOCATOR = "/proc/self/mountinfo"

# Псевдофайловые системы CHECK-адаптера product-suid-sgid-applications-check-v2.
PSEUDO_FS = (
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2",
    "securityfs", "pstore", "bpf", "tracefs", "debugfs", "configfs",
    "fusectl", "mqueue", "hugetlbfs", "ramfs", "autofs",
    "binfmt_misc", "nsfs", "efivarfs",
)

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

# Локатор единственного контроля механизма. Совпадение с parameter.locator
# проверяет test_suid_sgid_applications_mode_apply_adapter.py.
TARGETS = {
    "FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE": CANONICAL_LOCATOR,
}

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"

# Причины CHECK, которые означают, что сам локатор — объект не того типа.
CONFLICT_REASONS = ("mountinfo:symlink", "mountinfo:invalid-type")

_OCTAL_ESCAPE = re.compile(r"\\0?([0-7]{1,3})")
_FORBIDDEN_PATH_CHARS = ("\r", "\n", "\t")


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not isinstance(key, str) or not isinstance(op, str) or not isinstance(expected, str):
        raise ValueError("key, op and expected must be strings")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _is_eligible_contract(key, op, expected):
    """Только (mode, bits-clear, 0022); всё прочее решает администратор."""
    return key in SUPPORTED_KEYS and op in SUPPORTED_OPS and expected == EXPECTED_MASK


def _unescape_mountpoint(raw):
    """Аналог `printf -v mp "%b"` для поля mount point (\\040, \\011, \\134)."""
    return _OCTAL_ESCAPE.sub(lambda m: chr(int(m.group(1), 8) & 0xFF), raw)


def _scan_mount(mountpoint, found):
    """find -P <mountpoint> -xdev -type f -perm /6000. Возвращает reason | None."""
    try:
        root_dev = os.stat(mountpoint).st_dev
    except OSError:
        return "scan:find-failed"
    stack = [mountpoint]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError:
            return "scan:find-failed"
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                return "scan:find-failed"
            if stat.S_ISDIR(st.st_mode):
                if st.st_dev == root_dev:
                    stack.append(entry.path)
            elif stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) & SELECT_BITS:
                found.append((entry.path, st))
    return None


def _population(mountinfo_path):
    """Копия CHECK-наблюдателя: ("ERROR", reason) | ("VALUE", (mounts, [(path, lstat)]))."""
    if os.path.islink(mountinfo_path):
        return "ERROR", "mountinfo:symlink"
    if not os.path.exists(mountinfo_path):
        return "ERROR", "mountinfo:not-found"
    if not os.path.isfile(mountinfo_path):
        return "ERROR", "mountinfo:invalid-type"
    if not os.access(mountinfo_path, os.R_OK):
        return "ERROR", "mountinfo:unreadable"
    try:
        with open(mountinfo_path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return "ERROR", "mountinfo:read-failed"
    if b"\x00" in raw:
        return "ERROR", "mountinfo:invalid-bytes"

    seen_mounts = set()
    seen_files = set()
    items = []
    mounts = 0
    for line in raw.decode("utf-8", "surrogateescape").split("\n"):
        if not line:
            continue
        fields = line.split(" ", 6)
        if len(fields) != 7 or not all(fields):
            return "ERROR", "mountinfo:invalid-fields"
        tail = fields[6]
        if tail.startswith("- "):
            after = tail[2:]
        elif " - " in tail:
            after = tail.split(" - ", 1)[1]
        else:
            return "ERROR", "mountinfo:missing-separator"
        fstype = after.split(" ", 1)[0]
        if not fstype:
            return "ERROR", "mountinfo:missing-fstype"
        if fstype in PSEUDO_FS:
            continue
        mountpoint = _unescape_mountpoint(fields[4])
        if not mountpoint.startswith("/") or any(c in mountpoint for c in _FORBIDDEN_PATH_CHARS):
            return "ERROR", "mountinfo:invalid-mountpoint"
        if not os.path.isdir(mountpoint):
            return "ERROR", "mountinfo:missing-mountpoint"
        try:
            root_st = os.stat(mountpoint)
        except OSError:
            return "ERROR", "mountinfo:identity-failed"
        identity = (root_st.st_dev, root_st.st_ino)
        if identity in seen_mounts:
            continue
        seen_mounts.add(identity)
        mounts += 1

        found = []
        reason = _scan_mount(mountpoint, found)
        if reason is not None:
            return "ERROR", reason
        found.sort(key=lambda pair: os.fsencode(pair[0]))
        for path, st in found:
            if any(c in path for c in _FORBIDDEN_PATH_CHARS):
                return "ERROR", "target:invalid-path"
            file_identity = (st.st_dev, st.st_ino)
            if file_identity in seen_files:
                continue
            seen_files.add(file_identity)
            items.append((path, st))

    if mounts == 0:
        return "ERROR", "mountinfo:empty-population"
    return "VALUE", (mounts, items)


def _current_value(mounts, items, mask):
    violations = sum(1 for _path, st in items if stat.S_IMODE(st.st_mode) & mask)
    return "mounts=%d;checked=%d;violations=%d" % (mounts, len(items), violations)


def observe(mountinfo_path=CANONICAL_LOCATOR, expected=EXPECTED_MASK):
    """(status, value) в формате CHECK-адаптера для одного mountinfo."""
    mask = int(expected, 8)
    status, data = _population(mountinfo_path)
    if status == "ERROR":
        return "ERROR", data
    mounts, items = data
    return "VALUE", _current_value(mounts, items, mask)


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
    """Те же значения, что у optional-file-root-files-mode."""
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
    """Снять биты mask у одного объекта.

    Возвращает (mutated, kind, reason): kind — "ok", "skip" или "fail".
    Ревалидация на дескрипторе строго в порядке S_ISREG -> dev/ino -> 06000.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return False, "skip", "not-regular"
        return False, "fail", "open:%s" % errno.errorcode.get(exc.errno, exc.errno)
    try:
        now = os.fstat(fd)
        if not stat.S_ISREG(now.st_mode):
            return False, "skip", "not-regular"
        if (now.st_dev, now.st_ino) != (observed.st_dev, observed.st_ino):
            return False, "skip", "identity-drift"
        if not stat.S_IMODE(now.st_mode) & SELECT_BITS:
            return False, "skip", "no-suid-sgid"
        if now.st_nlink != 1:
            return False, "skip", "st_nlink"
        current = stat.S_IMODE(now.st_mode)
        planned = current & ~mask
        if planned == current:
            return False, "skip", "no-violation"
        fchmod(fd, planned, path)
        post = os.fstat(fd)
        if (
            stat.S_IMODE(post.st_mode) != planned
            or (post.st_uid, post.st_gid) != (now.st_uid, now.st_gid)
            or (post.st_dev, post.st_ino) != (now.st_dev, now.st_ino)
            or post.st_size != now.st_size
        ):
            return True, "fail", "post-state-mismatch"
        return True, "ok", None
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
    """Apply the 2.3.9 SUID/SGID mode control. Never follows a symlink, never relaxes."""
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]

    def done(outcome, **extra):
        return _result(control_id, target, outcome, actions=actions, dry_run=dry_run, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if not _is_eligible_contract(key, op, expected):
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    if target is None:
        target = TARGETS.get(control_id)
        if target is None:
            return done("ABORTED_PRECONDITION_OTHER", reason="target:unmapped-control")

    mask = int(expected, 8)
    actions.append("P1_POPULATION")
    status, data = _population(target)
    if status == "ERROR":
        outcome = "ABORTED_PRECONDITION_CONFLICT" if data in CONFLICT_REASONS else "ABORTED_PRECONDITION_OTHER"
        return done(outcome, reason=data)
    mounts, items = data

    actions.append("P2_PLAN")
    current = _current_value(mounts, items, mask)
    violators = [(path, st) for path, st in items if stat.S_IMODE(st.st_mode) & mask]
    if not violators:
        return done("ALREADY_COMPLIANT", current_mode=current)
    skipped = [
        {"path": path, "reason": "st_nlink"}
        for path, st in violators
        if st.st_nlink != 1
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
            changed, kind, reason = _apply_one(path, st, mask, fchmod)
        except OSError as exc:
            if exc.errno == errno.EROFS:
                outcome = "APPLIED_PARTIAL" if mutated else "ABORTED_PRECONDITION_OTHER"
                return done(outcome, reason="erofs", mutation=mutated, current_mode=current,
                            violators=violator_paths, applied=applied, skipped=skipped,
                            failed=failed + [{"path": path, "reason": "erofs"}])
            changed, kind, reason = False, "fail", "fchmod:%s" % errno.errorcode.get(exc.errno, exc.errno)
        mutated = mutated or changed
        if kind == "ok":
            applied.append(path)
        elif kind == "skip":
            skipped.append({"path": path, "reason": reason})
        else:
            failed.append({"path": path, "reason": reason})

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
