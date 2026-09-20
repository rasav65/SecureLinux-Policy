#!/usr/bin/env python3
"""product-standard-system-paths-mode-apply-v1.

APPLY adapter for mechanism `standard-system-paths-mode-v1` (2.3.8 standard paths).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-standard-system-paths-mode-v1.json

Population is the one of CHECK adapter product-standard-system-paths-mode-check-v2:
исполняемые файлы exec-корней, библиотеки lib-корней (`.so`, `.so.*`, `.a`) и
модули `/lib/modules/<uname-r>` (`.ko`, `.ko.*`), рекурсивно, с разрешением
симлинков в конечную цель и дедупликацией целей по `dev:ino`. Перечислитель
ниже — Python-копия того наблюдателя; паритет проверяется
tests/product-v1/test_standard_system_paths_mode_apply_adapter.py.

Канонические корни не литералы: они разбираются из локатора контроля
(`TARGETS`), и совпадение разбора с константами CHECK-адаптера
`CANONICAL_EXEC_ROOTS` / `CANONICAL_LIB_ROOTS` / `CANONICAL_MODULE_TEMPLATE`
закреплено тем же тестом.

Граница мутации: меняются только объекты, чей разрешённый путь лежит внутри
канонических корней. Дополнительные элементы PATH root и цели симлинков вне
канонических корней входят в популяцию (иначе CHECK и APPLY разошлись бы), но
не мутируются: пропуск с причиной `outside-canonical-roots`.

The plan is built before any mutation. A violator with st_nlink > 1 is skipped
and recorded. Перед мутацией объект ревалидируется на уже открытом дескрипторе
строго в порядке `S_ISREG` → `dev/ino` из плана → наличие битов маски;
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

ADAPTER_ID = "product-standard-system-paths-mode-apply-v1"
MECHANISM_ID = "standard-system-paths-mode-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "standard-system-paths-mode"
SEMANTIC_CONTRACT_ID = "standard-system-paths-mode-apply-semantic-v1"

SUPPORTED_KEYS = ("mode",)
SUPPORTED_OPS = ("bits-clear",)
EXPECTED_MASK = "0022"

# Маркеры локатора CHECK-адаптера.
PATH_ROOT_MARKER = "<root-PATH>"
UNAME_MARKER = "<uname-r>"

# Имена объектов популяции по ролям (копия CHECK-наблюдателя).
LIB_SUFFIXES = (b".so", b".a")
LIB_INFIX = b".so."
MODULE_SUFFIX = b".ko"
MODULE_INFIX = b".ko."
EXEC_BITS = 0o111

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

# Локатор единственного контроля механизма. Совпадение с parameter.locator и с
# константами CHECK-адаптера проверяет
# test_standard_system_paths_mode_apply_adapter.py.
TARGETS = {
    "FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE":
        "/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64"
        "|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>",
}

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"

# Причины CHECK, которые означают объект не того типа в популяции.
CONFLICT_REASONS = (
    "root:invalid-type",
    "target:invalid-type",
    "target:resolved-symlink",
)


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


def canonical_roots(locator):
    """Разбор локатора: (exec_roots, lib_roots, module_template) без подстановок."""
    parts = locator.split("|")
    if PATH_ROOT_MARKER not in parts or len(parts) < 3:
        raise ValueError("locator without %s separator" % PATH_ROOT_MARKER)
    cut = parts.index(PATH_ROOT_MARKER)
    exec_roots = tuple(parts[:cut])
    lib_roots = tuple(parts[cut + 1:-1])
    module_template = parts[-1]
    if not exec_roots or not lib_roots or not module_template:
        raise ValueError("locator without a complete role set")
    return exec_roots, lib_roots, module_template


def _path_entries():
    """Элементы PATH процесса; копия правил CHECK-адаптера."""
    value = os.environ.get("PATH")
    if not value or any(ch in value for ch in ("\r", "\n", "\t")):
        raise ValueError("path:invalid-environment")
    entries = value.split(":")
    if not entries:
        raise ValueError("path:empty-environment")
    for entry in entries:
        if not entry.startswith("/"):
            raise ValueError("path:nonabsolute-entry")
    return entries


def resolve_roots(locator):
    """(exec_roots, lib_roots, module_root) с PATH root и подстановкой <uname-r>."""
    exec_roots, lib_roots, module_template = canonical_roots(locator)
    exec_roots = list(exec_roots) + _path_entries()
    module_root = module_template.replace(UNAME_MARKER, os.uname().release)
    return exec_roots, list(lib_roots), module_root


def _resolve(path, role):
    """Аналог `readlink -f`: конечная цель цепочки симлинков."""
    parent = os.path.dirname(path) or "/"
    if not os.path.isdir(parent):
        raise _ObservationError(role + ":resolve-failed")
    result = os.path.realpath(path)
    if not result:
        raise _ObservationError(role + ":resolve-empty")
    return result


class _ObservationError(Exception):
    pass


def _entries(root):
    """find -P <root> -mindepth 1 -print0 | sort: все объекты ниже корня."""
    found = []

    def fail(_error):
        raise _ObservationError("scan:find-failed")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=fail):
        for name in dirnames + filenames:
            found.append(os.path.join(dirpath, name))
    found.sort(key=os.fsencode)
    return found


def _selected(entry, role):
    """Фильтр имени по роли (копия CHECK-наблюдателя)."""
    name = os.path.basename(os.fsencode(entry))
    if role == "lib":
        return name.endswith(LIB_SUFFIXES) or LIB_INFIX in name
    if role == "module":
        return name.endswith(MODULE_SUFFIX) or MODULE_INFIX in name
    return True


def _population(exec_roots, lib_roots, module_root):
    """Копия CHECK-наблюдателя: (mounts-подобные счётчики, объекты популяции).

    Возвращает ("ERROR", reason) либо ("VALUE", (counters, [(path, lstat, role)])).
    """
    groups = (("exec", list(exec_roots)), ("lib", list(lib_roots)), ("module", [module_root]))
    seen_roots, seen_targets = set(), set()
    exec_root_ids = set()
    for root in exec_roots:
        try:
            info = os.stat(root)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode):
            exec_root_ids.add((info.st_dev, info.st_ino))
    present = absent = aliases = 0
    counts = {"exec": 0, "lib": 0, "module": 0}
    items = []
    for role, roots in groups:
        for root in roots:
            try:
                os.lstat(root)
            except FileNotFoundError:
                absent += 1
                continue
            except OSError:
                return "ERROR", "root:resolve-failed"
            resolved = _resolve(root, "root")
            if not os.path.isdir(resolved):
                return "ERROR", "root:invalid-type"
            try:
                info = os.stat(resolved)
            except OSError:
                return "ERROR", "root:identity-failed"
            present += 1
            identity = (info.st_dev, info.st_ino)
            if identity in seen_roots:
                aliases += 1
                continue
            seen_roots.add(identity)
            for entry in _entries(resolved):
                if os.path.isdir(entry) and not os.path.islink(entry):
                    continue
                if not _selected(entry, role):
                    continue
                if os.path.islink(entry):
                    target = _resolve(entry, "target")
                    if os.path.islink(target):
                        return "ERROR", "target:resolved-symlink"
                    if not os.path.isfile(target):
                        if role == "exec" and os.path.isdir(target):
                            try:
                                dinfo = os.stat(target)
                            except OSError:
                                return "ERROR", "target:identity-failed"
                            if (dinfo.st_dev, dinfo.st_ino) in exec_root_ids:
                                continue
                        return "ERROR", "target:invalid-type"
                elif os.path.isfile(entry):
                    target = entry
                else:
                    return "ERROR", "target:invalid-type"
                try:
                    info = os.stat(target)
                except OSError:
                    return "ERROR", "target:identity-failed"
                if not stat.S_ISREG(info.st_mode):
                    return "ERROR", "target:invalid-type"
                mode = stat.S_IMODE(info.st_mode)
                if len(format(mode, "o")) not in (3, 4):
                    return "ERROR", "target:invalid-mode"
                if role == "exec" and not mode & EXEC_BITS:
                    continue
                identity = (info.st_dev, info.st_ino)
                if identity in seen_targets:
                    continue
                seen_targets.add(identity)
                counts[role] += 1
                items.append((target, info, role))
    for role in ("exec", "lib", "module"):
        if counts[role] == 0:
            return "ERROR", "population:missing-" + ("libraries" if role == "lib" else role + "s")
    counters = {"present": present, "absent": absent, "aliases": aliases, "counts": counts}
    return "VALUE", (counters, items)


def _observe_population(exec_roots, lib_roots, module_root):
    try:
        return _population(exec_roots, lib_roots, module_root)
    except _ObservationError as exc:
        return "ERROR", str(exc)
    except Exception:
        return "ERROR", "runtime:observer-failed"


def _current_value(counters, items, mask):
    violations = sum(1 for _p, st, _r in items if stat.S_IMODE(st.st_mode) & mask)
    counts = counters["counts"]
    return (
        "roots_present=%d;roots_absent=%d;aliases=%d;exec=%d;libraries=%d;modules=%d;"
        "checked=%d;violations=%d"
        % (counters["present"], counters["absent"], counters["aliases"],
           counts["exec"], counts["lib"], counts["module"], len(items), violations)
    )


def observe(exec_roots, lib_roots, module_root, expected=EXPECTED_MASK):
    """(status, value) в формате CHECK-адаптера для данных корней."""
    mask = int(expected, 8)
    status, data = _observe_population(exec_roots, lib_roots, module_root)
    if status == "ERROR":
        return "ERROR", data
    counters, items = data
    return "VALUE", _current_value(counters, items, mask)


def _canonical_dirs(locator):
    """Разрешённые пути канонических корней: граница мутации."""
    exec_roots, lib_roots, module_template = canonical_roots(locator)
    module_root = module_template.replace(UNAME_MARKER, os.uname().release)
    dirs = []
    for root in tuple(exec_roots) + tuple(lib_roots) + (module_root,):
        resolved = os.path.realpath(root)
        if resolved not in dirs:
            dirs.append(resolved)
    return dirs


def _inside(path, dirs):
    for root in dirs:
        if path == root or path.startswith(root.rstrip("/") + "/"):
            return True
    return False


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
    """Те же значения, что у suid-sgid-applications-mode."""
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
    Ревалидация на дескрипторе строго в порядке S_ISREG -> dev/ino -> биты mask.
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
        current = stat.S_IMODE(now.st_mode)
        if not current & mask:
            return False, "skip", "no-violation-bits"
        if now.st_nlink != 1:
            return False, "skip", "st_nlink"
        planned = current & ~mask
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
    """Apply the 2.3.8 standard system paths control. Never follows a symlink, never relaxes."""
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
    try:
        exec_roots, lib_roots, module_root = resolve_roots(target)
        canonical = _canonical_dirs(target)
    except ValueError as exc:
        return done("ABORTED_PRECONDITION_OTHER", reason=str(exc))
    status, data = _observe_population(exec_roots, lib_roots, module_root)
    if status == "ERROR":
        outcome = "ABORTED_PRECONDITION_CONFLICT" if data in CONFLICT_REASONS else "ABORTED_PRECONDITION_OTHER"
        return done(outcome, reason=data)
    counters, items = data

    actions.append("P2_PLAN")
    current = _current_value(counters, items, mask)
    violators = sorted(
        ((path, st) for path, st, _role in items if stat.S_IMODE(st.st_mode) & mask),
        key=lambda pair: os.fsencode(pair[0]),
    )
    if not violators:
        return done("ALREADY_COMPLIANT", current_mode=current)
    skipped = []
    planned = []
    for path, st in violators:
        if not _inside(path, canonical):
            skipped.append({"path": path, "reason": "outside-canonical-roots"})
        elif st.st_nlink != 1:
            skipped.append({"path": path, "reason": "st_nlink"})
        else:
            planned.append((path, st))
    violator_paths = [path for path, _st in violators]
    if not planned:
        reasons = {item["reason"] for item in skipped}
        reason = skipped[0]["reason"] if len(reasons) == 1 else "no-mutable-object"
        return done("ABORTED_PRECONDITION_CONFLICT", reason=reason, current_mode=current,
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
