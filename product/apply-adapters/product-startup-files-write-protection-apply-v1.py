#!/usr/bin/env python3
"""product-startup-files-write-protection-apply-v1.

APPLY adapter for mechanism `startup-files-write-protection-v1` (2.3.5 startup files).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-startup-files-write-protection-v1.json

Population is the one of CHECK adapter product-startup-files-write-protection-check-v1:
непосредственные элементы `/etc/rc0.d` … `/etc/rc6.d` (подкаталоги пропускаются)
и непосредственные `*.service` каждого уникального корня из
`systemd-analyze unit-paths`; симлинк разрешается в конечную цель (семантика
`chmod o-w`), цепочка `.service` до `/dev/null` — маска, не объект; цели
дедуплицируются по `dev:ino`; снимки корней, популяций, элементов и целей
сверяются в конце наблюдения. Перечислитель ниже — Python-копия того
наблюдателя; паритет проверяется
tests/product-v1/test_startup_files_write_protection_apply_adapter.py.

Корни rc не литералы: они разбираются из локатора контроля (`TARGETS`), и
совпадение разбора с константой CHECK-адаптера `CANONICAL_RC_ROOTS` закреплено
тем же тестом. Объект мутации — разрешённая цель из популяции CHECK, в том числе
цель симлинка вне rc-каталогов: иначе APPLY и CHECK разошлись бы.

The plan is built before any mutation. A violator with st_nlink > 1 is skipped
and recorded. Перед мутацией объект ревалидируется на уже открытом дескрипторе
строго в порядке `S_ISREG` → `dev/ino` из плана → наличие бита маски;
несовпадение любого шага — пропуск объекта с причиной. Each mutation is one
`fchmod` on a descriptor opened with O_NOFOLLOW and only clears bit 0002; there
is no compensation. An error on one object does not stop the others
(APPLIED_PARTIAL); EROFS stops immediately.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import subprocess

ADAPTER_ID = "product-startup-files-write-protection-apply-v1"
MECHANISM_ID = "startup-files-write-protection-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "startup-files-write-protection"
SEMANTIC_CONTRACT_ID = "startup-files-write-protection-apply-semantic-v1"

SUPPORTED_KEYS = ("other-write",)
SUPPORTED_OPS = ("bits-clear",)
EXPECTED_MASK = "0002"

# Маркер локатора CHECK-адаптера и его источник корней юнитов.
UNIT_PATHS_MARKER = "systemd-unit-paths"
SYSTEMD_ANALYZE = "/usr/bin/systemd-analyze"

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
# test_startup_files_write_protection_apply_adapter.py.
TARGETS = {
    "FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION": "/etc/rc[0-6].d|systemd-unit-paths",
}

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"

# Причины CHECK, которые означают объект не того типа в популяции.
CONFLICT_REASONS = (
    "directory:invalid-type",
    "target:invalid-type",
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
    """Только (other-write, bits-clear, 0002); всё прочее решает администратор."""
    return key in SUPPORTED_KEYS and op in SUPPORTED_OPS and expected == EXPECTED_MASK


def canonical_rc_roots(locator):
    """Разбор локатора `<prefix>[a-b]<suffix>|systemd-unit-paths` в rc-корни."""
    parts = locator.split("|")
    if len(parts) != 2 or parts[1] != UNIT_PATHS_MARKER:
        raise ValueError("locator without %s" % UNIT_PATHS_MARKER)
    match = re.fullmatch(r"(/[^\[\]|]*)\[([0-9])-([0-9])\]([^\[\]|]*)", parts[0])
    if match is None or int(match.group(2)) > int(match.group(3)):
        raise ValueError("locator without a runlevel range")
    prefix, low, high, suffix = match.group(1), int(match.group(2)), int(match.group(3)), match.group(4)
    return tuple("%s%d%s" % (prefix, level, suffix) for level in range(low, high + 1))


class _ObservationError(BaseException):
    """Отказ наблюдения; как SystemExit у CHECK, не ловится `except Exception`."""


def _population(rc_roots, unit_paths_override, systemd_analyze):
    """Копия CHECK-наблюдателя: (counters, [(target, target_state)]).

    target_state — кортеж CHECK `(dev, ino, uid, gid, type, mode, size, mtime,
    ctime, nlink)`. Отказ — _ObservationError с причиной CHECK.
    """

    def emit_error(reason):
        raise _ObservationError(reason)

    def state_lstat(path):
        st = os.lstat(path)
        return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def state_stat(path):
        st = os.stat(path, follow_symlinks=True)
        return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)

    def dir_identity(path):
        st = os.stat(path, follow_symlinks=True)
        if not stat.S_ISDIR(st.st_mode):
            emit_error("directory:invalid-type")
        return (st.st_dev, st.st_ino)

    def direct_names(root):
        try:
            names = []
            with os.scandir(root) as it:
                for ent in it:
                    names.append(ent.name)
            names.sort(key=os.fsencode)
            return tuple(names)
        except Exception:
            emit_error("directory:scan-failed")

    def direct_service_names(root):
        return tuple(x for x in direct_names(root) if x.endswith(".service"))

    def resolve_candidate(path, service_role):
        try:
            first_l = state_lstat(path)
        except Exception:
            emit_error("target:lstat-failed")
        mode_type = first_l[4]
        if stat.S_ISDIR(mode_type):
            if service_role:
                emit_error("target:invalid-type")
            return ("directory", None, first_l, None)
        if stat.S_ISLNK(mode_type):
            try:
                target = os.path.realpath(path)
            except Exception:
                emit_error("target:resolve-failed")
            if service_role and os.path.normpath(target) == "/dev/null":
                try:
                    if state_lstat(path) != first_l:
                        emit_error("target:changed-during-check")
                except Exception:
                    emit_error("target:lstat-failed")
                resolution_snapshots[path] = target
                return ("masked", None, first_l, None)
            try:
                target_state = state_stat(target)
            except Exception:
                emit_error("target:stat-failed")
            if not stat.S_ISREG(target_state[4]):
                emit_error("target:invalid-type")
            resolution_snapshots[path] = target
            return ("regular", target, first_l, target_state)
        if stat.S_ISREG(mode_type):
            try:
                target_state = state_stat(path)
            except Exception:
                emit_error("target:stat-failed")
            return ("regular", path, first_l, target_state)
        emit_error("target:invalid-type")

    def read_unit_paths():
        if unit_paths_override is not None:
            if not isinstance(unit_paths_override, (list, tuple)) or any(not isinstance(x, str) for x in unit_paths_override):
                emit_error("systemd:invalid-unit-paths")
            return tuple(unit_paths_override), None
        env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
        try:
            proc = subprocess.run([systemd_analyze, "unit-paths"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
        except Exception:
            emit_error("systemd:execution-failed")
        if proc.returncode != 0:
            emit_error("systemd:execution-failed")
        if proc.stderr:
            emit_error("systemd:stderr-output")
        if not proc.stdout:
            emit_error("systemd:empty-output")
        if b"\x00" in proc.stdout or b"\r" in proc.stdout:
            emit_error("systemd:invalid-bytes")
        try:
            text = proc.stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            emit_error("systemd:invalid-utf8")
        paths = []
        for line in text.splitlines():
            if not line.startswith("/") or "\x00" in line or "\r" in line or "\n" in line:
                emit_error("systemd:invalid-path")
            paths.append(line)
        if not paths:
            emit_error("systemd:empty-population")
        return tuple(paths), proc.stdout

    unit_paths, unit_paths_raw = read_unit_paths()
    initial_unit_paths = unit_paths
    root_snapshots = {}
    pop_snapshots = {}
    entry_snapshots = {}
    target_snapshots = {}
    resolution_snapshots = {}
    seen_root_ids = set()
    seen_target_ids = set()
    items = []
    n = dict.fromkeys((
        "rc_roots_present", "rc_roots_absent", "rc_entries", "rc_directories", "rc_targets",
        "service_roots_present", "service_roots_absent", "service_root_aliases",
        "service_entries", "service_masked", "service_targets", "checked",
    ), 0)

    def remember_root_state(logical, resolved):
        try:
            root_snapshots[logical] = (os.path.lexists(logical), state_lstat(logical) if os.path.lexists(logical) else None, resolved, state_stat(resolved))
        except Exception:
            emit_error("root:snapshot-failed")

    def check_target(path, entry_path, entry_state, target_state, role):
        ident = (target_state[0], target_state[1])
        n["rc_targets" if role == "rc" else "service_targets"] += 1
        entry_snapshots[entry_path] = entry_state
        target_snapshots[path] = target_state
        if ident in seen_target_ids:
            return
        seen_target_ids.add(ident)
        n["checked"] += 1
        items.append((path, target_state))

    # /etc/rc0.d ... /etc/rc6.d: direct file-like entries only; rcS.d is intentionally not in this population.
    for logical in rc_roots:
        if not isinstance(logical, str) or not logical.startswith("/"):
            emit_error("root:invalid-path")
        if not os.path.lexists(logical):
            n["rc_roots_absent"] += 1
            root_snapshots[logical] = (False, None, None, None)
            continue
        try:
            resolved = os.path.realpath(logical)
            ident = dir_identity(resolved)
        except Exception:
            emit_error("root:resolve-failed")
        n["rc_roots_present"] += 1
        names = direct_names(resolved)
        remember_root_state(logical, resolved)
        pop_snapshots[resolved] = (names, False)
        if ident in seen_root_ids:
            emit_error("root:ambiguous-alias")
        seen_root_ids.add(ident)
        for name in names:
            path = os.path.join(resolved, name)
            kind, target, entry_state, target_state = resolve_candidate(path, False)
            if kind == "directory":
                n["rc_directories"] += 1
                continue
            n["rc_entries"] += 1
            check_target(target, path, entry_state, target_state, "rc")

    # systemd unit load paths: only direct *.service entries of each unique root.
    for logical in unit_paths:
        if not isinstance(logical, str) or not logical.startswith("/"):
            emit_error("systemd:invalid-path")
        if not os.path.lexists(logical):
            n["service_roots_absent"] += 1
            root_snapshots.setdefault(logical, (False, None, None, None))
            continue
        try:
            resolved = os.path.realpath(logical)
            ident = dir_identity(resolved)
        except Exception:
            emit_error("root:resolve-failed")
        n["service_roots_present"] += 1
        remember_root_state(logical, resolved)
        if ident in seen_root_ids:
            n["service_root_aliases"] += 1
            continue
        seen_root_ids.add(ident)
        names = direct_service_names(resolved)
        pop_snapshots[resolved] = (names, True)
        for name in names:
            n["service_entries"] += 1
            path = os.path.join(resolved, name)
            kind, target, entry_state, target_state = resolve_candidate(path, True)
            if kind == "masked":
                n["service_masked"] += 1
                entry_snapshots[path] = entry_state
                continue
            check_target(target, path, entry_state, target_state, "service")

    # End-of-observation stability, as in CHECK: any drift is a refusal.
    if unit_paths_override is None:
        final_paths, final_raw = read_unit_paths()
        if final_paths != initial_unit_paths or final_raw != unit_paths_raw:
            emit_error("observation:unit-paths-changed")
    for logical, snap in root_snapshots.items():
        was_present, logical_state, resolved, resolved_state = snap
        if not was_present:
            if os.path.lexists(logical):
                emit_error("observation:root-changed")
            continue
        try:
            if not os.path.lexists(logical) or state_lstat(logical) != logical_state or os.path.realpath(logical) != resolved or state_stat(resolved) != resolved_state:
                emit_error("observation:root-changed")
        except Exception:
            emit_error("observation:root-unreadable")
    for resolved, snap in pop_snapshots.items():
        names, service_only = snap
        current = direct_service_names(resolved) if service_only else direct_names(resolved)
        if current != names:
            emit_error("observation:population-changed")
    for path, snap in entry_snapshots.items():
        try:
            if state_lstat(path) != snap:
                emit_error("observation:entry-changed")
        except Exception:
            emit_error("observation:entry-unreadable")
    for path, resolved in resolution_snapshots.items():
        try:
            if os.path.realpath(path) != resolved:
                emit_error("observation:resolution-changed")
        except Exception:
            emit_error("observation:resolution-failed")
    for path, snap in target_snapshots.items():
        try:
            if state_stat(path) != snap:
                emit_error("observation:target-changed")
        except Exception:
            emit_error("observation:target-unreadable")
    return n, items


def _observe_population(rc_roots, unit_paths_override, systemd_analyze=SYSTEMD_ANALYZE):
    try:
        return "VALUE", _population(rc_roots, unit_paths_override, systemd_analyze)
    except _ObservationError as exc:
        return "ERROR", str(exc)
    except Exception:
        return "ERROR", "runtime:observer-failed"


def _current_value(counters, items, mask):
    violations = sum(1 for _path, state in items if state[5] & mask)
    return (
        "rc_roots_present={rc_roots_present};rc_roots_absent={rc_roots_absent};rc_entries={rc_entries};"
        "rc_directories={rc_directories};rc_targets={rc_targets};service_roots_present={service_roots_present};"
        "service_roots_absent={service_roots_absent};service_root_aliases={service_root_aliases};"
        "service_entries={service_entries};service_masked={service_masked};service_targets={service_targets};"
        "checked={checked};".format(**counters)
        + "violations=%d" % violations
    )


def observe(rc_roots, unit_paths, expected=EXPECTED_MASK):
    """(status, value) в формате CHECK-адаптера для данных корней."""
    mask = int(expected, 8)
    status, data = _observe_population(list(rc_roots), list(unit_paths))
    if status == "ERROR":
        return "ERROR", data
    counters, items = data
    return "VALUE", _current_value(counters, items, mask)


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
    """Те же значения, что у standard-system-paths-mode."""
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
        if (now.st_dev, now.st_ino) != (observed[0], observed[1]):
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
    _layout=None,
):
    """Apply the 2.3.5 startup files control. Never follows a symlink at write, never relaxes.

    `_layout` — (rc_roots, unit_paths) только для тестов, как
    `_shell_function_for_layout` у CHECK-адаптера.
    """
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
        rc_roots = canonical_rc_roots(target)
    except ValueError as exc:
        return done("ABORTED_PRECONDITION_OTHER", reason=str(exc))
    unit_paths = None
    if _layout is not None:
        rc_roots, unit_paths = list(_layout[0]), list(_layout[1])
    status, data = _observe_population(list(rc_roots), unit_paths)
    if status == "ERROR":
        outcome = "ABORTED_PRECONDITION_CONFLICT" if data in CONFLICT_REASONS else "ABORTED_PRECONDITION_OTHER"
        return done(outcome, reason=data)
    counters, items = data

    actions.append("P2_PLAN")
    current = _current_value(counters, items, mask)
    violators = sorted(
        ((path, state) for path, state in items if state[5] & mask),
        key=lambda pair: os.fsencode(pair[0]),
    )
    if not violators:
        return done("ALREADY_COMPLIANT", current_mode=current)
    skipped = []
    planned = []
    for path, state in violators:
        if state[9] != 1:
            skipped.append({"path": path, "reason": "st_nlink"})
        else:
            planned.append((path, state))
    violator_paths = [path for path, _state in violators]
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
    for path, state in planned:
        try:
            changed, kind, reason = _apply_one(path, state, mask, fchmod)
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
