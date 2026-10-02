#!/usr/bin/env python3
"""APPLY-адаптер механизма local-account-password-aging-v1 (fstec-configuration-2026 п.1.1, таблица 2;
SRC-0055): сроки действия пароля 1/90/7 (min, max, warn) в записях /etc/shadow существующих учётных
записей.

Карта разбиения сроков паролей v6 (решения пользователя 01.10–02.10.2026):
* Популяция и разбор — как у CHECK local-account-password-aging (PARSER — тот же текст): записи с
  хэшем пароля. Предусловия: /etc/passwd и /etc/shadow — обычные файлы, одна жёсткая ссылка, root,
  без записи для группы и прочих; каталог /etc — root без записи для группы и прочих. Нарушение —
  решение администратора, без изменений.
* Сроки ставятся только записям с расхождением, у которых новые сроки не переводят запись в смену
  пароля или блокировку: дата смены 0 < поле 3 ≤ сегодня, возраст ≤ 83 дней (до истечения не меньше
  7 дней — срок предупреждения), поле 7 (inactive) пусто, поле 8 (expire) пусто или больше сегодня.
  Остальные записи с расхождением не меняются: перечень «имя — причины — дата последней смены» в
  решении администратора. Дата смены пароля (поле 3) не меняется никогда.
* Запись — одна транзакция под lckpwdf и /etc/shadow.lock (протокол shadow-utils 4.13
  lib/commonio.c: файл блокировки с PID через link): под блокировкой — сверка байтов обоих файлов с
  наблюдением, временный файл с владельцем, группой и режимом /etc/shadow, fsync, rename, fsync
  каталога, итоговое наблюдение. Меняются только поля 4–6 строк плана.
* Компенсация под теми же блокировками: файл = записанные байты — вернуть прежние; файл = прежние
  байты — ничего; иное или ошибка — FAILED_COMPENSATION (чужая правка не затирается).
"""

from __future__ import annotations

import ctypes
import os
import re
import stat
import time

ADAPTER_ID = "product-local-account-password-aging-apply-v1"
MECHANISM_ID = "local-account-password-aging-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "local-account-password-aging"
PASSWD = "/etc/passwd"
SHADOW = "/etc/shadow"
ETC = "/etc"
LOCK = "/etc/shadow.lock"
CANONICAL_LOCATOR = "/etc/shadow"
CANONICAL_KEY = "aging-fields"
CANONICAL_EXPECTED = "1/90/7"
APPLY_MAX_AGE = 83

ACTION_FILE = ("{what}: исправьте тип, владельца, число жёстких ссылок или права (обычный файл root без "
               "записи для группы и прочих; каталог /etc root без записи для группы и прочих)")
ACTION_MISSING = ("учётная запись есть в /etc/passwd, но не в /etc/shadow: восстановите теневые записи "
                  "(pwconv)")
ACTION_STALE = ("/etc/shadow.lock оставлен процессом, которого нет (или файл не содержит PID): убедитесь, "
                "что учётные записи никто не меняет, и удалите файл блокировки")
ACTION_ADMIN = ("сроки 1/90/7 не поставлены, чтобы не вызвать немедленную смену пароля или блокировку; "
                "имя — причины — дата последней смены: {items}. Причины: age-over-83, date-empty, "
                "date-zero — сменить пароль, затем повторный APPLY; date-future — проверить часы или задать "
                "дату (chage -d); inactive-set — решить, нужна ли блокировка после истечения (chage -I -1 "
                "или сроки вручную); account-expired — решить судьбу учётной записи (chage -E)")

OUTCOMES = (
    "APPLIED",
    "APPLIED_PARTIAL",
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

# Разбор — общий для двух CHECK сроков паролей и этого APPLY (тот же текст; сверяется тестом).
PARSER = r'''
# Разбор /etc/passwd и /etc/shadow — как у CHECK v2 2.1.1 (local-account-password-state), в том же
# порядке; популяция — записи с хэшем пароля (поле 2 /etc/shadow начинается с `$`).
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\$?")
NUMBER_RE = re.compile(r"[0-9]*")
AGING = ("1", "90", "7")  # поля 4–6: min, max, warn (политика компании, SRC-0055)
MAX_AGE = 90
NUM_DIGITS = 15  # больше значащих цифр — заведомо вне диапазона дат и сроков


def num(f):
    """Значение непустого поля из цифр. Значение длиннее NUM_DIGITS значащих цифр — бесконечность
    (больше любой даты и срока): int() для него не вызывается (лимит длины строки в int)."""
    s = f.lstrip("0")
    return float("inf") if len(s) > NUM_DIGITS else int(s or "0")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def file_problem(st, owner_ok):
    """Причина недоверия к файлу passwd/shadow по lstat или None."""
    if not stat.S_ISREG(st.st_mode):
        return "invalid-type"
    if st.st_nlink != 1:
        return "hardlinked"
    if not owner_ok(st.st_uid) or stat.S_IMODE(st.st_mode) & 0o022:
        return "untrusted"
    return None


def dir_problem(st, owner_ok):
    """Причина недоверия к каталогу файлов по lstat или None."""
    if not stat.S_ISDIR(st.st_mode):
        return "invalid-type"
    if not owner_ok(st.st_uid) or stat.S_IMODE(st.st_mode) & 0o022:
        return "untrusted"
    return None


def decode(raw, domain):
    """Байты как текст без потерь (latin-1): CHECK v2 2.1.1 не ограничивает кодировку полей,
    отвергает только NUL и CR."""
    if b"\x00" in raw or b"\r" in raw:
        raise ParseError(domain + ":invalid-bytes")
    return raw.decode("latin-1")


def records(text):
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def population(passwd_text, shadow_text):
    """[(имя, поля shadow)] записей с хэшем в порядке /etc/passwd; разбор — как CHECK v2 2.1.1."""
    passwd_lines = records(passwd_text)
    shadow_lines = records(shadow_text)
    if not passwd_lines:
        raise ParseError("passwd:empty-file")
    if not shadow_lines:
        raise ParseError("shadow:empty-file")
    shadow = {}
    for line in shadow_lines:
        if not line:
            raise ParseError("shadow:empty-record")
        parts = line.split(":")
        if len(parts) != 9:
            raise ParseError("shadow:invalid-fields")
        if NAME_RE.fullmatch(parts[0]) is None:
            raise ParseError("shadow:invalid-account")
        if parts[0] in shadow:
            raise ParseError("shadow:duplicate-account")
        shadow[parts[0]] = parts
    seen, out = set(), []
    for line in passwd_lines:
        if not line:
            raise ParseError("passwd:empty-record")
        parts = line.split(":")
        if len(parts) != 7:
            raise ParseError("passwd:invalid-fields")
        if NAME_RE.fullmatch(parts[0]) is None:
            raise ParseError("passwd:invalid-account")
        if parts[0] in seen:
            raise ParseError("passwd:duplicate-account")
        seen.add(parts[0])
        if parts[0] not in shadow:
            raise ParseError("passwd:missing-shadow-account")
        fields = shadow[parts[0]]
        if fields[1].startswith("$"):
            if any(NUMBER_RE.fullmatch(f) is None for f in fields[2:8]):
                raise ParseError("shadow:invalid-number")
            out.append((parts[0], fields))
    return out


def aging_ok(fields):
    """Поля 4–6 записи = 1/90/7 (по значению: пусто — несоответствие)."""
    return all(f != "" and num(f) == int(v) for f, v in zip(fields[3:6], AGING))


def age_state(fields, today):
    """None — возраст пароля соответствует политике; иначе счётчик контроля 2."""
    if fields[2] == "":
        return "date_empty"
    lastchg = num(fields[2])
    if lastchg == 0:
        return "date_zero"
    if lastchg > today:
        return "date_future"
    if today - lastchg > MAX_AGE:
        return "age_over"
    return None
'''
exec(PARSER, globals())  # noqa: S102 — один текст разбора с CHECK


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


class _WriteFailed(Exception):
    """Сбой записи файла: stage — tmp, rename или dirsync."""

    def __init__(self, stage):
        super().__init__(stage)
        self.stage = stage


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not isinstance(key, str) or not isinstance(op, str):
        raise ValueError("key and op must be strings")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _p(root, path):
    return path if root is None else os.path.join(root, path.lstrip("/"))


def _owner_check(root):
    return lambda uid: uid == 0 or (root is not None and uid == os.geteuid())


def _today():
    return int(time.time()) // 86400


# Операции ввода-вывода — отдельные функции (тесты подменяют их для отказов).
def _read_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


def _rename(src, dst):
    os.rename(src, dst)


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _snapshot(root):
    """{'passwd': байты, 'shadow': байты, 'shadow_stat': lstat} с проверкой предусловий."""
    owner_ok = _owner_check(root)
    try:
        dst = os.lstat(_p(root, ETC))
    except OSError:
        raise _other("etc:stat-failed")
    problem = dir_problem(dst, owner_ok)
    if problem is not None:
        raise _admin("etc:" + problem, ACTION_FILE.format(what=ETC))
    out = {}
    for domain, path in (("passwd", PASSWD), ("shadow", SHADOW)):
        full = _p(root, path)
        try:
            st = os.lstat(full)
        except FileNotFoundError:
            raise _other(domain + ":not-found")
        except OSError:
            raise _other(domain + ":stat-failed")
        problem = file_problem(st, owner_ok)
        if problem is not None:
            raise _admin(domain + ":" + problem, ACTION_FILE.format(what=path))
        try:
            out[domain] = _read_file(full)
        except OSError:
            raise _other(domain + ":read-failed")
        out[domain + "_stat"] = st
    return out


def _population(snap):
    try:
        return population(decode(snap["passwd"], "passwd"), decode(snap["shadow"], "shadow"))
    except ParseError as exc:
        if exc.reason == "passwd:missing-shadow-account":
            raise _admin("shadow:entry-missing", ACTION_MISSING)
        raise _other(exc.reason)


def _blockers(fields, today):
    """Причины, по которым запись с расхождением оставляется администратору."""
    reasons = []
    if fields[2] == "":
        reasons.append("date-empty")
    elif num(fields[2]) == 0:
        reasons.append("date-zero")
    elif num(fields[2]) > today:
        reasons.append("date-future")
    elif today - num(fields[2]) > APPLY_MAX_AGE:
        reasons.append("age-over-83")
    if fields[6] != "":
        reasons.append("inactive-set")
    if fields[7] != "" and num(fields[7]) <= today:
        reasons.append("account-expired")
    return reasons


def plan(pop, today):
    """(имена для записи, [(имя, причины, дата)] для администратора, число расхождений)."""
    apply_names, admin, mismatched = [], [], 0
    for name, fields in pop:
        if aging_ok(fields):
            continue
        mismatched += 1
        reasons = _blockers(fields, today)
        if reasons:
            admin.append((name, reasons, fields[2]))
        else:
            apply_names.append(name)
    return apply_names, admin, mismatched


def _date(value):
    if value == "" or num(value) == 0 or num(value) == float("inf"):
        return "—"
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(num(value) * 86400))
    except (OverflowError, OSError, ValueError):
        return "—"  # дата непредставима (например, далеко в будущем)


def _decision(admin):
    items = "; ".join("%s — %s — %s" % (name, ",".join(reasons), _date(lastchg)) for name, reasons, lastchg in admin)
    return {"class": "ADMIN_ACTION_REQUIRED", "required": True, "action": ACTION_ADMIN.format(items=items)}


def render_shadow(raw, names):
    """Байты /etc/shadow с полями 4–6 = 1/90/7 в строках имён names; прочие байты прежние."""
    wanted = set(n.encode("utf-8") for n in names)
    lines = raw.split(b"\n")
    done = set()
    for i, line in enumerate(lines):
        parts = line.split(b":")
        if len(parts) == 9 and parts[0] in wanted:
            parts[3:6] = [v.encode("ascii") for v in AGING]
            lines[i] = b":".join(parts)
            done.add(parts[0])
    if done != wanted:
        raise RuntimeError("render: record not found")
    return b"\n".join(lines)


# Блокировки shadow-utils.
def _libc_lock():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    return (lambda: libc.lckpwdf() == 0), (lambda: libc.ulckpwdf() == 0)


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _lock_owner(path):
    try:
        raw = _read_file(path)[:32]
    except OSError:
        return None
    text = raw.decode("ascii", "replace")
    return int(text) if re.fullmatch(r"[0-9]+", text) and int(text) > 0 else None


def _take_lock_file(root, pid):
    lock = _p(root, LOCK)
    tmp = _p(root, "%s.%d" % (SHADOW, pid))
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        raise _other("shadow:lock-failed")
    try:
        os.write(fd, str(pid).encode("ascii"))
        os.fsync(fd)
    except OSError:
        os.close(fd)
        os.unlink(tmp)
        raise _other("shadow:lock-failed")
    os.close(fd)
    try:
        os.link(tmp, lock)
    except FileExistsError:
        os.unlink(tmp)
        owner = _lock_owner(lock)
        if owner is not None and _alive(owner):
            raise _other("shadow:busy")
        raise _admin("shadow:stale-lock", ACTION_STALE)
    except OSError:
        os.unlink(tmp)
        raise _other("shadow:lock-failed")
    try:
        linked = os.lstat(lock).st_nlink == 2
    except OSError:
        linked = False
    os.unlink(tmp)
    if not linked:
        raise _other("shadow:lock-mismatch")
    try:
        st = os.lstat(lock)
    except OSError:
        raise _other("shadow:lock-mismatch")
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or _lock_owner(lock) != pid:
        raise _other("shadow:lock-mismatch")


def _unlink(path):
    os.unlink(path)


def _release_lock_file(root, pid):
    lock = _p(root, LOCK)
    if _lock_owner(lock) != pid:
        return False
    try:
        _unlink(lock)
    except OSError:
        return False
    return True


def _write(root, data, ref):
    """Временный файл с владельцем, группой и режимом ref, fsync, rename, fsync каталога."""
    target = _p(root, SHADOW)
    tmp = "%s.slp-tmp.%d" % (target, os.getpid())
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o000)
    except OSError:
        raise _WriteFailed("tmp")
    try:
        os.fchown(fd, ref.st_uid, ref.st_gid)
        os.fchmod(fd, stat.S_IMODE(ref.st_mode))
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except OSError:
        os.close(fd)
        os.unlink(tmp)
        raise _WriteFailed("tmp")
    os.close(fd)
    try:
        _rename(tmp, target)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise _WriteFailed("rename")
    try:
        _fsync_dir(_p(root, ETC))
    except OSError:
        raise _WriteFailed("dirsync")


def _commit_state(outcome, dry_run, mutation):
    if outcome in ("APPLIED", "APPLIED_PARTIAL") or (outcome == "ALREADY_COMPLIANT" and not dry_run):
        return COMMIT_COMMITTED
    if mutation:
        return COMMIT_NOT_COMMITTED
    return COMMIT_NOT_STARTED


def _result(control_id, outcome, *, actions, dry_run, mutation=False, **extra):
    record = {
        "adapter_id": ADAPTER_ID,
        "mechanism_id": MECHANISM_ID,
        "control_id": control_id,
        "target": SHADOW,
        "outcome": outcome,
        "reason": None,
        "policy_current": None,
        "operator_decision": None,
        "applied": [],
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
    """"0" для успешных исходов, иначе "nonzero"; APPLIED_PARTIAL — nonzero."""
    if outcome in ("APPLIED", "ALREADY_COMPLIANT", "NOT_ELIGIBLE_APPLY_UNSUPPORTED"):
        return "0"
    if dry_run and outcome == "DRY_RUN_WOULD_APPLY":
        return "0"
    return "nonzero"


def _shown(accounts, mismatched):
    return "accounts=%d;mismatched=%d" % (accounts, mismatched)


def _default_privilege_check() -> bool:
    return os.geteuid() == 0


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _locks=None, _pid=None):
    """Поставить сроки 1/90/7 применимым записям /etc/shadow.

    `_root`, `_locks` (пара функций lckpwdf/ulckpwdf) и `_pid` — только для тестов.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    mutation = False

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, mutation=mutation, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if key != CANONICAL_KEY or op != "eq" or expected != CANONICAL_EXPECTED:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    current = None
    try:
        actions.append("P1_OBSERVE")
        snap = _snapshot(_root)
        pop = _population(snap)
        today = _today()
        names, admin, mismatched = plan(pop, today)
        current = _shown(len(pop), mismatched)
        if mismatched == 0:
            return done("ALREADY_COMPLIANT", policy_current=current)
        decision = _decision(admin) if admin else None
        if not names:
            return done("ABORTED_PRECONDITION_CONFLICT", reason="admin-decision", policy_current=current,
                        operator_decision=decision)
        actions.append("P2_PLAN")
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY", policy_current=current, operator_decision=decision,
                        applied=list(names))
        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            raise _other("privilege")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, policy_current=current, operator_decision=exc.decision)

    if _locks is not None:
        lock_fn, unlock_fn = _locks
    elif _root is None:
        lock_fn, unlock_fn = _libc_lock()
    else:
        lock_fn, unlock_fn = (lambda: True), (lambda: True)
    pid = _pid if _pid is not None else os.getpid()
    actions.append("L1_LOCK")
    if not lock_fn():
        return done("ABORTED_PRECONDITION_OTHER", reason="shadow:busy", policy_current=current)
    state = {"file_locked": False}

    def transaction():
        nonlocal mutation
        try:
            _take_lock_file(_root, pid)
        except _Refused as exc:
            return done(exc.outcome, reason=exc.reason, policy_current=current, operator_decision=exc.decision)
        state["file_locked"] = True
        actions.append("L2_REVERIFY")
        # Под блокировкой: любое отличие от наблюдения P1 (байты, предусловия, чтение) — files:changed.
        try:
            snap2 = _snapshot(_root)
        except _Refused:
            snap2 = None
        if snap2 is None or snap2["passwd"] != snap["passwd"] or snap2["shadow"] != snap["shadow"]:
            return done("ABORTED_PRECONDITION_OTHER", reason="files:changed", policy_current=current)
        before = snap2["shadow"]
        after = render_shadow(before, names)
        actions.append("L3_WRITE")
        reason = None
        try:
            _write(_root, after, snap2["shadow_stat"])
        except _WriteFailed as exc:
            if exc.stage == "tmp":
                return done("FAILED_NOT_COMMITTED", reason="shadow:write-failed", policy_current=current)
            if exc.stage == "rename":
                try:
                    unchanged = _read_file(_p(_root, SHADOW)) == before
                except OSError:
                    unchanged = False
                if unchanged:
                    return done("FAILED_NOT_COMMITTED", reason="shadow:rename-failed", policy_current=current)
                mutation = True
                reason = "shadow:rename-failed"
            else:
                mutation = True
                reason = "shadow:dirsync-failed"
        else:
            mutation = True
            actions.append("L6_POSTCHECK")
            try:
                final = _snapshot(_root)
                ok = final["shadow"] == after and final["passwd"] == snap["passwd"]
                if ok:
                    states = dict(_population(final))
                    ok = all(aging_ok(states[n]) for n in names)
            except _Refused:
                ok = False
            if ok:
                outcome = "APPLIED_PARTIAL" if admin else "APPLIED"
                return done(outcome, reason="admin-decision" if admin else None, applied=list(names),
                            policy_current=_shown(len(pop), len(admin)), operator_decision=decision)
            reason = "postcheck:failed"
        actions.append("COMPENSATION")
        try:
            now = _read_file(_p(_root, SHADOW))
        except OSError:
            return done("FAILED_COMPENSATION", reason=reason + ";compensation:read-failed", policy_current=current)
        if now == before:
            return done("FAILED_NOT_COMMITTED", reason=reason, policy_current=current)
        if now != after:
            return done("FAILED_COMPENSATION", reason=reason + ";compensation:shadow-changed", policy_current=current)
        try:
            _write(_root, before, snap2["shadow_stat"])
            restored = _read_file(_p(_root, SHADOW)) == before
        except (_WriteFailed, OSError):
            return done("FAILED_COMPENSATION", reason=reason + ";compensation:write-failed", policy_current=current)
        if restored:
            return done("FAILED_NOT_COMMITTED", reason=reason, policy_current=current)
        return done("FAILED_COMPENSATION", reason=reason + ";compensation:read-failed", policy_current=current)

    released = True
    try:
        result = transaction()
    finally:
        if state["file_locked"] and not _release_lock_file(_root, pid):
            released = False
        if not unlock_fn():
            released = False
    if not released:
        # Ошибка снятия блокировок: исход по данным не меняется, step_rc — nonzero.
        result["reason"] = "lock:release-failed" if result["reason"] is None else result["reason"] + ";lock:release-failed"
    return result


def control_result_to_report(result, started_at, finished_at):
    rc = outcome_rc_contribution(result["outcome"], result["dry_run"])
    if result["reason"] is not None and "lock:release-failed" in result["reason"]:
        rc = "nonzero"
    return {
        "adapter_id": result["adapter_id"],
        "mechanism_id": result["mechanism_id"],
        "control_id": result["control_id"],
        "target": result["target"],
        "outcome": result["outcome"],
        "reason": result["reason"],
        "policy_current": result["policy_current"],
        "applied": list(result["applied"]),
        "operator_decision": None if result["operator_decision"] is None else dict(result["operator_decision"]),
        "started_at": started_at,
        "finished_at": finished_at,
        "actions_attempted": list(result["actions_attempted"]),
        "step_rc": rc,
        "mutation_performed": result["mutation_performed"],
        "transaction_commit": result["transaction_commit"],
    }
