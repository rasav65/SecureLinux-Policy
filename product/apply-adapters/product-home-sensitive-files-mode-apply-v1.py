#!/usr/bin/env python3
"""product-home-sensitive-files-mode-apply-v1.

APPLY-адаптер механизма home-sensitive-files-mode-v1 (fstec-linux-2022 2.3.10, SRC-0014).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-home-sensitive-files-mode-v1.json

Решение пользователя 29.09.2026: APPLY 2.3.10 устроен как APPLY 2.3.11 — исправляются только
файлы в домашних каталогах пользователей с UID ≥ 1000 из /etc/passwd; прочие случаи — решение
администратора. CHECK сохраняет проверку непосредственных элементов каталогов /home; популяции
различаются намеренно.

* Популяция: строки /etc/passwd (файл, не NSS) с UID ≥ 1000 и абсолютным полем home.
  Отсутствующий home — вне популяции. Каталог открывается с O_DIRECTORY | O_NOFOLLOW; ссылка
  или не каталог — решение администратора, файлы в нём не рассматриваются. Один каталог у
  нескольких записей — один объект (dev:ino); у записей с разными UID — решение администратора
  для его несоответствующих файлов.
* В каталоге рассматриваются только непосредственные элементы с именем из замкнутого набора
  CHECK (восемь имён источника и распространённые файлы оболочек). Отсутствующее имя — вне
  популяции. Имя открывается относительно дескриптора каталога с O_NOFOLLOW | O_NONBLOCK.
* Файл без битов группы и прочих соответствует требованию. Несоответствующий файл: ссылка, не
  обычный файл, владелец не UID записи или больше одной жёсткой ссылки — решение
  администратора без изменений.
* План строится до мутаций. Мутация — `fchmod(fd, mode & ~0o077)` на проверенном дескрипторе:
  только снятие битов группы и прочих; компенсации нет (возврат прежнего режима ослабил бы
  защиту). Ошибка одного объекта не останавливает остальные (APPLIED_PARTIAL); EROFS
  останавливает сразу.
* Объекты решения администратора при исправленных прочих — APPLIED_PARTIAL; без исправленных —
  ABORTED_PRECONDITION_CONFLICT с готовым действием администратора.
"""

from __future__ import annotations

import errno
import os
import re
import stat

ADAPTER_ID = "product-home-sensitive-files-mode-apply-v1"
MECHANISM_ID = "home-sensitive-files-mode-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "home-sensitive-files-mode"
SEMANTIC_CONTRACT_ID = "home-sensitive-files-mode-apply-semantic-v1"

SUPPORTED_KEYS = ("mode",)
SUPPORTED_OPS = ("bits-clear",)
EXPECTED_MASK = "0077"
CLEAR_BITS = 0o077
UID_FLOOR = 1000
PASSWD_PATH = "/etc/passwd"
ID_MAX = 4294967294
ID_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,9})")

# Тот же замкнутый набор имён, что у CHECK product-home-sensitive-files-mode-check-v2
# (совпадение проверяет тест).
MANDATORY_SOURCE_NAMES = (
    ".bash_history", ".history", ".sh_history", ".bash_profile",
    ".bashrc", ".profile", ".bash_logout", ".rhosts",
)
COMMON_SHELL_BASENAMES = (
    ".bash_login", ".xonshrc",
    ".zsh_history", ".zshrc", ".zprofile", ".zlogin", ".zlogout", ".zshenv",
    ".ksh_history", ".kshrc", ".mkshrc", ".cshrc", ".tcshrc", ".login", ".logout",
)
NAMES = tuple(sorted(MANDATORY_SOURCE_NAMES + COMMON_SHELL_BASENAMES))

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

CONTROLS = ("FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE",)
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
ADMIN_ACTION = ("Проверить назначение файла и владельца; при необходимости выполнить "
                "chmod go-rwx вручную.")

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
        raise ValueError("only bits-clear 0077 is supported")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


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


def _errname(exc):
    return errno.errorcode.get(exc.errno, str(exc.errno))


def _open_home(uid, home):
    """(fd|None, stat|None, admin_reason|None); fd=None и reason=None — каталога нет."""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in home):
        return None, None, "home:invalid-name"
    if not home.startswith("/"):
        return None, None, "home:not-absolute"
    try:
        fd = os.open(home, _DIR_FLAGS)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return None, None, None
        if exc.errno == errno.ELOOP:
            return None, None, "home:symlink"
        if exc.errno == errno.ENOTDIR:
            try:
                st = os.lstat(home)
            except OSError:
                return None, None, "home:stat-failed"
            return None, None, "home:symlink" if stat.S_ISLNK(st.st_mode) else "home:not-directory"
        return None, None, "home:open:%s" % _errname(exc)
    try:
        st = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        return None, None, "home:stat:%s" % _errname(exc)
    return fd, st, None


def _classify_file(dir_fd, name, uid):
    """("absent"|"ok"|"admin"|"plan", reason|None, stat|None) без мутаций."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return "absent", None, None
        return "admin", "file:stat:%s" % _errname(exc), None
    mode = stat.S_IMODE(st.st_mode)
    if stat.S_ISLNK(st.st_mode):
        return "admin", "file:symlink", st
    if not stat.S_ISREG(st.st_mode):
        return "admin", "file:not-regular", st
    if mode & CLEAR_BITS == 0:
        return "ok", None, st
    if st.st_uid != uid:
        return "admin", "file:owner-mismatch", st
    if st.st_nlink != 1:
        return "admin", "file:hardlink", st
    return "plan", None, st


def plan(passwd_path=PASSWD_PATH):
    """(error_reason|None, objects): по одному словарю на каталог-отказ и на файл (dev:ino)."""
    try:
        raw = _read_passwd(passwd_path)
        rows = parse_passwd(raw)
    except ValueError as exc:
        return str(exc), []
    except OSError as exc:
        return "passwd:open:%s" % _errname(exc), []
    objects, seen_homes, seen_files = [], {}, {}
    for name, uid, home in rows:
        fd, hst, reason = _open_home(uid, home)
        if fd is None and reason is None:
            continue
        hkey = (hst.st_dev, hst.st_ino) if hst is not None else ("path", home)
        if hkey in seen_homes:
            prior = seen_homes[hkey]
            if prior["uid"] != uid or prior["reason"] != reason:
                prior["conflict"] = True
            if fd is not None:
                os.close(fd)
            continue
        entry = {"uid": uid, "reason": reason, "conflict": False, "items": []}
        seen_homes[hkey] = entry
        if fd is None:
            shown = "<invalid-name>" if reason == "home:invalid-name" else home
            item = {"kind": "admin", "path": shown, "reason": reason, "stat": None,
                    "home": home, "home_stat": hst, "name": None, "uid": uid}
            entry["items"].append(item)
            objects.append(item)
            continue
        try:
            for fname in NAMES:
                kind, freason, fst = _classify_file(fd, fname, uid)
                if kind == "absent":
                    continue
                path = home.rstrip("/") + "/" + fname
                fkey = (fst.st_dev, fst.st_ino) if fst is not None else ("path", path)
                if fkey in seen_files:
                    continue
                item = {"kind": kind, "path": path, "reason": freason, "stat": fst,
                        "home": home, "home_stat": hst, "name": fname, "uid": uid}
                seen_files[fkey] = item
                entry["items"].append(item)
                objects.append(item)
        finally:
            os.close(fd)
    # Каталог, общий для записей с разными UID, — решение администратора для всех его файлов.
    for entry in seen_homes.values():
        if entry["conflict"]:
            for item in entry["items"]:
                if item["kind"] != "ok":
                    item["kind"], item["reason"] = "admin", "home:shared-conflict"
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


def _apply_one(item, fchmod):
    """Снять биты группы и прочих у одного файла. Возвращает (mutated, failure_reason|None).

    OSError наружу выходит только из самого fchmod (мутации не было). Любая ошибка после
    успешного fchmod (fstat, close) возвращается с mutated=True: факт мутации не теряется.
    """
    hst = item["home_stat"]
    try:
        dfd = os.open(item["home"], _DIR_FLAGS)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return False, "home-type-drift"
        return False, "home-open:%s" % _errname(exc)
    fd = None
    early = None
    try:
        try:
            now = os.fstat(dfd)
        except OSError as exc:
            early = (False, "home-stat:%s" % _errname(exc))
        else:
            if (now.st_dev, now.st_ino, now.st_uid) != (hst.st_dev, hst.st_ino, hst.st_uid):
                early = (False, "home-identity-drift")
            else:
                try:
                    fd = os.open(item["name"], _FILE_FLAGS, dir_fd=dfd)
                except OSError as exc:
                    early = (False, "type-drift" if exc.errno == errno.ELOOP else "open:%s" % _errname(exc))
    finally:
        # Ошибка закрытия каталога не выходит наружу: мутации ещё не было, файл закрывается ниже.
        try:
            os.close(dfd)
        except OSError as exc:
            if early is None:
                early = (False, "home-close:%s" % _errname(exc))
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
    passwd_path=PASSWD_PATH,
    privilege_check=None,
    _fchmod=None,
):
    """Снять биты группы и прочих у файлов оболочки в домашних каталогах UID ≥ 1000."""
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
