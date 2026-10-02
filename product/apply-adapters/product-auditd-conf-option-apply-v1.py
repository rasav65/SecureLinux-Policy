#!/usr/bin/env python3
"""APPLY-адаптер механизма auditd-conf-option-v1 (fstec-logging-2025 приложение 2, п.3; SRC-0052).

Решение пользователя 30.09.2026 (вариант B, карта разбиения auditd v5): в /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log, log_group = root, max_log_file = 50, num_logs = 10,
max_log_file_action = keep_logs, log_format = ENRICHED, space_left_action = syslog,
admin_space_left_action = suspend, disk_full_action = suspend.

* Наблюдение — тот же разбор, что у CHECK `auditd-conf-option-check-semantic-v1` (текст PARSER
  совпадает побайтно, сверяется тестом).
* Предусловия до записи (нарушение — решение администратора, файл не меняется): каталог
  /etc/audit — каталог (не ссылка), владелец uid 0, без записи для группы и прочих; файл —
  существует, обычный (не ссылка), st_nlink = 1, uid 0, gid 0, без записи для группы и прочих.
  Файла нет — отказ (пакет auditd не установлен; файл не создаётся). Две и более действующих
  строки ключа — решение администратора.
* Правка на месте: действующая строка ключа → закомментированный шаблон `# ключ = …` → строка в
  конце файла; строка пишется как `ключ = значение`.
* Идентичность (карта v5, протокол F1–F4): кортеж файла (st_dev, st_ino, st_mode, st_uid, st_gid,
  st_nlink, st_size, st_mtime_ns, st_ctime_ns) и каталога (st_dev, st_ino, st_mode, st_uid,
  st_gid) снимается при наблюдении (F1), сверяется перед созданием временного файла (F2) и
  непосредственно перед rename (F3); временный файл — в том же каталоге
  (O_CREAT|O_EXCL|O_NOFOLLOW, суффикс .slp-tmp), прежние владелец, группа и режим, fsync.
  После rename (F4) — новый кортеж (st_nlink = 1) и повторное наблюдение.
* Перечитывание: SIGHUP процессу auditd (MainPID юнита auditd.service, /proc/<pid>/comm =
  auditd); служба не запущена — сигнал не посылается (настройка действует при запуске). Итог —
  байты файла равны записанным, параметр соответствует, служба, если работала, работает.
* Перед SIGHUP файл сверяется с кортежем после rename (F4), каталог — с кортежем F1; расхождение
  — компенсация без сигнала. Ошибка после rename — мутация состоялась, компенсация.
* Ошибка записи или итоговой проверки — компенсация: прежние байты тем же протоколом; если сигнал
  перечитывания был доставлен — повторный SIGHUP (неудача — FAILED_COMPENSATION: процесс мог
  остаться с новой конфигурацией); служба работала и остановилась — `systemctl start
  auditd.service`. Прежние байты и состояние службы совпали — FAILED_NOT_COMMITTED, иначе
  FAILED_COMPENSATION.
"""

from __future__ import annotations

import os
import re
import signal
import stat
import subprocess

ADAPTER_ID = "product-auditd-conf-option-apply-v1"
MECHANISM_ID = "auditd-conf-option-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "auditd-conf-option"
CONF = "/etc/audit/auditd.conf"
CONF_DIR = "/etc/audit"
UNIT = "auditd.service"
SYSTEMCTL = "/usr/bin/systemctl"
TMP_SUFFIX = ".slp-tmp"
TOOL_TIMEOUT = 120

# Совпадает с CHECK-адаптером (проверяется тестом).
SPECS = {
    "admin_space_left_action": ("word", "suspend"),
    "disk_full_action": ("word", "suspend"),
    "log_file": ("exact", "/var/log/audit/audit.log"),
    "log_format": ("word", "ENRICHED"),
    "log_group": ("exact", "root"),
    "max_log_file": ("number", "50"),
    "max_log_file_action": ("word", "keep_logs"),
    "num_logs": ("number", "10"),
    "space_left_action": ("word", "syslog"),
}

# Разбор — общий с CHECK (product-auditd-conf-option-check-v1.py, PARSER; сверяется тестом).
PARSER = r'''
MAX_LINE = 158
NUMBER_RE = re.compile(rb"[0-9]+")
VALUE_RE = re.compile(rb"[\x21-\x7e]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def conf_lines(raw):
    """Строки файла без завершающего перевода строки; формат файла проверяется."""
    if b"\x00" in raw:
        raise ParseError("auditd-conf:invalid-bytes")
    if raw and not raw.endswith(b"\n"):
        raise ParseError("auditd-conf:no-final-newline")
    lines = raw.split(b"\n")[:-1] if raw else []
    if any(len(line) > MAX_LINE for line in lines):
        raise ParseError("auditd-conf:line-too-long")
    return lines


def key_lines(lines, key):
    """[(номер строки, значение, опция или None)] действующих строк ключа."""
    found = []
    name = key.encode("ascii")
    for number, line in enumerate(lines):
        tokens = [t for t in line.split(b" ") if t]
        if not tokens or tokens[0].startswith(b"#"):
            continue
        if tokens[0].lower().startswith(name + b"="):
            # `ключ=значение` без пробелов auditd не разбирает (Missing equal sign).
            raise ParseError("auditd-conf:invalid-line")
        if tokens[0].lower() != name:
            continue
        if len(tokens) not in (3, 4) or tokens[1] != b"=":
            raise ParseError("auditd-conf:invalid-line")
        found.append((number, tokens[2], tokens[3] if len(tokens) == 4 else None))
    return found


def matches(kind, expected, value):
    if kind == "number":
        return NUMBER_RE.fullmatch(value) is not None and int(value) == int(expected)
    if kind == "word":
        return value.lower() == expected.encode("ascii").lower()
    return value == expected.encode("ascii")


def observed(lines, key, kind, expected):
    """(VALUE, соответствие) параметра по строкам файла."""
    found = key_lines(lines, key)
    if not found:
        return "<absent>", False
    if len(found) > 1:
        return "<duplicate>", False
    _number, value, option = found[0]
    shown = value if option is None else value + b" " + option
    if VALUE_RE.fullmatch(value) is None or (option is not None and VALUE_RE.fullmatch(option) is None):
        raise ParseError("auditd-conf:invalid-value")
    return shown.decode("ascii"), option is None and matches(kind, expected, value)
'''
exec(PARSER, globals())  # noqa: S102 — один текст разбора с CHECK

ACTION_DIR = ("каталог {path} не является каталогом root без записи для группы и прочих: исправьте "
              "владельца и права каталога")
ACTION_FILE = ("{path} не является обычным файлом root:root с одной ссылкой без записи для группы и "
               "прочих: исправьте владельца и права файла или задайте {key} = {value} вручную")
ACTION_DUPLICATE = ("в {path} несколько действующих строк {key}: оставьте одну строку {key} = {value}")

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


class _Changed(Exception):
    """Объект изменился между фазами протокола записи или запись не удалась; файл не заменён."""


class _AfterRename(Exception):
    """Ошибка после rename: файл уже заменён (мутация состоялась), нужна компенсация."""


def _other(reason):
    return _Refused("ABORTED_PRECONDITION_OTHER", reason)


def _admin(reason, action):
    return _Refused("ABORTED_PRECONDITION_CONFLICT", reason,
                    {"class": "ADMIN_ACTION_REQUIRED", "required": True, "action": action})


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


def file_tuple(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def dir_tuple(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid)


def _uid_ok(st, root):
    return st.st_uid == 0 or (root is not None and st.st_uid == os.geteuid())


def _gid_ok(st, root):
    return st.st_gid == 0 or (root is not None and st.st_gid == os.getegid())


def _lstat(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def observe(root, key):
    """(байты, lstat файла, lstat каталога); отказ — _Refused."""
    dpath, fpath = _p(root, CONF_DIR), _p(root, CONF)
    kind, value = SPECS[key]
    try:
        dst = os.lstat(dpath)
    except FileNotFoundError:
        raise _other("auditd-conf:dir-missing")
    except OSError:
        raise _other("auditd-conf:stat-failed")
    if not stat.S_ISDIR(dst.st_mode) or not _uid_ok(dst, root) or stat.S_IMODE(dst.st_mode) & 0o022:
        raise _admin("auditd-conf:dir-untrusted", ACTION_DIR.format(path=CONF_DIR))
    try:
        st = os.lstat(fpath)
    except FileNotFoundError:
        raise _other("auditd-conf:missing")
    except OSError:
        raise _other("auditd-conf:stat-failed")
    if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not _uid_ok(st, root) or not _gid_ok(st, root)
            or stat.S_IMODE(st.st_mode) & 0o022):
        raise _admin("auditd-conf:untrusted", ACTION_FILE.format(path=CONF, key=key, value=value))
    try:
        fd = os.open(fpath, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise _other("auditd-conf:open-failed")
    chunks = []
    try:
        if file_tuple(os.fstat(fd)) != file_tuple(st):
            raise _other("auditd-conf:changed")
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        raise _other("auditd-conf:read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks), st, dst


def plan(lines, key):
    """Новые байты файла: действующая строка → шаблон `# ключ` → конец файла."""
    text = key.encode("ascii") + b" = " + SPECS[key][1].encode("ascii")
    new = list(lines)
    found = key_lines(lines, key)
    if found:
        new[found[0][0]] = text
    else:
        template = re.compile(rb"^[ ]*#[ \t]*" + re.escape(key.encode("ascii")) + rb"[ \t]*=", re.I)
        index = next((i for i, line in enumerate(new) if template.match(line)), None)
        if index is None:
            new.append(text)
        else:
            new[index] = text
    return b"".join(line + b"\n" for line in new)


def _write(root, data, ref_st, ref_dst):
    """Запись по протоколу F2–F4; возвращает lstat нового файла (кортеж F4).

    _Changed — файл не заменён; _AfterRename — файл заменён, но новый объект не прошёл проверку F4."""
    dpath, fpath = _p(root, CONF_DIR), _p(root, CONF)
    tmp = fpath + TMP_SUFFIX

    def same():
        st, dst = _lstat(fpath), _lstat(dpath)
        return (st is not None and dst is not None and file_tuple(st) == file_tuple(ref_st)
                and dir_tuple(dst) == dir_tuple(ref_dst) and st.st_nlink == 1)

    if not same():
        raise _Changed("auditd-conf:changed-before-write")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        raise _Changed("auditd-conf:tmp-create-failed")
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fchown(fd, ref_st.st_uid, ref_st.st_gid)
        os.fchmod(fd, stat.S_IMODE(ref_st.st_mode))
        os.fsync(fd)
    except OSError:
        os.close(fd)
        _unlink(tmp)
        raise _Changed("auditd-conf:write-failed")
    os.close(fd)
    if not same():
        _unlink(tmp)
        raise _Changed("auditd-conf:changed-before-rename")
    try:
        os.rename(tmp, fpath)
    except OSError:
        _unlink(tmp)
        raise _Changed("auditd-conf:rename-failed")
    try:
        dfd = os.open(dpath, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass
    new_st = _lstat(fpath)
    if new_st is None or not stat.S_ISREG(new_st.st_mode) or new_st.st_nlink != 1:
        raise _AfterRename("auditd-conf:after-rename-invalid")
    return new_st


def _unchanged_since_write(root, new_st, ref_dst):
    """Перед SIGHUP: файл — тот же объект, что после rename (F4), каталог — тот же, что при F1."""
    st, dst = _lstat(_p(root, CONF)), _lstat(_p(root, CONF_DIR))
    return (st is not None and dst is not None and file_tuple(st) == file_tuple(new_st)
            and dir_tuple(dst) == dir_tuple(ref_dst) and st.st_nlink == 1)


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _default_run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def _call(run, argv):
    try:
        cp = run(argv, TOOL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None, b""
    return cp.returncode, cp.stdout


def service_state(run):
    """(MainPID, ActiveState) юнита auditd.service; ошибка — _Refused."""
    rc, out = _call(run, [SYSTEMCTL, "show", "--property=MainPID,ActiveState", "--", UNIT])
    if rc != 0:
        raise _other("systemd:query-failed")
    props = {}
    try:
        text = out.decode("ascii")
    except UnicodeDecodeError:
        raise _other("systemd:invalid-output")
    for line in text.split("\n"):
        if not line:
            continue
        name, sep, value = line.partition("=")
        if not sep or name not in ("MainPID", "ActiveState") or name in props:
            raise _other("systemd:invalid-output")
        props[name] = value
    if set(props) != {"MainPID", "ActiveState"} or not re.fullmatch(r"[0-9]+", props["MainPID"]):
        raise _other("systemd:invalid-output")
    return int(props["MainPID"]), props["ActiveState"]


def reload_auditd(run, kill, proc, before):
    """SIGHUP работающему auditd. True — сигнал послан или служба не работала."""
    pid, active = before
    if active != "active" or pid == 0:
        return True
    try:
        with open("%s/%d/comm" % (proc, pid), "rb") as stream:
            if stream.read() != b"auditd\n":
                return False
        kill(pid, signal.SIGHUP)
    except OSError:
        return False
    return True


def _service_kept(run, before):
    """Служба, работавшая до APPLY, работает тем же процессом."""
    if before[1] != "active":
        return True
    try:
        now = service_state(run)
    except _Refused:
        return False
    return now == before


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
        "target": CONF,
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


def _postcheck(root, key, new_raw):
    try:
        raw, _st, _dst = observe(root, key)
        shown, ok = observed(conf_lines(raw), key, *SPECS[key])
    except (_Refused, ParseError):
        return None, False
    return shown, ok and raw == new_raw


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None, _kill=None, _proc="/proc"):
    """Привести параметр /etc/audit/auditd.conf к значению политики.

    `_root`, `_run`, `_kill` и `_proc` — только для тестов: корень файловой системы, запуск
    systemctl, отправка сигнала и каталог /proc.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run
    kill = _kill if _kill is not None else os.kill
    mutation = False

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, mutation=mutation, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if key not in SPECS or op != "eq" or expected != SPECS[key][1]:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    current = None
    try:
        actions.append("P1_OBSERVE")
        tool = _p(_root, SYSTEMCTL)
        if not os.path.isfile(tool) or not os.access(tool, os.X_OK):
            raise _other("tools:missing:systemctl")
        raw, st, dst = observe(_root, key)
        try:
            lines = conf_lines(raw)
            current, ok = observed(lines, key, *SPECS[key])
        except ParseError as exc:
            raise _other(exc.reason)
        if ok:
            return done("ALREADY_COMPLIANT", policy_current=current)
        if current == "<duplicate>":
            raise _admin("auditd-conf:duplicate-key",
                         ACTION_DUPLICATE.format(path=CONF, key=key, value=SPECS[key][1]))
        new_raw = plan(lines, key)
        try:
            planned, planned_ok = observed(conf_lines(new_raw), key, *SPECS[key])
        except ParseError:
            planned_ok = False
        if not planned_ok:
            raise _other("auditd-conf:plan-not-compliant")
        actions.append("P2_PLAN")
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY", policy_current=current)
        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            raise _other("privilege")
        before = service_state(run)
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, policy_current=current, operator_decision=exc.decision)

    actions.append("PHASE1_WRITE")
    reason = None
    try:
        new_st = _write(_root, new_raw, st, dst)
    except _Changed as exc:
        return done("FAILED_NOT_COMMITTED", reason=str(exc), policy_current=current)
    except _AfterRename as exc:
        # Rename состоялся — мутация была, нужна компенсация.
        new_st, reason = None, str(exc)
    mutation = True
    # Сигнал перечитывания доставлен работающему auditd: новая конфигурация могла быть загружена.
    hup_sent = False
    if reason is None:
        actions.append("PHASE2_RELOAD")
        # Перед SIGHUP — сверка с кортежем F4 файла и кортежем каталога F1.
        if not _unchanged_since_write(_root, new_st, dst):
            reason = "auditd-conf:changed-after-rename"
        elif not reload_auditd(run, kill, _proc, before):
            reason = "auditd:reload-failed"
        else:
            hup_sent = before[1] == "active" and before[0] != 0
    if reason is None:
        actions.append("FINAL_POSTCHECK")
        shown, ok = _postcheck(_root, key, new_raw)
        if ok and _service_kept(run, before):
            return done("APPLIED", policy_current=shown)
        reason = "auditd-conf:postcheck-failed"
    actions.append("COMPENSATION")
    restored = False
    now_st, now_dst = _lstat(_p(_root, CONF)), _lstat(_p(_root, CONF_DIR))
    if now_st is not None and now_dst is not None:
        try:
            _write(_root, raw, now_st, now_dst)
            restored = True
        except (_Changed, _AfterRename):
            restored = False
    if restored:
        try:
            restored = observe(_root, key)[0] == raw
        except _Refused:
            restored = False
    # Восстановленная конфигурация должна быть перечитана — иначе процесс
    # продолжает работать с новой.
    if hup_sent and not reload_auditd(run, kill, _proc, before):
        restored = False
    if before[1] == "active":
        try:
            if service_state(run)[1] != "active":
                _call(run, [SYSTEMCTL, "start", "--", UNIT])
        except _Refused:
            pass
        try:
            restored = restored and service_state(run)[1] == "active"
        except _Refused:
            restored = False
    if restored:
        return done("FAILED_NOT_COMMITTED", reason=reason, policy_current=current)
    return done("FAILED_COMPENSATION", reason=reason, policy_current=current)


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
