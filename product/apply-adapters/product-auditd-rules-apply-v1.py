#!/usr/bin/env python3
"""APPLY-адаптер механизма auditd-rules-v1 (fstec-logging-2025 приложение 2, п.4; SRC-0053).

Решение пользователя 30.09.2026 (вариант B): 25 правил таблицы 1 без примера myapp — один контроль.
Карта разбиения auditd v6 (решение пользователя 01.10.2026, разведка 01.10.2026 на средах 1–7).

* Наблюдение и набор — тот же текст, что у CHECK `auditd-rules-check-semantic-v1` (PARSER совпадает
  побайтно, сверяется тестом). Соответствие — каждое правило есть в файлах rules.d/*.rules и в
  выводе `auditctl -l`.
* Предусловия до записи (нарушение — решение администратора, ничего не меняется): каталоги
  /etc/audit и /etc/audit/rules.d — каталоги root без записи для группы и прочих; файл продукта
  /etc/audit/rules.d/50-securelinux-policy.rules — отсутствует либо обычный файл root:root с одной
  ссылкой без записи для группы и прочих; /etc/audit/audit.rules — отсутствует либо обычный файл
  root с одной ссылкой без записи для группы и прочих; прочие файлы rules.d/*.rules (как их
  отбирает augenrules) — обычные файлы root без записи для группы и прочих (как у CHECK), только
  чтение; ни одно правило набора (в любом из двух написаний) не записано в прочих файлах — иначе
  augenrules откажет на дубле (`Rule exists`); `auditctl -s` — не `enabled 2`; ни в одном файле
  rules.d/*.rules нет действующей строки `-e 2` (иначе откат невозможен до перезагрузки);
  `auditctl -l` читается.
* Мутация: файл продукта целиком (25 правил в написании таблицы 1), затем `augenrules --load`.
  Байты файла продукта уже равны плану — записи нет, только загрузка.
* Идентичность (карта v6, протокол F1–F5): кортежи файлов (st_dev, st_ino, st_mode, st_uid,
  st_gid, st_nlink, st_size, st_mtime_ns, st_ctime_ns) и каталогов (st_dev, st_ino, st_mode,
  st_uid, st_gid) снимаются при наблюдении (F1) и сверяются перед созданием временного файла (F2)
  и перед rename (F3); временный файл — в том же каталоге (O_CREAT|O_EXCL|O_NOFOLLOW, суффикс
  .slp-tmp, имя не оканчивается на .rules), fsync; файла не было — root:root 0640, иначе прежние
  владелец, группа и режим. После rename (F4) — новый кортеж; перед `augenrules --load` файл
  продукта = F4, audit.rules, прочие файлы и каталоги = F1. После загрузки (F5) — файл продукта
  = F4, audit.rules — обычный файл root с одной ссылкой, все 25 правил в файлах и в ядре.
* Откат (карта v6): прежние байты файла продукта (файла не было — удаляется), `augenrules --load`,
  затем прежние байты /etc/audit/audit.rules (не было — удаляется); сверка: вывод `auditctl -l`
  побайтно равен снимку F1, байты обоих файлов равны F1. Совпало — FAILED_NOT_COMMITTED, иначе
  FAILED_COMPENSATION. Отказ до загрузки — возвращается только файл продукта, загрузки нет.
  Файл, которого не было в F1, удаляется только при каталогах = F1 и относительно дескриптора
  сверенного родительского каталога; итоговая сверка — оба файла (в т.ч. отсутствие) и ядро после
  загрузки отката. Одна ссылка требуется только у изменяемых файлов.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess

ADAPTER_ID = "product-auditd-rules-apply-v1"
MECHANISM_ID = "auditd-rules-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "auditd-rules"
AUDIT_DIR = "/etc/audit"
RULES_DIR = "/etc/audit/rules.d"
PRODUCT_NAME = b"50-securelinux-policy.rules"
PRODUCT = RULES_DIR + "/" + PRODUCT_NAME.decode("ascii")
AUDIT_RULES = "/etc/audit/audit.rules"
MUTABLE = (PRODUCT, AUDIT_RULES)
AUDITCTL = "/usr/sbin/auditctl"
AUGENRULES = "/usr/sbin/augenrules"
CANONICAL_KEY = "table1"
CANONICAL_EXPECTED = "present"
TMP_SUFFIX = ".slp-tmp"
NEW_MODE = 0o640
TOOL_TIMEOUT = 120

# Набор и разбор — общие с CHECK (product-auditd-rules-check-v1.py, PARSER; сверяется тестом).
PARSER = r'''
# Набор правил таблицы 1 (SRC-0053) без примера myapp: (написание таблицы 1, вид в выводе
# `auditctl -l`). Нормализованный вид снят разведкой 01.10.2026 на средах 1–7 (одинаков побайтно).
RULES = (
    (b"-w /var/log -p w -k var_log_changes", b"-w /var/log -p w -k var_log_changes"),
    (b"-w /etc/group -p wa -k etcgroup", b"-w /etc/group -p wa -k etcgroup"),
    (b"-w /etc/passwd -p wa -k etcpasswd", b"-w /etc/passwd -p wa -k etcpasswd"),
    (b"-w /etc/gshadow -k etcgroup", b"-w /etc/gshadow -p rwxa -k etcgroup"),
    (b"-w /etc/shadow -k etcpasswd", b"-w /etc/shadow -p rwxa -k etcpasswd"),
    (b"-w /etc/security/opasswd -k opasswd", b"-w /etc/security/opasswd -p rwxa -k opasswd"),
    (b"-w /etc/adduser.conf -k adduserconf", b"-w /etc/adduser.conf -p rwxa -k adduserconf"),
    (b"-w /etc/sudoers -p wa -k actions", b"-w /etc/sudoers -p wa -k actions"),
    (b"-w /usr/bin/passwd -p x -k passwd_modification", b"-w /usr/bin/passwd -p x -k passwd_modification"),
    (b"-w /usr/bin/gpasswd -p x -k gpasswd_modification", b"-w /usr/bin/gpasswd -p x -k gpasswd_modification"),
    (b"-w /usr/sbin/groupadd -p x -k group_modification", b"-w /usr/sbin/groupadd -p x -k group_modification"),
    (b"-w /usr/sbin/groupmod -p x -k group_modification", b"-w /usr/sbin/groupmod -p x -k group_modification"),
    (b"-w /usr/sbin/addgroup -p x -k group_modification", b"-w /usr/sbin/addgroup -p x -k group_modification"),
    (b"-w /usr/sbin/useradd -p x -k user_modification", b"-w /usr/sbin/useradd -p x -k user_modification"),
    (b"-w /usr/sbin/usermod -p x -k user_modification", b"-w /usr/sbin/usermod -p x -k user_modification"),
    (b"-w /usr/sbin/adduser -p x -k user_modification", b"-w /usr/sbin/adduser -p x -k user_modification"),
    (b"-w /etc/login.defs -p wa -k login", b"-w /etc/login.defs -p wa -k login"),
    (b"-w /etc/securetty -p wa -k login", b"-w /etc/securetty -p wa -k login"),
    (b"-w /var/log/faillog -p wa -k login", b"-w /var/log/faillog -p wa -k login"),
    (b"-w /var/log/lastlog -p wa -k login", b"-w /var/log/lastlog -p wa -k login"),
    (b"-w /var/log/tallylog -p wa -k login", b"-w /var/log/tallylog -p wa -k login"),
    (b"-a exit,always -F arch=b64 -S execve -F uid=0 -k authentication_events",
     b"-a always,exit -F arch=b64 -S execve -F uid=0 -F key=authentication_events"),
    (b"-a exit,always -F arch=b32 -S execve -F uid=0 -k authentication_events",
     b"-a always,exit -F arch=b32 -S execve -F uid=0 -F key=authentication_events"),
    (b"-a exit,always -F arch=b64 -S bind -S connect -F success=0 -k network_events",
     b"-a always,exit -F arch=b64 -S connect,bind -F success=0 -F key=network_events"),
    (b"-w /dev/bus/usb -p rwxa -k usb", b"-w /dev/bus/usb -p rwxa -k usb"),
)


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def rule_file_names(names):
    """Имена загружаемых файлов правил: как `ls` без скрытых, имя оканчивается на .rules."""
    return sorted(n for n in names if not n.startswith(b".") and n.endswith(b".rules"))


def file_rule_lines(raw):
    """Множество строк файла правил без пробелов и табуляций по краям."""
    if b"\x00" in raw:
        raise ParseError("auditd-rules:invalid-bytes")
    return {line.strip(b" \t") for line in raw.split(b"\n")}


def present_in_files(lines):
    """Номера правил набора, записанных в файлах (в любом из двух написаний)."""
    return [i for i, (source, normal) in enumerate(RULES) if source in lines or normal in lines]


def present_in_kernel(output):
    """Номера правил набора в выводе `auditctl -l` (точная строка нормализованного вида)."""
    lines = set(output.split(b"\n"))
    return [i for i, (_source, normal) in enumerate(RULES) if normal in lines]
'''
exec(PARSER, globals())  # noqa: S102 — один текст набора с CHECK

PRODUCT_BYTES = (b"# SecureLinux-Policy: fstec-logging-2025 appendix 2 item 4, table 1 (without the myapp example).\n"
                 b"# The file is written by the product as a whole.\n"
                 + b"".join(source + b"\n" for source, _normal in RULES))

ACTION_DIR = ("каталог {path} не является каталогом root без записи для группы и прочих: исправьте "
              "владельца и права каталога")
ACTION_FILE = ("{path} не является обычным файлом root с одной ссылкой без записи для группы и прочих: "
               "исправьте владельца и права файла")
ACTION_OTHER = ("{path} не является обычным файлом root без записи для группы и прочих: исправьте "
                "владельца и права файла или удалите его")
ACTION_DUPLICATE = ("правила таблицы 1 уже записаны в {path}: удалите их оттуда (продукт пишет весь набор "
                    "в " + PRODUCT + ") или настройте весь набор вручную")
ACTION_LOCKED = ("правила auditd заблокированы (`-e 2`): изменение возможно только после перезагрузки без "
                 "строки `-e 2` в файлах rules.d")

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
ENABLED_RE = re.compile(rb"^enabled ([0-9]+)$", re.M)


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


def _tuple(st):
    return None if st is None else file_tuple(st)


def _uid_ok(st, root):
    return st.st_uid == 0 or (root is not None and st.st_uid == os.geteuid())


def _gid_ok(st, root):
    return st.st_gid == 0 or (root is not None and st.st_gid == os.getegid())


def _no_gw(st):
    return not stat.S_IMODE(st.st_mode) & 0o022


def _lstat(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None


def _read(path, st):
    """Байты обычного файла; объект должен совпасть с кортежем st; отказ — _Refused."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise _other("auditd-rules:open-failed")
    chunks = []
    try:
        if file_tuple(os.fstat(fd)) != file_tuple(st):
            raise _other("auditd-rules:changed")
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        raise _other("auditd-rules:read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


def _default_run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def _call(run, argv):
    try:
        cp = run(argv, TOOL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None, b""
    return cp.returncode, cp.stdout


def kernel_rules(run):
    """Вывод `auditctl -l` (байты); ошибка — _Refused."""
    rc, out = _call(run, [AUDITCTL, "-l"])
    if rc != 0:
        raise _other("auditctl:list-failed")
    return out


def enabled_state(run):
    """Значение `enabled` из `auditctl -s`; ошибка — _Refused."""
    rc, out = _call(run, [AUDITCTL, "-s"])
    found = ENABLED_RE.findall(out) if rc == 0 else []
    if len(found) != 1:
        raise _other("auditctl:status-failed")
    return int(found[0])


def locks_rules(lines):
    """Есть действующая строка `-e 2`."""
    return any(line.split()[:2] == [b"-e", b"2"] for line in lines if not line.startswith(b"#"))


def observe(root):
    """Снимок F1: {path: (lstat, байты)} для файлов, lstat каталогов; отказ — _Refused."""
    dirs = {}
    for path in (AUDIT_DIR, RULES_DIR):
        try:
            st = os.lstat(_p(root, path))
        except FileNotFoundError:
            raise _other("auditd-rules:dir-missing")
        except OSError:
            raise _other("auditd-rules:stat-failed")
        if not stat.S_ISDIR(st.st_mode) or not _uid_ok(st, root) or not _no_gw(st):
            raise _admin("auditd-rules:dir-untrusted", ACTION_DIR.format(path=path))
        dirs[path] = st
    files = {}
    for path, need_gid in ((PRODUCT, True), (AUDIT_RULES, False)):
        st = _lstat(_p(root, path))
        if st is None:
            files[path] = (None, None)
            continue
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not _uid_ok(st, root)
                or (need_gid and not _gid_ok(st, root)) or not _no_gw(st)):
            raise _admin("auditd-rules:untrusted", ACTION_FILE.format(path=path))
        files[path] = (st, _read(_p(root, path), st))
    try:
        names = rule_file_names(os.listdir(os.fsencode(_p(root, RULES_DIR))))
    except OSError:
        raise _other("auditd-rules:list-failed")
    others = {}
    for name in names:
        if name == PRODUCT_NAME:
            continue
        path = RULES_DIR + "/" + os.fsdecode(name)
        st = _lstat(_p(root, path))
        if st is None or not stat.S_ISREG(st.st_mode) or not _uid_ok(st, root) or not _no_gw(st):
            raise _admin("auditd-rules:other-untrusted", ACTION_OTHER.format(path=path))
        others[path] = (st, _read(_p(root, path), st))
    return dirs, files, others


def _lines(raw):
    try:
        return file_rule_lines(raw)
    except ParseError as exc:
        raise _other(exc.reason)


def unchanged(root, dirs, refs, full=True):
    """Каталоги = F1, файлы = ожидаемым кортежам (None — файла нет); у изменяемых файлов (файл
    продукта и audit.rules) st_nlink = 1 (прочие файлы только читаются).

    full — refs описывает все файлы: набор файлов rules.d/*.rules, которые загрузит augenrules,
    совпадает с файлами refs в rules.d (новый или удалённый файл правил — расхождение)."""
    if full:
        expected = {p for p, ref in refs.items() if ref is not None and p.startswith(RULES_DIR + "/")}
        try:
            names = rule_file_names(os.listdir(os.fsencode(_p(root, RULES_DIR))))
        except OSError:
            return False
        if {RULES_DIR + "/" + os.fsdecode(n) for n in names} != expected:
            return False
    for path, st in dirs.items():
        now = _lstat(_p(root, path))
        if now is None or dir_tuple(now) != dir_tuple(st):
            return False
    for path, ref in refs.items():
        now = _lstat(_p(root, path))
        if _tuple(now) != ref or (now is not None and path in MUTABLE and now.st_nlink != 1):
            return False
    return True


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _write(root, path, data, refs, dirs, owner, mode, full=True):
    """Запись по протоколу F2–F4; возвращает lstat нового файла (кортеж F4).

    refs — ожидаемые кортежи всех файлов (F1), dirs — lstat каталогов (F1).
    _Changed — файл не заменён; _AfterRename — файл заменён, но новый объект не прошёл проверку F4."""
    fpath = _p(root, path)
    tmp = fpath + TMP_SUFFIX
    if not unchanged(root, dirs, refs, full):
        raise _Changed("auditd-rules:changed-before-write")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        raise _Changed("auditd-rules:tmp-create-failed")
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fchown(fd, owner[0], owner[1])
        os.fchmod(fd, mode)
        os.fsync(fd)
    except OSError:
        os.close(fd)
        _unlink(tmp)
        raise _Changed("auditd-rules:write-failed")
    os.close(fd)
    if not unchanged(root, dirs, refs, full):
        _unlink(tmp)
        raise _Changed("auditd-rules:changed-before-rename")
    try:
        os.rename(tmp, fpath)
    except OSError:
        _unlink(tmp)
        raise _Changed("auditd-rules:rename-failed")
    try:
        dfd = os.open(os.path.dirname(fpath), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass
    new_st = _lstat(fpath)
    if new_st is None or not stat.S_ISREG(new_st.st_mode) or new_st.st_nlink != 1:
        raise _AfterRename("auditd-rules:after-rename-invalid")
    return new_st


def _dirs_same(root, dirs):
    for path, st in dirs.items():
        now = _lstat(_p(root, path))
        if now is None or dir_tuple(now) != dir_tuple(st):
            return False
    return True


def _unlink_checked(root, path, dirs):
    """Удалить файл, которого не было в F1: каталоги = F1; родительский каталог
    открыт без перехода по ссылке и сверен с F1, удаление — относительно его дескриптора; удаляется
    только обычный файл. Каталог подменён или объект не обычный файл — ничего не удаляется, False."""
    if not _dirs_same(root, dirs):
        return False
    parent = os.path.dirname(path)
    try:
        dfd = os.open(_p(root, parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        if dir_tuple(os.fstat(dfd)) != dir_tuple(dirs[parent]):
            return False
        name = os.path.basename(path)
        try:
            st = os.lstat(name, dir_fd=dfd)
        except FileNotFoundError:
            return True
        if not stat.S_ISREG(st.st_mode):
            return False
        os.unlink(name, dir_fd=dfd)
    except OSError:
        return False
    finally:
        os.close(dfd)
    return True


def matches_f1(root, path, before, dirs):
    """Файл совпадает с F1: каталоги = F1; не было — нет и сейчас; был — обычный файл с одной
    ссылкой, те же байты, владелец, группа и режим."""
    st0, raw0 = before
    if not _dirs_same(root, dirs):
        return False
    now = _lstat(_p(root, path))
    if st0 is None:
        return now is None
    if now is None or not stat.S_ISREG(now.st_mode) or now.st_nlink != 1:
        return False
    if (now.st_uid, now.st_gid, stat.S_IMODE(now.st_mode)) != (st0.st_uid, st0.st_gid, stat.S_IMODE(st0.st_mode)):
        return False
    try:
        return _read(_p(root, path), now) == raw0
    except _Refused:
        return False


def _restore(root, path, before, dirs):
    """Вернуть файл к F1 (байты, владелец, группа, режим; не было — удалить). True — совпало."""
    st0, raw0 = before
    fpath = _p(root, path)
    now = _lstat(fpath)
    if st0 is None:
        return _unlink_checked(root, path, dirs) and matches_f1(root, path, before, dirs)
    try:
        current = None if now is None else _read(fpath, now)
    except _Refused:
        current = None
    same_meta = (now is not None and (now.st_uid, now.st_gid, stat.S_IMODE(now.st_mode))
                 == (st0.st_uid, st0.st_gid, stat.S_IMODE(st0.st_mode)))
    if current != raw0 or not same_meta:
        try:
            _write(root, path, raw0, {path: _tuple(now)}, dirs, (st0.st_uid, st0.st_gid), stat.S_IMODE(st0.st_mode),
                   full=False)
        except (_Changed, _AfterRename):
            return False
    return matches_f1(root, path, before, dirs)


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
        "target": PRODUCT,
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


def _shown(files, kernel):
    return "files=%d/%d kernel=%d/%d" % (files, len(RULES), kernel, len(RULES))


def _state(root, run):
    """(число правил в файлах, число в ядре, снимок) по текущему состоянию; отказ — _Refused."""
    _dirs, files, others = observe(root)
    lines = set()
    for st, raw in [files[PRODUCT]] + list(others.values()):
        if st is not None:
            lines |= _lines(raw)
    snapshot = kernel_rules(run)
    return len(present_in_files(lines)), len(present_in_kernel(snapshot)), snapshot


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None):
    """Привести правила таблицы 1 в /etc/audit/rules.d и в ядре к набору политики.

    `_root` и `_run` — только для тестов: корень файловой системы и запуск auditctl/augenrules.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run
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
        for tool in (AUDITCTL, AUGENRULES):
            path = _p(_root, tool)
            if not os.path.isfile(path) or not os.access(path, os.X_OK):
                raise _other("tools:missing:" + os.path.basename(tool))
        dirs, files, others = observe(_root)
        product_st, product_raw = files[PRODUCT]
        other_lines = set()
        locked = False
        for st, raw in others.values():
            lines = _lines(raw)
            other_lines |= lines
            locked = locked or locks_rules(lines)
        product_lines = _lines(product_raw) if product_st is not None else set()
        locked = locked or locks_rules(product_lines)
        snapshot = kernel_rules(run)
        in_files = len(present_in_files(other_lines | product_lines))
        in_kernel = len(present_in_kernel(snapshot))
        current = _shown(in_files, in_kernel)
        if in_files == len(RULES) and in_kernel == len(RULES):
            return done("ALREADY_COMPLIANT", policy_current=current)
        if locked or enabled_state(run) == 2:
            raise _admin("auditd-rules:locked", ACTION_LOCKED)
        for path, (st, raw) in sorted(others.items()):
            if present_in_files(_lines(raw)):
                raise _admin("auditd-rules:rule-in-other-file", ACTION_DUPLICATE.format(path=path))
        actions.append("P2_PLAN")
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY", policy_current=current)
        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            raise _other("privilege")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, policy_current=current, operator_decision=exc.decision)

    refs = {PRODUCT: _tuple(product_st), AUDIT_RULES: _tuple(files[AUDIT_RULES][0])}
    refs.update({path: _tuple(st) for path, (st, _raw) in others.items()})
    reason = None
    loaded = False
    new_st = product_st
    if product_raw != PRODUCT_BYTES:
        actions.append("PHASE1_WRITE")
        if product_st is None:
            owner = (0, 0) if _root is None else (os.geteuid(), os.getegid())
            mode = NEW_MODE
        else:
            owner = (product_st.st_uid, product_st.st_gid)
            mode = stat.S_IMODE(product_st.st_mode)
        try:
            new_st = _write(_root, PRODUCT, PRODUCT_BYTES, refs, dirs, owner, mode)
        except _Changed as exc:
            return done("FAILED_NOT_COMMITTED", reason=str(exc), policy_current=current)
        except _AfterRename as exc:
            new_st, reason = None, str(exc)
        mutation = True
    if reason is None:
        actions.append("PHASE2_LOAD")
        after_write = dict(refs)
        after_write[PRODUCT] = _tuple(new_st)
        if not unchanged(_root, dirs, after_write):
            reason = "auditd-rules:changed-before-load"
        else:
            mutation = True
            loaded = True
            rc, _out = _call(run, [AUGENRULES, "--load"])
            if rc != 0:
                reason = "augenrules:load-failed"
    if reason is None:
        actions.append("FINAL_POSTCHECK")
        audit_st = _lstat(_p(_root, AUDIT_RULES))
        try:
            in_files, in_kernel, _snap = _state(_root, run)
        except _Refused:
            in_files = in_kernel = -1
        if (_tuple(_lstat(_p(_root, PRODUCT))) == _tuple(new_st) and audit_st is not None
                and stat.S_ISREG(audit_st.st_mode) and audit_st.st_nlink == 1 and _uid_ok(audit_st, _root)
                and in_files == len(RULES) and in_kernel == len(RULES)):
            return done("APPLIED", policy_current=_shown(in_files, in_kernel))
        reason = "auditd-rules:postcheck-failed"
    actions.append("COMPENSATION")
    restored = _restore(_root, PRODUCT, files[PRODUCT], dirs)
    if loaded:
        rc, _out = _call(run, [AUGENRULES, "--load"])
        restored = _restore(_root, AUDIT_RULES, files[AUDIT_RULES], dirs) and restored
        try:
            restored = restored and kernel_rules(run) == snapshot
        except _Refused:
            restored = False
    # Итоговая сверка обоих файлов с F1 (в т.ч. отсутствие) после загрузки отката.
    restored = (restored and matches_f1(_root, PRODUCT, files[PRODUCT], dirs)
                and matches_f1(_root, AUDIT_RULES, files[AUDIT_RULES], dirs))
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
