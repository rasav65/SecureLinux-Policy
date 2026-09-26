#!/usr/bin/env python3
"""product-sshd-config-option-apply-v1.

APPLY adapter for mechanism `sshd-config-option-v1` (fstec-configuration-2026 п.9.1,
SRC-0088): `PermitEmptyPasswords no`, `PermitRootLogin no`, `PasswordAuthentication no`
в основном `/etc/ssh/sshd_config`.

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-sshd-config-option-v1.json

Решения пользователя: APPLY для трёх директив п.9.1 выполняется (25.09.2026, требование
политики компании); правка на месте, без дублирования строк (схема 1–4, 26.09.2026):

1. Действующая глобальная строка ключа в основном файле — значение меняется на `no`.
2. Действующей нет, есть закомментированный шаблон `#<Key> …` в глобальной области —
   он заменяется строкой `<Key> no` на том же месте.
3. Нет ни того, ни другого — `<Key> no` добавляется перед первым `Match` или в конец.
4. Включаемые файлы (`Include`, глобальная область), где ключ задан не `no`, правятся
   на месте: значение меняется на `no` — иначе они перекрыли бы основной файл
   (sshd берёт первое прочитанное значение).

Каждый изменяемый файл готовится временным файлом в том же каталоге (режим и владелец
прежние) и проверяется `sshd -t` до замены; после замены — `sshd -t` всего дерева,
`systemctl try-reload-or-restart ssh.service` и итоговая проверка `sshd -T`. Ошибка любой
из них — прежние байты всех заменённых файлов возвращаются и сверяются (после попытки
перезагрузки sshd перезагружается повторно); несовпадение — FAILED_COMPENSATION.
Правила `Include` (ссылки, тип префикса шаблона, имена с переводом строки) — как у CHECK.

Отказ с блоком «решение администратора», без записи:
- основной файл (всегда, до признания соответствия) или изменяемый включаемый файл не
  является обычным файлом root без записи для группы и прочих;
- в области `Match` (основной файл или включаемые) директива задана не `no`;
- `PermitRootLogin`: в группах `sudo` и `admin` нет пользователя, кроме root, или ни один
  из них не войдёт по SSH сам (вход по паролю выключен и пригодного ключа нет);
- `PasswordAuthentication`: ни у одного такого пользователя нет пригодного ключа — непустого
  `~/.ssh/authorized_keys` (или `authorized_keys2`), при StrictModes с правами `~`, `~/.ssh`
  и файла, которые примет sshd;
- настройки входа администратора в `sshd -T` для его собственного соединения (`Match User`
  учитывается) не проверяемы механизмом: AllowUsers/DenyUsers/AllowGroups/DenyGroups,
  AuthenticationMethods не `any`, нестандартные AuthorizedKeysFile или PubkeyAuthentication.
"""

from __future__ import annotations

import errno
import glob
import os
import re
import stat
import subprocess

ADAPTER_ID = "product-sshd-config-option-apply-v1"
MECHANISM_ID = "sshd-config-option-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "sshd-config-option"

CONTROL_KEYS = {
    "FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION": "PasswordAuthentication",
    "FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS": "PermitEmptyPasswords",
    "FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN": "PermitRootLogin",
}
EXPECTED_OP = "eq"
EXPECTED_VALUE = "no"

SSHD_CONFIG = "/etc/ssh/sshd_config"
SSH_DIR = "/etc/ssh"
GROUP = "/etc/group"
PASSWD = "/etc/passwd"
SSHD = "/usr/sbin/sshd"
SYSTEMCTL = "/usr/bin/systemctl"
SSH_UNIT = "ssh.service"
EFFECTIVE_SPEC = "user=root,host=localhost,addr=127.0.0.1"
TOOL_TIMEOUT = 60
MAX_INCLUDE_DEPTH = 16
SUDO_GROUPS = ("sudo", "admin")
DEFAULT_AUTHORIZED_KEYS = (
    (".ssh/authorized_keys", ".ssh/authorized_keys2"),
    (".ssh/authorized_keys",),
)

ACTION_FILE = ("{path} не является обычным файлом root без записи для группы и прочих: задайте "
               "«{key} no» в /etc/ssh/sshd_config и уберите иные значения {key} вручную.")
ACTION_MATCH = ("в блоке Match файла sshd_config или включаемого файла {key} задан не «no»: глобальное "
                "значение его не перекрывает; исправьте блок Match вручную.")
ACTION_NO_SUDO = ("в группах sudo и admin нет пользователя, кроме root: после запрета входа root по SSH "
                  "удалённо администрировать сервер будет некому; назначьте администратора в группу sudo "
                  "или задайте «PermitRootLogin no» вручную.")
ACTION_NO_KEY = ("ни у одного пользователя групп sudo и admin нет ключа в ~/.ssh/authorized_keys: после "
                 "запрета входа по паролю вход по SSH станет невозможен; добавьте ключ администратору или "
                 "задайте «PasswordAuthentication no» вручную.")
ACTION_NO_ADMIN_LOGIN = ("ни один пользователь групп sudo и admin не может войти по SSH (вход по паролю "
                         "выключен, ключа нет): после запрета входа root удалённо администрировать сервер "
                         "будет некому; добавьте ключ администратору или задайте «PermitRootLogin no» вручную.")
ACTION_KEYS_SETUP = ("настройки входа администраторов по SSH (AllowUsers, DenyUsers, AllowGroups, DenyGroups, "
                     "AuthenticationMethods, AuthorizedKeysFile, PubkeyAuthentication) отличаются от значений по "
                     "умолчанию: возможность входа администратора не проверена; задайте «{key} no» вручную.")

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
# Пробельные символы — как `[[:space:]]` CHECK в локали C (без \n: строки уже разделены по LF).
SPACE = " \t\v\f\r"
DIRECTIVE_RE = re.compile(r"^[ \t\v\f\r]*([^ \t\v\f\r=]+)(?:[ \t\v\f\r]*=[ \t\v\f\r]*|[ \t\v\f\r]+)(.*)$")
BARE_DIRECTIVE_RE = re.compile(r"^[ \t\v\f\r]*([^ \t\v\f\r=]+)[ \t\v\f\r]*$")
VALUE_RE = re.compile(r"^([ \t\v\f\r]*[^ \t\v\f\r=]+(?:[ \t\v\f\r]*=[ \t\v\f\r]*|[ \t\v\f\r]+))"
                      r"([^ \t\v\f\r]+)(.*)$")
GLOB_CHARS = ("*", "?", "[")
USER_NAME_RE = re.compile(r"[a-z_][a-z0-9_.-]*")
TMP_SUFFIX = ".slp-tmp"


class _Refused(Exception):
    def __init__(self, outcome, reason, decision=None):
        super().__init__(reason)
        self.outcome = outcome
        self.reason = reason
        self.decision = decision


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


def _admin(action):
    return {"class": "ADMIN_ACTION_REQUIRED", "required": True, "action": action}


def _other(reason):
    return _Refused("ABORTED_PRECONDITION_OTHER", reason)


def _read_regular(path, refuse):
    """(байты, stat) обычного файла без перехода по ссылке; не обычный файл — `refuse`.

    `O_NONBLOCK`: FIFO без писателя не блокирует открытие и отвергается по типу дескриптора.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise refuse  # символьная ссылка — не обычный файл
        raise _other("sshd-config:read-failed")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise refuse
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        _close_quietly(fd)
        raise _other("sshd-config:read-failed")
    except BaseException:
        _close_quietly(fd)
        raise
    try:
        os.close(fd)
    except OSError:
        raise _other("sshd-config:read-failed")
    return b"".join(chunks), st


def _close_quietly(fd):
    try:
        os.close(fd)
    except OSError:
        pass


def _trusted_uid(root):
    """Владелец доверенного файла: root; в тестовом дереве (`_root`) — текущий пользователь."""
    return 0 if root is None else os.geteuid()


def _trusted(st, root):
    return (stat.S_ISREG(st.st_mode) and not stat.S_IMODE(st.st_mode) & 0o022
            and st.st_uid == _trusted_uid(root))


def _text(raw):
    if b"\x00" in raw or re.search(rb"\r(?!\n)", raw):
        raise _other("sshd-config:invalid-bytes")
    # Как у CHECK: допустимы любые байты, кроме NUL и одиночного CR; байты, не являющиеся
    # UTF-8, переносятся без изменений (surrogateescape туда и обратно).
    return raw.decode("utf-8", "surrogateescape")


def _lf_lines(text):
    """Строки с окончаниями, разделение только по LF (как у CHECK; \v, \f, \x1c… — не разделители)."""
    parts = text.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def _body(line):
    """Строка без окончания (\\n или \\r\\n)."""
    if line.endswith("\r\n"):
        return line[:-2]
    return line[:-1] if line.endswith("\n") else line


def _eol(line):
    if line.endswith("\r\n"):
        return "\r\n"
    return "\n" if line.endswith("\n") else ""


def _directive(line):
    """(ключ в нижнем регистре, остаток строки) значимой строки или None."""
    body = _body(line)
    if not body.strip(SPACE) or body.lstrip(SPACE).startswith("#"):
        return None
    m = DIRECTIVE_RE.match(body) or BARE_DIRECTIVE_RE.match(body)
    if m is None:
        return None
    return m.group(1).lower(), (m.group(2) if m.re is DIRECTIVE_RE else "")


ARG_SPACE = (" ", "\t", "\r")


def split_args(rest):
    """Аргументы строки — как `_slp_split_args` CHECK sshd-config-option (принятая семантика).

    Разделители — пробел, табуляция, CR; `#` в начале аргумента завершает строку; кавычки
    `'` и `"` группируют; незакрытая кавычка — отказ. Обратная косая черта в CHECK — обычный
    символ (сравнение с двухсимвольной строкой в bash никогда не истинно), здесь так же;
    равенство разбора проверено дифференциальным тестом против bash-функции CHECK.
    """
    args, i, n = [], 0, len(rest)
    while i < n:
        while i < n and rest[i] in ARG_SPACE:
            i += 1
        if i >= n or rest[i] == "#":
            return args
        token, quote = "", ""
        while i < n:
            c = rest[i]
            if quote:
                if c == quote:
                    quote = ""
                else:
                    token += c
                i += 1
                continue
            if c in ('"', "'"):
                quote = c
                i += 1
                continue
            if c in ARG_SPACE:
                break
            token += c
            i += 1
        if quote:
            raise _other("sshd-config:invalid-arguments")
        args.append(token)
    return args


def _absent(path, reason):
    """True при доказанном ENOENT; иная ошибка lstat — отказ `reason` (как у CHECK)."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        raise _other(reason)
    return False


def _include_targets(root, pattern):
    """Файлы строки Include по правилам CHECK sshd-config-option."""
    path = pattern if pattern.startswith("/") else SSH_DIR + "/" + pattern
    if any(ch in path for ch in GLOB_CHARS):
        cut = min(path.index(ch) for ch in GLOB_CHARS if ch in path)
        prefix = path[:cut].rsplit("/", 1)[0] or "/"
        real_prefix = _p(root, prefix)
        if not _absent(real_prefix, "sshd-config:include-prefix-stat-failed"):
            if os.path.islink(real_prefix):
                raise _other("sshd-config:include-prefix-symlink")
            if not os.path.isdir(real_prefix):
                raise _other("sshd-config:include-prefix-invalid-type")
            try:
                for _dir, dirs, files in os.walk(real_prefix, onerror=_raise_scan):
                    if any("\n" in name for name in dirs + files):
                        raise _other("sshd-config:include-newline-name")
            except OSError:
                raise _other("sshd-config:include-prefix-scan-failed")
        return sorted(glob.glob(_p(root, path)))
    real = _p(root, path)
    return [] if _absent(real, "sshd-config:include-stat-failed") else [real]


def _raise_scan(exc):
    raise exc


class Config:
    """Разобранное дерево sshd_config для одного ключа.

    Семантика та же, что у CHECK sshd-config-option: `Match` открывает область до
    конца файла; включаемый файл наследует область строки `Include`; глобальные `no`
    считаются только в основном файле.
    """

    def __init__(self, root, lkey):
        self.root = root
        self.lkey = lkey
        self.main = _p(root, SSHD_CONFIG)
        self.files = {}      # путь -> (байты, stat, строки с окончаниями)
        self.occurrences = []  # (путь, индекс строки, область, основной файл, значение)
        self.main_match_index = None
        self.main_template_index = None
        self._stack = set()
        self._parse(self.main, 0, True, "GLOBAL")

    def _load(self, path, main):
        if path not in self.files:
            refuse = (_Refused("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted", None) if main
                      else _other("sshd-config:include-invalid-type"))
            raw, st = _read_regular(path, refuse)
            self.files[path] = (raw, st, _lf_lines(_text(raw)))
        return self.files[path][2]

    def _parse(self, path, depth, main, scope):
        if depth > MAX_INCLUDE_DEPTH:
            raise _other("sshd-config:include-depth")
        ident = os.path.realpath(path)
        if ident in self._stack:
            raise _other("sshd-config:include-cycle")
        self._stack.add(ident)
        template = re.compile(r"^[ \t]*#[ \t]*" + re.escape(self.lkey) + r"(?:[ \t=]|$)", re.IGNORECASE)
        for index, line in enumerate(self._load(path, main)):
            if main and scope == "GLOBAL" and self.main_template_index is None and template.match(_body(line)):
                self.main_template_index = index
            parsed = _directive(line)
            if parsed is None:
                continue
            key, rest = parsed
            # Как у CHECK: аргументы разбираются только у Match, Include и ключа контроля.
            if key not in ("match", "include", self.lkey):
                continue
            args = split_args(rest)
            if key == "match":
                if not args:
                    raise _other("sshd-config:invalid-match")
                if main and self.main_match_index is None:
                    self.main_match_index = index
                scope = "MATCH"
            elif key == "include":
                if not args:
                    raise _other("sshd-config:invalid-include")
                for pattern in args:
                    for item in _include_targets(self.root, pattern):
                        if os.path.islink(item):
                            raise _other("sshd-config:include-symlink")
                        self._parse(item, depth + 1, False, scope)
            elif key == self.lkey:
                if len(args) != 1 or "=" in args[0]:
                    raise _other("sshd-config:invalid-directive")
                self.occurrences.append((path, index, scope, main, args[0].lower()))
        self._stack.discard(ident)

    @property
    def main_global_no(self):
        return sum(1 for o in self.occurrences if o[3] and o[2] == "GLOBAL" and o[4] == EXPECTED_VALUE)

    @property
    def match_non_no(self):
        return sum(1 for o in self.occurrences if o[2] == "MATCH" and o[4] != EXPECTED_VALUE)

    def plan(self, key):
        """{путь: новые байты} по схеме 1–4; пустой план невозможен при несоответствии."""
        lines = {path: list(rec[2]) for path, rec in self.files.items()}
        changed = set()
        main_global = False
        for path, index, scope, main, value in self.occurrences:
            if scope != "GLOBAL":
                continue
            main_global = main_global or main
            if value == EXPECTED_VALUE:
                continue
            line = lines[path][index]
            m = VALUE_RE.match(_body(line))
            if m is None:
                raise _other("sshd-config:invalid-directive")
            lines[path][index] = m.group(1) + EXPECTED_VALUE + m.group(3) + _eol(line)
            changed.add(path)
        if not main_global:
            main_lines = lines[self.main]
            new_line = key + " " + EXPECTED_VALUE
            if self.main_template_index is not None:
                old = main_lines[self.main_template_index]
                main_lines[self.main_template_index] = new_line + (_eol(old) or "\n")
            elif self.main_match_index is not None:
                main_lines.insert(self.main_match_index, new_line + "\n")
            else:
                if main_lines and not _eol(main_lines[-1]):
                    main_lines[-1] += "\n"
                main_lines.append(new_line + "\n")
            changed.add(self.main)
        return {path: "".join(lines[path]).encode("utf-8", "surrogateescape") for path in sorted(changed)}


def _default_run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def _call(run, argv):
    try:
        return run(argv, TOOL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _check_tools(root, paths):
    for path in paths:
        try:
            st = os.stat(_p(root, path))
        except OSError:
            raise _other("tools:missing:" + os.path.basename(path))
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            raise _other("tools:missing:" + os.path.basename(path))


def _syntax_ok(root, run, path=None):
    """`sshd -t -f`: по умолчанию основной файл; `path` — подготовленный временный файл."""
    cp = _call(run, [_p(root, SSHD), "-t", "-f", path or _p(root, SSHD_CONFIG)])
    return cp is not None and cp.returncode == 0


def effective_settings(root, run, user="root"):
    """Действующие значения `sshd -T` для соединения `user` (ключи в нижнем регистре; повтор — None)."""
    spec = EFFECTIVE_SPEC if user == "root" else EFFECTIVE_SPEC.replace("user=root", "user=" + user, 1)
    cp = _call(run, [_p(root, SSHD), "-T", "-C", spec, "-f", _p(root, SSHD_CONFIG)])
    if cp is None or cp.returncode != 0:
        raise _other("sshd-effective:query-failed")
    try:
        out = cp.stdout.decode("utf-8") if isinstance(cp.stdout, bytes) else cp.stdout
    except UnicodeDecodeError:
        raise _other("sshd-effective:query-failed")
    values = {}
    for line in out.split("\n"):
        parts = line.rstrip("\r").split(None, 1)
        if not parts:
            continue
        name = parts[0].lower()
        values[name] = None if name in values else (parts[1].strip() if len(parts) == 2 else "")
    return values


def _effective_value(values, lkey):
    value = values.get(lkey)
    if value is None or not value or len(value.split()) != 1:
        raise _other("sshd-effective:ambiguous-value")
    return value.lower()


def policy_current(main_no, effective):
    return "main_global_no=%d;effective=%s" % (main_no, effective)


def _read_account_file(root, path, reason):
    """Строки /etc/group или /etc/passwd: обычный файл без ожидания (FIFO — отказ), UTF-8."""
    try:
        raw, _st = _read_regular(_p(root, path), _other(reason))
        return raw.decode("utf-8").split("\n")
    except (_Refused, UnicodeDecodeError):
        raise _other(reason)


def _read_groups(root):
    lines = _read_account_file(root, GROUP, "group:read-failed")
    groups = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 4:
            raise _other("group:invalid-line")
        groups.setdefault(fields[0], [m for m in fields[3].split(",") if m])
    return groups


def _read_homes(root):
    """{пользователь: (домашний каталог, uid, основной gid)} из /etc/passwd."""
    lines = _read_account_file(root, PASSWD, "passwd:read-failed")
    homes = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 7 or not re.fullmatch(r"[0-9]+", fields[2]):
            raise _other("passwd:invalid-line")
        if not re.fullmatch(r"[0-9]+", fields[3]):
            raise _other("passwd:invalid-line")
        homes.setdefault(fields[0], (fields[5], int(fields[2]), int(fields[3])))
    return homes


def _strict_ok(root, path, uid):
    """Условие StrictModes sshd для одного пути: владелец root или пользователь, без записи g/o.

    В тестовом дереве (`_root`) владельцем допускается и текущий пользователь."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    owners = {0, uid} | ({os.geteuid()} if root is not None else set())
    return st.st_uid in owners and not stat.S_IMODE(st.st_mode) & 0o022


def _user_gids(root, user, primary_gid):
    """Группы пользователя: основная и те, где он указан участником в /etc/group."""
    gids = {primary_gid}
    for line in _read_account_file(root, GROUP, "group:read-failed"):
        fields = line.split(":")
        if len(fields) == 4 and re.fullmatch(r"[0-9]+", fields[2]) and user in fields[3].split(","):
            gids.add(int(fields[2]))
    return gids


def _user_may(root, path, uid, gids, bits):
    """Может ли пользователь (uid, gids) получить доступ `bits` (4 — чтение, 1 — проход) к пути
    по битам владельца, группы или прочих — как проверит ядро при входе от его имени.

    В тестовом дереве (`_root`) объект текущего пользователя считается объектом администратора."""
    try:
        st = os.stat(path)
    except OSError:
        return False
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid == uid or (root is not None and st.st_uid == os.geteuid()):
        return bool((mode >> 6) & bits == bits)
    if st.st_gid in gids:
        return bool((mode >> 3) & bits == bits)
    return bool(mode & bits == bits)


def admin_users(groups):
    """Участники групп sudo и admin (поле участников /etc/group), кроме root."""
    users = []
    for name in SUDO_GROUPS:
        for member in groups.get(name, []):
            if member != "root" and member not in users:
                users.append(member)
    return users


MAX_SYMLINK_HOPS = 40


def _walk_path(root, path):
    """Разбор пути `path` (как его видит система; в тестовом дереве — от его корня), как при обращении ядра: по одному компоненту, со всеми переходами по
    символическим ссылкам (цель ссылки разбирается так же, от «/» или от текущего каталога).

    Возвращает (фактический путь, каталоги, через которые проходит разбор — для каждого нужен
    бит прохода) или None: объект отсутствует, петля ссылок, выход за корень тестового дерева.
    В тестовом дереве (`_root`) предки его корня не проверяются, прочие каталоги вне корня —
    отказ; в рабочей системе корень — «/»."""
    anchor = os.path.realpath(root) if root is not None else "/"
    prefix = anchor.rstrip("/") + "/"

    def inside(p):
        return p == anchor or p.startswith(prefix)

    def ancestor_of_anchor(p):
        return anchor == p or anchor.startswith(p.rstrip("/") + "/")

    pending = [part for part in path.split("/") if part]
    current, walked, hops = anchor, [], 0
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if inside(current):
            walked.append(current)
        elif not ancestor_of_anchor(current):
            return None
        if part == "..":
            current = os.path.dirname(current)
            continue
        candidate = os.path.join(current, part)
        try:
            st = os.lstat(candidate)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            hops += 1
            if hops > MAX_SYMLINK_HOPS:
                return None
            try:
                target = os.readlink(candidate)
            except OSError:
                return None
            pending = [p for p in target.split("/") if p] + pending
            if target.startswith("/"):
                current = "/"
            continue
        if pending and not stat.S_ISDIR(st.st_mode):
            return None
        current = candidate
    if not inside(current):
        return None
    return current, walked


def _strict_chain(root, path, real_home):
    """Каталоги, которые проверяет StrictModes sshd (auth_secure_path): от каталога файла вверх
    до домашнего каталога включительно, а если файл вне него — до «/» (в тестовом дереве —
    до его корня)."""
    anchor = os.path.realpath(root) if root is not None else "/"
    chain, current = [], os.path.dirname(path)
    while True:
        chain.append(current)
        if current == real_home or current == anchor or current == "/":
            return chain
        current = os.path.dirname(current)


def _has_key(root, home, uid, gids, rel, strict):
    """Пригодный ключ: непустой файл, который администратор может прочитать, пройдя по всем
    каталогам фактического пути от «/» — с разбором каждой символической ссылки по пути и
    проверкой каталогов её цели (sshd читает ключи от имени пользователя); при StrictModes —
    ещё права файла и каталогов от файла до домашнего каталога (иначе sshd ключ отвергнет).
    В тестовом дереве (`_root`) путь проверяется от его корня."""
    if not home.startswith("/") or rel.startswith("/"):
        return False
    user_path = home.rstrip("/") + "/" + rel
    resolved = _walk_path(root, user_path)
    home_resolved = _walk_path(root, home)
    if resolved is None or home_resolved is None:
        return False
    path, walked = resolved
    if not all(_user_may(root, d, uid, gids, 1) for d in walked):
        return False
    if not _user_may(root, path, uid, gids, 4):
        return False
    if strict:
        chain = _strict_chain(root, path, home_resolved[0])
        if not _strict_ok(root, path, uid) or not all(_strict_ok(root, d, uid) for d in chain):
            return False
    try:
        raw, _st = _read_regular(path, _other("keys:invalid-type"))
    except _Refused:
        return False
    return any(l.strip() and not l.strip().startswith("#")
               for l in raw.decode("utf-8", errors="replace").split("\n"))


ACCESS_RESTRICTIONS = ("allowusers", "denyusers", "allowgroups", "denygroups")


def admin_access(root, run, users):
    """Доступ администраторов по SSH: [(пользователь, ключ пригоден, пароль разрешён)] и признак
    настройки, которую механизм не проверяет.

    Всё берётся из `sshd -T` для соединения самого администратора (`Match User` учитывается).
    Непроверяемо: AllowUsers/DenyUsers/AllowGroups/DenyGroups, AuthenticationMethods, отличные
    от `any`, нестандартные AuthorizedKeysFile или PubkeyAuthentication — такой администратор
    не засчитывается.
    """
    homes = _read_homes(root)
    access, unverified = [], False
    for user in users:
        if user not in homes or not USER_NAME_RE.fullmatch(user):
            continue
        values = effective_settings(root, run, user)
        key_files = tuple((values.get("authorizedkeysfile") or "").split())
        if (any(name in values for name in ACCESS_RESTRICTIONS)
                or (values.get("authenticationmethods") or "any").lower() != "any"
                or key_files not in DEFAULT_AUTHORIZED_KEYS
                or (values.get("pubkeyauthentication") or "").lower() != "yes"):
            unverified = True
            continue
        strict = (values.get("strictmodes") or "yes").lower() != "no"
        home, uid, gid = homes[user]
        gids = _user_gids(root, user, gid)
        keyed = any(_has_key(root, home, uid, gids, rel, strict) for rel in key_files)
        password = any((values.get(name) or "").lower() == "yes"
                       for name in ("passwordauthentication", "kbdinteractiveauthentication"))
        access.append((user, keyed, password))
    return access, unverified


class _StageFailed(OSError):
    """Ошибка подготовки временного файла, после которой его не удалось удалить."""

    def __init__(self, tmp):
        super().__init__("stage failed, temporary file left: " + tmp)
        self.tmp = tmp


def _stage_file(path, raw, st):
    """Временный файл `<путь>.slp-tmp` в том же каталоге: все байты, прежние режим и владелец."""
    tmp = path + TMP_SUFFIX
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        # Сначала владелец, затем полный режим: fchown снимает SUID/SGID, fchmod их возвращает.
        if os.geteuid() == 0:
            os.fchown(fd, st.st_uid, st.st_gid)
        os.fchmod(fd, stat.S_IMODE(st.st_mode))
        os.fsync(fd)
    except BaseException as exc:
        _close_quietly(fd)
        _abandon(tmp, exc)
    try:
        os.close(fd)
    except OSError as exc:
        _abandon(tmp, exc)
    return tmp


def _abandon(tmp, exc):
    """Удаление недоготовленного временного файла и повторный подъём ошибки.

    Не удалось удалить — `_StageFailed` с путём, чтобы компенсация учла оставшийся файл.
    """
    try:
        os.unlink(tmp)
    except OSError:
        if isinstance(exc, OSError):
            raise _StageFailed(tmp) from exc
        raise exc
    raise exc


def _write_file(path, raw, st):
    """Замена файла через временный файл в том же каталоге; режим и владелец прежние.

    Ошибка замены удаляет временный файл (ошибка удаления не скрывает ошибку замены).
    """
    tmp = _stage_file(path, raw, st)
    try:
        os.replace(tmp, path)
    except OSError:
        _discard([tmp])
        raise


def _bytes_equal(path, raw):
    try:
        return _read_regular(path, _other("sshd-config:read-failed"))[0] == raw
    except (_Refused, OSError):
        return False


def _discard(paths):
    """Удаление временных файлов; True, если все удалены или отсутствуют."""
    ok = True
    for tmp in list(paths):
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        except OSError:
            ok = False
    return ok


def _reload(root, run):
    cp = _call(run, [_p(root, SYSTEMCTL), "try-reload-or-restart", SSH_UNIT])
    return cp is not None and cp.returncode == 0


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
        "target": SSHD_CONFIG,
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


def _observe(root, run, key):
    """(Config, действующее значение, все значения sshd -T)."""
    lkey = key.lower()
    try:
        cfg = Config(root, lkey)
    except _Refused as exc:
        if exc.reason == "sshd-config:untrusted":
            raise _Refused(exc.outcome, exc.reason, _admin(ACTION_FILE.format(path=SSHD_CONFIG, key=key)))
        raise
    if not _trusted(cfg.files[cfg.main][1], root):
        raise _Refused("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted",
                       _admin(ACTION_FILE.format(path=SSHD_CONFIG, key=key)))
    if cfg.match_non_no:
        raise _Refused("ABORTED_PRECONDITION_CONFLICT", "sshd-config:ambiguous-match",
                       _admin(ACTION_MATCH.format(key=key)))
    if not _syntax_ok(root, run):
        raise _other("sshd-config:validation-failed")
    values = effective_settings(root, run)
    return cfg, _effective_value(values, lkey), values


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None, _write=None, _stage=None):
    """Set `<key> no` in /etc/ssh/sshd_config in place (scheme 1–4) and reload sshd.

    `_root`, `_run`, `_write` и `_stage` — только для тестов: корень файловой системы,
    запуск команд, восстановление файла (`_write(путь, байты, stat)`) и подготовка
    временного файла (`_stage(путь, байты, stat)` -> путь временного файла).
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run
    write = _write if _write is not None else _write_file
    stage = _stage if _stage is not None else _stage_file
    current = None

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, policy_current=current, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if CONTROL_KEYS.get(control_id) != key or op != EXPECTED_OP or expected != EXPECTED_VALUE:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    try:
        actions.append("P1_OBSERVE")
        _check_tools(_root, [SSHD, SYSTEMCTL])
        cfg, effective, values = _observe(_root, run, key)
        current = policy_current(cfg.main_global_no, effective)
        if cfg.main_global_no > 0 and effective == EXPECTED_VALUE:
            return done("ALREADY_COMPLIANT")

        actions.append("P2_PLAN")
        users = admin_users(_read_groups(_root))
        if key == "PermitRootLogin" and not users:
            raise _Refused("ABORTED_PRECONDITION_CONFLICT", "ssh:no-sudo-members", _admin(ACTION_NO_SUDO))
        if key in ("PermitRootLogin", "PasswordAuthentication"):
            access, unverified = admin_access(_root, run, users)
            if key == "PasswordAuthentication":
                # После записи вход по паролю закрыт: нужен администратор с пригодным ключом.
                can_login = [user for user, keyed, _password in access if keyed]
                missing = ("ssh:no-keyed-admin", ACTION_NO_KEY)
            else:
                # После записи root не входит: нужен администратор, который войдёт сам.
                can_login = [user for user, keyed, password in access if keyed or password]
                missing = ("ssh:no-admin-login", ACTION_NO_ADMIN_LOGIN)
            if not can_login and unverified:
                raise _Refused("ABORTED_PRECONDITION_CONFLICT", "ssh:keys-setup-nondefault", _admin(ACTION_KEYS_SETUP.format(key=key)))
            if not can_login:
                raise _Refused("ABORTED_PRECONDITION_CONFLICT", missing[0], _admin(missing[1]))
        planned = cfg.plan(key)
        for path in planned:
            if not _trusted(cfg.files[path][1], _root):
                shown = SSHD_CONFIG if path == cfg.main else (
                    path if _root is None else "/" + os.path.relpath(path, _root))
                raise _Refused("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted",
                               _admin(ACTION_FILE.format(path=shown, key=key)))
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY")

        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            return done("ABORTED_PRECONDITION_OTHER", reason="privilege")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, operator_decision=exc.decision)

    written = []
    staged = {}
    reload_attempted = False

    def compensate(reason):
        actions.append("COMPENSATION")
        ok = _discard(staged.values())
        # Оставшийся временный файл в /etc/ssh — тоже изменение системы.
        left = not ok
        for path in reversed(written):
            raw, st, _lines = cfg.files[path]
            try:
                write(path, raw, st)
            except OSError as exc:
                ok = False
                if isinstance(exc, _StageFailed) and not _discard([exc.tmp]):
                    left = True
                continue
            ok = _bytes_equal(path, raw) and ok
        if reload_attempted:
            ok = _reload(_root, run) and ok
        mutated = bool(written) or left
        if ok:
            return done("FAILED_NOT_COMMITTED", reason=reason, mutation=mutated)
        return done("FAILED_COMPENSATION", reason=reason, mutation=mutated)

    # Каждый подготовленный файл проверяется `sshd -t` до замены рабочего файла:
    # основной — вместе с текущими включаемыми, включаемый — сам по себе.
    actions.append("PHASE1_STAGE")
    for path, raw in planned.items():
        try:
            staged[path] = stage(path, raw, cfg.files[path][1])
        except OSError as exc:
            if isinstance(exc, _StageFailed):
                staged[path] = exc.tmp  # учитывается компенсацией: повторное удаление
            return compensate("sshd-config:write-failed")
        if not _syntax_ok(_root, run, staged[path]):
            return compensate("sshd-config:validation-failed")
    actions.append("PHASE1_CONFIG")
    for path in planned:
        try:
            os.replace(staged[path], path)
        except OSError:
            return compensate("sshd-config:write-failed")
        del staged[path]
        written.append(path)
    if not _syntax_ok(_root, run):
        return compensate("sshd-config:validation-failed")
    actions.append("PHASE2_RELOAD")
    reload_attempted = True
    if not _reload(_root, run):
        return compensate("reload:failed")
    actions.append("FINAL_POSTCHECK")
    try:
        after, after_effective, _values = _observe(_root, run, key)
    except (_Refused, OSError):
        return compensate("postcheck:read-failed")
    current = policy_current(after.main_global_no, after_effective)
    if (any(after.files.get(path, (None,))[0] != raw for path, raw in planned.items())
            or after.main_global_no < 1 or after_effective != EXPECTED_VALUE):
        return compensate("postcheck:not-compliant")
    return done("APPLIED", mutation=True)


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
