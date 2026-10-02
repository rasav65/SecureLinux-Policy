#!/usr/bin/env python3
"""APPLY-адаптер механизма pam-pwquality-option-v1 (fstec-configuration-2026 п.1.1; SRC-0055).

Решение пользователя 26.09.2026: пакет libpam-pwquality ставится; `minlen` не менее 12,
`ucredit`, `lcredit`, `dcredit`, `ocredit` = -1, `retry` = 3.

* Наблюдение — тот же разбор, что у CHECK `pam-pwquality-option-check-semantic-v1` (текст PARSER
  совпадает побайтно, сверяется тестом).
* Модуля нет в /etc/pam.d/common-password и пакет libpam-pwquality не установлен — сначала словарь
  cracklib (как у донора, до изменения PAM): `apt-get install cracklib-runtime wamerican`,
  `update-cracklib`, три непустых файла /var/cache/cracklib/cracklib_dict.*, проба
  `cracklib-check`; отказ любого шага — FAILED_NOT_COMMITTED, PAM не изменён. Затем
  `apt-get install libpam-pwquality` (при отказе установки — `apt-get update` и повтор); профиль
  PAM включает сам пакет (pam-auth-update). Пакет установлен, а модуль не включён — решение
  администратора. Установленный пакет не удаляется ни при каком исходе.
* Модуль включён, dictcheck не 0, а словаря cracklib нет — решение администратора (CHECK — FAIL
  <cracklib-dictionary-missing>).
* Параметр задан аргументом модуля с другим значением — решение администратора (строку
  формирует профиль pam-auth-update).
* Иначе значение пишется в /etc/security/pwquality.conf (читается после pwquality.conf.d):
  значение каждой действующей строки параметра → закомментированный шаблон `# key = …` →
  строка в конце файла. Запись — временный файл с прежними владельцем и режимом, fsync, rename;
  итоговая проверка — полное повторное наблюдение; ошибка — прежние байты файла возвращаются.
* Файл конфигурации не обычный, ссылка, не root или с записью для группы/прочих — решение
  администратора без изменений, в том числе до установки пакета.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess

ADAPTER_ID = "product-pam-pwquality-option-apply-v1"
MECHANISM_ID = "pam-pwquality-option-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "pam-pwquality-option"
COMMON_PASSWORD = "/etc/pam.d/common-password"
PWQ_CONF = "/etc/security/pwquality.conf"
PACKAGE = "libpam-pwquality"
# Механизм ставит пакеты: его контроли в APPLY выполняются первыми (генератор).
INSTALLS_PACKAGES = True
DICT_PACKAGES = ("cracklib-runtime", "wamerican")
UPDATE_CRACKLIB = "/usr/sbin/update-cracklib"
CRACKLIB_CHECK = "/usr/sbin/cracklib-check"
PROBE_WORD = b"Q7v!9mZ2#L4x8R6k"
PROBE_ERROR = re.compile(rb"no such file|error loading dictionary|cannot open|failed", re.I)
TMP_SUFFIX = ".slp-tmp"
TOOL_TIMEOUT = 60
APT_TIMEOUT = 900
DPKG_QUERY = "/usr/bin/dpkg-query"
APT_GET = "/usr/bin/apt-get"

# Совпадает с CHECK-адаптером (проверяется тестом).
SPECS = {
    "dcredit": ("eq", -1),
    "lcredit": ("eq", -1),
    "minlen": ("ge", 12),
    "ocredit": ("eq", -1),
    "retry": ("eq", 3),
    "ucredit": ("eq", -1),
}

# Разбор — общий с CHECK (product-pam-pwquality-option-check-v1.py, PARSER; сверяется тестом).
PARSER = r'''
C_SPACE = b" \t\n\v\f\r"
MAX_LINE = 1022
SETTINGS = {
    b"difok": "int", b"minlen": "int", b"dcredit": "int", b"ucredit": "int", b"lcredit": "int",
    b"ocredit": "int", b"minclass": "int", b"maxrepeat": "int", b"maxclassrepeat": "int",
    b"maxsequence": "int", b"gecoscheck": "int", b"dictcheck": "int", b"usercheck": "int",
    b"usersubstr": "int", b"enforcing": "int", b"badwords": "str", b"dictpath": "str",
    b"retry": "int", b"enforce_for_root": "set", b"local_users_only": "set",
}
DEFAULTS = {"minlen": 8, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "retry": 1,
            "dictcheck": 1}
INT_RE = re.compile(rb"[ \t\n\v\f\r]*[+-]?[0-9]+")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _int(value, reason):
    if INT_RE.fullmatch(value) is None:
        raise ParseError(reason)
    number = int(value)
    if not -2147483648 < number < 2147483647:
        raise ParseError(reason)
    return number


def conf_lines(raw):
    """[(номер строки, имя, начало значения, конец значения)] действующих строк файла, как
    read_config_file libpwquality; ошибка формата — ParseError."""
    if b"\x00" in raw:
        raise ParseError("pwquality:invalid-bytes")
    lines = raw.split(b"\n")
    if raw.endswith(b"\n"):
        lines.pop()
    result = []
    for number, line in enumerate(lines):
        if len(line) > MAX_LINE:
            raise ParseError("pwquality:line-too-long")
        end = line.find(b"#")
        if end < 0:
            end = len(line)
        while end > 0 and line[end - 1] in C_SPACE:
            end -= 1
        start = 0
        while start < end and line[start] in C_SPACE:
            start += 1
        if start == end:
            continue
        pos = start
        while pos < end and line[pos] not in C_SPACE and line[pos] != 61:
            pos += 1
        name = line[start:pos]
        eq = False
        if pos < end:
            eq = line[pos] == 61
            pos += 1
        while pos < end:
            c = line[pos]
            if c != 61 or eq:
                if c not in C_SPACE:
                    break
            else:
                eq = True
            pos += 1
        result.append((number, name, pos, end))
    return result


def apply_setting(settings, name, value, reason):
    kind = SETTINGS.get(name.lower())
    if kind is None:
        raise ParseError("pwquality:unknown-setting")
    key = name.lower().decode("ascii")
    if kind == "int":
        number = _int(value, reason)
        if key in DEFAULTS:
            settings[key] = number
    elif key == "dictpath":
        settings[key] = value


def conf_settings(files):
    """Итог чтения конфигурации: files — [(путь, байты)] в порядке libpwquality."""
    settings = {}
    for _path, raw in files:
        lines = raw.split(b"\n")
        for number, name, start, end in conf_lines(raw):
            apply_setting(settings, name, lines[number][start:end], "pwquality:invalid-integer")
    return settings


def conf_d_names(names):
    """Имена *.conf каталога pwquality.conf.d в порядке strcmp, фильтр как filter_conf."""
    chosen = []
    for name in names:
        i = name.find(b".conf")
        if i >= 0 and name[i + 5:] == b"":
            chosen.append(name)
    return sorted(chosen)


def pam_module_args(raw):
    """Аргументы единственной действующей строки password … pam_pwquality.so или None."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    found = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        module = tokens[index + 1]
        if module.rsplit(b"/", 1)[-1] != b"pam_pwquality.so":
            continue
        if tokens[1].lower() not in (b"requisite", b"required"):
            raise ParseError("pam:unsupported-control")
        args = tokens[index + 2:]
        if any(a.startswith(b"[") for a in args):
            raise ParseError("pam:unsupported-syntax")
        found.append(args)
    if len(found) > 1:
        raise ParseError("pam:ambiguous-module")
    return found[0] if found else None


def effective(key, args, settings):
    """Действующее целое значение параметра key (аргумент → конфигурация → по умолчанию)."""
    value = settings.get(key, DEFAULTS[key])
    for arg in args:
        name, sep, rest = arg.partition(b"=")
        if name.lower() == key.encode("ascii"):
            if not sep:
                raise ParseError("pam:invalid-argument")
            value = _int(rest, "pam:invalid-argument")
    if key == "minlen" and value < 6:
        value = 6
    if key == "retry" and value < 1:
        value = 1
    return value


def compliant(op, expected, value):
    return value >= expected if op == "ge" else value == expected


DICT_BASE = "/var/cache/cracklib/cracklib_dict"
DICT_MISSING = "<cracklib-dictionary-missing>"


def dictionary_required(args, settings):
    """pam_pwquality проверяет пароль по словарю cracklib: dictcheck не 0 (аргумент модуля →
    конфигурация → по умолчанию 1). Свой путь словаря (dictpath) — вне поддерживаемого состояния."""
    if "dictpath" in settings or any(a.partition(b"=")[0].lower() == b"dictpath" for a in args):
        raise ParseError("pwquality:dictpath-unsupported")
    return effective("dictcheck", args, settings) != 0


def dictionary_missing(root):
    """True — словаря cracklib нет: одного из файлов .pwd, .pwi, .hwm нет или он пуст; не обычный
    файл или ошибка lstat — ParseError."""
    missing = False
    for suffix in (".pwd", ".pwi", ".hwm"):
        try:
            st = os.lstat(root + DICT_BASE + suffix)
        except FileNotFoundError:
            missing = True
            continue
        except OSError:
            raise ParseError("cracklib:stat-failed")
        if not stat.S_ISREG(st.st_mode):
            raise ParseError("cracklib:invalid-type")
        if st.st_size == 0:
            missing = True
    return missing


def observed(key, op, expected, args, settings, root):
    """(VALUE, соответствие) при включённом модуле: словарь нужен, а его нет — DICT_MISSING, FAIL
    (pam_pwquality отвергает любой новый пароль)."""
    value = effective(key, args, settings)
    if dictionary_required(args, settings) and dictionary_missing(root):
        return DICT_MISSING, False
    return str(value), compliant(op, expected, value)
'''
exec(PARSER, globals())  # noqa: S102 — один текст разбора с CHECK

WRITE = {"dcredit": -1, "lcredit": -1, "minlen": 12, "ocredit": -1, "retry": 3, "ucredit": -1}

ACTION_FILE = ("{path} не является обычным файлом root без записи для группы и прочих: исправьте "
               "владельца и права файла или задайте {key} = {value} вручную")
ACTION_ARG = ("{key} задан аргументом pam_pwquality в /etc/pam.d/common-password со значением "
              "{current}: аргумент перекрывает pwquality.conf; исправьте профиль pam-auth-update "
              "или строку модуля вручную ({key}={value})")
ACTION_DICTIONARY = ("pam_pwquality включён, а словаря cracklib нет (/var/cache/cracklib/cracklib_dict.pwd, "
                     ".pwi, .hwm): смена пароля пользователем отвергается; установите cracklib-runtime и "
                     "wamerican и выполните update-cracklib")
ACTION_DISABLED = ("пакет libpam-pwquality установлен, но pam_pwquality не включён в "
                   "/etc/pam.d/common-password: включите профиль (pam-auth-update --enable pwquality) "
                   "или подключите модуль вручную")

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


def _other(reason):
    return _Refused("ABORTED_PRECONDITION_OTHER", reason)


def _admin(reason, action):
    return _Refused("ABORTED_PRECONDITION_CONFLICT", reason,
                    {"class": "ADMIN_ACTION_REQUIRED", "required": True, "action": action})


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not isinstance(key, str) or not isinstance(op, str):
        raise ValueError("key and op must be strings")
    if isinstance(expected, bool) or not isinstance(expected, int):
        raise ValueError("expected must be integer")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _p(root, path):
    return path if root is None else os.path.join(root, path.lstrip("/"))


def read_file(path, domain, missing_ok=False):
    """(байты, stat) обычного файла без перехода по ссылке; нет файла и missing_ok — (None, None)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        if missing_ok:
            return None, None
        raise _other(domain + ":missing")
    except OSError as exc:
        if exc.errno == 40:  # ELOOP: символическая ссылка
            raise _other(domain + ":invalid-type")
        raise _other(domain + ":open-failed")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _other(domain + ":invalid-type")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        raise _other(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks), st


def observe(root):
    """(аргументы модуля или None, настройки конфигурации, байты и stat pwquality.conf)."""
    try:
        args = pam_module_args(read_file(_p(root, COMMON_PASSWORD), "pam")[0])
        main = _p(root, PWQ_CONF)
        files = []
        try:
            names = os.listdir(os.fsencode(main + ".d"))
        except FileNotFoundError:
            names = []
        except OSError:
            raise _other("pwquality:open-failed")
        for name in conf_d_names(names):
            files.append((name, read_file(os.fsencode(main + ".d/") + name, "pwquality")[0]))
        raw, st = read_file(main, "pwquality", missing_ok=True)
        if raw is not None:
            files.append((b"main", raw))
        return args, conf_settings(files), raw, st
    except ParseError as exc:
        raise _other(exc.reason)


def arg_value(key, args):
    """Действующее значение параметра из аргументов модуля или None, если аргумента нет."""
    if not any(a.partition(b"=")[0].lower() == key.encode("ascii") for a in args):
        return None
    return effective(key, args, {})


def plan(raw, key, value):
    """Новые байты pwquality.conf: действующие строки параметра → шаблон `# key` → конец файла."""
    text = str(value).encode("ascii")
    lines = raw.split(b"\n")
    changed = False
    for number, name, start, end in conf_lines(raw):
        if name.lower() == key.encode("ascii"):
            line = lines[number]
            lines[number] = line[:start] + text + line[end:]
            changed = True
    if changed:
        return b"\n".join(lines)
    template = re.compile(rb"^#[ \t]*" + re.escape(key.encode("ascii")) + rb"[ \t]*(=|[ \t]|$)", re.I)
    for i, line in enumerate(lines):
        if template.match(line):
            lines[i] = key.encode("ascii") + b" = " + text
            return b"\n".join(lines)
    body = raw if raw.endswith(b"\n") or not raw else raw + b"\n"
    return body + key.encode("ascii") + b" = " + text + b"\n"


def _trusted(st, root):
    owner_ok = st.st_uid == 0 or (root is not None and st.st_uid == os.geteuid())
    return owner_ok and not stat.S_IMODE(st.st_mode) & 0o022


def _write(path, raw, st):
    tmp = path + TMP_SUFFIX
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fchown(fd, st.st_uid, st.st_gid)
        os.fchmod(fd, stat.S_IMODE(st.st_mode))
        os.fsync(fd)
    except OSError:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(fd)
    try:
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _default_run(argv, timeout, data=None):
    io = {"stdin": subprocess.DEVNULL} if data is None else {"input": data}
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                               "DEBIAN_FRONTEND": "noninteractive"}, **io)


def _call(run, argv, timeout=TOOL_TIMEOUT, data=None):
    try:
        return run(argv, timeout) if data is None else run(argv, timeout, data)
    except (OSError, subprocess.TimeoutExpired):
        return None


def package_installed(run, name=PACKAGE):
    cp = _call(run, [DPKG_QUERY, "-W", "-f=${Status}", name])
    if cp is None:
        raise _other("pkg:query-failed")
    if cp.returncode not in (0, 1):
        raise _other("pkg:query-failed")
    return cp.returncode == 0 and cp.stdout.strip() == b"install ok installed"


def install_packages(run, names):
    """True — все пакеты установлены после попытки; порядок: install, при отказе update и install."""
    install = [APT_GET, "-q", "-y", "-o", "DPkg::Lock::Timeout=300", "--no-install-recommends",
               "install", *names]
    cp = _call(run, install, APT_TIMEOUT)
    if cp is None or cp.returncode != 0:
        _call(run, [APT_GET, "-q", "-o", "DPkg::Lock::Timeout=300", "update"], APT_TIMEOUT)
        _call(run, install, APT_TIMEOUT)
    return all(package_installed(run, name) for name in names)


def install_package(run):
    return install_packages(run, (PACKAGE,))


def _dict_root(root):
    return "" if root is None else root


def prepare_dictionary(run, root):
    """Словарь cracklib до включения pam_pwquality: пакеты, update-cracklib, три непустых файла
    словаря, проба cracklib-check. None — словарь готов, иначе причина отказа (PAM не изменён)."""
    try:
        if not install_packages(run, DICT_PACKAGES):
            return "cracklib:install-failed"
    except _Refused:
        return "cracklib:install-failed"
    cp = _call(run, [UPDATE_CRACKLIB], APT_TIMEOUT)
    if cp is None or cp.returncode != 0:
        return "cracklib:update-failed"
    try:
        if dictionary_missing(_dict_root(root)):
            return "cracklib:dictionary-missing"
    except ParseError as exc:
        return exc.reason
    cp = _call(run, [CRACKLIB_CHECK], TOOL_TIMEOUT, PROBE_WORD + b"\n")
    if cp is None or cp.returncode != 0 or PROBE_ERROR.search(cp.stdout + cp.stderr) is not None:
        return "cracklib:probe-failed"
    return None


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
        "target": PWQ_CONF,
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


def _shown(args, value):
    return "<module-absent>" if args is None else str(value)


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None, _write_file=None):
    """Привести параметр pam_pwquality к значению политики.

    `_root`, `_run` и `_write_file` — только для тестов: корень файловой системы, запуск
    dpkg-query/apt-get и запись файла.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run
    write = _write_file if _write_file is not None else _write
    mutation = False

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, mutation=mutation, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if SPECS.get(key) != (op, expected):
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    current = None
    need_install = False
    try:
        actions.append("P1_OBSERVE")
        args, settings, raw, st = observe(_root)
        if args is not None:
            current, ok = observed(key, op, expected, args, settings, _dict_root(_root))
            if ok:
                return done("ALREADY_COMPLIANT", policy_current=current)
            if current == DICT_MISSING:
                raise _admin("cracklib:dictionary-missing", ACTION_DICTIONARY)
        else:
            current = "<module-absent>"
            if _root is None:
                _check_tools(_root, (DPKG_QUERY, APT_GET))
            if package_installed(run):
                raise _admin("pam:module-disabled", ACTION_DISABLED)
            # Недоверенный существующий pwquality.conf — отказ до
            # установки пакета, а не после неё.
            if raw is not None and not _trusted(st, _root):
                raise _admin("pwquality:untrusted", ACTION_FILE.format(path=PWQ_CONF, key=key, value=WRITE[key]))
            need_install = True
        if args is not None:
            arg = arg_value(key, args)
            if arg is not None:
                raise _admin("pam:argument-overrides",
                             ACTION_ARG.format(key=key, current=arg, value=WRITE[key]))
            if raw is None:
                raise _other("pwquality:conf-missing")
            if not _trusted(st, _root):
                raise _admin("pwquality:untrusted", ACTION_FILE.format(path=PWQ_CONF, key=key, value=WRITE[key]))
            new_raw = plan(raw, key, WRITE[key])
            if not compliant(op, expected, effective(key, args, _settings_with(_root, new_raw))):
                raise _other("pwquality:plan-not-compliant")
        actions.append("P2_PLAN")
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY", policy_current=current)
        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            raise _other("privilege")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, policy_current=current, operator_decision=exc.decision)
    except ParseError as exc:
        return done("ABORTED_PRECONDITION_OTHER", reason=exc.reason, policy_current=current)

    if need_install:
        actions.append("PHASE0_CRACKLIB_DICTIONARY")
        mutation = True
        reason = prepare_dictionary(run, _root)
        if reason is not None:
            return done("FAILED_NOT_COMMITTED", reason=reason, policy_current=current)
        actions.append("PHASE0_INSTALL_PACKAGE")
        try:
            installed = install_package(run)
        except _Refused:
            installed = False
        if not installed:
            return done("FAILED_NOT_COMMITTED", reason="pkg:install-failed", policy_current=current)
        try:
            args, settings, raw, st = observe(_root)
            if args is None:
                return done("FAILED_NOT_COMMITTED", reason="pam:module-not-enabled-after-install",
                            policy_current=current)
            current, ok = observed(key, op, expected, args, settings, _dict_root(_root))
            if ok:
                return done("APPLIED", policy_current=current)
            if current == DICT_MISSING:
                return done("FAILED_NOT_COMMITTED", reason="cracklib:dictionary-missing-after-install",
                            policy_current=current)
            if arg_value(key, args) is not None:
                return done("FAILED_NOT_COMMITTED", reason="pam:argument-overrides", policy_current=current)
            if raw is None or not _trusted(st, _root):
                return done("FAILED_NOT_COMMITTED", reason="pwquality:conf-untrusted-after-install",
                            policy_current=current)
            new_raw = plan(raw, key, WRITE[key])
        except (_Refused, ParseError):
            return done("FAILED_NOT_COMMITTED", reason="pwquality:observe-after-install-failed",
                        policy_current=current)

    actions.append("PHASE1_WRITE")
    mutation = True
    path = _p(_root, PWQ_CONF)
    reason = None
    try:
        write(path, new_raw, st)
    except OSError:
        reason = "pwquality:write-failed"
    if reason is None:
        actions.append("FINAL_POSTCHECK")
        try:
            after_args, after_settings, after_raw, _after_st = observe(_root)
            after = (None if after_args is None else
                     observed(key, op, expected, after_args, after_settings, _dict_root(_root)))
        except (_Refused, ParseError):
            reason = "pwquality:postcheck-failed"
        else:
            if after_raw == new_raw and after is not None and after[1]:
                return done("APPLIED", policy_current=after[0])
            reason = "pwquality:postcheck-failed"
    actions.append("COMPENSATION")
    try:
        now_raw, _now_st = read_file(path, "pwquality")
    except _Refused:
        now_raw = None
    if now_raw != raw:
        try:
            write(path, raw, st)
            now_raw, _now_st = read_file(path, "pwquality")
        except (OSError, _Refused):
            now_raw = None
    if now_raw == raw:
        return done("FAILED_NOT_COMMITTED", reason=reason, policy_current=current)
    return done("FAILED_COMPENSATION", reason=reason, policy_current=current)


def _check_tools(root, paths):
    for path in paths:
        try:
            st = os.stat(_p(root, path))
        except OSError:
            raise _other("tools:missing:" + os.path.basename(path))
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            raise _other("tools:missing:" + os.path.basename(path))


def _settings_with(root, new_main):
    """Настройки конфигурации, если pwquality.conf заменить на new_main (pwquality.conf.d — как есть)."""
    main = _p(root, PWQ_CONF)
    files = []
    try:
        names = os.listdir(os.fsencode(main + ".d"))
    except FileNotFoundError:
        names = []
    except OSError:
        raise _other("pwquality:open-failed")
    for name in conf_d_names(names):
        files.append((name, read_file(os.fsencode(main + ".d/") + name, "pwquality")[0]))
    files.append((b"main", new_main))
    return conf_settings(files)


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
