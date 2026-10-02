#!/usr/bin/env python3
"""Read-only observer SRC-0055 (fstec-configuration-2026 п.1.1): действующее значение параметра
pam_pwquality для смены пароля — как его получает модуль pam_pwquality (libpwquality 1.4.4/1.4.5).

* Модуль: ровно одна действующая строка `password requisite|required …/pam_pwquality.so` в
  /etc/pam.d/common-password; строки нет — VALUE <module-absent> FAIL.
* Значение: аргумент модуля (последний) → иначе последний параметр в конфигурации, читаемой как
  libpwquality: /etc/security/pwquality.conf.d/*.conf по порядку имён, затем
  /etc/security/pwquality.conf → иначе значение по умолчанию (minlen 8, *credit 0, retry 1).
  minlen ниже 6 действует как 6, retry ниже 1 — как 1.
* Ошибка чтения конфигурации (неизвестный параметр, неверное целое, слишком длинная строка)
  прерывает чтение и в libpwquality — здесь ERROR, без частичного результата.
* Словарь cracklib: модуль включён, dictcheck не 0, а одного из файлов
  /var/cache/cracklib/cracklib_dict.pwd, .pwi, .hwm нет или он пуст — VALUE
  <cracklib-dictionary-missing> FAIL: pam_pwquality отвергает любой новый пароль. Не обычный файл
  словаря и dictpath — ERROR.
"""

import re

SEMANTIC_CONTRACT_ID = "pam-pwquality-option-check-semantic-v1"
ADAPTER_ID = "product-pam-pwquality-option-check-v1"
ADAPTER_CONTRACT_VERSION = "product-pam-pwquality-option-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "pam-pwquality-option"
SUPPORTED_OPS = ("eq", "ge")
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/etc/pam.d/common-password|/etc/security/pwquality.conf"
# Значения — решение пользователя 26.09.2026 (политика компании; п.1.1 приводит minlen=15).
SPECS = {
    "dcredit": ("eq", -1),
    "lcredit": ("eq", -1),
    "minlen": ("ge", 12),
    "ocredit": ("eq", -1),
    "retry": ("eq", 3),
    "ucredit": ("eq", -1),
}
SUPPORTED_KEYS = tuple(sorted(SPECS))

# Разбор — общий с APPLY (product-pam-pwquality-option-apply-v1.py, тот же текст функций;
# сверяется тестом). Работает с байтами: libpwquality и Linux-PAM читают файлы как байты.
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

_OBSERVER = r'''import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
''' + PARSER + r'''

def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, missing_ok, domain):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        error(domain + ":missing")
    except OSError:
        error(domain + ":open-failed")
    if not stat.S_ISREG(st.st_mode):
        error(domain + ":invalid-type")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error(domain + ":open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks)


try:
    args = pam_module_args(read_regular(root + "/etc/pam.d/common-password", False, "pam"))
    if args is None:
        print("VALUE\t<module-absent>\tFAIL")
        raise SystemExit(0)
    main = root + "/etc/security/pwquality.conf"
    files = []
    try:
        names = os.listdir(os.fsencode(main + ".d"))
    except FileNotFoundError:
        names = []
    except OSError:
        error("pwquality:open-failed")
    for name in conf_d_names(names):
        files.append((name, read_regular(os.fsencode(main + ".d/") + name, False, "pwquality")))
    raw = read_regular(main, True, "pwquality")
    if raw is not None:
        files.append((b"main", raw))
    shown, ok = observed(key, op, expected, args, conf_settings(files), root)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
'''


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, key, op, expected, root=""):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if isinstance(expected, bool) or SPECS.get(key) != (op, expected):
        raise ValueError("unsupported contract fields")
    if not isinstance(root, str) or (root and not root.startswith("/")) or any(x in root for x in "\r\n\t"):
        raise ValueError("invalid root")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    cid = _sh_single(control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    return "\n".join([
        fn + "() {",
        "  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - "
        + " ".join(_sh_single(a) for a in (key, op, str(expected), root)) + " <<'SLP_PWQUALITY_PY'",
        _OBSERVER.rstrip("\n"),
        "SLP_PWQUALITY_PY",
        "  )",
        "  _slp_rc=$?",
        "  if (( _slp_rc != 0 )); then",
        emit + ' "ERROR" "observer:execution-failed" "ERROR"',
        "    return 0",
        "  fi",
        "  if [[ -z $_slp_obs || $_slp_obs == *$'\\n'* || $_slp_obs == *$'\\r'* ]]; then",
        emit + ' "ERROR" "observer:invalid-output" "ERROR"',
        "    return 0",
        "  fi",
        "  if [[ $_slp_obs == ERROR$'\\t'* ]]; then",
        emit + ' "ERROR" "${_slp_obs#ERROR$\'\\t\'}" "ERROR"',
        "    return 0",
        "  fi",
        "  IFS=$'\\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< \"$_slp_obs\"",
        "  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then",
        emit + ' "ERROR" "observer:invalid-output" "ERROR"',
        "    return 0",
        "  fi",
        emit + ' "VALUE" "$_slp_value" "$_slp_compliance"',
        "  return 0",
        "}",
        "",
    ])


def shell_function(control_id, locator, key, op, expected):
    if locator != CANONICAL_LOCATOR:
        raise ValueError("locator must be exactly " + CANONICAL_LOCATOR)
    return _render(control_id, key, op, expected)


def _shell_function_for_fixture(control_id, key, op, expected, root):
    return _render(control_id, key, op, expected, root)


MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ", "install ", "truncate ",
    "dd ", "ln ", "mkdir ", ">>", "sed -i", "os.write", "os.replace", "O_WRONLY", "O_RDWR", "apt-get",
    "pam-auth-update",
)


def _selftest():
    for key, (op, expected) in SPECS.items():
        src = shell_function("CTRL", CANONICAL_LOCATOR, key, op, expected)
        assert "command /usr/bin/python3 -I -S -B" in src
        for token in MUTATING_TOKENS:
            assert token not in src, token
    for args in (
        ("CTRL", "/etc/security/pwquality.conf", "minlen", "ge", 12),
        ("CTRL", CANONICAL_LOCATOR, "minlen", "eq", 12),
        ("CTRL", CANONICAL_LOCATOR, "minlen", "ge", 8),
        ("CTRL", CANONICAL_LOCATOR, "ucredit", "eq", "-1"),
        ("CTRL", CANONICAL_LOCATOR, "minclass", "ge", 4),
        ("CTRL", CANONICAL_LOCATOR, "retry", "eq", True),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
