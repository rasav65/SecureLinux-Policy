#!/usr/bin/env python3
"""Read-only observer SRC-0052 (fstec-logging-2025 приложение 2, п.3): значение параметра
/etc/audit/auditd.conf — как его читает auditd (auditd-config.c: nv_split, kw_lookup).

* Объект: обычный файл (lstat, без перехода по ссылке), владелец uid 0, без записи для группы и
  прочих; иначе ERROR. Файла нет — VALUE <file-absent> FAIL (пакет auditd не установлен).
* Разбор строки как в auditd: разделитель — только пробел, повторные пробелы пропускаются; первый
  токен с `#` — комментарий; имя ключа сравнивается без учёта регистра; строка ключа — ровно
  `ключ = значение` и не более одного дополнительного токена (опции). Строка ключа иной формы —
  ERROR auditd-conf:invalid-line.
* Файл не оканчивается переводом строки, содержит NUL или строку длиннее 158 байт — ERROR (такие
  строки auditd пропускает молча; результат зависел бы от версии).
* Действующих строк ключа нет — VALUE <absent> FAIL; больше одной — VALUE <duplicate> FAIL;
  одна — сравнение: числа (max_log_file, num_logs) — только цифры, по значению; слова (действия,
  log_format) — без учёта регистра; путь и группа — побайтно. Опция у строки — FAIL.
"""

import re

SEMANTIC_CONTRACT_ID = "auditd-conf-option-check-semantic-v1"
ADAPTER_ID = "product-auditd-conf-option-check-v1"
ADAPTER_CONTRACT_VERSION = "product-auditd-conf-option-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "auditd-conf-option"
SUPPORTED_OPS = ("eq",)
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/etc/audit/auditd.conf"
# Значения — решение пользователя 30.09.2026 (вариант B, карта разбиения auditd v5).
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
SUPPORTED_KEYS = tuple(sorted(SPECS))

# Разбор — общий с APPLY (product-auditd-conf-option-apply-v1.py, тот же текст; сверяется тестом).
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

_OBSERVER = r'''import os, re, stat, sys

key, kind, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
''' + PARSER + r'''

def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    st = os.lstat(path)
except FileNotFoundError:
    print("VALUE\t<file-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-conf:stat-failed")
if not stat.S_ISREG(st.st_mode):
    error("auditd-conf:invalid-type")
if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
    error("auditd-conf:untrusted")
try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError:
    error("auditd-conf:open-failed")
chunks = []
try:
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("auditd-conf:read-failed")
finally:
    os.close(fd)
try:
    shown, ok = observed(conf_lines(b"".join(chunks)), key, kind, expected)
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + shown + "\t" + ("PASS" if ok else "FAIL"))
'''


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, key, path=CANONICAL_LOCATOR, owner_root=True):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if key not in SPECS:
        raise ValueError("unsupported key")
    if not isinstance(path, str) or not path.startswith("/") or any(x in path for x in "\r\n\t"):
        raise ValueError("invalid path")
    kind, expected = SPECS[key]
    observer = _OBSERVER if owner_root else _OBSERVER.replace("st.st_uid != 0", "st.st_uid != os.geteuid()")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    cid = _sh_single(control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    return "\n".join([
        fn + "() {",
        "  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - "
        + " ".join(_sh_single(a) for a in (key, kind, expected, path)) + " <<'SLP_AUDITD_CONF_PY'",
        observer.rstrip("\n"),
        "SLP_AUDITD_CONF_PY",
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
    if locator != CANONICAL_LOCATOR or key not in SPECS or op != "eq" or expected != SPECS[key][1]:
        raise ValueError("only canonical auditd.conf contract is supported")
    return _render(control_id, key)


def _shell_function_for_fixture(control_id, key, path):
    """Фикстура: файл во временном каталоге, владелец — текущий пользователь вместо root."""
    return _render(control_id, key, path, owner_root=False)


MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ", "truncate ", "dd ", "ln ",
    "mkdir ", ">>", "sed -i", "os.write", "os.replace", "os.rename", "O_WRONLY", "O_RDWR", "O_CREAT",
    "kill", "SIGHUP",
)


def _selftest():
    for key, (_kind, value) in SPECS.items():
        src = shell_function("CTRL", CANONICAL_LOCATOR, key, "eq", value)
        assert "command /usr/bin/python3 -I -S -B" in src
        for token in MUTATING_TOKENS:
            assert token not in src, token
    for args in (
        ("CTRL", "/etc/audit/audit.rules", "log_format", "eq", "ENRICHED"),
        ("CTRL", CANONICAL_LOCATOR, "write_logs", "eq", "yes"),
        ("CTRL", CANONICAL_LOCATOR, "log_format", "eq", "RAW"),
        ("CTRL", CANONICAL_LOCATOR, "num_logs", "eq", 10),
        ("CTRL", CANONICAL_LOCATOR, "num_logs", "ge", "10"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
