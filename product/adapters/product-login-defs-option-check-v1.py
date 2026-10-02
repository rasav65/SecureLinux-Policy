#!/usr/bin/env python3
"""Read-only observer SRC-0055 (fstec-configuration-2026 п.1.1, таблица 2): значение параметра
парольной политики в /etc/login.defs — последняя действующая строка ключа, как читает shadow-utils."""

import re

SEMANTIC_CONTRACT_ID = "login-defs-option-check-semantic-v1"
ADAPTER_ID = "product-login-defs-option-check-v1"
ADAPTER_CONTRACT_VERSION = "product-login-defs-option-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "login-defs-option"
SUPPORTED_OPS = ("eq", "one-of")
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/etc/login.defs"
# Значения — решение пользователя 26.09.2026 (политика компании в пределах таблицы 2 источника).
SPECS = {
    "ENCRYPT_METHOD": ("one-of", "SHA512|YESCRYPT"),
    "HOME_MODE": ("eq", "0700"),
    "PASS_MAX_DAYS": ("eq", "90"),
    "PASS_MIN_DAYS": ("eq", "1"),
    "PASS_WARN_AGE": ("eq", "7"),
}
SUPPORTED_KEYS = tuple(sorted(SPECS))

_PY = r'''import os, re, stat, sys

key, op, expected, path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
KEY_RE = re.compile(r"^[A-Z0-9_]+$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except FileNotFoundError:
    error("login-defs:missing")
except OSError:
    error("login-defs:open-failed")
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        error("login-defs:invalid-type")
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
except OSError:
    error("login-defs:read-failed")
finally:
    os.close(fd)
raw = b"".join(chunks)
if b"\x00" in raw:
    error("login-defs:invalid-bytes")
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError:
    error("login-defs:invalid-bytes")
# Разбор строки совпадает с APPLY (_active/current_value): разделители — только пробел и
# табуляция, один завершающий CR строки допускается; иной управляющий или пробельный
# символ в любой строке (в том числе в комментарии) — ERROR login-defs:invalid-line.
LINE_RE = re.compile(r"[ \t]*([^ \t]+)(?:[ \t]+([^ \t]+))?")
value = None
for line in text.split("\n"):
    core = line[:-1] if line.endswith("\r") else line
    for c in core:
        if (c != "\t" and (ord(c) < 32 or ord(c) == 127)) or (c.isspace() and c not in " \t"):
            error("login-defs:invalid-line")
    body = core.strip(" \t")
    if not body or body.startswith("#"):
        continue
    m = LINE_RE.match(core)
    if m.group(1) != key:
        continue
    if m.group(2) is None:
        error("login-defs:invalid-line")
    token = m.group(2)
    if len(token) >= 2 and token[0] == token[-1] == '"':
        token = token[1:-1]
    if not token:
        error("login-defs:invalid-line")
    value = token
if value is None:
    print("VALUE\t<absent>\tFAIL")
    raise SystemExit(0)
if op == "eq":
    ok = re.fullmatch(r"-?[0-9]{1,9}", value) is not None and int(value) == int(expected)
else:
    ok = value in expected.split("|")
print("VALUE\t" + value + "\t" + ("PASS" if ok else "FAIL"))
'''


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, key, op, expected, path=CANONICAL_LOCATOR):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if SPECS.get(key) != (op, expected):
        raise ValueError("unsupported contract fields")
    if not isinstance(path, str) or not path.startswith("/") or any(x in path for x in "\r\n\t"):
        raise ValueError("invalid path")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    cid = _sh_single(control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    return "\n".join([
        fn + "() {",
        "  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - " + " ".join(_sh_single(a) for a in (key, op, expected, path))
        + " <<'SLP_LOGIN_DEFS_PY'",
        _PY.rstrip("\n"),
        "SLP_LOGIN_DEFS_PY",
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
        raise ValueError("locator must be exactly /etc/login.defs")
    return _render(control_id, key, op, expected)


def _shell_function_for_fixture(control_id, key, op, expected, path):
    return _render(control_id, key, op, expected, path)


MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ", "install ", "truncate ",
    "dd ", "ln ", "mkdir ", ">>", "sed -i", "os.write", "os.replace", "O_WRONLY", "O_RDWR",
)


def _selftest():
    for key, (op, expected) in SPECS.items():
        src = shell_function("CTRL", CANONICAL_LOCATOR, key, op, expected)
        assert "command /usr/bin/python3 -I -S -B" in src
        for token in MUTATING_TOKENS:
            assert token not in src, token
    for args in (
        ("CTRL", "/etc/default/login.defs", "PASS_MAX_DAYS", "eq", "90"),
        ("CTRL", CANONICAL_LOCATOR, "PASS_MAX_DAYS", "eq", "60"),
        ("CTRL", CANONICAL_LOCATOR, "PASS_MIN_LEN", "eq", "12"),
        ("CTRL", CANONICAL_LOCATOR, "ENCRYPT_METHOD", "eq", "SHA512"),
        ("CTRL", CANONICAL_LOCATOR, "pass_max_days", "eq", "90"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
