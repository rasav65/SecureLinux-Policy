#!/usr/bin/env python3
"""Read-only observer SRC-0056 (fstec-configuration-2026 п.1.2): запрет повторного использования
паролей — pam_pwhistory remember=5 в стеке password /etc/pam.d/common-password.

Решение пользователя 27.09.2026: принимаются только эталонные стеки password, перечисленные явно
и подтверждённые журналами семи сред (PARSER, STACKS):
* чистая установка и стек после APPLY п.1.1 (pam_pwquality) — VALUE <module-absent> FAIL;
* стек со строкой `requisite pam_pwhistory.so remember=5 retry=1 use_authtok` между pam_pwquality
  и pam_unix — VALUE 5 PASS, если /etc/security/pwhistory.conf и /usr/etc/security/pwhistory.conf
  (запасной путь поставщика) отсутствуют или не содержат действующих строк; действующая строка
  или не обычный файл — ERROR;
* иной стек (сравнение по словам строк password) — ERROR pam:unsupported-stack.
"""

import re

SEMANTIC_CONTRACT_ID = "pam-pwhistory-remember-check-semantic-v1"
ADAPTER_ID = "product-pam-pwhistory-remember-check-v1"
ADAPTER_CONTRACT_VERSION = "product-pam-pwhistory-remember-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "pam-pwhistory-remember"
SUPPORTED_OPS = ("ge",)
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/etc/pam.d/common-password"
# Значение — решение пользователя 26.09.2026 (pam_pwhistory remember=5; п.1.1 таблица 1: не менее 5–10).
SPECS = {"remember": ("ge", 5)}
# Эталонная строка задаёт remember=5; другое значение политики потребует нового эталона.
assert SPECS["remember"] == ("ge", 5)
SUPPORTED_KEYS = tuple(sorted(SPECS))

# Разбор — общий с APPLY (product-pam-pwhistory-profile-apply-v1.py, тот же текст; сверяется тестом).
PARSER = r'''
C_SPACE = b" \t\n\v\f\r"
REF_PWQ = (b"requisite", b"pam_pwquality.so", (b"retry=3",))
REF_HIST = (b"requisite", b"pam_pwhistory.so", (b"remember=5", b"retry=1", b"use_authtok"))
REF_UNIX_CLEAN = (b"[success=1 default=ignore]", b"pam_unix.so", (b"obscure", b"yescrypt"))
REF_UNIX = (b"[success=1 default=ignore]", b"pam_unix.so", (b"obscure", b"use_authtok", b"try_first_pass", b"yescrypt"))
REF_TAIL = ((b"requisite", b"pam_deny.so", ()), (b"required", b"pam_permit.so", ()))
# Эталонные стеки password /etc/pam.d/common-password — подтверждены журналами семи сред
# (ВМ-прогон 27.09.2026, runner v21): чистая установка; после APPLY п.1.1 (pam_pwquality);
# после APPLY п.1.2 (профиль securelinux-pwhistory). Иной стек — вне поддерживаемого состояния.
STACKS = {
    (REF_UNIX_CLEAN,) + REF_TAIL: "clean",
    (REF_PWQ, REF_UNIX) + REF_TAIL: "pwquality",
    (REF_PWQ, REF_HIST, REF_UNIX) + REF_TAIL: "enabled",
}
REMEMBER = 5
CONF_PATHS = ("/etc/security/pwhistory.conf", "/usr/etc/security/pwhistory.conf")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def password_lines(raw):
    """[(тип, управление, модуль, аргументы)] действующих строк password файла PAM, по порядку."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    result = []
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
        result.append((tokens[0], b" ".join(tokens[1:index + 1]), tokens[index + 1], tuple(tokens[index + 2:])))
    return result


def stack_state(raw):
    """"clean", "pwquality" или "enabled" — эталонный стек password; иной — ParseError."""
    lines = password_lines(raw)
    if any(line[0] != b"password" for line in lines):
        raise ParseError("pam:unsupported-stack")
    state = STACKS.get(tuple(line[1:] for line in lines))
    if state is None:
        raise ParseError("pam:unsupported-stack")
    return state


def conf_active(raw):
    """True — в pwhistory.conf есть действующая строка (как pam_modutil_search_key: '#' отрезает
    комментарий, ведущие пробельные символы пропускаются, пустая строка не действует)."""
    for line in raw.split(b"\n"):
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        if line.lstrip(C_SPACE):
            return True
    return False
'''

_OBSERVER = r'''import os, re, stat, sys

key, op, expected, root = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
''' + PARSER + r'''

def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_regular(path, domain, missing_ok):
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
    state = stack_state(read_regular(root + "/etc/pam.d/common-password", "pam", False))
except ParseError as exc:
    error(exc.reason)
if state != "enabled":
    print("VALUE\t<module-absent>\tFAIL")
    raise SystemExit(0)
for conf in CONF_PATHS:
    raw = read_regular(root + conf, "pwhistory-conf", True)
    if raw is not None and conf_active(raw):
        error("pwhistory-conf:active-lines")
print("VALUE\t" + str(REMEMBER) + "\t" + ("PASS" if REMEMBER >= expected else "FAIL"))
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
        + " ".join(_sh_single(a) for a in (key, op, str(expected), root)) + " <<'SLP_PWHISTORY_PY'",
        _OBSERVER.rstrip("\n"),
        "SLP_PWHISTORY_PY",
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
    "pam-auth-update", "useradd", "chpasswd",
)


def _selftest():
    for key, (op, expected) in SPECS.items():
        src = shell_function("CTRL", CANONICAL_LOCATOR, key, op, expected)
        assert "command /usr/bin/python3 -I -S -B" in src
        for token in MUTATING_TOKENS:
            assert token not in src, token
    for args in (
        ("CTRL", "/etc/pam.d/common-auth", "remember", "ge", 5),
        ("CTRL", CANONICAL_LOCATOR, "remember", "eq", 5),
        ("CTRL", CANONICAL_LOCATOR, "remember", "ge", 4),
        ("CTRL", CANONICAL_LOCATOR, "retry", "ge", 5),
        ("CTRL", CANONICAL_LOCATOR, "remember", "ge", "5"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
