#!/usr/bin/env python3
"""Read-only observer SRC-0055 (fstec-configuration-2026 п.1.1, таблица 2): возраст пароля
существующих учётных записей соответствует политике (не более 90 дней).

* Карта разбиения сроков паролей v6 (решения пользователя 01.10–02.10.2026): проверка политики
  компании, а не решения PAM (PAM смотрит поле 5 записи, допускает пустую и будущую дату; при
  возрасте > 90 может отказать из-за полей 7 и 8). APPLY нет: новый пароль задаёт пользователь или
  администратор.
* Популяция и разбор — как у контроля сроков (local-account-password-aging): записи с хэшем.
* Сегодня — дни от 1970-01-01 UTC по системным часам. Поле 3: пусто — date_empty, 0 — date_zero,
  больше сегодня — date_future, сегодня − поле 3 > 90 — age_over; иначе соответствует.
* VALUE `accounts=N;age_over=A;date_empty=B;date_zero=C;date_future=E`; PASS, если все четыре = 0.
"""

import re

SEMANTIC_CONTRACT_ID = "local-account-password-age-check-semantic-v1"
ADAPTER_ID = "product-local-account-password-age-check-v1"
ADAPTER_CONTRACT_VERSION = "product-local-account-password-age-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "local-account-password-age"
SUPPORTED_OPS = ("le",)
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/etc/shadow"
CANONICAL_KEY = "age-days"
CANONICAL_EXPECTED = 90
PASSWD = "/etc/passwd"
MODE = "age"
VALUE_RE = r"^accounts=[0-9]+;age_over=[0-9]+;date_empty=[0-9]+;date_zero=[0-9]+;date_future=[0-9]+$"

# Разбор — общий для двух CHECK сроков паролей и APPLY local-account-password-aging-v1 (тот же текст;
# сверяется тестом).
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

_OBSERVER = r'''import os, re, stat, sys, time

mode, passwd_path, shadow_path, owner_mode = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
''' + PARSER + r'''

def owner_ok(uid):
    return uid == 0 if owner_mode == "root" else uid == os.geteuid()


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read(path, domain):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        error(domain + ":not-found")
    except OSError:
        error(domain + ":stat-failed")
    problem = file_problem(st, owner_ok)
    if problem is not None:
        error(domain + ":" + problem)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except PermissionError:
        error(domain + ":unreadable")
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


for directory in sorted({os.path.dirname(passwd_path), os.path.dirname(shadow_path)}):
    try:
        dst = os.lstat(directory)
    except OSError:
        error("etc:stat-failed")
    problem = dir_problem(dst, owner_ok)
    if problem is not None:
        error("etc:" + problem)
passwd_raw = read(passwd_path, "passwd")
shadow_raw = read(shadow_path, "shadow")
try:
    pop = population(decode(passwd_raw, "passwd"), decode(shadow_raw, "shadow"))
except ParseError as exc:
    error(exc.reason)
if mode == "aging":
    mismatched = sum(1 for _name, fields in pop if not aging_ok(fields))
    print("VALUE\taccounts=%d;mismatched=%d\t%s" % (len(pop), mismatched, "PASS" if mismatched == 0 else "FAIL"))
else:
    today = int(time.time()) // 86400
    counts = {"age_over": 0, "date_empty": 0, "date_zero": 0, "date_future": 0}
    for _name, fields in pop:
        state = age_state(fields, today)
        if state is not None:
            counts[state] += 1
    bad = sum(counts.values())
    print("VALUE\taccounts=%d;age_over=%d;date_empty=%d;date_zero=%d;date_future=%d\t%s" % (
        len(pop), counts["age_over"], counts["date_empty"], counts["date_zero"], counts["date_future"],
        "PASS" if bad == 0 else "FAIL"))
'''


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, passwd_path=PASSWD, shadow_path=CANONICAL_LOCATOR, owner_root=True):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    for path in (passwd_path, shadow_path):
        if not isinstance(path, str) or not path.startswith("/") or any(x in path for x in "\r\n\t'"):
            raise ValueError("invalid path")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    cid = _sh_single(control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    args = (MODE, passwd_path, shadow_path, "root" if owner_root else "self")
    return "\n".join([
        fn + "() {",
        "  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra='' _slp_re=" + _sh_single(VALUE_RE),
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - "
        + " ".join(_sh_single(a) for a in args) + " <<'SLP_PW_AGE_PY'",
        _OBSERVER.rstrip("\n"),
        "SLP_PW_AGE_PY",
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
        "  if [[ $_slp_status != VALUE || ! $_slp_value =~ $_slp_re || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then",
        emit + ' "ERROR" "observer:invalid-output" "ERROR"',
        "    return 0",
        "  fi",
        emit + ' "VALUE" "$_slp_value" "$_slp_compliance"',
        "  return 0",
        "}",
        "",
    ])


def shell_function(control_id, locator, key, op, expected):
    if (locator != CANONICAL_LOCATOR or key != CANONICAL_KEY or op != "le"
            or isinstance(expected, bool) or not isinstance(expected, int) or expected != 90):
        raise ValueError("only canonical local-account-password-age contract is supported")
    return _render(control_id)


def _shell_function_for_fixture(control_id, passwd_path, shadow_path):
    """Фикстура: файлы во временном каталоге, владелец — текущий пользователь вместо root."""
    return _render(control_id, passwd_path, shadow_path, owner_root=False)


MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ", "truncate ", "dd ", "ln ",
    "mkdir ", ">>", "sed -i", "os.write", "os.replace", "os.rename", "O_WRONLY", "O_RDWR", "O_CREAT",
    "chage", "usermod", "lckpwdf",
)


def _selftest():
    src = shell_function("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "le", CANONICAL_EXPECTED)
    assert "command /usr/bin/python3 -I -S -B" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    for args in (
        ("CTRL", "/etc/passwd", CANONICAL_KEY, "le", CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, "other", "le", CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "ne", CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "le", '90'),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "le", True),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
