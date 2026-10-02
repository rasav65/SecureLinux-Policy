#!/usr/bin/env python3
"""Read-only observer SRC-0053 (fstec-logging-2025 приложение 2, п.4): набор 25 правил таблицы 1
(без примера myapp) — в файлах /etc/audit/rules.d/*.rules и в правилах ядра (`auditctl -l`).

* Решение пользователя 30.09.2026 (вариант B): правила таблицы 1 — один контроль на весь набор.
  Карта разбиения auditd v6 (решение пользователя 01.10.2026): правило в файле — точная строка
  (без пробелов по краям) в написании таблицы 1 или в нормализованном виде `auditctl -l`; правило
  в ядре — точная строка нормализованного вида (снят разведкой 01.10.2026, среды 1–7).
* Файлы — как их отбирает augenrules: имена без начальной точки, оканчивающиеся на `.rules`.
  Каталог /etc/audit/rules.d — каталог (lstat) root без записи для группы и прочих, иначе ERROR;
  каталога нет — VALUE <rules-dir-absent> FAIL. Файл — обычный (не ссылка) root без записи для
  группы и прочих, без NUL, иначе ERROR.
* `auditctl` нет — VALUE <auditctl-absent> FAIL; `auditctl -l` с ненулевым кодом — ERROR.
* VALUE — `files=<n>/25 kernel=<m>/25`; PASS только при n = m = 25.
"""

import re

SEMANTIC_CONTRACT_ID = "auditd-rules-check-semantic-v1"
ADAPTER_ID = "product-auditd-rules-check-v1"
ADAPTER_CONTRACT_VERSION = "product-auditd-rules-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "auditd-rules"
SUPPORTED_OPS = ("eq",)
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/etc/audit/rules.d"
CANONICAL_KEY = "table1"
CANONICAL_EXPECTED = "present"
AUDITCTL = "/usr/sbin/auditctl"

# Набор и разбор — общие с APPLY (product-auditd-rules-apply-v1.py, тот же текст; сверяется тестом).
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
exec(PARSER, globals())  # noqa: S102 — один текст набора с APPLY

_OBSERVER = r'''import os, re, stat, subprocess, sys

rules_dir, auditctl = sys.argv[1], sys.argv[2]
''' + PARSER + r'''

def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def trusted(st):
    return st.st_uid == 0 and not stat.S_IMODE(st.st_mode) & 0o022


try:
    dst = os.lstat(rules_dir)
except FileNotFoundError:
    print("VALUE\t<rules-dir-absent>\tFAIL")
    raise SystemExit(0)
except OSError:
    error("auditd-rules:stat-failed")
if not stat.S_ISDIR(dst.st_mode) or not trusted(dst):
    error("auditd-rules:dir-untrusted")
if not os.path.isfile(auditctl) or not os.access(auditctl, os.X_OK):
    print("VALUE\t<auditctl-absent>\tFAIL")
    raise SystemExit(0)
try:
    names = rule_file_names(os.listdir(os.fsencode(rules_dir)))
except OSError:
    error("auditd-rules:list-failed")
lines = set()
for name in names:
    path = os.path.join(os.fsencode(rules_dir), name)
    try:
        st = os.lstat(path)
    except OSError:
        error("auditd-rules:stat-failed")
    if not stat.S_ISREG(st.st_mode):
        error("auditd-rules:invalid-type")
    if not trusted(st):
        error("auditd-rules:untrusted")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        error("auditd-rules:open-failed")
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        error("auditd-rules:read-failed")
    finally:
        os.close(fd)
    try:
        lines |= file_rule_lines(b"".join(chunks))
    except ParseError as exc:
        error(exc.reason)
try:
    res = subprocess.run([auditctl, "-l"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, timeout=60,
                        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
except (OSError, subprocess.TimeoutExpired):
    error("auditd-rules:auditctl-failed")
if res.returncode != 0:
    error("auditd-rules:auditctl-failed")
files, kernel = len(present_in_files(lines)), len(present_in_kernel(res.stdout))
total = len(RULES)
ok = files == total and kernel == total
print("VALUE\tfiles=%d/%d kernel=%d/%d\t%s" % (files, total, kernel, total, "PASS" if ok else "FAIL"))
'''


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, rules_dir=CANONICAL_LOCATOR, auditctl=AUDITCTL, owner_root=True):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    for path in (rules_dir, auditctl):
        if not isinstance(path, str) or not path.startswith("/") or any(x in path for x in "\r\n\t\'"):
            raise ValueError("invalid path")
    observer = _OBSERVER if owner_root else _OBSERVER.replace("st.st_uid == 0", "st.st_uid == os.geteuid()")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    cid = _sh_single(control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    return "\n".join([
        fn + "() {",
        "  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - "
        + " ".join(_sh_single(a) for a in (rules_dir, auditctl)) + " <<'SLP_AUDITD_RULES_PY'",
        observer.rstrip("\n"),
        "SLP_AUDITD_RULES_PY",
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
    if locator != CANONICAL_LOCATOR or key != CANONICAL_KEY or op != "eq" or expected != CANONICAL_EXPECTED:
        raise ValueError("only canonical auditd rules contract is supported")
    return _render(control_id)


def _shell_function_for_fixture(control_id, rules_dir, auditctl):
    """Фикстура: каталог во временном корне, владелец — текущий пользователь вместо root."""
    return _render(control_id, rules_dir, auditctl, owner_root=False)


# Без "dd " — подстрока правила `groupadd -p x` (граница слова проверяет генератор).
MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ", "truncate ", "ln ",
    "mkdir ", ">>", "sed -i", "os.write", "os.replace", "os.rename", "O_WRONLY", "O_RDWR", "O_CREAT",
    "kill", "augenrules", "-D", "-R",
)


def _selftest():
    src = shell_function("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "eq", CANONICAL_EXPECTED)
    assert "command /usr/bin/python3 -I -S -B" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    for args in (
        ("CTRL", "/etc/audit/audit.rules", CANONICAL_KEY, "eq", CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, "myapp", "eq", CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "eq", "absent"),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "ge", CANONICAL_EXPECTED),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
