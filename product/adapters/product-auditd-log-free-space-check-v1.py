#!/usr/bin/env python3
"""Read-only observer SRC-0045 (fstec-logging-2025, п.5 основной части): свободное место для
журнала auditd.

* Решение пользователя 30.09.2026 (карта разбиения auditd v5/v6): контроль только CHECK — в файловой
  системе каталога /var/log/audit доступно не менее 7 GiB (7·2^30 байт; оценка на 3 месяца по замеру
  30.09.2026, серверы компании 60–100 GB). APPLY нет: размер диска — решение администратора.
* Каталога нет — берётся ближайший существующий предок (lstat). statvfs: доступно
  f_bavail × f_frsize байт (место, доступное непривилегированным процессам).
* VALUE — доступные байты (целое число); PASS при значении ≥ 7516192768, иначе FAIL; ошибка
  statvfs — ERROR auditd-log-space:statvfs-failed.
"""

import re

SEMANTIC_CONTRACT_ID = "auditd-log-free-space-check-semantic-v1"
ADAPTER_ID = "product-auditd-log-free-space-check-v1"
ADAPTER_CONTRACT_VERSION = "product-auditd-log-free-space-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "auditd-log-free-space"
SUPPORTED_OPS = ("ge",)
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/var/log/audit"
CANONICAL_KEY = "available_bytes"
THRESHOLD = 7 * 2 ** 30

_OBSERVER = r'''import os, sys

path, threshold = sys.argv[1], int(sys.argv[2])
while True:
    try:
        os.lstat(path)
        break
    except FileNotFoundError:
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    except OSError:
        print("ERROR\tauditd-log-space:stat-failed")
        raise SystemExit(0)
try:
    st = os.statvfs(path)
except OSError:
    print("ERROR\tauditd-log-space:statvfs-failed")
    raise SystemExit(0)
available = st.f_bavail * st.f_frsize
print("VALUE\t%d\t%s" % (available, "PASS" if available >= threshold else "FAIL"))
'''


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, path=CANONICAL_LOCATOR, threshold=THRESHOLD):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if not isinstance(path, str) or not path.startswith("/") or any(x in path for x in "\r\n\t'"):
        raise ValueError("invalid path")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 0:
        raise ValueError("invalid threshold")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    cid = _sh_single(control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    return "\n".join([
        fn + "() {",
        "  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - "
        + " ".join(_sh_single(a) for a in (path, str(threshold))) + " <<'SLP_AUDITD_SPACE_PY'",
        _OBSERVER.rstrip("\n"),
        "SLP_AUDITD_SPACE_PY",
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
        "  if [[ $_slp_status != VALUE || ! $_slp_value =~ ^[0-9]+$ || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then",
        emit + ' "ERROR" "observer:invalid-output" "ERROR"',
        "    return 0",
        "  fi",
        emit + ' "VALUE" "$_slp_value" "$_slp_compliance"',
        "  return 0",
        "}",
        "",
    ])


def shell_function(control_id, locator, key, op, expected):
    # Порог — только целое число (не bool, не float).
    if (locator != CANONICAL_LOCATOR or key != CANONICAL_KEY or op != "ge" or isinstance(expected, bool)
            or not isinstance(expected, int) or expected != THRESHOLD):
        raise ValueError("only canonical auditd log free space contract is supported")
    return _render(control_id)


def _shell_function_for_fixture(control_id, path, threshold):
    """Фикстура: произвольный каталог и порог."""
    return _render(control_id, path, threshold)


MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ", "truncate ", "dd ", "ln ",
    "mkdir ", ">>", "sed -i", "os.write", "os.replace", "os.rename", "O_WRONLY", "O_RDWR", "O_CREAT",
    "kill",
)


def _selftest():
    src = shell_function("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "ge", THRESHOLD)
    assert "command /usr/bin/python3 -I -S -B" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    for args in (
        ("CTRL", "/var/log", CANONICAL_KEY, "ge", THRESHOLD),
        ("CTRL", CANONICAL_LOCATOR, "size", "ge", THRESHOLD),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "eq", THRESHOLD),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "ge", 1024),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "ge", str(THRESHOLD)),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "ge", float(THRESHOLD)),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
