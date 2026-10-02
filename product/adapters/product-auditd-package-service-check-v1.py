#!/usr/bin/env python3
"""Read-only observer SRC-0050 и SRC-0051 (fstec-logging-2025 приложение 2, п.1 и п.2): пакет
auditd установлен; служба auditd.service включена и запущена.

* package: `dpkg-query -W -f=${Status} auditd`; Status `install ok installed` — VALUE installed PASS;
  пакет неизвестен dpkg (код 1) или Status оканчивается на `not-installed` — VALUE not-installed FAIL;
  иной Status (например, `deinstall ok config-files`) — VALUE с этим Status, FAIL.
* service: `systemctl show --property=LoadState,ActiveState,UnitFileState -- auditd.service`;
  PASS только при LoadState=loaded, UnitFileState=enabled и ActiveState=active, VALUE
  `<UnitFileState>/<ActiveState>`; юнита нет (not-found) — VALUE not-found FAIL; замаскирован —
  VALUE masked/<ActiveState> FAIL; иной LoadState — ERROR.
* Ошибка запуска или непредусмотренный вывод dpkg-query и systemctl — ERROR, в том числе поле
  Status (want, eflag, status) или LoadState, ActiveState, UnitFileState вне закрытых перечней
  (пустой UnitFileState допустим только при LoadState=not-found).
"""

import re

SEMANTIC_CONTRACT_ID = "auditd-package-service-check-semantic-v1"
ADAPTER_ID = "product-auditd-package-service-check-v1"
ADAPTER_CONTRACT_VERSION = "product-auditd-package-service-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "auditd-package-service"
SUPPORTED_OPS = ("eq",)
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "dpkg|systemd"
PACKAGE = "auditd"
UNIT = "auditd.service"
# Ключ — ожидаемое значение (решение пользователя 30.09.2026, карта разбиения auditd v5).
SPECS = {"package": "installed", "service": "enabled-active"}
SUPPORTED_KEYS = tuple(sorted(SPECS))
DEFAULT_DPKG_QUERY = "/usr/bin/dpkg-query"
DEFAULT_SYSTEMCTL = "/usr/bin/systemctl"

# Разбор вывода — общий с APPLY (product-auditd-package-service-apply-v1.py, тот же текст;
# сверяется тестом).
PARSER = r'''
# Значения полей Status dpkg (want, eflag, status) и состояний systemd — закрытые перечни;
# иное значение — ERROR, а не несоответствие.
DPKG_WANT = ("unknown", "install", "hold", "deinstall", "purge")
DPKG_EFLAG = ("ok", "reinstreq")
DPKG_STATUS = ("not-installed", "config-files", "half-installed", "unpacked", "half-configured",
               "triggers-awaited", "triggers-pending", "installed")
UNIT_PROPS = ("LoadState", "ActiveState", "UnitFileState")
LOAD_STATES = ("loaded", "not-found", "masked", "bad-setting", "error", "merged", "stub")
ACTIVE_STATES = ("active", "reloading", "inactive", "failed", "activating", "deactivating",
                 "maintenance", "refreshing")
UNIT_FILE_STATES = ("enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked",
                    "masked-runtime", "static", "indirect", "disabled", "generated", "transient", "bad")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def package_state(rc, out):
    """(VALUE, соответствие) по коду возврата и stdout `dpkg-query -W -f=${Status}`."""
    if rc == 1 and not out:
        return "not-installed", False
    if rc != 0:
        raise ParseError("dpkg:query-failed")
    try:
        text = out.decode("ascii")
    except UnicodeDecodeError:
        raise ParseError("dpkg:invalid-output")
    parts = text.split(" ")
    if (len(parts) != 3 or parts[0] not in DPKG_WANT or parts[1] not in DPKG_EFLAG
            or parts[2] not in DPKG_STATUS):
        raise ParseError("dpkg:invalid-output")
    if text == "install ok installed":
        return "installed", True
    if text.endswith(" not-installed"):
        return "not-installed", False
    return text, False


def unit_props(rc, out):
    """(LoadState, ActiveState, UnitFileState) по выводу `systemctl show`."""
    if rc != 0:
        raise ParseError("systemd:query-failed")
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        raise ParseError("systemd:invalid-output")
    props = {}
    for line in text.split("\n"):
        if not line:
            continue
        name, sep, value = line.partition("=")
        if not sep or name not in UNIT_PROPS or name in props:
            raise ParseError("systemd:invalid-output")
        props[name] = value
    if set(props) != set(UNIT_PROPS):
        raise ParseError("systemd:invalid-output")
    load, active, file_state = props["LoadState"], props["ActiveState"], props["UnitFileState"]
    if load not in LOAD_STATES or active not in ACTIVE_STATES:
        raise ParseError("systemd:invalid-output")
    # Пустой UnitFileState допустим только у юнита без файла (not-found).
    if file_state not in UNIT_FILE_STATES and not (file_state == "" and load == "not-found"):
        raise ParseError("systemd:invalid-output")
    return load, active, file_state


def service_state(load, active, file_state):
    """(VALUE, соответствие) службы по свойствам юнита."""
    if load == "not-found":
        return "not-found", False
    if load == "masked":
        return "masked/" + active, False
    if load != "loaded":
        raise ParseError("systemd:unit-load-" + load)
    return file_state + "/" + active, file_state == "enabled" and active == "active"
'''

_OBSERVER = r'''import re, subprocess, sys

key, dpkg_query, systemctl = sys.argv[1], sys.argv[2], sys.argv[3]
''' + PARSER + r'''

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def call(argv, domain):
    try:
        res = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=60, env=ENV)
    except (OSError, subprocess.TimeoutExpired):
        error(domain + ":query-failed")
    return res.returncode, res.stdout


try:
    if key == "package":
        rc, out = call([dpkg_query, "-W", "-f=${Status}", "__PACKAGE__"], "dpkg")
        value, ok = package_state(rc, out)
    else:
        rc, out = call([systemctl, "show", "--property=" + ",".join(UNIT_PROPS), "--", "__UNIT__"],
                       "systemd")
        value, ok = service_state(*unit_props(rc, out))
except ParseError as exc:
    error(exc.reason)
print("VALUE\t" + value + "\t" + ("PASS" if ok else "FAIL"))
'''
_OBSERVER = _OBSERVER.replace("__PACKAGE__", PACKAGE).replace("__UNIT__", UNIT)


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _validate_path(path, label):
    if not isinstance(path, str) or not path.startswith("/") or any(x in path for x in "\r\n\t"):
        raise ValueError("invalid " + label)


def _render(control_id, key, dpkg_query=DEFAULT_DPKG_QUERY, systemctl=DEFAULT_SYSTEMCTL):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if key not in SPECS:
        raise ValueError("unsupported key")
    _validate_path(dpkg_query, "dpkg-query path")
    _validate_path(systemctl, "systemctl path")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    cid = _sh_single(control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    return "\n".join([
        fn + "() {",
        "  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - "
        + " ".join(_sh_single(a) for a in (key, dpkg_query, systemctl)) + " <<'SLP_AUDITD_PKG_PY'",
        _OBSERVER.rstrip("\n"),
        "SLP_AUDITD_PKG_PY",
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
    if locator != CANONICAL_LOCATOR or key not in SPECS or op != "eq" or expected != SPECS[key]:
        raise ValueError("only canonical auditd package/service contract is supported")
    return _render(control_id, key)


def _shell_function_for_fixture(control_id, key, dpkg_query, systemctl):
    return _render(control_id, key, dpkg_query, systemctl)


MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ", "truncate ", "dd ", "ln ",
    "mkdir ", ">>", "sed -i", "apt-get", "dpkg -i", "dpkg --install", '"start"', '"enable"', '"stop"',
    '"disable"', '"mask"', '"unmask"', "systemctl start", "systemctl enable",
)


def _selftest():
    for key, value in SPECS.items():
        src = shell_function("CTRL", CANONICAL_LOCATOR, key, "eq", value)
        assert "command /usr/bin/python3 -I -S -B" in src
        for token in MUTATING_TOKENS:
            assert token not in src, token
    for args in (
        ("CTRL", "systemd", "service", "eq", "enabled-active"),
        ("CTRL", CANONICAL_LOCATOR, "unit", "eq", "enabled-active"),
        ("CTRL", CANONICAL_LOCATOR, "package", "eq", "enabled-active"),
        ("CTRL", CANONICAL_LOCATOR, "service", "eq", "installed"),
        ("CTRL", CANONICAL_LOCATOR, "package", "contains", "installed"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
