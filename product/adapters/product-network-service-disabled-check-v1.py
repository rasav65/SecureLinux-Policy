#!/usr/bin/env python3
"""Read-only observer SRC-0098 (fstec-configuration-2026 п.11.2): служба Telnet, FTP или SNMP
отключена — известные юниты systemd не активны и не включены, порт службы не прослушивается."""

import re

SEMANTIC_CONTRACT_ID = "network-service-disabled-check-semantic-v1"
ADAPTER_ID = "product-network-service-disabled-check-v1"
ADAPTER_CONTRACT_VERSION = "product-network-service-disabled-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "network-service-disabled"
SUPPORTED_OPS = ("eq",)
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "systemd|/proc/net"
EXPECTED_VALUE = "disabled"
DEFAULT_SYSTEMCTL = "/usr/bin/systemctl"

# Известные юниты и порт каждой службы. Юнит, которого нет в системе (LoadState=not-found),
# не нарушение. Порт прослушивается процессом вне этих юнитов (например, inetd) — тоже FAIL.
SERVICES = {
    "ftp": (("vsftpd.service", "proftpd.service", "pure-ftpd.service"), (("tcp", 21),)),
    "snmp": (("snmpd.service",), (("udp", 161),)),
    "telnet": (("telnet.socket", "telnetd.socket", "telnetd.service", "inetutils-telnetd.service"), (("tcp", 23),)),
}
SUPPORTED_KEYS = tuple(sorted(SERVICES))
ACTIVE_STATES = ("active", "activating", "reloading", "refreshing")
ENABLED_STATES = ("enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "indirect")

_PY = r'''import re, subprocess, sys

key, proc_root, systemctl = sys.argv[1], sys.argv[2], sys.argv[3]
SERVICES = __SERVICES__
ACTIVE_STATES = __ACTIVE__
ENABLED_STATES = __ENABLED__
UNIT_PROPS = ("LoadState", "ActiveState", "UnitFileState")
LOCAL = re.compile(r"^[0-9A-F]+:([0-9A-F]{4})$")
STATE = re.compile(r"^[0-9A-F]{2}$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def listeners(proto, port):
    found = 0
    for suffix in ("", "6"):
        path = proc_root + "/net/" + proto + suffix
        try:
            with open(path, "rb") as stream:
                raw = stream.read()
        except FileNotFoundError:
            # Без IPv6 файла tcp6/udp6 нет; tcp/udp обязан быть.
            if suffix == "6":
                continue
            error("proc-net:read-failed")
        except OSError:
            error("proc-net:read-failed")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            error("proc-net:invalid-bytes")
        lines = text.split("\n")
        head = lines[0].split()
        # Обязательные поля заголовка: номер, локальный и удалённый адрес, состояние; у tcp6/udp6
        # удалённый адрес называется remote_address (ВМ-прогон 27.09.2026), у tcp/udp — rem_address.
        if head[:4] != ["sl", "local_address", "remote_address" if suffix == "6" else "rem_address", "st"]:
            error("proc-net:invalid-header")
        for line in lines[1:]:
            if not line.strip():
                continue
            fields = line.split()
            if len(fields) < 10:
                error("proc-net:invalid-row")
            local, state = LOCAL.fullmatch(fields[1]), fields[3]
            if local is None or STATE.fullmatch(state) is None:
                error("proc-net:invalid-row")
            if int(local.group(1), 16) != port:
                continue
            # TCP — LISTEN (0A); UDP — привязанный сокет (07).
            if state == ("0A" if proto == "tcp" else "07"):
                found += 1
    return found


def unit_state(unit):
    try:
        res = subprocess.run([systemctl, "show", "--property=" + ",".join(UNIT_PROPS), "--", unit],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=60, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        error("systemd:query-failed")
    if res.returncode != 0:
        error("systemd:query-failed")
    try:
        text = res.stdout.decode("utf-8")
    except UnicodeDecodeError:
        error("systemd:invalid-output")
    props = {}
    for line in text.split("\n"):
        if not line:
            continue
        name, sep, value = line.partition("=")
        if not sep or name not in UNIT_PROPS or name in props:
            error("systemd:invalid-output")
        props[name] = value
    if set(props) != set(UNIT_PROPS):
        error("systemd:invalid-output")
    return props["LoadState"], props["ActiveState"], props["UnitFileState"]


units, ports = SERVICES[key]
bad_units = []
for unit in units:
    load, active, file_state = unit_state(unit)
    if load in ("not-found", "masked"):
        # Юнит без файла или замаскированный — норма, только если не работает.
        if active in ACTIVE_STATES:
            bad_units.append(unit + ":" + active + "/" + (file_state or "-"))
        continue
    if load != "loaded":
        error("systemd:unit-load-" + (load if re.fullmatch(r"[a-z-]{1,32}", load) else "invalid"))
    if active in ACTIVE_STATES or file_state in ENABLED_STATES:
        bad_units.append(unit + ":" + (active or "-") + "/" + (file_state or "-"))
bad_ports = [str(port) + "/" + proto for proto, port in ports if listeners(proto, port)]
value = "units=" + (",".join(bad_units) or "-") + ";listeners=" + (",".join(bad_ports) or "-")
print("VALUE\t" + value + "\t" + ("FAIL" if bad_units or bad_ports else "PASS"))
'''
_PY = (_PY.replace("__SERVICES__", repr(SERVICES)).replace("__ACTIVE__", repr(ACTIVE_STATES))
       .replace("__ENABLED__", repr(ENABLED_STATES)))


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _validate_path(path, label):
    if not isinstance(path, str) or not path.startswith("/") or any(x in path for x in "\r\n\t"):
        raise ValueError("invalid " + label)


def _render(control_id, key, proc_root="/proc", systemctl=DEFAULT_SYSTEMCTL):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if key not in SERVICES:
        raise ValueError("unsupported key")
    _validate_path(proc_root, "proc root")
    _validate_path(systemctl, "systemctl path")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    cid = _sh_single(control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    return "\n".join([
        fn + "() {",
        "  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - " + " ".join(_sh_single(a) for a in (key, proc_root, systemctl))
        + " <<'SLP_NETWORK_SERVICE_PY'",
        _PY.rstrip("\n"),
        "SLP_NETWORK_SERVICE_PY",
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
    if locator != CANONICAL_LOCATOR or key not in SERVICES or op != "eq" or expected != EXPECTED_VALUE:
        raise ValueError("only canonical SRC-0098 network-service contract is supported")
    return _render(control_id, key)


def _shell_function_for_fixture(control_id, key, proc_root, systemctl):
    return _render(control_id, key, proc_root, systemctl)


MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ", "install ", "truncate ",
    "dd ", "ln ", "mkdir ", ">>", "sed -i", "systemctl stop", "systemctl disable", "systemctl mask",
    '"stop"', '"disable"', '"mask"', '"kill"',
)


def _selftest():
    for key in SUPPORTED_KEYS:
        src = shell_function("CTRL", CANONICAL_LOCATOR, key, "eq", EXPECTED_VALUE)
        assert "command /usr/bin/python3 -I -S -B" in src and '"show"' in src
        for token in MUTATING_TOKENS:
            assert token not in src, token
    for args in (
        ("CTRL", "/proc/net", "ftp", "eq", EXPECTED_VALUE),
        ("CTRL", CANONICAL_LOCATOR, "ssh", "eq", EXPECTED_VALUE),
        ("CTRL", CANONICAL_LOCATOR, "FTP", "eq", EXPECTED_VALUE),
        ("CTRL", CANONICAL_LOCATOR, "ftp", "contains", EXPECTED_VALUE),
        ("CTRL", CANONICAL_LOCATOR, "ftp", "eq", "masked"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
