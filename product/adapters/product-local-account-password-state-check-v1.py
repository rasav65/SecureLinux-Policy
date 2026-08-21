#!/usr/bin/env python3
"""Read-only aggregate observer for SRC-0001 local account password state."""

import re

SEMANTIC_CONTRACT_ID = "local-account-password-state-check-semantic-v1"
ADAPTER_ID = "product-local-account-password-state-check-v1"
ADAPTER_CONTRACT_VERSION = "product-local-account-password-state-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "local-account-password-state"
SUPPORTED_OPS = ("all-nonempty",)
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
EXPECTED_LOCATOR = "/etc/shadow"
EXPECTED_KEY = "password-field"
EXPECTED_VALUE = True

def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def _shell_function_for_paths(control_id, passwd_path, shadow_path, key, op, expected):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if not isinstance(passwd_path, str) or not passwd_path.startswith("/") or any(x in passwd_path for x in "\r\n\t'"):
        raise ValueError("invalid passwd path")
    if not isinstance(shadow_path, str) or not shadow_path.startswith("/") or any(x in shadow_path for x in "\r\n\t'"):
        raise ValueError("invalid shadow path")
    if key != EXPECTED_KEY or op != "all-nonempty" or expected is not True:
        raise ValueError("unsupported contract fields")

    cid = _sh_single(control_id)
    passwd = _sh_single(passwd_path)
    shadow = _sh_single(shadow_path)
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid

    lines = [
        fn + "() {",
        "  local _slp_passwd=" + passwd,
        "  local _slp_shadow=" + shadow,
        "  local _slp_line _slp_user _slp_rest _slp_pwd _slp_colons",
        "  local _slp_accounts=0 _slp_empty=0",
        "  local -a _slp_passwd_lines=() _slp_shadow_lines=()",
        "  local -A _slp_shadow_seen=() _slp_shadow_pwd=() _slp_passwd_seen=()",
        '  if [[ -L "$_slp_passwd" || -L "$_slp_shadow" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ ! -f "$_slp_passwd" || ! -f "$_slp_shadow" || ! -r "$_slp_passwd" || ! -r "$_slp_shadow" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  if ! mapfile -t _slp_shadow_lines < "$_slp_shadow"; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  if ! mapfile -t _slp_passwd_lines < "$_slp_passwd"; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  if (( ${#_slp_passwd_lines[@]} == 0 || ${#_slp_shadow_lines[@]} == 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  for _slp_line in "${_slp_shadow_lines[@]}"; do',
        '    [[ -n "$_slp_line" ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    _slp_colons=${_slp_line//[^:]/}',
        '    [[ ${#_slp_colons} -eq 8 ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    _slp_user=${_slp_line%%:*}',
        '    _slp_rest=${_slp_line#*:}',
        '    _slp_pwd=${_slp_rest%%:*}',
        '    [[ "$_slp_user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\\$?$ ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    [[ -z ${_slp_shadow_seen["$_slp_user"]+x} ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    _slp_shadow_seen["$_slp_user"]=1',
        '    _slp_shadow_pwd["$_slp_user"]=$_slp_pwd',
        "  done",
        '  for _slp_line in "${_slp_passwd_lines[@]}"; do',
        '    [[ -n "$_slp_line" ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    _slp_colons=${_slp_line//[^:]/}',
        '    [[ ${#_slp_colons} -eq 6 ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    _slp_user=${_slp_line%%:*}',
        '    [[ "$_slp_user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\\$?$ ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    [[ -z ${_slp_passwd_seen["$_slp_user"]+x} ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    _slp_passwd_seen["$_slp_user"]=1',
        '    [[ -n ${_slp_shadow_seen["$_slp_user"]+x} ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    _slp_pwd=${_slp_shadow_pwd["$_slp_user"]}',
        "    ((_slp_accounts+=1))",
        '    [[ -n "$_slp_pwd" ]] || ((_slp_empty+=1))',
        "  done",
        '  (( _slp_accounts > 0 )) || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '  if (( _slp_empty == 0 )); then',
        emit + ' "VALUE" "accounts=$_slp_accounts;empty=0" "PASS"',
        "  else",
        emit + ' "VALUE" "accounts=$_slp_accounts;empty=$_slp_empty" "FAIL"',
        "  fi",
        "  return 0",
        "}",
    ]
    return "\n".join(lines) + "\n"

def shell_function(control_id, locator, key, op, expected):
    if locator != EXPECTED_LOCATOR:
        raise ValueError("locator must be exactly /etc/shadow")
    return _shell_function_for_paths(control_id, "/etc/passwd", locator, key, op, expected)

MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ",
    "install ", "truncate ", "dd ", "sysctl -w", "setfacl ", "ln ", "mkdir ",
    ">>", "sed -i",
)

def _selftest():
    src = shell_function("CTRL", "/etc/shadow", "password-field", "all-nonempty", True)
    assert "/etc/passwd" in src and "/etc/shadow" in src
    assert "mapfile -t" in src and "accounts=" in src and "empty=" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    bad = (
        ("CTRL", "/tmp/shadow", "password-field", "all-nonempty", True),
        ("CTRL", "/etc/shadow", "password", "all-nonempty", True),
        ("CTRL", "/etc/shadow", "password-field", "eq", True),
        ("CTRL", "/etc/shadow", "password-field", "all-nonempty", False),
    )
    for args in bad:
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")

if __name__ == "__main__":
    _selftest()
