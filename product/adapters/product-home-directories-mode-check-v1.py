#!/usr/bin/env python3
# Read-only adapter SRC-0015: selected user home-directory mode.
from __future__ import annotations
import re

ADAPTER_ID = "product-home-directories-mode-check-v1"
PARAMETER_KIND = "home-directories-mode"
TARGET_ID = "ubuntu-24.04-x86_64"
WIRE_RECORD_ID = "SLP-CHECK-V1"
CANONICAL_LOCATOR = "/etc/passwd|/etc/login.defs"
CANONICAL_PASSWD = "/etc/passwd"
CANONICAL_LOGIN_DEFS = "/etc/login.defs"
EXPECTED_MODE = "0700"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"


def _mode_compliance(mode_text, expected=EXPECTED_MODE):
    if not isinstance(mode_text, str) or re.fullmatch(r"[0-7]{3,4}", mode_text) is None:
        return None
    return int(mode_text, 8) == int(expected, 8)


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, passwd_path, login_defs_path):
    cid = _sh_single(control_id)
    passwd = _sh_single(passwd_path)
    login_defs = _sh_single(login_defs_path)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    lines = [
        fn + "() {",
        "  local _slp_passwd=" + passwd + " _slp_login_defs=" + login_defs,
        "  local _slp_expected=" + _sh_single(EXPECTED_MODE),
        "  local _slp_line _slp_body _slp_name _slp_pw _slp_uid _slp_gid _slp_gecos _slp_home _slp_shell _slp_path _slp_hex",
        "  local _slp_shell_trim _slp_shell_base _slp_home_id _slp_mode",
        "  local _slp_uid_min='' _slp_uid_min_hits=0 _slp_candidate=0",
        "  local _slp_accounts=0 _slp_homes=0 _slp_violations=0",
        "  local -a _slp_fields=()",
        "  local -A _slp_seen_homes=()",
        "",
        '  for _slp_path in "$_slp_passwd" "$_slp_login_defs"; do',
        '    if [[ ! -f "$_slp_path" || -L "$_slp_path" || ! -r "$_slp_path" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_path" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ "$_slp_hex" =~ (^|[[:space:]])00([[:space:]]|$) ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        "  done",
        "",
        '  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do',
        "    if [[ \"$_slp_line\" == *$'\\r'* ]]; then",
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_body=${_slp_line%%#*}',
        '    if [[ "$_slp_body" =~ ^[[:space:]]*UID_MIN[[:space:]]+([0-9]+)[[:space:]]*$ ]]; then',
        '      ((_slp_uid_min_hits+=1))',
        '      _slp_uid_min=${BASH_REMATCH[1]}',
        "    fi",
        '  done < "$_slp_login_defs"',
        '  if (( _slp_uid_min_hits != 1 )) || [[ -z "$_slp_uid_min" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        "",
        '  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do',
        "    if [[ -z \"$_slp_line\" || \"$_slp_line\" == *$'\\r'* ]]; then",
        '      [[ -z "$_slp_line" ]] && continue',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    IFS=: read -r -a _slp_fields <<< "$_slp_line"',
        '    if (( ${#_slp_fields[@]} != 7 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_name=${_slp_fields[0]}; _slp_pw=${_slp_fields[1]}; _slp_uid=${_slp_fields[2]}; _slp_gid=${_slp_fields[3]}',
        '    _slp_gecos=${_slp_fields[4]}; _slp_home=${_slp_fields[5]}; _slp_shell=${_slp_fields[6]}',
        '    if [[ ! "$_slp_uid" =~ ^[0-9]+$ || ! "$_slp_gid" =~ ^[0-9]+$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_shell_trim=${_slp_shell%/}; _slp_shell_base=${_slp_shell_trim##*/}',
        "    _slp_candidate=0",
        '    if [[ "$_slp_home" == /* && "$_slp_shell_base" != "nologin" && "$_slp_shell_base" != "false" ]]; then',
        '      if (( 10#$_slp_uid == 0 || (10#$_slp_uid >= 10#$_slp_uid_min && 10#$_slp_uid != 65534) )); then _slp_candidate=1; fi',
        "    fi",
        '    (( _slp_candidate == 1 )) || continue',
        '    ((_slp_accounts+=1))',
        '    if [[ ! -e "$_slp_home" && ! -L "$_slp_home" ]]; then continue; fi',
        '    if [[ -L "$_slp_home" || ! -d "$_slp_home" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if ! _slp_home_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_home" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ${_slp_seen_homes["$_slp_home_id"]+x} ]]; then continue; fi',
        '    _slp_seen_homes["$_slp_home_id"]=1',
        '    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_home" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ! "$_slp_mode" =~ ^[0-7]{3,4}$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    ((_slp_homes+=1))',
        '    if (( 8#$_slp_mode != 8#$_slp_expected )); then ((_slp_violations+=1)); fi',
        '  done < "$_slp_passwd"',
        '  if (( _slp_accounts == 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  local _slp_value="accounts=$_slp_accounts;homes=$_slp_homes;violations=$_slp_violations"',
        emit + ' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        "  return 0",
        "}",
    ]
    return "\n".join(lines) + "\n"


def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if locator != CANONICAL_LOCATOR or key != "mode" or op != "eq" or expected != EXPECTED_MODE:
        raise ValueError("unsupported SRC-0015 home-directory mode contract")
    return _render(control_id, CANONICAL_PASSWD, CANONICAL_LOGIN_DEFS)


def _shell_function_for_fixture(control_id, passwd_path, login_defs_path):
    for p in (passwd_path, login_defs_path):
        if not isinstance(p, str) or not p.startswith("/"):
            raise ValueError("absolute fixture path required")
    return _render(control_id, passwd_path, login_defs_path)


MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)


def _selftest():
    assert _mode_compliance("700") is True
    assert _mode_compliance("0700") is True
    assert _mode_compliance("0750") is False
    assert _mode_compliance("1700") is False
    assert _mode_compliance("bad") is None
    block = shell_function("CTRL.HOME.DIR", CANONICAL_LOCATOR, "mode", "eq", "0700")
    for marker in (CANONICAL_PASSWD, CANONICAL_LOGIN_DEFS, "UID_MIN", "violations="):
        assert marker in block
    for token in MUTATING_TOKENS:
        assert token not in block, token
    for args in (
        ("CTRL", "/etc/passwd", "mode", "eq", "0700"),
        ("CTRL", CANONICAL_LOCATOR, "owner", "eq", "0700"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "bits-clear", "0700"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "eq", "0750"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
