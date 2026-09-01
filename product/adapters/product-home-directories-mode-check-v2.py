#!/usr/bin/env python3
# Read-only adapter SRC-0015 v2: exact mode for all local user home directories.
from __future__ import annotations
import re

ADAPTER_ID = "product-home-directories-mode-check-v2"
ADAPTER_CONTRACT_VERSION = "product-home-directories-mode-check-adapter-v2"
SEMANTIC_CONTRACT_ID = "home-directories-mode-check-semantic-v2"
PARAMETER_KIND = "home-directories-mode"
TARGET_ID = "linux-x86_64-supported-v1"
WIRE_RECORD_ID = "SLP-CHECK-V1"
CANONICAL_LOCATOR = "/etc/passwd"
CANONICAL_PASSWD = "/etc/passwd"
EXPECTED_MODE = "0700"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"


def _mode_compliance(mode_text, expected=EXPECTED_MODE):
    if not isinstance(mode_text, str) or re.fullmatch(r"[0-7]{3,4}", mode_text) is None:
        return None
    return int(mode_text, 8) == int(expected, 8)


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, passwd_path):
    cid = _sh_single(control_id); passwd = _sh_single(passwd_path)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    lines = [
        fn + "() {",
        "  local _slp_passwd=" + passwd + " _slp_expected=" + _sh_single(EXPECTED_MODE),
        "  local _slp_line _slp_name _slp_uid _slp_gid _slp_home _slp_home_id _slp_mode _slp_hex",
        "  local _slp_accounts=0 _slp_homes=0 _slp_violations=0",
        "  local -a _slp_fields=()",
        "  local -A _slp_seen_users=() _slp_seen_homes=()",
        '  if [[ -L "$_slp_passwd" ]]; then',
        emit + ' "ERROR" "passwd:symlink" "ERROR"',
        '    return 0',
        '  fi',
        '  if [[ ! -e "$_slp_passwd" ]]; then',
        emit + ' "ERROR" "passwd:not-found" "ERROR"',
        '    return 0',
        '  fi',
        '  if [[ ! -f "$_slp_passwd" ]]; then',
        emit + ' "ERROR" "passwd:invalid-type" "ERROR"',
        '    return 0',
        '  fi',
        '  if [[ ! -r "$_slp_passwd" ]]; then',
        emit + ' "ERROR" "passwd:unreadable" "ERROR"',
        '    return 0',
        '  fi',
        '  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_passwd" 2>/dev/null); then',
        emit + ' "ERROR" "passwd:read-failed" "ERROR"',
        '    return 0',
        '  fi',
        '  if [[ "$_slp_hex" =~ (^|[[:space:]])(00|0d)([[:space:]]|$) ]]; then',
        emit + ' "ERROR" "passwd:invalid-bytes" "ERROR"',
        '    return 0',
        '  fi',
        '  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do',
        '    [[ -n "$_slp_line" ]] || continue',
        '    IFS=: read -r -a _slp_fields <<< "$_slp_line"',
        '    (( ${#_slp_fields[@]} == 7 )) || { ' + emit.strip() + ' "ERROR" "passwd:invalid-fields" "ERROR"; return 0; }',
        '    _slp_name=${_slp_fields[0]}; _slp_uid=${_slp_fields[2]}; _slp_gid=${_slp_fields[3]}; _slp_home=${_slp_fields[5]}',
        '    [[ "$_slp_name" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\\$?$ && "$_slp_uid" =~ ^[0-9]+$ && "$_slp_gid" =~ ^[0-9]+$ ]] || { ' + emit.strip() + ' "ERROR" "passwd:invalid-account" "ERROR"; return 0; }',
        '    [[ -z ${_slp_seen_users["$_slp_name"]+x} ]] || { ' + emit.strip() + ' "ERROR" "passwd:duplicate-account" "ERROR"; return 0; }',
        '    _slp_seen_users["$_slp_name"]=1',
        '    [[ "$_slp_home" == /* ]] || { ' + emit.strip() + ' "ERROR" "passwd:invalid-home" "ERROR"; return 0; }',
        '    ((_slp_accounts+=1))',
        '    if [[ ! -e "$_slp_home" && ! -L "$_slp_home" ]]; then continue; fi',
        '    if [[ -L "$_slp_home" ]]; then',
        emit + ' "ERROR" "home:symlink" "ERROR"',
        '      return 0',
        '    fi',
        '    if [[ ! -d "$_slp_home" ]]; then',
        emit + ' "ERROR" "home:invalid-type" "ERROR"',
        '      return 0',
        '    fi',
        '    if ! _slp_home_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_home" 2>/dev/null); then',
        emit + ' "ERROR" "home:identity-failed" "ERROR"',
        '      return 0',
        '    fi',
        '    if [[ ${_slp_seen_homes["$_slp_home_id"]+x} ]]; then continue; fi',
        '    _slp_seen_homes["$_slp_home_id"]=1',
        '    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_home" 2>/dev/null); then',
        emit + ' "ERROR" "home:mode-read-failed" "ERROR"',
        '      return 0',
        '    fi',
        '    [[ "$_slp_mode" =~ ^[0-7]{3,4}$ ]] || { ' + emit.strip() + ' "ERROR" "home:invalid-mode" "ERROR"; return 0; }',
        '    ((_slp_homes+=1))',
        '    if (( 8#$_slp_mode != 8#$_slp_expected )); then ((_slp_violations+=1)); fi',
        '  done < "$_slp_passwd"',
        '  (( _slp_accounts > 0 )) || { ' + emit.strip() + ' "ERROR" "passwd:empty-population" "ERROR"; return 0; }',
        '  local _slp_value="accounts=$_slp_accounts;homes=$_slp_homes;violations=$_slp_violations"',
        emit + ' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        '  return 0',
        '}',
    ]
    return "\n".join(lines) + "\n"


def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if locator != CANONICAL_LOCATOR or key != "mode" or op != "eq" or expected != EXPECTED_MODE:
        raise ValueError("unsupported SRC-0015 home-directory mode contract")
    return _render(control_id, CANONICAL_PASSWD)


def _shell_function_for_fixture(control_id, passwd_path):
    if not isinstance(passwd_path, str) or not passwd_path.startswith("/"):
        raise ValueError("absolute fixture path required")
    return _render(control_id, passwd_path)


MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)


def _selftest():
    assert _mode_compliance("700") is True and _mode_compliance("0755") is False
    block = shell_function("CTRL.HOME.DIR", CANONICAL_LOCATOR, "mode", "eq", "0700")
    assert CANONICAL_PASSWD in block and "UID_MIN" not in block and "nologin" not in block
    for token in MUTATING_TOKENS:
        assert token not in block, token
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
