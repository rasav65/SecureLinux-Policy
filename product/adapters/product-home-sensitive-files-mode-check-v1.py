#!/usr/bin/env python3
# Read-only adapter SRC-0014: sensitive shell/history files in selected user homes.
from __future__ import annotations
import re

ADAPTER_ID = "product-home-sensitive-files-mode-check-v1"
PARAMETER_KIND = "home-sensitive-files-mode"
TARGET_ID = "ubuntu-24.04-x86_64"
WIRE_RECORD_ID = "SLP-CHECK-V1"
CANONICAL_LOCATOR = "/etc/passwd|/etc/login.defs|/etc/securelinux-policy/home-sensitive-files-v1"
CANONICAL_PASSWD = "/etc/passwd"
CANONICAL_LOGIN_DEFS = "/etc/login.defs"
CANONICAL_INVENTORY = "/etc/securelinux-policy/home-sensitive-files-v1"
EXPECTED_MASK = "0077"
MANDATORY_SOURCE_NAMES = (
    ".bash_history", ".history", ".sh_history", ".bash_profile",
    ".bashrc", ".profile", ".bash_logout", ".rhosts",
)
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"


def _mode_compliance(mode_text, expected=EXPECTED_MASK):
    if not isinstance(mode_text, str) or re.fullmatch(r"[0-7]{3,4}", mode_text) is None:
        return None
    return (int(mode_text, 8) & int(expected, 8)) == 0


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, passwd_path, login_defs_path, inventory_path):
    cid = _sh_single(control_id)
    passwd = _sh_single(passwd_path)
    login_defs = _sh_single(login_defs_path)
    inventory = _sh_single(inventory_path)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    mandatory_words = " ".join(_sh_single(x) for x in MANDATORY_SOURCE_NAMES)
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    lines = [
        fn + "() {",
        "  local _slp_passwd=" + passwd + " _slp_login_defs=" + login_defs + " _slp_inventory=" + inventory,
        "  local _slp_expected=" + _sh_single(EXPECTED_MASK),
        "  local _slp_line _slp_body _slp_entry _slp_name _slp_pw _slp_uid _slp_gid _slp_gecos _slp_home _slp_shell",
        "  local _slp_shell_trim _slp_shell_base _slp_home_id _slp_rel _slp_path _slp_cur _slp_part _slp_mode",
        "  local _slp_uid_min='' _slp_uid_min_hits=0 _slp_candidate=0 _slp_missing=0",
        "  local _slp_accounts=0 _slp_homes=0 _slp_checked=0 _slp_violations=0",
        "  local -a _slp_fields=() _slp_names=() _slp_parts=() _slp_mandatory=(" + mandatory_words + ")",
        "  local -A _slp_seen_names=() _slp_seen_homes=()",
        "",
        '  for _slp_path in "$_slp_passwd" "$_slp_login_defs" "$_slp_inventory"; do',
        '    if [[ ! -f "$_slp_path" || -L "$_slp_path" || ! -r "$_slp_path" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        "  done",
        "",
        '  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do',
        '    if [[ "$_slp_line" == *$\'\\r\'* ]]; then',
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
        '  while IFS= read -r _slp_entry || [[ -n "$_slp_entry" ]]; do',
        '    if [[ "$_slp_entry" == *$\'\\r\'* || "$_slp_entry" == *$\'\\t\'* ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    [[ -z "$_slp_entry" || "${_slp_entry:0:1}" == "#" ]] && continue',
        '    if [[ ! "$_slp_entry" =~ ^\\.[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ${_slp_seen_names["$_slp_entry"]+x} ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_seen_names["$_slp_entry"]=1',
        '    _slp_names+=("$_slp_entry")',
        '  done < "$_slp_inventory"',
        "  for _slp_entry in \"${_slp_mandatory[@]}\"; do",
        '    if [[ ! ${_slp_seen_names["$_slp_entry"]+x} ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        "  done",
        "",
        '  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do',
        '    if [[ -z "$_slp_line" || "$_slp_line" == *$\'\\r\'* ]]; then',
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
        '    if [[ -L "$_slp_home" || ! -d "$_slp_home" || ! -r "$_slp_home" || ! -x "$_slp_home" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if ! _slp_home_id=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_home" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ${_slp_seen_homes["$_slp_home_id"]+x} ]]; then continue; fi',
        '    _slp_seen_homes["$_slp_home_id"]=1',
        '    ((_slp_homes+=1))',
        '    for _slp_rel in "${_slp_names[@]}"; do',
        '      _slp_cur=$_slp_home; _slp_missing=0',
        '      IFS=/ read -r -a _slp_parts <<< "$_slp_rel"',
        '      for ((_slp_i=0; _slp_i<${#_slp_parts[@]}; _slp_i++)); do',
        '        _slp_part=${_slp_parts[$_slp_i]}; _slp_cur="$_slp_cur/$_slp_part"',
        '        if [[ -L "$_slp_cur" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "          return 0",
        "        fi",
        '        if (( _slp_i + 1 < ${#_slp_parts[@]} )); then',
        '          if [[ ! -e "$_slp_cur" ]]; then _slp_missing=1; break; fi',
        '          if [[ ! -d "$_slp_cur" || ! -x "$_slp_cur" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "            return 0",
        "          fi",
        "        fi",
        "      done",
        '      (( _slp_missing == 1 )) && continue',
        '      _slp_path=$_slp_cur',
        '      if [[ ! -e "$_slp_path" ]]; then continue; fi',
        '      if [[ -L "$_slp_path" || ! -f "$_slp_path" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        '      if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -Lc "%a" -- "$_slp_path" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        '      if [[ ! "$_slp_mode" =~ ^[0-7]{3,4}$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        '      ((_slp_checked+=1))',
        '      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi',
        "    done",
        '  done < "$_slp_passwd"',
        '  if (( _slp_accounts == 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  local _slp_value="accounts=$_slp_accounts;homes=$_slp_homes;names=${#_slp_names[@]};checked=$_slp_checked;violations=$_slp_violations"',
        emit + ' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        "  return 0",
        "}",
    ]
    # _slp_i deliberately local to generated function.
    lines[6] = lines[6] + " _slp_i=0"
    return "\n".join(lines) + "\n"


def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if locator != CANONICAL_LOCATOR or key != "mode" or op != "bits-clear" or expected != EXPECTED_MASK:
        raise ValueError("unsupported SRC-0014 home-sensitive-files contract")
    return _render(control_id, CANONICAL_PASSWD, CANONICAL_LOGIN_DEFS, CANONICAL_INVENTORY)


def _shell_function_for_fixture(control_id, passwd_path, login_defs_path, inventory_path):
    for p in (passwd_path, login_defs_path, inventory_path):
        if not isinstance(p, str) or not p.startswith("/"):
            raise ValueError("absolute fixture path required")
    return _render(control_id, passwd_path, login_defs_path, inventory_path)


MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)


def _selftest():
    assert _mode_compliance("0600") is True
    assert _mode_compliance("0700") is True
    assert _mode_compliance("0644") is False
    assert _mode_compliance("0770") is False
    assert _mode_compliance("bad") is None
    block = shell_function("CTRL.HOME", CANONICAL_LOCATOR, "mode", "bits-clear", "0077")
    for marker in (CANONICAL_PASSWD, CANONICAL_LOGIN_DEFS, CANONICAL_INVENTORY, "UID_MIN", "violations="):
        assert marker in block
    for token in MUTATING_TOKENS:
        assert token not in block, token
    bad = (
        ("CTRL", "/etc/passwd", "mode", "bits-clear", "0077"),
        ("CTRL", CANONICAL_LOCATOR, "owner", "bits-clear", "0077"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "eq", "0077"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "bits-clear", "0022"),
    )
    for args in bad:
        try:
            shell_function(*args)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
