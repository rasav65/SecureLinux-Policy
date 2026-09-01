#!/usr/bin/env python3
"""Read-only source-faithful observer for SRC-0002 SSH root login."""

import re

SEMANTIC_CONTRACT_ID = "sshd-root-login-check-semantic-v1"
ADAPTER_ID = "product-sshd-root-login-check-v1"
ADAPTER_CONTRACT_VERSION = "product-sshd-root-login-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "sshd-root-login"
SUPPORTED_OPS = ("eq",)
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
EXPECTED_LOCATOR = "/etc/ssh/sshd_config"
EXPECTED_KEY = "PermitRootLogin"
EXPECTED_VALUE = "no"
DEFAULT_SSHD = "/usr/sbin/sshd"


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _validate_path(path, label):
    if not isinstance(path, str) or not path.startswith("/") or any(x in path for x in "\r\n\t"):
        raise ValueError("invalid " + label)


def _shell_function_for_fixture(control_id, config_path, sshd_path, key, op, expected, sort_path="/usr/bin/sort"):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    _validate_path(config_path, "config path")
    _validate_path(sshd_path, "sshd path")
    _validate_path(sort_path, "sort path")
    if key != EXPECTED_KEY or op != "eq" or expected != EXPECTED_VALUE:
        raise ValueError("unsupported contract fields")

    cid = _sh_single(control_id)
    cfg = _sh_single(config_path)
    sshd = _sh_single(sshd_path)
    sort = _sh_single(sort_path)
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid

    lines = [
        fn + "() {",
        "  local LC_ALL=C",
        "  local _slp_cfg=" + cfg,
        "  local _slp_sshd=" + sshd,
        "  local _slp_sort=" + sort,
        "  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0",
        "  local _slp_real _slp_line _slp_effective",
        "  local -a _slp_effective_lines=()",
        "  local -A _slp_stack=()",
        "  if [[ -L \"$_slp_cfg\" ]]; then",
        emit + ' "ERROR" "sshd-config:symlink" "ERROR"',
        "    return 0",
        "  fi",
        "  if [[ ! -e \"$_slp_cfg\" ]]; then",
        emit + ' "NOT_FOUND" "-" "FAIL"',
        "    return 0",
        "  fi",
        "  if [[ ! -f \"$_slp_cfg\" ]]; then",
        emit + ' "ERROR" "sshd-config:invalid-type" "ERROR"',
        "    return 0",
        "  fi",
        "  if [[ ! -r \"$_slp_cfg\" ]]; then",
        emit + ' "ERROR" "sshd-config:unreadable" "ERROR"',
        "    return 0",
        "  fi",
        "  [[ -x /usr/bin/readlink ]] || { " + emit.strip() + ' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }',
        "  [[ -x /usr/bin/find ]] || { " + emit.strip() + ' "ERROR" "tool:find-missing" "ERROR"; return 0; }',
        "  [[ -x \"$_slp_sort\" ]] || { " + emit.strip() + ' "ERROR" "tool:sort-missing" "ERROR"; return 0; }',
        "  if [[ -L \"$_slp_sshd\" ]]; then",
        "    _slp_real=$(command /usr/bin/readlink -f -- \"$_slp_sshd\" 2>/dev/null) || _slp_real=",
        "    [[ -n \"$_slp_real\" ]] || { " + emit.strip() + ' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }',
        "    _slp_sshd=$_slp_real",
        "  fi",
        "  if [[ ! -e \"$_slp_sshd\" ]]; then",
        emit + ' "NOT_FOUND" "-" "FAIL"',
        "    return 0",
        "  fi",
        "  if [[ ! -f \"$_slp_sshd\" ]]; then",
        emit + ' "ERROR" "sshd-binary:invalid-type" "ERROR"',
        "    return 0",
        "  fi",
        "  if [[ ! -x \"$_slp_sshd\" ]]; then",
        emit + ' "ERROR" "sshd-binary:not-executable" "ERROR"',
        "    return 0",
        "  fi",
        "  _slp_split_args() {",
        "    local _slp_s=$1 _slp_i=0 _slp_n=${#1} _slp_c _slp_q= _slp_t= _slp_next",
        "    _slp_args=()",
        "    while (( _slp_i < _slp_n )); do",
        "      while (( _slp_i < _slp_n )); do",
        "        _slp_c=${_slp_s:_slp_i:1}",
        "        [[ \"$_slp_c\" == ' ' || \"$_slp_c\" == $'\\t' || \"$_slp_c\" == $'\\r' ]] || break",
        "        ((_slp_i+=1))",
        "      done",
        "      (( _slp_i < _slp_n )) || return 0",
        "      _slp_c=${_slp_s:_slp_i:1}",
        "      [[ \"$_slp_c\" != '#' ]] || return 0",
        "      _slp_t= _slp_q=",
        "      while (( _slp_i < _slp_n )); do",
        "        _slp_c=${_slp_s:_slp_i:1}",
        "        if [[ -n \"$_slp_q\" ]]; then",
        "          if [[ \"$_slp_c\" == \"$_slp_q\" ]]; then _slp_q=; ((_slp_i+=1)); continue; fi",
        "          if [[ \"$_slp_c\" == '\\\\' && $((_slp_i + 1)) -lt _slp_n ]]; then",
        "            _slp_next=${_slp_s:_slp_i+1:1}",
        "            if [[ \"$_slp_next\" == \"'\" || \"$_slp_next\" == '\"' || \"$_slp_next\" == '\\\\' ]]; then",
        "              _slp_t+=\"$_slp_next\"; ((_slp_i+=2)); continue",
        "            fi",
        "          fi",
        "          _slp_t+=\"$_slp_c\"; ((_slp_i+=1)); continue",
        "        fi",
        "        if [[ \"$_slp_c\" == '\"' || \"$_slp_c\" == \"'\" ]]; then _slp_q=$_slp_c; ((_slp_i+=1)); continue; fi",
        "        if [[ \"$_slp_c\" == ' ' || \"$_slp_c\" == $'\\t' || \"$_slp_c\" == $'\\r' ]]; then break; fi",
        "        if [[ \"$_slp_c\" == '\\\\' && $((_slp_i + 1)) -lt _slp_n ]]; then",
        "          _slp_next=${_slp_s:_slp_i+1:1}",
        "          if [[ \"$_slp_next\" == \"'\" || \"$_slp_next\" == '\"' || \"$_slp_next\" == '\\\\' || \"$_slp_next\" == ' ' ]]; then",
        "            _slp_t+=\"$_slp_next\"; ((_slp_i+=2)); continue",
        "          fi",
        "        fi",
        "        _slp_t+=\"$_slp_c\"; ((_slp_i+=1))",
        "      done",
        "      [[ -z \"$_slp_q\" ]] || return 2",
        "      _slp_args+=(\"$_slp_t\")",
        "    done",
        "    return 0",
        "  }",
        "  _slp_validate_sshd_bytes() {",
        "    local _slp_v_path=$1 _slp_v_hex _slp_v_byte _slp_v_prev=''",
        '    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi',
        "    for _slp_v_byte in $_slp_v_hex; do",
        '      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1',
        '      [[ "$_slp_v_byte" != 00 ]] || return 1',
        '      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi',
        "      _slp_v_prev=$_slp_v_byte",
        "    done",
        '    [[ "$_slp_v_prev" != 0d ]] || return 1',
        "    return 0",
        "  }",
        "  _slp_parse_sshd_file() {",
        "    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4",
        "    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0",
        "    local -a _slp_args=() _slp_glob=()",
        "    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }",
        "    [[ ! -L \"$_slp_pf\" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }",
        "    [[ -e \"$_slp_pf\" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }",
        "    [[ -f \"$_slp_pf\" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }",
        "    [[ -r \"$_slp_pf\" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }",
        '    _slp_validate_sshd_bytes "$_slp_pf"; _slp_vrc=$?',
        "    if (( _slp_vrc != 0 )); then",
        "      _slp_parser_error=1",
        "      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi",
        "      return 0",
        "    fi",
        "    _slp_pr=$(command /usr/bin/readlink -f -- \"$_slp_pf\" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }",
        "    [[ -n \"$_slp_pr\" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }",
        "    [[ -z ${_slp_stack[\"$_slp_pr\"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }",
        "    _slp_stack[\"$_slp_pr\"]=1",
        "    while IFS= read -r _slp_pl || [[ -n \"$_slp_pl\" ]]; do",
        "      _slp_pl=${_slp_pl%$'\\r'}",
        "      [[ \"$_slp_pl\" =~ [^[:space:]] ]] || continue",
        "      [[ ! \"$_slp_pl\" =~ ^[[:space:]]*# ]] || continue",
        "      if [[ \"$_slp_pl\" =~ ^[[:space:]]*([^[:space:]=]+)([[:space:]]*=[[:space:]]*|[[:space:]]+)(.*)$ ]]; then",
        "        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=${BASH_REMATCH[3]}",
        "      elif [[ \"$_slp_pl\" =~ ^[[:space:]]*([^[:space:]=]+)[[:space:]]*$ ]]; then",
        "        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=",
        "      else",
        "        continue",
        "      fi",
        "      [[ \"$_slp_pk\" == match || \"$_slp_pk\" == include || \"$_slp_pk\" == permitrootlogin ]] || continue",
        "      _slp_split_args \"$_slp_rest\" || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-arguments; break; }",
        "      if [[ \"$_slp_pk\" == match ]]; then",
        "        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-match; break; }",
        "        _slp_scope=MATCH",
        "        continue",
        "      fi",
        "      if [[ \"$_slp_pk\" == include ]]; then",
        "        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-include; break; }",
        "        for _slp_pp in \"${_slp_args[@]}\"; do",
        "          if [[ \"$_slp_pp\" == /* ]]; then _slp_px=$_slp_pp; else _slp_px=/etc/ssh/$_slp_pp; fi",
        "          _slp_glob=()",
        "          if [[ \"$_slp_px\" == *'*'* || \"$_slp_px\" == *'?'* || \"$_slp_px\" == *'['* ]]; then",
        "            _slp_prefix=${_slp_px%%[\\*\\?\\[]*}",
        "            _slp_prefix=${_slp_prefix%/*}",
        "            [[ -n \"$_slp_prefix\" ]] || _slp_prefix=/",
        "            if [[ -e \"$_slp_prefix\" ]]; then",
        "              [[ ! -L \"$_slp_prefix\" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-symlink; break 2; }",
        "              [[ -d \"$_slp_prefix\" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-invalid-type; break 2; }",
        "              _slp_nl=$(command /usr/bin/find \"$_slp_prefix\" -name $'*\\n*' -print -quit 2>/dev/null)",
        "              _slp_grc=$?",
        "              (( _slp_grc == 0 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-scan-failed; break 2; }",
        "              [[ -z \"$_slp_nl\" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-newline-name; break 2; }",
        "            fi",
        "            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G \"$_slp_px\" | LC_ALL=C command \"$_slp_sort\" ) )",
        "            _slp_grc=$?",
        "            if (( _slp_grc == 0 )); then",
        "              while IFS= read -r _slp_item; do [[ -n \"$_slp_item\" ]] && _slp_glob+=(\"$_slp_item\"); done <<< \"$_slp_glob_text\"",
        "            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi",
        "          elif [[ -e \"$_slp_px\" || -L \"$_slp_px\" ]]; then",
        "            _slp_glob=(\"$_slp_px\")",
        "          fi",
        "          for _slp_item in \"${_slp_glob[@]}\"; do",
        "            _slp_parse_sshd_file \"$_slp_item\" $((_slp_pd + 1)) 0 \"$_slp_scope\"",
        "            (( _slp_parser_error == 0 )) || break 3",
        "          done",
        "        done",
        "        continue",
        "      fi",
        "      if [[ \"$_slp_pk\" == permitrootlogin ]]; then",
        "        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-permit-root-login; break; }",
        "        [[ \"${_slp_args[0]}\" != *\"=\"* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-permit-root-login; break; }",
        "        _slp_pv=${_slp_args[0],,}",
        "        if [[ \"$_slp_scope\" == GLOBAL && \"$_slp_pm\" == 1 && \"$_slp_pv\" == no ]]; then ((_slp_main_no+=1)); fi",
        "        if [[ \"$_slp_scope\" == MATCH && \"$_slp_pv\" != no ]]; then ((_slp_match_non_no+=1)); fi",
        "      fi",
        "    done < \"$_slp_pf\" || { _slp_parser_error=1; _slp_parser_reason=sshd-config:read-failed; }",
        "    unset '_slp_stack[$_slp_pr]'",
        "    return 0",
        "  }",
        "  _slp_parse_sshd_file \"$_slp_cfg\" 0 1 GLOBAL",
        "  if (( _slp_parser_error != 0 )); then",
        '    ' + emit.strip() + ' "ERROR" "$_slp_parser_reason" "ERROR"',
        "    return 0",
        "  fi",
        "  if (( _slp_match_non_no != 0 )); then",
        emit + ' "ERROR" "sshd-config:ambiguous-match" "ERROR"',
        "    return 0",
        "  fi",
        "  command \"$_slp_sshd\" -t -f \"$_slp_cfg\" >/dev/null 2>&1",
        "  _slp_rc=$?",
        "  if (( _slp_rc != 0 )); then",
        emit + ' "ERROR" "sshd-config:validation-failed" "ERROR"',
        "    return 0",
        "  fi",
        "  _slp_effective=$(command \"$_slp_sshd\" -T -C user=root,host=localhost,addr=127.0.0.1 -f \"$_slp_cfg\" 2>/dev/null)",
        "  _slp_rc=$?",
        "  if (( _slp_rc != 0 )); then",
        emit + ' "ERROR" "sshd-effective:query-failed" "ERROR"',
        "    return 0",
        "  fi",
        "  _slp_effective_lines=()",
        "  while IFS= read -r _slp_line; do",
        "    _slp_line=${_slp_line%$'\\r'}",
        "    [[ \"${_slp_line,,}\" =~ ^permitrootlogin[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue",
        "    _slp_effective_lines+=(\"${BASH_REMATCH[1],,}\")",
        "  done <<< \"$_slp_effective\"",
        "  if (( ${#_slp_effective_lines[@]} != 1 )); then",
        emit + ' "ERROR" "sshd-effective:ambiguous-value" "ERROR"',
        "    return 0",
        "  fi",
        "  _slp_effective=${_slp_effective_lines[0]}",
        "  if (( _slp_main_no > 0 )) && [[ \"$_slp_effective\" == no ]]; then",
        emit + ' "VALUE" "main_global_no=$_slp_main_no;effective=no" "PASS"',
        "  else",
        emit + ' "VALUE" "main_global_no=$_slp_main_no;effective=$_slp_effective" "FAIL"',
        "  fi",
        "  return 0",
        "}",
    ]
    return "\n".join(lines) + "\n"

def shell_function(control_id, locator, key, op, expected):
    if locator != EXPECTED_LOCATOR:
        raise ValueError("locator must be exactly /etc/ssh/sshd_config")
    return _shell_function_for_fixture(control_id, locator, DEFAULT_SSHD, key, op, expected)


MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ",
    "install ", "truncate ", "dd ", "sysctl -w", "setfacl ", "ln ", "mkdir ",
    ">>", "sed -i", "systemctl reload", "systemctl restart",
)


def _selftest():
    src = shell_function("CTRL", EXPECTED_LOCATOR, EXPECTED_KEY, "eq", EXPECTED_VALUE)
    assert "PermitRootLogin" not in src  # values are parsed case-insensitively at runtime; no config contents embedded
    assert "permitrootlogin" in src and "sshd" in src and "-T" in src and "-t" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    bad = (
        ("CTRL", "/tmp/sshd_config", EXPECTED_KEY, "eq", "no"),
        ("CTRL", EXPECTED_LOCATOR, "permitrootlogin", "eq", "no"),
        ("CTRL", EXPECTED_LOCATOR, EXPECTED_KEY, "contains", "no"),
        ("CTRL", EXPECTED_LOCATOR, EXPECTED_KEY, "eq", "prohibit-password"),
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
