#!/bin/bash -p
# SecureLinux-Policy v3 unified read-only product CLI
# STATUS=NON_RELEASE_PRODUCT_CANDIDATE
# PRODUCT_CLI=product-cli-v1
# GENERATOR_ID=product-check-generator-v2
# GENERATOR_SHA256=19f9dfd936a445b4582cf0aa1846fa7cf4743cc888dd7653fff81f0e56f863ab
# CONTROL_MANIFEST_SHA256=4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea
# ADAPTER_REGISTRY_SHA256=0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025
# TARGET_FAMILY_ID=linux-x86_64-supported-v1
# PLATFORM_MATRIX_SHA256=efc7436850d1ae92df0f36b33e86663728a9fb3643ba3be8cbcaf40b0c9490d7
# DESKTOP_MATRIX_SHA256=db17bfbe6f60a30831c2e4115bbaedbce4e15717715dd4a1174c75cecdfc4ece

set -u

slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE() {
  local _slp_passwd='/etc/passwd'
  local _slp_shadow='/etc/shadow'
  local _slp_line _slp_user _slp_rest _slp_pwd _slp_colons _slp_vrc
  local _slp_accounts=0 _slp_empty=0
  local -a _slp_passwd_lines=() _slp_shadow_lines=()
  local -A _slp_shadow_seen=() _slp_shadow_pwd=() _slp_passwd_seen=()
  if [[ -L "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:symlink" "ERROR"
    return 0
  fi
  if [[ -L "$_slp_shadow" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:unreadable" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_shadow" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_shadow" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_shadow" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:unreadable" "ERROR"
    return 0
  fi
  _slp_validate_text_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 && "$_slp_v_byte" != 0d ]] || return 1
    done
    return 0
  }
  _slp_validate_text_bytes "$_slp_passwd"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:read-failed" "ERROR"; else printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:invalid-bytes" "ERROR"; fi
    return 0
  fi
  _slp_validate_text_bytes "$_slp_shadow"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:read-failed" "ERROR"; else printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:invalid-bytes" "ERROR"; fi
    return 0
  fi
  if ! mapfile -t _slp_shadow_lines < "$_slp_shadow"; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:read-failed" "ERROR"
    return 0
  fi
  if ! mapfile -t _slp_passwd_lines < "$_slp_passwd"; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:read-failed" "ERROR"
    return 0
  fi
  if (( ${#_slp_passwd_lines[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:empty-file" "ERROR"
    return 0
  fi
  if (( ${#_slp_shadow_lines[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:empty-file" "ERROR"
    return 0
  fi
  for _slp_line in "${_slp_shadow_lines[@]}"; do
    [[ -n "$_slp_line" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:empty-record" "ERROR"; return 0; }
    _slp_colons=${_slp_line//[^:]/}
    [[ ${#_slp_colons} -eq 8 ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:invalid-fields" "ERROR"; return 0; }
    _slp_user=${_slp_line%%:*}
    _slp_rest=${_slp_line#*:}
    _slp_pwd=${_slp_rest%%:*}
    [[ "$_slp_user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:invalid-account" "ERROR"; return 0; }
    [[ -z ${_slp_shadow_seen["$_slp_user"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:duplicate-account" "ERROR"; return 0; }
    _slp_shadow_seen["$_slp_user"]=1
    _slp_shadow_pwd["$_slp_user"]=$_slp_pwd
  done
  for _slp_line in "${_slp_passwd_lines[@]}"; do
    [[ -n "$_slp_line" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:empty-record" "ERROR"; return 0; }
    _slp_colons=${_slp_line//[^:]/}
    [[ ${#_slp_colons} -eq 6 ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:invalid-fields" "ERROR"; return 0; }
    _slp_user=${_slp_line%%:*}
    [[ "$_slp_user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:invalid-account" "ERROR"; return 0; }
    [[ -z ${_slp_passwd_seen["$_slp_user"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:duplicate-account" "ERROR"; return 0; }
    _slp_passwd_seen["$_slp_user"]=1
    [[ -n ${_slp_shadow_seen["$_slp_user"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:missing-shadow-account" "ERROR"; return 0; }
    _slp_pwd=${_slp_shadow_pwd["$_slp_user"]}
    ((_slp_accounts+=1))
    [[ -n "$_slp_pwd" ]] || ((_slp_empty+=1))
  done
  (( _slp_accounts > 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:empty-population" "ERROR"; return 0; }
  if (( _slp_empty == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "VALUE" "accounts=$_slp_accounts;empty=0" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "VALUE" "accounts=$_slp_accounts;empty=$_slp_empty" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_1_2_SSH_ROOT_LOGIN() {
  local LC_ALL=C
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    return 0
  fi
  if [[ ! -f "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:unreadable" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "tool:find-missing" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "tool:sort-missing" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    return 0
  fi
  if [[ ! -f "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-binary:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-binary:not-executable" "ERROR"
    return 0
  fi
  _slp_split_args() {
    local _slp_s=$1 _slp_i=0 _slp_n=${#1} _slp_c _slp_q= _slp_t= _slp_next
    _slp_args=()
    while (( _slp_i < _slp_n )); do
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]] || break
        ((_slp_i+=1))
      done
      (( _slp_i < _slp_n )) || return 0
      _slp_c=${_slp_s:_slp_i:1}
      [[ "$_slp_c" != '#' ]] || return 0
      _slp_t= _slp_q=
      while (( _slp_i < _slp_n )); do
        _slp_c=${_slp_s:_slp_i:1}
        if [[ -n "$_slp_q" ]]; then
          if [[ "$_slp_c" == "$_slp_q" ]]; then _slp_q=; ((_slp_i+=1)); continue; fi
          if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
            _slp_next=${_slp_s:_slp_i+1:1}
            if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' ]]; then
              _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
            fi
          fi
          _slp_t+="$_slp_c"; ((_slp_i+=1)); continue
        fi
        if [[ "$_slp_c" == '"' || "$_slp_c" == "'" ]]; then _slp_q=$_slp_c; ((_slp_i+=1)); continue; fi
        if [[ "$_slp_c" == ' ' || "$_slp_c" == $'\t' || "$_slp_c" == $'\r' ]]; then break; fi
        if [[ "$_slp_c" == '\\' && $((_slp_i + 1)) -lt _slp_n ]]; then
          _slp_next=${_slp_s:_slp_i+1:1}
          if [[ "$_slp_next" == "'" || "$_slp_next" == '"' || "$_slp_next" == '\\' || "$_slp_next" == ' ' ]]; then
            _slp_t+="$_slp_next"; ((_slp_i+=2)); continue
          fi
        fi
        _slp_t+="$_slp_c"; ((_slp_i+=1))
      done
      [[ -z "$_slp_q" ]] || return 2
      _slp_args+=("$_slp_t")
    done
    return 0
  }
  _slp_validate_sshd_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte _slp_v_prev=''
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf"; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    while IFS= read -r _slp_pl || [[ -n "$_slp_pl" ]]; do
      _slp_pl=${_slp_pl%$'\r'}
      [[ "$_slp_pl" =~ [^[:space:]] ]] || continue
      [[ ! "$_slp_pl" =~ ^[[:space:]]*# ]] || continue
      if [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)([[:space:]]*=[[:space:]]*|[[:space:]]+)(.*)$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=${BASH_REMATCH[3]}
      elif [[ "$_slp_pl" =~ ^[[:space:]]*([^[:space:]=]+)[[:space:]]*$ ]]; then
        _slp_pk=${BASH_REMATCH[1],,}; _slp_rest=
      else
        continue
      fi
      [[ "$_slp_pk" == match || "$_slp_pk" == include || "$_slp_pk" == permitrootlogin ]] || continue
      _slp_split_args "$_slp_rest" || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-arguments; break; }
      if [[ "$_slp_pk" == match ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-match; break; }
        _slp_scope=MATCH
        continue
      fi
      if [[ "$_slp_pk" == include ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-include; break; }
        for _slp_pp in "${_slp_args[@]}"; do
          if [[ "$_slp_pp" == /* ]]; then _slp_px=$_slp_pp; else _slp_px=/etc/ssh/$_slp_pp; fi
          _slp_glob=()
          if [[ "$_slp_px" == *'*'* || "$_slp_px" == *'?'* || "$_slp_px" == *'['* ]]; then
            _slp_prefix=${_slp_px%%[\*\?\[]*}
            _slp_prefix=${_slp_prefix%/*}
            [[ -n "$_slp_prefix" ]] || _slp_prefix=/
            if [[ -e "$_slp_prefix" ]]; then
              [[ ! -L "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-symlink; break 2; }
              [[ -d "$_slp_prefix" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-invalid-type; break 2; }
              _slp_nl=$(command /usr/bin/find "$_slp_prefix" -name $'*\n*' -print -quit 2>/dev/null)
              _slp_grc=$?
              (( _slp_grc == 0 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-scan-failed; break 2; }
              [[ -z "$_slp_nl" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-newline-name; break 2; }
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          fi
          for _slp_item in "${_slp_glob[@]}"; do
            _slp_parse_sshd_file "$_slp_item" $((_slp_pd + 1)) 0 "$_slp_scope"
            (( _slp_parser_error == 0 )) || break 3
          done
        done
        continue
      fi
      if [[ "$_slp_pk" == permitrootlogin ]]; then
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-permit-root-login; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-permit-root-login; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == no ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != no ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done < "$_slp_pf" || { _slp_parser_error=1; _slp_parser_reason=sshd-config:read-failed; }
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "$_slp_parser_reason" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:ambiguous-match" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:validation-failed" "ERROR"
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-effective:query-failed" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^permitrootlogin[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-effective:ambiguous-value" "ERROR"
    return 0
  fi
  _slp_effective=${_slp_effective_lines[0]}
  if (( _slp_main_no > 0 )) && [[ "$_slp_effective" == no ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "VALUE" "main_global_no=$_slp_main_no;effective=no" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "VALUE" "main_global_no=$_slp_main_no;effective=$_slp_effective" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_2_1_SU_WHEEL_ACCESS() {
  local _slp_cid='FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS'
  local _slp_pam='/etc/pam.d/su'
  local _slp_group='/etc/group'
  local _slp_authority='/etc/securelinux-policy/wheel-users.allowlist-v1'
  local _slp_line _slp_logical='' _slp_trim _slp_module _slp_control _slp_type _slp_gid='' _slp_members='' _slp_name _slp_hex _slp_byte _slp_prev
  local -a _slp_tok=() _slp_members_arr=()
  local -A _slp_actual=() _slp_approved=()
  local _slp_exact=0 _slp_other=0 _slp_wheel=0 _slp_error=0 _slp_mismatch=0 _slp_midx=0 _slp_i=0 _slp_vrc=0

  _slp_name_has_forbidden_separator() {
    local _slp_n=$1
    case "$_slp_n" in
      *' '*|*$'\t'*|*$'\r'*|*$'\v'*|*$'\f'*|*:*|*','*|*'#'*) return 0 ;;
      *$'\xc2\x85'*|*$'\xc2\xa0'*|*$'\xe1\x9a\x80'*|*$'\xe2\x80\x80'*|*$'\xe2\x80\x81'*|*$'\xe2\x80\x82'*|*$'\xe2\x80\x83'*|*$'\xe2\x80\x84'*|*$'\xe2\x80\x85'*|*$'\xe2\x80\x86'*|*$'\xe2\x80\x87'*|*$'\xe2\x80\x88'*|*$'\xe2\x80\x89'*|*$'\xe2\x80\x8a'*|*$'\xe2\x80\xa8'*|*$'\xe2\x80\xa9'*|*$'\xe2\x80\xaf'*|*$'\xe2\x81\x9f'*|*$'\xe3\x80\x80'*) return 0 ;;
    esac
    return 1
  }

  if [[ -L "$_slp_pam" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tpam:symlink\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ -L "$_slp_group" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:symlink\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -e "$_slp_pam" || ! -e "$_slp_group" ]]; then
    printf 'SLP-CHECK-V1\t%s\tNOT_FOUND\t-\tFAIL\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -f "$_slp_pam" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tpam:invalid-type\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -r "$_slp_pam" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tpam:unreadable\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -f "$_slp_group" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:invalid-type\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -r "$_slp_group" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:unreadable\tERROR\n' "$_slp_cid"
    return 0
  fi
  _slp_validate_text_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte _slp_v_prev=''
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    return 0
  }
  _slp_validate_text_bytes "$_slp_pam"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tpam:read-failed\tERROR\n' "$_slp_cid"; else printf 'SLP-CHECK-V1\t%s\tERROR\tpam:invalid-bytes\tERROR\n' "$_slp_cid"; fi
    return 0
  fi
  _slp_validate_text_bytes "$_slp_group"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:read-failed\tERROR\n' "$_slp_cid"; else printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:invalid-bytes\tERROR\n' "$_slp_cid"; fi
    return 0
  fi

  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    if [[ "$_slp_line" == *$'\r'* ]]; then
      if [[ "$_slp_line" != *$'\r' || "${_slp_line%$'\r'}" == *$'\r'* ]]; then _slp_error=1; break; fi
      _slp_line=${_slp_line%$'\r'}
    fi
    _slp_line=${_slp_line%%#*}
    if [[ "$_slp_line" == *\\ ]]; then
      _slp_logical+=${_slp_line%\\}
      continue
    fi
    _slp_logical+="$_slp_line"
    _slp_trim=${_slp_logical#"${_slp_logical%%[!$' \t']*}"}
    _slp_trim=${_slp_trim%"${_slp_trim##*[!$' \t']}"}
    _slp_logical=''
    [[ -n "$_slp_trim" ]] || continue
    read -r -a _slp_tok <<< "$_slp_trim"
    if [[ "${_slp_tok[0]}" == @include ]]; then
      (( ${#_slp_tok[@]} == 2 )) || { _slp_error=1; break; }
      (( _slp_exact > 0 )) || { _slp_error=1; break; }
      continue
    fi
    (( ${#_slp_tok[@]} >= 3 )) || { _slp_error=1; break; }
    _slp_type=${_slp_tok[0],,}
    _slp_type=${_slp_type#-}
    _slp_control=${_slp_tok[1],,}
    if (( _slp_exact == 0 )) && [[ "$_slp_type" == auth ]]; then
      if [[ "$_slp_control" == sufficient || "$_slp_control" == include || "$_slp_control" == substack || "$_slp_control" == \[* ]]; then _slp_error=1; break; fi
    fi
    _slp_midx=2
    if [[ "$_slp_control" == \[* ]]; then
      _slp_midx=0
      for ((_slp_i=1; _slp_i<${#_slp_tok[@]}; _slp_i++)); do
        if [[ "${_slp_tok[_slp_i]}" == *\] ]]; then _slp_midx=$((_slp_i+1)); break; fi
      done
      (( _slp_midx > 0 && _slp_midx < ${#_slp_tok[@]} )) || { _slp_error=1; break; }
    fi
    _slp_module=${_slp_tok[_slp_midx]}
    if [[ "${_slp_module##*/}" == pam_wheel.so ]]; then
      if [[ "${_slp_tok[0],,}" == auth && "${_slp_tok[1],,}" == required && "$_slp_module" == pam_wheel.so && ${#_slp_tok[@]} -eq 4 && "${_slp_tok[3]}" == use_uid ]]; then
        ((_slp_exact+=1))
      else
        ((_slp_other+=1))
      fi
    fi
  done < "$_slp_pam"
  [[ -z "$_slp_logical" ]] || _slp_error=1
  if (( _slp_error || _slp_other > 0 )); then
    printf 'SLP-CHECK-V1\t%s\tERROR\tpam:ambiguous-stack\tERROR\n' "$_slp_cid"
    return 0
  fi

  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    if [[ "$_slp_line" == *$'\r'* ]]; then
      if [[ "$_slp_line" != *$'\r' || "${_slp_line%$'\r'}" == *$'\r'* ]]; then _slp_error=1; break; fi
      _slp_line=${_slp_line%$'\r'}
    fi
    [[ "$_slp_line" == wheel:* ]] || continue
    ((_slp_wheel+=1))
    if [[ "$_slp_line" =~ ^wheel:([^:]*):([0-9]+):([^:]*)$ ]]; then
      _slp_gid=${BASH_REMATCH[2]}
      _slp_members=${BASH_REMATCH[3]}
    else
      _slp_error=1
    fi
  done < "$_slp_group"
  if (( _slp_error || _slp_wheel > 1 )); then
    printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:invalid-record\tERROR\n' "$_slp_cid"
    return 0
  fi
  if (( _slp_wheel == 1 )) && [[ -n "$_slp_members" ]]; then
    if [[ "$_slp_members" == ,* || "$_slp_members" == *, || "$_slp_members" == *,,* ]]; then _slp_error=1; fi
    IFS=',' read -r -a _slp_members_arr <<< "$_slp_members"
    for _slp_name in "${_slp_members_arr[@]}"; do
      if [[ -z "$_slp_name" ]] || _slp_name_has_forbidden_separator "$_slp_name" || [[ -n "${_slp_actual[$_slp_name]+x}" ]]; then _slp_error=1; break; fi
      _slp_actual["$_slp_name"]=1
    done
  fi
  if (( _slp_error )); then
    printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:invalid-members\tERROR\n' "$_slp_cid"
    return 0
  fi

  if (( _slp_exact == 0 || _slp_wheel == 0 )); then
    printf 'SLP-CHECK-V1\t%s\tVALUE\tpam_exact=%d;wheel=%d;members=%d;authority=not-needed\tFAIL\n' "$_slp_cid" "$_slp_exact" "$_slp_wheel" "${#_slp_actual[@]}"
    return 0
  fi
  if [[ -z "${_slp_actual[root]+x}" ]]; then
    printf 'SLP-CHECK-V1\t%s\tVALUE\tpam_exact=%d;wheel=1;members=%d;root=missing;authority=not-needed\tFAIL\n' "$_slp_cid" "$_slp_exact" "${#_slp_actual[@]}"
    return 0
  fi

  if [[ "$_slp_gid" != 10 ]]; then
    printf 'SLP-CHECK-V1\t%s\tVALUE\tpam_exact=%d;wheel=1;gid=%s;expected_gid=10;authority=not-needed\tFAIL\n' "$_slp_cid" "$_slp_exact" "$_slp_gid"
    return 0
  fi
  if [[ -L "$_slp_authority" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tauthority:symlink\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -e "$_slp_authority" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tauthority:not-found\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -f "$_slp_authority" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tauthority:invalid-type\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -r "$_slp_authority" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\tauthority:unreadable\tERROR\n' "$_slp_cid"
    return 0
  fi
  _slp_validate_text_bytes "$_slp_authority"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tauthority:read-failed\tERROR\n' "$_slp_cid"; else printf 'SLP-CHECK-V1\t%s\tERROR\tauthority:invalid-bytes\tERROR\n' "$_slp_cid"; fi
    return 0
  fi
  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    if [[ "$_slp_line" == *$'\r'* ]]; then
      if [[ "$_slp_line" != *$'\r' || "${_slp_line%$'\r'}" == *$'\r'* ]]; then _slp_error=1; break; fi
      _slp_line=${_slp_line%$'\r'}
    fi
    [[ -n "$_slp_line" ]] || continue
    [[ "${_slp_line:0:1}" != \# ]] || continue
    if [[ "$_slp_line" == root ]] || _slp_name_has_forbidden_separator "$_slp_line" || [[ -n "${_slp_approved[$_slp_line]+x}" ]]; then _slp_error=1; break; fi
    _slp_approved["$_slp_line"]=1
  done < "$_slp_authority"
  if (( _slp_error )); then
    printf 'SLP-CHECK-V1\t%s\tERROR\tauthority:invalid-record\tERROR\n' "$_slp_cid"
    return 0
  fi

  for _slp_name in "${!_slp_approved[@]}"; do
    [[ -n "${_slp_actual[$_slp_name]+x}" ]] || ((_slp_mismatch+=1))
  done
  for _slp_name in "${!_slp_actual[@]}"; do
    if [[ "$_slp_name" != root && -z "${_slp_approved[$_slp_name]+x}" ]]; then ((_slp_mismatch+=1)); fi
  done
  if (( _slp_mismatch == 0 )); then
    printf 'SLP-CHECK-V1\t%s\tVALUE\tpam_exact=%d;wheel=1;gid=%s;members=%d;approved=%d;mismatch=0\tPASS\n' "$_slp_cid" "$_slp_exact" "$_slp_gid" "${#_slp_actual[@]}" "${#_slp_approved[@]}"
  else
    printf 'SLP-CHECK-V1\t%s\tVALUE\tpam_exact=%d;wheel=1;gid=%s;members=%d;approved=%d;mismatch=%d\tFAIL\n' "$_slp_cid" "$_slp_exact" "$_slp_gid" "${#_slp_actual[@]}" "${#_slp_approved[@]}" "$_slp_mismatch"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_2_2_SUDOERS_REVIEWED_POLICY() {
  local _slp_cid='FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY'
  local _slp_root='/etc/sudoers'
  local _slp_authority='/etc/securelinux-policy/sudoers-reviewed-policy-v1'
  local _slp_visudo='/usr/sbin/visudo'
  local _slp_line _slp_path _slp_hash _slp_out _slp_rc _slp_header='' _slp_hex _slp_byte _slp_prev='' _slp_char _slp_visudo_hex
  local _slp_actual_count=0 _slp_approved_count=0 _slp_mismatch=0 _slp_vrc=0 _slp_visudo_reason=visudo:invalid-output
  local -A _slp_actual=() _slp_approved=() _slp_seen=()

  _slp_error() { local _slp_reason=$1; printf 'SLP-CHECK-V1\t%s\tERROR\t%s\tERROR\n' "$_slp_cid" "$_slp_reason"; return 0; }
  _slp_validate_authority_bytes() {
    local _slp_v_hex _slp_v_byte _slp_v_prev=''
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_authority" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      case "$_slp_v_byte" in
        00|01|02|03|04|05|06|07|08|0b|0c|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f|7f) return 1 ;;
      esac
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    return 0
  }

  [[ ! -L "$_slp_root" ]] || { _slp_error sudoers:symlink; return 0; }
  [[ -e "$_slp_root" ]] || { _slp_error sudoers:not-found; return 0; }
  [[ -f "$_slp_root" ]] || { _slp_error sudoers:invalid-type; return 0; }
  [[ -r "$_slp_root" ]] || { _slp_error sudoers:unreadable; return 0; }
  [[ ! -L "$_slp_authority" ]] || { _slp_error authority:symlink; return 0; }
  [[ -e "$_slp_authority" ]] || { _slp_error authority:not-found; return 0; }
  [[ -f "$_slp_authority" ]] || { _slp_error authority:invalid-type; return 0; }
  [[ -r "$_slp_authority" ]] || { _slp_error authority:unreadable; return 0; }
  [[ -x "$_slp_visudo" ]] || { _slp_error tool:visudo-missing; return 0; }
  _slp_validate_authority_bytes; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then _slp_error authority:read-failed; else _slp_error authority:invalid-bytes; fi
    return 0
  fi

  _slp_accept_visudo_line() {
    local _slp_v_line=$1
    _slp_visudo_reason=visudo:invalid-output
    [[ -n "$_slp_v_line" && "$_slp_v_line" == *': parsed OK' ]] || { _slp_visudo_reason=visudo:unexpected-line; return 1; }
    _slp_path=${_slp_v_line%': parsed OK'}
    [[ "$_slp_path" == /* && "$_slp_path" != *$'\t'* && "$_slp_path" != *$'\r'* ]] || { _slp_visudo_reason=visudo-path:invalid-path; return 1; }
    [[ -z "${_slp_seen[$_slp_path]+x}" ]] || { _slp_visudo_reason=visudo-path:duplicate-path; return 1; }
    _slp_seen["$_slp_path"]=1
    [[ ! -L "$_slp_path" ]] || { _slp_visudo_reason=visudo-path:symlink; return 1; }
    [[ -e "$_slp_path" ]] || { _slp_visudo_reason=visudo-path:not-found; return 1; }
    [[ -f "$_slp_path" ]] || { _slp_visudo_reason=visudo-path:invalid-type; return 1; }
    [[ -r "$_slp_path" ]] || { _slp_visudo_reason=visudo-path:unreadable; return 1; }
    _slp_hash=$(LC_ALL=C command /usr/bin/sha256sum -- "$_slp_path" 2>/dev/null) || { _slp_visudo_reason=visudo-path:hash-failed; return 1; }
    _slp_hash=${_slp_hash%% *}
    [[ "$_slp_hash" =~ ^[0-9a-f]{64}$ ]] || { _slp_visudo_reason=visudo-path:invalid-hash; return 1; }
    _slp_actual["$_slp_path"]=$_slp_hash
    ((_slp_actual_count+=1))
    return 0
  }

  _slp_visudo_hex=$(set -o pipefail; LC_ALL=C command "$_slp_visudo" -c -f "$_slp_root" 2>&1 | LC_ALL=C command /usr/bin/od -An -v -tx1)
  _slp_rc=$?
  (( _slp_rc == 0 )) || { _slp_error visudo:validation-failed; return 0; }
  [[ -n "$_slp_visudo_hex" ]] || { _slp_error visudo:empty-output; return 0; }
  _slp_line=''
  for _slp_byte in $_slp_visudo_hex; do
    [[ "$_slp_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || { _slp_error visudo:invalid-bytes; return 0; }
    case "$_slp_byte" in
      0a)
        _slp_accept_visudo_line "$_slp_line" || { _slp_error "$_slp_visudo_reason"; return 0; }
        _slp_line=''
        ;;
      00|01|02|03|04|05|06|07|08|09|0b|0c|0d|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f|7f)
        _slp_error visudo:invalid-bytes; return 0
        ;;
      *)
        printf -v _slp_char '%b' "\x$_slp_byte" || { _slp_error visudo:invalid-bytes; return 0; }
        _slp_line+="$_slp_char"
        ;;
    esac
  done
  if [[ -n "$_slp_line" ]]; then
    _slp_accept_visudo_line "$_slp_line" || { _slp_error "$_slp_visudo_reason"; return 0; }
  fi
  [[ _slp_actual_count -gt 0 && -n "${_slp_actual[$_slp_root]+x}" ]] || { _slp_error visudo:incomplete-output; return 0; }

  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    if [[ "$_slp_line" == *$'\r'* ]]; then
      [[ "$_slp_line" == *$'\r' && "${_slp_line%$'\r'}" != *$'\r'* ]] || { _slp_error authority:invalid-bytes; return 0; }
      _slp_line=${_slp_line%$'\r'}
    fi
    if [[ -z "$_slp_header" ]]; then
      [[ "$_slp_line" == 'SLP-SUDOERS-REVIEWED-POLICY-V1' ]] || { _slp_error authority:invalid-header; return 0; }
      _slp_header=1
      continue
    fi
    [[ -n "$_slp_line" && "$_slp_line" == *$'\t'* ]] || { _slp_error authority:invalid-record; return 0; }
    _slp_hash=${_slp_line%%$'\t'*}
    _slp_path=${_slp_line#*$'\t'}
    [[ "$_slp_path" != *$'\t'* && "$_slp_hash" =~ ^[0-9a-f]{64}$ && "$_slp_path" == /* && -n "$_slp_path" ]] || { _slp_error authority:invalid-record; return 0; }
    [[ -z "${_slp_approved[$_slp_path]+x}" ]] || { _slp_error authority:duplicate-record; return 0; }
    _slp_approved["$_slp_path"]=$_slp_hash
    ((_slp_approved_count+=1))
  done < "$_slp_authority"
  [[ -n "$_slp_header" && _slp_approved_count -gt 0 && -n "${_slp_approved[$_slp_root]+x}" ]] || { _slp_error authority:incomplete; return 0; }

  for _slp_path in "${!_slp_actual[@]}"; do
    if [[ -z "${_slp_approved[$_slp_path]+x}" || "${_slp_approved[$_slp_path]}" != "${_slp_actual[$_slp_path]}" ]]; then ((_slp_mismatch+=1)); fi
  done
  for _slp_path in "${!_slp_approved[@]}"; do
    [[ -n "${_slp_actual[$_slp_path]+x}" ]] || ((_slp_mismatch+=1))
  done
  if (( _slp_mismatch == 0 )); then
    printf 'SLP-CHECK-V1\t%s\tVALUE\tfiles=%d;approved=%d;mismatch=0\tPASS\n' "$_slp_cid" "$_slp_actual_count" "$_slp_approved_count"
  else
    printf 'SLP-CHECK-V1\t%s\tVALUE\tfiles=%d;approved=%d;mismatch=%d\tFAIL\n' "$_slp_cid" "$_slp_actual_count" "$_slp_approved_count" "$_slp_mismatch"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_1_GROUP_MODE() {
  local _slp_path='/etc/group'
  local _slp_expected='0644'
  local _slp_mode _slp_parent _slp_comp
  if [[ ! -x /usr/bin/stat ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "tool:stat-missing" "ERROR"
    return 0
  fi
  if [[ -e "$_slp_path" || -L "$_slp_path" ]]; then
    if [[ ! -f "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
  fi
  if _slp_mode=$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null); then
    if [[ ! $_slp_mode =~ ^[0-7]{1,4}$ ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    while [[ ${#_slp_mode} -lt 4 ]]; do _slp_mode="0$_slp_mode"; done
    _slp_comp=FAIL
    [[ $_slp_mode == "$_slp_expected" ]] && _slp_comp=PASS
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "VALUE" "$_slp_mode" "$_slp_comp"
    return 0
  fi
  _slp_parent=${_slp_path%/*}
  [[ -z $_slp_parent ]] && _slp_parent=/
  if [[ -d $_slp_parent && -x $_slp_parent && ! -e $_slp_path && ! -L $_slp_path ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "NOT_FOUND" "-" "NOT_FOUND"
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "target:stat-failed" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_1_PASSWD_MODE() {
  local _slp_path='/etc/passwd'
  local _slp_expected='0644'
  local _slp_mode _slp_parent _slp_comp
  if [[ ! -x /usr/bin/stat ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "tool:stat-missing" "ERROR"
    return 0
  fi
  if [[ -e "$_slp_path" || -L "$_slp_path" ]]; then
    if [[ ! -f "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
  fi
  if _slp_mode=$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null); then
    if [[ ! $_slp_mode =~ ^[0-7]{1,4}$ ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    while [[ ${#_slp_mode} -lt 4 ]]; do _slp_mode="0$_slp_mode"; done
    _slp_comp=FAIL
    [[ $_slp_mode == "$_slp_expected" ]] && _slp_comp=PASS
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "VALUE" "$_slp_mode" "$_slp_comp"
    return 0
  fi
  _slp_parent=${_slp_path%/*}
  [[ -z $_slp_parent ]] && _slp_parent=/
  if [[ -d $_slp_parent && -x $_slp_parent && ! -e $_slp_path && ! -L $_slp_path ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "NOT_FOUND" "-" "NOT_FOUND"
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "target:stat-failed" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_1_SHADOW_GO_RWX() {
  local _slp_path='/etc/shadow'
  local _slp_expected='0077'
  local _slp_mode _slp_parent _slp_comp
  if [[ ! -x /usr/bin/stat ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "tool:stat-missing" "ERROR"
    return 0
  fi
  if [[ -e "$_slp_path" || -L "$_slp_path" ]]; then
    if [[ ! -f "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
  fi
  if _slp_mode=$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null); then
    if [[ ! $_slp_mode =~ ^[0-7]{1,4}$ ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    while [[ ${#_slp_mode} -lt 4 ]]; do _slp_mode="0$_slp_mode"; done
    _slp_comp=FAIL
    (( ( 8#$_slp_mode & 8#$_slp_expected ) == 0 )) && _slp_comp=PASS
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "VALUE" "$_slp_mode" "$_slp_comp"
    return 0
  fi
  _slp_parent=${_slp_path%/*}
  [[ -z $_slp_parent ]] && _slp_parent=/
  if [[ -d $_slp_parent && -x $_slp_parent && ! -e $_slp_path && ! -L $_slp_path ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "NOT_FOUND" "-" "NOT_FOUND"
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "target:stat-failed" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_10_HOME_SENSITIVE_FILES_MODE() {
  local _slp_passwd='/etc/passwd' _slp_inventory='/etc/securelinux-policy/home-sensitive-files-v1'
  local _slp_expected='0077'
  local _slp_line _slp_entry _slp_name _slp_uid _slp_gid _slp_home _slp_rel _slp_base _slp_mode _slp_hex
  local _slp_home_id _slp_ident _slp_marker _slp_find_rc _slp_sort_rc _slp_i _slp_candidate=0
  local _slp_accounts=0 _slp_homes=0 _slp_names=0 _slp_checked=0 _slp_violations=0 _slp_dynamic=0
  local -a _slp_fields=() _slp_entries=() _slp_mandatory=('.bash_history' '.history' '.sh_history' '.bash_profile' '.bashrc' '.profile' '.bash_logout' '.rhosts')
  local -A _slp_seen_users=() _slp_seen_homes=() _slp_inventory_names=() _slp_seen_targets=()

  if [[ -L "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:unreadable" "ERROR"
    return 0
  fi
  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_passwd" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:read-failed" "ERROR"
    return 0
  fi
  if [[ "$_slp_hex" =~ (^|[[:space:]])(00|0d)([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:invalid-bytes" "ERROR"
    return 0
  fi
  if [[ -L "$_slp_inventory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "inventory:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_inventory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "inventory:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_inventory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "inventory:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_inventory" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "inventory:unreadable" "ERROR"
    return 0
  fi
  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_inventory" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "inventory:read-failed" "ERROR"
    return 0
  fi
  if [[ "$_slp_hex" =~ (^|[[:space:]])(00|0d)([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "inventory:invalid-bytes" "ERROR"
    return 0
  fi

  while IFS= read -r _slp_entry || [[ -n "$_slp_entry" ]]; do
    [[ -z "$_slp_entry" || "${_slp_entry:0:1}" == "#" ]] && continue
    if [[ ! "$_slp_entry" =~ ^\.[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "inventory:invalid-path" "ERROR"
      return 0
    fi
    if [[ ${_slp_inventory_names["$_slp_entry"]+x} ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "inventory:duplicate-path" "ERROR"
      return 0
    fi
    _slp_inventory_names["$_slp_entry"]=1
  done < "$_slp_inventory"
  for _slp_entry in "${_slp_mandatory[@]}"; do
    [[ ${_slp_inventory_names["$_slp_entry"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "inventory:missing-required" "ERROR"; return 0; }
  done
  _slp_names=${#_slp_inventory_names[@]}

  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    [[ -n "$_slp_line" ]] || continue
    IFS=: read -r -a _slp_fields <<< "$_slp_line"
    (( ${#_slp_fields[@]} == 7 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:invalid-fields" "ERROR"; return 0; }
    _slp_name=${_slp_fields[0]}; _slp_uid=${_slp_fields[2]}; _slp_gid=${_slp_fields[3]}; _slp_home=${_slp_fields[5]}
    [[ "$_slp_name" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ && "$_slp_uid" =~ ^[0-9]+$ && "$_slp_gid" =~ ^[0-9]+$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:invalid-account" "ERROR"; return 0; }
    [[ -z ${_slp_seen_users["$_slp_name"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:duplicate-account" "ERROR"; return 0; }
    _slp_seen_users["$_slp_name"]=1
    [[ "$_slp_home" == /* ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:invalid-home" "ERROR"; return 0; }
    ((_slp_accounts+=1))
    if [[ ! -e "$_slp_home" && ! -L "$_slp_home" ]]; then continue; fi
    if [[ -L "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:symlink" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -r "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:unreadable" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:unsearchable" "ERROR"
      return 0
    fi
    if ! _slp_home_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_home" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:identity-failed" "ERROR"
      return 0
    fi
    if [[ ${_slp_seen_homes["$_slp_home_id"]+x} ]]; then continue; fi
    _slp_seen_homes["$_slp_home_id"]=1
    ((_slp_homes+=1))
    _slp_entries=()
    mapfile -d "" -t _slp_entries < <(
      LC_ALL=C command /usr/bin/find -P -- "$_slp_home" -xdev -mindepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
      _slp_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
      printf "__SLP_SCAN_RC=%s\0" "$_slp_marker"
    )
    (( ${#_slp_entries[@]} > 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "scan:missing-marker" "ERROR"; return 0; }
    _slp_i=$((${#_slp_entries[@]}-1)); _slp_marker=${_slp_entries[$_slp_i]}; unset '_slp_entries[$_slp_i]'
    [[ "$_slp_marker" =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "scan:invalid-marker" "ERROR"; return 0; }
    _slp_find_rc=${BASH_REMATCH[1]}; _slp_sort_rc=${BASH_REMATCH[2]}
    (( _slp_find_rc == 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "scan:find-failed" "ERROR"; return 0; }
    (( _slp_sort_rc == 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "scan:sort-failed" "ERROR"; return 0; }
    for _slp_entry in "${_slp_entries[@]}"; do
      _slp_rel=${_slp_entry#"$_slp_home"/}; _slp_base=${_slp_entry##*/}; _slp_candidate=0
      if [[ ${_slp_inventory_names["$_slp_rel"]+x} ]]; then _slp_candidate=1; fi
      if [[ "$_slp_base" == .* ]]; then
        case "$_slp_base" in
          .bash_login|.xonshrc|.zsh_history|.zshrc|.zprofile|.zlogin|.zlogout|.zshenv|.ksh_history|.kshrc|.mkshrc|.cshrc|.tcshrc|.login|.logout) _slp_candidate=1 ;;
        esac
      fi
      case "$_slp_rel" in
        .config/fish/*.fish|.local/share/fish/fish_history|.config/nushell/config.nu|.config/nushell/env.nu|.config/nushell/login.nu|.config/nushell/autoload/*.nu|.local/share/nushell/vendor/autoload/*.nu|.config/nushell/history.txt|.config/nushell/history.sqlite3|.config/xonsh/rc.xsh|.config/xonsh/rc.d/*.xsh|.config/xonsh/rc.d/*.py|.local/share/xonsh/history_json/xonsh-*.json|.local/share/xonsh/xonsh-*.json|.local/share/xonsh/xonsh-history.sqlite|.config/elvish/rc.elv|.elvish/rc.elv|.local/state/elvish/db.bolt|.elvish/db) _slp_candidate=1 ;;
      esac
      (( _slp_candidate == 1 )) || continue
      ((_slp_dynamic+=1))
      if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "target:symlink" "ERROR"
        return 0
      fi
      if [[ ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "target:invalid-type" "ERROR"
        return 0
      fi
      if ! _slp_ident=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "target:identity-failed" "ERROR"
        return 0
      fi
      if [[ ${_slp_seen_targets["$_slp_ident"]+x} ]]; then continue; fi
      _slp_seen_targets["$_slp_ident"]=1
      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "target:mode-read-failed" "ERROR"
        return 0
      fi
      [[ "$_slp_mode" =~ ^[0-7]{3,4}$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "target:invalid-mode" "ERROR"; return 0; }
      ((_slp_checked+=1))
      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
    done
  done < "$_slp_passwd"
  (( _slp_accounts > 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "passwd:empty-population" "ERROR"; return 0; }
  local _slp_value="accounts=$_slp_accounts;homes=$_slp_homes;names=$_slp_names;discovered=$_slp_dynamic;checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_11_HOME_DIRECTORIES_MODE() {
  local _slp_passwd='/etc/passwd' _slp_expected='0700'
  local _slp_line _slp_name _slp_uid _slp_gid _slp_home _slp_home_id _slp_mode _slp_hex
  local _slp_accounts=0 _slp_homes=0 _slp_violations=0
  local -a _slp_fields=()
  local -A _slp_seen_users=() _slp_seen_homes=()
  if [[ -L "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_passwd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:unreadable" "ERROR"
    return 0
  fi
  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_passwd" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:read-failed" "ERROR"
    return 0
  fi
  if [[ "$_slp_hex" =~ (^|[[:space:]])(00|0d)([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:invalid-bytes" "ERROR"
    return 0
  fi
  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    [[ -n "$_slp_line" ]] || continue
    IFS=: read -r -a _slp_fields <<< "$_slp_line"
    (( ${#_slp_fields[@]} == 7 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:invalid-fields" "ERROR"; return 0; }
    _slp_name=${_slp_fields[0]}; _slp_uid=${_slp_fields[2]}; _slp_gid=${_slp_fields[3]}; _slp_home=${_slp_fields[5]}
    [[ "$_slp_name" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ && "$_slp_uid" =~ ^[0-9]+$ && "$_slp_gid" =~ ^[0-9]+$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:invalid-account" "ERROR"; return 0; }
    [[ -z ${_slp_seen_users["$_slp_name"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:duplicate-account" "ERROR"; return 0; }
    _slp_seen_users["$_slp_name"]=1
    [[ "$_slp_home" == /* ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:invalid-home" "ERROR"; return 0; }
    ((_slp_accounts+=1))
    if [[ ! -e "$_slp_home" && ! -L "$_slp_home" ]]; then continue; fi
    if [[ -L "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:symlink" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_home_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_home" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:identity-failed" "ERROR"
      return 0
    fi
    if [[ ${_slp_seen_homes["$_slp_home_id"]+x} ]]; then continue; fi
    _slp_seen_homes["$_slp_home_id"]=1
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_home" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:mode-read-failed" "ERROR"
      return 0
    fi
    [[ "$_slp_mode" =~ ^[0-7]{3,4}$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-mode" "ERROR"; return 0; }
    ((_slp_homes+=1))
    if (( 8#$_slp_mode != 8#$_slp_expected )); then ((_slp_violations+=1)); fi
  done < "$_slp_passwd"
  (( _slp_accounts > 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "passwd:empty-population" "ERROR"; return 0; }
  local _slp_value="accounts=$_slp_accounts;homes=$_slp_homes;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_2_RUNNING_PROCESS_PATHS_WRITE_PROTECTION() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/proc' '/' <<'SLP_RUNTIME_PATHS_PY'
import os, re, stat, sys
from pathlib import Path

proc_root = Path(sys.argv[1])
parent_stop = Path(sys.argv[2])

MAP_ADDRESS = re.compile(r"^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)$")
MAP_PERMS = re.compile(r"^[r-][w-][x-][ps]$")
MAP_OFFSET = re.compile(r"^[0-9A-Fa-f]+$")
MAP_DEVICE = re.compile(r"^([0-9A-Fa-f]+):([0-9A-Fa-f]+)$")
ASCII_DECIMAL = re.compile(r"^[0-9]+$")
ASCII_SIGNED_DECIMAL = re.compile(r"^-?[0-9]+$")
PROC_PROCESSES = re.compile(r"^processes[ \t]+([0-9]+)$")
OCTAL = set("01234567")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_start(pid):
    try:
        raw = (pid / "stat").read_text(encoding="ascii", errors="strict")
    except FileNotFoundError:
        return None
    except Exception:
        error("proc-stat:read-failed")
    if "\x00" in raw or "\r" in raw:
        error("proc-stat:invalid-bytes")
    if raw.endswith("\n"):
        body = raw[:-1]
    else:
        body = raw
    if not body or "\n" in body or "\t" in body or "\v" in body or "\f" in body:
        error("proc-stat:invalid-layout")
    prefix = pid.name + " ("
    if not body.startswith(prefix):
        error("proc-stat:invalid-prefix")
    close = body.rfind(")")
    if close < len(prefix) - 1 or close + 1 >= len(body) or body[close + 1] != " ":
        error("proc-stat:invalid-command-field")
    fields = body[close + 2:].split(" ")
    if len(fields) != 50 or any(field == "" for field in fields):
        error("proc-stat:invalid-field-count")
    state = fields[0]
    if len(state) != 1 or not state.isascii() or not state.isalpha():
        error("proc-stat:invalid-state")
    for value in fields[1:]:
        if ASCII_SIGNED_DECIMAL.fullmatch(value) is None:
            error("proc-stat:invalid-number")
    starttime = fields[19]
    if ASCII_DECIMAL.fullmatch(starttime) is None:
        error("proc-stat:invalid-starttime")
    return starttime


def read_process_counter():
    try:
        text = (proc_root / "stat").read_text(encoding="ascii", errors="strict")
    except Exception:
        error("proc-counter:read-failed")
    if "\x00" in text or "\r" in text:
        error("proc-counter:invalid-bytes")
    values = []
    for line in text.splitlines():
        if not line.startswith("processes"):
            continue
        match = PROC_PROCESSES.fullmatch(line)
        if match is None:
            error("proc-counter:invalid-record")
        values.append(int(match.group(1), 10))
    if len(values) != 1:
        error("proc-counter:invalid-record-count")
    return values[0]


def population_snapshot():
    try:
        entries = sorted((p for p in proc_root.iterdir() if p.name.isdigit()), key=lambda p: int(p.name))
    except Exception:
        error("proc-population:scan-failed")
    if not entries:
        error("proc-population:empty")
    snap = {}
    for pid in entries:
        start = read_start(pid)
        if start is None:
            error("proc-population:process-disappeared")
        snap[pid.name] = start
    return snap


def classify_no_exe(pid, expected_start):
    try:
        status = (pid / "status").read_text(encoding="utf-8", errors="strict")
    except Exception:
        error("proc-status:read-failed")
    if "\x00" in status or "\r" in status:
        error("proc-status:invalid-bytes")
    kthread = False
    state = None
    for line in status.splitlines():
        if line.startswith("Kthread:"):
            kthread = line.split(":", 1)[1].strip() == "1"
        elif line.startswith("State:"):
            value = line.split(":", 1)[1].strip()
            state = value[:1] if value else None
    if not (kthread or state == "Z"):
        error("proc-status:no-exe-unclassified")
    end = read_start(pid)
    if end is None or end != expected_start:
        error("proc-stat:excluded-classification-changed")
    return "excluded"


def decode_proc_path(raw):
    out = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 3 >= len(raw):
            error("proc:invalid-path-escape")
        digits = raw[i + 1:i + 4]
        if any(c not in OCTAL for c in digits):
            error("proc:invalid-path-escape")
        value = int(digits, 8)
        if value == 0:
            error("proc:invalid-path-escape")
        out.append(chr(value))
        i += 4
    return "".join(out)


def obj_state(st):
    return (
        st.st_dev,
        st.st_ino,
        st.st_uid,
        st.st_gid,
        stat.S_IMODE(st.st_mode),
        st.st_ctime_ns,
    )


def within_stop(real):
    if parent_stop == Path("/"):
        return
    try:
        Path(real).relative_to(parent_stop)
    except ValueError:
        error("path:outside-scope")


def check_path(path_text, file_records, file_states, parent_records, path_set, expected_mapping=None):
    if not path_text.startswith("/") or "\x00" in path_text:
        error("path:invalid-absolute")
    try:
        source_lstat = os.lstat(path_text)
        real = os.path.realpath(path_text)
    except Exception:
        error("path:resolve-failed")
    if not real.startswith("/"):
        error("path:invalid-resolved")
    within_stop(real)
    try:
        fst = os.stat(real, follow_symlinks=True)
    except Exception:
        error("path:stat-failed")
    if not stat.S_ISREG(fst.st_mode):
        error("path:invalid-type")
    if expected_mapping is not None:
        map_major, map_minor, map_inode = expected_mapping
        try:
            actual_major = os.major(fst.st_dev)
            actual_minor = os.minor(fst.st_dev)
        except Exception:
            error("path:device-id-failed")
        if (actual_major, actual_minor, fst.st_ino) != (map_major, map_minor, map_inode):
            error("path:mapping-mismatch")
    source_state = obj_state(source_lstat)
    target_state = obj_state(fst)
    record = (real, source_state, target_state)
    old = file_records.get(path_text)
    if old is not None and old != record:
        error("path:repeat-record-changed")
    file_records[path_text] = record
    identity = (fst.st_dev, fst.st_ino)
    old_state = file_states.get(identity)
    if old_state is not None and old_state != target_state:
        error("path:identity-state-changed")
    file_states[identity] = target_state
    path_set.add(real)

    cur = Path(real).parent
    stop = parent_stop
    while True:
        try:
            dst = os.stat(cur, follow_symlinks=True)
        except Exception:
            error("parent:stat-failed")
        if not stat.S_ISDIR(dst.st_mode):
            error("parent:invalid-type")
        state = obj_state(dst)
        old_dir = parent_records.get(str(cur))
        if old_dir is not None and old_dir != state:
            error("parent:repeat-snapshot-changed")
        parent_records[str(cur)] = state
        if cur == stop:
            break
        if cur == cur.parent:
            if stop != cur:
                error("path:outside-scope")
            break
        if stop != Path("/"):
            try:
                cur.relative_to(stop)
            except ValueError:
                error("path:outside-scope")
        cur = cur.parent
    return identity


def parse_maps(pid):
    try:
        text = (pid / "maps").read_text(encoding="utf-8", errors="strict")
    except Exception:
        error("proc-maps:read-failed")
    if "\x00" in text or "\r" in text:
        error("proc-maps:invalid-bytes")
    mapped_exec = []
    saw_line = False
    for line in text.splitlines():
        if not line:
            continue
        saw_line = True
        parts = line.split(None, 5)
        if len(parts) not in (5, 6):
            error("proc-maps:invalid-fields")

        address_text, perms, offset_text, device_text, inode_text = parts[:5]
        address = MAP_ADDRESS.fullmatch(address_text)
        if address is None:
            error("proc-maps:invalid-address")
        start = int(address.group(1), 16)
        end = int(address.group(2), 16)
        if start >= end:
            error("proc-maps:invalid-address-range")
        if not MAP_PERMS.fullmatch(perms):
            error("proc-maps:invalid-permissions")
        if not MAP_OFFSET.fullmatch(offset_text):
            error("proc-maps:invalid-offset")
        offset = int(offset_text, 16)
        device = MAP_DEVICE.fullmatch(device_text)
        if device is None:
            error("proc-maps:invalid-device")
        dev_major = int(device.group(1), 16)
        dev_minor = int(device.group(2), 16)
        if ASCII_DECIMAL.fullmatch(inode_text) is None:
            error("proc-maps:invalid-inode")
        inode = int(inode_text, 10)

        if len(parts) == 5:
            if inode != 0:
                error("proc-maps:anonymous-inode")
            continue

        raw_path = parts[5]
        if raw_path.startswith("[") and raw_path.endswith("]"):
            if inode != 0:
                error("proc-maps:pseudo-inode")
            continue

        path = decode_proc_path(raw_path)
        if path.endswith(" (deleted)"):
            error("proc-maps:deleted-path")
        if not path.startswith("/"):
            error("proc-maps:nonabsolute-path")
        if perms[2] != "x":
            continue
        if inode == 0:
            error("proc-maps:executable-zero-inode")
        mapped_exec.append((path, start, end, offset, dev_major, dev_minor, inode))

    if not saw_line or not mapped_exec:
        error("proc-maps:empty-executable-population")
    return mapped_exec


def read_exe(pid):
    try:
        target = os.readlink(pid / "exe")
        exe_stat = os.stat(pid / "exe", follow_symlinks=True)
    except FileNotFoundError:
        return None
    except Exception:
        error("proc-exe:read-failed")
    if target.endswith(" (deleted)") or not target.startswith("/") or "\x00" in target:
        error("proc-exe:invalid-target")
    if not stat.S_ISREG(exe_stat.st_mode):
        error("proc-exe:invalid-type")
    return target, obj_state(exe_stat)


def recheck_files(file_records):
    for source, (real, source_state, target_state) in file_records.items():
        try:
            now_source = os.lstat(source)
            now_real = os.path.realpath(source)
            now_target = os.stat(now_real, follow_symlinks=True)
        except Exception:
            error("path:recheck-stat-failed")
        if now_real != real:
            error("path:recheck-resolved-target-changed")
        if obj_state(now_source) != source_state or obj_state(now_target) != target_state:
            error("path:recheck-snapshot-changed")


def recheck_parents(parent_records):
    for path, expected in parent_records.items():
        try:
            now = os.stat(path, follow_symlinks=True)
        except Exception:
            error("parent:recheck-stat-failed")
        if not stat.S_ISDIR(now.st_mode):
            error("parent:recheck-invalid-type")
        if obj_state(now) != expected:
            error("parent:recheck-snapshot-changed")


def recheck_processes(process_records, excluded_records):
    for pid_name, record in process_records.items():
        expected_start, expected_target, expected_exe_state, expected_maps = record
        pid = proc_root / pid_name
        start = read_start(pid)
        if start is None or start != expected_start:
            error("proc-stat:recheck-starttime-changed")
        current_exe = read_exe(pid)
        if current_exe is None:
            error("proc-exe:recheck-missing")
        target, exe_state = current_exe
        if target != expected_target or exe_state != expected_exe_state:
            error("proc-exe:recheck-changed")
        current_maps = tuple(parse_maps(pid))
        if current_maps != expected_maps:
            error("proc-maps:recheck-changed")
        end = read_start(pid)
        if end is None or end != expected_start:
            error("proc-stat:recheck-endtime-changed")

    for pid_name, expected_start in excluded_records.items():
        pid = proc_root / pid_name
        start = read_start(pid)
        if start is None or start != expected_start:
            error("proc-stat:excluded-recheck-changed")
        if read_exe(pid) is not None:
            error("proc-exe:excluded-reappeared")
        classify_no_exe(pid, expected_start)


try:
    pst = os.lstat(proc_root)
except Exception:
    error("proc-root:lstat-failed")
if not stat.S_ISDIR(pst.st_mode) or stat.S_ISLNK(pst.st_mode):
    error("proc-root:invalid-type")
try:
    sst = os.stat(parent_stop)
except Exception:
    error("parent-stop:stat-failed")
if not stat.S_ISDIR(sst.st_mode):
    error("parent-stop:invalid-type")

fork_counter = read_process_counter()
initial_population = population_snapshot()
file_records = {}
file_states = {}
path_set = set()
parent_records = {}
process_records = {}
excluded_records = {}
processes = 0
libraries_seen = 0
excluded = 0

for pid_name, expected_start in sorted(initial_population.items(), key=lambda item: int(item[0])):
    pid = proc_root / pid_name
    start = read_start(pid)
    if start is None or start != expected_start:
        error("proc-stat:initial-starttime-changed")

    exe_observation = read_exe(pid)
    if exe_observation is None:
        classify_no_exe(pid, expected_start)
        excluded_records[pid_name] = expected_start
        excluded += 1
        continue

    target, exe_state = exe_observation
    exe_identity = check_path(target, file_records, file_states, parent_records, path_set)
    if (exe_state[0], exe_state[1]) != exe_identity:
        error("proc-exe:identity-mismatch")

    mapped_records = tuple(parse_maps(pid))
    mapped_ids = set()
    for path, map_start, map_end, map_offset, map_major, map_minor, map_inode in mapped_records:
        mapped_ids.add(
            check_path(
                path,
                file_records,
                file_states,
                parent_records,
                path_set,
                expected_mapping=(map_major, map_minor, map_inode),
            )
        )

    end = read_start(pid)
    if end is None or end != expected_start:
        error("proc-stat:initial-endtime-changed")

    process_records[pid_name] = (expected_start, target, exe_state, mapped_records)
    processes += 1
    libraries_seen += len(mapped_ids - {exe_identity})

if processes == 0 or not file_states:
    error("proc-population:empty-observation")

mid_population = population_snapshot()
if mid_population != initial_population:
    error("pid-population:mid-snapshot-changed")
if read_process_counter() != fork_counter:
    error("proc-counter:mid-snapshot-changed")

recheck_processes(process_records, excluded_records)
recheck_files(file_records)
recheck_parents(parent_records)

final_population = population_snapshot()
if final_population != initial_population:
    error("pid-population:final-snapshot-changed")
if read_process_counter() != fork_counter:
    error("proc-counter:final-snapshot-changed")

file_violations = sum(1 for state in file_states.values() if state[4] & 0o022)
parent_violations = 0
parent_ambiguous = 0
for state in parent_records.values():
    uid, mode = state[2], state[4]
    # Directory entry mutation requires both write and search (execute) on the
    # directory. A non-root owner or world class with wx proves unprivileged
    # writability. Group-class wx alone does not identify which principals
    # receive it (owning-group membership / POSIX ACL semantics), so it is
    # fail-closed ambiguity rather than a source-level FAIL.
    if uid != 0 and (mode & 0o300) == 0o300:
        parent_violations += 1
    if (mode & 0o003) == 0o003:
        parent_violations += 1
    if (mode & 0o030) == 0o030:
        parent_ambiguous += 1

if parent_violations == 0 and parent_ambiguous:
    error("parent:group-write-ambiguous")

value = (
    f"pids={processes};files={len(file_states)};paths={len(path_set)};parents={len(parent_records)};"
    f"libraries={libraries_seen};forks={fork_counter};vanished=0;excluded={excluded};"
    f"file_violations={file_violations};parent_violations={parent_violations}"
)
compliance = "PASS" if file_violations == 0 and parent_violations == 0 else "FAIL"
print("VALUE\t" + value + "\t" + compliance)
SLP_RUNTIME_PATHS_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'	'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "${_slp_obs#*$'	'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_3_CRON_COMMAND_PATHS_WRITE_PROTECTION() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/' '0' <<'SLP_CRON_PATHS_PY'
import hashlib, os, re, shlex, stat, sys
from pathlib import Path

fsroot = Path(sys.argv[1])
logical_root_uid = int(sys.argv[2], 10)
ASCII_DECIMAL = re.compile(r"^[0-9]+$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CROND_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", re.S)
SCHEDULE_FIELD = re.compile(r"^[A-Za-z0-9*?,/\-]+$")
SPECIAL = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}
SAFE_BUILTINS = {"cd", "test", "[", ":", "true", "false", "echo", "printf", "pwd"}
UNSUPPORTED_COMMANDS = {
    ".", "source", "eval", "exec", "command", "export", "unset", "read", "set", "shift", "trap",
    "env", "nice", "nohup", "timeout", "sudo", "su", "runuser", "chroot", "xargs", "find",
    "flock", "setsid", "stdbuf", "taskset", "ionice", "systemd-run", "start-stop-daemon",
    "busybox", "toybox",
    "time", "setpriv", "unshare", "nsenter", "prlimit", "setarch", "linux32", "linux64",
    "chrt", "watch", "strace", "ltrace", "gdb", "valgrind", "perf", "script",
    "daemon", "daemonize", "parallel", "numactl", "capsh", "firejail", "bwrap",
    "fakeroot", "torsocks", "proxychains", "proxychains4", "eatmydata", "sg", "newgrp",
    "docker", "podman", "systemd-nspawn", "machinectl",
}
INTERPRETER_NAME = re.compile(
    r"^(?:sh|ash|bash|dash|ksh|mksh|zsh|python(?:[0-9]+(?:\.[0-9]+)*)?|"
    r"perl(?:[0-9.]+)?|ruby(?:[0-9.]+)?|node(?:js)?(?:[0-9.]+)?|php(?:[0-9.]+)?|"
    r"lua(?:[0-9.]+)?|tclsh(?:[0-9.]+)?|wish(?:[0-9.]+)?|java|javaw|dotnet|mono|Rscript)$"
)
CONTROL_OPS = {"&&", "||", ";", "|", "&", "(", ")"}


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def map_abs(path_text):
    if not isinstance(path_text, str) or not path_text.startswith("/") or "\x00" in path_text or "\r" in path_text or "\n" in path_text:
        error("path:invalid-absolute")
    return fsroot / path_text.lstrip("/")


def obj_state(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)


def stable_regular(path, allow_symlink=False):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        return None
    except Exception:
        error("file:lstat-failed")
    if stat.S_ISLNK(first.st_mode):
        if not allow_symlink:
            error("file:symlink")
        try:
            real = os.path.realpath(path)
            target = os.stat(real, follow_symlinks=True)
            second = os.lstat(path)
        except Exception:
            error("file:resolve-failed")
        if obj_state(first) != obj_state(second):
            error("file:changed-during-check")
        if not stat.S_ISREG(target.st_mode):
            error("file:invalid-type")
        return (str(path), real, obj_state(first), obj_state(target))
    if not stat.S_ISREG(first.st_mode):
        error("file:invalid-type")
    try:
        second = os.lstat(path)
    except Exception:
        error("file:lstat-failed")
    if obj_state(first) != obj_state(second):
        error("file:changed-during-check")
    return (str(path), str(path), obj_state(first), obj_state(first))


def stable_text(path, optional=False, allow_symlink=False):
    rec = stable_regular(path, allow_symlink=allow_symlink)
    if rec is None:
        if optional:
            return None
        error("file:not-found")
    try:
        raw = path.read_bytes()
        after = stable_regular(path, allow_symlink=allow_symlink)
    except Exception:
        error("file:read-failed")
    if after != rec:
        error("file:changed-during-check")
    if b"\x00" in raw or b"\r" in raw:
        error("file:invalid-bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error("file:invalid-utf8")
    return rec, hashlib.sha256(raw).hexdigest(), text


def stable_dir(path, optional=False):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        if optional:
            return None
        error("directory:not-found")
    except Exception:
        error("directory:lstat-failed")
    if stat.S_ISLNK(first.st_mode):
        error("directory:symlink")
    if not stat.S_ISDIR(first.st_mode):
        error("directory:invalid-type")
    try:
        names = sorted(os.listdir(path), key=os.fsencode)
        second = os.lstat(path)
    except Exception:
        error("directory:scan-failed")
    if obj_state(first) != obj_state(second):
        error("directory:changed-during-check")
    return obj_state(first), tuple(names)


def parse_passwd():
    observed = stable_text(map_abs("/etc/passwd"), optional=False)
    users = {}
    for line in observed[2].splitlines():
        if not line:
            error("passwd:empty-record")
        parts = line.split(":")
        if len(parts) != 7:
            error("passwd:invalid-fields")
        name, _, uid_text, gid_text, _, home, _ = parts
        if not name:
            error("passwd:invalid-account")
        if name in users:
            error("passwd:duplicate-account")
        if ASCII_DECIMAL.fullmatch(uid_text) is None or ASCII_DECIMAL.fullmatch(gid_text) is None:
            error("passwd:invalid-id")
        if not home.startswith("/"):
            error("passwd:invalid-home")
        users[name] = (int(uid_text), int(gid_text), home)
    if "root" not in users or users["root"][0] != 0:
        error("passwd:invalid-root")
    return observed, users


def parse_env_value(raw):
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    if any(ch in value for ch in "\x00\r\n`$"):
        error("cron:invalid-environment-value")
    return value


def parse_path_value(raw):
    value = parse_env_value(raw)
    parts = value.split(":")
    if not parts or any(not p.startswith("/") or p == "/" and False for p in parts) or any(p == "" for p in parts):
        error("cron:invalid-path")
    return tuple(parts)


def split_percent(command):
    out = []
    escaped = False
    for ch in command:
        if escaped:
            if ch == "%":
                out.append("%")
            else:
                out.append("\\")
                out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == "%":
            break
        out.append(ch)
    if escaped:
        out.append("\\")
    result = "".join(out).strip()
    if not result:
        error("cron:empty-command")
    return result


def cron_job(line, system_file, owner_user, users):
    parts = line.split()
    if not parts:
        error("cron:empty-record")
    if parts[0].startswith("@"):
        if parts[0] not in SPECIAL:
            error("cron:invalid-schedule")
        needed = 3 if system_file else 2
        if len(parts) < needed:
            error("cron:invalid-fields")
        user = parts[1] if system_file else owner_user
        command = line.split(None, 2 if system_file else 1)[2 if system_file else 1]
    else:
        if len(parts) < (7 if system_file else 6):
            error("cron:invalid-fields")
        for field in parts[:5]:
            if SCHEDULE_FIELD.fullmatch(field) is None:
                error("cron:invalid-schedule")
        user = parts[5] if system_file else owner_user
        command = line.split(None, 6 if system_file else 5)[6 if system_file else 5]
    if user not in users:
        error("cron:unknown-user")
    return user, split_percent(command)


def lex_command(command):
    if any(ch in command for ch in "\x00\r\n`$"):
        error("command:invalid-bytes")
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except Exception:
        error("command:parse-failed")
    if not tokens:
        error("command:empty")
    for tok in tokens:
        if "<" in tok or ">" in tok:
            error("command:unsupported-redirection")
    return tokens


def resolve_root_command(word, path_env, uid, dir_records):
    if "/" in word:
        if not word.startswith("/"):
            error("command:relative-path")
        return word
    if uid != 0 or path_env is None:
        error("command:unresolved-name")
    for d in path_env:
        dpath = map_abs(d)
        drec = stable_dir(dpath, optional=False)
        dir_records[("path", d)] = drec
        candidate_text = d.rstrip("/") + "/" + word
        candidate = map_abs(candidate_text)
        try:
            st = os.stat(candidate, follow_symlinks=True)
        except FileNotFoundError:
            continue
        except Exception:
            error("command:stat-failed")
        if stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) & 0o111:
            return candidate_text
    error("command:not-found")


def resolved_command_record(path_text):
    mapped = map_abs(path_text)
    rec = stable_regular(mapped, allow_symlink=True)
    if rec is None:
        error("target:not-found")
    target_state = rec[3]
    if target_state[8] != 1:
        error("target:hardlink")
    if (target_state[4] & 0o111) == 0:
        error("target:not-executable")
    canonical_base = os.path.basename(rec[1])
    if not canonical_base or canonical_base in {".", ".."}:
        error("target:invalid-name")
    return rec, canonical_base


def add_target(path_text, targets, allow_nonexec=False):
    mapped = map_abs(path_text)
    rec = stable_regular(mapped, allow_symlink=True)
    if rec is None:
        error("target:not-found")
    target_state = rec[3]
    if not allow_nonexec and (target_state[4] & 0o111) == 0:
        error("target:not-executable")
    previous = targets.get(path_text)
    if previous is not None and previous != rec:
        error("target:changed-during-check")
    targets[path_text] = rec


def expand_run_parts(args, targets, dir_records):
    directory = None
    for arg in args:
        if arg in {"--report", "--verbose"}:
            continue
        if arg.startswith("-"):
            error("run-parts:unsupported-option")
        if directory is not None:
            error("run-parts:ambiguous-directory")
        directory = arg
    if directory is None or not directory.startswith("/"):
        error("run-parts:invalid-directory")
    dpath = map_abs(directory)
    drec = stable_dir(dpath, optional=False)
    dir_records[("run-parts", directory)] = drec
    for name in drec[1]:
        if CROND_NAME.fullmatch(name) is None:
            continue
        child_text = directory.rstrip("/") + "/" + name
        child = map_abs(child_text)
        try:
            st = os.stat(child, follow_symlinks=True)
        except FileNotFoundError:
            error("run-parts:child-not-found")
        except Exception:
            error("run-parts:child-stat-failed")
        if not stat.S_ISREG(st.st_mode):
            continue
        if stat.S_IMODE(st.st_mode) & 0o111:
            add_target(child_text, targets, allow_nonexec=False)


def parse_shell(command, user, users, path_env, targets, dir_records):
    tokens = lex_command(command)
    segments = []
    current = []
    depth = 0
    for tok in tokens:
        if tok == "(":
            if current:
                error("command:unsupported-grouping")
            depth += 1
            continue
        if tok == ")":
            if current:
                segments.append(current); current = []
            depth -= 1
            if depth < 0:
                error("command:unbalanced-group")
            continue
        if tok in CONTROL_OPS:
            if tok in {"(", ")"}:
                error("command:unsupported-grouping")
            if current:
                segments.append(current); current = []
            continue
        current.append(tok)
    if current:
        segments.append(current)
    if depth != 0 or not segments:
        error("command:unbalanced-group")

    uid = users[user][0]
    for seg in segments:
        local_path = path_env
        i = 0
        while i < len(seg) and ASSIGNMENT.fullmatch(seg[i]):
            name, value = seg[i].split("=", 1)
            if name == "PATH":
                local_path = parse_path_value(value)
            i += 1
        if i >= len(seg):
            continue
        command_word = seg[i]
        args = seg[i + 1:]
        if command_word in SAFE_BUILTINS:
            continue
        if command_word in UNSUPPORTED_COMMANDS:
            error("command:unsupported-wrapper")
        resolved = resolve_root_command(command_word, local_path, uid, dir_records)
        _resolved_rec, canonical_base = resolved_command_record(resolved)
        if canonical_base in UNSUPPORTED_COMMANDS or INTERPRETER_NAME.fullmatch(canonical_base) is not None:
            error("command:unsupported-execution-chain")
        add_target(resolved, targets, allow_nonexec=False)
        if canonical_base == "run-parts":
            expand_run_parts(args, targets, dir_records)


def parse_crontab(path, system_file, owner_user, users, sources, targets, dir_records):
    observed = stable_text(path, optional=False, allow_symlink=False)
    if observed[2] and not observed[2].endswith("\n"):
        error("cron:invalid-line-ending")
    sources[str(path)] = observed[:2]
    path_env = None
    jobs = 0
    for raw_line in observed[2].splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", raw_line)
        if m:
            name, value = m.group(1), m.group(2)
            if not ENV_NAME.fullmatch(name):
                error("cron:invalid-environment-name")
            if name == "PATH":
                path_env = parse_path_value(value)
            elif name == "SHELL":
                if parse_env_value(value) != "/bin/sh":
                    error("cron:unsupported-shell")
            continue
        user, command = cron_job(raw_line, system_file, owner_user, users)
        parse_shell(command, user, users, path_env, targets, dir_records)
        jobs += 1
    return jobs


def discover():
    passwd_obs, users = parse_passwd()
    sources = {str(map_abs("/etc/passwd")): passwd_obs[:2]}
    targets = {}
    dir_records = {}
    jobs = 0
    configs = 0

    etc_dir = stable_dir(map_abs("/etc"), optional=False)
    dir_records[("root", "/etc")] = etc_dir

    crontab_path = map_abs("/etc/crontab")
    if stable_regular(crontab_path, allow_symlink=False) is not None:
        jobs += parse_crontab(crontab_path, True, None, users, sources, targets, dir_records)
        configs += 1

    cron_d_path = map_abs("/etc/cron.d")
    cron_d = stable_dir(cron_d_path, optional=True)
    if cron_d is not None:
        dir_records[("root", "/etc/cron.d")] = cron_d
        for name in cron_d[1]:
            if CROND_NAME.fullmatch(name) is None:
                continue
            cfg = cron_d_path / name
            rec = stable_regular(cfg, allow_symlink=False)
            if rec is None:
                error("cron:config-disappeared")
            st = os.stat(cfg, follow_symlinks=False)
            if st.st_uid != logical_root_uid or stat.S_IMODE(st.st_mode) & 0o022:
                error("cron:config-untrusted")
            jobs += parse_crontab(cfg, True, None, users, sources, targets, dir_records)
            configs += 1

    spool_path = map_abs("/var/spool/cron/crontabs")
    spool = stable_dir(spool_path, optional=True)
    if spool is not None:
        dir_records[("root", "/var/spool/cron/crontabs")] = spool
        for name in spool[1]:
            if name not in users:
                continue
            cfg = spool_path / name
            rec = stable_regular(cfg, allow_symlink=False)
            if rec is None:
                error("cron:spool-disappeared")
            st = os.stat(cfg, follow_symlinks=False)
            if st.st_uid != users[name][0] or stat.S_IMODE(st.st_mode) & 0o022:
                error("cron:spool-untrusted")
            jobs += parse_crontab(cfg, False, name, users, sources, targets, dir_records)
            configs += 1

    violations = sum(1 for rec in targets.values() if rec[3][4] & 0o022)
    periodic = sum(1 for key in dir_records if key[0] == "run-parts")
    return sources, targets, dir_records, configs, jobs, periodic, violations


try:
    rst = os.lstat(fsroot)
except Exception:
    error("root:lstat-failed")
if stat.S_ISLNK(rst.st_mode):
    error("root:symlink")
if not stat.S_ISDIR(rst.st_mode):
    error("root:invalid-type")

first = discover()
second = discover()
if first != second:
    error("observation:changed-during-check")
_, targets, _, configs, jobs, periodic, violations = first
value = f"configs={configs};jobs={jobs};targets={len(targets)};periodic_dirs={periodic};violations={violations};ambiguous=0"
print("VALUE\t" + value + "\t" + ("PASS" if violations == 0 else "FAIL"))
SLP_CRON_PATHS_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "observer:execution-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR$'	'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "${_slp_obs#*$'	'}" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "observer:invalid-output" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_4_SUDO_ROOT_COMMAND_FILES_PROTECTION() {
  local _slp_cid='FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION' _slp_obs _slp_rc _slp_kind _slp_value _slp_compliance _slp_extra
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/' '0' '/etc/sudoers' '/etc/securelinux-policy/sudoers-reviewed-policy-v1' '/usr/sbin/visudo' '/usr/bin/cvtsudoers' <<'SLP_SUDO_ROOT_FILES_PY'
import hashlib, json, os, re, stat, subprocess, sys
from pathlib import Path

fsroot = Path(sys.argv[1])
logical_root_uid = int(sys.argv[2], 10)
sudoers_path = Path(sys.argv[3])
authority_path = Path(sys.argv[4])
visudo_path = sys.argv[5]
cvtsudoers_path = sys.argv[6]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_COMMAND_KEYS = {"command", "negated", "sha224", "sha256", "sha384", "sha512"}
WILDCARD_CHARS = set("*?[")
EXECUTION_FRONTENDS = {
    "env", "nice", "nohup", "timeout", "sudo", "su", "runuser", "chroot", "xargs", "find",
    "flock", "setsid", "stdbuf", "taskset", "ionice", "systemd-run", "start-stop-daemon",
    "busybox", "toybox", "time", "setpriv", "unshare", "nsenter", "prlimit", "setarch",
    "linux32", "linux64", "chrt", "watch", "strace", "ltrace", "gdb", "valgrind", "perf",
    "script", "daemon", "daemonize", "parallel", "numactl", "capsh", "firejail", "bwrap",
    "fakeroot", "torsocks", "proxychains", "proxychains4", "eatmydata", "sg", "newgrp",
    "docker", "podman", "systemd-nspawn", "machinectl", "run-parts",
}
INTERPRETER_NAME = re.compile(
    r"^(?:sh|ash|bash|dash|ksh|mksh|zsh|python(?:[0-9]+(?:\.[0-9]+)*)?|"
    r"perl(?:[0-9.]+)?|ruby(?:[0-9.]+)?|node(?:js)?(?:[0-9.]+)?|php(?:[0-9.]+)?|"
    r"lua(?:[0-9.]+)?|tclsh(?:[0-9.]+)?|wish(?:[0-9.]+)?|java|javaw|dotnet|mono|Rscript)$"
)


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def obj_state(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)


def stable_regular_bytes(path, domain):
    try:
        first = os.lstat(path)
    except Exception:
        error(domain + ":lstat-failed")
    if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):
        error(domain + ":invalid-type")
    try:
        raw = path.read_bytes()
        second = os.lstat(path)
    except Exception:
        error(domain + ":read-failed")
    if obj_state(first) != obj_state(second):
        error(domain + ":changed-during-check")
    return obj_state(first), raw


def parse_authority(raw):
    if not raw.endswith(b"\n") or b"\x00" in raw or b"\r" in raw:
        error("authority:invalid-bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error("authority:invalid-bytes")
    lines = text.splitlines()
    if not lines or lines[0] != "SLP-SUDOERS-REVIEWED-POLICY-V1":
        error("authority:invalid-header")
    out = {}
    for line in lines[1:]:
        if not line or line.count("\t") != 1:
            error("authority:invalid-record")
        digest, path = line.split("\t", 1)
        if HEX64.fullmatch(digest) is None or not path.startswith("/") or any(c in path for c in "\x00\r\n\t"):
            error("authority:invalid-record")
        if path in out:
            error("authority:duplicate-record")
        out[path] = digest
    if not out or str(sudoers_path) not in out:
        error("authority:incomplete")
    return out


def policy_snapshot():
    authority_state, authority_raw = stable_regular_bytes(authority_path, "authority")
    approved = parse_authority(authority_raw)
    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        proc = subprocess.run([visudo_path, "-c", "-f", str(sudoers_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, check=False)
    except Exception:
        error("visudo:execution-failed")
    if proc.returncode != 0:
        error("visudo:validation-failed")
    if not proc.stdout:
        error("visudo:invalid-output")
    if b"\x00" in proc.stdout or b"\r" in proc.stdout:
        error("visudo:invalid-bytes")
    try:
        text = proc.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error("visudo:invalid-bytes")
    actual = {}
    states = {}
    for line in text.splitlines():
        suffix = ": parsed OK"
        if not line.endswith(suffix):
            error("visudo:invalid-output")
        path_text = line[:-len(suffix)]
        if not path_text.startswith("/") or any(c in path_text for c in "\x00\r\n\t") or path_text in actual:
            error("visudo:invalid-output")
        path = Path(path_text)
        state, raw = stable_regular_bytes(path, "sudoers")
        actual[path_text] = hashlib.sha256(raw).hexdigest()
        states[path_text] = state
    if not actual or str(sudoers_path) not in actual:
        error("visudo:invalid-output")
    if actual != approved:
        error("authority:policy-mismatch")
    return (authority_state, hashlib.sha256(authority_raw).hexdigest(), tuple(sorted(actual.items())), tuple(sorted(states.items())))


def cvt_snapshot():
    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        proc = subprocess.run(
            [cvtsudoers_path, "-c", "/dev/null", "-e", "-s", "aliases", "-f", "json", str(sudoers_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False,
        )
    except Exception:
        error("cvtsudoers:execution-failed")
    if proc.returncode != 0 or proc.stderr:
        error("cvtsudoers:execution-failed")
    if not proc.stdout:
        error("cvtsudoers:invalid-output")
    if b"\x00" in proc.stdout:
        error("cvtsudoers:invalid-bytes")
    try:
        data = json.loads(proc.stdout.decode("utf-8", errors="strict"))
    except Exception:
        error("cvtsudoers:invalid-output")
    if not isinstance(data, dict) or set(data) - {"Defaults", "User_Specs"}:
        error("cvtsudoers:invalid-output")
    defaults = data.get("Defaults", [])
    specs = data.get("User_Specs", [])
    if not isinstance(defaults, list) or not isinstance(specs, list):
        error("cvtsudoers:invalid-output")
    return proc.stdout, defaults, specs


def reject_enabled_runchroot_options(options):
    if options is None:
        return
    if not isinstance(options, list):
        error("sudo-policy:invalid-options")
    for obj in options:
        if not isinstance(obj, dict):
            error("sudo-policy:invalid-options")
        if "runchroot" in obj:
            if set(obj) != {"runchroot"}:
                error("sudo-policy:runchroot-mixed-option")
            value = obj["runchroot"]
            if value is False:
                continue
            error("sudo-policy:runchroot-enabled")


def validate_defaults(defaults):
    for entry in defaults:
        if not isinstance(entry, dict) or set(entry) - {"Binding", "Options"} or "Options" not in entry:
            error("sudo-policy:invalid-defaults")
        binding = entry.get("Binding")
        if binding is not None and (not isinstance(binding, list) or not binding):
            error("sudo-policy:invalid-default-binding")
        options = entry["Options"]
        reject_enabled_runchroot_options(options)
        if not isinstance(options, list):
            error("sudo-policy:invalid-options")
        for obj in options:
            if not isinstance(obj, dict):
                error("sudo-policy:invalid-options")
            # sudoers runas_default changes the effective target user whenever a
            # Cmnd_Spec omits an explicit Runas_Spec.  v1 does not evaluate
            # Defaults binding precedence, so accepting such a policy could
            # classify a non-root command as root-runnable and false-FAIL its file.
            if "runas_default" in obj:
                error("sudo-policy:runas-default-unsupported")
            if "case_insensitive_user" in obj:
                error("sudo-policy:case-insensitive-user-unsupported")


def one_selector(obj, allowed):
    if not isinstance(obj, dict) or set(obj) - (allowed | {"negated"}):
        error("sudo-policy:ambiguous-selector")
    keys = [k for k in obj if k != "negated"]
    if len(keys) != 1 or not isinstance(obj.get("negated", False), bool):
        error("sudo-policy:ambiguous-selector")
    return keys[0], obj[keys[0]], obj.get("negated", False)


def ordinary_invoker_possible(user_list):
    if not isinstance(user_list, list) or not user_list:
        error("sudo-policy:invalid-user-list")
    ordinary = False
    allowed = {"netgroup", "nonunixgid", "nonunixgroup", "usergid", "usergroup", "userid", "username"}
    for obj in user_list:
        key, value, neg = one_selector(obj, allowed)
        # Membership- and negation-dependent selectors cannot be over-approximated
        # into a VALUE/FAIL population without risking a false FAIL.
        if neg or key not in {"username", "userid"}:
            error("sudo-policy:unsupported-user-selector")
        if key == "username":
            if not isinstance(value, str) or not value:
                error("sudo-policy:invalid-user-selector")
            if value.casefold() == "root":
                continue
            ordinary = True
            continue
        text = str(value)
        if not text.isdigit():
            error("sudo-policy:invalid-user-selector")
        if int(text, 10) != 0:
            ordinary = True
    return ordinary


def host_scope_supported(host_list):
    if not isinstance(host_list, list) or not host_list:
        error("sudo-policy:invalid-host-list")
    # v1 deliberately supports only an unconditional ALL host selector.  Correct
    # sudo hostname/network/netgroup matching depends on local host/network state;
    # treating a non-ALL selector as applicable would over-check another host and
    # could return a false FAIL.  Unsupported host qualification is therefore ERROR.
    if len(host_list) != 1:
        error("sudo-policy:ambiguous-host-selector")
    key, value, neg = one_selector(host_list[0], {"hostname", "networkaddr", "netgroup"})
    if neg or key != "hostname" or value != "ALL":
        error("sudo-policy:unsupported-host-selector")
    return True


def root_runas_possible(spec):
    if "runasusers" not in spec:
        return True
    runas = spec["runasusers"]
    if not isinstance(runas, list) or not runas:
        error("sudo-policy:invalid-runas-list")
    allowed = {"netgroup", "nonunixgid", "nonunixgroup", "runasalias", "usergid", "usergroup", "userid", "username"}
    root_possible = False
    for obj in runas:
        key, value, neg = one_selector(obj, allowed)
        # Group/netgroup membership and negated runas selectors are not resolved by
        # this adapter.  Do not over-approximate them into a FAIL-able population.
        if neg or key not in {"username", "userid"}:
            error("sudo-policy:unsupported-runas-selector")
        if key == "username":
            if not isinstance(value, str) or not value:
                error("sudo-policy:invalid-runas-selector")
            if value == "ALL" or value.casefold() == "root":
                root_possible = True
            continue
        text = str(value)
        if not text.isdigit():
            error("sudo-policy:invalid-runas-selector")
        if int(text, 10) == 0:
            root_possible = True
    return root_possible


def path_shape_ok(path):
    if not path.startswith("/") or path.endswith("/") or "\\" in path or any(c in path for c in WILDCARD_CHARS):
        return False
    parts = path.split("/")
    return not any(part in {".", ".."} for part in parts)


def executable_candidate(logical):
    if not path_shape_ok(logical):
        return False
    path = map_target(logical)
    try:
        st = os.stat(path, follow_symlinks=True)
    except FileNotFoundError:
        return False
    except Exception:
        error("target:stat-failed")
    return stat.S_ISREG(st.st_mode) and (stat.S_IMODE(st.st_mode) & 0o111) != 0


def logical_target(command):
    if not isinstance(command, str) or not command or any(c in command for c in "\x00\r\n"):
        error("sudo-policy:invalid-command")
    if command == "sudoedit" or command.startswith("sudoedit "):
        return None
    if command == "ALL":
        error("sudo-policy:all-command")
    if command.startswith("^"):
        error("sudo-policy:regex-command")
    if not command.startswith("/"):
        error("sudo-policy:nonabsolute-command")
    if any(c in command for c in WILDCARD_CHARS):
        error("sudo-policy:wildcard-command")
    if command.endswith("/"):
        error("sudo-policy:directory-command")

    # cvtsudoers JSON returns command path and arguments in one string and
    # unescapes whitespace inside a pathname.  Never split at the first blank:
    # enumerate every whitespace boundary plus the full string and accept only
    # one existing executable path prefix.  Zero or multiple candidates are
    # ambiguous and therefore ERROR.
    candidates = []
    boundaries = [i for i, ch in enumerate(command) if ch.isspace()] + [len(command)]
    for end in boundaries:
        candidate = command[:end]
        if candidate and executable_candidate(candidate):
            candidates.append(candidate)
    candidates = sorted(set(candidates), key=os.fsencode)
    if len(candidates) != 1:
        error("sudo-policy:ambiguous-command-path")
    return candidates[0]


def collect_targets(specs):
    targets = set()
    for user_spec in specs:
        if not isinstance(user_spec, dict) or set(user_spec) != {"User_List", "Host_List", "Cmnd_Specs"}:
            error("sudo-policy:invalid-user-spec")
        if not ordinary_invoker_possible(user_spec["User_List"]):
            continue
        host_scope_supported(user_spec["Host_List"])
        cmnd_specs = user_spec["Cmnd_Specs"]
        if not isinstance(cmnd_specs, list):
            error("sudo-policy:invalid-command-specs")
        for spec in cmnd_specs:
            if not isinstance(spec, dict) or "Commands" not in spec or set(spec) - {"Commands", "runasusers", "runasgroups", "Options"}:
                error("sudo-policy:invalid-command-spec")
            options = spec.get("Options")
            reject_enabled_runchroot_options(options)
            if options is not None:
                if not isinstance(options, list):
                    error("sudo-policy:invalid-command-options")
                for obj in options:
                    if not isinstance(obj, dict):
                        error("sudo-policy:invalid-command-options")
                    # NOTBEFORE/NOTAFTER are direct applicability predicates.
                    # v1 does not evaluate sudo generalized-time windows, so an
                    # inactive rule must never be over-checked into VALUE/FAIL.
                    if "notbefore" in obj or "notafter" in obj:
                        error("sudo-policy:time-qualified-command")
            if not root_runas_possible(spec):
                continue
            commands = spec["Commands"]
            if not isinstance(commands, list) or not commands:
                error("sudo-policy:invalid-command-list")
            for obj in commands:
                if not isinstance(obj, dict) or set(obj) - ALLOWED_COMMAND_KEYS:
                    error("sudo-policy:invalid-command-entry")
                if "command" not in obj or not isinstance(obj.get("negated", False), bool):
                    error("sudo-policy:invalid-command-entry")
                if any(key in obj for key in ("sha224", "sha256", "sha384", "sha512")):
                    # A sudo command digest is an applicability predicate.  v1 does
                    # not reimplement sudo digest syntax/matching, so including the
                    # pathname regardless of digest could over-check a command that
                    # is not runnable with the current bytes.
                    error("sudo-policy:digest-qualified-command")
                if obj.get("negated", False):
                    # Correct command-list override semantics are not reimplemented
                    # here; silently dropping a negation can over-check a target.
                    error("sudo-policy:negated-command")
                target = logical_target(obj["command"])
                if target is not None:
                    targets.add(target)
    return tuple(sorted(targets, key=os.fsencode))


def map_target(logical):
    return fsroot / logical.lstrip("/")


def stable_target(logical):
    path = map_target(logical)
    try:
        link_first = os.lstat(path)
        target_first = os.stat(path, follow_symlinks=True)
        resolved = os.path.realpath(path)
        link_second = os.lstat(path)
        target_second = os.stat(path, follow_symlinks=True)
    except Exception:
        error("target:snapshot-failed")
    if obj_state(link_first) != obj_state(link_second) or obj_state(target_first) != obj_state(target_second):
        error("target:changed-during-check")
    if not stat.S_ISREG(target_first.st_mode) or (stat.S_IMODE(target_first.st_mode) & 0o111) == 0:
        error("target:invalid-type")
    if fsroot != Path("/"):
        try:
            Path(resolved).relative_to(fsroot.resolve())
        except Exception:
            error("target:outside-root")
    canonical_base = Path(resolved).name
    if target_first.st_nlink != 1 or canonical_base in EXECUTION_FRONTENDS or INTERPRETER_NAME.fullmatch(canonical_base) is not None:
        error("target:unsupported-execution-chain")
    # A shebang script delegates privileged execution to another executable.
    # This v1 checker intentionally does not model recursive interpreter chains;
    # fail closed rather than returning PASS after checking only the script inode.
    fd = None
    try:
        fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        fd_state = os.fstat(fd)
        prefix = os.read(fd, 2)
    except Exception:
        error("target:read-failed")
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                error("target:close-failed")
    if obj_state(fd_state) != obj_state(target_first):
        error("target:changed-during-check")
    if prefix == b"#!":
        error("target:unsupported-execution-chain")
    return (logical, resolved, obj_state(link_first), obj_state(target_first))


policy_before = policy_snapshot()
cvt_before, defaults, specs = cvt_snapshot()
validate_defaults(defaults)
targets = collect_targets(specs)
records = {logical: stable_target(logical) for logical in targets}
owner_bad = 0
mode_bad = 0
for rec in records.values():
    state = rec[3]
    if state[2] != logical_root_uid:
        owner_bad += 1
    if state[4] & 0o022:
        mode_bad += 1
policy_after = policy_snapshot()
cvt_after, defaults_after, specs_after = cvt_snapshot()
validate_defaults(defaults_after)
if policy_after != policy_before or cvt_after != cvt_before or collect_targets(specs_after) != targets:
    error("observation:policy-changed")
for logical, before in records.items():
    if stable_target(logical) != before:
        error("observation:target-changed")
print(f"VALUE\tfiles={len(targets)};owner_violations={owner_bad};mode_violations={mode_bad}\t" + ("PASS" if owner_bad == 0 and mode_bad == 0 else "FAIL"))

SLP_SUDO_ROOT_FILES_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:execution-failed\tERROR\n' "$_slp_cid"; return 0; fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\t%s\tERROR\n' "$_slp_cid" "${_slp_obs#*$'\t'}"; return 0; fi
  IFS=$'\t' read -r _slp_kind _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ "$_slp_kind" != VALUE || -z "$_slp_value" || -n "$_slp_extra" || ( "$_slp_compliance" != PASS && "$_slp_compliance" != FAIL ) ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:invalid-output\tERROR\n' "$_slp_cid"; return 0; fi
  printf 'SLP-CHECK-V1\t%s\tVALUE\t%s\t%s\n' "$_slp_cid" "$_slp_value" "$_slp_compliance"
}

slp_check_FSTEC_LINUX_2022_2_3_5_STARTUP_FILES_WRITE_PROTECTION() {
  local _slp_obs _slp_status _slp_value _slp_compliance _slp_extra
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '["/etc/rc0.d","/etc/rc1.d","/etc/rc2.d","/etc/rc3.d","/etc/rc4.d","/etc/rc5.d","/etc/rc6.d"]' 'null' '/usr/bin/systemd-analyze' '0002' <<'SLP_STARTUP_FILES_PY'
import json, os, stat, subprocess, sys

rc_roots = json.loads(sys.argv[1])
unit_paths_override = json.loads(sys.argv[2])
systemd_analyze = sys.argv[3]
expected_mask = int(sys.argv[4], 8)


def emit_error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def state_lstat(path):
    st = os.lstat(path)
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def state_stat(path):
    st = os.stat(path, follow_symlinks=True)
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def dir_identity(path):
    st = os.stat(path, follow_symlinks=True)
    if not stat.S_ISDIR(st.st_mode):
        emit_error("directory:invalid-type")
    return (st.st_dev, st.st_ino)


def direct_names(root):
    try:
        names = []
        with os.scandir(root) as it:
            for ent in it:
                names.append(ent.name)
        names.sort(key=os.fsencode)
        return tuple(names)
    except Exception:
        emit_error("directory:scan-failed")


def direct_service_names(root):
    return tuple(x for x in direct_names(root) if x.endswith(".service"))


def resolve_candidate(path, service_role):
    try:
        first_l = state_lstat(path)
    except Exception:
        emit_error("target:lstat-failed")
    mode_type = first_l[4]
    if stat.S_ISDIR(mode_type):
        if service_role:
            emit_error("target:invalid-type")
        return ("directory", None, first_l, None)
    if stat.S_ISLNK(mode_type):
        try:
            target = os.path.realpath(path)
        except Exception:
            emit_error("target:resolve-failed")
        if service_role and os.path.normpath(target) == "/dev/null":
            try:
                if state_lstat(path) != first_l:
                    emit_error("target:changed-during-check")
            except Exception:
                emit_error("target:lstat-failed")
            resolution_snapshots[path] = target
            return ("masked", None, first_l, None)
        try:
            target_state = state_stat(target)
        except Exception:
            emit_error("target:stat-failed")
        if not stat.S_ISREG(target_state[4]):
            emit_error("target:invalid-type")
        resolution_snapshots[path] = target
        return ("regular", target, first_l, target_state)
    if stat.S_ISREG(mode_type):
        try:
            target_state = state_stat(path)
        except Exception:
            emit_error("target:stat-failed")
        return ("regular", path, first_l, target_state)
    emit_error("target:invalid-type")


def read_unit_paths():
    if unit_paths_override is not None:
        if not isinstance(unit_paths_override, list) or any(not isinstance(x, str) for x in unit_paths_override):
            emit_error("systemd:invalid-unit-paths")
        return tuple(unit_paths_override), None
    env = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    try:
        proc = subprocess.run([systemd_analyze, "unit-paths"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    except Exception:
        emit_error("systemd:execution-failed")
    if proc.returncode != 0:
        emit_error("systemd:execution-failed")
    if proc.stderr:
        emit_error("systemd:stderr-output")
    if not proc.stdout:
        emit_error("systemd:empty-output")
    if b"\x00" in proc.stdout or b"\r" in proc.stdout:
        emit_error("systemd:invalid-bytes")
    try:
        text = proc.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        emit_error("systemd:invalid-utf8")
    paths = []
    for line in text.splitlines():
        if not line.startswith("/") or "\x00" in line or "\r" in line or "\n" in line:
            emit_error("systemd:invalid-path")
        paths.append(line)
    if not paths:
        emit_error("systemd:empty-population")
    return tuple(paths), proc.stdout


unit_paths, unit_paths_raw = read_unit_paths()
initial_unit_paths = unit_paths
root_snapshots = {}
pop_snapshots = {}
entry_snapshots = {}
target_snapshots = {}
resolution_snapshots = {}
seen_root_ids = set()
seen_target_ids = set()

rc_roots_present = 0
rc_roots_absent = 0
rc_entries = 0
rc_directories = 0
rc_targets = 0
service_roots_present = 0
service_roots_absent = 0
service_root_aliases = 0
service_entries = 0
service_masked = 0
service_targets = 0
checked = 0
violations = 0


def remember_root_state(logical, resolved):
    try:
        root_snapshots[logical] = (os.path.lexists(logical), state_lstat(logical) if os.path.lexists(logical) else None, resolved, state_stat(resolved))
    except Exception:
        emit_error("root:snapshot-failed")


def remember_population(resolved, names, service_only):
    pop_snapshots[resolved] = (names, service_only)


def check_target(path, entry_path, entry_state, target_state, role):
    global checked, violations, rc_targets, service_targets
    ident = (target_state[0], target_state[1])
    if role == "rc":
        rc_targets += 1
    else:
        service_targets += 1
    entry_snapshots[entry_path] = entry_state
    target_snapshots[path] = target_state
    if ident in seen_target_ids:
        return
    seen_target_ids.add(ident)
    checked += 1
    if target_state[5] & expected_mask:
        violations += 1


# /etc/rc0.d ... /etc/rc6.d: direct file-like entries only; rcS.d is intentionally not in this population.
for logical in rc_roots:
    if not isinstance(logical, str) or not logical.startswith("/"):
        emit_error("root:invalid-path")
    exists = os.path.lexists(logical)
    if not exists:
        rc_roots_absent += 1
        root_snapshots[logical] = (False, None, None, None)
        continue
    try:
        resolved = os.path.realpath(logical)
        ident = dir_identity(resolved)
    except Exception:
        emit_error("root:resolve-failed")
    rc_roots_present += 1
    names = direct_names(resolved)
    remember_root_state(logical, resolved)
    remember_population(resolved, names, False)
    # rc roots are fixed distinct runlevel directories; aliasing two roots would make the source population ambiguous.
    if ident in seen_root_ids:
        emit_error("root:ambiguous-alias")
    seen_root_ids.add(ident)
    for name in names:
        path = os.path.join(resolved, name)
        kind, target, entry_state, target_state = resolve_candidate(path, False)
        if kind == "directory":
            rc_directories += 1
            continue
        rc_entries += 1
        check_target(target, path, entry_state, target_state, "rc")

# systemd unit load paths: scan only direct *.service entries. Dependency directories are references, not extra unit-file population.
for logical in unit_paths:
    if not isinstance(logical, str) or not logical.startswith("/"):
        emit_error("systemd:invalid-path")
    if not os.path.lexists(logical):
        service_roots_absent += 1
        root_snapshots.setdefault(logical, (False, None, None, None))
        continue
    try:
        resolved = os.path.realpath(logical)
        ident = dir_identity(resolved)
    except Exception:
        emit_error("root:resolve-failed")
    service_roots_present += 1
    remember_root_state(logical, resolved)
    if ident in seen_root_ids:
        service_root_aliases += 1
        continue
    seen_root_ids.add(ident)
    names = direct_service_names(resolved)
    remember_population(resolved, names, True)
    for name in names:
        service_entries += 1
        path = os.path.join(resolved, name)
        kind, target, entry_state, target_state = resolve_candidate(path, True)
        if kind == "masked":
            service_masked += 1
            entry_snapshots[path] = entry_state
            continue
        check_target(target, path, entry_state, target_state, "service")

# A fully observed empty .service population is vacuously compliant; discovery failures above are ERROR.

# End-of-observation stability: unit-path authority, roots, direct populations, entries and final targets must be unchanged.
if unit_paths_override is None:
    final_paths, final_raw = read_unit_paths()
    if final_paths != initial_unit_paths or final_raw != unit_paths_raw:
        emit_error("observation:unit-paths-changed")

for logical, snap in root_snapshots.items():
    was_present, logical_state, resolved, resolved_state = snap
    if not was_present:
        if os.path.lexists(logical):
            emit_error("observation:root-changed")
        continue
    try:
        if not os.path.lexists(logical) or state_lstat(logical) != logical_state or os.path.realpath(logical) != resolved or state_stat(resolved) != resolved_state:
            emit_error("observation:root-changed")
    except Exception:
        emit_error("observation:root-unreadable")

for resolved, snap in pop_snapshots.items():
    names, service_only = snap
    current = direct_service_names(resolved) if service_only else direct_names(resolved)
    if current != names:
        emit_error("observation:population-changed")

for path, snap in entry_snapshots.items():
    try:
        if state_lstat(path) != snap:
            emit_error("observation:entry-changed")
    except Exception:
        emit_error("observation:entry-unreadable")
for path, resolved in resolution_snapshots.items():
    try:
        if os.path.realpath(path) != resolved:
            emit_error("observation:resolution-changed")
    except Exception:
        emit_error("observation:resolution-failed")
for path, snap in target_snapshots.items():
    try:
        if state_stat(path) != snap:
            emit_error("observation:target-changed")
    except Exception:
        emit_error("observation:target-unreadable")

value = (
    f"rc_roots_present={rc_roots_present};rc_roots_absent={rc_roots_absent};rc_entries={rc_entries};"
    f"rc_directories={rc_directories};rc_targets={rc_targets};service_roots_present={service_roots_present};"
    f"service_roots_absent={service_roots_absent};service_root_aliases={service_root_aliases};"
    f"service_entries={service_entries};service_masked={service_masked};service_targets={service_targets};"
    f"checked={checked};violations={violations}"
)
print("VALUE\t" + value + "\t" + ("PASS" if violations == 0 else "FAIL"))

SLP_STARTUP_FILES_PY
  ) || { printf "%s\t%s\tERROR\tobserver:execution-failed\tERROR\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION'; return 0; }
  if [[ $_slp_obs == ERROR$'	'* ]]; then
    printf "%s\t%s\tERROR\t%s\tERROR\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION' "${_slp_obs#*$'\t'}"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<<"$_slp_obs"
  if [[ $_slp_status != VALUE || -n $_slp_extra || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) ]]; then
    printf "%s\t%s\tERROR\tobserver:invalid-output\tERROR\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION'
    return 0
  fi
  printf "%s\t%s\tVALUE\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION' "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_D() {
  local _slp_path='/etc/cron.d'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    if [[ ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:state-changed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_DAILY() {
  local _slp_path='/etc/cron.daily'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    if [[ ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:state-changed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_HOURLY() {
  local _slp_path='/etc/cron.hourly'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    if [[ ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:state-changed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_MONTHLY() {
  local _slp_path='/etc/cron.monthly'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    if [[ ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:state-changed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_WEEKLY() {
  local _slp_path='/etc/cron.weekly'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    if [[ ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:state-changed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRONTAB() {
  local _slp_path='/etc/crontab'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:parent-not-found" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:parent-invalid-type" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_parent" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:parent-unsearchable" "ERROR"
      return 0
    fi
    if [[ ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:state-changed" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:mode-read-failed" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:invalid-mode" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "root:invalid-type" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "target:symlink" "ERROR"
      return 0
    fi
    if [[ -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "target:invalid-type" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "target:mode-read-failed" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "target:invalid-mode" "ERROR"
      return 0
    fi
    ((_slp_checked+=1))
    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_7_USER_CRON_FILES_MODE() {
  local _slp_expected='0022' _slp_root _slp_probe _slp_entry _slp_mode _slp_scan_marker
  local _slp_find_rc _slp_sort_rc _slp_i
  local _slp_roots_present=0 _slp_roots_absent=0 _slp_checked=0 _slp_violations=0
  local -a _slp_roots=('/var/spool/cron/crontabs') _slp_entries=()
  local -A _slp_seen=()
  for _slp_root in "${_slp_roots[@]}"; do
    if [[ -L "$_slp_root" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:symlink" "ERROR"
      return 0
    fi
    if [[ ! -e "$_slp_root" ]]; then
      _slp_probe=$_slp_root
      while [[ $_slp_probe != / && ! -e "$_slp_probe" && ! -L "$_slp_probe" ]]; do
        _slp_probe=${_slp_probe%/*}
        [[ -n $_slp_probe ]] || _slp_probe=/
      done
      if [[ -L "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:ancestor-symlink" "ERROR"
        return 0
      fi
      if [[ ! -d "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:ancestor-invalid-type" "ERROR"
        return 0
      fi
      if [[ ! -x "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:ancestor-unsearchable" "ERROR"
        return 0
      fi
      ((_slp_roots_absent+=1))
      continue
    fi
    if [[ ! -d "$_slp_root" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-root:invalid-type" "ERROR"
      return 0
    fi
    ((_slp_roots_present+=1))
    _slp_entries=()
    mapfile -d '' -t _slp_entries < <(
      LC_ALL=C command /usr/bin/find -P -- "$_slp_root" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
      _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
      printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
    )
    if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "scan:missing-marker" "ERROR"
      return 0
    fi
    _slp_i=$((${#_slp_entries[@]}-1))
    _slp_scan_marker=${_slp_entries[$_slp_i]}
    unset '_slp_entries[$_slp_i]'
    if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "scan:invalid-marker" "ERROR"
      return 0
    fi
    _slp_find_rc=${BASH_REMATCH[1]}
    _slp_sort_rc=${BASH_REMATCH[2]}
    if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "scan:find-failed" "ERROR"
      return 0
    fi
    if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "scan:sort-failed" "ERROR"
      return 0
    fi
    for _slp_entry in "${_slp_entries[@]}"; do
      if [[ ${_slp_seen["$_slp_entry"]+x} ]]; then continue; fi
      _slp_seen["$_slp_entry"]=1
      if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-file:symlink" "ERROR"
        return 0
      fi
      if [[ -d "$_slp_entry" ]]; then continue; fi
      if [[ ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-file:invalid-type" "ERROR"
        return 0
      fi
      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-file:mode-read-failed" "ERROR"
        return 0
      fi
      if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "cron-file:invalid-mode" "ERROR"
        return 0
      fi
      ((_slp_checked+=1))
      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
    done
  done
  local _slp_value="roots_present=$_slp_roots_present;roots_absent=$_slp_roots_absent;checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_8_STANDARD_SYSTEM_PATHS_MODE() {
  local _slp_expected='0022' _slp_role _slp_root _slp_resolved _slp_root_id
  local _slp_entry _slp_name _slp_candidate _slp_mode _slp_ident _slp_target _slp_scan_marker
  local _slp_find_rc _slp_sort_rc _slp_i _slp_uname_r='' _slp_path_env='' _slp_path_part
  local _slp_roots_present=0 _slp_roots_absent=0 _slp_aliases=0
  local _slp_exec=0 _slp_libraries=0 _slp_modules=0 _slp_checked=0 _slp_violations=0
  local -a _slp_exec_roots=('/bin' '/sbin' '/usr/bin' '/usr/sbin') _slp_lib_roots=('/lib' '/lib64' '/usr/lib' '/usr/lib64' '/usr/local/lib' '/usr/local/lib64') _slp_entries=() _slp_path_roots=()
  local _slp_module_root='/lib/modules/<uname-r>'
  local -A _slp_seen_roots=() _slp_seen_targets=()
  if (( EUID != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "runtime:requires-root" "ERROR"
    return 0
  fi
  _slp_path_env=${PATH-}
  if [[ -z "$_slp_path_env" || "$_slp_path_env" == *$'\r'* || "$_slp_path_env" == *$'\n'* || "$_slp_path_env" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "path:invalid-environment" "ERROR"
    return 0
  fi
  IFS=: read -r -a _slp_path_roots <<< "$_slp_path_env"
  (( ${#_slp_path_roots[@]} > 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "path:empty-environment" "ERROR"; return 0; }
  for _slp_path_part in "${_slp_path_roots[@]}"; do
    [[ "$_slp_path_part" == /* ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "path:nonabsolute-entry" "ERROR"; return 0; }
    _slp_exec_roots+=("$_slp_path_part")
  done
  if ! _slp_uname_r=$(command /usr/bin/uname -r 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "kernel:release-query-failed" "ERROR"
    return 0
  fi
  if [[ -z $_slp_uname_r || $_slp_uname_r == *$'\n'* || $_slp_uname_r == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "kernel:invalid-release" "ERROR"
    return 0
  fi
  _slp_module_root=${_slp_module_root/<uname-r>/$_slp_uname_r}
  for _slp_role in exec lib module; do
    local -a _slp_role_roots=()
    case "$_slp_role" in
      exec) _slp_role_roots=("${_slp_exec_roots[@]}") ;;
      lib) _slp_role_roots=("${_slp_lib_roots[@]}") ;;
      module) _slp_role_roots=("$_slp_module_root") ;;
    esac
    for _slp_root in "${_slp_role_roots[@]}"; do
      if [[ ! -e "$_slp_root" && ! -L "$_slp_root" ]]; then
        ((_slp_roots_absent+=1))
        continue
      fi
      if ! _slp_resolved=$(command /usr/bin/readlink -f -- "$_slp_root" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "root:resolve-failed" "ERROR"
        return 0
      fi
      if [[ -z $_slp_resolved ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "root:resolve-empty" "ERROR"
        return 0
      fi
      if [[ ! -d "$_slp_resolved" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "root:invalid-type" "ERROR"
        return 0
      fi
      if ! _slp_root_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_resolved" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "root:identity-failed" "ERROR"
        return 0
      fi
      ((_slp_roots_present+=1))
      if [[ ${_slp_seen_roots["$_slp_root_id"]+x} ]]; then
        ((_slp_aliases+=1))
        continue
      fi
      _slp_seen_roots["$_slp_root_id"]=1
      _slp_entries=()
      mapfile -d "" -t _slp_entries < <(
        LC_ALL=C command /usr/bin/find -P -- "$_slp_resolved" -mindepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
        _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
        printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
      )
      if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "scan:missing-marker" "ERROR"
        return 0
      fi
      _slp_i=$((${#_slp_entries[@]}-1))
      _slp_scan_marker=${_slp_entries[$_slp_i]}
      unset '_slp_entries[$_slp_i]'
      if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "scan:invalid-marker" "ERROR"
        return 0
      fi
      _slp_find_rc=${BASH_REMATCH[1]}
      _slp_sort_rc=${BASH_REMATCH[2]}
      if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "scan:find-failed" "ERROR"
        return 0
      fi
      if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "scan:sort-failed" "ERROR"
        return 0
      fi
      for _slp_entry in "${_slp_entries[@]}"; do
        if [[ -d "$_slp_entry" && ! -L "$_slp_entry" ]]; then continue; fi
        _slp_name=${_slp_entry##*/}
        _slp_candidate=0
        case "$_slp_role:$_slp_name" in
          exec:*) _slp_candidate=1 ;;
          lib:*.so|lib:*.so.*|lib:*.a) _slp_candidate=1 ;;
          module:*.ko|module:*.ko.*) _slp_candidate=1 ;;
        esac
        (( _slp_candidate == 1 )) || continue
        if [[ -L "$_slp_entry" ]]; then
          if ! _slp_target=$(command /usr/bin/readlink -f -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "target:resolve-failed" "ERROR"
            return 0
          fi
          if [[ -z $_slp_target ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "target:resolve-empty" "ERROR"
            return 0
          fi
          if [[ -L "$_slp_target" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "target:resolved-symlink" "ERROR"
            return 0
          fi
          if [[ ! -f "$_slp_target" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "target:invalid-type" "ERROR"
            return 0
          fi
        elif [[ -f "$_slp_entry" ]]; then
          _slp_target=$_slp_entry
        else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "target:invalid-type" "ERROR"
          return 0
        fi
        if ! _slp_ident=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_target" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "target:identity-failed" "ERROR"
          return 0
        fi
        if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc %a -- "$_slp_target" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "target:mode-read-failed" "ERROR"
          return 0
        fi
        if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "target:invalid-mode" "ERROR"
          return 0
        fi
        if [[ "$_slp_role" == exec ]] && (( (8#$_slp_mode & 8#0111) == 0 )); then continue; fi
        if [[ ${_slp_seen_targets["$_slp_ident"]+x} ]]; then continue; fi
        _slp_seen_targets["$_slp_ident"]=1
        case "$_slp_role" in
          exec) ((_slp_exec+=1)) ;;
          lib) ((_slp_libraries+=1)) ;;
          module) ((_slp_modules+=1)) ;;
        esac
        ((_slp_checked+=1))
        if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
      done
    done
  done
  if (( _slp_exec == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "population:missing-exec" "ERROR"
    return 0
  fi
  if (( _slp_libraries == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "population:missing-libraries" "ERROR"
    return 0
  fi
  if (( _slp_modules == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "population:missing-modules" "ERROR"
    return 0
  fi
  local _slp_value="roots_present=$_slp_roots_present;roots_absent=$_slp_roots_absent;aliases=$_slp_aliases;exec=$_slp_exec;libraries=$_slp_libraries;modules=$_slp_modules;checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_ALLOWLIST() {
  local _slp_key='approved-set' _slp_op='subset-of-file' _slp_expected='/etc/securelinux-policy/suid-sgid.allowlist-v1'
  local _slp_mountinfo='/proc/self/mountinfo' _slp_line _slp_id _slp_parent _slp_majmin _slp_root _slp_mp_raw _slp_opts _slp_tail
  local _slp_mp _slp_after _slp_fstype _slp_root_id _slp_entry _slp_ident _slp_mode _slp_marker _slp_find_rc _slp_sort_rc _slp_i _slp_hex
  local _slp_mounts=0 _slp_checked=0 _slp_violations=0 _slp_extras=0 _slp_lineno=0
  local -a _slp_entries=()
  local -A _slp_seen_mounts=() _slp_seen_files=() _slp_allowed=()

  if [[ -L "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:unreadable" "ERROR"
    return 0
  fi
  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_mountinfo" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:read-failed" "ERROR"
    return 0
  fi
  if [[ "$_slp_hex" =~ (^|[[:space:]])00([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:invalid-bytes" "ERROR"
    return 0
  fi
  local _slp_allowlist="$_slp_expected" _slp_allow_line
  if [[ "$_slp_allowlist" != /* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "allowlist:invalid-path" "ERROR"
    return 0
  fi
  if [[ -L "$_slp_allowlist" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "allowlist:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_allowlist" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "allowlist:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_allowlist" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "allowlist:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_allowlist" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "allowlist:unreadable" "ERROR"
    return 0
  fi
  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_allowlist" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "allowlist:read-failed" "ERROR"
    return 0
  fi
  if [[ "$_slp_hex" =~ (^|[[:space:]])00([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "allowlist:invalid-bytes" "ERROR"
    return 0
  fi
  while IFS= read -r _slp_allow_line || [[ -n "$_slp_allow_line" ]]; do
    if [[ "$_slp_allow_line" == *$'\r'* || "$_slp_allow_line" == *$'\t'* || "$_slp_allow_line" == *$'\n'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "allowlist:invalid-record" "ERROR"
      return 0
    fi
    [[ -z "$_slp_allow_line" || "${_slp_allow_line:0:1}" == "#" ]] && continue
    if [[ "$_slp_allow_line" != /* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "allowlist:invalid-path" "ERROR"
      return 0
    fi
    if [[ ${_slp_allowed["$_slp_allow_line"]+x} ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "allowlist:duplicate-path" "ERROR"
      return 0
    fi
    _slp_allowed["$_slp_allow_line"]=1
  done < "$_slp_allowlist"
  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    ((_slp_lineno+=1))
    [[ -n "$_slp_line" ]] || continue
    IFS=" " read -r _slp_id _slp_parent _slp_majmin _slp_root _slp_mp_raw _slp_opts _slp_tail <<< "$_slp_line"
    if [[ -z "$_slp_id" || -z "$_slp_parent" || -z "$_slp_majmin" || -z "$_slp_root" || -z "$_slp_mp_raw" || -z "$_slp_opts" || -z "$_slp_tail" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:invalid-fields" "ERROR"
      return 0
    fi
    if [[ "$_slp_tail" == "- "* ]]; then
      _slp_after=${_slp_tail#- }
    elif [[ "$_slp_tail" == *" - "* ]]; then
      _slp_after=${_slp_tail#*" - "}
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:missing-separator" "ERROR"
      return 0
    fi
    _slp_fstype=${_slp_after%% *}
    [[ -n "$_slp_fstype" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:missing-fstype" "ERROR"; return 0; }
    case "$_slp_fstype" in
      proc|sysfs|devtmpfs|devpts|cgroup|cgroup2|securityfs|pstore|bpf|tracefs|debugfs|configfs|fusectl|mqueue|hugetlbfs|ramfs|autofs|binfmt_misc|nsfs|efivarfs) continue ;;
    esac
    printf -v _slp_mp "%b" "$_slp_mp_raw"
    if [[ "$_slp_mp" != /* || "$_slp_mp" == *$'\r'* || "$_slp_mp" == *$'\n'* || "$_slp_mp" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:invalid-mountpoint" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_mp" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:missing-mountpoint" "ERROR"
      return 0
    fi
    if ! _slp_root_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_mp" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:identity-failed" "ERROR"
      return 0
    fi
    if [[ ${_slp_seen_mounts["$_slp_root_id"]+x} ]]; then continue; fi
    _slp_seen_mounts["$_slp_root_id"]=1
    ((_slp_mounts+=1))
    _slp_entries=()
    mapfile -d "" -t _slp_entries < <(
      LC_ALL=C command /usr/bin/find -P -- "$_slp_mp" -xdev -type f -"per""m" /6000 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
      _slp_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
      printf "__SLP_SCAN_RC=%s\0" "$_slp_marker"
    )
    if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "scan:missing-marker" "ERROR"
      return 0
    fi
    _slp_i=$((${#_slp_entries[@]}-1))
    _slp_marker=${_slp_entries[$_slp_i]}
    unset '_slp_entries[$_slp_i]'
    if [[ ! "$_slp_marker" =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "scan:invalid-marker" "ERROR"
      return 0
    fi
    _slp_find_rc=${BASH_REMATCH[1]}
    _slp_sort_rc=${BASH_REMATCH[2]}
    if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "scan:find-failed" "ERROR"
      return 0
    fi
    if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "scan:sort-failed" "ERROR"
      return 0
    fi
    for _slp_entry in "${_slp_entries[@]}"; do
      if [[ "$_slp_entry" == *$'\r'* || "$_slp_entry" == *$'\n'* || "$_slp_entry" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "target:invalid-path" "ERROR"
        return 0
      fi
      if ! _slp_ident=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "target:identity-failed" "ERROR"
        return 0
      fi
      if [[ ${_slp_seen_files["$_slp_ident"]+x} ]]; then continue; fi
      _slp_seen_files["$_slp_ident"]=1
      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "target:mode-read-failed" "ERROR"
        return 0
      fi
      if [[ ! "$_slp_mode" =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "target:invalid-mode" "ERROR"
        return 0
      fi
      ((_slp_checked+=1))
      if [[ ! ${_slp_allowed["$_slp_entry"]+x} ]]; then ((_slp_extras+=1)); fi
    done
  done < "$_slp_mountinfo"
  if (( _slp_mounts == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "mountinfo:empty-population" "ERROR"
    return 0
  fi
  local _slp_value="mounts=$_slp_mounts;checked=$_slp_checked;extras=$_slp_extras"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "VALUE" "$_slp_value" "$([[ $_slp_extras -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_MODE() {
  local _slp_key='mode' _slp_op='bits-clear' _slp_expected='0022'
  local _slp_mountinfo='/proc/self/mountinfo' _slp_line _slp_id _slp_parent _slp_majmin _slp_root _slp_mp_raw _slp_opts _slp_tail
  local _slp_mp _slp_after _slp_fstype _slp_root_id _slp_entry _slp_ident _slp_mode _slp_marker _slp_find_rc _slp_sort_rc _slp_i _slp_hex
  local _slp_mounts=0 _slp_checked=0 _slp_violations=0 _slp_extras=0 _slp_lineno=0
  local -a _slp_entries=()
  local -A _slp_seen_mounts=() _slp_seen_files=() _slp_allowed=()

  if [[ -L "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:unreadable" "ERROR"
    return 0
  fi
  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_mountinfo" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:read-failed" "ERROR"
    return 0
  fi
  if [[ "$_slp_hex" =~ (^|[[:space:]])00([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:invalid-bytes" "ERROR"
    return 0
  fi
  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    ((_slp_lineno+=1))
    [[ -n "$_slp_line" ]] || continue
    IFS=" " read -r _slp_id _slp_parent _slp_majmin _slp_root _slp_mp_raw _slp_opts _slp_tail <<< "$_slp_line"
    if [[ -z "$_slp_id" || -z "$_slp_parent" || -z "$_slp_majmin" || -z "$_slp_root" || -z "$_slp_mp_raw" || -z "$_slp_opts" || -z "$_slp_tail" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:invalid-fields" "ERROR"
      return 0
    fi
    if [[ "$_slp_tail" == "- "* ]]; then
      _slp_after=${_slp_tail#- }
    elif [[ "$_slp_tail" == *" - "* ]]; then
      _slp_after=${_slp_tail#*" - "}
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:missing-separator" "ERROR"
      return 0
    fi
    _slp_fstype=${_slp_after%% *}
    [[ -n "$_slp_fstype" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:missing-fstype" "ERROR"; return 0; }
    case "$_slp_fstype" in
      proc|sysfs|devtmpfs|devpts|cgroup|cgroup2|securityfs|pstore|bpf|tracefs|debugfs|configfs|fusectl|mqueue|hugetlbfs|ramfs|autofs|binfmt_misc|nsfs|efivarfs) continue ;;
    esac
    printf -v _slp_mp "%b" "$_slp_mp_raw"
    if [[ "$_slp_mp" != /* || "$_slp_mp" == *$'\r'* || "$_slp_mp" == *$'\n'* || "$_slp_mp" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:invalid-mountpoint" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_mp" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:missing-mountpoint" "ERROR"
      return 0
    fi
    if ! _slp_root_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_mp" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:identity-failed" "ERROR"
      return 0
    fi
    if [[ ${_slp_seen_mounts["$_slp_root_id"]+x} ]]; then continue; fi
    _slp_seen_mounts["$_slp_root_id"]=1
    ((_slp_mounts+=1))
    _slp_entries=()
    mapfile -d "" -t _slp_entries < <(
      LC_ALL=C command /usr/bin/find -P -- "$_slp_mp" -xdev -type f -"per""m" /6000 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
      _slp_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
      printf "__SLP_SCAN_RC=%s\0" "$_slp_marker"
    )
    if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "scan:missing-marker" "ERROR"
      return 0
    fi
    _slp_i=$((${#_slp_entries[@]}-1))
    _slp_marker=${_slp_entries[$_slp_i]}
    unset '_slp_entries[$_slp_i]'
    if [[ ! "$_slp_marker" =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "scan:invalid-marker" "ERROR"
      return 0
    fi
    _slp_find_rc=${BASH_REMATCH[1]}
    _slp_sort_rc=${BASH_REMATCH[2]}
    if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "scan:find-failed" "ERROR"
      return 0
    fi
    if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "scan:sort-failed" "ERROR"
      return 0
    fi
    for _slp_entry in "${_slp_entries[@]}"; do
      if [[ "$_slp_entry" == *$'\r'* || "$_slp_entry" == *$'\n'* || "$_slp_entry" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "target:invalid-path" "ERROR"
        return 0
      fi
      if ! _slp_ident=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "target:identity-failed" "ERROR"
        return 0
      fi
      if [[ ${_slp_seen_files["$_slp_ident"]+x} ]]; then continue; fi
      _slp_seen_files["$_slp_ident"]=1
      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "target:mode-read-failed" "ERROR"
        return 0
      fi
      if [[ ! "$_slp_mode" =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "target:invalid-mode" "ERROR"
        return 0
      fi
      ((_slp_checked+=1))
      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
    done
  done < "$_slp_mountinfo"
  if (( _slp_mounts == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "mountinfo:empty-population" "ERROR"
    return 0
  fi
  local _slp_value="mounts=$_slp_mounts;checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_1_DMESG_RESTRICT() {
  local _slp_path='/proc/sys/kernel/dmesg_restrict'
  local _slp_expected='1'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_2_KPTR_RESTRICT() {
  local _slp_path='/proc/sys/kernel/kptr_restrict'
  local _slp_expected='2'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_3_INIT_ON_ALLOC() {
  local _slp_path='/proc/cmdline'
  local _slp_key='init_on_alloc'
  local _slp_expected='1'
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_4_SLAB_NOMERGE() {
  local _slp_path='/proc/cmdline'
  local _slp_key='slab_nomerge'
  local _slp_expected='true'
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_values > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:unexpected-value-form" "ERROR"
    return 0
  fi
  if (( _slp_bare > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "VALUE" "true" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "VALUE" "false" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_FORCE() {
  local _slp_path='/proc/cmdline'
  local _slp_key='iommu'
  local _slp_expected='force'
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_PASSTHROUGH() {
  local _slp_path='/proc/cmdline'
  local _slp_key='iommu.passthrough'
  local _slp_expected='0'
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_STRICT() {
  local _slp_path='/proc/cmdline'
  local _slp_key='iommu.strict'
  local _slp_expected='1'
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_6_RANDOMIZE_KSTACK_OFFSET() {
  local _slp_path='/proc/cmdline'
  local _slp_key='randomize_kstack_offset'
  local _slp_expected='1'
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_7_MITIGATIONS() {
  local _slp_path='/proc/cmdline'
  local _slp_key='mitigations'
  local _slp_expected='auto,nosmt'
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_8_BPF_JIT_HARDEN() {
  local _slp_path='/proc/sys/net/core/bpf_jit_harden'
  local _slp_expected='2'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_1_VSYSCALL() {
  local _slp_path='/proc/cmdline'
  local _slp_key='vsyscall'
  local _slp_expected='none'
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_10_MMAP_MIN_ADDR() {
  local _slp_path='/proc/sys/vm/mmap_min_addr'
  local _slp_expected='4096'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  if [[ $_slp_value == "$_slp_expected" ]]; then
    _slp_comp=PASS
  elif [[ $_slp_value == -* && $_slp_expected != -* ]]; then
    _slp_comp=FAIL
  elif [[ $_slp_value != -* && $_slp_expected == -* ]]; then
    _slp_comp=PASS
  else
    _slp_a=${_slp_value#-}
    _slp_b=${_slp_expected#-}
    _slp_negative=0
    [[ $_slp_value == -* ]] && _slp_negative=1
    if (( ${#_slp_a} != ${#_slp_b} )); then
      if (( _slp_negative == 0 )); then
        (( ${#_slp_a} > ${#_slp_b} )) && _slp_comp=PASS
      else
        (( ${#_slp_a} < ${#_slp_b} )) && _slp_comp=PASS
      fi
    else
      _slp_cmp=0
      _slp_i=0
      while (( _slp_i < ${#_slp_a} )); do
        _slp_ad=${_slp_a:_slp_i:1}
        _slp_bd=${_slp_b:_slp_i:1}
        if (( 10#$_slp_ad > 10#$_slp_bd )); then _slp_cmp=1; break; fi
        if (( 10#$_slp_ad < 10#$_slp_bd )); then _slp_cmp=-1; break; fi
        ((_slp_i+=1))
      done
      if (( _slp_negative == 0 )); then
        (( _slp_cmp >= 0 )) && _slp_comp=PASS
      else
        (( _slp_cmp <= 0 )) && _slp_comp=PASS
      fi
    fi
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_11_RANDOMIZE_VA_SPACE() {
  local _slp_path='/proc/sys/kernel/randomize_va_space'
  local _slp_expected='2'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_11_RANDOMIZE_VA_SPACE_TESTED_BEFORE_USE() {
  local _slp_authority='/etc/securelinux-policy/tested-setting-attestations-v1'
  local _slp_source_id='SRC-0034'
  local _slp_expected_setting='kernel.randomize_va_space=2'
  local _slp_line _slp_hex _slp_byte _slp_prev='' _slp_header='' _slp_row_re
  local _slp_rows=0 _slp_target_rows=0 _slp_setting_match=0 _slp_tested=0 _slp_line_no=0
  local -A _slp_seen=()
  _slp_row_re=$'^(SRC-[0-9]{4})\t([A-Za-z0-9_.-]+=-?[0-9]+)\t(TESTED-BEFORE-USE|NOT-TESTED-BEFORE-USE)$'

  if [[ -L "$_slp_authority" ]]; then
  printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_authority" ]]; then
  printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:not-found" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_authority" ]]; then
  printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_authority" ]]; then
  printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:unreadable" "ERROR"
    return 0
  fi
  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_authority" 2>/dev/null); then
  printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:read-failed" "ERROR"
    return 0
  fi
  for _slp_byte in $_slp_hex; do
    [[ "$_slp_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || { printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:invalid-hex" "ERROR"; return 0; }
    case "$_slp_byte" in
      09|0a) ;;
      00|01|02|03|04|05|06|07|08|0b|0c|0d|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f|7f) printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:invalid-bytes" "ERROR"; return 0 ;;
    esac
  done

  if ! IFS= read -r _slp_header < "$_slp_authority"; then
  printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:header-read-failed" "ERROR"
    return 0
  fi
  [[ "$_slp_header" == 'SLP-TESTED-SETTING-ATTESTATIONS-V1' ]] || { printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:invalid-header" "ERROR"; return 0; }

  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    ((_slp_line_no+=1))
    if (( _slp_line_no == 1 )); then [[ "$_slp_line" == "$_slp_header" ]] || { printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:header-drift" "ERROR"; return 0; }; continue; fi
    [[ -n "$_slp_line" ]] || { printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:empty-record" "ERROR"; return 0; }
    if [[ ! "$_slp_line" =~ $_slp_row_re ]]; then
  printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:invalid-record" "ERROR"
      return 0
    fi
    local _slp_sid=${BASH_REMATCH[1]} _slp_setting=${BASH_REMATCH[2]} _slp_state=${BASH_REMATCH[3]}
    [[ -z "${_slp_seen[$_slp_sid]+x}" ]] || { printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:duplicate-record" "ERROR"; return 0; }
    _slp_seen["$_slp_sid"]=1
    ((_slp_rows+=1))
    if [[ "$_slp_sid" == "$_slp_source_id" ]]; then
      ((_slp_target_rows+=1))
      [[ "$_slp_setting" == "$_slp_expected_setting" ]] && _slp_setting_match=1
      [[ "$_slp_state" == TESTED-BEFORE-USE ]] && _slp_tested=1
    fi
  done < "$_slp_authority"

  if (( _slp_target_rows != 1 )); then
  printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "ERROR" "authority:ambiguous-target" "ERROR"
    return 0
  fi
  local _slp_value="authority_rows=$_slp_rows;target_rows=$_slp_target_rows;setting_match=$_slp_setting_match;tested_before_use=$_slp_tested"
  if (( _slp_setting_match == 1 && _slp_tested == 1 )); then
  printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "VALUE" "$_slp_value" "PASS"
  else
  printf '%s\t%s\t%s\t%s\t%s\n' 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' "VALUE" "$_slp_value" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_2_PERF_EVENT_PARANOID() {
  local _slp_path='/proc/sys/kernel/perf_event_paranoid'
  local _slp_expected='3'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_3_DEBUGFS() {
  local _slp_path='/proc/cmdline'
  local _slp_key='debugfs'
  local _slp_expected='off|no-mount'
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  IFS='|' read -r -a _slp_choices <<< "$_slp_expected"
  for _slp_choice in "${_slp_choices[@]}"; do
    if [[ $_slp_first == "$_slp_choice" ]]; then
      _slp_comp=PASS
      break
    fi
  done
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_4_KEXEC_LOAD_DISABLED() {
  local _slp_path='/proc/sys/kernel/kexec_load_disabled'
  local _slp_expected='1'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_5_MAX_USER_NAMESPACES() {
  local _slp_path='/proc/sys/user/max_user_namespaces'
  local _slp_expected='0'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_6_UNPRIVILEGED_BPF_DISABLED() {
  local _slp_path='/proc/sys/kernel/unprivileged_bpf_disabled'
  local _slp_expected='1'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_7_UNPRIVILEGED_USERFAULTFD() {
  local _slp_path='/proc/sys/vm/unprivileged_userfaultfd'
  local _slp_expected='0'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_8_LDISC_AUTOLOAD() {
  local _slp_path='/proc/sys/dev/tty/ldisc_autoload'
  local _slp_expected='0'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_5_9_TSX() {
  local _slp_path='/proc/cmdline'
  local _slp_key='tsx'
  local _slp_expected='off'
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:read-failed" "ERROR"
    return 0
  fi
  IFS=$' \t\r\n' read -r -a _slp_tokens <<< "$_slp_raw"
  for _slp_token in "${_slp_tokens[@]}"; do
    if [[ $_slp_token == "$_slp_key" ]]; then
      ((_slp_bare+=1))
    elif [[ $_slp_token == "$_slp_key="* ]]; then
      _slp_value=${_slp_token#*=}
      if (( _slp_values == 0 )); then
        _slp_first=$_slp_value
      elif [[ $_slp_value != "$_slp_first" ]]; then
        _slp_conflict=1
      fi
      ((_slp_values+=1))
    fi
  done
  if (( _slp_bare > 0 || _slp_conflict > 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:ambiguous-value" "ERROR"
    return 0
  fi
  if (( _slp_values == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "VALUE" "<absent>" "FAIL"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "VALUE" "$_slp_first" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_1_PTRACE_SCOPE() {
  local _slp_path='/proc/sys/kernel/yama/ptrace_scope'
  local _slp_expected='3'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_2_PROTECTED_SYMLINKS() {
  local _slp_path='/proc/sys/fs/protected_symlinks'
  local _slp_expected='1'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_3_PROTECTED_HARDLINKS() {
  local _slp_path='/proc/sys/fs/protected_hardlinks'
  local _slp_expected='1'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_4_PROTECTED_FIFOS() {
  local _slp_path='/proc/sys/fs/protected_fifos'
  local _slp_expected='2'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_5_PROTECTED_REGULAR() {
  local _slp_path='/proc/sys/fs/protected_regular'
  local _slp_expected='2'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_6_6_SUID_DUMPABLE() {
  local _slp_path='/proc/sys/fs/suid_dumpable'
  local _slp_expected='0'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  _slp_validate_source_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    return 0
  }
  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:read-failed" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:invalid-value" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

SLP_SYSTEM_ID=''
SLP_SYSTEM_VERSION_ID=''
SLP_SYSTEM_PRETTY_NAME=''
SLP_SYSTEM_ARCH=''
SLP_SYSTEM_PROFILE=''
SLP_SYSTEM_TYPE=''
SLP_SYSTEM_PLATFORM=''
SLP_SYSTEM_ENVIRONMENT=''
SLP_CLASSIFY_REASON=''

slp_classify_dpkg_status() {
  local _slp_out=$1 _slp_want='' _slp_eflag='' _slp_status='' _slp_extra=''
  [[ $_slp_out != *$'\n'* && $_slp_out != *$'\r'* ]] || return 1
  IFS=' ' read -r _slp_want _slp_eflag _slp_status _slp_extra <<< "$_slp_out"
  [[ -n $_slp_want && -n $_slp_eflag && -n $_slp_status && -z $_slp_extra ]] || return 1
  case "$_slp_want" in
    unknown|install|hold|deinstall|purge) ;;
    *) return 1 ;;
  esac
  [[ $_slp_eflag == ok ]] || return 1
  case "$_slp_status" in
    installed) printf '%s' installed ;;
    not-installed|config-files) printf '%s' absent ;;
    *) return 1 ;;
  esac
}

slp_dpkg_package_state() {
  local _slp_pkg=$1 _slp_out='' _slp_rc=0
  [[ -x /usr/bin/dpkg-query ]] || return 1
  _slp_out=$(LC_ALL=C command /usr/bin/dpkg-query --root=/ --admindir=/var/lib/dpkg -W -f='${Status}' -- "$_slp_pkg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc == 0 )); then
    slp_classify_dpkg_status "$_slp_out"
    return $?
  fi
  if (( _slp_rc == 1 )); then
    printf '%s' absent
    return 0
  fi
  return 1
}

slp_classify_environment() {
  local _slp_id=$1 _slp_version=$2 _slp_arch=$3
  local _slp_server_minimal=$4 _slp_ubuntu_minimal=$5 _slp_ubuntu_standard=$6
  local _slp_profile='' _slp_type='' _slp_platform='' _slp_environment=''
  SLP_CLASSIFY_REASON=''
  SLP_SYSTEM_ID=$_slp_id
  SLP_SYSTEM_VERSION_ID=$_slp_version
  SLP_SYSTEM_ARCH=$_slp_arch
  SLP_SYSTEM_PROFILE=''
  SLP_SYSTEM_TYPE=''
  SLP_SYSTEM_PLATFORM=''
  SLP_SYSTEM_ENVIRONMENT=''
  if [[ $_slp_arch != x86_64 ]]; then
    SLP_CLASSIFY_REASON=PLATFORM
    return 3
  fi
  _slp_platform="$_slp_id-$_slp_version-$_slp_arch"
  case "$_slp_id:$_slp_version" in
    ubuntu:22.04|ubuntu:24.04|ubuntu:26.04)
      SLP_SYSTEM_PLATFORM=$_slp_platform
      if [[ $_slp_server_minimal == installed ]]; then
        if [[ $_slp_ubuntu_minimal == installed && $_slp_ubuntu_standard == installed ]]; then
          _slp_profile=FULL
        elif [[ $_slp_ubuntu_minimal == absent && $_slp_ubuntu_standard == absent ]]; then
          _slp_profile=MINIMIZED
        else
          SLP_SYSTEM_PROFILE=UNKNOWN
          SLP_CLASSIFY_REASON=PROFILE
          return 3
        fi
      elif [[ $_slp_server_minimal == absent && $_slp_ubuntu_minimal == installed && $_slp_ubuntu_standard == installed ]]; then
        if [[ $_slp_version == 24.04 ]]; then
          _slp_type=DESKTOP
        else
          SLP_SYSTEM_TYPE=UNKNOWN
          SLP_CLASSIFY_REASON=TYPE
          return 3
        fi
      else
        SLP_SYSTEM_TYPE=UNKNOWN
        SLP_CLASSIFY_REASON=TYPE
        return 3
      fi
      ;;
    debian:12|debian:13)
      _slp_profile=SERVER
      ;;
    *)
      SLP_CLASSIFY_REASON=PLATFORM
      return 3
      ;;
  esac
  if [[ -n $_slp_type ]]; then
    _slp_environment="$_slp_platform-${_slp_type,,}"
  else
    _slp_environment="$_slp_platform-${_slp_profile,,}"
  fi
  case "$_slp_environment" in
    'ubuntu-22.04-x86_64-full'|'ubuntu-24.04-x86_64-minimized'|'ubuntu-24.04-x86_64-full'|'ubuntu-26.04-x86_64-minimized'|'ubuntu-26.04-x86_64-full'|'debian-12-x86_64-server'|'debian-13-x86_64-server'|'ubuntu-24.04-x86_64-desktop') ;;
    *)
      if [[ -n $_slp_type ]]; then
        SLP_SYSTEM_TYPE=UNKNOWN
        SLP_CLASSIFY_REASON=TYPE
      else
        SLP_SYSTEM_PROFILE=UNKNOWN
        SLP_CLASSIFY_REASON=PROFILE
      fi
      SLP_SYSTEM_PLATFORM=$_slp_platform
      return 3
      ;;
  esac
  SLP_SYSTEM_PROFILE=$_slp_profile
  SLP_SYSTEM_TYPE=$_slp_type
  SLP_SYSTEM_PLATFORM=$_slp_platform
  SLP_SYSTEM_ENVIRONMENT=$_slp_environment
  return 0
}

slp_preflight_validate_text_bytes() {
  local _slp_v_path=$1 _slp_v_hex _slp_v_byte _slp_v_n=0
  local _slp_v_need=0 _slp_v_min=128 _slp_v_max=191
  if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
  for _slp_v_byte in $_slp_v_hex; do
    [[ $_slp_v_byte =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
    case "$_slp_v_byte" in
      00|01|02|03|04|05|06|07|08|09|0b|0c|0d|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f) return 1 ;;
    esac
    _slp_v_n=$((16#$_slp_v_byte))
    if (( _slp_v_need > 0 )); then
      (( _slp_v_n >= _slp_v_min && _slp_v_n <= _slp_v_max )) || return 1
      ((_slp_v_need-=1))
      _slp_v_min=128 _slp_v_max=191
      continue
    fi
    if (( _slp_v_n <= 127 )); then
      continue
    elif (( _slp_v_n >= 194 && _slp_v_n <= 223 )); then
      _slp_v_need=1
    elif (( _slp_v_n == 224 )); then
      _slp_v_need=2 _slp_v_min=160
    elif (( (_slp_v_n >= 225 && _slp_v_n <= 236) || (_slp_v_n >= 238 && _slp_v_n <= 239) )); then
      _slp_v_need=2
    elif (( _slp_v_n == 237 )); then
      _slp_v_need=2 _slp_v_max=159
    elif (( _slp_v_n == 240 )); then
      _slp_v_need=3 _slp_v_min=144
    elif (( _slp_v_n >= 241 && _slp_v_n <= 243 )); then
      _slp_v_need=3
    elif (( _slp_v_n == 244 )); then
      _slp_v_need=3 _slp_v_max=143
    else
      return 1
    fi
  done
  (( _slp_v_need == 0 )) || return 1
  return 0
}

SLP_OS_RELEASE_VALUE=''
SLP_OS_RELEASE_ID=''
SLP_OS_RELEASE_VERSION_ID=''
SLP_OS_RELEASE_PRETTY_NAME=''

slp_parse_os_release_value() {
  local LC_ALL=C
  local _slp_in=$1 _slp_mode=unquoted _slp_body='' _slp_out='' _slp_ch='' _slp_next=''
  local _slp_len=${#1}
  SLP_OS_RELEASE_VALUE=''
  if (( _slp_len > 0 )) && [[ ${_slp_in:0:1} == '"' ]]; then
    (( _slp_len >= 2 )) || return 1
    [[ ${_slp_in: -1} == '"' ]] || return 1
    _slp_mode=double
    _slp_body=${_slp_in:1:_slp_len-2}
  elif (( _slp_len > 0 )) && [[ ${_slp_in:0:1} == "'" ]]; then
    (( _slp_len >= 2 )) || return 1
    [[ ${_slp_in: -1} == "'" ]] || return 1
    _slp_mode=single
    _slp_body=${_slp_in:1:_slp_len-2}
  else
    _slp_body=$_slp_in
  fi
  if [[ $_slp_mode == single ]]; then
    [[ $_slp_body != *"'"* ]] || return 1
    SLP_OS_RELEASE_VALUE=$_slp_body
    return 0
  fi
  while [[ -n $_slp_body ]]; do
    _slp_ch=${_slp_body:0:1}
    _slp_body=${_slp_body:1}
    if [[ $_slp_ch == '\' ]]; then
      [[ -n $_slp_body ]] || return 1
      _slp_next=${_slp_body:0:1}
      if [[ $_slp_mode == double ]]; then
        case "$_slp_next" in
          '$'|'`'|'"'|'\') _slp_out+=$_slp_next; _slp_body=${_slp_body:1} ;;
          *) _slp_out+='\' ;;
        esac
      else
        _slp_out+=$_slp_next
        _slp_body=${_slp_body:1}
      fi
      continue
    fi
    if [[ $_slp_mode == double ]]; then
      case "$_slp_ch" in
        '"'|'$'|'`') return 1 ;;
      esac
    else
      case "$_slp_ch" in
        "'"|'"'|'$'|'`'|' '|$'\t'|';') return 1 ;;
      esac
    fi
    _slp_out+=$_slp_ch
  done
  SLP_OS_RELEASE_VALUE=$_slp_out
  return 0
}

slp_parse_os_release_file() {
  local _slp_p_path=$1 _slp_p_line='' _slp_p_key='' _slp_p_raw=''
  SLP_OS_RELEASE_ID=''
  SLP_OS_RELEASE_VERSION_ID=''
  SLP_OS_RELEASE_PRETTY_NAME=''
  while IFS= read -r _slp_p_line || [[ -n $_slp_p_line ]]; do
    [[ $_slp_p_line == *=* ]] || continue
    _slp_p_key=${_slp_p_line%%=*}
    case "$_slp_p_key" in
      ID|VERSION_ID|PRETTY_NAME)
        _slp_p_raw=${_slp_p_line#*=}
        slp_parse_os_release_value "$_slp_p_raw" || return 1
        case "$_slp_p_key" in
          ID) SLP_OS_RELEASE_ID=$SLP_OS_RELEASE_VALUE ;;
          VERSION_ID) SLP_OS_RELEASE_VERSION_ID=$SLP_OS_RELEASE_VALUE ;;
          PRETTY_NAME) SLP_OS_RELEASE_PRETTY_NAME=$SLP_OS_RELEASE_VALUE ;;
        esac
        ;;
    esac
  done < "$_slp_p_path"
  return 0
}

slp_target_preflight() {
  local _slp_id='' _slp_version='' _slp_pretty='' _slp_arch='' _slp_k _slp_v _slp_vrc=0
  local _slp_server_minimal=na _slp_ubuntu_minimal=na _slp_ubuntu_standard=na
  if [[ ! -r /etc/os-release ]]; then
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  fi
  slp_preflight_validate_text_bytes /etc/os-release; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  fi
  slp_parse_os_release_file /etc/os-release || {
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  }
  _slp_id=$SLP_OS_RELEASE_ID
  _slp_version=$SLP_OS_RELEASE_VERSION_ID
  _slp_pretty=$SLP_OS_RELEASE_PRETTY_NAME
  _slp_arch=$(command /usr/bin/uname -m 2>/dev/null) || {
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  }
  case "$_slp_id:$_slp_version:$_slp_arch" in
    ubuntu:22.04:x86_64|ubuntu:24.04:x86_64|ubuntu:26.04:x86_64|debian:12:x86_64|debian:13:x86_64) ;;
    *)
      printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
      return 3
      ;;
  esac
  if [[ $_slp_id == ubuntu ]]; then
    _slp_server_minimal=$(slp_dpkg_package_state ubuntu-server-minimal) || {
      printf '%s\n' 'UNSUPPORTED_PROFILE' >&2
      return 3
    }
    _slp_ubuntu_minimal=$(slp_dpkg_package_state ubuntu-minimal) || {
      printf '%s\n' 'UNSUPPORTED_PROFILE' >&2
      return 3
    }
    _slp_ubuntu_standard=$(slp_dpkg_package_state ubuntu-standard) || {
      printf '%s\n' 'UNSUPPORTED_PROFILE' >&2
      return 3
    }
  fi
  slp_classify_environment "$_slp_id" "$_slp_version" "$_slp_arch" \
    "$_slp_server_minimal" "$_slp_ubuntu_minimal" "$_slp_ubuntu_standard" || {
    case "$SLP_CLASSIFY_REASON" in
      PROFILE) printf '%s\n' 'UNSUPPORTED_PROFILE' >&2 ;;
      TYPE) printf '%s\n' 'UNSUPPORTED_TYPE' >&2 ;;
      *) printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2 ;;
    esac
    return 3
  }
  [[ -n $_slp_pretty ]] || _slp_pretty="$_slp_id $_slp_version"
  SLP_SYSTEM_PRETTY_NAME=$_slp_pretty
  return 0
}

slp_provenance_all() {
  command /usr/bin/cat <<'SLP_PROVENANCE_EOF'
{"adapter_contract_sha256":"25e210b2e5c31fc57733dbb0cd7d926be4b02b50ff2b84e48752128b4a755142","adapter_id":"product-local-account-password-state-check-v2","adapter_implementation_sha256":"718acd195fe11ab3f7890a64e4e52e250915046664e5b59ad7375f960c5f2642","control_id":"FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"82d8121586664ee803efec1f1b4bb93a248ce1f302bdf90a2561468ead86d802","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"all-nonempty","expected_type":"boolean","expected_value":true,"index_id":"SRC-0001","parameter_key":"password-field","parameter_kind":"local-account-password-state","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"8351b4431f8f6ddd403afb4315cf2f8b5ebcf3f8d9c38f91bb3778e5086593cc","source_locator":"2.1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"cf22028040e96aa92261265318590a3e4566bac97bd29c08cbf5c4cfd724ec38","adapter_id":"product-sshd-root-login-check-v1","adapter_implementation_sha256":"55f4b92f0fd15439ec1eabdd2db5cc0c91fecdaa583600386fb8667cac6cc96d","control_id":"FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"2f965f6e8901380f14088a167c77b07fc3b4c1872ac1f38865ba0a236a80b1de","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0002","parameter_key":"PermitRootLogin","parameter_kind":"sshd-root-login","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c671457700fd0fc656b34ccab9796a6b3b31a304492a26c3f317f0279e753785","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"5f22669198e49c77ca8062ff163e722924a199a4f6ece1e7fb7e4ce53966f400","source_locator":"2.1.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"2aad1cd3b8a9ddc7d2071b275c267b8f9bfbcb9bf4bf778ddfa7653f032fc57f","adapter_id":"product-pam-wheel-access-check-v2","adapter_implementation_sha256":"8c13be39ed0ea7c6b8e77f1596016fdc3dd23dfc467bec9fd37e9051582cb2b9","control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"d6771f8b26de807a96b62b7f4cbc84c4527e80798e0e00d5789598af5d36faba","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq-authority-file","expected_type":"string","expected_value":"/etc/securelinux-policy/wheel-users.allowlist-v1","index_id":"SRC-0003","parameter_key":"policy","parameter_kind":"pam-wheel-access","parameter_locator":"/etc/pam.d/su|/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"25dd0790262b44e6c787ec36df8c1aabb8b2f8f3e50d6c9bed83285c50c64c62","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"e068bafd196b4bc4204cca9143481a960e516823f8364fd4d17919afe5ab3d1c","source_locator":"2.2.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"e8aec8c2a7c3576a61f31408f49edecd8a42ffcde3389677e8c00c9834337dad","adapter_id":"product-sudoers-reviewed-policy-check-v1","adapter_implementation_sha256":"a7f8dae0cce8b28440652b5c4c50bc067b8c62ed742413afbdfedce85ab27eb8","control_id":"FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"179a59e8284a29ecedc7c7196ab3fb27d07e470bfd0f1989e5f6d6f11d63e90f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq-reviewed-policy","expected_type":"string","expected_value":"/etc/securelinux-policy/sudoers-reviewed-policy-v1","index_id":"SRC-0004","parameter_key":"policy-tree","parameter_kind":"sudoers-reviewed-policy","parameter_locator":"/etc/sudoers","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"779597efe81ae7d291d2b7b0883cffb5af1a56f0234919b0243f360e688babea","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"e77abc26b031bd6b4c3d95610513e39e8f392d06f7296ec34463dcda1dfa148c","source_locator":"2.2.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"0f5e967cc7124445b7cc11b057a3687067e4d9a7a32bfde4e567397d03c04bc8","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"a8e9548341c1ab2a91eb3a72d5267498ba9778884fa4c296bf4280c135a59d67","control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"719123c6ab9e5a26bd261a67aa2340ad1cf388ca3749db9c05b23f3079584a81","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"0f5e967cc7124445b7cc11b057a3687067e4d9a7a32bfde4e567397d03c04bc8","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"a8e9548341c1ab2a91eb3a72d5267498ba9778884fa4c296bf4280c135a59d67","control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"93faa0e6920c07e2f8e12b8326131e9dc52cf9b6145eafda75943d0eef1278b1","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/passwd","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"0f5e967cc7124445b7cc11b057a3687067e4d9a7a32bfde4e567397d03c04bc8","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"a8e9548341c1ab2a91eb3a72d5267498ba9778884fa4c296bf4280c135a59d67","control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"62efde1e39f219e843193c7bc5a2d539d685ab79c33094c05a70e3d21873e03f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"6ea805aee74f102c9c981b2b497c144f01aff27ef00cdbc491738dde303d1704","adapter_id":"product-home-sensitive-files-mode-check-v2","adapter_implementation_sha256":"950aa7e227af60e6e73103771e6aea599d817242e4f6ddffd13e53bb61496e33","control_id":"FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"673f3ccff153d0073310215ae70b6a2a0707e7f5e25d40eb65408de7eaf39e9a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0014","parameter_key":"mode","parameter_kind":"home-sensitive-files-mode","parameter_locator":"/etc/passwd|/etc/securelinux-policy/home-sensitive-files-v1","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f96bf7dbcff317e8f17e518541b380cd561614de1e0fa5414b1e9b2832d47868","source_locator":"2.3.10","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"91351c1091a5cff2f1b1292b166ed95e0afbdbc12be211a74030eeff946ab61f","adapter_id":"product-home-directories-mode-check-v2","adapter_implementation_sha256":"16db9d0ddc178b491d6e30c6b1e4f4ea33c83011b2fa73f6c9c268b858f3099e","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"cfc484e47c27914b409e4200315817f59eeb31775c438226377fead7e151162f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","parameter_key":"mode","parameter_kind":"home-directories-mode","parameter_locator":"/etc/passwd","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"653f327bc4370c196e86ab8f77f1dcc88b324c18fdc03a7124f926cb11e00243","source_locator":"2.3.11","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"c66a1cf45e2e59038c9890be11a1c025523c3abfabd2ea4cafaf4d98850a2edd","adapter_id":"product-running-process-paths-write-protection-check-v1","adapter_implementation_sha256":"a69c9f93cc7791266ce76a2e413b1d875fb3a8ad8dec39a555bf81b479e9e530","control_id":"FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"4c622265a9397061ef2edd2f99b6f90f78bf80aef8390f1cf129d8858daf76b3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"runtime-paths-safe","expected_type":"string","expected_value":"file-go-w;parent-unprivileged-write-denied","index_id":"SRC-0006","parameter_key":"write-protection","parameter_kind":"running-process-paths-write-protection","parameter_locator":"/proc/<pid>/exe|/proc/<pid>/maps","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f395bcd1e9dd9648161d6eac735f2b616c59c12e3d57a7cb1e9203cae2834aa5","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"cb1badc12483cb6b94a382e0d184c40e82a114ef6a8c4298a90e888697e5bff9","source_locator":"2.3.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"3ab815a36901a865a0b8adca67b582efbf36047b0b2288c6943aefda17945e82","adapter_id":"product-cron-command-paths-write-protection-check-v1","adapter_implementation_sha256":"645e9cff4343a55f2b13bb7415ff0bb100795feebdf12bf20d21b853dd9da2d1","control_id":"FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"aaab15a2454a7de6c5560aff10e367170706c6f47e6c5f879e46abe4fe9d6343","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"cron-command-paths-safe","expected_type":"string","expected_value":"file-go-w","index_id":"SRC-0007","parameter_key":"write-protection","parameter_kind":"cron-command-paths-write-protection","parameter_locator":"/etc/crontab|/etc/cron.d|/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"87a3b8a9ab953c58d4b04024444d5654019d1036eb0b424ddb3a87f621e68a7a","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"49d9c919fedbc012c9fd88ab2b1b65f24172df235a519b2b43b0c8e4dc3fc9c8","source_locator":"2.3.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"23b33fb8861ee01fe337175c690bd00753fdceb050deda9405612344ab641b52","adapter_id":"product-sudo-root-command-files-protection-check-v1","adapter_implementation_sha256":"18b4a601188878577d416cbbff8cefe754aefd4e04c79fefdda3a7bb08b264eb","control_id":"FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"e401b18ccf1ff851720d06d934edc9ec383a33fb3a671896cfa61999aa8627d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"root-owned-go-w","expected_type":"string","expected_value":"uid0;bits-clear-0022","index_id":"SRC-0008","parameter_key":"root-command-files","parameter_kind":"sudo-root-command-files-protection","parameter_locator":"/etc/sudoers|/etc/securelinux-policy/sudoers-reviewed-policy-v1","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0be87131f3aea07d4da4134cd82c960c608b16feff43b6996ea4817d9bb38dfe","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"97202dafa1c3ebc0fe8787519bcd5a976627a923e9c96564b22de6ea1574d35b","source_locator":"2.3.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"86d848929c2ec2873faf65f34c6e980cf59d58b83f95020bf869f8b81521a297","adapter_id":"product-startup-files-write-protection-check-v1","adapter_implementation_sha256":"0a0845beb56938f92f3a7a0a4393c43c360b4c1f69e94b0d8b1fdc6192cdf442","control_id":"FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"f06a42e88648b412e21b77a070622324e4d8f57694101263a8f47d2d1fd38194","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0002","index_id":"SRC-0009","parameter_key":"other-write","parameter_kind":"startup-files-write-protection","parameter_locator":"/etc/rc[0-6].d|systemd-unit-paths","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4a65bb314af3f2b4bb276e5b28cfd26b85b311d610553bd8e51bd26b1bfe8c6b","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"6098e676f64447097d2c3be5c44d30bb8f8bd2a379d3dba4fb9c38af88355737","source_locator":"2.3.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"d1dd9b4af5c49732ec93ac350d82fb138cb1fdc967396dda25062d59ff77527a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.d","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"a6c928414a1091aa8bf7291eee2e7574c9ad5f204831930d39a8536700f1731a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.daily","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"882eec0779eac5f5942f10e6670b2812f8000bf8f3e7600ba1c264362a8f4dce","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.hourly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"ca59fb02687823c843038099bd5698d42cd7d3cd402a22b4f0126bd89da42433","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.monthly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"62383ceb2d82745bdfeee36b424136c351b12d17ba430bf48b1706338a7c35e5","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.weekly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"043329e8aff8fa44762e5a2a22f6688c03bd30399dc78acb30821748d81d4fda","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/crontab","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"1428e2b90fb1e21f493c8c01ff5a631a7d58c1b7074b2eaedee358075da26877","adapter_id":"product-user-cron-files-mode-check-v2","adapter_implementation_sha256":"1efb24d36aec57592688472f8c2b0baadc23b32a5ca1f79fe018e3b5dcd4f0be","control_id":"FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"b5cb46dc92c854012b0a970a9d3c78febae83b29f28b3dfdc3bd80626ee5ac87","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0011","parameter_key":"mode","parameter_kind":"user-cron-files-mode","parameter_locator":"/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"af9430a9911e812b6f4b9735f35554d02e4203f7c39a3cae3d1c03004eb9adbe","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"1f1a6a01bc4a5f0b1ca8cf1d649a7e1c08b3667df2a8702134d56497950abc13","source_locator":"2.3.7","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"ae2dde5c930ce7e1a08ecf0c151a744bcd4a782fab55f4a7702d5274b4878c42","adapter_id":"product-standard-system-paths-mode-check-v2","adapter_implementation_sha256":"e021b632f1db643ab9f6349c777eefecc1defb0cc179376f7f476c825cf0b48e","control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"9f3041f0f9809cedcafb7f7e6b6b82641324902e34a3a84f9d24228af932cb1e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0012","parameter_key":"mode","parameter_kind":"standard-system-paths-mode","parameter_locator":"/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c14203a718160e12100efac4e8e4f748cdf7517bba948d7ee66d8811f2e462e3","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"1ea83595f910be4a5364dbe49d98ebf2b8eafb64446a3496f83830898fa223dc","source_locator":"2.3.8","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"2ee27cffe1cdd5cb211a9587079518e62107a6b74b5d4a297d5fa628a5584ed7","adapter_id":"product-suid-sgid-applications-check-v2","adapter_implementation_sha256":"be7899d602a64e14914412464e528df39fda09271afd3ae9f1effdb09ece34df","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"0c7c2ff2dbafa54b15440ce8f8d25173c174a28c8b1752804631a829c191a86c","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"subset-of-file","expected_type":"string","expected_value":"/etc/securelinux-policy/suid-sgid.allowlist-v1","index_id":"SRC-0013","parameter_key":"approved-set","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"9c0156d9705459d4c51a026e4abd0cc303ac0815eceb513c9a824b5ae281b708","source_locator":"2.3.9","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"2ee27cffe1cdd5cb211a9587079518e62107a6b74b5d4a297d5fa628a5584ed7","adapter_id":"product-suid-sgid-applications-check-v2","adapter_implementation_sha256":"be7899d602a64e14914412464e528df39fda09271afd3ae9f1effdb09ece34df","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"5e52002e72ea86d8c10dad28d09c82f0a027850ca4ae6e0d40745b7cdc33710b","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0013","parameter_key":"mode","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"9c0156d9705459d4c51a026e4abd0cc303ac0815eceb513c9a824b5ae281b708","source_locator":"2.3.9","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"51f99ed4b7c67eb30558176685885337c27a4d8c2047a8e667059dd2bbff07d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0016","parameter_key":"kernel.dmesg_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c889161dc17ca0ec538a88477aeebfd920e8d10a53d34952e69b12b24338a5e6","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"ba25c49b237cf91b74afcda02e15fd872e81c08973abd9719a8f4c465513aa9a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0017","parameter_key":"kernel.kptr_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"a4c2ba6bc1c18e8cc9a3b025cbf55b542e9cf327e3ce69fd2d8e4877bbc3ef60","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"68b4a5d37e9addc54b6c8d9316e1a9e47e4eda7cb0683b2df99c4be911c7ea5c","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0018","parameter_key":"init_on_alloc","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"817ddc5844c8600b30ea82b013576e8c90fe4381f37ff2d3e6f697766881aa9e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"present","expected_type":"boolean","expected_value":true,"index_id":"SRC-0019","parameter_key":"slab_nomerge","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"6a5c7fa4c5804ef3c2e152c338da6c73553bb8bce5dbde0331e4ba4db09d8b6f","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"595da19602209ab601375e129f45dfa720038e5a5b92017e51b5b7873bd6233d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"force","index_id":"SRC-0020","parameter_key":"iommu","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"85b3d67e7f741cfd9d50b3d935bc96ac38d6468d44cb18465baefa3379242942","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0","index_id":"SRC-0020","parameter_key":"iommu.passthrough","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"0d68a6bb3b7869e9d76046d196e61511e34560cfb55cf130b30c65b3b9d3e629","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0020","parameter_key":"iommu.strict","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"876b71fa1a3eabed4455db496c576c43ec897ccfe335266ae707b9bb976f124e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0021","parameter_key":"randomize_kstack_offset","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"69cbdb70f31aadd134129cae9eb95a96f836168646a821927cc3ea56ea58c980","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"2d004e6effde058bcd8d5713b8116adec36af1476da6e4f5acb1553d7857d981","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"auto,nosmt","index_id":"SRC-0022","parameter_key":"mitigations","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"593127f71a130fb574410cc9b249cf9ce42c1ec9698ebad648c79c4554d55ceb","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.7","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"cfe64060a4d9829351c2c6f19c6f41b0e0697bd8be5b503a90ffe27a5f4c52ee","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0023","parameter_key":"net.core.bpf_jit_harden","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ffeec17a621afd4726e6c0fcf0aef4fb1e22c86f45ca20d1d568471675c3914f","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.8","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"611d219ec1d517ebceb3539968662a6e40a75bb028fc553ec18eb9a95544f413","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"none","index_id":"SRC-0024","parameter_key":"vsyscall","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"909ac7e3825f234cf325dac5b9615486ef4c856315aeb9c25d4b7a6af47fa421","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"f2733434c77fa39bec5210262632becd3f0aad65ddb7423c869725fe95fa5655","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"ge","expected_type":"integer","expected_value":4096,"index_id":"SRC-0033","parameter_key":"vm.mmap_min_addr","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.10","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"4a08a7bfd4f6a803dfb7bbc2486a83bd2fe1e877dcaa2e9938d402ee9765ee6d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0034","parameter_key":"kernel.randomize_va_space","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.11","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"2e3a3ec6753d880dea9aa0c3b7ac0dfc7b6e88238aed4e767293f1130613bace","adapter_id":"product-tested-setting-attestation-check-v1","adapter_implementation_sha256":"5f4a7345ef3863aacaef0c42780fbbbed1ce726c21773ce04760f462724231f3","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"c301ab7c5f08b0822aa61c955d00bdbec607f8188ce4fbe8d88ad0b756a293c0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"tested-before-use","expected_type":"string","expected_value":"kernel.randomize_va_space=2","index_id":"SRC-0034","parameter_key":"SRC-0034","parameter_kind":"tested-setting-attestation","parameter_locator":"/etc/securelinux-policy/tested-setting-attestations-v1","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"d15d7e89982de63578337429b97a429ecad136c8a8f39f5ba218cce5597193c7","source_locator":"2.5.11","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"b0eb7068712e20660c0d84871c271c6f3fdc542132cca1cf529910dcf7f85c0a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0025","parameter_key":"kernel.perf_event_paranoid","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8e6f4b120bd3527b380251e92eca56e1b4c358d362f1246357579eb8af616382","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"806da488a05c5d4ea11c2cef4bbde3b327387c1b96b143fe97c32e50e08a8894","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"one-of","expected_type":"string","expected_value":"off|no-mount","index_id":"SRC-0026","parameter_key":"debugfs","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"10391c151e6a53e91d637a11bc0f87a05a1ca7fdd408f9493dd27b366da46184","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"6006fdfb164b8a8860b8f4ae6d4e2758799f25ed32d53e185916da0ef0b7ed01","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0027","parameter_key":"kernel.kexec_load_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0231e3c8de27fab8de667f632bf6d08609a7c62836be9c787fd4cb955974ff09","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"b13b0e0b47c820d396a9a4a8d044ffdfc4eb779c5def2347c072cbc9e3900f32","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0028","parameter_key":"user.max_user_namespaces","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"77edbfb78e01426b6c40ccedca310ff6091870e235d4225ac488f4cd5d8c090c","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"44423cf2e57eabddd637a973430a6633282f8eba658430a1290bfa610efe5b67","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0029","parameter_key":"kernel.unprivileged_bpf_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"1c320abae9872972364ef95685204f4968a2c84bc27ee9c2707907eac8c5823e","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"3a5a2c1c560d688eeea441f4455297a86983c599745acf8963507f91b72c86f4","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0030","parameter_key":"vm.unprivileged_userfaultfd","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"cba35949a04f5d3dab8bd9a0501d75e5c310773ac11c1ad2c4d80845cdd03080","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.7","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"d6e4d8f63a5235ff32f3cb429c91caa7b7ff7864ba8ab90f8fd350362e8d3a69","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0031","parameter_key":"dev.tty.ldisc_autoload","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0860efcf66e2da819b06b5d6198e3b4c9b4ea96b66929752aceba65fae301783","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.8","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.5.9-TSX","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"07040e8445ac0565a587fcf6cfadf124a45b6b076592d4a268eff2abe37b5ef3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"off","index_id":"SRC-0032","parameter_key":"tsx","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"40b0ad985774f12adad55439e22a5ba29b3a2c50c9fedd16551fa261fd29464c","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.9","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"2bc9bb0cb5372fb5738612ff3738526cad9adb831b0043cc5924f36d23e7ca37","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0035","parameter_key":"kernel.yama.ptrace_scope","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"7be4210587e64fe1864bfbf1b5e8f7cc3512434629eb17898ad487d50a9ae246","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"b709581e94eb65e5a059d70ff4ec7aac7d248e6b664ffb42c502e23c88e2bbe8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0036","parameter_key":"fs.protected_symlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ce09b5104160f3fe27f17f1d5e57a5fe81001adac3c362ed652552ccbc59571f","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"fc1fd0f1141cb6d78b5d322e6a04b2649f0264a5e8c4784c64116bed55d70ffa","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0037","parameter_key":"fs.protected_hardlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"315736677a4e3192cde79d4badbf20809da81c8605785c8720fcd0fc3260fe97","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"af3b312efb3d252c1752a9ee70da6248e2a8e86f2e29479388206afbfbcd453d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0038","parameter_key":"fs.protected_fifos","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016aaaf884c10febb3e99a86acfcbe63eae04f05f5fcf35a00c59f03fb30a31b","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"677905dff8f0fa0db1c82008b7b3acc0456dd61c46db0008390ab99f89ef9d92","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0039","parameter_key":"fs.protected_regular","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0f1eea51ec98d254f230a48dfc4950cb060e11460e1f30be68fde3fb9439cb14","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"35c1fe8f6a4591fdf5b7d25f4dff6b244b868fbc1514498a7b55f9a321ddda8f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0040","parameter_key":"fs.suid_dumpable","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.6","target_id":"linux-x86_64-supported-v1"}
SLP_PROVENANCE_EOF
}

slp_provenance_one() {
  case "$1" in
    'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE') printf '%s\n' '{"adapter_contract_sha256":"25e210b2e5c31fc57733dbb0cd7d926be4b02b50ff2b84e48752128b4a755142","adapter_id":"product-local-account-password-state-check-v2","adapter_implementation_sha256":"718acd195fe11ab3f7890a64e4e52e250915046664e5b59ad7375f960c5f2642","control_id":"FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"82d8121586664ee803efec1f1b4bb93a248ce1f302bdf90a2561468ead86d802","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"all-nonempty","expected_type":"boolean","expected_value":true,"index_id":"SRC-0001","parameter_key":"password-field","parameter_kind":"local-account-password-state","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"8351b4431f8f6ddd403afb4315cf2f8b5ebcf3f8d9c38f91bb3778e5086593cc","source_locator":"2.1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN') printf '%s\n' '{"adapter_contract_sha256":"cf22028040e96aa92261265318590a3e4566bac97bd29c08cbf5c4cfd724ec38","adapter_id":"product-sshd-root-login-check-v1","adapter_implementation_sha256":"55f4b92f0fd15439ec1eabdd2db5cc0c91fecdaa583600386fb8667cac6cc96d","control_id":"FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"2f965f6e8901380f14088a167c77b07fc3b4c1872ac1f38865ba0a236a80b1de","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0002","parameter_key":"PermitRootLogin","parameter_kind":"sshd-root-login","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c671457700fd0fc656b34ccab9796a6b3b31a304492a26c3f317f0279e753785","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"5f22669198e49c77ca8062ff163e722924a199a4f6ece1e7fb7e4ce53966f400","source_locator":"2.1.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS') printf '%s\n' '{"adapter_contract_sha256":"2aad1cd3b8a9ddc7d2071b275c267b8f9bfbcb9bf4bf778ddfa7653f032fc57f","adapter_id":"product-pam-wheel-access-check-v2","adapter_implementation_sha256":"8c13be39ed0ea7c6b8e77f1596016fdc3dd23dfc467bec9fd37e9051582cb2b9","control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"d6771f8b26de807a96b62b7f4cbc84c4527e80798e0e00d5789598af5d36faba","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq-authority-file","expected_type":"string","expected_value":"/etc/securelinux-policy/wheel-users.allowlist-v1","index_id":"SRC-0003","parameter_key":"policy","parameter_kind":"pam-wheel-access","parameter_locator":"/etc/pam.d/su|/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"25dd0790262b44e6c787ec36df8c1aabb8b2f8f3e50d6c9bed83285c50c64c62","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"e068bafd196b4bc4204cca9143481a960e516823f8364fd4d17919afe5ab3d1c","source_locator":"2.2.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY') printf '%s\n' '{"adapter_contract_sha256":"e8aec8c2a7c3576a61f31408f49edecd8a42ffcde3389677e8c00c9834337dad","adapter_id":"product-sudoers-reviewed-policy-check-v1","adapter_implementation_sha256":"a7f8dae0cce8b28440652b5c4c50bc067b8c62ed742413afbdfedce85ab27eb8","control_id":"FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"179a59e8284a29ecedc7c7196ab3fb27d07e470bfd0f1989e5f6d6f11d63e90f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq-reviewed-policy","expected_type":"string","expected_value":"/etc/securelinux-policy/sudoers-reviewed-policy-v1","index_id":"SRC-0004","parameter_key":"policy-tree","parameter_kind":"sudoers-reviewed-policy","parameter_locator":"/etc/sudoers","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"779597efe81ae7d291d2b7b0883cffb5af1a56f0234919b0243f360e688babea","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"e77abc26b031bd6b4c3d95610513e39e8f392d06f7296ec34463dcda1dfa148c","source_locator":"2.2.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.1-GROUP-MODE') printf '%s\n' '{"adapter_contract_sha256":"0f5e967cc7124445b7cc11b057a3687067e4d9a7a32bfde4e567397d03c04bc8","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"a8e9548341c1ab2a91eb3a72d5267498ba9778884fa4c296bf4280c135a59d67","control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"719123c6ab9e5a26bd261a67aa2340ad1cf388ca3749db9c05b23f3079584a81","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE') printf '%s\n' '{"adapter_contract_sha256":"0f5e967cc7124445b7cc11b057a3687067e4d9a7a32bfde4e567397d03c04bc8","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"a8e9548341c1ab2a91eb3a72d5267498ba9778884fa4c296bf4280c135a59d67","control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"93faa0e6920c07e2f8e12b8326131e9dc52cf9b6145eafda75943d0eef1278b1","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/passwd","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX') printf '%s\n' '{"adapter_contract_sha256":"0f5e967cc7124445b7cc11b057a3687067e4d9a7a32bfde4e567397d03c04bc8","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"a8e9548341c1ab2a91eb3a72d5267498ba9778884fa4c296bf4280c135a59d67","control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"62efde1e39f219e843193c7bc5a2d539d685ab79c33094c05a70e3d21873e03f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE') printf '%s\n' '{"adapter_contract_sha256":"6ea805aee74f102c9c981b2b497c144f01aff27ef00cdbc491738dde303d1704","adapter_id":"product-home-sensitive-files-mode-check-v2","adapter_implementation_sha256":"950aa7e227af60e6e73103771e6aea599d817242e4f6ddffd13e53bb61496e33","control_id":"FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"673f3ccff153d0073310215ae70b6a2a0707e7f5e25d40eb65408de7eaf39e9a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0014","parameter_key":"mode","parameter_kind":"home-sensitive-files-mode","parameter_locator":"/etc/passwd|/etc/securelinux-policy/home-sensitive-files-v1","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f96bf7dbcff317e8f17e518541b380cd561614de1e0fa5414b1e9b2832d47868","source_locator":"2.3.10","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE') printf '%s\n' '{"adapter_contract_sha256":"91351c1091a5cff2f1b1292b166ed95e0afbdbc12be211a74030eeff946ab61f","adapter_id":"product-home-directories-mode-check-v2","adapter_implementation_sha256":"16db9d0ddc178b491d6e30c6b1e4f4ea33c83011b2fa73f6c9c268b858f3099e","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"cfc484e47c27914b409e4200315817f59eeb31775c438226377fead7e151162f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","parameter_key":"mode","parameter_kind":"home-directories-mode","parameter_locator":"/etc/passwd","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"653f327bc4370c196e86ab8f77f1dcc88b324c18fdc03a7124f926cb11e00243","source_locator":"2.3.11","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"c66a1cf45e2e59038c9890be11a1c025523c3abfabd2ea4cafaf4d98850a2edd","adapter_id":"product-running-process-paths-write-protection-check-v1","adapter_implementation_sha256":"a69c9f93cc7791266ce76a2e413b1d875fb3a8ad8dec39a555bf81b479e9e530","control_id":"FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"4c622265a9397061ef2edd2f99b6f90f78bf80aef8390f1cf129d8858daf76b3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"runtime-paths-safe","expected_type":"string","expected_value":"file-go-w;parent-unprivileged-write-denied","index_id":"SRC-0006","parameter_key":"write-protection","parameter_kind":"running-process-paths-write-protection","parameter_locator":"/proc/<pid>/exe|/proc/<pid>/maps","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f395bcd1e9dd9648161d6eac735f2b616c59c12e3d57a7cb1e9203cae2834aa5","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"cb1badc12483cb6b94a382e0d184c40e82a114ef6a8c4298a90e888697e5bff9","source_locator":"2.3.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"3ab815a36901a865a0b8adca67b582efbf36047b0b2288c6943aefda17945e82","adapter_id":"product-cron-command-paths-write-protection-check-v1","adapter_implementation_sha256":"645e9cff4343a55f2b13bb7415ff0bb100795feebdf12bf20d21b853dd9da2d1","control_id":"FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"aaab15a2454a7de6c5560aff10e367170706c6f47e6c5f879e46abe4fe9d6343","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"cron-command-paths-safe","expected_type":"string","expected_value":"file-go-w","index_id":"SRC-0007","parameter_key":"write-protection","parameter_kind":"cron-command-paths-write-protection","parameter_locator":"/etc/crontab|/etc/cron.d|/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"87a3b8a9ab953c58d4b04024444d5654019d1036eb0b424ddb3a87f621e68a7a","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"49d9c919fedbc012c9fd88ab2b1b65f24172df235a519b2b43b0c8e4dc3fc9c8","source_locator":"2.3.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"23b33fb8861ee01fe337175c690bd00753fdceb050deda9405612344ab641b52","adapter_id":"product-sudo-root-command-files-protection-check-v1","adapter_implementation_sha256":"18b4a601188878577d416cbbff8cefe754aefd4e04c79fefdda3a7bb08b264eb","control_id":"FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"e401b18ccf1ff851720d06d934edc9ec383a33fb3a671896cfa61999aa8627d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"root-owned-go-w","expected_type":"string","expected_value":"uid0;bits-clear-0022","index_id":"SRC-0008","parameter_key":"root-command-files","parameter_kind":"sudo-root-command-files-protection","parameter_locator":"/etc/sudoers|/etc/securelinux-policy/sudoers-reviewed-policy-v1","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0be87131f3aea07d4da4134cd82c960c608b16feff43b6996ea4817d9bb38dfe","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"97202dafa1c3ebc0fe8787519bcd5a976627a923e9c96564b22de6ea1574d35b","source_locator":"2.3.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"86d848929c2ec2873faf65f34c6e980cf59d58b83f95020bf869f8b81521a297","adapter_id":"product-startup-files-write-protection-check-v1","adapter_implementation_sha256":"0a0845beb56938f92f3a7a0a4393c43c360b4c1f69e94b0d8b1fdc6192cdf442","control_id":"FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"f06a42e88648b412e21b77a070622324e4d8f57694101263a8f47d2d1fd38194","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0002","index_id":"SRC-0009","parameter_key":"other-write","parameter_kind":"startup-files-write-protection","parameter_locator":"/etc/rc[0-6].d|systemd-unit-paths","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4a65bb314af3f2b4bb276e5b28cfd26b85b311d610553bd8e51bd26b1bfe8c6b","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"6098e676f64447097d2c3be5c44d30bb8f8bd2a379d3dba4fb9c38af88355737","source_locator":"2.3.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-D') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"d1dd9b4af5c49732ec93ac350d82fb138cb1fdc967396dda25062d59ff77527a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.d","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-DAILY') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"a6c928414a1091aa8bf7291eee2e7574c9ad5f204831930d39a8536700f1731a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.daily","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"882eec0779eac5f5942f10e6670b2812f8000bf8f3e7600ba1c264362a8f4dce","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.hourly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"ca59fb02687823c843038099bd5698d42cd7d3cd402a22b4f0126bd89da42433","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.monthly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"62383ceb2d82745bdfeee36b424136c351b12d17ba430bf48b1706338a7c35e5","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.weekly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRONTAB') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"043329e8aff8fa44762e5a2a22f6688c03bd30399dc78acb30821748d81d4fda","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/crontab","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE') printf '%s\n' '{"adapter_contract_sha256":"1428e2b90fb1e21f493c8c01ff5a631a7d58c1b7074b2eaedee358075da26877","adapter_id":"product-user-cron-files-mode-check-v2","adapter_implementation_sha256":"1efb24d36aec57592688472f8c2b0baadc23b32a5ca1f79fe018e3b5dcd4f0be","control_id":"FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"b5cb46dc92c854012b0a970a9d3c78febae83b29f28b3dfdc3bd80626ee5ac87","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0011","parameter_key":"mode","parameter_kind":"user-cron-files-mode","parameter_locator":"/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"af9430a9911e812b6f4b9735f35554d02e4203f7c39a3cae3d1c03004eb9adbe","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"1f1a6a01bc4a5f0b1ca8cf1d649a7e1c08b3667df2a8702134d56497950abc13","source_locator":"2.3.7","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE') printf '%s\n' '{"adapter_contract_sha256":"ae2dde5c930ce7e1a08ecf0c151a744bcd4a782fab55f4a7702d5274b4878c42","adapter_id":"product-standard-system-paths-mode-check-v2","adapter_implementation_sha256":"e021b632f1db643ab9f6349c777eefecc1defb0cc179376f7f476c825cf0b48e","control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"9f3041f0f9809cedcafb7f7e6b6b82641324902e34a3a84f9d24228af932cb1e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0012","parameter_key":"mode","parameter_kind":"standard-system-paths-mode","parameter_locator":"/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c14203a718160e12100efac4e8e4f748cdf7517bba948d7ee66d8811f2e462e3","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"1ea83595f910be4a5364dbe49d98ebf2b8eafb64446a3496f83830898fa223dc","source_locator":"2.3.8","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST') printf '%s\n' '{"adapter_contract_sha256":"2ee27cffe1cdd5cb211a9587079518e62107a6b74b5d4a297d5fa628a5584ed7","adapter_id":"product-suid-sgid-applications-check-v2","adapter_implementation_sha256":"be7899d602a64e14914412464e528df39fda09271afd3ae9f1effdb09ece34df","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"0c7c2ff2dbafa54b15440ce8f8d25173c174a28c8b1752804631a829c191a86c","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"subset-of-file","expected_type":"string","expected_value":"/etc/securelinux-policy/suid-sgid.allowlist-v1","index_id":"SRC-0013","parameter_key":"approved-set","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"9c0156d9705459d4c51a026e4abd0cc303ac0815eceb513c9a824b5ae281b708","source_locator":"2.3.9","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE') printf '%s\n' '{"adapter_contract_sha256":"2ee27cffe1cdd5cb211a9587079518e62107a6b74b5d4a297d5fa628a5584ed7","adapter_id":"product-suid-sgid-applications-check-v2","adapter_implementation_sha256":"be7899d602a64e14914412464e528df39fda09271afd3ae9f1effdb09ece34df","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"5e52002e72ea86d8c10dad28d09c82f0a027850ca4ae6e0d40745b7cdc33710b","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0013","parameter_key":"mode","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"9c0156d9705459d4c51a026e4abd0cc303ac0815eceb513c9a824b5ae281b708","source_locator":"2.3.9","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"51f99ed4b7c67eb30558176685885337c27a4d8c2047a8e667059dd2bbff07d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0016","parameter_key":"kernel.dmesg_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c889161dc17ca0ec538a88477aeebfd920e8d10a53d34952e69b12b24338a5e6","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"ba25c49b237cf91b74afcda02e15fd872e81c08973abd9719a8f4c465513aa9a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0017","parameter_key":"kernel.kptr_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"a4c2ba6bc1c18e8cc9a3b025cbf55b542e9cf327e3ce69fd2d8e4877bbc3ef60","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC') printf '%s\n' '{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"68b4a5d37e9addc54b6c8d9316e1a9e47e4eda7cb0683b2df99c4be911c7ea5c","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0018","parameter_key":"init_on_alloc","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE') printf '%s\n' '{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"817ddc5844c8600b30ea82b013576e8c90fe4381f37ff2d3e6f697766881aa9e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"present","expected_type":"boolean","expected_value":true,"index_id":"SRC-0019","parameter_key":"slab_nomerge","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"6a5c7fa4c5804ef3c2e152c338da6c73553bb8bce5dbde0331e4ba4db09d8b6f","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE') printf '%s\n' '{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"595da19602209ab601375e129f45dfa720038e5a5b92017e51b5b7873bd6233d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"force","index_id":"SRC-0020","parameter_key":"iommu","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH') printf '%s\n' '{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"85b3d67e7f741cfd9d50b3d935bc96ac38d6468d44cb18465baefa3379242942","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0","index_id":"SRC-0020","parameter_key":"iommu.passthrough","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT') printf '%s\n' '{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"0d68a6bb3b7869e9d76046d196e61511e34560cfb55cf130b30c65b3b9d3e629","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0020","parameter_key":"iommu.strict","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET') printf '%s\n' '{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"876b71fa1a3eabed4455db496c576c43ec897ccfe335266ae707b9bb976f124e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0021","parameter_key":"randomize_kstack_offset","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"69cbdb70f31aadd134129cae9eb95a96f836168646a821927cc3ea56ea58c980","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.7-MITIGATIONS') printf '%s\n' '{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"2d004e6effde058bcd8d5713b8116adec36af1476da6e4f5acb1553d7857d981","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"auto,nosmt","index_id":"SRC-0022","parameter_key":"mitigations","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"593127f71a130fb574410cc9b249cf9ce42c1ec9698ebad648c79c4554d55ceb","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.7","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"cfe64060a4d9829351c2c6f19c6f41b0e0697bd8be5b503a90ffe27a5f4c52ee","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0023","parameter_key":"net.core.bpf_jit_harden","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ffeec17a621afd4726e6c0fcf0aef4fb1e22c86f45ca20d1d568471675c3914f","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.8","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.1-VSYSCALL') printf '%s\n' '{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"611d219ec1d517ebceb3539968662a6e40a75bb028fc553ec18eb9a95544f413","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"none","index_id":"SRC-0024","parameter_key":"vsyscall","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"909ac7e3825f234cf325dac5b9615486ef4c856315aeb9c25d4b7a6af47fa421","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"f2733434c77fa39bec5210262632becd3f0aad65ddb7423c869725fe95fa5655","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"ge","expected_type":"integer","expected_value":4096,"index_id":"SRC-0033","parameter_key":"vm.mmap_min_addr","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.10","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"4a08a7bfd4f6a803dfb7bbc2486a83bd2fe1e877dcaa2e9938d402ee9765ee6d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0034","parameter_key":"kernel.randomize_va_space","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.11","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE') printf '%s\n' '{"adapter_contract_sha256":"2e3a3ec6753d880dea9aa0c3b7ac0dfc7b6e88238aed4e767293f1130613bace","adapter_id":"product-tested-setting-attestation-check-v1","adapter_implementation_sha256":"5f4a7345ef3863aacaef0c42780fbbbed1ce726c21773ce04760f462724231f3","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"c301ab7c5f08b0822aa61c955d00bdbec607f8188ce4fbe8d88ad0b756a293c0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"tested-before-use","expected_type":"string","expected_value":"kernel.randomize_va_space=2","index_id":"SRC-0034","parameter_key":"SRC-0034","parameter_kind":"tested-setting-attestation","parameter_locator":"/etc/securelinux-policy/tested-setting-attestations-v1","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"d15d7e89982de63578337429b97a429ecad136c8a8f39f5ba218cce5597193c7","source_locator":"2.5.11","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"b0eb7068712e20660c0d84871c271c6f3fdc542132cca1cf529910dcf7f85c0a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0025","parameter_key":"kernel.perf_event_paranoid","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8e6f4b120bd3527b380251e92eca56e1b4c358d362f1246357579eb8af616382","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.3-DEBUGFS') printf '%s\n' '{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"806da488a05c5d4ea11c2cef4bbde3b327387c1b96b143fe97c32e50e08a8894","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"one-of","expected_type":"string","expected_value":"off|no-mount","index_id":"SRC-0026","parameter_key":"debugfs","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"10391c151e6a53e91d637a11bc0f87a05a1ca7fdd408f9493dd27b366da46184","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"6006fdfb164b8a8860b8f4ae6d4e2758799f25ed32d53e185916da0ef0b7ed01","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0027","parameter_key":"kernel.kexec_load_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0231e3c8de27fab8de667f632bf6d08609a7c62836be9c787fd4cb955974ff09","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"b13b0e0b47c820d396a9a4a8d044ffdfc4eb779c5def2347c072cbc9e3900f32","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0028","parameter_key":"user.max_user_namespaces","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"77edbfb78e01426b6c40ccedca310ff6091870e235d4225ac488f4cd5d8c090c","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"44423cf2e57eabddd637a973430a6633282f8eba658430a1290bfa610efe5b67","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0029","parameter_key":"kernel.unprivileged_bpf_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"1c320abae9872972364ef95685204f4968a2c84bc27ee9c2707907eac8c5823e","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"3a5a2c1c560d688eeea441f4455297a86983c599745acf8963507f91b72c86f4","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0030","parameter_key":"vm.unprivileged_userfaultfd","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"cba35949a04f5d3dab8bd9a0501d75e5c310773ac11c1ad2c4d80845cdd03080","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.7","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"d6e4d8f63a5235ff32f3cb429c91caa7b7ff7864ba8ab90f8fd350362e8d3a69","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0031","parameter_key":"dev.tty.ldisc_autoload","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0860efcf66e2da819b06b5d6198e3b4c9b4ea96b66929752aceba65fae301783","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.8","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.9-TSX') printf '%s\n' '{"adapter_contract_sha256":"efb292dc4b90cc6f090aef861e51f523099c997d9fc6284e6fd38286de3a1db1","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"91b922fd4a9e1e5d16a5a3387ea14c06e32aabf6f5ed75d174a82a7c658d7160","control_id":"FSTEC-LINUX-2022-2.5.9-TSX","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"07040e8445ac0565a587fcf6cfadf124a45b6b076592d4a268eff2abe37b5ef3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"off","index_id":"SRC-0032","parameter_key":"tsx","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"40b0ad985774f12adad55439e22a5ba29b3a2c50c9fedd16551fa261fd29464c","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.9","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"2bc9bb0cb5372fb5738612ff3738526cad9adb831b0043cc5924f36d23e7ca37","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0035","parameter_key":"kernel.yama.ptrace_scope","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"7be4210587e64fe1864bfbf1b5e8f7cc3512434629eb17898ad487d50a9ae246","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"b709581e94eb65e5a059d70ff4ec7aac7d248e6b664ffb42c502e23c88e2bbe8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0036","parameter_key":"fs.protected_symlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ce09b5104160f3fe27f17f1d5e57a5fe81001adac3c362ed652552ccbc59571f","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"fc1fd0f1141cb6d78b5d322e6a04b2649f0264a5e8c4784c64116bed55d70ffa","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0037","parameter_key":"fs.protected_hardlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"315736677a4e3192cde79d4badbf20809da81c8605785c8720fcd0fc3260fe97","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"af3b312efb3d252c1752a9ee70da6248e2a8e86f2e29479388206afbfbcd453d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0038","parameter_key":"fs.protected_fifos","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016aaaf884c10febb3e99a86acfcbe63eae04f05f5fcf35a00c59f03fb30a31b","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"677905dff8f0fa0db1c82008b7b3acc0456dd61c46db0008390ab99f89ef9d92","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0039","parameter_key":"fs.protected_regular","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0f1eea51ec98d254f230a48dfc4950cb060e11460e1f30be68fde3fb9439cb14","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE') printf '%s\n' '{"adapter_contract_sha256":"d5db0104eb012bced042adf475e7421880fd820732b532dfb793c875b97d299d","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"d5fce240da7b8a913c084a381a96b974ad69c110affe97c4cad496cae4c63b26","control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","control_manifest_sha256":"4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea","control_sha256":"35c1fe8f6a4591fdf5b7d25f4dff6b244b868fbc1514498a7b55f9a321ddda8f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0040","parameter_key":"fs.suid_dumpable","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d","registry_sha256":"0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.6","target_id":"linux-x86_64-supported-v1"}' ;;
    *) return 2 ;;
  esac
}

slp_build_info() {
  printf '%s\n' \
    'STATUS=NON_RELEASE_PRODUCT_CANDIDATE' \
    'PRODUCT_CLI=product-cli-v1' \
    'GENERATOR_ID=product-check-generator-v2' \
    'GENERATOR_SHA256=19f9dfd936a445b4582cf0aa1846fa7cf4743cc888dd7653fff81f0e56f863ab' \
    'CONTROL_COUNT=51' \
    'CONTROL_MANIFEST_SHA256=4639ea7624e4ff52bf4295e32f2c8e6c1cc6eaf9e1684eb7824470d034a9c5ea' \
    'ADAPTER_COUNT=18' \
    'ADAPTER_REGISTRY_SHA256=0c605c5b1b563eb41b4caf64f86dc8b1ae54e7e2f49b148b7e1355053ec83025' \
    'TARGET_FAMILY_ID=linux-x86_64-supported-v1' \
    'SUPPORTED_PROFILE_ENVIRONMENTS=7' \
    'SUPPORTED_DESKTOP_ENVIRONMENTS=1' \
    'SUPPORTED_ENVIRONMENTS=8' \
    'PLATFORM_MATRIX_SHA256=efc7436850d1ae92df0f36b33e86663728a9fb3643ba3be8cbcaf40b0c9490d7' \
    'DESKTOP_MATRIX_SHA256=db17bfbe6f60a30831c2e4115bbaedbce4e15717715dd4a1174c75cecdfc4ece' \
    'MUTATING_MODES=NONE'
}

slp_help() {
  command /usr/bin/cat <<'SLP_HELP_EOF'
SecureLinux-Policy v3 — единый read-only CLI

Использование:
  ./securelinux-policy.sh --check [--failed] [--format pretty|raw|json]
  ./securelinux-policy.sh --report
  ./securelinux-policy.sh --build-info
  ./securelinux-policy.sh --provenance [CONTROL_ID]
  ./securelinux-policy.sh --version
  ./securelinux-policy.sh --help
  ./securelinux-policy.sh --apply

Режимы:
  --check               read-only проверка текущих canonical controls
  --check --failed      показать только FAIL и ERROR
  --format pretty       выровненная таблица для человека (по умолчанию)
  --format raw          стабильный SLP-CHECK-V1 TSV для автоматизации
  --format json         структурированный JSON-отчёт
  --report              краткая сводка + FAIL/ERROR
  --build-info          metadata сборки
  --provenance          provenance всех controls или одного CONTROL_ID
  --version             версия product CLI
  --apply               NOT_IMPLEMENTED; ничего не изменяет

Без аргументов печатается эта справка. CHECK не изменяет состояние хоста.
SLP_HELP_EOF
}

slp_version() {
  printf '%s\n' \
    'PRODUCT=SecureLinux-Policy-v3' \
    'PRODUCT_CLI=product-cli-v1' \
    'STATUS=NON_RELEASE_PRODUCT_CANDIDATE' \
    'CONTROL_COUNT=51' \
    'TARGET_FAMILY_ID=linux-x86_64-supported-v1'
}

slp_json_escape() {
  local _slp_s=$1
  _slp_s=${_slp_s//\\/\\\\}
  _slp_s=${_slp_s//\"/\\\"}
  _slp_s=${_slp_s//$'\x01'/\\u0001}
  _slp_s=${_slp_s//$'\x02'/\\u0002}
  _slp_s=${_slp_s//$'\x03'/\\u0003}
  _slp_s=${_slp_s//$'\x04'/\\u0004}
  _slp_s=${_slp_s//$'\x05'/\\u0005}
  _slp_s=${_slp_s//$'\x06'/\\u0006}
  _slp_s=${_slp_s//$'\x07'/\\u0007}
  _slp_s=${_slp_s//$'\x08'/\\b}
  _slp_s=${_slp_s//$'\t'/\\t}
  _slp_s=${_slp_s//$'\n'/\\n}
  _slp_s=${_slp_s//$'\x0b'/\\u000b}
  _slp_s=${_slp_s//$'\x0c'/\\f}
  _slp_s=${_slp_s//$'\r'/\\r}
  _slp_s=${_slp_s//$'\x0e'/\\u000e}
  _slp_s=${_slp_s//$'\x0f'/\\u000f}
  _slp_s=${_slp_s//$'\x10'/\\u0010}
  _slp_s=${_slp_s//$'\x11'/\\u0011}
  _slp_s=${_slp_s//$'\x12'/\\u0012}
  _slp_s=${_slp_s//$'\x13'/\\u0013}
  _slp_s=${_slp_s//$'\x14'/\\u0014}
  _slp_s=${_slp_s//$'\x15'/\\u0015}
  _slp_s=${_slp_s//$'\x16'/\\u0016}
  _slp_s=${_slp_s//$'\x17'/\\u0017}
  _slp_s=${_slp_s//$'\x18'/\\u0018}
  _slp_s=${_slp_s//$'\x19'/\\u0019}
  _slp_s=${_slp_s//$'\x1a'/\\u001a}
  _slp_s=${_slp_s//$'\x1b'/\\u001b}
  _slp_s=${_slp_s//$'\x1c'/\\u001c}
  _slp_s=${_slp_s//$'\x1d'/\\u001d}
  _slp_s=${_slp_s//$'\x1e'/\\u001e}
  _slp_s=${_slp_s//$'\x1f'/\\u001f}
  printf '%s' "$_slp_s"
}

slp_pretty_row() {
  local _slp_result=$1 _slp_cid=$2 _slp_value=$3
  local _slp_width=56 _slp_part _slp_piece _slp_line=''
  local _slp_first=1
  local -a _slp_parts=()
  IFS=';' read -r -a _slp_parts <<< "$_slp_value"
  if (( ${#_slp_parts[@]} <= 1 )); then
    printf '%-7s  %-61s  %s\n' "$_slp_result" "$_slp_cid" "$_slp_value"
    return 0
  fi
  for _slp_part in "${_slp_parts[@]}"; do
    if [[ -z $_slp_line ]]; then
      _slp_line=$_slp_part
      continue
    fi
    _slp_piece=";$_slp_part"
    if (( ${#_slp_line} + ${#_slp_piece} <= _slp_width )); then
      _slp_line+="$_slp_piece"
    else
      if (( _slp_first == 1 )); then
        printf '%-7s  %-61s  %s\n' "$_slp_result" "$_slp_cid" "$_slp_line"
        _slp_first=0
      else
        printf '%-7s  %-61s  %s\n' '' '' "$_slp_line"
      fi
      _slp_line=$_slp_part
    fi
  done
  if (( _slp_first == 1 )); then
    printf '%-7s  %-61s  %s\n' "$_slp_result" "$_slp_cid" "$_slp_line"
  else
    printf '%-7s  %-61s  %s\n' '' '' "$_slp_line"
  fi
}

slp_collect_policy() {
  local _slp_fn _slp_expected_cid _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_extra
  local _slp_i
  local -a _slp_fns=('slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE' 'slp_check_FSTEC_LINUX_2022_2_1_2_SSH_ROOT_LOGIN' 'slp_check_FSTEC_LINUX_2022_2_2_1_SU_WHEEL_ACCESS' 'slp_check_FSTEC_LINUX_2022_2_2_2_SUDOERS_REVIEWED_POLICY' 'slp_check_FSTEC_LINUX_2022_2_3_1_GROUP_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_1_PASSWD_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_1_SHADOW_GO_RWX' 'slp_check_FSTEC_LINUX_2022_2_3_10_HOME_SENSITIVE_FILES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_11_HOME_DIRECTORIES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_2_RUNNING_PROCESS_PATHS_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_3_CRON_COMMAND_PATHS_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_4_SUDO_ROOT_COMMAND_FILES_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_5_STARTUP_FILES_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_D' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_DAILY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_HOURLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_MONTHLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_WEEKLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRONTAB' 'slp_check_FSTEC_LINUX_2022_2_3_7_USER_CRON_FILES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_8_STANDARD_SYSTEM_PATHS_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_ALLOWLIST' 'slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_MODE' 'slp_check_FSTEC_LINUX_2022_2_4_1_DMESG_RESTRICT' 'slp_check_FSTEC_LINUX_2022_2_4_2_KPTR_RESTRICT' 'slp_check_FSTEC_LINUX_2022_2_4_3_INIT_ON_ALLOC' 'slp_check_FSTEC_LINUX_2022_2_4_4_SLAB_NOMERGE' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_FORCE' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_PASSTHROUGH' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_STRICT' 'slp_check_FSTEC_LINUX_2022_2_4_6_RANDOMIZE_KSTACK_OFFSET' 'slp_check_FSTEC_LINUX_2022_2_4_7_MITIGATIONS' 'slp_check_FSTEC_LINUX_2022_2_4_8_BPF_JIT_HARDEN' 'slp_check_FSTEC_LINUX_2022_2_5_1_VSYSCALL' 'slp_check_FSTEC_LINUX_2022_2_5_10_MMAP_MIN_ADDR' 'slp_check_FSTEC_LINUX_2022_2_5_11_RANDOMIZE_VA_SPACE' 'slp_check_FSTEC_LINUX_2022_2_5_11_RANDOMIZE_VA_SPACE_TESTED_BEFORE_USE' 'slp_check_FSTEC_LINUX_2022_2_5_2_PERF_EVENT_PARANOID' 'slp_check_FSTEC_LINUX_2022_2_5_3_DEBUGFS' 'slp_check_FSTEC_LINUX_2022_2_5_4_KEXEC_LOAD_DISABLED' 'slp_check_FSTEC_LINUX_2022_2_5_5_MAX_USER_NAMESPACES' 'slp_check_FSTEC_LINUX_2022_2_5_6_UNPRIVILEGED_BPF_DISABLED' 'slp_check_FSTEC_LINUX_2022_2_5_7_UNPRIVILEGED_USERFAULTFD' 'slp_check_FSTEC_LINUX_2022_2_5_8_LDISC_AUTOLOAD' 'slp_check_FSTEC_LINUX_2022_2_5_9_TSX' 'slp_check_FSTEC_LINUX_2022_2_6_1_PTRACE_SCOPE' 'slp_check_FSTEC_LINUX_2022_2_6_2_PROTECTED_SYMLINKS' 'slp_check_FSTEC_LINUX_2022_2_6_3_PROTECTED_HARDLINKS' 'slp_check_FSTEC_LINUX_2022_2_6_4_PROTECTED_FIFOS' 'slp_check_FSTEC_LINUX_2022_2_6_5_PROTECTED_REGULAR' 'slp_check_FSTEC_LINUX_2022_2_6_6_SUID_DUMPABLE')
  local -a _slp_ids=('FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' 'FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS' 'FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.6-CRON-D' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' 'FSTEC-LINUX-2022-2.5.9-TSX' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE')

  SLP_RESULTS=()
  SLP_TOTAL=0 SLP_PASS=0 SLP_FAIL=0 SLP_NF=0 SLP_ERR=0 SLP_POLICY_STATUS='' SLP_POLICY_RC=0

  for ((_slp_i=0; _slp_i<${#_slp_fns[@]}; _slp_i++)); do
    _slp_fn=${_slp_fns[$_slp_i]}
    _slp_expected_cid=${_slp_ids[$_slp_i]}
    if ! _slp_line="$($_slp_fn)"; then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    _slp_tag='' _slp_cid='' _slp_status='' _slp_value='' _slp_comp='' _slp_extra=''
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_extra <<< "$_slp_line"
    if [[ $_slp_tag != SLP-CHECK-V1 || $_slp_cid != "$_slp_expected_cid" || -n $_slp_extra ]]; then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    case "$_slp_status:$_slp_comp" in
      VALUE:PASS|VALUE:FAIL|NOT_FOUND:FAIL|NOT_FOUND:NOT_FOUND|ERROR:ERROR) ;;
      *)
        printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
        return 1
        ;;
    esac
    if [[ $_slp_comp == ERROR ]]; then
      if [[ ! $_slp_value =~ ^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$ ]]; then
        printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
        return 1
      fi
    fi
    SLP_RESULTS+=("$_slp_line")
    ((SLP_TOTAL+=1))
    case "$_slp_comp" in
      PASS) ((SLP_PASS+=1)) ;;
      FAIL) ((SLP_FAIL+=1)) ;;
      NOT_FOUND) ((SLP_NF+=1)) ;;
      ERROR) ((SLP_ERR+=1)) ;;
      *) return 1 ;;
    esac
  done

  if (( SLP_NF > 0 || SLP_ERR > 0 )); then
    SLP_POLICY_STATUS=UNEVALUATED
    SLP_POLICY_RC=1
  elif (( SLP_FAIL > 0 )); then
    SLP_POLICY_STATUS=NONCOMPLIANT
    SLP_POLICY_RC=0
  else
    SLP_POLICY_STATUS=COMPLIANT
    SLP_POLICY_RC=0
  fi
  return 0
}

slp_selected() {
  local _slp_result=$1 _slp_failed_only=$2
  if (( _slp_failed_only == 0 )); then return 0; fi
  [[ $_slp_result == FAIL || $_slp_result == ERROR ]]
}

slp_render_raw() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp
  printf 'SLP-PLATFORM-V1\tSYSTEM=%s\tID=%s\tVERSION_ID=%s\tARCH=%s\tPROFILE=%s\tTYPE=%s\tPLATFORM=%s\tENVIRONMENT=%s\tSUPPORT=SUPPORTED\n' \
    "$SLP_SYSTEM_PRETTY_NAME" "$SLP_SYSTEM_ID" "$SLP_SYSTEM_VERSION_ID" "$SLP_SYSTEM_ARCH" \
    "$SLP_SYSTEM_PROFILE" "$SLP_SYSTEM_TYPE" "$SLP_SYSTEM_PLATFORM" "$SLP_SYSTEM_ENVIRONMENT"
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    printf '%s\n' "$_slp_line"
  done
  printf 'SLP-SUMMARY-V1\tTOTAL=%d\tPASS=%d\tFAIL=%d\tNOT_FOUND=%d\tERROR=%d\tPOLICY_STATUS=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_ERR" "$SLP_POLICY_STATUS"
}

slp_render_pretty() {
  local _slp_failed_only=$1 _slp_title=$2 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp
  printf '=== SecureLinux Policy — %s ===\n' "$_slp_title"
  printf 'SYSTEM=%s   ARCH=%s\n' "$SLP_SYSTEM_PRETTY_NAME" "$SLP_SYSTEM_ARCH"
  if [[ -n $SLP_SYSTEM_TYPE ]]; then
    printf 'TYPE=%s   PLATFORM=%s   SUPPORT=SUPPORTED\n\n' "$SLP_SYSTEM_TYPE" "$SLP_SYSTEM_PLATFORM"
  else
    printf 'PROFILE=%s   PLATFORM=%s   SUPPORT=SUPPORTED\n\n' "$SLP_SYSTEM_PROFILE" "$SLP_SYSTEM_PLATFORM"
  fi
  printf '%-7s  %-61s  %s\n' 'RESULT' 'CONTROL' 'VALUE / DETAILS'
  printf '%-7s  %-61s  %s\n' '------' '-------------------------------------------------------------' '--------------------------------------------------------'
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    slp_pretty_row "$_slp_comp" "$_slp_cid" "$_slp_value"
  done
  printf '%s\n' '----------------------------------------------------------------------------------------------------------------------------------'
  printf 'TOTAL=%d   PASS=%d   FAIL=%d   NOT_FOUND=%d   ERROR=%d   POLICY=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_ERR" "$SLP_POLICY_STATUS"
}

slp_render_json() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_first=1 _slp_filter=all
  (( _slp_failed_only == 1 )) && _slp_filter=failed
  printf '{"schema":"SLP-REPORT-V1","filter":"%s","platform":{"system":"%s","id":"%s","version_id":"%s","arch":"%s","profile":"%s","type":"%s","platform_id":"%s","environment_id":"%s","support":"SUPPORTED"},"policy_status":"%s","summary":{"total":%d,"pass":%d,"fail":%d,"not_found":%d,"error":%d},"results":[' \
    "$_slp_filter" "$(slp_json_escape "$SLP_SYSTEM_PRETTY_NAME")" "$(slp_json_escape "$SLP_SYSTEM_ID")" \
    "$(slp_json_escape "$SLP_SYSTEM_VERSION_ID")" "$(slp_json_escape "$SLP_SYSTEM_ARCH")" \
    "$(slp_json_escape "$SLP_SYSTEM_PROFILE")" "$(slp_json_escape "$SLP_SYSTEM_TYPE")" "$(slp_json_escape "$SLP_SYSTEM_PLATFORM")" \
    "$(slp_json_escape "$SLP_SYSTEM_ENVIRONMENT")" "$SLP_POLICY_STATUS" "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_ERR"
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    if (( _slp_first == 0 )); then printf ','; fi
    _slp_first=0
    printf '{"control_id":"%s","observation":"%s","value":"%s","result":"%s"}' \
      "$(slp_json_escape "$_slp_cid")" "$(slp_json_escape "$_slp_status")" "$(slp_json_escape "$_slp_value")" "$(slp_json_escape "$_slp_comp")"
  done
  printf ']}\n'
}

slp_run_check() {
  local _slp_format=$1 _slp_failed_only=$2 _slp_title=${3:-CHECK}
  slp_target_preflight || return $?
  slp_collect_policy || return $?
  case "$_slp_format" in
    pretty) slp_render_pretty "$_slp_failed_only" "$_slp_title" ;;
    raw) slp_render_raw "$_slp_failed_only" ;;
    json) slp_render_json "$_slp_failed_only" ;;
    *) return 2 ;;
  esac
  return "$SLP_POLICY_RC"
}

slp_not_implemented() {
  local _slp_mode=$1
  printf 'NOT_IMPLEMENTED: %s; host state was not changed.\n' "$_slp_mode" >&2
  return 2
}

slp_main() {
  local _slp_format=pretty _slp_failed_only=0
  if (( $# == 0 )); then
    slp_help
    return 0
  fi
  case "$1" in
    --help)
      (( $# == 1 )) || return 2
      slp_help
      return 0
      ;;
    --version)
      (( $# == 1 )) || return 2
      slp_version
      return 0
      ;;
    --build-info)
      (( $# == 1 )) || return 2
      slp_build_info
      return 0
      ;;
    --provenance)
      if (( $# == 1 )); then
        slp_provenance_all
      elif (( $# == 2 )); then
        slp_provenance_one "$2" || return 2
      else
        return 2
      fi
      return 0
      ;;
    --apply)
      (( $# == 1 )) || return 2
      slp_not_implemented APPLY
      return $?
      ;;
    --report)
      (( $# == 1 )) || return 2
      slp_run_check pretty 1 REPORT
      return $?
      ;;
    --check)
      shift
      while (( $# > 0 )); do
        case "$1" in
          --failed)
            (( _slp_failed_only == 0 )) || return 2
            _slp_failed_only=1
            ;;
          --format)
            shift
            (( $# > 0 )) || return 2
            case "$1" in pretty|raw|json) _slp_format=$1 ;; *) return 2 ;; esac
            ;;
          --format=*)
            _slp_format=${1#--format=}
            case "$_slp_format" in pretty|raw|json) ;; *) return 2 ;; esac
            ;;
          *) return 2 ;;
        esac
        shift
      done
      slp_run_check "$_slp_format" "$_slp_failed_only" CHECK
      return $?
      ;;
    *)
      return 2
      ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  slp_main "$@"
  exit $?
fi
