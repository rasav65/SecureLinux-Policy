#!/bin/bash -p
# SecureLinux-Policy unified product CLI
# STATUS=NON_RELEASE_PRODUCT_CANDIDATE
# PRODUCT_CLI=product-cli-v1
# GENERATOR_ID=product-check-generator-v2
# GENERATOR_SHA256=d8564f86461304bf9d8c4a08d752201a840aa6a916e401f06f320fb5857d2f0a
# CONTROL_MANIFEST_SHA256=b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4
# ADAPTER_REGISTRY_SHA256=8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc
# APPLY_KINDS=config-line-with-runtime-v1,file-mode-owner-v1,kernel-cmdline-grub-v1,optional-file-root-files-mode-v1,pam-wheel-su-v1,sshd-config-option-v1,standard-system-paths-mode-v1,startup-files-write-protection-v1,suid-sgid-applications-mode-v1
# APPLY_CONTROL_COUNT=43
# APPLY_KIND_REGISTRY_SHA256=35031db3bb6140789f5127f1930511a8d1932a92963884182c51a5d989b74800
# APPLY_IMPLEMENTATION_REGISTRY_SHA256=a9abb02944f5af488c2e06f29e6f2b31f72800b35be908415d181df21727fa2a
# TARGET_FAMILY_ID=linux-x86_64-supported-v1
# PLATFORM_MATRIX_SHA256=efc7436850d1ae92df0f36b33e86663728a9fb3643ba3be8cbcaf40b0c9490d7
# DESKTOP_MATRIX_SHA256=5a910c9efa49fa13e2d1183cc3efc9f8c4a951f11f4aca2ee56bd990463ac29e

set -u

slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE() {
  local _slp_passwd='/etc/passwd'
  local _slp_shadow='/etc/shadow'
  local _slp_line _slp_user _slp_rest _slp_pwd _slp_colons _slp_vrc
  local _slp_passwd_text _slp_shadow_text
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
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 && "$_slp_v_byte" != 0d ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_passwd" _slp_passwd_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:read-failed" "ERROR"; else printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "passwd:invalid-bytes" "ERROR"; fi
    return 0
  fi
  _slp_load_text "$_slp_shadow" _slp_shadow_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:read-failed" "ERROR"; else printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "shadow:invalid-bytes" "ERROR"; fi
    return 0
  fi
  _slp_rest=$_slp_shadow_text
  while [[ -n $_slp_rest ]]; do
    if [[ $_slp_rest == *$'\n'* ]]; then _slp_line=${_slp_rest%%$'\n'*}; _slp_rest=${_slp_rest#*$'\n'}; else _slp_line=$_slp_rest; _slp_rest=""; fi
    _slp_shadow_lines+=("$_slp_line")
  done
  _slp_rest=$_slp_passwd_text
  while [[ -n $_slp_rest ]]; do
    if [[ $_slp_rest == *$'\n'* ]]; then _slp_line=${_slp_rest%%$'\n'*}; _slp_rest=${_slp_rest#*$'\n'}; else _slp_line=$_slp_rest; _slp_rest=""; fi
    _slp_passwd_lines+=("$_slp_line")
  done
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
  local _slp_real _slp_line _slp_effective _slp_parent _slp_stat_out
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
    _slp_parent=${_slp_cfg%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_cfg" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-config:unreadable" "ERROR"
    fi
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
    _slp_parent=${_slp_sshd%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_sshd" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "sshd-binary:resolve-failed" "ERROR"
    fi
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
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local _slp_pf_text _slp_ptext_rest _slp_stat_out
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf" _slp_pf_text; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    _slp_ptext_rest=$_slp_pf_text
    while [[ -n $_slp_ptext_rest ]]; do
      if [[ $_slp_ptext_rest == *$'\n'* ]]; then _slp_pl=${_slp_ptext_rest%%$'\n'*}; _slp_ptext_rest=${_slp_ptext_rest#*$'\n'}; else _slp_pl=$_slp_ptext_rest; _slp_ptext_rest=''; fi
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
            else
              _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_prefix" 2>&1)
              if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-stat-failed; break 2; fi
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          else
            _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_px" 2>&1)
            if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-stat-failed; break 2; fi
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
    done
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
  local _slp_line _slp_logical='' _slp_trim _slp_module _slp_control _slp_type _slp_gid='' _slp_members='' _slp_name _slp_pam_text _slp_group_text _slp_rest
  local _slp_parent= _slp_pam_field _slp_wheel_field _slp_root_field _slp_comp _slp_stat_out
  local _slp_pam_absent=0 _slp_group_absent=0
  local -a _slp_tok=() _slp_members_arr=()
  local -A _slp_actual=()
  local _slp_exact=0 _slp_nouid=0 _slp_other=0 _slp_wheel=0 _slp_error=0 _slp_midx=0 _slp_i=0 _slp_vrc=0 _slp_hazard=0

  _slp_name_has_forbidden_separator() {
    local _slp_n=$1
    case "$_slp_n" in
      *' '*|*$'\t'*|*$'\r'*|*$'\v'*|*$'\f'*|*$'\x7f'*|*:*|*','*|*'#'*) return 0 ;;
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
  if [[ ! -e "$_slp_pam" ]]; then
    _slp_parent=${_slp_pam%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    [[ -d $_slp_parent && -x $_slp_parent ]] || {
      printf 'SLP-CHECK-V1\t%s\tERROR\tpam:read-failed\tERROR\n' "$_slp_cid"
      return 0
    }
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_pam" 2>&1)
    if (( $? == 0 )) || [[ $_slp_stat_out != *': No such file or directory' ]]; then
      printf 'SLP-CHECK-V1\t%s\tERROR\tpam:read-failed\tERROR\n' "$_slp_cid"
      return 0
    fi
    _slp_pam_absent=1
  fi
  if [[ ! -e "$_slp_group" ]]; then
    _slp_parent=${_slp_group%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    [[ -d $_slp_parent && -x $_slp_parent ]] || {
      printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:read-failed\tERROR\n' "$_slp_cid"
      return 0
    }
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_group" 2>&1)
    if (( $? == 0 )) || [[ $_slp_stat_out != *': No such file or directory' ]]; then
      printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:read-failed\tERROR\n' "$_slp_cid"
      return 0
    fi
    _slp_group_absent=1
  fi
  if (( _slp_pam_absent || _slp_group_absent )); then
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
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
        _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_pam" _slp_pam_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tpam:read-failed\tERROR\n' "$_slp_cid"; else printf 'SLP-CHECK-V1\t%s\tERROR\tpam:invalid-bytes\tERROR\n' "$_slp_cid"; fi
    return 0
  fi
  _slp_load_text "$_slp_group" _slp_group_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:read-failed\tERROR\n' "$_slp_cid"; else printf 'SLP-CHECK-V1\t%s\tERROR\tgroup:invalid-bytes\tERROR\n' "$_slp_cid"; fi
    return 0
  fi

  _slp_rest=$_slp_pam_text
  while [[ -n $_slp_rest ]]; do
    if [[ $_slp_rest == *$'\n'* ]]; then _slp_line=${_slp_rest%%$'\n'*}; _slp_rest=${_slp_rest#*$'\n'}; else _slp_line=$_slp_rest; _slp_rest=''; fi
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
      (( _slp_exact > 0 )) || _slp_hazard=1
      continue
    fi
    (( ${#_slp_tok[@]} >= 3 )) || { _slp_error=1; break; }
    _slp_type=${_slp_tok[0],,}
    _slp_type=${_slp_type#-}
    _slp_control=${_slp_tok[1],,}
    if (( _slp_exact == 0 )) && [[ "$_slp_type" == auth ]]; then
      if [[ "${_slp_tok[0],,}" == auth && "$_slp_control" == sufficient && ${#_slp_tok[@]} -eq 3 && "${_slp_tok[2]}" == pam_rootok.so ]]; then
        :
      elif [[ "$_slp_control" == sufficient || "$_slp_control" == include || "$_slp_control" == substack || "$_slp_control" == \[* ]]; then
        _slp_hazard=1
      fi
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
      if [[ "${_slp_tok[0],,}" == auth && "${_slp_tok[1],,}" == required && "$_slp_module" == pam_wheel.so ]]; then
        if (( ${#_slp_tok[@]} == 4 )) && [[ "${_slp_tok[3]}" == use_uid ]]; then
          ((_slp_exact+=1))
        else
          ((_slp_nouid+=1))
          for ((_slp_i=3; _slp_i<${#_slp_tok[@]}; _slp_i++)); do
            if [[ "${_slp_tok[_slp_i]}" == use_uid ]]; then ((_slp_nouid-=1)); ((_slp_other+=1)); break; fi
          done
        fi
      else
        ((_slp_other+=1))
      fi
    fi
  done
  [[ -z "$_slp_logical" ]] || _slp_error=1
  if (( _slp_error || _slp_other > 0 || (_slp_hazard && _slp_exact > 0) || (_slp_nouid > 0 && _slp_exact > 0) )); then
    printf 'SLP-CHECK-V1\t%s\tERROR\tpam:ambiguous-stack\tERROR\n' "$_slp_cid"
    return 0
  fi

  _slp_rest=$_slp_group_text
  while [[ -n $_slp_rest ]]; do
    if [[ $_slp_rest == *$'\n'* ]]; then _slp_line=${_slp_rest%%$'\n'*}; _slp_rest=${_slp_rest#*$'\n'}; else _slp_line=$_slp_rest; _slp_rest=''; fi
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
  done
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

  if (( _slp_exact > 0 )); then _slp_pam_field=present; elif (( _slp_nouid > 0 )); then _slp_pam_field=no-use_uid; else _slp_pam_field=absent; fi
  if (( _slp_wheel == 1 )); then printf -v _slp_wheel_field 'gid %s' "$_slp_gid"; else _slp_wheel_field=absent; fi
  if [[ -n "${_slp_actual[root]+x}" ]]; then _slp_root_field=member; else _slp_root_field=missing; fi
  if [[ $_slp_pam_field == present && $_slp_wheel_field != absent && $_slp_root_field == member ]]; then _slp_comp=PASS; else _slp_comp=FAIL; fi
  printf 'SLP-CHECK-V1\t%s\tVALUE\tpam_wheel=%s;wheel=%s;root=%s\t%s\n' "$_slp_cid" "$_slp_pam_field" "$_slp_wheel_field" "$_slp_root_field" "$_slp_comp"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_2_2_SUDOERS_REVIEWED_POLICY() {
  local _slp_cid='FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY' _slp_obs _slp_rc _slp_kind _slp_value _slp_compliance _slp_extra
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/etc/sudoers' '/usr/sbin/visudo' '/usr/bin/cvtsudoers' <<'SLP_SUDOERS_POLICY_PY'
import hashlib, json, os, stat, subprocess, sys
from pathlib import Path

sudoers_path = Path(sys.argv[1])
visudo_path = sys.argv[2]
cvtsudoers_path = sys.argv[3]
ENV = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def resolve_cvtsudoers(primary):
    # Ubuntu 26.04 with sudo-rs active: package sudo installs cvtsudoers as cvtsudoers.ws.
    if os.path.lexists(primary):
        return primary
    fallback = primary + ".ws"
    try:
        st = os.stat(fallback)
    except FileNotFoundError:
        return primary
    except Exception:
        error("cvtsudoers:fallback-stat-failed")
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.geteuid()) or stat.S_IMODE(st.st_mode) & 0o022:
        error("cvtsudoers:untrusted-fallback")
    return fallback


def stock_rule(invoker, runas_group):
    spec = {"runasusers": [{"username": "ALL"}]}
    if runas_group:
        spec["runasgroups"] = [{"usergroup": "ALL"}]
    # cvtsudoers reports the command ALL with its implied SETENV tag.
    spec["Options"] = [{"setenv": True}]
    spec["Commands"] = [{"command": "ALL"}]
    return {"User_List": [invoker], "Host_List": [{"hostname": "ALL"}], "Cmnd_Specs": [spec]}


# The only admissible user specifications: the rules a Debian-family installer
# writes.  Group membership and Defaults are not evaluated.
STOCK_RULES = frozenset(json.dumps(rule, sort_keys=True) for rule in (
    stock_rule({"username": "root"}, True),     # root ALL=(ALL:ALL) ALL
    stock_rule({"usergroup": "sudo"}, True),    # %sudo ALL=(ALL:ALL) ALL
    stock_rule({"usergroup": "admin"}, False),  # %admin ALL=(ALL) ALL
))


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


def policy_snapshot():
    # The sudoers pathset is the closure that visudo reports after validating the
    # active tree; no reviewed-policy file is read.  Identities and bytes of that
    # pathset are compared between the two policy observations of one check.
    try:
        proc = subprocess.run([visudo_path, "-c", "-f", str(sudoers_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENV, check=False)
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
    closure = []
    for line in text.splitlines():
        suffix = ": parsed OK"
        if not line.endswith(suffix):
            error("visudo:invalid-output")
        path_text = line[:-len(suffix)]
        if not path_text.startswith("/") or any(c in path_text for c in "\x00\r\n\t") or path_text in closure:
            error("visudo:invalid-output")
        closure.append(path_text)
    if not closure or str(sudoers_path) not in closure:
        error("visudo:invalid-output")
    out = []
    for path_text in sorted(closure):
        state, raw = stable_regular_bytes(Path(path_text), "sudoers")
        out.append((path_text, state, hashlib.sha256(raw).hexdigest()))
    return tuple(out)


def cvt_snapshot():
    try:
        proc = subprocess.run(
            [cvtsudoers_path, "-c", "/dev/null", "-e", "-s", "aliases", "-f", "json", str(sudoers_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, check=False,
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
    specs = data.get("User_Specs", [])
    if not isinstance(specs, list):
        error("cvtsudoers:invalid-output")
    return proc.stdout, specs


def count_nonstandard(specs):
    nonstandard = 0
    for user_spec in specs:
        if not isinstance(user_spec, dict) or set(user_spec) != {"User_List", "Host_List", "Cmnd_Specs"}:
            error("sudo-policy:invalid-user-spec")
        # Canonical JSON keeps JSON true distinct from 1.
        if json.dumps(user_spec, sort_keys=True) not in STOCK_RULES:
            nonstandard += 1
    return nonstandard


cvtsudoers_path = resolve_cvtsudoers(cvtsudoers_path)
policy_before = policy_snapshot()
cvt_before, specs = cvt_snapshot()
nonstandard = count_nonstandard(specs)
policy_after = policy_snapshot()
cvt_after, specs_after = cvt_snapshot()
if policy_after != policy_before or cvt_after != cvt_before:
    error("observation:policy-changed")

print("VALUE\trules=%d;nonstandard=%d\t%s" % (len(specs), nonstandard, "PASS" if nonstandard == 0 else "FAIL"))

SLP_SUDOERS_POLICY_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:execution-failed\tERROR\n' "$_slp_cid"; return 0; fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\t%s\tERROR\n' "$_slp_cid" "${_slp_obs#*$'\t'}"; return 0; fi
  IFS=$'\t' read -r _slp_kind _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ "$_slp_kind" != VALUE || -z "$_slp_value" || -n "$_slp_extra" || ( "$_slp_compliance" != PASS && "$_slp_compliance" != FAIL ) ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:invalid-output\tERROR\n' "$_slp_cid"; return 0; fi
  printf 'SLP-CHECK-V1\t%s\tVALUE\t%s\t%s\n' "$_slp_cid" "$_slp_value" "$_slp_compliance"
}

slp_check_FSTEC_LINUX_2022_2_3_1_GROUP_MODE() {
  local _slp_path='/etc/group'
  local _slp_expected='0644'
  local _slp_mode _slp_parent _slp_comp _slp_stat_out
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
  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
  if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "NOT_FOUND" "-" "NOT_FOUND"
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "target:stat-failed" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_1_PASSWD_MODE() {
  local _slp_path='/etc/passwd'
  local _slp_expected='0644'
  local _slp_mode _slp_parent _slp_comp _slp_stat_out
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
  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
  if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "NOT_FOUND" "-" "NOT_FOUND"
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "target:stat-failed" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_1_SHADOW_GO_RWX() {
  local _slp_path='/etc/shadow'
  local _slp_expected='0077'
  local _slp_mode _slp_parent _slp_comp _slp_stat_out
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
  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
  if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "NOT_FOUND" "-" "NOT_FOUND"
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "target:stat-failed" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_10_HOME_SENSITIVE_FILES_MODE() {
  local _slp_home='/home'
  local _slp_expected='0077'
  local _slp_entry _slp_base _slp_mode
  local _slp_ident _slp_marker _slp_find_rc _slp_sort_rc _slp_i
  local _slp_probe _slp_stat_out _slp_reason _slp_target _slp_bad
  local _slp_homes=0 _slp_checked=0 _slp_violations=0 _slp_dynamic=0
  local -a _slp_entries=() _slp_home_entries=()
  local -A _slp_seen_targets=() _slp_seen_entries=()

  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_home" 2>&1)
  if (( $? != 0 )); then
    if [[ "$_slp_stat_out" != *": No such file or directory" ]]; then
      printf -v _slp_reason 'home-base:stat-failed:%s' "$_slp_home"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    _slp_probe=$_slp_home
    while [[ $_slp_probe != / ]]; do
      _slp_probe=${_slp_probe%/*}
      [[ -n $_slp_probe ]] || _slp_probe=/
      if [[ $_slp_probe == / ]]; then break; fi
      _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_probe" 2>&1)
      if (( $? == 0 )); then break; fi
      if [[ "$_slp_stat_out" != *": No such file or directory" ]]; then
        printf -v _slp_reason 'home-base:ancestor-stat-failed:%s' "$_slp_probe"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "$_slp_reason" "ERROR"
        return 0
      fi
    done
    if [[ $_slp_probe == / ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "VALUE" "homes=0;discovered=0;checked=0;violations=0" "PASS"
      return 0
    fi
    case "$_slp_stat_out" in
      'symbolic link')
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-base:ancestor-symlink" "ERROR"
        return 0 ;;
      directory) ;;
      *)
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-base:ancestor-invalid-type" "ERROR"
        return 0 ;;
    esac
    if [[ ! -x "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-base:ancestor-unsearchable" "ERROR"
      return 0
    fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "VALUE" "homes=0;discovered=0;checked=0;violations=0" "PASS"
    return 0
  fi
  case "$_slp_stat_out" in
    'symbolic link')
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-base:symlink" "ERROR"
      return 0 ;;
    directory) ;;
    *)
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-base:invalid-type" "ERROR"
      return 0 ;;
  esac

  _slp_home_entries=()
  mapfile -d "" -t _slp_home_entries < <(
    LC_ALL=C command /usr/bin/find -P -- "$_slp_home" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_marker"
  )
  if (( ${#_slp_home_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_home_entries[@]}-1))
  _slp_marker=${_slp_home_entries[$_slp_i]}
  unset '_slp_home_entries[$_slp_i]'
  if [[ ! $_slp_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home-scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_home_entries[@]}"; do
    if [[ ${_slp_seen_entries["$_slp_entry"]+x} ]]; then continue; fi
    _slp_seen_entries["$_slp_entry"]=1
    _slp_bad=0
    if [[ "$_slp_entry" == *$'\t'* || "$_slp_entry" == *$'\n'* || "$_slp_entry" == *$'\r'* || "$_slp_entry" == *$'\x7f'* ]]; then _slp_bad=1; fi
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_entry" 2>&1)
    if (( $? != 0 )); then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      if [[ "$_slp_stat_out" == *": No such file or directory" ]]; then
        printf -v _slp_reason 'home:vanished:%s' "$_slp_entry"
      else
        printf -v _slp_reason 'home:stat-failed:%s' "$_slp_entry"
      fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if [[ "$_slp_stat_out" == "symbolic link" ]]; then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      _slp_target=$(command /usr/bin/readlink -- "$_slp_entry" 2>/dev/null && printf x)
      if [[ $? -eq 0 ]]; then
        _slp_target=${_slp_target%x}
        _slp_target=${_slp_target%$'\n'}
        if [[ "$_slp_target" == *$'\t'* || "$_slp_target" == *$'\n'* || "$_slp_target" == *$'\r'* || "$_slp_target" == *$'\x7f'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-name" "ERROR"
          return 0
        elif [[ -n "$_slp_target" ]]; then
          printf -v _slp_reason 'home:symlink:%s->%s' "$_slp_entry" "$_slp_target"
        else
          printf -v _slp_reason 'home:symlink:%s' "$_slp_entry"
        fi
      else
        printf -v _slp_reason 'home:symlink:%s' "$_slp_entry"
      fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if [[ "$_slp_stat_out" != "directory" ]]; then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      printf -v _slp_reason 'home:not-directory:%s' "$_slp_entry"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:invalid-name" "ERROR"
      return 0
    fi
    _slp_home=$_slp_entry
    if [[ ! -r "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:unreadable" "ERROR"
      return 0
    fi
    if [[ ! -x "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "home:unsearchable" "ERROR"
      return 0
    fi
    ((_slp_homes+=1))
    _slp_entries=()
    mapfile -d "" -t _slp_entries < <(
      LC_ALL=C command /usr/bin/find -P -- "$_slp_home" -xdev -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
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
      _slp_base=${_slp_entry##*/}
      case "$_slp_base" in
        .bash_history|.history|.sh_history|.bash_profile|.bashrc|.profile|.bash_logout|.rhosts|.bash_login|.xonshrc|.zsh_history|.zshrc|.zprofile|.zlogin|.zlogout|.zshenv|.ksh_history|.kshrc|.mkshrc|.cshrc|.tcshrc|.login|.logout) ;;
        *) continue ;;
      esac
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
  done
  local _slp_value="homes=$_slp_homes;discovered=$_slp_dynamic;checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_11_HOME_DIRECTORIES_MODE() {
  local _slp_home='/home' _slp_expected='0700'
  local _slp_probe _slp_entry _slp_mode _slp_scan_marker _slp_find_rc _slp_sort_rc _slp_i
  local _slp_target _slp_reason _slp_bad _slp_stat_out
  local _slp_checked=0 _slp_violations=0
  local -a _slp_entries=()
  local -A _slp_seen=()
  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_home" 2>&1)
  if (( $? != 0 )); then
    if [[ "$_slp_stat_out" != *": No such file or directory" ]]; then
      printf -v _slp_reason 'home-base:stat-failed:%s' "$_slp_home"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    _slp_probe=$_slp_home
    while [[ $_slp_probe != / ]]; do
      _slp_probe=${_slp_probe%/*}
      [[ -n $_slp_probe ]] || _slp_probe=/
      if [[ $_slp_probe == / ]]; then break; fi
      _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_probe" 2>&1)
      if (( $? == 0 )); then break; fi
      if [[ "$_slp_stat_out" != *": No such file or directory" ]]; then
        printf -v _slp_reason 'home-base:ancestor-stat-failed:%s' "$_slp_probe"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "$_slp_reason" "ERROR"
        return 0
      fi
    done
    if [[ $_slp_probe == / ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "VALUE" "checked=0;violations=0" "PASS"
      return 0
    fi
    case "$_slp_stat_out" in
      'symbolic link')
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home-base:ancestor-symlink" "ERROR"
        return 0 ;;
      directory) ;;
      *)
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home-base:ancestor-invalid-type" "ERROR"
        return 0 ;;
    esac
    if [[ ! -x "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home-base:ancestor-unsearchable" "ERROR"
      return 0
    fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "VALUE" "checked=0;violations=0" "PASS"
    return 0
  fi
  case "$_slp_stat_out" in
    'symbolic link')
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home-base:symlink" "ERROR"
      return 0 ;;
    directory) ;;
    *)
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home-base:invalid-type" "ERROR"
      return 0 ;;
  esac
  _slp_entries=()
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -P -- "$_slp_home" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "scan:missing-marker" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "scan:invalid-marker" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "scan:find-failed" "ERROR"
    return 0
  fi
  if (( _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "scan:sort-failed" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ ${_slp_seen["$_slp_entry"]+x} ]]; then continue; fi
    _slp_seen["$_slp_entry"]=1
    _slp_bad=0
    if [[ "$_slp_entry" == *$'\t'* || "$_slp_entry" == *$'\n'* || "$_slp_entry" == *$'\r'* || "$_slp_entry" == *$'\x7f'* ]]; then _slp_bad=1; fi
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_entry" 2>&1)
    if (( $? != 0 )); then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      if [[ "$_slp_stat_out" == *": No such file or directory" ]]; then
        printf -v _slp_reason 'home:vanished:%s' "$_slp_entry"
      else
        printf -v _slp_reason 'home:stat-failed:%s' "$_slp_entry"
      fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if [[ "$_slp_stat_out" == "symbolic link" ]]; then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      _slp_target=$(command /usr/bin/readlink -- "$_slp_entry" 2>/dev/null && printf x)
      if [[ $? -eq 0 ]]; then
        _slp_target=${_slp_target%x}
        _slp_target=${_slp_target%$'\n'}
        if [[ "$_slp_target" == *$'\t'* || "$_slp_target" == *$'\n'* || "$_slp_target" == *$'\r'* || "$_slp_target" == *$'\x7f'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-name" "ERROR"
          return 0
        elif [[ -n "$_slp_target" ]]; then
          printf -v _slp_reason 'home:symlink:%s->%s' "$_slp_entry" "$_slp_target"
        else
          printf -v _slp_reason 'home:symlink:%s' "$_slp_entry"
        fi
      else
        printf -v _slp_reason 'home:symlink:%s' "$_slp_entry"
      fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if [[ "$_slp_stat_out" != "directory" ]]; then
      if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-name" "ERROR"
        return 0
      fi
      printf -v _slp_reason 'home:not-directory:%s' "$_slp_entry"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "$_slp_reason" "ERROR"
      return 0
    fi
    if (( _slp_bad )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-name" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:mode-read-failed" "ERROR"
      return 0
    fi
    [[ "$_slp_mode" =~ ^[0-7]{3,4}$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "home:invalid-mode" "ERROR"; return 0; }
    ((_slp_checked+=1))
    if (( 8#$_slp_mode != 8#$_slp_expected )); then ((_slp_violations+=1)); fi
  done
  local _slp_value="checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_2_RUNNING_PROCESS_PATHS_WRITE_PROTECTION() {
  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra='' _slp_attempt=0
  while :; do
  _slp_attempt=$((_slp_attempt + 1))
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
PF_KTHREAD = 0x00200000


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def read_stat_fields(pid):
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
    if ASCII_DECIMAL.fullmatch(fields[19]) is None:
        error("proc-stat:invalid-starttime")
    return fields


def read_start(pid):
    fields = read_stat_fields(pid)
    if fields is None:
        return None
    return fields[19]


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
    except UnicodeDecodeError:
        error("proc-status:invalid-bytes")
    except Exception:
        error("proc-status:read-failed")
    if "\x00" in status or "\r" in status:
        error("proc-status:invalid-bytes")
    kthread = None
    state = None
    for line in status.splitlines():
        if line.startswith("Kthread:"):
            kthread = line.split(":", 1)[1].strip() == "1"
        elif line.startswith("State:"):
            value = line.split(":", 1)[1].strip()
            state = value[:1] if value else None
    if kthread is None:
        # No Kthread line in status (observed on 5.15 and 6.1): PF_KTHREAD in stat flags.
        fields = read_stat_fields(pid)
        if fields is None:
            error("proc-stat:excluded-classification-vanished")
        if ASCII_DECIMAL.fullmatch(fields[6]) is None:
            error("proc-stat:invalid-flags")
        kthread = (int(fields[6], 10) & PF_KTHREAD) != 0
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
    except UnicodeDecodeError:
        error("proc-maps:invalid-bytes")
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
        if path.startswith("anon_inode:") and perms[2] != "x":
            continue
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
  if (( _slp_rc == 0 && _slp_attempt < 3 )) && [[ $_slp_obs == ERROR$'\t'* ]]; then
    case ${_slp_obs#ERROR$'\t'} in
      proc-population:process-disappeared|proc-stat:initial-starttime-changed|proc-stat:initial-endtime-changed|proc-stat:excluded-classification-vanished|proc-stat:excluded-classification-changed|pid-population:mid-snapshot-changed|proc-counter:mid-snapshot-changed|proc-stat:recheck-starttime-changed|proc-exe:recheck-missing|proc-stat:recheck-endtime-changed|proc-stat:excluded-recheck-changed|proc-exe:excluded-reappeared|pid-population:final-snapshot-changed|proc-counter:final-snapshot-changed) command /usr/bin/sleep 1; continue ;;
    esac
  fi
  break
  done
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
# No PATH= in the crontab: every executable match in these directories is a target.
DEFAULT_SEARCH_PATH = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/snap/bin")
UNSUPPORTED_COMPOUND = {"while", "until", "for", "case", "select", "function", "coproc", "do", "done", "esac", "[[", "]]"}
FD_WORDS = {"1", "2"}


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


def stable_search_dir(path, optional):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        if optional:
            return None
        error("directory:not-found")
    except Exception:
        error("directory:lstat-failed")
    if not stat.S_ISLNK(first.st_mode):
        return stable_dir(path, optional=optional)
    try:
        real = os.path.realpath(path)
        target = os.stat(real, follow_symlinks=True)
        second = os.lstat(path)
    except FileNotFoundError:
        if optional:
            return None
        error("directory:not-found")
    except Exception:
        error("directory:resolve-failed")
    if obj_state(first) != obj_state(second):
        error("directory:changed-during-check")
    if not stat.S_ISDIR(target.st_mode):
        error("directory:invalid-type")
    return obj_state(first), real, obj_state(target)


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
        if ("<" in tok or ">" in tok) and tok not in {">", ">&"}:
            error("command:unsupported-redirection")
    return tokens


def resolve_root_command(word, path_env, uid, dir_records):
    if "/" in word:
        if not word.startswith("/"):
            error("command:relative-path")
        return [word]
    if uid != 0:
        error("command:unresolved-name")
    search = DEFAULT_SEARCH_PATH if path_env is None else path_env
    found = []
    for d in search:
        drec = stable_search_dir(map_abs(d), optional=path_env is None)
        dir_records[("path", d)] = drec
        if drec is None:
            continue
        candidate_text = d.rstrip("/") + "/" + word
        candidate = map_abs(candidate_text)
        try:
            st = os.stat(candidate, follow_symlinks=True)
        except FileNotFoundError:
            continue
        except Exception:
            error("command:stat-failed")
        if stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) & 0o111:
            if path_env is not None:
                return [candidate_text]
            found.append(candidate_text)
    if not found:
        error("command:not-found")
    return found


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
    stack = []
    closed = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in {">", ">&"}:
            if i + 1 >= len(tokens):
                error("command:unsupported-redirection")
            sink = tokens[i + 1]
            if not ((tok == ">" and sink == "/dev/null") or (tok == ">&" and sink in FD_WORDS)):
                error("command:unsupported-redirection")
            if len(current) >= 2 and current[-1] in FD_WORDS:
                current.pop()
            if not current:
                error("command:unsupported-redirection")
            i += 2
            continue
        i += 1
        if closed:
            if tok not in CONTROL_OPS or tok == "(":
                error("command:unsupported-grouping")
            closed = False
        if not current:
            if tok in {"(", "{", "if"}:
                stack.append(tok)
                continue
            if tok == "}":
                if not stack or stack[-1] != "{":
                    error("command:unbalanced-group")
                stack.pop()
                closed = True
                continue
            if tok == "then":
                if not stack or stack[-1] not in {"if", "elif"}:
                    error("command:unbalanced-group")
                stack[-1] = "then"
                continue
            if tok in {"elif", "else"}:
                if not stack or stack[-1] != "then":
                    error("command:unbalanced-group")
                stack[-1] = tok
                continue
            if tok == "fi":
                if not stack or stack[-1] not in {"then", "else"}:
                    error("command:unbalanced-group")
                stack.pop()
                closed = True
                continue
            if tok == "!":
                continue
        if tok == ")":
            if current:
                segments.append(current); current = []
            if not stack or stack[-1] != "(":
                error("command:unbalanced-group")
            stack.pop()
            closed = True
            continue
        if tok in CONTROL_OPS:
            if tok == "(":
                error("command:unsupported-grouping")
            if current:
                segments.append(current); current = []
            continue
        current.append(tok)
    if current:
        segments.append(current)
    if stack or not segments:
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
        if command_word == "exec":
            if not args or args[0].startswith("-") or ASSIGNMENT.fullmatch(args[0]):
                error("command:unsupported-wrapper")
            command_word, args = args[0], args[1:]
        if command_word in SAFE_BUILTINS:
            continue
        # command -v/-V only reports the lookup result and runs nothing.
        if command_word == "command" and len(args) == 2 and args[0] in {"-v", "-V"}:
            continue
        if command_word in UNSUPPORTED_COMPOUND:
            error("command:unsupported-compound")
        if command_word in UNSUPPORTED_COMMANDS:
            error("command:unsupported-wrapper")
        periodic = False
        for resolved in resolve_root_command(command_word, local_path, uid, dir_records):
            _resolved_rec, canonical_base = resolved_command_record(resolved)
            if canonical_base in UNSUPPORTED_COMMANDS or INTERPRETER_NAME.fullmatch(canonical_base) is not None:
                error("command:unsupported-execution-chain")
            add_target(resolved, targets, allow_nonexec=False)
            if canonical_base == "run-parts":
                periodic = True
        if periodic:
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

    # One file reached by several paths (/usr/bin/run-parts and /bin/run-parts on merged /usr)
    # is counted once: identity is dev:ino of the final regular file.
    unique = {rec[3][:2]: rec for rec in targets.values()}
    violations = sum(1 for rec in unique.values() if rec[3][4] & 0o022)
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
value = f"configs={configs};jobs={jobs};targets={len({rec[3][:2] for rec in targets.values()})};periodic_dirs={periodic};violations={violations};ambiguous=0"
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
  _slp_obs=$(command /usr/bin/python3 -I -S -B - '/' '/etc/sudoers' '/usr/sbin/visudo' '/usr/bin/cvtsudoers' '/etc/login.defs' '/etc/adduser.conf' <<'SLP_SUDO_ROOT_FILES_PY'
import hashlib, json, os, re, stat, subprocess, sys
from pathlib import Path

fsroot = Path(sys.argv[1])
sudoers_path = Path(sys.argv[2])
visudo_path = sys.argv[3]
cvtsudoers_path = sys.argv[4]
login_defs_path = Path(sys.argv[5])
adduser_conf_path = Path(sys.argv[6])
ALLOWED_COMMAND_KEYS = {"command", "negated", "sha224", "sha256", "sha384", "sha512"}
WILDCARD_CHARS = set("*?[")
UID_RANGE_LINE = re.compile(r"^\s*([A-Z_]+)\s+([0-9]+)\s*$")
CONF_RANGE_LINE = re.compile(r"^\s*([A-Z_]+)\s*=\s*\"?([0-9]+)\"?\s*$")


def error(reason):
    print("ERROR\t" + reason)
    raise SystemExit(0)


def resolve_cvtsudoers(primary):
    # Ubuntu 26.04 with sudo-rs active: package sudo installs cvtsudoers as cvtsudoers.ws.
    if os.path.lexists(primary):
        return primary
    fallback = primary + ".ws"
    try:
        st = os.stat(fallback)
    except FileNotFoundError:
        return primary
    except Exception:
        error("cvtsudoers:fallback-stat-failed")
    if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.geteuid()) or stat.S_IMODE(st.st_mode) & 0o022:
        error("cvtsudoers:untrusted-fallback")
    return fallback


def obj_state(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)


def map_target(logical):
    return fsroot / logical.lstrip("/")


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


def observe_pathset(paths, domain):
    out = {}
    for path_text in sorted(paths):
        state, raw = stable_regular_bytes(Path(path_text), domain)
        out[path_text] = (state, hashlib.sha256(raw).hexdigest())
    return out


def policy_snapshot():
    # The sudoers pathset is the closure that visudo reports after validating the
    # active tree; no reviewed-policy file is read.  Identities and bytes of that
    # pathset are part of the snapshot, and the whole snapshot is compared
    # between the two policy observations of one check.
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
    closure = []
    for line in text.splitlines():
        suffix = ": parsed OK"
        if not line.endswith(suffix):
            error("visudo:invalid-output")
        path_text = line[:-len(suffix)]
        if not path_text.startswith("/") or any(c in path_text for c in "\x00\r\n\t") or path_text in closure:
            error("visudo:invalid-output")
        closure.append(path_text)
    if not closure or str(sudoers_path) not in closure:
        error("visudo:invalid-output")
    return tuple(sorted(observe_pathset(closure, "sudoers").items()))


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
            if obj["runchroot"] is False:
                continue
            error("sudo-policy:runchroot-enabled")


def validate_defaults_shape(defaults):
    # Shape validation never depends on admission: an unmodelled Defaults document
    # means the policy was not observed completely, and an incompletely observed
    # policy cannot yield the determinate NOT_APPLICABLE result.
    if not isinstance(defaults, list):
        error("sudo-policy:invalid-defaults")
    for entry in defaults:
        if not isinstance(entry, dict) or set(entry) - {"Binding", "Options"} or "Options" not in entry:
            error("sudo-policy:invalid-defaults")
        binding = entry.get("Binding")
        if binding is not None and (not isinstance(binding, list) or not binding):
            error("sudo-policy:invalid-default-binding")
        options = entry["Options"]
        if not isinstance(options, list):
            error("sudo-policy:invalid-options")
        for obj in options:
            if not isinstance(obj, dict):
                error("sudo-policy:invalid-options")
            if "runchroot" in obj and set(obj) != {"runchroot"}:
                error("sudo-policy:runchroot-mixed-option")


def validate_defaults_applicability(defaults):
    # Applicability is evaluated only when the population is non-empty: Defaults
    # that cannot affect an explicit non-root-only Runas_Spec are out of scope.
    for entry in defaults:
        options = entry["Options"]
        reject_enabled_runchroot_options(options)
        for obj in options:
            # runas_default changes the implicit Runas_Spec; this adapter does not
            # evaluate Defaults binding precedence, so applicability is ambiguous.
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


def validate_user_list(user_list):
    # Invoker identity does not narrow the population: any invoker able to run the
    # rule is out of scope for SRC-0008.  Only structural validity is required.
    if not isinstance(user_list, list) or not user_list:
        error("sudo-policy:invalid-user-list")
    for obj in user_list:
        if not isinstance(obj, dict) or not obj:
            error("sudo-policy:invalid-user-list")


def host_scope_supported(host_list):
    if not isinstance(host_list, list) or not host_list:
        error("sudo-policy:invalid-host-list")
    if len(host_list) != 1:
        error("sudo-policy:ambiguous-host-selector")
    key, value, neg = one_selector(host_list[0], {"hostname", "networkaddr", "netgroup"})
    if neg or key != "hostname" or value != "ALL":
        error("sudo-policy:unsupported-host-selector")
    return True


def root_runas_possible(spec):
    groups = spec.get("runasgroups")
    if groups is not None:
        if not isinstance(groups, list):
            error("sudo-policy:invalid-runas-list")
        # A group part next to a user part, as in (ALL:ALL), only selects the
        # target group; admission is decided by the user part below.  A
        # group-only Runas_Spec runs the command as the invoking user, which the
        # user-part rules below do not model, so it stays fail-closed.
        if groups and "runasusers" not in spec:
            error("sudo-policy:unsupported-runas-group")
    if "runasusers" not in spec:
        return True
    runas = spec["runasusers"]
    if not isinstance(runas, list) or not runas:
        error("sudo-policy:invalid-runas-list")
    allowed = {"netgroup", "nonunixgid", "nonunixgroup", "runasalias", "usergid", "usergroup", "userid", "username"}
    root_possible = False
    for obj in runas:
        key, value, neg = one_selector(obj, allowed)
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


def logical_target(command):
    if not isinstance(command, str) or not command or any(c in command for c in "\x00\r\n"):
        error("sudo-policy:invalid-command")
    # sudoedit does not name an executable target of this control; it is excluded
    # before any other command-form check.
    if command == "sudoedit" or command.startswith("sudoedit "):
        return None
    # ALL names no concrete executable file of this control; the rights of
    # system programs are checked by 2.3.8.  Only explicit absolute pathnames
    # enter the population.
    if command == "ALL":
        return None
    if command.startswith("^"):
        error("sudo-policy:regex-command")
    if not command.startswith("/"):
        error("sudo-policy:nonabsolute-command")
    if any(c in command for c in WILDCARD_CHARS):
        error("sudo-policy:wildcard-command")
    if command.endswith("/"):
        error("sudo-policy:directory-command")
    # cvtsudoers JSON merges pathname and arguments into one string and unescapes
    # escaped whitespace inside a pathname, so a command string containing any
    # whitespace has no provable pathname boundary.  The filesystem is never used
    # as an oracle for that boundary.
    if any(ch.isspace() for ch in command):
        error("sudo-policy:unprovable-command-path")
    parts = command.split("/")
    if any(part in {".", ".."} for part in parts) or "\\" in command:
        error("sudo-policy:nonabsolute-command")
    return command


def collect_targets(specs):
    targets = set()
    for user_spec in specs:
        if not isinstance(user_spec, dict) or set(user_spec) != {"User_List", "Host_List", "Cmnd_Specs"}:
            error("sudo-policy:invalid-user-spec")
        validate_user_list(user_spec["User_List"])
        host_list = user_spec["Host_List"]
        if not isinstance(host_list, list) or not host_list:
            error("sudo-policy:invalid-host-list")
        cmnd_specs = user_spec["Cmnd_Specs"]
        if not isinstance(cmnd_specs, list):
            error("sudo-policy:invalid-command-specs")
        # Admission by runas is decided first: a rule whose targets can only run as
        # explicit non-root accounts is outside SRC-0008 and must not be rejected
        # because of an unsupported host scope or command option.
        admitted = []
        for spec in cmnd_specs:
            if not isinstance(spec, dict) or "Commands" not in spec or set(spec) - {"Commands", "runasusers", "runasgroups", "Options"}:
                error("sudo-policy:invalid-command-spec")
            if root_runas_possible(spec):
                admitted.append(spec)
        if not admitted:
            continue
        host_scope_supported(host_list)
        for spec in admitted:
            options = spec.get("Options")
            reject_enabled_runchroot_options(options)
            if options is not None:
                if not isinstance(options, list):
                    error("sudo-policy:invalid-command-options")
                for obj in options:
                    if not isinstance(obj, dict):
                        error("sudo-policy:invalid-command-options")
                    if "notbefore" in obj or "notafter" in obj:
                        error("sudo-policy:time-qualified-command")
            commands = spec["Commands"]
            if not isinstance(commands, list) or not commands:
                error("sudo-policy:invalid-command-list")
            for obj in commands:
                if not isinstance(obj, dict) or set(obj) - ALLOWED_COMMAND_KEYS:
                    error("sudo-policy:invalid-command-entry")
                if "command" not in obj or not isinstance(obj.get("negated", False), bool):
                    error("sudo-policy:invalid-command-entry")
                if any(key in obj for key in ("sha224", "sha256", "sha384", "sha512")):
                    error("sudo-policy:digest-qualified-command")
                if obj.get("negated", False):
                    error("sudo-policy:negated-command")
                target = logical_target(obj["command"])
                if target is not None:
                    targets.add(target)
    return tuple(sorted(targets, key=os.fsencode))


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
    if target_first.st_nlink != 1:
        error("target:ambiguous-identity")
    return (logical, resolved, obj_state(link_first), obj_state(target_first))


def stable_optional_regular_bytes(path, domain):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        # Absence is a legitimate state for the two optional UID-range sources.
        # It is recorded so that the final owner-authority revalidation can detect
        # an absent->present transition.
        try:
            os.lstat(path)
        except FileNotFoundError:
            return ("ABSENT",), None
        except Exception:
            error(domain + ":stat-failed")
        error(domain + ":changed-during-check")
    except Exception:
        error(domain + ":stat-failed")
    if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):
        error(domain + ":invalid-type")
    try:
        raw = path.read_bytes()
        second = os.lstat(path)
    except Exception:
        error(domain + ":read-failed")
    if obj_state(first) != obj_state(second):
        error(domain + ":changed-during-check")
    return ("PRESENT", obj_state(first), hashlib.sha256(raw).hexdigest()), raw


def read_uid_range(path, pattern, keys, domain):
    mapped = map_target(str(path))
    snapshot, raw = stable_optional_regular_bytes(mapped, domain)
    if raw is None:
        return None, snapshot
    if b"\x00" in raw:
        error(domain + ":invalid-bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error(domain + ":invalid-bytes")
    found = {}
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        match = pattern.match(line)
        if match is None:
            continue
        name, value = match.group(1), match.group(2)
        if name not in keys:
            continue
        if name in found:
            error(domain + ":duplicate-key")
        found[name] = int(value, 10)
    # An existing source that does not yield the exact key pair is unusable, and an
    # unusable source is an error rather than an absent one.
    if set(found) != set(keys):
        error(domain + ":incomplete-range")
    low, high = found[keys[0]], found[keys[1]]
    if low > high:
        error(domain + ":invalid-range")
    return (low, high), snapshot


def passwd_snapshot():
    mapped = map_target("/etc/passwd")
    state, raw = stable_regular_bytes(mapped, "passwd")
    if b"\x00" in raw or b"\r" in raw:
        error("passwd:invalid-bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error("passwd:invalid-bytes")
    by_uid = {}
    for line in text.splitlines():
        if not line:
            continue
        fields = line.split(":")
        if len(fields) != 7:
            error("passwd:invalid-record")
        if not fields[2].isdigit():
            error("passwd:invalid-record")
        uid = int(fields[2], 10)
        by_uid.setdefault(uid, set()).add(fields[0])
    names = {uid: tuple(sorted(values)) for uid, values in by_uid.items()}
    snapshot = (state, hashlib.sha256(raw).hexdigest())
    return snapshot, names


def owner_sources():
    ranges = []
    tokens = []

    login, login_token = read_uid_range(
        login_defs_path, UID_RANGE_LINE, ("UID_MIN", "UID_MAX"), "login-defs")
    tokens.append(("login-defs", login_token))
    if login is not None:
        ranges.append(login)

    adduser, adduser_token = read_uid_range(
        adduser_conf_path, CONF_RANGE_LINE, ("FIRST_UID", "LAST_UID"), "adduser-conf")
    tokens.append(("adduser-conf", adduser_token))
    if adduser is not None:
        ranges.append(adduser)

    if not ranges:
        # Without any usable range source a non-root owner cannot be classified as
        # regular or non-regular, and a fallback default would invent authority.
        error("owner-classification:no-source")

    passwd_token, passwd_names = passwd_snapshot()
    tokens.append(("passwd", passwd_token))
    return tuple(ranges), passwd_names, tuple(tokens)


def owner_condition(uid, ranges, passwd_names):
    if uid == 0:
        return False
    names = passwd_names.get(uid, ())
    if not names:
        error("owner-classification:unknown-uid")
    if len(names) != 1:
        error("owner-classification:ambiguous-uid")
    verdicts = {low <= uid <= high for (low, high) in ranges}
    if len(verdicts) != 1:
        error("owner-classification:conflicting-sources")
    return verdicts.pop()


cvtsudoers_path = resolve_cvtsudoers(cvtsudoers_path)
policy_before = policy_snapshot()
cvt_before, defaults, specs = cvt_snapshot()

# Population admission is decided before semantic Defaults validation.  Defaults
# that cannot affect an explicit non-root-only Runas_Spec are outside SRC-0008 and
# must not turn a clean empty population into ERROR.  When at least one target is
# admitted, the current fail-closed Defaults boundary remains unchanged.
validate_defaults_shape(defaults)
targets = collect_targets(specs)
if not targets:
    policy_after = policy_snapshot()
    cvt_after, defaults_after, specs_after = cvt_snapshot()
    validate_defaults_shape(defaults_after)
    if policy_after != policy_before or cvt_after != cvt_before or collect_targets(specs_after) != ():
        error("observation:policy-changed")
    print("NOT_APPLICABLE\tfiles=0;owner_violations=0;mode_violations=0\tNOT_APPLICABLE")
    raise SystemExit(0)

validate_defaults_applicability(defaults)
records = {logical: stable_target(logical) for logical in targets}

# UID 0 is decided without OWNER classification sources.  For any non-root owner,
# capture all OWNER-authority inputs once, classify only from that snapshot, then
# re-read and compare those inputs after the second policy/cvtsudoers snapshot.
owner_before = None
ranges = ()
passwd_names = {}
if any(rec[3][2] != 0 for rec in records.values()):
    ranges, passwd_names, owner_before = owner_sources()

owner_bad = 0
mode_bad = 0
for rec in records.values():
    state = rec[3]
    if owner_condition(state[2], ranges, passwd_names):
        owner_bad += 1
    if state[4] & 0o002:
        mode_bad += 1

policy_after = policy_snapshot()
cvt_after, defaults_after, specs_after = cvt_snapshot()
validate_defaults_shape(defaults_after)
validate_defaults_applicability(defaults_after)
if policy_after != policy_before or cvt_after != cvt_before or collect_targets(specs_after) != targets:
    error("observation:policy-changed")

if owner_before is not None:
    ranges_after, passwd_names_after, owner_after = owner_sources()
    if owner_after != owner_before:
        error("owner-authority:changed-during-check")

for logical, before in records.items():
    if stable_target(logical) != before:
        error("observation:target-changed")

print("VALUE\tfiles=%d;owner_violations=%d;mode_violations=%d\t%s" % (
    len(targets), owner_bad, mode_bad, "PASS" if owner_bad == 0 and mode_bad == 0 else "FAIL"))

SLP_SUDO_ROOT_FILES_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )); then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:execution-failed\tERROR\n' "$_slp_cid"; return 0; fi
  if [[ $_slp_obs == ERROR$'\t'* ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\t%s\tERROR\n' "$_slp_cid" "${_slp_obs#*$'\t'}"; return 0; fi
  if [[ $_slp_obs == NOT_APPLICABLE$'\t'* ]]; then IFS=$'\t' read -r _slp_kind _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"; if [[ -z "$_slp_value" || -n "$_slp_extra" || "$_slp_compliance" != NOT_APPLICABLE ]]; then printf 'SLP-CHECK-V1\t%s\tERROR\tobserver:invalid-output\tERROR\n' "$_slp_cid"; return 0; fi; printf 'SLP-CHECK-V1\t%s\tNOT_APPLICABLE\t%s\tNOT_APPLICABLE\n' "$_slp_cid" "$_slp_value"; return 0; fi
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
  if [[ ! -x /usr/bin/python3 ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "runtime:python3-missing" "ERROR"
    return 0
  fi
  local _slp_observed=''
  if ! _slp_observed=$(LC_ALL=C command /usr/bin/python3 -I -S -B - 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "$_slp_expected" "${#_slp_exec_roots[@]}" "${#_slp_lib_roots[@]}" "${_slp_exec_roots[@]}" "${_slp_lib_roots[@]}" "$_slp_module_root" 2>/dev/null <<'SLP_SRC0012_PY'
import os
import stat
import subprocess
import sys

class ObservationError(Exception):
    pass

def error(reason):
    raise ObservationError(reason)

def resolve(path, role):
    try:
        proc = subprocess.run([b"/usr/bin/readlink", b"-f", b"--", path],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        error(role + ":resolve-failed")
    if proc.returncode != 0:
        error(role + ":resolve-failed")
    result = proc.stdout.rstrip(b"\n")
    if not result:
        error(role + ":resolve-empty")
    return result

def entries(root):
    try:
        proc = subprocess.run([b"/usr/bin/find", b"-P", b"--", root,
                               b"-mindepth", b"1", b"-print0"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        error("scan:find-failed")
    if proc.returncode != 0:
        error("scan:find-failed")
    if proc.stdout and not proc.stdout.endswith(b"\0"):
        error("scan:missing-marker")
    try:
        return sorted(proc.stdout.split(b"\0")[:-1]) if proc.stdout else []
    except MemoryError:
        error("scan:sort-failed")

def observe():
    mask = int(sys.argv[2], 8)
    ne, nl = int(sys.argv[3]), int(sys.argv[4])
    paths = [os.fsencode(p) for p in sys.argv[5:]]
    if len(paths) != ne + nl + 1:
        error("runtime:observer-arguments")
    groups = (("exec", paths[:ne]), ("lib", paths[ne:ne+nl]), ("module", paths[ne+nl:]))
    seen_roots, seen_targets = set(), set()
    exec_root_ids = set()
    for root in paths[:ne]:
        try:
            info = os.stat(root)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode):
            exec_root_ids.add((info.st_dev, info.st_ino))
    present = absent = aliases = checked = violations = 0
    _slp_exec = _slp_libraries = _slp_modules = 0
    for role, roots in groups:
        for root in roots:
            try:
                os.lstat(root)
            except FileNotFoundError:
                absent += 1
                continue
            except OSError:
                error("root:resolve-failed")
            resolved = resolve(root, "root")
            if not os.path.isdir(resolved):
                error("root:invalid-type")
            try:
                info = os.stat(resolved)
            except OSError:
                error("root:identity-failed")
            present += 1
            identity = (info.st_dev, info.st_ino)
            if identity in seen_roots:
                aliases += 1
                continue
            seen_roots.add(identity)
            for entry in entries(resolved):
                if os.path.isdir(entry) and not os.path.islink(entry):
                    continue
                name = os.path.basename(entry)
                if role == "lib" and not (name.endswith(b".so") or b".so." in name or name.endswith(b".a")):
                    continue
                if role == "module" and not (name.endswith(b".ko") or b".ko." in name):
                    continue
                if os.path.islink(entry):
                    target = resolve(entry, "target")
                    if os.path.islink(target):
                        error("target:resolved-symlink")
                    if not os.path.isfile(target):
                        if role == "exec" and os.path.isdir(target):
                            try:
                                dinfo = os.stat(target)
                            except OSError:
                                error("target:identity-failed")
                            if (dinfo.st_dev, dinfo.st_ino) in exec_root_ids:
                                continue
                        error("target:invalid-type")
                elif os.path.isfile(entry):
                    target = entry
                else:
                    error("target:invalid-type")
                try:
                    info = os.stat(target)
                except OSError:
                    error("target:identity-failed")
                if not stat.S_ISREG(info.st_mode):
                    error("target:invalid-type")
                mode = stat.S_IMODE(info.st_mode)
                if len(format(mode, "o")) not in (3, 4):
                    error("target:invalid-mode")
                if role == "exec" and not mode & 0o111:
                    continue
                identity = (info.st_dev, info.st_ino)
                if identity in seen_targets:
                    continue
                seen_targets.add(identity)
                if role == "exec":
                    _slp_exec += 1
                elif role == "lib":
                    _slp_libraries += 1
                else:
                    _slp_modules += 1
                checked += 1
                if mode & mask:
                    violations += 1
    if _slp_exec == 0:
        error("population:missing-exec")
    if _slp_libraries == 0:
        error("population:missing-libraries")
    if _slp_modules == 0:
        error("population:missing-modules")
    value = (f"roots_present={present};roots_absent={absent};aliases={aliases};"
             f"exec={_slp_exec};libraries={_slp_libraries};modules={_slp_modules};"
             f"checked={checked};violations={violations}")
    return "VALUE", value, "FAIL" if violations else "PASS"

try:
    status, value, compliance = observe()
except ObservationError as exc:
    status, value, compliance = "ERROR", str(exc), "ERROR"
except Exception:
    status, value, compliance = "ERROR", "runtime:observer-failed", "ERROR"
print("\t".join(("SLP-CHECK-V1", sys.argv[1], status, value, compliance)))
SLP_SRC0012_PY
  ); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "runtime:observer-failed" "ERROR"
    return 0
  fi
  printf "%s\n" "$_slp_observed"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_MODE() {
  local _slp_key='mode' _slp_op='bits-clear' _slp_expected='0022'
  local _slp_mountinfo='/proc/self/mountinfo' _slp_line _slp_id _slp_parent _slp_majmin _slp_root _slp_mp_raw _slp_opts _slp_tail
  local _slp_mp _slp_after _slp_fstype _slp_root_id _slp_entry _slp_ident _slp_mode _slp_marker _slp_find_rc _slp_sort_rc _slp_i _slp_hex
  local _slp_mountinfo_text _slp_rest _slp_v_esc
  local _slp_mounts=0 _slp_checked=0 _slp_violations=0 _slp_lineno=0
  local -a _slp_entries=()
  local -A _slp_seen_mounts=() _slp_seen_files=()

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
  if [[ -z $_slp_hex ]]; then
    _slp_mountinfo_text=""
  else
    _slp_v_esc=$(printf '\\x%s' $_slp_hex)
    printf -v _slp_mountinfo_text %b "$_slp_v_esc"
  fi
  _slp_rest=$_slp_mountinfo_text
  while [[ -n $_slp_rest ]]; do
    if [[ $_slp_rest == *$'\n'* ]]; then _slp_line=${_slp_rest%%$'\n'*}; _slp_rest=${_slp_rest#*$'\n'}; else _slp_line=$_slp_rest; _slp_rest=""; fi
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
  done
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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

slp_check_FSTEC_LINUX_2022_2_5_2_PERF_EVENT_PARANOID() {
  local _slp_path='/proc/sys/kernel/perf_event_paranoid'
  local _slp_expected='3'
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0
  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent= _slp_stat_out=
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "NOT_FOUND" "-" "NOT_FOUND"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:read-failed" "ERROR"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "cmdline:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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
  local _slp_raw _slp_text _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd _slp_parent _slp_stat_out
  local LC_ALL=C
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)
    if (( $? != 0 )) && [[ "$_slp_stat_out" == *": No such file or directory" ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "NOT_FOUND" "-" "NOT_FOUND"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:read-failed" "ERROR"
    fi
    return 0
  fi
  _slp_load_text() {
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
    done
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_load_text "$_slp_path" _slp_text; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    if (( _slp_vrc == 2 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:read-failed" "ERROR"
    else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "sysctl:invalid-bytes" "ERROR"
    fi
    return 0
  fi
  if [[ $_slp_text == *$'\n'* ]]; then
    _slp_raw=${_slp_text%%$'\n'*}
  else
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

slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PASSWORD_AUTHENTICATION() {
  local LC_ALL=C
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective _slp_parent _slp_stat_out
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
    _slp_parent=${_slp_cfg%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_cfg" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:unreadable" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:unreadable" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "tool:find-missing" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "tool:sort-missing" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
    _slp_parent=${_slp_sshd%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_sshd" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-binary:resolve-failed" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-binary:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-binary:not-executable" "ERROR"
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
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local _slp_pf_text _slp_ptext_rest _slp_stat_out
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf" _slp_pf_text; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    _slp_ptext_rest=$_slp_pf_text
    while [[ -n $_slp_ptext_rest ]]; do
      if [[ $_slp_ptext_rest == *$'\n'* ]]; then _slp_pl=${_slp_ptext_rest%%$'\n'*}; _slp_ptext_rest=${_slp_ptext_rest#*$'\n'}; else _slp_pl=$_slp_ptext_rest; _slp_ptext_rest=''; fi
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
      [[ "$_slp_pk" == match || "$_slp_pk" == include || "$_slp_pk" == passwordauthentication ]] || continue
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
            else
              _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_prefix" 2>&1)
              if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-stat-failed; break 2; fi
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          else
            _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_px" 2>&1)
            if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-stat-failed; break 2; fi
          fi
          for _slp_item in "${_slp_glob[@]}"; do
            _slp_parse_sshd_file "$_slp_item" $((_slp_pd + 1)) 0 "$_slp_scope"
            (( _slp_parser_error == 0 )) || break 3
          done
        done
        continue
      fi
      if [[ "$_slp_pk" == passwordauthentication ]]; then
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == no ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != no ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "$_slp_parser_reason" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:ambiguous-match" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-config:validation-failed" "ERROR"
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-effective:query-failed" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^passwordauthentication[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "ERROR" "sshd-effective:ambiguous-value" "ERROR"
    return 0
  fi
  _slp_effective=${_slp_effective_lines[0]}
  if (( _slp_main_no > 0 )) && [[ "$_slp_effective" == no ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "VALUE" "main_global_no=$_slp_main_no;effective=no" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' "VALUE" "main_global_no=$_slp_main_no;effective=$_slp_effective" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PERMIT_EMPTY_PASSWORDS() {
  local LC_ALL=C
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective _slp_parent _slp_stat_out
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
    _slp_parent=${_slp_cfg%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_cfg" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:unreadable" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:unreadable" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "tool:find-missing" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "tool:sort-missing" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
    _slp_parent=${_slp_sshd%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_sshd" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-binary:resolve-failed" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-binary:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-binary:not-executable" "ERROR"
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
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local _slp_pf_text _slp_ptext_rest _slp_stat_out
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf" _slp_pf_text; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    _slp_ptext_rest=$_slp_pf_text
    while [[ -n $_slp_ptext_rest ]]; do
      if [[ $_slp_ptext_rest == *$'\n'* ]]; then _slp_pl=${_slp_ptext_rest%%$'\n'*}; _slp_ptext_rest=${_slp_ptext_rest#*$'\n'}; else _slp_pl=$_slp_ptext_rest; _slp_ptext_rest=''; fi
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
      [[ "$_slp_pk" == match || "$_slp_pk" == include || "$_slp_pk" == permitemptypasswords ]] || continue
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
            else
              _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_prefix" 2>&1)
              if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-stat-failed; break 2; fi
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          else
            _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_px" 2>&1)
            if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-stat-failed; break 2; fi
          fi
          for _slp_item in "${_slp_glob[@]}"; do
            _slp_parse_sshd_file "$_slp_item" $((_slp_pd + 1)) 0 "$_slp_scope"
            (( _slp_parser_error == 0 )) || break 3
          done
        done
        continue
      fi
      if [[ "$_slp_pk" == permitemptypasswords ]]; then
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == no ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != no ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "$_slp_parser_reason" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:ambiguous-match" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-config:validation-failed" "ERROR"
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-effective:query-failed" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^permitemptypasswords[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "ERROR" "sshd-effective:ambiguous-value" "ERROR"
    return 0
  fi
  _slp_effective=${_slp_effective_lines[0]}
  if (( _slp_main_no > 0 )) && [[ "$_slp_effective" == no ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "VALUE" "main_global_no=$_slp_main_no;effective=no" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' "VALUE" "main_global_no=$_slp_main_no;effective=$_slp_effective" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PERMIT_ROOT_LOGIN() {
  local LC_ALL=C
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_parser_reason=sshd-config:internal-reason-missing _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective _slp_parent _slp_stat_out
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:symlink" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
    _slp_parent=${_slp_cfg%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_cfg" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:unreadable" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:unreadable" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "tool:readlink-missing" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "tool:find-missing" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "tool:sort-missing" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-binary:resolve-failed" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
    _slp_parent=${_slp_sshd%/*}; [[ -z $_slp_parent ]] && _slp_parent=/
    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_sshd" 2>&1)
    if (( $? != 0 )) && [[ $_slp_stat_out == *': No such file or directory' ]] && [[ -d $_slp_parent && -x $_slp_parent ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-binary:resolve-failed" "ERROR"
    fi
    return 0
  fi
  if [[ ! -f "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-binary:invalid-type" "ERROR"
    return 0
  fi
  if [[ ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-binary:not-executable" "ERROR"
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
    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    if [[ -z $_slp_v_hex ]]; then
      printf -v "$_slp_v_out" %s ""
      return 0
    fi
    _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)
    printf -v "$_slp_v_out" %b "$_slp_v_esc"
    return 0
  }
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl _slp_vrc=0
    local _slp_pf_text _slp_ptext_rest _slp_stat_out
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-depth; return 0; }
    [[ ! -L "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-symlink; return 0; }
    [[ -e "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-not-found; return 0; }
    [[ -f "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-invalid-type; return 0; }
    [[ -r "$_slp_pf" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-unreadable; return 0; }
    _slp_validate_sshd_bytes "$_slp_pf" _slp_pf_text; _slp_vrc=$?
    if (( _slp_vrc != 0 )); then
      _slp_parser_error=1
      if (( _slp_vrc == 2 )); then _slp_parser_reason=sshd-config:read-failed; else _slp_parser_reason=sshd-config:invalid-bytes; fi
      return 0
    fi
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-resolve-failed; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:include-cycle; return 0; }
    _slp_stack["$_slp_pr"]=1
    _slp_ptext_rest=$_slp_pf_text
    while [[ -n $_slp_ptext_rest ]]; do
      if [[ $_slp_ptext_rest == *$'\n'* ]]; then _slp_pl=${_slp_ptext_rest%%$'\n'*}; _slp_ptext_rest=${_slp_ptext_rest#*$'\n'}; else _slp_pl=$_slp_ptext_rest; _slp_ptext_rest=''; fi
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
            else
              _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_prefix" 2>&1)
              if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-prefix-stat-failed; break 2; fi
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-glob-failed; break 2; fi
          elif [[ -e "$_slp_px" || -L "$_slp_px" ]]; then
            _slp_glob=("$_slp_px")
          else
            _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_px" 2>&1)
            if (( $? == 0 )) || ! [[ $_slp_stat_out == *': No such file or directory' ]]; then _slp_parser_error=1; _slp_parser_reason=sshd-config:include-stat-failed; break 2; fi
          fi
          for _slp_item in "${_slp_glob[@]}"; do
            _slp_parse_sshd_file "$_slp_item" $((_slp_pd + 1)) 0 "$_slp_scope"
            (( _slp_parser_error == 0 )) || break 3
          done
        done
        continue
      fi
      if [[ "$_slp_pk" == permitrootlogin ]]; then
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; _slp_parser_reason=sshd-config:invalid-directive; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == no ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != no ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "$_slp_parser_reason" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:ambiguous-match" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-config:validation-failed" "ERROR"
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-effective:query-failed" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^permitrootlogin[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "ERROR" "sshd-effective:ambiguous-value" "ERROR"
    return 0
  fi
  _slp_effective=${_slp_effective_lines[0]}
  if (( _slp_main_no > 0 )) && [[ "$_slp_effective" == no ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "VALUE" "main_global_no=$_slp_main_no;effective=no" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN' "VALUE" "main_global_no=$_slp_main_no;effective=$_slp_effective" "FAIL"
  fi
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
{"adapter_contract_sha256":"b61bf8df26744aade1d1fc284c1e64e485ec1fca706312e237ad04cad257e0a0","adapter_id":"product-local-account-password-state-check-v2","adapter_implementation_sha256":"041ed9a038bc735d4d9f3e0f95c956ae197365aed7c334daf60ecbe2bef76666","control_id":"FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"82d8121586664ee803efec1f1b4bb93a248ce1f302bdf90a2561468ead86d802","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"all-nonempty","expected_type":"boolean","expected_value":true,"index_id":"SRC-0001","parameter_key":"password-field","parameter_kind":"local-account-password-state","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"8351b4431f8f6ddd403afb4315cf2f8b5ebcf3f8d9c38f91bb3778e5086593cc","source_locator":"2.1.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"e90cdf56b44dfc8fc57817ec5cd01f6acb399542d0d994656ff8dda0cfc03d7f","adapter_id":"product-sshd-root-login-check-v1","adapter_implementation_sha256":"dbb3c2793c0bcda5eacc963dc3c8e72c993b034720ac7206c8146e5dec2f2ccb","control_id":"FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"2f965f6e8901380f14088a167c77b07fc3b4c1872ac1f38865ba0a236a80b1de","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0002","parameter_key":"PermitRootLogin","parameter_kind":"sshd-root-login","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c671457700fd0fc656b34ccab9796a6b3b31a304492a26c3f317f0279e753785","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"5f22669198e49c77ca8062ff163e722924a199a4f6ece1e7fb7e4ce53966f400","source_locator":"2.1.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"0067b3c40bbb65a0fd07423689aa322834807e474f0a87d992e4e679da5cf6fe","adapter_id":"product-pam-wheel-access-check-v2","adapter_implementation_sha256":"54ed508c23f712069aebe797345cf5edf954be690ce99e562cdc5afb9fb3b7e8","apply":{"adapter_id":"product-pam-wheel-su-apply-v1","apply_kind":"pam-wheel-su-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"b88859644f1b90a5d33808f7fba51dd3281de76defc14b8b519e8d08193ef1ad","control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","implementation_sha256":"d06b490ca0fe4f93a99b8dae0ef6f6dae5f2d9f20c0870c5c06ff8a2fb0c8b9a","mechanism_id":"pam-wheel-su-v1","parameter_kind":"pam-wheel-access","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"19ba20db72ac9f80aad08aa197a6db925f059cfd6258992229d4d822fb1a2eac","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"pam-wheel-root-member","expected_type":"string","expected_value":"auth required pam_wheel.so use_uid;wheel:root","index_id":"SRC-0003","parameter_key":"policy","parameter_kind":"pam-wheel-access","parameter_locator":"/etc/pam.d/su|/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"25dd0790262b44e6c787ec36df8c1aabb8b2f8f3e50d6c9bed83285c50c64c62","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"6b419ad3093a3634becefddda3418a247c81ecec42f8074978c17eefd08c7a95","source_locator":"2.2.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"1be47bcba6dcca29c0b4e5dcf06611d7352141169bd7e2d0e78627f3e77a769e","adapter_id":"product-sudoers-reviewed-policy-check-v1","adapter_implementation_sha256":"0202d78c9d4c5ce7b62f8ea6844333fecbed9df5895ef7d1e9ed9f8fe33520bc","control_id":"FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"7509b7d80d34eb317bf960351cd2fcecd7ed964bde6c293c7ee577f45b2189b0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"standard-rules-only","expected_type":"string","expected_value":"root ALL=(ALL:ALL) ALL;%sudo ALL=(ALL:ALL) ALL;%admin ALL=(ALL) ALL","index_id":"SRC-0004","parameter_key":"user-specs","parameter_kind":"sudoers-reviewed-policy","parameter_locator":"/etc/sudoers","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"779597efe81ae7d291d2b7b0883cffb5af1a56f0234919b0243f360e688babea","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"c2ddb8b4643a5dac0996dc5bd6f250af8627d49a05e77ae1c5a7187d9ff85139","source_locator":"2.2.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","apply":{"adapter_id":"product-file-mode-owner-apply-v1","apply_kind":"file-mode-owner-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"c12e918000c09ec61aac18690fafb75e7b74d6702fa3f153187ebbba76ffd400","control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","implementation_sha256":"549c004ab8fc1fb131e95754ded533e01426a2cdde85fccb45ec36632c5e9ed3","mechanism_id":"file-mode-owner-v1","parameter_kind":"file-mode-owner","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"956008d60174d803f30d84131015702ef531ee9e0532b242f9a3a56d4bea0cb3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","apply":{"adapter_id":"product-file-mode-owner-apply-v1","apply_kind":"file-mode-owner-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"c12e918000c09ec61aac18690fafb75e7b74d6702fa3f153187ebbba76ffd400","control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","implementation_sha256":"549c004ab8fc1fb131e95754ded533e01426a2cdde85fccb45ec36632c5e9ed3","mechanism_id":"file-mode-owner-v1","parameter_kind":"file-mode-owner","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"e642ca111817660456d8c2a9f205719d4f3274d56d0a3baba18e41788b05aa30","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/passwd","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","apply":{"adapter_id":"product-file-mode-owner-apply-v1","apply_kind":"file-mode-owner-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"c12e918000c09ec61aac18690fafb75e7b74d6702fa3f153187ebbba76ffd400","control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","implementation_sha256":"549c004ab8fc1fb131e95754ded533e01426a2cdde85fccb45ec36632c5e9ed3","mechanism_id":"file-mode-owner-v1","parameter_kind":"file-mode-owner","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"26ac697290ebc2ad421907d5baac22c879a5ef5b70b29bb92bd758aa1e7c5ff6","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"ad6b570114d9c600113a6166bfa0c4ca901d90fababc4cd11b1c5486465f48b1","adapter_id":"product-home-sensitive-files-mode-check-v2","adapter_implementation_sha256":"03ab45b1a7dc4506340e9935212255d5c712ce72a6b998b84bc417cb8e58cf99","control_id":"FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"92315eed6b9dcd24ed50b5da9127df3f577b292d97d28cc04ce90081e38f4839","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0014","parameter_key":"mode","parameter_kind":"home-sensitive-files-mode","parameter_locator":"/home","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"4853f540825a2fc9b37f4728ddc19b01d4f7e83847635b3870f88d4827f8ffd6","source_locator":"2.3.10","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"34aa738612177cbfcab8847926d8bf6bf0e41d8fb8d1d024011b14eed0328026","adapter_id":"product-home-directories-mode-check-v2","adapter_implementation_sha256":"ae900179253bcd73050a9514f946eccfb3c7e70371e102b4dbb04e7d15cc8c9a","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"5a3e3bfbf5a9607b5c51b59a71c5b39a7c1249d7212500cfa41a8f9f6372874c","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","parameter_key":"mode","parameter_kind":"home-directories-mode","parameter_locator":"/home","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"163fe3d08be697984641cfc896487e630403c9481339a1b84457b97a7c76f9ca","source_locator":"2.3.11","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"fa2193b2f3653846d8bc21b1426e6c579815dcf48ebdbdfa008f07e3df410238","adapter_id":"product-running-process-paths-write-protection-check-v1","adapter_implementation_sha256":"e6c92da4ba25991d829441a7d023438e78413577db4e70f3ea902788b6114845","control_id":"FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"4c622265a9397061ef2edd2f99b6f90f78bf80aef8390f1cf129d8858daf76b3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"runtime-paths-safe","expected_type":"string","expected_value":"file-go-w;parent-unprivileged-write-denied","index_id":"SRC-0006","parameter_key":"write-protection","parameter_kind":"running-process-paths-write-protection","parameter_locator":"/proc/<pid>/exe|/proc/<pid>/maps","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f395bcd1e9dd9648161d6eac735f2b616c59c12e3d57a7cb1e9203cae2834aa5","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"05ee121a548ab26105af2efb26a3a8fa43647eabe022e069b64dc4a76c919274","source_locator":"2.3.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"603a53e31926cb2c997a7e0d2eb777563a33b0c33b55db2eec26d8dc911e6d6c","adapter_id":"product-cron-command-paths-write-protection-check-v1","adapter_implementation_sha256":"6732c11c8b87f6757ca0b2b1f0bf7930b8f56cdb94d273e0fd4dc9b6b512d084","control_id":"FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"aaab15a2454a7de6c5560aff10e367170706c6f47e6c5f879e46abe4fe9d6343","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"cron-command-paths-safe","expected_type":"string","expected_value":"file-go-w","index_id":"SRC-0007","parameter_key":"write-protection","parameter_kind":"cron-command-paths-write-protection","parameter_locator":"/etc/crontab|/etc/cron.d|/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"87a3b8a9ab953c58d4b04024444d5654019d1036eb0b424ddb3a87f621e68a7a","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"87e2d582651a44d085aa52d2cbd428054ab346eb86f2586341675a9662a6fe31","source_locator":"2.3.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"6e126f5079f9ab5c41a21c00f3807741a9d93bdec1454f08f132b212c7d6bae2","adapter_id":"product-sudo-root-command-files-protection-check-v2","adapter_implementation_sha256":"020db05b1b08a317cfcd740fbb584aff8774effc8be29cf5c1cb8f973bf126e8","control_id":"FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"ebaabd61921e597adc02cca4828cea4084363a2b40f93c571ff1502d72e01e21","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"root-owned-go-w-conditional","expected_type":"string","expected_value":"owner-if-regular-user;go-w-if-other-write","index_id":"SRC-0008","parameter_key":"root-command-files","parameter_kind":"sudo-root-command-files-protection","parameter_locator":"/etc/sudoers","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0be87131f3aea07d4da4134cd82c960c608b16feff43b6996ea4817d9bb38dfe","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"93d613b99ba5de1ff8026c3c68e938ce02e292824425852ab16619c53cde8582","source_locator":"2.3.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"86d848929c2ec2873faf65f34c6e980cf59d58b83f95020bf869f8b81521a297","adapter_id":"product-startup-files-write-protection-check-v1","adapter_implementation_sha256":"0a0845beb56938f92f3a7a0a4393c43c360b4c1f69e94b0d8b1fdc6192cdf442","apply":{"adapter_id":"product-startup-files-write-protection-apply-v1","apply_kind":"startup-files-write-protection-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"19f3b4f55a9a9a992f40afd63804ae9651f1a6326e5845156d14a9ef998cfd7b","control_id":"FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION","implementation_sha256":"a4c8a0d2c8c028dc31bdd4e9ea403462d321e9924cf8a3deadc687d630deae2a","mechanism_id":"startup-files-write-protection-v1","parameter_kind":"startup-files-write-protection","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"d92d47e065d5f64a34946143f7f8e57ff436d9439c1720e41d3c77b2e2185c57","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0002","index_id":"SRC-0009","parameter_key":"other-write","parameter_kind":"startup-files-write-protection","parameter_locator":"/etc/rc[0-6].d|systemd-unit-paths","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4a65bb314af3f2b4bb276e5b28cfd26b85b311d610553bd8e51bd26b1bfe8c6b","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"6098e676f64447097d2c3be5c44d30bb8f8bd2a379d3dba4fb9c38af88355737","source_locator":"2.3.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"42abb75c7ef704214114dee04997f64383de1049569d4b7049577265eed15371","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.d","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"94de7ae285f6ec4df63334a5f92f8bd16b91a0513e22d8a95cfe0e2d72068838","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.daily","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"40bcf7f54293f77ce0ac0f595d590ff351e40dd2f35bac9d8c2e2e1f794b28a8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.hourly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"e7fcd7d9de1f2021f17043f302dc7b1422b44c67dcac0c0c23a7465ab21208d3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.monthly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"4768263b4db31032e27abc3aef54d131beb5faa605b01acd20c8ad236e11d43e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.weekly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"d50e07de9a8e1d3feaf89464fe5807c60eb0ce864931c5de0fbeea57cd48a485","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/crontab","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"bc4bc9b9998249430bad6e9f1dad0be73450a6d2ab6f1ebbd9b928b93c21f6cc","adapter_id":"product-user-cron-files-mode-check-v2","adapter_implementation_sha256":"1efb24d36aec57592688472f8c2b0baadc23b32a5ca1f79fe018e3b5dcd4f0be","control_id":"FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"b5cb46dc92c854012b0a970a9d3c78febae83b29f28b3dfdc3bd80626ee5ac87","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0011","parameter_key":"mode","parameter_kind":"user-cron-files-mode","parameter_locator":"/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"af9430a9911e812b6f4b9735f35554d02e4203f7c39a3cae3d1c03004eb9adbe","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"e2099c6abb144a09eb4bf848bc47ebece27f053441d3bff7d1d58e23c2753c14","source_locator":"2.3.7","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"76b966250d242fd9dc266dbe726c17bbd3a2abd2283227c575de2b7cf8665334","adapter_id":"product-standard-system-paths-mode-check-v2","adapter_implementation_sha256":"7a823bb1721f774c7f26963c67dfc9a1ea2ca9cde33285141f77fcfcbb43cb56","apply":{"adapter_id":"product-standard-system-paths-mode-apply-v1","apply_kind":"standard-system-paths-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"1509afe0e0bb2d5f6ab92b81f18d81c46d84866c5ad022464d7eafb361c1dfe7","control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","implementation_sha256":"9d60edefaaadbdf4adddfd61c978110299c5a34e212eb7abbbe9134ee531baf2","mechanism_id":"standard-system-paths-mode-v1","parameter_kind":"standard-system-paths-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"fc60c18b38228707f5885c13f1f16a89b3c2dca42a38e9c69effb3ceb7048216","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0012","parameter_key":"mode","parameter_kind":"standard-system-paths-mode","parameter_locator":"/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c14203a718160e12100efac4e8e4f748cdf7517bba948d7ee66d8811f2e462e3","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"a71ce393cc1b83a087f30516ac5a8dc5379bbdd3ab32992dcb2b8edde4c41de4","source_locator":"2.3.8","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"18cd406165da1ea48d57cc948db4e86763f762b9f3665a34c67754c184050806","adapter_id":"product-suid-sgid-applications-check-v2","adapter_implementation_sha256":"0dfcb867919131a42ca7361d0ec63728f65ef2b933d528fcb7b7e0cf91be2052","apply":{"adapter_id":"product-suid-sgid-applications-mode-apply-v1","apply_kind":"suid-sgid-applications-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"36a2f89a51cf109044292cb27862f2f767111a0e06ae1428168d38285df4d3d4","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","implementation_sha256":"797e283275a37f9a1a6c07821c290e9ada4fae88498086242e92c63663b5c530","mechanism_id":"suid-sgid-applications-mode-v1","parameter_kind":"suid-sgid-applications","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"181c86580d9111600a2e2e8661db62f61c8e0f05e8c4b4c119f27bdd2818dfc8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0013","parameter_key":"mode","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"18ea993e68d5cf6e70968cc25d023a68f7b82e66a0fa93a251a55b971757e64e","source_locator":"2.3.9","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"53f03ee29dfa574d13b10683fcdfe738cbd04629ba81fb1ec092bb1fc91ef49a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0016","parameter_key":"kernel.dmesg_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c889161dc17ca0ec538a88477aeebfd920e8d10a53d34952e69b12b24338a5e6","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"0a257a5fadad7de419ef47749abb09eba1721028b122080b90256e7d47d156d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0017","parameter_key":"kernel.kptr_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"a4c2ba6bc1c18e8cc9a3b025cbf55b542e9cf327e3ce69fd2d8e4877bbc3ef60","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"1a20732ab081299b502577bff09076e0cac80d795e5e0f7dfa99d56b543eb6f0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0018","parameter_key":"init_on_alloc","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"42598531d328f70c985077c172050b942eb0383912f83f1fb3fcc3bceff866ae","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"present","expected_type":"boolean","expected_value":true,"index_id":"SRC-0019","parameter_key":"slab_nomerge","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"6a5c7fa4c5804ef3c2e152c338da6c73553bb8bce5dbde0331e4ba4db09d8b6f","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"de768afa461b5dac76760483f750d1c5d20a1e64cda8ce0a72f5fd1cf74f8935","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"force","index_id":"SRC-0020","parameter_key":"iommu","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"faea7e28cf9f4358b4c4e91c802a07e7316dd42b8443099a4741cdf1fbe01488","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0","index_id":"SRC-0020","parameter_key":"iommu.passthrough","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"7d0d5f2e3b289189e06f78b1c4a33e8c4570bcec467d34986b7b916c7a68d354","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0020","parameter_key":"iommu.strict","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"403e9c13d75c6c0cd6aede3d002e1e82227f180d71cfef65017ab81b1e2dbd44","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0021","parameter_key":"randomize_kstack_offset","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"69cbdb70f31aadd134129cae9eb95a96f836168646a821927cc3ea56ea58c980","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"e32cb42a14db86fc69a2c7960a07ef8398fb7079ae5ea839e377de7338ea55b5","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"auto,nosmt","index_id":"SRC-0022","parameter_key":"mitigations","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"593127f71a130fb574410cc9b249cf9ce42c1ec9698ebad648c79c4554d55ceb","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.7","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"47b6b8e37bf7cc6065455bc2fe3607841eaf5c16cf1e748ac58c6a838c7d0132","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0023","parameter_key":"net.core.bpf_jit_harden","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ffeec17a621afd4726e6c0fcf0aef4fb1e22c86f45ca20d1d568471675c3914f","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.8","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"74e099ee4df9dac18a3e2df48caa314926d3e72b7ea9e7783a4943f4b3d847c9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"none","index_id":"SRC-0024","parameter_key":"vsyscall","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"909ac7e3825f234cf325dac5b9615486ef4c856315aeb9c25d4b7a6af47fa421","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"a78e5d528693d8981244270851b0e562063b021045e56f9b58fd855c82760818","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"ge","expected_type":"integer","expected_value":4096,"index_id":"SRC-0033","parameter_key":"vm.mmap_min_addr","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.10","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"c5d4a6d65c18a1a12d68d14594f93bf6d33fc0c3e8f18b8a5333d3ad7ae9ea70","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0034","parameter_key":"kernel.randomize_va_space","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.11","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"e7bce3ca88fe891571b2a31bac7b7e78a35e736cf4dbdc0f0de0c3278342dc6a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0025","parameter_key":"kernel.perf_event_paranoid","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8e6f4b120bd3527b380251e92eca56e1b4c358d362f1246357579eb8af616382","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"84ae56f9c2362a51d053979a3f2eb982b4ca1ae43f2b227ef0477634d4beb292","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"one-of","expected_type":"string","expected_value":"off|no-mount","index_id":"SRC-0026","parameter_key":"debugfs","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"10391c151e6a53e91d637a11bc0f87a05a1ca7fdd408f9493dd27b366da46184","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"6e5edb1b1a4ae8d231abfb1aa6df0695b632d4ec4c36f9da1a98307b1526f6cf","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0027","parameter_key":"kernel.kexec_load_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0231e3c8de27fab8de667f632bf6d08609a7c62836be9c787fd4cb955974ff09","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"6eaa0334658fb48e9117a6dc17c96d66324ba94d9e7f6df4a08c6fe30ec14590","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0028","parameter_key":"user.max_user_namespaces","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"77edbfb78e01426b6c40ccedca310ff6091870e235d4225ac488f4cd5d8c090c","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"675490eca28c80f2bcaf85f3bfed38e0cd69f65a131133c5432deb9c3b34f73d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0029","parameter_key":"kernel.unprivileged_bpf_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"1c320abae9872972364ef95685204f4968a2c84bc27ee9c2707907eac8c5823e","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"655ca09fc55ba9c256a8c465c8e4e641880da38ae5ae1b54ca3c9131ddf1a097","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0030","parameter_key":"vm.unprivileged_userfaultfd","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"cba35949a04f5d3dab8bd9a0501d75e5c310773ac11c1ad2c4d80845cdd03080","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.7","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"ebee2def369534141260369cab0c06590a2794552840614ed1c07c82706eac30","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0031","parameter_key":"dev.tty.ldisc_autoload","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0860efcf66e2da819b06b5d6198e3b4c9b4ea96b66929752aceba65fae301783","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.8","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.5.9-TSX","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.9-TSX","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"494ea76e9e0e691222570f565c70b01f6a06e852ae4f851f3e8f65e95827fe19","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"off","index_id":"SRC-0032","parameter_key":"tsx","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"40b0ad985774f12adad55439e22a5ba29b3a2c50c9fedd16551fa261fd29464c","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.9","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"5c929cb7994116522a03e040af9e13dea447478d632cf58e45baac64d844cda7","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0035","parameter_key":"kernel.yama.ptrace_scope","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"7be4210587e64fe1864bfbf1b5e8f7cc3512434629eb17898ad487d50a9ae246","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"9109618bf48e0d314306aa7165c39dc78e16de398f77ce534fffa464c2b850f1","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0036","parameter_key":"fs.protected_symlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ce09b5104160f3fe27f17f1d5e57a5fe81001adac3c362ed652552ccbc59571f","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.2","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"0e8844a89ff5c2678009b8c27d3f031a778e2a8b9753f93a8901f450e07fa80f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0037","parameter_key":"fs.protected_hardlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"315736677a4e3192cde79d4badbf20809da81c8605785c8720fcd0fc3260fe97","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.3","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"5510b1f68c078e769ab1b29775eef8500f102d68982db8c13a5f444e6a7a7f03","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0038","parameter_key":"fs.protected_fifos","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016aaaf884c10febb3e99a86acfcbe63eae04f05f5fcf35a00c59f03fb30a31b","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.4","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"9bfd2d1c3ae0ee3c48f6405a07e21e85da430418929147834bfbf83f82fc1791","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0039","parameter_key":"fs.protected_regular","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0f1eea51ec98d254f230a48dfc4950cb060e11460e1f30be68fde3fb9439cb14","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.5","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"cee0ebd9587fda4e329e2759b697db93a8eff99cfe287207831670b86ed63350","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0040","parameter_key":"fs.suid_dumpable","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.6","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"e9e5d24dc0b3dfe3596f71eba87a38d4e4ad833f0667fa8370b497388833d8f8","adapter_id":"product-sshd-config-option-check-v1","adapter_implementation_sha256":"c675395822e78a5a698c4209970b3f716223a0efef6e5b132b96392f8102ac31","apply":{"adapter_id":"product-sshd-config-option-apply-v1","apply_kind":"sshd-config-option-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"209bb6f0a959bbb7dd2c85a3afc66e63ccfc61d3180a27d68c6164ac42b66045","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION","implementation_sha256":"8a820935da88cfbb2b5c931100366cfbf6ba7838136298054756d9577cb59c36","mechanism_id":"sshd-config-option-v1","parameter_kind":"sshd-config-option","route_status":"BOUND"},"control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"76f8526661cb3c9854c2e8436d98649482a2be5a6bc4e7b953ac97db71a5a5aa","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","parameter_key":"PasswordAuthentication","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"7d3de4611b0d53f06452ba26f73457278a54c1d17382d11fb625ca695a921293","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"e9e5d24dc0b3dfe3596f71eba87a38d4e4ad833f0667fa8370b497388833d8f8","adapter_id":"product-sshd-config-option-check-v1","adapter_implementation_sha256":"c675395822e78a5a698c4209970b3f716223a0efef6e5b132b96392f8102ac31","apply":{"adapter_id":"product-sshd-config-option-apply-v1","apply_kind":"sshd-config-option-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"209bb6f0a959bbb7dd2c85a3afc66e63ccfc61d3180a27d68c6164ac42b66045","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS","implementation_sha256":"8a820935da88cfbb2b5c931100366cfbf6ba7838136298054756d9577cb59c36","mechanism_id":"sshd-config-option-v1","parameter_kind":"sshd-config-option","route_status":"BOUND"},"control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"eb6ea9f476a6b65ef758631f9a920e5c9af3d1f7b136145f2727991641c88055","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","parameter_key":"PermitEmptyPasswords","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"7d3de4611b0d53f06452ba26f73457278a54c1d17382d11fb625ca695a921293","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}
{"adapter_contract_sha256":"e9e5d24dc0b3dfe3596f71eba87a38d4e4ad833f0667fa8370b497388833d8f8","adapter_id":"product-sshd-config-option-check-v1","adapter_implementation_sha256":"c675395822e78a5a698c4209970b3f716223a0efef6e5b132b96392f8102ac31","apply":{"adapter_id":"product-sshd-config-option-apply-v1","apply_kind":"sshd-config-option-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"209bb6f0a959bbb7dd2c85a3afc66e63ccfc61d3180a27d68c6164ac42b66045","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN","implementation_sha256":"8a820935da88cfbb2b5c931100366cfbf6ba7838136298054756d9577cb59c36","mechanism_id":"sshd-config-option-v1","parameter_kind":"sshd-config-option","route_status":"BOUND"},"control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"ff7f9436907ec698f6298a7d3a5a785da36399228a0f213295ec0626303c8cd2","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","parameter_key":"PermitRootLogin","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"7d3de4611b0d53f06452ba26f73457278a54c1d17382d11fb625ca695a921293","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}
SLP_PROVENANCE_EOF
}

slp_provenance_one() {
  case "$1" in
    'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE') printf '%s\n' '{"adapter_contract_sha256":"b61bf8df26744aade1d1fc284c1e64e485ec1fca706312e237ad04cad257e0a0","adapter_id":"product-local-account-password-state-check-v2","adapter_implementation_sha256":"041ed9a038bc735d4d9f3e0f95c956ae197365aed7c334daf60ecbe2bef76666","control_id":"FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"82d8121586664ee803efec1f1b4bb93a248ce1f302bdf90a2561468ead86d802","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"all-nonempty","expected_type":"boolean","expected_value":true,"index_id":"SRC-0001","parameter_key":"password-field","parameter_kind":"local-account-password-state","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"8351b4431f8f6ddd403afb4315cf2f8b5ebcf3f8d9c38f91bb3778e5086593cc","source_locator":"2.1.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN') printf '%s\n' '{"adapter_contract_sha256":"e90cdf56b44dfc8fc57817ec5cd01f6acb399542d0d994656ff8dda0cfc03d7f","adapter_id":"product-sshd-root-login-check-v1","adapter_implementation_sha256":"dbb3c2793c0bcda5eacc963dc3c8e72c993b034720ac7206c8146e5dec2f2ccb","control_id":"FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"2f965f6e8901380f14088a167c77b07fc3b4c1872ac1f38865ba0a236a80b1de","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0002","parameter_key":"PermitRootLogin","parameter_kind":"sshd-root-login","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c671457700fd0fc656b34ccab9796a6b3b31a304492a26c3f317f0279e753785","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"5f22669198e49c77ca8062ff163e722924a199a4f6ece1e7fb7e4ce53966f400","source_locator":"2.1.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS') printf '%s\n' '{"adapter_contract_sha256":"0067b3c40bbb65a0fd07423689aa322834807e474f0a87d992e4e679da5cf6fe","adapter_id":"product-pam-wheel-access-check-v2","adapter_implementation_sha256":"54ed508c23f712069aebe797345cf5edf954be690ce99e562cdc5afb9fb3b7e8","apply":{"adapter_id":"product-pam-wheel-su-apply-v1","apply_kind":"pam-wheel-su-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"b88859644f1b90a5d33808f7fba51dd3281de76defc14b8b519e8d08193ef1ad","control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","implementation_sha256":"d06b490ca0fe4f93a99b8dae0ef6f6dae5f2d9f20c0870c5c06ff8a2fb0c8b9a","mechanism_id":"pam-wheel-su-v1","parameter_kind":"pam-wheel-access","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"19ba20db72ac9f80aad08aa197a6db925f059cfd6258992229d4d822fb1a2eac","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"pam-wheel-root-member","expected_type":"string","expected_value":"auth required pam_wheel.so use_uid;wheel:root","index_id":"SRC-0003","parameter_key":"policy","parameter_kind":"pam-wheel-access","parameter_locator":"/etc/pam.d/su|/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"25dd0790262b44e6c787ec36df8c1aabb8b2f8f3e50d6c9bed83285c50c64c62","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"6b419ad3093a3634becefddda3418a247c81ecec42f8074978c17eefd08c7a95","source_locator":"2.2.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY') printf '%s\n' '{"adapter_contract_sha256":"1be47bcba6dcca29c0b4e5dcf06611d7352141169bd7e2d0e78627f3e77a769e","adapter_id":"product-sudoers-reviewed-policy-check-v1","adapter_implementation_sha256":"0202d78c9d4c5ce7b62f8ea6844333fecbed9df5895ef7d1e9ed9f8fe33520bc","control_id":"FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"7509b7d80d34eb317bf960351cd2fcecd7ed964bde6c293c7ee577f45b2189b0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"standard-rules-only","expected_type":"string","expected_value":"root ALL=(ALL:ALL) ALL;%sudo ALL=(ALL:ALL) ALL;%admin ALL=(ALL) ALL","index_id":"SRC-0004","parameter_key":"user-specs","parameter_kind":"sudoers-reviewed-policy","parameter_locator":"/etc/sudoers","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"779597efe81ae7d291d2b7b0883cffb5af1a56f0234919b0243f360e688babea","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"c2ddb8b4643a5dac0996dc5bd6f250af8627d49a05e77ae1c5a7187d9ff85139","source_locator":"2.2.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.1-GROUP-MODE') printf '%s\n' '{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","apply":{"adapter_id":"product-file-mode-owner-apply-v1","apply_kind":"file-mode-owner-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"c12e918000c09ec61aac18690fafb75e7b74d6702fa3f153187ebbba76ffd400","control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","implementation_sha256":"549c004ab8fc1fb131e95754ded533e01426a2cdde85fccb45ec36632c5e9ed3","mechanism_id":"file-mode-owner-v1","parameter_kind":"file-mode-owner","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"956008d60174d803f30d84131015702ef531ee9e0532b242f9a3a56d4bea0cb3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE') printf '%s\n' '{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","apply":{"adapter_id":"product-file-mode-owner-apply-v1","apply_kind":"file-mode-owner-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"c12e918000c09ec61aac18690fafb75e7b74d6702fa3f153187ebbba76ffd400","control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","implementation_sha256":"549c004ab8fc1fb131e95754ded533e01426a2cdde85fccb45ec36632c5e9ed3","mechanism_id":"file-mode-owner-v1","parameter_kind":"file-mode-owner","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"e642ca111817660456d8c2a9f205719d4f3274d56d0a3baba18e41788b05aa30","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/passwd","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX') printf '%s\n' '{"adapter_contract_sha256":"4705b37de4b99ef2fcb5b958d0a0359d143c5545974bc8dab7ccd4faed5ceb2a","adapter_id":"product-file-mode-owner-check-v2","adapter_implementation_sha256":"d1ffd5187d946c27c59805a24660d2400b66eada54feda0774d2cf82ba09863e","apply":{"adapter_id":"product-file-mode-owner-apply-v1","apply_kind":"file-mode-owner-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"c12e918000c09ec61aac18690fafb75e7b74d6702fa3f153187ebbba76ffd400","control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","implementation_sha256":"549c004ab8fc1fb131e95754ded533e01426a2cdde85fccb45ec36632c5e9ed3","mechanism_id":"file-mode-owner-v1","parameter_kind":"file-mode-owner","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"26ac697290ebc2ad421907d5baac22c879a5ef5b70b29bb92bd758aa1e7c5ff6","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"ead8459d087217bdbb2512d5d8760e7d8635290303a08680070eff067fd9e656","source_locator":"2.3.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE') printf '%s\n' '{"adapter_contract_sha256":"ad6b570114d9c600113a6166bfa0c4ca901d90fababc4cd11b1c5486465f48b1","adapter_id":"product-home-sensitive-files-mode-check-v2","adapter_implementation_sha256":"03ab45b1a7dc4506340e9935212255d5c712ce72a6b998b84bc417cb8e58cf99","control_id":"FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"92315eed6b9dcd24ed50b5da9127df3f577b292d97d28cc04ce90081e38f4839","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0014","parameter_key":"mode","parameter_kind":"home-sensitive-files-mode","parameter_locator":"/home","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"4853f540825a2fc9b37f4728ddc19b01d4f7e83847635b3870f88d4827f8ffd6","source_locator":"2.3.10","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE') printf '%s\n' '{"adapter_contract_sha256":"34aa738612177cbfcab8847926d8bf6bf0e41d8fb8d1d024011b14eed0328026","adapter_id":"product-home-directories-mode-check-v2","adapter_implementation_sha256":"ae900179253bcd73050a9514f946eccfb3c7e70371e102b4dbb04e7d15cc8c9a","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"5a3e3bfbf5a9607b5c51b59a71c5b39a7c1249d7212500cfa41a8f9f6372874c","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","parameter_key":"mode","parameter_kind":"home-directories-mode","parameter_locator":"/home","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"163fe3d08be697984641cfc896487e630403c9481339a1b84457b97a7c76f9ca","source_locator":"2.3.11","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"fa2193b2f3653846d8bc21b1426e6c579815dcf48ebdbdfa008f07e3df410238","adapter_id":"product-running-process-paths-write-protection-check-v1","adapter_implementation_sha256":"e6c92da4ba25991d829441a7d023438e78413577db4e70f3ea902788b6114845","control_id":"FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"4c622265a9397061ef2edd2f99b6f90f78bf80aef8390f1cf129d8858daf76b3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"runtime-paths-safe","expected_type":"string","expected_value":"file-go-w;parent-unprivileged-write-denied","index_id":"SRC-0006","parameter_key":"write-protection","parameter_kind":"running-process-paths-write-protection","parameter_locator":"/proc/<pid>/exe|/proc/<pid>/maps","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f395bcd1e9dd9648161d6eac735f2b616c59c12e3d57a7cb1e9203cae2834aa5","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"05ee121a548ab26105af2efb26a3a8fa43647eabe022e069b64dc4a76c919274","source_locator":"2.3.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"603a53e31926cb2c997a7e0d2eb777563a33b0c33b55db2eec26d8dc911e6d6c","adapter_id":"product-cron-command-paths-write-protection-check-v1","adapter_implementation_sha256":"6732c11c8b87f6757ca0b2b1f0bf7930b8f56cdb94d273e0fd4dc9b6b512d084","control_id":"FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"aaab15a2454a7de6c5560aff10e367170706c6f47e6c5f879e46abe4fe9d6343","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"cron-command-paths-safe","expected_type":"string","expected_value":"file-go-w","index_id":"SRC-0007","parameter_key":"write-protection","parameter_kind":"cron-command-paths-write-protection","parameter_locator":"/etc/crontab|/etc/cron.d|/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"87a3b8a9ab953c58d4b04024444d5654019d1036eb0b424ddb3a87f621e68a7a","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"87e2d582651a44d085aa52d2cbd428054ab346eb86f2586341675a9662a6fe31","source_locator":"2.3.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"6e126f5079f9ab5c41a21c00f3807741a9d93bdec1454f08f132b212c7d6bae2","adapter_id":"product-sudo-root-command-files-protection-check-v2","adapter_implementation_sha256":"020db05b1b08a317cfcd740fbb584aff8774effc8be29cf5c1cb8f973bf126e8","control_id":"FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"ebaabd61921e597adc02cca4828cea4084363a2b40f93c571ff1502d72e01e21","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"root-owned-go-w-conditional","expected_type":"string","expected_value":"owner-if-regular-user;go-w-if-other-write","index_id":"SRC-0008","parameter_key":"root-command-files","parameter_kind":"sudo-root-command-files-protection","parameter_locator":"/etc/sudoers","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0be87131f3aea07d4da4134cd82c960c608b16feff43b6996ea4817d9bb38dfe","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"93d613b99ba5de1ff8026c3c68e938ce02e292824425852ab16619c53cde8582","source_locator":"2.3.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"86d848929c2ec2873faf65f34c6e980cf59d58b83f95020bf869f8b81521a297","adapter_id":"product-startup-files-write-protection-check-v1","adapter_implementation_sha256":"0a0845beb56938f92f3a7a0a4393c43c360b4c1f69e94b0d8b1fdc6192cdf442","apply":{"adapter_id":"product-startup-files-write-protection-apply-v1","apply_kind":"startup-files-write-protection-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"19f3b4f55a9a9a992f40afd63804ae9651f1a6326e5845156d14a9ef998cfd7b","control_id":"FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION","implementation_sha256":"a4c8a0d2c8c028dc31bdd4e9ea403462d321e9924cf8a3deadc687d630deae2a","mechanism_id":"startup-files-write-protection-v1","parameter_kind":"startup-files-write-protection","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"d92d47e065d5f64a34946143f7f8e57ff436d9439c1720e41d3c77b2e2185c57","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0002","index_id":"SRC-0009","parameter_key":"other-write","parameter_kind":"startup-files-write-protection","parameter_locator":"/etc/rc[0-6].d|systemd-unit-paths","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4a65bb314af3f2b4bb276e5b28cfd26b85b311d610553bd8e51bd26b1bfe8c6b","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"6098e676f64447097d2c3be5c44d30bb8f8bd2a379d3dba4fb9c38af88355737","source_locator":"2.3.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-D') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"42abb75c7ef704214114dee04997f64383de1049569d4b7049577265eed15371","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.d","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-DAILY') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"94de7ae285f6ec4df63334a5f92f8bd16b91a0513e22d8a95cfe0e2d72068838","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.daily","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"40bcf7f54293f77ce0ac0f595d590ff351e40dd2f35bac9d8c2e2e1f794b28a8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.hourly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"e7fcd7d9de1f2021f17043f302dc7b1422b44c67dcac0c0c23a7465ab21208d3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.monthly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"4768263b4db31032e27abc3aef54d131beb5faa605b01acd20c8ad236e11d43e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.weekly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRONTAB') printf '%s\n' '{"adapter_contract_sha256":"4b0284ee1cd14be7e399c4fd132aa6058a5e1c0bc7d5a67c1015f99e8b136ebd","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"93bbc702e1a516b76a15d30077ce66c44c857859aeed5b9d86a584746fd35220","apply":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"8c3f31abbd2f8f7d747812b855e1ce9645ccb36b4f7e316495aa6ec2dcd744b1","control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","parameter_kind":"optional-file-root-files-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"d50e07de9a8e1d3feaf89464fe5807c60eb0ce864931c5de0fbeea57cd48a485","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/crontab","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"35f57d7fe38bb1e7714e97fe82c74f03aac33d9ec1a0d745e2d6c271f36d86e2","source_locator":"2.3.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE') printf '%s\n' '{"adapter_contract_sha256":"bc4bc9b9998249430bad6e9f1dad0be73450a6d2ab6f1ebbd9b928b93c21f6cc","adapter_id":"product-user-cron-files-mode-check-v2","adapter_implementation_sha256":"1efb24d36aec57592688472f8c2b0baadc23b32a5ca1f79fe018e3b5dcd4f0be","control_id":"FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"b5cb46dc92c854012b0a970a9d3c78febae83b29f28b3dfdc3bd80626ee5ac87","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0011","parameter_key":"mode","parameter_kind":"user-cron-files-mode","parameter_locator":"/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"af9430a9911e812b6f4b9735f35554d02e4203f7c39a3cae3d1c03004eb9adbe","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"e2099c6abb144a09eb4bf848bc47ebece27f053441d3bff7d1d58e23c2753c14","source_locator":"2.3.7","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE') printf '%s\n' '{"adapter_contract_sha256":"76b966250d242fd9dc266dbe726c17bbd3a2abd2283227c575de2b7cf8665334","adapter_id":"product-standard-system-paths-mode-check-v2","adapter_implementation_sha256":"7a823bb1721f774c7f26963c67dfc9a1ea2ca9cde33285141f77fcfcbb43cb56","apply":{"adapter_id":"product-standard-system-paths-mode-apply-v1","apply_kind":"standard-system-paths-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"1509afe0e0bb2d5f6ab92b81f18d81c46d84866c5ad022464d7eafb361c1dfe7","control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","implementation_sha256":"9d60edefaaadbdf4adddfd61c978110299c5a34e212eb7abbbe9134ee531baf2","mechanism_id":"standard-system-paths-mode-v1","parameter_kind":"standard-system-paths-mode","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"fc60c18b38228707f5885c13f1f16a89b3c2dca42a38e9c69effb3ceb7048216","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0012","parameter_key":"mode","parameter_kind":"standard-system-paths-mode","parameter_locator":"/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c14203a718160e12100efac4e8e4f748cdf7517bba948d7ee66d8811f2e462e3","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"a71ce393cc1b83a087f30516ac5a8dc5379bbdd3ab32992dcb2b8edde4c41de4","source_locator":"2.3.8","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE') printf '%s\n' '{"adapter_contract_sha256":"18cd406165da1ea48d57cc948db4e86763f762b9f3665a34c67754c184050806","adapter_id":"product-suid-sgid-applications-check-v2","adapter_implementation_sha256":"0dfcb867919131a42ca7361d0ec63728f65ef2b933d528fcb7b7e0cf91be2052","apply":{"adapter_id":"product-suid-sgid-applications-mode-apply-v1","apply_kind":"suid-sgid-applications-mode-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"36a2f89a51cf109044292cb27862f2f767111a0e06ae1428168d38285df4d3d4","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","implementation_sha256":"797e283275a37f9a1a6c07821c290e9ada4fae88498086242e92c63663b5c530","mechanism_id":"suid-sgid-applications-mode-v1","parameter_kind":"suid-sgid-applications","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"181c86580d9111600a2e2e8661db62f61c8e0f05e8c4b4c119f27bdd2818dfc8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0013","parameter_key":"mode","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"18ea993e68d5cf6e70968cc25d023a68f7b82e66a0fa93a251a55b971757e64e","source_locator":"2.3.9","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"53f03ee29dfa574d13b10683fcdfe738cbd04629ba81fb1ec092bb1fc91ef49a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0016","parameter_key":"kernel.dmesg_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c889161dc17ca0ec538a88477aeebfd920e8d10a53d34952e69b12b24338a5e6","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"0a257a5fadad7de419ef47749abb09eba1721028b122080b90256e7d47d156d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0017","parameter_key":"kernel.kptr_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"a4c2ba6bc1c18e8cc9a3b025cbf55b542e9cf327e3ce69fd2d8e4877bbc3ef60","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC') printf '%s\n' '{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"1a20732ab081299b502577bff09076e0cac80d795e5e0f7dfa99d56b543eb6f0","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0018","parameter_key":"init_on_alloc","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE') printf '%s\n' '{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"42598531d328f70c985077c172050b942eb0383912f83f1fb3fcc3bceff866ae","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"present","expected_type":"boolean","expected_value":true,"index_id":"SRC-0019","parameter_key":"slab_nomerge","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"6a5c7fa4c5804ef3c2e152c338da6c73553bb8bce5dbde0331e4ba4db09d8b6f","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE') printf '%s\n' '{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"de768afa461b5dac76760483f750d1c5d20a1e64cda8ce0a72f5fd1cf74f8935","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"force","index_id":"SRC-0020","parameter_key":"iommu","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH') printf '%s\n' '{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"faea7e28cf9f4358b4c4e91c802a07e7316dd42b8443099a4741cdf1fbe01488","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0","index_id":"SRC-0020","parameter_key":"iommu.passthrough","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT') printf '%s\n' '{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"7d0d5f2e3b289189e06f78b1c4a33e8c4570bcec467d34986b7b916c7a68d354","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0020","parameter_key":"iommu.strict","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET') printf '%s\n' '{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"403e9c13d75c6c0cd6aede3d002e1e82227f180d71cfef65017ab81b1e2dbd44","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0021","parameter_key":"randomize_kstack_offset","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"69cbdb70f31aadd134129cae9eb95a96f836168646a821927cc3ea56ea58c980","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.7-MITIGATIONS') printf '%s\n' '{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"e32cb42a14db86fc69a2c7960a07ef8398fb7079ae5ea839e377de7338ea55b5","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"auto,nosmt","index_id":"SRC-0022","parameter_key":"mitigations","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"593127f71a130fb574410cc9b249cf9ce42c1ec9698ebad648c79c4554d55ceb","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.4.7","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"47b6b8e37bf7cc6065455bc2fe3607841eaf5c16cf1e748ac58c6a838c7d0132","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0023","parameter_key":"net.core.bpf_jit_harden","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ffeec17a621afd4726e6c0fcf0aef4fb1e22c86f45ca20d1d568471675c3914f","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.4.8","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.1-VSYSCALL') printf '%s\n' '{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"74e099ee4df9dac18a3e2df48caa314926d3e72b7ea9e7783a4943f4b3d847c9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"none","index_id":"SRC-0024","parameter_key":"vsyscall","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"909ac7e3825f234cf325dac5b9615486ef4c856315aeb9c25d4b7a6af47fa421","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"a78e5d528693d8981244270851b0e562063b021045e56f9b58fd855c82760818","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"ge","expected_type":"integer","expected_value":4096,"index_id":"SRC-0033","parameter_key":"vm.mmap_min_addr","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.10","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"c5d4a6d65c18a1a12d68d14594f93bf6d33fc0c3e8f18b8a5333d3ad7ae9ea70","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0034","parameter_key":"kernel.randomize_va_space","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.11","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"e7bce3ca88fe891571b2a31bac7b7e78a35e736cf4dbdc0f0de0c3278342dc6a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0025","parameter_key":"kernel.perf_event_paranoid","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8e6f4b120bd3527b380251e92eca56e1b4c358d362f1246357579eb8af616382","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.3-DEBUGFS') printf '%s\n' '{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"84ae56f9c2362a51d053979a3f2eb982b4ca1ae43f2b227ef0477634d4beb292","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"one-of","expected_type":"string","expected_value":"off|no-mount","index_id":"SRC-0026","parameter_key":"debugfs","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"10391c151e6a53e91d637a11bc0f87a05a1ca7fdd408f9493dd27b366da46184","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"6e5edb1b1a4ae8d231abfb1aa6df0695b632d4ec4c36f9da1a98307b1526f6cf","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0027","parameter_key":"kernel.kexec_load_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0231e3c8de27fab8de667f632bf6d08609a7c62836be9c787fd4cb955974ff09","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"6eaa0334658fb48e9117a6dc17c96d66324ba94d9e7f6df4a08c6fe30ec14590","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0028","parameter_key":"user.max_user_namespaces","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"77edbfb78e01426b6c40ccedca310ff6091870e235d4225ac488f4cd5d8c090c","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"675490eca28c80f2bcaf85f3bfed38e0cd69f65a131133c5432deb9c3b34f73d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0029","parameter_key":"kernel.unprivileged_bpf_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"1c320abae9872972364ef95685204f4968a2c84bc27ee9c2707907eac8c5823e","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"655ca09fc55ba9c256a8c465c8e4e641880da38ae5ae1b54ca3c9131ddf1a097","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0030","parameter_key":"vm.unprivileged_userfaultfd","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"cba35949a04f5d3dab8bd9a0501d75e5c310773ac11c1ad2c4d80845cdd03080","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.7","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"ebee2def369534141260369cab0c06590a2794552840614ed1c07c82706eac30","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0031","parameter_key":"dev.tty.ldisc_autoload","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0860efcf66e2da819b06b5d6198e3b4c9b4ea96b66929752aceba65fae301783","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.5.8","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.5.9-TSX') printf '%s\n' '{"adapter_contract_sha256":"f0fbde8d1f438f345eb276418a43fd8fc865dbe647363b55ba5c06ede92a59b8","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"534ab2ed18523b1b36b2382ddda881831cbd0ffb61edfe1fae3864fe6ed81b36","apply":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"eaec868080fdb4b98b2d047300dcf46cf3a1997a9f42d423a33a7ba2201cb459","control_id":"FSTEC-LINUX-2022-2.5.9-TSX","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","parameter_kind":"kernel-cmdline","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.5.9-TSX","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"494ea76e9e0e691222570f565c70b01f6a06e852ae4f851f3e8f65e95827fe19","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"off","index_id":"SRC-0032","parameter_key":"tsx","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"40b0ad985774f12adad55439e22a5ba29b3a2c50c9fedd16551fa261fd29464c","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"10de2ce43d3fc5e19f6f7d9e486c9463e7a5cf4867d72c6fa6a01ecd08269e50","source_locator":"2.5.9","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"5c929cb7994116522a03e040af9e13dea447478d632cf58e45baac64d844cda7","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0035","parameter_key":"kernel.yama.ptrace_scope","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"7be4210587e64fe1864bfbf1b5e8f7cc3512434629eb17898ad487d50a9ae246","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"9109618bf48e0d314306aa7165c39dc78e16de398f77ce534fffa464c2b850f1","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0036","parameter_key":"fs.protected_symlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ce09b5104160f3fe27f17f1d5e57a5fe81001adac3c362ed652552ccbc59571f","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.2","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"0e8844a89ff5c2678009b8c27d3f031a778e2a8b9753f93a8901f450e07fa80f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0037","parameter_key":"fs.protected_hardlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"315736677a4e3192cde79d4badbf20809da81c8605785c8720fcd0fc3260fe97","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.3","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"5510b1f68c078e769ab1b29775eef8500f102d68982db8c13a5f444e6a7a7f03","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0038","parameter_key":"fs.protected_fifos","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016aaaf884c10febb3e99a86acfcbe63eae04f05f5fcf35a00c59f03fb30a31b","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.4","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"9bfd2d1c3ae0ee3c48f6405a07e21e85da430418929147834bfbf83f82fc1791","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0039","parameter_key":"fs.protected_regular","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0f1eea51ec98d254f230a48dfc4950cb060e11460e1f30be68fde3fb9439cb14","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.5","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE') printf '%s\n' '{"adapter_contract_sha256":"4bb445ff312b97368150514f825687467c12aae984833412be6830877d6ff6ee","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"ac348026b5e2e11d27bcfe3c1b5978a2bc6464ff98ee0ae911244a6f0c93327f","apply":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"dcb6163ec0de1317e7c723fd96df2525aa8452b23f85e10784e4235272e212d3","control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","parameter_kind":"sysctl","route_status":"BOUND"},"control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"cee0ebd9587fda4e329e2759b697db93a8eff99cfe287207831670b86ed63350","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0040","parameter_key":"fs.suid_dumpable","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"f912d89b80d2a17819a691190cf8c4bdb1c5340545a5a6b0b1e5b107757a3695","source_locator":"2.6.6","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION') printf '%s\n' '{"adapter_contract_sha256":"e9e5d24dc0b3dfe3596f71eba87a38d4e4ad833f0667fa8370b497388833d8f8","adapter_id":"product-sshd-config-option-check-v1","adapter_implementation_sha256":"c675395822e78a5a698c4209970b3f716223a0efef6e5b132b96392f8102ac31","apply":{"adapter_id":"product-sshd-config-option-apply-v1","apply_kind":"sshd-config-option-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"209bb6f0a959bbb7dd2c85a3afc66e63ccfc61d3180a27d68c6164ac42b66045","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION","implementation_sha256":"8a820935da88cfbb2b5c931100366cfbf6ba7838136298054756d9577cb59c36","mechanism_id":"sshd-config-option-v1","parameter_kind":"sshd-config-option","route_status":"BOUND"},"control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"76f8526661cb3c9854c2e8436d98649482a2be5a6bc4e7b953ac97db71a5a5aa","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","parameter_key":"PasswordAuthentication","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"7d3de4611b0d53f06452ba26f73457278a54c1d17382d11fb625ca695a921293","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS') printf '%s\n' '{"adapter_contract_sha256":"e9e5d24dc0b3dfe3596f71eba87a38d4e4ad833f0667fa8370b497388833d8f8","adapter_id":"product-sshd-config-option-check-v1","adapter_implementation_sha256":"c675395822e78a5a698c4209970b3f716223a0efef6e5b132b96392f8102ac31","apply":{"adapter_id":"product-sshd-config-option-apply-v1","apply_kind":"sshd-config-option-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"209bb6f0a959bbb7dd2c85a3afc66e63ccfc61d3180a27d68c6164ac42b66045","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS","implementation_sha256":"8a820935da88cfbb2b5c931100366cfbf6ba7838136298054756d9577cb59c36","mechanism_id":"sshd-config-option-v1","parameter_kind":"sshd-config-option","route_status":"BOUND"},"control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"eb6ea9f476a6b65ef758631f9a920e5c9af3d1f7b136145f2727991641c88055","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","parameter_key":"PermitEmptyPasswords","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"7d3de4611b0d53f06452ba26f73457278a54c1d17382d11fb625ca695a921293","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN') printf '%s\n' '{"adapter_contract_sha256":"e9e5d24dc0b3dfe3596f71eba87a38d4e4ad833f0667fa8370b497388833d8f8","adapter_id":"product-sshd-config-option-check-v1","adapter_implementation_sha256":"c675395822e78a5a698c4209970b3f716223a0efef6e5b132b96392f8102ac31","apply":{"adapter_id":"product-sshd-config-option-apply-v1","apply_kind":"sshd-config-option-v1","authority_form":"MECHANISM_AUTHORITY_V1","authority_sha256":"209bb6f0a959bbb7dd2c85a3afc66e63ccfc61d3180a27d68c6164ac42b66045","control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN","implementation_sha256":"8a820935da88cfbb2b5c931100366cfbf6ba7838136298054756d9577cb59c36","mechanism_id":"sshd-config-option-v1","parameter_kind":"sshd-config-option","route_status":"BOUND"},"control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN","control_manifest_sha256":"b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4","control_sha256":"ff7f9436907ec698f6298a7d3a5a785da36399228a0f213295ec0626303c8cd2","doc_id":"fstec-configuration-2026","doc_sha256":"1f2e53a3c047cd1a21f2f99e8605f7ba7a7680a45fc332b8236199b049c3dad6","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0088","parameter_key":"PermitRootLogin","parameter_kind":"sshd-config-option","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06","registry_sha256":"8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc","semantic_contract_sha256":"7d3de4611b0d53f06452ba26f73457278a54c1d17382d11fb625ca695a921293","source_locator":"9.1","target_id":"linux-x86_64-supported-v1"}' ;;
    *) return 2 ;;
  esac
}

slp_build_info() {
  printf '%s\n' \
    'STATUS=NON_RELEASE_PRODUCT_CANDIDATE' \
    'PRODUCT_CLI=product-cli-v1' \
    'GENERATOR_ID=product-check-generator-v2' \
    'GENERATOR_SHA256=d8564f86461304bf9d8c4a08d752201a840aa6a916e401f06f320fb5857d2f0a' \
    'CONTROL_COUNT=52' \
    'CONTROL_MANIFEST_SHA256=b64e4cd610181bce848eb68d52e7ee755df9d2de815095396aec492165408ba4' \
    'ADAPTER_COUNT=18' \
    'ADAPTER_REGISTRY_SHA256=8b6cec55189430e4e995d81cfea5af6d90ecfa1150ad2ddd7e9ed6eb59efcccc' \
    'APPLY_KINDS=config-line-with-runtime-v1,file-mode-owner-v1,kernel-cmdline-grub-v1,optional-file-root-files-mode-v1,pam-wheel-su-v1,sshd-config-option-v1,standard-system-paths-mode-v1,startup-files-write-protection-v1,suid-sgid-applications-mode-v1' \
    'APPLY_CONTROL_COUNT=43' \
    'APPLY_IMPLEMENTATION_COUNT=9' \
    'APPLY_KIND_REGISTRY_SHA256=35031db3bb6140789f5127f1930511a8d1932a92963884182c51a5d989b74800' \
    'APPLY_IMPLEMENTATION_REGISTRY_SHA256=a9abb02944f5af488c2e06f29e6f2b31f72800b35be908415d181df21727fa2a' \
    'TARGET_FAMILY_ID=linux-x86_64-supported-v1' \
    'SUPPORTED_PROFILE_ENVIRONMENTS=7' \
    'FIELD_COMPATIBILITY_ENVIRONMENTS=1' \
    'SUPPORTED_ENVIRONMENTS=7' \
    'PLATFORM_MATRIX_SHA256=efc7436850d1ae92df0f36b33e86663728a9fb3643ba3be8cbcaf40b0c9490d7' \
    'DESKTOP_MATRIX_SHA256=5a910c9efa49fa13e2d1183cc3efc9f8c4a951f11f4aca2ee56bd990463ac29e'
}

slp_help() {
  command /usr/bin/cat <<'SLP_HELP_EOF'
SecureLinux-Policy — единый product CLI

Использование:
  ./securelinux-policy.sh --check [--failed] [--format pretty|raw|json]
  ./securelinux-policy.sh --report
  ./securelinux-policy.sh --build-info
  ./securelinux-policy.sh --provenance [CONTROL_ID]
  ./securelinux-policy.sh --version
  ./securelinux-policy.sh --help
  ./securelinux-policy.sh --apply
  ./securelinux-policy.sh --apply --dry-run

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
  --apply               применить все controls с apply.supported=true
  --apply --dry-run     выполнить те же наблюдения и расчёт без target-мутаций

Без аргументов печатается эта справка. CHECK не изменяет состояние хоста.
SLP_HELP_EOF
}

slp_version() {
  printf '%s\n' \
    'PRODUCT=SecureLinux-Policy-v3' \
    'PRODUCT_CLI=product-cli-v1' \
    'STATUS=NON_RELEASE_PRODUCT_CANDIDATE' \
    'CONTROL_COUNT=52' \
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

slp_presentation_for_control() {
  local _slp_cid=$1
  case "$_slp_cid" in
    'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE') printf '%s' 'fstec-linux-2022 §2.1.1	local-account-password-state	all non-empty' ;;
    'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN') printf '%s' 'fstec-linux-2022 §2.1.2	ssh-root-login	= no' ;;
    'FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS') printf '%s' 'fstec-linux-2022 §2.2.1	su-wheel-access	rule and root in wheel: auth required pam_wheel.so use_uid;wheel:root' ;;
    'FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY') printf '%s' 'fstec-linux-2022 §2.2.2	sudoers-reviewed-policy	stock rules only: root ALL=(ALL:ALL) ALL;%sudo ALL=(ALL:ALL) ALL;%admin ALL=(ALL) ALL' ;;
    'FSTEC-LINUX-2022-2.3.1-GROUP-MODE') printf '%s' 'fstec-linux-2022 §2.3.1	group-mode	= 0644' ;;
    'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE') printf '%s' 'fstec-linux-2022 §2.3.1	passwd-mode	= 0644' ;;
    'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX') printf '%s' 'fstec-linux-2022 §2.3.1	shadow-go-rwx	bits 0077 = 0' ;;
    'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE') printf '%s' 'fstec-linux-2022 §2.3.10	home-sensitive-files-mode	bits 0077 = 0' ;;
    'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE') printf '%s' 'fstec-linux-2022 §2.3.11	home-directories-mode	= 0700' ;;
    'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION') printf '%s' 'fstec-linux-2022 §2.3.2	running-process-paths-write-protection	runtime paths safe' ;;
    'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION') printf '%s' 'fstec-linux-2022 §2.3.3	cron-command-paths-write-protection	cron command paths safe' ;;
    'FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION') printf '%s' 'fstec-linux-2022 §2.3.4	sudo-root-command-files-protection	owner root if regular user; go-w if other-writable' ;;
    'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION') printf '%s' 'fstec-linux-2022 §2.3.5	startup-files-write-protection	bits 0002 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-D') printf '%s' 'fstec-linux-2022 §2.3.6	cron-d	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-DAILY') printf '%s' 'fstec-linux-2022 §2.3.6	cron-daily	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY') printf '%s' 'fstec-linux-2022 §2.3.6	cron-hourly	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY') printf '%s' 'fstec-linux-2022 §2.3.6	cron-monthly	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY') printf '%s' 'fstec-linux-2022 §2.3.6	cron-weekly	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.6-CRONTAB') printf '%s' 'fstec-linux-2022 §2.3.6	crontab	bits 0033 = 0' ;;
    'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE') printf '%s' 'fstec-linux-2022 §2.3.7	user-cron-files-mode	bits 0022 = 0' ;;
    'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE') printf '%s' 'fstec-linux-2022 §2.3.8	standard-system-paths-mode	bits 0022 = 0' ;;
    'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE') printf '%s' 'fstec-linux-2022 §2.3.9	suid-sgid-mode	bits 0022 = 0' ;;
    'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT') printf '%s' 'fstec-linux-2022 §2.4.1	dmesg-restrict	= 1' ;;
    'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT') printf '%s' 'fstec-linux-2022 §2.4.2	kptr-restrict	= 2' ;;
    'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC') printf '%s' 'fstec-linux-2022 §2.4.3	init-on-alloc	= 1' ;;
    'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE') printf '%s' 'fstec-linux-2022 §2.4.4	slab-nomerge	present' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE') printf '%s' 'fstec-linux-2022 §2.4.5	iommu-force	= force' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH') printf '%s' 'fstec-linux-2022 §2.4.5	iommu-passthrough	= 0' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT') printf '%s' 'fstec-linux-2022 §2.4.5	iommu-strict	= 1' ;;
    'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET') printf '%s' 'fstec-linux-2022 §2.4.6	randomize-kstack-offset	= 1' ;;
    'FSTEC-LINUX-2022-2.4.7-MITIGATIONS') printf '%s' 'fstec-linux-2022 §2.4.7	mitigations	= auto,nosmt' ;;
    'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN') printf '%s' 'fstec-linux-2022 §2.4.8	bpf-jit-harden	= 2' ;;
    'FSTEC-LINUX-2022-2.5.1-VSYSCALL') printf '%s' 'fstec-linux-2022 §2.5.1	vsyscall	= none' ;;
    'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR') printf '%s' 'fstec-linux-2022 §2.5.10	mmap-min-addr	>= 4096' ;;
    'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE') printf '%s' 'fstec-linux-2022 §2.5.11	randomize-va-space	= 2' ;;
    'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID') printf '%s' 'fstec-linux-2022 §2.5.2	perf-event-paranoid	= 3' ;;
    'FSTEC-LINUX-2022-2.5.3-DEBUGFS') printf '%s' 'fstec-linux-2022 §2.5.3	debugfs	one of: off|no-mount' ;;
    'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED') printf '%s' 'fstec-linux-2022 §2.5.4	kexec-load-disabled	= 1' ;;
    'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES') printf '%s' 'fstec-linux-2022 §2.5.5	max-user-namespaces	= 0' ;;
    'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED') printf '%s' 'fstec-linux-2022 §2.5.6	unprivileged-bpf-disabled	= 1' ;;
    'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD') printf '%s' 'fstec-linux-2022 §2.5.7	unprivileged-userfaultfd	= 0' ;;
    'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD') printf '%s' 'fstec-linux-2022 §2.5.8	ldisc-autoload	= 0' ;;
    'FSTEC-LINUX-2022-2.5.9-TSX') printf '%s' 'fstec-linux-2022 §2.5.9	tsx	= off' ;;
    'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE') printf '%s' 'fstec-linux-2022 §2.6.1	ptrace-scope	= 3' ;;
    'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS') printf '%s' 'fstec-linux-2022 §2.6.2	protected-symlinks	= 1' ;;
    'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS') printf '%s' 'fstec-linux-2022 §2.6.3	protected-hardlinks	= 1' ;;
    'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS') printf '%s' 'fstec-linux-2022 §2.6.4	protected-fifos	= 2' ;;
    'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR') printf '%s' 'fstec-linux-2022 §2.6.5	protected-regular	= 2' ;;
    'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE') printf '%s' 'fstec-linux-2022 §2.6.6	suid-dumpable	= 0' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION') printf '%s' 'fstec-configuration-2026 §9.1	ssh-password-authentication	= no' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS') printf '%s' 'fstec-configuration-2026 §9.1	ssh-permit-empty-passwords	= no' ;;
    'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN') printf '%s' 'fstec-configuration-2026 §9.1	ssh-permit-root-login	= no' ;;
    *) return 1 ;;
  esac
}

slp_pretty_status() {
  case "$1" in
    PASS) printf '%s' ok ;;
    FAIL) printf '%s' fail ;;
    ERROR) printf '%s' err ;;
    NOT_FOUND) printf '%s' nf ;;
    NOT_APPLICABLE) printf '%s' na ;;
    *) return 1 ;;
  esac
}

SLP_PRETTY_COLS=116
SLP_PRETTY_MODE=table
SLP_PRETTY_WS=5
SLP_PRETTY_WSRC=29
SLP_PRETTY_WC=29
SLP_PRETTY_WCUR=14
SLP_PRETTY_WREQ=24
SLP_PRETTY_VFIELD=8
SLP_PRETTY_VVALUE=104

slp_terminal_columns() {
  local _slp_size='' _slp_rows='' _slp_cols='' _slp_extra=''
  if [[ -r /dev/tty && -x /usr/bin/stty ]]; then
    _slp_size=$(command /usr/bin/stty size < /dev/tty 2>/dev/null) || _slp_size=''
    if [[ -n $_slp_size ]]; then
      read -r _slp_rows _slp_cols _slp_extra <<< "$_slp_size"
      if [[ $_slp_rows =~ ^[0-9]+$ && $_slp_cols =~ ^[0-9]+$ && -z $_slp_extra ]] && (( _slp_cols >= 40 && _slp_cols <= 1000 )); then
        printf '%s\n' "$_slp_cols"
        return 0
      fi
    fi
  fi
  printf '116\n'
}

slp_pretty_layout_for_cols() {
  local _slp_cols=$1 _slp_available _slp_remaining _slp_req_min
  [[ $_slp_cols =~ ^[0-9]+$ ]] || return 1
  (( _slp_cols >= 40 && _slp_cols <= 1000 )) || return 1
  SLP_PRETTY_COLS=$_slp_cols
  SLP_PRETTY_WS=5
  if (( _slp_cols < 90 )); then
    SLP_PRETTY_MODE=vertical
    SLP_PRETTY_VFIELD=8
    SLP_PRETTY_VVALUE=$((_slp_cols - SLP_PRETTY_VFIELD - 6))
    (( SLP_PRETTY_VVALUE > 0 )) || return 1
    return 0
  fi
  SLP_PRETTY_MODE=table
  if (( _slp_cols < 100 )); then
    SLP_PRETTY_WSRC=18
    SLP_PRETTY_WC=24
    _slp_req_min=10
  elif (( _slp_cols < 110 )); then
    SLP_PRETTY_WSRC=29
    SLP_PRETTY_WC=25
    _slp_req_min=12
  elif (( _slp_cols < 120 )); then
    SLP_PRETTY_WSRC=29
    SLP_PRETTY_WC=29
    _slp_req_min=14
  else
    SLP_PRETTY_WSRC=29
    SLP_PRETTY_WC=33
    _slp_req_min=16
  fi
  _slp_available=$((_slp_cols - 15))
  _slp_remaining=$((_slp_available - SLP_PRETTY_WS - SLP_PRETTY_WSRC - SLP_PRETTY_WC))
  (( _slp_remaining > _slp_req_min )) || return 1
  SLP_PRETTY_WCUR=$((_slp_remaining - _slp_req_min))
  (( SLP_PRETTY_WCUR > 43 )) && SLP_PRETTY_WCUR=43
  # current отдаёт required 10 символов, но не становится уже 12.
  if (( SLP_PRETTY_WCUR - 10 > 12 )); then
    SLP_PRETTY_WCUR=$((SLP_PRETTY_WCUR - 10))
  elif (( SLP_PRETTY_WCUR > 12 )); then
    SLP_PRETTY_WCUR=12
  fi
  SLP_PRETTY_WREQ=$((_slp_remaining - SLP_PRETTY_WCUR))
}

slp_pretty_layout_init() {
  local _slp_cols
  if [[ ! -t 1 ]]; then
    slp_pretty_layout_for_cols 116
    return $?
  fi
  _slp_cols=$(slp_terminal_columns) || return 1
  slp_pretty_layout_for_cols "$_slp_cols"
}

slp_repeat_dash() {
  local _slp_n=$1 _slp_out
  printf -v _slp_out '%*s' "$_slp_n" ''
  printf '%s' "${_slp_out// /-}"
}

slp_pretty_separator() {
  if [[ $SLP_PRETTY_MODE == vertical ]]; then
    slp_repeat_dash $((SLP_PRETTY_VFIELD + 2))
    printf '+'
    slp_repeat_dash $((SLP_PRETTY_VVALUE + 2))
    printf '+\n'
    return 0
  fi
  slp_repeat_dash $((SLP_PRETTY_WS + 2))
  printf '+'
  slp_repeat_dash $((SLP_PRETTY_WSRC + 2))
  printf '+'
  slp_repeat_dash $((SLP_PRETTY_WC + 2))
  printf '+'
  slp_repeat_dash $((SLP_PRETTY_WCUR + 2))
  printf '+'
  slp_repeat_dash $((SLP_PRETTY_WREQ + 2))
  printf '+\n'
}

slp_pretty_cell() {
  local _slp_text=$1 _slp_width=$2 _slp_chars _slp_bytes _slp_printf_width
  local LC_ALL=C.UTF-8
  _slp_chars=${#_slp_text}
  LC_ALL=C
  _slp_bytes=${#_slp_text}
  _slp_printf_width=$((_slp_width + _slp_bytes - _slp_chars))
  printf '%-*s' "$_slp_printf_width" "$_slp_text"
}

slp_pretty_vertical_field() {
  local LC_ALL=C.UTF-8
  local _slp_label=$1 _slp_text=$2 _slp_chunk
  if [[ -z $_slp_text ]]; then
    printf ' '
    slp_pretty_cell "$_slp_label" "$SLP_PRETTY_VFIELD"
    printf ' | '
    slp_pretty_cell '' "$SLP_PRETTY_VVALUE"
    printf ' |\n'
    return 0
  fi
  while [[ -n $_slp_text ]]; do
    _slp_chunk=${_slp_text:0:SLP_PRETTY_VVALUE}
    _slp_text=${_slp_text:SLP_PRETTY_VVALUE}
    printf ' '
    slp_pretty_cell "$_slp_label" "$SLP_PRETTY_VFIELD"
    printf ' | '
    slp_pretty_cell "$_slp_chunk" "$SLP_PRETTY_VVALUE"
    printf ' |\n'
    _slp_label=''
  done
}

slp_pretty_row() {
  local LC_ALL=C.UTF-8
  local _slp_st=$1 _slp_source=$2 _slp_control=$3 _slp_current=$4 _slp_required=$5
  local _slp_a _slp_b _slp_c _slp_d _slp_e
  if [[ $SLP_PRETTY_MODE == vertical ]]; then
    if [[ $_slp_st == st && $_slp_source == source && $_slp_control == control ]]; then
      printf ' '
      slp_pretty_cell field "$SLP_PRETTY_VFIELD"
      printf ' | '
      slp_pretty_cell value "$SLP_PRETTY_VVALUE"
      printf ' |\n'
      return 0
    fi
    slp_pretty_vertical_field st "$_slp_st"
    slp_pretty_vertical_field source "$_slp_source"
    slp_pretty_vertical_field control "$_slp_control"
    slp_pretty_vertical_field current "$_slp_current"
    slp_pretty_vertical_field required "$_slp_required"
    return 0
  fi
  while [[ -n $_slp_st || -n $_slp_source || -n $_slp_control || -n $_slp_current || -n $_slp_required ]]; do
    _slp_a=${_slp_st:0:SLP_PRETTY_WS}; _slp_st=${_slp_st:SLP_PRETTY_WS}
    _slp_b=${_slp_source:0:SLP_PRETTY_WSRC}; _slp_source=${_slp_source:SLP_PRETTY_WSRC}
    _slp_c=${_slp_control:0:SLP_PRETTY_WC}; _slp_control=${_slp_control:SLP_PRETTY_WC}
    _slp_d=${_slp_current:0:SLP_PRETTY_WCUR}; _slp_current=${_slp_current:SLP_PRETTY_WCUR}
    _slp_e=${_slp_required:0:SLP_PRETTY_WREQ}; _slp_required=${_slp_required:SLP_PRETTY_WREQ}
    printf ' '
    slp_pretty_cell "$_slp_a" "$SLP_PRETTY_WS"
    printf ' | '
    slp_pretty_cell "$_slp_b" "$SLP_PRETTY_WSRC"
    printf ' | '
    slp_pretty_cell "$_slp_c" "$SLP_PRETTY_WC"
    printf ' | '
    slp_pretty_cell "$_slp_d" "$SLP_PRETTY_WCUR"
    printf ' | '
    slp_pretty_cell "$_slp_e" "$SLP_PRETTY_WREQ"
    printf ' |\n'
  done
}

slp_collect_policy() {
  # reason допускает необязательный третий сегмент-payload (путь, цель
  # readlink и т. п.): <domain>:<reason>[:<payload>]. Payload может содержать
  # любые байты, кроме control-байт (0x00-0x1F, 0x7F) — они ломают
  # табличный/TSV вывод. Локаль фиксируется явно: классификация [:cntrl:]
  # обязана быть побайтовой, не зависеть от окружения вызова.
  local LC_ALL=C
  local _slp_fn _slp_expected_cid _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_extra
  local _slp_i
  local -a _slp_fns=('slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE' 'slp_check_FSTEC_LINUX_2022_2_1_2_SSH_ROOT_LOGIN' 'slp_check_FSTEC_LINUX_2022_2_2_1_SU_WHEEL_ACCESS' 'slp_check_FSTEC_LINUX_2022_2_2_2_SUDOERS_REVIEWED_POLICY' 'slp_check_FSTEC_LINUX_2022_2_3_1_GROUP_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_1_PASSWD_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_1_SHADOW_GO_RWX' 'slp_check_FSTEC_LINUX_2022_2_3_10_HOME_SENSITIVE_FILES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_11_HOME_DIRECTORIES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_2_RUNNING_PROCESS_PATHS_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_3_CRON_COMMAND_PATHS_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_4_SUDO_ROOT_COMMAND_FILES_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_5_STARTUP_FILES_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_D' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_DAILY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_HOURLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_MONTHLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_WEEKLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRONTAB' 'slp_check_FSTEC_LINUX_2022_2_3_7_USER_CRON_FILES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_8_STANDARD_SYSTEM_PATHS_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_MODE' 'slp_check_FSTEC_LINUX_2022_2_4_1_DMESG_RESTRICT' 'slp_check_FSTEC_LINUX_2022_2_4_2_KPTR_RESTRICT' 'slp_check_FSTEC_LINUX_2022_2_4_3_INIT_ON_ALLOC' 'slp_check_FSTEC_LINUX_2022_2_4_4_SLAB_NOMERGE' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_FORCE' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_PASSTHROUGH' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_STRICT' 'slp_check_FSTEC_LINUX_2022_2_4_6_RANDOMIZE_KSTACK_OFFSET' 'slp_check_FSTEC_LINUX_2022_2_4_7_MITIGATIONS' 'slp_check_FSTEC_LINUX_2022_2_4_8_BPF_JIT_HARDEN' 'slp_check_FSTEC_LINUX_2022_2_5_1_VSYSCALL' 'slp_check_FSTEC_LINUX_2022_2_5_10_MMAP_MIN_ADDR' 'slp_check_FSTEC_LINUX_2022_2_5_11_RANDOMIZE_VA_SPACE' 'slp_check_FSTEC_LINUX_2022_2_5_2_PERF_EVENT_PARANOID' 'slp_check_FSTEC_LINUX_2022_2_5_3_DEBUGFS' 'slp_check_FSTEC_LINUX_2022_2_5_4_KEXEC_LOAD_DISABLED' 'slp_check_FSTEC_LINUX_2022_2_5_5_MAX_USER_NAMESPACES' 'slp_check_FSTEC_LINUX_2022_2_5_6_UNPRIVILEGED_BPF_DISABLED' 'slp_check_FSTEC_LINUX_2022_2_5_7_UNPRIVILEGED_USERFAULTFD' 'slp_check_FSTEC_LINUX_2022_2_5_8_LDISC_AUTOLOAD' 'slp_check_FSTEC_LINUX_2022_2_5_9_TSX' 'slp_check_FSTEC_LINUX_2022_2_6_1_PTRACE_SCOPE' 'slp_check_FSTEC_LINUX_2022_2_6_2_PROTECTED_SYMLINKS' 'slp_check_FSTEC_LINUX_2022_2_6_3_PROTECTED_HARDLINKS' 'slp_check_FSTEC_LINUX_2022_2_6_4_PROTECTED_FIFOS' 'slp_check_FSTEC_LINUX_2022_2_6_5_PROTECTED_REGULAR' 'slp_check_FSTEC_LINUX_2022_2_6_6_SUID_DUMPABLE' 'slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PASSWORD_AUTHENTICATION' 'slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PERMIT_EMPTY_PASSWORDS' 'slp_check_FSTEC_CONFIGURATION_2026_9_1_SSH_PERMIT_ROOT_LOGIN')
  local -a _slp_ids=('FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' 'FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS' 'FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION' 'FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.6-CRON-D' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' 'FSTEC-LINUX-2022-2.5.9-TSX' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS' 'FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN')

  SLP_RESULTS=()
  SLP_TOTAL=0 SLP_PASS=0 SLP_FAIL=0 SLP_NF=0 SLP_NA=0 SLP_ERR=0 SLP_POLICY_STATUS='' SLP_POLICY_RC=0

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
      VALUE:PASS|VALUE:FAIL|NOT_FOUND:FAIL|NOT_FOUND:NOT_FOUND|NOT_APPLICABLE:NOT_APPLICABLE|ERROR:ERROR) ;;
      *)
        printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
        return 1
        ;;
    esac
    if [[ $_slp_comp == ERROR ]]; then
      if [[ ! $_slp_value =~ ^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*(:[^[:cntrl:]]*)?$ ]]; then
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
      NOT_APPLICABLE) ((SLP_NA+=1)) ;;
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

slp_support_class() {
  if [[ $SLP_SYSTEM_TYPE == DESKTOP ]]; then
    printf '%s' FIELD_COMPATIBILITY
  else
    printf '%s' SUPPORTED
  fi
}

slp_render_raw() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp
  printf 'SLP-PLATFORM-V1\tSYSTEM=%s\tID=%s\tVERSION_ID=%s\tARCH=%s\tPROFILE=%s\tTYPE=%s\tPLATFORM=%s\tENVIRONMENT=%s\tSUPPORT=%s\n' \
    "$SLP_SYSTEM_PRETTY_NAME" "$SLP_SYSTEM_ID" "$SLP_SYSTEM_VERSION_ID" "$SLP_SYSTEM_ARCH" \
    "$SLP_SYSTEM_PROFILE" "$SLP_SYSTEM_TYPE" "$SLP_SYSTEM_PLATFORM" "$SLP_SYSTEM_ENVIRONMENT" "$(slp_support_class)"
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    printf '%s\n' "$_slp_line"
  done
  printf 'SLP-SUMMARY-V1\tTOTAL=%d\tPASS=%d\tFAIL=%d\tNOT_FOUND=%d\tNOT_APPLICABLE=%d\tERROR=%d\tPOLICY_STATUS=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_NA" "$SLP_ERR" "$SLP_POLICY_STATUS"
}

slp_render_pretty() {
  local _slp_failed_only=$1 _slp_title=$2 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp
  local _slp_current _slp_required _slp_meta _slp_source _slp_control _slp_extra _slp_st
  printf '=== SecureLinux Policy — %s ===\n' "$_slp_title"
  printf 'SUPPORT=%s\n' "$(slp_support_class)"
  printf 'SYSTEM=%s ARCH=%s\n' "$SLP_SYSTEM_PRETTY_NAME" "$SLP_SYSTEM_ARCH"
  printf 'PLATFORM=%s\n' "$SLP_SYSTEM_PLATFORM"
  if [[ -n $SLP_SYSTEM_TYPE ]]; then
    printf 'TYPE=%s\n\n' "$SLP_SYSTEM_TYPE"
  else
    printf 'PROFILE=%s\n\n' "$SLP_SYSTEM_PROFILE"
  fi
  slp_pretty_layout_init || return 1
  slp_pretty_separator
  slp_pretty_row 'st' 'source' 'control' 'current' 'required'
  slp_pretty_separator
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    if ! _slp_meta=$(slp_presentation_for_control "$_slp_cid"); then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    IFS=$'\t' read -r _slp_source _slp_control _slp_required _slp_extra <<< "$_slp_meta"
    if [[ -z $_slp_source || -z $_slp_control || -z $_slp_required || -n $_slp_extra ]]; then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    if ! _slp_st=$(slp_pretty_status "$_slp_comp"); then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    case "$_slp_status" in
      VALUE) _slp_current=$_slp_value ;;
      NOT_FOUND) _slp_current='<absent>' ;;
      NOT_APPLICABLE) _slp_current='<not-applicable>' ;;
      ERROR) _slp_current="not-determined; reason: $_slp_value" ;;
      *) printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2; return 1 ;;
    esac
    slp_pretty_row "$_slp_st" "$_slp_source" "$_slp_control" "$_slp_current" "$_slp_required"
  done
  slp_pretty_separator
  printf 'TOTAL=%d   PASS=%d   FAIL=%d   NOT_FOUND=%d   NOT_APPLICABLE=%d   ERROR=%d   POLICY=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_NA" "$SLP_ERR" "$SLP_POLICY_STATUS"
}

slp_render_json() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_first=1 _slp_filter=all
  (( _slp_failed_only == 1 )) && _slp_filter=failed
  printf '{"schema":"SLP-REPORT-V1","filter":"%s","platform":{"system":"%s","id":"%s","version_id":"%s","arch":"%s","profile":"%s","type":"%s","platform_id":"%s","environment_id":"%s","support":"%s"},"policy_status":"%s","summary":{"total":%d,"pass":%d,"fail":%d,"not_found":%d,"not_applicable":%d,"error":%d},"results":[' \
    "$_slp_filter" "$(slp_json_escape "$SLP_SYSTEM_PRETTY_NAME")" "$(slp_json_escape "$SLP_SYSTEM_ID")" \
    "$(slp_json_escape "$SLP_SYSTEM_VERSION_ID")" "$(slp_json_escape "$SLP_SYSTEM_ARCH")" \
    "$(slp_json_escape "$SLP_SYSTEM_PROFILE")" "$(slp_json_escape "$SLP_SYSTEM_TYPE")" "$(slp_json_escape "$SLP_SYSTEM_PLATFORM")" \
    "$(slp_json_escape "$SLP_SYSTEM_ENVIRONMENT")" "$(slp_json_escape "$(slp_support_class)")" "$SLP_POLICY_STATUS" "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_NA" "$SLP_ERR"
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

slp_run_apply() {
  local _slp_mode=$1
  slp_target_preflight || return $?
  if [[ $_slp_mode == APPLY && $SLP_SYSTEM_TYPE == DESKTOP ]]; then
    {
      printf '\n%s\n' '+------------------------------------------------------------------------------------------+'
      printf '%s\n' '| ВНИМАНИЕ: UBUNTU DESKTOP = FIELD_COMPATIBILITY                                           |'
      printf '%s\n' '| Корректность APPLY на изменённой пользователем desktop-системе не гарантируется.         |'
      printf '%s\n' '| Установленные пакеты, службы и локальные настройки могут изменить поведение CHECK/APPLY. |'
      printf '%s\n' '| Перед APPLY выполните --apply --dry-run и обеспечьте внешний snapshot/backup.            |'
      printf '%s\n\n' '+------------------------------------------------------------------------------------------+'
    } >&2
  fi
  command /usr/bin/python3 -I -S -B - "$_slp_mode" <<'SLP_PRODUCT_APPLY_EOF'
import base64
import datetime
import fcntl
import grp
import json
import os
import stat
import sys
import tempfile
import traceback

MODE = sys.argv[1] if len(sys.argv) == 2 else ""
if MODE not in {"APPLY", "DRY_RUN"}:
    raise SystemExit(2)
DRY_RUN = MODE == "DRY_RUN"
STATE_DIR = "/var/log/securelinux-policy"
APPLY_LOG = "apply.log"
DEBUG_LOG = "debug.log"
REPORT_PATH = "report.json"
TRUSTED_UID = PARENT_TRUSTED_UID = 0
PARENT_WRITABLE_GROUPS = ("root", "syslog")
LOCK_NAME = ".lock"
LOCK_PATH = os.path.join(STATE_DIR, LOCK_NAME)
_LOCK_FD = None
_STATE_DFD = None
APPLY_CONTROLS = json.loads('[{"control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","display_control":"su-wheel-access","expected":"auth required pam_wheel.so use_uid;wheel:root","key":"policy","op":"pam-wheel-root-member","parameter_kind":"pam-wheel-access","required":"rule and root in wheel: auth required pam_wheel.so use_uid;wheel:root","source":"fstec-linux-2022 §2.2.1"},{"control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","display_control":"group-mode","expected":"0644","key":"mode","op":"eq","parameter_kind":"file-mode-owner","required":"= 0644","source":"fstec-linux-2022 §2.3.1"},{"control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","display_control":"passwd-mode","expected":"0644","key":"mode","op":"eq","parameter_kind":"file-mode-owner","required":"= 0644","source":"fstec-linux-2022 §2.3.1"},{"control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","display_control":"shadow-go-rwx","expected":"0077","key":"mode","op":"bits-clear","parameter_kind":"file-mode-owner","required":"bits 0077 = 0","source":"fstec-linux-2022 §2.3.1"},{"control_id":"FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION","display_control":"startup-files-write-protection","expected":"0002","key":"other-write","op":"bits-clear","parameter_kind":"startup-files-write-protection","required":"bits 0002 = 0","source":"fstec-linux-2022 §2.3.5"},{"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","display_control":"cron-d","expected":"0033","key":"mode","op":"bits-clear","parameter_kind":"optional-file-root-files-mode","required":"bits 0033 = 0","source":"fstec-linux-2022 §2.3.6"},{"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","display_control":"cron-daily","expected":"0033","key":"mode","op":"bits-clear","parameter_kind":"optional-file-root-files-mode","required":"bits 0033 = 0","source":"fstec-linux-2022 §2.3.6"},{"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","display_control":"cron-hourly","expected":"0033","key":"mode","op":"bits-clear","parameter_kind":"optional-file-root-files-mode","required":"bits 0033 = 0","source":"fstec-linux-2022 §2.3.6"},{"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","display_control":"cron-monthly","expected":"0033","key":"mode","op":"bits-clear","parameter_kind":"optional-file-root-files-mode","required":"bits 0033 = 0","source":"fstec-linux-2022 §2.3.6"},{"control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","display_control":"cron-weekly","expected":"0033","key":"mode","op":"bits-clear","parameter_kind":"optional-file-root-files-mode","required":"bits 0033 = 0","source":"fstec-linux-2022 §2.3.6"},{"control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","display_control":"crontab","expected":"0033","key":"mode","op":"bits-clear","parameter_kind":"optional-file-root-files-mode","required":"bits 0033 = 0","source":"fstec-linux-2022 §2.3.6"},{"control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","display_control":"standard-system-paths-mode","expected":"0022","key":"mode","op":"bits-clear","parameter_kind":"standard-system-paths-mode","required":"bits 0022 = 0","source":"fstec-linux-2022 §2.3.8"},{"control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","display_control":"suid-sgid-mode","expected":"0022","key":"mode","op":"bits-clear","parameter_kind":"suid-sgid-applications","required":"bits 0022 = 0","source":"fstec-linux-2022 §2.3.9"},{"control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","display_control":"dmesg-restrict","expected":1,"key":"kernel.dmesg_restrict","op":"eq","parameter_kind":"sysctl","required":"= 1","source":"fstec-linux-2022 §2.4.1"},{"control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","display_control":"kptr-restrict","expected":2,"key":"kernel.kptr_restrict","op":"eq","parameter_kind":"sysctl","required":"= 2","source":"fstec-linux-2022 §2.4.2"},{"control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","display_control":"init-on-alloc","expected":"1","key":"init_on_alloc","op":"eq","parameter_kind":"kernel-cmdline","required":"= 1","source":"fstec-linux-2022 §2.4.3"},{"control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","display_control":"slab-nomerge","expected":true,"key":"slab_nomerge","op":"present","parameter_kind":"kernel-cmdline","required":"present","source":"fstec-linux-2022 §2.4.4"},{"control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","display_control":"iommu-force","expected":"force","key":"iommu","op":"eq","parameter_kind":"kernel-cmdline","required":"= force","source":"fstec-linux-2022 §2.4.5"},{"control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","display_control":"iommu-passthrough","expected":"0","key":"iommu.passthrough","op":"eq","parameter_kind":"kernel-cmdline","required":"= 0","source":"fstec-linux-2022 §2.4.5"},{"control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","display_control":"iommu-strict","expected":"1","key":"iommu.strict","op":"eq","parameter_kind":"kernel-cmdline","required":"= 1","source":"fstec-linux-2022 §2.4.5"},{"control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","display_control":"randomize-kstack-offset","expected":"1","key":"randomize_kstack_offset","op":"eq","parameter_kind":"kernel-cmdline","required":"= 1","source":"fstec-linux-2022 §2.4.6"},{"control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","display_control":"mitigations","expected":"auto,nosmt","key":"mitigations","op":"eq","parameter_kind":"kernel-cmdline","required":"= auto,nosmt","source":"fstec-linux-2022 §2.4.7"},{"control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","display_control":"bpf-jit-harden","expected":2,"key":"net.core.bpf_jit_harden","op":"eq","parameter_kind":"sysctl","required":"= 2","source":"fstec-linux-2022 §2.4.8"},{"control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","display_control":"vsyscall","expected":"none","key":"vsyscall","op":"eq","parameter_kind":"kernel-cmdline","required":"= none","source":"fstec-linux-2022 §2.5.1"},{"control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","display_control":"mmap-min-addr","expected":4096,"key":"vm.mmap_min_addr","op":"ge","parameter_kind":"sysctl","required":">= 4096","source":"fstec-linux-2022 §2.5.10"},{"control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","display_control":"randomize-va-space","expected":2,"key":"kernel.randomize_va_space","op":"eq","parameter_kind":"sysctl","required":"= 2","source":"fstec-linux-2022 §2.5.11"},{"control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","display_control":"perf-event-paranoid","expected":3,"key":"kernel.perf_event_paranoid","op":"eq","parameter_kind":"sysctl","required":"= 3","source":"fstec-linux-2022 §2.5.2"},{"control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","display_control":"debugfs","expected":"off|no-mount","key":"debugfs","op":"one-of","parameter_kind":"kernel-cmdline","required":"one of: off|no-mount","source":"fstec-linux-2022 §2.5.3"},{"control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","display_control":"kexec-load-disabled","expected":1,"key":"kernel.kexec_load_disabled","op":"eq","parameter_kind":"sysctl","required":"= 1","source":"fstec-linux-2022 §2.5.4"},{"control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","display_control":"max-user-namespaces","expected":0,"key":"user.max_user_namespaces","op":"eq","parameter_kind":"sysctl","required":"= 0","source":"fstec-linux-2022 §2.5.5"},{"control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","display_control":"unprivileged-bpf-disabled","expected":1,"key":"kernel.unprivileged_bpf_disabled","op":"eq","parameter_kind":"sysctl","required":"= 1","source":"fstec-linux-2022 §2.5.6"},{"control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","display_control":"unprivileged-userfaultfd","expected":0,"key":"vm.unprivileged_userfaultfd","op":"eq","parameter_kind":"sysctl","required":"= 0","source":"fstec-linux-2022 §2.5.7"},{"control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","display_control":"ldisc-autoload","expected":0,"key":"dev.tty.ldisc_autoload","op":"eq","parameter_kind":"sysctl","required":"= 0","source":"fstec-linux-2022 §2.5.8"},{"control_id":"FSTEC-LINUX-2022-2.5.9-TSX","display_control":"tsx","expected":"off","key":"tsx","op":"eq","parameter_kind":"kernel-cmdline","required":"= off","source":"fstec-linux-2022 §2.5.9"},{"control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","display_control":"ptrace-scope","expected":3,"key":"kernel.yama.ptrace_scope","op":"eq","parameter_kind":"sysctl","required":"= 3","source":"fstec-linux-2022 §2.6.1"},{"control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","display_control":"protected-symlinks","expected":1,"key":"fs.protected_symlinks","op":"eq","parameter_kind":"sysctl","required":"= 1","source":"fstec-linux-2022 §2.6.2"},{"control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","display_control":"protected-hardlinks","expected":1,"key":"fs.protected_hardlinks","op":"eq","parameter_kind":"sysctl","required":"= 1","source":"fstec-linux-2022 §2.6.3"},{"control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","display_control":"protected-fifos","expected":2,"key":"fs.protected_fifos","op":"eq","parameter_kind":"sysctl","required":"= 2","source":"fstec-linux-2022 §2.6.4"},{"control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","display_control":"protected-regular","expected":2,"key":"fs.protected_regular","op":"eq","parameter_kind":"sysctl","required":"= 2","source":"fstec-linux-2022 §2.6.5"},{"control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","display_control":"suid-dumpable","expected":0,"key":"fs.suid_dumpable","op":"eq","parameter_kind":"sysctl","required":"= 0","source":"fstec-linux-2022 §2.6.6"},{"control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION","display_control":"ssh-password-authentication","expected":"no","key":"PasswordAuthentication","op":"eq","parameter_kind":"sshd-config-option","required":"= no","source":"fstec-configuration-2026 §9.1"},{"control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS","display_control":"ssh-permit-empty-passwords","expected":"no","key":"PermitEmptyPasswords","op":"eq","parameter_kind":"sshd-config-option","required":"= no","source":"fstec-configuration-2026 §9.1"},{"control_id":"FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN","display_control":"ssh-permit-root-login","expected":"no","key":"PermitRootLogin","op":"eq","parameter_kind":"sshd-config-option","required":"= no","source":"fstec-configuration-2026 §9.1"}]')
ROUTES = json.loads('{"file-mode-owner":{"adapter_id":"product-file-mode-owner-apply-v1","apply_kind":"file-mode-owner-v1","implementation_sha256":"549c004ab8fc1fb131e95754ded533e01426a2cdde85fccb45ec36632c5e9ed3","mechanism_id":"file-mode-owner-v1","source_b64":"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiJwcm9kdWN0LWZpbGUtbW9kZS1vd25lci1hcHBseS12MS4KCkFQUExZIGFkYXB0ZXIgZm9yIG1lY2hhbmlzbSBgZmlsZS1tb2RlLW93bmVyLXYxYC4KClBVUlBPU0U9REVGRU5TSVZFX0NPTVBMSUFOQ0VfVkFMSURBVElPTgpBdXRob3JpdHk6IHByb2R1Y3QvY29udHJhY3RzL21lY2hhbmlzbS1maWxlLW1vZGUtb3duZXItdjEuanNvbgoKTXV0YXRpb24gaXMgYSBzaW5nbGUgYGZjaG1vZGAgb24gYSBmaWxlIGRlc2NyaXB0b3Igb3BlbmVkIHdpdGggT19OT0ZPTExPVy4KVGhlIG1lY2hhbmlzbSBvbmx5IGNsZWFycyBwZXJtaXNzaW9uIGJpdHM6IGFueSBwbGFubmVkIG1vZGUgdGhhdCB3b3VsZCBhZGQgYQpiaXQgYWJzZW50IGZyb20gdGhlIGN1cnJlbnQgbW9kZSBpcyByZWZ1c2VkIGJlZm9yZSB0aGUgc3lzY2FsbC4gVGhlcmUgaXMgbm8KY29tcGVuc2F0aW9uIHBhdGgsIGJlY2F1c2UgcmVzdG9yaW5nIGEgd2Vha2VyIHByaW9yIG1vZGUgaXMgYSBzZWN1cml0eQp3ZWFrZW5pbmcgYW5kIHRoZSBhdXRob3JpdHkgZm9yYmlkcyBpdC4KIiIiCgpmcm9tIF9fZnV0dXJlX18gaW1wb3J0IGFubm90YXRpb25zCgppbXBvcnQgZXJybm8KaW1wb3J0IG9zCmltcG9ydCByZQppbXBvcnQgc3RhdAoKQURBUFRFUl9JRCA9ICJwcm9kdWN0LWZpbGUtbW9kZS1vd25lci1hcHBseS12MSIKTUVDSEFOSVNNX0lEID0gImZpbGUtbW9kZS1vd25lci12MSIKVEFSR0VUX0lEID0gImxpbnV4LXg4Nl82NC1zdXBwb3J0ZWQtdjEiClBBUkFNRVRFUl9LSU5EID0gImZpbGUtbW9kZS1vd25lciIKU0VNQU5USUNfQ09OVFJBQ1RfSUQgPSAiZmlsZS1tb2RlLW93bmVyLWFwcGx5LXNlbWFudGljLXYxIgoKU1VQUE9SVEVEX0tFWVMgPSAoIm1vZGUiLCkKU1VQUE9SVEVEX09QUyA9ICgiZXEiLCAiYml0cy1jbGVhciIpCgpPVVRDT01FUyA9ICgKICAgICJBUFBMSUVEIiwKICAgICJBTFJFQURZX0NPTVBMSUFOVCIsCiAgICAiRFJZX1JVTl9XT1VMRF9BUFBMWSIsCiAgICAiTk9UX0VMSUdJQkxFX0FQUExZX1VOU1VQUE9SVEVEIiwKICAgICJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsCiAgICAiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLAogICAgIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwKKQoKQ09NTUlUX0NPTU1JVFRFRCA9ICJDT01NSVRURUQiCkNPTU1JVF9OT1RfQ09NTUlUVEVEID0gIk5PVF9DT01NSVRURUQiCkNPTU1JVF9OT1RfU1RBUlRFRCA9ICJOT1RfU1RBUlRFRCIKCiMg0KbQtdC70Ywg0LrQsNC20LTQvtCz0L4g0LrQvtC90YLRgNC+0LvRjy4g0KHQvtCy0L/QsNC00LXQvdC40LUg0YEgcGFyYW1ldGVyLmxvY2F0b3Ig0LrQvtC90YLRgNC+0LvQtdC5INC4INGBCiMgbXV0YXRpb24uYWxsb3dlZF9wYXRocyBhdXRob3JpdHkg0L/RgNC+0LLQtdGA0Y/QtdGCIHRlc3RfZmlsZV9tb2RlX293bmVyX2FwcGx5X2FkYXB0ZXIucHkuClRBUkdFVFMgPSB7CiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjMuMS1HUk9VUC1NT0RFIjogIi9ldGMvZ3JvdXAiLAogICAgIkZTVEVDLUxJTlVYLTIwMjItMi4zLjEtUEFTU1dELU1PREUiOiAiL2V0Yy9wYXNzd2QiLAogICAgIkZTVEVDLUxJTlVYLTIwMjItMi4zLjEtU0hBRE9XLUdPLVJXWCI6ICIvZXRjL3NoYWRvdyIsCn0KCkNPTlRST0xfSURfUEFUVEVSTiA9IHIiXig/IS4qW1xyXG5dKVtBLVphLXowLTkuXy1dKyQiCk1PREU0X1BBVFRFUk4gPSByIl5bMC03XXs0fSQiCgoKZGVmIHZhbGlkYXRlX2NvbnRyb2xfaW5wdXQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIGFwcGx5X3N1cHBvcnRlZCk6CiAgICAiIiJGYWlsLWNsb3NlZCB2YWxpZGF0aW9uIG9mIG9uZSBjb250cm9sIHJvdy4gUmFpc2VzIFZhbHVlRXJyb3IuIiIiCiAgICBpZiBub3QgaXNpbnN0YW5jZShjb250cm9sX2lkLCBzdHIpIG9yIG5vdCByZS5mdWxsbWF0Y2goQ09OVFJPTF9JRF9QQVRURVJOLCBjb250cm9sX2lkKToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJpbnZhbGlkIGNvbnRyb2wgaWQiKQogICAgaWYga2V5IG5vdCBpbiBTVVBQT1JURURfS0VZUzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJ1bnN1cHBvcnRlZCBrZXk6ICVyIiAlIChrZXksKSkKICAgIGlmIG9wIG5vdCBpbiBTVVBQT1JURURfT1BTOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoInVuc3VwcG9ydGVkIG9wOiAlciIgJSAob3AsKSkKICAgIGlmIG5vdCBpc2luc3RhbmNlKGV4cGVjdGVkLCBzdHIpIG9yIG5vdCByZS5mdWxsbWF0Y2goTU9ERTRfUEFUVEVSTiwgZXhwZWN0ZWQpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImV4cGVjdGVkIG11c3QgYmUgZXhhY3RseSBmb3VyIG9jdGFsIGRpZ2l0cyIpCiAgICBpZiBvcCA9PSAiYml0cy1jbGVhciIgYW5kIGV4cGVjdGVkID09ICIwMDAwIjoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJiaXRzLWNsZWFyIG1hc2sgMDAwMCBpcyBmb3JiaWRkZW4iKQogICAgaWYgbm90IGlzaW5zdGFuY2UoYXBwbHlfc3VwcG9ydGVkLCBib29sKToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJhcHBseV9zdXBwb3J0ZWQgbXVzdCBiZSBib29sIikKICAgIHJldHVybiBUcnVlCgoKZGVmIF9tb2RlX3RleHQobW9kZTogaW50KSAtPiBzdHI6CiAgICByZXR1cm4gZm9ybWF0KHN0YXQuU19JTU9ERShtb2RlKSwgIjA0byIpCgoKZGVmIF9kZWZhdWx0X3ByaXZpbGVnZV9jaGVjayhmZDogaW50KSAtPiBib29sOgogICAgIiIiUm9vdCwgb3IgdGhlIGNhbGxlciBhbHJlYWR5IG93bnMgdGhlIG9iamVjdC4gQW55dGhpbmcgZWxzZSBpcyByZWZ1c2VkLiIiIgogICAgZXVpZCA9IG9zLmdldGV1aWQoKQogICAgcmV0dXJuIGV1aWQgPT0gMCBvciBvcy5mc3RhdChmZCkuc3RfdWlkID09IGV1aWQKCgpkZWYgX3Jlc3VsdChjb250cm9sX2lkLCB0YXJnZXQsIG91dGNvbWUsICosIGFjdGlvbnMsIGRyeV9ydW4sIG11dGF0aW9uPUZhbHNlLCAqKmV4dHJhKToKICAgIHJlY29yZCA9IHsKICAgICAgICAiYWRhcHRlcl9pZCI6IEFEQVBURVJfSUQsCiAgICAgICAgIm1lY2hhbmlzbV9pZCI6IE1FQ0hBTklTTV9JRCwKICAgICAgICAiY29udHJvbF9pZCI6IGNvbnRyb2xfaWQsCiAgICAgICAgInRhcmdldCI6IHRhcmdldCwKICAgICAgICAib3V0Y29tZSI6IG91dGNvbWUsCiAgICAgICAgInJlYXNvbiI6IE5vbmUsCiAgICAgICAgImN1cnJlbnRfbW9kZSI6IE5vbmUsCiAgICAgICAgInBsYW5uZWRfbW9kZSI6IE5vbmUsCiAgICAgICAgInJlc3VsdGluZ19tb2RlIjogTm9uZSwKICAgICAgICAiYWN0aW9uc19hdHRlbXB0ZWQiOiBsaXN0KGFjdGlvbnMpLAogICAgICAgICJtdXRhdGlvbl9wZXJmb3JtZWQiOiBib29sKG11dGF0aW9uKSwKICAgICAgICAidHJhbnNhY3Rpb25fY29tbWl0IjogX2NvbW1pdF9zdGF0ZShvdXRjb21lLCBkcnlfcnVuLCBtdXRhdGlvbiksCiAgICAgICAgImRyeV9ydW4iOiBib29sKGRyeV9ydW4pLAogICAgfQogICAgcmVjb3JkLnVwZGF0ZShleHRyYSkKICAgIGlmIHJlY29yZFsib3V0Y29tZSJdIG5vdCBpbiBPVVRDT01FUzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJvdXRjb21lIG91dHNpZGUgY2xvc2VkIHZvY2FidWxhcnkiKQogICAgcmV0dXJuIHJlY29yZAoKCmRlZiBfY29tbWl0X3N0YXRlKG91dGNvbWUsIGRyeV9ydW4sIG11dGF0aW9uKToKICAgICIiItCi0LUg0LbQtSDQt9C90LDRh9C10L3QuNGPLCDRh9GC0L4g0YMgY29uZmlnLWxpbmU6IENPTU1JVFRFRCDQsiDQutC+0L3RhtC1INGD0YHQv9C10YjQvdC+0LPQviDQv9GA0L7RhdC+0LTQsC4iIiIKICAgIGlmIG91dGNvbWUgPT0gIkFQUExJRUQiIG9yIChvdXRjb21lID09ICJBTFJFQURZX0NPTVBMSUFOVCIgYW5kIG5vdCBkcnlfcnVuKToKICAgICAgICByZXR1cm4gQ09NTUlUX0NPTU1JVFRFRAogICAgaWYgbXV0YXRpb246CiAgICAgICAgcmV0dXJuIENPTU1JVF9OT1RfQ09NTUlUVEVECiAgICByZXR1cm4gQ09NTUlUX05PVF9TVEFSVEVECgoKZGVmIG91dGNvbWVfcmNfY29udHJpYnV0aW9uKG91dGNvbWUsIGRyeV9ydW49RmFsc2UpOgogICAgIiIi0J/RgNCw0LLQuNC70L4gc3RlcF9yYyBjb25maWctbGluZTogIjAiINC00LvRjyDRg9GB0L/QtdGI0L3Ri9GFINC40YHRhdC+0LTQvtCyLCDQuNC90LDRh9C1ICJub256ZXJvIi4iIiIKICAgIGlmIG91dGNvbWUgaW4gKCJBUFBMSUVEIiwgIkFMUkVBRFlfQ09NUExJQU5UIiwgIk5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRCIpOgogICAgICAgIHJldHVybiAiMCIKICAgIGlmIGRyeV9ydW4gYW5kIG91dGNvbWUgPT0gIkRSWV9SVU5fV09VTERfQVBQTFkiOgogICAgICAgIHJldHVybiAiMCIKICAgIHJldHVybiAibm9uemVybyIKCgpkZWYgY29tcHV0ZV9wbGFubmVkX21vZGUob3A6IHN0ciwgY3VycmVudDogaW50LCBleHBlY3RlZDogc3RyKSAtPiBpbnQ6CiAgICB2YWx1ZSA9IGludChleHBlY3RlZCwgOCkKICAgIGlmIG9wID09ICJlcSI6CiAgICAgICAgcmV0dXJuIHZhbHVlCiAgICByZXR1cm4gc3RhdC5TX0lNT0RFKGN1cnJlbnQpICYgfnZhbHVlCgoKZGVmIGlzX2NvbXBsaWFudChvcDogc3RyLCBjdXJyZW50OiBpbnQsIGV4cGVjdGVkOiBzdHIpIC0+IGJvb2w6CiAgICB2YWx1ZSA9IGludChleHBlY3RlZCwgOCkKICAgIG1vZGUgPSBzdGF0LlNfSU1PREUoY3VycmVudCkKICAgIHJldHVybiBtb2RlID09IHZhbHVlIGlmIG9wID09ICJlcSIgZWxzZSAobW9kZSAmIHZhbHVlKSA9PSAwCgoKZGVmIGV4ZWN1dGVfY29udHJvbCgKICAgIGNvbnRyb2xfaWQsCiAgICBrZXksCiAgICBvcCwKICAgIGV4cGVjdGVkLAogICAgYXBwbHlfc3VwcG9ydGVkLAogICAgKiwKICAgIHRhcmdldD1Ob25lLAogICAgZHJ5X3J1biwKICAgIHByaXZpbGVnZV9jaGVjaz1Ob25lLAogICAgX3ByZV9zeXNjYWxsX2hvb2s9Tm9uZSwKKToKICAgICIiIkFwcGx5IG9uZSBmaWxlLW1vZGUgY29udHJvbC4gTmV2ZXIgZm9sbG93cyBhIHN5bWxpbmssIG5ldmVyIHJlbGF4ZXMuIiIiCiAgICB2YWxpZGF0ZV9jb250cm9sX2lucHV0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQpCiAgICBhY3Rpb25zID0gWyJQMF9FTElHSUJJTElUWSJdCgogICAgZGVmIGRvbmUob3V0Y29tZSwgKipleHRyYSk6CiAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwgdGFyZ2V0LCBvdXRjb21lLCBhY3Rpb25zPWFjdGlvbnMsIGRyeV9ydW49ZHJ5X3J1biwgKipleHRyYSkKCiAgICBpZiBub3QgYXBwbHlfc3VwcG9ydGVkOgogICAgICAgIHJldHVybiBkb25lKCJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiLCByZWFzb249ImFwcGx5LXVuc3VwcG9ydGVkIikKCiAgICBpZiB0YXJnZXQgaXMgTm9uZToKICAgICAgICB0YXJnZXQgPSBUQVJHRVRTLmdldChjb250cm9sX2lkKQogICAgICAgIGlmIHRhcmdldCBpcyBOb25lOgogICAgICAgICAgICByZXR1cm4gZG9uZSgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLCByZWFzb249InRhcmdldDp1bm1hcHBlZC1jb250cm9sIikKCiAgICBhY3Rpb25zLmFwcGVuZCgiUDFfVEFSR0VUX09QRU4iKQoKICAgIHRyeToKICAgICAgICBmZCA9IG9zLm9wZW4odGFyZ2V0LCBvcy5PX1JET05MWSB8IG9zLk9fTk9GT0xMT1cgfCBvcy5PX0NMT0VYRUMpCiAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgaWYgZXhjLmVycm5vIGluIChlcnJuby5FTE9PUCwgZXJybm8uRU1MSU5LKToKICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwKICAgICAgICAgICAgICAgICAgICAgICAgcmVhc29uPSJzeW1saW5rIikKICAgICAgICBpZiBleGMuZXJybm8gPT0gZXJybm8uRU5PRU5UOgogICAgICAgICAgICByZXR1cm4gZG9uZSgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLAogICAgICAgICAgICAgICAgICAgICAgICByZWFzb249ImFic2VudCIpCiAgICAgICAgcmV0dXJuIGRvbmUoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwKICAgICAgICAgICAgICAgICAgICByZWFzb249Im9wZW46JXMiICUgZXJybm8uZXJyb3Jjb2RlLmdldChleGMuZXJybm8sIGV4Yy5lcnJubykpCgogICAgdHJ5OgogICAgICAgIHN0ID0gb3MuZnN0YXQoZmQpCiAgICAgICAgaWYgbm90IHN0YXQuU19JU1JFRyhzdC5zdF9tb2RlKToKICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwKICAgICAgICAgICAgICAgICAgICAgICAgcmVhc29uPSJub3QtcmVndWxhciIpCiAgICAgICAgaWYgc3Quc3RfbmxpbmsgIT0gMToKICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwKICAgICAgICAgICAgICAgICAgICAgICAgcmVhc29uPSJzdF9ubGluayIpCgogICAgICAgIGN1cnJlbnQgPSBzdGF0LlNfSU1PREUoc3Quc3RfbW9kZSkKICAgICAgICBpZiBpc19jb21wbGlhbnQob3AsIGN1cnJlbnQsIGV4cGVjdGVkKToKICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkFMUkVBRFlfQ09NUExJQU5UIiwKICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudF9tb2RlPV9tb2RlX3RleHQoY3VycmVudCksCiAgICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdGluZ19tb2RlPV9tb2RlX3RleHQoY3VycmVudCkpCgogICAgICAgIHBsYW5uZWQgPSBjb21wdXRlX3BsYW5uZWRfbW9kZShvcCwgY3VycmVudCwgZXhwZWN0ZWQpCiAgICAgICAgaWYgcGxhbm5lZCAmIH5jdXJyZW50OgogICAgICAgICAgICByZXR1cm4gZG9uZSgiQUJPUlRFRF9QUkVDT05ESVRJT05fQ09ORkxJQ1QiLAogICAgICAgICAgICAgICAgICAgICAgICByZWFzb249Im1vZGUtcmVsYXhhdGlvbi1mb3JiaWRkZW4iLAogICAgICAgICAgICAgICAgICAgICAgICBjdXJyZW50X21vZGU9X21vZGVfdGV4dChjdXJyZW50KSwKICAgICAgICAgICAgICAgICAgICAgICAgcGxhbm5lZF9tb2RlPV9tb2RlX3RleHQocGxhbm5lZCkpCgogICAgICAgIGlmIGRyeV9ydW46CiAgICAgICAgICAgIHJldHVybiBkb25lKCJEUllfUlVOX1dPVUxEX0FQUExZIiwKICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudF9tb2RlPV9tb2RlX3RleHQoY3VycmVudCksCiAgICAgICAgICAgICAgICAgICAgICAgIHBsYW5uZWRfbW9kZT1fbW9kZV90ZXh0KHBsYW5uZWQpKQoKICAgICAgICBhY3Rpb25zLmFwcGVuZCgiUDNfUFJJVklMRUdFIikKICAgICAgICBjaGVjayA9IHByaXZpbGVnZV9jaGVjayBpZiBwcml2aWxlZ2VfY2hlY2sgaXMgbm90IE5vbmUgZWxzZSAobGFtYmRhOiBfZGVmYXVsdF9wcml2aWxlZ2VfY2hlY2soZmQpKQogICAgICAgIGlmIG5vdCBjaGVjaygpOgogICAgICAgICAgICByZXR1cm4gZG9uZSgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLAogICAgICAgICAgICAgICAgICAgICAgICByZWFzb249InByaXZpbGVnZSIsCiAgICAgICAgICAgICAgICAgICAgICAgIGN1cnJlbnRfbW9kZT1fbW9kZV90ZXh0KGN1cnJlbnQpLAogICAgICAgICAgICAgICAgICAgICAgICBwbGFubmVkX21vZGU9X21vZGVfdGV4dChwbGFubmVkKSkKCiAgICAgICAgaWYgX3ByZV9zeXNjYWxsX2hvb2sgaXMgbm90IE5vbmU6CiAgICAgICAgICAgIF9wcmVfc3lzY2FsbF9ob29rKCkKCiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlBIQVNFMV9NT0RFIikKICAgICAgICBkcmlmdCA9IF9yZXZhbGlkYXRlKGZkLCB0YXJnZXQsIHN0LCBvcCwgZXhwZWN0ZWQsIHBsYW5uZWQpCiAgICAgICAgaWYgZHJpZnQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsCiAgICAgICAgICAgICAgICAgICAgICAgIHJlYXNvbj1kcmlmdCwKICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudF9tb2RlPV9tb2RlX3RleHQoY3VycmVudCksCiAgICAgICAgICAgICAgICAgICAgICAgIHBsYW5uZWRfbW9kZT1fbW9kZV90ZXh0KHBsYW5uZWQpKQoKICAgICAgICBvcy5mY2htb2QoZmQsIHBsYW5uZWQpCgogICAgICAgIGFjdGlvbnMuYXBwZW5kKCJGSU5BTF9QT1NUQ0hFQ0siKQogICAgICAgIHBvc3QgPSBvcy5mc3RhdChmZCkKICAgICAgICByZXN1bHRpbmcgPSBzdGF0LlNfSU1PREUocG9zdC5zdF9tb2RlKQogICAgICAgIGlmICgKICAgICAgICAgICAgcmVzdWx0aW5nICE9IHBsYW5uZWQKICAgICAgICAgICAgb3IgcG9zdC5zdF91aWQgIT0gc3Quc3RfdWlkCiAgICAgICAgICAgIG9yIHBvc3Quc3RfZ2lkICE9IHN0LnN0X2dpZAogICAgICAgICAgICBvciBwb3N0LnN0X2lubyAhPSBzdC5zdF9pbm8KICAgICAgICAgICAgb3IgcG9zdC5zdF9kZXYgIT0gc3Quc3RfZGV2CiAgICAgICAgICAgIG9yIHBvc3Quc3Rfc2l6ZSAhPSBzdC5zdF9zaXplCiAgICAgICAgKToKICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwKICAgICAgICAgICAgICAgICAgICAgICAgcmVhc29uPSJwb3N0LXN0YXRlLW1pc21hdGNoIiwgbXV0YXRpb249VHJ1ZSwKICAgICAgICAgICAgICAgICAgICAgICAgY3VycmVudF9tb2RlPV9tb2RlX3RleHQoY3VycmVudCksCiAgICAgICAgICAgICAgICAgICAgICAgIHBsYW5uZWRfbW9kZT1fbW9kZV90ZXh0KHBsYW5uZWQpLAogICAgICAgICAgICAgICAgICAgICAgICByZXN1bHRpbmdfbW9kZT1fbW9kZV90ZXh0KHJlc3VsdGluZykpCgogICAgICAgIHJldHVybiBkb25lKCJBUFBMSUVEIiwgbXV0YXRpb249VHJ1ZSwKICAgICAgICAgICAgICAgICAgICBjdXJyZW50X21vZGU9X21vZGVfdGV4dChjdXJyZW50KSwKICAgICAgICAgICAgICAgICAgICBwbGFubmVkX21vZGU9X21vZGVfdGV4dChwbGFubmVkKSwKICAgICAgICAgICAgICAgICAgICByZXN1bHRpbmdfbW9kZT1fbW9kZV90ZXh0KHJlc3VsdGluZykpCiAgICBmaW5hbGx5OgogICAgICAgIG9zLmNsb3NlKGZkKQoKCmRlZiBfcmV2YWxpZGF0ZShmZCwgdGFyZ2V0LCBvYnNlcnZlZCwgb3AsIGV4cGVjdGVkLCBwbGFubmVkKToKICAgICIiIlJldHVybiBhIGRyaWZ0IHJlYXNvbiwgb3IgTm9uZSB3aGVuIHRoZSBvYmplY3QgaXMgc3RpbGwgdGhlIHBsYW5uZWQgb25lLiIiIgogICAgdHJ5OgogICAgICAgIHBhdGhfc3QgPSBvcy5sc3RhdCh0YXJnZXQpCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICByZXR1cm4gImlkZW50aXR5LWRyaWZ0IgogICAgaWYgKHBhdGhfc3Quc3RfZGV2LCBwYXRoX3N0LnN0X2lubykgIT0gKG9ic2VydmVkLnN0X2Rldiwgb2JzZXJ2ZWQuc3RfaW5vKToKICAgICAgICByZXR1cm4gImlkZW50aXR5LWRyaWZ0IgogICAgbm93ID0gb3MuZnN0YXQoZmQpCiAgICBpZiBub3Qgc3RhdC5TX0lTUkVHKG5vdy5zdF9tb2RlKToKICAgICAgICByZXR1cm4gIm5vdC1yZWd1bGFyIgogICAgaWYgbm93LnN0X25saW5rICE9IDE6CiAgICAgICAgcmV0dXJuICJzdF9ubGluayIKICAgIGlmIChub3cuc3RfdWlkLCBub3cuc3RfZ2lkKSAhPSAob2JzZXJ2ZWQuc3RfdWlkLCBvYnNlcnZlZC5zdF9naWQpOgogICAgICAgIHJldHVybiAib3duZXJzaGlwLWRyaWZ0IgogICAgaWYgc3RhdC5TX0lNT0RFKG5vdy5zdF9tb2RlKSAhPSBzdGF0LlNfSU1PREUob2JzZXJ2ZWQuc3RfbW9kZSk6CiAgICAgICAgcmV0dXJuICJtb2RlLWRyaWZ0IgogICAgaWYgaXNfY29tcGxpYW50KG9wLCBzdGF0LlNfSU1PREUobm93LnN0X21vZGUpLCBleHBlY3RlZCk6CiAgICAgICAgcmV0dXJuICJtb2RlLWRyaWZ0IgogICAgaWYgcGxhbm5lZCAmIH5zdGF0LlNfSU1PREUobm93LnN0X21vZGUpOgogICAgICAgIHJldHVybiAibW9kZS1yZWxheGF0aW9uLWZvcmJpZGRlbiIKICAgIHJldHVybiBOb25lCgoKZGVmIGNvbnRyb2xfcmVzdWx0X3RvX3JlcG9ydChyZXN1bHQsIHN0YXJ0ZWRfYXQsIGZpbmlzaGVkX2F0KToKICAgIHJlcG9ydCA9IHsKICAgICAgICAiYWRhcHRlcl9pZCI6IHJlc3VsdFsiYWRhcHRlcl9pZCJdLAogICAgICAgICJtZWNoYW5pc21faWQiOiByZXN1bHRbIm1lY2hhbmlzbV9pZCJdLAogICAgICAgICJjb250cm9sX2lkIjogcmVzdWx0WyJjb250cm9sX2lkIl0sCiAgICAgICAgInRhcmdldCI6IHJlc3VsdFsidGFyZ2V0Il0sCiAgICAgICAgIm91dGNvbWUiOiByZXN1bHRbIm91dGNvbWUiXSwKICAgICAgICAicmVhc29uIjogcmVzdWx0WyJyZWFzb24iXSwKICAgICAgICAiY3VycmVudF9tb2RlIjogcmVzdWx0WyJjdXJyZW50X21vZGUiXSwKICAgICAgICAicGxhbm5lZF9tb2RlIjogcmVzdWx0WyJwbGFubmVkX21vZGUiXSwKICAgICAgICAicmVzdWx0aW5nX21vZGUiOiByZXN1bHRbInJlc3VsdGluZ19tb2RlIl0sCiAgICAgICAgInN0YXJ0ZWRfYXQiOiBzdGFydGVkX2F0LAogICAgICAgICJmaW5pc2hlZF9hdCI6IGZpbmlzaGVkX2F0LAogICAgICAgICJhY3Rpb25zX2F0dGVtcHRlZCI6IGxpc3QocmVzdWx0WyJhY3Rpb25zX2F0dGVtcHRlZCJdKSwKICAgICAgICAic3RlcF9yYyI6IG91dGNvbWVfcmNfY29udHJpYnV0aW9uKHJlc3VsdFsib3V0Y29tZSJdLCByZXN1bHRbImRyeV9ydW4iXSksCiAgICAgICAgIm11dGF0aW9uX3BlcmZvcm1lZCI6IHJlc3VsdFsibXV0YXRpb25fcGVyZm9ybWVkIl0sCiAgICAgICAgInRyYW5zYWN0aW9uX2NvbW1pdCI6IHJlc3VsdFsidHJhbnNhY3Rpb25fY29tbWl0Il0sCiAgICB9CiAgICByZXR1cm4gcmVwb3J0Cg=="},"kernel-cmdline":{"adapter_id":"product-kernel-cmdline-grub-apply-v1","apply_kind":"kernel-cmdline-grub-v1","implementation_sha256":"e594f5aaf90fc8964e66d732a8bee36075ce467e22b6b702a02534791a701ef5","mechanism_id":"kernel-cmdline-grub-v1","source_b64":"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiJwcm9kdWN0LWtlcm5lbC1jbWRsaW5lLWdydWItYXBwbHktdjEuCgpBUFBMWSBhZGFwdGVyIGZvciBtZWNoYW5pc20gYGtlcm5lbC1jbWRsaW5lLWdydWItdjFgICgyLjQuMy0yLjQuNywgMi41LjEsIDIuNS4zLCAyLjUuOSkuCgpQVVJQT1NFPURFRkVOU0lWRV9DT01QTElBTkNFX1ZBTElEQVRJT04KQXV0aG9yaXR5OiBwcm9kdWN0L2NvbnRyYWN0cy9tZWNoYW5pc20ta2VybmVsLWNtZGxpbmUtZ3J1Yi12MS5qc29uCgrQoNC10YjQtdC90LjRjyDRh9C10LvQvtCy0LXQutCwIDI0LjA5LjIwMjY6CgoqINCf0LDRgNCw0LzQtdGC0YAg0LTQvtCx0LDQstC70Y/QtdGC0YHRjyDQsiBgR1JVQl9DTURMSU5FX0xJTlVYYCDRhNCw0LnQu9CwCiAgYC9ldGMvZGVmYXVsdC9ncnViLmQvenotc2VjdXJlbGludXgtcG9saWN5LmNmZ2A7INC40LzRjyBgenotYCDigJQg0YfRgtC+0LHRiyDRhNCw0LnQuyDRh9C40YLQsNC70YHRjwogINC/0L7RgdC70LUgYGluaXQtc2VsZWN0LmNmZ2Ag0LggYGtkdW1wLXRvb2xzLmNmZ2Ag0Y3RgtCw0LvQvtC90L3Ri9GFINGB0YDQtdC0LiDQl9Cw0YLQtdC8IGB1cGRhdGUtZ3J1YmAuCiAg0J3QvtCy0L7QtSDQt9C90LDRh9C10L3QuNC1INCy0YHRgtGD0L/QsNC10YIg0LIg0YHQuNC70YMg0L/QvtGB0LvQtSDQv9C10YDQtdC30LDQs9GA0YPQt9C60Lg7IENIRUNLIChgL3Byb2MvY21kbGluZWApCiAg0LTQviDQvdC10ZEg0L7RgdGC0LDRkdGC0YHRjyBGQUlMLgoqINCQ0LLRgtC+0LzQsNGC0LjRh9C10YHQutC4OiBgaW5pdF9vbl9hbGxvYz0xYCwgYHNsYWJfbm9tZXJnZWAsIGByYW5kb21pemVfa3N0YWNrX29mZnNldD0xYCwKICBgdnN5c2NhbGw9bm9uZWAsIGBpb21tdT1mb3JjZWAsIGBpb21tdS5zdHJpY3Q9MWAsIGBpb21tdS5wYXNzdGhyb3VnaD0wYCAoYEFVVE9gOwogIGlvbW11IOKAlCDRgNC10YjQtdC90LjQtSDQv9C+0LvRjNC30L7QstCw0YLQtdC70Y8gMjYuMDkuMjAyNikuCiogYG1pdGlnYXRpb25zPWF1dG8sbm9zbXRgLCBgdHN4PW9mZmAsIGBkZWJ1Z2ZzPW9mZmAg0L3QtSDQv9C40YjRg9GC0YHRjzog0LjRgdGF0L7QtCBBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCDRgQogIGBvcGVyYXRvcl9kZWNpc2lvbmAg0LrQu9Cw0YHRgdCwIEJPT1RfUEFSQU1FVEVSX0FETUlOX0RFQ0lTSU9OIOKAlCDQsdC70L7QuiDCq9GC0YDQtdCx0YPQtdGC0YHRjwogINGA0LXRiNC10L3QuNC1INCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGA0LDCuywg0LrQsNC6INGDIDIuNi42IChgQURNSU5gKS4KKiDQlNGA0YPQs9C+0LUg0LfQvdCw0YfQtdC90LjQtSDRgtC+0LPQviDQttC1INC/0LDRgNCw0LzQtdGC0YDQsCDQsiBgL2V0Yy9kZWZhdWx0L2dydWJgINC40LvQuCDQtNGA0YPQs9C+0LwKICBgL2V0Yy9kZWZhdWx0L2dydWIuZC8qLmNmZ2Ag4oCUINC+0YLQutCw0Lcg0LHQtdC3INC30LDQv9C40YHQuCAoYGdydWI6Zm9yZWlnbi1jb25mbGljdGApOyDRhNCw0LnQu9GLCiAg0LDQtNC80LjQvdC40YHRgtGA0LDRgtC+0YDQsCDQvdC1INC/0YDQsNCy0Y/RgtGB0Y8uINCi0L7RgiDQttC1INGC0L7QutC10L0g0YLQsNC8IOKAlCDQsiDRhNCw0LnQuyDQvdC1INC00YPQsdC70LjRgNGD0LXRgtGB0Y8uCgrQn9C+0YDRj9C00L7Qujog0L3QsNCx0LvRjtC00LXQvdC40LUg4oaSINC/0LvQsNC9IOKGkiDQt9Cw0L/QuNGB0Ywg0YTQsNC50LvQsCAodG1wICsgcmVuYW1lLCByb290IDA2NDQpIOKGkgpgdXBkYXRlLWdydWJgIOKGkiDQv9GA0L7QstC10YDQutCwLCDRh9GC0L4g0YLQvtC60LXQvSDQtdGB0YLRjCDQsiDQutCw0LbQtNC+0Lkg0YHRgtGA0L7QutC1IGBsaW51eCDigKZ2bWxpbnV64oCmYCDRhNCw0LnQu9CwCmAvYm9vdC9ncnViL2dydWIuY2ZnYCAo0LIgZ3J1YiAyLjEyIGBHUlVCX0NNRExJTkVfTElOVVhgINCy0YXQvtC00LjRgiDQuCDQsiDQvtCx0YvRh9C90YPRjiwg0Lgg0LIKcmVjb3Zlcnkt0LfQsNC/0LjRgdGMIGAxMF9saW51eGApLiDQntGI0LjQsdC60LAgYHVwZGF0ZS1ncnViYCDQuNC70Lgg0L/RgNC+0LLQtdGA0LrQuCDigJQg0L/RgNC10LbQvdC10LUg0YHQvtC00LXRgNC20LjQvNC+0LUK0YTQsNC50LvQsCAo0LjQu9C4INC10LPQviDQvtGC0YHRg9GC0YHRgtCy0LjQtSkg0LLQvtGB0YHRgtCw0L3QsNCy0LvQuNCy0LDQtdGC0YHRjyDQuCBgdXBkYXRlLWdydWJgINC30LDQv9GD0YHQutCw0LXRgtGB0Y8g0YHQvdC+0LLQsC4K0J7RgtC60LDRgiDQsNC00LzQuNC90LjRgdGC0YDQsNGC0L7RgNC+0Lw6INGD0LTQsNC70LjRgtGMINGE0LDQudC7INC4INCy0YvQv9C+0LvQvdC40YLRjCBgdXBkYXRlLWdydWJgLgoiIiIKCmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnMKCmltcG9ydCBvcwppbXBvcnQgcmUKaW1wb3J0IHN0YXQKaW1wb3J0IHN1YnByb2Nlc3MKCkFEQVBURVJfSUQgPSAicHJvZHVjdC1rZXJuZWwtY21kbGluZS1ncnViLWFwcGx5LXYxIgpNRUNIQU5JU01fSUQgPSAia2VybmVsLWNtZGxpbmUtZ3J1Yi12MSIKVEFSR0VUX0lEID0gImxpbnV4LXg4Nl82NC1zdXBwb3J0ZWQtdjEiClBBUkFNRVRFUl9LSU5EID0gImtlcm5lbC1jbWRsaW5lIgoKRFJPUElOID0gIi9ldGMvZGVmYXVsdC9ncnViLmQvenotc2VjdXJlbGludXgtcG9saWN5LmNmZyIKR1JVQl9ERUZBVUxUID0gIi9ldGMvZGVmYXVsdC9ncnViIgpHUlVCX0QgPSAiL2V0Yy9kZWZhdWx0L2dydWIuZCIKVVBEQVRFX0dSVUIgPSAiL3Vzci9zYmluL3VwZGF0ZS1ncnViIgpHUlVCX0NGRyA9ICIvYm9vdC9ncnViL2dydWIuY2ZnIgpQUk9DX0NNRExJTkUgPSAiL3Byb2MvY21kbGluZSIKVVBEQVRFX0dSVUJfVElNRU9VVCA9IDYwMAoKRFJPUElOX0hFQURFUiA9ICgKICAgICIjIE1hbmFnZWQgYnkgU2VjdXJlTGludXgtUG9saWN5OiBGU1RFQyAyMDIyIGtlcm5lbCBib290IHBhcmFtZXRlcnMuXG4iCiAgICAiIyBSZXZlcnQ6IHJlbW92ZSB0aGlzIGZpbGUgYW5kIHJ1biB1cGRhdGUtZ3J1Yi5cbiIKKQpEUk9QSU5fTElORV9SRSA9IHJlLmNvbXBpbGUocideR1JVQl9DTURMSU5FX0xJTlVYPSJcJEdSVUJfQ01ETElORV9MSU5VWCgoPzogW0EtWmEtejAtOV8uLD0tXSspKikiJCcpClRPS0VOX1JFID0gcmUuY29tcGlsZShyIl5bQS1aYS16MC05Xy4tXSsoPzo9W0EtWmEtejAtOV8uLC1dKyk/JCIpCgojIChrZXksIG9wLCBleHBlY3RlZCkg0LrQvtC90YLRgNC+0LvQtdC5INC80LXRhdCw0L3QuNC30LzQsC4gZXhwZWN0ZWQg0YMgYHByZXNlbnRgIOKAlCBib29sLCDQutCw0Log0LIgY29udHJvbC15YW1sLgpBVVRPID0gewogICAgIkZTVEVDLUxJTlVYLTIwMjItMi40LjMtSU5JVC1PTi1BTExPQyI6ICgiaW5pdF9vbl9hbGxvYyIsICJlcSIsICIxIiksCiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjQuNC1TTEFCLU5PTUVSR0UiOiAoInNsYWJfbm9tZXJnZSIsICJwcmVzZW50IiwgVHJ1ZSksCiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjQuNi1SQU5ET01JWkUtS1NUQUNLLU9GRlNFVCI6ICgicmFuZG9taXplX2tzdGFja19vZmZzZXQiLCAiZXEiLCAiMSIpLAogICAgIkZTVEVDLUxJTlVYLTIwMjItMi41LjEtVlNZU0NBTEwiOiAoInZzeXNjYWxsIiwgImVxIiwgIm5vbmUiKSwKICAgICMg0KDQtdGI0LXQvdC40LUg0L/QvtC70YzQt9C+0LLQsNGC0LXQu9GPIDI2LjA5LjIwMjY6INGC0YDQuCDQv9Cw0YDQsNC80LXRgtGA0LAgMi40LjUg0L/QuNGI0YPRgtGB0Y8g0LDQstGC0L7QvNCw0YLQuNGH0LXRgdC60LguCiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjQuNS1JT01NVS1GT1JDRSI6ICgiaW9tbXUiLCAiZXEiLCAiZm9yY2UiKSwKICAgICJGU1RFQy1MSU5VWC0yMDIyLTIuNC41LUlPTU1VLVBBU1NUSFJPVUdIIjogKCJpb21tdS5wYXNzdGhyb3VnaCIsICJlcSIsICIwIiksCiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjQuNS1JT01NVS1TVFJJQ1QiOiAoImlvbW11LnN0cmljdCIsICJlcSIsICIxIiksCn0KQURNSU4gPSB7CiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjQuNy1NSVRJR0FUSU9OUyI6ICgoIm1pdGlnYXRpb25zIiwgImVxIiwgImF1dG8sbm9zbXQiKSwKICAgICAgICAibm9zbXQg0L7RgtC60LvRjtGH0LDQtdGCIFNNVDog0YfQuNGB0LvQviDQu9C+0LPQuNGH0LXRgdC60LjRhSBDUFUg0YPQvNC10L3RjNGI0LDQtdGC0YHRjyDQstC00LLQvtC1IiksCiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjUuMy1ERUJVR0ZTIjogKCgiZGVidWdmcyIsICJvbmUtb2YiLCAib2ZmfG5vLW1vdW50IiksCiAgICAgICAgItC/0LXRgNC10YHRgtCw0Y7RgiDRgNCw0LHQvtGC0LDRgtGMINC40L3RgdGC0YDRg9C80LXQvdGC0YssINC60L7RgtC+0YDRi9C8INC90YPQttC10L0gZGVidWdmcyIpLAogICAgIkZTVEVDLUxJTlVYLTIwMjItMi41LjktVFNYIjogKCgidHN4IiwgImVxIiwgIm9mZiIpLAogICAgICAgICLQvdCwINGH0LDRgdGC0Lgg0L/RgNC+0YbQtdGB0YHQvtGA0L7QsiDRgdC90LjQttCw0LXRgtGB0Y8g0L/RgNC+0LjQt9Cy0L7QtNC40YLQtdC70YzQvdC+0YHRgtGMIiksCn0KCk9VVENPTUVTID0gKAogICAgIkFQUExJRUQiLAogICAgIlBFTkRJTkdfUkVCT09UIiwKICAgICJBTFJFQURZX0NPTVBMSUFOVCIsCiAgICAiRFJZX1JVTl9XT1VMRF9BUFBMWSIsCiAgICAiTk9UX0VMSUdJQkxFX0FQUExZX1VOU1VQUE9SVEVEIiwKICAgICJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsCiAgICAiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLAogICAgIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwKICAgICJGQUlMRURfQ09NUEVOU0FUSU9OIiwKKQpDT01NSVRfQ09NTUlUVEVEID0gIkNPTU1JVFRFRCIKQ09NTUlUX05PVF9DT01NSVRURUQgPSAiTk9UX0NPTU1JVFRFRCIKQ09NTUlUX05PVF9TVEFSVEVEID0gIk5PVF9TVEFSVEVEIgoKQ09OVFJPTF9JRF9QQVRURVJOID0gciJeKD8hLipbXHJcbl0pW0EtWmEtejAtOS5fLV0rJCIKCgpjbGFzcyBfUmVmdXNlZChFeGNlcHRpb24pOgogICAgZGVmIF9faW5pdF9fKHNlbGYsIG91dGNvbWUsIHJlYXNvbik6CiAgICAgICAgc3VwZXIoKS5fX2luaXRfXyhyZWFzb24pCiAgICAgICAgc2VsZi5vdXRjb21lID0gb3V0Y29tZQogICAgICAgIHNlbGYucmVhc29uID0gcmVhc29uCgoKZGVmIHZhbGlkYXRlX2NvbnRyb2xfaW5wdXQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIGFwcGx5X3N1cHBvcnRlZCk6CiAgICAiIiJGYWlsLWNsb3NlZCB2YWxpZGF0aW9uIG9mIG9uZSBjb250cm9sIHJvdy4gUmFpc2VzIFZhbHVlRXJyb3IuIiIiCiAgICBpZiBub3QgaXNpbnN0YW5jZShjb250cm9sX2lkLCBzdHIpIG9yIG5vdCByZS5mdWxsbWF0Y2goQ09OVFJPTF9JRF9QQVRURVJOLCBjb250cm9sX2lkKToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJpbnZhbGlkIGNvbnRyb2wgaWQiKQogICAgaWYgbm90IGlzaW5zdGFuY2Uoa2V5LCBzdHIpIG9yIG5vdCBpc2luc3RhbmNlKG9wLCBzdHIpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImtleSBhbmQgb3AgbXVzdCBiZSBzdHJpbmdzIikKICAgIGlmIG5vdCBpc2luc3RhbmNlKGV4cGVjdGVkLCAoc3RyLCBib29sKSk6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigiZXhwZWN0ZWQgbXVzdCBiZSBhIHN0cmluZyBvciBib29sIikKICAgIGlmIG5vdCBpc2luc3RhbmNlKGFwcGx5X3N1cHBvcnRlZCwgYm9vbCk6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigiYXBwbHlfc3VwcG9ydGVkIG11c3QgYmUgYm9vbCIpCiAgICByZXR1cm4gVHJ1ZQoKCmRlZiBkZXNpcmVkX3Rva2VuKGtleSwgb3AsIGV4cGVjdGVkKToKICAgICIiItCi0L7QutC10L0sINC60L7RgtC+0YDRi9C5INC/0LjRiNC10YIg0LzQtdGF0LDQvdC40LfQvDogYGtleT12YWx1ZWAsIGBrZXlgINC00LvRjyBwcmVzZW50LCDQv9C10YDQstGL0Lkg0YfQu9C10L0gb25lLW9mLiIiIgogICAgaWYgb3AgPT0gInByZXNlbnQiOgogICAgICAgIHJldHVybiBrZXkKICAgIGlmIG9wID09ICJvbmUtb2YiOgogICAgICAgIHJldHVybiAiJXM9JXMiICUgKGtleSwgZXhwZWN0ZWQuc3BsaXQoInwiKVswXSkKICAgIHJldHVybiAiJXM9JXMiICUgKGtleSwgZXhwZWN0ZWQpCgoKZGVmIGV2YWx1YXRlKHRva2Vucywga2V5LCBvcCwgZXhwZWN0ZWQpOgogICAgIiIi0KHQtdC80LDQvdGC0LjQutCwIENIRUNLIGtlcm5lbC1jbWRsaW5lLWNoZWNrLXNlbWFudGljLXYyINC00LvRjyDQvtC00L3QvtCz0L4g0LrQu9GO0YfQsC4KCiAgICDQktC+0LfQstGA0LDRidCw0LXRgiAoY29tcGxpYW50LCBjdXJyZW50KTogY3VycmVudCDigJQg0LfQvdCw0YfQtdC90LjQtSDQsdC10LcgYGtleT1gLCBgdHJ1ZWAvYGZhbHNlYAogICAg0LTQu9GPIHByZXNlbnQsIGA8YWJzZW50PmAsINC70LjQsdC+IGBjb25mbGljdGAgKNC60L7QvdGE0LvQuNC60YLRg9GO0YnQuNC1INC/0L7QstGC0L7RgNGLID0gRVJST1Ig0YMgQ0hFQ0spLgogICAgIiIiCiAgICBiYXJlID0ga2V5IGluIHRva2VucwogICAgdmFsdWVzID0ge3RbbGVuKGtleSkgKyAxOl0gZm9yIHQgaW4gdG9rZW5zIGlmIHQuc3RhcnRzd2l0aChrZXkgKyAiPSIpfQogICAgaWYgb3AgPT0gInByZXNlbnQiOgogICAgICAgIGlmIHZhbHVlczoKICAgICAgICAgICAgcmV0dXJuIEZhbHNlLCAiY29uZmxpY3QiCiAgICAgICAgcmV0dXJuIGJhcmUsICJ0cnVlIiBpZiBiYXJlIGVsc2UgImZhbHNlIgogICAgaWYgYmFyZSBvciBsZW4odmFsdWVzKSA+IDE6CiAgICAgICAgcmV0dXJuIEZhbHNlLCAiY29uZmxpY3QiCiAgICBpZiBub3QgdmFsdWVzOgogICAgICAgIHJldHVybiBGYWxzZSwgIjxhYnNlbnQ+IgogICAgdmFsdWUgPSBuZXh0KGl0ZXIodmFsdWVzKSkKICAgIG1lbWJlcnMgPSBleHBlY3RlZC5zcGxpdCgifCIpIGlmIG9wID09ICJvbmUtb2YiIGVsc2UgW2V4cGVjdGVkXQogICAgcmV0dXJuIHZhbHVlIGluIG1lbWJlcnMsIHZhbHVlCgoKZGVmIF9wKHJvb3QsIHBhdGgpOgogICAgcmV0dXJuIHBhdGggaWYgcm9vdCBpcyBOb25lIGVsc2Ugb3MucGF0aC5qb2luKHJvb3QsIHBhdGgubHN0cmlwKCIvIikpCgoKZGVmIF9yZWFkX2NtZGxpbmUocm9vdCk6CiAgICB0cnk6CiAgICAgICAgd2l0aCBvcGVuKF9wKHJvb3QsIFBST0NfQ01ETElORSksICJyYiIpIGFzIHN0cmVhbToKICAgICAgICAgICAgcmF3ID0gc3RyZWFtLnJlYWQoKQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwgImNtZGxpbmU6cmVhZC1mYWlsZWQiKQogICAgaWYgYiJceDAwIiBpbiByYXc6CiAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwgImNtZGxpbmU6aW52YWxpZC1ieXRlcyIpCiAgICByZXR1cm4gcmF3LmRlY29kZSgiYXNjaWkiLCAicmVwbGFjZSIpLnNwbGl0KCkKCgpkZWYgX3JlYWRfZHJvcGluKHJvb3QpOgogICAgIiIi0KLQvtC60LXQvdGLINC90LDRiNC10LPQviDRhNCw0LnQu9CwINC40LvQuCBOb25lLCDQtdGB0LvQuCDRhNCw0LnQu9CwINC90LXRgi4g0KfRg9C20L7QtSDRgdC+0LTQtdGA0LbQuNC80L7QtSDigJQg0L7RgtC60LDQty4iIiIKICAgIHBhdGggPSBfcChyb290LCBEUk9QSU4pCiAgICB0cnk6CiAgICAgICAgc3QgPSBvcy5sc3RhdChwYXRoKQogICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgIHJldHVybiBOb25lCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICByYWlzZSBfUmVmdXNlZCgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLCAiZHJvcGluOmxzdGF0LWZhaWxlZCIpCiAgICBpZiBub3Qgc3RhdC5TX0lTUkVHKHN0LnN0X21vZGUpOgogICAgICAgIHJhaXNlIF9SZWZ1c2VkKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsICJkcm9waW46bm90LXJlZ3VsYXIiKQogICAgaWYgcm9vdCBpcyBOb25lIGFuZCBzdC5zdF91aWQgIT0gMDoKICAgICAgICByYWlzZSBfUmVmdXNlZCgiQUJPUlRFRF9QUkVDT05ESVRJT05fQ09ORkxJQ1QiLCAiZHJvcGluOm93bmVyIikKICAgIGlmIHN0YXQuU19JTU9ERShzdC5zdF9tb2RlKSAmIDBvMDIyOgogICAgICAgIHJhaXNlIF9SZWZ1c2VkKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsICJkcm9waW46d3JpdGFibGUiKQogICAgd2l0aCBvcGVuKHBhdGgsICJyIiwgZW5jb2Rpbmc9ImFzY2lpIiwgZXJyb3JzPSJyZXBsYWNlIikgYXMgc3RyZWFtOgogICAgICAgIHRleHQgPSBzdHJlYW0ucmVhZCgpCiAgICBpZiBub3QgdGV4dC5zdGFydHN3aXRoKERST1BJTl9IRUFERVIpOgogICAgICAgIHJhaXNlIF9SZWZ1c2VkKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsICJkcm9waW46Zm9yZWlnbi1jb250ZW50IikKICAgIGJvZHkgPSB0ZXh0W2xlbihEUk9QSU5fSEVBREVSKTpdCiAgICBpZiBub3QgYm9keS5lbmRzd2l0aCgiXG4iKSBvciBib2R5LmNvdW50KCJcbiIpICE9IDE6CiAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwgImRyb3Bpbjpmb3JlaWduLWNvbnRlbnQiKQogICAgbWF0Y2ggPSBEUk9QSU5fTElORV9SRS5mdWxsbWF0Y2goYm9keVs6LTFdKQogICAgaWYgbWF0Y2ggaXMgTm9uZToKICAgICAgICByYWlzZSBfUmVmdXNlZCgiQUJPUlRFRF9QUkVDT05ESVRJT05fQ09ORkxJQ1QiLCAiZHJvcGluOmZvcmVpZ24tY29udGVudCIpCiAgICByZXR1cm4gbWF0Y2guZ3JvdXAoMSkuc3BsaXQoKQoKCmRlZiByZW5kZXJfZHJvcGluKHRva2Vucyk6CiAgICByZXR1cm4gRFJPUElOX0hFQURFUiArICdHUlVCX0NNRExJTkVfTElOVVg9IiRHUlVCX0NNRExJTkVfTElOVVglcyJcbicgJSAiIi5qb2luKCIgIiArIHQgZm9yIHQgaW4gdG9rZW5zKQoKCmRlZiBfZGVmYXVsdF9ydW4oYXJndiwgdGltZW91dCk6CiAgICByZXR1cm4gc3VicHJvY2Vzcy5ydW4oYXJndiwgc3RkaW49c3VicHJvY2Vzcy5ERVZOVUxMLCBzdGRvdXQ9c3VicHJvY2Vzcy5QSVBFLCBzdGRlcnI9c3VicHJvY2Vzcy5QSVBFLAogICAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQ9dGltZW91dCwgZW52PXsiUEFUSCI6ICIvdXNyL3NiaW46L3Vzci9iaW46L3NiaW46L2JpbiIsICJMQ19BTEwiOiAiQyJ9KQoKCmRlZiBfZm9yZWlnbl90b2tlbnMocm9vdCwgcnVuKToKICAgICIiIkdSVUJfQ01ETElORV9MSU5VWCDQuCBfREVGQVVMVCDQv9C+0YHQu9C1IC9ldGMvZGVmYXVsdC9ncnViINC4IGdydWIuZC8qLmNmZyDQsdC10Lcg0L3QsNGI0LXQs9C+INGE0LDQudC70LAuCgogICAg0KLQsNC6INC20LUsINC60LDQuiDQuNGFINGH0LjRgtCw0LXRgiBncnViLW1rY29uZmlnOiBgLmAg0LrQsNC20LTQvtCz0L4g0YTQsNC50LvQsCDQv9C+INC/0L7RgNGP0LTQutGDIGdsb2IuCiAgICAiIiIKICAgIHNjcmlwdCA9ICgKICAgICAgICAnc2V0IC1lOyAuICIkMSI7IGZvciBmIGluICIkMiIvKi5jZmc7IGRvIFsgIiRmIiA9ICIkMyIgXSAmJiBjb250aW51ZTsgJwogICAgICAgICdbIC1lICIkZiIgXSAmJiAuICIkZiI7IGRvbmU7IHByaW50ZiAiJXNcXG4lc1xcbiIgIiRHUlVCX0NNRExJTkVfTElOVVgiICIkR1JVQl9DTURMSU5FX0xJTlVYX0RFRkFVTFQiJwogICAgKQogICAgY3AgPSBydW4oWyIvYmluL3NoIiwgIi1jIiwgc2NyaXB0LCAic2giLCBfcChyb290LCBHUlVCX0RFRkFVTFQpLCBfcChyb290LCBHUlVCX0QpLCBfcChyb290LCBEUk9QSU4pXSwgNjApCiAgICBpZiBjcC5yZXR1cm5jb2RlICE9IDA6CiAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwgImdydWI6Y29uZmlnLXJlYWQtZmFpbGVkIikKICAgIHJldHVybiBjcC5zdGRvdXQuZGVjb2RlKCJhc2NpaSIsICJyZXBsYWNlIikuc3BsaXQoKQoKCmRlZiBfY2hlY2tfbGF5b3V0KHJvb3QpOgogICAgZ3J1Yl9kID0gX3Aocm9vdCwgR1JVQl9EKQogICAgdHJ5OgogICAgICAgIHN0ID0gb3MubHN0YXQoZ3J1Yl9kKQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwgImdydWI6Z3J1Yi1kLW1pc3NpbmciKQogICAgaWYgbm90IHN0YXQuU19JU0RJUihzdC5zdF9tb2RlKSBvciBzdGF0LlNfSU1PREUoc3Quc3RfbW9kZSkgJiAwbzAyMiBvciAocm9vdCBpcyBOb25lIGFuZCBzdC5zdF91aWQgIT0gMCk6CiAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwgImdydWI6Z3J1Yi1kLXVudHJ1c3RlZCIpCiAgICBpZiBub3Qgb3MucGF0aC5pc2ZpbGUoX3Aocm9vdCwgR1JVQl9ERUZBVUxUKSk6CiAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwgImdydWI6ZGVmYXVsdC1taXNzaW5nIikKICAgICMg0KLQuNC/INGE0LDQudC70LAg0Lgg0LHQuNGC0Ysg0LjRgdC/0L7Qu9C90LXQvdC40Y87INGB0LDQvCDQt9Cw0L/Rg9GB0Log0L/RgNC+0LLQtdGA0Y/QtdGC0YHRjyDQv9C+INC60L7QtNGDINCy0L7Qt9Cy0YDQsNGC0LAgdXBkYXRlLWdydWIuCiAgICB0cnk6CiAgICAgICAgdG9vbCA9IG9zLnN0YXQoX3Aocm9vdCwgVVBEQVRFX0dSVUIpKQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwgImdydWI6dXBkYXRlLWdydWItbWlzc2luZyIpCiAgICBpZiBub3Qgc3RhdC5TX0lTUkVHKHRvb2wuc3RfbW9kZSkgb3Igbm90IHRvb2wuc3RfbW9kZSAmIDBvMTExOgogICAgICAgIHJhaXNlIF9SZWZ1c2VkKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsICJncnViOnVwZGF0ZS1ncnViLW1pc3NpbmciKQoKCmRlZiBfd3JpdGVfZHJvcGluKHJvb3QsIHRva2Vucyk6CiAgICBwYXRoID0gX3Aocm9vdCwgRFJPUElOKQogICAgdG1wID0gcGF0aCArICIuc2xwLXRtcCIKICAgIHdpdGggb3Blbih0bXAsICJ3IiwgZW5jb2Rpbmc9ImFzY2lpIikgYXMgc3RyZWFtOgogICAgICAgIHN0cmVhbS53cml0ZShyZW5kZXJfZHJvcGluKHRva2VucykpCiAgICAgICAgc3RyZWFtLmZsdXNoKCkKICAgICAgICBvcy5mc3luYyhzdHJlYW0uZmlsZW5vKCkpCiAgICBvcy5jaG1vZCh0bXAsIDBvNjQ0KQogICAgb3MucmVwbGFjZSh0bXAsIHBhdGgpCgoKZGVmIF9yZXN0b3JlX2Ryb3Bpbihyb290LCBvbGRfdG9rZW5zKToKICAgIGlmIG9sZF90b2tlbnMgaXMgTm9uZToKICAgICAgICB0cnk6CiAgICAgICAgICAgIG9zLnVubGluayhfcChyb290LCBEUk9QSU4pKQogICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgcGFzcwogICAgZWxzZToKICAgICAgICBfd3JpdGVfZHJvcGluKHJvb3QsIG9sZF90b2tlbnMpCgoKZGVmIF9ncnViX2NmZ19oYXMocm9vdCwgdG9rZW4pOgogICAgdHJ5OgogICAgICAgIHdpdGggb3BlbihfcChyb290LCBHUlVCX0NGRyksICJyIiwgZW5jb2Rpbmc9InV0Zi04IiwgZXJyb3JzPSJyZXBsYWNlIikgYXMgc3RyZWFtOgogICAgICAgICAgICAjINCi0L7Qu9GM0LrQviDRgdGC0YDQvtC60Lgg0Y/QtNGA0LA6IG1lbXRlc3Q4Nisg0Lgg0LTRgC4g0YLQvtC20LUg0LzQvtCz0YPRgiDQt9Cw0LPRgNGD0LbQsNGC0YzRgdGPINC60L7QvNCw0L3QtNC+0LkgYGxpbnV4YC4KICAgICAgICAgICAgbGluZXMgPSBbbC5zcGxpdCgpIGZvciBsIGluIHN0cmVhbSBpZiByZS5tYXRjaChyIl5ccypsaW51eFxzK1xTKnZtbGludXoiLCBsKV0KICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgIHJldHVybiBGYWxzZQogICAgcmV0dXJuIGJvb2wobGluZXMpIGFuZCBhbGwodG9rZW4gaW4gd29yZHMgZm9yIHdvcmRzIGluIGxpbmVzKQoKCmRlZiBfdXBkYXRlX2dydWIocm9vdCwgcnVuKToKICAgIHRyeToKICAgICAgICBjcCA9IHJ1bihbX3Aocm9vdCwgVVBEQVRFX0dSVUIpXSwgVVBEQVRFX0dSVUJfVElNRU9VVCkKICAgIGV4Y2VwdCAoT1NFcnJvciwgc3VicHJvY2Vzcy5UaW1lb3V0RXhwaXJlZCk6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICByZXR1cm4gY3AucmV0dXJuY29kZSA9PSAwCgoKZGVmIF9kZWZhdWx0X3ByaXZpbGVnZV9jaGVjaygpIC0+IGJvb2w6CiAgICByZXR1cm4gb3MuZ2V0ZXVpZCgpID09IDAKCgpkZWYgX3Jlc3VsdChjb250cm9sX2lkLCBvdXRjb21lLCAqLCBhY3Rpb25zLCBkcnlfcnVuLCBtdXRhdGlvbj1GYWxzZSwgKipleHRyYSk6CiAgICByZWNvcmQgPSB7CiAgICAgICAgImFkYXB0ZXJfaWQiOiBBREFQVEVSX0lELAogICAgICAgICJtZWNoYW5pc21faWQiOiBNRUNIQU5JU01fSUQsCiAgICAgICAgImNvbnRyb2xfaWQiOiBjb250cm9sX2lkLAogICAgICAgICJ0YXJnZXQiOiBEUk9QSU4sCiAgICAgICAgIm91dGNvbWUiOiBvdXRjb21lLAogICAgICAgICJyZWFzb24iOiBOb25lLAogICAgICAgICJ0b2tlbiI6IE5vbmUsCiAgICAgICAgImNtZGxpbmVfY3VycmVudCI6IE5vbmUsCiAgICAgICAgInJlYm9vdF9yZXF1aXJlZCI6IEZhbHNlLAogICAgICAgICJvcGVyYXRvcl9kZWNpc2lvbiI6IE5vbmUsCiAgICAgICAgImFjdGlvbnNfYXR0ZW1wdGVkIjogbGlzdChhY3Rpb25zKSwKICAgICAgICAibXV0YXRpb25fcGVyZm9ybWVkIjogYm9vbChtdXRhdGlvbiksCiAgICAgICAgInRyYW5zYWN0aW9uX2NvbW1pdCI6IF9jb21taXRfc3RhdGUob3V0Y29tZSwgZHJ5X3J1biwgbXV0YXRpb24pLAogICAgICAgICJkcnlfcnVuIjogYm9vbChkcnlfcnVuKSwKICAgIH0KICAgIHJlY29yZC51cGRhdGUoZXh0cmEpCiAgICBpZiByZWNvcmRbIm91dGNvbWUiXSBub3QgaW4gT1VUQ09NRVM6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigib3V0Y29tZSBvdXRzaWRlIGNsb3NlZCB2b2NhYnVsYXJ5IikKICAgIHJldHVybiByZWNvcmQKCgpkZWYgX2NvbW1pdF9zdGF0ZShvdXRjb21lLCBkcnlfcnVuLCBtdXRhdGlvbik6CiAgICBpZiBvdXRjb21lID09ICJBUFBMSUVEIiBvciAob3V0Y29tZSBpbiAoIkFMUkVBRFlfQ09NUExJQU5UIiwgIlBFTkRJTkdfUkVCT09UIikgYW5kIG5vdCBkcnlfcnVuKToKICAgICAgICByZXR1cm4gQ09NTUlUX0NPTU1JVFRFRAogICAgaWYgbXV0YXRpb246CiAgICAgICAgcmV0dXJuIENPTU1JVF9OT1RfQ09NTUlUVEVECiAgICByZXR1cm4gQ09NTUlUX05PVF9TVEFSVEVECgoKZGVmIG91dGNvbWVfcmNfY29udHJpYnV0aW9uKG91dGNvbWUsIGRyeV9ydW49RmFsc2UpOgogICAgIiIiIjAiINC00LvRjyDRg9GB0L/QtdGI0L3Ri9GFINC40YHRhdC+0LTQvtCyLCDQuNC90LDRh9C1ICJub256ZXJvIi4iIiIKICAgIGlmIG91dGNvbWUgaW4gKCJBUFBMSUVEIiwgIlBFTkRJTkdfUkVCT09UIiwgIkFMUkVBRFlfQ09NUExJQU5UIiwgIk5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRCIpOgogICAgICAgIHJldHVybiAiMCIKICAgIGlmIGRyeV9ydW4gYW5kIG91dGNvbWUgPT0gIkRSWV9SVU5fV09VTERfQVBQTFkiOgogICAgICAgIHJldHVybiAiMCIKICAgIHJldHVybiAibm9uemVybyIKCgpkZWYgZXhlY3V0ZV9jb250cm9sKGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQsICosIGRyeV9ydW4sCiAgICAgICAgICAgICAgICAgICAgcHJpdmlsZWdlX2NoZWNrPU5vbmUsIF9yb290PU5vbmUsIF9ydW49Tm9uZSk6CiAgICAiIiJBcHBseSBvbmUga2VybmVsIGJvb3QgcGFyYW1ldGVyIHRocm91Z2ggdGhlIEdSVUIgZHJvcC1pbi4KCiAgICBgX3Jvb3RgINC4IGBfcnVuYCDigJQg0YLQvtC70YzQutC+INC00LvRjyDRgtC10YHRgtC+0LI6INC60L7RgNC10L3RjCDRhNCw0LnQu9C+0LLQvtC5INGB0LjRgdGC0LXQvNGLINC4INC30LDQv9GD0YHQuiDQutC+0LzQsNC90LQuCiAgICAiIiIKICAgIHZhbGlkYXRlX2NvbnRyb2xfaW5wdXQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIGFwcGx5X3N1cHBvcnRlZCkKICAgIGFjdGlvbnMgPSBbIlAwX0VMSUdJQklMSVRZIl0KICAgIHJ1biA9IF9ydW4gaWYgX3J1biBpcyBub3QgTm9uZSBlbHNlIF9kZWZhdWx0X3J1bgoKICAgIGRlZiBkb25lKG91dGNvbWUsICoqZXh0cmEpOgogICAgICAgIHJldHVybiBfcmVzdWx0KGNvbnRyb2xfaWQsIG91dGNvbWUsIGFjdGlvbnM9YWN0aW9ucywgZHJ5X3J1bj1kcnlfcnVuLCAqKmV4dHJhKQoKICAgIGlmIG5vdCBhcHBseV9zdXBwb3J0ZWQ6CiAgICAgICAgcmV0dXJuIGRvbmUoIk5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRCIsIHJlYXNvbj0iYXBwbHktdW5zdXBwb3J0ZWQiKQogICAgYWRtaW4gPSBBRE1JTi5nZXQoY29udHJvbF9pZCkKICAgIHNwZWMgPSBhZG1pblswXSBpZiBhZG1pbiBpcyBub3QgTm9uZSBlbHNlIEFVVE8uZ2V0KGNvbnRyb2xfaWQpCiAgICBpZiBzcGVjIGlzIE5vbmUgb3Igc3BlYyAhPSAoa2V5LCBvcCwgZXhwZWN0ZWQpOgogICAgICAgIHJldHVybiBkb25lKCJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiLCByZWFzb249Im9wLXVuc3VwcG9ydGVkIikKICAgIHRva2VuID0gZGVzaXJlZF90b2tlbihrZXksIG9wLCBleHBlY3RlZCkKICAgIGlmIG5vdCBUT0tFTl9SRS5mdWxsbWF0Y2godG9rZW4pOgogICAgICAgIHJldHVybiBkb25lKCJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiLCByZWFzb249Im9wLXVuc3VwcG9ydGVkIikKCiAgICB0cnk6CiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlAxX09CU0VSVkUiKQogICAgICAgIHJ1bm5pbmdfb2ssIGN1cnJlbnQgPSBldmFsdWF0ZShfcmVhZF9jbWRsaW5lKF9yb290KSwga2V5LCBvcCwgZXhwZWN0ZWQpCiAgICAgICAgaWYgYWRtaW4gaXMgbm90IE5vbmU6CiAgICAgICAgICAgIGlmIHJ1bm5pbmdfb2s6CiAgICAgICAgICAgICAgICByZXR1cm4gZG9uZSgiQUxSRUFEWV9DT01QTElBTlQiLCB0b2tlbj10b2tlbiwgY21kbGluZV9jdXJyZW50PWN1cnJlbnQpCiAgICAgICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsIHJlYXNvbj0iYWRtaW4tZGVjaXNpb246IiArIGtleSwgdG9rZW49dG9rZW4sCiAgICAgICAgICAgICAgICAgICAgICAgIGNtZGxpbmVfY3VycmVudD1jdXJyZW50LAogICAgICAgICAgICAgICAgICAgICAgICBvcGVyYXRvcl9kZWNpc2lvbj17ImNsYXNzIjogIkJPT1RfUEFSQU1FVEVSX0FETUlOX0RFQ0lTSU9OIiwgInJlcXVpcmVkIjogVHJ1ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJwYXJhbWV0ZXIiOiBrZXksICJ2YWx1ZSI6IHRva2VuLCAicmlzayI6IGFkbWluWzFdfSkKICAgICAgICBfY2hlY2tfbGF5b3V0KF9yb290KQogICAgICAgIG9sZCA9IF9yZWFkX2Ryb3Bpbihfcm9vdCkKICAgICAgICBmb3JlaWduID0gX2ZvcmVpZ25fdG9rZW5zKF9yb290LCBydW4pCiAgICAgICAgZm9yZWlnbl9vaywgZm9yZWlnbl92YWx1ZSA9IGV2YWx1YXRlKGZvcmVpZ24sIGtleSwgb3AsIGV4cGVjdGVkKQogICAgICAgIGlmIGZvcmVpZ25fdmFsdWUgPT0gImNvbmZsaWN0IiBvciAobm90IGZvcmVpZ25fb2sgYW5kIGZvcmVpZ25fdmFsdWUgbm90IGluICgiPGFic2VudD4iLCAiZmFsc2UiKSk6CiAgICAgICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsIHJlYXNvbj0iZ3J1Yjpmb3JlaWduLWNvbmZsaWN0IiwgdG9rZW49dG9rZW4sCiAgICAgICAgICAgICAgICAgICAgICAgIGNtZGxpbmVfY3VycmVudD1jdXJyZW50KQogICAgICAgICMg0J3QsNGIINGE0LDQudC7OiDQv9GA0L7Rh9C40LUg0YLQvtC60LXQvdGLINGB0L7RhdGA0LDQvdGP0Y7RgtGB0Y8sINGC0L7QutC10L0g0Y3RgtC+0LPQviDQutC70Y7Rh9CwIOKAlCDRgtC+0LvRjNC60L4g0LXRgdC70Lgg0LXQs9C+INC90LXRgiDRgyDQsNC00LzQuNC90LjRgdGC0YDQsNGC0L7RgNCwLgogICAgICAgIG91cnMgPSBbdCBmb3IgdCBpbiAob2xkIG9yIFtdKSBpZiB0ICE9IGtleSBhbmQgbm90IHQuc3RhcnRzd2l0aChrZXkgKyAiPSIpXQogICAgICAgIHdhbnRfb3VycyA9IHNvcnRlZChvdXJzICsgKFtdIGlmIGZvcmVpZ25fb2sgZWxzZSBbdG9rZW5dKSkKICAgICAgICBkcm9waW5fb2sgPSAob2xkIGlzIE5vbmUgYW5kIGZvcmVpZ25fb2spIG9yIChvbGQgaXMgbm90IE5vbmUgYW5kIHNvcnRlZChvbGQpID09IHdhbnRfb3VycykKCiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlAyX1BMQU4iKQogICAgICAgIGlmIGRyb3Bpbl9vayBhbmQgX2dydWJfY2ZnX2hhcyhfcm9vdCwgdG9rZW4pOgogICAgICAgICAgICBpZiBydW5uaW5nX29rOgogICAgICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkFMUkVBRFlfQ09NUExJQU5UIiwgdG9rZW49dG9rZW4sIGNtZGxpbmVfY3VycmVudD1jdXJyZW50KQogICAgICAgICAgICByZXR1cm4gZG9uZSgiUEVORElOR19SRUJPT1QiLCB0b2tlbj10b2tlbiwgY21kbGluZV9jdXJyZW50PWN1cnJlbnQsIHJlYm9vdF9yZXF1aXJlZD1UcnVlKQogICAgICAgIGlmIGRyeV9ydW46CiAgICAgICAgICAgIHJldHVybiBkb25lKCJEUllfUlVOX1dPVUxEX0FQUExZIiwgdG9rZW49dG9rZW4sIGNtZGxpbmVfY3VycmVudD1jdXJyZW50KQoKICAgICAgICBhY3Rpb25zLmFwcGVuZCgiUDNfUFJJVklMRUdFIikKICAgICAgICBjaGVjayA9IHByaXZpbGVnZV9jaGVjayBpZiBwcml2aWxlZ2VfY2hlY2sgaXMgbm90IE5vbmUgZWxzZSBfZGVmYXVsdF9wcml2aWxlZ2VfY2hlY2sKICAgICAgICBpZiBub3QgY2hlY2soKToKICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwgcmVhc29uPSJwcml2aWxlZ2UiLCB0b2tlbj10b2tlbiwgY21kbGluZV9jdXJyZW50PWN1cnJlbnQpCgogICAgICAgIGFjdGlvbnMuYXBwZW5kKCJQSEFTRTFfRFJPUElOIikKICAgICAgICBtdXRhdGVkID0gRmFsc2UKICAgICAgICBpZiBub3QgZHJvcGluX29rOgogICAgICAgICAgICBfd3JpdGVfZHJvcGluKF9yb290LCB3YW50X291cnMpCiAgICAgICAgICAgIG11dGF0ZWQgPSBUcnVlCiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlBIQVNFMl9VUERBVEVfR1JVQiIpCiAgICAgICAgaWYgX3VwZGF0ZV9ncnViKF9yb290LCBydW4pIGFuZCBfZ3J1Yl9jZmdfaGFzKF9yb290LCB0b2tlbik6CiAgICAgICAgICAgIGFjdGlvbnMuYXBwZW5kKCJGSU5BTF9QT1NUQ0hFQ0siKQogICAgICAgICAgICByZXR1cm4gZG9uZSgiQVBQTElFRCIsIG11dGF0aW9uPVRydWUsIHRva2VuPXRva2VuLCBjbWRsaW5lX2N1cnJlbnQ9Y3VycmVudCwgcmVib290X3JlcXVpcmVkPVRydWUpCiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIkNPTVBFTlNBVElPTiIpCiAgICAgICAgcmVhc29uID0gInVwZGF0ZS1ncnViOmZhaWxlZC1vci10b2tlbi1taXNzaW5nIgogICAgICAgIGlmIG11dGF0ZWQ6CiAgICAgICAgICAgIF9yZXN0b3JlX2Ryb3Bpbihfcm9vdCwgb2xkKQogICAgICAgIGlmIF91cGRhdGVfZ3J1Yihfcm9vdCwgcnVuKToKICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwgcmVhc29uPXJlYXNvbiwgbXV0YXRpb249VHJ1ZSwgdG9rZW49dG9rZW4sIGNtZGxpbmVfY3VycmVudD1jdXJyZW50KQogICAgICAgIHJldHVybiBkb25lKCJGQUlMRURfQ09NUEVOU0FUSU9OIiwgcmVhc29uPXJlYXNvbiwgbXV0YXRpb249VHJ1ZSwgdG9rZW49dG9rZW4sIGNtZGxpbmVfY3VycmVudD1jdXJyZW50KQogICAgZXhjZXB0IF9SZWZ1c2VkIGFzIGV4YzoKICAgICAgICByZXR1cm4gZG9uZShleGMub3V0Y29tZSwgcmVhc29uPWV4Yy5yZWFzb24sIHRva2VuPXRva2VuKQoKCmRlZiBjb250cm9sX3Jlc3VsdF90b19yZXBvcnQocmVzdWx0LCBzdGFydGVkX2F0LCBmaW5pc2hlZF9hdCk6CiAgICByZXR1cm4gewogICAgICAgICJhZGFwdGVyX2lkIjogcmVzdWx0WyJhZGFwdGVyX2lkIl0sCiAgICAgICAgIm1lY2hhbmlzbV9pZCI6IHJlc3VsdFsibWVjaGFuaXNtX2lkIl0sCiAgICAgICAgImNvbnRyb2xfaWQiOiByZXN1bHRbImNvbnRyb2xfaWQiXSwKICAgICAgICAidGFyZ2V0IjogcmVzdWx0WyJ0YXJnZXQiXSwKICAgICAgICAib3V0Y29tZSI6IHJlc3VsdFsib3V0Y29tZSJdLAogICAgICAgICJyZWFzb24iOiByZXN1bHRbInJlYXNvbiJdLAogICAgICAgICJ0b2tlbiI6IHJlc3VsdFsidG9rZW4iXSwKICAgICAgICAiY21kbGluZV9jdXJyZW50IjogcmVzdWx0WyJjbWRsaW5lX2N1cnJlbnQiXSwKICAgICAgICAicmVib290X3JlcXVpcmVkIjogcmVzdWx0WyJyZWJvb3RfcmVxdWlyZWQiXSwKICAgICAgICAib3BlcmF0b3JfZGVjaXNpb24iOiBOb25lIGlmIHJlc3VsdFsib3BlcmF0b3JfZGVjaXNpb24iXSBpcyBOb25lIGVsc2UgZGljdChyZXN1bHRbIm9wZXJhdG9yX2RlY2lzaW9uIl0pLAogICAgICAgICJzdGFydGVkX2F0Ijogc3RhcnRlZF9hdCwKICAgICAgICAiZmluaXNoZWRfYXQiOiBmaW5pc2hlZF9hdCwKICAgICAgICAiYWN0aW9uc19hdHRlbXB0ZWQiOiBsaXN0KHJlc3VsdFsiYWN0aW9uc19hdHRlbXB0ZWQiXSksCiAgICAgICAgInN0ZXBfcmMiOiBvdXRjb21lX3JjX2NvbnRyaWJ1dGlvbihyZXN1bHRbIm91dGNvbWUiXSwgcmVzdWx0WyJkcnlfcnVuIl0pLAogICAgICAgICJtdXRhdGlvbl9wZXJmb3JtZWQiOiByZXN1bHRbIm11dGF0aW9uX3BlcmZvcm1lZCJdLAogICAgICAgICJ0cmFuc2FjdGlvbl9jb21taXQiOiByZXN1bHRbInRyYW5zYWN0aW9uX2NvbW1pdCJdLAogICAgfQo="},"optional-file-root-files-mode":{"adapter_id":"product-optional-file-root-files-mode-apply-v1","apply_kind":"optional-file-root-files-mode-v1","implementation_sha256":"c9c58306189ef3dec14947b256a925fa3e8acf1d381ec26caecfb53303e0401e","mechanism_id":"optional-file-root-files-mode-v1","source_b64":"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiJwcm9kdWN0LW9wdGlvbmFsLWZpbGUtcm9vdC1maWxlcy1tb2RlLWFwcGx5LXYxLgoKQVBQTFkgYWRhcHRlciBmb3IgbWVjaGFuaXNtIGBvcHRpb25hbC1maWxlLXJvb3QtZmlsZXMtbW9kZS12MWAgKDIuMy42IGNyb24gcm9vdHMpLgoKUFVSUE9TRT1ERUZFTlNJVkVfQ09NUExJQU5DRV9WQUxJREFUSU9OCkF1dGhvcml0eTogcHJvZHVjdC9jb250cmFjdHMvbWVjaGFuaXNtLW9wdGlvbmFsLWZpbGUtcm9vdC1maWxlcy1tb2RlLXYxLmpzb24KClBvcHVsYXRpb24gaXMgdGhlIG9uZSBvZiBDSEVDSyBhZGFwdGVyIHByb2R1Y3Qtb3B0aW9uYWwtZmlsZS1yb290LWZpbGVzLW1vZGUtY2hlY2stdjE6CnRoZSByb290IGl0c2VsZiBwbHVzIGl0cyBkaXJlY3QgZW50cmllcywgd2hpY2ggbXVzdCBhbGwgYmUgcmVndWxhciBmaWxlcy4gVGhlCmVudW1lcmF0b3IgYmVsb3cgaXMgYSBQeXRob24gY29weSBvZiB0aGF0IHNoZWxsIG9ic2VydmVyOyBwYXJpdHkgaXMgY2hlY2tlZCBieQp0ZXN0cy9wcm9kdWN0LXYxL3Rlc3Rfb3B0aW9uYWxfZmlsZV9yb290X2ZpbGVzX21vZGVfYXBwbHlfYWRhcHRlci5weS4KClRoZSBwbGFuIGlzIGJ1aWx0IGJlZm9yZSBhbnkgbXV0YXRpb24uIEEgc3ltbGluayBvciBhIG5vbi1yZWd1bGFyIGVudHJ5IGluIHRoZQpwb3B1bGF0aW9uIHJlZnVzZXMgdGhlIGNvbnRyb2wgd2l0aG91dCBtdXRhdGlvbi4gQSB2aW9sYXRvciB3aXRoIHN0X25saW5rID4gMQppcyBza2lwcGVkIGFuZCByZWNvcmRlZC4gRWFjaCBtdXRhdGlvbiBpcyBvbmUgYGZjaG1vZGAgb24gYSBkZXNjcmlwdG9yIG9wZW5lZAp3aXRoIE9fTk9GT0xMT1cgYW5kIG9ubHkgY2xlYXJzIGJpdHM7IHRoZXJlIGlzIG5vIGNvbXBlbnNhdGlvbi4gQW4gZXJyb3Igb24gb25lCm9iamVjdCBkb2VzIG5vdCBzdG9wIHRoZSBvdGhlcnMgKEFQUExJRURfUEFSVElBTCk7IEVST0ZTIHN0b3BzIGltbWVkaWF0ZWx5LgoiIiIKCmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnMKCmltcG9ydCBlcnJubwppbXBvcnQgb3MKaW1wb3J0IHJlCmltcG9ydCBzdGF0CgpBREFQVEVSX0lEID0gInByb2R1Y3Qtb3B0aW9uYWwtZmlsZS1yb290LWZpbGVzLW1vZGUtYXBwbHktdjEiCk1FQ0hBTklTTV9JRCA9ICJvcHRpb25hbC1maWxlLXJvb3QtZmlsZXMtbW9kZS12MSIKVEFSR0VUX0lEID0gImxpbnV4LXg4Nl82NC1zdXBwb3J0ZWQtdjEiClBBUkFNRVRFUl9LSU5EID0gIm9wdGlvbmFsLWZpbGUtcm9vdC1maWxlcy1tb2RlIgpTRU1BTlRJQ19DT05UUkFDVF9JRCA9ICJvcHRpb25hbC1maWxlLXJvb3QtZmlsZXMtbW9kZS1hcHBseS1zZW1hbnRpYy12MSIKClNVUFBPUlRFRF9LRVlTID0gKCJtb2RlIiwpClNVUFBPUlRFRF9PUFMgPSAoImJpdHMtY2xlYXIiLCkKRVhQRUNURURfTUFTSyA9ICIwMDMzIgoKT1VUQ09NRVMgPSAoCiAgICAiQVBQTElFRCIsCiAgICAiQVBQTElFRF9QQVJUSUFMIiwKICAgICJBTFJFQURZX0NPTVBMSUFOVCIsCiAgICAiRFJZX1JVTl9XT1VMRF9BUFBMWSIsCiAgICAiTk9UX0VMSUdJQkxFX0FQUExZX1VOU1VQUE9SVEVEIiwKICAgICJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsCiAgICAiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLAogICAgIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwKKQoKQ09NTUlUX0NPTU1JVFRFRCA9ICJDT01NSVRURUQiCkNPTU1JVF9OT1RfQ09NTUlUVEVEID0gIk5PVF9DT01NSVRURUQiCkNPTU1JVF9OT1RfU1RBUlRFRCA9ICJOT1RfU1RBUlRFRCIKCiMg0JrQvtGA0LXQvdGMINC60LDQttC00L7Qs9C+INC60L7QvdGC0YDQvtC70Y8uINCh0L7QstC/0LDQtNC10L3QuNC1INGBIHBhcmFtZXRlci5sb2NhdG9yINC60L7QvdGC0YDQvtC70LXQuSDQv9GA0L7QstC10YDRj9C10YIKIyB0ZXN0X29wdGlvbmFsX2ZpbGVfcm9vdF9maWxlc19tb2RlX2FwcGx5X2FkYXB0ZXIucHkuClRBUkdFVFMgPSB7CiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjMuNi1DUk9OVEFCIjogIi9ldGMvY3JvbnRhYiIsCiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjMuNi1DUk9OLUQiOiAiL2V0Yy9jcm9uLmQiLAogICAgIkZTVEVDLUxJTlVYLTIwMjItMi4zLjYtQ1JPTi1IT1VSTFkiOiAiL2V0Yy9jcm9uLmhvdXJseSIsCiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjMuNi1DUk9OLURBSUxZIjogIi9ldGMvY3Jvbi5kYWlseSIsCiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjMuNi1DUk9OLVdFRUtMWSI6ICIvZXRjL2Nyb24ud2Vla2x5IiwKICAgICJGU1RFQy1MSU5VWC0yMDIyLTIuMy42LUNST04tTU9OVEhMWSI6ICIvZXRjL2Nyb24ubW9udGhseSIsCn0KCkNPTlRST0xfSURfUEFUVEVSTiA9IHIiXig/IS4qW1xyXG5dKVtBLVphLXowLTkuXy1dKyQiCgojINCf0YDQuNGH0LjQvdGLIENIRUNLLCDQutC+0YLQvtGA0YvQtSDQvtC30L3QsNGH0LDRjtGCINC+0LHRitC10LrRgiDQvdC1INGC0L7Qs9C+INGC0LjQv9CwINCyINC/0L7Qv9GD0LvRj9GG0LjQuC4KQ09ORkxJQ1RfUkVBU09OUyA9ICgicm9vdDpzeW1saW5rIiwgInJvb3Q6aW52YWxpZC10eXBlIiwgInRhcmdldDpzeW1saW5rIiwgInRhcmdldDppbnZhbGlkLXR5cGUiKQoKCmRlZiB2YWxpZGF0ZV9jb250cm9sX2lucHV0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQpOgogICAgIiIiRmFpbC1jbG9zZWQgdmFsaWRhdGlvbiBvZiBvbmUgY29udHJvbCByb3cuIFJhaXNlcyBWYWx1ZUVycm9yLiIiIgogICAgaWYgbm90IGlzaW5zdGFuY2UoY29udHJvbF9pZCwgc3RyKSBvciBub3QgcmUuZnVsbG1hdGNoKENPTlRST0xfSURfUEFUVEVSTiwgY29udHJvbF9pZCk6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigiaW52YWxpZCBjb250cm9sIGlkIikKICAgIGlmIGtleSBub3QgaW4gU1VQUE9SVEVEX0tFWVM6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigidW5zdXBwb3J0ZWQga2V5OiAlciIgJSAoa2V5LCkpCiAgICBpZiBvcCBub3QgaW4gU1VQUE9SVEVEX09QUzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJ1bnN1cHBvcnRlZCBvcDogJXIiICUgKG9wLCkpCiAgICBpZiBleHBlY3RlZCAhPSBFWFBFQ1RFRF9NQVNLOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoIm9ubHkgYml0cy1jbGVhciAwMDMzIGlzIHN1cHBvcnRlZCIpCiAgICBpZiBub3QgaXNpbnN0YW5jZShhcHBseV9zdXBwb3J0ZWQsIGJvb2wpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImFwcGx5X3N1cHBvcnRlZCBtdXN0IGJlIGJvb2wiKQogICAgcmV0dXJuIFRydWUKCgpkZWYgX21vZGVfdGV4dChtb2RlOiBpbnQpIC0+IHN0cjoKICAgIHJldHVybiBmb3JtYXQoc3RhdC5TX0lNT0RFKG1vZGUpLCAiMDRvIikKCgpkZWYgX3BvcHVsYXRpb24ocm9vdCwgbWFzayk6CiAgICAiIiLQmtC+0L/QuNGPIENIRUNLLdC90LDQsdC70Y7QtNCw0YLQtdC70Y86ICgiRVJST1IiLCByZWFzb24pIHwgKCJBQlNFTlQiLCBOb25lKSB8ICgiVkFMVUUiLCBbKHBhdGgsIGxzdGF0KV0pLiIiIgogICAgaWYgb3MucGF0aC5pc2xpbmsocm9vdCk6CiAgICAgICAgcmV0dXJuICJFUlJPUiIsICJyb290OnN5bWxpbmsiCiAgICBpZiBub3Qgb3MucGF0aC5leGlzdHMocm9vdCk6CiAgICAgICAgcGFyZW50ID0gcm9vdC5yc3BsaXQoIi8iLCAxKVswXSBvciAiLyIKICAgICAgICBpZiBub3Qgb3MucGF0aC5sZXhpc3RzKHBhcmVudCk6CiAgICAgICAgICAgIHJldHVybiAiRVJST1IiLCAicm9vdDpwYXJlbnQtbm90LWZvdW5kIgogICAgICAgIGlmIG5vdCBvcy5wYXRoLmlzZGlyKHBhcmVudCk6CiAgICAgICAgICAgIHJldHVybiAiRVJST1IiLCAicm9vdDpwYXJlbnQtaW52YWxpZC10eXBlIgogICAgICAgIGlmIG5vdCBvcy5hY2Nlc3MocGFyZW50LCBvcy5YX09LKToKICAgICAgICAgICAgcmV0dXJuICJFUlJPUiIsICJyb290OnBhcmVudC11bnNlYXJjaGFibGUiCiAgICAgICAgcmV0dXJuICJBQlNFTlQiLCBOb25lCiAgICB0cnk6CiAgICAgICAgcm9vdF9zdCA9IG9zLmxzdGF0KHJvb3QpCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICByZXR1cm4gIkVSUk9SIiwgInJvb3Q6bW9kZS1yZWFkLWZhaWxlZCIKICAgIGl0ZW1zID0gWyhyb290LCByb290X3N0KV0KICAgIGlmIHN0YXQuU19JU1JFRyhyb290X3N0LnN0X21vZGUpOgogICAgICAgIHJldHVybiAiVkFMVUUiLCBpdGVtcwogICAgaWYgbm90IHN0YXQuU19JU0RJUihyb290X3N0LnN0X21vZGUpOgogICAgICAgIHJldHVybiAiRVJST1IiLCAicm9vdDppbnZhbGlkLXR5cGUiCiAgICB0cnk6CiAgICAgICAgd2l0aCBvcy5zY2FuZGlyKHJvb3QpIGFzIGl0OgogICAgICAgICAgICBuYW1lcyA9IHNvcnRlZCgoZW50cnkubmFtZSBmb3IgZW50cnkgaW4gaXQpLCBrZXk9b3MuZnNlbmNvZGUpCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICByZXR1cm4gIkVSUk9SIiwgInNjYW46ZmluZC1mYWlsZWQiCiAgICBmb3IgbmFtZSBpbiBuYW1lczoKICAgICAgICBwYXRoID0gb3MucGF0aC5qb2luKHJvb3QsIG5hbWUpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzdCA9IG9zLmxzdGF0KHBhdGgpCiAgICAgICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgICAgIHJldHVybiAiRVJST1IiLCAidGFyZ2V0Om1vZGUtcmVhZC1mYWlsZWQiCiAgICAgICAgaWYgc3RhdC5TX0lTTE5LKHN0LnN0X21vZGUpOgogICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgInRhcmdldDpzeW1saW5rIgogICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcoc3Quc3RfbW9kZSk6CiAgICAgICAgICAgIHJldHVybiAiRVJST1IiLCAidGFyZ2V0OmludmFsaWQtdHlwZSIKICAgICAgICBpdGVtcy5hcHBlbmQoKHBhdGgsIHN0KSkKICAgIHJldHVybiAiVkFMVUUiLCBpdGVtcwoKCmRlZiBvYnNlcnZlKHJvb3QsIGV4cGVjdGVkPUVYUEVDVEVEX01BU0spOgogICAgIiIiKHN0YXR1cywgdmFsdWUpINCyINGE0L7RgNC80LDRgtC1IENIRUNLLdCw0LTQsNC/0YLQtdGA0LAg0LTQu9GPINC60L7RgNC90Y8gcm9vdC4iIiIKICAgIG1hc2sgPSBpbnQoZXhwZWN0ZWQsIDgpCiAgICBzdGF0dXMsIGRhdGEgPSBfcG9wdWxhdGlvbihyb290LCBtYXNrKQogICAgaWYgc3RhdHVzID09ICJFUlJPUiI6CiAgICAgICAgcmV0dXJuICJFUlJPUiIsIGRhdGEKICAgIGlmIHN0YXR1cyA9PSAiQUJTRU5UIjoKICAgICAgICByZXR1cm4gIlZBTFVFIiwgIjxhYnNlbnQ+IgogICAgdmlvbGF0aW9ucyA9IHN1bSgxIGZvciBfcGF0aCwgc3QgaW4gZGF0YSBpZiBzdGF0LlNfSU1PREUoc3Quc3RfbW9kZSkgJiBtYXNrKQogICAgcmV0dXJuICJWQUxVRSIsICJjaGVja2VkPSVkO3Zpb2xhdGlvbnM9JWQiICUgKGxlbihkYXRhKSwgdmlvbGF0aW9ucykKCgpkZWYgX2RlZmF1bHRfcHJpdmlsZWdlX2NoZWNrKCkgLT4gYm9vbDoKICAgIHJldHVybiBvcy5nZXRldWlkKCkgPT0gMAoKCmRlZiBfZGVmYXVsdF9mY2htb2QoZmQsIG1vZGUsIHBhdGgpOgogICAgb3MuZmNobW9kKGZkLCBtb2RlKQoKCmRlZiBfcmVzdWx0KGNvbnRyb2xfaWQsIHRhcmdldCwgb3V0Y29tZSwgKiwgYWN0aW9ucywgZHJ5X3J1biwgbXV0YXRpb249RmFsc2UsICoqZXh0cmEpOgogICAgcmVjb3JkID0gewogICAgICAgICJhZGFwdGVyX2lkIjogQURBUFRFUl9JRCwKICAgICAgICAibWVjaGFuaXNtX2lkIjogTUVDSEFOSVNNX0lELAogICAgICAgICJjb250cm9sX2lkIjogY29udHJvbF9pZCwKICAgICAgICAidGFyZ2V0IjogdGFyZ2V0LAogICAgICAgICJvdXRjb21lIjogb3V0Y29tZSwKICAgICAgICAicmVhc29uIjogTm9uZSwKICAgICAgICAiY3VycmVudF9tb2RlIjogTm9uZSwKICAgICAgICAidmlvbGF0b3JzIjogW10sCiAgICAgICAgImFwcGxpZWQiOiBbXSwKICAgICAgICAic2tpcHBlZCI6IFtdLAogICAgICAgICJmYWlsZWQiOiBbXSwKICAgICAgICAiYWN0aW9uc19hdHRlbXB0ZWQiOiBsaXN0KGFjdGlvbnMpLAogICAgICAgICJtdXRhdGlvbl9wZXJmb3JtZWQiOiBib29sKG11dGF0aW9uKSwKICAgICAgICAidHJhbnNhY3Rpb25fY29tbWl0IjogX2NvbW1pdF9zdGF0ZShvdXRjb21lLCBkcnlfcnVuLCBtdXRhdGlvbiksCiAgICAgICAgImRyeV9ydW4iOiBib29sKGRyeV9ydW4pLAogICAgfQogICAgcmVjb3JkLnVwZGF0ZShleHRyYSkKICAgIGlmIHJlY29yZFsib3V0Y29tZSJdIG5vdCBpbiBPVVRDT01FUzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJvdXRjb21lIG91dHNpZGUgY2xvc2VkIHZvY2FidWxhcnkiKQogICAgcmV0dXJuIHJlY29yZAoKCmRlZiBfY29tbWl0X3N0YXRlKG91dGNvbWUsIGRyeV9ydW4sIG11dGF0aW9uKToKICAgICIiItCi0LUg0LbQtSDQt9C90LDRh9C10L3QuNGPLCDRh9GC0L4g0YMgZmlsZS1tb2RlLW93bmVyLiIiIgogICAgaWYgb3V0Y29tZSA9PSAiQVBQTElFRCIgb3IgKG91dGNvbWUgPT0gIkFMUkVBRFlfQ09NUExJQU5UIiBhbmQgbm90IGRyeV9ydW4pOgogICAgICAgIHJldHVybiBDT01NSVRfQ09NTUlUVEVECiAgICBpZiBtdXRhdGlvbjoKICAgICAgICByZXR1cm4gQ09NTUlUX05PVF9DT01NSVRURUQKICAgIHJldHVybiBDT01NSVRfTk9UX1NUQVJURUQKCgpkZWYgb3V0Y29tZV9yY19jb250cmlidXRpb24ob3V0Y29tZSwgZHJ5X3J1bj1GYWxzZSk6CiAgICAiIiIiMCIg0LTQu9GPINGD0YHQv9C10YjQvdGL0YUg0LjRgdGF0L7QtNC+0LIsINC40L3QsNGH0LUgIm5vbnplcm8iOyBBUFBMSUVEX1BBUlRJQUwg4oCUIG5vbnplcm8uIiIiCiAgICBpZiBvdXRjb21lIGluICgiQVBQTElFRCIsICJBTFJFQURZX0NPTVBMSUFOVCIsICJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiKToKICAgICAgICByZXR1cm4gIjAiCiAgICBpZiBkcnlfcnVuIGFuZCBvdXRjb21lID09ICJEUllfUlVOX1dPVUxEX0FQUExZIjoKICAgICAgICByZXR1cm4gIjAiCiAgICByZXR1cm4gIm5vbnplcm8iCgoKZGVmIF9hcHBseV9vbmUocGF0aCwgb2JzZXJ2ZWQsIG1hc2ssIGZjaG1vZCk6CiAgICAiIiLQodC90Y/RgtGMINCx0LjRgtGLIG1hc2sg0YMg0L7QtNC90L7Qs9C+INC+0LHRitC10LrRgtCwLiDQktC+0LfQstGA0LDRidCw0LXRgiAobXV0YXRlZCwgZmFpbHVyZV9yZWFzb258Tm9uZSkuIiIiCiAgICB0cnk6CiAgICAgICAgZmQgPSBvcy5vcGVuKHBhdGgsIG9zLk9fUkRPTkxZIHwgb3MuT19OT0ZPTExPVyB8IG9zLk9fQ0xPRVhFQykKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICBpZiBleGMuZXJybm8gPT0gZXJybm8uRUxPT1A6CiAgICAgICAgICAgIHJldHVybiBGYWxzZSwgInN5bWxpbmsiCiAgICAgICAgcmV0dXJuIEZhbHNlLCAib3BlbjolcyIgJSBlcnJuby5lcnJvcmNvZGUuZ2V0KGV4Yy5lcnJubywgZXhjLmVycm5vKQogICAgdHJ5OgogICAgICAgIG5vdyA9IG9zLmZzdGF0KGZkKQogICAgICAgIGlmIChub3cuc3RfZGV2LCBub3cuc3RfaW5vKSAhPSAob2JzZXJ2ZWQuc3RfZGV2LCBvYnNlcnZlZC5zdF9pbm8pOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJpZGVudGl0eS1kcmlmdCIKICAgICAgICBpZiBzdGF0LlNfSUZNVChub3cuc3RfbW9kZSkgIT0gc3RhdC5TX0lGTVQob2JzZXJ2ZWQuc3RfbW9kZSk6CiAgICAgICAgICAgIHJldHVybiBGYWxzZSwgInR5cGUtZHJpZnQiCiAgICAgICAgaWYgc3RhdC5TX0lTUkVHKG5vdy5zdF9tb2RlKSBhbmQgbm93LnN0X25saW5rICE9IDE6CiAgICAgICAgICAgIHJldHVybiBGYWxzZSwgInN0X25saW5rIgogICAgICAgIGlmIChub3cuc3RfdWlkLCBub3cuc3RfZ2lkKSAhPSAob2JzZXJ2ZWQuc3RfdWlkLCBvYnNlcnZlZC5zdF9naWQpOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJvd25lcnNoaXAtZHJpZnQiCiAgICAgICAgY3VycmVudCA9IHN0YXQuU19JTU9ERShub3cuc3RfbW9kZSkKICAgICAgICBpZiBjdXJyZW50ICE9IHN0YXQuU19JTU9ERShvYnNlcnZlZC5zdF9tb2RlKToKICAgICAgICAgICAgcmV0dXJuIEZhbHNlLCAibW9kZS1kcmlmdCIKICAgICAgICBwbGFubmVkID0gY3VycmVudCAmIH5tYXNrCiAgICAgICAgZmNobW9kKGZkLCBwbGFubmVkLCBwYXRoKQogICAgICAgIHBvc3QgPSBvcy5mc3RhdChmZCkKICAgICAgICBpZiAoCiAgICAgICAgICAgIHN0YXQuU19JTU9ERShwb3N0LnN0X21vZGUpICE9IHBsYW5uZWQKICAgICAgICAgICAgb3IgKHBvc3Quc3RfdWlkLCBwb3N0LnN0X2dpZCkgIT0gKG5vdy5zdF91aWQsIG5vdy5zdF9naWQpCiAgICAgICAgICAgIG9yIChwb3N0LnN0X2RldiwgcG9zdC5zdF9pbm8pICE9IChub3cuc3RfZGV2LCBub3cuc3RfaW5vKQogICAgICAgICAgICBvciBwb3N0LnN0X3NpemUgIT0gbm93LnN0X3NpemUKICAgICAgICApOgogICAgICAgICAgICByZXR1cm4gVHJ1ZSwgInBvc3Qtc3RhdGUtbWlzbWF0Y2giCiAgICAgICAgcmV0dXJuIFRydWUsIE5vbmUKICAgIGZpbmFsbHk6CiAgICAgICAgb3MuY2xvc2UoZmQpCgoKZGVmIGV4ZWN1dGVfY29udHJvbCgKICAgIGNvbnRyb2xfaWQsCiAgICBrZXksCiAgICBvcCwKICAgIGV4cGVjdGVkLAogICAgYXBwbHlfc3VwcG9ydGVkLAogICAgKiwKICAgIHRhcmdldD1Ob25lLAogICAgZHJ5X3J1biwKICAgIHByaXZpbGVnZV9jaGVjaz1Ob25lLAogICAgX2ZjaG1vZD1Ob25lLAopOgogICAgIiIiQXBwbHkgb25lIG9wdGlvbmFsIHJvb3QgY29udHJvbC4gTmV2ZXIgZm9sbG93cyBhIHN5bWxpbmssIG5ldmVyIHJlbGF4ZXMuIiIiCiAgICB2YWxpZGF0ZV9jb250cm9sX2lucHV0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQpCiAgICBhY3Rpb25zID0gWyJQMF9FTElHSUJJTElUWSJdCgogICAgZGVmIGRvbmUob3V0Y29tZSwgKipleHRyYSk6CiAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwgdGFyZ2V0LCBvdXRjb21lLCBhY3Rpb25zPWFjdGlvbnMsIGRyeV9ydW49ZHJ5X3J1biwgKipleHRyYSkKCiAgICBpZiBub3QgYXBwbHlfc3VwcG9ydGVkOgogICAgICAgIHJldHVybiBkb25lKCJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiLCByZWFzb249ImFwcGx5LXVuc3VwcG9ydGVkIikKCiAgICBpZiB0YXJnZXQgaXMgTm9uZToKICAgICAgICB0YXJnZXQgPSBUQVJHRVRTLmdldChjb250cm9sX2lkKQogICAgICAgIGlmIHRhcmdldCBpcyBOb25lOgogICAgICAgICAgICByZXR1cm4gZG9uZSgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLCByZWFzb249InRhcmdldDp1bm1hcHBlZC1jb250cm9sIikKCiAgICBtYXNrID0gaW50KGV4cGVjdGVkLCA4KQogICAgYWN0aW9ucy5hcHBlbmQoIlAxX1BPUFVMQVRJT04iKQogICAgc3RhdHVzLCBkYXRhID0gX3BvcHVsYXRpb24odGFyZ2V0LCBtYXNrKQogICAgaWYgc3RhdHVzID09ICJFUlJPUiI6CiAgICAgICAgb3V0Y29tZSA9ICJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIgaWYgZGF0YSBpbiBDT05GTElDVF9SRUFTT05TIGVsc2UgIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIgogICAgICAgIHJldHVybiBkb25lKG91dGNvbWUsIHJlYXNvbj1kYXRhKQogICAgaWYgc3RhdHVzID09ICJBQlNFTlQiOgogICAgICAgIHJldHVybiBkb25lKCJBTFJFQURZX0NPTVBMSUFOVCIsIHJlYXNvbj0iYWJzZW50IiwgY3VycmVudF9tb2RlPSI8YWJzZW50PiIpCgogICAgYWN0aW9ucy5hcHBlbmQoIlAyX1BMQU4iKQogICAgdmlvbGF0b3JzID0gWyhwYXRoLCBzdCkgZm9yIHBhdGgsIHN0IGluIGRhdGEgaWYgc3RhdC5TX0lNT0RFKHN0LnN0X21vZGUpICYgbWFza10KICAgIGN1cnJlbnQgPSAiY2hlY2tlZD0lZDt2aW9sYXRpb25zPSVkIiAlIChsZW4oZGF0YSksIGxlbih2aW9sYXRvcnMpKQogICAgaWYgbm90IHZpb2xhdG9yczoKICAgICAgICByZXR1cm4gZG9uZSgiQUxSRUFEWV9DT01QTElBTlQiLCBjdXJyZW50X21vZGU9Y3VycmVudCkKICAgIHNraXBwZWQgPSBbCiAgICAgICAgeyJwYXRoIjogcGF0aCwgInJlYXNvbiI6ICJzdF9ubGluayJ9CiAgICAgICAgZm9yIHBhdGgsIHN0IGluIHZpb2xhdG9ycwogICAgICAgIGlmIHN0YXQuU19JU1JFRyhzdC5zdF9tb2RlKSBhbmQgc3Quc3RfbmxpbmsgIT0gMQogICAgXQogICAgc2tpcHBlZF9wYXRocyA9IHtpdGVtWyJwYXRoIl0gZm9yIGl0ZW0gaW4gc2tpcHBlZH0KICAgIHBsYW5uZWQgPSBbKHBhdGgsIHN0KSBmb3IgcGF0aCwgc3QgaW4gdmlvbGF0b3JzIGlmIHBhdGggbm90IGluIHNraXBwZWRfcGF0aHNdCiAgICB2aW9sYXRvcl9wYXRocyA9IFtwYXRoIGZvciBwYXRoLCBfc3QgaW4gdmlvbGF0b3JzXQogICAgaWYgbm90IHBsYW5uZWQ6CiAgICAgICAgcmV0dXJuIGRvbmUoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwgcmVhc29uPSJzdF9ubGluayIsIGN1cnJlbnRfbW9kZT1jdXJyZW50LAogICAgICAgICAgICAgICAgICAgIHZpb2xhdG9ycz12aW9sYXRvcl9wYXRocywgc2tpcHBlZD1za2lwcGVkKQogICAgaWYgZHJ5X3J1bjoKICAgICAgICByZXR1cm4gZG9uZSgiRFJZX1JVTl9XT1VMRF9BUFBMWSIsIGN1cnJlbnRfbW9kZT1jdXJyZW50LAogICAgICAgICAgICAgICAgICAgIHZpb2xhdG9ycz12aW9sYXRvcl9wYXRocywgc2tpcHBlZD1za2lwcGVkKQoKICAgIGFjdGlvbnMuYXBwZW5kKCJQM19QUklWSUxFR0UiKQogICAgY2hlY2sgPSBwcml2aWxlZ2VfY2hlY2sgaWYgcHJpdmlsZWdlX2NoZWNrIGlzIG5vdCBOb25lIGVsc2UgX2RlZmF1bHRfcHJpdmlsZWdlX2NoZWNrCiAgICBpZiBub3QgY2hlY2soKToKICAgICAgICByZXR1cm4gZG9uZSgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLCByZWFzb249InByaXZpbGVnZSIsIGN1cnJlbnRfbW9kZT1jdXJyZW50LAogICAgICAgICAgICAgICAgICAgIHZpb2xhdG9ycz12aW9sYXRvcl9wYXRocywgc2tpcHBlZD1za2lwcGVkKQoKICAgIGFjdGlvbnMuYXBwZW5kKCJQSEFTRTFfTU9ERSIpCiAgICBmY2htb2QgPSBfZmNobW9kIGlmIF9mY2htb2QgaXMgbm90IE5vbmUgZWxzZSBfZGVmYXVsdF9mY2htb2QKICAgIGFwcGxpZWQsIGZhaWxlZCA9IFtdLCBbXQogICAgbXV0YXRlZCA9IEZhbHNlCiAgICBmb3IgcGF0aCwgc3QgaW4gcGxhbm5lZDoKICAgICAgICB0cnk6CiAgICAgICAgICAgIGNoYW5nZWQsIGZhaWx1cmUgPSBfYXBwbHlfb25lKHBhdGgsIHN0LCBtYXNrLCBmY2htb2QpCiAgICAgICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgICAgICBpZiBleGMuZXJybm8gPT0gZXJybm8uRVJPRlM6CiAgICAgICAgICAgICAgICBvdXRjb21lID0gIkFQUExJRURfUEFSVElBTCIgaWYgbXV0YXRlZCBlbHNlICJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIKICAgICAgICAgICAgICAgIHJldHVybiBkb25lKG91dGNvbWUsIHJlYXNvbj0iZXJvZnMiLCBtdXRhdGlvbj1tdXRhdGVkLCBjdXJyZW50X21vZGU9Y3VycmVudCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZpb2xhdG9ycz12aW9sYXRvcl9wYXRocywgYXBwbGllZD1hcHBsaWVkLCBza2lwcGVkPXNraXBwZWQsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmYWlsZWQ9ZmFpbGVkICsgW3sicGF0aCI6IHBhdGgsICJyZWFzb24iOiAiZXJvZnMifV0pCiAgICAgICAgICAgIGNoYW5nZWQsIGZhaWx1cmUgPSBGYWxzZSwgImZjaG1vZDolcyIgJSBlcnJuby5lcnJvcmNvZGUuZ2V0KGV4Yy5lcnJubywgZXhjLmVycm5vKQogICAgICAgIG11dGF0ZWQgPSBtdXRhdGVkIG9yIGNoYW5nZWQKICAgICAgICBpZiBmYWlsdXJlIGlzIE5vbmU6CiAgICAgICAgICAgIGFwcGxpZWQuYXBwZW5kKHBhdGgpCiAgICAgICAgZWxzZToKICAgICAgICAgICAgZmFpbGVkLmFwcGVuZCh7InBhdGgiOiBwYXRoLCAicmVhc29uIjogZmFpbHVyZX0pCgogICAgYWN0aW9ucy5hcHBlbmQoIkZJTkFMX1BPU1RDSEVDSyIpCiAgICBleHRyYSA9IGRpY3QoY3VycmVudF9tb2RlPWN1cnJlbnQsIHZpb2xhdG9ycz12aW9sYXRvcl9wYXRocywgYXBwbGllZD1hcHBsaWVkLAogICAgICAgICAgICAgICAgIHNraXBwZWQ9c2tpcHBlZCwgZmFpbGVkPWZhaWxlZCkKICAgIGlmIG5vdCBmYWlsZWQgYW5kIG5vdCBza2lwcGVkOgogICAgICAgIHJldHVybiBkb25lKCJBUFBMSUVEIiwgbXV0YXRpb249bXV0YXRlZCwgKipleHRyYSkKICAgIGlmIGFwcGxpZWQ6CiAgICAgICAgcmV0dXJuIGRvbmUoIkFQUExJRURfUEFSVElBTCIsIHJlYXNvbj0icGFydGlhbCIsIG11dGF0aW9uPW11dGF0ZWQsICoqZXh0cmEpCiAgICByZXR1cm4gZG9uZSgiRkFJTEVEX05PVF9DT01NSVRURUQiLCByZWFzb249Im5vLW9iamVjdC1hcHBsaWVkIiwgbXV0YXRpb249bXV0YXRlZCwgKipleHRyYSkKCgpkZWYgY29udHJvbF9yZXN1bHRfdG9fcmVwb3J0KHJlc3VsdCwgc3RhcnRlZF9hdCwgZmluaXNoZWRfYXQpOgogICAgcmV0dXJuIHsKICAgICAgICAiYWRhcHRlcl9pZCI6IHJlc3VsdFsiYWRhcHRlcl9pZCJdLAogICAgICAgICJtZWNoYW5pc21faWQiOiByZXN1bHRbIm1lY2hhbmlzbV9pZCJdLAogICAgICAgICJjb250cm9sX2lkIjogcmVzdWx0WyJjb250cm9sX2lkIl0sCiAgICAgICAgInRhcmdldCI6IHJlc3VsdFsidGFyZ2V0Il0sCiAgICAgICAgIm91dGNvbWUiOiByZXN1bHRbIm91dGNvbWUiXSwKICAgICAgICAicmVhc29uIjogcmVzdWx0WyJyZWFzb24iXSwKICAgICAgICAiY3VycmVudF9tb2RlIjogcmVzdWx0WyJjdXJyZW50X21vZGUiXSwKICAgICAgICAidmlvbGF0b3JzIjogbGlzdChyZXN1bHRbInZpb2xhdG9ycyJdKSwKICAgICAgICAiYXBwbGllZCI6IGxpc3QocmVzdWx0WyJhcHBsaWVkIl0pLAogICAgICAgICJza2lwcGVkIjogW2RpY3QoaXRlbSkgZm9yIGl0ZW0gaW4gcmVzdWx0WyJza2lwcGVkIl1dLAogICAgICAgICJmYWlsZWQiOiBbZGljdChpdGVtKSBmb3IgaXRlbSBpbiByZXN1bHRbImZhaWxlZCJdXSwKICAgICAgICAic3RhcnRlZF9hdCI6IHN0YXJ0ZWRfYXQsCiAgICAgICAgImZpbmlzaGVkX2F0IjogZmluaXNoZWRfYXQsCiAgICAgICAgImFjdGlvbnNfYXR0ZW1wdGVkIjogbGlzdChyZXN1bHRbImFjdGlvbnNfYXR0ZW1wdGVkIl0pLAogICAgICAgICJzdGVwX3JjIjogb3V0Y29tZV9yY19jb250cmlidXRpb24ocmVzdWx0WyJvdXRjb21lIl0sIHJlc3VsdFsiZHJ5X3J1biJdKSwKICAgICAgICAibXV0YXRpb25fcGVyZm9ybWVkIjogcmVzdWx0WyJtdXRhdGlvbl9wZXJmb3JtZWQiXSwKICAgICAgICAidHJhbnNhY3Rpb25fY29tbWl0IjogcmVzdWx0WyJ0cmFuc2FjdGlvbl9jb21taXQiXSwKICAgIH0K"},"pam-wheel-access":{"adapter_id":"product-pam-wheel-su-apply-v1","apply_kind":"pam-wheel-su-v1","implementation_sha256":"d06b490ca0fe4f93a99b8dae0ef6f6dae5f2d9f20c0870c5c06ff8a2fb0c8b9a","mechanism_id":"pam-wheel-su-v1","source_b64":"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiJwcm9kdWN0LXBhbS13aGVlbC1zdS1hcHBseS12MS4KCkFQUExZIGFkYXB0ZXIgZm9yIG1lY2hhbmlzbSBgcGFtLXdoZWVsLXN1LXYxYCAoMi4yLjEgYHN1LXdoZWVsLWFjY2Vzc2AsIFNSQy0wMDAzKS4KClBVUlBPU0U9REVGRU5TSVZFX0NPTVBMSUFOQ0VfVkFMSURBVElPTgpBdXRob3JpdHk6IHByb2R1Y3QvY29udHJhY3RzL21lY2hhbmlzbS1wYW0td2hlZWwtc3UtdjEuanNvbgoK0KDQtdGI0LXQvdC40Y8g0YfQtdC70L7QstC10LrQsCAyNS4wOS4yMDI2OgoKMS4gYC9ldGMvcGFtLmQvc3VgINC80LXQvdGP0LXRgtGB0Y8g0YLQvtC70YzQutC+INC10YHQu9C4INC+0L0g0L/QvtCx0LDQudGC0L3QviDRgNCw0LLQtdC9INGE0LDQudC70YMg0L/QsNC60LXRgtCwIHV0aWwtbGludXgKICAgKGBQQU1fUEFDS0FHRV9TSEEyNTZgLCDQvtC00LjQvdCw0LrQvtCyINC90LAg0LLRgdC10YUg0YHQtdC80Lgg0Y3RgtCw0LvQvtC90L3Ri9GFINGB0YDQtdC00LDRhSk6INC30LDQutC+0LzQvNC10L3RgtC40YDQvtCy0LDQvdC90LDRjwogICDRgdGC0YDQvtC60LAgYCMgYXV0aCAgICAgICByZXF1aXJlZCAgIHBhbV93aGVlbC5zb2Ag0LfQsNC80LXQvdGP0LXRgtGB0Y8g0L3QsAogICBgYXV0aCAgICAgICByZXF1aXJlZCAgIHBhbV93aGVlbC5zbyB1c2VfdWlkYCAodG1wICsgcmVuYW1lLCDRgNC10LbQuNC8INC4INCy0LvQsNC00LXQu9C10YYKICAg0L/RgNC10LbQvdC40LUpLiDQm9GO0LHQvtC1INC00YDRg9Cz0L7QtSDRgdC+0LTQtdGA0LbQuNC80L7QtSDigJQgQUJPUlRFRF9QUkVDT05ESVRJT05fQ09ORkxJQ1QsINCx0LvQvtC6CiAgIMKr0YDQtdGI0LXQvdC40LUg0LDQtNC80LjQvdC40YHRgtGA0LDRgtC+0YDQsMK7INGBINCz0L7RgtC+0LLQvtC5INGB0YLRgNC+0LrQvtC5LgoyLiDQndC10YIg0LPRgNGD0L/Qv9GLIGB3aGVlbGAg4oCUIGBncm91cGFkZCAtLXN5c3RlbSB3aGVlbGAgKEdJRCDQstGL0LHQuNGA0LDQtdGCINGB0LjRgdGC0LXQvNCwKSwg0LfQsNGC0LXQvAogICBgZ3Bhc3N3ZCAtYSByb290IHdoZWVsYDsg0LXRgdGC0Ywg4oCUINGC0L7Qu9GM0LrQviDQtNC+0LHQsNCy0LvRj9C10YLRgdGPIGByb290YCwg0L/RgNC+0YfQuNC1INGD0YfQsNGB0YLQvdC40LrQuCDQvdC1CiAgINC80LXQvdGP0Y7RgtGB0Y8uIGA8dXNlciBsaXN0PmAg0LjRgdGC0L7Rh9C90LjQutCwIOKAlCDRgNC10YjQtdC90LjQtSDQsNC00LzQuNC90LjRgdGC0YDQsNGC0L7RgNCwLgozLiDQn9C+0YHQu9C1INC30LDQv9C40YHQuCBgc3VgINC00L7RgdGC0YPQv9C10L0g0YLQvtC70YzQutC+INGD0YfQsNGB0YLQvdC40LrQsNC8IGB3aGVlbGAsINGC0L4g0LXRgdGC0YwgYHJvb3RgOiDQt9Cw0L/QuNGB0YwKICAg0LLRi9C/0L7Qu9C90Y/QtdGC0YHRjywg0YLQvtC70YzQutC+INC10YHQu9C4INCyINCz0YDRg9C/0L/QtSBgc3Vkb2Ag0LjQu9C4IGBhZG1pbmAgKNC/0L7Qu9C1INGD0YfQsNGB0YLQvdC40LrQvtCyCiAgIGAvZXRjL2dyb3VwYCkg0LXRgdGC0Ywg0YXQvtGC0Y8g0LHRiyDQvtC00LjQvSDQv9C+0LvRjNC30L7QstCw0YLQtdC70Yw7INC40L3QsNGH0LUg4oCUINCx0LvQvtC6IMKr0YDQtdGI0LXQvdC40LUg0LDQtNC80LjQvdC40YHRgtGA0LDRgtC+0YDQsMK7Lgo0LiDQodC90LDRh9Cw0LvQsCDQs9GA0YPQv9C/0LAsINC30LDRgtC10LwgUEFNLiDQntGI0LjQsdC60LAg0LfQsNC/0LjRgdC4IFBBTSDQuNC70Lgg0LjRgtC+0LPQvtCy0L7QuSDQv9GA0L7QstC10YDQutC4IOKAlCDRgdC+0LfQtNCw0L3QvdCw0Y8KICAg0Y3RgtC40Lwg0LfQsNC/0YPRgdC60L7QvCDQs9GA0YPQv9C/0LAg0YPQtNCw0LvRj9C10YLRgdGPIChgZ3JvdXBkZWxgKSwg0LTQvtCx0LDQstC70LXQvdC90YvQuSBgcm9vdGAg0YPQsdC40YDQsNC10YLRgdGPCiAgIChgZ3Bhc3N3ZCAtZGApLCDQv9GA0LXQttC90LjQtSDQsdCw0LnRgtGLIFBBTSDQstC+0LfQstGA0LDRidCw0Y7RgtGB0Y8uCiIiIgoKZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9ucwoKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IG9zCmltcG9ydCByZQppbXBvcnQgc3RhdAppbXBvcnQgc3VicHJvY2VzcwoKQURBUFRFUl9JRCA9ICJwcm9kdWN0LXBhbS13aGVlbC1zdS1hcHBseS12MSIKTUVDSEFOSVNNX0lEID0gInBhbS13aGVlbC1zdS12MSIKVEFSR0VUX0lEID0gImxpbnV4LXg4Nl82NC1zdXBwb3J0ZWQtdjEiClBBUkFNRVRFUl9LSU5EID0gInBhbS13aGVlbC1hY2Nlc3MiCgpDT05UUk9MX0lEID0gIkZTVEVDLUxJTlVYLTIwMjItMi4yLjEtU1UtV0hFRUwtQUNDRVNTIgpDT05UUk9MX1NQRUMgPSAoInBvbGljeSIsICJwYW0td2hlZWwtcm9vdC1tZW1iZXIiLCAiYXV0aCByZXF1aXJlZCBwYW1fd2hlZWwuc28gdXNlX3VpZDt3aGVlbDpyb290IikKClBBTV9TVSA9ICIvZXRjL3BhbS5kL3N1IgpHUk9VUCA9ICIvZXRjL2dyb3VwIgpHUk9VUEFERCA9ICIvdXNyL3NiaW4vZ3JvdXBhZGQiCkdST1VQREVMID0gIi91c3Ivc2Jpbi9ncm91cGRlbCIKR1BBU1NXRCA9ICIvdXNyL2Jpbi9ncGFzc3dkIgpUT09MX1RJTUVPVVQgPSA2MAoKUEFNX1BBQ0tBR0VfU0hBMjU2ID0gImZkYTE2NjIyZGM2MTk4ZWFlNWQ2YWU1MjJiYjgyMGI3YjY4ZGJmMmU3Mzg5OTI5NWM0Y2FjOTc0NGY3Yzc5MDQiClBBTV9BUFBMSUVEX1NIQTI1NiA9ICI4YzNiYzllNTYzYjZkNTMzNzk4MGU1YTE2NDZiYjM2YjAwZTgwM2RmZTYxZDFmOThhMzFjYTBjZGZiNWEwNTRjIgpQQU1fTElORV9PTEQgPSBiIiMgYXV0aCAgICAgICByZXF1aXJlZCAgIHBhbV93aGVlbC5zb1xuIgpQQU1fTElORV9ORVcgPSBiImF1dGggICAgICAgcmVxdWlyZWQgICBwYW1fd2hlZWwuc28gdXNlX3VpZFxuIgpTVURPX0dST1VQUyA9ICgic3VkbyIsICJhZG1pbiIpCgpBQ1RJT05fUEFNID0gKCIvZXRjL3BhbS5kL3N1INC+0YLQu9C40YfQsNC10YLRgdGPINC+0YIg0YTQsNC50LvQsCDQv9Cw0LrQtdGC0LA6INC00L7QsdCw0LLRjNGC0LUg0YHRgtGA0L7QutGDIMKrYXV0aCByZXF1aXJlZCBwYW1fd2hlZWwuc28gdXNlX3VpZMK7ICIKICAgICAgICAgICAgICAi0L/QvtGB0LvQtSDCq2F1dGggc3VmZmljaWVudCBwYW1fcm9vdG9rLnNvwrssINGB0L7Qt9C00LDQudGC0LUg0LPRgNGD0L/Qv9GDIHdoZWVsINC4INCy0LrQu9GO0YfQuNGC0LUg0LIg0L3QtdGRIHJvb3QuIikKQUNUSU9OX05PX1NVRE8gPSAoItCyINCz0YDRg9C/0L/QsNGFIHN1ZG8g0LggYWRtaW4g0L3QtdGCINC/0L7Qu9GM0LfQvtCy0LDRgtC10LvQtdC5OiDQv9C+0YHQu9C1INC+0LPRgNCw0L3QuNGH0LXQvdC40Y8gc3Ug0L/QvtCy0YvRgdC40YLRjCDQv9GA0LDQstCwINGB0LzQvtC20LXRgiDRgtC+0LvRjNC60L4gIgogICAgICAgICAgICAgICAgICAicm9vdDsg0L3QsNC30L3QsNGH0YzRgtC1INCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGA0LAg0LIg0LPRgNGD0L/Qv9GDIHN1ZG8g0LjQu9C4INCy0YvQv9C+0LvQvdC40YLQtSDQvdCw0YHRgtGA0L7QudC60YMg0LLRgNGD0YfQvdGD0Y4uIikKCk9VVENPTUVTID0gKAogICAgIkFQUExJRUQiLAogICAgIkFMUkVBRFlfQ09NUExJQU5UIiwKICAgICJEUllfUlVOX1dPVUxEX0FQUExZIiwKICAgICJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiLAogICAgIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwKICAgICJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsCiAgICAiRkFJTEVEX05PVF9DT01NSVRURUQiLAogICAgIkZBSUxFRF9DT01QRU5TQVRJT04iLAopCkNPTU1JVF9DT01NSVRURUQgPSAiQ09NTUlUVEVEIgpDT01NSVRfTk9UX0NPTU1JVFRFRCA9ICJOT1RfQ09NTUlUVEVEIgpDT01NSVRfTk9UX1NUQVJURUQgPSAiTk9UX1NUQVJURUQiCgpDT05UUk9MX0lEX1BBVFRFUk4gPSByIl4oPyEuKltcclxuXSlbQS1aYS16MC05Ll8tXSskIgoKCmNsYXNzIF9SZWZ1c2VkKEV4Y2VwdGlvbik6CiAgICBkZWYgX19pbml0X18oc2VsZiwgb3V0Y29tZSwgcmVhc29uLCBkZWNpc2lvbj1Ob25lKToKICAgICAgICBzdXBlcigpLl9faW5pdF9fKHJlYXNvbikKICAgICAgICBzZWxmLm91dGNvbWUgPSBvdXRjb21lCiAgICAgICAgc2VsZi5yZWFzb24gPSByZWFzb24KICAgICAgICBzZWxmLmRlY2lzaW9uID0gZGVjaXNpb24KCgpkZWYgdmFsaWRhdGVfY29udHJvbF9pbnB1dChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgYXBwbHlfc3VwcG9ydGVkKToKICAgICIiIkZhaWwtY2xvc2VkIHZhbGlkYXRpb24gb2Ygb25lIGNvbnRyb2wgcm93LiBSYWlzZXMgVmFsdWVFcnJvci4iIiIKICAgIGlmIG5vdCBpc2luc3RhbmNlKGNvbnRyb2xfaWQsIHN0cikgb3Igbm90IHJlLmZ1bGxtYXRjaChDT05UUk9MX0lEX1BBVFRFUk4sIGNvbnRyb2xfaWQpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImludmFsaWQgY29udHJvbCBpZCIpCiAgICBpZiBub3QgaXNpbnN0YW5jZShrZXksIHN0cikgb3Igbm90IGlzaW5zdGFuY2Uob3AsIHN0cikgb3Igbm90IGlzaW5zdGFuY2UoZXhwZWN0ZWQsIHN0cik6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigia2V5LCBvcCBhbmQgZXhwZWN0ZWQgbXVzdCBiZSBzdHJpbmdzIikKICAgIGlmIG5vdCBpc2luc3RhbmNlKGFwcGx5X3N1cHBvcnRlZCwgYm9vbCk6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigiYXBwbHlfc3VwcG9ydGVkIG11c3QgYmUgYm9vbCIpCiAgICByZXR1cm4gVHJ1ZQoKCmRlZiBfcChyb290LCBwYXRoKToKICAgIHJldHVybiBwYXRoIGlmIHJvb3QgaXMgTm9uZSBlbHNlIG9zLnBhdGguam9pbihyb290LCBwYXRoLmxzdHJpcCgiLyIpKQoKCmRlZiBfYWRtaW4oYWN0aW9uKToKICAgIHJldHVybiB7ImNsYXNzIjogIkFETUlOX0FDVElPTl9SRVFVSVJFRCIsICJyZXF1aXJlZCI6IFRydWUsICJhY3Rpb24iOiBhY3Rpb259CgoKZGVmIF9yZWFkX3BhbShyb290KToKICAgICIiIijQsdCw0LnRgtGLLCBzdGF0KSAvZXRjL3BhbS5kL3N1OyDQvdC1INC+0LHRi9GH0L3Ri9C5INGE0LDQudC7LCDRh9GD0LbQvtC5INCy0LvQsNC00LXQu9C10YYg0LjQu9C4INC30LDQv9C40YHRjCDQtNC70Y8g0LPRgNGD0L/Qv9GLIOKAlCDQvtGC0LrQsNC3LiIiIgogICAgcGF0aCA9IF9wKHJvb3QsIFBBTV9TVSkKICAgIHRyeToKICAgICAgICBmZCA9IG9zLm9wZW4ocGF0aCwgb3MuT19SRE9OTFkgfCBvcy5PX05PRk9MTE9XKQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwgInBhbTpyZWFkLWZhaWxlZCIpCiAgICB0cnk6CiAgICAgICAgc3QgPSBvcy5mc3RhdChmZCkKICAgICAgICBpZiBub3Qgc3RhdC5TX0lTUkVHKHN0LnN0X21vZGUpIG9yIHN0YXQuU19JTU9ERShzdC5zdF9tb2RlKSAmIDBvMDIyIG9yIChyb290IGlzIE5vbmUgYW5kIHN0LnN0X3VpZCAhPSAwKToKICAgICAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwgInBhbTp1bnRydXN0ZWQiLCBfYWRtaW4oQUNUSU9OX1BBTSkpCiAgICAgICAgY2h1bmtzID0gW10KICAgICAgICB3aGlsZSBUcnVlOgogICAgICAgICAgICBjaHVuayA9IG9zLnJlYWQoZmQsIDY1NTM2KQogICAgICAgICAgICBpZiBub3QgY2h1bms6CiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICBjaHVua3MuYXBwZW5kKGNodW5rKQogICAgZmluYWxseToKICAgICAgICBvcy5jbG9zZShmZCkKICAgIHJldHVybiBiIiIuam9pbihjaHVua3MpLCBzdAoKCmRlZiBwYW1fc3RhdGUocmF3KToKICAgIGRpZ2VzdCA9IGhhc2hsaWIuc2hhMjU2KHJhdykuaGV4ZGlnZXN0KCkKICAgIGlmIGRpZ2VzdCA9PSBQQU1fQVBQTElFRF9TSEEyNTY6CiAgICAgICAgcmV0dXJuICJhcHBsaWVkIgogICAgaWYgZGlnZXN0ID09IFBBTV9QQUNLQUdFX1NIQTI1NiBhbmQgcmF3LmNvdW50KFBBTV9MSU5FX09MRCkgPT0gMToKICAgICAgICByZXR1cm4gInBhY2thZ2UiCiAgICByZXR1cm4gImZvcmVpZ24iCgoKZGVmIF9yZWFkX2dyb3Vwcyhyb290KToKICAgIHRyeToKICAgICAgICB3aXRoIG9wZW4oX3Aocm9vdCwgR1JPVVApLCAiciIsIGVuY29kaW5nPSJ1dGYtOCIsIGVycm9ycz0ic3RyaWN0IikgYXMgc3RyZWFtOgogICAgICAgICAgICBsaW5lcyA9IHN0cmVhbS5yZWFkKCkuc3BsaXQoIlxuIikKICAgIGV4Y2VwdCAoT1NFcnJvciwgVW5pY29kZURlY29kZUVycm9yKToKICAgICAgICByYWlzZSBfUmVmdXNlZCgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLCAiZ3JvdXA6cmVhZC1mYWlsZWQiKQogICAgZ3JvdXBzID0ge30KICAgIGZvciBsaW5lIGluIGxpbmVzOgogICAgICAgIGlmIG5vdCBsaW5lIG9yIGxpbmUuc3RhcnRzd2l0aCgiIyIpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGZpZWxkcyA9IGxpbmUuc3BsaXQoIjoiKQogICAgICAgIGlmIGxlbihmaWVsZHMpICE9IDQ6CiAgICAgICAgICAgIHJhaXNlIF9SZWZ1c2VkKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsICJncm91cDppbnZhbGlkLWxpbmUiKQogICAgICAgIGlmIGZpZWxkc1swXSBpbiBncm91cHM6CiAgICAgICAgICAgIGlmIGZpZWxkc1swXSA9PSAid2hlZWwiOgogICAgICAgICAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwgImdyb3VwOmR1cGxpY2F0ZS13aGVlbCIsIF9hZG1pbihBQ1RJT05fUEFNKSkKICAgICAgICAgICAgY29udGludWUKICAgICAgICBncm91cHNbZmllbGRzWzBdXSA9IChmaWVsZHNbMl0sIFttIGZvciBtIGluIGZpZWxkc1szXS5zcGxpdCgiLCIpIGlmIG1dKQogICAgcmV0dXJuIGdyb3VwcwoKCmRlZiBwb2xpY3lfY3VycmVudChzdGF0ZSwgZ3JvdXBzKToKICAgIHBhbSA9IHsiYXBwbGllZCI6ICJwcmVzZW50IiwgInBhY2thZ2UiOiAiYWJzZW50In0uZ2V0KHN0YXRlLCAibm90LWRldGVybWluZWQiKQogICAgd2hlZWwgPSBncm91cHMuZ2V0KCJ3aGVlbCIpCiAgICByZXR1cm4gInBhbV93aGVlbD0lczt3aGVlbD0lcztyb290PSVzIiAlICgKICAgICAgICBwYW0sICJhYnNlbnQiIGlmIHdoZWVsIGlzIE5vbmUgZWxzZSAiZ2lkICIgKyB3aGVlbFswXSwKICAgICAgICAibWVtYmVyIiBpZiB3aGVlbCBpcyBub3QgTm9uZSBhbmQgInJvb3QiIGluIHdoZWVsWzFdIGVsc2UgIm1pc3NpbmciKQoKCmRlZiBfZGVmYXVsdF9ydW4oYXJndiwgdGltZW91dCk6CiAgICByZXR1cm4gc3VicHJvY2Vzcy5ydW4oYXJndiwgc3RkaW49c3VicHJvY2Vzcy5ERVZOVUxMLCBzdGRvdXQ9c3VicHJvY2Vzcy5QSVBFLCBzdGRlcnI9c3VicHJvY2Vzcy5QSVBFLAogICAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQ9dGltZW91dCwgZW52PXsiUEFUSCI6ICIvdXNyL3NiaW46L3Vzci9iaW46L3NiaW46L2JpbiIsICJMQ19BTEwiOiAiQyJ9KQoKCmRlZiBfdG9vbChyb290LCBydW4sIHBhdGgsICphcmdzKToKICAgIHRyeToKICAgICAgICBjcCA9IHJ1bihbX3Aocm9vdCwgcGF0aCksICphcmdzXSwgVE9PTF9USU1FT1VUKQogICAgZXhjZXB0IChPU0Vycm9yLCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIHJldHVybiBjcC5yZXR1cm5jb2RlID09IDAKCgpkZWYgX2NoZWNrX3Rvb2xzKHJvb3QsIHBhdGhzKToKICAgIGZvciBwYXRoIGluIHBhdGhzOgogICAgICAgIHRyeToKICAgICAgICAgICAgc3QgPSBvcy5zdGF0KF9wKHJvb3QsIHBhdGgpKQogICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICByYWlzZSBfUmVmdXNlZCgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLCAidG9vbHM6bWlzc2luZzoiICsgb3MucGF0aC5iYXNlbmFtZShwYXRoKSkKICAgICAgICBpZiBub3Qgc3RhdC5TX0lTUkVHKHN0LnN0X21vZGUpIG9yIG5vdCBzdC5zdF9tb2RlICYgMG8xMTE6CiAgICAgICAgICAgIHJhaXNlIF9SZWZ1c2VkKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsICJ0b29sczptaXNzaW5nOiIgKyBvcy5wYXRoLmJhc2VuYW1lKHBhdGgpKQoKCmRlZiBfd3JpdGVfcGFtKHJvb3QsIHJhdywgc3QpOgogICAgcGF0aCA9IF9wKHJvb3QsIFBBTV9TVSkKICAgIHRtcCA9IHBhdGggKyAiLnNscC10bXAiCiAgICBmZCA9IG9zLm9wZW4odG1wLCBvcy5PX1dST05MWSB8IG9zLk9fQ1JFQVQgfCBvcy5PX0VYQ0wgfCBvcy5PX05PRk9MTE9XLCAwbzYwMCkKICAgIHRyeToKICAgICAgICBvcy53cml0ZShmZCwgcmF3KQogICAgICAgIG9zLmZjaG1vZChmZCwgc3RhdC5TX0lNT0RFKHN0LnN0X21vZGUpKQogICAgICAgIGlmIHJvb3QgaXMgTm9uZToKICAgICAgICAgICAgb3MuZmNob3duKGZkLCBzdC5zdF91aWQsIHN0LnN0X2dpZCkKICAgICAgICBvcy5mc3luYyhmZCkKICAgIGV4Y2VwdCBCYXNlRXhjZXB0aW9uOgogICAgICAgIG9zLmNsb3NlKGZkKQogICAgICAgIG9zLnVubGluayh0bXApCiAgICAgICAgcmFpc2UKICAgIG9zLmNsb3NlKGZkKQogICAgb3MucmVwbGFjZSh0bXAsIHBhdGgpCgoKZGVmIF9kZWZhdWx0X3ByaXZpbGVnZV9jaGVjaygpIC0+IGJvb2w6CiAgICByZXR1cm4gb3MuZ2V0ZXVpZCgpID09IDAKCgpkZWYgX2NvbW1pdF9zdGF0ZShvdXRjb21lLCBkcnlfcnVuLCBtdXRhdGlvbik6CiAgICBpZiBvdXRjb21lID09ICJBUFBMSUVEIiBvciAob3V0Y29tZSA9PSAiQUxSRUFEWV9DT01QTElBTlQiIGFuZCBub3QgZHJ5X3J1bik6CiAgICAgICAgcmV0dXJuIENPTU1JVF9DT01NSVRURUQKICAgIGlmIG11dGF0aW9uOgogICAgICAgIHJldHVybiBDT01NSVRfTk9UX0NPTU1JVFRFRAogICAgcmV0dXJuIENPTU1JVF9OT1RfU1RBUlRFRAoKCmRlZiBfcmVzdWx0KGNvbnRyb2xfaWQsIG91dGNvbWUsICosIGFjdGlvbnMsIGRyeV9ydW4sIG11dGF0aW9uPUZhbHNlLCAqKmV4dHJhKToKICAgIHJlY29yZCA9IHsKICAgICAgICAiYWRhcHRlcl9pZCI6IEFEQVBURVJfSUQsCiAgICAgICAgIm1lY2hhbmlzbV9pZCI6IE1FQ0hBTklTTV9JRCwKICAgICAgICAiY29udHJvbF9pZCI6IGNvbnRyb2xfaWQsCiAgICAgICAgInRhcmdldCI6IFBBTV9TVSwKICAgICAgICAib3V0Y29tZSI6IG91dGNvbWUsCiAgICAgICAgInJlYXNvbiI6IE5vbmUsCiAgICAgICAgInBvbGljeV9jdXJyZW50IjogTm9uZSwKICAgICAgICAib3BlcmF0b3JfZGVjaXNpb24iOiBOb25lLAogICAgICAgICJhY3Rpb25zX2F0dGVtcHRlZCI6IGxpc3QoYWN0aW9ucyksCiAgICAgICAgIm11dGF0aW9uX3BlcmZvcm1lZCI6IGJvb2wobXV0YXRpb24pLAogICAgICAgICJ0cmFuc2FjdGlvbl9jb21taXQiOiBfY29tbWl0X3N0YXRlKG91dGNvbWUsIGRyeV9ydW4sIG11dGF0aW9uKSwKICAgICAgICAiZHJ5X3J1biI6IGJvb2woZHJ5X3J1biksCiAgICB9CiAgICByZWNvcmQudXBkYXRlKGV4dHJhKQogICAgaWYgcmVjb3JkWyJvdXRjb21lIl0gbm90IGluIE9VVENPTUVTOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoIm91dGNvbWUgb3V0c2lkZSBjbG9zZWQgdm9jYWJ1bGFyeSIpCiAgICByZXR1cm4gcmVjb3JkCgoKZGVmIG91dGNvbWVfcmNfY29udHJpYnV0aW9uKG91dGNvbWUsIGRyeV9ydW49RmFsc2UpOgogICAgIiIiIjAiINC00LvRjyDRg9GB0L/QtdGI0L3Ri9GFINC40YHRhdC+0LTQvtCyLCDQuNC90LDRh9C1ICJub256ZXJvIi4iIiIKICAgIGlmIG91dGNvbWUgaW4gKCJBUFBMSUVEIiwgIkFMUkVBRFlfQ09NUExJQU5UIiwgIk5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRCIpOgogICAgICAgIHJldHVybiAiMCIKICAgIGlmIGRyeV9ydW4gYW5kIG91dGNvbWUgPT0gIkRSWV9SVU5fV09VTERfQVBQTFkiOgogICAgICAgIHJldHVybiAiMCIKICAgIHJldHVybiAibm9uemVybyIKCgpkZWYgZXhlY3V0ZV9jb250cm9sKGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQsICosIGRyeV9ydW4sCiAgICAgICAgICAgICAgICAgICAgcHJpdmlsZWdlX2NoZWNrPU5vbmUsIF9yb290PU5vbmUsIF9ydW49Tm9uZSwgX3dyaXRlPU5vbmUpOgogICAgIiIiUmVzdHJpY3Qgc3UgdG8gdGhlIHdoZWVsIGdyb3VwIHRocm91Z2ggL2V0Yy9wYW0uZC9zdSBhbmQgL2V0Yy9ncm91cC4KCiAgICBgX3Jvb3RgLCBgX3J1bmAg0LggYF93cml0ZWAg4oCUINGC0L7Qu9GM0LrQviDQtNC70Y8g0YLQtdGB0YLQvtCyOiDQutC+0YDQtdC90Ywg0YTQsNC50LvQvtCy0L7QuSDRgdC40YHRgtC10LzRiywg0LfQsNC/0YPRgdC6CiAgICDQutC+0LzQsNC90LQg0Lgg0LfQsNC/0LjRgdGMIFBBTS3RhNCw0LnQu9CwLgogICAgIiIiCiAgICB2YWxpZGF0ZV9jb250cm9sX2lucHV0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQpCiAgICBhY3Rpb25zID0gWyJQMF9FTElHSUJJTElUWSJdCiAgICBydW4gPSBfcnVuIGlmIF9ydW4gaXMgbm90IE5vbmUgZWxzZSBfZGVmYXVsdF9ydW4KICAgIHdyaXRlID0gX3dyaXRlIGlmIF93cml0ZSBpcyBub3QgTm9uZSBlbHNlIF93cml0ZV9wYW0KICAgIGN1cnJlbnQgPSBOb25lCgogICAgZGVmIGRvbmUob3V0Y29tZSwgKipleHRyYSk6CiAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwgb3V0Y29tZSwgYWN0aW9ucz1hY3Rpb25zLCBkcnlfcnVuPWRyeV9ydW4sIHBvbGljeV9jdXJyZW50PWN1cnJlbnQsICoqZXh0cmEpCgogICAgaWYgbm90IGFwcGx5X3N1cHBvcnRlZDoKICAgICAgICByZXR1cm4gZG9uZSgiTk9UX0VMSUdJQkxFX0FQUExZX1VOU1VQUE9SVEVEIiwgcmVhc29uPSJhcHBseS11bnN1cHBvcnRlZCIpCiAgICBpZiBjb250cm9sX2lkICE9IENPTlRST0xfSUQgb3IgKGtleSwgb3AsIGV4cGVjdGVkKSAhPSBDT05UUk9MX1NQRUM6CiAgICAgICAgcmV0dXJuIGRvbmUoIk5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRCIsIHJlYXNvbj0ib3AtdW5zdXBwb3J0ZWQiKQoKICAgIHRyeToKICAgICAgICBhY3Rpb25zLmFwcGVuZCgiUDFfT0JTRVJWRSIpCiAgICAgICAgcmF3LCBzdCA9IF9yZWFkX3BhbShfcm9vdCkKICAgICAgICBzdGF0ZSA9IHBhbV9zdGF0ZShyYXcpCiAgICAgICAgZ3JvdXBzID0gX3JlYWRfZ3JvdXBzKF9yb290KQogICAgICAgIGN1cnJlbnQgPSBwb2xpY3lfY3VycmVudChzdGF0ZSwgZ3JvdXBzKQogICAgICAgIGlmIHN0YXRlID09ICJmb3JlaWduIjoKICAgICAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwgInBhbTpmb3JlaWduLWNvbnRlbnQiLCBfYWRtaW4oQUNUSU9OX1BBTSkpCiAgICAgICAgd2hlZWwgPSBncm91cHMuZ2V0KCJ3aGVlbCIpCiAgICAgICAgY3JlYXRlID0gd2hlZWwgaXMgTm9uZQogICAgICAgIGFkZF9yb290ID0gY3JlYXRlIG9yICJyb290IiBub3QgaW4gd2hlZWxbMV0KICAgICAgICBpZiBzdGF0ZSA9PSAiYXBwbGllZCIgYW5kIG5vdCBhZGRfcm9vdDoKICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkFMUkVBRFlfQ09NUExJQU5UIikKCiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlAyX1BMQU4iKQogICAgICAgIGlmIG5vdCBhbnkoZ3JvdXBzLmdldChuYW1lLCAoIiIsIFtdKSlbMV0gZm9yIG5hbWUgaW4gU1VET19HUk9VUFMpOgogICAgICAgICAgICByYWlzZSBfUmVmdXNlZCgiQUJPUlRFRF9QUkVDT05ESVRJT05fQ09ORkxJQ1QiLCAic3U6bm8tc3Vkby1tZW1iZXJzIiwgX2FkbWluKEFDVElPTl9OT19TVURPKSkKICAgICAgICBfY2hlY2tfdG9vbHMoX3Jvb3QsIChbR1JPVVBBREQsIEdST1VQREVMXSBpZiBjcmVhdGUgZWxzZSBbXSkgKyAoW0dQQVNTV0RdIGlmIGFkZF9yb290IGVsc2UgW10pKQogICAgICAgIGlmIGRyeV9ydW46CiAgICAgICAgICAgIHJldHVybiBkb25lKCJEUllfUlVOX1dPVUxEX0FQUExZIikKCiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlAzX1BSSVZJTEVHRSIpCiAgICAgICAgY2hlY2sgPSBwcml2aWxlZ2VfY2hlY2sgaWYgcHJpdmlsZWdlX2NoZWNrIGlzIG5vdCBOb25lIGVsc2UgX2RlZmF1bHRfcHJpdmlsZWdlX2NoZWNrCiAgICAgICAgaWYgbm90IGNoZWNrKCk6CiAgICAgICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsIHJlYXNvbj0icHJpdmlsZWdlIikKICAgIGV4Y2VwdCBfUmVmdXNlZCBhcyBleGM6CiAgICAgICAgcmV0dXJuIGRvbmUoZXhjLm91dGNvbWUsIHJlYXNvbj1leGMucmVhc29uLCBvcGVyYXRvcl9kZWNpc2lvbj1leGMuZGVjaXNpb24pCgogICAgY3JlYXRlZCA9IHJvb3RfYWRkZWQgPSBwYW1fd3JpdHRlbiA9IEZhbHNlCgogICAgZGVmIGNvbXBlbnNhdGUocmVhc29uKToKICAgICAgICBhY3Rpb25zLmFwcGVuZCgiQ09NUEVOU0FUSU9OIikKICAgICAgICBvayA9IFRydWUKICAgICAgICBpZiBwYW1fd3JpdHRlbjoKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgd3JpdGUoX3Jvb3QsIHJhdywgc3QpCiAgICAgICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICAgICAgb2sgPSBGYWxzZQogICAgICAgIGlmIGNyZWF0ZWQ6CiAgICAgICAgICAgIG9rID0gX3Rvb2woX3Jvb3QsIHJ1biwgR1JPVVBERUwsICJ3aGVlbCIpIGFuZCBvawogICAgICAgIGVsaWYgcm9vdF9hZGRlZDoKICAgICAgICAgICAgb2sgPSBfdG9vbChfcm9vdCwgcnVuLCBHUEFTU1dELCAiLWQiLCAicm9vdCIsICJ3aGVlbCIpIGFuZCBvawogICAgICAgIG11dGF0ZWQgPSBjcmVhdGVkIG9yIHJvb3RfYWRkZWQgb3IgcGFtX3dyaXR0ZW4KICAgICAgICBpZiBvazoKICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwgcmVhc29uPXJlYXNvbiwgbXV0YXRpb249bXV0YXRlZCkKICAgICAgICByZXR1cm4gZG9uZSgiRkFJTEVEX0NPTVBFTlNBVElPTiIsIHJlYXNvbj1yZWFzb24sIG11dGF0aW9uPW11dGF0ZWQpCgogICAgYWN0aW9ucy5hcHBlbmQoIlBIQVNFMV9HUk9VUCIpCiAgICBpZiBjcmVhdGU6CiAgICAgICAgaWYgbm90IF90b29sKF9yb290LCBydW4sIEdST1VQQURELCAiLS1zeXN0ZW0iLCAid2hlZWwiKToKICAgICAgICAgICAgcmV0dXJuIGNvbXBlbnNhdGUoImdyb3VwOmdyb3VwYWRkLWZhaWxlZCIpCiAgICAgICAgY3JlYXRlZCA9IFRydWUKICAgIGlmIGFkZF9yb290OgogICAgICAgIGlmIG5vdCBfdG9vbChfcm9vdCwgcnVuLCBHUEFTU1dELCAiLWEiLCAicm9vdCIsICJ3aGVlbCIpOgogICAgICAgICAgICByZXR1cm4gY29tcGVuc2F0ZSgiZ3JvdXA6Z3Bhc3N3ZC1mYWlsZWQiKQogICAgICAgIHJvb3RfYWRkZWQgPSBUcnVlCiAgICBpZiBzdGF0ZSA9PSAicGFja2FnZSI6CiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlBIQVNFMl9QQU0iKQogICAgICAgIHRyeToKICAgICAgICAgICAgd3JpdGUoX3Jvb3QsIHJhdy5yZXBsYWNlKFBBTV9MSU5FX09MRCwgUEFNX0xJTkVfTkVXKSwgc3QpCiAgICAgICAgICAgIHBhbV93cml0dGVuID0gVHJ1ZQogICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICByZXR1cm4gY29tcGVuc2F0ZSgicGFtOndyaXRlLWZhaWxlZCIpCiAgICBhY3Rpb25zLmFwcGVuZCgiRklOQUxfUE9TVENIRUNLIikKICAgIHRyeToKICAgICAgICBhZnRlcl9zdGF0ZSA9IHBhbV9zdGF0ZShfcmVhZF9wYW0oX3Jvb3QpWzBdKQogICAgICAgIGFmdGVyX3doZWVsID0gX3JlYWRfZ3JvdXBzKF9yb290KS5nZXQoIndoZWVsIikKICAgIGV4Y2VwdCBfUmVmdXNlZDoKICAgICAgICByZXR1cm4gY29tcGVuc2F0ZSgicG9zdGNoZWNrOnJlYWQtZmFpbGVkIikKICAgIGlmIGFmdGVyX3N0YXRlICE9ICJhcHBsaWVkIiBvciBhZnRlcl93aGVlbCBpcyBOb25lIG9yICJyb290IiBub3QgaW4gYWZ0ZXJfd2hlZWxbMV06CiAgICAgICAgcmV0dXJuIGNvbXBlbnNhdGUoInBvc3RjaGVjazpub3QtY29tcGxpYW50IikKICAgIHJldHVybiBkb25lKCJBUFBMSUVEIiwgbXV0YXRpb249VHJ1ZSkKCgpkZWYgY29udHJvbF9yZXN1bHRfdG9fcmVwb3J0KHJlc3VsdCwgc3RhcnRlZF9hdCwgZmluaXNoZWRfYXQpOgogICAgcmV0dXJuIHsKICAgICAgICAiYWRhcHRlcl9pZCI6IHJlc3VsdFsiYWRhcHRlcl9pZCJdLAogICAgICAgICJtZWNoYW5pc21faWQiOiByZXN1bHRbIm1lY2hhbmlzbV9pZCJdLAogICAgICAgICJjb250cm9sX2lkIjogcmVzdWx0WyJjb250cm9sX2lkIl0sCiAgICAgICAgInRhcmdldCI6IHJlc3VsdFsidGFyZ2V0Il0sCiAgICAgICAgIm91dGNvbWUiOiByZXN1bHRbIm91dGNvbWUiXSwKICAgICAgICAicmVhc29uIjogcmVzdWx0WyJyZWFzb24iXSwKICAgICAgICAicG9saWN5X2N1cnJlbnQiOiByZXN1bHRbInBvbGljeV9jdXJyZW50Il0sCiAgICAgICAgIm9wZXJhdG9yX2RlY2lzaW9uIjogTm9uZSBpZiByZXN1bHRbIm9wZXJhdG9yX2RlY2lzaW9uIl0gaXMgTm9uZSBlbHNlIGRpY3QocmVzdWx0WyJvcGVyYXRvcl9kZWNpc2lvbiJdKSwKICAgICAgICAic3RhcnRlZF9hdCI6IHN0YXJ0ZWRfYXQsCiAgICAgICAgImZpbmlzaGVkX2F0IjogZmluaXNoZWRfYXQsCiAgICAgICAgImFjdGlvbnNfYXR0ZW1wdGVkIjogbGlzdChyZXN1bHRbImFjdGlvbnNfYXR0ZW1wdGVkIl0pLAogICAgICAgICJzdGVwX3JjIjogb3V0Y29tZV9yY19jb250cmlidXRpb24ocmVzdWx0WyJvdXRjb21lIl0sIHJlc3VsdFsiZHJ5X3J1biJdKSwKICAgICAgICAibXV0YXRpb25fcGVyZm9ybWVkIjogcmVzdWx0WyJtdXRhdGlvbl9wZXJmb3JtZWQiXSwKICAgICAgICAidHJhbnNhY3Rpb25fY29tbWl0IjogcmVzdWx0WyJ0cmFuc2FjdGlvbl9jb21taXQiXSwKICAgIH0K"},"sshd-config-option":{"adapter_id":"product-sshd-config-option-apply-v1","apply_kind":"sshd-config-option-v1","implementation_sha256":"8a820935da88cfbb2b5c931100366cfbf6ba7838136298054756d9577cb59c36","mechanism_id":"sshd-config-option-v1","source_b64":"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiJwcm9kdWN0LXNzaGQtY29uZmlnLW9wdGlvbi1hcHBseS12MS4KCkFQUExZIGFkYXB0ZXIgZm9yIG1lY2hhbmlzbSBgc3NoZC1jb25maWctb3B0aW9uLXYxYCAoZnN0ZWMtY29uZmlndXJhdGlvbi0yMDI2INC/LjkuMSwKU1JDLTAwODgpOiBgUGVybWl0RW1wdHlQYXNzd29yZHMgbm9gLCBgUGVybWl0Um9vdExvZ2luIG5vYCwgYFBhc3N3b3JkQXV0aGVudGljYXRpb24gbm9gCtCyINC+0YHQvdC+0LLQvdC+0LwgYC9ldGMvc3NoL3NzaGRfY29uZmlnYC4KClBVUlBPU0U9REVGRU5TSVZFX0NPTVBMSUFOQ0VfVkFMSURBVElPTgpBdXRob3JpdHk6IHByb2R1Y3QvY29udHJhY3RzL21lY2hhbmlzbS1zc2hkLWNvbmZpZy1vcHRpb24tdjEuanNvbgoK0KDQtdGI0LXQvdC40Y8g0L/QvtC70YzQt9C+0LLQsNGC0LXQu9GPOiBBUFBMWSDQtNC70Y8g0YLRgNGR0YUg0LTQuNGA0LXQutGC0LjQsiDQvy45LjEg0LLRi9C/0L7Qu9C90Y/QtdGC0YHRjyAoMjUuMDkuMjAyNiwg0YLRgNC10LHQvtCy0LDQvdC40LUK0L/QvtC70LjRgtC40LrQuCDQutC+0LzQv9Cw0L3QuNC4KTsg0L/RgNCw0LLQutCwINC90LAg0LzQtdGB0YLQtSwg0LHQtdC3INC00YPQsdC70LjRgNC+0LLQsNC90LjRjyDRgdGC0YDQvtC6ICjRgdGF0LXQvNCwIDHigJM0LCAyNi4wOS4yMDI2KToKCjEuINCU0LXQudGB0YLQstGD0Y7RidCw0Y8g0LPQu9C+0LHQsNC70YzQvdCw0Y8g0YHRgtGA0L7QutCwINC60LvRjtGH0LAg0LIg0L7RgdC90L7QstC90L7QvCDRhNCw0LnQu9C1IOKAlCDQt9C90LDRh9C10L3QuNC1INC80LXQvdGP0LXRgtGB0Y8g0L3QsCBgbm9gLgoyLiDQlNC10LnRgdGC0LLRg9GO0YnQtdC5INC90LXRgiwg0LXRgdGC0Ywg0LfQsNC60L7QvNC80LXQvdGC0LjRgNC+0LLQsNC90L3Ri9C5INGI0LDQsdC70L7QvSBgIzxLZXk+IOKApmAg0LIg0LPQu9C+0LHQsNC70YzQvdC+0Lkg0L7QsdC70LDRgdGC0Lgg4oCUCiAgINC+0L0g0LfQsNC80LXQvdGP0LXRgtGB0Y8g0YHRgtGA0L7QutC+0LkgYDxLZXk+IG5vYCDQvdCwINGC0L7QvCDQttC1INC80LXRgdGC0LUuCjMuINCd0LXRgiDQvdC4INGC0L7Qs9C+LCDQvdC4INC00YDRg9Cz0L7Qs9C+IOKAlCBgPEtleT4gbm9gINC00L7QsdCw0LLQu9GP0LXRgtGB0Y8g0L/QtdGA0LXQtCDQv9C10YDQstGL0LwgYE1hdGNoYCDQuNC70Lgg0LIg0LrQvtC90LXRhi4KNC4g0JLQutC70Y7Rh9Cw0LXQvNGL0LUg0YTQsNC50LvRiyAoYEluY2x1ZGVgLCDQs9C70L7QsdCw0LvRjNC90LDRjyDQvtCx0LvQsNGB0YLRjCksINCz0LTQtSDQutC70Y7RhyDQt9Cw0LTQsNC9INC90LUgYG5vYCwg0L/RgNCw0LLRj9GC0YHRjwogICDQvdCwINC80LXRgdGC0LU6INC30L3QsNGH0LXQvdC40LUg0LzQtdC90Y/QtdGC0YHRjyDQvdCwIGBub2Ag4oCUINC40L3QsNGH0LUg0L7QvdC4INC/0LXRgNC10LrRgNGL0LvQuCDQsdGLINC+0YHQvdC+0LLQvdC+0Lkg0YTQsNC50LsKICAgKHNzaGQg0LHQtdGA0ZHRgiDQv9C10YDQstC+0LUg0L/RgNC+0YfQuNGC0LDQvdC90L7QtSDQt9C90LDRh9C10L3QuNC1KS4KCtCa0LDQttC00YvQuSDQuNC30LzQtdC90Y/QtdC80YvQuSDRhNCw0LnQuyDQs9C+0YLQvtCy0LjRgtGB0Y8g0LLRgNC10LzQtdC90L3Ri9C8INGE0LDQudC70L7QvCDQsiDRgtC+0Lwg0LbQtSDQutCw0YLQsNC70L7Qs9C1ICjRgNC10LbQuNC8INC4INCy0LvQsNC00LXQu9C10YYK0L/RgNC10LbQvdC40LUpINC4INC/0YDQvtCy0LXRgNGP0LXRgtGB0Y8gYHNzaGQgLXRgINC00L4g0LfQsNC80LXQvdGLOyDQv9C+0YHQu9C1INC30LDQvNC10L3RiyDigJQgYHNzaGQgLXRgINCy0YHQtdCz0L4g0LTQtdGA0LXQstCwLApgc3lzdGVtY3RsIHRyeS1yZWxvYWQtb3ItcmVzdGFydCBzc2guc2VydmljZWAg0Lgg0LjRgtC+0LPQvtCy0LDRjyDQv9GA0L7QstC10YDQutCwIGBzc2hkIC1UYC4g0J7RiNC40LHQutCwINC70Y7QsdC+0LkK0LjQtyDQvdC40YUg4oCUINC/0YDQtdC20L3QuNC1INCx0LDQudGC0Ysg0LLRgdC10YUg0LfQsNC80LXQvdGR0L3QvdGL0YUg0YTQsNC50LvQvtCyINCy0L7Qt9Cy0YDQsNGJ0LDRjtGC0YHRjyDQuCDRgdCy0LXRgNGP0Y7RgtGB0Y8gKNC/0L7RgdC70LUg0L/QvtC/0YvRgtC60LgK0L/QtdGA0LXQt9Cw0LPRgNGD0LfQutC4IHNzaGQg0L/QtdGA0LXQt9Cw0LPRgNGD0LbQsNC10YLRgdGPINC/0L7QstGC0L7RgNC90L4pOyDQvdC10YHQvtCy0L/QsNC00LXQvdC40LUg4oCUIEZBSUxFRF9DT01QRU5TQVRJT04uCtCf0YDQsNCy0LjQu9CwIGBJbmNsdWRlYCAo0YHRgdGL0LvQutC4LCDRgtC40L8g0L/RgNC10YTQuNC60YHQsCDRiNCw0LHQu9C+0L3QsCwg0LjQvNC10L3QsCDRgSDQv9C10YDQtdCy0L7QtNC+0Lwg0YHRgtGA0L7QutC4KSDigJQg0LrQsNC6INGDIENIRUNLLgoK0J7RgtC60LDQtyDRgSDQsdC70L7QutC+0LwgwqvRgNC10YjQtdC90LjQtSDQsNC00LzQuNC90LjRgdGC0YDQsNGC0L7RgNCwwrssINCx0LXQtyDQt9Cw0L/QuNGB0Lg6Ci0g0L7RgdC90L7QstC90L7QuSDRhNCw0LnQuyAo0LLRgdC10LPQtNCwLCDQtNC+INC/0YDQuNC30L3QsNC90LjRjyDRgdC+0L7RgtCy0LXRgtGB0YLQstC40Y8pINC40LvQuCDQuNC30LzQtdC90Y/QtdC80YvQuSDQstC60LvRjtGH0LDQtdC80YvQuSDRhNCw0LnQuyDQvdC1CiAg0Y/QstC70Y/QtdGC0YHRjyDQvtCx0YvRh9C90YvQvCDRhNCw0LnQu9C+0Lwgcm9vdCDQsdC10Lcg0LfQsNC/0LjRgdC4INC00LvRjyDQs9GA0YPQv9C/0Ysg0Lgg0L/RgNC+0YfQuNGFOwotINCyINC+0LHQu9Cw0YHRgtC4IGBNYXRjaGAgKNC+0YHQvdC+0LLQvdC+0Lkg0YTQsNC50Lsg0LjQu9C4INCy0LrQu9GO0YfQsNC10LzRi9C1KSDQtNC40YDQtdC60YLQuNCy0LAg0LfQsNC00LDQvdCwINC90LUgYG5vYDsKLSBgUGVybWl0Um9vdExvZ2luYDog0LIg0LPRgNGD0L/Qv9Cw0YUgYHN1ZG9gINC4IGBhZG1pbmAg0L3QtdGCINC/0L7Qu9GM0LfQvtCy0LDRgtC10LvRjywg0LrRgNC+0LzQtSByb290LCDQuNC70Lgg0L3QuCDQvtC00LjQvQogINC40Lcg0L3QuNGFINC90LUg0LLQvtC50LTRkdGCINC/0L4gU1NIINGB0LDQvCAo0LLRhdC+0LQg0L/QviDQv9Cw0YDQvtC70Y4g0LLRi9C60LvRjtGH0LXQvSDQuCDQv9GA0LjQs9C+0LTQvdC+0LPQviDQutC70Y7Rh9CwINC90LXRgik7Ci0gYFBhc3N3b3JkQXV0aGVudGljYXRpb25gOiDQvdC4INGDINC+0LTQvdC+0LPQviDRgtCw0LrQvtCz0L4g0L/QvtC70YzQt9C+0LLQsNGC0LXQu9GPINC90LXRgiDQv9GA0LjQs9C+0LTQvdC+0LPQviDQutC70Y7Rh9CwIOKAlCDQvdC10L/Rg9GB0YLQvtCz0L4KICBgfi8uc3NoL2F1dGhvcml6ZWRfa2V5c2AgKNC40LvQuCBgYXV0aG9yaXplZF9rZXlzMmApLCDQv9GA0LggU3RyaWN0TW9kZXMg0YEg0L/RgNCw0LLQsNC80LggYH5gLCBgfi8uc3NoYAogINC4INGE0LDQudC70LAsINC60L7RgtC+0YDRi9C1INC/0YDQuNC80LXRgiBzc2hkOwotINC90LDRgdGC0YDQvtC50LrQuCDQstGF0L7QtNCwINCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGA0LAg0LIgYHNzaGQgLVRgINC00LvRjyDQtdCz0L4g0YHQvtCx0YHRgtCy0LXQvdC90L7Qs9C+INGB0L7QtdC00LjQvdC10L3QuNGPIChgTWF0Y2ggVXNlcmAKICDRg9GH0LjRgtGL0LLQsNC10YLRgdGPKSDQvdC1INC/0YDQvtCy0LXRgNGP0LXQvNGLINC80LXRhdCw0L3QuNC30LzQvtC8OiBBbGxvd1VzZXJzL0RlbnlVc2Vycy9BbGxvd0dyb3Vwcy9EZW55R3JvdXBzLAogIEF1dGhlbnRpY2F0aW9uTWV0aG9kcyDQvdC1IGBhbnlgLCDQvdC10YHRgtCw0L3QtNCw0YDRgtC90YvQtSBBdXRob3JpemVkS2V5c0ZpbGUg0LjQu9C4IFB1YmtleUF1dGhlbnRpY2F0aW9uLgoiIiIKCmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnMKCmltcG9ydCBlcnJubwppbXBvcnQgZ2xvYgppbXBvcnQgb3MKaW1wb3J0IHJlCmltcG9ydCBzdGF0CmltcG9ydCBzdWJwcm9jZXNzCgpBREFQVEVSX0lEID0gInByb2R1Y3Qtc3NoZC1jb25maWctb3B0aW9uLWFwcGx5LXYxIgpNRUNIQU5JU01fSUQgPSAic3NoZC1jb25maWctb3B0aW9uLXYxIgpUQVJHRVRfSUQgPSAibGludXgteDg2XzY0LXN1cHBvcnRlZC12MSIKUEFSQU1FVEVSX0tJTkQgPSAic3NoZC1jb25maWctb3B0aW9uIgoKQ09OVFJPTF9LRVlTID0gewogICAgIkZTVEVDLUNPTkZJR1VSQVRJT04tMjAyNi05LjEtU1NILVBBU1NXT1JELUFVVEhFTlRJQ0FUSU9OIjogIlBhc3N3b3JkQXV0aGVudGljYXRpb24iLAogICAgIkZTVEVDLUNPTkZJR1VSQVRJT04tMjAyNi05LjEtU1NILVBFUk1JVC1FTVBUWS1QQVNTV09SRFMiOiAiUGVybWl0RW1wdHlQYXNzd29yZHMiLAogICAgIkZTVEVDLUNPTkZJR1VSQVRJT04tMjAyNi05LjEtU1NILVBFUk1JVC1ST09ULUxPR0lOIjogIlBlcm1pdFJvb3RMb2dpbiIsCn0KRVhQRUNURURfT1AgPSAiZXEiCkVYUEVDVEVEX1ZBTFVFID0gIm5vIgoKU1NIRF9DT05GSUcgPSAiL2V0Yy9zc2gvc3NoZF9jb25maWciClNTSF9ESVIgPSAiL2V0Yy9zc2giCkdST1VQID0gIi9ldGMvZ3JvdXAiClBBU1NXRCA9ICIvZXRjL3Bhc3N3ZCIKU1NIRCA9ICIvdXNyL3NiaW4vc3NoZCIKU1lTVEVNQ1RMID0gIi91c3IvYmluL3N5c3RlbWN0bCIKU1NIX1VOSVQgPSAic3NoLnNlcnZpY2UiCkVGRkVDVElWRV9TUEVDID0gInVzZXI9cm9vdCxob3N0PWxvY2FsaG9zdCxhZGRyPTEyNy4wLjAuMSIKVE9PTF9USU1FT1VUID0gNjAKTUFYX0lOQ0xVREVfREVQVEggPSAxNgpTVURPX0dST1VQUyA9ICgic3VkbyIsICJhZG1pbiIpCkRFRkFVTFRfQVVUSE9SSVpFRF9LRVlTID0gKAogICAgKCIuc3NoL2F1dGhvcml6ZWRfa2V5cyIsICIuc3NoL2F1dGhvcml6ZWRfa2V5czIiKSwKICAgICgiLnNzaC9hdXRob3JpemVkX2tleXMiLCksCikKCkFDVElPTl9GSUxFID0gKCJ7cGF0aH0g0L3QtSDRj9Cy0LvRj9C10YLRgdGPINC+0LHRi9GH0L3Ri9C8INGE0LDQudC70L7QvCByb290INCx0LXQtyDQt9Cw0L/QuNGB0Lgg0LTQu9GPINCz0YDRg9C/0L/RiyDQuCDQv9GA0L7Rh9C40YU6INC30LDQtNCw0LnRgtC1ICIKICAgICAgICAgICAgICAgIsKre2tleX0gbm/CuyDQsiAvZXRjL3NzaC9zc2hkX2NvbmZpZyDQuCDRg9Cx0LXRgNC40YLQtSDQuNC90YvQtSDQt9C90LDRh9C10L3QuNGPIHtrZXl9INCy0YDRg9GH0L3Rg9GOLiIpCkFDVElPTl9NQVRDSCA9ICgi0LIg0LHQu9C+0LrQtSBNYXRjaCDRhNCw0LnQu9CwIHNzaGRfY29uZmlnINC40LvQuCDQstC60LvRjtGH0LDQtdC80L7Qs9C+INGE0LDQudC70LAge2tleX0g0LfQsNC00LDQvSDQvdC1IMKrbm/Cuzog0LPQu9C+0LHQsNC70YzQvdC+0LUgIgogICAgICAgICAgICAgICAgItC30L3QsNGH0LXQvdC40LUg0LXQs9C+INC90LUg0L/QtdGA0LXQutGA0YvQstCw0LXRgjsg0LjRgdC/0YDQsNCy0YzRgtC1INCx0LvQvtC6IE1hdGNoINCy0YDRg9GH0L3Rg9GOLiIpCkFDVElPTl9OT19TVURPID0gKCLQsiDQs9GA0YPQv9C/0LDRhSBzdWRvINC4IGFkbWluINC90LXRgiDQv9C+0LvRjNC30L7QstCw0YLQtdC70Y8sINC60YDQvtC80LUgcm9vdDog0L/QvtGB0LvQtSDQt9Cw0L/RgNC10YLQsCDQstGF0L7QtNCwIHJvb3Qg0L/QviBTU0ggIgogICAgICAgICAgICAgICAgICAi0YPQtNCw0LvRkdC90L3QviDQsNC00LzQuNC90LjRgdGC0YDQuNGA0L7QstCw0YLRjCDRgdC10YDQstC10YAg0LHRg9C00LXRgiDQvdC10LrQvtC80YM7INC90LDQt9C90LDRh9GM0YLQtSDQsNC00LzQuNC90LjRgdGC0YDQsNGC0L7RgNCwINCyINCz0YDRg9C/0L/RgyBzdWRvICIKICAgICAgICAgICAgICAgICAgItC40LvQuCDQt9Cw0LTQsNC50YLQtSDCq1Blcm1pdFJvb3RMb2dpbiBub8K7INCy0YDRg9GH0L3Rg9GOLiIpCkFDVElPTl9OT19LRVkgPSAoItC90Lgg0YMg0L7QtNC90L7Qs9C+INC/0L7Qu9GM0LfQvtCy0LDRgtC10LvRjyDQs9GA0YPQv9C/IHN1ZG8g0LggYWRtaW4g0L3QtdGCINC60LvRjtGH0LAg0LIgfi8uc3NoL2F1dGhvcml6ZWRfa2V5czog0L/QvtGB0LvQtSAiCiAgICAgICAgICAgICAgICAgItC30LDQv9GA0LXRgtCwINCy0YXQvtC00LAg0L/QviDQv9Cw0YDQvtC70Y4g0LLRhdC+0LQg0L/QviBTU0gg0YHRgtCw0L3QtdGCINC90LXQstC+0LfQvNC+0LbQtdC9OyDQtNC+0LHQsNCy0YzRgtC1INC60LvRjtGHINCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGA0YMg0LjQu9C4ICIKICAgICAgICAgICAgICAgICAi0LfQsNC00LDQudGC0LUgwqtQYXNzd29yZEF1dGhlbnRpY2F0aW9uIG5vwrsg0LLRgNGD0YfQvdGD0Y4uIikKQUNUSU9OX05PX0FETUlOX0xPR0lOID0gKCLQvdC4INC+0LTQuNC9INC/0L7Qu9GM0LfQvtCy0LDRgtC10LvRjCDQs9GA0YPQv9C/IHN1ZG8g0LggYWRtaW4g0L3QtSDQvNC+0LbQtdGCINCy0L7QudGC0Lgg0L/QviBTU0ggKNCy0YXQvtC0INC/0L4g0L/QsNGA0L7Qu9GOICIKICAgICAgICAgICAgICAgICAgICAgICAgICLQstGL0LrQu9GO0YfQtdC9LCDQutC70Y7Rh9CwINC90LXRgik6INC/0L7RgdC70LUg0LfQsNC/0YDQtdGC0LAg0LLRhdC+0LTQsCByb290INGD0LTQsNC70ZHQvdC90L4g0LDQtNC80LjQvdC40YHRgtGA0LjRgNC+0LLQsNGC0Ywg0YHQtdGA0LLQtdGAICIKICAgICAgICAgICAgICAgICAgICAgICAgICLQsdGD0LTQtdGCINC90LXQutC+0LzRgzsg0LTQvtCx0LDQstGM0YLQtSDQutC70Y7RhyDQsNC00LzQuNC90LjRgdGC0YDQsNGC0L7RgNGDINC40LvQuCDQt9Cw0LTQsNC50YLQtSDCq1Blcm1pdFJvb3RMb2dpbiBub8K7INCy0YDRg9GH0L3Rg9GOLiIpCkFDVElPTl9LRVlTX1NFVFVQID0gKCLQvdCw0YHRgtGA0L7QudC60Lgg0LLRhdC+0LTQsCDQsNC00LzQuNC90LjRgdGC0YDQsNGC0L7RgNC+0LIg0L/QviBTU0ggKEFsbG93VXNlcnMsIERlbnlVc2VycywgQWxsb3dHcm91cHMsIERlbnlHcm91cHMsICIKICAgICAgICAgICAgICAgICAgICAgIkF1dGhlbnRpY2F0aW9uTWV0aG9kcywgQXV0aG9yaXplZEtleXNGaWxlLCBQdWJrZXlBdXRoZW50aWNhdGlvbikg0L7RgtC70LjRh9Cw0Y7RgtGB0Y8g0L7RgiDQt9C90LDRh9C10L3QuNC5INC/0L4gIgogICAgICAgICAgICAgICAgICAgICAi0YPQvNC+0LvRh9Cw0L3QuNGOOiDQstC+0LfQvNC+0LbQvdC+0YHRgtGMINCy0YXQvtC00LAg0LDQtNC80LjQvdC40YHRgtGA0LDRgtC+0YDQsCDQvdC1INC/0YDQvtCy0LXRgNC10L3QsDsg0LfQsNC00LDQudGC0LUgwqt7a2V5fSBub8K7INCy0YDRg9GH0L3Rg9GOLiIpCgpPVVRDT01FUyA9ICgKICAgICJBUFBMSUVEIiwKICAgICJBTFJFQURZX0NPTVBMSUFOVCIsCiAgICAiRFJZX1JVTl9XT1VMRF9BUFBMWSIsCiAgICAiTk9UX0VMSUdJQkxFX0FQUExZX1VOU1VQUE9SVEVEIiwKICAgICJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsCiAgICAiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLAogICAgIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwKICAgICJGQUlMRURfQ09NUEVOU0FUSU9OIiwKKQpDT01NSVRfQ09NTUlUVEVEID0gIkNPTU1JVFRFRCIKQ09NTUlUX05PVF9DT01NSVRURUQgPSAiTk9UX0NPTU1JVFRFRCIKQ09NTUlUX05PVF9TVEFSVEVEID0gIk5PVF9TVEFSVEVEIgoKQ09OVFJPTF9JRF9QQVRURVJOID0gciJeKD8hLipbXHJcbl0pW0EtWmEtejAtOS5fLV0rJCIKIyDQn9GA0L7QsdC10LvRjNC90YvQtSDRgdC40LzQstC+0LvRiyDigJQg0LrQsNC6IGBbWzpzcGFjZTpdXWAgQ0hFQ0sg0LIg0LvQvtC60LDQu9C4IEMgKNCx0LXQtyBcbjog0YHRgtGA0L7QutC4INGD0LbQtSDRgNCw0LfQtNC10LvQtdC90Ysg0L/QviBMRikuClNQQUNFID0gIiBcdFx2XGZcciIKRElSRUNUSVZFX1JFID0gcmUuY29tcGlsZShyIl5bIFx0XHZcZlxyXSooW14gXHRcdlxmXHI9XSspKD86WyBcdFx2XGZccl0qPVsgXHRcdlxmXHJdKnxbIFx0XHZcZlxyXSspKC4qKSQiKQpCQVJFX0RJUkVDVElWRV9SRSA9IHJlLmNvbXBpbGUociJeWyBcdFx2XGZccl0qKFteIFx0XHZcZlxyPV0rKVsgXHRcdlxmXHJdKiQiKQpWQUxVRV9SRSA9IHJlLmNvbXBpbGUociJeKFsgXHRcdlxmXHJdKlteIFx0XHZcZlxyPV0rKD86WyBcdFx2XGZccl0qPVsgXHRcdlxmXHJdKnxbIFx0XHZcZlxyXSspKSIKICAgICAgICAgICAgICAgICAgICAgIHIiKFteIFx0XHZcZlxyXSspKC4qKSQiKQpHTE9CX0NIQVJTID0gKCIqIiwgIj8iLCAiWyIpClVTRVJfTkFNRV9SRSA9IHJlLmNvbXBpbGUociJbYS16X11bYS16MC05Xy4tXSoiKQpUTVBfU1VGRklYID0gIi5zbHAtdG1wIgoKCmNsYXNzIF9SZWZ1c2VkKEV4Y2VwdGlvbik6CiAgICBkZWYgX19pbml0X18oc2VsZiwgb3V0Y29tZSwgcmVhc29uLCBkZWNpc2lvbj1Ob25lKToKICAgICAgICBzdXBlcigpLl9faW5pdF9fKHJlYXNvbikKICAgICAgICBzZWxmLm91dGNvbWUgPSBvdXRjb21lCiAgICAgICAgc2VsZi5yZWFzb24gPSByZWFzb24KICAgICAgICBzZWxmLmRlY2lzaW9uID0gZGVjaXNpb24KCgpkZWYgdmFsaWRhdGVfY29udHJvbF9pbnB1dChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgYXBwbHlfc3VwcG9ydGVkKToKICAgICIiIkZhaWwtY2xvc2VkIHZhbGlkYXRpb24gb2Ygb25lIGNvbnRyb2wgcm93LiBSYWlzZXMgVmFsdWVFcnJvci4iIiIKICAgIGlmIG5vdCBpc2luc3RhbmNlKGNvbnRyb2xfaWQsIHN0cikgb3Igbm90IHJlLmZ1bGxtYXRjaChDT05UUk9MX0lEX1BBVFRFUk4sIGNvbnRyb2xfaWQpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImludmFsaWQgY29udHJvbCBpZCIpCiAgICBpZiBub3QgaXNpbnN0YW5jZShrZXksIHN0cikgb3Igbm90IGlzaW5zdGFuY2Uob3AsIHN0cikgb3Igbm90IGlzaW5zdGFuY2UoZXhwZWN0ZWQsIHN0cik6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigia2V5LCBvcCBhbmQgZXhwZWN0ZWQgbXVzdCBiZSBzdHJpbmdzIikKICAgIGlmIG5vdCBpc2luc3RhbmNlKGFwcGx5X3N1cHBvcnRlZCwgYm9vbCk6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigiYXBwbHlfc3VwcG9ydGVkIG11c3QgYmUgYm9vbCIpCiAgICByZXR1cm4gVHJ1ZQoKCmRlZiBfcChyb290LCBwYXRoKToKICAgIHJldHVybiBwYXRoIGlmIHJvb3QgaXMgTm9uZSBlbHNlIG9zLnBhdGguam9pbihyb290LCBwYXRoLmxzdHJpcCgiLyIpKQoKCmRlZiBfYWRtaW4oYWN0aW9uKToKICAgIHJldHVybiB7ImNsYXNzIjogIkFETUlOX0FDVElPTl9SRVFVSVJFRCIsICJyZXF1aXJlZCI6IFRydWUsICJhY3Rpb24iOiBhY3Rpb259CgoKZGVmIF9vdGhlcihyZWFzb24pOgogICAgcmV0dXJuIF9SZWZ1c2VkKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsIHJlYXNvbikKCgpkZWYgX3JlYWRfcmVndWxhcihwYXRoLCByZWZ1c2UpOgogICAgIiIiKNCx0LDQudGC0YssIHN0YXQpINC+0LHRi9GH0L3QvtCz0L4g0YTQsNC50LvQsCDQsdC10Lcg0L/QtdGA0LXRhdC+0LTQsCDQv9C+INGB0YHRi9C70LrQtTsg0L3QtSDQvtCx0YvRh9C90YvQuSDRhNCw0LnQuyDigJQgYHJlZnVzZWAuCgogICAgYE9fTk9OQkxPQ0tgOiBGSUZPINCx0LXQtyDQv9C40YHQsNGC0LXQu9GPINC90LUg0LHQu9C+0LrQuNGA0YPQtdGCINC+0YLQutGA0YvRgtC40LUg0Lgg0L7RgtCy0LXRgNCz0LDQtdGC0YHRjyDQv9C+INGC0LjQv9GDINC00LXRgdC60YDQuNC/0YLQvtGA0LAuCiAgICAiIiIKICAgIHRyeToKICAgICAgICBmZCA9IG9zLm9wZW4ocGF0aCwgb3MuT19SRE9OTFkgfCBvcy5PX05PRk9MTE9XIHwgb3MuT19OT05CTE9DSyB8IG9zLk9fQ0xPRVhFQykKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICBpZiBleGMuZXJybm8gPT0gZXJybm8uRUxPT1A6CiAgICAgICAgICAgIHJhaXNlIHJlZnVzZSAgIyDRgdC40LzQstC+0LvRjNC90LDRjyDRgdGB0YvQu9C60LAg4oCUINC90LUg0L7QsdGL0YfQvdGL0Lkg0YTQsNC50LsKICAgICAgICByYWlzZSBfb3RoZXIoInNzaGQtY29uZmlnOnJlYWQtZmFpbGVkIikKICAgIHRyeToKICAgICAgICBzdCA9IG9zLmZzdGF0KGZkKQogICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcoc3Quc3RfbW9kZSk6CiAgICAgICAgICAgIHJhaXNlIHJlZnVzZQogICAgICAgIGNodW5rcyA9IFtdCiAgICAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgICAgY2h1bmsgPSBvcy5yZWFkKGZkLCA2NTUzNikKICAgICAgICAgICAgaWYgbm90IGNodW5rOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgY2h1bmtzLmFwcGVuZChjaHVuaykKICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgIF9jbG9zZV9xdWlldGx5KGZkKQogICAgICAgIHJhaXNlIF9vdGhlcigic3NoZC1jb25maWc6cmVhZC1mYWlsZWQiKQogICAgZXhjZXB0IEJhc2VFeGNlcHRpb246CiAgICAgICAgX2Nsb3NlX3F1aWV0bHkoZmQpCiAgICAgICAgcmFpc2UKICAgIHRyeToKICAgICAgICBvcy5jbG9zZShmZCkKICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgIHJhaXNlIF9vdGhlcigic3NoZC1jb25maWc6cmVhZC1mYWlsZWQiKQogICAgcmV0dXJuIGIiIi5qb2luKGNodW5rcyksIHN0CgoKZGVmIF9jbG9zZV9xdWlldGx5KGZkKToKICAgIHRyeToKICAgICAgICBvcy5jbG9zZShmZCkKICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgIHBhc3MKCgpkZWYgX3RydXN0ZWRfdWlkKHJvb3QpOgogICAgIiIi0JLQu9Cw0LTQtdC70LXRhiDQtNC+0LLQtdGA0LXQvdC90L7Qs9C+INGE0LDQudC70LA6IHJvb3Q7INCyINGC0LXRgdGC0L7QstC+0Lwg0LTQtdGA0LXQstC1IChgX3Jvb3RgKSDigJQg0YLQtdC60YPRidC40Lkg0L/QvtC70YzQt9C+0LLQsNGC0LXQu9GMLiIiIgogICAgcmV0dXJuIDAgaWYgcm9vdCBpcyBOb25lIGVsc2Ugb3MuZ2V0ZXVpZCgpCgoKZGVmIF90cnVzdGVkKHN0LCByb290KToKICAgIHJldHVybiAoc3RhdC5TX0lTUkVHKHN0LnN0X21vZGUpIGFuZCBub3Qgc3RhdC5TX0lNT0RFKHN0LnN0X21vZGUpICYgMG8wMjIKICAgICAgICAgICAgYW5kIHN0LnN0X3VpZCA9PSBfdHJ1c3RlZF91aWQocm9vdCkpCgoKZGVmIF90ZXh0KHJhdyk6CiAgICBpZiBiIlx4MDAiIGluIHJhdyBvciByZS5zZWFyY2gocmIiXHIoPyFcbikiLCByYXcpOgogICAgICAgIHJhaXNlIF9vdGhlcigic3NoZC1jb25maWc6aW52YWxpZC1ieXRlcyIpCiAgICAjINCa0LDQuiDRgyBDSEVDSzog0LTQvtC/0YPRgdGC0LjQvNGLINC70Y7QsdGL0LUg0LHQsNC50YLRiywg0LrRgNC+0LzQtSBOVUwg0Lgg0L7QtNC40L3QvtGH0L3QvtCz0L4gQ1I7INCx0LDQudGC0YssINC90LUg0Y/QstC70Y/RjtGJ0LjQtdGB0Y8KICAgICMgVVRGLTgsINC/0LXRgNC10L3QvtGB0Y/RgtGB0Y8g0LHQtdC3INC40LfQvNC10L3QtdC90LjQuSAoc3Vycm9nYXRlZXNjYXBlINGC0YPQtNCwINC4INC+0LHRgNCw0YLQvdC+KS4KICAgIHJldHVybiByYXcuZGVjb2RlKCJ1dGYtOCIsICJzdXJyb2dhdGVlc2NhcGUiKQoKCmRlZiBfbGZfbGluZXModGV4dCk6CiAgICAiIiLQodGC0YDQvtC60Lgg0YEg0L7QutC+0L3Rh9Cw0L3QuNGP0LzQuCwg0YDQsNC30LTQtdC70LXQvdC40LUg0YLQvtC70YzQutC+INC/0L4gTEYgKNC60LDQuiDRgyBDSEVDSzsgXHYsIFxmLCBceDFj4oCmIOKAlCDQvdC1INGA0LDQt9C00LXQu9C40YLQtdC70LgpLiIiIgogICAgcGFydHMgPSB0ZXh0LnNwbGl0KCJcbiIpCiAgICBsaW5lcyA9IFtwYXJ0ICsgIlxuIiBmb3IgcGFydCBpbiBwYXJ0c1s6LTFdXQogICAgaWYgcGFydHNbLTFdOgogICAgICAgIGxpbmVzLmFwcGVuZChwYXJ0c1stMV0pCiAgICByZXR1cm4gbGluZXMKCgpkZWYgX2JvZHkobGluZSk6CiAgICAiIiLQodGC0YDQvtC60LAg0LHQtdC3INC+0LrQvtC90YfQsNC90LjRjyAoXFxuINC40LvQuCBcXHJcXG4pLiIiIgogICAgaWYgbGluZS5lbmRzd2l0aCgiXHJcbiIpOgogICAgICAgIHJldHVybiBsaW5lWzotMl0KICAgIHJldHVybiBsaW5lWzotMV0gaWYgbGluZS5lbmRzd2l0aCgiXG4iKSBlbHNlIGxpbmUKCgpkZWYgX2VvbChsaW5lKToKICAgIGlmIGxpbmUuZW5kc3dpdGgoIlxyXG4iKToKICAgICAgICByZXR1cm4gIlxyXG4iCiAgICByZXR1cm4gIlxuIiBpZiBsaW5lLmVuZHN3aXRoKCJcbiIpIGVsc2UgIiIKCgpkZWYgX2RpcmVjdGl2ZShsaW5lKToKICAgICIiIijQutC70Y7RhyDQsiDQvdC40LbQvdC10Lwg0YDQtdCz0LjRgdGC0YDQtSwg0L7RgdGC0LDRgtC+0Log0YHRgtGA0L7QutC4KSDQt9C90LDRh9C40LzQvtC5INGB0YLRgNC+0LrQuCDQuNC70LggTm9uZS4iIiIKICAgIGJvZHkgPSBfYm9keShsaW5lKQogICAgaWYgbm90IGJvZHkuc3RyaXAoU1BBQ0UpIG9yIGJvZHkubHN0cmlwKFNQQUNFKS5zdGFydHN3aXRoKCIjIik6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIG0gPSBESVJFQ1RJVkVfUkUubWF0Y2goYm9keSkgb3IgQkFSRV9ESVJFQ1RJVkVfUkUubWF0Y2goYm9keSkKICAgIGlmIG0gaXMgTm9uZToKICAgICAgICByZXR1cm4gTm9uZQogICAgcmV0dXJuIG0uZ3JvdXAoMSkubG93ZXIoKSwgKG0uZ3JvdXAoMikgaWYgbS5yZSBpcyBESVJFQ1RJVkVfUkUgZWxzZSAiIikKCgpBUkdfU1BBQ0UgPSAoIiAiLCAiXHQiLCAiXHIiKQoKCmRlZiBzcGxpdF9hcmdzKHJlc3QpOgogICAgIiIi0JDRgNCz0YPQvNC10L3RgtGLINGB0YLRgNC+0LrQuCDigJQg0LrQsNC6IGBfc2xwX3NwbGl0X2FyZ3NgIENIRUNLIHNzaGQtY29uZmlnLW9wdGlvbiAo0L/RgNC40L3Rj9GC0LDRjyDRgdC10LzQsNC90YLQuNC60LApLgoKICAgINCg0LDQt9C00LXQu9C40YLQtdC70Lgg4oCUINC/0YDQvtCx0LXQuywg0YLQsNCx0YPQu9GP0YbQuNGPLCBDUjsgYCNgINCyINC90LDRh9Cw0LvQtSDQsNGA0LPRg9C80LXQvdGC0LAg0LfQsNCy0LXRgNGI0LDQtdGCINGB0YLRgNC+0LrRgzsg0LrQsNCy0YvRh9C60LgKICAgIGAnYCDQuCBgImAg0LPRgNGD0L/Qv9C40YDRg9GO0YI7INC90LXQt9Cw0LrRgNGL0YLQsNGPINC60LDQstGL0YfQutCwIOKAlCDQvtGC0LrQsNC3LiDQntCx0YDQsNGC0L3QsNGPINC60L7RgdCw0Y8g0YfQtdGA0YLQsCDQsiBDSEVDSyDigJQg0L7QsdGL0YfQvdGL0LkKICAgINGB0LjQvNCy0L7QuyAo0YHRgNCw0LLQvdC10L3QuNC1INGBINC00LLRg9GF0YHQuNC80LLQvtC70YzQvdC+0Lkg0YHRgtGA0L7QutC+0Lkg0LIgYmFzaCDQvdC40LrQvtCz0LTQsCDQvdC1INC40YHRgtC40L3QvdC+KSwg0LfQtNC10YHRjCDRgtCw0Log0LbQtTsKICAgINGA0LDQstC10L3RgdGC0LLQviDRgNCw0LfQsdC+0YDQsCDQv9GA0L7QstC10YDQtdC90L4g0LTQuNGE0YTQtdGA0LXQvdGG0LjQsNC70YzQvdGL0Lwg0YLQtdGB0YLQvtC8INC/0YDQvtGC0LjQsiBiYXNoLdGE0YPQvdC60YbQuNC4IENIRUNLLgogICAgIiIiCiAgICBhcmdzLCBpLCBuID0gW10sIDAsIGxlbihyZXN0KQogICAgd2hpbGUgaSA8IG46CiAgICAgICAgd2hpbGUgaSA8IG4gYW5kIHJlc3RbaV0gaW4gQVJHX1NQQUNFOgogICAgICAgICAgICBpICs9IDEKICAgICAgICBpZiBpID49IG4gb3IgcmVzdFtpXSA9PSAiIyI6CiAgICAgICAgICAgIHJldHVybiBhcmdzCiAgICAgICAgdG9rZW4sIHF1b3RlID0gIiIsICIiCiAgICAgICAgd2hpbGUgaSA8IG46CiAgICAgICAgICAgIGMgPSByZXN0W2ldCiAgICAgICAgICAgIGlmIHF1b3RlOgogICAgICAgICAgICAgICAgaWYgYyA9PSBxdW90ZToKICAgICAgICAgICAgICAgICAgICBxdW90ZSA9ICIiCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgIHRva2VuICs9IGMKICAgICAgICAgICAgICAgIGkgKz0gMQogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgaWYgYyBpbiAoJyInLCAiJyIpOgogICAgICAgICAgICAgICAgcXVvdGUgPSBjCiAgICAgICAgICAgICAgICBpICs9IDEKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGlmIGMgaW4gQVJHX1NQQUNFOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgdG9rZW4gKz0gYwogICAgICAgICAgICBpICs9IDEKICAgICAgICBpZiBxdW90ZToKICAgICAgICAgICAgcmFpc2UgX290aGVyKCJzc2hkLWNvbmZpZzppbnZhbGlkLWFyZ3VtZW50cyIpCiAgICAgICAgYXJncy5hcHBlbmQodG9rZW4pCiAgICByZXR1cm4gYXJncwoKCmRlZiBfYWJzZW50KHBhdGgsIHJlYXNvbik6CiAgICAiIiJUcnVlINC/0YDQuCDQtNC+0LrQsNC30LDQvdC90L7QvCBFTk9FTlQ7INC40L3QsNGPINC+0YjQuNCx0LrQsCBsc3RhdCDigJQg0L7RgtC60LDQtyBgcmVhc29uYCAo0LrQsNC6INGDIENIRUNLKS4iIiIKICAgIHRyeToKICAgICAgICBvcy5sc3RhdChwYXRoKQogICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgIHJldHVybiBUcnVlCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICByYWlzZSBfb3RoZXIocmVhc29uKQogICAgcmV0dXJuIEZhbHNlCgoKZGVmIF9pbmNsdWRlX3RhcmdldHMocm9vdCwgcGF0dGVybik6CiAgICAiIiLQpNCw0LnQu9GLINGB0YLRgNC+0LrQuCBJbmNsdWRlINC/0L4g0L/RgNCw0LLQuNC70LDQvCBDSEVDSyBzc2hkLWNvbmZpZy1vcHRpb24uIiIiCiAgICBwYXRoID0gcGF0dGVybiBpZiBwYXR0ZXJuLnN0YXJ0c3dpdGgoIi8iKSBlbHNlIFNTSF9ESVIgKyAiLyIgKyBwYXR0ZXJuCiAgICBpZiBhbnkoY2ggaW4gcGF0aCBmb3IgY2ggaW4gR0xPQl9DSEFSUyk6CiAgICAgICAgY3V0ID0gbWluKHBhdGguaW5kZXgoY2gpIGZvciBjaCBpbiBHTE9CX0NIQVJTIGlmIGNoIGluIHBhdGgpCiAgICAgICAgcHJlZml4ID0gcGF0aFs6Y3V0XS5yc3BsaXQoIi8iLCAxKVswXSBvciAiLyIKICAgICAgICByZWFsX3ByZWZpeCA9IF9wKHJvb3QsIHByZWZpeCkKICAgICAgICBpZiBub3QgX2Fic2VudChyZWFsX3ByZWZpeCwgInNzaGQtY29uZmlnOmluY2x1ZGUtcHJlZml4LXN0YXQtZmFpbGVkIik6CiAgICAgICAgICAgIGlmIG9zLnBhdGguaXNsaW5rKHJlYWxfcHJlZml4KToKICAgICAgICAgICAgICAgIHJhaXNlIF9vdGhlcigic3NoZC1jb25maWc6aW5jbHVkZS1wcmVmaXgtc3ltbGluayIpCiAgICAgICAgICAgIGlmIG5vdCBvcy5wYXRoLmlzZGlyKHJlYWxfcHJlZml4KToKICAgICAgICAgICAgICAgIHJhaXNlIF9vdGhlcigic3NoZC1jb25maWc6aW5jbHVkZS1wcmVmaXgtaW52YWxpZC10eXBlIikKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgZm9yIF9kaXIsIGRpcnMsIGZpbGVzIGluIG9zLndhbGsocmVhbF9wcmVmaXgsIG9uZXJyb3I9X3JhaXNlX3NjYW4pOgogICAgICAgICAgICAgICAgICAgIGlmIGFueSgiXG4iIGluIG5hbWUgZm9yIG5hbWUgaW4gZGlycyArIGZpbGVzKToKICAgICAgICAgICAgICAgICAgICAgICAgcmFpc2UgX290aGVyKCJzc2hkLWNvbmZpZzppbmNsdWRlLW5ld2xpbmUtbmFtZSIpCiAgICAgICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICAgICAgcmFpc2UgX290aGVyKCJzc2hkLWNvbmZpZzppbmNsdWRlLXByZWZpeC1zY2FuLWZhaWxlZCIpCiAgICAgICAgcmV0dXJuIHNvcnRlZChnbG9iLmdsb2IoX3Aocm9vdCwgcGF0aCkpKQogICAgcmVhbCA9IF9wKHJvb3QsIHBhdGgpCiAgICByZXR1cm4gW10gaWYgX2Fic2VudChyZWFsLCAic3NoZC1jb25maWc6aW5jbHVkZS1zdGF0LWZhaWxlZCIpIGVsc2UgW3JlYWxdCgoKZGVmIF9yYWlzZV9zY2FuKGV4Yyk6CiAgICByYWlzZSBleGMKCgpjbGFzcyBDb25maWc6CiAgICAiIiLQoNCw0LfQvtCx0YDQsNC90L3QvtC1INC00LXRgNC10LLQviBzc2hkX2NvbmZpZyDQtNC70Y8g0L7QtNC90L7Qs9C+INC60LvRjtGH0LAuCgogICAg0KHQtdC80LDQvdGC0LjQutCwINGC0LAg0LbQtSwg0YfRgtC+INGDIENIRUNLIHNzaGQtY29uZmlnLW9wdGlvbjogYE1hdGNoYCDQvtGC0LrRgNGL0LLQsNC10YIg0L7QsdC70LDRgdGC0Ywg0LTQvgogICAg0LrQvtC90YbQsCDRhNCw0LnQu9CwOyDQstC60LvRjtGH0LDQtdC80YvQuSDRhNCw0LnQuyDQvdCw0YHQu9C10LTRg9C10YIg0L7QsdC70LDRgdGC0Ywg0YHRgtGA0L7QutC4IGBJbmNsdWRlYDsg0LPQu9C+0LHQsNC70YzQvdGL0LUgYG5vYAogICAg0YHRh9C40YLQsNGO0YLRgdGPINGC0L7Qu9GM0LrQviDQsiDQvtGB0L3QvtCy0L3QvtC8INGE0LDQudC70LUuCiAgICAiIiIKCiAgICBkZWYgX19pbml0X18oc2VsZiwgcm9vdCwgbGtleSk6CiAgICAgICAgc2VsZi5yb290ID0gcm9vdAogICAgICAgIHNlbGYubGtleSA9IGxrZXkKICAgICAgICBzZWxmLm1haW4gPSBfcChyb290LCBTU0hEX0NPTkZJRykKICAgICAgICBzZWxmLmZpbGVzID0ge30gICAgICAjINC/0YPRgtGMIC0+ICjQsdCw0LnRgtGLLCBzdGF0LCDRgdGC0YDQvtC60Lgg0YEg0L7QutC+0L3Rh9Cw0L3QuNGP0LzQuCkKICAgICAgICBzZWxmLm9jY3VycmVuY2VzID0gW10gICMgKNC/0YPRgtGMLCDQuNC90LTQtdC60YEg0YHRgtGA0L7QutC4LCDQvtCx0LvQsNGB0YLRjCwg0L7RgdC90L7QstC90L7QuSDRhNCw0LnQuywg0LfQvdCw0YfQtdC90LjQtSkKICAgICAgICBzZWxmLm1haW5fbWF0Y2hfaW5kZXggPSBOb25lCiAgICAgICAgc2VsZi5tYWluX3RlbXBsYXRlX2luZGV4ID0gTm9uZQogICAgICAgIHNlbGYuX3N0YWNrID0gc2V0KCkKICAgICAgICBzZWxmLl9wYXJzZShzZWxmLm1haW4sIDAsIFRydWUsICJHTE9CQUwiKQoKICAgIGRlZiBfbG9hZChzZWxmLCBwYXRoLCBtYWluKToKICAgICAgICBpZiBwYXRoIG5vdCBpbiBzZWxmLmZpbGVzOgogICAgICAgICAgICByZWZ1c2UgPSAoX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwgInNzaGQtY29uZmlnOnVudHJ1c3RlZCIsIE5vbmUpIGlmIG1haW4KICAgICAgICAgICAgICAgICAgICAgIGVsc2UgX290aGVyKCJzc2hkLWNvbmZpZzppbmNsdWRlLWludmFsaWQtdHlwZSIpKQogICAgICAgICAgICByYXcsIHN0ID0gX3JlYWRfcmVndWxhcihwYXRoLCByZWZ1c2UpCiAgICAgICAgICAgIHNlbGYuZmlsZXNbcGF0aF0gPSAocmF3LCBzdCwgX2xmX2xpbmVzKF90ZXh0KHJhdykpKQogICAgICAgIHJldHVybiBzZWxmLmZpbGVzW3BhdGhdWzJdCgogICAgZGVmIF9wYXJzZShzZWxmLCBwYXRoLCBkZXB0aCwgbWFpbiwgc2NvcGUpOgogICAgICAgIGlmIGRlcHRoID4gTUFYX0lOQ0xVREVfREVQVEg6CiAgICAgICAgICAgIHJhaXNlIF9vdGhlcigic3NoZC1jb25maWc6aW5jbHVkZS1kZXB0aCIpCiAgICAgICAgaWRlbnQgPSBvcy5wYXRoLnJlYWxwYXRoKHBhdGgpCiAgICAgICAgaWYgaWRlbnQgaW4gc2VsZi5fc3RhY2s6CiAgICAgICAgICAgIHJhaXNlIF9vdGhlcigic3NoZC1jb25maWc6aW5jbHVkZS1jeWNsZSIpCiAgICAgICAgc2VsZi5fc3RhY2suYWRkKGlkZW50KQogICAgICAgIHRlbXBsYXRlID0gcmUuY29tcGlsZShyIl5bIFx0XSojWyBcdF0qIiArIHJlLmVzY2FwZShzZWxmLmxrZXkpICsgciIoPzpbIFx0PV18JCkiLCByZS5JR05PUkVDQVNFKQogICAgICAgIGZvciBpbmRleCwgbGluZSBpbiBlbnVtZXJhdGUoc2VsZi5fbG9hZChwYXRoLCBtYWluKSk6CiAgICAgICAgICAgIGlmIG1haW4gYW5kIHNjb3BlID09ICJHTE9CQUwiIGFuZCBzZWxmLm1haW5fdGVtcGxhdGVfaW5kZXggaXMgTm9uZSBhbmQgdGVtcGxhdGUubWF0Y2goX2JvZHkobGluZSkpOgogICAgICAgICAgICAgICAgc2VsZi5tYWluX3RlbXBsYXRlX2luZGV4ID0gaW5kZXgKICAgICAgICAgICAgcGFyc2VkID0gX2RpcmVjdGl2ZShsaW5lKQogICAgICAgICAgICBpZiBwYXJzZWQgaXMgTm9uZToKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGtleSwgcmVzdCA9IHBhcnNlZAogICAgICAgICAgICAjINCa0LDQuiDRgyBDSEVDSzog0LDRgNCz0YPQvNC10L3RgtGLINGA0LDQt9Cx0LjRgNCw0Y7RgtGB0Y8g0YLQvtC70YzQutC+INGDIE1hdGNoLCBJbmNsdWRlINC4INC60LvRjtGH0LAg0LrQvtC90YLRgNC+0LvRjy4KICAgICAgICAgICAgaWYga2V5IG5vdCBpbiAoIm1hdGNoIiwgImluY2x1ZGUiLCBzZWxmLmxrZXkpOgogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgYXJncyA9IHNwbGl0X2FyZ3MocmVzdCkKICAgICAgICAgICAgaWYga2V5ID09ICJtYXRjaCI6CiAgICAgICAgICAgICAgICBpZiBub3QgYXJnczoKICAgICAgICAgICAgICAgICAgICByYWlzZSBfb3RoZXIoInNzaGQtY29uZmlnOmludmFsaWQtbWF0Y2giKQogICAgICAgICAgICAgICAgaWYgbWFpbiBhbmQgc2VsZi5tYWluX21hdGNoX2luZGV4IGlzIE5vbmU6CiAgICAgICAgICAgICAgICAgICAgc2VsZi5tYWluX21hdGNoX2luZGV4ID0gaW5kZXgKICAgICAgICAgICAgICAgIHNjb3BlID0gIk1BVENIIgogICAgICAgICAgICBlbGlmIGtleSA9PSAiaW5jbHVkZSI6CiAgICAgICAgICAgICAgICBpZiBub3QgYXJnczoKICAgICAgICAgICAgICAgICAgICByYWlzZSBfb3RoZXIoInNzaGQtY29uZmlnOmludmFsaWQtaW5jbHVkZSIpCiAgICAgICAgICAgICAgICBmb3IgcGF0dGVybiBpbiBhcmdzOgogICAgICAgICAgICAgICAgICAgIGZvciBpdGVtIGluIF9pbmNsdWRlX3RhcmdldHMoc2VsZi5yb290LCBwYXR0ZXJuKToKICAgICAgICAgICAgICAgICAgICAgICAgaWYgb3MucGF0aC5pc2xpbmsoaXRlbSk6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICByYWlzZSBfb3RoZXIoInNzaGQtY29uZmlnOmluY2x1ZGUtc3ltbGluayIpCiAgICAgICAgICAgICAgICAgICAgICAgIHNlbGYuX3BhcnNlKGl0ZW0sIGRlcHRoICsgMSwgRmFsc2UsIHNjb3BlKQogICAgICAgICAgICBlbGlmIGtleSA9PSBzZWxmLmxrZXk6CiAgICAgICAgICAgICAgICBpZiBsZW4oYXJncykgIT0gMSBvciAiPSIgaW4gYXJnc1swXToKICAgICAgICAgICAgICAgICAgICByYWlzZSBfb3RoZXIoInNzaGQtY29uZmlnOmludmFsaWQtZGlyZWN0aXZlIikKICAgICAgICAgICAgICAgIHNlbGYub2NjdXJyZW5jZXMuYXBwZW5kKChwYXRoLCBpbmRleCwgc2NvcGUsIG1haW4sIGFyZ3NbMF0ubG93ZXIoKSkpCiAgICAgICAgc2VsZi5fc3RhY2suZGlzY2FyZChpZGVudCkKCiAgICBAcHJvcGVydHkKICAgIGRlZiBtYWluX2dsb2JhbF9ubyhzZWxmKToKICAgICAgICByZXR1cm4gc3VtKDEgZm9yIG8gaW4gc2VsZi5vY2N1cnJlbmNlcyBpZiBvWzNdIGFuZCBvWzJdID09ICJHTE9CQUwiIGFuZCBvWzRdID09IEVYUEVDVEVEX1ZBTFVFKQoKICAgIEBwcm9wZXJ0eQogICAgZGVmIG1hdGNoX25vbl9ubyhzZWxmKToKICAgICAgICByZXR1cm4gc3VtKDEgZm9yIG8gaW4gc2VsZi5vY2N1cnJlbmNlcyBpZiBvWzJdID09ICJNQVRDSCIgYW5kIG9bNF0gIT0gRVhQRUNURURfVkFMVUUpCgogICAgZGVmIHBsYW4oc2VsZiwga2V5KToKICAgICAgICAiIiJ70L/Rg9GC0Yw6INC90L7QstGL0LUg0LHQsNC50YLRi30g0L/QviDRgdGF0LXQvNC1IDHigJM0OyDQv9GD0YHRgtC+0Lkg0L/Qu9Cw0L0g0L3QtdCy0L7Qt9C80L7QttC10L0g0L/RgNC4INC90LXRgdC+0L7RgtCy0LXRgtGB0YLQstC40LguIiIiCiAgICAgICAgbGluZXMgPSB7cGF0aDogbGlzdChyZWNbMl0pIGZvciBwYXRoLCByZWMgaW4gc2VsZi5maWxlcy5pdGVtcygpfQogICAgICAgIGNoYW5nZWQgPSBzZXQoKQogICAgICAgIG1haW5fZ2xvYmFsID0gRmFsc2UKICAgICAgICBmb3IgcGF0aCwgaW5kZXgsIHNjb3BlLCBtYWluLCB2YWx1ZSBpbiBzZWxmLm9jY3VycmVuY2VzOgogICAgICAgICAgICBpZiBzY29wZSAhPSAiR0xPQkFMIjoKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIG1haW5fZ2xvYmFsID0gbWFpbl9nbG9iYWwgb3IgbWFpbgogICAgICAgICAgICBpZiB2YWx1ZSA9PSBFWFBFQ1RFRF9WQUxVRToKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIGxpbmUgPSBsaW5lc1twYXRoXVtpbmRleF0KICAgICAgICAgICAgbSA9IFZBTFVFX1JFLm1hdGNoKF9ib2R5KGxpbmUpKQogICAgICAgICAgICBpZiBtIGlzIE5vbmU6CiAgICAgICAgICAgICAgICByYWlzZSBfb3RoZXIoInNzaGQtY29uZmlnOmludmFsaWQtZGlyZWN0aXZlIikKICAgICAgICAgICAgbGluZXNbcGF0aF1baW5kZXhdID0gbS5ncm91cCgxKSArIEVYUEVDVEVEX1ZBTFVFICsgbS5ncm91cCgzKSArIF9lb2wobGluZSkKICAgICAgICAgICAgY2hhbmdlZC5hZGQocGF0aCkKICAgICAgICBpZiBub3QgbWFpbl9nbG9iYWw6CiAgICAgICAgICAgIG1haW5fbGluZXMgPSBsaW5lc1tzZWxmLm1haW5dCiAgICAgICAgICAgIG5ld19saW5lID0ga2V5ICsgIiAiICsgRVhQRUNURURfVkFMVUUKICAgICAgICAgICAgaWYgc2VsZi5tYWluX3RlbXBsYXRlX2luZGV4IGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgb2xkID0gbWFpbl9saW5lc1tzZWxmLm1haW5fdGVtcGxhdGVfaW5kZXhdCiAgICAgICAgICAgICAgICBtYWluX2xpbmVzW3NlbGYubWFpbl90ZW1wbGF0ZV9pbmRleF0gPSBuZXdfbGluZSArIChfZW9sKG9sZCkgb3IgIlxuIikKICAgICAgICAgICAgZWxpZiBzZWxmLm1haW5fbWF0Y2hfaW5kZXggaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICBtYWluX2xpbmVzLmluc2VydChzZWxmLm1haW5fbWF0Y2hfaW5kZXgsIG5ld19saW5lICsgIlxuIikKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIGlmIG1haW5fbGluZXMgYW5kIG5vdCBfZW9sKG1haW5fbGluZXNbLTFdKToKICAgICAgICAgICAgICAgICAgICBtYWluX2xpbmVzWy0xXSArPSAiXG4iCiAgICAgICAgICAgICAgICBtYWluX2xpbmVzLmFwcGVuZChuZXdfbGluZSArICJcbiIpCiAgICAgICAgICAgIGNoYW5nZWQuYWRkKHNlbGYubWFpbikKICAgICAgICByZXR1cm4ge3BhdGg6ICIiLmpvaW4obGluZXNbcGF0aF0pLmVuY29kZSgidXRmLTgiLCAic3Vycm9nYXRlZXNjYXBlIikgZm9yIHBhdGggaW4gc29ydGVkKGNoYW5nZWQpfQoKCmRlZiBfZGVmYXVsdF9ydW4oYXJndiwgdGltZW91dCk6CiAgICByZXR1cm4gc3VicHJvY2Vzcy5ydW4oYXJndiwgc3RkaW49c3VicHJvY2Vzcy5ERVZOVUxMLCBzdGRvdXQ9c3VicHJvY2Vzcy5QSVBFLCBzdGRlcnI9c3VicHJvY2Vzcy5QSVBFLAogICAgICAgICAgICAgICAgICAgICAgICAgIHRpbWVvdXQ9dGltZW91dCwgZW52PXsiUEFUSCI6ICIvdXNyL3NiaW46L3Vzci9iaW46L3NiaW46L2JpbiIsICJMQ19BTEwiOiAiQyJ9KQoKCmRlZiBfY2FsbChydW4sIGFyZ3YpOgogICAgdHJ5OgogICAgICAgIHJldHVybiBydW4oYXJndiwgVE9PTF9USU1FT1VUKQogICAgZXhjZXB0IChPU0Vycm9yLCBzdWJwcm9jZXNzLlRpbWVvdXRFeHBpcmVkKToKICAgICAgICByZXR1cm4gTm9uZQoKCmRlZiBfY2hlY2tfdG9vbHMocm9vdCwgcGF0aHMpOgogICAgZm9yIHBhdGggaW4gcGF0aHM6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBzdCA9IG9zLnN0YXQoX3Aocm9vdCwgcGF0aCkpCiAgICAgICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgICAgIHJhaXNlIF9vdGhlcigidG9vbHM6bWlzc2luZzoiICsgb3MucGF0aC5iYXNlbmFtZShwYXRoKSkKICAgICAgICBpZiBub3Qgc3RhdC5TX0lTUkVHKHN0LnN0X21vZGUpIG9yIG5vdCBzdC5zdF9tb2RlICYgMG8xMTE6CiAgICAgICAgICAgIHJhaXNlIF9vdGhlcigidG9vbHM6bWlzc2luZzoiICsgb3MucGF0aC5iYXNlbmFtZShwYXRoKSkKCgpkZWYgX3N5bnRheF9vayhyb290LCBydW4sIHBhdGg9Tm9uZSk6CiAgICAiIiJgc3NoZCAtdCAtZmA6INC/0L4g0YPQvNC+0LvRh9Cw0L3QuNGOINC+0YHQvdC+0LLQvdC+0Lkg0YTQsNC50Ls7IGBwYXRoYCDigJQg0L/QvtC00LPQvtGC0L7QstC70LXQvdC90YvQuSDQstGA0LXQvNC10L3QvdGL0Lkg0YTQsNC50LsuIiIiCiAgICBjcCA9IF9jYWxsKHJ1biwgW19wKHJvb3QsIFNTSEQpLCAiLXQiLCAiLWYiLCBwYXRoIG9yIF9wKHJvb3QsIFNTSERfQ09ORklHKV0pCiAgICByZXR1cm4gY3AgaXMgbm90IE5vbmUgYW5kIGNwLnJldHVybmNvZGUgPT0gMAoKCmRlZiBlZmZlY3RpdmVfc2V0dGluZ3Mocm9vdCwgcnVuLCB1c2VyPSJyb290Iik6CiAgICAiIiLQlNC10LnRgdGC0LLRg9GO0YnQuNC1INC30L3QsNGH0LXQvdC40Y8gYHNzaGQgLVRgINC00LvRjyDRgdC+0LXQtNC40L3QtdC90LjRjyBgdXNlcmAgKNC60LvRjtGH0Lgg0LIg0L3QuNC20L3QtdC8INGA0LXQs9C40YHRgtGA0LU7INC/0L7QstGC0L7RgCDigJQgTm9uZSkuIiIiCiAgICBzcGVjID0gRUZGRUNUSVZFX1NQRUMgaWYgdXNlciA9PSAicm9vdCIgZWxzZSBFRkZFQ1RJVkVfU1BFQy5yZXBsYWNlKCJ1c2VyPXJvb3QiLCAidXNlcj0iICsgdXNlciwgMSkKICAgIGNwID0gX2NhbGwocnVuLCBbX3Aocm9vdCwgU1NIRCksICItVCIsICItQyIsIHNwZWMsICItZiIsIF9wKHJvb3QsIFNTSERfQ09ORklHKV0pCiAgICBpZiBjcCBpcyBOb25lIG9yIGNwLnJldHVybmNvZGUgIT0gMDoKICAgICAgICByYWlzZSBfb3RoZXIoInNzaGQtZWZmZWN0aXZlOnF1ZXJ5LWZhaWxlZCIpCiAgICB0cnk6CiAgICAgICAgb3V0ID0gY3Auc3Rkb3V0LmRlY29kZSgidXRmLTgiKSBpZiBpc2luc3RhbmNlKGNwLnN0ZG91dCwgYnl0ZXMpIGVsc2UgY3Auc3Rkb3V0CiAgICBleGNlcHQgVW5pY29kZURlY29kZUVycm9yOgogICAgICAgIHJhaXNlIF9vdGhlcigic3NoZC1lZmZlY3RpdmU6cXVlcnktZmFpbGVkIikKICAgIHZhbHVlcyA9IHt9CiAgICBmb3IgbGluZSBpbiBvdXQuc3BsaXQoIlxuIik6CiAgICAgICAgcGFydHMgPSBsaW5lLnJzdHJpcCgiXHIiKS5zcGxpdChOb25lLCAxKQogICAgICAgIGlmIG5vdCBwYXJ0czoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBuYW1lID0gcGFydHNbMF0ubG93ZXIoKQogICAgICAgIHZhbHVlc1tuYW1lXSA9IE5vbmUgaWYgbmFtZSBpbiB2YWx1ZXMgZWxzZSAocGFydHNbMV0uc3RyaXAoKSBpZiBsZW4ocGFydHMpID09IDIgZWxzZSAiIikKICAgIHJldHVybiB2YWx1ZXMKCgpkZWYgX2VmZmVjdGl2ZV92YWx1ZSh2YWx1ZXMsIGxrZXkpOgogICAgdmFsdWUgPSB2YWx1ZXMuZ2V0KGxrZXkpCiAgICBpZiB2YWx1ZSBpcyBOb25lIG9yIG5vdCB2YWx1ZSBvciBsZW4odmFsdWUuc3BsaXQoKSkgIT0gMToKICAgICAgICByYWlzZSBfb3RoZXIoInNzaGQtZWZmZWN0aXZlOmFtYmlndW91cy12YWx1ZSIpCiAgICByZXR1cm4gdmFsdWUubG93ZXIoKQoKCmRlZiBwb2xpY3lfY3VycmVudChtYWluX25vLCBlZmZlY3RpdmUpOgogICAgcmV0dXJuICJtYWluX2dsb2JhbF9ubz0lZDtlZmZlY3RpdmU9JXMiICUgKG1haW5fbm8sIGVmZmVjdGl2ZSkKCgpkZWYgX3JlYWRfYWNjb3VudF9maWxlKHJvb3QsIHBhdGgsIHJlYXNvbik6CiAgICAiIiLQodGC0YDQvtC60LggL2V0Yy9ncm91cCDQuNC70LggL2V0Yy9wYXNzd2Q6INC+0LHRi9GH0L3Ri9C5INGE0LDQudC7INCx0LXQtyDQvtC20LjQtNCw0L3QuNGPIChGSUZPIOKAlCDQvtGC0LrQsNC3KSwgVVRGLTguIiIiCiAgICB0cnk6CiAgICAgICAgcmF3LCBfc3QgPSBfcmVhZF9yZWd1bGFyKF9wKHJvb3QsIHBhdGgpLCBfb3RoZXIocmVhc29uKSkKICAgICAgICByZXR1cm4gcmF3LmRlY29kZSgidXRmLTgiKS5zcGxpdCgiXG4iKQogICAgZXhjZXB0IChfUmVmdXNlZCwgVW5pY29kZURlY29kZUVycm9yKToKICAgICAgICByYWlzZSBfb3RoZXIocmVhc29uKQoKCmRlZiBfcmVhZF9ncm91cHMocm9vdCk6CiAgICBsaW5lcyA9IF9yZWFkX2FjY291bnRfZmlsZShyb290LCBHUk9VUCwgImdyb3VwOnJlYWQtZmFpbGVkIikKICAgIGdyb3VwcyA9IHt9CiAgICBmb3IgbGluZSBpbiBsaW5lczoKICAgICAgICBpZiBub3QgbGluZSBvciBsaW5lLnN0YXJ0c3dpdGgoIiMiKToKICAgICAgICAgICAgY29udGludWUKICAgICAgICBmaWVsZHMgPSBsaW5lLnNwbGl0KCI6IikKICAgICAgICBpZiBsZW4oZmllbGRzKSAhPSA0OgogICAgICAgICAgICByYWlzZSBfb3RoZXIoImdyb3VwOmludmFsaWQtbGluZSIpCiAgICAgICAgZ3JvdXBzLnNldGRlZmF1bHQoZmllbGRzWzBdLCBbbSBmb3IgbSBpbiBmaWVsZHNbM10uc3BsaXQoIiwiKSBpZiBtXSkKICAgIHJldHVybiBncm91cHMKCgpkZWYgX3JlYWRfaG9tZXMocm9vdCk6CiAgICAiIiJ70L/QvtC70YzQt9C+0LLQsNGC0LXQu9GMOiAo0LTQvtC80LDRiNC90LjQuSDQutCw0YLQsNC70L7QsywgdWlkLCDQvtGB0L3QvtCy0L3QvtC5IGdpZCl9INC40LcgL2V0Yy9wYXNzd2QuIiIiCiAgICBsaW5lcyA9IF9yZWFkX2FjY291bnRfZmlsZShyb290LCBQQVNTV0QsICJwYXNzd2Q6cmVhZC1mYWlsZWQiKQogICAgaG9tZXMgPSB7fQogICAgZm9yIGxpbmUgaW4gbGluZXM6CiAgICAgICAgaWYgbm90IGxpbmUgb3IgbGluZS5zdGFydHN3aXRoKCIjIik6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgZmllbGRzID0gbGluZS5zcGxpdCgiOiIpCiAgICAgICAgaWYgbGVuKGZpZWxkcykgIT0gNyBvciBub3QgcmUuZnVsbG1hdGNoKHIiWzAtOV0rIiwgZmllbGRzWzJdKToKICAgICAgICAgICAgcmFpc2UgX290aGVyKCJwYXNzd2Q6aW52YWxpZC1saW5lIikKICAgICAgICBpZiBub3QgcmUuZnVsbG1hdGNoKHIiWzAtOV0rIiwgZmllbGRzWzNdKToKICAgICAgICAgICAgcmFpc2UgX290aGVyKCJwYXNzd2Q6aW52YWxpZC1saW5lIikKICAgICAgICBob21lcy5zZXRkZWZhdWx0KGZpZWxkc1swXSwgKGZpZWxkc1s1XSwgaW50KGZpZWxkc1syXSksIGludChmaWVsZHNbM10pKSkKICAgIHJldHVybiBob21lcwoKCmRlZiBfc3RyaWN0X29rKHJvb3QsIHBhdGgsIHVpZCk6CiAgICAiIiLQo9GB0LvQvtCy0LjQtSBTdHJpY3RNb2RlcyBzc2hkINC00LvRjyDQvtC00L3QvtCz0L4g0L/Rg9GC0Lg6INCy0LvQsNC00LXQu9C10YYgcm9vdCDQuNC70Lgg0L/QvtC70YzQt9C+0LLQsNGC0LXQu9GMLCDQsdC10Lcg0LfQsNC/0LjRgdC4IGcvby4KCiAgICDQkiDRgtC10YHRgtC+0LLQvtC8INC00LXRgNC10LLQtSAoYF9yb290YCkg0LLQu9Cw0LTQtdC70YzRhtC10Lwg0LTQvtC/0YPRgdC60LDQtdGC0YHRjyDQuCDRgtC10LrRg9GJ0LjQuSDQv9C+0LvRjNC30L7QstCw0YLQtdC70YwuIiIiCiAgICB0cnk6CiAgICAgICAgc3QgPSBvcy5sc3RhdChwYXRoKQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBvd25lcnMgPSB7MCwgdWlkfSB8ICh7b3MuZ2V0ZXVpZCgpfSBpZiByb290IGlzIG5vdCBOb25lIGVsc2Ugc2V0KCkpCiAgICByZXR1cm4gc3Quc3RfdWlkIGluIG93bmVycyBhbmQgbm90IHN0YXQuU19JTU9ERShzdC5zdF9tb2RlKSAmIDBvMDIyCgoKZGVmIF91c2VyX2dpZHMocm9vdCwgdXNlciwgcHJpbWFyeV9naWQpOgogICAgIiIi0JPRgNGD0L/Qv9GLINC/0L7Qu9GM0LfQvtCy0LDRgtC10LvRjzog0L7RgdC90L7QstC90LDRjyDQuCDRgtC1LCDQs9C00LUg0L7QvSDRg9C60LDQt9Cw0L0g0YPRh9Cw0YHRgtC90LjQutC+0Lwg0LIgL2V0Yy9ncm91cC4iIiIKICAgIGdpZHMgPSB7cHJpbWFyeV9naWR9CiAgICBmb3IgbGluZSBpbiBfcmVhZF9hY2NvdW50X2ZpbGUocm9vdCwgR1JPVVAsICJncm91cDpyZWFkLWZhaWxlZCIpOgogICAgICAgIGZpZWxkcyA9IGxpbmUuc3BsaXQoIjoiKQogICAgICAgIGlmIGxlbihmaWVsZHMpID09IDQgYW5kIHJlLmZ1bGxtYXRjaChyIlswLTldKyIsIGZpZWxkc1syXSkgYW5kIHVzZXIgaW4gZmllbGRzWzNdLnNwbGl0KCIsIik6CiAgICAgICAgICAgIGdpZHMuYWRkKGludChmaWVsZHNbMl0pKQogICAgcmV0dXJuIGdpZHMKCgpkZWYgX3VzZXJfbWF5KHJvb3QsIHBhdGgsIHVpZCwgZ2lkcywgYml0cyk6CiAgICAiIiLQnNC+0LbQtdGCINC70Lgg0L/QvtC70YzQt9C+0LLQsNGC0LXQu9GMICh1aWQsIGdpZHMpINC/0L7Qu9GD0YfQuNGC0Ywg0LTQvtGB0YLRg9C/IGBiaXRzYCAoNCDigJQg0YfRgtC10L3QuNC1LCAxIOKAlCDQv9GA0L7RhdC+0LQpINC6INC/0YPRgtC4CiAgICDQv9C+INCx0LjRgtCw0Lwg0LLQu9Cw0LTQtdC70YzRhtCwLCDQs9GA0YPQv9C/0Ysg0LjQu9C4INC/0YDQvtGH0LjRhSDigJQg0LrQsNC6INC/0YDQvtCy0LXRgNC40YIg0Y/QtNGA0L4g0L/RgNC4INCy0YXQvtC00LUg0L7RgiDQtdCz0L4g0LjQvNC10L3QuC4KCiAgICDQkiDRgtC10YHRgtC+0LLQvtC8INC00LXRgNC10LLQtSAoYF9yb290YCkg0L7QsdGK0LXQutGCINGC0LXQutGD0YnQtdCz0L4g0L/QvtC70YzQt9C+0LLQsNGC0LXQu9GPINGB0YfQuNGC0LDQtdGC0YHRjyDQvtCx0YrQtdC60YLQvtC8INCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGA0LAuIiIiCiAgICB0cnk6CiAgICAgICAgc3QgPSBvcy5zdGF0KHBhdGgpCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICByZXR1cm4gRmFsc2UKICAgIG1vZGUgPSBzdGF0LlNfSU1PREUoc3Quc3RfbW9kZSkKICAgIGlmIHN0LnN0X3VpZCA9PSB1aWQgb3IgKHJvb3QgaXMgbm90IE5vbmUgYW5kIHN0LnN0X3VpZCA9PSBvcy5nZXRldWlkKCkpOgogICAgICAgIHJldHVybiBib29sKChtb2RlID4+IDYpICYgYml0cyA9PSBiaXRzKQogICAgaWYgc3Quc3RfZ2lkIGluIGdpZHM6CiAgICAgICAgcmV0dXJuIGJvb2woKG1vZGUgPj4gMykgJiBiaXRzID09IGJpdHMpCiAgICByZXR1cm4gYm9vbChtb2RlICYgYml0cyA9PSBiaXRzKQoKCmRlZiBhZG1pbl91c2Vycyhncm91cHMpOgogICAgIiIi0KPRh9Cw0YHRgtC90LjQutC4INCz0YDRg9C/0L8gc3VkbyDQuCBhZG1pbiAo0L/QvtC70LUg0YPRh9Cw0YHRgtC90LjQutC+0LIgL2V0Yy9ncm91cCksINC60YDQvtC80LUgcm9vdC4iIiIKICAgIHVzZXJzID0gW10KICAgIGZvciBuYW1lIGluIFNVRE9fR1JPVVBTOgogICAgICAgIGZvciBtZW1iZXIgaW4gZ3JvdXBzLmdldChuYW1lLCBbXSk6CiAgICAgICAgICAgIGlmIG1lbWJlciAhPSAicm9vdCIgYW5kIG1lbWJlciBub3QgaW4gdXNlcnM6CiAgICAgICAgICAgICAgICB1c2Vycy5hcHBlbmQobWVtYmVyKQogICAgcmV0dXJuIHVzZXJzCgoKTUFYX1NZTUxJTktfSE9QUyA9IDQwCgoKZGVmIF93YWxrX3BhdGgocm9vdCwgcGF0aCk6CiAgICAiIiLQoNCw0LfQsdC+0YAg0L/Rg9GC0LggYHBhdGhgICjQutCw0Log0LXQs9C+INCy0LjQtNC40YIg0YHQuNGB0YLQtdC80LA7INCyINGC0LXRgdGC0L7QstC+0Lwg0LTQtdGA0LXQstC1IOKAlCDQvtGCINC10LPQviDQutC+0YDQvdGPKSwg0LrQsNC6INC/0YDQuCDQvtCx0YDQsNGJ0LXQvdC40Lgg0Y/QtNGA0LA6INC/0L4g0L7QtNC90L7QvNGDINC60L7QvNC/0L7QvdC10L3RgtGDLCDRgdC+INCy0YHQtdC80Lgg0L/QtdGA0LXRhdC+0LTQsNC80Lgg0L/QvgogICAg0YHQuNC80LLQvtC70LjRh9C10YHQutC40Lwg0YHRgdGL0LvQutCw0LwgKNGG0LXQu9GMINGB0YHRi9C70LrQuCDRgNCw0LfQsdC40YDQsNC10YLRgdGPINGC0LDQuiDQttC1LCDQvtGCIMKrL8K7INC40LvQuCDQvtGCINGC0LXQutGD0YnQtdCz0L4g0LrQsNGC0LDQu9C+0LPQsCkuCgogICAg0JLQvtC30LLRgNCw0YnQsNC10YIgKNGE0LDQutGC0LjRh9C10YHQutC40Lkg0L/Rg9GC0YwsINC60LDRgtCw0LvQvtCz0LgsINGH0LXRgNC10Lcg0LrQvtGC0L7RgNGL0LUg0L/RgNC+0YXQvtC00LjRgiDRgNCw0LfQsdC+0YAg4oCUINC00LvRjyDQutCw0LbQtNC+0LPQviDQvdGD0LbQtdC9CiAgICDQsdC40YIg0L/RgNC+0YXQvtC00LApINC40LvQuCBOb25lOiDQvtCx0YrQtdC60YIg0L7RgtGB0YPRgtGB0YLQstGD0LXRgiwg0L/QtdGC0LvRjyDRgdGB0YvQu9C+0LosINC90LUt0LrQsNGC0LDQu9C+0LMg0L/QtdGA0LXQtCDCqy/CuyAo0LIg0YLQvtC8INGH0LjRgdC70LUKICAgINC30LDQstC10YDRiNCw0Y7RidC40Lwgwqsvwrsg0YbQtdC70Lgg0YHRgdGL0LvQutC4IOKAlCBFTk9URElSKSwg0LLRi9GF0L7QtCDQt9CwINC60L7RgNC10L3RjCDRgtC10YHRgtC+0LLQvtCz0L4g0LTQtdGA0LXQstCwLgogICAg0JIg0YLQtdGB0YLQvtCy0L7QvCDQtNC10YDQtdCy0LUgKGBfcm9vdGApINC/0YDQtdC00LrQuCDQtdCz0L4g0LrQvtGA0L3RjyDQvdC1INC/0YDQvtCy0LXRgNGP0Y7RgtGB0Y8sINC/0YDQvtGH0LjQtSDQutCw0YLQsNC70L7Qs9C4INCy0L3QtSDQutC+0YDQvdGPIOKAlAogICAg0L7RgtC60LDQtywgwqsuLsK7INC40Lcg0LrQvtGA0L3RjyDQuNC70Lgg0LjQtyDQtdCz0L4g0L/RgNC10LTQutCwIOKAlCDQvtGC0LrQsNC3OyDQsiDRgNCw0LHQvtGH0LXQuSDRgdC40YHRgtC10LzQtSDQutC+0YDQtdC90Ywg4oCUIMKrL8K7LiIiIgogICAgYW5jaG9yID0gb3MucGF0aC5yZWFscGF0aChyb290KSBpZiByb290IGlzIG5vdCBOb25lIGVsc2UgIi8iCiAgICBwcmVmaXggPSBhbmNob3IucnN0cmlwKCIvIikgKyAiLyIKCiAgICBkZWYgaW5zaWRlKHApOgogICAgICAgIHJldHVybiBwID09IGFuY2hvciBvciBwLnN0YXJ0c3dpdGgocHJlZml4KQoKICAgIGRlZiBhbmNlc3Rvcl9vZl9hbmNob3IocCk6CiAgICAgICAgcmV0dXJuIGFuY2hvciA9PSBwIG9yIGFuY2hvci5zdGFydHN3aXRoKHAucnN0cmlwKCIvIikgKyAiLyIpCgogICAgZGVmIHNwbGl0KHRleHQpOgogICAgICAgICMg0JfQsNCy0LXRgNGI0LDRjtGJ0LjQuSDCqy/CuyDigJQg0YLRgNC10LHQvtCy0LDQvdC40LUg0LrQsNGC0LDQu9C+0LPQsDog0L/Rg9GB0YLQvtC5INC60L7QvNC/0L7QvdC10L3RgiDQsiDQutC+0L3RhtC1INGB0L7RhdGA0LDQvdGP0LXRgtGB0Y8uCiAgICAgICAgcGFydHMgPSBbcGFydCBmb3IgcGFydCBpbiB0ZXh0LnNwbGl0KCIvIikgaWYgcGFydF0KICAgICAgICByZXR1cm4gcGFydHMgKyBbIiJdIGlmIHBhcnRzIGFuZCB0ZXh0LmVuZHN3aXRoKCIvIikgZWxzZSBwYXJ0cwoKICAgIHBlbmRpbmcgPSBzcGxpdChwYXRoKQogICAgY3VycmVudCwgd2Fsa2VkLCBob3BzID0gYW5jaG9yLCBbXSwgMAogICAgd2hpbGUgcGVuZGluZzoKICAgICAgICBwYXJ0ID0gcGVuZGluZy5wb3AoMCkKICAgICAgICBpZiBwYXJ0IGluICgiLiIsICIiKToKICAgICAgICAgICAgY29udGludWUKICAgICAgICBpZiBpbnNpZGUoY3VycmVudCk6CiAgICAgICAgICAgIHdhbGtlZC5hcHBlbmQoY3VycmVudCkKICAgICAgICBlbGlmIG5vdCBhbmNlc3Rvcl9vZl9hbmNob3IoY3VycmVudCk6CiAgICAgICAgICAgIHJldHVybiBOb25lCiAgICAgICAgaWYgcGFydCA9PSAiLi4iOgogICAgICAgICAgICBpZiByb290IGlzIG5vdCBOb25lIGFuZCBub3QgY3VycmVudC5zdGFydHN3aXRoKHByZWZpeCk6CiAgICAgICAgICAgICAgICByZXR1cm4gTm9uZQogICAgICAgICAgICBjdXJyZW50ID0gb3MucGF0aC5kaXJuYW1lKGN1cnJlbnQpCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgY2FuZGlkYXRlID0gb3MucGF0aC5qb2luKGN1cnJlbnQsIHBhcnQpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzdCA9IG9zLmxzdGF0KGNhbmRpZGF0ZSkKICAgICAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICAgICAgcmV0dXJuIE5vbmUKICAgICAgICBpZiBzdGF0LlNfSVNMTksoc3Quc3RfbW9kZSk6CiAgICAgICAgICAgIGhvcHMgKz0gMQogICAgICAgICAgICBpZiBob3BzID4gTUFYX1NZTUxJTktfSE9QUzoKICAgICAgICAgICAgICAgIHJldHVybiBOb25lCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHRhcmdldCA9IG9zLnJlYWRsaW5rKGNhbmRpZGF0ZSkKICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgICAgICAgICByZXR1cm4gTm9uZQogICAgICAgICAgICBwZW5kaW5nID0gc3BsaXQodGFyZ2V0KSArIHBlbmRpbmcKICAgICAgICAgICAgaWYgdGFyZ2V0LnN0YXJ0c3dpdGgoIi8iKToKICAgICAgICAgICAgICAgIGN1cnJlbnQgPSAiLyIKICAgICAgICAgICAgY29udGludWUKICAgICAgICBpZiBwZW5kaW5nIGFuZCBub3Qgc3RhdC5TX0lTRElSKHN0LnN0X21vZGUpOgogICAgICAgICAgICByZXR1cm4gTm9uZQogICAgICAgIGN1cnJlbnQgPSBjYW5kaWRhdGUKICAgIGlmIG5vdCBpbnNpZGUoY3VycmVudCk6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIHJldHVybiBjdXJyZW50LCB3YWxrZWQKCgpkZWYgX3N0cmljdF9jaGFpbihyb290LCBwYXRoLCByZWFsX2hvbWUpOgogICAgIiIi0JrQsNGC0LDQu9C+0LPQuCwg0LrQvtGC0L7RgNGL0LUg0L/RgNC+0LLQtdGA0Y/QtdGCIFN0cmljdE1vZGVzIHNzaGQgKGF1dGhfc2VjdXJlX3BhdGgpOiDQvtGCINC60LDRgtCw0LvQvtCz0LAg0YTQsNC50LvQsCDQstCy0LXRgNGFCiAgICDQtNC+INC00L7QvNCw0YjQvdC10LPQviDQutCw0YLQsNC70L7Qs9CwINCy0LrQu9GO0YfQuNGC0LXQu9GM0L3Qviwg0LAg0LXRgdC70Lgg0YTQsNC50Lsg0LLQvdC1INC90LXQs9C+IOKAlCDQtNC+IMKrL8K7ICjQsiDRgtC10YHRgtC+0LLQvtC8INC00LXRgNC10LLQtSDigJQKICAgINC00L4g0LXQs9C+INC60L7RgNC90Y8pLiIiIgogICAgYW5jaG9yID0gb3MucGF0aC5yZWFscGF0aChyb290KSBpZiByb290IGlzIG5vdCBOb25lIGVsc2UgIi8iCiAgICBjaGFpbiwgY3VycmVudCA9IFtdLCBvcy5wYXRoLmRpcm5hbWUocGF0aCkKICAgIHdoaWxlIFRydWU6CiAgICAgICAgY2hhaW4uYXBwZW5kKGN1cnJlbnQpCiAgICAgICAgaWYgY3VycmVudCA9PSByZWFsX2hvbWUgb3IgY3VycmVudCA9PSBhbmNob3Igb3IgY3VycmVudCA9PSAiLyI6CiAgICAgICAgICAgIHJldHVybiBjaGFpbgogICAgICAgIGN1cnJlbnQgPSBvcy5wYXRoLmRpcm5hbWUoY3VycmVudCkKCgpkZWYgX2hhc19rZXkocm9vdCwgaG9tZSwgdWlkLCBnaWRzLCByZWwsIHN0cmljdCk6CiAgICAiIiLQn9GA0LjQs9C+0LTQvdGL0Lkg0LrQu9GO0Yc6INC90LXQv9GD0YHRgtC+0Lkg0YTQsNC50LssINC60L7RgtC+0YDRi9C5INCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGAINC80L7QttC10YIg0L/RgNC+0YfQuNGC0LDRgtGMLCDQv9GA0L7QudC00Y8g0L/QviDQstGB0LXQvAogICAg0LrQsNGC0LDQu9C+0LPQsNC8INGE0LDQutGC0LjRh9C10YHQutC+0LPQviDQv9GD0YLQuCDQvtGCIMKrL8K7IOKAlCDRgSDRgNCw0LfQsdC+0YDQvtC8INC60LDQttC00L7QuSDRgdC40LzQstC+0LvQuNGH0LXRgdC60L7QuSDRgdGB0YvQu9C60Lgg0L/QviDQv9GD0YLQuCDQuAogICAg0L/RgNC+0LLQtdGA0LrQvtC5INC60LDRgtCw0LvQvtCz0L7QsiDQtdGRINGG0LXQu9C4IChzc2hkINGH0LjRgtCw0LXRgiDQutC70Y7Rh9C4INC+0YIg0LjQvNC10L3QuCDQv9C+0LvRjNC30L7QstCw0YLQtdC70Y8pOyDQv9GA0LggU3RyaWN0TW9kZXMg4oCUCiAgICDQtdGJ0ZEg0L/RgNCw0LLQsCDRhNCw0LnQu9CwINC4INC60LDRgtCw0LvQvtCz0L7QsiDQvtGCINGE0LDQudC70LAg0LTQviDQtNC+0LzQsNGI0L3QtdCz0L4g0LrQsNGC0LDQu9C+0LPQsCAo0LjQvdCw0YfQtSBzc2hkINC60LvRjtGHINC+0YLQstC10YDQs9C90LXRgikuCiAgICDQkiDRgtC10YHRgtC+0LLQvtC8INC00LXRgNC10LLQtSAoYF9yb290YCkg0L/Rg9GC0Ywg0L/RgNC+0LLQtdGA0Y/QtdGC0YHRjyDQvtGCINC10LPQviDQutC+0YDQvdGPLiIiIgogICAgaWYgbm90IGhvbWUuc3RhcnRzd2l0aCgiLyIpIG9yIHJlbC5zdGFydHN3aXRoKCIvIik6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICB1c2VyX3BhdGggPSBob21lLnJzdHJpcCgiLyIpICsgIi8iICsgcmVsCiAgICByZXNvbHZlZCA9IF93YWxrX3BhdGgocm9vdCwgdXNlcl9wYXRoKQogICAgaG9tZV9yZXNvbHZlZCA9IF93YWxrX3BhdGgocm9vdCwgaG9tZSkKICAgIGlmIHJlc29sdmVkIGlzIE5vbmUgb3IgaG9tZV9yZXNvbHZlZCBpcyBOb25lOgogICAgICAgIHJldHVybiBGYWxzZQogICAgcGF0aCwgd2Fsa2VkID0gcmVzb2x2ZWQKICAgIGlmIG5vdCBhbGwoX3VzZXJfbWF5KHJvb3QsIGQsIHVpZCwgZ2lkcywgMSkgZm9yIGQgaW4gd2Fsa2VkKToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGlmIG5vdCBfdXNlcl9tYXkocm9vdCwgcGF0aCwgdWlkLCBnaWRzLCA0KToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIGlmIHN0cmljdDoKICAgICAgICBjaGFpbiA9IF9zdHJpY3RfY2hhaW4ocm9vdCwgcGF0aCwgaG9tZV9yZXNvbHZlZFswXSkKICAgICAgICBpZiBub3QgX3N0cmljdF9vayhyb290LCBwYXRoLCB1aWQpIG9yIG5vdCBhbGwoX3N0cmljdF9vayhyb290LCBkLCB1aWQpIGZvciBkIGluIGNoYWluKToKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCiAgICB0cnk6CiAgICAgICAgcmF3LCBfc3QgPSBfcmVhZF9yZWd1bGFyKHBhdGgsIF9vdGhlcigia2V5czppbnZhbGlkLXR5cGUiKSkKICAgIGV4Y2VwdCBfUmVmdXNlZDoKICAgICAgICByZXR1cm4gRmFsc2UKICAgIHJldHVybiBhbnkobC5zdHJpcCgpIGFuZCBub3QgbC5zdHJpcCgpLnN0YXJ0c3dpdGgoIiMiKQogICAgICAgICAgICAgICBmb3IgbCBpbiByYXcuZGVjb2RlKCJ1dGYtOCIsIGVycm9ycz0icmVwbGFjZSIpLnNwbGl0KCJcbiIpKQoKCkFDQ0VTU19SRVNUUklDVElPTlMgPSAoImFsbG93dXNlcnMiLCAiZGVueXVzZXJzIiwgImFsbG93Z3JvdXBzIiwgImRlbnlncm91cHMiKQoKCmRlZiBhZG1pbl9hY2Nlc3Mocm9vdCwgcnVuLCB1c2Vycyk6CiAgICAiIiLQlNC+0YHRgtGD0L8g0LDQtNC80LjQvdC40YHRgtGA0LDRgtC+0YDQvtCyINC/0L4gU1NIOiBbKNC/0L7Qu9GM0LfQvtCy0LDRgtC10LvRjCwg0LrQu9GO0Ycg0L/RgNC40LPQvtC00LXQvSwg0L/QsNGA0L7Qu9GMINGA0LDQt9GA0LXRiNGR0L0pXSDQuCDQv9GA0LjQt9C90LDQugogICAg0L3QsNGB0YLRgNC+0LnQutC4LCDQutC+0YLQvtGA0YPRjiDQvNC10YXQsNC90LjQt9C8INC90LUg0L/RgNC+0LLQtdGA0Y/QtdGCLgoKICAgINCS0YHRkSDQsdC10YDRkdGC0YHRjyDQuNC3IGBzc2hkIC1UYCDQtNC70Y8g0YHQvtC10LTQuNC90LXQvdC40Y8g0YHQsNC80L7Qs9C+INCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGA0LAgKGBNYXRjaCBVc2VyYCDRg9GH0LjRgtGL0LLQsNC10YLRgdGPKS4KICAgINCd0LXQv9GA0L7QstC10YDRj9C10LzQvjogQWxsb3dVc2Vycy9EZW55VXNlcnMvQWxsb3dHcm91cHMvRGVueUdyb3VwcywgQXV0aGVudGljYXRpb25NZXRob2RzLCDQvtGC0LvQuNGH0L3Ri9C1CiAgICDQvtGCIGBhbnlgLCDQvdC10YHRgtCw0L3QtNCw0YDRgtC90YvQtSBBdXRob3JpemVkS2V5c0ZpbGUg0LjQu9C4IFB1YmtleUF1dGhlbnRpY2F0aW9uIOKAlCDRgtCw0LrQvtC5INCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGACiAgICDQvdC1INC30LDRgdGH0LjRgtGL0LLQsNC10YLRgdGPLgogICAgIiIiCiAgICBob21lcyA9IF9yZWFkX2hvbWVzKHJvb3QpCiAgICBhY2Nlc3MsIHVudmVyaWZpZWQgPSBbXSwgRmFsc2UKICAgIGZvciB1c2VyIGluIHVzZXJzOgogICAgICAgIGlmIHVzZXIgbm90IGluIGhvbWVzIG9yIG5vdCBVU0VSX05BTUVfUkUuZnVsbG1hdGNoKHVzZXIpOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIHZhbHVlcyA9IGVmZmVjdGl2ZV9zZXR0aW5ncyhyb290LCBydW4sIHVzZXIpCiAgICAgICAga2V5X2ZpbGVzID0gdHVwbGUoKHZhbHVlcy5nZXQoImF1dGhvcml6ZWRrZXlzZmlsZSIpIG9yICIiKS5zcGxpdCgpKQogICAgICAgIGlmIChhbnkobmFtZSBpbiB2YWx1ZXMgZm9yIG5hbWUgaW4gQUNDRVNTX1JFU1RSSUNUSU9OUykKICAgICAgICAgICAgICAgIG9yICh2YWx1ZXMuZ2V0KCJhdXRoZW50aWNhdGlvbm1ldGhvZHMiKSBvciAiYW55IikubG93ZXIoKSAhPSAiYW55IgogICAgICAgICAgICAgICAgb3Iga2V5X2ZpbGVzIG5vdCBpbiBERUZBVUxUX0FVVEhPUklaRURfS0VZUwogICAgICAgICAgICAgICAgb3IgKHZhbHVlcy5nZXQoInB1YmtleWF1dGhlbnRpY2F0aW9uIikgb3IgIiIpLmxvd2VyKCkgIT0gInllcyIpOgogICAgICAgICAgICB1bnZlcmlmaWVkID0gVHJ1ZQogICAgICAgICAgICBjb250aW51ZQogICAgICAgIHN0cmljdCA9ICh2YWx1ZXMuZ2V0KCJzdHJpY3Rtb2RlcyIpIG9yICJ5ZXMiKS5sb3dlcigpICE9ICJubyIKICAgICAgICBob21lLCB1aWQsIGdpZCA9IGhvbWVzW3VzZXJdCiAgICAgICAgZ2lkcyA9IF91c2VyX2dpZHMocm9vdCwgdXNlciwgZ2lkKQogICAgICAgIGtleWVkID0gYW55KF9oYXNfa2V5KHJvb3QsIGhvbWUsIHVpZCwgZ2lkcywgcmVsLCBzdHJpY3QpIGZvciByZWwgaW4ga2V5X2ZpbGVzKQogICAgICAgIHBhc3N3b3JkID0gYW55KCh2YWx1ZXMuZ2V0KG5hbWUpIG9yICIiKS5sb3dlcigpID09ICJ5ZXMiCiAgICAgICAgICAgICAgICAgICAgICAgZm9yIG5hbWUgaW4gKCJwYXNzd29yZGF1dGhlbnRpY2F0aW9uIiwgImtiZGludGVyYWN0aXZlYXV0aGVudGljYXRpb24iKSkKICAgICAgICBhY2Nlc3MuYXBwZW5kKCh1c2VyLCBrZXllZCwgcGFzc3dvcmQpKQogICAgcmV0dXJuIGFjY2VzcywgdW52ZXJpZmllZAoKCmNsYXNzIF9TdGFnZUZhaWxlZChPU0Vycm9yKToKICAgICIiItCe0YjQuNCx0LrQsCDQv9C+0LTQs9C+0YLQvtCy0LrQuCDQstGA0LXQvNC10L3QvdC+0LPQviDRhNCw0LnQu9CwLCDQv9C+0YHQu9C1INC60L7RgtC+0YDQvtC5INC10LPQviDQvdC1INGD0LTQsNC70L7RgdGMINGD0LTQsNC70LjRgtGMLiIiIgoKICAgIGRlZiBfX2luaXRfXyhzZWxmLCB0bXApOgogICAgICAgIHN1cGVyKCkuX19pbml0X18oInN0YWdlIGZhaWxlZCwgdGVtcG9yYXJ5IGZpbGUgbGVmdDogIiArIHRtcCkKICAgICAgICBzZWxmLnRtcCA9IHRtcAoKCmRlZiBfc3RhZ2VfZmlsZShwYXRoLCByYXcsIHN0KToKICAgICIiItCS0YDQtdC80LXQvdC90YvQuSDRhNCw0LnQuyBgPNC/0YPRgtGMPi5zbHAtdG1wYCDQsiDRgtC+0Lwg0LbQtSDQutCw0YLQsNC70L7Qs9C1OiDQstGB0LUg0LHQsNC50YLRiywg0L/RgNC10LbQvdC40LUg0YDQtdC20LjQvCDQuCDQstC70LDQtNC10LvQtdGGLiIiIgogICAgdG1wID0gcGF0aCArIFRNUF9TVUZGSVgKICAgIGZkID0gb3Mub3Blbih0bXAsIG9zLk9fV1JPTkxZIHwgb3MuT19DUkVBVCB8IG9zLk9fRVhDTCB8IG9zLk9fTk9GT0xMT1cgfCBvcy5PX0NMT0VYRUMsIDBvNjAwKQogICAgdHJ5OgogICAgICAgIHZpZXcgPSBtZW1vcnl2aWV3KHJhdykKICAgICAgICB3aGlsZSB2aWV3OgogICAgICAgICAgICB3cml0dGVuID0gb3Mud3JpdGUoZmQsIHZpZXcpCiAgICAgICAgICAgIGlmIHdyaXR0ZW4gPD0gMDoKICAgICAgICAgICAgICAgIHJhaXNlIE9TRXJyb3IoInNob3J0IHdyaXRlIikKICAgICAgICAgICAgdmlldyA9IHZpZXdbd3JpdHRlbjpdCiAgICAgICAgIyDQodC90LDRh9Cw0LvQsCDQstC70LDQtNC10LvQtdGGLCDQt9Cw0YLQtdC8INC/0L7Qu9C90YvQuSDRgNC10LbQuNC8OiBmY2hvd24g0YHQvdC40LzQsNC10YIgU1VJRC9TR0lELCBmY2htb2Qg0LjRhSDQstC+0LfQstGA0LDRidCw0LXRgi4KICAgICAgICBpZiBvcy5nZXRldWlkKCkgPT0gMDoKICAgICAgICAgICAgb3MuZmNob3duKGZkLCBzdC5zdF91aWQsIHN0LnN0X2dpZCkKICAgICAgICBvcy5mY2htb2QoZmQsIHN0YXQuU19JTU9ERShzdC5zdF9tb2RlKSkKICAgICAgICBvcy5mc3luYyhmZCkKICAgIGV4Y2VwdCBCYXNlRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICBfY2xvc2VfcXVpZXRseShmZCkKICAgICAgICBfYWJhbmRvbih0bXAsIGV4YykKICAgIHRyeToKICAgICAgICBvcy5jbG9zZShmZCkKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICBfYWJhbmRvbih0bXAsIGV4YykKICAgIHJldHVybiB0bXAKCgpkZWYgX2FiYW5kb24odG1wLCBleGMpOgogICAgIiIi0KPQtNCw0LvQtdC90LjQtSDQvdC10LTQvtCz0L7RgtC+0LLQu9C10L3QvdC+0LPQviDQstGA0LXQvNC10L3QvdC+0LPQviDRhNCw0LnQu9CwINC4INC/0L7QstGC0L7RgNC90YvQuSDQv9C+0LTRitGR0Lwg0L7RiNC40LHQutC4LgoKICAgINCd0LUg0YPQtNCw0LvQvtGB0Ywg0YPQtNCw0LvQuNGC0Ywg4oCUIGBfU3RhZ2VGYWlsZWRgINGBINC/0YPRgtGR0LwsINGH0YLQvtCx0Ysg0LrQvtC80L/QtdC90YHQsNGG0LjRjyDRg9GH0LvQsCDQvtGB0YLQsNCy0YjQuNC50YHRjyDRhNCw0LnQuy4KICAgICIiIgogICAgdHJ5OgogICAgICAgIG9zLnVubGluayh0bXApCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICBpZiBpc2luc3RhbmNlKGV4YywgT1NFcnJvcik6CiAgICAgICAgICAgIHJhaXNlIF9TdGFnZUZhaWxlZCh0bXApIGZyb20gZXhjCiAgICAgICAgcmFpc2UgZXhjCiAgICByYWlzZSBleGMKCgpkZWYgX3dyaXRlX2ZpbGUocGF0aCwgcmF3LCBzdCk6CiAgICAiIiLQl9Cw0LzQtdC90LAg0YTQsNC50LvQsCDRh9C10YDQtdC3INCy0YDQtdC80LXQvdC90YvQuSDRhNCw0LnQuyDQsiDRgtC+0Lwg0LbQtSDQutCw0YLQsNC70L7Qs9C1OyDRgNC10LbQuNC8INC4INCy0LvQsNC00LXQu9C10YYg0L/RgNC10LbQvdC40LUuCgogICAg0J7RiNC40LHQutCwINC30LDQvNC10L3RiyDRg9C00LDQu9GP0LXRgiDQstGA0LXQvNC10L3QvdGL0Lkg0YTQsNC50LsgKNC+0YjQuNCx0LrQsCDRg9C00LDQu9C10L3QuNGPINC90LUg0YHQutGA0YvQstCw0LXRgiDQvtGI0LjQsdC60YMg0LfQsNC80LXQvdGLKS4KICAgICIiIgogICAgdG1wID0gX3N0YWdlX2ZpbGUocGF0aCwgcmF3LCBzdCkKICAgIHRyeToKICAgICAgICBvcy5yZXBsYWNlKHRtcCwgcGF0aCkKICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgIF9kaXNjYXJkKFt0bXBdKQogICAgICAgIHJhaXNlCgoKZGVmIF9ieXRlc19lcXVhbChwYXRoLCByYXcpOgogICAgdHJ5OgogICAgICAgIHJldHVybiBfcmVhZF9yZWd1bGFyKHBhdGgsIF9vdGhlcigic3NoZC1jb25maWc6cmVhZC1mYWlsZWQiKSlbMF0gPT0gcmF3CiAgICBleGNlcHQgKF9SZWZ1c2VkLCBPU0Vycm9yKToKICAgICAgICByZXR1cm4gRmFsc2UKCgpkZWYgX2Rpc2NhcmQocGF0aHMpOgogICAgIiIi0KPQtNCw0LvQtdC90LjQtSDQstGA0LXQvNC10L3QvdGL0YUg0YTQsNC50LvQvtCyOyBUcnVlLCDQtdGB0LvQuCDQstGB0LUg0YPQtNCw0LvQtdC90Ysg0LjQu9C4INC+0YLRgdGD0YLRgdGC0LLRg9GO0YIuIiIiCiAgICBvayA9IFRydWUKICAgIGZvciB0bXAgaW4gbGlzdChwYXRocyk6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBvcy51bmxpbmsodG1wKQogICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgcGFzcwogICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICBvayA9IEZhbHNlCiAgICByZXR1cm4gb2sKCgpkZWYgX3JlbG9hZChyb290LCBydW4pOgogICAgY3AgPSBfY2FsbChydW4sIFtfcChyb290LCBTWVNURU1DVEwpLCAidHJ5LXJlbG9hZC1vci1yZXN0YXJ0IiwgU1NIX1VOSVRdKQogICAgcmV0dXJuIGNwIGlzIG5vdCBOb25lIGFuZCBjcC5yZXR1cm5jb2RlID09IDAKCgpkZWYgX2RlZmF1bHRfcHJpdmlsZWdlX2NoZWNrKCkgLT4gYm9vbDoKICAgIHJldHVybiBvcy5nZXRldWlkKCkgPT0gMAoKCmRlZiBfY29tbWl0X3N0YXRlKG91dGNvbWUsIGRyeV9ydW4sIG11dGF0aW9uKToKICAgIGlmIG91dGNvbWUgPT0gIkFQUExJRUQiIG9yIChvdXRjb21lID09ICJBTFJFQURZX0NPTVBMSUFOVCIgYW5kIG5vdCBkcnlfcnVuKToKICAgICAgICByZXR1cm4gQ09NTUlUX0NPTU1JVFRFRAogICAgaWYgbXV0YXRpb246CiAgICAgICAgcmV0dXJuIENPTU1JVF9OT1RfQ09NTUlUVEVECiAgICByZXR1cm4gQ09NTUlUX05PVF9TVEFSVEVECgoKZGVmIF9yZXN1bHQoY29udHJvbF9pZCwgb3V0Y29tZSwgKiwgYWN0aW9ucywgZHJ5X3J1biwgbXV0YXRpb249RmFsc2UsICoqZXh0cmEpOgogICAgcmVjb3JkID0gewogICAgICAgICJhZGFwdGVyX2lkIjogQURBUFRFUl9JRCwKICAgICAgICAibWVjaGFuaXNtX2lkIjogTUVDSEFOSVNNX0lELAogICAgICAgICJjb250cm9sX2lkIjogY29udHJvbF9pZCwKICAgICAgICAidGFyZ2V0IjogU1NIRF9DT05GSUcsCiAgICAgICAgIm91dGNvbWUiOiBvdXRjb21lLAogICAgICAgICJyZWFzb24iOiBOb25lLAogICAgICAgICJwb2xpY3lfY3VycmVudCI6IE5vbmUsCiAgICAgICAgIm9wZXJhdG9yX2RlY2lzaW9uIjogTm9uZSwKICAgICAgICAiYWN0aW9uc19hdHRlbXB0ZWQiOiBsaXN0KGFjdGlvbnMpLAogICAgICAgICJtdXRhdGlvbl9wZXJmb3JtZWQiOiBib29sKG11dGF0aW9uKSwKICAgICAgICAidHJhbnNhY3Rpb25fY29tbWl0IjogX2NvbW1pdF9zdGF0ZShvdXRjb21lLCBkcnlfcnVuLCBtdXRhdGlvbiksCiAgICAgICAgImRyeV9ydW4iOiBib29sKGRyeV9ydW4pLAogICAgfQogICAgcmVjb3JkLnVwZGF0ZShleHRyYSkKICAgIGlmIHJlY29yZFsib3V0Y29tZSJdIG5vdCBpbiBPVVRDT01FUzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJvdXRjb21lIG91dHNpZGUgY2xvc2VkIHZvY2FidWxhcnkiKQogICAgcmV0dXJuIHJlY29yZAoKCmRlZiBvdXRjb21lX3JjX2NvbnRyaWJ1dGlvbihvdXRjb21lLCBkcnlfcnVuPUZhbHNlKToKICAgICIiIiIwIiDQtNC70Y8g0YPRgdC/0LXRiNC90YvRhSDQuNGB0YXQvtC00L7Qsiwg0LjQvdCw0YfQtSAibm9uemVybyIuIiIiCiAgICBpZiBvdXRjb21lIGluICgiQVBQTElFRCIsICJBTFJFQURZX0NPTVBMSUFOVCIsICJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiKToKICAgICAgICByZXR1cm4gIjAiCiAgICBpZiBkcnlfcnVuIGFuZCBvdXRjb21lID09ICJEUllfUlVOX1dPVUxEX0FQUExZIjoKICAgICAgICByZXR1cm4gIjAiCiAgICByZXR1cm4gIm5vbnplcm8iCgoKZGVmIF9vYnNlcnZlKHJvb3QsIHJ1biwga2V5KToKICAgICIiIihDb25maWcsINC00LXQudGB0YLQstGD0Y7RidC10LUg0LfQvdCw0YfQtdC90LjQtSwg0LLRgdC1INC30L3QsNGH0LXQvdC40Y8gc3NoZCAtVCkuIiIiCiAgICBsa2V5ID0ga2V5Lmxvd2VyKCkKICAgIHRyeToKICAgICAgICBjZmcgPSBDb25maWcocm9vdCwgbGtleSkKICAgIGV4Y2VwdCBfUmVmdXNlZCBhcyBleGM6CiAgICAgICAgaWYgZXhjLnJlYXNvbiA9PSAic3NoZC1jb25maWc6dW50cnVzdGVkIjoKICAgICAgICAgICAgcmFpc2UgX1JlZnVzZWQoZXhjLm91dGNvbWUsIGV4Yy5yZWFzb24sIF9hZG1pbihBQ1RJT05fRklMRS5mb3JtYXQocGF0aD1TU0hEX0NPTkZJRywga2V5PWtleSkpKQogICAgICAgIHJhaXNlCiAgICBpZiBub3QgX3RydXN0ZWQoY2ZnLmZpbGVzW2NmZy5tYWluXVsxXSwgcm9vdCk6CiAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwgInNzaGQtY29uZmlnOnVudHJ1c3RlZCIsCiAgICAgICAgICAgICAgICAgICAgICAgX2FkbWluKEFDVElPTl9GSUxFLmZvcm1hdChwYXRoPVNTSERfQ09ORklHLCBrZXk9a2V5KSkpCiAgICBpZiBjZmcubWF0Y2hfbm9uX25vOgogICAgICAgIHJhaXNlIF9SZWZ1c2VkKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsICJzc2hkLWNvbmZpZzphbWJpZ3VvdXMtbWF0Y2giLAogICAgICAgICAgICAgICAgICAgICAgIF9hZG1pbihBQ1RJT05fTUFUQ0guZm9ybWF0KGtleT1rZXkpKSkKICAgIGlmIG5vdCBfc3ludGF4X29rKHJvb3QsIHJ1bik6CiAgICAgICAgcmFpc2UgX290aGVyKCJzc2hkLWNvbmZpZzp2YWxpZGF0aW9uLWZhaWxlZCIpCiAgICB2YWx1ZXMgPSBlZmZlY3RpdmVfc2V0dGluZ3Mocm9vdCwgcnVuKQogICAgcmV0dXJuIGNmZywgX2VmZmVjdGl2ZV92YWx1ZSh2YWx1ZXMsIGxrZXkpLCB2YWx1ZXMKCgpkZWYgZXhlY3V0ZV9jb250cm9sKGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQsICosIGRyeV9ydW4sCiAgICAgICAgICAgICAgICAgICAgcHJpdmlsZWdlX2NoZWNrPU5vbmUsIF9yb290PU5vbmUsIF9ydW49Tm9uZSwgX3dyaXRlPU5vbmUsIF9zdGFnZT1Ob25lKToKICAgICIiIlNldCBgPGtleT4gbm9gIGluIC9ldGMvc3NoL3NzaGRfY29uZmlnIGluIHBsYWNlIChzY2hlbWUgMeKAkzQpIGFuZCByZWxvYWQgc3NoZC4KCiAgICBgX3Jvb3RgLCBgX3J1bmAsIGBfd3JpdGVgINC4IGBfc3RhZ2VgIOKAlCDRgtC+0LvRjNC60L4g0LTQu9GPINGC0LXRgdGC0L7Qsjog0LrQvtGA0LXQvdGMINGE0LDQudC70L7QstC+0Lkg0YHQuNGB0YLQtdC80YssCiAgICDQt9Cw0L/Rg9GB0Log0LrQvtC80LDQvdC0LCDQstC+0YHRgdGC0LDQvdC+0LLQu9C10L3QuNC1INGE0LDQudC70LAgKGBfd3JpdGUo0L/Rg9GC0YwsINCx0LDQudGC0YssIHN0YXQpYCkg0Lgg0L/QvtC00LPQvtGC0L7QstC60LAKICAgINCy0YDQtdC80LXQvdC90L7Qs9C+INGE0LDQudC70LAgKGBfc3RhZ2Uo0L/Rg9GC0YwsINCx0LDQudGC0YssIHN0YXQpYCAtPiDQv9GD0YLRjCDQstGA0LXQvNC10L3QvdC+0LPQviDRhNCw0LnQu9CwKS4KICAgICIiIgogICAgdmFsaWRhdGVfY29udHJvbF9pbnB1dChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgYXBwbHlfc3VwcG9ydGVkKQogICAgYWN0aW9ucyA9IFsiUDBfRUxJR0lCSUxJVFkiXQogICAgcnVuID0gX3J1biBpZiBfcnVuIGlzIG5vdCBOb25lIGVsc2UgX2RlZmF1bHRfcnVuCiAgICB3cml0ZSA9IF93cml0ZSBpZiBfd3JpdGUgaXMgbm90IE5vbmUgZWxzZSBfd3JpdGVfZmlsZQogICAgc3RhZ2UgPSBfc3RhZ2UgaWYgX3N0YWdlIGlzIG5vdCBOb25lIGVsc2UgX3N0YWdlX2ZpbGUKICAgIGN1cnJlbnQgPSBOb25lCgogICAgZGVmIGRvbmUob3V0Y29tZSwgKipleHRyYSk6CiAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwgb3V0Y29tZSwgYWN0aW9ucz1hY3Rpb25zLCBkcnlfcnVuPWRyeV9ydW4sIHBvbGljeV9jdXJyZW50PWN1cnJlbnQsICoqZXh0cmEpCgogICAgaWYgbm90IGFwcGx5X3N1cHBvcnRlZDoKICAgICAgICByZXR1cm4gZG9uZSgiTk9UX0VMSUdJQkxFX0FQUExZX1VOU1VQUE9SVEVEIiwgcmVhc29uPSJhcHBseS11bnN1cHBvcnRlZCIpCiAgICBpZiBDT05UUk9MX0tFWVMuZ2V0KGNvbnRyb2xfaWQpICE9IGtleSBvciBvcCAhPSBFWFBFQ1RFRF9PUCBvciBleHBlY3RlZCAhPSBFWFBFQ1RFRF9WQUxVRToKICAgICAgICByZXR1cm4gZG9uZSgiTk9UX0VMSUdJQkxFX0FQUExZX1VOU1VQUE9SVEVEIiwgcmVhc29uPSJvcC11bnN1cHBvcnRlZCIpCgogICAgdHJ5OgogICAgICAgIGFjdGlvbnMuYXBwZW5kKCJQMV9PQlNFUlZFIikKICAgICAgICBfY2hlY2tfdG9vbHMoX3Jvb3QsIFtTU0hELCBTWVNURU1DVExdKQogICAgICAgIGNmZywgZWZmZWN0aXZlLCB2YWx1ZXMgPSBfb2JzZXJ2ZShfcm9vdCwgcnVuLCBrZXkpCiAgICAgICAgY3VycmVudCA9IHBvbGljeV9jdXJyZW50KGNmZy5tYWluX2dsb2JhbF9ubywgZWZmZWN0aXZlKQogICAgICAgIGlmIGNmZy5tYWluX2dsb2JhbF9ubyA+IDAgYW5kIGVmZmVjdGl2ZSA9PSBFWFBFQ1RFRF9WQUxVRToKICAgICAgICAgICAgcmV0dXJuIGRvbmUoIkFMUkVBRFlfQ09NUExJQU5UIikKCiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlAyX1BMQU4iKQogICAgICAgIHVzZXJzID0gYWRtaW5fdXNlcnMoX3JlYWRfZ3JvdXBzKF9yb290KSkKICAgICAgICBpZiBrZXkgPT0gIlBlcm1pdFJvb3RMb2dpbiIgYW5kIG5vdCB1c2VyczoKICAgICAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwgInNzaDpuby1zdWRvLW1lbWJlcnMiLCBfYWRtaW4oQUNUSU9OX05PX1NVRE8pKQogICAgICAgIGlmIGtleSBpbiAoIlBlcm1pdFJvb3RMb2dpbiIsICJQYXNzd29yZEF1dGhlbnRpY2F0aW9uIik6CiAgICAgICAgICAgIGFjY2VzcywgdW52ZXJpZmllZCA9IGFkbWluX2FjY2Vzcyhfcm9vdCwgcnVuLCB1c2VycykKICAgICAgICAgICAgaWYga2V5ID09ICJQYXNzd29yZEF1dGhlbnRpY2F0aW9uIjoKICAgICAgICAgICAgICAgICMg0J/QvtGB0LvQtSDQt9Cw0L/QuNGB0Lgg0LLRhdC+0LQg0L/QviDQv9Cw0YDQvtC70Y4g0LfQsNC60YDRi9GCOiDQvdGD0LbQtdC9INCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGAINGBINC/0YDQuNCz0L7QtNC90YvQvCDQutC70Y7Rh9C+0LwuCiAgICAgICAgICAgICAgICBjYW5fbG9naW4gPSBbdXNlciBmb3IgdXNlciwga2V5ZWQsIF9wYXNzd29yZCBpbiBhY2Nlc3MgaWYga2V5ZWRdCiAgICAgICAgICAgICAgICBtaXNzaW5nID0gKCJzc2g6bm8ta2V5ZWQtYWRtaW4iLCBBQ1RJT05fTk9fS0VZKQogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgIyDQn9C+0YHQu9C1INC30LDQv9C40YHQuCByb290INC90LUg0LLRhdC+0LTQuNGCOiDQvdGD0LbQtdC9INCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGALCDQutC+0YLQvtGA0YvQuSDQstC+0LnQtNGR0YIg0YHQsNC8LgogICAgICAgICAgICAgICAgY2FuX2xvZ2luID0gW3VzZXIgZm9yIHVzZXIsIGtleWVkLCBwYXNzd29yZCBpbiBhY2Nlc3MgaWYga2V5ZWQgb3IgcGFzc3dvcmRdCiAgICAgICAgICAgICAgICBtaXNzaW5nID0gKCJzc2g6bm8tYWRtaW4tbG9naW4iLCBBQ1RJT05fTk9fQURNSU5fTE9HSU4pCiAgICAgICAgICAgIGlmIG5vdCBjYW5fbG9naW4gYW5kIHVudmVyaWZpZWQ6CiAgICAgICAgICAgICAgICByYWlzZSBfUmVmdXNlZCgiQUJPUlRFRF9QUkVDT05ESVRJT05fQ09ORkxJQ1QiLCAic3NoOmtleXMtc2V0dXAtbm9uZGVmYXVsdCIsIF9hZG1pbihBQ1RJT05fS0VZU19TRVRVUC5mb3JtYXQoa2V5PWtleSkpKQogICAgICAgICAgICBpZiBub3QgY2FuX2xvZ2luOgogICAgICAgICAgICAgICAgcmFpc2UgX1JlZnVzZWQoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwgbWlzc2luZ1swXSwgX2FkbWluKG1pc3NpbmdbMV0pKQogICAgICAgIHBsYW5uZWQgPSBjZmcucGxhbihrZXkpCiAgICAgICAgZm9yIHBhdGggaW4gcGxhbm5lZDoKICAgICAgICAgICAgaWYgbm90IF90cnVzdGVkKGNmZy5maWxlc1twYXRoXVsxXSwgX3Jvb3QpOgogICAgICAgICAgICAgICAgc2hvd24gPSBTU0hEX0NPTkZJRyBpZiBwYXRoID09IGNmZy5tYWluIGVsc2UgKAogICAgICAgICAgICAgICAgICAgIHBhdGggaWYgX3Jvb3QgaXMgTm9uZSBlbHNlICIvIiArIG9zLnBhdGgucmVscGF0aChwYXRoLCBfcm9vdCkpCiAgICAgICAgICAgICAgICByYWlzZSBfUmVmdXNlZCgiQUJPUlRFRF9QUkVDT05ESVRJT05fQ09ORkxJQ1QiLCAic3NoZC1jb25maWc6dW50cnVzdGVkIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIF9hZG1pbihBQ1RJT05fRklMRS5mb3JtYXQocGF0aD1zaG93biwga2V5PWtleSkpKQogICAgICAgIGlmIGRyeV9ydW46CiAgICAgICAgICAgIHJldHVybiBkb25lKCJEUllfUlVOX1dPVUxEX0FQUExZIikKCiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlAzX1BSSVZJTEVHRSIpCiAgICAgICAgY2hlY2sgPSBwcml2aWxlZ2VfY2hlY2sgaWYgcHJpdmlsZWdlX2NoZWNrIGlzIG5vdCBOb25lIGVsc2UgX2RlZmF1bHRfcHJpdmlsZWdlX2NoZWNrCiAgICAgICAgaWYgbm90IGNoZWNrKCk6CiAgICAgICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsIHJlYXNvbj0icHJpdmlsZWdlIikKICAgIGV4Y2VwdCBfUmVmdXNlZCBhcyBleGM6CiAgICAgICAgcmV0dXJuIGRvbmUoZXhjLm91dGNvbWUsIHJlYXNvbj1leGMucmVhc29uLCBvcGVyYXRvcl9kZWNpc2lvbj1leGMuZGVjaXNpb24pCgogICAgd3JpdHRlbiA9IFtdCiAgICBzdGFnZWQgPSB7fQogICAgcmVsb2FkX2F0dGVtcHRlZCA9IEZhbHNlCgogICAgZGVmIGNvbXBlbnNhdGUocmVhc29uKToKICAgICAgICBhY3Rpb25zLmFwcGVuZCgiQ09NUEVOU0FUSU9OIikKICAgICAgICBvayA9IF9kaXNjYXJkKHN0YWdlZC52YWx1ZXMoKSkKICAgICAgICAjINCe0YHRgtCw0LLRiNC40LnRgdGPINCy0YDQtdC80LXQvdC90YvQuSDRhNCw0LnQuyDQsiAvZXRjL3NzaCDigJQg0YLQvtC20LUg0LjQt9C80LXQvdC10L3QuNC1INGB0LjRgdGC0LXQvNGLLgogICAgICAgIGxlZnQgPSBub3Qgb2sKICAgICAgICBmb3IgcGF0aCBpbiByZXZlcnNlZCh3cml0dGVuKToKICAgICAgICAgICAgcmF3LCBzdCwgX2xpbmVzID0gY2ZnLmZpbGVzW3BhdGhdCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHdyaXRlKHBhdGgsIHJhdywgc3QpCiAgICAgICAgICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICAgICAgICAgIG9rID0gRmFsc2UKICAgICAgICAgICAgICAgIGlmIGlzaW5zdGFuY2UoZXhjLCBfU3RhZ2VGYWlsZWQpIGFuZCBub3QgX2Rpc2NhcmQoW2V4Yy50bXBdKToKICAgICAgICAgICAgICAgICAgICBsZWZ0ID0gVHJ1ZQogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgb2sgPSBfYnl0ZXNfZXF1YWwocGF0aCwgcmF3KSBhbmQgb2sKICAgICAgICBpZiByZWxvYWRfYXR0ZW1wdGVkOgogICAgICAgICAgICBvayA9IF9yZWxvYWQoX3Jvb3QsIHJ1bikgYW5kIG9rCiAgICAgICAgbXV0YXRlZCA9IGJvb2wod3JpdHRlbikgb3IgbGVmdAogICAgICAgIGlmIG9rOgogICAgICAgICAgICByZXR1cm4gZG9uZSgiRkFJTEVEX05PVF9DT01NSVRURUQiLCByZWFzb249cmVhc29uLCBtdXRhdGlvbj1tdXRhdGVkKQogICAgICAgIHJldHVybiBkb25lKCJGQUlMRURfQ09NUEVOU0FUSU9OIiwgcmVhc29uPXJlYXNvbiwgbXV0YXRpb249bXV0YXRlZCkKCiAgICAjINCa0LDQttC00YvQuSDQv9C+0LTQs9C+0YLQvtCy0LvQtdC90L3Ri9C5INGE0LDQudC7INC/0YDQvtCy0LXRgNGP0LXRgtGB0Y8gYHNzaGQgLXRgINC00L4g0LfQsNC80LXQvdGLINGA0LDQsdC+0YfQtdCz0L4g0YTQsNC50LvQsDoKICAgICMg0L7RgdC90L7QstC90L7QuSDigJQg0LLQvNC10YHRgtC1INGBINGC0LXQutGD0YnQuNC80Lgg0LLQutC70Y7Rh9Cw0LXQvNGL0LzQuCwg0LLQutC70Y7Rh9Cw0LXQvNGL0Lkg4oCUINGB0LDQvCDQv9C+INGB0LXQsdC1LgogICAgYWN0aW9ucy5hcHBlbmQoIlBIQVNFMV9TVEFHRSIpCiAgICBmb3IgcGF0aCwgcmF3IGluIHBsYW5uZWQuaXRlbXMoKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIHN0YWdlZFtwYXRoXSA9IHN0YWdlKHBhdGgsIHJhdywgY2ZnLmZpbGVzW3BhdGhdWzFdKQogICAgICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICAgICAgaWYgaXNpbnN0YW5jZShleGMsIF9TdGFnZUZhaWxlZCk6CiAgICAgICAgICAgICAgICBzdGFnZWRbcGF0aF0gPSBleGMudG1wICAjINGD0YfQuNGC0YvQstCw0LXRgtGB0Y8g0LrQvtC80L/QtdC90YHQsNGG0LjQtdC5OiDQv9C+0LLRgtC+0YDQvdC+0LUg0YPQtNCw0LvQtdC90LjQtQogICAgICAgICAgICByZXR1cm4gY29tcGVuc2F0ZSgic3NoZC1jb25maWc6d3JpdGUtZmFpbGVkIikKICAgICAgICBpZiBub3QgX3N5bnRheF9vayhfcm9vdCwgcnVuLCBzdGFnZWRbcGF0aF0pOgogICAgICAgICAgICByZXR1cm4gY29tcGVuc2F0ZSgic3NoZC1jb25maWc6dmFsaWRhdGlvbi1mYWlsZWQiKQogICAgYWN0aW9ucy5hcHBlbmQoIlBIQVNFMV9DT05GSUciKQogICAgZm9yIHBhdGggaW4gcGxhbm5lZDoKICAgICAgICB0cnk6CiAgICAgICAgICAgIG9zLnJlcGxhY2Uoc3RhZ2VkW3BhdGhdLCBwYXRoKQogICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICByZXR1cm4gY29tcGVuc2F0ZSgic3NoZC1jb25maWc6d3JpdGUtZmFpbGVkIikKICAgICAgICBkZWwgc3RhZ2VkW3BhdGhdCiAgICAgICAgd3JpdHRlbi5hcHBlbmQocGF0aCkKICAgIGlmIG5vdCBfc3ludGF4X29rKF9yb290LCBydW4pOgogICAgICAgIHJldHVybiBjb21wZW5zYXRlKCJzc2hkLWNvbmZpZzp2YWxpZGF0aW9uLWZhaWxlZCIpCiAgICBhY3Rpb25zLmFwcGVuZCgiUEhBU0UyX1JFTE9BRCIpCiAgICByZWxvYWRfYXR0ZW1wdGVkID0gVHJ1ZQogICAgaWYgbm90IF9yZWxvYWQoX3Jvb3QsIHJ1bik6CiAgICAgICAgcmV0dXJuIGNvbXBlbnNhdGUoInJlbG9hZDpmYWlsZWQiKQogICAgYWN0aW9ucy5hcHBlbmQoIkZJTkFMX1BPU1RDSEVDSyIpCiAgICB0cnk6CiAgICAgICAgYWZ0ZXIsIGFmdGVyX2VmZmVjdGl2ZSwgX3ZhbHVlcyA9IF9vYnNlcnZlKF9yb290LCBydW4sIGtleSkKICAgIGV4Y2VwdCAoX1JlZnVzZWQsIE9TRXJyb3IpOgogICAgICAgIHJldHVybiBjb21wZW5zYXRlKCJwb3N0Y2hlY2s6cmVhZC1mYWlsZWQiKQogICAgY3VycmVudCA9IHBvbGljeV9jdXJyZW50KGFmdGVyLm1haW5fZ2xvYmFsX25vLCBhZnRlcl9lZmZlY3RpdmUpCiAgICBpZiAoYW55KGFmdGVyLmZpbGVzLmdldChwYXRoLCAoTm9uZSwpKVswXSAhPSByYXcgZm9yIHBhdGgsIHJhdyBpbiBwbGFubmVkLml0ZW1zKCkpCiAgICAgICAgICAgIG9yIGFmdGVyLm1haW5fZ2xvYmFsX25vIDwgMSBvciBhZnRlcl9lZmZlY3RpdmUgIT0gRVhQRUNURURfVkFMVUUpOgogICAgICAgIHJldHVybiBjb21wZW5zYXRlKCJwb3N0Y2hlY2s6bm90LWNvbXBsaWFudCIpCiAgICByZXR1cm4gZG9uZSgiQVBQTElFRCIsIG11dGF0aW9uPVRydWUpCgoKZGVmIGNvbnRyb2xfcmVzdWx0X3RvX3JlcG9ydChyZXN1bHQsIHN0YXJ0ZWRfYXQsIGZpbmlzaGVkX2F0KToKICAgIHJldHVybiB7CiAgICAgICAgImFkYXB0ZXJfaWQiOiByZXN1bHRbImFkYXB0ZXJfaWQiXSwKICAgICAgICAibWVjaGFuaXNtX2lkIjogcmVzdWx0WyJtZWNoYW5pc21faWQiXSwKICAgICAgICAiY29udHJvbF9pZCI6IHJlc3VsdFsiY29udHJvbF9pZCJdLAogICAgICAgICJ0YXJnZXQiOiByZXN1bHRbInRhcmdldCJdLAogICAgICAgICJvdXRjb21lIjogcmVzdWx0WyJvdXRjb21lIl0sCiAgICAgICAgInJlYXNvbiI6IHJlc3VsdFsicmVhc29uIl0sCiAgICAgICAgInBvbGljeV9jdXJyZW50IjogcmVzdWx0WyJwb2xpY3lfY3VycmVudCJdLAogICAgICAgICJvcGVyYXRvcl9kZWNpc2lvbiI6IE5vbmUgaWYgcmVzdWx0WyJvcGVyYXRvcl9kZWNpc2lvbiJdIGlzIE5vbmUgZWxzZSBkaWN0KHJlc3VsdFsib3BlcmF0b3JfZGVjaXNpb24iXSksCiAgICAgICAgInN0YXJ0ZWRfYXQiOiBzdGFydGVkX2F0LAogICAgICAgICJmaW5pc2hlZF9hdCI6IGZpbmlzaGVkX2F0LAogICAgICAgICJhY3Rpb25zX2F0dGVtcHRlZCI6IGxpc3QocmVzdWx0WyJhY3Rpb25zX2F0dGVtcHRlZCJdKSwKICAgICAgICAic3RlcF9yYyI6IG91dGNvbWVfcmNfY29udHJpYnV0aW9uKHJlc3VsdFsib3V0Y29tZSJdLCByZXN1bHRbImRyeV9ydW4iXSksCiAgICAgICAgIm11dGF0aW9uX3BlcmZvcm1lZCI6IHJlc3VsdFsibXV0YXRpb25fcGVyZm9ybWVkIl0sCiAgICAgICAgInRyYW5zYWN0aW9uX2NvbW1pdCI6IHJlc3VsdFsidHJhbnNhY3Rpb25fY29tbWl0Il0sCiAgICB9Cg=="},"standard-system-paths-mode":{"adapter_id":"product-standard-system-paths-mode-apply-v1","apply_kind":"standard-system-paths-mode-v1","implementation_sha256":"9d60edefaaadbdf4adddfd61c978110299c5a34e212eb7abbbe9134ee531baf2","mechanism_id":"standard-system-paths-mode-v1","source_b64":"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiJwcm9kdWN0LXN0YW5kYXJkLXN5c3RlbS1wYXRocy1tb2RlLWFwcGx5LXYxLgoKQVBQTFkgYWRhcHRlciBmb3IgbWVjaGFuaXNtIGBzdGFuZGFyZC1zeXN0ZW0tcGF0aHMtbW9kZS12MWAgKDIuMy44IHN0YW5kYXJkIHBhdGhzKS4KClBVUlBPU0U9REVGRU5TSVZFX0NPTVBMSUFOQ0VfVkFMSURBVElPTgpBdXRob3JpdHk6IHByb2R1Y3QvY29udHJhY3RzL21lY2hhbmlzbS1zdGFuZGFyZC1zeXN0ZW0tcGF0aHMtbW9kZS12MS5qc29uCgpQb3B1bGF0aW9uIGlzIHRoZSBvbmUgb2YgQ0hFQ0sgYWRhcHRlciBwcm9kdWN0LXN0YW5kYXJkLXN5c3RlbS1wYXRocy1tb2RlLWNoZWNrLXYyOgrQuNGB0L/QvtC70L3Rj9C10LzRi9C1INGE0LDQudC70YsgZXhlYy3QutC+0YDQvdC10LksINCx0LjQsdC70LjQvtGC0LXQutC4IGxpYi3QutC+0YDQvdC10LkgKGAuc29gLCBgLnNvLipgLCBgLmFgKSDQuArQvNC+0LTRg9C70LggYC9saWIvbW9kdWxlcy88dW5hbWUtcj5gIChgLmtvYCwgYC5rby4qYCksINGA0LXQutGD0YDRgdC40LLQvdC+LCDRgSDRgNCw0LfRgNC10YjQtdC90LjQtdC8CtGB0LjQvNC70LjQvdC60L7QsiDQsiDQutC+0L3QtdGH0L3Rg9GOINGG0LXQu9GMINC4INC00LXQtNGD0L/Qu9C40LrQsNGG0LjQtdC5INGG0LXQu9C10Lkg0L/QviBgZGV2Omlub2AuINCf0LXRgNC10YfQuNGB0LvQuNGC0LXQu9GMCtC90LjQttC1IOKAlCBQeXRob24t0LrQvtC/0LjRjyDRgtC+0LPQviDQvdCw0LHQu9GO0LTQsNGC0LXQu9GPOyDQv9Cw0YDQuNGC0LXRgiDQv9GA0L7QstC10YDRj9C10YLRgdGPCnRlc3RzL3Byb2R1Y3QtdjEvdGVzdF9zdGFuZGFyZF9zeXN0ZW1fcGF0aHNfbW9kZV9hcHBseV9hZGFwdGVyLnB5LgoK0JrQsNC90L7QvdC40YfQtdGB0LrQuNC1INC60L7RgNC90Lgg0L3QtSDQu9C40YLQtdGA0LDQu9GLOiDQvtC90Lgg0YDQsNC30LHQuNGA0LDRjtGC0YHRjyDQuNC3INC70L7QutCw0YLQvtGA0LAg0LrQvtC90YLRgNC+0LvRjwooYFRBUkdFVFNgKSwg0Lgg0YHQvtCy0L/QsNC00LXQvdC40LUg0YDQsNC30LHQvtGA0LAg0YEg0LrQvtC90YHRgtCw0L3RgtCw0LzQuCBDSEVDSy3QsNC00LDQv9GC0LXRgNCwCmBDQU5PTklDQUxfRVhFQ19ST09UU2AgLyBgQ0FOT05JQ0FMX0xJQl9ST09UU2AgLyBgQ0FOT05JQ0FMX01PRFVMRV9URU1QTEFURWAK0LfQsNC60YDQtdC/0LvQtdC90L4g0YLQtdC8INC20LUg0YLQtdGB0YLQvtC8LgoK0JPRgNCw0L3QuNGG0LAg0LzRg9GC0LDRhtC40Lg6INC80LXQvdGP0Y7RgtGB0Y8g0YLQvtC70YzQutC+INC+0LHRitC10LrRgtGLLCDRh9C10Lkg0YDQsNC30YDQtdGI0ZHQvdC90YvQuSDQv9GD0YLRjCDQu9C10LbQuNGCINCy0L3Rg9GC0YDQuArQutCw0L3QvtC90LjRh9C10YHQutC40YUg0LrQvtGA0L3QtdC5LiDQlNC+0L/QvtC70L3QuNGC0LXQu9GM0L3Ri9C1INGN0LvQtdC80LXQvdGC0YsgUEFUSCByb290INC4INGG0LXQu9C4INGB0LjQvNC70LjQvdC60L7QsiDQstC90LUK0LrQsNC90L7QvdC40YfQtdGB0LrQuNGFINC60L7RgNC90LXQuSDQstGF0L7QtNGP0YIg0LIg0L/QvtC/0YPQu9GP0YbQuNGOICjQuNC90LDRh9C1IENIRUNLINC4IEFQUExZINGA0LDQt9C+0YjQu9C40YHRjCDQsdGLKSwg0L3QvgrQvdC1INC80YPRgtC40YDRg9GO0YLRgdGPOiDQv9GA0L7Qv9GD0YHQuiDRgSDQv9GA0LjRh9C40L3QvtC5IGBvdXRzaWRlLWNhbm9uaWNhbC1yb290c2AuCgpUaGUgcGxhbiBpcyBidWlsdCBiZWZvcmUgYW55IG11dGF0aW9uLiBBIHZpb2xhdG9yIHdpdGggc3RfbmxpbmsgPiAxIGlzIHNraXBwZWQKYW5kIHJlY29yZGVkLiDQn9C10YDQtdC0INC80YPRgtCw0YbQuNC10Lkg0L7QsdGK0LXQutGCINGA0LXQstCw0LvQuNC00LjRgNGD0LXRgtGB0Y8g0L3QsCDRg9C20LUg0L7RgtC60YDRi9GC0L7QvCDQtNC10YHQutGA0LjQv9GC0L7RgNC1CtGB0YLRgNC+0LPQviDQsiDQv9C+0YDRj9C00LrQtSBgU19JU1JFR2Ag4oaSIGBkZXYvaW5vYCDQuNC3INC/0LvQsNC90LAg4oaSINC90LDQu9C40YfQuNC1INCx0LjRgtC+0LIg0LzQsNGB0LrQuDsK0L3QtdGB0L7QstC/0LDQtNC10L3QuNC1INC70Y7QsdC+0LPQviDRiNCw0LPQsCDigJQg0L/RgNC+0L/Rg9GB0Log0L7QsdGK0LXQutGC0LAg0YEg0L/RgNC40YfQuNC90L7QuS4gRWFjaCBtdXRhdGlvbiBpcyBvbmUKYGZjaG1vZGAgb24gYSBkZXNjcmlwdG9yIG9wZW5lZCB3aXRoIE9fTk9GT0xMT1cgYW5kIG9ubHkgY2xlYXJzIGJpdHM7IHRoZXJlIGlzCm5vIGNvbXBlbnNhdGlvbi4gQW4gZXJyb3Igb24gb25lIG9iamVjdCBkb2VzIG5vdCBzdG9wIHRoZSBvdGhlcnMKKEFQUExJRURfUEFSVElBTCk7IEVST0ZTIHN0b3BzIGltbWVkaWF0ZWx5LgoiIiIKCmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnMKCmltcG9ydCBlcnJubwppbXBvcnQgb3MKaW1wb3J0IHJlCmltcG9ydCBzdGF0CgpBREFQVEVSX0lEID0gInByb2R1Y3Qtc3RhbmRhcmQtc3lzdGVtLXBhdGhzLW1vZGUtYXBwbHktdjEiCk1FQ0hBTklTTV9JRCA9ICJzdGFuZGFyZC1zeXN0ZW0tcGF0aHMtbW9kZS12MSIKVEFSR0VUX0lEID0gImxpbnV4LXg4Nl82NC1zdXBwb3J0ZWQtdjEiClBBUkFNRVRFUl9LSU5EID0gInN0YW5kYXJkLXN5c3RlbS1wYXRocy1tb2RlIgpTRU1BTlRJQ19DT05UUkFDVF9JRCA9ICJzdGFuZGFyZC1zeXN0ZW0tcGF0aHMtbW9kZS1hcHBseS1zZW1hbnRpYy12MSIKClNVUFBPUlRFRF9LRVlTID0gKCJtb2RlIiwpClNVUFBPUlRFRF9PUFMgPSAoImJpdHMtY2xlYXIiLCkKRVhQRUNURURfTUFTSyA9ICIwMDIyIgoKIyDQnNCw0YDQutC10YDRiyDQu9C+0LrQsNGC0L7RgNCwIENIRUNLLdCw0LTQsNC/0YLQtdGA0LAuClBBVEhfUk9PVF9NQVJLRVIgPSAiPHJvb3QtUEFUSD4iClVOQU1FX01BUktFUiA9ICI8dW5hbWUtcj4iCgojINCY0LzQtdC90LAg0L7QsdGK0LXQutGC0L7QsiDQv9C+0L/Rg9C70Y/RhtC40Lgg0L/QviDRgNC+0LvRj9C8ICjQutC+0L/QuNGPIENIRUNLLdC90LDQsdC70Y7QtNCw0YLQtdC70Y8pLgpMSUJfU1VGRklYRVMgPSAoYiIuc28iLCBiIi5hIikKTElCX0lORklYID0gYiIuc28uIgpNT0RVTEVfU1VGRklYID0gYiIua28iCk1PRFVMRV9JTkZJWCA9IGIiLmtvLiIKRVhFQ19CSVRTID0gMG8xMTEKCk9VVENPTUVTID0gKAogICAgIkFQUExJRUQiLAogICAgIkFQUExJRURfUEFSVElBTCIsCiAgICAiQUxSRUFEWV9DT01QTElBTlQiLAogICAgIkRSWV9SVU5fV09VTERfQVBQTFkiLAogICAgIk5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRCIsCiAgICAiQUJPUlRFRF9QUkVDT05ESVRJT05fQ09ORkxJQ1QiLAogICAgIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwKICAgICJGQUlMRURfTk9UX0NPTU1JVFRFRCIsCikKCkNPTU1JVF9DT01NSVRURUQgPSAiQ09NTUlUVEVEIgpDT01NSVRfTk9UX0NPTU1JVFRFRCA9ICJOT1RfQ09NTUlUVEVEIgpDT01NSVRfTk9UX1NUQVJURUQgPSAiTk9UX1NUQVJURUQiCgojINCb0L7QutCw0YLQvtGAINC10LTQuNC90YHRgtCy0LXQvdC90L7Qs9C+INC60L7QvdGC0YDQvtC70Y8g0LzQtdGF0LDQvdC40LfQvNCwLiDQodC+0LLQv9Cw0LTQtdC90LjQtSDRgSBwYXJhbWV0ZXIubG9jYXRvciDQuCDRgQojINC60L7QvdGB0YLQsNC90YLQsNC80LggQ0hFQ0st0LDQtNCw0L/RgtC10YDQsCDQv9GA0L7QstC10YDRj9C10YIKIyB0ZXN0X3N0YW5kYXJkX3N5c3RlbV9wYXRoc19tb2RlX2FwcGx5X2FkYXB0ZXIucHkuClRBUkdFVFMgPSB7CiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjMuOC1TVEFOREFSRC1TWVNURU0tUEFUSFMtTU9ERSI6CiAgICAgICAgIi9iaW58L3NiaW58L3Vzci9iaW58L3Vzci9zYmlufDxyb290LVBBVEg+fC9saWJ8L2xpYjY0fC91c3IvbGlifC91c3IvbGliNjQiCiAgICAgICAgInwvdXNyL2xvY2FsL2xpYnwvdXNyL2xvY2FsL2xpYjY0fC9saWIvbW9kdWxlcy88dW5hbWUtcj4iLAp9CgpDT05UUk9MX0lEX1BBVFRFUk4gPSByIl4oPyEuKltcclxuXSlbQS1aYS16MC05Ll8tXSskIgoKIyDQn9GA0LjRh9C40L3RiyBDSEVDSywg0LrQvtGC0L7RgNGL0LUg0L7Qt9C90LDRh9Cw0Y7RgiDQvtCx0YrQtdC60YIg0L3QtSDRgtC+0LPQviDRgtC40L/QsCDQsiDQv9C+0L/Rg9C70Y/RhtC40LguCkNPTkZMSUNUX1JFQVNPTlMgPSAoCiAgICAicm9vdDppbnZhbGlkLXR5cGUiLAogICAgInRhcmdldDppbnZhbGlkLXR5cGUiLAogICAgInRhcmdldDpyZXNvbHZlZC1zeW1saW5rIiwKKQoKCmRlZiB2YWxpZGF0ZV9jb250cm9sX2lucHV0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQpOgogICAgIiIiRmFpbC1jbG9zZWQgdmFsaWRhdGlvbiBvZiBvbmUgY29udHJvbCByb3cuIFJhaXNlcyBWYWx1ZUVycm9yLiIiIgogICAgaWYgbm90IGlzaW5zdGFuY2UoY29udHJvbF9pZCwgc3RyKSBvciBub3QgcmUuZnVsbG1hdGNoKENPTlRST0xfSURfUEFUVEVSTiwgY29udHJvbF9pZCk6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigiaW52YWxpZCBjb250cm9sIGlkIikKICAgIGlmIG5vdCBpc2luc3RhbmNlKGtleSwgc3RyKSBvciBub3QgaXNpbnN0YW5jZShvcCwgc3RyKSBvciBub3QgaXNpbnN0YW5jZShleHBlY3RlZCwgc3RyKToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJrZXksIG9wIGFuZCBleHBlY3RlZCBtdXN0IGJlIHN0cmluZ3MiKQogICAgaWYgbm90IGlzaW5zdGFuY2UoYXBwbHlfc3VwcG9ydGVkLCBib29sKToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJhcHBseV9zdXBwb3J0ZWQgbXVzdCBiZSBib29sIikKICAgIHJldHVybiBUcnVlCgoKZGVmIF9pc19lbGlnaWJsZV9jb250cmFjdChrZXksIG9wLCBleHBlY3RlZCk6CiAgICAiIiLQotC+0LvRjNC60L4gKG1vZGUsIGJpdHMtY2xlYXIsIDAwMjIpOyDQstGB0ZEg0L/RgNC+0YfQtdC1INGA0LXRiNCw0LXRgiDQsNC00LzQuNC90LjRgdGC0YDQsNGC0L7RgC4iIiIKICAgIHJldHVybiBrZXkgaW4gU1VQUE9SVEVEX0tFWVMgYW5kIG9wIGluIFNVUFBPUlRFRF9PUFMgYW5kIGV4cGVjdGVkID09IEVYUEVDVEVEX01BU0sKCgpkZWYgY2Fub25pY2FsX3Jvb3RzKGxvY2F0b3IpOgogICAgIiIi0KDQsNC30LHQvtGAINC70L7QutCw0YLQvtGA0LA6IChleGVjX3Jvb3RzLCBsaWJfcm9vdHMsIG1vZHVsZV90ZW1wbGF0ZSkg0LHQtdC3INC/0L7QtNGB0YLQsNC90L7QstC+0LouIiIiCiAgICBwYXJ0cyA9IGxvY2F0b3Iuc3BsaXQoInwiKQogICAgaWYgUEFUSF9ST09UX01BUktFUiBub3QgaW4gcGFydHMgb3IgbGVuKHBhcnRzKSA8IDM6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigibG9jYXRvciB3aXRob3V0ICVzIHNlcGFyYXRvciIgJSBQQVRIX1JPT1RfTUFSS0VSKQogICAgY3V0ID0gcGFydHMuaW5kZXgoUEFUSF9ST09UX01BUktFUikKICAgIGV4ZWNfcm9vdHMgPSB0dXBsZShwYXJ0c1s6Y3V0XSkKICAgIGxpYl9yb290cyA9IHR1cGxlKHBhcnRzW2N1dCArIDE6LTFdKQogICAgbW9kdWxlX3RlbXBsYXRlID0gcGFydHNbLTFdCiAgICBpZiBub3QgZXhlY19yb290cyBvciBub3QgbGliX3Jvb3RzIG9yIG5vdCBtb2R1bGVfdGVtcGxhdGU6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigibG9jYXRvciB3aXRob3V0IGEgY29tcGxldGUgcm9sZSBzZXQiKQogICAgcmV0dXJuIGV4ZWNfcm9vdHMsIGxpYl9yb290cywgbW9kdWxlX3RlbXBsYXRlCgoKZGVmIF9wYXRoX2VudHJpZXMoKToKICAgICIiItCt0LvQtdC80LXQvdGC0YsgUEFUSCDQv9GA0L7RhtC10YHRgdCwOyDQutC+0L/QuNGPINC/0YDQsNCy0LjQuyBDSEVDSy3QsNC00LDQv9GC0LXRgNCwLiIiIgogICAgdmFsdWUgPSBvcy5lbnZpcm9uLmdldCgiUEFUSCIpCiAgICBpZiBub3QgdmFsdWUgb3IgYW55KGNoIGluIHZhbHVlIGZvciBjaCBpbiAoIlxyIiwgIlxuIiwgIlx0IikpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoInBhdGg6aW52YWxpZC1lbnZpcm9ubWVudCIpCiAgICBlbnRyaWVzID0gdmFsdWUuc3BsaXQoIjoiKQogICAgaWYgbm90IGVudHJpZXM6CiAgICAgICAgcmFpc2UgVmFsdWVFcnJvcigicGF0aDplbXB0eS1lbnZpcm9ubWVudCIpCiAgICBmb3IgZW50cnkgaW4gZW50cmllczoKICAgICAgICBpZiBub3QgZW50cnkuc3RhcnRzd2l0aCgiLyIpOgogICAgICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJwYXRoOm5vbmFic29sdXRlLWVudHJ5IikKICAgIHJldHVybiBlbnRyaWVzCgoKZGVmIHJlc29sdmVfcm9vdHMobG9jYXRvcik6CiAgICAiIiIoZXhlY19yb290cywgbGliX3Jvb3RzLCBtb2R1bGVfcm9vdCkg0YEgUEFUSCByb290INC4INC/0L7QtNGB0YLQsNC90L7QstC60L7QuSA8dW5hbWUtcj4uIiIiCiAgICBleGVjX3Jvb3RzLCBsaWJfcm9vdHMsIG1vZHVsZV90ZW1wbGF0ZSA9IGNhbm9uaWNhbF9yb290cyhsb2NhdG9yKQogICAgZXhlY19yb290cyA9IGxpc3QoZXhlY19yb290cykgKyBfcGF0aF9lbnRyaWVzKCkKICAgIG1vZHVsZV9yb290ID0gbW9kdWxlX3RlbXBsYXRlLnJlcGxhY2UoVU5BTUVfTUFSS0VSLCBvcy51bmFtZSgpLnJlbGVhc2UpCiAgICByZXR1cm4gZXhlY19yb290cywgbGlzdChsaWJfcm9vdHMpLCBtb2R1bGVfcm9vdAoKCmRlZiBfcmVzb2x2ZShwYXRoLCByb2xlKToKICAgICIiItCQ0L3QsNC70L7QsyBgcmVhZGxpbmsgLWZgOiDQutC+0L3QtdGH0L3QsNGPINGG0LXQu9GMINGG0LXQv9C+0YfQutC4INGB0LjQvNC70LjQvdC60L7Qsi4iIiIKICAgIHBhcmVudCA9IG9zLnBhdGguZGlybmFtZShwYXRoKSBvciAiLyIKICAgIGlmIG5vdCBvcy5wYXRoLmlzZGlyKHBhcmVudCk6CiAgICAgICAgcmFpc2UgX09ic2VydmF0aW9uRXJyb3Iocm9sZSArICI6cmVzb2x2ZS1mYWlsZWQiKQogICAgcmVzdWx0ID0gb3MucGF0aC5yZWFscGF0aChwYXRoKQogICAgaWYgbm90IHJlc3VsdDoKICAgICAgICByYWlzZSBfT2JzZXJ2YXRpb25FcnJvcihyb2xlICsgIjpyZXNvbHZlLWVtcHR5IikKICAgIHJldHVybiByZXN1bHQKCgpjbGFzcyBfT2JzZXJ2YXRpb25FcnJvcihFeGNlcHRpb24pOgogICAgcGFzcwoKCmRlZiBfZW50cmllcyhyb290KToKICAgICIiImZpbmQgLVAgPHJvb3Q+IC1taW5kZXB0aCAxIC1wcmludDAgfCBzb3J0OiDQstGB0LUg0L7QsdGK0LXQutGC0Ysg0L3QuNC20LUg0LrQvtGA0L3Rjy4iIiIKICAgIGZvdW5kID0gW10KCiAgICBkZWYgZmFpbChfZXJyb3IpOgogICAgICAgIHJhaXNlIF9PYnNlcnZhdGlvbkVycm9yKCJzY2FuOmZpbmQtZmFpbGVkIikKCiAgICBmb3IgZGlycGF0aCwgZGlybmFtZXMsIGZpbGVuYW1lcyBpbiBvcy53YWxrKHJvb3QsIGZvbGxvd2xpbmtzPUZhbHNlLCBvbmVycm9yPWZhaWwpOgogICAgICAgIGZvciBuYW1lIGluIGRpcm5hbWVzICsgZmlsZW5hbWVzOgogICAgICAgICAgICBmb3VuZC5hcHBlbmQob3MucGF0aC5qb2luKGRpcnBhdGgsIG5hbWUpKQogICAgZm91bmQuc29ydChrZXk9b3MuZnNlbmNvZGUpCiAgICByZXR1cm4gZm91bmQKCgpkZWYgX3NlbGVjdGVkKGVudHJ5LCByb2xlKToKICAgICIiItCk0LjQu9GM0YLRgCDQuNC80LXQvdC4INC/0L4g0YDQvtC70LggKNC60L7Qv9C40Y8gQ0hFQ0st0L3QsNCx0LvRjtC00LDRgtC10LvRjykuIiIiCiAgICBuYW1lID0gb3MucGF0aC5iYXNlbmFtZShvcy5mc2VuY29kZShlbnRyeSkpCiAgICBpZiByb2xlID09ICJsaWIiOgogICAgICAgIHJldHVybiBuYW1lLmVuZHN3aXRoKExJQl9TVUZGSVhFUykgb3IgTElCX0lORklYIGluIG5hbWUKICAgIGlmIHJvbGUgPT0gIm1vZHVsZSI6CiAgICAgICAgcmV0dXJuIG5hbWUuZW5kc3dpdGgoTU9EVUxFX1NVRkZJWCkgb3IgTU9EVUxFX0lORklYIGluIG5hbWUKICAgIHJldHVybiBUcnVlCgoKZGVmIF9wb3B1bGF0aW9uKGV4ZWNfcm9vdHMsIGxpYl9yb290cywgbW9kdWxlX3Jvb3QpOgogICAgIiIi0JrQvtC/0LjRjyBDSEVDSy3QvdCw0LHQu9GO0LTQsNGC0LXQu9GPOiAobW91bnRzLdC/0L7QtNC+0LHQvdGL0LUg0YHRh9GR0YLRh9C40LrQuCwg0L7QsdGK0LXQutGC0Ysg0L/QvtC/0YPQu9GP0YbQuNC4KS4KCiAgICDQktC+0LfQstGA0LDRidCw0LXRgiAoIkVSUk9SIiwgcmVhc29uKSDQu9C40LHQviAoIlZBTFVFIiwgKGNvdW50ZXJzLCBbKHBhdGgsIGxzdGF0LCByb2xlKV0pKS4KICAgICIiIgogICAgZ3JvdXBzID0gKCgiZXhlYyIsIGxpc3QoZXhlY19yb290cykpLCAoImxpYiIsIGxpc3QobGliX3Jvb3RzKSksICgibW9kdWxlIiwgW21vZHVsZV9yb290XSkpCiAgICBzZWVuX3Jvb3RzLCBzZWVuX3RhcmdldHMgPSBzZXQoKSwgc2V0KCkKICAgIGV4ZWNfcm9vdF9pZHMgPSBzZXQoKQogICAgZm9yIHJvb3QgaW4gZXhlY19yb290czoKICAgICAgICB0cnk6CiAgICAgICAgICAgIGluZm8gPSBvcy5zdGF0KHJvb3QpCiAgICAgICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWYgc3RhdC5TX0lTRElSKGluZm8uc3RfbW9kZSk6CiAgICAgICAgICAgIGV4ZWNfcm9vdF9pZHMuYWRkKChpbmZvLnN0X2RldiwgaW5mby5zdF9pbm8pKQogICAgcHJlc2VudCA9IGFic2VudCA9IGFsaWFzZXMgPSAwCiAgICBjb3VudHMgPSB7ImV4ZWMiOiAwLCAibGliIjogMCwgIm1vZHVsZSI6IDB9CiAgICBpdGVtcyA9IFtdCiAgICBmb3Igcm9sZSwgcm9vdHMgaW4gZ3JvdXBzOgogICAgICAgIGZvciByb290IGluIHJvb3RzOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBvcy5sc3RhdChyb290KQogICAgICAgICAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgICAgICAgICBhYnNlbnQgKz0gMQogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgInJvb3Q6cmVzb2x2ZS1mYWlsZWQiCiAgICAgICAgICAgIHJlc29sdmVkID0gX3Jlc29sdmUocm9vdCwgInJvb3QiKQogICAgICAgICAgICBpZiBub3Qgb3MucGF0aC5pc2RpcihyZXNvbHZlZCk6CiAgICAgICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgInJvb3Q6aW52YWxpZC10eXBlIgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBpbmZvID0gb3Muc3RhdChyZXNvbHZlZCkKICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgInJvb3Q6aWRlbnRpdHktZmFpbGVkIgogICAgICAgICAgICBwcmVzZW50ICs9IDEKICAgICAgICAgICAgaWRlbnRpdHkgPSAoaW5mby5zdF9kZXYsIGluZm8uc3RfaW5vKQogICAgICAgICAgICBpZiBpZGVudGl0eSBpbiBzZWVuX3Jvb3RzOgogICAgICAgICAgICAgICAgYWxpYXNlcyArPSAxCiAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICBzZWVuX3Jvb3RzLmFkZChpZGVudGl0eSkKICAgICAgICAgICAgZm9yIGVudHJ5IGluIF9lbnRyaWVzKHJlc29sdmVkKToKICAgICAgICAgICAgICAgIGlmIG9zLnBhdGguaXNkaXIoZW50cnkpIGFuZCBub3Qgb3MucGF0aC5pc2xpbmsoZW50cnkpOgogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICBpZiBub3QgX3NlbGVjdGVkKGVudHJ5LCByb2xlKToKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgaWYgb3MucGF0aC5pc2xpbmsoZW50cnkpOgogICAgICAgICAgICAgICAgICAgIHRhcmdldCA9IF9yZXNvbHZlKGVudHJ5LCAidGFyZ2V0IikKICAgICAgICAgICAgICAgICAgICBpZiBvcy5wYXRoLmlzbGluayh0YXJnZXQpOgogICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgInRhcmdldDpyZXNvbHZlZC1zeW1saW5rIgogICAgICAgICAgICAgICAgICAgIGlmIG5vdCBvcy5wYXRoLmlzZmlsZSh0YXJnZXQpOgogICAgICAgICAgICAgICAgICAgICAgICBpZiByb2xlID09ICJleGVjIiBhbmQgb3MucGF0aC5pc2Rpcih0YXJnZXQpOgogICAgICAgICAgICAgICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRpbmZvID0gb3Muc3RhdCh0YXJnZXQpCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgInRhcmdldDppZGVudGl0eS1mYWlsZWQiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoZGluZm8uc3RfZGV2LCBkaW5mby5zdF9pbm8pIGluIGV4ZWNfcm9vdF9pZHM6CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuICJFUlJPUiIsICJ0YXJnZXQ6aW52YWxpZC10eXBlIgogICAgICAgICAgICAgICAgZWxpZiBvcy5wYXRoLmlzZmlsZShlbnRyeSk6CiAgICAgICAgICAgICAgICAgICAgdGFyZ2V0ID0gZW50cnkKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgcmV0dXJuICJFUlJPUiIsICJ0YXJnZXQ6aW52YWxpZC10eXBlIgogICAgICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgICAgIGluZm8gPSBvcy5zdGF0KHRhcmdldCkKICAgICAgICAgICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICAgICAgICAgIHJldHVybiAiRVJST1IiLCAidGFyZ2V0OmlkZW50aXR5LWZhaWxlZCIKICAgICAgICAgICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcoaW5mby5zdF9tb2RlKToKICAgICAgICAgICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgInRhcmdldDppbnZhbGlkLXR5cGUiCiAgICAgICAgICAgICAgICBtb2RlID0gc3RhdC5TX0lNT0RFKGluZm8uc3RfbW9kZSkKICAgICAgICAgICAgICAgIGlmIGxlbihmb3JtYXQobW9kZSwgIm8iKSkgbm90IGluICgzLCA0KToKICAgICAgICAgICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgInRhcmdldDppbnZhbGlkLW1vZGUiCiAgICAgICAgICAgICAgICBpZiByb2xlID09ICJleGVjIiBhbmQgbm90IG1vZGUgJiBFWEVDX0JJVFM6CiAgICAgICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgICAgIGlkZW50aXR5ID0gKGluZm8uc3RfZGV2LCBpbmZvLnN0X2lubykKICAgICAgICAgICAgICAgIGlmIGlkZW50aXR5IGluIHNlZW5fdGFyZ2V0czoKICAgICAgICAgICAgICAgICAgICBjb250aW51ZQogICAgICAgICAgICAgICAgc2Vlbl90YXJnZXRzLmFkZChpZGVudGl0eSkKICAgICAgICAgICAgICAgIGNvdW50c1tyb2xlXSArPSAxCiAgICAgICAgICAgICAgICBpdGVtcy5hcHBlbmQoKHRhcmdldCwgaW5mbywgcm9sZSkpCiAgICBmb3Igcm9sZSBpbiAoImV4ZWMiLCAibGliIiwgIm1vZHVsZSIpOgogICAgICAgIGlmIGNvdW50c1tyb2xlXSA9PSAwOgogICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgInBvcHVsYXRpb246bWlzc2luZy0iICsgKCJsaWJyYXJpZXMiIGlmIHJvbGUgPT0gImxpYiIgZWxzZSByb2xlICsgInMiKQogICAgY291bnRlcnMgPSB7InByZXNlbnQiOiBwcmVzZW50LCAiYWJzZW50IjogYWJzZW50LCAiYWxpYXNlcyI6IGFsaWFzZXMsICJjb3VudHMiOiBjb3VudHN9CiAgICByZXR1cm4gIlZBTFVFIiwgKGNvdW50ZXJzLCBpdGVtcykKCgpkZWYgX29ic2VydmVfcG9wdWxhdGlvbihleGVjX3Jvb3RzLCBsaWJfcm9vdHMsIG1vZHVsZV9yb290KToKICAgIHRyeToKICAgICAgICByZXR1cm4gX3BvcHVsYXRpb24oZXhlY19yb290cywgbGliX3Jvb3RzLCBtb2R1bGVfcm9vdCkKICAgIGV4Y2VwdCBfT2JzZXJ2YXRpb25FcnJvciBhcyBleGM6CiAgICAgICAgcmV0dXJuICJFUlJPUiIsIHN0cihleGMpCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHJldHVybiAiRVJST1IiLCAicnVudGltZTpvYnNlcnZlci1mYWlsZWQiCgoKZGVmIF9jdXJyZW50X3ZhbHVlKGNvdW50ZXJzLCBpdGVtcywgbWFzayk6CiAgICB2aW9sYXRpb25zID0gc3VtKDEgZm9yIF9wLCBzdCwgX3IgaW4gaXRlbXMgaWYgc3RhdC5TX0lNT0RFKHN0LnN0X21vZGUpICYgbWFzaykKICAgIGNvdW50cyA9IGNvdW50ZXJzWyJjb3VudHMiXQogICAgcmV0dXJuICgKICAgICAgICAicm9vdHNfcHJlc2VudD0lZDtyb290c19hYnNlbnQ9JWQ7YWxpYXNlcz0lZDtleGVjPSVkO2xpYnJhcmllcz0lZDttb2R1bGVzPSVkOyIKICAgICAgICAiY2hlY2tlZD0lZDt2aW9sYXRpb25zPSVkIgogICAgICAgICUgKGNvdW50ZXJzWyJwcmVzZW50Il0sIGNvdW50ZXJzWyJhYnNlbnQiXSwgY291bnRlcnNbImFsaWFzZXMiXSwKICAgICAgICAgICBjb3VudHNbImV4ZWMiXSwgY291bnRzWyJsaWIiXSwgY291bnRzWyJtb2R1bGUiXSwgbGVuKGl0ZW1zKSwgdmlvbGF0aW9ucykKICAgICkKCgpkZWYgb2JzZXJ2ZShleGVjX3Jvb3RzLCBsaWJfcm9vdHMsIG1vZHVsZV9yb290LCBleHBlY3RlZD1FWFBFQ1RFRF9NQVNLKToKICAgICIiIihzdGF0dXMsIHZhbHVlKSDQsiDRhNC+0YDQvNCw0YLQtSBDSEVDSy3QsNC00LDQv9GC0LXRgNCwINC00LvRjyDQtNCw0L3QvdGL0YUg0LrQvtGA0L3QtdC5LiIiIgogICAgbWFzayA9IGludChleHBlY3RlZCwgOCkKICAgIHN0YXR1cywgZGF0YSA9IF9vYnNlcnZlX3BvcHVsYXRpb24oZXhlY19yb290cywgbGliX3Jvb3RzLCBtb2R1bGVfcm9vdCkKICAgIGlmIHN0YXR1cyA9PSAiRVJST1IiOgogICAgICAgIHJldHVybiAiRVJST1IiLCBkYXRhCiAgICBjb3VudGVycywgaXRlbXMgPSBkYXRhCiAgICByZXR1cm4gIlZBTFVFIiwgX2N1cnJlbnRfdmFsdWUoY291bnRlcnMsIGl0ZW1zLCBtYXNrKQoKCmRlZiBfY2Fub25pY2FsX2RpcnMobG9jYXRvcik6CiAgICAiIiLQoNCw0LfRgNC10YjRkdC90L3Ri9C1INC/0YPRgtC4INC60LDQvdC+0L3QuNGH0LXRgdC60LjRhSDQutC+0YDQvdC10Lk6INCz0YDQsNC90LjRhtCwINC80YPRgtCw0YbQuNC4LiIiIgogICAgZXhlY19yb290cywgbGliX3Jvb3RzLCBtb2R1bGVfdGVtcGxhdGUgPSBjYW5vbmljYWxfcm9vdHMobG9jYXRvcikKICAgIG1vZHVsZV9yb290ID0gbW9kdWxlX3RlbXBsYXRlLnJlcGxhY2UoVU5BTUVfTUFSS0VSLCBvcy51bmFtZSgpLnJlbGVhc2UpCiAgICBkaXJzID0gW10KICAgIGZvciByb290IGluIHR1cGxlKGV4ZWNfcm9vdHMpICsgdHVwbGUobGliX3Jvb3RzKSArIChtb2R1bGVfcm9vdCwpOgogICAgICAgIHJlc29sdmVkID0gb3MucGF0aC5yZWFscGF0aChyb290KQogICAgICAgIGlmIHJlc29sdmVkIG5vdCBpbiBkaXJzOgogICAgICAgICAgICBkaXJzLmFwcGVuZChyZXNvbHZlZCkKICAgIHJldHVybiBkaXJzCgoKZGVmIF9pbnNpZGUocGF0aCwgZGlycyk6CiAgICBmb3Igcm9vdCBpbiBkaXJzOgogICAgICAgIGlmIHBhdGggPT0gcm9vdCBvciBwYXRoLnN0YXJ0c3dpdGgocm9vdC5yc3RyaXAoIi8iKSArICIvIik6CiAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICByZXR1cm4gRmFsc2UKCgpkZWYgX2RlZmF1bHRfcHJpdmlsZWdlX2NoZWNrKCkgLT4gYm9vbDoKICAgIHJldHVybiBvcy5nZXRldWlkKCkgPT0gMAoKCmRlZiBfZGVmYXVsdF9mY2htb2QoZmQsIG1vZGUsIHBhdGgpOgogICAgb3MuZmNobW9kKGZkLCBtb2RlKQoKCmRlZiBfcmVzdWx0KGNvbnRyb2xfaWQsIHRhcmdldCwgb3V0Y29tZSwgKiwgYWN0aW9ucywgZHJ5X3J1biwgbXV0YXRpb249RmFsc2UsICoqZXh0cmEpOgogICAgcmVjb3JkID0gewogICAgICAgICJhZGFwdGVyX2lkIjogQURBUFRFUl9JRCwKICAgICAgICAibWVjaGFuaXNtX2lkIjogTUVDSEFOSVNNX0lELAogICAgICAgICJjb250cm9sX2lkIjogY29udHJvbF9pZCwKICAgICAgICAidGFyZ2V0IjogdGFyZ2V0LAogICAgICAgICJvdXRjb21lIjogb3V0Y29tZSwKICAgICAgICAicmVhc29uIjogTm9uZSwKICAgICAgICAiY3VycmVudF9tb2RlIjogTm9uZSwKICAgICAgICAidmlvbGF0b3JzIjogW10sCiAgICAgICAgImFwcGxpZWQiOiBbXSwKICAgICAgICAic2tpcHBlZCI6IFtdLAogICAgICAgICJmYWlsZWQiOiBbXSwKICAgICAgICAiYWN0aW9uc19hdHRlbXB0ZWQiOiBsaXN0KGFjdGlvbnMpLAogICAgICAgICJtdXRhdGlvbl9wZXJmb3JtZWQiOiBib29sKG11dGF0aW9uKSwKICAgICAgICAidHJhbnNhY3Rpb25fY29tbWl0IjogX2NvbW1pdF9zdGF0ZShvdXRjb21lLCBkcnlfcnVuLCBtdXRhdGlvbiksCiAgICAgICAgImRyeV9ydW4iOiBib29sKGRyeV9ydW4pLAogICAgfQogICAgcmVjb3JkLnVwZGF0ZShleHRyYSkKICAgIGlmIHJlY29yZFsib3V0Y29tZSJdIG5vdCBpbiBPVVRDT01FUzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJvdXRjb21lIG91dHNpZGUgY2xvc2VkIHZvY2FidWxhcnkiKQogICAgcmV0dXJuIHJlY29yZAoKCmRlZiBfY29tbWl0X3N0YXRlKG91dGNvbWUsIGRyeV9ydW4sIG11dGF0aW9uKToKICAgICIiItCi0LUg0LbQtSDQt9C90LDRh9C10L3QuNGPLCDRh9GC0L4g0YMgc3VpZC1zZ2lkLWFwcGxpY2F0aW9ucy1tb2RlLiIiIgogICAgaWYgb3V0Y29tZSA9PSAiQVBQTElFRCIgb3IgKG91dGNvbWUgPT0gIkFMUkVBRFlfQ09NUExJQU5UIiBhbmQgbm90IGRyeV9ydW4pOgogICAgICAgIHJldHVybiBDT01NSVRfQ09NTUlUVEVECiAgICBpZiBtdXRhdGlvbjoKICAgICAgICByZXR1cm4gQ09NTUlUX05PVF9DT01NSVRURUQKICAgIHJldHVybiBDT01NSVRfTk9UX1NUQVJURUQKCgpkZWYgb3V0Y29tZV9yY19jb250cmlidXRpb24ob3V0Y29tZSwgZHJ5X3J1bj1GYWxzZSk6CiAgICAiIiIiMCIg0LTQu9GPINGD0YHQv9C10YjQvdGL0YUg0LjRgdGF0L7QtNC+0LIsINC40L3QsNGH0LUgIm5vbnplcm8iOyBBUFBMSUVEX1BBUlRJQUwg4oCUIG5vbnplcm8uIiIiCiAgICBpZiBvdXRjb21lIGluICgiQVBQTElFRCIsICJBTFJFQURZX0NPTVBMSUFOVCIsICJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiKToKICAgICAgICByZXR1cm4gIjAiCiAgICBpZiBkcnlfcnVuIGFuZCBvdXRjb21lID09ICJEUllfUlVOX1dPVUxEX0FQUExZIjoKICAgICAgICByZXR1cm4gIjAiCiAgICByZXR1cm4gIm5vbnplcm8iCgoKZGVmIF9hcHBseV9vbmUocGF0aCwgb2JzZXJ2ZWQsIG1hc2ssIGZjaG1vZCk6CiAgICAiIiLQodC90Y/RgtGMINCx0LjRgtGLIG1hc2sg0YMg0L7QtNC90L7Qs9C+INC+0LHRitC10LrRgtCwLgoKICAgINCS0L7Qt9Cy0YDQsNGJ0LDQtdGCIChtdXRhdGVkLCBraW5kLCByZWFzb24pOiBraW5kIOKAlCAib2siLCAic2tpcCIg0LjQu9C4ICJmYWlsIi4KICAgINCg0LXQstCw0LvQuNC00LDRhtC40Y8g0L3QsCDQtNC10YHQutGA0LjQv9GC0L7RgNC1INGB0YLRgNC+0LPQviDQsiDQv9C+0YDRj9C00LrQtSBTX0lTUkVHIC0+IGRldi9pbm8gLT4g0LHQuNGC0YsgbWFzay4KICAgICIiIgogICAgdHJ5OgogICAgICAgIGZkID0gb3Mub3BlbihwYXRoLCBvcy5PX1JET05MWSB8IG9zLk9fTk9GT0xMT1cgfCBvcy5PX0NMT0VYRUMpCiAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgaWYgZXhjLmVycm5vID09IGVycm5vLkVMT09QOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgIm5vdC1yZWd1bGFyIgogICAgICAgIHJldHVybiBGYWxzZSwgImZhaWwiLCAib3BlbjolcyIgJSBlcnJuby5lcnJvcmNvZGUuZ2V0KGV4Yy5lcnJubywgZXhjLmVycm5vKQogICAgdHJ5OgogICAgICAgIG5vdyA9IG9zLmZzdGF0KGZkKQogICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcobm93LnN0X21vZGUpOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgIm5vdC1yZWd1bGFyIgogICAgICAgIGlmIChub3cuc3RfZGV2LCBub3cuc3RfaW5vKSAhPSAob2JzZXJ2ZWQuc3RfZGV2LCBvYnNlcnZlZC5zdF9pbm8pOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgImlkZW50aXR5LWRyaWZ0IgogICAgICAgIGN1cnJlbnQgPSBzdGF0LlNfSU1PREUobm93LnN0X21vZGUpCiAgICAgICAgaWYgbm90IGN1cnJlbnQgJiBtYXNrOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgIm5vLXZpb2xhdGlvbi1iaXRzIgogICAgICAgIGlmIG5vdy5zdF9ubGluayAhPSAxOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgInN0X25saW5rIgogICAgICAgIHBsYW5uZWQgPSBjdXJyZW50ICYgfm1hc2sKICAgICAgICBmY2htb2QoZmQsIHBsYW5uZWQsIHBhdGgpCiAgICAgICAgcG9zdCA9IG9zLmZzdGF0KGZkKQogICAgICAgIGlmICgKICAgICAgICAgICAgc3RhdC5TX0lNT0RFKHBvc3Quc3RfbW9kZSkgIT0gcGxhbm5lZAogICAgICAgICAgICBvciAocG9zdC5zdF91aWQsIHBvc3Quc3RfZ2lkKSAhPSAobm93LnN0X3VpZCwgbm93LnN0X2dpZCkKICAgICAgICAgICAgb3IgKHBvc3Quc3RfZGV2LCBwb3N0LnN0X2lubykgIT0gKG5vdy5zdF9kZXYsIG5vdy5zdF9pbm8pCiAgICAgICAgICAgIG9yIHBvc3Quc3Rfc2l6ZSAhPSBub3cuc3Rfc2l6ZQogICAgICAgICk6CiAgICAgICAgICAgIHJldHVybiBUcnVlLCAiZmFpbCIsICJwb3N0LXN0YXRlLW1pc21hdGNoIgogICAgICAgIHJldHVybiBUcnVlLCAib2siLCBOb25lCiAgICBmaW5hbGx5OgogICAgICAgIG9zLmNsb3NlKGZkKQoKCmRlZiBleGVjdXRlX2NvbnRyb2woCiAgICBjb250cm9sX2lkLAogICAga2V5LAogICAgb3AsCiAgICBleHBlY3RlZCwKICAgIGFwcGx5X3N1cHBvcnRlZCwKICAgICosCiAgICB0YXJnZXQ9Tm9uZSwKICAgIGRyeV9ydW4sCiAgICBwcml2aWxlZ2VfY2hlY2s9Tm9uZSwKICAgIF9mY2htb2Q9Tm9uZSwKKToKICAgICIiIkFwcGx5IHRoZSAyLjMuOCBzdGFuZGFyZCBzeXN0ZW0gcGF0aHMgY29udHJvbC4gTmV2ZXIgZm9sbG93cyBhIHN5bWxpbmssIG5ldmVyIHJlbGF4ZXMuIiIiCiAgICB2YWxpZGF0ZV9jb250cm9sX2lucHV0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQpCiAgICBhY3Rpb25zID0gWyJQMF9FTElHSUJJTElUWSJdCgogICAgZGVmIGRvbmUob3V0Y29tZSwgKipleHRyYSk6CiAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwgdGFyZ2V0LCBvdXRjb21lLCBhY3Rpb25zPWFjdGlvbnMsIGRyeV9ydW49ZHJ5X3J1biwgKipleHRyYSkKCiAgICBpZiBub3QgYXBwbHlfc3VwcG9ydGVkOgogICAgICAgIHJldHVybiBkb25lKCJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiLCByZWFzb249ImFwcGx5LXVuc3VwcG9ydGVkIikKICAgIGlmIG5vdCBfaXNfZWxpZ2libGVfY29udHJhY3Qoa2V5LCBvcCwgZXhwZWN0ZWQpOgogICAgICAgIHJldHVybiBkb25lKCJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiLCByZWFzb249Im9wLXVuc3VwcG9ydGVkIikKCiAgICBpZiB0YXJnZXQgaXMgTm9uZToKICAgICAgICB0YXJnZXQgPSBUQVJHRVRTLmdldChjb250cm9sX2lkKQogICAgICAgIGlmIHRhcmdldCBpcyBOb25lOgogICAgICAgICAgICByZXR1cm4gZG9uZSgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLCByZWFzb249InRhcmdldDp1bm1hcHBlZC1jb250cm9sIikKCiAgICBtYXNrID0gaW50KGV4cGVjdGVkLCA4KQogICAgYWN0aW9ucy5hcHBlbmQoIlAxX1BPUFVMQVRJT04iKQogICAgdHJ5OgogICAgICAgIGV4ZWNfcm9vdHMsIGxpYl9yb290cywgbW9kdWxlX3Jvb3QgPSByZXNvbHZlX3Jvb3RzKHRhcmdldCkKICAgICAgICBjYW5vbmljYWwgPSBfY2Fub25pY2FsX2RpcnModGFyZ2V0KQogICAgZXhjZXB0IFZhbHVlRXJyb3IgYXMgZXhjOgogICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsIHJlYXNvbj1zdHIoZXhjKSkKICAgIHN0YXR1cywgZGF0YSA9IF9vYnNlcnZlX3BvcHVsYXRpb24oZXhlY19yb290cywgbGliX3Jvb3RzLCBtb2R1bGVfcm9vdCkKICAgIGlmIHN0YXR1cyA9PSAiRVJST1IiOgogICAgICAgIG91dGNvbWUgPSAiQUJPUlRFRF9QUkVDT05ESVRJT05fQ09ORkxJQ1QiIGlmIGRhdGEgaW4gQ09ORkxJQ1RfUkVBU09OUyBlbHNlICJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIKICAgICAgICByZXR1cm4gZG9uZShvdXRjb21lLCByZWFzb249ZGF0YSkKICAgIGNvdW50ZXJzLCBpdGVtcyA9IGRhdGEKCiAgICBhY3Rpb25zLmFwcGVuZCgiUDJfUExBTiIpCiAgICBjdXJyZW50ID0gX2N1cnJlbnRfdmFsdWUoY291bnRlcnMsIGl0ZW1zLCBtYXNrKQogICAgdmlvbGF0b3JzID0gc29ydGVkKAogICAgICAgICgocGF0aCwgc3QpIGZvciBwYXRoLCBzdCwgX3JvbGUgaW4gaXRlbXMgaWYgc3RhdC5TX0lNT0RFKHN0LnN0X21vZGUpICYgbWFzayksCiAgICAgICAga2V5PWxhbWJkYSBwYWlyOiBvcy5mc2VuY29kZShwYWlyWzBdKSwKICAgICkKICAgIGlmIG5vdCB2aW9sYXRvcnM6CiAgICAgICAgcmV0dXJuIGRvbmUoIkFMUkVBRFlfQ09NUExJQU5UIiwgY3VycmVudF9tb2RlPWN1cnJlbnQpCiAgICBza2lwcGVkID0gW10KICAgIHBsYW5uZWQgPSBbXQogICAgZm9yIHBhdGgsIHN0IGluIHZpb2xhdG9yczoKICAgICAgICBpZiBub3QgX2luc2lkZShwYXRoLCBjYW5vbmljYWwpOgogICAgICAgICAgICBza2lwcGVkLmFwcGVuZCh7InBhdGgiOiBwYXRoLCAicmVhc29uIjogIm91dHNpZGUtY2Fub25pY2FsLXJvb3RzIn0pCiAgICAgICAgZWxpZiBzdC5zdF9ubGluayAhPSAxOgogICAgICAgICAgICBza2lwcGVkLmFwcGVuZCh7InBhdGgiOiBwYXRoLCAicmVhc29uIjogInN0X25saW5rIn0pCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcGxhbm5lZC5hcHBlbmQoKHBhdGgsIHN0KSkKICAgIHZpb2xhdG9yX3BhdGhzID0gW3BhdGggZm9yIHBhdGgsIF9zdCBpbiB2aW9sYXRvcnNdCiAgICBpZiBub3QgcGxhbm5lZDoKICAgICAgICByZWFzb25zID0ge2l0ZW1bInJlYXNvbiJdIGZvciBpdGVtIGluIHNraXBwZWR9CiAgICAgICAgcmVhc29uID0gc2tpcHBlZFswXVsicmVhc29uIl0gaWYgbGVuKHJlYXNvbnMpID09IDEgZWxzZSAibm8tbXV0YWJsZS1vYmplY3QiCiAgICAgICAgcmV0dXJuIGRvbmUoIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIiwgcmVhc29uPXJlYXNvbiwgY3VycmVudF9tb2RlPWN1cnJlbnQsCiAgICAgICAgICAgICAgICAgICAgdmlvbGF0b3JzPXZpb2xhdG9yX3BhdGhzLCBza2lwcGVkPXNraXBwZWQpCiAgICBpZiBkcnlfcnVuOgogICAgICAgIHJldHVybiBkb25lKCJEUllfUlVOX1dPVUxEX0FQUExZIiwgY3VycmVudF9tb2RlPWN1cnJlbnQsCiAgICAgICAgICAgICAgICAgICAgdmlvbGF0b3JzPXZpb2xhdG9yX3BhdGhzLCBza2lwcGVkPXNraXBwZWQpCgogICAgYWN0aW9ucy5hcHBlbmQoIlAzX1BSSVZJTEVHRSIpCiAgICBjaGVjayA9IHByaXZpbGVnZV9jaGVjayBpZiBwcml2aWxlZ2VfY2hlY2sgaXMgbm90IE5vbmUgZWxzZSBfZGVmYXVsdF9wcml2aWxlZ2VfY2hlY2sKICAgIGlmIG5vdCBjaGVjaygpOgogICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsIHJlYXNvbj0icHJpdmlsZWdlIiwgY3VycmVudF9tb2RlPWN1cnJlbnQsCiAgICAgICAgICAgICAgICAgICAgdmlvbGF0b3JzPXZpb2xhdG9yX3BhdGhzLCBza2lwcGVkPXNraXBwZWQpCgogICAgYWN0aW9ucy5hcHBlbmQoIlBIQVNFMV9NT0RFIikKICAgIGZjaG1vZCA9IF9mY2htb2QgaWYgX2ZjaG1vZCBpcyBub3QgTm9uZSBlbHNlIF9kZWZhdWx0X2ZjaG1vZAogICAgYXBwbGllZCwgZmFpbGVkID0gW10sIFtdCiAgICBtdXRhdGVkID0gRmFsc2UKICAgIGZvciBwYXRoLCBzdCBpbiBwbGFubmVkOgogICAgICAgIHRyeToKICAgICAgICAgICAgY2hhbmdlZCwga2luZCwgcmVhc29uID0gX2FwcGx5X29uZShwYXRoLCBzdCwgbWFzaywgZmNobW9kKQogICAgICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICAgICAgaWYgZXhjLmVycm5vID09IGVycm5vLkVST0ZTOgogICAgICAgICAgICAgICAgb3V0Y29tZSA9ICJBUFBMSUVEX1BBUlRJQUwiIGlmIG11dGF0ZWQgZWxzZSAiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiCiAgICAgICAgICAgICAgICByZXR1cm4gZG9uZShvdXRjb21lLCByZWFzb249ImVyb2ZzIiwgbXV0YXRpb249bXV0YXRlZCwgY3VycmVudF9tb2RlPWN1cnJlbnQsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2aW9sYXRvcnM9dmlvbGF0b3JfcGF0aHMsIGFwcGxpZWQ9YXBwbGllZCwgc2tpcHBlZD1za2lwcGVkLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgZmFpbGVkPWZhaWxlZCArIFt7InBhdGgiOiBwYXRoLCAicmVhc29uIjogImVyb2ZzIn1dKQogICAgICAgICAgICBjaGFuZ2VkLCBraW5kLCByZWFzb24gPSBGYWxzZSwgImZhaWwiLCAiZmNobW9kOiVzIiAlIGVycm5vLmVycm9yY29kZS5nZXQoZXhjLmVycm5vLCBleGMuZXJybm8pCiAgICAgICAgbXV0YXRlZCA9IG11dGF0ZWQgb3IgY2hhbmdlZAogICAgICAgIGlmIGtpbmQgPT0gIm9rIjoKICAgICAgICAgICAgYXBwbGllZC5hcHBlbmQocGF0aCkKICAgICAgICBlbGlmIGtpbmQgPT0gInNraXAiOgogICAgICAgICAgICBza2lwcGVkLmFwcGVuZCh7InBhdGgiOiBwYXRoLCAicmVhc29uIjogcmVhc29ufSkKICAgICAgICBlbHNlOgogICAgICAgICAgICBmYWlsZWQuYXBwZW5kKHsicGF0aCI6IHBhdGgsICJyZWFzb24iOiByZWFzb259KQoKICAgIGFjdGlvbnMuYXBwZW5kKCJGSU5BTF9QT1NUQ0hFQ0siKQogICAgZXh0cmEgPSBkaWN0KGN1cnJlbnRfbW9kZT1jdXJyZW50LCB2aW9sYXRvcnM9dmlvbGF0b3JfcGF0aHMsIGFwcGxpZWQ9YXBwbGllZCwKICAgICAgICAgICAgICAgICBza2lwcGVkPXNraXBwZWQsIGZhaWxlZD1mYWlsZWQpCiAgICBpZiBub3QgZmFpbGVkIGFuZCBub3Qgc2tpcHBlZDoKICAgICAgICByZXR1cm4gZG9uZSgiQVBQTElFRCIsIG11dGF0aW9uPW11dGF0ZWQsICoqZXh0cmEpCiAgICBpZiBhcHBsaWVkOgogICAgICAgIHJldHVybiBkb25lKCJBUFBMSUVEX1BBUlRJQUwiLCByZWFzb249InBhcnRpYWwiLCBtdXRhdGlvbj1tdXRhdGVkLCAqKmV4dHJhKQogICAgcmV0dXJuIGRvbmUoIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwgcmVhc29uPSJuby1vYmplY3QtYXBwbGllZCIsIG11dGF0aW9uPW11dGF0ZWQsICoqZXh0cmEpCgoKZGVmIGNvbnRyb2xfcmVzdWx0X3RvX3JlcG9ydChyZXN1bHQsIHN0YXJ0ZWRfYXQsIGZpbmlzaGVkX2F0KToKICAgIHJldHVybiB7CiAgICAgICAgImFkYXB0ZXJfaWQiOiByZXN1bHRbImFkYXB0ZXJfaWQiXSwKICAgICAgICAibWVjaGFuaXNtX2lkIjogcmVzdWx0WyJtZWNoYW5pc21faWQiXSwKICAgICAgICAiY29udHJvbF9pZCI6IHJlc3VsdFsiY29udHJvbF9pZCJdLAogICAgICAgICJ0YXJnZXQiOiByZXN1bHRbInRhcmdldCJdLAogICAgICAgICJvdXRjb21lIjogcmVzdWx0WyJvdXRjb21lIl0sCiAgICAgICAgInJlYXNvbiI6IHJlc3VsdFsicmVhc29uIl0sCiAgICAgICAgImN1cnJlbnRfbW9kZSI6IHJlc3VsdFsiY3VycmVudF9tb2RlIl0sCiAgICAgICAgInZpb2xhdG9ycyI6IGxpc3QocmVzdWx0WyJ2aW9sYXRvcnMiXSksCiAgICAgICAgImFwcGxpZWQiOiBsaXN0KHJlc3VsdFsiYXBwbGllZCJdKSwKICAgICAgICAic2tpcHBlZCI6IFtkaWN0KGl0ZW0pIGZvciBpdGVtIGluIHJlc3VsdFsic2tpcHBlZCJdXSwKICAgICAgICAiZmFpbGVkIjogW2RpY3QoaXRlbSkgZm9yIGl0ZW0gaW4gcmVzdWx0WyJmYWlsZWQiXV0sCiAgICAgICAgInN0YXJ0ZWRfYXQiOiBzdGFydGVkX2F0LAogICAgICAgICJmaW5pc2hlZF9hdCI6IGZpbmlzaGVkX2F0LAogICAgICAgICJhY3Rpb25zX2F0dGVtcHRlZCI6IGxpc3QocmVzdWx0WyJhY3Rpb25zX2F0dGVtcHRlZCJdKSwKICAgICAgICAic3RlcF9yYyI6IG91dGNvbWVfcmNfY29udHJpYnV0aW9uKHJlc3VsdFsib3V0Y29tZSJdLCByZXN1bHRbImRyeV9ydW4iXSksCiAgICAgICAgIm11dGF0aW9uX3BlcmZvcm1lZCI6IHJlc3VsdFsibXV0YXRpb25fcGVyZm9ybWVkIl0sCiAgICAgICAgInRyYW5zYWN0aW9uX2NvbW1pdCI6IHJlc3VsdFsidHJhbnNhY3Rpb25fY29tbWl0Il0sCiAgICB9Cg=="},"startup-files-write-protection":{"adapter_id":"product-startup-files-write-protection-apply-v1","apply_kind":"startup-files-write-protection-v1","implementation_sha256":"a4c8a0d2c8c028dc31bdd4e9ea403462d321e9924cf8a3deadc687d630deae2a","mechanism_id":"startup-files-write-protection-v1","source_b64":"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiJwcm9kdWN0LXN0YXJ0dXAtZmlsZXMtd3JpdGUtcHJvdGVjdGlvbi1hcHBseS12MS4KCkFQUExZIGFkYXB0ZXIgZm9yIG1lY2hhbmlzbSBgc3RhcnR1cC1maWxlcy13cml0ZS1wcm90ZWN0aW9uLXYxYCAoMi4zLjUgc3RhcnR1cCBmaWxlcykuCgpQVVJQT1NFPURFRkVOU0lWRV9DT01QTElBTkNFX1ZBTElEQVRJT04KQXV0aG9yaXR5OiBwcm9kdWN0L2NvbnRyYWN0cy9tZWNoYW5pc20tc3RhcnR1cC1maWxlcy13cml0ZS1wcm90ZWN0aW9uLXYxLmpzb24KClBvcHVsYXRpb24gaXMgdGhlIG9uZSBvZiBDSEVDSyBhZGFwdGVyIHByb2R1Y3Qtc3RhcnR1cC1maWxlcy13cml0ZS1wcm90ZWN0aW9uLWNoZWNrLXYxOgrQvdC10L/QvtGB0YDQtdC00YHRgtCy0LXQvdC90YvQtSDRjdC70LXQvNC10L3RgtGLIGAvZXRjL3JjMC5kYCDigKYgYC9ldGMvcmM2LmRgICjQv9C+0LTQutCw0YLQsNC70L7Qs9C4INC/0YDQvtC/0YPRgdC60LDRjtGC0YHRjykK0Lgg0L3QtdC/0L7RgdGA0LXQtNGB0YLQstC10L3QvdGL0LUgYCouc2VydmljZWAg0LrQsNC20LTQvtCz0L4g0YPQvdC40LrQsNC70YzQvdC+0LPQviDQutC+0YDQvdGPINC40LcKYHN5c3RlbWQtYW5hbHl6ZSB1bml0LXBhdGhzYDsg0YHQuNC80LvQuNC90Log0YDQsNC30YDQtdGI0LDQtdGC0YHRjyDQsiDQutC+0L3QtdGH0L3Rg9GOINGG0LXQu9GMICjRgdC10LzQsNC90YLQuNC60LAKYGNobW9kIG8td2ApLCDRhtC10L/QvtGH0LrQsCBgLnNlcnZpY2VgINC00L4gYC9kZXYvbnVsbGAg4oCUINC80LDRgdC60LAsINC90LUg0L7QsdGK0LXQutGCOyDRhtC10LvQuArQtNC10LTRg9C/0LvQuNGG0LjRgNGD0Y7RgtGB0Y8g0L/QviBgZGV2Omlub2A7INGB0L3QuNC80LrQuCDQutC+0YDQvdC10LksINC/0L7Qv9GD0LvRj9GG0LjQuSwg0Y3Qu9C10LzQtdC90YLQvtCyINC4INGG0LXQu9C10LkK0YHQstC10YDRj9GO0YLRgdGPINCyINC60L7QvdGG0LUg0L3QsNCx0LvRjtC00LXQvdC40Y8uINCf0LXRgNC10YfQuNGB0LvQuNGC0LXQu9GMINC90LjQttC1IOKAlCBQeXRob24t0LrQvtC/0LjRjyDRgtC+0LPQvgrQvdCw0LHQu9GO0LTQsNGC0LXQu9GPOyDQv9Cw0YDQuNGC0LXRgiDQv9GA0L7QstC10YDRj9C10YLRgdGPCnRlc3RzL3Byb2R1Y3QtdjEvdGVzdF9zdGFydHVwX2ZpbGVzX3dyaXRlX3Byb3RlY3Rpb25fYXBwbHlfYWRhcHRlci5weS4KCtCa0L7RgNC90LggcmMg0L3QtSDQu9C40YLQtdGA0LDQu9GLOiDQvtC90Lgg0YDQsNC30LHQuNGA0LDRjtGC0YHRjyDQuNC3INC70L7QutCw0YLQvtGA0LAg0LrQvtC90YLRgNC+0LvRjyAoYFRBUkdFVFNgKSwg0LgK0YHQvtCy0L/QsNC00LXQvdC40LUg0YDQsNC30LHQvtGA0LAg0YEg0LrQvtC90YHRgtCw0L3RgtC+0LkgQ0hFQ0st0LDQtNCw0L/RgtC10YDQsCBgQ0FOT05JQ0FMX1JDX1JPT1RTYCDQt9Cw0LrRgNC10L/Qu9C10L3QvgrRgtC10Lwg0LbQtSDRgtC10YHRgtC+0LwuINCe0LHRitC10LrRgiDQvNGD0YLQsNGG0LjQuCDigJQg0YDQsNC30YDQtdGI0ZHQvdC90LDRjyDRhtC10LvRjCDQuNC3INC/0L7Qv9GD0LvRj9GG0LjQuCBDSEVDSywg0LIg0YLQvtC8INGH0LjRgdC70LUK0YbQtdC70Ywg0YHQuNC80LvQuNC90LrQsCDQstC90LUgcmMt0LrQsNGC0LDQu9C+0LPQvtCyOiDQuNC90LDRh9C1IEFQUExZINC4IENIRUNLINGA0LDQt9C+0YjQu9C40YHRjCDQsdGLLgoKVGhlIHBsYW4gaXMgYnVpbHQgYmVmb3JlIGFueSBtdXRhdGlvbi4gQSB2aW9sYXRvciB3aXRoIHN0X25saW5rID4gMSBpcyBza2lwcGVkCmFuZCByZWNvcmRlZC4g0J/QtdGA0LXQtCDQvNGD0YLQsNGG0LjQtdC5INC+0LHRitC10LrRgiDRgNC10LLQsNC70LjQtNC40YDRg9C10YLRgdGPINC90LAg0YPQttC1INC+0YLQutGA0YvRgtC+0Lwg0LTQtdGB0LrRgNC40L/RgtC+0YDQtQrRgdGC0YDQvtCz0L4g0LIg0L/QvtGA0Y/QtNC60LUgYFNfSVNSRUdgIOKGkiBgZGV2L2lub2Ag0LjQtyDQv9C70LDQvdCwIOKGkiDQvdCw0LvQuNGH0LjQtSDQsdC40YLQsCDQvNCw0YHQutC4OwrQvdC10YHQvtCy0L/QsNC00LXQvdC40LUg0LvRjtCx0L7Qs9C+INGI0LDQs9CwIOKAlCDQv9GA0L7Qv9GD0YHQuiDQvtCx0YrQtdC60YLQsCDRgSDQv9GA0LjRh9C40L3QvtC5LiBFYWNoIG11dGF0aW9uIGlzIG9uZQpgZmNobW9kYCBvbiBhIGRlc2NyaXB0b3Igb3BlbmVkIHdpdGggT19OT0ZPTExPVyBhbmQgb25seSBjbGVhcnMgYml0IDAwMDI7IHRoZXJlCmlzIG5vIGNvbXBlbnNhdGlvbi4gQW4gZXJyb3Igb24gb25lIG9iamVjdCBkb2VzIG5vdCBzdG9wIHRoZSBvdGhlcnMKKEFQUExJRURfUEFSVElBTCk7IEVST0ZTIHN0b3BzIGltbWVkaWF0ZWx5LgoiIiIKCmZyb20gX19mdXR1cmVfXyBpbXBvcnQgYW5ub3RhdGlvbnMKCmltcG9ydCBlcnJubwppbXBvcnQgb3MKaW1wb3J0IHJlCmltcG9ydCBzdGF0CmltcG9ydCBzdWJwcm9jZXNzCgpBREFQVEVSX0lEID0gInByb2R1Y3Qtc3RhcnR1cC1maWxlcy13cml0ZS1wcm90ZWN0aW9uLWFwcGx5LXYxIgpNRUNIQU5JU01fSUQgPSAic3RhcnR1cC1maWxlcy13cml0ZS1wcm90ZWN0aW9uLXYxIgpUQVJHRVRfSUQgPSAibGludXgteDg2XzY0LXN1cHBvcnRlZC12MSIKUEFSQU1FVEVSX0tJTkQgPSAic3RhcnR1cC1maWxlcy13cml0ZS1wcm90ZWN0aW9uIgpTRU1BTlRJQ19DT05UUkFDVF9JRCA9ICJzdGFydHVwLWZpbGVzLXdyaXRlLXByb3RlY3Rpb24tYXBwbHktc2VtYW50aWMtdjEiCgpTVVBQT1JURURfS0VZUyA9ICgib3RoZXItd3JpdGUiLCkKU1VQUE9SVEVEX09QUyA9ICgiYml0cy1jbGVhciIsKQpFWFBFQ1RFRF9NQVNLID0gIjAwMDIiCgojINCc0LDRgNC60LXRgCDQu9C+0LrQsNGC0L7RgNCwIENIRUNLLdCw0LTQsNC/0YLQtdGA0LAg0Lgg0LXQs9C+INC40YHRgtC+0YfQvdC40Log0LrQvtGA0L3QtdC5INGO0L3QuNGC0L7Qsi4KVU5JVF9QQVRIU19NQVJLRVIgPSAic3lzdGVtZC11bml0LXBhdGhzIgpTWVNURU1EX0FOQUxZWkUgPSAiL3Vzci9iaW4vc3lzdGVtZC1hbmFseXplIgoKT1VUQ09NRVMgPSAoCiAgICAiQVBQTElFRCIsCiAgICAiQVBQTElFRF9QQVJUSUFMIiwKICAgICJBTFJFQURZX0NPTVBMSUFOVCIsCiAgICAiRFJZX1JVTl9XT1VMRF9BUFBMWSIsCiAgICAiTk9UX0VMSUdJQkxFX0FQUExZX1VOU1VQUE9SVEVEIiwKICAgICJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsCiAgICAiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLAogICAgIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwKKQoKQ09NTUlUX0NPTU1JVFRFRCA9ICJDT01NSVRURUQiCkNPTU1JVF9OT1RfQ09NTUlUVEVEID0gIk5PVF9DT01NSVRURUQiCkNPTU1JVF9OT1RfU1RBUlRFRCA9ICJOT1RfU1RBUlRFRCIKCiMg0JvQvtC60LDRgtC+0YAg0LXQtNC40L3RgdGC0LLQtdC90L3QvtCz0L4g0LrQvtC90YLRgNC+0LvRjyDQvNC10YXQsNC90LjQt9C80LAuINCh0L7QstC/0LDQtNC10L3QuNC1INGBIHBhcmFtZXRlci5sb2NhdG9yINC4INGBCiMg0LrQvtC90YHRgtCw0L3RgtCw0LzQuCBDSEVDSy3QsNC00LDQv9GC0LXRgNCwINC/0YDQvtCy0LXRgNGP0LXRggojIHRlc3Rfc3RhcnR1cF9maWxlc193cml0ZV9wcm90ZWN0aW9uX2FwcGx5X2FkYXB0ZXIucHkuClRBUkdFVFMgPSB7CiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjMuNS1TVEFSVFVQLUZJTEVTLVdSSVRFLVBST1RFQ1RJT04iOiAiL2V0Yy9yY1swLTZdLmR8c3lzdGVtZC11bml0LXBhdGhzIiwKfQoKQ09OVFJPTF9JRF9QQVRURVJOID0gciJeKD8hLipbXHJcbl0pW0EtWmEtejAtOS5fLV0rJCIKCiMg0J/RgNC40YfQuNC90YsgQ0hFQ0ssINC60L7RgtC+0YDRi9C1INC+0LfQvdCw0YfQsNGO0YIg0L7QsdGK0LXQutGCINC90LUg0YLQvtCz0L4g0YLQuNC/0LAg0LIg0L/QvtC/0YPQu9GP0YbQuNC4LgpDT05GTElDVF9SRUFTT05TID0gKAogICAgImRpcmVjdG9yeTppbnZhbGlkLXR5cGUiLAogICAgInRhcmdldDppbnZhbGlkLXR5cGUiLAopCgoKZGVmIHZhbGlkYXRlX2NvbnRyb2xfaW5wdXQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIGFwcGx5X3N1cHBvcnRlZCk6CiAgICAiIiJGYWlsLWNsb3NlZCB2YWxpZGF0aW9uIG9mIG9uZSBjb250cm9sIHJvdy4gUmFpc2VzIFZhbHVlRXJyb3IuIiIiCiAgICBpZiBub3QgaXNpbnN0YW5jZShjb250cm9sX2lkLCBzdHIpIG9yIG5vdCByZS5mdWxsbWF0Y2goQ09OVFJPTF9JRF9QQVRURVJOLCBjb250cm9sX2lkKToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJpbnZhbGlkIGNvbnRyb2wgaWQiKQogICAgaWYgbm90IGlzaW5zdGFuY2Uoa2V5LCBzdHIpIG9yIG5vdCBpc2luc3RhbmNlKG9wLCBzdHIpIG9yIG5vdCBpc2luc3RhbmNlKGV4cGVjdGVkLCBzdHIpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImtleSwgb3AgYW5kIGV4cGVjdGVkIG11c3QgYmUgc3RyaW5ncyIpCiAgICBpZiBub3QgaXNpbnN0YW5jZShhcHBseV9zdXBwb3J0ZWQsIGJvb2wpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImFwcGx5X3N1cHBvcnRlZCBtdXN0IGJlIGJvb2wiKQogICAgcmV0dXJuIFRydWUKCgpkZWYgX2lzX2VsaWdpYmxlX2NvbnRyYWN0KGtleSwgb3AsIGV4cGVjdGVkKToKICAgICIiItCi0L7Qu9GM0LrQviAob3RoZXItd3JpdGUsIGJpdHMtY2xlYXIsIDAwMDIpOyDQstGB0ZEg0L/RgNC+0YfQtdC1INGA0LXRiNCw0LXRgiDQsNC00LzQuNC90LjRgdGC0YDQsNGC0L7RgC4iIiIKICAgIHJldHVybiBrZXkgaW4gU1VQUE9SVEVEX0tFWVMgYW5kIG9wIGluIFNVUFBPUlRFRF9PUFMgYW5kIGV4cGVjdGVkID09IEVYUEVDVEVEX01BU0sKCgpkZWYgY2Fub25pY2FsX3JjX3Jvb3RzKGxvY2F0b3IpOgogICAgIiIi0KDQsNC30LHQvtGAINC70L7QutCw0YLQvtGA0LAgYDxwcmVmaXg+W2EtYl08c3VmZml4PnxzeXN0ZW1kLXVuaXQtcGF0aHNgINCyIHJjLdC60L7RgNC90LguIiIiCiAgICBwYXJ0cyA9IGxvY2F0b3Iuc3BsaXQoInwiKQogICAgaWYgbGVuKHBhcnRzKSAhPSAyIG9yIHBhcnRzWzFdICE9IFVOSVRfUEFUSFNfTUFSS0VSOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImxvY2F0b3Igd2l0aG91dCAlcyIgJSBVTklUX1BBVEhTX01BUktFUikKICAgIG1hdGNoID0gcmUuZnVsbG1hdGNoKHIiKC9bXlxbXF18XSopXFsoWzAtOV0pLShbMC05XSlcXShbXlxbXF18XSopIiwgcGFydHNbMF0pCiAgICBpZiBtYXRjaCBpcyBOb25lIG9yIGludChtYXRjaC5ncm91cCgyKSkgPiBpbnQobWF0Y2guZ3JvdXAoMykpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImxvY2F0b3Igd2l0aG91dCBhIHJ1bmxldmVsIHJhbmdlIikKICAgIHByZWZpeCwgbG93LCBoaWdoLCBzdWZmaXggPSBtYXRjaC5ncm91cCgxKSwgaW50KG1hdGNoLmdyb3VwKDIpKSwgaW50KG1hdGNoLmdyb3VwKDMpKSwgbWF0Y2guZ3JvdXAoNCkKICAgIHJldHVybiB0dXBsZSgiJXMlZCVzIiAlIChwcmVmaXgsIGxldmVsLCBzdWZmaXgpIGZvciBsZXZlbCBpbiByYW5nZShsb3csIGhpZ2ggKyAxKSkKCgpjbGFzcyBfT2JzZXJ2YXRpb25FcnJvcihCYXNlRXhjZXB0aW9uKToKICAgICIiItCe0YLQutCw0Lcg0L3QsNCx0LvRjtC00LXQvdC40Y87INC60LDQuiBTeXN0ZW1FeGl0INGDIENIRUNLLCDQvdC1INC70L7QstC40YLRgdGPIGBleGNlcHQgRXhjZXB0aW9uYC4iIiIKCgpkZWYgX3BvcHVsYXRpb24ocmNfcm9vdHMsIHVuaXRfcGF0aHNfb3ZlcnJpZGUsIHN5c3RlbWRfYW5hbHl6ZSk6CiAgICAiIiLQmtC+0L/QuNGPIENIRUNLLdC90LDQsdC70Y7QtNCw0YLQtdC70Y86IChjb3VudGVycywgWyh0YXJnZXQsIHRhcmdldF9zdGF0ZSldKS4KCiAgICB0YXJnZXRfc3RhdGUg4oCUINC60L7RgNGC0LXQtiBDSEVDSyBgKGRldiwgaW5vLCB1aWQsIGdpZCwgdHlwZSwgbW9kZSwgc2l6ZSwgbXRpbWUsCiAgICBjdGltZSwgbmxpbmspYC4g0J7RgtC60LDQtyDigJQgX09ic2VydmF0aW9uRXJyb3Ig0YEg0L/RgNC40YfQuNC90L7QuSBDSEVDSy4KICAgICIiIgoKICAgIGRlZiBlbWl0X2Vycm9yKHJlYXNvbik6CiAgICAgICAgcmFpc2UgX09ic2VydmF0aW9uRXJyb3IocmVhc29uKQoKICAgIGRlZiBzdGF0ZV9sc3RhdChwYXRoKToKICAgICAgICBzdCA9IG9zLmxzdGF0KHBhdGgpCiAgICAgICAgcmV0dXJuIChzdC5zdF9kZXYsIHN0LnN0X2lubywgc3Quc3RfdWlkLCBzdC5zdF9naWQsIHN0YXQuU19JRk1UKHN0LnN0X21vZGUpLCBzdGF0LlNfSU1PREUoc3Quc3RfbW9kZSksIHN0LnN0X3NpemUsIHN0LnN0X210aW1lX25zLCBzdC5zdF9jdGltZV9ucywgc3Quc3RfbmxpbmspCgogICAgZGVmIHN0YXRlX3N0YXQocGF0aCk6CiAgICAgICAgc3QgPSBvcy5zdGF0KHBhdGgsIGZvbGxvd19zeW1saW5rcz1UcnVlKQogICAgICAgIHJldHVybiAoc3Quc3RfZGV2LCBzdC5zdF9pbm8sIHN0LnN0X3VpZCwgc3Quc3RfZ2lkLCBzdGF0LlNfSUZNVChzdC5zdF9tb2RlKSwgc3RhdC5TX0lNT0RFKHN0LnN0X21vZGUpLCBzdC5zdF9zaXplLCBzdC5zdF9tdGltZV9ucywgc3Quc3RfY3RpbWVfbnMsIHN0LnN0X25saW5rKQoKICAgIGRlZiBkaXJfaWRlbnRpdHkocGF0aCk6CiAgICAgICAgc3QgPSBvcy5zdGF0KHBhdGgsIGZvbGxvd19zeW1saW5rcz1UcnVlKQogICAgICAgIGlmIG5vdCBzdGF0LlNfSVNESVIoc3Quc3RfbW9kZSk6CiAgICAgICAgICAgIGVtaXRfZXJyb3IoImRpcmVjdG9yeTppbnZhbGlkLXR5cGUiKQogICAgICAgIHJldHVybiAoc3Quc3RfZGV2LCBzdC5zdF9pbm8pCgogICAgZGVmIGRpcmVjdF9uYW1lcyhyb290KToKICAgICAgICB0cnk6CiAgICAgICAgICAgIG5hbWVzID0gW10KICAgICAgICAgICAgd2l0aCBvcy5zY2FuZGlyKHJvb3QpIGFzIGl0OgogICAgICAgICAgICAgICAgZm9yIGVudCBpbiBpdDoKICAgICAgICAgICAgICAgICAgICBuYW1lcy5hcHBlbmQoZW50Lm5hbWUpCiAgICAgICAgICAgIG5hbWVzLnNvcnQoa2V5PW9zLmZzZW5jb2RlKQogICAgICAgICAgICByZXR1cm4gdHVwbGUobmFtZXMpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgZW1pdF9lcnJvcigiZGlyZWN0b3J5OnNjYW4tZmFpbGVkIikKCiAgICBkZWYgZGlyZWN0X3NlcnZpY2VfbmFtZXMocm9vdCk6CiAgICAgICAgcmV0dXJuIHR1cGxlKHggZm9yIHggaW4gZGlyZWN0X25hbWVzKHJvb3QpIGlmIHguZW5kc3dpdGgoIi5zZXJ2aWNlIikpCgogICAgZGVmIHJlc29sdmVfY2FuZGlkYXRlKHBhdGgsIHNlcnZpY2Vfcm9sZSk6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBmaXJzdF9sID0gc3RhdGVfbHN0YXQocGF0aCkKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICBlbWl0X2Vycm9yKCJ0YXJnZXQ6bHN0YXQtZmFpbGVkIikKICAgICAgICBtb2RlX3R5cGUgPSBmaXJzdF9sWzRdCiAgICAgICAgaWYgc3RhdC5TX0lTRElSKG1vZGVfdHlwZSk6CiAgICAgICAgICAgIGlmIHNlcnZpY2Vfcm9sZToKICAgICAgICAgICAgICAgIGVtaXRfZXJyb3IoInRhcmdldDppbnZhbGlkLXR5cGUiKQogICAgICAgICAgICByZXR1cm4gKCJkaXJlY3RvcnkiLCBOb25lLCBmaXJzdF9sLCBOb25lKQogICAgICAgIGlmIHN0YXQuU19JU0xOSyhtb2RlX3R5cGUpOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICB0YXJnZXQgPSBvcy5wYXRoLnJlYWxwYXRoKHBhdGgpCiAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgICAgICBlbWl0X2Vycm9yKCJ0YXJnZXQ6cmVzb2x2ZS1mYWlsZWQiKQogICAgICAgICAgICBpZiBzZXJ2aWNlX3JvbGUgYW5kIG9zLnBhdGgubm9ybXBhdGgodGFyZ2V0KSA9PSAiL2Rldi9udWxsIjoKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBpZiBzdGF0ZV9sc3RhdChwYXRoKSAhPSBmaXJzdF9sOgogICAgICAgICAgICAgICAgICAgICAgICBlbWl0X2Vycm9yKCJ0YXJnZXQ6Y2hhbmdlZC1kdXJpbmctY2hlY2siKQogICAgICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgICAgICAgICBlbWl0X2Vycm9yKCJ0YXJnZXQ6bHN0YXQtZmFpbGVkIikKICAgICAgICAgICAgICAgIHJlc29sdXRpb25fc25hcHNob3RzW3BhdGhdID0gdGFyZ2V0CiAgICAgICAgICAgICAgICByZXR1cm4gKCJtYXNrZWQiLCBOb25lLCBmaXJzdF9sLCBOb25lKQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICB0YXJnZXRfc3RhdGUgPSBzdGF0ZV9zdGF0KHRhcmdldCkKICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgICAgIGVtaXRfZXJyb3IoInRhcmdldDpzdGF0LWZhaWxlZCIpCiAgICAgICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcodGFyZ2V0X3N0YXRlWzRdKToKICAgICAgICAgICAgICAgIGVtaXRfZXJyb3IoInRhcmdldDppbnZhbGlkLXR5cGUiKQogICAgICAgICAgICByZXNvbHV0aW9uX3NuYXBzaG90c1twYXRoXSA9IHRhcmdldAogICAgICAgICAgICByZXR1cm4gKCJyZWd1bGFyIiwgdGFyZ2V0LCBmaXJzdF9sLCB0YXJnZXRfc3RhdGUpCiAgICAgICAgaWYgc3RhdC5TX0lTUkVHKG1vZGVfdHlwZSk6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHRhcmdldF9zdGF0ZSA9IHN0YXRlX3N0YXQocGF0aCkKICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgICAgIGVtaXRfZXJyb3IoInRhcmdldDpzdGF0LWZhaWxlZCIpCiAgICAgICAgICAgIHJldHVybiAoInJlZ3VsYXIiLCBwYXRoLCBmaXJzdF9sLCB0YXJnZXRfc3RhdGUpCiAgICAgICAgZW1pdF9lcnJvcigidGFyZ2V0OmludmFsaWQtdHlwZSIpCgogICAgZGVmIHJlYWRfdW5pdF9wYXRocygpOgogICAgICAgIGlmIHVuaXRfcGF0aHNfb3ZlcnJpZGUgaXMgbm90IE5vbmU6CiAgICAgICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKHVuaXRfcGF0aHNfb3ZlcnJpZGUsIChsaXN0LCB0dXBsZSkpIG9yIGFueShub3QgaXNpbnN0YW5jZSh4LCBzdHIpIGZvciB4IGluIHVuaXRfcGF0aHNfb3ZlcnJpZGUpOgogICAgICAgICAgICAgICAgZW1pdF9lcnJvcigic3lzdGVtZDppbnZhbGlkLXVuaXQtcGF0aHMiKQogICAgICAgICAgICByZXR1cm4gdHVwbGUodW5pdF9wYXRoc19vdmVycmlkZSksIE5vbmUKICAgICAgICBlbnYgPSB7IkxDX0FMTCI6ICJDIiwgIlBBVEgiOiAiL3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4ifQogICAgICAgIHRyeToKICAgICAgICAgICAgcHJvYyA9IHN1YnByb2Nlc3MucnVuKFtzeXN0ZW1kX2FuYWx5emUsICJ1bml0LXBhdGhzIl0sIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsIHN0ZGVycj1zdWJwcm9jZXNzLlBJUEUsIGVudj1lbnYsIGNoZWNrPUZhbHNlKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIGVtaXRfZXJyb3IoInN5c3RlbWQ6ZXhlY3V0aW9uLWZhaWxlZCIpCiAgICAgICAgaWYgcHJvYy5yZXR1cm5jb2RlICE9IDA6CiAgICAgICAgICAgIGVtaXRfZXJyb3IoInN5c3RlbWQ6ZXhlY3V0aW9uLWZhaWxlZCIpCiAgICAgICAgaWYgcHJvYy5zdGRlcnI6CiAgICAgICAgICAgIGVtaXRfZXJyb3IoInN5c3RlbWQ6c3RkZXJyLW91dHB1dCIpCiAgICAgICAgaWYgbm90IHByb2Muc3Rkb3V0OgogICAgICAgICAgICBlbWl0X2Vycm9yKCJzeXN0ZW1kOmVtcHR5LW91dHB1dCIpCiAgICAgICAgaWYgYiJceDAwIiBpbiBwcm9jLnN0ZG91dCBvciBiIlxyIiBpbiBwcm9jLnN0ZG91dDoKICAgICAgICAgICAgZW1pdF9lcnJvcigic3lzdGVtZDppbnZhbGlkLWJ5dGVzIikKICAgICAgICB0cnk6CiAgICAgICAgICAgIHRleHQgPSBwcm9jLnN0ZG91dC5kZWNvZGUoInV0Zi04IiwgZXJyb3JzPSJzdHJpY3QiKQogICAgICAgIGV4Y2VwdCBVbmljb2RlRGVjb2RlRXJyb3I6CiAgICAgICAgICAgIGVtaXRfZXJyb3IoInN5c3RlbWQ6aW52YWxpZC11dGY4IikKICAgICAgICBwYXRocyA9IFtdCiAgICAgICAgZm9yIGxpbmUgaW4gdGV4dC5zcGxpdGxpbmVzKCk6CiAgICAgICAgICAgIGlmIG5vdCBsaW5lLnN0YXJ0c3dpdGgoIi8iKSBvciAiXHgwMCIgaW4gbGluZSBvciAiXHIiIGluIGxpbmUgb3IgIlxuIiBpbiBsaW5lOgogICAgICAgICAgICAgICAgZW1pdF9lcnJvcigic3lzdGVtZDppbnZhbGlkLXBhdGgiKQogICAgICAgICAgICBwYXRocy5hcHBlbmQobGluZSkKICAgICAgICBpZiBub3QgcGF0aHM6CiAgICAgICAgICAgIGVtaXRfZXJyb3IoInN5c3RlbWQ6ZW1wdHktcG9wdWxhdGlvbiIpCiAgICAgICAgcmV0dXJuIHR1cGxlKHBhdGhzKSwgcHJvYy5zdGRvdXQKCiAgICB1bml0X3BhdGhzLCB1bml0X3BhdGhzX3JhdyA9IHJlYWRfdW5pdF9wYXRocygpCiAgICBpbml0aWFsX3VuaXRfcGF0aHMgPSB1bml0X3BhdGhzCiAgICByb290X3NuYXBzaG90cyA9IHt9CiAgICBwb3Bfc25hcHNob3RzID0ge30KICAgIGVudHJ5X3NuYXBzaG90cyA9IHt9CiAgICB0YXJnZXRfc25hcHNob3RzID0ge30KICAgIHJlc29sdXRpb25fc25hcHNob3RzID0ge30KICAgIHNlZW5fcm9vdF9pZHMgPSBzZXQoKQogICAgc2Vlbl90YXJnZXRfaWRzID0gc2V0KCkKICAgIGl0ZW1zID0gW10KICAgIG4gPSBkaWN0LmZyb21rZXlzKCgKICAgICAgICAicmNfcm9vdHNfcHJlc2VudCIsICJyY19yb290c19hYnNlbnQiLCAicmNfZW50cmllcyIsICJyY19kaXJlY3RvcmllcyIsICJyY190YXJnZXRzIiwKICAgICAgICAic2VydmljZV9yb290c19wcmVzZW50IiwgInNlcnZpY2Vfcm9vdHNfYWJzZW50IiwgInNlcnZpY2Vfcm9vdF9hbGlhc2VzIiwKICAgICAgICAic2VydmljZV9lbnRyaWVzIiwgInNlcnZpY2VfbWFza2VkIiwgInNlcnZpY2VfdGFyZ2V0cyIsICJjaGVja2VkIiwKICAgICksIDApCgogICAgZGVmIHJlbWVtYmVyX3Jvb3Rfc3RhdGUobG9naWNhbCwgcmVzb2x2ZWQpOgogICAgICAgIHRyeToKICAgICAgICAgICAgcm9vdF9zbmFwc2hvdHNbbG9naWNhbF0gPSAob3MucGF0aC5sZXhpc3RzKGxvZ2ljYWwpLCBzdGF0ZV9sc3RhdChsb2dpY2FsKSBpZiBvcy5wYXRoLmxleGlzdHMobG9naWNhbCkgZWxzZSBOb25lLCByZXNvbHZlZCwgc3RhdGVfc3RhdChyZXNvbHZlZCkpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgZW1pdF9lcnJvcigicm9vdDpzbmFwc2hvdC1mYWlsZWQiKQoKICAgIGRlZiBjaGVja190YXJnZXQocGF0aCwgZW50cnlfcGF0aCwgZW50cnlfc3RhdGUsIHRhcmdldF9zdGF0ZSwgcm9sZSk6CiAgICAgICAgaWRlbnQgPSAodGFyZ2V0X3N0YXRlWzBdLCB0YXJnZXRfc3RhdGVbMV0pCiAgICAgICAgblsicmNfdGFyZ2V0cyIgaWYgcm9sZSA9PSAicmMiIGVsc2UgInNlcnZpY2VfdGFyZ2V0cyJdICs9IDEKICAgICAgICBlbnRyeV9zbmFwc2hvdHNbZW50cnlfcGF0aF0gPSBlbnRyeV9zdGF0ZQogICAgICAgIHRhcmdldF9zbmFwc2hvdHNbcGF0aF0gPSB0YXJnZXRfc3RhdGUKICAgICAgICBpZiBpZGVudCBpbiBzZWVuX3RhcmdldF9pZHM6CiAgICAgICAgICAgIHJldHVybgogICAgICAgIHNlZW5fdGFyZ2V0X2lkcy5hZGQoaWRlbnQpCiAgICAgICAgblsiY2hlY2tlZCJdICs9IDEKICAgICAgICBpdGVtcy5hcHBlbmQoKHBhdGgsIHRhcmdldF9zdGF0ZSkpCgogICAgIyAvZXRjL3JjMC5kIC4uLiAvZXRjL3JjNi5kOiBkaXJlY3QgZmlsZS1saWtlIGVudHJpZXMgb25seTsgcmNTLmQgaXMgaW50ZW50aW9uYWxseSBub3QgaW4gdGhpcyBwb3B1bGF0aW9uLgogICAgZm9yIGxvZ2ljYWwgaW4gcmNfcm9vdHM6CiAgICAgICAgaWYgbm90IGlzaW5zdGFuY2UobG9naWNhbCwgc3RyKSBvciBub3QgbG9naWNhbC5zdGFydHN3aXRoKCIvIik6CiAgICAgICAgICAgIGVtaXRfZXJyb3IoInJvb3Q6aW52YWxpZC1wYXRoIikKICAgICAgICBpZiBub3Qgb3MucGF0aC5sZXhpc3RzKGxvZ2ljYWwpOgogICAgICAgICAgICBuWyJyY19yb290c19hYnNlbnQiXSArPSAxCiAgICAgICAgICAgIHJvb3Rfc25hcHNob3RzW2xvZ2ljYWxdID0gKEZhbHNlLCBOb25lLCBOb25lLCBOb25lKQogICAgICAgICAgICBjb250aW51ZQogICAgICAgIHRyeToKICAgICAgICAgICAgcmVzb2x2ZWQgPSBvcy5wYXRoLnJlYWxwYXRoKGxvZ2ljYWwpCiAgICAgICAgICAgIGlkZW50ID0gZGlyX2lkZW50aXR5KHJlc29sdmVkKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIGVtaXRfZXJyb3IoInJvb3Q6cmVzb2x2ZS1mYWlsZWQiKQogICAgICAgIG5bInJjX3Jvb3RzX3ByZXNlbnQiXSArPSAxCiAgICAgICAgbmFtZXMgPSBkaXJlY3RfbmFtZXMocmVzb2x2ZWQpCiAgICAgICAgcmVtZW1iZXJfcm9vdF9zdGF0ZShsb2dpY2FsLCByZXNvbHZlZCkKICAgICAgICBwb3Bfc25hcHNob3RzW3Jlc29sdmVkXSA9IChuYW1lcywgRmFsc2UpCiAgICAgICAgaWYgaWRlbnQgaW4gc2Vlbl9yb290X2lkczoKICAgICAgICAgICAgZW1pdF9lcnJvcigicm9vdDphbWJpZ3VvdXMtYWxpYXMiKQogICAgICAgIHNlZW5fcm9vdF9pZHMuYWRkKGlkZW50KQogICAgICAgIGZvciBuYW1lIGluIG5hbWVzOgogICAgICAgICAgICBwYXRoID0gb3MucGF0aC5qb2luKHJlc29sdmVkLCBuYW1lKQogICAgICAgICAgICBraW5kLCB0YXJnZXQsIGVudHJ5X3N0YXRlLCB0YXJnZXRfc3RhdGUgPSByZXNvbHZlX2NhbmRpZGF0ZShwYXRoLCBGYWxzZSkKICAgICAgICAgICAgaWYga2luZCA9PSAiZGlyZWN0b3J5IjoKICAgICAgICAgICAgICAgIG5bInJjX2RpcmVjdG9yaWVzIl0gKz0gMQogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgblsicmNfZW50cmllcyJdICs9IDEKICAgICAgICAgICAgY2hlY2tfdGFyZ2V0KHRhcmdldCwgcGF0aCwgZW50cnlfc3RhdGUsIHRhcmdldF9zdGF0ZSwgInJjIikKCiAgICAjIHN5c3RlbWQgdW5pdCBsb2FkIHBhdGhzOiBvbmx5IGRpcmVjdCAqLnNlcnZpY2UgZW50cmllcyBvZiBlYWNoIHVuaXF1ZSByb290LgogICAgZm9yIGxvZ2ljYWwgaW4gdW5pdF9wYXRoczoKICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShsb2dpY2FsLCBzdHIpIG9yIG5vdCBsb2dpY2FsLnN0YXJ0c3dpdGgoIi8iKToKICAgICAgICAgICAgZW1pdF9lcnJvcigic3lzdGVtZDppbnZhbGlkLXBhdGgiKQogICAgICAgIGlmIG5vdCBvcy5wYXRoLmxleGlzdHMobG9naWNhbCk6CiAgICAgICAgICAgIG5bInNlcnZpY2Vfcm9vdHNfYWJzZW50Il0gKz0gMQogICAgICAgICAgICByb290X3NuYXBzaG90cy5zZXRkZWZhdWx0KGxvZ2ljYWwsIChGYWxzZSwgTm9uZSwgTm9uZSwgTm9uZSkpCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgdHJ5OgogICAgICAgICAgICByZXNvbHZlZCA9IG9zLnBhdGgucmVhbHBhdGgobG9naWNhbCkKICAgICAgICAgICAgaWRlbnQgPSBkaXJfaWRlbnRpdHkocmVzb2x2ZWQpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgZW1pdF9lcnJvcigicm9vdDpyZXNvbHZlLWZhaWxlZCIpCiAgICAgICAgblsic2VydmljZV9yb290c19wcmVzZW50Il0gKz0gMQogICAgICAgIHJlbWVtYmVyX3Jvb3Rfc3RhdGUobG9naWNhbCwgcmVzb2x2ZWQpCiAgICAgICAgaWYgaWRlbnQgaW4gc2Vlbl9yb290X2lkczoKICAgICAgICAgICAgblsic2VydmljZV9yb290X2FsaWFzZXMiXSArPSAxCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgc2Vlbl9yb290X2lkcy5hZGQoaWRlbnQpCiAgICAgICAgbmFtZXMgPSBkaXJlY3Rfc2VydmljZV9uYW1lcyhyZXNvbHZlZCkKICAgICAgICBwb3Bfc25hcHNob3RzW3Jlc29sdmVkXSA9IChuYW1lcywgVHJ1ZSkKICAgICAgICBmb3IgbmFtZSBpbiBuYW1lczoKICAgICAgICAgICAgblsic2VydmljZV9lbnRyaWVzIl0gKz0gMQogICAgICAgICAgICBwYXRoID0gb3MucGF0aC5qb2luKHJlc29sdmVkLCBuYW1lKQogICAgICAgICAgICBraW5kLCB0YXJnZXQsIGVudHJ5X3N0YXRlLCB0YXJnZXRfc3RhdGUgPSByZXNvbHZlX2NhbmRpZGF0ZShwYXRoLCBUcnVlKQogICAgICAgICAgICBpZiBraW5kID09ICJtYXNrZWQiOgogICAgICAgICAgICAgICAgblsic2VydmljZV9tYXNrZWQiXSArPSAxCiAgICAgICAgICAgICAgICBlbnRyeV9zbmFwc2hvdHNbcGF0aF0gPSBlbnRyeV9zdGF0ZQogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgY2hlY2tfdGFyZ2V0KHRhcmdldCwgcGF0aCwgZW50cnlfc3RhdGUsIHRhcmdldF9zdGF0ZSwgInNlcnZpY2UiKQoKICAgICMgRW5kLW9mLW9ic2VydmF0aW9uIHN0YWJpbGl0eSwgYXMgaW4gQ0hFQ0s6IGFueSBkcmlmdCBpcyBhIHJlZnVzYWwuCiAgICBpZiB1bml0X3BhdGhzX292ZXJyaWRlIGlzIE5vbmU6CiAgICAgICAgZmluYWxfcGF0aHMsIGZpbmFsX3JhdyA9IHJlYWRfdW5pdF9wYXRocygpCiAgICAgICAgaWYgZmluYWxfcGF0aHMgIT0gaW5pdGlhbF91bml0X3BhdGhzIG9yIGZpbmFsX3JhdyAhPSB1bml0X3BhdGhzX3JhdzoKICAgICAgICAgICAgZW1pdF9lcnJvcigib2JzZXJ2YXRpb246dW5pdC1wYXRocy1jaGFuZ2VkIikKICAgIGZvciBsb2dpY2FsLCBzbmFwIGluIHJvb3Rfc25hcHNob3RzLml0ZW1zKCk6CiAgICAgICAgd2FzX3ByZXNlbnQsIGxvZ2ljYWxfc3RhdGUsIHJlc29sdmVkLCByZXNvbHZlZF9zdGF0ZSA9IHNuYXAKICAgICAgICBpZiBub3Qgd2FzX3ByZXNlbnQ6CiAgICAgICAgICAgIGlmIG9zLnBhdGgubGV4aXN0cyhsb2dpY2FsKToKICAgICAgICAgICAgICAgIGVtaXRfZXJyb3IoIm9ic2VydmF0aW9uOnJvb3QtY2hhbmdlZCIpCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgdHJ5OgogICAgICAgICAgICBpZiBub3Qgb3MucGF0aC5sZXhpc3RzKGxvZ2ljYWwpIG9yIHN0YXRlX2xzdGF0KGxvZ2ljYWwpICE9IGxvZ2ljYWxfc3RhdGUgb3Igb3MucGF0aC5yZWFscGF0aChsb2dpY2FsKSAhPSByZXNvbHZlZCBvciBzdGF0ZV9zdGF0KHJlc29sdmVkKSAhPSByZXNvbHZlZF9zdGF0ZToKICAgICAgICAgICAgICAgIGVtaXRfZXJyb3IoIm9ic2VydmF0aW9uOnJvb3QtY2hhbmdlZCIpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgZW1pdF9lcnJvcigib2JzZXJ2YXRpb246cm9vdC11bnJlYWRhYmxlIikKICAgIGZvciByZXNvbHZlZCwgc25hcCBpbiBwb3Bfc25hcHNob3RzLml0ZW1zKCk6CiAgICAgICAgbmFtZXMsIHNlcnZpY2Vfb25seSA9IHNuYXAKICAgICAgICBjdXJyZW50ID0gZGlyZWN0X3NlcnZpY2VfbmFtZXMocmVzb2x2ZWQpIGlmIHNlcnZpY2Vfb25seSBlbHNlIGRpcmVjdF9uYW1lcyhyZXNvbHZlZCkKICAgICAgICBpZiBjdXJyZW50ICE9IG5hbWVzOgogICAgICAgICAgICBlbWl0X2Vycm9yKCJvYnNlcnZhdGlvbjpwb3B1bGF0aW9uLWNoYW5nZWQiKQogICAgZm9yIHBhdGgsIHNuYXAgaW4gZW50cnlfc25hcHNob3RzLml0ZW1zKCk6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBpZiBzdGF0ZV9sc3RhdChwYXRoKSAhPSBzbmFwOgogICAgICAgICAgICAgICAgZW1pdF9lcnJvcigib2JzZXJ2YXRpb246ZW50cnktY2hhbmdlZCIpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgZW1pdF9lcnJvcigib2JzZXJ2YXRpb246ZW50cnktdW5yZWFkYWJsZSIpCiAgICBmb3IgcGF0aCwgcmVzb2x2ZWQgaW4gcmVzb2x1dGlvbl9zbmFwc2hvdHMuaXRlbXMoKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIGlmIG9zLnBhdGgucmVhbHBhdGgocGF0aCkgIT0gcmVzb2x2ZWQ6CiAgICAgICAgICAgICAgICBlbWl0X2Vycm9yKCJvYnNlcnZhdGlvbjpyZXNvbHV0aW9uLWNoYW5nZWQiKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIGVtaXRfZXJyb3IoIm9ic2VydmF0aW9uOnJlc29sdXRpb24tZmFpbGVkIikKICAgIGZvciBwYXRoLCBzbmFwIGluIHRhcmdldF9zbmFwc2hvdHMuaXRlbXMoKToKICAgICAgICB0cnk6CiAgICAgICAgICAgIGlmIHN0YXRlX3N0YXQocGF0aCkgIT0gc25hcDoKICAgICAgICAgICAgICAgIGVtaXRfZXJyb3IoIm9ic2VydmF0aW9uOnRhcmdldC1jaGFuZ2VkIikKICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICBlbWl0X2Vycm9yKCJvYnNlcnZhdGlvbjp0YXJnZXQtdW5yZWFkYWJsZSIpCiAgICByZXR1cm4gbiwgaXRlbXMKCgpkZWYgX29ic2VydmVfcG9wdWxhdGlvbihyY19yb290cywgdW5pdF9wYXRoc19vdmVycmlkZSwgc3lzdGVtZF9hbmFseXplPVNZU1RFTURfQU5BTFlaRSk6CiAgICB0cnk6CiAgICAgICAgcmV0dXJuICJWQUxVRSIsIF9wb3B1bGF0aW9uKHJjX3Jvb3RzLCB1bml0X3BhdGhzX292ZXJyaWRlLCBzeXN0ZW1kX2FuYWx5emUpCiAgICBleGNlcHQgX09ic2VydmF0aW9uRXJyb3IgYXMgZXhjOgogICAgICAgIHJldHVybiAiRVJST1IiLCBzdHIoZXhjKQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICByZXR1cm4gIkVSUk9SIiwgInJ1bnRpbWU6b2JzZXJ2ZXItZmFpbGVkIgoKCmRlZiBfY3VycmVudF92YWx1ZShjb3VudGVycywgaXRlbXMsIG1hc2spOgogICAgdmlvbGF0aW9ucyA9IHN1bSgxIGZvciBfcGF0aCwgc3RhdGUgaW4gaXRlbXMgaWYgc3RhdGVbNV0gJiBtYXNrKQogICAgcmV0dXJuICgKICAgICAgICAicmNfcm9vdHNfcHJlc2VudD17cmNfcm9vdHNfcHJlc2VudH07cmNfcm9vdHNfYWJzZW50PXtyY19yb290c19hYnNlbnR9O3JjX2VudHJpZXM9e3JjX2VudHJpZXN9OyIKICAgICAgICAicmNfZGlyZWN0b3JpZXM9e3JjX2RpcmVjdG9yaWVzfTtyY190YXJnZXRzPXtyY190YXJnZXRzfTtzZXJ2aWNlX3Jvb3RzX3ByZXNlbnQ9e3NlcnZpY2Vfcm9vdHNfcHJlc2VudH07IgogICAgICAgICJzZXJ2aWNlX3Jvb3RzX2Fic2VudD17c2VydmljZV9yb290c19hYnNlbnR9O3NlcnZpY2Vfcm9vdF9hbGlhc2VzPXtzZXJ2aWNlX3Jvb3RfYWxpYXNlc307IgogICAgICAgICJzZXJ2aWNlX2VudHJpZXM9e3NlcnZpY2VfZW50cmllc307c2VydmljZV9tYXNrZWQ9e3NlcnZpY2VfbWFza2VkfTtzZXJ2aWNlX3RhcmdldHM9e3NlcnZpY2VfdGFyZ2V0c307IgogICAgICAgICJjaGVja2VkPXtjaGVja2VkfTsiLmZvcm1hdCgqKmNvdW50ZXJzKQogICAgICAgICsgInZpb2xhdGlvbnM9JWQiICUgdmlvbGF0aW9ucwogICAgKQoKCmRlZiBvYnNlcnZlKHJjX3Jvb3RzLCB1bml0X3BhdGhzLCBleHBlY3RlZD1FWFBFQ1RFRF9NQVNLKToKICAgICIiIihzdGF0dXMsIHZhbHVlKSDQsiDRhNC+0YDQvNCw0YLQtSBDSEVDSy3QsNC00LDQv9GC0LXRgNCwINC00LvRjyDQtNCw0L3QvdGL0YUg0LrQvtGA0L3QtdC5LiIiIgogICAgbWFzayA9IGludChleHBlY3RlZCwgOCkKICAgIHN0YXR1cywgZGF0YSA9IF9vYnNlcnZlX3BvcHVsYXRpb24obGlzdChyY19yb290cyksIGxpc3QodW5pdF9wYXRocykpCiAgICBpZiBzdGF0dXMgPT0gIkVSUk9SIjoKICAgICAgICByZXR1cm4gIkVSUk9SIiwgZGF0YQogICAgY291bnRlcnMsIGl0ZW1zID0gZGF0YQogICAgcmV0dXJuICJWQUxVRSIsIF9jdXJyZW50X3ZhbHVlKGNvdW50ZXJzLCBpdGVtcywgbWFzaykKCgpkZWYgX2RlZmF1bHRfcHJpdmlsZWdlX2NoZWNrKCkgLT4gYm9vbDoKICAgIHJldHVybiBvcy5nZXRldWlkKCkgPT0gMAoKCmRlZiBfZGVmYXVsdF9mY2htb2QoZmQsIG1vZGUsIHBhdGgpOgogICAgb3MuZmNobW9kKGZkLCBtb2RlKQoKCmRlZiBfcmVzdWx0KGNvbnRyb2xfaWQsIHRhcmdldCwgb3V0Y29tZSwgKiwgYWN0aW9ucywgZHJ5X3J1biwgbXV0YXRpb249RmFsc2UsICoqZXh0cmEpOgogICAgcmVjb3JkID0gewogICAgICAgICJhZGFwdGVyX2lkIjogQURBUFRFUl9JRCwKICAgICAgICAibWVjaGFuaXNtX2lkIjogTUVDSEFOSVNNX0lELAogICAgICAgICJjb250cm9sX2lkIjogY29udHJvbF9pZCwKICAgICAgICAidGFyZ2V0IjogdGFyZ2V0LAogICAgICAgICJvdXRjb21lIjogb3V0Y29tZSwKICAgICAgICAicmVhc29uIjogTm9uZSwKICAgICAgICAiY3VycmVudF9tb2RlIjogTm9uZSwKICAgICAgICAidmlvbGF0b3JzIjogW10sCiAgICAgICAgImFwcGxpZWQiOiBbXSwKICAgICAgICAic2tpcHBlZCI6IFtdLAogICAgICAgICJmYWlsZWQiOiBbXSwKICAgICAgICAiYWN0aW9uc19hdHRlbXB0ZWQiOiBsaXN0KGFjdGlvbnMpLAogICAgICAgICJtdXRhdGlvbl9wZXJmb3JtZWQiOiBib29sKG11dGF0aW9uKSwKICAgICAgICAidHJhbnNhY3Rpb25fY29tbWl0IjogX2NvbW1pdF9zdGF0ZShvdXRjb21lLCBkcnlfcnVuLCBtdXRhdGlvbiksCiAgICAgICAgImRyeV9ydW4iOiBib29sKGRyeV9ydW4pLAogICAgfQogICAgcmVjb3JkLnVwZGF0ZShleHRyYSkKICAgIGlmIHJlY29yZFsib3V0Y29tZSJdIG5vdCBpbiBPVVRDT01FUzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJvdXRjb21lIG91dHNpZGUgY2xvc2VkIHZvY2FidWxhcnkiKQogICAgcmV0dXJuIHJlY29yZAoKCmRlZiBfY29tbWl0X3N0YXRlKG91dGNvbWUsIGRyeV9ydW4sIG11dGF0aW9uKToKICAgICIiItCi0LUg0LbQtSDQt9C90LDRh9C10L3QuNGPLCDRh9GC0L4g0YMgc3RhbmRhcmQtc3lzdGVtLXBhdGhzLW1vZGUuIiIiCiAgICBpZiBvdXRjb21lID09ICJBUFBMSUVEIiBvciAob3V0Y29tZSA9PSAiQUxSRUFEWV9DT01QTElBTlQiIGFuZCBub3QgZHJ5X3J1bik6CiAgICAgICAgcmV0dXJuIENPTU1JVF9DT01NSVRURUQKICAgIGlmIG11dGF0aW9uOgogICAgICAgIHJldHVybiBDT01NSVRfTk9UX0NPTU1JVFRFRAogICAgcmV0dXJuIENPTU1JVF9OT1RfU1RBUlRFRAoKCmRlZiBvdXRjb21lX3JjX2NvbnRyaWJ1dGlvbihvdXRjb21lLCBkcnlfcnVuPUZhbHNlKToKICAgICIiIiIwIiDQtNC70Y8g0YPRgdC/0LXRiNC90YvRhSDQuNGB0YXQvtC00L7Qsiwg0LjQvdCw0YfQtSAibm9uemVybyI7IEFQUExJRURfUEFSVElBTCDigJQgbm9uemVyby4iIiIKICAgIGlmIG91dGNvbWUgaW4gKCJBUFBMSUVEIiwgIkFMUkVBRFlfQ09NUExJQU5UIiwgIk5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRCIpOgogICAgICAgIHJldHVybiAiMCIKICAgIGlmIGRyeV9ydW4gYW5kIG91dGNvbWUgPT0gIkRSWV9SVU5fV09VTERfQVBQTFkiOgogICAgICAgIHJldHVybiAiMCIKICAgIHJldHVybiAibm9uemVybyIKCgpkZWYgX2FwcGx5X29uZShwYXRoLCBvYnNlcnZlZCwgbWFzaywgZmNobW9kKToKICAgICIiItCh0L3Rj9GC0Ywg0LHQuNGC0YsgbWFzayDRgyDQvtC00L3QvtCz0L4g0L7QsdGK0LXQutGC0LAuCgogICAg0JLQvtC30LLRgNCw0YnQsNC10YIgKG11dGF0ZWQsIGtpbmQsIHJlYXNvbik6IGtpbmQg4oCUICJvayIsICJza2lwIiDQuNC70LggImZhaWwiLgogICAg0KDQtdCy0LDQu9C40LTQsNGG0LjRjyDQvdCwINC00LXRgdC60YDQuNC/0YLQvtGA0LUg0YHRgtGA0L7Qs9C+INCyINC/0L7RgNGP0LTQutC1IFNfSVNSRUcgLT4gZGV2L2lubyAtPiDQsdC40YLRiyBtYXNrLgogICAgIiIiCiAgICB0cnk6CiAgICAgICAgZmQgPSBvcy5vcGVuKHBhdGgsIG9zLk9fUkRPTkxZIHwgb3MuT19OT0ZPTExPVyB8IG9zLk9fQ0xPRVhFQykKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICBpZiBleGMuZXJybm8gPT0gZXJybm8uRUxPT1A6CiAgICAgICAgICAgIHJldHVybiBGYWxzZSwgInNraXAiLCAibm90LXJlZ3VsYXIiCiAgICAgICAgcmV0dXJuIEZhbHNlLCAiZmFpbCIsICJvcGVuOiVzIiAlIGVycm5vLmVycm9yY29kZS5nZXQoZXhjLmVycm5vLCBleGMuZXJybm8pCiAgICB0cnk6CiAgICAgICAgbm93ID0gb3MuZnN0YXQoZmQpCiAgICAgICAgaWYgbm90IHN0YXQuU19JU1JFRyhub3cuc3RfbW9kZSk6CiAgICAgICAgICAgIHJldHVybiBGYWxzZSwgInNraXAiLCAibm90LXJlZ3VsYXIiCiAgICAgICAgaWYgKG5vdy5zdF9kZXYsIG5vdy5zdF9pbm8pICE9IChvYnNlcnZlZFswXSwgb2JzZXJ2ZWRbMV0pOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgImlkZW50aXR5LWRyaWZ0IgogICAgICAgIGN1cnJlbnQgPSBzdGF0LlNfSU1PREUobm93LnN0X21vZGUpCiAgICAgICAgaWYgbm90IGN1cnJlbnQgJiBtYXNrOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgIm5vLXZpb2xhdGlvbi1iaXRzIgogICAgICAgIGlmIG5vdy5zdF9ubGluayAhPSAxOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgInN0X25saW5rIgogICAgICAgIHBsYW5uZWQgPSBjdXJyZW50ICYgfm1hc2sKICAgICAgICBmY2htb2QoZmQsIHBsYW5uZWQsIHBhdGgpCiAgICAgICAgcG9zdCA9IG9zLmZzdGF0KGZkKQogICAgICAgIGlmICgKICAgICAgICAgICAgc3RhdC5TX0lNT0RFKHBvc3Quc3RfbW9kZSkgIT0gcGxhbm5lZAogICAgICAgICAgICBvciAocG9zdC5zdF91aWQsIHBvc3Quc3RfZ2lkKSAhPSAobm93LnN0X3VpZCwgbm93LnN0X2dpZCkKICAgICAgICAgICAgb3IgKHBvc3Quc3RfZGV2LCBwb3N0LnN0X2lubykgIT0gKG5vdy5zdF9kZXYsIG5vdy5zdF9pbm8pCiAgICAgICAgICAgIG9yIHBvc3Quc3Rfc2l6ZSAhPSBub3cuc3Rfc2l6ZQogICAgICAgICk6CiAgICAgICAgICAgIHJldHVybiBUcnVlLCAiZmFpbCIsICJwb3N0LXN0YXRlLW1pc21hdGNoIgogICAgICAgIHJldHVybiBUcnVlLCAib2siLCBOb25lCiAgICBmaW5hbGx5OgogICAgICAgIG9zLmNsb3NlKGZkKQoKCmRlZiBleGVjdXRlX2NvbnRyb2woCiAgICBjb250cm9sX2lkLAogICAga2V5LAogICAgb3AsCiAgICBleHBlY3RlZCwKICAgIGFwcGx5X3N1cHBvcnRlZCwKICAgICosCiAgICB0YXJnZXQ9Tm9uZSwKICAgIGRyeV9ydW4sCiAgICBwcml2aWxlZ2VfY2hlY2s9Tm9uZSwKICAgIF9mY2htb2Q9Tm9uZSwKICAgIF9sYXlvdXQ9Tm9uZSwKKToKICAgICIiIkFwcGx5IHRoZSAyLjMuNSBzdGFydHVwIGZpbGVzIGNvbnRyb2wuIE5ldmVyIGZvbGxvd3MgYSBzeW1saW5rIGF0IHdyaXRlLCBuZXZlciByZWxheGVzLgoKICAgIGBfbGF5b3V0YCDigJQgKHJjX3Jvb3RzLCB1bml0X3BhdGhzKSDRgtC+0LvRjNC60L4g0LTQu9GPINGC0LXRgdGC0L7Qsiwg0LrQsNC6CiAgICBgX3NoZWxsX2Z1bmN0aW9uX2Zvcl9sYXlvdXRgINGDIENIRUNLLdCw0LTQsNC/0YLQtdGA0LAuCiAgICAiIiIKICAgIHZhbGlkYXRlX2NvbnRyb2xfaW5wdXQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIGFwcGx5X3N1cHBvcnRlZCkKICAgIGFjdGlvbnMgPSBbIlAwX0VMSUdJQklMSVRZIl0KCiAgICBkZWYgZG9uZShvdXRjb21lLCAqKmV4dHJhKToKICAgICAgICByZXR1cm4gX3Jlc3VsdChjb250cm9sX2lkLCB0YXJnZXQsIG91dGNvbWUsIGFjdGlvbnM9YWN0aW9ucywgZHJ5X3J1bj1kcnlfcnVuLCAqKmV4dHJhKQoKICAgIGlmIG5vdCBhcHBseV9zdXBwb3J0ZWQ6CiAgICAgICAgcmV0dXJuIGRvbmUoIk5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRCIsIHJlYXNvbj0iYXBwbHktdW5zdXBwb3J0ZWQiKQogICAgaWYgbm90IF9pc19lbGlnaWJsZV9jb250cmFjdChrZXksIG9wLCBleHBlY3RlZCk6CiAgICAgICAgcmV0dXJuIGRvbmUoIk5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRCIsIHJlYXNvbj0ib3AtdW5zdXBwb3J0ZWQiKQoKICAgIGlmIHRhcmdldCBpcyBOb25lOgogICAgICAgIHRhcmdldCA9IFRBUkdFVFMuZ2V0KGNvbnRyb2xfaWQpCiAgICAgICAgaWYgdGFyZ2V0IGlzIE5vbmU6CiAgICAgICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsIHJlYXNvbj0idGFyZ2V0OnVubWFwcGVkLWNvbnRyb2wiKQoKICAgIG1hc2sgPSBpbnQoZXhwZWN0ZWQsIDgpCiAgICBhY3Rpb25zLmFwcGVuZCgiUDFfUE9QVUxBVElPTiIpCiAgICB0cnk6CiAgICAgICAgcmNfcm9vdHMgPSBjYW5vbmljYWxfcmNfcm9vdHModGFyZ2V0KQogICAgZXhjZXB0IFZhbHVlRXJyb3IgYXMgZXhjOgogICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIsIHJlYXNvbj1zdHIoZXhjKSkKICAgIHVuaXRfcGF0aHMgPSBOb25lCiAgICBpZiBfbGF5b3V0IGlzIG5vdCBOb25lOgogICAgICAgIHJjX3Jvb3RzLCB1bml0X3BhdGhzID0gbGlzdChfbGF5b3V0WzBdKSwgbGlzdChfbGF5b3V0WzFdKQogICAgc3RhdHVzLCBkYXRhID0gX29ic2VydmVfcG9wdWxhdGlvbihsaXN0KHJjX3Jvb3RzKSwgdW5pdF9wYXRocykKICAgIGlmIHN0YXR1cyA9PSAiRVJST1IiOgogICAgICAgIG91dGNvbWUgPSAiQUJPUlRFRF9QUkVDT05ESVRJT05fQ09ORkxJQ1QiIGlmIGRhdGEgaW4gQ09ORkxJQ1RfUkVBU09OUyBlbHNlICJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIKICAgICAgICByZXR1cm4gZG9uZShvdXRjb21lLCByZWFzb249ZGF0YSkKICAgIGNvdW50ZXJzLCBpdGVtcyA9IGRhdGEKCiAgICBhY3Rpb25zLmFwcGVuZCgiUDJfUExBTiIpCiAgICBjdXJyZW50ID0gX2N1cnJlbnRfdmFsdWUoY291bnRlcnMsIGl0ZW1zLCBtYXNrKQogICAgdmlvbGF0b3JzID0gc29ydGVkKAogICAgICAgICgocGF0aCwgc3RhdGUpIGZvciBwYXRoLCBzdGF0ZSBpbiBpdGVtcyBpZiBzdGF0ZVs1XSAmIG1hc2spLAogICAgICAgIGtleT1sYW1iZGEgcGFpcjogb3MuZnNlbmNvZGUocGFpclswXSksCiAgICApCiAgICBpZiBub3QgdmlvbGF0b3JzOgogICAgICAgIHJldHVybiBkb25lKCJBTFJFQURZX0NPTVBMSUFOVCIsIGN1cnJlbnRfbW9kZT1jdXJyZW50KQogICAgc2tpcHBlZCA9IFtdCiAgICBwbGFubmVkID0gW10KICAgIGZvciBwYXRoLCBzdGF0ZSBpbiB2aW9sYXRvcnM6CiAgICAgICAgaWYgc3RhdGVbOV0gIT0gMToKICAgICAgICAgICAgc2tpcHBlZC5hcHBlbmQoeyJwYXRoIjogcGF0aCwgInJlYXNvbiI6ICJzdF9ubGluayJ9KQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIHBsYW5uZWQuYXBwZW5kKChwYXRoLCBzdGF0ZSkpCiAgICB2aW9sYXRvcl9wYXRocyA9IFtwYXRoIGZvciBwYXRoLCBfc3RhdGUgaW4gdmlvbGF0b3JzXQogICAgaWYgbm90IHBsYW5uZWQ6CiAgICAgICAgcmVhc29ucyA9IHtpdGVtWyJyZWFzb24iXSBmb3IgaXRlbSBpbiBza2lwcGVkfQogICAgICAgIHJlYXNvbiA9IHNraXBwZWRbMF1bInJlYXNvbiJdIGlmIGxlbihyZWFzb25zKSA9PSAxIGVsc2UgIm5vLW11dGFibGUtb2JqZWN0IgogICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsIHJlYXNvbj1yZWFzb24sIGN1cnJlbnRfbW9kZT1jdXJyZW50LAogICAgICAgICAgICAgICAgICAgIHZpb2xhdG9ycz12aW9sYXRvcl9wYXRocywgc2tpcHBlZD1za2lwcGVkKQogICAgaWYgZHJ5X3J1bjoKICAgICAgICByZXR1cm4gZG9uZSgiRFJZX1JVTl9XT1VMRF9BUFBMWSIsIGN1cnJlbnRfbW9kZT1jdXJyZW50LAogICAgICAgICAgICAgICAgICAgIHZpb2xhdG9ycz12aW9sYXRvcl9wYXRocywgc2tpcHBlZD1za2lwcGVkKQoKICAgIGFjdGlvbnMuYXBwZW5kKCJQM19QUklWSUxFR0UiKQogICAgY2hlY2sgPSBwcml2aWxlZ2VfY2hlY2sgaWYgcHJpdmlsZWdlX2NoZWNrIGlzIG5vdCBOb25lIGVsc2UgX2RlZmF1bHRfcHJpdmlsZWdlX2NoZWNrCiAgICBpZiBub3QgY2hlY2soKToKICAgICAgICByZXR1cm4gZG9uZSgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLCByZWFzb249InByaXZpbGVnZSIsIGN1cnJlbnRfbW9kZT1jdXJyZW50LAogICAgICAgICAgICAgICAgICAgIHZpb2xhdG9ycz12aW9sYXRvcl9wYXRocywgc2tpcHBlZD1za2lwcGVkKQoKICAgIGFjdGlvbnMuYXBwZW5kKCJQSEFTRTFfTU9ERSIpCiAgICBmY2htb2QgPSBfZmNobW9kIGlmIF9mY2htb2QgaXMgbm90IE5vbmUgZWxzZSBfZGVmYXVsdF9mY2htb2QKICAgIGFwcGxpZWQsIGZhaWxlZCA9IFtdLCBbXQogICAgbXV0YXRlZCA9IEZhbHNlCiAgICBmb3IgcGF0aCwgc3RhdGUgaW4gcGxhbm5lZDoKICAgICAgICB0cnk6CiAgICAgICAgICAgIGNoYW5nZWQsIGtpbmQsIHJlYXNvbiA9IF9hcHBseV9vbmUocGF0aCwgc3RhdGUsIG1hc2ssIGZjaG1vZCkKICAgICAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgICAgIGlmIGV4Yy5lcnJubyA9PSBlcnJuby5FUk9GUzoKICAgICAgICAgICAgICAgIG91dGNvbWUgPSAiQVBQTElFRF9QQVJUSUFMIiBpZiBtdXRhdGVkIGVsc2UgIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIgogICAgICAgICAgICAgICAgcmV0dXJuIGRvbmUob3V0Y29tZSwgcmVhc29uPSJlcm9mcyIsIG11dGF0aW9uPW11dGF0ZWQsIGN1cnJlbnRfbW9kZT1jdXJyZW50LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgdmlvbGF0b3JzPXZpb2xhdG9yX3BhdGhzLCBhcHBsaWVkPWFwcGxpZWQsIHNraXBwZWQ9c2tpcHBlZCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGZhaWxlZD1mYWlsZWQgKyBbeyJwYXRoIjogcGF0aCwgInJlYXNvbiI6ICJlcm9mcyJ9XSkKICAgICAgICAgICAgY2hhbmdlZCwga2luZCwgcmVhc29uID0gRmFsc2UsICJmYWlsIiwgImZjaG1vZDolcyIgJSBlcnJuby5lcnJvcmNvZGUuZ2V0KGV4Yy5lcnJubywgZXhjLmVycm5vKQogICAgICAgIG11dGF0ZWQgPSBtdXRhdGVkIG9yIGNoYW5nZWQKICAgICAgICBpZiBraW5kID09ICJvayI6CiAgICAgICAgICAgIGFwcGxpZWQuYXBwZW5kKHBhdGgpCiAgICAgICAgZWxpZiBraW5kID09ICJza2lwIjoKICAgICAgICAgICAgc2tpcHBlZC5hcHBlbmQoeyJwYXRoIjogcGF0aCwgInJlYXNvbiI6IHJlYXNvbn0pCiAgICAgICAgZWxzZToKICAgICAgICAgICAgZmFpbGVkLmFwcGVuZCh7InBhdGgiOiBwYXRoLCAicmVhc29uIjogcmVhc29ufSkKCiAgICBhY3Rpb25zLmFwcGVuZCgiRklOQUxfUE9TVENIRUNLIikKICAgIGV4dHJhID0gZGljdChjdXJyZW50X21vZGU9Y3VycmVudCwgdmlvbGF0b3JzPXZpb2xhdG9yX3BhdGhzLCBhcHBsaWVkPWFwcGxpZWQsCiAgICAgICAgICAgICAgICAgc2tpcHBlZD1za2lwcGVkLCBmYWlsZWQ9ZmFpbGVkKQogICAgaWYgbm90IGZhaWxlZCBhbmQgbm90IHNraXBwZWQ6CiAgICAgICAgcmV0dXJuIGRvbmUoIkFQUExJRUQiLCBtdXRhdGlvbj1tdXRhdGVkLCAqKmV4dHJhKQogICAgaWYgYXBwbGllZDoKICAgICAgICByZXR1cm4gZG9uZSgiQVBQTElFRF9QQVJUSUFMIiwgcmVhc29uPSJwYXJ0aWFsIiwgbXV0YXRpb249bXV0YXRlZCwgKipleHRyYSkKICAgIHJldHVybiBkb25lKCJGQUlMRURfTk9UX0NPTU1JVFRFRCIsIHJlYXNvbj0ibm8tb2JqZWN0LWFwcGxpZWQiLCBtdXRhdGlvbj1tdXRhdGVkLCAqKmV4dHJhKQoKCmRlZiBjb250cm9sX3Jlc3VsdF90b19yZXBvcnQocmVzdWx0LCBzdGFydGVkX2F0LCBmaW5pc2hlZF9hdCk6CiAgICByZXR1cm4gewogICAgICAgICJhZGFwdGVyX2lkIjogcmVzdWx0WyJhZGFwdGVyX2lkIl0sCiAgICAgICAgIm1lY2hhbmlzbV9pZCI6IHJlc3VsdFsibWVjaGFuaXNtX2lkIl0sCiAgICAgICAgImNvbnRyb2xfaWQiOiByZXN1bHRbImNvbnRyb2xfaWQiXSwKICAgICAgICAidGFyZ2V0IjogcmVzdWx0WyJ0YXJnZXQiXSwKICAgICAgICAib3V0Y29tZSI6IHJlc3VsdFsib3V0Y29tZSJdLAogICAgICAgICJyZWFzb24iOiByZXN1bHRbInJlYXNvbiJdLAogICAgICAgICJjdXJyZW50X21vZGUiOiByZXN1bHRbImN1cnJlbnRfbW9kZSJdLAogICAgICAgICJ2aW9sYXRvcnMiOiBsaXN0KHJlc3VsdFsidmlvbGF0b3JzIl0pLAogICAgICAgICJhcHBsaWVkIjogbGlzdChyZXN1bHRbImFwcGxpZWQiXSksCiAgICAgICAgInNraXBwZWQiOiBbZGljdChpdGVtKSBmb3IgaXRlbSBpbiByZXN1bHRbInNraXBwZWQiXV0sCiAgICAgICAgImZhaWxlZCI6IFtkaWN0KGl0ZW0pIGZvciBpdGVtIGluIHJlc3VsdFsiZmFpbGVkIl1dLAogICAgICAgICJzdGFydGVkX2F0Ijogc3RhcnRlZF9hdCwKICAgICAgICAiZmluaXNoZWRfYXQiOiBmaW5pc2hlZF9hdCwKICAgICAgICAiYWN0aW9uc19hdHRlbXB0ZWQiOiBsaXN0KHJlc3VsdFsiYWN0aW9uc19hdHRlbXB0ZWQiXSksCiAgICAgICAgInN0ZXBfcmMiOiBvdXRjb21lX3JjX2NvbnRyaWJ1dGlvbihyZXN1bHRbIm91dGNvbWUiXSwgcmVzdWx0WyJkcnlfcnVuIl0pLAogICAgICAgICJtdXRhdGlvbl9wZXJmb3JtZWQiOiByZXN1bHRbIm11dGF0aW9uX3BlcmZvcm1lZCJdLAogICAgICAgICJ0cmFuc2FjdGlvbl9jb21taXQiOiByZXN1bHRbInRyYW5zYWN0aW9uX2NvbW1pdCJdLAogICAgfQo="},"suid-sgid-applications":{"adapter_id":"product-suid-sgid-applications-mode-apply-v1","apply_kind":"suid-sgid-applications-mode-v1","implementation_sha256":"797e283275a37f9a1a6c07821c290e9ada4fae88498086242e92c63663b5c530","mechanism_id":"suid-sgid-applications-mode-v1","source_b64":"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiJwcm9kdWN0LXN1aWQtc2dpZC1hcHBsaWNhdGlvbnMtbW9kZS1hcHBseS12MS4KCkFQUExZIGFkYXB0ZXIgZm9yIG1lY2hhbmlzbSBgc3VpZC1zZ2lkLWFwcGxpY2F0aW9ucy1tb2RlLXYxYCAoMi4zLjkgU1VJRC9TR0lEIG1vZGUpLgoKUFVSUE9TRT1ERUZFTlNJVkVfQ09NUExJQU5DRV9WQUxJREFUSU9OCkF1dGhvcml0eTogcHJvZHVjdC9jb250cmFjdHMvbWVjaGFuaXNtLXN1aWQtc2dpZC1hcHBsaWNhdGlvbnMtbW9kZS12MS5qc29uCgrQnNC10YXQsNC90LjQt9C8INC+0LHRgdC70YPQttC40LLQsNC10YIgcGFyYW1ldGVyX2tpbmQgYHN1aWQtc2dpZC1hcHBsaWNhdGlvbnNgLCDQtdC00LjQvdGB0YLQstC10L3QvdGL0Lkg0LrQvtC90YLRgNC+0LvRjArQutC+0YLQvtGA0L7Qs9C+IOKAlCBgRlNURUMtTElOVVgtMjAyMi0yLjMuOS1TVUlELVNHSUQtTU9ERWAgKGBtb2RlYCAvIGBiaXRzLWNsZWFyYCAvIGAwMDIyYCk7CtC70Y7QsdCw0Y8g0LjQvdCw0Y8g0YLRgNC+0LnQutCwIChrZXksIG9wLCBleHBlY3RlZCkg0LTQsNGR0YIgYE5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRGAuCgpQb3B1bGF0aW9uIGlzIHRoZSBvbmUgb2YgQ0hFQ0sgYWRhcHRlciBwcm9kdWN0LXN1aWQtc2dpZC1hcHBsaWNhdGlvbnMtY2hlY2stdjI6CmBmaW5kIC1QIDxtb3VudHBvaW50PiAteGRldiAtdHlwZSBmIC1wZXJtIC82MDAwYCDQv9C+INCy0YHQtdC8INC90LXQv9GB0LXQstC00L4t0YLQvtGH0LrQsNC8CtC80L7QvdGC0LjRgNC+0LLQsNC90LjRjyDQuNC3IG1vdW50aW5mbywg0YEg0LTQtdC00YPQv9C70LjQutCw0YbQuNC10Lkg0YLQvtGH0LXQuiDQuCDRhNCw0LnQu9C+0LIg0L/QviBgZGV2Omlub2AuCtCf0LXRgNC10YfQuNGB0LvQuNGC0LXQu9GMINC90LjQttC1IOKAlCBQeXRob24t0LrQvtC/0LjRjyDRgtC+0LPQviBzaGVsbC3QvdCw0LHQu9GO0LTQsNGC0LXQu9GPOyDQv9Cw0YDQuNGC0LXRgiDQv9GA0L7QstC10YDRj9C10YLRgdGPCnRlc3RzL3Byb2R1Y3QtdjEvdGVzdF9zdWlkX3NnaWRfYXBwbGljYXRpb25zX21vZGVfYXBwbHlfYWRhcHRlci5weS4KClRoZSBwbGFuIGlzIGJ1aWx0IGJlZm9yZSBhbnkgbXV0YXRpb24uIEEgdmlvbGF0b3Igd2l0aCBzdF9ubGluayA+IDEgaXMgc2tpcHBlZAphbmQgcmVjb3JkZWQuINCf0LXRgNC10LQg0LzRg9GC0LDRhtC40LXQuSDQvtCx0YrQtdC60YIg0YDQtdCy0LDQu9C40LTQuNGA0YPQtdGC0YHRjyDQvdCwINGD0LbQtSDQvtGC0LrRgNGL0YLQvtC8INC00LXRgdC60YDQuNC/0YLQvtGA0LUK0YHRgtGA0L7Qs9C+INCyINC/0L7RgNGP0LTQutC1IGBTX0lTUkVHYCDihpIgYGRldi9pbm9gINC40Lcg0L/Qu9Cw0L3QsCDihpIg0L3QsNC70LjRh9C40LUg0LHQuNGC0L7QsiBgMDYwMDBgOwrQvdC10YHQvtCy0L/QsNC00LXQvdC40LUg0LvRjtCx0L7Qs9C+INGI0LDQs9CwIOKAlCDQv9GA0L7Qv9GD0YHQuiDQvtCx0YrQtdC60YLQsCDRgSDQv9GA0LjRh9C40L3QvtC5LiBFYWNoIG11dGF0aW9uIGlzIG9uZQpgZmNobW9kYCBvbiBhIGRlc2NyaXB0b3Igb3BlbmVkIHdpdGggT19OT0ZPTExPVyBhbmQgb25seSBjbGVhcnMgYml0czsgdGhlcmUgaXMKbm8gY29tcGVuc2F0aW9uLiBBbiBlcnJvciBvbiBvbmUgb2JqZWN0IGRvZXMgbm90IHN0b3AgdGhlIG90aGVycwooQVBQTElFRF9QQVJUSUFMKTsgRVJPRlMgc3RvcHMgaW1tZWRpYXRlbHkuCiIiIgoKZnJvbSBfX2Z1dHVyZV9fIGltcG9ydCBhbm5vdGF0aW9ucwoKaW1wb3J0IGVycm5vCmltcG9ydCBvcwppbXBvcnQgcmUKaW1wb3J0IHN0YXQKCkFEQVBURVJfSUQgPSAicHJvZHVjdC1zdWlkLXNnaWQtYXBwbGljYXRpb25zLW1vZGUtYXBwbHktdjEiCk1FQ0hBTklTTV9JRCA9ICJzdWlkLXNnaWQtYXBwbGljYXRpb25zLW1vZGUtdjEiClRBUkdFVF9JRCA9ICJsaW51eC14ODZfNjQtc3VwcG9ydGVkLXYxIgpQQVJBTUVURVJfS0lORCA9ICJzdWlkLXNnaWQtYXBwbGljYXRpb25zIgpTRU1BTlRJQ19DT05UUkFDVF9JRCA9ICJzdWlkLXNnaWQtYXBwbGljYXRpb25zLW1vZGUtYXBwbHktc2VtYW50aWMtdjEiCgpTVVBQT1JURURfS0VZUyA9ICgibW9kZSIsKQpTVVBQT1JURURfT1BTID0gKCJiaXRzLWNsZWFyIiwpCkVYUEVDVEVEX01BU0sgPSAiMDAyMiIKCiMg0JHQuNGC0YssINC/0L4g0LrQvtGC0L7RgNGL0LwgQ0hFQ0sg0L7RgtCx0LjRgNCw0LXRgiDQv9C+0L/Rg9C70Y/RhtC40Y4gKFNVSUQvU0dJRCkuClNFTEVDVF9CSVRTID0gMG82MDAwCgpDQU5PTklDQUxfTE9DQVRPUiA9ICIvcHJvYy9zZWxmL21vdW50aW5mbyIKCiMg0J/RgdC10LLQtNC+0YTQsNC50LvQvtCy0YvQtSDRgdC40YHRgtC10LzRiyBDSEVDSy3QsNC00LDQv9GC0LXRgNCwIHByb2R1Y3Qtc3VpZC1zZ2lkLWFwcGxpY2F0aW9ucy1jaGVjay12Mi4KUFNFVURPX0ZTID0gKAogICAgInByb2MiLCAic3lzZnMiLCAiZGV2dG1wZnMiLCAiZGV2cHRzIiwgImNncm91cCIsICJjZ3JvdXAyIiwKICAgICJzZWN1cml0eWZzIiwgInBzdG9yZSIsICJicGYiLCAidHJhY2VmcyIsICJkZWJ1Z2ZzIiwgImNvbmZpZ2ZzIiwKICAgICJmdXNlY3RsIiwgIm1xdWV1ZSIsICJodWdldGxiZnMiLCAicmFtZnMiLCAiYXV0b2ZzIiwKICAgICJiaW5mbXRfbWlzYyIsICJuc2ZzIiwgImVmaXZhcmZzIiwKKQoKT1VUQ09NRVMgPSAoCiAgICAiQVBQTElFRCIsCiAgICAiQVBQTElFRF9QQVJUSUFMIiwKICAgICJBTFJFQURZX0NPTVBMSUFOVCIsCiAgICAiRFJZX1JVTl9XT1VMRF9BUFBMWSIsCiAgICAiTk9UX0VMSUdJQkxFX0FQUExZX1VOU1VQUE9SVEVEIiwKICAgICJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsCiAgICAiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLAogICAgIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwKKQoKQ09NTUlUX0NPTU1JVFRFRCA9ICJDT01NSVRURUQiCkNPTU1JVF9OT1RfQ09NTUlUVEVEID0gIk5PVF9DT01NSVRURUQiCkNPTU1JVF9OT1RfU1RBUlRFRCA9ICJOT1RfU1RBUlRFRCIKCiMg0JvQvtC60LDRgtC+0YAg0LXQtNC40L3RgdGC0LLQtdC90L3QvtCz0L4g0LrQvtC90YLRgNC+0LvRjyDQvNC10YXQsNC90LjQt9C80LAuINCh0L7QstC/0LDQtNC10L3QuNC1INGBIHBhcmFtZXRlci5sb2NhdG9yCiMg0L/RgNC+0LLQtdGA0Y/QtdGCIHRlc3Rfc3VpZF9zZ2lkX2FwcGxpY2F0aW9uc19tb2RlX2FwcGx5X2FkYXB0ZXIucHkuClRBUkdFVFMgPSB7CiAgICAiRlNURUMtTElOVVgtMjAyMi0yLjMuOS1TVUlELVNHSUQtTU9ERSI6IENBTk9OSUNBTF9MT0NBVE9SLAp9CgpDT05UUk9MX0lEX1BBVFRFUk4gPSByIl4oPyEuKltcclxuXSlbQS1aYS16MC05Ll8tXSskIgoKIyDQn9GA0LjRh9C40L3RiyBDSEVDSywg0LrQvtGC0L7RgNGL0LUg0L7Qt9C90LDRh9Cw0Y7Rgiwg0YfRgtC+INGB0LDQvCDQu9C+0LrQsNGC0L7RgCDigJQg0L7QsdGK0LXQutGCINC90LUg0YLQvtCz0L4g0YLQuNC/0LAuCkNPTkZMSUNUX1JFQVNPTlMgPSAoIm1vdW50aW5mbzpzeW1saW5rIiwgIm1vdW50aW5mbzppbnZhbGlkLXR5cGUiKQoKX09DVEFMX0VTQ0FQRSA9IHJlLmNvbXBpbGUociJcXDA/KFswLTddezEsM30pIikKX0ZPUkJJRERFTl9QQVRIX0NIQVJTID0gKCJcciIsICJcbiIsICJcdCIpCgoKZGVmIHZhbGlkYXRlX2NvbnRyb2xfaW5wdXQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIGFwcGx5X3N1cHBvcnRlZCk6CiAgICAiIiJGYWlsLWNsb3NlZCB2YWxpZGF0aW9uIG9mIG9uZSBjb250cm9sIHJvdy4gUmFpc2VzIFZhbHVlRXJyb3IuIiIiCiAgICBpZiBub3QgaXNpbnN0YW5jZShjb250cm9sX2lkLCBzdHIpIG9yIG5vdCByZS5mdWxsbWF0Y2goQ09OVFJPTF9JRF9QQVRURVJOLCBjb250cm9sX2lkKToKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJpbnZhbGlkIGNvbnRyb2wgaWQiKQogICAgaWYgbm90IGlzaW5zdGFuY2Uoa2V5LCBzdHIpIG9yIG5vdCBpc2luc3RhbmNlKG9wLCBzdHIpIG9yIG5vdCBpc2luc3RhbmNlKGV4cGVjdGVkLCBzdHIpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImtleSwgb3AgYW5kIGV4cGVjdGVkIG11c3QgYmUgc3RyaW5ncyIpCiAgICBpZiBub3QgaXNpbnN0YW5jZShhcHBseV9zdXBwb3J0ZWQsIGJvb2wpOgogICAgICAgIHJhaXNlIFZhbHVlRXJyb3IoImFwcGx5X3N1cHBvcnRlZCBtdXN0IGJlIGJvb2wiKQogICAgcmV0dXJuIFRydWUKCgpkZWYgX2lzX2VsaWdpYmxlX2NvbnRyYWN0KGtleSwgb3AsIGV4cGVjdGVkKToKICAgICIiItCi0L7Qu9GM0LrQviAobW9kZSwgYml0cy1jbGVhciwgMDAyMik7INCy0YHRkSDQv9GA0L7Rh9C10LUg0YDQtdGI0LDQtdGCINCw0LTQvNC40L3QuNGB0YLRgNCw0YLQvtGALiIiIgogICAgcmV0dXJuIGtleSBpbiBTVVBQT1JURURfS0VZUyBhbmQgb3AgaW4gU1VQUE9SVEVEX09QUyBhbmQgZXhwZWN0ZWQgPT0gRVhQRUNURURfTUFTSwoKCmRlZiBfdW5lc2NhcGVfbW91bnRwb2ludChyYXcpOgogICAgIiIi0JDQvdCw0LvQvtCzIGBwcmludGYgLXYgbXAgIiViImAg0LTQu9GPINC/0L7Qu9GPIG1vdW50IHBvaW50IChcXDA0MCwgXFwwMTEsIFxcMTM0KS4iIiIKICAgIHJldHVybiBfT0NUQUxfRVNDQVBFLnN1YihsYW1iZGEgbTogY2hyKGludChtLmdyb3VwKDEpLCA4KSAmIDB4RkYpLCByYXcpCgoKZGVmIF9zY2FuX21vdW50KG1vdW50cG9pbnQsIGZvdW5kKToKICAgICIiImZpbmQgLVAgPG1vdW50cG9pbnQ+IC14ZGV2IC10eXBlIGYgLXBlcm0gLzYwMDAuINCS0L7Qt9Cy0YDQsNGJ0LDQtdGCIHJlYXNvbiB8IE5vbmUuIiIiCiAgICB0cnk6CiAgICAgICAgcm9vdF9kZXYgPSBvcy5zdGF0KG1vdW50cG9pbnQpLnN0X2RldgogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcmV0dXJuICJzY2FuOmZpbmQtZmFpbGVkIgogICAgc3RhY2sgPSBbbW91bnRwb2ludF0KICAgIHdoaWxlIHN0YWNrOgogICAgICAgIGN1cnJlbnQgPSBzdGFjay5wb3AoKQogICAgICAgIHRyeToKICAgICAgICAgICAgd2l0aCBvcy5zY2FuZGlyKGN1cnJlbnQpIGFzIGl0OgogICAgICAgICAgICAgICAgZW50cmllcyA9IGxpc3QoaXQpCiAgICAgICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgICAgIHJldHVybiAic2NhbjpmaW5kLWZhaWxlZCIKICAgICAgICBmb3IgZW50cnkgaW4gZW50cmllczoKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgc3QgPSBlbnRyeS5zdGF0KGZvbGxvd19zeW1saW5rcz1GYWxzZSkKICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgICAgICAgICByZXR1cm4gInNjYW46ZmluZC1mYWlsZWQiCiAgICAgICAgICAgIGlmIHN0YXQuU19JU0RJUihzdC5zdF9tb2RlKToKICAgICAgICAgICAgICAgIGlmIHN0LnN0X2RldiA9PSByb290X2RldjoKICAgICAgICAgICAgICAgICAgICBzdGFjay5hcHBlbmQoZW50cnkucGF0aCkKICAgICAgICAgICAgZWxpZiBzdGF0LlNfSVNSRUcoc3Quc3RfbW9kZSkgYW5kIHN0YXQuU19JTU9ERShzdC5zdF9tb2RlKSAmIFNFTEVDVF9CSVRTOgogICAgICAgICAgICAgICAgZm91bmQuYXBwZW5kKChlbnRyeS5wYXRoLCBzdCkpCiAgICByZXR1cm4gTm9uZQoKCmRlZiBfcG9wdWxhdGlvbihtb3VudGluZm9fcGF0aCk6CiAgICAiIiLQmtC+0L/QuNGPIENIRUNLLdC90LDQsdC70Y7QtNCw0YLQtdC70Y86ICgiRVJST1IiLCByZWFzb24pIHwgKCJWQUxVRSIsIChtb3VudHMsIFsocGF0aCwgbHN0YXQpXSkpLiIiIgogICAgaWYgb3MucGF0aC5pc2xpbmsobW91bnRpbmZvX3BhdGgpOgogICAgICAgIHJldHVybiAiRVJST1IiLCAibW91bnRpbmZvOnN5bWxpbmsiCiAgICBpZiBub3Qgb3MucGF0aC5leGlzdHMobW91bnRpbmZvX3BhdGgpOgogICAgICAgIHJldHVybiAiRVJST1IiLCAibW91bnRpbmZvOm5vdC1mb3VuZCIKICAgIGlmIG5vdCBvcy5wYXRoLmlzZmlsZShtb3VudGluZm9fcGF0aCk6CiAgICAgICAgcmV0dXJuICJFUlJPUiIsICJtb3VudGluZm86aW52YWxpZC10eXBlIgogICAgaWYgbm90IG9zLmFjY2Vzcyhtb3VudGluZm9fcGF0aCwgb3MuUl9PSyk6CiAgICAgICAgcmV0dXJuICJFUlJPUiIsICJtb3VudGluZm86dW5yZWFkYWJsZSIKICAgIHRyeToKICAgICAgICB3aXRoIG9wZW4obW91bnRpbmZvX3BhdGgsICJyYiIpIGFzIGZoOgogICAgICAgICAgICByYXcgPSBmaC5yZWFkKCkKICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgIHJldHVybiAiRVJST1IiLCAibW91bnRpbmZvOnJlYWQtZmFpbGVkIgogICAgaWYgYiJceDAwIiBpbiByYXc6CiAgICAgICAgcmV0dXJuICJFUlJPUiIsICJtb3VudGluZm86aW52YWxpZC1ieXRlcyIKCiAgICBzZWVuX21vdW50cyA9IHNldCgpCiAgICBzZWVuX2ZpbGVzID0gc2V0KCkKICAgIGl0ZW1zID0gW10KICAgIG1vdW50cyA9IDAKICAgIGZvciBsaW5lIGluIHJhdy5kZWNvZGUoInV0Zi04IiwgInN1cnJvZ2F0ZWVzY2FwZSIpLnNwbGl0KCJcbiIpOgogICAgICAgIGlmIG5vdCBsaW5lOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGZpZWxkcyA9IGxpbmUuc3BsaXQoIiAiLCA2KQogICAgICAgIGlmIGxlbihmaWVsZHMpICE9IDcgb3Igbm90IGFsbChmaWVsZHMpOgogICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgIm1vdW50aW5mbzppbnZhbGlkLWZpZWxkcyIKICAgICAgICB0YWlsID0gZmllbGRzWzZdCiAgICAgICAgaWYgdGFpbC5zdGFydHN3aXRoKCItICIpOgogICAgICAgICAgICBhZnRlciA9IHRhaWxbMjpdCiAgICAgICAgZWxpZiAiIC0gIiBpbiB0YWlsOgogICAgICAgICAgICBhZnRlciA9IHRhaWwuc3BsaXQoIiAtICIsIDEpWzFdCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcmV0dXJuICJFUlJPUiIsICJtb3VudGluZm86bWlzc2luZy1zZXBhcmF0b3IiCiAgICAgICAgZnN0eXBlID0gYWZ0ZXIuc3BsaXQoIiAiLCAxKVswXQogICAgICAgIGlmIG5vdCBmc3R5cGU6CiAgICAgICAgICAgIHJldHVybiAiRVJST1IiLCAibW91bnRpbmZvOm1pc3NpbmctZnN0eXBlIgogICAgICAgIGlmIGZzdHlwZSBpbiBQU0VVRE9fRlM6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgbW91bnRwb2ludCA9IF91bmVzY2FwZV9tb3VudHBvaW50KGZpZWxkc1s0XSkKICAgICAgICBpZiBub3QgbW91bnRwb2ludC5zdGFydHN3aXRoKCIvIikgb3IgYW55KGMgaW4gbW91bnRwb2ludCBmb3IgYyBpbiBfRk9SQklEREVOX1BBVEhfQ0hBUlMpOgogICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgIm1vdW50aW5mbzppbnZhbGlkLW1vdW50cG9pbnQiCiAgICAgICAgaWYgbm90IG9zLnBhdGguaXNkaXIobW91bnRwb2ludCk6CiAgICAgICAgICAgIHJldHVybiAiRVJST1IiLCAibW91bnRpbmZvOm1pc3NpbmctbW91bnRwb2ludCIKICAgICAgICB0cnk6CiAgICAgICAgICAgIHJvb3Rfc3QgPSBvcy5zdGF0KG1vdW50cG9pbnQpCiAgICAgICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgICAgIHJldHVybiAiRVJST1IiLCAibW91bnRpbmZvOmlkZW50aXR5LWZhaWxlZCIKICAgICAgICBpZGVudGl0eSA9IChyb290X3N0LnN0X2Rldiwgcm9vdF9zdC5zdF9pbm8pCiAgICAgICAgaWYgaWRlbnRpdHkgaW4gc2Vlbl9tb3VudHM6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgc2Vlbl9tb3VudHMuYWRkKGlkZW50aXR5KQogICAgICAgIG1vdW50cyArPSAxCgogICAgICAgIGZvdW5kID0gW10KICAgICAgICByZWFzb24gPSBfc2Nhbl9tb3VudChtb3VudHBvaW50LCBmb3VuZCkKICAgICAgICBpZiByZWFzb24gaXMgbm90IE5vbmU6CiAgICAgICAgICAgIHJldHVybiAiRVJST1IiLCByZWFzb24KICAgICAgICBmb3VuZC5zb3J0KGtleT1sYW1iZGEgcGFpcjogb3MuZnNlbmNvZGUocGFpclswXSkpCiAgICAgICAgZm9yIHBhdGgsIHN0IGluIGZvdW5kOgogICAgICAgICAgICBpZiBhbnkoYyBpbiBwYXRoIGZvciBjIGluIF9GT1JCSURERU5fUEFUSF9DSEFSUyk6CiAgICAgICAgICAgICAgICByZXR1cm4gIkVSUk9SIiwgInRhcmdldDppbnZhbGlkLXBhdGgiCiAgICAgICAgICAgIGZpbGVfaWRlbnRpdHkgPSAoc3Quc3RfZGV2LCBzdC5zdF9pbm8pCiAgICAgICAgICAgIGlmIGZpbGVfaWRlbnRpdHkgaW4gc2Vlbl9maWxlczoKICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgIHNlZW5fZmlsZXMuYWRkKGZpbGVfaWRlbnRpdHkpCiAgICAgICAgICAgIGl0ZW1zLmFwcGVuZCgocGF0aCwgc3QpKQoKICAgIGlmIG1vdW50cyA9PSAwOgogICAgICAgIHJldHVybiAiRVJST1IiLCAibW91bnRpbmZvOmVtcHR5LXBvcHVsYXRpb24iCiAgICByZXR1cm4gIlZBTFVFIiwgKG1vdW50cywgaXRlbXMpCgoKZGVmIF9jdXJyZW50X3ZhbHVlKG1vdW50cywgaXRlbXMsIG1hc2spOgogICAgdmlvbGF0aW9ucyA9IHN1bSgxIGZvciBfcGF0aCwgc3QgaW4gaXRlbXMgaWYgc3RhdC5TX0lNT0RFKHN0LnN0X21vZGUpICYgbWFzaykKICAgIHJldHVybiAibW91bnRzPSVkO2NoZWNrZWQ9JWQ7dmlvbGF0aW9ucz0lZCIgJSAobW91bnRzLCBsZW4oaXRlbXMpLCB2aW9sYXRpb25zKQoKCmRlZiBvYnNlcnZlKG1vdW50aW5mb19wYXRoPUNBTk9OSUNBTF9MT0NBVE9SLCBleHBlY3RlZD1FWFBFQ1RFRF9NQVNLKToKICAgICIiIihzdGF0dXMsIHZhbHVlKSDQsiDRhNC+0YDQvNCw0YLQtSBDSEVDSy3QsNC00LDQv9GC0LXRgNCwINC00LvRjyDQvtC00L3QvtCz0L4gbW91bnRpbmZvLiIiIgogICAgbWFzayA9IGludChleHBlY3RlZCwgOCkKICAgIHN0YXR1cywgZGF0YSA9IF9wb3B1bGF0aW9uKG1vdW50aW5mb19wYXRoKQogICAgaWYgc3RhdHVzID09ICJFUlJPUiI6CiAgICAgICAgcmV0dXJuICJFUlJPUiIsIGRhdGEKICAgIG1vdW50cywgaXRlbXMgPSBkYXRhCiAgICByZXR1cm4gIlZBTFVFIiwgX2N1cnJlbnRfdmFsdWUobW91bnRzLCBpdGVtcywgbWFzaykKCgpkZWYgX2RlZmF1bHRfcHJpdmlsZWdlX2NoZWNrKCkgLT4gYm9vbDoKICAgIHJldHVybiBvcy5nZXRldWlkKCkgPT0gMAoKCmRlZiBfZGVmYXVsdF9mY2htb2QoZmQsIG1vZGUsIHBhdGgpOgogICAgb3MuZmNobW9kKGZkLCBtb2RlKQoKCmRlZiBfcmVzdWx0KGNvbnRyb2xfaWQsIHRhcmdldCwgb3V0Y29tZSwgKiwgYWN0aW9ucywgZHJ5X3J1biwgbXV0YXRpb249RmFsc2UsICoqZXh0cmEpOgogICAgcmVjb3JkID0gewogICAgICAgICJhZGFwdGVyX2lkIjogQURBUFRFUl9JRCwKICAgICAgICAibWVjaGFuaXNtX2lkIjogTUVDSEFOSVNNX0lELAogICAgICAgICJjb250cm9sX2lkIjogY29udHJvbF9pZCwKICAgICAgICAidGFyZ2V0IjogdGFyZ2V0LAogICAgICAgICJvdXRjb21lIjogb3V0Y29tZSwKICAgICAgICAicmVhc29uIjogTm9uZSwKICAgICAgICAiY3VycmVudF9tb2RlIjogTm9uZSwKICAgICAgICAidmlvbGF0b3JzIjogW10sCiAgICAgICAgImFwcGxpZWQiOiBbXSwKICAgICAgICAic2tpcHBlZCI6IFtdLAogICAgICAgICJmYWlsZWQiOiBbXSwKICAgICAgICAiYWN0aW9uc19hdHRlbXB0ZWQiOiBsaXN0KGFjdGlvbnMpLAogICAgICAgICJtdXRhdGlvbl9wZXJmb3JtZWQiOiBib29sKG11dGF0aW9uKSwKICAgICAgICAidHJhbnNhY3Rpb25fY29tbWl0IjogX2NvbW1pdF9zdGF0ZShvdXRjb21lLCBkcnlfcnVuLCBtdXRhdGlvbiksCiAgICAgICAgImRyeV9ydW4iOiBib29sKGRyeV9ydW4pLAogICAgfQogICAgcmVjb3JkLnVwZGF0ZShleHRyYSkKICAgIGlmIHJlY29yZFsib3V0Y29tZSJdIG5vdCBpbiBPVVRDT01FUzoKICAgICAgICByYWlzZSBWYWx1ZUVycm9yKCJvdXRjb21lIG91dHNpZGUgY2xvc2VkIHZvY2FidWxhcnkiKQogICAgcmV0dXJuIHJlY29yZAoKCmRlZiBfY29tbWl0X3N0YXRlKG91dGNvbWUsIGRyeV9ydW4sIG11dGF0aW9uKToKICAgICIiItCi0LUg0LbQtSDQt9C90LDRh9C10L3QuNGPLCDRh9GC0L4g0YMgb3B0aW9uYWwtZmlsZS1yb290LWZpbGVzLW1vZGUuIiIiCiAgICBpZiBvdXRjb21lID09ICJBUFBMSUVEIiBvciAob3V0Y29tZSA9PSAiQUxSRUFEWV9DT01QTElBTlQiIGFuZCBub3QgZHJ5X3J1bik6CiAgICAgICAgcmV0dXJuIENPTU1JVF9DT01NSVRURUQKICAgIGlmIG11dGF0aW9uOgogICAgICAgIHJldHVybiBDT01NSVRfTk9UX0NPTU1JVFRFRAogICAgcmV0dXJuIENPTU1JVF9OT1RfU1RBUlRFRAoKCmRlZiBvdXRjb21lX3JjX2NvbnRyaWJ1dGlvbihvdXRjb21lLCBkcnlfcnVuPUZhbHNlKToKICAgICIiIiIwIiDQtNC70Y8g0YPRgdC/0LXRiNC90YvRhSDQuNGB0YXQvtC00L7Qsiwg0LjQvdCw0YfQtSAibm9uemVybyI7IEFQUExJRURfUEFSVElBTCDigJQgbm9uemVyby4iIiIKICAgIGlmIG91dGNvbWUgaW4gKCJBUFBMSUVEIiwgIkFMUkVBRFlfQ09NUExJQU5UIiwgIk5PVF9FTElHSUJMRV9BUFBMWV9VTlNVUFBPUlRFRCIpOgogICAgICAgIHJldHVybiAiMCIKICAgIGlmIGRyeV9ydW4gYW5kIG91dGNvbWUgPT0gIkRSWV9SVU5fV09VTERfQVBQTFkiOgogICAgICAgIHJldHVybiAiMCIKICAgIHJldHVybiAibm9uemVybyIKCgpkZWYgX2FwcGx5X29uZShwYXRoLCBvYnNlcnZlZCwgbWFzaywgZmNobW9kKToKICAgICIiItCh0L3Rj9GC0Ywg0LHQuNGC0YsgbWFzayDRgyDQvtC00L3QvtCz0L4g0L7QsdGK0LXQutGC0LAuCgogICAg0JLQvtC30LLRgNCw0YnQsNC10YIgKG11dGF0ZWQsIGtpbmQsIHJlYXNvbik6IGtpbmQg4oCUICJvayIsICJza2lwIiDQuNC70LggImZhaWwiLgogICAg0KDQtdCy0LDQu9C40LTQsNGG0LjRjyDQvdCwINC00LXRgdC60YDQuNC/0YLQvtGA0LUg0YHRgtGA0L7Qs9C+INCyINC/0L7RgNGP0LTQutC1IFNfSVNSRUcgLT4gZGV2L2lubyAtPiAwNjAwMC4KICAgICIiIgogICAgdHJ5OgogICAgICAgIGZkID0gb3Mub3BlbihwYXRoLCBvcy5PX1JET05MWSB8IG9zLk9fTk9GT0xMT1cgfCBvcy5PX0NMT0VYRUMpCiAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgaWYgZXhjLmVycm5vID09IGVycm5vLkVMT09QOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgIm5vdC1yZWd1bGFyIgogICAgICAgIHJldHVybiBGYWxzZSwgImZhaWwiLCAib3BlbjolcyIgJSBlcnJuby5lcnJvcmNvZGUuZ2V0KGV4Yy5lcnJubywgZXhjLmVycm5vKQogICAgdHJ5OgogICAgICAgIG5vdyA9IG9zLmZzdGF0KGZkKQogICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcobm93LnN0X21vZGUpOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgIm5vdC1yZWd1bGFyIgogICAgICAgIGlmIChub3cuc3RfZGV2LCBub3cuc3RfaW5vKSAhPSAob2JzZXJ2ZWQuc3RfZGV2LCBvYnNlcnZlZC5zdF9pbm8pOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgImlkZW50aXR5LWRyaWZ0IgogICAgICAgIGlmIG5vdCBzdGF0LlNfSU1PREUobm93LnN0X21vZGUpICYgU0VMRUNUX0JJVFM6CiAgICAgICAgICAgIHJldHVybiBGYWxzZSwgInNraXAiLCAibm8tc3VpZC1zZ2lkIgogICAgICAgIGlmIG5vdy5zdF9ubGluayAhPSAxOgogICAgICAgICAgICByZXR1cm4gRmFsc2UsICJza2lwIiwgInN0X25saW5rIgogICAgICAgIGN1cnJlbnQgPSBzdGF0LlNfSU1PREUobm93LnN0X21vZGUpCiAgICAgICAgcGxhbm5lZCA9IGN1cnJlbnQgJiB+bWFzawogICAgICAgIGlmIHBsYW5uZWQgPT0gY3VycmVudDoKICAgICAgICAgICAgcmV0dXJuIEZhbHNlLCAic2tpcCIsICJuby12aW9sYXRpb24iCiAgICAgICAgZmNobW9kKGZkLCBwbGFubmVkLCBwYXRoKQogICAgICAgIHBvc3QgPSBvcy5mc3RhdChmZCkKICAgICAgICBpZiAoCiAgICAgICAgICAgIHN0YXQuU19JTU9ERShwb3N0LnN0X21vZGUpICE9IHBsYW5uZWQKICAgICAgICAgICAgb3IgKHBvc3Quc3RfdWlkLCBwb3N0LnN0X2dpZCkgIT0gKG5vdy5zdF91aWQsIG5vdy5zdF9naWQpCiAgICAgICAgICAgIG9yIChwb3N0LnN0X2RldiwgcG9zdC5zdF9pbm8pICE9IChub3cuc3RfZGV2LCBub3cuc3RfaW5vKQogICAgICAgICAgICBvciBwb3N0LnN0X3NpemUgIT0gbm93LnN0X3NpemUKICAgICAgICApOgogICAgICAgICAgICByZXR1cm4gVHJ1ZSwgImZhaWwiLCAicG9zdC1zdGF0ZS1taXNtYXRjaCIKICAgICAgICByZXR1cm4gVHJ1ZSwgIm9rIiwgTm9uZQogICAgZmluYWxseToKICAgICAgICBvcy5jbG9zZShmZCkKCgpkZWYgZXhlY3V0ZV9jb250cm9sKAogICAgY29udHJvbF9pZCwKICAgIGtleSwKICAgIG9wLAogICAgZXhwZWN0ZWQsCiAgICBhcHBseV9zdXBwb3J0ZWQsCiAgICAqLAogICAgdGFyZ2V0PU5vbmUsCiAgICBkcnlfcnVuLAogICAgcHJpdmlsZWdlX2NoZWNrPU5vbmUsCiAgICBfZmNobW9kPU5vbmUsCik6CiAgICAiIiJBcHBseSB0aGUgMi4zLjkgU1VJRC9TR0lEIG1vZGUgY29udHJvbC4gTmV2ZXIgZm9sbG93cyBhIHN5bWxpbmssIG5ldmVyIHJlbGF4ZXMuIiIiCiAgICB2YWxpZGF0ZV9jb250cm9sX2lucHV0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQpCiAgICBhY3Rpb25zID0gWyJQMF9FTElHSUJJTElUWSJdCgogICAgZGVmIGRvbmUob3V0Y29tZSwgKipleHRyYSk6CiAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwgdGFyZ2V0LCBvdXRjb21lLCBhY3Rpb25zPWFjdGlvbnMsIGRyeV9ydW49ZHJ5X3J1biwgKipleHRyYSkKCiAgICBpZiBub3QgYXBwbHlfc3VwcG9ydGVkOgogICAgICAgIHJldHVybiBkb25lKCJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiLCByZWFzb249ImFwcGx5LXVuc3VwcG9ydGVkIikKICAgIGlmIG5vdCBfaXNfZWxpZ2libGVfY29udHJhY3Qoa2V5LCBvcCwgZXhwZWN0ZWQpOgogICAgICAgIHJldHVybiBkb25lKCJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiLCByZWFzb249Im9wLXVuc3VwcG9ydGVkIikKCiAgICBpZiB0YXJnZXQgaXMgTm9uZToKICAgICAgICB0YXJnZXQgPSBUQVJHRVRTLmdldChjb250cm9sX2lkKQogICAgICAgIGlmIHRhcmdldCBpcyBOb25lOgogICAgICAgICAgICByZXR1cm4gZG9uZSgiQUJPUlRFRF9QUkVDT05ESVRJT05fT1RIRVIiLCByZWFzb249InRhcmdldDp1bm1hcHBlZC1jb250cm9sIikKCiAgICBtYXNrID0gaW50KGV4cGVjdGVkLCA4KQogICAgYWN0aW9ucy5hcHBlbmQoIlAxX1BPUFVMQVRJT04iKQogICAgc3RhdHVzLCBkYXRhID0gX3BvcHVsYXRpb24odGFyZ2V0KQogICAgaWYgc3RhdHVzID09ICJFUlJPUiI6CiAgICAgICAgb3V0Y29tZSA9ICJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIgaWYgZGF0YSBpbiBDT05GTElDVF9SRUFTT05TIGVsc2UgIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIgogICAgICAgIHJldHVybiBkb25lKG91dGNvbWUsIHJlYXNvbj1kYXRhKQogICAgbW91bnRzLCBpdGVtcyA9IGRhdGEKCiAgICBhY3Rpb25zLmFwcGVuZCgiUDJfUExBTiIpCiAgICBjdXJyZW50ID0gX2N1cnJlbnRfdmFsdWUobW91bnRzLCBpdGVtcywgbWFzaykKICAgIHZpb2xhdG9ycyA9IFsocGF0aCwgc3QpIGZvciBwYXRoLCBzdCBpbiBpdGVtcyBpZiBzdGF0LlNfSU1PREUoc3Quc3RfbW9kZSkgJiBtYXNrXQogICAgaWYgbm90IHZpb2xhdG9yczoKICAgICAgICByZXR1cm4gZG9uZSgiQUxSRUFEWV9DT01QTElBTlQiLCBjdXJyZW50X21vZGU9Y3VycmVudCkKICAgIHNraXBwZWQgPSBbCiAgICAgICAgeyJwYXRoIjogcGF0aCwgInJlYXNvbiI6ICJzdF9ubGluayJ9CiAgICAgICAgZm9yIHBhdGgsIHN0IGluIHZpb2xhdG9ycwogICAgICAgIGlmIHN0LnN0X25saW5rICE9IDEKICAgIF0KICAgIHNraXBwZWRfcGF0aHMgPSB7aXRlbVsicGF0aCJdIGZvciBpdGVtIGluIHNraXBwZWR9CiAgICBwbGFubmVkID0gWyhwYXRoLCBzdCkgZm9yIHBhdGgsIHN0IGluIHZpb2xhdG9ycyBpZiBwYXRoIG5vdCBpbiBza2lwcGVkX3BhdGhzXQogICAgdmlvbGF0b3JfcGF0aHMgPSBbcGF0aCBmb3IgcGF0aCwgX3N0IGluIHZpb2xhdG9yc10KICAgIGlmIG5vdCBwbGFubmVkOgogICAgICAgIHJldHVybiBkb25lKCJBQk9SVEVEX1BSRUNPTkRJVElPTl9DT05GTElDVCIsIHJlYXNvbj0ic3RfbmxpbmsiLCBjdXJyZW50X21vZGU9Y3VycmVudCwKICAgICAgICAgICAgICAgICAgICB2aW9sYXRvcnM9dmlvbGF0b3JfcGF0aHMsIHNraXBwZWQ9c2tpcHBlZCkKICAgIGlmIGRyeV9ydW46CiAgICAgICAgcmV0dXJuIGRvbmUoIkRSWV9SVU5fV09VTERfQVBQTFkiLCBjdXJyZW50X21vZGU9Y3VycmVudCwKICAgICAgICAgICAgICAgICAgICB2aW9sYXRvcnM9dmlvbGF0b3JfcGF0aHMsIHNraXBwZWQ9c2tpcHBlZCkKCiAgICBhY3Rpb25zLmFwcGVuZCgiUDNfUFJJVklMRUdFIikKICAgIGNoZWNrID0gcHJpdmlsZWdlX2NoZWNrIGlmIHByaXZpbGVnZV9jaGVjayBpcyBub3QgTm9uZSBlbHNlIF9kZWZhdWx0X3ByaXZpbGVnZV9jaGVjawogICAgaWYgbm90IGNoZWNrKCk6CiAgICAgICAgcmV0dXJuIGRvbmUoIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIiwgcmVhc29uPSJwcml2aWxlZ2UiLCBjdXJyZW50X21vZGU9Y3VycmVudCwKICAgICAgICAgICAgICAgICAgICB2aW9sYXRvcnM9dmlvbGF0b3JfcGF0aHMsIHNraXBwZWQ9c2tpcHBlZCkKCiAgICBhY3Rpb25zLmFwcGVuZCgiUEhBU0UxX01PREUiKQogICAgZmNobW9kID0gX2ZjaG1vZCBpZiBfZmNobW9kIGlzIG5vdCBOb25lIGVsc2UgX2RlZmF1bHRfZmNobW9kCiAgICBhcHBsaWVkLCBmYWlsZWQgPSBbXSwgW10KICAgIG11dGF0ZWQgPSBGYWxzZQogICAgZm9yIHBhdGgsIHN0IGluIHBsYW5uZWQ6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBjaGFuZ2VkLCBraW5kLCByZWFzb24gPSBfYXBwbHlfb25lKHBhdGgsIHN0LCBtYXNrLCBmY2htb2QpCiAgICAgICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgICAgICBpZiBleGMuZXJybm8gPT0gZXJybm8uRVJPRlM6CiAgICAgICAgICAgICAgICBvdXRjb21lID0gIkFQUExJRURfUEFSVElBTCIgaWYgbXV0YXRlZCBlbHNlICJBQk9SVEVEX1BSRUNPTkRJVElPTl9PVEhFUiIKICAgICAgICAgICAgICAgIHJldHVybiBkb25lKG91dGNvbWUsIHJlYXNvbj0iZXJvZnMiLCBtdXRhdGlvbj1tdXRhdGVkLCBjdXJyZW50X21vZGU9Y3VycmVudCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZpb2xhdG9ycz12aW9sYXRvcl9wYXRocywgYXBwbGllZD1hcHBsaWVkLCBza2lwcGVkPXNraXBwZWQsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICBmYWlsZWQ9ZmFpbGVkICsgW3sicGF0aCI6IHBhdGgsICJyZWFzb24iOiAiZXJvZnMifV0pCiAgICAgICAgICAgIGNoYW5nZWQsIGtpbmQsIHJlYXNvbiA9IEZhbHNlLCAiZmFpbCIsICJmY2htb2Q6JXMiICUgZXJybm8uZXJyb3Jjb2RlLmdldChleGMuZXJybm8sIGV4Yy5lcnJubykKICAgICAgICBtdXRhdGVkID0gbXV0YXRlZCBvciBjaGFuZ2VkCiAgICAgICAgaWYga2luZCA9PSAib2siOgogICAgICAgICAgICBhcHBsaWVkLmFwcGVuZChwYXRoKQogICAgICAgIGVsaWYga2luZCA9PSAic2tpcCI6CiAgICAgICAgICAgIHNraXBwZWQuYXBwZW5kKHsicGF0aCI6IHBhdGgsICJyZWFzb24iOiByZWFzb259KQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIGZhaWxlZC5hcHBlbmQoeyJwYXRoIjogcGF0aCwgInJlYXNvbiI6IHJlYXNvbn0pCgogICAgYWN0aW9ucy5hcHBlbmQoIkZJTkFMX1BPU1RDSEVDSyIpCiAgICBleHRyYSA9IGRpY3QoY3VycmVudF9tb2RlPWN1cnJlbnQsIHZpb2xhdG9ycz12aW9sYXRvcl9wYXRocywgYXBwbGllZD1hcHBsaWVkLAogICAgICAgICAgICAgICAgIHNraXBwZWQ9c2tpcHBlZCwgZmFpbGVkPWZhaWxlZCkKICAgIGlmIG5vdCBmYWlsZWQgYW5kIG5vdCBza2lwcGVkOgogICAgICAgIHJldHVybiBkb25lKCJBUFBMSUVEIiwgbXV0YXRpb249bXV0YXRlZCwgKipleHRyYSkKICAgIGlmIGFwcGxpZWQ6CiAgICAgICAgcmV0dXJuIGRvbmUoIkFQUExJRURfUEFSVElBTCIsIHJlYXNvbj0icGFydGlhbCIsIG11dGF0aW9uPW11dGF0ZWQsICoqZXh0cmEpCiAgICByZXR1cm4gZG9uZSgiRkFJTEVEX05PVF9DT01NSVRURUQiLCByZWFzb249Im5vLW9iamVjdC1hcHBsaWVkIiwgbXV0YXRpb249bXV0YXRlZCwgKipleHRyYSkKCgpkZWYgY29udHJvbF9yZXN1bHRfdG9fcmVwb3J0KHJlc3VsdCwgc3RhcnRlZF9hdCwgZmluaXNoZWRfYXQpOgogICAgcmV0dXJuIHsKICAgICAgICAiYWRhcHRlcl9pZCI6IHJlc3VsdFsiYWRhcHRlcl9pZCJdLAogICAgICAgICJtZWNoYW5pc21faWQiOiByZXN1bHRbIm1lY2hhbmlzbV9pZCJdLAogICAgICAgICJjb250cm9sX2lkIjogcmVzdWx0WyJjb250cm9sX2lkIl0sCiAgICAgICAgInRhcmdldCI6IHJlc3VsdFsidGFyZ2V0Il0sCiAgICAgICAgIm91dGNvbWUiOiByZXN1bHRbIm91dGNvbWUiXSwKICAgICAgICAicmVhc29uIjogcmVzdWx0WyJyZWFzb24iXSwKICAgICAgICAiY3VycmVudF9tb2RlIjogcmVzdWx0WyJjdXJyZW50X21vZGUiXSwKICAgICAgICAidmlvbGF0b3JzIjogbGlzdChyZXN1bHRbInZpb2xhdG9ycyJdKSwKICAgICAgICAiYXBwbGllZCI6IGxpc3QocmVzdWx0WyJhcHBsaWVkIl0pLAogICAgICAgICJza2lwcGVkIjogW2RpY3QoaXRlbSkgZm9yIGl0ZW0gaW4gcmVzdWx0WyJza2lwcGVkIl1dLAogICAgICAgICJmYWlsZWQiOiBbZGljdChpdGVtKSBmb3IgaXRlbSBpbiByZXN1bHRbImZhaWxlZCJdXSwKICAgICAgICAic3RhcnRlZF9hdCI6IHN0YXJ0ZWRfYXQsCiAgICAgICAgImZpbmlzaGVkX2F0IjogZmluaXNoZWRfYXQsCiAgICAgICAgImFjdGlvbnNfYXR0ZW1wdGVkIjogbGlzdChyZXN1bHRbImFjdGlvbnNfYXR0ZW1wdGVkIl0pLAogICAgICAgICJzdGVwX3JjIjogb3V0Y29tZV9yY19jb250cmlidXRpb24ocmVzdWx0WyJvdXRjb21lIl0sIHJlc3VsdFsiZHJ5X3J1biJdKSwKICAgICAgICAibXV0YXRpb25fcGVyZm9ybWVkIjogcmVzdWx0WyJtdXRhdGlvbl9wZXJmb3JtZWQiXSwKICAgICAgICAidHJhbnNhY3Rpb25fY29tbWl0IjogcmVzdWx0WyJ0cmFuc2FjdGlvbl9jb21taXQiXSwKICAgIH0K"},"sysctl":{"adapter_id":"product-config-line-runtime-apply-v1","apply_kind":"config-line-with-runtime-v1","implementation_sha256":"853de26f2ef5e3b84ff9457aec0f73b898603fbdfb03a0730ebcb6f0af2e645c","mechanism_id":"config-line-with-runtime-v1","source_b64":"IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiJBUFBMWSBhZGFwdGVyIGNvcmUgZm9yIGNvbmZpZy1saW5lLXdpdGgtcnVudGltZS12MS4KClRoZSBtb2R1bGUga2VlcHMgQ0hFQ0stY29tcGF0aWJsZSBpbnRlZ2VyIHNlbWFudGljcywgcGFyc2VzIHRoZSBjb250cmFjdC1kZWZpbmVkCmV4cGxpY2l0IHN5c2N0bCBhc3NpZ25tZW50cywgcmVzb2x2ZXMgc3lzY3RsLmQgcHJlY2VkZW5jZSwgcGxhbnMgb25lIGNvbnRyb2wgYW5kCmV4ZWN1dGVzIGl0cyBwZXJzaXN0ZW50L3J1bnRpbWUgdHJhbnNhY3Rpb24uIE1lcmVseSBpbXBvcnRpbmcgb3IgcnVubmluZyB0aGUKc2VsZi10ZXN0IG5ldmVyIG11dGF0ZXMgL2V0Yy9zeXNjdGwuZCBvciAvcHJvYy9zeXMuCiIiIgoKZnJvbSBkYXRhY2xhc3NlcyBpbXBvcnQgZGF0YWNsYXNzCmZyb20gcGF0aGxpYiBpbXBvcnQgUHVyZVBvc2l4UGF0aAppbXBvcnQgcmUKaW1wb3J0IGVycm5vCmltcG9ydCBoYXNobGliCmltcG9ydCBvcwppbXBvcnQgcG9zaXhwYXRoCmltcG9ydCBzZWNyZXRzCmltcG9ydCBzdGF0CmltcG9ydCBqc29uCmltcG9ydCBiYXNlNjQKaW1wb3J0IGRhdGV0aW1lIGFzIF9kYXRldGltZQppbXBvcnQgdHJhY2ViYWNrCgpNRUNIQU5JU01fSUQgPSAiY29uZmlnLWxpbmUtd2l0aC1ydW50aW1lLXYxIgpBREFQVEVSX0lEID0gInByb2R1Y3QtY29uZmlnLWxpbmUtcnVudGltZS1hcHBseS12MSIKVEFSR0VUX0lEID0gImxpbnV4LXg4Nl82NC1zdXBwb3J0ZWQtdjEiClBBUkFNRVRFUl9LSU5EID0gInN5c2N0bCIKU1VQUE9SVEVEX09QUyA9ICgiZXEiLCAiZ2UiKQpFWFBFQ1RFRF9UWVBFID0gImludGVnZXIiCgpPVVRDT01FX05PVF9FTElHSUJMRSA9ICJOT1RfRUxJR0lCTEVfQVBQTFlfVU5TVVBQT1JURUQiCkJSQU5DSF9BTFJFQURZID0gIm5laXRoZXJfbmVlZHNfY2hhbmdlIgpCUkFOQ0hfUEVSU0lTVEVOVF9PTkxZID0gInBlcnNpc3RlbnRfb25seSIKQlJBTkNIX1JVTlRJTUVfT05MWSA9ICJydW50aW1lX29ubHkiCkJSQU5DSF9CT1RIID0gImJvdGgiCgpDT05UUk9MX0lEX1JFID0gcmUuY29tcGlsZShyIl4oPyEuKltcclxuXSlbQS1aYS16MC05Ll8tXSskIikKU1lTQ1RMX0tFWV9SRSA9IHJlLmNvbXBpbGUociJeW0EtWmEtejAtOV8tXSsoPzpcLltBLVphLXowLTlfLV0rKSokIikKSU5URUdFUl9SRSA9IHJlLmNvbXBpbGUocmIiXlsrLV0/WzAtOV0rJCIpCkFTQ0lJX0VER0VfV1MgPSBiIiBcdFxuXHJcdlxmIgoKU1lTQ1RMX0RfRElSUyA9ICgKICAgICIvZXRjL3N5c2N0bC5kIiwKICAgICIvcnVuL3N5c2N0bC5kIiwKICAgICIvdXNyL2xvY2FsL2xpYi9zeXNjdGwuZCIsCiAgICAiL3Vzci9saWIvc3lzY3RsLmQiLAogICAgIi9saWIvc3lzY3RsLmQiLAopCkRJUl9QUklPUklUWSA9IHtuYW1lOiBpIGZvciBpLCBuYW1lIGluIGVudW1lcmF0ZShTWVNDVExfRF9ESVJTKX0KU1lTQ1RMX0NPTkYgPSAiL2V0Yy9zeXNjdGwuY29uZiIKQ0FOT05JQ0FMX0hFQURFUiA9IGIiIyBNYW5hZ2VkIGJ5IFNlY3VyZUxpbnV4LVBvbGljeVxuIgoKCmNsYXNzIENvbnRyYWN0RXJyb3IoVmFsdWVFcnJvcik6CiAgICBwYXNzCgoKY2xhc3MgUHJlY29uZGl0aW9uRXJyb3IoUnVudGltZUVycm9yKToKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBjb2RlLCBzb3VyY2U9Tm9uZSk6CiAgICAgICAgc3VwZXIoKS5fX2luaXRfXyhjb2RlIGlmIHNvdXJjZSBpcyBOb25lIGVsc2UgZiJ7Y29kZX06e3NvdXJjZX0iKQogICAgICAgIHNlbGYuY29kZSA9IGNvZGUKICAgICAgICBzZWxmLnNvdXJjZSA9IHNvdXJjZQoKCkBkYXRhY2xhc3MoZnJvemVuPVRydWUpCmNsYXNzIEV4cGxpY2l0QXNzaWdubWVudDoKICAgIGtleTogc3RyCiAgICB2YWx1ZV90ZXh0OiBzdHIKICAgIGxpbmVfbm86IGludAoKCkBkYXRhY2xhc3MoZnJvemVuPVRydWUpCmNsYXNzIFNvdXJjZUZpbGU6CiAgICBwYXRoOiBzdHIKICAgIGFzc2lnbm1lbnRzOiB0dXBsZSA9ICgpCgoKQGRhdGFjbGFzcyhmcm96ZW49VHJ1ZSkKY2xhc3MgUHJlY2VkZW5jZVJlc3VsdDoKICAgIGVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlOiBpbnQgfCBOb25lCiAgICBlZmZlY3RpdmVfZm9yZWlnbl9zb3VyY2U6IHN0ciB8IE5vbmUKICAgIGNvbmZsaWN0X3NvdXJjZXM6IHR1cGxlCiAgICBzaGFkb3dlZF9zb3VyY2VzOiB0dXBsZQoKCkBkYXRhY2xhc3MoZnJvemVuPVRydWUpCmNsYXNzIFBsYW46CiAgICB0YXJnZXRfdmFsdWU6IGludAogICAgcnVudGltZV9jb21wbGlhbnQ6IGJvb2wKICAgIHBlcnNpc3RlbnRfY29tcGxpYW50OiBib29sCiAgICBicmFuY2g6IHN0cgoKCmRlZiBfcmVxdWlyZV9pbnQodmFsdWUsIGZpZWxkKToKICAgIGlmIGlzaW5zdGFuY2UodmFsdWUsIGJvb2wpIG9yIG5vdCBpc2luc3RhbmNlKHZhbHVlLCBpbnQpOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoZiJ7ZmllbGR9IG11c3QgYmUgaW50ZWdlciIpCiAgICByZXR1cm4gdmFsdWUKCgpkZWYgdmFsaWRhdGVfY29udHJvbF9pbnB1dChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgYXBwbHlfc3VwcG9ydGVkKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKGNvbnRyb2xfaWQsIHN0cikgb3IgQ09OVFJPTF9JRF9SRS5mdWxsbWF0Y2goY29udHJvbF9pZCkgaXMgTm9uZToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJpbnZhbGlkIGNvbnRyb2wgaWQiKQogICAgcHJvY19wYXRoKGtleSkKICAgIGlmIG9wIG5vdCBpbiBTVVBQT1JURURfT1BTOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoInVuc3VwcG9ydGVkIG9wIikKICAgIF9yZXF1aXJlX2ludChleHBlY3RlZCwgImV4cGVjdGVkIikKICAgIGlmIG5vdCBpc2luc3RhbmNlKGFwcGx5X3N1cHBvcnRlZCwgYm9vbCk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiYXBwbHkuc3VwcG9ydGVkIG11c3QgYmUgYm9vbGVhbiIpCgoKZGVmIGVsaWdpYmlsaXR5X291dGNvbWUoYXBwbHlfc3VwcG9ydGVkKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKGFwcGx5X3N1cHBvcnRlZCwgYm9vbCk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiYXBwbHkuc3VwcG9ydGVkIG11c3QgYmUgYm9vbGVhbiIpCiAgICByZXR1cm4gTm9uZSBpZiBhcHBseV9zdXBwb3J0ZWQgZWxzZSBPVVRDT01FX05PVF9FTElHSUJMRQoKCmRlZiBwcm9jX3BhdGgoa2V5KToKICAgIGlmIG5vdCBpc2luc3RhbmNlKGtleSwgc3RyKSBvciBTWVNDVExfS0VZX1JFLmZ1bGxtYXRjaChrZXkpIGlzIE5vbmU6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiaW52YWxpZCBzeXNjdGwga2V5IikKICAgIHJldHVybiAiL3Byb2Mvc3lzLyIgKyBrZXkucmVwbGFjZSgiLiIsICIvIikKCgpkZWYgcGVyc2lzdGVudF9wYXRoKGtleSk6CiAgICBwcm9jX3BhdGgoa2V5KQogICAgcmV0dXJuICIvZXRjL3N5c2N0bC5kL3p6LXNlY3VyZWxpbnV4LXBvbGljeS0iICsga2V5LnJlcGxhY2UoIi4iLCAiLSIpICsgIi5jb25mIgoKCmRlZiBwYXJzZV9pbnRlZ2VyX2J5dGVzKHJhdyk6CiAgICBpZiBub3QgaXNpbnN0YW5jZShyYXcsIChieXRlcywgYnl0ZWFycmF5KSk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiaW50ZWdlciBzb3VyY2UgbXVzdCBiZSBieXRlcyIpCiAgICBkYXRhID0gYnl0ZXMocmF3KQogICAgaWYgYiJceDAwIiBpbiBkYXRhOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoImludmFsaWQgaW50ZWdlciBieXRlcyIpCiAgICB0b2tlbiA9IGRhdGEuc3RyaXAoQVNDSUlfRURHRV9XUykKICAgIGlmIElOVEVHRVJfUkUuZnVsbG1hdGNoKHRva2VuKSBpcyBOb25lOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoImludmFsaWQgaW50ZWdlciB2YWx1ZSIpCiAgICAjIFB5dGhvbiBpbnRlZ2VycyBhcmUgdW5ib3VuZGVkOyBpbnQoKSBhbHNvIGNhbm9uaWNhbGl6ZXMgbGVhZGluZyB6ZXJvcyBhbmQgKy4KICAgIHJldHVybiBpbnQodG9rZW4sIDEwKQoKCmRlZiBwYXJzZV9pbnRlZ2VyX3RleHQodGV4dCk6CiAgICBpZiBub3QgaXNpbnN0YW5jZSh0ZXh0LCBzdHIpOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoImludGVnZXIgc291cmNlIG11c3QgYmUgdGV4dCIpCiAgICB0cnk6CiAgICAgICAgcmF3ID0gdGV4dC5lbmNvZGUoImFzY2lpIikKICAgIGV4Y2VwdCBVbmljb2RlRW5jb2RlRXJyb3IgYXMgZXhjOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoImludmFsaWQgaW50ZWdlciB2YWx1ZSIpIGZyb20gZXhjCiAgICByZXR1cm4gcGFyc2VfaW50ZWdlcl9ieXRlcyhyYXcpCgoKZGVmIGNhbm9uaWNhbF9pbnRlZ2VyKHZhbHVlKToKICAgIF9yZXF1aXJlX2ludCh2YWx1ZSwgImludGVnZXIiKQogICAgcmV0dXJuIHN0cih2YWx1ZSkKCgpkZWYgbm9ybWFsaXplX3NvdXJjZV9rZXkoa2V5KToKICAgICIiIlJldHVybiB0aGUgcHJvYy1zdWZmaXggZm9ybSBkZWZpbmVkIGJ5IHRoZSBhY2NlcHRlZCBzeXNjdGwgc2VtYW50aWNzLiIiIgogICAgaWYgbm90IGlzaW5zdGFuY2Uoa2V5LCBzdHIpIG9yIG5vdCBrZXkgb3IgYW55KGNoLmlzc3BhY2UoKSBmb3IgY2ggaW4ga2V5KToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJpbnZhbGlkIHNvdXJjZSBrZXkiKQogICAgIyBBIGxlYWRpbmcgJy0nIGJlbG9uZ3MgdG8gc3lzY3RsIGxpbmUgc3ludGF4LCBub3QgdG8ga2V5IG5vcm1hbGl6YXRpb24uCiAgICAjIHBhcnNlX3N5c2N0bF9hc3NpZ25tZW50X2xpbmUoKSByZW1vdmVzIGl0IG9ubHkgZm9yIHRoZSBleHBsaWNpdAogICAgIyAiLWtleSA9IHZhbHVlIiBmb3JtLiBBIGJhcmUgIi1rZXkiIGxpbmUgaXMgdGhlcmVmb3JlIG5ldmVyIGNvbmZ1c2VkCiAgICAjIHdpdGggYW4gYXNzaWdubWVudC4KICAgIGlmIG5vdCBrZXk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiaW52YWxpZCBzb3VyY2Uga2V5IikKICAgIGRvdCA9IGtleS5maW5kKCIuIikKICAgIHNsYXNoID0ga2V5LmZpbmQoIi8iKQogICAgaWYgZG90IDwgMCBhbmQgc2xhc2ggPCAwOgogICAgICAgIHJldHVybiBrZXkKICAgIGlmIHNsYXNoID49IDAgYW5kIChkb3QgPCAwIG9yIHNsYXNoIDwgZG90KToKICAgICAgICByZXR1cm4ga2V5CiAgICB0YWJsZSA9IHN0ci5tYWtldHJhbnMoeyIuIjogIi8iLCAiLyI6ICIuIn0pCiAgICByZXR1cm4ga2V5LnRyYW5zbGF0ZSh0YWJsZSkKCgpkZWYgY29udHJvbF9wcm9jX3N1ZmZpeChrZXkpOgogICAgcHJvY19wYXRoKGtleSkKICAgIHJldHVybiBrZXkucmVwbGFjZSgiLiIsICIvIikKCgpkZWYgY29tcHV0ZV90YXJnZXRfdmFsdWUob3AsIGV4cGVjdGVkLCBydW50aW1lX2JlZm9yZSwgb3duX3BlcnNpc3RlbnRfdmFsdWU9Tm9uZSwgZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWU9Tm9uZSk6CiAgICBpZiBvcCBub3QgaW4gU1VQUE9SVEVEX09QUzoKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJ1bnN1cHBvcnRlZCBvcCIpCiAgICB2YWx1ZXMgPSBbX3JlcXVpcmVfaW50KGV4cGVjdGVkLCAiZXhwZWN0ZWQiKSwgX3JlcXVpcmVfaW50KHJ1bnRpbWVfYmVmb3JlLCAicnVudGltZV9iZWZvcmUiKV0KICAgIGlmIG9wID09ICJlcSI6CiAgICAgICAgcmV0dXJuIHZhbHVlc1swXQogICAgZm9yIG5hbWUsIHZhbHVlIGluICgoIm93bl9wZXJzaXN0ZW50X3ZhbHVlIiwgb3duX3BlcnNpc3RlbnRfdmFsdWUpLCAoImVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlIiwgZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWUpKToKICAgICAgICBpZiB2YWx1ZSBpcyBub3QgTm9uZToKICAgICAgICAgICAgdmFsdWVzLmFwcGVuZChfcmVxdWlyZV9pbnQodmFsdWUsIG5hbWUpKQogICAgcmV0dXJuIG1heCh2YWx1ZXMpCgoKZGVmIHJ1bnRpbWVfaXNfY29tcGxpYW50KG9wLCBydW50aW1lX3ZhbHVlLCB0YXJnZXRfdmFsdWUpOgogICAgcnVudGltZV92YWx1ZSA9IF9yZXF1aXJlX2ludChydW50aW1lX3ZhbHVlLCAicnVudGltZV92YWx1ZSIpCiAgICB0YXJnZXRfdmFsdWUgPSBfcmVxdWlyZV9pbnQodGFyZ2V0X3ZhbHVlLCAidGFyZ2V0X3ZhbHVlIikKICAgIGlmIG9wID09ICJlcSI6CiAgICAgICAgcmV0dXJuIHJ1bnRpbWVfdmFsdWUgPT0gdGFyZ2V0X3ZhbHVlCiAgICBpZiBvcCA9PSAiZ2UiOgogICAgICAgIHJldHVybiBydW50aW1lX3ZhbHVlID49IHRhcmdldF92YWx1ZQogICAgcmFpc2UgQ29udHJhY3RFcnJvcigidW5zdXBwb3J0ZWQgb3AiKQoKCmRlZiBjYW5vbmljYWxfcGVyc2lzdGVudF9ieXRlcyhrZXksIHRhcmdldF92YWx1ZSk6CiAgICBwcm9jX3BhdGgoa2V5KQogICAgdGFyZ2V0ID0gY2Fub25pY2FsX2ludGVnZXIodGFyZ2V0X3ZhbHVlKS5lbmNvZGUoImFzY2lpIikKICAgIHJldHVybiBDQU5PTklDQUxfSEVBREVSICsga2V5LmVuY29kZSgiYXNjaWkiKSArIGIiID0gIiArIHRhcmdldCArIGIiXG4iCgoKZGVmIHBlcnNpc3RlbnRfaXNfY29tcGxpYW50KGtleSwgdGFyZ2V0X3ZhbHVlLCByYXdfYnl0ZXMsIHVpZCwgZ2lkLCBtb2RlLCBleHBlY3RlZF91aWQ9MCwgZXhwZWN0ZWRfZ2lkPTAsIGV4cGVjdGVkX21vZGU9MG82NDQpOgogICAgaWYgcmF3X2J5dGVzIGlzIE5vbmU6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBpZiBub3QgaXNpbnN0YW5jZShyYXdfYnl0ZXMsIChieXRlcywgYnl0ZWFycmF5KSk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigicGVyc2lzdGVudCBieXRlcyBtdXN0IGJlIGJ5dGVzIG9yIE5vbmUiKQogICAgZm9yIG5hbWUsIHZhbHVlIGluICgoInVpZCIsIHVpZCksICgiZ2lkIiwgZ2lkKSwgKCJtb2RlIiwgbW9kZSkpOgogICAgICAgIGlmIGlzaW5zdGFuY2UodmFsdWUsIGJvb2wpIG9yIG5vdCBpc2luc3RhbmNlKHZhbHVlLCBpbnQpOgogICAgICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKGYie25hbWV9IG11c3QgYmUgaW50ZWdlciIpCiAgICBmb3IgbmFtZSwgdmFsdWUgaW4gKCgiZXhwZWN0ZWRfdWlkIiwgZXhwZWN0ZWRfdWlkKSwgKCJleHBlY3RlZF9naWQiLCBleHBlY3RlZF9naWQpLCAoImV4cGVjdGVkX21vZGUiLCBleHBlY3RlZF9tb2RlKSk6CiAgICAgICAgaWYgaXNpbnN0YW5jZSh2YWx1ZSwgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2UodmFsdWUsIGludCk6CiAgICAgICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoZiJ7bmFtZX0gbXVzdCBiZSBpbnRlZ2VyIikKICAgIHJldHVybiAoCiAgICAgICAgYnl0ZXMocmF3X2J5dGVzKSA9PSBjYW5vbmljYWxfcGVyc2lzdGVudF9ieXRlcyhrZXksIHRhcmdldF92YWx1ZSkKICAgICAgICBhbmQgdWlkID09IGV4cGVjdGVkX3VpZAogICAgICAgIGFuZCBnaWQgPT0gZXhwZWN0ZWRfZ2lkCiAgICAgICAgYW5kIG1vZGUgPT0gZXhwZWN0ZWRfbW9kZQogICAgKQoKCmRlZiBzZWxlY3RfYnJhbmNoKHJ1bnRpbWVfY29tcGxpYW50LCBwZXJzaXN0ZW50X2NvbXBsaWFudCk6CiAgICBpZiBub3QgaXNpbnN0YW5jZShydW50aW1lX2NvbXBsaWFudCwgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2UocGVyc2lzdGVudF9jb21wbGlhbnQsIGJvb2wpOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoImNvbXBsaWFuY2UgaW5wdXRzIG11c3QgYmUgYm9vbGVhbiIpCiAgICBpZiBydW50aW1lX2NvbXBsaWFudCBhbmQgcGVyc2lzdGVudF9jb21wbGlhbnQ6CiAgICAgICAgcmV0dXJuIEJSQU5DSF9BTFJFQURZCiAgICBpZiBydW50aW1lX2NvbXBsaWFudDoKICAgICAgICByZXR1cm4gQlJBTkNIX1BFUlNJU1RFTlRfT05MWQogICAgaWYgcGVyc2lzdGVudF9jb21wbGlhbnQ6CiAgICAgICAgcmV0dXJuIEJSQU5DSF9SVU5USU1FX09OTFkKICAgIHJldHVybiBCUkFOQ0hfQk9USAoKCmRlZiBidWlsZF9wbGFuKGtleSwgb3AsIGV4cGVjdGVkLCBydW50aW1lX2JlZm9yZSwgcGVyc2lzdGVudF9ieXRlcywgdWlkLCBnaWQsIG1vZGUsIG93bl9wZXJzaXN0ZW50X3ZhbHVlPU5vbmUsIGVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlPU5vbmUsIGV4cGVjdGVkX3VpZD0wLCBleHBlY3RlZF9naWQ9MCwgZXhwZWN0ZWRfbW9kZT0wbzY0NCk6CiAgICB0YXJnZXQgPSBjb21wdXRlX3RhcmdldF92YWx1ZShvcCwgZXhwZWN0ZWQsIHJ1bnRpbWVfYmVmb3JlLCBvd25fcGVyc2lzdGVudF92YWx1ZSwgZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWUpCiAgICBydW50aW1lX29rID0gcnVudGltZV9pc19jb21wbGlhbnQob3AsIHJ1bnRpbWVfYmVmb3JlLCB0YXJnZXQpCiAgICBwZXJzaXN0ZW50X29rID0gcGVyc2lzdGVudF9pc19jb21wbGlhbnQoa2V5LCB0YXJnZXQsIHBlcnNpc3RlbnRfYnl0ZXMsIHVpZCwgZ2lkLCBtb2RlLCBleHBlY3RlZF91aWQsIGV4cGVjdGVkX2dpZCwgZXhwZWN0ZWRfbW9kZSkKICAgIHJldHVybiBQbGFuKHRhcmdldCwgcnVudGltZV9vaywgcGVyc2lzdGVudF9vaywgc2VsZWN0X2JyYW5jaChydW50aW1lX29rLCBwZXJzaXN0ZW50X29rKSkKCgpkZWYgX3BhdGhfcGFydHMocGF0aCk6CiAgICBpZiBub3QgaXNpbnN0YW5jZShwYXRoLCBzdHIpIG9yIG5vdCBwYXRoLnN0YXJ0c3dpdGgoIi8iKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJzb3VyY2UgcGF0aCBtdXN0IGJlIGFic29sdXRlIikKICAgIHAgPSBQdXJlUG9zaXhQYXRoKHBhdGgpCiAgICByZXR1cm4gc3RyKHAucGFyZW50KSwgcC5uYW1lCgoKZGVmIF92YWxpZGF0ZV9zb3VyY2VfZmlsZShzb3VyY2UpOgogICAgaWYgbm90IGlzaW5zdGFuY2Uoc291cmNlLCBTb3VyY2VGaWxlKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJzb3VyY2UgbXVzdCBiZSBTb3VyY2VGaWxlIikKICAgIHBhcmVudCwgYmFzZW5hbWUgPSBfcGF0aF9wYXJ0cyhzb3VyY2UucGF0aCkKICAgIGlmIHNvdXJjZS5wYXRoICE9IFNZU0NUTF9DT05GOgogICAgICAgIGlmIHBhcmVudCBub3QgaW4gRElSX1BSSU9SSVRZIG9yIG5vdCBiYXNlbmFtZS5lbmRzd2l0aCgiLmNvbmYiKToKICAgICAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigidW5zdXBwb3J0ZWQgc3lzY3RsIHNvdXJjZSBwYXRoIikKICAgIGZvciBhc3NpZ25tZW50IGluIHNvdXJjZS5hc3NpZ25tZW50czoKICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShhc3NpZ25tZW50LCBFeHBsaWNpdEFzc2lnbm1lbnQpOgogICAgICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJhc3NpZ25tZW50IG11c3QgYmUgRXhwbGljaXRBc3NpZ25tZW50IikKICAgICAgICBpZiBpc2luc3RhbmNlKGFzc2lnbm1lbnQubGluZV9ubywgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2UoYXNzaWdubWVudC5saW5lX25vLCBpbnQpIG9yIGFzc2lnbm1lbnQubGluZV9ubyA8IDE6CiAgICAgICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoImludmFsaWQgbGluZSBudW1iZXIiKQogICAgICAgIG5vcm1hbGl6ZV9zb3VyY2Vfa2V5KGFzc2lnbm1lbnQua2V5KQogICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKGFzc2lnbm1lbnQudmFsdWVfdGV4dCwgc3RyKToKICAgICAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiYXNzaWdubWVudCB2YWx1ZSBtdXN0IGJlIHRleHQiKQoKCmRlZiBfc2hhZG93X3N5c2N0bF9kX3NvdXJjZXMoZmlsZXMsIG93bl9wYXRoKToKICAgIG93bl9wYXJlbnQsIG93bl9iYXNlbmFtZSA9IF9wYXRoX3BhcnRzKG93bl9wYXRoKQogICAgaWYgb3duX3BhcmVudCAhPSAiL2V0Yy9zeXNjdGwuZCI6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigib3duIHBhdGggb3V0c2lkZSAvZXRjL3N5c2N0bC5kIikKICAgIGJ5X2Jhc2VuYW1lID0ge30KICAgIHNoYWRvd2VkID0gW10KICAgIGZvciBzcmMgaW4gZmlsZXM6CiAgICAgICAgaWYgc3JjLnBhdGggPT0gU1lTQ1RMX0NPTkY6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgcGFyZW50LCBiYXNlbmFtZSA9IF9wYXRoX3BhcnRzKHNyYy5wYXRoKQogICAgICAgIGN1cnJlbnQgPSBieV9iYXNlbmFtZS5nZXQoYmFzZW5hbWUpCiAgICAgICAgaWYgY3VycmVudCBpcyBOb25lOgogICAgICAgICAgICBieV9iYXNlbmFtZVtiYXNlbmFtZV0gPSBzcmMKICAgICAgICAgICAgY29udGludWUKICAgICAgICBjdXJfcGFyZW50LCBfID0gX3BhdGhfcGFydHMoY3VycmVudC5wYXRoKQogICAgICAgIGlmIHBhcmVudCA9PSBjdXJfcGFyZW50OgogICAgICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJkdXBsaWNhdGUgc291cmNlIHBhdGgvYmFzZW5hbWUiKQogICAgICAgIGlmIERJUl9QUklPUklUWVtwYXJlbnRdIDwgRElSX1BSSU9SSVRZW2N1cl9wYXJlbnRdOgogICAgICAgICAgICBzaGFkb3dlZC5hcHBlbmQoY3VycmVudC5wYXRoKQogICAgICAgICAgICBieV9iYXNlbmFtZVtiYXNlbmFtZV0gPSBzcmMKICAgICAgICBlbHNlOgogICAgICAgICAgICBzaGFkb3dlZC5hcHBlbmQoc3JjLnBhdGgpCiAgICByZXR1cm4gdHVwbGUoYnlfYmFzZW5hbWUudmFsdWVzKCkpLCB0dXBsZShzb3J0ZWQoc2hhZG93ZWQsIGtleT1sYW1iZGEgcDogcC5lbmNvZGUoInV0Zi04IikpKQoKCmRlZiByZXNvbHZlX3ByZWNlZGVuY2UoY29udHJvbF9rZXksIHNvdXJjZV9maWxlcyk6CiAgICAiIiJSZXNvbHZlIHN0cnVjdHVyZWQgZXhwbGljaXQgYXNzaWdubWVudHMgd2l0aG91dCByZWFkaW5nIHRoZSBmaWxlc3lzdGVtLgoKICAgIGBzb3VyY2VfZmlsZXNgIG11c3QgcmVwcmVzZW50IGZpbGVzIGFmdGVyIHBhcnNlci1sZXZlbCBjbGFzc2lmaWNhdGlvbi4gQSBmaWxlCiAgICBtYXkgaGF2ZSB6ZXJvIGFzc2lnbm1lbnRzIHNvIHNhbWUtYmFzZW5hbWUgc2hhZG93aW5nIHJlbWFpbnMgcmVwcmVzZW50YWJsZS4KICAgIEVudHJpZXMgaW4gZWFjaCBmaWxlIG11c3QgYmUgaW4gb3JpZ2luYWwgbGluZSBvcmRlci4KICAgICIiIgogICAgb3duX3BhdGggPSBwZXJzaXN0ZW50X3BhdGgoY29udHJvbF9rZXkpCiAgICBvd25fYmFzZW5hbWUgPSBQdXJlUG9zaXhQYXRoKG93bl9wYXRoKS5uYW1lCiAgICB0YXJnZXRfc3VmZml4ID0gY29udHJvbF9wcm9jX3N1ZmZpeChjb250cm9sX2tleSkKICAgIGZpbGVzID0gdHVwbGUoc291cmNlX2ZpbGVzKQogICAgc2Vlbl9wYXRocyA9IHNldCgpCiAgICBmb3Igc3JjIGluIGZpbGVzOgogICAgICAgIF92YWxpZGF0ZV9zb3VyY2VfZmlsZShzcmMpCiAgICAgICAgaWYgc3JjLnBhdGggaW4gc2Vlbl9wYXRoczoKICAgICAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiZHVwbGljYXRlIHNvdXJjZSBwYXRoIikKICAgICAgICBzZWVuX3BhdGhzLmFkZChzcmMucGF0aCkKCiAgICBzdXJ2aXZvcnMsIHNoYWRvd2VkID0gX3NoYWRvd19zeXNjdGxfZF9zb3VyY2VzKGZpbGVzLCBvd25fcGF0aCkKICAgIHN1cnZpdm9ycyA9IHNvcnRlZChzdXJ2aXZvcnMsIGtleT1sYW1iZGEgczogUHVyZVBvc2l4UGF0aChzLnBhdGgpLm5hbWUuZW5jb2RlKCJ1dGYtOCIpKQoKICAgIGVmZmVjdGl2ZSA9IE5vbmUKICAgIGVmZmVjdGl2ZV9zb3VyY2UgPSBOb25lCiAgICBlZmZlY3RpdmVfYXNzaWdubWVudCA9IE5vbmUKICAgIGNvbmZsaWN0cyA9IFtdCgogICAgZGVmIG1hdGNoaW5nX2Fzc2lnbm1lbnRzKHNyYyk6CiAgICAgICAgcmV0dXJuIFthIGZvciBhIGluIHNyYy5hc3NpZ25tZW50cyBpZiBub3JtYWxpemVfc291cmNlX2tleShhLmtleSkgPT0gdGFyZ2V0X3N1ZmZpeF0KCiAgICBmb3Igc3JjIGluIHN1cnZpdm9yczoKICAgICAgICBpZiBzcmMucGF0aCA9PSBvd25fcGF0aDoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBiYXNlbmFtZSA9IFB1cmVQb3NpeFBhdGgoc3JjLnBhdGgpLm5hbWUKICAgICAgICBtYXRjaGVzID0gbWF0Y2hpbmdfYXNzaWdubWVudHMoc3JjKQogICAgICAgIGlmIG5vdCBtYXRjaGVzOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmIGJhc2VuYW1lLmVuY29kZSgidXRmLTgiKSA+IG93bl9iYXNlbmFtZS5lbmNvZGUoInV0Zi04Iik6CiAgICAgICAgICAgIGNvbmZsaWN0cy5hcHBlbmQoc3JjLnBhdGgpCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgIyBEMDgvcjExOiBvbmx5IHRoZSBmaW5hbCBlZmZlY3RpdmUgZXhwbGljaXQgYXNzaWdubWVudCBiZWZvcmUgb3VyIGZpbGUKICAgICAgICAjIGRldGVybWluZXMgZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWUuIEVhcmxpZXIgb3ZlcnJpZGRlbiBhc3NpZ25tZW50cyBhcmUKICAgICAgICAjIG5vdCBwYXJzZWQgYXMgY2FuZGlkYXRlIHZhbHVlcy4KICAgICAgICBlZmZlY3RpdmVfYXNzaWdubWVudCA9IHNvcnRlZChtYXRjaGVzLCBrZXk9bGFtYmRhIGE6IGEubGluZV9ubylbLTFdCiAgICAgICAgZWZmZWN0aXZlX3NvdXJjZSA9IHNyYy5wYXRoCgogICAgZm9yIHNyYyBpbiBmaWxlczoKICAgICAgICBpZiBzcmMucGF0aCAhPSBTWVNDVExfQ09ORjoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBpZiBtYXRjaGluZ19hc3NpZ25tZW50cyhzcmMpOgogICAgICAgICAgICBjb25mbGljdHMuYXBwZW5kKFNZU0NUTF9DT05GKQoKICAgIGlmIGNvbmZsaWN0czoKICAgICAgICAjIENvbmZsaWN0IGRldGVjdGlvbiBpcyBpbmRlcGVuZGVudCBmcm9tIG51bWVyaWMgc3RyZW5ndGg6IGxhdGVyIGV4cGxpY2l0CiAgICAgICAgIyBhc3NpZ25tZW50cyBhcmUgZmFpbC1jbG9zZWQgYnkgSDQ2LUQwOC4KICAgICAgICByYWlzZSBQcmVjb25kaXRpb25FcnJvcigic291cmNlOmxhdGUtY29uZmxpY3QiLCB0dXBsZShzb3J0ZWQoc2V0KGNvbmZsaWN0cyksIGtleT1sYW1iZGEgcDogcC5lbmNvZGUoInV0Zi04IikpKSkKCiAgICBpZiBlZmZlY3RpdmVfYXNzaWdubWVudCBpcyBub3QgTm9uZToKICAgICAgICB0cnk6CiAgICAgICAgICAgIGVmZmVjdGl2ZSA9IHBhcnNlX2ludGVnZXJfdGV4dChlZmZlY3RpdmVfYXNzaWdubWVudC52YWx1ZV90ZXh0KQogICAgICAgIGV4Y2VwdCBDb250cmFjdEVycm9yIGFzIGV4YzoKICAgICAgICAgICAgcmFpc2UgUHJlY29uZGl0aW9uRXJyb3IoInNvdXJjZTppbnZhbGlkLWludGVnZXIiLCBlZmZlY3RpdmVfc291cmNlKSBmcm9tIGV4YwoKICAgIHJldHVybiBQcmVjZWRlbmNlUmVzdWx0KGVmZmVjdGl2ZSwgZWZmZWN0aXZlX3NvdXJjZSwgKCksIHNoYWRvd2VkKQoKCgpAZGF0YWNsYXNzKGZyb3plbj1UcnVlKQpjbGFzcyBPYmplY3RJZGVudGl0eToKICAgIGV4aXN0czogYm9vbAogICAgc3RfZGV2OiBpbnQgfCBOb25lID0gTm9uZQogICAgc3RfaW5vOiBpbnQgfCBOb25lID0gTm9uZQogICAgZmlsZV90eXBlOiBpbnQgfCBOb25lID0gTm9uZQogICAgc3Rfbmxpbms6IGludCB8IE5vbmUgPSBOb25lCiAgICB1aWQ6IGludCB8IE5vbmUgPSBOb25lCiAgICBnaWQ6IGludCB8IE5vbmUgPSBOb25lCiAgICBtb2RlOiBpbnQgfCBOb25lID0gTm9uZQogICAgcmF3X2J5dGVzOiBieXRlcyB8IE5vbmUgPSBOb25lCgoKQGRhdGFjbGFzcyhmcm96ZW49VHJ1ZSkKY2xhc3MgUGVyc2lzdGVudE11dGF0aW9uU3RhdGU6CiAgICB0YXJnZXRfcGF0aDogc3RyCiAgICBwcmVzdGF0ZTogT2JqZWN0SWRlbnRpdHkKICAgIGF0dGVtcHRfd3JpdHRlbl9pZGVudGl0eTogT2JqZWN0SWRlbnRpdHkKCgpAZGF0YWNsYXNzKGZyb3plbj1UcnVlKQpjbGFzcyBSdW50aW1lUGhhc2VSZXN1bHQ6CiAgICBydW50aW1lX3ByZXdyaXRlOiBpbnQKICAgIHdyaXR0ZW5fdmFsdWU6IGludCB8IE5vbmUKICAgIHJ1bnRpbWVfYWZ0ZXI6IGludAogICAgd3JpdGVfcGVyZm9ybWVkOiBib29sCgoKY2xhc3MgUGVyc2lzdGVudFBoYXNlRXJyb3IoUnVudGltZUVycm9yKToKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBvdXRjb21lLCBjb2RlLCBtdXRhdGlvbl9wZXJmb3JtZWQsIGF0dGVtcHRfd3JpdHRlbl9pZGVudGl0eT1Ob25lKToKICAgICAgICBzdXBlcigpLl9faW5pdF9fKGYie291dGNvbWV9Ontjb2RlfSIpCiAgICAgICAgc2VsZi5vdXRjb21lID0gb3V0Y29tZQogICAgICAgIHNlbGYuY29kZSA9IGNvZGUKICAgICAgICBzZWxmLm11dGF0aW9uX3BlcmZvcm1lZCA9IG11dGF0aW9uX3BlcmZvcm1lZAogICAgICAgIHNlbGYuYXR0ZW1wdF93cml0dGVuX2lkZW50aXR5ID0gYXR0ZW1wdF93cml0dGVuX2lkZW50aXR5CgoKY2xhc3MgQ29tcGVuc2F0aW9uRXJyb3IoUnVudGltZUVycm9yKToKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBjb2RlKToKICAgICAgICBzdXBlcigpLl9faW5pdF9fKGNvZGUpCiAgICAgICAgc2VsZi5jb2RlID0gY29kZQoKClJVTlRJTUVfV1JJVEVSX1BST1RPQ09MX1YxID0gIlNMUF9SVU5USU1FX1dSSVRFUl9WMSIKCgpjbGFzcyBSdW50aW1lV3JpdGVFcnJvcihSdW50aW1lRXJyb3IpOgogICAgZGVmIF9faW5pdF9fKHNlbGYsIGNvZGUsIHdyaXRlX3N0YXJ0ZWQ9RmFsc2UpOgogICAgICAgIHN1cGVyKCkuX19pbml0X18oY29kZSkKICAgICAgICBzZWxmLmNvZGUgPSBjb2RlCiAgICAgICAgc2VsZi53cml0ZV9zdGFydGVkID0gYm9vbCh3cml0ZV9zdGFydGVkKQoKCmNsYXNzIFJ1bnRpbWVXcml0ZXJQcm90b2NvbFZpb2xhdGlvbihSdW50aW1lRXJyb3IpOgogICAgcGFzcwoKCmNsYXNzIFJ1bnRpbWVNdXRhdGlvblByZWNvbmRpdGlvbkVycm9yKFJ1bnRpbWVFcnJvcik6CiAgICBkZWYgX19pbml0X18oc2VsZiwgcmVhc29uLCBydW50aW1lX3ByZXdyaXRlKToKICAgICAgICBzdXBlcigpLl9faW5pdF9fKHJlYXNvbikKICAgICAgICBzZWxmLnJlYXNvbiA9IHJlYXNvbgogICAgICAgIHNlbGYucnVudGltZV9wcmV3cml0ZSA9IHJ1bnRpbWVfcHJld3JpdGUKCgpjbGFzcyBSdW50aW1lUGhhc2VFcnJvcihSdW50aW1lRXJyb3IpOgogICAgZGVmIF9faW5pdF9fKHNlbGYsIGNvZGUsIHJ1bnRpbWVfcHJld3JpdGU9Tm9uZSwgcnVudGltZV9hZnRlcj1Ob25lLCB3cml0ZV9hdHRlbXB0ZWQ9RmFsc2UsCiAgICAgICAgICAgICAgICAgd3JpdGVfcGVyZm9ybWVkPUZhbHNlLCB3cml0dGVuX3ZhbHVlPU5vbmUpOgogICAgICAgIHN1cGVyKCkuX19pbml0X18oY29kZSkKICAgICAgICBzZWxmLmNvZGUgPSBjb2RlCiAgICAgICAgc2VsZi5ydW50aW1lX3ByZXdyaXRlID0gcnVudGltZV9wcmV3cml0ZQogICAgICAgIHNlbGYucnVudGltZV9hZnRlciA9IHJ1bnRpbWVfYWZ0ZXIKICAgICAgICBzZWxmLndyaXRlX2F0dGVtcHRlZCA9IGJvb2wod3JpdGVfYXR0ZW1wdGVkKQogICAgICAgIHNlbGYud3JpdGVfcGVyZm9ybWVkID0gYm9vbCh3cml0ZV9wZXJmb3JtZWQpCiAgICAgICAgc2VsZi53cml0dGVuX3ZhbHVlID0gd3JpdHRlbl92YWx1ZSBpZiBzZWxmLndyaXRlX3BlcmZvcm1lZCBlbHNlIE5vbmUKCgpkZWYgX21vZGVfdHlwZShtb2RlKToKICAgIHJldHVybiBzdGF0LlNfSUZNVChtb2RlKQoKCmRlZiBfcmVhZF9hbGxfZmQoZmQpOgogICAgb3MubHNlZWsoZmQsIDAsIG9zLlNFRUtfU0VUKQogICAgY2h1bmtzID0gW10KICAgIHdoaWxlIFRydWU6CiAgICAgICAgY2h1bmsgPSBvcy5yZWFkKGZkLCAxIDw8IDIwKQogICAgICAgIGlmIG5vdCBjaHVuazoKICAgICAgICAgICAgYnJlYWsKICAgICAgICBjaHVua3MuYXBwZW5kKGNodW5rKQogICAgcmV0dXJuIGIiIi5qb2luKGNodW5rcykKCgpkZWYgX2lkZW50aXR5X2Zyb21fZmQoZmQsIHJlYWRfYnl0ZXM9VHJ1ZSk6CiAgICBzdCA9IG9zLmZzdGF0KGZkKQogICAgcmF3ID0gX3JlYWRfYWxsX2ZkKGZkKSBpZiByZWFkX2J5dGVzIGVsc2UgTm9uZQogICAgcmV0dXJuIE9iamVjdElkZW50aXR5KAogICAgICAgIFRydWUsCiAgICAgICAgc3Quc3RfZGV2LAogICAgICAgIHN0LnN0X2lubywKICAgICAgICBfbW9kZV90eXBlKHN0LnN0X21vZGUpLAogICAgICAgIHN0LnN0X25saW5rLAogICAgICAgIHN0LnN0X3VpZCwKICAgICAgICBzdC5zdF9naWQsCiAgICAgICAgc3RhdC5TX0lNT0RFKHN0LnN0X21vZGUpLAogICAgICAgIHJhdywKICAgICkKCgpkZWYgX3JlcXVpcmVfcmVndWxhcl9zaW5nbGUoaWRlbnRpdHksIGNvZGU9InBlcnNpc3RlbnQ6Zm9yYmlkZGVuLW9iamVjdCIpOgogICAgaWYgbm90IGlkZW50aXR5LmV4aXN0cyBvciBpZGVudGl0eS5maWxlX3R5cGUgIT0gc3RhdC5TX0lGUkVHIG9yIGlkZW50aXR5LnN0X25saW5rICE9IDE6CiAgICAgICAgcmFpc2UgUHJlY29uZGl0aW9uRXJyb3IoY29kZSkKICAgIHJldHVybiBpZGVudGl0eQoKCmRlZiBfb3Blbl9kaXJfbm9mb2xsb3cocGF0aCk6CiAgICBpZiBub3QgaXNpbnN0YW5jZShwYXRoLCBzdHIpIG9yIG5vdCBwYXRoLnN0YXJ0c3dpdGgoIi8iKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJkaXJlY3RvcnkgcGF0aCBtdXN0IGJlIGFic29sdXRlIikKICAgIHRyeToKICAgICAgICBsc3QgPSBvcy5sc3RhdChwYXRoKQogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJwZXJzaXN0ZW50OmRpcmVjdG9yeS11bmF2YWlsYWJsZSIsIHBhdGgpIGZyb20gZXhjCiAgICBpZiBzdGF0LlNfSVNMTksobHN0LnN0X21vZGUpIG9yIG5vdCBzdGF0LlNfSVNESVIobHN0LnN0X21vZGUpOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJwZXJzaXN0ZW50OmRpcmVjdG9yeS1mb3JiaWRkZW4iLCBwYXRoKQogICAgZmxhZ3MgPSBvcy5PX1JET05MWSB8IGdldGF0dHIob3MsICJPX0NMT0VYRUMiLCAwKSB8IGdldGF0dHIob3MsICJPX0RJUkVDVE9SWSIsIDApCiAgICBmbGFncyB8PSBnZXRhdHRyKG9zLCAiT19OT0ZPTExPVyIsIDApCiAgICB0cnk6CiAgICAgICAgcmV0dXJuIG9zLm9wZW4ocGF0aCwgZmxhZ3MpCiAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgcmFpc2UgUHJlY29uZGl0aW9uRXJyb3IoInBlcnNpc3RlbnQ6ZGlyZWN0b3J5LXVuYXZhaWxhYmxlIiwgcGF0aCkgZnJvbSBleGMKCgpkZWYgX3NuYXBzaG90X25hbWUoZGlyX2ZkLCBuYW1lLCBhbGxvd19hYnNlbnQ9VHJ1ZSk6CiAgICB0cnk6CiAgICAgICAgbHN0ID0gb3Muc3RhdChuYW1lLCBkaXJfZmQ9ZGlyX2ZkLCBmb2xsb3dfc3ltbGlua3M9RmFsc2UpCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgaWYgYWxsb3dfYWJzZW50OgogICAgICAgICAgICByZXR1cm4gT2JqZWN0SWRlbnRpdHkoRmFsc2UpCiAgICAgICAgcmFpc2UgUHJlY29uZGl0aW9uRXJyb3IoInBlcnNpc3RlbnQ6dGFyZ2V0LW1pc3NpbmciLCBuYW1lKQogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJwZXJzaXN0ZW50OnRhcmdldC11bnJlYWRhYmxlIiwgbmFtZSkgZnJvbSBleGMKICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcobHN0LnN0X21vZGUpIG9yIGxzdC5zdF9ubGluayAhPSAxOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJwZXJzaXN0ZW50OmZvcmJpZGRlbi1vYmplY3QiLCBuYW1lKQogICAgZmxhZ3MgPSBvcy5PX1JET05MWSB8IGdldGF0dHIob3MsICJPX0NMT0VYRUMiLCAwKSB8IGdldGF0dHIob3MsICJPX05PRk9MTE9XIiwgMCkKICAgIHRyeToKICAgICAgICBmZCA9IG9zLm9wZW4obmFtZSwgZmxhZ3MsIGRpcl9mZD1kaXJfZmQpCiAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgaWYgZXhjLmVycm5vIGluIChlcnJuby5FTE9PUCwgZXJybm8uRU5PVERJUik6CiAgICAgICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJwZXJzaXN0ZW50OmZvcmJpZGRlbi1vYmplY3QiLCBuYW1lKSBmcm9tIGV4YwogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJwZXJzaXN0ZW50OnRhcmdldC11bnJlYWRhYmxlIiwgbmFtZSkgZnJvbSBleGMKICAgIHRyeToKICAgICAgICBmc3QgPSBvcy5mc3RhdChmZCkKICAgICAgICBpZiAoZnN0LnN0X2RldiwgZnN0LnN0X2lubywgX21vZGVfdHlwZShmc3Quc3RfbW9kZSksIGZzdC5zdF9ubGluaykgIT0gKGxzdC5zdF9kZXYsIGxzdC5zdF9pbm8sIF9tb2RlX3R5cGUobHN0LnN0X21vZGUpLCBsc3Quc3RfbmxpbmspOgogICAgICAgICAgICByYWlzZSBQcmVjb25kaXRpb25FcnJvcigicGVyc2lzdGVudDp0YXJnZXQtZHJpZnQiLCBuYW1lKQogICAgICAgIGlkZW50aXR5ID0gX2lkZW50aXR5X2Zyb21fZmQoZmQpCiAgICBmaW5hbGx5OgogICAgICAgIG9zLmNsb3NlKGZkKQogICAgcmV0dXJuIF9yZXF1aXJlX3JlZ3VsYXJfc2luZ2xlKGlkZW50aXR5KQoKCmRlZiBzbmFwc2hvdF9wZXJzaXN0ZW50X3RhcmdldCh0YXJnZXRfcGF0aCk6CiAgICBpZiBub3QgaXNpbnN0YW5jZSh0YXJnZXRfcGF0aCwgc3RyKSBvciBub3QgdGFyZ2V0X3BhdGguc3RhcnRzd2l0aCgiLyIpOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoInRhcmdldCBwYXRoIG11c3QgYmUgYWJzb2x1dGUiKQogICAgcGFyZW50ID0gc3RyKFB1cmVQb3NpeFBhdGgodGFyZ2V0X3BhdGgpLnBhcmVudCkKICAgIG5hbWUgPSBQdXJlUG9zaXhQYXRoKHRhcmdldF9wYXRoKS5uYW1lCiAgICBkaXJfZmQgPSBfb3Blbl9kaXJfbm9mb2xsb3cocGFyZW50KQogICAgdHJ5OgogICAgICAgIHJldHVybiBfc25hcHNob3RfbmFtZShkaXJfZmQsIG5hbWUsIGFsbG93X2Fic2VudD1UcnVlKQogICAgZmluYWxseToKICAgICAgICBvcy5jbG9zZShkaXJfZmQpCgoKZGVmIF93cml0ZV9hbGwoZmQsIGRhdGEpOgogICAgaWYgbm90IGlzaW5zdGFuY2UoZGF0YSwgKGJ5dGVzLCBieXRlYXJyYXkpKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJ3cml0ZSBkYXRhIG11c3QgYmUgYnl0ZXMiKQogICAgdmlldyA9IG1lbW9yeXZpZXcoYnl0ZXMoZGF0YSkpCiAgICBvZmZzZXQgPSAwCiAgICB3aGlsZSBvZmZzZXQgPCBsZW4odmlldyk6CiAgICAgICAgd3JpdHRlbiA9IG9zLndyaXRlKGZkLCB2aWV3W29mZnNldDpdKQogICAgICAgIGlmIHdyaXR0ZW4gPD0gMDoKICAgICAgICAgICAgcmFpc2UgT1NFcnJvcihlcnJuby5FSU8sICJzaG9ydCB3cml0ZSIpCiAgICAgICAgb2Zmc2V0ICs9IHdyaXR0ZW4KCgpkZWYgX3VubGlua19pZl9leGlzdHMoZGlyX2ZkLCBuYW1lKToKICAgIHRyeToKICAgICAgICBvcy51bmxpbmsobmFtZSwgZGlyX2ZkPWRpcl9mZCkKICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICBwYXNzCgoKZGVmIF9wcmVwYXJlX3RlbXAoZGlyX2ZkLCB0YXJnZXRfbmFtZSwgZGVzaXJlZF9ieXRlcywgZGVzaXJlZF91aWQsIGRlc2lyZWRfZ2lkLCBkZXNpcmVkX21vZGUpOgogICAgZm9yIGZpZWxkLCB2YWx1ZSBpbiAoKCJ1aWQiLCBkZXNpcmVkX3VpZCksICgiZ2lkIiwgZGVzaXJlZF9naWQpLCAoIm1vZGUiLCBkZXNpcmVkX21vZGUpKToKICAgICAgICBpZiBpc2luc3RhbmNlKHZhbHVlLCBib29sKSBvciBub3QgaXNpbnN0YW5jZSh2YWx1ZSwgaW50KToKICAgICAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcihmIntmaWVsZH0gbXVzdCBiZSBpbnRlZ2VyIikKICAgIGlmIG5vdCBpc2luc3RhbmNlKGRlc2lyZWRfYnl0ZXMsIChieXRlcywgYnl0ZWFycmF5KSk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiZGVzaXJlZCBieXRlcyBtdXN0IGJlIGJ5dGVzIikKICAgIHRlbXBfbmFtZSA9IGYiLnt0YXJnZXRfbmFtZX0udG1wLntvcy5nZXRwaWQoKX0ue3NlY3JldHMudG9rZW5faGV4KDgpfSIKICAgIGZsYWdzID0gb3MuT19DUkVBVCB8IG9zLk9fRVhDTCB8IG9zLk9fUkRXUiB8IGdldGF0dHIob3MsICJPX0NMT0VYRUMiLCAwKSB8IGdldGF0dHIob3MsICJPX05PRk9MTE9XIiwgMCkKICAgIGZkID0gb3Mub3Blbih0ZW1wX25hbWUsIGZsYWdzLCAwbzAwMCwgZGlyX2ZkPWRpcl9mZCkKICAgIGtlZXAgPSBGYWxzZQogICAgdHJ5OgogICAgICAgIF93cml0ZV9hbGwoZmQsIGRlc2lyZWRfYnl0ZXMpCiAgICAgICAgb3MuZnN5bmMoZmQpCiAgICAgICAgb3MuZmNob3duKGZkLCBkZXNpcmVkX3VpZCwgZGVzaXJlZF9naWQpCiAgICAgICAgb3MuZmNobW9kKGZkLCBkZXNpcmVkX21vZGUpCiAgICAgICAgcHJlcGFyZWQgPSBfaWRlbnRpdHlfZnJvbV9mZChmZCkKICAgICAgICBpZiAoCiAgICAgICAgICAgIHByZXBhcmVkLmZpbGVfdHlwZSAhPSBzdGF0LlNfSUZSRUcKICAgICAgICAgICAgb3IgcHJlcGFyZWQuc3RfbmxpbmsgIT0gMQogICAgICAgICAgICBvciBwcmVwYXJlZC51aWQgIT0gZGVzaXJlZF91aWQKICAgICAgICAgICAgb3IgcHJlcGFyZWQuZ2lkICE9IGRlc2lyZWRfZ2lkCiAgICAgICAgICAgIG9yIHByZXBhcmVkLm1vZGUgIT0gZGVzaXJlZF9tb2RlCiAgICAgICAgICAgIG9yIHByZXBhcmVkLnJhd19ieXRlcyAhPSBieXRlcyhkZXNpcmVkX2J5dGVzKQogICAgICAgICk6CiAgICAgICAgICAgIHJhaXNlIE9TRXJyb3IoZXJybm8uRUlPLCAicHJlcGFyZWQgdGVtcCB2ZXJpZmljYXRpb24gZmFpbGVkIikKICAgICAgICBrZWVwID0gVHJ1ZQogICAgICAgIHJldHVybiB0ZW1wX25hbWUsIHByZXBhcmVkCiAgICBmaW5hbGx5OgogICAgICAgIG9zLmNsb3NlKGZkKQogICAgICAgIGlmIG5vdCBrZWVwOgogICAgICAgICAgICBfdW5saW5rX2lmX2V4aXN0cyhkaXJfZmQsIHRlbXBfbmFtZSkKCgpkZWYgX3JldmFsaWRhdGVfcHJlc3RhdGUoZGlyX2ZkLCB0YXJnZXRfbmFtZSwgcHJlc3RhdGUpOgogICAgdHJ5OgogICAgICAgIGN1cnJlbnQgPSBfc25hcHNob3RfbmFtZShkaXJfZmQsIHRhcmdldF9uYW1lLCBhbGxvd19hYnNlbnQ9VHJ1ZSkKICAgIGV4Y2VwdCBQcmVjb25kaXRpb25FcnJvciBhcyBleGM6CiAgICAgICAgIyBUaGUgdGFyZ2V0IHdhcyB2YWxpZCB3aGVuIHByZXN0YXRlIHdhcyBjYXB0dXJlZC4gQmVjb21pbmcgbWlzc2luZywKICAgICAgICAjIHN5bWxpbmsvc3BlY2lhbC9oYXJkbGlua2VkL3VucmVhZGFibGUgYmVmb3JlIHJlbmFtZSBpcyB0aGVyZWZvcmUgZHJpZnQsCiAgICAgICAgIyBub3QgYSBmcmVzaCBpbml0aWFsLW9iamVjdCBjbGFzc2lmaWNhdGlvbi4KICAgICAgICByYWlzZSBQcmVjb25kaXRpb25FcnJvcigicGVyc2lzdGVudDpkcmlmdC1iZWZvcmUtcmVuYW1lIiwgdGFyZ2V0X25hbWUpIGZyb20gZXhjCiAgICBpZiBjdXJyZW50ICE9IHByZXN0YXRlOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJwZXJzaXN0ZW50OmRyaWZ0LWJlZm9yZS1yZW5hbWUiLCB0YXJnZXRfbmFtZSkKCgpkZWYgX2ZzeW5jX2RpcihkaXJfZmQpOgogICAgb3MuZnN5bmMoZGlyX2ZkKQoKCmRlZiBfdmVyaWZ5X2F0dGVtcHRfaWRlbnRpdHkoZGlyX2ZkLCB0YXJnZXRfbmFtZSwgYXR0ZW1wdF9pZGVudGl0eSk6CiAgICBjdXJyZW50ID0gX3NuYXBzaG90X25hbWUoZGlyX2ZkLCB0YXJnZXRfbmFtZSwgYWxsb3dfYWJzZW50PUZhbHNlKQogICAgaWYgY3VycmVudCAhPSBhdHRlbXB0X2lkZW50aXR5OgogICAgICAgIHJhaXNlIE9TRXJyb3IoZXJybm8uRUlPLCAicG9zdC1yZW5hbWUgaWRlbnRpdHkgbWlzbWF0Y2giKQogICAgcmV0dXJuIGN1cnJlbnQKCgpkZWYgX3Jlc3RvcmVkX3N0YXRlX21hdGNoZXMoY3VycmVudCwgcHJlc3RhdGUpOgogICAgaWYgbm90IGN1cnJlbnQuZXhpc3RzIG9yIG5vdCBwcmVzdGF0ZS5leGlzdHM6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICByZXR1cm4gKAogICAgICAgIGN1cnJlbnQuZmlsZV90eXBlID09IHN0YXQuU19JRlJFRwogICAgICAgIGFuZCBjdXJyZW50LnN0X25saW5rID09IDEKICAgICAgICBhbmQgY3VycmVudC51aWQgPT0gcHJlc3RhdGUudWlkCiAgICAgICAgYW5kIGN1cnJlbnQuZ2lkID09IHByZXN0YXRlLmdpZAogICAgICAgIGFuZCBjdXJyZW50Lm1vZGUgPT0gcHJlc3RhdGUubW9kZQogICAgICAgIGFuZCBjdXJyZW50LnJhd19ieXRlcyA9PSBwcmVzdGF0ZS5yYXdfYnl0ZXMKICAgICkKCgpkZWYgY29tcGVuc2F0ZV9wZXJzaXN0ZW50KHN0YXRlKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKHN0YXRlLCBQZXJzaXN0ZW50TXV0YXRpb25TdGF0ZSk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiaW52YWxpZCBwZXJzaXN0ZW50IG11dGF0aW9uIHN0YXRlIikKICAgIHRhcmdldCA9IFB1cmVQb3NpeFBhdGgoc3RhdGUudGFyZ2V0X3BhdGgpCiAgICB0cnk6CiAgICAgICAgZGlyX2ZkID0gX29wZW5fZGlyX25vZm9sbG93KHN0cih0YXJnZXQucGFyZW50KSkKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgIHJhaXNlIENvbXBlbnNhdGlvbkVycm9yKCJwZXJzaXN0ZW50OmNvbXBlbnNhdGlvbi1kaXJlY3RvcnktdW5hdmFpbGFibGUiKSBmcm9tIGV4YwogICAgdGVtcF9uYW1lID0gTm9uZQogICAgdHJ5OgogICAgICAgIHRyeToKICAgICAgICAgICAgY3VycmVudCA9IF9zbmFwc2hvdF9uYW1lKGRpcl9mZCwgdGFyZ2V0Lm5hbWUsIGFsbG93X2Fic2VudD1GYWxzZSkKICAgICAgICBleGNlcHQgUHJlY29uZGl0aW9uRXJyb3IgYXMgZXhjOgogICAgICAgICAgICByYWlzZSBDb21wZW5zYXRpb25FcnJvcigicGVyc2lzdGVudDpvd25lcnNoaXAtZHJpZnQiKSBmcm9tIGV4YwogICAgICAgIGlmIGN1cnJlbnQgIT0gc3RhdGUuYXR0ZW1wdF93cml0dGVuX2lkZW50aXR5OgogICAgICAgICAgICByYWlzZSBDb21wZW5zYXRpb25FcnJvcigicGVyc2lzdGVudDpvd25lcnNoaXAtZHJpZnQiKQoKICAgICAgICBpZiBzdGF0ZS5wcmVzdGF0ZS5leGlzdHM6CiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHRlbXBfbmFtZSwgXyA9IF9wcmVwYXJlX3RlbXAoCiAgICAgICAgICAgICAgICAgICAgZGlyX2ZkLAogICAgICAgICAgICAgICAgICAgIHRhcmdldC5uYW1lLAogICAgICAgICAgICAgICAgICAgIHN0YXRlLnByZXN0YXRlLnJhd19ieXRlcywKICAgICAgICAgICAgICAgICAgICBzdGF0ZS5wcmVzdGF0ZS51aWQsCiAgICAgICAgICAgICAgICAgICAgc3RhdGUucHJlc3RhdGUuZ2lkLAogICAgICAgICAgICAgICAgICAgIHN0YXRlLnByZXN0YXRlLm1vZGUsCiAgICAgICAgICAgICAgICApCiAgICAgICAgICAgICAgICAjIE93bmVyc2hpcCBpcyBjaGVja2VkIGFnYWluIGltbWVkaWF0ZWx5IGJlZm9yZSB0aGUgZGVzdHJ1Y3RpdmUgcmVuYW1lLgogICAgICAgICAgICAgICAgY3VycmVudCA9IF9zbmFwc2hvdF9uYW1lKGRpcl9mZCwgdGFyZ2V0Lm5hbWUsIGFsbG93X2Fic2VudD1GYWxzZSkKICAgICAgICAgICAgICAgIGlmIGN1cnJlbnQgIT0gc3RhdGUuYXR0ZW1wdF93cml0dGVuX2lkZW50aXR5OgogICAgICAgICAgICAgICAgICAgIHJhaXNlIENvbXBlbnNhdGlvbkVycm9yKCJwZXJzaXN0ZW50Om93bmVyc2hpcC1kcmlmdCIpCiAgICAgICAgICAgICAgICBvcy5yZXBsYWNlKHRlbXBfbmFtZSwgdGFyZ2V0Lm5hbWUsIHNyY19kaXJfZmQ9ZGlyX2ZkLCBkc3RfZGlyX2ZkPWRpcl9mZCkKICAgICAgICAgICAgICAgIHRlbXBfbmFtZSA9IE5vbmUKICAgICAgICAgICAgICAgIF9mc3luY19kaXIoZGlyX2ZkKQogICAgICAgICAgICAgICAgcmVzdG9yZWQgPSBfc25hcHNob3RfbmFtZShkaXJfZmQsIHRhcmdldC5uYW1lLCBhbGxvd19hYnNlbnQ9RmFsc2UpCiAgICAgICAgICAgICAgICBpZiBub3QgX3Jlc3RvcmVkX3N0YXRlX21hdGNoZXMocmVzdG9yZWQsIHN0YXRlLnByZXN0YXRlKToKICAgICAgICAgICAgICAgICAgICByYWlzZSBDb21wZW5zYXRpb25FcnJvcigicGVyc2lzdGVudDpyZXN0b3JlLXZlcmlmaWNhdGlvbi1mYWlsZWQiKQogICAgICAgICAgICBleGNlcHQgQ29tcGVuc2F0aW9uRXJyb3I6CiAgICAgICAgICAgICAgICByYWlzZQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICAgICAgICAgIHJhaXNlIENvbXBlbnNhdGlvbkVycm9yKCJwZXJzaXN0ZW50OnJlc3RvcmUtZmFpbGVkIikgZnJvbSBleGMKICAgICAgICBlbHNlOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBjdXJyZW50ID0gX3NuYXBzaG90X25hbWUoZGlyX2ZkLCB0YXJnZXQubmFtZSwgYWxsb3dfYWJzZW50PUZhbHNlKQogICAgICAgICAgICAgICAgaWYgY3VycmVudCAhPSBzdGF0ZS5hdHRlbXB0X3dyaXR0ZW5faWRlbnRpdHk6CiAgICAgICAgICAgICAgICAgICAgcmFpc2UgQ29tcGVuc2F0aW9uRXJyb3IoInBlcnNpc3RlbnQ6b3duZXJzaGlwLWRyaWZ0IikKICAgICAgICAgICAgICAgIG9zLnVubGluayh0YXJnZXQubmFtZSwgZGlyX2ZkPWRpcl9mZCkKICAgICAgICAgICAgICAgIF9mc3luY19kaXIoZGlyX2ZkKQogICAgICAgICAgICAgICAgaWYgX3NuYXBzaG90X25hbWUoZGlyX2ZkLCB0YXJnZXQubmFtZSwgYWxsb3dfYWJzZW50PVRydWUpLmV4aXN0czoKICAgICAgICAgICAgICAgICAgICByYWlzZSBDb21wZW5zYXRpb25FcnJvcigicGVyc2lzdGVudDpyZW1vdmUtdmVyaWZpY2F0aW9uLWZhaWxlZCIpCiAgICAgICAgICAgIGV4Y2VwdCBDb21wZW5zYXRpb25FcnJvcjoKICAgICAgICAgICAgICAgIHJhaXNlCiAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgICAgICAgICAgcmFpc2UgQ29tcGVuc2F0aW9uRXJyb3IoInBlcnNpc3RlbnQ6cmVtb3ZlLWZhaWxlZCIpIGZyb20gZXhjCiAgICBmaW5hbGx5OgogICAgICAgIGlmIHRlbXBfbmFtZSBpcyBub3QgTm9uZToKICAgICAgICAgICAgX3VubGlua19pZl9leGlzdHMoZGlyX2ZkLCB0ZW1wX25hbWUpCiAgICAgICAgb3MuY2xvc2UoZGlyX2ZkKQoKCmRlZiBhcHBseV9wZXJzaXN0ZW50X2NoYW5nZSh0YXJnZXRfcGF0aCwgZGVzaXJlZF9ieXRlcywgZGVzaXJlZF91aWQ9MCwgZGVzaXJlZF9naWQ9MCwgZGVzaXJlZF9tb2RlPTBvNjQ0LCBleHBlY3RlZF9wcmVzdGF0ZT1Ob25lKToKICAgICIiIkF0b21pY2FsbHkgcmVwbGFjZS9jcmVhdGUgb25lIHBlcnNpc3RlbnQgdGFyZ2V0IGFuZCByZXR1cm4gcm9sbGJhY2sgc3RhdGUuCgogICAgVGhlIGZ1bmN0aW9uIHBlcmZvcm1zIG5vIHJ1bnRpbWUgbXV0YXRpb24uIEZhaWx1cmVzIGJlZm9yZSByZW5hbWUgbGVhdmUgdGhlCiAgICB0YXJnZXQgdW50b3VjaGVkLiBGYWlsdXJlcyBhZnRlciByZW5hbWUgdHJpZ2dlciB0cmFuc2FjdGlvbi1sb2NhbCBwZXJzaXN0ZW50CiAgICBjb21wZW5zYXRpb24gYmVmb3JlIHJldHVybmluZyBhbiBlcnJvci4KICAgICIiIgogICAgaWYgbm90IGlzaW5zdGFuY2UodGFyZ2V0X3BhdGgsIHN0cikgb3Igbm90IHRhcmdldF9wYXRoLnN0YXJ0c3dpdGgoIi8iKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJ0YXJnZXQgcGF0aCBtdXN0IGJlIGFic29sdXRlIikKICAgIHRhcmdldCA9IFB1cmVQb3NpeFBhdGgodGFyZ2V0X3BhdGgpCiAgICBkaXJfZmQgPSBfb3Blbl9kaXJfbm9mb2xsb3coc3RyKHRhcmdldC5wYXJlbnQpKQogICAgdGVtcF9uYW1lID0gTm9uZQogICAgcmVuYW1lZCA9IEZhbHNlCiAgICBhdHRlbXB0X2lkZW50aXR5ID0gTm9uZQogICAgcHJlc3RhdGUgPSBOb25lCiAgICB0cnk6CiAgICAgICAgaWYgZXhwZWN0ZWRfcHJlc3RhdGUgaXMgTm9uZToKICAgICAgICAgICAgcHJlc3RhdGUgPSBfc25hcHNob3RfbmFtZShkaXJfZmQsIHRhcmdldC5uYW1lLCBhbGxvd19hYnNlbnQ9VHJ1ZSkKICAgICAgICBlbHNlOgogICAgICAgICAgICBpZiBub3QgaXNpbnN0YW5jZShleHBlY3RlZF9wcmVzdGF0ZSwgT2JqZWN0SWRlbnRpdHkpOgogICAgICAgICAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiZXhwZWN0ZWRfcHJlc3RhdGUgbXVzdCBiZSBPYmplY3RJZGVudGl0eSBvciBOb25lIikKICAgICAgICAgICAgcHJlc3RhdGUgPSBleHBlY3RlZF9wcmVzdGF0ZQogICAgICAgIHRlbXBfbmFtZSwgcHJlcGFyZWQgPSBfcHJlcGFyZV90ZW1wKGRpcl9mZCwgdGFyZ2V0Lm5hbWUsIGRlc2lyZWRfYnl0ZXMsIGRlc2lyZWRfdWlkLCBkZXNpcmVkX2dpZCwgZGVzaXJlZF9tb2RlKQogICAgICAgIF9yZXZhbGlkYXRlX3ByZXN0YXRlKGRpcl9mZCwgdGFyZ2V0Lm5hbWUsIHByZXN0YXRlKQogICAgICAgIG9zLnJlcGxhY2UodGVtcF9uYW1lLCB0YXJnZXQubmFtZSwgc3JjX2Rpcl9mZD1kaXJfZmQsIGRzdF9kaXJfZmQ9ZGlyX2ZkKQogICAgICAgIHRlbXBfbmFtZSA9IE5vbmUKICAgICAgICByZW5hbWVkID0gVHJ1ZQogICAgICAgIGF0dGVtcHRfaWRlbnRpdHkgPSBwcmVwYXJlZAogICAgICAgIHN0YXRlID0gUGVyc2lzdGVudE11dGF0aW9uU3RhdGUodGFyZ2V0X3BhdGgsIHByZXN0YXRlLCBhdHRlbXB0X2lkZW50aXR5KQogICAgICAgIHRyeToKICAgICAgICAgICAgX2ZzeW5jX2RpcihkaXJfZmQpCiAgICAgICAgICAgIF92ZXJpZnlfYXR0ZW1wdF9pZGVudGl0eShkaXJfZmQsIHRhcmdldC5uYW1lLCBhdHRlbXB0X2lkZW50aXR5KQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBjb21wZW5zYXRlX3BlcnNpc3RlbnQoc3RhdGUpCiAgICAgICAgICAgIGV4Y2VwdCBDb21wZW5zYXRpb25FcnJvciBhcyBjZXhjOgogICAgICAgICAgICAgICAgcmFpc2UgUGVyc2lzdGVudFBoYXNlRXJyb3IoCiAgICAgICAgICAgICAgICAgICAgIkZBSUxFRF9DT01QRU5TQVRJT04iLAogICAgICAgICAgICAgICAgICAgICJwZXJzaXN0ZW50OnBvc3QtcmVuYW1lLWZhaWx1cmU7Y29tcGVuc2F0aW9uOiIgKyBjZXhjLmNvZGUsCiAgICAgICAgICAgICAgICAgICAgVHJ1ZSwgYXR0ZW1wdF9pZGVudGl0eSwKICAgICAgICAgICAgICAgICkgZnJvbSBjZXhjCiAgICAgICAgICAgIHJhaXNlIFBlcnNpc3RlbnRQaGFzZUVycm9yKCJGQUlMRURfTk9UX0NPTU1JVFRFRCIsICJwZXJzaXN0ZW50OnBvc3QtcmVuYW1lLWZhaWx1cmUiLCBUcnVlLCBhdHRlbXB0X2lkZW50aXR5KSBmcm9tIGV4YwogICAgICAgIHJldHVybiBzdGF0ZQogICAgZXhjZXB0IFByZWNvbmRpdGlvbkVycm9yOgogICAgICAgIHJhaXNlCiAgICBleGNlcHQgUGVyc2lzdGVudFBoYXNlRXJyb3I6CiAgICAgICAgcmFpc2UKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgIGlmIHJlbmFtZWQgYW5kIGF0dGVtcHRfaWRlbnRpdHkgaXMgbm90IE5vbmUgYW5kIHByZXN0YXRlIGlzIG5vdCBOb25lOgogICAgICAgICAgICBzdGF0ZSA9IFBlcnNpc3RlbnRNdXRhdGlvblN0YXRlKHRhcmdldF9wYXRoLCBwcmVzdGF0ZSwgYXR0ZW1wdF9pZGVudGl0eSkKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgY29tcGVuc2F0ZV9wZXJzaXN0ZW50KHN0YXRlKQogICAgICAgICAgICBleGNlcHQgQ29tcGVuc2F0aW9uRXJyb3IgYXMgY2V4YzoKICAgICAgICAgICAgICAgIHJhaXNlIFBlcnNpc3RlbnRQaGFzZUVycm9yKAogICAgICAgICAgICAgICAgICAgICJGQUlMRURfQ09NUEVOU0FUSU9OIiwKICAgICAgICAgICAgICAgICAgICAicGVyc2lzdGVudDpwaGFzZTEtZmFpbHVyZTtjb21wZW5zYXRpb246IiArIGNleGMuY29kZSwKICAgICAgICAgICAgICAgICAgICBUcnVlLCBhdHRlbXB0X2lkZW50aXR5LAogICAgICAgICAgICAgICAgKSBmcm9tIGNleGMKICAgICAgICAgICAgcmFpc2UgUGVyc2lzdGVudFBoYXNlRXJyb3IoIkZBSUxFRF9OT1RfQ09NTUlUVEVEIiwgInBlcnNpc3RlbnQ6cGhhc2UxLWZhaWx1cmUiLCBUcnVlLCBhdHRlbXB0X2lkZW50aXR5KSBmcm9tIGV4YwogICAgICAgIHJhaXNlIFBlcnNpc3RlbnRQaGFzZUVycm9yKCJGQUlMRURfTk9UX0NPTU1JVFRFRCIsICJwZXJzaXN0ZW50OnBoYXNlMS1iZWZvcmUtcmVuYW1lIiwgRmFsc2UsIE5vbmUpIGZyb20gZXhjCiAgICBmaW5hbGx5OgogICAgICAgIGlmIHRlbXBfbmFtZSBpcyBub3QgTm9uZToKICAgICAgICAgICAgX3VubGlua19pZl9leGlzdHMoZGlyX2ZkLCB0ZW1wX25hbWUpCiAgICAgICAgb3MuY2xvc2UoZGlyX2ZkKQoKCmRlZiByZWFkX3J1bnRpbWVfcGF0aChwYXRoKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKHBhdGgsIHN0cikgb3Igbm90IHBhdGguc3RhcnRzd2l0aCgiLyIpOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoInJ1bnRpbWUgcGF0aCBtdXN0IGJlIGFic29sdXRlIikKICAgIGZsYWdzID0gb3MuT19SRE9OTFkgfCBnZXRhdHRyKG9zLCAiT19DTE9FWEVDIiwgMCkgfCBnZXRhdHRyKG9zLCAiT19OT0ZPTExPVyIsIDApCiAgICBmZCA9IG9zLm9wZW4ocGF0aCwgZmxhZ3MpCiAgICB0cnk6CiAgICAgICAgY2h1bmtzID0gW10KICAgICAgICB3aGlsZSBUcnVlOgogICAgICAgICAgICBjaHVuayA9IG9zLnJlYWQoZmQsIDQwOTYpCiAgICAgICAgICAgIGlmIG5vdCBjaHVuazoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIGNodW5rcy5hcHBlbmQoY2h1bmspCiAgICAgICAgcmV0dXJuIHBhcnNlX2ludGVnZXJfYnl0ZXMoYiIiLmpvaW4oY2h1bmtzKSkKICAgIGZpbmFsbHk6CiAgICAgICAgb3MuY2xvc2UoZmQpCgoKZGVmIHdyaXRlX3J1bnRpbWVfcGF0aChwYXRoLCB2YWx1ZSk6CiAgICBpZiBub3QgaXNpbnN0YW5jZShwYXRoLCBzdHIpIG9yIG5vdCBwYXRoLnN0YXJ0c3dpdGgoIi8iKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJydW50aW1lIHBhdGggbXVzdCBiZSBhYnNvbHV0ZSIpCiAgICBkYXRhID0gY2Fub25pY2FsX2ludGVnZXIodmFsdWUpLmVuY29kZSgiYXNjaWkiKQogICAgZmxhZ3MgPSBvcy5PX1dST05MWSB8IGdldGF0dHIob3MsICJPX0NMT0VYRUMiLCAwKSB8IGdldGF0dHIob3MsICJPX05PRk9MTE9XIiwgMCkKICAgIHRyeToKICAgICAgICBmZCA9IG9zLm9wZW4ocGF0aCwgZmxhZ3MpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICByYWlzZSBSdW50aW1lV3JpdGVFcnJvcigicnVudGltZTp3cml0ZS1mYWlsdXJlIiwgRmFsc2UpIGZyb20gZXhjCgogICAgd3JpdGVfc3RhcnRlZCA9IEZhbHNlCiAgICBjbG9zZWQgPSBGYWxzZQogICAgdHJ5OgogICAgICAgIHZpZXcgPSBtZW1vcnl2aWV3KGRhdGEpCiAgICAgICAgb2Zmc2V0ID0gMAogICAgICAgIHdoaWxlIG9mZnNldCA8IGxlbih2aWV3KToKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgd3JpdHRlbiA9IG9zLndyaXRlKGZkLCB2aWV3W29mZnNldDpdKQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVXcml0ZUVycm9yKCJydW50aW1lOndyaXRlLWZhaWx1cmUiLCB3cml0ZV9zdGFydGVkKSBmcm9tIGV4YwogICAgICAgICAgICBpZiB3cml0dGVuIDw9IDA6CiAgICAgICAgICAgICAgICByYWlzZSBSdW50aW1lV3JpdGVFcnJvcigicnVudGltZTp3cml0ZS1mYWlsdXJlIiwgd3JpdGVfc3RhcnRlZCkKICAgICAgICAgICAgd3JpdGVfc3RhcnRlZCA9IFRydWUKICAgICAgICAgICAgb2Zmc2V0ICs9IHdyaXR0ZW4KICAgICAgICB0cnk6CiAgICAgICAgICAgIG9zLmNsb3NlKGZkKQogICAgICAgICAgICBjbG9zZWQgPSBUcnVlCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVXcml0ZUVycm9yKCJydW50aW1lOndyaXRlLWZhaWx1cmUiLCB3cml0ZV9zdGFydGVkKSBmcm9tIGV4YwogICAgZmluYWxseToKICAgICAgICBpZiBub3QgY2xvc2VkOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBvcy5jbG9zZShmZCkKICAgICAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgICAgIHBhc3MKCgpkZWYgZXhlY3V0ZV9ydW50aW1lX3BoYXNlKG9wLCB0YXJnZXRfdmFsdWUsIHJlYWRfdmFsdWUsIHdyaXRlX3ZhbHVlLCAqLCB3cml0ZXJfcHJvdG9jb2w9Tm9uZSwgcHJlX3dyaXRlX2d1YXJkPU5vbmUpOgogICAgIiIiRXhlY3V0ZSB0aGUgc2luZ2xlLXdyaXRlIHJ1bnRpbWUgcGhhc2UgdXNpbmcgaW5qZWN0ZWQgcmVhZC93cml0ZSBjYWxsYWJsZXMuCgogICAgTG93LWxldmVsIGNhbGxlcnMgbWF5IG9taXQgYGB3cml0ZXJfcHJvdG9jb2xgYCBmb3IgZGlyZWN0IHVuaXQgdGVzdGluZy4gVGhlCiAgICBwcm9kdWN0LWxldmVsIGV4ZWN1dGVfY29udHJvbCBib3VuZGFyeSBhbHdheXMgc3VwcGxpZXMKICAgIFNMUF9SVU5USU1FX1dSSVRFUl9WMS4gQSBkZWNsYXJlZCBWMSB3cml0ZXIgbXVzdCByZXBvcnQgZmFpbGVkLXdyaXRlCiAgICBwcm9ncmVzcyB3aXRoIFJ1bnRpbWVXcml0ZUVycm9yOyBhIGdlbmVyaWMgZXhjZXB0aW9uIGlzIGFuIGludGVyZmFjZQogICAgdmlvbGF0aW9uIGFuZCBpcyBkZWxpYmVyYXRlbHkgbm90IG5vcm1hbGl6ZWQgaW50byBhIGZhbHNlIG5vLW11dGF0aW9uIGZhY3QuCiAgICAiIiIKICAgIGlmIHdyaXRlcl9wcm90b2NvbCBub3QgaW4gKE5vbmUsIFJVTlRJTUVfV1JJVEVSX1BST1RPQ09MX1YxKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJ1bnN1cHBvcnRlZCBydW50aW1lIHdyaXRlciBwcm90b2NvbCIpCiAgICBpZiBvcCBub3QgaW4gU1VQUE9SVEVEX09QUzoKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJ1bnN1cHBvcnRlZCBvcCIpCiAgICBfcmVxdWlyZV9pbnQodGFyZ2V0X3ZhbHVlLCAidGFyZ2V0X3ZhbHVlIikKICAgIGlmIG5vdCBjYWxsYWJsZShyZWFkX3ZhbHVlKSBvciBub3QgY2FsbGFibGUod3JpdGVfdmFsdWUpOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoInJ1bnRpbWUgY2FsbGJhY2tzIG11c3QgYmUgY2FsbGFibGUiKQogICAgaWYgcHJlX3dyaXRlX2d1YXJkIGlzIG5vdCBOb25lIGFuZCBub3QgY2FsbGFibGUocHJlX3dyaXRlX2d1YXJkKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJydW50aW1lIHByZS13cml0ZSBndWFyZCBtdXN0IGJlIGNhbGxhYmxlIikKICAgIHRyeToKICAgICAgICBwcmV3cml0ZSA9IF9yZXF1aXJlX2ludChyZWFkX3ZhbHVlKCksICJydW50aW1lX3ByZXdyaXRlIikKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgIHJhaXNlIFJ1bnRpbWVQaGFzZUVycm9yKCJydW50aW1lOnByZXdyaXRlLWZhaWx1cmUiKSBmcm9tIGV4YwoKICAgIGlmIHJ1bnRpbWVfaXNfY29tcGxpYW50KG9wLCBwcmV3cml0ZSwgdGFyZ2V0X3ZhbHVlKToKICAgICAgICByZXR1cm4gUnVudGltZVBoYXNlUmVzdWx0KHByZXdyaXRlLCBOb25lLCBwcmV3cml0ZSwgRmFsc2UpCgogICAgaWYgcHJlX3dyaXRlX2d1YXJkIGlzIG5vdCBOb25lOgogICAgICAgIHRyeToKICAgICAgICAgICAgcHJlX3dyaXRlX2d1YXJkKCkKICAgICAgICBleGNlcHQgUHJlY29uZGl0aW9uRXJyb3IgYXMgZXhjOgogICAgICAgICAgICByYWlzZSBSdW50aW1lTXV0YXRpb25QcmVjb25kaXRpb25FcnJvcihzdHIoZXhjKSwgcHJld3JpdGUpIGZyb20gZXhjCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgICAgIHJhaXNlIFJ1bnRpbWVNdXRhdGlvblByZWNvbmRpdGlvbkVycm9yKAogICAgICAgICAgICAgICAgInBlcnNpc3RlbnQ6cHJld3JpdGUtcmV2YWxpZGF0aW9uLWZhaWx1cmUiLCBwcmV3cml0ZQogICAgICAgICAgICApIGZyb20gZXhjCgogICAgdHJ5OgogICAgICAgIHdyaXRlX3ZhbHVlKHRhcmdldF92YWx1ZSkKICAgIGV4Y2VwdCBSdW50aW1lV3JpdGVFcnJvciBhcyBleGM6CiAgICAgICAgcmFpc2UgUnVudGltZVBoYXNlRXJyb3IoCiAgICAgICAgICAgICJydW50aW1lOndyaXRlLWZhaWx1cmUiLCBwcmV3cml0ZSwgTm9uZSwgVHJ1ZSwKICAgICAgICAgICAgZXhjLndyaXRlX3N0YXJ0ZWQsIHRhcmdldF92YWx1ZSBpZiBleGMud3JpdGVfc3RhcnRlZCBlbHNlIE5vbmUsCiAgICAgICAgKSBmcm9tIGV4YwogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgaWYgd3JpdGVyX3Byb3RvY29sID09IFJVTlRJTUVfV1JJVEVSX1BST1RPQ09MX1YxOgogICAgICAgICAgICByYWlzZSBSdW50aW1lV3JpdGVyUHJvdG9jb2xWaW9sYXRpb24oInJ1bnRpbWU6d3JpdGVyLXByb3RvY29sLXZpb2xhdGlvbiIpIGZyb20gZXhjCiAgICAgICAgIyBMZWdhY3kgbG93LWxldmVsIHRlc3QgbW9kZTogd2l0aG91dCBhIGRlY2xhcmVkIHByb2R1Y3Qgd3JpdGVyIHByb3RvY29sCiAgICAgICAgIyBvbmx5IHRoZSBhdHRlbXB0ZWQgY2FsbCBpcyBrbm93YWJsZS4gUHJvZHVjdCBleGVjdXRpb24gbmV2ZXIgdXNlcyB0aGlzCiAgICAgICAgIyBicmFuY2guCiAgICAgICAgcmFpc2UgUnVudGltZVBoYXNlRXJyb3IoInJ1bnRpbWU6d3JpdGUtZmFpbHVyZSIsIHByZXdyaXRlLCBOb25lLCBUcnVlLCBGYWxzZSwgTm9uZSkgZnJvbSBleGMKCiAgICB0cnk6CiAgICAgICAgYWZ0ZXIgPSBfcmVxdWlyZV9pbnQocmVhZF92YWx1ZSgpLCAicnVudGltZV9hZnRlciIpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICByYWlzZSBSdW50aW1lUGhhc2VFcnJvcigicnVudGltZTpwb3N0Y2hlY2stcmVhZC1mYWlsdXJlIiwgcHJld3JpdGUsIE5vbmUsIFRydWUsIFRydWUsIHRhcmdldF92YWx1ZSkgZnJvbSBleGMKICAgIGlmIG5vdCBydW50aW1lX2lzX2NvbXBsaWFudChvcCwgYWZ0ZXIsIHRhcmdldF92YWx1ZSk6CiAgICAgICAgcmFpc2UgUnVudGltZVBoYXNlRXJyb3IoInJ1bnRpbWU6cG9zdGNoZWNrLW5vbmNvbXBsaWFudCIsIHByZXdyaXRlLCBhZnRlciwgVHJ1ZSwgVHJ1ZSwgdGFyZ2V0X3ZhbHVlKQogICAgcmV0dXJuIFJ1bnRpbWVQaGFzZVJlc3VsdChwcmV3cml0ZSwgdGFyZ2V0X3ZhbHVlLCBhZnRlciwgVHJ1ZSkKCgpPVVRDT01FX0FQUExJRUQgPSAiQVBQTElFRCIKT1VUQ09NRV9BTFJFQURZX0NPTVBMSUFOVCA9ICJBTFJFQURZX0NPTVBMSUFOVCIKT1VUQ09NRV9OT1RfQVBQTElDQUJMRSA9ICJOT1RfQVBQTElDQUJMRV9LRVlfQUJTRU5UIgpPVVRDT01FX0FCT1JUX0NPTkZMSUNUID0gIkFCT1JURURfUFJFQ09ORElUSU9OX0NPTkZMSUNUIgpPVVRDT01FX0FCT1JUX09USEVSID0gIkFCT1JURURfUFJFQ09ORElUSU9OX09USEVSIgpPVVRDT01FX0ZBSUxFRF9OT1RfQ09NTUlUVEVEID0gIkZBSUxFRF9OT1RfQ09NTUlUVEVEIgpPVVRDT01FX0ZBSUxFRF9DT01QRU5TQVRJT04gPSAiRkFJTEVEX0NPTVBFTlNBVElPTiIKT1VUQ09NRV9EUllfUlVOX1dPVUxEX0FQUExZID0gIkRSWV9SVU5fV09VTERfQVBQTFkiCkNPTU1JVF9DT01NSVRURUQgPSAiQ09NTUlUVEVEIgpDT01NSVRfTk9UX0NPTU1JVFRFRCA9ICJOT1RfQ09NTUlUVEVEIgpDT01NSVRfTk9UX1NUQVJURUQgPSAiTk9UX1NUQVJURUQiCgoKQGRhdGFjbGFzcyhmcm96ZW49VHJ1ZSkKY2xhc3MgQ29udHJvbEV4ZWN1dGlvblJlc3VsdDoKICAgIGNvbnRyb2xfaWQ6IHN0cgogICAga2V5OiBzdHIKICAgIG9wOiBzdHIKICAgIGV4cGVjdGVkOiBpbnQKICAgIGVsaWdpYmxlOiBib29sCiAgICBvdXRjb21lOiBzdHIKICAgIHJlYXNvbjogc3RyCiAgICBicmFuY2g6IHN0ciB8IE5vbmUKICAgIHRhcmdldF92YWx1ZTogaW50IHwgTm9uZQogICAgZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWU6IGludCB8IE5vbmUKICAgIHJ1bnRpbWVfYmVmb3JlOiBpbnQgfCBOb25lCiAgICBydW50aW1lX3ByZXdyaXRlOiBpbnQgfCBOb25lCiAgICBydW50aW1lX2FmdGVyOiBpbnQgfCBOb25lCiAgICBwZXJzaXN0ZW50X2JlZm9yZTogT2JqZWN0SWRlbnRpdHkgfCBOb25lCiAgICBwZXJzaXN0ZW50X2FmdGVyOiBPYmplY3RJZGVudGl0eSB8IE5vbmUKICAgIHdyaXR0ZW5fdmFsdWU6IGludCB8IE5vbmUKICAgIGFjdGlvbnNfYXR0ZW1wdGVkOiB0dXBsZQogICAgbXV0YXRpb25fcGVyZm9ybWVkOiBib29sCiAgICB0cmFuc2FjdGlvbl9jb21taXQ6IHN0cgogICAgYXR0ZW1wdF93cml0dGVuX2lkZW50aXR5OiBPYmplY3RJZGVudGl0eSB8IE5vbmUKICAgIGRyeV9ydW46IGJvb2wKCgpkZWYgX3Jlc3VsdChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgZWxpZ2libGUsIG91dGNvbWUsIHJlYXNvbiwgKiwgYnJhbmNoPU5vbmUsCiAgICAgICAgICAgIHRhcmdldF92YWx1ZT1Ob25lLCBlZmZlY3RpdmVfZm9yZWlnbl92YWx1ZT1Ob25lLCBydW50aW1lX2JlZm9yZT1Ob25lLAogICAgICAgICAgICBydW50aW1lX3ByZXdyaXRlPU5vbmUsIHJ1bnRpbWVfYWZ0ZXI9Tm9uZSwgcGVyc2lzdGVudF9iZWZvcmU9Tm9uZSwKICAgICAgICAgICAgcGVyc2lzdGVudF9hZnRlcj1Ob25lLCB3cml0dGVuX3ZhbHVlPU5vbmUsIGFjdGlvbnM9KCksIG11dGF0aW9uPUZhbHNlLAogICAgICAgICAgICBjb21taXQ9Q09NTUlUX05PVF9TVEFSVEVELCBhdHRlbXB0X2lkZW50aXR5PU5vbmUsIGRyeV9ydW49RmFsc2UpOgogICAgcmV0dXJuIENvbnRyb2xFeGVjdXRpb25SZXN1bHQoCiAgICAgICAgY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIGVsaWdpYmxlLCBvdXRjb21lLCByZWFzb24sIGJyYW5jaCwgdGFyZ2V0X3ZhbHVlLAogICAgICAgIGVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlLCBydW50aW1lX2JlZm9yZSwgcnVudGltZV9wcmV3cml0ZSwgcnVudGltZV9hZnRlciwKICAgICAgICBwZXJzaXN0ZW50X2JlZm9yZSwgcGVyc2lzdGVudF9hZnRlciwgd3JpdHRlbl92YWx1ZSwgdHVwbGUoYWN0aW9ucyksIGJvb2wobXV0YXRpb24pLAogICAgICAgIGNvbW1pdCwgYXR0ZW1wdF9pZGVudGl0eSwgYm9vbChkcnlfcnVuKSwKICAgICkKCgpkZWYgcGFyc2Vfc3lzY3RsX2Fzc2lnbm1lbnRfbGluZShsaW5lLCBsaW5lX25vKToKICAgICIiIlBhcnNlIG9uZSBjb250cmFjdC1kZWZpbmVkIGV4cGxpY2l0IHN5c2N0bCBhc3NpZ25tZW50LgoKICAgIFJlY29nbml6ZWQgYXNzaWdubWVudCBmb3JtcyBhcmUgYGBrZXkgPSB2YWx1ZWBgIGFuZCBgYC1rZXkgPSB2YWx1ZWBgLgogICAgVGhlIGxlYWRpbmcgJy0nIGluIHRoZSBsYXR0ZXIgbWVhbnMgImlnbm9yZSB3cml0ZSBlcnJvciIgdG8gcHJvY3BzOyBpdCBkb2VzCiAgICBub3QgY2hhbmdlIHByZWNlZGVuY2Ugc2VtYW50aWNzIGhlcmUgYW5kIHRoZXJlZm9yZSBpcyBpbnRlbnRpb25hbGx5IG5vdAogICAgc3RvcmVkLiBBIGJhcmUgYGAta2V5YGAgbGluZSBoYXMgbm8gJz0nIGFuZCBpcyBhbiBleGNsdXNpb24vZ2xvYiBkaXJlY3RpdmUsCiAgICBzbyBpdCByZXR1cm5zIE5vbmUgYW5kIGNhbiBuZXZlciBiZWNvbWUgYW4gRXhwbGljaXRBc3NpZ25tZW50LiBMaW5lcyB3aG9zZQogICAgbGVmdCBzaWRlIGNvbnRhaW5zIGdsb2IgbWV0YWNoYXJhY3RlcnMgYXJlIG91dHNpZGUgdGhlIHByb3ZlZCBtZWNoYW5pc20KICAgIGd1YXJhbnRlZSBhbmQgYWxzbyByZXR1cm4gTm9uZS4KICAgICIiIgogICAgaWYgaXNpbnN0YW5jZShsaW5lLCAoYnl0ZXMsIGJ5dGVhcnJheSkpOgogICAgICAgIHRyeToKICAgICAgICAgICAgbGluZSA9IGJ5dGVzKGxpbmUpLmRlY29kZSgidXRmLTgiKQogICAgICAgIGV4Y2VwdCBVbmljb2RlRGVjb2RlRXJyb3IgYXMgZXhjOgogICAgICAgICAgICByYWlzZSBQcmVjb25kaXRpb25FcnJvcigic291cmNlOmludmFsaWQtZW5jb2RpbmciKSBmcm9tIGV4YwogICAgaWYgbm90IGlzaW5zdGFuY2UobGluZSwgc3RyKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJzb3VyY2UgbGluZSBtdXN0IGJlIHRleHQgb3IgYnl0ZXMiKQogICAgaWYgaXNpbnN0YW5jZShsaW5lX25vLCBib29sKSBvciBub3QgaXNpbnN0YW5jZShsaW5lX25vLCBpbnQpIG9yIGxpbmVfbm8gPCAxOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoImludmFsaWQgbGluZSBudW1iZXIiKQogICAgc3RyaXBwZWQgPSBsaW5lLnN0cmlwKCkKICAgIGlmIG5vdCBzdHJpcHBlZCBvciBzdHJpcHBlZC5zdGFydHN3aXRoKCIjIikgb3Igc3RyaXBwZWQuc3RhcnRzd2l0aCgiOyIpIG9yICI9IiBub3QgaW4gc3RyaXBwZWQ6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGxlZnQsIHJpZ2h0ID0gc3RyaXBwZWQuc3BsaXQoIj0iLCAxKQogICAgbGVmdCA9IGxlZnQuc3RyaXAoKQogICAgcmlnaHQgPSByaWdodC5zdHJpcCgpCiAgICBpZiBsZWZ0LnN0YXJ0c3dpdGgoIi0iKToKICAgICAgICBsZWZ0ID0gbGVmdFsxOl0uc3RyaXAoKQogICAgaWYgbm90IGxlZnQgb3IgYW55KGNoIGluIGxlZnQgZm9yIGNoIGluICIqP1tdIik6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIHRyeToKICAgICAgICBub3JtYWxpemVfc291cmNlX2tleShsZWZ0KQogICAgZXhjZXB0IENvbnRyYWN0RXJyb3IgYXMgZXhjOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJzb3VyY2U6aW52YWxpZC1rZXkiKSBmcm9tIGV4YwogICAgcmV0dXJuIEV4cGxpY2l0QXNzaWdubWVudChsZWZ0LCByaWdodCwgbGluZV9ubykKCgpkZWYgcGFyc2Vfc3lzY3RsX3NvdXJjZV9ieXRlcyhyYXcsIGxvZ2ljYWxfcGF0aCk6CiAgICAiIiJQYXJzZSBleHBsaWNpdCBhc3NpZ25tZW50cyBmcm9tIG9uZSBzb3VyY2UgZmlsZSB3aXRob3V0IG11dGF0aW9uLiIiIgogICAgaWYgbm90IGlzaW5zdGFuY2UocmF3LCAoYnl0ZXMsIGJ5dGVhcnJheSkpOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoInNvdXJjZSBieXRlcyBtdXN0IGJlIGJ5dGVzIikKICAgIGFzc2lnbm1lbnRzID0gW10KICAgIGZvciBsaW5lX25vLCBsaW5lIGluIGVudW1lcmF0ZShieXRlcyhyYXcpLnNwbGl0bGluZXMoKSwgMSk6CiAgICAgICAgYXNzaWdubWVudCA9IHBhcnNlX3N5c2N0bF9hc3NpZ25tZW50X2xpbmUobGluZSwgbGluZV9ubykKICAgICAgICBpZiBhc3NpZ25tZW50IGlzIG5vdCBOb25lOgogICAgICAgICAgICBhc3NpZ25tZW50cy5hcHBlbmQoYXNzaWdubWVudCkKICAgIHJldHVybiBTb3VyY2VGaWxlKGxvZ2ljYWxfcGF0aCwgdHVwbGUoYXNzaWdubWVudHMpKQoKCmRlZiBfcm9vdGVkX3NvdXJjZV9wYXRoKHJvb3QsIGxvZ2ljYWxfcGF0aCk6CiAgICByb290ID0gb3MuZnNwYXRoKHJvb3QpCiAgICBpZiBub3Qgb3MucGF0aC5pc2Ficyhyb290KToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJzb3VyY2Ugcm9vdCBtdXN0IGJlIGFic29sdXRlIikKICAgIGlmIHJvb3QgPT0gIi8iOgogICAgICAgIHJldHVybiBsb2dpY2FsX3BhdGgKICAgIHJldHVybiBvcy5wYXRoLmpvaW4ocm9vdCwgbG9naWNhbF9wYXRoLmxzdHJpcCgiLyIpKQoKCmRlZiBfbG9naWNhbF9jb25mX25hbWVzKHJvb3QsIGxvZ2ljYWxfZGlyKToKICAgIHBoeXNpY2FsID0gX3Jvb3RlZF9zb3VyY2VfcGF0aChyb290LCBsb2dpY2FsX2RpcikKICAgIHRyeToKICAgICAgICB3aXRoIG9zLnNjYW5kaXIocGh5c2ljYWwpIGFzIGl0OgogICAgICAgICAgICBuYW1lcyA9IFtlbnRyeS5uYW1lIGZvciBlbnRyeSBpbiBpdCBpZiBlbnRyeS5uYW1lLmVuZHN3aXRoKCIuY29uZiIpXQogICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgIHJldHVybiAoKQogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJzb3VyY2U6dW5yZWFkYWJsZS1kaXJlY3RvcnkiLCBsb2dpY2FsX2RpcikgZnJvbSBleGMKICAgIGlmIGxlbihuYW1lcykgIT0gbGVuKHNldChuYW1lcykpOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJzb3VyY2U6ZHVwbGljYXRlLW5hbWUiLCBsb2dpY2FsX2RpcikKICAgIHJldHVybiB0dXBsZShzb3J0ZWQobmFtZXMsIGtleT1sYW1iZGEgbmFtZTogbmFtZS5lbmNvZGUoInV0Zi04IikpKQoKCmRlZiBfcmVhZF9sb2dpY2FsX3NvdXJjZShyb290LCBsb2dpY2FsX3BhdGgpOgogICAgcGh5c2ljYWwgPSBfcm9vdGVkX3NvdXJjZV9wYXRoKHJvb3QsIGxvZ2ljYWxfcGF0aCkKICAgIHRyeToKICAgICAgICBsc3QgPSBvcy5sc3RhdChwaHlzaWNhbCkKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICByYWlzZSBQcmVjb25kaXRpb25FcnJvcigic291cmNlOnVucmVhZGFibGUtc291cmNlIiwgbG9naWNhbF9wYXRoKSBmcm9tIGV4YwoKICAgIGZsYWdzID0gb3MuT19SRE9OTFkgfCBnZXRhdHRyKG9zLCAiT19DTE9FWEVDIiwgMCkgfCBnZXRhdHRyKG9zLCAiT19OT05CTE9DSyIsIDApCiAgICB0cnk6CiAgICAgICAgZmQgPSBvcy5vcGVuKHBoeXNpY2FsLCBmbGFncykKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICByYWlzZSBQcmVjb25kaXRpb25FcnJvcigic291cmNlOnVucmVhZGFibGUtc291cmNlIiwgbG9naWNhbF9wYXRoKSBmcm9tIGV4YwogICAgdHJ5OgogICAgICAgIHRyeToKICAgICAgICAgICAgc3QgPSBvcy5mc3RhdChmZCkKICAgICAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJzb3VyY2U6dW5yZWFkYWJsZS1zb3VyY2UiLCBsb2dpY2FsX3BhdGgpIGZyb20gZXhjCgogICAgICAgIGlmIHN0YXQuU19JU1JFRyhzdC5zdF9tb2RlKToKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgcmF3ID0gX3JlYWRfYWxsX2ZkKGZkKQogICAgICAgICAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgICAgICAgICByYWlzZSBQcmVjb25kaXRpb25FcnJvcigic291cmNlOnVucmVhZGFibGUtc291cmNlIiwgbG9naWNhbF9wYXRoKSBmcm9tIGV4YwogICAgICAgICAgICByZXR1cm4gcGFyc2Vfc3lzY3RsX3NvdXJjZV9ieXRlcyhyYXcsIGxvZ2ljYWxfcGF0aCkKCiAgICAgICAgIyByMTEgZ2l2ZXMgb25lIHNwZWNpYWwgc3ltbGluayBydWxlOiBhIHN5bWxpbmsgcmVzb2x2aW5nIHRvIC9kZXYvbnVsbAogICAgICAgICMgaXMgYW4gZW1wdHkgc291cmNlLiAgQWxsIG90aGVyIG5vbi1yZWd1bGFyIHJlc29sdmVkIG9iamVjdHMgZmFpbCBjbG9zZWQuCiAgICAgICAgaWYgc3RhdC5TX0lTTE5LKGxzdC5zdF9tb2RlKSBhbmQgc3RhdC5TX0lTQ0hSKHN0LnN0X21vZGUpOgogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBudWxsX3N0ID0gb3Muc3RhdCgiL2Rldi9udWxsIikKICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgICAgICAgICAgcmFpc2UgUHJlY29uZGl0aW9uRXJyb3IoInNvdXJjZTp1bnJlYWRhYmxlLXNvdXJjZSIsIGxvZ2ljYWxfcGF0aCkgZnJvbSBleGMKICAgICAgICAgICAgaWYgc3Quc3RfcmRldiA9PSBudWxsX3N0LnN0X3JkZXY6CiAgICAgICAgICAgICAgICByZXR1cm4gU291cmNlRmlsZShsb2dpY2FsX3BhdGgsICgpKQogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJzb3VyY2U6dW5yZWFkYWJsZS1zb3VyY2UiLCBsb2dpY2FsX3BhdGgpCiAgICBmaW5hbGx5OgogICAgICAgIG9zLmNsb3NlKGZkKQoKCmRlZiBfbG9hZF9zeXNjdGxfc291cmNlc19vYnNlcnZlZChjb250cm9sX2tleSwgcm9vdD0iLyIpOgogICAgIiIiUmV0dXJuIChzb3VyY2VfZmlsZXMsIG93bl9wcmVzZW50X2R1cmluZ19QMikuCgogICAgb3duX3ByZXNlbnRfZHVyaW5nX1AyIGJpbmRzIHRoZSBzYW1lLWJhc2VuYW1lIHNoYWRvd2luZyBkZWNpc2lvbiB0byB0aGUKICAgIHBlcnNpc3RlbnQgcHJlc3RhdGUgdXNlZCBmb3IgdGFyZ2V0IHBsYW5uaW5nLiBleGVjdXRlX2NvbnRyb2woKSBjb21wYXJlcyBpdAogICAgd2l0aCB0aGUgdGFyZ2V0IHNuYXBzaG90IHRha2VuIGltbWVkaWF0ZWx5IGFmdGVyIFAyIGFuZCBhYm9ydHMgb24gbWlzbWF0Y2guCiAgICAiIiIKICAgIG93bl9wYXRoID0gcGVyc2lzdGVudF9wYXRoKGNvbnRyb2xfa2V5KQogICAgb3duX2Jhc2VuYW1lID0gUHVyZVBvc2l4UGF0aChvd25fcGF0aCkubmFtZQogICAgbmFtZXNfYnlfZGlyID0ge2xvZ2ljYWxfZGlyOiBzZXQoX2xvZ2ljYWxfY29uZl9uYW1lcyhyb290LCBsb2dpY2FsX2RpcikpIGZvciBsb2dpY2FsX2RpciBpbiBTWVNDVExfRF9ESVJTfQogICAgb3duX3BhcmVudCA9IHN0cihQdXJlUG9zaXhQYXRoKG93bl9wYXRoKS5wYXJlbnQpCiAgICBvd25fcHJlc2VudCA9IG93bl9wYXJlbnQgaW4gbmFtZXNfYnlfZGlyIGFuZCBvd25fYmFzZW5hbWUgaW4gbmFtZXNfYnlfZGlyW293bl9wYXJlbnRdCiAgICBhbGxfbmFtZXMgPSBzZXQoKS51bmlvbigqbmFtZXNfYnlfZGlyLnZhbHVlcygpKSBpZiBuYW1lc19ieV9kaXIgZWxzZSBzZXQoKQogICAgcmVzdWx0ID0gW10KICAgIGZvciBiYXNlbmFtZSBpbiBzb3J0ZWQoYWxsX25hbWVzLCBrZXk9bGFtYmRhIG5hbWU6IG5hbWUuZW5jb2RlKCJ1dGYtOCIpKToKICAgICAgICBwcmVzZW50ID0gW2QgZm9yIGQgaW4gU1lTQ1RMX0RfRElSUyBpZiBiYXNlbmFtZSBpbiBuYW1lc19ieV9kaXJbZF1dCiAgICAgICAgc2VsZWN0ZWQgPSBwcmVzZW50WzBdICsgIi8iICsgYmFzZW5hbWUgaWYgcHJlc2VudCBlbHNlIE5vbmUKICAgICAgICBmb3IgbG9naWNhbF9kaXIgaW4gcHJlc2VudDoKICAgICAgICAgICAgbG9naWNhbF9wYXRoID0gbG9naWNhbF9kaXIgKyAiLyIgKyBiYXNlbmFtZQogICAgICAgICAgICBpZiBsb2dpY2FsX3BhdGggPT0gc2VsZWN0ZWQ6CiAgICAgICAgICAgICAgICAjIFRoZSBvd24gdGFyZ2V0IGlzIG9ic2VydmVkIGxhdGVyIHRocm91Z2ggc25hcHNob3RfcGVyc2lzdGVudF90YXJnZXQsCiAgICAgICAgICAgICAgICAjIHdoaWNoIHZhbGlkYXRlcyBvYmplY3QgdHlwZSB3aXRob3V0IHByZS1yZWFkaW5nIGl0LiBQMiBtdXN0IG5vdAogICAgICAgICAgICAgICAgIyBwYXJzZS9yZWFkIG93biBieXRlczogZXEgYWxsb3dzIGFuIHVucGFyc2VhYmxlIG93biBmaWxlIHRvIGJlCiAgICAgICAgICAgICAgICAjIHJlcGxhY2VkLCBhbmQgYSBGSUZPL3NwZWNpYWwgb3duIHRhcmdldCBtdXN0IGZhaWwgY2xvc2VkIHJhdGhlcgogICAgICAgICAgICAgICAgIyB0aGFuIGJsb2NrIHRoZSBzb3VyY2UgbG9hZGVyLgogICAgICAgICAgICAgICAgaWYgbG9naWNhbF9wYXRoID09IG93bl9wYXRoOgogICAgICAgICAgICAgICAgICAgIHJlc3VsdC5hcHBlbmQoU291cmNlRmlsZShsb2dpY2FsX3BhdGgsICgpKSkKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LmFwcGVuZChfcmVhZF9sb2dpY2FsX3NvdXJjZShyb290LCBsb2dpY2FsX3BhdGgpKQogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgcmVzdWx0LmFwcGVuZChTb3VyY2VGaWxlKGxvZ2ljYWxfcGF0aCwgKCkpKQoKICAgIGNvbmZfcGh5c2ljYWwgPSBfcm9vdGVkX3NvdXJjZV9wYXRoKHJvb3QsIFNZU0NUTF9DT05GKQogICAgdHJ5OgogICAgICAgIG9zLmxzdGF0KGNvbmZfcGh5c2ljYWwpCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgcGFzcwogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJzb3VyY2U6dW5yZWFkYWJsZS1zb3VyY2UiLCBTWVNDVExfQ09ORikgZnJvbSBleGMKICAgIGVsc2U6CiAgICAgICAgcmVzdWx0LmFwcGVuZChfcmVhZF9sb2dpY2FsX3NvdXJjZShyb290LCBTWVNDVExfQ09ORikpCiAgICByZXR1cm4gdHVwbGUocmVzdWx0KSwgYm9vbChvd25fcHJlc2VudCkKCgpkZWYgbG9hZF9zeXNjdGxfc291cmNlcyhjb250cm9sX2tleSwgcm9vdD0iLyIpOgogICAgIiIiUmVhZCB0aGUgRDA4IHNvdXJjZSBzZXQgYWZ0ZXIgc2FtZS1iYXNlbmFtZSBzaGFkb3dpbmcuIiIiCiAgICByZXR1cm4gX2xvYWRfc3lzY3RsX3NvdXJjZXNfb2JzZXJ2ZWQoY29udHJvbF9rZXksIHJvb3QpWzBdCgoKZGVmIG93bl9wZXJzaXN0ZW50X3ZhbHVlKGtleSwgcmF3X2J5dGVzKToKICAgIGlmIHJhd19ieXRlcyBpcyBOb25lOgogICAgICAgIHJldHVybiBOb25lCiAgICBpZiBub3QgaXNpbnN0YW5jZShyYXdfYnl0ZXMsIChieXRlcywgYnl0ZWFycmF5KSk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigicGVyc2lzdGVudCBieXRlcyBtdXN0IGJlIGJ5dGVzIG9yIE5vbmUiKQogICAgdHJ5OgogICAgICAgIHRleHQgPSBieXRlcyhyYXdfYnl0ZXMpLmRlY29kZSgidXRmLTgiKQogICAgZXhjZXB0IFVuaWNvZGVEZWNvZGVFcnJvciBhcyBleGM6CiAgICAgICAgcmFpc2UgUHJlY29uZGl0aW9uRXJyb3IoInBlcnNpc3RlbnQ6b3duLXVucGFyc2VhYmxlIikgZnJvbSBleGMKICAgIHN1ZmZpeCA9IGNvbnRyb2xfcHJvY19zdWZmaXgoa2V5KQogICAgbWF0Y2hlcyA9IFtdCiAgICBmb3IgbGluZV9ubywgbGluZSBpbiBlbnVtZXJhdGUodGV4dC5zcGxpdGxpbmVzKCksIDEpOgogICAgICAgIGFzc2lnbm1lbnQgPSBwYXJzZV9zeXNjdGxfYXNzaWdubWVudF9saW5lKGxpbmUsIGxpbmVfbm8pCiAgICAgICAgaWYgYXNzaWdubWVudCBpcyBub3QgTm9uZSBhbmQgbm9ybWFsaXplX3NvdXJjZV9rZXkoYXNzaWdubWVudC5rZXkpID09IHN1ZmZpeDoKICAgICAgICAgICAgbWF0Y2hlcy5hcHBlbmQoYXNzaWdubWVudCkKICAgIGlmIGxlbihtYXRjaGVzKSAhPSAxOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJwZXJzaXN0ZW50Om93bi11bnBhcnNlYWJsZSIpCiAgICB0cnk6CiAgICAgICAgcmV0dXJuIHBhcnNlX2ludGVnZXJfdGV4dChtYXRjaGVzWzBdLnZhbHVlX3RleHQpCiAgICBleGNlcHQgQ29udHJhY3RFcnJvciBhcyBleGM6CiAgICAgICAgcmFpc2UgUHJlY29uZGl0aW9uRXJyb3IoInBlcnNpc3RlbnQ6b3duLXVucGFyc2VhYmxlIikgZnJvbSBleGMKCgojIEg0Ni1EMTYvSDQ2LUQxNzogcnVudGltZS13cml0ZXIgY29uZmxpY3QgcHJlY29uZGl0aW9uIChQMlIpLiBUaGUgZGV0ZWN0b3IgaXMKIyBzdHJpY3RseSByZWFkLW9ubHkgYW5kIG5ldmVyIGNoYW5nZXMgYW55IHNlcnZpY2UsIHN5c3RlbWQsIFN5c1Ygb3Igc3lzY3RsIG9iamVjdC4KUlVOVElNRV9XUklURVJfQ09ORkxJQ1QgPSAiQ09ORkxJQ1QiClJVTlRJTUVfV1JJVEVSX05PX0NPTkZMSUNUID0gIk5PX0NPTkZMSUNUIgpSVU5USU1FX1dSSVRFUl9VTkRFVEVSTUlORUQgPSAiVU5ERVRFUk1JTkVEIgpSVU5USU1FX1dSSVRFUl9ERUxFR0FURV9TWVNWID0gIkRFTEVHQVRFX1NZU1YiClJVTlRJTUVfV1JJVEVSX1JVTEVfQVBQT1JUX05BVElWRSA9ICJBUFBPUlQtTkFUSVZFLVNVSUQtRFVNUEFCTEUtVjEiClJVTlRJTUVfV1JJVEVSX1JVTEVfQVBQT1JUX1NZU1YgPSAiQVBQT1JULVNZU1YtU1VJRC1EVU1QQUJMRS1WMSIKUlVOVElNRV9XUklURVJfUlVMRVMgPSB7ImZzLnN1aWRfZHVtcGFibGUiOiBSVU5USU1FX1dSSVRFUl9SVUxFX0FQUE9SVF9OQVRJVkV9ClNFUlZJQ0VfTUFOQUdFRF9SVU5USU1FX1dSSVRFUlMgPSB7CiAgICBSVU5USU1FX1dSSVRFUl9SVUxFX0FQUE9SVF9OQVRJVkU6ICJBcHBvcnQiLAogICAgUlVOVElNRV9XUklURVJfUlVMRV9BUFBPUlRfU1lTVjogIkFwcG9ydCIsCn0KCkFQUE9SVF9JTklUX1NDUklQVCA9ICIvZXRjL2luaXQuZC9hcHBvcnQiCkFQUE9SVF9JTklUX1NDUklQVF9TSEEyNTYgPSBmcm96ZW5zZXQoewogICAgIjQwZTI1MmNkOTllMDMwZmNkZjI4ZDI4NmE3YWM3OGY0MzRlMGNlMDc0MmY1NWNkMTJjMzhiZWY4ZTFmMTg2MzMiLAp9KQpBUFBPUlRfQUdFTlQgPSAiL3Vzci9zaGFyZS9hcHBvcnQvYXBwb3J0IgpBUFBPUlRfREVGQVVMVF9GSUxFID0gIi9ldGMvZGVmYXVsdC9hcHBvcnQiCkFQUE9SVF9ERUZBVUxUX0VOQUJMRURfU0hBMjU2ID0gZnJvemVuc2V0KHsKICAgICI4MTAzMDRmYjBkZjZkYmM4YTY1MWE4OTI4ZGRkMGJiMmI1MjFmYTBjYTZmMzJhMzI4YWExMDNiZTYxOTc3ZjkxIiwKfSkKUElEMV9FTlZJUk9OID0gIi9wcm9jLzEvZW52aXJvbiIKQVBQT1JUX1NZU1RFTURfQ09OVEFJTkVSID0gIi9ydW4vc3lzdGVtZC9jb250YWluZXIiCkFQUE9SVF9SQ19ESVJTID0gKCIvZXRjL3JjUy5kIiwgIi9ldGMvcmMyLmQiLCAiL2V0Yy9yYzMuZCIsICIvZXRjL3JjNC5kIiwgIi9ldGMvcmM1LmQiKQpBUFBPUlRfUkNfTElOS19SRSA9IHJlLmNvbXBpbGUociJTLi5hcHBvcnQiLCByZS5ET1RBTEwpCgpBUFBPUlRfU1lTVEVNRF9ST09UUyA9ICgKICAgICIvZXRjL3N5c3RlbWQvc3lzdGVtLmNvbnRyb2wiLAogICAgIi9ydW4vc3lzdGVtZC9zeXN0ZW0uY29udHJvbCIsCiAgICAiL3J1bi9zeXN0ZW1kL3RyYW5zaWVudCIsCiAgICAiL3J1bi9zeXN0ZW1kL2dlbmVyYXRvci5lYXJseSIsCiAgICAiL2V0Yy9zeXN0ZW1kL3N5c3RlbSIsCiAgICAiL2V0Yy9zeXN0ZW1kL3N5c3RlbS5hdHRhY2hlZCIsCiAgICAiL3J1bi9zeXN0ZW1kL3N5c3RlbSIsCiAgICAiL3J1bi9zeXN0ZW1kL3N5c3RlbS5hdHRhY2hlZCIsCiAgICAiL3J1bi9zeXN0ZW1kL2dlbmVyYXRvciIsCiAgICAiL3Vzci9sb2NhbC9saWIvc3lzdGVtZC9zeXN0ZW0iLAogICAgIi91c3IvbGliL3N5c3RlbWQvc3lzdGVtIiwKICAgICIvcnVuL3N5c3RlbWQvZ2VuZXJhdG9yLmxhdGUiLAopCkFQUE9SVF9EQlVTX1JPT1RTID0gKAogICAgIi91c3Ivc2hhcmUvZGJ1cy0xL3N5c3RlbS1zZXJ2aWNlcyIsCiAgICAiL2V0Yy9kYnVzLTEvc3lzdGVtLXNlcnZpY2VzIiwKICAgICIvdXNyL2xvY2FsL3NoYXJlL2RidXMtMS9zeXN0ZW0tc2VydmljZXMiLAopCkFQUE9SVF9NQVJLRVIgPSBiImFwcG9ydCIKCkFQUE9SVF9BVVhfUkVHVUxBUl9TSEEyNTYgPSB7CiAgICAiL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LWF1dG9yZXBvcnQucGF0aCI6ICIyMmRmODM4ODA1MjE3YmQzYzczODFlODdhOGU3YWZmN2RiMTFlZWM2OTc3Yjc1YTg5MmRiMWU2ZGM0MmI0ZThhIiwKICAgICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtYXV0b3JlcG9ydC5zZXJ2aWNlIjogIjliZTcyYjZhNWNlMzczZmMzYzQ1ODBjYmUzOTAxNzAzYTZjYjQ3ZmZmMGJkZTNkMmMyOWZiODJkNjkxNjBiNzMiLAogICAgIi91c3IvbGliL3N5c3RlbWQvc3lzdGVtL2FwcG9ydC1hdXRvcmVwb3J0LnRpbWVyIjogIjcyZTQ3MDA4NTRkMmMzYmFiZWU2MTJmNmRkYTdjMWM2MWNhZjM3ODc4YjdhZGY5NjYzZGRiY2JiYzNlNGM5YzUiLAogICAgIi91c3IvbGliL3N5c3RlbWQvc3lzdGVtL2FwcG9ydC1mb3J3YXJkLnNvY2tldCI6ICJkM2I3ZDY4MjY5ZDhhMGQwNTFlMWFiNjM2ODBhYmRmZmZiMWI0YWQxMmZiNTAzOTk3ZmI2ZGE0Y2VhZjFjMDgzIiwKICAgICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtZm9yd2FyZEAuc2VydmljZSI6ICIzMWFmYmM4NjY0MmRkYmI1ZTIyODZkZmY3ODU1OGJjZTFmZmNhYWZkZDY5NjgzMDk3YjZmZmUxZmNlZGY2Y2VjIiwKICAgICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtY29yZWR1bXAtaG9va0Auc2VydmljZSI6ICJmZGFiZmJkNDQ4NDdiZDM0ZDAzZWZkOWNjNTJkODQ3ZDNkYmFmZmVjOTZlMTNjZDQxM2E0MGIzNWFjYzM5YTAwIiwKICAgICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9zeXN0ZW1kLWNvcmVkdW1wQC5zZXJ2aWNlLmQvYXBwb3J0LWNvcmVkdW1wLWhvb2suY29uZiI6ICJkMDI1ZDIzOTVmMWQ1ZjBlOWZjMTgzYjM5ZGIxMWRkNWYxMjE3NDBmZDgxOGZjMjMzM2VkNWNhNGEzOWRiZmFhIiwKfQpBUFBPUlRfQVVYX0xJTktfVEFSR0VUUyA9IHsKICAgICIvZXRjL3N5c3RlbWQvc3lzdGVtL3BhdGhzLnRhcmdldC53YW50cy9hcHBvcnQtYXV0b3JlcG9ydC5wYXRoIjogZnJvemVuc2V0KHsKICAgICAgICAiL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtYXV0b3JlcG9ydC5wYXRoIiwKICAgICAgICAiL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LWF1dG9yZXBvcnQucGF0aCIsCiAgICB9KSwKICAgICIvZXRjL3N5c3RlbWQvc3lzdGVtL3NvY2tldHMudGFyZ2V0LndhbnRzL2FwcG9ydC1mb3J3YXJkLnNvY2tldCI6IGZyb3plbnNldCh7CiAgICAgICAgIi9saWIvc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LWZvcndhcmQuc29ja2V0IiwKICAgICAgICAiL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LWZvcndhcmQuc29ja2V0IiwKICAgIH0pLAogICAgIi9ldGMvc3lzdGVtZC9zeXN0ZW0vdGltZXJzLnRhcmdldC53YW50cy9hcHBvcnQtYXV0b3JlcG9ydC50aW1lciI6IGZyb3plbnNldCh7CiAgICAgICAgIi9saWIvc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LWF1dG9yZXBvcnQudGltZXIiLAogICAgICAgICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtYXV0b3JlcG9ydC50aW1lciIsCiAgICB9KSwKfQpBUFBPUlRfQVVYX0xJTktfUkVTT0xWRUQgPSB7CiAgICAiL2V0Yy9zeXN0ZW1kL3N5c3RlbS9wYXRocy50YXJnZXQud2FudHMvYXBwb3J0LWF1dG9yZXBvcnQucGF0aCI6ICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtYXV0b3JlcG9ydC5wYXRoIiwKICAgICIvZXRjL3N5c3RlbWQvc3lzdGVtL3NvY2tldHMudGFyZ2V0LndhbnRzL2FwcG9ydC1mb3J3YXJkLnNvY2tldCI6ICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtZm9yd2FyZC5zb2NrZXQiLAogICAgIi9ldGMvc3lzdGVtZC9zeXN0ZW0vdGltZXJzLnRhcmdldC53YW50cy9hcHBvcnQtYXV0b3JlcG9ydC50aW1lciI6ICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtYXV0b3JlcG9ydC50aW1lciIsCn0KQVBQT1JUX0FVWF9CQVNFX1BBVEhTID0gZnJvemVuc2V0KHsKICAgICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtYXV0b3JlcG9ydC5wYXRoIiwKICAgICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtYXV0b3JlcG9ydC5zZXJ2aWNlIiwKICAgICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtYXV0b3JlcG9ydC50aW1lciIsCiAgICAiL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LWZvcndhcmQuc29ja2V0IiwKICAgICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQtZm9yd2FyZEAuc2VydmljZSIsCiAgICAiL2V0Yy9zeXN0ZW1kL3N5c3RlbS9wYXRocy50YXJnZXQud2FudHMvYXBwb3J0LWF1dG9yZXBvcnQucGF0aCIsCiAgICAiL2V0Yy9zeXN0ZW1kL3N5c3RlbS9zb2NrZXRzLnRhcmdldC53YW50cy9hcHBvcnQtZm9yd2FyZC5zb2NrZXQiLAogICAgIi9ldGMvc3lzdGVtZC9zeXN0ZW0vdGltZXJzLnRhcmdldC53YW50cy9hcHBvcnQtYXV0b3JlcG9ydC50aW1lciIsCn0pCkFQUE9SVF9BVVhfQ09SRURVTVBfUEFUSFMgPSBmcm96ZW5zZXQoc2V0KEFQUE9SVF9BVVhfQkFTRV9QQVRIUykgfCB7CiAgICAiL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LWNvcmVkdW1wLWhvb2tALnNlcnZpY2UiLAogICAgIi91c3IvbGliL3N5c3RlbWQvc3lzdGVtL3N5c3RlbWQtY29yZWR1bXBALnNlcnZpY2UuZC9hcHBvcnQtY29yZWR1bXAtaG9vay5jb25mIiwKfSkKCkFQUE9SVF9OQVRJVkVfVU5JVCA9ICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQuc2VydmljZSIKQVBQT1JUX05BVElWRV9VTklUX1NIQTI1NiA9ICJjMjAyNmE4ZjgxMzc3NjEwOGUyZDkxNjI5ZjUxZmYwY2Y1YmYwMTNmYWMwMzMxNDE2NGNhYmNkYTZjOTY5OGFhIgpBUFBPUlRfTkFUSVZFX1dBTlRTID0gIi9ldGMvc3lzdGVtZC9zeXN0ZW0vbXVsdGktdXNlci50YXJnZXQud2FudHMvYXBwb3J0LnNlcnZpY2UiCkFQUE9SVF9OQVRJVkVfV0FOVFNfVEFSR0VUID0gIi91c3IvbGliL3N5c3RlbWQvc3lzdGVtL2FwcG9ydC5zZXJ2aWNlIgpBUFBPUlRfTkFUSVZFX0FHRU5UX1NIQTI1NiA9IGZyb3plbnNldCh7CiAgICAiMWI4YjVlMmM1M2U4OTcwZGQyZjQ3YzlhMDg5MjAzMGQxZWJhZDU3Y2FlMWY3MjQyYzQzYTYyNTJmMWY2ZGZmMiIsCiAgICAiZThiNTdkYTk5MjRkNDYxZmVlNmQzYjM5MmRjMTg0Njk3YmMxNGQyZWI4ZDcxN2MwNWUxY2JmMGJkMzc2MDQxZSIsCn0pCkFQUE9SVF9OQVRJVkVfUFJJTUFSWV9QQVRIUyA9IGZyb3plbnNldCh7QVBQT1JUX05BVElWRV9VTklULCBBUFBPUlRfTkFUSVZFX1dBTlRTfSkKCkFQUE9SVF9HRU5FUkFURURfVU5JVCA9ICIvcnVuL3N5c3RlbWQvZ2VuZXJhdG9yLmxhdGUvYXBwb3J0LnNlcnZpY2UiCkFQUE9SVF9HRU5FUkFURURfVU5JVF9TSEEyNTYgPSAiOGI4ZDIzNWMzNjZhZTliNDMzYWYwNzNjNWE4MTNlMzQ2NWUwZDZjNjZlM2YzOThiYTczMDk1YzlmNmQzMzM2MyIKQVBQT1JUX0dFTkVSQVRFRF9VTklUX01PREUgPSAwbzY0NApBUFBPUlRfR0VORVJBVEVEX1VOSVRfU0laRSA9IDUxOApBUFBPUlRfR0VORVJBVEVEX0xJTktTID0gewogICAgIi9ydW4vc3lzdGVtZC9nZW5lcmF0b3IubGF0ZS9tdWx0aS11c2VyLnRhcmdldC53YW50cy9hcHBvcnQuc2VydmljZSI6ICIuLi9hcHBvcnQuc2VydmljZSIsCiAgICAiL3J1bi9zeXN0ZW1kL2dlbmVyYXRvci5sYXRlL2dyYXBoaWNhbC50YXJnZXQud2FudHMvYXBwb3J0LnNlcnZpY2UiOiAiLi4vYXBwb3J0LnNlcnZpY2UiLAp9CkFQUE9SVF9HRU5FUkFURURfUFJJTUFSWV9QQVRIUyA9IGZyb3plbnNldCh7QVBQT1JUX0dFTkVSQVRFRF9VTklULCAqQVBQT1JUX0dFTkVSQVRFRF9MSU5LU30pCkFQUE9SVF9NQVNLX1BBVEhTID0gKAogICAgIi9ldGMvc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LnNlcnZpY2UiLAogICAgIi9ydW4vc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LnNlcnZpY2UiLAopCkFQUE9SVF9PVkVSUklERV9QQVRIUyA9ICgKICAgICIvZXRjL3N5c3RlbWQvc3lzdGVtL2FwcG9ydC5zZXJ2aWNlLmQiLAogICAgIi9ydW4vc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LnNlcnZpY2UuZCIsCiAgICAiL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LnNlcnZpY2UuZCIsCiAgICAiL2xpYi9zeXN0ZW1kL3N5c3RlbS9hcHBvcnQuc2VydmljZSIsCiAgICAiL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0vYXBwb3J0LnNlcnZpY2UiLAopCgoKY2xhc3MgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoRXhjZXB0aW9uKToKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBzdGVwLCBkZXRhaWw9Tm9uZSk6CiAgICAgICAgc3VwZXIoKS5fX2luaXRfXyhzdGVwIGlmIGRldGFpbCBpcyBOb25lIGVsc2UgZiJ7c3RlcH06e2RldGFpbH0iKQogICAgICAgIHNlbGYuc3RlcCA9IHN0ZXAKICAgICAgICBzZWxmLmRldGFpbCA9IGRldGFpbAoKCmNsYXNzIF9SdW50aW1lV3JpdGVyU3RlcChzdHIpOgogICAgIiIiU3RyaW5nLWNvbXBhdGlibGUgc3RlcCBjYXJyeWluZyB0aGUgcnVsZSBpZCB1c2VkIG9ubHkgZm9yIHJlcG9ydCBncmFtbWFyLiIiIgogICAgZGVmIF9fbmV3X18oY2xzLCB2YWx1ZSwgcnVsZV9pZD1Ob25lKToKICAgICAgICBvYmogPSBzdHIuX19uZXdfXyhjbHMsIHZhbHVlKQogICAgICAgIG9iai5ydWxlX2lkID0gcnVsZV9pZAogICAgICAgIHJldHVybiBvYmoKCgpAZGF0YWNsYXNzKGZyb3plbj1UcnVlKQpjbGFzcyBfQXBwb3J0SGl0OgogICAgcGF0aDogc3RyCiAgICBvYmplY3RfdHlwZTogc3RyCiAgICBtb2RlOiBpbnQgfCBOb25lID0gTm9uZQogICAgc2l6ZTogaW50IHwgTm9uZSA9IE5vbmUKICAgIHNoYTI1Njogc3RyIHwgTm9uZSA9IE5vbmUKICAgIHJhd190YXJnZXQ6IHN0ciB8IE5vbmUgPSBOb25lCiAgICByZXNvbHZlZF9wYXRoOiBzdHIgfCBOb25lID0gTm9uZQogICAgcmVzb2x2ZWRfdHlwZTogc3RyIHwgTm9uZSA9IE5vbmUKICAgIHJlc29sdmVkX3NoYTI1Njogc3RyIHwgTm9uZSA9IE5vbmUKICAgIG1hcmtlcl9wYXRoOiBib29sID0gRmFsc2UKICAgIG1hcmtlcl90YXJnZXQ6IGJvb2wgPSBGYWxzZQogICAgbWFya2VyX2J5dGVzOiBib29sID0gRmFsc2UKCgpAZGF0YWNsYXNzKGZyb3plbj1UcnVlKQpjbGFzcyBfQXBwb3J0TmF0aXZlRGVjaXNpb246CiAgICB2ZXJkaWN0OiBzdHIKICAgIHN0ZXA6IHN0ciB8IE5vbmUKICAgIGRldGFpbDogc3RyIHwgTm9uZQogICAgYXV4aWxpYXJ5X25vbmVtcHR5OiBib29sID0gRmFsc2UKCgpkZWYgX2Vycm5vX3Rva2VuKGV4Yyk6CiAgICByZXR1cm4gZXJybm8uZXJyb3Jjb2RlLmdldChnZXRhdHRyKGV4YywgImVycm5vIiwgTm9uZSksICJPU0VSUk9SIikKCgpkZWYgX3J3X2xzdGF0KHBhdGgsIHN0ZXApOgogICAgdHJ5OgogICAgICAgIHJldHVybiBvcy5sc3RhdChwYXRoKQogICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgIHJldHVybiBOb25lCiAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoc3RlcCwgX2Vycm5vX3Rva2VuKGV4YykpCgoKZGVmIF9yd19yZWFkX3JlZ3VsYXIocGF0aCwgc3QsIHN0ZXApOgogICAgaWYgbm90IHN0YXQuU19JU1JFRyhzdC5zdF9tb2RlKToKICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZChzdGVwLCAibm90LXJlZ3VsYXIiKQogICAgdHJ5OgogICAgICAgIGZkID0gb3Mub3BlbihwYXRoLCBvcy5PX1JET05MWSB8IG9zLk9fTk9GT0xMT1cgfCBvcy5PX05PTkJMT0NLIHwgZ2V0YXR0cihvcywgIk9fQ0xPRVhFQyIsIDApKQogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKHN0ZXAsIF9lcnJub190b2tlbihleGMpKQogICAgdHJ5OgogICAgICAgIG9wZW5lZCA9IG9zLmZzdGF0KGZkKQogICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcob3BlbmVkLnN0X21vZGUpIG9yIChvcGVuZWQuc3RfZGV2LCBvcGVuZWQuc3RfaW5vKSAhPSAoc3Quc3RfZGV2LCBzdC5zdF9pbm8pOgogICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZChzdGVwLCAib2JqZWN0LWRyaWZ0IikKICAgICAgICByZXR1cm4gX3JlYWRfYWxsX2ZkKGZkKQogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKHN0ZXAsIF9lcnJub190b2tlbihleGMpKQogICAgZmluYWxseToKICAgICAgICBvcy5jbG9zZShmZCkKCgpkZWYgX2FzY2lpX21hcmtlcihkYXRhKToKICAgIGlmIGlzaW5zdGFuY2UoZGF0YSwgc3RyKToKICAgICAgICBkYXRhID0gb3MuZnNlbmNvZGUoZGF0YSkKICAgIHJldHVybiBBUFBPUlRfTUFSS0VSIGluIGJ5dGVzKGRhdGEpLmxvd2VyKCkKCgpkZWYgX3J3X25vcm1hbGl6ZV9sb2dpY2FsKHBhdGgpOgogICAgaWYgbm90IGlzaW5zdGFuY2UocGF0aCwgc3RyKSBvciBub3QgcGF0aC5zdGFydHN3aXRoKCIvIikgb3IgIlx4MDAiIGluIHBhdGg6CiAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoIkMxIiwgImludmFsaWQtbG9naWNhbC1wYXRoIikKICAgIHJldHVybiBwYXRoCgoKZGVmIF9yd19yZXNvbHZlX2xvZ2ljYWwocm9vdCwgbG9naWNhbCwgc3RlcCk6CiAgICAiIiJTdHJpY3Qgcm9vdC1hd2FyZSBjb21wb25lbnQgcmVzb2x1dGlvbi4gQWJzb2x1dGUgdGFyZ2V0cyBzdGF5IGluc2lkZSBzb3VyY2Vfcm9vdC4iIiIKICAgIGxvZ2ljYWwgPSBfcndfbm9ybWFsaXplX2xvZ2ljYWwobG9naWNhbCkKICAgIHBlbmRpbmcgPSBbcGFydCBmb3IgcGFydCBpbiBsb2dpY2FsLnNwbGl0KCIvIikgaWYgcGFydF0KICAgIGlmIGxvZ2ljYWwuZW5kc3dpdGgoIi8iKSBhbmQgcGVuZGluZzoKICAgICAgICBwZW5kaW5nLmFwcGVuZCgiLiIpCiAgICByZXNvbHZlZCA9IFtdCiAgICBsaW5rcyA9IDAKICAgIHdoaWxlIHBlbmRpbmc6CiAgICAgICAgcGFydCA9IHBlbmRpbmcucG9wKDApCiAgICAgICAgaWYgcGFydCA9PSAiLiI6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWYgcGFydCA9PSAiLi4iOgogICAgICAgICAgICBpZiByZXNvbHZlZDoKICAgICAgICAgICAgICAgIHJlc29sdmVkLnBvcCgpCiAgICAgICAgICAgIGNvbnRpbnVlCgogICAgICAgIGNhbmRpZGF0ZSA9ICIvIiArICIvIi5qb2luKHJlc29sdmVkICsgW3BhcnRdKQogICAgICAgIHBoeXNpY2FsID0gX3Jvb3RlZF9zb3VyY2VfcGF0aChyb290LCBjYW5kaWRhdGUpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzdCA9IG9zLmxzdGF0KHBoeXNpY2FsKQogICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgcmV0dXJuIE5vbmUKICAgICAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKHN0ZXAsIF9lcnJub190b2tlbihleGMpICsgIjoiICsgY2FuZGlkYXRlKQogICAgICAgIGlmIHN0YXQuU19JU0xOSyhzdC5zdF9tb2RlKToKICAgICAgICAgICAgbGlua3MgKz0gMQogICAgICAgICAgICBpZiBsaW5rcyA+IDQwOgogICAgICAgICAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoc3RlcCwgIkVMT09QOiIgKyBjYW5kaWRhdGUpCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHRhcmdldCA9IG9zLnJlYWRsaW5rKHBoeXNpY2FsKQogICAgICAgICAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZChzdGVwLCBfZXJybm9fdG9rZW4oZXhjKSArICI6IiArIGNhbmRpZGF0ZSkKICAgICAgICAgICAgaWYgbm90IGlzaW5zdGFuY2UodGFyZ2V0LCBzdHIpOgogICAgICAgICAgICAgICAgdGFyZ2V0ID0gb3MuZnNkZWNvZGUodGFyZ2V0KQogICAgICAgICAgICB0YXJnZXRfcGFydHMgPSBbcCBmb3IgcCBpbiB0YXJnZXQuc3BsaXQoIi8iKSBpZiBwXQogICAgICAgICAgICBpZiB0YXJnZXQuZW5kc3dpdGgoIi8iKSBhbmQgdGFyZ2V0X3BhcnRzOgogICAgICAgICAgICAgICAgdGFyZ2V0X3BhcnRzLmFwcGVuZCgiLiIpCiAgICAgICAgICAgIGlmIHRhcmdldC5zdGFydHN3aXRoKCIvIik6CiAgICAgICAgICAgICAgICByZXNvbHZlZCA9IFtdCiAgICAgICAgICAgIHBlbmRpbmcgPSB0YXJnZXRfcGFydHMgKyBwZW5kaW5nCiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWYgcGVuZGluZyBhbmQgbm90IHN0YXQuU19JU0RJUihzdC5zdF9tb2RlKToKICAgICAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoc3RlcCwgIkVOT1RESVI6IiArIGNhbmRpZGF0ZSkKICAgICAgICByZXNvbHZlZC5hcHBlbmQocGFydCkKICAgIGZpbmFsX2xvZ2ljYWwgPSAiLyIgKyAiLyIuam9pbihyZXNvbHZlZCkKICAgIHBoeXNpY2FsID0gX3Jvb3RlZF9zb3VyY2VfcGF0aChyb290LCBmaW5hbF9sb2dpY2FsKQogICAgdHJ5OgogICAgICAgIGZpbmFsX3N0ID0gb3MubHN0YXQocGh5c2ljYWwpCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZChzdGVwLCBfZXJybm9fdG9rZW4oZXhjKSArICI6IiArIGZpbmFsX2xvZ2ljYWwpCiAgICByZXR1cm4gZmluYWxfbG9naWNhbCwgZmluYWxfc3QKCgpkZWYgX3J3X3NhbWVfbG9naWNhbF9vYmplY3Qocm9vdCwgbGVmdCwgcmlnaHQsIHN0ZXApOgogICAgbHJlcyA9IF9yd19yZXNvbHZlX2xvZ2ljYWwocm9vdCwgbGVmdCwgc3RlcCkKICAgIHJyZXMgPSBfcndfcmVzb2x2ZV9sb2dpY2FsKHJvb3QsIHJpZ2h0LCBzdGVwKQogICAgaWYgbHJlcyBpcyBOb25lIG9yIHJyZXMgaXMgTm9uZToKICAgICAgICByZXR1cm4gRmFsc2UKICAgIHJldHVybiAobHJlc1sxXS5zdF9kZXYsIGxyZXNbMV0uc3RfaW5vKSA9PSAocnJlc1sxXS5zdF9kZXYsIHJyZXNbMV0uc3RfaW5vKQoKCmRlZiBfcndfY2Vuc3VzX3N5bWxpbmsocm9vdCwgbG9naWNhbCwgcmVsYXRpdmUsIHN0KToKICAgIHBoeXNpY2FsID0gX3Jvb3RlZF9zb3VyY2VfcGF0aChyb290LCBsb2dpY2FsKQogICAgdHJ5OgogICAgICAgIHJhd190YXJnZXQgPSBvcy5yZWFkbGluayhwaHlzaWNhbCkKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzEiLCAicmVhZGxpbms6IiArIF9lcnJub190b2tlbihleGMpICsgIjoiICsgbG9naWNhbCkKICAgIGlmIG5vdCBpc2luc3RhbmNlKHJhd190YXJnZXQsIHN0cik6CiAgICAgICAgcmF3X3RhcmdldCA9IG9zLmZzZGVjb2RlKHJhd190YXJnZXQpCiAgICBtYXJrZXJfcGF0aCA9IF9hc2NpaV9tYXJrZXIocmVsYXRpdmUpCiAgICBtYXJrZXJfdGFyZ2V0ID0gX2FzY2lpX21hcmtlcihyYXdfdGFyZ2V0KQogICAgcHJlbGltaW5hcnkgPSBtYXJrZXJfcGF0aCBvciBtYXJrZXJfdGFyZ2V0CgogICAgIyBFeGFjdCAvZGV2L251bGwgbWFza3MgYXJlIG1ldGFkYXRhLW9ubHk7IHRoZSBkZXZpY2UgaXMgbmV2ZXIgb3BlbmVkL3JlYWQuCiAgICBpZiByYXdfdGFyZ2V0ID09ICIvZGV2L251bGwiOgogICAgICAgIGlmIHByZWxpbWluYXJ5OgogICAgICAgICAgICByZXR1cm4gX0FwcG9ydEhpdCgKICAgICAgICAgICAgICAgIGxvZ2ljYWwsICJzeW1saW5rIiwgbW9kZT1zdGF0LlNfSU1PREUoc3Quc3RfbW9kZSksIHNpemU9c3Quc3Rfc2l6ZSwKICAgICAgICAgICAgICAgIHJhd190YXJnZXQ9cmF3X3RhcmdldCwgcmVzb2x2ZWRfcGF0aD0iL2Rldi9udWxsIiwgcmVzb2x2ZWRfdHlwZT0ic3BlY2lhbCIsCiAgICAgICAgICAgICAgICBtYXJrZXJfcGF0aD1tYXJrZXJfcGF0aCwgbWFya2VyX3RhcmdldD1tYXJrZXJfdGFyZ2V0LAogICAgICAgICAgICApCiAgICAgICAgcmV0dXJuIE5vbmUKCiAgICByZXNvbHZlZCA9IF9yd19yZXNvbHZlX2xvZ2ljYWwocm9vdCwgbG9naWNhbCwgIkMxIikKICAgIGlmIHJlc29sdmVkIGlzIE5vbmU6CiAgICAgICAgaWYgbm90IHByZWxpbWluYXJ5OgogICAgICAgICAgICByZXR1cm4gTm9uZQogICAgICAgIHJldHVybiBfQXBwb3J0SGl0KAogICAgICAgICAgICBsb2dpY2FsLCAic3ltbGluayIsIG1vZGU9c3RhdC5TX0lNT0RFKHN0LnN0X21vZGUpLCBzaXplPXN0LnN0X3NpemUsCiAgICAgICAgICAgIHJhd190YXJnZXQ9cmF3X3RhcmdldCwgbWFya2VyX3BhdGg9bWFya2VyX3BhdGgsIG1hcmtlcl90YXJnZXQ9bWFya2VyX3RhcmdldCwKICAgICAgICApCiAgICByZXNvbHZlZF9sb2dpY2FsLCByZXNvbHZlZF9zdCA9IHJlc29sdmVkCiAgICBpZiBzdGF0LlNfSVNSRUcocmVzb2x2ZWRfc3Quc3RfbW9kZSk6CiAgICAgICAgZGF0YSA9IF9yd19yZWFkX3JlZ3VsYXIoX3Jvb3RlZF9zb3VyY2VfcGF0aChyb290LCByZXNvbHZlZF9sb2dpY2FsKSwgcmVzb2x2ZWRfc3QsICJDMSIpCiAgICAgICAgbWFya2VyX2J5dGVzID0gX2FzY2lpX21hcmtlcihkYXRhKQogICAgICAgIGlmIG5vdCAocHJlbGltaW5hcnkgb3IgbWFya2VyX2J5dGVzKToKICAgICAgICAgICAgcmV0dXJuIE5vbmUKICAgICAgICByZXR1cm4gX0FwcG9ydEhpdCgKICAgICAgICAgICAgbG9naWNhbCwgInN5bWxpbmsiLCBtb2RlPXN0YXQuU19JTU9ERShzdC5zdF9tb2RlKSwgc2l6ZT1zdC5zdF9zaXplLAogICAgICAgICAgICByYXdfdGFyZ2V0PXJhd190YXJnZXQsIHJlc29sdmVkX3BhdGg9cmVzb2x2ZWRfbG9naWNhbCwgcmVzb2x2ZWRfdHlwZT0icmVndWxhciIsCiAgICAgICAgICAgIHJlc29sdmVkX3NoYTI1Nj1oYXNobGliLnNoYTI1NihkYXRhKS5oZXhkaWdlc3QoKSwgbWFya2VyX3BhdGg9bWFya2VyX3BhdGgsCiAgICAgICAgICAgIG1hcmtlcl90YXJnZXQ9bWFya2VyX3RhcmdldCwgbWFya2VyX2J5dGVzPW1hcmtlcl9ieXRlcywKICAgICAgICApCiAgICBpZiBzdGF0LlNfSVNESVIocmVzb2x2ZWRfc3Quc3RfbW9kZSk6CiAgICAgICAgaWYgcHJlbGltaW5hcnk6CiAgICAgICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJDMSIsICJtYXJrZXItZGlyZWN0b3J5LXN5bWxpbms6IiArIGxvZ2ljYWwpCiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGlmIHByZWxpbWluYXJ5OgogICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJDMSIsICJtYXJrZXItc3BlY2lhbC1zeW1saW5rOiIgKyBsb2dpY2FsKQogICAgcmV0dXJuIE5vbmUKCgpkZWYgX3J3X2FwcG9ydF9jZW5zdXMocm9vdCk6CiAgICAjIE1lcmdlZC0vdXNyIGFsaWFzIGlzIGV2aWRlbmNlLWJvdW5kIGJlZm9yZSB0aGUgcmVjdXJzaXZlIHNjYW4uIC9saWIgaXMgbmV2ZXIKICAgICMgc2Nhbm5lZCBhcyBhIHNlY29uZCBzeXN0ZW1kIHRyZWUuCiAgICBsaWJfcGF0aCA9IF9yb290ZWRfc291cmNlX3BhdGgocm9vdCwgIi9saWIvc3lzdGVtZC9zeXN0ZW0iKQogICAgdXNyX3BhdGggPSBfcm9vdGVkX3NvdXJjZV9wYXRoKHJvb3QsICIvdXNyL2xpYi9zeXN0ZW1kL3N5c3RlbSIpCiAgICBsaWJfc3QgPSBfcndfbHN0YXQobGliX3BhdGgsICJDMSIpCiAgICB1c3Jfc3QgPSBfcndfbHN0YXQodXNyX3BhdGgsICJDMSIpCiAgICBpZiBsaWJfc3QgaXMgbm90IE5vbmUgYW5kIHVzcl9zdCBpcyBub3QgTm9uZToKICAgICAgICBpZiBub3QgX3J3X3NhbWVfbG9naWNhbF9vYmplY3Qocm9vdCwgIi9saWIvc3lzdGVtZC9zeXN0ZW0iLCAiL3Vzci9saWIvc3lzdGVtZC9zeXN0ZW0iLCAiQzEiKToKICAgICAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoIkMxIiwgImxpYi11c3Itc3lzdGVtZC1kaXZlcmdlbnQiKQoKICAgIGhpdHMgPSB7fQogICAgZm9yIGtpbmQsIGxvZ2ljYWxfcm9vdCBpbiB0dXBsZSgoInN5c3RlbWQiLCBwKSBmb3IgcCBpbiBBUFBPUlRfU1lTVEVNRF9ST09UUykgKyB0dXBsZSgoImRidXMiLCBwKSBmb3IgcCBpbiBBUFBPUlRfREJVU19ST09UUyk6CiAgICAgICAgcGh5c2ljYWxfcm9vdCA9IF9yb290ZWRfc291cmNlX3BhdGgocm9vdCwgbG9naWNhbF9yb290KQogICAgICAgIHJvb3Rfc3QgPSBfcndfbHN0YXQocGh5c2ljYWxfcm9vdCwgIkMxIikKICAgICAgICBpZiByb290X3N0IGlzIE5vbmU6CiAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgaWYgbm90IHN0YXQuU19JU0RJUihyb290X3N0LnN0X21vZGUpOgogICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzEiLCAicm9vdC1ub3QtZGlyZWN0b3J5OiIgKyBsb2dpY2FsX3Jvb3QpCiAgICAgICAgc3RhY2sgPSBbKGxvZ2ljYWxfcm9vdCwgIiIpXQogICAgICAgIHdoaWxlIHN0YWNrOgogICAgICAgICAgICBsb2dpY2FsX2RpciwgcmVsX2Jhc2UgPSBzdGFjay5wb3AoKQogICAgICAgICAgICBwaHlzaWNhbF9kaXIgPSBfcm9vdGVkX3NvdXJjZV9wYXRoKHJvb3QsIGxvZ2ljYWxfZGlyKQogICAgICAgICAgICB0cnk6CiAgICAgICAgICAgICAgICBuYW1lcyA9IG9zLmxpc3RkaXIocGh5c2ljYWxfZGlyKQogICAgICAgICAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzEiLCAicmVhZGRpcjoiICsgX2Vycm5vX3Rva2VuKGV4YykgKyAiOiIgKyBsb2dpY2FsX2RpcikKICAgICAgICAgICAgZm9yIG5hbWUgaW4gc29ydGVkKG5hbWVzLCBrZXk9b3MuZnNlbmNvZGUpOgogICAgICAgICAgICAgICAgbG9naWNhbCA9IHBvc2l4cGF0aC5qb2luKGxvZ2ljYWxfZGlyLCBuYW1lKQogICAgICAgICAgICAgICAgcmVsYXRpdmUgPSBwb3NpeHBhdGguam9pbihyZWxfYmFzZSwgbmFtZSkgaWYgcmVsX2Jhc2UgZWxzZSBuYW1lCiAgICAgICAgICAgICAgICBwaHlzaWNhbCA9IF9yb290ZWRfc291cmNlX3BhdGgocm9vdCwgbG9naWNhbCkKICAgICAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgICAgICBzdCA9IG9zLmxzdGF0KHBoeXNpY2FsKQogICAgICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgICAgICAgICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJDMSIsICJsc3RhdDoiICsgX2Vycm5vX3Rva2VuKGV4YykgKyAiOiIgKyBsb2dpY2FsKQogICAgICAgICAgICAgICAgaWYgc3RhdC5TX0lTRElSKHN0LnN0X21vZGUpOgogICAgICAgICAgICAgICAgICAgIHN0YWNrLmFwcGVuZCgobG9naWNhbCwgcmVsYXRpdmUpKQogICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlCiAgICAgICAgICAgICAgICBoaXQgPSBOb25lCiAgICAgICAgICAgICAgICBpZiBzdGF0LlNfSVNSRUcoc3Quc3RfbW9kZSk6CiAgICAgICAgICAgICAgICAgICAgZGF0YSA9IF9yd19yZWFkX3JlZ3VsYXIocGh5c2ljYWwsIHN0LCAiQzEiKQogICAgICAgICAgICAgICAgICAgIG1hcmtlcl9wYXRoID0gX2FzY2lpX21hcmtlcihyZWxhdGl2ZSkKICAgICAgICAgICAgICAgICAgICBtYXJrZXJfYnl0ZXMgPSBfYXNjaWlfbWFya2VyKGRhdGEpCiAgICAgICAgICAgICAgICAgICAgaWYgbWFya2VyX3BhdGggb3IgbWFya2VyX2J5dGVzOgogICAgICAgICAgICAgICAgICAgICAgICBoaXQgPSBfQXBwb3J0SGl0KAogICAgICAgICAgICAgICAgICAgICAgICAgICAgbG9naWNhbCwgInJlZ3VsYXIiLCBtb2RlPXN0YXQuU19JTU9ERShzdC5zdF9tb2RlKSwgc2l6ZT1zdC5zdF9zaXplLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgc2hhMjU2PWhhc2hsaWIuc2hhMjU2KGRhdGEpLmhleGRpZ2VzdCgpLCBtYXJrZXJfcGF0aD1tYXJrZXJfcGF0aCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIG1hcmtlcl9ieXRlcz1tYXJrZXJfYnl0ZXMsCiAgICAgICAgICAgICAgICAgICAgICAgICkKICAgICAgICAgICAgICAgIGVsaWYgc3RhdC5TX0lTTE5LKHN0LnN0X21vZGUpOgogICAgICAgICAgICAgICAgICAgIGhpdCA9IF9yd19jZW5zdXNfc3ltbGluayhyb290LCBsb2dpY2FsLCByZWxhdGl2ZSwgc3QpCiAgICAgICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgICAgIGlmIF9hc2NpaV9tYXJrZXIocmVsYXRpdmUpOgogICAgICAgICAgICAgICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzEiLCAibWFya2VyLXNwZWNpYWwtb2JqZWN0OiIgKyBsb2dpY2FsKQogICAgICAgICAgICAgICAgaWYgaGl0IGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgICAgIGlmIGtpbmQgPT0gImRidXMiOgogICAgICAgICAgICAgICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzIiLCAiZGJ1cy1oaXQ6IiArIGxvZ2ljYWwpCiAgICAgICAgICAgICAgICAgICAgaWYgbG9naWNhbCBpbiBoaXRzOgogICAgICAgICAgICAgICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzIiLCAiZHVwbGljYXRlLWhpdDoiICsgbG9naWNhbCkKICAgICAgICAgICAgICAgICAgICBoaXRzW2xvZ2ljYWxdID0gaGl0CiAgICByZXR1cm4gaGl0cwoKCmRlZiBfcndfdmFsaWRhdGVfcmVndWxhcl9oaXQoaGl0cywgcGF0aCwgZXhwZWN0ZWRfc2hhLCBzdGVwKToKICAgIGhpdCA9IGhpdHMuZ2V0KHBhdGgpCiAgICBpZiBoaXQgaXMgTm9uZSBvciBoaXQub2JqZWN0X3R5cGUgIT0gInJlZ3VsYXIiIG9yIGhpdC5zaGEyNTYgIT0gZXhwZWN0ZWRfc2hhOgogICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKHN0ZXAsICJyZWd1bGFyLW1pc21hdGNoOiIgKyBwYXRoKQogICAgcmV0dXJuIGhpdAoKCmRlZiBfcndfdmFsaWRhdGVfbGlua19oaXQocm9vdCwgaGl0cywgcGF0aCwgYWxsb3dlZF90YXJnZXRzLCByZXNvbHZlZF9wYXRoLCBzdGVwKToKICAgIGhpdCA9IGhpdHMuZ2V0KHBhdGgpCiAgICBpZiBoaXQgaXMgTm9uZSBvciBoaXQub2JqZWN0X3R5cGUgIT0gInN5bWxpbmsiIG9yIGhpdC5yYXdfdGFyZ2V0IG5vdCBpbiBhbGxvd2VkX3RhcmdldHM6CiAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoc3RlcCwgImxpbmstbWlzbWF0Y2g6IiArIHBhdGgpCiAgICBpZiBoaXQucmVzb2x2ZWRfdHlwZSAhPSAicmVndWxhciIgb3IgaGl0LnJlc29sdmVkX3BhdGggIT0gcmVzb2x2ZWRfcGF0aDoKICAgICAgICAjIG1lcmdlZC0vdXNyIG1heSBwcmVzZXJ2ZSBhIC9saWIgbG9naWNhbCBzcGVsbGluZyBvbmx5IG9uIHVudXN1YWwgYmluZCBsYXlvdXRzOwogICAgICAgICMgZXhhY3Qgb2JqZWN0IGlkZW50aXR5IHdpdGggdGhlIC91c3IgcGF0aCBpcyBzdGlsbCByZXF1aXJlZC4KICAgICAgICBpZiBoaXQucmVzb2x2ZWRfdHlwZSAhPSAicmVndWxhciIgb3IgaGl0LnJlc29sdmVkX3BhdGggaXMgTm9uZSBvciBub3QgX3J3X3NhbWVfbG9naWNhbF9vYmplY3Qocm9vdCwgaGl0LnJlc29sdmVkX3BhdGgsIHJlc29sdmVkX3BhdGgsIHN0ZXApOgogICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZChzdGVwLCAibGluay1yZXNvbHV0aW9uOiIgKyBwYXRoKQogICAgdGFyZ2V0X2hpdCA9IGhpdHMuZ2V0KHJlc29sdmVkX3BhdGgpCiAgICBpZiB0YXJnZXRfaGl0IGlzIE5vbmUgb3IgdGFyZ2V0X2hpdC5vYmplY3RfdHlwZSAhPSAicmVndWxhciIgb3IgaGl0LnJlc29sdmVkX3NoYTI1NiAhPSB0YXJnZXRfaGl0LnNoYTI1NjoKICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZChzdGVwLCAibGluay10YXJnZXQtYnl0ZXM6IiArIHBhdGgpCgoKZGVmIF9yd19jbGFzc2lmeV9hdXhpbGlhcnkocm9vdCwgaGl0cywgYXV4X3BhdGhzKToKICAgIGlmIG5vdCBhdXhfcGF0aHM6CiAgICAgICAgcmV0dXJuICJFTVBUWSIKICAgIGlmIGF1eF9wYXRocyA9PSBBUFBPUlRfQVVYX0JBU0VfUEFUSFM6CiAgICAgICAgcHJvZmlsZSA9ICJBVVgtQkFTRS1WMSIKICAgIGVsaWYgYXV4X3BhdGhzID09IEFQUE9SVF9BVVhfQ09SRURVTVBfUEFUSFM6CiAgICAgICAgcHJvZmlsZSA9ICJBVVgtQ09SRURVTVAtVjEiCiAgICBlbHNlOgogICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJDMiIsICJhdXgtcHJvZmlsZSIpCiAgICBmb3IgcGF0aCBpbiBhdXhfcGF0aHMgJiBzZXQoQVBQT1JUX0FVWF9SRUdVTEFSX1NIQTI1Nik6CiAgICAgICAgX3J3X3ZhbGlkYXRlX3JlZ3VsYXJfaGl0KGhpdHMsIHBhdGgsIEFQUE9SVF9BVVhfUkVHVUxBUl9TSEEyNTZbcGF0aF0sICJDMiIpCiAgICBmb3IgcGF0aCBpbiBhdXhfcGF0aHMgJiBzZXQoQVBQT1JUX0FVWF9MSU5LX1RBUkdFVFMpOgogICAgICAgIF9yd192YWxpZGF0ZV9saW5rX2hpdChyb290LCBoaXRzLCBwYXRoLCBBUFBPUlRfQVVYX0xJTktfVEFSR0VUU1twYXRoXSwgQVBQT1JUX0FVWF9MSU5LX1JFU09MVkVEW3BhdGhdLCAiQzIiKQogICAgcmV0dXJuIHByb2ZpbGUKCgpkZWYgX3J3X3ZhbGlkYXRlX25hdGl2ZV9wcmltYXJ5KHJvb3QsIGhpdHMpOgogICAgX3J3X3ZhbGlkYXRlX3JlZ3VsYXJfaGl0KGhpdHMsIEFQUE9SVF9OQVRJVkVfVU5JVCwgQVBQT1JUX05BVElWRV9VTklUX1NIQTI1NiwgIkM0IikKICAgIF9yd192YWxpZGF0ZV9saW5rX2hpdChyb290LCBoaXRzLCBBUFBPUlRfTkFUSVZFX1dBTlRTLCBmcm96ZW5zZXQoe0FQUE9SVF9OQVRJVkVfV0FOVFNfVEFSR0VUfSksIEFQUE9SVF9OQVRJVkVfVU5JVCwgIkM0IikKCgpkZWYgX3J3X3ZhbGlkYXRlX2dlbmVyYXRlZF9wcmltYXJ5KHJvb3QsIGhpdHMpOgogICAgdW5pdCA9IF9yd192YWxpZGF0ZV9yZWd1bGFyX2hpdChoaXRzLCBBUFBPUlRfR0VORVJBVEVEX1VOSVQsIEFQUE9SVF9HRU5FUkFURURfVU5JVF9TSEEyNTYsICJDNSIpCiAgICBpZiB1bml0Lm1vZGUgIT0gQVBQT1JUX0dFTkVSQVRFRF9VTklUX01PREUgb3IgdW5pdC5zaXplICE9IEFQUE9SVF9HRU5FUkFURURfVU5JVF9TSVpFOgogICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJDNSIsICJnZW5lcmF0ZWQtdW5pdC1tZXRhZGF0YSIpCiAgICBmb3IgcGF0aCwgcmF3X3RhcmdldCBpbiBBUFBPUlRfR0VORVJBVEVEX0xJTktTLml0ZW1zKCk6CiAgICAgICAgX3J3X3ZhbGlkYXRlX2xpbmtfaGl0KHJvb3QsIGhpdHMsIHBhdGgsIGZyb3plbnNldCh7cmF3X3RhcmdldH0pLCBBUFBPUlRfR0VORVJBVEVEX1VOSVQsICJDNSIpCgoKZGVmIF9yd19yZWFkX2NvbnRhaW5lcl9ldmlkZW5jZShyb290KToKICAgIGVudl9wYXRoID0gX3Jvb3RlZF9zb3VyY2VfcGF0aChyb290LCBQSUQxX0VOVklST04pCiAgICBlbnZfc3QgPSBfcndfbHN0YXQoZW52X3BhdGgsICJDNCIpCiAgICBpZiBlbnZfc3QgaXMgTm9uZToKICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzQiLCAicHJvYzEtZW52aXJvbi1FTk9FTlQiKQogICAgZW52ID0gX3J3X3JlYWRfcmVndWxhcihlbnZfcGF0aCwgZW52X3N0LCAiQzQiKQogICAgaWYgYW55KGl0ZW0uc3RhcnRzd2l0aChiImNvbnRhaW5lcj0iKSBmb3IgaXRlbSBpbiBlbnYuc3BsaXQoYiJcMCIpKToKICAgICAgICByZXR1cm4gVHJ1ZSwgInByb2MxLWVudmlyb24iCgogICAgbG9naWNhbCA9IEFQUE9SVF9TWVNURU1EX0NPTlRBSU5FUgogICAgcGF0aCA9IF9yb290ZWRfc291cmNlX3BhdGgocm9vdCwgbG9naWNhbCkKICAgIHN0ID0gX3J3X2xzdGF0KHBhdGgsICJDNCIpCiAgICBpZiBzdCBpcyBOb25lOgogICAgICAgIHJldHVybiBGYWxzZSwgTm9uZQogICAgZGF0YSA9IF9yd19yZWFkX3JlZ3VsYXIocGF0aCwgc3QsICJDNCIpCiAgICBzdHJpcHBlZCA9IGRhdGEuc3RyaXAoQVNDSUlfRURHRV9XUykKICAgIGlmIHN0cmlwcGVkOgogICAgICAgIHJldHVybiBUcnVlLCAicnVuLXN5c3RlbWQtY29udGFpbmVyIgogICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoIkM0IiwgImVtcHR5LXN5c3RlbWQtY29udGFpbmVyIikKCgpkZWYgX3J3X25hdGl2ZV9hZ2VudF92ZXJkaWN0KHJvb3QpOgogICAgcGF0aCA9IF9yb290ZWRfc291cmNlX3BhdGgocm9vdCwgQVBQT1JUX0FHRU5UKQogICAgc3QgPSBfcndfbHN0YXQocGF0aCwgIkM0IikKICAgIGlmIHN0IGlzIE5vbmU6CiAgICAgICAgcmV0dXJuIFJVTlRJTUVfV1JJVEVSX05PX0NPTkZMSUNULCAiYWdlbnQtYWJzZW50IgogICAgaWYgc3RhdC5TX0lTTE5LKHN0LnN0X21vZGUpOgogICAgICAgIHJlc29sdmVkID0gX3J3X3Jlc29sdmVfbG9naWNhbChyb290LCBBUFBPUlRfQUdFTlQsICJDNCIpCiAgICAgICAgaWYgcmVzb2x2ZWQgaXMgTm9uZToKICAgICAgICAgICAgcmV0dXJuIFJVTlRJTUVfV1JJVEVSX05PX0NPTkZMSUNULCAiYWdlbnQtZGFuZ2xpbmciCiAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoIkM0IiwgImFnZW50LXJlc29sdmFibGUtc3ltbGluayIpCiAgICBpZiBub3Qgc3RhdC5TX0lTUkVHKHN0LnN0X21vZGUpOgogICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJDNCIsICJhZ2VudC1ub3QtcmVndWxhciIpCiAgICBpZiBub3Qgb3MuYWNjZXNzKHBhdGgsIG9zLlhfT0spOgogICAgICAgIHJldHVybiBSVU5USU1FX1dSSVRFUl9OT19DT05GTElDVCwgImFnZW50LW5vdC1leGVjdXRhYmxlIgogICAgZGF0YSA9IF9yd19yZWFkX3JlZ3VsYXIocGF0aCwgc3QsICJDNCIpCiAgICBzaGEgPSBoYXNobGliLnNoYTI1NihkYXRhKS5oZXhkaWdlc3QoKQogICAgaWYgc2hhIG5vdCBpbiBBUFBPUlRfTkFUSVZFX0FHRU5UX1NIQTI1NjoKICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzQiLCAiYWdlbnQtc2hhMjU2PSIgKyBzaGEpCiAgICByZXR1cm4gUlVOVElNRV9XUklURVJfQ09ORkxJQ1QsICJhZ2VudC1leGFjdCIKCgpkZWYgX2RldGVjdF9hcHBvcnRfbmF0aXZlX3N1aWRfZHVtcGFibGUocm9vdCk6CiAgICBoaXRzID0gX3J3X2FwcG9ydF9jZW5zdXMocm9vdCkKICAgIGhpdF9wYXRocyA9IHNldChoaXRzKQogICAga25vd25fYXV4ID0gc2V0KEFQUE9SVF9BVVhfQ09SRURVTVBfUEFUSFMpCiAgICBhdXhfcGF0aHMgPSBoaXRfcGF0aHMgJiBrbm93bl9hdXgKICAgIGF1eF9wcm9maWxlID0gX3J3X2NsYXNzaWZ5X2F1eGlsaWFyeShyb290LCBoaXRzLCBhdXhfcGF0aHMpCiAgICBhdXhfbm9uZW1wdHkgPSBhdXhfcHJvZmlsZSAhPSAiRU1QVFkiCiAgICBwcmltYXJ5X3BhdGhzID0gaGl0X3BhdGhzIC0gYXV4X3BhdGhzCgogICAgIyBDMiBwYXJ0aXRpb25zIHRoZSBjb21wbGV0ZSBoaXQgc2V0IGJlZm9yZSBhbnkgcG9zaXRpdmUgbWFzay9jb250YWluZXIgcmVzdWx0LgogICAgaWYgbm90IHByaW1hcnlfcGF0aHM6CiAgICAgICAgcmV0dXJuIF9BcHBvcnROYXRpdmVEZWNpc2lvbihSVU5USU1FX1dSSVRFUl9ERUxFR0FURV9TWVNWLCAiQzYiLCAiemVyby1wcmltYXJ5IiwgYXV4X25vbmVtcHR5KQoKICAgIG1hc2tfcGF0aHMgPSBbcGF0aCBmb3IgcGF0aCBpbiBBUFBPUlRfTUFTS19QQVRIUyBpZiBwYXRoIGluIHByaW1hcnlfcGF0aHNdCiAgICBpZiBtYXNrX3BhdGhzOgogICAgICAgIGlmIGxlbihwcmltYXJ5X3BhdGhzKSAhPSAxOgogICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzIiLCAibWFzay1leHRyYS1wcmltYXJ5IikKICAgICAgICBwYXRoID0gbWFza19wYXRoc1swXQogICAgICAgIGhpdCA9IGhpdHNbcGF0aF0KICAgICAgICBpZiBoaXQub2JqZWN0X3R5cGUgIT0gInN5bWxpbmsiIG9yIGhpdC5yYXdfdGFyZ2V0ICE9ICIvZGV2L251bGwiOgogICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzMiLCAibWFzay1taXNtYXRjaDoiICsgcGF0aCkKICAgICAgICBpZiBhdXhfbm9uZW1wdHk6CiAgICAgICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJDMyIsICJtYXNrLXdpdGgtYXV4aWxpYXJ5IikKICAgICAgICByZXR1cm4gX0FwcG9ydE5hdGl2ZURlY2lzaW9uKFJVTlRJTUVfV1JJVEVSX05PX0NPTkZMSUNULCAiQzMiLCBwYXRoLCBGYWxzZSkKCiAgICBpZiBwcmltYXJ5X3BhdGhzID09IHNldChBUFBPUlRfTkFUSVZFX1BSSU1BUllfUEFUSFMpOgogICAgICAgIF9yd192YWxpZGF0ZV9uYXRpdmVfcHJpbWFyeShyb290LCBoaXRzKQogICAgICAgIGlzX2NvbnRhaW5lciwgY29udGFpbmVyX3NvdXJjZSA9IF9yd19yZWFkX2NvbnRhaW5lcl9ldmlkZW5jZShyb290KQogICAgICAgIGlmIGlzX2NvbnRhaW5lcjoKICAgICAgICAgICAgaWYgYXV4X25vbmVtcHR5OgogICAgICAgICAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoIkM0IiwgImNvbnRhaW5lci13aXRoLWF1eGlsaWFyeToiICsgY29udGFpbmVyX3NvdXJjZSkKICAgICAgICAgICAgcmV0dXJuIF9BcHBvcnROYXRpdmVEZWNpc2lvbihSVU5USU1FX1dSSVRFUl9OT19DT05GTElDVCwgIkM0IiwgImNvbnRhaW5lcjoiICsgY29udGFpbmVyX3NvdXJjZSwgRmFsc2UpCiAgICAgICAgdmVyZGljdCwgZGV0YWlsID0gX3J3X25hdGl2ZV9hZ2VudF92ZXJkaWN0KHJvb3QpCiAgICAgICAgaWYgdmVyZGljdCA9PSBSVU5USU1FX1dSSVRFUl9OT19DT05GTElDVCBhbmQgYXV4X25vbmVtcHR5OgogICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiQzQiLCBkZXRhaWwgKyAiOndpdGgtYXV4aWxpYXJ5IikKICAgICAgICByZXR1cm4gX0FwcG9ydE5hdGl2ZURlY2lzaW9uKHZlcmRpY3QsICJDNCIsIGRldGFpbCwgYXV4X25vbmVtcHR5KQoKICAgIGlmIHByaW1hcnlfcGF0aHMgPT0gc2V0KEFQUE9SVF9HRU5FUkFURURfUFJJTUFSWV9QQVRIUyk6CiAgICAgICAgX3J3X3ZhbGlkYXRlX2dlbmVyYXRlZF9wcmltYXJ5KHJvb3QsIGhpdHMpCiAgICAgICAgcmV0dXJuIF9BcHBvcnROYXRpdmVEZWNpc2lvbihSVU5USU1FX1dSSVRFUl9ERUxFR0FURV9TWVNWLCAiQzUiLCAiZ2VuZXJhdGVkLXN5c3YtYnJpZGdlIiwgYXV4X25vbmVtcHR5KQoKICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJDMiIsICJ1bmFzc2lnbmVkLXByaW1hcnkiKQoKCmRlZiBfZGV0ZWN0X2FwcG9ydF9zeXN2X3N1aWRfZHVtcGFibGUocm9vdCk6CiAgICBkZWYgcm9vdGVkKGxvZ2ljYWwpOgogICAgICAgIHJldHVybiBfcm9vdGVkX3NvdXJjZV9wYXRoKHJvb3QsIGxvZ2ljYWwpCgogICAgIyBSMS9SMjogZXhhY3QgYnl0ZXMgb2YgdGhlIGluc3RhbGxlZCBTeXNWIGluaXQtc2NyaXB0LgogICAgaW5pdF9wYXRoID0gcm9vdGVkKEFQUE9SVF9JTklUX1NDUklQVCkKICAgIGluaXRfc3QgPSBfcndfbHN0YXQoaW5pdF9wYXRoLCAiUjIiKQogICAgaWYgaW5pdF9zdCBpcyBOb25lOgogICAgICAgIHJldHVybiBSVU5USU1FX1dSSVRFUl9OT19DT05GTElDVCwgIlIxIiwgTm9uZQogICAgaW5pdF9zaGEgPSBoYXNobGliLnNoYTI1NihfcndfcmVhZF9yZWd1bGFyKGluaXRfcGF0aCwgaW5pdF9zdCwgIlIyIikpLmhleGRpZ2VzdCgpCiAgICBpZiBpbml0X3NoYSBub3QgaW4gQVBQT1JUX0lOSVRfU0NSSVBUX1NIQTI1NjoKICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiUjIiLCAic2hhMjU2PSIgKyBpbml0X3NoYSkKCiAgICAjIFIzOiB0aGUgaW5pdC1zY3JpcHQgZ3VhcmQgYFsgLXggIiRBR0VOVCIgXWAgZm9sbG93cyBzeW1ib2xpYyBsaW5rcy4KICAgIGFnZW50X3BhdGggPSByb290ZWQoQVBQT1JUX0FHRU5UKQogICAgdHJ5OgogICAgICAgIG9zLnN0YXQoYWdlbnRfcGF0aCkKICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICByZXR1cm4gUlVOVElNRV9XUklURVJfTk9fQ09ORkxJQ1QsICJSMyIsICJhYnNlbnQiCiAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoIlIzIiwgX2Vycm5vX3Rva2VuKGV4YykpCiAgICBpZiBub3Qgb3MuYWNjZXNzKGFnZW50X3BhdGgsIG9zLlhfT0spOgogICAgICAgIHJldHVybiBSVU5USU1FX1dSSVRFUl9OT19DT05GTElDVCwgIlIzIiwgIm5vdC1leGVjdXRhYmxlIgoKICAgICMgUjQ6IHRoZSBpbml0LXNjcmlwdCBkb2VzIG5vdCBzdGFydCBpbnNpZGUgYSBjb250YWluZXIuCiAgICB0cnk6CiAgICAgICAgZmQgPSBvcy5vcGVuKHJvb3RlZChQSUQxX0VOVklST04pLCBvcy5PX1JET05MWSB8IG9zLk9fTk9GT0xMT1cgfCBnZXRhdHRyKG9zLCAiT19DTE9FWEVDIiwgMCkpCiAgICAgICAgdHJ5OgogICAgICAgICAgICBlbnZpcm9uID0gX3JlYWRfYWxsX2ZkKGZkKQogICAgICAgIGZpbmFsbHk6CiAgICAgICAgICAgIG9zLmNsb3NlKGZkKQogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJSNCIsIF9lcnJub190b2tlbihleGMpKQogICAgaWYgYW55KGl0ZW0uc3RhcnRzd2l0aChiImNvbnRhaW5lcj0iKSBmb3IgaXRlbSBpbiBlbnZpcm9uLnNwbGl0KGIiXDAiKSk6CiAgICAgICAgcmV0dXJuIFJVTlRJTUVfV1JJVEVSX05PX0NPTkZMSUNULCAiUjQiLCAiY29udGFpbmVyIgoKICAgICMgRDE3IG93bnMgc3lzdGVtZC1uYXRpdmUvZ2VuZXJhdGVkL21hc2sgY2xhc3NpZmljYXRpb24gYmVmb3JlIEQxNi4gVGhlc2UKICAgICMgbGVnYWN5IFI1L1I2IGNoZWNrcyByZW1haW4gYXMgYSBkaXJlY3QgRDE2IGZhaWwtY2xvc2VkIGd1YXJkIGlmIEQxNiBpcyBldmVyCiAgICAjIGludm9rZWQgb3V0c2lkZSB0aGUgRDE3IGRpc3BhdGNoZXIuCiAgICBmb3IgbG9naWNhbCBpbiBBUFBPUlRfTUFTS19QQVRIUzoKICAgICAgICBwYXRoID0gcm9vdGVkKGxvZ2ljYWwpCiAgICAgICAgc3QgPSBfcndfbHN0YXQocGF0aCwgIlI2IikKICAgICAgICBpZiBzdCBpcyBOb25lOgogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGlmIHN0YXQuU19JU0xOSyhzdC5zdF9tb2RlKToKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgdGFyZ2V0ID0gb3MucmVhZGxpbmsocGF0aCkKICAgICAgICAgICAgZXhjZXB0IE9TRXJyb3IgYXMgZXhjOgogICAgICAgICAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoIlI2IiwgX2Vycm5vX3Rva2VuKGV4YykpCiAgICAgICAgICAgIGlmIHRhcmdldCA9PSAiL2Rldi9udWxsIjoKICAgICAgICAgICAgICAgIHJldHVybiBSVU5USU1FX1dSSVRFUl9OT19DT05GTElDVCwgIlI1IiwgbG9naWNhbAogICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJSNiIsIGxvZ2ljYWwpCgogICAgZm9yIGxvZ2ljYWwgaW4gQVBQT1JUX09WRVJSSURFX1BBVEhTOgogICAgICAgIGlmIF9yd19sc3RhdChyb290ZWQobG9naWNhbCksICJSNiIpIGlzIG5vdCBOb25lOgogICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiUjYiLCBsb2dpY2FsKQoKICAgICMgUjc6IG9ubHkgc3RhcnQgbGlua3MgcmVzb2x2aW5nIGV4YWN0bHkgdG8gdGhlIHZlcmlmaWVkIGluaXQtc2NyaXB0IGNvdW50LgogICAgdmFsaWRfbGlua3MgPSAwCiAgICBmb3IgbG9naWNhbF9kaXIgaW4gQVBQT1JUX1JDX0RJUlM6CiAgICAgICAgdHJ5OgogICAgICAgICAgICBuYW1lcyA9IHNvcnRlZChvcy5saXN0ZGlyKHJvb3RlZChsb2dpY2FsX2RpcikpKQogICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICAgICAgY29udGludWUKICAgICAgICBleGNlcHQgT1NFcnJvciBhcyBleGM6CiAgICAgICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJSNyIsIF9lcnJub190b2tlbihleGMpKQogICAgICAgIGZvciBuYW1lIGluIG5hbWVzOgogICAgICAgICAgICBpZiBub3QgQVBQT1JUX1JDX0xJTktfUkUuZnVsbG1hdGNoKG5hbWUpOgogICAgICAgICAgICAgICAgY29udGludWUKICAgICAgICAgICAgbG9naWNhbF9saW5rID0gbG9naWNhbF9kaXIgKyAiLyIgKyBuYW1lCiAgICAgICAgICAgIGxpbmtfcGF0aCA9IHJvb3RlZChsb2dpY2FsX2xpbmspCiAgICAgICAgICAgIHN0ID0gX3J3X2xzdGF0KGxpbmtfcGF0aCwgIlI3IikKICAgICAgICAgICAgaWYgc3QgaXMgTm9uZSBvciBub3Qgc3RhdC5TX0lTTE5LKHN0LnN0X21vZGUpOgogICAgICAgICAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoIlI3IiwgIm5vdC1zeW1saW5rOiIgKyBsb2dpY2FsX2xpbmspCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIHRhcmdldCA9IG9zLnJlYWRsaW5rKGxpbmtfcGF0aCkKICAgICAgICAgICAgICAgIHJlc29sdmVkID0gb3Muc3RhdChsaW5rX3BhdGgpCiAgICAgICAgICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGV4YzoKICAgICAgICAgICAgICAgIHJhaXNlIF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkKCJSNyIsIF9lcnJub190b2tlbihleGMpICsgIjoiICsgbG9naWNhbF9saW5rKQogICAgICAgICAgICBsb2dpY2FsX3RhcmdldCA9IG9zLnBhdGgubm9ybXBhdGgodGFyZ2V0IGlmIHRhcmdldC5zdGFydHN3aXRoKCIvIikgZWxzZSBsb2dpY2FsX2RpciArICIvIiArIHRhcmdldCkKICAgICAgICAgICAgaWYgbG9naWNhbF90YXJnZXQgIT0gQVBQT1JUX0lOSVRfU0NSSVBUIG9yIChyZXNvbHZlZC5zdF9kZXYsIHJlc29sdmVkLnN0X2lubykgIT0gKGluaXRfc3Quc3RfZGV2LCBpbml0X3N0LnN0X2lubyk6CiAgICAgICAgICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiUjciLCAidGFyZ2V0OiIgKyBsb2dpY2FsX2xpbmspCiAgICAgICAgICAgIHZhbGlkX2xpbmtzICs9IDEKICAgIGlmIHZhbGlkX2xpbmtzID09IDA6CiAgICAgICAgcmFpc2UgX1J1bnRpbWVXcml0ZXJVbmRldGVybWluZWQoIlI3IiwgIm5vLXN0YXJ0LWxpbmsiKQoKICAgICMgUjgvUjk6IC9ldGMvZGVmYXVsdC9hcHBvcnQgaXMgc291cmNlZCBhcyBzaGVsbCwgc28gb25seSBleGFjdCBieXRlcyBjb3VudC4KICAgIGRlZmF1bHRfcGF0aCA9IHJvb3RlZChBUFBPUlRfREVGQVVMVF9GSUxFKQogICAgZGVmYXVsdF9zdCA9IF9yd19sc3RhdChkZWZhdWx0X3BhdGgsICJSOSIpCiAgICBpZiBkZWZhdWx0X3N0IGlzIE5vbmU6CiAgICAgICAgcmV0dXJuIFJVTlRJTUVfV1JJVEVSX0NPTkZMSUNULCAiUjgiLCAiZGVmYXVsdC1hYnNlbnQiCiAgICBkZWZhdWx0X3NoYSA9IGhhc2hsaWIuc2hhMjU2KF9yd19yZWFkX3JlZ3VsYXIoZGVmYXVsdF9wYXRoLCBkZWZhdWx0X3N0LCAiUjkiKSkuaGV4ZGlnZXN0KCkKICAgIGlmIGRlZmF1bHRfc2hhIG5vdCBpbiBBUFBPUlRfREVGQVVMVF9FTkFCTEVEX1NIQTI1NjoKICAgICAgICByYWlzZSBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCgiUjkiLCAic2hhMjU2PSIgKyBkZWZhdWx0X3NoYSkKICAgIHJldHVybiBSVU5USU1FX1dSSVRFUl9DT05GTElDVCwgIlI4IiwgImRlZmF1bHQtc2hhMjU2PSIgKyBkZWZhdWx0X3NoYQoKCmRlZiBkZXRlY3RfcnVudGltZV93cml0ZXJfY29uZmxpY3QoY29udHJvbF9rZXksIHJvb3Q9Ii8iKToKICAgICIiIlJldHVybiAodmVyZGljdCwgc3RlcCwgZGV0YWlsKSBvZiB0aGUgSDQ2LUQxNy0+RDE2IFAyUiBwcmVjb25kaXRpb247IHJlYWQtb25seS4iIiIKICAgIGlmIGNvbnRyb2xfa2V5IG5vdCBpbiBSVU5USU1FX1dSSVRFUl9SVUxFUzoKICAgICAgICByZXR1cm4gUlVOVElNRV9XUklURVJfTk9fQ09ORkxJQ1QsIE5vbmUsIE5vbmUKICAgIHRyeToKICAgICAgICBuYXRpdmUgPSBfZGV0ZWN0X2FwcG9ydF9uYXRpdmVfc3VpZF9kdW1wYWJsZShyb290KQogICAgZXhjZXB0IF9SdW50aW1lV3JpdGVyVW5kZXRlcm1pbmVkIGFzIGV4YzoKICAgICAgICBzdGVwID0gX1J1bnRpbWVXcml0ZXJTdGVwKGV4Yy5zdGVwLCBSVU5USU1FX1dSSVRFUl9SVUxFX0FQUE9SVF9OQVRJVkUpCiAgICAgICAgcmV0dXJuIFJVTlRJTUVfV1JJVEVSX1VOREVURVJNSU5FRCwgc3RlcCwgZXhjLmRldGFpbAoKICAgIGlmIG5hdGl2ZS52ZXJkaWN0ID09IFJVTlRJTUVfV1JJVEVSX0NPTkZMSUNUOgogICAgICAgIHJldHVybiBSVU5USU1FX1dSSVRFUl9DT05GTElDVCwgX1J1bnRpbWVXcml0ZXJTdGVwKG5hdGl2ZS5zdGVwLCBSVU5USU1FX1dSSVRFUl9SVUxFX0FQUE9SVF9OQVRJVkUpLCBuYXRpdmUuZGV0YWlsCiAgICBpZiBuYXRpdmUudmVyZGljdCA9PSBSVU5USU1FX1dSSVRFUl9OT19DT05GTElDVDoKICAgICAgICByZXR1cm4gUlVOVElNRV9XUklURVJfTk9fQ09ORkxJQ1QsIG5hdGl2ZS5zdGVwLCBuYXRpdmUuZGV0YWlsCiAgICBpZiBuYXRpdmUudmVyZGljdCAhPSBSVU5USU1FX1dSSVRFUl9ERUxFR0FURV9TWVNWOgogICAgICAgIHJldHVybiBSVU5USU1FX1dSSVRFUl9VTkRFVEVSTUlORUQsICJkZXRlY3Rvci1mYWlsdXJlIiwgTm9uZQoKICAgIHRyeToKICAgICAgICB2ZXJkaWN0LCBzdGVwLCBkZXRhaWwgPSBfZGV0ZWN0X2FwcG9ydF9zeXN2X3N1aWRfZHVtcGFibGUocm9vdCkKICAgIGV4Y2VwdCBfUnVudGltZVdyaXRlclVuZGV0ZXJtaW5lZCBhcyBleGM6CiAgICAgICAgcmV0dXJuIFJVTlRJTUVfV1JJVEVSX1VOREVURVJNSU5FRCwgZXhjLnN0ZXAsIGV4Yy5kZXRhaWwKICAgIGlmIHZlcmRpY3QgPT0gUlVOVElNRV9XUklURVJfQ09ORkxJQ1Q6CiAgICAgICAgcmV0dXJuIHZlcmRpY3QsIF9SdW50aW1lV3JpdGVyU3RlcChzdGVwLCBSVU5USU1FX1dSSVRFUl9SVUxFX0FQUE9SVF9TWVNWKSwgZGV0YWlsCiAgICBpZiB2ZXJkaWN0ID09IFJVTlRJTUVfV1JJVEVSX1VOREVURVJNSU5FRDoKICAgICAgICByZXR1cm4gdmVyZGljdCwgc3RlcCwgZGV0YWlsCiAgICBpZiB2ZXJkaWN0ID09IFJVTlRJTUVfV1JJVEVSX05PX0NPTkZMSUNUOgogICAgICAgIGlmIG5hdGl2ZS5hdXhpbGlhcnlfbm9uZW1wdHk6CiAgICAgICAgICAgIHJldHVybiBSVU5USU1FX1dSSVRFUl9VTkRFVEVSTUlORUQsIF9SdW50aW1lV3JpdGVyU3RlcCgiQzYiLCBSVU5USU1FX1dSSVRFUl9SVUxFX0FQUE9SVF9OQVRJVkUpLCAiYXV4aWxpYXJ5LXdpdGgtc3lzdi1uby1jb25mbGljdCIKICAgICAgICByZXR1cm4gdmVyZGljdCwgc3RlcCwgZGV0YWlsCiAgICByZXR1cm4gUlVOVElNRV9XUklURVJfVU5ERVRFUk1JTkVELCAiZGV0ZWN0b3ItZmFpbHVyZSIsIE5vbmUKCgpkZWYgY2hlY2tfYXBwbHlfcHJpdmlsZWdlcyhwZXJzaXN0ZW50X3RhcmdldCwgcnVudGltZV90YXJnZXQpOgogICAgIiIiUmVhZC1vbmx5IFAzIGFwcHJveGltYXRpb246IHJlZnVzZSB3aGVuIGN1cnJlbnQgcHJvY2VzcyBsYWNrcyB3cml0ZSBhY2Nlc3MuIiIiCiAgICBwYXJlbnQgPSBzdHIoUHVyZVBvc2l4UGF0aChwZXJzaXN0ZW50X3RhcmdldCkucGFyZW50KQogICAgaWYgbm90IG9zLmFjY2VzcyhwYXJlbnQsIG9zLldfT0spIG9yIG5vdCBvcy5hY2Nlc3MocnVudGltZV90YXJnZXQsIG9zLldfT0spOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJwcml2aWxlZ2U6d3JpdGUtdW5hdmFpbGFibGUiKQoKCmRlZiBfc25hcHNob3RfZm9yX3Jlc3VsdChwYXRoKToKICAgIHRyeToKICAgICAgICByZXR1cm4gc25hcHNob3RfcGVyc2lzdGVudF90YXJnZXQocGF0aCkKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIE5vbmUKCgpkZWYgX3JlYWRfZm9yX3Jlc3VsdChyZWFkX3J1bnRpbWUpOgogICAgdHJ5OgogICAgICAgIHJldHVybiBfcmVxdWlyZV9pbnQocmVhZF9ydW50aW1lKCksICJydW50aW1lX2FmdGVyIikKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIE5vbmUKCgpkZWYgX29ic2VydmVfZmluYWxfcnVudGltZShyZWFkX3J1bnRpbWUpOgogICAgdHJ5OgogICAgICAgIHJhdyA9IHJlYWRfcnVudGltZSgpCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHJldHVybiBOb25lLCAicnVudGltZTpmaW5hbC1yZWFkLWZhaWx1cmUiCiAgICB0cnk6CiAgICAgICAgcmV0dXJuIF9yZXF1aXJlX2ludChyYXcsICJydW50aW1lX2FmdGVyIiksIE5vbmUKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIE5vbmUsICJydW50aW1lOmZpbmFsLXBhcnNlLWZhaWx1cmUiCgoKZGVmIF9jb21wZW5zYXRlX2FmdGVyX2ZhaWx1cmUoc3RhdGUsIGFjdGlvbnMsIG9yaWdpbmFsX3JlYXNvbik6CiAgICB0cnk6CiAgICAgICAgYWN0aW9ucy5hcHBlbmQoInBlcnNpc3RlbnRfY29tcGVuc2F0aW9uIikKICAgICAgICBjb21wZW5zYXRlX3BlcnNpc3RlbnQoc3RhdGUpCiAgICAgICAgcmV0dXJuIE9VVENPTUVfRkFJTEVEX05PVF9DT01NSVRURUQsIG9yaWdpbmFsX3JlYXNvbgogICAgZXhjZXB0IENvbXBlbnNhdGlvbkVycm9yIGFzIGV4YzoKICAgICAgICByZXR1cm4gT1VUQ09NRV9GQUlMRURfQ09NUEVOU0FUSU9OLCBvcmlnaW5hbF9yZWFzb24gKyAiO2NvbXBlbnNhdGlvbjoiICsgZXhjLmNvZGUKCgpkZWYgX3ByZWNvbmRpdGlvbl9yZWFzb24oZXhjKToKICAgIGlmIG5vdCBpc2luc3RhbmNlKGV4YywgUHJlY29uZGl0aW9uRXJyb3IpOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoImludmFsaWQgcHJlY29uZGl0aW9uIGVycm9yIikKICAgIGlmIGV4Yy5zb3VyY2UgaXMgTm9uZToKICAgICAgICByZXR1cm4gZXhjLmNvZGUKICAgIGlmIGlzaW5zdGFuY2UoZXhjLnNvdXJjZSwgdHVwbGUpOgogICAgICAgIGRldGFpbCA9ICIsIi5qb2luKHN0cihpdGVtKSBmb3IgaXRlbSBpbiBleGMuc291cmNlKQogICAgZWxzZToKICAgICAgICBkZXRhaWwgPSBzdHIoZXhjLnNvdXJjZSkKICAgIHJldHVybiBleGMuY29kZSArICI6IiArIGRldGFpbAoKCmRlZiBfcmV2YWxpZGF0ZV9wZXJzaXN0ZW50X2JlZm9yZV9ydW50aW1lKHRhcmdldF9wYXRoLCBwcmVzdGF0ZSk6CiAgICBuYW1lID0gUHVyZVBvc2l4UGF0aCh0YXJnZXRfcGF0aCkubmFtZQogICAgdHJ5OgogICAgICAgIGN1cnJlbnQgPSBzbmFwc2hvdF9wZXJzaXN0ZW50X3RhcmdldCh0YXJnZXRfcGF0aCkKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZXhjOgogICAgICAgIHJhaXNlIFByZWNvbmRpdGlvbkVycm9yKCJwZXJzaXN0ZW50OmRyaWZ0LWJlZm9yZS1ydW50aW1lIiwgbmFtZSkgZnJvbSBleGMKICAgIGlmIGN1cnJlbnQgIT0gcHJlc3RhdGU6CiAgICAgICAgcmFpc2UgUHJlY29uZGl0aW9uRXJyb3IoInBlcnNpc3RlbnQ6ZHJpZnQtYmVmb3JlLXJ1bnRpbWUiLCBuYW1lKQoKCmRlZiBleGVjdXRlX2NvbnRyb2woCiAgICBjb250cm9sX2lkLAogICAga2V5LAogICAgb3AsCiAgICBleHBlY3RlZCwKICAgIGFwcGx5X3N1cHBvcnRlZCwKICAgIHNvdXJjZV9maWxlcz1Ob25lLAogICAgKiwKICAgIHNvdXJjZV9yb290PSIvIiwKICAgIGRyeV9ydW49RmFsc2UsCiAgICBwZXJzaXN0ZW50X3RhcmdldD1Ob25lLAogICAgcnVudGltZV90YXJnZXQ9Tm9uZSwKICAgIHJlYWRfcnVudGltZT1Ob25lLAogICAgd3JpdGVfcnVudGltZT1Ob25lLAogICAgd3JpdGVfcnVudGltZV9wcm90b2NvbD1Ob25lLAogICAgcHJpdmlsZWdlX2NoZWNrPU5vbmUsCiAgICBydW50aW1lX3dyaXRlcl9kZXRlY3Rvcj1Ob25lLAogICAgcGVyc2lzdGVudF91aWQ9MCwKICAgIHBlcnNpc3RlbnRfZ2lkPTAsCiAgICBwZXJzaXN0ZW50X21vZGU9MG82NDQsCik6CiAgICAiIiJFeGVjdXRlIG9uZSBjb250cm9sIHRyYW5zYWN0aW9uIHVzaW5nIHRoZSByMTAgYnJhbmNoL2NvbXBlbnNhdGlvbiBzZW1hbnRpY3MuCgogICAgV2hlbiBgc291cmNlX2ZpbGVzYCBpcyBOb25lLCB0aGUgYWRhcHRlciByZWFkcyB0aGUgRDA4IHNvdXJjZSBzZXQgdGhyb3VnaAogICAgbG9hZF9zeXNjdGxfc291cmNlcygpLiBUZXN0cyBtYXkgcGFzcyBzdHJ1Y3R1cmVkIFNvdXJjZUZpbGUgb2JqZWN0cyBkaXJlY3RseQogICAgb3IgcmVkaXJlY3Qgc291cmNlX3Jvb3QvcGVyc2lzdGVudC9ydW50aW1lIHRhcmdldHMgYXdheSBmcm9tIHRoZSBob3N0LgogICAgIiIiCiAgICB2YWxpZGF0ZV9jb250cm9sX2lucHV0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBhcHBseV9zdXBwb3J0ZWQpCiAgICBpZiBub3QgaXNpbnN0YW5jZShkcnlfcnVuLCBib29sKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJkcnlfcnVuIG11c3QgYmUgYm9vbGVhbiIpCiAgICBmb3IgbmFtZSwgdmFsdWUgaW4gKCgicGVyc2lzdGVudF91aWQiLCBwZXJzaXN0ZW50X3VpZCksICgicGVyc2lzdGVudF9naWQiLCBwZXJzaXN0ZW50X2dpZCksICgicGVyc2lzdGVudF9tb2RlIiwgcGVyc2lzdGVudF9tb2RlKSk6CiAgICAgICAgaWYgaXNpbnN0YW5jZSh2YWx1ZSwgYm9vbCkgb3Igbm90IGlzaW5zdGFuY2UodmFsdWUsIGludCk6CiAgICAgICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoZiJ7bmFtZX0gbXVzdCBiZSBpbnRlZ2VyIikKCiAgICBhY3Rpb25zID0gWyJQMF9FTElHSUJJTElUWSJdCiAgICBpZiBub3QgYXBwbHlfc3VwcG9ydGVkOgogICAgICAgIHJldHVybiBfcmVzdWx0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBGYWxzZSwgT1VUQ09NRV9OT1RfRUxJR0lCTEUsCiAgICAgICAgICAgICAgICAgICAgICAgImFwcGx5LnN1cHBvcnRlZD1mYWxzZSIsIGFjdGlvbnM9YWN0aW9ucywgZHJ5X3J1bj1kcnlfcnVuKQoKICAgIHBlcnNpc3RlbnRfdGFyZ2V0ID0gcGVyc2lzdGVudF90YXJnZXQgb3IgcGVyc2lzdGVudF9wYXRoKGtleSkKICAgIHJ1bnRpbWVfdGFyZ2V0ID0gcnVudGltZV90YXJnZXQgb3IgcHJvY19wYXRoKGtleSkKICAgIHJlYWRfcnVudGltZSA9IHJlYWRfcnVudGltZSBvciAobGFtYmRhOiByZWFkX3J1bnRpbWVfcGF0aChydW50aW1lX3RhcmdldCkpCiAgICBpZiB3cml0ZV9ydW50aW1lIGlzIE5vbmU6CiAgICAgICAgd3JpdGVfcnVudGltZSA9IGxhbWJkYSB2YWx1ZTogd3JpdGVfcnVudGltZV9wYXRoKHJ1bnRpbWVfdGFyZ2V0LCB2YWx1ZSkKICAgICAgICB3cml0ZV9ydW50aW1lX3Byb3RvY29sID0gUlVOVElNRV9XUklURVJfUFJPVE9DT0xfVjEKICAgIGVsaWYgd3JpdGVfcnVudGltZV9wcm90b2NvbCAhPSBSVU5USU1FX1dSSVRFUl9QUk9UT0NPTF9WMToKICAgICAgICByZXR1cm4gX3Jlc3VsdCgKICAgICAgICAgICAgY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIFRydWUsIE9VVENPTUVfQUJPUlRfT1RIRVIsCiAgICAgICAgICAgICJydW50aW1lOndyaXRlci1wcm90b2NvbC1yZXF1aXJlZCIsIGFjdGlvbnM9YWN0aW9ucywgZHJ5X3J1bj1kcnlfcnVuLAogICAgICAgICkKICAgIHByaXZpbGVnZV9jaGVjayA9IHByaXZpbGVnZV9jaGVjayBvciAobGFtYmRhOiBjaGVja19hcHBseV9wcml2aWxlZ2VzKHBlcnNpc3RlbnRfdGFyZ2V0LCBydW50aW1lX3RhcmdldCkpCiAgICBydW50aW1lX3dyaXRlcl9kZXRlY3RvciA9IHJ1bnRpbWVfd3JpdGVyX2RldGVjdG9yIG9yICgKICAgICAgICBsYW1iZGEgY29udHJvbF9rZXk6IGRldGVjdF9ydW50aW1lX3dyaXRlcl9jb25mbGljdChjb250cm9sX2tleSwgc291cmNlX3Jvb3QpCiAgICApCgogICAgcnVudGltZV9iZWZvcmUgPSBOb25lCiAgICBwZXJzaXN0ZW50X2JlZm9yZSA9IE5vbmUKICAgIHByZWNlZGVuY2UgPSBOb25lCiAgICB0YXJnZXQgPSBOb25lCiAgICBicmFuY2ggPSBOb25lCiAgICBhdHRlbXB0X2lkZW50aXR5ID0gTm9uZQogICAgcnVudGltZV9wcmV3cml0ZSA9IE5vbmUKICAgIHJ1bnRpbWVfYWZ0ZXIgPSBOb25lCiAgICB3cml0dGVuX3ZhbHVlID0gTm9uZQogICAgbXV0YXRpb24gPSBGYWxzZQoKICAgICMgUDE6IHJ1bnRpbWUga2V5IHByZXNlbmNlL3JlYWRhYmlsaXR5IGFuZCBpbnRlZ2VyIHNlbWFudGljcy4KICAgIGFjdGlvbnMuYXBwZW5kKCJQMV9SVU5USU1FX0tFWV9QUkVTRU5UIikKICAgIHRyeToKICAgICAgICBydW50aW1lX2JlZm9yZSA9IF9yZXF1aXJlX2ludChyZWFkX3J1bnRpbWUoKSwgInJ1bnRpbWVfYmVmb3JlIikKICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvcjoKICAgICAgICByZXR1cm4gX3Jlc3VsdChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgVHJ1ZSwgT1VUQ09NRV9OT1RfQVBQTElDQUJMRSwKICAgICAgICAgICAgICAgICAgICAgICAicnVudGltZTprZXktYWJzZW50IiwgYWN0aW9ucz1hY3Rpb25zLCBkcnlfcnVuPWRyeV9ydW4pCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGV4YzoKICAgICAgICByZXR1cm4gX3Jlc3VsdChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgVHJ1ZSwgT1VUQ09NRV9BQk9SVF9PVEhFUiwKICAgICAgICAgICAgICAgICAgICAgICAicnVudGltZTppbml0aWFsLXJlYWQtZmFpbHVyZSIsIGFjdGlvbnM9YWN0aW9ucywgZHJ5X3J1bj1kcnlfcnVuKQoKICAgICMgUDI6IHNvdXJjZSBkaXNjb3ZlcnkvcGFyc2luZy9wcmVjZWRlbmNlIGFuZCBvd24gcGVyc2lzdGVudCBvYnNlcnZhdGlvbi4KICAgICMgRm9yIHByb2R1Y3Rpb24gZmlsZXN5c3RlbSBkaXNjb3ZlcnksIHJlbWVtYmVyIHdoZXRoZXIgUDIgYWN0dWFsbHkgb2JzZXJ2ZWQKICAgICMgdGhlIG93biBiYXNlbmFtZS4gVGhlIGZvbGxvd2luZyB0YXJnZXQgc25hcHNob3QgbXVzdCBhZ3JlZSB3aXRoIHRoYXQgZmFjdC4KICAgIGFjdGlvbnMuYXBwZW5kKCJQMl9TT1VSQ0VfUFJFQ0VERU5DRSIpCiAgICBvd25fcHJlc2VudF9kdXJpbmdfcDIgPSBOb25lCiAgICB0cnk6CiAgICAgICAgaWYgc291cmNlX2ZpbGVzIGlzIE5vbmU6CiAgICAgICAgICAgIHNvdXJjZV9maWxlcyA9IGxvYWRfc3lzY3RsX3NvdXJjZXMoa2V5LCBzb3VyY2Vfcm9vdCkKICAgICAgICAgICAgb3duX3BhdGggPSBwZXJzaXN0ZW50X3BhdGgoa2V5KQogICAgICAgICAgICBvd25fcHJlc2VudF9kdXJpbmdfcDIgPSBhbnkoc3JjLnBhdGggPT0gb3duX3BhdGggZm9yIHNyYyBpbiBzb3VyY2VfZmlsZXMpCiAgICAgICAgcHJlY2VkZW5jZSA9IHJlc29sdmVfcHJlY2VkZW5jZShrZXksIHNvdXJjZV9maWxlcykKICAgIGV4Y2VwdCBQcmVjb25kaXRpb25FcnJvciBhcyBleGM6CiAgICAgICAgb3V0Y29tZSA9IE9VVENPTUVfQUJPUlRfQ09ORkxJQ1QgaWYgZXhjLmNvZGUgPT0gInNvdXJjZTpsYXRlLWNvbmZsaWN0IiBlbHNlIE9VVENPTUVfQUJPUlRfT1RIRVIKICAgICAgICAjIEg0Ni1EMDg6IGEgUDIgcmVmdXNhbCBkb2VzIG5vdCBjaGFuZ2UgdGhlIG93biBmaWxlLCBidXQgdGhlIHJlcG9ydCBtdXN0CiAgICAgICAgIyBzdGlsbCBjYXJyeSBpdHMgZmFjdHVhbCBzdGF0ZSB3aGVuIGl0IGNhbiBiZSBvYnNlcnZlZCByZWFkLW9ubHkuCiAgICAgICAgcGVyc2lzdGVudF9iZWZvcmUgPSBfc25hcHNob3RfZm9yX3Jlc3VsdChwZXJzaXN0ZW50X3RhcmdldCkKICAgICAgICByZXR1cm4gX3Jlc3VsdChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgVHJ1ZSwgb3V0Y29tZSwgX3ByZWNvbmRpdGlvbl9yZWFzb24oZXhjKSwKICAgICAgICAgICAgICAgICAgICAgICBydW50aW1lX2JlZm9yZT1ydW50aW1lX2JlZm9yZSwgcGVyc2lzdGVudF9iZWZvcmU9cGVyc2lzdGVudF9iZWZvcmUsCiAgICAgICAgICAgICAgICAgICAgICAgcGVyc2lzdGVudF9hZnRlcj1wZXJzaXN0ZW50X2JlZm9yZSwgYWN0aW9ucz1hY3Rpb25zLCBkcnlfcnVuPWRyeV9ydW4pCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHBlcnNpc3RlbnRfYmVmb3JlID0gX3NuYXBzaG90X2Zvcl9yZXN1bHQocGVyc2lzdGVudF90YXJnZXQpCiAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIFRydWUsIE9VVENPTUVfQUJPUlRfT1RIRVIsCiAgICAgICAgICAgICAgICAgICAgICAgInNvdXJjZTpwcmVjZWRlbmNlLWZhaWx1cmUiLCBydW50aW1lX2JlZm9yZT1ydW50aW1lX2JlZm9yZSwKICAgICAgICAgICAgICAgICAgICAgICBwZXJzaXN0ZW50X2JlZm9yZT1wZXJzaXN0ZW50X2JlZm9yZSwgcGVyc2lzdGVudF9hZnRlcj1wZXJzaXN0ZW50X2JlZm9yZSwKICAgICAgICAgICAgICAgICAgICAgICBhY3Rpb25zPWFjdGlvbnMsIGRyeV9ydW49ZHJ5X3J1bikKCiAgICB0cnk6CiAgICAgICAgcGVyc2lzdGVudF9iZWZvcmUgPSBzbmFwc2hvdF9wZXJzaXN0ZW50X3RhcmdldChwZXJzaXN0ZW50X3RhcmdldCkKICAgIGV4Y2VwdCBQcmVjb25kaXRpb25FcnJvciBhcyBleGM6CiAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIFRydWUsIE9VVENPTUVfQUJPUlRfT1RIRVIsIF9wcmVjb25kaXRpb25fcmVhc29uKGV4YyksCiAgICAgICAgICAgICAgICAgICAgICAgZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWU9cHJlY2VkZW5jZS5lZmZlY3RpdmVfZm9yZWlnbl92YWx1ZSwKICAgICAgICAgICAgICAgICAgICAgICBydW50aW1lX2JlZm9yZT1ydW50aW1lX2JlZm9yZSwgYWN0aW9ucz1hY3Rpb25zLCBkcnlfcnVuPWRyeV9ydW4pCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHJldHVybiBfcmVzdWx0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBUcnVlLCBPVVRDT01FX0FCT1JUX09USEVSLAogICAgICAgICAgICAgICAgICAgICAgICJwZXJzaXN0ZW50OmluaXRpYWwtcmVhZC1mYWlsdXJlIiwKICAgICAgICAgICAgICAgICAgICAgICBlZmZlY3RpdmVfZm9yZWlnbl92YWx1ZT1wcmVjZWRlbmNlLmVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlLAogICAgICAgICAgICAgICAgICAgICAgIHJ1bnRpbWVfYmVmb3JlPXJ1bnRpbWVfYmVmb3JlLCBhY3Rpb25zPWFjdGlvbnMsIGRyeV9ydW49ZHJ5X3J1bikKCiAgICBpZiBvd25fcHJlc2VudF9kdXJpbmdfcDIgaXMgbm90IE5vbmUgYW5kIHBlcnNpc3RlbnRfYmVmb3JlLmV4aXN0cyAhPSBvd25fcHJlc2VudF9kdXJpbmdfcDI6CiAgICAgICAgcmV0dXJuIF9yZXN1bHQoCiAgICAgICAgICAgIGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBUcnVlLCBPVVRDT01FX0FCT1JUX09USEVSLAogICAgICAgICAgICAicGVyc2lzdGVudDpvYnNlcnZhdGlvbi1kcmlmdCIsCiAgICAgICAgICAgIGVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlPXByZWNlZGVuY2UuZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWUsCiAgICAgICAgICAgIHJ1bnRpbWVfYmVmb3JlPXJ1bnRpbWVfYmVmb3JlLCBwZXJzaXN0ZW50X2JlZm9yZT1wZXJzaXN0ZW50X2JlZm9yZSwKICAgICAgICAgICAgcGVyc2lzdGVudF9hZnRlcj1wZXJzaXN0ZW50X2JlZm9yZSwgYWN0aW9ucz1hY3Rpb25zLCBkcnlfcnVuPWRyeV9ydW4sCiAgICAgICAgKQoKICAgIG93bl92YWx1ZSA9IE5vbmUKICAgIGlmIG9wID09ICJnZSIgYW5kIHBlcnNpc3RlbnRfYmVmb3JlLmV4aXN0czoKICAgICAgICB0cnk6CiAgICAgICAgICAgIG93bl92YWx1ZSA9IG93bl9wZXJzaXN0ZW50X3ZhbHVlKGtleSwgcGVyc2lzdGVudF9iZWZvcmUucmF3X2J5dGVzKQogICAgICAgIGV4Y2VwdCBQcmVjb25kaXRpb25FcnJvciBhcyBleGM6CiAgICAgICAgICAgIHJldHVybiBfcmVzdWx0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBUcnVlLCBPVVRDT01FX0FCT1JUX09USEVSLCBfcHJlY29uZGl0aW9uX3JlYXNvbihleGMpLAogICAgICAgICAgICAgICAgICAgICAgICAgICBlZmZlY3RpdmVfZm9yZWlnbl92YWx1ZT1wcmVjZWRlbmNlLmVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlLAogICAgICAgICAgICAgICAgICAgICAgICAgICBydW50aW1lX2JlZm9yZT1ydW50aW1lX2JlZm9yZSwgcGVyc2lzdGVudF9iZWZvcmU9cGVyc2lzdGVudF9iZWZvcmUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgIHBlcnNpc3RlbnRfYWZ0ZXI9cGVyc2lzdGVudF9iZWZvcmUsIGFjdGlvbnM9YWN0aW9ucywgZHJ5X3J1bj1kcnlfcnVuKQoKICAgIHRyeToKICAgICAgICB0YXJnZXQgPSBjb21wdXRlX3RhcmdldF92YWx1ZShvcCwgZXhwZWN0ZWQsIHJ1bnRpbWVfYmVmb3JlLCBvd25fdmFsdWUsIHByZWNlZGVuY2UuZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWUpCiAgICAgICAgcGVyc2lzdGVudF9vayA9IHBlcnNpc3RlbnRfaXNfY29tcGxpYW50KAogICAgICAgICAgICBrZXksIHRhcmdldCwKICAgICAgICAgICAgcGVyc2lzdGVudF9iZWZvcmUucmF3X2J5dGVzIGlmIHBlcnNpc3RlbnRfYmVmb3JlLmV4aXN0cyBlbHNlIE5vbmUsCiAgICAgICAgICAgIHBlcnNpc3RlbnRfYmVmb3JlLnVpZCBpZiBwZXJzaXN0ZW50X2JlZm9yZS5leGlzdHMgZWxzZSBOb25lLAogICAgICAgICAgICBwZXJzaXN0ZW50X2JlZm9yZS5naWQgaWYgcGVyc2lzdGVudF9iZWZvcmUuZXhpc3RzIGVsc2UgTm9uZSwKICAgICAgICAgICAgcGVyc2lzdGVudF9iZWZvcmUubW9kZSBpZiBwZXJzaXN0ZW50X2JlZm9yZS5leGlzdHMgZWxzZSBOb25lLAogICAgICAgICAgICBwZXJzaXN0ZW50X3VpZCwgcGVyc2lzdGVudF9naWQsIHBlcnNpc3RlbnRfbW9kZSwKICAgICAgICApCiAgICAgICAgcnVudGltZV9vayA9IHJ1bnRpbWVfaXNfY29tcGxpYW50KG9wLCBydW50aW1lX2JlZm9yZSwgdGFyZ2V0KQogICAgICAgIGJyYW5jaCA9IHNlbGVjdF9icmFuY2gocnVudGltZV9vaywgcGVyc2lzdGVudF9vaykKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIFRydWUsIE9VVENPTUVfQUJPUlRfT1RIRVIsCiAgICAgICAgICAgICAgICAgICAgICAgInBsYW5uaW5nOmZhaWx1cmUiLCBlZmZlY3RpdmVfZm9yZWlnbl92YWx1ZT1wcmVjZWRlbmNlLmVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlLAogICAgICAgICAgICAgICAgICAgICAgIHJ1bnRpbWVfYmVmb3JlPXJ1bnRpbWVfYmVmb3JlLCBwZXJzaXN0ZW50X2JlZm9yZT1wZXJzaXN0ZW50X2JlZm9yZSwKICAgICAgICAgICAgICAgICAgICAgICBwZXJzaXN0ZW50X2FmdGVyPXBlcnNpc3RlbnRfYmVmb3JlLCBhY3Rpb25zPWFjdGlvbnMsIGRyeV9ydW49ZHJ5X3J1bikKCiAgICAjIFAzOiByZWFkLW9ubHkgcHJpdmlsZWdlL2FjY2VzcyBwcmVjb25kaXRpb24gYmVmb3JlIHRhcmdldCBtdXRhdGlvbi4KICAgIGFjdGlvbnMuYXBwZW5kKCJQM19QUklWSUxFR0UiKQogICAgdHJ5OgogICAgICAgIHByaXZpbGVnZV9jaGVjaygpCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHJldHVybiBfcmVzdWx0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBUcnVlLCBPVVRDT01FX0FCT1JUX09USEVSLAogICAgICAgICAgICAgICAgICAgICAgICJwcml2aWxlZ2U6d3JpdGUtdW5hdmFpbGFibGUiLCBicmFuY2g9YnJhbmNoLCB0YXJnZXRfdmFsdWU9dGFyZ2V0LAogICAgICAgICAgICAgICAgICAgICAgIGVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlPXByZWNlZGVuY2UuZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWUsCiAgICAgICAgICAgICAgICAgICAgICAgcnVudGltZV9iZWZvcmU9cnVudGltZV9iZWZvcmUsIHBlcnNpc3RlbnRfYmVmb3JlPXBlcnNpc3RlbnRfYmVmb3JlLAogICAgICAgICAgICAgICAgICAgICAgIHBlcnNpc3RlbnRfYWZ0ZXI9cGVyc2lzdGVudF9iZWZvcmUsIGFjdGlvbnM9YWN0aW9ucywgZHJ5X3J1bj1kcnlfcnVuKQoKICAgICMgUDJSIChINDYtRDE2KTogcmVhZC1vbmx5IHJ1bnRpbWUtd3JpdGVyIGNvbmZsaWN0IHByZWNvbmRpdGlvbi4gSXQgcnVucyBhZnRlcgogICAgIyBQMyBhbmQgYmVmb3JlIHRoZSBkcnktcnVuIG91dGNvbWUgb3IgdGhlIGZpcnN0IHRhcmdldCBtdXRhdGlvbiwgaWRlbnRpY2FsbHkKICAgICMgaW4gQVBQTFkgYW5kIGRyeS1ydW4uCiAgICBpZiBrZXkgaW4gUlVOVElNRV9XUklURVJfUlVMRVM6CiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlAyUl9SVU5USU1FX1dSSVRFUiIpCiAgICAgICAgdHJ5OgogICAgICAgICAgICB2ZXJkaWN0LCBzdGVwLCBkZXRhaWwgPSBydW50aW1lX3dyaXRlcl9kZXRlY3RvcihrZXkpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgdmVyZGljdCwgc3RlcCwgZGV0YWlsID0gUlVOVElNRV9XUklURVJfVU5ERVRFUk1JTkVELCAiZGV0ZWN0b3ItZmFpbHVyZSIsIE5vbmUKICAgICAgICBpZiB2ZXJkaWN0IG5vdCBpbiAoUlVOVElNRV9XUklURVJfQ09ORkxJQ1QsIFJVTlRJTUVfV1JJVEVSX05PX0NPTkZMSUNULCBSVU5USU1FX1dSSVRFUl9VTkRFVEVSTUlORUQpOgogICAgICAgICAgICB2ZXJkaWN0LCBzdGVwLCBkZXRhaWwgPSBSVU5USU1FX1dSSVRFUl9VTkRFVEVSTUlORUQsICJkZXRlY3Rvci1mYWlsdXJlIiwgTm9uZQogICAgICAgIGlmIHZlcmRpY3QgIT0gUlVOVElNRV9XUklURVJfTk9fQ09ORkxJQ1Q6CiAgICAgICAgICAgIHJ1bGVfaWQgPSBnZXRhdHRyKHN0ZXAsICJydWxlX2lkIiwgTm9uZSkKICAgICAgICAgICAgaWYgdmVyZGljdCA9PSBSVU5USU1FX1dSSVRFUl9DT05GTElDVDoKICAgICAgICAgICAgICAgIG91dGNvbWUgPSBPVVRDT01FX0FCT1JUX0NPTkZMSUNUCiAgICAgICAgICAgICAgICByZWFzb24gPSAicnVudGltZS13cml0ZXI6IiArIChydWxlX2lkIG9yIFJVTlRJTUVfV1JJVEVSX1JVTEVTW2tleV0pCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBvdXRjb21lID0gT1VUQ09NRV9BQk9SVF9PVEhFUgogICAgICAgICAgICAgICAgcmVhc29uID0gInJ1bnRpbWUtd3JpdGVyOnVuZGV0ZXJtaW5lZCIKICAgICAgICAgICAgICAgIGlmIHJ1bGVfaWQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICAgICAgcmVhc29uICs9ICI6IiArIHJ1bGVfaWQKICAgICAgICAgICAgZm9yIHBhcnQgaW4gKHN0ZXAsIGRldGFpbCk6CiAgICAgICAgICAgICAgICBpZiBwYXJ0IGlzIG5vdCBOb25lOgogICAgICAgICAgICAgICAgICAgIHJlYXNvbiArPSAiOiIgKyBzdHIocGFydCkKICAgICAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIFRydWUsIG91dGNvbWUsIHJlYXNvbiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJhbmNoPWJyYW5jaCwgdGFyZ2V0X3ZhbHVlPXRhcmdldCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWU9cHJlY2VkZW5jZS5lZmZlY3RpdmVfZm9yZWlnbl92YWx1ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgcnVudGltZV9iZWZvcmU9cnVudGltZV9iZWZvcmUsIHBlcnNpc3RlbnRfYmVmb3JlPXBlcnNpc3RlbnRfYmVmb3JlLAogICAgICAgICAgICAgICAgICAgICAgICAgICBwZXJzaXN0ZW50X2FmdGVyPXBlcnNpc3RlbnRfYmVmb3JlLCBhY3Rpb25zPWFjdGlvbnMsIGRyeV9ydW49ZHJ5X3J1bikKCiAgICBpZiBkcnlfcnVuOgogICAgICAgIG91dGNvbWUgPSBPVVRDT01FX0FMUkVBRFlfQ09NUExJQU5UIGlmIGJyYW5jaCA9PSBCUkFOQ0hfQUxSRUFEWSBlbHNlIE9VVENPTUVfRFJZX1JVTl9XT1VMRF9BUFBMWQogICAgICAgIHJlYXNvbiA9ICJhbHJlYWR5LWNvbXBsaWFudCIgaWYgYnJhbmNoID09IEJSQU5DSF9BTFJFQURZIGVsc2UgIndvdWxkLWFwcGx5OiIgKyBicmFuY2gKICAgICAgICByZXR1cm4gX3Jlc3VsdChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgVHJ1ZSwgb3V0Y29tZSwgcmVhc29uLAogICAgICAgICAgICAgICAgICAgICAgIGJyYW5jaD1icmFuY2gsIHRhcmdldF92YWx1ZT10YXJnZXQsCiAgICAgICAgICAgICAgICAgICAgICAgZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWU9cHJlY2VkZW5jZS5lZmZlY3RpdmVfZm9yZWlnbl92YWx1ZSwKICAgICAgICAgICAgICAgICAgICAgICBydW50aW1lX2JlZm9yZT1ydW50aW1lX2JlZm9yZSwgcnVudGltZV9hZnRlcj1ydW50aW1lX2JlZm9yZSwKICAgICAgICAgICAgICAgICAgICAgICBwZXJzaXN0ZW50X2JlZm9yZT1wZXJzaXN0ZW50X2JlZm9yZSwgcGVyc2lzdGVudF9hZnRlcj1wZXJzaXN0ZW50X2JlZm9yZSwKICAgICAgICAgICAgICAgICAgICAgICBhY3Rpb25zPWFjdGlvbnMsIGNvbW1pdD1DT01NSVRfTk9UX1NUQVJURUQsIGRyeV9ydW49VHJ1ZSkKCiAgICBwZXJzaXN0ZW50X3N0YXRlID0gTm9uZQogICAgcnVudGltZV9yZXN1bHQgPSBOb25lCgogICAgaWYgYnJhbmNoIGluIChCUkFOQ0hfUEVSU0lTVEVOVF9PTkxZLCBCUkFOQ0hfQk9USCk6CiAgICAgICAgYWN0aW9ucy5hcHBlbmQoIlBIQVNFMV9QRVJTSVNURU5UIikKICAgICAgICB0cnk6CiAgICAgICAgICAgIHBlcnNpc3RlbnRfc3RhdGUgPSBhcHBseV9wZXJzaXN0ZW50X2NoYW5nZSgKICAgICAgICAgICAgICAgIHBlcnNpc3RlbnRfdGFyZ2V0LCBjYW5vbmljYWxfcGVyc2lzdGVudF9ieXRlcyhrZXksIHRhcmdldCksCiAgICAgICAgICAgICAgICBwZXJzaXN0ZW50X3VpZCwgcGVyc2lzdGVudF9naWQsIHBlcnNpc3RlbnRfbW9kZSwKICAgICAgICAgICAgICAgIGV4cGVjdGVkX3ByZXN0YXRlPXBlcnNpc3RlbnRfYmVmb3JlLAogICAgICAgICAgICApCiAgICAgICAgICAgIGF0dGVtcHRfaWRlbnRpdHkgPSBwZXJzaXN0ZW50X3N0YXRlLmF0dGVtcHRfd3JpdHRlbl9pZGVudGl0eQogICAgICAgICAgICBtdXRhdGlvbiA9IFRydWUKICAgICAgICBleGNlcHQgUHJlY29uZGl0aW9uRXJyb3IgYXMgZXhjOgogICAgICAgICAgICByZXR1cm4gX3Jlc3VsdChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgVHJ1ZSwgT1VUQ09NRV9BQk9SVF9PVEhFUiwgX3ByZWNvbmRpdGlvbl9yZWFzb24oZXhjKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJhbmNoPWJyYW5jaCwgdGFyZ2V0X3ZhbHVlPXRhcmdldCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWU9cHJlY2VkZW5jZS5lZmZlY3RpdmVfZm9yZWlnbl92YWx1ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgcnVudGltZV9iZWZvcmU9cnVudGltZV9iZWZvcmUsIHBlcnNpc3RlbnRfYmVmb3JlPXBlcnNpc3RlbnRfYmVmb3JlLAogICAgICAgICAgICAgICAgICAgICAgICAgICBwZXJzaXN0ZW50X2FmdGVyPV9zbmFwc2hvdF9mb3JfcmVzdWx0KHBlcnNpc3RlbnRfdGFyZ2V0KSwgYWN0aW9ucz1hY3Rpb25zLAogICAgICAgICAgICAgICAgICAgICAgICAgICBtdXRhdGlvbj1GYWxzZSwgY29tbWl0PUNPTU1JVF9OT1RfU1RBUlRFRCwgZHJ5X3J1bj1GYWxzZSkKICAgICAgICBleGNlcHQgUGVyc2lzdGVudFBoYXNlRXJyb3IgYXMgZXhjOgogICAgICAgICAgICByZXR1cm4gX3Jlc3VsdChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgVHJ1ZSwgZXhjLm91dGNvbWUsIGV4Yy5jb2RlLAogICAgICAgICAgICAgICAgICAgICAgICAgICBicmFuY2g9YnJhbmNoLCB0YXJnZXRfdmFsdWU9dGFyZ2V0LAogICAgICAgICAgICAgICAgICAgICAgICAgICBlZmZlY3RpdmVfZm9yZWlnbl92YWx1ZT1wcmVjZWRlbmNlLmVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlLAogICAgICAgICAgICAgICAgICAgICAgICAgICBydW50aW1lX2JlZm9yZT1ydW50aW1lX2JlZm9yZSwgcnVudGltZV9hZnRlcj1fcmVhZF9mb3JfcmVzdWx0KHJlYWRfcnVudGltZSksCiAgICAgICAgICAgICAgICAgICAgICAgICAgIHBlcnNpc3RlbnRfYmVmb3JlPXBlcnNpc3RlbnRfYmVmb3JlLCBwZXJzaXN0ZW50X2FmdGVyPV9zbmFwc2hvdF9mb3JfcmVzdWx0KHBlcnNpc3RlbnRfdGFyZ2V0KSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgYWN0aW9ucz1hY3Rpb25zLCBtdXRhdGlvbj1leGMubXV0YXRpb25fcGVyZm9ybWVkLAogICAgICAgICAgICAgICAgICAgICAgICAgICBjb21taXQ9Q09NTUlUX05PVF9DT01NSVRURUQsIGF0dGVtcHRfaWRlbnRpdHk9ZXhjLmF0dGVtcHRfd3JpdHRlbl9pZGVudGl0eSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgZHJ5X3J1bj1GYWxzZSkKCiAgICBpZiBicmFuY2ggaW4gKEJSQU5DSF9SVU5USU1FX09OTFksIEJSQU5DSF9CT1RIKToKICAgICAgICBhY3Rpb25zLmFwcGVuZCgiUEhBU0UyX1JVTlRJTUUiKQogICAgICAgIHByZV93cml0ZV9ndWFyZCA9IE5vbmUKICAgICAgICBpZiBicmFuY2ggPT0gQlJBTkNIX1JVTlRJTUVfT05MWToKICAgICAgICAgICAgcHJlX3dyaXRlX2d1YXJkID0gbGFtYmRhOiBfcmV2YWxpZGF0ZV9wZXJzaXN0ZW50X2JlZm9yZV9ydW50aW1lKAogICAgICAgICAgICAgICAgcGVyc2lzdGVudF90YXJnZXQsIHBlcnNpc3RlbnRfYmVmb3JlCiAgICAgICAgICAgICkKICAgICAgICB0cnk6CiAgICAgICAgICAgIHJ1bnRpbWVfcmVzdWx0ID0gZXhlY3V0ZV9ydW50aW1lX3BoYXNlKAogICAgICAgICAgICAgICAgb3AsIHRhcmdldCwgcmVhZF9ydW50aW1lLCB3cml0ZV9ydW50aW1lLAogICAgICAgICAgICAgICAgd3JpdGVyX3Byb3RvY29sPVJVTlRJTUVfV1JJVEVSX1BST1RPQ09MX1YxLAogICAgICAgICAgICAgICAgcHJlX3dyaXRlX2d1YXJkPXByZV93cml0ZV9ndWFyZCwKICAgICAgICAgICAgKQogICAgICAgICAgICBydW50aW1lX3ByZXdyaXRlID0gcnVudGltZV9yZXN1bHQucnVudGltZV9wcmV3cml0ZQogICAgICAgICAgICBydW50aW1lX2FmdGVyID0gcnVudGltZV9yZXN1bHQucnVudGltZV9hZnRlcgogICAgICAgICAgICB3cml0dGVuX3ZhbHVlID0gcnVudGltZV9yZXN1bHQud3JpdHRlbl92YWx1ZQogICAgICAgICAgICBtdXRhdGlvbiA9IG11dGF0aW9uIG9yIHJ1bnRpbWVfcmVzdWx0LndyaXRlX3BlcmZvcm1lZAogICAgICAgIGV4Y2VwdCBSdW50aW1lTXV0YXRpb25QcmVjb25kaXRpb25FcnJvciBhcyBleGM6CiAgICAgICAgICAgIHJ1bnRpbWVfcHJld3JpdGUgPSBleGMucnVudGltZV9wcmV3cml0ZQogICAgICAgICAgICByZXR1cm4gX3Jlc3VsdCgKICAgICAgICAgICAgICAgIGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBUcnVlLCBPVVRDT01FX0FCT1JUX09USEVSLCBleGMucmVhc29uLAogICAgICAgICAgICAgICAgYnJhbmNoPWJyYW5jaCwgdGFyZ2V0X3ZhbHVlPXRhcmdldCwKICAgICAgICAgICAgICAgIGVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlPXByZWNlZGVuY2UuZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWUsCiAgICAgICAgICAgICAgICBydW50aW1lX2JlZm9yZT1ydW50aW1lX2JlZm9yZSwgcnVudGltZV9wcmV3cml0ZT1ydW50aW1lX3ByZXdyaXRlLAogICAgICAgICAgICAgICAgcnVudGltZV9hZnRlcj1ydW50aW1lX3ByZXdyaXRlLCBwZXJzaXN0ZW50X2JlZm9yZT1wZXJzaXN0ZW50X2JlZm9yZSwKICAgICAgICAgICAgICAgIHBlcnNpc3RlbnRfYWZ0ZXI9X3NuYXBzaG90X2Zvcl9yZXN1bHQocGVyc2lzdGVudF90YXJnZXQpLAogICAgICAgICAgICAgICAgd3JpdHRlbl92YWx1ZT1Ob25lLCBhY3Rpb25zPWFjdGlvbnMsIG11dGF0aW9uPUZhbHNlLAogICAgICAgICAgICAgICAgY29tbWl0PUNPTU1JVF9OT1RfU1RBUlRFRCwgYXR0ZW1wdF9pZGVudGl0eT1hdHRlbXB0X2lkZW50aXR5LCBkcnlfcnVuPUZhbHNlLAogICAgICAgICAgICApCiAgICAgICAgZXhjZXB0IFJ1bnRpbWVQaGFzZUVycm9yIGFzIGV4YzoKICAgICAgICAgICAgcnVudGltZV9wcmV3cml0ZSA9IGV4Yy5ydW50aW1lX3ByZXdyaXRlCiAgICAgICAgICAgIHJ1bnRpbWVfYWZ0ZXIgPSBleGMucnVudGltZV9hZnRlciBpZiBleGMucnVudGltZV9hZnRlciBpcyBub3QgTm9uZSBlbHNlIF9yZWFkX2Zvcl9yZXN1bHQocmVhZF9ydW50aW1lKQogICAgICAgICAgICB3cml0dGVuX3ZhbHVlID0gZXhjLndyaXR0ZW5fdmFsdWUKICAgICAgICAgICAgbXV0YXRpb24gPSBtdXRhdGlvbiBvciBleGMud3JpdGVfcGVyZm9ybWVkCiAgICAgICAgICAgIGlmIHBlcnNpc3RlbnRfc3RhdGUgaXMgbm90IE5vbmU6CiAgICAgICAgICAgICAgICBvdXRjb21lLCByZWFzb24gPSBfY29tcGVuc2F0ZV9hZnRlcl9mYWlsdXJlKHBlcnNpc3RlbnRfc3RhdGUsIGFjdGlvbnMsIGV4Yy5jb2RlKQogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgb3V0Y29tZSwgcmVhc29uID0gT1VUQ09NRV9GQUlMRURfTk9UX0NPTU1JVFRFRCwgZXhjLmNvZGUKICAgICAgICAgICAgcmV0dXJuIF9yZXN1bHQoY29udHJvbF9pZCwga2V5LCBvcCwgZXhwZWN0ZWQsIFRydWUsIG91dGNvbWUsIHJlYXNvbiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgYnJhbmNoPWJyYW5jaCwgdGFyZ2V0X3ZhbHVlPXRhcmdldCwKICAgICAgICAgICAgICAgICAgICAgICAgICAgZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWU9cHJlY2VkZW5jZS5lZmZlY3RpdmVfZm9yZWlnbl92YWx1ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgcnVudGltZV9iZWZvcmU9cnVudGltZV9iZWZvcmUsIHJ1bnRpbWVfcHJld3JpdGU9cnVudGltZV9wcmV3cml0ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgcnVudGltZV9hZnRlcj1ydW50aW1lX2FmdGVyLCBwZXJzaXN0ZW50X2JlZm9yZT1wZXJzaXN0ZW50X2JlZm9yZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVyc2lzdGVudF9hZnRlcj1fc25hcHNob3RfZm9yX3Jlc3VsdChwZXJzaXN0ZW50X3RhcmdldCksIHdyaXR0ZW5fdmFsdWU9d3JpdHRlbl92YWx1ZSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgYWN0aW9ucz1hY3Rpb25zLCBtdXRhdGlvbj1tdXRhdGlvbiwgY29tbWl0PUNPTU1JVF9OT1RfQ09NTUlUVEVELAogICAgICAgICAgICAgICAgICAgICAgICAgICBhdHRlbXB0X2lkZW50aXR5PWF0dGVtcHRfaWRlbnRpdHksIGRyeV9ydW49RmFsc2UpCgogICAgIyBGaW5hbCBwb3N0LWNoZWNrIG9mIGJvdGggY29tcG9uZW50cy4gTm8gaW1wbGljaXQgYnJhbmNoIGNoYW5nZSBpcyBhbGxvd2VkLgogICAgYWN0aW9ucy5hcHBlbmQoIkZJTkFMX1BPU1RDSEVDSyIpCiAgICBmaW5hbF9ydW50aW1lLCBmaW5hbF9ydW50aW1lX2Vycm9yID0gX29ic2VydmVfZmluYWxfcnVudGltZShyZWFkX3J1bnRpbWUpCiAgICBmaW5hbF9wZXJzaXN0ZW50X2Vycm9yID0gTm9uZQogICAgdHJ5OgogICAgICAgIGZpbmFsX3BlcnNpc3RlbnQgPSBzbmFwc2hvdF9wZXJzaXN0ZW50X3RhcmdldChwZXJzaXN0ZW50X3RhcmdldCkKICAgIGV4Y2VwdCBQcmVjb25kaXRpb25FcnJvciBhcyBleGM6CiAgICAgICAgZmluYWxfcGVyc2lzdGVudCA9IE5vbmUKICAgICAgICBmaW5hbF9wZXJzaXN0ZW50X2Vycm9yID0gX3ByZWNvbmRpdGlvbl9yZWFzb24oZXhjKQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICBmaW5hbF9wZXJzaXN0ZW50ID0gTm9uZQogICAgICAgIGZpbmFsX3BlcnNpc3RlbnRfZXJyb3IgPSAicGVyc2lzdGVudDpmaW5hbC1yZWFkLWZhaWx1cmUiCgogICAgcnVudGltZV9maW5hbF9vayA9ICgKICAgICAgICBmaW5hbF9ydW50aW1lX2Vycm9yIGlzIE5vbmUgYW5kIGZpbmFsX3J1bnRpbWUgaXMgbm90IE5vbmUKICAgICAgICBhbmQgcnVudGltZV9pc19jb21wbGlhbnQob3AsIGZpbmFsX3J1bnRpbWUsIHRhcmdldCkKICAgICkKICAgIHBlcnNpc3RlbnRfZmluYWxfb2sgPSAoCiAgICAgICAgZmluYWxfcGVyc2lzdGVudF9lcnJvciBpcyBOb25lIGFuZCBmaW5hbF9wZXJzaXN0ZW50IGlzIG5vdCBOb25lIGFuZCBmaW5hbF9wZXJzaXN0ZW50LmV4aXN0cyBhbmQKICAgICAgICBwZXJzaXN0ZW50X2lzX2NvbXBsaWFudChrZXksIHRhcmdldCwgZmluYWxfcGVyc2lzdGVudC5yYXdfYnl0ZXMsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZmluYWxfcGVyc2lzdGVudC51aWQsIGZpbmFsX3BlcnNpc3RlbnQuZ2lkLCBmaW5hbF9wZXJzaXN0ZW50Lm1vZGUsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcGVyc2lzdGVudF91aWQsIHBlcnNpc3RlbnRfZ2lkLCBwZXJzaXN0ZW50X21vZGUpCiAgICApCgogICAgaWYgbm90IHJ1bnRpbWVfZmluYWxfb2sgb3Igbm90IHBlcnNpc3RlbnRfZmluYWxfb2s6CiAgICAgICAgaWYgZmluYWxfcnVudGltZV9lcnJvciBpcyBub3QgTm9uZToKICAgICAgICAgICAgcmVhc29uID0gZmluYWxfcnVudGltZV9lcnJvcgogICAgICAgIGVsaWYgbm90IHJ1bnRpbWVfZmluYWxfb2s6CiAgICAgICAgICAgIHJlYXNvbiA9ICJwb3N0Y2hlY2s6cnVudGltZS1ub25jb21wbGlhbnQiCiAgICAgICAgZWxpZiBmaW5hbF9wZXJzaXN0ZW50X2Vycm9yIGlzIG5vdCBOb25lOgogICAgICAgICAgICByZWFzb24gPSBmaW5hbF9wZXJzaXN0ZW50X2Vycm9yCiAgICAgICAgZWxzZToKICAgICAgICAgICAgcmVhc29uID0gInBvc3RjaGVjazpwZXJzaXN0ZW50LW5vbmNvbXBsaWFudCIKICAgICAgICBpZiBwZXJzaXN0ZW50X3N0YXRlIGlzIG5vdCBOb25lOgogICAgICAgICAgICBvdXRjb21lLCByZWFzb24gPSBfY29tcGVuc2F0ZV9hZnRlcl9mYWlsdXJlKHBlcnNpc3RlbnRfc3RhdGUsIGFjdGlvbnMsIHJlYXNvbikKICAgICAgICBlbHNlOgogICAgICAgICAgICBvdXRjb21lID0gT1VUQ09NRV9GQUlMRURfTk9UX0NPTU1JVFRFRAogICAgICAgIHJldHVybiBfcmVzdWx0KGNvbnRyb2xfaWQsIGtleSwgb3AsIGV4cGVjdGVkLCBUcnVlLCBvdXRjb21lLCByZWFzb24sCiAgICAgICAgICAgICAgICAgICAgICAgYnJhbmNoPWJyYW5jaCwgdGFyZ2V0X3ZhbHVlPXRhcmdldCwKICAgICAgICAgICAgICAgICAgICAgICBlZmZlY3RpdmVfZm9yZWlnbl92YWx1ZT1wcmVjZWRlbmNlLmVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlLAogICAgICAgICAgICAgICAgICAgICAgIHJ1bnRpbWVfYmVmb3JlPXJ1bnRpbWVfYmVmb3JlLAogICAgICAgICAgICAgICAgICAgICAgIHJ1bnRpbWVfcHJld3JpdGU9cnVudGltZV9wcmV3cml0ZSwKICAgICAgICAgICAgICAgICAgICAgICBydW50aW1lX2FmdGVyPWZpbmFsX3J1bnRpbWUsCiAgICAgICAgICAgICAgICAgICAgICAgcGVyc2lzdGVudF9iZWZvcmU9cGVyc2lzdGVudF9iZWZvcmUsCiAgICAgICAgICAgICAgICAgICAgICAgcGVyc2lzdGVudF9hZnRlcj1fc25hcHNob3RfZm9yX3Jlc3VsdChwZXJzaXN0ZW50X3RhcmdldCksCiAgICAgICAgICAgICAgICAgICAgICAgd3JpdHRlbl92YWx1ZT13cml0dGVuX3ZhbHVlLCBhY3Rpb25zPWFjdGlvbnMsIG11dGF0aW9uPW11dGF0aW9uLAogICAgICAgICAgICAgICAgICAgICAgIGNvbW1pdD1DT01NSVRfTk9UX0NPTU1JVFRFRCwgYXR0ZW1wdF9pZGVudGl0eT1hdHRlbXB0X2lkZW50aXR5LCBkcnlfcnVuPUZhbHNlKQoKICAgIGlmIG11dGF0aW9uOgogICAgICAgIG91dGNvbWUgPSBPVVRDT01FX0FQUExJRUQKICAgICAgICByZWFzb24gPSAiYXBwbGllZCIKICAgIGVsc2U6CiAgICAgICAgb3V0Y29tZSA9IE9VVENPTUVfQUxSRUFEWV9DT01QTElBTlQKICAgICAgICByZWFzb24gPSAiYWxyZWFkeS1jb21wbGlhbnQiCiAgICByZXR1cm4gX3Jlc3VsdChjb250cm9sX2lkLCBrZXksIG9wLCBleHBlY3RlZCwgVHJ1ZSwgb3V0Y29tZSwgcmVhc29uLAogICAgICAgICAgICAgICAgICAgYnJhbmNoPWJyYW5jaCwgdGFyZ2V0X3ZhbHVlPXRhcmdldCwKICAgICAgICAgICAgICAgICAgIGVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlPXByZWNlZGVuY2UuZWZmZWN0aXZlX2ZvcmVpZ25fdmFsdWUsCiAgICAgICAgICAgICAgICAgICBydW50aW1lX2JlZm9yZT1ydW50aW1lX2JlZm9yZSwKICAgICAgICAgICAgICAgICAgIHJ1bnRpbWVfcHJld3JpdGU9cnVudGltZV9wcmV3cml0ZSwKICAgICAgICAgICAgICAgICAgIHJ1bnRpbWVfYWZ0ZXI9ZmluYWxfcnVudGltZSwKICAgICAgICAgICAgICAgICAgIHBlcnNpc3RlbnRfYmVmb3JlPXBlcnNpc3RlbnRfYmVmb3JlLAogICAgICAgICAgICAgICAgICAgcGVyc2lzdGVudF9hZnRlcj1maW5hbF9wZXJzaXN0ZW50LAogICAgICAgICAgICAgICAgICAgd3JpdHRlbl92YWx1ZT13cml0dGVuX3ZhbHVlLCBhY3Rpb25zPWFjdGlvbnMsIG11dGF0aW9uPW11dGF0aW9uLAogICAgICAgICAgICAgICAgICAgY29tbWl0PUNPTU1JVF9DT01NSVRURUQsIGF0dGVtcHRfaWRlbnRpdHk9YXR0ZW1wdF9pZGVudGl0eSwgZHJ5X3J1bj1GYWxzZSkKCgpSRVBPUlRfU1RBVEVfRElSID0gIi92YXIvbG9nL3NlY3VyZWxpbnV4LXBvbGljeSIKUkVQT1JUX0FQUExZX0xPRyA9ICJhcHBseS5sb2ciClJFUE9SVF9ERUJVR19MT0cgPSAiZGVidWcubG9nIgpSRVBPUlRfSlNPTiA9ICJyZXBvcnQuanNvbiIKQ09WRVJBR0VfU1RBVEVNRU5UID0gKAogICAgIlNlY3VyZUxpbnV4LVBvbGljeSByZXBvcnRzIGNvdmVyYWdlIG9mIGEgc3Vic2V0IG9mIHNvdXJjZSByZXF1aXJlbWVudHM7ICIKICAgICJ0aGlzIHJlcG9ydCBpcyBub3QgZXZpZGVuY2Ugb2YgY29uZm9ybWl0eSB3aXRoIHRoZSBzb3VyY2UgZG9jdW1lbnQgYXMgYSB3aG9sZS4iCikKUlVOVElNRV9UT0NUT1VfTElNSVRBVElPTiA9ICgKICAgICJObyBhdG9taWMgY29tcGFyZS1hbmQtc2V0IGlzIGF2YWlsYWJsZSBmb3IgdGhlIHJ1bnRpbWUgd3JpdGU7IHRoZSBndWFyYW50ZWUgaXMgbGltaXRlZCAiCiAgICAidG8gdmFsdWVzIGFjdHVhbGx5IG9ic2VydmVkIGF0IHJ1bnRpbWVfYmVmb3JlL3J1bnRpbWVfcHJld3JpdGUgYW5kIHRoZSBmaW5hbCBwb3N0LWNoZWNrLiIKKQpQRVJTSVNURU5UX1RPQ1RPVV9MSU1JVEFUSU9OID0gKAogICAgIk5vIGF0b21pYyBjb21wYXJlLWFuZC1zd2FwIGlzIGF2YWlsYWJsZSBiZXR3ZWVuIHBlcnNpc3RlbnQgdGFyZ2V0IHJldmFsaWRhdGlvbiBhbmQgcmVuYW1lLiIKKQpDT01QRU5TQVRJT05fVE9DVE9VX0xJTUlUQVRJT04gPSAoCiAgICAiTm8gYXRvbWljIGNvbXBhcmUtYW5kLXN3YXAgaXMgYXZhaWxhYmxlIGJldHdlZW4gY29tcGVuc2F0aW9uIG93bmVyc2hpcCByZXZhbGlkYXRpb24gIgogICAgImFuZCB0aGUgZGVzdHJ1Y3RpdmUgcmVuYW1lL3VubGluay4iCikKCgpAZGF0YWNsYXNzKGZyb3plbj1UcnVlKQpjbGFzcyBCYXRjaEV4ZWN1dGlvblJlc3VsdDoKICAgIGNvbnRyb2xzOiB0dXBsZQogICAgcmNfemVybzogYm9vbAogICAgcmVwb3J0X3BhdGg6IHN0cgogICAgYXBwbHlfbG9nX3BhdGg6IHN0cgogICAgZGVidWdfbG9nX3BhdGg6IHN0cgogICAgc3RhcnRlZF9hdDogc3RyCiAgICBmaW5pc2hlZF9hdDogc3RyCgoKZGVmIF90aW1lc3RhbXBfbm93KCk6CiAgICByZXR1cm4gX2RhdGV0aW1lLmRhdGV0aW1lLm5vdygpLmFzdGltZXpvbmUoKS5zdHJmdGltZSgiJVktJW0tJWQgJUg6JU06JVMgJXoiKQoKCmRlZiBfaWRlbnRpdHlfcmVwb3J0KGlkZW50aXR5KToKICAgIGlmIGlkZW50aXR5IGlzIE5vbmU6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIGlmIG5vdCBpc2luc3RhbmNlKGlkZW50aXR5LCBPYmplY3RJZGVudGl0eSk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiaW52YWxpZCBpZGVudGl0eSBmb3IgcmVwb3J0IikKICAgIHJldHVybiB7CiAgICAgICAgImV4aXN0cyI6IGlkZW50aXR5LmV4aXN0cywKICAgICAgICAic3RfZGV2IjogaWRlbnRpdHkuc3RfZGV2LAogICAgICAgICJzdF9pbm8iOiBpZGVudGl0eS5zdF9pbm8sCiAgICAgICAgImZpbGVfdHlwZSI6IGlkZW50aXR5LmZpbGVfdHlwZSwKICAgICAgICAic3RfbmxpbmsiOiBpZGVudGl0eS5zdF9ubGluaywKICAgICAgICAidWlkIjogaWRlbnRpdHkudWlkLAogICAgICAgICJnaWQiOiBpZGVudGl0eS5naWQsCiAgICAgICAgIm1vZGUiOiBpZGVudGl0eS5tb2RlLAogICAgICAgICJieXRlc19iNjQiOiAoCiAgICAgICAgICAgIE5vbmUgaWYgaWRlbnRpdHkucmF3X2J5dGVzIGlzIE5vbmUKICAgICAgICAgICAgZWxzZSBiYXNlNjQuYjY0ZW5jb2RlKGlkZW50aXR5LnJhd19ieXRlcykuZGVjb2RlKCJhc2NpaSIpCiAgICAgICAgKSwKICAgIH0KCgpkZWYgb3V0Y29tZV9yY19jb250cmlidXRpb24ob3V0Y29tZSwgZHJ5X3J1bj1GYWxzZSk6CiAgICAiIiJSZXR1cm4gdGhlIHIxMCBzZW1hbnRpYyBSQyBjb250cmlidXRpb24gd2l0aG91dCBjaG9vc2luZyBhIENMSSBub256ZXJvIGludGVnZXIuIiIiCiAgICBpZiBub3QgaXNpbnN0YW5jZShvdXRjb21lLCBzdHIpOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoIm91dGNvbWUgbXVzdCBiZSB0ZXh0IikKICAgIGlmIG5vdCBpc2luc3RhbmNlKGRyeV9ydW4sIGJvb2wpOgogICAgICAgIHJhaXNlIENvbnRyYWN0RXJyb3IoImRyeV9ydW4gbXVzdCBiZSBib29sZWFuIikKICAgIGlmIG91dGNvbWUgaW4gKE9VVENPTUVfQVBQTElFRCwgT1VUQ09NRV9BTFJFQURZX0NPTVBMSUFOVCwgT1VUQ09NRV9OT1RfRUxJR0lCTEUpOgogICAgICAgIHJldHVybiAiMCIKICAgIGlmIGRyeV9ydW4gYW5kIG91dGNvbWUgPT0gT1VUQ09NRV9EUllfUlVOX1dPVUxEX0FQUExZOgogICAgICAgIHJldHVybiAiMCIKICAgIHJldHVybiAibm9uemVybyIKCgpkZWYgX3RhcmdldF92YWx1ZV9ydWxlKHJlc3VsdCk6CiAgICBpZiByZXN1bHQudGFyZ2V0X3ZhbHVlIGlzIE5vbmU6CiAgICAgICAgcmV0dXJuIE5vbmUKICAgIHJldHVybiAiZXEtZXhhY3QiIGlmIHJlc3VsdC5vcCA9PSAiZXEiIGVsc2UgImdlLW1heC1wcmVzZXJ2ZSIKCgpkZWYgX29wZXJhdG9yX2RlY2lzaW9uX2Zvcl9yZXN1bHQocmVzdWx0KToKICAgIGlmIHJlc3VsdC5vdXRjb21lICE9IE9VVENPTUVfQUJPUlRfQ09ORkxJQ1Qgb3IgcmVzdWx0Lm11dGF0aW9uX3BlcmZvcm1lZDoKICAgICAgICByZXR1cm4gTm9uZQogICAgcHJlZml4ID0gInJ1bnRpbWUtd3JpdGVyOiIKICAgIGlmIG5vdCByZXN1bHQucmVhc29uLnN0YXJ0c3dpdGgocHJlZml4KToKICAgICAgICByZXR1cm4gTm9uZQogICAgcnVsZV9pZCA9IHJlc3VsdC5yZWFzb25bbGVuKHByZWZpeCk6XS5zcGxpdCgiOiIsIDEpWzBdCiAgICBzZXJ2aWNlID0gU0VSVklDRV9NQU5BR0VEX1JVTlRJTUVfV1JJVEVSUy5nZXQocnVsZV9pZCkKICAgIGlmIHNlcnZpY2UgaXMgTm9uZSBvciByZXN1bHQucnVudGltZV9iZWZvcmUgaXMgTm9uZToKICAgICAgICByZXR1cm4gTm9uZQogICAgcmV0dXJuIHsKICAgICAgICAiY2xhc3MiOiAiU0VSVklDRV9NQU5BR0VEX1BBUkFNRVRFUiIsCiAgICAgICAgInJlcXVpcmVkIjogVHJ1ZSwKICAgICAgICAic2VydmljZSI6IHNlcnZpY2UsCiAgICAgICAgInBhcmFtZXRlciI6IHJlc3VsdC5rZXksCiAgICAgICAgImN1cnJlbnRfdmFsdWUiOiByZXN1bHQucnVudGltZV9iZWZvcmUsCiAgICB9CgoKZGVmIGNvbnRyb2xfcmVzdWx0X3RvX3JlcG9ydChyZXN1bHQsIHN0YXJ0ZWRfYXQsIGZpbmlzaGVkX2F0KToKICAgIGlmIG5vdCBpc2luc3RhbmNlKHJlc3VsdCwgQ29udHJvbEV4ZWN1dGlvblJlc3VsdCk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiaW52YWxpZCBjb250cm9sIHJlc3VsdCIpCiAgICByZWNvcmQgPSB7CiAgICAgICAgImNvbnRyb2xfaWQiOiByZXN1bHQuY29udHJvbF9pZCwKICAgICAgICAia2V5IjogcmVzdWx0LmtleSwKICAgICAgICAib3AiOiByZXN1bHQub3AsCiAgICAgICAgImV4cGVjdGVkIjogcmVzdWx0LmV4cGVjdGVkLAogICAgICAgICJydW50aW1lX2JlZm9yZSI6IHJlc3VsdC5ydW50aW1lX2JlZm9yZSwKICAgICAgICAicGVyc2lzdGVudF9iZWZvcmUiOiBfaWRlbnRpdHlfcmVwb3J0KHJlc3VsdC5wZXJzaXN0ZW50X2JlZm9yZSksCiAgICAgICAgImVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlIjogcmVzdWx0LmVmZmVjdGl2ZV9mb3JlaWduX3ZhbHVlLAogICAgICAgICJ0YXJnZXRfdmFsdWUiOiByZXN1bHQudGFyZ2V0X3ZhbHVlLAogICAgICAgICJ0YXJnZXRfdmFsdWVfcnVsZSI6IF90YXJnZXRfdmFsdWVfcnVsZShyZXN1bHQpLAogICAgICAgICJ3cml0dGVuX3ZhbHVlIjogcmVzdWx0LndyaXR0ZW5fdmFsdWUsCiAgICAgICAgInJ1bnRpbWVfYWZ0ZXIiOiByZXN1bHQucnVudGltZV9hZnRlciwKICAgICAgICAicGVyc2lzdGVudF9hZnRlciI6IF9pZGVudGl0eV9yZXBvcnQocmVzdWx0LnBlcnNpc3RlbnRfYWZ0ZXIpLAogICAgICAgICJwZXJzaXN0ZW50X3BhdGgiOiBwZXJzaXN0ZW50X3BhdGgocmVzdWx0LmtleSksCiAgICAgICAgIm91dGNvbWUiOiByZXN1bHQub3V0Y29tZSwKICAgICAgICAicmVhc29uIjogcmVzdWx0LnJlYXNvbiwKICAgICAgICAic3RhcnRlZF9hdCI6IHN0YXJ0ZWRfYXQsCiAgICAgICAgImZpbmlzaGVkX2F0IjogZmluaXNoZWRfYXQsCiAgICAgICAgInJ1bnRpbWVfcHJld3JpdGUiOiByZXN1bHQucnVudGltZV9wcmV3cml0ZSwKICAgICAgICAiZHJ5X3J1biI6IHJlc3VsdC5kcnlfcnVuLAogICAgICAgICJhY3Rpb25zX2F0dGVtcHRlZCI6IGxpc3QocmVzdWx0LmFjdGlvbnNfYXR0ZW1wdGVkKSwKICAgICAgICAic3RlcF9yYyI6IG91dGNvbWVfcmNfY29udHJpYnV0aW9uKHJlc3VsdC5vdXRjb21lLCByZXN1bHQuZHJ5X3J1biksCiAgICAgICAgIm11dGF0aW9uX3BlcmZvcm1lZCI6IHJlc3VsdC5tdXRhdGlvbl9wZXJmb3JtZWQsCiAgICAgICAgInRyYW5zYWN0aW9uX2NvbW1pdCI6IHJlc3VsdC50cmFuc2FjdGlvbl9jb21taXQsCiAgICAgICAgImVsaWdpYmxlIjogcmVzdWx0LmVsaWdpYmxlLAogICAgICAgICJhdHRlbXB0X3dyaXR0ZW5faWRlbnRpdHkiOiBfaWRlbnRpdHlfcmVwb3J0KHJlc3VsdC5hdHRlbXB0X3dyaXR0ZW5faWRlbnRpdHkpLAogICAgICAgICJicmFuY2giOiByZXN1bHQuYnJhbmNoLAogICAgfQogICAgb3BlcmF0b3JfZGVjaXNpb24gPSBfb3BlcmF0b3JfZGVjaXNpb25fZm9yX3Jlc3VsdChyZXN1bHQpCiAgICBpZiBvcGVyYXRvcl9kZWNpc2lvbiBpcyBub3QgTm9uZToKICAgICAgICByZWNvcmRbIm9wZXJhdG9yX2RlY2lzaW9uIl0gPSBvcGVyYXRvcl9kZWNpc2lvbgogICAgcmV0dXJuIHJlY29yZAoKCmRlZiBfb3Blbl9yZXBvcnRpbmdfbG9nKHBhdGgsIGFwcGVuZD1GYWxzZSk6CiAgICBwYXJlbnQgPSBvcy5wYXRoLmRpcm5hbWUocGF0aCkKICAgIG5hbWUgPSBvcy5wYXRoLmJhc2VuYW1lKHBhdGgpCiAgICBkaXJfZmQgPSBfb3Blbl9kaXJfbm9mb2xsb3cocGFyZW50KQogICAgZmxhZ3MgPSBvcy5PX1dST05MWSB8IG9zLk9fQ1JFQVQgfCBnZXRhdHRyKG9zLCAiT19DTE9FWEVDIiwgMCkgfCBnZXRhdHRyKG9zLCAiT19OT0ZPTExPVyIsIDApCiAgICBpZiBhcHBlbmQ6CiAgICAgICAgZmxhZ3MgfD0gb3MuT19BUFBFTkQKICAgIHRyeToKICAgICAgICBmZCA9IG9zLm9wZW4obmFtZSwgZmxhZ3MsIDBvNjAwLCBkaXJfZmQ9ZGlyX2ZkKQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICBvcy5jbG9zZShkaXJfZmQpCiAgICAgICAgcmFpc2UKICAgIHRyeToKICAgICAgICBzdCA9IG9zLmZzdGF0KGZkKQogICAgICAgIGlmIG5vdCBzdGF0LlNfSVNSRUcoc3Quc3RfbW9kZSkgb3Igc3Quc3RfbmxpbmsgIT0gMToKICAgICAgICAgICAgcmFpc2UgUHJlY29uZGl0aW9uRXJyb3IoInJlcG9ydGluZzpmb3JiaWRkZW4tbG9nLW9iamVjdCIsIHBhdGgpCiAgICAgICAgcmV0dXJuIGRpcl9mZCwgZmQKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgb3MuY2xvc2UoZmQpCiAgICAgICAgb3MuY2xvc2UoZGlyX2ZkKQogICAgICAgIHJhaXNlCgoKZGVmIF9lbnN1cmVfbG9nX2ZpbGUocGF0aCk6CiAgICBkaXJfZmQsIGZkID0gX29wZW5fcmVwb3J0aW5nX2xvZyhwYXRoLCBhcHBlbmQ9RmFsc2UpCiAgICB0cnk6CiAgICAgICAgb3MuZnN5bmMoZmQpCiAgICBmaW5hbGx5OgogICAgICAgIG9zLmNsb3NlKGZkKQogICAgICAgIG9zLmNsb3NlKGRpcl9mZCkKCgpkZWYgX2FwcGVuZF9sb2cocGF0aCwgdGltZXN0YW1wLCBtZXNzYWdlKToKICAgIGxpbmUgPSBmIlt7dGltZXN0YW1wfV0ge21lc3NhZ2V9XG4iLmVuY29kZSgidXRmLTgiLCAiYmFja3NsYXNocmVwbGFjZSIpCiAgICBkaXJfZmQsIGZkID0gX29wZW5fcmVwb3J0aW5nX2xvZyhwYXRoLCBhcHBlbmQ9VHJ1ZSkKICAgIHRyeToKICAgICAgICBfd3JpdGVfYWxsKGZkLCBsaW5lKQogICAgICAgIG9zLmZzeW5jKGZkKQogICAgZmluYWxseToKICAgICAgICBvcy5jbG9zZShmZCkKICAgICAgICBvcy5jbG9zZShkaXJfZmQpCgoKZGVmIF9hdG9taWNfd3JpdGVfcmVwb3J0KHBhdGgsIHBheWxvYWQpOgogICAgcGFyZW50ID0gb3MucGF0aC5kaXJuYW1lKHBhdGgpCiAgICBuYW1lID0gb3MucGF0aC5iYXNlbmFtZShwYXRoKQogICAgZGlyX2ZkID0gX29wZW5fZGlyX25vZm9sbG93KHBhcmVudCkKICAgIHRlbXBfbmFtZSA9IGYiLntuYW1lfS50bXAue29zLmdldHBpZCgpfS57c2VjcmV0cy50b2tlbl9oZXgoOCl9IgogICAgZmQgPSBOb25lCiAgICB0cnk6CiAgICAgICAgZmxhZ3MgPSBvcy5PX0NSRUFUIHwgb3MuT19FWENMIHwgb3MuT19XUk9OTFkgfCBnZXRhdHRyKG9zLCAiT19DTE9FWEVDIiwgMCkgfCBnZXRhdHRyKG9zLCAiT19OT0ZPTExPVyIsIDApCiAgICAgICAgZmQgPSBvcy5vcGVuKHRlbXBfbmFtZSwgZmxhZ3MsIDBvNjAwLCBkaXJfZmQ9ZGlyX2ZkKQogICAgICAgIGRhdGEgPSAoanNvbi5kdW1wcyhwYXlsb2FkLCBlbnN1cmVfYXNjaWk9RmFsc2UsIHNvcnRfa2V5cz1UcnVlLCBpbmRlbnQ9MikgKyAiXG4iKS5lbmNvZGUoInV0Zi04IikKICAgICAgICBfd3JpdGVfYWxsKGZkLCBkYXRhKQogICAgICAgIG9zLmZzeW5jKGZkKQogICAgICAgIG9zLmNsb3NlKGZkKQogICAgICAgIGZkID0gTm9uZQogICAgICAgIG9zLnJlcGxhY2UodGVtcF9uYW1lLCBuYW1lLCBzcmNfZGlyX2ZkPWRpcl9mZCwgZHN0X2Rpcl9mZD1kaXJfZmQpCiAgICAgICAgdGVtcF9uYW1lID0gTm9uZQogICAgICAgIF9mc3luY19kaXIoZGlyX2ZkKQogICAgZmluYWxseToKICAgICAgICBpZiBmZCBpcyBub3QgTm9uZToKICAgICAgICAgICAgb3MuY2xvc2UoZmQpCiAgICAgICAgaWYgdGVtcF9uYW1lIGlzIG5vdCBOb25lOgogICAgICAgICAgICBfdW5saW5rX2lmX2V4aXN0cyhkaXJfZmQsIHRlbXBfbmFtZSkKICAgICAgICBvcy5jbG9zZShkaXJfZmQpCgoKZGVmIF92YWxpZGF0ZV9iYXRjaF9jb250cm9sKGNvbnRyb2wpOgogICAgaWYgbm90IGlzaW5zdGFuY2UoY29udHJvbCwgZGljdCk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiYmF0Y2ggY29udHJvbCBtdXN0IGJlIG1hcHBpbmciKQogICAgcmVxdWlyZWQgPSAoImNvbnRyb2xfaWQiLCAia2V5IiwgIm9wIiwgImV4cGVjdGVkIiwgImFwcGx5X3N1cHBvcnRlZCIpCiAgICBtaXNzaW5nID0gW25hbWUgZm9yIG5hbWUgaW4gcmVxdWlyZWQgaWYgbmFtZSBub3QgaW4gY29udHJvbF0KICAgIGlmIG1pc3Npbmc6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiYmF0Y2ggY29udHJvbCBtaXNzaW5nOiIgKyAiLCIuam9pbihtaXNzaW5nKSkKICAgIHZhbGlkYXRlX2NvbnRyb2xfaW5wdXQoCiAgICAgICAgY29udHJvbFsiY29udHJvbF9pZCJdLCBjb250cm9sWyJrZXkiXSwgY29udHJvbFsib3AiXSwKICAgICAgICBjb250cm9sWyJleHBlY3RlZCJdLCBjb250cm9sWyJhcHBseV9zdXBwb3J0ZWQiXSwKICAgICkKICAgIHJldHVybiB7bmFtZTogY29udHJvbFtuYW1lXSBmb3IgbmFtZSBpbiByZXF1aXJlZH0KCgpkZWYgZXhlY3V0ZV9iYXRjaCgKICAgIGNvbnRyb2xzLAogICAgKiwKICAgIHN0YXRlX2Rpcj1SRVBPUlRfU1RBVEVfRElSLAogICAgZHJ5X3J1bj1GYWxzZSwKICAgIGV4ZWN1dGVfb25lPU5vbmUsCiAgICBjb21tb25fZXhlY3V0ZV9rd2FyZ3M9Tm9uZSwKICAgIG5vd19mbj1Ob25lLAopOgogICAgIiIiRXhlY3V0ZSBldmVyeSBjb250cm9sIGluZGVwZW5kZW50bHkgYW5kIG1haW50YWluIEQxMi9EMTMgcmVwb3J0aW5nIGFydGlmYWN0cy4KCiAgICBUaGUgZnVuY3Rpb24gZGVsaWJlcmF0ZWx5IHJldHVybnMgcmNfemVybyByYXRoZXIgdGhhbiBhIG51bWVyaWMgcHJvY2VzcyBleGl0IGNvZGUuCiAgICByMTAgZml4ZXMgb25seSB6ZXJvIHZzIG5vbnplcm8gY29udHJpYnV0aW9uOyB0aGUgY29uY3JldGUgQ0xJIG5vbnplcm8gaW50ZWdlciBpcwogICAgYXNzaWduZWQgbGF0ZXIgYnkgdGhlIENMSSBjb250cmFjdC4KICAgICIiIgogICAgaWYgaXNpbnN0YW5jZShjb250cm9scywgKHN0ciwgYnl0ZXMpKSBvciBub3QgaGFzYXR0cihjb250cm9scywgIl9faXRlcl9fIik6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiY29udHJvbHMgbXVzdCBiZSBpdGVyYWJsZSIpCiAgICBpZiBub3QgaXNpbnN0YW5jZShzdGF0ZV9kaXIsIHN0cikgb3Igbm90IHN0YXRlX2Rpci5zdGFydHN3aXRoKCIvIik6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigic3RhdGVfZGlyIG11c3QgYmUgYWJzb2x1dGUiKQogICAgaWYgbm90IGlzaW5zdGFuY2UoZHJ5X3J1biwgYm9vbCk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiZHJ5X3J1biBtdXN0IGJlIGJvb2xlYW4iKQogICAgZXhlY3V0ZV9vbmUgPSBleGVjdXRlX29uZSBvciBleGVjdXRlX2NvbnRyb2wKICAgIGlmIG5vdCBjYWxsYWJsZShleGVjdXRlX29uZSk6CiAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiZXhlY3V0ZV9vbmUgbXVzdCBiZSBjYWxsYWJsZSIpCiAgICBjb21tb25fZXhlY3V0ZV9rd2FyZ3MgPSB7fSBpZiBjb21tb25fZXhlY3V0ZV9rd2FyZ3MgaXMgTm9uZSBlbHNlIGRpY3QoY29tbW9uX2V4ZWN1dGVfa3dhcmdzKQogICAgbm93X2ZuID0gbm93X2ZuIG9yIF90aW1lc3RhbXBfbm93CiAgICBpZiBub3QgY2FsbGFibGUobm93X2ZuKToKICAgICAgICByYWlzZSBDb250cmFjdEVycm9yKCJub3dfZm4gbXVzdCBiZSBjYWxsYWJsZSIpCgogICAgb3MubWFrZWRpcnMoc3RhdGVfZGlyLCBtb2RlPTBvNzAwLCBleGlzdF9vaz1UcnVlKQogICAgIyBSZWplY3QgYSBzeW1saW5rL25vbi1kaXJlY3Rvcnkgc3RhdGUgcGF0aCBiZWZvcmUgYW55IHJlcG9ydGluZyB3cml0ZS4KICAgIF9zdGF0ZV9mZCA9IF9vcGVuX2Rpcl9ub2ZvbGxvdyhzdGF0ZV9kaXIpCiAgICBvcy5jbG9zZShfc3RhdGVfZmQpCiAgICBhcHBseV9sb2dfcGF0aCA9IG9zLnBhdGguam9pbihzdGF0ZV9kaXIsIFJFUE9SVF9BUFBMWV9MT0cpCiAgICBkZWJ1Z19sb2dfcGF0aCA9IG9zLnBhdGguam9pbihzdGF0ZV9kaXIsIFJFUE9SVF9ERUJVR19MT0cpCiAgICByZXBvcnRfcGF0aCA9IG9zLnBhdGguam9pbihzdGF0ZV9kaXIsIFJFUE9SVF9KU09OKQogICAgc3RhcnRlZF9hdCA9IG5vd19mbigpCiAgICByZWNvcmRzID0gW10KICAgIHBheWxvYWQgPSB7CiAgICAgICAgIm1lY2hhbmlzbV9pZCI6IE1FQ0hBTklTTV9JRCwKICAgICAgICAiYWRhcHRlcl9pZCI6IEFEQVBURVJfSUQsCiAgICAgICAgImRyeV9ydW4iOiBkcnlfcnVuLAogICAgICAgICJzdGFydGVkX2F0Ijogc3RhcnRlZF9hdCwKICAgICAgICAiZmluaXNoZWRfYXQiOiBOb25lLAogICAgICAgICJjb21wbGV0ZSI6IEZhbHNlLAogICAgICAgICJyY196ZXJvIjogTm9uZSwKICAgICAgICAicnVuX2Vycm9yIjogTm9uZSwKICAgICAgICAiY292ZXJhZ2Vfc3RhdGVtZW50IjogQ09WRVJBR0VfU1RBVEVNRU5ULAogICAgICAgICJjb250cm9scyI6IHJlY29yZHMsCiAgICB9CiAgICAjIEQxMjogZXN0YWJsaXNoIHJlcG9ydC5qc29uIGJlZm9yZSBvcGVyYXRpb25zIG9uIHNpYmxpbmcgcmVwb3J0aW5nIGFydGlmYWN0cywKICAgICMgc28gYSByZWZ1c2FsIG9uIGFwcGx5LmxvZy9kZWJ1Zy5sb2cgY2FuIHN0aWxsIGJlIHJlcG9ydGVkLgogICAgX2F0b21pY193cml0ZV9yZXBvcnQocmVwb3J0X3BhdGgsIHBheWxvYWQpCiAgICB0cnk6CiAgICAgICAgX2Vuc3VyZV9sb2dfZmlsZShhcHBseV9sb2dfcGF0aCkKICAgICAgICBfZW5zdXJlX2xvZ19maWxlKGRlYnVnX2xvZ19wYXRoKQogICAgICAgIF9hcHBlbmRfbG9nKGFwcGx5X2xvZ19wYXRoLCBzdGFydGVkX2F0LCBmImJhdGNoIHN0YXJ0IGRyeV9ydW49e3N0cihkcnlfcnVuKS5sb3dlcigpfSIpCiAgICBleGNlcHQgQmFzZUV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgZmluaXNoZWRfYXQgPSBub3dfZm4oKQogICAgICAgIHBheWxvYWRbInJ1bl9lcnJvciJdID0gewogICAgICAgICAgICAidHlwZSI6IHR5cGUoZXhjKS5fX25hbWVfXywKICAgICAgICAgICAgIm1lc3NhZ2UiOiBzdHIoZXhjKSwKICAgICAgICAgICAgInBoYXNlIjogInJlcG9ydGluZy1ib290c3RyYXAiLAogICAgICAgIH0KICAgICAgICBwYXlsb2FkWyJmaW5pc2hlZF9hdCJdID0gZmluaXNoZWRfYXQKICAgICAgICBwYXlsb2FkWyJjb21wbGV0ZSJdID0gRmFsc2UKICAgICAgICBwYXlsb2FkWyJyY196ZXJvIl0gPSBGYWxzZQogICAgICAgIHRyeToKICAgICAgICAgICAgX2F0b21pY193cml0ZV9yZXBvcnQocmVwb3J0X3BhdGgsIHBheWxvYWQpCiAgICAgICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICAgICAgcGFzcwogICAgICAgIHJhaXNlCgogICAgdHJ5OgogICAgICAgIHJhd19jb250cm9scyA9IGxpc3QoY29udHJvbHMpCiAgICAgICAgZm9yIHJhd19jb250cm9sIGluIHJhd19jb250cm9sczoKICAgICAgICAgICAgY29udHJvbCA9IE5vbmUKICAgICAgICAgICAgY19zdGFydGVkID0gbm93X2ZuKCkKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgY29udHJvbCA9IF92YWxpZGF0ZV9iYXRjaF9jb250cm9sKHJhd19jb250cm9sKQogICAgICAgICAgICAgICAgX2FwcGVuZF9sb2coYXBwbHlfbG9nX3BhdGgsIGNfc3RhcnRlZCwgZiJjb250cm9sIHN0YXJ0IHtjb250cm9sWydjb250cm9sX2lkJ119IikKICAgICAgICAgICAgICAgIHJlc3VsdCA9IGV4ZWN1dGVfb25lKAogICAgICAgICAgICAgICAgICAgIGNvbnRyb2xbImNvbnRyb2xfaWQiXSwgY29udHJvbFsia2V5Il0sIGNvbnRyb2xbIm9wIl0sCiAgICAgICAgICAgICAgICAgICAgY29udHJvbFsiZXhwZWN0ZWQiXSwgY29udHJvbFsiYXBwbHlfc3VwcG9ydGVkIl0sCiAgICAgICAgICAgICAgICAgICAgZHJ5X3J1bj1kcnlfcnVuLCAqKmNvbW1vbl9leGVjdXRlX2t3YXJncywKICAgICAgICAgICAgICAgICkKICAgICAgICAgICAgICAgIGlmIG5vdCBpc2luc3RhbmNlKHJlc3VsdCwgQ29udHJvbEV4ZWN1dGlvblJlc3VsdCk6CiAgICAgICAgICAgICAgICAgICAgcmFpc2UgQ29udHJhY3RFcnJvcigiZXhlY3V0ZV9vbmUgcmV0dXJuZWQgaW52YWxpZCByZXN1bHQiKQogICAgICAgICAgICBleGNlcHQgQmFzZUV4Y2VwdGlvbiBhcyBleGM6CiAgICAgICAgICAgICAgICBjX2ZpbmlzaGVkID0gbm93X2ZuKCkKICAgICAgICAgICAgICAgIF9hcHBlbmRfbG9nKGRlYnVnX2xvZ19wYXRoLCBjX2ZpbmlzaGVkLCB0cmFjZWJhY2suZm9ybWF0X2V4YygpLnJzdHJpcCgpKQogICAgICAgICAgICAgICAgcGF5bG9hZFsicnVuX2Vycm9yIl0gPSB7CiAgICAgICAgICAgICAgICAgICAgImNvbnRyb2xfaWQiOiBOb25lIGlmIGNvbnRyb2wgaXMgTm9uZSBlbHNlIGNvbnRyb2xbImNvbnRyb2xfaWQiXSwKICAgICAgICAgICAgICAgICAgICAidHlwZSI6IHR5cGUoZXhjKS5fX25hbWVfXywKICAgICAgICAgICAgICAgICAgICAibWVzc2FnZSI6IHN0cihleGMpLAogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgcGF5bG9hZFsiZmluaXNoZWRfYXQiXSA9IGNfZmluaXNoZWQKICAgICAgICAgICAgICAgIHBheWxvYWRbImNvbXBsZXRlIl0gPSBGYWxzZQogICAgICAgICAgICAgICAgcGF5bG9hZFsicmNfemVybyJdID0gRmFsc2UKICAgICAgICAgICAgICAgIF9hdG9taWNfd3JpdGVfcmVwb3J0KHJlcG9ydF9wYXRoLCBwYXlsb2FkKQogICAgICAgICAgICAgICAgX2FwcGVuZF9sb2coCiAgICAgICAgICAgICAgICAgICAgYXBwbHlfbG9nX3BhdGgsIGNfZmluaXNoZWQsCiAgICAgICAgICAgICAgICAgICAgImNvbnRyb2wgY3Jhc2ggPGludmFsaWQ+IiBpZiBjb250cm9sIGlzIE5vbmUgZWxzZSBmImNvbnRyb2wgY3Jhc2gge2NvbnRyb2xbJ2NvbnRyb2xfaWQnXX0iLAogICAgICAgICAgICAgICAgKQogICAgICAgICAgICAgICAgcmFpc2UKCiAgICAgICAgICAgIGNfZmluaXNoZWQgPSBub3dfZm4oKQogICAgICAgICAgICByZWNvcmQgPSBjb250cm9sX3Jlc3VsdF90b19yZXBvcnQocmVzdWx0LCBjX3N0YXJ0ZWQsIGNfZmluaXNoZWQpCiAgICAgICAgICAgIHJlY29yZHMuYXBwZW5kKHJlY29yZCkKICAgICAgICAgICAgX2F0b21pY193cml0ZV9yZXBvcnQocmVwb3J0X3BhdGgsIHBheWxvYWQpCiAgICAgICAgICAgIF9hcHBlbmRfbG9nKAogICAgICAgICAgICAgICAgYXBwbHlfbG9nX3BhdGgsIGNfZmluaXNoZWQsCiAgICAgICAgICAgICAgICBmImNvbnRyb2wgZmluaXNoIHtjb250cm9sWydjb250cm9sX2lkJ119IG91dGNvbWU9e3Jlc3VsdC5vdXRjb21lfSBzdGVwX3JjPXtyZWNvcmRbJ3N0ZXBfcmMnXX0iLAogICAgICAgICAgICApCgogICAgICAgIGZpbmlzaGVkX2F0ID0gbm93X2ZuKCkKICAgICAgICByY196ZXJvID0gYWxsKHJlY29yZFsic3RlcF9yYyJdID09ICIwIiBmb3IgcmVjb3JkIGluIHJlY29yZHMpCiAgICAgICAgcGF5bG9hZFsiZmluaXNoZWRfYXQiXSA9IGZpbmlzaGVkX2F0CiAgICAgICAgcGF5bG9hZFsiY29tcGxldGUiXSA9IFRydWUKICAgICAgICBwYXlsb2FkWyJyY196ZXJvIl0gPSByY196ZXJvCiAgICAgICAgX2F0b21pY193cml0ZV9yZXBvcnQocmVwb3J0X3BhdGgsIHBheWxvYWQpCiAgICAgICAgX2FwcGVuZF9sb2coYXBwbHlfbG9nX3BhdGgsIGZpbmlzaGVkX2F0LCBmImJhdGNoIGZpbmlzaCByY196ZXJvPXtzdHIocmNfemVybykubG93ZXIoKX0iKQogICAgICAgIHJldHVybiBCYXRjaEV4ZWN1dGlvblJlc3VsdCgKICAgICAgICAgICAgdHVwbGUocmVjb3JkcyksIHJjX3plcm8sIHJlcG9ydF9wYXRoLCBhcHBseV9sb2dfcGF0aCwgZGVidWdfbG9nX3BhdGgsCiAgICAgICAgICAgIHN0YXJ0ZWRfYXQsIGZpbmlzaGVkX2F0LAogICAgICAgICkKICAgIGV4Y2VwdCBCYXNlRXhjZXB0aW9uOgogICAgICAgICMgSWYgYSBmYWlsdXJlIGhhcHBlbmVkIG91dHNpZGUgdGhlIHBlci1jb250cm9sIHdyYXBwZXIsIG1ha2Ugb25lIGZpbmFsCiAgICAgICAgIyBiZXN0LWVmZm9ydCByZXBvcnQgd3JpdGUgd2l0aG91dCBoaWRpbmcgdGhlIG9yaWdpbmFsIGV4Y2VwdGlvbi4KICAgICAgICBpZiBwYXlsb2FkWyJydW5fZXJyb3IiXSBpcyBOb25lOgogICAgICAgICAgICBmaW5pc2hlZF9hdCA9IG5vd19mbigpCiAgICAgICAgICAgIHBheWxvYWRbInJ1bl9lcnJvciJdID0geyJ0eXBlIjogImJhdGNoX2V4Y2VwdGlvbiIsICJtZXNzYWdlIjogImJhdGNoIGFib3J0ZWQifQogICAgICAgICAgICBwYXlsb2FkWyJmaW5pc2hlZF9hdCJdID0gZmluaXNoZWRfYXQKICAgICAgICAgICAgcGF5bG9hZFsiY29tcGxldGUiXSA9IEZhbHNlCiAgICAgICAgICAgIHBheWxvYWRbInJjX3plcm8iXSA9IEZhbHNlCiAgICAgICAgICAgIHRyeToKICAgICAgICAgICAgICAgIF9hdG9taWNfd3JpdGVfcmVwb3J0KHJlcG9ydF9wYXRoLCBwYXlsb2FkKQogICAgICAgICAgICAgICAgX2FwcGVuZF9sb2coZGVidWdfbG9nX3BhdGgsIGZpbmlzaGVkX2F0LCB0cmFjZWJhY2suZm9ybWF0X2V4YygpLnJzdHJpcCgpKQogICAgICAgICAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgICAgICAgICAgcGFzcwogICAgICAgIHJhaXNlCgoKZGVmIF9zZWxmdGVzdCgpOgogICAgdmFsaWRhdGVfY29udHJvbF9pbnB1dCgiQ1RSTC0xIiwgInZtLm1tYXBfbWluX2FkZHIiLCAiZ2UiLCA0MDk2LCBUcnVlKQogICAgYXNzZXJ0IHBhcnNlX2ludGVnZXJfYnl0ZXMoYiIgLTAwMDMgXHJcbiIpID09IC0zCiAgICBhc3NlcnQgY29tcHV0ZV90YXJnZXRfdmFsdWUoImdlIiwgNDA5NiwgODE5MiwgMTYzODQsIDMyNzY4KSA9PSAzMjc2OAogICAgYXNzZXJ0IGNhbm9uaWNhbF9wZXJzaXN0ZW50X2J5dGVzKCJ2bS5tbWFwX21pbl9hZGRyIiwgNDA5NikuZW5kc3dpdGgoYiJ2bS5tbWFwX21pbl9hZGRyID0gNDA5NlxuIikKICAgIGFzc2VydCBzZWxlY3RfYnJhbmNoKFRydWUsIEZhbHNlKSA9PSBCUkFOQ0hfUEVSU0lTVEVOVF9PTkxZCiAgICBwcmludCgiUFVSRV9BREFQVEVSX0NPUkVfU0VMRlRFU1Q9UEFTUyIpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIF9zZWxmdGVzdCgpCg=="}}')
COMMON = {
    "control_id", "outcome", "reason", "actions_attempted", "step_rc",
    "mutation_performed", "transaction_commit", "started_at", "finished_at",
}

def now():
    return datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds")

class StateRefused(Exception):
    pass

def _refuse(reason, detail):
    raise StateRefused(reason, detail)

def _check_parent():
    parent = os.path.dirname(STATE_DIR)
    try:
        st = os.stat(parent)
    except OSError as exc:
        _refuse("reporting:state-parent-unavailable", f"{parent}: {exc.strerror}")
    if st.st_uid != PARENT_TRUSTED_UID:
        _refuse("reporting:state-parent-owner", f"{parent} owner uid={st.st_uid}, expected {PARENT_TRUSTED_UID}")
    if st.st_mode & 0o002:
        _refuse("reporting:state-parent-mode", f"{parent} is world-writable (mode {st.st_mode & 0o7777:04o})")
    if st.st_mode & 0o020:
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = None
        if st.st_gid != 0 and group not in PARENT_WRITABLE_GROUPS:
            _refuse("reporting:state-parent-mode", f"{parent} is group-writable by gid={st.st_gid} (mode {st.st_mode & 0o7777:04o})")

def _acquire_lock(dir_st):
    # dfd остаётся открытым до конца работы (см. _STATE_DFD): все последующие
    # записи (отчёт, журналы) идут относительно него, а не по строке STATE_DIR,
    # иначе подмена каталога после проверки уходит мимо проверенного inode.
    global _LOCK_FD, _STATE_DFD
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    dfd = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    ok = False
    try:
        opened = os.fstat(dfd)
        if (opened.st_dev, opened.st_ino) != (dir_st.st_dev, dir_st.st_ino):
            _refuse("reporting:state-dir-invalid", f"{STATE_DIR} changed during validation")
        fd = os.open(LOCK_NAME, flags, 0o600, dir_fd=dfd)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != TRUSTED_UID or st.st_mode & 0o022:
            os.close(fd)
            _refuse("reporting:state-lock-invalid", f"{LOCK_PATH} is not a regular root-owned single-link file without group/other write")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            _refuse("reporting:already-running", f"another instance already running (lock {LOCK_PATH})")
        _LOCK_FD = fd
        _STATE_DFD = dfd
        ok = True
    finally:
        if not ok:
            os.close(dfd)

def ensure_state_dir():
    _check_parent()
    try:
        os.mkdir(STATE_DIR, 0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        _refuse("reporting:state-dir-unavailable", f"{STATE_DIR}: {exc.strerror}")
    st = os.lstat(STATE_DIR)
    if stat.S_ISLNK(st.st_mode):
        _refuse("reporting:state-dir-symlink", f"{STATE_DIR} is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        _refuse("reporting:state-dir-invalid", f"{STATE_DIR} is not a directory")
    if st.st_uid != TRUSTED_UID:
        _refuse("reporting:state-dir-owner", f"{STATE_DIR} owner uid={st.st_uid}, expected {TRUSTED_UID}")
    if st.st_mode & 0o022:
        _refuse("reporting:state-dir-mode", f"{STATE_DIR} is group/other-writable (mode {st.st_mode & 0o7777:04o})")
    try:
        _acquire_lock(st)
    except OSError as exc:
        _refuse("reporting:state-lock-unavailable", f"{LOCK_PATH}: {exc.strerror}")

def _mkstemp_at(dfd, prefix):
    # Аналог tempfile.mkstemp, но относительно удерживаемого дескриптора
    # каталога (dir_fd), а не по строке пути.
    for _ in range(100):
        name = prefix + os.urandom(8).hex()
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        except FileExistsError:
            continue
        return fd, name
    raise OSError("reporting:tmp-name-exhausted")

def atomic_report(payload):
    fd, tmp = _mkstemp_at(_STATE_DFD, ".report.json.")
    try:
        data = (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, REPORT_PATH, src_dir_fd=_STATE_DFD, dst_dir_fd=_STATE_DFD)
        os.fsync(_STATE_DFD)
    except Exception:
        try:
            os.unlink(tmp, dir_fd=_STATE_DFD)
        except FileNotFoundError:
            pass
        raise

def append_log(name, message):
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=_STATE_DFD)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise RuntimeError("reporting:log-target-invalid")
        os.write(fd, (f"[{now()}] {message}\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)

def ensure_log_file(name):
    flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=_STATE_DFD)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise RuntimeError("reporting:log-target-invalid")
        os.fsync(fd)
    finally:
        os.close(fd)

def load_route(meta):
    raw = base64.b64decode(meta["source_b64"], validate=True)
    if __import__("hashlib").sha256(raw).hexdigest() != meta["implementation_sha256"]:
        raise RuntimeError("routing:embedded-implementation-sha-mismatch")
    ns = {"__name__": "_slp_embedded_" + meta["mechanism_id"].replace("-", "_"), "__file__": "<embedded>"}
    exec(compile(raw, "<embedded:" + meta["mechanism_id"] + ">", "exec"), ns)
    if ns.get("MECHANISM_ID") != meta["mechanism_id"] or ns.get("ADAPTER_ID") != meta["adapter_id"]:
        raise RuntimeError("routing:embedded-implementation-identity-mismatch")
    if not callable(ns.get("execute_control")) or not callable(ns.get("control_result_to_report")):
        raise RuntimeError("routing:embedded-implementation-api-missing")
    return ns

def unavailable_record(control, started, finished):
    return {
        "control_id": control["control_id"],
        "mechanism_id": None,
        "outcome": "ABORTED_PRECONDITION_OTHER",
        "reason": "routing:mechanism-unavailable",
        "actions_attempted": ["P0_ELIGIBILITY"],
        "step_rc": "nonzero",
        "mutation_performed": False,
        "transaction_commit": "NOT_STARTED",
        "started_at": started,
        "finished_at": finished,
        "mechanism_result": {"parameter_kind": control["parameter_kind"]},
    }

def crash_record(control, meta, started, finished, exc):
    return {
        "control_id": control["control_id"],
        "mechanism_id": None if meta is None else meta["mechanism_id"],
        "outcome": "FAILED_NOT_COMMITTED",
        "reason": "mechanism:unhandled-exception",
        "actions_attempted": [],
        "step_rc": "nonzero",
        "mutation_performed": None,
        "transaction_commit": "UNKNOWN",
        "started_at": started,
        "finished_at": finished,
        "mechanism_result": {"error_type": type(exc).__name__, "error_message": str(exc)},
    }

def _terminal_scalar(value, label):
    if value is None or isinstance(value, (dict, list, tuple, set)):
        raise RuntimeError("presentation:" + label + "-invalid")
    text = str(value)
    if not text or "\n" in text or "\r" in text:
        raise RuntimeError("presentation:" + label + "-invalid")
    return text

def _compact_outcome(outcome):
    exact = _terminal_scalar(outcome, "outcome")
    mapping = {
        "ALREADY_COMPLIANT": "ok",
        "APPLIED": "done",
        "APPLIED_PARTIAL": "part",
        "PENDING_REBOOT": "boot",
        "DRY_RUN_WOULD_APPLY": "would",
        "ABORTED_PRECONDITION_CONFLICT": "block",
        "ABORTED_PRECONDITION_OTHER": "abort",
        "FAILED_NOT_COMMITTED": "fail",
        "FAILED_COMPENSATION": "fail",
    }
    return mapping.get(exact, exact.lower())

def _table_chunks(value, width, label):
    text = _terminal_scalar(value, label) if value != "" else ""
    if not text:
        return [""]
    return [text[i:i + width] for i in range(0, len(text), width)]

def _word_chunks(value, width, label):
    # Перенос по пробелам; слово длиннее колонки режется по ширине.
    text = _terminal_scalar(value, label) if value != "" else ""
    chunks, line = [], ""
    for word in text.split(" "):
        while len(word) > width:
            if line:
                chunks.append(line)
                line = ""
            chunks.append(word[:width])
            word = word[width:]
        if not word:
            continue
        if line and len(line) + 1 + len(word) > width:
            chunks.append(line)
            line = word
        else:
            line = line + " " + word if line else word
    chunks.append(line)
    return chunks

def _terminal_columns():
    try:
        cols = os.get_terminal_size(sys.stdout.fileno()).columns
    except (OSError, ValueError):
        return 116
    if not isinstance(cols, int) or cols < 40 or cols > 1000:
        return 116
    return cols

PRETTY_COLUMNS = _terminal_columns()
PRETTY_IS_TTY = sys.stdout.isatty()
BLOCKS = []

def _terminal_layout(columns=None):
    if columns is None and not PRETTY_IS_TTY:
        columns = 116
    cols = PRETTY_COLUMNS if columns is None else columns
    if cols < 90:
        return ("vertical", cols, (8, cols - 14))
    # source от 100 колонок — 29 символов, «fstec-configuration-2026 §9.1» в одну строку;
    # место отдают control и current (решение пользователя 26.09.2026).
    if cols < 100:
        wsrc, wc, req_min = 18, 24, 10
    elif cols < 110:
        wsrc, wc, req_min = 29, 25, 12
    elif cols < 120:
        wsrc, wc, req_min = 29, 29, 14
    else:
        wsrc, wc, req_min = 29, 33, 16
    ws = 5
    available = cols - 15
    remaining = available - ws - wsrc - wc
    if remaining <= req_min:
        raise RuntimeError("presentation:terminal-width-invalid")
    wcur_base = min(43, remaining - req_min)
    # current отдаёт required 10 символов, но не становится уже 12.
    wcur = max(min(12, wcur_base), wcur_base - 10)
    wreq = remaining - wcur
    return ("table", cols, (ws, wsrc, wc, wcur, wreq))

def _emit_vertical_field(label, value, widths):
    wfield, wvalue = widths
    chunks = _table_chunks(value, wvalue, label) if value else [""]
    for i, chunk in enumerate(chunks):
        field = label if i == 0 else ""
        print(f" {field:<{wfield}} | {chunk:<{wvalue}} |")

def _emit_table_row(st, source, control, current, required):
    mode, _cols, widths = _terminal_layout()
    if mode == "vertical":
        if st == "st" and source == "source" and control == "control":
            wfield, wvalue = widths
            print(f" {'field':<{wfield}} | {'value':<{wvalue}} |")
            return
        _emit_vertical_field("st", st, widths)
        _emit_vertical_field("source", source, widths)
        _emit_vertical_field("control", control, widths)
        _emit_vertical_field("current", current, widths)
        _emit_vertical_field("required", required, widths)
        return
    ws, wsrc, wc, wcur, wreq = widths
    values = (st, source, control, current, required)
    labels = ("st", "source", "display-control", "current", "required")
    chunks = [_table_chunks(value, width, label) for value, width, label in zip(values, widths, labels)]
    rows = max(len(item) for item in chunks)
    for i in range(rows):
        parts = [item[i] if i < len(item) else "" for item in chunks]
        print(
            f" {parts[0]:<{ws}} | {parts[1]:<{wsrc}} | {parts[2]:<{wc}} | "
            f"{parts[3]:<{wcur}} | {parts[4]:<{wreq}} |"
        )

def _emit_separator():
    mode, _cols, widths = _terminal_layout()
    if mode == "vertical":
        wfield, wvalue = widths
        print("-" * (wfield + 2) + "+" + "-" * (wvalue + 2) + "+")
        return
    ws, wsrc, wc, wcur, wreq = widths
    print(
        "-" * (ws + 2) + "+"
        + "-" * (wsrc + 2) + "+"
        + "-" * (wc + 2) + "+"
        + "-" * (wcur + 2) + "+"
        + "-" * (wreq + 2) + "+"
    )

def _current_display(record):
    mechanism_result = record.get("mechanism_result")
    if not isinstance(mechanism_result, dict):
        return "not-determined"
    # sysctl отдаёт runtime_*, режимы файлов — resulting_mode/current_mode, параметры ядра — cmdline_current,
    # доступ к su — policy_current.
    for field in ("runtime_after", "runtime_before", "resulting_mode", "current_mode", "cmdline_current",
                  "policy_current"):
        value = mechanism_result.get(field)
        if value is not None:
            return _terminal_scalar(value, "current")
    return "not-determined"

def _block_entry(record, control):
    # Причина отказа видна администратору для обоих исходов ABORTED_PRECONDITION_*.
    if record.get("outcome") not in ("ABORTED_PRECONDITION_CONFLICT", "ABORTED_PRECONDITION_OTHER"):
        return None
    if record.get("step_rc") == "0" or record.get("mutation_performed") is not False:
        raise RuntimeError("presentation:block-invariant")
    record_id = _terminal_scalar(record.get("control_id"), "control-id")
    control_id = _terminal_scalar(control.get("control_id"), "control-id")
    if record_id != control_id:
        raise RuntimeError("presentation:control-id-mismatch")
    display_control = _block_control_label(control)
    detail = _terminal_scalar(record.get("reason"), "reason")
    entry = {"control": display_control, "rows": [("detail", detail)], "admin": False, "risk": None}
    mechanism_result = record.get("mechanism_result")
    if not isinstance(mechanism_result, dict):
        raise RuntimeError("presentation:block-mechanism-result-invalid")
    decision = mechanism_result.get("operator_decision")
    if decision is not None:
        if not isinstance(decision, dict) or decision.get("required") is not True:
            raise RuntimeError("presentation:operator-decision-invalid")
        if decision.get("class") == "SERVICE_MANAGED_PARAMETER":
            service = _terminal_scalar(decision.get("service"), "service")
            parameter = _terminal_scalar(decision.get("parameter"), "parameter")
            current_value = _terminal_scalar(decision.get("current_value"), "current-value")
            entry["rows"].append(
                ("note", f"{parameter}={current_value}: обнаружен штатный механизм {service}, управляющий этим параметром.")
            )
        elif decision.get("class") == "BOOT_PARAMETER_ADMIN_DECISION":
            value = _terminal_scalar(decision.get("value"), "value")
            risk = _terminal_scalar(decision.get("risk"), "risk")
            # Код причины остаётся в JSON-отчёте; инструкция add печатается над таблицей.
            entry["rows"] = [("add", value)]
            entry["risk"] = risk + "."
        elif decision.get("class") == "ADMIN_ACTION_REQUIRED":
            # Готовое действие администратора (2.2.1, решение человека 25.09.2026).
            entry["rows"].append(("note", _terminal_scalar(decision.get("action"), "action")))
        else:
            raise RuntimeError("presentation:operator-decision-invalid")
        entry["admin"] = True
    return entry

def _block_control_label(control):
    source = _terminal_scalar(control.get("source"), "source")
    if "§" not in source:
        raise RuntimeError("presentation:block-locator-missing")
    display_control = _terminal_scalar(control.get("display_control"), "display-control")
    return "§" + source.rsplit("§", 1)[1] + " " + display_control

def _blocks_layout():
    cols = PRETTY_COLUMNS if PRETTY_IS_TTY else 116
    wtype = 6
    need = max((len(_block_control_label(c)) for c in APPLY_CONTROLS), default=12)
    wcontrol = min(max(12, need), max(12, cols // 3))
    wmessage = cols - 9 - wcontrol - wtype
    if wmessage < 12:
        raise RuntimeError("presentation:blocks-terminal-width-invalid")
    return cols, (wcontrol, wtype, wmessage)

def _emit_blocks_row(control, kind, message):
    _cols, widths = _blocks_layout()
    wcontrol, wtype, wmessage = widths
    control_chunks = _table_chunks(control, wcontrol, "block-control")
    kind_chunks = _table_chunks(kind, wtype, "block-type")
    message_chunks = _word_chunks(message, wmessage, "block-message")
    rows = max(len(control_chunks), len(kind_chunks), len(message_chunks))
    for i in range(rows):
        c = control_chunks[i] if i < len(control_chunks) else ""
        k = kind_chunks[i] if i < len(kind_chunks) else ""
        m = message_chunks[i] if i < len(message_chunks) else ""
        print(f" {c:<{wcontrol}} | {k:<{wtype}} | {m:<{wmessage}} |")

def _emit_blocks_separator():
    _cols, widths = _blocks_layout()
    wcontrol, wtype, wmessage = widths
    print(
        "-" * (wcontrol + 2) + "+"
        + "-" * (wtype + 2) + "+"
        + "-" * (wmessage + 2) + "+"
    )

def emit_blocks():
    if not BLOCKS:
        return
    # Первая строка определяет статус block основной таблицы и общие для блоков фразы
    # (решения человека 24.09.2026). «Не применено» верно для каждого блока: _block_entry
    # требует mutation_performed=False.
    all_admin = all(entry["admin"] for entry in BLOCKS)
    print("block — не применено автоматически"
          + (", требуется решение администратора" if all_admin else "") + f" ({len(BLOCKS)}):")
    if any(kind == "add" for entry in BLOCKS for kind, _message in entry["rows"]):
        print("add: добавить параметр в GRUB_CMDLINE_LINUX, выполнить update-grub и перезагрузить систему.")
    _emit_blocks_separator()
    _emit_blocks_row("control", "type", "message")
    _emit_blocks_separator()
    for i, entry in enumerate(BLOCKS):
        for n, (kind, message) in enumerate(entry["rows"]):
            _emit_blocks_row(entry["control"] if n == 0 else "", kind, message)
        if entry["admin"] and not all_admin:
            _emit_blocks_row("", "note", "Требуется решение администратора.")
        # Одинаковый риск у блоков подряд — один раз, после последнего из них.
        following = BLOCKS[i + 1] if i + 1 < len(BLOCKS) else None
        if entry["risk"] and (following is None or following["risk"] != entry["risk"]):
            _emit_blocks_row("", "risk", entry["risk"])
    _emit_blocks_separator()

def emit_control_result(record, control):
    control_id = _terminal_scalar(record.get("control_id"), "control-id")
    if control_id != _terminal_scalar(control.get("control_id"), "control-id"):
        raise RuntimeError("presentation:control-id-mismatch")
    outcome = _compact_outcome(record.get("outcome"))
    source = _terminal_scalar(control.get("source"), "source")
    display_control = _terminal_scalar(control.get("display_control"), "display-control")
    current = _current_display(record)
    required = _terminal_scalar(control.get("required"), "required")
    _emit_table_row(outcome, source, display_control, current, required)
    block = _block_entry(record, control)
    if block is not None:
        BLOCKS.append(block)

def emit_summary(payload):
    controls = payload.get("controls")
    if not isinstance(controls, list):
        raise RuntimeError("presentation:controls-invalid")
    counts = {}
    for record in controls:
        if not isinstance(record, dict):
            raise RuntimeError("presentation:record-invalid")
        outcome = _terminal_scalar(record.get("outcome"), "outcome")
        counts[outcome] = counts.get(outcome, 0) + 1
    parts = [f"{name}={counts[name]}" for name in sorted(counts)]
    rc_text = "0" if payload.get("rc_zero") is True else "NONZERO"
    middle = (" " + " ".join(parts)) if parts else ""
    print(f"TOTAL={len(controls)}{middle} RC={rc_text}")

started_at = now()
payload = {
    "schema": "SLP-APPLY-REPORT-V2",
    "dry_run": DRY_RUN,
    "apply_kinds": sorted({meta["apply_kind"] for meta in ROUTES.values()}),
    "apply_control_count": len(APPLY_CONTROLS),
    "started_at": started_at,
    "finished_at": None,
    "complete": False,
    "rc_zero": None,
    "run_error": None,
    "controls": [],
}
try:
    ensure_state_dir()
except StateRefused as exc:
    print(f"REFUSED {exc.args[0]}: {exc.args[1]}", file=sys.stderr)
    raise SystemExit(1)
atomic_report(payload)
try:
    ensure_log_file(APPLY_LOG)
    ensure_log_file(DEBUG_LOG)
    append_log(APPLY_LOG, f"product apply start dry_run={str(DRY_RUN).lower()} controls={len(APPLY_CONTROLS)}")
    print(f"MODE={MODE} APPLY_CONTROLS={len(APPLY_CONTROLS)}")
    _emit_separator()
    _emit_table_row("st", "source", "control", "current", "required")
    _emit_separator()
    loaded = {}
    for control in APPLY_CONTROLS:
        c_started = now()
        meta = ROUTES.get(control["parameter_kind"])
        if meta is None:
            record = unavailable_record(control, c_started, now())
        else:
            try:
                ns = loaded.get(control["parameter_kind"])
                if ns is None:
                    ns = load_route(meta)
                    loaded[control["parameter_kind"]] = ns
                append_log(APPLY_LOG, f"control start {control['control_id']} mechanism={meta['mechanism_id']}")
                result = ns["execute_control"](
                    control["control_id"], control["key"], control["op"], control["expected"], True,
                    dry_run=DRY_RUN,
                )
                c_finished = now()
                raw = ns["control_result_to_report"](result, c_started, c_finished)
                mechanism_result = {k: v for k, v in raw.items() if k not in COMMON}
                record = {
                    "control_id": raw["control_id"],
                    "mechanism_id": meta["mechanism_id"],
                    "outcome": raw["outcome"],
                    "reason": raw["reason"],
                    "actions_attempted": raw["actions_attempted"],
                    "step_rc": raw["step_rc"],
                    "mutation_performed": raw["mutation_performed"],
                    "transaction_commit": raw["transaction_commit"],
                    "started_at": raw["started_at"],
                    "finished_at": raw["finished_at"],
                    "mechanism_result": mechanism_result,
                }
            except BaseException as exc:
                c_finished = now()
                append_log(DEBUG_LOG, traceback.format_exc().rstrip())
                record = crash_record(control, meta, c_started, c_finished, exc)
        payload["controls"].append(record)
        atomic_report(payload)
        emit_control_result(record, control)
        append_log(APPLY_LOG, f"control finish {control['control_id']} outcome={record['outcome']} step_rc={record['step_rc']}")
    payload["finished_at"] = now()
    payload["complete"] = True
    payload["rc_zero"] = all(item["step_rc"] == "0" for item in payload["controls"])
    atomic_report(payload)
    append_log(APPLY_LOG, f"product apply finish rc_zero={str(payload['rc_zero']).lower()}")
    _emit_separator()
    emit_blocks()
    emit_summary(payload)
    raise SystemExit(0 if payload["rc_zero"] else 1)
except SystemExit:
    raise
except BaseException as exc:
    payload["run_error"] = {"type": type(exc).__name__, "message": str(exc), "phase": "product-dispatch"}
    payload["finished_at"] = now()
    payload["complete"] = False
    payload["rc_zero"] = False
    try:
        atomic_report(payload)
        append_log(DEBUG_LOG, traceback.format_exc().rstrip())
    except Exception:
        pass
    raise

SLP_PRODUCT_APPLY_EOF
  return $?
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
      shift
      if (( $# == 0 )); then
        slp_run_apply APPLY
        return $?
      fi
      if (( $# == 1 )) && [[ $1 == --dry-run ]]; then
        slp_run_apply DRY_RUN
        return $?
      fi
      return 2
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
