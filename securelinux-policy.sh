#!/bin/bash -p
# SecureLinux-Policy v3 unified read-only product CLI
# STATUS=NON_RELEASE_PRODUCT_CANDIDATE
# PRODUCT_CLI=product-cli-v1
# GENERATOR_ID=product-check-generator-v2
# GENERATOR_SHA256=2221d4d144275ae18718d50bf4a7de568d763f6380d6a7b7c2394bae7b141ea3
# CONTROL_MANIFEST_SHA256=a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216
# ADAPTER_REGISTRY_SHA256=c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60
# TARGET_ID=ubuntu-24.04-x86_64

set -u

slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE() {
  local _slp_passwd='/etc/passwd'
  local _slp_shadow='/etc/shadow'
  local _slp_line _slp_user _slp_rest _slp_pwd _slp_colons
  local _slp_accounts=0 _slp_empty=0
  local -a _slp_passwd_lines=() _slp_shadow_lines=()
  local -A _slp_shadow_seen=() _slp_shadow_pwd=() _slp_passwd_seen=()
  if [[ -L "$_slp_passwd" || -L "$_slp_shadow" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! -f "$_slp_passwd" || ! -f "$_slp_shadow" || ! -r "$_slp_passwd" || ! -r "$_slp_shadow" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"
    return 0
  fi
  if ! mapfile -t _slp_shadow_lines < "$_slp_shadow"; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"
    return 0
  fi
  if ! mapfile -t _slp_passwd_lines < "$_slp_passwd"; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"
    return 0
  fi
  if (( ${#_slp_passwd_lines[@]} == 0 || ${#_slp_shadow_lines[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"
    return 0
  fi
  for _slp_line in "${_slp_shadow_lines[@]}"; do
    [[ -n "$_slp_line" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"; return 0; }
    _slp_colons=${_slp_line//[^:]/}
    [[ ${#_slp_colons} -eq 8 ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"; return 0; }
    _slp_user=${_slp_line%%:*}
    _slp_rest=${_slp_line#*:}
    _slp_pwd=${_slp_rest%%:*}
    [[ "$_slp_user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"; return 0; }
    [[ -z ${_slp_shadow_seen["$_slp_user"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"; return 0; }
    _slp_shadow_seen["$_slp_user"]=1
    _slp_shadow_pwd["$_slp_user"]=$_slp_pwd
  done
  for _slp_line in "${_slp_passwd_lines[@]}"; do
    [[ -n "$_slp_line" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"; return 0; }
    _slp_colons=${_slp_line//[^:]/}
    [[ ${#_slp_colons} -eq 6 ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"; return 0; }
    _slp_user=${_slp_line%%:*}
    [[ "$_slp_user" =~ ^[A-Za-z_][A-Za-z0-9_.-]*\$?$ ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"; return 0; }
    [[ -z ${_slp_passwd_seen["$_slp_user"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"; return 0; }
    _slp_passwd_seen["$_slp_user"]=1
    [[ -n ${_slp_shadow_seen["$_slp_user"]+x} ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"; return 0; }
    _slp_pwd=${_slp_shadow_pwd["$_slp_user"]}
    ((_slp_accounts+=1))
    [[ -n "$_slp_pwd" ]] || ((_slp_empty+=1))
  done
  (( _slp_accounts > 0 )) || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "ERROR" "-" "ERROR"; return 0; }
  if (( _slp_empty == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "VALUE" "accounts=$_slp_accounts;empty=0" "PASS"
  else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' "VALUE" "accounts=$_slp_accounts;empty=$_slp_empty" "FAIL"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_1_2_SSH_ROOT_LOGIN() {
  local _slp_cfg='/etc/ssh/sshd_config'
  local _slp_sshd='/usr/sbin/sshd'
  local _slp_sort='/usr/bin/sort'
  local _slp_parser_error=0 _slp_main_no=0 _slp_match_non_no=0 _slp_rc=0
  local _slp_real _slp_line _slp_effective
  local -a _slp_effective_lines=()
  local -A _slp_stack=()
  if [[ -L "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    return 0
  fi
  if [[ ! -f "$_slp_cfg" || ! -r "$_slp_cfg" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"
    return 0
  fi
  [[ -x /usr/bin/readlink ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"; return 0; }
  [[ -x /usr/bin/find ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"; return 0; }
  [[ -x "$_slp_sort" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"; return 0; }
  if [[ -L "$_slp_sshd" ]]; then
    _slp_real=$(command /usr/bin/readlink -f -- "$_slp_sshd" 2>/dev/null) || _slp_real=
    [[ -n "$_slp_real" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"; return 0; }
    _slp_sshd=$_slp_real
  fi
  if [[ ! -e "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "NOT_FOUND" "-" "FAIL"
    return 0
  fi
  if [[ ! -f "$_slp_sshd" || ! -x "$_slp_sshd" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"
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
  _slp_parse_sshd_file() {
    local _slp_pf=$1 _slp_pd=$2 _slp_pm=$3 _slp_scope=$4
    local _slp_pr _slp_pl _slp_pk _slp_rest _slp_pp _slp_px _slp_prefix _slp_item _slp_pv _slp_grc _slp_glob_text _slp_nl
    local -a _slp_args=() _slp_glob=()
    (( _slp_pd <= 16 )) || { _slp_parser_error=1; return 0; }
    [[ ! -L "$_slp_pf" && -f "$_slp_pf" && -r "$_slp_pf" ]] || { _slp_parser_error=1; return 0; }
    _slp_pr=$(command /usr/bin/readlink -f -- "$_slp_pf" 2>/dev/null) || { _slp_parser_error=1; return 0; }
    [[ -n "$_slp_pr" ]] || { _slp_parser_error=1; return 0; }
    [[ -z ${_slp_stack["$_slp_pr"]+x} ]] || { _slp_parser_error=1; return 0; }
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
      _slp_split_args "$_slp_rest" || { _slp_parser_error=1; break; }
      if [[ "$_slp_pk" == match ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; break; }
        _slp_scope=MATCH
        continue
      fi
      if [[ "$_slp_pk" == include ]]; then
        (( ${#_slp_args[@]} >= 1 )) || { _slp_parser_error=1; break; }
        for _slp_pp in "${_slp_args[@]}"; do
          if [[ "$_slp_pp" == /* ]]; then _slp_px=$_slp_pp; else _slp_px=/etc/ssh/$_slp_pp; fi
          _slp_glob=()
          if [[ "$_slp_px" == *'*'* || "$_slp_px" == *'?'* || "$_slp_px" == *'['* ]]; then
            _slp_prefix=${_slp_px%%[\*\?\[]*}
            _slp_prefix=${_slp_prefix%/*}
            [[ -n "$_slp_prefix" ]] || _slp_prefix=/
            if [[ -e "$_slp_prefix" ]]; then
              [[ -d "$_slp_prefix" && ! -L "$_slp_prefix" ]] || { _slp_parser_error=1; break 2; }
              _slp_nl=$(command /usr/bin/find "$_slp_prefix" -name $'*\n*' -print -quit 2>/dev/null)
              _slp_grc=$?
              (( _slp_grc == 0 )) || { _slp_parser_error=1; break 2; }
              [[ -z "$_slp_nl" ]] || { _slp_parser_error=1; break 2; }
            fi
            _slp_glob_text=$( ( set -o pipefail; builtin compgen -G "$_slp_px" | LC_ALL=C command "$_slp_sort" ) )
            _slp_grc=$?
            if (( _slp_grc == 0 )); then
              while IFS= read -r _slp_item; do [[ -n "$_slp_item" ]] && _slp_glob+=("$_slp_item"); done <<< "$_slp_glob_text"
            elif (( _slp_grc != 1 )); then _slp_parser_error=1; break 2; fi
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
        (( ${#_slp_args[@]} == 1 )) || { _slp_parser_error=1; break; }
        [[ "${_slp_args[0]}" != *"="* ]] || { _slp_parser_error=1; break; }
        _slp_pv=${_slp_args[0],,}
        if [[ "$_slp_scope" == GLOBAL && "$_slp_pm" == 1 && "$_slp_pv" == no ]]; then ((_slp_main_no+=1)); fi
        if [[ "$_slp_scope" == MATCH && "$_slp_pv" != no ]]; then ((_slp_match_non_no+=1)); fi
      fi
    done < "$_slp_pf" || _slp_parser_error=1
    unset '_slp_stack[$_slp_pr]'
    return 0
  }
  _slp_parse_sshd_file "$_slp_cfg" 0 1 GLOBAL
  if (( _slp_parser_error != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"
    return 0
  fi
  if (( _slp_match_non_no != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"
    return 0
  fi
  command "$_slp_sshd" -t -f "$_slp_cfg" >/dev/null 2>&1
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_effective=$(command "$_slp_sshd" -T -C user=root,host=localhost,addr=127.0.0.1 -f "$_slp_cfg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_effective_lines=()
  while IFS= read -r _slp_line; do
    _slp_line=${_slp_line%$'\r'}
    [[ "${_slp_line,,}" =~ ^permitrootlogin[[:space:]]+([^[:space:]]+)[[:space:]]*$ ]] || continue
    _slp_effective_lines+=("${BASH_REMATCH[1],,}")
  done <<< "$_slp_effective"
  if (( ${#_slp_effective_lines[@]} != 1 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' "ERROR" "-" "ERROR"
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
  local _slp_line _slp_logical='' _slp_trim _slp_module _slp_control _slp_gid='' _slp_members='' _slp_name _slp_hex _slp_byte _slp_prev
  local -a _slp_tok=() _slp_members_arr=()
  local -A _slp_actual=() _slp_approved=()
  local _slp_exact=0 _slp_other=0 _slp_wheel=0 _slp_error=0 _slp_mismatch=0 _slp_midx=0 _slp_i=0

  if [[ -L "$_slp_pam" || -L "$_slp_group" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\t-\tERROR\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -e "$_slp_pam" || ! -e "$_slp_group" ]]; then
    printf 'SLP-CHECK-V1\t%s\tNOT_FOUND\t-\tFAIL\n' "$_slp_cid"
    return 0
  fi
  if [[ ! -f "$_slp_pam" || ! -r "$_slp_pam" || ! -f "$_slp_group" || ! -r "$_slp_group" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\t-\tERROR\n' "$_slp_cid"
    return 0
  fi
  _slp_validate_text_bytes() {
    local _slp_v_path=$1 _slp_v_hex _slp_v_byte _slp_v_prev=''
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 1; fi
    for _slp_v_byte in $_slp_v_hex; do
      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
      [[ "$_slp_v_byte" != 00 ]] || return 1
      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi
      _slp_v_prev=$_slp_v_byte
    done
    [[ "$_slp_v_prev" != 0d ]] || return 1
    return 0
  }
  for _slp_name in "$_slp_pam" "$_slp_group"; do
    if ! _slp_validate_text_bytes "$_slp_name"; then
      printf 'SLP-CHECK-V1\t%s\tERROR\t-\tERROR\n' "$_slp_cid"
      return 0
    fi
  done

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
      continue
    fi
    (( ${#_slp_tok[@]} >= 3 )) || { _slp_error=1; break; }
    _slp_control=${_slp_tok[1],,}
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
    printf 'SLP-CHECK-V1\t%s\tERROR\t-\tERROR\n' "$_slp_cid"
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
    printf 'SLP-CHECK-V1\t%s\tERROR\t-\tERROR\n' "$_slp_cid"
    return 0
  fi
  if (( _slp_wheel == 1 )) && [[ -n "$_slp_members" ]]; then
    if [[ "$_slp_members" == ,* || "$_slp_members" == *, || "$_slp_members" == *,,* ]]; then _slp_error=1; fi
    IFS=',' read -r -a _slp_members_arr <<< "$_slp_members"
    for _slp_name in "${_slp_members_arr[@]}"; do
      if [[ -z "$_slp_name" || "$_slp_name" == *[[:space:]:#]* || -n "${_slp_actual[$_slp_name]+x}" ]]; then _slp_error=1; break; fi
      _slp_actual["$_slp_name"]=1
    done
  fi
  if (( _slp_error )); then
    printf 'SLP-CHECK-V1\t%s\tERROR\t-\tERROR\n' "$_slp_cid"
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

  if [[ ! -e "$_slp_authority" || ! -f "$_slp_authority" || -L "$_slp_authority" || ! -r "$_slp_authority" ]]; then
    printf 'SLP-CHECK-V1\t%s\tERROR\t-\tERROR\n' "$_slp_cid"
    return 0
  fi
  if ! _slp_validate_text_bytes "$_slp_authority"; then
    printf 'SLP-CHECK-V1\t%s\tERROR\t-\tERROR\n' "$_slp_cid"
    return 0
  fi
  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    if [[ "$_slp_line" == *$'\r'* ]]; then
      if [[ "$_slp_line" != *$'\r' || "${_slp_line%$'\r'}" == *$'\r'* ]]; then _slp_error=1; break; fi
      _slp_line=${_slp_line%$'\r'}
    fi
    [[ -n "$_slp_line" ]] || continue
    [[ "${_slp_line:0:1}" != \# ]] || continue
    if [[ "$_slp_line" == root || "$_slp_line" == *[[:space:],:#]* || -n "${_slp_approved[$_slp_line]+x}" ]]; then _slp_error=1; break; fi
    _slp_approved["$_slp_line"]=1
  done < "$_slp_authority"
  if (( _slp_error )); then
    printf 'SLP-CHECK-V1\t%s\tERROR\t-\tERROR\n' "$_slp_cid"
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
  local _slp_actual_count=0 _slp_approved_count=0 _slp_mismatch=0
  local -A _slp_actual=() _slp_approved=() _slp_seen=()

  _slp_error() { printf 'SLP-CHECK-V1\t%s\tERROR\t-\tERROR\n' "$_slp_cid"; return 0; }
  _slp_validate_authority_bytes() {
    local _slp_v_hex _slp_v_byte _slp_v_prev=''
    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_authority" 2>/dev/null); then return 1; fi
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

  [[ -e "$_slp_root" && -f "$_slp_root" && ! -L "$_slp_root" && -r "$_slp_root" ]] || { _slp_error; return 0; }
  [[ -e "$_slp_authority" && -f "$_slp_authority" && ! -L "$_slp_authority" && -r "$_slp_authority" ]] || { _slp_error; return 0; }
  [[ -x "$_slp_visudo" ]] || { _slp_error; return 0; }
  _slp_validate_authority_bytes || { _slp_error; return 0; }

  _slp_accept_visudo_line() {
    local _slp_v_line=$1
    [[ -n "$_slp_v_line" && "$_slp_v_line" == *': parsed OK' ]] || return 1
    _slp_path=${_slp_v_line%': parsed OK'}
    [[ "$_slp_path" == /* && "$_slp_path" != *$'\t'* && "$_slp_path" != *$'\r'* ]] || return 1
    [[ -z "${_slp_seen[$_slp_path]+x}" ]] || return 1
    _slp_seen["$_slp_path"]=1
    [[ -e "$_slp_path" && -f "$_slp_path" && ! -L "$_slp_path" && -r "$_slp_path" ]] || return 1
    _slp_hash=$(LC_ALL=C command /usr/bin/sha256sum -- "$_slp_path" 2>/dev/null) || return 1
    _slp_hash=${_slp_hash%% *}
    [[ "$_slp_hash" =~ ^[0-9a-f]{64}$ ]] || return 1
    _slp_actual["$_slp_path"]=$_slp_hash
    ((_slp_actual_count+=1))
    return 0
  }

  _slp_visudo_hex=$(set -o pipefail; LC_ALL=C command "$_slp_visudo" -c -f "$_slp_root" 2>&1 | LC_ALL=C command /usr/bin/od -An -v -tx1)
  _slp_rc=$?
  (( _slp_rc == 0 )) || { _slp_error; return 0; }
  [[ -n "$_slp_visudo_hex" ]] || { _slp_error; return 0; }
  _slp_line=''
  for _slp_byte in $_slp_visudo_hex; do
    [[ "$_slp_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || { _slp_error; return 0; }
    case "$_slp_byte" in
      0a)
        _slp_accept_visudo_line "$_slp_line" || { _slp_error; return 0; }
        _slp_line=''
        ;;
      00|01|02|03|04|05|06|07|08|09|0b|0c|0d|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f|7f)
        _slp_error; return 0
        ;;
      *)
        printf -v _slp_char '%b' "\x$_slp_byte" || { _slp_error; return 0; }
        _slp_line+="$_slp_char"
        ;;
    esac
  done
  if [[ -n "$_slp_line" ]]; then
    _slp_accept_visudo_line "$_slp_line" || { _slp_error; return 0; }
  fi
  [[ _slp_actual_count -gt 0 && -n "${_slp_actual[$_slp_root]+x}" ]] || { _slp_error; return 0; }

  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    if [[ "$_slp_line" == *$'\r'* ]]; then
      [[ "$_slp_line" == *$'\r' && "${_slp_line%$'\r'}" != *$'\r'* ]] || { _slp_error; return 0; }
      _slp_line=${_slp_line%$'\r'}
    fi
    if [[ -z "$_slp_header" ]]; then
      [[ "$_slp_line" == 'SLP-SUDOERS-REVIEWED-POLICY-V1' ]] || { _slp_error; return 0; }
      _slp_header=1
      continue
    fi
    [[ -n "$_slp_line" && "$_slp_line" == *$'\t'* ]] || { _slp_error; return 0; }
    _slp_hash=${_slp_line%%$'\t'*}
    _slp_path=${_slp_line#*$'\t'}
    [[ "$_slp_path" != *$'\t'* && "$_slp_hash" =~ ^[0-9a-f]{64}$ && "$_slp_path" == /* && -n "$_slp_path" ]] || { _slp_error; return 0; }
    [[ -z "${_slp_approved[$_slp_path]+x}" ]] || { _slp_error; return 0; }
    _slp_approved["$_slp_path"]=$_slp_hash
    ((_slp_approved_count+=1))
  done < "$_slp_authority"
  [[ -n "$_slp_header" && _slp_approved_count -gt 0 && -n "${_slp_approved[$_slp_root]+x}" ]] || { _slp_error; return 0; }

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
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
  if _slp_mode=$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null); then
    if [[ ! $_slp_mode =~ ^[0-7]{1,4}$ ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "-" "ERROR"
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
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "-" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_1_PASSWD_MODE() {
  local _slp_path='/etc/passwd'
  local _slp_expected='0644'
  local _slp_mode _slp_parent _slp_comp
  if [[ ! -x /usr/bin/stat ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
  if _slp_mode=$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null); then
    if [[ ! $_slp_mode =~ ^[0-7]{1,4}$ ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "-" "ERROR"
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
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "-" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_1_SHADOW_GO_RWX() {
  local _slp_path='/etc/shadow'
  local _slp_expected='0077'
  local _slp_mode _slp_parent _slp_comp
  if [[ ! -x /usr/bin/stat ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "-" "ERROR"
    return 0
  fi
  if _slp_mode=$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null); then
    if [[ ! $_slp_mode =~ ^[0-7]{1,4}$ ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "-" "ERROR"
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
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "-" "ERROR"
  fi
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_10_HOME_SENSITIVE_FILES_MODE() {
  local _slp_passwd='/etc/passwd' _slp_login_defs='/etc/login.defs' _slp_inventory='/etc/securelinux-policy/home-sensitive-files-v1'
  local _slp_expected='0077'
  local _slp_line _slp_body _slp_entry _slp_name _slp_pw _slp_uid _slp_gid _slp_gecos _slp_home _slp_shell
  local _slp_shell_trim _slp_shell_base _slp_home_id _slp_rel _slp_path _slp_cur _slp_part _slp_mode _slp_hex
  local _slp_uid_min='' _slp_uid_min_hits=0 _slp_candidate=0 _slp_missing=0
  local _slp_accounts=0 _slp_homes=0 _slp_checked=0 _slp_violations=0 _slp_i=0
  local -a _slp_fields=() _slp_names=() _slp_parts=() _slp_mandatory=('.bash_history' '.history' '.sh_history' '.bash_profile' '.bashrc' '.profile' '.bash_logout' '.rhosts')
  local -A _slp_seen_names=() _slp_seen_homes=()

  for _slp_path in "$_slp_passwd" "$_slp_login_defs" "$_slp_inventory"; do
    if [[ ! -f "$_slp_path" || -L "$_slp_path" || ! -r "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ "$_slp_hex" =~ (^|[[:space:]])00([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
  done

  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    if [[ "$_slp_line" == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_body=${_slp_line%%#*}
    if [[ "$_slp_body" =~ ^[[:space:]]*UID_MIN[[:space:]]+([0-9]+)[[:space:]]*$ ]]; then
      ((_slp_uid_min_hits+=1))
      _slp_uid_min=${BASH_REMATCH[1]}
    fi
  done < "$_slp_login_defs"
  if (( _slp_uid_min_hits != 1 )) || [[ -z "$_slp_uid_min" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
    return 0
  fi

  while IFS= read -r _slp_entry || [[ -n "$_slp_entry" ]]; do
    if [[ "$_slp_entry" == *$'\r'* || "$_slp_entry" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    [[ -z "$_slp_entry" || "${_slp_entry:0:1}" == "#" ]] && continue
    if [[ ! "$_slp_entry" =~ ^\.[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ${_slp_seen_names["$_slp_entry"]+x} ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_seen_names["$_slp_entry"]=1
    _slp_names+=("$_slp_entry")
  done < "$_slp_inventory"
  for _slp_entry in "${_slp_mandatory[@]}"; do
    if [[ ! ${_slp_seen_names["$_slp_entry"]+x} ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
  done

  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    if [[ -z "$_slp_line" || "$_slp_line" == *$'\r'* ]]; then
      [[ -z "$_slp_line" ]] && continue
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    IFS=: read -r -a _slp_fields <<< "$_slp_line"
    if (( ${#_slp_fields[@]} != 7 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_name=${_slp_fields[0]}; _slp_pw=${_slp_fields[1]}; _slp_uid=${_slp_fields[2]}; _slp_gid=${_slp_fields[3]}
    _slp_gecos=${_slp_fields[4]}; _slp_home=${_slp_fields[5]}; _slp_shell=${_slp_fields[6]}
    if [[ ! "$_slp_uid" =~ ^[0-9]+$ || ! "$_slp_gid" =~ ^[0-9]+$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_shell_trim=${_slp_shell%/}; _slp_shell_base=${_slp_shell_trim##*/}
    _slp_candidate=0
    if [[ "$_slp_home" == /* && "$_slp_shell_base" != "nologin" && "$_slp_shell_base" != "false" ]]; then
      if (( 10#$_slp_uid == 0 || (10#$_slp_uid >= 10#$_slp_uid_min && 10#$_slp_uid != 65534) )); then _slp_candidate=1; fi
    fi
    (( _slp_candidate == 1 )) || continue
    ((_slp_accounts+=1))
    if [[ ! -e "$_slp_home" && ! -L "$_slp_home" ]]; then continue; fi
    if [[ -L "$_slp_home" || ! -d "$_slp_home" || ! -r "$_slp_home" || ! -x "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_home_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_home" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ${_slp_seen_homes["$_slp_home_id"]+x} ]]; then continue; fi
    _slp_seen_homes["$_slp_home_id"]=1
    ((_slp_homes+=1))
    for _slp_rel in "${_slp_names[@]}"; do
      _slp_cur=$_slp_home; _slp_missing=0
      IFS=/ read -r -a _slp_parts <<< "$_slp_rel"
      for ((_slp_i=0; _slp_i<${#_slp_parts[@]}; _slp_i++)); do
        _slp_part=${_slp_parts[$_slp_i]}; _slp_cur="$_slp_cur/$_slp_part"
        if [[ -L "$_slp_cur" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
          return 0
        fi
        if (( _slp_i + 1 < ${#_slp_parts[@]} )); then
          if [[ ! -e "$_slp_cur" ]]; then _slp_missing=1; break; fi
          if [[ ! -d "$_slp_cur" || ! -x "$_slp_cur" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
            return 0
          fi
        fi
      done
      (( _slp_missing == 1 )) && continue
      _slp_path=$_slp_cur
      if [[ ! -e "$_slp_path" ]]; then continue; fi
      if [[ -L "$_slp_path" || ! -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ ! "$_slp_mode" =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      ((_slp_checked+=1))
      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
    done
  done < "$_slp_passwd"
  if (( _slp_accounts == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
  local _slp_value="accounts=$_slp_accounts;homes=$_slp_homes;names=${#_slp_names[@]};checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_11_HOME_DIRECTORIES_MODE() {
  local _slp_passwd='/etc/passwd' _slp_login_defs='/etc/login.defs'
  local _slp_expected='0700'
  local _slp_line _slp_body _slp_name _slp_pw _slp_uid _slp_gid _slp_gecos _slp_home _slp_shell _slp_path _slp_hex
  local _slp_shell_trim _slp_shell_base _slp_home_id _slp_mode
  local _slp_uid_min='' _slp_uid_min_hits=0 _slp_candidate=0
  local _slp_accounts=0 _slp_homes=0 _slp_violations=0
  local -a _slp_fields=()
  local -A _slp_seen_homes=()

  for _slp_path in "$_slp_passwd" "$_slp_login_defs"; do
    if [[ ! -f "$_slp_path" || -L "$_slp_path" || ! -r "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ "$_slp_hex" =~ (^|[[:space:]])00([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
  done

  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    if [[ "$_slp_line" == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_body=${_slp_line%%#*}
    if [[ "$_slp_body" =~ ^[[:space:]]*UID_MIN[[:space:]]+([0-9]+)[[:space:]]*$ ]]; then
      ((_slp_uid_min_hits+=1))
      _slp_uid_min=${BASH_REMATCH[1]}
    fi
  done < "$_slp_login_defs"
  if (( _slp_uid_min_hits != 1 )) || [[ -z "$_slp_uid_min" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
    return 0
  fi

  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    if [[ -z "$_slp_line" || "$_slp_line" == *$'\r'* ]]; then
      [[ -z "$_slp_line" ]] && continue
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    IFS=: read -r -a _slp_fields <<< "$_slp_line"
    if (( ${#_slp_fields[@]} != 7 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_name=${_slp_fields[0]}; _slp_pw=${_slp_fields[1]}; _slp_uid=${_slp_fields[2]}; _slp_gid=${_slp_fields[3]}
    _slp_gecos=${_slp_fields[4]}; _slp_home=${_slp_fields[5]}; _slp_shell=${_slp_fields[6]}
    if [[ ! "$_slp_uid" =~ ^[0-9]+$ || ! "$_slp_gid" =~ ^[0-9]+$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_shell_trim=${_slp_shell%/}; _slp_shell_base=${_slp_shell_trim##*/}
    _slp_candidate=0
    if [[ "$_slp_home" == /* && "$_slp_shell_base" != "nologin" && "$_slp_shell_base" != "false" ]]; then
      if (( 10#$_slp_uid == 0 || (10#$_slp_uid >= 10#$_slp_uid_min && 10#$_slp_uid != 65534) )); then _slp_candidate=1; fi
    fi
    (( _slp_candidate == 1 )) || continue
    ((_slp_accounts+=1))
    if [[ ! -e "$_slp_home" && ! -L "$_slp_home" ]]; then continue; fi
    if [[ -L "$_slp_home" || ! -d "$_slp_home" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_home_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_home" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ${_slp_seen_homes["$_slp_home_id"]+x} ]]; then continue; fi
    _slp_seen_homes["$_slp_home_id"]=1
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_home" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ! "$_slp_mode" =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    ((_slp_homes+=1))
    if (( 8#$_slp_mode != 8#$_slp_expected )); then ((_slp_violations+=1)); fi
  done < "$_slp_passwd"
  if (( _slp_accounts == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
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


def error():
    print("ERROR")
    raise SystemExit(0)


def read_start(pid):
    try:
        raw = (pid / "stat").read_text(encoding="ascii", errors="strict")
    except FileNotFoundError:
        return None
    except Exception:
        error()
    if "\x00" in raw or "\r" in raw:
        error()
    if raw.endswith("\n"):
        body = raw[:-1]
    else:
        body = raw
    if not body or "\n" in body or "\t" in body or "\v" in body or "\f" in body:
        error()
    prefix = pid.name + " ("
    if not body.startswith(prefix):
        error()
    close = body.rfind(")")
    if close < len(prefix) - 1 or close + 1 >= len(body) or body[close + 1] != " ":
        error()
    fields = body[close + 2:].split(" ")
    if len(fields) != 50 or any(field == "" for field in fields):
        error()
    state = fields[0]
    if len(state) != 1 or not state.isascii() or not state.isalpha():
        error()
    for value in fields[1:]:
        if ASCII_SIGNED_DECIMAL.fullmatch(value) is None:
            error()
    starttime = fields[19]
    if ASCII_DECIMAL.fullmatch(starttime) is None:
        error()
    return starttime


def read_process_counter():
    try:
        text = (proc_root / "stat").read_text(encoding="ascii", errors="strict")
    except Exception:
        error()
    if "\x00" in text or "\r" in text:
        error()
    values = []
    for line in text.splitlines():
        if not line.startswith("processes"):
            continue
        match = PROC_PROCESSES.fullmatch(line)
        if match is None:
            error()
        values.append(int(match.group(1), 10))
    if len(values) != 1:
        error()
    return values[0]


def population_snapshot():
    try:
        entries = sorted((p for p in proc_root.iterdir() if p.name.isdigit()), key=lambda p: int(p.name))
    except Exception:
        error()
    if not entries:
        error()
    snap = {}
    for pid in entries:
        start = read_start(pid)
        if start is None:
            error()
        snap[pid.name] = start
    return snap


def classify_no_exe(pid, expected_start):
    try:
        status = (pid / "status").read_text(encoding="utf-8", errors="strict")
    except Exception:
        error()
    if "\x00" in status or "\r" in status:
        error()
    kthread = False
    state = None
    for line in status.splitlines():
        if line.startswith("Kthread:"):
            kthread = line.split(":", 1)[1].strip() == "1"
        elif line.startswith("State:"):
            value = line.split(":", 1)[1].strip()
            state = value[:1] if value else None
    if not (kthread or state == "Z"):
        error()
    end = read_start(pid)
    if end is None or end != expected_start:
        error()
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
            error()
        digits = raw[i + 1:i + 4]
        if any(c not in OCTAL for c in digits):
            error()
        value = int(digits, 8)
        if value == 0:
            error()
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
        error()


def check_path(path_text, file_records, file_states, parent_records, path_set, expected_mapping=None):
    if not path_text.startswith("/") or "\x00" in path_text:
        error()
    try:
        source_lstat = os.lstat(path_text)
        real = os.path.realpath(path_text)
    except Exception:
        error()
    if not real.startswith("/"):
        error()
    within_stop(real)
    try:
        fst = os.stat(real, follow_symlinks=True)
    except Exception:
        error()
    if not stat.S_ISREG(fst.st_mode):
        error()
    if expected_mapping is not None:
        map_major, map_minor, map_inode = expected_mapping
        try:
            actual_major = os.major(fst.st_dev)
            actual_minor = os.minor(fst.st_dev)
        except Exception:
            error()
        if (actual_major, actual_minor, fst.st_ino) != (map_major, map_minor, map_inode):
            error()
    source_state = obj_state(source_lstat)
    target_state = obj_state(fst)
    record = (real, source_state, target_state)
    old = file_records.get(path_text)
    if old is not None and old != record:
        error()
    file_records[path_text] = record
    identity = (fst.st_dev, fst.st_ino)
    old_state = file_states.get(identity)
    if old_state is not None and old_state != target_state:
        error()
    file_states[identity] = target_state
    path_set.add(real)

    cur = Path(real).parent
    stop = parent_stop
    while True:
        try:
            dst = os.stat(cur, follow_symlinks=True)
        except Exception:
            error()
        if not stat.S_ISDIR(dst.st_mode):
            error()
        state = obj_state(dst)
        old_dir = parent_records.get(str(cur))
        if old_dir is not None and old_dir != state:
            error()
        parent_records[str(cur)] = state
        if cur == stop:
            break
        if cur == cur.parent:
            if stop != cur:
                error()
            break
        if stop != Path("/"):
            try:
                cur.relative_to(stop)
            except ValueError:
                error()
        cur = cur.parent
    return identity


def parse_maps(pid):
    try:
        text = (pid / "maps").read_text(encoding="utf-8", errors="strict")
    except Exception:
        error()
    if "\x00" in text or "\r" in text:
        error()
    mapped_exec = []
    saw_line = False
    for line in text.splitlines():
        if not line:
            continue
        saw_line = True
        parts = line.split(None, 5)
        if len(parts) not in (5, 6):
            error()

        address_text, perms, offset_text, device_text, inode_text = parts[:5]
        address = MAP_ADDRESS.fullmatch(address_text)
        if address is None:
            error()
        start = int(address.group(1), 16)
        end = int(address.group(2), 16)
        if start >= end:
            error()
        if not MAP_PERMS.fullmatch(perms):
            error()
        if not MAP_OFFSET.fullmatch(offset_text):
            error()
        offset = int(offset_text, 16)
        device = MAP_DEVICE.fullmatch(device_text)
        if device is None:
            error()
        dev_major = int(device.group(1), 16)
        dev_minor = int(device.group(2), 16)
        if ASCII_DECIMAL.fullmatch(inode_text) is None:
            error()
        inode = int(inode_text, 10)

        if len(parts) == 5:
            if inode != 0:
                error()
            continue

        raw_path = parts[5]
        if raw_path.startswith("[") and raw_path.endswith("]"):
            if inode != 0:
                error()
            continue

        path = decode_proc_path(raw_path)
        if path.endswith(" (deleted)"):
            error()
        if not path.startswith("/"):
            error()
        if perms[2] != "x":
            continue
        if inode == 0:
            error()
        mapped_exec.append((path, start, end, offset, dev_major, dev_minor, inode))

    if not saw_line or not mapped_exec:
        error()
    return mapped_exec


def read_exe(pid):
    try:
        target = os.readlink(pid / "exe")
        exe_stat = os.stat(pid / "exe", follow_symlinks=True)
    except FileNotFoundError:
        return None
    except Exception:
        error()
    if target.endswith(" (deleted)") or not target.startswith("/") or "\x00" in target:
        error()
    if not stat.S_ISREG(exe_stat.st_mode):
        error()
    return target, obj_state(exe_stat)


def recheck_files(file_records):
    for source, (real, source_state, target_state) in file_records.items():
        try:
            now_source = os.lstat(source)
            now_real = os.path.realpath(source)
            now_target = os.stat(now_real, follow_symlinks=True)
        except Exception:
            error()
        if now_real != real:
            error()
        if obj_state(now_source) != source_state or obj_state(now_target) != target_state:
            error()


def recheck_parents(parent_records):
    for path, expected in parent_records.items():
        try:
            now = os.stat(path, follow_symlinks=True)
        except Exception:
            error()
        if not stat.S_ISDIR(now.st_mode) or obj_state(now) != expected:
            error()


def recheck_processes(process_records, excluded_records):
    for pid_name, record in process_records.items():
        expected_start, expected_target, expected_exe_state, expected_maps = record
        pid = proc_root / pid_name
        start = read_start(pid)
        if start is None or start != expected_start:
            error()
        current_exe = read_exe(pid)
        if current_exe is None:
            error()
        target, exe_state = current_exe
        if target != expected_target or exe_state != expected_exe_state:
            error()
        current_maps = tuple(parse_maps(pid))
        if current_maps != expected_maps:
            error()
        end = read_start(pid)
        if end is None or end != expected_start:
            error()

    for pid_name, expected_start in excluded_records.items():
        pid = proc_root / pid_name
        start = read_start(pid)
        if start is None or start != expected_start:
            error()
        if read_exe(pid) is not None:
            error()
        classify_no_exe(pid, expected_start)


try:
    pst = os.lstat(proc_root)
except Exception:
    error()
if not stat.S_ISDIR(pst.st_mode) or stat.S_ISLNK(pst.st_mode):
    error()
try:
    sst = os.stat(parent_stop)
except Exception:
    error()
if not stat.S_ISDIR(sst.st_mode):
    error()

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
        error()

    exe_observation = read_exe(pid)
    if exe_observation is None:
        classify_no_exe(pid, expected_start)
        excluded_records[pid_name] = expected_start
        excluded += 1
        continue

    target, exe_state = exe_observation
    exe_identity = check_path(target, file_records, file_states, parent_records, path_set)
    if (exe_state[0], exe_state[1]) != exe_identity:
        error()

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
        error()

    process_records[pid_name] = (expected_start, target, exe_state, mapped_records)
    processes += 1
    libraries_seen += len(mapped_ids - {exe_identity})

if processes == 0 or not file_states:
    error()

mid_population = population_snapshot()
if mid_population != initial_population:
    error()
if read_process_counter() != fork_counter:
    error()

recheck_processes(process_records, excluded_records)
recheck_files(file_records)
recheck_parents(parent_records)

final_population = population_snapshot()
if final_population != initial_population:
    error()
if read_process_counter() != fork_counter:
    error()

file_violations = sum(1 for state in file_states.values() if state[4] & 0o022)
parent_violations = 0
for state in parent_records.values():
    uid, mode = state[2], state[4]
    if mode & 0o022:
        parent_violations += 1
    elif uid != 0 and mode & 0o200:
        parent_violations += 1

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
  if (( _slp_rc != 0 )) || [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "-" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' "ERROR" "-" "ERROR"
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


def error():
    print("ERROR")
    raise SystemExit(0)


def map_abs(path_text):
    if not isinstance(path_text, str) or not path_text.startswith("/") or "\x00" in path_text or "\r" in path_text or "\n" in path_text:
        error()
    return fsroot / path_text.lstrip("/")


def obj_state(st):
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)


def stable_regular(path, allow_symlink=False):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        return None
    except Exception:
        error()
    if stat.S_ISLNK(first.st_mode):
        if not allow_symlink:
            error()
        try:
            real = os.path.realpath(path)
            target = os.stat(real, follow_symlinks=True)
            second = os.lstat(path)
        except Exception:
            error()
        if obj_state(first) != obj_state(second) or not stat.S_ISREG(target.st_mode):
            error()
        return (str(path), real, obj_state(first), obj_state(target))
    if not stat.S_ISREG(first.st_mode):
        error()
    try:
        second = os.lstat(path)
    except Exception:
        error()
    if obj_state(first) != obj_state(second):
        error()
    return (str(path), str(path), obj_state(first), obj_state(first))


def stable_text(path, optional=False, allow_symlink=False):
    rec = stable_regular(path, allow_symlink=allow_symlink)
    if rec is None:
        if optional:
            return None
        error()
    try:
        raw = path.read_bytes()
        after = stable_regular(path, allow_symlink=allow_symlink)
    except Exception:
        error()
    if after != rec or b"\x00" in raw or b"\r" in raw:
        error()
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        error()
    return rec, hashlib.sha256(raw).hexdigest(), text


def stable_dir(path, optional=False):
    try:
        first = os.lstat(path)
    except FileNotFoundError:
        if optional:
            return None
        error()
    except Exception:
        error()
    if stat.S_ISLNK(first.st_mode) or not stat.S_ISDIR(first.st_mode):
        error()
    try:
        names = sorted(os.listdir(path), key=os.fsencode)
        second = os.lstat(path)
    except Exception:
        error()
    if obj_state(first) != obj_state(second):
        error()
    return obj_state(first), tuple(names)


def parse_passwd():
    observed = stable_text(map_abs("/etc/passwd"), optional=False)
    users = {}
    for line in observed[2].splitlines():
        if not line:
            error()
        parts = line.split(":")
        if len(parts) != 7:
            error()
        name, _, uid_text, gid_text, _, home, _ = parts
        if not name or name in users or ASCII_DECIMAL.fullmatch(uid_text) is None or ASCII_DECIMAL.fullmatch(gid_text) is None:
            error()
        if not home.startswith("/"):
            error()
        users[name] = (int(uid_text), int(gid_text), home)
    if "root" not in users or users["root"][0] != 0:
        error()
    return observed, users


def parse_env_value(raw):
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    if any(ch in value for ch in "\x00\r\n`$"):
        error()
    return value


def parse_path_value(raw):
    value = parse_env_value(raw)
    parts = value.split(":")
    if not parts or any(not p.startswith("/") or p == "/" and False for p in parts) or any(p == "" for p in parts):
        error()
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
        error()
    return result


def cron_job(line, system_file, owner_user, users):
    parts = line.split()
    if not parts:
        error()
    if parts[0].startswith("@"):
        if parts[0] not in SPECIAL:
            error()
        needed = 3 if system_file else 2
        if len(parts) < needed:
            error()
        user = parts[1] if system_file else owner_user
        command = line.split(None, 2 if system_file else 1)[2 if system_file else 1]
    else:
        if len(parts) < (7 if system_file else 6):
            error()
        for field in parts[:5]:
            if SCHEDULE_FIELD.fullmatch(field) is None:
                error()
        user = parts[5] if system_file else owner_user
        command = line.split(None, 6 if system_file else 5)[6 if system_file else 5]
    if user not in users:
        error()
    return user, split_percent(command)


def lex_command(command):
    if any(ch in command for ch in "\x00\r\n`$"):
        error()
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except Exception:
        error()
    if not tokens:
        error()
    for tok in tokens:
        if "<" in tok or ">" in tok:
            error()
    return tokens


def resolve_root_command(word, path_env, uid, dir_records):
    if "/" in word:
        if not word.startswith("/"):
            error()
        return word
    if uid != 0 or path_env is None:
        error()
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
            error()
        if stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) & 0o111:
            return candidate_text
    error()


def resolved_command_record(path_text):
    mapped = map_abs(path_text)
    rec = stable_regular(mapped, allow_symlink=True)
    if rec is None:
        error()
    target_state = rec[3]
    if target_state[8] != 1:
        error()
    if (target_state[4] & 0o111) == 0:
        error()
    canonical_base = os.path.basename(rec[1])
    if not canonical_base or canonical_base in {".", ".."}:
        error()
    return rec, canonical_base


def add_target(path_text, targets, allow_nonexec=False):
    mapped = map_abs(path_text)
    rec = stable_regular(mapped, allow_symlink=True)
    if rec is None:
        error()
    target_state = rec[3]
    if not allow_nonexec and (target_state[4] & 0o111) == 0:
        error()
    previous = targets.get(path_text)
    if previous is not None and previous != rec:
        error()
    targets[path_text] = rec


def expand_run_parts(args, targets, dir_records):
    directory = None
    for arg in args:
        if arg in {"--report", "--verbose"}:
            continue
        if arg.startswith("-"):
            error()
        if directory is not None:
            error()
        directory = arg
    if directory is None or not directory.startswith("/"):
        error()
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
            error()
        except Exception:
            error()
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
                error()
            depth += 1
            continue
        if tok == ")":
            if current:
                segments.append(current); current = []
            depth -= 1
            if depth < 0:
                error()
            continue
        if tok in CONTROL_OPS:
            if tok in {"(", ")"}:
                error()
            if current:
                segments.append(current); current = []
            continue
        current.append(tok)
    if current:
        segments.append(current)
    if depth != 0 or not segments:
        error()

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
            error()
        resolved = resolve_root_command(command_word, local_path, uid, dir_records)
        _resolved_rec, canonical_base = resolved_command_record(resolved)
        if canonical_base in UNSUPPORTED_COMMANDS or INTERPRETER_NAME.fullmatch(canonical_base) is not None:
            error()
        add_target(resolved, targets, allow_nonexec=False)
        if canonical_base == "run-parts":
            expand_run_parts(args, targets, dir_records)


def parse_crontab(path, system_file, owner_user, users, sources, targets, dir_records):
    observed = stable_text(path, optional=False, allow_symlink=False)
    if observed[2] and not observed[2].endswith("\n"):
        error()
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
                error()
            if name == "PATH":
                path_env = parse_path_value(value)
            elif name == "SHELL":
                if parse_env_value(value) != "/bin/sh":
                    error()
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
                error()
            st = os.stat(cfg, follow_symlinks=False)
            if st.st_uid != logical_root_uid or stat.S_IMODE(st.st_mode) & 0o022:
                error()
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
                error()
            st = os.stat(cfg, follow_symlinks=False)
            if st.st_uid != users[name][0] or stat.S_IMODE(st.st_mode) & 0o022:
                error()
            jobs += parse_crontab(cfg, False, name, users, sources, targets, dir_records)
            configs += 1

    violations = sum(1 for rec in targets.values() if rec[3][4] & 0o022)
    periodic = sum(1 for key in dir_records if key[0] == "run-parts")
    return sources, targets, dir_records, configs, jobs, periodic, violations


try:
    rst = os.lstat(fsroot)
except Exception:
    error()
if stat.S_ISLNK(rst.st_mode) or not stat.S_ISDIR(rst.st_mode):
    error()

first = discover()
second = discover()
if first != second:
    error()
_, targets, _, configs, jobs, periodic, violations = first
value = f"configs={configs};jobs={jobs};targets={len(targets)};periodic_dirs={periodic};violations={violations};ambiguous=0"
print("VALUE\t" + value + "\t" + ("PASS" if violations == 0 else "FAIL"))
SLP_CRON_PATHS_PY
  )
  _slp_rc=$?
  if (( _slp_rc != 0 )) || [[ -z $_slp_obs || $_slp_obs == *$'\n'* || $_slp_obs == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_obs == ERROR ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "-" "ERROR"
    return 0
  fi
  IFS=$'\t' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< "$_slp_obs"
  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "ERROR" "-" "ERROR"
    return 0
  fi
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' "VALUE" "$_slp_value" "$_slp_compliance"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_3_6_CRON_D() {
  local _slp_path='/etc/cron.d'
  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker
  local _slp_type _slp_find_rc _slp_sort_rc
  local _slp_checked=0 _slp_violations=0 _slp_i
  local -a _slp_entries=()
  if [[ -L "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ -d "$_slp_parent" && -x "$_slp_parent" && ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" || -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-D' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ -d "$_slp_parent" && -x "$_slp_parent" && ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" || -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ -d "$_slp_parent" && -x "$_slp_parent" && ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" || -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ -d "$_slp_parent" && -x "$_slp_parent" && ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" || -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ -d "$_slp_parent" && -x "$_slp_parent" && ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" || -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! -e "$_slp_path" ]]; then
    _slp_parent=${_slp_path%/*}
    [[ -n $_slp_parent ]] || _slp_parent=/
    if [[ -d "$_slp_parent" && -x "$_slp_parent" && ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "VALUE" "<absent>" "PASS"
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
    fi
    return 0
  fi
  if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
    return 0
  fi
  ((_slp_checked+=1))
  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
  if [[ -f "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
    return 0
  fi
  if [[ ! -d "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
    return 0
  fi
  mapfile -d '' -t _slp_entries < <(
    LC_ALL=C command /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
    printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
  )
  if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_i=$((${#_slp_entries[@]}-1))
  _slp_scan_marker=${_slp_entries[$_slp_i]}
  unset '_slp_entries[$_slp_i]'
  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_find_rc=${BASH_REMATCH[1]}
  _slp_sort_rc=${BASH_REMATCH[2]}
  if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
    return 0
  fi
  for _slp_entry in "${_slp_entries[@]}"; do
    if [[ -L "$_slp_entry" || -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' "ERROR" "-" "ERROR"
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
  local -a _slp_roots=('/var/spool/cron' '/var/spool/cron/crontabs') _slp_entries=()
  local -A _slp_seen=()
  for _slp_root in "${_slp_roots[@]}"; do
    if [[ -L "$_slp_root" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ! -e "$_slp_root" ]]; then
      _slp_probe=$_slp_root
      while [[ $_slp_probe != / && ! -e "$_slp_probe" && ! -L "$_slp_probe" ]]; do
        _slp_probe=${_slp_probe%/*}
        [[ -n $_slp_probe ]] || _slp_probe=/
      done
      if [[ -L "$_slp_probe" || ! -d "$_slp_probe" || ! -x "$_slp_probe" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      ((_slp_roots_absent+=1))
      continue
    fi
    if [[ ! -d "$_slp_root" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    ((_slp_roots_present+=1))
    _slp_entries=()
    mapfile -d '' -t _slp_entries < <(
      LC_ALL=C command /usr/bin/find -P -- "$_slp_root" -mindepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z
      _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"
      printf "__SLP_SCAN_RC=%s\0" "$_slp_scan_marker"
    )
    if (( ${#_slp_entries[@]} == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_i=$((${#_slp_entries[@]}-1))
    _slp_scan_marker=${_slp_entries[$_slp_i]}
    unset '_slp_entries[$_slp_i]'
    if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_find_rc=${BASH_REMATCH[1]}
    _slp_sort_rc=${BASH_REMATCH[2]}
    if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    for _slp_entry in "${_slp_entries[@]}"; do
      if [[ ${_slp_seen["$_slp_entry"]+x} ]]; then continue; fi
      _slp_seen["$_slp_entry"]=1
      if [[ -L "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ -d "$_slp_entry" ]]; then continue; fi
      if [[ ! -f "$_slp_entry" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' "ERROR" "-" "ERROR"
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
  local _slp_find_rc _slp_sort_rc _slp_i _slp_uname_r=''
  local _slp_roots_present=0 _slp_roots_absent=0 _slp_aliases=0
  local _slp_exec=0 _slp_libraries=0 _slp_modules=0 _slp_checked=0 _slp_violations=0
  local -a _slp_exec_roots=('/bin' '/sbin' '/usr/bin' '/usr/sbin') _slp_lib_roots=('/lib' '/lib64' '/usr/lib' '/usr/lib64') _slp_entries=()
  local _slp_module_root='/lib/modules/<uname-r>'
  local -A _slp_seen_roots=() _slp_seen_targets=()
  if ! _slp_uname_r=$(command /usr/bin/uname -r 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ -z $_slp_uname_r || $_slp_uname_r == *$'\n'* || $_slp_uname_r == *$'\r'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ -z $_slp_resolved || ! -d "$_slp_resolved" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if ! _slp_root_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_resolved" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      _slp_i=$((${#_slp_entries[@]}-1))
      _slp_scan_marker=${_slp_entries[$_slp_i]}
      unset '_slp_entries[$_slp_i]'
      if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      _slp_find_rc=${BASH_REMATCH[1]}
      _slp_sort_rc=${BASH_REMATCH[2]}
      if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
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
        case "$_slp_role" in
          exec) ((_slp_exec+=1)) ;;
          lib) ((_slp_libraries+=1)) ;;
          module) ((_slp_modules+=1)) ;;
        esac
        if [[ -L "$_slp_entry" ]]; then
          if ! _slp_target=$(command /usr/bin/readlink -f -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
            return 0
          fi
          if [[ -z $_slp_target || ! -f "$_slp_target" || -L "$_slp_target" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
            return 0
          fi
        elif [[ -f "$_slp_entry" ]]; then
          _slp_target=$_slp_entry
        else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
          return 0
        fi
        if ! _slp_ident=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_target" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
          return 0
        fi
        if [[ ${_slp_seen_targets["$_slp_ident"]+x} ]]; then continue; fi
        _slp_seen_targets["$_slp_ident"]=1
        if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc %a -- "$_slp_target" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
          return 0
        fi
        if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
          return 0
        fi
        ((_slp_checked+=1))
        if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
      done
    done
  done
  if (( _slp_exec == 0 || _slp_libraries == 0 || _slp_modules == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
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

  if [[ ! -f "$_slp_mountinfo" || -L "$_slp_mountinfo" || ! -r "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
    return 0
  fi
  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_mountinfo" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ "$_slp_hex" =~ (^|[[:space:]])00([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
    return 0
  fi
  local _slp_allowlist="$_slp_expected" _slp_allow_line
  if [[ "$_slp_allowlist" != /* || ! -f "$_slp_allowlist" || -L "$_slp_allowlist" || ! -r "$_slp_allowlist" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
    return 0
  fi
  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_allowlist" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ "$_slp_hex" =~ (^|[[:space:]])00([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
    return 0
  fi
  while IFS= read -r _slp_allow_line || [[ -n "$_slp_allow_line" ]]; do
    if [[ "$_slp_allow_line" == *$'\r'* || "$_slp_allow_line" == *$'\t'* || "$_slp_allow_line" == *$'\n'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
      return 0
    fi
    [[ -z "$_slp_allow_line" || "${_slp_allow_line:0:1}" == "#" ]] && continue
    if [[ "$_slp_allow_line" != /* || ${_slp_allowed["$_slp_allow_line"]+x} ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_allowed["$_slp_allow_line"]=1
  done < "$_slp_allowlist"
  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    ((_slp_lineno+=1))
    [[ -n "$_slp_line" ]] || continue
    IFS=" " read -r _slp_id _slp_parent _slp_majmin _slp_root _slp_mp_raw _slp_opts _slp_tail <<< "$_slp_line"
    if [[ -z "$_slp_id" || -z "$_slp_parent" || -z "$_slp_majmin" || -z "$_slp_root" || -z "$_slp_mp_raw" || -z "$_slp_opts" || -z "$_slp_tail" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ "$_slp_tail" == "- "* ]]; then
      _slp_after=${_slp_tail#- }
    elif [[ "$_slp_tail" == *" - "* ]]; then
      _slp_after=${_slp_tail#*" - "}
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_fstype=${_slp_after%% *}
    [[ -n "$_slp_fstype" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"; return 0; }
    case "$_slp_fstype" in
      proc|sysfs|devtmpfs|devpts|cgroup|cgroup2|securityfs|pstore|bpf|tracefs|debugfs|configfs|fusectl|mqueue|hugetlbfs|ramfs|autofs|binfmt_misc|nsfs|efivarfs) continue ;;
    esac
    case ",$_slp_opts," in *,nosuid,*) continue ;; esac
    printf -v _slp_mp "%b" "$_slp_mp_raw"
    if [[ "$_slp_mp" != /* || "$_slp_mp" == *$'\r'* || "$_slp_mp" == *$'\n'* || "$_slp_mp" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_mp" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_root_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_mp" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_i=$((${#_slp_entries[@]}-1))
    _slp_marker=${_slp_entries[$_slp_i]}
    unset '_slp_entries[$_slp_i]'
    if [[ ! "$_slp_marker" =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_find_rc=${BASH_REMATCH[1]}
    _slp_sort_rc=${BASH_REMATCH[2]}
    if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
      return 0
    fi
    for _slp_entry in "${_slp_entries[@]}"; do
      if [[ "$_slp_entry" == *$'\r'* || "$_slp_entry" == *$'\n'* || "$_slp_entry" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
        return 0
      fi
      if ! _slp_ident=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ ${_slp_seen_files["$_slp_ident"]+x} ]]; then continue; fi
      _slp_seen_files["$_slp_ident"]=1
      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ ! "$_slp_mode" =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
        return 0
      fi
      ((_slp_checked+=1))
      if [[ ! ${_slp_allowed["$_slp_entry"]+x} ]]; then ((_slp_extras+=1)); fi
    done
  done < "$_slp_mountinfo"
  if (( _slp_mounts == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
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

  if [[ ! -f "$_slp_mountinfo" || -L "$_slp_mountinfo" || ! -r "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_mountinfo" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ "$_slp_hex" =~ (^|[[:space:]])00([[:space:]]|$) ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do
    ((_slp_lineno+=1))
    [[ -n "$_slp_line" ]] || continue
    IFS=" " read -r _slp_id _slp_parent _slp_majmin _slp_root _slp_mp_raw _slp_opts _slp_tail <<< "$_slp_line"
    if [[ -z "$_slp_id" || -z "$_slp_parent" || -z "$_slp_majmin" || -z "$_slp_root" || -z "$_slp_mp_raw" || -z "$_slp_opts" || -z "$_slp_tail" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ "$_slp_tail" == "- "* ]]; then
      _slp_after=${_slp_tail#- }
    elif [[ "$_slp_tail" == *" - "* ]]; then
      _slp_after=${_slp_tail#*" - "}
    else
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_fstype=${_slp_after%% *}
    [[ -n "$_slp_fstype" ]] || { printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"; return 0; }
    case "$_slp_fstype" in
      proc|sysfs|devtmpfs|devpts|cgroup|cgroup2|securityfs|pstore|bpf|tracefs|debugfs|configfs|fusectl|mqueue|hugetlbfs|ramfs|autofs|binfmt_misc|nsfs|efivarfs) continue ;;
    esac
    case ",$_slp_opts," in *,nosuid,*) continue ;; esac
    printf -v _slp_mp "%b" "$_slp_mp_raw"
    if [[ "$_slp_mp" != /* || "$_slp_mp" == *$'\r'* || "$_slp_mp" == *$'\n'* || "$_slp_mp" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ! -d "$_slp_mp" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if ! _slp_root_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_mp" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_i=$((${#_slp_entries[@]}-1))
    _slp_marker=${_slp_entries[$_slp_i]}
    unset '_slp_entries[$_slp_i]'
    if [[ ! "$_slp_marker" =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    _slp_find_rc=${BASH_REMATCH[1]}
    _slp_sort_rc=${BASH_REMATCH[2]}
    if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    for _slp_entry in "${_slp_entries[@]}"; do
      if [[ "$_slp_entry" == *$'\r'* || "$_slp_entry" == *$'\n'* || "$_slp_entry" == *$'\t'* ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if ! _slp_ident=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ ${_slp_seen_files["$_slp_ident"]+x} ]]; then continue; fi
      _slp_seen_files["$_slp_ident"]=1
      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ ! "$_slp_mode" =~ ^[0-7]{3,4}$ ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      ((_slp_checked+=1))
      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi
    done
  done < "$_slp_mountinfo"
  if (( _slp_mounts == 0 )); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
  local _slp_value="mounts=$_slp_mounts;checked=$_slp_checked;violations=$_slp_violations"
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"
  return 0
}

slp_check_FSTEC_LINUX_2022_2_4_1_DMESG_RESTRICT() {
  local _slp_path='/proc/sys/kernel/dmesg_restrict'
  local _slp_expected='1'
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp
  local _slp_bare=0 _slp_values=0 _slp_conflict=0
  local -a _slp_tokens=() _slp_choices=()
  if [[ ! -e "$_slp_path" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "-" "ERROR"
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
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.5.9-TSX' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' "ERROR" "-" "ERROR"
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
  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp
  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd
  if [[ ! -e "$_slp_path" ]]; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "NOT_FOUND" "-" "NOT_FOUND"
    return 0
  fi
  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then
    _slp_num=${BASH_REMATCH[1]}
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "-" "ERROR"
    return 0
  fi
  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then
    _slp_value=0
  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then
    _slp_sign=${BASH_REMATCH[1]}
    _slp_digits=${BASH_REMATCH[3]}
    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi
  else
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "ERROR" "-" "ERROR"
    return 0
  fi
  _slp_comp=FAIL
  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE' "VALUE" "$_slp_value" "$_slp_comp"
  return 0
}

slp_target_preflight() {
  local _slp_id='' _slp_version='' _slp_arch='' _slp_k _slp_v
  if [[ ! -r /etc/os-release ]]; then
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  fi
  while IFS='=' read -r _slp_k _slp_v; do
    case "$_slp_k" in
      ID)
        _slp_v=${_slp_v#\"}
        _slp_v=${_slp_v%\"}
        _slp_id=$_slp_v
        ;;
      VERSION_ID)
        _slp_v=${_slp_v#\"}
        _slp_v=${_slp_v%\"}
        _slp_version=$_slp_v
        ;;
    esac
  done < /etc/os-release
  _slp_arch=$(command /usr/bin/uname -m 2>/dev/null) || {
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  }
  if [[ $_slp_id != ubuntu || $_slp_version != 24.04 || $_slp_arch != x86_64 ]]; then
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  fi
  return 0
}

slp_provenance_all() {
  cat <<'SLP_PROVENANCE_EOF'
{"adapter_contract_sha256":"461a96c3fa8f0ebe0e2684bed109576eda536a2f260902c8ce516cddd2043648","adapter_id":"product-local-account-password-state-check-v1","adapter_implementation_sha256":"f92af716622ef9ef5c9463e0496a4d5cb636729a087fd8520a89a5d0e6cc6a47","control_id":"FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"82d8121586664ee803efec1f1b4bb93a248ce1f302bdf90a2561468ead86d802","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"all-nonempty","expected_type":"boolean","expected_value":true,"index_id":"SRC-0001","parameter_key":"password-field","parameter_kind":"local-account-password-state","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"2dbfb302061eab4d698dd5c74c15132ca92d0fd8f98808582986dbe8cd4c2cb1","source_locator":"2.1.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"b66f2500e094932542f3506cf2da99145c805abcf0e8f9e17e8f0fee8cbbb892","adapter_id":"product-sshd-root-login-check-v1","adapter_implementation_sha256":"36038293e506b3c3c6b62f90756b44548044c26617bcebec1886a7f3de43b342","control_id":"FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"2f965f6e8901380f14088a167c77b07fc3b4c1872ac1f38865ba0a236a80b1de","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0002","parameter_key":"PermitRootLogin","parameter_kind":"sshd-root-login","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c671457700fd0fc656b34ccab9796a6b3b31a304492a26c3f317f0279e753785","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"db8f1a56bb13c28cb0fb77eafdbeeac3ccd7439ae11df34a65e1c24ec7c0c6ba","source_locator":"2.1.2","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"b5dc703267bf6c3ca0488138d92ce3046fd67e547f4e29bd49fbefcbd61c64f2","adapter_id":"product-pam-wheel-access-check-v1","adapter_implementation_sha256":"6c8c83d5191eb0787ed89bba77b993ae8697c5b166970fb852fc047fddad6631","control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"5259fa5c65b8ec5e55a1d28840266460b2bfa47ae40e95e601908f1c81719f66","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq-authority-file","expected_type":"string","expected_value":"/etc/securelinux-policy/wheel-users.allowlist-v1","index_id":"SRC-0003","parameter_key":"policy","parameter_kind":"pam-wheel-access","parameter_locator":"/etc/pam.d/su|/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"25dd0790262b44e6c787ec36df8c1aabb8b2f8f3e50d6c9bed83285c50c64c62","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"93a0e24dee2f88e59be813d94e8e65f9f5a31576e335b5966327cb3260eb1de2","source_locator":"2.2.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"c4aa130536c6b10ad70939f8f9be8e9dc9ce8cb4bbbdca1a67ea4f4d6301b248","adapter_id":"product-sudoers-reviewed-policy-check-v1","adapter_implementation_sha256":"5476dbc0be9cce163981e21b80eb7b9c96e9d8464771f9efab0c1b644f93fca6","control_id":"FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"117faacf555065fcedc311b32cb852d3d9150c60eec60eccec71f37df60ebc3d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq-reviewed-policy","expected_type":"string","expected_value":"/etc/securelinux-policy/sudoers-reviewed-policy-v1","index_id":"SRC-0004","parameter_key":"policy-tree","parameter_kind":"sudoers-reviewed-policy","parameter_locator":"/etc/sudoers","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"779597efe81ae7d291d2b7b0883cffb5af1a56f0234919b0243f360e688babea","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"f067dc99a5756351b50d71d2915c647307027d6f7a0a25f7209578a713f9b750","source_locator":"2.2.2","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"aab39b925d1e92b6fe427e50e7545736b47945e6cc9265d8fa7b4cb0029a0020","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"8df7c4922cf2b6a79bbcfa23afedb3ffd75343108fd5f373083238c237d260fe","control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"719123c6ab9e5a26bd261a67aa2340ad1cf388ca3749db9c05b23f3079584a81","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"aab39b925d1e92b6fe427e50e7545736b47945e6cc9265d8fa7b4cb0029a0020","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"8df7c4922cf2b6a79bbcfa23afedb3ffd75343108fd5f373083238c237d260fe","control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"93faa0e6920c07e2f8e12b8326131e9dc52cf9b6145eafda75943d0eef1278b1","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/passwd","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"aab39b925d1e92b6fe427e50e7545736b47945e6cc9265d8fa7b4cb0029a0020","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"8df7c4922cf2b6a79bbcfa23afedb3ffd75343108fd5f373083238c237d260fe","control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"62efde1e39f219e843193c7bc5a2d539d685ab79c33094c05a70e3d21873e03f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"2d8f6c23e9dad2e9344db67cd45de1e48c62a71665f300fbb7907be004d6ccf0","adapter_id":"product-home-sensitive-files-mode-check-v1","adapter_implementation_sha256":"6ba96a888e40d4fe0ce24ea46611207301013f6f3fbeda30fa1c23d4b4e9265f","control_id":"FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"1343b6983ddfff62222a03db98023417abbe8ad9c4236a67231debac09793aed","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0014","parameter_key":"mode","parameter_kind":"home-sensitive-files-mode","parameter_locator":"/etc/passwd|/etc/login.defs|/etc/securelinux-policy/home-sensitive-files-v1","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"ff17e541191574a1ba2a03add49087851679f3e37aed3d9e4bf5f6886c9bd894","source_locator":"2.3.10","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"1f30c66df70df87619fc37e3f4be60c28ae325369701466a3e2d6cbb2dc49c98","adapter_id":"product-home-directories-mode-check-v1","adapter_implementation_sha256":"e1724ab6c5f7dfe046effc16be48e03b227de810cb86e271736dd9df38afd1ce","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"ac070436aa49c1b78cc45972d1fdb41bb8462c4c40c5fcb26ec814ee45f84aed","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","parameter_key":"mode","parameter_kind":"home-directories-mode","parameter_locator":"/etc/passwd|/etc/login.defs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"a8592300ca57892e95b8efc38cc478b2034b3971f50e0e2a58bd520c772d94e3","source_locator":"2.3.11","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"95ef77bb04aa3a8c535f7050f788cd4cba923081fe6944550cb8049308955dd5","adapter_id":"product-running-process-paths-write-protection-check-v1","adapter_implementation_sha256":"33975181554c43e312ef207d9afd9660f83434e096f93dd8e226ca2614fa11e7","control_id":"FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"4c622265a9397061ef2edd2f99b6f90f78bf80aef8390f1cf129d8858daf76b3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"runtime-paths-safe","expected_type":"string","expected_value":"file-go-w;parent-unprivileged-write-denied","index_id":"SRC-0006","parameter_key":"write-protection","parameter_kind":"running-process-paths-write-protection","parameter_locator":"/proc/<pid>/exe|/proc/<pid>/maps","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f395bcd1e9dd9648161d6eac735f2b616c59c12e3d57a7cb1e9203cae2834aa5","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"1a3b0522124c2e5ffe07e0f53adcc6421d84b651fec89cc1cd6c800f7a10edaf","source_locator":"2.3.2","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"7373f3df058b88b20cdb50d3aaf7e26a6697ac116452bd18c334b56dfadf2c0c","adapter_id":"product-cron-command-paths-write-protection-check-v1","adapter_implementation_sha256":"5da2f01e2094983a7f278697585b506cd885768a97751ca0a453738b7e4a877b","control_id":"FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"aaab15a2454a7de6c5560aff10e367170706c6f47e6c5f879e46abe4fe9d6343","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"cron-command-paths-safe","expected_type":"string","expected_value":"file-go-w","index_id":"SRC-0007","parameter_key":"write-protection","parameter_kind":"cron-command-paths-write-protection","parameter_locator":"/etc/crontab|/etc/cron.d|/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"87a3b8a9ab953c58d4b04024444d5654019d1036eb0b424ddb3a87f621e68a7a","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"b937ecd625c94cdf83b980ee7150c014f45f41a21c8dd5e297589782eb1e65fa","source_locator":"2.3.3","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"d1dd9b4af5c49732ec93ac350d82fb138cb1fdc967396dda25062d59ff77527a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.d","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"a6c928414a1091aa8bf7291eee2e7574c9ad5f204831930d39a8536700f1731a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.daily","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"882eec0779eac5f5942f10e6670b2812f8000bf8f3e7600ba1c264362a8f4dce","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.hourly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"ca59fb02687823c843038099bd5698d42cd7d3cd402a22b4f0126bd89da42433","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.monthly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"62383ceb2d82745bdfeee36b424136c351b12d17ba430bf48b1706338a7c35e5","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.weekly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"043329e8aff8fa44762e5a2a22f6688c03bd30399dc78acb30821748d81d4fda","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/crontab","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"70af46d412c8970446a8e77112d9740c72303766ee4c9cfc2f18e440f5c60a33","adapter_id":"product-user-cron-files-mode-check-v1","adapter_implementation_sha256":"a27b80ec8e0320e03ee072de6a2ee2351202c518daf9e6a7ead115ce74f820b1","control_id":"FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"9ec427f2f8fe4fd76ae91e4a0b276a98eddf2c95949feca8a43035008f575360","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0011","parameter_key":"mode","parameter_kind":"user-cron-files-mode","parameter_locator":"/var/spool/cron|/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"af9430a9911e812b6f4b9735f35554d02e4203f7c39a3cae3d1c03004eb9adbe","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"81e008a5ecc0e451679b4b7bacf25d2c2de365c4cd4573db801009f926559ea3","source_locator":"2.3.7","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"64a315c7702579b77cb63885a62a3aca3daf5395c4e50b37e2ab6823c1b0928e","adapter_id":"product-standard-system-paths-mode-check-v1","adapter_implementation_sha256":"0b5e8b974c08e1034715024cad87bb9aeb1850a76d5d7ffd7403fc41e4885bd2","control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"ba4c3310e62afdb05e7d3cba0f2ba086c77389574565d5f0d34abe3bd0e86962","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0012","parameter_key":"mode","parameter_kind":"standard-system-paths-mode","parameter_locator":"/bin|/sbin|/usr/bin|/usr/sbin|/lib|/lib64|/usr/lib|/usr/lib64|/lib/modules/<uname-r>","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c14203a718160e12100efac4e8e4f748cdf7517bba948d7ee66d8811f2e462e3","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"bc44b45c985fd83ce4d0dcd9c87d7f8add24ff57a6cf081040a7f9d7d605fe71","source_locator":"2.3.8","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"2bcb810ddbcd73c74672dd4abef974bcfab05e565b7eff3c9bcca66649ac65f8","adapter_id":"product-suid-sgid-applications-check-v1","adapter_implementation_sha256":"2c4210150e82d9c639e50e18687c47504bb8cd8e61e25a01f4f3aad6c4bd5553","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"f74216265e6cc6dba28028813d9bc7d39ca680aa601c20a64d453c637637b2ac","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"subset-of-file","expected_type":"string","expected_value":"/etc/securelinux-policy/suid-sgid.allowlist-v1","index_id":"SRC-0013","parameter_key":"approved-set","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"6a29a8da2e6376e271e29dabc9b505d10c7e317e0bbafd0b1bacafd120431c6c","source_locator":"2.3.9","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"2bcb810ddbcd73c74672dd4abef974bcfab05e565b7eff3c9bcca66649ac65f8","adapter_id":"product-suid-sgid-applications-check-v1","adapter_implementation_sha256":"2c4210150e82d9c639e50e18687c47504bb8cd8e61e25a01f4f3aad6c4bd5553","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"5e52002e72ea86d8c10dad28d09c82f0a027850ca4ae6e0d40745b7cdc33710b","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0013","parameter_key":"mode","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"6a29a8da2e6376e271e29dabc9b505d10c7e317e0bbafd0b1bacafd120431c6c","source_locator":"2.3.9","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"51f99ed4b7c67eb30558176685885337c27a4d8c2047a8e667059dd2bbff07d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0016","parameter_key":"kernel.dmesg_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c889161dc17ca0ec538a88477aeebfd920e8d10a53d34952e69b12b24338a5e6","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"ba25c49b237cf91b74afcda02e15fd872e81c08973abd9719a8f4c465513aa9a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0017","parameter_key":"kernel.kptr_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"a4c2ba6bc1c18e8cc9a3b025cbf55b542e9cf327e3ce69fd2d8e4877bbc3ef60","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.2","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"68b4a5d37e9addc54b6c8d9316e1a9e47e4eda7cb0683b2df99c4be911c7ea5c","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0018","parameter_key":"init_on_alloc","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.3","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"817ddc5844c8600b30ea82b013576e8c90fe4381f37ff2d3e6f697766881aa9e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"present","expected_type":"boolean","expected_value":true,"index_id":"SRC-0019","parameter_key":"slab_nomerge","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"6a5c7fa4c5804ef3c2e152c338da6c73553bb8bce5dbde0331e4ba4db09d8b6f","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.4","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"595da19602209ab601375e129f45dfa720038e5a5b92017e51b5b7873bd6233d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"force","index_id":"SRC-0020","parameter_key":"iommu","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"85b3d67e7f741cfd9d50b3d935bc96ac38d6468d44cb18465baefa3379242942","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0","index_id":"SRC-0020","parameter_key":"iommu.passthrough","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"0d68a6bb3b7869e9d76046d196e61511e34560cfb55cf130b30c65b3b9d3e629","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0020","parameter_key":"iommu.strict","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"876b71fa1a3eabed4455db496c576c43ec897ccfe335266ae707b9bb976f124e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0021","parameter_key":"randomize_kstack_offset","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"69cbdb70f31aadd134129cae9eb95a96f836168646a821927cc3ea56ea58c980","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"2d004e6effde058bcd8d5713b8116adec36af1476da6e4f5acb1553d7857d981","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"auto,nosmt","index_id":"SRC-0022","parameter_key":"mitigations","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"593127f71a130fb574410cc9b249cf9ce42c1ec9698ebad648c79c4554d55ceb","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.7","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"cfe64060a4d9829351c2c6f19c6f41b0e0697bd8be5b503a90ffe27a5f4c52ee","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0023","parameter_key":"net.core.bpf_jit_harden","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ffeec17a621afd4726e6c0fcf0aef4fb1e22c86f45ca20d1d568471675c3914f","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.8","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"611d219ec1d517ebceb3539968662a6e40a75bb028fc553ec18eb9a95544f413","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"none","index_id":"SRC-0024","parameter_key":"vsyscall","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"909ac7e3825f234cf325dac5b9615486ef4c856315aeb9c25d4b7a6af47fa421","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"f2733434c77fa39bec5210262632becd3f0aad65ddb7423c869725fe95fa5655","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"ge","expected_type":"integer","expected_value":4096,"index_id":"SRC-0033","parameter_key":"vm.mmap_min_addr","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.10","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"4a08a7bfd4f6a803dfb7bbc2486a83bd2fe1e877dcaa2e9938d402ee9765ee6d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0034","parameter_key":"kernel.randomize_va_space","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.11","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"b0eb7068712e20660c0d84871c271c6f3fdc542132cca1cf529910dcf7f85c0a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0025","parameter_key":"kernel.perf_event_paranoid","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8e6f4b120bd3527b380251e92eca56e1b4c358d362f1246357579eb8af616382","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.2","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"806da488a05c5d4ea11c2cef4bbde3b327387c1b96b143fe97c32e50e08a8894","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"one-of","expected_type":"string","expected_value":"off|no-mount","index_id":"SRC-0026","parameter_key":"debugfs","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"10391c151e6a53e91d637a11bc0f87a05a1ca7fdd408f9493dd27b366da46184","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.3","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"6006fdfb164b8a8860b8f4ae6d4e2758799f25ed32d53e185916da0ef0b7ed01","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0027","parameter_key":"kernel.kexec_load_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0231e3c8de27fab8de667f632bf6d08609a7c62836be9c787fd4cb955974ff09","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.4","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"b13b0e0b47c820d396a9a4a8d044ffdfc4eb779c5def2347c072cbc9e3900f32","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0028","parameter_key":"user.max_user_namespaces","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"77edbfb78e01426b6c40ccedca310ff6091870e235d4225ac488f4cd5d8c090c","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.5","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"44423cf2e57eabddd637a973430a6633282f8eba658430a1290bfa610efe5b67","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0029","parameter_key":"kernel.unprivileged_bpf_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"1c320abae9872972364ef95685204f4968a2c84bc27ee9c2707907eac8c5823e","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"3a5a2c1c560d688eeea441f4455297a86983c599745acf8963507f91b72c86f4","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0030","parameter_key":"vm.unprivileged_userfaultfd","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"cba35949a04f5d3dab8bd9a0501d75e5c310773ac11c1ad2c4d80845cdd03080","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.7","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"d6e4d8f63a5235ff32f3cb429c91caa7b7ff7864ba8ab90f8fd350362e8d3a69","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0031","parameter_key":"dev.tty.ldisc_autoload","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0860efcf66e2da819b06b5d6198e3b4c9b4ea96b66929752aceba65fae301783","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.8","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.9-TSX","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"07040e8445ac0565a587fcf6cfadf124a45b6b076592d4a268eff2abe37b5ef3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"off","index_id":"SRC-0032","parameter_key":"tsx","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"40b0ad985774f12adad55439e22a5ba29b3a2c50c9fedd16551fa261fd29464c","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.9","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"2bc9bb0cb5372fb5738612ff3738526cad9adb831b0043cc5924f36d23e7ca37","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0035","parameter_key":"kernel.yama.ptrace_scope","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"7be4210587e64fe1864bfbf1b5e8f7cc3512434629eb17898ad487d50a9ae246","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"b709581e94eb65e5a059d70ff4ec7aac7d248e6b664ffb42c502e23c88e2bbe8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0036","parameter_key":"fs.protected_symlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ce09b5104160f3fe27f17f1d5e57a5fe81001adac3c362ed652552ccbc59571f","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.2","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"fc1fd0f1141cb6d78b5d322e6a04b2649f0264a5e8c4784c64116bed55d70ffa","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0037","parameter_key":"fs.protected_hardlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"315736677a4e3192cde79d4badbf20809da81c8605785c8720fcd0fc3260fe97","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.3","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"af3b312efb3d252c1752a9ee70da6248e2a8e86f2e29479388206afbfbcd453d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0038","parameter_key":"fs.protected_fifos","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016aaaf884c10febb3e99a86acfcbe63eae04f05f5fcf35a00c59f03fb30a31b","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.4","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"677905dff8f0fa0db1c82008b7b3acc0456dd61c46db0008390ab99f89ef9d92","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0039","parameter_key":"fs.protected_regular","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0f1eea51ec98d254f230a48dfc4950cb060e11460e1f30be68fde3fb9439cb14","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.5","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"35c1fe8f6a4591fdf5b7d25f4dff6b244b868fbc1514498a7b55f9a321ddda8f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0040","parameter_key":"fs.suid_dumpable","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.6","target_id":"ubuntu-24.04-x86_64"}
SLP_PROVENANCE_EOF
}

slp_provenance_one() {
  case "$1" in
    'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE') printf '%s\n' '{"adapter_contract_sha256":"461a96c3fa8f0ebe0e2684bed109576eda536a2f260902c8ce516cddd2043648","adapter_id":"product-local-account-password-state-check-v1","adapter_implementation_sha256":"f92af716622ef9ef5c9463e0496a4d5cb636729a087fd8520a89a5d0e6cc6a47","control_id":"FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"82d8121586664ee803efec1f1b4bb93a248ce1f302bdf90a2561468ead86d802","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"all-nonempty","expected_type":"boolean","expected_value":true,"index_id":"SRC-0001","parameter_key":"password-field","parameter_kind":"local-account-password-state","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"2dbfb302061eab4d698dd5c74c15132ca92d0fd8f98808582986dbe8cd4c2cb1","source_locator":"2.1.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN') printf '%s\n' '{"adapter_contract_sha256":"b66f2500e094932542f3506cf2da99145c805abcf0e8f9e17e8f0fee8cbbb892","adapter_id":"product-sshd-root-login-check-v1","adapter_implementation_sha256":"36038293e506b3c3c6b62f90756b44548044c26617bcebec1886a7f3de43b342","control_id":"FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"2f965f6e8901380f14088a167c77b07fc3b4c1872ac1f38865ba0a236a80b1de","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"no","index_id":"SRC-0002","parameter_key":"PermitRootLogin","parameter_kind":"sshd-root-login","parameter_locator":"/etc/ssh/sshd_config","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c671457700fd0fc656b34ccab9796a6b3b31a304492a26c3f317f0279e753785","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"db8f1a56bb13c28cb0fb77eafdbeeac3ccd7439ae11df34a65e1c24ec7c0c6ba","source_locator":"2.1.2","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS') printf '%s\n' '{"adapter_contract_sha256":"b5dc703267bf6c3ca0488138d92ce3046fd67e547f4e29bd49fbefcbd61c64f2","adapter_id":"product-pam-wheel-access-check-v1","adapter_implementation_sha256":"6c8c83d5191eb0787ed89bba77b993ae8697c5b166970fb852fc047fddad6631","control_id":"FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"5259fa5c65b8ec5e55a1d28840266460b2bfa47ae40e95e601908f1c81719f66","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq-authority-file","expected_type":"string","expected_value":"/etc/securelinux-policy/wheel-users.allowlist-v1","index_id":"SRC-0003","parameter_key":"policy","parameter_kind":"pam-wheel-access","parameter_locator":"/etc/pam.d/su|/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"25dd0790262b44e6c787ec36df8c1aabb8b2f8f3e50d6c9bed83285c50c64c62","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"93a0e24dee2f88e59be813d94e8e65f9f5a31576e335b5966327cb3260eb1de2","source_locator":"2.2.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY') printf '%s\n' '{"adapter_contract_sha256":"c4aa130536c6b10ad70939f8f9be8e9dc9ce8cb4bbbdca1a67ea4f4d6301b248","adapter_id":"product-sudoers-reviewed-policy-check-v1","adapter_implementation_sha256":"5476dbc0be9cce163981e21b80eb7b9c96e9d8464771f9efab0c1b644f93fca6","control_id":"FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"117faacf555065fcedc311b32cb852d3d9150c60eec60eccec71f37df60ebc3d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq-reviewed-policy","expected_type":"string","expected_value":"/etc/securelinux-policy/sudoers-reviewed-policy-v1","index_id":"SRC-0004","parameter_key":"policy-tree","parameter_kind":"sudoers-reviewed-policy","parameter_locator":"/etc/sudoers","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"779597efe81ae7d291d2b7b0883cffb5af1a56f0234919b0243f360e688babea","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"f067dc99a5756351b50d71d2915c647307027d6f7a0a25f7209578a713f9b750","source_locator":"2.2.2","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.1-GROUP-MODE') printf '%s\n' '{"adapter_contract_sha256":"aab39b925d1e92b6fe427e50e7545736b47945e6cc9265d8fa7b4cb0029a0020","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"8df7c4922cf2b6a79bbcfa23afedb3ffd75343108fd5f373083238c237d260fe","control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"719123c6ab9e5a26bd261a67aa2340ad1cf388ca3749db9c05b23f3079584a81","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE') printf '%s\n' '{"adapter_contract_sha256":"aab39b925d1e92b6fe427e50e7545736b47945e6cc9265d8fa7b4cb0029a0020","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"8df7c4922cf2b6a79bbcfa23afedb3ffd75343108fd5f373083238c237d260fe","control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"93faa0e6920c07e2f8e12b8326131e9dc52cf9b6145eafda75943d0eef1278b1","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/passwd","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX') printf '%s\n' '{"adapter_contract_sha256":"aab39b925d1e92b6fe427e50e7545736b47945e6cc9265d8fa7b4cb0029a0020","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"8df7c4922cf2b6a79bbcfa23afedb3ffd75343108fd5f373083238c237d260fe","control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"62efde1e39f219e843193c7bc5a2d539d685ab79c33094c05a70e3d21873e03f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE') printf '%s\n' '{"adapter_contract_sha256":"2d8f6c23e9dad2e9344db67cd45de1e48c62a71665f300fbb7907be004d6ccf0","adapter_id":"product-home-sensitive-files-mode-check-v1","adapter_implementation_sha256":"6ba96a888e40d4fe0ce24ea46611207301013f6f3fbeda30fa1c23d4b4e9265f","control_id":"FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"1343b6983ddfff62222a03db98023417abbe8ad9c4236a67231debac09793aed","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0014","parameter_key":"mode","parameter_kind":"home-sensitive-files-mode","parameter_locator":"/etc/passwd|/etc/login.defs|/etc/securelinux-policy/home-sensitive-files-v1","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"ff17e541191574a1ba2a03add49087851679f3e37aed3d9e4bf5f6886c9bd894","source_locator":"2.3.10","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE') printf '%s\n' '{"adapter_contract_sha256":"1f30c66df70df87619fc37e3f4be60c28ae325369701466a3e2d6cbb2dc49c98","adapter_id":"product-home-directories-mode-check-v1","adapter_implementation_sha256":"e1724ab6c5f7dfe046effc16be48e03b227de810cb86e271736dd9df38afd1ce","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"ac070436aa49c1b78cc45972d1fdb41bb8462c4c40c5fcb26ec814ee45f84aed","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","parameter_key":"mode","parameter_kind":"home-directories-mode","parameter_locator":"/etc/passwd|/etc/login.defs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"a8592300ca57892e95b8efc38cc478b2034b3971f50e0e2a58bd520c772d94e3","source_locator":"2.3.11","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"95ef77bb04aa3a8c535f7050f788cd4cba923081fe6944550cb8049308955dd5","adapter_id":"product-running-process-paths-write-protection-check-v1","adapter_implementation_sha256":"33975181554c43e312ef207d9afd9660f83434e096f93dd8e226ca2614fa11e7","control_id":"FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"4c622265a9397061ef2edd2f99b6f90f78bf80aef8390f1cf129d8858daf76b3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"runtime-paths-safe","expected_type":"string","expected_value":"file-go-w;parent-unprivileged-write-denied","index_id":"SRC-0006","parameter_key":"write-protection","parameter_kind":"running-process-paths-write-protection","parameter_locator":"/proc/<pid>/exe|/proc/<pid>/maps","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f395bcd1e9dd9648161d6eac735f2b616c59c12e3d57a7cb1e9203cae2834aa5","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"1a3b0522124c2e5ffe07e0f53adcc6421d84b651fec89cc1cd6c800f7a10edaf","source_locator":"2.3.2","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION') printf '%s\n' '{"adapter_contract_sha256":"7373f3df058b88b20cdb50d3aaf7e26a6697ac116452bd18c334b56dfadf2c0c","adapter_id":"product-cron-command-paths-write-protection-check-v1","adapter_implementation_sha256":"5da2f01e2094983a7f278697585b506cd885768a97751ca0a453738b7e4a877b","control_id":"FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"aaab15a2454a7de6c5560aff10e367170706c6f47e6c5f879e46abe4fe9d6343","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"cron-command-paths-safe","expected_type":"string","expected_value":"file-go-w","index_id":"SRC-0007","parameter_key":"write-protection","parameter_kind":"cron-command-paths-write-protection","parameter_locator":"/etc/crontab|/etc/cron.d|/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"87a3b8a9ab953c58d4b04024444d5654019d1036eb0b424ddb3a87f621e68a7a","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"b937ecd625c94cdf83b980ee7150c014f45f41a21c8dd5e297589782eb1e65fa","source_locator":"2.3.3","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-D') printf '%s\n' '{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"d1dd9b4af5c49732ec93ac350d82fb138cb1fdc967396dda25062d59ff77527a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.d","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-DAILY') printf '%s\n' '{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"a6c928414a1091aa8bf7291eee2e7574c9ad5f204831930d39a8536700f1731a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.daily","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY') printf '%s\n' '{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"882eec0779eac5f5942f10e6670b2812f8000bf8f3e7600ba1c264362a8f4dce","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.hourly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY') printf '%s\n' '{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"ca59fb02687823c843038099bd5698d42cd7d3cd402a22b4f0126bd89da42433","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.monthly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY') printf '%s\n' '{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"62383ceb2d82745bdfeee36b424136c351b12d17ba430bf48b1706338a7c35e5","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.weekly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRONTAB') printf '%s\n' '{"adapter_contract_sha256":"73cd2d5455649917128a6e28405177648a2f8bb90fde9247babcc687955b1bb5","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"9cc727b05337da4cac52142238f64dbb8879a49b3823499ee304f9891e397a23","control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"043329e8aff8fa44762e5a2a22f6688c03bd30399dc78acb30821748d81d4fda","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/crontab","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE') printf '%s\n' '{"adapter_contract_sha256":"70af46d412c8970446a8e77112d9740c72303766ee4c9cfc2f18e440f5c60a33","adapter_id":"product-user-cron-files-mode-check-v1","adapter_implementation_sha256":"a27b80ec8e0320e03ee072de6a2ee2351202c518daf9e6a7ead115ce74f820b1","control_id":"FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"9ec427f2f8fe4fd76ae91e4a0b276a98eddf2c95949feca8a43035008f575360","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0011","parameter_key":"mode","parameter_kind":"user-cron-files-mode","parameter_locator":"/var/spool/cron|/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"af9430a9911e812b6f4b9735f35554d02e4203f7c39a3cae3d1c03004eb9adbe","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"81e008a5ecc0e451679b4b7bacf25d2c2de365c4cd4573db801009f926559ea3","source_locator":"2.3.7","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE') printf '%s\n' '{"adapter_contract_sha256":"64a315c7702579b77cb63885a62a3aca3daf5395c4e50b37e2ab6823c1b0928e","adapter_id":"product-standard-system-paths-mode-check-v1","adapter_implementation_sha256":"0b5e8b974c08e1034715024cad87bb9aeb1850a76d5d7ffd7403fc41e4885bd2","control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"ba4c3310e62afdb05e7d3cba0f2ba086c77389574565d5f0d34abe3bd0e86962","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0012","parameter_key":"mode","parameter_kind":"standard-system-paths-mode","parameter_locator":"/bin|/sbin|/usr/bin|/usr/sbin|/lib|/lib64|/usr/lib|/usr/lib64|/lib/modules/<uname-r>","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c14203a718160e12100efac4e8e4f748cdf7517bba948d7ee66d8811f2e462e3","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"bc44b45c985fd83ce4d0dcd9c87d7f8add24ff57a6cf081040a7f9d7d605fe71","source_locator":"2.3.8","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST') printf '%s\n' '{"adapter_contract_sha256":"2bcb810ddbcd73c74672dd4abef974bcfab05e565b7eff3c9bcca66649ac65f8","adapter_id":"product-suid-sgid-applications-check-v1","adapter_implementation_sha256":"2c4210150e82d9c639e50e18687c47504bb8cd8e61e25a01f4f3aad6c4bd5553","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"f74216265e6cc6dba28028813d9bc7d39ca680aa601c20a64d453c637637b2ac","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"subset-of-file","expected_type":"string","expected_value":"/etc/securelinux-policy/suid-sgid.allowlist-v1","index_id":"SRC-0013","parameter_key":"approved-set","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"6a29a8da2e6376e271e29dabc9b505d10c7e317e0bbafd0b1bacafd120431c6c","source_locator":"2.3.9","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE') printf '%s\n' '{"adapter_contract_sha256":"2bcb810ddbcd73c74672dd4abef974bcfab05e565b7eff3c9bcca66649ac65f8","adapter_id":"product-suid-sgid-applications-check-v1","adapter_implementation_sha256":"2c4210150e82d9c639e50e18687c47504bb8cd8e61e25a01f4f3aad6c4bd5553","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"5e52002e72ea86d8c10dad28d09c82f0a027850ca4ae6e0d40745b7cdc33710b","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0013","parameter_key":"mode","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"6a29a8da2e6376e271e29dabc9b505d10c7e317e0bbafd0b1bacafd120431c6c","source_locator":"2.3.9","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"51f99ed4b7c67eb30558176685885337c27a4d8c2047a8e667059dd2bbff07d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0016","parameter_key":"kernel.dmesg_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c889161dc17ca0ec538a88477aeebfd920e8d10a53d34952e69b12b24338a5e6","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"ba25c49b237cf91b74afcda02e15fd872e81c08973abd9719a8f4c465513aa9a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0017","parameter_key":"kernel.kptr_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"a4c2ba6bc1c18e8cc9a3b025cbf55b542e9cf327e3ce69fd2d8e4877bbc3ef60","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.2","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"68b4a5d37e9addc54b6c8d9316e1a9e47e4eda7cb0683b2df99c4be911c7ea5c","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0018","parameter_key":"init_on_alloc","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.3","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"817ddc5844c8600b30ea82b013576e8c90fe4381f37ff2d3e6f697766881aa9e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"present","expected_type":"boolean","expected_value":true,"index_id":"SRC-0019","parameter_key":"slab_nomerge","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"6a5c7fa4c5804ef3c2e152c338da6c73553bb8bce5dbde0331e4ba4db09d8b6f","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.4","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"595da19602209ab601375e129f45dfa720038e5a5b92017e51b5b7873bd6233d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"force","index_id":"SRC-0020","parameter_key":"iommu","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"85b3d67e7f741cfd9d50b3d935bc96ac38d6468d44cb18465baefa3379242942","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0","index_id":"SRC-0020","parameter_key":"iommu.passthrough","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"0d68a6bb3b7869e9d76046d196e61511e34560cfb55cf130b30c65b3b9d3e629","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0020","parameter_key":"iommu.strict","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"876b71fa1a3eabed4455db496c576c43ec897ccfe335266ae707b9bb976f124e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0021","parameter_key":"randomize_kstack_offset","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"69cbdb70f31aadd134129cae9eb95a96f836168646a821927cc3ea56ea58c980","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.7-MITIGATIONS') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"2d004e6effde058bcd8d5713b8116adec36af1476da6e4f5acb1553d7857d981","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"auto,nosmt","index_id":"SRC-0022","parameter_key":"mitigations","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"593127f71a130fb574410cc9b249cf9ce42c1ec9698ebad648c79c4554d55ceb","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.7","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"cfe64060a4d9829351c2c6f19c6f41b0e0697bd8be5b503a90ffe27a5f4c52ee","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0023","parameter_key":"net.core.bpf_jit_harden","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ffeec17a621afd4726e6c0fcf0aef4fb1e22c86f45ca20d1d568471675c3914f","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.8","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.1-VSYSCALL') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"611d219ec1d517ebceb3539968662a6e40a75bb028fc553ec18eb9a95544f413","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"none","index_id":"SRC-0024","parameter_key":"vsyscall","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"909ac7e3825f234cf325dac5b9615486ef4c856315aeb9c25d4b7a6af47fa421","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"f2733434c77fa39bec5210262632becd3f0aad65ddb7423c869725fe95fa5655","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"ge","expected_type":"integer","expected_value":4096,"index_id":"SRC-0033","parameter_key":"vm.mmap_min_addr","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.10","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"4a08a7bfd4f6a803dfb7bbc2486a83bd2fe1e877dcaa2e9938d402ee9765ee6d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0034","parameter_key":"kernel.randomize_va_space","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.11","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"b0eb7068712e20660c0d84871c271c6f3fdc542132cca1cf529910dcf7f85c0a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0025","parameter_key":"kernel.perf_event_paranoid","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8e6f4b120bd3527b380251e92eca56e1b4c358d362f1246357579eb8af616382","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.2","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.3-DEBUGFS') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"806da488a05c5d4ea11c2cef4bbde3b327387c1b96b143fe97c32e50e08a8894","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"one-of","expected_type":"string","expected_value":"off|no-mount","index_id":"SRC-0026","parameter_key":"debugfs","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"10391c151e6a53e91d637a11bc0f87a05a1ca7fdd408f9493dd27b366da46184","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.3","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"6006fdfb164b8a8860b8f4ae6d4e2758799f25ed32d53e185916da0ef0b7ed01","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0027","parameter_key":"kernel.kexec_load_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0231e3c8de27fab8de667f632bf6d08609a7c62836be9c787fd4cb955974ff09","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.4","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"b13b0e0b47c820d396a9a4a8d044ffdfc4eb779c5def2347c072cbc9e3900f32","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0028","parameter_key":"user.max_user_namespaces","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"77edbfb78e01426b6c40ccedca310ff6091870e235d4225ac488f4cd5d8c090c","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.5","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"44423cf2e57eabddd637a973430a6633282f8eba658430a1290bfa610efe5b67","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0029","parameter_key":"kernel.unprivileged_bpf_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"1c320abae9872972364ef95685204f4968a2c84bc27ee9c2707907eac8c5823e","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"3a5a2c1c560d688eeea441f4455297a86983c599745acf8963507f91b72c86f4","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0030","parameter_key":"vm.unprivileged_userfaultfd","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"cba35949a04f5d3dab8bd9a0501d75e5c310773ac11c1ad2c4d80845cdd03080","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.7","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"d6e4d8f63a5235ff32f3cb429c91caa7b7ff7864ba8ab90f8fd350362e8d3a69","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0031","parameter_key":"dev.tty.ldisc_autoload","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0860efcf66e2da819b06b5d6198e3b4c9b4ea96b66929752aceba65fae301783","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.8","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.9-TSX') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.9-TSX","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"07040e8445ac0565a587fcf6cfadf124a45b6b076592d4a268eff2abe37b5ef3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"off","index_id":"SRC-0032","parameter_key":"tsx","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"40b0ad985774f12adad55439e22a5ba29b3a2c50c9fedd16551fa261fd29464c","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.9","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"2bc9bb0cb5372fb5738612ff3738526cad9adb831b0043cc5924f36d23e7ca37","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0035","parameter_key":"kernel.yama.ptrace_scope","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"7be4210587e64fe1864bfbf1b5e8f7cc3512434629eb17898ad487d50a9ae246","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"b709581e94eb65e5a059d70ff4ec7aac7d248e6b664ffb42c502e23c88e2bbe8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0036","parameter_key":"fs.protected_symlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ce09b5104160f3fe27f17f1d5e57a5fe81001adac3c362ed652552ccbc59571f","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.2","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"fc1fd0f1141cb6d78b5d322e6a04b2649f0264a5e8c4784c64116bed55d70ffa","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0037","parameter_key":"fs.protected_hardlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"315736677a4e3192cde79d4badbf20809da81c8605785c8720fcd0fc3260fe97","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.3","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"af3b312efb3d252c1752a9ee70da6248e2a8e86f2e29479388206afbfbcd453d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0038","parameter_key":"fs.protected_fifos","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016aaaf884c10febb3e99a86acfcbe63eae04f05f5fcf35a00c59f03fb30a31b","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.4","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"677905dff8f0fa0db1c82008b7b3acc0456dd61c46db0008390ab99f89ef9d92","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0039","parameter_key":"fs.protected_regular","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0f1eea51ec98d254f230a48dfc4950cb060e11460e1f30be68fde3fb9439cb14","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.5","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","control_manifest_sha256":"a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216","control_sha256":"35c1fe8f6a4591fdf5b7d25f4dff6b244b868fbc1514498a7b55f9a321ddda8f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0040","parameter_key":"fs.suid_dumpable","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d","registry_sha256":"c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    *) return 2 ;;
  esac
}

slp_build_info() {
  printf '%s\n' \
    'STATUS=NON_RELEASE_PRODUCT_CANDIDATE' \
    'PRODUCT_CLI=product-cli-v1' \
    'GENERATOR_ID=product-check-generator-v2' \
    'GENERATOR_SHA256=2221d4d144275ae18718d50bf4a7de568d763f6380d6a7b7c2394bae7b141ea3' \
    'CONTROL_COUNT=48' \
    'CONTROL_MANIFEST_SHA256=a7f6339e117ed8e2d1ae7f0840c3a3cda20a7592e12acaf84f6be4f0d5fb7216' \
    'ADAPTER_COUNT=15' \
    'ADAPTER_REGISTRY_SHA256=c2ee4342c6de1cacba3d14f018cc8345800c2ceff25a2c7a3c09d6a8354e6d60' \
    'TARGET_ID=ubuntu-24.04-x86_64' \
    'MUTATING_MODES=NONE'
}

slp_help() {
  cat <<'SLP_HELP_EOF'
SecureLinux-Policy v3 — единый read-only CLI

Использование:
  ./securelinux-policy.sh --check [--failed] [--format pretty|raw|json]
  ./securelinux-policy.sh --report
  ./securelinux-policy.sh --build-info
  ./securelinux-policy.sh --provenance [CONTROL_ID]
  ./securelinux-policy.sh --version
  ./securelinux-policy.sh --help
  ./securelinux-policy.sh --apply
  ./securelinux-policy.sh --restore

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
  --restore             NOT_IMPLEMENTED; ничего не изменяет

Без аргументов печатается эта справка. CHECK не изменяет состояние хоста.
SLP_HELP_EOF
}

slp_version() {
  printf '%s\n' \
    'PRODUCT=SecureLinux-Policy-v3' \
    'PRODUCT_CLI=product-cli-v1' \
    'STATUS=NON_RELEASE_PRODUCT_CANDIDATE' \
    'CONTROL_COUNT=48' \
    'TARGET_ID=ubuntu-24.04-x86_64'
}

slp_json_escape() {
  local _slp_s=$1
  _slp_s=${_slp_s//\\/\\\\}
  _slp_s=${_slp_s//\"/\\\"}
  _slp_s=${_slp_s//$'\t'/\\t}
  _slp_s=${_slp_s//$'\r'/\\r}
  _slp_s=${_slp_s//$'\n'/\\n}
  printf '%s' "$_slp_s"
}

slp_pretty_row() {
  local _slp_result=$1 _slp_cid=$2 _slp_value=$3
  local _slp_width=56 _slp_part _slp_piece _slp_line=''
  local _slp_first=1
  local -a _slp_parts=()
  IFS=';' read -r -a _slp_parts <<< "$_slp_value"
  if (( ${#_slp_parts[@]} <= 1 )); then
    printf '%-7s  %-52s  %s\n' "$_slp_result" "$_slp_cid" "$_slp_value"
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
        printf '%-7s  %-52s  %s\n' "$_slp_result" "$_slp_cid" "$_slp_line"
        _slp_first=0
      else
        printf '%-7s  %-52s  %s\n' '' '' "$_slp_line"
      fi
      _slp_line=$_slp_part
    fi
  done
  if (( _slp_first == 1 )); then
    printf '%-7s  %-52s  %s\n' "$_slp_result" "$_slp_cid" "$_slp_line"
  else
    printf '%-7s  %-52s  %s\n' '' '' "$_slp_line"
  fi
}

slp_collect_policy() {
  local _slp_fn _slp_expected_cid _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_extra
  local _slp_i
  local -a _slp_fns=('slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE' 'slp_check_FSTEC_LINUX_2022_2_1_2_SSH_ROOT_LOGIN' 'slp_check_FSTEC_LINUX_2022_2_2_1_SU_WHEEL_ACCESS' 'slp_check_FSTEC_LINUX_2022_2_2_2_SUDOERS_REVIEWED_POLICY' 'slp_check_FSTEC_LINUX_2022_2_3_1_GROUP_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_1_PASSWD_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_1_SHADOW_GO_RWX' 'slp_check_FSTEC_LINUX_2022_2_3_10_HOME_SENSITIVE_FILES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_11_HOME_DIRECTORIES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_2_RUNNING_PROCESS_PATHS_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_3_CRON_COMMAND_PATHS_WRITE_PROTECTION' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_D' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_DAILY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_HOURLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_MONTHLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_WEEKLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRONTAB' 'slp_check_FSTEC_LINUX_2022_2_3_7_USER_CRON_FILES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_8_STANDARD_SYSTEM_PATHS_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_ALLOWLIST' 'slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_MODE' 'slp_check_FSTEC_LINUX_2022_2_4_1_DMESG_RESTRICT' 'slp_check_FSTEC_LINUX_2022_2_4_2_KPTR_RESTRICT' 'slp_check_FSTEC_LINUX_2022_2_4_3_INIT_ON_ALLOC' 'slp_check_FSTEC_LINUX_2022_2_4_4_SLAB_NOMERGE' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_FORCE' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_PASSTHROUGH' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_STRICT' 'slp_check_FSTEC_LINUX_2022_2_4_6_RANDOMIZE_KSTACK_OFFSET' 'slp_check_FSTEC_LINUX_2022_2_4_7_MITIGATIONS' 'slp_check_FSTEC_LINUX_2022_2_4_8_BPF_JIT_HARDEN' 'slp_check_FSTEC_LINUX_2022_2_5_1_VSYSCALL' 'slp_check_FSTEC_LINUX_2022_2_5_10_MMAP_MIN_ADDR' 'slp_check_FSTEC_LINUX_2022_2_5_11_RANDOMIZE_VA_SPACE' 'slp_check_FSTEC_LINUX_2022_2_5_2_PERF_EVENT_PARANOID' 'slp_check_FSTEC_LINUX_2022_2_5_3_DEBUGFS' 'slp_check_FSTEC_LINUX_2022_2_5_4_KEXEC_LOAD_DISABLED' 'slp_check_FSTEC_LINUX_2022_2_5_5_MAX_USER_NAMESPACES' 'slp_check_FSTEC_LINUX_2022_2_5_6_UNPRIVILEGED_BPF_DISABLED' 'slp_check_FSTEC_LINUX_2022_2_5_7_UNPRIVILEGED_USERFAULTFD' 'slp_check_FSTEC_LINUX_2022_2_5_8_LDISC_AUTOLOAD' 'slp_check_FSTEC_LINUX_2022_2_5_9_TSX' 'slp_check_FSTEC_LINUX_2022_2_6_1_PTRACE_SCOPE' 'slp_check_FSTEC_LINUX_2022_2_6_2_PROTECTED_SYMLINKS' 'slp_check_FSTEC_LINUX_2022_2_6_3_PROTECTED_HARDLINKS' 'slp_check_FSTEC_LINUX_2022_2_6_4_PROTECTED_FIFOS' 'slp_check_FSTEC_LINUX_2022_2_6_5_PROTECTED_REGULAR' 'slp_check_FSTEC_LINUX_2022_2_6_6_SUID_DUMPABLE')
  local -a _slp_ids=('FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' 'FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN' 'FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS' 'FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' 'FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION' 'FSTEC-LINUX-2022-2.3.6-CRON-D' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' 'FSTEC-LINUX-2022-2.5.9-TSX' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE')

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
      VALUE:PASS|VALUE:FAIL|NOT_FOUND:NOT_FOUND|ERROR:ERROR) ;;
      *)
        printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
        return 1
        ;;
    esac
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
  printf '=== SecureLinux Policy — %s ===\n\n' "$_slp_title"
  printf '%-7s  %-52s  %s\n' 'RESULT' 'CONTROL' 'VALUE / DETAILS'
  printf '%-7s  %-52s  %s\n' '------' '----------------------------------------------------' '--------------------------------------------------------'
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    slp_pretty_row "$_slp_comp" "$_slp_cid" "$_slp_value"
  done
  printf '%s\n' '-------------------------------------------------------------------------------------------------------------------------'
  printf 'TOTAL=%d   PASS=%d   FAIL=%d   NOT_FOUND=%d   ERROR=%d   POLICY=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_ERR" "$SLP_POLICY_STATUS"
}

slp_render_json() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_first=1 _slp_filter=all
  (( _slp_failed_only == 1 )) && _slp_filter=failed
  printf '{"schema":"SLP-REPORT-V1","filter":"%s","policy_status":"%s","summary":{"total":%d,"pass":%d,"fail":%d,"not_found":%d,"error":%d},"results":[' \
    "$_slp_filter" "$SLP_POLICY_STATUS" "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_ERR"
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
    --restore)
      (( $# == 1 )) || return 2
      slp_not_implemented RESTORE
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
