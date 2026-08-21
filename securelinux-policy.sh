#!/usr/bin/env bash
# SecureLinux-Policy v3 unified read-only product CLI
# STATUS=NON_RELEASE_PRODUCT_CANDIDATE
# PRODUCT_CLI=product-cli-v1
# GENERATOR_ID=product-check-generator-v2
# GENERATOR_SHA256=88bd5ce40322d89b957e61ab4d9333e3af90ba5cbf3fd6ac687f91db50c8093b
# CONTROL_MANIFEST_SHA256=f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448
# ADAPTER_REGISTRY_SHA256=12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43
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

slp_check_FSTEC_LINUX_2022_2_3_1_GROUP_MODE() {
  local _slp_path='/etc/group'
  local _slp_expected='0644'
  local _slp_mode _slp_parent _slp_comp
  if ! command -v stat >/dev/null 2>&1; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
  if _slp_mode=$(LC_ALL=C stat -L -c %a -- "$_slp_path" 2>/dev/null); then
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
  if ! command -v stat >/dev/null 2>&1; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' "ERROR" "-" "ERROR"
    return 0
  fi
  if _slp_mode=$(LC_ALL=C stat -L -c %a -- "$_slp_path" 2>/dev/null); then
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
  if ! command -v stat >/dev/null 2>&1; then
    printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' "ERROR" "-" "ERROR"
    return 0
  fi
  if _slp_mode=$(LC_ALL=C stat -L -c %a -- "$_slp_path" 2>/dev/null); then
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
  local _slp_shell_trim _slp_shell_base _slp_home_id _slp_rel _slp_path _slp_cur _slp_part _slp_mode
  local _slp_uid_min='' _slp_uid_min_hits=0 _slp_candidate=0 _slp_missing=0
  local _slp_accounts=0 _slp_homes=0 _slp_checked=0 _slp_violations=0 _slp_i=0
  local -a _slp_fields=() _slp_names=() _slp_parts=() _slp_mandatory=('.bash_history' '.history' '.sh_history' '.bash_profile' '.bashrc' '.profile' '.bash_logout' '.rhosts')
  local -A _slp_seen_names=() _slp_seen_homes=()

  for _slp_path in "$_slp_passwd" "$_slp_login_defs" "$_slp_inventory"; do
    if [[ ! -f "$_slp_path" || -L "$_slp_path" || ! -r "$_slp_path" ]]; then
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
    if ! _slp_home_id=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_home" 2>/dev/null); then
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
      if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -Lc "%a" -- "$_slp_path" 2>/dev/null); then
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
  local _slp_line _slp_body _slp_name _slp_pw _slp_uid _slp_gid _slp_gecos _slp_home _slp_shell _slp_path
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
    if ! _slp_home_id=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_home" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ${_slp_seen_homes["$_slp_home_id"]+x} ]]; then continue; fi
    _slp_seen_homes["$_slp_home_id"]=1
    if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -Lc "%a" -- "$_slp_home" 2>/dev/null); then
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
  if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
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
    LC_ALL=C /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z
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
    if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
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
  if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
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
    LC_ALL=C /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z
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
    if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
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
  if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
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
    LC_ALL=C /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z
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
    if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
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
  if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
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
    LC_ALL=C /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z
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
    if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
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
  if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
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
    LC_ALL=C /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z
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
    if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
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
  if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then
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
    LC_ALL=C /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z
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
    if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
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
      LC_ALL=C /usr/bin/find -P -- "$_slp_root" -mindepth 1 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z
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
      if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then
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
  if ! _slp_uname_r=$(/usr/bin/uname -r 2>/dev/null); then
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
      if ! _slp_resolved=$(/usr/bin/readlink -f -- "$_slp_root" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ -z $_slp_resolved || ! -d "$_slp_resolved" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if ! _slp_root_id=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_resolved" 2>/dev/null); then
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
        LC_ALL=C /usr/bin/find -P -- "$_slp_resolved" -mindepth 1 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z
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
          if ! _slp_target=$(/usr/bin/readlink -f -- "$_slp_entry" 2>/dev/null); then
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
        if ! _slp_ident=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_target" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' "ERROR" "-" "ERROR"
          return 0
        fi
        if [[ ${_slp_seen_targets["$_slp_ident"]+x} ]]; then continue; fi
        _slp_seen_targets["$_slp_ident"]=1
        if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -Lc %a -- "$_slp_target" 2>/dev/null); then
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
  local _slp_mp _slp_after _slp_fstype _slp_root_id _slp_entry _slp_ident _slp_mode _slp_marker _slp_find_rc _slp_sort_rc _slp_i
  local _slp_mounts=0 _slp_checked=0 _slp_violations=0 _slp_extras=0 _slp_lineno=0
  local -a _slp_entries=()
  local -A _slp_seen_mounts=() _slp_seen_files=() _slp_allowed=()

  if [[ ! -f "$_slp_mountinfo" || -L "$_slp_mountinfo" || ! -r "$_slp_mountinfo" ]]; then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
    return 0
  fi
  local _slp_allowlist="$_slp_expected" _slp_allow_line
  if [[ "$_slp_allowlist" != /* || ! -f "$_slp_allowlist" || -L "$_slp_allowlist" || ! -r "$_slp_allowlist" ]]; then
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
    if ! _slp_root_id=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_mp" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ${_slp_seen_mounts["$_slp_root_id"]+x} ]]; then continue; fi
    _slp_seen_mounts["$_slp_root_id"]=1
    ((_slp_mounts+=1))
    _slp_entries=()
    mapfile -d "" -t _slp_entries < <(
      LC_ALL=C /usr/bin/find -P -- "$_slp_mp" -xdev -type f -"per""m" /6000 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z
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
      if ! _slp_ident=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ ${_slp_seen_files["$_slp_ident"]+x} ]]; then continue; fi
      _slp_seen_files["$_slp_ident"]=1
      if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then
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
  local _slp_mp _slp_after _slp_fstype _slp_root_id _slp_entry _slp_ident _slp_mode _slp_marker _slp_find_rc _slp_sort_rc _slp_i
  local _slp_mounts=0 _slp_checked=0 _slp_violations=0 _slp_extras=0 _slp_lineno=0
  local -a _slp_entries=()
  local -A _slp_seen_mounts=() _slp_seen_files=() _slp_allowed=()

  if [[ ! -f "$_slp_mountinfo" || -L "$_slp_mountinfo" || ! -r "$_slp_mountinfo" ]]; then
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
    if ! _slp_root_id=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_mp" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
      return 0
    fi
    if [[ ${_slp_seen_mounts["$_slp_root_id"]+x} ]]; then continue; fi
    _slp_seen_mounts["$_slp_root_id"]=1
    ((_slp_mounts+=1))
    _slp_entries=()
    mapfile -d "" -t _slp_entries < <(
      LC_ALL=C /usr/bin/find -P -- "$_slp_mp" -xdev -type f -"per""m" /6000 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z
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
      if ! _slp_ident=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then
  printf "%s\t%s\t%s\t%s\t%s\n" 'SLP-CHECK-V1' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' "ERROR" "-" "ERROR"
        return 0
      fi
      if [[ ${_slp_seen_files["$_slp_ident"]+x} ]]; then continue; fi
      _slp_seen_files["$_slp_ident"]=1
      if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then
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
  _slp_arch=$(/usr/bin/uname -m 2>/dev/null) || {
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
{"adapter_contract_sha256":"461a96c3fa8f0ebe0e2684bed109576eda536a2f260902c8ce516cddd2043648","adapter_id":"product-local-account-password-state-check-v1","adapter_implementation_sha256":"f92af716622ef9ef5c9463e0496a4d5cb636729a087fd8520a89a5d0e6cc6a47","control_id":"FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"82d8121586664ee803efec1f1b4bb93a248ce1f302bdf90a2561468ead86d802","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"all-nonempty","expected_type":"boolean","expected_value":true,"index_id":"SRC-0001","parameter_key":"password-field","parameter_kind":"local-account-password-state","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"2dbfb302061eab4d698dd5c74c15132ca92d0fd8f98808582986dbe8cd4c2cb1","source_locator":"2.1.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ea6c62f0c9fb1455830378f0a069a7d214f10ce7f3f621c8307dff6c797f1d8a","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"02765c2d3deb62fbcd16a637f14c55407fa0a2e7102a205e85624bf18dc93bee","control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"719123c6ab9e5a26bd261a67aa2340ad1cf388ca3749db9c05b23f3079584a81","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ea6c62f0c9fb1455830378f0a069a7d214f10ce7f3f621c8307dff6c797f1d8a","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"02765c2d3deb62fbcd16a637f14c55407fa0a2e7102a205e85624bf18dc93bee","control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"93faa0e6920c07e2f8e12b8326131e9dc52cf9b6145eafda75943d0eef1278b1","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/passwd","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ea6c62f0c9fb1455830378f0a069a7d214f10ce7f3f621c8307dff6c797f1d8a","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"02765c2d3deb62fbcd16a637f14c55407fa0a2e7102a205e85624bf18dc93bee","control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"62efde1e39f219e843193c7bc5a2d539d685ab79c33094c05a70e3d21873e03f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"f3baf4d06049bb76535b4f9736be703ea8fc2792a8dfbfac9cbb6f7a41fd7408","adapter_id":"product-home-sensitive-files-mode-check-v1","adapter_implementation_sha256":"3ad914ec048eea766d8f45ececabd209c47a5de3fd7dc7545449673545e40f13","control_id":"FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"1343b6983ddfff62222a03db98023417abbe8ad9c4236a67231debac09793aed","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0014","parameter_key":"mode","parameter_kind":"home-sensitive-files-mode","parameter_locator":"/etc/passwd|/etc/login.defs|/etc/securelinux-policy/home-sensitive-files-v1","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"b737347b3377148507c544e0dc2f2eb8fa0b8548ec04449ea33de8e05c0d578b","source_locator":"2.3.10","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"f699ddb309987acb0383bd297c9f5aab067c2b02a874ab964d47e4c9af60fa43","adapter_id":"product-home-directories-mode-check-v1","adapter_implementation_sha256":"c1b46821519c0641196907633d51e90028085448fd9acee4173491ae59b8d4aa","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"ac070436aa49c1b78cc45972d1fdb41bb8462c4c40c5fcb26ec814ee45f84aed","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","parameter_key":"mode","parameter_kind":"home-directories-mode","parameter_locator":"/etc/passwd|/etc/login.defs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4d99341eb83d8e8eab7f9c41970cbd07662d0e37e1ff7a6e95e67022ec4427a9","source_locator":"2.3.11","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"d1dd9b4af5c49732ec93ac350d82fb138cb1fdc967396dda25062d59ff77527a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.d","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"a6c928414a1091aa8bf7291eee2e7574c9ad5f204831930d39a8536700f1731a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.daily","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"882eec0779eac5f5942f10e6670b2812f8000bf8f3e7600ba1c264362a8f4dce","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.hourly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"ca59fb02687823c843038099bd5698d42cd7d3cd402a22b4f0126bd89da42433","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.monthly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"62383ceb2d82745bdfeee36b424136c351b12d17ba430bf48b1706338a7c35e5","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.weekly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"043329e8aff8fa44762e5a2a22f6688c03bd30399dc78acb30821748d81d4fda","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/crontab","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ec4878322f7a4d502dcec911f455fe8fb2c3265531c3231b107d52b063a50d33","adapter_id":"product-user-cron-files-mode-check-v1","adapter_implementation_sha256":"f2dc0f2a7e6653ae4273769d634c02fb3d11277c0589123930b04713bd19911d","control_id":"FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"9ec427f2f8fe4fd76ae91e4a0b276a98eddf2c95949feca8a43035008f575360","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0011","parameter_key":"mode","parameter_kind":"user-cron-files-mode","parameter_locator":"/var/spool/cron|/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"af9430a9911e812b6f4b9735f35554d02e4203f7c39a3cae3d1c03004eb9adbe","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"81e008a5ecc0e451679b4b7bacf25d2c2de365c4cd4573db801009f926559ea3","source_locator":"2.3.7","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"4d60671baf64d13f586e1507781b987765e8bc66727046d1181ad8869d58332e","adapter_id":"product-standard-system-paths-mode-check-v1","adapter_implementation_sha256":"299a44565dcd8dc9d10539326a34371498cb24df2be77382d29a2fcd12e180ab","control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"ba4c3310e62afdb05e7d3cba0f2ba086c77389574565d5f0d34abe3bd0e86962","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0012","parameter_key":"mode","parameter_kind":"standard-system-paths-mode","parameter_locator":"/bin|/sbin|/usr/bin|/usr/sbin|/lib|/lib64|/usr/lib|/usr/lib64|/lib/modules/<uname-r>","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c14203a718160e12100efac4e8e4f748cdf7517bba948d7ee66d8811f2e462e3","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"bc44b45c985fd83ce4d0dcd9c87d7f8add24ff57a6cf081040a7f9d7d605fe71","source_locator":"2.3.8","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"f4fd2c4f55967a4dc9c0ffa8c59f64a8b6f4b2262782cb2f4d0714dac067dc08","adapter_id":"product-suid-sgid-applications-check-v1","adapter_implementation_sha256":"c072d9b5e0267eaa1ad6401b7671f3fc3b264e281a113183a518f130f2b0c82a","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"f74216265e6cc6dba28028813d9bc7d39ca680aa601c20a64d453c637637b2ac","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"subset-of-file","expected_type":"string","expected_value":"/etc/securelinux-policy/suid-sgid.allowlist-v1","index_id":"SRC-0013","parameter_key":"approved-set","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"7a5f6780dfd5ec858f4e4c89d706f60ee35387678f5ca8437c7631fbd0eefaaa","source_locator":"2.3.9","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"f4fd2c4f55967a4dc9c0ffa8c59f64a8b6f4b2262782cb2f4d0714dac067dc08","adapter_id":"product-suid-sgid-applications-check-v1","adapter_implementation_sha256":"c072d9b5e0267eaa1ad6401b7671f3fc3b264e281a113183a518f130f2b0c82a","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"5e52002e72ea86d8c10dad28d09c82f0a027850ca4ae6e0d40745b7cdc33710b","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0013","parameter_key":"mode","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"7a5f6780dfd5ec858f4e4c89d706f60ee35387678f5ca8437c7631fbd0eefaaa","source_locator":"2.3.9","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"51f99ed4b7c67eb30558176685885337c27a4d8c2047a8e667059dd2bbff07d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0016","parameter_key":"kernel.dmesg_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c889161dc17ca0ec538a88477aeebfd920e8d10a53d34952e69b12b24338a5e6","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"ba25c49b237cf91b74afcda02e15fd872e81c08973abd9719a8f4c465513aa9a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0017","parameter_key":"kernel.kptr_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"a4c2ba6bc1c18e8cc9a3b025cbf55b542e9cf327e3ce69fd2d8e4877bbc3ef60","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.2","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"68b4a5d37e9addc54b6c8d9316e1a9e47e4eda7cb0683b2df99c4be911c7ea5c","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0018","parameter_key":"init_on_alloc","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.3","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"817ddc5844c8600b30ea82b013576e8c90fe4381f37ff2d3e6f697766881aa9e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"present","expected_type":"boolean","expected_value":true,"index_id":"SRC-0019","parameter_key":"slab_nomerge","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"6a5c7fa4c5804ef3c2e152c338da6c73553bb8bce5dbde0331e4ba4db09d8b6f","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.4","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"595da19602209ab601375e129f45dfa720038e5a5b92017e51b5b7873bd6233d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"force","index_id":"SRC-0020","parameter_key":"iommu","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"85b3d67e7f741cfd9d50b3d935bc96ac38d6468d44cb18465baefa3379242942","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0","index_id":"SRC-0020","parameter_key":"iommu.passthrough","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"0d68a6bb3b7869e9d76046d196e61511e34560cfb55cf130b30c65b3b9d3e629","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0020","parameter_key":"iommu.strict","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"876b71fa1a3eabed4455db496c576c43ec897ccfe335266ae707b9bb976f124e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0021","parameter_key":"randomize_kstack_offset","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"69cbdb70f31aadd134129cae9eb95a96f836168646a821927cc3ea56ea58c980","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"2d004e6effde058bcd8d5713b8116adec36af1476da6e4f5acb1553d7857d981","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"auto,nosmt","index_id":"SRC-0022","parameter_key":"mitigations","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"593127f71a130fb574410cc9b249cf9ce42c1ec9698ebad648c79c4554d55ceb","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.7","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"cfe64060a4d9829351c2c6f19c6f41b0e0697bd8be5b503a90ffe27a5f4c52ee","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0023","parameter_key":"net.core.bpf_jit_harden","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ffeec17a621afd4726e6c0fcf0aef4fb1e22c86f45ca20d1d568471675c3914f","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.8","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"611d219ec1d517ebceb3539968662a6e40a75bb028fc553ec18eb9a95544f413","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"none","index_id":"SRC-0024","parameter_key":"vsyscall","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"909ac7e3825f234cf325dac5b9615486ef4c856315aeb9c25d4b7a6af47fa421","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"f2733434c77fa39bec5210262632becd3f0aad65ddb7423c869725fe95fa5655","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"ge","expected_type":"integer","expected_value":4096,"index_id":"SRC-0033","parameter_key":"vm.mmap_min_addr","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.10","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"4a08a7bfd4f6a803dfb7bbc2486a83bd2fe1e877dcaa2e9938d402ee9765ee6d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0034","parameter_key":"kernel.randomize_va_space","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.11","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"b0eb7068712e20660c0d84871c271c6f3fdc542132cca1cf529910dcf7f85c0a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0025","parameter_key":"kernel.perf_event_paranoid","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8e6f4b120bd3527b380251e92eca56e1b4c358d362f1246357579eb8af616382","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.2","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"806da488a05c5d4ea11c2cef4bbde3b327387c1b96b143fe97c32e50e08a8894","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"one-of","expected_type":"string","expected_value":"off|no-mount","index_id":"SRC-0026","parameter_key":"debugfs","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"10391c151e6a53e91d637a11bc0f87a05a1ca7fdd408f9493dd27b366da46184","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.3","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"6006fdfb164b8a8860b8f4ae6d4e2758799f25ed32d53e185916da0ef0b7ed01","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0027","parameter_key":"kernel.kexec_load_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0231e3c8de27fab8de667f632bf6d08609a7c62836be9c787fd4cb955974ff09","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.4","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"b13b0e0b47c820d396a9a4a8d044ffdfc4eb779c5def2347c072cbc9e3900f32","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0028","parameter_key":"user.max_user_namespaces","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"77edbfb78e01426b6c40ccedca310ff6091870e235d4225ac488f4cd5d8c090c","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.5","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"44423cf2e57eabddd637a973430a6633282f8eba658430a1290bfa610efe5b67","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0029","parameter_key":"kernel.unprivileged_bpf_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"1c320abae9872972364ef95685204f4968a2c84bc27ee9c2707907eac8c5823e","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.6","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"3a5a2c1c560d688eeea441f4455297a86983c599745acf8963507f91b72c86f4","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0030","parameter_key":"vm.unprivileged_userfaultfd","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"cba35949a04f5d3dab8bd9a0501d75e5c310773ac11c1ad2c4d80845cdd03080","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.7","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"d6e4d8f63a5235ff32f3cb429c91caa7b7ff7864ba8ab90f8fd350362e8d3a69","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0031","parameter_key":"dev.tty.ldisc_autoload","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0860efcf66e2da819b06b5d6198e3b4c9b4ea96b66929752aceba65fae301783","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.8","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.9-TSX","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"07040e8445ac0565a587fcf6cfadf124a45b6b076592d4a268eff2abe37b5ef3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"off","index_id":"SRC-0032","parameter_key":"tsx","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"40b0ad985774f12adad55439e22a5ba29b3a2c50c9fedd16551fa261fd29464c","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.9","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"2bc9bb0cb5372fb5738612ff3738526cad9adb831b0043cc5924f36d23e7ca37","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0035","parameter_key":"kernel.yama.ptrace_scope","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"7be4210587e64fe1864bfbf1b5e8f7cc3512434629eb17898ad487d50a9ae246","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.1","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"b709581e94eb65e5a059d70ff4ec7aac7d248e6b664ffb42c502e23c88e2bbe8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0036","parameter_key":"fs.protected_symlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ce09b5104160f3fe27f17f1d5e57a5fe81001adac3c362ed652552ccbc59571f","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.2","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"fc1fd0f1141cb6d78b5d322e6a04b2649f0264a5e8c4784c64116bed55d70ffa","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0037","parameter_key":"fs.protected_hardlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"315736677a4e3192cde79d4badbf20809da81c8605785c8720fcd0fc3260fe97","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.3","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"af3b312efb3d252c1752a9ee70da6248e2a8e86f2e29479388206afbfbcd453d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0038","parameter_key":"fs.protected_fifos","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016aaaf884c10febb3e99a86acfcbe63eae04f05f5fcf35a00c59f03fb30a31b","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.4","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"677905dff8f0fa0db1c82008b7b3acc0456dd61c46db0008390ab99f89ef9d92","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0039","parameter_key":"fs.protected_regular","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0f1eea51ec98d254f230a48dfc4950cb060e11460e1f30be68fde3fb9439cb14","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.5","target_id":"ubuntu-24.04-x86_64"}
{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"35c1fe8f6a4591fdf5b7d25f4dff6b244b868fbc1514498a7b55f9a321ddda8f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0040","parameter_key":"fs.suid_dumpable","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.6","target_id":"ubuntu-24.04-x86_64"}
SLP_PROVENANCE_EOF
}

slp_provenance_one() {
  case "$1" in
    'FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE') printf '%s\n' '{"adapter_contract_sha256":"461a96c3fa8f0ebe0e2684bed109576eda536a2f260902c8ce516cddd2043648","adapter_id":"product-local-account-password-state-check-v1","adapter_implementation_sha256":"f92af716622ef9ef5c9463e0496a4d5cb636729a087fd8520a89a5d0e6cc6a47","control_id":"FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"82d8121586664ee803efec1f1b4bb93a248ce1f302bdf90a2561468ead86d802","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"all-nonempty","expected_type":"boolean","expected_value":true,"index_id":"SRC-0001","parameter_key":"password-field","parameter_kind":"local-account-password-state","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"2dbfb302061eab4d698dd5c74c15132ca92d0fd8f98808582986dbe8cd4c2cb1","source_locator":"2.1.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.1-GROUP-MODE') printf '%s\n' '{"adapter_contract_sha256":"ea6c62f0c9fb1455830378f0a069a7d214f10ce7f3f621c8307dff6c797f1d8a","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"02765c2d3deb62fbcd16a637f14c55407fa0a2e7102a205e85624bf18dc93bee","control_id":"FSTEC-LINUX-2022-2.3.1-GROUP-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"719123c6ab9e5a26bd261a67aa2340ad1cf388ca3749db9c05b23f3079584a81","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/group","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE') printf '%s\n' '{"adapter_contract_sha256":"ea6c62f0c9fb1455830378f0a069a7d214f10ce7f3f621c8307dff6c797f1d8a","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"02765c2d3deb62fbcd16a637f14c55407fa0a2e7102a205e85624bf18dc93bee","control_id":"FSTEC-LINUX-2022-2.3.1-PASSWD-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"93faa0e6920c07e2f8e12b8326131e9dc52cf9b6145eafda75943d0eef1278b1","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0644","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/passwd","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX') printf '%s\n' '{"adapter_contract_sha256":"ea6c62f0c9fb1455830378f0a069a7d214f10ce7f3f621c8307dff6c797f1d8a","adapter_id":"product-file-mode-owner-check-v1","adapter_implementation_sha256":"02765c2d3deb62fbcd16a637f14c55407fa0a2e7102a205e85624bf18dc93bee","control_id":"FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"62efde1e39f219e843193c7bc5a2d539d685ab79c33094c05a70e3d21873e03f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0005","parameter_key":"mode","parameter_kind":"file-mode-owner","parameter_locator":"/etc/shadow","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"9ff1921e56eb10d64d5a4bd66ed41a79923f1ef2600826cf96f99540d8dcbf66","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"cbd40227aa286a2d761efbd6c33563235f6b15155c766bbe4a5947f28dafedd8","source_locator":"2.3.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE') printf '%s\n' '{"adapter_contract_sha256":"f3baf4d06049bb76535b4f9736be703ea8fc2792a8dfbfac9cbb6f7a41fd7408","adapter_id":"product-home-sensitive-files-mode-check-v1","adapter_implementation_sha256":"3ad914ec048eea766d8f45ececabd209c47a5de3fd7dc7545449673545e40f13","control_id":"FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"1343b6983ddfff62222a03db98023417abbe8ad9c4236a67231debac09793aed","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0077","index_id":"SRC-0014","parameter_key":"mode","parameter_kind":"home-sensitive-files-mode","parameter_locator":"/etc/passwd|/etc/login.defs|/etc/securelinux-policy/home-sensitive-files-v1","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"b737347b3377148507c544e0dc2f2eb8fa0b8548ec04449ea33de8e05c0d578b","source_locator":"2.3.10","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE') printf '%s\n' '{"adapter_contract_sha256":"f699ddb309987acb0383bd297c9f5aab067c2b02a874ab964d47e4c9af60fa43","adapter_id":"product-home-directories-mode-check-v1","adapter_implementation_sha256":"c1b46821519c0641196907633d51e90028085448fd9acee4173491ae59b8d4aa","control_id":"FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"ac070436aa49c1b78cc45972d1fdb41bb8462c4c40c5fcb26ec814ee45f84aed","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0700","index_id":"SRC-0015","parameter_key":"mode","parameter_kind":"home-directories-mode","parameter_locator":"/etc/passwd|/etc/login.defs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"2a65505db54ec27a6fec5682d2d2eb71e33b441dffad14c9dcc2d43a7c4b3c8d","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4d99341eb83d8e8eab7f9c41970cbd07662d0e37e1ff7a6e95e67022ec4427a9","source_locator":"2.3.11","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-D') printf '%s\n' '{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-D","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"d1dd9b4af5c49732ec93ac350d82fb138cb1fdc967396dda25062d59ff77527a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.d","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-DAILY') printf '%s\n' '{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-DAILY","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"a6c928414a1091aa8bf7291eee2e7574c9ad5f204831930d39a8536700f1731a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.daily","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY') printf '%s\n' '{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-HOURLY","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"882eec0779eac5f5942f10e6670b2812f8000bf8f3e7600ba1c264362a8f4dce","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.hourly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY') printf '%s\n' '{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"ca59fb02687823c843038099bd5698d42cd7d3cd402a22b4f0126bd89da42433","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.monthly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY') printf '%s\n' '{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"62383ceb2d82745bdfeee36b424136c351b12d17ba430bf48b1706338a7c35e5","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/cron.weekly","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.6-CRONTAB') printf '%s\n' '{"adapter_contract_sha256":"81b7ed8d496af95c68c7b31fbc90f190085bbff2e4021248770f3bb83c15d85f","adapter_id":"product-optional-file-root-files-mode-check-v1","adapter_implementation_sha256":"8e6bde277ad265352f3549a22411daf9d4416d80c8c683e346221b173aea2991","control_id":"FSTEC-LINUX-2022-2.3.6-CRONTAB","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"043329e8aff8fa44762e5a2a22f6688c03bd30399dc78acb30821748d81d4fda","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0033","index_id":"SRC-0010","parameter_key":"mode","parameter_kind":"optional-file-root-files-mode","parameter_locator":"/etc/crontab","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"36b35ef73a2a7e674dc2ac2ce1242033ec2e83d32a793824e7e36fd0e8435962","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"391d2db8f698fd6c34e0bce7adf830ffd59079402dc2363d1a149d497d0a1aa1","source_locator":"2.3.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE') printf '%s\n' '{"adapter_contract_sha256":"ec4878322f7a4d502dcec911f455fe8fb2c3265531c3231b107d52b063a50d33","adapter_id":"product-user-cron-files-mode-check-v1","adapter_implementation_sha256":"f2dc0f2a7e6653ae4273769d634c02fb3d11277c0589123930b04713bd19911d","control_id":"FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"9ec427f2f8fe4fd76ae91e4a0b276a98eddf2c95949feca8a43035008f575360","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0011","parameter_key":"mode","parameter_kind":"user-cron-files-mode","parameter_locator":"/var/spool/cron|/var/spool/cron/crontabs","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"af9430a9911e812b6f4b9735f35554d02e4203f7c39a3cae3d1c03004eb9adbe","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"81e008a5ecc0e451679b4b7bacf25d2c2de365c4cd4573db801009f926559ea3","source_locator":"2.3.7","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE') printf '%s\n' '{"adapter_contract_sha256":"4d60671baf64d13f586e1507781b987765e8bc66727046d1181ad8869d58332e","adapter_id":"product-standard-system-paths-mode-check-v1","adapter_implementation_sha256":"299a44565dcd8dc9d10539326a34371498cb24df2be77382d29a2fcd12e180ab","control_id":"FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"ba4c3310e62afdb05e7d3cba0f2ba086c77389574565d5f0d34abe3bd0e86962","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0012","parameter_key":"mode","parameter_kind":"standard-system-paths-mode","parameter_locator":"/bin|/sbin|/usr/bin|/usr/sbin|/lib|/lib64|/usr/lib|/usr/lib64|/lib/modules/<uname-r>","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c14203a718160e12100efac4e8e4f748cdf7517bba948d7ee66d8811f2e462e3","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"bc44b45c985fd83ce4d0dcd9c87d7f8add24ff57a6cf081040a7f9d7d605fe71","source_locator":"2.3.8","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST') printf '%s\n' '{"adapter_contract_sha256":"f4fd2c4f55967a4dc9c0ffa8c59f64a8b6f4b2262782cb2f4d0714dac067dc08","adapter_id":"product-suid-sgid-applications-check-v1","adapter_implementation_sha256":"c072d9b5e0267eaa1ad6401b7671f3fc3b264e281a113183a518f130f2b0c82a","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"f74216265e6cc6dba28028813d9bc7d39ca680aa601c20a64d453c637637b2ac","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"subset-of-file","expected_type":"string","expected_value":"/etc/securelinux-policy/suid-sgid.allowlist-v1","index_id":"SRC-0013","parameter_key":"approved-set","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"7a5f6780dfd5ec858f4e4c89d706f60ee35387678f5ca8437c7631fbd0eefaaa","source_locator":"2.3.9","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE') printf '%s\n' '{"adapter_contract_sha256":"f4fd2c4f55967a4dc9c0ffa8c59f64a8b6f4b2262782cb2f4d0714dac067dc08","adapter_id":"product-suid-sgid-applications-check-v1","adapter_implementation_sha256":"c072d9b5e0267eaa1ad6401b7671f3fc3b264e281a113183a518f130f2b0c82a","control_id":"FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"5e52002e72ea86d8c10dad28d09c82f0a027850ca4ae6e0d40745b7cdc33710b","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"bits-clear","expected_type":"string","expected_value":"0022","index_id":"SRC-0013","parameter_key":"mode","parameter_kind":"suid-sgid-applications","parameter_locator":"/proc/self/mountinfo","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"4561a2f408c1d943d273eef49191f38e86733b007e5dd4259df73429d34bc0e1","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"7a5f6780dfd5ec858f4e4c89d706f60ee35387678f5ca8437c7631fbd0eefaaa","source_locator":"2.3.9","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"51f99ed4b7c67eb30558176685885337c27a4d8c2047a8e667059dd2bbff07d9","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0016","parameter_key":"kernel.dmesg_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"c889161dc17ca0ec538a88477aeebfd920e8d10a53d34952e69b12b24338a5e6","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"ba25c49b237cf91b74afcda02e15fd872e81c08973abd9719a8f4c465513aa9a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0017","parameter_key":"kernel.kptr_restrict","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"a4c2ba6bc1c18e8cc9a3b025cbf55b542e9cf327e3ce69fd2d8e4877bbc3ef60","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.2","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"68b4a5d37e9addc54b6c8d9316e1a9e47e4eda7cb0683b2df99c4be911c7ea5c","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0018","parameter_key":"init_on_alloc","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.3","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"817ddc5844c8600b30ea82b013576e8c90fe4381f37ff2d3e6f697766881aa9e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"present","expected_type":"boolean","expected_value":true,"index_id":"SRC-0019","parameter_key":"slab_nomerge","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"6a5c7fa4c5804ef3c2e152c338da6c73553bb8bce5dbde0331e4ba4db09d8b6f","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.4","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"595da19602209ab601375e129f45dfa720038e5a5b92017e51b5b7873bd6233d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"force","index_id":"SRC-0020","parameter_key":"iommu","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"85b3d67e7f741cfd9d50b3d935bc96ac38d6468d44cb18465baefa3379242942","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"0","index_id":"SRC-0020","parameter_key":"iommu.passthrough","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"0d68a6bb3b7869e9d76046d196e61511e34560cfb55cf130b30c65b3b9d3e629","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0020","parameter_key":"iommu.strict","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5d6db53b7945c06a610654f7b22d3f23b2840228e091cdf675568d3b6ecc3af5","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.5","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"876b71fa1a3eabed4455db496c576c43ec897ccfe335266ae707b9bb976f124e","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"1","index_id":"SRC-0021","parameter_key":"randomize_kstack_offset","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"69cbdb70f31aadd134129cae9eb95a96f836168646a821927cc3ea56ea58c980","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.7-MITIGATIONS') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.4.7-MITIGATIONS","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"2d004e6effde058bcd8d5713b8116adec36af1476da6e4f5acb1553d7857d981","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"auto,nosmt","index_id":"SRC-0022","parameter_key":"mitigations","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"593127f71a130fb574410cc9b249cf9ce42c1ec9698ebad648c79c4554d55ceb","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.4.7","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"cfe64060a4d9829351c2c6f19c6f41b0e0697bd8be5b503a90ffe27a5f4c52ee","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0023","parameter_key":"net.core.bpf_jit_harden","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ffeec17a621afd4726e6c0fcf0aef4fb1e22c86f45ca20d1d568471675c3914f","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.4.8","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.1-VSYSCALL') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.1-VSYSCALL","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"611d219ec1d517ebceb3539968662a6e40a75bb028fc553ec18eb9a95544f413","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"none","index_id":"SRC-0024","parameter_key":"vsyscall","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"909ac7e3825f234cf325dac5b9615486ef4c856315aeb9c25d4b7a6af47fa421","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"f2733434c77fa39bec5210262632becd3f0aad65ddb7423c869725fe95fa5655","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"ge","expected_type":"integer","expected_value":4096,"index_id":"SRC-0033","parameter_key":"vm.mmap_min_addr","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.10","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"4a08a7bfd4f6a803dfb7bbc2486a83bd2fe1e877dcaa2e9938d402ee9765ee6d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0034","parameter_key":"kernel.randomize_va_space","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"b40ce183dea4e9a89aff8cbc97a533d80b6db0b14ca8c844ce16486cfad417cf","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.11","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"b0eb7068712e20660c0d84871c271c6f3fdc542132cca1cf529910dcf7f85c0a","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0025","parameter_key":"kernel.perf_event_paranoid","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"8e6f4b120bd3527b380251e92eca56e1b4c358d362f1246357579eb8af616382","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.2","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.3-DEBUGFS') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.3-DEBUGFS","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"806da488a05c5d4ea11c2cef4bbde3b327387c1b96b143fe97c32e50e08a8894","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"one-of","expected_type":"string","expected_value":"off|no-mount","index_id":"SRC-0026","parameter_key":"debugfs","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"10391c151e6a53e91d637a11bc0f87a05a1ca7fdd408f9493dd27b366da46184","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.3","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"6006fdfb164b8a8860b8f4ae6d4e2758799f25ed32d53e185916da0ef0b7ed01","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0027","parameter_key":"kernel.kexec_load_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0231e3c8de27fab8de667f632bf6d08609a7c62836be9c787fd4cb955974ff09","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.4","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"b13b0e0b47c820d396a9a4a8d044ffdfc4eb779c5def2347c072cbc9e3900f32","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0028","parameter_key":"user.max_user_namespaces","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"77edbfb78e01426b6c40ccedca310ff6091870e235d4225ac488f4cd5d8c090c","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.5","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"44423cf2e57eabddd637a973430a6633282f8eba658430a1290bfa610efe5b67","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0029","parameter_key":"kernel.unprivileged_bpf_disabled","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"1c320abae9872972364ef95685204f4968a2c84bc27ee9c2707907eac8c5823e","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"3a5a2c1c560d688eeea441f4455297a86983c599745acf8963507f91b72c86f4","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0030","parameter_key":"vm.unprivileged_userfaultfd","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"cba35949a04f5d3dab8bd9a0501d75e5c310773ac11c1ad2c4d80845cdd03080","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.7","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"d6e4d8f63a5235ff32f3cb429c91caa7b7ff7864ba8ab90f8fd350362e8d3a69","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0031","parameter_key":"dev.tty.ldisc_autoload","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0860efcf66e2da819b06b5d6198e3b4c9b4ea96b66929752aceba65fae301783","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.5.8","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.5.9-TSX') printf '%s\n' '{"adapter_contract_sha256":"ded28f9648eb43338c175031d6f5a9c40a843076aeb9c6bc7eb562f05c50b275","adapter_id":"product-kernel-cmdline-check-v2","adapter_implementation_sha256":"870c72022f376a7af419774a9e6c498dcefac97700e7d442449d47875cc523ae","control_id":"FSTEC-LINUX-2022-2.5.9-TSX","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"07040e8445ac0565a587fcf6cfadf124a45b6b076592d4a268eff2abe37b5ef3","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"string","expected_value":"off","index_id":"SRC-0032","parameter_key":"tsx","parameter_kind":"kernel-cmdline","parameter_locator":"/proc/cmdline","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"40b0ad985774f12adad55439e22a5ba29b3a2c50c9fedd16551fa261fd29464c","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"4fe84ad535964544852d3c30ee63f4ad89290ee1b597da0cf16cad856ce36a4a","source_locator":"2.5.9","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"2bc9bb0cb5372fb5738612ff3738526cad9adb831b0043cc5924f36d23e7ca37","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":3,"index_id":"SRC-0035","parameter_key":"kernel.yama.ptrace_scope","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"7be4210587e64fe1864bfbf1b5e8f7cc3512434629eb17898ad487d50a9ae246","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.1","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"b709581e94eb65e5a059d70ff4ec7aac7d248e6b664ffb42c502e23c88e2bbe8","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0036","parameter_key":"fs.protected_symlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"ce09b5104160f3fe27f17f1d5e57a5fe81001adac3c362ed652552ccbc59571f","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.2","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"fc1fd0f1141cb6d78b5d322e6a04b2649f0264a5e8c4784c64116bed55d70ffa","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":1,"index_id":"SRC-0037","parameter_key":"fs.protected_hardlinks","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"315736677a4e3192cde79d4badbf20809da81c8605785c8720fcd0fc3260fe97","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.3","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"af3b312efb3d252c1752a9ee70da6248e2a8e86f2e29479388206afbfbcd453d","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0038","parameter_key":"fs.protected_fifos","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"016aaaf884c10febb3e99a86acfcbe63eae04f05f5fcf35a00c59f03fb30a31b","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.4","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"677905dff8f0fa0db1c82008b7b3acc0456dd61c46db0008390ab99f89ef9d92","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":2,"index_id":"SRC-0039","parameter_key":"fs.protected_regular","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"0f1eea51ec98d254f230a48dfc4950cb060e11460e1f30be68fde3fb9439cb14","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.5","target_id":"ubuntu-24.04-x86_64"}' ;;
    'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE') printf '%s\n' '{"adapter_contract_sha256":"bf18392ba3db1abd2240d6086c0eb490f4393a4aa38dc2811ca727b65aa572b3","adapter_id":"product-sysctl-check-v2","adapter_implementation_sha256":"525bf535b91047f2a4b3d7e7e28f43acfc2d2fc72286aa731c889352c6d4ac00","control_id":"FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE","control_manifest_sha256":"f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448","control_sha256":"35c1fe8f6a4591fdf5b7d25f4dff6b244b868fbc1514498a7b55f9a321ddda8f","doc_id":"fstec-linux-2022","doc_sha256":"350f00669436b1d505499b41f1f069bde335e5845441f8985209e1844620967d","expected_op":"eq","expected_type":"integer","expected_value":0,"index_id":"SRC-0040","parameter_key":"fs.suid_dumpable","parameter_kind":"sysctl","parameter_locator":"sysctl","product_status":"NON_RELEASE_PRODUCT_CANDIDATE","quote_sha256":"f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d","registry_sha256":"12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43","semantic_contract_sha256":"5b4a142383602aaa5689cdb2d8e718dc92939bb1599d7f07889e29fb4eb72225","source_locator":"2.6.6","target_id":"ubuntu-24.04-x86_64"}' ;;
    *) return 2 ;;
  esac
}

slp_build_info() {
  printf '%s\n' \
    'STATUS=NON_RELEASE_PRODUCT_CANDIDATE' \
    'PRODUCT_CLI=product-cli-v1' \
    'GENERATOR_ID=product-check-generator-v2' \
    'GENERATOR_SHA256=88bd5ce40322d89b957e61ab4d9333e3af90ba5cbf3fd6ac687f91db50c8093b' \
    'CONTROL_COUNT=43' \
    'CONTROL_MANIFEST_SHA256=f00ee053188c1af5b4554ebbb5193a2e5cab1b3253b295dba46c048524f4a448' \
    'ADAPTER_COUNT=10' \
    'ADAPTER_REGISTRY_SHA256=12a725ce134d2d7de248b5d832046e3c525d276ff6208816831079f234bd5b43' \
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
    'CONTROL_COUNT=43' \
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
  local -a _slp_fns=('slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE' 'slp_check_FSTEC_LINUX_2022_2_3_1_GROUP_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_1_PASSWD_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_1_SHADOW_GO_RWX' 'slp_check_FSTEC_LINUX_2022_2_3_10_HOME_SENSITIVE_FILES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_11_HOME_DIRECTORIES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_D' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_DAILY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_HOURLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_MONTHLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRON_WEEKLY' 'slp_check_FSTEC_LINUX_2022_2_3_6_CRONTAB' 'slp_check_FSTEC_LINUX_2022_2_3_7_USER_CRON_FILES_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_8_STANDARD_SYSTEM_PATHS_MODE' 'slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_ALLOWLIST' 'slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_MODE' 'slp_check_FSTEC_LINUX_2022_2_4_1_DMESG_RESTRICT' 'slp_check_FSTEC_LINUX_2022_2_4_2_KPTR_RESTRICT' 'slp_check_FSTEC_LINUX_2022_2_4_3_INIT_ON_ALLOC' 'slp_check_FSTEC_LINUX_2022_2_4_4_SLAB_NOMERGE' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_FORCE' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_PASSTHROUGH' 'slp_check_FSTEC_LINUX_2022_2_4_5_IOMMU_STRICT' 'slp_check_FSTEC_LINUX_2022_2_4_6_RANDOMIZE_KSTACK_OFFSET' 'slp_check_FSTEC_LINUX_2022_2_4_7_MITIGATIONS' 'slp_check_FSTEC_LINUX_2022_2_4_8_BPF_JIT_HARDEN' 'slp_check_FSTEC_LINUX_2022_2_5_1_VSYSCALL' 'slp_check_FSTEC_LINUX_2022_2_5_10_MMAP_MIN_ADDR' 'slp_check_FSTEC_LINUX_2022_2_5_11_RANDOMIZE_VA_SPACE' 'slp_check_FSTEC_LINUX_2022_2_5_2_PERF_EVENT_PARANOID' 'slp_check_FSTEC_LINUX_2022_2_5_3_DEBUGFS' 'slp_check_FSTEC_LINUX_2022_2_5_4_KEXEC_LOAD_DISABLED' 'slp_check_FSTEC_LINUX_2022_2_5_5_MAX_USER_NAMESPACES' 'slp_check_FSTEC_LINUX_2022_2_5_6_UNPRIVILEGED_BPF_DISABLED' 'slp_check_FSTEC_LINUX_2022_2_5_7_UNPRIVILEGED_USERFAULTFD' 'slp_check_FSTEC_LINUX_2022_2_5_8_LDISC_AUTOLOAD' 'slp_check_FSTEC_LINUX_2022_2_5_9_TSX' 'slp_check_FSTEC_LINUX_2022_2_6_1_PTRACE_SCOPE' 'slp_check_FSTEC_LINUX_2022_2_6_2_PROTECTED_SYMLINKS' 'slp_check_FSTEC_LINUX_2022_2_6_3_PROTECTED_HARDLINKS' 'slp_check_FSTEC_LINUX_2022_2_6_4_PROTECTED_FIFOS' 'slp_check_FSTEC_LINUX_2022_2_6_5_PROTECTED_REGULAR' 'slp_check_FSTEC_LINUX_2022_2_6_6_SUID_DUMPABLE')
  local -a _slp_ids=('FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE' 'FSTEC-LINUX-2022-2.3.1-GROUP-MODE' 'FSTEC-LINUX-2022-2.3.1-PASSWD-MODE' 'FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX' 'FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE' 'FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE' 'FSTEC-LINUX-2022-2.3.6-CRON-D' 'FSTEC-LINUX-2022-2.3.6-CRON-DAILY' 'FSTEC-LINUX-2022-2.3.6-CRON-HOURLY' 'FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY' 'FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY' 'FSTEC-LINUX-2022-2.3.6-CRONTAB' 'FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE' 'FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST' 'FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE' 'FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT' 'FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT' 'FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC' 'FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE' 'FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE' 'FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH' 'FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT' 'FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET' 'FSTEC-LINUX-2022-2.4.7-MITIGATIONS' 'FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN' 'FSTEC-LINUX-2022-2.5.1-VSYSCALL' 'FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR' 'FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE' 'FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID' 'FSTEC-LINUX-2022-2.5.3-DEBUGFS' 'FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED' 'FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES' 'FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED' 'FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD' 'FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD' 'FSTEC-LINUX-2022-2.5.9-TSX' 'FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE' 'FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS' 'FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS' 'FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS' 'FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR' 'FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE')

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
