#!/usr/bin/env python3
import re
SEMANTIC_CONTRACT_ID="check-semantic-v1"
ADAPTER_ID="sysctl-check-v1"
ADAPTER_CONTRACT_VERSION="sysctl-check-adapter-v1"
TARGET_ID="ubuntu-24.04-x86_64"
def proc_path(key):
    parts=key.split('.')
    if not parts or any(not p for p in parts): raise ValueError('invalid sysctl key')
    return '/proc/sys/' + '/'.join(parts)
def shell_function(control_id,key,expected):
    if not re.fullmatch(r'[A-Za-z0-9._-]+',control_id): raise ValueError('invalid control id')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',key): raise ValueError('invalid sysctl key')
    path=proc_path(key)
    expected_canonical=str(int(expected))
    fn='slp_check_'+re.sub(r'[^A-Za-z0-9_]', '_', control_id)
    lines=[
      f'{fn}() {{',
      f'  local _slp_path={path!r}',
      f'  local _slp_expected={expected_canonical!r}',
      '  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp',
      '  if [[ ! -e "$_slp_path" ]]; then',
      '    printf "%s\t%s\t%s\t%s\t%s\n" "SLP-CHECK-V1" '+repr(control_id)+' "NOT_FOUND" "-" "NOT_FOUND"',
      '    return 0',
      '  fi',
      '  if ! IFS= read -r _slp_raw < "$_slp_path"; then',
      '    printf "%s\t%s\t%s\t%s\t%s\n" "SLP-CHECK-V1" '+repr(control_id)+' "ERROR" "-" "ERROR"',
      '    return 0',
      '  fi',
      '  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then',
      '    _slp_num=${BASH_REMATCH[1]}',
      '  else',
      '    printf "%s\t%s\t%s\t%s\t%s\n" "SLP-CHECK-V1" '+repr(control_id)+' "ERROR" "-" "ERROR"',
      '    return 0',
      '  fi',
      '  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then',
      '    _slp_value=0',
      '  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then',
      '    _slp_sign=${BASH_REMATCH[1]}',
      '    _slp_digits=${BASH_REMATCH[3]}',
      '    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi',
      '  else',
      '    printf "%s\t%s\t%s\t%s\t%s\n" "SLP-CHECK-V1" '+repr(control_id)+' "ERROR" "-" "ERROR"',
      '    return 0',
      '  fi',
      '  _slp_comp=FAIL',
      '  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS',
      '  printf "%s\t%s\t%s\t%s\t%s\n" "SLP-CHECK-V1" '+repr(control_id)+' "VALUE" "$_slp_value" "$_slp_comp"',
      '}',
    ]
    return '\n'.join(lines)+'\n'
if __name__=='__main__':
    s=shell_function('CTRL-A','kernel.dmesg_restrict',1)
    assert '/proc/sys/kernel/dmesg_restrict' in s
    assert 'sysctl -w' not in s and '$(("' not in s and '10#' not in s
    print('ADAPTER_SELFTEST=PASS')
