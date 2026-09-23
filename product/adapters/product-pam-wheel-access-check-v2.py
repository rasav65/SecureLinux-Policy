#!/usr/bin/env python3
"""Read-only adapter SRC-0003: PAM su rule + local wheel membership."""
from __future__ import annotations

import re

ADAPTER_ID = "product-pam-wheel-access-check-v2"
ADAPTER_CONTRACT_VERSION = "product-pam-wheel-access-check-adapter-v2"
PARAMETER_KIND = "pam-wheel-access"
TARGET_ID = "linux-x86_64-supported-v1"
CANONICAL_LOCATOR = "/etc/pam.d/su|/etc/group"
CANONICAL_KEY = "policy"
CANONICAL_OP = "pam-wheel-root-member"
CANONICAL_EXPECTED = "auth required pam_wheel.so use_uid;wheel:root"


def _sh_single(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _fn_name(control_id: str) -> str:
    return "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)


def _render(control_id: str, pam_path: str, group_path: str) -> str:
    fn = _fn_name(control_id)
    return "\n".join([
        f"{fn}() {{",
        f"  local _slp_cid={_sh_single(control_id)}",
        f"  local _slp_pam={_sh_single(pam_path)}",
        f"  local _slp_group={_sh_single(group_path)}",
        "  local _slp_line _slp_logical='' _slp_trim _slp_module _slp_control _slp_type _slp_gid='' _slp_members='' _slp_name _slp_pam_text _slp_group_text _slp_rest",
        "  local _slp_parent= _slp_pam_field _slp_wheel_field _slp_root_field _slp_comp",
        "  local -a _slp_tok=() _slp_members_arr=()",
        "  local -A _slp_actual=()",
        "  local _slp_exact=0 _slp_nouid=0 _slp_other=0 _slp_wheel=0 _slp_error=0 _slp_midx=0 _slp_i=0 _slp_vrc=0 _slp_hazard=0",
        "",
        "  _slp_name_has_forbidden_separator() {",
        "    local _slp_n=$1",
        "    case \"$_slp_n\" in",
        "      *' '*|*$'\\t'*|*$'\\r'*|*$'\\v'*|*$'\\f'*|*$'\\x7f'*|*:*|*','*|*'#'*) return 0 ;;",
        "      *$'\\xc2\\x85'*|*$'\\xc2\\xa0'*|*$'\\xe1\\x9a\\x80'*|*$'\\xe2\\x80\\x80'*|*$'\\xe2\\x80\\x81'*|*$'\\xe2\\x80\\x82'*|*$'\\xe2\\x80\\x83'*|*$'\\xe2\\x80\\x84'*|*$'\\xe2\\x80\\x85'*|*$'\\xe2\\x80\\x86'*|*$'\\xe2\\x80\\x87'*|*$'\\xe2\\x80\\x88'*|*$'\\xe2\\x80\\x89'*|*$'\\xe2\\x80\\x8a'*|*$'\\xe2\\x80\\xa8'*|*$'\\xe2\\x80\\xa9'*|*$'\\xe2\\x80\\xaf'*|*$'\\xe2\\x81\\x9f'*|*$'\\xe3\\x80\\x80'*) return 0 ;;",
        "    esac",
        "    return 1",
        "  }",
        "",
        "  if [[ -L \"$_slp_pam\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\tpam:symlink\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  if [[ -L \"$_slp_group\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\tgroup:symlink\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  if [[ ! -e \"$_slp_pam\" ]]; then",
        "    _slp_parent=${_slp_pam%/*}; [[ -z $_slp_parent ]] && _slp_parent=/",
        "    [[ -d $_slp_parent && -x $_slp_parent ]] || {",
        "      printf 'SLP-CHECK-V1\\t%s\\tERROR\\tpam:read-failed\\tERROR\\n' \"$_slp_cid\"",
        "      return 0",
        "    }",
        "  fi",
        "  if [[ ! -e \"$_slp_group\" ]]; then",
        "    _slp_parent=${_slp_group%/*}; [[ -z $_slp_parent ]] && _slp_parent=/",
        "    [[ -d $_slp_parent && -x $_slp_parent ]] || {",
        "      printf 'SLP-CHECK-V1\\t%s\\tERROR\\tgroup:read-failed\\tERROR\\n' \"$_slp_cid\"",
        "      return 0",
        "    }",
        "  fi",
        "  if [[ ! -e \"$_slp_pam\" || ! -e \"$_slp_group\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tNOT_FOUND\\t-\\tFAIL\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  if [[ ! -f \"$_slp_pam\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\tpam:invalid-type\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  if [[ ! -r \"$_slp_pam\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\tpam:unreadable\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  if [[ ! -f \"$_slp_group\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\tgroup:invalid-type\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  if [[ ! -r \"$_slp_group\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\tgroup:unreadable\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        # Файл читается один раз: проверенные `od` байты декодируются в текст, который затем
        # разбирается; повторного открытия файла (и потери ошибки перенаправления) нет.
        "  _slp_load_text() {",
        "    local _slp_v_path=$1 _slp_v_out=$2 _slp_v_hex _slp_v_byte _slp_v_prev='' _slp_v_esc",
        '    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi',
        "    for _slp_v_byte in $_slp_v_hex; do",
        '      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1',
        '      [[ "$_slp_v_byte" != 00 ]] || return 1',
        '      if [[ "$_slp_v_prev" == 0d && "$_slp_v_byte" != 0a ]]; then return 1; fi',
        "      _slp_v_prev=$_slp_v_byte",
        "    done",
        '    [[ "$_slp_v_prev" != 0d ]] || return 1',
        "    if [[ -z $_slp_v_hex ]]; then",
        '      printf -v "$_slp_v_out" %s ""',
        "      return 0",
        "    fi",
        r"        _slp_v_esc=$(printf '\\x%s' $_slp_v_hex)",
        '    printf -v "$_slp_v_out" %b "$_slp_v_esc"',
        "    return 0",
        "  }",
        '  _slp_load_text "$_slp_pam" _slp_pam_text; _slp_vrc=$?',
        '  if (( _slp_vrc != 0 )); then',
        "    if (( _slp_vrc == 2 )); then printf 'SLP-CHECK-V1\\t%s\\tERROR\\tpam:read-failed\\tERROR\\n' \"$_slp_cid\"; else printf 'SLP-CHECK-V1\\t%s\\tERROR\\tpam:invalid-bytes\\tERROR\\n' \"$_slp_cid\"; fi",
        "    return 0",
        "  fi",
        '  _slp_load_text "$_slp_group" _slp_group_text; _slp_vrc=$?',
        '  if (( _slp_vrc != 0 )); then',
        "    if (( _slp_vrc == 2 )); then printf 'SLP-CHECK-V1\\t%s\\tERROR\\tgroup:read-failed\\tERROR\\n' \"$_slp_cid\"; else printf 'SLP-CHECK-V1\\t%s\\tERROR\\tgroup:invalid-bytes\\tERROR\\n' \"$_slp_cid\"; fi",
        "    return 0",
        "  fi",
        "",
        "  _slp_rest=$_slp_pam_text",
        "  while [[ -n $_slp_rest ]]; do",
        "    if [[ $_slp_rest == *$'\\n'* ]]; then _slp_line=${_slp_rest%%$'\\n'*}; _slp_rest=${_slp_rest#*$'\\n'}; else _slp_line=$_slp_rest; _slp_rest=''; fi",
        "    if [[ \"$_slp_line\" == *$'\\r'* ]]; then",
        "      if [[ \"$_slp_line\" != *$'\\r' || \"${_slp_line%$'\\r'}\" == *$'\\r'* ]]; then _slp_error=1; break; fi",
        "      _slp_line=${_slp_line%$'\\r'}",
        "    fi",
        "    _slp_line=${_slp_line%%#*}",
        "    if [[ \"$_slp_line\" == *\\\\ ]]; then",
        "      _slp_logical+=${_slp_line%\\\\}",
        "      continue",
        "    fi",
        "    _slp_logical+=\"$_slp_line\"",
        "    _slp_trim=${_slp_logical#\"${_slp_logical%%[!$' \\t']*}\"}",
        "    _slp_trim=${_slp_trim%\"${_slp_trim##*[!$' \\t']}\"}",
        "    _slp_logical=''",
        "    [[ -n \"$_slp_trim\" ]] || continue",
        "    read -r -a _slp_tok <<< \"$_slp_trim\"",
        "    if [[ \"${_slp_tok[0]}\" == @include ]]; then",
        "      (( ${#_slp_tok[@]} == 2 )) || { _slp_error=1; break; }",
        "      (( _slp_exact > 0 )) || _slp_hazard=1",
        "      continue",
        "    fi",
        "    (( ${#_slp_tok[@]} >= 3 )) || { _slp_error=1; break; }",
        "    _slp_type=${_slp_tok[0],,}",
        "    _slp_type=${_slp_type#-}",
        "    _slp_control=${_slp_tok[1],,}",
        # Штатная `auth sufficient pam_rootok.so` (ровно три токена, без `-`)
        # пропускает только root и перед pam_wheel опасной не считается.
        "    if (( _slp_exact == 0 )) && [[ \"$_slp_type\" == auth ]]; then",
        "      if [[ \"${_slp_tok[0],,}\" == auth && \"$_slp_control\" == sufficient && ${#_slp_tok[@]} -eq 3 && \"${_slp_tok[2]}\" == pam_rootok.so ]]; then",
        "        :",
        "      elif [[ \"$_slp_control\" == sufficient || \"$_slp_control\" == include || \"$_slp_control\" == substack || \"$_slp_control\" == \\[* ]]; then",
        "        _slp_hazard=1",
        "      fi",
        "    fi",
        "    _slp_midx=2",
        "    if [[ \"$_slp_control\" == \\[* ]]; then",
        "      _slp_midx=0",
        "      for ((_slp_i=1; _slp_i<${#_slp_tok[@]}; _slp_i++)); do",
        "        if [[ \"${_slp_tok[_slp_i]}\" == *\\] ]]; then _slp_midx=$((_slp_i+1)); break; fi",
        "      done",
        "      (( _slp_midx > 0 && _slp_midx < ${#_slp_tok[@]} )) || { _slp_error=1; break; }",
        "    fi",
        "    _slp_module=${_slp_tok[_slp_midx]}",
        "    if [[ \"${_slp_module##*/}\" == pam_wheel.so ]]; then",
        # auth required pam_wheel.so: ровно `use_uid` — эталон; без `use_uid`
        # среди аргументов — FAIL no-use_uid; прочие формы — неоднозначность.
        "      if [[ \"${_slp_tok[0],,}\" == auth && \"${_slp_tok[1],,}\" == required && \"$_slp_module\" == pam_wheel.so ]]; then",
        "        if (( ${#_slp_tok[@]} == 4 )) && [[ \"${_slp_tok[3]}\" == use_uid ]]; then",
        "          ((_slp_exact+=1))",
        "        else",
        "          ((_slp_nouid+=1))",
        "          for ((_slp_i=3; _slp_i<${#_slp_tok[@]}; _slp_i++)); do",
        "            if [[ \"${_slp_tok[_slp_i]}\" == use_uid ]]; then ((_slp_nouid-=1)); ((_slp_other+=1)); break; fi",
        "          done",
        "        fi",
        "      else",
        "        ((_slp_other+=1))",
        "      fi",
        "    fi",
        "  done",
        "  [[ -z \"$_slp_logical\" ]] || _slp_error=1",
        "  if (( _slp_error || _slp_other > 0 || (_slp_hazard && _slp_exact > 0) || (_slp_nouid > 0 && _slp_exact > 0) )); then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\tpam:ambiguous-stack\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "",
        "  _slp_rest=$_slp_group_text",
        "  while [[ -n $_slp_rest ]]; do",
        "    if [[ $_slp_rest == *$'\\n'* ]]; then _slp_line=${_slp_rest%%$'\\n'*}; _slp_rest=${_slp_rest#*$'\\n'}; else _slp_line=$_slp_rest; _slp_rest=''; fi",
        "    if [[ \"$_slp_line\" == *$'\\r'* ]]; then",
        "      if [[ \"$_slp_line\" != *$'\\r' || \"${_slp_line%$'\\r'}\" == *$'\\r'* ]]; then _slp_error=1; break; fi",
        "      _slp_line=${_slp_line%$'\\r'}",
        "    fi",
        # Группа wheel ищется по имени; номер gid не оценивается.
        "    [[ \"$_slp_line\" == wheel:* ]] || continue",
        "    ((_slp_wheel+=1))",
        "    if [[ \"$_slp_line\" =~ ^wheel:([^:]*):([0-9]+):([^:]*)$ ]]; then",
        "      _slp_gid=${BASH_REMATCH[2]}",
        "      _slp_members=${BASH_REMATCH[3]}",
        "    else",
        "      _slp_error=1",
        "    fi",
        "  done",
        "  if (( _slp_error || _slp_wheel > 1 )); then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\tgroup:invalid-record\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  if (( _slp_wheel == 1 )) && [[ -n \"$_slp_members\" ]]; then",
        "    if [[ \"$_slp_members\" == ,* || \"$_slp_members\" == *, || \"$_slp_members\" == *,,* ]]; then _slp_error=1; fi",
        "    IFS=',' read -r -a _slp_members_arr <<< \"$_slp_members\"",
        "    for _slp_name in \"${_slp_members_arr[@]}\"; do",
        "      if [[ -z \"$_slp_name\" ]] || _slp_name_has_forbidden_separator \"$_slp_name\" || [[ -n \"${_slp_actual[$_slp_name]+x}\" ]]; then _slp_error=1; break; fi",
        "      _slp_actual[\"$_slp_name\"]=1",
        "    done",
        "  fi",
        "  if (( _slp_error )); then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\tgroup:invalid-members\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "",
        # Стек и /etc/group разобраны: payload перечисляет все три условия,
        # чтобы при FAIL было видно, чего не хватает. Прочие участники wheel
        # не оцениваются.
        "  if (( _slp_exact > 0 )); then _slp_pam_field=present; elif (( _slp_nouid > 0 )); then _slp_pam_field=no-use_uid; else _slp_pam_field=absent; fi",
        "  if (( _slp_wheel == 1 )); then printf -v _slp_wheel_field 'gid %s' \"$_slp_gid\"; else _slp_wheel_field=absent; fi",
        "  if [[ -n \"${_slp_actual[root]+x}\" ]]; then _slp_root_field=member; else _slp_root_field=missing; fi",
        "  if [[ $_slp_pam_field == present && $_slp_wheel_field != absent && $_slp_root_field == member ]]; then _slp_comp=PASS; else _slp_comp=FAIL; fi",
        "  printf 'SLP-CHECK-V1\\t%s\\tVALUE\\tpam_wheel=%s;wheel=%s;root=%s\\t%s\\n' \"$_slp_cid\" \"$_slp_pam_field\" \"$_slp_wheel_field\" \"$_slp_root_field\" \"$_slp_comp\"",
        "  return 0",
        "}",
    ]) + "\n"


def shell_function(control_id, locator, key, op, expected):
    if (locator, key, op, expected) != (CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED):
        raise ValueError("unsupported SRC-0003 pam-wheel-access contract")
    return _render(control_id, "/etc/pam.d/su", "/etc/group")


def _shell_function_for_fixture(control_id, pam_path, group_path):
    return _render(control_id, pam_path, group_path)


def main() -> int:
    block = shell_function(
        "FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS",
        CANONICAL_LOCATOR,
        CANONICAL_KEY,
        CANONICAL_OP,
        CANONICAL_EXPECTED,
    )
    for token in ("chmod ", "chown ", "groupadd ", "groupdel ", "gpasswd ", "usermod ", ">>"):
        assert token not in block
    assert "pam_wheel.so" in block and "wheel:" in block
    print("ADAPTER_SELFTEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
