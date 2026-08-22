#!/usr/bin/env python3
"""Read-only adapter SRC-0003: PAM su rule + local wheel membership."""
from __future__ import annotations

import re

ADAPTER_ID = "product-pam-wheel-access-check-v1"
ADAPTER_CONTRACT_VERSION = "product-pam-wheel-access-check-adapter-v1"
PARAMETER_KIND = "pam-wheel-access"
TARGET_ID = "ubuntu-24.04-x86_64"
CANONICAL_LOCATOR = "/etc/pam.d/su|/etc/group"
CANONICAL_KEY = "policy"
CANONICAL_OP = "eq-authority-file"
CANONICAL_AUTHORITY = "/etc/securelinux-policy/wheel-users.allowlist-v1"


def _sh_single(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _fn_name(control_id: str) -> str:
    return "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)


def _render(control_id: str, pam_path: str, group_path: str, authority_path: str) -> str:
    fn = _fn_name(control_id)
    return "\n".join([
        f"{fn}() {{",
        f"  local _slp_cid={_sh_single(control_id)}",
        f"  local _slp_pam={_sh_single(pam_path)}",
        f"  local _slp_group={_sh_single(group_path)}",
        f"  local _slp_authority={_sh_single(authority_path)}",
        "  local _slp_line _slp_logical='' _slp_trim _slp_module _slp_control _slp_gid='' _slp_members='' _slp_name",
        "  local -a _slp_tok=() _slp_members_arr=()",
        "  local -A _slp_actual=() _slp_approved=()",
        "  local _slp_exact=0 _slp_other=0 _slp_wheel=0 _slp_error=0 _slp_mismatch=0 _slp_midx=0 _slp_i=0",
        "",
        "  if [[ -L \"$_slp_pam\" || -L \"$_slp_group\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  if [[ ! -e \"$_slp_pam\" || ! -e \"$_slp_group\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tNOT_FOUND\\t-\\tFAIL\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  if [[ ! -f \"$_slp_pam\" || ! -r \"$_slp_pam\" || ! -f \"$_slp_group\" || ! -r \"$_slp_group\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "",
        "  while IFS= read -r _slp_line || [[ -n \"$_slp_line\" ]]; do",
        "    [[ \"$_slp_line\" != *$'\\r' ]] || _slp_line=${_slp_line%$'\\r'}",
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
        "      continue",
        "    fi",
        "    (( ${#_slp_tok[@]} >= 3 )) || { _slp_error=1; break; }",
        "    _slp_control=${_slp_tok[1],,}",
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
        "      if [[ \"${_slp_tok[0],,}\" == auth && \"${_slp_tok[1],,}\" == required && \"$_slp_module\" == pam_wheel.so && ${#_slp_tok[@]} -eq 4 && \"${_slp_tok[3]}\" == use_uid ]]; then",
        "        ((_slp_exact+=1))",
        "      else",
        "        ((_slp_other+=1))",
        "      fi",
        "    fi",
        "  done < \"$_slp_pam\"",
        "  [[ -z \"$_slp_logical\" ]] || _slp_error=1",
        "  if (( _slp_error || _slp_other > 0 )); then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "",
        "  while IFS= read -r _slp_line || [[ -n \"$_slp_line\" ]]; do",
        "    [[ \"$_slp_line\" != *$'\\r' ]] || _slp_line=${_slp_line%$'\\r'}",
        "    [[ \"$_slp_line\" == wheel:* ]] || continue",
        "    ((_slp_wheel+=1))",
        "    if [[ \"$_slp_line\" =~ ^wheel:([^:]*):([0-9]+):([^:]*)$ ]]; then",
        "      _slp_gid=${BASH_REMATCH[2]}",
        "      _slp_members=${BASH_REMATCH[3]}",
        "    else",
        "      _slp_error=1",
        "    fi",
        "  done < \"$_slp_group\"",
        "  if (( _slp_error || _slp_wheel > 1 )); then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  if (( _slp_wheel == 1 )) && [[ -n \"$_slp_members\" ]]; then",
        "    if [[ \"$_slp_members\" == ,* || \"$_slp_members\" == *, || \"$_slp_members\" == *,,* ]]; then _slp_error=1; fi",
        "    IFS=',' read -r -a _slp_members_arr <<< \"$_slp_members\"",
        "    for _slp_name in \"${_slp_members_arr[@]}\"; do",
        "      if [[ -z \"$_slp_name\" || \"$_slp_name\" == *[[:space:]:#]* || -n \"${_slp_actual[$_slp_name]+x}\" ]]; then _slp_error=1; break; fi",
        "      _slp_actual[\"$_slp_name\"]=1",
        "    done",
        "  fi",
        "  if (( _slp_error )); then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "",
        "  if (( _slp_exact == 0 || _slp_wheel == 0 )); then",
        "    printf 'SLP-CHECK-V1\\t%s\\tVALUE\\tpam_exact=%d;wheel=%d;members=%d;authority=not-needed\\tFAIL\\n' \"$_slp_cid\" \"$_slp_exact\" \"$_slp_wheel\" \"${#_slp_actual[@]}\"",
        "    return 0",
        "  fi",
        "  if [[ -z \"${_slp_actual[root]+x}\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tVALUE\\tpam_exact=%d;wheel=1;members=%d;root=missing;authority=not-needed\\tFAIL\\n' \"$_slp_cid\" \"$_slp_exact\" \"${#_slp_actual[@]}\"",
        "    return 0",
        "  fi",
        "",
        "  if [[ ! -e \"$_slp_authority\" || ! -f \"$_slp_authority\" || -L \"$_slp_authority\" || ! -r \"$_slp_authority\" ]]; then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "  while IFS= read -r _slp_line || [[ -n \"$_slp_line\" ]]; do",
        "    [[ \"$_slp_line\" != *$'\\r' ]] || _slp_line=${_slp_line%$'\\r'}",
        "    [[ -n \"$_slp_line\" ]] || continue",
        "    [[ \"${_slp_line:0:1}\" != \\# ]] || continue",
        "    if [[ \"$_slp_line\" == root || \"$_slp_line\" == *[[:space:],:#]* || -n \"${_slp_approved[$_slp_line]+x}\" ]]; then _slp_error=1; break; fi",
        "    _slp_approved[\"$_slp_line\"]=1",
        "  done < \"$_slp_authority\"",
        "  if (( _slp_error )); then",
        "    printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"",
        "    return 0",
        "  fi",
        "",
        "  for _slp_name in \"${!_slp_approved[@]}\"; do",
        "    [[ -n \"${_slp_actual[$_slp_name]+x}\" ]] || ((_slp_mismatch+=1))",
        "  done",
        "  for _slp_name in \"${!_slp_actual[@]}\"; do",
        "    if [[ \"$_slp_name\" != root && -z \"${_slp_approved[$_slp_name]+x}\" ]]; then ((_slp_mismatch+=1)); fi",
        "  done",
        "  if (( _slp_mismatch == 0 )); then",
        "    printf 'SLP-CHECK-V1\\t%s\\tVALUE\\tpam_exact=%d;wheel=1;gid=%s;members=%d;approved=%d;mismatch=0\\tPASS\\n' \"$_slp_cid\" \"$_slp_exact\" \"$_slp_gid\" \"${#_slp_actual[@]}\" \"${#_slp_approved[@]}\"",
        "  else",
        "    printf 'SLP-CHECK-V1\\t%s\\tVALUE\\tpam_exact=%d;wheel=1;gid=%s;members=%d;approved=%d;mismatch=%d\\tFAIL\\n' \"$_slp_cid\" \"$_slp_exact\" \"$_slp_gid\" \"${#_slp_actual[@]}\" \"${#_slp_approved[@]}\" \"$_slp_mismatch\"",
        "  fi",
        "  return 0",
        "}",
    ]) + "\n"


def shell_function(control_id, locator, key, op, expected):
    if (locator, key, op, expected) != (CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_AUTHORITY):
        raise ValueError("unsupported SRC-0003 pam-wheel-access contract")
    return _render(control_id, "/etc/pam.d/su", "/etc/group", expected)


def _shell_function_for_fixture(control_id, pam_path, group_path, authority_path):
    return _render(control_id, pam_path, group_path, authority_path)


def main() -> int:
    block = shell_function(
        "FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS",
        CANONICAL_LOCATOR,
        CANONICAL_KEY,
        CANONICAL_OP,
        CANONICAL_AUTHORITY,
    )
    for token in ("chmod ", "chown ", "groupadd ", "groupdel ", "gpasswd ", "usermod ", ">>"):
        assert token not in block
    assert "pam_wheel.so" in block and "wheel:" in block
    print("ADAPTER_SELFTEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
