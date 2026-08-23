#!/usr/bin/env python3
"""Read-only adapter SRC-0004: exact active sudoers tree vs reviewed authority."""
from __future__ import annotations

import re

ADAPTER_ID = "product-sudoers-reviewed-policy-check-v1"
ADAPTER_CONTRACT_VERSION = "product-sudoers-reviewed-policy-check-adapter-v1"
PARAMETER_KIND = "sudoers-reviewed-policy"
TARGET_ID = "ubuntu-24.04-x86_64"
CANONICAL_LOCATOR = "/etc/sudoers"
CANONICAL_KEY = "policy-tree"
CANONICAL_OP = "eq-reviewed-policy"
CANONICAL_AUTHORITY = "/etc/securelinux-policy/sudoers-reviewed-policy-v1"
DEFAULT_VISUDO = "/usr/sbin/visudo"
AUTHORITY_HEADER = "SLP-SUDOERS-REVIEWED-POLICY-V1"


def _sh_single(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _fn_name(control_id: str) -> str:
    return "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)


def _render(control_id: str, root_path: str, authority_path: str, visudo_path: str) -> str:
    fn = _fn_name(control_id)
    emit = "    printf 'SLP-CHECK-V1\\t%s\\t%s\\t%s\\t%s\\n' \"$_slp_cid\""
    lines = [
        f"{fn}() {{",
        f"  local _slp_cid={_sh_single(control_id)}",
        f"  local _slp_root={_sh_single(root_path)}",
        f"  local _slp_authority={_sh_single(authority_path)}",
        f"  local _slp_visudo={_sh_single(visudo_path)}",
        "  local _slp_line _slp_path _slp_hash _slp_out _slp_rc _slp_header='' _slp_hex _slp_byte _slp_prev='' _slp_char _slp_visudo_hex",
        "  local _slp_actual_count=0 _slp_approved_count=0 _slp_mismatch=0",
        "  local -A _slp_actual=() _slp_approved=() _slp_seen=()",
        "",
        "  _slp_error() { printf 'SLP-CHECK-V1\\t%s\\tERROR\\t-\\tERROR\\n' \"$_slp_cid\"; return 0; }",
        "  _slp_validate_authority_bytes() {",
        "    local _slp_v_hex _slp_v_byte _slp_v_prev=''",
        "    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- \"$_slp_authority\" 2>/dev/null); then return 1; fi",
        "    for _slp_v_byte in $_slp_v_hex; do",
        "      [[ \"$_slp_v_byte\" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1",
        "      if [[ \"$_slp_v_prev\" == 0d && \"$_slp_v_byte\" != 0a ]]; then return 1; fi",
        "      case \"$_slp_v_byte\" in",
        "        00|01|02|03|04|05|06|07|08|0b|0c|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f|7f) return 1 ;;",
        "      esac",
        "      _slp_v_prev=$_slp_v_byte",
        "    done",
        "    [[ \"$_slp_v_prev\" != 0d ]] || return 1",
        "    return 0",
        "  }",
        "",
        "  [[ -e \"$_slp_root\" && -f \"$_slp_root\" && ! -L \"$_slp_root\" && -r \"$_slp_root\" ]] || { _slp_error; return 0; }",
        "  [[ -e \"$_slp_authority\" && -f \"$_slp_authority\" && ! -L \"$_slp_authority\" && -r \"$_slp_authority\" ]] || { _slp_error; return 0; }",
        "  [[ -x \"$_slp_visudo\" ]] || { _slp_error; return 0; }",
        "  _slp_validate_authority_bytes || { _slp_error; return 0; }",
        "",
        "  _slp_accept_visudo_line() {",
        "    local _slp_v_line=$1",
        "    [[ -n \"$_slp_v_line\" && \"$_slp_v_line\" == *': parsed OK' ]] || return 1",
        "    _slp_path=${_slp_v_line%': parsed OK'}",
        "    [[ \"$_slp_path\" == /* && \"$_slp_path\" != *$'\\t'* && \"$_slp_path\" != *$'\\r'* ]] || return 1",
        "    [[ -z \"${_slp_seen[$_slp_path]+x}\" ]] || return 1",
        "    _slp_seen[\"$_slp_path\"]=1",
        "    [[ -e \"$_slp_path\" && -f \"$_slp_path\" && ! -L \"$_slp_path\" && -r \"$_slp_path\" ]] || return 1",
        "    _slp_hash=$(LC_ALL=C command /usr/bin/sha256sum -- \"$_slp_path\" 2>/dev/null) || return 1",
        "    _slp_hash=${_slp_hash%% *}",
        "    [[ \"$_slp_hash\" =~ ^[0-9a-f]{64}$ ]] || return 1",
        "    _slp_actual[\"$_slp_path\"]=$_slp_hash",
        "    ((_slp_actual_count+=1))",
        "    return 0",
        "  }",
        "",
        "  _slp_visudo_hex=$(set -o pipefail; LC_ALL=C command \"$_slp_visudo\" -c -f \"$_slp_root\" 2>&1 | LC_ALL=C command /usr/bin/od -An -v -tx1)",
        "  _slp_rc=$?",
        "  (( _slp_rc == 0 )) || { _slp_error; return 0; }",
        "  [[ -n \"$_slp_visudo_hex\" ]] || { _slp_error; return 0; }",
        "  _slp_line=''",
        "  for _slp_byte in $_slp_visudo_hex; do",
        "    [[ \"$_slp_byte\" =~ ^[0-9a-f][0-9a-f]$ ]] || { _slp_error; return 0; }",
        "    case \"$_slp_byte\" in",
        "      0a)",
        "        _slp_accept_visudo_line \"$_slp_line\" || { _slp_error; return 0; }",
        "        _slp_line=''",
        "        ;;",
        "      00|01|02|03|04|05|06|07|08|09|0b|0c|0d|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f|7f)",
        "        _slp_error; return 0",
        "        ;;",
        "      *)",
        "        printf -v _slp_char '%b' \"\\x$_slp_byte\" || { _slp_error; return 0; }",
        "        _slp_line+=\"$_slp_char\"",
        "        ;;",
        "    esac",
        "  done",
        "  if [[ -n \"$_slp_line\" ]]; then",
        "    _slp_accept_visudo_line \"$_slp_line\" || { _slp_error; return 0; }",
        "  fi",
        "  [[ _slp_actual_count -gt 0 && -n \"${_slp_actual[$_slp_root]+x}\" ]] || { _slp_error; return 0; }",
        "",
        "  while IFS= read -r _slp_line || [[ -n \"$_slp_line\" ]]; do",
        "    if [[ \"$_slp_line\" == *$'\\r'* ]]; then",
        "      [[ \"$_slp_line\" == *$'\\r' && \"${_slp_line%$'\\r'}\" != *$'\\r'* ]] || { _slp_error; return 0; }",
        "      _slp_line=${_slp_line%$'\\r'}",
        "    fi",
        "    if [[ -z \"$_slp_header\" ]]; then",
        "      [[ \"$_slp_line\" == 'SLP-SUDOERS-REVIEWED-POLICY-V1' ]] || { _slp_error; return 0; }",
        "      _slp_header=1",
        "      continue",
        "    fi",
        "    [[ -n \"$_slp_line\" && \"$_slp_line\" == *$'\\t'* ]] || { _slp_error; return 0; }",
        "    _slp_hash=${_slp_line%%$'\\t'*}",
        "    _slp_path=${_slp_line#*$'\\t'}",
        "    [[ \"$_slp_path\" != *$'\\t'* && \"$_slp_hash\" =~ ^[0-9a-f]{64}$ && \"$_slp_path\" == /* && -n \"$_slp_path\" ]] || { _slp_error; return 0; }",
        "    [[ -z \"${_slp_approved[$_slp_path]+x}\" ]] || { _slp_error; return 0; }",
        "    _slp_approved[\"$_slp_path\"]=$_slp_hash",
        "    ((_slp_approved_count+=1))",
        "  done < \"$_slp_authority\"",
        "  [[ -n \"$_slp_header\" && _slp_approved_count -gt 0 && -n \"${_slp_approved[$_slp_root]+x}\" ]] || { _slp_error; return 0; }",
        "",
        "  for _slp_path in \"${!_slp_actual[@]}\"; do",
        "    if [[ -z \"${_slp_approved[$_slp_path]+x}\" || \"${_slp_approved[$_slp_path]}\" != \"${_slp_actual[$_slp_path]}\" ]]; then ((_slp_mismatch+=1)); fi",
        "  done",
        "  for _slp_path in \"${!_slp_approved[@]}\"; do",
        "    [[ -n \"${_slp_actual[$_slp_path]+x}\" ]] || ((_slp_mismatch+=1))",
        "  done",
        "  if (( _slp_mismatch == 0 )); then",
        "    printf 'SLP-CHECK-V1\\t%s\\tVALUE\\tfiles=%d;approved=%d;mismatch=0\\tPASS\\n' \"$_slp_cid\" \"$_slp_actual_count\" \"$_slp_approved_count\"",
        "  else",
        "    printf 'SLP-CHECK-V1\\t%s\\tVALUE\\tfiles=%d;approved=%d;mismatch=%d\\tFAIL\\n' \"$_slp_cid\" \"$_slp_actual_count\" \"$_slp_approved_count\" \"$_slp_mismatch\"",
        "  fi",
        "  return 0",
        "}",
    ]
    return "\n".join(lines) + "\n"


def shell_function_for_fixture(control_id: str, locator: str, key: str, op: str, expected: str, visudo_path: str) -> str:
    if (locator, key, op, expected) != (CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_AUTHORITY):
        raise ValueError("unsupported SRC-0004 sudoers-reviewed-policy contract")
    return _render(control_id, locator, expected, visudo_path)


def shell_function(control_id, locator, key, op, expected):
    return shell_function_for_fixture(control_id, locator, key, op, expected, DEFAULT_VISUDO)


MUTATING_TOKENS = (
    "chmod ", "chown ", "chgrp ", "rm ", "mv ", "cp ", "touch ", "tee ",
    "install ", "truncate ", "dd ", "sysctl -w", "setfacl ", "ln ", "mkdir ",
    ">>", "sed -i", "visudo -f", "visudo -cf /tmp", "systemctl ",
)


def _selftest():
    src = shell_function("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_AUTHORITY)
    assert "visudo" in src and "sha256sum" in src and "SLP-SUDOERS-REVIEWED-POLICY-V1" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    bad = (
        ("/tmp/sudoers", CANONICAL_KEY, CANONICAL_OP, CANONICAL_AUTHORITY),
        (CANONICAL_LOCATOR, "users", CANONICAL_OP, CANONICAL_AUTHORITY),
        (CANONICAL_LOCATOR, CANONICAL_KEY, "eq", CANONICAL_AUTHORITY),
        (CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, "/tmp/policy"),
    )
    for args in bad:
        try:
            shell_function("CTRL", *args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
