#!/usr/bin/env python3
# product-sysctl-check-v2: permanent product-line read-only sysctl CHECK emitter.
# v2 adds source-faithful integer lower-bound comparison (ge) without weakening eq.
import re

SEMANTIC_CONTRACT_ID = "sysctl-check-semantic-v2"
ADAPTER_ID = "product-sysctl-check-v2"
ADAPTER_CONTRACT_VERSION = "product-sysctl-check-adapter-v2"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "sysctl"
SUPPORTED_OPS = ("eq", "ge")
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
SYSCTL_KEY_PATTERN = r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$"

def proc_path(key):
    if not isinstance(key, str) or not re.fullmatch(SYSCTL_KEY_PATTERN, key):
        raise ValueError("invalid sysctl key")
    return "/proc/sys/" + key.replace(".", "/")

def _ge_lines(emit_value):
    return [
        "  _slp_comp=FAIL",
        '  if [[ $_slp_value == "$_slp_expected" ]]; then',
        "    _slp_comp=PASS",
        '  elif [[ $_slp_value == -* && $_slp_expected != -* ]]; then',
        "    _slp_comp=FAIL",
        '  elif [[ $_slp_value != -* && $_slp_expected == -* ]]; then',
        "    _slp_comp=PASS",
        "  else",
        '    _slp_a=${_slp_value#-}',
        '    _slp_b=${_slp_expected#-}',
        '    _slp_negative=0',
        '    [[ $_slp_value == -* ]] && _slp_negative=1',
        '    if (( ${#_slp_a} != ${#_slp_b} )); then',
        '      if (( _slp_negative == 0 )); then',
        '        (( ${#_slp_a} > ${#_slp_b} )) && _slp_comp=PASS',
        '      else',
        '        (( ${#_slp_a} < ${#_slp_b} )) && _slp_comp=PASS',
        '      fi',
        "    else",
        "      _slp_cmp=0",
        "      _slp_i=0",
        '      while (( _slp_i < ${#_slp_a} )); do',
        '        _slp_ad=${_slp_a:_slp_i:1}',
        '        _slp_bd=${_slp_b:_slp_i:1}',
        '        if (( 10#$_slp_ad > 10#$_slp_bd )); then _slp_cmp=1; break; fi',
        '        if (( 10#$_slp_ad < 10#$_slp_bd )); then _slp_cmp=-1; break; fi',
        '        ((_slp_i+=1))',
        "      done",
        '      if (( _slp_negative == 0 )); then',
        '        (( _slp_cmp >= 0 )) && _slp_comp=PASS',
        "      else",
        '        (( _slp_cmp <= 0 )) && _slp_comp=PASS',
        "      fi",
        "    fi",
        "  fi",
        emit_value,
    ]

def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if "'" in control_id:
        raise ValueError("quote forbidden in emitted literal")
    if locator != "sysctl":
        raise ValueError("unsupported locator")
    if op not in SUPPORTED_OPS:
        raise ValueError("unsupported op: %r" % (op,))
    if isinstance(expected, bool) or not isinstance(expected, int):
        raise ValueError("expected must be integer")
    path = proc_path(key)
    expected_canonical = str(expected)
    cid_lit = repr(control_id)
    path_lit = repr(path)
    exp_lit = repr(expected_canonical)
    if not cid_lit.startswith("'") or not path_lit.startswith("'"):
        raise ValueError("non single-quoted shell literal")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    emit = '    printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + repr(WIRE_RECORD_ID) + " " + cid_lit
    emit_error_read = emit + ' "ERROR" "sysctl:read-failed" "ERROR"'
    emit_error_bytes = emit + ' "ERROR" "sysctl:invalid-bytes" "ERROR"'
    emit_error_value = emit + ' "ERROR" "sysctl:invalid-value" "ERROR"'
    emit_missing = emit + ' "NOT_FOUND" "-" "NOT_FOUND"'
    emit_value = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + repr(WIRE_RECORD_ID) + " " + cid_lit + ' "VALUE" "$_slp_value" "$_slp_comp"'
    lines = [
        fn + "() {",
        "  local _slp_path=" + path_lit,
        "  local _slp_expected=" + exp_lit,
        "  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp _slp_vrc=0",
        "  local _slp_a _slp_b _slp_negative _slp_cmp _slp_i _slp_ad _slp_bd",
        "  local LC_ALL=C",
        '  if [[ ! -e "$_slp_path" ]]; then', emit_missing, "    return 0", "  fi",
        "  _slp_validate_source_bytes() {",
        "    local _slp_v_path=$1 _slp_v_hex _slp_v_byte",
        '    if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi',
        "    for _slp_v_byte in $_slp_v_hex; do",
        '      [[ "$_slp_v_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || return 1',
        '      [[ "$_slp_v_byte" != 00 ]] || return 1',
        "    done",
        "    return 0",
        "  }",
        '  _slp_validate_source_bytes "$_slp_path"; _slp_vrc=$?',
        "  if (( _slp_vrc != 0 )); then",
        "    if (( _slp_vrc == 2 )); then", emit_error_read, "    else", emit_error_bytes, "    fi",
        "    return 0",
        "  fi",
        '  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then', emit_error_read, "    return 0", "  fi",
        "  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then",
        "    _slp_num=${BASH_REMATCH[1]}", "  else", emit_error_value, "    return 0", "  fi",
        "  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then", "    _slp_value=0",
        "  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then",
        "    _slp_sign=${BASH_REMATCH[1]}", "    _slp_digits=${BASH_REMATCH[3]}",
        '    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi',
        "  else", emit_error_value, "    return 0", "  fi",
    ]
    if op == "eq":
        lines.extend([
            "  _slp_comp=FAIL",
            '  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS',
            emit_value,
        ])
    else:
        lines.extend(_ge_lines(emit_value))
    lines.extend(["  return 0", "}"])
    return "\n".join(lines) + "\n"

MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod", "chown",
    "chgrp", "rm ", "mv ", "cp ", "touch ", "truncate", "dd ", ">>",
)

def _selftest():
    eq = shell_function("CTRL-EQ", "sysctl", "kernel.dmesg_restrict", "eq", 1)
    ge = shell_function("CTRL-GE", "sysctl", "vm.mmap_min_addr", "ge", 4096)
    assert "/proc/sys/kernel/dmesg_restrict" in eq
    assert "/proc/sys/vm/mmap_min_addr" in ge
    assert '} 2>/dev/null' in eq and '} 2>/dev/null' in ge
    assert "10#$_slp_ad" in ge
    assert "command /usr/bin/od -An -v -tx1" in eq and "sysctl:invalid-bytes" in eq
    for src in (eq, ge):
        od_read = '$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null)'
        assert src.count(od_read) == 1
        assert "$(" not in src.replace(od_read, "")
        for token in MUTATING_TOKENS:
            assert token not in src, token
    for bad in (
        ("CTRL-A", "/proc/sys", "kernel.x", "eq", 1),
        ("CTRL-A", "sysctl", ".kernel.x", "eq", 1),
        ("CTRL-A", "sysctl", "kernel..x", "eq", 1),
        ("CTRL-A", "sysctl", "kernel.x", "gt", 1),
        ("CTRL-A", "sysctl", "kernel.x", "eq", "1"),
        ("CTRL-A", "sysctl", "kernel.x", "ge", "4096"),
        ("CTRL-A", "sysctl", "kernel.x", "eq", True),
        ("CTRL A", "sysctl", "kernel.x", "eq", 1),
    ):
        try:
            shell_function(*bad)
        except ValueError:
            continue
        raise AssertionError("accepted: %r" % (bad,))
    print("ADAPTER_SELFTEST=PASS")

if __name__ == "__main__":
    _selftest()
