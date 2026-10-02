#!/usr/bin/env python3
# product-sysctl-check-v1: permanent product-line read-only sysctl CHECK emitter.
# Historical Step7B0 admitted bytes remain separate with adapter_id sysctl-check-v1.
import re

SEMANTIC_CONTRACT_ID = "sysctl-check-semantic-v1"
ADAPTER_ID = "product-sysctl-check-v1"
ADAPTER_CONTRACT_VERSION = "product-sysctl-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "sysctl"
SUPPORTED_OPS = ("eq",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
SYSCTL_KEY_PATTERN = r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$"

def proc_path(key):
    if not isinstance(key, str) or not re.fullmatch(SYSCTL_KEY_PATTERN, key):
        raise ValueError("invalid sysctl key")
    return "/proc/sys/" + key.replace(".", "/")

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
    emit_error = emit + ' "ERROR" "-" "ERROR"'
    emit_missing = emit + ' "NOT_FOUND" "-" "NOT_FOUND"'
    emit_value = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + repr(WIRE_RECORD_ID) + " " + cid_lit + ' "VALUE" "$_slp_value" "$_slp_comp"'
    lines = [
        fn + "() {",
        "  local _slp_path=" + path_lit,
        "  local _slp_expected=" + exp_lit,
        "  local _slp_raw _slp_num _slp_sign _slp_digits _slp_value _slp_comp",
        '  if [[ ! -e "$_slp_path" ]]; then', emit_missing, "    return 0", "  fi",
        '  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then', emit_error, "    return 0", "  fi",
        "  if [[ $_slp_raw =~ ^[[:space:]]*([+-]?[0-9]+)[[:space:]]*$ ]]; then",
        "    _slp_num=${BASH_REMATCH[1]}", "  else", emit_error, "    return 0", "  fi",
        "  if [[ $_slp_num =~ ^[+-]?0+$ ]]; then", "    _slp_value=0",
        "  elif [[ $_slp_num =~ ^([+-]?)(0*)([1-9][0-9]*)$ ]]; then",
        "    _slp_sign=${BASH_REMATCH[1]}", "    _slp_digits=${BASH_REMATCH[3]}",
        '    if [[ $_slp_sign == - ]]; then _slp_value="-$_slp_digits"; else _slp_value="$_slp_digits"; fi',
        "  else", emit_error, "    return 0", "  fi",
        "  _slp_comp=FAIL", '  [[ $_slp_value == "$_slp_expected" ]] && _slp_comp=PASS', emit_value, "  return 0", "}",
    ]
    return "\n".join(lines) + "\n"

MUTATING_TOKENS = ("sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod", "chown", "chgrp", "rm ", "mv ", "cp ", "touch ", "truncate", "dd ", ">>")

def _selftest():
    src = shell_function("CTRL-A", "sysctl", "kernel.dmesg_restrict", "eq", 1)
    assert "/proc/sys/kernel/dmesg_restrict" in src
    assert '} 2>/dev/null' in src
    assert "$(" not in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    for bad in (("CTRL-A", "/proc/sys", "kernel.dmesg_restrict", "eq", 1), ("CTRL-A", "sysctl", ".kernel.x", "eq", 1), ("CTRL-A", "sysctl", "kernel..x", "eq", 1), ("CTRL-A", "sysctl", "kernel.x", "ge", 1), ("CTRL-A", "sysctl", "kernel.x", "eq", "1"), ("CTRL-A", "sysctl", "kernel.x", "eq", True), ("CTRL A", "sysctl", "kernel.x", "eq", 1)):
        try:
            shell_function(*bad)
        except ValueError:
            continue
        raise AssertionError("accepted: %r" % (bad,))
    print("ADAPTER_SELFTEST=PASS")

if __name__ == "__main__":
    _selftest()
