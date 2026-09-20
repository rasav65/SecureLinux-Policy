#!/usr/bin/env python3
# product-kernel-cmdline-check-v2: read-only exact /proc/cmdline observer.
import re

SEMANTIC_CONTRACT_ID = "kernel-cmdline-check-semantic-v2"
ADAPTER_ID = "product-kernel-cmdline-check-v2"
ADAPTER_CONTRACT_VERSION = "product-kernel-cmdline-check-adapter-v2"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "kernel-cmdline"
SUPPORTED_OPS = ("eq", "present", "one-of")
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
KEY_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9_.-]+$"
VALUE_PATTERN = r"^(?!.*[\r\n\t ])[A-Za-z0-9_.,:+/-]+$"
ONE_OF_PATTERN = r"^(?!.*[\r\n\t ])[A-Za-z0-9_.,:+/-]+(?:\|[A-Za-z0-9_.,:+/-]+)+$"
LOCATOR = "/proc/cmdline"

def _model(tokens, key, op, expected):
    bare = 0
    values = []
    prefix = key + "="
    for token in tokens:
        if token == key:
            bare += 1
        elif token.startswith(prefix):
            values.append(token[len(prefix):])
    if op == "present":
        if values:
            return ("ERROR", "cmdline:unexpected-value-form", "ERROR")
        return ("VALUE", "true" if bare else "false", "PASS" if bare else "FAIL")
    if bare:
        return ("ERROR", "cmdline:ambiguous-value", "ERROR")
    if not values:
        return ("VALUE", "<absent>", "FAIL")
    first = values[0]
    if any(value != first for value in values[1:]):
        return ("ERROR", "cmdline:ambiguous-value", "ERROR")
    if op == "eq":
        return ("VALUE", first, "PASS" if first == expected else "FAIL")
    choices = expected.split("|")
    return ("VALUE", first, "PASS" if first in choices else "FAIL")

def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if locator != LOCATOR:
        raise ValueError("unsupported locator")
    if not isinstance(key, str) or not re.fullmatch(KEY_PATTERN, key):
        raise ValueError("invalid kernel cmdline key")
    if op not in SUPPORTED_OPS:
        raise ValueError("unsupported op")
    if op == "eq":
        if not isinstance(expected, str) or not re.fullmatch(VALUE_PATTERN, expected):
            raise ValueError("eq expected must be one safe nonempty token value")
    elif op == "one-of":
        if not isinstance(expected, str) or not re.fullmatch(ONE_OF_PATTERN, expected):
            raise ValueError("one-of expected must be 2+ safe token values joined by |")
    else:
        if expected is not True:
            raise ValueError("present expected must be boolean true")

    cid_lit = repr(control_id)
    key_lit = repr(key)
    exp_lit = repr(expected if isinstance(expected, str) else "true")
    path_lit = repr(LOCATOR)
    for lit in (cid_lit, key_lit, exp_lit, path_lit):
        if not lit.startswith("'"):
            raise ValueError("non single-quoted shell literal")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + repr(WIRE_RECORD_ID) + " " + cid_lit
    lines = [
        fn + "() {",
        "  local _slp_path=" + path_lit,
        "  local _slp_key=" + key_lit,
        "  local _slp_expected=" + exp_lit,
        "  local _slp_raw _slp_token _slp_value _slp_first _slp_choice _slp_comp _slp_vrc=0",
        "  local _slp_bare=0 _slp_values=0 _slp_conflict=0 _slp_parent=",
        "  local -a _slp_tokens=() _slp_choices=()",
        '  if [[ ! -e "$_slp_path" ]]; then',
        '    _slp_parent=${_slp_path%/*}',
        '    [[ -z $_slp_parent ]] && _slp_parent=/',
        '    if [[ -d $_slp_parent && -x $_slp_parent && ! -L "$_slp_path" ]]; then',
        emit + ' "NOT_FOUND" "-" "NOT_FOUND"',
        "    else",
        emit + ' "ERROR" "cmdline:read-failed" "ERROR"',
        "    fi",
        "    return 0",
        "  fi",
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
        "    if (( _slp_vrc == 2 )); then",
        emit + ' "ERROR" "cmdline:read-failed" "ERROR"',
        "    else",
        emit + ' "ERROR" "cmdline:invalid-bytes" "ERROR"',
        "    fi",
        "    return 0",
        "  fi",
        '  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then',
        emit + ' "ERROR" "cmdline:read-failed" "ERROR"',
        "    return 0",
        "  fi",
        '  IFS=$\' \\t\\r\\n\' read -r -a _slp_tokens <<< "$_slp_raw"',
        '  for _slp_token in "${_slp_tokens[@]}"; do',
        '    if [[ $_slp_token == "$_slp_key" ]]; then',
        "      ((_slp_bare+=1))",
        '    elif [[ $_slp_token == "$_slp_key="* ]]; then',
        '      _slp_value=${_slp_token#*=}',
        "      if (( _slp_values == 0 )); then",
        '        _slp_first=$_slp_value',
        '      elif [[ $_slp_value != "$_slp_first" ]]; then',
        "        _slp_conflict=1",
        "      fi",
        "      ((_slp_values+=1))",
        "    fi",
        "  done",
    ]
    if op == "present":
        lines.extend([
            "  if (( _slp_values > 0 )); then",
            emit + ' "ERROR" "cmdline:unexpected-value-form" "ERROR"',
            "    return 0",
            "  fi",
            "  if (( _slp_bare > 0 )); then",
            emit + ' "VALUE" "true" "PASS"',
            "  else",
            emit + ' "VALUE" "false" "FAIL"',
            "  fi",
        ])
    elif op == "eq":
        lines.extend([
            "  if (( _slp_bare > 0 || _slp_conflict > 0 )); then",
            emit + ' "ERROR" "cmdline:ambiguous-value" "ERROR"',
            "    return 0",
            "  fi",
            "  if (( _slp_values == 0 )); then",
            emit + ' "VALUE" "<absent>" "FAIL"',
            "    return 0",
            "  fi",
            "  _slp_comp=FAIL",
            '  [[ $_slp_first == "$_slp_expected" ]] && _slp_comp=PASS',
            emit + ' "VALUE" "$_slp_first" "$_slp_comp"',
        ])
    else:
        lines.extend([
            "  if (( _slp_bare > 0 || _slp_conflict > 0 )); then",
            emit + ' "ERROR" "cmdline:ambiguous-value" "ERROR"',
            "    return 0",
            "  fi",
            "  if (( _slp_values == 0 )); then",
            emit + ' "VALUE" "<absent>" "FAIL"',
            "    return 0",
            "  fi",
            "  _slp_comp=FAIL",
            '  IFS=\'|\' read -r -a _slp_choices <<< "$_slp_expected"',
            '  for _slp_choice in "${_slp_choices[@]}"; do',
            '    if [[ $_slp_first == "$_slp_choice" ]]; then',
            "      _slp_comp=PASS",
            "      break",
            "    fi",
            "  done",
            emit + ' "VALUE" "$_slp_first" "$_slp_comp"',
        ])
    lines.extend(["  return 0", "}"])
    return "\n".join(lines) + "\n"

MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod", "chown",
    "chgrp", "rm ", "mv ", "cp ", "touch ", "truncate", "dd ", ">>",
)

def _selftest():
    cases = [
        (["init_on_alloc=1"], "init_on_alloc", "eq", "1", ("VALUE","1","PASS")),
        (["init_on_alloc=0"], "init_on_alloc", "eq", "1", ("VALUE","0","FAIL")),
        ([], "init_on_alloc", "eq", "1", ("VALUE","<absent>","FAIL")),
        (["iommu=force","iommu=force"], "iommu", "eq", "force", ("VALUE","force","PASS")),
        (["iommu=force","iommu=pt"], "iommu", "eq", "force", ("ERROR","cmdline:ambiguous-value","ERROR")),
        (["iommu","iommu=force"], "iommu", "eq", "force", ("ERROR","cmdline:ambiguous-value","ERROR")),
        (["slab_nomerge"], "slab_nomerge", "present", True, ("VALUE","true","PASS")),
        ([], "slab_nomerge", "present", True, ("VALUE","false","FAIL")),
        (["slab_nomerge=1"], "slab_nomerge", "present", True, ("ERROR","cmdline:unexpected-value-form","ERROR")),
        (["debugfs=off"], "debugfs", "one-of", "off|no-mount", ("VALUE","off","PASS")),
        (["debugfs=no-mount"], "debugfs", "one-of", "off|no-mount", ("VALUE","no-mount","PASS")),
        (["debugfs=on"], "debugfs", "one-of", "off|no-mount", ("VALUE","on","FAIL")),
        ([], "debugfs", "one-of", "off|no-mount", ("VALUE","<absent>","FAIL")),
        (["debugfs=off","debugfs=no-mount"], "debugfs", "one-of", "off|no-mount", ("ERROR","cmdline:ambiguous-value","ERROR")),
        (["debugfs","debugfs=off"], "debugfs", "one-of", "off|no-mount", ("ERROR","cmdline:ambiguous-value","ERROR")),
    ]
    for tokens, key, op, expected, wanted in cases:
        got = _model(tokens, key, op, expected)
        assert got == wanted, (tokens, got, wanted)
    eq = shell_function("CTRL-EQ", "/proc/cmdline", "init_on_alloc", "eq", "1")
    present = shell_function("CTRL-PRESENT", "/proc/cmdline", "slab_nomerge", "present", True)
    one = shell_function("CTRL-ONE", "/proc/cmdline", "debugfs", "one-of", "off|no-mount")
    for src in (eq, present, one):
        assert "/proc/cmdline" in src
        assert "read -r -a _slp_tokens" in src
        assert "command /usr/bin/od -An -v -tx1" in src
        assert "cmdline:invalid-bytes" in src
        od_read = '$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null)'
        assert src.count(od_read) == 1
        assert "$(" not in src.replace(od_read, "")
        for token in MUTATING_TOKENS:
            assert token not in src, token
    assert "IFS='|' read -r -a _slp_choices" in one
    for bad in (
        ("CTRL", "/tmp/x", "x", "eq", "1"),
        ("CTRL", "/proc/cmdline", "bad key", "eq", "1"),
        ("CTRL", "/proc/cmdline", "x", "eq", "bad value"),
        ("CTRL", "/proc/cmdline", "x", "present", False),
        ("CTRL", "/proc/cmdline", "x", "present", "true"),
        ("CTRL", "/proc/cmdline", "x", "one-of", "off"),
        ("CTRL", "/proc/cmdline", "x", "one-of", "off|bad value"),
        ("CTRL", "/proc/cmdline", "x", "contains", "1"),
    ):
        try:
            shell_function(*bad)
        except ValueError:
            continue
        raise AssertionError("accepted: %r" % (bad,))
    print("ADAPTER_SELFTEST=PASS")

if __name__ == "__main__":
    _selftest()
