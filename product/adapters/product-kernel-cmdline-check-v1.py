#!/usr/bin/env python3
# product-kernel-cmdline-check-v1: read-only exact /proc/cmdline observer.
import re

SEMANTIC_CONTRACT_ID = "kernel-cmdline-check-semantic-v1"
ADAPTER_ID = "product-kernel-cmdline-check-v1"
ADAPTER_CONTRACT_VERSION = "product-kernel-cmdline-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "kernel-cmdline"
SUPPORTED_OPS = ("eq", "present")
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
KEY_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9_.-]+$"
VALUE_PATTERN = r"^(?!.*[\r\n\t ])[A-Za-z0-9_.,:+/-]+$"
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
            return ("ERROR", "-", "ERROR")
        return ("VALUE", "true" if bare else "false", "PASS" if bare else "FAIL")
    if bare:
        return ("ERROR", "-", "ERROR")
    if not values:
        return ("VALUE", "<absent>", "FAIL")
    first = values[0]
    if any(value != first for value in values[1:]):
        return ("ERROR", "-", "ERROR")
    return ("VALUE", first, "PASS" if first == expected else "FAIL")

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
        "  local _slp_raw _slp_token _slp_value _slp_first _slp_comp",
        "  local _slp_bare=0 _slp_values=0 _slp_conflict=0",
        "  local -a _slp_tokens=()",
        '  if [[ ! -e "$_slp_path" ]]; then',
        emit + ' "NOT_FOUND" "-" "NOT_FOUND"',
        "    return 0",
        "  fi",
        '  if ! { IFS= read -r _slp_raw < "$_slp_path"; } 2>/dev/null; then',
        emit + ' "ERROR" "-" "ERROR"',
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
            emit + ' "ERROR" "-" "ERROR"',
            "    return 0",
            "  fi",
            "  if (( _slp_bare > 0 )); then",
            emit + ' "VALUE" "true" "PASS"',
            "  else",
            emit + ' "VALUE" "false" "FAIL"',
            "  fi",
        ])
    else:
        lines.extend([
            "  if (( _slp_bare > 0 || _slp_conflict > 0 )); then",
            emit + ' "ERROR" "-" "ERROR"',
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
        (["iommu=force","iommu=pt"], "iommu", "eq", "force", ("ERROR","-","ERROR")),
        (["iommu","iommu=force"], "iommu", "eq", "force", ("ERROR","-","ERROR")),
        (["slab_nomerge"], "slab_nomerge", "present", True, ("VALUE","true","PASS")),
        ([], "slab_nomerge", "present", True, ("VALUE","false","FAIL")),
        (["slab_nomerge=1"], "slab_nomerge", "present", True, ("ERROR","-","ERROR")),
    ]
    for tokens, key, op, expected, wanted in cases:
        got = _model(tokens, key, op, expected)
        assert got == wanted, (tokens, got, wanted)
    eq = shell_function("CTRL-EQ", "/proc/cmdline", "init_on_alloc", "eq", "1")
    present = shell_function("CTRL-PRESENT", "/proc/cmdline", "slab_nomerge", "present", True)
    for src in (eq, present):
        assert "/proc/cmdline" in src
        assert "read -r -a _slp_tokens" in src
        assert "$(" not in src
        for token in MUTATING_TOKENS:
            assert token not in src, token
    for bad in (
        ("CTRL", "/tmp/x", "x", "eq", "1"),
        ("CTRL", "/proc/cmdline", "bad key", "eq", "1"),
        ("CTRL", "/proc/cmdline", "x", "eq", "bad value"),
        ("CTRL", "/proc/cmdline", "x", "present", False),
        ("CTRL", "/proc/cmdline", "x", "present", "true"),
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
