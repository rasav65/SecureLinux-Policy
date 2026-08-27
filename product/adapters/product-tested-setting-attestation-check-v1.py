#!/usr/bin/env python3
# Read-only adapter for explicit tested-before-use local attestation.
import re

SEMANTIC_CONTRACT_ID = "tested-setting-attestation-check-semantic-v1"
ADAPTER_ID = "product-tested-setting-attestation-check-v1"
ADAPTER_CONTRACT_VERSION = "product-tested-setting-attestation-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "tested-setting-attestation"
SUPPORTED_OPS = ("tested-before-use",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/etc/securelinux-policy/tested-setting-attestations-v1"
CANONICAL_KEY = "SRC-0034"
CANONICAL_OP = "tested-before-use"
CANONICAL_EXPECTED = "kernel.randomize_va_space=2"
AUTHORITY_HEADER = "SLP-TESTED-SETTING-ATTESTATIONS-V1"


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _fn_name(control_id):
    return "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)


def _render(control_id, authority_path, source_id, expected_setting):
    fn = _fn_name(control_id)
    emit = "  printf '%s\\t%s\\t%s\\t%s\\t%s\\n' " + _sh_single(WIRE_RECORD_ID) + " " + _sh_single(control_id)
    return "\n".join([
        fn + "() {",
        "  local _slp_authority=" + _sh_single(authority_path),
        "  local _slp_source_id=" + _sh_single(source_id),
        "  local _slp_expected_setting=" + _sh_single(expected_setting),
        "  local _slp_line _slp_hex _slp_byte _slp_prev='' _slp_header='' _slp_row_re",
        "  local _slp_rows=0 _slp_target_rows=0 _slp_setting_match=0 _slp_tested=0 _slp_line_no=0",
        "  local -A _slp_seen=()",
        "  _slp_row_re=$'^(SRC-[0-9]{4})\\t([A-Za-z0-9_.-]+=-?[0-9]+)\\t(TESTED-BEFORE-USE|NOT-TESTED-BEFORE-USE)$'",
        "",
        '  if [[ ! -e "$_slp_authority" || ! -f "$_slp_authority" || -L "$_slp_authority" || ! -r "$_slp_authority" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_authority" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        "  for _slp_byte in $_slp_hex; do",
        '    [[ "$_slp_byte" =~ ^[0-9a-f][0-9a-f]$ ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        "    case \"$_slp_byte\" in",
        "      09|0a) ;;",
        "      00|01|02|03|04|05|06|07|08|0b|0c|0d|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f|7f) " + emit.strip() + ' "ERROR" "-" "ERROR"; return 0 ;;',
        "    esac",
        "  done",
        "",
        '  if ! IFS= read -r _slp_header < "$_slp_authority"; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  [[ "$_slp_header" == ' + _sh_single(AUTHORITY_HEADER) + ' ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        "",
        '  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do',
        '    ((_slp_line_no+=1))',
        '    if (( _slp_line_no == 1 )); then [[ "$_slp_line" == "$_slp_header" ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }; continue; fi',
        '    [[ -n "$_slp_line" ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    if [[ ! "$_slp_line" =~ $_slp_row_re ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        "    local _slp_sid=${BASH_REMATCH[1]} _slp_setting=${BASH_REMATCH[2]} _slp_state=${BASH_REMATCH[3]}",
        '    [[ -z "${_slp_seen[$_slp_sid]+x}" ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    _slp_seen["$_slp_sid"]=1',
        "    ((_slp_rows+=1))",
        '    if [[ "$_slp_sid" == "$_slp_source_id" ]]; then',
        "      ((_slp_target_rows+=1))",
        '      [[ "$_slp_setting" == "$_slp_expected_setting" ]] && _slp_setting_match=1',
        '      [[ "$_slp_state" == TESTED-BEFORE-USE ]] && _slp_tested=1',
        "    fi",
        '  done < "$_slp_authority"',
        "",
        '  if (( _slp_target_rows != 1 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  local _slp_value="authority_rows=$_slp_rows;target_rows=$_slp_target_rows;setting_match=$_slp_setting_match;tested_before_use=$_slp_tested"',
        '  if (( _slp_setting_match == 1 && _slp_tested == 1 )); then',
        emit + ' "VALUE" "$_slp_value" "PASS"',
        "  else",
        emit + ' "VALUE" "$_slp_value" "FAIL"',
        "  fi",
        "  return 0",
        "}",
    ]) + "\n"


def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if locator != CANONICAL_LOCATOR or key != CANONICAL_KEY or op != CANONICAL_OP or expected != CANONICAL_EXPECTED:
        raise ValueError("only canonical SRC-0034 tested-setting attestation contract is supported")
    return _render(control_id, locator, key, expected)


def _shell_function_for_fixture(control_id, authority_path):
    if not isinstance(authority_path, str) or not authority_path.startswith("/"):
        raise ValueError("absolute fixture authority path required")
    return _render(control_id, authority_path, CANONICAL_KEY, CANONICAL_EXPECTED)


MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)


def _selftest():
    src = shell_function("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED)
    assert AUTHORITY_HEADER in src and "TESTED-BEFORE-USE" in src and "/usr/bin/od" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    bad = (
        ("/tmp/attest", CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED),
        (CANONICAL_LOCATOR, "SRC-0028", CANONICAL_OP, CANONICAL_EXPECTED),
        (CANONICAL_LOCATOR, CANONICAL_KEY, "eq", CANONICAL_EXPECTED),
        (CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, "kernel.randomize_va_space=1"),
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
