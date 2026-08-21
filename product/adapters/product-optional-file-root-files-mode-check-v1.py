#!/usr/bin/env python3
# product-optional-file-root-files-mode-check-v1: read-only mode observer for one optional root and its direct files.
import re

SEMANTIC_CONTRACT_ID = "optional-file-root-files-mode-check-semantic-v1"
ADAPTER_ID = "product-optional-file-root-files-mode-check-v1"
ADAPTER_CONTRACT_VERSION = "product-optional-file-root-files-mode-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "optional-file-root-files-mode"
SUPPORTED_OPS = ("bits-clear",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
LOCATOR_PATTERN = r"^/(?!.*[\r\n\t])[A-Za-z0-9_./-]+$"
EXPECTED_MASK = "0033"

def _mode_compliance(mode_text, expected=EXPECTED_MASK):
    if not isinstance(mode_text, str) or re.fullmatch(r"[0-7]{3,4}", mode_text) is None:
        return None
    return (int(mode_text, 8) & int(expected, 8)) == 0

def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not isinstance(locator, str) or not re.fullmatch(LOCATOR_PATTERN, locator):
        raise ValueError("invalid locator")
    if key != "mode" or op != "bits-clear" or expected != EXPECTED_MASK:
        raise ValueError("only mode bits-clear 0033 is supported")
    cid = _sh_single(control_id)
    path = _sh_single(locator)
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    lines = [
        fn + "() {",
        "  local _slp_path=" + path,
        "  local _slp_expected='0033' _slp_parent _slp_mode _slp_entry _slp_scan_marker",
        "  local _slp_type _slp_find_rc _slp_sort_rc",
        "  local _slp_checked=0 _slp_violations=0 _slp_i",
        "  local -a _slp_entries=()",
        '  if [[ -L "$_slp_path" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ ! -e "$_slp_path" ]]; then',
        '    _slp_parent=${_slp_path%/*}',
        '    [[ -n $_slp_parent ]] || _slp_parent=/',
        '    if [[ -d "$_slp_parent" && -x "$_slp_parent" && ! -L "$_slp_path" && ! -e "$_slp_path" ]]; then',
        emit + ' "VALUE" "<absent>" "PASS"',
        "    else",
        emit + ' "ERROR" "-" "ERROR"',
        "    fi",
        "    return 0",
        "  fi",
        '  if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_path" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        "  ((_slp_checked+=1))",
        '  if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi',
        '  if [[ -f "$_slp_path" ]]; then',
        emit + ' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        "    return 0",
        "  fi",
        '  if [[ ! -d "$_slp_path" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  mapfile -d \'\' -t _slp_entries < <(',
        '    LC_ALL=C /usr/bin/find -- "$_slp_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z',
        '    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"',
        '    printf "__SLP_SCAN_RC=%s\\0" "$_slp_scan_marker"',
        "  )",
        '  if (( ${#_slp_entries[@]} == 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  _slp_i=$((${#_slp_entries[@]}-1))',
        '  _slp_scan_marker=${_slp_entries[$_slp_i]}',
        '  unset \'_slp_entries[$_slp_i]\'',
        '  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  _slp_find_rc=${BASH_REMATCH[1]}',
        '  _slp_sort_rc=${BASH_REMATCH[2]}',
        '  if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
        '  for _slp_entry in "${_slp_entries[@]}"; do',
        '    if [[ -L "$_slp_entry" || -d "$_slp_entry" || ! -f "$_slp_entry" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        "    ((_slp_checked+=1))",
        '    if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi',
        "  done",
        emit + ' "VALUE" "checked=$_slp_checked;violations=$_slp_violations" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        "  return 0",
        "}",
    ]
    return "\n".join(lines) + "\n"

MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)

def _selftest():
    assert _mode_compliance("700") is True
    assert _mode_compliance("0644") is True
    assert _mode_compliance("0755") is False
    assert _mode_compliance("0664") is False
    assert _mode_compliance("bogus") is None
    src = shell_function("CTRL", "/tmp/example", "mode", "bits-clear", "0033")
    assert "/usr/bin/find" in src and "/usr/bin/sort -z" in src and "<absent>" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    bad = [
        ("CTRL", "relative", "mode", "bits-clear", "0033"),
        ("CTRL", "/tmp/x", "owner", "bits-clear", "0033"),
        ("CTRL", "/tmp/x", "mode", "eq", "0033"),
        ("CTRL", "/tmp/x", "mode", "bits-clear", "0077"),
    ]
    for args in bad:
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")

if __name__ == "__main__":
    _selftest()
