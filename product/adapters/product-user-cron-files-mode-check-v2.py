#!/usr/bin/env python3
# Read-only adapter SRC-0011 v2: direct user-crontab file mode population.
import re

SEMANTIC_CONTRACT_ID = "user-cron-files-mode-check-semantic-v2"
ADAPTER_ID = "product-user-cron-files-mode-check-v2"
ADAPTER_CONTRACT_VERSION = "product-user-cron-files-mode-check-adapter-v2"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "user-cron-files-mode"
SUPPORTED_OPS = ("bits-clear",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/var/spool/cron/crontabs"
CANONICAL_ROOTS = ("/var/spool/cron/crontabs",)
EXPECTED_MASK = "0022"

def _mode_compliance(mode_text, expected=EXPECTED_MASK):
    if not isinstance(mode_text, str) or re.fullmatch(r"[0-7]{3,4}", mode_text) is None:
        return None
    return (int(mode_text, 8) & int(expected, 8)) == 0

def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def _render(control_id, roots, expected=EXPECTED_MASK):
    cid = _sh_single(control_id)
    roots_shell = " ".join(_sh_single(x) for x in roots)
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    return "\n".join([
        fn + "() {",
        "  local _slp_expected=" + _sh_single(expected) + " _slp_root _slp_probe _slp_entry _slp_mode _slp_scan_marker",
        "  local _slp_find_rc _slp_sort_rc _slp_i",
        "  local _slp_roots_present=0 _slp_roots_absent=0 _slp_checked=0 _slp_violations=0",
        "  local -a _slp_roots=(" + roots_shell + ") _slp_entries=()",
        "  local -A _slp_seen=()",
        '  for _slp_root in "${_slp_roots[@]}"; do',
        '    if [[ -L "$_slp_root" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ! -e "$_slp_root" ]]; then',
        '      _slp_probe=$_slp_root',
        '      while [[ $_slp_probe != / && ! -e "$_slp_probe" && ! -L "$_slp_probe" ]]; do',
        '        _slp_probe=${_slp_probe%/*}',
        '        [[ -n $_slp_probe ]] || _slp_probe=/',
        "      done",
        '      if [[ -L "$_slp_probe" || ! -d "$_slp_probe" || ! -x "$_slp_probe" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        "      ((_slp_roots_absent+=1))",
        "      continue",
        "    fi",
        '    if [[ ! -d "$_slp_root" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        "    ((_slp_roots_present+=1))",
        "    _slp_entries=()",
        "    mapfile -d '' -t _slp_entries < <(",
        '      LC_ALL=C command /usr/bin/find -P -- "$_slp_root" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z',
        '      _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"',
        '      printf "__SLP_SCAN_RC=%s\\0" "$_slp_scan_marker"',
        "    )",
        '    if (( ${#_slp_entries[@]} == 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_i=$((${#_slp_entries[@]}-1))',
        '    _slp_scan_marker=${_slp_entries[$_slp_i]}',
        "    unset '_slp_entries[$_slp_i]'",
        '    if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_find_rc=${BASH_REMATCH[1]}',
        '    _slp_sort_rc=${BASH_REMATCH[2]}',
        '    if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    for _slp_entry in "${_slp_entries[@]}"; do',
        '      if [[ ${_slp_seen["$_slp_entry"]+x} ]]; then continue; fi',
        '      _slp_seen["$_slp_entry"]=1',
        '      if [[ -L "$_slp_entry" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        '      if [[ -d "$_slp_entry" ]]; then continue; fi',
        '      if [[ ! -f "$_slp_entry" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        '      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -c %a -- "$_slp_entry" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        '      if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        "      ((_slp_checked+=1))",
        '      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi',
        "    done",
        "  done",
        '  local _slp_value="roots_present=$_slp_roots_present;roots_absent=$_slp_roots_absent;checked=$_slp_checked;violations=$_slp_violations"',
        emit + ' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        "  return 0",
        "}",
    ]) + "\n"

def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if locator != CANONICAL_LOCATOR or key != "mode" or op != "bits-clear" or expected != EXPECTED_MASK:
        raise ValueError("only canonical SRC-0011 user-cron mode contract is supported")
    return _render(control_id, CANONICAL_ROOTS, expected)

def _shell_function_for_roots(control_id, roots, expected=EXPECTED_MASK):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not roots or any(not isinstance(x, str) or not x.startswith("/") for x in roots):
        raise ValueError("absolute test roots required")
    return _render(control_id, tuple(roots), expected)

MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)

def _selftest():
    assert _mode_compliance("600") is True
    assert _mode_compliance("0640") is True
    assert _mode_compliance("0620") is False
    assert _mode_compliance("0664") is False
    assert _mode_compliance("bogus") is None
    src = shell_function("CTRL", CANONICAL_LOCATOR, "mode", "bits-clear", "0022")
    assert "command /usr/bin/find -P" in src and "command /usr/bin/sort -z" in src
    assert "roots_present=" in src and "violations=" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    for args in (
        ("CTRL", "/var/spool/cron", "mode", "bits-clear", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "owner", "bits-clear", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "eq", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "bits-clear", "0033"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")

if __name__ == "__main__":
    _selftest()
