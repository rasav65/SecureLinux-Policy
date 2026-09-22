#!/usr/bin/env python3
# Read-only adapter SRC-0015 v2: exact mode for direct /home entries.
from __future__ import annotations
import re

ADAPTER_ID = "product-home-directories-mode-check-v2"
ADAPTER_CONTRACT_VERSION = "product-home-directories-mode-check-adapter-v2"
SEMANTIC_CONTRACT_ID = "home-directories-mode-check-semantic-v2"
PARAMETER_KIND = "home-directories-mode"
TARGET_ID = "linux-x86_64-supported-v1"
WIRE_RECORD_ID = "SLP-CHECK-V1"
CANONICAL_LOCATOR = "/home"
CANONICAL_HOME_BASE = "/home"
EXPECTED_MODE = "0700"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"


def _mode_compliance(mode_text, expected=EXPECTED_MODE):
    if not isinstance(mode_text, str) or re.fullmatch(r"[0-7]{3,4}", mode_text) is None:
        return None
    return int(mode_text, 8) == int(expected, 8)


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, home_base):
    cid = _sh_single(control_id); home = _sh_single(home_base)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    lines = [
        fn + "() {",
        "  local _slp_home=" + home + " _slp_expected=" + _sh_single(EXPECTED_MODE),
        "  local _slp_probe _slp_entry _slp_mode _slp_scan_marker _slp_find_rc _slp_sort_rc _slp_i",
        "  local _slp_target _slp_reason _slp_bad",
        "  local _slp_checked=0 _slp_violations=0",
        "  local -a _slp_entries=()",
        "  local -A _slp_seen=()",
        # Корень /home: симлинк — ERROR; отсутствие (при доступном для поиска
        # предке) — вне популяции, PASS с пустыми счётчиками; не каталог — ERROR.
        '  if [[ -L "$_slp_home" ]]; then',
        emit + ' "ERROR" "home-base:symlink" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ ! -e "$_slp_home" ]]; then',
        "    _slp_probe=$_slp_home",
        '    while [[ $_slp_probe != / && ! -e "$_slp_probe" && ! -L "$_slp_probe" ]]; do',
        '      _slp_probe=${_slp_probe%/*}',
        "      [[ -n $_slp_probe ]] || _slp_probe=/",
        "    done",
        '    if [[ -L "$_slp_probe" ]]; then',
        emit + ' "ERROR" "home-base:ancestor-symlink" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ! -d "$_slp_probe" ]]; then',
        emit + ' "ERROR" "home-base:ancestor-invalid-type" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ! -x "$_slp_probe" ]]; then',
        emit + ' "ERROR" "home-base:ancestor-unsearchable" "ERROR"',
        "      return 0",
        "    fi",
        emit + ' "VALUE" "checked=0;violations=0" "PASS"',
        "    return 0",
        "  fi",
        '  if [[ ! -d "$_slp_home" ]]; then',
        emit + ' "ERROR" "home-base:invalid-type" "ERROR"',
        "    return 0",
        "  fi",
        "  _slp_entries=()",
        "  mapfile -d '' -t _slp_entries < <(",
        '    LC_ALL=C command /usr/bin/find -P -- "$_slp_home" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z',
        '    _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"',
        '    printf "__SLP_SCAN_RC=%s\\0" "$_slp_scan_marker"',
        "  )",
        "  if (( ${#_slp_entries[@]} == 0 )); then",
        emit + ' "ERROR" "scan:missing-marker" "ERROR"',
        "    return 0",
        "  fi",
        "  _slp_i=$((${#_slp_entries[@]}-1))",
        "  _slp_scan_marker=${_slp_entries[$_slp_i]}",
        "  unset '_slp_entries[$_slp_i]'",
        '  if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then',
        emit + ' "ERROR" "scan:invalid-marker" "ERROR"',
        "    return 0",
        "  fi",
        "  _slp_find_rc=${BASH_REMATCH[1]}",
        "  _slp_sort_rc=${BASH_REMATCH[2]}",
        "  if (( _slp_find_rc != 0 )); then",
        emit + ' "ERROR" "scan:find-failed" "ERROR"',
        "    return 0",
        "  fi",
        "  if (( _slp_sort_rc != 0 )); then",
        emit + ' "ERROR" "scan:sort-failed" "ERROR"',
        "    return 0",
        "  fi",
        '  for _slp_entry in "${_slp_entries[@]}"; do',
        '    if [[ ${_slp_seen["$_slp_entry"]+x} ]]; then continue; fi',
        '    _slp_seen["$_slp_entry"]=1',
        # Имя записи или цель readlink с байтами табуляции/CR/LF ломают
        # TSV-формат вывода — такой объект получает безопасную причину без
        # внедрения сырых байт в поле reason.
        "    _slp_bad=0",
        '    if [[ "$_slp_entry" == *$\'\\t\'* || "$_slp_entry" == *$\'\\n\'* || "$_slp_entry" == *$\'\\r\'* ]]; then _slp_bad=1; fi',
        '    if [[ -L "$_slp_entry" ]]; then',
        "      if (( _slp_bad )); then",
        emit + ' "ERROR" "home:invalid-name" "ERROR"',
        "        return 0",
        "      fi",
        '      _slp_target=$(command /usr/bin/readlink -- "$_slp_entry" 2>/dev/null)',
        '      if [[ $? -eq 0 && -n "$_slp_target" && "$_slp_target" != *$\'\\t\'* && "$_slp_target" != *$\'\\n\'* && "$_slp_target" != *$\'\\r\'* ]]; then',
        "        printf -v _slp_reason 'home:symlink:%s->%s' \"$_slp_entry\" \"$_slp_target\"",
        "      else",
        "        printf -v _slp_reason 'home:symlink:%s' \"$_slp_entry\"",
        "      fi",
        emit + ' "ERROR" "$_slp_reason" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ! -d "$_slp_entry" ]]; then',
        "      if (( _slp_bad )); then",
        emit + ' "ERROR" "home:invalid-name" "ERROR"',
        "        return 0",
        "      fi",
        "      printf -v _slp_reason 'home:not-directory:%s' \"$_slp_entry\"",
        emit + ' "ERROR" "$_slp_reason" "ERROR"',
        "      return 0",
        "    fi",
        '    if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then',
        emit + ' "ERROR" "home:mode-read-failed" "ERROR"',
        "      return 0",
        "    fi",
        '    [[ "$_slp_mode" =~ ^[0-7]{3,4}$ ]] || { ' + emit.strip() + ' "ERROR" "home:invalid-mode" "ERROR"; return 0; }',
        "    ((_slp_checked+=1))",
        "    if (( 8#$_slp_mode != 8#$_slp_expected )); then ((_slp_violations+=1)); fi",
        "  done",
        '  local _slp_value="checked=$_slp_checked;violations=$_slp_violations"',
        emit + ' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        "  return 0",
        "}",
    ]
    return "\n".join(lines) + "\n"


def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if locator != CANONICAL_LOCATOR or key != "mode" or op != "eq" or expected != EXPECTED_MODE:
        raise ValueError("unsupported SRC-0015 home-directory mode contract")
    return _render(control_id, CANONICAL_HOME_BASE)


def _shell_function_for_fixture(control_id, home_base):
    if not isinstance(home_base, str) or not home_base.startswith("/"):
        raise ValueError("absolute fixture path required")
    return _render(control_id, home_base)


MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)


def _selftest():
    assert _mode_compliance("700") is True and _mode_compliance("0755") is False
    block = shell_function("CTRL.HOME.DIR", CANONICAL_LOCATOR, "mode", "eq", "0700")
    assert "/etc/passwd" not in block and "_slp_passwd" not in block
    assert "command /usr/bin/find -P" in block and "command /usr/bin/readlink" in block
    for token in MUTATING_TOKENS:
        assert token not in block, token
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
