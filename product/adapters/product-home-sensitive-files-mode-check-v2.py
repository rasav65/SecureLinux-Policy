#!/usr/bin/env python3
# Read-only adapter SRC-0014 v2: sensitive shell/history files in all local user homes.
from __future__ import annotations
import re

ADAPTER_ID = "product-home-sensitive-files-mode-check-v2"
ADAPTER_CONTRACT_VERSION = "product-home-sensitive-files-mode-check-adapter-v2"
PARAMETER_KIND = "home-sensitive-files-mode"
TARGET_ID = "linux-x86_64-supported-v1"
WIRE_RECORD_ID = "SLP-CHECK-V1"
SEMANTIC_CONTRACT_ID = "home-sensitive-files-mode-check-semantic-v2"
CANONICAL_HOME_BASE = "/home"
CANONICAL_INVENTORY = "/etc/securelinux-policy/home-sensitive-files-v1"
EXPECTED_MASK = "0077"
MANDATORY_SOURCE_NAMES = (
    ".bash_history", ".history", ".sh_history", ".bash_profile",
    ".bashrc", ".profile", ".bash_logout", ".rhosts",
)
COMMON_SHELL_BASENAMES = (
    ".bash_login", ".xonshrc",
    ".zsh_history", ".zshrc", ".zprofile", ".zlogin", ".zlogout", ".zshenv",
    ".ksh_history", ".kshrc", ".mkshrc", ".cshrc", ".tcshrc", ".login", ".logout",
)
COMMON_SHELL_RELATIVE_PATTERNS = (
    ".config/fish/*.fish", ".local/share/fish/fish_history",
    ".config/nushell/config.nu", ".config/nushell/env.nu", ".config/nushell/login.nu",
    ".config/nushell/autoload/*.nu", ".local/share/nushell/vendor/autoload/*.nu",
    ".config/nushell/history.txt", ".config/nushell/history.sqlite3",
    ".config/xonsh/rc.xsh", ".config/xonsh/rc.d/*.xsh", ".config/xonsh/rc.d/*.py",
    ".local/share/xonsh/history_json/xonsh-*.json", ".local/share/xonsh/xonsh-*.json",
    ".local/share/xonsh/xonsh-history.sqlite",
    ".config/elvish/rc.elv", ".elvish/rc.elv",
    ".local/state/elvish/db.bolt", ".elvish/db",
)
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"


def _mode_compliance(mode_text, expected=EXPECTED_MASK):
    if not isinstance(mode_text, str) or re.fullmatch(r"[0-7]{3,4}", mode_text) is None:
        return None
    return (int(mode_text, 8) & int(expected, 8)) == 0


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _render(control_id, home_base, inventory_path):
    cid = _sh_single(control_id)
    home = _sh_single(home_base)
    inventory = _sh_single(inventory_path)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    mandatory_words = " ".join(_sh_single(x) for x in MANDATORY_SOURCE_NAMES)
    basename_case = "|".join(COMMON_SHELL_BASENAMES)
    relative_case = "|".join(COMMON_SHELL_RELATIVE_PATTERNS)
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    lines = [
        fn + "() {",
        "  local _slp_home=" + home + " _slp_inventory=" + inventory,
        "  local _slp_expected=" + _sh_single(EXPECTED_MASK),
        "  local _slp_entry _slp_rel _slp_base _slp_mode _slp_hex",
        "  local _slp_ident _slp_marker _slp_find_rc _slp_sort_rc _slp_i _slp_candidate=0",
        "  local _slp_probe _slp_stat_out _slp_reason _slp_target _slp_bad",
        "  local _slp_rest _slp_inventory_text",
        "  local _slp_homes=0 _slp_names=0 _slp_checked=0 _slp_violations=0 _slp_dynamic=0",
        "  local -a _slp_fields=() _slp_entries=() _slp_mandatory=(" + mandatory_words + ") _slp_home_entries=()",
        "  local -A _slp_inventory_names=() _slp_seen_targets=() _slp_seen_entries=()",
        "",
        '  if [[ -L "$_slp_inventory" ]]; then',
        emit + ' "ERROR" "inventory:symlink" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ ! -e "$_slp_inventory" ]]; then',
        emit + ' "ERROR" "inventory:not-found" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ ! -f "$_slp_inventory" ]]; then',
        emit + ' "ERROR" "inventory:invalid-type" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ ! -r "$_slp_inventory" ]]; then',
        emit + ' "ERROR" "inventory:unreadable" "ERROR"',
        "    return 0",
        "  fi",
        '  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_inventory" 2>/dev/null); then',
        emit + ' "ERROR" "inventory:read-failed" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ "$_slp_hex" =~ (^|[[:space:]])(00|0d)([[:space:]]|$) ]]; then',
        emit + ' "ERROR" "inventory:invalid-bytes" "ERROR"',
        "    return 0",
        "  fi",
        # Файл читается один раз: проверенные `od` байты декодируются в текст,
        # который затем разбирается; повторного открытия файла нет.
        '  if [[ -z $_slp_hex ]]; then',
        '    _slp_inventory_text=""',
        '  else',
        r"    _slp_inventory_text=$(printf '\\x%s' $_slp_hex)",
        '    printf -v _slp_inventory_text %b "$_slp_inventory_text"',
        '  fi',
        "",
        '  _slp_rest=$_slp_inventory_text',
        '  while [[ -n $_slp_rest ]]; do',
        '    if [[ $_slp_rest == *$\'\\n\'* ]]; then _slp_entry=${_slp_rest%%$\'\\n\'*}; _slp_rest=${_slp_rest#*$\'\\n\'}; else _slp_entry=$_slp_rest; _slp_rest=""; fi',
        '    [[ -z "$_slp_entry" || "${_slp_entry:0:1}" == "#" ]] && continue',
        '    if [[ ! "$_slp_entry" =~ ^\\.[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*$ ]]; then',
        emit + ' "ERROR" "inventory:invalid-path" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ${_slp_inventory_names["$_slp_entry"]+x} ]]; then',
        emit + ' "ERROR" "inventory:duplicate-path" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_inventory_names["$_slp_entry"]=1',
        '  done',
        '  for _slp_entry in "${_slp_mandatory[@]}"; do',
        '    [[ ${_slp_inventory_names["$_slp_entry"]+x} ]] || { ' + emit.strip() + ' "ERROR" "inventory:missing-required" "ERROR"; return 0; }',
        '  done',
        '  _slp_names=${#_slp_inventory_names[@]}',
        "",
        # /home сам: [[ ! -e ]]/[[ -L ]] не отличают доказанный ENOENT от
        # прочих ошибок stat (EIO, ENAMETOOLONG, EACCES на самом /home и
        # т. п.) — по прецеденту 2.3.11 (product-home-directories-mode-
        # check-v2.py): `stat -c %F` (lstat-семантика) плюс разбор текста
        # ошибки, только буквальное «No such file or directory» —
        # доказательство ENOENT, дающее право искать ближайшего доступного
        # предка.
        '  _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_home" 2>&1)',
        "  if (( $? != 0 )); then",
        '    if [[ "$_slp_stat_out" != *": No such file or directory" ]]; then',
        "      printf -v _slp_reason 'home-base:stat-failed:%s' \"$_slp_home\"",
        emit + ' "ERROR" "$_slp_reason" "ERROR"',
        "      return 0",
        "    fi",
        "    _slp_probe=$_slp_home",
        '    while [[ $_slp_probe != / ]]; do',
        '      _slp_probe=${_slp_probe%/*}',
        "      [[ -n $_slp_probe ]] || _slp_probe=/",
        '      if [[ $_slp_probe == / ]]; then break; fi',
        '      _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_probe" 2>&1)',
        "      if (( $? == 0 )); then break; fi",
        '      if [[ "$_slp_stat_out" != *": No such file or directory" ]]; then',
        "        printf -v _slp_reason 'home-base:ancestor-stat-failed:%s' \"$_slp_probe\"",
        emit + ' "ERROR" "$_slp_reason" "ERROR"',
        "        return 0",
        "      fi",
        "    done",
        '    if [[ $_slp_probe == / ]]; then',
        emit + ' "VALUE" "homes=0;names=$_slp_names;discovered=0;checked=0;violations=0" "PASS"',
        "      return 0",
        "    fi",
        '    case "$_slp_stat_out" in',
        "      'symbolic link')",
        emit + ' "ERROR" "home-base:ancestor-symlink" "ERROR"',
        "        return 0 ;;",
        "      directory) ;;",
        "      *)",
        emit + ' "ERROR" "home-base:ancestor-invalid-type" "ERROR"',
        "        return 0 ;;",
        "    esac",
        '    if [[ ! -x "$_slp_probe" ]]; then',
        emit + ' "ERROR" "home-base:ancestor-unsearchable" "ERROR"',
        "      return 0",
        "    fi",
        emit + ' "VALUE" "homes=0;names=$_slp_names;discovered=0;checked=0;violations=0" "PASS"',
        "    return 0",
        "  fi",
        '  case "$_slp_stat_out" in',
        "    'symbolic link')",
        emit + ' "ERROR" "home-base:symlink" "ERROR"',
        "      return 0 ;;",
        "    directory) ;;",
        "    *)",
        emit + ' "ERROR" "home-base:invalid-type" "ERROR"',
        "      return 0 ;;",
        "  esac",
        "",
        "  _slp_home_entries=()",
        '  mapfile -d "" -t _slp_home_entries < <(',
        '    LC_ALL=C command /usr/bin/find -P -- "$_slp_home" -mindepth 1 -maxdepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z',
        '    _slp_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"',
        '    printf "__SLP_SCAN_RC=%s\\0" "$_slp_marker"',
        "  )",
        "  if (( ${#_slp_home_entries[@]} == 0 )); then",
        emit + ' "ERROR" "home-scan:missing-marker" "ERROR"',
        "    return 0",
        "  fi",
        "  _slp_i=$((${#_slp_home_entries[@]}-1))",
        "  _slp_marker=${_slp_home_entries[$_slp_i]}",
        "  unset '_slp_home_entries[$_slp_i]'",
        '  if [[ ! $_slp_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then',
        emit + ' "ERROR" "home-scan:invalid-marker" "ERROR"',
        "    return 0",
        "  fi",
        "  _slp_find_rc=${BASH_REMATCH[1]}",
        "  _slp_sort_rc=${BASH_REMATCH[2]}",
        "  if (( _slp_find_rc != 0 )); then",
        emit + ' "ERROR" "home-scan:find-failed" "ERROR"',
        "    return 0",
        "  fi",
        "  if (( _slp_sort_rc != 0 )); then",
        emit + ' "ERROR" "home-scan:sort-failed" "ERROR"',
        "    return 0",
        "  fi",
        '  for _slp_entry in "${_slp_home_entries[@]}"; do',
        '    if [[ ${_slp_seen_entries["$_slp_entry"]+x} ]]; then continue; fi',
        '    _slp_seen_entries["$_slp_entry"]=1',
        # Имя элемента или цель readlink с control-байтами (TAB/CR/LF/DEL)
        # ломают TSV-строку вывода — безопасная причина без внедрения сырых
        # байт в reason, на любой ветке классификации (по прецеденту 2.3.11).
        "    _slp_bad=0",
        '    if [[ "$_slp_entry" == *$\'\\t\'* || "$_slp_entry" == *$\'\\n\'* || "$_slp_entry" == *$\'\\r\'* || "$_slp_entry" == *$\'\\x7f\'* ]]; then _slp_bad=1; fi',
        # Классификация элемента — по `case "$_slp_stat_out" in` (вывод
        # `stat -c %F`), не по `[[ -L ]]`/`[[ ! -d ]]`, которые не отличают
        # доказанный тип от ошибки lstat (в т.ч. TOCTOU-исчезновение).
        '    _slp_stat_out=$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_entry" 2>&1)',
        "    if (( $? != 0 )); then",
        "      if (( _slp_bad )); then",
        emit + ' "ERROR" "home:invalid-name" "ERROR"',
        "        return 0",
        "      fi",
        '      if [[ "$_slp_stat_out" == *": No such file or directory" ]]; then',
        "        printf -v _slp_reason 'home:vanished:%s' \"$_slp_entry\"",
        "      else",
        "        printf -v _slp_reason 'home:stat-failed:%s' \"$_slp_entry\"",
        "      fi",
        emit + ' "ERROR" "$_slp_reason" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ "$_slp_stat_out" == "symbolic link" ]]; then',
        "      if (( _slp_bad )); then",
        emit + ' "ERROR" "home:invalid-name" "ERROR"',
        "        return 0",
        "      fi",
        '      _slp_target=$(command /usr/bin/readlink -- "$_slp_entry" 2>/dev/null && printf x)',
        "      if [[ $? -eq 0 ]]; then",
        '        _slp_target=${_slp_target%x}',
        '        _slp_target=${_slp_target%$\'\\n\'}',
        '        if [[ "$_slp_target" == *$\'\\t\'* || "$_slp_target" == *$\'\\n\'* || "$_slp_target" == *$\'\\r\'* || "$_slp_target" == *$\'\\x7f\'* ]]; then',
        emit + ' "ERROR" "home:invalid-name" "ERROR"',
        "          return 0",
        '        elif [[ -n "$_slp_target" ]]; then',
        "          printf -v _slp_reason 'home:symlink:%s->%s' \"$_slp_entry\" \"$_slp_target\"",
        "        else",
        "          printf -v _slp_reason 'home:symlink:%s' \"$_slp_entry\"",
        "        fi",
        "      else",
        "        printf -v _slp_reason 'home:symlink:%s' \"$_slp_entry\"",
        "      fi",
        emit + ' "ERROR" "$_slp_reason" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ "$_slp_stat_out" != "directory" ]]; then',
        "      if (( _slp_bad )); then",
        emit + ' "ERROR" "home:invalid-name" "ERROR"',
        "        return 0",
        "      fi",
        "      printf -v _slp_reason 'home:not-directory:%s' \"$_slp_entry\"",
        emit + ' "ERROR" "$_slp_reason" "ERROR"',
        "      return 0",
        "    fi",
        "    if (( _slp_bad )); then",
        emit + ' "ERROR" "home:invalid-name" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_home=$_slp_entry',
        '    if [[ ! -r "$_slp_home" ]]; then',
        emit + ' "ERROR" "home:unreadable" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ! -x "$_slp_home" ]]; then',
        emit + ' "ERROR" "home:unsearchable" "ERROR"',
        "      return 0",
        "    fi",
        "    ((_slp_homes+=1))",
        '    _slp_entries=()',
        '    mapfile -d "" -t _slp_entries < <(',
        '      LC_ALL=C command /usr/bin/find -P -- "$_slp_home" -xdev -mindepth 1 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z',
        '      _slp_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"',
        '      printf "__SLP_SCAN_RC=%s\\0" "$_slp_marker"',
        '    )',
        '    (( ${#_slp_entries[@]} > 0 )) || { ' + emit.strip() + ' "ERROR" "scan:missing-marker" "ERROR"; return 0; }',
        '    _slp_i=$((${#_slp_entries[@]}-1)); _slp_marker=${_slp_entries[$_slp_i]}; unset \'_slp_entries[$_slp_i]\'',
        '    [[ "$_slp_marker" =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]] || { ' + emit.strip() + ' "ERROR" "scan:invalid-marker" "ERROR"; return 0; }',
        '    _slp_find_rc=${BASH_REMATCH[1]}; _slp_sort_rc=${BASH_REMATCH[2]}',
        '    (( _slp_find_rc == 0 )) || { ' + emit.strip() + ' "ERROR" "scan:find-failed" "ERROR"; return 0; }',
        '    (( _slp_sort_rc == 0 )) || { ' + emit.strip() + ' "ERROR" "scan:sort-failed" "ERROR"; return 0; }',
        '    for _slp_entry in "${_slp_entries[@]}"; do',
        '      _slp_rel=${_slp_entry#"$_slp_home"/}; _slp_base=${_slp_entry##*/}; _slp_candidate=0',
        '      if [[ ${_slp_inventory_names["$_slp_rel"]+x} ]]; then _slp_candidate=1; fi',
        '      if [[ "$_slp_base" == .* ]]; then',
        '        case "$_slp_base" in',
        '          ' + basename_case + ') _slp_candidate=1 ;;',
        '        esac',
        '      fi',
        '      case "$_slp_rel" in',
        '        ' + relative_case + ') _slp_candidate=1 ;;',
        '      esac',
        '      (( _slp_candidate == 1 )) || continue',
        '      ((_slp_dynamic+=1))',
        '      if [[ -L "$_slp_entry" ]]; then',
        emit + ' "ERROR" "target:symlink" "ERROR"',
        "        return 0",
        "      fi",
        '      if [[ ! -f "$_slp_entry" ]]; then',
        emit + ' "ERROR" "target:invalid-type" "ERROR"',
        "        return 0",
        "      fi",
        '      if ! _slp_ident=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then',
        emit + ' "ERROR" "target:identity-failed" "ERROR"',
        "        return 0",
        "      fi",
        '      if [[ ${_slp_seen_targets["$_slp_ident"]+x} ]]; then continue; fi',
        '      _slp_seen_targets["$_slp_ident"]=1',
        '      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then',
        emit + ' "ERROR" "target:mode-read-failed" "ERROR"',
        "        return 0",
        "      fi",
        '      [[ "$_slp_mode" =~ ^[0-7]{3,4}$ ]] || { ' + emit.strip() + ' "ERROR" "target:invalid-mode" "ERROR"; return 0; }',
        '      ((_slp_checked+=1))',
        '      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi',
        '    done',
        '  done',
        '  local _slp_value="homes=$_slp_homes;names=$_slp_names;discovered=$_slp_dynamic;checked=$_slp_checked;violations=$_slp_violations"',
        emit + ' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        "  return 0",
        "}",
    ]
    return "\n".join(lines) + "\n"


def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if locator != CANONICAL_HOME_BASE + "|" + CANONICAL_INVENTORY or key != "mode" or op != "bits-clear" or expected != EXPECTED_MASK:
        raise ValueError("unsupported SRC-0014 home-sensitive-files contract")
    return _render(control_id, CANONICAL_HOME_BASE, CANONICAL_INVENTORY)


def _shell_function_for_fixture(control_id, home_base, inventory_path):
    for p in (home_base, inventory_path):
        if not isinstance(p, str) or not p.startswith("/"):
            raise ValueError("absolute fixture path required")
    return _render(control_id, home_base, inventory_path)


MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)


def _selftest():
    assert _mode_compliance("0600") is True
    assert _mode_compliance("0700") is True
    assert _mode_compliance("0644") is False
    assert _mode_compliance("0770") is False
    assert _mode_compliance("bad") is None
    block = shell_function(
        "CTRL.HOME", CANONICAL_HOME_BASE + "|" + CANONICAL_INVENTORY, "mode", "bits-clear", "0077"
    )
    assert "/etc/passwd" not in block and "_slp_passwd" not in block
    for marker in (
        CANONICAL_HOME_BASE, CANONICAL_INVENTORY, "discovered=", "violations=",
        ".bash_login", ".xonshrc", ".config/nushell/autoload/*.nu", ".config/xonsh/rc.xsh",
        ".config/elvish/rc.elv", ".local/state/elvish/db.bolt",
    ):
        assert marker in block
    assert "UID_MIN" not in block and "nologin" not in block
    for token in MUTATING_TOKENS:
        assert token not in block, token
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
