#!/usr/bin/env python3
# Read-only adapter SRC-0012: стандартные executable/library/module paths.
import re

SEMANTIC_CONTRACT_ID = "standard-system-paths-mode-check-semantic-v1"
ADAPTER_ID = "product-standard-system-paths-mode-check-v1"
ADAPTER_CONTRACT_VERSION = "product-standard-system-paths-mode-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "standard-system-paths-mode"
SUPPORTED_OPS = ("bits-clear",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/bin|/sbin|/usr/bin|/usr/sbin|/lib|/lib64|/usr/lib|/usr/lib64|/lib/modules/<uname-r>"
CANONICAL_EXEC_ROOTS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin")
CANONICAL_LIB_ROOTS = ("/lib", "/lib64", "/usr/lib", "/usr/lib64")
CANONICAL_MODULE_TEMPLATE = "/lib/modules/<uname-r>"
EXPECTED_MASK = "0022"

def _mode_compliance(mode_text, expected=EXPECTED_MASK):
    if not isinstance(mode_text, str) or re.fullmatch(r"[0-7]{3,4}", mode_text) is None:
        return None
    return (int(mode_text, 8) & int(expected, 8)) == 0

def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def _render(control_id, exec_roots, lib_roots, module_root, expected=EXPECTED_MASK, dynamic_module=False):
    cid = _sh_single(control_id)
    exec_shell = " ".join(_sh_single(x) for x in exec_roots)
    lib_shell = " ".join(_sh_single(x) for x in lib_roots)
    module_shell = _sh_single(module_root)
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    lines = [
        fn + "() {",
        "  local _slp_expected=" + _sh_single(expected) + " _slp_role _slp_root _slp_resolved _slp_root_id",
        "  local _slp_entry _slp_name _slp_candidate _slp_mode _slp_ident _slp_target _slp_scan_marker",
        "  local _slp_find_rc _slp_sort_rc _slp_i _slp_uname_r=''",
        "  local _slp_roots_present=0 _slp_roots_absent=0 _slp_aliases=0",
        "  local _slp_exec=0 _slp_libraries=0 _slp_modules=0 _slp_checked=0 _slp_violations=0",
        "  local -a _slp_exec_roots=(" + exec_shell + ") _slp_lib_roots=(" + lib_shell + ") _slp_entries=()",
        "  local _slp_module_root=" + module_shell,
        "  local -A _slp_seen_roots=() _slp_seen_targets=()",
    ]
    if dynamic_module:
        lines += [
            "  if ! _slp_uname_r=$(/usr/bin/uname -r 2>/dev/null); then",
            emit + ' "ERROR" "-" "ERROR"',
            "    return 0",
            "  fi",
            "  if [[ -z $_slp_uname_r || $_slp_uname_r == *$'\\n'* || $_slp_uname_r == *$'\\r'* ]]; then",
            emit + ' "ERROR" "-" "ERROR"',
            "    return 0",
            "  fi",
            '  _slp_module_root=${_slp_module_root/<uname-r>/$_slp_uname_r}',
        ]
    lines += [
        '  for _slp_role in exec lib module; do',
        '    local -a _slp_role_roots=()',
        '    case "$_slp_role" in',
        '      exec) _slp_role_roots=("${_slp_exec_roots[@]}") ;;',
        '      lib) _slp_role_roots=("${_slp_lib_roots[@]}") ;;',
        '      module) _slp_role_roots=("$_slp_module_root") ;;',
        '    esac',
        '    for _slp_root in "${_slp_role_roots[@]}"; do',
        '      if [[ ! -e "$_slp_root" && ! -L "$_slp_root" ]]; then',
        '        ((_slp_roots_absent+=1))',
        '        continue',
        '      fi',
        '      if ! _slp_resolved=$(/usr/bin/readlink -f -- "$_slp_root" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        '        return 0',
        '      fi',
        '      if [[ -z $_slp_resolved || ! -d "$_slp_resolved" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        '        return 0',
        '      fi',
        '      if ! _slp_root_id=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_resolved" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        '        return 0',
        '      fi',
        '      ((_slp_roots_present+=1))',
        '      if [[ ${_slp_seen_roots["$_slp_root_id"]+x} ]]; then',
        '        ((_slp_aliases+=1))',
        '        continue',
        '      fi',
        '      _slp_seen_roots["$_slp_root_id"]=1',
        '      _slp_entries=()',
        '      mapfile -d \"\" -t _slp_entries < <(',
        '        LC_ALL=C /usr/bin/find -P -- "$_slp_resolved" -mindepth 1 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z',
        '        _slp_scan_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"',
        '        printf "__SLP_SCAN_RC=%s\\0" "$_slp_scan_marker"',
        '      )',
        '      if (( ${#_slp_entries[@]} == 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        '        return 0',
        '      fi',
        '      _slp_i=$((${#_slp_entries[@]}-1))',
        '      _slp_scan_marker=${_slp_entries[$_slp_i]}',
        "      unset '_slp_entries[$_slp_i]'",
        '      if [[ ! $_slp_scan_marker =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        '        return 0',
        '      fi',
        '      _slp_find_rc=${BASH_REMATCH[1]}',
        '      _slp_sort_rc=${BASH_REMATCH[2]}',
        '      if (( _slp_find_rc != 0 || _slp_sort_rc != 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        '        return 0',
        '      fi',
        '      for _slp_entry in "${_slp_entries[@]}"; do',
        '        if [[ -d "$_slp_entry" && ! -L "$_slp_entry" ]]; then continue; fi',
        '        _slp_name=${_slp_entry##*/}',
        '        _slp_candidate=0',
        '        case "$_slp_role:$_slp_name" in',
        '          exec:*) _slp_candidate=1 ;;',
        '          lib:*.so|lib:*.so.*|lib:*.a) _slp_candidate=1 ;;',
        '          module:*.ko|module:*.ko.*) _slp_candidate=1 ;;',
        '        esac',
        '        (( _slp_candidate == 1 )) || continue',
        '        case "$_slp_role" in',
        '          exec) ((_slp_exec+=1)) ;;',
        '          lib) ((_slp_libraries+=1)) ;;',
        '          module) ((_slp_modules+=1)) ;;',
        '        esac',
        '        if [[ -L "$_slp_entry" ]]; then',
        '          if ! _slp_target=$(/usr/bin/readlink -f -- "$_slp_entry" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        '            return 0',
        '          fi',
        '          if [[ -z $_slp_target || ! -f "$_slp_target" || -L "$_slp_target" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        '            return 0',
        '          fi',
        '        elif [[ -f "$_slp_entry" ]]; then',
        '          _slp_target=$_slp_entry',
        '        else',
        emit + ' "ERROR" "-" "ERROR"',
        '          return 0',
        '        fi',
        '        if ! _slp_ident=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_target" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        '          return 0',
        '        fi',
        '        if [[ ${_slp_seen_targets["$_slp_ident"]+x} ]]; then continue; fi',
        '        _slp_seen_targets["$_slp_ident"]=1',
        '        if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -Lc %a -- "$_slp_target" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        '          return 0',
        '        fi',
        '        if [[ ! $_slp_mode =~ ^[0-7]{3,4}$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        '          return 0',
        '        fi',
        '        ((_slp_checked+=1))',
        '        if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi',
        '      done',
        '    done',
        '  done',
        '  if (( _slp_exec == 0 || _slp_libraries == 0 || _slp_modules == 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        '    return 0',
        '  fi',
        '  local _slp_value="roots_present=$_slp_roots_present;roots_absent=$_slp_roots_absent;aliases=$_slp_aliases;exec=$_slp_exec;libraries=$_slp_libraries;modules=$_slp_modules;checked=$_slp_checked;violations=$_slp_violations"',
        emit + ' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        '  return 0',
        '}',
    ]
    return "\n".join(lines) + "\n"

def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if locator != CANONICAL_LOCATOR or key != "mode" or op != "bits-clear" or expected != EXPECTED_MASK:
        raise ValueError("only canonical SRC-0012 standard-system-paths contract is supported")
    return _render(control_id, CANONICAL_EXEC_ROOTS, CANONICAL_LIB_ROOTS, CANONICAL_MODULE_TEMPLATE, expected, dynamic_module=True)

def _shell_function_for_layout(control_id, exec_roots, lib_roots, module_root, expected=EXPECTED_MASK):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    roots = tuple(exec_roots) + tuple(lib_roots) + (module_root,)
    if any(not isinstance(x, str) or not x.startswith("/") for x in roots):
        raise ValueError("absolute test roots required")
    return _render(control_id, tuple(exec_roots), tuple(lib_roots), module_root, expected, dynamic_module=False)

MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)

def _selftest():
    assert _mode_compliance("755") is True
    assert _mode_compliance("0644") is True
    assert _mode_compliance("0775") is False
    assert _mode_compliance("0664") is False
    assert _mode_compliance("bogus") is None
    src = shell_function("CTRL", CANONICAL_LOCATOR, "mode", "bits-clear", "0022")
    assert "/usr/bin/find -P" in src and "/usr/bin/readlink -f" in src
    assert "/lib/modules/<uname-r>" in src and "/usr/bin/uname -r" in src
    assert "libraries=" in src and "modules=" in src and "violations=" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    for args in (
        ("CTRL", "/bin", "mode", "bits-clear", "0022"),
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
