#!/usr/bin/env python3
# Read-only adapter SRC-0013: SUID/SGID application population.
import re

SEMANTIC_CONTRACT_ID = "suid-sgid-applications-check-semantic-v2"
ADAPTER_ID = "product-suid-sgid-applications-check-v2"
ADAPTER_CONTRACT_VERSION = "product-suid-sgid-applications-check-adapter-v2"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "suid-sgid-applications"
SUPPORTED_OPS = ("bits-clear",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/proc/self/mountinfo"
EXPECTED_MASK = "0022"
PSEUDO_FS = (
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2",
    "securityfs", "pstore", "bpf", "tracefs", "debugfs", "configfs",
    "fusectl", "mqueue", "hugetlbfs", "ramfs", "autofs",
    "binfmt_misc", "nsfs", "efivarfs",
)

def _mode_compliance(mode_text, expected=EXPECTED_MASK):
    if not isinstance(mode_text, str) or re.fullmatch(r"[0-7]{3,4}", mode_text) is None:
        return None
    return (int(mode_text, 8) & int(expected, 8)) == 0

def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def _render(control_id, key, op, expected, mountinfo_path=CANONICAL_LOCATOR):
    cid = _sh_single(control_id)
    mountinfo = _sh_single(mountinfo_path)
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    pseudo_case = "|".join(PSEUDO_FS)

    lines = [
        fn + "() {",
        "  local _slp_key=" + _sh_single(key) + " _slp_op=" + _sh_single(op) + " _slp_expected=" + _sh_single(expected),
        "  local _slp_mountinfo=" + mountinfo + " _slp_line _slp_id _slp_parent _slp_majmin _slp_root _slp_mp_raw _slp_opts _slp_tail",
        "  local _slp_mp _slp_after _slp_fstype _slp_root_id _slp_entry _slp_ident _slp_mode _slp_marker _slp_find_rc _slp_sort_rc _slp_i _slp_hex",
        "  local _slp_mountinfo_text _slp_rest _slp_v_esc",
        "  local _slp_mounts=0 _slp_checked=0 _slp_violations=0 _slp_lineno=0",
        "  local -a _slp_entries=()",
        "  local -A _slp_seen_mounts=() _slp_seen_files=()",
        "",
        '  if [[ -L "$_slp_mountinfo" ]]; then',
        emit + ' "ERROR" "mountinfo:symlink" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ ! -e "$_slp_mountinfo" ]]; then',
        emit + ' "ERROR" "mountinfo:not-found" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ ! -f "$_slp_mountinfo" ]]; then',
        emit + ' "ERROR" "mountinfo:invalid-type" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ ! -r "$_slp_mountinfo" ]]; then',
        emit + ' "ERROR" "mountinfo:unreadable" "ERROR"',
        "    return 0",
        "  fi",
        '  if ! _slp_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_mountinfo" 2>/dev/null); then',
        emit + ' "ERROR" "mountinfo:read-failed" "ERROR"',
        "    return 0",
        "  fi",
        '  if [[ "$_slp_hex" =~ (^|[[:space:]])00([[:space:]]|$) ]]; then',
        emit + ' "ERROR" "mountinfo:invalid-bytes" "ERROR"',
        "    return 0",
        "  fi",
        # Файл читается один раз: проверенные `od` байты декодируются в текст,
        # который затем разбирается; повторного открытия файла нет.
        '  if [[ -z $_slp_hex ]]; then',
        '    _slp_mountinfo_text=""',
        '  else',
        r"    _slp_v_esc=$(printf '\\x%s' $_slp_hex)",
        '    printf -v _slp_mountinfo_text %b "$_slp_v_esc"',
        '  fi',
    ]

    lines += [
        # Файл читается один раз: разбор идёт по уже декодированному тексту
        # (_slp_mountinfo_text); повторного открытия нет.
        '  _slp_rest=$_slp_mountinfo_text',
        '  while [[ -n $_slp_rest ]]; do',
        '    if [[ $_slp_rest == *$\'\\n\'* ]]; then _slp_line=${_slp_rest%%$\'\\n\'*}; _slp_rest=${_slp_rest#*$\'\\n\'}; else _slp_line=$_slp_rest; _slp_rest=""; fi',
        '    ((_slp_lineno+=1))',
        '    [[ -n "$_slp_line" ]] || continue',
        '    IFS=" " read -r _slp_id _slp_parent _slp_majmin _slp_root _slp_mp_raw _slp_opts _slp_tail <<< "$_slp_line"',
        '    if [[ -z "$_slp_id" || -z "$_slp_parent" || -z "$_slp_majmin" || -z "$_slp_root" || -z "$_slp_mp_raw" || -z "$_slp_opts" || -z "$_slp_tail" ]]; then',
        emit + ' "ERROR" "mountinfo:invalid-fields" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ "$_slp_tail" == "- "* ]]; then',
        '      _slp_after=${_slp_tail#- }',
        '    elif [[ "$_slp_tail" == *" - "* ]]; then',
        '      _slp_after=${_slp_tail#*" - "}',
        '    else',
        emit + ' "ERROR" "mountinfo:missing-separator" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_fstype=${_slp_after%% *}',
        '    [[ -n "$_slp_fstype" ]] || { ' + emit.strip() + ' "ERROR" "mountinfo:missing-fstype" "ERROR"; return 0; }',
        '    case "$_slp_fstype" in',
        '      ' + pseudo_case + ') continue ;;',
        '    esac',
        '    printf -v _slp_mp "%b" "$_slp_mp_raw"',
        '    if [[ "$_slp_mp" != /* || "$_slp_mp" == *$\'\\r\'* || "$_slp_mp" == *$\'\\n\'* || "$_slp_mp" == *$\'\\t\'* ]]; then',
        emit + ' "ERROR" "mountinfo:invalid-mountpoint" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ! -d "$_slp_mp" ]]; then',
        emit + ' "ERROR" "mountinfo:missing-mountpoint" "ERROR"',
        "      return 0",
        "    fi",
        '    if ! _slp_root_id=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_mp" 2>/dev/null); then',
        emit + ' "ERROR" "mountinfo:identity-failed" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ${_slp_seen_mounts["$_slp_root_id"]+x} ]]; then continue; fi',
        '    _slp_seen_mounts["$_slp_root_id"]=1',
        '    ((_slp_mounts+=1))',
        '    _slp_entries=()',
        '    mapfile -d "" -t _slp_entries < <(',
        '      LC_ALL=C command /usr/bin/find -P -- "$_slp_mp" -xdev -type f -"per""m" /6000 -print0 2>/dev/null | LC_ALL=C command /usr/bin/sort -z',
        '      _slp_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"',
        '      printf "__SLP_SCAN_RC=%s\\0" "$_slp_marker"',
        '    )',
        '    if (( ${#_slp_entries[@]} == 0 )); then',
        emit + ' "ERROR" "scan:missing-marker" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_i=$((${#_slp_entries[@]}-1))',
        '    _slp_marker=${_slp_entries[$_slp_i]}',
        "    unset '_slp_entries[$_slp_i]'",
        '    if [[ ! "$_slp_marker" =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then',
        emit + ' "ERROR" "scan:invalid-marker" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_find_rc=${BASH_REMATCH[1]}',
        '    _slp_sort_rc=${BASH_REMATCH[2]}',
        '    if (( _slp_find_rc != 0 )); then',
        emit + ' "ERROR" "scan:find-failed" "ERROR"',
        "      return 0",
        "    fi",
        '    if (( _slp_sort_rc != 0 )); then',
        emit + ' "ERROR" "scan:sort-failed" "ERROR"',
        "      return 0",
        "    fi",
        '    for _slp_entry in "${_slp_entries[@]}"; do',
        '      if [[ "$_slp_entry" == *$\'\\r\'* || "$_slp_entry" == *$\'\\n\'* || "$_slp_entry" == *$\'\\t\'* ]]; then',
        emit + ' "ERROR" "target:invalid-path" "ERROR"',
        "        return 0",
        "      fi",
        '      if ! _slp_ident=$(LC_ALL=C command /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then',
        emit + ' "ERROR" "target:identity-failed" "ERROR"',
        "        return 0",
        "      fi",
        '      if [[ ${_slp_seen_files["$_slp_ident"]+x} ]]; then continue; fi',
        '      _slp_seen_files["$_slp_ident"]=1',
        '      if ! _slp_mode=$(LC_ALL=C command /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then',
        emit + ' "ERROR" "target:mode-read-failed" "ERROR"',
        "        return 0",
        "      fi",
        '      if [[ ! "$_slp_mode" =~ ^[0-7]{3,4}$ ]]; then',
        emit + ' "ERROR" "target:invalid-mode" "ERROR"',
        "        return 0",
        "      fi",
        '      ((_slp_checked+=1))',
    ]

    lines += [
        '      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi',
        "    done",
        '  done',
        '  if (( _slp_mounts == 0 )); then',
        emit + ' "ERROR" "mountinfo:empty-population" "ERROR"',
        "    return 0",
        "  fi",
    ]

    lines += [
        '  local _slp_value="mounts=$_slp_mounts;checked=$_slp_checked;violations=$_slp_violations"',
        emit + ' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        "  return 0",
        "}",
    ]
    return "\n".join(lines) + "\n"

def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if locator != CANONICAL_LOCATOR:
        raise ValueError("unsupported locator")
    if key == "mode" and op == "bits-clear" and expected == EXPECTED_MASK:
        return _render(control_id, key, op, expected)
    raise ValueError("unsupported SRC-0013 SUID/SGID contract")

def _shell_function_for_fixture(control_id, key, op, expected, mountinfo_path):
    if not isinstance(mountinfo_path, str) or not mountinfo_path.startswith("/"):
        raise ValueError("absolute fixture mountinfo path required")
    if (key, op) != ("mode", "bits-clear"):
        raise ValueError("unsupported SRC-0013 SUID/SGID contract")
    return _render(control_id, key, op, expected, mountinfo_path=mountinfo_path)

MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)

def _selftest():
    assert _mode_compliance("4755") is True
    assert _mode_compliance("2755") is True
    assert _mode_compliance("4775") is False
    assert _mode_compliance("2675") is False
    assert _mode_compliance("bogus") is None
    one = shell_function("CTRL.MODE", CANONICAL_LOCATOR, "mode", "bits-clear", "0022")
    assert "command /usr/bin/find -P" in one
    assert '-"per""m" /6000' in one
    assert "/proc/self/mountinfo" in one
    for token in MUTATING_TOKENS:
        assert token not in one, token
    assert "violations=" in one
    for args in (
        ("CTRL", "/proc/mounts", "mode", "bits-clear", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "owner", "bits-clear", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "eq", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "bits-clear", "0033"),
        ("CTRL", CANONICAL_LOCATOR, "approved-set", "subset-of-file", "/tmp/list"),
        ("CTRL", CANONICAL_LOCATOR, "approved-set", "subset-of-file", "/etc/securelinux-policy/suid-sgid.allowlist-v1"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")

if __name__ == "__main__":
    _selftest()
