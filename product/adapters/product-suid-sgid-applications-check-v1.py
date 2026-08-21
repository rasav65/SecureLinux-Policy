#!/usr/bin/env python3
# Read-only adapter SRC-0013: SUID/SGID application population.
import re

SEMANTIC_CONTRACT_ID = "suid-sgid-applications-check-semantic-v1"
ADAPTER_ID = "product-suid-sgid-applications-check-v1"
ADAPTER_CONTRACT_VERSION = "product-suid-sgid-applications-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "suid-sgid-applications"
SUPPORTED_OPS = ("bits-clear", "subset-of-file")
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/proc/self/mountinfo"
CANONICAL_ALLOWLIST = "/etc/securelinux-policy/suid-sgid.allowlist-v1"
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
        "  local _slp_mp _slp_after _slp_fstype _slp_root_id _slp_entry _slp_ident _slp_mode _slp_marker _slp_find_rc _slp_sort_rc _slp_i",
        "  local _slp_mounts=0 _slp_checked=0 _slp_violations=0 _slp_extras=0 _slp_lineno=0",
        "  local -a _slp_entries=()",
        "  local -A _slp_seen_mounts=() _slp_seen_files=() _slp_allowed=()",
        "",
        '  if [[ ! -f "$_slp_mountinfo" || -L "$_slp_mountinfo" || ! -r "$_slp_mountinfo" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
    ]

    if op == "subset-of-file":
        lines += [
            '  local _slp_allowlist="$_slp_expected" _slp_allow_line',
            '  if [[ "$_slp_allowlist" != /* || ! -f "$_slp_allowlist" || -L "$_slp_allowlist" || ! -r "$_slp_allowlist" ]]; then',
            emit + ' "ERROR" "-" "ERROR"',
            "    return 0",
            "  fi",
            '  while IFS= read -r _slp_allow_line || [[ -n "$_slp_allow_line" ]]; do',
            '    if [[ "$_slp_allow_line" == *$\'\\r\'* || "$_slp_allow_line" == *$\'\\t\'* || "$_slp_allow_line" == *$\'\\n\'* ]]; then',
            emit + ' "ERROR" "-" "ERROR"',
            "      return 0",
            "    fi",
            '    [[ -z "$_slp_allow_line" || "${_slp_allow_line:0:1}" == "#" ]] && continue',
            '    if [[ "$_slp_allow_line" != /* || ${_slp_allowed["$_slp_allow_line"]+x} ]]; then',
            emit + ' "ERROR" "-" "ERROR"',
            "      return 0",
            "    fi",
            '    _slp_allowed["$_slp_allow_line"]=1',
            '  done < "$_slp_allowlist"',
        ]

    lines += [
        '  while IFS= read -r _slp_line || [[ -n "$_slp_line" ]]; do',
        '    ((_slp_lineno+=1))',
        '    [[ -n "$_slp_line" ]] || continue',
        '    IFS=" " read -r _slp_id _slp_parent _slp_majmin _slp_root _slp_mp_raw _slp_opts _slp_tail <<< "$_slp_line"',
        '    if [[ -z "$_slp_id" || -z "$_slp_parent" || -z "$_slp_majmin" || -z "$_slp_root" || -z "$_slp_mp_raw" || -z "$_slp_opts" || -z "$_slp_tail" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ "$_slp_tail" == "- "* ]]; then',
        '      _slp_after=${_slp_tail#- }',
        '    elif [[ "$_slp_tail" == *" - "* ]]; then',
        '      _slp_after=${_slp_tail#*" - "}',
        '    else',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_fstype=${_slp_after%% *}',
        '    [[ -n "$_slp_fstype" ]] || { ' + emit.strip() + ' "ERROR" "-" "ERROR"; return 0; }',
        '    case "$_slp_fstype" in',
        '      ' + pseudo_case + ') continue ;;',
        '    esac',
        '    case ",$_slp_opts," in *,nosuid,*) continue ;; esac',
        '    printf -v _slp_mp "%b" "$_slp_mp_raw"',
        '    if [[ "$_slp_mp" != /* || "$_slp_mp" == *$\'\\r\'* || "$_slp_mp" == *$\'\\n\'* || "$_slp_mp" == *$\'\\t\'* ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ! -d "$_slp_mp" ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if ! _slp_root_id=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_mp" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    if [[ ${_slp_seen_mounts["$_slp_root_id"]+x} ]]; then continue; fi',
        '    _slp_seen_mounts["$_slp_root_id"]=1',
        '    ((_slp_mounts+=1))',
        '    _slp_entries=()',
        '    mapfile -d "" -t _slp_entries < <(',
        '      LC_ALL=C /usr/bin/find -P -- "$_slp_mp" -xdev -type f -"per""m" /6000 -print0 2>/dev/null | LC_ALL=C /usr/bin/sort -z',
        '      _slp_marker="${PIPESTATUS[0]},${PIPESTATUS[1]}"',
        '      printf "__SLP_SCAN_RC=%s\\0" "$_slp_marker"',
        '    )',
        '    if (( ${#_slp_entries[@]} == 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "      return 0",
        "    fi",
        '    _slp_i=$((${#_slp_entries[@]}-1))',
        '    _slp_marker=${_slp_entries[$_slp_i]}',
        "    unset '_slp_entries[$_slp_i]'",
        '    if [[ ! "$_slp_marker" =~ ^__SLP_SCAN_RC=([0-9]+),([0-9]+)$ ]]; then',
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
        '      if [[ "$_slp_entry" == *$\'\\r\'* || "$_slp_entry" == *$\'\\n\'* || "$_slp_entry" == *$\'\\t\'* ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        '      if ! _slp_ident=$(LC_ALL=C /usr/bin/stat -Lc "%d:%i" -- "$_slp_entry" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        '      if [[ ${_slp_seen_files["$_slp_ident"]+x} ]]; then continue; fi',
        '      _slp_seen_files["$_slp_ident"]=1',
        '      if ! _slp_mode=$(LC_ALL=C /usr/bin/stat -Lc "%a" -- "$_slp_entry" 2>/dev/null); then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        '      if [[ ! "$_slp_mode" =~ ^[0-7]{3,4}$ ]]; then',
        emit + ' "ERROR" "-" "ERROR"',
        "        return 0",
        "      fi",
        '      ((_slp_checked+=1))',
    ]

    if op == "bits-clear":
        lines += [
            '      if (( (8#$_slp_mode & 8#$_slp_expected) != 0 )); then ((_slp_violations+=1)); fi',
        ]
    else:
        lines += [
            '      if [[ ! ${_slp_allowed["$_slp_entry"]+x} ]]; then ((_slp_extras+=1)); fi',
        ]

    lines += [
        "    done",
        '  done < "$_slp_mountinfo"',
        '  if (( _slp_mounts == 0 )); then',
        emit + ' "ERROR" "-" "ERROR"',
        "    return 0",
        "  fi",
    ]

    if op == "bits-clear":
        lines += [
            '  local _slp_value="mounts=$_slp_mounts;checked=$_slp_checked;violations=$_slp_violations"',
            emit + ' "VALUE" "$_slp_value" "$([[ $_slp_violations -eq 0 ]] && printf PASS || printf FAIL)"',
        ]
    else:
        lines += [
            '  local _slp_value="mounts=$_slp_mounts;checked=$_slp_checked;extras=$_slp_extras"',
            emit + ' "VALUE" "$_slp_value" "$([[ $_slp_extras -eq 0 ]] && printf PASS || printf FAIL)"',
        ]

    lines += [
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
    if key == "approved-set" and op == "subset-of-file" and expected == CANONICAL_ALLOWLIST:
        return _render(control_id, key, op, expected)
    raise ValueError("unsupported SRC-0013 SUID/SGID contract")

def _shell_function_for_fixture(control_id, key, op, expected, mountinfo_path):
    if not isinstance(mountinfo_path, str) or not mountinfo_path.startswith("/"):
        raise ValueError("absolute fixture mountinfo path required")
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
    two = shell_function("CTRL.ALLOW", CANONICAL_LOCATOR, "approved-set", "subset-of-file", CANONICAL_ALLOWLIST)
    for src in (one, two):
        assert "/usr/bin/find -P" in src
        assert '-"per""m" /6000' in src
        assert "/proc/self/mountinfo" in src
        for token in MUTATING_TOKENS:
            assert token not in src, token
    assert "violations=" in one
    assert "extras=" in two
    for args in (
        ("CTRL", "/proc/mounts", "mode", "bits-clear", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "owner", "bits-clear", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "eq", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "bits-clear", "0033"),
        ("CTRL", CANONICAL_LOCATOR, "approved-set", "subset-of-file", "/tmp/list"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")

if __name__ == "__main__":
    _selftest()
