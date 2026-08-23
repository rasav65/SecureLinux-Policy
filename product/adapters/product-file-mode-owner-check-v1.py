#!/usr/bin/env python3
"""product-file-mode-owner-check-v1.

Read-only adapter: emits one bash function per canonical control of
parameter kind `file-mode-owner`, key `mode`, op `eq` or `bits-clear`.

Not related to step7b0/phase-a/adapter/sysctl-check-adapter-v1.py.
That adapter is historical assurance-line and keeps adapter id
`sysctl-check-v1`. This one is the permanent product line.
"""
import re

SEMANTIC_CONTRACT_ID = "file-mode-owner-check-semantic-v1"
ADAPTER_ID = "product-file-mode-owner-check-v1"
ADAPTER_CONTRACT_VERSION = "product-file-mode-owner-check-adapter-v1"
TARGET_ID = "ubuntu-24.04-x86_64"
PARAMETER_KIND = "file-mode-owner"
SUPPORTED_KEYS = ("mode",)
SUPPORTED_OPS = ("eq", "bits-clear")
WIRE_RECORD_ID = "SLP-CHECK-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
LOCATOR_PATTERN = r"^(?!.*[\r\n])/[A-Za-z0-9._/+:@,=-]+$"
MODE4_PATTERN = r"^[0-7]{4}$"


def shell_function(control_id, locator, key, op, expected):
    """Return the bash source of one read-only check function.

    Fail-closed: anything outside the supported subset raises ValueError.
    `owner`, `group` and `owner_group` are legal in the canonical schema but
    are rejected here until an adapter implements them.
    """
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not isinstance(locator, str) or not re.fullmatch(LOCATOR_PATTERN, locator):
        raise ValueError("invalid locator")
    if "'" in locator or "'" in control_id:
        raise ValueError("quote forbidden in emitted literal")
    if key not in SUPPORTED_KEYS:
        raise ValueError("unsupported key: %r" % (key,))
    if op not in SUPPORTED_OPS:
        raise ValueError("unsupported op: %r" % (op,))
    if not isinstance(expected, str) or not re.fullmatch(MODE4_PATTERN, expected):
        raise ValueError("expected must be exactly four octal digits")
    if op == "bits-clear" and expected == "0000":
        raise ValueError("bits-clear mask 0000 is forbidden")

    path_lit = repr(locator)
    exp_lit = repr(expected)
    cid_lit = repr(control_id)
    if not path_lit.startswith("'") or not cid_lit.startswith("'"):
        raise ValueError("non single-quoted shell literal")

    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    emit = '    printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + repr(WIRE_RECORD_ID) + " " + cid_lit
    emit_error = emit + ' "ERROR" "-" "ERROR"'
    emit_missing = emit + ' "NOT_FOUND" "-" "NOT_FOUND"'
    emit_value = ('    printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + repr(WIRE_RECORD_ID)
                  + " " + cid_lit + ' "VALUE" "$_slp_mode" "$_slp_comp"')

    if op == "eq":
        compare = '    [[ $_slp_mode == "$_slp_expected" ]] && _slp_comp=PASS'
    else:
        compare = '    (( ( 8#$_slp_mode & 8#$_slp_expected ) == 0 )) && _slp_comp=PASS'

    lines = [
        fn + "() {",
        "  local _slp_path=" + path_lit,
        "  local _slp_expected=" + exp_lit,
        "  local _slp_mode _slp_parent _slp_comp",
        "  if [[ ! -x /usr/bin/stat ]]; then",
        emit_error,
        "    return 0",
        "  fi",
        '  if _slp_mode=$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null); then',
        "    if [[ ! $_slp_mode =~ ^[0-7]{1,4}$ ]]; then",
        emit_error,
        "      return 0",
        "    fi",
        '    while [[ ${#_slp_mode} -lt 4 ]]; do _slp_mode="0$_slp_mode"; done',
        "    _slp_comp=FAIL",
        compare,
        emit_value,
        "    return 0",
        "  fi",
        "  _slp_parent=${_slp_path%/*}",
        "  [[ -z $_slp_parent ]] && _slp_parent=/",
        '  if [[ -d $_slp_parent && -x $_slp_parent && ! -e $_slp_path && ! -L $_slp_path ]]; then',
        emit_missing,
        "  else",
        emit_error,
        "  fi",
        "  return 0",
        "}",
    ]
    return "\n".join(lines) + "\n"


MUTATING_TOKENS = (
    "chmod", "chown", "chgrp", "rm ", "rmdir", "mv ", "cp ", "touch", "tee",
    "install ", "truncate", "dd ", "sysctl -w", "setfacl", "ln ", "mkdir",
    ">>", "sed -i",
)


def _selftest():
    s = shell_function("CTRL-A", "/etc/shadow", "mode", "bits-clear", "0077")
    assert "command /usr/bin/stat -L -c %a" in s
    assert "8#$_slp_mode & 8#$_slp_expected" in s
    for token in MUTATING_TOKENS:
        assert token not in s, token
    e = shell_function("CTRL-B", "/etc/passwd", "mode", "eq", "0644")
    assert '[[ $_slp_mode == "$_slp_expected" ]]' in e
    for bad in (
        ("CTRL-C", "/etc/passwd", "owner", "eq", "0644"),
        ("CTRL-C", "/etc/passwd", "group", "eq", "0644"),
        ("CTRL-C", "/etc/passwd", "owner_group", "eq", "0644"),
        ("CTRL-C", "/etc/passwd", "mode", "ge", "0644"),
        ("CTRL-C", "/etc/passwd", "mode", "bits-clear", "0000"),
        ("CTRL-C", "/etc/passwd", "mode", "bits-clear", "077"),
        ("CTRL-C", "etc/passwd", "mode", "eq", "0644"),
        ("CTRL-C", "/etc/pa'sswd", "mode", "eq", "0644"),
        ("CTRL C", "/etc/passwd", "mode", "eq", "0644"),
    ):
        try:
            shell_function(*bad)
        except ValueError:
            continue
        raise AssertionError("accepted: %r" % (bad,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
