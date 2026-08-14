#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-state-dir-security-regression"
HARNESS="$TMP_ROOT/harness.sh"

rm -rf -- "$TMP_ROOT"
mkdir -p -- "$TMP_ROOT"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

python3 - "$SOURCE" <<'PYSTATIC'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
errors = []


def function_text(name):
    matches = list(
        re.finditer(
            r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
            source,
        )
    )
    for index, match in enumerate(matches):
        if match.group(1) != name:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        return source[match.start():end]
    errors.append(f"FUNCTION_NOT_FOUND:{name}")
    return ""


secure = function_text("secure_state_dir")
ensure = function_text("ensure_state_dir")
apply_mode = function_text("run_apply_mode")
restore_mode = function_text("run_restore_mode")

for marker in (
    "os.O_NOFOLLOW",
    "os.fstat(fd)",
    "os.lstat(path)",
    "os.fchmod(fd, 0o700)",
    "opened.st_uid != expected_uid",
    "STATE_DIR changed during validation",
):
    if marker not in secure:
        errors.append(f"SECURE_HELPER_MARKER_MISSING:{marker}")

if 'chmod 700 "$STATE_DIR" 2>/dev/null || true' in ensure:
    errors.append("UNCHECKED_STATE_DIR_CHMOD_REMAINS")

guard = 'if ! ensure_state_dir; then\n        return 1\n    fi'

if guard not in apply_mode:
    errors.append("APPLY_STATE_DIR_FAIL_FAST_MISSING")

if guard not in restore_mode:
    errors.append("RESTORE_STATE_DIR_FAIL_FAST_MISSING")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=STATE_DIR_SECURITY_STATIC_REGRESSION_OK")
PYSTATIC
RC_STATIC=$?

python3 - "$SOURCE" "$HARNESS" <<'PYHARNESS'
import re
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
harness_path = Path(sys.argv[2])
source = source_path.read_text(encoding="utf-8")
matches = list(
    re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
        source,
    )
)


def function_text(name):
    for index, match in enumerate(matches):
        if match.group(1) != name:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        return source[match.start():end].rstrip()
    raise RuntimeError(f"function not found: {name}")


body = r'''
ERRORS=()
WARNINGS=()
DRY_RUN=0

log() { :; }
add_error() { ERRORS+=("$1"); }
add_warning() { WARNINGS+=("$1"); }

reset_messages() {
    ERRORS=()
    WARNINGS=()
}

case_create_and_repair() {
    local path="$TMP_ROOT/create"
    secure_state_dir "$path" 2>/dev/null || return 1
    local mode owner
    mode="$(stat -c '%a' "$path")"
    owner="$(stat -c '%u' "$path")"
    printf '%s\n' "CREATE_MODE=$mode" "CREATE_OWNER=$owner"
    [[ "$mode" == "700" ]] || return 1
    [[ "$owner" == "$EUID" ]] || return 1

    chmod 0755 "$path" || return 1
    secure_state_dir "$path" 2>/dev/null || return 1
    mode="$(stat -c '%a' "$path")"
    printf '%s\n' "REPAIRED_MODE=$mode"
    [[ "$mode" == "700" ]] || return 1
    echo "RESULT=STATE_DIR_CREATE_AND_REPAIR_OK"
}

case_symlink_rejected() {
    local target="$TMP_ROOT/symlink-target"
    local link="$TMP_ROOT/symlink-state"
    mkdir -m 0755 "$target" || return 1
    ln -s "$target" "$link" || return 1
    secure_state_dir "$link" 2>/dev/null
    local rc=$?
    local target_mode
    target_mode="$(stat -c '%a' "$target")"
    printf '%s\n' "SYMLINK_RC=$rc" "SYMLINK_TARGET_MODE=$target_mode"
    (( rc != 0 )) || return 1
    [[ -L "$link" ]] || return 1
    [[ "$target_mode" == "755" ]] || return 1
    echo "RESULT=STATE_DIR_SYMLINK_REJECTED_OK"
}

case_non_directory_rejected() {
    local path="$TMP_ROOT/plain-file"
    printf 'x\n' > "$path"
    secure_state_dir "$path" 2>/dev/null
    local rc=$?
    printf '%s\n' "NON_DIRECTORY_RC=$rc"
    (( rc != 0 )) || return 1
    echo "RESULT=STATE_DIR_NON_DIRECTORY_REJECTED_OK"
}

case_owner_mismatch_rejected() {
    local path="$TMP_ROOT/owner"
    mkdir -m 0700 "$path" || return 1
    secure_state_dir "$path" "$(( EUID + 1 ))" 2>/dev/null
    local rc=$?
    printf '%s\n' "OWNER_MISMATCH_RC=$rc"
    (( rc != 0 )) || return 1
    echo "RESULT=STATE_DIR_OWNER_MISMATCH_REJECTED_OK"
}

case_check_fallback() {
    reset_messages
    local target="$TMP_ROOT/check-target"
    local original="$TMP_ROOT/check-link"
    SCRIPT_DIR="$TMP_ROOT/check-script"
    mkdir -p "$target" "$SCRIPT_DIR" || return 1
    chmod 0755 "$target" || return 1
    ln -s "$target" "$original" || return 1

    MODE=check
    RESTORE_MANIFEST=""
    STATE_DIR="$original"
    REPORT_FILE="$original/report.json"
    MANIFEST_FILE="$original/manifest.json"

    ensure_state_dir
    local rc=$?
    local expected="$SCRIPT_DIR/.securelinux-ng-state"
    local mode
    mode="$(stat -c '%a' "$STATE_DIR" 2>/dev/null)"
    printf '%s\n' \
        "CHECK_FALLBACK_RC=$rc" \
        "CHECK_FALLBACK_STATE=$STATE_DIR" \
        "CHECK_FALLBACK_MODE=$mode" \
        "CHECK_FALLBACK_WARNINGS=${#WARNINGS[@]}"
    (( rc == 0 )) || return 1
    [[ "$STATE_DIR" == "$expected" ]] || return 1
    [[ "$REPORT_FILE" == "$expected/report.json" ]] || return 1
    [[ "$MANIFEST_FILE" == "$expected/manifest.json" ]] || return 1
    [[ "$mode" == "700" ]] || return 1
    (( ${#WARNINGS[@]} == 1 )) || return 1
    echo "RESULT=STATE_DIR_CHECK_FALLBACK_OK"
}

case_apply_rejected() {
    reset_messages
    local target="$TMP_ROOT/apply-target"
    local original="$TMP_ROOT/apply-link"
    SCRIPT_DIR="$TMP_ROOT/apply-script"
    mkdir -p "$target" "$SCRIPT_DIR" || return 1
    ln -s "$target" "$original" || return 1

    MODE=apply
    RESTORE_MANIFEST=""
    STATE_DIR="$original"
    REPORT_FILE="$original/report.json"
    MANIFEST_FILE="$original/manifest.json"

    ensure_state_dir
    local rc=$?
    printf '%s\n' \
        "APPLY_REJECT_RC=$rc" \
        "APPLY_REJECT_ERRORS=${#ERRORS[@]}"
    (( rc == 1 )) || return 1
    (( ${#ERRORS[@]} == 1 )) || return 1
    [[ -L "$original" ]] || return 1
    echo "RESULT=STATE_DIR_APPLY_REJECTED_OK"
}

case_dry_run() {
    reset_messages
    DRY_RUN=1
    MODE=apply
    SCRIPT_DIR="$TMP_ROOT/dry-script"
    STATE_DIR="$TMP_ROOT/dry-missing"
    REPORT_FILE="$STATE_DIR/report.json"
    MANIFEST_FILE="$STATE_DIR/manifest.json"
    ensure_state_dir
    local rc=$?
    printf '%s\n' "DRY_RUN_RC=$rc"
    DRY_RUN=0
    (( rc == 0 )) || return 1
    [[ ! -e "$STATE_DIR" ]] || return 1
    echo "RESULT=STATE_DIR_DRY_RUN_OK"
}

main() {
    local rc=0
    case_create_and_repair || rc=1
    case_symlink_rejected || rc=1
    case_non_directory_rejected || rc=1
    case_owner_mismatch_rejected || rc=1
    case_check_fallback || rc=1
    case_apply_rejected || rc=1
    case_dry_run || rc=1
    return "$rc"
}

main
'''

content = "\n\n".join(
    [
        "#!/usr/bin/env bash",
        function_text("secure_state_dir"),
        function_text("ensure_state_dir"),
        body.strip(),
    ]
) + "\n"

harness_path.write_text(content, encoding="utf-8")
harness_path.chmod(0o700)
PYHARNESS
RC_BUILD=$?

if (( RC_BUILD == 0 )); then
    TMP_ROOT="$TMP_ROOT" bash "$HARNESS"
    RC_DYNAMIC=$?
else
    RC_DYNAMIC=1
fi

printf '%s\n' \
    "RC_STATIC=$RC_STATIC" \
    "RC_BUILD=$RC_BUILD" \
    "RC_DYNAMIC=$RC_DYNAMIC"

if (( RC_STATIC == 0 && RC_BUILD == 0 && RC_DYNAMIC == 0 )); then
    echo "RESULT=STATE_DIR_SECURITY_REGRESSION_OK"
else
    echo "RESULT=STATE_DIR_SECURITY_REGRESSION_FAILED"
    false
fi
