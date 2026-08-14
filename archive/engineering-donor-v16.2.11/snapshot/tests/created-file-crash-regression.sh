#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-created-file-crash-regression"

main() {
    rm -rf -- "$TMP_ROOT"
    mkdir -p -- "$TMP_ROOT"

    python3 - "$SOURCE" <<'PYTEST'
import re
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
root = source_path.parent
source = source_path.read_text(encoding="utf-8")
errors = []


def function_text(name):
    matches = list(re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
        source,
    ))
    for index, match in enumerate(matches):
        if match.group(1) != name:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        return source[match.start():end]
    errors.append(f"FUNCTION_NOT_FOUND:{name}")
    return ""

manifest_init = function_text("manifest_init")
updater = function_text("update_manifest_created_file_state")
prepare = function_text("prepare_created_file_transaction")
restore_created = function_text("restore_has_created_file")
restore_path = function_text("restore_manifest_has_path")

if '"pending_created_files": []' not in manifest_init:
    errors.append("PENDING_CREATED_FILES_SCHEMA_MISSING")

for marker in (
    'action == "pending"',
    'action == "commit"',
    'os.fsync(fd)',
    'os.replace(temporary, path)',
    'os.fsync(directory_fd)',
):
    if marker not in updater:
        errors.append(f"UPDATER_MARKER_MISSING:{marker}")

if "record_manifest_pending_created_file" not in prepare:
    errors.append("PREPARE_PENDING_WRITER_MISSING")

for name, block in (
    ("restore_has_created_file", restore_created),
    ("restore_manifest_has_path", restore_path),
):
    if "pending_created_files" not in block:
        errors.append(f"RESTORE_PENDING_SUPPORT_MISSING:{name}")

prepare_call_count = len(re.findall(
    r"(?m)^\s+if ! prepare_created_file_transaction \\\\?$",
    source,
))
if prepare_call_count != 19:
    errors.append(f"PREPARE_CALL_COUNT:{prepare_call_count}")

transactions = (
    ("apply_sysctl_userspace_protection_module", "$SYSCTL_USERSPACE_PROTECTION_DROPIN"),
    ("apply_sysctl_userspace_apport_dropin", "$dropin_path"),
    ("apply_sysctl_attack_surface_module", "$SYSCTL_ATTACK_SURFACE_DROPIN"),
    ("apply_sysctl_kernel_module", "$SYSCTL_KERNEL_DROPIN"),
    ("apply_sysctl_network_module", "$SYSCTL_NETWORK_DROPIN"),
    ("apply_sysctl_network_module", "$sysctl_unit"),
    ("apply_ssh_hardening_module", "$SSH_HARDENING_DROPIN"),
    ("apply_account_audit_module", "$ACCOUNT_AUDIT_FILE"),
    ("apply_fail2ban_module", "$FAIL2BAN_JAIL"),
    ("apply_kernel_modules_module", "$KERNEL_MODULE_BLACKLIST"),
    ("apply_auditd_module", "$AUDITD_BASELINE_RULES"),
    ("apply_auditd_module", "$AUDITD_STRICT_RULES"),
    ("apply_password_policy_module", "$PWQUALITY_CONF"),
    ("apply_faillock_module", "$FAILLOCK_CONF"),
    ("apply_sudo_policy_module", "$SUDO_POLICY_DROPIN"),
    ("apply_ssh_root_login_module", "$SSH_ROOT_LOGIN_DROPIN"),
    ("apply_coredump_module", "$COREDUMP_LIMITS_FILE"),
    ("apply_coredump_module", "$COREDUMP_SYSTEMD_FILE"),
    ("apply_coredump_module", "$coredump_sysctl"),
)

for function_name, target in transactions:
    block = function_text(function_name)
    escaped_target = re.escape(target)
    prepare_match = re.search(
        rf'prepare_created_file_transaction\s+\\\s*"{escaped_target}"',
        block,
    )
    commit_match = re.search(
        rf'record_manifest_created_file\s+(?:\\\s*)?"{escaped_target}"',
        block,
    )
    if prepare_match is None:
        errors.append(f"PREPARE_MISSING:{function_name}:{target}")
        continue
    if commit_match is None:
        errors.append(f"COMMIT_MISSING:{function_name}:{target}")
        continue
    if prepare_match.start() > commit_match.start():
        errors.append(f"PREPARE_AFTER_COMMIT:{function_name}:{target}")

for document in (
    root / "README.md",
    root / "docs/architecture.md",
    root / "docs/restore-model.md",
):
    content = document.read_text(encoding="utf-8")
    if "pending_created_files" not in content:
        errors.append(f"DOCUMENTATION_MISSING:{document.name}")

if errors:
    for error in errors:
        print(error)
    raise RuntimeError("created-file crash static regression failed")

print("RESULT=CREATED_FILE_CRASH_STATIC_REGRESSION_OK")
PYTEST
    RC_STATIC=$?

    FUNCTION_SOURCE="$(
python3 - "$SOURCE" <<'PYEXTRACT'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
names = {
    "update_manifest_created_file_state",
    "record_manifest_pending_created_file",
    "record_manifest_created_file",
    "prepare_created_file_transaction",
    "restore_has_created_file",
    "restore_manifest_has_path",
}
matches = list(re.finditer(
    r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
    source,
))
found = set()
for index, match in enumerate(matches):
    name = match.group(1)
    if name not in names:
        continue
    end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
    print(source[match.start():end], end="")
    found.add(name)
missing = names - found
if missing:
    raise RuntimeError("missing functions: " + ",".join(sorted(missing)))
PYEXTRACT
    )"
    RC_EXTRACT=$?

    if (( RC_STATIC != 0 || RC_EXTRACT != 0 )); then
        printf '%s\n' \
            "RC_STATIC=$RC_STATIC" \
            "RC_EXTRACT=$RC_EXTRACT" \
            "RESULT=CREATED_FILE_CRASH_REGRESSION_FAILED"
        rm -rf -- "$TMP_ROOT"
        return 1
    fi

    eval "$FUNCTION_SOURCE"

    DRY_RUN=0
    DEBUG_LOG_FILE="/dev/null"
    MANIFEST_FILE="$TMP_ROOT/manifest.json"
    RESTORE_SOURCE_MANIFEST="$MANIFEST_FILE"
    ERRORS=()

    add_error() { ERRORS+=("$1"); }

    python3 - "$MANIFEST_FILE" <<'PYMANIFEST'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(
    json.dumps(
        {
            "backups": [],
            "pending_created_files": [],
            "created_files": [],
        },
        indent=2,
    ) + "\n",
    encoding="utf-8",
)
PYMANIFEST

    TARGET="$TMP_ROOT/managed.conf"
    LEGACY_TARGET="$TMP_ROOT/legacy.conf"

    prepare_created_file_transaction "$TARGET" 0 "focused test"
    RC_PENDING=$?

    printf '%s\n' "created-after-pending" > "$TARGET"

    restore_has_created_file "$TARGET"
    RC_RESTORE_PENDING=$?

    restore_manifest_has_path "$TARGET"
    RC_PATH_PENDING=$?

    record_manifest_created_file "$TARGET"
    RC_COMMIT=$?

    record_manifest_created_file "$LEGACY_TARGET"
    RC_LEGACY_COMMIT=$?

    COUNTS="$(
python3 - "$MANIFEST_FILE" "$TARGET" "$LEGACY_TARGET" <<'PYCOUNT'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
pending = data.get("pending_created_files", [])
created = data.get("created_files", [])
print(
    f"PENDING_COUNT={len(pending)} "
    f"TARGET_CREATED={int(sys.argv[2] in created)} "
    f"LEGACY_CREATED={int(sys.argv[3] in created)}"
)
PYCOUNT
    )"

    python3 - "$MANIFEST_FILE" <<'PYINVALID'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["pending_created_files"] = {}
path.write_text(json.dumps(data) + "\n", encoding="utf-8")
PYINVALID

    record_manifest_pending_created_file "$TMP_ROOT/invalid.conf" \
        >/dev/null 2>&1
    RC_INVALID=$?

    printf '%s\n' \
        "RC_PENDING=$RC_PENDING" \
        "RC_RESTORE_PENDING=$RC_RESTORE_PENDING" \
        "RC_PATH_PENDING=$RC_PATH_PENDING" \
        "RC_COMMIT=$RC_COMMIT" \
        "RC_LEGACY_COMMIT=$RC_LEGACY_COMMIT" \
        "$COUNTS" \
        "RC_INVALID=$RC_INVALID" \
        "ERROR_COUNT=${#ERRORS[@]}"

    RC_DYNAMIC=0

    [[ "$RC_PENDING" == "0" ]] || RC_DYNAMIC=1
    [[ "$RC_RESTORE_PENDING" == "0" ]] || RC_DYNAMIC=1
    [[ "$RC_PATH_PENDING" == "0" ]] || RC_DYNAMIC=1
    [[ "$RC_COMMIT" == "0" ]] || RC_DYNAMIC=1
    [[ "$RC_LEGACY_COMMIT" == "0" ]] || RC_DYNAMIC=1
    [[ "$COUNTS" == "PENDING_COUNT=0 TARGET_CREATED=1 LEGACY_CREATED=1" ]] || RC_DYNAMIC=1
    [[ "$RC_INVALID" != "0" ]] || RC_DYNAMIC=1
    (( ${#ERRORS[@]} == 0 )) || RC_DYNAMIC=1

    rm -rf -- "$TMP_ROOT"

    if (( RC_DYNAMIC != 0 )); then
        printf '%s\n' \
            "RC_STATIC=$RC_STATIC" \
            "RC_EXTRACT=$RC_EXTRACT" \
            "RC_DYNAMIC=$RC_DYNAMIC" \
            "RESULT=CREATED_FILE_CRASH_REGRESSION_FAILED"
        return 1
    fi

    printf '%s\n' \
        "RESULT=CREATED_FILE_PENDING_RESTORE_OK" \
        "RESULT=CREATED_FILE_COMMIT_OK" \
        "RESULT=CREATED_FILE_LEGACY_COMMIT_OK" \
        "RESULT=CREATED_FILE_INVALID_PENDING_REJECTED_OK" \
        "RC_STATIC=$RC_STATIC" \
        "RC_EXTRACT=$RC_EXTRACT" \
        "RC_DYNAMIC=$RC_DYNAMIC" \
        "RESULT=CREATED_FILE_CRASH_REGRESSION_OK"

    return 0
}

main "$@"
