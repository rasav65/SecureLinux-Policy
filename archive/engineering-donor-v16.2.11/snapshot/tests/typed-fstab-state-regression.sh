#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-typed-fstab-state-regression"

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
architecture = (root / "docs/architecture.md").read_text(encoding="utf-8")
restore_model = (root / "docs/restore-model.md").read_text(encoding="utf-8")
readme = (root / "README.md").read_text(encoding="utf-8")
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

manifest_init = function_text("manifest_init")
apply_mount = function_text("apply_mount_hardening_module")
apply_tmp = function_text("apply_tmp_tmpfs_module")
restore_mount = function_text("restore_mount_hardening_module")
restore_tmp = function_text("restore_tmp_tmpfs_module")
restore_helper = function_text("restore_fstab_module_if_required")

if '"module_state": {}' not in manifest_init:
    errors.append("MODULE_STATE_FIELD_MISSING")

for document_name, document in (
    ("architecture", architecture),
    ("restore_model", restore_model),
    ("readme", readme),
):
    if "module_state" not in document:
        errors.append(f"MODULE_STATE_DOCUMENTATION_MISSING:{document_name}")

if "apply_report` остаётся только человекочитаемым журналом" not in architecture:
    errors.append("ARCHITECTURE_APPLY_REPORT_ROLE_MISSING")

if "его строки не используются как restore-база" not in restore_model:
    errors.append("RESTORE_MODEL_APPLY_REPORT_ROLE_MISSING")

for name, block, module in (
    ("mount", apply_mount, "mount_hardening"),
    ("tmp", apply_tmp, "tmp_tmpfs"),
):
    marker = f'record_manifest_module_restore_required "{module}"'
    if marker not in block:
        errors.append(f"TYPED_WRITER_MISSING:{name}")
    elif block.find(marker) > block.find("atomic_write_command_output"):
        errors.append(f"TYPED_WRITER_AFTER_MUTATION:{name}")

for name, block in (("mount", restore_mount), ("tmp", restore_tmp)):
    if "restore_manifest_has_report_text" in block:
        errors.append(f"REPORT_TEXT_DEPENDENCY_REMAINS:{name}")
    if "restore_fstab_module_if_required" not in block:
        errors.append(f"TYPED_RESTORE_HELPER_MISSING:{name}")

if 'FSTAB_RESTORE_DONE == 1' not in restore_helper:
    errors.append("FSTAB_RESTORE_DEDUPLICATION_MISSING")

for required in (
    "record_manifest_module_restore_required",
    "restore_manifest_module_restore_required",
    "restore_manifest_has_backup_for",
    "restore_fstab_module_if_required",
):
    function_text(required)

if errors:
    for error in errors:
        print(error)
    raise RuntimeError("typed fstab state static regression failed")

print("RESULT=TYPED_FSTAB_STATE_STATIC_REGRESSION_OK")
PYTEST
    RC_STATIC=$?

    FUNCTION_SOURCE="$(
python3 - "$SOURCE" <<'PYEXTRACT'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
names = {
    "record_manifest_module_restore_required",
    "restore_manifest_module_restore_required",
    "restore_manifest_has_backup_for",
    "restore_fstab_module_if_required",
    "restore_mount_hardening_module",
    "restore_tmp_tmpfs_module",
}

matches = list(
    re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
        source,
    )
)
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
            "RESULT=TYPED_FSTAB_STATE_REGRESSION_FAILED"
        rm -rf -- "$TMP_ROOT"
        return 1
    fi

    eval "$FUNCTION_SOURCE"

    DRY_RUN=0
    DEBUG_LOG_FILE="/dev/null"
    TEST_FSTAB="$TMP_ROOT/fstab"
    TEST_BACKUP="$TMP_ROOT/fstab.bak"
    MANIFEST_FILE="$TMP_ROOT/manifest.json"
    RESTORE_SOURCE_MANIFEST="$MANIFEST_FILE"
    FSTAB_RESTORE_DONE=0
    FSTAB_LAST_MODULE_REQUIRED=0
    RESTORE_CALL_COUNT=0
    WARNINGS=()
    ERRORS=()

    log() { :; }
    add_warning() { WARNINGS+=("$1"); }
    add_error() { ERRORS+=("$1"); }

    restore_lookup_backup() {
        python3 - "$RESTORE_SOURCE_MANIFEST" "$1" <<'PYLOOKUP'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for entry in data.get("backups", []):
    if isinstance(entry, dict) and entry.get("original") == sys.argv[2]:
        print(entry.get("backup", ""))
        break
else:
    print("")
PYLOOKUP
    }

    restore_file_from_manifest() {
        local target="$1"
        [[ "$target" == "/etc/fstab" ]] || return 1
        cp -a -- "$TEST_BACKUP" "$TEST_FSTAB" || return 1
        RESTORE_CALL_COUNT=$((RESTORE_CALL_COUNT + 1))
        return 0
    }

    write_manifest() {
        local mode="$1"
        python3 - "$MANIFEST_FILE" "$TEST_BACKUP" "$mode" <<'PYMANIFEST'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
backup = sys.argv[2]
mode = sys.argv[3]

data = {
    "backups": [
        {
            "original": "/etc/fstab",
            "backup": backup,
        }
    ],
    "apply_report": [],
}

if mode == "typed-empty":
    data["module_state"] = {}
elif mode == "typed-invalid":
    data["module_state"] = []
elif mode == "legacy":
    pass
else:
    raise RuntimeError("unknown manifest mode")

path.write_text(
    json.dumps(data, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
PYMANIFEST
    }

    printf '%s\n' "ORIGINAL_FSTAB" > "$TEST_FSTAB"
    cp -a -- "$TEST_FSTAB" "$TEST_BACKUP"
    write_manifest typed-empty

    record_manifest_module_restore_required "mount_hardening"
    RC_RECORD_MOUNT=$?
    record_manifest_module_restore_required "tmp_tmpfs"
    RC_RECORD_TMP=$?

    printf '%s\n' "HARDENED_WITHOUT_APPLY_REPORT" > "$TEST_FSTAB"

    restore_mount_hardening_module
    RC_RESTORE_MOUNT=$?
    restore_tmp_tmpfs_module
    RC_RESTORE_TMP=$?

    CONTENT_AFTER_TYPED="$(cat "$TEST_FSTAB")"
    APPLY_REPORT_COUNT="$(
python3 - "$MANIFEST_FILE" <<'PYCOUNT'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(len(data.get("apply_report", [])))
PYCOUNT
    )"

    printf '%s\n' \
        "RC_RECORD_MOUNT=$RC_RECORD_MOUNT" \
        "RC_RECORD_TMP=$RC_RECORD_TMP" \
        "RC_RESTORE_MOUNT=$RC_RESTORE_MOUNT" \
        "RC_RESTORE_TMP=$RC_RESTORE_TMP" \
        "CONTENT_AFTER_TYPED=$CONTENT_AFTER_TYPED" \
        "RESTORE_CALL_COUNT=$RESTORE_CALL_COUNT" \
        "APPLY_REPORT_COUNT=$APPLY_REPORT_COUNT" \
        "ERROR_COUNT=${#ERRORS[@]}"

    RC_TYPED=1
    if (( RC_RECORD_MOUNT == 0 )) &&
       (( RC_RECORD_TMP == 0 )) &&
       (( RC_RESTORE_MOUNT == 0 )) &&
       (( RC_RESTORE_TMP == 0 )) &&
       [[ "$CONTENT_AFTER_TYPED" == "ORIGINAL_FSTAB" ]] &&
       (( RESTORE_CALL_COUNT == 1 )) &&
       (( APPLY_REPORT_COUNT == 0 )) &&
       (( ${#ERRORS[@]} == 0 )); then
        RC_TYPED=0
        echo "RESULT=TYPED_STATE_RESTORE_WITHOUT_APPLY_REPORT_OK"
    fi

    FSTAB_RESTORE_DONE=0
    FSTAB_LAST_MODULE_REQUIRED=0
    RESTORE_CALL_COUNT=0
    WARNINGS=()
    ERRORS=()
    write_manifest typed-empty
    printf '%s\n' "UNCHANGED_WITHOUT_MARKER" > "$TEST_FSTAB"

    restore_mount_hardening_module
    RC_TYPED_SKIP_CALL=$?
    CONTENT_TYPED_SKIP="$(cat "$TEST_FSTAB")"

    RC_TYPED_SKIP=1
    if (( RC_TYPED_SKIP_CALL == 0 )) &&
       [[ "$CONTENT_TYPED_SKIP" == "UNCHANGED_WITHOUT_MARKER" ]] &&
       (( RESTORE_CALL_COUNT == 0 )) &&
       (( ${#ERRORS[@]} == 0 )); then
        RC_TYPED_SKIP=0
        echo "RESULT=TYPED_STATE_ABSENT_MODULE_SKIPPED_OK"
    fi

    FSTAB_RESTORE_DONE=0
    FSTAB_LAST_MODULE_REQUIRED=0
    RESTORE_CALL_COUNT=0
    WARNINGS=()
    ERRORS=()
    write_manifest legacy
    printf '%s\n' "LEGACY_HARDENED" > "$TEST_FSTAB"

    restore_tmp_tmpfs_module
    RC_LEGACY_CALL=$?
    CONTENT_LEGACY="$(cat "$TEST_FSTAB")"

    RC_LEGACY=1
    if (( RC_LEGACY_CALL == 0 )) &&
       [[ "$CONTENT_LEGACY" == "ORIGINAL_FSTAB" ]] &&
       (( RESTORE_CALL_COUNT == 1 )) &&
       (( ${#ERRORS[@]} == 0 )); then
        RC_LEGACY=0
        echo "RESULT=LEGACY_FSTAB_BACKUP_FALLBACK_OK"
    fi

    FSTAB_RESTORE_DONE=0
    FSTAB_LAST_MODULE_REQUIRED=0
    RESTORE_CALL_COUNT=0
    WARNINGS=()
    ERRORS=()
    write_manifest typed-invalid

    restore_mount_hardening_module
    RC_INVALID_CALL=$?

    RC_INVALID=1
    if (( RC_INVALID_CALL == 1 )) &&
       (( RESTORE_CALL_COUNT == 0 )) &&
       (( ${#ERRORS[@]} == 1 )); then
        RC_INVALID=0
        echo "RESULT=INVALID_TYPED_STATE_REJECTED_OK"
    fi

    printf '%s\n' '{invalid-json' > "$MANIFEST_FILE"
    record_manifest_module_restore_required "mount_hardening" 2>/dev/null
    RC_INVALID_WRITER_CALL=$?

    RC_INVALID_WRITER=1
    if (( RC_INVALID_WRITER_CALL != 0 )); then
        RC_INVALID_WRITER=0
        echo "RESULT=INVALID_MANIFEST_TYPED_WRITER_REJECTED_OK"
    fi

    printf '%s\n' \
        "RC_STATIC=$RC_STATIC" \
        "RC_EXTRACT=$RC_EXTRACT" \
        "RC_TYPED=$RC_TYPED" \
        "RC_TYPED_SKIP=$RC_TYPED_SKIP" \
        "RC_LEGACY=$RC_LEGACY" \
        "RC_INVALID=$RC_INVALID" \
        "RC_INVALID_WRITER=$RC_INVALID_WRITER"

    rm -rf -- "$TMP_ROOT"

    if (( RC_STATIC == 0 )) &&
       (( RC_EXTRACT == 0 )) &&
       (( RC_TYPED == 0 )) &&
       (( RC_TYPED_SKIP == 0 )) &&
       (( RC_LEGACY == 0 )) &&
       (( RC_INVALID == 0 )) &&
       (( RC_INVALID_WRITER == 0 )); then
        echo "RESULT=TYPED_FSTAB_STATE_REGRESSION_OK"
        return 0
    fi

    echo "RESULT=TYPED_FSTAB_STATE_REGRESSION_FAILED"
    return 1
}

main "$@"
