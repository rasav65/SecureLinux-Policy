#!/usr/bin/env bash

# Проверяет отказ apply/restore от обычных файлов с несколькими hardlink-именами.
# Hardlink topology не хранится в manifest, поэтому безопасное поведение —
# остановить мутацию, а не молча разорвать связь inode.

set -u

ROOT="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"

SOURCE="$ROOT/securelinux-ng.sh"

python3 - "$SOURCE" <<'PYSTATIC'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")

matches = list(
    re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)"
        r"\(\) \{$",
        source,
    )
)

functions = {}
for index, match in enumerate(matches):
    end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
    functions[match.group(1)] = source[match.start():end]

errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

for name in (
    "validate_managed_file_hardlinks",
    "backup_file_checked",
    "atomic_write_command_output",
    "restore_file_from_manifest",
):
    require(name in functions, f"FUNCTION_MISSING:{name}")

validator = functions.get("validate_managed_file_hardlinks", "")
backup = functions.get("backup_file_checked", "")
atomic = functions.get("atomic_write_command_output", "")
restore = functions.get("restore_file_from_manifest", "")

for marker in (
    "os.lstat(path)",
    "stat.S_ISREG(metadata.st_mode)",
    "metadata.st_nlink > 1",
):
    require(marker in validator, f"VALIDATOR_MARKER_MISSING:{marker}")

require(
    'validate_managed_file_hardlinks "$src" "$ctx source"' in backup,
    "BACKUP_HARDLINK_GUARD_MISSING",
)

for marker in (
    "requested_metadata = target.lstat()",
    "requested_metadata.st_nlink > 1",
    "atomic write refused regular file with multiple hard links",
):
    require(marker in atomic, f"ATOMIC_MARKER_MISSING:{marker}")

require(
    restore.count("validate_managed_file_hardlinks") == 3,
    "RESTORE_HARDLINK_GUARD_COUNT_INVALID",
)

for marker in (
    '"restore backup"',
    '"restore target"',
    '"restore created-file target"',
):
    require(marker in restore, f"RESTORE_GUARD_MISSING:{marker}")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=HARDLINK_SAFETY_STATIC_REGRESSION_OK")
PYSTATIC

rc_static=$?
if (( rc_static != 0 )); then
    echo "RC_STATIC=$rc_static"
    exit 1
fi

WORK_DIR="$ROOT/.tmp-hardlink-safety-regression"
rm -rf -- "$WORK_DIR"
mkdir -p "$WORK_DIR"
trap 'rm -rf -- "$WORK_DIR"' EXIT

python3 - "$SOURCE" "$WORK_DIR/functions.sh" <<'PYEXTRACT'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
output = Path(sys.argv[2])
wanted = (
    "validate_managed_file_hardlinks",
    "backup_file_checked",
    "atomic_write_command_output",
    "restore_lookup_backup",
    "restore_has_created_file",
    "restore_file_from_manifest",
)

matches = list(
    re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)"
        r"\(\) \{$",
        source,
    )
)
blocks = {}
for index, match in enumerate(matches):
    end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
    name = match.group(1)
    if name in wanted:
        blocks[name] = source[match.start():end].rstrip()

missing = [name for name in wanted if name not in blocks]
if missing:
    raise SystemExit("Missing functions: " + ", ".join(missing))

output.write_text(
    "\n\n".join(blocks[name] for name in wanted) + "\n",
    encoding="utf-8",
)
PYEXTRACT
rc_extract=$?

if (( rc_extract != 0 )); then
    echo "RC_EXTRACT=$rc_extract"
    exit 1
fi

cat > "$WORK_DIR/harness.sh" <<'HARNESS'
#!/usr/bin/env bash
set -u

WORK_DIR="$1"
DEBUG_LOG_FILE="$WORK_DIR/debug.log"
MANIFEST_FILE="$WORK_DIR/manifest.json"
RESTORE_SOURCE_MANIFEST="$MANIFEST_FILE"
DRY_RUN=0
WARNINGS=()
ERRORS=()
SAFE_ITEMS=()

add_warning() { WARNINGS+=("$1"); }
add_error() { ERRORS+=("$1"); }
add_safe() { SAFE_ITEMS+=("$1"); }
record_manifest_warning() { return 0; }

. "$WORK_DIR/functions.sh"

write_manifest() {
    local original="$1" backup="$2"
    python3 - "$MANIFEST_FILE" "$original" "$backup" <<'PYJSON'
import json
from pathlib import Path
import sys

Path(sys.argv[1]).write_text(
    json.dumps(
        {
            "backups": [
                {
                    "original": sys.argv[2],
                    "backup": sys.argv[3],
                }
            ],
            "created_files": [],
            "pending_created_files": [],
        }
    ),
    encoding="utf-8",
)
PYJSON
}

original="$WORK_DIR/original.conf"
peer="$WORK_DIR/peer.conf"
backup="$WORK_DIR/backup.conf"
printf 'ORIGINAL\n' > "$original"
ln "$original" "$peer"

validate_managed_file_hardlinks "$original" "validate case"
rc_validate=$?
echo "RC_VALIDATE_HARDLINK=$rc_validate"
echo "VALIDATE_ERRORS=${#ERRORS[@]}"

ERRORS=()
backup_file_checked "$original" "$backup" "backup case"
rc_backup=$?
echo "RC_BACKUP_HARDLINK=$rc_backup"
echo "BACKUP_EXISTS=$([[ -e "$backup" ]] && echo 1 || echo 0)"
echo "BACKUP_ERRORS=${#ERRORS[@]}"

ERRORS=()
printf 'NEW\n' | atomic_write_command_output "$original" 0644 cat
rc_atomic=$?
echo "RC_ATOMIC_HARDLINK=$rc_atomic"
echo "ORIGINAL_CONTENT=$(tr -d '\n' < "$original")"
echo "PEER_CONTENT=$(tr -d '\n' < "$peer")"

plain="$WORK_DIR/plain.conf"
printf 'OLD\n' > "$plain"
printf 'NEW\n' | atomic_write_command_output "$plain" 0644 cat
rc_plain_atomic=$?
echo "RC_ATOMIC_PLAIN=$rc_plain_atomic"
echo "PLAIN_CONTENT=$(tr -d '\n' < "$plain")"

restore_backup="$WORK_DIR/restore-backup.conf"
restore_target="$WORK_DIR/restore-target.conf"
restore_peer="$WORK_DIR/restore-peer.conf"
printf 'RESTORED\n' > "$restore_backup"
printf 'CURRENT\n' > "$restore_target"
ln "$restore_target" "$restore_peer"
write_manifest "$restore_target" "$restore_backup"
ERRORS=()
restore_file_from_manifest "$restore_target"
rc_restore_target=$?
echo "RC_RESTORE_TARGET_HARDLINK=$rc_restore_target"
echo "RESTORE_TARGET_CONTENT=$(tr -d '\n' < "$restore_target")"
echo "RESTORE_PEER_CONTENT=$(tr -d '\n' < "$restore_peer")"
echo "RESTORE_TARGET_ERRORS=${#ERRORS[@]}"

backup_hard="$WORK_DIR/backup-hard.conf"
backup_peer="$WORK_DIR/backup-hard-peer.conf"
target_plain="$WORK_DIR/target-plain.conf"
printf 'BACKUP\n' > "$backup_hard"
ln "$backup_hard" "$backup_peer"
printf 'CURRENT\n' > "$target_plain"
write_manifest "$target_plain" "$backup_hard"
ERRORS=()
restore_file_from_manifest "$target_plain"
rc_restore_backup=$?
echo "RC_RESTORE_BACKUP_HARDLINK=$rc_restore_backup"
echo "TARGET_PLAIN_CONTENT=$(tr -d '\n' < "$target_plain")"
echo "RESTORE_BACKUP_ERRORS=${#ERRORS[@]}"

normal_backup="$WORK_DIR/normal-backup.conf"
normal_target="$WORK_DIR/normal-target.conf"
printf 'RESTORED\n' > "$normal_backup"
printf 'CURRENT\n' > "$normal_target"
write_manifest "$normal_target" "$normal_backup"
ERRORS=()
restore_file_from_manifest "$normal_target"
rc_restore_plain=$?
echo "RC_RESTORE_PLAIN=$rc_restore_plain"
echo "NORMAL_TARGET_CONTENT=$(tr -d '\n' < "$normal_target")"
echo "RESTORE_PLAIN_ERRORS=${#ERRORS[@]}"

if (( rc_validate != 1 )); then exit 1; fi
if (( rc_backup != 1 )); then exit 1; fi
if [[ -e "$backup" ]]; then exit 1; fi
if (( rc_atomic == 0 )); then exit 1; fi
if [[ "$(tr -d '\n' < "$original")" != "ORIGINAL" ]]; then exit 1; fi
if [[ "$(tr -d '\n' < "$peer")" != "ORIGINAL" ]]; then exit 1; fi
if (( rc_plain_atomic != 0 )); then exit 1; fi
if [[ "$(tr -d '\n' < "$plain")" != "NEW" ]]; then exit 1; fi
if (( rc_restore_target != 1 )); then exit 1; fi
if [[ "$(tr -d '\n' < "$restore_target")" != "CURRENT" ]]; then exit 1; fi
if [[ "$(tr -d '\n' < "$restore_peer")" != "CURRENT" ]]; then exit 1; fi
if (( rc_restore_backup != 1 )); then exit 1; fi
if [[ "$(tr -d '\n' < "$target_plain")" != "CURRENT" ]]; then exit 1; fi
if (( rc_restore_plain != 0 )); then exit 1; fi
if [[ "$(tr -d '\n' < "$normal_target")" != "RESTORED" ]]; then exit 1; fi

exit 0
HARNESS

chmod 700 "$WORK_DIR/harness.sh"

bash "$WORK_DIR/harness.sh" "$WORK_DIR"
rc_dynamic=$?

echo "RC_STATIC=$rc_static"
echo "RC_EXTRACT=$rc_extract"
echo "RC_DYNAMIC=$rc_dynamic"

if (( rc_static == 0 && rc_extract == 0 && rc_dynamic == 0 )); then
    echo "RESULT=HARDLINK_SAFETY_REGRESSION_OK"
    exit 0
fi

exit 1
