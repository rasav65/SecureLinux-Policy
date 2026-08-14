#!/usr/bin/env bash

# Проверяет symlink-safe транзакцию:
# backup → manifest → atomic mutation → restore.
#
# Покрываются:
# - относительная ссылка;
# - абсолютная ссылка;
# - висячая ссылка;
# - сохранение mode обычного файла;
# - запрет наследования mode/xattrs через symlink-target;
# - отказ генератора без изменения файла;
# - GRUB backup/restore;
# - атомарные coredump-записи.

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

source = Path(sys.argv[1]).read_text(
    encoding="utf-8"
)

matches = list(
    re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)"
        r"\(\) \{$",
        source,
    )
)

functions = {}

for index, match in enumerate(matches):
    end = (
        matches[index + 1].start()
        if index + 1 < len(matches)
        else len(source)
    )

    functions[match.group(1)] = source[
        match.start():end
    ]

errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

required_functions = (
    "validate_managed_file_hardlinks",
    "backup_file_checked",
    "atomic_write_command_output",
    "restore_lookup_backup",
    "restore_has_created_file",
    "restore_file_from_manifest",
    "apply_grub_kernel_params_module",
    "restore_grub_module",
    "apply_coredump_module",
)

for name in required_functions:
    require(
        name in functions,
        f"FUNCTION_MISSING:{name}",
    )

helper = functions.get(
    "atomic_write_command_output",
    "",
)
apply_grub = functions.get(
    "apply_grub_kernel_params_module",
    "",
)
restore_grub = functions.get(
    "restore_grub_module",
    "",
)
coredump = functions.get(
    "apply_coredump_module",
    "",
)

require(
    "target = requested" in helper,
    "ATOMIC_TARGET_NOT_REQUESTED_PATH",
)

require(
    "resolve(strict=True)" not in helper,
    "ATOMIC_WRITE_DEREFERENCES_SYMLINK",
)

require(
    "requested_is_symlink" in helper,
    "ATOMIC_SYMLINK_METADATA_CLASSIFICATION_MISSING",
)

require(
    "requested_is_regular" in helper,
    "ATOMIC_REGULAR_METADATA_CLASSIFICATION_MISSING",
)

require(
    "if target.exists():" not in helper,
    "ATOMIC_SYMLINK_TARGET_EXISTS_CHECK_REMAINS",
)

require(
    "target.stat()" not in helper,
    "ATOMIC_SYMLINK_TARGET_STAT_REMAINS",
)

require(
    helper.count("follow_symlinks=False") >= 2,
    "ATOMIC_XATTR_NOFOLLOW_MISSING",
)

require(
    "backup_file_checked" in apply_grub,
    "GRUB_BACKUP_HELPER_MISSING",
)

require(
    'cp "${grub_file}" "${grub_backup}"'
    not in apply_grub,
    "GRUB_DIRECT_BACKUP_CP_REMAINS",
)

require(
    'restore_lookup_backup "$grub_file"'
    in restore_grub,
    "GRUB_RESTORE_LOOKUP_MISSING",
)

require(
    'restore_file_from_manifest "$grub_file"'
    in restore_grub,
    "GRUB_COMMON_RESTORE_HELPER_MISSING",
)

require(
    'cp "${backup}" "${grub_file}"'
    not in restore_grub,
    "GRUB_DIRECT_RESTORE_CP_REMAINS",
)

require(
    coredump.count(
        "atomic_write_command_output"
    ) == 3,
    "COREDUMP_ATOMIC_WRITE_COUNT_INVALID",
)

require(
    re.search(
        r">\s*\"\$(?:"
        r"COREDUMP_LIMITS_FILE|"
        r"COREDUMP_SYSTEMD_FILE|"
        r"coredump_sysctl"
        r")\"",
        coredump,
    ) is None,
    "COREDUMP_DIRECT_WRITE_REMAINS",
)

for variable in (
    "COREDUMP_LIMITS_FILE",
    "COREDUMP_SYSTEMD_FILE",
    "coredump_sysctl",
):
    require(
        coredump.count(
            f'|| -L "${variable}"'
        ) == 2,
        f"COREDUMP_SYMLINK_GUARD_INVALID:{variable}",
    )

if errors:
    for error in errors:
        print(f"FAIL={error}")

    raise SystemExit(1)

print("RESULT=SYMLINK_STATIC_REGRESSION_OK")
PYSTATIC

rc_static=$?

if (( rc_static != 0 )); then
    echo "RC_SYMLINK_STATIC=$rc_static"
    exit 1
fi

WORK_DIR="$ROOT/.tmp-symlink-target-regression"

rm -rf -- "$WORK_DIR"

mkdir -p \
    "$WORK_DIR/relative" \
    "$WORK_DIR/absolute" \
    "$WORK_DIR/dangling" \
    "$WORK_DIR/plain" \
    "$WORK_DIR/symlink-metadata-file" \
    "$WORK_DIR/symlink-metadata-directory" \
    "$WORK_DIR/symlink-metadata-devnull" \
    "$WORK_DIR/state"

trap 'rm -rf -- "$WORK_DIR"' EXIT

python3 - \
    "$SOURCE" \
    "$WORK_DIR/functions.sh" \
    <<'PYEXTRACT'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text(
    encoding="utf-8"
)

output_path = Path(sys.argv[2])

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
    end = (
        matches[index + 1].start()
        if index + 1 < len(matches)
        else len(source)
    )

    name = match.group(1)

    if name in wanted:
        blocks[name] = source[
            match.start():end
        ].rstrip()

missing = [
    name
    for name in wanted
    if name not in blocks
]

if missing:
    raise SystemExit(
        "Missing functions: "
        + ", ".join(missing)
    )

output_path.write_text(
    "\n\n".join(
        blocks[name]
        for name in wanted
    )
    + "\n",
    encoding="utf-8",
)
PYEXTRACT

rc_extract=$?

if (( rc_extract != 0 )); then
    echo "RC_SYMLINK_EXTRACT=$rc_extract"
    exit 1
fi

add_warning() {
    printf 'WARNING=%s\n' "$*"
}

record_manifest_warning() {
    printf 'MANIFEST_WARNING=%s\n' "$*"
}

add_error() {
    printf 'ERROR=%s\n' "$*"
}

add_safe() {
    printf 'SAFE=%s\n' "$*"
}

DEBUG_LOG_FILE=/dev/null
RESTORE_SOURCE_MANIFEST="$WORK_DIR/manifest.json"

# shellcheck source=/dev/null
source "$WORK_DIR/functions.sh"

write_backup_manifest() {
    local original="$1"
    local backup="$2"

    python3 - \
        "$RESTORE_SOURCE_MANIFEST" \
        "$original" \
        "$backup" \
        <<'PYMANIFEST'
import json
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
original = sys.argv[2]
backup = sys.argv[3]

manifest.write_text(
    json.dumps(
        {
            "backups": [
                {
                    "original": original,
                    "backup": backup,
                }
            ],
            "created_files": [],
        },
        ensure_ascii=False,
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
PYMANIFEST
}

run_relative_case() {
    local directory="$WORK_DIR/relative"
    local target="$directory/target.real"
    local managed="$directory/managed.conf"
    local backup="$WORK_DIR/state/relative.bak"

    printf 'ORIGINAL_RELATIVE\n' > "$target"
    chmod 0640 "$target"

    ln -s target.real "$managed"

    backup_file_checked \
        "$managed" \
        "$backup" \
        "relative symlink"

    [[ -L "$backup" ]] || {
        echo "FAIL=RELATIVE_BACKUP_NOT_SYMLINK"
        return 1
    }

    write_backup_manifest "$managed" "$backup"

    atomic_write_command_output \
        "$managed" \
        0644 \
        printf '%s\n' HARDENED_RELATIVE

    [[ ! -L "$managed" ]] || {
        echo "FAIL=RELATIVE_PATH_STILL_SYMLINK"
        return 1
    }

    [[ "$(cat "$managed")" == "HARDENED_RELATIVE" ]] || {
        echo "FAIL=RELATIVE_MANAGED_CONTENT"
        return 1
    }

    [[ "$(cat "$target")" == "ORIGINAL_RELATIVE" ]] || {
        echo "FAIL=RELATIVE_TARGET_CHANGED"
        return 1
    }

    [[ "$(stat -c '%a' "$target")" == "640" ]] || {
        echo "FAIL=RELATIVE_TARGET_MODE_CHANGED"
        return 1
    }

    restore_file_from_manifest "$managed"

    [[ -L "$managed" ]] || {
        echo "FAIL=RELATIVE_LINK_NOT_RESTORED"
        return 1
    }

    [[ "$(readlink "$managed")" == "target.real" ]] || {
        echo "FAIL=RELATIVE_LINK_TARGET_CHANGED"
        return 1
    }

    [[ "$(cat "$managed")" == "ORIGINAL_RELATIVE" ]] || {
        echo "FAIL=RELATIVE_CONTENT_NOT_RESTORED"
        return 1
    }

    echo "RESULT=RELATIVE_SYMLINK_TRANSACTION_OK"
}

run_absolute_case() {
    local directory="$WORK_DIR/absolute"
    local target="$directory/target.real"
    local managed="$directory/managed.conf"
    local backup="$WORK_DIR/state/absolute.bak"

    printf 'ORIGINAL_ABSOLUTE\n' > "$target"
    chmod 0600 "$target"

    ln -s "$target" "$managed"

    backup_file_checked \
        "$managed" \
        "$backup" \
        "absolute symlink"

    [[ -L "$backup" ]] || {
        echo "FAIL=ABSOLUTE_BACKUP_NOT_SYMLINK"
        return 1
    }

    write_backup_manifest "$managed" "$backup"

    atomic_write_command_output \
        "$managed" \
        0644 \
        printf '%s\n' HARDENED_ABSOLUTE

    [[ "$(cat "$target")" == "ORIGINAL_ABSOLUTE" ]] || {
        echo "FAIL=ABSOLUTE_TARGET_CHANGED"
        return 1
    }

    [[ "$(stat -c '%a' "$target")" == "600" ]] || {
        echo "FAIL=ABSOLUTE_TARGET_MODE_CHANGED"
        return 1
    }

    restore_file_from_manifest "$managed"

    [[ -L "$managed" ]] || {
        echo "FAIL=ABSOLUTE_LINK_NOT_RESTORED"
        return 1
    }

    [[ "$(readlink "$managed")" == "$target" ]] || {
        echo "FAIL=ABSOLUTE_LINK_TARGET_CHANGED"
        return 1
    }

    [[ "$(cat "$managed")" == "ORIGINAL_ABSOLUTE" ]] || {
        echo "FAIL=ABSOLUTE_CONTENT_NOT_RESTORED"
        return 1
    }

    echo "RESULT=ABSOLUTE_SYMLINK_TRANSACTION_OK"
}

run_dangling_case() {
    local directory="$WORK_DIR/dangling"
    local missing="$directory/missing.real"
    local managed="$directory/managed.conf"
    local backup="$WORK_DIR/state/dangling.bak"

    ln -s missing.real "$managed"

    backup_file_checked \
        "$managed" \
        "$backup" \
        "dangling symlink"

    [[ -L "$backup" ]] || {
        echo "FAIL=DANGLING_BACKUP_NOT_SYMLINK"
        return 1
    }

    write_backup_manifest "$managed" "$backup"

    atomic_write_command_output \
        "$managed" \
        0644 \
        printf '%s\n' HARDENED_DANGLING

    [[ ! -L "$managed" ]] || {
        echo "FAIL=DANGLING_PATH_STILL_SYMLINK"
        return 1
    }

    [[ ! -e "$missing" ]] || {
        echo "FAIL=DANGLING_TARGET_CREATED"
        return 1
    }

    restore_file_from_manifest "$managed"

    [[ -L "$managed" ]] || {
        echo "FAIL=DANGLING_LINK_NOT_RESTORED"
        return 1
    }

    [[ "$(readlink "$managed")" == "missing.real" ]] || {
        echo "FAIL=DANGLING_LINK_TARGET_CHANGED"
        return 1
    }

    [[ ! -e "$missing" ]] || {
        echo "FAIL=DANGLING_TARGET_EXISTS_AFTER_RESTORE"
        return 1
    }

    echo "RESULT=DANGLING_SYMLINK_TRANSACTION_OK"
}

run_symlink_metadata_case() {
    local file_directory="$WORK_DIR/symlink-metadata-file"
    local file_target="$file_directory/weak-target.conf"
    local file_managed="$file_directory/managed.conf"

    printf 'WEAK_TARGET_ORIGINAL\n' > "$file_target"
    chmod 0666 "$file_target"
    ln -s weak-target.conf "$file_managed"

    atomic_write_command_output \
        "$file_managed" \
        0600 \
        printf '%s\n' HARDENED_FILE_SYMLINK

    [[ ! -L "$file_managed" ]] || {
        echo "FAIL=FILE_METADATA_PATH_STILL_SYMLINK"
        return 1
    }

    [[ "$(stat -c '%a' "$file_managed")" == "600" ]] || {
        echo "FAIL=FILE_SYMLINK_TARGET_MODE_INHERITED:$(stat -c '%a' "$file_managed")"
        return 1
    }

    [[ "$(stat -c '%a' "$file_target")" == "666" ]] || {
        echo "FAIL=FILE_SYMLINK_TARGET_MODE_CHANGED"
        return 1
    }

    [[ "$(cat "$file_target")" == "WEAK_TARGET_ORIGINAL" ]] || {
        echo "FAIL=FILE_SYMLINK_TARGET_CONTENT_CHANGED"
        return 1
    }

    local directory_directory="$WORK_DIR/symlink-metadata-directory"
    local directory_target="$directory_directory/target.dir"
    local directory_managed="$directory_directory/managed.conf"

    mkdir "$directory_target"
    chmod 0755 "$directory_target"
    ln -s target.dir "$directory_managed"

    atomic_write_command_output \
        "$directory_managed" \
        0644 \
        printf '%s\n' HARDENED_DIRECTORY_SYMLINK

    [[ "$(stat -c '%a' "$directory_managed")" == "644" ]] || {
        echo "FAIL=DIRECTORY_SYMLINK_TARGET_MODE_INHERITED:$(stat -c '%a' "$directory_managed")"
        return 1
    }

    [[ -d "$directory_target" ]] || {
        echo "FAIL=DIRECTORY_SYMLINK_TARGET_REMOVED"
        return 1
    }

    local devnull_directory="$WORK_DIR/symlink-metadata-devnull"
    local devnull_managed="$devnull_directory/managed.conf"

    ln -s /dev/null "$devnull_managed"

    atomic_write_command_output \
        "$devnull_managed" \
        0644 \
        printf '%s\n' HARDENED_DEVNULL_SYMLINK

    [[ "$(stat -c '%a' "$devnull_managed")" == "644" ]] || {
        echo "FAIL=DEVNULL_SYMLINK_TARGET_MODE_INHERITED:$(stat -c '%a' "$devnull_managed")"
        return 1
    }

    echo "RESULT=SYMLINK_DEFAULT_METADATA_REGRESSION_OK"
}

run_plain_case() {
    local managed="$WORK_DIR/plain/managed.conf"

    printf 'PLAIN_OLD\n' > "$managed"
    chmod 0640 "$managed"

    atomic_write_command_output \
        "$managed" \
        0644 \
        printf '%s\n' PLAIN_NEW

    [[ "$(stat -c '%a' "$managed")" == "640" ]] || {
        echo "FAIL=PLAIN_MODE_NOT_PRESERVED"
        return 1
    }

    [[ "$(cat "$managed")" == "PLAIN_NEW" ]] || {
        echo "FAIL=PLAIN_CONTENT_INVALID"
        return 1
    }

    if atomic_write_command_output \
        "$managed" \
        0644 \
        false
    then
        echo "FAIL=FAILING_COMMAND_SUCCEEDED"
        return 1
    fi

    [[ "$(cat "$managed")" == "PLAIN_NEW" ]] || {
        echo "FAIL=PLAIN_CHANGED_AFTER_FAILURE"
        return 1
    }

    local temporary_count

    temporary_count="$(
        find "$WORK_DIR" \
            -name '*.securelinux-ng.*' \
            -print |
        wc -l
    )"

    [[ "$temporary_count" == "0" ]] || {
        echo "FAIL=TEMPORARY_FILES_LEFT:$temporary_count"
        return 1
    }

    echo "RESULT=PLAIN_ATOMIC_WRITE_REGRESSION_OK"
}

run_relative_case
rc_relative=$?

run_absolute_case
rc_absolute=$?

run_dangling_case
rc_dangling=$?

run_symlink_metadata_case
rc_symlink_metadata=$?

run_plain_case
rc_plain=$?

printf 'RC_RELATIVE_SYMLINK=%s\n' "$rc_relative"
printf 'RC_ABSOLUTE_SYMLINK=%s\n' "$rc_absolute"
printf 'RC_DANGLING_SYMLINK=%s\n' "$rc_dangling"
printf 'RC_SYMLINK_DEFAULT_METADATA=%s\n' "$rc_symlink_metadata"
printf 'RC_PLAIN_ATOMIC_WRITE=%s\n' "$rc_plain"

if (( rc_relative == 0
      && rc_absolute == 0
      && rc_dangling == 0
      && rc_symlink_metadata == 0
      && rc_plain == 0 ))
then
    echo "RESULT=SYMLINK_TARGET_REGRESSION_OK"
    exit 0
fi

echo "RESULT=SYMLINK_TARGET_REGRESSION_FAILED"
exit 1
