#!/usr/bin/env bash

export PATH="/usr/local/bin:/usr/bin:/bin"
cd "$(dirname "$0")/.." || exit 1

SOURCE="$(pwd)/securelinux-ng.sh"
TMP_ROOT="$(pwd)/.tmp-manifest-resolution-regression"
HARNESS="$TMP_ROOT/harness.sh"

rm -rf "$TMP_ROOT"
mkdir -p "$TMP_ROOT"

python3 - "$SOURCE" "$HARNESS" <<'PYBUILD'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
harness_path = Path(sys.argv[2])

start = source.index("resolve_restore_manifest() {")
end = source.index("\n}\n\nrestore_lookup_backup()", start) + 2
function_text = source[start:end]

required = (
    'archive_pattern = re.compile(',
    'r"^.+[.]json[.]bak-([0-9]{8}-[0-9]{6})$"',
    'if item.is_symlink() or not item.is_file():',
    'print(max(archives)[2])',
)
for marker in required:
    if marker not in function_text:
        raise SystemExit(f"MISSING_SOURCE_MARKER:{marker}")

harness = r'''#!/usr/bin/env bash
set -u

die() {
    printf 'DIE=%s\n' "$*" >&2
    exit 1
}

''' + function_text + r'''

RESTORE_MANIFEST="${RESTORE_MANIFEST:-}"
RESTORE_SOURCE_MANIFEST=""
resolve_restore_manifest
printf '%s\n' "$RESTORE_SOURCE_MANIFEST"
'''

harness_path.write_text(harness, encoding="utf-8")
harness_path.chmod(0o755)
print("RESULT=MANIFEST_RESOLUTION_STATIC_REGRESSION_OK")
PYBUILD
RC_BUILD=$?

run_case() {
    local state_dir="$1"
    RESTORE_MANIFEST="${2:-}" STATE_DIR="$state_dir" bash "$HARNESS"
}

RC_DATED=99
RC_CURRENT=99
RC_ARCHIVE=99
RC_SYMLINK=99
RC_EXPLICIT=99
RC_MISSING=99

if (( RC_BUILD == 0 )); then
    DATED_DIR="$TMP_ROOT/dated"
    mkdir -p "$DATED_DIR"
    : > "$DATED_DIR/manifest-20260804-100000.json"
    : > "$DATED_DIR/manifest-20260804-120000.json"
    : > "$DATED_DIR/manifest.json"
    DATED_RESULT="$(run_case "$DATED_DIR")"
    RC_DATED=$?
    printf 'DATED_RESULT=%s\n' "$DATED_RESULT"
    [[ "$DATED_RESULT" == "$DATED_DIR/manifest-20260804-120000.json" ]] || RC_DATED=1

    CURRENT_DIR="$TMP_ROOT/current"
    mkdir -p "$CURRENT_DIR"
    : > "$CURRENT_DIR/manifest.json"
    : > "$CURRENT_DIR/manifest.json.bak-20260804-130000"
    CURRENT_RESULT="$(run_case "$CURRENT_DIR")"
    RC_CURRENT=$?
    printf 'CURRENT_RESULT=%s\n' "$CURRENT_RESULT"
    [[ "$CURRENT_RESULT" == "$CURRENT_DIR/manifest.json" ]] || RC_CURRENT=1

    ARCHIVE_DIR="$TMP_ROOT/archive"
    mkdir -p "$ARCHIVE_DIR"
    : > "$ARCHIVE_DIR/manifest.json.bak-20260804-120000"
    : > "$ARCHIVE_DIR/custom.json.bak-20260804-140000"
    : > "$ARCHIVE_DIR/manifest.json.bak-invalid"
    ARCHIVE_RESULT="$(run_case "$ARCHIVE_DIR")"
    RC_ARCHIVE=$?
    printf 'ARCHIVE_RESULT=%s\n' "$ARCHIVE_RESULT"
    [[ "$ARCHIVE_RESULT" == "$ARCHIVE_DIR/custom.json.bak-20260804-140000" ]] || RC_ARCHIVE=1

    SYMLINK_DIR="$TMP_ROOT/symlink"
    mkdir -p "$SYMLINK_DIR"
    : > "$SYMLINK_DIR/manifest.json.bak-20260804-120000"
    : > "$TMP_ROOT/outside.json"
    ln -s "$TMP_ROOT/outside.json" "$SYMLINK_DIR/manifest.json.bak-20260804-150000"
    SYMLINK_RESULT="$(run_case "$SYMLINK_DIR")"
    RC_SYMLINK=$?
    printf 'SYMLINK_RESULT=%s\n' "$SYMLINK_RESULT"
    [[ "$SYMLINK_RESULT" == "$SYMLINK_DIR/manifest.json.bak-20260804-120000" ]] || RC_SYMLINK=1

    EXPLICIT_DIR="$TMP_ROOT/explicit"
    mkdir -p "$EXPLICIT_DIR"
    : > "$EXPLICIT_DIR/chosen.json"
    EXPLICIT_RESULT="$(run_case "$EXPLICIT_DIR" "$EXPLICIT_DIR/chosen.json")"
    RC_EXPLICIT=$?
    printf 'EXPLICIT_RESULT=%s\n' "$EXPLICIT_RESULT"
    [[ "$EXPLICIT_RESULT" == "$EXPLICIT_DIR/chosen.json" ]] || RC_EXPLICIT=1

    MISSING_DIR="$TMP_ROOT/missing"
    mkdir -p "$MISSING_DIR"
    if run_case "$MISSING_DIR" > "$TMP_ROOT/missing.out" 2>&1; then
        RC_MISSING=1
    else
        RC_MISSING=0
    fi
fi

printf 'RC_BUILD=%s\n' "$RC_BUILD"
printf 'RC_DATED=%s\n' "$RC_DATED"
printf 'RC_CURRENT=%s\n' "$RC_CURRENT"
printf 'RC_ARCHIVE=%s\n' "$RC_ARCHIVE"
printf 'RC_SYMLINK=%s\n' "$RC_SYMLINK"
printf 'RC_EXPLICIT=%s\n' "$RC_EXPLICIT"
printf 'RC_MISSING=%s\n' "$RC_MISSING"

rm -rf "$TMP_ROOT"

if (( RC_BUILD == 0 \
      && RC_DATED == 0 \
      && RC_CURRENT == 0 \
      && RC_ARCHIVE == 0 \
      && RC_SYMLINK == 0 \
      && RC_EXPLICIT == 0 \
      && RC_MISSING == 0 )); then
    echo "RESULT=MANIFEST_RESOLUTION_REGRESSION_OK"
    exit 0
fi

exit 1
