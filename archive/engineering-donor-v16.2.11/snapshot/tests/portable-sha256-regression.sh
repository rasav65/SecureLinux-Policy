#!/usr/bin/env bash

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/tools/write-sha256.py"
TMP_ROOT="$ROOT/.tmp-portable-sha256-regression"

rm -rf "$TMP_ROOT"
mkdir -p "$TMP_ROOT/source with spaces" "$TMP_ROOT/verify"

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

python3 - "$TOOL" <<'PY'
from pathlib import Path
import ast
import sys

tool = Path(sys.argv[1])
source = tool.read_text(encoding="utf-8")
tree = ast.parse(source, filename=str(tool))

required = (
    "path.name",
    "duplicate basenames are not portable",
    "refusing symlink input",
    "refusing symlink output",
    "os.replace(temporary_name, path)",
    "os.fsync(directory_fd)",
)

missing = [marker for marker in required if marker not in source]
if missing:
    for marker in missing:
        print(f"FAIL=PORTABLE_SHA256_STATIC_MISSING:{marker}")
    raise SystemExit(1)

if not any(
    isinstance(node, ast.FunctionDef) and node.name == "sha256_file"
    for node in ast.walk(tree)
):
    raise SystemExit("FAIL=SHA256_FILE_FUNCTION_MISSING")

print("RESULT=PORTABLE_SHA256_STATIC_REGRESSION_OK")
PY
RC_STATIC=$?

ARTIFACT="$TMP_ROOT/source with spaces/SecureLinux-NG-v16.2.11-test.tar.gz"
printf 'portable-checksum-test\n' > "$ARTIFACT"

python3 "$TOOL" "$ARTIFACT" > "$TMP_ROOT/write.log" 2>&1
RC_WRITE=$?

CHECKSUM_FILE="${ARTIFACT}.sha256"
EXPECTED_BASENAME="$(basename "$ARTIFACT")"

RC_CONTENT=0
if [[ ! -f "$CHECKSUM_FILE" ]]; then
    echo "FAIL=CHECKSUM_FILE_MISSING"
    RC_CONTENT=1
else
    ENTRY="$(cat "$CHECKSUM_FILE")"
    ENTRY_NAME="${ENTRY#*  }"

    printf 'ENTRY=%s\n' "$ENTRY"
    printf 'ENTRY_NAME=%s\n' "$ENTRY_NAME"

    if [[ "$ENTRY_NAME" != "$EXPECTED_BASENAME" ]]; then
        echo "FAIL=CHECKSUM_ENTRY_NOT_BASENAME"
        RC_CONTENT=1
    fi

    if [[ "$ENTRY_NAME" == */* ]]; then
        echo "FAIL=CHECKSUM_ENTRY_CONTAINS_PATH_SEPARATOR"
        RC_CONTENT=1
    fi
fi

(
    cd "$(dirname "$ARTIFACT")" || exit 1
    sha256sum -c "$(basename "$CHECKSUM_FILE")"
) > "$TMP_ROOT/check.log" 2>&1
RC_SHA256SUM_CHECK=$?

mkdir -p "$TMP_ROOT/one" "$TMP_ROOT/two"
printf 'one\n' > "$TMP_ROOT/one/same.bin"
printf 'two\n' > "$TMP_ROOT/two/same.bin"

python3 "$TOOL" \
    --output "$TMP_ROOT/duplicates.sha256" \
    "$TMP_ROOT/one/same.bin" \
    "$TMP_ROOT/two/same.bin" \
    > "$TMP_ROOT/duplicates.log" 2>&1
RC_DUPLICATE=$?

ln -s "$ARTIFACT" "$TMP_ROOT/artifact-link.tar.gz"
python3 "$TOOL" "$TMP_ROOT/artifact-link.tar.gz" \
    > "$TMP_ROOT/input-symlink.log" 2>&1
RC_INPUT_SYMLINK=$?

OUTPUT_LINK="$TMP_ROOT/output.sha256"
printf 'do-not-touch\n' > "$TMP_ROOT/output-target"
ln -s "$TMP_ROOT/output-target" "$OUTPUT_LINK"

python3 "$TOOL" \
    --output "$OUTPUT_LINK" \
    "$ARTIFACT" \
    > "$TMP_ROOT/output-symlink.log" 2>&1
RC_OUTPUT_SYMLINK=$?

OUTPUT_TARGET_CONTENT="$(cat "$TMP_ROOT/output-target")"

printf 'RC_STATIC=%s\n' "$RC_STATIC"
printf 'RC_WRITE=%s\n' "$RC_WRITE"
printf 'RC_CONTENT=%s\n' "$RC_CONTENT"
printf 'RC_SHA256SUM_CHECK=%s\n' "$RC_SHA256SUM_CHECK"
printf 'RC_DUPLICATE=%s\n' "$RC_DUPLICATE"
printf 'RC_INPUT_SYMLINK=%s\n' "$RC_INPUT_SYMLINK"
printf 'RC_OUTPUT_SYMLINK=%s\n' "$RC_OUTPUT_SYMLINK"
printf 'OUTPUT_TARGET_CONTENT=%s\n' "$OUTPUT_TARGET_CONTENT"

if [[ "$RC_STATIC" -eq 0
      && "$RC_WRITE" -eq 0
      && "$RC_CONTENT" -eq 0
      && "$RC_SHA256SUM_CHECK" -eq 0
      && "$RC_DUPLICATE" -ne 0
      && "$RC_INPUT_SYMLINK" -ne 0
      && "$RC_OUTPUT_SYMLINK" -ne 0
      && "$OUTPUT_TARGET_CONTENT" == "do-not-touch" ]]
then
    echo "RESULT=PORTABLE_SHA256_REGRESSION_OK"
    exit 0
fi

echo "RESULT=PORTABLE_SHA256_REGRESSION_FAILED"
exit 1
