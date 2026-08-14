#!/usr/bin/env bash

ROOT="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
    pwd
)"

SOURCE="$ROOT/securelinux-ng.sh"

TMP="$(
    mktemp -d
)"
RC_TMP=$?

CASE_SCRIPT="$TMP/case.sh"
RC_EXTRACT=SKIPPED
RC_CASE_SYNTAX=SKIPPED
RC_CASE=SKIPPED

if [[ "$RC_TMP" == "0" && -n "$TMP" ]]; then
    python3 - "$SOURCE" "$CASE_SCRIPT" <<'PYEXTRACT'
from pathlib import Path
import sys

source_path = Path(sys.argv[1])
case_path = Path(sys.argv[2])

source = source_path.read_text(
    encoding="utf-8",
)

start_marker = "atomic_write_command_output() {\n"
end_marker = "\n# acquire_run_lock"

start = source.find(start_marker)
end = source.find(end_marker, start)

if start < 0 or end < 0:
    raise RuntimeError(
        "ATOMIC_WRITER_EXTRACTION_FAILED"
    )

helper = source[start:end].rstrip() + "\n"

case = r'''
FAILURE_COUNT=0
WORK="$1"

function_target="$WORK/function.conf"
external_target="$WORK/external.conf"
stdin_target="$WORK/stdin.conf"
failure_target="$WORK/failure.conf"
invalid_target="$WORK/invalid-target"
side_effect="$WORK/preflight-side-effect"

TEST_ARRAY=(
    alpha
    beta
)

helper_dependency() {
    printf 'DEPENDENCY=%s\n' "$1"
}

render_shell_function() {
    local value="$1"
    local item=""

    printf 'FUNCTION=%s\n' "$value"
    printf 'GLOBAL=%s\n' "$GLOBAL_VALUE"

    for item in "${TEST_ARRAY[@]}"; do
        printf 'ARRAY=%s\n' "$item"
    done

    helper_dependency "VISIBLE"
}

GLOBAL_VALUE='VISIBLE'

atomic_write_command_output \
    "$function_target" \
    0644 \
    render_shell_function \
    'OK'

RC_FUNCTION=$?

EXPECTED_FUNCTION=$'FUNCTION=OK\nGLOBAL=VISIBLE\nARRAY=alpha\nARRAY=beta\nDEPENDENCY=VISIBLE'
ACTUAL_FUNCTION="$(
    cat "$function_target" 2>/dev/null
)"

if [[ "$RC_FUNCTION" != "0" ]]; then
    echo "FAIL=SHELL_FUNCTION_RC:$RC_FUNCTION"
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
elif [[ "$ACTUAL_FUNCTION" != "$EXPECTED_FUNCTION" ]]; then
    echo 'FAIL=SHELL_FUNCTION_CONTENT'
    printf 'ACTUAL=%q\n' "$ACTUAL_FUNCTION"
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
else
    echo 'RESULT=SHELL_FUNCTION_PRODUCER_OK'
fi

printf 'OLD\n' >"$external_target"
chmod 0640 "$external_target"

atomic_write_command_output \
    "$external_target" \
    0644 \
    printf '%s\n' 'EXTERNAL_OK'

RC_EXTERNAL=$?

if [[ "$RC_EXTERNAL" != "0" ]]; then
    echo "FAIL=EXTERNAL_PRODUCER_RC:$RC_EXTERNAL"
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
elif [[ "$(
    cat "$external_target"
)" != 'EXTERNAL_OK' ]]; then
    echo 'FAIL=EXTERNAL_PRODUCER_CONTENT'
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
elif [[ "$(
    stat -c '%a' "$external_target"
)" != '640' ]]; then
    echo 'FAIL=EXTERNAL_MODE_NOT_PRESERVED'
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
else
    echo 'RESULT=EXTERNAL_PRODUCER_OK'
fi

atomic_write_command_output \
    "$stdin_target" \
    0644 \
    python3 - <<'PYDATA'
import sys

payload = sys.stdin.read()

if payload:
    raise RuntimeError(
        "unexpected nested stdin payload"
    )

print("HEREDOC_OK")
PYDATA

RC_STDIN=$?

if [[ "$RC_STDIN" != "0" ]]; then
    echo "FAIL=HEREDOC_PRODUCER_RC:$RC_STDIN"
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
elif [[ "$(
    cat "$stdin_target"
)" != 'HEREDOC_OK' ]]; then
    echo 'FAIL=HEREDOC_PRODUCER_CONTENT'
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
else
    echo 'RESULT=HEREDOC_PRODUCER_OK'
fi

printf 'UNCHANGED\n' >"$failure_target"

failing_shell_function() {
    printf 'MUST_NOT_REPLACE\n'
    return 7
}

atomic_write_command_output \
    "$failure_target" \
    0644 \
    failing_shell_function

RC_FAILURE=$?

if [[ "$RC_FAILURE" != "7" ]]; then
    echo "FAIL=FAILURE_RC_NOT_PRESERVED:$RC_FAILURE"
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
elif [[ "$(
    cat "$failure_target"
)" != 'UNCHANGED' ]]; then
    echo 'FAIL=FAILED_PRODUCER_REPLACED_TARGET'
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
else
    echo 'RESULT=FAILED_PRODUCER_TRANSACTION_OK'
fi

mkdir "$invalid_target"

preflight_side_effect_producer() {
    printf 'RAN\n' >"$side_effect"
    printf 'DATA\n'
}

atomic_write_command_output \
    "$invalid_target" \
    0644 \
    preflight_side_effect_producer

RC_PREFLIGHT=$?

if [[ "$RC_PREFLIGHT" == "0" ]]; then
    echo 'FAIL=INVALID_TARGET_ACCEPTED'
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
elif [[ -e "$side_effect" ]]; then
    echo 'FAIL=PRODUCER_RAN_BEFORE_PREFLIGHT'
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
else
    echo 'RESULT=TARGET_PREFLIGHT_BEFORE_PRODUCER_OK'
fi

PRODUCER_TEMP_COUNT="$(
    find "$WORK" \
        -maxdepth 1 \
        -type f \
        -name '*.securelinux-ng.producer.*' |
    wc -l
)"

if [[ "$PRODUCER_TEMP_COUNT" != "0" ]]; then
    echo "FAIL=PRODUCER_TEMP_REMAINS:$PRODUCER_TEMP_COUNT"
    FAILURE_COUNT=$((FAILURE_COUNT + 1))
else
    echo 'RESULT=PRODUCER_TEMP_CLEANUP_OK'
fi

echo "FAILURE_COUNT=$FAILURE_COUNT"

if [[ "$FAILURE_COUNT" == "0" ]]; then
    echo 'RESULT=ATOMIC_WRITER_SHELL_FUNCTION_REGRESSION_OK'
    true
else
    echo 'FAIL=ATOMIC_WRITER_SHELL_FUNCTION_REGRESSION'
    false
fi
'''

case_path.write_text(
    helper + "\n" + case,
    encoding="utf-8",
)
PYEXTRACT

    RC_EXTRACT=$?
fi

if [[ "$RC_EXTRACT" == "0" ]]; then
    bash -n "$CASE_SCRIPT"
    RC_CASE_SYNTAX=$?
fi

if [[ "$RC_CASE_SYNTAX" == "0" ]]; then
    bash "$CASE_SCRIPT" "$TMP"
    RC_CASE=$?
fi

rm -rf -- "$TMP"
RC_CLEANUP=$?

echo "RC_TMP=$RC_TMP"
echo "RC_EXTRACT=$RC_EXTRACT"
echo "RC_CASE_SYNTAX=$RC_CASE_SYNTAX"
echo "RC_CASE=$RC_CASE"
echo "RC_CLEANUP=$RC_CLEANUP"

if [[ "$RC_TMP" == "0" &&
      "$RC_EXTRACT" == "0" &&
      "$RC_CASE_SYNTAX" == "0" &&
      "$RC_CASE" == "0" &&
      "$RC_CLEANUP" == "0" ]]; then
    echo 'RESULT=ATOMIC_WRITER_SHELL_FUNCTION_TEST_OK'
    true
else
    echo 'FAIL=ATOMIC_WRITER_SHELL_FUNCTION_TEST'
    false
fi
