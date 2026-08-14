#!/usr/bin/env bash
set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
WORK="$(mktemp -d "$ROOT/.write-once-sysctl-test.XXXXXX")"
FUNCTION_FILE="$WORK/restore-function.sh"
FAILURES=0

cleanup() {
    if (( FAILURES != 0 )); then
        printf 'DIAGNOSTIC_WORK=%s\n' "$WORK"
        return
    fi

    rm -rf -- "$WORK"
}
trap cleanup EXIT

fail() {
    printf 'FAIL=%s\n' "$1"
    FAILURES=$((FAILURES + 1))
}

require_marker() {
    local marker="$1"

    if ! grep -Fq -- "$marker" "$SOURCE"; then
        fail "MISSING_SOURCE_MARKER:$marker"
    fi
}

require_marker 'WRITE_ONCE_TRANSITIONS = {'
require_marker '"kernel.kexec_load_disabled"'
require_marker '"kernel.unprivileged_bpf_disabled"'
require_marker '"kernel.yama.ptrace_scope"'
require_marker 'current_result = subprocess.run('
require_marker 'proc_path.is_file()'
require_marker 'os.statvfs(proc_path)'
require_marker 'in WRITE_ONCE_TRANSITIONS.get(key, set())'
require_marker 'raise SystemExit(5)'
require_marker 'add_restore_irreversible "$partial_message"'
require_marker '"irreversible_changes": split_lines(sys.argv[19])'

python3 - "$SOURCE" "$FUNCTION_FILE" <<'PY'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
lines = source.read_text(encoding="utf-8").splitlines(keepends=True)

start = None
for index, line in enumerate(lines):
    if line.rstrip("\n") == "restore_sysctl_runtime_snapshot() {":
        start = index
        break

if start is None:
    raise SystemExit("restore_sysctl_runtime_snapshot not found")

function_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\(\) \{\s*$")
end = None

for index in range(start + 1, len(lines)):
    if function_re.match(lines[index].rstrip("\n")):
        end = index
        break

if end is None:
    raise SystemExit("next top-level function not found")

target.write_text("".join(lines[start:end]), encoding="utf-8")
PY
RC_EXTRACT=$?

if (( RC_EXTRACT != 0 )); then
    fail "FUNCTION_EXTRACTION_RC_$RC_EXTRACT"
fi

bash -n "$FUNCTION_FILE"
RC_FUNCTION_SYNTAX=$?

if (( RC_FUNCTION_SYNTAX != 0 )); then
    fail "FUNCTION_SYNTAX_RC_$RC_FUNCTION_SYNTAX"
fi

run_case() {
    local name="$1"
    local injected_rc="$2"
    local expected_rc="$3"
    local expected_warning_count="$4"
    local expected_irreversible_count="$5"
    local scenario_mode="${6:-injected}"
    local case_dir="$WORK/$name"
    local output="$case_dir/output.txt"
    local real_python3
    real_python3="$(command -v python3)"

    mkdir -p "$case_dir/bin"
    mkdir -p "$case_dir/proc"
    : > "$case_dir/manifest.json"
    : > "$case_dir/snapshot.json"

    case "$scenario_mode" in
        injected)
            ;;
        write_once_only|ordinary_known|already_target|proc_missing)
            cat > "$case_dir/snapshot.json" <<'JSON'
{"values":[{"key":"kernel.kexec_load_disabled","value":"0"}],"missing":[]}
JSON

            if [[ "$scenario_mode" != "proc_missing" ]]; then
                mkdir -p "$case_dir/proc/kernel"
                : > "$case_dir/proc/kernel/kexec_load_disabled"
            fi
            ;;
        mixed)
            cat > "$case_dir/snapshot.json" <<'JSON'
{"values":[{"key":"kernel.kexec_load_disabled","value":"0"},{"key":"net.ipv4.ip_forward","value":"0"}],"missing":[]}
JSON

            mkdir -p "$case_dir/proc/kernel"
            mkdir -p "$case_dir/proc/net/ipv4"
            : > "$case_dir/proc/kernel/kexec_load_disabled"
            : > "$case_dir/proc/net/ipv4/ip_forward"
            ;;
        *)
            fail "${name}:UNKNOWN_SCENARIO_MODE_$scenario_mode"
            return
            ;;
    esac

    cat > "$case_dir/bin/python3" <<'FAKE'
#!/usr/bin/env bash
count=0

if [[ -f "$FAKE_PYTHON_COUNTER" ]]; then
    read -r count < "$FAKE_PYTHON_COUNTER"
fi

count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_PYTHON_COUNTER"

if (( count == 1 )); then
    printf '1\n%s\n' "$FAKE_SNAPSHOT"
    exit 0
fi

if [[ "$FAKE_SECOND_RC" == "real" ]]; then
    exec "$REAL_PYTHON3" "$@"
fi

exit "$FAKE_SECOND_RC"
FAKE

    cat > "$case_dir/bin/sysctl" <<'FAKE'
#!/usr/bin/env bash

if [[ "${1:-}" == "-w" ]]; then
    printf 'simulated write failure\n' >&2
    exit 1
fi

if [[ "${1:-}" == "-n" ]]; then
    case "$FAKE_SYSCTL_MODE:${2:-}" in
        write_once_only:kernel.kexec_load_disabled)
            printf '1\n'
            exit 0
            ;;
        ordinary_known:kernel.kexec_load_disabled)
            printf '2\n'
            exit 0
            ;;
        already_target:kernel.kexec_load_disabled)
            printf '0\n'
            exit 0
            ;;
        proc_missing:kernel.kexec_load_disabled)
            printf '1\n'
            exit 0
            ;;
        mixed:kernel.kexec_load_disabled)
            printf '1\n'
            exit 0
            ;;
        mixed:net.ipv4.ip_forward)
            printf '1\n'
            exit 0
            ;;
    esac
fi

printf 'unexpected fake sysctl call: %s\n' "$*" >&2
exit 1
FAKE

    chmod 700 "$case_dir/bin/python3"
    chmod 700 "$case_dir/bin/sysctl"

    PATH="$case_dir/bin:$PATH" \
    FAKE_PYTHON_COUNTER="$case_dir/counter" \
    FAKE_SNAPSHOT="$case_dir/snapshot.json" \
    FAKE_SECOND_RC="$injected_rc" \
    FAKE_SYSCTL_MODE="$scenario_mode" \
    REAL_PYTHON3="$real_python3" \
    SECURELINUX_SYSCTL_PROC_ROOT="$case_dir/proc" \
    FUNCTION_FILE="$FUNCTION_FILE" \
    MANIFEST="$case_dir/manifest.json" \
    FALLBACK="$case_dir/absent-fallback.conf" \
    bash <<'HARNESS' > "$output" 2>&1
set -u
source "$FUNCTION_FILE"

declare -a ERRORS=()
declare -a WARNINGS=()
declare -a RESTORE_IRREVERSIBLE_CHANGES=()

log() {
    :
}

add_error() {
    ERRORS+=("$1")
}

add_warning() {
    WARNINGS+=("$1")
}

add_restore_irreversible() {
    RESTORE_IRREVERSIBLE_CHANGES+=("$1")
}

RESTORE_SOURCE_MANIFEST="$MANIFEST"
DEBUG_LOG_FILE="/dev/null"

restore_sysctl_runtime_snapshot \
    "focused-test" \
    "$FALLBACK"

rc=$?

printf 'RC=%s\n' "$rc"
printf 'ERROR_COUNT=%s\n' "${#ERRORS[@]}"
printf 'WARNING_COUNT=%s\n' "${#WARNINGS[@]}"
printf 'IRREVERSIBLE_COUNT=%s\n' \
    "${#RESTORE_IRREVERSIBLE_CHANGES[@]}"

for item in "${ERRORS[@]}"; do
    printf 'ERROR=%s\n' "$item"
done

for item in "${WARNINGS[@]}"; do
    printf 'WARNING=%s\n' "$item"
done

for item in "${RESTORE_IRREVERSIBLE_CHANGES[@]}"; do
    printf 'IRREVERSIBLE=%s\n' "$item"
done
HARNESS
    local harness_rc=$?
    local actual_rc
    local actual_warning_count
    local actual_irreversible_count

    actual_rc="$(
        awk -F= \
            '$1 == "RC" {value = substr($0, 4)} END {print value}' \
            "$output"
    )"

    actual_warning_count="$(
        awk -F= \
            '$1 == "WARNING_COUNT" {value = substr($0, 15)} END {print value}' \
            "$output"
    )"

    actual_irreversible_count="$(
        awk -F= \
            '$1 == "IRREVERSIBLE_COUNT" {value = substr($0, 20)} END {print value}' \
            "$output"
    )"

    printf '=== CASE %s ACTUAL OUTPUT ===\n' "$name"
    cat -- "$output"
    printf '=== END CASE %s ACTUAL OUTPUT ===\n' "$name"

    if (( harness_rc != 0 )); then
        fail "${name}:HARNESS_RC_$harness_rc"
        printf 'SCENARIO=%s HARNESS_RC=%s\n' \
            "$name" \
            "$harness_rc"
        return
    fi

    if ! grep -Fxq "RC=$expected_rc" "$output"; then
        fail "${name}:UNEXPECTED_RC"
        printf 'EXPECTED_RC=%s ACTUAL_RC=%s\n' \
            "$expected_rc" \
            "${actual_rc:-MISSING}"
    fi

    if ! grep -Fxq \
        "WARNING_COUNT=$expected_warning_count" \
        "$output"
    then
        fail "${name}:UNEXPECTED_WARNING_COUNT"
        printf 'EXPECTED_WARNING_COUNT=%s ACTUAL_WARNING_COUNT=%s\n' \
            "$expected_warning_count" \
            "${actual_warning_count:-MISSING}"
    fi

    if ! grep -Fxq \
        "IRREVERSIBLE_COUNT=$expected_irreversible_count" \
        "$output"
    then
        fail "${name}:UNEXPECTED_IRREVERSIBLE_COUNT"
        printf 'EXPECTED_IRREVERSIBLE_COUNT=%s ACTUAL_IRREVERSIBLE_COUNT=%s\n' \
            "$expected_irreversible_count" \
            "${actual_irreversible_count:-MISSING}"
    fi

    printf 'SCENARIO=%s RC=%s WARNINGS=%s IRREVERSIBLE=%s\n' \
        "$name" \
        "${actual_rc:-MISSING}" \
        "${actual_warning_count:-MISSING}" \
        "${actual_irreversible_count:-MISSING}"
}

run_case write_once_only 5 0 1 1
run_case ordinary_failure 2 1 1 0
run_case incomplete_snapshot 3 1 1 0
run_case complete_success 0 0 0 0
run_case corrupt_snapshot 4 1 1 0

run_case real_write_once real 0 1 1 write_once_only
run_case real_ordinary_known_key real 1 1 0 ordinary_known
run_case real_mixed_failure real 1 1 0 mixed
run_case real_already_target real 0 0 0 already_target
run_case real_proc_missing real 1 1 0 proc_missing

printf 'RC_EXTRACT=%s\n' "$RC_EXTRACT"
printf 'RC_FUNCTION_SYNTAX=%s\n' "$RC_FUNCTION_SYNTAX"
printf 'FAILURE_COUNT=%s\n' "$FAILURES"

if (( FAILURES == 0 )); then
    printf 'RESULT=WRITE_ONCE_SYSCTL_RESTORE_REGRESSION_OK\n'
    exit 0
fi

printf 'FAIL=WRITE_ONCE_SYSCTL_RESTORE_REGRESSION\n'
exit 1
