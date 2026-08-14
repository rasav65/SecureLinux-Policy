#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-manifest-bootstrap-regression"
HARNESS="$TMP_ROOT/harness.sh"

main() {
    rm -rf -- "$TMP_ROOT"
    mkdir -p -- "$TMP_ROOT"

    python3 - "$SOURCE" <<'PY_STATIC'
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

        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(source)
        )
        return source[match.start():end]

    errors.append(f"FUNCTION_NOT_FOUND:{name}")
    return ""


run_apply = function_text("run_apply_mode")

guard = re.search(
    r'if\s+!\s+manifest_init;\s*then\s*\n'
    r'[ \t]*add_error\s+"apply: инициализация manifest завершилась ошибкой: \$MANIFEST_FILE"\s*\n'
    r'[ \t]*return\s+1\s*\n'
    r'[ \t]*fi',
    run_apply,
)

if guard is None:
    errors.append("MANIFEST_INIT_FAIL_FAST_GUARD_MISSING")

first_apply = run_apply.find("apply_empty_passwords_module")

if first_apply < 0:
    errors.append("FIRST_APPLY_MODULE_NOT_FOUND")
elif guard is not None and guard.start() > first_apply:
    errors.append("MANIFEST_INIT_GUARD_AFTER_FIRST_MUTATION")

if errors:
    for error in errors:
        print(error)
    raise SystemExit(1)

print("RESULT=MANIFEST_BOOTSTRAP_STATIC_REGRESSION_OK")
PY_STATIC
    RC_STATIC=$?

    python3 - "$SOURCE" "$HARNESS" <<'PY_HARNESS'
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

run_apply = None
for index, match in enumerate(matches):
    if match.group(1) != "run_apply_mode":
        continue
    end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
    run_apply = source[match.start():end]
    break

if run_apply is None:
    raise SystemExit("run_apply_mode not found")

start = source.index("run_apply_mode() {")
end = source.index("\nrun_restore_mode() {", start)
block = source[start:end]
modules = sorted(set(re.findall(r"(?m)^[ \t]+(apply_[A-Za-z0-9_]+)[ \t]*$", block)))

lines = [
    "#!/usr/bin/env bash",
    run_apply.rstrip(),
    'DRY_RUN=0',
    'LOG_FILE="/dev/null"',
    'SCRIPT_VERSION="test"',
    'PROFILE="baseline"',
    'DISTRO_ID="test"',
    'DISTRO_VERSION_ID="test"',
    'MANIFEST_FILE="$1/manifest.json"',
    'TIMESTAMP="20260804-000000"',
    'ERRORS=()',
    'MANIFEST_INIT_CALL_COUNT=0',
    'POST_BOOTSTRAP_CALL_COUNT=0',
    'log() { :; }',
    'log_debug() { :; }',
    'run_preflight() { :; }',
    'check_memory_requirements() { :; }',
    'ensure_state_dir() { :; }',
    'acquire_run_lock() { :; }',
    'add_error() { ERRORS+=("$1"); }',
    'add_skipped() { POST_BOOTSTRAP_CALL_COUNT=$((POST_BOOTSTRAP_CALL_COUNT + 1)); }',
    'additional_measures_enabled() { POST_BOOTSTRAP_CALL_COUNT=$((POST_BOOTSTRAP_CALL_COUNT + 1)); return 1; }',
    'manifest_init() { MANIFEST_INIT_CALL_COUNT=$((MANIFEST_INIT_CALL_COUNT + 1)); return 1; }',
    'write_report() { POST_BOOTSTRAP_CALL_COUNT=$((POST_BOOTSTRAP_CALL_COUNT + 1)); }',
    'print_report_stdout() { POST_BOOTSTRAP_CALL_COUNT=$((POST_BOOTSTRAP_CALL_COUNT + 1)); }',
]

for module in modules:
    lines.append(f'{module}() {{ POST_BOOTSTRAP_CALL_COUNT=$((POST_BOOTSTRAP_CALL_COUNT + 1)); return 0; }}')

lines.extend([
    'run_apply_mode',
    'RC_APPLY=$?',
    'printf "%s\\n" "MANIFEST_INIT_CALL_COUNT=$MANIFEST_INIT_CALL_COUNT" "POST_BOOTSTRAP_CALL_COUNT=$POST_BOOTSTRAP_CALL_COUNT" "ERROR_COUNT=${#ERRORS[@]}" "RUN_APPLY_RC=$RC_APPLY"',
    'if (( MANIFEST_INIT_CALL_COUNT == 1 )) && (( POST_BOOTSTRAP_CALL_COUNT == 0 )) && (( ${#ERRORS[@]} == 1 )) && [[ "${ERRORS[0]}" == "apply: инициализация manifest завершилась ошибкой: $MANIFEST_FILE" ]] && (( RC_APPLY == 1 )); then',
    '    echo "RESULT=MANIFEST_BOOTSTRAP_FAILURE_OK"',
    'else',
    '    echo "RESULT=MANIFEST_BOOTSTRAP_FAILURE_FAILED"',
    '    false',
    'fi',
])

harness_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
harness_path.chmod(0o700)
PY_HARNESS
    RC_HARNESS_BUILD=$?

    RC_DYNAMIC=1
    if (( RC_STATIC == 0 && RC_HARNESS_BUILD == 0 )); then
        command bash "$HARNESS" "$TMP_ROOT"
        RC_DYNAMIC=$?
    fi

    printf '%s\n' \
        "RC_STATIC=$RC_STATIC" \
        "RC_HARNESS_BUILD=$RC_HARNESS_BUILD" \
        "RC_DYNAMIC=$RC_DYNAMIC"

    rm -rf -- "$TMP_ROOT"

    if (( RC_STATIC == 0 && RC_HARNESS_BUILD == 0 && RC_DYNAMIC == 0 )); then
        echo "RESULT=MANIFEST_BOOTSTRAP_REGRESSION_OK"
        return 0
    fi

    echo "RESULT=MANIFEST_BOOTSTRAP_REGRESSION_FAILED"
    return 1
}

main "$@"
