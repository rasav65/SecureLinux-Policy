#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-top-level-rc-regression"
HARNESS="$TMP_ROOT/harness.sh"

main() {
    rm -rf -- "$TMP_ROOT"
    mkdir -p -- "$TMP_ROOT"

    python3 - "$SOURCE" "$ROOT/tests/smoke.sh" <<'PYTEST'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
smoke = Path(sys.argv[2]).read_text(encoding="utf-8")
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


helper = function_text("run_mode_step")
apply_mode = function_text("run_apply_mode")
restore_mode = function_text("run_restore_mode")

if 'local errors_before=${#ERRORS[@]}' not in helper:
    errors.append("RUN_MODE_STEP_ERROR_SNAPSHOT_MISSING")
if 'add_error "$mode_name: сбой шага $step_name (RC=$step_rc)"' not in helper:
    errors.append("RUN_MODE_STEP_GENERIC_ERROR_MISSING")
if 'return "$step_rc"' not in helper:
    errors.append("RUN_MODE_STEP_RC_PROPAGATION_MISSING")

for mode_name, block, prefix in (
    ("apply", apply_mode, "apply_"),
    ("restore", restore_mode, "restore_"),
):
    if "local overall_rc=0" not in block:
        errors.append(f"{mode_name.upper()}_OVERALL_RC_MISSING")

    wrapped_modules = re.findall(
        rf"(?m)^\s+run_mode_step {mode_name} ({prefix}[A-Za-z0-9_]+) \1 \|\| overall_rc=1$",
        block,
    )
    if len(wrapped_modules) != 38:
        errors.append(
            f"{mode_name.upper()}_WRAPPED_MODULE_COUNT:{len(wrapped_modules)}"
        )

    for report_step in ("write_report", "print_report_stdout"):
        expected = (
            f"run_mode_step {mode_name} {report_step} "
            f"{report_step} || overall_rc=1"
        )
        if expected not in block:
            errors.append(
                f"{mode_name.upper()}_{report_step.upper()}_WRAPPER_MISSING"
            )

    if "${#ERRORS[@]} > 0 || overall_rc != 0" not in block:
        errors.append(f"{mode_name.upper()}_FINAL_RC_CONDITION_MISSING")

    bare = re.findall(rf"(?m)^\s+({prefix}[A-Za-z0-9_]+)\s*$", block)
    if bare:
        errors.append(f"{mode_name.upper()}_BARE_MODULES:{','.join(bare)}")

if smoke.count("bash tests/top-level-rc-regression.sh &&") != 1:
    errors.append("SMOKE_REGISTRATION_INVALID")

if errors:
    for error in errors:
        print(error)
    raise RuntimeError("top-level RC static regression failed")

print("RESULT=TOP_LEVEL_RC_STATIC_REGRESSION_OK")
PYTEST
    RC_STATIC=$?

    python3 - "$SOURCE" "$HARNESS" "$TMP_ROOT" <<'PYBUILD'
import re
import shlex
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
harness_path = Path(sys.argv[2])
tmp_root = Path(sys.argv[3])
source = source_path.read_text(encoding="utf-8")


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
    raise RuntimeError(f"function not found: {name}")


helper = function_text("run_mode_step")
apply_mode = function_text("run_apply_mode")
restore_mode = function_text("run_restore_mode")
apply_modules = re.findall(
    r"(?m)^\s+run_mode_step apply (apply_[A-Za-z0-9_]+) \1 \|\| overall_rc=1$",
    apply_mode,
)
restore_modules = re.findall(
    r"(?m)^\s+run_mode_step restore (restore_[A-Za-z0-9_]+) \1 \|\| overall_rc=1$",
    restore_mode,
)

lines = [
    "#!/usr/bin/env bash",
    "",
    helper.rstrip(),
    "",
    apply_mode.rstrip(),
    "",
    restore_mode.rstrip(),
    "",
    f"TMP_ROOT={shlex.quote(str(tmp_root))}",
    'DRY_RUN=0',
    'LOG_FILE="/dev/null"',
    'DEBUG_LOG_FILE="/dev/null"',
    'SCRIPT_VERSION="test"',
    'PROFILE="baseline"',
    'DISTRO_ID="test"',
    'DISTRO_VERSION_ID="test"',
    'OS_FAMILY="debian"',
    'MODE="apply"',
    'MANIFEST_FILE="$TMP_ROOT/manifest.json"',
    'RESTORE_SOURCE_MANIFEST="$TMP_ROOT/missing-manifest.json"',
    'RESTORE_MANIFEST=""',
    'TIMESTAMP="20260804-000000"',
    'ERRORS=()',
    'CALLS=()',
    'FAIL_STEP=""',
    'FAIL_RC=1',
    'FAIL_ADD_ERROR=0',
    "",
    'log() { :; }',
    'log_debug() { :; }',
    'run_preflight() { return 0; }',
    'check_memory_requirements() { return 0; }',
    'ensure_state_dir() { return 0; }',
    'acquire_run_lock() { return 0; }',
    'resolve_restore_manifest() { RESTORE_SOURCE_MANIFEST="$TMP_ROOT/missing-manifest.json"; return 0; }',
    'manifest_init() { return 0; }',
    'additional_measures_enabled() { return 0; }',
    'add_skipped() { return 0; }',
    'add_error() { ERRORS+=("$1"); }',
    "",
    'record_call() {',
    '    local step="$1"',
    '    CALLS+=("$step")',
    '    if [[ "$FAIL_STEP" == "$step" ]]; then',
    '        if (( FAIL_ADD_ERROR == 1 )); then',
    '            add_error "module-specific:$step"',
    '        fi',
    '        return "$FAIL_RC"',
    '    fi',
    '    return 0',
    '}',
    "",
]

for name in apply_modules + restore_modules + ["write_report", "print_report_stdout"]:
    lines.append(f'{name}() {{ record_call {shlex.quote(name)}; }}')

lines.extend(
    [
        "",
        'contains_call() {',
        '    local wanted="$1"',
        '    local item',
        '    for item in "${CALLS[@]}"; do',
        '        [[ "$item" == "$wanted" ]] && return 0',
        '    done',
        '    return 1',
        '}',
        "",
        'reset_case() {',
        '    ERRORS=()',
        '    CALLS=()',
        '    FAIL_STEP=""',
        '    FAIL_RC=1',
        '    FAIL_ADD_ERROR=0',
        '    rm -f -- "$MANIFEST_FILE" "$RESTORE_SOURCE_MANIFEST"',
        '}',
        "",
        'case_apply_module_failure() {',
        '    reset_case',
        '    MODE="apply"',
        '    FAIL_STEP="apply_ufw_module"',
        '    FAIL_RC=7',
        '    run_apply_mode',
        '    local rc=$?',
        '    printf "%s\\n" "APPLY_FAILURE_RC=$rc" "APPLY_FAILURE_ERRORS=${#ERRORS[@]}"',
        '    (( rc == 1 )) || return 1',
        '    (( ${#ERRORS[@]} == 1 )) || return 1',
        '    [[ "${ERRORS[0]}" == "apply: сбой шага apply_ufw_module (RC=7)" ]] || return 1',
        '    contains_call apply_ufw_module || return 1',
        '    contains_call apply_modules_disabled_module || return 1',
        '    contains_call write_report || return 1',
        '    contains_call print_report_stdout || return 1',
        '    echo "RESULT=APPLY_MODULE_RC_AGGREGATION_OK"',
        '    return 0',
        '}',
        "",
        'case_restore_module_failure() {',
        '    reset_case',
        '    MODE="restore"',
        '    FAIL_STEP="restore_grub_kernel_params_module"',
        '    FAIL_RC=9',
        '    run_restore_mode',
        '    local rc=$?',
        '    printf "%s\\n" "RESTORE_FAILURE_RC=$rc" "RESTORE_FAILURE_ERRORS=${#ERRORS[@]}"',
        '    (( rc == 1 )) || return 1',
        '    (( ${#ERRORS[@]} == 1 )) || return 1',
        '    [[ "${ERRORS[0]}" == "restore: сбой шага restore_grub_kernel_params_module (RC=9)" ]] || return 1',
        '    contains_call restore_grub_kernel_params_module || return 1',
        '    contains_call restore_fs_critical_files_module || return 1',
        '    contains_call restore_systemd_unit_targets_module || return 1',
        '    contains_call write_report || return 1',
        '    contains_call print_report_stdout || return 1',
        '    echo "RESULT=RESTORE_MODULE_RC_AGGREGATION_OK"',
        '    return 0',
        '}',
        "",
        'case_no_duplicate_error() {',
        '    reset_case',
        '    MODE="restore"',
        '    FAIL_STEP="restore_ufw_module"',
        '    FAIL_RC=5',
        '    FAIL_ADD_ERROR=1',
        '    run_restore_mode',
        '    local rc=$?',
        '    printf "%s\\n" "NO_DUPLICATE_RC=$rc" "NO_DUPLICATE_ERRORS=${#ERRORS[@]}"',
        '    (( rc == 1 )) || return 1',
        '    (( ${#ERRORS[@]} == 1 )) || return 1',
        '    [[ "${ERRORS[0]}" == "module-specific:restore_ufw_module" ]] || return 1',
        '    echo "RESULT=MODULE_ERROR_NOT_DUPLICATED_OK"',
        '    return 0',
        '}',
        "",
        'case_report_failure() {',
        '    reset_case',
        '    MODE="apply"',
        '    FAIL_STEP="write_report"',
        '    FAIL_RC=6',
        '    run_apply_mode',
        '    local rc=$?',
        '    printf "%s\\n" "REPORT_FAILURE_RC=$rc" "REPORT_FAILURE_ERRORS=${#ERRORS[@]}"',
        '    (( rc == 1 )) || return 1',
        '    (( ${#ERRORS[@]} == 1 )) || return 1',
        '    [[ "${ERRORS[0]}" == "apply: сбой шага write_report (RC=6)" ]] || return 1',
        '    contains_call print_report_stdout || return 1',
        '    echo "RESULT=REPORT_WRITER_RC_AGGREGATION_OK"',
        '    return 0',
        '}',
        "",
        'case_all_success() {',
        '    reset_case',
        '    MODE="apply"',
        '    run_apply_mode',
        '    local apply_rc=$?',
        '    reset_case',
        '    MODE="restore"',
        '    run_restore_mode',
        '    local restore_rc=$?',
        '    printf "%s\\n" "ALL_SUCCESS_APPLY_RC=$apply_rc" "ALL_SUCCESS_RESTORE_RC=$restore_rc"',
        '    (( apply_rc == 0 && restore_rc == 0 )) || return 1',
        '    (( ${#ERRORS[@]} == 0 )) || return 1',
        '    echo "RESULT=TOP_LEVEL_ALL_SUCCESS_OK"',
        '    return 0',
        '}',
        "",
        'main() {',
        '    local rc=0',
        '    case_apply_module_failure || rc=1',
        '    case_restore_module_failure || rc=1',
        '    case_no_duplicate_error || rc=1',
        '    case_report_failure || rc=1',
        '    case_all_success || rc=1',
        '    if (( rc == 0 )); then',
        '        echo "RESULT=TOP_LEVEL_RC_DYNAMIC_REGRESSION_OK"',
        '    else',
        '        echo "RESULT=TOP_LEVEL_RC_DYNAMIC_REGRESSION_FAILED"',
        '    fi',
        '    return "$rc"',
        '}',
        "",
        'main "$@"',
    ]
)

harness_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
harness_path.chmod(0o755)
PYBUILD
    RC_BUILD=$?

    RC_DYNAMIC=99
    if (( RC_BUILD == 0 )); then
        bash "$HARNESS"
        RC_DYNAMIC=$?
    fi

    printf '%s\n' \
        "RC_STATIC=$RC_STATIC" \
        "RC_BUILD=$RC_BUILD" \
        "RC_DYNAMIC=$RC_DYNAMIC"

    rm -rf -- "$TMP_ROOT"

    if (( RC_STATIC == 0 && RC_BUILD == 0 && RC_DYNAMIC == 0 )); then
        echo "RESULT=TOP_LEVEL_RC_REGRESSION_OK"
        return 0
    fi

    echo "RESULT=TOP_LEVEL_RC_REGRESSION_FAILED"
    return 1
}

main "$@"
