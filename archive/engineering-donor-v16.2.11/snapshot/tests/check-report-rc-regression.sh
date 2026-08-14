#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-check-report-rc-regression"
HARNESS="$TMP_ROOT/harness.sh"

main() {
    rm -rf -- "$TMP_ROOT"
    mkdir -p -- "$TMP_ROOT"

    python3 - "$SOURCE" "$HARNESS" <<'PY_STATIC'
import re
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
harness_path = Path(sys.argv[2])
source = source_path.read_text(encoding="utf-8")
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

    raise RuntimeError(f"FUNCTION_NOT_FOUND:{name}")


run_mode_step = function_text("run_mode_step")
run_preflight = function_text("run_preflight")
run_check = function_text("run_check_mode")
run_report = function_text("run_report_mode")

check_steps = [
    "run_preflight",
    "ensure_state_dir",
    "write_check_report_txt",
    "write_report",
    "print_report_stdout",
]

report_steps = [
    "run_preflight",
    "ensure_state_dir",
    "write_report",
    "print_report_stdout",
]

if "return 0" not in run_preflight:
    errors.append("PREFLIGHT_SUCCESS_RETURN_MISSING")

if "local overall_rc=0" not in run_check:
    errors.append("CHECK_OVERALL_RC_MISSING")

if "local overall_rc=0" not in run_report:
    errors.append("REPORT_OVERALL_RC_MISSING")

for step in check_steps:
    expected = f"run_mode_step check {step} {step} || overall_rc=1"
    if run_check.count(expected) != 1:
        errors.append(f"CHECK_STEP_GUARD_INVALID:{step}")

for step in report_steps:
    expected = f"run_mode_step report {step} {step} || overall_rc=1"
    if run_report.count(expected) != 1:
        errors.append(f"REPORT_STEP_GUARD_INVALID:{step}")

if "${#ERRORS[@]} > 0 || overall_rc != 0" not in run_check:
    errors.append("CHECK_FINAL_RC_INVALID")

if "${#ERRORS[@]} > 0 || overall_rc != 0" not in run_report:
    errors.append("REPORT_FINAL_RC_INVALID")

if "run_mode_step check check_ssh_root_login_module" in run_check:
    errors.append("CHECK_POLICY_RESULT_MUST_NOT_BE_AGGREGATED_AS_FAILURE")

if errors:
    for error in errors:
        print(error)
    raise RuntimeError("check/report static regression failed")

print("RESULT=CHECK_REPORT_RC_STATIC_REGRESSION_OK")

function_calls = set(check_steps + report_steps)

for block in (run_check, run_report):
    function_calls.update(
        re.findall(r"\$\(([A-Za-z_][A-Za-z0-9_]*)", block)
    )
    function_calls.update(
        re.findall(
            r"(?m)^\s+((?:check|record|add)_[A-Za-z0-9_]+)(?:\s|$)",
            block,
        )
    )

function_calls.update({"log", "additional_measures_enabled"})
function_calls.difference_update(
    {"run_mode_step", "run_check_mode", "run_report_mode"}
)

quoted_functions = " ".join(sorted(function_calls))

harness = f'''#!/usr/bin/env bash

{run_mode_step}
{run_check}
{run_report}

DEPENDENCIES=({quoted_functions})

reset_environment() {{
    ERRORS=()
    CALLS=()
    PROFILE="test"

    local function_name
    for function_name in "${{DEPENDENCIES[@]}}"; do
        eval "$function_name() {{ return 0; }}"
    done

    log() {{ :; }}
    add_error() {{ ERRORS+=("$1"); }}
    add_warning() {{ :; }}
    add_skipped() {{ :; }}
    add_risky() {{ :; }}
    additional_measures_enabled() {{ return 1; }}
}}

case_check_policy_result_nonfatal() {{
    reset_environment

    check_ssh_root_login_module() {{
        CALLS+=("policy_noncompliant")
        return 1
    }}

    check_pam_wheel_module() {{
        CALLS+=("check_after_policy_result")
        return 0
    }}

    run_check_mode
    local rc=$?

    printf '%s\\n' \\
        "CHECK_POLICY_RC=$rc" \\
        "CHECK_POLICY_ERRORS=${{#ERRORS[@]}}" \\
        "CHECK_POLICY_CALLS=${{CALLS[*]}}"

    if (( rc == 0 )) &&
       (( ${{#ERRORS[@]}} == 0 )) &&
       [[ " ${{CALLS[*]}} " == *" check_after_policy_result "* ]]; then
        echo "RESULT=CHECK_POLICY_RESULT_NONFATAL_OK"
        return 0
    fi

    return 1
}}

case_check_preflight_failure() {{
    reset_environment

    run_preflight() {{
        CALLS+=("check_preflight_failure")
        return 1
    }}

    check_ssh_root_login_module() {{
        CALLS+=("check_after_preflight_failure")
        return 0
    }}

    run_check_mode
    local rc=$?

    printf '%s\\n' \\
        "CHECK_PREFLIGHT_RC=$rc" \\
        "CHECK_PREFLIGHT_ERRORS=${{#ERRORS[@]}}" \\
        "CHECK_PREFLIGHT_CALLS=${{CALLS[*]}}"

    if (( rc == 1 )) &&
       (( ${{#ERRORS[@]}} == 1 )) &&
       [[ " ${{CALLS[*]}} " == *" check_after_preflight_failure "* ]]; then
        echo "RESULT=CHECK_PREFLIGHT_RC_AGGREGATION_OK"
        return 0
    fi

    return 1
}}

case_check_report_failure() {{
    reset_environment

    write_check_report_txt() {{
        CALLS+=("check_report_failure")
        return 1
    }}

    write_report() {{
        CALLS+=("check_report_after_failure")
        return 0
    }}

    run_check_mode
    local rc=$?

    printf '%s\\n' \\
        "CHECK_REPORT_FAILURE_RC=$rc" \\
        "CHECK_REPORT_FAILURE_ERRORS=${{#ERRORS[@]}}" \\
        "CHECK_REPORT_FAILURE_CALLS=${{CALLS[*]}}"

    if (( rc == 1 )) &&
       (( ${{#ERRORS[@]}} == 1 )) &&
       [[ " ${{CALLS[*]}} " == *" check_report_after_failure "* ]]; then
        echo "RESULT=CHECK_REPORT_RC_AGGREGATION_OK"
        return 0
    fi

    return 1
}}

case_report_failure() {{
    reset_environment

    run_preflight() {{
        CALLS+=("report_preflight_failure")
        return 1
    }}

    write_report() {{
        CALLS+=("report_after_failure")
        return 0
    }}

    run_report_mode
    local rc=$?

    printf '%s\\n' \\
        "REPORT_FAILURE_RC=$rc" \\
        "REPORT_FAILURE_ERRORS=${{#ERRORS[@]}}" \\
        "REPORT_FAILURE_CALLS=${{CALLS[*]}}"

    if (( rc == 1 )) &&
       (( ${{#ERRORS[@]}} == 1 )) &&
       [[ " ${{CALLS[*]}} " == *" report_after_failure "* ]]; then
        echo "RESULT=REPORT_MODE_RC_AGGREGATION_OK"
        return 0
    fi

    return 1
}}

case_no_duplicate_error() {{
    reset_environment

    write_report() {{
        add_error "report-specific-error"
        return 1
    }}

    run_report_mode
    local rc=$?

    printf '%s\\n' \\
        "REPORT_NO_DUPLICATE_RC=$rc" \\
        "REPORT_NO_DUPLICATE_ERRORS=${{#ERRORS[@]}}"

    if (( rc == 1 )) &&
       (( ${{#ERRORS[@]}} == 1 )) &&
       [[ "${{ERRORS[0]}}" == "report-specific-error" ]]; then
        echo "RESULT=REPORT_ERROR_NOT_DUPLICATED_OK"
        return 0
    fi

    return 1
}}

case_all_success() {{
    reset_environment
    run_check_mode
    local check_rc=$?

    reset_environment
    run_report_mode
    local report_rc=$?

    printf '%s\\n' \\
        "ALL_SUCCESS_CHECK_RC=$check_rc" \\
        "ALL_SUCCESS_REPORT_RC=$report_rc"

    if (( check_rc == 0 && report_rc == 0 )); then
        echo "RESULT=CHECK_REPORT_ALL_SUCCESS_OK"
        return 0
    fi

    return 1
}}

main() {{
    local overall_rc=0

    case_check_policy_result_nonfatal || overall_rc=1
    case_check_preflight_failure || overall_rc=1
    case_check_report_failure || overall_rc=1
    case_report_failure || overall_rc=1
    case_no_duplicate_error || overall_rc=1
    case_all_success || overall_rc=1

    if (( overall_rc == 0 )); then
        echo "RESULT=CHECK_REPORT_RC_DYNAMIC_REGRESSION_OK"
    else
        echo "RESULT=CHECK_REPORT_RC_DYNAMIC_REGRESSION_FAILED"
    fi

    return "$overall_rc"
}}

main "$@"
'''

harness_path.write_text(harness, encoding="utf-8")
harness_path.chmod(0o755)
PY_STATIC
    RC_STATIC=$?

    bash "$HARNESS"
    RC_DYNAMIC=$?

    rm -rf -- "$TMP_ROOT"

    printf '%s\n' \
        "RC_STATIC=$RC_STATIC" \
        "RC_DYNAMIC=$RC_DYNAMIC"

    if (( RC_STATIC == 0 && RC_DYNAMIC == 0 )); then
        echo "RESULT=CHECK_REPORT_RC_REGRESSION_OK"
        return 0
    fi

    echo "RESULT=CHECK_REPORT_RC_REGRESSION_FAILED"
    return 1
}

main "$@"

check_internal_module_failure_rc_regression() {
    local internal_harness="$TMP_ROOT/check-internal-module-failure-harness.sh"

    rm -rf -- "$TMP_ROOT"
    mkdir -p -- "$TMP_ROOT" || return 1

    python3 - "$SOURCE" "$internal_harness" <<'PY_INTERNAL_FAILURE'
import re
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
harness_path = Path(sys.argv[2])
source = source_path.read_text(encoding="utf-8")
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
        return source[match.start():end].rstrip()

    raise RuntimeError(f"FUNCTION_NOT_FOUND:{name}")


systemd_check = function_text(
    "check_systemd_unit_targets_module"
)
wheel_check = function_text(
    "check_pam_wheel_module"
)
run_check = function_text("run_check_mode")

systemd_error = (
    'add_error "systemd unit targets: '
    'не удалось получить список объектов"'
)
wheel_error = (
    'add_error "2.2.1 не удалось разобрать WHEEL_USERS"'
)

if systemd_error not in systemd_check:
    errors.append("SYSTEMD_INTERNAL_FAILURE_NOT_ERROR")

if (
    'add_risky "systemd unit targets: '
    'не удалось получить список объектов"'
    in systemd_check
):
    errors.append("SYSTEMD_INTERNAL_FAILURE_STILL_RISKY")

if wheel_error not in wheel_check:
    errors.append("WHEEL_INTERNAL_FAILURE_NOT_ERROR")

if (
    'add_risky "2.2.1 не удалось разобрать WHEEL_USERS"'
    in wheel_check
):
    errors.append("WHEEL_INTERNAL_FAILURE_STILL_RISKY")

if (
    '${#ERRORS[@]} > 0 || overall_rc != 0'
    not in run_check
):
    errors.append("CHECK_FINAL_ERROR_RC_CONTRACT_MISSING")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

harness = f"""#!/usr/bin/env bash

{systemd_check}

{wheel_check}

ERRORS=()
RISKY=()
SAFE=()

add_error() {{
    ERRORS+=("$1")
}}

add_risky() {{
    RISKY+=("$1")
}}

add_safe() {{
    SAFE+=("$1")
}}

systemd_unit_candidates() {{
    return 73
}}

check_systemd_unit_one() {{
    return 0
}}

pam_wheel_group_exists() {{
    return 0
}}

pam_wheel_rule_present() {{
    return 0
}}

pam_wheel_has_members() {{
    return 0
}}

pam_wheel_configured_users_present() {{
    return 1
}}

pam_wheel_user_is_member() {{
    return 0
}}

configured_wheel_users() {{
    return 74
}}

case_systemd_internal_failure() {{
    ERRORS=()
    RISKY=()
    SAFE=()

    check_systemd_unit_targets_module
    local rc=$?

    printf '%s\n' \
        "SYSTEMD_INTERNAL_RC=$rc" \
        "SYSTEMD_INTERNAL_ERRORS=${{#ERRORS[@]}}" \
        "SYSTEMD_INTERNAL_RISKY=${{#RISKY[@]}}"

    if (( rc == 1 )) &&
       (( ${{#ERRORS[@]}} == 1 )) &&
       (( ${{#RISKY[@]}} == 0 )) &&
       [[ "${{ERRORS[0]}}" == \
          "systemd unit targets: не удалось получить список объектов" ]]
    then
        echo "RESULT=CHECK_SYSTEMD_INTERNAL_FAILURE_RC_OK"
        return 0
    fi

    return 1
}}

case_wheel_internal_failure() {{
    ERRORS=()
    RISKY=()
    SAFE=()

    check_pam_wheel_module
    local rc=$?

    printf '%s\n' \
        "WHEEL_INTERNAL_RC=$rc" \
        "WHEEL_INTERNAL_ERRORS=${{#ERRORS[@]}}"

    if (( rc == 1 )) &&
       (( ${{#ERRORS[@]}} == 1 )) &&
       [[ "${{ERRORS[0]}}" == \
          "2.2.1 не удалось разобрать WHEEL_USERS" ]]
    then
        echo "RESULT=CHECK_WHEEL_INTERNAL_FAILURE_RC_OK"
        return 0
    fi

    return 1
}}

main() {{
    local rc_systemd=0
    local rc_wheel=0

    case_systemd_internal_failure || rc_systemd=$?
    case_wheel_internal_failure || rc_wheel=$?

    printf '%s\n' \
        "RC_SYSTEMD_INTERNAL=$rc_systemd" \
        "RC_WHEEL_INTERNAL=$rc_wheel"

    if (( rc_systemd == 0 && rc_wheel == 0 )); then
        echo "RESULT=CHECK_INTERNAL_MODULE_FAILURE_RC_DYNAMIC_OK"
        return 0
    fi

    return 1
}}

main "$@"
"""

harness_path.write_text(harness, encoding="utf-8")
harness_path.chmod(0o755)

print("RESULT=CHECK_INTERNAL_MODULE_FAILURE_RC_STATIC_OK")
PY_INTERNAL_FAILURE
    local rc_static=$?

    local rc_dynamic=99
    if (( rc_static == 0 )); then
        bash "$internal_harness"
        rc_dynamic=$?
    fi

    rm -rf -- "$TMP_ROOT"

    printf '%s\n' \
        "RC_INTERNAL_STATIC=$rc_static" \
        "RC_INTERNAL_DYNAMIC=$rc_dynamic"

    if (( rc_static == 0 && rc_dynamic == 0 )); then
        echo "RESULT=CHECK_INTERNAL_MODULE_FAILURE_RC_REGRESSION_OK"
        return 0
    fi

    return 1
}

check_internal_module_failure_rc_regression || exit 1
