#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-service-state-crash-regression"
HARNESS="$TMP_ROOT/harness.sh"

main() {
    rm -rf -- "$TMP_ROOT"
    mkdir -p -- "$TMP_ROOT"

    python3 - "$SOURCE" "$HARNESS" <<'PYBUILD'
import re
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
harness_path = Path(sys.argv[2])
source = source_path.read_text(encoding="utf-8")

required = [
    "read_systemd_unit_enabled_state",
    "read_systemd_unit_active_state",
    "record_manifest_pending_service_transaction",
    "commit_manifest_service_transaction",
    "restore_manifest_service_transaction",
    "prepare_systemd_service_transaction",
    "commit_systemd_service_transaction",
    "restore_systemd_unit_exact_state",
    "restore_systemd_service_transaction",
]

matches = list(re.finditer(
    r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
    source,
))
functions = {}
for index, match in enumerate(matches):
    name = match.group(1)
    if name not in required:
        continue
    end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
    functions[name] = source[match.start():end].rstrip() + "\n"
missing = [name for name in required if name not in functions]
if missing:
    raise RuntimeError("FUNCTION_NOT_FOUND:" + ",".join(missing))

for field in (
    '"pending_service_transactions": []',
    '"service_transactions": []',
):
    if field not in source:
        raise RuntimeError("MANIFEST_FIELD_MISSING:" + field)

coverage = {
    "apply_sysctl_network_module": (
        "prepare_systemd_service_transaction",
        "commit_systemd_service_transaction",
    ),
    "apply_apparmor_module": (
        "prepare_systemd_service_transaction",
        "commit_systemd_service_transaction",
    ),
    "apply_rsyslog_module": (
        "prepare_systemd_service_transaction",
        "commit_systemd_service_transaction",
    ),
    "apply_chrony_module": (
        "prepare_systemd_service_transaction",
        "commit_systemd_service_transaction",
    ),
    "apply_unattended_upgrades_module": (
        "prepare_systemd_service_transaction",
        "commit_systemd_service_transaction",
    ),
    "apply_apport_module": (
        "prepare_systemd_service_transaction",
        "commit_systemd_service_transaction",
    ),
    "restore_sysctl_network_module": (
        "restore_systemd_service_transaction",
    ),
    "restore_apparmor_module": (
        "restore_systemd_service_transaction",
    ),
    "restore_rsyslog_module": (
        "restore_systemd_service_transaction",
    ),
    "restore_chrony_module": (
        "restore_systemd_service_transaction",
    ),
    "restore_unattended_upgrades_module": (
        "restore_systemd_service_transaction",
    ),
    "restore_apport_module": (
        "restore_systemd_service_transaction",
    ),
}

for name, markers in coverage.items():
    match = re.search(rf"(?ms)^{name}\(\) \{{.*?^\}}\n", source)
    if match is None:
        raise RuntimeError("FUNCTION_NOT_FOUND:" + name)
    body = match.group(0)
    for marker in markers:
        if marker not in body:
            raise RuntimeError(f"SERVICE_TRANSACTION_MISSING:{name}:{marker}")

if '^[A-Za-z0-9_.@:-]+[.]service$' not in source:
    raise RuntimeError("PORTABLE_UNIT_REGEX_MISSING")

print("RESULT=SERVICE_STATE_CRASH_STATIC_REGRESSION_OK")

function_source = "\n".join(functions[name] for name in required)
harness = f'''#!/usr/bin/env bash

{function_source}

ERRORS=()
WARNINGS=()
CALLS=()
DRY_RUN=0
STATE_DIR="{harness_path.parent}/state"
MANIFEST_FILE="$STATE_DIR/manifest.json"
RESTORE_SOURCE_MANIFEST="$MANIFEST_FILE"
DEBUG_LOG_FILE="{harness_path.parent}/debug.log"
ENABLED_STATE="disabled"
ACTIVE_STATE="inactive"
PENDING_WRITER_RC=0

add_error() {{ ERRORS+=("$1"); }}
add_warning() {{ WARNINGS+=("$1"); }}
log() {{ :; }}

systemctl() {{
    local command="$1"
    shift
    case "$command" in
        is-enabled)
            printf '%s\n' "$ENABLED_STATE"
            [[ "$ENABLED_STATE" == "enabled" ]] && return 0
            return 1
            ;;
        is-active)
            if [[ "${{1:-}}" == "--quiet" ]]; then
                shift
                [[ "$ACTIVE_STATE" == "active" ]]
                return
            fi
            printf '%s\n' "$ACTIVE_STATE"
            [[ "$ACTIVE_STATE" == "active" ]] && return 0
            return 3
            ;;
        enable|disable|start|stop|mask|unmask)
            CALLS+=("$command:$*")
            case "$command" in
                start) ACTIVE_STATE="active" ;;
                stop) ACTIVE_STATE="inactive" ;;
                enable) ENABLED_STATE="enabled" ;;
                disable) ENABLED_STATE="disabled" ;;
                mask) ENABLED_STATE="masked" ;;
                unmask) [[ "$ENABLED_STATE" == masked* ]] && ENABLED_STATE="disabled" ;;
            esac
            return 0
            ;;
    esac
    return 0
}}

real_pending_writer="$(declare -f record_manifest_pending_service_transaction)"

reset_case() {{
    rm -rf -- "$STATE_DIR"
    mkdir -p -- "$STATE_DIR"
    printf '%s\n' '{{
  "pending_service_transactions": [],
  "service_transactions": []
}}' > "$MANIFEST_FILE"
    ERRORS=()
    WARNINGS=()
    CALLS=()
    ENABLED_STATE="disabled"
    ACTIVE_STATE="inactive"
    eval "$real_pending_writer"
}}

case_commit() {{
    reset_case
    record_manifest_pending_service_transaction \\
        demo example.service enable-now disabled inactive
    RC_PENDING=$?
    commit_manifest_service_transaction demo example.service
    RC_COMMIT=$?
    python3 - "$MANIFEST_FILE" <<'PYVALID'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if data.get("pending_service_transactions") != []:
    raise RuntimeError("PENDING_NOT_CLEARED")
expected = [{{
    "module": "demo",
    "unit": "example.service",
    "operation": "enable-now",
    "enabled_before": "disabled",
    "active_before": "inactive",
}}]
if data.get("service_transactions") != expected:
    raise RuntimeError("COMMITTED_INVALID")
PYVALID
    RC_VALIDATE=$?
    printf 'RC_PENDING=%s\nRC_COMMIT=%s\nRC_VALIDATE=%s\n' \\
        "$RC_PENDING" "$RC_COMMIT" "$RC_VALIDATE"
    (( RC_PENDING == 0 && RC_COMMIT == 0 && RC_VALIDATE == 0 ))
}}

case_pending_restore() {{
    reset_case
    record_manifest_pending_service_transaction \\
        demo example.service enable-now disabled inactive
    ENABLED_STATE="enabled"
    ACTIVE_STATE="active"
    restore_systemd_service_transaction demo example.service demo
    RC_RESTORE=$?
    printf 'RC_RESTORE=%s\nENABLED=%s\nACTIVE=%s\nCALL_COUNT=%s\n' \\
        "$RC_RESTORE" "$ENABLED_STATE" "$ACTIVE_STATE" "${{#CALLS[@]}}"
    (( RC_RESTORE == 0 ))
    [[ "$ENABLED_STATE" == "disabled" ]]
    [[ "$ACTIVE_STATE" == "inactive" ]]
}}

case_writer_failure() {{
    reset_case
    record_manifest_pending_service_transaction() {{ return 7; }}
    prepare_systemd_service_transaction demo example.service enable-now
    RC_PREPARE=$?
    printf 'RC_PREPARE=%s\nCALL_COUNT=%s\nERROR_COUNT=%s\n' \\
        "$RC_PREPARE" "${{#CALLS[@]}}" "${{#ERRORS[@]}}"
    (( RC_PREPARE != 0 ))
    (( ${{#CALLS[@]}} == 0 ))
    (( ${{#ERRORS[@]}} == 1 ))
}}

case_invalid_unit() {{
    reset_case
    prepare_systemd_service_transaction demo 'bad\\.service' enable-now
    RC_INVALID=$?
    printf 'RC_INVALID=%s\nERROR_COUNT=%s\n' "$RC_INVALID" "${{#ERRORS[@]}}"
    (( RC_INVALID != 0 ))
}}

main() {{
    case_commit
    RC_COMMIT_CASE=$?
    case_pending_restore
    RC_RESTORE_CASE=$?
    case_writer_failure
    RC_WRITER_CASE=$?
    case_invalid_unit
    RC_INVALID_CASE=$?

    printf 'RC_COMMIT_CASE=%s\nRC_RESTORE_CASE=%s\nRC_WRITER_CASE=%s\nRC_INVALID_CASE=%s\n' \\
        "$RC_COMMIT_CASE" "$RC_RESTORE_CASE" "$RC_WRITER_CASE" "$RC_INVALID_CASE"

    if (( RC_COMMIT_CASE == 0 \\
        && RC_RESTORE_CASE == 0 \\
        && RC_WRITER_CASE == 0 \\
        && RC_INVALID_CASE == 0 )); then
        echo "RESULT=SERVICE_STATE_CRASH_DYNAMIC_REGRESSION_OK"
        return 0
    fi
    return 1
}}

main "$@"
'''

harness_path.write_text(harness, encoding="utf-8")
harness_path.chmod(0o755)
PYBUILD
    RC_BUILD=$?

    bash "$HARNESS"
    RC_DYNAMIC=$?

    rm -rf -- "$TMP_ROOT"

    echo "RC_BUILD=$RC_BUILD"
    echo "RC_DYNAMIC=$RC_DYNAMIC"

    if (( RC_BUILD == 0 && RC_DYNAMIC == 0 )); then
        echo "RESULT=SERVICE_STATE_CRASH_REGRESSION_OK"
        return 0
    fi
    return 1
}

main "$@"
