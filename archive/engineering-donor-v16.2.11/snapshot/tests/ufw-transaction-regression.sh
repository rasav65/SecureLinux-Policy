#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-ufw-transaction-regression"

rm -rf -- "$TMP_ROOT"
mkdir -p -- "$TMP_ROOT"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

python3 - "$SOURCE" <<'PYTEST'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
errors = []


def function_text(name):
    pattern = re.compile(
        rf"(?ms)^{re.escape(name)}\(\) \{{.*?(?=^[A-Za-z_][A-Za-z0-9_]*\(\) \{{|\Z)"
    )
    match = pattern.search(source)
    if not match:
        errors.append(f"FUNCTION_NOT_FOUND:{name}")
        return ""
    return match.group(0)


writer = function_text("record_manifest_firewall_state")
reader = function_text("restore_manifest_firewall_state")
apply = function_text("apply_ufw_module")
restore = function_text("restore_ufw_module")

if 'module_state["firewall"]' not in writer:
    errors.append("TYPED_FIREWALL_WRITER_MISSING")

for field in (
    "ufw_was_active",
    "ufw_service_was_enabled",
    "nftables_was_active",
    "nftables_was_enabled",
    "nftables_mutation_attempted",
    "rules_mutation_attempted",
    "ufw_enable_attempted",
    "ufw_service_enable_attempted",
):
    if field not in writer or field not in reader:
        errors.append(f"FIREWALL_FIELD_MISSING:{field}")

if '"restore_policy": "typed-partial-rules"' not in writer:
    errors.append("FIREWALL_RESTORE_POLICY_MISSING")

initial_record = apply.find("record_manifest_firewall_state")
first_nft_mutation = apply.find("systemctl stop nftables")
first_rule_mutation = apply.find("ufw default deny incoming")
enable_marker = apply.find("ufw_enable_attempted=1")
enable_call = apply.find("ufw --force enable")
service_marker = apply.find("ufw_service_enable_attempted=1")
service_call = apply.find("systemctl enable ufw")

ufw_active_snapshot = apply.find(
    'ufw status 2>/dev/null | grep -q "^Status: active"'
)
ufw_enabled_snapshot = apply.find(
    "systemctl is-enabled ufw"
)
nft_active_snapshot = apply.find(
    "systemctl is-active nftables"
)
nft_enabled_snapshot = apply.find(
    "systemctl is-enabled nftables"
)
package_install = apply.find(
    'install_packages_transactionally "firewall" ufw'
)

for name, position in (
    ("UFW_ACTIVE_PRESTATE", ufw_active_snapshot),
    ("UFW_ENABLED_PRESTATE", ufw_enabled_snapshot),
    ("NFT_ACTIVE_PRESTATE", nft_active_snapshot),
    ("NFT_ENABLED_PRESTATE", nft_enabled_snapshot),
):
    if position < 0:
        errors.append(f"{name}_SNAPSHOT_MISSING")
    elif package_install >= 0 and position >= package_install:
        errors.append(f"{name}_SNAPSHOT_AFTER_PACKAGE_INSTALL")

if package_install < 0:
    errors.append("UFW_PACKAGE_INSTALL_MARKER_MISSING")
elif initial_record >= 0 and package_install >= initial_record:
    errors.append("UFW_PACKAGE_INSTALL_NOT_BEFORE_TYPED_RECORD")

if initial_record < 0:
    errors.append("INITIAL_FIREWALL_STATE_RECORD_MISSING")

if first_nft_mutation >= 0 and initial_record > first_nft_mutation:
    errors.append("NFTA_STATE_RECORDED_AFTER_MUTATION")

if first_rule_mutation >= 0 and initial_record > first_rule_mutation:
    errors.append("UFW_STATE_RECORDED_AFTER_RULE_MUTATION")

if enable_marker < 0 or enable_call < 0 or enable_marker > enable_call:
    errors.append("UFW_ENABLE_INTENT_ORDER_INVALID")

if service_marker < 0 or service_call < 0 or service_marker > service_call:
    errors.append("UFW_SERVICE_INTENT_ORDER_INVALID")

if "systemctl enable ufw завершился с ошибкой" not in apply:
    errors.append("SYSTEMCTL_ENABLE_FAILURE_NOT_FATAL")

if "ufw --force disable" not in apply:
    errors.append("LOCAL_UFW_ROLLBACK_MISSING")

if restore.find("restore_manifest_firewall_state") > restore.find("apply_report fallback"):
    errors.append("TYPED_STATE_NOT_PRIMARY_RESTORE_SOURCE")

if "systemctl disable ufw" not in restore:
    errors.append("UFW_SERVICE_DISABLE_RESTORE_MISSING")

if "systemctl disable nftables" not in restore:
    errors.append("NFTABLES_DISABLED_STATE_RESTORE_MISSING")

if errors:
    for error in errors:
        print(error)
    raise SystemExit(1)

print("RESULT=UFW_TRANSACTION_STATIC_REGRESSION_OK")
PYTEST
RC_STATIC=$?

python3 - "$SOURCE" "$TMP_ROOT" <<'PYBUILD'
import re
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
tmp_root = Path(sys.argv[2])
source = source_path.read_text(encoding="utf-8")


def function_text(name):
    pattern = re.compile(
        rf"(?ms)^{re.escape(name)}\(\) \{{.*?(?=^[A-Za-z_][A-Za-z0-9_]*\(\) \{{|\Z)"
    )
    match = pattern.search(source)
    if not match:
        raise RuntimeError(f"FUNCTION_NOT_FOUND:{name}")
    return match.group(0)


functions = "\n".join(
    function_text(name)
    for name in (
        "record_manifest_firewall_state",
        "restore_manifest_firewall_state",
        "apply_ufw_module",
        "restore_ufw_module",
    )
)

harness = r'''#!/usr/bin/env bash

CASE_NAME="$1"
CASE_ROOT="$2"
mkdir -p -- "$CASE_ROOT"

DRY_RUN=0
DEBUG_LOG_FILE="/dev/null"
MANIFEST_FILE="$CASE_ROOT/manifest.json"
RESTORE_SOURCE_MANIFEST="$MANIFEST_FILE"
UFW_SSH_PORT="22"
UFW_EXTRA_RULES=""
SSH_PORT_RESOLVED="22"
ERRORS=()
WARNINGS=()
SAFE_ITEMS=()
POLICY_GATES=()
CALLS=()

UFW_ACTIVE=0
UFW_SERVICE_ENABLED=0
NFT_ACTIVE=0
NFT_ENABLED=0
NFT_MASKED=0
FAIL_SYSTEMCTL_ENABLE_UFW=0
FAIL_UFW_DISABLE=0

printf '%s\n' '{"module_state": {}, "apply_report": [], "warnings": [], "irreversible_changes": []}' > "$MANIFEST_FILE"

log() { :; }
add_error() { ERRORS+=("$1"); }
add_warning() { WARNINGS+=("$1"); }
add_safe() { SAFE_ITEMS+=("$1"); }
add_skipped() { :; }
add_policy_gate() { POLICY_GATES+=("$1"); }
apt_update_once() { return 0; }
pkg_installed() { return 0; }
resolve_ssh_port() { SSH_PORT_RESOLVED="$1"; return 0; }
record_manifest_warning() { return 0; }
record_manifest_apply_report() { return 0; }
record_manifest_irreversible_change() { return 0; }
restore_manifest_has_report_text() { return 1; }
report_installed_packages_for_manual_restore() { return 0; }

ufw() {
    CALLS+=("ufw:$*")

    case "$*" in
        "status")
            if (( UFW_ACTIVE == 1 )); then
                echo "Status: active"
            else
                echo "Status: inactive"
            fi
            return 0
            ;;
        "status verbose")
            if (( UFW_ACTIVE == 1 )); then
                printf '%s\n' 'Status: active' 'Default: deny (incoming), allow (outgoing), disabled (routed)'
            else
                printf '%s\n' 'Status: inactive'
            fi
            return 0
            ;;
        "show added")
            return 0
            ;;
        "--force enable")
            UFW_ACTIVE=1
            return 0
            ;;
        "--force disable")
            if (( FAIL_UFW_DISABLE == 1 )); then
                return 1
            fi
            UFW_ACTIVE=0
            return 0
            ;;
        "default deny incoming"|"default allow outgoing"|allow*)
            return 0
            ;;
    esac

    return 0
}

systemctl() {
    CALLS+=("systemctl:$*")

    case "$1:$2" in
        "is-active:nftables")
            (( NFT_ACTIVE == 1 ))
            return
            ;;
        "is-enabled:nftables")
            (( NFT_ENABLED == 1 ))
            return
            ;;
        "is-enabled:ufw")
            (( UFW_SERVICE_ENABLED == 1 ))
            return
            ;;
        "stop:nftables")
            NFT_ACTIVE=0
            return 0
            ;;
        "start:nftables")
            NFT_ACTIVE=1
            return 0
            ;;
        "mask:nftables")
            NFT_MASKED=1
            return 0
            ;;
        "unmask:nftables")
            NFT_MASKED=0
            return 0
            ;;
        "enable:nftables")
            NFT_ENABLED=1
            return 0
            ;;
        "disable:nftables")
            NFT_ENABLED=0
            return 0
            ;;
        "enable:ufw")
            if (( FAIL_SYSTEMCTL_ENABLE_UFW == 1 )); then
                return 1
            fi
            UFW_SERVICE_ENABLED=1
            return 0
            ;;
        "disable:ufw")
            UFW_SERVICE_ENABLED=0
            return 0
            ;;
    esac

    return 0
}

manifest_value() {
    python3 - "$MANIFEST_FILE" "$1" <<'PYJSON'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
state = data.get("module_state", {}).get("firewall", {})
value = state.get(sys.argv[2])
if isinstance(value, bool):
    print("1" if value else "0")
else:
    print(value if value is not None else "missing")
PYJSON
}

case "$CASE_NAME" in
    rollback-success)
        FAIL_SYSTEMCTL_ENABLE_UFW=1
        apply_ufw_module
        APPLY_RC=$?
        printf '%s\n' \
            "APPLY_RC=$APPLY_RC" \
            "UFW_ACTIVE=$UFW_ACTIVE" \
            "ENABLE_ATTEMPTED=$(manifest_value ufw_enable_attempted)" \
            "SERVICE_ATTEMPTED=$(manifest_value ufw_service_enable_attempted)" \
            "ERROR_COUNT=${#ERRORS[@]}"
        (( APPLY_RC == 1 ))
        (( UFW_ACTIVE == 0 ))
        [[ "$(manifest_value ufw_enable_attempted)" == "1" ]]
        [[ "$(manifest_value ufw_service_enable_attempted)" == "1" ]]
        (( ${#ERRORS[@]} == 1 ))
        ;;

    rollback-failure-restore)
        FAIL_SYSTEMCTL_ENABLE_UFW=1
        FAIL_UFW_DISABLE=1
        apply_ufw_module
        APPLY_RC=$?
        ACTIVE_AFTER_APPLY=$UFW_ACTIVE
        FAIL_UFW_DISABLE=0
        restore_ufw_module
        RESTORE_RC=$?
        printf '%s\n' \
            "APPLY_RC=$APPLY_RC" \
            "ACTIVE_AFTER_APPLY=$ACTIVE_AFTER_APPLY" \
            "RESTORE_RC=$RESTORE_RC" \
            "ACTIVE_AFTER_RESTORE=$UFW_ACTIVE" \
            "SERVICE_AFTER_RESTORE=$UFW_SERVICE_ENABLED"
        (( APPLY_RC == 1 ))
        (( ACTIVE_AFTER_APPLY == 1 ))
        (( RESTORE_RC == 0 ))
        (( UFW_ACTIVE == 0 ))
        (( UFW_SERVICE_ENABLED == 0 ))
        ;;

    writer-failure)
        MANIFEST_FILE="$CASE_ROOT/missing/manifest.json"
        RESTORE_SOURCE_MANIFEST="$MANIFEST_FILE"
        apply_ufw_module
        APPLY_RC=$?
        printf '%s\n' \
            "APPLY_RC=$APPLY_RC" \
            "UFW_ACTIVE=$UFW_ACTIVE" \
            "CALL_COUNT=${#CALLS[@]}" \
            "ERROR_COUNT=${#ERRORS[@]}"
        (( APPLY_RC == 1 ))
        (( UFW_ACTIVE == 0 ))
        ! printf '%s\n' "${CALLS[@]}" | grep -q '^ufw:--force enable$'
        ;;

    nft-restore)
        record_manifest_firewall_state 0 0 1 1 1 0 0 0
        NFT_ACTIVE=0
        NFT_ENABLED=0
        NFT_MASKED=1
        restore_ufw_module
        RESTORE_RC=$?
        printf '%s\n' \
            "RESTORE_RC=$RESTORE_RC" \
            "NFT_ACTIVE=$NFT_ACTIVE" \
            "NFT_ENABLED=$NFT_ENABLED" \
            "NFT_MASKED=$NFT_MASKED"
        (( RESTORE_RC == 0 ))
        (( NFT_ACTIVE == 1 ))
        (( NFT_ENABLED == 1 ))
        (( NFT_MASKED == 0 ))
        ;;

    preactive-service-restore)
        record_manifest_firewall_state 1 0 0 0 0 1 0 1
        UFW_ACTIVE=1
        UFW_SERVICE_ENABLED=1
        restore_ufw_module
        RESTORE_RC=$?
        printf '%s\n' \
            "RESTORE_RC=$RESTORE_RC" \
            "UFW_ACTIVE=$UFW_ACTIVE" \
            "UFW_SERVICE_ENABLED=$UFW_SERVICE_ENABLED" \
            "WARNING_COUNT=${#WARNINGS[@]}"
        (( RESTORE_RC == 0 ))
        (( UFW_ACTIVE == 1 ))
        (( UFW_SERVICE_ENABLED == 0 ))
        (( ${#WARNINGS[@]} == 1 ))
        ;;

    invalid-state)
        printf '%s\n' '{"module_state": {"firewall": {"ufw_was_active": "bad"}}}' > "$MANIFEST_FILE"
        restore_ufw_module
        RESTORE_RC=$?
        printf '%s\n' \
            "RESTORE_RC=$RESTORE_RC" \
            "ERROR_COUNT=${#ERRORS[@]}"
        (( RESTORE_RC == 1 ))
        (( ${#ERRORS[@]} == 1 ))
        ;;

    *)
        echo "UNKNOWN_CASE=$CASE_NAME"
        false
        ;;
esac
'''

output = tmp_root / "ufw-transaction-harness.sh"
output.write_text(functions + "\n" + harness, encoding="utf-8")
output.chmod(0o755)
PYBUILD
RC_BUILD=$?

RC_ROLLBACK_SUCCESS=99
RC_ROLLBACK_FAILURE=99
RC_WRITER_FAILURE=99
RC_NFT_RESTORE=99
RC_PREACTIVE=99
RC_INVALID=99

if (( RC_STATIC == 0 && RC_BUILD == 0 )); then
    bash "$TMP_ROOT/ufw-transaction-harness.sh" \
        rollback-success "$TMP_ROOT/rollback-success"
    RC_ROLLBACK_SUCCESS=$?

    bash "$TMP_ROOT/ufw-transaction-harness.sh" \
        rollback-failure-restore "$TMP_ROOT/rollback-failure"
    RC_ROLLBACK_FAILURE=$?

    bash "$TMP_ROOT/ufw-transaction-harness.sh" \
        writer-failure "$TMP_ROOT/writer-failure"
    RC_WRITER_FAILURE=$?

    bash "$TMP_ROOT/ufw-transaction-harness.sh" \
        nft-restore "$TMP_ROOT/nft-restore"
    RC_NFT_RESTORE=$?

    bash "$TMP_ROOT/ufw-transaction-harness.sh" \
        preactive-service-restore "$TMP_ROOT/preactive"
    RC_PREACTIVE=$?

    bash "$TMP_ROOT/ufw-transaction-harness.sh" \
        invalid-state "$TMP_ROOT/invalid"
    RC_INVALID=$?
fi

printf '%s\n' \
    "RC_STATIC=$RC_STATIC" \
    "RC_BUILD=$RC_BUILD" \
    "RC_ROLLBACK_SUCCESS=$RC_ROLLBACK_SUCCESS" \
    "RC_ROLLBACK_FAILURE=$RC_ROLLBACK_FAILURE" \
    "RC_WRITER_FAILURE=$RC_WRITER_FAILURE" \
    "RC_NFT_RESTORE=$RC_NFT_RESTORE" \
    "RC_PREACTIVE=$RC_PREACTIVE" \
    "RC_INVALID=$RC_INVALID"

if (( RC_STATIC == 0 )) &&
   (( RC_BUILD == 0 )) &&
   (( RC_ROLLBACK_SUCCESS == 0 )) &&
   (( RC_ROLLBACK_FAILURE == 0 )) &&
   (( RC_WRITER_FAILURE == 0 )) &&
   (( RC_NFT_RESTORE == 0 )) &&
   (( RC_PREACTIVE == 0 )) &&
   (( RC_INVALID == 0 )); then
    echo "RESULT=UFW_TRANSACTION_REGRESSION_OK"
    exit 0
fi

echo "RESULT=UFW_TRANSACTION_REGRESSION_FAILED"
exit 1
