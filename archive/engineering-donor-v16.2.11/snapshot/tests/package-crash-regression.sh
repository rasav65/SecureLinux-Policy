#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-package-crash-regression"
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

required_functions = [
    "record_manifest_pending_package_transaction",
    "commit_manifest_package_transaction",
    "snapshot_installed_packages",
    "record_newly_installed_packages",
    "install_packages_transactionally",
    "collect_manifest_package_candidates",
    "restore_installed_packages",
    "report_installed_packages_for_manual_restore",
]

matches = list(
    re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
        source,
    )
)

functions = {}
for index, match in enumerate(matches):
    name = match.group(1)
    if name not in required_functions:
        continue
    end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
    functions[name] = source[match.start():end].rstrip() + "\n"

missing = [name for name in required_functions if name not in functions]
if missing:
    raise RuntimeError("FUNCTION_NOT_FOUND:" + ",".join(missing))

if '"pending_package_transactions": []' not in source:
    raise RuntimeError("MANIFEST_PENDING_PACKAGE_FIELD_MISSING")

apt_install_functions = []
current_function = None
for line in source.splitlines():
    function_match = re.match(
        r"^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
        line,
    )
    if function_match:
        current_function = function_match.group(1)
    stripped = line.strip()
    if re.match(
        r"^(?:DEBIAN_FRONTEND=noninteractive[ \t]+)?apt-get[ \t]+install\b",
        stripped,
    ):
        apt_install_functions.append(current_function)

if apt_install_functions != ["install_packages_transactionally"]:
    raise RuntimeError(
        "UNJOURNALED_APT_INSTALL:" + repr(apt_install_functions)
    )

transactional_modules = {
    "apply_apparmor_module": 'install_packages_transactionally',
    "apply_aide_module": 'install_packages_transactionally',
    "apply_fail2ban_module": 'install_packages_transactionally',
    "apply_rkhunter_module": 'install_packages_transactionally',
    "apply_ufw_module": 'install_packages_transactionally',
    "apply_auditd_module": 'install_packages_transactionally',
    "apply_password_policy_module": 'install_packages_transactionally',
    "apply_rsyslog_module": 'install_packages_transactionally',
    "apply_chrony_module": 'install_packages_transactionally',
    "apply_unattended_upgrades_module": 'install_packages_transactionally',
}

for name, marker in transactional_modules.items():
    pattern = re.compile(
        rf"(?ms)^{re.escape(name)}\(\) \{{.*?^\}}\n"
    )
    match = pattern.search(source)
    if match is None or marker not in match.group(0):
        raise RuntimeError(f"TRANSACTIONAL_INSTALL_MISSING:{name}")

for name in (
    "restore_fail2ban_module",
    "restore_auditd_module",
    "restore_password_policy_module",
):
    match = re.search(
        rf"(?ms)^{name}\(\) \{{.*?^\}}\n",
        source,
    )
    if match is None or "restore_installed_packages" not in match.group(0):
        raise RuntimeError(f"AUTO_PACKAGE_RESTORE_MISSING:{name}")

for name in (
    "restore_apparmor_module",
    "restore_aide_module",
    "restore_rkhunter_module",
    "restore_ufw_module",
    "restore_rsyslog_module",
    "restore_chrony_module",
    "restore_unattended_upgrades_module",
):
    match = re.search(
        rf"(?ms)^{name}\(\) \{{.*?^\}}\n",
        source,
    )
    if match is None or "report_installed_packages_for_manual_restore" not in match.group(0):
        raise RuntimeError(f"MANUAL_PACKAGE_RECOVERY_MISSING:{name}")

print("RESULT=PACKAGE_CRASH_STATIC_REGRESSION_OK")

function_source = "\n".join(functions[name] for name in required_functions)

harness = f'''#!/usr/bin/env bash

{function_source}

ERRORS=()
WARNINGS=()
SAFE=()
CALLS=()
DRY_RUN=0
TIMESTAMP="20260804-120000"
STATE_DIR="{harness_path.parent}/state"
MANIFEST_FILE="$STATE_DIR/manifest.json"
RESTORE_SOURCE_MANIFEST="$MANIFEST_FILE"
DEBUG_LOG_FILE="{harness_path.parent}/debug.log"
CURRENT_PACKAGES=()
INSTALLED_SET=()
APT_INSTALL_RC=0
APT_PURGE_RC=0
SNAPSHOT_OVERRIDE_RC=0
TRACK_OVERRIDE_RC=0
USE_OVERRIDE=0

add_error() {{ ERRORS+=("$1"); }}
add_warning() {{ WARNINGS+=("$1"); }}
add_safe() {{ SAFE+=("$1"); }}
log() {{ :; }}
record_manifest_apply_report() {{ return 0; }}

pkg_installed() {{
    local wanted="$1"
    local item=""
    for item in "${{INSTALLED_SET[@]}}"; do
        [[ "$item" == "$wanted" ]] && return 0
    done
    return 1
}}

dpkg-query() {{
    local package=""
    for package in "${{CURRENT_PACKAGES[@]}}"; do
        printf '%s\\tinstall ok installed\\n' "$package"
    done
}}

apt-get() {{
    if [[ "$1" == "install" ]]; then
        CALLS+=("install")
        return "$APT_INSTALL_RC"
    fi
    if [[ "$1" == "purge" ]]; then
        shift
        while (( $# > 0 )); do
            case "$1" in
                -y|-q|-o)
                    if [[ "$1" == "-o" ]]; then
                        shift
                    fi
                    ;;
                *)
                    CALLS+=("purge:$1")
                    ;;
            esac
            shift
        done
        return "$APT_PURGE_RC"
    fi
    return 0
}}

real_snapshot_installed_packages="$(declare -f snapshot_installed_packages)"
real_record_newly_installed_packages="$(declare -f record_newly_installed_packages)"

reset_case() {{
    rm -rf -- "$STATE_DIR"
    mkdir -p -- "$STATE_DIR"
    printf '%s\\n' '{{
  "pending_package_transactions": [],
  "installed_packages": []
}}' > "$MANIFEST_FILE"
    chmod 600 "$MANIFEST_FILE"
    ERRORS=()
    WARNINGS=()
    SAFE=()
    CALLS=()
    CURRENT_PACKAGES=()
    INSTALLED_SET=()
    APT_INSTALL_RC=0
    APT_PURGE_RC=0
    SNAPSHOT_OVERRIDE_RC=0
    TRACK_OVERRIDE_RC=0
    USE_OVERRIDE=0
}}

restore_real_helpers() {{
    eval "$real_snapshot_installed_packages"
    eval "$real_record_newly_installed_packages"
}}

case_writer_commit() {{
    reset_case
    printf '%s\\n' base > "$STATE_DIR/before.txt"
    printf '%s\\n' base dependency requested > "$STATE_DIR/after.txt"
    chmod 600 "$STATE_DIR/before.txt" "$STATE_DIR/after.txt"

    record_manifest_pending_package_transaction \\
        test-module \\
        "$STATE_DIR/before.txt"
    RC_PENDING=$?

    COMMIT_COUNT="$(
        commit_manifest_package_transaction \\
            test-module \\
            "$STATE_DIR/before.txt" \\
            "$STATE_DIR/after.txt"
    )"
    RC_COMMIT=$?

    python3 - "$MANIFEST_FILE" "$COMMIT_COUNT" <<'PYVALID'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
count = sys.argv[2]
expected = [
    {{"module": "test-module", "package": "dependency"}},
    {{"module": "test-module", "package": "requested"}},
]
if data.get("pending_package_transactions") != []:
    raise RuntimeError("PENDING_NOT_CLEARED")
if data.get("installed_packages") != expected:
    raise RuntimeError(f"INSTALLED_INVALID:{{data.get('installed_packages')!r}}")
if count != "2":
    raise RuntimeError(f"COUNT_INVALID:{{count}}")
PYVALID
    RC_VALIDATE=$?

    printf '%s\\n' \\
        "RC_PENDING=$RC_PENDING" \\
        "RC_COMMIT=$RC_COMMIT" \\
        "RC_VALIDATE=$RC_VALIDATE"

    if (( RC_PENDING == 0 && RC_COMMIT == 0 && RC_VALIDATE == 0 )); then
        echo "RESULT=PACKAGE_JOURNAL_COMMIT_OK"
        return 0
    fi

    return 1
}}

case_pending_restore() {{
    reset_case
    printf '%s\\n' base > "$STATE_DIR/before.txt"
    chmod 600 "$STATE_DIR/before.txt"
    CURRENT_PACKAGES=(base dependency requested)
    INSTALLED_SET=(base dependency requested)

    record_manifest_pending_package_transaction \\
        test-module \\
        "$STATE_DIR/before.txt" || return 1

    restore_installed_packages test-module
    RC_RESTORE=$?

    printf '%s\\n' \\
        "RC_RESTORE=$RC_RESTORE" \\
        "CALLS=${{CALLS[*]}}" \\
        "ERROR_COUNT=${{#ERRORS[@]}}"

    if (( RC_RESTORE == 0 \
        && ${{#ERRORS[@]}} == 0 )) \
        && [[ " ${{CALLS[*]}} " == *" purge:dependency "* ]] \
        && [[ " ${{CALLS[*]}} " == *" purge:requested "* ]] \
        && [[ " ${{CALLS[*]}} " != *" purge:base "* ]]
    then
        echo "RESULT=PACKAGE_PENDING_RESTORE_OK"
        return 0
    fi

    return 1
}}

case_pending_before_mutation() {{
    reset_case
    printf '%s\\n' base > "$STATE_DIR/before.txt"
    chmod 600 "$STATE_DIR/before.txt"
    CURRENT_PACKAGES=(base)
    INSTALLED_SET=(base)

    record_manifest_pending_package_transaction \\
        test-module \\
        "$STATE_DIR/before.txt" || return 1

    restore_installed_packages test-module
    RC_RESTORE=$?

    printf '%s\\n' \\
        "RC_PREMUTATION_RESTORE=$RC_RESTORE" \\
        "CALL_COUNT=${{#CALLS[@]}}"

    if (( RC_RESTORE == 0 && ${{#CALLS[@]}} == 0 )); then
        echo "RESULT=PACKAGE_PENDING_BEFORE_MUTATION_OK"
        return 0
    fi

    return 1
}}

case_invalid_snapshot() {{
    reset_case
    python3 - "$MANIFEST_FILE" "$STATE_DIR/missing.txt" <<'PYINVALID'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["pending_package_transactions"] = [
    {{"module": "test-module", "snapshot": sys.argv[2]}}
]
path.write_text(json.dumps(data), encoding="utf-8")
PYINVALID

    restore_installed_packages test-module
    RC_INVALID=$?

    printf '%s\\n' \\
        "RC_INVALID=$RC_INVALID" \\
        "ERROR_COUNT=${{#ERRORS[@]}}" \\
        "CALL_COUNT=${{#CALLS[@]}}"

    if (( RC_INVALID != 0 \
        && ${{#ERRORS[@]}} == 1 \
        && ${{#CALLS[@]}} == 0 ))
    then
        echo "RESULT=PACKAGE_PENDING_INVALID_REJECTED_OK"
        return 0
    fi

    return 1
}}

case_install_order() {{
    reset_case
    USE_OVERRIDE=1

    snapshot_installed_packages() {{
        CALLS+=("pending")
        return "$SNAPSHOT_OVERRIDE_RC"
    }}

    record_newly_installed_packages() {{
        CALLS+=("commit")
        return "$TRACK_OVERRIDE_RC"
    }}

    install_packages_transactionally test-module requested
    RC_INSTALL=$?

    printf '%s\\n' \\
        "RC_INSTALL=$RC_INSTALL" \\
        "CALLS=${{CALLS[*]}}" \\
        "INSTALL_RC=$PACKAGE_TRANSACTION_INSTALL_RC" \\
        "TRACK_RC=$PACKAGE_TRANSACTION_TRACKING_RC"

    restore_real_helpers

    if (( RC_INSTALL == 0 )) \
        && [[ "${{CALLS[*]}}" == "pending install commit" ]]
    then
        echo "RESULT=PACKAGE_TRANSACTION_ORDER_OK"
        return 0
    fi

    return 1
}}

case_install_failure_still_commits() {{
    reset_case

    snapshot_installed_packages() {{
        CALLS+=("pending")
        return 0
    }}

    record_newly_installed_packages() {{
        CALLS+=("commit")
        return 0
    }}

    APT_INSTALL_RC=7
    install_packages_transactionally test-module requested
    RC_INSTALL=$?

    printf '%s\\n' \\
        "RC_FAILED_INSTALL=$RC_INSTALL" \\
        "CALLS=${{CALLS[*]}}" \\
        "INSTALL_RC=$PACKAGE_TRANSACTION_INSTALL_RC" \\
        "TRACK_RC=$PACKAGE_TRANSACTION_TRACKING_RC"

    restore_real_helpers

    if (( RC_INSTALL != 0 \
        && PACKAGE_TRANSACTION_INSTALL_RC == 7 \
        && PACKAGE_TRANSACTION_TRACKING_RC == 0 )) \
        && [[ "${{CALLS[*]}}" == "pending install commit" ]]
    then
        echo "RESULT=PACKAGE_FAILED_INSTALL_TRACKED_OK"
        return 0
    fi

    return 1
}}

case_pending_writer_failure_blocks_install() {{
    reset_case

    snapshot_installed_packages() {{
        CALLS+=("pending")
        return 1
    }}

    record_newly_installed_packages() {{
        CALLS+=("commit")
        return 0
    }}

    install_packages_transactionally test-module requested
    RC_INSTALL=$?

    printf '%s\\n' \\
        "RC_PENDING_FAILURE=$RC_INSTALL" \\
        "CALLS=${{CALLS[*]}}" \\
        "INSTALL_RC=$PACKAGE_TRANSACTION_INSTALL_RC" \\
        "TRACK_RC=$PACKAGE_TRANSACTION_TRACKING_RC"

    restore_real_helpers

    if (( RC_INSTALL != 0 \
        && PACKAGE_TRANSACTION_INSTALL_RC == 0 \
        && PACKAGE_TRANSACTION_TRACKING_RC == 1 )) \
        && [[ "${{CALLS[*]}}" == "pending" ]]
    then
        echo "RESULT=PACKAGE_PENDING_FAILURE_BLOCKS_INSTALL_OK"
        return 0
    fi

    return 1
}}

main() {{
    mkdir -p -- "$STATE_DIR"

    case_writer_commit
    RC_WRITER=$?

    case_pending_restore
    RC_RESTORE=$?

    case_pending_before_mutation
    RC_PREMUTATION=$?

    case_invalid_snapshot
    RC_INVALID=$?

    case_install_order
    RC_ORDER=$?

    case_install_failure_still_commits
    RC_FAILED_INSTALL=$?

    case_pending_writer_failure_blocks_install
    RC_PENDING_FAILURE=$?

    printf '%s\\n' \\
        "RC_WRITER=$RC_WRITER" \\
        "RC_RESTORE=$RC_RESTORE" \\
        "RC_PREMUTATION=$RC_PREMUTATION" \\
        "RC_INVALID=$RC_INVALID" \\
        "RC_ORDER=$RC_ORDER" \\
        "RC_FAILED_INSTALL=$RC_FAILED_INSTALL" \\
        "RC_PENDING_FAILURE=$RC_PENDING_FAILURE"

    if (( RC_WRITER == 0 \
        && RC_RESTORE == 0 \
        && RC_PREMUTATION == 0 \
        && RC_INVALID == 0 \
        && RC_ORDER == 0 \
        && RC_FAILED_INSTALL == 0 \
        && RC_PENDING_FAILURE == 0 ))
    then
        echo "RESULT=PACKAGE_CRASH_DYNAMIC_REGRESSION_OK"
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

    RC_DYNAMIC=99
    if (( RC_BUILD == 0 )); then
        bash "$HARNESS"
        RC_DYNAMIC=$?
    fi

    rm -rf -- "$TMP_ROOT"

    printf '%s\n' \
        "RC_BUILD=$RC_BUILD" \
        "RC_DYNAMIC=$RC_DYNAMIC"

    if (( RC_BUILD == 0 && RC_DYNAMIC == 0 )); then
        echo "RESULT=PACKAGE_CRASH_REGRESSION_OK"
        return 0
    fi

    echo "RESULT=PACKAGE_CRASH_REGRESSION_FAILED"
    return 1
}

main "$@"
