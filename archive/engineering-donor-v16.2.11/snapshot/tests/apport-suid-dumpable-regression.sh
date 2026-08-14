#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 1

python3 - <<'PYCHECK'
from pathlib import Path
import re

source = Path("securelinux-ng.sh").read_text(encoding="utf-8")
readme = Path("README.md").read_text(encoding="utf-8")
architecture = Path("docs/architecture.md").read_text(encoding="utf-8")
compatibility = Path("docs/compatibility.md").read_text(encoding="utf-8")
mapping = Path("docs/fstec-mapping.md").read_text(encoding="utf-8")
restore_doc = Path("docs/restore-model.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
smoke = Path("tests/smoke.sh").read_text(encoding="utf-8")
errors = []


def require(condition, message):
    if not condition:
        errors.append(message)


def function_block(name):
    matches = list(re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
        source,
    ))
    for index, match in enumerate(matches):
        if match.group(1) != name:
            continue
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(source)
        )
        return source[match.start():end]
    return ""


for marker in (
    'SYSCTL_USERSPACE_APPORT_DROPIN="/etc/systemd/system/apport.service.d/60-securelinux-ng-suid-dumpable.conf"',
    "check_sysctl_userspace_apport_dropin()",
    "apply_sysctl_userspace_apport_dropin()",
    "restore_sysctl_userspace_apport_dropin()",
    "ExecStartPost=/usr/sbin/sysctl -q -w fs.suid_dumpable=0",
    "systemctl cat apport.service",
):
    require(marker in source, f"SOURCE_MARKER_MISSING:{marker}")

for forbidden in (
    "SYSCTL_USERSPACE_LATE_UNIT",
    "securelinux-ng-userspace-sysctl.service",
    "PartOf=apport.service",
    "WantedBy=multi-user.target apport.service",
):
    require(forbidden not in source, f"OLD_UNIT_MARKER_PRESENT:{forbidden}")

apply_block = function_block("apply_sysctl_userspace_protection_module")
restore_block = function_block("restore_sysctl_userspace_protection_module")
dropin_apply = function_block("apply_sysctl_userspace_apport_dropin")
dropin_restore = function_block("restore_sysctl_userspace_apport_dropin")
run_check = function_block("run_check_mode")
run_apply = function_block("run_apply_mode")

for name, block in (
    ("apply", apply_block),
    ("restore", restore_block),
    ("dropin_apply", dropin_apply),
    ("dropin_restore", dropin_restore),
    ("run_check", run_check),
    ("run_apply", run_apply),
):
    require(bool(block), f"FUNCTION_MISSING:{name}")

if apply_block:
    hook = apply_block.find("apply_sysctl_userspace_apport_dropin")
    runtime = apply_block.find(
        'sysctl -p "$SYSCTL_USERSPACE_PROTECTION_DROPIN"'
    )
    require(hook >= 0 and runtime > hook, "APPLY_ORDER_INVALID")

if run_apply:
    userspace = run_apply.find(
        "run_mode_step apply apply_sysctl_userspace_protection_module"
    )
    apport = run_apply.find(
        "run_mode_step apply apply_apport_module"
    )
    require(
        userspace >= 0 and apport > userspace,
        "APPORT_ADDITIONAL_AFTER_USERSPACE_INVALID",
    )

if restore_block:
    hook = restore_block.find("restore_sysctl_userspace_apport_dropin")
    managed = restore_block.find("restore_file_from_manifest")
    runtime = restore_block.find("restore_sysctl_runtime_snapshot")
    require(
        hook >= 0 and managed > hook and runtime > managed,
        "RESTORE_ORDER_INVALID",
    )

for marker in (
    "backup_file_checked",
    "record_manifest_backup",
    "prepare_created_file_transaction",
    "record_manifest_created_file",
    "record_manifest_modified_file_best_effort",
    "systemctl daemon-reload",
):
    require(
        marker in dropin_apply,
        f"DROPIN_APPLY_MARKER_MISSING:{marker}",
    )

for forbidden in (
    "prepare_systemd_service_transaction",
    "commit_systemd_service_transaction",
    "systemctl enable",
    "systemctl disable",
):
    require(
        forbidden not in dropin_apply,
        f"DROPIN_APPLY_FORBIDDEN:{forbidden}",
    )

for marker in (
    "restore_lookup_backup",
    "restore_has_created_file",
    "restore_file_from_manifest",
    "systemctl daemon-reload",
):
    require(
        marker in dropin_restore,
        f"DROPIN_RESTORE_MARKER_MISSING:{marker}",
    )

require(
    "restore_systemd_service_transaction" not in dropin_restore,
    "DROPIN_RESTORE_SERVICE_STATE_PRESENT",
)

require(
    "check_sysctl_userspace_apport_dropin" in run_check,
    "RUN_CHECK_CALL_MISSING",
)

dropin_path = (
    "/etc/systemd/system/apport.service.d/"
    "60-securelinux-ng-suid-dumpable.conf"
)

for document, label in (
    (readme, "README"),
    (architecture, "ARCHITECTURE"),
    (compatibility, "COMPATIBILITY"),
    (mapping, "MAPPING"),
    (restore_doc, "RESTORE"),
):
    require(
        dropin_path in document,
        f"{label}_DROPIN_MARKER_MISSING",
    )
    require(
        "securelinux-ng-userspace-sysctl.service" not in document,
        f"{label}_OLD_UNIT_MARKER_PRESENT",
    )

require(
    "Добавлен `tests/apport-suid-dumpable-regression.sh`" in changelog,
    "CHANGELOG_TEST_MISSING",
)
require(
    "ExecStartPost" in changelog,
    "CHANGELOG_EXECSTARTPOST_MISSING",
)
require(
    smoke.count("bash tests/apport-suid-dumpable-regression.sh &&") == 1,
    "SMOKE_REGISTRATION_INVALID",
)

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=APPORT_SUID_DUMPABLE_DROPIN_REGRESSION_OK")
PYCHECK
RC_TEST=$?
echo "RC_TEST=$RC_TEST"
exit "$RC_TEST"
