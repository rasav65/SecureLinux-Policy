#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT/securelinux-ng.sh" "$ROOT/docs/architecture.md" <<'PYTEST'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
docs = Path(sys.argv[2]).read_text(encoding="utf-8")
errors = []
fence = chr(96) * 3


def require(condition, message):
    if not condition:
        errors.append(message)


def function_text(name):
    matches = list(
        re.finditer(
            r"(?m)^([A-Za-z0-9_]+)\(\) \{$",
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


def require_order(text, markers, message):
    cursor = 0

    for marker in markers:
        position = text.find(marker, cursor)
        if position < 0:
            errors.append(
                f"{message}:MISSING_OR_OUT_OF_ORDER:{marker}"
            )
            return
        cursor = position + len(marker)


required_headings = (
    "## Общая схема выполнения",
    "## Карта модулей усиления безопасности",
    "## Поток apply, manifest и restore",
)

for heading in required_headings:
    require(
        docs.count(heading) == 1,
        f"ARCHITECTURE_HEADING_INVALID:{heading}",
    )

require(
    docs.count(fence + "mermaid") == 3,
    "MERMAID_BLOCK_COUNT_INVALID",
)
require(
    docs.count("flowchart TB") == 3,
    "MERMAID_FLOWCHART_COUNT_INVALID",
)
require(
    "UFW_ALLOW_FROM_" not in docs,
    "STALE_UFW_ALLOW_FROM_REFERENCE",
)

required_doc_markers = (
    "parse_args()",
    "require_cmds()",
    "validate_args()",
    "load_config()",
    "validate_args_post_config()",
    "validate_execution_context()",
    "finalize_paths()",
    "run_check_mode()",
    "run_apply_mode()",
    "run_restore_mode()",
    "run_report_mode()",
    "run_preflight()",
    "check_memory_requirements()",
    "ensure_state_dir()",
    "acquire_run_lock()",
    "manifest_init()",
    "resolve_restore_manifest()",
    "backup_file_checked()",
    "additional_measures_enabled",
    "ENABLE_CORPORATE_PASSWORD_POLICY = 1?",
    "kernel.modules_disabled (временно SKIP)",
    "pending_created_groups",
    "pending_group_memberships",
    "added_group_memberships",
    "password_aging_snapshots",
    "apply_report",
    "последний manifest-*.json",
    "manifest.json",
)

for marker in required_doc_markers:
    require(
        marker in docs,
        f"ARCHITECTURE_MARKER_MISSING:{marker}",
    )

main = function_text("main")
require_order(
    main,
    (
        'parse_args "$@"',
        "require_cmds",
        "validate_args",
        "load_config",
        "validate_args_post_config",
        "validate_execution_context",
        "finalize_paths",
        'case "$MODE" in',
    ),
    "MAIN_PIPELINE_CHANGED",
)

for marker in (
    "check) run_check_mode ;;",
    "apply) run_apply_mode ;;",
    "restore) run_restore_mode ;;",
    "report) run_report_mode ;;",
):
    require(marker in main, f"MAIN_DISPATCH_CHANGED:{marker}")

check = function_text("run_check_mode")
require_order(
    check,
    (
        "run_preflight",
        "check_empty_passwords_module",
        "check_ssh_root_login_module",
        "if additional_measures_enabled; then",
        "check_pam_wheel_module",
        "write_report",
        "print_report_stdout",
    ),
    "CHECK_FLOW_CHANGED",
)

apply = function_text("run_apply_mode")
require_order(
    apply,
    (
        "run_preflight",
        "check_memory_requirements",
        "ensure_state_dir",
        "acquire_run_lock",
        "manifest_init",
        "apply_empty_passwords_module",
        "if additional_measures_enabled; then",
        "apply_pam_wheel_module",
        "apply_faillock_module",
        "apply_password_policy_module",
        "write_report",
        "print_report_stdout",
    ),
    "APPLY_FLOW_CHANGED",
)

restore = function_text("run_restore_mode")
require_order(
    restore,
    (
        "run_preflight",
        "resolve_restore_manifest",
        "ensure_state_dir",
        "acquire_run_lock",
        'data.get("additional_measures_enabled", True)',
        "restore_ssh_root_login_module",
        "if (( restore_additional_measures == 1 )); then",
        "restore_pam_wheel_module",
        "write_report",
        "print_report_stdout",
    ),
    "RESTORE_FLOW_CHANGED",
)

report = function_text("run_report_mode")
require_order(
    report,
    (
        "run_preflight",
        "ensure_state_dir",
        "write_report",
        "print_report_stdout",
    ),
    "REPORT_FLOW_CHANGED",
)

for function_name in (
    "check_faillock_module",
    "apply_faillock_module",
    "check_password_policy_module",
    "apply_password_policy_module",
):
    function = function_text(function_name)
    require(
        "corporate_password_policy_enabled" in function,
        f"CORPORATE_POLICY_GATE_CHANGED:{function_name}",
    )

resolve = function_text("resolve_restore_manifest")
require_order(
    resolve,
    (
        'if [[ -n "$RESTORE_MANIFEST" ]]',
        'base.glob("manifest-*.json")',
        'base / "manifest.json"',
    ),
    "RESTORE_MANIFEST_SELECTION_CHANGED",
)

for marker in (
    "backup_file_checked() {",
    "manifest_init() {",
    "corporate_password_policy_enabled() {",
    "os.replace(tmp_path, str(path))",
    '"additional_measures_enabled":',
    '"pending_created_groups":',
    '"pending_group_memberships":',
    '"added_group_memberships":',
    '"password_aging_snapshots":',
    '"apply_report":',
):
    require(
        marker in source,
        f"ARCHITECTURE_SOURCE_MARKER_MISSING:{marker}",
    )

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=ARCHITECTURE_REGRESSION_OK")
PYTEST

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0

# BEGIN GRUB CLASSIFICATION REGRESSION
RC_ARCHITECTURE_BASE=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/securelinux-ng.sh" \
    <<'PYGRUBCLASS'
import json
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(
    encoding="utf-8"
)

errors = []

expected = {
    "2.4.3": (
        "grub_init_on_alloc",
        ("init_on_alloc=1",),
    ),
    "2.4.4": (
        "grub_slab_nomerge",
        ("slab_nomerge",),
    ),
    "2.4.5": (
        "grub_iommu_hardening",
        (
            "iommu=force",
            "iommu.strict=1",
            "iommu.passthrough=0",
        ),
    ),
    "2.4.6": (
        "grub_randomize_kstack_offset",
        ("randomize_kstack_offset=1",),
    ),
    "2.4.7": (
        "grub_mitigations",
        ("mitigations=auto,nosmt",),
    ),
    "2.5.1": (
        "grub_vsyscall_none",
        ("vsyscall=none",),
    ),
    "2.5.9": (
        "grub_tsx_off",
        ("tsx=off",),
    ),
}

def require(condition, message):
    if not condition:
        errors.append(message)

inventory_match = re.search(
    r"(?ms)^[ \t]*fstec_items[ \t]*=[ \t]*\[\n"
    r"(?P<body>.*?)"
    r"^[ \t]*\][ \t]*$",
    source,
)

require(
    inventory_match is not None,
    "FSTEC_ITEMS_BLOCK_MISSING",
)

inventory = {}

if inventory_match is not None:
    for raw in re.findall(
        r"(?m)^[ \t]*(\{[^\n]+\}),?[ \t]*$",
        inventory_match.group("body"),
    ):
        entry = json.loads(raw)
        inventory[entry["item"]] = entry

array_match = re.search(
    r"(?ms)^GRUB_KERNEL_REQUIRED_PARAMS=\(\n"
    r"(?P<body>.*?)"
    r"^\)[ \t]*$",
    source,
)

require(
    array_match is not None,
    "GRUB_REQUIRED_PARAMS_BLOCK_MISSING",
)

required_params = set()

if array_match is not None:
    required_params = set(
        re.findall(
            r'^[ \t]*"([^"]+)"[ \t]*$',
            array_match.group("body"),
            re.MULTILINE,
        )
    )

for item_id, (module, parameters) in expected.items():
    entry = inventory.get(item_id)

    require(
        entry is not None,
        f"GRUB_CLASSIFICATION_ITEM_MISSING:{item_id}",
    )

    if entry is None:
        continue

    require(
        entry.get("status") == "partial",
        f"GRUB_CLASSIFICATION_STATUS_INVALID:{item_id}",
    )

    require(
        entry.get("restore")
        == "grub-backup+reboot-required",
        f"GRUB_CLASSIFICATION_RESTORE_INVALID:{item_id}",
    )

    require(
        entry.get("module") == module,
        f"GRUB_CLASSIFICATION_MODULE_INVALID:{item_id}",
    )

    for parameter in parameters:
        require(
            parameter in required_params,
            f"GRUB_REQUIRED_PARAMETER_MISSING:"
            f"{item_id}:{parameter}",
        )

detect_only_items = [
    entry["item"]
    for entry in inventory.values()
    if entry.get("restore")
    == "policy-gated-detect-only"
]

require(
    not detect_only_items,
    "OBSOLETE_DETECT_ONLY_CLASSIFICATION:"
    + ",".join(sorted(detect_only_items)),
)

require(
    '"restore_grub_backup_reboot_required": '
    'sum(1 for x in fstec_items '
    'if x["restore"] == '
    '"grub-backup+reboot-required")'
    in source,
    "GRUB_RESTORE_SUMMARY_COUNTER_MISSING",
)

require(
    'grub_params=('
    '"${GRUB_KERNEL_REQUIRED_PARAMS[@]}")'
    in source,
    "GRUB_REQUIRED_PARAMS_NOT_USED_BY_APPLY",
)

apply_start = source.find(
    "apply_grub_kernel_params_module() {"
)
restore_start = source.find(
    "restore_grub_module() {"
)

require(
    apply_start >= 0,
    "GRUB_APPLY_FUNCTION_MISSING",
)

require(
    restore_start >= 0,
    "GRUB_RESTORE_FUNCTION_MISSING",
)

if apply_start >= 0 and restore_start >= 0:
    apply_block = source[
        apply_start:restore_start
    ]

    restore_body_start = source.find(
        "\n",
        restore_start,
    )

    require(
        restore_body_start >= 0,
        "GRUB_RESTORE_HEADER_TERMINATOR_MISSING",
    )

    if restore_body_start < 0:
        restore_end = len(source)
    else:
        restore_body_start += 1

        restore_end_match = re.search(
            r"(?m)^[A-Za-z_][A-Za-z0-9_]*"
            r"\(\)[ \t]*\{[ \t]*$",
            source[restore_body_start:],
        )

        restore_end = (
            restore_body_start
            + restore_end_match.start()
            if restore_end_match is not None
            else len(source)
        )

    restore_block = source[
        restore_start:restore_end
    ]

    require(
        "record_manifest_backup" in apply_block,
        "GRUB_APPLY_BACKUP_MAPPING_MISSING",
    )

    require(
        "atomic_write_command_output"
        in apply_block,
        "GRUB_APPLY_ATOMIC_WRITE_MISSING",
    )

    require(
        'restore_file_from_manifest "$grub_file"'
        in restore_block
        or '"${grub_file}" восстановлен из "${backup}"'
        in restore_block
        or 'cp "${backup}" "${grub_file}"'
        in restore_block,
        "GRUB_RESTORE_BACKUP_USE_MISSING",
    )

    require(
        "update-grub" in restore_block
        or "grub2-mkconfig" in restore_block,
        "GRUB_RESTORE_CONFIG_REGENERATION_MISSING",
    )

if errors:
    for error in errors:
        print(f"FAIL={error}")

    raise SystemExit(1)

print(
    "RESULT=GRUB_CLASSIFICATION_REGRESSION_OK"
)
PYGRUBCLASS

RC_GRUB_CLASSIFICATION=$?

printf 'RC_GRUB_CLASSIFICATION=%s\n' \
    "$RC_GRUB_CLASSIFICATION"

if (( RC_ARCHITECTURE_BASE == 0
      && RC_GRUB_CLASSIFICATION == 0 ))
then
    printf '%s\n' \
        'RESULT=ARCHITECTURE_WITH_GRUB_CLASSIFICATION_OK'
else
    printf '%s\n' \
        'RESULT=ARCHITECTURE_WITH_GRUB_CLASSIFICATION_FAILED'
fi

test "$RC_ARCHITECTURE_BASE" -eq 0 \
    && test "$RC_GRUB_CLASSIFICATION" -eq 0
# END GRUB CLASSIFICATION REGRESSION

# BEGIN REMAINING STATUS CLASSIFICATION REGRESSION
RC_PREVIOUS_ARCHITECTURE=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/securelinux-ng.sh" \
    <<'PYSTATUS'
import json
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(
    encoding="utf-8"
)

errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

inventory_match = re.search(
    r"(?ms)^[ \t]*fstec_items[ \t]*=[ \t]*\[\n"
    r"(?P<body>.*?)"
    r"^[ \t]*\][ \t]*$",
    source,
)

require(
    inventory_match is not None,
    "FSTEC_ITEMS_BLOCK_MISSING",
)

entries = []

if inventory_match is not None:
    for raw in re.findall(
        r"(?m)^[ \t]*(\{[^\n]+\}),?[ \t]*$",
        inventory_match.group("body"),
    ):
        entries.append(json.loads(raw))

done_items = {
    "2.1.1": (
        "empty_password_lock",
        "security-preserving-nonrestore",
    ),
    "corporate_faillock": (
        "pam_faillock",
        "managed-file",
    ),
    "corporate_password_policy": (
        "password_policy",
        "managed-file+runtime-state",
    ),
    "audit": (
        "auditd_rules",
        "managed-file+service+package",
    ),
    "fail2ban": (
        "fail2ban_ssh_jail",
        "managed-file+service+package",
    ),
    "account_audit": (
        "account_audit_report",
        "managed-file",
    ),
}

partial_modules = {
    "ufw": "irreversible",
    "tmp_tmpfs": "managed-file+reboot-required",
    "mount_hardening":
        "managed-file+reboot-required",
    "aide_init": "irreversible",
    "apparmor_enforce": "irreversible",
    "grub_init_on_alloc":
        "grub-backup+reboot-required",
    "grub_slab_nomerge":
        "grub-backup+reboot-required",
    "grub_iommu_hardening":
        "grub-backup+reboot-required",
    "grub_randomize_kstack_offset":
        "grub-backup+reboot-required",
    "grub_mitigations":
        "grub-backup+reboot-required",
    "grub_vsyscall_none":
        "grub-backup+reboot-required",
    "grub_tsx_off":
        "grub-backup+reboot-required",
    "kexec_load_disabled":
        "managed-file+reboot-required",
    "unprivileged_bpf_disabled":
        "managed-file+reboot-required",
    "yama_ptrace_scope":
        "managed-file+reboot-required",
}

for item, (module, restore) in done_items.items():
    matches = [
        entry
        for entry in entries
        if entry.get("item") == item
        and entry.get("module") == module
    ]

    require(
        len(matches) == 1,
        f"DONE_ITEM_MISSING_OR_DUPLICATED:{item}",
    )

    if len(matches) == 1:
        require(
            matches[0].get("status") == "done",
            f"DONE_STATUS_INVALID:{item}",
        )
        require(
            matches[0].get("restore") == restore,
            f"DONE_RESTORE_INVALID:{item}",
        )

partial_entries = [
    entry
    for entry in entries
    if entry.get("status") == "partial"
]

actual_partial = {
    entry.get("module"): entry.get("restore")
    for entry in partial_entries
}

require(
    actual_partial == partial_modules,
    "PARTIAL_MODULE_SET_INVALID:"
    + repr(actual_partial),
)

done_count = sum(
    entry.get("status") == "done"
    for entry in entries
)

partial_count = len(partial_entries)

implemented_count = sum(
    entry.get("status") != "not_applicable"
    for entry in entries
)

require(
    done_count == 44,
    f"DONE_COUNT_INVALID:{done_count}",
)

require(
    partial_count == 15,
    f"PARTIAL_COUNT_INVALID:{partial_count}",
)

require(
    implemented_count == 59,
    f"IMPLEMENTED_COUNT_INVALID:{implemented_count}",
)

require(
    "FSTEC_DONE_ITEMS=44" in source,
    "DONE_CONSTANT_INVALID",
)

require(
    "FSTEC_PARTIAL_ITEMS=15" in source,
    "PARTIAL_CONSTANT_INVALID",
)

# Unmanaged faillock stack is a safety abort before backup/mutation.
faillock_start = source.find(
    "apply_faillock_module() {"
)
faillock_end = source.find(
    "\nrestore_faillock_module() {",
    faillock_start,
)
faillock = source[faillock_start:faillock_end]

unmanaged_position = faillock.find(
    "partial or unmanaged PAM stack detected"
)
first_backup_position = faillock.find(
    "backup_file_checked"
)

require(
    unmanaged_position >= 0
    and first_backup_position >= 0
    and unmanaged_position < first_backup_position,
    "FAILLOCK_UNMANAGED_ABORT_ORDER_INVALID",
)

restore_requirements = {
    "restore_faillock_module": (
        'restore_file_from_manifest "$target"',
        '"$PAM_COMMON_AUTH_FILE"',
        '"$PAM_COMMON_ACCOUNT_FILE"',
    ),
    "restore_password_policy_module": (
        'restore_installed_packages "password-policy"',
        'restore_file_from_manifest "$PWQUALITY_CONF"',
        'restore_file_from_manifest "$LOGIN_DEFS"',
        'restore_password_aging_snapshots',
    ),
    "restore_auditd_module": (
        "restore_auditd_service_state",
        'restore_file_from_manifest',
        'restore_installed_packages "auditd"',
    ),
    "restore_fail2ban_module": (
        "restore_fail2ban_service_state",
        'restore_file_from_manifest',
        'restore_installed_packages "fail2ban"',
    ),
    "restore_account_audit_module": (
        'restore_file_from_manifest "$ACCOUNT_AUDIT_FILE"',
        "restore_has_created_file",
    ),
}

function_matches = list(
    re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)"
        r"\(\)[ \t]*\{[ \t]*$",
        source,
    )
)

function_blocks = {}

for index, match in enumerate(function_matches):
    end = (
        function_matches[index + 1].start()
        if index + 1 < len(function_matches)
        else len(source)
    )
    function_blocks[match.group(1)] = source[
        match.start():end
    ]

for name, markers in restore_requirements.items():
    block = function_blocks.get(name, "")

    require(
        bool(block),
        f"RESTORE_FUNCTION_MISSING:{name}",
    )

    for marker in markers:
        require(
            marker in block,
            f"RESTORE_MARKER_MISSING:{name}:{marker}",
        )

if errors:
    for error in errors:
        print(f"FAIL={error}")

    raise SystemExit(1)

print("RESULT=REMAINING_STATUS_REGRESSION_OK")
PYSTATUS

RC_REMAINING_STATUS=$?

printf 'RC_REMAINING_STATUS=%s\n' \
    "$RC_REMAINING_STATUS"

if (( RC_PREVIOUS_ARCHITECTURE == 0
      && RC_REMAINING_STATUS == 0 ))
then
    echo \
        'RESULT=ARCHITECTURE_WITH_ALL_CLASSIFICATIONS_OK'
else
    echo \
        'RESULT=ARCHITECTURE_WITH_ALL_CLASSIFICATIONS_FAILED'
fi

test "$RC_PREVIOUS_ARCHITECTURE" -eq 0 \
    && test "$RC_REMAINING_STATUS" -eq 0
# END REMAINING STATUS CLASSIFICATION REGRESSION

# BEGIN PARTIAL DOCUMENTATION REGRESSION
RC_PREVIOUS_CLASSIFICATIONS=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/securelinux-ng.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/README.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/compatibility.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md" \
    <<'PYPARTIALDOC'
import json
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(
    encoding="utf-8"
)
readme = Path(sys.argv[2]).read_text(
    encoding="utf-8"
)
compatibility = Path(sys.argv[3]).read_text(
    encoding="utf-8"
)
changelog = Path(sys.argv[4]).read_text(
    encoding="utf-8"
)

errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

inventory_match = re.search(
    r"(?ms)^[ \t]*fstec_items[ \t]*=[ \t]*\[\n"
    r"(?P<body>.*?)"
    r"^[ \t]*\][ \t]*$",
    source,
)

require(
    inventory_match is not None,
    "FSTEC_ITEMS_BLOCK_MISSING",
)

entries = []

if inventory_match is not None:
    for raw in re.findall(
        r"(?m)^[ \t]*(\{[^\n]+\}),?[ \t]*$",
        inventory_match.group("body"),
    ):
        entries.append(json.loads(raw))

partial_entries = [
    entry
    for entry in entries
    if entry.get("status") == "partial"
]

require(
    len(partial_entries) == 15,
    f"SOURCE_PARTIAL_COUNT_INVALID:{len(partial_entries)}",
)

require(
    sum(
        entry.get("status") == "done"
        for entry in entries
    ) == 44,
    "SOURCE_DONE_COUNT_INVALID",
)

require(
    "`done=44`, `partial=15`" in readme,
    "README_SUMMARY_COUNTERS_MISSING",
)

require(
    "`done=44`, `partial=15`" in compatibility,
    "COMPATIBILITY_SUMMARY_COUNTERS_MISSING",
)

for stale in (
    "`done=39`, `partial=20`",
    "статус done (полная restore): 39",
    "статус partial (reboot или ручные действия): 20",
):
    require(
        stale not in readme,
        f"README_STALE_COUNTER:{stale}",
    )
    require(
        stale not in compatibility,
        f"COMPATIBILITY_STALE_COUNTER:{stale}",
    )

table_match = re.search(
    r"(?ms)<!-- BEGIN PARTIAL STATUS TABLE -->\n"
    r"(?P<table>.*?)"
    r"<!-- END PARTIAL STATUS TABLE -->",
    readme,
)

require(
    table_match is not None,
    "README_PARTIAL_TABLE_MISSING",
)

table = (
    table_match.group("table")
    if table_match is not None
    else ""
)

rows = re.findall(
    r"(?m)^\|[ \t]*([0-9]+)[ \t]*\|.*$",
    table,
)

require(
    len(rows) == 15,
    f"README_PARTIAL_TABLE_ROW_COUNT:{len(rows)}",
)

require(
    rows == [str(number) for number in range(1, 16)],
    "README_PARTIAL_TABLE_NUMBERING_INVALID",
)

expected_modules = {
    "ufw",
    "tmp_tmpfs",
    "mount_hardening",
    "aide_init",
    "apparmor_enforce",
    "grub_init_on_alloc",
    "grub_slab_nomerge",
    "grub_iommu_hardening",
    "grub_randomize_kstack_offset",
    "grub_mitigations",
    "grub_vsyscall_none",
    "grub_tsx_off",
    "kexec_load_disabled",
    "unprivileged_bpf_disabled",
    "yama_ptrace_scope",
}

actual_partial_modules = {
    entry.get("module")
    for entry in partial_entries
}

require(
    actual_partial_modules == expected_modules,
    "SOURCE_PARTIAL_MODULE_SET_INVALID:"
    + repr(actual_partial_modules),
)

for module in sorted(expected_modules):
    require(
        f"`{module}`" in table,
        f"README_PARTIAL_MODULE_MISSING:{module}",
    )

require(
    "корпоративной парольной политики, `auditd` и `fail2ban`"
    in readme,
    "README_PACKAGE_RESTORE_DESCRIPTION_INVALID",
)

require(
    "password policy, auditd и fail2ban"
    in compatibility,
    "COMPATIBILITY_PACKAGE_RESTORE_DESCRIPTION_INVALID",
)

required_changelog_markers = (
    "таблица всех 15 мер со статусом `partial`",
    "`grub-backup+reboot-required`",
    "`implemented=59`, `done=44`, `partial=15`",
    "restore пакетов password policy, auditd и fail2ban",
)

for marker in required_changelog_markers:
    require(
        marker in changelog,
        f"CHANGELOG_MARKER_MISSING:{marker}",
    )

if errors:
    for error in errors:
        print(f"FAIL={error}")

    raise SystemExit(1)

print(
    "RESULT=PARTIAL_DOCUMENTATION_REGRESSION_OK"
)
PYPARTIALDOC

RC_PARTIAL_DOCUMENTATION=$?

printf 'RC_PARTIAL_DOCUMENTATION=%s\n' \
    "$RC_PARTIAL_DOCUMENTATION"

if (( RC_PREVIOUS_CLASSIFICATIONS == 0
      && RC_PARTIAL_DOCUMENTATION == 0 ))
then
    echo \
        'RESULT=ARCHITECTURE_AND_DOCUMENTATION_OK'
else
    echo \
        'RESULT=ARCHITECTURE_AND_DOCUMENTATION_FAILED'
fi

test "$RC_PREVIOUS_CLASSIFICATIONS" -eq 0 \
    && test "$RC_PARTIAL_DOCUMENTATION" -eq 0
# END PARTIAL DOCUMENTATION REGRESSION

# BEGIN SYMLINK DOCUMENTATION REGRESSION
RC_PRE_SYMLINK_DOCUMENTATION=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/securelinux-ng.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/README.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/architecture.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/restore-model.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/compatibility.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/smoke.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/symlink-target-regression.sh" \
    <<'PYSYMLINKDOC'
from pathlib import Path
import re
import sys

(
    source_path,
    readme_path,
    architecture_path,
    restore_path,
    compatibility_path,
    changelog_path,
    smoke_path,
    regression_path,
) = map(Path, sys.argv[1:])

source = source_path.read_text(encoding="utf-8")
readme = readme_path.read_text(encoding="utf-8")
architecture = architecture_path.read_text(encoding="utf-8")
restore = restore_path.read_text(encoding="utf-8")
compatibility = compatibility_path.read_text(encoding="utf-8")
changelog = changelog_path.read_text(encoding="utf-8")
smoke = smoke_path.read_text(encoding="utf-8")
regression = regression_path.read_text(encoding="utf-8")

errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

required_source = (
    "target = requested",
    "requested_is_symlink",
    "requested_is_regular",
    "follow_symlinks=False",
    'restore_file_from_manifest "$grub_file"',
    "atomic_write_command_output",
)

for marker in required_source:
    require(
        marker in source,
        f"SOURCE_MARKER_MISSING:{marker}",
    )

require(
    "resolve(strict=True)" not in source,
    "SOURCE_SYMLINK_RESOLVE_REMAINS",
)

required_readme = (
    "Symlink-safe транзакция файлов",
    "symlink-target-regression.sh",
)

for marker in required_readme:
    require(
        marker in readme,
        f"README_MARKER_MISSING:{marker}",
    )

required_architecture = (
    "`remove_manifest_backup()`",
    "`restore_manifest_has_path()`",
    "Для символьной ссылки helper намеренно не выполняет `resolve()`",
    "mode/uid/gid/xattrs наследуются исключительно от существующего обычного файла",
    "Это исключает создание world-writable managed-файла",
    "Та же модель применяется к GRUB и трём managed-файлам coredump",
)

for marker in required_architecture:
    require(
        marker in architecture,
        f"ARCHITECTURE_MARKER_MISSING:{marker}",
    )

required_restore = (
    "## Символьные ссылки в файловом restore",
    "`backup_file_checked()` выполняет `cp -a`",
    "`restore_file_from_manifest()` удаляет текущий объект",
    "относительную, абсолютную либо висячую ссылку",
    "Mode, владелец и xattrs файла-цели ссылки намеренно не наследуются",
)

for marker in required_restore:
    require(
        marker in restore,
        f"RESTORE_MODEL_MARKER_MISSING:{marker}",
    )

require(
    "apply заменяет саму ссылку обычным managed-файлом"
    in compatibility,
    "COMPATIBILITY_SYMLINK_DESCRIPTION_MISSING",
)

require(
    "не наследует mode/xattrs target ссылки"
    in compatibility,
    "COMPATIBILITY_SYMLINK_METADATA_POLICY_MISSING",
)

required_changelog = (
    "Добавлен `tests/symlink-target-regression.sh`",
    "Устранена потеря данных при работе с символьными ссылками",
    "Исправлено наследование ослабленных metadata через symlink-target",
    "GRUB переведён на общие symlink-safe",
    "Три managed-файла coredump переведены",
)

for marker in required_changelog:
    require(
        marker in changelog,
        f"CHANGELOG_MARKER_MISSING:{marker}",
    )

require(
    smoke.count(
        "bash tests/symlink-target-regression.sh &&"
    ) == 1,
    "SMOKE_SYMLINK_REGISTRATION_INVALID",
)

required_regression = (
    "RESULT=RELATIVE_SYMLINK_TRANSACTION_OK",
    "RESULT=ABSOLUTE_SYMLINK_TRANSACTION_OK",
    "RESULT=DANGLING_SYMLINK_TRANSACTION_OK",
    "RESULT=SYMLINK_DEFAULT_METADATA_REGRESSION_OK",
    "RC_SYMLINK_DEFAULT_METADATA",
    'restore_file_from_manifest "$managed"',
)

for marker in required_regression:
    require(
        marker in regression,
        f"SYMLINK_TEST_MARKER_MISSING:{marker}",
    )

if errors:
    for error in errors:
        print(f"FAIL={error}")

    raise SystemExit(1)

print("RESULT=SYMLINK_DOCUMENTATION_REGRESSION_OK")
PYSYMLINKDOC

RC_SYMLINK_DOCUMENTATION=$?

printf 'RC_SYMLINK_DOCUMENTATION=%s\n' \
    "$RC_SYMLINK_DOCUMENTATION"

if (( RC_PRE_SYMLINK_DOCUMENTATION == 0
      && RC_SYMLINK_DOCUMENTATION == 0 ))
then
    echo "RESULT=ARCHITECTURE_WITH_SYMLINK_DOCUMENTATION_OK"
else
    echo "RESULT=ARCHITECTURE_WITH_SYMLINK_DOCUMENTATION_FAILED"
fi

test "$RC_PRE_SYMLINK_DOCUMENTATION" -eq 0 \
    && test "$RC_SYMLINK_DOCUMENTATION" -eq 0
# END SYMLINK DOCUMENTATION REGRESSION

# BEGIN STATE DIR SECURITY DOCUMENTATION REGRESSION
RC_PRE_STATE_DIR_DOCUMENTATION=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/securelinux-ng.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/README.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/architecture.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/restore-model.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/smoke.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/state-dir-security-regression.sh" \
    <<'PYSTATEDIRDOC'
from pathlib import Path
import sys

(
    source_path,
    readme_path,
    architecture_path,
    restore_path,
    changelog_path,
    smoke_path,
    regression_path,
) = map(Path, sys.argv[1:])

source = source_path.read_text(encoding="utf-8")
readme = readme_path.read_text(encoding="utf-8")
architecture = architecture_path.read_text(encoding="utf-8")
restore = restore_path.read_text(encoding="utf-8")
changelog = changelog_path.read_text(encoding="utf-8")
smoke = smoke_path.read_text(encoding="utf-8")
regression = regression_path.read_text(encoding="utf-8")

errors = []


def require(condition, message):
    if not condition:
        errors.append(message)

for marker in (
    "secure_state_dir()",
    "os.O_NOFOLLOW",
    "os.fchmod(fd, 0o700)",
    "opened.st_uid != expected_uid",
):
    require(marker in source, f"SOURCE_MARKER_MISSING:{marker}")

for marker in (
    "Защита `STATE_DIR`",
    "O_NOFOLLOW",
    "mode `0700`",
):
    require(marker in readme, f"README_MARKER_MISSING:{marker}")

require(
    "`secure_state_dir()` создаёт/открывает `STATE_DIR`" in architecture,
    "ARCHITECTURE_STATE_DIR_DESCRIPTION_MISSING",
)
require(
    "## Защита каталога состояния" in restore,
    "RESTORE_MODEL_STATE_DIR_SECTION_MISSING",
)
require(
    "Добавлен `tests/state-dir-security-regression.sh`" in changelog,
    "CHANGELOG_STATE_DIR_TEST_MISSING",
)
require(
    smoke.count("bash tests/state-dir-security-regression.sh &&") == 1,
    "SMOKE_STATE_DIR_REGISTRATION_INVALID",
)
for marker in (
    "RESULT=STATE_DIR_SYMLINK_REJECTED_OK",
    "RESULT=STATE_DIR_OWNER_MISMATCH_REJECTED_OK",
    "RESULT=STATE_DIR_CHECK_FALLBACK_OK",
    "RESULT=STATE_DIR_APPLY_REJECTED_OK",
):
    require(marker in regression, f"STATE_DIR_TEST_MARKER_MISSING:{marker}")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=STATE_DIR_DOCUMENTATION_REGRESSION_OK")
PYSTATEDIRDOC

RC_STATE_DIR_DOCUMENTATION=$?

printf 'RC_STATE_DIR_DOCUMENTATION=%s\n' \
    "$RC_STATE_DIR_DOCUMENTATION"

if (( RC_PRE_STATE_DIR_DOCUMENTATION == 0
      && RC_STATE_DIR_DOCUMENTATION == 0 ))
then
    echo "RESULT=ARCHITECTURE_WITH_STATE_DIR_DOCUMENTATION_OK"
else
    echo "RESULT=ARCHITECTURE_WITH_STATE_DIR_DOCUMENTATION_FAILED"
fi

test "$RC_PRE_STATE_DIR_DOCUMENTATION" -eq 0 \
    && test "$RC_STATE_DIR_DOCUMENTATION" -eq 0
# END STATE DIR SECURITY DOCUMENTATION REGRESSION

# BEGIN PACKAGE CRASH DOCUMENTATION REGRESSION
RC_PRE_PACKAGE_CRASH_DOCUMENTATION=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/securelinux-ng.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/README.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/architecture.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/restore-model.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/smoke.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/package-crash-regression.sh" \
    <<'PYPACKAGEDOC'
from pathlib import Path
import re
import sys

(
    source_path,
    readme_path,
    architecture_path,
    restore_path,
    changelog_path,
    smoke_path,
    regression_path,
) = map(Path, sys.argv[1:])

source = source_path.read_text(encoding="utf-8")
readme = readme_path.read_text(encoding="utf-8")
architecture = architecture_path.read_text(encoding="utf-8")
restore = restore_path.read_text(encoding="utf-8")
changelog = changelog_path.read_text(encoding="utf-8")
smoke = smoke_path.read_text(encoding="utf-8")
regression = regression_path.read_text(encoding="utf-8")

errors = []


def require(condition, message):
    if not condition:
        errors.append(message)


for marker in (
    '"pending_package_transactions": []',
    "record_manifest_pending_package_transaction()",
    "commit_manifest_package_transaction()",
    "install_packages_transactionally()",
    "collect_manifest_package_candidates()",
):
    require(marker in source, f"SOURCE_MARKER_MISSING:{marker}")

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

require(
    apt_install_functions == ["install_packages_transactionally"],
    f"UNJOURNALED_APT_INSTALL:{apt_install_functions!r}",
)

for marker in (
    "pending_package_transactions",
    "При аварии restore вычисляет разницу",
):
    require(marker in readme, f"README_MARKER_MISSING:{marker}")

for marker in (
    "Durable package intent",
    "Crash-consistent package journal",
    "двухфазный журнал",
):
    require(marker in architecture, f"ARCHITECTURE_MARKER_MISSING:{marker}")

for marker in (
    "### Пакетные транзакции",
    "current − before",
    "находящийся вне каталога manifest snapshot",
):
    require(marker in restore, f"RESTORE_MARKER_MISSING:{marker}")

require(
    "Добавлен `tests/package-crash-regression.sh`" in changelog,
    "CHANGELOG_PACKAGE_TEST_MISSING",
)
require(
    smoke.count("bash tests/package-crash-regression.sh &&") == 1,
    "SMOKE_PACKAGE_TEST_REGISTRATION_INVALID",
)

for marker in (
    "RESULT=PACKAGE_JOURNAL_COMMIT_OK",
    "RESULT=PACKAGE_PENDING_RESTORE_OK",
    "RESULT=PACKAGE_FAILED_INSTALL_TRACKED_OK",
    "RESULT=PACKAGE_PENDING_FAILURE_BLOCKS_INSTALL_OK",
):
    require(marker in regression, f"PACKAGE_TEST_MARKER_MISSING:{marker}")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=PACKAGE_CRASH_DOCUMENTATION_REGRESSION_OK")
PYPACKAGEDOC

RC_PACKAGE_CRASH_DOCUMENTATION=$?

printf 'RC_PACKAGE_CRASH_DOCUMENTATION=%s\n' \
    "$RC_PACKAGE_CRASH_DOCUMENTATION"

if (( RC_PRE_PACKAGE_CRASH_DOCUMENTATION == 0
      && RC_PACKAGE_CRASH_DOCUMENTATION == 0 ))
then
    echo "RESULT=ARCHITECTURE_WITH_PACKAGE_CRASH_DOCUMENTATION_OK"
else
    echo "RESULT=ARCHITECTURE_WITH_PACKAGE_CRASH_DOCUMENTATION_FAILED"
fi

test "$RC_PRE_PACKAGE_CRASH_DOCUMENTATION" -eq 0 \
    && test "$RC_PACKAGE_CRASH_DOCUMENTATION" -eq 0
# END PACKAGE CRASH DOCUMENTATION REGRESSION

# BEGIN SERVICE STATE CRASH DOCUMENTATION REGRESSION
RC_PRE_SERVICE_STATE_DOCUMENTATION=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/securelinux-ng.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/README.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/architecture.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/restore-model.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/smoke.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/service-state-crash-regression.sh" \
    <<'PYSERVICEDOC'
from pathlib import Path
import sys

(
    source_path,
    readme_path,
    architecture_path,
    restore_path,
    changelog_path,
    smoke_path,
    regression_path,
) = map(Path, sys.argv[1:])

source = source_path.read_text(encoding="utf-8")
readme = readme_path.read_text(encoding="utf-8")
architecture = architecture_path.read_text(encoding="utf-8")
restore = restore_path.read_text(encoding="utf-8")
changelog = changelog_path.read_text(encoding="utf-8")
smoke = smoke_path.read_text(encoding="utf-8")
regression = regression_path.read_text(encoding="utf-8")

errors = []


def require(condition, message):
    if not condition:
        errors.append(message)


for marker in (
    '"pending_service_transactions": []',
    '"service_transactions": []',
    "record_manifest_pending_service_transaction()",
    "commit_manifest_service_transaction()",
    "restore_systemd_service_transaction()",
    "^[A-Za-z0-9_.@:-]+[.]service$",
):
    require(marker in source, f"SOURCE_MARKER_MISSING:{marker}")

for marker in (
    "Crash-consistent systemd service-state",
    "pending_service_transactions",
):
    require(marker in readme, f"README_MARKER_MISSING:{marker}")

for marker in (
    "Durable service-state intent",
    "pending_service_transactions → service_transactions",
):
    require(marker in architecture, f"ARCHITECTURE_MARKER_MISSING:{marker}")

for marker in (
    "Systemd service-state transactions",
    "enable-now",
    "disable-now",
):
    require(marker in restore, f"RESTORE_MARKER_MISSING:{marker}")

require(
    "Добавлен `tests/service-state-crash-regression.sh`" in changelog,
    "CHANGELOG_SERVICE_TEST_MISSING",
)
require(
    smoke.count("bash tests/service-state-crash-regression.sh &&") == 1,
    "SMOKE_SERVICE_TEST_REGISTRATION_INVALID",
)

for marker in (
    "RESULT=SERVICE_STATE_CRASH_STATIC_REGRESSION_OK",
    "RESULT=SERVICE_STATE_CRASH_DYNAMIC_REGRESSION_OK",
    "RESULT=SERVICE_STATE_CRASH_REGRESSION_OK",
):
    require(marker in regression, f"SERVICE_TEST_MARKER_MISSING:{marker}")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=SERVICE_STATE_DOCUMENTATION_REGRESSION_OK")
PYSERVICEDOC

RC_SERVICE_STATE_DOCUMENTATION=$?

printf 'RC_SERVICE_STATE_DOCUMENTATION=%s\n' \
    "$RC_SERVICE_STATE_DOCUMENTATION"

if (( RC_PRE_SERVICE_STATE_DOCUMENTATION == 0
      && RC_SERVICE_STATE_DOCUMENTATION == 0 ))
then
    echo "RESULT=ARCHITECTURE_WITH_SERVICE_STATE_DOCUMENTATION_OK"
else
    echo "RESULT=ARCHITECTURE_WITH_SERVICE_STATE_DOCUMENTATION_FAILED"
fi

test "$RC_PRE_SERVICE_STATE_DOCUMENTATION" -eq 0 \
    && test "$RC_SERVICE_STATE_DOCUMENTATION" -eq 0
# END SERVICE STATE CRASH DOCUMENTATION REGRESSION


# BEGIN MANIFEST RESOLUTION DOCUMENTATION REGRESSION
RC_PRE_MANIFEST_RESOLUTION_DOCUMENTATION=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/securelinux-ng.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/README.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/architecture.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/restore-model.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/smoke.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/manifest-resolution-regression.sh" \
    <<'PYMANIFESTRESOLUTIONDOC'
from pathlib import Path
import sys

(
    source_path,
    readme_path,
    architecture_path,
    restore_path,
    changelog_path,
    smoke_path,
    regression_path,
) = map(Path, sys.argv[1:])

source = source_path.read_text(encoding="utf-8")
readme = readme_path.read_text(encoding="utf-8")
architecture = architecture_path.read_text(encoding="utf-8")
restore = restore_path.read_text(encoding="utf-8")
changelog = changelog_path.read_text(encoding="utf-8")
smoke = smoke_path.read_text(encoding="utf-8")
regression = regression_path.read_text(encoding="utf-8")

errors = []


def require(condition, message):
    if not condition:
        errors.append(message)


for marker in (
    'archive_pattern = re.compile(',
    'r"^.+[.]json[.]bak-([0-9]{8}-[0-9]{6})$"',
    'if item.is_symlink() or not item.is_file():',
    'print(max(archives)[2])',
):
    require(marker in source, f"SOURCE_MARKER_MISSING:{marker}")

require(
    "MANIFEST --> MODULES" not in architecture,
    "ARCHITECTURE_DIRECT_APPLY_TO_RESTORE_ARROW_PRESENT",
)
require(
    'MANIFEST -. "используется последующим --restore" .-> RESOLVE' in architecture,
    "ARCHITECTURE_DEFERRED_RESTORE_ARROW_MISSING",
)
require(
    "последний *.json.bak-TIMESTAMP" in architecture,
    "ARCHITECTURE_ARCHIVE_FALLBACK_MISSING",
)

for marker in (
    "последний обычный файл `*.json.bak-yyyymmdd-hhmmss`",
    "symlink-кандидаты",
):
    require(marker in readme.lower(), f"README_MARKER_MISSING:{marker}")

for marker in (
    "*.json.bak-YYYYMMDD-HHMMSS",
    "archive fallback",
    "Symlink-кандидаты",
):
    require(marker in restore, f"RESTORE_MARKER_MISSING:{marker}")

require(
    "Добавлен `tests/manifest-resolution-regression.sh`" in changelog,
    "CHANGELOG_MANIFEST_RESOLUTION_TEST_MISSING",
)
require(
    smoke.count("bash tests/manifest-resolution-regression.sh &&") == 1,
    "SMOKE_MANIFEST_RESOLUTION_REGISTRATION_INVALID",
)

for marker in (
    "RESULT=MANIFEST_RESOLUTION_STATIC_REGRESSION_OK",
    "RESULT=MANIFEST_RESOLUTION_REGRESSION_OK",
):
    require(marker in regression, f"MANIFEST_TEST_MARKER_MISSING:{marker}")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=MANIFEST_RESOLUTION_DOCUMENTATION_REGRESSION_OK")
PYMANIFESTRESOLUTIONDOC

RC_MANIFEST_RESOLUTION_DOCUMENTATION=$?

printf 'RC_MANIFEST_RESOLUTION_DOCUMENTATION=%s\n' \
    "$RC_MANIFEST_RESOLUTION_DOCUMENTATION"

if (( RC_PRE_MANIFEST_RESOLUTION_DOCUMENTATION == 0
      && RC_MANIFEST_RESOLUTION_DOCUMENTATION == 0 ))
then
    echo "RESULT=ARCHITECTURE_WITH_MANIFEST_RESOLUTION_DOCUMENTATION_OK"
else
    echo "RESULT=ARCHITECTURE_WITH_MANIFEST_RESOLUTION_DOCUMENTATION_FAILED"
fi

test "$RC_PRE_MANIFEST_RESOLUTION_DOCUMENTATION" -eq 0 \
    && test "$RC_MANIFEST_RESOLUTION_DOCUMENTATION" -eq 0
# END MANIFEST RESOLUTION DOCUMENTATION REGRESSION


# BEGIN HARDLINK SAFETY DOCUMENTATION REGRESSION
RC_PRE_HARDLINK_DOCUMENTATION=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/securelinux-ng.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/README.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/architecture.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/restore-model.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/smoke.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/hardlink-safety-regression.sh" \
    <<'PYHARDLINKDOC'
from pathlib import Path
import sys

(
    source_path,
    readme_path,
    architecture_path,
    restore_path,
    changelog_path,
    smoke_path,
    regression_path,
) = map(Path, sys.argv[1:])

source = source_path.read_text(encoding="utf-8")
readme = readme_path.read_text(encoding="utf-8")
architecture = architecture_path.read_text(encoding="utf-8")
restore = restore_path.read_text(encoding="utf-8")
changelog = changelog_path.read_text(encoding="utf-8")
smoke = smoke_path.read_text(encoding="utf-8")
regression = regression_path.read_text(encoding="utf-8")

errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

for marker in (
    "validate_managed_file_hardlinks()",
    "metadata.st_nlink > 1",
    "requested_metadata.st_nlink > 1",
    '"restore backup"',
    '"restore target"',
    '"restore created-file target"',
):
    require(marker in source, f"SOURCE_MARKER_MISSING:{marker}")

for marker in (
    "Hardlink-safe managed files",
    "st_nlink > 1",
):
    require(marker in readme, f"README_MARKER_MISSING:{marker}")

for marker in (
    "Hardlink safety boundary",
    "не сохраняет множество имён одного inode",
):
    require(marker in architecture, f"ARCHITECTURE_MARKER_MISSING:{marker}")

for marker in (
    "Обычные файлы с несколькими hardlink-именами",
    "restore завершается с RC=1",
):
    require(marker in restore, f"RESTORE_MARKER_MISSING:{marker}")

require(
    "Добавлен `tests/hardlink-safety-regression.sh`" in changelog,
    "CHANGELOG_HARDLINK_TEST_MISSING",
)
require(
    smoke.count("bash tests/hardlink-safety-regression.sh &&") == 1,
    "SMOKE_HARDLINK_TEST_REGISTRATION_INVALID",
)

for marker in (
    "RESULT=HARDLINK_SAFETY_STATIC_REGRESSION_OK",
    "RESULT=HARDLINK_SAFETY_REGRESSION_OK",
):
    require(marker in regression, f"HARDLINK_TEST_MARKER_MISSING:{marker}")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=HARDLINK_SAFETY_DOCUMENTATION_REGRESSION_OK")
PYHARDLINKDOC

RC_HARDLINK_DOCUMENTATION=$?

printf 'RC_HARDLINK_DOCUMENTATION=%s\n' \
    "$RC_HARDLINK_DOCUMENTATION"

if (( RC_PRE_HARDLINK_DOCUMENTATION == 0
      && RC_HARDLINK_DOCUMENTATION == 0 ))
then
    echo "RESULT=ARCHITECTURE_WITH_HARDLINK_DOCUMENTATION_OK"
else
    echo "RESULT=ARCHITECTURE_WITH_HARDLINK_DOCUMENTATION_FAILED"
fi

test "$RC_PRE_HARDLINK_DOCUMENTATION" -eq 0 \
    && test "$RC_HARDLINK_DOCUMENTATION" -eq 0
# END HARDLINK SAFETY DOCUMENTATION REGRESSION


# BEGIN EXTENDED METADATA DOCUMENTATION REGRESSION
RC_PRE_EXTENDED_METADATA_DOCUMENTATION=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/securelinux-ng.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/README.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/architecture.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/restore-model.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/smoke.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/extended-metadata-regression.sh" \
    <<'PYEXTENDEDMETADATADOC'
from pathlib import Path
import sys

(
    source_path,
    readme_path,
    architecture_path,
    restore_path,
    changelog_path,
    smoke_path,
    regression_path,
) = map(Path, sys.argv[1:])

source = source_path.read_text(encoding="utf-8")
readme = readme_path.read_text(encoding="utf-8")
architecture = architecture_path.read_text(encoding="utf-8")
restore = restore_path.read_text(encoding="utf-8")
changelog = changelog_path.read_text(encoding="utf-8")
smoke = smoke_path.read_text(encoding="utf-8")
regression = regression_path.read_text(encoding="utf-8")

errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

atomic_start = source.find("atomic_write_command_output() {")
atomic_end = source.find(
    "\nacquire_run_lock() {",
    atomic_start,
)

require(
    atomic_start >= 0 and atomic_end > atomic_start,
    "ATOMIC_WRITE_FUNCTION_BOUNDARY_MISSING",
)

atomic = (
    source[atomic_start:atomic_end]
    if atomic_start >= 0 and atomic_end > atomic_start
    else ""
)

for marker in (
    "import errno",
    "requested_metadata = target.lstat()",
    "requested_is_symlink = (",
    "requested_is_regular = (",
    "if requested_is_regular:",
    "xattr_names = os.listxattr(",
    "except OSError as error:",
    "unsupported_xattr_errors = {",
    "errno.ENOTSUP",
    "EOPNOTSUPP",
    "ENOSYS",
    "if error.errno not in unsupported_xattr_errors:",
    "xattr_names = []",
    "for name in xattr_names:",
    "xattrs[name] = os.getxattr(",
    "follow_symlinks=False",
    "os.setxattr(fd, name, value)",
    "os.getxattr(fd, name) != value",
    "atomic write metadata xattr verification failed",
):
    require(marker in atomic, f"ATOMIC_SOURCE_MARKER_MISSING:{marker}")

for forbidden in (
    "target.exists()",
    "target.stat()",
    "for name in os.listxattr(target):",
    "xattrs[name] = os.getxattr(target, name)",
):
    require(
        forbidden not in atomic,
        f"ATOMIC_SYMLINK_FOLLOWING_MARKER_PRESENT:{forbidden}",
    )

for marker in (
    "Расширенная metadata managed-файлов",
    "POSIX ACL, file capabilities и security labels",
    "ENOTSUP",
):
    require(marker in readme, f"README_MARKER_MISSING:{marker}")

for marker in (
    "Extended metadata preservation",
    "os.listxattr()",
    "ENOTSUP",
    "EACCES",
    "fail-before-replace",
):
    require(marker in architecture, f"ARCHITECTURE_MARKER_MISSING:{marker}")

for marker in (
    "ACL, xattrs, capabilities и security labels",
    "исходный объект остаётся неизменным",
):
    require(marker in restore, f"RESTORE_MARKER_MISSING:{marker}")

require(
    "Добавлен `tests/extended-metadata-regression.sh`" in changelog,
    "CHANGELOG_EXTENDED_METADATA_TEST_MISSING",
)
require(
    smoke.count("bash tests/extended-metadata-regression.sh &&") == 1,
    "SMOKE_EXTENDED_METADATA_REGISTRATION_INVALID",
)

for marker in (
    "RESULT=EXTENDED_METADATA_STATIC_REGRESSION_OK",
    "RESULT=XATTR_UNSUPPORTED_FALLBACK_OK",
    "RESULT=XATTR_UNEXPECTED_ERROR_REJECTED_OK",
    "RESULT=EXTENDED_METADATA_REGRESSION_OK",
):
    require(marker in regression, f"EXTENDED_METADATA_TEST_MARKER_MISSING:{marker}")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=EXTENDED_METADATA_DOCUMENTATION_REGRESSION_OK")
PYEXTENDEDMETADATADOC

RC_EXTENDED_METADATA_DOCUMENTATION=$?

printf 'RC_EXTENDED_METADATA_DOCUMENTATION=%s\n' \
    "$RC_EXTENDED_METADATA_DOCUMENTATION"

if (( RC_PRE_EXTENDED_METADATA_DOCUMENTATION == 0
      && RC_EXTENDED_METADATA_DOCUMENTATION == 0 ))
then
    echo "RESULT=ARCHITECTURE_WITH_EXTENDED_METADATA_DOCUMENTATION_OK"
else
    echo "RESULT=ARCHITECTURE_WITH_EXTENDED_METADATA_DOCUMENTATION_FAILED"
fi

test "$RC_PRE_EXTENDED_METADATA_DOCUMENTATION" -eq 0 \
    && test "$RC_EXTENDED_METADATA_DOCUMENTATION" -eq 0
# END EXTENDED METADATA DOCUMENTATION REGRESSION

# BEGIN PORTABLE SHA256 DOCUMENTATION REGRESSION
RC_PRE_PORTABLE_SHA256_DOCUMENTATION=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/write-sha256.py" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/README.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/architecture.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/smoke.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/portable-sha256-regression.sh" \
    <<'PYPORTABLESHA256DOC'
from pathlib import Path
import sys

(
    tool_path,
    readme_path,
    architecture_path,
    changelog_path,
    smoke_path,
    regression_path,
) = map(Path, sys.argv[1:])

tool = tool_path.read_text(encoding="utf-8")
readme = readme_path.read_text(encoding="utf-8")
architecture = architecture_path.read_text(encoding="utf-8")
changelog = changelog_path.read_text(encoding="utf-8")
smoke = smoke_path.read_text(encoding="utf-8")
regression = regression_path.read_text(encoding="utf-8")

errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

for marker in (
    "path.name",
    "duplicate basenames are not portable",
    "refusing symlink input",
    "refusing symlink output",
    "os.replace(temporary_name, path)",
    "os.fsync(directory_fd)",
):
    require(marker in tool, f"TOOL_MARKER_MISSING:{marker}")

for marker in (
    "Переносимая контрольная сумма релиза",
    "tools/write-sha256.py",
    "sha256sum -c",
    "Абсолютный путь машины сборки",
):
    require(marker in readme, f"README_MARKER_MISSING:{marker}")

for marker in (
    "Portable release checksum",
    "Path.name",
    "одинаковые basename отклоняются",
):
    require(marker in architecture, f"ARCHITECTURE_MARKER_MISSING:{marker}")

require(
    "Добавлен `tests/portable-sha256-regression.sh`" in changelog,
    "CHANGELOG_PORTABLE_SHA256_TEST_MISSING",
)
require(
    smoke.count("bash tests/portable-sha256-regression.sh &&") == 1,
    "SMOKE_PORTABLE_SHA256_REGISTRATION_INVALID",
)

for marker in (
    "RESULT=PORTABLE_SHA256_STATIC_REGRESSION_OK",
    "RESULT=PORTABLE_SHA256_REGRESSION_OK",
):
    require(marker in regression, f"PORTABLE_SHA256_TEST_MARKER_MISSING:{marker}")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=PORTABLE_SHA256_DOCUMENTATION_REGRESSION_OK")
PYPORTABLESHA256DOC

RC_PORTABLE_SHA256_DOCUMENTATION=$?

printf 'RC_PORTABLE_SHA256_DOCUMENTATION=%s\n' \
    "$RC_PORTABLE_SHA256_DOCUMENTATION"

if (( RC_PRE_PORTABLE_SHA256_DOCUMENTATION == 0
      && RC_PORTABLE_SHA256_DOCUMENTATION == 0 ))
then
    echo "RESULT=ARCHITECTURE_WITH_PORTABLE_SHA256_DOCUMENTATION_OK"
else
    echo "RESULT=ARCHITECTURE_WITH_PORTABLE_SHA256_DOCUMENTATION_FAILED"
fi

test "$RC_PRE_PORTABLE_SHA256_DOCUMENTATION" -eq 0 \
    && test "$RC_PORTABLE_SHA256_DOCUMENTATION" -eq 0
# END PORTABLE SHA256 DOCUMENTATION REGRESSION

# BEGIN FSTEC MAPPING DOCUMENTATION REGRESSION
RC_PRE_FSTEC_MAPPING_DOCUMENTATION=$?

python3 - \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/README.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docs/fstec-mapping.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/CHANGELOG.md" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/smoke.sh" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/fstec-mapping-regression.sh" \
    <<'PYFSTECMAPPINGDOC'
from pathlib import Path
import sys

(
    readme_path,
    mapping_path,
    changelog_path,
    smoke_path,
    regression_path,
) = map(Path, sys.argv[1:])

readme = readme_path.read_text(encoding="utf-8")
mapping = mapping_path.read_text(encoding="utf-8")
changelog = changelog_path.read_text(encoding="utf-8")
smoke = smoke_path.read_text(encoding="utf-8")
regression = regression_path.read_text(encoding="utf-8")

errors = []


def require(condition, message):
    if not condition:
        errors.append(message)


require(
    "fstec-mapping-regression.sh" in readme,
    "README_FSTEC_MAPPING_TEST_MISSING",
)
require(
    "Общий реестр: `done=44`, `partial=15`." in mapping,
    "MAPPING_FINAL_COUNTS_MISSING",
)
require(
    "Синхронизирована `docs/fstec-mapping.md`" in changelog,
    "CHANGELOG_FSTEC_MAPPING_SYNC_MISSING",
)
require(
    smoke.count("bash tests/fstec-mapping-regression.sh &&") == 1,
    "SMOKE_FSTEC_MAPPING_REGISTRATION_INVALID",
)
for marker in (
    "RESULT=FSTEC_MAPPING_SOURCE_SYNC_OK",
    "RESULT=FSTEC_MAPPING_SUMMARY_OK",
    "RESULT=FSTEC_MAPPING_REGRESSION_OK",
):
    require(marker in regression, f"FSTEC_MAPPING_TEST_MARKER_MISSING:{marker}")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=FSTEC_MAPPING_DOCUMENTATION_REGRESSION_OK")
PYFSTECMAPPINGDOC

RC_FSTEC_MAPPING_DOCUMENTATION=$?

printf 'RC_FSTEC_MAPPING_DOCUMENTATION=%s\n' \
    "$RC_FSTEC_MAPPING_DOCUMENTATION"

if (( RC_PRE_FSTEC_MAPPING_DOCUMENTATION == 0
      && RC_FSTEC_MAPPING_DOCUMENTATION == 0 ))
then
    echo "RESULT=ARCHITECTURE_WITH_FSTEC_MAPPING_DOCUMENTATION_OK"
else
    echo "RESULT=ARCHITECTURE_WITH_FSTEC_MAPPING_DOCUMENTATION_FAILED"
fi

test "$RC_PRE_FSTEC_MAPPING_DOCUMENTATION" -eq 0 \
    && test "$RC_FSTEC_MAPPING_DOCUMENTATION" -eq 0
# END FSTEC MAPPING DOCUMENTATION REGRESSION
