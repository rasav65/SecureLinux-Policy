#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT/securelinux-ng.sh" <<'PYTEST'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
errors = []

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
            errors.append(f"{message}:MISSING:{marker}")
            return
        cursor = position + len(marker)


def require_regex_order(text, patterns, message):
    normalized = re.sub(
        r"\\\n[ \t]*",
        " ",
        text,
    )
    cursor = 0

    for label, pattern in patterns:
        match = re.search(
            pattern,
            normalized[cursor:],
            re.DOTALL,
        )

        if match is None:
            errors.append(
                f"{message}:MISSING:{label}"
            )
            return

        cursor += match.end()

forbidden = (
    'cp -a "$fstab" "$bak"',
    'cp -a "$PWQUALITY_CONF" "$pwquality_backup_before_dependencies"',
    'cp -a "$pwhistory_file" "$bak_ph"',
    'cp -a "$LOGIN_DEFS" "$bak2"',
)

for marker in forbidden:
    require(
        marker not in source,
        f"UNCHECKED_BACKUP_REMAINS:{marker}",
    )

mount = function_text("apply_mount_hardening_module")
require_order(
    mount,
    (
        'backup_file_checked "$fstab" "$bak" "mount hardening fstab"',
        'add_skipped "mount hardening apply skipped: fstab backup failed"',
        "return 0",
        'if ! record_manifest_backup',
        'python3 - "$fstab"',
    ),
    "MOUNT_HARDENING_BACKUP_GUARD_BROKEN",
)

tmp_tmpfs = function_text("apply_tmp_tmpfs_module")
require_order(
    tmp_tmpfs,
    (
        'backup_file_checked "$fstab" "$bak" "/tmp tmpfs fstab"',
        'add_skipped "/tmp tmpfs apply skipped: fstab backup failed"',
        "return 0",
        'if ! record_manifest_backup',
        'python3 - "$fstab"',
    ),
    "TMP_TMPFS_BACKUP_GUARD_BROKEN",
)

password = function_text("apply_password_policy_module")

require_order(
    password,
    (
        '"CORP-PASSWORD pwquality.conf pre-install"',
        'add_error "CORP-PASSWORD зависимости не устанавливались: backup pwquality.conf failed"',
        "return 1",
        'record_manifest_backup',
        'log "[i]     pwquality/Cracklib:',
    ),
    "PWQUALITY_PREINSTALL_BACKUP_GUARD_BROKEN",
)

require_order(
    password,
    (
        '"CORP-PASSWORD common-password"',
        'add_error "CORP-PASSWORD common-password не изменён: backup failed"',
        "return 1",
        'record_manifest_backup "$pwhistory_file" "$bak_ph"',
        'normalize_common_password_stack',
    ),
    "COMMON_PASSWORD_BACKUP_GUARD_BROKEN",
)

require_order(
    password,
    (
        '"CORP-PASSWORD login.defs"',
        'add_error "CORP-PASSWORD login.defs не изменён: backup failed"',
        "return 1",
        'record_manifest_backup "$LOGIN_DEFS" "$bak2"',
        'python3 - "$LOGIN_DEFS"',
    ),
    "LOGIN_DEFS_BACKUP_GUARD_BROKEN",
)

fs_critical = function_text(
    "apply_fs_critical_file_one"
)

require_regex_order(
    fs_critical,
    (
        (
            "manifest mapping guard",
            r'if\s+!\s+record_manifest_backup\s+'
            r'"\$target"\s+"\$backup_path";\s*then',
        ),
        (
            "unregistered snapshot cleanup",
            r'rm\s+-f\s+--\s+"\$backup_path"',
        ),
        (
            "failure return",
            r'return\s+1',
        ),
        (
            "filesystem mutation",
            r'fs_apply_expected_mode\s+"\$target"',
        ),
    ),
    "FS_CRITICAL_MANIFEST_CLEANUP_BROKEN",
)

cron_target = function_text(
    "apply_cron_target_one"
)

require_regex_order(
    cron_target,
    (
        (
            "manifest mapping guard",
            r'if\s+!\s+record_manifest_backup\s+'
            r'"\$path"\s+"\$backup_path";\s*then',
        ),
        (
            "unregistered snapshot cleanup",
            r'rm\s+-f\s+--\s+"\$backup_path"',
        ),
        (
            "failure return",
            r'return\s+1',
        ),
        (
            "cron metadata mutation",
            r'chown\s+'
            r'"\$\{exp_owner\}:\$\{exp_group\}"\s+'
            r'"\$path"',
        ),
    ),
    "CRON_TARGET_MANIFEST_CLEANUP_BROKEN",
)

systemd_unit = function_text(
    "apply_systemd_unit_one"
)

require_regex_order(
    systemd_unit,
    (
        (
            "manifest mapping guard",
            r'if\s+!\s+record_manifest_backup\s+'
            r'"\$path"\s+"\$backup_path";\s*then',
        ),
        (
            "unregistered snapshot cleanup",
            r'rm\s+-f\s+--\s+"\$backup_path"',
        ),
        (
            "failure return",
            r'return\s+1',
        ),
        (
            "systemd metadata mutation",
            r'chown\s+root:root\s+"\$path"',
        ),
    ),
    "SYSTEMD_UNIT_MANIFEST_CLEANUP_BROKEN",
)

pam_wheel = function_text(
    "apply_pam_wheel_module"
)

require_regex_order(
    pam_wheel,
    (
        (
            "manifest mapping guard",
            r'if\s+!\s+record_manifest_backup\s+'
            r'"\$PAM_SU_FILE"\s+'
            r'"\$backup_path"',
        ),
        (
            "unregistered backup cleanup",
            r'rm\s+-f\s+--\s+"\$backup_path"',
        ),
        (
            "failure return",
            r'return\s+1',
        ),
        (
            "pam mutation",
            r'atomic_write_command_output\s+'
            r'"\$PAM_SU_FILE"',
        ),
    ),
    "PAM_WHEEL_MANIFEST_CLEANUP_BROKEN",
)

home_permissions = function_text(
    "apply_home_permissions_module"
)

require_regex_order(
    home_permissions,
    (
        (
            "home manifest mapping guard",
            r'elif\s+!\s+record_manifest_backup\s+'
            r'"\$home_dir"\s+'
            r'"\$backup_path"',
        ),
        (
            "home snapshot cleanup",
            r'rm\s+-f\s+--\s+"\$backup_path"',
        ),
        (
            "home failure state",
            r'module_rc\s*=\s*1',
        ),
        (
            "home mutation",
            r'elif\s+chmod\s+700\s+"\$home_dir";\s*then',
        ),
        (
            "file manifest mapping guard",
            r'if\s+!\s+record_manifest_backup\s+'
            r'"\$file"\s+'
            r'"\$backup_path"',
        ),
        (
            "file snapshot cleanup",
            r'rm\s+-f\s+--\s+"\$backup_path"',
        ),
        (
            "file failure state",
            r'module_rc\s*=\s*1',
        ),
        (
            "file mutation",
            r'if\s+chmod\s+go-rwx\s+"\$file";\s*then',
        ),
    ),
    "HOME_PERMISSIONS_MANIFEST_CLEANUP_BROKEN",
)

if errors:
    for error in errors:
        print(error)
    raise SystemExit(1)

print("RESULT=BACKUP_FAILURE_REGRESSION_OK")
PYTEST
