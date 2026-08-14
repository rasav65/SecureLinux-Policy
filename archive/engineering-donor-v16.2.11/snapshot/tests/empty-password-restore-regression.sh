#!/usr/bin/env bash
cd "$(dirname "$0")/.." || return 1

python3 - <<'PYCHECK'
import re
from pathlib import Path

text = Path("securelinux-ng.sh").read_text(encoding="utf-8")
errors = []


def function_text(name):
    matches = list(
        re.finditer(
            r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
            text,
        )
    )
    for index, match in enumerate(matches):
        if match.group(1) != name:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        return text[match.start():end]
    errors.append(f"FUNCTION_NOT_FOUND={name}")
    return ""


def require(condition, message):
    if not condition:
        errors.append(message)


def require_order(block, patterns, message):
    normalized = re.sub(r"\\\n[ \t]*", " ", block)
    cursor = 0
    for label, pattern in patterns:
        match = re.search(pattern, normalized[cursor:], re.DOTALL)
        if match is None:
            errors.append(f"{message}:MISSING:{label}")
            return
        cursor += match.end()


apply_block = function_text("apply_empty_passwords_module")
restore_block = function_text("restore_empty_passwords_module")
record_state = function_text("record_manifest_empty_password_state")
remove_state = function_text("remove_manifest_empty_password_state")
lookup_state = function_text("restore_manifest_empty_password_state")

for helper, block in (
    ("record", record_state),
    ("remove", remove_state),
    ("lookup", lookup_state),
):
    require(bool(block), f"EMPTY_PASSWORD_STATE_{helper.upper()}_HELPER_MISSING")

require_order(
    apply_block,
    (
        ("symlink guard", r'\[\[\s+-L\s+"\$shadow_file"\s+\]\]'),
        ("candidate preparation", r'if\s+!\s+shadow_candidate="\$\('),
        ("typed state", r'if\s+!\s+record_manifest_empty_password_state'),
        ("shadow commit", r'if\s+!\s+python3\s+-\s+"\$shadow_candidate"\s+"\$shadow_file"'),
        ("typed rollback", r'if\s+!\s+remove_manifest_empty_password_state'),
        ("modified file", r'if\s+!\s+record_manifest_modified_file\s+"\$shadow_file"'),
    ),
    "EMPTY_PASSWORD_TYPED_TRANSACTION_ORDER_BROKEN",
)

require(
    'record_manifest_backup \\\n        "/etc/shadow"' not in apply_block,
    "GENERIC_EMPTY_PASSWORD_BACKUP_PRESENT",
)
require(
    'remove_manifest_backup \\\n            "/etc/shadow"' not in apply_block,
    "GENERIC_EMPTY_PASSWORD_BACKUP_ROLLBACK_PRESENT",
)
require(
    "shadow.is_symlink()" in apply_block,
    "PYTHON_SHADOW_SYMLINK_GUARD_MISSING",
)
require(
    "restore_manifest_empty_password_state" in restore_block,
    "TYPED_EMPTY_PASSWORD_RESTORE_LOOKUP_MISSING",
)
require(
    'data.get("backups", [])' in restore_block,
    "LEGACY_EMPTY_PASSWORD_FALLBACK_MISSING",
)
require(
    "security-preserving-nonrestore" in record_state,
    "SECURITY_PRESERVING_RESTORE_POLICY_MISSING",
)
require(
    "восстановление пустых полей пароля запрещено" in restore_block,
    "UNSAFE_EMPTY_PASSWORD_RESTORE_GUARD_MISSING",
)

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=EMPTY_PASSWORD_TRANSACTION_REGRESSION_OK")
print("RESULT=EMPTY_PASSWORD_RESTORE_REGRESSION_OK")
PYCHECK

RC_TEST=$?
printf 'RC_TEST=%s\n' "$RC_TEST"
test "$RC_TEST" -eq 0
