#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-group-membership-crash-regression"
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
errors = []

required_fields = (
    '"pending_created_groups": []',
    '"created_groups": []',
    '"pending_group_memberships": []',
    '"added_group_memberships": []',
)
for field in required_fields:
    if source.count(field) != 1:
        errors.append(f"MANIFEST_FIELD_COUNT_INVALID:{field}")

required_functions = (
    "update_manifest_group_state()",
    "record_manifest_pending_created_group()",
    "record_manifest_created_group()",
    "record_manifest_pending_group_membership()",
    "record_manifest_added_group_membership()",
    "restore_added_group_members()",
    "restore_has_created_group()",
)
for function in required_functions:
    if function not in source:
        errors.append(f"FUNCTION_MISSING:{function}")

matches = list(re.finditer(
    r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
    source,
))
functions = {}
for index, match in enumerate(matches):
    end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
    functions[match.group(1)] = source[match.start():end]

apply_block = functions.get("apply_pam_wheel_module", "")
restore_members_block = functions.get("restore_added_group_members", "")
restore_group_block = functions.get("restore_has_created_group", "")

group_pending = apply_block.find('record_manifest_pending_created_group wheel')
group_add = apply_block.find('groupadd wheel', group_pending)
group_commit = apply_block.find('record_manifest_created_group wheel', group_add)
root_pending = apply_block.find('record_manifest_pending_group_membership wheel root')
root_add = apply_block.find('gpasswd -a root wheel', root_pending)
root_commit = apply_block.find('record_manifest_added_group_membership', root_add)

checks = (
    (
        "GROUP_PENDING_ORDER",
        group_pending,
        group_add,
        group_commit,
    ),
    (
        "ROOT_MEMBERSHIP_PENDING_ORDER",
        root_pending,
        root_add,
        root_commit,
    ),
)
for name, first, second, third in checks:
    if not (first >= 0 and first < second < third):
        errors.append(f"{name}_INVALID:{first}:{second}:{third}")

user_pending = apply_block.find('record_manifest_pending_group_membership \\\n            wheel \\\n            "$user_name"')
user_add = apply_block.find('gpasswd -a "$user_name" wheel')
user_commit = apply_block.find('record_manifest_added_group_membership', user_add)
if not (user_pending >= 0 and user_pending < user_add < user_commit):
    errors.append(
        f"USER_MEMBERSHIP_PENDING_ORDER_INVALID:{user_pending}:{user_add}:{user_commit}"
    )

if 'data.get("pending_group_memberships", [])' not in restore_members_block:
    errors.append("PENDING_MEMBERSHIP_RESTORE_MISSING")
if 'data.get("pending_created_groups", [])' not in restore_group_block:
    errors.append("PENDING_GROUP_RESTORE_MISSING")

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise RuntimeError("group membership crash static regression failed")

print("RESULT=GROUP_MEMBERSHIP_CRASH_STATIC_REGRESSION_OK")

selected = (
    "update_manifest_group_state",
    "record_manifest_pending_created_group",
    "record_manifest_created_group",
    "record_manifest_pending_group_membership",
    "record_manifest_added_group_membership",
    "restore_has_created_group",
    "restore_added_group_members",
    "restore_pam_wheel_module",
)
missing = [name for name in selected if name not in functions]
if missing:
    raise RuntimeError("FUNCTION_EXTRACTION_FAILED:" + ",".join(missing))

function_source = "\n".join(functions[name].rstrip() for name in selected)

harness = """#!/usr/bin/env bash

""" + function_source + r'''

SAFE_COUNT=0
WARNING_COUNT=0
ERROR_COUNT=0
GROUP_EXISTS=0
ROOT_MEMBER=0
ADMIN_MEMBER=0
GROUPDEL_COUNT=0

add_safe() { SAFE_COUNT=$((SAFE_COUNT + 1)); }
add_warning() { WARNING_COUNT=$((WARNING_COUNT + 1)); }
add_error() { ERROR_COUNT=$((ERROR_COUNT + 1)); }
restore_file_from_manifest() { return 0; }

getent() {
    case "$1:$2" in
        group:wheel) (( GROUP_EXISTS == 1 )) ;;
        passwd:root|passwd:admin) return 0 ;;
        *) return 1 ;;
    esac
}

id() {
    case "$1" in
        root|admin) return 0 ;;
        *) return 1 ;;
    esac
}

pam_wheel_user_is_member() {
    case "$1" in
        root) (( ROOT_MEMBER == 1 )) ;;
        admin) (( ADMIN_MEMBER == 1 )) ;;
        *) return 1 ;;
    esac
}

gpasswd() {
    if [[ "$1" == "-d" && "$3" == "wheel" ]]; then
        case "$2" in
            root) ROOT_MEMBER=0; return 0 ;;
            admin) ADMIN_MEMBER=0; return 0 ;;
        esac
    fi
    return 1
}

pam_wheel_group_members() {
    (( ROOT_MEMBER == 1 )) && printf '%s\n' root
    (( ADMIN_MEMBER == 1 )) && printf '%s\n' admin
    return 0
}

groupdel() {
    if [[ "$1" == "wheel" && "$GROUP_EXISTS" == "1" ]]; then
        GROUP_EXISTS=0
        GROUPDEL_COUNT=$((GROUPDEL_COUNT + 1))
        return 0
    fi
    return 1
}

write_manifest() {
    printf '%s\n' "$2" > "$1"
}

validate_json_state() {
    python3 - "$1" "$2" <<'PYCHECK'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = json.loads(sys.argv[2])
for key, value in expected.items():
    if data.get(key) != value:
        raise RuntimeError(f"STATE_MISMATCH:{key}:{data.get(key)!r}:{value!r}")
PYCHECK
}

run_writer_case() {
    MANIFEST_FILE="$TMP_ROOT/writer.json"
    write_manifest "$MANIFEST_FILE" '{}'

    record_manifest_pending_created_group wheel
    RC_PENDING_GROUP=$?
    record_manifest_created_group wheel
    RC_COMMIT_GROUP=$?
    record_manifest_pending_group_membership wheel admin
    RC_PENDING_MEMBERSHIP=$?
    record_manifest_added_group_membership wheel admin
    RC_COMMIT_MEMBERSHIP=$?

    validate_json_state \
        "$MANIFEST_FILE" \
        '{"pending_created_groups": [], "created_groups": ["wheel"], "pending_group_memberships": [], "added_group_memberships": [{"group": "wheel", "user": "admin"}]}'
    RC_VALIDATE=$?

    printf '%s\n' \
        "RC_PENDING_GROUP=$RC_PENDING_GROUP" \
        "RC_COMMIT_GROUP=$RC_COMMIT_GROUP" \
        "RC_PENDING_MEMBERSHIP=$RC_PENDING_MEMBERSHIP" \
        "RC_COMMIT_MEMBERSHIP=$RC_COMMIT_MEMBERSHIP" \
        "RC_VALIDATE=$RC_VALIDATE"

    (( RC_PENDING_GROUP == 0 \
        && RC_COMMIT_GROUP == 0 \
        && RC_PENDING_MEMBERSHIP == 0 \
        && RC_COMMIT_MEMBERSHIP == 0 \
        && RC_VALIDATE == 0 )) || return 1

    echo "RESULT=GROUP_MEMBERSHIP_JOURNAL_COMMIT_OK"
    return 0
}

run_pending_restore_case() {
    RESTORE_SOURCE_MANIFEST="$TMP_ROOT/pending-restore.json"
    write_manifest \
        "$RESTORE_SOURCE_MANIFEST" \
        '{"pending_created_groups": ["wheel"], "created_groups": [], "pending_group_memberships": [{"group": "wheel", "user": "root"}, {"group": "wheel", "user": "admin"}], "added_group_memberships": []}'

    GROUP_EXISTS=1
    ROOT_MEMBER=1
    ADMIN_MEMBER=1
    GROUPDEL_COUNT=0
    ERROR_COUNT=0

    restore_pam_wheel_module
    RC_RESTORE=$?

    printf '%s\n' \
        "RC_RESTORE=$RC_RESTORE" \
        "GROUP_EXISTS=$GROUP_EXISTS" \
        "ROOT_MEMBER=$ROOT_MEMBER" \
        "ADMIN_MEMBER=$ADMIN_MEMBER" \
        "GROUPDEL_COUNT=$GROUPDEL_COUNT" \
        "ERROR_COUNT=$ERROR_COUNT"

    (( RC_RESTORE == 0 \
        && GROUP_EXISTS == 0 \
        && ROOT_MEMBER == 0 \
        && ADMIN_MEMBER == 0 \
        && GROUPDEL_COUNT == 1 \
        && ERROR_COUNT == 0 )) || return 1

    echo "RESULT=GROUP_MEMBERSHIP_PENDING_RESTORE_OK"
    return 0
}

run_pending_before_mutation_case() {
    RESTORE_SOURCE_MANIFEST="$TMP_ROOT/pending-before-mutation.json"
    write_manifest \
        "$RESTORE_SOURCE_MANIFEST" \
        '{"pending_created_groups": ["wheel"], "created_groups": [], "pending_group_memberships": [], "added_group_memberships": []}'

    GROUP_EXISTS=0
    ROOT_MEMBER=0
    ADMIN_MEMBER=0
    GROUPDEL_COUNT=0
    ERROR_COUNT=0

    restore_pam_wheel_module
    RC_RESTORE=$?

    printf '%s\n' \
        "RC_PREMUTATION_RESTORE=$RC_RESTORE" \
        "GROUPDEL_COUNT=$GROUPDEL_COUNT" \
        "ERROR_COUNT=$ERROR_COUNT"

    (( RC_RESTORE == 0 \
        && GROUPDEL_COUNT == 0 \
        && ERROR_COUNT == 0 )) || return 1

    echo "RESULT=GROUP_PENDING_BEFORE_MUTATION_OK"
    return 0
}

run_invalid_case() {
    RESTORE_SOURCE_MANIFEST="$TMP_ROOT/invalid.json"
    write_manifest \
        "$RESTORE_SOURCE_MANIFEST" \
        '{"pending_created_groups": "wheel", "created_groups": []}'

    ERROR_COUNT=0
    restore_has_created_group wheel
    RC_INVALID=$?

    printf '%s\n' \
        "RC_INVALID=$RC_INVALID" \
        "ERROR_COUNT=$ERROR_COUNT"

    (( RC_INVALID == 2 && ERROR_COUNT == 1 )) || return 1

    echo "RESULT=GROUP_PENDING_INVALID_REJECTED_OK"
    return 0
}

main() {
    DRY_RUN=0
    DEBUG_LOG_FILE=/dev/null
    PAM_SU_FILE="$TMP_ROOT/su"

    run_writer_case
    RC_WRITER=$?
    run_pending_restore_case
    RC_RESTORE=$?
    run_pending_before_mutation_case
    RC_PREMUTATION=$?
    run_invalid_case
    RC_INVALID=$?

    printf '%s\n' \
        "RC_WRITER=$RC_WRITER" \
        "RC_RESTORE=$RC_RESTORE" \
        "RC_PREMUTATION=$RC_PREMUTATION" \
        "RC_INVALID=$RC_INVALID"

    (( RC_WRITER == 0 \
        && RC_RESTORE == 0 \
        && RC_PREMUTATION == 0 \
        && RC_INVALID == 0 )) || return 1

    echo "RESULT=GROUP_MEMBERSHIP_CRASH_DYNAMIC_REGRESSION_OK"
    return 0
}

main "$@"
'''

harness_path.write_text(harness, encoding="utf-8")
harness_path.chmod(0o755)
PYBUILD
    RC_BUILD=$?

    RC_DYNAMIC=99
    if (( RC_BUILD == 0 )); then
        TMP_ROOT="$TMP_ROOT" bash "$HARNESS"
        RC_DYNAMIC=$?
    fi

    rm -rf -- "$TMP_ROOT"

    printf '%s\n' \
        "RC_BUILD=$RC_BUILD" \
        "RC_DYNAMIC=$RC_DYNAMIC"

    if (( RC_BUILD == 0 && RC_DYNAMIC == 0 )); then
        echo "RESULT=GROUP_MEMBERSHIP_CRASH_REGRESSION_OK"
        return 0
    fi

    echo "RESULT=GROUP_MEMBERSHIP_CRASH_REGRESSION_FAILED"
    return 1
}

main "$@"
