#!/usr/bin/env bash

# Проверяет, что atomic managed-file update сохраняет расширенную metadata:
# все читаемые xattrs обычного файла, включая представленные ими POSIX ACL,
# file capabilities и security labels. Метаданные symlink-цели не наследуются.
# ENOTSUP/EOPNOTSUPP/ENOSYS трактуются как отсутствие xattr-поддержки;
# неожиданные ошибки должны остановить replace.

set -u

ROOT="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"
SOURCE="$ROOT/securelinux-ng.sh"

python3 - "$SOURCE" <<'PYSTATIC'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(
    r"(?ms)^atomic_write_command_output\(\) \{.*?"
    r"(?=^[A-Za-z_][A-Za-z0-9_]*\(\) \{|\Z)",
    source,
)

errors = []

def require(condition, message):
    if not condition:
        errors.append(message)

require(match is not None, "ATOMIC_FUNCTION_MISSING")
atomic = match.group(0) if match else ""

for marker in (
    "import errno",
    "requested_metadata = target.lstat()",
    "requested_is_symlink = (",
    "requested_is_regular = (",
    "xattrs = {}",
    "if requested_is_regular:",
    "metadata = requested_metadata",
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
    "for name, value in xattrs.items():",
    "os.setxattr(fd, name, value)",
    "os.getxattr(fd, name) != value",
    "atomic write metadata xattr verification failed",
):
    require(marker in atomic, f"ATOMIC_XATTR_MARKER_MISSING:{marker}")

require(
    atomic.count("follow_symlinks=False") >= 2,
    "ATOMIC_NOFOLLOW_XATTR_MARKERS_MISSING",
)
require(
    "target.exists()" not in atomic,
    "ATOMIC_SYMLINK_FOLLOWING_EXISTS_PRESENT",
)
require(
    "target.stat()" not in atomic,
    "ATOMIC_SYMLINK_FOLLOWING_STAT_PRESENT",
)
require(
    "for name in os.listxattr(target):" not in atomic,
    "ATOMIC_FOLLOWING_LISTXATTR_PRESENT",
)
require(
    "xattrs[name] = os.getxattr(target, name)" not in atomic,
    "ATOMIC_FOLLOWING_GETXATTR_PRESENT",
)

regular_branch = atomic.find("if requested_is_regular:")
listxattr_position = atomic.find("xattr_names = os.listxattr(")
regular_else = atomic.find("\nelse:\n", listxattr_position)

require(
    regular_branch >= 0
    and listxattr_position > regular_branch
    and regular_else > listxattr_position,
    "ATOMIC_XATTR_COLLECTION_NOT_SCOPED_TO_REGULAR_FILE",
)

positions = [
    atomic.find("os.fchown(fd, uid, gid)"),
    atomic.find("os.fchmod(fd, mode)"),
    atomic.find("os.setxattr(fd, name, value)"),
    atomic.find("os.getxattr(fd, name) != value"),
    atomic.find("os.fsync(fd)"),
    atomic.find("os.replace(temporary, target)"),
]
require(
    all(position >= 0 for position in positions),
    "ATOMIC_METADATA_ORDER_MARKER_MISSING",
)
require(
    positions == sorted(positions),
    "ATOMIC_METADATA_ORDER_INVALID",
)

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=EXTENDED_METADATA_STATIC_REGRESSION_OK")
PYSTATIC
rc_static=$?

if (( rc_static != 0 )); then
    echo "RC_STATIC=$rc_static"
    exit 1
fi

WORK_DIR="$ROOT/.tmp-extended-metadata-regression"
rm -rf -- "$WORK_DIR"
mkdir -p "$WORK_DIR"
trap 'rm -rf -- "$WORK_DIR"' EXIT

python3 - "$SOURCE" "$WORK_DIR/functions.sh" <<'PYEXTRACT'
from pathlib import Path
import re
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
output = Path(sys.argv[2])
match = re.search(
    r"(?ms)^atomic_write_command_output\(\) \{.*?"
    r"(?=^[A-Za-z_][A-Za-z0-9_]*\(\) \{|\Z)",
    source,
)
if match is None:
    raise SystemExit("atomic_write_command_output missing")

function_text = match.group(0).rstrip() + "\n"
needle = "import os\n"
injection = """import os

_test_listxattr_errno_name = os.environ.get(
    "SECURELINUX_NG_TEST_LISTXATTR_ERRNO"
)
if _test_listxattr_errno_name:
    _test_listxattr_errno = getattr(
        errno,
        _test_listxattr_errno_name,
    )

    def _securelinux_test_listxattr(*args, **kwargs):
        raise OSError(
            _test_listxattr_errno,
            _test_listxattr_errno_name,
        )

    os.listxattr = _securelinux_test_listxattr
"""
if function_text.count(needle) != 1:
    raise SystemExit("atomic os import marker mismatch")
function_text = function_text.replace(needle, injection, 1)
output.write_text(function_text, encoding="utf-8")
PYEXTRACT
rc_extract=$?

if (( rc_extract != 0 )); then
    echo "RC_EXTRACT=$rc_extract"
    exit 1
fi

cat > "$WORK_DIR/harness.sh" <<'HARNESS'
#!/usr/bin/env bash
set -u

WORK_DIR="$1"
. "$WORK_DIR/functions.sh"

target="$WORK_DIR/managed.conf"
printf 'OLD\n' > "$target"
chmod 0640 "$target"

unsupported_target="$WORK_DIR/xattr-unsupported.conf"
printf 'OLD\n' > "$unsupported_target"
chmod 0640 "$unsupported_target"

SECURELINUX_NG_TEST_LISTXATTR_ERRNO=ENOTSUP
export SECURELINUX_NG_TEST_LISTXATTR_ERRNO
printf 'NEW\n' | atomic_write_command_output \
    "$unsupported_target" \
    0600 \
    cat
rc_xattr_unsupported=$?
unset SECURELINUX_NG_TEST_LISTXATTR_ERRNO

unsupported_content="$(tr -d '\n' < "$unsupported_target")"
unsupported_mode="$(stat -c '%a' "$unsupported_target")"

echo "XATTR_UNSUPPORTED_RC=$rc_xattr_unsupported"
echo "XATTR_UNSUPPORTED_CONTENT=$unsupported_content"
echo "XATTR_UNSUPPORTED_MODE=$unsupported_mode"

if (( rc_xattr_unsupported != 0 )); then exit 1; fi
if [[ "$unsupported_content" != "NEW" ]]; then exit 1; fi
if [[ "$unsupported_mode" != "640" ]]; then exit 1; fi

echo "RESULT=XATTR_UNSUPPORTED_FALLBACK_OK"

unexpected_target="$WORK_DIR/xattr-unexpected-error.conf"
printf 'OLD\n' > "$unexpected_target"
chmod 0640 "$unexpected_target"

SECURELINUX_NG_TEST_LISTXATTR_ERRNO=EACCES
export SECURELINUX_NG_TEST_LISTXATTR_ERRNO
printf 'NEW\n' | atomic_write_command_output \
    "$unexpected_target" \
    0600 \
    cat
rc_xattr_unexpected=$?
unset SECURELINUX_NG_TEST_LISTXATTR_ERRNO

unexpected_content="$(tr -d '\n' < "$unexpected_target")"
unexpected_mode="$(stat -c '%a' "$unexpected_target")"

echo "XATTR_UNEXPECTED_ERROR_RC=$rc_xattr_unexpected"
echo "XATTR_UNEXPECTED_ERROR_CONTENT=$unexpected_content"
echo "XATTR_UNEXPECTED_ERROR_MODE=$unexpected_mode"

if (( rc_xattr_unexpected == 0 )); then exit 1; fi
if [[ "$unexpected_content" != "OLD" ]]; then exit 1; fi
if [[ "$unexpected_mode" != "640" ]]; then exit 1; fi

echo "RESULT=XATTR_UNEXPECTED_ERROR_REJECTED_OK"

python3 - "$target" <<'PYSET'
import errno
import os
import sys

path = sys.argv[1]
try:
    os.setxattr(path, "user.securelinux_ng_test", b"preserve-me")
except OSError as exc:
    if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
        print("XATTR_SUPPORTED=0")
        raise SystemExit(77)
    raise
print("XATTR_SUPPORTED=1")
PYSET
rc_xattr_setup=$?

if (( rc_xattr_setup == 77 )); then
    echo "RESULT=EXTENDED_METADATA_XATTR_UNSUPPORTED_SKIP"
    exit 0
fi
if (( rc_xattr_setup != 0 )); then
    exit "$rc_xattr_setup"
fi

acl_before=""
acl_enabled=0
if command -v setfacl >/dev/null 2>&1 \
    && command -v getfacl >/dev/null 2>&1 \
    && setfacl -m u:12345:r-- "$target" >/dev/null 2>&1
then
    acl_enabled=1
    acl_before="$(getfacl -cp "$target")"
fi

cap_before=""
cap_enabled=0
if command -v setcap >/dev/null 2>&1 \
    && command -v getcap >/dev/null 2>&1 \
    && setcap cap_net_bind_service=ep "$target" >/dev/null 2>&1
then
    cap_enabled=1
    cap_before="$(getcap -n "$target")"
fi

printf 'NEW\n' | atomic_write_command_output "$target" 0600 cat
rc_atomic=$?

content="$(tr -d '\n' < "$target")"
mode="$(stat -c '%a' "$target")"
xattr_value="$(python3 - "$target" <<'PYGET'
import os
import sys
print(os.getxattr(sys.argv[1], "user.securelinux_ng_test").decode())
PYGET
)"

acl_after=""
if (( acl_enabled == 1 )); then
    acl_after="$(getfacl -cp "$target")"
fi

cap_after=""
if (( cap_enabled == 1 )); then
    cap_after="$(getcap -n "$target")"
fi

echo "RC_ATOMIC=$rc_atomic"
echo "CONTENT=$content"
echo "MODE=$mode"
echo "XATTR_VALUE=$xattr_value"
echo "ACL_ENABLED=$acl_enabled"
echo "ACL_PRESERVED=$([[ "$acl_before" == "$acl_after" ]] && echo 1 || echo 0)"
echo "CAP_ENABLED=$cap_enabled"
echo "CAP_PRESERVED=$([[ "$cap_before" == "$cap_after" ]] && echo 1 || echo 0)"

if (( rc_atomic != 0 )); then exit 1; fi
if [[ "$content" != "NEW" ]]; then exit 1; fi
if [[ "$mode" != "640" ]]; then exit 1; fi
if [[ "$xattr_value" != "preserve-me" ]]; then exit 1; fi
if (( acl_enabled == 1 )) && [[ "$acl_before" != "$acl_after" ]]; then exit 1; fi
if (( cap_enabled == 1 )) && [[ "$cap_before" != "$cap_after" ]]; then exit 1; fi

exit 0
HARNESS
chmod 0755 "$WORK_DIR/harness.sh"

bash "$WORK_DIR/harness.sh" "$WORK_DIR"
rc_dynamic=$?

echo "RC_STATIC=$rc_static"
echo "RC_EXTRACT=$rc_extract"
echo "RC_DYNAMIC=$rc_dynamic"

if (( rc_static == 0 && rc_extract == 0 && rc_dynamic == 0 )); then
    echo "RESULT=EXTENDED_METADATA_REGRESSION_OK"
    exit 0
fi

echo "RESULT=EXTENDED_METADATA_REGRESSION_FAILED"
exit 1
