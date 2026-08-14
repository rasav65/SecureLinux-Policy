#!/usr/bin/env bash

# Regression: the managed sudo policy must remain portable to sudo-rs,
# whose visudo rejects the classic sudo "Defaults logfile=..." setting.

ROOT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &&
    pwd -P
)"
RC_ROOT=$?

SOURCE="$ROOT_DIR/securelinux-ng.sh"

if (( RC_ROOT != 0 )) || [[ ! -f "$SOURCE" ]]; then
    echo "FAIL=SUDO_POLICY_SOURCE_NOT_FOUND"
    echo "RC_ROOT=$RC_ROOT"
    exit 1
fi

python3 - "$SOURCE" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

source = Path(sys.argv[1])
text = source.read_text(encoding="utf-8")

match = re.search(
    r"^SUDO_POLICY_CONTENT=\$'(?P<body>(?:[^'\\]|\\.)*)'$",
    text,
    flags=re.MULTILINE,
)

if match is None:
    print("FAIL=SUDO_POLICY_CONTENT_NOT_FOUND")
    raise SystemExit(1)

body = bytes(
    match.group("body"),
    "utf-8",
).decode("unicode_escape")

required = (
    "# Managed by SecureLinux-NG",
    "%wheel ALL=(ALL:ALL) ALL",
    "Defaults use_pty",
    "Defaults timestamp_timeout=5",
    "Defaults passwd_tries=3",
    'Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"',
)

failures = 0

for line in required:
    if line in body.splitlines():
        print(f"RESULT=SUDO_POLICY_REQUIRED_LINE_OK:{line}")
    else:
        print(f"FAIL=SUDO_POLICY_REQUIRED_LINE_MISSING:{line}")
        failures += 1

forbidden = (
    "Defaults logfile=",
)

for token in forbidden:
    if token in body:
        print(f"FAIL=SUDO_POLICY_UNSUPPORTED_SETTING_PRESENT:{token}")
        failures += 1
    else:
        print(f"RESULT=SUDO_POLICY_UNSUPPORTED_SETTING_ABSENT:{token}")

if not body.endswith("\n"):
    print("FAIL=SUDO_POLICY_FINAL_NEWLINE_MISSING")
    failures += 1
else:
    print("RESULT=SUDO_POLICY_FINAL_NEWLINE_OK")

print(f"SUDO_POLICY_PORTABILITY_FAILURE_COUNT={failures}")

if failures:
    raise SystemExit(1)

print("RESULT=SUDO_POLICY_PORTABILITY_REGRESSION_OK")
PY

RC_TEST=$?

echo "RC_TEST=$RC_TEST"

if (( RC_TEST != 0 )); then
    exit "$RC_TEST"
fi

exit 0
