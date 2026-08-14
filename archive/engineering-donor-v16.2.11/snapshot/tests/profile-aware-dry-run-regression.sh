#!/usr/bin/env bash

ROOT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &&
    pwd -P
)"
RC_ROOT=$?

SOURCE="$ROOT_DIR/securelinux-ng.sh"

if (( RC_ROOT != 0 )) || [[ ! -f "$SOURCE" || -L "$SOURCE" ]]; then
    echo "FAIL=PROFILE_DRY_RUN_SOURCE_NOT_FOUND"
    echo "RC_ROOT=$RC_ROOT"
    exit 1
fi

python3 - "$SOURCE" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

source = Path(sys.argv[1])
lines = source.read_text(encoding="utf-8").splitlines()

expected = {
    "apply_apparmor_module": "strict",
    "apply_aide_module": "strict",
    "apply_fail2ban_module": "paranoid",
    "apply_rkhunter_module": "paranoid",
    "apply_mount_hardening_module": "paranoid",
    "apply_tmp_tmpfs_module": "paranoid",
}

function_pattern = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{\s*$"
)

starts = []

for index, line in enumerate(lines):
    match = function_pattern.match(line)

    if match:
        starts.append((match.group(1), index))

ranges = {}

for position, (name, start) in enumerate(starts):
    end = (
        starts[position + 1][1]
        if position + 1 < len(starts)
        else len(lines)
    )
    ranges[name] = (start, end)

dry_pattern = re.compile(
    r"^\s*if \(\(\s*DRY_RUN(?:\s*==\s*1)?\s*\)\); then\s*$"
)

failures = 0

for name, level in expected.items():
    function_range = ranges.get(name)

    if function_range is None:
        print(f"FAIL=PROFILE_DRY_RUN_FUNCTION_MISSING:{name}")
        failures += 1
        continue

    start, end = function_range
    body = lines[start:end]

    dry_offsets = [
        offset
        for offset, line in enumerate(body)
        if dry_pattern.match(line)
    ]

    gate_pattern = re.compile(
        rf"^\s*if ! profile_allows {re.escape(level)}; then\s*$"
    )

    gate_offsets = [
        offset
        for offset, line in enumerate(body)
        if gate_pattern.match(line)
    ]

    if len(dry_offsets) != 1:
        print(
            f"FAIL=PROFILE_DRY_RUN_CHECK_COUNT:{name}:"
            f"{len(dry_offsets)}"
        )
        failures += 1
        continue

    if len(gate_offsets) != 1:
        print(
            f"FAIL=PROFILE_GATE_COUNT:{name}:"
            f"{len(gate_offsets)}"
        )
        failures += 1
        continue

    dry_line = start + dry_offsets[0] + 1
    gate_line = start + gate_offsets[0] + 1

    print(f"FUNCTION={name}")
    print(f"REQUIRED_PROFILE={level}")
    print(f"PROFILE_GATE_LINE={gate_line}")
    print(f"DRY_RUN_LINE={dry_line}")

    if gate_line < dry_line:
        print(f"RESULT=PROFILE_GATE_BEFORE_DRY_RUN:{name}")
    else:
        print(f"FAIL=DRY_RUN_BEFORE_PROFILE_GATE:{name}")
        failures += 1

print(f"PROFILE_AWARE_DRY_RUN_FAILURE_COUNT={failures}")

if failures:
    raise SystemExit(1)

print("RESULT=PROFILE_AWARE_DRY_RUN_REGRESSION_OK")
PY

RC_TEST=$?
echo "RC_TEST=$RC_TEST"

if (( RC_TEST != 0 )); then
    exit "$RC_TEST"
fi

exit 0
