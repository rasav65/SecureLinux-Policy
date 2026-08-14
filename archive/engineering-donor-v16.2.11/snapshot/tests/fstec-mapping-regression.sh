#!/usr/bin/env bash

set -u
set -o pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - \
    "$PROJECT_ROOT/securelinux-ng.sh" \
    "$PROJECT_ROOT/docs/fstec-mapping.md" \
    "$PROJECT_ROOT/README.md" \
    "$PROJECT_ROOT/docs/compatibility.md" \
    "$PROJECT_ROOT/CHANGELOG.md" \
    "$PROJECT_ROOT/tests/smoke.sh" \
    <<'PYFSTECSYNC'
from pathlib import Path
import json
import re
import sys

(
    source_path,
    mapping_path,
    readme_path,
    compatibility_path,
    changelog_path,
    smoke_path,
) = map(Path, sys.argv[1:])

source = source_path.read_text(encoding="utf-8")
mapping = mapping_path.read_text(encoding="utf-8")
readme = readme_path.read_text(encoding="utf-8")
compatibility = compatibility_path.read_text(encoding="utf-8")
changelog = changelog_path.read_text(encoding="utf-8")
smoke = smoke_path.read_text(encoding="utf-8")

errors = []


def require(condition, message):
    if not condition:
        errors.append(message)


inventory_match = re.search(
    r"(?ms)^fstec_items = \[\n(?P<body>.*?)^\]\n\ndata = \{",
    source,
)
require(inventory_match is not None, "SOURCE_FSTEC_ITEMS_MISSING")

entries = []
if inventory_match is not None:
    for raw in re.findall(
        r"(?m)^\s*(\{[^\n]+\}),?\s*$",
        inventory_match.group("body"),
    ):
        entries.append(json.loads(raw))

source_counts = {
    status: sum(entry.get("status") == status for entry in entries)
    for status in ("done", "partial", "not_applicable")
}
require(
    source_counts == {
        "done": 44,
        "partial": 15,
        "not_applicable": 1,
    },
    f"SOURCE_COUNTS_INVALID:{source_counts}",
)

source_official = {}
for entry in entries:
    item = entry.get("item", "")
    if not re.fullmatch(r"2\.[1-6]\.\d+", item):
        continue
    status = entry.get("status")
    previous = source_official.setdefault(item, status)
    require(
        previous == status,
        f"SOURCE_DUPLICATE_STATUS_CONFLICT:{item}:{previous}:{status}",
    )

require(
    len(source_official) == 40,
    f"SOURCE_OFFICIAL_ITEM_COUNT:{len(source_official)}",
)
require(
    sum(value == "done" for value in source_official.values()) == 30,
    "SOURCE_OFFICIAL_DONE_COUNT_INVALID",
)
require(
    sum(value == "partial" for value in source_official.values()) == 10,
    "SOURCE_OFFICIAL_PARTIAL_COUNT_INVALID",
)

mapping_official = {}
for line in mapping.splitlines():
    match = re.match(
        r"^\|\s*(2\.[1-6]\.\d+)\.[^|]*\|\s*"
        r"(done|partial|not_applicable|not applicable)\s*\|",
        line,
    )
    if match is None:
        continue
    item, status = match.groups()
    status = status.replace(" ", "_")
    require(item not in mapping_official, f"MAPPING_DUPLICATE_ITEM:{item}")
    mapping_official[item] = status

require(
    mapping_official == source_official,
    "MAPPING_OFFICIAL_STATUS_MISMATCH:"
    f"expected={source_official}:actual={mapping_official}",
)

partial_additional_rows = {
    "UFW firewall (default deny incoming, allow SSH)",
    "/tmp tmpfs (nosuid,nodev,noexec)",
    "mount hardening (/dev/shm, /var/tmp)",
    "AIDE integrity monitoring",
    "AppArmor enforce",
}

actual_partial_additional = set()
for line in mapping.splitlines():
    match = re.match(r"^\|\s*(.*?)\s*\|\s*partial\s*\|", line)
    if match is None:
        continue
    label = match.group(1).strip()
    if not label.startswith("2."):
        actual_partial_additional.add(label)

require(
    actual_partial_additional == partial_additional_rows,
    "MAPPING_ADDITIONAL_PARTIAL_SET_INVALID:"
    f"{actual_partial_additional}",
)

for marker in (
    "Общий реестр: `done=44`, `partial=15`.",
    "40 пунктов разделов 2.1–2.6: `done=30`, `partial=10`.",
    "Дополнительные позиции реестра: `done=14`, `partial=5`.",
):
    require(marker in mapping, f"MAPPING_SUMMARY_MISSING:{marker}")

for stale in (
    "- `done`: 39.",
    "- `partial`: 20.",
):
    require(stale not in mapping, f"MAPPING_STALE_SUMMARY_PRESENT:{stale}")

for document_name, document in (
    ("README", readme),
    ("COMPATIBILITY", compatibility),
):
    require(
        "done=44" in document and "partial=15" in document,
        f"{document_name}_COUNTS_NOT_SYNCHRONIZED",
    )

require(
    "Синхронизирована `docs/fstec-mapping.md`" in changelog,
    "CHANGELOG_MAPPING_SYNC_MISSING",
)
require(
    smoke.count("bash tests/fstec-mapping-regression.sh &&") == 1,
    "SMOKE_MAPPING_REGISTRATION_INVALID",
)

if errors:
    for error in errors:
        print(f"FAIL={error}")
    raise SystemExit(1)

print("RESULT=FSTEC_MAPPING_SOURCE_SYNC_OK")
print("RESULT=FSTEC_MAPPING_SUMMARY_OK")
print("RESULT=FSTEC_MAPPING_REGRESSION_OK")
PYFSTECSYNC
