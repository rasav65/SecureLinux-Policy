#!/usr/bin/env python3
from pathlib import Path
import csv
import re

ROOT = Path(__file__).resolve().parents[2]
readme = (ROOT / "README.md").read_text(encoding="utf-8")
pmap = (ROOT / "docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")
roadmap = (ROOT / "docs/ROADMAP-v3.md").read_text(encoding="utf-8")

with (ROOT / "index/source-v4/SOURCE-INDEX.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    index_rows = list(csv.DictReader(stream, delimiter="\t"))
with (ROOT / "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    controls = list(csv.DictReader(stream, delimiter="\t"))
with (ROOT / "product/ADAPTER-REGISTRY.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    adapters = list(csv.DictReader(stream, delimiter="\t"))

total = len(index_rows)
controlled = sum(
    row["status"] == "CLOSED" and not row["disposition"] for row in index_rows
)
disposed = sum(
    row["status"] == "CLOSED" and bool(row["disposition"]) for row in index_rows
)
open_rows = sum(row["status"] == "OPEN" for row in index_rows)

def parse_progress_text(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw or "=" not in raw:
            raise ValueError(f"bad PROGRESS line {lineno}")
        key, value = raw.split("=", 1)
        if not key or key in result:
            raise ValueError(f"bad/duplicate PROGRESS key {key!r} at {lineno}")
        result[key] = value
    return result

expected_source_progress = {
    "TOTAL_INDEX_ROWS": str(total),
    "CLOSED_INDEX_ROWS": str(controlled + disposed),
    "OPEN_INDEX_ROWS": str(open_rows),
    "CLOSURE_RATIO": f"{controlled + disposed}/{total}",
    "CONTROLLED_CLOSED_WITH_CONTRACT": str(controlled),
    "DISPOSED_CLOSED_ROWS": str(disposed),
}
source_progress_text = (ROOT / "index/source-v4/PROGRESS.txt").read_text(encoding="utf-8")
source_progress = parse_progress_text(source_progress_text)
assert source_progress == expected_source_progress, (source_progress, expected_source_progress)
for label, mutated in (
    ("disposed_stale", source_progress_text.replace("DISPOSED_CLOSED_ROWS=0", "DISPOSED_CLOSED_ROWS=1", 1)),
    ("extra_key", source_progress_text + "CURRENT_CHECKPOINT=STEP7B_ACTIVE\n"),
    ("duplicate_key", "OPEN_INDEX_ROWS=999\n" + source_progress_text),
):
    try:
        parsed = parse_progress_text(mutated)
        assert parsed == expected_source_progress
    except (AssertionError, ValueError):
        pass
    else:
        raise AssertionError(f"source-v4 PROGRESS negative fixture accepted: {label}")

assert readme.count("<!-- BEGIN GENERATED CURRENT STATUS -->") == 1
assert readme.count("<!-- END GENERATED CURRENT STATUS -->") == 1
for marker in (
    f"TOTAL_INDEX_ROWS={total}",
    f"CONTROLLED_CLOSED_WITH_CONTRACT={controlled}",
    f"DISPOSED_CLOSED_ROWS={disposed}",
    f"OPEN_INDEX_ROWS={open_rows}",
    f"CLOSURE_RATIO={controlled + disposed}/{total}",
    f"CANONICAL_CONTROLS={len(controls)}",
    f"ADAPTER_KINDS={len(adapters)}",
    "FULL_FSTEC_COMPLIANCE_CLAIM=false",
):
    assert marker in readme, marker

assert pmap.count("<!-- BEGIN GENERATED MAP STATUS -->") == 1
assert pmap.count("<!-- END GENERATED MAP STATUS -->") == 1
map_status = pmap.split("<!-- BEGIN GENERATED MAP STATUS -->", 1)[1].split(
    "<!-- END GENERATED MAP STATUS -->", 1
)[0]
# Проверяем значения machine truth, не закрепляя английскую presentation-prose.
status_patterns = {
    "source_rows": (rf"(?:source rows|строки source)={total}(?:\D|$)"),
    "controlled_closed": (rf"controlled CLOSED={controlled}(?:\D|$)"),
    "open_rows": (rf"OPEN={open_rows}(?:\D|$)"),
    "controls": (rf"canonical controls={len(controls)}(?:\D|$)"),
    "adapters": (rf"adapters={len(adapters)}(?:\D|$)"),
}
for name, pattern in status_patterns.items():
    assert re.search(pattern, map_status), (name, map_status)

for path in (
    "docs/PROJECT-MAP-v3.md",
    "docs/policy-layers.md",
    "docs/fstec-coverage.md",
    "docs/compatibility.md",
):
    assert path in readme, path

src0005_rows = [row for row in index_rows if row["index_id"] == "SRC-0005"]
assert len(src0005_rows) == 1
assert src0005_rows[0]["status"] == "CLOSED"
assert not src0005_rows[0]["disposition"]
src0005_controls = [row for row in controls if row["index_id"] == "SRC-0005"]
assert len(src0005_controls) == 3

by_index = {row["index_id"]: row for row in index_rows}
for index_id in ("SRC-0030", "SRC-0031", "SRC-0036", "SRC-0037", "SRC-0038", "SRC-0039"):
    assert by_index[index_id]["status"] == "CLOSED", index_id
    assert not by_index[index_id]["disposition"], index_id
assert by_index["SRC-0033"]["status"] == "CLOSED"
assert not by_index["SRC-0033"]["disposition"]
for index_id in ("SRC-0018", "SRC-0019", "SRC-0020", "SRC-0021", "SRC-0022", "SRC-0024", "SRC-0032"):
    assert by_index[index_id]["status"] == "CLOSED", index_id
    assert not by_index[index_id]["disposition"], index_id
assert by_index["SRC-0011"]["status"] == "CLOSED"
assert not by_index["SRC-0011"]["disposition"]
assert by_index["SRC-0012"]["status"] == "CLOSED"
assert not by_index["SRC-0012"]["disposition"]
assert by_index["SRC-0013"]["status"] == "CLOSED"
assert not by_index["SRC-0013"]["disposition"]
assert by_index["SRC-0014"]["status"] == "CLOSED"
assert not by_index["SRC-0014"]["disposition"]
assert by_index["SRC-0002"]["status"] == "CLOSED"
assert not by_index["SRC-0002"]["disposition"]
assert by_index["SRC-0003"]["status"] == "CLOSED"
assert not by_index["SRC-0003"]["disposition"]
assert by_index["SRC-0004"]["status"] == "CLOSED"
assert not by_index["SRC-0004"]["disposition"]
assert by_index["SRC-0006"]["status"] == "CLOSED"
assert not by_index["SRC-0006"]["disposition"]
assert by_index["SRC-0007"]["status"] == "CLOSED"
assert not by_index["SRC-0007"]["disposition"]
assert by_index["SRC-0008"]["status"] == "CLOSED"
assert not by_index["SRC-0008"]["disposition"]
assert by_index["SRC-0009"]["status"] == "CLOSED"
assert not by_index["SRC-0009"]["disposition"]
assert by_index["SRC-0015"]["status"] == "CLOSED"
assert not by_index["SRC-0015"]["disposition"]
assert by_index["SRC-0026"]["status"] == "CLOSED"
assert not by_index["SRC-0026"]["disposition"]
assert by_index["SRC-0034"]["status"] == "CLOSED"
assert not by_index["SRC-0034"]["disposition"]
assert by_index["SRC-0040"]["status"] == "CLOSED"
assert not by_index["SRC-0040"]["disposition"]

adapter_kinds = {row["parameter_kind"] for row in adapters}
assert {"sysctl", "file-mode-owner", "kernel-cmdline", "user-cron-files-mode", "standard-system-paths-mode", "suid-sgid-applications", "home-sensitive-files-mode", "home-directories-mode", "sshd-root-login", "pam-wheel-access", "sudoers-reviewed-policy", "tested-setting-attestation", "running-process-paths-write-protection", "cron-command-paths-write-protection", "sudo-root-command-files-protection", "startup-files-write-protection"} <= adapter_kinds
assert (ROOT / "product/generate-product-check-v1.py").is_file()
assert (ROOT / "product/generate-product-check-v2.py").is_file()
assert (ROOT / "securelinux-policy.sh").is_file()
assert (ROOT / "securelinux-policy.sh.sha256").is_file()

current = pmap.split("## 6. Где мы находимся", 1)[1].split(
    "## Что является источником истины", 1
)[0]
assert current.count(":::current") == 1
# Milestone/source identities are semantic; presentation wording may be Russian.
for marker in (
    "SRC-0005 / 2.3.1", "CHECK-11", "CHECK-17", "SRC-0040 / 2.6.6",
    "CHECK-18", "SRC-0033 / 2.5.10", "CHECK-19", "CHECK-28",
    "securelinux-policy.sh", "fstec-linux-2022 CHECK COMPLETE",
    "fstec-linux-2022-check-complete-v1", "DONOR_TO_V3_MAPPING",
    "ACCEPTED + COMMITTED", "1db91b0", "APPLY semantic contract",
    "EXTERNAL SNAPSHOT",
):
    assert marker in current, marker
assert "МЫ ЗДЕСЬ<br/>APPLY semantic contract" in current
assert "RESTORE исключён" in current
assert "МЫ ЗДЕСЬ<br/>Step 7B" not in current

with (ROOT / "docs/ROADMAP-v3.tsv").open(encoding="utf-8", newline="") as stream:
    rows = list(csv.DictReader(stream, delimiter="\t"))
by_id = {row["step_id"]: row["status"] for row in rows}
assert by_id["SOURCE_BLOCK_REGENERATION_PARITY"] == "CLOSED"
assert by_id["FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS"] == "PAUSED_BY_CURRENT_DOCUMENT_APPLY"
assert by_id["APPLY_SEMANTIC_CONTRACT"] == "NEXT"
assert "PAUSED_BY_CURRENT_DOCUMENT_APPLY" in roadmap
assert "единственный текущий" in roadmap
assert "APPLY semantic contract" in roadmap

print("SOURCE_PROGRESS_CONTRACT=PASS_EXACT_SIX_KEYS negative_fixtures=3")
print(
    "CURRENT_STATUS_CONSISTENCY=PASS "
    f"source_rows={total} closed={controlled} open={open_rows} "
    f"controls={len(controls)} adapters={len(adapters)}"
)
