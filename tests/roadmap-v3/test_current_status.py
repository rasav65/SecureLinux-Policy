#!/usr/bin/env python3
from pathlib import Path
import csv

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
for marker in (
    f"source rows={total}",
    f"controlled CLOSED={controlled}",
    f"OPEN={open_rows}",
    f"canonical controls={len(controls)}",
    f"adapters={len(adapters)}",
):
    assert marker in pmap, marker

for path in (
    "docs/PROJECT-MAP-v3.md",
    "docs/policy-layers.md",
    "docs/fstec-coverage.md",
    "docs/compatibility.md",
):
    assert path in readme, path

with (ROOT / "docs/ROADMAP-v3.tsv").open(encoding="utf-8", newline="") as stream:
    rows = list(csv.DictReader(stream, delimiter="\t"))
by_id = {row["step_id"]: row["status"] for row in rows}
assert by_id["SOURCE_BLOCK_REGENERATION_PARITY"] == "CLOSED"
assert by_id["FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS"] == "NEXT"
assert "Step 7B" in roadmap

print(
    "CURRENT_STATUS_CONSISTENCY=PASS "
    f"source_rows={total} closed={controlled} open={open_rows} "
    f"controls={len(controls)} adapters={len(adapters)}"
)
