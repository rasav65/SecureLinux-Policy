#!/usr/bin/env python3
from pathlib import Path
import csv

ROOT = Path(__file__).resolve().parents[2]
readme = (ROOT / "README.md").read_text(encoding="utf-8")
roadmap = (ROOT / "docs/ROADMAP-v3.md").read_text(encoding="utf-8")
pmap = (ROOT / "docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")

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
open_rows = sum(row["status"] == "OPEN" for row in index_rows)

# README current-status facts must agree with machine truth.
assert f"TOTAL_INDEX_ROWS={total}" in readme
assert f"CLOSED_INDEX_ROWS={controlled}" in readme
assert f"OPEN_INDEX_ROWS={open_rows}" in readme
assert f"CLOSURE_RATIO={controlled}/{total}" in readme
assert "product/generate-product-check-v1.py" in readme
assert "ADAPTER-REGISTRY.tsv" in readme

# Primary map must show the same live population and current product line.
assert f"{total} rows" in pmap
assert f"{controlled} controlled CLOSED" in pmap
assert f"{open_rows} OPEN" in pmap
assert f"{len(controls)} current controls" in pmap
assert "product/ADAPTER-REGISTRY.tsv" in pmap
assert "product/generate-product-check-v1.py" in pmap
for row in adapters:
    assert row["adapter_id"] in pmap

# Macro-roadmap state remains machine-owned by ROADMAP-v3.tsv.
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
