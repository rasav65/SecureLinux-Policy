#!/usr/bin/env python3
from pathlib import Path
import csv

root = Path(__file__).resolve().parents[2]
text = (root / "docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")
readme = (root / "README.md").read_text(encoding="utf-8")

assert "основная архитектурная карта текущего SecureLinux-Policy v3" in text
assert "engineering donor" in text

with (root / "index/source-v4/SOURCE-INDEX.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    index_rows = list(csv.DictReader(stream, delimiter="\t"))
with (root / "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    controls = list(csv.DictReader(stream, delimiter="\t"))

total = len(index_rows)
closed = sum(
    row["status"] == "CLOSED" and not row["disposition"] for row in index_rows
)
open_rows = sum(row["status"] == "OPEN" for row in index_rows)

for marker in (
    f"{total} rows",
    f"{closed} controlled CLOSED",
    f"{open_rows} OPEN",
    f"{len(controls)} current controls",
    "raw-pdftotext",
    "raw-glyph-recovered",
    "sources/recovered-v1/norm-v1",
    "SOURCE-INDEX.text_quality",
    "CLOSURE-CONTRACT.tsv",
    "Draft202012Validator",
    "source skeleton generator",
    "source-block parity",
    "DONOR_TO_V3_MAPPING",
    "REUSE / ADAPT / REJECT / DEFER",
    "product/ADAPTER-REGISTRY.tsv",
    "product-sysctl-check-v1",
    "product-file-mode-owner-check-v1",
    "product/generate-product-check-v1.py",
    "NON_RELEASE_PRODUCT_CANDIDATE",
):
    assert marker in text, marker

# There is one macro-roadmap current node. Diagram count and exact node labels
# are intentionally not contractual.
assert text.count(":::current") == 1

# Gate 0 remains generation parity, not semantic parity.
assert "Gate 0 PASS" in text
assert "только byte-generation parity" in text

assert "docs/PROJECT-MAP-v3.md" in readme
print(
    "PROJECT_MAP_V3=PASS "
    f"source_rows={total} closed={closed} open={open_rows} "
    f"controls={len(controls)} current_nodes=1"
)
