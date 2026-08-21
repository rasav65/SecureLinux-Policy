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
assert by_index["SRC-0026"]["status"] == "CLOSED"
assert not by_index["SRC-0026"]["disposition"]
assert by_index["SRC-0034"]["status"] == "CLOSED"
assert not by_index["SRC-0034"]["disposition"]
assert by_index["SRC-0040"]["status"] == "CLOSED"
assert not by_index["SRC-0040"]["disposition"]

adapter_kinds = {row["parameter_kind"] for row in adapters}
assert {"sysctl", "file-mode-owner", "kernel-cmdline", "user-cron-files-mode", "standard-system-paths-mode", "suid-sgid-applications", "home-sensitive-files-mode"} <= adapter_kinds
assert (ROOT / "product/generate-product-check-v1.py").is_file()

current = pmap.split("## 6. Где мы находимся", 1)[1].split(
    "## Что является источником истины", 1
)[0]
assert current.count(":::current") == 1
assert "SRC-0005 / 2.3.1" in current
assert "3 canonical file-mode controls" in current
assert "CHECK-11" in current
assert "sysctl exact-eq batch" in current
assert "CHECK-17" in current
assert "SRC-0040 / 2.6.6" in current
assert "terminal source-boundary fix + CHECK-18" in current
assert "SRC-0033 / 2.5.10" in current
assert "sysctl lower-bound ge 4096 + CHECK-19" in current
assert "kernel-cmdline exact-token batch" in current
assert "7 source rows · 9 controls + CHECK-28" in current
assert "systematic FSTEC expansion" in current
assert "МЫ ЗДЕСЬ<br/>systematic FSTEC expansion" in current
assert "МЫ ЗДЕСЬ<br/>Step 7B" not in current

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
