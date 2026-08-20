#!/usr/bin/env python3
from pathlib import Path
import csv

root = Path(__file__).resolve().parents[2]
policy = (root / "docs/DONOR-V3-ADOPTION-POLICY.md").read_text(encoding="utf-8")
roadmap = (root / "docs/ROADMAP-v3.md").read_text(encoding="utf-8")

for marker in (
    "engineering donor",
    "DONOR_TO_V3_MAPPING",
    "REUSE`, `ADAPT`, `REJECT`, or `DEFER",
    "apply/restore semantic contract",
    "deterministic build artifact",
    "`control_id`",
    "`quote_sha256`",
):
    assert marker in policy, marker

# Donor adoption never acts as normative closure.
assert "mapping itself closes zero source-index rows" in policy
assert "The mapping is engineering provenance. It is not normative evidence." in policy

# Roadmap must retain the donor precondition, but wording is not pinned.
assert "DONOR_TO_V3_MAPPING" in roadmap
assert "docs/DONOR-V3-ADOPTION-POLICY.md" in roadmap
assert "0 строк FSTEC" in roadmap or "закрывает 0 строк" in roadmap

with (root / "docs/ROADMAP-v3.tsv").open(encoding="utf-8", newline="") as stream:
    rows = list(csv.DictReader(stream, delimiter="\t"))
orders = [int(row["order"]) for row in rows]
assert orders == list(range(1, len(rows) + 1))
assert rows[7]["step_id"] == "APPLY_RESTORE_SEMANTIC_CONTRACT"
assert rows[7]["status"] == "BLOCKED_BY_PREVIOUS"

print("DONOR_V3_POLICY=PASS donor_is_non_normative=1 roadmap_precondition=1")
