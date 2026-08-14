#!/usr/bin/env python3
import csv
from pathlib import Path

root = Path(__file__).resolve().parents[2]
with (root / "docs/ROADMAP-v3.tsv").open(encoding="utf-8", newline="") as f:
    rows = list(csv.DictReader(f, delimiter="\t"))

expected = [
    "STEP5_AUDIT_PROVENANCE_CLOSURE",
    "GATE6_EVIDENCE_BINDING",
    "TYPE_BOOLEAN_CONTRACT_CLEANUP",
    "MANDATORY_REAL_JSONSCHEMA_RELEASE_GATE",
    "INDEX_GENERIC_SOURCE_SKELETON_GENERATOR",
    "SOURCE_BLOCK_REGENERATION_PARITY",
    "FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS",
    "APPLY_RESTORE_SEMANTIC_CONTRACT",
    "IMPLEMENTATION_ADAPTERS",
    "DETERMINISTIC_BUILD",
    "SINGLE_DISTRIBUTABLE_SECURELINUX_NG_SH",
]
assert [r["step_id"] for r in rows] == expected
assert rows[0]["status"] == "CLOSED"
assert rows[1]["status"] == "CLOSED_BY_THIS_CHANGE"
assert rows[2]["status"] == "NEXT"
assert all(r["status"] == "BLOCKED_BY_PREVIOUS" for r in rows[3:])
print("ROADMAP_V3_ORDER=PASS")
