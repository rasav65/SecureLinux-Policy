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
    "APPLY_SEMANTIC_CONTRACT",
    "APPLY_IMPLEMENTATION_ADAPTERS",
    "FINAL_DETERMINISTIC_PACKAGING",
    "SINGLE_DISTRIBUTABLE_ARTIFACT",
]
assert [r["step_id"] for r in rows] == expected
assert rows[0]["status"] == "CLOSED"
assert rows[1]["status"] == "CLOSED"
assert rows[2]["status"] == "CLOSED"
assert rows[3]["status"] == "CLOSED"
assert rows[4]["status"] == "CLOSED"
assert rows[5]["status"] == "CLOSED"
assert rows[6]["status"] == "NEXT"
assert all(r["status"] == "BLOCKED_BY_PREVIOUS" for r in rows[7:])
roadmap_md = (root / "docs/ROADMAP-v3.md").read_text(encoding="utf-8")
assert "Единый распространяемый `securelinux-ng.sh`" not in roadmap_md
assert "APPLY implementation adapters" in roadmap_md
assert "пользовательский режим RESTORE не входит в целевую архитектуру" in roadmap_md
assert "external snapshot" in roadmap_md
assert "Единый распространяемый артефакт (имя не закреплено)" in roadmap_md
print("ROADMAP_V3_ORDER=PASS")
