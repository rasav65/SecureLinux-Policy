#!/usr/bin/env python3
from pathlib import Path
import csv

ROOT = Path(__file__).resolve().parents[2]

readme = (ROOT / "README.md").read_text(encoding="utf-8")
roadmap = (ROOT / "docs/ROADMAP-v3.md").read_text(encoding="utf-8")
pmap = (ROOT / "docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")

assert "Текущая активная стадия: **type/boolean contract cleanup**." in readme
assert "The current authorized engineering step is `type/boolean contract cleanup`." in readme
assert "The next authorized engineering step is Gate 6 `evidence_binding`." not in readme
assert "NEXT: Gate 6 `evidence_binding`." not in roadmap
assert "NEXT: type/boolean contract cleanup." in roadmap

with (ROOT / "docs/ROADMAP-v3.tsv").open(encoding="utf-8", newline="") as f:
    rows = list(csv.DictReader(f, delimiter="\t"))
by_id = {r["step_id"]: r["status"] for r in rows}

assert by_id["STEP5_AUDIT_PROVENANCE_CLOSURE"] == "CLOSED"
assert by_id["GATE6_EVIDENCE_BINDING"] == "CLOSED"
assert by_id["TYPE_BOOLEAN_CONTRACT_CLEANUP"] == "NEXT"
assert pmap.count(":::current") == 1

print("CURRENT_STATUS_CONSISTENCY=PASS next=TYPE_BOOLEAN_CONTRACT_CLEANUP")
