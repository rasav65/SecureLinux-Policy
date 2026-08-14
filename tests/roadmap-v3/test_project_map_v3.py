#!/usr/bin/env python3
from pathlib import Path

root=Path(__file__).resolve().parents[2]
text=(root/"docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")

assert text.count("```mermaid")==4
assert text.count(":::current")==1

for marker in (
    "index/source-v4",
    "349 строк",
    "5 controlled CLOSED",
    "344 OPEN",
    "schema_generation_parity",
    "Gate 6",
    "evidence_binding",
    "FSTEC core",
    "corporate",
    "DONOR_TO_V3_MAPPING",
    "REUSE / ADAPT / REJECT / DEFER",
    "deterministic build",
    "МЫ ЗДЕСЬ",
    "type/boolean",
    "securelinux-ng.sh",
):
    assert marker in text, marker

readme=(root/"README.md").read_text(encoding="utf-8")
assert "docs/PROJECT-MAP-v3.md" in readme

legacy=(root/"docs/ARCHITECTURE-DIAGRAMS.md").read_text(encoding="utf-8")
assert "donor runtime reference" in legacy
assert "PROJECT-MAP-v3.md" in legacy

print("PROJECT_MAP_V3=PASS mermaid_blocks=4 current_nodes=1")
