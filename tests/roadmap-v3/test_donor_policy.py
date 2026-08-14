#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
policy = (root / "docs/DONOR-V3-ADOPTION-POLICY.md").read_text(encoding="utf-8")
roadmap = (root / "docs/ROADMAP-v3.md").read_text(encoding="utf-8")

required_policy = [
    "engineering donor",
    "REUSE`, `ADAPT`, `REJECT`, or `DEFER",
    "DONOR_TO_V3_MAPPING",
    "mapping itself closes zero source-index rows",
    "apply/restore semantic contract",
    "deterministic build artifact",
    "`control_id`",
    "`quote_sha256`",
]
for marker in required_policy:
    assert marker in policy, marker

required_roadmap = [
    "DONOR_TO_V3_MAPPING",
    "docs/DONOR-V3-ADOPTION-POLICY.md",
    "mapping itself closes zero FSTEC or",
]
for marker in required_roadmap:
    assert marker in roadmap, marker

# Exact roadmap order remains unchanged.
order = [
    "1. Step 5 audit provenance closure",
    "2. Gate 6 `evidence_binding`",
    "3. type/boolean contract cleanup",
    "4. mandatory real-jsonschema release gate",
    "5. index-generic source skeleton generator",
    "6. source-block regeneration parity gate",
    "7. FSTEC + corporate index expansion / dispositions",
    "8. apply/restore semantic contract",
    "9. implementation adapters",
    "10. deterministic build",
    "11. single distributable `securelinux-ng.sh`",
]
positions = [roadmap.index(x) for x in order]
assert positions == sorted(positions)

print("DONOR_V3_POLICY=PASS")
