#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
text = (root / "docs/ARCHITECTURE-DIAGRAMS.md").read_text(encoding="utf-8")
readme = (root / "README.md").read_text(encoding="utf-8")

# This file is a donor/future runtime reference, not the primary current map.
assert "donor runtime reference" in text
assert "PROJECT-MAP-v3.md" in text
assert "не являются источником текущего статуса" in text

# Preserve the engineering concepts worth carrying forward without pinning
# diagram count, node labels or line wrapping.
for marker in (
    "manifest_init()",
    "backup_file_checked()",
    "--restore",
    "DONOR_TO_V3_MAPPING",
    "apply/restore semantic contract",
):
    assert marker in text, marker

assert "docs/ARCHITECTURE-DIAGRAMS.md" in readme
print("ARCHITECTURE_DIAGRAMS=PASS role=donor_runtime_reference semantic_markers=5")
