#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
text = (root / "docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")
readme = (root / "README.md").read_text(encoding="utf-8")

assert "основная архитектурная карта текущего SecureLinux-Policy v3" in text
assert "engineering donor" in text
assert "<!-- BEGIN GENERATED MAP STATUS -->" in text
assert "docs/fstec-coverage.md" in text
assert "docs/policy-layers.md" in text
assert "docs/compatibility.md" in text

# Structural branches worth preserving. Diagram count, exact labels and current
# numeric population are intentionally not contractual here.
for marker in (
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

assert text.count(":::current") == 1
assert "Gate 0 PASS" in text
assert "только byte-generation parity" in text
assert "docs/PROJECT-MAP-v3.md" in readme
print("PROJECT_MAP_V3=PASS primary=1 current_nodes=1 machine_status_block=1")
