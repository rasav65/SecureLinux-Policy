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

# Current product CHECK components are implemented in the dedicated product line.
product_line = text.split("## 3. Текущая read-only product-line CHECK", 1)[1].split(
    "## 4. Инженерный донор", 1
)[0]
for marker in (
    'product-sysctl-check-v1<br/>read-only"]:::closed',
    'product-file-mode-owner-check-v1<br/>read-only"]:::closed',
    'tracked deterministic generator"]:::closed',
    'generated CHECK<br/>current manifest population<br/>NON_RELEASE_PRODUCT_CANDIDATE"]:::closed',
):
    assert marker in product_line, marker

# "Где мы" is a product checkpoint, not a replay of old macro-roadmap labels.
current = text.split("## 6. Где мы находимся", 1)[1].split(
    "## Что является источником истины", 1
)[0]
assert current.count(":::current") == 1
assert 'P4["SRC-0005 / 2.3.1<br/>3 canonical file-mode controls<br/>DONE"]:::closed' in current
assert 'P5["CHECK-11<br/>regenerate + read-only run<br/>DONE"]:::closed' in current
assert 'P6["sysctl exact-eq batch<br/>SRC-0030,0031,0036–0039 + CHECK-17<br/>DONE"]:::closed' in current
assert 'P7["МЫ ЗДЕСЬ<br/>systematic FSTEC expansion<br/>remaining OPEN rows"]:::current' in current
for marker in (
    "CHECK-8 product-line",
    "TEST BASELINE",
    "DOCUMENTATION BASELINE",
    "SRC-0005 / 2.3.1",
    "3 canonical file-mode controls",
    "CHECK-11",
    "sysctl exact-eq batch",
    "CHECK-17",
    "systematic FSTEC expansion",
    "APPLY semantic contract",
    "APPLY implementation",
    "RESTORE contract + implementation",
    "final distributable artifact",
):
    assert marker in current, marker

positions = [current.index(marker) for marker in (
    "CHECK-8 product-line",
    "TEST BASELINE",
    "DOCUMENTATION BASELINE",
    "SRC-0005 / 2.3.1",
    "CHECK-11",
    "sysctl exact-eq batch",
    "CHECK-17",
    "systematic FSTEC expansion",
    "APPLY semantic contract",
    "APPLY implementation",
    "RESTORE contract + implementation",
    "final distributable artifact",
)]
assert positions == sorted(positions)

for stale in (
    "МЫ ЗДЕСЬ<br/>Step 7B",
    'implementation<br/>adapters"]:::future',
    'deterministic<br/>build"]:::future',
    "single distributable<br/>securelinux-ng.sh",
):
    assert stale not in current, stale

assert "путь к конечному `securelinux-ng.sh`" not in text
assert "Финальный `securelinux-ng.sh`" not in text
assert "future final<br/>distributable artifact" in text
assert "Gate 0 PASS" in text
assert "только byte-generation parity" in text
assert "docs/PROJECT-MAP-v3.md" in readme
print(
    "PROJECT_MAP_V3=PASS primary=1 current_checkpoint=systematic-expansion "
    "src0005_check11_done=1 exact_eq_check17_done=1 future_apply_restore=1"
)
