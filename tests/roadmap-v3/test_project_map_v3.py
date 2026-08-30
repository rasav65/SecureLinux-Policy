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
    "generator source skeleton",
    "parity source-block",
    "DONOR_TO_V3_MAPPING",
    "REUSE / ADAPT / REJECT / DEFER",
    "product/ADAPTER-REGISTRY.tsv",
    "product-sysctl-check-v2",
    "product-file-mode-owner-check-v1",
    "product/generate-product-check-v1.py",
    "product/generate-product-check-v2.py",
    "securelinux-policy.sh",
    "NON_RELEASE_PRODUCT_CANDIDATE",
):
    assert marker in text, marker

# Current product CHECK components are implemented in the dedicated product line.
product_line = text.split("## 3. Текущая read-only product-line CHECK", 1)[1].split(
    "## 4. Инженерный донор", 1
)[0]
for marker in (
    'product-sysctl-check-v2<br/>read-only `eq` + integer `ge`"]:::closed',
    'product-file-mode-owner-check-v1<br/>read-only"]:::closed',
    'product/generate-product-check-v2.py<br/>текущий детерминированный generator"]:::closed',
    'securelinux-policy.sh<br/>tracked единый read-only CLI<br/>NON_RELEASE_PRODUCT_CANDIDATE<br/>pretty · raw · JSON"]:::closed',
):
    assert marker in product_line, marker

# Accepted mapping must be represented as closed, not as future work.
donor_runtime = text.split("## 4. Инженерный донор", 1)[1].split(
    "## 5. Provenance", 1
)[0]
assert 'MAP["DONOR_TO_V3_MAPPING<br/>ACCEPTED + COMMITTED<br/>REUSE / ADAPT / REJECT / DEFER"]:::closed' in donor_runtime
assert 'MAP["DONOR_TO_V3_MAPPING<br/>REUSE / ADAPT / REJECT / DEFER"]:::future' not in donor_runtime
assert 'classDef closed fill:#d9f7df' in donor_runtime

# "Где мы" is a product checkpoint, not a replay of old macro-roadmap labels.
current = text.split("## 6. Где мы находимся", 1)[1].split(
    "## Что является источником истины", 1
)[0]
assert current.count(":::current") == 1
assert "текущий substantive checkpoint — отдельный `APPLY semantic contract`" in current
assert "PAUSED_BY_CURRENT_DOCUMENT_APPLY" in current
assert "текущий product checkpoint внутри макроэтапа Step 7B" not in current
assert "Step 7B разрешён" not in current
assert 'P4["SRC-0005 / 2.3.1<br/>3 canonical file-mode controls<br/>ГОТОВО"]:::closed' in current
assert 'P5["CHECK-11<br/>регенерация + read-only запуск<br/>ГОТОВО"]:::closed' in current
assert 'P6["batch sysctl exact-eq<br/>SRC-0030,0031,0036–0039 + CHECK-17<br/>ГОТОВО"]:::closed' in current
assert 'P7["SRC-0040 / 2.6.6<br/>исправление terminal source-boundary + CHECK-18<br/>ГОТОВО"]:::closed' in current
assert 'P8["SRC-0033 / 2.5.10<br/>sysctl lower-bound `ge 4096` + CHECK-19<br/>ГОТОВО"]:::closed' in current
assert 'P9["batch kernel-cmdline exact-token<br/>7 source rows · 9 controls + CHECK-28<br/>ГОТОВО"]:::closed' in current
assert 'P9B["ЕДИНЫЙ CLI / БЫСТРЫЙ СТАРТ v1<br/>securelinux-policy.sh · pretty/raw/json<br/>ГОТОВО"]:::closed' in current
assert 'P10["fstec-linux-2022 CHECK COMPLETE<br/>tag fstec-linux-2022-check-complete-v1<br/>ГОТОВО"]:::closed' in current
assert 'P10A["DONOR_TO_V3_MAPPING<br/>ACCEPTED + COMMITTED<br/>1db91b0…<br/>ГОТОВО"]:::closed' in current
assert 'P11["МЫ ЗДЕСЬ<br/>APPLY semantic contract<br/>СЛЕДУЮЩИЙ SUBSTANTIVE ЭТАП"]:::current' in current
diagram = current.split("```mermaid", 1)[1].split("```", 1)[0]
for marker in (
    "CHECK-8 product-line",
    "БАЗОВЫЙ НАБОР ТЕСТОВ",
    "БАЗОВАЯ ДОКУМЕНТАЦИЯ",
    "SRC-0005 / 2.3.1",
    "3 canonical file-mode controls",
    "CHECK-11",
    "batch sysctl exact-eq",
    "CHECK-17",
    "SRC-0040 / 2.6.6",
    "CHECK-18",
    "SRC-0033 / 2.5.10",
    "CHECK-19",
    "batch kernel-cmdline exact-token",
    "CHECK-28",
    "ЕДИНЫЙ CLI / БЫСТРЫЙ СТАРТ v1",
    "securelinux-policy.sh · pretty/raw/json",
    "fstec-linux-2022 CHECK COMPLETE",
    "DONOR_TO_V3_MAPPING",
    "APPLY semantic contract",
    "APPLY implementation",
    "итоговый distributable artifact",
    "EXTERNAL SNAPSHOT",
):
    assert marker in current, marker

positions = [diagram.index(marker) for marker in (
    "CHECK-8 product-line",
    "БАЗОВЫЙ НАБОР ТЕСТОВ",
    "БАЗОВАЯ ДОКУМЕНТАЦИЯ",
    "SRC-0005 / 2.3.1",
    "CHECK-11",
    "batch sysctl exact-eq",
    "CHECK-17",
    "SRC-0040 / 2.6.6",
    "CHECK-18",
    "SRC-0033 / 2.5.10",
    "CHECK-19",
    "batch kernel-cmdline exact-token",
    "CHECK-28",
    "ЕДИНЫЙ CLI / БЫСТРЫЙ СТАРТ v1",
    "securelinux-policy.sh · pretty/raw/json",
    "fstec-linux-2022 CHECK COMPLETE",
    "DONOR_TO_V3_MAPPING",
    "APPLY semantic contract",
    "APPLY implementation",
    "итоговый distributable artifact",
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
assert "итоговый distributable artifact" in text
assert "tracked единый read-only CLI" in text
assert "Gate 0 PASS" in text
assert "только byte-generation parity" in text
assert "docs/PROJECT-MAP-v3.md" in readme
print(
    "PROJECT_MAP_V3=PASS primary=1 current_checkpoint=apply-semantic-contract "
    "src0005_check11_done=1 exact_eq_check17_done=1 src0040_check18_done=1 "
    "src0033_check19_done=1 kernel_cmdline_check28_done=1 unified_cli_done=1 future_apply=1 restore_out_of_scope=1"
)
