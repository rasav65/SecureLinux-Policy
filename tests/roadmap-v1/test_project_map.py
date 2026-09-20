#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
text = (root / "docs/PROJECT-MAP.md").read_text(encoding="utf-8")
readme = (root / "README.md").read_text(encoding="utf-8")

assert "основная архитектурная карта текущего SecureLinux-Policy.**" in text
assert "SecureLinux-Policy v3" not in text
# Реестр диспозиций заполнен; число закрытых строк — только в генерируемых блоках.
assert "0 реальных rows" not in text
assert "Реальных disposed-строк пока 0" not in text
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
    "product-file-mode-owner-check-v2",
    "product/generate-product-check-v1.py",
    "product/generate-product-check-v2.py",
    "securelinux-policy.sh",
    "NON_RELEASE_PRODUCT_CANDIDATE",
):
    assert marker in text, marker

# Current product CHECK components are implemented in the dedicated product line.
product_line = text.split("## 3. Текущая product-line: read-only CHECK + mechanism-oriented APPLY", 1)[1].split(
    "## 4. Инженерный донор", 1
)[0]
for marker in (
    'product-sysctl-check-v2<br/>read-only `eq` + integer `ge`"]:::closed',
    'product-file-mode-owner-check-v2<br/>read-only"]:::closed',
    'product/generate-product-check-v2.py<br/>текущий детерминированный generator"]:::closed',
    'product/APPLY-IMPLEMENTATION-REGISTRY.tsv<br/>exact binding активных механизмов"]:::closed',
    'config-line-with-runtime-v1<br/>sysctl · dry-run · APPLY<br/>ВМ: 1 среда PASS, приёмка 8 сред — впереди"]:::current',
    'file-mode-owner-v1<br/>режимы файлов SRC-0005 · APPLY<br/>ВМ: 1 среда PASS, приёмка 8 сред — впереди"]:::current',
    'optional-file-root-files-mode-v1<br/>режимы cron SRC-0010 · APPLY<br/>ВМ: 1 среда PASS, приёмка 8 сред — впереди"]:::current',
    'suid-sgid-applications-mode-v1<br/>режимы SUID/SGID SRC-0013 · APPLY<br/>ВМ-прогона ещё нет"]:::current',
    'ADMIN["граница продукта<br/>APPLY не реализуется по решению<br/>решение администратору, пример: suid-dumpable при Apport"]:::note',
    'securelinux-policy.sh<br/>tracked CHECK + mechanism-oriented APPLY CLI<br/>NON_RELEASE_PRODUCT_CANDIDATE"]:::closed',
):
    assert marker in product_line, marker
# B4: status of a mechanism node is defined by gates, not by prose.
assert "`closed` — механизм прошёл `--release` и восьмисредовый VM-цикл" in product_line
assert "`current` — идёт работа. Иного статуса у узла механизма нет." in product_line
assert "APPLY1" in product_line and ":::closed" not in product_line.split('APPLY1["', 1)[1].split("\n", 1)[0]
# B1: mechanism prose names mechanisms, not live control counts.
for stale_count in ("17 sysctl", "3 controls SRC-0005", "итого 20", "активны 17", "(3 контроля SRC-0005)"):
    assert stale_count not in text, stale_count

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
assert "active APPLY registries" in current
assert "predicate / transform definitions" in current
assert "AUTHORITY_2026_REFRESH" in current
assert "PAUSED_BY_CURRENT_DOCUMENT_APPLY" not in current
assert "восьмисредовый VM-cycle" in current
assert "Step 7B · расширение FSTEC" in current
assert "HORIZON1_SAFE_CLASS_APPLY_AND_VM_RUNS" in current
assert "Step 7B возвращён в `NEXT`" not in current
assert 'P4["SRC-0005 / 2.3.1<br/>3 canonical file-mode controls<br/>ГОТОВО"]:::closed' in current
assert 'P5["CHECK-11<br/>регенерация + read-only запуск<br/>ГОТОВО"]:::closed' in current
assert 'P6["batch sysctl exact-eq<br/>SRC-0030,0031,0036–0039 + CHECK-17<br/>ГОТОВО"]:::closed' in current
assert 'P7["SRC-0040 / 2.6.6<br/>исправление terminal source-boundary + CHECK-18<br/>ГОТОВО"]:::closed' in current
assert 'P8["SRC-0033 / 2.5.10<br/>sysctl lower-bound `ge 4096` + CHECK-19<br/>ГОТОВО"]:::closed' in current
assert 'P9["batch kernel-cmdline exact-token<br/>7 source rows · 9 controls + CHECK-28<br/>ГОТОВО"]:::closed' in current
assert 'P9B["ЕДИНЫЙ CLI / БЫСТРЫЙ СТАРТ v1<br/>securelinux-policy.sh · pretty/raw/json<br/>ГОТОВО"]:::closed' in current
assert 'P10["fstec-linux-2022 CHECK COMPLETE<br/>tag fstec-linux-2022-check-complete-v1<br/>ГОТОВО"]:::closed' in current
assert 'P10A["DONOR_TO_V3_MAPPING<br/>ACCEPTED + COMMITTED<br/>1db91b0…<br/>ГОТОВО"]:::closed' in current
assert 'P11["APPLY parent gate<br/>ПРИНЯТО<br/>SRC-0001 flat contract candidate: REVISE"]:::note' in current
assert 'P12["AUTHORITY_2026_REFRESH<br/>приказы № 117 + № 137<br/>ГОТОВО"]:::closed' in current
assert 'P13["SRC-0001 modular APPLY contract architecture<br/>compact registry + SHA bindings<br/>ГОТОВО"]:::closed' in current
assert 'P14["SRC-0001 predicate / transform definitions<br/>exact empty + exact bang<br/>ГОТОВО"]:::closed' in current
assert 'P15["SRC-0001 external snapshot precondition<br/>exact attestation + prestate binding<br/>ГОТОВО"]:::closed' in current
assert 'P16["SRC-0001 lock/reread + object identity<br/>stale + path identity fail-closed<br/>ГОТОВО"]:::closed' in current
assert 'P17["SRC-0001 метаданные/транзакция/отчёт<br/>8 определений + композиция<br/>ГОТОВО"]:::closed' in current
assert 'P18["APPLY для SRC-0001<br/>ОДНА ВЕРТИКАЛЬ<br/>ГОТОВО"]:::closed' in current
assert 'P19["финальная детерминированная упаковка<br/>ГОТОВО"]:::closed' in current
assert 'P20["единый распространяемый артефакт<br/>ГОТОВО"]:::closed' in current
assert 'P21["МЫ ЗДЕСЬ<br/>горизонт 1 · APPLY безопасных классов + ВМ"]:::current' in current
assert 'P22["Step 7B · расширение FSTEC<br/>ждёт закрытия горизонта 1"]:::future' in current
assert 'P18["адаптеры реализации APPLY<br/>заблокировано до semantic chain"]:::future' not in current
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
    "APPLY parent gate",
    "AUTHORITY_2026_REFRESH",
    "SRC-0001 modular APPLY contract architecture",
    "SRC-0001 predicate / transform definitions",
    "SRC-0001 external snapshot precondition",
    "SRC-0001 lock/reread + object identity",
    "SRC-0001 метаданные/транзакция/отчёт",
    "APPLY для SRC-0001",
    "финальная детерминированная упаковка",
    "единый распространяемый артефакт",
    "горизонт 1 · APPLY безопасных классов + ВМ",
    "Step 7B · расширение FSTEC",
    "ВНЕШНИЙ СНИМОК",
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
    "APPLY parent gate",
    "AUTHORITY_2026_REFRESH",
    "SRC-0001 modular APPLY contract architecture",
    "SRC-0001 predicate / transform definitions",
    "SRC-0001 external snapshot precondition",
    "SRC-0001 lock/reread + object identity",
    "SRC-0001 метаданные/транзакция/отчёт",
    "APPLY для SRC-0001",
    "финальная детерминированная упаковка",
    "единый распространяемый артефакт",
    "горизонт 1 · APPLY безопасных классов + ВМ",
    "Step 7B · расширение FSTEC",
)]
assert positions == sorted(positions)

for stale in (
    "МЫ ЗДЕСЬ<br/>единый распространяемый артефакт",
    "МЫ ЗДЕСЬ<br/>Step 7B · расширение FSTEC",
    'implementation<br/>adapters"]:::future',
    'deterministic<br/>build"]:::future',
    "single distributable<br/>securelinux-ng.sh",
):
    assert stale not in current, stale

assert "путь к конечному `securelinux-ng.sh`" not in text
assert "Финальный `securelinux-ng.sh`" not in text
assert "итоговый распространяемый артефакт" in text
assert "tracked CHECK + mechanism-oriented APPLY CLI" in text
assert "Gate 0 PASS" in text
assert "только byte-generation parity" in text
assert "docs/PROJECT-MAP.md" in readme

# B6: deliberately deferred directions are named with their reason.
deferred = text.split("## Отложено сознательно", 1)[1]
for marker in ("SRC-0008", "kernel cmdline", "G3", "G5", "инвентарь механизмов"):
    assert marker in deferred, marker
# Карта сегментации контролей fstec-linux-2022 (принята 19.09.2026): классы
# G1–G7 покрывают population CONTROL-MANIFEST ровно один раз, колонка
# «APPLY сейчас» совпадает с apply.supported контролей. Счётчики не пинуются.
import csv as _csv
_ctrl_dir = root / "controls/fstec-core/linux-2022"
with (_ctrl_dir / "CONTROL-MANIFEST.tsv").open(encoding="utf-8", newline="") as _f:
    _manifest = list(_csv.DictReader(_f, delimiter="\t"))
_supported = {
    row["control_id"]: "\napply:\n  supported: true\n" in (_ctrl_dir / row["file"]).read_text(encoding="utf-8")
    for row in _manifest
}
_seg = text.split("## Карта сегментации контролей fstec-linux-2022", 1)[1].split("\n## ", 1)[0]
_rows = [line for line in _seg.splitlines() if line.startswith("| G")]
_classes = [line.split("|")[1].strip() for line in _rows]
# Класс может занимать несколько соседних строк (например, часть класса уже с
# APPLY, часть без); вразброс класс не повторяется.
_class_order = [c for i, c in enumerate(_classes) if i == 0 or _classes[i - 1] != c]
assert _class_order == ["G1", "G2", "G3", "G4", "G5", "G6", "G7"], _classes
# Определение класса G6 закреплено литералом: меняется только явным решением
# при принятии нового механизма или популяции этого класса; повторяется в каждой
# строке класса.
_G6_DEFINITION = (
    "режимы файлов по вычисляемой стабильной популяции (системные корни cron, "
    "SUID/SGID-файлы всех непсевдо-точек монтирования), только снятие битов"
)
_g6_definitions = [line.split("|")[2].strip() for line in _rows if line.split("|")[1].strip() == "G6"]
assert _g6_definitions and all(d == _G6_DEFINITION for d in _g6_definitions), _g6_definitions
_seen = []
for line in _rows:
    cells = [c.strip() for c in line.split("|")[1:-1]]
    ids = [x.strip().strip("`") for x in cells[2].split(",")]
    apply_now = cells[3].split()[0]
    assert apply_now in ("да", "нет"), line
    for cid in ids:
        assert cid in _supported, cid
        assert _supported[cid] == (apply_now == "да"), (cid, apply_now)
    _seen.extend(ids)
assert sorted(_seen) == sorted(_supported), sorted(set(_supported) ^ set(_seen))
assert len(_seen) == len(set(_seen)), "control in more than one class"

print(
    "PROJECT_MAP_V3=PASS primary=1 current_checkpoint=horizon1-safe-class-apply "
    "src0005_check11_done=1 exact_eq_check17_done=1 src0040_check18_done=1 "
    "src0033_check19_done=1 kernel_cmdline_check28_done=1 unified_cli_done=1 src0001_apply_done=1 restore_out_of_scope=1"
)
