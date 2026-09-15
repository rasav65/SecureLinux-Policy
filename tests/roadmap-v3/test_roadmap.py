#!/usr/bin/env python3
import csv
import re
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
    "AUTHORITY_2026_REFRESH",
    "SRC0001_MODULAR_APPLY_CONTRACT_ARCHITECTURE",
    "SRC0001_PREDICATE_TRANSFORM_DEFINITIONS",
    "SRC0001_SNAPSHOT_PRECONDITION_DEFINITION",
    "SRC0001_LOCK_REREAD_OBJECT_IDENTITY_DEFINITIONS",
    "SRC0001_METADATA_TRANSACTION_REPORT_DEFINITIONS",
    "APPLY_IMPLEMENTATION_ADAPTERS",
    "FINAL_DETERMINISTIC_PACKAGING",
    "SINGLE_DISTRIBUTABLE_ARTIFACT",
    "SRC0008_CHECK_SEMANTIC_REWORK",
]
assert [r["step_id"] for r in rows] == expected
assert rows[0]["status"] == "CLOSED"
assert rows[1]["status"] == "CLOSED"
assert rows[2]["status"] == "CLOSED"
assert rows[3]["status"] == "CLOSED"
assert rows[4]["status"] == "CLOSED"
assert rows[5]["status"] == "CLOSED"
assert rows[6]["status"] == "NEXT"
assert rows[7]["status"] == "PARENT_GATE_CLOSED_SOURCE_INSTANCE_REVISE"
assert rows[8]["status"] == "CLOSED"
assert rows[9]["status"] == "CLOSED"
assert rows[10]["status"] == "CLOSED"
assert rows[11]["status"] == "CLOSED"
assert rows[12]["status"] == "CLOSED"
assert rows[13]["status"] == "CLOSED"
assert rows[14]["status"] == "CLOSED"
assert rows[15]["status"] == "CLOSED"
assert rows[16]["status"] == "CLOSED"
assert rows[17]["status"] == "SEMANTIC_REWORK_IN_PROGRESS"
assert [r["step_id"] for r in rows if r["status"] == "NEXT"] == [
    "FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS"
]
with (root / "index/source-v4/SOURCE-INDEX.tsv").open(encoding="utf-8", newline="") as f:
    source_index_rows = list(csv.DictReader(f, delimiter="\t"))
roadmap_md = (root / "docs/ROADMAP-v3.md").read_text(encoding="utf-8")
project_map = (root / "docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")
disposition_doc = (root / "docs/disposition-ledger.md").read_text(encoding="utf-8")


def validate_markdown_order(text: str) -> None:
    intro = text.split("Неизменяемые правила:", 1)[0]
    numbered = {}
    for line in intro.splitlines():
        match = __import__("re").match(r"^(\d+)\.\s+(.+)$", line)
        if match:
            numbered[int(match.group(1))] = match.group(2).strip()
    assert numbered.get(9) == "Authority refresh 2026: приказ № 117 + изменения № 137", numbered.get(9)
    assert numbered.get(10) == "Модульная архитектура APPLY-contract для `SRC-0001`", numbered.get(10)
    assert numbered.get(11) == "Точные определения предиката и преобразования для `SRC-0001`", numbered.get(11)
    assert numbered.get(12) == "Определение условия внешнего снимка для `SRC-0001`", numbered.get(12)
    assert numbered.get(13) == "Определения блокировки, повторного чтения и идентичности объекта для `SRC-0001`", numbered.get(13)
    assert numbered.get(14) == "Определения метаданных, атомарной транзакции и сухого запуска с отчётом для `SRC-0001`", numbered.get(14)
    assert numbered.get(15) == "Адаптеры реализации APPLY", numbered.get(15)
    assert numbered.get(16) == "Детерминированная финальная упаковка", numbered.get(16)
    assert numbered.get(17) == "Единый распространяемый артефакт (имя не закреплено)", numbered.get(17)


def validate_current_checkpoint(roadmap_text: str, map_text: str, disposition_text: str) -> None:
    assert "DOCUMENT COMPLETE" in roadmap_text
    assert "FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS" in roadmap_text
    assert "Step 7B" in roadmap_text and "NEXT" in roadmap_text
    assert "МЫ ЗДЕСЬ<br/>Step 7B · расширение FSTEC" in map_text
    assert "PAUSED_BY_CURRENT_DOCUMENT_APPLY" not in roadmap_text
    assert "PAUSED_BY_CURRENT_DOCUMENT_APPLY" not in map_text
    assert "PAUSED_BY_CURRENT_DOCUMENT_APPLY" not in disposition_text
    assert "Step 7B generator API теперь различает `EXACT | REFUSED | UNSUPPORTED`" in disposition_text
    re_mod = __import__("re")
    for doc in (roadmap_text, map_text, disposition_text):
        for paragraph in re_mod.split(r"\n\s*\n", doc):
            if "Step 7B" not in paragraph or paragraph.lstrip().startswith("### Step 7B"):
                continue
            normalized = re_mod.sub(
                r"(?i)пауз\w*\s+Step\s+7B\s+снят\w*",
                "",
                paragraph,
            )
            for pattern in (
                r"(?i)приостанов\w*",
                r"(?i)отлож\w*",
                r"(?i)пауз\w*",
                r"PAUSED_BY_CURRENT_DOCUMENT_APPLY",
                r"(?i)до\s+DOCUMENT\s+COMPLETE",
            ):
                assert not re_mod.search(pattern, normalized), paragraph


def validate_apply_adapters_roadmap_identity(text: str) -> None:
    stage_ref = re.compile(
        r"(?i)(?:APPLY[^\n]{0,36}(?:adapter|адаптер)|(?:adapter|адаптер)\w*[^\n]{0,36}APPLY)"
    )
    cancellation = re.compile(
        r"(?i)(?:отмен\w*|упраздн\w*|больше\s+не\s+планир\w*|"
        r"не\s+планир\w*\s+в\s+будущ\w*|исключен\w*\s+из\s+(?:roadmap|плана)|"
        r"удален\w*\s+из\s+(?:roadmap|плана)|снят\w*\s+с\s+(?:roadmap|плана)|"
        r"не\s+предусмотрен\w*|не\s+будет\s+реализован\w*|не\s+предполагается|"
        r"не\s+входит\s+в(?:\s+(?:дальнейш\w*|будущ\w*))?\s+(?:работ\w*|план\w*|этап\w*)|"
        r"не\s+включен\w*\s+в(?:\s+(?:дальнейш\w*|будущ\w*))?\s+(?:работ\w*|план\w*|roadmap))"
    )
    for paragraph in re.split(r"\n\s*\n", text):
        if not stage_ref.search(paragraph):
            continue
        normalized = re.sub(r"(?i)не\s+отмен\w*", "", paragraph)
        assert not cancellation.search(normalized), paragraph


def validate_no_manual_live_population_counts(text: str) -> None:
    for line in text.splitlines():
        if re.match(r"^\s*\d+\.\s+", line):
            continue
        lower = line.lower()
        if not re.search(r"(?:current\s+controls?|adapter\s+kinds?|текущ\w*\s+контрол\w*|адаптер\w*)", lower):
            continue
        assert not re.search(r"\b\d+\b", line), line
        assert not re.search(
            r"(?i)\b(?:один|два|три|четыре|пять|шесть|семь|восемь|девять|десять|"
            r"сорок|пятьдесят|восемнадцать|eight|fifty|eighteen)\b", line
        ), line


def validate_document_complete_definition(text: str, index_rows: list) -> None:
    normalized = re.sub(r"\s+", " ", text)
    for fragment in (
        "Для `fstec-linux-2022` `DOCUMENT COMPLETE` достигается, когда все строки "
        "этого документа в `index/source-v4/SOURCE-INDEX.tsv` имеют `status=CLOSED`, "
        "APPLY завершён в принятом scope `SRC-0001_ONLY`, а этапы "
        "`FINAL_DETERMINISTIC_PACKAGING` и `SINGLE_DISTRIBUTABLE_ARTIFACT` закрыты.",
        "Настоящим решением APPLY для остальных строк `fstec-linux-2022` в критерий "
        "`DOCUMENT COMPLETE` не входит.",
        "Для следующих документов критерий определяется отдельно и автоматически "
        "не наследуется.",
    ):
        assert fragment in normalized, fragment
    document_rows = [r for r in index_rows if r["source_id"] == "fstec-linux-2022"]
    assert document_rows, "fstec-linux-2022 rows not found in SOURCE-INDEX.tsv"
    assert all(r["status"] == "CLOSED" for r in document_rows), [
        r["index_id"] for r in document_rows if r["status"] != "CLOSED"
    ]

def expect_rejected(check, *args) -> None:
    try:
        check(*args)
    except AssertionError:
        return
    raise AssertionError("negative fixture unexpectedly accepted")


assert "Единый распространяемый `securelinux-ng.sh`" not in roadmap_md
assert "пользовательский режим RESTORE не входит в целевую архитектуру" in roadmap_md
assert "external snapshot" in roadmap_md
validate_markdown_order(roadmap_md)
validate_current_checkpoint(roadmap_md, project_map, disposition_doc)
validate_no_manual_live_population_counts(roadmap_md)
validate_apply_adapters_roadmap_identity(roadmap_md)
validate_document_complete_definition(roadmap_md, source_index_rows)
expect_rejected(
    validate_markdown_order,
    roadmap_md.replace("12. Определение условия внешнего снимка для `SRC-0001`\n", "12. Этап после predicate/transform\n", 1),
)
expect_rejected(
    validate_current_checkpoint,
    roadmap_md,
    project_map,
    disposition_doc + "\n\nStep 7B снова приостановлен до следующего этапа.\n",
)
expect_rejected(
    validate_current_checkpoint,
    roadmap_md,
    project_map,
    disposition_doc + "\n\nStep 7B формально возвращён в паузу.\n",
)
expect_rejected(
    validate_no_manual_live_population_counts,
    roadmap_md + "\nПоддержаны 51 current controls.\n",
)
expect_rejected(
    validate_no_manual_live_population_counts,
    roadmap_md + "\nТекущих контролей сейчас восемь.\n",
)
expect_rejected(
    validate_apply_adapters_roadmap_identity,
    roadmap_md + "\nЭтап APPLY-adapters отменён и больше не планируется.\n",
)
expect_rejected(
    validate_apply_adapters_roadmap_identity,
    roadmap_md + "\nВ дальнейшем реализация адаптеров APPLY не предусмотрена.\n",
)
expect_rejected(
    validate_current_checkpoint,
    roadmap_md + "\n\nПосле DOCUMENT COMPLETE Step 7B снова объявлен PAUSED_BY_CURRENT_DOCUMENT_APPLY.\n",
    project_map,
    disposition_doc,
)
expect_rejected(
    validate_apply_adapters_roadmap_identity,
    roadmap_md + "\nВ дальнейшем этап реализации APPLY-адаптеров больше не входит в планы проекта.\n",
)
expect_rejected(
    validate_current_checkpoint,
    roadmap_md + "\n\nStep 7B снова отложен после DOCUMENT COMPLETE.\n",
    project_map,
    disposition_doc,
)
print("ROADMAP_NEGATIVE_FIXTURES=PASS_10 apply_adapters_item=4 step7_stale_pause=4 live_counts=2")
print("DOCUMENT_COMPLETE_DEFINITION=PASS")
print("ROADMAP_V3_ORDER=PASS")
