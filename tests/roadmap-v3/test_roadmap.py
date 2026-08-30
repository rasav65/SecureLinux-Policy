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
assert rows[6]["status"] == "PAUSED_BY_CURRENT_DOCUMENT_APPLY"
assert rows[7]["status"] == "NEXT"
assert all(r["status"] == "BLOCKED_BY_PREVIOUS" for r in rows[8:])
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
    assert numbered.get(9) == "Адаптеры реализации APPLY", numbered.get(9)
    assert numbered.get(10) == "Детерминированная финальная упаковка", numbered.get(10)
    assert numbered.get(11) == "Единый распространяемый артефакт (имя не закреплено)", numbered.get(11)


def validate_current_checkpoint(roadmap_text: str, map_text: str, disposition_text: str) -> None:
    assert "PAUSED_BY_CURRENT_DOCUMENT_APPLY" in roadmap_text
    assert "APPLY_SEMANTIC_CONTRACT" in roadmap_text
    assert "Step 7B сейчас приостановлен (`PAUSED_BY_CURRENT_DOCUMENT_APPLY`)" in roadmap_text
    assert "текущий substantive checkpoint — отдельный `APPLY semantic contract`" in map_text
    assert "Step 7B приостановлен" in map_text
    assert "Step 7B приостановлен (`PAUSED_BY_CURRENT_DOCUMENT_APPLY`)" in disposition_text
    assert "текущий product checkpoint внутри макроэтапа Step 7B" not in map_text
    # Step 7B может упоминаться только как paused/backlog/history. Активный/current
    # статус запрещён даже при перефразировке; известные отрицательные формулировки
    # сначала удаляются, чтобы не ловить "не является текущим NEXT".
    re_mod = __import__("re")
    for doc in (roadmap_text, map_text, disposition_text):
        for paragraph in re_mod.split(r"\n\s*\n", doc):
            if "Step 7B" not in paragraph or paragraph.lstrip().startswith("### Step 7B"):
                continue
            assert re_mod.search(
                r"(?i)(?:приостанов\w*|отлож\w*|PAUSED_BY_CURRENT_DOCUMENT_APPLY|backlog|historical|историческ\w*)",
                paragraph,
            ), paragraph
            normalized = re_mod.sub(
                r"(?i)не\s+(?:является|являются|считается|считаются)\s+(?:текущ\w*|активн\w*|\bNEXT\b)(?:\s+\w+)?",
                "", paragraph,
            )
            normalized = re_mod.sub(r"(?i)до\s+разрешённого\s+возврата", "", normalized)
            for pattern in (
                r"(?i)Step 7B\s+(?:является|служит|ведущ\w*|активн\w*|разрешён\w*|приоритет\w*|текущ\w*|(?:остаётся|считается)\s+(?:текущ\w*|активн\w*|ведущ\w*|разрешён\w*|приоритет\w*|NEXT))",
                r"(?i)Step 7B[^\n.]{0,40}\bNEXT\b",
                r"(?i)(?:ведущ\w*|активн\w*|приоритет\w*|текущ\w*)\s+(?:этап\w*|направлен\w*|checkpoint\w*)?[^\n.]{0,20}Step 7B",
                r"(?i)\bNEXT\b\s*[:—-]?\s*Step 7B",
                r"(?i)разрешён\w*[^\n.]{0,20}Step 7B",
                r"(?i)(?:фактически|на\s+деле|реально)?[^\n.]{0,36}(?:возобнов\w*|активирован\w*)[^\n.]{0,36}(?:Step 7B|работ\w*|поток\w*|направлен\w*)",
                r"(?i)(?:Step 7B|работ\w*\s+по\s+Step 7B)[^\n.]{0,60}(?:возобнов\w*|активирован\w*|основн\w*\s+(?:поток\w*|трек\w*|направлен\w*))",
                r"(?i)(?:основн\w*|главн\w*|ведущ\w*|приоритет\w*)\s+(?:поток\w*|трек\w*|направлен\w*|этап\w*|checkpoint\w*)[^\n.]{0,40}Step 7B",
                r"(?i)Step 7B[^\n.]{0,100}(?:работ\w*\s+(?:снова\s+)?(?:идут|ведутся|продолжаются)|(?:главн\w*|основн\w*|ведущ\w*|приоритет\w*)\s+направлен\w*)",
            ):
                assert not re_mod.search(pattern, normalized), paragraph


def validate_apply_adapters_future_stage(text: str) -> None:
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
validate_apply_adapters_future_stage(roadmap_md)
expect_rejected(
    validate_markdown_order,
    roadmap_md.replace("9. Адаптеры реализации APPLY\n", "9. Этап реализации после APPLY\n", 1),
)
expect_rejected(
    validate_current_checkpoint,
    roadmap_md,
    project_map,
    disposition_doc + "\n\nStep 7B является текущим разрешённым этапом.\n",
)
expect_rejected(
    validate_current_checkpoint,
    roadmap_md,
    project_map,
    disposition_doc + "\n\nStep 7B является ведущим активным направлением работ проекта.\n",
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
    validate_apply_adapters_future_stage,
    roadmap_md + "\nЭтап APPLY-adapters отменён и больше не планируется.\n",
)
expect_rejected(
    validate_apply_adapters_future_stage,
    roadmap_md + "\nВ дальнейшем реализация адаптеров APPLY не предусмотрена.\n",
)
expect_rejected(
    validate_current_checkpoint,
    roadmap_md + "\n\nХотя формально Step 7B помечен PAUSED_BY_CURRENT_DOCUMENT_APPLY, фактически работы по нему возобновлены и это основной поток проекта.\n",
    project_map,
    disposition_doc,
)
expect_rejected(
    validate_apply_adapters_future_stage,
    roadmap_md + "\nВ дальнейшем этап реализации APPLY-адаптеров больше не входит в планы проекта.\n",
)
expect_rejected(
    validate_current_checkpoint,
    roadmap_md + "\n\nStep 7B формально PAUSED_BY_CURRENT_DOCUMENT_APPLY, однако работы снова идут и это главное направление проекта.\n",
    project_map,
    disposition_doc,
)
print("ROADMAP_NEGATIVE_FIXTURES=PASS_10 apply_adapters_item=4 step7_active_rephrase=4 live_counts=2")
print("ROADMAP_V3_ORDER=PASS")
