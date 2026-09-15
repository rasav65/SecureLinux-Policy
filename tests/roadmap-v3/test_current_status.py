#!/usr/bin/env python3
from pathlib import Path
import csv
import re

ROOT = Path(__file__).resolve().parents[2]
readme = (ROOT / "README.md").read_text(encoding="utf-8")
pmap = (ROOT / "docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")
roadmap = (ROOT / "docs/ROADMAP-v3.md").read_text(encoding="utf-8")

with (ROOT / "index/source-v4/SOURCE-INDEX.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    index_rows = list(csv.DictReader(stream, delimiter="\t"))
with (ROOT / "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    controls = list(csv.DictReader(stream, delimiter="\t"))
with (ROOT / "product/ADAPTER-REGISTRY.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    adapters = list(csv.DictReader(stream, delimiter="\t"))
with (ROOT / "product/APPLY-IMPLEMENTATION-REGISTRY.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    apply_implementations = list(csv.DictReader(stream, delimiter="\t"))
with (ROOT / "index/source-v4/FRAMEWORK-SOURCES.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    framework_sources = list(csv.DictReader(stream, delimiter="\t"))
with (ROOT / "index/source-v4/FRAMEWORK-AUTHORITY-RELATIONS.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    framework_relations = list(csv.DictReader(stream, delimiter="\t"))
with (ROOT / "sources/visual-v1/PROVENANCE.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    visual_provenance = list(csv.DictReader(stream, delimiter="\t"))

total = len(index_rows)
controlled = sum(
    row["status"] == "CLOSED" and not row["disposition"] for row in index_rows
)
disposed = sum(
    row["status"] == "CLOSED" and bool(row["disposition"]) for row in index_rows
)
open_rows = sum(row["status"] == "OPEN" for row in index_rows)

def parse_progress_text(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw or "=" not in raw:
            raise ValueError(f"bad PROGRESS line {lineno}")
        key, value = raw.split("=", 1)
        if not key or key in result:
            raise ValueError(f"bad/duplicate PROGRESS key {key!r} at {lineno}")
        result[key] = value
    return result

expected_source_progress = {
    "TOTAL_INDEX_ROWS": str(total),
    "CLOSED_INDEX_ROWS": str(controlled + disposed),
    "OPEN_INDEX_ROWS": str(open_rows),
    "CLOSURE_RATIO": f"{controlled + disposed}/{total}",
    "CONTROLLED_CLOSED_WITH_CONTRACT": str(controlled),
    "DISPOSED_CLOSED_ROWS": str(disposed),
}
source_progress_text = (ROOT / "index/source-v4/PROGRESS.txt").read_text(encoding="utf-8")
source_progress = parse_progress_text(source_progress_text)
assert source_progress == expected_source_progress, (source_progress, expected_source_progress)
for label, mutated in (
    ("disposed_stale", source_progress_text.replace("DISPOSED_CLOSED_ROWS=0", "DISPOSED_CLOSED_ROWS=1", 1)),
    ("extra_key", source_progress_text + "CURRENT_CHECKPOINT=STEP7B_ACTIVE\n"),
    ("duplicate_key", "OPEN_INDEX_ROWS=999\n" + source_progress_text),
):
    try:
        parsed = parse_progress_text(mutated)
        assert parsed == expected_source_progress
    except (AssertionError, ValueError):
        pass
    else:
        raise AssertionError(f"source-v4 PROGRESS negative fixture accepted: {label}")

assert readme.count("<!-- BEGIN GENERATED CURRENT STATUS -->") == 1
assert readme.count("<!-- END GENERATED CURRENT STATUS -->") == 1
for marker in (
    f"TOTAL_INDEX_ROWS={total}",
    f"CONTROLLED_CLOSED_WITH_CONTRACT={controlled}",
    f"DISPOSED_CLOSED_ROWS={disposed}",
    f"OPEN_INDEX_ROWS={open_rows}",
    f"CLOSURE_RATIO={controlled + disposed}/{total}",
    f"CANONICAL_CONTROLS={len(controls)}",
    f"ADAPTER_KINDS={len(adapters)}",
    "APPLY=IMPLEMENTED",
    "APPLY_KINDS=config-line-with-runtime-v1",
    "APPLY_CONTROL_COUNT=17",
    f"APPLY_IMPLEMENTATION_COUNT={len(apply_implementations)}",
    "FULL_FSTEC_COMPLIANCE_CLAIM=false",
):
    assert marker in readme, marker

assert pmap.count("<!-- BEGIN GENERATED MAP STATUS -->") == 1
assert pmap.count("<!-- END GENERATED MAP STATUS -->") == 1
map_status = pmap.split("<!-- BEGIN GENERATED MAP STATUS -->", 1)[1].split(
    "<!-- END GENERATED MAP STATUS -->", 1
)[0]
# Проверяем значения machine truth, не закрепляя английскую presentation-prose.
status_patterns = {
    "source_rows": (rf"(?:source rows|строки source)={total}(?:\D|$)"),
    "controlled_closed": (rf"controlled CLOSED={controlled}(?:\D|$)"),
    "open_rows": (rf"OPEN={open_rows}(?:\D|$)"),
    "controls": (rf"canonical controls={len(controls)}(?:\D|$)"),
    "adapters": (rf"adapters={len(adapters)}(?:\D|$)"),
}
for name, pattern in status_patterns.items():
    assert re.search(pattern, map_status), (name, map_status)

for path in (
    "docs/PROJECT-MAP-v3.md",
    "docs/policy-layers.md",
    "docs/fstec-coverage.md",
    "docs/compatibility.md",
):
    assert path in readme, path

src0005_rows = [row for row in index_rows if row["index_id"] == "SRC-0005"]
assert len(src0005_rows) == 1
assert src0005_rows[0]["status"] == "CLOSED"
assert not src0005_rows[0]["disposition"]
src0005_controls = [row for row in controls if row["index_id"] == "SRC-0005"]
assert len(src0005_controls) == 3

by_index = {row["index_id"]: row for row in index_rows}
for index_id in ("SRC-0030", "SRC-0031", "SRC-0036", "SRC-0037", "SRC-0038", "SRC-0039"):
    assert by_index[index_id]["status"] == "CLOSED", index_id
    assert not by_index[index_id]["disposition"], index_id
assert by_index["SRC-0033"]["status"] == "CLOSED"
assert not by_index["SRC-0033"]["disposition"]
for index_id in ("SRC-0018", "SRC-0019", "SRC-0020", "SRC-0021", "SRC-0022", "SRC-0024", "SRC-0032"):
    assert by_index[index_id]["status"] == "CLOSED", index_id
    assert not by_index[index_id]["disposition"], index_id
assert by_index["SRC-0011"]["status"] == "CLOSED"
assert not by_index["SRC-0011"]["disposition"]
assert by_index["SRC-0012"]["status"] == "CLOSED"
assert not by_index["SRC-0012"]["disposition"]
assert by_index["SRC-0013"]["status"] == "CLOSED"
assert not by_index["SRC-0013"]["disposition"]
assert by_index["SRC-0014"]["status"] == "CLOSED"
assert not by_index["SRC-0014"]["disposition"]
assert by_index["SRC-0002"]["status"] == "CLOSED"
assert not by_index["SRC-0002"]["disposition"]
assert by_index["SRC-0003"]["status"] == "CLOSED"
assert not by_index["SRC-0003"]["disposition"]
assert by_index["SRC-0004"]["status"] == "CLOSED"
assert not by_index["SRC-0004"]["disposition"]
assert by_index["SRC-0006"]["status"] == "CLOSED"
assert not by_index["SRC-0006"]["disposition"]
assert by_index["SRC-0007"]["status"] == "CLOSED"
assert not by_index["SRC-0007"]["disposition"]
assert by_index["SRC-0008"]["status"] == "CLOSED"
assert not by_index["SRC-0008"]["disposition"]
assert by_index["SRC-0009"]["status"] == "CLOSED"
assert not by_index["SRC-0009"]["disposition"]
assert by_index["SRC-0015"]["status"] == "CLOSED"
assert not by_index["SRC-0015"]["disposition"]
assert by_index["SRC-0026"]["status"] == "CLOSED"
assert not by_index["SRC-0026"]["disposition"]
assert by_index["SRC-0034"]["status"] == "CLOSED"
assert not by_index["SRC-0034"]["disposition"]
assert by_index["SRC-0040"]["status"] == "CLOSED"
assert not by_index["SRC-0040"]["disposition"]

adapter_kinds = {row["parameter_kind"] for row in adapters}
assert {"sysctl", "file-mode-owner", "kernel-cmdline", "user-cron-files-mode", "standard-system-paths-mode", "suid-sgid-applications", "home-sensitive-files-mode", "home-directories-mode", "sshd-root-login", "pam-wheel-access", "sudoers-reviewed-policy", "tested-setting-attestation", "running-process-paths-write-protection", "cron-command-paths-write-protection", "sudo-root-command-files-protection", "startup-files-write-protection"} <= adapter_kinds
assert (ROOT / "product/generate-product-check-v1.py").is_file()
assert (ROOT / "product/generate-product-check-v2.py").is_file()
assert (ROOT / "securelinux-policy.sh").is_file()
assert (ROOT / "securelinux-policy.sh.sha256").is_file()

framework_by_id = {row["source_id"]: row for row in framework_sources}
assert set(framework_by_id) == {
    "fstec-order-117-2025-requirements",
    "fstec-order-137-2026-amendments-to-117",
    "fstec-methodology-2026-04-12",
}
order137 = framework_by_id["fstec-order-137-2026-amendments-to-117"]
assert order137["source_sha256"] == "eea32d569889ed57e9b7081b3a69fd31e44d0422d23349fefa3521427401c61a"
assert order137["source_role"] == "framework"
assert order137["closure_counted"] == "NO"
assert "amends fstec-order-117-2025-requirements" in order137["followup"]

assert framework_relations == [{
    "base_source_id": "fstec-order-117-2025-requirements",
    "amendment_source_id": "fstec-order-137-2026-amendments-to-117",
    "relation": "AMENDED_BY",
    "effective_from": "2026-09-01",
    "deferred_locator": "application-point-7",
    "deferred_effective_from": "2027-03-01",
    "evidence_path": "sources/visual-v1/PROVENANCE.tsv",
}]
assert len(visual_provenance) == 19
assert visual_provenance[0]["record_id"] == "ORDER137-METADATA"
assert visual_provenance[0]["pdf_page"] == "1"
change7 = [row for row in visual_provenance if row["record_id"] == "ORDER137-CHANGE-007"]
assert len(change7) == 1
assert change7[0]["pdf_page"] == "2-3"
assert change7[0]["effective_from"] == "2027-03-01"
assert all(
    row["source_pdf_sha256"] == "eea32d569889ed57e9b7081b3a69fd31e44d0422d23349fefa3521427401c61a"
    for row in visual_provenance
)
assert not any(
    row["source_id"] == "fstec-order-137-2026-amendments-to-117"
    for row in index_rows
)
linux40 = [row for row in index_rows if row["index_id"].startswith("SRC-") and 1 <= int(row["index_id"].split("-")[1]) <= 40]
assert len(linux40) == 40
assert all(row["source_id"] == "fstec-linux-2022" and row["status"] == "CLOSED" for row in linux40)

current = pmap.split("## 6. Где мы находимся", 1)[1].split(
    "## Что является источником истины", 1
)[0]
assert current.count(":::current") == 1
# Milestone/source identities are semantic; presentation wording may be Russian.
for marker in (
    "SRC-0005 / 2.3.1", "CHECK-11", "CHECK-17", "SRC-0040 / 2.6.6",
    "CHECK-18", "SRC-0033 / 2.5.10", "CHECK-19", "CHECK-28",
    "securelinux-policy.sh", "fstec-linux-2022 CHECK COMPLETE",
    "fstec-linux-2022-check-complete-v1", "DONOR_TO_V3_MAPPING",
    "ACCEPTED + COMMITTED", "1db91b0", "AUTHORITY_2026_REFRESH",
    "SRC-0001 modular APPLY contract architecture",
    "SRC-0001 predicate / transform definitions", "SRC-0001 external snapshot precondition", "SRC-0001 lock/reread + object identity", "SRC-0001 метаданные/транзакция/отчёт", "ВНЕШНИЙ СНИМОК",
):
    assert marker in current, marker
assert "приказы № 117 + № 137<br/>ГОТОВО" in current
assert "SRC-0001 modular APPLY contract architecture<br/>compact registry + SHA bindings<br/>ГОТОВО" in current
assert "SRC-0001 predicate / transform definitions<br/>exact empty + exact bang<br/>ГОТОВО" in current
assert "SRC-0001 external snapshot precondition<br/>exact attestation + prestate binding<br/>ГОТОВО" in current
assert "SRC-0001 lock/reread + object identity<br/>stale + path identity fail-closed<br/>ГОТОВО" in current
assert 'P17["SRC-0001 метаданные/транзакция/отчёт<br/>8 определений + композиция<br/>ГОТОВО"]:::closed' in current
assert 'P18["APPLY для SRC-0001<br/>ОДНА ВЕРТИКАЛЬ<br/>ГОТОВО"]:::closed' in current
assert 'P19["финальная детерминированная упаковка<br/>ГОТОВО"]:::closed' in current
assert 'P20["единый распространяемый артефакт<br/>ГОТОВО"]:::closed' in current
assert 'P21["МЫ ЗДЕСЬ<br/>Step 7B · расширение FSTEC"]:::current' in current
assert "SRC-0001 flat contract candidate: REVISE" in current
assert "SRC-0001 current contract<br/>ПРИНЯТО" not in current
assert "RESTORE исключён" in current
assert "МЫ ЗДЕСЬ<br/>Step 7B · расширение FSTEC" in current

with (ROOT / "docs/ROADMAP-v3.tsv").open(encoding="utf-8", newline="") as stream:
    rows = list(csv.DictReader(stream, delimiter="\t"))
by_id = {row["step_id"]: row["status"] for row in rows}
assert by_id["SOURCE_BLOCK_REGENERATION_PARITY"] == "CLOSED"
assert by_id["FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS"] == "NEXT"
assert by_id["APPLY_SEMANTIC_CONTRACT"] == "PARENT_GATE_CLOSED_SOURCE_INSTANCE_REVISE"
assert by_id["AUTHORITY_2026_REFRESH"] == "CLOSED"
assert by_id["SRC0001_MODULAR_APPLY_CONTRACT_ARCHITECTURE"] == "CLOSED"
assert by_id["SRC0001_PREDICATE_TRANSFORM_DEFINITIONS"] == "CLOSED"
assert by_id["SRC0001_SNAPSHOT_PRECONDITION_DEFINITION"] == "CLOSED"
assert by_id["SRC0001_LOCK_REREAD_OBJECT_IDENTITY_DEFINITIONS"] == "CLOSED"
assert by_id["SRC0001_METADATA_TRANSACTION_REPORT_DEFINITIONS"] == "CLOSED"
assert by_id["APPLY_IMPLEMENTATION_ADAPTERS"] == "CLOSED"
assert by_id["FINAL_DETERMINISTIC_PACKAGING"] == "CLOSED"
assert by_id["SINGLE_DISTRIBUTABLE_ARTIFACT"] == "CLOSED"
assert by_id["SRC0008_CHECK_SEMANTIC_REWORK"] == "SEMANTIC_REWORK_IN_PROGRESS"
assert "PAUSED_BY_CURRENT_DOCUMENT_APPLY" not in roadmap
assert "DOCUMENT COMPLETE" in roadmap
next_rows = [row["step_id"] for row in rows if row["status"] == "NEXT"]
assert next_rows == ["FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS"], next_rows
assert "SRC0001_MODULAR_APPLY_CONTRACT_ARCHITECTURE" in roadmap
assert "SRC0001_PREDICATE_TRANSFORM_DEFINITIONS" in roadmap
assert "SRC0001_SNAPSHOT_PRECONDITION_DEFINITION" in roadmap
assert "SRC0001_LOCK_REREAD_OBJECT_IDENTITY_DEFINITIONS" in roadmap

print("SOURCE_PROGRESS_CONTRACT=PASS_EXACT_SIX_KEYS negative_fixtures=3")
print("AUTHORITY_2026_REFRESH=PASS framework_sources=3 relations=1 visual_records=19 linux40_unchanged=1")
print(
    "CURRENT_STATUS_CONSISTENCY=PASS "
    f"source_rows={total} closed={controlled} open={open_rows} "
    f"controls={len(controls)} adapters={len(adapters)}"
)
