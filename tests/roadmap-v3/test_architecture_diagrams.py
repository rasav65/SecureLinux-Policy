#!/usr/bin/env python3
from pathlib import Path
from collections import Counter
import csv
import re

root = Path(__file__).resolve().parents[2]
text = (root / "docs/ARCHITECTURE-DIAGRAMS.md").read_text(encoding="utf-8")
readme = (root / "README.md").read_text(encoding="utf-8")
docs_index = (root / "docs/README.md").read_text(encoding="utf-8")
donor = (root / "archive/securelinux-ng.sh").read_text(encoding="utf-8")

with (root / "index/engineering-donor-v1/DONOR-TO-V3-MAPPING.tsv").open(encoding="utf-8", newline="") as stream:
    mapping_rows = list(csv.DictReader(stream, delimiter="\t"))
with (root / "index/engineering-tests-v1/TEST-INVENTORY.tsv").open(encoding="utf-8", newline="") as stream:
    test_inventory = list(csv.DictReader(stream, delimiter="\t"))

# Это current-accessible historical donor runtime reference, но не PRIMARY/current/future target map.
assert "PROJECT-MAP-v3.md" in text
assert "historical donor runtime reference" in text
assert "не является future target model" in text
assert "RESTORE_OPERATIONAL_CONTOUR=EXCLUDED" in text
assert "POST_APPLY_RECOVERY_MODEL=EXTERNAL_SNAPSHOT" in text
assert "TRANSACTION_LOCAL_COMPENSATION=FAILED_UNCOMMITTED_APPLY_ONLY" in text


def validate_exact_donor_restore_evidence() -> tuple[int, int, Counter]:
    # Историческая истина проверяется по exact donor bytes, а не по пересказу docs.
    for marker in (
        "./securelinux-ng.sh --restore [--manifest FILE]",
        "--restore         Restore from manifest/backups",
        "resolve_restore_manifest() {",
        "run_restore_mode() {",
        'die "--restore требует root"',
        "Повторный --apply без предварительного --restore перезапишет manifest.",
        "После этого --restore не сможет корректно откатить изменения.",
    ):
        assert marker in donor, marker

    restore_functions = re.findall(r"(?m)^(restore_[A-Za-z0-9_]+)\(\)\s*\{", donor)
    assert len(restore_functions) == 66
    assert len(set(restore_functions)) == 66

    restore_body = donor.split("run_restore_mode() {", 1)[1].split("\nrun_report_mode() {", 1)[0]
    restore_steps = len(re.findall(r"(?m)^\s*run_mode_step\s+restore\s+", restore_body))
    assert restore_steps == 40

    restore_mapping = [
        row for row in mapping_rows
        if row["item_kind"] == "FUNCTION" and (
            row["donor_label"] in {"run_restore_mode", "resolve_restore_manifest"}
            or row["donor_label"].startswith("restore_")
        )
    ]
    decisions = Counter(row["decision"] for row in restore_mapping)
    assert len(restore_mapping) == 68
    assert decisions == Counter({"REJECT": 45, "ADAPT": 16, "DEFER": 7})
    run_restore = [row for row in restore_mapping if row["donor_label"] == "run_restore_mode"]
    assert len(run_restore) == 1
    assert run_restore[0]["decision"] == "REJECT"
    assert run_restore[0]["target_v3_family"] == "donor-historical/operational-recovery-excluded"
    assert "user-invokable RESTORE is excluded from v3" in run_restore[0]["rationale"]
    assert "completed APPLY recovery is EXTERNAL_SNAPSHOT" in run_restore[0]["rationale"]
    assert all(
        "transaction-local compensation" in row["rationale"]
        for row in restore_mapping if row["decision"] == "ADAPT"
    )

    inventory_names = {row["test_name"] for row in test_inventory}
    required_restore_regressions = {
        "empty-password-restore-regression.sh",
        "manifest-bootstrap-regression.sh",
        "manifest-resolution-regression.sh",
        "manifest-writer-contract-regression.sh",
        "password-package-restore-regression.sh",
        "write-once-sysctl-restore-regression.sh",
    }
    assert required_restore_regressions <= inventory_names
    for name in required_restore_regressions:
        assert (root / "archive/engineering-donor-v16.2.11/snapshot/tests" / name).is_file(), name
    return len(restore_functions), restore_steps, decisions


def validate_historical_restore_documentation(body: str) -> None:
    # Current docs обязаны честно признавать зрелый donor RESTORE и одновременно
    # отделять его от target v3 operational contour.
    for marker in (
        "полноценный standalone operational-контур",
        "RESTORE: отдельный CLI `--restore`, `run_restore_mode()`",
        "manifest/backups",
        "модульное восстановление",
        "специализированные regression-тесты",
        "реализованный механизм донора, а не stub",
        "В v3 этот operational-контур целиком не",
        "через `ADAPT` для transaction-local compensation",
    ):
        assert marker in body, marker

    # Запрещаем отрицать существование/реализацию donor RESTORE. Это не запрещает
    # корректное утверждение, что operational contour не переносится в v3.
    for paragraph in re.split(r"\n\s*\n", body):
        lower = paragraph.lower()
        if not re.search(r"securelinux-ng|донор|donor|историческ", lower):
            continue
        if not re.search(r"restore|восстанов|run_restore_mode|--restore", lower):
            continue
        assert not re.search(r"не\s+(?:имел|содержал|существовал|реализован|поддерживал)", lower), paragraph
        assert not re.search(r"(?:реализован|реализовывался|существовал|поддерживался)\s+не\s+был", lower), paragraph
        assert not re.search(r"(?:restore|режим\s+восстанов\w*|восстанов\w*)[^\n]{0,80}(?:отсутствовал|не\s+существовал)", lower), paragraph


def expect_rejected(mutated: str, label: str) -> None:
    try:
        validate_historical_restore_documentation(mutated)
    except AssertionError:
        return
    raise AssertionError(f"negative fixture unexpectedly accepted: {label}")


restore_count, restore_steps, decision_counts = validate_exact_donor_restore_evidence()
validate_historical_restore_documentation(text)

# Synthetic negative fixtures. They deliberately damage the true historical paragraph;
# they are not project claims and must be rejected by the validator.
history_marker = "полноценный standalone operational-контур"
expect_rejected(text.replace(history_marker, "historical operational-контур", 1), "donor_restore_maturity_omitted")
expect_rejected(
    text.replace("содержал полноценный", "не " + "содержал полноценный", 1),
    "INTENTIONAL_FALSE_HISTORY_MUTATION",
)
expect_rejected(
    text + "\n\nИсторический режим восстановления у донора реализован не был.\n",
    "INTENTIONAL_FALSE_HISTORY_REPHRASE",
)

def validate_architecture_role_and_recovery_boundary(body: str) -> None:
    for marker in (
        "historical donor runtime reference",
        "не является current\nproject map",
        "не является future target model",
        "RESTORE_OPERATIONAL_CONTOUR=EXCLUDED",
        "POST_APPLY_RECOVERY_MODEL=EXTERNAL_SNAPSHOT",
        "TRANSACTION_LOCAL_COMPENSATION=FAILED_UNCOMMITTED_APPLY_ONLY",
        "slp_run_check pretty 1 REPORT",
        "--build-info",
        "--provenance",
    ):
        assert marker in body, marker
    assert "целевая APPLY-only runtime-модель" not in body
    assert "целевая runtime-модель v3" not in body

    mermaid_blocks = re.findall(r"```mermaid\n(.*?)```", body, flags=re.S)
    assert mermaid_blocks
    for block in mermaid_blocks:
        lower = block.lower()
        # Operational recovery may be shown only as explicit historical donor evidence
        # or REJECT classification; never as current/future product behavior.
        if re.search(r"restore|восстанов|откат|rollback", lower):
            assert "historical donor only" in lower or "reject" in lower, block
        recovery_topic = r"(?:восстанов\w*|откат\w*|restore|rollback|(?:возврат|возвращ|вернут)\w*[^\n]{0,40}(?:состояни\w*|конфигурац\w*|настройк\w*|сред\w*)|исходн\w*[^\n]{0,24}(?:состояни\w*|конфигурац\w*|настройк\w*))"
        for pattern in (
            rf"(?i)(?:успешн\w*|completed|committed)[^\n]{{0,80}}apply[^\n]{{0,120}}(?:встроен\w*|внутренн\w*|средствами\s+securelinux-policy|продукт\w*)[^\n]{{0,80}}{recovery_topic}",
            rf"(?i)(?:встроен\w*|внутренн\w*|средствами\s+securelinux-policy|продукт\w*)[^\n]{{0,80}}{recovery_topic}[^\n]{{0,120}}(?:успешн\w*|completed|committed)[^\n]{{0,80}}apply",
            rf"(?i)(?:успешн\w*|completed|committed)[^\n]{{0,80}}apply[^\n]{{0,120}}{recovery_topic}",
        ):
            assert not re.search(pattern, block), block


def expect_architecture_rejected(mutated: str, label: str) -> None:
    try:
        validate_architecture_role_and_recovery_boundary(mutated)
    except AssertionError:
        return
    raise AssertionError(f"negative architecture fixture unexpectedly accepted: {label}")


validate_architecture_role_and_recovery_boundary(text)
expect_architecture_rejected(
    text.replace("historical donor runtime reference", "целевая runtime-модель v3", 1),
    "role_changed_to_future_target_model",
)
expect_architecture_rejected(
    text + "\n```mermaid\nflowchart LR\nA[\"успешный APPLY\"] --> B[\"Встроенное восстановление состояния после успешного APPLY\"]\n```\n",
    "post_apply_internal_recovery_euphemism",
)
expect_architecture_rejected(
    text + "\n```mermaid\nflowchart LR\nA[\"успешный APPLY\"] --> B[\"Возврат к исходной конфигурации внутри SecureLinux-Policy\"]\n```\n",
    "post_apply_original_configuration_return",
)

assert "docs/ARCHITECTURE-DIAGRAMS.md" in readme
assert "ARCHITECTURE-DIAGRAMS.md" in docs_index
assert "historical donor runtime reference" in docs_index
assert "не future target model" in docs_index
print(
    "DONOR_RESTORE_EVIDENCE=PASS "
    f"restore_functions={restore_count} restore_run_steps={restore_steps} "
    f"mapping_REJECT={decision_counts['REJECT']} mapping_ADAPT={decision_counts['ADAPT']} "
    f"mapping_DEFER={decision_counts['DEFER']} restore_regressions=6"
)
print("ARCHITECTURE_NEGATIVE_FIXTURES=PASS_6 maturity_omission=1 false_history_mutation=2 role_boundary=1 post_apply_recovery=2")
print("ARCHITECTURE_DIAGRAMS=PASS restore_operational_contour=excluded role=historical_donor_reference donor_restore_history=preserved")
