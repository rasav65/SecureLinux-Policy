#!/usr/bin/env python3
from pathlib import Path
import csv
import hashlib
import json
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
policy = (root / "docs/DONOR-V3-ADOPTION-POLICY.md").read_text(encoding="utf-8")
roadmap = (root / "docs/ROADMAP-v3.md").read_text(encoding="utf-8")

for marker in (
    "DONOR_TO_V3_MAPPING",
    "REUSE",
    "ADAPT",
    "REJECT",
    "DEFER",
    "APPLY semantic contract",
    "`control_id`",
    "`quote_sha256`",
    "<!-- BEGIN MATURE DONOR FAMILIES -->",
    "<!-- END MATURE DONOR FAMILIES -->",
):
    assert marker in policy, marker

# Donor adoption never acts as normative closure. Human prose is Russian;
# tests pin semantic tokens/markers rather than obsolete English sentences.
for marker in (
    "ненормативный",
    "инженерный донор",
    "сам mapping закрывает 0 строк source index",
    "не является нормативным evidence",
    "`EXTERNAL_SNAPSHOT`",
):
    assert marker in policy, marker

# Roadmap must retain the donor precondition, but wording is not pinned.
assert "DONOR_TO_V3_MAPPING" in roadmap
assert "docs/DONOR-V3-ADOPTION-POLICY.md" in roadmap
assert "0 строк FSTEC" in roadmap or "закрывает 0 строк" in roadmap

with (root / "docs/ROADMAP-v3.tsv").open(encoding="utf-8", newline="") as stream:
    rows = list(csv.DictReader(stream, delimiter="\t"))
orders = [int(row["order"]) for row in rows]
assert orders == list(range(1, len(rows) + 1))
by_step = {row["step_id"]: row["status"] for row in rows}
assert by_step["FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS"] == "WAITING_FOR_HORIZON_1"
assert by_step["HORIZON1_SAFE_CLASS_APPLY_AND_VM_RUNS"] == "NEXT"
assert by_step["APPLY_SEMANTIC_CONTRACT"] == "PARENT_GATE_CLOSED_SOURCE_INSTANCE_REVISE"
assert by_step["AUTHORITY_2026_REFRESH"] == "CLOSED"
assert by_step["SRC0001_MODULAR_APPLY_CONTRACT_ARCHITECTURE"] == "CLOSED"
assert by_step["SRC0001_PREDICATE_TRANSFORM_DEFINITIONS"] == "CLOSED"
assert by_step["SRC0001_SNAPSHOT_PRECONDITION_DEFINITION"] == "CLOSED"
assert by_step["SRC0001_LOCK_REREAD_OBJECT_IDENTITY_DEFINITIONS"] == "CLOSED"
assert by_step["SRC0001_METADATA_TRANSACTION_REPORT_DEFINITIONS"] == "CLOSED"
assert by_step["APPLY_IMPLEMENTATION_ADAPTERS"] == "CLOSED"
assert by_step["FINAL_DETERMINISTIC_PACKAGING"] == "CLOSED"
assert by_step["SINGLE_DISTRIBUTABLE_ARTIFACT"] == "CLOSED"

# Parent schema remains accepted. The active APPLY registries now describe
# mechanism-authority rows; SRC-0001 contracts below are historical evidence only.
apply_schema_path = root / "product/contracts/apply-semantic-contract-v1.schema.json"
apply_registry_path = root / "product/APPLY-KIND-REGISTRY.tsv"
impl_registry_path = root / "product/APPLY-IMPLEMENTATION-REGISTRY.tsv"
authority_path = root / "product/contracts/mechanism-config-line-runtime-v1.json"
assert apply_schema_path.is_file() and apply_registry_path.is_file() and authority_path.is_file()
apply_schema = json.loads(apply_schema_path.read_text(encoding="utf-8"))
assert apply_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
assert apply_schema["$id"] == "urn:securelinux-policy-v3:apply-semantic-contract:v1"

def _sha(path):
    h = hashlib.sha256(); h.update(path.read_bytes()); return h.hexdigest()

with apply_registry_path.open(encoding="utf-8", newline="") as stream:
    reader = csv.DictReader(stream, delimiter="\t")
    assert tuple(reader.fieldnames or ()) == (
        "apply_kind", "parameter_kind", "target_class", "authority_form",
        "architecture_id", "architecture_path", "architecture_sha256",
    )
    apply_kinds = list(reader)
# Литерал закреплён явным решением: расширяется только осознанной правкой
# этого теста при принятии нового APPLY-механизма, а не автоматически под
# результат прогона.
assert len(apply_kinds) == 2
row = apply_kinds[0]
assert row["apply_kind"] == "config-line-with-runtime-v1"
assert row["parameter_kind"] == "sysctl"
assert row["target_class"] == "sysctl-runtime-persistent"
assert row["authority_form"] == "MECHANISM_AUTHORITY_V1"
assert row["architecture_id"] == "config-line-with-runtime-v1"
assert row["architecture_path"] == "product/contracts/mechanism-config-line-runtime-v1.json"
assert row["architecture_sha256"] == _sha(authority_path)
authority = json.loads(authority_path.read_text(encoding="utf-8"))
assert authority["authority_form"] == "MECHANISM_AUTHORITY_V1"
assert authority["mechanism_id"] == row["apply_kind"]
rb = authority["registry_binding"]
assert rb["parameter_kind"] == row["parameter_kind"]
assert rb["target_class"] == row["target_class"]
assert rb["architecture_id"] == row["architecture_id"]
assert rb["authority_path"] == row["architecture_path"]

with impl_registry_path.open(encoding="utf-8", newline="") as stream:
    impl_reader = csv.DictReader(stream, delimiter="\t")
    assert tuple(impl_reader.fieldnames or ()) == (
        "apply_kind", "composition_contract_id", "adapter_id", "binding_path",
        "binding_sha256", "implementation_path", "implementation_sha256",
    )
    impl_rows = list(impl_reader)
# Литерал закреплён явным решением: меняется только осознанной правкой этого
# теста при принятии нового APPLY-механизма, а не автоматически под результат
# прогона. Вычисление здесь дало бы сравнение реестра с самим собой.
assert len(impl_rows) == 2
impl_row = impl_rows[0]
assert impl_row["apply_kind"] == row["apply_kind"]
assert impl_row["composition_contract_id"] == rb["composition_contract_id"]
assert impl_row["adapter_id"] == rb["adapter_id"]
assert impl_row["binding_sha256"] == _sha(root / impl_row["binding_path"])
assert impl_row["implementation_sha256"] == _sha(root / impl_row["implementation_path"])
impl_binding_doc = json.loads((root / impl_row["binding_path"]).read_text(encoding="utf-8"))
assert impl_binding_doc["adapter_id"] == impl_row["adapter_id"]
assert impl_binding_doc["binding_contract_id"] == rb["binding_contract_id"]
assert impl_binding_doc["composition_contract_path"] == row["architecture_path"]
assert impl_binding_doc["composition_contract_sha256"] == row["architecture_sha256"]

# The generalized binding checker validates every active registry pair.
binding_tool = root / "tools/rebuild-apply-contract-bindings.py"
check = subprocess.run(
    ["/usr/bin/python3", "-I", "-S", "-B", str(binding_tool), "--project-root", str(root), "--check"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
)
assert check.returncode == 0, check.stdout + check.stderr
# Значение равно числу зарегистрированных механизмов APPLY и меняется только
# явным решением о новом механизме, не как побочный эффект правки реестров.
assert "APPLY_BINDING_ARCHITECTURES=2" in check.stdout

# Historical SRC-0001 modular authority remains byte-present and semantically
# inspectable, but is deliberately absent from both active APPLY registries.
architecture_path = root / "product/contracts/src0001-apply/architecture-v1.json"
assert architecture_path.is_file()
arch = json.loads(architecture_path.read_text(encoding="utf-8"))
assert arch["apply_kind"] == "local-account-password-lock"
assert arch["definition_reuse_scope"] == "SRC0001_SOURCE_LOCAL_UNTIL_SECOND_PROVEN_USE_CASE"
assert arch["bindings"]["flat_candidate"]["status"] == "REVISE_INPUT_NOT_FINAL_AUTHORITY"
assert arch["definition_progress"] == {
    "closed_roles": ["predicate", "transform", "snapshot_precondition", "lock_reread", "object_identity", "metadata_preservation", "atomic_transaction", "dry_run_report"],
    "pending_roles": [],
}
by_role = {rec["role"]: rec for rec in arch["definition_roles"]}
for role in ("predicate", "transform", "snapshot_precondition", "lock_reread", "object_identity", "metadata_preservation", "atomic_transaction", "dry_run_report"):
    rec = by_role[role]
    assert rec["state"] == "CLOSED"
    assert rec["sha256"] == _sha(root / rec["path"])
predicate = json.loads((root / by_role["predicate"]["path"]).read_text(encoding="utf-8"))
transform = json.loads((root / by_role["transform"]["path"]).read_text(encoding="utf-8"))
assert predicate["predicate"] == {"expected_length": 0, "match": "SELECT_FOR_TRANSFORM", "nonmatch": "NOT_SELECTED_PRESERVE_UNCHANGED", "operator": "BYTE_LENGTH_EQ"}
assert predicate["input_field"]["field_index_1_based"] == 2
assert transform["transform"]["input_field_bytes_hex"] == ""
assert transform["transform"]["output_field_bytes_hex"] == "21"
assert transform["predicate_binding"]["sha256"] == _sha(root / by_role["predicate"]["path"])
assert transform["preservation"]["nonselected_record_bytes"] == "EXACT"
assert transform["preservation"]["file_bytes_outside_selected_second_fields"] == "EXACT"
snapshot = json.loads((root / by_role["snapshot_precondition"]["path"]).read_text(encoding="utf-8"))
assert snapshot["definition_class"] == "APPLY_SNAPSHOT_PRECONDITION"
assert snapshot["evidence"]["format"] == "SLP-EXTERNAL-SNAPSHOT-ATTESTATION-V1"
assert snapshot["recovery_model"]["product_creates_snapshot"] is False
assert snapshot["recovery_model"]["product_restores_snapshot"] is False
lock_reread = json.loads((root / by_role["lock_reread"]["path"]).read_text(encoding="utf-8"))
assert lock_reread["definition_class"] == "APPLY_LOCK_REREAD"
assert lock_reread["failure"]["stale_prestate"] == "ABORT_NO_MUTATION"
object_identity = json.loads((root / by_role["object_identity"]["path"]).read_text(encoding="utf-8"))
assert object_identity["definition_class"] == "APPLY_OBJECT_IDENTITY"
assert object_identity["identity"]["target"]["symlink"] == "FORBIDDEN"
assert object_identity["failure"]["identity_drift"] == "ABORT_NO_MUTATION"
composition_actual = json.loads((root / arch["composition_contract"]["path"]).read_text(encoding="utf-8"))
assert composition_actual["architecture_binding"]["sha256"] == _sha(architecture_path)
assert set(composition_actual["definition_bindings"]) == set(by_role)
for role, binding in composition_actual["definition_bindings"].items():
    assert binding["sha256"] == by_role[role]["sha256"]
assert all(r["apply_kind"] != "local-account-password-lock" for r in apply_kinds)
assert all(r["apply_kind"] != "local-account-password-lock" for r in impl_rows)

src0001_apply_path = root / "product/contracts/local-account-password-state-apply-semantic-v1.json"
assert src0001_apply_path.is_file()
src0001_apply = json.loads(src0001_apply_path.read_text(encoding="utf-8"))
assert src0001_apply["source_row"] == "SRC-0001"
assert src0001_apply["apply_kind"] == "local-account-password-lock"
for marker in (
    "Parent gate для APPLY semantic contracts",
    "apply-semantic-contract-v1.schema.json",
    "APPLY-KIND-REGISTRY.tsv",
    "architecture-v1.json",
    "local-account-password-lock",
    "0 строк source index",
):
    assert marker in policy, marker
def section(text: str, heading: str, next_heading: str | None = None) -> str:
    assert heading in text, heading
    body = text.split(heading, 1)[1]
    if next_heading is not None:
        assert next_heading in body, next_heading
        body = body.split(next_heading, 1)[0]
    return body


def validate_restore_roadmap_boundary(text: str) -> None:
    roadmap_part = section(text, "## Связь с утверждённым roadmap")
    assert "`RESTORE` не является этапом roadmap" in roadmap_part
    # Проверяем не только literal RESTORE, но и русские/английские синонимы recovery.
    # Положительный user/post-APPLY recovery средствами v3 запрещён независимо от wording.
    recovery_atom = (
        r"(?:\bRESTORE\b|восстанов\w*|откат\w*|rollback|"
        r"возврат\w*[^\n]{0,40}(?:состояни\w*|конфигурац\w*|настройк\w*|сред\w*)|"
        r"возвращ\w*[^\n]{0,40}(?:состояни\w*|конфигурац\w*|настройк\w*|сред\w*)|"
        r"вернут\w*[^\n]{0,40}(?:состояни\w*|конфигурац\w*|настройк\w*|сред\w*)|"
        r"исходн\w*[^\n]{0,24}(?:состояни\w*|конфигурац\w*|настройк\w*))"
    )
    recovery = re.compile(rf"(?i){recovery_atom}")
    paragraphs = [p for p in re.split(r"\n\s*\n", text) if recovery.search(p)]
    assert paragraphs
    allowed_boundary = (
        "не являются", "`REJECT`", "не является", "НЕ ДОЛЖЕН", "historical evidence",
        "не принимает", "не откатывается", "EXTERNAL_SNAPSHOT", "external snapshot",
        "ответственность инфраструктуры", "вне продукта", "не переносится",
    )
    forbidden_positive = (
        rf"(?i)(?:обязател\w*|предусмотрен\w*|требуется|должен\w*|реализован\w*|встроен\w*)[^\n]{{0,100}}{recovery_atom}",
        rf"(?i){recovery_atom}[^\n]{{0,100}}(?:обязател\w*|предусмотрен\w*|требуется|должен\w*|реализован\w*|встроен\w*)",
    )
    for paragraph in paragraphs:
        lower = paragraph.lower()
        semantic = re.sub(
            r"(?i)\bне\s+(?:должен\w*|является|являются|принимает|откатывается|переносится|реализуется|реализован\w*)",
            "", paragraph,
        )
        for pattern in forbidden_positive:
            assert not re.search(pattern, semantic), paragraph
        # Если paragraph относится к current v3/APPLY boundary, он обязан явно
        # указывать отрицание operational recovery или внешний snapshot.
        if re.search(r"(?i)(?:\bv3\b|SecureLinux-Policy|post-APPLY|после[^\n]{0,30}APPLY|пользовательск)", paragraph):
            assert any(marker.lower() in lower for marker in allowed_boundary), paragraph


def validate_artifact_contract(text: str) -> None:
    artifact = section(text, "## Правило итогового распространяемого артефакта", "## Связь с утверждённым roadmap")
    assert "имя пока не закреплено" in artifact
    assert "детерминированным артефактом сборки" in artifact
    assert "не вручную поддерживаемым источником истины" in artifact
    assert "исторического donor artifact" in artifact
    assert "не закрепляет\nимя будущего distributable v3" in artifact
    normalized = text.lower().replace("не вручную поддерживаемым", "")
    for forbidden in (
        "недетерминированным артефактом",
        "поддерживается вручную",
        "вручную поддерживаем",
        "ручная сборка",
        "сборка может отличаться",
        "повторная сборка может отличаться",
        "не воспроизводим",
        "вправе иметь разные байты",
        "разрешено иметь разные байты",
    ):
        assert forbidden not in normalized, forbidden
    for pattern in (
        r"(?i)(?:сборк\w*|артефакт\w*|distributable)[^\n]{0,100}не\s+обязан\w*[^\n]{0,40}совпад\w*",
        r"(?i)(?:сборк\w*|артефакт\w*|distributable)[^\n]{0,100}(?:может|могут|допускает\w*)[^\n]{0,40}(?:отличаться|различаться)",
        r"(?i)(?:артефакт\w*|сборк\w*|distributable)[^\n]{0,80}(?:не\s+детерминирован\w*|недетерминирован\w*|не\s+воспроизводим\w*)",
        r"(?i)(?:не\s+детерминирован\w*|недетерминирован\w*|не\s+воспроизводим\w*)[^\n]{0,80}(?:артефакт\w*|сборк\w*|distributable)",
        r"(?i)(?:distributable|артефакт\w*|сборк\w*)[^\n]{0,100}(?:вправе|разрешен\w*|допускает\w*)[^\n]{0,80}разн\w*\s+байт",
        r"(?i)одинаков\w*\s+вход\w*[^\n]{0,100}разн\w*\s+байт",
        r"(?i)разн\w*\s+байт[^\n]{0,100}одинаков\w*\s+вход\w*",
        r"(?i)одинаков\w*[^\n]{0,24}вход\w*[^\n]{0,120}не\s+гарантир\w*[^\n]{0,80}одинаков\w*[^\n]{0,30}(?:результат\w*|байт\w*|артефакт\w*)",
        r"(?i)не\s+гарантир\w*[^\n]{0,80}одинаков\w*[^\n]{0,30}(?:результат\w*|байт\w*|артефакт\w*)[^\n]{0,120}одинаков\w*[^\n]{0,24}вход\w*",
        r"(?i)(?:результат\w*|сборк\w*|артефакт\w*)[^\n]{0,80}(?:при|для)\s+(?:тех\s+же|одинаков\w*)[^\n]{0,30}вход\w*[^\n]{0,80}(?:может|могут|способен\w*)\s+(?:меняться|изменяться|различаться)",
        r"(?i)(?:тех\s+же|одинаков\w*)[^\n]{0,30}вход\w*[^\n]{0,100}(?:результат\w*|сборк\w*|артефакт\w*)[^\n]{0,40}(?:может|могут|способен\w*)\s+(?:меняться|изменяться|различаться)",
    ):
        assert not re.search(pattern, normalized), pattern
    paragraphs = [p for p in re.split(r"\n\s*\n", text) if p.strip()]
    future_name_binding = re.compile(
        r"(?i)(?:будущ\w*|future)[^\n]{0,100}(?:distributable|артефакт\w*)"
        r"[^\n]{0,100}(?:обязан\w*\s+называться|будет\s+называться|называется|"
        r"закрепля\w*\s+(?:имя|названи\w*))[^\n]{0,60}`?[A-Za-z0-9_.-]+\.sh`?"
    )
    reverse_future_name_binding = re.compile(
        r"(?i)`?[A-Za-z0-9_.-]+\.sh`?[^\n]{0,80}(?:имя|названи\w*)?[^\n]{0,40}"
        r"(?:будущ\w*|future)[^\n]{0,60}(?:distributable|артефакт\w*)"
    )
    for paragraph in paragraphs:
        normalized_paragraph = re.sub(
            r"(?i)не\s+закрепля\w*[^\n]{0,60}(?:имя|названи\w*)",
            "", paragraph,
        )
        assert not future_name_binding.search(normalized_paragraph), paragraph
        assert not reverse_future_name_binding.search(normalized_paragraph), paragraph
        shell_names = re.findall(r"`?([A-Za-z0-9_.-]+\.sh)`?", paragraph)
        if shell_names and re.search(r"(?i)(?:будущ\w*|future)", paragraph):
            donor_nonbinding = (
                set(shell_names) == {"securelinux-ng.sh"}
                and "исторического donor artifact" in paragraph
                and re.search(r"(?i)не\s+закрепля\w*", paragraph)
            )
            assert donor_nonbinding, paragraph
        if "securelinux-ng.sh" in paragraph:
            # В current policy donor-name допустим только как явно historical и non-binding.
            assert "исторического donor artifact" in paragraph, paragraph
            assert "не закрепляет" in paragraph, paragraph


def validate_donor_restore_history_boundary(text: str) -> None:
    # Политика обязана одновременно признавать зрелость donor RESTORE и запрещать
    # перенос standalone/post-APPLY operational contour в v3.
    for marker in (
        "RESTORE у донора был зрелым и протестированным operational-семейством",
        "v3\nне принимает его как user-invokable или post-APPLY RESTORE",
    ):
        assert marker in text, marker
    roadmap_part = section(text, "## Связь с утверждённым roadmap")
    for marker in (
        "исторический `SecureLinux-NG` имел полноценный",
        "standalone operational-контур RESTORE",
        "manifest/backups",
        "модульным восстановлением",
        "специализированными regression-тестами",
        "В v3 этот operational-контур целиком не",
        "`ADAPT` исключительно для transaction-local compensation",
    ):
        assert marker in roadmap_part, marker
    assert "`RESTORE` не является этапом roadmap" in roadmap_part
    # Любое отрицание факта реализации donor RESTORE запрещено, даже без literal SecureLinux-NG.
    for paragraph in re.split(r"\n\s*\n", text):
        lower = paragraph.lower()
        if not re.search(r"донор|donor|историческ", lower):
            continue
        if not re.search(r"restore|восстанов", lower):
            continue
        for pattern in (
            r"не\s+(?:существовал\w*|реализован\w*|имел\w*|содержал\w*|поддерживал\w*)",
            r"(?:реализован\w*|реализовывал\w*|существовал\w*|поддерживал\w*)\s+не\s+был\w*",
            r"(?:restore|восстанов\w*)[^\n]{0,80}отсутствовал\w*",
            r"(?:restore|восстанов\w*)[^\n]{0,100}(?:лишь|только)\s+(?:экспериментальн\w*|прототип\w*|заготовк\w*|чернов\w*)",
            r"(?:лишь|только)\s+(?:экспериментальн\w*|прототип\w*|заготовк\w*|чернов\w*)[^\n]{0,100}(?:restore|восстанов\w*)",
            r"(?:restore|восстанов\w*)[^\n]{0,100}не\s+(?:был\w*\s+)?(?:зрел\w*|полноценн\w*)",
            r"(?:restore|восстанов\w*)[^\n]{0,100}(?:демонстрационн\w*|экспериментальн\w*|прототип\w*|заготовк\w*|чернов\w*|макет\w*|stub\w*)",
            r"(?:демонстрационн\w*|экспериментальн\w*|прототип\w*|заготовк\w*|чернов\w*|макет\w*|stub\w*)[^\n]{0,100}(?:restore|восстанов\w*)",
        ):
            assert not re.search(pattern, lower), paragraph


def validate_no_roadmap_status_copy(text: str) -> None:
    roadmap_part = section(text, "## Связь с утверждённым roadmap")
    assert "не дублирует текущие статусы roadmap" in roadmap_part
    assert "ROADMAP-v3.tsv" in roadmap_part
    # Policy задаёт правила adoption, но не копирует live row statuses из machine truth.
    for status in ("PAUSED_BY_CURRENT_DOCUMENT_APPLY", "BLOCKED_BY_PREVIOUS"):
        assert status not in roadmap_part, status
    assert not re.search(r"(?m)^\s*\d+\.\s+`[A-Z0-9_]+`\s+—\s+`(?:CLOSED|NEXT|PAUSED_BY_CURRENT_DOCUMENT_APPLY|BLOCKED_BY_PREVIOUS)`", roadmap_part)


def expect_rejected(check, mutated: str, label: str) -> None:
    try:
        check(mutated)
    except AssertionError:
        return
    raise AssertionError(f"negative fixture unexpectedly accepted: {label}")


assert "Модель отката после успешно завершённого APPLY" in policy
assert "`EXTERNAL_SNAPSHOT`" in policy
validate_restore_roadmap_boundary(policy)
validate_donor_restore_history_boundary(policy)
validate_artifact_contract(policy)
validate_no_roadmap_status_copy(policy)
assert "single distributable securelinux-ng.sh" not in policy
assert not any("RESTORE" in row["step_id"].upper() for row in rows)

expect_rejected(
    validate_restore_roadmap_boundary,
    policy + "\nRESTORE является этапом roadmap и ДОЛЖЕН появляться.\n",
    "restore_as_roadmap_stage",
)
expect_rejected(
    validate_donor_restore_history_boundary,
    policy.replace("исторический `SecureLinux-NG` имел полноценный", "исторический `SecureLinux-NG` сохранён в archive", 1),
    "donor_restore_history_omitted",
)
expect_rejected(
    validate_restore_roadmap_boundary,
    policy + "\nПользовательский RESTORE обязателен после APPLY.\n",
    "restore_operational_rephrase",
)
expect_rejected(
    validate_restore_roadmap_boundary,
    policy + "\nПосле APPLY предусматривается обязательное пользовательское восстановление системы средствами SecureLinux-Policy.\n",
    "restore_operational_euphemism",
)
expect_rejected(
    validate_artifact_contract,
    policy.replace(
        "детерминированным артефактом сборки, а не вручную поддерживаемым источником истины",
        "вручную поддерживаемым недетерминированным артефактом и источником истины",
        1,
    ),
    "manual_nondeterministic_artifact",
)
expect_rejected(
    validate_artifact_contract,
    policy + "\nИтоговый distributable поддерживается вручную, повторная сборка может отличаться.\n",
    "manual_nondeterministic_artifact_rephrase",
)
expect_rejected(
    validate_artifact_contract,
    policy + "\nПовторная сборка итогового артефакта не обязана совпадать побайтно с предыдущей.\n",
    "manual_nondeterministic_artifact_semantic_rephrase",
)
expect_rejected(
    validate_artifact_contract,
    policy + "\nБудущий итоговый distributable обязан называться `securelinux-ng.sh`.\n",
    "future_securelinux_ng_name",
)
expect_rejected(
    validate_donor_restore_history_boundary,
    policy + "\nИсторический режим восстановления у донора реализован не был.\n",
    "donor_restore_false_denial_rephrase",
)
expect_rejected(
    validate_artifact_contract,
    policy + "\nБудущий distributable вправе иметь разные байты при одинаковых входах.\n",
    "determinism_opposite_same_inputs_different_bytes",
)
expect_rejected(
    validate_donor_restore_history_boundary,
    policy + "\nИсторический donor RESTORE был лишь экспериментальной заготовкой.\n",
    "donor_restore_maturity_downgrade_rephrase",
)
expect_rejected(
    validate_artifact_contract,
    policy + "\nБудущий итоговый distributable обязан называться `securelinux-policy-v3.sh`.\n",
    "future_generic_shell_name_pin",
)
expect_rejected(
    validate_restore_roadmap_boundary,
    policy + "\nПосле APPLY обязателен возврат состояния средствами SecureLinux-Policy.\n",
    "post_apply_state_return_euphemism",
)
expect_rejected(
    validate_restore_roadmap_boundary,
    policy + "\nПосле успешного APPLY SecureLinux-Policy самостоятельно возвращает исходную конфигурацию средствами продукта.\n",
    "post_apply_original_configuration_return",
)
expect_rejected(
    validate_donor_restore_history_boundary,
    policy + "\nИсторический donor RESTORE представлял собой демонстрационный прототип.\n",
    "donor_restore_prototype_downgrade",
)
expect_rejected(
    validate_artifact_contract,
    policy + "\nДля будущего distributable одинаковый набор входов не гарантирует одинаковый результат генерации.\n",
    "determinism_not_guaranteed_same_inputs",
)
expect_rejected(
    validate_artifact_contract,
    policy + "\nИмя будущего исполняемого файла — `securelinux-policy-v3.sh`.\n",
    "future_executable_filename_pin",
)

expect_rejected(
    validate_artifact_contract,
    policy + "\nДля будущего distributable результат сборки при тех же входах может меняться.\n",
    "determinism_same_inputs_result_may_change",
)
print("SRC0001_APPLY_ARCHITECTURE_BINDING=PASS compact_registry=1 target_class=1 stale_registry=1 stale_dependency=2")
print("DONOR_POLICY_NEGATIVE_FIXTURES=PASS_18 restore_stage=5 donor_restore_history=4 artifact_truth=6 future_name=3")
print("DONOR_V3_POLICY=PASS donor_is_non_normative=1 roadmap_precondition=1")
