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
assert by_step["FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS"] == "NEXT"
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

# Parent schema remains accepted; compact registry now binds kind/target-class to architecture.
apply_schema_path = root / "product/contracts/apply-semantic-contract-v1.schema.json"
apply_registry_path = root / "product/APPLY-KIND-REGISTRY.tsv"
architecture_path = root / "product/contracts/src0001-apply/architecture-v1.json"
assert apply_schema_path.is_file() and apply_registry_path.is_file() and architecture_path.is_file()
apply_schema = json.loads(apply_schema_path.read_text(encoding="utf-8"))
assert apply_schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
assert apply_schema["$id"] == "urn:securelinux-policy-v3:apply-semantic-contract:v1"
with apply_registry_path.open(encoding="utf-8", newline="") as stream:
    reader = csv.DictReader(stream, delimiter="\t")
    assert tuple(reader.fieldnames or ()) == (
        "apply_kind", "target_class", "architecture_id", "architecture_path", "architecture_sha256"
    )
    apply_kinds = list(reader)
assert len(apply_kinds) == 1
row = apply_kinds[0]
assert row["apply_kind"] == "local-account-password-lock"
assert row["target_class"] == "shadow-password-field"
assert row["architecture_id"] == "src0001-local-account-password-state-apply-modular-v1"
assert row["architecture_path"] == "product/contracts/src0001-apply/architecture-v1.json"
import hashlib
def _sha(path):
    h = hashlib.sha256(); h.update(path.read_bytes()); return h.hexdigest()
assert row["architecture_sha256"] == _sha(architecture_path)
arch = json.loads(architecture_path.read_text(encoding="utf-8"))
assert arch["apply_kind"] == row["apply_kind"]
assert arch["target_class"] == row["target_class"]
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
wire = snapshot["evidence"]["wire_contract"]
assert wire["additional_properties"] is False
assert wire["required"] == ["attestation_version", "control_id", "host_identity", "prestate_sha256", "provider", "rollback_capable", "snapshot_id", "snapshot_scope", "source_row", "state", "target_path"]
assert set(wire["properties"]) == set(wire["required"])
assert wire["properties"]["host_identity"]["pattern"] == "^[0-9a-f]{32}$"
assert wire["properties"]["prestate_sha256"]["pattern"] == "^[0-9a-f]{64}$"
assert snapshot["evidence"]["claim_strength"] == "EXTERNAL_OPERATOR_ATTESTATION_NOT_PROVIDER_CRYPTOGRAPHIC_PROOF"
assert snapshot["evidence"]["constraints"]["snapshot_scope"] == "FULL_TARGET_HOST_OR_VM"
assert snapshot["evidence"]["constraints"]["state"] == "READY"
assert snapshot["evidence"]["constraints"]["rollback_capable"] is True
assert snapshot["precondition"]["target_prestate_binding"] == "SHA256_EXACT_FILE_BYTES"
assert snapshot["failure"]["missing_evidence"] == "ABORT_NO_MUTATION"
assert snapshot["failure"]["mismatched_evidence"] == "ABORT_NO_MUTATION"
assert snapshot["recovery_model"]["product_creates_snapshot"] is False
assert snapshot["recovery_model"]["product_restores_snapshot"] is False
lock_reread = json.loads((root / by_role["lock_reread"]["path"]).read_text(encoding="utf-8"))
assert lock_reread["definition_class"] == "APPLY_LOCK_REREAD"
assert lock_reread["lock"]["authority"] == "LIBC_LCKPWDF_PASSWORD_DATABASE_LOCK"
assert lock_reread["lock"]["api"] == "lckpwdf(3)"
assert lock_reread["lock"]["release_api"] == "ulckpwdf(3)"
assert lock_reread["lock"]["documented_lock_file"] == "/etc/.pwd.lock"
assert lock_reread["lock"]["interoperability"] == "SERIALIZES_WITH_PASSWORD_DATABASE_WRITERS_THAT_HONOR_LCKPWDF"
assert lock_reread["lock"]["noncooperating_direct_writers"] == "NOT_SERIALIZED_BY_LCKPWDF"
assert lock_reread["lock"]["mode"] == "EXCLUSIVE"
assert lock_reread["lock"]["acquire_before"] == "UNDER_LOCK_REREAD_AND_ANY_HOST_MUTATION"
assert lock_reread["reread"]["under_lock"] is True
assert lock_reread["reread"]["input_paths"] == ["/etc/passwd", "/etc/shadow"]
assert lock_reread["reread"]["comparator"]["all_input_file_sha256"] == "EXACT_EQUAL_BY_PATH"
assert lock_reread["reread"]["final_precommit_revalidation"]["required"] is True
assert lock_reread["reread"]["final_precommit_revalidation"]["failure"] == "ABORT_NO_MUTATION"
assert lock_reread["reread"]["comparator"]["selected_record_keys"] == "EXACT_EQUAL"
assert lock_reread["failure"]["stale_prestate"] == "ABORT_NO_MUTATION"
object_identity = json.loads((root / by_role["object_identity"]["path"]).read_text(encoding="utf-8"))
assert object_identity["definition_class"] == "APPLY_OBJECT_IDENTITY"
assert object_identity["identity"]["target"]["lstat_type"] == "REGULAR_FILE"
assert object_identity["identity"]["target"]["symlink"] == "FORBIDDEN"
assert object_identity["identity"]["target"]["st_nlink"] == 1
assert object_identity["identity"]["target"]["open_binding"] == "NOFOLLOW_FD_WITH_FSTAT_IDENTITY_MATCH"
assert object_identity["failure"]["identity_drift"] == "ABORT_NO_MUTATION"
assert object_identity["path_replacement_boundary"]["external_replace_between_capture_points"] == "STALE_ABORT_NO_MUTATION"
assert arch["implementation_binding"]["model"] == "SEPARATE_REGISTRY"
assert arch["composition_contract"]["state"] == "CLOSED"
composition_actual = json.loads((root / arch["composition_contract"]["path"]).read_text(encoding="utf-8"))
assert composition_actual["architecture_binding"]["sha256"] == hashlib.sha256((root / "product/contracts/src0001-apply/architecture-v1.json").read_bytes()).hexdigest()
assert set(composition_actual["definition_bindings"]) == set(by_role)
for role, binding in composition_actual["definition_bindings"].items():
    assert binding["sha256"] == by_role[role]["sha256"]
impl_binding_decl = arch["implementation_binding"]
assert impl_binding_decl["registry_state"] == "PRESENT"
assert tuple(impl_binding_decl["required_fields"]) == (
    "apply_kind", "composition_contract_id", "adapter_id", "binding_path",
    "binding_sha256", "implementation_path", "implementation_sha256",
)
impl_registry_path = root / impl_binding_decl["registry_path"]
assert impl_registry_path.is_file() and not impl_registry_path.is_symlink()
impl_lines = impl_registry_path.read_text(encoding="utf-8").splitlines()
assert len(impl_lines) == 2, impl_lines
assert tuple(impl_lines[0].split("\t")) == tuple(impl_binding_decl["required_fields"])
impl_row = dict(zip(impl_lines[0].split("\t"), impl_lines[1].split("\t")))
assert len(impl_row) == len(impl_binding_decl["required_fields"])
assert all(impl_row[field] for field in impl_binding_decl["required_fields"])
assert impl_row["apply_kind"] == arch["apply_kind"]
assert impl_row["composition_contract_id"] == composition_actual["composition_contract_id"]
for impl_rel in (impl_row["binding_path"], impl_row["implementation_path"]):
    assert impl_rel and not impl_rel.startswith("/")
    assert "\\" not in impl_rel and "\x00" not in impl_rel
    impl_parts = impl_rel.split("/")
    assert all(impl_parts) and "." not in impl_parts and ".." not in impl_parts
    impl_probe = root
    for impl_part in impl_parts:
        impl_probe = impl_probe / impl_part
        assert not impl_probe.is_symlink(), impl_rel
    assert impl_probe.is_file(), impl_rel
assert impl_row["binding_sha256"] == _sha(root / impl_row["binding_path"])
assert impl_row["implementation_sha256"] == _sha(root / impl_row["implementation_path"])
impl_binding_doc = json.loads(
    (root / impl_row["binding_path"]).read_text(encoding="utf-8")
)
assert set(impl_binding_doc) == {
    "adapter_id", "binding_contract_id",
    "composition_contract_path", "composition_contract_sha256",
}
assert impl_binding_doc["adapter_id"] == impl_row["adapter_id"]
assert impl_binding_doc["composition_contract_path"] == arch["composition_contract"]["path"]
assert impl_binding_doc["composition_contract_sha256"] == _sha(
    root / arch["composition_contract"]["path"]
)
for forbidden in ("allowed_paths", "predicate_id", "transform_id", "commit_model", "privilege", "exclusive_lock"):
    assert forbidden not in row

# Deterministic binding checker: stale registry SHA is repairable only by explicit --write;
# drift of a pinned dependency is never auto-rebound.
binding_tool = root / "tools/rebuild-apply-contract-bindings.py"
check = subprocess.run(
    ["/usr/bin/python3", "-I", "-S", "-B", str(binding_tool), "--project-root", str(root), "--check"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
)
assert check.returncode == 0, check.stdout + check.stderr
with tempfile.TemporaryDirectory(prefix="src0001-apply-binding-") as td:
    probe = Path(td)
    for rel in (
        "product/APPLY-KIND-REGISTRY.tsv",
        "product/contracts/src0001-apply/architecture-v1.json",
        "product/contracts/src0001-apply/composition-v1.schema.json",
        "product/contracts/src0001-apply/predicate-empty-second-shadow-field-v1.json",
        "product/contracts/src0001-apply/transform-empty-second-shadow-field-to-bang-v1.json",
        "product/contracts/src0001-apply/snapshot-precondition-v1.json",
        "product/contracts/src0001-apply/lock-reread-v1.json",
        "product/contracts/src0001-apply/object-identity-v1.json",
        "product/contracts/src0001-apply/metadata-preservation-v1.json",
        "product/contracts/src0001-apply/atomic-transaction-v1.json",
        "product/contracts/src0001-apply/dry-run-report-v1.json",
        "product/contracts/src0001-apply/composition-v1.json",
        "product/contracts/apply-semantic-contract-v1.schema.json",
        "product/contracts/local-account-password-state-apply-semantic-v1.json",
        "product/contracts/local-account-password-state-check-semantic-v2.json",
        "tools/rebuild-apply-contract-bindings.py",
    ):
        src = root / rel
        dst = probe / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    probe_reg = probe / "product/APPLY-KIND-REGISTRY.tsv"
    probe_reg.write_text(
        probe_reg.read_text(encoding="utf-8").replace(row["architecture_sha256"], "0" * 64),
        encoding="utf-8", newline="\n",
    )
    stale = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", "-B", str(probe / "tools/rebuild-apply-contract-bindings.py"), "--project-root", str(probe), "--check"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert stale.returncode == 1 and "stale" in stale.stderr.lower(), stale.stdout + stale.stderr
    repaired = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", "-B", str(probe / "tools/rebuild-apply-contract-bindings.py"), "--project-root", str(probe), "--write"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert repaired.returncode == 0, repaired.stdout + repaired.stderr
    predicate_probe = probe / "product/contracts/src0001-apply/predicate-empty-second-shadow-field-v1.json"
    predicate_original = predicate_probe.read_bytes()
    predicate_probe.write_bytes(predicate_original + b" ")
    stale_definition = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", "-B", str(probe / "tools/rebuild-apply-contract-bindings.py"), "--project-root", str(probe), "--check"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert stale_definition.returncode == 1 and "stale definition binding: predicate" in stale_definition.stderr, stale_definition.stdout + stale_definition.stderr
    predicate_probe.write_bytes(predicate_original)
    snapshot_probe = probe / "product/contracts/src0001-apply/snapshot-precondition-v1.json"
    snapshot_original = snapshot_probe.read_bytes()
    snapshot_probe.write_bytes(snapshot_original + b" ")
    stale_snapshot = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", "-B", str(probe / "tools/rebuild-apply-contract-bindings.py"), "--project-root", str(probe), "--check"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert stale_snapshot.returncode == 1 and "stale definition binding: snapshot_precondition" in stale_snapshot.stderr, stale_snapshot.stdout + stale_snapshot.stderr
    snapshot_probe.write_bytes(snapshot_original)
    for role_name, rel_path in (("lock_reread", "product/contracts/src0001-apply/lock-reread-v1.json"), ("object_identity", "product/contracts/src0001-apply/object-identity-v1.json")):
        role_probe = probe / rel_path
        role_original = role_probe.read_bytes()
        role_probe.write_bytes(role_original + b" ")
        stale_role = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-B", str(probe / "tools/rebuild-apply-contract-bindings.py"), "--project-root", str(probe), "--check"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert stale_role.returncode == 1 and f"stale definition binding: {role_name}" in stale_role.stderr, stale_role.stdout + stale_role.stderr
        role_probe.write_bytes(role_original)
    dependency = probe / "product/contracts/local-account-password-state-check-semantic-v2.json"
    dependency.write_bytes(dependency.read_bytes() + b" ")
    for mode in ("--check", "--write"):
        rejected = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-B", str(probe / "tools/rebuild-apply-contract-bindings.py"), "--project-root", str(probe), mode],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert rejected.returncode == 1 and "stale architecture binding" in rejected.stderr, (mode, rejected.stdout, rejected.stderr)

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
