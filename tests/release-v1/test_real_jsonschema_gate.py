#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = ROOT / "checker/release-v1/real_jsonschema_gate.py"

spec = importlib.util.spec_from_file_location(
    "real_jsonschema_gate_tested", GATE_PATH
)
gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(gate)

report = gate.run_gate(ROOT)
assert report["pass"] is True, report
assert report["jsonschema_version"]
assert report["minimum_jsonschema_version"] == "4.10.3"
assert gate.parse_jsonschema_release(report["jsonschema_version"]) >= (4, 10, 3)
assert report["validator_class"] == "Draft202012Validator"
assert report["draft"] == "2020-12"
assert report["checks"]["draft202012_check_schema"] is True
assert report["checks"]["schema_generation_parity"] is True
assert report["checks"]["runtime_real_parity"] is True
assert report["checks"]["emulator_real_parity"] is True
assert report["checks"]["all_kinds_bidirectional"] is True
assert report["matrix"]["total_cases"] >= 50
assert report["matrix"]["newline_cases"] >= 16
assert report["matrix"]["runtime_real_disagreements"] == []
assert report["matrix"]["emulator_real_disagreements"] == []
assert report["matrix"]["missing_kinds"] == []
assert report["matrix"]["one_sided_kinds"] == []

expected_active = len(list((ROOT / "controls").rglob("*.yaml")))
assert report["active_controls"]["count"] == expected_active
assert report["active_controls"]["runtime_invalid"] == []
assert report["active_controls"]["real_schema_invalid"] == []


def missing(_root):
    raise RuntimeError("simulated jsonschema absence")


negative = gate.run_gate(ROOT, dependency_loader=missing)
assert negative["pass"] is False
assert negative["jsonschema_version"] is None
assert any(
    "simulated jsonschema absence" in err
    for err in negative["errors"]
)

real_validator, _real_version = gate.require_real_jsonschema(ROOT)

apply_schema = json.loads(
    (ROOT / "product/contracts/apply-semantic-contract-v1.schema.json").read_text(encoding="utf-8")
)
real_validator.check_schema(apply_schema)

APPLY_REGISTRY_PATH = ROOT / "product/APPLY-KIND-REGISTRY.tsv"
APPLY_REGISTRY_FIELDS = (
    "apply_kind", "target_class", "architecture_id", "architecture_path", "architecture_sha256",
)
ARCHITECTURE_PATH = ROOT / "product/contracts/src0001-apply/architecture-v1.json"
COMPOSITION_SCHEMA_PATH = ROOT / "product/contracts/src0001-apply/composition-v1.schema.json"


def sha256_file(path):
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def load_apply_registry():
    with APPLY_REGISTRY_PATH.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        assert tuple(reader.fieldnames or ()) == APPLY_REGISTRY_FIELDS
        rows = list(reader)
    assert len(rows) == 1
    row = rows[0]
    assert all(row[field] for field in APPLY_REGISTRY_FIELDS)
    return row


def validate_architecture_binding(row):
    assert row["apply_kind"] == "local-account-password-lock"
    assert row["target_class"] == "shadow-password-field"
    assert row["architecture_id"] == "src0001-local-account-password-state-apply-modular-v1"
    assert row["architecture_path"] == "product/contracts/src0001-apply/architecture-v1.json"
    assert row["architecture_sha256"] == sha256_file(ARCHITECTURE_PATH)
    arch = json.loads(ARCHITECTURE_PATH.read_text(encoding="utf-8"))
    assert arch["architecture_id"] == row["architecture_id"]
    assert arch["apply_kind"] == row["apply_kind"]
    assert arch["target_class"] == row["target_class"]
    assert arch["source_row"] == "SRC-0001"
    assert arch["definition_reuse_scope"] == "SRC0001_SOURCE_LOCAL_UNTIL_SECOND_PROVEN_USE_CASE"
    assert arch["bindings"]["flat_candidate"]["status"] == "REVISE_INPUT_NOT_FINAL_AUTHORITY"
    for rec in arch["bindings"].values():
        bound = ROOT / rec["path"]
        assert bound.is_file() and not bound.is_symlink()
        assert sha256_file(bound) == rec["sha256"]
    expected_roles = [
        ("predicate", "src0001-empty-second-shadow-field-predicate-v1", "product/contracts/src0001-apply/predicate-empty-second-shadow-field-v1.json", "CLOSED"),
        ("transform", "src0001-empty-second-shadow-field-to-bang-transform-v1", "product/contracts/src0001-apply/transform-empty-second-shadow-field-to-bang-v1.json", "CLOSED"),
        ("snapshot_precondition", "src0001-external-snapshot-precondition-v1", "product/contracts/src0001-apply/snapshot-precondition-v1.json", "CLOSED"),
        ("lock_reread", "src0001-account-db-lock-reread-v1", "product/contracts/src0001-apply/lock-reread-v1.json", "CLOSED"),
        ("object_identity", "src0001-shadow-object-identity-v1", "product/contracts/src0001-apply/object-identity-v1.json", "CLOSED"),
        ("metadata_preservation", "src0001-shadow-metadata-preservation-v1", "product/contracts/src0001-apply/metadata-preservation-v1.json", "CLOSED"),
        ("atomic_transaction", "src0001-shadow-atomic-transaction-v1", "product/contracts/src0001-apply/atomic-transaction-v1.json", "CLOSED"),
        ("dry_run_report", "src0001-dry-run-report-v1", "product/contracts/src0001-apply/dry-run-report-v1.json", "CLOSED"),
    ]
    assert len(arch["definition_roles"]) == len(expected_roles)
    for rec, expected in zip(arch["definition_roles"], expected_roles):
        role, definition_id, rel, state = expected
        assert rec["role"] == role
        assert rec["definition_id"] == definition_id
        assert rec["path"] == rel
        assert rec["state"] == state
        target = ROOT / rel
        if state == "CLOSED":
            assert target.is_file() and not target.is_symlink()
            assert rec["sha256"] == sha256_file(target)
        else:
            assert "sha256" not in rec
            assert not target.exists()
    assert arch["definition_progress"] == {
        "closed_roles": ["predicate", "transform", "snapshot_precondition", "lock_reread", "object_identity", "metadata_preservation", "atomic_transaction", "dry_run_report"],
        "pending_roles": [],
    }
    assert arch["composition_contract"]["state"] == "CLOSED"
    assert (ROOT / arch["composition_contract"]["path"]).is_file()
    assert arch["implementation_binding"]["model"] == "SEPARATE_REGISTRY"
    impl_binding_decl = arch["implementation_binding"]
    assert impl_binding_decl["registry_state"] == "PRESENT"
    assert tuple(impl_binding_decl["required_fields"]) == (
        "apply_kind", "composition_contract_id", "adapter_id", "binding_path",
        "binding_sha256", "implementation_path", "implementation_sha256",
    )
    impl_registry_path = ROOT / impl_binding_decl["registry_path"]
    assert impl_registry_path.is_file() and not impl_registry_path.is_symlink()
    impl_lines = impl_registry_path.read_text(encoding="utf-8").splitlines()
    assert len(impl_lines) == 2, impl_lines
    assert tuple(impl_lines[0].split("\t")) == tuple(impl_binding_decl["required_fields"])
    impl_row = dict(zip(impl_lines[0].split("\t"), impl_lines[1].split("\t")))
    assert len(impl_row) == len(impl_binding_decl["required_fields"])
    assert all(impl_row[field] for field in impl_binding_decl["required_fields"])
    assert impl_row["apply_kind"] == arch["apply_kind"]
    composition_doc = json.loads(
        (ROOT / arch["composition_contract"]["path"]).read_text(encoding="utf-8")
    )
    assert impl_row["composition_contract_id"] == composition_doc["composition_contract_id"]
    for impl_rel in (impl_row["binding_path"], impl_row["implementation_path"]):
        assert impl_rel and not impl_rel.startswith("/")
        assert "\\" not in impl_rel and "\x00" not in impl_rel
        impl_parts = impl_rel.split("/")
        assert all(impl_parts) and "." not in impl_parts and ".." not in impl_parts
        impl_probe = ROOT
        for impl_part in impl_parts:
            impl_probe = impl_probe / impl_part
            assert not impl_probe.is_symlink(), impl_rel
        assert impl_probe.is_file(), impl_rel
    assert impl_row["binding_sha256"] == sha256_file(ROOT / impl_row["binding_path"])
    assert impl_row["implementation_sha256"] == sha256_file(
        ROOT / impl_row["implementation_path"]
    )
    impl_binding_doc = json.loads(
        (ROOT / impl_row["binding_path"]).read_text(encoding="utf-8")
    )
    assert set(impl_binding_doc) == {
        "adapter_id", "binding_contract_id",
        "composition_contract_path", "composition_contract_sha256",
    }
    assert impl_binding_doc["adapter_id"] == impl_row["adapter_id"]
    assert impl_binding_doc["composition_contract_path"] == arch["composition_contract"]["path"]
    assert impl_binding_doc["composition_contract_sha256"] == sha256_file(
        ROOT / arch["composition_contract"]["path"]
    )
    return arch


apply_registry = load_apply_registry()
apply_architecture = validate_architecture_binding(apply_registry)

PREDICATE_PATH = ROOT / "product/contracts/src0001-apply/predicate-empty-second-shadow-field-v1.json"
TRANSFORM_PATH = ROOT / "product/contracts/src0001-apply/transform-empty-second-shadow-field-to-bang-v1.json"
predicate_definition = json.loads(PREDICATE_PATH.read_text(encoding="utf-8"))
transform_definition = json.loads(TRANSFORM_PATH.read_text(encoding="utf-8"))
SNAPSHOT_PATH = ROOT / "product/contracts/src0001-apply/snapshot-precondition-v1.json"
snapshot_definition = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
P06_EXPECTED_SHA256 = {
    "product/contracts/src0001-apply/metadata-preservation-v1.json": "b380cb242f8b4141301cc196b5f2abf4e09373b90886ac94a7dcd8d899fb990c",
    "product/contracts/src0001-apply/atomic-transaction-v1.json": "a171356ea7521e52be5883cff8f785ac12a95857b5e950094aa615e0472e5ee4",
    "product/contracts/src0001-apply/dry-run-report-v1.json": "aa9e57dc2533fa95b4e2de87f8ba9aeec098b7bf5b439fbb96c6645b44a7eaaf",
}
for rel, expected_sha in P06_EXPECTED_SHA256.items():
    assert sha256_file(ROOT / rel) == expected_sha



def validate_snapshot_definition(item):
    assert item["definition_class"] == "APPLY_SNAPSHOT_PRECONDITION"
    assert item["definition_id"] == "src0001-external-snapshot-precondition-v1"
    assert item["definition_version"] == 1
    assert item["source_row"] == "SRC-0001"
    assert item["control_id"] == "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE"
    assert item["target_class"] == "shadow-password-field"
    assert item["target"] == {"path": "/etc/shadow", "prestate_digest": "SHA256_EXACT_FILE_BYTES"}
    assert item["precondition"] == {
        "comparison_time": "BEFORE_ANY_HOST_MUTATION",
        "host_identity_binding": "EXACT_TRIMMED_MACHINE_ID_BYTES",
        "required_before_host_mutation": True,
        "target_prestate_binding": "SHA256_EXACT_FILE_BYTES",
    }
    assert item["evidence"]["carrier"] == "CALLER_SUPPLIED_READ_ONLY_JSON_FILE"
    assert item["evidence"]["format"] == "SLP-EXTERNAL-SNAPSHOT-ATTESTATION-V1"
    assert item["evidence"]["claim_strength"] == "EXTERNAL_OPERATOR_ATTESTATION_NOT_PROVIDER_CRYPTOGRAPHIC_PROOF"
    wire = item["evidence"]["wire_contract"]
    required = ["attestation_version", "control_id", "host_identity", "prestate_sha256", "provider", "rollback_capable", "snapshot_id", "snapshot_scope", "source_row", "state", "target_path"]
    assert wire["type"] == "object" and wire["additional_properties"] is False
    assert wire["required"] == required and set(wire["properties"]) == set(required)
    assert wire["properties"]["host_identity"] == {"binding": "EXACT_TRIMMED_MACHINE_ID_BYTES", "pattern": "^[0-9a-f]{32}$", "type": "string"}
    assert wire["properties"]["prestate_sha256"] == {"binding": "SHA256_EXACT_FILE_BYTES:/etc/shadow", "pattern": "^[0-9a-f]{64}$", "type": "string"}
    expected_negative = {"MISSING_HOST_IDENTITY", "MISSING_PRESTATE_SHA256", "UNKNOWN_TOP_LEVEL_FIELD", "DUPLICATE_TOP_LEVEL_KEY", "HOST_IDENTITY_WRONG_JSON_TYPE", "HOST_IDENTITY_BAD_FORMAT", "HOST_IDENTITY_MISMATCH", "PRESTATE_SHA256_WRONG_JSON_TYPE", "PRESTATE_SHA256_BAD_FORMAT", "PRESTATE_SHA256_MISMATCH", "STATE_NOT_READY", "ROLLBACK_CAPABLE_FALSE", "INVALID_PROVIDER_OR_SNAPSHOT_ID"}
    assert {x["case"] for x in item["evidence"]["required_negative_fixtures"]} == expected_negative
    assert all(x["expected"] == "ABORT_NO_MUTATION" for x in item["evidence"]["required_negative_fixtures"])
    c=item["evidence"]["constraints"]
    assert c["host_identity_source"] == "/etc/machine-id"
    assert c["snapshot_scope"] == "FULL_TARGET_HOST_OR_VM"
    assert c["state"] == "READY" and c["rollback_capable"] is True
    assert c["target_path"] == "/etc/shadow" and c["prestate_sha256_format"] == "LOWERCASE_HEX_64"
    assert item["failure"] == {
        "error_value_contract": "domain:reason",
        "invalid_evidence": "ABORT_NO_MUTATION",
        "literal_dash_for_error": False,
        "mismatched_evidence": "ABORT_NO_MUTATION",
        "missing_evidence": "ABORT_NO_MUTATION",
        "provider_state_not_ready": "ABORT_NO_MUTATION",
    }
    assert item["recovery_model"] == {
        "failed_uncommitted_apply": "TRANSACTION_LOCAL_COMPENSATION_ONLY",
        "product_creates_snapshot": False,
        "product_restores_snapshot": False,
        "successful_apply_recovery": "EXTERNAL_SNAPSHOT_ROLLBACK_ONLY",
        "user_invokable_restore": False,
    }


def validate_predicate_definition(item):
    assert item == {
        "check_population_authority_binding": {
            "path": "product/contracts/local-account-password-state-check-semantic-v2.json",
            "semantic_contract_id": "local-account-password-state-check-semantic-v2",
            "sha256": "8351b4431f8f6ddd403afb4315cf2f8b5ebcf3f8d9c38f91bb3778e5086593cc",
        },
        "control_id": "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE",
        "definition_class": "APPLY_PREDICATE",
        "definition_id": "src0001-empty-second-shadow-field-predicate-v1",
        "definition_version": 1,
        "failure": {
            "ambiguous_or_malformed": "ABORT_NO_MUTATION",
            "error_value_contract": "domain:reason",
            "literal_dash_for_error": False,
        },
        "input_field": {
            "field": "password-field",
            "field_index_1_based": 2,
            "path": "/etc/shadow",
            "raw_byte_contract": "BOUND_CHECK_V2_NUL_OR_CR_REJECTED_BEFORE_LINE_PARSING",
            "record_key_field": "username",
            "record_key_field_index_1_based": 1,
        },
        "population_scope": {
            "authority": "BOUND_CURRENT_CHECK_SEMANTIC",
            "extra_shadow_records": "OUTSIDE_TARGET_POPULATION_PRESERVE_UNCHANGED",
            "partial_or_ambiguous_population": "ABORT_NO_MUTATION",
            "rule": "EXACT_PASSWD_ACCOUNT_POPULATION_WITH_UNIQUE_SHADOW_MAPPING",
        },
        "precondition": {
            "check_error": "ABORT_NO_MUTATION",
            "check_pass": "NOOP_SUCCESS",
            "current_check_result": "FAIL",
        },
        "predicate": {
            "expected_length": 0,
            "match": "SELECT_FOR_TRANSFORM",
            "nonmatch": "NOT_SELECTED_PRESERVE_UNCHANGED",
            "operator": "BYTE_LENGTH_EQ",
        },
        "source_row": "SRC-0001",
        "target_class": "shadow-password-field",
    }
    bound = ROOT / item["check_population_authority_binding"]["path"]
    assert item["check_population_authority_binding"]["sha256"] == sha256_file(bound)


def validate_transform_definition(item):
    assert item == {
        "cardinality": {"byte_delta_per_selected_record": 1, "records_added": 0, "records_removed": 0},
        "control_id": "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE",
        "definition_class": "APPLY_TRANSFORM",
        "definition_id": "src0001-empty-second-shadow-field-to-bang-transform-v1",
        "definition_version": 1,
        "forbidden": [
            "transform non-empty password field",
            "modify account name",
            "modify non-selected record",
            "modify any field other than selected second field",
            "generate password hash or secret",
            "add or remove shadow record",
        ],
        "postcondition": {
            "bound_predicate_matches_after_transform": False,
            "idempotent_reapply": "NO_MUTATION",
            "selected_field_bytes_hex": "21",
        },
        "precondition": {
            "input_field_bytes_hex": "",
            "selected_by_bound_predicate": True,
            "stale_or_nonempty_selected_field": "ABORT_NO_MUTATION",
        },
        "predicate_binding": {
            "definition_id": "src0001-empty-second-shadow-field-predicate-v1",
            "path": "product/contracts/src0001-apply/predicate-empty-second-shadow-field-v1.json",
            "sha256": sha256_file(PREDICATE_PATH),
        },
        "preservation": {
            "file_bytes_outside_selected_second_fields": "EXACT",
            "nonempty_password_field_bytes": "EXACT",
            "nonselected_record_bytes": "EXACT",
            "record_delimiter_bytes": "EXACT",
            "record_order": "EXACT",
            "selected_record_all_other_field_bytes": "EXACT",
            "selected_record_username_bytes": "EXACT",
        },
        "source_row": "SRC-0001",
        "target": {"field": "password-field", "field_index_1_based": 2, "path": "/etc/shadow"},
        "target_class": "shadow-password-field",
        "transform": {
            "generated_secret": False,
            "input_field_bytes_hex": "",
            "operation": "EXACT_FIELD_BYTE_REPLACEMENT",
            "output_field_bytes_hex": "21",
            "output_field_utf8": "!",
        },
    }


def rejected_definition(base, validator, mutator, label):
    candidate = json.loads(json.dumps(base))
    mutator(candidate)
    try:
        validator(candidate)
    except Exception:
        return
    raise AssertionError(f"SRC-0001 definition negative accepted: {label}")


validate_predicate_definition(predicate_definition)
validate_transform_definition(transform_definition)
validate_snapshot_definition(snapshot_definition)
rejected_definition(predicate_definition, validate_predicate_definition, lambda x: x["predicate"].__setitem__("expected_length", 1), "predicate_nonempty")
rejected_definition(predicate_definition, validate_predicate_definition, lambda x: x["input_field"].__setitem__("field_index_1_based", 3), "predicate_wrong_field")
rejected_definition(predicate_definition, validate_predicate_definition, lambda x: x["population_scope"].__setitem__("authority", "DONOR"), "predicate_wrong_authority")
rejected_definition(predicate_definition, validate_predicate_definition, lambda x: x["precondition"].__setitem__("check_error", "SELECT_FOR_TRANSFORM"), "predicate_check_error")
rejected_definition(transform_definition, validate_transform_definition, lambda x: x["transform"].__setitem__("output_field_bytes_hex", "2121"), "transform_double_bang")
rejected_definition(transform_definition, validate_transform_definition, lambda x: x["transform"].__setitem__("generated_secret", True), "transform_generated_secret")
rejected_definition(transform_definition, validate_transform_definition, lambda x: x["preservation"].__setitem__("nonselected_record_bytes", "MAY_CHANGE"), "transform_nonselected_drift")
rejected_definition(transform_definition, validate_transform_definition, lambda x: x["precondition"].__setitem__("stale_or_nonempty_selected_field", "CONTINUE"), "transform_stale_continue")
rejected_definition(snapshot_definition, validate_snapshot_definition, lambda x: x["failure"].__setitem__("missing_evidence", "CONTINUE"), "snapshot_missing_continue")
rejected_definition(snapshot_definition, validate_snapshot_definition, lambda x: x["evidence"]["constraints"].__setitem__("snapshot_scope", "FILE_ONLY"), "snapshot_scope_narrow")
rejected_definition(snapshot_definition, validate_snapshot_definition, lambda x: x["evidence"].__setitem__("claim_strength", "CRYPTOGRAPHIC_PROOF"), "snapshot_false_proof")
rejected_definition(snapshot_definition, validate_snapshot_definition, lambda x: x["recovery_model"].__setitem__("product_restores_snapshot", True), "snapshot_product_restore")
print("SRC0001_PREDICATE_TRANSFORM_DEFINITIONS=PASS positive=2 negative=8 exact_empty=1 exact_bang=1")
print("SRC0001_SNAPSHOT_PRECONDITION_DEFINITION=PASS positive=1 negative=4 prestate_binding=1 fail_closed=1")

composition_schema = json.loads(COMPOSITION_SCHEMA_PATH.read_text(encoding="utf-8"))
real_validator.check_schema(composition_schema)
assert composition_schema["$id"] == "urn:securelinux-policy-v3:src0001-apply-composition:v1"

apply_contract_paths = sorted(
    (ROOT / "product/contracts").glob("*-apply-semantic-v*.json")
)
for apply_contract_path in apply_contract_paths:
    current_apply_instance = json.loads(
        apply_contract_path.read_text(encoding="utf-8")
    )
    real_validator(apply_schema).validate(current_apply_instance)

apply_instance = {
    "semantic_contract_id": "local-account-password-state-apply-semantic-v1",
    "semantic_contract_version": 1,
    "contract_class": "APPLY",
    "source_row": "SRC-0001",
    "control_id": "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE",
    "check_contract_id": "local-account-password-state-check-semantic-v2",
    "target_id": "linux-x86_64-supported-v1",
    "apply_kind": "local-account-password-lock",
    "precondition": {
        "check_pass": "NOOP_SUCCESS",
        "check_fail": "ELIGIBLE_FOR_APPLY",
        "check_error": "ABORT_NO_MUTATION",
    },
    "privilege": "ROOT_REQUIRED_FAIL_CLOSED",
    "target_selection": {
        "population_authority": "current CHECK semantic v2",
        "predicate_id": "empty-password-field",
        "exact_set_required": True,
    },
    "mutation": {
        "allowed_paths": ["/etc/shadow"],
        "transform_id": "empty-field-to-bang",
        "preserve_unrelated_bytes": True,
        "preserve_present_security_metadata": True,
        "no_generated_secret": True,
    },
    "concurrency": {
        "exclusive_lock": "SYSTEM_ACCOUNT_DB_LOCK",
        "reread_under_lock": True,
        "stale_prestate": "ABORT_NO_MUTATION",
    },
    "transaction": {
        "commit_model": "SINGLE_ATOMIC_FILE_COMMIT",
        "before_commit_failure": "CLEANUP_TEMP_ONLY",
        "after_mutation_failure": "NO_UNSAFE_COMPENSATION_EXTERNAL_RECOVERY",
    },
    "postcondition": {
        "current_check_required": True,
        "required_compliance": "PASS",
        "idempotent_reapply": "NO_MUTATION",
    },
    "recovery": {
        "user_restore": False,
        "successful_apply": "EXTERNAL_SNAPSHOT",
        "security_weakening_compensation": "FORBIDDEN",
    },
    "dry_run": {
        "required": True,
        "host_mutation": False,
        "must_report_exact_target_set": True,
    },
    "forbidden": ["user-invokable RESTORE"],
    "donor_mapping": [
        {"mapping_id": "MAP-FUNC-0226", "decision": "ADAPT", "usage": "transaction mechanics only"},
        {"mapping_id": "MAP-FUNC-0296", "decision": "REJECT", "usage": "standalone RESTORE excluded"},
    ],
}
real_validator(apply_schema).validate(apply_instance)


src0001_apply_path = ROOT / "product/contracts/local-account-password-state-apply-semantic-v1.json"
assert src0001_apply_path.is_file() and not src0001_apply_path.is_symlink()
src0001_apply = json.loads(src0001_apply_path.read_text(encoding="utf-8"))


def validate_src0001_apply_semantics(item):
    assert item["semantic_contract_id"] == "local-account-password-state-apply-semantic-v1"
    assert item["semantic_contract_version"] == 1
    assert item["contract_class"] == "APPLY"
    assert item["source_row"] == "SRC-0001"
    assert item["control_id"] == "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE"
    assert item["check_contract_id"] == "local-account-password-state-check-semantic-v2"
    assert item["target_id"] == "linux-x86_64-supported-v1"
    assert item["apply_kind"] == "local-account-password-lock"
    assert item["precondition"] == {
        "check_pass": "NOOP_SUCCESS",
        "check_fail": "ELIGIBLE_FOR_APPLY",
        "check_error": "ABORT_NO_MUTATION",
    }
    assert item["target_selection"] == {
        "population_authority": "current CHECK semantic v2",
        "predicate_id": "empty-password-field",
        "exact_set_required": True,
    }
    assert item["mutation"]["allowed_paths"] == ["/etc/shadow"]
    assert item["mutation"]["transform_id"] == "empty-field-to-bang"
    assert item["mutation"]["preserve_unrelated_bytes"] is True
    assert item["mutation"]["preserve_present_security_metadata"] is True
    assert item["mutation"]["no_generated_secret"] is True
    assert item["concurrency"] == {
        "exclusive_lock": "SYSTEM_ACCOUNT_DB_LOCK",
        "reread_under_lock": True,
        "stale_prestate": "ABORT_NO_MUTATION",
    }
    assert item["transaction"] == {
        "commit_model": "SINGLE_ATOMIC_FILE_COMMIT",
        "before_commit_failure": "CLEANUP_TEMP_ONLY",
        "after_mutation_failure": "NO_UNSAFE_COMPENSATION_EXTERNAL_RECOVERY",
    }
    assert item["postcondition"] == {
        "current_check_required": True,
        "required_compliance": "PASS",
        "idempotent_reapply": "NO_MUTATION",
    }
    assert item["recovery"] == {
        "user_restore": False,
        "successful_apply": "EXTERNAL_SNAPSHOT",
        "security_weakening_compensation": "FORBIDDEN",
    }
    assert item["dry_run"] == {
        "required": True,
        "host_mutation": False,
        "must_report_exact_target_set": True,
    }
    assert item["forbidden"] == ["user-invokable RESTORE"]
    assert item["donor_mapping"] == [
        {"mapping_id": "MAP-FUNC-0226", "decision": "ADAPT", "usage": "transaction mechanics only"},
        {"mapping_id": "MAP-FUNC-0296", "decision": "REJECT", "usage": "standalone RESTORE excluded"},
    ]


validate_src0001_apply_semantics(src0001_apply)
assert src0001_apply == apply_instance


def rejected_src0001_semantics(mutator, label):
    candidate = json.loads(json.dumps(src0001_apply))
    mutator(candidate)
    try:
        real_validator(apply_schema).validate(candidate)
        validate_src0001_apply_semantics(candidate)
    except Exception:
        return
    raise AssertionError(f"SRC-0001 APPLY semantic negative accepted: {label}")


rejected_src0001_semantics(
    lambda item: item["mutation"].__setitem__("no_generated_secret", False),
    "generated_secret",
)
rejected_src0001_semantics(
    lambda item: item["target_selection"].__setitem__("population_authority", "donor"),
    "population_authority",
)
rejected_src0001_semantics(
    lambda item: item["precondition"].__setitem__("check_error", "ELIGIBLE_FOR_APPLY"),
    "check_error",
)
rejected_src0001_semantics(
    lambda item: item["recovery"].__setitem__("user_restore", True),
    "user_restore",
)
rejected_src0001_semantics(
    lambda item: item["dry_run"].__setitem__("host_mutation", True),
    "dry_run_host_mutation",
)
rejected_src0001_semantics(
    lambda item: item.__setitem__("forbidden", []),
    "restore_forbidden",
)
print("SRC0001_APPLY_SEMANTIC_FIXTURES=PASS_7 positive=1 negative=6")


valid_composition = {
    "composition_contract_id": "local-account-password-state-apply-composition-v1",
    "composition_contract_version": 1,
    "contract_class": "APPLY_COMPOSITION",
    "source_row": "SRC-0001",
    "control_id": "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE",
    "apply_kind": "local-account-password-lock",
    "target_class": "shadow-password-field",
    "architecture_binding": {
        "architecture_id": apply_architecture["architecture_id"],
        "path": "product/contracts/src0001-apply/architecture-v1.json",
        "sha256": sha256_file(ARCHITECTURE_PATH),
    },
    "parent_contract_binding": {
        "semantic_contract_id": "local-account-password-state-apply-semantic-v1",
        "path": "product/contracts/local-account-password-state-apply-semantic-v1.json",
        "sha256": "48e008ac5cd7da8e17dac3f5cef556cb9def3ba36051e4623bc2255ca3c312be",
    },
    "check_population_authority_binding": {
        "semantic_contract_id": "local-account-password-state-check-semantic-v2",
        "path": "product/contracts/local-account-password-state-check-semantic-v2.json",
        "sha256": "8351b4431f8f6ddd403afb4315cf2f8b5ebcf3f8d9c38f91bb3778e5086593cc",
    },
    "definition_bindings": {},
    "compatibility_chain": apply_architecture["compatibility_chain"],
    "postcondition": {
        "check_contract_id": "local-account-password-state-check-semantic-v2",
        "required_compliance": "PASS",
        "idempotent_reapply": "NO_MUTATION",
    },
}
for role in apply_architecture["definition_roles"]:
    valid_composition["definition_bindings"][role["role"]] = {
        "definition_id": role["definition_id"],
        "path": role["path"],
        "sha256": role["sha256"],
    }
real_validator(composition_schema).validate(valid_composition)
actual_composition = json.loads((ROOT / apply_architecture["composition_contract"]["path"]).read_text(encoding="utf-8"))
assert actual_composition == valid_composition
real_validator(composition_schema).validate(actual_composition)


def rejected_composition(mutator, label):
    candidate = json.loads(json.dumps(valid_composition))
    mutator(candidate)
    try:
        real_validator(composition_schema).validate(candidate)
    except Exception:
        return
    raise AssertionError(f"SRC-0001 composition schema negative accepted: {label}")


rejected_composition(lambda x: x.__setitem__("target_class", "other"), "target_class")
rejected_composition(lambda x: x.__setitem__("source_row", "SRC-0002"), "source_row")
rejected_composition(lambda x: x["definition_bindings"].pop("predicate"), "missing_predicate")
rejected_composition(
    lambda x: x["definition_bindings"]["predicate"].__setitem__("definition_id", "src0001-other-v1"),
    "predicate_identity",
)
rejected_composition(lambda x: x["definition_bindings"].__setitem__("extra", x["definition_bindings"]["predicate"]), "extra_role")
print("SRC0001_APPLY_COMPOSITION_SCHEMA=PASS positive=1 negative=5 roles=8")

invalid_apply_instance = dict(apply_instance)
invalid_apply_instance["contract_class"] = "CHECK"
try:
    real_validator(apply_schema).validate(invalid_apply_instance)
except Exception:
    pass
else:
    raise AssertionError("APPLY schema accepted contract_class=CHECK")

def below_minimum(_root):
    return real_validator, "4.10.2"

negative_version = gate.run_gate(ROOT, dependency_loader=below_minimum)
assert negative_version["pass"] is False
assert negative_version["jsonschema_version"] is None
assert any(
    "below minimum supported 4.10.3" in err
    for err in negative_version["errors"]
)

print(
    "REAL_JSONSCHEMA_RELEASE_TESTS=PASS "
    f"version={report['jsonschema_version']} "
    f"apply_instances={len(apply_contract_paths)} "
    "apply_architecture_binding=PASS compact_registry=1 definitions=PASS_2_POSITIVE_8_NEGATIVE composition_schema=PASS_5_NEGATIVE "
    "positive=1 negative_missing_dependency=1 negative_below_minimum=1"
)
