#!/usr/bin/env python3
from __future__ import annotations

import csv
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
    "apply_kind",
    "target_class",
    "allowed_paths",
    "predicate_id",
    "transform_id",
    "commit_model",
    "privilege",
    "exclusive_lock",
    "compensation_policy",
    "dry_run_required",
)


def load_apply_registry():
    with APPLY_REGISTRY_PATH.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        assert tuple(reader.fieldnames or ()) == APPLY_REGISTRY_FIELDS
        rows = list(reader)
    by_kind = {}
    for row in rows:
        kind = row["apply_kind"]
        assert kind and kind not in by_kind
        assert all(row[field] for field in APPLY_REGISTRY_FIELDS)
        by_kind[kind] = row
    assert by_kind
    return by_kind


def validate_apply_registry_binding(instance, registry):
    kind = instance["apply_kind"]
    assert kind in registry, f"unregistered apply_kind: {kind}"
    row = registry[kind]
    expected_paths = row["allowed_paths"].split(";")
    assert instance["mutation"]["allowed_paths"] == expected_paths
    assert instance["target_selection"]["predicate_id"] == row["predicate_id"]
    assert instance["mutation"]["transform_id"] == row["transform_id"]
    assert instance["transaction"]["commit_model"] == row["commit_model"]
    assert instance["privilege"] == row["privilege"]
    assert instance["concurrency"]["exclusive_lock"] == row["exclusive_lock"]
    if row["compensation_policy"] == "NO_SECURITY_WEAKENING_COMPENSATION":
        assert instance["recovery"]["security_weakening_compensation"] == "FORBIDDEN"
    else:
        raise AssertionError(
            f"unsupported compensation_policy for {kind}: {row['compensation_policy']}"
        )
    if row["dry_run_required"] == "true":
        assert instance["dry_run"]["required"] is True
    elif row["dry_run_required"] == "false":
        assert instance["dry_run"]["required"] is False
    else:
        raise AssertionError(
            f"invalid dry_run_required for {kind}: {row['dry_run_required']}"
        )


apply_registry = load_apply_registry()
apply_contract_paths = sorted(
    (ROOT / "product/contracts").glob("*-apply-semantic-v*.json")
)
for apply_contract_path in apply_contract_paths:
    current_apply_instance = json.loads(
        apply_contract_path.read_text(encoding="utf-8")
    )
    real_validator(apply_schema).validate(current_apply_instance)
    validate_apply_registry_binding(current_apply_instance, apply_registry)

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
validate_apply_registry_binding(apply_instance, apply_registry)


def rejected_registry_binding(mutator, label):
    candidate = json.loads(json.dumps(apply_instance))
    mutator(candidate)
    try:
        real_validator(apply_schema).validate(candidate)
        validate_apply_registry_binding(candidate, apply_registry)
    except Exception:
        return
    raise AssertionError(f"registry binding negative accepted: {label}")


rejected_registry_binding(
    lambda item: item.__setitem__("apply_kind", "unregistered-kind"),
    "unregistered_kind",
)
rejected_registry_binding(
    lambda item: item["mutation"].__setitem__("allowed_paths", ["/etc/passwd"]),
    "allowed_paths",
)
rejected_registry_binding(
    lambda item: item["target_selection"].__setitem__("predicate_id", "other"),
    "predicate_id",
)
rejected_registry_binding(
    lambda item: item["mutation"].__setitem__("transform_id", "other"),
    "transform_id",
)
rejected_registry_binding(
    lambda item: item["transaction"].__setitem__("commit_model", "MULTI_STEP_TRANSACTION"),
    "commit_model",
)
rejected_registry_binding(
    lambda item: item.__setitem__("privilege", "OTHER"),
    "privilege",
)
rejected_registry_binding(
    lambda item: item["concurrency"].__setitem__("exclusive_lock", "OTHER_LOCK"),
    "exclusive_lock",
)
rejected_registry_binding(
    lambda item: item["recovery"].__setitem__("security_weakening_compensation", "OTHER"),
    "compensation_policy",
)
rejected_registry_binding(
    lambda item: item["dry_run"].__setitem__("required", False),
    "dry_run_required",
)

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
    "apply_registry_binding=PASS_9 "
    "positive=1 negative_missing_dependency=1 negative_below_minimum=1"
)
