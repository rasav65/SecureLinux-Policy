#!/usr/bin/env python3
"""Failing-first regressions for the file-mode-owner APPLY mechanism.

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every mutation case runs against files created inside a temporary directory
owned by the current user. No system path is touched and root is not required.

The adapter under test does not exist yet: this file defines the contract it
must satisfy. Until it exists every class below fails on import.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

CONTRACT = ROOT / "product/contracts/mechanism-file-mode-owner-v1.json"
BINDING = ROOT / "product/apply-adapters/product-file-mode-owner-apply-v1.json"
ADAPTER = ROOT / "product/apply-adapters/product-file-mode-owner-apply-v1.py"
KIND_REGISTRY = ROOT / "product/APPLY-KIND-REGISTRY.tsv"
IMPL_REGISTRY = ROOT / "product/APPLY-IMPLEMENTATION-REGISTRY.tsv"
CONTROL_DIR = ROOT / "controls/fstec-core/linux-2022"

APPLY_KIND = "file-mode-owner-v1"
PARAMETER_KIND = "file-mode-owner"
ADAPTER_ID = "product-file-mode-owner-apply-v1"
TARGET_ID = "linux-x86_64-supported-v1"

CONTROLS = {
    "FSTEC-LINUX-2022-2.3.1-GROUP-MODE": ("/etc/group", "eq", "0644"),
    "FSTEC-LINUX-2022-2.3.1-PASSWD-MODE": ("/etc/passwd", "eq", "0644"),
    "FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX": ("/etc/shadow", "bits-clear", "0077"),
}


def load_adapter():
    spec = importlib.util.spec_from_file_location("slp_fmo_apply", ADAPTER)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load adapter: {ADAPTER}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_tsv(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"))) for line in lines[1:] if line]


def make_target(tmp: str, name: str, mode: int) -> str:
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("fixture\n")
    os.chmod(path, mode)
    return path


def mode_of(path: str) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


class T01_AuthorityAndRegistries(unittest.TestCase):
    """Mechanism identity is expressible by the current generator rules."""

    def test_contract_exists_and_is_json(self):
        self.assertTrue(CONTRACT.is_file(), f"missing {CONTRACT}")
        json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_authority_identity_fields(self):
        doc = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(doc["authority_form"], "MECHANISM_AUTHORITY_V1")
        self.assertEqual(doc["mechanism_id"], APPLY_KIND)
        self.assertEqual(doc["apply_kind"], APPLY_KIND)
        rb = doc["registry_binding"]
        self.assertEqual(
            set(rb),
            {
                "apply_kind", "parameter_kind", "target_class", "architecture_id",
                "composition_contract_id", "authority_path",
                "legacy_column_semantics", "adapter_id", "binding_contract_id",
            },
        )
        self.assertEqual(rb["authority_path"], "product/contracts/mechanism-file-mode-owner-v1.json")

    def test_kind_registry_row_matches_authority(self):
        rows = [r for r in read_tsv(KIND_REGISTRY) if r["apply_kind"] == APPLY_KIND]
        self.assertEqual(len(rows), 1, "exactly one APPLY kind row expected")
        row = rows[0]
        rb = json.loads(CONTRACT.read_text(encoding="utf-8"))["registry_binding"]
        for field in ("apply_kind", "parameter_kind", "target_class", "architecture_id"):
            self.assertEqual(row[field], rb[field], field)
        self.assertEqual(row["authority_form"], "MECHANISM_AUTHORITY_V1")
        self.assertEqual(row["architecture_path"], rb["authority_path"])

    def test_one_parameter_kind_route(self):
        kinds = [r["parameter_kind"] for r in read_tsv(KIND_REGISTRY)]
        self.assertEqual(len(kinds), len(set(kinds)), "duplicate parameter_kind route")

    def test_implementation_registry_and_binding(self):
        rows = [r for r in read_tsv(IMPL_REGISTRY) if r["apply_kind"] == APPLY_KIND]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["adapter_id"], ADAPTER_ID)
        binding = json.loads(BINDING.read_text(encoding="utf-8"))
        self.assertEqual(
            set(binding),
            {"adapter_id", "binding_contract_id", "composition_contract_path", "composition_contract_sha256"},
        )
        self.assertEqual(binding["composition_contract_path"], "product/contracts/mechanism-file-mode-owner-v1.json")

    def test_allowed_paths_equal_control_locators(self):
        doc = json.loads(CONTRACT.read_text(encoding="utf-8"))
        declared = set(doc["mutation"]["allowed_paths"])
        self.assertEqual(declared, {locator for locator, _, _ in CONTROLS.values()})

    def test_controls_declare_apply_supported(self):
        found = {}
        for path in sorted(CONTROL_DIR.glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            for control_id in CONTROLS:
                if f'id: "{control_id}"' in text:
                    found[control_id] = text
        self.assertEqual(set(found), set(CONTROLS), "control files not found")
        for control_id, text in found.items():
            self.assertIn("supported: true", text, control_id)


class T02_AdapterApi(unittest.TestCase):

    def setUp(self):
        self.mod = load_adapter()

    def test_module_identity(self):
        self.assertEqual(self.mod.ADAPTER_ID, ADAPTER_ID)
        self.assertEqual(self.mod.MECHANISM_ID, APPLY_KIND)
        self.assertEqual(self.mod.TARGET_ID, TARGET_ID)

    def test_required_callables(self):
        for name in ("execute_control", "control_result_to_report"):
            self.assertTrue(callable(getattr(self.mod, name, None)), name)

    def test_rejects_unsupported_op_and_key(self):
        for key, op, expected in (("owner", "eq", "0644"), ("mode", "ge", "0644"), ("mode", "bits-clear", "0000")):
            with self.assertRaises(ValueError):
                self.mod.validate_control_input("CTRL", key, op, expected, True)

    def test_rejects_apply_unsupported_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "passwd", 0o600)
            result = self.mod.execute_control(
                "CTRL", "mode", "eq", "0644", False, target=target, dry_run=False,
            )
            self.assertEqual(result["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
            self.assertEqual(mode_of(target), 0o600)


class T03_Eligibility(unittest.TestCase):

    def setUp(self):
        self.mod = load_adapter()

    def test_already_compliant_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "passwd", 0o644)
            result = self.mod.execute_control(
                "CTRL", "mode", "eq", "0644", True, target=target, dry_run=False,
            )
            self.assertEqual(result["outcome"], "ALREADY_COMPLIANT")
            self.assertEqual(mode_of(target), 0o644)

    def test_absent_target_aborts(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "absent")
            result = self.mod.execute_control(
                "CTRL", "mode", "eq", "0644", True, target=target, dry_run=False,
            )
            self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")

    def test_dry_run_reports_exact_target_and_does_not_mutate(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "passwd", 0o666)
            result = self.mod.execute_control(
                "CTRL", "mode", "eq", "0644", True, target=target, dry_run=True,
            )
            self.assertEqual(result["outcome"], "DRY_RUN_WOULD_APPLY")
            self.assertEqual(result["target"], target)
            self.assertEqual(result["current_mode"], "0666")
            self.assertEqual(result["planned_mode"], "0644")
            self.assertEqual(mode_of(target), 0o666)


class T04_Mutation(unittest.TestCase):

    def setUp(self):
        self.mod = load_adapter()

    def test_eq_sets_exact_mode_and_preserves_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "passwd", 0o666)
            before = os.lstat(target)
            result = self.mod.execute_control(
                "CTRL", "mode", "eq", "0644", True, target=target, dry_run=False,
            )
            after = os.lstat(target)
            self.assertEqual(result["outcome"], "APPLIED")
            self.assertEqual(mode_of(target), 0o644)
            self.assertEqual((before.st_uid, before.st_gid), (after.st_uid, after.st_gid))
            self.assertEqual(before.st_ino, after.st_ino)
            self.assertEqual(
                Path(target).read_text(encoding="utf-8"), "fixture\n"
            )

    def test_bits_clear_removes_only_masked_bits(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "shadow", 0o646)
            result = self.mod.execute_control(
                "CTRL", "mode", "bits-clear", "0077", True, target=target, dry_run=False,
            )
            self.assertEqual(result["outcome"], "APPLIED")
            self.assertEqual(mode_of(target), 0o600)

    def test_mutation_never_relaxes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "passwd", 0o600)
            result = self.mod.execute_control(
                "CTRL", "mode", "eq", "0644", True, target=target, dry_run=False,
            )
            self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
            self.assertEqual(result["reason"], "mode-relaxation-forbidden")
            self.assertEqual(mode_of(target), 0o600)

    def test_reapply_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "shadow", 0o646)
            self.mod.execute_control(
                "CTRL", "mode", "bits-clear", "0077", True, target=target, dry_run=False,
            )
            again = self.mod.execute_control(
                "CTRL", "mode", "bits-clear", "0077", True, target=target, dry_run=False,
            )
            self.assertEqual(again["outcome"], "ALREADY_COMPLIANT")
            self.assertEqual(mode_of(target), 0o600)


class T05_SafetyBlockers(unittest.TestCase):

    def setUp(self):
        self.mod = load_adapter()

    def _blocked(self, target, *, op="eq", expected="0644"):
        return self.mod.execute_control(
            "CTRL", "mode", op, expected, True, target=target, dry_run=False,
        )

    def test_directory_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "dir")
            os.mkdir(target)
            os.chmod(target, 0o777)
            result = self._blocked(target)
            self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
            self.assertEqual(mode_of(target), 0o777)

    def test_symlink_target_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = make_target(tmp, "real", 0o666)
            link = os.path.join(tmp, "link")
            os.symlink(real, link)
            result = self._blocked(link)
            self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
            self.assertEqual(mode_of(real), 0o666)

    def test_multiple_hardlinks_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "passwd", 0o666)
            os.link(target, os.path.join(tmp, "alias"))
            result = self._blocked(target)
            self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
            self.assertEqual(result["reason"], "st_nlink")
            self.assertEqual(mode_of(target), 0o666)

    def test_identity_drift_between_observation_and_syscall(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "passwd", 0o666)
            replacement = make_target(tmp, "other", 0o666)

            def swap():
                os.replace(replacement, target)

            result = self.mod.execute_control(
                "CTRL", "mode", "eq", "0644", True, target=target, dry_run=False,
                _pre_syscall_hook=swap,
            )
            self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
            self.assertEqual(result["reason"], "identity-drift")
            self.assertEqual(mode_of(target), 0o666)

    def test_privilege_check_failure_blocks_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "passwd", 0o666)
            result = self.mod.execute_control(
                "CTRL", "mode", "eq", "0644", True, target=target, dry_run=False,
                privilege_check=lambda: False,
            )
            self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
            self.assertEqual(result["reason"], "privilege")
            self.assertEqual(mode_of(target), 0o666)


class T06_Reporting(unittest.TestCase):

    def setUp(self):
        self.mod = load_adapter()

    def test_report_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "passwd", 0o666)
            result = self.mod.execute_control(
                "CTRL", "mode", "eq", "0644", True, target=target, dry_run=False,
            )
            report = self.mod.control_result_to_report(result, "T0", "T1")
            for field in ("control_id", "outcome", "started_at", "finished_at"):
                self.assertIn(field, report)
            self.assertEqual(report["outcome"], "APPLIED")
            json.dumps(report)

    def test_outcome_vocabulary_is_closed(self):
        allowed = {
            "APPLIED", "ALREADY_COMPLIANT", "DRY_RUN_WOULD_APPLY",
            "NOT_ELIGIBLE_APPLY_UNSUPPORTED", "ABORTED_PRECONDITION_CONFLICT",
            "ABORTED_PRECONDITION_OTHER", "FAILED_NOT_COMMITTED",
        }
        self.assertEqual(set(self.mod.OUTCOMES), allowed)


def yaml_apply_locators() -> dict:
    """control_id -> parameter.locator для file-mode-owner контролей с apply.supported=true."""
    found = {}
    for path in sorted(CONTROL_DIR.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if f'\nparameter:\n  kind: "{PARAMETER_KIND}"\n' not in text:
            continue
        if "\napply:\n  supported: true\n" not in text:
            continue
        cid = ("\n" + text).split('\nid: "', 1)[1].split('"', 1)[0]
        locator = text.split('\nparameter:\n', 1)[1].split('  locator: "', 1)[1].split('"', 1)[0]
        found[cid] = locator
    return found


class T07_DispatcherIntegration(unittest.TestCase):
    """Адаптер вызывается единым dispatcher без target и отдаёт поля, которые тот читает."""

    DISPATCHER_FIELDS = ("actions_attempted", "step_rc", "mutation_performed", "transaction_commit")

    def setUp(self):
        self.mod = load_adapter()

    def test_target_table_equals_yaml_locators_and_allowed_paths(self):
        locators = yaml_apply_locators()
        self.assertTrue(locators)
        self.assertEqual(dict(self.mod.TARGETS), locators)
        doc = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(set(doc["mutation"]["allowed_paths"]), set(locators.values()))

    def test_default_target_comes_from_table(self):
        cid = "FSTEC-LINUX-2022-2.3.1-GROUP-MODE"
        result = self.mod.execute_control(cid, "mode", "eq", "0644", True, dry_run=True)
        self.assertEqual(result["target"], self.mod.TARGETS[cid])
        self.assertNotIn(result["outcome"], ("APPLIED", "FAILED_NOT_COMMITTED"))

    def test_unknown_control_without_target_aborts(self):
        result = self.mod.execute_control("CTRL", "mode", "eq", "0644", True, dry_run=False)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        report = self.mod.control_result_to_report(result, "T0", "T1")
        self.assertIs(report["mutation_performed"], False)
        self.assertEqual(report["transaction_commit"], "NOT_STARTED")
        self.assertEqual(report["step_rc"], "nonzero")

    def _report(self, mode, *, dry_run, op="eq", expected="0644"):
        with tempfile.TemporaryDirectory() as tmp:
            target = make_target(tmp, "passwd", mode)
            result = self.mod.execute_control(
                "CTRL", "mode", op, expected, True, target=target, dry_run=dry_run,
            )
            return self.mod.control_result_to_report(result, "T0", "T1")

    def test_report_carries_dispatcher_fields(self):
        # (mode, dry_run, outcome, step_rc, mutation_performed, transaction_commit)
        cases = (
            (0o666, False, "APPLIED", "0", True, "COMMITTED"),
            (0o644, False, "ALREADY_COMPLIANT", "0", False, "COMMITTED"),
            (0o666, True, "DRY_RUN_WOULD_APPLY", "0", False, "NOT_STARTED"),
            (0o644, True, "ALREADY_COMPLIANT", "0", False, "NOT_STARTED"),
            (0o600, False, "ABORTED_PRECONDITION_CONFLICT", "nonzero", False, "NOT_STARTED"),
        )
        for mode, dry_run, outcome, step_rc, mutation, commit in cases:
            with self.subTest(mode=oct(mode), dry_run=dry_run):
                report = self._report(mode, dry_run=dry_run)
                for field in self.DISPATCHER_FIELDS:
                    self.assertIn(field, report)
                self.assertEqual(report["outcome"], outcome)
                self.assertEqual(report["step_rc"], step_rc)
                self.assertIs(report["mutation_performed"], mutation)
                self.assertEqual(report["transaction_commit"], commit)
                self.assertIsInstance(report["actions_attempted"], list)
                self.assertTrue(report["actions_attempted"])
                self.assertTrue(all(isinstance(a, str) for a in report["actions_attempted"]))
                json.dumps(report)


if __name__ == "__main__":
    unittest.main()
