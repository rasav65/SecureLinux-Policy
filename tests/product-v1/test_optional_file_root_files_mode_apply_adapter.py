#!/usr/bin/env python3
"""Failing-first regressions for the optional-file-root-files-mode APPLY mechanism (G6-cron).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on trees created inside a temporary directory owned by the
current user. No system path is touched and root is not required: the
privilege check and the fchmod call are injected where a case needs them.

The adapter under test does not exist yet: this file defines the contract it
must satisfy. Until it exists every class below fails on import.
"""

from __future__ import annotations

import errno
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

ADAPTER = ROOT / "product/apply-adapters/product-optional-file-root-files-mode-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-optional-file-root-files-mode-check-v1.py"
CONTROL_DIR = ROOT / "controls/fstec-core/linux-2022"

APPLY_KIND = "optional-file-root-files-mode-v1"
PARAMETER_KIND = "optional-file-root-files-mode"
ADAPTER_ID = "product-optional-file-root-files-mode-apply-v1"
TARGET_ID = "linux-x86_64-supported-v1"
MASK = "0033"

CONTROLS = {
    "FSTEC-LINUX-2022-2.3.6-CRONTAB": "/etc/crontab",
    "FSTEC-LINUX-2022-2.3.6-CRON-D": "/etc/cron.d",
    "FSTEC-LINUX-2022-2.3.6-CRON-HOURLY": "/etc/cron.hourly",
    "FSTEC-LINUX-2022-2.3.6-CRON-DAILY": "/etc/cron.daily",
    "FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY": "/etc/cron.weekly",
    "FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY": "/etc/cron.monthly",
}
CID = "FSTEC-LINUX-2022-2.3.6-CRON-D"

# Поля записи, которые читает встроенный dispatcher (как у file-mode-owner).
DISPATCHER_FIELDS = {
    "control_id", "outcome", "reason", "actions_attempted", "step_rc",
    "mutation_performed", "transaction_commit", "started_at", "finished_at",
}


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_adapter():
    return load_module(ADAPTER, "slp_ofrfm_apply")


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def make_file(path, mode, content="fixture\n"):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, mode)
    return path


def make_dir(path, mode):
    os.mkdir(path)
    os.chmod(path, mode)
    return path


def check_observation(root):
    """(status, value) из встроенного CHECK-адаптера, исполненного bash на root."""
    check = load_module(CHECK_ADAPTER, "slp_ofrfm_check")
    src = check.shell_function("CTRL", root, "mode", "bits-clear", MASK)
    proc = subprocess.run(
        ["/bin/bash", "-c", src + "\nslp_check_CTRL\n"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60,
    )
    fields = proc.stdout.rstrip("\n").split("\t")
    if proc.returncode != 0 or len(fields) != 5:
        raise AssertionError(f"CHECK failed: rc={proc.returncode} out={proc.stdout!r} err={proc.stderr!r}")
    return fields[2], fields[3]


def run(adapter, root, *, dry_run=False, privilege=True, fchmod=None):
    kwargs = {"target": root, "dry_run": dry_run, "privilege_check": lambda: privilege}
    if fchmod is not None:
        kwargs["_fchmod"] = fchmod
    return adapter.execute_control(CID, "mode", "bits-clear", MASK, True, **kwargs)


class _Tree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="slp-ofrfm-apply-")
        self.adapter = load_adapter()

    def tearDown(self):
        for dirpath, dirnames, filenames in os.walk(self.tmp):
            for name in dirnames:
                p = os.path.join(dirpath, name)
                if not os.path.islink(p):
                    os.chmod(p, 0o700)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cron_dir(self, children):
        """Каталог 0755 (нарушитель по 0033) с детьми {имя: режим}."""
        root = make_dir(os.path.join(self.tmp, "cron.d"), 0o755)
        for name, mode in children.items():
            make_file(os.path.join(root, name), mode, content=name + "\n")
        return root


class T01_Identity(unittest.TestCase):
    def test_module_identity_and_api(self):
        mod = load_adapter()
        self.assertEqual(mod.ADAPTER_ID, ADAPTER_ID)
        self.assertEqual(mod.MECHANISM_ID, APPLY_KIND)
        self.assertEqual(mod.PARAMETER_KIND, PARAMETER_KIND)
        self.assertEqual(mod.TARGET_ID, TARGET_ID)
        self.assertIn("APPLIED_PARTIAL", mod.OUTCOMES)
        for fn in ("execute_control", "control_result_to_report", "observe"):
            self.assertTrue(callable(getattr(mod, fn, None)), fn)

    def test_target_table_equals_yaml_locators(self):
        mod = load_adapter()
        self.assertEqual(mod.TARGETS, CONTROLS)
        for cid, locator in CONTROLS.items():
            name = "fstec-linux-2022-" + cid.split("FSTEC-LINUX-2022-", 1)[1].lower() + ".yaml"
            text = (CONTROL_DIR / name).read_text(encoding="utf-8")
            self.assertIn(f'kind: "{PARAMETER_KIND}"', text)
            self.assertEqual(re.search(r'\nparameter:\n  kind: "[^"]*"\n  locator: "([^"]*)"', text).group(1), locator)


class T02_EnumeratorParity(_Tree):
    """APPLY-перечислитель и CHECK-адаптер дают одно и то же (status, value)."""

    def assert_parity(self, root):
        self.assertEqual(tuple(self.adapter.observe(root)), check_observation(root))

    def test_root_file(self):
        self.assert_parity(make_file(os.path.join(self.tmp, "crontab"), 0o644))
        self.assert_parity(make_file(os.path.join(self.tmp, "crontab2"), 0o666))

    def test_directory_with_children(self):
        self.assert_parity(self.cron_dir({"a": 0o644, "b": 0o666, "c": 0o755}))

    def test_absent_root(self):
        self.assert_parity(os.path.join(self.tmp, "absent"))

    def test_symlink_child(self):
        root = self.cron_dir({"a": 0o644})
        os.symlink(os.path.join(root, "a"), os.path.join(root, "link"))
        self.assert_parity(root)

    def test_subdirectory_child(self):
        root = self.cron_dir({"a": 0o644})
        make_dir(os.path.join(root, "sub"), 0o755)
        self.assert_parity(root)


class T03_Plan(_Tree):
    """План строится до мутаций; запреты останавливают контроль без мутаций."""

    def test_symlink_among_children_conflict_without_mutation(self):
        root = self.cron_dir({"a": 0o666})
        os.symlink(os.path.join(root, "a"), os.path.join(root, "link"))
        result = run(self.adapter, root)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(root), 0o755)
        self.assertEqual(mode_of(os.path.join(root, "a")), 0o666)

    def test_wrong_type_among_children_conflict_without_mutation(self):
        root = self.cron_dir({"a": 0o666})
        make_dir(os.path.join(root, "sub"), 0o777)
        result = run(self.adapter, root)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(os.path.join(root, "a")), 0o666)
        self.assertEqual(mode_of(os.path.join(root, "sub")), 0o777)

    def test_hardlinked_violator_skipped_with_record(self):
        root = self.cron_dir({"a": 0o666, "b": 0o666})
        os.link(os.path.join(root, "b"), os.path.join(self.tmp, "b-outside"))
        result = run(self.adapter, root)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": os.path.join(root, "b"), "reason": "st_nlink"}])
        self.assertEqual(mode_of(os.path.join(root, "b")), 0o666)
        self.assertEqual(mode_of(os.path.join(root, "a")), 0o644)

    def test_only_hardlinked_violators_conflict_without_mutation(self):
        root = make_dir(os.path.join(self.tmp, "cron.d"), 0o700)
        make_file(os.path.join(root, "a"), 0o644)
        make_file(os.path.join(root, "b"), 0o666)
        os.link(os.path.join(root, "b"), os.path.join(self.tmp, "b-outside"))
        result = run(self.adapter, root)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(result["skipped"], [{"path": os.path.join(root, "b"), "reason": "st_nlink"}])
        self.assertEqual(mode_of(os.path.join(root, "b")), 0o666)

    def test_dry_run_lists_violators_without_mutation(self):
        root = self.cron_dir({"a": 0o644, "b": 0o666, "c": 0o700})
        result = run(self.adapter, root, dry_run=True, privilege=False)
        self.assertEqual(result["outcome"], "DRY_RUN_WOULD_APPLY")
        self.assertEqual(result["violators"], [root, os.path.join(root, "b")])
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(root), 0o755)
        self.assertEqual(mode_of(os.path.join(root, "b")), 0o666)

    def test_privilege_refusal_stops_before_mutation(self):
        root = self.cron_dir({"a": 0o666})
        result = run(self.adapter, root, privilege=False)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(result["reason"], "privilege")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(os.path.join(root, "a")), 0o666)


class T04_Execute(_Tree):
    def test_clears_only_0033_and_preserves_owner_and_content(self):
        root = self.cron_dir({"a": 0o777, "b": 0o4755, "c": 0o600})
        before = {n: os.lstat(os.path.join(root, n)) for n in ("a", "b", "c")}
        result = run(self.adapter, root)
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertEqual(mode_of(root), 0o744)
        self.assertEqual(mode_of(os.path.join(root, "a")), 0o744)
        self.assertEqual(mode_of(os.path.join(root, "b")), 0o4744)
        self.assertEqual(mode_of(os.path.join(root, "c")), 0o600)
        for name, st in before.items():
            path = os.path.join(root, name)
            now = os.lstat(path)
            self.assertEqual((now.st_uid, now.st_gid, now.st_ino), (st.st_uid, st.st_gid, st.st_ino))
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), name + "\n")

    def test_object_failure_does_not_stop_others(self):
        root = self.cron_dir({"a": 0o666, "b": 0o666, "c": 0o666})
        bad = os.path.join(root, "b")

        def fchmod(fd, mode, path):
            if path == bad:
                raise OSError(errno.EIO, "injected")
            os.fchmod(fd, mode)

        result = run(self.adapter, root, fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertIs(result["mutation_performed"], True)
        self.assertEqual([f["path"] for f in result["failed"]], [bad])
        self.assertEqual(mode_of(bad), 0o666)
        self.assertEqual(mode_of(os.path.join(root, "a")), 0o644)
        self.assertEqual(mode_of(os.path.join(root, "c")), 0o644)
        self.assertEqual(mode_of(root), 0o744)
        report = self.adapter.control_result_to_report(result, "t0", "t1")
        self.assertTrue(DISPATCHER_FIELDS <= set(report), sorted(DISPATCHER_FIELDS - set(report)))
        self.assertEqual(report["step_rc"], "nonzero")
        self.assertIs(report["mutation_performed"], True)

    def test_erofs_stops_immediately(self):
        root = self.cron_dir({"a": 0o666, "b": 0o666})
        calls = []

        def fchmod(fd, mode, path):
            calls.append(path)
            raise OSError(errno.EROFS, "injected")

        result = run(self.adapter, root, fchmod=fchmod)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["reason"], "erofs")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(self.adapter.control_result_to_report(result, "t0", "t1")["step_rc"], "nonzero")
        self.assertEqual(mode_of(os.path.join(root, "a")), 0o666)
        self.assertEqual(mode_of(os.path.join(root, "b")), 0o666)


class T05_Repeat(_Tree):
    def test_reapply_is_already_compliant(self):
        root = self.cron_dir({"a": 0o666, "b": 0o755})
        self.assertEqual(run(self.adapter, root)["outcome"], "APPLIED")
        second = run(self.adapter, root)
        self.assertEqual(second["outcome"], "ALREADY_COMPLIANT")
        self.assertIs(second["mutation_performed"], False)

    def test_absent_root_is_already_compliant(self):
        result = run(self.adapter, os.path.join(self.tmp, "absent"))
        self.assertEqual(result["outcome"], "ALREADY_COMPLIANT")
        self.assertIs(result["mutation_performed"], False)


if __name__ == "__main__":
    unittest.main()
