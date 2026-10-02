#!/usr/bin/env python3
"""Regressions for the cron-command-paths-write-protection APPLY mechanism (2.3.3, SRC-0007).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on a fixture filesystem root created inside a temporary directory
owned by the current user; the logical root UID of the observer is the current UID.
No system path is touched and root is not required: the privilege check and the
fchmod call are injected where a case needs them.

Решение пользователя 29.09.2026, которое фиксирует этот файл: APPLY 2.3.3 снимает биты
записи группы и прочих у всей популяции CHECK при любом владельце файла.
"""

from __future__ import annotations

import errno
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "product/apply-adapters/product-cron-command-paths-write-protection-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-cron-command-paths-write-protection-check-v1.py"
CONTROL = ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.3-cron-command-paths-write-protection.yaml"
CID = "FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION"
ARGS = ("write-protection", "cron-command-paths-safe", "file-go-w")

DISPATCHER_FIELDS = {
    "control_id", "outcome", "reason", "actions_attempted", "step_rc",
    "mutation_performed", "transaction_commit", "started_at", "finished_at",
}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


class _Root(unittest.TestCase):
    def setUp(self):
        self.mod = load(ADAPTER, "slp_cron_paths_apply")
        self.tmp = tempfile.mkdtemp(prefix="slp-cron-apply-")
        self.fs = os.path.join(self.tmp, "root")
        for d in ("etc/cron.d", "opt"):
            os.makedirs(os.path.join(self.fs, d))
        with open(os.path.join(self.fs, "etc/passwd"), "w", encoding="utf-8") as fh:
            fh.write("root:x:0:0::/root:/bin/sh\n")
        self.lines = []

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def exe(self, rel, mode):
        path = os.path.join(self.fs, rel)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/true\n")
        os.chmod(path, mode)
        return path

    def job(self, command):
        self.lines.append("17 3 * * * root " + command)

    def write_cron(self):
        path = os.path.join(self.fs, "etc/cron.d/slp")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("".join(x + "\n" for x in self.lines))
        os.chmod(path, 0o644)

    def run_apply(self, dry_run=False, **kw):
        self.write_cron()
        kw.setdefault("privilege_check", lambda: True)
        return self.mod.execute_control(CID, *ARGS, True, dry_run=dry_run, fsroot=self.fs,
                                        logical_root_uid=os.getuid(), **kw)


class T01_Identity(unittest.TestCase):
    def test_module_identity_and_control(self):
        mod = load(ADAPTER, "slp_cron_paths_apply")
        self.assertEqual(mod.ADAPTER_ID, "product-cron-command-paths-write-protection-apply-v1")
        self.assertEqual(mod.MECHANISM_ID, "cron-command-paths-write-protection-v1")
        self.assertEqual(mod.TARGET_ID, "linux-x86_64-supported-v1")
        self.assertEqual(mod.PARAMETER_KIND, "cron-command-paths-write-protection")
        self.assertEqual(mod.CONTROLS, (CID,))
        text = CONTROL.read_text(encoding="utf-8")
        self.assertIn('id: "%s"\n' % CID, text)
        self.assertIn('  op: "cron-command-paths-safe"\n  value: "file-go-w"\n', text)
        self.assertIn("\napply:\n  supported: true\n", text)

    def test_discovery_is_byte_copy_of_check_observer(self):
        mod = load(ADAPTER, "slp_cron_paths_apply")
        check = load(CHECK_ADAPTER, "slp_cron_paths_check")
        self.assertTrue(check._PY.startswith(mod.DISCOVERY_SOURCE))
        self.assertTrue(check._PY[len(mod.DISCOVERY_SOURCE):].startswith("\ntry:\n    rst = os.lstat(fsroot)"))
        self.assertEqual(mod.CANONICAL_LOCATOR, check.CANONICAL_LOCATOR)

    def test_input_validation(self):
        mod = load(ADAPTER, "slp_cron_paths_apply")
        for args in (("mode", ARGS[1], ARGS[2]), (ARGS[0], "bits-clear", ARGS[2]), (ARGS[0], ARGS[1], "file-go-rwx")):
            with self.assertRaises(ValueError):
                mod.validate_control_input(CID, *args, True)


class T02_Execute(_Root):
    def test_clears_go_w_and_keeps_owner(self):
        a = self.exe("opt/a", 0o777)
        b = self.exe("opt/b", 0o4775)
        self.job("/opt/a && /opt/b")
        before = {p: os.lstat(p) for p in (a, b)}
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED", result)
        self.assertEqual(sorted(result["applied"]), ["/opt/a", "/opt/b"])
        self.assertEqual((mode_of(a), mode_of(b)), (0o755, 0o4755))
        for p in (a, b):
            st = os.lstat(p)
            self.assertEqual((st.st_uid, st.st_gid, st.st_ino), (before[p].st_uid, before[p].st_gid, before[p].st_ino))

    def test_symlink_command_fixes_final_file(self):
        real = self.exe("opt/real", 0o777)
        os.symlink(real, os.path.join(self.fs, "opt/link"))
        self.job("/opt/link")
        result = self.run_apply()
        self.assertEqual((result["outcome"], result["applied"]), ("APPLIED", ["/opt/link"]))
        self.assertEqual(mode_of(real), 0o755)

    def test_compliant_is_already_compliant(self):
        self.exe("opt/a", 0o755)
        self.job("/opt/a")
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["current_mode"]), ("ALREADY_COMPLIANT", "targets=1;violations=0;admin=0"))

    def test_dry_run_does_not_mutate(self):
        a = self.exe("opt/a", 0o777)
        self.job("/opt/a")
        result = self.run_apply(dry_run=True, _fchmod=lambda *x: self.fail("fchmod in dry-run"))
        self.assertEqual((result["outcome"], result["violators"]), ("DRY_RUN_WOULD_APPLY", ["/opt/a"]))
        self.assertEqual(mode_of(a), 0o777)

    def test_privilege_refusal_before_mutation(self):
        a = self.exe("opt/a", 0o777)
        self.job("/opt/a")
        result = self.run_apply(privilege_check=lambda: False, _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
        self.assertEqual(mode_of(a), 0o777)

    def test_observer_refusal_is_check_reason(self):
        a = self.exe("opt/a", 0o777)
        self.job("sudo /opt/a")
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["reason"]),
                         ("ABORTED_PRECONDITION_OTHER", "check:command:unsupported-wrapper"))
        self.assertEqual(mode_of(a), 0o777)

    def test_hardlinked_command_is_refused_by_observer(self):
        a = self.exe("opt/a", 0o777)
        os.link(a, os.path.join(self.fs, "opt/a2"))
        self.job("/opt/a")
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["reason"], "check:target:hardlink")
        self.assertEqual(mode_of(a), 0o777)

    def test_control_bytes_are_admin_with_marker(self):
        a = self.exe("opt/a\x1bb", 0o777)
        self.job("/opt/a\x1bb")
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertEqual(result["reason"], "target:invalid-name:<invalid-name>")
        self.assertEqual(result["skipped"], [{"path": "<invalid-name>", "reason": "target:invalid-name"}])
        self.assertEqual(mode_of(a), 0o777)

    def test_object_failure_does_not_stop_others(self):
        a = self.exe("opt/a", 0o777)
        b = self.exe("opt/b", 0o777)
        self.job("/opt/a && /opt/b")

        def fchmod(fd, mode, path):
            if path == "/opt/a":
                raise OSError(errno.EPERM, "denied")
            os.fchmod(fd, mode)

        result = self.run_apply(_fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["failed"], [{"path": "/opt/a", "reason": "fchmod:EPERM"}])
        self.assertEqual((mode_of(a), mode_of(b)), (0o777, 0o755))

    def test_erofs_stops_immediately(self):
        self.exe("opt/a", 0o777)
        b = self.exe("opt/b", 0o777)
        self.job("/opt/a && /opt/b")
        calls = []

        def fchmod(fd, mode, path):
            calls.append(path)
            raise OSError(errno.EROFS, "ro")

        result = self.run_apply(_fchmod=fchmod)
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "erofs"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(mode_of(b), 0o777)

    def test_mode_drift_is_refused(self):
        a = self.exe("opt/a", 0o777)
        self.job("/opt/a")
        real_plan = self.mod.plan

        def plan_then_drift(*args):
            error, objects = real_plan(*args)
            os.chmod(a, 0o775)
            return error, objects

        with mock.patch.object(self.mod, "plan", plan_then_drift):
            result = self.run_apply()
        self.assertEqual(result["failed"], [{"path": "/opt/a", "reason": "mode-drift"}])
        self.assertEqual(mode_of(a), 0o775)

    def test_postcheck_error_keeps_mutation_fact(self):
        a = self.exe("opt/a", 0o777)
        self.job("/opt/a")
        real_fstat = os.fstat
        done = {"flag": False}

        def fchmod(fd, mode, path):
            os.fchmod(fd, mode)
            done["flag"] = True

        def fstat(fd):
            if done["flag"]:
                raise OSError(errno.EIO, "injected")
            return real_fstat(fd)

        with mock.patch.object(self.mod.os, "fstat", fstat):
            result = self.run_apply(_fchmod=fchmod)
        self.assertEqual(mode_of(a), 0o755)
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(result["failed"], [{"path": "/opt/a", "reason": "postcheck:EIO"}])

    def test_repeat_and_report(self):
        self.exe("opt/a", 0o777)
        self.job("/opt/a")
        report = self.mod.control_result_to_report(self.run_apply(), "t0", "t1")
        self.assertTrue(DISPATCHER_FIELDS <= set(report))
        self.assertEqual(report["step_rc"], "0")
        again = self.run_apply(_fchmod=lambda *x: self.fail("fchmod on repeat"))
        self.assertEqual((again["outcome"], again["transaction_commit"]), ("ALREADY_COMPLIANT", "COMMITTED"))


if __name__ == "__main__":
    unittest.main()
