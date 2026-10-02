#!/usr/bin/env python3
"""Regressions for the user-cron-files-mode APPLY mechanism (2.3.7, SRC-0011).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on a crontab spool directory created inside a temporary
directory owned by the current user. No system path is touched and root is not
required: the privilege check and the fchmod call are injected where a case
needs them.

Решение ведущего 29.09.2026 по образцу решения пользователя для 2.3.3, которое фиксирует этот
файл: APPLY 2.3.7 снимает биты записи группы и прочих у всей популяции CHECK
(непосредственные элементы /var/spool/cron/crontabs) при любом владельце.
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
ADAPTER = ROOT / "product/apply-adapters/product-user-cron-files-mode-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-user-cron-files-mode-check-v2.py"
CONTROL = ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.7-user-cron-files-mode.yaml"
CID = "FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE"
ARGS = ("mode", "bits-clear", "0022")

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


class _Spool(unittest.TestCase):
    def setUp(self):
        self.mod = load(ADAPTER, "slp_user_cron_apply")
        self.tmp = tempfile.mkdtemp(prefix="slp-user-cron-apply-")
        self.root = os.path.join(self.tmp, "spool", "crontabs")
        os.makedirs(self.root)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def tab(self, name, mode):
        path = os.path.join(self.root, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# x\n")
        os.chmod(path, mode)
        return path

    def run_apply(self, dry_run=False, root=None, **kw):
        kw.setdefault("privilege_check", lambda: True)
        return self.mod.execute_control(CID, *ARGS, True, dry_run=dry_run,
                                        root=self.root if root is None else root, **kw)


class T01_Identity(unittest.TestCase):
    def test_module_identity_and_control(self):
        mod = load(ADAPTER, "slp_user_cron_apply")
        check = load(CHECK_ADAPTER, "slp_user_cron_check")
        self.assertEqual(mod.ADAPTER_ID, "product-user-cron-files-mode-apply-v1")
        self.assertEqual(mod.MECHANISM_ID, "user-cron-files-mode-v1")
        self.assertEqual(mod.TARGET_ID, "linux-x86_64-supported-v1")
        self.assertEqual(mod.PARAMETER_KIND, "user-cron-files-mode")
        self.assertEqual(mod.CONTROLS, (CID,))
        self.assertEqual(mod.CANONICAL_ROOT, check.CANONICAL_LOCATOR)
        self.assertEqual(mod.EXPECTED_MASK, check.EXPECTED_MASK)
        text = CONTROL.read_text(encoding="utf-8")
        self.assertIn('id: "%s"\n' % CID, text)
        self.assertIn('  op: "bits-clear"\n  value: "0022"\n', text)
        self.assertIn("\napply:\n  supported: true\n", text)

    def test_input_validation(self):
        mod = load(ADAPTER, "slp_user_cron_apply")
        for args in (("owner", "bits-clear", "0022"), ("mode", "eq", "0022"), ("mode", "bits-clear", "0077")):
            with self.assertRaises(ValueError):
                mod.validate_control_input(CID, *args, True)


class T02_Plan(_Spool):
    def test_classification(self):
        ok = self.tab("user", 0o600)
        bad = self.tab("other", 0o622)
        real = os.path.join(self.tmp, "real")
        open(real, "w").close()
        os.chmod(real, 0o666)
        link = os.path.join(self.root, "link")
        os.symlink(real, link)
        hard = os.path.join(self.root, "hard")
        os.link(self.tab("hardsrc", 0o666), hard)
        fifo = os.path.join(self.root, "fifo")
        os.mkfifo(fifo, 0o666)
        error, objects, _rst = self.mod.plan(self.root)
        self.assertIsNone(error)
        got = {o["path"]: (o["kind"], o["reason"]) for o in objects}
        self.assertEqual(got[ok], ("ok", None))
        self.assertEqual(got[bad], ("plan", None))
        self.assertEqual(got[link], ("admin", "cron-file:symlink"))
        self.assertEqual(got[fifo], ("admin", "cron-file:invalid-type"))
        self.assertEqual(got[hard], ("admin", "cron-file:hardlink"))
        self.assertEqual(got[os.path.join(self.root, "hardsrc")], ("admin", "cron-file:hardlink"))

    def test_every_name_is_an_object_like_check(self):
        a = self.tab("a", 0o600)
        os.link(a, os.path.join(self.root, "b"))
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["current_mode"]), ("ALREADY_COMPLIANT", "checked=2;violations=0;admin=0"))

    def test_compliant_file_needs_no_decision(self):
        # Решение ведущего 29.09.2026: как у принятых 2.3.3 и 2.3.10, соответствующий файл
        # не требует действий при любом имени и числе ссылок.
        self.tab("x\x1by", 0o600)
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["outcome"], "ALREADY_COMPLIANT")

    def test_absent_root_is_already_compliant(self):
        result = self.run_apply(root=os.path.join(self.tmp, "missing", "crontabs"),
                                _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["current_mode"]), ("ALREADY_COMPLIANT", "checked=0;violations=0;admin=0"))

    def test_root_symlink_and_ancestor_symlink_refuse(self):
        link_root = os.path.join(self.tmp, "linkroot")
        os.symlink(self.root, link_root)
        self.assertEqual(self.run_apply(root=link_root)["reason"], "cron-root:symlink")
        anc = os.path.join(self.tmp, "anc")
        os.symlink(os.path.join(self.tmp, "spool"), anc)
        result = self.run_apply(root=os.path.join(anc, "crontabs"), _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "cron-root:ancestor-symlink"))

    def test_control_bytes_are_admin_with_marker(self):
        for ch in ("\x01", "\x1b", "\t", "\x7f"):
            path = self.tab("a" + ch + "b", 0o622)
            result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
            self.assertEqual(result["reason"], "cron-file:invalid-name:<invalid-name>", repr(ch))
            self.assertEqual(mode_of(path), 0o622)
            os.unlink(path)


class T03_Execute(_Spool):
    def test_clears_go_w_and_keeps_owner(self):
        a = self.tab("user", 0o622)
        b = self.tab("slp-fixture", 0o666)
        before = {p: os.lstat(p) for p in (a, b)}
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED", result)
        self.assertEqual((mode_of(a), mode_of(b)), (0o600, 0o644))
        for p in (a, b):
            st = os.lstat(p)
            self.assertEqual((st.st_uid, st.st_gid, st.st_ino), (before[p].st_uid, before[p].st_gid, before[p].st_ino))

    def test_dry_run_does_not_mutate(self):
        a = self.tab("user", 0o622)
        result = self.run_apply(dry_run=True, _fchmod=lambda *x: self.fail("fchmod in dry-run"))
        self.assertEqual((result["outcome"], result["violators"]), ("DRY_RUN_WOULD_APPLY", [a]))
        self.assertEqual(mode_of(a), 0o622)

    def test_privilege_refusal_before_mutation(self):
        a = self.tab("user", 0o622)
        result = self.run_apply(privilege_check=lambda: False, _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
        self.assertEqual(mode_of(a), 0o622)

    def test_object_failure_does_not_stop_others(self):
        a = self.tab("a", 0o622)
        b = self.tab("b", 0o622)

        def fchmod(fd, mode, path):
            if path == a:
                raise OSError(errno.EPERM, "denied")
            os.fchmod(fd, mode)

        result = self.run_apply(_fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["failed"], [{"path": a, "reason": "fchmod:EPERM"}])
        self.assertEqual((mode_of(a), mode_of(b)), (0o622, 0o600))

    def test_erofs_stops_immediately(self):
        self.tab("a", 0o622)
        b = self.tab("b", 0o622)
        calls = []

        def fchmod(fd, mode, path):
            calls.append(path)
            raise OSError(errno.EROFS, "ro")

        result = self.run_apply(_fchmod=fchmod)
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "erofs"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(mode_of(b), 0o622)

    def test_replaced_by_symlink_is_refused(self):
        a = self.tab("user", 0o622)
        outside = os.path.join(self.tmp, "outside")
        open(outside, "w").close()
        os.chmod(outside, 0o666)
        real_plan = self.mod.plan

        def plan_then_swap(*args):
            result = real_plan(*args)
            os.unlink(a)
            os.symlink(outside, a)
            return result

        with mock.patch.object(self.mod, "plan", plan_then_swap):
            result = self.run_apply()
        self.assertEqual(result["failed"], [{"path": a, "reason": "type-drift"}])
        self.assertEqual(mode_of(outside), 0o666)

    def test_mode_drift_is_refused(self):
        a = self.tab("user", 0o622)
        real_plan = self.mod.plan

        def plan_then_drift(*args):
            result = real_plan(*args)
            os.chmod(a, 0o620)
            return result

        with mock.patch.object(self.mod, "plan", plan_then_drift):
            result = self.run_apply()
        self.assertEqual(result["failed"], [{"path": a, "reason": "mode-drift"}])
        self.assertEqual(mode_of(a), 0o620)

    def test_directory_close_error_closes_file(self):
        a = self.tab("user", 0o622)
        real_open, real_close, real_plan = os.open, os.close, self.mod.plan
        dirs, armed = set(), {"on": False}

        def plan_then_arm(*args):
            result = real_plan(*args)
            armed["on"] = True
            return result

        def fake_open(path, flags, *args, **kw):
            fd = real_open(path, flags, *args, **kw)
            if armed["on"] and flags & os.O_DIRECTORY:
                dirs.add(fd)
            return fd

        def fake_close(fd):
            real_close(fd)
            if fd in dirs:
                raise OSError(errno.EIO, "injected")

        before = set(os.listdir("/proc/self/fd"))
        with mock.patch.object(self.mod, "plan", plan_then_arm), mock.patch.object(self.mod.os, "open", fake_open), \
                mock.patch.object(self.mod.os, "close", fake_close):
            result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["failed"], [{"path": a, "reason": "root-close:EIO"}])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_postcheck_error_keeps_mutation_fact(self):
        a = self.tab("user", 0o622)
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
        self.assertEqual(mode_of(a), 0o600)
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(result["failed"], [{"path": a, "reason": "postcheck:EIO"}])

    def test_repeat_and_report(self):
        self.tab("user", 0o622)
        report = self.mod.control_result_to_report(self.run_apply(), "t0", "t1")
        self.assertTrue(DISPATCHER_FIELDS <= set(report))
        self.assertEqual(report["step_rc"], "0")
        again = self.run_apply(_fchmod=lambda *x: self.fail("fchmod on repeat"))
        self.assertEqual((again["outcome"], again["transaction_commit"]), ("ALREADY_COMPLIANT", "COMMITTED"))


if __name__ == "__main__":
    unittest.main()
