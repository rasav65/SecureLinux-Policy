#!/usr/bin/env python3
"""Regressions for the home-sensitive-files-mode APPLY mechanism (2.3.10, SRC-0014).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on a passwd file, home directories and files created inside a
temporary directory owned by the current user. No system path is touched and
root is not required: the privilege check and the fchmod call are injected where
a case needs them. UID_FLOOR is lowered to 0 for fixture cases so that the
current UID is inside the population on any runner.

Решение пользователя 29.09.2026, которое фиксирует этот файл: APPLY 2.3.10 устроен как
APPLY 2.3.11 — популяция APPLY — файлы с именами из набора CHECK в домашних каталогах
пользователей с UID ≥ 1000 из /etc/passwd; прочие случаи — решение администратора; CHECK
(непосредственные элементы каталогов /home) не меняется.
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
ADAPTER = ROOT / "product/apply-adapters/product-home-sensitive-files-mode-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-home-sensitive-files-mode-check-v2.py"
CONTROL = ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.10-home-sensitive-files-mode.yaml"
CID = "FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE"

DISPATCHER_FIELDS = {
    "control_id", "outcome", "reason", "actions_attempted", "step_rc",
    "mutation_performed", "transaction_commit", "started_at", "finished_at",
}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_adapter():
    return load(ADAPTER, "slp_home_files_apply")


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


class _Tree(unittest.TestCase):
    def setUp(self):
        self.mod = load_adapter()
        self.tmp = tempfile.mkdtemp(prefix="slp-home-files-apply-")
        self.uid = os.getuid()
        self.rows = []
        patcher = mock.patch.object(self.mod, "UID_FLOOR", 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        for dirpath, dirnames, _files in os.walk(self.tmp):
            for name in dirnames:
                path = os.path.join(dirpath, name)
                if not os.path.islink(path):
                    os.chmod(path, 0o700)
        shutil.rmtree(self.tmp)

    def home(self, name, uid=None):
        path = os.path.join(self.tmp, name)
        os.mkdir(path)
        os.chmod(path, 0o755)
        self.row(name, path, uid)
        return path

    def row(self, name, home, uid=None):
        self.rows.append("%s:x:%d:%d::%s:/bin/sh" % (name, self.uid if uid is None else uid, self.uid, home))

    def file(self, home, name, mode):
        path = os.path.join(home, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("x\n")
        os.chmod(path, mode)
        return path

    def passwd(self):
        path = os.path.join(self.tmp, "passwd")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("".join(r + "\n" for r in self.rows))
        return path

    def run_apply(self, dry_run=False, **kw):
        kw.setdefault("privilege_check", lambda: True)
        return self.mod.execute_control(CID, "mode", "bits-clear", "0077", True, dry_run=dry_run,
                                        passwd_path=self.passwd(), **kw)


class T01_Identity(unittest.TestCase):
    def test_module_identity_and_control(self):
        mod = load_adapter()
        self.assertEqual(mod.ADAPTER_ID, "product-home-sensitive-files-mode-apply-v1")
        self.assertEqual(mod.MECHANISM_ID, "home-sensitive-files-mode-v1")
        self.assertEqual(mod.TARGET_ID, "linux-x86_64-supported-v1")
        self.assertEqual(mod.PARAMETER_KIND, "home-sensitive-files-mode")
        self.assertEqual(mod.UID_FLOOR, 1000)
        self.assertEqual(mod.CONTROLS, (CID,))
        text = CONTROL.read_text(encoding="utf-8")
        self.assertIn('id: "%s"\n' % CID, text)
        self.assertIn('  kind: "home-sensitive-files-mode"\n', text)
        self.assertIn('  op: "bits-clear"\n  value: "0077"\n', text)
        self.assertIn("\napply:\n  supported: true\n", text)

    def test_name_set_matches_check(self):
        mod = load_adapter()
        check = load(CHECK_ADAPTER, "slp_home_files_check")
        self.assertEqual(mod.MANDATORY_SOURCE_NAMES, check.MANDATORY_SOURCE_NAMES)
        self.assertEqual(mod.COMMON_SHELL_BASENAMES, check.COMMON_SHELL_BASENAMES)
        self.assertEqual(len(mod.NAMES), 23)
        self.assertEqual(mod.EXPECTED_MASK, check.EXPECTED_MASK)

    def test_input_validation(self):
        mod = load_adapter()
        for args in (("mode", "bits-clear", "0022"), ("owner", "bits-clear", "0077"), ("mode", "eq", "0077")):
            with self.assertRaises(ValueError):
                mod.validate_control_input(CID, *args, True)


class T02_Plan(_Tree):
    def test_classification(self):
        h = self.home("u")
        ok = self.file(h, ".bash_history", 0o600)
        bad = self.file(h, ".bashrc", 0o644)
        self.file(h, "notes.txt", 0o644)
        real = self.file(self.tmp, "real", 0o644)
        link = os.path.join(h, ".zshrc")
        os.symlink(real, link)
        hard = os.path.join(h, ".kshrc")
        os.link(self.file(self.tmp, "hardsrc", 0o644), hard)
        fifo = os.path.join(h, ".history")
        os.mkfifo(fifo, 0o644)
        error, objects = self.mod.plan(self.passwd())
        self.assertIsNone(error)
        got = {item["path"]: (item["kind"], item["reason"]) for item in objects}
        self.assertEqual(got, {
            ok: ("ok", None),
            bad: ("plan", None),
            link: ("admin", "file:symlink"),
            hard: ("admin", "file:hardlink"),
            fifo: ("admin", "file:not-regular"),
        })

    def test_owner_mismatch_is_admin(self):
        h = self.home("u", uid=self.uid + 1)
        bad = self.file(h, ".bashrc", 0o644)
        compliant = self.file(h, ".profile", 0o600)
        _error, objects = self.mod.plan(self.passwd())
        got = {item["path"]: (item["kind"], item["reason"]) for item in objects}
        self.assertEqual(got, {bad: ("admin", "file:owner-mismatch"), compliant: ("ok", None)})

    def test_home_errors(self):
        target = self.home("t")
        link = os.path.join(self.tmp, "link")
        os.symlink(target, link)
        self.row("link", link)
        afile = self.file(self.tmp, "afile", 0o644)
        self.row("afile", afile)
        self.row("absent", os.path.join(self.tmp, "absent"))
        self.row("relative", "home/rel")
        self.row("ctl", self.tmp + "/a\x7fb")
        _error, objects = self.mod.plan(self.passwd())
        got = {item["path"]: (item["kind"], item["reason"]) for item in objects}
        self.assertEqual(got, {
            link: ("admin", "home:symlink"),
            afile: ("admin", "home:not-directory"),
            "home/rel": ("admin", "home:not-absolute"),
            "<invalid-name>": ("admin", "home:invalid-name"),
        })

    def test_control_bytes_never_reach_report(self):
        for ch in ("\x01", "\x0b", "\x1b", "\t", "\x7f"):
            self.rows = []
            self.row("ctl", self.tmp + "/a" + ch + "b")
            result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
            self.assertEqual(result["reason"], "home:invalid-name:<invalid-name>", repr(ch))
            self.assertEqual(result["skipped"], [{"path": "<invalid-name>", "reason": "home:invalid-name"}])

    def test_shared_home_is_one_object(self):
        h = self.home("a")
        bad = self.file(h, ".bashrc", 0o644)
        self.row("b", h)
        _error, objects = self.mod.plan(self.passwd())
        self.assertEqual([(o["path"], o["kind"]) for o in objects], [(bad, "plan")])

    def test_shared_home_with_conflict_is_admin(self):
        h = self.home("a")
        self.file(h, ".bashrc", 0o644)
        self.file(h, ".profile", 0o600)
        self.row("b", h, uid=self.uid + 1)
        _error, objects = self.mod.plan(self.passwd())
        self.assertEqual(sorted((o["kind"], o["reason"]) for o in objects),
                         [("admin", "home:shared-conflict"), ("ok", None)])

    def test_floor_excludes_system_accounts(self):
        self.mod.UID_FLOOR = self.uid + 1
        h = self.home("low")
        self.file(h, ".bashrc", 0o644)
        _error, objects = self.mod.plan(self.passwd())
        self.assertEqual(objects, [])

    def test_passwd_errors(self):
        result = self.mod.execute_control(CID, "mode", "bits-clear", "0077", True, dry_run=False,
                                          passwd_path=os.path.join(self.tmp, "missing"),
                                          privilege_check=lambda: True)
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "passwd:open:ENOENT"))
        self.assertFalse(result["mutation_performed"])


class T03_Execute(_Tree):
    def test_clears_group_and_other_bits_only(self):
        h = self.home("u")
        a = self.file(h, ".bashrc", 0o644)
        b = self.file(h, ".profile", 0o4754)
        before = {p: os.lstat(p) for p in (a, b)}
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(sorted(result["applied"]), sorted([a, b]))
        self.assertEqual((mode_of(a), mode_of(b)), (0o600, 0o4700))
        for path in (a, b):
            st = os.lstat(path)
            self.assertEqual((st.st_uid, st.st_gid, st.st_ino), (before[path].st_uid, before[path].st_gid, before[path].st_ino))

    def test_dry_run_does_not_mutate(self):
        h = self.home("u")
        a = self.file(h, ".bashrc", 0o644)
        result = self.run_apply(dry_run=True, _fchmod=lambda *x: self.fail("fchmod in dry-run"))
        self.assertEqual(result["outcome"], "DRY_RUN_WOULD_APPLY")
        self.assertEqual(result["violators"], [a])
        self.assertEqual(mode_of(a), 0o644)

    def test_privilege_refusal_before_mutation(self):
        h = self.home("u")
        a = self.file(h, ".bashrc", 0o644)
        result = self.run_apply(privilege_check=lambda: False, _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
        self.assertEqual(mode_of(a), 0o644)

    def test_admin_only_is_block_with_decision(self):
        h = self.home("u", uid=self.uid + 1)
        a = self.file(h, ".bashrc", 0o644)
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertEqual(result["reason"], "file:owner-mismatch:" + a)
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
        self.assertEqual(mode_of(a), 0o644)

    def test_mixed_is_partial(self):
        h = self.home("u")
        a = self.file(h, ".bashrc", 0o644)
        hard = os.path.join(h, ".profile")
        os.link(self.file(self.tmp, "src", 0o644), hard)
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["applied"], [a])
        self.assertEqual(result["skipped"], [{"path": hard, "reason": "file:hardlink"}])
        self.assertEqual((mode_of(a), mode_of(hard)), (0o600, 0o644))

    def test_object_failure_does_not_stop_others(self):
        h = self.home("u")
        a = self.file(h, ".bashrc", 0o644)
        b = self.file(h, ".profile", 0o644)

        def fchmod(fd, mode, path):
            if path == a:
                raise OSError(errno.EPERM, "denied")
            os.fchmod(fd, mode)

        result = self.run_apply(_fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["failed"], [{"path": a, "reason": "fchmod:EPERM"}])
        self.assertEqual((mode_of(a), mode_of(b)), (0o644, 0o600))

    def test_erofs_stops_immediately(self):
        h = self.home("u")
        self.file(h, ".bashrc", 0o644)
        b = self.file(h, ".profile", 0o644)
        calls = []

        def fchmod(fd, mode, path):
            calls.append(path)
            raise OSError(errno.EROFS, "ro")

        result = self.run_apply(_fchmod=fchmod)
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "erofs"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(mode_of(b), 0o644)

    def test_drift_is_refused(self):
        h = self.home("u")
        a = self.file(h, ".bashrc", 0o644)
        real_plan = self.mod.plan

        def plan_then_drift(path):
            error, objects = real_plan(path)
            os.chmod(a, 0o640)
            return error, objects

        with mock.patch.object(self.mod, "plan", plan_then_drift):
            result = self.run_apply()
        self.assertEqual(result["outcome"], "FAILED_NOT_COMMITTED")
        self.assertEqual(result["failed"], [{"path": a, "reason": "mode-drift"}])
        self.assertEqual(mode_of(a), 0o640)

    def test_replaced_by_symlink_is_refused(self):
        h = self.home("u")
        a = self.file(h, ".bashrc", 0o644)
        outside = self.file(self.tmp, "outside", 0o644)
        real_plan = self.mod.plan

        def plan_then_swap(path):
            error, objects = real_plan(path)
            os.unlink(a)
            os.symlink(outside, a)
            return error, objects

        with mock.patch.object(self.mod, "plan", plan_then_swap):
            result = self.run_apply()
        self.assertEqual(result["failed"], [{"path": a, "reason": "type-drift"}])
        self.assertEqual(mode_of(outside), 0o644)

    def test_postcheck_error_keeps_mutation_fact(self):
        h = self.home("u")
        a = self.file(h, ".bashrc", 0o644)
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
        self.assertEqual(result["outcome"], "FAILED_NOT_COMMITTED")
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(result["transaction_commit"], "NOT_COMMITTED")
        self.assertEqual(result["failed"], [{"path": a, "reason": "postcheck:EIO"}])

    def test_directory_close_error_closes_file_and_is_not_fchmod(self):
        h = self.home("u")
        a = self.file(h, ".bashrc", 0o644)
        real_open, real_close, real_plan = os.open, os.close, self.mod.plan
        dirs, armed = set(), {"on": False}

        def plan_then_arm(path):
            result = real_plan(path)
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
        self.assertEqual(result["failed"], [{"path": a, "reason": "home-close:EIO"}])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(mode_of(a), 0o644)
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_repeat_is_already_compliant(self):
        h = self.home("u")
        self.file(h, ".bashrc", 0o644)
        self.assertEqual(self.run_apply()["outcome"], "APPLIED")
        again = self.run_apply(_fchmod=lambda *x: self.fail("fchmod on repeat"))
        self.assertEqual(again["outcome"], "ALREADY_COMPLIANT")
        self.assertEqual(again["transaction_commit"], "COMMITTED")

    def test_report_has_dispatcher_fields(self):
        h = self.home("u")
        self.file(h, ".bashrc", 0o644)
        report = self.mod.control_result_to_report(self.run_apply(), "t0", "t1")
        self.assertTrue(DISPATCHER_FIELDS <= set(report))
        self.assertEqual(report["step_rc"], "0")
        self.assertIn("current_mode", report)


if __name__ == "__main__":
    unittest.main()
