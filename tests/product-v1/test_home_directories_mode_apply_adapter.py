#!/usr/bin/env python3
"""Regressions for the home-directories-mode APPLY mechanism (2.3.11, SRC-0015).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on a passwd file and directories created inside a temporary
directory owned by the current user. No system path is touched and root is not
required: the privilege check and the fchmod call are injected where a case
needs them. UID_FLOOR is lowered to 0 for fixture cases so that the current
UID is inside the population on any runner.

Решение пользователя 29.09.2026, которое фиксирует этот файл: популяция APPLY —
домашние каталоги пользователей с UID ≥ 1000 из /etc/passwd; прочие случаи —
решение администратора; CHECK (непосредственные элементы /home) не меняется.
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
ADAPTER = ROOT / "product/apply-adapters/product-home-directories-mode-apply-v1.py"
CONTROL = ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.11-home-directories-mode.yaml"
CID = "FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE"

DISPATCHER_FIELDS = {
    "control_id", "outcome", "reason", "actions_attempted", "step_rc",
    "mutation_performed", "transaction_commit", "started_at", "finished_at",
}


def load_adapter():
    spec = importlib.util.spec_from_file_location("slp_home_dirs_apply", ADAPTER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


class _Tree(unittest.TestCase):
    def setUp(self):
        self.mod = load_adapter()
        self.tmp = tempfile.mkdtemp(prefix="slp-home-apply-")
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

    def home(self, name, mode, uid=None):
        path = os.path.join(self.tmp, name)
        os.mkdir(path)
        os.chmod(path, mode)
        self.rows.append("%s:x:%d:%d::%s:/bin/sh" % (name, self.uid if uid is None else uid, self.uid, path))
        return path

    def row(self, name, home, uid=None):
        self.rows.append("%s:x:%d:%d::%s:/bin/sh" % (name, self.uid if uid is None else uid, self.uid, home))

    def passwd(self):
        path = os.path.join(self.tmp, "passwd")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("".join(r + "\n" for r in self.rows))
        return path

    def run_apply(self, dry_run=False, **kw):
        kw.setdefault("privilege_check", lambda: True)
        return self.mod.execute_control(CID, "mode", "eq", "0700", True, dry_run=dry_run,
                                        passwd_path=self.passwd(), **kw)


class T01_Identity(unittest.TestCase):
    def test_module_identity_and_control(self):
        mod = load_adapter()
        self.assertEqual(mod.ADAPTER_ID, "product-home-directories-mode-apply-v1")
        self.assertEqual(mod.MECHANISM_ID, "home-directories-mode-v1")
        self.assertEqual(mod.TARGET_ID, "linux-x86_64-supported-v1")
        self.assertEqual(mod.PARAMETER_KIND, "home-directories-mode")
        self.assertEqual(mod.UID_FLOOR, 1000)
        self.assertEqual(mod.CONTROLS, (CID,))
        text = CONTROL.read_text(encoding="utf-8")
        self.assertIn('id: "%s"\n' % CID, text)
        self.assertIn('  kind: "home-directories-mode"\n', text)
        self.assertIn('  op: "eq"\n  value: "0700"\n', text)
        self.assertIn("\napply:\n  supported: true\n", text)

    def test_input_validation(self):
        mod = load_adapter()
        for args in (("mode", "eq", "0750"), ("owner", "eq", "0700"), ("mode", "bits-clear", "0700")):
            with self.assertRaises(ValueError):
                mod.validate_control_input(CID, *args, True)


class T02_Passwd(unittest.TestCase):
    def test_floor_and_fields(self):
        mod = load_adapter()
        raw = (b"root:x:0:0::/root:/bin/bash\nsys:x:999:999::/var/sys:/bin/false\n"
               b"user:x:1000:1000::/home/user:/bin/bash\nnobody:x:65534:65534::/nonexistent:/bin/false\n")
        self.assertEqual(mod.parse_passwd(raw),
                         [("user", 1000, "/home/user"), ("nobody", 65534, "/nonexistent")])

    def test_invalid_records_refuse(self):
        mod = load_adapter()
        for raw in (b"user:x:1000:1000::/home/user\n", b"user:x:abc:1000::/home/u:/bin/sh\n",
                    b"u:x:1000:1000::/h:/bin/sh\r\n", b"u:x:1000:1000::/h\x00:/bin/sh\n",
                    b"u:x:1000:INVALID::/h:/bin/sh\n", b"u:x:1000::::/h:/bin/sh\n",
                    "u:x:\u0661\u0660\u0660\u0660:1000::/h:/bin/sh\n".encode(),
                    b"u:x:01000:1000::/h:/bin/sh\n", b"u:x:4294967295:1000::/h:/bin/sh\n",
                    b"u:x:1000:-1::/h:/bin/sh\n", b"u:x: 1000:1000::/h:/bin/sh\n"):
            with self.assertRaises(ValueError):
                mod.parse_passwd(raw)


class T03_Plan(_Tree):
    def test_classification(self):
        ok = self.home("ok", 0o700)
        bad = self.home("bad", 0o755)
        nobits = self.home("nobits", 0o500)
        other = self.home("other", 0o755, uid=self.uid + 1)
        target = self.home("target", 0o755)
        link = os.path.join(self.tmp, "link")
        os.symlink(target, link)
        self.row("link", link)
        afile = os.path.join(self.tmp, "afile")
        open(afile, "w").close()
        self.row("afile", afile)
        self.row("absent", os.path.join(self.tmp, "absent"))
        self.row("relative", "home/rel")
        error, objects = self.mod.plan(self.passwd())
        self.assertIsNone(error)
        got = {item["path"]: (item["kind"], item["reason"]) for item in objects}
        self.assertEqual(got, {
            ok: ("ok", None),
            bad: ("plan", None),
            nobits: ("admin", "home:owner-bits-missing"),
            other: ("admin", "home:owner-mismatch"),
            target: ("plan", None),
            link: ("admin", "home:symlink"),
            afile: ("admin", "home:not-directory"),
            "home/rel": ("admin", "home:not-absolute"),
        })

    def test_shared_directory_is_one_object(self):
        shared = self.home("a", 0o750)
        self.row("b", shared)
        _error, objects = self.mod.plan(self.passwd())
        self.assertEqual([(o["path"], o["kind"]) for o in objects], [(shared, "plan")])

    def test_shared_directory_with_conflict_is_admin(self):
        shared = self.home("a", 0o750)
        self.row("b", shared, uid=self.uid + 1)
        _error, objects = self.mod.plan(self.passwd())
        self.assertEqual([(o["kind"], o["reason"]) for o in objects], [("admin", "home:shared-conflict")])

    def test_floor_excludes_system_accounts(self):
        self.mod.UID_FLOOR = self.uid + 1
        self.home("low", 0o755)
        _error, objects = self.mod.plan(self.passwd())
        self.assertEqual(objects, [])

    def test_passwd_errors(self):
        result = self.mod.execute_control(CID, "mode", "eq", "0700", True, dry_run=False,
                                          passwd_path=os.path.join(self.tmp, "missing"),
                                          privilege_check=lambda: True)
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "passwd:open:ENOENT"))
        self.assertFalse(result["mutation_performed"])


class T04_Execute(_Tree):
    def test_sets_0700_and_keeps_owner(self):
        a = self.home("a", 0o755)
        b = self.home("b", 0o2750)
        before = {p: os.lstat(p) for p in (a, b)}
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(sorted(result["applied"]), sorted([a, b]))
        for path in (a, b):
            st = os.lstat(path)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)
            self.assertEqual((st.st_uid, st.st_gid, st.st_ino), (before[path].st_uid, before[path].st_gid, before[path].st_ino))

    def test_dry_run_does_not_mutate(self):
        a = self.home("a", 0o755)
        result = self.run_apply(dry_run=True, _fchmod=lambda *x: self.fail("fchmod in dry-run"))
        self.assertEqual(result["outcome"], "DRY_RUN_WOULD_APPLY")
        self.assertEqual(result["violators"], [a])
        self.assertEqual(mode_of(a), 0o755)

    def test_privilege_refusal_before_mutation(self):
        a = self.home("a", 0o755)
        result = self.run_apply(privilege_check=lambda: False, _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
        self.assertEqual(mode_of(a), 0o755)

    def test_admin_only_is_block_with_decision(self):
        other = self.home("other", 0o755, uid=self.uid + 1)
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertEqual(result["reason"], "home:owner-mismatch:" + other)
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
        self.assertTrue(result["operator_decision"]["required"])
        self.assertEqual(mode_of(other), 0o755)

    def test_mixed_is_partial(self):
        a = self.home("a", 0o755)
        other = self.home("other", 0o755, uid=self.uid + 1)
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["applied"], [a])
        self.assertEqual(result["skipped"], [{"path": other, "reason": "home:owner-mismatch"}])
        self.assertEqual((mode_of(a), mode_of(other)), (0o700, 0o755))

    def test_object_failure_does_not_stop_others(self):
        a = self.home("a", 0o755)
        b = self.home("b", 0o755)

        def fchmod(fd, mode, path):
            if path == a:
                raise OSError(errno.EPERM, "denied")
            os.fchmod(fd, mode)

        result = self.run_apply(_fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["failed"], [{"path": a, "reason": "fchmod:EPERM"}])
        self.assertEqual((mode_of(a), mode_of(b)), (0o755, 0o700))

    def test_erofs_stops_immediately(self):
        self.home("a", 0o755)
        b = self.home("b", 0o755)
        calls = []

        def fchmod(fd, mode, path):
            calls.append(path)
            raise OSError(errno.EROFS, "ro")

        result = self.run_apply(_fchmod=fchmod)
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "erofs"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(mode_of(b), 0o755)

    def test_mode_drift_is_refused(self):
        a = self.home("a", 0o755)
        real_plan = self.mod.plan

        def plan_then_drift(path):
            error, objects = real_plan(path)
            os.chmod(a, 0o750)
            return error, objects

        with mock.patch.object(self.mod, "plan", plan_then_drift):
            result = self.run_apply()
        self.assertEqual(result["outcome"], "FAILED_NOT_COMMITTED")
        self.assertEqual(result["failed"], [{"path": a, "reason": "mode-drift"}])
        self.assertEqual(mode_of(a), 0o750)

    def _fail_after_fchmod(self, errno_value):
        real_fstat = os.fstat
        done = {"flag": False}

        def fchmod(fd, mode, path):
            os.fchmod(fd, mode)
            done["flag"] = True

        def fstat(fd):
            if done["flag"]:
                raise OSError(errno_value, "injected")
            return real_fstat(fd)

        with mock.patch.object(self.mod.os, "fstat", fstat):
            return self.run_apply(_fchmod=fchmod)

    def test_postcheck_error_keeps_mutation_fact(self):
        a = self.home("a", 0o755)
        result = self._fail_after_fchmod(errno.EIO)
        self.assertEqual(mode_of(a), 0o700)
        self.assertEqual(result["outcome"], "FAILED_NOT_COMMITTED")
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(result["transaction_commit"], "NOT_COMMITTED")
        self.assertEqual(result["failed"], [{"path": a, "reason": "postcheck:EIO"}])

    def test_postcheck_erofs_is_not_aborted_after_mutation(self):
        a = self.home("a", 0o755)
        result = self._fail_after_fchmod(errno.EROFS)
        self.assertEqual(mode_of(a), 0o700)
        self.assertNotIn(result["outcome"], ("ABORTED_PRECONDITION_OTHER", "ABORTED_PRECONDITION_CONFLICT"))
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(result["failed"], [{"path": a, "reason": "postcheck:EROFS"}])

    def test_close_error_after_mutation_is_recorded(self):
        a = self.home("a", 0o755)
        real_close = os.close
        done = {"flag": False}

        def fchmod(fd, mode, path):
            os.fchmod(fd, mode)
            done["flag"] = True

        def close(fd):
            real_close(fd)
            if done["flag"]:
                raise OSError(errno.EIO, "injected")

        with mock.patch.object(self.mod.os, "close", close):
            result = self.run_apply(_fchmod=fchmod)
        self.assertEqual(mode_of(a), 0o700)
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(result["failed"], [{"path": a, "reason": "close:EIO"}])

    def test_repeat_is_already_compliant(self):
        self.home("a", 0o755)
        self.assertEqual(self.run_apply()["outcome"], "APPLIED")
        again = self.run_apply(_fchmod=lambda *x: self.fail("fchmod on repeat"))
        self.assertEqual(again["outcome"], "ALREADY_COMPLIANT")
        self.assertEqual(again["transaction_commit"], "COMMITTED")

    def test_report_has_dispatcher_fields(self):
        self.home("a", 0o755)
        report = self.mod.control_result_to_report(self.run_apply(), "t0", "t1")
        self.assertTrue(DISPATCHER_FIELDS <= set(report))
        self.assertEqual(report["step_rc"], "0")
        self.assertIn("current_mode", report)


if __name__ == "__main__":
    unittest.main()
