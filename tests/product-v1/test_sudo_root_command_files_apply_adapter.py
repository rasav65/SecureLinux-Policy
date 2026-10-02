#!/usr/bin/env python3
"""Regressions for the sudo-root-command-files-protection APPLY mechanism (2.3.4, SRC-0008).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Cases run on files created inside a temporary directory owned by the current
user; the CHECK observer is either replaced by a small fixture observer
(plumbing of NOT_APPLICABLE / ERROR / VALUE) or by an injected observation.
No system path is touched and root is not required.

Решение пользователя 29.09.2026, которое фиксирует этот файл: APPLY 2.3.4 снимает go-w у файлов
с битом записи для прочих при любом владельце; смена владельца (chown root) — решение
администратора. Расширенный POSIX ACL у файла, требующего chmod, останавливает весь APPLY до
первой мутации (контракт CHECK, acl_policy.future_apply).
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
ADAPTER = ROOT / "product/apply-adapters/product-sudo-root-command-files-protection-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-sudo-root-command-files-protection-check-v2.py"
CONTROL = ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.4-sudo-root-command-files-protection.yaml"
CID = "FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION"
ARGS = ("root-command-files", "root-owned-go-w-conditional", "owner-if-regular-user;go-w-if-other-write")

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


def state_of(path):
    st = os.stat(path)
    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns,
            st.st_mtime_ns, st.st_size, st.st_nlink)


class _Files(unittest.TestCase):
    def setUp(self):
        self.mod = load(ADAPTER, "slp_sudo_files_apply")
        self.tmp = tempfile.mkdtemp(prefix="slp-sudo-apply-")
        self.items = []

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def cmd(self, name, mode, owner_bad=False, logical=None):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/true\n")
        os.chmod(path, mode)
        st = state_of(path)
        logical = logical or "/usr/local/sbin/" + name
        self.items.append((logical, (logical, path, st, st), owner_bad, bool(st[4] & 0o002)))
        return path, logical

    def run_apply(self, dry_run=False, **kw):
        kw.setdefault("privilege_check", lambda: True)
        items = list(self.items)
        return self.mod.execute_control(CID, *ARGS, True, dry_run=dry_run,
                                        _observer=lambda: (None, items), **kw)


class T01_Identity(unittest.TestCase):
    def test_module_identity_and_control(self):
        mod = load(ADAPTER, "slp_sudo_files_apply")
        self.assertEqual(mod.ADAPTER_ID, "product-sudo-root-command-files-protection-apply-v1")
        self.assertEqual(mod.MECHANISM_ID, "sudo-root-command-files-protection-v1")
        self.assertEqual(mod.TARGET_ID, "linux-x86_64-supported-v1")
        self.assertEqual(mod.PARAMETER_KIND, "sudo-root-command-files-protection")
        self.assertEqual(mod.CONTROLS, (CID,))
        text = CONTROL.read_text(encoding="utf-8")
        self.assertIn('id: "%s"\n' % CID, text)
        self.assertIn("\napply:\n  supported: true\n", text)

    def test_observer_is_byte_copy_of_check(self):
        mod = load(ADAPTER, "slp_sudo_files_apply")
        check = load(CHECK_ADAPTER, "slp_sudo_files_check")
        self.assertEqual(mod.OBSERVER_SOURCE, check._PY)
        for name in ("DEFAULT_VISUDO", "DEFAULT_CVTSUDOERS", "DEFAULT_LOGIN_DEFS", "DEFAULT_ADDUSER_CONF",
                     "CANONICAL_LOCATOR"):
            self.assertEqual(getattr(mod, name), getattr(check, name), name)

    def test_input_validation(self):
        mod = load(ADAPTER, "slp_sudo_files_apply")
        for args in (("mode", ARGS[1], ARGS[2]), (ARGS[0], "bits-clear", ARGS[2]), (ARGS[0], ARGS[1], "go-w")):
            with self.assertRaises(ValueError):
                mod.validate_control_input(CID, *args, True)


class T02_ObserverPlumbing(unittest.TestCase):
    def setUp(self):
        self.mod = load(ADAPTER, "slp_sudo_files_apply")

    def observe_with(self, source):
        with mock.patch.object(self.mod, "OBSERVER_SOURCE", source):
            saved = list(__import__("sys").argv)
            result = self.mod.observe()
            self.assertEqual(__import__("sys").argv, saved)
            return result

    def test_not_applicable_is_empty_population(self):
        self.assertEqual(self.observe_with('print("NOT_APPLICABLE\\tfiles=0")\nraise SystemExit(0)\n'), (None, []))

    def test_error_is_reason(self):
        self.assertEqual(self.observe_with('print("ERROR\\tvisudo:validation-failed")\nraise SystemExit(0)\n'),
                         ("visudo:validation-failed", None))

    def test_value_exposes_records_and_owner_classification(self):
        src = ('records = {"/b": ("/b", "/r/b", 0, (1, 2, 1000, 1000, 0o777, 0, 0, 0, 1)),\n'
               '           "/a": ("/a", "/r/a", 0, (1, 3, 0, 0, 0o755, 0, 0, 0, 1))}\n'
               'ranges = ((1000, 60000),)\npasswd_names = {}\n'
               'def owner_condition(uid, ranges, names):\n    return uid >= 1000\n'
               'print("VALUE\\tfiles=2;owner_violations=1;mode_violations=1\\tFAIL")\n')
        error, items = self.observe_with(src)
        self.assertIsNone(error)
        self.assertEqual([(i[0], i[2], i[3]) for i in items], [("/a", False, False), ("/b", True, True)])

    def test_unexpected_output_refuses(self):
        self.assertEqual(self.observe_with('print("garbage")\n'), ("observer:invalid-output", None))


class T03_Execute(_Files):
    def test_other_write_is_cleared_owner_kept(self):
        path, logical = self.cmd("a", 0o777)
        before = os.lstat(path)
        result = self.run_apply()
        self.assertEqual((result["outcome"], result["applied"]), ("APPLIED", [logical]))
        self.assertEqual(mode_of(path), 0o755)
        st = os.lstat(path)
        self.assertEqual((st.st_uid, st.st_gid, st.st_ino), (before.st_uid, before.st_gid, before.st_ino))

    def test_group_write_only_is_compliant(self):
        path, _ = self.cmd("a", 0o775)
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["outcome"], "ALREADY_COMPLIANT")
        self.assertEqual(mode_of(path), 0o775)

    def test_regular_user_owner_is_admin_only(self):
        path, logical = self.cmd("a", 0o755, owner_bad=True)
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertEqual(result["reason"], "owner:regular-user:" + logical)
        self.assertIn("chown root", result["operator_decision"]["action"])
        self.assertEqual(mode_of(path), 0o755)

    def test_owner_and_mode_is_partial(self):
        path, logical = self.cmd("a", 0o777, owner_bad=True)
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["applied"], [logical])
        self.assertEqual(result["skipped"], [{"path": logical, "reason": "owner:regular-user"}])
        self.assertEqual(result["current_mode"], "files=1;mode_violations=1;admin=1")
        self.assertEqual(mode_of(path), 0o755)

    def test_dry_run_does_not_mutate(self):
        path, logical = self.cmd("a", 0o777)
        result = self.run_apply(dry_run=True, _fchmod=lambda *x: self.fail("fchmod in dry-run"))
        self.assertEqual((result["outcome"], result["violators"]), ("DRY_RUN_WOULD_APPLY", [logical]))
        self.assertEqual(mode_of(path), 0o777)

    def test_observer_error_refuses_without_mutation(self):
        result = self.mod.execute_control(CID, *ARGS, True, dry_run=False, privilege_check=lambda: True,
                                          _observer=lambda: ("visudo:validation-failed", None),
                                          _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["reason"]),
                         ("ABORTED_PRECONDITION_OTHER", "check:visudo:validation-failed"))

    def test_control_bytes_are_admin_with_marker(self):
        path, _ = self.cmd("a", 0o777, logical="/usr/local/sbin/a\x1bb")
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["reason"], "target:invalid-name:<invalid-name>")
        self.assertEqual(mode_of(path), 0o777)

    def test_privilege_refusal_before_mutation(self):
        path, _ = self.cmd("a", 0o777)
        result = self.run_apply(privilege_check=lambda: False, _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
        self.assertEqual(mode_of(path), 0o777)

    def test_drift_is_refused(self):
        path, logical = self.cmd("a", 0o777)
        os.chmod(path, 0o776)
        result = self.run_apply()
        self.assertEqual(result["failed"], [{"path": logical, "reason": "mode-drift"}])
        self.assertEqual(mode_of(path), 0o776)

    def _to_symlink(self, path):
        outside = os.path.join(self.tmp, "outside")
        open(outside, "w").close()
        os.chmod(outside, 0o666)
        os.unlink(path)
        os.symlink(outside, path)
        return outside

    def test_replaced_by_symlink_before_acl_scan_is_refused(self):
        path, logical = self.cmd("a", 0o777)
        outside = self._to_symlink(path)
        result = self.run_apply(_fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["reason"]),
                         ("ABORTED_PRECONDITION_OTHER", "acl:open:ELOOP:" + logical))
        self.assertEqual(mode_of(outside), 0o666)

    def test_replaced_by_symlink_after_acl_scan_is_refused(self):
        path, logical = self.cmd("a", 0o777)
        box = {}

        def listxattr(fd):
            if not box:
                box["outside"] = self._to_symlink(path)
            return []

        result = self.run_apply(_listxattr=listxattr)
        self.assertEqual(result["failed"], [{"path": logical, "reason": "type-drift"}])
        self.assertEqual(mode_of(box["outside"]), 0o666)

    def test_extended_acl_blocks_whole_apply_before_first_mutation(self):
        a, _ = self.cmd("a", 0o777)
        b, logical_b = self.cmd("b", 0o777)
        acl_ino = os.stat(b).st_ino

        def listxattr(fd):
            return [self.mod.ACL_XATTR] if os.fstat(fd).st_ino == acl_ino else []

        for dry_run in (False, True):
            result = self.run_apply(dry_run=dry_run, _listxattr=listxattr, _fchmod=lambda *x: self.fail("fchmod"))
            self.assertEqual((result["outcome"], result["reason"]),
                             ("ABORTED_PRECONDITION_CONFLICT", "acl:extended:" + logical_b))
            self.assertFalse(result["mutation_performed"])
            self.assertIn("getfacl", result["operator_decision"]["action"])
            self.assertEqual((mode_of(a), mode_of(b)), (0o777, 0o777))

    def test_acl_on_compliant_or_admin_only_file_is_not_a_blocker(self):
        self.cmd("a", 0o755)
        self.cmd("b", 0o755, owner_bad=True)
        result = self.run_apply(_listxattr=lambda fd: [self.mod.ACL_XATTR], _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["reason"], "owner:regular-user:/usr/local/sbin/b")

    def test_acl_appearing_before_fchmod_is_drift(self):
        path, logical = self.cmd("a", 0o777)
        calls = []

        def listxattr(fd):
            calls.append(fd)
            return [self.mod.ACL_XATTR] if len(calls) > 1 else []

        result = self.run_apply(_listxattr=listxattr, _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual(result["failed"], [{"path": logical, "reason": "acl-drift"}])
        self.assertEqual(mode_of(path), 0o777)

    def test_acl_unsupported_is_absent_and_read_error_refuses(self):
        path, logical = self.cmd("a", 0o777)

        def raising(code):
            def listxattr(fd):
                raise OSError(code, "injected")
            return listxattr

        result = self.run_apply(_listxattr=raising(errno.EIO), _fchmod=lambda *x: self.fail("fchmod"))
        self.assertEqual((result["outcome"], result["reason"]),
                         ("ABORTED_PRECONDITION_OTHER", "acl:read:EIO:" + logical))
        self.assertEqual(mode_of(path), 0o777)
        result = self.run_apply(_listxattr=raising(errno.EOPNOTSUPP))
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertEqual(mode_of(path), 0o755)

    def test_erofs_stops_immediately(self):
        self.cmd("a", 0o777)
        b, _ = self.cmd("b", 0o777)
        calls = []

        def fchmod(fd, mode, path):
            calls.append(path)
            raise OSError(errno.EROFS, "ro")

        result = self.run_apply(_fchmod=fchmod)
        self.assertEqual((result["outcome"], result["reason"]), ("ABORTED_PRECONDITION_OTHER", "erofs"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(mode_of(b), 0o777)

    def test_postcheck_error_keeps_mutation_fact(self):
        path, logical = self.cmd("a", 0o777)
        real_fstat = os.fstat
        done = {"flag": False}

        def fchmod(fd, mode, p):
            os.fchmod(fd, mode)
            done["flag"] = True

        def fstat(fd):
            if done["flag"]:
                raise OSError(errno.EIO, "injected")
            return real_fstat(fd)

        with mock.patch.object(self.mod.os, "fstat", fstat):
            result = self.run_apply(_fchmod=fchmod)
        self.assertEqual(mode_of(path), 0o755)
        self.assertTrue(result["mutation_performed"])
        self.assertEqual(result["failed"], [{"path": logical, "reason": "postcheck:EIO"}])

    def test_report_has_dispatcher_fields(self):
        self.cmd("a", 0o777)
        report = self.mod.control_result_to_report(self.run_apply(), "t0", "t1")
        self.assertTrue(DISPATCHER_FIELDS <= set(report))
        self.assertEqual(report["step_rc"], "0")


if __name__ == "__main__":
    unittest.main()
