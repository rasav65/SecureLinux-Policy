#!/usr/bin/env python3
"""Regressions for the pam-wheel-su-v1 APPLY mechanism (2.2.1 su-wheel-access, SRC-0003).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on a tree inside a temporary directory passed to the adapter as
`_root`; `groupadd`, `gpasswd` and `groupdel` are replaced by `_run`, which edits
the tree's `etc/group`. No system path is touched and root is not required.

Решения человека 25.09.2026, которые фиксирует этот файл:

* `/etc/pam.d/su` меняется только в байтах файла пакета util-linux (SHA
  `fda16622…`): закомментированная строка `pam_wheel.so` заменяется на
  `auth       required   pam_wheel.so use_uid`; другое содержимое — блок
  «решение администратора»;
* нет `wheel` — `groupadd --system wheel`, затем `gpasswd -a root wheel`; прочие
  участники существующей `wheel` не меняются;
* без участников `sudo`/`admin` — блок «решение администратора», без записи;
* сначала группа, затем PAM; при ошибке группа и PAM возвращаются.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "product/apply-adapters/product-pam-wheel-su-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-pam-wheel-access-check-v2.py"
CONTROL = ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.2.1-su-wheel-access.yaml"
BASH = shutil.which("bash")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = load(ADAPTER, "slp_pam_wheel_su_apply")
CHECK = load(CHECK_ADAPTER, "slp_pam_wheel_access_check_for_apply")


def stock_pam_su():
    # Байты файла пакета util-linux — тот же литерал, что у тестов CHECK 2.2.1.
    src = (ROOT / "tests/product-v1/test_product_generator.py").read_text(encoding="utf-8")
    start = src.index("UBUNTU_2404_STOCK_PAM_SU = (")
    namespace = {}
    exec(src[start:src.index("\n)\n", start) + 3], namespace)
    return namespace["UBUNTU_2404_STOCK_PAM_SU"].encode("utf-8")


STOCK = stock_pam_su()
SPEC = A.CONTROL_SPEC
BASE_GROUP = "root:x:0:\nuucp:x:10:\nsudo:x:27:user\nuser:x:1000:\n"


class Tree:
    def __init__(self, td, pam=STOCK, group=BASE_GROUP):
        self.root = Path(td)
        (self.root / "etc/pam.d").mkdir(parents=True)
        self.pam_path = self.root / "etc/pam.d/su"
        self.pam_path.write_bytes(pam)
        # Права задаются явно: адаптер отказывает при записи для группы, а umask на ПК часто 0002.
        self.pam_path.chmod(0o644)
        self.group_path = self.root / "etc/group"
        self.group_path.write_text(group, encoding="utf-8")
        for rel in ("usr/sbin/groupadd", "usr/sbin/groupdel", "usr/bin/gpasswd"):
            tool = self.root / rel
            tool.parent.mkdir(parents=True, exist_ok=True)
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            tool.chmod(0o755)
        self.calls = []
        self.fail = set()

    def run(self, argv, timeout):
        name = os.path.basename(argv[0])
        self.calls.append([name] + list(argv[1:]))
        if name in self.fail:
            return subprocess.CompletedProcess(argv, 1, b"", b"")
        lines = self.group_path.read_text(encoding="utf-8").splitlines()
        if name == "groupadd":
            lines.append("wheel:x:998:")
        elif name == "groupdel":
            lines = [l for l in lines if not l.startswith("wheel:")]
        elif name == "gpasswd":
            out = []
            for l in lines:
                if l.startswith("wheel:"):
                    f = l.split(":")
                    members = [m for m in f[3].split(",") if m]
                    if argv[1] == "-a":
                        members.append(argv[2])
                    else:
                        members.remove(argv[2])
                    f[3] = ",".join(members)
                    l = ":".join(f)
                out.append(l)
            lines = out
        self.group_path.write_text("".join(l + "\n" for l in lines), encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def pam(self):
        return self.pam_path.read_bytes()

    def group(self):
        return self.group_path.read_text(encoding="utf-8")


def execute(tree, *, dry_run=False, privileged=True, write=None, spec=SPEC):
    return A.execute_control(A.CONTROL_ID, *spec, True, dry_run=dry_run, privilege_check=lambda: privileged,
                             _root=str(tree.root), _run=tree.run, _write=write)


class Apply(unittest.TestCase):
    def test_control_yaml_matches_adapter_spec(self):
        text = CONTROL.read_text(encoding="utf-8")
        self.assertIn('kind: "pam-wheel-access"', text)
        self.assertIn('key: "policy"', text)
        self.assertIn('op: "pam-wheel-root-member"', text)
        self.assertIn('value: "%s"' % SPEC[2], text)
        self.assertEqual(hashlib.sha256(STOCK).hexdigest(), A.PAM_PACKAGE_SHA256)

    def test_stock_system_is_applied_then_compliant_and_check_passes(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            r = execute(t)
            self.assertEqual((r["outcome"], r["mutation_performed"]), ("APPLIED", True), r)
            self.assertEqual(r["policy_current"], "pam_wheel=absent;wheel=absent;root=missing")
            self.assertEqual([c[0] for c in t.calls], ["groupadd", "gpasswd"])
            self.assertEqual(t.calls[0], ["groupadd", "--system", "wheel"])
            self.assertEqual(hashlib.sha256(t.pam()).hexdigest(), A.PAM_APPLIED_SHA256)
            self.assertEqual(t.pam(), STOCK.replace(A.PAM_LINE_OLD, A.PAM_LINE_NEW))
            self.assertEqual(t.pam_path.stat().st_mode & 0o777, 0o644)
            self.assertIn("wheel:x:998:root\n", t.group())
            self.assertEqual(A.outcome_rc_contribution(r["outcome"]), "0")
            r = execute(t)
            self.assertEqual(r["outcome"], "ALREADY_COMPLIANT")
            self.assertEqual(r["policy_current"], "pam_wheel=present;wheel=gid 998;root=member")
            if BASH is None:
                self.skipTest("bash not found")
            block = CHECK._shell_function_for_fixture("PAM.WHEEL.TEST", str(t.pam_path), str(t.group_path))
            cp = subprocess.run([BASH, "-c", "set -u\n" + block + "\nslp_check_PAM_WHEEL_TEST\n"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(cp.stdout.strip().split("\t")[2:], ["VALUE", "pam_wheel=present;wheel=gid 998;root=member", "PASS"])

    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            r = execute(t, dry_run=True)
            self.assertEqual(r["outcome"], "DRY_RUN_WOULD_APPLY")
            self.assertEqual((t.pam(), t.group(), t.calls), (STOCK, BASE_GROUP, []))
            self.assertEqual(A.outcome_rc_contribution(r["outcome"], True), "0")

    def test_existing_wheel_keeps_members_and_gets_root(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, group=BASE_GROUP + "wheel:x:1500:alice\n")
            r = execute(t)
            self.assertEqual(r["outcome"], "APPLIED", r)
            self.assertEqual(t.calls, [["gpasswd", "-a", "root", "wheel"]])
            self.assertIn("wheel:x:1500:alice,root\n", t.group())

    def test_applied_pam_and_wheel_without_root_only_adds_root(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, pam=STOCK.replace(A.PAM_LINE_OLD, A.PAM_LINE_NEW), group=BASE_GROUP + "wheel:x:1500:\n")
            r = execute(t)
            self.assertEqual(r["outcome"], "APPLIED", r)
            self.assertNotIn("PHASE2_PAM", r["actions_attempted"])
            self.assertEqual(t.calls, [["gpasswd", "-a", "root", "wheel"]])

    def test_foreign_pam_is_admin_decision_without_write(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, pam=STOCK + b"# local\n")
            r = execute(t)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "pam:foreign-content"))
            self.assertEqual(r["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
            self.assertIn("auth required pam_wheel.so use_uid", r["operator_decision"]["action"])
            self.assertEqual(r["policy_current"], "pam_wheel=not-determined;wheel=absent;root=missing")
            self.assertEqual((t.pam(), t.group(), t.calls), (STOCK + b"# local\n", BASE_GROUP, []))

    def test_no_sudo_members_is_admin_decision_without_write(self):
        with tempfile.TemporaryDirectory() as td:
            group = "root:x:0:\nsudo:x:27:\n"
            t = Tree(td, group=group)
            r = execute(t)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "su:no-sudo-members"))
            self.assertEqual(r["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
            self.assertEqual((t.pam(), t.group(), t.calls), (STOCK, group, []))

    def test_admin_group_member_is_enough(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, group="root:x:0:\nadmin:x:116:user\n")
            self.assertEqual(execute(t)["outcome"], "APPLIED")

    def test_group_writable_pam_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.pam_path.chmod(0o664)
            r = execute(t)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "pam:untrusted"))
            self.assertEqual(t.calls, [])

    def test_duplicate_wheel_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, group=BASE_GROUP + "wheel:x:1500:\nwheel:x:1501:root\n")
            r = execute(t)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "group:duplicate-wheel"))

    def test_groupadd_failure_changes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.fail = {"groupadd"}
            r = execute(t)
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "group:groupadd-failed", False))
            self.assertEqual((t.pam(), t.group()), (STOCK, BASE_GROUP))

    def test_pam_write_failure_removes_created_group(self):
        def broken(root, raw, st):
            raise OSError("fixture")
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            r = execute(t, write=broken)
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "pam:write-failed"))
            self.assertEqual(t.calls[-1], ["groupdel", "wheel"])
            self.assertEqual((t.pam(), t.group()), (STOCK, BASE_GROUP))
            self.assertEqual(A.outcome_rc_contribution(r["outcome"]), "nonzero")

    def test_pam_write_failure_removes_added_root_from_existing_wheel(self):
        def broken(root, raw, st):
            raise OSError("fixture")
        with tempfile.TemporaryDirectory() as td:
            group = BASE_GROUP + "wheel:x:1500:alice\n"
            t = Tree(td, group=group)
            r = execute(t, write=broken)
            self.assertEqual(r["outcome"], "FAILED_NOT_COMMITTED")
            self.assertEqual(t.calls[-1], ["gpasswd", "-d", "root", "wheel"])
            self.assertEqual(t.group(), group)

    def test_failed_compensation_is_reported(self):
        def broken(root, raw, st):
            raise OSError("fixture")
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.fail = {"groupdel"}
            r = execute(t, write=broken)
            self.assertEqual(r["outcome"], "FAILED_COMPENSATION")

    def test_postcheck_failure_restores_pam_and_group(self):
        def wrong(root, raw, st):
            A._write_pam(root, raw + b"# drift\n", st)
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            r = execute(t, write=wrong)
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "postcheck:not-compliant"))
            self.assertEqual(t.group(), BASE_GROUP)
            self.assertEqual(t.pam(), STOCK + b"# drift\n")

    def test_privilege_and_spec_are_checked(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            r = execute(t, privileged=False)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
            r = execute(t, spec=("policy", "eq", "x"))
            self.assertEqual((r["outcome"], r["reason"]), ("NOT_ELIGIBLE_APPLY_UNSUPPORTED", "op-unsupported"))
            self.assertEqual((t.pam(), t.group(), t.calls), (STOCK, BASE_GROUP, []))

    def test_report_carries_decision_and_current(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, group="root:x:0:\n")
            rep = A.control_result_to_report(execute(t), "s", "f")
            self.assertEqual(rep["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
            self.assertEqual(rep["policy_current"], "pam_wheel=absent;wheel=absent;root=missing")
            self.assertEqual(rep["step_rc"], "nonzero")
            self.assertFalse(rep["mutation_performed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
