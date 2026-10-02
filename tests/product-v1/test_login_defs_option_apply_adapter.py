#!/usr/bin/env python3
"""Regressions for the login-defs-option-v1 APPLY mechanism (fstec-configuration-2026 п.1.1).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Каждый случай работает на дереве во временном каталоге внутри репозитория (`_root`); запись
файла подменяется только там, где проверяется отказ. Решение пользователя 26.09.2026:
PASS_MAX_DAYS 90, PASS_MIN_DAYS 1, PASS_WARN_AGE 7, ENCRYPT_METHOD SHA512 или YESCRYPT.
"""

from __future__ import annotations

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
ADAPTER = ROOT / "product/apply-adapters/product-login-defs-option-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-login-defs-option-check-v1.py"
CONTROLS = ROOT / "controls/fstec-core/configuration-2026"
BASH = shutil.which("bash")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = load(ADAPTER, "slp_login_defs_apply")
C = load(CHECK_ADAPTER, "slp_login_defs_check")

STOCK = (
    "# /etc/login.defs - Configuration control definitions for the login package.\n"
    "MAIL_DIR\t\t/var/mail\n"
    "#\n"
    "# Password aging controls:\n"
    "PASS_MAX_DAYS\t99999\n"
    "PASS_MIN_DAYS\t0\n"
    "PASS_WARN_AGE\t7\n"
    "UMASK\t\t022\n"
    "#ENCRYPT_METHOD DES\n"
)


class Tree:
    def __init__(self, td, text=STOCK, mode=0o644):
        self.root = Path(td)
        (self.root / "etc").mkdir()
        self.path = self.root / "etc/login.defs"
        self.path.write_bytes(text.encode("utf-8"))
        self.path.chmod(mode)

    def text(self):
        return self.path.read_bytes().decode("utf-8")


def execute(t, key, dry_run=False, privileged=True, write=None):
    op, expected = A.SPECS[key]
    return A.execute_control("FSTEC-CONFIGURATION-2026-1.1-" + key.replace("_", "-"), key, op, expected, True,
                             dry_run=dry_run, privilege_check=lambda: privileged, _root=str(t.root),
                             _write_file=write)


class Contract(unittest.TestCase):
    def test_specs_match_check_adapter(self):
        self.assertEqual(A.SPECS, C.SPECS)
        self.assertEqual(set(A.WRITE), set(A.SPECS))
        for key, value in A.WRITE.items():
            self.assertTrue(A.compliant(key, value), key)

    def test_controls_are_routed(self):
        seen = {}
        paths = sorted(CONTROLS.glob("fstec-configuration-2026-1.1-*.yaml"))
        paths.append(ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.11-home-mode.yaml")
        for path in paths:
            text = path.read_text(encoding="utf-8")
            if '  kind: "login-defs-option"\n' not in text:
                continue  # иные контроли п.1.1 (pam_pwquality)
            self.assertIn('  kind: "login-defs-option"\n  locator: "/etc/login.defs"\n', text)
            self.assertIn("apply:\n  supported: true\n", text)
            key = re.search(r'^  key: "([A-Z_]+)"$', text, re.M).group(1)
            op = re.search(r'^  op: "([a-z-]+)"$', text, re.M).group(1)
            value = re.search(r'^  value: "([^"]+)"$', text, re.M).group(1)
            seen[key] = (op, value)
        self.assertEqual(seen, A.SPECS)

    def test_unsupported_inputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            for key, op, value in (("PASS_MIN_LEN", "eq", "12"), ("PASS_MAX_DAYS", "eq", "60"),
                                   ("ENCRYPT_METHOD", "eq", "SHA512")):
                r = A.execute_control("C", key, op, value, True, dry_run=False, _root=str(t.root))
                self.assertEqual((r["outcome"], r["reason"]), ("NOT_ELIGIBLE_APPLY_UNSUPPORTED", "op-unsupported"))
            self.assertEqual(t.text(), STOCK)

    @unittest.skipIf(BASH is None, "bash not available")
    def test_check_and_apply_read_the_same_value(self):
        texts = (STOCK, "PASS_MAX_DAYS 1\nPASS_MAX_DAYS 90\n", '  PASS_MAX_DAYS\t"90"  # c\n', "#PASS_MAX_DAYS 90\n",
                 "PASS_MAX_DAYS -1\n", "ENCRYPT_METHOD yescrypt\nENCRYPT_METHOD YESCRYPT\n", "PASS_MAX_DAYS\n",
                 # Иные пробельные и управляющие символы.
                 "PASS_MAX_DAYS 90\n\x0b\n", "\rPASS_MAX_DAYS 90\n", "PASS_MAX_DAYS 90\r\n", "PASS_MAX_DAYS\x0c90\n",
                 "PASS_MAX_DAYS\u00a090\n", "# c\u2028\nPASS_MAX_DAYS 90\n", "PASS_MAX_DAYS 90\x85\n",
                 "PASS_MAX_DAYS \"\"\n", "PASS_MAX_DAYS\t\r\n", "\t \r\nPASS_MAX_DAYS 7 90\n")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "login.defs"
            for text in texts:
                path.write_text(text, encoding="utf-8")
                for key, (op, expected) in C.SPECS.items():
                    with self.subTest(text=text, key=key):
                        fn = C._shell_function_for_fixture("C.1", key, op, expected, str(path))
                        row = subprocess.run([BASH, "-c", fn + "\nslp_check_C_1\n"], capture_output=True,
                                             text=True).stdout.strip().split("\t")
                        try:
                            value = A.current_value(text, key)
                        except A._Refused as exc:
                            self.assertEqual(row[2:], ["ERROR", exc.reason, "ERROR"])
                            continue
                        self.assertEqual(row[2:], ["VALUE", "<absent>" if value is None else value,
                                                   "PASS" if A.compliant(key, value) else "FAIL"])

    @unittest.skipIf(BASH is None, "bash not available")
    def test_check_errors_and_read_only(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            base = Path(td)
            (base / "dir").mkdir()
            (base / "nul").write_bytes(b"PASS_MAX_DAYS 90\x00\n")
            for name, reason in (("missing", "login-defs:missing"), ("dir", "login-defs:invalid-type"),
                                 ("nul", "login-defs:invalid-bytes")):
                with self.subTest(name=name):
                    fn = C._shell_function_for_fixture("C.1", "PASS_MAX_DAYS", "eq", "90", str(base / name))
                    row = subprocess.run([BASH, "-c", fn + "\nslp_check_C_1\n"], capture_output=True,
                                         text=True).stdout.strip().split("\t")
                    self.assertEqual(row[2:], ["ERROR", reason, "ERROR"])
        for key, (op, expected) in C.SPECS.items():
            src = C.shell_function("C", "/etc/login.defs", key, op, expected)
            for token in C.MUTATING_TOKENS:
                self.assertNotIn(token, src)
        with self.assertRaises(ValueError):
            C.shell_function("C", "/etc/login.defs", "PASS_MAX_DAYS", "eq", "99999")


class Apply(unittest.TestCase):
    def test_foreign_whitespace_is_refused_without_write(self):
        for text in ("PASS_MAX_DAYS 99999\n\x0b\n", "\rPASS_MAX_DAYS 99999\n", "# \u2028\nPASS_MAX_DAYS 1\n"):
            with self.subTest(text=text), tempfile.TemporaryDirectory(dir=ROOT) as td:
                t = Tree(td, text=text)
                r = execute(t, "PASS_MAX_DAYS")
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "login-defs:invalid-line"))
                self.assertEqual(t.text(), text)

    def test_crlf_line_is_changed_in_place(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, text="PASS_MAX_DAYS\t99999\r\n")
            r = execute(t, "PASS_MAX_DAYS")
            self.assertEqual(r["outcome"], "APPLIED")
            self.assertEqual(t.text(), "PASS_MAX_DAYS\t90\r\n")

    def test_compliant_value_is_not_rewritten(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            before = os.stat(t.path).st_ino
            r = execute(t, "PASS_WARN_AGE")
            self.assertEqual((r["outcome"], r["policy_current"]), ("ALREADY_COMPLIANT", "7"))
            self.assertEqual((t.text(), os.stat(t.path).st_ino), (STOCK, before))

    def test_active_line_is_changed_in_place(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            r = execute(t, "PASS_MAX_DAYS")
            self.assertEqual((r["outcome"], r["mutation_performed"], r["policy_current"]), ("APPLIED", True, "90"))
            self.assertEqual(t.text(), STOCK.replace("PASS_MAX_DAYS\t99999\n", "PASS_MAX_DAYS\t90\n"))
            self.assertEqual(stat.S_IMODE(t.path.stat().st_mode), 0o644)
            self.assertEqual(execute(t, "PASS_MAX_DAYS")["outcome"], "ALREADY_COMPLIANT")
            self.assertEqual(list(t.path.parent.iterdir()), [t.path])

    def test_every_active_line_is_changed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, "PASS_MIN_DAYS 0\nX 1\nPASS_MIN_DAYS 3 # later\n")
            self.assertEqual(execute(t, "PASS_MIN_DAYS")["outcome"], "APPLIED")
            self.assertEqual(t.text(), "PASS_MIN_DAYS 1\nX 1\nPASS_MIN_DAYS 1 # later\n")

    def test_template_then_append(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            self.assertEqual(execute(t, "ENCRYPT_METHOD")["outcome"], "APPLIED")
            self.assertEqual(t.text(), STOCK.replace("#ENCRYPT_METHOD DES\n", "ENCRYPT_METHOD\tSHA512\n"))
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, "UMASK 022")
            self.assertEqual(execute(t, "PASS_MAX_DAYS")["outcome"], "APPLIED")
            self.assertEqual(t.text(), "UMASK 022\nPASS_MAX_DAYS\t90\n")

    def test_yescrypt_is_compliant(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, "ENCRYPT_METHOD YESCRYPT\n")
            self.assertEqual(execute(t, "ENCRYPT_METHOD")["outcome"], "ALREADY_COMPLIANT")

    def test_dry_run_and_privilege_do_not_write(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            r = execute(t, "PASS_MAX_DAYS", dry_run=True)
            self.assertEqual((r["outcome"], r["policy_current"]), ("DRY_RUN_WOULD_APPLY", "99999"))
            self.assertEqual(A.outcome_rc_contribution(r["outcome"], True), "0")
            r = execute(t, "PASS_MAX_DAYS", privileged=False)
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("ABORTED_PRECONDITION_OTHER", "privilege", False))
            self.assertEqual(t.text(), STOCK)

    def test_untrusted_file_needs_admin(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, mode=0o664)
            r = execute(t, "PASS_MAX_DAYS")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "login-defs:untrusted"))
            self.assertEqual(r["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
            self.assertEqual(t.text(), STOCK)
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            real = t.root / "etc/real.defs"
            t.path.rename(real)
            t.path.symlink_to(real)
            r = execute(t, "PASS_MAX_DAYS")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "login-defs:untrusted"))

    def test_invalid_content_is_refused(self):
        for text, reason in (("PASS_MAX_DAYS\n", "login-defs:invalid-line"), ("A\x00\n", "login-defs:invalid-bytes"),
                             (b"\xff\n".decode("latin-1"), "login-defs:invalid-bytes")):
            with tempfile.TemporaryDirectory(dir=ROOT) as td:
                t = Tree(td)
                t.path.write_bytes(text.encode("latin-1") if "\xff" in text else text.encode("utf-8"))
                r = execute(t, "PASS_MAX_DAYS")
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", reason))
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            t.path.unlink()
            self.assertEqual(execute(t, "PASS_MAX_DAYS")["reason"], "login-defs:missing")

    def test_write_failure_is_not_committed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)

            def write(path, raw, st):
                raise OSError("EIO")

            r = execute(t, "PASS_MAX_DAYS", write=write)
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "login-defs:write-failed", True))
            self.assertEqual(t.text(), STOCK)
            self.assertEqual(A.outcome_rc_contribution(r["outcome"]), "nonzero")

    def test_postcheck_failure_restores_bytes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            calls = []

            def write(path, raw, st):
                calls.append(raw)
                A._write(path, raw if len(calls) > 1 else raw + b"PASS_MAX_DAYS 5\n", st)

            r = execute(t, "PASS_MAX_DAYS", write=write)
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "login-defs:postcheck-failed"))
            self.assertEqual(t.text(), STOCK)
            self.assertEqual(len(calls), 2)

    def test_failed_restore_is_failed_compensation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            calls = []

            def write(path, raw, st):
                calls.append(raw)
                if len(calls) > 1:
                    raise OSError("EIO")
                A._write(path, raw + b"PASS_MAX_DAYS 5\n", st)

            r = execute(t, "PASS_MAX_DAYS", write=write)
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_COMPENSATION", "login-defs:postcheck-failed", True))

    def test_report_fields(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            rep = A.control_result_to_report(execute(t, "PASS_MIN_DAYS"), "s", "f")
            self.assertEqual((rep["outcome"], rep["step_rc"], rep["target"]), ("APPLIED", "0", "/etc/login.defs"))
            self.assertEqual(set(rep), {"adapter_id", "mechanism_id", "control_id", "target", "outcome", "reason",
                                        "policy_current", "operator_decision", "started_at", "finished_at",
                                        "actions_attempted", "step_rc", "mutation_performed", "transaction_commit"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
