#!/usr/bin/env python3
"""Regressions for the pam-pwhistory-profile-v1 APPLY mechanism (fstec-configuration-2026 п.1.2).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Каждый случай работает на дереве во временном каталоге внутри репозитория (`_root`);
pam-auth-update подменяется (`_run`) моделью, которая по профилю вставляет строку модуля в
common-password или, по сценарию, ничего не меняет, завершается ошибкой или меняет лишний файл.
Решение пользователя 26.09.2026: remember=5; 27.09.2026 — профиль pam-auth-update и только
эталонные стеки password (строки PWQ, UNIX, UNIX_CLEAN, TAIL — как в журналах ВМ-прогона
27.09.2026 на семи средах).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "product/apply-adapters/product-pam-pwhistory-profile-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-pam-pwhistory-remember-check-v1.py"
CONTROLS = ROOT / "controls/fstec-core/configuration-2026"
BASH = shutil.which("bash")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = load(ADAPTER, "slp_pwhistory_apply")
C = load(CHECK_ADAPTER, "slp_pwhistory_check")

PWQ = b"password\trequisite\t\t\tpam_pwquality.so retry=3\n"
UNIX = b"password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass yescrypt\n"
TAIL = b"password\trequisite\t\t\tpam_deny.so\npassword\trequired\t\t\tpam_permit.so\n"
HEAD = b"# here are the per-package modules (the \"Primary\" block)\n"
PAM = HEAD + PWQ + UNIX + TAIL
HIST = b"password\trequisite\t\t\tpam_pwhistory.so remember=5 retry=1 use_authtok\n"
NO_RETRY = b"password\trequisite\t\t\tpam_pwhistory.so remember=5 use_authtok\n"
SEEN = b"unix\npwquality\n"
PAM_AFTER = HEAD + PWQ + HIST + UNIX + TAIL
UNIX_CLEAN = b"password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n"
PAM_CLEAN = HEAD + UNIX_CLEAN + TAIL
CONF_STOCK = b"# pwhistory.conf\n#\n# remember = 10\n  # retry = 1\n\n"
AUTH = b"auth\t[success=1 default=ignore]\tpam_unix.so nullok\nauth\trequisite\t\t\tpam_deny.so\n"


class Proc:
    def __init__(self, returncode):
        self.returncode = returncode
        self.stdout = b""
        self.stderr = b""


class FakePamAuthUpdate:
    """mode: ok — вставить строку по профилю; local — ничего не менять (локальные правки);
    fail — код 1; extra — ещё и изменить common-auth; broken — вставить строку после pam_unix;
    noretry — строка без retry; remove-fail — как extra, и --remove завершается кодом 1;
    debconf-stuck — как extra, и --remove оставляет лишний выбор в debconf; debconf-fail —
    debconf-show завершается ошибкой. Включение и удаление
    переписывают /var/lib/pam/seen и /var/lib/pam/password, как pam-auth-update."""

    def __init__(self, tree, mode="ok"):
        self.tree = tree
        self.mode = mode
        self.calls = []
        self.selection = b"unix, pwquality"

    def __call__(self, argv, timeout):
        if argv[0] == A.DEBCONF_SHOW:
            if self.mode == "debconf-fail":
                return Proc(1)
            out = Proc(0)
            out.stdout = b"* libpam-runtime/override: false\n* libpam-runtime/profiles: " + self.selection + b"\n"
            return out
        self.calls.append(argv)
        assert argv[0] == A.PAM_AUTH_UPDATE and argv[1] == "--package", argv
        pam = self.tree.pam
        if argv[2] == "--enable":
            if self.mode == "fail":
                return Proc(1)
            if self.mode == "local" or not self.tree.profile.exists():
                return Proc(0)
            data = pam.read_bytes()
            self.selection = b"unix, securelinux-pwhistory, pwquality, extra"
            self.tree.seen.write_bytes(b"unix\nsecurelinux-pwhistory\npwquality\n")
            self.tree.state_password.write_bytes(b"generated\n")
            if self.mode == "broken":
                pam.write_bytes(data.replace(UNIX, UNIX + HIST))
            elif self.mode == "noretry":
                pam.write_bytes(data.replace(UNIX, NO_RETRY + UNIX))
            else:
                pam.write_bytes(data.replace(UNIX, HIST + UNIX))
            if self.mode in ("extra", "remove-fail", "debconf-stuck"):
                self.tree.auth.write_bytes(AUTH + b"auth\toptional\tpam_cap.so\n")
            return Proc(0)
        if argv[2] == "--remove":
            if self.mode == "remove-fail":
                return Proc(1)
            pam.write_bytes(pam.read_bytes().replace(HIST, b"").replace(NO_RETRY, b""))
            self.selection = b"unix, pwquality, extra" if self.mode == "debconf-stuck" else b"unix, pwquality"
            self.tree.seen.write_bytes(b"pwquality\nunix\n")
            return Proc(0)
        raise AssertionError(argv)


class Tree:
    def __init__(self, td, pam=PAM, module=True, profile=None, conf=None, vendor_conf=None):
        self.root = Path(td)
        (self.root / "etc/pam.d").mkdir(parents=True)
        (self.root / "usr/share/pam-configs").mkdir(parents=True)
        (self.root / "var/lib/pam").mkdir(parents=True)
        self.seen = self.root / "var/lib/pam/seen"
        self.state_password = self.root / "var/lib/pam/password"
        self.seen.write_bytes(SEEN)
        for name, default in (("unix", b"yes"), ("pwquality", b"yes"), ("mkhomedir", b"no")):
            (self.root / "usr/share/pam-configs" / name).write_bytes(b"Name: x\nDefault: " + default + b"\n")
        self.state_password.write_bytes(b"stock\n")
        self.pam = self.root / "etc/pam.d/common-password"
        self.auth = self.root / "etc/pam.d/common-auth"
        self.profile = self.root / "usr/share/pam-configs/securelinux-pwhistory"
        self.pam.write_bytes(pam)
        self.auth.write_bytes(AUTH)
        if module:
            mod = self.root / A.MODULE_PATHS[0].lstrip("/")
            mod.parent.mkdir(parents=True)
            mod.write_bytes(b"\x7fELF")
        if profile is not None:
            self.profile.write_bytes(profile)
        for path, data in (("etc/security/pwhistory.conf", conf), ("usr/etc/security/pwhistory.conf", vendor_conf)):
            if data is not None:
                (self.root / path).parent.mkdir(parents=True, exist_ok=True)
                if data == "dir":
                    (self.root / path).mkdir()
                else:
                    (self.root / path).write_bytes(data)

    def state(self):
        return (self.pam.read_bytes(), self.auth.read_bytes(), self.profile.exists(),
                self.seen.read_bytes(), self.state_password.read_bytes())


def execute(t, run=None, dry_run=False, privileged=True):
    return A.execute_control("FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER", "remember", "ge", 5, True,
                             dry_run=dry_run, privilege_check=lambda: privileged, _root=str(t.root),
                             _run=run if run is not None else FakePamAuthUpdate(t))


def check_row(root):
    fn = C._shell_function_for_fixture("C.1", "remember", "ge", 5, str(root))
    out = subprocess.run([BASH, "-c", fn + "\nslp_check_C_1\n"], capture_output=True, text=True).stdout
    return out.strip().split("\t")[2:]


class Contract(unittest.TestCase):
    def test_specs_and_parser_match_check_adapter(self):
        self.assertEqual(A.SPECS, C.SPECS)
        self.assertEqual(A.PARSER, C.PARSER)
        self.assertEqual(A.stack_state(PAM_AFTER), "enabled")
        self.assertEqual(A.stack_state(PAM), "pwquality")
        self.assertEqual(A.stack_state(PAM_CLEAN), "clean")
        self.assertEqual(A.REF_HIST[2], (b"remember=" + str(A.REMEMBER).encode(), b"retry=1", b"use_authtok"))

    def test_control_is_routed(self):
        paths = sorted(CONTROLS.glob("fstec-configuration-2026-1.2-*.yaml"))
        self.assertEqual([p.name for p in paths], ["fstec-configuration-2026-1.2-pwhistory-remember.yaml"])
        text = paths[0].read_text(encoding="utf-8")
        self.assertIn('  kind: "pam-pwhistory-remember"\n  locator: "/etc/pam.d/common-password"\n'
                      '  key: "remember"\nexpected:\n  op: "ge"\n  value: 5\n  type: "integer"\n', text)
        self.assertIn("apply:\n  supported: true\n", text)

    def test_profile_line_is_what_check_accepts(self):
        # pam-auth-update 1.5.3 в песочнице 27.09.2026 записал строку профиля как
        # "password\trequisite\tpam_pwhistory.so remember=5 retry=1 use_authtok" между pam_pwquality и pam_unix.
        line = re.search(rb"Password:\n\t(\S+)\t(.+)\n", A.PROFILE_BYTES)
        self.assertEqual(line.group(1), b"requisite")
        generated = HEAD + PWQ + b"password\trequisite\t" + line.group(2) + b"\n" + UNIX + TAIL
        self.assertEqual(A.stack_state(generated), "enabled")

    @unittest.skipIf(BASH is None, "bash not available")
    def test_check_and_apply_observe_the_same(self):
        cases = [(pam, None, None) for pam in (
            PAM, PAM_AFTER, PAM_CLEAN, HEAD + HIST + UNIX + TAIL, HEAD + PWQ + UNIX + HIST + TAIL,
            PAM_AFTER.replace(b"remember=5", b"REMEMBER=5"), PAM_AFTER.replace(b"remember=5", b"remember=3"),
            PAM_AFTER.replace(b"remember=5", b"remember=12"), PAM_AFTER.replace(b"remember=5 ", b""),
            PAM_AFTER.replace(b" retry=1", b""), PAM_AFTER.replace(b" use_authtok\n", b"\n", 1),
            PAM_AFTER + HIST, PAM_AFTER.replace(b"requisite\t\t\tpam_pwhistory", b"required\tpam_pwhistory"),
            PAM_AFTER.replace(b"requisite\t\t\tpam_pwquality", b"[success=ok default=bad]\tpam_pwquality"),
            HEAD + PWQ + HIST + TAIL, PAM_AFTER + b"@include common-extra\n", PAM_AFTER.replace(HIST, b"#" + HIST),
            PAM_AFTER.replace(b"pam_pwhistory.so", b"/lib/x86_64-linux-gnu/security/pam_pwhistory.so"),
            PAM_AFTER.replace(HIST, b"-" + HIST), PAM_AFTER + b"password\n", PAM_AFTER + b"\x00",
            PAM_AFTER.replace(b"remember=5", b"remember=5 [x]"), PAM_AFTER.replace(b"password", b"PASSWORD"),
            b"password sufficient pam_permit.so\n" + PAM_AFTER, PAM_AFTER + b"session optional pam_x.so\n",
            PAM_AFTER.replace(b"yescrypt", b"sha512"), PAM_AFTER.replace(b"retry=3", b"retry=3 minlen=12"),
            PAM_AFTER + b"password\trequired\tpam_permit.so\n", PAM_AFTER.replace(b"\t", b" "),
            PAM_AFTER.replace(HIST, HIST.rstrip(b"\n") + b" \\\n"),
        )] + [
            (PAM_AFTER, CONF_STOCK, None), (PAM_AFTER, None, CONF_STOCK), (PAM_AFTER, b"remember = 10\n", None),
            (PAM_AFTER, b"  # c\n\t retry=0 # x\n", None), (PAM_AFTER, None, b"enforce_for_root\n"),
            (PAM_AFTER, "dir", None), (PAM, b"remember = 10\n", None), (PAM_CLEAN, None, b"debug\n"),
        ]
        for pam, conf, vendor in cases:
            with self.subTest(pam=pam, conf=conf, vendor=vendor), tempfile.TemporaryDirectory(dir=ROOT) as td:
                t = Tree(td, pam=pam, conf=conf, vendor_conf=vendor)
                row = check_row(t.root)
                try:
                    state = A.observe(str(t.root))
                    active = A.active_conf(str(t.root)) if state == "enabled" else None
                except A._Refused as exc:
                    self.assertEqual(row, ["ERROR", exc.reason, "ERROR"])
                    continue
                if active is not None:
                    self.assertEqual(row, ["ERROR", "pwhistory-conf:active-lines", "ERROR"])
                elif state == "enabled":
                    self.assertEqual(row, ["VALUE", "5", "PASS"])
                else:
                    self.assertEqual(row, ["VALUE", "<module-absent>", "FAIL"])

    @unittest.skipIf(BASH is None, "bash not available")
    def test_only_reference_stacks_are_accepted(self):
        expected = {PAM: ["VALUE", "<module-absent>", "FAIL"], PAM_CLEAN: ["VALUE", "<module-absent>", "FAIL"],
                    PAM_AFTER: ["VALUE", "5", "PASS"],
                    PAM_AFTER.replace(b"remember=5", b"remember=12"): ["ERROR", "pam:unsupported-stack", "ERROR"],
                    HEAD + PWQ + UNIX + HIST + TAIL: ["ERROR", "pam:unsupported-stack", "ERROR"],
                    PAM_AFTER.replace(b"yescrypt", b"sha512"): ["ERROR", "pam:unsupported-stack", "ERROR"]}
        for pam, row in expected.items():
            with self.subTest(pam=pam), tempfile.TemporaryDirectory(dir=ROOT) as td:
                self.assertEqual(check_row(Tree(td, pam=pam, conf=CONF_STOCK).root), row)

    @unittest.skipIf(BASH is None, "bash not available")
    def test_check_is_read_only_and_closed(self):
        src = C.shell_function("C", C.CANONICAL_LOCATOR, "remember", "ge", 5)
        for token in C.MUTATING_TOKENS:
            self.assertNotIn(token, src)
        with self.assertRaises(ValueError):
            C.shell_function("C", C.CANONICAL_LOCATOR, "remember", "ge", 3)
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            t.pam.unlink()
            self.assertEqual(check_row(t.root), ["ERROR", "pam:missing", "ERROR"])


class Apply(unittest.TestCase):
    @unittest.skipIf(BASH is None, "bash not available")
    def test_profile_enables_module_before_unix(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            run = FakePamAuthUpdate(t)
            r = execute(t, run)
            self.assertEqual((r["outcome"], r["policy_current"]), ("APPLIED", "5"))
            self.assertEqual(t.profile.read_bytes(), A.PROFILE_BYTES)
            self.assertEqual(t.profile.stat().st_mode & 0o777, 0o644)
            self.assertEqual(t.pam.read_bytes(), PAM_AFTER)
            self.assertEqual(run.calls, [[A.PAM_AUTH_UPDATE, "--package", "--enable", "securelinux-pwhistory"]])
            self.assertEqual(run.selection, b"unix, securelinux-pwhistory, pwquality, extra")
            self.assertEqual(check_row(t.root), ["VALUE", "5", "PASS"])
            self.assertEqual(execute(t, run)["outcome"], "ALREADY_COMPLIANT")

    def test_existing_identical_profile_is_reused(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, profile=A.PROFILE_BYTES)
            self.assertEqual(execute(t)["outcome"], "APPLIED")
            self.assertEqual(t.profile.read_bytes(), A.PROFILE_BYTES)

    def test_local_modifications_are_compensated(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            before = t.state()
            r = execute(t, FakePamAuthUpdate(t, "local"))
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "pam:auth-update-not-applied"))
            self.assertEqual(t.state(), before)

    def test_failed_or_extra_changes_are_compensated(self):
        for mode, reason in (("fail", "pam:auth-update-failed"), ("extra", "pam:postcheck-failed"),
                             ("broken", "pam:postcheck-failed"), ("noretry", "pam:postcheck-failed")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as td:
                t = Tree(td)
                before = t.state()
                run = FakePamAuthUpdate(t, mode)
                r = execute(t, run)
                self.assertEqual((r["outcome"], r["reason"], r["transaction_commit"]),
                                 ("FAILED_NOT_COMMITTED", reason, "NOT_COMMITTED"))
                self.assertEqual(run.calls[-1], [A.PAM_AUTH_UPDATE, "--package", "--remove", "securelinux-pwhistory"])
                self.assertEqual(t.state(), before)

    def test_failed_remove_is_failed_compensation(self):
        for mode in ("remove-fail", "debconf-stuck"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as td:
                t = Tree(td)
                r = execute(t, FakePamAuthUpdate(t, mode))
                self.assertEqual(r["outcome"], "FAILED_COMPENSATION")

    def test_unseen_default_profile_or_debconf_failure_is_refused(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            (t.root / "usr/share/pam-configs/newprof").write_bytes(b"Name: n\nDefault: yes\n")
            before = t.state()
            run = FakePamAuthUpdate(t)
            r = execute(t, run)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "pam:unseen-default-profiles"))
            self.assertIn("newprof", r["operator_decision"]["action"])
            self.assertEqual((run.calls, t.state()), ([], before))
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            before = t.state()
            run = FakePamAuthUpdate(t, "debconf-fail")
            r = execute(t, run)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "debconf:query-failed"))
            self.assertEqual((run.calls, t.state()), ([], before))

    def test_failed_restore_is_failed_compensation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            saved = A._restore

            def refuse(path, raw, root):
                raise OSError("disk")
            A._restore = refuse
            try:
                r = execute(t, FakePamAuthUpdate(t, "extra"))
            finally:
                A._restore = saved
            self.assertEqual(r["outcome"], "FAILED_COMPENSATION")

    def test_foreign_stack_profile_or_conf_needs_admin(self):
        for kwargs, reason in (
            ({"pam": PAM_AFTER.replace(b"remember=5", b"remember=3")}, "pam:unsupported-stack"),
            ({"pam": HEAD + PWQ + UNIX + HIST + TAIL}, "pam:unsupported-stack"),
            ({"pam": PAM_AFTER.replace(b" retry=1", b"")}, "pam:unsupported-stack"),
            ({"pam": PAM + b"@include x\n"}, "pam:include-unsupported"),
            ({"pam": b"password sufficient pam_permit.so\n" + PAM}, "pam:unsupported-stack"),
            ({"pam": PAM_CLEAN}, "pam:pwquality-not-enabled"),
            ({"profile": b"Name: other\n"}, "pam:profile-conflict"),
            ({"conf": b"remember = 10\n"}, "pwhistory-conf:active-lines"),
            ({"vendor_conf": b"retry=0\n"}, "pwhistory-conf:active-lines"),
            ({"pam": PAM_AFTER, "conf": b"enforce_for_root\n"}, "pwhistory-conf:active-lines"),
        ):
            with self.subTest(reason=reason, kwargs=kwargs), tempfile.TemporaryDirectory(dir=ROOT) as td:
                t = Tree(td, **kwargs)
                before = t.state()
                run = FakePamAuthUpdate(t)
                r = execute(t, run)
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", reason))
                self.assertEqual(r["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
                self.assertEqual((run.calls, t.state()), ([], before))

    def test_stock_conf_is_accepted(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, conf=CONF_STOCK)
            self.assertEqual(execute(t)["outcome"], "APPLIED")

    def test_missing_module_or_invalid_conf_is_refused(self):
        for kwargs, reason in (({"module": False}, "pam:module-missing"),
                               ({"conf": "dir"}, "pwhistory-conf:invalid-type")):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory(dir=ROOT) as td:
                t = Tree(td, **kwargs)
                before = t.state()
                run = FakePamAuthUpdate(t)
                r = execute(t, run)
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", reason))
                self.assertEqual((run.calls, t.state()), ([], before))

    def test_dry_run_and_privilege_do_not_change(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            before = t.state()
            run = FakePamAuthUpdate(t)
            r = execute(t, run, dry_run=True)
            self.assertEqual((r["outcome"], r["policy_current"]), ("DRY_RUN_WOULD_APPLY", "<module-absent>"))
            r = execute(t, run, privileged=False)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
            self.assertEqual((run.calls, t.state()), ([], before))

    def test_unsupported_inputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            for key, op, value in (("remember", "ge", 3), ("remember", "eq", 5), ("retry", "ge", 5)):
                r = A.execute_control("C", key, op, value, True, dry_run=False, _root=str(t.root),
                                      _run=FakePamAuthUpdate(t))
                self.assertEqual((r["outcome"], r["reason"]), ("NOT_ELIGIBLE_APPLY_UNSUPPORTED", "op-unsupported"))
            with self.assertRaises(ValueError):
                A.execute_control("C", "remember", "ge", "5", True, dry_run=False, _root=str(t.root))

    def test_report_fields(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            rep = A.control_result_to_report(execute(t), "s", "f")
            self.assertEqual((rep["outcome"], rep["policy_current"], rep["step_rc"], rep["target"]),
                             ("APPLIED", "5", "0", "/etc/pam.d/common-password"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
