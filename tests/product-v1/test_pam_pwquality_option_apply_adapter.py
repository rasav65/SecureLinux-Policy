#!/usr/bin/env python3
"""Regressions for the pam-pwquality-option-v1 APPLY mechanism (fstec-configuration-2026 п.1.1).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Каждый случай работает на дереве во временном каталоге внутри репозитория (`_root`); dpkg-query и
apt-get подменяются (`_run`), установка пакета моделируется записью файлов профиля PAM и
pwquality.conf в это дерево. Решение пользователя 26.09.2026: minlen не менее 12,
ucredit/lcredit/dcredit/ocredit = -1, retry = 3; пакет libpam-pwquality ставится. Решение
пользователя 27.09.2026 (как у донора): до libpam-pwquality ставятся cracklib-runtime и wamerican,
словарь cracklib строится и проверяется; модуль включён без словаря — CHECK FAIL.
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
ADAPTER = ROOT / "product/apply-adapters/product-pam-pwquality-option-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-pam-pwquality-option-check-v1.py"
CONTROLS = ROOT / "controls/fstec-core/configuration-2026"
BASH = shutil.which("bash")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = load(ADAPTER, "slp_pwquality_apply")
C = load(CHECK_ADAPTER, "slp_pwquality_check")

PAM_BEFORE = (
    b"# /etc/pam.d/common-password - password-related modules common to all services\n"
    b"password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n"
    b"password\trequisite\t\t\tpam_deny.so\n"
    b"password\trequired\t\t\tpam_permit.so\n"
)
PAM_AFTER = (
    b"# /etc/pam.d/common-password - password-related modules common to all services\n"
    b"password\trequisite\t\t\tpam_pwquality.so retry=3\n"
    b"password\t[success=1 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass yescrypt\n"
    b"password\trequisite\t\t\tpam_deny.so\n"
    b"password\trequired\t\t\tpam_permit.so\n"
)
CONF_STOCK = (
    b"# Configuration for systemwide password quality limits\n"
    b"# difok = 1\n"
    b"# minlen = 8\n"
    b"# dcredit = 0\n"
    b"# ucredit = 0\n"
    b"# lcredit = 0\n"
    b"# ocredit = 0\n"
    b"# retry = 1\n"
    b"# enforce_for_root\n"
)


class Proc:
    def __init__(self, returncode, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeHost:
    """dpkg-query/apt-get/update-cracklib/cracklib-check: установка пишет профиль PAM и
    pwquality.conf, update-cracklib — файлы словаря в дерево."""

    def __init__(self, tree, installed=False, install_ok=True, install_after_update=False,
                 dict_install_ok=True, update_ok=True, dict_build=True, probe_ok=True):
        self.tree = tree
        self.pkgs = {A.PACKAGE} if installed else set()
        self.install_ok = install_ok
        self.install_after_update = install_after_update
        self.dict_install_ok = dict_install_ok
        self.update_ok = update_ok
        self.dict_build = dict_build
        self.probe_ok = probe_ok
        self.updated = False
        self.calls = []

    def __call__(self, argv, timeout, data=None):
        self.calls.append(argv)
        if argv[0] == A.DPKG_QUERY:
            return Proc(0, b"install ok installed") if argv[-1] in self.pkgs else Proc(1, b"")
        if argv[0] == A.APT_GET and argv[-1] == "update":
            self.updated = True
            return Proc(0)
        if argv[0] == A.APT_GET and argv[-3:] == ["install", *A.DICT_PACKAGES]:
            if self.dict_install_ok:
                self.pkgs.update(A.DICT_PACKAGES)
                return Proc(0)
            return Proc(100)
        if argv[0] == A.APT_GET and argv[-2:] == ["install", A.PACKAGE]:
            if self.install_ok or (self.install_after_update and self.updated):
                self.pkgs.add(A.PACKAGE)
                self.tree.pam.write_bytes(PAM_AFTER)
                if not self.tree.conf.exists():
                    self.tree.conf.write_bytes(CONF_STOCK)
                    self.tree.conf.chmod(0o644)
                return Proc(0)
            return Proc(100)
        if argv == [A.UPDATE_CRACKLIB]:
            if not self.update_ok or "cracklib-runtime" not in self.pkgs:
                return Proc(1)
            if self.dict_build:
                self.tree.dictionary()
            return Proc(0)
        if argv == [A.CRACKLIB_CHECK]:
            self.probe = data
            if self.probe_ok and (self.tree.root / DICT_PWD).exists():
                return Proc(0, data.rstrip(b"\n") + b": OK\n")
            return Proc(0, b"", b"/var/cache/cracklib/cracklib_dict.pwd: No such file or directory\n")
        raise AssertionError(argv)


DICT_PWD = "var/cache/cracklib/cracklib_dict.pwd"


class Tree:
    def __init__(self, td, pam=PAM_AFTER, conf=CONF_STOCK, confd=None, mode=0o644, dictionary=True):
        self.root = Path(td)
        (self.root / "etc/pam.d").mkdir(parents=True)
        (self.root / "etc/security").mkdir(parents=True)
        self.pam = self.root / "etc/pam.d/common-password"
        self.conf = self.root / "etc/security/pwquality.conf"
        self.pam.write_bytes(pam)
        if dictionary:
            self.dictionary()
        if conf is not None:
            self.conf.write_bytes(conf)
            self.conf.chmod(mode)
        if confd is not None:
            (self.root / "etc/security/pwquality.conf.d").mkdir()
            for name, data in confd.items():
                (self.root / "etc/security/pwquality.conf.d" / name).write_bytes(data)

    def dictionary(self):
        base = self.root / "var/cache/cracklib"
        base.mkdir(parents=True, exist_ok=True)
        for suffix in (".pwd", ".pwi", ".hwm"):
            (base / ("cracklib_dict" + suffix)).write_bytes(b"x")


def execute(t, key, host=None, dry_run=False, privileged=True, write=None):
    op, expected = A.SPECS[key]
    return A.execute_control("FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-" + key.upper(), key, op, expected, True,
                             dry_run=dry_run, privilege_check=lambda: privileged, _root=str(t.root),
                             _run=host if host is not None else FakeHost(t, installed=True), _write_file=write)


def check_row(root, key):
    op, expected = C.SPECS[key]
    fn = C._shell_function_for_fixture("C.1", key, op, expected, str(root))
    out = subprocess.run([BASH, "-c", fn + "\nslp_check_C_1\n"], capture_output=True, text=True).stdout
    return out.strip().split("\t")[2:]


class Contract(unittest.TestCase):
    def test_specs_and_parser_match_check_adapter(self):
        self.assertEqual(A.SPECS, C.SPECS)
        self.assertEqual(A.PARSER, C.PARSER)
        self.assertEqual(set(A.WRITE), set(A.SPECS))
        self.assertIs(A.INSTALLS_PACKAGES, True)
        for key, value in A.WRITE.items():
            self.assertTrue(A.compliant(*A.SPECS[key], value), key)

    def test_controls_are_routed(self):
        seen = {}
        for path in sorted(CONTROLS.glob("fstec-configuration-2026-1.1-pwquality-*.yaml")):
            text = path.read_text(encoding="utf-8")
            self.assertIn('  kind: "pam-pwquality-option"\n  locator: "' + C.CANONICAL_LOCATOR + '"\n', text)
            self.assertIn("apply:\n  supported: true\n", text)
            key = re.search(r'^  key: "([a-z]+)"$', text, re.M).group(1)
            op = re.search(r'^  op: "([a-z]+)"$', text, re.M).group(1)
            value = int(re.search(r"^  value: (-?[0-9]+)$", text, re.M).group(1))
            seen[key] = (op, value)
        self.assertEqual(seen, A.SPECS)

    def test_unsupported_inputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            for key, op, value in (("minlen", "ge", 8), ("minlen", "eq", 12), ("minclass", "ge", 4)):
                r = A.execute_control("C", key, op, value, True, dry_run=False, _root=str(t.root),
                                      _run=FakeHost(t, installed=True))
                self.assertEqual((r["outcome"], r["reason"]), ("NOT_ELIGIBLE_APPLY_UNSUPPORTED", "op-unsupported"))
            with self.assertRaises(ValueError):
                A.execute_control("C", "minlen", "ge", "12", True, dry_run=False, _root=str(t.root))
            self.assertEqual(t.conf.read_bytes(), CONF_STOCK)

    @unittest.skipIf(BASH is None, "bash not available")
    def test_check_and_apply_observe_the_same(self):
        cases = (
            (PAM_BEFORE, CONF_STOCK, None),
            (PAM_AFTER, CONF_STOCK, None),
            (PAM_AFTER, b"minlen = 12\nucredit=-1\nlcredit -1\n", None),
            (PAM_AFTER, b"MINLEN=14 # c\nminlen = 3\n", None),
            (PAM_AFTER, b"minlen = 12\n", {"50-a.conf": b"minlen = 20\ndcredit = -2\n", "x.conf.bak": b"bad\n"}),
            (PAM_AFTER, b"minlen = 12 13\n", None),
            (PAM_AFTER, b"unknownsetting = 1\n", None),
            (PAM_AFTER, b"minlen = 0x10\n", None),
            (PAM_AFTER, b"minlen = +12\nretry = 0\n", None),
            (PAM_AFTER, b"dictpath = /x y\nenforce_for_root\nminlen=12\n", None),
            (PAM_AFTER, b"a" * 1100 + b"\n", None),
            (PAM_AFTER, b"minlen = 12\x00\n", None),
            (PAM_AFTER, None, None),
            (PAM_AFTER.replace(b"retry=3", b"retry=3 minlen=9 ucredit=-1"), b"minlen = 12\n", None),
            (PAM_AFTER.replace(b"retry=3", b"minlen"), CONF_STOCK, None),
            (PAM_AFTER + b"password requisite pam_pwquality.so\n", CONF_STOCK, None),
            (PAM_AFTER.replace(b"requisite\t\t\tpam_pwquality", b"[default=die]\tpam_pwquality"), CONF_STOCK, None),
            (PAM_AFTER + b"@include common-extra\n", CONF_STOCK, None),
            (PAM_AFTER.replace(b"pam_pwquality.so", b"/lib/x86_64-linux-gnu/security/pam_pwquality.so"),
             b"minlen=12\n", None),
            (b"#password requisite pam_pwquality.so retry=3\n" + PAM_BEFORE, CONF_STOCK, None),
        )
        cases = tuple(case + ("full",) for case in cases) + (
            (PAM_AFTER, CONF_STOCK, None, None),
            (PAM_BEFORE, CONF_STOCK, None, None),
            (PAM_AFTER, b"minlen = 12\ndictcheck = 0\n", None, None),
            (PAM_AFTER, b"minlen = 12\ndictcheck = 1\n", None, None),
            (PAM_AFTER.replace(b"retry=3", b"retry=3 dictcheck=0"), b"minlen = 12\n", None, None),
            (PAM_AFTER.replace(b"retry=3", b"retry=3 dictcheck=0"), b"minlen = 12\n", None, "empty"),
            (PAM_AFTER, b"minlen = 12\n", None, "empty"),
            (PAM_AFTER, b"minlen = 12\n", None, "link"),
            (PAM_AFTER, b"minlen = 12\n", None, "dir"),
            (PAM_AFTER.replace(b"retry=3", b"retry=3 dictpath=/x"), b"minlen = 12\n", None, "full"),
            (PAM_AFTER, b"minlen = 12\ndictpath =\n", None, "full"),
        )
        for pam, conf, confd, dictionary in cases:
            with tempfile.TemporaryDirectory(dir=ROOT) as td:
                t = Tree(td, pam=pam, conf=conf, confd=confd, dictionary=dictionary is not None)
                pwd = t.root / DICT_PWD
                if dictionary == "empty":
                    pwd.write_bytes(b"")
                elif dictionary == "link":
                    pwd.unlink()
                    pwd.symlink_to("cracklib_dict.pwi")
                elif dictionary == "dir":
                    pwd.unlink()
                    pwd.mkdir()
                for key, (op, expected) in C.SPECS.items():
                    with self.subTest(pam=pam[-40:], conf=conf, confd=confd, dictionary=dictionary, key=key):
                        row = check_row(t.root, key)
                        try:
                            args, settings, _raw, _st = A.observe(str(t.root))
                            value = None if args is None else A.observed(key, op, expected, args, settings,
                                                                          str(t.root))
                        except (A._Refused, A.ParseError) as exc:
                            self.assertEqual(row, ["ERROR", exc.reason, "ERROR"])
                            continue
                        if value is None:
                            self.assertEqual(row, ["VALUE", "<module-absent>", "FAIL"])
                        else:
                            self.assertEqual(row, ["VALUE", value[0], "PASS" if value[1] else "FAIL"])

    @unittest.skipIf(BASH is None, "bash not available")
    def test_check_is_read_only_and_closed(self):
        for key, (op, expected) in C.SPECS.items():
            src = C.shell_function("C", C.CANONICAL_LOCATOR, key, op, expected)
            for token in C.MUTATING_TOKENS:
                self.assertNotIn(token, src)
        with self.assertRaises(ValueError):
            C.shell_function("C", C.CANONICAL_LOCATOR, "minlen", "ge", 15)
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            t.pam.unlink()
            self.assertEqual(check_row(t.root, "minlen"), ["ERROR", "pam:missing", "ERROR"])


class Dictionary(unittest.TestCase):
    @unittest.skipIf(BASH is None, "bash not available")
    def test_check_fails_without_dictionary(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, conf=b"minlen = 12\nucredit = -1\n", dictionary=False)
            for key in C.SPECS:
                self.assertEqual(check_row(t.root, key), ["VALUE", "<cracklib-dictionary-missing>", "FAIL"], key)
            t.conf.write_bytes(b"minlen = 12\nucredit = -1\ndictcheck = 0\n")
            self.assertEqual(check_row(t.root, "minlen"), ["VALUE", "12", "PASS"])
            self.assertEqual(check_row(t.root, "retry"), ["VALUE", "3", "PASS"])
            t.conf.write_bytes(b"minlen = 12\ndictpath = /usr/share/dict/x\n")
            self.assertEqual(check_row(t.root, "minlen"), ["ERROR", "pwquality:dictpath-unsupported", "ERROR"])

    def test_install_builds_dictionary_before_pam(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, pam=PAM_BEFORE, conf=None, dictionary=False)
            host = FakeHost(t)
            r = execute(t, "retry", host)
            self.assertEqual((r["outcome"], r["policy_current"]), ("APPLIED", "3"))
            self.assertEqual(r["actions_attempted"][-2:], ["PHASE0_CRACKLIB_DICTIONARY", "PHASE0_INSTALL_PACKAGE"])
            installs = [c[c.index("install") + 1:] for c in host.calls if c[0] == A.APT_GET and "install" in c]
            self.assertEqual(installs, [list(A.DICT_PACKAGES), [A.PACKAGE]])
            self.assertIn("--no-install-recommends", host.calls[1])
            order = [c[0] for c in host.calls]
            self.assertLess(order.index(A.UPDATE_CRACKLIB), order.index(A.CRACKLIB_CHECK))
            self.assertLess(order.index(A.CRACKLIB_CHECK),
                            next(i for i, c in enumerate(host.calls) if c[-1] == A.PACKAGE and "install" in c))
            self.assertEqual(host.probe, A.PROBE_WORD + b"\n")
            self.assertTrue((t.root / DICT_PWD).exists())

    def test_dictionary_failures_leave_pam_unchanged(self):
        for kwargs, reason in (({"dict_install_ok": False}, "cracklib:install-failed"),
                               ({"update_ok": False}, "cracklib:update-failed"),
                               ({"dict_build": False}, "cracklib:dictionary-missing"),
                               ({"probe_ok": False}, "cracklib:probe-failed")):
            with tempfile.TemporaryDirectory(dir=ROOT) as td:
                t = Tree(td, pam=PAM_BEFORE, conf=None, dictionary=False)
                host = FakeHost(t, **kwargs)
                r = execute(t, "minlen", host)
                self.assertEqual((r["outcome"], r["reason"], r["transaction_commit"]),
                                 ("FAILED_NOT_COMMITTED", reason, "NOT_COMMITTED"), kwargs)
                self.assertNotIn("PHASE0_INSTALL_PACKAGE", r["actions_attempted"])
                self.assertFalse(any(c[-1] == A.PACKAGE and "install" in c for c in host.calls))
                self.assertEqual(t.pam.read_bytes(), PAM_BEFORE)
                self.assertFalse(t.conf.exists())

    def test_enabled_module_without_dictionary_needs_admin(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, conf=b"minlen = 12\n", dictionary=False)
            host = FakeHost(t, installed=True)
            for key in ("minlen", "ucredit"):
                r = execute(t, key, host)
                self.assertEqual((r["outcome"], r["reason"], r["policy_current"]),
                                 ("ABORTED_PRECONDITION_CONFLICT", "cracklib:dictionary-missing",
                                  "<cracklib-dictionary-missing>"))
                self.assertIn("cracklib-runtime", r["operator_decision"]["action"])
                self.assertFalse(r["mutation_performed"])
            self.assertEqual([c for c in host.calls if c[0] != A.DPKG_QUERY], [])
            self.assertEqual(t.conf.read_bytes(), b"minlen = 12\n")
            t.conf.write_bytes(b"minlen = 12\ndictcheck = 0\n")
            self.assertEqual(execute(t, "minlen", host)["outcome"], "ALREADY_COMPLIANT")
            self.assertEqual(execute(t, "ucredit", host)["outcome"], "APPLIED")

    def test_dictionary_lost_after_install_is_not_committed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, pam=PAM_BEFORE, conf=None, dictionary=False)
            host = FakeHost(t)
            real = host.__call__

            def lose(argv, timeout, data=None):
                cp = real(argv, timeout, data)
                if argv[-1] == A.PACKAGE and "install" in argv:
                    (t.root / DICT_PWD).unlink()
                return cp
            r = execute(t, "minlen", lose)
            self.assertEqual((r["outcome"], r["reason"]),
                             ("FAILED_NOT_COMMITTED", "cracklib:dictionary-missing-after-install"))


class Apply(unittest.TestCase):
    def test_install_enables_module_then_conf(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, pam=PAM_BEFORE, conf=None, dictionary=False)
            host = FakeHost(t)
            r = execute(t, "retry", host)
            self.assertEqual((r["outcome"], r["policy_current"]), ("APPLIED", "3"))
            self.assertIn("PHASE0_INSTALL_PACKAGE", r["actions_attempted"])
            self.assertTrue(r["mutation_performed"])
            self.assertEqual(t.conf.read_bytes(), CONF_STOCK)
            r = execute(t, "minlen", host)
            self.assertEqual((r["outcome"], r["policy_current"]), ("APPLIED", "12"))
            self.assertIn(b"\nminlen = 12\n", t.conf.read_bytes())
            self.assertNotIn(b"# minlen = 8", t.conf.read_bytes())
            self.assertEqual(sum(1 for c in host.calls if c[-1] == A.PACKAGE and c[-2] == "install"), 1)
            for key in ("ucredit", "lcredit", "dcredit", "ocredit"):
                self.assertEqual(execute(t, key, host)["outcome"], "APPLIED")
            for key in A.SPECS:
                self.assertEqual(check_row(t.root, key)[2], "PASS", key)
                self.assertEqual(execute(t, key, host)["outcome"], "ALREADY_COMPLIANT")

    def test_install_on_fresh_tree_writes_conf_after_install(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, pam=PAM_BEFORE, conf=None)
            r = execute(t, "minlen", FakeHost(t))
            self.assertEqual((r["outcome"], r["policy_current"]), ("APPLIED", "12"))
            self.assertEqual(r["transaction_commit"], "COMMITTED")

    def test_install_retries_after_update_and_reports_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, pam=PAM_BEFORE, conf=None)
            host = FakeHost(t, install_ok=False, install_after_update=True)
            self.assertEqual(execute(t, "retry", host)["outcome"], "APPLIED")
            self.assertTrue(host.updated)
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, pam=PAM_BEFORE, conf=None)
            r = execute(t, "minlen", FakeHost(t, install_ok=False))
            self.assertEqual((r["outcome"], r["reason"], r["transaction_commit"]),
                             ("FAILED_NOT_COMMITTED", "pkg:install-failed", "NOT_COMMITTED"))
            self.assertEqual(t.pam.read_bytes(), PAM_BEFORE)

    def test_installed_but_disabled_needs_admin(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, pam=PAM_BEFORE)
            host = FakeHost(t, installed=True)
            r = execute(t, "minlen", host)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "pam:module-disabled"))
            self.assertEqual(r["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
            self.assertFalse(r["mutation_performed"])
            self.assertFalse(any(c[0] == A.APT_GET for c in host.calls))

    def test_argument_override_needs_admin(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, pam=PAM_AFTER.replace(b"retry=3", b"retry=3 minlen=9"))
            r = execute(t, "minlen")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "pam:argument-overrides"))
            self.assertIn("minlen", r["operator_decision"]["action"])
            self.assertEqual(t.conf.read_bytes(), CONF_STOCK)

    def test_active_lines_changed_in_place_and_appended(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, conf=b"minlen=8 # old\nMinLen\t9\n")
            self.assertEqual(execute(t, "minlen")["outcome"], "APPLIED")
            self.assertEqual(t.conf.read_bytes(), b"minlen=12 # old\nMinLen\t12\n")
            self.assertEqual(execute(t, "ucredit")["outcome"], "APPLIED")
            self.assertEqual(t.conf.read_bytes(), b"minlen=12 # old\nMinLen\t12\nucredit = -1\n")

    def test_main_conf_overrides_conf_d(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, confd={"10-site.conf": b"minlen = 8\n"})
            self.assertEqual(execute(t, "minlen")["outcome"], "APPLIED")
            self.assertEqual(check_row(t.root, "minlen"), ["VALUE", "12", "PASS"])
            self.assertEqual((t.root / "etc/security/pwquality.conf.d/10-site.conf").read_bytes(), b"minlen = 8\n")

    def test_stricter_minlen_is_compliant(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, conf=b"minlen = 16\n")
            self.assertEqual(execute(t, "minlen")["outcome"], "ALREADY_COMPLIANT")

    def test_untrusted_conf_is_refused_before_install(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, pam=PAM_BEFORE, conf=b"minlen = 8\n", mode=0o666)
            host = FakeHost(t)
            r = execute(t, "minlen", host)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "pwquality:untrusted"))
            self.assertFalse(r["mutation_performed"])
            self.assertFalse(any(c[0] == A.APT_GET for c in host.calls))
            self.assertEqual((t.pam.read_bytes(), t.conf.read_bytes()), (PAM_BEFORE, b"minlen = 8\n"))

    def test_untrusted_or_invalid_conf_is_refused(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, mode=0o666)
            r = execute(t, "minlen")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "pwquality:untrusted"))
            self.assertEqual(t.conf.read_bytes(), CONF_STOCK)
        for conf, reason in ((b"bogus = 1\n", "pwquality:unknown-setting"),
                             (b"minlen = ten\n", "pwquality:invalid-integer")):
            with tempfile.TemporaryDirectory(dir=ROOT) as td:
                t = Tree(td, conf=conf)
                r = execute(t, "minlen")
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", reason))
                self.assertEqual(t.conf.read_bytes(), conf)

    def test_dry_run_and_privilege_do_not_change(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td, pam=PAM_BEFORE, conf=None)
            host = FakeHost(t)
            r = execute(t, "minlen", host, dry_run=True)
            self.assertEqual((r["outcome"], r["policy_current"]), ("DRY_RUN_WOULD_APPLY", "<module-absent>"))
            r = execute(t, "minlen", host, privileged=False)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
            self.assertFalse(any(c[0] == A.APT_GET for c in host.calls))
            self.assertEqual(t.pam.read_bytes(), PAM_BEFORE)

    def test_write_failure_is_not_committed(self):
        def fail(path, raw, st):
            raise OSError("disk")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            r = execute(t, "minlen", write=fail)
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "pwquality:write-failed"))
            self.assertEqual(t.conf.read_bytes(), CONF_STOCK)

    def test_postcheck_failure_restores_bytes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)

            def wrong(path, raw, st):
                A._write(path, raw.replace(b"minlen = 12", b"minlen = 7"), st)
            r = execute(t, "minlen", write=wrong)
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "pwquality:postcheck-failed"))
            self.assertEqual(t.conf.read_bytes(), CONF_STOCK)

    def test_failed_restore_is_failed_compensation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            calls = []

            def once(path, raw, st):
                calls.append(raw)
                if len(calls) == 1:
                    A._write(path, raw.replace(b"minlen = 12", b"minlen = 7"), st)
                else:
                    raise OSError("disk")
            r = execute(t, "minlen", write=once)
            self.assertEqual((r["outcome"], r["transaction_commit"]), ("FAILED_COMPENSATION", "NOT_COMMITTED"))

    def test_report_fields(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            t = Tree(td)
            r = execute(t, "ocredit")
            rep = A.control_result_to_report(r, "s", "f")
            self.assertEqual(rep["outcome"], "APPLIED")
            self.assertEqual(rep["policy_current"], "-1")
            self.assertEqual(rep["step_rc"], "0")
            self.assertEqual(rep["target"], "/etc/security/pwquality.conf")


if __name__ == "__main__":
    unittest.main(verbosity=2)
