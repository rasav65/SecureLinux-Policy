#!/usr/bin/env python3
"""Regressions for SRC-0055 existing-account password aging: CHECK local-account-password-aging,
CHECK local-account-password-age and APPLY local-account-password-aging-v1 (карта разбиения сроков
паролей v6, решения пользователя 01.10–02.10.2026).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Каждый случай работает на дереве во временном каталоге внутри репозитория (`_root`: `etc/passwd`,
`etc/shadow`); блокировка lckpwdf заменена парой функций, файл блокировки /etc/shadow.lock —
настоящий файл во временном корне. Файлы принадлежат текущему пользователю — адаптеры при заданном
корне принимают его вместо root.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
APPLY = ROOT / "product/apply-adapters/product-local-account-password-aging-apply-v1.py"
CHECK_AGING = ROOT / "product/adapters/product-local-account-password-aging-check-v1.py"
CHECK_AGE = ROOT / "product/adapters/product-local-account-password-age-check-v1.py"
CHECK_EMPTY = ROOT / "product/adapters/product-local-account-password-state-check-v2.py"
CONTROLS = ROOT / "controls/fstec-core/configuration-2026"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = load(APPLY, "slp_pw_aging_apply")
CA = load(CHECK_AGING, "slp_pw_aging_check")
CG = load(CHECK_AGE, "slp_pw_age_check")
CE = load(CHECK_EMPTY, "slp_pw_state_check_v2")

D = 20728  # «сегодня» в тестах APPLY (2026-10-02)

PASSWD = (b"root:x:0:0:root:/root:/bin/bash\n"
          b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
          b"user:x:1000:1000:user:/home/user:/bin/bash\n"
          b"old:x:1001:1001::/home/old:/bin/bash\n")


def shadow(**records):
    """Строки /etc/shadow; по умолчанию root — `*`, daemon — `*`."""
    base = {"root": "root:*:19000:0:99999:7:::", "daemon": "daemon:*:19000:0:99999:7:::"}
    base.update(records)
    order = ["root", "daemon", "user", "old"] + [k for k in records if k not in ("root", "daemon", "user", "old")]
    return ("\n".join(base[k] for k in order if k in base) + "\n").encode()


LONG = "9" * 5000  # длиннее лимита int() для строки (4300 цифр)


def rec(name, lastchg, mn="0", mx="99999", warn="7", inactive="", expire="", pw="$y$j9T$a$b"):
    return "%s:%s:%s:%s:%s:%s:%s:%s:" % (name, pw, lastchg, mn, mx, warn, inactive, expire)


class Host:
    def __init__(self, td, passwd=PASSWD, shadow_bytes=None):
        self.root = Path(td)
        self.etc = self.root / "etc"
        self.etc.mkdir()
        os.chmod(self.etc, 0o755)
        self.passwd = self.etc / "passwd"
        self.shadow = self.etc / "shadow"
        self.passwd.write_bytes(passwd)
        os.chmod(self.passwd, 0o644)
        self.shadow.write_bytes(shadow_bytes if shadow_bytes is not None else
                                shadow(user=rec("user", D - 30), old=rec("old", 18262)))
        os.chmod(self.shadow, 0o640)
        self.lock_calls = []
        self.lock_ok = True
        self.unlock_ok = True

    def locks(self):
        def lock():
            self.lock_calls.append("lock")
            return self.lock_ok

        def unlock():
            self.lock_calls.append("unlock")
            return self.unlock_ok
        return lock, unlock

    def fields(self, name):
        for line in self.shadow.read_text().split("\n"):
            parts = line.split(":")
            if parts[0] == name:
                return parts
        return None

    def execute(self, dry_run=False, privileged=True, key="aging-fields", op="eq", expected="1/90/7", pid=None):
        return A.execute_control("FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING", key, op, expected, True,
                                 dry_run=dry_run, privilege_check=lambda: privileged, _root=str(self.root),
                                 _locks=self.locks(), _pid=pid if pid is not None else os.getpid())

    def check(self, module):
        src = module._shell_function_for_fixture("CTRL", str(self.passwd), str(self.shadow))
        cp = subprocess.run(["/bin/bash", "-c", src + "\nslp_check_CTRL\n"], stdout=subprocess.PIPE, check=True,
                            timeout=60)
        f = cp.stdout.decode().rstrip("\n").split("\t")
        return f[2], f[3], f[4]

    def check_state(self):
        src = CE._shell_function_for_paths("CTRL", str(self.passwd), str(self.shadow), "password-field",
                                           "all-nonempty", True)
        cp = subprocess.run(["/bin/bash", "-c", src + "\nslp_check_CTRL\n"], stdout=subprocess.PIPE, check=True,
                            timeout=60)
        return cp.stdout.decode().rstrip("\n").split("\t")[2:4]


class Today:
    """Подмена «сегодня» APPLY."""

    def __init__(self, day=D):
        self.day = day

    def __enter__(self):
        self.saved = A._today
        A._today = lambda: self.day

    def __exit__(self, *exc):
        A._today = self.saved


class Shared(unittest.TestCase):
    def test_parser_text_is_shared(self):
        self.assertEqual(A.PARSER, CA.PARSER)
        self.assertEqual(A.PARSER, CG.PARSER)

    def test_controls_are_routed(self):
        aging = (CONTROLS / "fstec-configuration-2026-1.1-existing-password-aging.yaml").read_text(encoding="utf-8")
        age = (CONTROLS / "fstec-configuration-2026-1.1-existing-password-age.yaml").read_text(encoding="utf-8")
        self.assertIn('  kind: "local-account-password-aging"\n  locator: "/etc/shadow"\n  key: "aging-fields"\n', aging)
        self.assertIn('  op: "eq"\n  value: "1/90/7"\n  type: "string"\napply:\n  supported: true\n', aging)
        self.assertIn('  kind: "local-account-password-age"\n  locator: "/etc/shadow"\n  key: "age-days"\n', age)
        self.assertIn('  op: "le"\n  value: 90\n  type: "integer"\napply:\n  supported: false\n', age)

    def test_checks_are_read_only(self):
        for mod in (CA, CG):
            mod._selftest()


class CheckAging(unittest.TestCase):
    def test_values(self):
        cases = (
            (rec("user", D, "1", "90", "7"), ("VALUE", "accounts=1;mismatched=0", "PASS")),
            (rec("user", D, "01", "090", "07"), ("VALUE", "accounts=1;mismatched=0", "PASS")),
            (rec("user", D, "1", "", "7"), ("VALUE", "accounts=1;mismatched=1", "FAIL")),
            (rec("user", D, "1", "99999", "7"), ("VALUE", "accounts=1;mismatched=1", "FAIL")),
            (rec("user", D, "0", "90", "7"), ("VALUE", "accounts=1;mismatched=1", "FAIL")),
            (rec("user", D, "1", "90", "14"), ("VALUE", "accounts=1;mismatched=1", "FAIL")),
            (rec("user", D, pw="!$y$a$b"), ("VALUE", "accounts=0;mismatched=0", "PASS")),
            (rec("user", D, pw="*"), ("VALUE", "accounts=0;mismatched=0", "PASS")),
            (rec("user", D, pw=""), ("VALUE", "accounts=0;mismatched=0", "PASS")),
            (rec("user", D, pw="!"), ("VALUE", "accounts=0;mismatched=0", "PASS")),
            (rec("user", "x1"), ("ERROR", "shadow:invalid-number", "ERROR")),
            (rec("user", D, "1", LONG, "7"), ("VALUE", "accounts=1;mismatched=1", "FAIL")),
            (rec("user", LONG, "1", "90", "7", LONG, LONG), ("VALUE", "accounts=1;mismatched=0", "PASS")),
            (rec("user", D, "0" * 5000 + "1", "90", "7"), ("VALUE", "accounts=1;mismatched=0", "PASS")),
        )
        for line, expected in cases:
            with self.subTest(line=line), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td, passwd=PASSWD.replace(b"old:x:1001:1001::/home/old:/bin/bash\n", b""),
                            shadow_bytes=shadow(user=line))
                self.assertEqual(host.check(CA), expected)

    def test_preconditions(self):
        cases = (
            (lambda h: os.chmod(h.shadow, 0o660), "shadow:untrusted"),
            (lambda h: os.link(h.shadow, h.etc / "shadow-copy"), "shadow:hardlinked"),
            (lambda h: (h.passwd.unlink(), os.symlink("/dev/null", h.passwd)), "passwd:invalid-type"),
            (lambda h: os.chmod(h.etc, 0o777), "etc:untrusted"),
        )
        for prepare, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td)
                prepare(host)
                self.assertEqual(host.check(CA), ("ERROR", reason, "ERROR"))
                self.assertEqual(host.check(CG), ("ERROR", reason, "ERROR"))
                with Today():
                    res = host.execute()
                self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_CONFLICT", reason))
                self.assertFalse(res["mutation_performed"])


    def test_foreign_owner(self):
        """Владелец не root (и не текущий пользователь фикстуры) — ERROR и решение администратора."""
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            if os.geteuid() == 0:
                os.chown(host.shadow, 65534, -1)
                self.assertEqual(host.check(CA), ("ERROR", "shadow:untrusted", "ERROR"))
                self.assertEqual(host.check(CG), ("ERROR", "shadow:untrusted", "ERROR"))
                with Today():
                    res = host.execute()
            else:
                for mod in (CA, CG):
                    src = mod._render("CTRL", str(host.passwd), str(host.shadow), owner_root=True)
                    out = subprocess.run(["/bin/bash", "-c", src + "\nslp_check_CTRL\n"], stdout=subprocess.PIPE,
                                         check=True, timeout=60).stdout.decode().split("\t")
                    # Без root файл чужого владельца не создать: владелец root требуется у каталога и файлов,
                    # первым отказывает каталог (у root-прогона проверяется владелец файла shadow).
                    self.assertEqual(out[2], "ERROR")
                    self.assertTrue(out[3].endswith(":untrusted"), out)
                real = A._owner_check
                A._owner_check = lambda root: (lambda uid: False)
                try:
                    with Today():
                        res = host.execute()
                finally:
                    A._owner_check = real
            self.assertEqual(res["outcome"], "ABORTED_PRECONDITION_CONFLICT")
            self.assertTrue(res["reason"].endswith(":untrusted"), res)
            self.assertFalse(res["mutation_performed"])


class CheckAge(unittest.TestCase):
    def value(self, lastchg):
        today = int(__import__("time").time()) // 86400
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, passwd=PASSWD.replace(b"old:x:1001:1001::/home/old:/bin/bash\n", b""),
                        shadow_bytes=shadow(user=rec("user", lastchg(today))))
            return host.check(CG)

    def test_boundaries(self):
        cases = (
            (lambda t: str(t - 89), "accounts=1;age_over=0;date_empty=0;date_zero=0;date_future=0", "PASS"),
            (lambda t: str(t - 90), "accounts=1;age_over=0;date_empty=0;date_zero=0;date_future=0", "PASS"),
            (lambda t: str(t - 91), "accounts=1;age_over=1;date_empty=0;date_zero=0;date_future=0", "FAIL"),
            (lambda t: "", "accounts=1;age_over=0;date_empty=1;date_zero=0;date_future=0", "FAIL"),
            (lambda t: "0", "accounts=1;age_over=0;date_empty=0;date_zero=1;date_future=0", "FAIL"),
            (lambda t: str(t + 1), "accounts=1;age_over=0;date_empty=0;date_zero=0;date_future=1", "FAIL"),
            (lambda t: LONG, "accounts=1;age_over=0;date_empty=0;date_zero=0;date_future=1", "FAIL"),
            (lambda t: "0" * 5000 + str(t - 10), "accounts=1;age_over=0;date_empty=0;date_zero=0;date_future=0",
             "PASS"),
        )
        for lastchg, value, compliance in cases:
            with self.subTest(value=value):
                self.assertEqual(self.value(lastchg), ("VALUE", value, compliance))

    def test_non_numeric_is_error(self):
        self.assertEqual(self.value(lambda t: "1a"), ("ERROR", "shadow:invalid-number", "ERROR"))


class ParserParity(unittest.TestCase):
    """Разбор совпадает с CHECK v2 2.1.1: где он даёт ERROR, CHECK сроков и APPLY — отказ."""

    CASES = (
        ("passwd:empty-file", b"", None),
        ("shadow:empty-file", PASSWD, b""),
        ("passwd:duplicate-account", PASSWD + b"user:x:1000:1000:user:/home/user:/bin/bash\n", None),
        ("shadow:duplicate-account", PASSWD, shadow(user=rec("user", D - 30), old=rec("old", 18262))
         + rec("user", D).encode() + b"\n"),
        ("shadow:invalid-fields", PASSWD, shadow(user="user:", old=rec("old", 18262))),
        ("passwd:invalid-fields", PASSWD.replace(b"user:x:1000:1000:user:/home/user:/bin/bash", b"user:x:1000"), None),
        ("passwd:empty-record", PASSWD + b"\n", None),
        ("shadow:invalid-account", PASSWD, shadow(user=rec("user", D - 30), old=rec("old", 18262)) + b"-bad::1::::::\n"),
        ("passwd:missing-shadow-account", PASSWD + b"ghost:x:1002:1002::/:/bin/sh\n", None),
    )

    def test_non_utf8_bytes_match_check_v2(self):
        """Байт 0xff в GECOS: CHECK v2 принимает — CHECK сроков и APPLY тоже."""
        passwd = PASSWD.replace(b"user:x:1000:1000:user:", b"user:x:1000:1000:us\xffer:")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, passwd=passwd)
            self.assertEqual(host.check_state()[0], "VALUE")
            self.assertEqual(host.check(CA)[0], "VALUE")
            self.assertEqual(host.check(CG)[0], "VALUE")
            with Today():
                res = host.execute()
            self.assertEqual(res["outcome"], "APPLIED_PARTIAL", res)
            self.assertEqual(host.passwd.read_bytes(), passwd)

    def test_parity(self):
        for reason, passwd, shadow_bytes in self.CASES:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td, passwd=passwd, shadow_bytes=shadow_bytes)
                self.assertEqual(host.check_state(), ["ERROR", reason])
                self.assertEqual(host.check(CA), ("ERROR", reason, "ERROR"))
                self.assertEqual(host.check(CG), ("ERROR", reason, "ERROR"))
                before = host.shadow.read_bytes()
                with Today():
                    res = host.execute()
                expected = ("ABORTED_PRECONDITION_CONFLICT", "shadow:entry-missing") \
                    if reason == "passwd:missing-shadow-account" else ("ABORTED_PRECONDITION_OTHER", reason)
                self.assertEqual((res["outcome"], res["reason"]), expected)
                self.assertEqual(host.shadow.read_bytes(), before)
                self.assertEqual(host.lock_calls, [])


class Eligibility(unittest.TestCase):
    def run_one(self, line, day=D):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, passwd=PASSWD.replace(b"old:x:1001:1001::/home/old:/bin/bash\n", b""),
                        shadow_bytes=shadow(user=line))
            with Today(day):
                res = host.execute()
            return res, host.fields("user")

    def test_boundary_83_84(self):
        res, f = self.run_one(rec("user", D - 83))
        self.assertEqual((res["outcome"], f[2:6]), ("APPLIED", [str(D - 83), "1", "90", "7"]))
        res, f = self.run_one(rec("user", D - 84))
        self.assertEqual((res["outcome"], f[3:6]), ("ABORTED_PRECONDITION_CONFLICT", ["0", "99999", "7"]))
        self.assertIn("user — age-over-83 — ", res["operator_decision"]["action"])

    def test_admin_reasons(self):
        cases = (
            (rec("user", ""), "date-empty", " —"),
            (rec("user", "0"), "date-zero", " —"),
            (rec("user", str(D + 1)), "date-future", ""),
            (rec("user", D - 30, inactive="14"), "inactive-set", ""),
            (rec("user", D - 30, expire=str(D)), "account-expired", ""),
            (rec("user", D - 30, expire=str(D - 1)), "account-expired", ""),
            (rec("user", D - 100, inactive="5"), "age-over-83,inactive-set", ""),
        )
        for line, reason, tail in cases:
            with self.subTest(line=line):
                res, f = self.run_one(line)
                self.assertEqual(res["outcome"], "ABORTED_PRECONDITION_CONFLICT", res)
                self.assertIn("user — %s —%s" % (reason, tail), res["operator_decision"]["action"])
                self.assertEqual(f[3:6], ["0", "99999", "7"])

    def test_unrepresentable_future_date(self):
        res, f = self.run_one(rec("user", "1000000000000000"))
        self.assertEqual(res["outcome"], "ABORTED_PRECONDITION_CONFLICT", res)
        self.assertIn("user — date-future — —", res["operator_decision"]["action"])

    def test_long_numeric_fields(self):
        """Поле из цифр длиннее лимита int(): без исключения, причины и исход — как у большого числа."""
        res, f = self.run_one(rec("user", LONG))
        self.assertEqual(res["outcome"], "ABORTED_PRECONDITION_CONFLICT", res)
        self.assertIn("user — date-future — —", res["operator_decision"]["action"])
        res, f = self.run_one(rec("user", D - 10, "1", LONG, "7", expire=LONG))
        self.assertEqual((res["outcome"], f[3:6], f[7]), ("APPLIED", ["1", "90", "7"], LONG))
        res, f = self.run_one(rec("user", D - 90, expire=LONG))
        self.assertEqual(res["outcome"], "ABORTED_PRECONDITION_CONFLICT", res)
        self.assertIn("user — age-over-83 — ", res["operator_decision"]["action"])
        res, f = self.run_one(rec("user", "0" * 5000 + str(D - 10)))
        self.assertEqual((res["outcome"], f[2], f[3:6]), ("APPLIED", "0" * 5000 + str(D - 10), ["1", "90", "7"]))

    def test_future_expire_is_applied(self):
        res, f = self.run_one(rec("user", D - 30, expire=str(D + 1)))
        self.assertEqual((res["outcome"], f[3:6], f[7]), ("APPLIED", ["1", "90", "7"], str(D + 1)))

    def test_mixed_aging_values(self):
        for mn, mx, warn in (("0", "", "7"), ("1", "99999", "7"), ("1", "90", "14"), ("", "", "")):
            with self.subTest(fields=(mn, mx, warn)):
                res, f = self.run_one(rec("user", D - 10, mn, mx, warn))
                self.assertEqual((res["outcome"], f[3:6]), ("APPLIED", ["1", "90", "7"]))


class Apply(unittest.TestCase):
    def test_partial_and_only_fields_4_to_6_change(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            before = host.shadow.read_bytes()
            mode = os.stat(host.shadow).st_mode
            with Today():
                res = host.execute()
            self.assertEqual(res["outcome"], "APPLIED_PARTIAL", res)
            self.assertEqual((res["transaction_commit"], res["applied"]), ("COMMITTED", ["user"]))
            self.assertIn("old — age-over-83 — 2020-01-01", res["operator_decision"]["action"])
            expected = before.replace(rec("user", D - 30).encode(), rec("user", D - 30, "1", "90", "7").encode())
            self.assertEqual(host.shadow.read_bytes(), expected)
            self.assertEqual(os.stat(host.shadow).st_mode, mode)
            self.assertFalse((host.etc / "shadow.lock").exists())
            self.assertEqual(host.lock_calls, ["lock", "unlock"])
            self.assertEqual(sorted(p.name for p in host.etc.iterdir()), ["passwd", "shadow"])
            with Today():
                again = host.execute()
            self.assertEqual(again["outcome"], "ABORTED_PRECONDITION_CONFLICT")
            self.assertEqual(host.shadow.read_bytes(), expected)

    def test_applied_and_already_compliant(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow_bytes=shadow(user=rec("user", D - 30), old=rec("old", D - 1)))
            with Today():
                self.assertEqual(host.execute()["outcome"], "APPLIED")
                res = host.execute()
            self.assertEqual((res["outcome"], res["policy_current"]), ("ALREADY_COMPLIANT", "accounts=2;mismatched=0"))
            self.assertEqual(host.check(CA), ("VALUE", "accounts=2;mismatched=0", "PASS"))

    def test_dry_run_and_privilege(self):
        for kwargs, outcome in (({"dry_run": True}, "DRY_RUN_WOULD_APPLY"),
                                ({"privileged": False}, "ABORTED_PRECONDITION_OTHER")):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td)
                before = host.shadow.read_bytes()
                with Today():
                    res = host.execute(**kwargs)
                self.assertEqual(res["outcome"], outcome)
                self.assertEqual(host.shadow.read_bytes(), before)
                self.assertEqual(host.lock_calls, [])

    def test_contract_fields_are_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            for kwargs in ({"key": "x"}, {"op": "le"}, {"expected": "1/90/14"}):
                self.assertEqual(host.execute(**kwargs)["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")


class Locks(unittest.TestCase):
    def test_lckpwdf_busy(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            host.lock_ok = False
            before = host.shadow.read_bytes()
            with Today():
                res = host.execute()
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", "shadow:busy"))
            self.assertEqual(host.shadow.read_bytes(), before)
            self.assertEqual(host.lock_calls, ["lock"])

    def test_lock_file_alive_stale_empty(self):
        for content, outcome, reason in ((str(os.getppid()), "ABORTED_PRECONDITION_OTHER", "shadow:busy"),
                                         ("999999999", "ABORTED_PRECONDITION_CONFLICT", "shadow:stale-lock"),
                                         ("", "ABORTED_PRECONDITION_CONFLICT", "shadow:stale-lock"),
                                         ("abc", "ABORTED_PRECONDITION_CONFLICT", "shadow:stale-lock")):
            with self.subTest(content=content), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td)
                (host.etc / "shadow.lock").write_text(content)
                before = host.shadow.read_bytes()
                with Today():
                    res = host.execute()
                self.assertEqual((res["outcome"], res["reason"]), (outcome, reason))
                self.assertEqual(host.shadow.read_bytes(), before)
                self.assertEqual((host.etc / "shadow.lock").read_text(), content)
                self.assertFalse((host.etc / ("shadow.%d" % os.getpid())).exists())
                self.assertEqual(host.lock_calls, ["lock", "unlock"])

    def test_lock_file_holds_pid_during_transaction(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            seen = {}
            real = A._rename

            def rename(src, dst):
                lock = host.etc / "shadow.lock"
                seen["content"] = lock.read_text()
                seen["nlink"] = os.lstat(lock).st_nlink
                return real(src, dst)

            A._rename = rename
            try:
                with Today():
                    res = host.execute(pid=4242)
            finally:
                A._rename = real
            self.assertEqual(res["outcome"], "APPLIED_PARTIAL")
            self.assertEqual(seen, {"content": "4242", "nlink": 1})
            self.assertFalse((host.etc / "shadow.lock").exists())

    def test_lock_mismatch_after_link(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            real = A._lock_owner
            A._lock_owner = lambda path: 1 if path.endswith("shadow.lock") else real(path)
            try:
                with Today():
                    res = host.execute(pid=4242)
            finally:
                A._lock_owner = real
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", "shadow:lock-mismatch"))

    def test_release_failure_is_reported(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            host.unlock_ok = False
            with Today():
                res = host.execute()
            self.assertEqual((res["outcome"], res["reason"]), ("APPLIED_PARTIAL", "admin-decision;lock:release-failed"))
            rep = A.control_result_to_report(res, "s", "f")
            self.assertEqual(rep["step_rc"], "nonzero")
            ok = Host.__new__(Host)
            with tempfile.TemporaryDirectory(dir=ROOT) as td2:
                ok = Host(td2, shadow_bytes=shadow(user=rec("user", D - 30), old=rec("old", D - 1)))
                ok.unlock_ok = False
                with Today():
                    res2 = ok.execute()
                self.assertEqual((res2["outcome"], res2["reason"]), ("APPLIED", "lock:release-failed"))
                self.assertEqual(A.control_result_to_report(res2, "s", "f")["step_rc"], "nonzero")

    def test_release_unlink_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            real = A._unlink

            def unlink(path):
                if path.endswith("shadow.lock"):
                    raise OSError("fail")
                return real(path)

            A._unlink = unlink
            try:
                with Today():
                    res = host.execute(pid=4242)
            finally:
                A._unlink = real
            self.assertEqual((res["outcome"], res["reason"]), ("APPLIED_PARTIAL", "admin-decision;lock:release-failed"))
            self.assertEqual(A.control_result_to_report(res, "s", "f")["step_rc"], "nonzero")
            self.assertEqual((host.etc / "shadow.lock").read_text(), "4242")

    def test_crash_after_link_leaves_pid(self):
        """Аварийное завершение сразу после link: дочерний процесс берёт блокировку и завершается
        (os._exit) сразу после успешного link, до следующих операций. В файле блокировки — PID этого
        процесса (не пустой файл); повторный запуск видит завершённый процесс (stale-lock) и чужие
        файлы не трогает."""
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            pid = os.fork()
            if pid == 0:
                real_link = os.link

                def link_then_crash(src, dst):
                    real_link(src, dst)
                    os._exit(0)

                os.link = link_then_crash
                try:
                    A._take_lock_file(str(host.root), os.getpid())
                finally:
                    os._exit(3)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            lock = host.etc / "shadow.lock"
            tmp = host.etc / ("shadow.%d" % pid)
            self.assertEqual(lock.read_text(), str(pid))
            self.assertEqual(tmp.read_text(), str(pid))
            before = host.shadow.read_bytes()
            with Today():
                res = host.execute()
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "shadow:stale-lock"))
            self.assertEqual((lock.read_text(), tmp.read_text()), (str(pid), str(pid)))
            self.assertEqual(host.shadow.read_bytes(), before)

    def test_read_errors_p1_and_l2(self):
        for n, outcome, reason in ((1, "ABORTED_PRECONDITION_OTHER", "passwd:read-failed"),
                                   (2, "ABORTED_PRECONDITION_OTHER", "shadow:read-failed"),
                                   (3, "ABORTED_PRECONDITION_OTHER", "files:changed"),
                                   (4, "ABORTED_PRECONDITION_OTHER", "files:changed")):
            with self.subTest(call=n), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td)
                before = host.shadow.read_bytes()
                real = A._read_file
                calls = {"n": 0}

                def read_file(path):
                    if path.endswith("/etc/passwd") or path.endswith("/etc/shadow"):
                        calls["n"] += 1
                        if calls["n"] == n:
                            raise OSError("fail")
                    return real(path)

                A._read_file = read_file
                try:
                    with Today():
                        res = host.execute()
                finally:
                    A._read_file = real
                self.assertEqual((res["outcome"], res["reason"]), (outcome, reason))
                self.assertFalse(res["mutation_performed"])
                self.assertEqual(host.shadow.read_bytes(), before)
                self.assertFalse((host.etc / "shadow.lock").exists())

    def test_precondition_change_at_l2_is_files_changed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            real = A._take_lock_file

            def take(root, pid):
                os.chmod(host.shadow, 0o660)
                return real(root, pid)

            A._take_lock_file = take
            try:
                with Today():
                    res = host.execute()
            finally:
                A._take_lock_file = real
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", "files:changed"))
            self.assertFalse((host.etc / "shadow.lock").exists())

    def test_files_changed_before_lock(self):
        for target in ("passwd", "shadow"):
            with self.subTest(target=target), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td)
                real = A._take_lock_file

                def take(root, pid):
                    path = host.passwd if target == "passwd" else host.shadow
                    path.write_bytes(path.read_bytes() + (b"new:x:1003:1003::/:/bin/sh\n" if target == "passwd"
                                                          else b"zz:*:1::::::\n"))
                    if target == "passwd":
                        host.shadow.write_bytes(host.shadow.read_bytes() + b"new:*:1::::::\n")
                    return real(root, pid)

                A._take_lock_file = take
                try:
                    with Today():
                        res = host.execute()
                finally:
                    A._take_lock_file = real
                self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", "files:changed"))
                self.assertFalse(res["mutation_performed"])
                self.assertFalse((host.etc / "shadow.lock").exists())


class Failures(unittest.TestCase):
    def run_with(self, attr, replacement, verify):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            before = host.shadow.read_bytes()
            real = getattr(A, attr)
            setattr(A, attr, replacement(host, real))
            try:
                with Today():
                    res = host.execute()
            finally:
                setattr(A, attr, real)
            verify(res, host, before)
            self.assertFalse((host.etc / "shadow.lock").exists())

    def test_tmp_write_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            before = host.shadow.read_bytes()
            real = os.fsync
            calls = {"n": 0}

            def fsync(fd):
                calls["n"] += 1
                if calls["n"] == 2:  # 1 — файл блокировки, 2 — временный файл
                    raise OSError("fail")
                return real(fd)

            os.fsync = fsync
            try:
                with Today():
                    res = host.execute()
            finally:
                os.fsync = real
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "shadow:write-failed"))
            self.assertEqual(host.shadow.read_bytes(), before)
            self.assertEqual(sorted(p.name for p in host.etc.iterdir()), ["passwd", "shadow"])

    def test_rename_failure(self):
        def fail(host, real):
            def rename(src, dst):
                raise OSError("fail")
            return rename
        def verify(res, host, before):
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "shadow:rename-failed"))
            self.assertEqual(host.shadow.read_bytes(), before)
            self.assertEqual(sorted(p.name for p in host.etc.iterdir()), ["passwd", "shadow"])
        self.run_with("_rename", fail, verify)

    def test_dirsync_failure_is_compensated(self):
        def fail(host, real):
            calls = {"n": 0}

            def fsync_dir(path):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise OSError("fail")
                return real(path)
            return fsync_dir
        def verify(res, host, before):
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "shadow:dirsync-failed"))
            self.assertTrue(res["mutation_performed"])
            self.assertEqual(host.shadow.read_bytes(), before)
        self.run_with("_fsync_dir", fail, verify)

    def test_dirsync_and_compensation_write_failure(self):
        def fail(host, real):
            def fsync_dir(path):
                raise OSError("fail")
            return fsync_dir
        def verify(res, host, before):
            self.assertEqual((res["outcome"], res["reason"]),
                             ("FAILED_COMPENSATION", "shadow:dirsync-failed;compensation:write-failed"))
        self.run_with("_fsync_dir", fail, verify)

    def test_postcheck_read_failure_is_compensated(self):
        def fail(host, real):
            calls = {"n": 0}

            def read_file(path):
                if path.endswith("/etc/passwd") or path.endswith("/etc/shadow"):
                    calls["n"] += 1
                    if calls["n"] == 5:  # P1: 2, L2: 2, L6: passwd
                        raise OSError("fail")
                return real(path)
            return read_file
        def verify(res, host, before):
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "postcheck:failed"))
            self.assertEqual(host.shadow.read_bytes(), before)
        self.run_with("_read_file", fail, verify)

    def test_foreign_change_after_write_is_not_overwritten(self):
        def fail(host, real):
            def fsync_dir(path):
                real(path)
                data = host.shadow.read_bytes().replace(b"old:$y$j9T$a$b:18262:0:", b"old:$y$j9T$a$b:18262:5:")
                host.shadow.write_bytes(data)
            return fsync_dir
        def verify(res, host, before):
            self.assertEqual((res["outcome"], res["reason"]),
                             ("FAILED_COMPENSATION", "postcheck:failed;compensation:shadow-changed"))
            self.assertEqual(host.fields("old")[3], "5")
            self.assertEqual(host.fields("user")[3:6], ["1", "90", "7"])
        self.run_with("_fsync_dir", fail, verify)

    def test_compensation_read_failure(self):
        def fail(host, real):
            calls = {"n": 0}

            def read_file(path):
                if path.endswith("/etc/shadow"):
                    calls["n"] += 1
                    if calls["n"] >= 3:  # P1, L2, затем L6 и компенсация
                        raise OSError("fail")
                return real(path)
            return read_file
        def verify(res, host, before):
            self.assertEqual(res["outcome"], "FAILED_COMPENSATION", res)
            self.assertIn("compensation:read-failed", res["reason"])
        self.run_with("_read_file", fail, verify)


class Report(unittest.TestCase):
    def test_report_fields(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow_bytes=shadow(user=rec("user", D - 30, "1", "90", "7"), old=rec("old", D, "1", "90", "7")))
            with Today():
                rep = A.control_result_to_report(host.execute(), "s", "f")
            self.assertEqual((rep["step_rc"], rep["mechanism_id"], rep["target"], rep["outcome"]),
                             ("0", "local-account-password-aging-v1", "/etc/shadow", "ALREADY_COMPLIANT"))
            self.assertEqual(A.outcome_rc_contribution("APPLIED_PARTIAL"), "nonzero")


if __name__ == "__main__":
    unittest.main(verbosity=2)
