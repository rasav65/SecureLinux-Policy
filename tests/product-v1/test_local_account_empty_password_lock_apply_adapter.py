#!/usr/bin/env python3
"""Regressions for the local-account-empty-password-lock-v1 APPLY mechanism (fstec-linux-2022 п.2.1.1;
SRC-0001).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Каждый случай работает на дереве во временном каталоге внутри репозитория (`_root`:
`etc/passwd`, `etc/shadow`, `usr/sbin/usermod`); usermod заменён моделью (`_run`), которая правит
поле пароля в `etc/shadow` корня, как `usermod -L` и `usermod -p ''`. Файлы принадлежат текущему
пользователю — адаптер при заданном корне принимает его вместо root. Решение пользователя
01.10.2026: блокируются все учётные записи с пустым паролем, без исключений.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "product/apply-adapters/product-local-account-empty-password-lock-apply-v1.py"
CONTROL = ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.1.1-local-account-password-state.yaml"
CHECK_ADAPTER = ROOT / "product/adapters/product-local-account-password-state-check-v2.py"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = load(ADAPTER, "slp_empty_password_lock_apply")
C = load(CHECK_ADAPTER, "slp_password_state_check_v2")

PASSWD = (b"root:x:0:0:root:/root:/bin/bash\n"
          b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
          b"user:x:1000:1000:user:/home/user:/bin/bash\n"
          b"admin1:x:1001:1001::/home/admin1:/bin/bash\n")
SHADOW = (b"root:*:19000:0:99999:7:::\n"
          b"daemon:*:19000:0:99999:7:::\n"
          b"user:$y$j9T$abc$def:19000:0:99999:7:::\n"
          b"admin1:$y$j9T$ghi$jkl:19000:0:99999:7:::\n")


def with_empty(shadow, *names):
    out = []
    for line in shadow.split(b"\n"):
        parts = line.split(b":")
        if parts[0].decode() in names:
            parts[1] = b""
        out.append(b":".join(parts))
    return b"\n".join(out)


class Host:
    """Временный корень с /etc/passwd, /etc/shadow, usermod и моделью usermod."""

    def __init__(self, td, passwd=PASSWD, shadow=SHADOW, fail_on=(), wrong_on=(), unlock_fails=False):
        self.root = Path(td)
        (self.root / "etc").mkdir()
        self.passwd = self.root / "etc/passwd"
        self.shadow = self.root / "etc/shadow"
        self.passwd.write_bytes(passwd)
        os.chmod(self.passwd, 0o644)
        self.shadow.write_bytes(shadow)
        os.chmod(self.shadow, 0o640)
        (self.root / "usr/sbin").mkdir(parents=True)
        tool = self.root / "usr/sbin/usermod"
        tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        tool.chmod(0o755)
        self.fail_on, self.wrong_on, self.unlock_fails = set(fail_on), set(wrong_on), unlock_fails
        self.calls = []

    def set_field(self, name, value):
        lines = []
        for line in self.shadow.read_bytes().split(b"\n"):
            parts = line.split(b":")
            if parts[0] == name.encode():
                parts[1] = value.encode()
            lines.append(b":".join(parts))
        self.shadow.write_bytes(b"\n".join(lines))

    def field(self, name):
        for line in self.shadow.read_bytes().decode().split("\n"):
            parts = line.split(":")
            if parts[0] == name:
                return parts[1]
        return None

    def run(self, argv, timeout):
        self.calls.append(tuple(argv[1:]))
        assert argv[0] == A.USERMOD, argv
        name = argv[-1]
        if argv[1] == "-L":
            if name in self.fail_on:
                return subprocess.CompletedProcess(argv, 1, b"", b"")
            self.set_field(name, "!x" if name in self.wrong_on else "!" + self.field(name))
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv[1:3] == ["-p", ""]:
            if self.unlock_fails:
                return subprocess.CompletedProcess(argv, 1, b"", b"")
            self.set_field(name, "")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(argv)

    def check_status(self):
        """Статус CHECK v2 (VALUE или ERROR) и причина на тех же файлах."""
        src = C._shell_function_for_paths("CTRL", str(self.passwd), str(self.shadow),
                                          "password-field", "all-nonempty", True)
        cp = subprocess.run(["/bin/bash", "-c", src + "\nslp_check_CTRL\n"], stdout=subprocess.PIPE,
                            check=True, timeout=60)
        fields = cp.stdout.decode().rstrip("\n").split("\t")
        return fields[2], fields[3]

    def execute(self, dry_run=False, privileged=True, key="password-field", op="all-nonempty", expected=True):
        return A.execute_control("FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE", key, op, expected, True,
                                 dry_run=dry_run, privilege_check=lambda: privileged,
                                 _root=str(self.root), _run=self.run)


class Contract(unittest.TestCase):
    def test_control_is_routed(self):
        text = CONTROL.read_text(encoding="utf-8")
        self.assertIn('  kind: "local-account-password-state"\n  locator: "/etc/shadow"\n  key: "password-field"\n', text)
        self.assertIn('  op: "all-nonempty"\n  value: true\n', text)
        self.assertIn("apply:\n  supported: true\n", text)
        self.assertFalse(hasattr(A, "INSTALLS_PACKAGES"))

    def test_contract_fields_are_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow=with_empty(SHADOW, "user"))
            for kwargs in ({"key": "password"}, {"op": "eq"}, {"expected": False}):
                self.assertEqual(host.execute(**kwargs)["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
            self.assertEqual(host.calls, [])


class Apply(unittest.TestCase):
    def test_all_empty_accounts_are_locked_without_exceptions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow=with_empty(SHADOW, "root", "user", "admin1"))
            res = host.execute()
            self.assertEqual((res["outcome"], res["policy_current"]), ("APPLIED", "accounts=4 empty=0"), res)
            self.assertEqual([host.field(n) for n in ("root", "daemon", "user", "admin1")], ["!", "*", "!", "!"])
            self.assertEqual(host.calls, [("-L", "root"), ("-L", "user"), ("-L", "admin1")])
            self.assertEqual(host.execute()["outcome"], "ALREADY_COMPLIANT")

    def test_compliant_host_is_untouched(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            res = host.execute()
            self.assertEqual((res["outcome"], res["policy_current"]), ("ALREADY_COMPLIANT", "accounts=4 empty=0"))
            self.assertEqual(host.calls, [])

    def test_dry_run_and_privilege_do_not_change(self):
        for kwargs, outcome in (({"dry_run": True}, "DRY_RUN_WOULD_APPLY"),
                                ({"privileged": False}, "ABORTED_PRECONDITION_OTHER")):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td, shadow=with_empty(SHADOW, "user"))
                res = host.execute(**kwargs)
                self.assertEqual((res["outcome"], res["policy_current"]), (outcome, "accounts=4 empty=1"))
                self.assertEqual(host.field("user"), "")
                self.assertEqual(host.calls, [])

    def test_field_filled_meanwhile_is_not_touched(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow=with_empty(SHADOW, "user", "admin1"))
            real = host.run

            def run(argv, timeout):
                if argv[-1] == "user":
                    host.set_field("admin1", "$y$new")
                return real(argv, timeout)

            host.run = run
            res = host.execute()
            self.assertEqual(res["outcome"], "APPLIED", res)
            self.assertEqual((host.field("user"), host.field("admin1")), ("!", "$y$new"))
            self.assertEqual(host.calls, [("-L", "user")])


class Refusals(unittest.TestCase):
    def test_missing_shadow_entry_is_admin_decision(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, passwd=PASSWD + b"ghost:x:1002:1002::/home/ghost:/bin/sh\n")
            res = host.execute()
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "shadow:entry-missing"))
            self.assertIn("ghost", res["operator_decision"]["action"])
            self.assertEqual(host.calls, [])

    def test_unsupported_name_is_admin_decision(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, passwd=PASSWD + b"Admin2:x:1002:1002::/:/bin/sh\n",
                        shadow=SHADOW + b"Admin2::19000:0:99999:7:::\n")
            res = host.execute()
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "account:unsupported-name"))
            self.assertEqual(host.calls, [])

    def test_untrusted_or_broken_files(self):
        cases = (
            (lambda h: os.chmod(h.shadow, 0o642), "ABORTED_PRECONDITION_CONFLICT", "shadow:untrusted"),
            (lambda h: (h.shadow.unlink(), os.symlink("/dev/null", h.shadow)), "ABORTED_PRECONDITION_CONFLICT", "shadow:untrusted"),
            (lambda h: h.shadow.write_bytes(b"user::1\r\n"), "ABORTED_PRECONDITION_OTHER", "shadow:invalid-bytes"),
            (lambda h: h.passwd.write_bytes(b"broken\n"), "ABORTED_PRECONDITION_OTHER", "passwd:invalid-fields"),
            (lambda h: (h.root / "usr/sbin/usermod").unlink(), "ABORTED_PRECONDITION_OTHER", "tools:missing:usermod"),
        )
        for prepare, outcome, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td, shadow=with_empty(SHADOW, "user"))
                prepare(host)
                res = host.execute()
                self.assertEqual((res["outcome"], res["reason"]), (outcome, reason), res)
                self.assertFalse(res["mutation_performed"])
                self.assertEqual(host.calls, [])


class ParserParity(unittest.TestCase):
    """Разбор популяции совпадает с CHECK v2: где CHECK даёт ERROR, APPLY отказывает до мутации."""

    CASES = (
        ("passwd:empty-file", b"", with_empty(SHADOW, "user")),
        ("shadow:empty-file", PASSWD, b""),
        ("passwd:duplicate-account", PASSWD + b"user:x:1000:1000:user:/home/user:/bin/bash\n",
         with_empty(SHADOW, "user")),
        ("shadow:duplicate-account", PASSWD, with_empty(SHADOW, "user") + b"user:$y$j9T$x$y:19000:0:99999:7:::\n"),
        ("shadow:invalid-fields", PASSWD, with_empty(SHADOW, "user").replace(b"user::19000:0:99999:7:::", b"user:")),
        ("passwd:invalid-fields", PASSWD.replace(b"user:x:1000:1000:user:/home/user:/bin/bash", b"user:x:1000"),
         with_empty(SHADOW, "user")),
        ("shadow:empty-record", PASSWD, with_empty(SHADOW, "user").replace(b"\nuser:", b"\n\nuser:")),
        ("passwd:empty-record", PASSWD + b"\n", with_empty(SHADOW, "user")),
        ("shadow:invalid-account", PASSWD, with_empty(SHADOW, "user") + b"-bad::19000:0:99999:7:::\n"),
        ("passwd:invalid-account", PASSWD + b"-bad:x:1002:1002::/:/bin/sh\n", with_empty(SHADOW, "user")),
    )

    def test_check_error_means_apply_refusal(self):
        for reason, passwd, shadow in self.CASES:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td, passwd=passwd, shadow=shadow)
                self.assertEqual(host.check_status(), ("ERROR", reason))
                res = host.execute()
                self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", reason), res)
                self.assertFalse(res["mutation_performed"])
                self.assertEqual(host.calls, [])
                self.assertEqual((host.passwd.read_bytes(), host.shadow.read_bytes()), (passwd, shadow))

    def test_missing_shadow_entry_matches_check_error(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, passwd=PASSWD + b"ghost:x:1002:1002::/home/ghost:/bin/sh\n")
            self.assertEqual(host.check_status(), ("ERROR", "passwd:missing-shadow-account"))
            self.assertEqual(host.execute()["outcome"], "ABORTED_PRECONDITION_CONFLICT")

    def test_first_error_in_passwd_order_matches_check(self):
        """Запись без shadow перед повреждённой записью — решение администратора; после — ошибка разбора."""
        ghost = b"ghost:x:1002:1002::/home/ghost:/bin/sh\n"
        cases = (
            (ghost + b"user:x:1000:1000:user:/home/user:/bin/bash\n", "passwd:missing-shadow-account",
             "ABORTED_PRECONDITION_CONFLICT", "shadow:entry-missing"),
            (ghost + b"broken\n", "passwd:missing-shadow-account",
             "ABORTED_PRECONDITION_CONFLICT", "shadow:entry-missing"),
            (b"broken\n" + ghost, "passwd:invalid-fields", "ABORTED_PRECONDITION_OTHER", "passwd:invalid-fields"),
            (b"user:x:1000:1000:user:/home/user:/bin/bash\n" + ghost, "passwd:duplicate-account",
             "ABORTED_PRECONDITION_OTHER", "passwd:duplicate-account"),
        )
        for tail, check_reason, outcome, reason in cases:
            with self.subTest(check=check_reason, tail=tail), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td, passwd=PASSWD + tail, shadow=with_empty(SHADOW, "user"))
                self.assertEqual(host.check_status(), ("ERROR", check_reason))
                res = host.execute()
                self.assertEqual((res["outcome"], res["reason"]), (outcome, reason), res)
                if outcome == "ABORTED_PRECONDITION_CONFLICT":
                    self.assertEqual(res["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
                    self.assertIn("ghost", res["operator_decision"]["action"])
                self.assertEqual(host.calls, [])

    def test_value_cases_match_check(self):
        for shadow, check, outcome in ((SHADOW, ("VALUE", "accounts=4;empty=0"), "ALREADY_COMPLIANT"),
                                       (with_empty(SHADOW, "user"), ("VALUE", "accounts=4;empty=1"), "APPLIED")):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td, shadow=shadow)
                self.assertEqual(host.check_status(), check)
                self.assertEqual(host.execute()["outcome"], outcome)
                self.assertEqual(host.check_status(), ("VALUE", "accounts=4;empty=0"))


class Compensation(unittest.TestCase):
    def test_usermod_failure_rolls_back_locked(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow=with_empty(SHADOW, "user", "admin1"), fail_on={"admin1"})
            res = host.execute()
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "usermod:lock-failed"), res)
            self.assertEqual((host.field("user"), host.field("admin1")), ("", ""))
            self.assertEqual(res["transaction_commit"], "NOT_COMMITTED")

    def test_unexpected_lock_value_is_compensation_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow=with_empty(SHADOW, "user"), wrong_on={"user"})
            res = host.execute()
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_COMPENSATION", "shadow:lock-not-applied"), res)
            self.assertEqual(host.field("user"), "!x")

    def test_rollback_is_verified_after_all_commands(self):
        """Откат второй записи снова блокирует первую: итоговая сверка даёт FAILED_COMPENSATION."""
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow=with_empty(SHADOW, "root", "user", "admin1"), fail_on={"admin1"})
            real = host.run

            def run(argv, timeout):
                rc = real(argv, timeout)
                if argv[1:3] == ["-p", ""] and argv[-1] == "root":
                    host.set_field("user", "!")
                return rc

            host.run = run
            res = host.execute()
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_COMPENSATION", "usermod:lock-failed"), res)
            self.assertEqual(host.calls, [("-L", "root"), ("-L", "user"), ("-L", "admin1"),
                                          ("-p", "", "user"), ("-p", "", "root")])
            self.assertEqual(host.field("user"), "!")

    def test_unreadable_shadow_after_rollback_is_compensation_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow=with_empty(SHADOW, "user", "admin1"), fail_on={"admin1"})
            real = host.run

            def run(argv, timeout):
                rc = real(argv, timeout)
                if argv[1:3] == ["-p", ""]:
                    os.chmod(host.shadow, 0o642)
                return rc

            host.run = run
            res = host.execute()
            self.assertEqual(res["outcome"], "FAILED_COMPENSATION", res)
            self.assertEqual(host.field("user"), "")

    def test_single_read_error_during_rollback_is_compensation_failure(self):
        """Однократный отказ чтения в откате: итоговое чтение успешно, но исход — FAILED_COMPENSATION."""
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow=with_empty(SHADOW, "user", "admin1"), fail_on={"admin1"})
            real_field = A._field
            state = {"armed": False, "fired": False}

            def field(root, name):
                if state["armed"] and not state["fired"]:
                    state["fired"] = True
                    return None
                return real_field(root, name)

            real_run = host.run

            def run(argv, timeout):
                rc = real_run(argv, timeout)
                if argv[1] == "-L" and argv[-1] == "admin1":
                    state["armed"] = True
                return rc

            host.run = run
            A._field = field
            try:
                res = host.execute()
            finally:
                A._field = real_field
            self.assertTrue(state["fired"])
            self.assertEqual(res["outcome"], "FAILED_COMPENSATION", res)

    def test_failed_unlock_is_compensation_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, shadow=with_empty(SHADOW, "user", "admin1"), fail_on={"admin1"}, unlock_fails=True)
            res = host.execute()
            self.assertEqual(res["outcome"], "FAILED_COMPENSATION", res)


class Report(unittest.TestCase):
    def test_report_fields(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            rep = A.control_result_to_report(host.execute(), "s", "f")
            self.assertEqual((rep["step_rc"], rep["mechanism_id"], rep["target"]),
                             ("0", "local-account-empty-password-lock-v1", "/etc/shadow"))
            self.assertEqual(A.outcome_rc_contribution("FAILED_COMPENSATION"), "nonzero")


if __name__ == "__main__":
    unittest.main(verbosity=2)
