#!/usr/bin/env python3
"""Regressions for the auditd-conf-option-v1 APPLY mechanism (fstec-logging-2025 приложение 2, п.3;
SRC-0052).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Каждый случай работает на дереве во временном каталоге внутри репозитория (`_root`:
`etc/audit/auditd.conf`, `usr/bin/systemctl`; `_proc`: `<pid>/comm`); systemd и сигнал заменены
моделью (`_run`, `_kill`). Файлы принадлежат текущему пользователю — адаптер при заданном `_root`
принимает его вместо root. Решение пользователя 30.09.2026: девять параметров auditd.conf.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "product/apply-adapters/product-auditd-conf-option-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-auditd-conf-option-check-v1.py"
CONTROLS = ROOT / "controls/fstec-core/logging-2025"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = load(ADAPTER, "slp_auditd_conf_option_apply")
C = load(CHECK_ADAPTER, "slp_auditd_conf_option_check")

# Фрагмент файла по умолчанию Debian/Ubuntu (значения, отличные от политики).
DEFAULT = (
    b"#\n"
    b"# This file controls the configuration of the audit daemon\n"
    b"#\n"
    b"\n"
    b"local_events = yes\n"
    b"write_logs = yes\n"
    b"log_file = /var/log/audit/audit.log\n"
    b"log_group = adm\n"
    b"log_format = ENRICHED\n"
    b"flush = INCREMENTAL_ASYNC\n"
    b"freq = 50\n"
    b"max_log_file = 8\n"
    b"num_logs = 5\n"
    b"max_log_file_action = ROTATE\n"
    b"space_left = 75\n"
    b"space_left_action = SYSLOG\n"
    b"admin_space_left = 50\n"
    b"admin_space_left_action = SUSPEND\n"
    b"disk_full_action = SUSPEND\n"
    b"disk_error_action = SUSPEND\n"
)
# Все девять параметров не соответствуют политике.
NONCOMPLIANT = (DEFAULT.replace(b"log_file = /var/log/audit/audit.log", b"log_file = /var/log/audit/other.log")
                .replace(b"log_format = ENRICHED", b"log_format = RAW")
                .replace(b"space_left_action = SYSLOG", b"space_left_action = email")
                .replace(b"admin_space_left_action = SUSPEND", b"admin_space_left_action = halt")
                .replace(b"disk_full_action = SUSPEND", b"disk_full_action = ignore"))
COMPLIANT = {
    "log_file": b"/var/log/audit/audit.log", "log_group": b"root", "max_log_file": b"50", "num_logs": b"10",
    "max_log_file_action": b"keep_logs", "log_format": b"ENRICHED", "space_left_action": b"syslog",
    "admin_space_left_action": b"suspend", "disk_full_action": b"suspend",
}


class Host:
    """Временный корень: каталог /etc/audit, auditd.conf, systemctl и модель службы auditd."""

    def __init__(self, td, raw=DEFAULT, mode=0o640, active=True, comm=b"auditd\n", die_on_hup=False,
                 show_rc=0):
        self.root = Path(td)
        self.conf = self.root / "etc/audit/auditd.conf"
        self.conf.parent.mkdir(parents=True)
        os.chmod(self.conf.parent, 0o750)
        if raw is not None:
            self.conf.write_bytes(raw)
            os.chmod(self.conf, mode)
        (self.root / "usr/bin").mkdir(parents=True)
        tool = self.root / "usr/bin/systemctl"
        tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        tool.chmod(0o755)
        self.proc = self.root / "proc"
        self.pid = 4242
        (self.proc / str(self.pid)).mkdir(parents=True)
        (self.proc / str(self.pid) / "comm").write_bytes(comm)
        self.active = active
        self.die_on_hup = die_on_hup
        self.show_rc = show_rc
        self.signals = []
        self.calls = []

    def run(self, argv, timeout):
        assert argv[0] == A.SYSTEMCTL, argv
        self.calls.append(tuple(argv[1:]))
        if argv[1] == "show":
            if self.show_rc:
                return subprocess.CompletedProcess(argv, self.show_rc, b"", b"")
            body = "MainPID=%d\nActiveState=%s\n" % ((self.pid, "active") if self.active else (0, "inactive"))
            return subprocess.CompletedProcess(argv, 0, body.encode(), b"")
        if argv[1] == "start":
            self.active = True
            self.pid += 1
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(argv)

    def kill(self, pid, sig):
        self.signals.append((pid, sig))
        if self.die_on_hup and len(self.signals) == 1:
            self.active = False

    def execute(self, key, dry_run=False, privileged=True):
        return A.execute_control("FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-" + key.upper().replace("_", "-"),
                                 key, "eq", A.SPECS[key][1], True, dry_run=dry_run,
                                 privilege_check=lambda: privileged, _root=str(self.root), _run=self.run,
                                 _kill=self.kill, _proc=str(self.proc))

    def lines(self, key):
        return [line for line in self.conf.read_bytes().split(b"\n")
                if line.split(b" ")[0].lower() == key.encode()]


class Contract(unittest.TestCase):
    def test_parser_and_specs_match_check_adapter(self):
        self.assertEqual(A.PARSER, C.PARSER)
        self.assertEqual(A.SPECS, C.SPECS)
        self.assertEqual(A.PARAMETER_KIND, C.PARAMETER_KIND)
        self.assertFalse(hasattr(A, "INSTALLS_PACKAGES"))

    def test_controls_are_routed(self):
        keys = set()
        for path in sorted(CONTROLS.glob("fstec-logging-2025-appendix2-linux-3-*.yaml")):
            text = path.read_text(encoding="utf-8")
            self.assertIn('  kind: "auditd-conf-option"\n', text)
            self.assertIn('  locator: "/etc/audit/auditd.conf"\n', text)
            self.assertIn("apply:\n  supported: true\n", text)
            key = re.search(r'^  key: "([a-z_]+)"$', text, re.M).group(1)
            self.assertIn('  op: "eq"\n  value: "%s"\n' % A.SPECS[key][1], text)
            keys.add(key)
        self.assertEqual(keys, set(A.SPECS))


class Apply(unittest.TestCase):
    def test_every_key_is_applied_in_place(self):
        for key in A.SPECS:
            with self.subTest(key=key), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td, raw=NONCOMPLIANT)
                res = host.execute(key)
                self.assertEqual(res["outcome"], "APPLIED", res)
                self.assertEqual(res["transaction_commit"], "COMMITTED")
                self.assertEqual(host.lines(key), [key.encode() + b" = " + COMPLIANT[key]])
                other = [ln for ln in host.conf.read_bytes().split(b"\n") if not ln.startswith(key.encode() + b" ")]
                self.assertEqual(other, [ln for ln in NONCOMPLIANT.split(b"\n") if not ln.startswith(key.encode() + b" ")])
                self.assertEqual(os.stat(host.conf).st_mode & 0o7777, 0o640)
                self.assertEqual(host.signals, [(4242, signal.SIGHUP)])
                self.assertFalse(list(host.conf.parent.glob("*.slp-tmp")))

    def test_compliant_values_are_already_compliant(self):
        for key in ("log_file", "log_format"):
            with self.subTest(key=key), tempfile.TemporaryDirectory(dir=ROOT) as td:
                host = Host(td)
                before = host.conf.read_bytes()
                res = host.execute(key)
                self.assertEqual((res["outcome"], res["policy_current"]), ("ALREADY_COMPLIANT", COMPLIANT[key].decode()))
                self.assertEqual(host.conf.read_bytes(), before)
                self.assertEqual(host.signals, [])

    def test_case_insensitive_word_and_numeric_values(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, raw=b"MAX_LOG_FILE_ACTION = KEEP_LOGS\nnum_logs = 010\n")
            self.assertEqual(host.execute("max_log_file_action")["outcome"], "ALREADY_COMPLIANT")
            self.assertEqual(host.execute("num_logs")["outcome"], "ALREADY_COMPLIANT")

    def test_template_then_append(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, raw=b"# log_group = adm\nlog_file = /var/log/audit/audit.log\n")
            self.assertEqual(host.execute("log_group")["outcome"], "APPLIED")
            self.assertEqual(host.conf.read_bytes(), b"log_group = root\nlog_file = /var/log/audit/audit.log\n")
            self.assertEqual(host.execute("num_logs")["outcome"], "APPLIED")
            self.assertEqual(host.conf.read_bytes(),
                             b"log_group = root\nlog_file = /var/log/audit/audit.log\nnum_logs = 10\n")

    def test_option_is_replaced(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, raw=b"space_left_action = exec /usr/local/bin/x\n")
            res = host.execute("space_left_action")
            self.assertEqual((res["outcome"], res["policy_current"]), ("APPLIED", "syslog"))
            self.assertEqual(host.conf.read_bytes(), b"space_left_action = syslog\n")

    def test_dry_run_and_privilege_do_not_write(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            res = host.execute("num_logs", dry_run=True)
            self.assertEqual((res["outcome"], res["policy_current"]), ("DRY_RUN_WOULD_APPLY", "5"))
            res = host.execute("num_logs", privileged=False)
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
            self.assertEqual(host.conf.read_bytes(), DEFAULT)
            self.assertEqual(host.signals, [])

    def test_stopped_service_gets_no_signal(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, active=False)
            res = host.execute("num_logs")
            self.assertEqual(res["outcome"], "APPLIED")
            self.assertEqual(host.signals, [])


class Refusals(unittest.TestCase):
    def check(self, host, key, outcome, reason):
        before = host.conf.read_bytes() if host.conf.exists() else None
        res = host.execute(key)
        self.assertEqual((res["outcome"], res["reason"]), (outcome, reason), res)
        self.assertFalse(res["mutation_performed"])
        if before is not None:
            self.assertEqual(host.conf.read_bytes(), before)
        self.assertEqual(host.signals, [])
        return res

    def test_missing_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            self.check(Host(td, raw=None), "num_logs", "ABORTED_PRECONDITION_OTHER", "auditd-conf:missing")

    def test_untrusted_file_and_dir(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            res = self.check(Host(td, mode=0o664), "num_logs", "ABORTED_PRECONDITION_CONFLICT", "auditd-conf:untrusted")
            self.assertEqual(res["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            os.link(host.conf, host.root / "etc/hardlink")
            self.check(host, "num_logs", "ABORTED_PRECONDITION_CONFLICT", "auditd-conf:untrusted")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            real = host.root / "etc/real.conf"
            os.rename(host.conf, real)
            os.symlink(real, host.conf)
            self.check(host, "num_logs", "ABORTED_PRECONDITION_CONFLICT", "auditd-conf:untrusted")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            os.chmod(host.conf.parent, 0o770)
            self.check(host, "num_logs", "ABORTED_PRECONDITION_CONFLICT", "auditd-conf:dir-untrusted")

    def test_duplicate_key(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            self.check(Host(td, raw=b"num_logs = 5\nNUM_LOGS = 10\n"), "num_logs",
                       "ABORTED_PRECONDITION_CONFLICT", "auditd-conf:duplicate-key")

    def test_malformed_files(self):
        cases = (
            (b"num_logs=5\n", "auditd-conf:invalid-line"),
            (b"num_logs = 5 x y\n", "auditd-conf:invalid-line"),
            (b"num_logs : 5\n", "auditd-conf:invalid-line"),
            (b"num_logs = 5", "auditd-conf:no-final-newline"),
            (b"num_logs = 5\n\x00\n", "auditd-conf:invalid-bytes"),
            (b"#" + b"x" * 200 + b"\n", "auditd-conf:line-too-long"),
        )
        for raw, reason in cases:
            with self.subTest(raw=raw[:20]), tempfile.TemporaryDirectory(dir=ROOT) as td:
                self.check(Host(td, raw=raw), "num_logs", "ABORTED_PRECONDITION_OTHER", reason)

    def test_systemd_query_failure_before_write(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            self.check(Host(td, show_rc=1), "num_logs", "ABORTED_PRECONDITION_OTHER", "systemd:query-failed")

    def test_missing_systemctl(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            (host.root / "usr/bin/systemctl").unlink()
            self.check(host, "num_logs", "ABORTED_PRECONDITION_OTHER", "tools:missing:systemctl")


class Compensation(unittest.TestCase):
    def test_wrong_process_name_restores_bytes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, comm=b"bash\n")
            res = host.execute("num_logs")
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "auditd:reload-failed"))
            self.assertTrue(res["mutation_performed"])
            self.assertEqual(host.conf.read_bytes(), DEFAULT)
            self.assertEqual(host.signals, [])
            self.assertIn("COMPENSATION", res["actions_attempted"])

    def test_daemon_stopped_after_reload_is_restarted(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, die_on_hup=True)
            res = host.execute("num_logs")
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "auditd-conf:postcheck-failed"))
            self.assertEqual(host.conf.read_bytes(), DEFAULT)
            self.assertIn(("start", "--", "auditd.service"), host.calls)
            self.assertTrue(host.active)

    def test_write_protocol_refuses_changed_object(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            raw, st, dst = A.observe(str(host.root), "num_logs")
            host.conf.write_bytes(DEFAULT + b"# changed\n")
            with self.assertRaises(A._Changed):
                A._write(str(host.root), b"num_logs = 10\n", st, dst)
            self.assertEqual(host.conf.read_bytes(), DEFAULT + b"# changed\n")
            self.assertFalse(list(host.conf.parent.glob("*.slp-tmp")))


class Regressions(unittest.TestCase):
    """Регрессии: подмена файла после rename, ошибка после rename, повторное перечитывание."""

    def setUp(self):
        self.original_write = A._write
        self.original_postcheck = A._postcheck

    def tearDown(self):
        A._write = self.original_write
        A._postcheck = self.original_postcheck

    def test_b01_file_replaced_after_rename_blocks_reload(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)

            def write(root, data, ref_st, ref_dst):
                new_st = self.original_write(root, data, ref_st, ref_dst)
                other = host.conf.parent / "other"
                other.write_bytes(host.conf.read_bytes())
                os.chmod(other, 0o640)
                os.replace(other, host.conf)
                return new_st

            A._write = write
            res = host.execute("num_logs")
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "auditd-conf:changed-after-rename"))
            self.assertTrue(res["mutation_performed"])
            self.assertNotIn("FINAL_POSTCHECK", res["actions_attempted"])
            self.assertEqual(host.conf.read_bytes(), DEFAULT)
            # Сигнал не посылался ни до, ни после компенсации: новая конфигурация не загружалась.
            self.assertEqual(host.signals, [])

    def test_b02_error_after_rename_is_a_mutation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)

            def write(root, data, ref_st, ref_dst):
                self.original_write(root, data, ref_st, ref_dst)
                os.link(host.conf, host.root / "etc/hardlink")
                raise A._AfterRename("auditd-conf:after-rename-invalid")

            A._write = write
            res = host.execute("num_logs")
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_COMPENSATION", "auditd-conf:after-rename-invalid"))
            self.assertTrue(res["mutation_performed"])
            self.assertEqual(res["transaction_commit"], "NOT_COMMITTED")
            self.assertIn("COMPENSATION", res["actions_attempted"])

    def test_b03_failed_reload_of_restored_config_is_compensation_failure(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            A._postcheck = lambda root, key, new_raw: (None, False)
            calls = []

            def kill(pid, sig):
                calls.append(sig)
                if len(calls) > 1:
                    raise PermissionError("denied")

            res = A.execute_control("FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS", "num_logs", "eq", "10", True,
                                    dry_run=False, privilege_check=lambda: True, _root=str(host.root),
                                    _run=host.run, _kill=kill, _proc=str(host.proc))
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_COMPENSATION", "auditd-conf:postcheck-failed"))
            self.assertEqual(host.conf.read_bytes(), DEFAULT)
            self.assertEqual(len(calls), 2)


class Report(unittest.TestCase):
    def test_report_fields(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            rep = A.control_result_to_report(host.execute("num_logs"), "s", "f")
            self.assertEqual((rep["step_rc"], rep["mechanism_id"], rep["target"]),
                             ("0", "auditd-conf-option-v1", "/etc/audit/auditd.conf"))
            self.assertEqual(A.outcome_rc_contribution("FAILED_COMPENSATION"), "nonzero")


if __name__ == "__main__":
    unittest.main(verbosity=2)
