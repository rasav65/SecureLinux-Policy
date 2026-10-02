#!/usr/bin/env python3
"""Regressions for the network-service-mask-v1 APPLY mechanism (fstec-configuration-2026 п.11.2).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Каждый случай работает на дереве во временном каталоге (`_root`: `proc/net/*`,
`usr/bin/systemctl`); systemd заменён моделью в `_run`. Системные пути не затрагиваются,
root не нужен; временный каталог — внутри репозитория (на ПК /tmp смонтирован noexec,
а адаптер проверяет бит исполнения systemctl). Решение пользователя 26.09.2026: службы Telnet, FTP и SNMP останавливаются и
маскируются; порт вне известных юнитов и юнит из /etc/systemd/system — решение администратора.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "product/apply-adapters/product-network-service-mask-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-network-service-disabled-check-v1.py"
CONTROLS = ROOT / "controls/fstec-core/configuration-2026"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = load(ADAPTER, "slp_network_service_mask_apply")
C = load(CHECK_ADAPTER, "slp_network_service_disabled_check")
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
HEADER6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
PORT = {"vsftpd.service": ("tcp", 21), "proftpd.service": ("tcp", 21), "snmpd.service": ("udp", 161),
        "inetd.service": ("tcp", 23)}


def row(port, state):
    return ("   0: 00000000:%04X 00000000:0000 %s 00000000:00000000 00:00000000 00000000     0        0 1 1 "
            "0000000000000000 100 0 0 10 0\n" % (port, state))


class Systemd:
    """Модель systemd: юниты, их состояния и сокеты, которые открывает активный юнит."""

    def __init__(self, td, units=None, fail=None):
        self.root = Path(td)
        (self.root / "proc/net").mkdir(parents=True)
        (self.root / "usr/bin").mkdir(parents=True)
        tool = self.root / "usr/bin/systemctl"
        tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        tool.chmod(0o755)
        # unit: [LoadState, ActiveState, UnitFileState, FragmentPath]
        self.units = {name: list(state) for name, state in (units or {}).items()}
        self.fail = dict(fail or {})
        self.calls = []
        self.extra_listeners = []
        self.sync()

    def sync(self):
        text = {"tcp": HEADER, "udp": HEADER}
        for unit, state in self.units.items():
            if state[1] == "active" and unit in PORT:
                proto, port = PORT[unit]
                text[proto] += row(port, "0A" if proto == "tcp" else "07")
        for proto, port in self.extra_listeners:
            text[proto] += row(port, "0A" if proto == "tcp" else "07")
        for proto, body in text.items():
            (self.root / "proc/net" / proto).write_text(body, encoding="ascii")

    def run(self, argv, timeout):
        assert argv[0] == A.SYSTEMCTL, argv
        verb, unit = argv[1], argv[-1]
        self.calls.append((verb, unit))
        if self.fail.get(verb) == unit or self.fail.get(verb) == "*":
            return subprocess.CompletedProcess(argv, 1, b"", b"")
        state = self.units.get(unit)
        if verb == "show":
            if state is None:
                state = ["not-found", "inactive", "", ""]
            body = "LoadState=%s\nActiveState=%s\nUnitFileState=%s\nFragmentPath=%s\n" % tuple(state)
            return subprocess.CompletedProcess(argv, 0, body.encode(), b"")
        if state is None:
            return subprocess.CompletedProcess(argv, 5, b"", b"")
        if verb == "disable":
            assert argv[2] == "--now"
            state[1], state[2] = "inactive", "disabled"
        elif verb == "mask":
            state[0], state[2] = "masked", "masked"
        elif verb == "unmask":
            if state[0] == "masked":
                state[0], state[2] = "loaded", "disabled"
        elif verb == "enable":
            state[2] = "enabled-runtime" if "--runtime" in argv else "enabled"
        elif verb == "start":
            state[1] = "active"
        elif verb == "stop":
            state[1] = "inactive"
        else:
            raise AssertionError(argv)
        self.sync()
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def mutating(self):
        return [c for c in self.calls if c[0] != "show"]


def execute(sd, key, dry_run=False, privileged=True):
    return A.execute_control("FSTEC-CONFIGURATION-2026-11.2-" + key.upper(), key, "eq", "disabled", True,
                             dry_run=dry_run, privilege_check=lambda: privileged,
                             _root=str(sd.root), _run=sd.run)


VSFTPD_ON = {"vsftpd.service": ("loaded", "active", "enabled", "/usr/lib/systemd/system/vsftpd.service")}


class Contract(unittest.TestCase):
    def test_services_match_check_adapter(self):
        self.assertEqual(A.SERVICES, C.SERVICES)
        self.assertEqual(A.ACTIVE_STATES, C.ACTIVE_STATES)
        self.assertEqual(A.ENABLED_STATES, C.ENABLED_STATES)
        self.assertEqual(A.PARAMETER_KIND, C.PARAMETER_KIND)

    def test_controls_are_routed(self):
        keys = set()
        for path in sorted(CONTROLS.glob("fstec-configuration-2026-11.2-*.yaml")):
            text = path.read_text(encoding="utf-8")
            self.assertIn('  kind: "network-service-disabled"\n', text)
            self.assertIn('  locator: "systemd|/proc/net"\n', text)
            self.assertIn('  op: "eq"\n  value: "disabled"\n', text)
            self.assertIn("apply:\n  supported: true\n", text)
            keys.add(re.search(r'^  key: "([a-z]+)"$', text, re.M).group(1))
        self.assertEqual(keys, set(A.SERVICES))

    def test_unsupported_inputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON)
            for key, op, value in (("ssh", "eq", "disabled"), ("ftp", "contains", "disabled"), ("ftp", "eq", "masked")):
                r = A.execute_control("C", key, op, value, True, dry_run=False, _root=str(sd.root), _run=sd.run)
                self.assertEqual((r["outcome"], r["reason"]), ("NOT_ELIGIBLE_APPLY_UNSUPPORTED", "op-unsupported"))
            r = A.execute_control("C", "ftp", "eq", "disabled", False, dry_run=False, _root=str(sd.root), _run=sd.run)
            self.assertEqual(r["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
            self.assertEqual(sd.calls, [])
            with self.assertRaises(ValueError):
                A.execute_control("C\n", "ftp", "eq", "disabled", True, dry_run=False)


class Apply(unittest.TestCase):
    def test_absent_service_is_compliant(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td)
            for key in A.SERVICES:
                r = execute(sd, key)
                self.assertEqual((r["outcome"], r["policy_current"]), ("ALREADY_COMPLIANT", "units=-;listeners=-"))
            self.assertEqual(sd.mutating(), [])

    def test_masked_and_disabled_units_are_compliant(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"vsftpd.service": ("masked", "inactive", "masked", ""),
                              "proftpd.service": ("loaded", "inactive", "disabled", "/usr/lib/systemd/system/p")})
            self.assertEqual(execute(sd, "ftp")["outcome"], "ALREADY_COMPLIANT")
            self.assertEqual(sd.mutating(), [])

    def test_active_service_is_stopped_and_masked(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON)
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["mutation_performed"], r["transaction_commit"]),
                             ("APPLIED", True, "COMMITTED"))
            self.assertEqual(sd.mutating(), [("disable", "vsftpd.service"), ("mask", "vsftpd.service")])
            self.assertEqual(sd.units["vsftpd.service"][:3], ["masked", "inactive", "masked"])
            self.assertEqual(r["policy_current"], "units=-;listeners=-")
            self.assertEqual(A.outcome_rc_contribution(r["outcome"]), "0")
            self.assertEqual(execute(sd, "ftp")["outcome"], "ALREADY_COMPLIANT")

    def test_masked_but_running_unit_is_stopped(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"vsftpd.service": ("masked", "active", "masked", "")})
            r = execute(sd, "ftp", dry_run=True)
            self.assertEqual((r["outcome"], r["policy_current"]),
                             ("DRY_RUN_WOULD_APPLY", "units=vsftpd.service:active/masked;listeners=21/tcp"))
            r = execute(sd, "ftp")
            self.assertEqual(r["outcome"], "APPLIED")
            self.assertEqual(sd.mutating(), [("stop", "vsftpd.service")])
            self.assertEqual(sd.units["vsftpd.service"][:3], ["masked", "inactive", "masked"])

    def test_masked_stop_failure_is_restored(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"vsftpd.service": ("masked", "active", "masked", "")}, fail={"stop": "vsftpd.service"})
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "systemctl:stop-failed"))
            self.assertEqual(sd.units["vsftpd.service"][:3], ["masked", "active", "masked"])

    def test_not_found_but_running_unit_is_stopped(self):
        # Юнит без файла, но активный — не соответствует.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"snmpd.service": ("not-found", "active", "", "")})
            r = execute(sd, "snmp", dry_run=True)
            self.assertEqual((r["outcome"], r["policy_current"]),
                             ("DRY_RUN_WOULD_APPLY", "units=snmpd.service:active/-;listeners=161/udp"))
            r = execute(sd, "snmp")
            self.assertEqual(r["outcome"], "APPLIED")
            self.assertEqual(sd.mutating(), [("stop", "snmpd.service")])
            self.assertEqual(sd.units["snmpd.service"][:2], ["not-found", "inactive"])

    def test_runtime_enable_is_restored_exactly(self):
        # enabled-runtime восстанавливается enable --runtime.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"vsftpd.service": ("loaded", "active", "enabled-runtime", "/usr/lib/systemd/system/v")},
                         fail={"mask": "vsftpd.service"})
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "systemctl:mask-failed"))
            self.assertEqual(sd.units["vsftpd.service"][:3], ["loaded", "active", "enabled-runtime"])
            self.assertIn(("enable", "vsftpd.service"), sd.mutating())

    def test_inexact_restore_is_failed_compensation(self):
        # linked точно не восстанавливается: enable даёт enabled — FAILED_COMPENSATION.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"vsftpd.service": ("loaded", "active", "linked", "/usr/lib/systemd/system/v")},
                         fail={"mask": "vsftpd.service"})
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_COMPENSATION", "systemctl:mask-failed"))
            self.assertEqual(sd.units["vsftpd.service"][2], "enabled")

    def test_enabled_inactive_service_is_masked(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"snmpd.service": ("loaded", "inactive", "enabled", "/usr/lib/systemd/system/snmpd.service")})
            r = execute(sd, "snmp")
            self.assertEqual(r["outcome"], "APPLIED")
            self.assertEqual(sd.units["snmpd.service"][0], "masked")

    def test_dry_run_and_privilege_do_not_mutate(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON)
            r = execute(sd, "ftp", dry_run=True)
            self.assertEqual((r["outcome"], r["policy_current"]),
                             ("DRY_RUN_WOULD_APPLY", "units=vsftpd.service:active/enabled;listeners=21/tcp"))
            self.assertEqual(A.outcome_rc_contribution(r["outcome"], True), "0")
            r = execute(sd, "ftp", privileged=False)
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("ABORTED_PRECONDITION_OTHER", "privilege", False))
            self.assertEqual(sd.mutating(), [])

    def test_listener_without_known_unit_needs_admin(self):
        # telnet через inetd: порт 23 открыт, известных юнитов нет.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"inetd.service": ("loaded", "active", "enabled", "/usr/lib/systemd/system/inetd.service")})
            r = execute(sd, "telnet")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "service:unmanaged-listener"))
            self.assertEqual(r["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
            self.assertIn("23/tcp", r["operator_decision"]["action"])
            self.assertEqual((r["mutation_performed"], r["policy_current"]), (False, "units=-;listeners=23/tcp"))
            self.assertEqual(sd.mutating(), [])

    def test_admin_unit_file_needs_admin(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"vsftpd.service": ("loaded", "active", "enabled", "/etc/systemd/system/vsftpd.service")})
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "service:admin-unit-file"))
            self.assertIn("/etc/systemd/system/vsftpd.service", r["operator_decision"]["action"])
            self.assertEqual(sd.mutating(), [])

    def test_unit_load_error_and_query_failure_are_refused(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"snmpd.service": ("bad-setting", "inactive", "", "")})
            r = execute(sd, "snmp")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "systemd:unit-load-bad-setting"))
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON, fail={"show": "*"})
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "systemd:query-failed"))
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON)
            (sd.root / "usr/bin/systemctl").unlink()
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "tools:missing:systemctl"))
            self.assertEqual(sd.calls, [])

    def test_proc_net_errors_are_refused(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON)
            for bad in ("garbage\n", "sl\n", "  sl  local_address\n"):
                # Неполный заголовок — ошибка, а не «нет слушателей».
                (sd.root / "proc/net/tcp").write_text(bad, encoding="ascii")
                r = execute(sd, "ftp")
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "proc-net:invalid-header"))
            (sd.root / "proc/net/tcp").unlink()
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "proc-net:read-failed"))
            self.assertEqual(sd.mutating(), [])

    def test_ipv6_listener_counts(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td)
            (sd.root / "proc/net/tcp6").write_text(
                HEADER6 + "   0: 00000000000000000000000000000000:0015 00000000000000000000000000000000:0000 0A "
                "00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n",
                encoding="ascii")
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["policy_current"]), ("ABORTED_PRECONDITION_CONFLICT", "units=-;listeners=21/tcp"))
            # Заголовок IPv4 в tcp6 — ошибка разбора (у IPv6 поле remote_address).
            (sd.root / "proc/net/tcp6").write_text(HEADER, encoding="ascii")
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "proc-net:invalid-header"))

    def test_mask_failure_restores_previous_state(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON, fail={"mask": "vsftpd.service"})
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"], r["transaction_commit"]),
                             ("FAILED_NOT_COMMITTED", "systemctl:mask-failed", True, "NOT_COMMITTED"))
            self.assertEqual(sd.units["vsftpd.service"][:3], ["loaded", "active", "enabled"])
            self.assertEqual(sd.mutating(), [("disable", "vsftpd.service"), ("mask", "vsftpd.service"),
                                             ("unmask", "vsftpd.service"), ("enable", "vsftpd.service"),
                                             ("start", "vsftpd.service")])

    def test_second_unit_failure_restores_both(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, {"vsftpd.service": ("loaded", "active", "enabled", "/usr/lib/systemd/system/v"),
                              "proftpd.service": ("loaded", "inactive", "enabled", "/usr/lib/systemd/system/p")},
                         fail={"disable": "proftpd.service"})
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "systemctl:disable-failed"))
            self.assertEqual(sd.units["vsftpd.service"][:3], ["loaded", "active", "enabled"])
            self.assertEqual(sd.units["proftpd.service"][:3], ["loaded", "inactive", "enabled"])

    def test_failed_restore_is_failed_compensation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON, fail={"mask": "vsftpd.service", "start": "vsftpd.service"})
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_COMPENSATION", "systemctl:mask-failed", True))
            self.assertEqual(A.outcome_rc_contribution(r["outcome"]), "nonzero")

    def test_postcheck_failure_is_compensated(self):
        # systemctl mask сообщает успех, а юнит остаётся активным.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON)
            real = sd.run

            def run(argv, timeout):
                cp = real(argv, timeout)
                if argv[1] == "mask":
                    sd.units[argv[-1]][1] = "active"
                    sd.sync()
                return cp

            r = A.execute_control("C", "ftp", "eq", "disabled", True, dry_run=False, privilege_check=lambda: True,
                                  _root=str(sd.root), _run=run)
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "service:postcheck-failed"))
            self.assertEqual(sd.units["vsftpd.service"][:3], ["loaded", "active", "enabled"])

    def test_foreign_listener_after_mask_is_visible(self):
        # Порт держит другой процесс: юнит маскирован, порт виден в policy_current.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON)
            sd.extra_listeners = [("tcp", 21)]
            sd.sync()
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["policy_current"]), ("APPLIED", "units=-;listeners=21/tcp"))
            r = execute(sd, "ftp")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "service:unmanaged-listener"))

    def test_report_fields(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            sd = Systemd(td, VSFTPD_ON)
            rep = A.control_result_to_report(execute(sd, "ftp"), "s", "f")
            self.assertEqual(rep["outcome"], "APPLIED")
            self.assertEqual(rep["step_rc"], "0")
            self.assertEqual((rep["target"], rep["mechanism_id"]), ("systemd", "network-service-mask-v1"))
            self.assertEqual(set(rep), {"adapter_id", "mechanism_id", "control_id", "target", "outcome", "reason",
                                        "policy_current", "operator_decision", "started_at", "finished_at",
                                        "actions_attempted", "step_rc", "mutation_performed", "transaction_commit"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
