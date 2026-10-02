#!/usr/bin/env python3
"""Regressions for the auditd-package-service-v1 APPLY mechanism (fstec-logging-2025 приложение 2,
п.1 и п.2; SRC-0050, SRC-0051).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Каждый случай работает на дереве во временном каталоге (`_root`: `usr/bin/dpkg-query`,
`usr/bin/apt-get`, `usr/bin/systemctl`); dpkg, apt и systemd заменены моделью в `_run`. Системные
пути не затрагиваются, root не нужен; временный каталог — внутри репозитория (на ПК /tmp
смонтирован noexec, а адаптер проверяет бит исполнения инструментов). Решение пользователя
30.09.2026: пакет auditd ставится, служба auditd.service включается и запускается.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "product/apply-adapters/product-auditd-package-service-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-auditd-package-service-check-v1.py"
CONTROLS = ROOT / "controls/fstec-core/logging-2025"
PACKAGE_ID = "FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE"
SERVICE_ID = "FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = load(ADAPTER, "slp_auditd_package_service_apply")
C = load(CHECK_ADAPTER, "slp_auditd_package_service_check")


class Host:
    """Модель dpkg, apt-get и systemd для пакета auditd и юнита auditd.service."""

    def __init__(self, td, installed=False, unit=None, install_ok=True, install_starts=True,
                 fail=None, refuse_stop=True, status=None):
        self.root = Path(td)
        (self.root / "usr/bin").mkdir(parents=True)
        for name in ("dpkg-query", "apt-get", "systemctl"):
            tool = self.root / "usr/bin" / name
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            tool.chmod(0o755)
        self.installed = installed
        self.status = status
        # [LoadState, ActiveState, UnitFileState]
        self.unit = list(unit) if unit else (["loaded", "active", "enabled"] if installed else
                                             ["not-found", "inactive", ""])
        self.install_ok = install_ok
        self.install_starts = install_starts
        self.fail = dict(fail or {})
        self.refuse_stop = refuse_stop
        self.calls = []

    def run(self, argv, timeout):
        tool = argv[0]
        self.calls.append(tuple(argv))
        if tool == A.DPKG_QUERY:
            assert argv[1:] == ["-W", "-f=${Status}", "auditd"], argv
            if self.status is not None:
                return subprocess.CompletedProcess(argv, 0, self.status.encode(), b"")
            if self.installed:
                return subprocess.CompletedProcess(argv, 0, b"install ok installed", b"")
            return subprocess.CompletedProcess(argv, 1, b"", b"dpkg-query: no packages found\n")
        if tool == A.APT_GET:
            if argv[-1] == "update":
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            assert argv[-2:] == ["install", "auditd"], argv
            if not self.install_ok:
                return subprocess.CompletedProcess(argv, 100, b"", b"E: unable")
            self.installed, self.status = True, None
            if self.unit[0] == "not-found":
                self.unit = ["loaded", "active", "enabled"] if self.install_starts else ["loaded", "inactive", "disabled"]
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        assert tool == A.SYSTEMCTL, argv
        verb = argv[1]
        if self.fail.get(verb):
            return subprocess.CompletedProcess(argv, 1, b"", b"")
        if verb == "show":
            body = "LoadState=%s\nActiveState=%s\nUnitFileState=%s\n" % tuple(self.unit)
            return subprocess.CompletedProcess(argv, 0, body.encode(), b"")
        assert argv[-1] == "auditd.service", argv
        if verb == "enable":
            if "--runtime" in argv:
                self.unit[2] = "enabled-runtime"
            else:
                self.unit[2] = "enabled"
            if "--now" in argv:
                self.unit[1] = self.fail.get("start-state", "active")
        elif verb == "disable":
            self.unit[2] = "disabled"
        elif verb == "stop":
            if self.refuse_stop:
                return subprocess.CompletedProcess(argv, 1, b"", b"Operation refused")
            self.unit[1] = "inactive"
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def mutating(self):
        return [c for c in self.calls
                if not (c[0] == A.DPKG_QUERY or (c[0] == A.SYSTEMCTL and c[1] == "show"))]


def execute(host, key, dry_run=False, privileged=True):
    cid = PACKAGE_ID if key == "package" else SERVICE_ID
    return A.execute_control(cid, key, "eq", A.SPECS[key], True, dry_run=dry_run,
                             privilege_check=lambda: privileged, _root=str(host.root), _run=host.run)


class Contract(unittest.TestCase):
    def test_specs_and_parser_match_check_adapter(self):
        self.assertEqual(A.SPECS, C.SPECS)
        self.assertEqual(A.PARAMETER_KIND, C.PARAMETER_KIND)
        self.assertEqual(A.PARSER, C.PARSER)
        self.assertEqual((A.PACKAGE, A.UNIT), (C.PACKAGE, C.UNIT))
        self.assertTrue(A.INSTALLS_PACKAGES)

    def test_controls_are_routed(self):
        keys = set()
        for path in sorted(CONTROLS.glob("fstec-logging-2025-appendix2-linux-[12]-*.yaml")):
            text = path.read_text(encoding="utf-8")
            self.assertIn('  kind: "auditd-package-service"\n', text)
            self.assertIn('  locator: "dpkg|systemd"\n', text)
            self.assertIn("apply:\n  supported: true\n", text)
            key = re.search(r'^  key: "([a-z]+)"$', text, re.M).group(1)
            self.assertIn('  op: "eq"\n  value: "%s"\n' % A.SPECS[key], text)
            keys.add(key)
        self.assertEqual(keys, set(A.SPECS))

    def test_closed_inputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            for args in (("package", "eq", "enabled-active"), ("service", "eq", "installed"),
                         ("unit", "eq", "installed"), ("package", "contains", "installed")):
                res = A.execute_control("C", *args, True, dry_run=False, _root=str(host.root), _run=host.run)
                self.assertEqual((res["outcome"], res["reason"]), ("NOT_ELIGIBLE_APPLY_UNSUPPORTED", "op-unsupported"))
            res = A.execute_control("C", "package", "eq", "installed", False, dry_run=False,
                                    _root=str(host.root), _run=host.run)
            self.assertEqual(res["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
            self.assertEqual(host.mutating(), [])
            with self.assertRaises(ValueError):
                A.execute_control("C\n", "package", "eq", "installed", True, dry_run=False)


class Package(unittest.TestCase):
    def test_installed_is_already_compliant(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True)
            res = execute(host, "package")
            self.assertEqual((res["outcome"], res["policy_current"]), ("ALREADY_COMPLIANT", "installed"))
            self.assertEqual(host.mutating(), [])

    def test_missing_package_is_installed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            res = execute(host, "package")
            self.assertEqual(res["outcome"], "APPLIED")
            self.assertEqual(res["policy_current"], "installed")
            self.assertTrue(res["mutation_performed"])
            self.assertEqual(res["transaction_commit"], "COMMITTED")
            self.assertIn("PHASE0_INSTALL_PACKAGE", res["actions_attempted"])
            self.assertEqual([c[-1] for c in host.mutating()], ["auditd"])

    def test_config_files_status_is_reinstalled(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, status="deinstall ok config-files")
            res = execute(host, "package")
            self.assertEqual(res["outcome"], "APPLIED")

    def test_install_failure_retries_after_update(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, install_ok=False)
            res = execute(host, "package")
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "pkg:install-failed"))
            self.assertEqual([c[-1] for c in host.mutating()], ["auditd", "update", "auditd"])

    def test_dry_run_and_privilege(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            res = execute(host, "package", dry_run=True)
            self.assertEqual((res["outcome"], res["policy_current"]), ("DRY_RUN_WOULD_APPLY", "not-installed"))
            res = execute(host, "package", privileged=False)
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
            self.assertEqual(host.mutating(), [])

    def test_missing_tool_refuses(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            (host.root / "usr/bin/apt-get").unlink()
            res = execute(host, "package")
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", "tools:missing:apt-get"))
            self.assertEqual(host.calls, [])

    def test_unknown_status_refuses_before_install(self):
        # Status вне закрытого перечня — отказ без установки.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, status="garbage garbage garbage")
            for key in ("package", "service"):
                res = execute(host, key)
                self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", "dpkg:invalid-output"))
            self.assertEqual(host.mutating(), [])

    def test_masked_unit_refuses_package_install(self):
        # Установка пакета включает службу — замаскированный юнит проверяется до apt-get.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, unit=["masked", "inactive", "masked"])
            res = execute(host, "package")
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "service:masked"))
            self.assertEqual(host.mutating(), [])

    def test_missing_systemctl_refuses_package_install(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            (host.root / "usr/bin/systemctl").unlink()
            res = execute(host, "package")
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", "tools:missing:systemctl"))
            self.assertEqual(host.calls, [])

    def test_query_error_refuses(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, status="garbage")
            res = execute(host, "package")
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_OTHER", "dpkg:invalid-output"))
            self.assertEqual(host.mutating(), [])


class Service(unittest.TestCase):
    def test_enabled_active_is_already_compliant(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True)
            res = execute(host, "service")
            self.assertEqual((res["outcome"], res["policy_current"]), ("ALREADY_COMPLIANT", "enabled/active"))
            self.assertEqual(host.mutating(), [])

    def test_disabled_service_is_enabled_and_started(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True, unit=["loaded", "inactive", "disabled"])
            res = execute(host, "service")
            self.assertEqual((res["outcome"], res["policy_current"]), ("APPLIED", "enabled/active"))
            self.assertEqual(host.mutating(), [(A.SYSTEMCTL, "enable", "--now", "--", "auditd.service")])
            self.assertIn("PHASE1_ENABLE_START", res["actions_attempted"])

    def test_missing_package_install_starts_service(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            res = execute(host, "service")
            self.assertEqual((res["outcome"], res["policy_current"]), ("APPLIED", "enabled/active"))
            self.assertEqual([c[1] for c in host.mutating()], ["-q"])
            self.assertNotIn("PHASE1_ENABLE_START", res["actions_attempted"])

    def test_missing_package_then_enable(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, install_starts=False)
            res = execute(host, "service")
            self.assertEqual(res["outcome"], "APPLIED")
            self.assertEqual(host.mutating()[-1], (A.SYSTEMCTL, "enable", "--now", "--", "auditd.service"))

    def test_masked_unit_is_admin_decision(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True, unit=["masked", "inactive", "masked"])
            res = execute(host, "service")
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "service:masked"))
            self.assertEqual(res["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
            self.assertEqual(host.mutating(), [])

    def test_unit_missing_with_package_is_admin_decision(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True, unit=["not-found", "inactive", ""])
            res = execute(host, "service")
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "service:unit-missing"))
            self.assertEqual(host.mutating(), [])

    def test_unknown_unit_states_refuse(self):
        # Пустой или неизвестный ActiveState, неизвестный UnitFileState — отказ без enable.
        for unit in (["loaded", "", "disabled"], ["loaded", "bogus", "disabled"], ["loaded", "inactive", "bogus"],
                     ["loaded", "inactive", ""]):
            with self.subTest(unit=unit):
                with tempfile.TemporaryDirectory(dir=ROOT) as td:
                    host = Host(td, installed=True, unit=unit)
                    res = execute(host, "service")
                    self.assertEqual((res["outcome"], res["reason"]),
                                     ("ABORTED_PRECONDITION_OTHER", "systemd:invalid-output"))
                    self.assertEqual(host.mutating(), [])

    def test_static_unit_is_admin_decision(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True, unit=["loaded", "active", "static"])
            res = execute(host, "service")
            self.assertEqual((res["outcome"], res["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "service:unit-file-state"))
            self.assertEqual(host.mutating(), [])

    def test_enable_failure_compensates_exactly(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True, unit=["loaded", "active", "disabled"], fail={"enable": True})
            res = execute(host, "service")
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "systemctl:enable-failed"))
            self.assertEqual(host.unit, ["loaded", "active", "disabled"])

    def test_start_failure_restores_disabled_state(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True, unit=["loaded", "inactive", "disabled"], fail={"start-state": "failed"})
            res = execute(host, "service")
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "service:postcheck-failed"))
            self.assertEqual(host.unit[2], "disabled")
            self.assertIn("COMPENSATION", res["actions_attempted"])

    def test_runtime_enabled_state_is_restored(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True, unit=["loaded", "inactive", "enabled-runtime"],
                        fail={"start-state": "failed"}, refuse_stop=False)
            res = execute(host, "service")
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "service:postcheck-failed"))
            self.assertEqual(host.unit, ["loaded", "inactive", "enabled-runtime"])
            self.assertEqual([c[1:-2] for c in host.mutating()],
                             [("enable", "--now"), ("disable",), ("enable", "--runtime"), ("stop",)])

    def test_failed_start_of_running_service_is_compensation_failure(self):
        # Служба работала, но не была включена; после enable --now она в состоянии failed:
        # прежнюю активность компенсация не возвращает — FAILED_COMPENSATION.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True, unit=["loaded", "active", "disabled"], fail={"start-state": "failed"})
            res = execute(host, "service")
            self.assertEqual(res["outcome"], "FAILED_COMPENSATION")
            self.assertEqual(host.unit[2], "disabled")

    def test_refused_stop_is_compensation_failure(self):
        # Postcheck видит службу запущенной, но не включённой — нужна компенсация; остановка
        # auditd.service запрещена (RefuseManualStop): исход FAILED_COMPENSATION.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True, unit=["loaded", "inactive", "disabled"])
            original = host.run

            def run(argv, timeout):
                cp = original(argv, timeout)
                if argv[0] == A.SYSTEMCTL and argv[1] == "enable" and "--now" in argv:
                    host.unit[2] = "disabled"
                return cp

            res = A.execute_control(SERVICE_ID, "service", "eq", "enabled-active", True, dry_run=False,
                                    privilege_check=lambda: True, _root=str(host.root), _run=run)
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_COMPENSATION", "service:postcheck-failed"))
            self.assertEqual(host.unit[1], "active")

    def test_install_failure_leaves_unit_alone(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, install_ok=False)
            res = execute(host, "service")
            self.assertEqual((res["outcome"], res["reason"]), ("FAILED_NOT_COMMITTED", "pkg:install-failed"))
            self.assertFalse(any(c[0] == A.SYSTEMCTL and c[1] != "show" for c in host.calls))

    def test_dry_run_plans_without_mutation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td, installed=True, unit=["loaded", "inactive", "disabled"])
            res = execute(host, "service", dry_run=True)
            self.assertEqual((res["outcome"], res["policy_current"]), ("DRY_RUN_WOULD_APPLY", "disabled/inactive"))
            self.assertEqual(host.mutating(), [])


class Report(unittest.TestCase):
    def test_report_fields(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            host = Host(td)
            res = execute(host, "package")
            rep = A.control_result_to_report(res, "s", "f")
            self.assertEqual(rep["step_rc"], "0")
            self.assertEqual(rep["mechanism_id"], "auditd-package-service-v1")
            self.assertEqual(rep["target"], "auditd")
            self.assertEqual(A.outcome_rc_contribution("FAILED_NOT_COMMITTED"), "nonzero")
            self.assertEqual(A.outcome_rc_contribution("DRY_RUN_WOULD_APPLY", True), "0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
