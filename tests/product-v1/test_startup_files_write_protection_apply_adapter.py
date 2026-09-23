#!/usr/bin/env python3
"""Failing-first regressions for the startup-files-write-protection APPLY mechanism (G6-startup-files).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on trees created inside a temporary directory owned by the
current user and passed to the adapter as the rc and unit roots (`_layout`),
as the CHECK adapter does through `_shell_function_for_layout`. No system path
is touched and root is not required: the privilege check and the fchmod call
are injected where a case needs them.

Принятые решения (человек), которые фиксирует этот файл:

* `apply_kind` `startup-files-write-protection-v1` обслуживает `parameter_kind`
  `startup-files-write-protection` (контроль
  `2.3.5-STARTUP-FILES-WRITE-PROTECTION`, `other-write bits-clear 0002`).
* Образец — `standard-system-paths-mode-v1`: популяция из фиксированных корней
  плюс корней, вычисляемых на хосте, симлинк разрешается в конечную цель,
  дедупликация целей по `dev:ino`.
* Популяция применения = популяция проверки 2.3.5: перечислитель —
  Python-копия CHECK-наблюдателя `product-startup-files-write-protection-check-v1`;
  паритет проверяется исполнением самого CHECK-адаптера на тех же корнях.
  Объект — разрешённая цель записи (семантика `chmod o-w` по симлинку);
  маскированный `.service` (цепочка до `/dev/null`) в популяцию не входит.
* Снимается только бит `0002`; прочие биты, владелец и группа не меняются.
  Запись — один `fchmod` на дескрипторе, открытом с `O_NOFOLLOW`; перед ним
  ревалидация строго в порядке `S_ISREG` → `dev/ino` из плана → бит `0002`,
  несовпадение — пропуск с причиной `not-regular`, `identity-drift` или
  `no-violation-bits`. `st_nlink > 1` — пропуск с записью.
* Исходы и причины — словарь образца: ошибка CHECK-популяции — отказ контроля
  без мутаций; применено что-то и есть пропуски — `APPLIED_PARTIAL`; применять
  нечего, кроме пропусков — `ABORTED_PRECONDITION_CONFLICT`; `EROFS` и
  отсутствие привилегии останавливают сразу. Dry-run не мутирует.

Адаптера ещё нет: этот файл описывает контракт, которому он обязан
удовлетворять. Пока адаптера нет, каждый класс падает на импорте.
"""

from __future__ import annotations

import errno
import importlib.util
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]

ADAPTER = ROOT / "product/apply-adapters/product-startup-files-write-protection-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-startup-files-write-protection-check-v1.py"
CONTROL_YAML = ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.5-startup-files-write-protection.yaml"

APPLY_KIND = "startup-files-write-protection-v1"
PARAMETER_KIND = "startup-files-write-protection"
ADAPTER_ID = "product-startup-files-write-protection-apply-v1"
TARGET_ID = "linux-x86_64-supported-v1"
KEY = "other-write"
MASK = "0002"

CID = "FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION"

# Поля записи, которые читает встроенный dispatcher (как у file-mode-owner).
DISPATCHER_FIELDS = {
    "control_id", "outcome", "reason", "actions_attempted", "step_rc",
    "mutation_performed", "transaction_commit", "started_at", "finished_at",
}

BASH = shutil.which("bash")


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_adapter():
    return load_module(ADAPTER, "slp_startup_files_apply")


def load_check():
    return load_module(CHECK_ADAPTER, "slp_startup_files_check")


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def check_observation(rc_roots, unit_paths):
    """(status, value) из встроенного CHECK-адаптера, исполненного bash на тех же корнях."""
    check = load_check()
    src = check._shell_function_for_layout(
        "CTRL", [str(x) for x in rc_roots], [str(x) for x in unit_paths], MASK
    )
    proc = subprocess.run(
        [BASH, "-c", "set -u\n" + src + "\nslp_check_CTRL\n"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120,
    )
    fields = proc.stdout.rstrip("\n").split("\t")
    if proc.returncode != 0 or len(fields) != 5:
        raise AssertionError(f"CHECK failed: rc={proc.returncode} out={proc.stdout!r} err={proc.stderr!r}")
    return fields[2], fields[3]


class _Tree(unittest.TestCase):
    """Дерево-фикстура: rc-корень, корень юнитов и каталог скриптов вне обоих."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="slp-startup-apply-")
        self.adapter = load_adapter()
        self.rc = os.path.join(self.tmp, "rc3.d")
        self.units = os.path.join(self.tmp, "units")
        self.initd = os.path.join(self.tmp, "init.d")
        for d in (self.rc, self.units, self.initd):
            os.mkdir(d)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- фикстуры ---------------------------------------------------------

    def make_file(self, path, mode, content=None):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content if content is not None else os.path.basename(path) + "\n")
        os.chmod(path, mode)
        return path

    def baseline(self, rc_mode=0o755, service_mode=0o644, script_mode=0o755):
        """rc-элемент-файл, rc-симлинк на скрипт вне корней и два .service."""
        rc_file = self.make_file(os.path.join(self.rc, "S01local"), rc_mode)
        script = self.make_file(os.path.join(self.initd, "demo"), script_mode)
        os.symlink(script, os.path.join(self.rc, "S02demo"))
        svc_a = self.make_file(os.path.join(self.units, "a.service"), service_mode)
        svc_b = self.make_file(os.path.join(self.units, "b.service"), 0o644)
        return rc_file, script, svc_a, svc_b

    def layout(self, rc_roots=None, unit_paths=None):
        rc_roots = [self.rc] if rc_roots is None else [str(x) for x in rc_roots]
        unit_paths = [self.units] if unit_paths is None else [str(x) for x in unit_paths]
        return rc_roots, unit_paths

    def counting_fchmod(self, calls, before=None):
        def fchmod(fd, mode, path):
            calls.append(path)
            if before is not None:
                before(path)
            os.fchmod(fd, mode)
        return fchmod

    def run_apply(self, *, layout=None, dry_run=False, privilege=True, fchmod=None):
        kwargs = {
            "dry_run": dry_run,
            "privilege_check": lambda: privilege,
            "_layout": self.layout() if layout is None else layout,
        }
        if fchmod is not None:
            kwargs["_fchmod"] = fchmod
        return self.adapter.execute_control(CID, KEY, "bits-clear", MASK, True, **kwargs)


class T01_Identity(unittest.TestCase):
    def test_module_identity_and_api(self):
        mod = load_adapter()
        self.assertEqual(mod.ADAPTER_ID, ADAPTER_ID)
        self.assertEqual(mod.MECHANISM_ID, APPLY_KIND)
        self.assertEqual(mod.PARAMETER_KIND, PARAMETER_KIND)
        self.assertEqual(mod.TARGET_ID, TARGET_ID)
        self.assertEqual(mod.EXPECTED_MASK, MASK)
        self.assertIn("APPLIED_PARTIAL", mod.OUTCOMES)
        self.assertIn("NOT_ELIGIBLE_APPLY_UNSUPPORTED", mod.OUTCOMES)
        for fn in ("execute_control", "control_result_to_report", "observe",
                   "canonical_rc_roots", "validate_control_input"):
            self.assertTrue(callable(getattr(mod, fn, None)), fn)

    def test_outcome_vocabulary_is_the_one_of_the_template(self):
        """Словарь исходов — ровно словарь образца standard-system-paths-mode-v1."""
        mod = load_adapter()
        template = load_module(
            ROOT / "product/apply-adapters/product-standard-system-paths-mode-apply-v1.py",
            "slp_standard_paths_apply_template",
        )
        self.assertEqual(mod.OUTCOMES, template.OUTCOMES)

    def test_target_table_is_the_control_locator(self):
        mod = load_adapter()
        text = CONTROL_YAML.read_text(encoding="utf-8")
        self.assertIn(f'kind: "{PARAMETER_KIND}"', text)
        locator = re.search(r'\nparameter:\n  kind: "[^"]*"\n  locator: "([^"]*)"', text).group(1)
        self.assertEqual(mod.TARGETS, {CID: locator})
        self.assertIn(f'key: "{KEY}"', text)
        self.assertIn('op: "bits-clear"', text)
        self.assertIn(f'value: "{MASK}"', text)

    def test_canonical_roots_are_parsed_from_the_locator_not_literals(self):
        """Разбор локатора обязан совпасть с константами CHECK-адаптера."""
        mod = load_adapter()
        check = load_check()
        self.assertEqual(mod.TARGETS[CID], check.CANONICAL_LOCATOR)
        self.assertEqual(tuple(mod.canonical_rc_roots(mod.TARGETS[CID])), check.CANONICAL_RC_ROOTS)
        self.assertEqual(mod.SYSTEMD_ANALYZE, check.DEFAULT_SYSTEMD_ANALYZE)
        for bad in ("/etc/rc#.d|systemd-unit-paths", "/etc/rc[0-6].d", "/etc/rc[0-6].d|other"):
            with self.subTest(locator=bad), self.assertRaises(ValueError):
                mod.canonical_rc_roots(bad)

    def test_invalid_control_id_is_rejected(self):
        mod = load_adapter()
        with self.assertRaises(ValueError):
            mod.validate_control_input("bad id\n", KEY, "bits-clear", MASK, True)


@unittest.skipIf(BASH is None, "bash not available")
class T02_EnumeratorParity(_Tree):
    """APPLY-перечислитель и CHECK-адаптер дают одно и то же (status, value)."""

    def assert_parity(self, rc_roots=None, unit_paths=None):
        rc_roots, unit_paths = self.layout(rc_roots, unit_paths)
        self.assertEqual(
            tuple(self.adapter.observe(rc_roots, unit_paths)),
            check_observation(rc_roots, unit_paths),
        )

    def test_compliant_baseline(self):
        self.baseline()
        self.assert_parity()

    def test_violation_in_each_role(self):
        rc_file, script, svc_a, _svc_b = self.baseline()
        for path in (rc_file, script, svc_a):
            with self.subTest(path=path):
                before = mode_of(path)
                os.chmod(path, before | 0o002)
                self.assert_parity()
                os.chmod(path, before)

    def test_masked_service_dependency_dir_and_non_service_names(self):
        self.baseline()
        os.symlink("/dev/null", os.path.join(self.units, "masked.service"))
        wants = os.path.join(self.units, "multi-user.target.wants")
        self.make_file(os.path.join(wants, "ignored.service"), 0o666)
        self.make_file(os.path.join(self.units, "demo.timer"), 0o666)
        self.assert_parity()

    def test_rc_subdirectory_is_skipped(self):
        self.baseline()
        os.mkdir(os.path.join(self.rc, "subdir"))
        self.make_file(os.path.join(self.rc, "subdir", "inner"), 0o666)
        self.assert_parity()

    def test_symlink_and_hardlink_share_one_target(self):
        _rc_file, script, _a, _b = self.baseline(script_mode=0o757)
        os.symlink(script, os.path.join(self.rc, "K01demo"))
        os.link(script, os.path.join(self.rc, "S03hard"))
        self.assert_parity()

    def test_absent_rc_root_and_alias_unit_root(self):
        self.baseline(service_mode=0o646)
        alias = os.path.join(self.tmp, "units-alias")
        os.symlink(self.units, alias)
        absent = os.path.join(self.tmp, "rc5.d")
        self.assert_parity(rc_roots=[self.rc, absent], unit_paths=[self.units, alias, os.path.join(self.tmp, "none")])

    def test_empty_population_is_determinate(self):
        self.assert_parity()

    def test_dangling_symlink_is_error(self):
        self.baseline()
        os.symlink(os.path.join(self.tmp, "missing"), os.path.join(self.units, "bad.service"))
        self.assert_parity()

    def test_symlink_to_directory_is_error(self):
        self.baseline()
        os.symlink(self.initd, os.path.join(self.rc, "S09dir"))
        self.assert_parity()

    def test_aliased_rc_roots_are_error(self):
        self.baseline()
        alias = os.path.join(self.tmp, "rc4.d")
        os.symlink(self.rc, alias)
        self.assert_parity(rc_roots=[self.rc, alias])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "mkfifo not available")
    def test_special_file_is_error(self):
        self.baseline()
        os.mkfifo(os.path.join(self.units, "pipe.service"))
        self.assert_parity()


class T03_NoMutationWhenCompliant(_Tree):
    def test_all_objects_without_0002_mutate_nothing(self):
        rc_file, script, svc_a, svc_b = self.baseline()
        group_writable = self.make_file(os.path.join(self.units, "c.service"), 0o664)
        before = {p: os.lstat(p) for p in (rc_file, script, svc_a, svc_b, group_writable)}
        calls = []
        result = self.run_apply(fchmod=self.counting_fchmod(calls))
        self.assertEqual(result["outcome"], "ALREADY_COMPLIANT")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(calls, [])
        for path, st in before.items():
            now = os.lstat(path)
            self.assertEqual((now.st_mode, now.st_ctime_ns), (st.st_mode, st.st_ctime_ns), path)


class T04_Execute(_Tree):
    def test_one_service_0646_becomes_0644_others_untouched(self):
        rc_file, script, svc_a, svc_b = self.baseline(service_mode=0o646)
        group_writable = self.make_file(os.path.join(self.units, "c.service"), 0o664)
        untouched = {p: os.lstat(p) for p in (rc_file, script, svc_b, group_writable)}
        before = os.lstat(svc_a)
        calls = []
        result = self.run_apply(fchmod=self.counting_fchmod(calls))
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertIs(result["mutation_performed"], True)
        self.assertEqual(result["applied"], [svc_a])
        self.assertEqual(calls, [svc_a])
        self.assertEqual(mode_of(svc_a), 0o644)
        now = os.lstat(svc_a)
        self.assertEqual((now.st_uid, now.st_gid, now.st_ino), (before.st_uid, before.st_gid, before.st_ino))
        for path, st in untouched.items():
            now = os.lstat(path)
            self.assertEqual((now.st_mode, now.st_ctime_ns), (st.st_mode, st.st_ctime_ns), path)
        report = self.adapter.control_result_to_report(result, "t0", "t1")
        self.assertTrue(DISPATCHER_FIELDS <= set(report), sorted(DISPATCHER_FIELDS - set(report)))
        self.assertEqual(report["step_rc"], "0")
        self.assertEqual(report["transaction_commit"], "COMMITTED")

    @unittest.skipIf(BASH is None, "bash not available")
    def test_rc3_symlink_to_script_0757_follows_check_verdict(self):
        """CHECK оценивает конечную цель симлинка; APPLY меняет ту же цель."""
        _rc_file, script, _a, _b = self.baseline()
        os.chmod(script, 0o757)
        link = os.path.join(self.rc, "S02demo")
        status, value = check_observation(*self.layout())
        self.assertEqual(status, "VALUE")
        self.assertTrue(value.endswith(";checked=4;violations=1"), value)
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertEqual(result["applied"], [script])
        self.assertEqual(mode_of(script), 0o755)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.readlink(link), script)
        status, value = check_observation(*self.layout())
        self.assertTrue(value.endswith(";checked=4;violations=0"), value)

    def test_clears_only_0002_and_keeps_other_bits(self):
        rc_file, script, svc_a, _b = self.baseline(rc_mode=0o4757, service_mode=0o666, script_mode=0o2777)
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertEqual(mode_of(rc_file), 0o4755)
        self.assertEqual(mode_of(script), 0o2775)
        self.assertEqual(mode_of(svc_a), 0o664)
        for path in (rc_file, script, svc_a):
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), os.path.basename(path) + "\n")

    def test_masked_service_is_never_a_target(self):
        self.baseline(service_mode=0o646)
        os.symlink("/dev/null", os.path.join(self.units, "masked.service"))
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertNotIn("/dev/null", result["violators"] + result["applied"])

    def test_object_failure_does_not_stop_others(self):
        self.baseline()
        a = self.make_file(os.path.join(self.units, "x-a.service"), 0o646)
        bad = self.make_file(os.path.join(self.units, "x-b.service"), 0o646)
        c = self.make_file(os.path.join(self.units, "x-c.service"), 0o646)

        def fchmod(fd, mode, path):
            if path == bad:
                raise OSError(errno.EIO, "injected")
            os.fchmod(fd, mode)

        result = self.run_apply(fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual([f["path"] for f in result["failed"]], [bad])
        self.assertEqual((mode_of(a), mode_of(bad), mode_of(c)), (0o644, 0o646, 0o644))
        self.assertEqual(self.adapter.control_result_to_report(result, "t0", "t1")["step_rc"], "nonzero")

    def test_erofs_stops_immediately(self):
        self.baseline()
        a = self.make_file(os.path.join(self.units, "x-a.service"), 0o646)
        b = self.make_file(os.path.join(self.units, "x-b.service"), 0o646)
        calls = []

        def fchmod(fd, mode, path):
            calls.append(path)
            raise OSError(errno.EROFS, "injected")

        result = self.run_apply(fchmod=fchmod)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(result["reason"], "erofs")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual((mode_of(a), mode_of(b)), (0o646, 0o646))

    def test_reapply_is_already_compliant(self):
        _rc, script, svc_a, _b = self.baseline(service_mode=0o646, script_mode=0o757)
        self.assertEqual(self.run_apply()["outcome"], "APPLIED")
        second = self.run_apply()
        self.assertEqual(second["outcome"], "ALREADY_COMPLIANT")
        self.assertIs(second["mutation_performed"], False)
        self.assertEqual((mode_of(script), mode_of(svc_a)), (0o755, 0o644))


class T05_DryRunAndPlan(_Tree):
    def test_dry_run_mutates_nothing(self):
        rc_file, script, svc_a, _b = self.baseline(rc_mode=0o757, service_mode=0o646, script_mode=0o757)
        before = {p: os.lstat(p) for p in (rc_file, script, svc_a)}
        calls = []
        result = self.run_apply(dry_run=True, privilege=False, fchmod=self.counting_fchmod(calls))
        self.assertEqual(result["outcome"], "DRY_RUN_WOULD_APPLY")
        self.assertEqual(result["violators"], sorted([rc_file, script, svc_a], key=os.fsencode))
        self.assertEqual(result["applied"], [])
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(calls, [])
        for path, st in before.items():
            now = os.lstat(path)
            self.assertEqual((now.st_mode, now.st_ctime_ns), (st.st_mode, st.st_ctime_ns), path)
        report = self.adapter.control_result_to_report(result, "t0", "t1")
        self.assertEqual(report["step_rc"], "0")
        self.assertEqual(report["transaction_commit"], "NOT_STARTED")

    def test_privilege_refusal_stops_before_mutation(self):
        _rc, _script, svc_a, _b = self.baseline(service_mode=0o646)
        result = self.run_apply(privilege=False)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(result["reason"], "privilege")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(svc_a), 0o646)

    def test_population_error_refuses_the_control(self):
        _rc, _script, svc_a, _b = self.baseline(service_mode=0o646)
        os.symlink(os.path.join(self.tmp, "missing"), os.path.join(self.units, "bad.service"))
        result = self.run_apply()
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(result["reason"], "target:stat-failed")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(svc_a), 0o646)

    def test_wrong_type_in_population_is_conflict(self):
        _rc, _script, svc_a, _b = self.baseline(service_mode=0o646)
        os.symlink(self.initd, os.path.join(self.rc, "S09dir"))
        result = self.run_apply()
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertEqual(result["reason"], "target:invalid-type")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(svc_a), 0o646)

    def test_hardlinked_violator_is_skipped_with_record(self):
        self.baseline()
        linked = self.make_file(os.path.join(self.units, "x-linked.service"), 0o646)
        os.link(linked, os.path.join(self.tmp, "kept"))
        other = self.make_file(os.path.join(self.units, "x-other.service"), 0o646)
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": linked, "reason": "st_nlink"}])
        self.assertEqual(result["applied"], [other])
        self.assertEqual((mode_of(linked), mode_of(other)), (0o646, 0o644))

    def test_only_hardlinked_violators_conflict_without_mutation(self):
        self.baseline()
        linked = self.make_file(os.path.join(self.units, "x-linked.service"), 0o646)
        os.link(linked, os.path.join(self.tmp, "kept"))
        result = self.run_apply()
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertEqual(result["reason"], "st_nlink")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(linked), 0o646)


class T06_Revalidation(_Tree):
    """Объект изменился между планом и записью: S_ISREG → dev/ino → бит 0002."""

    def two_violators(self):
        self.baseline()
        first = self.make_file(os.path.join(self.units, "x-first.service"), 0o646)
        second = self.make_file(os.path.join(self.units, "x-second.service"), 0o646)
        return first, second

    def drift_on(self, first, mutate):
        return self.counting_fchmod([], before=lambda path: mutate() if path == first else None)

    def test_not_regular_is_skipped(self):
        first, second = self.two_violators()

        def mutate():
            os.unlink(second)
            os.mkdir(second)
            os.chmod(second, 0o757)

        result = self.run_apply(fchmod=self.drift_on(first, mutate))
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": second, "reason": "not-regular"}])
        self.assertEqual(result["applied"], [first])
        self.assertEqual(mode_of(second), 0o757)

    def test_identity_drift_is_skipped(self):
        first, second = self.two_violators()

        def mutate():
            # Подменыш создаётся, пока цель ещё существует: его инод заведомо
            # другой. unlink с последующим созданием дал бы переиспользование.
            other = second + ".new"
            self.make_file(other, 0o646, content="replaced\n")
            os.replace(other, second)

        result = self.run_apply(fchmod=self.drift_on(first, mutate))
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": second, "reason": "identity-drift"}])
        self.assertEqual(result["applied"], [first])
        self.assertEqual(mode_of(second), 0o646)

    def test_lost_violation_bit_is_skipped(self):
        first, second = self.two_violators()
        result = self.run_apply(fchmod=self.drift_on(first, lambda: os.chmod(second, 0o664)))
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": second, "reason": "no-violation-bits"}])
        self.assertEqual(result["applied"], [first])
        self.assertEqual(mode_of(second), 0o664)

    def test_symlink_swapped_in_at_target_path_is_skipped(self):
        """Цель заменена симлинком: O_NOFOLLOW не идёт по нему, объект — пропуск."""
        first, second = self.two_violators()
        decoy = self.make_file(os.path.join(self.tmp, "decoy"), 0o646)

        def mutate():
            os.unlink(second)
            os.symlink(decoy, second)

        result = self.run_apply(fchmod=self.drift_on(first, mutate))
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": second, "reason": "not-regular"}])
        self.assertEqual(mode_of(decoy), 0o646)


class T07_Eligibility(_Tree):
    """Иной контракт и снятый apply.supported — отказ без мутаций."""

    def not_eligible(self, key, op, expected, apply_supported=True):
        return self.adapter.execute_control(
            CID, key, op, expected, apply_supported,
            dry_run=False, privilege_check=lambda: True, _layout=self.layout(),
        )

    def test_apply_unsupported_control_is_not_eligible(self):
        _rc, _script, svc_a, _b = self.baseline(service_mode=0o646)
        result = self.not_eligible(KEY, "bits-clear", MASK, apply_supported=False)
        self.assertEqual(result["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
        self.assertEqual(result["reason"], "apply-unsupported")
        self.assertEqual(mode_of(svc_a), 0o646)

    def test_other_key_op_or_mask_is_not_eligible(self):
        _rc, _script, svc_a, _b = self.baseline(service_mode=0o646)
        for key, op, expected in (("mode", "bits-clear", MASK), (KEY, "eq", MASK),
                                  (KEY, "bits-clear", "0022")):
            with self.subTest(key=key, op=op, expected=expected):
                result = self.not_eligible(key, op, expected)
                self.assertEqual(result["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
                self.assertIs(result["mutation_performed"], False)
                self.assertEqual(mode_of(svc_a), 0o646)

    def test_unmapped_control_is_refused(self):
        result = self.adapter.execute_control(
            "OTHER-CONTROL", KEY, "bits-clear", MASK, True,
            dry_run=True, privilege_check=lambda: True,
        )
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(result["reason"], "target:unmapped-control")


def failing_scandir(bad):
    """os.scandir, который отказывает (EACCES) только для каталога bad."""
    real = os.scandir
    bad = os.path.realpath(bad)

    def scandir(path="."):
        if os.path.realpath(os.fspath(path)) == bad:
            raise PermissionError(errno.EACCES, "injected", bad)
        return real(path)

    return scandir


class T08_ScanFailure(_Tree):
    """Ошибка чтения каталога — отказ до мутаций, а не план по неполной популяции."""

    def test_unreadable_root_refuses_apply_and_dry_run(self):
        for bad_attr in ("rc", "units"):
            for dry_run in (False, True):
                with self.subTest(root=bad_attr, dry_run=dry_run):
                    _rc, script, svc_a, _b = self.baseline(service_mode=0o646, script_mode=0o757)
                    calls = []
                    with mock.patch.object(os, "scandir", failing_scandir(getattr(self, bad_attr))):
                        result = self.run_apply(dry_run=dry_run, fchmod=self.counting_fchmod(calls))
                    self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
                    self.assertEqual(result["reason"], "directory:scan-failed")
                    self.assertIs(result["mutation_performed"], False)
                    self.assertEqual(calls, [])
                    self.assertEqual((mode_of(script), mode_of(svc_a)), (0o757, 0o646))
                    for d in (self.rc, self.units, self.initd):
                        shutil.rmtree(d)
                        os.mkdir(d)


if __name__ == "__main__":
    unittest.main()
