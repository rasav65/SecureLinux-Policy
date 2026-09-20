#!/usr/bin/env python3
"""Failing-first regressions for the standard-system-paths-mode APPLY mechanism (G6-standard-paths).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on trees created inside a temporary directory owned by the
current user and reached through a fixture locator that names those trees as
the roots. No system path is touched and root is not required: the privilege
check and the fchmod call are injected where a case needs them.

Принятые решения (человек), которые фиксирует этот файл:

* `apply_kind` `standard-system-paths-mode-v1` обслуживает `parameter_kind`
  `standard-system-paths-mode` (контроль `2.3.8-STANDARD-SYSTEM-PATHS-MODE`).
* Перечислитель — Python-копия CHECK-наблюдателя
  `product-standard-system-paths-check-v2`; паритет проверяется исполнением
  самого CHECK-адаптера через `_shell_function_for_layout` на тех же корнях.
* Канонические корни не литералы: они разбираются из локатора контроля
  (`parameter.locator`), и разбор обязан совпасть с константами
  CHECK-адаптера `CANONICAL_EXEC_ROOTS`, `CANONICAL_LIB_ROOTS`,
  `CANONICAL_MODULE_TEMPLATE`.
* Граница мутации: меняются только объекты, чей разрешённый путь лежит внутри
  канонических корней. Дополнительные элементы PATH root и цели симлинков вне
  канонических корней в популяцию входят, но не мутируются — пропуск с
  причиной `outside-canonical-roots`.
* Симлинк: объект — разрешённая цель. Разрешённый путь открывается с
  `O_NOFOLLOW`, на дескрипторе ревалидация строго в порядке `S_ISREG` →
  `dev/ino` из плана → наличие битов `0022`; несовпадение любого шага —
  пропуск с причиной `not-regular`, `identity-drift` или `no-violation-bits`.
* Ошибка CHECK-популяции (dangling-симлинк, ссылка на не-файл) — отказ
  контроля без мутаций.
* `st_nlink > 1` — пропуск с записью; только снятие `0022`, компенсации нет;
  ошибка объекта не останавливает остальные; `EROFS` и отсутствие привилегии
  останавливают сразу. Исходы как у `suid-sgid-applications-mode-v1`:
  применено что-то и есть пропуски — `APPLIED_PARTIAL`; применять нечего,
  кроме пропусков — `ABORTED_PRECONDITION_CONFLICT` без мутаций.

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

ROOT = Path(__file__).resolve().parents[2]

ADAPTER = ROOT / "product/apply-adapters/product-standard-system-paths-mode-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-standard-system-paths-mode-check-v2.py"
CONTROL_YAML = ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.8-standard-system-paths-mode.yaml"

APPLY_KIND = "standard-system-paths-mode-v1"
PARAMETER_KIND = "standard-system-paths-mode"
ADAPTER_ID = "product-standard-system-paths-mode-apply-v1"
TARGET_ID = "linux-x86_64-supported-v1"
MASK = "0022"

CID = "FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE"
PATH_ROOT_MARKER = "<root-PATH>"

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
    return load_module(ADAPTER, "slp_standard_paths_apply")


def load_check():
    return load_module(CHECK_ADAPTER, "slp_standard_paths_check")


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def check_observation(exec_roots, lib_roots, module_root):
    """(status, value) из встроенного CHECK-адаптера, исполненного bash на тех же корнях."""
    check = load_check()
    src = check._shell_function_for_layout(
        "CTRL", [str(x) for x in exec_roots], [str(x) for x in lib_roots], str(module_root), MASK
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
    """Дерево-фикстура: exec-, lib- и module-корень плюс локатор по ним."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="slp-stdpaths-apply-")
        self.adapter = load_adapter()
        self.exe = os.path.join(self.tmp, "usr-bin")
        self.lib = os.path.join(self.tmp, "usr-lib")
        self.mod = os.path.join(self.tmp, "modules")
        for d in (self.exe, self.lib, self.mod):
            os.mkdir(d)
        self._path_backup = os.environ.get("PATH")
        self.empty_path = os.path.join(self.tmp, "empty-path")
        os.mkdir(self.empty_path)
        os.environ["PATH"] = self.empty_path

    def tearDown(self):
        if self._path_backup is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = self._path_backup
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- фикстуры ---------------------------------------------------------

    def locator(self, exec_roots=None, lib_roots=None, module_root=None):
        exec_roots = [self.exe] if exec_roots is None else [str(x) for x in exec_roots]
        lib_roots = [self.lib] if lib_roots is None else [str(x) for x in lib_roots]
        module_root = self.mod if module_root is None else str(module_root)
        return "|".join(exec_roots + [PATH_ROOT_MARKER] + lib_roots + [module_root])

    def make_file(self, path, mode, content=None):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content if content is not None else os.path.basename(path) + "\n")
        os.chmod(path, mode)
        return path

    def baseline(self, exec_mode=0o755, lib_mode=0o644, module_mode=0o644):
        """Минимальная непустая популяция: по одному объекту каждой роли."""
        return (
            self.make_file(os.path.join(self.exe, "tool"), exec_mode),
            self.make_file(os.path.join(self.lib, "libdemo.so.1"), lib_mode),
            self.make_file(os.path.join(self.mod, "demo.ko.zst"), module_mode),
        )

    def run_apply(self, *, locator=None, dry_run=False, privilege=True, fchmod=None):
        kwargs = {
            "target": self.locator() if locator is None else locator,
            "dry_run": dry_run,
            "privilege_check": lambda: privilege,
        }
        if fchmod is not None:
            kwargs["_fchmod"] = fchmod
        return self.adapter.execute_control(CID, "mode", "bits-clear", MASK, True, **kwargs)


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
                   "canonical_roots", "resolve_roots", "validate_control_input"):
            self.assertTrue(callable(getattr(mod, fn, None)), fn)

    def test_target_table_is_the_control_locator(self):
        mod = load_adapter()
        text = CONTROL_YAML.read_text(encoding="utf-8")
        self.assertIn(f'kind: "{PARAMETER_KIND}"', text)
        locator = re.search(r'\nparameter:\n  kind: "[^"]*"\n  locator: "([^"]*)"', text).group(1)
        self.assertEqual(mod.TARGETS, {CID: locator})
        self.assertIn('op: "bits-clear"', text)
        self.assertIn(f'value: "{MASK}"', text)

    def test_canonical_roots_are_parsed_from_the_locator_not_literals(self):
        """Разбор локатора обязан совпасть с константами CHECK-адаптера."""
        mod = load_adapter()
        check = load_check()
        exec_roots, lib_roots, module_template = mod.canonical_roots(mod.TARGETS[CID])
        self.assertEqual(tuple(exec_roots), check.CANONICAL_EXEC_ROOTS)
        self.assertEqual(tuple(lib_roots), check.CANONICAL_LIB_ROOTS)
        self.assertEqual(module_template, check.CANONICAL_MODULE_TEMPLATE)
        self.assertEqual(mod.TARGETS[CID], check.CANONICAL_LOCATOR)

    def test_invalid_control_id_is_rejected(self):
        mod = load_adapter()
        with self.assertRaises(ValueError):
            mod.validate_control_input("bad id\n", "mode", "bits-clear", MASK, True)


class T02_PathRootAndUname(_Tree):
    """Разрешение корней: PATH root добавляется, <uname-r> подставляется."""

    def test_path_entries_are_appended_to_exec_roots(self):
        extra = os.path.join(self.tmp, "extra-bin")
        os.mkdir(extra)
        os.environ["PATH"] = extra + ":" + self.empty_path
        exec_roots, lib_roots, module_root = self.adapter.resolve_roots(self.locator())
        self.assertEqual(list(exec_roots), [self.exe, extra, self.empty_path])
        self.assertEqual(list(lib_roots), [self.lib])
        self.assertEqual(module_root, self.mod)

    def test_uname_marker_is_substituted(self):
        template = os.path.join(self.tmp, "modules-<uname-r>")
        release = os.uname().release
        os.mkdir(template.replace("<uname-r>", release))
        _exec, _lib, module_root = self.adapter.resolve_roots(self.locator(module_root=template))
        self.assertEqual(module_root, template.replace("<uname-r>", release))


@unittest.skipIf(BASH is None, "bash not available")
class T03_EnumeratorParity(_Tree):
    """APPLY-перечислитель и CHECK-адаптер дают одно и то же (status, value)."""

    def assert_parity(self, exec_roots=None, lib_roots=None, module_root=None):
        exec_roots = [self.exe] if exec_roots is None else exec_roots
        lib_roots = [self.lib] if lib_roots is None else lib_roots
        module_root = self.mod if module_root is None else module_root
        self.assertEqual(
            tuple(self.adapter.observe(exec_roots, lib_roots, module_root)),
            check_observation(exec_roots, lib_roots, module_root),
        )

    def test_compliant_baseline(self):
        self.baseline()
        self.assert_parity()

    def test_violation_in_each_role(self):
        self.baseline()
        for path, mode in (
            (os.path.join(self.exe, "tool"), 0o775),
            (os.path.join(self.lib, "libdemo.so.1"), 0o664),
            (os.path.join(self.mod, "demo.ko.zst"), 0o646),
        ):
            with self.subTest(path=path):
                before = mode_of(path)
                os.chmod(path, mode)
                self.assert_parity()
                os.chmod(path, before)

    def test_non_executable_file_under_exec_root_is_outside_population(self):
        self.baseline()
        self.make_file(os.path.join(self.exe, "notes.txt"), 0o666)
        self.assert_parity()

    def test_library_and_module_name_filters(self):
        self.baseline()
        self.make_file(os.path.join(self.lib, "README"), 0o666)
        self.make_file(os.path.join(self.mod, "modules.dep"), 0o666)
        self.assert_parity()

    def test_nested_directories_are_scanned(self):
        self.baseline()
        self.make_file(os.path.join(self.exe, "sub", "deep-tool"), 0o775)
        self.make_file(os.path.join(self.lib, "sub", "libdeep.so"), 0o664)
        self.assert_parity()

    def test_symlink_target_inside_root_is_counted_once(self):
        self.baseline()
        target = self.make_file(os.path.join(self.exe, "real-tool"), 0o775)
        os.symlink(target, os.path.join(self.exe, "alias-tool"))
        self.assert_parity()

    def test_symlink_target_outside_roots_is_in_population(self):
        self.baseline()
        outside = self.make_file(os.path.join(self.tmp, "outside.so"), 0o664)
        os.symlink(outside, os.path.join(self.lib, "liboutside.so"))
        self.assert_parity()

    def test_hardlinked_file_counted_once(self):
        self.baseline()
        target = self.make_file(os.path.join(self.exe, "a-tool"), 0o775)
        os.link(target, os.path.join(self.exe, "b-tool"))
        self.assert_parity()

    def test_absent_root_and_alias_root(self):
        self.baseline()
        absent = os.path.join(self.tmp, "absent-bin")
        self.assert_parity(exec_roots=[self.exe, absent, self.exe])

    def test_dangling_symlink_is_error(self):
        self.baseline()
        os.symlink(os.path.join(self.tmp, "missing.so"), os.path.join(self.lib, "libmissing.so"))
        self.assert_parity()

    def test_symlink_to_directory_outside_exec_roots_is_error(self):
        self.baseline()
        os.symlink(self.tmp, os.path.join(self.lib, "libdir.so"), target_is_directory=True)
        self.assert_parity()

    def test_empty_role_population_is_error(self):
        self.make_file(os.path.join(self.exe, "tool"), 0o755)
        self.make_file(os.path.join(self.lib, "libdemo.so"), 0o644)
        self.assert_parity()


class T04_CanonicalBoundary(_Tree):
    """Мутируются только объекты внутри канонических корней локатора."""

    def test_symlink_target_outside_roots_is_skipped(self):
        self.baseline()
        outside = self.make_file(os.path.join(self.tmp, "outside.so"), 0o664)
        os.symlink(outside, os.path.join(self.lib, "liboutside.so"))
        result = self.run_apply()
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertEqual(result["skipped"], [{"path": outside, "reason": "outside-canonical-roots"}])
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(outside), 0o664)

    def test_extra_path_root_violator_is_skipped(self):
        self.baseline()
        extra = os.path.join(self.tmp, "extra-bin")
        os.mkdir(extra)
        tool = self.make_file(os.path.join(extra, "local-tool"), 0o775)
        os.environ["PATH"] = extra
        inside = self.make_file(os.path.join(self.exe, "inside-tool"), 0o775)
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": tool, "reason": "outside-canonical-roots"}])
        self.assertEqual(result["applied"], [inside])
        self.assertEqual(mode_of(tool), 0o775)
        self.assertEqual(mode_of(inside), 0o755)

    def test_symlink_target_inside_roots_is_applied(self):
        self.baseline()
        target = self.make_file(os.path.join(self.exe, "real-tool"), 0o775)
        os.symlink(target, os.path.join(self.exe, "alias-tool"))
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertEqual(result["applied"], [target])
        self.assertEqual(mode_of(target), 0o755)
        self.assertTrue(os.path.islink(os.path.join(self.exe, "alias-tool")))


class T05_Plan(_Tree):
    """План строится до мутаций; ошибки популяции и запреты не мутируют."""

    def test_dry_run_lists_violators_without_mutation(self):
        exe_tool, lib_file, mod_file = self.baseline(exec_mode=0o775, lib_mode=0o664)
        result = self.run_apply(dry_run=True, privilege=False)
        self.assertEqual(result["outcome"], "DRY_RUN_WOULD_APPLY")
        self.assertEqual(result["violators"], sorted([exe_tool, lib_file], key=os.fsencode))
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(exe_tool), 0o775)
        self.assertEqual(mode_of(lib_file), 0o664)
        self.assertEqual(self.adapter.control_result_to_report(result, "t0", "t1")["step_rc"], "0")

    def test_compliant_population_is_already_compliant(self):
        self.baseline()
        result = self.run_apply()
        self.assertEqual(result["outcome"], "ALREADY_COMPLIANT")
        self.assertIs(result["mutation_performed"], False)

    def test_privilege_refusal_stops_before_mutation(self):
        exe_tool, _lib, _mod = self.baseline(exec_mode=0o775)
        result = self.run_apply(privilege=False)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(result["reason"], "privilege")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(exe_tool), 0o775)

    def test_dangling_symlink_refuses_the_control(self):
        exe_tool, _lib, _mod = self.baseline(exec_mode=0o775)
        os.symlink(os.path.join(self.tmp, "missing.so"), os.path.join(self.lib, "libmissing.so"))
        result = self.run_apply()
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertEqual(result["reason"], "target:invalid-type")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(exe_tool), 0o775)

    def test_missing_role_population_refuses_the_control(self):
        self.make_file(os.path.join(self.exe, "tool"), 0o775)
        self.make_file(os.path.join(self.lib, "libdemo.so"), 0o664)
        result = self.run_apply()
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(result["reason"], "population:missing-modules")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(os.path.join(self.exe, "tool")), 0o775)


class T06_Hardlink(_Tree):
    def test_hardlinked_violator_is_skipped_with_record(self):
        self.baseline()
        linked = self.make_file(os.path.join(self.exe, "a-linked"), 0o775)
        os.link(linked, os.path.join(self.tmp, "kept"))
        other = self.make_file(os.path.join(self.exe, "b-other"), 0o775)
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": linked, "reason": "st_nlink"}])
        self.assertEqual(result["applied"], [other])
        self.assertEqual(mode_of(linked), 0o775)
        self.assertEqual(mode_of(other), 0o755)

    def test_only_hardlinked_violators_conflict_without_mutation(self):
        self.baseline()
        linked = self.make_file(os.path.join(self.exe, "a-linked"), 0o775)
        os.link(linked, os.path.join(self.tmp, "kept"))
        result = self.run_apply()
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertEqual(result["reason"], "st_nlink")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(result["skipped"], [{"path": linked, "reason": "st_nlink"}])
        self.assertEqual(mode_of(linked), 0o775)


class T07_Revalidation(_Tree):
    """Ревалидация на дескрипторе: S_ISREG → dev/ino → биты 0022."""

    def drift_during_first_fchmod(self, first, mutate):
        def fchmod(fd, mode, path):
            if path == first:
                mutate()
            os.fchmod(fd, mode)
        return fchmod

    def two_violators(self):
        self.baseline()
        first = self.make_file(os.path.join(self.exe, "a-first"), 0o775)
        second = self.make_file(os.path.join(self.exe, "b-second"), 0o775)
        return first, second

    def test_not_regular_is_skipped(self):
        first, second = self.two_violators()

        def mutate():
            os.unlink(second)
            os.mkdir(second)
            os.chmod(second, 0o775)

        result = self.run_apply(fchmod=self.drift_during_first_fchmod(first, mutate))
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": second, "reason": "not-regular"}])
        self.assertEqual(result["applied"], [first])

    def test_identity_drift_is_skipped(self):
        first, second = self.two_violators()

        def mutate():
            # Подменыш создаётся, пока цель ещё существует: его инод заведомо
            # другой. unlink с последующим созданием дал бы переиспользование.
            other = second + ".new"
            self.make_file(other, 0o775, content="replaced\n")
            os.replace(other, second)

        result = self.run_apply(fchmod=self.drift_during_first_fchmod(first, mutate))
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": second, "reason": "identity-drift"}])
        self.assertEqual(result["applied"], [first])
        self.assertEqual(mode_of(second), 0o775)

    def test_lost_violation_bits_is_skipped(self):
        first, second = self.two_violators()
        result = self.run_apply(
            fchmod=self.drift_during_first_fchmod(first, lambda: os.chmod(second, 0o755))
        )
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": second, "reason": "no-violation-bits"}])
        self.assertEqual(result["applied"], [first])
        self.assertEqual(mode_of(second), 0o755)


class T08_Execute(_Tree):
    def test_clears_only_0022_and_preserves_owner_identity_and_content(self):
        exe_tool, lib_file, mod_file = self.baseline(exec_mode=0o4777, lib_mode=0o666, module_mode=0o646)
        before = {p: os.lstat(p) for p in (exe_tool, lib_file, mod_file)}
        result = self.run_apply()
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertIs(result["mutation_performed"], True)
        self.assertEqual(mode_of(exe_tool), 0o4755)
        self.assertEqual(mode_of(lib_file), 0o644)
        self.assertEqual(mode_of(mod_file), 0o644)
        for path, st in before.items():
            now = os.lstat(path)
            self.assertEqual((now.st_uid, now.st_gid, now.st_ino), (st.st_uid, st.st_gid, st.st_ino))
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), os.path.basename(path) + "\n")
        report = self.adapter.control_result_to_report(result, "t0", "t1")
        self.assertTrue(DISPATCHER_FIELDS <= set(report), sorted(DISPATCHER_FIELDS - set(report)))
        self.assertEqual(report["step_rc"], "0")
        self.assertEqual(report["transaction_commit"], "COMMITTED")

    def test_object_failure_does_not_stop_others(self):
        self.baseline()
        a = self.make_file(os.path.join(self.exe, "a-tool"), 0o775)
        bad = self.make_file(os.path.join(self.exe, "b-tool"), 0o775)
        c = self.make_file(os.path.join(self.exe, "c-tool"), 0o775)

        def fchmod(fd, mode, path):
            if path == bad:
                raise OSError(errno.EIO, "injected")
            os.fchmod(fd, mode)

        result = self.run_apply(fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertIs(result["mutation_performed"], True)
        self.assertEqual([f["path"] for f in result["failed"]], [bad])
        self.assertEqual(mode_of(bad), 0o775)
        self.assertEqual(mode_of(a), 0o755)
        self.assertEqual(mode_of(c), 0o755)
        report = self.adapter.control_result_to_report(result, "t0", "t1")
        self.assertEqual(report["step_rc"], "nonzero")
        self.assertIs(report["mutation_performed"], True)

    def test_erofs_stops_immediately(self):
        self.baseline()
        a = self.make_file(os.path.join(self.exe, "a-tool"), 0o775)
        b = self.make_file(os.path.join(self.exe, "b-tool"), 0o775)
        calls = []

        def fchmod(fd, mode, path):
            calls.append(path)
            raise OSError(errno.EROFS, "injected")

        result = self.run_apply(fchmod=fchmod)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(result["reason"], "erofs")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(self.adapter.control_result_to_report(result, "t0", "t1")["step_rc"], "nonzero")
        self.assertEqual(mode_of(a), 0o775)
        self.assertEqual(mode_of(b), 0o775)


class T09_Repeat(_Tree):
    def test_reapply_is_already_compliant(self):
        exe_tool, lib_file, _mod = self.baseline(exec_mode=0o775, lib_mode=0o664)
        self.assertEqual(self.run_apply()["outcome"], "APPLIED")
        second = self.run_apply()
        self.assertEqual(second["outcome"], "ALREADY_COMPLIANT")
        self.assertIs(second["mutation_performed"], False)
        self.assertEqual(mode_of(exe_tool), 0o755)
        self.assertEqual(mode_of(lib_file), 0o644)


class T10_Eligibility(_Tree):
    """Иной контракт и снятый apply.supported — отказ без мутаций."""

    def not_eligible(self, key, op, expected, apply_supported=True):
        return self.adapter.execute_control(
            CID, key, op, expected, apply_supported,
            target=self.locator(), dry_run=False, privilege_check=lambda: True,
        )

    def test_apply_unsupported_control_is_not_eligible(self):
        exe_tool, _lib, _mod = self.baseline(exec_mode=0o775)
        result = self.not_eligible("mode", "bits-clear", MASK, apply_supported=False)
        self.assertEqual(result["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
        self.assertEqual(result["reason"], "apply-unsupported")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(exe_tool), 0o775)

    def test_other_key_op_or_mask_is_not_eligible(self):
        exe_tool, _lib, _mod = self.baseline(exec_mode=0o775)
        for key, op, expected in (("owner", "bits-clear", MASK), ("mode", "eq", MASK),
                                  ("mode", "bits-clear", "0033")):
            with self.subTest(key=key, op=op, expected=expected):
                result = self.not_eligible(key, op, expected)
                self.assertEqual(result["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
                self.assertIs(result["mutation_performed"], False)
                self.assertEqual(mode_of(exe_tool), 0o775)
        self.assertEqual(self.adapter.control_result_to_report(
            self.not_eligible("mode", "eq", MASK), "t0", "t1")["step_rc"], "0")


if __name__ == "__main__":
    unittest.main()
