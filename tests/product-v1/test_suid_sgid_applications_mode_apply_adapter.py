#!/usr/bin/env python3
"""Failing-first regressions for the suid-sgid-applications-mode APPLY mechanism (G6-suid-sgid).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on trees created inside a temporary directory owned by the
current user, reached through a fixture `mountinfo` that names that directory
as the only mount point. No system path is touched and root is not required:
the privilege check and the fchmod call are injected where a case needs them.

Принятые решения (человек), которые фиксирует этот файл:

* `apply_kind` `suid-sgid-applications-mode-v1` обслуживает `parameter_kind`
  `suid-sgid-applications`, но только контроль `2.3.9-SUID-SGID-MODE`;
  иной op (`subset-of-file`, контроль `2.3.9-ALLOWLIST`) даёт
  `NOT_ELIGIBLE_APPLY_UNSUPPORTED` без мутаций.
* Перечислитель — Python-копия CHECK-наблюдателя: `find -P -xdev -type f
  -perm /6000` по непсевдо-точкам монтирования из mountinfo, дедупликация
  точек и файлов по `dev:ino`. Паритет проверяется исполнением самого
  CHECK-адаптера на той же фикстуре.
* Остальное — как у `optional-file-root-files-mode-v1`: план до мутаций,
  `O_NOFOLLOW` + `fchmod`, только снятие `0022`, `st_nlink > 1` — пропуск с
  записью, ошибка объекта не останавливает остальные (`APPLIED_PARTIAL`),
  `EROFS` и отсутствие привилегии — остановка.
* Дополнительно ревалидация на дескрипторе строго в этом порядке:
  `S_ISREG` → `dev/ino` из плана → наличие битов `06000`. Несовпадение любого
  шага — пропуск объекта с причиной `not-regular`, `identity-drift` или
  `no-suid-sgid` соответственно. Порядок закреплён тем, что каждый случай
  ниже требует своей причины: проверка, вставленная перед этими тремя, ломает
  соответствующий тест.

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

ADAPTER = ROOT / "product/apply-adapters/product-suid-sgid-applications-mode-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-suid-sgid-applications-check-v2.py"
CONTROL_DIR = ROOT / "controls/fstec-core/linux-2022"

APPLY_KIND = "suid-sgid-applications-mode-v1"
PARAMETER_KIND = "suid-sgid-applications"
ADAPTER_ID = "product-suid-sgid-applications-mode-apply-v1"
TARGET_ID = "linux-x86_64-supported-v1"
MASK = "0022"
CANONICAL_LOCATOR = "/proc/self/mountinfo"

CID = "FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE"
ALLOWLIST_CID = "FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST"
ALLOWLIST_EXPECTED = "/etc/securelinux-policy/suid-sgid.allowlist-v1"

TARGETS = {CID: CANONICAL_LOCATOR}

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
    return load_module(ADAPTER, "slp_suid_sgid_apply")


def mode_of(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def make_file(path, mode, content=None):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content if content is not None else os.path.basename(path) + "\n")
    os.chmod(path, mode)
    return path


def check_observation(mountinfo):
    """(status, value) из встроенного CHECK-адаптера, исполненного bash на фикстуре."""
    check = load_module(CHECK_ADAPTER, "slp_suid_sgid_check")
    src = check._shell_function_for_fixture("CTRL", "mode", "bits-clear", MASK, str(mountinfo))
    proc = subprocess.run(
        [BASH, "-c", "set -u\n" + src + "\nslp_check_CTRL\n"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120,
    )
    fields = proc.stdout.rstrip("\n").split("\t")
    if proc.returncode != 0 or len(fields) != 5:
        raise AssertionError(f"CHECK failed: rc={proc.returncode} out={proc.stdout!r} err={proc.stderr!r}")
    return fields[2], fields[3]


def run(adapter, mountinfo, *, dry_run=False, privilege=True, fchmod=None):
    kwargs = {"target": str(mountinfo), "dry_run": dry_run, "privilege_check": lambda: privilege}
    if fchmod is not None:
        kwargs["_fchmod"] = fchmod
    return adapter.execute_control(CID, "mode", "bits-clear", MASK, True, **kwargs)


class _Tree(unittest.TestCase):
    """Дерево-фикстура и mountinfo, указывающий на него одной непсевдо-точкой."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="slp-suid-apply-")
        self.adapter = load_adapter()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def mountinfo(self, *mount_points, fstype="ext4"):
        """Фикстурный mountinfo; без аргументов — одна точка на корне дерева."""
        points = mount_points or (self.tmp,)
        path = os.path.join(self.tmp, "mountinfo")
        with open(path, "w", encoding="utf-8") as fh:
            for i, mp in enumerate(points, start=1):
                fh.write(f"{i} 0 0:{i} / {mp} rw,relatime - {fstype} /dev/test rw\n")
        return path

    def tree(self, files):
        """Создаёт {относительный путь: режим} внутри дерева; возвращает абсолютные пути."""
        made = {}
        for rel, mode in files.items():
            path = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            made[rel] = make_file(path, mode, content=rel + "\n")
        return made


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
        for fn in ("execute_control", "control_result_to_report", "observe", "validate_control_input"):
            self.assertTrue(callable(getattr(mod, fn, None)), fn)

    def test_target_table_is_the_mode_control_only(self):
        mod = load_adapter()
        self.assertEqual(mod.TARGETS, TARGETS)
        self.assertNotIn(ALLOWLIST_CID, mod.TARGETS)

    def test_target_table_equals_yaml_locator(self):
        text = (CONTROL_DIR / "fstec-linux-2022-2.3.9-suid-sgid-mode.yaml").read_text(encoding="utf-8")
        self.assertIn(f'kind: "{PARAMETER_KIND}"', text)
        locator = re.search(r'\nparameter:\n  kind: "[^"]*"\n  locator: "([^"]*)"', text).group(1)
        self.assertEqual(load_adapter().TARGETS[CID], locator)
        self.assertIn('op: "bits-clear"', text)
        self.assertIn(f'value: "{MASK}"', text)

    def test_invalid_control_id_is_rejected(self):
        mod = load_adapter()
        with self.assertRaises(ValueError):
            mod.validate_control_input("bad id\n", "mode", "bits-clear", MASK, True)


@unittest.skipIf(BASH is None, "bash not available")
class T02_EnumeratorParity(_Tree):
    """APPLY-перечислитель и CHECK-адаптер дают одно и то же (status, value)."""

    def assert_parity(self, mountinfo):
        self.assertEqual(tuple(self.adapter.observe(mountinfo)), check_observation(mountinfo))

    def test_no_suid_files(self):
        self.tree({"bin/plain": 0o755})
        self.assert_parity(self.mountinfo())

    def test_compliant_and_violating_suid_files(self):
        made = self.tree({"bin/ok": 0o4755, "bin/bad": 0o4775})
        mountinfo = self.mountinfo()
        self.assert_parity(mountinfo)
        os.chmod(made["bin/bad"], 0o4755)
        self.assert_parity(mountinfo)
        os.chmod(made["bin/ok"], 0o2757)
        self.assert_parity(mountinfo)

    def test_nested_directories_are_scanned(self):
        self.tree({"a/b/c/deep": 0o6775, "a/shallow": 0o4755})
        self.assert_parity(self.mountinfo())

    def test_hardlinked_file_counted_once(self):
        made = self.tree({"bin/bad": 0o4775})
        os.link(made["bin/bad"], os.path.join(self.tmp, "bin", "same"))
        self.assert_parity(self.mountinfo())

    def test_symlink_to_suid_file_is_not_population(self):
        made = self.tree({"bin/bad": 0o4775})
        os.symlink(made["bin/bad"], os.path.join(self.tmp, "bin", "link"))
        self.assert_parity(self.mountinfo())

    def test_pseudo_filesystem_is_skipped(self):
        self.tree({"bin/bad": 0o4775})
        self.assert_parity(self.mountinfo(fstype="proc"))

    def test_duplicate_mount_point_counted_once(self):
        self.tree({"bin/bad": 0o4775})
        self.assert_parity(self.mountinfo(self.tmp, self.tmp))

    def test_missing_mount_point_is_error(self):
        self.tree({"bin/bad": 0o4775})
        self.assert_parity(self.mountinfo(os.path.join(self.tmp, "absent")))


class T03_Plan(_Tree):
    """План строится до мутаций; запреты останавливают контроль без мутаций."""

    def test_dry_run_lists_violators_without_mutation(self):
        made = self.tree({"bin/bad": 0o4775, "bin/ok": 0o4755, "bin/also": 0o2757})
        result = run(self.adapter, self.mountinfo(), dry_run=True, privilege=False)
        self.assertEqual(result["outcome"], "DRY_RUN_WOULD_APPLY")
        self.assertEqual(result["violators"], sorted([made["bin/also"], made["bin/bad"]], key=os.fsencode))
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(made["bin/bad"]), 0o4775)
        self.assertEqual(mode_of(made["bin/also"]), 0o2757)
        self.assertEqual(mode_of(made["bin/ok"]), 0o4755)
        self.assertEqual(self.adapter.control_result_to_report(result, "t0", "t1")["step_rc"], "0")

    def test_compliant_population_is_already_compliant(self):
        self.tree({"bin/ok": 0o4755})
        result = run(self.adapter, self.mountinfo())
        self.assertEqual(result["outcome"], "ALREADY_COMPLIANT")
        self.assertIs(result["mutation_performed"], False)

    def test_privilege_refusal_stops_before_mutation(self):
        made = self.tree({"bin/bad": 0o4775})
        result = run(self.adapter, self.mountinfo(), privilege=False)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(result["reason"], "privilege")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(made["bin/bad"]), 0o4775)

    def test_enumerator_error_aborts_without_mutation(self):
        made = self.tree({"bin/bad": 0o4775})
        result = run(self.adapter, self.mountinfo(os.path.join(self.tmp, "absent")))
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(result["reason"], "mountinfo:missing-mountpoint")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(made["bin/bad"]), 0o4775)


class T04_Hardlink(_Tree):
    def test_hardlinked_violator_skipped_with_record(self):
        made = self.tree({"bin/bad": 0o4775, "bin/other": 0o2757})
        os.link(made["bin/bad"], os.path.join(self.tmp, "kept"))
        result = run(self.adapter, self.mountinfo())
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": made["bin/bad"], "reason": "st_nlink"}])
        self.assertEqual(mode_of(made["bin/bad"]), 0o4775)
        self.assertEqual(mode_of(made["bin/other"]), 0o2755)

    def test_only_hardlinked_violators_conflict_without_mutation(self):
        made = self.tree({"bin/bad": 0o4775, "bin/ok": 0o4755})
        os.link(made["bin/bad"], os.path.join(self.tmp, "kept"))
        result = run(self.adapter, self.mountinfo())
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_CONFLICT")
        self.assertEqual(result["reason"], "st_nlink")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(result["skipped"], [{"path": made["bin/bad"], "reason": "st_nlink"}])
        self.assertEqual(mode_of(made["bin/bad"]), 0o4775)


class T05_Revalidation(_Tree):
    """Ревалидация на дескрипторе: S_ISREG → dev/ino → биты 06000."""

    def drift_during_first_fchmod(self, first, mutate):
        """Выполняет mutate() на второй цели во время fchmod по первой."""
        seen = []

        def fchmod(fd, mode, path):
            seen.append(path)
            if path == first:
                mutate()
            os.fchmod(fd, mode)

        return fchmod, seen

    def test_not_regular_is_skipped(self):
        made = self.tree({"bin/a-first": 0o4775, "bin/b-second": 0o4775})
        target = made["bin/b-second"]

        def mutate():
            os.unlink(target)
            os.mkdir(target)
            os.chmod(target, 0o4775)

        fchmod, _seen = self.drift_during_first_fchmod(made["bin/a-first"], mutate)
        result = run(self.adapter, self.mountinfo(), fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": target, "reason": "not-regular"}])
        self.assertEqual(result["applied"], [made["bin/a-first"]])
        self.assertEqual(mode_of(target), 0o4775)

    def test_identity_drift_is_skipped(self):
        made = self.tree({"bin/a-first": 0o4775, "bin/b-second": 0o4775})
        target = made["bin/b-second"]

        def mutate():
            # Замена через os.replace: инод подменыша выделяется, пока цель ещё
            # существует, поэтому он заведомо не равен иноду из плана. unlink с
            # последующим созданием файла дал бы переиспользование инода и
            # недетерминированный тест.
            other = target + ".new"
            make_file(other, 0o4775, content="replaced\n")
            os.replace(other, target)

        fchmod, _seen = self.drift_during_first_fchmod(made["bin/a-first"], mutate)
        result = run(self.adapter, self.mountinfo(), fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": target, "reason": "identity-drift"}])
        self.assertEqual(result["applied"], [made["bin/a-first"]])
        self.assertEqual(mode_of(target), 0o4775)

    def test_lost_suid_sgid_bits_is_skipped(self):
        made = self.tree({"bin/a-first": 0o4775, "bin/b-second": 0o4775})
        target = made["bin/b-second"]
        fchmod, _seen = self.drift_during_first_fchmod(
            made["bin/a-first"], lambda: os.chmod(target, 0o0775)
        )
        result = run(self.adapter, self.mountinfo(), fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertEqual(result["skipped"], [{"path": target, "reason": "no-suid-sgid"}])
        self.assertEqual(result["applied"], [made["bin/a-first"]])
        self.assertEqual(mode_of(target), 0o0775)


class T06_Execute(_Tree):
    def test_clears_only_0022_and_preserves_owner_identity_and_content(self):
        made = self.tree({"bin/a": 0o4777, "bin/b": 0o2757, "bin/c": 0o6755})
        before = {rel: os.lstat(path) for rel, path in made.items()}
        result = run(self.adapter, self.mountinfo())
        self.assertEqual(result["outcome"], "APPLIED")
        self.assertIs(result["mutation_performed"], True)
        self.assertEqual(mode_of(made["bin/a"]), 0o4755)
        self.assertEqual(mode_of(made["bin/b"]), 0o2755)
        self.assertEqual(mode_of(made["bin/c"]), 0o6755)
        for rel, st in before.items():
            now = os.lstat(made[rel])
            self.assertEqual((now.st_uid, now.st_gid, now.st_ino), (st.st_uid, st.st_gid, st.st_ino))
            with open(made[rel], encoding="utf-8") as fh:
                self.assertEqual(fh.read(), rel + "\n")
        report = self.adapter.control_result_to_report(result, "t0", "t1")
        self.assertTrue(DISPATCHER_FIELDS <= set(report), sorted(DISPATCHER_FIELDS - set(report)))
        self.assertEqual(report["step_rc"], "0")
        self.assertEqual(report["transaction_commit"], "COMMITTED")

    def test_object_failure_does_not_stop_others(self):
        made = self.tree({"bin/a": 0o4775, "bin/b": 0o4775, "bin/c": 0o4775})
        bad = made["bin/b"]

        def fchmod(fd, mode, path):
            if path == bad:
                raise OSError(errno.EIO, "injected")
            os.fchmod(fd, mode)

        result = run(self.adapter, self.mountinfo(), fchmod=fchmod)
        self.assertEqual(result["outcome"], "APPLIED_PARTIAL")
        self.assertIs(result["mutation_performed"], True)
        self.assertEqual([f["path"] for f in result["failed"]], [bad])
        self.assertEqual(mode_of(bad), 0o4775)
        self.assertEqual(mode_of(made["bin/a"]), 0o4755)
        self.assertEqual(mode_of(made["bin/c"]), 0o4755)
        report = self.adapter.control_result_to_report(result, "t0", "t1")
        self.assertTrue(DISPATCHER_FIELDS <= set(report), sorted(DISPATCHER_FIELDS - set(report)))
        self.assertEqual(report["step_rc"], "nonzero")
        self.assertIs(report["mutation_performed"], True)

    def test_erofs_stops_immediately(self):
        made = self.tree({"bin/a": 0o4775, "bin/b": 0o4775})
        calls = []

        def fchmod(fd, mode, path):
            calls.append(path)
            raise OSError(errno.EROFS, "injected")

        result = run(self.adapter, self.mountinfo(), fchmod=fchmod)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["reason"], "erofs")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(result["outcome"], "ABORTED_PRECONDITION_OTHER")
        self.assertEqual(self.adapter.control_result_to_report(result, "t0", "t1")["step_rc"], "nonzero")
        self.assertEqual(mode_of(made["bin/a"]), 0o4775)
        self.assertEqual(mode_of(made["bin/b"]), 0o4775)


class T07_Repeat(_Tree):
    def test_reapply_is_already_compliant(self):
        made = self.tree({"bin/a": 0o4775, "bin/b": 0o2757})
        mountinfo = self.mountinfo()
        self.assertEqual(run(self.adapter, mountinfo)["outcome"], "APPLIED")
        second = run(self.adapter, mountinfo)
        self.assertEqual(second["outcome"], "ALREADY_COMPLIANT")
        self.assertIs(second["mutation_performed"], False)
        self.assertEqual(mode_of(made["bin/a"]), 0o4755)
        self.assertEqual(mode_of(made["bin/b"]), 0o2755)

    def test_empty_population_is_already_compliant(self):
        self.tree({"bin/plain": 0o755})
        result = run(self.adapter, self.mountinfo())
        self.assertEqual(result["outcome"], "ALREADY_COMPLIANT")
        self.assertIs(result["mutation_performed"], False)


class T08_Eligibility(_Tree):
    """Иной op и снятый apply.supported — отказ без мутаций."""

    def test_allowlist_op_is_not_eligible(self):
        made = self.tree({"bin/bad": 0o4775})
        result = self.adapter.execute_control(
            ALLOWLIST_CID, "approved-set", "subset-of-file", ALLOWLIST_EXPECTED, True,
            target=self.mountinfo(), dry_run=False, privilege_check=lambda: True,
        )
        self.assertEqual(result["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(made["bin/bad"]), 0o4775)
        self.assertEqual(self.adapter.control_result_to_report(result, "t0", "t1")["step_rc"], "0")

    def test_allowlist_op_is_not_eligible_in_dry_run(self):
        result = self.adapter.execute_control(
            ALLOWLIST_CID, "approved-set", "subset-of-file", ALLOWLIST_EXPECTED, True,
            target=self.mountinfo(), dry_run=True, privilege_check=lambda: True,
        )
        self.assertEqual(result["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")

    def test_apply_unsupported_control_is_not_eligible(self):
        made = self.tree({"bin/bad": 0o4775})
        result = self.adapter.execute_control(
            CID, "mode", "bits-clear", MASK, False,
            target=self.mountinfo(), dry_run=False, privilege_check=lambda: True,
        )
        self.assertEqual(result["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
        self.assertEqual(result["reason"], "apply-unsupported")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(made["bin/bad"]), 0o4775)

    def test_other_mask_is_not_eligible(self):
        made = self.tree({"bin/bad": 0o4775})
        result = self.adapter.execute_control(
            CID, "mode", "bits-clear", "0033", True,
            target=self.mountinfo(), dry_run=False, privilege_check=lambda: True,
        )
        self.assertEqual(result["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
        self.assertIs(result["mutation_performed"], False)
        self.assertEqual(mode_of(made["bin/bad"]), 0o4775)


if __name__ == "__main__":
    unittest.main()
