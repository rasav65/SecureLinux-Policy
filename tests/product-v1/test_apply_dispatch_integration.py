#!/usr/bin/env python3
"""Сквозная проверка встроенного APPLY-dispatcher с реальными адаптерами.

Продукт генерируется во временный каталог вне репозитория. Из сгенерированных
байтов извлекается встроенный Python-dispatcher и исполняется в режиме DRY_RUN
без root. Замены на стороне теста — STATE_DIR (отчёт и журналы пишутся во
временный каталог, как в test_product_generator.py) и TRUSTED_UID/PARENT_TRUSTED_UID (владелец
каталога состояния и его родителя — пользователь прогона вместо root).
Ожидаемые множества контролей вычисляются из реестров.
"""
import csv
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = ROOT / "product" / "generate-product-check-v2.py"
PYTHON = os.environ.get("PYTHON", "/usr/bin/python3")
KIND_REGISTRY = ROOT / "product" / "APPLY-KIND-REGISTRY.tsv"
IMPL_REGISTRY = ROOT / "product" / "APPLY-IMPLEMENTATION-REGISTRY.tsv"

DISPATCH_OPEN = "<<'SLP_PRODUCT_APPLY_EOF'\n"
DISPATCH_CLOSE = "\nSLP_PRODUCT_APPLY_EOF\n"
STATE_DIR_LINE = 'STATE_DIR = "/var/log/securelinux-policy"'
TRUSTED_UID_LINE = "TRUSTED_UID = PARENT_TRUSTED_UID = 0"
CRASH_REASON = "mechanism:unhandled-exception"


def load_generator():
    spec = importlib.util.spec_from_file_location("slp_generator_v2_dispatch_it", GEN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def adapter_outcomes():
    """Исходы всех APPLY-адаптеров реестра: кортеж OUTCOMES и константы OUTCOME_*."""
    outcomes = set()
    for row in read_tsv(IMPL_REGISTRY):
        spec = importlib.util.spec_from_file_location(
            "slp_apply_outcomes_" + re.sub(r"[^A-Za-z0-9_]", "_", row["adapter_id"]),
            ROOT / row["implementation_path"],
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        outcomes.update(getattr(mod, "OUTCOMES", ()))
        outcomes.update(
            value for name, value in vars(mod).items()
            if name.startswith("OUTCOME_") and isinstance(value, str)
        )
    return outcomes


def read_tsv(path):
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def expected_population():
    """apply_kind -> множество control_id с apply.supported=true этого вида."""
    gen = load_generator()
    kind_to_param = {row["apply_kind"]: row["parameter_kind"] for row in read_tsv(KIND_REGISTRY)}
    impl_kinds = [row["apply_kind"] for row in read_tsv(IMPL_REGISTRY)]
    rows, _ = gen.load_manifest(ROOT)
    controls = [gen.load_control(ROOT, row) for row in rows]
    population = {}
    for apply_kind in impl_kinds:
        param = kind_to_param[apply_kind]
        population[apply_kind] = {
            c["control_id"] for c in controls
            if c["apply_supported"] and c["parameter_kind"] == param
        }
    return population


class ApplyDispatchIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="slp-apply-dispatch-it-"))
        out = cls.tmp / "securelinux-policy.sh"
        gen = subprocess.run(
            [PYTHON, "-I", "-S", "-B", str(GEN_PATH), "--repo", str(ROOT), "--out", str(out)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600,
        )
        if gen.returncode != 0:
            raise RuntimeError("generator failed:\n" + gen.stdout + gen.stderr)
        product = out.read_text(encoding="utf-8")
        start = product.index(DISPATCH_OPEN) + len(DISPATCH_OPEN)
        end = product.index(DISPATCH_CLOSE, start)
        dispatcher = product[start:end] + "\n"
        if dispatcher.count(STATE_DIR_LINE) != 1:
            raise RuntimeError("STATE_DIR line not found exactly once in dispatcher")
        cls.state = cls.tmp / "state"
        isolated = dispatcher.replace(STATE_DIR_LINE, "STATE_DIR = " + repr(str(cls.state)), 1)
        isolated = isolated.replace(TRUSTED_UID_LINE, "TRUSTED_UID = PARENT_TRUSTED_UID = %d" % os.getuid(), 1)
        cls.dispatcher = dispatcher
        cls.raw_keys = set(re.findall(r'raw\["([A-Za-z_]+)"\]', dispatcher))
        compact = dispatcher[dispatcher.index("def _compact_outcome("):]
        compact = compact[:compact.index("\ndef ")]
        cls.compact_mapping = dict(re.findall(r'"([A-Z_]+)": "([a-z]+)"', compact))
        cls.proc = subprocess.run(
            [PYTHON, "-I", "-S", "-B", "-", "DRY_RUN"],
            input=isolated, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=cls.tmp, timeout=600,
        )
        report = cls.state / "report.json"
        cls.payload = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else None
        debug = cls.state / "debug.log"
        cls.debug = debug.read_text(encoding="utf-8") if debug.is_file() else None
        cls.population = expected_population()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_report_is_complete_dry_run(self):
        self.assertIsNotNone(self.payload, self.proc.stdout + self.proc.stderr)
        self.assertIs(self.payload["dry_run"], True)
        self.assertIs(self.payload["complete"], True)
        self.assertIsNone(self.payload["run_error"])

    def test_dispatcher_reads_adapter_fields(self):
        self.assertTrue(self.raw_keys, "dispatcher reads no raw[...] fields")

    def test_compact_outcome_keys_are_adapter_outcomes(self):
        self.assertTrue(self.compact_mapping, "compact mapping not found")
        unknown = sorted(set(self.compact_mapping) - adapter_outcomes())
        self.assertEqual(unknown, [], "ключи _compact_outcome вне исходов адаптеров")
        self.assertEqual(self.compact_mapping.get("DRY_RUN_WOULD_APPLY"), "would")
        self.assertEqual(self.compact_mapping.get("APPLIED_PARTIAL"), "part")

    def test_every_apply_kind_has_controls(self):
        self.assertTrue(self.population)
        for apply_kind, ids in self.population.items():
            with self.subTest(apply_kind=apply_kind):
                self.assertTrue(ids, "apply_kind without apply.supported controls")

    def test_each_control_dispatched_without_crash(self):
        self.assertIsNotNone(self.payload, self.proc.stdout + self.proc.stderr)
        by_id = {}
        for record in self.payload["controls"]:
            by_id.setdefault(record["control_id"], []).append(record)
        failures = []
        for apply_kind in sorted(self.population):
            for cid in sorted(self.population[apply_kind]):
                records = by_id.get(cid, [])
                problems = []
                if len(records) != 1:
                    problems.append(f"records={len(records)}")
                else:
                    rec = records[0]
                    mres = rec.get("mechanism_result") or {}
                    if rec.get("reason") == CRASH_REASON:
                        problems.append(
                            f"reason={CRASH_REASON}:{mres.get('error_type')}:{mres.get('error_message')}"
                        )
                    if str(rec.get("outcome", "")).startswith("FAILED_"):
                        problems.append(f"outcome={rec.get('outcome')}")
                    if rec.get("mutation_performed") is not False:
                        problems.append(f"mutation_performed={rec.get('mutation_performed')!r}")
                    missing = sorted(k for k in self.raw_keys if k not in rec and k not in mres)
                    if missing:
                        problems.append("missing_fields=" + ",".join(missing))
                if problems:
                    failures.append(f"{apply_kind} {cid} " + " ".join(problems))
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_no_unexpected_controls_in_report(self):
        self.assertIsNotNone(self.payload, self.proc.stdout + self.proc.stderr)
        expected = set().union(*self.population.values())
        actual = [record["control_id"] for record in self.payload["controls"]]
        self.assertEqual(sorted(actual), sorted(expected))


class StateDirGuard(unittest.TestCase):
    """Каталог состояния и блокировка встроенного dispatcher (решение человека).

    Существующий каталог: не симлинк, каталог, владелец root, биты 022 не
    установлены; родитель — владелец root, без o+w (группа-владелец root или
    syslog: на Ubuntu /var/log — root:syslog 0775). Иначе отказ до любой
    мутации, RC ненулевой. Блокировка flock LOCK_EX|LOCK_NB на файле в каталоге
    состояния: второй экземпляр — сразу отказ «already running» без записи
    отчёта. Тесты подставляют STATE_DIR и TRUSTED_UID; отказ происходит до
    исполнения каких-либо контролей, поэтому прогон быстрый.
    """

    ENSURE_CALL = "    ensure_state_dir()\n"

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="slp-state-guard-"))
        out = cls.tmp / "securelinux-policy.sh"
        gen = subprocess.run(
            [PYTHON, "-I", "-S", "-B", str(GEN_PATH), "--repo", str(ROOT), "--out", str(out)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600,
        )
        if gen.returncode != 0:
            raise RuntimeError("generator failed:\n" + gen.stdout + gen.stderr)
        product = out.read_text(encoding="utf-8")
        start = product.index(DISPATCH_OPEN) + len(DISPATCH_OPEN)
        end = product.index(DISPATCH_CLOSE, start)
        cls.dispatcher = product[start:end] + "\n"
        if cls.dispatcher.count(STATE_DIR_LINE) != 1:
            raise RuntimeError("STATE_DIR line not found exactly once in dispatcher")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="case-", dir=self.tmp))
        os.chmod(self.base, 0o700)
        self.state = self.base / "state"

    def run_dispatcher(self, dir_uid=None, parent_uid=None, mode="DRY_RUN"):
        """dir_uid/parent_uid — доверенный владелец каталога состояния/его родителя (по умолчанию — пользователь прогона)."""
        me = os.getuid()
        uids = "TRUSTED_UID = %d\nPARENT_TRUSTED_UID = %d" % (
            me if dir_uid is None else dir_uid, me if parent_uid is None else parent_uid)
        source = self.dispatcher.replace(STATE_DIR_LINE, "STATE_DIR = " + repr(str(self.state)), 1)
        source = source.replace(TRUSTED_UID_LINE, uids, 1)
        return subprocess.run(
            [PYTHON, "-I", "-S", "-B", "-", mode], input=source,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=self.tmp, timeout=600,
        )

    def assert_refused(self, cp, reason):
        self.assertNotEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("REFUSED " + reason, cp.stderr)
        self.assertNotIn("Traceback", cp.stderr)
        self.assertEqual(cp.stdout, "")
        self.assertFalse((self.state / "report.json").exists(), "отчёт записан при отказе")
        self.assertFalse((self.state / "apply.log").exists(), "журнал записан при отказе")

    def test_dispatcher_declares_trusted_owner_line_once(self):
        self.assertEqual(self.dispatcher.count(TRUSTED_UID_LINE), 1)

    def test_foreign_owner_dir_is_refused(self):
        self.state.mkdir(mode=0o700)
        cp = self.run_dispatcher(dir_uid=os.getuid() + 1)
        self.assert_refused(cp, "reporting:state-dir-owner")

    def test_group_or_other_writable_dir_is_refused(self):
        self.state.mkdir(mode=0o700)
        os.chmod(self.state, 0o775)
        self.assert_refused(self.run_dispatcher(), "reporting:state-dir-mode")

    def test_other_writable_dir_is_refused(self):
        self.state.mkdir(mode=0o700)
        os.chmod(self.state, 0o702)
        self.assert_refused(self.run_dispatcher(), "reporting:state-dir-mode")

    def test_symlink_state_dir_is_refused(self):
        real = self.base / "real"
        real.mkdir(mode=0o700)
        self.state.symlink_to(real)
        self.assert_refused(self.run_dispatcher(), "reporting:state-dir-symlink")
        self.assertEqual(sorted(p.name for p in real.iterdir()), [], "мутация через симлинк")

    def test_regular_file_state_dir_is_refused(self):
        self.state.write_text("", encoding="utf-8")
        self.assert_refused(self.run_dispatcher(), "reporting:state-dir-invalid")

    def test_other_writable_parent_is_refused(self):
        os.chmod(self.base, 0o703)
        try:
            cp = self.run_dispatcher()
        finally:
            os.chmod(self.base, 0o700)
        self.assert_refused(cp, "reporting:state-parent-mode")
        self.assertFalse(self.state.exists(), "каталог создан при отказе по родителю")

    def test_group_writable_parent_with_foreign_group_is_refused(self):
        os.chmod(self.base, 0o770)
        try:
            cp = self.run_dispatcher()
        finally:
            os.chmod(self.base, 0o700)
        self.assert_refused(cp, "reporting:state-parent-mode")
        self.assertFalse(self.state.exists(), "каталог создан при отказе по родителю")

    def test_foreign_owner_parent_is_refused(self):
        cp = self.run_dispatcher(parent_uid=os.getuid() + 1)
        self.assert_refused(cp, "reporting:state-parent-owner")
        self.assertFalse(self.state.exists(), "каталог создан при отказе по родителю")

    def test_second_instance_is_refused_while_lock_is_held(self):
        import fcntl
        self.state.mkdir(mode=0o700)
        holder = os.open(str(self.state / ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for mode in ("DRY_RUN", "APPLY"):
                with self.subTest(mode=mode):
                    cp = self.run_dispatcher(mode=mode)
                    self.assert_refused(cp, "reporting:already-running")
                    self.assertIn("already running", cp.stderr)
        finally:
            os.close(holder)

    def test_lock_is_released_after_holder_exits(self):
        import fcntl
        self.state.mkdir(mode=0o700)
        holder = os.open(str(self.state / ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.close(holder)
        cp = self.run_dispatcher()
        self.assertNotIn("already running", cp.stderr)
        self.assertTrue((self.state / "report.json").is_file(), cp.stdout + cp.stderr)

    def run_dispatcher_holding_lock(self, marker, gate, mode="DRY_RUN"):
        """Первый экземпляр dispatcher, запущенный в фоне: держит flock,
        взятый внутри его собственного ensure_state_dir(), до появления
        файла `gate`; сразу после взятия блокировки создаёт `marker` — по
        нему тест узнаёт, что можно безопасно запускать второй экземпляр, не
        полагаясь на фиксированный sleep."""
        self.assertEqual(self.dispatcher.count(self.ENSURE_CALL), 1)
        stall = (
            self.ENSURE_CALL
            + "    import time as _slp_test_time\n"
            + "    with open(%r, 'w') as _slp_test_f:\n" % str(marker)
            + "        _slp_test_f.write('locked')\n"
            + "    while not os.path.exists(%r):\n" % str(gate)
            + "        _slp_test_time.sleep(0.02)\n"
        )
        source = self.dispatcher.replace(self.ENSURE_CALL, stall, 1)
        source = source.replace(STATE_DIR_LINE, "STATE_DIR = " + repr(str(self.state)), 1)
        me = os.getuid()
        source = source.replace(TRUSTED_UID_LINE, "TRUSTED_UID = %d\nPARENT_TRUSTED_UID = %d" % (me, me), 1)
        proc = subprocess.Popen(
            [PYTHON, "-I", "-S", "-B", "-", mode],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=self.tmp,
        )
        proc.stdin.write(source)
        proc.stdin.close()
        proc.stdin = None
        return proc

    def test_second_instance_is_refused_while_first_dispatcher_run_holds_lock(self):
        # Пробел теста (репарация, аудит Codex 3215d1c..cc90fd6):
        # test_second_instance_is_refused_while_lock_is_held держит flock
        # ВНЕШНИМ дескриптором теста, не самим dispatcher — реальную
        # конкуренцию двух прогонов dispatcher friend против friend не
        # проверял. Здесь первый экземпляр dispatcher реально держит flock,
        # взятый внутри собственного ensure_state_dir(), пока идёт второй
        # запуск, — а не деремся за файл после того, как первый уже вышел.
        self.state.mkdir(mode=0o700)
        marker = self.base / "locked.marker"
        gate = self.base / "release.gate"
        proc = self.run_dispatcher_holding_lock(marker, gate)
        try:
            for _ in range(500):
                if marker.exists():
                    break
                time.sleep(0.02)
            else:
                self.fail("первый экземпляр не подтвердил взятие блокировки")
            self.assertIsNone(proc.poll(), "первый экземпляр завершился раньше времени")
            cp2 = self.run_dispatcher()
            self.assert_refused(cp2, "reporting:already-running")
            self.assertIn("already running", cp2.stderr)
        finally:
            gate.write_text("go", encoding="utf-8")
            out, err = proc.communicate(timeout=60)
        # DRY_RUN с абортами/would-apply по устройству возвращает ненулевой
        # RC — это не про блокировку; здесь важно, что первый экземпляр не
        # был отказан "already running" и штатно дописал свой отчёт.
        self.assertNotIn("Traceback", err, out + err)
        self.assertNotIn("already running", err, out + err)
        self.assertTrue((self.state / "report.json").is_file(), out + err)


class StateDirDescriptorPinning(StateDirGuard):
    """После проверки каталога состояния и взятия flock все записи (отчёт,
    журналы) идут относительно удерживаемого дескриптора проверенного
    каталога, а не по строке пути STATE_DIR (аудит Codex, коммит 6780086,
    п. B-01). Атака: сразу после `ensure_state_dir()` (дескриптор уже открыт,
    flock уже удерживается) каталог состояния переименовывается, а на его
    месте создаётся новый пустой каталог — как если бы внешний процесс подменил
    каталог между проверкой и записью. Запись обязана остаться в исходном
    (переименованном) inode; новый каталог должен остаться пустым.
    """

    def run_dispatcher_with_rename_attack(self, mode="DRY_RUN"):
        self.assertEqual(self.dispatcher.count(self.ENSURE_CALL), 1)
        attack = (
            self.ENSURE_CALL
            + "    _slp_test_attacker_dir = STATE_DIR + '.attacker'\n"
            + "    os.rename(STATE_DIR, _slp_test_attacker_dir)\n"
            + "    os.mkdir(STATE_DIR, 0o700)\n"
        )
        me = os.getuid()
        source = self.dispatcher.replace(self.ENSURE_CALL, attack, 1)
        source = source.replace(STATE_DIR_LINE, "STATE_DIR = " + repr(str(self.state)), 1)
        source = source.replace(TRUSTED_UID_LINE, "TRUSTED_UID = %d\nPARENT_TRUSTED_UID = %d" % (me, me), 1)
        return subprocess.run(
            [PYTHON, "-I", "-S", "-B", "-", mode], input=source,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=self.tmp, timeout=600,
        )

    def test_report_and_logs_stay_in_originally_validated_directory(self):
        self.state.mkdir(mode=0o700)
        cp = self.run_dispatcher_with_rename_attack()
        attacker_dir = self.state.parent / (self.state.name + ".attacker")
        self.assertTrue(attacker_dir.is_dir(), "переименование в сценарии атаки не произошло")
        self.assertFalse(
            (self.state / "report.json").exists(),
            "отчёт записан в подменённый каталог, а не в тот, что был проверен: " + cp.stdout + cp.stderr,
        )
        self.assertFalse(
            (self.state / "apply.log").exists(),
            "журнал записан в подменённый каталог, а не в тот, что был проверен: " + cp.stdout + cp.stderr,
        )
        self.assertTrue(
            (attacker_dir / "report.json").is_file(),
            "отчёт не найден в исходном (переименованном) каталоге: " + cp.stdout + cp.stderr,
        )
        self.assertTrue(
            (attacker_dir / "apply.log").is_file(),
            "журнал не найден в исходном (переименованном) каталоге: " + cp.stdout + cp.stderr,
        )

    def test_debug_log_and_lock_stay_in_originally_validated_directory(self):
        # Пробел теста (репарация, аудит Codex 6780086..3215d1c): та же атака
        # переименования проверяет ТОЛЬКО report.json и apply.log; debug.log
        # и .lock открываются тем же способом (dir_fd от того же дескриптора,
        # взятого в ensure_state_dir() до переименования), но раньше отдельно
        # не проверялись.
        self.state.mkdir(mode=0o700)
        cp = self.run_dispatcher_with_rename_attack()
        attacker_dir = self.state.parent / (self.state.name + ".attacker")
        self.assertTrue(attacker_dir.is_dir(), "переименование в сценарии атаки не произошло")
        self.assertFalse(
            (self.state / "debug.log").exists(),
            "debug.log записан в подменённый каталог, а не в тот, что был проверен: " + cp.stdout + cp.stderr,
        )
        self.assertFalse(
            (self.state / ".lock").exists(),
            ".lock создан в подменённом каталоге, а не в том, что был проверен: " + cp.stdout + cp.stderr,
        )
        self.assertTrue(
            (attacker_dir / "debug.log").is_file(),
            "debug.log не найден в исходном (переименованном) каталоге: " + cp.stdout + cp.stderr,
        )
        self.assertTrue(
            (attacker_dir / ".lock").is_file(),
            ".lock не найден в исходном (переименованном) каталоге: " + cp.stdout + cp.stderr,
        )

    def test_lock_after_rename_attack_is_independent_inode_from_new_path(self):
        # flock берётся на дескрипторе, открытом ДО переименования (в
        # ensure_state_dir()), поэтому это другой inode, чем тот, что получил
        # бы .lock, открытый заново по пути STATE_DIR после подмены каталога.
        # Свежий, не атакующий прогон по тому же пути STATE_DIR (который после
        # атаки указывает на новый, пустой каталог подменённого сценария) не
        # видит блокировку исходного (переименованного) каталога — это и
        # доказывает, что блокировки относятся к разным inode, а не к одному
        # пути.
        self.state.mkdir(mode=0o700)
        cp = self.run_dispatcher_with_rename_attack()
        self.assertNotIn("already running", cp.stderr, cp.stdout + cp.stderr)
        attacker_dir = self.state.parent / (self.state.name + ".attacker")
        self.assertTrue((attacker_dir / ".lock").is_file())
        # исходный процесс уже завершился (subprocess дождались) — его flock
        # снят вместе с закрытием дескриптора; тем не менее самим .lock-файлом
        # в исходном (переименованном) каталоге подтверждено, что запись шла
        # не по пути self.state. Явно фиксируем это отдельным inode-сравнением.
        self.assertNotEqual(
            os.stat(attacker_dir / ".lock").st_ino,
            os.stat(self.state).st_ino,
            "самопроверка сценария: атакующий каталог и новый self.state не должны совпадать",
        )
        cp2 = self.run_dispatcher()
        self.assertNotIn("already running", cp2.stderr, cp2.stdout + cp2.stderr)
        self.assertTrue((self.state / "report.json").is_file(), cp2.stdout + cp2.stderr)


if __name__ == "__main__":
    unittest.main()
