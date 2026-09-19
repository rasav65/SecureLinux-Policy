#!/usr/bin/env python3
"""Сквозная проверка встроенного APPLY-dispatcher с реальными адаптерами.

Продукт генерируется во временный каталог вне репозитория. Из сгенерированных
байтов извлекается встроенный Python-dispatcher и исполняется в режиме DRY_RUN
без root. Единственная замена на стороне теста — STATE_DIR, как в
test_product_generator.py: отчёт и журналы пишутся во временный каталог.
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


if __name__ == "__main__":
    unittest.main()
