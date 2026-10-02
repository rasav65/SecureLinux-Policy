#!/usr/bin/env python3
# product-v1 regression: every canonical control resolves to exactly one semantic
# contract through product/ADAPTER-REGISTRY.tsv, and the control operation is one
# the contract declares. The link is derived; no field is added to control files.
import csv, json, re, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADAPTER_REGISTRY = ROOT / "product" / "ADAPTER-REGISTRY.tsv"
CONTROLS_DIR = ROOT / "controls" / "fstec-core" / "linux-2022"

# Active contracts that do not yet declare supported_ops. This list may only
# shrink: a new entry means a contract lost its operation vocabulary.
# Пусто с 25.09.2026: все активные контракты объявляют supported_ops.
OPS_DECLARATION_GAPS = frozenset()

BLOCK_RE = r"^%s:\n((?:[ \t]+\S.*\n|[ \t]*\n)*)"

def scalar(block, key):
    match = re.search(r"^\s+%s:\s*(.+?)\s*$" % re.escape(key), block, re.M)
    if match is None:
        return None
    value = match.group(1)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value

def control_facts(path):
    text = path.read_text(encoding="utf-8")
    facts = {}
    for section, key in (("parameter", "kind"), ("expected", "op")):
        block = re.search(BLOCK_RE % section, text, re.M)
        facts[key] = scalar(block.group(1), key) if block else None
    return facts

def registry_rows():
    with ADAPTER_REGISTRY.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))

ROWS = registry_rows()
BY_KIND = {row["parameter_kind"]: row for row in ROWS}
CONTROLS = {
    path.name: control_facts(path)
    for path in sorted((ROOT / "controls" / "fstec-core").glob("*/*.yaml"))
}

class ControlContractBinding(unittest.TestCase):
    def test_every_control_declares_kind_and_op(self):
        self.assertTrue(CONTROLS)
        for name, facts in sorted(CONTROLS.items()):
            with self.subTest(control=name):
                self.assertTrue(facts["kind"], "parameter.kind not readable")
                self.assertTrue(facts["op"], "expected.op not readable")

    def test_every_control_resolves_to_exactly_one_contract(self):
        for name, facts in sorted(CONTROLS.items()):
            with self.subTest(control=name):
                row = BY_KIND.get(facts["kind"])
                self.assertIsNotNone(row, "parameter kind absent from ADAPTER-REGISTRY.tsv")
                contract = ROOT / row["semantic_contract_path"]
                self.assertTrue(contract.is_file(), row["semantic_contract_path"])

    def test_no_registry_kind_is_left_without_controls(self):
        used = {facts["kind"] for facts in CONTROLS.values()}
        orphans = sorted(set(BY_KIND) - used)
        self.assertEqual(orphans, [], "registry kinds with no canonical control")

    def test_control_operation_is_declared_by_its_contract(self):
        for name, facts in sorted(CONTROLS.items()):
            row = BY_KIND.get(facts["kind"])
            if row is None:
                continue
            contract = json.loads((ROOT / row["semantic_contract_path"]).read_text(encoding="utf-8"))
            supported = contract.get("supported_ops")
            if supported is None:
                continue
            with self.subTest(control=name):
                self.assertIsInstance(supported, list)
                self.assertIn(facts["op"], supported,
                              "control operation is not in the contract vocabulary")

    def test_operation_vocabulary_gaps_only_shrink(self):
        gaps = set()
        for kind, row in sorted(BY_KIND.items()):
            contract = json.loads((ROOT / row["semantic_contract_path"]).read_text(encoding="utf-8"))
            if contract.get("supported_ops") is None:
                gaps.add(kind)
        new_gaps = sorted(gaps - OPS_DECLARATION_GAPS)
        self.assertEqual(new_gaps, [], "contract stopped declaring supported_ops")
        closed = sorted(OPS_DECLARATION_GAPS - gaps)
        self.assertEqual(closed, [],
                         "gap closed: remove these kinds from OPS_DECLARATION_GAPS")

if __name__ == "__main__":
    unittest.main(verbosity=2)
