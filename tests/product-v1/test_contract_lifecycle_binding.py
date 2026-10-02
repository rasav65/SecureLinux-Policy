#!/usr/bin/env python3
# product-v1 regression: active/historical derivation for product contracts and adapters.
# Active set is derived from product/ADAPTER-REGISTRY.tsv only. No separate status file.
import csv, hashlib, json, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADAPTER_REGISTRY = ROOT / "product" / "ADAPTER-REGISTRY.tsv"
OTHER_REGISTRIES = (
    ROOT / "product" / "APPLY-KIND-REGISTRY.tsv",
    ROOT / "product" / "APPLY-IMPLEMENTATION-REGISTRY.tsv",
)
CONTRACTS_DIR = ROOT / "product" / "contracts"
ADAPTERS_DIR = ROOT / "product" / "adapters"
HISTORICAL = "HISTORICAL_UNREGISTERED"

def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def registry_rows():
    with ADAPTER_REGISTRY.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))

def registry_texts():
    out = {ADAPTER_REGISTRY.name: ADAPTER_REGISTRY.read_text(encoding="utf-8")}
    for path in OTHER_REGISTRIES:
        if path.is_file():
            out[path.name] = path.read_text(encoding="utf-8")
    return out

def check_contract_paths():
    return sorted(p.relative_to(ROOT).as_posix() for p in CONTRACTS_DIR.glob("*check-semantic*.json"))

def adapter_paths():
    return sorted(p.relative_to(ROOT).as_posix() for p in ADAPTERS_DIR.glob("product-*-check-v*.*"))

ROWS = registry_rows()
ACTIVE_CONTRACTS = {r["semantic_contract_path"] for r in ROWS}
ACTIVE_ADAPTER_FILES = {r["adapter_contract_path"] for r in ROWS} | {r["implementation_path"] for r in ROWS}

class Derivation(unittest.TestCase):
    def test_registry_shape_is_the_single_active_source(self):
        self.assertTrue(ROWS)
        self.assertEqual(
            set(ROWS[0]),
            {"parameter_kind", "adapter_id", "semantic_contract_path", "semantic_contract_sha256",
             "adapter_contract_path", "adapter_contract_sha256", "implementation_path", "implementation_sha256"},
        )
        self.assertEqual(len({r["parameter_kind"] for r in ROWS}), len(ROWS))
        self.assertEqual(len({r["adapter_id"] for r in ROWS}), len(ROWS))
        self.assertEqual(len(ACTIVE_CONTRACTS), len(ROWS))

    def test_active_contract_bytes_are_bound_and_not_marked_historical(self):
        for row in ROWS:
            path = ROOT / row["semantic_contract_path"]
            with self.subTest(contract=row["semantic_contract_path"]):
                self.assertTrue(path.is_file())
                self.assertEqual(sha256_file(path), row["semantic_contract_sha256"])
                data = json.loads(path.read_text(encoding="utf-8"))
                self.assertNotEqual(data.get("lifecycle_status"), HISTORICAL,
                                    "active row points at a historical contract")

    def test_every_check_contract_is_either_active_or_unreferenced(self):
        contracts = check_contract_paths()
        self.assertTrue(contracts)
        self.assertTrue(ACTIVE_CONTRACTS.issubset(set(contracts)))
        historical = [c for c in contracts if c not in ACTIVE_CONTRACTS]
        self.assertTrue(historical, "expected at least one superseded contract")
        for name, text in registry_texts().items():
            for contract in historical:
                with self.subTest(registry=name, contract=contract):
                    self.assertNotIn(contract, text, "historical contract referenced by an active registry")
                    self.assertNotIn(sha256_file(ROOT / contract), text,
                                     "historical contract SHA referenced by an active registry")

    def test_every_check_adapter_is_either_active_or_unreferenced(self):
        adapters = adapter_paths()
        self.assertTrue(adapters)
        self.assertTrue(ACTIVE_ADAPTER_FILES.issubset(set(adapters)))
        for row in ROWS:
            with self.subTest(adapter=row["adapter_id"]):
                for path_key, sha_key in (("adapter_contract_path", "adapter_contract_sha256"),
                                          ("implementation_path", "implementation_sha256")):
                    path = ROOT / row[path_key]
                    self.assertTrue(path.is_file(), row[path_key])
                    self.assertEqual(sha256_file(path), row[sha_key], row[path_key])
        historical = [a for a in adapters if a not in ACTIVE_ADAPTER_FILES]
        self.assertTrue(historical, "expected at least one superseded adapter file")
        for name, text in registry_texts().items():
            for adapter in historical:
                with self.subTest(registry=name, adapter=adapter):
                    self.assertNotIn(adapter, text, "historical adapter referenced by an active registry")

    def test_adapter_files_come_in_json_plus_py_pairs(self):
        stems = {}
        for rel in adapter_paths():
            path = Path(rel)
            stems.setdefault(path.stem, set()).add(path.suffix)
        for stem, suffixes in sorted(stems.items()):
            with self.subTest(adapter=stem):
                self.assertEqual(suffixes, {".json", ".py"})

if __name__ == "__main__":
    unittest.main(verbosity=2)
