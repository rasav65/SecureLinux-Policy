#!/usr/bin/env python3
from __future__ import annotations

import csv
import importlib.util
import json
import shutil
import tempfile
import unittest
import csv
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = Path(__file__).resolve().parents[2]
CHECKER = PROJECT / "checker/gates-v3/checker.py"

spec = importlib.util.spec_from_file_location("checker_v3", CHECKER)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)


def base_record(cid="CTRL-ONE", layer="fstec-core", profile=None, value=1):
    return {
        "id": cid,
        "layer": layer,
        "profile": profile,
        "source": {
            "index_id": "SRC-0001",
            "doc_id": "test",
            "doc_sha256": "0"*64,
            "locator": "1",
            "quote": "q",
            "quote_sha256": "8e35c2cd3bf6641bdb0e2050b76932cbb2e6034a0ddacc1d9bea82a6ba57f7cf",
            "norm": "norm-v1",
        },
        "requirement": {
            "stated": "x",
            "derived": False,
            "justification": None,
            "applicability": "technical",
        },
        "parameter": {
            "kind": "sysctl",
            "locator": "sysctl",
            "key": "kernel.test",
        },
        "expected": {"op": "eq", "value": value, "type": "integer"},
        "apply": {"supported": False},
    }


class Gate4ScopeTests(unittest.TestCase):
    def test_same_scope_divergence_fails(self):
        a=base_record("CTRL-A",value=1)
        b=base_record("CTRL-B",value=2)
        g=mod.gate4([(Path("a"),a),(Path("b"),b)])
        self.assertFalse(g["pass"])
        self.assertEqual(g["scope_conflicts"],1)

    def test_corporate_profile_variants_allowed(self):
        a=base_record("CTRL-A","corporate","baseline",1)
        b=base_record("CTRL-B","corporate","strict",2)
        g=mod.gate4([(Path("a"),a),(Path("b"),b)])
        self.assertTrue(g["pass"],g["errors"])
        self.assertEqual(g["profile_variants"],1)

    def test_cross_layer_divergence_fail_closed(self):
        a=base_record("CTRL-A","fstec-core",None,1)
        b=base_record("CTRL-B","recommended",None,2)
        g=mod.gate4([(Path("a"),a),(Path("b"),b)])
        self.assertFalse(g["pass"])
        self.assertEqual(g["cross_scope_conflicts"],1)


class ContractTests(unittest.TestCase):
    def index_rows(self):
        return [{
            "index_id":"SRC-0001","source_id":"test","source_file":"test.pdf",
            "source_sha256":"0"*64,"source_role":"technical-core",
            "unit_kind":"numbered","locator":"1","raw_match_line":"1",
            "text_quality":"readable","quote_anchor_ready":"YES",
            "status":"CLOSED","disposition":"","reason":"","note":"",
        }]

    def write_contract(self, root, mode, ids):
        p=root/"CLOSURE-CONTRACT.tsv"
        p.write_text(
            "index_id\tcoverage_mode\texpected_control_ids\tbasis\n"
            f"SRC-0001\t{mode}\t{ids}\tfull-clause semantic review\n",
            encoding="utf-8",newline="\n"
        )
        return p

    def write_empty_ledger(self, root):
        p=root/"DISPOSITION-LEDGER.tsv"
        p.write_text(
            "index_id\tdisposition\treason\tbasis\tdecided_by\tdecided_at\n",
            encoding="utf-8",newline="\n"
        )
        return p

    def test_atomic_contract_exact_set_passes(self):
        with tempfile.TemporaryDirectory() as td:
            p=self.write_contract(Path(td),"atomic-single","CTRL-ONE")
            ledger=self.write_empty_ledger(Path(td))
            rows=self.index_rows()
            g=mod.gate2(rows,{"SRC-0001":rows[0]},
                [(Path("x"),base_record())],p,ledger)
            self.assertTrue(g["pass"],g["errors"])

    def test_missing_contract_fails(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"CLOSURE-CONTRACT.tsv"
            p.write_text(
                "index_id\tcoverage_mode\texpected_control_ids\tbasis\n",
                encoding="utf-8",newline="\n"
            )
            ledger=self.write_empty_ledger(Path(td))
            rows=self.index_rows()
            g=mod.gate2(rows,{"SRC-0001":rows[0]},
                [(Path("x"),base_record())],p,ledger)
            self.assertFalse(g["pass"])

    def test_composite_contract_incomplete_actual_set_fails(self):
        with tempfile.TemporaryDirectory() as td:
            p=self.write_contract(Path(td),"exact-control-set","CTRL-ONE,CTRL-TWO")
            ledger=self.write_empty_ledger(Path(td))
            rows=self.index_rows()
            g=mod.gate2(rows,{"SRC-0001":rows[0]},
                [(Path("x"),base_record())],p,ledger)
            self.assertFalse(g["pass"])


class SchemaContractTests(unittest.TestCase):
    def test_schema_has_nested_contract_and_eight_kinds(self):
        schema=json.loads((PROJECT/"checker/gates-v3/CONTROL-SCHEMA.json").read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        for key in ("source","requirement","parameter","expected","apply"):
            self.assertIn("properties",schema["properties"][key])
            self.assertIn("required",schema["properties"][key])
            self.assertFalse(schema["properties"][key]["additionalProperties"])
        kinds=set(schema["properties"]["parameter"]["properties"]["kind"]["enum"])
        self.assertEqual(kinds,{
            "sysctl","file-kv","file-mode-owner","mount-option",
            "systemd-unit-state","package-presence","pam-line","audit-rule"
        })


class ActivePilotTests(unittest.TestCase):
    def test_active_pilot_without_vm_evidence_is_fail_closed(self):
        r=mod.run_all(
            PROJECT,
            PROJECT/"index/source-v4/SOURCE-INDEX.tsv",
            PROJECT/"controls",
            None,
        )
        by={g["gate"]:g for g in r["gates"]}
        with (PROJECT/"index/source-v4/SOURCE-INDEX.tsv").open(
            encoding="utf-8", newline=""
        ) as stream:
            index_rows=list(csv.DictReader(stream, delimiter="\t"))
        with (PROJECT/"index/source-v4/CLOSURE-CONTRACT.tsv").open(
            encoding="utf-8", newline=""
        ) as stream:
            contract_rows=list(csv.DictReader(stream, delimiter="\t"))
        controlled=sum(
            row["status"]=="CLOSED" and not row["disposition"]
            for row in index_rows
        )
        open_rows=sum(row["status"]=="OPEN" for row in index_rows)

        self.assertTrue(by[1]["pass"])
        self.assertFalse(by[2]["pass"])
        self.assertEqual(by[2]["controlled_closed_rows"], controlled)
        self.assertEqual(by[2]["uncovered_rows"], open_rows)
        self.assertEqual(by[2]["contract_rows"], len(contract_rows))
        self.assertTrue(by[3]["pass"])
        self.assertTrue(by[4]["pass"])
        self.assertFalse(by[5]["pass"])


if __name__=="__main__":
    unittest.main(verbosity=2)
