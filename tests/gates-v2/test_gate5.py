#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = Path(__file__).resolve().parents[2]
CHECKER = PROJECT / "checker/gates-v2/checker.py"

spec = importlib.util.spec_from_file_location("checker_v2", CHECKER)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)

def record():
    return {
        "id":"TEST-SYSCTL",
        "layer":"fstec-core",
        "profile":None,
        "source":{
            "index_id":"SRC-0001","doc_id":"test","doc_sha256":"0"*64,
            "locator":"1","quote":"q",
            "quote_sha256":"8e35c2cd3bf6641bdb0e2050b76932cbb2e6034a0ddacc1d9bea82a6ba57f7cf",
            "norm":"norm-v1",
        },
        "requirement":{"stated":"x","derived":False,"justification":None,"applicability":"technical"},
        "parameter":{"kind":"sysctl","locator":"sysctl","key":"kernel.dmesg_restrict"},
        "expected":{"op":"eq","value":1,"type":"integer"},
        "apply":{"supported":False},
    }

def payload(status="VALUE", value="1", compliance="PASS"):
    return {
        "schema":"securelinux-policy-probe-results-v1",
        "probe_kind":"sysctl",
        "read_only":True,
        "results":[{
            "control_id":"TEST-SYSCTL","kind":"sysctl","locator":"sysctl",
            "key":"kernel.dmesg_restrict","status":status,"value":value,
            "compliance":compliance,
            "evidence_path":"/proc/sys/kernel/dmesg_restrict",
        }],
    }

class Gate5Tests(unittest.TestCase):
    def run_payload(self, data):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"r.json"
            p.write_text(json.dumps(data),encoding="utf-8")
            return mod.gate5([(Path("test.yaml"),record())],p)

    def test_value_compliant_passes(self):
        g=self.run_payload(payload()); self.assertTrue(g["pass"]); self.assertEqual(g["value_observations"],1)

    def test_value_noncompliant_still_executable(self):
        g=self.run_payload(payload(value="0",compliance="FAIL"))
        self.assertTrue(g["pass"]); self.assertEqual(g["noncompliant_observations"],1)

    def test_not_found_is_explicit_execution_result(self):
        g=self.run_payload(payload(status="NOT_FOUND",value=None,compliance="NOT_FOUND"))
        self.assertTrue(g["pass"]); self.assertEqual(g["not_found_observations"],1)

    def test_missing_results_file_fails(self):
        g=mod.gate5([(Path("test.yaml"),record())],None); self.assertFalse(g["pass"])

    def test_identity_mismatch_fails(self):
        d=payload(); d["results"][0]["key"]="kernel.kptr_restrict"
        self.assertFalse(self.run_payload(d)["pass"])

    def test_error_status_fails(self):
        self.assertFalse(self.run_payload(payload(status="ERROR",value=None,compliance="ERROR"))["pass"])

    def test_duplicate_result_fails(self):
        d=payload(); d["results"].append(dict(d["results"][0]))
        self.assertFalse(self.run_payload(d)["pass"])

    def test_extra_result_fails(self):
        d=payload()
        x=dict(d["results"][0]); x["control_id"]="EXTRA"; d["results"].append(x)
        self.assertFalse(self.run_payload(d)["pass"])

if __name__=="__main__":
    unittest.main(verbosity=2)
