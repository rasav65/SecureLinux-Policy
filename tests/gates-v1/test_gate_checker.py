#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = Path(__file__).resolve().parents[2]
CHECKER = PROJECT / "checker/gates-v1/checker.py"
FIX = HERE / "fixtures"

spec = importlib.util.spec_from_file_location("gate_checker_v1", CHECKER)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)

class GatesV1Tests(unittest.TestCase):
    def run_case(self, index_name, control_case):
        return mod.run_all(PROJECT, FIX/"indexes"/index_name, FIX/control_case)
    def gate(self, report, n):
        return next(g for g in report["gates"] if g["gate"] == n)

    def test_positive_all_gates(self):
        r=self.run_case("positive.tsv","positive"); self.assertTrue(r["overall_pass"],mod.format_report(r))
    def test_gate1_bad_quote_hash(self):
        self.assertFalse(self.gate(self.run_case("positive.tsv","negative-bad-quote-hash"),1)["pass"])
    def test_gate1_bad_doc_hash(self):
        self.assertFalse(self.gate(self.run_case("positive.tsv","negative-bad-doc-hash"),1)["pass"])
    def test_gate1_quote_not_found(self):
        self.assertFalse(self.gate(self.run_case("positive.tsv","negative-quote-not-found"),1)["pass"])
    def test_gate1_unknown_index(self):
        self.assertFalse(self.gate(self.run_case("positive.tsv","negative-unknown-index"),1)["pass"])
    def test_gate2_open_uncovered(self):
        g=self.gate(self.run_case("uncovered.tsv","positive"),2); self.assertFalse(g["pass"]); self.assertEqual(g["uncovered_rows"],1)
    def test_gate3_derived_requires_justification(self):
        self.assertFalse(self.gate(self.run_case("positive.tsv","negative-derived-without-justification"),3)["pass"])
    def test_gate3_bad_sysctl_locator(self):
        self.assertFalse(self.gate(self.run_case("positive.tsv","negative-bad-sysctl-locator"),3)["pass"])
    def test_gate3_type_mismatch(self):
        self.assertFalse(self.gate(self.run_case("positive.tsv","negative-type-mismatch"),3)["pass"])
    def test_gate3_unknown_field(self):
        self.assertFalse(self.gate(self.run_case("positive.tsv","negative-unknown-field"),3)["pass"])
    def test_gate4_duplicate_id(self):
        self.assertFalse(self.gate(self.run_case("positive.tsv","negative-duplicate-id"),4)["pass"])
    def test_gate4_conflicting_parameter(self):
        g=self.gate(self.run_case("positive.tsv","negative-conflict"),4); self.assertFalse(g["pass"]); self.assertEqual(g["conflicts"],1)
    def test_active_corpus_is_fail_closed(self):
        r=mod.run_all(PROJECT,PROJECT/"index/source-v2/SOURCE-INDEX.tsv",PROJECT/"controls")
        self.assertFalse(r["overall_pass"])
        g1 = self.gate(r,1)
        # Historical gates-v1 is not current product authority. SRC-0014 uses an
        # exact pinned inline page-furniture correction that exists only in the
        # current source-skeleton/gates-v3 path. Legacy Gate1 must therefore fail
        # closed on that one canonical quote instead of guessing the correction.
        self.assertFalse(g1["pass"])
        self.assertEqual(g1["passed_records"] + 1, g1["checked_records"])
        self.assertEqual(len(g1["errors"]), 1)
        self.assertTrue(any(
            "fstec-linux-2022-2.3.10-home-sensitive-files-mode.yaml: normalized quote not found in normalized source corpus" in e
            for e in g1["errors"]
        ))
        self.assertFalse(self.gate(r,2)["pass"])
        self.assertEqual(self.gate(r,2)["uncovered_rows"],349)
        # Historical gates-v1 is not current product authority: the current corpus
        # now contains file-mode-owner/bits-clear semantics added in gates-v3.
        # It must fail closed rather than silently accept that newer kind.
        g3 = self.gate(r,3)
        self.assertFalse(g3["pass"])
        self.assertTrue(any("file-mode-owner" in e for e in g3["errors"]))
        self.assertTrue(self.gate(r,4)["pass"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
