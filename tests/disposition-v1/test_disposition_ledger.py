#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
CHECKER = PROJECT / "checker/gates-v3/checker.py"

spec = importlib.util.spec_from_file_location("checker_disposition_v1", CHECKER)
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)

HEADER = "index_id\tdisposition\treason\tbasis\tdecided_by\tdecided_at\n"


def row(*, status="CLOSED", disposition="informational", reason="Synthetic reviewed disposition"):
    return {
        "index_id":"SRC-9000","source_id":"synthetic","source_file":"synthetic.pdf",
        "source_sha256":"0"*64,"source_role":"transitive-process",
        "unit_kind":"synthetic","locator":"1","raw_match_line":"1",
        "text_quality":"readable","quote_anchor_ready":"YES",
        "status":status,"disposition":disposition,"reason":reason,"note":"",
    }


def control_record():
    return {
        "id":"CTRL-SYNTHETIC","layer":"fstec-core","profile":None,
        "source":{
            "index_id":"SRC-9000","doc_id":"synthetic","doc_sha256":"0"*64,
            "locator":"1","quote":"q",
            "quote_sha256":"8e35c2cd3bf6641bdb0e2050b76932cbb2e6034a0ddacc1d9bea82a6ba57f7cf",
            "norm":"norm-v1",
        },
        "requirement":{
            "stated":"x","derived":False,"justification":None,
            "applicability":"technical",
        },
        "parameter":{
            "kind":"sysctl","locator":"sysctl","key":"kernel.synthetic",
        },
        "expected":{"op":"eq","value":1,"type":"integer"},
        "apply":{"supported":False},
    }


def write_contract(root: Path, text: str = "") -> Path:
    p = root / "CLOSURE-CONTRACT.tsv"
    p.write_text(
        "index_id\tcoverage_mode\texpected_control_ids\tbasis\n" + text,
        encoding="utf-8", newline="\n",
    )
    return p


def write_ledger(root: Path, body: str = "") -> Path:
    p = root / "DISPOSITION-LEDGER.tsv"
    p.write_text(HEADER + body, encoding="utf-8", newline="\n")
    return p


def valid_ledger_line(
    *, idx="SRC-9000", disposition="informational",
    reason="Synthetic reviewed disposition",
    basis="Synthetic independent review basis",
    decided_by="reviewer-1", decided_at="2026-08-15T12:00:00Z",
):
    return (
        f"{idx}\t{disposition}\t{reason}\t{basis}\t{decided_by}\t{decided_at}\n"
    )


def gate2_for(root: Path, index_row, *, controls=None, contract_body="", ledger_body=""):
    contract = write_contract(root, contract_body)
    ledger = write_ledger(root, ledger_body)
    return mod.gate2(
        [index_row], {index_row["index_id"]: index_row},
        [] if controls is None else controls,
        contract, ledger,
    )


# Positive: the alternative closure path is executed synthetically before any
# real FSTEC disposition exists.
with tempfile.TemporaryDirectory(prefix="slp-disposition-positive-") as td:
    root = Path(td)
    g = gate2_for(root, row(), ledger_body=valid_ledger_line())
    assert g["pass"], g["errors"]
    assert g["controlled_closed_rows"] == 0
    assert g["disposed_closed_rows"] == 1
    assert g["uncovered_rows"] == 0
    assert g["disposition_ledger_rows"] == 1

# Negative 1: unknown disposition is rejected by the ledger contract.
with tempfile.TemporaryDirectory(prefix="slp-disposition-enum-") as td:
    root = Path(td)
    g = gate2_for(
        root, row(disposition="made-up"),
        ledger_body=valid_ledger_line(disposition="made-up"),
    )
    assert not g["pass"]
    assert any("unsupported disposition" in e for e in g["errors"]), g["errors"]

# Negative 2: blank/whitespace reason is not a valid disposed closure.
with tempfile.TemporaryDirectory(prefix="slp-disposition-reason-") as td:
    root = Path(td)
    g = gate2_for(
        root, row(reason="   "),
        ledger_body=valid_ledger_line(reason="   "),
    )
    assert not g["pass"]
    assert any("reason is required" in e or "no valid CLOSED disposition+reason" in e
               for e in g["errors"]), g["errors"]

# Negative 3: disposed CLOSED without ledger must fail.
with tempfile.TemporaryDirectory(prefix="slp-disposition-missing-ledger-") as td:
    root = Path(td)
    g = gate2_for(root, row())
    assert not g["pass"]
    assert any("has no disposition ledger entry" in e for e in g["errors"]), g["errors"]

# Negative 4: duplicate ledger identity is invalid.
with tempfile.TemporaryDirectory(prefix="slp-disposition-duplicate-") as td:
    root = Path(td)
    body = valid_ledger_line() + valid_ledger_line()
    g = gate2_for(root, row(), ledger_body=body)
    assert not g["pass"]
    assert any("duplicate index_id" in e for e in g["errors"]), g["errors"]

# Negative 5: orphan ledger entry is an explicit error.
with tempfile.TemporaryDirectory(prefix="slp-disposition-orphan-") as td:
    root = Path(td)
    contract = write_contract(root)
    ledger = write_ledger(root, valid_ledger_line(idx="SRC-9999"))
    r = row()
    g = mod.gate2([r], {r["index_id"]:r}, [], contract, ledger)
    assert not g["pass"]
    assert any("references unknown index row SRC-9999" in e for e in g["errors"]), g["errors"]

# Negative 6: a represented/controlled row may not carry disposition state.
with tempfile.TemporaryDirectory(prefix="slp-disposition-controlled-") as td:
    root = Path(td)
    r = row(disposition="informational", reason="Synthetic reviewed disposition")
    contract_body = (
        "SRC-9000\tatomic-single\tCTRL-SYNTHETIC\tfull-clause synthetic review\n"
    )
    g = gate2_for(
        root, r,
        controls=[(Path("synthetic.yaml"), control_record())],
        contract_body=contract_body,
        ledger_body=valid_ledger_line(),
    )
    assert not g["pass"]
    assert any("controlled row must not carry disposition/reason" in e
               for e in g["errors"]), g["errors"]

# Negative 7: even with empty disposition/reason, a controlled row may not
# carry a disposition ledger entry.
with tempfile.TemporaryDirectory(prefix="slp-disposition-controlled-ledger-") as td:
    root = Path(td)
    r = row(disposition="", reason="")
    contract_body = (
        "SRC-9000\tatomic-single\tCTRL-SYNTHETIC\tfull-clause synthetic review\n"
    )
    g = gate2_for(
        root, r,
        controls=[(Path("synthetic.yaml"), control_record())],
        contract_body=contract_body,
        ledger_body=valid_ledger_line(),
    )
    assert not g["pass"]
    assert any("controlled row must not carry a disposition ledger entry" in e
               for e in g["errors"]), g["errors"]

# Negative 8: the ledger file itself is a required fail-closed artifact.
with tempfile.TemporaryDirectory(prefix="slp-disposition-ledger-file-") as td:
    root = Path(td)
    contract = write_contract(root)
    missing = root / "DISPOSITION-LEDGER.tsv"
    r = row()
    g = mod.gate2([r], {r["index_id"]:r}, [], contract, missing)
    assert not g["pass"]
    assert any("disposition ledger invalid" in e for e in g["errors"]), g["errors"]

# Negative 9: disposed row must not carry a completeness contract.
with tempfile.TemporaryDirectory(prefix="slp-disposition-contract-") as td:
    root = Path(td)
    contract_body = (
        "SRC-9000\tatomic-single\tCTRL-SYNTHETIC\tfull-clause synthetic review\n"
    )
    g = gate2_for(
        root, row(), contract_body=contract_body,
        ledger_body=valid_ledger_line(),
    )
    assert not g["pass"]
    assert any("disposed CLOSED row must not carry a control completeness contract" in e
               for e in g["errors"]), g["errors"]

# Negative 10: ledger disposition must equal SOURCE-INDEX disposition.
with tempfile.TemporaryDirectory(prefix="slp-disposition-mismatch-") as td:
    root = Path(td)
    g = gate2_for(
        root, row(disposition="informational"),
        ledger_body=valid_ledger_line(disposition="organizational"),
    )
    assert not g["pass"]
    assert any("disposition ledger mismatch" in e for e in g["errors"]), g["errors"]

# Additional fail-closed invariant: the duplicated human reason may not drift.
with tempfile.TemporaryDirectory(prefix="slp-disposition-reason-mismatch-") as td:
    root = Path(td)
    g = gate2_for(
        root, row(reason="Index reason"),
        ledger_body=valid_ledger_line(reason="Ledger reason"),
    )
    assert not g["pass"]
    assert any("disposition ledger reason mismatch" in e for e in g["errors"]), g["errors"]

# Fixed machine-verifiable timestamp format and actual calendar validity.
with tempfile.TemporaryDirectory(prefix="slp-disposition-time-") as td:
    root = Path(td)
    g = gate2_for(
        root, row(),
        ledger_body=valid_ledger_line(decided_at="2026-02-30T12:00:00Z"),
    )
    assert not g["pass"]
    assert any("invalid decided_at" in e for e in g["errors"]), g["errors"]

# Negative 13: a data row may not carry more values than the closed schema.
with tempfile.TemporaryDirectory(prefix="slp-disposition-extra-data-field-") as td:
    root = Path(td)
    extra = valid_ledger_line().rstrip("\n") + "\tUNDECLARED_EXTRA\n"
    g = gate2_for(root, row(), ledger_body=extra)
    assert not g["pass"]
    assert any("expected 6 TSV fields, got 7" in e for e in g["errors"]), g["errors"]

# Negative 14: a short data row is rejected explicitly by the closed schema.
with tempfile.TemporaryDirectory(prefix="slp-disposition-short-data-row-") as td:
    root = Path(td)
    short = "\t".join(valid_ledger_line().rstrip("\n").split("\t")[:-1]) + "\n"
    g = gate2_for(root, row(), ledger_body=short)
    assert not g["pass"]
    assert any("expected 6 TSV fields, got 5" in e for e in g["errors"]), g["errors"]

# Negative 15: quoting is disabled; a tab in free-text basis is a real delimiter.
with tempfile.TemporaryDirectory(prefix="slp-disposition-quoted-tab-basis-") as td:
    root = Path(td)
    quoted = valid_ledger_line(basis='"Basis\tINJECTED"')
    g = gate2_for(root, row(), ledger_body=quoted)
    assert not g["pass"]
    assert any("expected 6 TSV fields, got 7" in e for e in g["errors"]), g["errors"]

# Negative 16: quoting may not merge physical LF-delimited lines.
with tempfile.TemporaryDirectory(prefix="slp-disposition-quoted-newline-basis-") as td:
    root = Path(td)
    quoted = valid_ledger_line(basis='"Basis\nINJECTED"')
    g = gate2_for(root, row(), ledger_body=quoted)
    assert not g["pass"]
    assert any("expected 6 TSV fields" in e for e in g["errors"]), g["errors"]

# Negative 17: quoting may not merge physical CR-delimited lines either.
with tempfile.TemporaryDirectory(prefix="slp-disposition-quoted-cr-basis-") as td:
    root = Path(td)
    quoted = valid_ledger_line(basis='"Basis\rINJECTED"')
    g = gate2_for(root, row(), ledger_body=quoted)
    assert not g["pass"]
    assert any("expected 6 TSV fields" in e for e in g["errors"]), g["errors"]

# Negative 18: parser safety in reason must not depend on index equality as a side effect.
with tempfile.TemporaryDirectory(prefix="slp-disposition-quoted-tab-reason-") as td:
    root = Path(td)
    quoted = valid_ledger_line(reason='"Synthetic\treviewed disposition"')
    g = gate2_for(root, row(), ledger_body=quoted)
    assert not g["pass"]
    assert any("expected 6 TSV fields, got 7" in e for e in g["errors"]), g["errors"]

print(
    "DISPOSITION_LEDGER_TESTS=PASS positive=1 "
    "negative_enum=1 negative_blank_reason=1 negative_missing_ledger=1 "
    "negative_duplicate=1 negative_orphan=1 negative_controlled_disposition=1 "
    "negative_controlled_ledger=1 negative_missing_ledger_file=1 "
    "negative_disposed_contract=1 negative_disposition_mismatch=1 "
    "negative_reason_mismatch=1 negative_invalid_decided_at=1 "
    "negative_extra_data_field=1 negative_short_data_row=1 "
    "negative_quoted_tab_basis=1 negative_quoted_newline_basis=1 "
    "negative_quoted_cr_basis=1 negative_quoted_tab_reason=1"
)
