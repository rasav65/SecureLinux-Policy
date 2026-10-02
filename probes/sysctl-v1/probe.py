#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path

SCHEMA = "securelinux-policy-probe-results-v1"
PLAN_FIELDS = ["control_id","kind","locator","key","expected_type","expected_value"]


def load_plan(path: Path):
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    if fields != PLAN_FIELDS:
        raise RuntimeError(f"unexpected probe plan fields: {fields}")
    if not rows:
        raise RuntimeError("empty probe plan")
    seen = set()
    for row in rows:
        if row["control_id"] in seen:
            raise RuntimeError(f"duplicate control_id in plan: {row['control_id']}")
        seen.add(row["control_id"])
        if row["kind"] != "sysctl" or row["locator"] != "sysctl":
            raise RuntimeError(f"unsupported plan row: {row}")
        if row["expected_type"] not in {"integer","string","boolean"}:
            raise RuntimeError(f"unsupported expected_type: {row['expected_type']}")
    return rows


def compute_compliance(raw: str, typ: str, expected_raw: str):
    if typ == "integer":
        try:
            actual = int(raw)
            expected = int(expected_raw)
        except ValueError:
            return "ERROR"
    elif typ == "boolean":
        if raw not in {"true","false"} or expected_raw not in {"true","false"}:
            return "ERROR"
        actual = raw == "true"
        expected = expected_raw == "true"
    else:
        actual = raw
        expected = expected_raw
    return "PASS" if actual == expected else "FAIL"


def read_one(row, proc_root: Path):
    key = row["key"]
    evidence = Path("/proc/sys") / Path(*key.split("."))
    actual_path = proc_root / Path(*key.split("."))
    base = {
        "control_id": row["control_id"],
        "kind": "sysctl",
        "locator": "sysctl",
        "key": key,
        "evidence_path": evidence.as_posix(),
    }
    try:
        raw = actual_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return {**base, "status":"NOT_FOUND", "value":None, "compliance":"NOT_FOUND"}
    except Exception as exc:
        return {
            **base, "status":"ERROR", "value":None, "compliance":"ERROR",
            "error":f"{type(exc).__name__}: {exc}"
        }

    compliance = compute_compliance(raw, row["expected_type"], row["expected_value"])
    if compliance == "ERROR":
        return {
            **base, "status":"ERROR", "value":raw, "compliance":"ERROR",
            "error":f"value cannot be parsed as {row['expected_type']}"
        }
    return {**base, "status":"VALUE", "value":raw, "compliance":compliance}


def strip_error_fields(results):
    return [{k:v for k,v in item.items() if k != "error"} for item in results]


def run(plan: Path, proc_root: Path):
    rows = load_plan(plan)
    raw_results = [read_one(row, proc_root) for row in rows]
    errors = [r for r in raw_results if r["status"] == "ERROR"]
    payload = {
        "schema":SCHEMA,
        "probe_kind":"sysctl",
        "read_only":True,
        "results":strip_error_fields(raw_results),
    }
    return payload, errors


def selftest():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        proc = root / "proc"
        (proc / "kernel").mkdir(parents=True)
        (proc / "kernel/dmesg_restrict").write_text("1\n", encoding="utf-8")
        plan = root / "plan.tsv"
        plan.write_text(
            "\t".join(PLAN_FIELDS) + "\n"
            "CTRL-A\tsysctl\tsysctl\tkernel.dmesg_restrict\tinteger\t1\n"
            "CTRL-B\tsysctl\tsysctl\tkernel.kptr_restrict\tinteger\t2\n",
            encoding="utf-8", newline="\n",
        )
        payload, errors = run(plan, proc)
        assert not errors
        assert payload["results"][0]["status"] == "VALUE"
        assert payload["results"][0]["value"] == "1"
        assert payload["results"][0]["compliance"] == "PASS"
        assert payload["results"][1]["status"] == "NOT_FOUND"
        assert payload["results"][1]["value"] is None
        assert payload["results"][1]["compliance"] == "NOT_FOUND"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan")
    ap.add_argument("--output")
    ap.add_argument("--proc-root", default="/proc/sys")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        print("SYSCTL_PROBE_SELFTEST=PASS")
        return 0

    if not args.plan or not args.output:
        ap.error("--plan and --output are required unless --selftest is used")

    payload, errors = run(Path(args.plan), Path(args.proc_root))
    out = Path(args.output)
    out.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n",
    )

    values = sum(r["status"] == "VALUE" for r in payload["results"])
    missing = sum(r["status"] == "NOT_FOUND" for r in payload["results"])
    noncompliant = sum(r.get("compliance") == "FAIL" for r in payload["results"])
    print(f"PROBE_RESULTS={len(payload['results'])}")
    print(f"VALUE={values}")
    print(f"NOT_FOUND={missing}")
    print(f"NONCOMPLIANT={noncompliant}")
    print(f"ERROR={len(errors)}")
    print(f"OUTPUT={out}")

    if errors:
        for e in errors:
            print(
                f"PROBE_ERROR control_id={e['control_id']} key={e['key']} "
                f"error={e.get('error','unknown')}",
                file=sys.stderr,
            )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
