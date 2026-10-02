#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "checker/gate6-v1/evidence_binding.py"
EVIDENCE = ROOT / "probes/sysctl-v1/evidence/ubuntu-24.04.4-minimal-testmin-20260814"

spec = importlib.util.spec_from_file_location("evidence_binding", MODULE)
m = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(m)


def sha(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def rewrite_sums(d: Path) -> None:
    names = sorted(m.EVIDENCE_MEMBERS)
    (d / "SHA256SUMS").write_text(
        "".join(f"{sha(d/name)}  {name}\n" for name in names),
        encoding="utf-8",
        newline="\n",
    )


def expect_fail(mutator, label: str) -> None:
    with tempfile.TemporaryDirectory(prefix="gate6-neg-") as td:
        d = Path(td) / "evidence"
        shutil.copytree(EVIDENCE, d)
        mutator(d)
        r = m.run_gate(ROOT, d)
        assert r["pass"] is False, label
        assert r["errors"], label


real = m.run_gate(ROOT, EVIDENCE)
assert real["pass"] is True, real
assert real["metadata_bindings"] == 4
assert real["result_documents"] == 2
assert real["vm_origin_attestation"] is False


def bad_probe_hash(d):
    p=d/"VM-METADATA.txt"
    t=p.read_text(encoding="utf-8")
    t=t.replace("PROBE_SHA256=", "PROBE_SHA256=" + "0"*64 + "#", 1)
    p.write_text(t,encoding="utf-8",newline="\n")
    rewrite_sums(d)
expect_fail(bad_probe_hash, "probe hash mutation")


def bad_plan_hash(d):
    p=d/"VM-METADATA.txt"
    lines=[]
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.startswith("PROBE_PLAN_SHA256="):
            line="PROBE_PLAN_SHA256="+"0"*64
        lines.append(line)
    p.write_text("\n".join(lines)+"\n",encoding="utf-8",newline="\n")
    rewrite_sums(d)
expect_fail(bad_plan_hash, "plan hash mutation")


def stale_root_result(d):
    p=d/"probe-results-root.json"
    data=json.loads(p.read_text(encoding="utf-8"))
    data["results"][0]["value"]="999"
    p.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    rewrite_sums(d)
expect_fail(stale_root_result, "root result binding")


def stale_unpriv_result(d):
    p=d/"probe-results-unprivileged.json"
    data=json.loads(p.read_text(encoding="utf-8"))
    data["results"][0]["value"]="999"
    p.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    rewrite_sums(d)
expect_fail(stale_unpriv_result, "unpriv result binding")


def bad_sums(d):
    p=d/"SHA256SUMS"
    t=p.read_text(encoding="utf-8")
    p.write_text(("0"*64)+t[64:],encoding="utf-8",newline="\n")
expect_fail(bad_sums, "evidence checksum mutation")


def missing_sum_member(d):
    p=d/"SHA256SUMS"
    lines=p.read_text(encoding="utf-8").splitlines()
    p.write_text("\n".join(lines[:-1])+"\n",encoding="utf-8",newline="\n")
expect_fail(missing_sum_member, "missing checksum member")


def duplicate_metadata_key(d):
    p=d/"VM-METADATA.txt"
    t=p.read_text(encoding="utf-8")
    p.write_text(t+"HOSTNAME=duplicate\n",encoding="utf-8",newline="\n")
    rewrite_sums(d)
expect_fail(duplicate_metadata_key, "duplicate metadata key")


def unexpected_metadata_key(d):
    p=d/"VM-METADATA.txt"
    t=p.read_text(encoding="utf-8")
    p.write_text(t+"UNDECLARED_FIELD=x\n",encoding="utf-8",newline="\n")
    rewrite_sums(d)
expect_fail(unexpected_metadata_key, "unexpected metadata key")


def false_read_only(d):
    p=d/"probe-results-root.json"
    data=json.loads(p.read_text(encoding="utf-8"))
    data["read_only"]=False
    p.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    # deliberately update metadata and sums so only structural read_only check catches it
    mp=d/"VM-METADATA.txt"
    lines=[]
    newsha=sha(p)
    for line in mp.read_text(encoding="utf-8").splitlines():
        if line.startswith("PROBE_RESULTS_ROOT_SHA256="):
            line="PROBE_RESULTS_ROOT_SHA256="+newsha
        lines.append(line)
    mp.write_text("\n".join(lines)+"\n",encoding="utf-8",newline="\n")
    rewrite_sums(d)
expect_fail(false_read_only, "read_only=false")


print("GATE6_TESTS=PASS positive=1 negative=9")
