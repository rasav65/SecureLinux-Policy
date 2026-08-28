#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, re, stat, zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
IDX = ROOT / "index/engineering-tests-v1"
ARC = ROOT / "archive/engineering-donor-v16.2.11/16.2.11.zip"
PINNED_ZIP_SHA = "1b25f554a5ad1509037aa9613b7851a595159fd44291913cc2dba63280e50494"
PINNED_DONOR_SHA = "f3be8723cd5a2be499e9e8e6370fad712bdec8afd68050f27af6a3e2d6fbc34b"
def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()
def fail(msg): raise SystemExit("FAIL="+msg)
if sha(ARC) != PINNED_ZIP_SHA: fail("ZIP_SHA")
with zipfile.ZipFile(ARC) as z:
    infos=z.infolist(); names=[i.filename for i in infos]
    if len(names)!=len(set(names)): fail("DUPLICATE_ZIP_MEMBER")
    roots=set(); files={}
    for i in infos:
        n=i.filename
        if n.startswith("/"): fail("ABSOLUTE_ZIP_PATH")
        parts=[p for p in n.split("/") if p not in ("",".")]
        if ".." in parts: fail("DOTDOT_ZIP_PATH")
        if parts: roots.add(parts[0])
        mode=(i.external_attr>>16)&0xFFFF
        if stat.S_IFMT(mode)==stat.S_IFLNK: fail("ZIP_SYMLINK")
        if not i.is_dir(): files[n]=z.read(n)
    if roots != {"16.0.0"}: fail("ZIP_ROOT")
    if len(files)!=52: fail("ZIP_FILE_COUNT")
    donor=files["16.0.0/securelinux-ng.sh"]
    if hashlib.sha256(donor).hexdigest()!=PINNED_DONOR_SHA: fail("DONOR_SHA")
    if donor.count(b"\n")!=18928: fail("DONOR_LINES")
    tests={Path(n).name:b for n,b in files.items() if n.startswith("16.0.0/tests/")}
    if len(tests)!=38: fail("TEST_COUNT")
    regressions={n for n in tests if n.endswith("-regression.sh")}
    if len(regressions)!=36: fail("REGRESSION_COUNT")
    smoke=tests["smoke.sh"].decode("utf-8")
    wired=re.findall(r"bash tests/([A-Za-z0-9._-]+-regression\.sh)",smoke)
    if len(wired)!=36 or len(set(wired))!=36 or set(wired)!=regressions:
        fail("SMOKE_REGRESSION_COMPLETENESS")
with (IDX/"TEST-INVENTORY.tsv").open(encoding="utf-8",newline="") as f:
    rows=list(csv.DictReader(f,delimiter="\t"))
if len(rows)!=38: fail("INVENTORY_COUNT")
for row in rows:
    name=row["test_name"]; data=tests.get(name)
    if data is None: fail("INVENTORY_UNKNOWN_TEST:"+name)
    if row["sha256"]!=hashlib.sha256(data).hexdigest(): fail("TEST_SHA:"+name)
    if int(row["bytes"])!=len(data): fail("TEST_BYTES:"+name)
    if int(row["lines"])!=data.count(b"\n"): fail("TEST_LINES:"+name)
with (IDX/"TEST-CONTRACTS.tsv").open(encoding="utf-8",newline="") as f:
    contracts=list(csv.DictReader(f,delimiter="\t"))
if len(contracts)!=32: fail("CONTRACT_COUNT")
ids=[r["contract_id"] for r in contracts]
if len(ids)!=len(set(ids)): fail("DUPLICATE_CONTRACT_ID")
known=set(tests)
for row in contracts:
    for name in [x.strip() for x in row["donor_tests"].split(",") if x.strip()]:
        if name not in known: fail("CONTRACT_UNKNOWN_TEST:"+name)
legacy={r["test_name"]:r["adoption_status"] for r in rows}
for name in ("fstec-mapping-regression.sh","wheel-fstec-regression.sh"):
    if legacy.get(name)!="historical-only": fail("LEGACY_NORMATIVE_ISOLATION:"+name)
forbidden_stages={"future-apply-restore","future-restore","future-sysctl-restore"}
for row in rows:
    if row["adoption_status"] in forbidden_stages:
        fail("STALE_RESTORE_INVENTORY_STAGE:"+row["test_name"])
for row in contracts:
    if row["target_stage"] in forbidden_stages:
        fail("STALE_RESTORE_CONTRACT_STAGE:"+row["contract_id"])
if legacy.get("manifest-resolution-regression.sh")!="historical-only":
    fail("RESTORE_MANIFEST_TEST_NOT_HISTORICAL")
manifest_contract=next(r for r in contracts if r["contract_id"]=="TST-010")
if manifest_contract["target_stage"]!="historical-only":
    fail("RESTORE_MANIFEST_CONTRACT_NOT_HISTORICAL")
contract_by_id={r["contract_id"]:r for r in contracts}
if contract_by_id["TST-002"]["invariant"].startswith("restore-critical"):
    fail("STALE_RESTORE_MANIFEST_WRITER_TERMINOLOGY")
if contract_by_id["TST-019"]["area"]!="package-compensation":
    fail("STALE_PACKAGE_RESTORE_CONTRACT_AREA")
if sha(ROOT/"tools/write-sha256.py") != sha(ROOT/"archive/engineering-donor-v16.2.11/snapshot/tools/write-sha256.py"):
    fail("ACTIVE_TOOL_NOT_PINNED_DONOR")
print("RESULT=ENGINEERING_TEST_DONOR_V1_OK")
print("ZIP_FILES=52")
print("TEST_FILES=38")
print("REGRESSION_FILES=36")
print("SMOKE_WIRED_REGRESSIONS=36")
print("GENERALIZED_TEST_CONTRACTS=32")
print("ACTIVE_TOOL_ADOPTIONS=1")
print("V3_FSTEC_ROWS_CLOSED_BY_THIS_INDEX=0")
