#!/usr/bin/env python3
from __future__ import annotations
import csv
import hashlib
import io
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DONOR = ROOT / "archive/securelinux-ng.sh"
IDX = ROOT / "index/engineering-donor-v1"
REVIEW = ROOT / "archive/engineering-review-20260731"
EXPECTED_DONOR_SHA = "f3be8723cd5a2be499e9e8e6370fad712bdec8afd68050f27af6a3e2d6fbc34b"
EXPECTED_REVIEW_SHA = "7a62c1304a423e4431b08c34e999ed221777d63ecfb0aec180767fadf80759d2"

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def fail(msg):
    print("FAIL=" + msg)
    raise SystemExit(1)

if sha256_file(DONOR) != EXPECTED_DONOR_SHA:
    fail("DONOR_SHA")
source_text = DONOR.read_text(encoding="utf-8")
if len(source_text.splitlines()) != 18928:
    fail("DONOR_LINES")

# Function reverse index
with (IDX / "FUNCTION-INDEX.tsv").open(encoding="utf-8", newline="") as f:
    function_rows = list(csv.DictReader(f, delimiter="\t"))
matches = list(re.finditer(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", source_text))
if len(matches) != 310 or len(function_rows) != 310:
    fail("FUNCTION_COUNT")
for i, (row, match) in enumerate(zip(function_rows, matches)):
    end = matches[i+1].start() if i+1 < len(matches) else len(source_text)
    segment = source_text[match.start():end].encode("utf-8")
    start_line = source_text.count("\n", 0, match.start()) + 1
    end_line = source_text.count("\n", 0, end) if i+1 < len(matches) else len(source_text.splitlines())
    if row["name"] != match.group(1):
        fail("FUNCTION_NAME")
    if int(row["start_line"]) != start_line or int(row["end_line"]) != end_line:
        fail("FUNCTION_RANGE")
    if row["segment_sha256"] != hashlib.sha256(segment).hexdigest():
        fail("FUNCTION_SEGMENT_SHA")

# Complete line coverage in 100-line chunks.
raw_lines = DONOR.read_bytes().splitlines(keepends=True)
with (IDX / "SOURCE-CHUNKS.tsv").open(encoding="utf-8", newline="") as f:
    chunks = list(csv.DictReader(f, delimiter="\t"))
if len(chunks) != 190:
    fail("CHUNK_COUNT")
for i,row in enumerate(chunks):
    start = i * 100
    data = b"".join(raw_lines[start:start+100])
    if int(row["start_line"]) != start + 1:
        fail("CHUNK_START")
    if int(row["end_line"]) != min(start + 100, len(raw_lines)):
        fail("CHUNK_END")
    if int(row["bytes"]) != len(data):
        fail("CHUNK_BYTES")
    if row["sha256"] != hashlib.sha256(data).hexdigest():
        fail("CHUNK_SHA")

# Candidate/raw evidence counts and pinned source.
with (IDX / "SEMANTIC-CANDIDATES.tsv").open(encoding="utf-8", newline="") as f:
    candidates = list(csv.DictReader(f, delimiter="\t"))
if len(candidates) != 141:
    fail("CANDIDATE_COUNT")
if {r["source_sha256"] for r in candidates} != {EXPECTED_DONOR_SHA}:
    fail("CANDIDATE_SOURCE_SHA")
with (IDX / "RAW-EVIDENCE.tsv").open(encoding="utf-8", newline="") as f:
    raw = list(csv.DictReader(f, delimiter="\t"))
if len(raw) != 478:
    fail("RAW_EVIDENCE_COUNT")

# Engineering contracts must point at real donor evidence and remain non-active.
with (IDX / "ENGINEERING-CONTRACTS.tsv").open(encoding="utf-8", newline="") as f:
    contracts = list(csv.DictReader(f, delimiter="\t"))
if len(contracts) != 20:
    fail("CONTRACT_COUNT")
for row in contracts:
    if row["v3_status"] != "PENDING_NOT_ACTIVE":
        fail("CONTRACT_STATUS")
    if row["evidence_marker"] not in source_text:
        fail("CONTRACT_MARKER:" + row["contract_id"])

# Every donor function carries an explicit adoption class. The class is derived
# from the other index tables, so the column can never drift away from them, and
# "pending-review" is an explicit statement that the function has NOT been
# reviewed - it is not a decision that no invariant is needed.
ADOPTION_CLASSES = {"contracted", "candidate", "evidence-only", "pending-review"}
NON_FUNCTION_ORIGINS = {
    "TOPLEVEL",
    "CRON_CRITICAL_TARGETS",
    "FAILLOCK_CONF_STRICT",
    "GRUB_KERNEL_REQUIRED_PARAMS",
}
contracted = {r["evidence_function"] for r in contracts if r["evidence_function"]}
candidate = {r["source_function"] for r in candidates if r["source_function"]}
evidence = {r["source_function"] for r in raw if r["source_function"]}
function_names = {r["name"] for r in function_rows}
stray = (contracted | candidate | evidence) - function_names - NON_FUNCTION_ORIGINS
if stray:
    fail("UNKNOWN_SOURCE_FUNCTION:" + ",".join(sorted(stray)))
counts = {c: 0 for c in ADOPTION_CLASSES}
for row in function_rows:
    cls = row.get("adoption_class", "")
    if cls not in ADOPTION_CLASSES:
        fail("ADOPTION_CLASS:" + row["name"])
    if not row.get("adoption_note", "").strip():
        fail("ADOPTION_NOTE:" + row["name"])
    name = row["name"]
    expected = (
        "contracted" if name in contracted
        else "candidate" if name in candidate
        else "evidence-only" if name in evidence
        else "pending-review"
    )
    if cls != expected:
        fail("ADOPTION_CLASS_DERIVATION:" + name)
    counts[cls] += 1
if sum(counts.values()) != 310:
    fail("ADOPTION_CLASS_TOTAL")

# Donor design documents are registered as pinned sources, not merely archived.
with (IDX / "SOURCE.tsv").open(encoding="utf-8", newline="") as f:
    sources = list(csv.DictReader(f, delimiter="\t"))
REQUIRED_SOURCE_IDS = {
    "DONOR-SCRIPT",
    "FINAL-ARCH-REVIEW",
    "DONOR-DOC-RESTORE-MODEL",
    "DONOR-DOC-ARCHITECTURE",
    "DONOR-DOC-COMPATIBILITY",
    "DONOR-DOC-FSTEC-MAPPING",
}
if {r["artifact_id"] for r in sources} != REQUIRED_SOURCE_IDS:
    fail("SOURCE_IDS")
for row in sources:
    p = ROOT / row["path"]
    if not p.is_file():
        fail("SOURCE_MISSING:" + row["artifact_id"])
    if sha256_file(p) != row["sha256"]:
        fail("SOURCE_SHA:" + row["artifact_id"])

# Original architecture review preserved exactly.
archive = REVIEW / "SecureLinux-NG-architecture-final-review-20260731-112906.tar.gz"
if sha256_file(archive) != EXPECTED_REVIEW_SHA:
    fail("REVIEW_ARCHIVE_SHA")
with (REVIEW / "review/SHA256SUMS").open(encoding="utf-8") as f:
    for line in f:
        digest, rel = line.rstrip("\n").split("  ", 1)
        p = REVIEW / "review" / rel
        if sha256_file(p) != digest:
            fail("REVIEW_MEMBER_SHA:" + rel)

# Run the archived architecture-regression unchanged against the pinned donor
# by staging the exact three paths it expects.
with tempfile.TemporaryDirectory(prefix="slp-donor-review-") as td:
    t = Path(td)
    (t / "docs").mkdir()
    (t / "tests").mkdir()
    (t / "securelinux-ng.sh").write_bytes(DONOR.read_bytes())
    (t / "docs/architecture.md").write_bytes(
        (REVIEW / "review/docs/architecture.md").read_bytes()
    )
    test = t / "tests/architecture-regression.sh"
    test.write_bytes((REVIEW / "review/tests/architecture-regression.sh").read_bytes())
    test.chmod(0o755)
    cp = subprocess.run(["bash", str(test)], text=True, capture_output=True)
    if cp.returncode != 0 or "RESULT=ARCHITECTURE_REGRESSION_OK" not in cp.stdout:
        print(cp.stdout, end="")
        print(cp.stderr, end="", file=sys.stderr)
        fail("LEGACY_ARCHITECTURE_REGRESSION")

print("RESULT=ENGINEERING_DONOR_V1_OK")
print("DONOR_LINES=18928")
print("FUNCTION_ROWS=310")
print("SOURCE_CHUNKS=190")
print("SEMANTIC_CANDIDATES=141")
print("RAW_EVIDENCE_ROWS=478")
print("ENGINEERING_CONTRACTS=20")
print("REGISTERED_SOURCES=6")
print("FUNCTIONS_CONTRACTED=%d" % counts["contracted"])
print("FUNCTIONS_CANDIDATE=%d" % counts["candidate"])
print("FUNCTIONS_EVIDENCE_ONLY=%d" % counts["evidence-only"])
print("FUNCTIONS_PENDING_REVIEW=%d" % counts["pending-review"])
print("FSTEC_ROWS_CLOSED_BY_THIS_INDEX=0")
