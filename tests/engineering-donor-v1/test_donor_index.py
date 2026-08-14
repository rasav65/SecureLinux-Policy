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
if len(contracts) != 15:
    fail("CONTRACT_COUNT")
for row in contracts:
    if row["v3_status"] != "PENDING_NOT_ACTIVE":
        fail("CONTRACT_STATUS")
    if row["evidence_marker"] not in source_text:
        fail("CONTRACT_MARKER:" + row["contract_id"])

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
print("ENGINEERING_CONTRACTS=15")
print("FSTEC_ROWS_CLOSED_BY_THIS_INDEX=0")
