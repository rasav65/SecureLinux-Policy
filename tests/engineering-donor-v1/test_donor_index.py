#!/usr/bin/env python3
from __future__ import annotations
import csv
import hashlib
import io
import re
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
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

# Engineering contracts must point at real donor evidence. APPLY-relevant
# invariants remain PENDING_NOT_ACTIVE; the restore-manifest selector is
# preserved only as explicitly rejected historical evidence.
with (IDX / "ENGINEERING-CONTRACTS.tsv").open(encoding="utf-8", newline="") as f:
    contracts = list(csv.DictReader(f, delimiter="\t"))
if len(contracts) != 20:
    fail("CONTRACT_COUNT")
for row in contracts:
    expected_status = "REJECTED_RESTORE_ONLY" if row["contract_id"] == "ENG-012" else "PENDING_NOT_ACTIVE"
    if row["v3_status"] != expected_status:
        fail("CONTRACT_STATUS:" + row["contract_id"])
    if row["evidence_marker"] not in source_text:
        fail("CONTRACT_MARKER:" + row["contract_id"])
expected_apply_only_mechanisms = {
    "ENG-003": "exclusive APPLY execution lock",
    "ENG-008": "targeted sysctl runtime transaction-local compensation",
    "ENG-011": "compensate only recorded package delta",
    "ENG-012": "donor RESTORE manifest selection (historical-only)",
    "ENG-013": "file compensation from recorded backup",
    "ENG-015": "APPLY pre-state captured in manifest",
    "ENG-016": "explicit irreversible/external-recovery ledger",
}
contract_by_id = {row["contract_id"]: row for row in contracts}
for contract_id, mechanism in expected_apply_only_mechanisms.items():
    if contract_by_id[contract_id]["mechanism"] != mechanism:
        fail("CONTRACT_APPLY_ONLY_MECHANISM:" + contract_id)

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

# DONOR_TO_V3_MAPPING candidate must cover the complete donor inventory while
# remaining non-normative and blocked from roadmap step 8 until separate review.
TIDX = ROOT / "index/engineering-tests-v1"
MAPPING = IDX / "DONOR-TO-V3-MAPPING.tsv"
DECISIONS = {"REUSE", "ADAPT", "REJECT", "DEFER"}
EXPECTED_CAPABILITIES = {f"CAP-{i:02d}" for i in range(1, 17)}
EXPECTED_KINDS = {"FUNCTION": 310, "TEST_FILE": 38, "MATURE_FAMILY": 16}

def read_tsv(path: Path):
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))

def split_refs(value: str):
    return [x for x in value.split(",") if x]

mapping_rows = read_tsv(MAPPING)
test_contracts = read_tsv(TIDX / "TEST-CONTRACTS.tsv")
inventory = read_tsv(TIDX / "TEST-INVENTORY.tsv")
if len(mapping_rows) != 364:
    fail("MAPPING_ROW_COUNT")
kind_counts = Counter(row["item_kind"] for row in mapping_rows)
if dict(kind_counts) != EXPECTED_KINDS:
    fail("MAPPING_ITEM_KIND_COUNTS")
for row in mapping_rows:
    if row["decision"] not in DECISIONS:
        fail("MAPPING_DECISION:" + row["mapping_id"])
    if not row["target_v3_family"].strip() or not row["rationale"].strip():
        fail("MAPPING_REQUIRED_TEXT:" + row["mapping_id"])
    if row["normative_effect"] != "NONE" or row["closes_source_rows"] != "0":
        fail("MAPPING_NORMATIVE_BOUNDARY:" + row["mapping_id"])
    if "restore" in row["target_v3_family"].lower():
        fail("MAPPING_RESTORE_TARGET_FAMILY:" + row["mapping_id"])
    if "operational-recovery-excluded" in row["target_v3_family"] and row["decision"] != "REJECT":
        fail("MAPPING_OPERATIONAL_RECOVERY_EXCLUSION:" + row["mapping_id"])

restore_entry = next(
    row for row in mapping_rows
    if row["item_kind"] == "FUNCTION" and row["donor_label"] == "run_restore_mode"
)
if restore_entry["decision"] != "REJECT":
    fail("MAPPING_USER_RESTORE_ENTRYPOINT")
for row in mapping_rows:
    if row["item_kind"] == "FUNCTION" and row["donor_label"].startswith("restore_") and "_module" in row["donor_label"]:
        if row["decision"] != "REJECT":
            fail("MAPPING_STANDALONE_RESTORE_MODULE:" + row["mapping_id"])
cap04 = next(row for row in mapping_rows if row["item_kind"] == "MATURE_FAMILY" and row["mandatory_capability_refs"] == "CAP-04")
if cap04["donor_label"] != "transaction-local compensation from recorded pre-state":
    fail("MAPPING_CAP04_APPLY_ONLY")
if "run_restore_mode" in cap04["donor_label"] or "FUNC-0308" in split_refs(cap04["donor_refs"]):
    fail("MAPPING_CAP04_RESTORE_ENTRYPOINT")

function_by_id = {row["function_id"]: row for row in function_rows}
func_mapping = [row for row in mapping_rows if row["item_kind"] == "FUNCTION"]
func_refs = [row["donor_refs"] for row in func_mapping]
if len(func_refs) != len(set(func_refs)) or set(func_refs) != set(function_by_id):
    fail("MAPPING_FUNCTION_COVERAGE")
for row in func_mapping:
    src = function_by_id[row["donor_refs"]]
    if row["donor_label"] != src["name"] or row["donor_binding_sha256"] != src["segment_sha256"]:
        fail("MAPPING_FUNCTION_BINDING:" + row["donor_refs"])

inventory_by_name = {row["test_name"]: row for row in inventory}
test_mapping = [row for row in mapping_rows if row["item_kind"] == "TEST_FILE"]
test_refs = [row["donor_refs"] for row in test_mapping]
if len(test_refs) != len(set(test_refs)) or set(test_refs) != set(inventory_by_name):
    fail("MAPPING_TEST_COVERAGE")
for row in test_mapping:
    if row["donor_binding_sha256"] != inventory_by_name[row["donor_refs"]]["sha256"]:
        fail("MAPPING_TEST_BINDING:" + row["donor_refs"])

eng_ids = {row["contract_id"] for row in contracts}
tst_ids = {row["contract_id"] for row in test_contracts}
mapping_eng = {ref for row in mapping_rows for ref in split_refs(row["engineering_contract_refs"])}
mapping_tst = {ref for row in mapping_rows for ref in split_refs(row["donor_test_contract_refs"])}
if mapping_eng != eng_ids:
    fail("MAPPING_ENGINEERING_CONTRACT_COVERAGE")
if mapping_tst != tst_ids:
    fail("MAPPING_TEST_CONTRACT_COVERAGE")
for row in mapping_rows:
    for ref in split_refs(row["donor_test_files"]):
        if ref not in inventory_by_name:
            fail("MAPPING_UNKNOWN_TEST_REF:" + row["mapping_id"] + ":" + ref)

family_rows = [row for row in mapping_rows if row["item_kind"] == "MATURE_FAMILY"]
cap_refs = [row["mandatory_capability_refs"] for row in family_rows]
if len(cap_refs) != len(set(cap_refs)) or set(cap_refs) != EXPECTED_CAPABILITIES:
    fail("MAPPING_CAPABILITY_COVERAGE")
func_mapping_by_ref = {row["donor_refs"]: row for row in func_mapping}
for row in family_rows:
    refs = split_refs(row["donor_refs"])
    if not refs or any(ref not in function_by_id for ref in refs):
        fail("MAPPING_CAPABILITY_DONOR_REFS:" + row["mapping_id"])
    capability = row["mandatory_capability_refs"]
    for ref in refs:
        if capability not in split_refs(func_mapping_by_ref[ref]["mandatory_capability_refs"]):
            fail("MAPPING_CAPABILITY_FUNCTION_BACKREF:" + row["mapping_id"] + ":" + ref)

# Current non-REJECT FUNCTION capability refs must also have a current forward
# MATURE_FAMILY -> FUNCTION edge. REJECT rows may retain historical refs only.
family_refs_by_capability = {
    row["mandatory_capability_refs"]: set(split_refs(row["donor_refs"]))
    for row in family_rows
}
for row in func_mapping:
    if row["decision"] == "REJECT":
        continue
    function_ref = row["donor_refs"]
    for capability in split_refs(row["mandatory_capability_refs"]):
        if function_ref not in family_refs_by_capability.get(capability, set()):
            fail("MAPPING_NONREJECT_FUNCTION_CAPABILITY_FORWARD_REF:" + row["mapping_id"] + ":" + capability)

# CAP-12 должен ссылаться на donor-функции, которые действительно несут
# DRY_RUN-механику, а не только на соседний profile/policy helper.
cap12 = next(row for row in family_rows if row["mandatory_capability_refs"] == "CAP-12")
cap12_refs = split_refs(cap12["donor_refs"])
if cap12_refs == ["FUNC-0016"]:
    fail("MAPPING_CAP12_PROFILE_ONLY_EVIDENCE")
for ref in cap12_refs:
    src = function_by_id[ref]
    start = int(src["start_line"]) - 1
    end = int(src["end_line"])
    body = "\n".join(source_text.splitlines()[start:end])
    if "DRY_RUN" not in body:
        fail("MAPPING_CAP12_REF_WITHOUT_DRY_RUN:" + ref)

# Active or deferred mature-family evidence must not cite a function row that the
# mapping itself rejects. A rejected orchestration/recovery function cannot be
# smuggled back into an ADAPT/DEFER family through donor_refs.
func_mapping_by_ref = {row["donor_refs"]: row for row in func_mapping}
for row in family_rows:
    if row["decision"] not in {"REUSE", "ADAPT", "DEFER"}:
        continue
    rejected_refs = sorted(
        ref for ref in split_refs(row["donor_refs"])
        if func_mapping_by_ref[ref]["decision"] == "REJECT"
    )
    if rejected_refs:
        fail("MAPPING_FAMILY_REFERENCES_REJECTED_FUNCTION:" + row["mapping_id"] + ":" + ",".join(rejected_refs))

# Every non-historical engineering contract must bind to donor evidence whose
# function mapping remains accepted/deferred rather than REJECT.
func_mapping_by_name = {row["donor_label"]: row for row in func_mapping}
for contract in contracts:
    if contract["adoption_class"] == "historical-only":
        continue
    evidence = func_mapping_by_name.get(contract["evidence_function"])
    if evidence is None:
        fail("CONTRACT_EVIDENCE_FUNCTION_UNMAPPED:" + contract["contract_id"])
    if evidence["decision"] == "REJECT":
        fail("CONTRACT_EVIDENCE_FUNCTION_REJECTED:" + contract["contract_id"] + ":" + evidence["mapping_id"])
# Explicit regression checks for the independent-review blockers.
for mapping_id in ("MAP-FUNC-0052", "MAP-FUNC-0054", "MAP-FUNC-0056", "MAP-FUNC-0058"):
    row = next(r for r in mapping_rows if r["mapping_id"] == mapping_id)
    if row["decision"] != "REJECT" or row["target_v3_family"] != "current-check-superseded":
        fail("MAPPING_ACCEPTED_CHECK_REOPEN:" + mapping_id)
run_lock = next(r for r in mapping_rows if r["mapping_id"] == "MAP-FUNC-0015")
if run_lock["decision"] != "ADAPT" or run_lock["target_v3_family"] != "apply-foundation/run-lock":
    fail("MAPPING_RUN_LOCK_FAMILY")
profile_gate = next(r for r in mapping_rows if r["mapping_id"] == "MAP-FUNC-0016")
if profile_gate["decision"] != "ADAPT" or profile_gate["target_v3_family"] != "apply-foundation/policy-layer-gating":
    fail("MAPPING_PROFILE_GATE_FAMILY")
eng015 = contract_by_id["ENG-015"]
if eng015["evidence_function"] != "manifest_init" or eng015["evidence_start_line"] != "16880" or eng015["evidence_marker"] != "manifest_init() {":
    fail("CONTRACT_ENG015_EVIDENCE_BINDING")
ufw_check = next(r for r in mapping_rows if r["mapping_id"] == "MAP-FUNC-0157")
if ufw_check["decision"] != "DEFER" or ufw_check["target_v3_family"] != "future-firewall":
    fail("MAPPING_UFW_FAMILY")
run_apply = next(r for r in mapping_rows if r["mapping_id"] == "MAP-FUNC-0307")
if run_apply["decision"] != "REJECT" or run_apply["target_v3_family"] != "donor-historical/orchestration-operational-recovery-excluded":
    fail("MAPPING_RUN_APPLY_RESTORE_CONTOUR")
if "restore sequencing" in run_apply["rationale"].lower():
    fail("MAPPING_RUN_APPLY_STALE_RATIONALE")
func0269 = next(row for row in func_mapping if row["mapping_id"] == "MAP-FUNC-0269")
func0269_source = function_by_id["FUNC-0269"]
func0269_body = "\n".join(
    source_text.splitlines()[int(func0269_source["start_line"]) - 1:int(func0269_source["end_line"])]
)
if func0269["decision"] != "REJECT" or func0269["target_v3_family"] != "donor-historical/operational-recovery-excluded":
    fail("MAPPING_FUNC0269_CLASSIFICATION")
if "apply_report" not in func0269_body:
    fail("MAPPING_FUNC0269_SOURCE_SEMANTICS")
if "apply_report" not in func0269["rationale"] or "recorded pre-state" not in func0269["rationale"]:
    fail("MAPPING_FUNC0269_RATIONALE_SEMANTICS")
# ADAPT rationale must describe failed-uncommitted APPLY compensation, not preserve
# an operational/post-APPLY RESTORE vocabulary. Donor restore-named identifiers
# remain permitted where the rationale explicitly isolates them as compensation
# or historical evidence.
stale_adapt_phrases = (
    "apply/restore",
    "restore sequencing",
    "safe restore",
    "targeted restore",
    "exact restore",
    "snapshot/restore",
    "discovery/mutation/restore",
    "restore mechanics",
    "restore state",
    "non-symmetric restore",
)
for row in mapping_rows:
    if row["decision"] == "ADAPT":
        rationale = row["rationale"].lower()
        for phrase in stale_adapt_phrases:
            if phrase in rationale:
                fail("MAPPING_ADAPT_STALE_RESTORE_RATIONALE:" + row["mapping_id"] + ":" + phrase)
if contract_by_id["ENG-012"]["adoption_class"] != "historical-only":
    fail("CONTRACT_RESTORE_ONLY_ADOPTION_CLASS")
cap04 = next(r for r in family_rows if r["mandatory_capability_refs"] == "CAP-04")
if "ENG-012" in split_refs(cap04["engineering_contract_refs"]) or "TST-010" in split_refs(cap04["donor_test_contract_refs"]):
    fail("MAPPING_CAP04_RESTORE_ONLY_CONTRACT")
if "manifest-resolution-regression.sh" in split_refs(cap04["donor_test_files"]):
    fail("MAPPING_CAP04_RESTORE_ONLY_TEST")

password = next(row for row in test_mapping if row["donor_refs"] == "password-policy-regression.sh")
if password["decision"] != "DEFER" or password["target_v3_family"] != "future-corporate/password-policy":
    fail("MAPPING_PASSWORD_POLICY_DISPOSITION")
if inventory_by_name["password-policy-regression.sh"]["adoption_status"] != "future-corporate":
    fail("MAPPING_PASSWORD_POLICY_INVENTORY")
portable = next(row for row in test_mapping if row["donor_refs"] == "portable-sha256-regression.sh")
if portable["decision"] != "REUSE":
    fail("MAPPING_PORTABLE_SHA")
for name in ("fstec-mapping-regression.sh", "wheel-fstec-regression.sh"):
    if next(row for row in test_mapping if row["donor_refs"] == name)["decision"] != "REJECT":
        fail("MAPPING_LEGACY_NORMATIVE_ISOLATION:" + name)

def parse_progress(path: Path) -> dict[str, str]:
    progress: dict[str, str] = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line or "=" not in line:
            raise ValueError(f"format:{lineno}")
        key, value = line.split("=", 1)
        if not key or key in progress:
            raise ValueError(f"duplicate-or-empty-key:{lineno}:{key}")
        progress[key] = value
    return progress


decision_counts = Counter(row["decision"] for row in mapping_rows)
expected_progress = {
    "INDEX_VERSION": "engineering-donor-v1",
    "SOURCE_SHA256": EXPECTED_DONOR_SHA,
    "SOURCE_LINES": str(len(source_text.splitlines())),
    "FUNCTION_ROWS": str(len(function_rows)),
    "SOURCE_CHUNKS_100_LINES": str(len(chunks)),
    "SEMANTIC_CANDIDATES": str(len(candidates)),
    "RAW_EVIDENCE_ROWS": str(len(raw)),
    "REGISTERED_SOURCES": str(len(sources)),
    "FUNCTIONS_CONTRACTED": str(counts["contracted"]),
    "FUNCTIONS_CANDIDATE": str(counts["candidate"]),
    "FUNCTIONS_EVIDENCE_ONLY": str(counts["evidence-only"]),
    "FUNCTIONS_PENDING_REVIEW": str(counts["pending-review"]),
    "ENGINEERING_CONTRACTS": str(len(contracts)),
    "IMPLEMENTED_AS_V3_CONTROLS": "0",
    "CLOSES_FSTEC_SOURCE_ROWS": "0",
    "REFERENCE_VM_EVIDENCE": "NOT_YET_PROVIDED",
    "STATUS": "MAPPING_ACCEPTED_COMMITTED",
    "DONOR_TO_V3_MAPPING": "ACCEPTED_COMMITTED",
    "MAPPING_ACCEPTED_COMMIT": "1db91b0e17d6ef37e4c42cd41dca77eeb2b743da",
    "MAPPING_ACCEPTED_TREE": "d3f624651bf13f1174619cef881fababbc768553",
    "MAPPING_ROWS": str(len(mapping_rows)),
    "MAPPING_FUNCTION_ROWS": str(kind_counts["FUNCTION"]),
    "MAPPING_TEST_FILE_ROWS": str(kind_counts["TEST_FILE"]),
    "MAPPING_MATURE_FAMILY_ROWS": str(kind_counts["MATURE_FAMILY"]),
    "MAPPING_UNMAPPED_FUNCTIONS": "0",
    "MAPPING_UNMAPPED_TEST_FILES": "0",
    "MAPPING_NORMATIVE_EFFECT": "NONE",
    "MAPPING_CLOSES_SOURCE_ROWS": "0",
    "MAPPING_DECISION_REUSE": str(decision_counts["REUSE"]),
    "MAPPING_DECISION_ADAPT": str(decision_counts["ADAPT"]),
    "MAPPING_DECISION_REJECT": str(decision_counts["REJECT"]),
    "MAPPING_DECISION_DEFER": str(decision_counts["DEFER"]),
    "APPLY_SEMANTIC_CONTRACT_ALLOWED": "true",
    "RESTORE_OPERATIONAL_CONTOUR": "EXCLUDED",
    "POST_APPLY_RECOVERY_MODEL": "EXTERNAL_SNAPSHOT",
    "TRANSACTION_LOCAL_COMPENSATION": "FAILED_UNCOMMITTED_APPLY_ONLY",
    "MAPPING_RESTORE_TARGET_FAMILIES": "0",
    "MAPPING_USER_RESTORE_ENTRYPOINTS_ACCEPTED": "0",
    "RESTORE_ONLY_ENGINEERING_CONTRACTS_REJECTED": "1",
    "RESTORE_ONLY_TEST_CONTRACTS_HISTORICAL": "1",
}

def validate_progress(progress: dict[str, str]) -> None:
    if set(progress) != set(expected_progress):
        raise ValueError(
            f"key-set missing={sorted(set(expected_progress)-set(progress))} "
            f"extra={sorted(set(progress)-set(expected_progress))}"
        )
    for key, expected in expected_progress.items():
        if progress[key] != expected:
            raise ValueError(f"value:{key}:{progress[key]}!={expected}")

try:
    progress = parse_progress(IDX / "PROGRESS.txt")
    validate_progress(progress)
except ValueError as exc:
    fail("MAPPING_PROGRESS_PARSE_OR_PARITY:" + str(exc))

with tempfile.TemporaryDirectory(prefix="slp-donor-progress-") as td:
    base = (IDX / "PROGRESS.txt").read_text(encoding="utf-8")
    mutations = {
        "duplicate": "APPLY_SEMANTIC_CONTRACT_ALLOWED=false\n" + base,
        "malformed": "THIS IS NOT KEY VALUE\n" + base,
        "extra": base + "CURRENT_CHECKPOINT=STEP7B_ACTIVE\n",
        "stale": base.replace("SOURCE_LINES=18928", "SOURCE_LINES=1", 1),
    }
    for label, text in mutations.items():
        fixture = Path(td) / f"{label}.txt"
        fixture.write_text(text, encoding="utf-8")
        try:
            parsed = parse_progress(fixture)
            validate_progress(parsed)
        except ValueError:
            pass
        else:
            fail("MAPPING_PROGRESS_NEGATIVE_FIXTURE:" + label)

policy = (ROOT / "docs/DONOR-V3-ADOPTION-POLICY.md").read_text(encoding="utf-8")
roadmap = (ROOT / "docs/ROADMAP-v3.md").read_text(encoding="utf-8")
if "DONOR_TO_V3_MAPPING" not in policy or not all(
    token in policy for token in ("`REUSE`", "`ADAPT`", "`REJECT`", "`DEFER`")
):
    fail("MAPPING_POLICY_PRECONDITION")
if "DONOR_TO_V3_MAPPING" not in roadmap:
    fail("MAPPING_ROADMAP_PRECONDITION")
_family_begin = "<!-- BEGIN MATURE DONOR FAMILIES -->"
_family_end = "<!-- END MATURE DONOR FAMILIES -->"
if policy.count(_family_begin) != 1 or policy.count(_family_end) != 1:
    fail("MAPPING_POLICY_FAMILY_MARKERS")
policy_family_block = policy.split(_family_begin, 1)[1].split(_family_end, 1)[0]
policy_family_labels = []
for line in policy_family_block.splitlines():
    match = re.match(r"^([0-9]+)\. (.+?)[.;]$", line)
    if match:
        policy_family_labels.append(match.group(2))
mapping_family_labels = [row["donor_label"] for row in sorted(family_rows, key=lambda r: r["mandatory_capability_refs"])]
if policy_family_labels != mapping_family_labels:
    fail("MAPPING_POLICY_MATURE_FAMILY_SYNC")

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

# Proven function-specific donor-test provenance must stay byte-backed.
# This is deliberately a closed set of semantic bindings established from exact donor
# regression bytes; do not infer a generic "test must name every function" rule.
_proven_function_test_provenance = {
    "MAP-FUNC-0006": "TST-020",
    "MAP-FUNC-0016": "TST-022",
    "MAP-FUNC-0050": "TST-027",
    "MAP-FUNC-0067": "TST-027",
    "MAP-FUNC-0070": "TST-027",
    "MAP-FUNC-0108": "TST-027",
    "MAP-FUNC-0129": "TST-022",
    "MAP-FUNC-0132": "TST-022",
    "MAP-FUNC-0142": "TST-022",
    "MAP-FUNC-0145": "TST-022",
}
_mapping_by_id = {row["mapping_id"]: row for row in mapping_rows}
_test_contract_by_id = {row["contract_id"]: row for row in test_contracts}
_donor_test_zip = ROOT / "archive/engineering-donor-v16.2.11/16.2.11.zip"
with zipfile.ZipFile(_donor_test_zip) as _zf:
    _members = [name for name in _zf.namelist() if not name.endswith("/")]
    for _mapping_id, _contract_id in _proven_function_test_provenance.items():
        _row = _mapping_by_id[_mapping_id]
        if _contract_id not in split_refs(_row["donor_test_contract_refs"]):
            fail("MAPPING_FUNCTION_TEST_PROVENANCE:" + _mapping_id + ":" + _contract_id)
        _contract = _test_contract_by_id[_contract_id]
        _texts = []
        for _test_name in split_refs(_contract["donor_tests"]):
            _hits = [name for name in _members if name.endswith("/tests/" + _test_name)]
            if len(_hits) != 1:
                fail("DONOR_TEST_PROVENANCE_MEMBER:" + _contract_id + ":" + _test_name)
            _texts.append(_zf.read(_hits[0]).decode("utf-8"))
        if not any(_row["donor_label"] in _text for _text in _texts):
            fail("DONOR_TEST_PROVENANCE_BYTES:" + _mapping_id + ":" + _contract_id)

_profile_refs = split_refs(_mapping_by_id["MAP-FUNC-0016"]["donor_test_contract_refs"])
if _profile_refs != ["TST-022"]:
    fail("PROFILE_ALLOWS_TEST_PROVENANCE:" + ",".join(_profile_refs))

# Active mapping decisions must never rely on historical-only donor test contracts.
with (ROOT / "index/engineering-tests-v1/TEST-CONTRACTS.tsv").open(encoding="utf-8", newline="") as f:
    _test_contract_rows = list(csv.DictReader(f, delimiter="\t"))
_historical_test_contracts = {r["contract_id"] for r in _test_contract_rows if r["target_stage"] == "historical-only"}
for row in mapping_rows:
    if row["decision"] not in {"REUSE", "ADAPT"}:
        continue
    refs = {x for x in row["donor_test_contract_refs"].split(",") if x}
    bad = sorted(refs & _historical_test_contracts)
    if bad:
        fail("HISTORICAL_ONLY_TEST_CONTRACT_ON_ACTIVE_MAPPING:" + row["mapping_id"] + ":" + ",".join(bad))

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
print("DONOR_TO_V3_MAPPING=PASS")
print("MAPPING_ROWS=%d" % len(mapping_rows))
print("MAPPING_FUNCTION_ROWS=%d" % kind_counts["FUNCTION"])
print("MAPPING_TEST_FILE_ROWS=%d" % kind_counts["TEST_FILE"])
print("MAPPING_MATURE_FAMILY_ROWS=%d" % kind_counts["MATURE_FAMILY"])
print("MAPPING_DECISION_REUSE=%d" % decision_counts["REUSE"])
print("MAPPING_DECISION_ADAPT=%d" % decision_counts["ADAPT"])
print("MAPPING_DECISION_REJECT=%d" % decision_counts["REJECT"])
print("MAPPING_DECISION_DEFER=%d" % decision_counts["DEFER"])
print("MAPPING_NORMATIVE_EFFECT=NONE")
print("MAPPING_SOURCE_ROWS_CLOSED=0")
print("MAPPING_STATUS=ACCEPTED_COMMITTED")
print("MAPPING_ACCEPTED_COMMIT=1db91b0e17d6ef37e4c42cd41dca77eeb2b743da")
print("MAPPING_ACCEPTED_TREE=d3f624651bf13f1174619cef881fababbc768553")
print("PROGRESS_CONTRACT=PASS_EXACT_KEYS_VALUES negative_fixtures=4")
print("APPLY_SEMANTIC_CONTRACT_ALLOWED=true")
print("RESTORE_OPERATIONAL_CONTOUR=EXCLUDED")
print("POST_APPLY_RECOVERY_MODEL=EXTERNAL_SNAPSHOT")
print("TRANSACTION_LOCAL_COMPENSATION=FAILED_UNCOMMITTED_APPLY_ONLY")
print("FSTEC_ROWS_CLOSED_BY_THIS_INDEX=0")
