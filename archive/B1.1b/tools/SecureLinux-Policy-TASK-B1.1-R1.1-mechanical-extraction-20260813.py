#!/usr/bin/env python3
"""R1: mechanically extract the immutable B1.1b v9 baseline into modules.

No normative content is edited. Proposal bytes are partitioned into exact
slices; the JSON Schema tree is partitioned into exact definition objects.
The command proves byte-identical proposal reconstruction and object-identical
schema reconstruction before publishing the R1 artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys


SCRIPT_NAME = "SecureLinux-Policy-TASK-B1.1-R1.1-mechanical-extraction-20260813.py"
DATE = "2026-08-13"
BASELINE_SHA256 = "3daac5da494cabb9551b269dcb56df83469ee79491a83c3445bcd33bae0274e3"
OPEN_FINDINGS_SHA256 = "5b9bd4da4cb22aad60e75b79851bc8b58b707b6695cceca47dcc47e1540df53a"
R0_TOOL_SHA256 = "5374feee2c083ce70553d23c320d8a73478b64ba59872d27ca48e08cc2aff0a8"

ADMIN_LEDGER_REL = "B1.1b/state/R0.1-ADMIN-DOCS-LEDGER.json"
ADMIN_MANIFEST_REL = "B1.1b/state/R0.1-ADMIN-DOCS.sha256"

PROPOSAL_REL = "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-proposal-v9-20260813.md"
PROPOSAL_SHA256 = "bb359806252163cc6cf29f3499ff828891d3ce11104fe9934704c7022f14abfb"
SCHEMA_REL = "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-schema-v9-20260813.json"
SCHEMA_SHA256 = "2304b192d4f3c8e4fde056a42970ae4b2200df28012019445023c704c6375995"
SELFTEST_REL = "docs/SecureLinux-Policy-TASK-B1.1b-v9-selftest-20260813.py"

MODULE_IDS = (
    "M0-integration-invariants",
    "M1-primitives",
    "M2-outcomes",
    "M3-source-set",
    "M4-filters",
    "M5-pipeline",
    "M6.1-registries",
    "M6.2-operation-algebra",
    "M6.3-enumeration-domains",
    "M6.4-population-matrix",
    "M6.5-behavior-trace",
    "M7-selector-mapping",
)

# This is an R1 extraction assignment, not the normative ownership table.
# Normative owners and symbol-level imports are created only in R2.
DEF_ASSIGNMENT = {
    "M1-primitives": (
        "Id", "ReasonCode", "Sha256", "NonEmptyString", "Signed64",
        "AbsoluteLexicalPosixPath", "TypedString", "TypedInteger",
        "TypedPositiveInteger", "TypedBoolean", "TypedPath", "TypedIdentifier",
        "TypedStringSet", "TypedIntegerSet", "TypedScalar", "TypedSet", "TypedLiteral",
    ),
    "M2-outcomes": (
        "OperationUnitId", "ResolverInputUnitId", "IntrinsicReferenceUnitId",
        "SourceEntryUnitId", "FilterReferenceUnitId", "NonOperationUnitId", "UnitId",
        "RequiredUnit", "CompletedOperationUnit", "CompletedNonOperationUnit",
        "CompletedUnit", "IncompleteOperationNotAttempted", "IncompleteOperationError",
        "IncompleteNonOperationNotAttempted", "IncompleteNonOperationTerminal",
        "IncompleteUnit", "Coverage", "DiagnosticEvidence", "ResolvedResult",
        "ResolvedEmptyResult", "PartialResult", "MissingUnavailableResult", "ErrorResult",
        "SelectorResolutionResult", "RootOperationUnitId",
        "SourceEntryResolveOperationUnitId", "OtherNonOperationUnitId",
        "CompletedSourceEntryUnit", "IncompleteSourceEntryNotAttempted",
        "IncompleteSourceEntryTerminal",
    ),
    "M3-source-set": (
        "SourceStatement", "LiteralPathEntry", "SingleDecimalSlotPathEntry",
        "FilenameMarkerEntry", "LiteralValueEntry", "SourceSetEntry", "SelectorSourceSet",
        "SourceSetArtifact", "EntryDecision", "SelectorSourceAdjudication",
        "SourceAdjudicationArtifact", "SourceMembershipClause",
        "SourceMembershipClauseArtifact", "SourcePathItem", "SourceValueItem", "SourceItem",
        "SourceItemProvenance",
    ),
    "M4-filters": (
        "OperandNone", "OperandScalarLiteral", "OperandSetLiteral", "OperandPositiveInteger",
        "OperandReference", "ExistsFilter", "ScalarComparisonFilter", "MembershipFilter",
        "BitSetFilter", "Filter", "OperandBindingNone", "OperandBindingLiteral",
        "OperandBindingReference", "OperandBinding", "SourceOperandBinding", "SourceBasis",
        "ReferenceBasis", "SourceNoneAuthorization", "SourceLiteralAuthorization",
        "ReferenceAuthorization", "FilterAuthorization", "FilterAuthorizationArtifact",
    ),
    "M5-pipeline": (
        "Identity", "LexicographicOrdering", "SourceOrdering", "Ordering", "IdentityValue",
        "FilterFactPresent", "FilterFactAbsent", "FilterFact", "OrderingValue", "RawCandidate",
    ),
    "M6.1-registries": (
        "InputSlot", "ResolverRegistryEntry", "AdapterRegistryEntry", "RootInputTarget",
        "SourceSetInputTarget", "AdapterInputTarget", "EventSourceInputTarget",
        "ReferenceInputTarget", "ProducerInputTarget", "InputValueTarget",
        "InputValueRegistryEntry", "FieldRegistryEntry", "ReferenceRegistryEntry",
        "PopulationContract", "ReferenceUse", "Binding", "ProducerUse",
        "RootInputRegistryEntry", "EventSourceRegistryEntry", "FilenamePopulationSlot",
        "FilenamePopulationEntry", "FilenamePopulationUse", "AdapterPopulationInputTarget",
    ),
    "M6.2-operation-algebra": (
        "BehaviorAuthorizationNone", "BehaviorAuthorizationSource",
        "BehaviorAuthorizationReference", "BehaviorContract", "BehaviorInputSlotRef",
        "BehaviorOperationOutputRef", "BehaviorInputValueRef", "BehaviorDataInputRef",
        "CopyOperation", "TypedParseOperation", "NfcNormalizeOperation",
        "LexicalPathComposeOperation", "BasenameExtractOperation",
        "SourceSequenceAttachOperation", "MembershipOutputPopulationRef",
        "MembershipDecisionOperation", "PureTransformationOperation",
        "NonEnumerationBehaviorOperation", "BehaviorOperationRecord",
    ),
    "M6.3-enumeration-domains": (
        "EnumerationRootTarget", "EnumerationAdapterTarget", "EnumerationSourceTarget",
        "EmitSingleValueOperator", "EmitSetElementsOperator", "EmitPopulationElementsOperator",
        "EmitImmediatePathEntriesOperator", "EnumerationOperator", "SingleValueDomain",
        "SetElementsDomain", "PopulationElementsDomain", "ImmediatePathEntriesDomain",
        "EnumerationDomainContract", "EnumerationDomainUse", "BehaviorEnumerationMemberRef",
        "EnumerateDomainOperation", "EnumerationPopulationRef",
    ),
    "M6.4-population-matrix": (
        "BehaviorPopulationMemberRef", "BoundPopulationRef", "BehaviorPopulationRef",
        "HostExtensionalBehavior", "HostSnapshotBehavior", "AdapterBehavior",
        "SourceDefinedBehavior", "UpstreamBehavior", "EventStreamBehavior",
        "NetworkScopeBehavior",
    ),
    "M6.5-behavior-trace": (
        "TraceInputBinding", "EnumerationOperationTrace", "CopyOperationTrace",
        "TypedParseOperationTrace", "NfcNormalizeOperationTrace", "BasenameExtractOperationTrace",
        "SourceSequenceAttachOperationTrace", "LexicalPathComposeOperationTrace",
        "PureTransformationTrace", "MembershipCandidateDecisionTrace",
        "MembershipDecisionOperationTrace", "BehaviorOperationTrace", "BehaviorExecutionTrace",
    ),
    "M7-selector-mapping": (
        "HostResolution", "AdapterResolution", "ReferenceMembershipResolution",
        "SourceDefinedResolution", "UpstreamResolution", "EventStreamResolution",
        "NetworkScopeResolution", "NonUnionResolution", "UnionMember", "UnionResolution",
        "Resolution", "SelectorContract", "SelectorContractArtifact", "Requirement",
    ),
    "M0-integration-invariants": (),
}


class R1Error(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def require_regular(path: Path, expected_sha256: str | None = None) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise R1Error(f"missing or unsafe regular file: {path}")
    data = path.read_bytes()
    if expected_sha256 is not None and sha256_bytes(data) != expected_sha256:
        raise R1Error(f"SHA-256 mismatch: {path}")
    return data


def verify_baseline(root: Path) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    base = root / "B1.1b"
    baseline_path = base / "baseline/v9/BASELINE.json"
    baseline_data = require_regular(baseline_path, BASELINE_SHA256)
    sidecar = require_regular(base / "baseline/v9/BASELINE.sha256").decode("utf-8")
    if sidecar != f"{BASELINE_SHA256}  BASELINE.json\n":
        raise R1Error("BASELINE.sha256 mismatch")
    findings_data = require_regular(base / "state/OPEN-FINDINGS.json", OPEN_FINDINGS_SHA256)
    state_data = require_regular(base / "state/PROJECT-STATE.json")
    baseline = json.loads(baseline_data)
    findings = json.loads(findings_data)
    state = json.loads(state_data)
    if baseline.get("gate") != "R0_BASELINE_CLOSURE_PASS":
        raise R1Error("R0 baseline gate is not PASS")
    if state.get("baseline_sha256") != BASELINE_SHA256:
        raise R1Error("PROJECT-STATE baseline reference mismatch")
    if state.get("open_findings_sha256") != OPEN_FINDINGS_SHA256:
        raise R1Error("PROJECT-STATE findings reference mismatch")
    if state.get("current_phase") not in ("R0_1_COMPLETE", "R1_COMPLETE"):
        raise R1Error("R1 requires the completed R0.1 administrative overlay")
    if state.get("gates", {}).get("R0_1_ADMIN_DOCS_OVERLAY_PASS") is not True:
        raise R1Error("R0.1 administrative overlay gate is not PASS")
    finding_ids = {item.get("finding_id") for item in findings.get("findings", [])}
    if finding_ids != {"V8-01", "V8-EXT-01", "V8-EXT-02"}:
        raise R1Error("open finding set changed")
    return baseline, findings, state


def scan_live_snapshot(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            rel = path.relative_to(root)
            if rel.parts[0] in (".git", "B1.1b"):
                continue
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISLNK(mode):
                raise R1Error(f"live project link forbidden: {rel.as_posix()}")
            if stat.S_ISDIR(mode):
                visit(path)
            elif stat.S_ISREG(mode):
                result[rel.as_posix()] = {"sha256": sha256_file(path), "size": entry.stat().st_size}
            else:
                raise R1Error(f"live project special entry forbidden: {rel.as_posix()}")

    visit(root)
    return result


def verify_admin_overlay(
    root: Path,
    baseline: dict[str, object],
    state: dict[str, object],
) -> tuple[dict[str, dict[str, object]], dict[str, object]]:
    expected_list = baseline.get("project_snapshot", {}).get("files")
    if not isinstance(expected_list, list):
        raise R1Error("baseline project file inventory missing")
    expected = {
        item["path"]: {"sha256": item["sha256"], "size": item["size"]}
        for item in expected_list
    }
    ledger_data = require_regular(root / ADMIN_LEDGER_REL)
    manifest_data = require_regular(root / ADMIN_MANIFEST_REL)
    overlay_state = state.get("r0_1_admin_docs")
    if not isinstance(overlay_state, dict):
        raise R1Error("PROJECT-STATE R0.1 overlay record missing")
    if overlay_state.get("ledger_sha256") != sha256_bytes(ledger_data):
        raise R1Error("R0.1 ledger hash mismatch")
    if overlay_state.get("manifest_sha256") != sha256_bytes(manifest_data):
        raise R1Error("R0.1 manifest hash mismatch")
    ledger = json.loads(ledger_data)
    if ledger.get("schema") != "securelinux-policy-r0.1-admin-docs-ledger/v1":
        raise R1Error("unsupported R0.1 ledger schema")
    if ledger.get("classification") != "ADMINISTRATIVE_NON_NORMATIVE":
        raise R1Error("R0.1 overlay is not administrative/non-normative")
    if ledger.get("baseline_sha256") != BASELINE_SHA256:
        raise R1Error("R0.1 ledger baseline mismatch")
    if ledger.get("allowed_paths") != ["README.md", "CHANGELOG.md"]:
        raise R1Error("R0.1 allowed path set changed")
    changes = ledger.get("changes")
    if not isinstance(changes, dict) or set(changes) != {"README.md", "CHANGELOG.md"}:
        raise R1Error("R0.1 change set is not exact")
    readme = changes["README.md"]
    changelog = changes["CHANGELOG.md"]
    if (
        readme.get("action") != "UPDATE"
        or changelog.get("action") != "CREATE"
        or set(readme) != {"action", "before_sha256", "before_size", "after_sha256", "after_size"}
        or set(changelog) != {"action", "after_sha256", "after_size"}
    ):
        raise R1Error("R0.1 ledger record shape changed")
    if expected.get("README.md") != {
        "sha256": readme["before_sha256"],
        "size": readme["before_size"],
    }:
        raise R1Error("R0.1 README before-state does not match R0")
    if "CHANGELOG.md" in expected:
        raise R1Error("R0 unexpectedly contains CHANGELOG.md")
    expected["README.md"] = {"sha256": readme["after_sha256"], "size": readme["after_size"]}
    expected["CHANGELOG.md"] = {"sha256": changelog["after_sha256"], "size": changelog["after_size"]}
    expected_manifest = (
        f"{readme['after_sha256']}  README.md\n"
        f"{changelog['after_sha256']}  CHANGELOG.md\n"
        f"{sha256_bytes(ledger_data)}  {ADMIN_LEDGER_REL}\n"
    ).encode("utf-8")
    if manifest_data != expected_manifest:
        raise R1Error("R0.1 administrative manifest mismatch")
    if overlay_state.get("readme_sha256") != readme["after_sha256"]:
        raise R1Error("PROJECT-STATE README overlay hash mismatch")
    if overlay_state.get("changelog_sha256") != changelog["after_sha256"]:
        raise R1Error("PROJECT-STATE CHANGELOG overlay hash mismatch")
    return expected, ledger


def verify_snapshot_unchanged(
    root: Path,
    baseline: dict[str, object],
    state: dict[str, object],
) -> dict[str, dict[str, object]]:
    expected, _ledger = verify_admin_overlay(root, baseline, state)
    actual = scan_live_snapshot(root)
    if actual != expected:
        missing = sorted(set(expected) - set(actual))[:5]
        extra = sorted(set(actual) - set(expected))[:5]
        changed = sorted(
            name for name in set(expected) & set(actual) if expected[name] != actual[name]
        )[:5]
        raise R1Error(f"live project differs from R0 plus R0.1 overlay: missing={missing}, extra={extra}, changed={changed}")
    return actual


def proposal_module(section: int | None, subsection: tuple[int, int] | None) -> str:
    if section == 5:
        return "M1-primitives"
    if section == 6:
        return "M3-source-set"
    if section == 7:
        if subsection in ((7, 1), (7, 2), (7, 3), (7, 4), (7, 9)):
            return "M6.1-registries"
        if subsection == (7, 5):
            return "M6.3-enumeration-domains"
        if subsection == (7, 6):
            return "M6.4-population-matrix"
        if subsection == (7, 7):
            return "M6.2-operation-algebra"
        if subsection == (7, 8):
            return "M6.5-behavior-trace"
        return "M0-integration-invariants"
    if section in (8, 9, 24, 25, 26):
        return "M7-selector-mapping"
    if section == 10:
        return "M3-source-set"
    if section in (11, 12):
        return "M4-filters"
    if section in (13, 14, 15, 16, 21):
        return "M2-outcomes"
    if section in (17, 18, 19, 20):
        return "M5-pipeline"
    return "M0-integration-invariants"


def fixture_assignment() -> dict[int, str]:
    result = {number: "M0-integration-invariants" for number in range(1, 128)}

    def assign(numbers: range | tuple[int, ...], module: str) -> None:
        for number in numbers:
            result[number] = module

    assign(range(4, 15), "M2-outcomes")
    assign((15, 60, 61, 62, 88, 89, 90, 91, 92), "M1-primitives")
    assign((16, 17, 75, 78, 79, 80, 81, 84), "M7-selector-mapping")
    assign((18, 99), "M2-outcomes")
    assign((20, 21, 22, 23, 100, 101, 102, 108), "M6.1-registries")
    assign(tuple(range(24, 31)) + (76, 77, 93, 94, 95, 96, 97, 98), "M3-source-set")
    assign(tuple(range(31, 47)) + (87,), "M4-filters")
    assign(range(47, 60), "M5-pipeline")
    assign(range(63, 75), "M2-outcomes")
    assign((104, 105, 110, 111, 112, 113, 114, 115, 116, 117, 118), "M6.2-operation-algebra")
    assign((121, 122, 123), "M6.3-enumeration-domains")
    assign((124, 126), "M6.4-population-matrix")
    assign((119, 127), "M6.5-behavior-trace")
    if set(result) != set(range(1, 128)):
        raise R1Error("fixture assignment is incomplete")
    return result


def extract_proposal(source: bytes) -> tuple[dict[str, bytes], list[dict[str, object]], dict[str, int]]:
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise R1Error("v9 proposal is not UTF-8") from exc
    lines = text.splitlines(keepends=True)
    if b"".join(line.encode("utf-8") for line in lines) != source:
        raise R1Error("proposal line split is not byte-lossless")

    fixtures = fixture_assignment()
    targets: dict[str, bytearray] = {
        f"B1.1b/modules/{module}/MODULE.md": bytearray() for module in MODULE_IDS
    }
    entries: list[dict[str, object]] = []
    section: int | None = None
    subsection: tuple[int, int] | None = None
    source_offset = 0
    seen_fixtures: set[int] = set()

    for line_number, line in enumerate(lines, 1):
        raw = line.encode("utf-8")
        h2 = re.match(r"^##\s+(\d+)\.", line)
        h3 = re.match(r"^###\s+(\d+)\.(\d+)", line)
        if h2:
            section = int(h2.group(1))
            subsection = None
        if h3:
            subsection = (int(h3.group(1)), int(h3.group(2)))

        fixture = re.match(r"^(\d{2,3})\s+", line) if section == 28 else None
        if fixture:
            fixture_id = int(fixture.group(1))
            if fixture_id not in fixtures or fixture_id in seen_fixtures:
                raise R1Error(f"invalid or duplicate fixture line: {fixture_id}")
            seen_fixtures.add(fixture_id)
            module = fixtures[fixture_id]
            target = f"B1.1b/modules/{module}/fixtures/{fixture_id:03}.txt"
        else:
            module = proposal_module(section, subsection)
            target = f"B1.1b/modules/{module}/MODULE.md"

        buffer = targets.setdefault(target, bytearray())
        target_start = len(buffer)
        buffer.extend(raw)
        entries.append({
            "kind": "proposal-byte-slice",
            "module_id": module,
            "source_byte_start": source_offset,
            "source_byte_end_exclusive": source_offset + len(raw),
            "source_line_start_one_based": line_number,
            "source_line_end_one_based_exclusive": line_number + 1,
            "target_path": target,
            "target_byte_start": target_start,
            "target_byte_end_exclusive": target_start + len(raw),
            "slice_sha256": sha256_bytes(raw),
        })
        source_offset += len(raw)

    if source_offset != len(source):
        raise R1Error("proposal extraction did not cover all bytes")
    if seen_fixtures != set(range(1, 128)):
        raise R1Error(f"fixture set mismatch: {sorted(set(range(1, 128)) - seen_fixtures)}")

    outputs = {name: bytes(data) for name, data in targets.items()}
    reconstructed = bytearray()
    for entry in entries:
        data = outputs[str(entry["target_path"])]
        reconstructed.extend(data[int(entry["target_byte_start"]):int(entry["target_byte_end_exclusive"])])
    if bytes(reconstructed) != source:
        raise R1Error("proposal reconstruction is not byte-identical")
    counts = {
        module: sum(1 for fixture_id, assigned in fixtures.items() if assigned == module)
        for module in MODULE_IDS
    }
    return outputs, entries, counts


def extract_schema(source: bytes) -> tuple[dict[str, bytes], list[dict[str, object]], list[str], str]:
    try:
        schema = json.loads(source.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise R1Error("v9 schema is not valid UTF-8 JSON") from exc
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict):
        raise R1Error("v9 schema has no $defs object")

    assigned: dict[str, str] = {}
    for module, names in DEF_ASSIGNMENT.items():
        for name in names:
            if name in assigned:
                raise R1Error(f"duplicate schema extraction assignment: {name}")
            assigned[name] = module
    if set(assigned) != set(definitions):
        missing = sorted(set(definitions) - set(assigned))
        extra = sorted(set(assigned) - set(definitions))
        raise R1Error(f"schema extraction assignment mismatch: missing={missing}, extra={extra}")

    root_schema = {key: value for key, value in schema.items() if key != "$defs"}
    outputs: dict[str, bytes] = {}
    entries: list[dict[str, object]] = []
    definition_order = list(definitions)
    for module in MODULE_IDS:
        fragment = {
            "schema": "securelinux-policy-b1.1b-schema-extraction-fragment/v1",
            "module_id": module,
            "assignment_is_normative_ownership": False,
            "source_schema_sha256": SCHEMA_SHA256,
            "root_schema": root_schema if module == "M0-integration-invariants" else None,
            "definitions": {
                name: definitions[name]
                for name in definition_order if assigned[name] == module
            },
        }
        target = f"B1.1b/modules/{module}/schema.json"
        data = canonical_json_bytes(fragment)
        outputs[target] = data
        if module == "M0-integration-invariants":
            for key in root_schema:
                entries.append({
                    "kind": "schema-root-member",
                    "module_id": module,
                    "source_json_pointer": "/" + key.replace("~", "~0").replace("/", "~1"),
                    "target_path": target,
                    "target_json_pointer": "/root_schema/" + key.replace("~", "~0").replace("/", "~1"),
                    "value_sha256": sha256_bytes(canonical_json_bytes(root_schema[key])),
                })
        for name in fragment["definitions"]:
            escaped = name.replace("~", "~0").replace("/", "~1")
            entries.append({
                "kind": "schema-definition",
                "module_id": module,
                "source_json_pointer": "/$defs/" + escaped,
                "target_path": target,
                "target_json_pointer": "/definitions/" + escaped,
                "value_sha256": sha256_bytes(canonical_json_bytes(definitions[name])),
            })

    reconstructed = dict(root_schema)
    reconstructed_defs: dict[str, object] = {}
    fragments = {name: json.loads(data) for name, data in outputs.items()}
    for name in definition_order:
        module = assigned[name]
        target = f"B1.1b/modules/{module}/schema.json"
        reconstructed_defs[name] = fragments[target]["definitions"][name]
    reconstructed["$defs"] = reconstructed_defs
    if reconstructed != schema:
        raise R1Error("schema reconstruction is not object-identical")
    tree_sha256 = sha256_bytes(canonical_json_bytes(schema))
    if sha256_bytes(canonical_json_bytes(reconstructed)) != tree_sha256:
        raise R1Error("schema canonical tree hash mismatch")
    return outputs, entries, definition_order, tree_sha256


def reconstruct_from_outputs(
    outputs: dict[str, bytes],
    proposal_entries: list[dict[str, object]],
    definition_order: list[str],
) -> tuple[bytes, dict[str, object]]:
    proposal = bytearray()
    for entry in proposal_entries:
        data = outputs[str(entry["target_path"])]
        proposal.extend(data[int(entry["target_byte_start"]):int(entry["target_byte_end_exclusive"])])

    fragments = {
        module: json.loads(outputs[f"B1.1b/modules/{module}/schema.json"])
        for module in MODULE_IDS
    }
    schema = dict(fragments["M0-integration-invariants"]["root_schema"])
    definitions: dict[str, object] = {}
    locations: dict[str, str] = {}
    for module, fragment in fragments.items():
        for name, value in fragment["definitions"].items():
            if name in definitions:
                raise R1Error(f"duplicate definition during reconstruction: {name}")
            definitions[name] = value
            locations[name] = module
    if set(definitions) != set(definition_order):
        raise R1Error("definition set changed during reconstruction")
    schema["$defs"] = {name: definitions[name] for name in definition_order}
    return bytes(proposal), schema


def run_tests(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    selftest = subprocess.run(
        [sys.executable, str(root / SELFTEST_REL), str(root)],
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if selftest.returncode != 0 or "RESULT=B1_1B_V9_SELFTEST_PASS" not in selftest.stdout:
        raise R1Error("v9 self-test failed:\n" + selftest.stdout[-4000:])
    regression = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    match = re.search(r"Ran\s+(\d+)\s+tests?", regression.stdout)
    count = int(match.group(1)) if match else None
    if regression.returncode != 0 or count != 107 or not re.search(r"^OK$", regression.stdout, re.MULTILINE):
        raise R1Error("107-test regression failed:\n" + regression.stdout[-5000:])
    return (
        {"result": "PASS", "marker": "RESULT=B1_1B_V9_SELFTEST_PASS"},
        {"result": "PASS", "tests": 107},
    )


def immutable_write(path: Path, data: bytes) -> None:
    if path.exists():
        if not path.is_file() or path.is_symlink() or path.read_bytes() != data:
            raise R1Error(f"existing R1 artifact differs: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-r1")
    if temporary.exists():
        raise R1Error(f"stale R1 temporary file: {temporary}")
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def replace_state(path: Path, old_data: bytes, new_data: bytes, verify_only: bool) -> None:
    current = require_regular(path)
    if current == new_data:
        return
    if verify_only:
        raise R1Error("PROJECT-STATE is not at R1_COMPLETE")
    if current != old_data:
        raise R1Error("PROJECT-STATE changed after R0.1 admission")
    old_state = json.loads(old_data)
    if old_state.get("current_phase") != "R0_1_COMPLETE":
        raise R1Error("PROJECT-STATE is neither completed R0.1 nor expected R1")
    temporary = path.with_name(path.name + ".tmp-r1")
    if temporary.exists():
        raise R1Error(f"stale state temporary file: {temporary}")
    with temporary.open("xb") as stream:
        stream.write(new_data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def verify_expected_layout(root: Path, expected_paths: set[str]) -> None:
    base = root / "B1.1b"
    scoped = (base / "modules", base / "integration", base / "reports")
    actual = {
        path.relative_to(root).as_posix()
        for directory in scoped for path in directory.rglob("*") if path.is_file()
    }
    scoped_expected = {
        name for name in expected_paths
        if name.startswith("B1.1b/modules/")
        or name.startswith("B1.1b/integration/")
        or name.startswith("B1.1b/reports/")
    }
    if actual != scoped_expected:
        raise R1Error(
            f"unexpected R1 scoped files: missing={sorted(scoped_expected-actual)[:5]}, "
            f"extra={sorted(actual-scoped_expected)[:5]}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project_root", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    root = arguments.project_root.resolve()
    script_path = Path(__file__).resolve()
    if not root.is_dir() or not (root / "B1.1b").is_dir():
        raise R1Error(f"R0 project root missing: {root}")

    baseline, _findings, initial_state = verify_baseline(root)
    initial_state_data = canonical_json_bytes(initial_state)
    if arguments.verify_only and initial_state.get("current_phase") != "R1_COMPLETE":
        raise R1Error("--verify-only requires R1_COMPLETE")
    if not arguments.verify_only and initial_state.get("current_phase") not in ("R0_1_COMPLETE", "R1_COMPLETE"):
        raise R1Error("R1 may start only from completed R0.1")

    snapshot_before = verify_snapshot_unchanged(root, baseline, initial_state)
    proposal_source = require_regular(root / PROPOSAL_REL, PROPOSAL_SHA256)
    schema_source = require_regular(root / SCHEMA_REL, SCHEMA_SHA256)
    proposal_outputs, proposal_entries, fixture_counts = extract_proposal(proposal_source)
    schema_outputs, schema_entries, definition_order, schema_tree_sha256 = extract_schema(schema_source)
    outputs = {**proposal_outputs, **schema_outputs}
    reconstructed_proposal, reconstructed_schema = reconstruct_from_outputs(
        outputs, proposal_entries, definition_order
    )
    if reconstructed_proposal != proposal_source:
        raise R1Error("final proposal reconstruction mismatch")
    source_schema_object = json.loads(schema_source)
    if reconstructed_schema != source_schema_object:
        raise R1Error("final schema reconstruction mismatch")

    selftest_result, regression_result = run_tests(root)
    if scan_live_snapshot(root) != snapshot_before:
        raise R1Error("tests mutated files outside B1.1b/")

    script_data = require_regular(script_path)
    script_digest = sha256_bytes(script_data)
    tool_rel = f"B1.1b/tools/{SCRIPT_NAME}"
    tool_sidecar_rel = tool_rel + ".sha256"
    outputs[tool_rel] = script_data
    outputs[tool_sidecar_rel] = f"{script_digest}  {SCRIPT_NAME}\n".encode("utf-8")

    module_outputs: dict[str, dict[str, object]] = {}
    for module in MODULE_IDS:
        names = sorted(name for name in outputs if name.startswith(f"B1.1b/modules/{module}/"))
        module_outputs[module] = {
            "files": len(names),
            "fixtures": fixture_counts[module],
            "schema_definitions": len(DEF_ASSIGNMENT[module]),
            "content_sha256": sha256_bytes(canonical_json_bytes([
                {"path": name, "sha256": sha256_bytes(outputs[name])} for name in names
            ])),
        }

    extraction_map = {
        "schema": "securelinux-policy-b1.1b-r1-extraction-map/v1",
        "date": DATE,
        "baseline_sha256": BASELINE_SHA256,
        "r0_1_admin_docs_ledger_sha256": initial_state["r0_1_admin_docs"]["ledger_sha256"],
        "assignment_is_normative_ownership": False,
        "proposal": {
            "source_path": PROPOSAL_REL,
            "source_sha256": PROPOSAL_SHA256,
            "source_bytes": len(proposal_source),
            "slice_count": len(proposal_entries),
            "reconstruction": "BYTE_IDENTICAL",
            "entries": proposal_entries,
        },
        "schema_extraction": {
            "source_path": SCHEMA_REL,
            "source_sha256": SCHEMA_SHA256,
            "definition_count": len(definition_order),
            "definition_order": definition_order,
            "tree_sha256": schema_tree_sha256,
            "reconstruction": "OBJECT_IDENTICAL",
            "entries": schema_entries,
        },
        "fixtures": {
            "specification_count": 127,
            "executable_in_b1_1b": False,
            "execution_owner": "B2_AFTER_TASK_B1_1_ACCEPTANCE",
            "per_module": fixture_counts,
        },
        "modules": module_outputs,
    }
    map_rel = "B1.1b/integration/R1-EXTRACTION-MAP.json"
    outputs[map_rel] = canonical_json_bytes(extraction_map)

    report = {
        "schema": "securelinux-policy-b1.1b-r1-extraction-report/v1",
        "date": DATE,
        "result": "R1_EXTRACTION_EQUIVALENCE_PASS",
        "baseline_sha256": BASELINE_SHA256,
        "proposal_reconstruction": {
            "result": "PASS",
            "mode": "byte-identical",
            "sha256": sha256_bytes(reconstructed_proposal),
        },
        "schema_reconstruction": {
            "result": "PASS",
            "mode": "parsed-tree-object-identical",
            "definitions": len(definition_order),
            "tree_sha256": schema_tree_sha256,
            "validation_equivalence_basis": "identical parsed schema tree",
        },
        "fixture_specifications": {
            "result": "PASS",
            "count": 127,
            "executable_fixtures": "DEFERRED_TO_B2_BY_V9_SECTION_28",
        },
        "v9_selftest": selftest_result,
        "full_regression": regression_result,
        "existing_project_mutation": False,
        "interfaces_created": False,
        "locks_created": False,
        "normative_owners_assigned": False,
        "next_phase": "R2_INTERFACES_DAG_CHECKER",
    }
    report_rel = "B1.1b/reports/R1-EXTRACTION-REPORT.json"
    outputs[report_rel] = canonical_json_bytes(report)

    manifest_names = sorted(outputs)
    manifest = "".join(f"{sha256_bytes(outputs[name])}  {name}\n" for name in manifest_names).encode("utf-8")
    manifest_rel = "B1.1b/reports/R1-OUTPUTS.sha256"
    outputs[manifest_rel] = manifest
    manifest_digest = sha256_bytes(manifest)

    new_state = json.loads(json.dumps(initial_state))
    new_state["current_phase"] = "R1_COMPLETE"
    new_state["current_next_step"] = "R2_INTERFACES_DAG_CHECKER"
    new_state["gates"]["R1_EXTRACTION_EQUIVALENCE_PASS"] = True
    new_state["r1"] = {
        "extraction_map_sha256": sha256_bytes(outputs[map_rel]),
        "report_sha256": sha256_bytes(outputs[report_rel]),
        "outputs_manifest_sha256": manifest_digest,
        "proposal_reconstruction": "BYTE_IDENTICAL",
        "schema_reconstruction": "OBJECT_IDENTICAL",
        "fixture_specifications": 127,
        "v9_selftest": "PASS",
        "regression_tests": "107/107_PASS",
    }
    for module in MODULE_IDS:
        new_state["modules"][module]["status"] = "OPEN"
        new_state["modules"][module]["version"] = "v9-extracted-r1"
        new_state["modules"][module]["extraction_content_sha256"] = module_outputs[module]["content_sha256"]
    new_state_data = canonical_json_bytes(new_state)

    expected_paths = set(outputs)
    if arguments.verify_only:
        for relative, data in outputs.items():
            if require_regular(root / relative) != data:
                raise R1Error(f"R1 verification mismatch: {relative}")
        replace_state(
            root / "B1.1b/state/PROJECT-STATE.json",
            initial_state_data,
            new_state_data,
            True,
        )
        verify_expected_layout(root, expected_paths)
    else:
        for relative, data in outputs.items():
            immutable_write(root / relative, data)
        replace_state(
            root / "B1.1b/state/PROJECT-STATE.json",
            initial_state_data,
            new_state_data,
            False,
        )
        verify_expected_layout(root, expected_paths)

    final_snapshot = scan_live_snapshot(root)
    if final_snapshot != snapshot_before:
        raise R1Error("R1 changed files outside B1.1b/")

    print("RESULT=R1_EXTRACTION_EQUIVALENCE_PASS")
    print("PROPOSAL_RECONSTRUCTION=BYTE_IDENTICAL")
    print("SCHEMA_RECONSTRUCTION=OBJECT_IDENTICAL")
    print(f"SCHEMA_DEFINITIONS={len(definition_order)}/192")
    print("FIXTURE_SPECIFICATIONS=127/127")
    print("V9_SELFTEST=PASS")
    print("FULL_REGRESSION_TESTS=107/107_PASS")
    print("R0_1_ADMIN_DOCS_OVERLAY=PASS")
    print("MODULES=12/12_OPEN")
    print("INTERFACES_CREATED=false")
    print("LOCKS_CREATED=false")
    print("NORMATIVE_OWNERS_ASSIGNED=false")
    print("B1_1B_V9=IMMUTABLE_CANDIDATE_NOT_ACCEPTED")
    print("TASK_B1_1_ACCEPTED=false")
    print("TASK_B1_2=NOT_STARTED")
    print("SELECTOR_INSTANCES_FROZEN=0/20")
    print(f"SHA256={sha256_bytes(outputs[map_rel])}  {map_rel}")
    print(f"SHA256={sha256_bytes(outputs[report_rel])}  {report_rel}")
    print(f"SHA256={manifest_digest}  {manifest_rel}")
    print(f"SHA256={sha256_bytes(new_state_data)}  B1.1b/state/PROJECT-STATE.json")
    print("CURRENT_NEXT_STEP=R2_INTERFACES_DAG_CHECKER")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (R1Error, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"R1_FAIL={exc}", file=sys.stderr)
        raise SystemExit(1)
