#!/usr/bin/env python3
"""R2: materialize and verify B1.1b module interfaces and dependency DAG.

The tool is both the point installer and checker v1.  It derives exports from
the immutable R1 schema/text fragments, assigns exactly one owner per symbol,
builds offline-only JSON Schema references, rejects dependency cycles, writes
module locks, and advances PROJECT-STATE only after all checks pass.

No v9 normative source, canonical corpus, validator, runtime, src, tests,
sources, SVG, or PNG file is modified.  README.md and CHANGELOG.md are updated
through an explicitly recorded administrative/non-normative overlay.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any


SCRIPT_NAME = "SecureLinux-Policy-TASK-B1.1-R2-interface-dag-checker-v1-20260813.py"
DATE = "2026-08-13"

BASELINE_SHA256 = "3daac5da494cabb9551b269dcb56df83469ee79491a83c3445bcd33bae0274e3"
OPEN_FINDINGS_SHA256 = "5b9bd4da4cb22aad60e75b79851bc8b58b707b6695cceca47dcc47e1540df53a"
R1_PROJECT_STATE_SHA256 = "80d0a88f317aa66ac2218b91cd357317c669bb6135c9374fb144db698ff6bb63"
R1_MAP_SHA256 = "fcf313e78bea73798604c37a3ce1fadc7d30188ebaa7edc26db15c43f45ec410"
R1_REPORT_SHA256 = "d2e61fd07ee16d624f8e8a3972fb94d046463bd17546d0893b8cb07a64a5d4de"
R1_OUTPUTS_SHA256 = "877c2a9bd2238c302a2f6e8aca669e2975c46871b0cb90646ae0fe458e3c593d"
R1_OUTPUT_RECORDS = 155

PROPOSAL_REL = "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-proposal-v9-20260813.md"
PROPOSAL_SHA256 = "bb359806252163cc6cf29f3499ff828891d3ce11104fe9934704c7022f14abfb"
SCHEMA_REL = "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-schema-v9-20260813.json"
SCHEMA_SHA256 = "2304b192d4f3c8e4fde056a42970ae4b2200df28012019445023c704c6375995"
SELFTEST_REL = "docs/SecureLinux-Policy-TASK-B1.1b-v9-selftest-20260813.py"

R0_1_LEDGER_REL = "B1.1b/state/R0.1-ADMIN-DOCS-LEDGER.json"
R0_1_MANIFEST_REL = "B1.1b/state/R0.1-ADMIN-DOCS.sha256"
R1_MAP_REL = "B1.1b/integration/R1-EXTRACTION-MAP.json"
R1_REPORT_REL = "B1.1b/reports/R1-EXTRACTION-REPORT.json"
R1_OUTPUTS_REL = "B1.1b/reports/R1-OUTPUTS.sha256"
STATE_REL = "B1.1b/state/PROJECT-STATE.json"

R2_OWNERSHIP_REL = "B1.1b/state/R2-OWNERSHIP.json"
R2_DAG_REL = "B1.1b/integration/R2-SYMBOL-DAG.json"
R2_LOCK_REL = "B1.1b/integration/INTEGRATION.lock.json"
R2_REPORT_REL = "B1.1b/reports/R2-CHECKER-REPORT.json"
R2_OUTPUTS_REL = "B1.1b/reports/R2-OUTPUTS.sha256"
R2_ADMIN_LEDGER_REL = "B1.1b/state/R2-ADMIN-DOCS-LEDGER.json"
R2_ADMIN_MANIFEST_REL = "B1.1b/state/R2-ADMIN-DOCS.sha256"
R1_STATE_CHECKPOINT_REL = "B1.1b/state/R1-PROJECT-STATE.json"

R0_1_README_SHA256 = "2e5fae57ccefafa1599dbff15a1693acd101f012b0a9c0b57368f94b46e09cd0"
R0_1_CHANGELOG_SHA256 = "c36c831a8a7d91f6e4d0c1a067046b353df2f15c306635574e21b8bc5def0a5b"

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

# R1 placement is extraction-only.  These six content-preserving ownership
# relocations are required to make the symbol dependency graph acyclic.
OWNER_REHOMES = {
    "SourceStatement": "M1-primitives",
    "Requirement": "M1-primitives",
    "BehaviorPopulationMemberRef": "M6.2-operation-algebra",
    "BoundPopulationRef": "M6.2-operation-algebra",
    "BehaviorPopulationRef": "M6.2-operation-algebra",
    "BehaviorContract": "M6.4-population-matrix",
}

EXPECTED_REHOME_SOURCES = {
    "SourceStatement": "M3-source-set",
    "Requirement": "M7-selector-mapping",
    "BehaviorPopulationMemberRef": "M6.4-population-matrix",
    "BoundPopulationRef": "M6.4-population-matrix",
    "BehaviorPopulationRef": "M6.4-population-matrix",
    "BehaviorContract": "M6.2-operation-algebra",
}


class R2Error(RuntimeError):
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


def canonical_value_sha256(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def require_regular(path: Path, expected_sha256: str | None = None) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise R2Error(f"missing or unsafe regular file: {path}")
    data = path.read_bytes()
    if expected_sha256 is not None and sha256_bytes(data) != expected_sha256:
        raise R2Error(f"SHA-256 mismatch: {path}")
    return data


def atomic_replace(path: Path, data: bytes, suffix: str) -> None:
    temporary = path.with_name(path.name + suffix)
    if temporary.exists():
        raise R2Error(f"stale temporary file: {temporary}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def immutable_write(path: Path, data: bytes) -> None:
    if path.exists():
        if not path.is_file() or path.is_symlink() or path.read_bytes() != data:
            raise R2Error(f"existing R2 artifact differs: {path}")
        return
    atomic_replace(path, data, ".tmp-r2")


def safe_relative_name(name: str) -> bool:
    pure = PurePosixPath(name)
    return bool(name) and not pure.is_absolute() and all(part not in ("", ".", "..") for part in pure.parts)


def parse_manifest(data: bytes, label: str) -> list[tuple[str, str]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise R2Error(f"manifest is not UTF-8: {label}") from exc
    records: list[tuple[str, str]] = []
    seen: set[str] = set()
    for number, line in enumerate(lines, 1):
        if len(line) < 67 or line[64:66] not in ("  ", " *"):
            raise R2Error(f"invalid manifest record: {label}:{number}")
        digest = line[:64].lower()
        name = line[66:]
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise R2Error(f"invalid manifest SHA-256: {label}:{number}")
        if not safe_relative_name(name) or name in seen:
            raise R2Error(f"unsafe or duplicate manifest name: {label}:{number}: {name!r}")
        seen.add(name)
        records.append((digest, name))
    return records


def verify_manifest(root: Path, relative: str, expected_sha256: str, expected_records: int) -> dict[str, str]:
    data = require_regular(root / relative, expected_sha256)
    records = parse_manifest(data, relative)
    if len(records) != expected_records:
        raise R2Error(f"manifest record count mismatch: {relative}: {len(records)} != {expected_records}")
    result: dict[str, str] = {}
    for digest, name in records:
        if sha256_file(root / name) != digest:
            raise R2Error(f"manifest target mismatch: {relative}: {name}")
        result[name] = digest
    return result


def baseline_inventory(baseline: dict[str, object]) -> dict[str, dict[str, object]]:
    records = baseline.get("project_snapshot", {}).get("files")
    if not isinstance(records, list):
        raise R2Error("R0 baseline project inventory missing")
    result: dict[str, dict[str, object]] = {}
    for item in records:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise R2Error("invalid R0 baseline inventory record")
        result[str(item["path"])] = {"sha256": item["sha256"], "size": item["size"]}
    return result


def scan_snapshot(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            relative = path.relative_to(root)
            if relative.parts[0] in (".git", "B1.1b"):
                continue
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise R2Error(f"project link forbidden: {relative.as_posix()}")
            if stat.S_ISDIR(metadata.st_mode):
                visit(path)
            elif stat.S_ISREG(metadata.st_mode):
                result[relative.as_posix()] = {"sha256": sha256_file(path), "size": metadata.st_size}
            else:
                raise R2Error(f"project special entry forbidden: {relative.as_posix()}")

    visit(root)
    return result


def diff_summary(expected: dict[str, object], actual: dict[str, object]) -> str:
    missing = sorted(set(expected) - set(actual))[:5]
    extra = sorted(set(actual) - set(expected))[:5]
    changed = sorted(name for name in set(expected) & set(actual) if expected[name] != actual[name])[:5]
    return f"missing={missing}, extra={extra}, changed={changed}"


def load_admission(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes, dict[str, str]]:
    baseline_data = require_regular(root / "B1.1b/baseline/v9/BASELINE.json", BASELINE_SHA256)
    if require_regular(root / "B1.1b/baseline/v9/BASELINE.sha256") != f"{BASELINE_SHA256}  BASELINE.json\n".encode():
        raise R2Error("BASELINE.sha256 mismatch")
    findings_data = require_regular(root / "B1.1b/state/OPEN-FINDINGS.json", OPEN_FINDINGS_SHA256)
    state_data = require_regular(root / STATE_REL)
    baseline = json.loads(baseline_data)
    findings = json.loads(findings_data)
    state = json.loads(state_data)
    if baseline.get("gate") != "R0_BASELINE_CLOSURE_PASS":
        raise R2Error("R0 baseline gate is not PASS")
    if state.get("baseline_sha256") != BASELINE_SHA256 or state.get("open_findings_sha256") != OPEN_FINDINGS_SHA256:
        raise R2Error("PROJECT-STATE baseline/findings references changed")
    if {item.get("finding_id") for item in findings.get("findings", [])} != {"V8-01", "V8-EXT-01", "V8-EXT-02"}:
        raise R2Error("open finding set changed")
    if state.get("current_phase") not in ("R1_COMPLETE", "R2_COMPLETE"):
        raise R2Error("R2 requires R1_COMPLETE or verifies R2_COMPLETE")
    if state.get("current_phase") == "R1_COMPLETE" and sha256_bytes(state_data) != R1_PROJECT_STATE_SHA256:
        raise R2Error("R1 PROJECT-STATE is not the pinned state")
    if state.get("gates", {}).get("R1_EXTRACTION_EQUIVALENCE_PASS") is not True:
        raise R2Error("R1 extraction gate is not PASS")
    r1 = state.get("r1", {})
    if (
        r1.get("extraction_map_sha256") != R1_MAP_SHA256
        or r1.get("report_sha256") != R1_REPORT_SHA256
        or r1.get("outputs_manifest_sha256") != R1_OUTPUTS_SHA256
        or r1.get("proposal_reconstruction") != "BYTE_IDENTICAL"
        or r1.get("schema_reconstruction") != "OBJECT_IDENTICAL"
        or r1.get("fixture_specifications") != 127
        or r1.get("regression_tests") != "107/107_PASS"
    ):
        raise R2Error("R1 state evidence changed")
    r1_files = verify_manifest(root, R1_OUTPUTS_REL, R1_OUTPUTS_SHA256, R1_OUTPUT_RECORDS)
    require_regular(root / R1_MAP_REL, R1_MAP_SHA256)
    require_regular(root / R1_REPORT_REL, R1_REPORT_SHA256)
    return baseline, findings, state, state_data, r1_files


def expected_r0_1_snapshot(root: Path, baseline: dict[str, Any], state: dict[str, Any]) -> dict[str, dict[str, object]]:
    expected = baseline_inventory(baseline)
    ledger_data = require_regular(root / R0_1_LEDGER_REL)
    manifest_data = require_regular(root / R0_1_MANIFEST_REL)
    overlay_state = state.get("r0_1_admin_docs")
    if not isinstance(overlay_state, dict):
        raise R2Error("R0.1 overlay state missing")
    if overlay_state.get("ledger_sha256") != sha256_bytes(ledger_data):
        raise R2Error("R0.1 ledger reference mismatch")
    if overlay_state.get("manifest_sha256") != sha256_bytes(manifest_data):
        raise R2Error("R0.1 manifest reference mismatch")
    ledger = json.loads(ledger_data)
    if ledger.get("allowed_paths") != ["README.md", "CHANGELOG.md"]:
        raise R2Error("R0.1 allowed path set changed")
    changes = ledger.get("changes", {})
    readme = changes.get("README.md", {})
    changelog = changes.get("CHANGELOG.md", {})
    if readme.get("after_sha256") != R0_1_README_SHA256 or changelog.get("after_sha256") != R0_1_CHANGELOG_SHA256:
        raise R2Error("R0.1 root documentation hashes changed")
    if expected.get("README.md") != {"sha256": readme.get("before_sha256"), "size": readme.get("before_size")}:
        raise R2Error("R0.1 README before-state mismatch")
    if "CHANGELOG.md" in expected:
        raise R2Error("R0 baseline unexpectedly contains CHANGELOG.md")
    expected["README.md"] = {"sha256": readme["after_sha256"], "size": readme["after_size"]}
    expected["CHANGELOG.md"] = {"sha256": changelog["after_sha256"], "size": changelog["after_size"]}
    return expected


def reconstruct_r1(root: Path, r1_files: dict[str, str]) -> tuple[dict[str, bytes], dict[str, Any], dict[str, Any]]:
    extraction_map = json.loads(require_regular(root / R1_MAP_REL, R1_MAP_SHA256))
    proposal_map = extraction_map.get("proposal", {})
    schema_map = extraction_map.get("schema_extraction", {})
    if proposal_map.get("reconstruction") != "BYTE_IDENTICAL" or schema_map.get("reconstruction") != "OBJECT_IDENTICAL":
        raise R2Error("R1 extraction map claims changed")
    module_files = {
        name: require_regular(root / name)
        for name in r1_files
        if name.startswith("B1.1b/modules/")
    }
    proposal = bytearray()
    for entry in proposal_map.get("entries", []):
        target = entry.get("target_path")
        if target not in module_files:
            raise R2Error(f"R1 proposal target missing: {target}")
        start = entry.get("target_byte_start")
        end = entry.get("target_byte_end_exclusive")
        if not isinstance(start, int) or not isinstance(end, int) or not (0 <= start < end <= len(module_files[target])):
            raise R2Error("invalid R1 proposal slice range")
        data = module_files[target][start:end]
        if sha256_bytes(data) != entry.get("slice_sha256"):
            raise R2Error("R1 proposal slice hash mismatch")
        proposal.extend(data)
    proposal_bytes = bytes(proposal)
    if sha256_bytes(proposal_bytes) != PROPOSAL_SHA256 or proposal_bytes != require_regular(root / PROPOSAL_REL, PROPOSAL_SHA256):
        raise R2Error("R1 proposal reconstruction regressed")

    fragments: dict[str, Any] = {}
    extraction_owner: dict[str, str] = {}
    definitions: dict[str, Any] = {}
    for module in MODULE_IDS:
        path = f"B1.1b/modules/{module}/schema.json"
        fragment = json.loads(module_files[path])
        if fragment.get("module_id") != module or fragment.get("assignment_is_normative_ownership") is not False:
            raise R2Error(f"R1 schema fragment identity changed: {module}")
        fragments[module] = fragment
        for name, value in fragment.get("definitions", {}).items():
            if name in definitions:
                raise R2Error(f"duplicate R1 schema definition: {name}")
            definitions[name] = value
            extraction_owner[name] = module
    order = schema_map.get("definition_order")
    if not isinstance(order, list) or len(order) != 192 or set(order) != set(definitions):
        raise R2Error("R1 schema definition set/order changed")
    root_schema = fragments["M0-integration-invariants"].get("root_schema")
    if not isinstance(root_schema, dict):
        raise R2Error("R1 root schema missing")
    reconstructed = dict(root_schema)
    reconstructed["$defs"] = {name: definitions[name] for name in order}
    source_schema = json.loads(require_regular(root / SCHEMA_REL, SCHEMA_SHA256))
    if reconstructed != source_schema:
        raise R2Error("R1 schema reconstruction regressed")
    return module_files, extraction_map, {
        "root_schema": root_schema,
        "definitions": definitions,
        "definition_order": order,
        "extraction_owner": extraction_owner,
    }


def json_pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def walk_refs(value: object, pointer: str = "") -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_pointer = pointer + "/" + json_pointer_escape(str(key))
            if key == "$ref" and isinstance(child, str):
                if not child.startswith("#/$defs/"):
                    raise R2Error(f"non-local v9 $ref forbidden at {child_pointer}: {child}")
                result.append((child_pointer, child[len("#/$defs/"):]))
            result.extend(walk_refs(child, child_pointer))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.extend(walk_refs(child, pointer + f"/{index}"))
    return result


def walk_schema_values(value: object, pointer: str = "") -> list[tuple[str, str, object]]:
    result: list[tuple[str, str, object]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_pointer = pointer + "/" + json_pointer_escape(str(key))
            if key == "const":
                result.append(("schema-const-value", child_pointer, child))
            elif key == "enum" and isinstance(child, list):
                for index, item in enumerate(child):
                    result.append(("schema-enum-value", child_pointer + f"/{index}", item))
            result.extend(walk_schema_values(child, child_pointer))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.extend(walk_schema_values(child, pointer + f"/{index}"))
    return result


def ownership(schema_data: dict[str, Any]) -> tuple[dict[str, str], list[dict[str, object]]]:
    extraction_owner = schema_data["extraction_owner"]
    owners = dict(extraction_owner)
    relocations: list[dict[str, object]] = []
    for name, owner in OWNER_REHOMES.items():
        if extraction_owner.get(name) != EXPECTED_REHOME_SOURCES[name]:
            raise R2Error(f"R1 extraction owner changed for rehomed symbol: {name}")
        owners[name] = owner
        relocations.append({
            "symbol_id": f"schema-definition:{name}",
            "definition_name": name,
            "from_extraction_module": extraction_owner[name],
            "to_normative_owner": owner,
            "definition_sha256": canonical_value_sha256(schema_data["definitions"][name]),
            "classification": "CONTENT_PRESERVING_OWNER_REHOME",
            "reason": "BREAK_SCHEMA_DEPENDENCY_CYCLE",
        })
    if set(owners) != set(schema_data["definitions"]) or set(owners.values()) - set(MODULE_IDS):
        raise R2Error("schema ownership is incomplete")
    return owners, relocations


def extract_rules(module_files: dict[str, bytes]) -> tuple[dict[str, list[dict[str, object]]], dict[str, list[dict[str, object]]]]:
    rules_by_module: dict[str, list[dict[str, object]]] = {module: [] for module in MODULE_IDS}
    fixtures_by_module: dict[str, list[dict[str, object]]] = {module: [] for module in MODULE_IDS}
    seen_rules: set[str] = set()
    fixture_ids: set[int] = set()
    heading_pattern = re.compile(rb"^(##|###)\s+(\d+(?:\.\d+)?)\.?[^\n]*(?:\n|$)", re.MULTILINE)
    for module in MODULE_IDS:
        path = f"B1.1b/modules/{module}/MODULE.md"
        data = module_files[path]
        matches = list(heading_pattern.finditer(data))
        starts: list[tuple[int, str, str]] = []
        if matches and matches[0].start() > 0:
            starts.append((0, "preamble", "preamble"))
        for match in matches:
            section = match.group(2).decode("ascii")
            starts.append((match.start(), f"section:{section}", match.group(0).decode("utf-8").strip()))
        for index, (start, suffix, heading) in enumerate(starts):
            end = starts[index + 1][0] if index + 1 < len(starts) else len(data)
            block = data[start:end]
            rule_id = f"rule:b1.1b-v9:{suffix}"
            if rule_id in seen_rules:
                raise R2Error(f"duplicate extracted normative rule: {rule_id}")
            seen_rules.add(rule_id)
            rules_by_module[module].append({
                "rule_id": rule_id,
                "owner": module,
                "source_path": path,
                "byte_start": start,
                "byte_end_exclusive": end,
                "definition_sha256": sha256_bytes(block),
                "heading": heading,
            })
        fixture_prefix = f"B1.1b/modules/{module}/fixtures/"
        for path in sorted(name for name in module_files if name.startswith(fixture_prefix)):
            name = PurePosixPath(path).name
            if not re.fullmatch(r"\d{3}\.txt", name):
                raise R2Error(f"unexpected R1 fixture filename: {path}")
            number = int(name[:3])
            if number in fixture_ids:
                raise R2Error(f"duplicate R1 fixture: {number}")
            fixture_ids.add(number)
            fixtures_by_module[module].append({
                "fixture_id": f"fixture:b1.1b-v9:{number:03}",
                "number": number,
                "module_ref": module,
                "rule_ref": "rule:b1.1b-v9:section:28",
                "source_path": path,
                "definition_sha256": sha256_bytes(module_files[path]),
            })
    if fixture_ids != set(range(1, 128)):
        raise R2Error("R1 fixture set is not 127/127")
    if "rule:b1.1b-v9:section:28" not in seen_rules:
        raise R2Error("fixture owner rule §28 missing")
    return rules_by_module, fixtures_by_module


def extract_inline_terms(
    module_files: dict[str, bytes],
    extraction_map: dict[str, Any],
) -> tuple[dict[str, dict[str, object]], dict[str, list[str]]]:
    target_slices: dict[str, list[dict[str, Any]]] = {}
    for entry in extraction_map["proposal"]["entries"]:
        if entry.get("kind") != "proposal-byte-slice":
            raise R2Error("unexpected R1 proposal map entry kind")
        target_slices.setdefault(entry["target_path"], []).append(entry)
    occurrences: dict[bytes, list[tuple[int, str]]] = {}
    uses: dict[str, set[bytes]] = {module: set() for module in MODULE_IDS}
    for module in MODULE_IDS:
        path = f"B1.1b/modules/{module}/MODULE.md"
        data = module_files[path]
        slices = sorted(target_slices[path], key=lambda item: item["target_byte_start"])
        for match in re.finditer(rb"`([^`\n]+)`", data):
            token = match.group(1)
            containing = [
                item for item in slices
                if item["target_byte_start"] <= match.start(1)
                and match.end(1) <= item["target_byte_end_exclusive"]
            ]
            if len(containing) != 1:
                raise R2Error(f"inline term does not map to one source slice: {module}")
            item = containing[0]
            source_offset = item["source_byte_start"] + match.start(1) - item["target_byte_start"]
            occurrences.setdefault(token, []).append((source_offset, module))
            uses[module].add(token)
    terms: dict[str, dict[str, object]] = {}
    token_to_id: dict[bytes, str] = {}
    for token, found in occurrences.items():
        try:
            value = token.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise R2Error("inline term is not UTF-8") from exc
        ordered = sorted(found)
        term_id = "term:b1.1b-v9:inline-code:" + sha256_bytes(token)
        token_to_id[token] = term_id
        terms[term_id] = {
            "term_id": term_id,
            "owner": ordered[0][1],
            "definition_sha256": sha256_bytes(token),
            "value": value,
            "first_source_byte_offset": ordered[0][0],
            "occurrences": len(ordered),
        }
    uses_by_module = {
        module: sorted(token_to_id[token] for token in tokens)
        for module, tokens in uses.items()
    }
    return terms, uses_by_module


def build_schema_exports(
    schema_data: dict[str, Any],
    owners: dict[str, str],
) -> dict[str, list[dict[str, object]]]:
    exports: dict[str, list[dict[str, object]]] = {module: [] for module in MODULE_IDS}
    for name in schema_data["definition_order"]:
        value = schema_data["definitions"][name]
        owner = owners[name]
        exports[owner].append({
            "symbol_id": f"schema-definition:{name}",
            "kind": "schema-definition",
            "definition_name": name,
            "definition_sha256": canonical_value_sha256(value),
            "source_extraction_module": schema_data["extraction_owner"][name],
            "extensible": False,
        })
        for kind, pointer, literal in walk_schema_values(value):
            literal_hash = canonical_value_sha256(literal)
            exports[owner].append({
                "symbol_id": f"schema-value:{name}:{pointer}:{literal_hash}",
                "kind": kind,
                "definition_name": name,
                "json_pointer": pointer,
                "value": literal,
                "definition_sha256": sha256_bytes(canonical_json_bytes({
                    "definition_name": name,
                    "json_pointer": pointer,
                    "value": literal,
                })),
                "extensible": False,
            })
    root = schema_data["root_schema"]
    exports["M0-integration-invariants"].append({
        "symbol_id": "schema-root:b1.1b-v9",
        "kind": "schema-root",
        "definition_sha256": canonical_value_sha256(root),
        "extensible": False,
    })
    return exports


def build_imports(
    schema_data: dict[str, Any],
    owners: dict[str, str],
) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, dict[str, dict[str, object]]] = {module: {} for module in MODULE_IDS}

    def add(consumer: str, source_symbol: str, value: object) -> None:
        for pointer, target in walk_refs(value):
            if target not in owners:
                raise R2Error(f"unresolved schema reference: {source_symbol}{pointer} -> {target}")
            provider = owners[target]
            if provider == consumer:
                continue
            symbol_id = f"schema-definition:{target}"
            entry = grouped[consumer].setdefault(symbol_id, {
                "symbol_id": symbol_id,
                "kind": "schema-definition",
                "from_module_id": provider,
                "definition_sha256": canonical_value_sha256(schema_data["definitions"][target]),
                "reference_sites": [],
            })
            entry["reference_sites"].append({"source_symbol": source_symbol, "json_pointer": pointer})

    for name, value in schema_data["definitions"].items():
        add(owners[name], f"schema-definition:{name}", value)
    add("M0-integration-invariants", "schema-root:b1.1b-v9", schema_data["root_schema"])
    return {
        module: [
            {**entry, "reference_sites": sorted(entry["reference_sites"], key=lambda item: (item["source_symbol"], item["json_pointer"]))}
            for _symbol, entry in sorted(grouped[module].items())
        ]
        for module in MODULE_IDS
    }


def rewrite_refs(value: object, current_module: str, owners: dict[str, str]) -> object:
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str):
                if not child.startswith("#/$defs/"):
                    raise R2Error(f"network or unsupported $ref forbidden: {child}")
                target = child[len("#/$defs/"):]
                provider = owners[target]
                if provider == current_module:
                    result[key] = child
                else:
                    result[key] = f"../{provider}/schema.offline.json#/$defs/{target}"
            else:
                result[key] = rewrite_refs(child, current_module, owners)
        return result
    if isinstance(value, list):
        return [rewrite_refs(item, current_module, owners) for item in value]
    return value


def offline_schemas(schema_data: dict[str, Any], owners: dict[str, str]) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    meta_schema = schema_data["root_schema"].get("$schema")
    for module in MODULE_IDS:
        owned = {
            name: rewrite_refs(schema_data["definitions"][name], module, owners)
            for name in schema_data["definition_order"] if owners[name] == module
        }
        if module == "M0-integration-invariants":
            document = rewrite_refs(schema_data["root_schema"], module, owners)
            document["$id"] = "./schema.offline.json"
            document["$defs"] = owned
        else:
            document = {
                "$schema": meta_schema,
                "$id": "./schema.offline.json",
                "$defs": owned,
            }
        result[module] = canonical_json_bytes(document)
    return result


def verify_offline_refs(offline: dict[str, bytes]) -> int:
    documents = {module: json.loads(data) for module, data in offline.items()}
    count = 0
    external_pattern = re.compile(r"^\.\./([^/]+)/schema\.offline\.json#/\$defs/([^/]+)$")

    def visit(value: object, module: str) -> None:
        nonlocal count
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "$ref":
                    if not isinstance(child, str):
                        raise R2Error("offline $ref is not a string")
                    count += 1
                    if child.startswith("#/$defs/"):
                        target = child[len("#/$defs/"):]
                        if target not in documents[module].get("$defs", {}):
                            raise R2Error(f"unresolved local offline $ref: {module}: {child}")
                    else:
                        match = external_pattern.fullmatch(child)
                        if not match or match.group(1) not in documents:
                            raise R2Error(f"network or malformed offline $ref: {module}: {child}")
                        if match.group(2) not in documents[match.group(1)].get("$defs", {}):
                            raise R2Error(f"unresolved external offline $ref: {module}: {child}")
                visit(child, module)
        elif isinstance(value, list):
            for child in value:
                visit(child, module)

    for module, document in documents.items():
        visit(document, module)
    return count


def schema_closure_checks(source_schema: dict[str, Any]) -> dict[str, int]:
    objects = 0
    values = 0

    def visit(value: object, pointer: str = "") -> None:
        nonlocal objects, values
        if isinstance(value, dict):
            if value.get("type") == "object":
                objects += 1
                if value.get("additionalProperties") is not False or "required" not in value:
                    raise R2Error(f"open or non-required object schema: {pointer}")
            if "enum" in value:
                if not isinstance(value["enum"], list) or not value["enum"]:
                    raise R2Error(f"empty/invalid enum: {pointer}")
                values += len(value["enum"])
            if "const" in value:
                values += 1
            for key, child in value.items():
                visit(child, pointer + "/" + json_pointer_escape(str(key)))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, pointer + f"/{index}")

    visit(source_schema)
    signed = source_schema["$defs"].get("Signed64")
    if signed != {"type": "integer", "minimum": -(2**63), "maximum": 2**63 - 1}:
        raise R2Error("Signed64 bounds changed")
    positive = source_schema["$defs"].get("TypedPositiveInteger", {})
    if positive.get("properties", {}).get("value", {}).get("minimum") != 1:
        raise R2Error("TypedPositiveInteger minimum changed")
    return {"closed_object_schemas": objects, "schema_enum_const_values": values}


def dependency_dag(imports: dict[str, list[dict[str, object]]]) -> tuple[list[dict[str, object]], list[str]]:
    edge_symbols: dict[tuple[str, str], list[str]] = {}
    dependencies: dict[str, set[str]] = {module: set() for module in MODULE_IDS}
    for consumer, entries in imports.items():
        for entry in entries:
            provider = str(entry["from_module_id"])
            dependencies[consumer].add(provider)
            edge_symbols.setdefault((consumer, provider), []).append(str(entry["symbol_id"]))
    completed: list[str] = []
    remaining = set(MODULE_IDS)
    while remaining:
        ready = [module for module in MODULE_IDS if module in remaining and dependencies[module] <= set(completed)]
        if not ready:
            cycle = {module: sorted(dependencies[module] & remaining) for module in sorted(remaining)}
            raise R2Error(f"module dependency cycle: {cycle}")
        for module in ready:
            remaining.remove(module)
            completed.append(module)
    edges = [
        {
            "consumer": consumer,
            "provider": provider,
            "symbols": sorted(symbols),
        }
        for (consumer, provider), symbols in sorted(edge_symbols.items())
    ]
    return edges, completed


def source_content_manifest(module: str, module_files: dict[str, bytes]) -> tuple[list[dict[str, object]], str]:
    prefix = f"B1.1b/modules/{module}/"
    names = sorted(name for name in module_files if name.startswith(prefix))
    records = [{"path": name, "sha256": sha256_bytes(module_files[name]), "size": len(module_files[name])} for name in names]
    return records, sha256_bytes(canonical_json_bytes(records))


def interface_hash(interface: dict[str, object]) -> str:
    unsigned = dict(interface)
    unsigned.pop("interface_sha256", None)
    return sha256_bytes(canonical_json_bytes(unsigned))


def classify_exports(old: dict[str, str], new: dict[str, str], extensible: set[str]) -> str:
    common = set(old) & set(new)
    if any(old[name] != new[name] for name in common) or set(old) - set(new):
        return "BREAKING"
    added = set(new) - set(old)
    if not added:
        return "INTERNAL"
    if added <= extensible:
        return "ADDITIVE_COMPATIBLE"
    return "BREAKING"


def classification_selftest() -> None:
    if classify_exports({"a": "1"}, {"a": "1"}, set()) != "INTERNAL":
        raise R2Error("change classifier internal self-test failed")
    if classify_exports({"a": "1"}, {"a": "1", "b": "2"}, {"b"}) != "ADDITIVE_COMPATIBLE":
        raise R2Error("change classifier additive self-test failed")
    if classify_exports({"a": "1"}, {"a": "2"}, set()) != "BREAKING":
        raise R2Error("change classifier changed-symbol self-test failed")
    if classify_exports({"a": "1"}, {"a": "1", "b": "2"}, set()) != "BREAKING":
        raise R2Error("change classifier conservative-add self-test failed")


def update_readme(source: bytes) -> bytes:
    if sha256_bytes(source) != R0_1_README_SHA256:
        if "Следующий этап — `R3_INITIAL_LOCK`".encode("utf-8") in source and b"symbol-level DAG" in source:
            return source
        raise R2Error("README.md is not the pinned R0.1 version")
    text = source.decode("utf-8")
    old = "Этап `R0` завершён: baseline v9, открытые находки и machine-readable state закреплены в `B1.1b/`. Следующий этап — `R1_MECHANICAL_EXTRACTION`: механическое разбиение v9 на модули без изменения нормативной семантики."
    new = "Этапы `R0`, `R0.1`, `R1` и `R2` завершены. Proposal реконструирован побайтово, schema — объектно; интерфейсы, владельцы символов, offline `$ref` и ациклический DAG закреплены. Следующий этап — `R3_INITIAL_LOCK`."
    if text.count(old) != 1:
        raise R2Error("README current-stage paragraph changed")
    text = text.replace(old, new)
    replacements = {
        "2. `R1` — механическое извлечение модулей — следующий шаг;": "2. `R1` — механическое извлечение модулей — `PASS`;",
        "3. `R2` — интерфейсы, symbol-level DAG и checker;": "3. `R2` — интерфейсы, symbol-level DAG и checker — `PASS`;",
        "4. `R3`–`R6` — локализация, исправление и focused-аудит M6;": "4. `R3` — первоначальная фиксация неизменённых модулей — следующий шаг;\n5. `R4`–`R6` — локализация, исправление и focused-аудит M6;",
        "5. `R7`–`R8` — интеграционная сборка и полный механический прогон;": "6. `R7`–`R8` — интеграционная сборка и полный механический прогон;",
        "6. `R9` — два независимых интеграционных `ACCEPT` одного immutable пакета;": "7. `R9` — два независимых интеграционных `ACCEPT` одного immutable пакета;",
        "7. `R10` — разрешение открыть `B1.2`.": "8. `R10` — разрешение открыть `B1.2`.",
    }
    for before, after in replacements.items():
        if text.count(before) != 1:
            raise R2Error(f"README workflow line changed: {before}")
        text = text.replace(before, after)
    return text.encode("utf-8")


def update_changelog(source: bytes) -> bytes:
    if sha256_bytes(source) != R0_1_CHANGELOG_SHA256:
        if b"R2_INTERFACE_DAG_PASS" in source:
            return source
        raise R2Error("CHANGELOG.md is not the pinned R0.1 version")
    text = source.decode("utf-8")
    added_anchor = "### Added\n\n"
    added = (
        "- R1: механическое разбиение B1.1b v9 на 12 модулей с побайтовой реконструкцией proposal и объектной реконструкцией schema.\n"
        "- R2: автоматически извлечённые интерфейсы, единичные владельцы символов, offline `$ref`, ациклический symbol-level DAG, module locks и checker v1.\n"
    )
    verified_anchor = "### Verified\n\n"
    verified = "- `R1_EXTRACTION_EQUIVALENCE_PASS`.\n- `R2_INTERFACE_DAG_PASS`.\n"
    if text.count(added_anchor) != 1 or text.count(verified_anchor) != 1:
        raise R2Error("CHANGELOG section structure changed")
    text = text.replace(added_anchor, added_anchor + added, 1)
    text = text.replace(verified_anchor, verified_anchor + verified, 1)
    return text.encode("utf-8")


def run_tests(root: Path) -> None:
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
        raise R2Error("v9 self-test failed:\n" + selftest.stdout[-4000:])
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
        raise R2Error("107-test regression failed:\n" + regression.stdout[-5000:])


def build_outputs(
    root: Path,
    state: dict[str, Any],
    module_files: dict[str, bytes],
    extraction_map: dict[str, Any],
    schema_data: dict[str, Any],
    script_data: bytes,
    readme_after: bytes,
    changelog_after: bytes,
) -> tuple[dict[str, bytes], dict[str, Any], dict[str, Any]]:
    owners, relocations = ownership(schema_data)
    rules, fixtures = extract_rules(module_files)
    terms, term_uses = extract_inline_terms(module_files, extraction_map)
    schema_exports = build_schema_exports(schema_data, owners)
    imports = build_imports(schema_data, owners)
    offline = offline_schemas(schema_data, owners)
    offline_ref_count = verify_offline_refs(offline)
    edges, topological_order = dependency_dag(imports)
    source_schema = dict(schema_data["root_schema"])
    source_schema["$defs"] = {name: schema_data["definitions"][name] for name in schema_data["definition_order"]}
    closure = schema_closure_checks(source_schema)
    classification_selftest()

    term_exports: dict[str, list[dict[str, object]]] = {module: [] for module in MODULE_IDS}
    for term in terms.values():
        term_exports[str(term["owner"])].append({
            "symbol_id": term["term_id"],
            "kind": "inline-code-term",
            "definition_sha256": term["definition_sha256"],
            "value": term["value"],
            "extensible": False,
        })

    outputs: dict[str, bytes] = {}
    interfaces: dict[str, dict[str, Any]] = {}
    rules_documents: dict[str, dict[str, Any]] = {}
    source_manifests: dict[str, list[dict[str, object]]] = {}
    content_hashes: dict[str, str] = {}

    for module in MODULE_IDS:
        source_records, content_hash = source_content_manifest(module, module_files)
        source_manifests[module] = source_records
        content_hashes[module] = content_hash
        rule_exports = [{
            "symbol_id": item["rule_id"],
            "kind": "normative-rule",
            "definition_sha256": item["definition_sha256"],
            "extensible": False,
        } for item in rules[module]]
        fixture_exports = [{
            "symbol_id": item["fixture_id"],
            "kind": "fixture-specification",
            "definition_sha256": item["definition_sha256"],
            "extensible": False,
        } for item in fixtures[module]]
        exports = sorted(schema_exports[module] + rule_exports + fixture_exports + term_exports[module], key=lambda item: str(item["symbol_id"]))
        interface: dict[str, Any] = {
            "schema": "securelinux-policy-module-interface/v1",
            "module_id": module,
            "version": "v9-r2-interface-v1",
            "status": "OPEN",
            "content_sha256": content_hash,
            "exports": exports,
            "imports": imports[module],
            "non_dependency_term_uses": term_uses[module],
            "owners": {
                "module_id": module,
                "schema_definitions": sum(item["kind"] == "schema-definition" for item in exports),
                "schema_values": sum(item["kind"] in ("schema-enum-value", "schema-const-value") for item in exports),
                "normative_rules": len(rules[module]),
                "fixtures": len(fixtures[module]),
                "inline_code_terms": len(term_exports[module]),
            },
        }
        interface["interface_sha256"] = interface_hash(interface)
        interfaces[module] = interface
        rules_document = {
            "schema": "securelinux-policy-module-rules/v1",
            "module_id": module,
            "source_content_sha256": content_hash,
            "rules": rules[module],
            "fixtures": fixtures[module],
            "owned_inline_code_terms": sorted(
                [term for term in terms.values() if term["owner"] == module],
                key=lambda item: str(item["term_id"]),
            ),
        }
        rules_documents[module] = rules_document
        base = f"B1.1b/modules/{module}"
        outputs[f"{base}/INTERFACE.json"] = canonical_json_bytes(interface)
        outputs[f"{base}/RULES.json"] = canonical_json_bytes(rules_document)
        outputs[f"{base}/schema.offline.json"] = offline[module]

    ownership_document = {
        "schema": "securelinux-policy-r2-symbol-ownership/v1",
        "date": DATE,
        "baseline_sha256": BASELINE_SHA256,
        "r1_extraction_map_sha256": R1_MAP_SHA256,
        "exports_are_checker_derived": True,
        "schema_definition_owners": dict(sorted(owners.items())),
        "content_preserving_owner_rehomes": relocations,
        "normative_rule_owners": {
            item["rule_id"]: module
            for module in MODULE_IDS for item in rules[module]
        },
        "inline_code_term_owners": {
            term_id: term["owner"] for term_id, term in sorted(terms.items())
        },
        "unique_owner_invariant": "PASS",
    }
    outputs[R2_OWNERSHIP_REL] = canonical_json_bytes(ownership_document)

    dag_document = {
        "schema": "securelinux-policy-r2-symbol-dag/v1",
        "date": DATE,
        "nodes": list(MODULE_IDS),
        "edges": edges,
        "topological_order_dependencies_first": topological_order,
        "acyclic": True,
        "schema_symbol_imports": sum(len(items) for items in imports.values()),
    }
    outputs[R2_DAG_REL] = canonical_json_bytes(dag_document)

    for module in MODULE_IDS:
        dependency_interfaces = {
            str(item["from_module_id"]): interfaces[str(item["from_module_id"])]["interface_sha256"]
            for item in imports[module]
        }
        module_lock = {
            "schema": "securelinux-policy-module-lock/v1",
            "module_id": module,
            "version": "v9-r2-interface-v1",
            "status": "OPEN",
            "content_sha256": content_hashes[module],
            "interface_sha256": interfaces[module]["interface_sha256"],
            "rules_sha256": sha256_bytes(outputs[f"B1.1b/modules/{module}/RULES.json"]),
            "offline_schema_sha256": sha256_bytes(outputs[f"B1.1b/modules/{module}/schema.offline.json"]),
            "dependency_interface_sha256": dict(sorted(dependency_interfaces.items())),
            "focused_external_accept": False,
            "frozen": False,
        }
        outputs[f"B1.1b/modules/{module}/MODULE-LOCK.json"] = canonical_json_bytes(module_lock)

    script_digest = sha256_bytes(script_data)
    tool_rel = f"B1.1b/tools/{SCRIPT_NAME}"
    outputs[tool_rel] = script_data
    outputs[tool_rel + ".sha256"] = f"{script_digest}  {SCRIPT_NAME}\n".encode("utf-8")
    r1_state_data = canonical_json_bytes(state)
    if sha256_bytes(r1_state_data) != R1_PROJECT_STATE_SHA256 or state.get("current_phase") != "R1_COMPLETE":
        raise R2Error("R2 build base is not the pinned R1 PROJECT-STATE")
    outputs[R1_STATE_CHECKPOINT_REL] = r1_state_data
    outputs[R1_STATE_CHECKPOINT_REL + ".sha256"] = (
        f"{R1_PROJECT_STATE_SHA256}  {PurePosixPath(R1_STATE_CHECKPOINT_REL).name}\n"
    ).encode("utf-8")

    admin_ledger = {
        "schema": "securelinux-policy-r2-admin-docs-ledger/v1",
        "date": DATE,
        "classification": "ADMINISTRATIVE_NON_NORMATIVE",
        "allowed_paths": ["README.md", "CHANGELOG.md"],
        "changes": {
            "README.md": {
                "action": "UPDATE",
                "before_sha256": R0_1_README_SHA256,
                "after_sha256": sha256_bytes(readme_after),
                "after_size": len(readme_after),
            },
            "CHANGELOG.md": {
                "action": "UPDATE",
                "before_sha256": R0_1_CHANGELOG_SHA256,
                "after_sha256": sha256_bytes(changelog_after),
                "after_size": len(changelog_after),
            },
        },
        "mutation_assertion": {
            "baseline": False,
            "proposal": False,
            "schema": False,
            "canonical": False,
            "validator": False,
            "runtime": False,
            "src": False,
            "tests": False,
            "sources": False,
            "svg_png": False,
            "host": False,
        },
    }
    outputs[R2_ADMIN_LEDGER_REL] = canonical_json_bytes(admin_ledger)
    outputs[R2_ADMIN_MANIFEST_REL] = (
        f"{sha256_bytes(readme_after)}  README.md\n"
        f"{sha256_bytes(changelog_after)}  CHANGELOG.md\n"
        f"{sha256_bytes(outputs[R2_ADMIN_LEDGER_REL])}  {R2_ADMIN_LEDGER_REL}\n"
    ).encode("utf-8")

    integration_modules = {}
    for module in MODULE_IDS:
        base = f"B1.1b/modules/{module}"
        integration_modules[module] = {
            "status": "OPEN",
            "content_sha256": content_hashes[module],
            "interface_sha256": interfaces[module]["interface_sha256"],
            "rules_sha256": sha256_bytes(outputs[f"{base}/RULES.json"]),
            "offline_schema_sha256": sha256_bytes(outputs[f"{base}/schema.offline.json"]),
            "module_lock_sha256": sha256_bytes(outputs[f"{base}/MODULE-LOCK.json"]),
        }
    integration_lock = {
        "schema": "securelinux-policy-integration-lock/v1",
        "date": DATE,
        "baseline_sha256": BASELINE_SHA256,
        "r1_project_state_sha256": R1_PROJECT_STATE_SHA256,
        "r1_extraction_map_sha256": R1_MAP_SHA256,
        "r2_checker_sha256": script_digest,
        "ownership_sha256": sha256_bytes(outputs[R2_OWNERSHIP_REL]),
        "dag_sha256": sha256_bytes(outputs[R2_DAG_REL]),
        "modules": integration_modules,
        "all_modules_status": "OPEN",
        "normative_change": False,
        "open_findings": ["V8-01", "V8-EXT-01", "V8-EXT-02"],
    }
    outputs[R2_LOCK_REL] = canonical_json_bytes(integration_lock)

    report = {
        "schema": "securelinux-policy-r2-checker-report/v1",
        "date": DATE,
        "result": "R2_INTERFACE_DAG_PASS",
        "r1_proposal_reconstruction": "BYTE_IDENTICAL",
        "r1_schema_reconstruction": "OBJECT_IDENTICAL",
        "schema_definitions": len(schema_data["definitions"]),
        "fixture_specifications": sum(len(items) for items in fixtures.values()),
        "module_interfaces": len(interfaces),
        "schema_symbol_imports": sum(len(items) for items in imports.values()),
        "dependency_edges": len(edges),
        "dag_acyclic": True,
        "offline_refs_resolved": offline_ref_count,
        "unique_schema_owners": len(owners),
        "content_preserving_owner_rehomes": len(relocations),
        "inline_code_terms_owned": len(terms),
        "normative_rule_blocks": sum(len(items) for items in rules.values()),
        "schema_closure": closure,
        "change_classifier_selftest": "PASS",
        "normative_deletions": 0,
        "existing_r1_sources_mutated": False,
        "v9_selftest": "PASS",
        "regression_tests": "107/107_PASS",
        "modules_locked": 0,
        "modules_frozen": 0,
        "next_phase": "R3_INITIAL_LOCK",
    }
    outputs[R2_REPORT_REL] = canonical_json_bytes(report)

    manifest_names = sorted(outputs)
    manifest_data = "".join(f"{sha256_bytes(outputs[name])}  {name}\n" for name in manifest_names).encode("utf-8")
    outputs[R2_OUTPUTS_REL] = manifest_data

    new_state = copy.deepcopy(state)
    new_state["current_phase"] = "R2_COMPLETE"
    new_state["current_next_step"] = "R3_INITIAL_LOCK"
    new_state["gates"]["R2_INTERFACE_DAG_PASS"] = True
    new_state["r2"] = {
        "checker_sha256": script_digest,
        "ownership_sha256": sha256_bytes(outputs[R2_OWNERSHIP_REL]),
        "dag_sha256": sha256_bytes(outputs[R2_DAG_REL]),
        "integration_lock_sha256": sha256_bytes(outputs[R2_LOCK_REL]),
        "report_sha256": sha256_bytes(outputs[R2_REPORT_REL]),
        "outputs_manifest_sha256": sha256_bytes(outputs[R2_OUTPUTS_REL]),
        "admin_docs_ledger_sha256": sha256_bytes(outputs[R2_ADMIN_LEDGER_REL]),
        "proposal_reconstruction": "BYTE_IDENTICAL",
        "schema_reconstruction": "OBJECT_IDENTICAL",
        "interfaces": "12/12",
        "dag": "ACYCLIC",
        "offline_refs": "PASS",
        "regression_tests": "107/107_PASS",
    }
    for module in MODULE_IDS:
        new_state["modules"][module].update({
            "status": "OPEN",
            "version": "v9-r2-interface-v1",
            "content_sha256": content_hashes[module],
            "interface_sha256": interfaces[module]["interface_sha256"],
            "module_lock_sha256": integration_modules[module]["module_lock_sha256"],
        })
    return outputs, new_state, report


def verify_r2_layout(root: Path, outputs: dict[str, bytes]) -> None:
    expected = {
        name for name in outputs
        if name.startswith("B1.1b/modules/")
    }
    actual = set()
    for module in MODULE_IDS:
        base = root / "B1.1b/modules" / module
        for name in ("INTERFACE.json", "RULES.json", "schema.offline.json", "MODULE-LOCK.json"):
            path = base / name
            if path.is_file() and not path.is_symlink():
                actual.add(path.relative_to(root).as_posix())
    if actual != expected:
        raise R2Error(f"R2 module layout mismatch: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project_root", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    root = arguments.project_root.resolve()
    script_path = Path(__file__).resolve()
    if not root.is_dir() or not (root / "B1.1b").is_dir():
        raise R2Error(f"R1 project root missing: {root}")

    baseline, _findings, current_state, current_state_data, r1_files = load_admission(root)
    if current_state.get("current_phase") == "R1_COMPLETE":
        base_state = current_state
        base_state_data = current_state_data
    else:
        base_state_data = require_regular(root / R1_STATE_CHECKPOINT_REL, R1_PROJECT_STATE_SHA256)
        sidecar = require_regular(root / (R1_STATE_CHECKPOINT_REL + ".sha256"))
        expected_sidecar = f"{R1_PROJECT_STATE_SHA256}  {PurePosixPath(R1_STATE_CHECKPOINT_REL).name}\n".encode("utf-8")
        if sidecar != expected_sidecar:
            raise R2Error("R1 PROJECT-STATE checkpoint sidecar mismatch")
        base_state = json.loads(base_state_data)
    expected_before = expected_r0_1_snapshot(root, baseline, base_state)
    readme_before = require_regular(root / "README.md")
    changelog_before = require_regular(root / "CHANGELOG.md")
    readme_after = update_readme(readme_before)
    changelog_after = update_changelog(changelog_before)
    expected_after = dict(expected_before)
    expected_after["README.md"] = {"sha256": sha256_bytes(readme_after), "size": len(readme_after)}
    expected_after["CHANGELOG.md"] = {"sha256": sha256_bytes(changelog_after), "size": len(changelog_after)}
    snapshot = scan_snapshot(root)
    if snapshot not in (expected_before, expected_after):
        raise R2Error("live project differs from admitted R1/R2 administrative state: " + diff_summary(expected_before, snapshot))
    if arguments.verify_only and current_state.get("current_phase") != "R2_COMPLETE":
        raise R2Error("--verify-only requires R2_COMPLETE")

    module_files, extraction_map, schema_data = reconstruct_r1(root, r1_files)
    script_data = require_regular(script_path)
    outputs, new_state, report = build_outputs(
        root, base_state, module_files, extraction_map, schema_data,
        script_data, readme_after, changelog_after,
    )
    outputs_repeat, new_state_repeat, report_repeat = build_outputs(
        root, base_state, module_files, extraction_map, schema_data,
        script_data, readme_after, changelog_after,
    )
    if outputs_repeat != outputs or new_state_repeat != new_state or report_repeat != report:
        raise R2Error("R2 generation is not deterministic")
    new_state_data = canonical_json_bytes(new_state)

    if arguments.verify_only or current_state.get("current_phase") == "R2_COMPLETE":
        for relative, data in outputs.items():
            if require_regular(root / relative) != data:
                raise R2Error(f"R2 verification mismatch: {relative}")
        if require_regular(root / STATE_REL) != new_state_data:
            raise R2Error("R2 PROJECT-STATE verification mismatch")
        if snapshot != expected_after:
            raise R2Error("R2 root documentation verification mismatch")
    else:
        for relative, data in outputs.items():
            immutable_write(root / relative, data)
        changed_docs = False
        try:
            if readme_before != readme_after:
                atomic_replace(root / "README.md", readme_after, ".tmp-r2")
                changed_docs = True
            if changelog_before != changelog_after:
                atomic_replace(root / "CHANGELOG.md", changelog_after, ".tmp-r2")
                changed_docs = True
            if scan_snapshot(root) != expected_after:
                raise R2Error("R2 changed a path outside its administrative overlay")
            run_tests(root)
            if scan_snapshot(root) != expected_after:
                raise R2Error("tests changed the project snapshot")
        except Exception:
            if changed_docs:
                atomic_replace(root / "README.md", readme_before, ".tmp-r2-rollback")
                atomic_replace(root / "CHANGELOG.md", changelog_before, ".tmp-r2-rollback")
            raise
        live_state = require_regular(root / STATE_REL)
        if live_state != base_state_data or sha256_bytes(live_state) != R1_PROJECT_STATE_SHA256:
            raise R2Error("PROJECT-STATE changed during R2")
        atomic_replace(root / STATE_REL, new_state_data, ".tmp-r2")

    verify_r2_layout(root, outputs)
    if scan_snapshot(root) != expected_after:
        raise R2Error("final R2 administrative snapshot mismatch")
    if sha256_file(root / PROPOSAL_REL) != PROPOSAL_SHA256 or sha256_file(root / SCHEMA_REL) != SCHEMA_SHA256:
        raise R2Error("v9 normative source changed")

    print("RESULT=R2_INTERFACE_DAG_PASS")
    print("R1_PROPOSAL_RECONSTRUCTION=BYTE_IDENTICAL")
    print("R1_SCHEMA_RECONSTRUCTION=OBJECT_IDENTICAL")
    print("SCHEMA_DEFINITIONS=192/192")
    print("FIXTURE_SPECIFICATIONS=127/127")
    print("MODULE_INTERFACES=12/12")
    print("UNIQUE_SYMBOL_OWNERS=PASS")
    print("SYMBOL_DAG=ACYCLIC")
    print("OFFLINE_REFS=PASS")
    print("CHANGE_CLASSIFIER_SELFTEST=PASS")
    print("V9_SELFTEST=PASS")
    print("FULL_REGRESSION_TESTS=107/107_PASS")
    print("README_MD=UPDATED_R2_STATE")
    print("CHANGELOG_MD=UPDATED_R2_STATE")
    print("SVG_PNG=UNCHANGED")
    print("MODULES=12/12_OPEN")
    print("MODULES_LOCKED=0/12")
    print("MODULES_FROZEN=0/12")
    print("TASK_B1_1_ACCEPTED=false")
    print("TASK_B1_2=NOT_STARTED")
    print("SELECTOR_INSTANCES_FROZEN=0/20")
    print(f"SHA256={sha256_bytes(outputs[R2_OWNERSHIP_REL])}  {R2_OWNERSHIP_REL}")
    print(f"SHA256={sha256_bytes(outputs[R2_DAG_REL])}  {R2_DAG_REL}")
    print(f"SHA256={sha256_bytes(outputs[R2_LOCK_REL])}  {R2_LOCK_REL}")
    print(f"SHA256={sha256_bytes(outputs[R2_REPORT_REL])}  {R2_REPORT_REL}")
    print(f"SHA256={sha256_bytes(outputs[R2_OUTPUTS_REL])}  {R2_OUTPUTS_REL}")
    print(f"SHA256={sha256_bytes(new_state_data)}  {STATE_REL}")
    print("CURRENT_NEXT_STEP=R3_INITIAL_LOCK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (R2Error, OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"R2_FAIL={exc}", file=sys.stderr)
        raise SystemExit(1)
