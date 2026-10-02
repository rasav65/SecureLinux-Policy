#!/usr/bin/env python3
"""R3: lock unchanged B1.1b modules without changing v9 semantics.

The installer/checker admits only the pinned user R2 state, verifies the R2
checker, v9 self-test and 107-test regression suite, then changes lifecycle
metadata only:

* M0, M1, M2, M3, M4, M5 and M7 -> LOCKED;
* M6.1..M6.5 remain OPEN;
* every module remains not frozen and without external ACCEPT;
* exported symbols, module source, rules, schemas and fixtures remain unchanged;
* README.md and CHANGELOG.md receive a recorded administrative overlay;
* SVG and PNG files are not touched.

The script is idempotent.  A repeated run verifies the exact R3 result.
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


SCRIPT_NAME = "SecureLinux-Policy-TASK-B1.1-R3-initial-lock-20260813.py"
DATE = "2026-08-13"

BASELINE_SHA256 = "3daac5da494cabb9551b269dcb56df83469ee79491a83c3445bcd33bae0274e3"
OPEN_FINDINGS_SHA256 = "5b9bd4da4cb22aad60e75b79851bc8b58b707b6695cceca47dcc47e1540df53a"
R2_STATE_SHA256 = "45ad7182cc61b7665dfa048df59ee83c6017c27f16bfce5d43c7c6fb72319fef"
R2_CHECKER_SHA256 = "c759abffcf3817267fab081dc491242d929b27a1fdf803e35d10927f36c88566"
R2_OWNERSHIP_SHA256 = "ec960b66183e76fb275b09bafb745ef95df54d58d31fcb323a0aee1e1d7b1f9d"
R2_DAG_SHA256 = "ea1b4035a3c7473f7a4974b2aa4071a8369927bd7432d6ebf57eec4596421369"
R2_INTEGRATION_LOCK_SHA256 = "c2b2b87eae2f8249c6cd29163b32ee13cc0bb1c461196b8683912727649658e1"
R2_REPORT_SHA256 = "4a9687fbbd5a018d2fa64439bb75cb2072b0fe5b3fbc8cc233d2f49c77dee6f4"
R2_OUTPUTS_SHA256 = "30480a4461a6185800538e2861d08200103e6a8365dcca882689533aef041603"
R1_PROJECT_STATE_SHA256 = "80d0a88f317aa66ac2218b91cd357317c669bb6135c9374fb144db698ff6bb63"
R1_MAP_SHA256 = "fcf313e78bea73798604c37a3ce1fadc7d30188ebaa7edc26db15c43f45ec410"

PROPOSAL_REL = "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-proposal-v9-20260813.md"
PROPOSAL_SHA256 = "bb359806252163cc6cf29f3499ff828891d3ce11104fe9934704c7022f14abfb"
SCHEMA_REL = "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-schema-v9-20260813.json"
SCHEMA_SHA256 = "2304b192d4f3c8e4fde056a42970ae4b2200df28012019445023c704c6375995"
SELFTEST_REL = "docs/SecureLinux-Policy-TASK-B1.1b-v9-selftest-20260813.py"

STATE_REL = "B1.1b/state/PROJECT-STATE.json"
FINDINGS_REL = "B1.1b/state/OPEN-FINDINGS.json"
R2_CHECKER_REL = "B1.1b/tools/SecureLinux-Policy-TASK-B1.1-R2-interface-dag-checker-v1-20260813.py"
R2_OWNERSHIP_REL = "B1.1b/state/R2-OWNERSHIP.json"
R2_DAG_REL = "B1.1b/integration/R2-SYMBOL-DAG.json"
INTEGRATION_LOCK_REL = "B1.1b/integration/INTEGRATION.lock.json"
R2_REPORT_REL = "B1.1b/reports/R2-CHECKER-REPORT.json"
R2_OUTPUTS_REL = "B1.1b/reports/R2-OUTPUTS.sha256"

R2_STATE_CHECKPOINT_REL = "B1.1b/state/R2-PROJECT-STATE.json"
R3_LOCK_STATE_REL = "B1.1b/state/R3-LOCKED-MODULES.json"
R3_LEDGER_REL = "B1.1b/state/R3-LIFECYCLE-TRANSITION-LEDGER.json"
R3_REPORT_REL = "B1.1b/reports/R3-INITIAL-LOCK-REPORT.json"
R3_OUTPUTS_REL = "B1.1b/reports/R3-OUTPUTS.sha256"
R3_ADMIN_LEDGER_REL = "B1.1b/state/R3-ADMIN-DOCS-LEDGER.json"
R3_ADMIN_MANIFEST_REL = "B1.1b/state/R3-ADMIN-DOCS.sha256"

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

LOCKED_MODULES = (
    "M0-integration-invariants",
    "M1-primitives",
    "M2-outcomes",
    "M3-source-set",
    "M4-filters",
    "M5-pipeline",
    "M7-selector-mapping",
)

OPEN_MODULES = (
    "M6.1-registries",
    "M6.2-operation-algebra",
    "M6.3-enumeration-domains",
    "M6.4-population-matrix",
    "M6.5-behavior-trace",
)

EXPECTED_FINDING_OWNERS = {
    "V8-01": ("M6.2-operation-algebra",),
    "V8-EXT-01": ("M6.3-enumeration-domains",),
    "V8-EXT-02": ("M6.3-enumeration-domains", "M6.4-population-matrix"),
}


class R3Error(RuntimeError):
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


def interface_hash(interface: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(interface)
    unsigned.pop("interface_sha256", None)
    return canonical_value_sha256(unsigned)


def require_regular(path: Path, expected_sha256: str | None = None) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise R3Error(f"missing or unsafe regular file: {path}")
    data = path.read_bytes()
    if expected_sha256 is not None and sha256_bytes(data) != expected_sha256:
        raise R3Error(f"SHA-256 mismatch: {path}")
    return data


def atomic_replace(path: Path, data: bytes, suffix: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + suffix)
    if temporary.exists():
        raise R3Error(f"stale temporary file: {temporary}")
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def safe_relative_name(name: str) -> bool:
    pure = PurePosixPath(name)
    return bool(name) and not pure.is_absolute() and all(part not in ("", ".", "..") for part in pure.parts)


def parse_manifest(data: bytes, label: str) -> list[tuple[str, str]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise R3Error(f"manifest is not UTF-8: {label}") from exc
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for number, line in enumerate(lines, 1):
        if len(line) < 67 or line[64:66] not in ("  ", " *"):
            raise R3Error(f"invalid manifest line: {label}:{number}")
        digest = line[:64].lower()
        name = line[66:]
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise R3Error(f"invalid manifest digest: {label}:{number}")
        if not safe_relative_name(name) or name in seen:
            raise R3Error(f"unsafe or duplicate manifest path: {label}:{number}: {name!r}")
        seen.add(name)
        result.append((digest, name))
    return result


def verify_manifest(root: Path, relative: str, expected_sha256: str) -> int:
    data = require_regular(root / relative, expected_sha256)
    records = parse_manifest(data, relative)
    for digest, name in records:
        if sha256_file(root / name) != digest:
            raise R3Error(f"manifest target mismatch: {relative}: {name}")
    return len(records)


def scan_project(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            relative = path.relative_to(root)
            if relative.parts[0] in (".git", "B1.1b"):
                continue
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise R3Error(f"project link forbidden: {relative.as_posix()}")
            if stat.S_ISDIR(metadata.st_mode):
                visit(path)
            elif stat.S_ISREG(metadata.st_mode):
                result[relative.as_posix()] = {"sha256": sha256_file(path), "size": metadata.st_size}
            else:
                raise R3Error(f"project special entry forbidden: {relative.as_posix()}")

    visit(root)
    return result


def changed_snapshot_paths(before: dict[str, object], after: dict[str, object]) -> set[str]:
    return {
        name for name in set(before) | set(after)
        if before.get(name) != after.get(name)
    }


def run_checked(command: list[str], root: Path, marker: str, label: str) -> str:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0 or marker not in result.stdout:
        raise R3Error(f"{label} failed:\n" + result.stdout[-6000:])
    return result.stdout


def run_r2_verify(root: Path) -> None:
    checker = root / R2_CHECKER_REL
    require_regular(checker, R2_CHECKER_SHA256)
    run_checked(
        [sys.executable, str(checker), str(root), "--verify-only"],
        root,
        "RESULT=R2_INTERFACE_DAG_PASS",
        "R2 checker verification",
    )


def run_tests(root: Path) -> None:
    run_checked(
        [sys.executable, str(root / SELFTEST_REL), str(root)],
        root,
        "RESULT=B1_1B_V9_SELFTEST_PASS",
        "v9 self-test",
    )
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    match = re.search(r"Ran\s+(\d+)\s+tests?", result.stdout)
    count = int(match.group(1)) if match else None
    if result.returncode != 0 or count != 107 or not re.search(r"^OK$", result.stdout, re.MULTILINE):
        raise R3Error("107-test regression failed:\n" + result.stdout[-6000:])


def verify_pinned_r2_artifacts(root: Path, state: dict[str, Any]) -> None:
    expected = {
        R2_OWNERSHIP_REL: R2_OWNERSHIP_SHA256,
        R2_DAG_REL: R2_DAG_SHA256,
        R2_REPORT_REL: R2_REPORT_SHA256,
    }
    for relative, digest in expected.items():
        require_regular(root / relative, digest)
    r2 = state.get("r2", {})
    claims = {
        "checker_sha256": R2_CHECKER_SHA256,
        "ownership_sha256": R2_OWNERSHIP_SHA256,
        "dag_sha256": R2_DAG_SHA256,
        "integration_lock_sha256": R2_INTEGRATION_LOCK_SHA256,
        "report_sha256": R2_REPORT_SHA256,
        "outputs_manifest_sha256": R2_OUTPUTS_SHA256,
    }
    for key, value in claims.items():
        if r2.get(key) != value:
            raise R3Error(f"R2 state claim mismatch: {key}")
    if state.get("gates", {}).get("R2_INTERFACE_DAG_PASS") is not True:
        raise R3Error("R2 gate is not PASS")
    project_gate = state.get("project_gate", {})
    if project_gate != {
        "b1_1a": "ACCEPT",
        "b1_1b": "NOT_ACCEPTED",
        "selector_instances_frozen": "0/20",
        "task_b1_1": "NOT_ACCEPTED",
        "task_b1_2": "NOT_STARTED",
    }:
        raise R3Error("project gate changed before R3")


def load_base_state(root: Path, current_data: bytes) -> tuple[dict[str, Any], bool]:
    current = json.loads(current_data)
    phase = current.get("current_phase")
    if phase == "R2_COMPLETE":
        if sha256_bytes(current_data) != R2_STATE_SHA256:
            raise R3Error("R2 PROJECT-STATE is not the pinned user checkpoint")
        run_r2_verify(root)
        base_data = current_data
        already_r3 = False
    elif phase == "R3_COMPLETE":
        base_data = require_regular(root / R2_STATE_CHECKPOINT_REL, R2_STATE_SHA256)
        sidecar = require_regular(root / (R2_STATE_CHECKPOINT_REL + ".sha256"))
        expected = f"{R2_STATE_SHA256}  {PurePosixPath(R2_STATE_CHECKPOINT_REL).name}\n".encode("utf-8")
        if sidecar != expected:
            raise R3Error("R2 checkpoint sidecar mismatch")
        already_r3 = True
    else:
        raise R3Error(f"R3 requires R2_COMPLETE or verifies R3_COMPLETE, got {phase!r}")
    base = json.loads(base_data)
    if base.get("current_phase") != "R2_COMPLETE" or base.get("current_next_step") != "R3_INITIAL_LOCK":
        raise R3Error("R2 checkpoint phase changed")
    verify_pinned_r2_artifacts(root, base)
    return base, already_r3


def verify_findings(root: Path) -> dict[str, tuple[str, ...]]:
    document = json.loads(require_regular(root / FINDINGS_REL, OPEN_FINDINGS_SHA256))
    actual: dict[str, tuple[str, ...]] = {}
    for finding in document.get("findings", []):
        finding_id = finding.get("finding_id")
        owners = tuple(finding.get("owners", []))
        if not isinstance(finding_id, str):
            raise R3Error("invalid finding id")
        actual[finding_id] = owners
        if finding.get("status") != "OPEN_FOR_MODULAR_PROOF":
            raise R3Error(f"finding status changed before R3: {finding_id}")
    if actual != EXPECTED_FINDING_OWNERS:
        raise R3Error(f"open finding ownership mismatch: {actual}")
    if set(owner for owners in actual.values() for owner in owners) - set(OPEN_MODULES):
        raise R3Error("a module selected for R3 lock owns an open finding")
    return actual


def validate_interface(document: dict[str, Any], module: str) -> None:
    if document.get("schema") != "securelinux-policy-module-interface/v1":
        raise R3Error(f"interface schema mismatch: {module}")
    if document.get("module_id") != module:
        raise R3Error(f"interface module mismatch: {module}")
    if document.get("status") not in ("OPEN", "LOCKED"):
        raise R3Error(f"interface lifecycle status invalid: {module}")
    if document.get("interface_sha256") != interface_hash(document):
        raise R3Error(f"interface self-hash mismatch: {module}")
    exports = document.get("exports")
    imports = document.get("imports")
    if not isinstance(exports, list) or not isinstance(imports, list):
        raise R3Error(f"interface exports/imports invalid: {module}")
    ids = [entry.get("symbol_id") for entry in exports if isinstance(entry, dict)]
    if len(ids) != len(exports) or len(ids) != len(set(ids)):
        raise R3Error(f"interface exports are not unique: {module}")


def recover_r2_interfaces(root: Path, base_state: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, bytes]]:
    documents: dict[str, dict[str, Any]] = {}
    original_bytes: dict[str, bytes] = {}
    for module in MODULE_IDS:
        path = root / "B1.1b/modules" / module / "INTERFACE.json"
        live = json.loads(require_regular(path))
        validate_interface(live, module)
        original = copy.deepcopy(live)
        original["status"] = "OPEN"
        original["interface_sha256"] = interface_hash(original)
        expected = base_state["modules"][module]
        if original["content_sha256"] != expected.get("content_sha256"):
            raise R3Error(f"module content hash changed: {module}")
        if original["interface_sha256"] != expected.get("interface_sha256"):
            raise R3Error(f"cannot recover pinned R2 interface: {module}")
        documents[module] = original
        original_bytes[module] = canonical_json_bytes(original)
    return documents, original_bytes


def export_digest(interface: dict[str, Any]) -> str:
    exports = {
        str(item["symbol_id"]): str(item["definition_sha256"])
        for item in interface["exports"]
    }
    return canonical_value_sha256(exports)


def provider_interfaces(interface: dict[str, Any], current_interfaces: dict[str, dict[str, Any]]) -> dict[str, str]:
    providers = {
        str(item["from_module_id"])
        for item in interface.get("imports", [])
    }
    if providers - set(MODULE_IDS):
        raise R3Error(f"unknown interface provider: {sorted(providers-set(MODULE_IDS))}")
    return {
        module: str(current_interfaces[module]["interface_sha256"])
        for module in sorted(providers)
    }


def verify_rules_and_fixtures(root: Path, module: str, interface: dict[str, Any]) -> tuple[bytes, bytes, int]:
    base = root / "B1.1b/modules" / module
    rules_data = require_regular(base / "RULES.json")
    offline_data = require_regular(base / "schema.offline.json")
    rules = json.loads(rules_data)
    if rules.get("module_id") != module or rules.get("source_content_sha256") != interface.get("content_sha256"):
        raise R3Error(f"RULES identity/content mismatch: {module}")
    known_rules = {item.get("rule_id") for item in rules.get("rules", [])}
    count = 0
    for fixture in rules.get("fixtures", []):
        if fixture.get("module_ref") != module:
            raise R3Error(f"fixture module_ref mismatch: {module}")
        source_path = fixture.get("source_path")
        if not isinstance(source_path, str) or not safe_relative_name(source_path):
            raise R3Error(f"fixture source path invalid: {module}")
        if sha256_file(root / source_path) != fixture.get("definition_sha256"):
            raise R3Error(f"fixture source hash mismatch: {source_path}")
        # All extracted fixtures point to the shared §28 rule, owned by M0.
        rule_ref = fixture.get("rule_ref")
        if rule_ref != "rule:b1.1b-v9:section:28" and rule_ref not in known_rules:
            raise R3Error(f"fixture rule_ref unresolved: {module}: {rule_ref}")
        count += 1
    return rules_data, offline_data, count


def build_r2_module_lock(
    module: str,
    interface: dict[str, Any],
    interfaces: dict[str, dict[str, Any]],
    rules_data: bytes,
    offline_data: bytes,
) -> dict[str, Any]:
    return {
        "schema": "securelinux-policy-module-lock/v1",
        "module_id": module,
        "version": "v9-r2-interface-v1",
        "status": "OPEN",
        "content_sha256": interface["content_sha256"],
        "interface_sha256": interface["interface_sha256"],
        "rules_sha256": sha256_bytes(rules_data),
        "offline_schema_sha256": sha256_bytes(offline_data),
        "dependency_interface_sha256": provider_interfaces(interface, interfaces),
        "focused_external_accept": False,
        "frozen": False,
    }


def update_readme(source: bytes) -> bytes:
    text = source.decode("utf-8")
    if "Следующий этап — `R4_LOCALIZE_M6`." in text and "7/12 модулей имеют статус `LOCKED`" in text:
        return source
    old = (
        "Этапы `R0`, `R0.1`, `R1` и `R2` завершены. Proposal реконструирован побайтово, "
        "schema — объектно; интерфейсы, владельцы символов, offline `$ref` и ациклический DAG "
        "закреплены. Следующий этап — `R3_INITIAL_LOCK`."
    )
    new = (
        "Этапы `R0`–`R3` завершены: 7/12 модулей имеют статус `LOCKED`; `M6.1`–`M6.5` "
        "остаются `OPEN`, все модули остаются `NOT_FROZEN`. Следующий этап — `R4_LOCALIZE_M6`."
    )
    if text.count(old) != 1:
        raise R3Error("README R2 stage paragraph changed")
    text = text.replace(old, new)
    old_line = "4. `R3` — первоначальная фиксация неизменённых модулей — следующий шаг;"
    new_line = "4. `R3` — первоначальная фиксация неизменённых модулей — `PASS`;"
    if text.count(old_line) != 1:
        raise R3Error("README R3 workflow line changed")
    text = text.replace(old_line, new_line)
    return text.encode("utf-8")


def update_changelog(source: bytes) -> bytes:
    text = source.decode("utf-8")
    if "`R3_INITIAL_LOCK_PASS`" in text:
        return source
    added_anchor = "### Added\n\n"
    changed_anchor = "### Changed\n\n"
    verified_anchor = "### Verified\n\n"
    if text.count(added_anchor) != 1 or text.count(changed_anchor) != 1 or text.count(verified_anchor) != 1:
        raise R3Error("CHANGELOG section structure changed")
    text = text.replace(
        added_anchor,
        added_anchor + "- R3: machine-readable lock set and lifecycle transition ledger for the unchanged modules.\n",
        1,
    )
    text = text.replace(
        changed_anchor,
        changed_anchor + "- R3: M0, M1–M5 and M7 moved from `OPEN` to `LOCKED`; M6.1–M6.5 remain `OPEN`.\n",
        1,
    )
    text = text.replace(verified_anchor, verified_anchor + "- `R3_INITIAL_LOCK_PASS`.\n", 1)
    return text.encode("utf-8")


def build_outputs(
    root: Path,
    base_state: dict[str, Any],
    script_data: bytes,
    readme_before: bytes,
    changelog_before: bytes,
) -> tuple[dict[str, bytes], dict[str, Any], dict[str, Any]]:
    findings = verify_findings(root)
    original_interfaces, _ = recover_r2_interfaces(root, base_state)
    current_interfaces: dict[str, dict[str, Any]] = {}
    interface_outputs: dict[str, bytes] = {}
    for module, original in original_interfaces.items():
        current = copy.deepcopy(original)
        current["status"] = "LOCKED" if module in LOCKED_MODULES else "OPEN"
        current["interface_sha256"] = interface_hash(current)
        validate_interface(current, module)
        current_interfaces[module] = current
        interface_outputs[module] = canonical_json_bytes(current)

    rules_data: dict[str, bytes] = {}
    offline_data: dict[str, bytes] = {}
    fixture_counts: dict[str, int] = {}
    original_locks: dict[str, dict[str, Any]] = {}
    current_locks: dict[str, dict[str, Any]] = {}
    current_lock_bytes: dict[str, bytes] = {}
    for module in MODULE_IDS:
        rules_data[module], offline_data[module], fixture_counts[module] = verify_rules_and_fixtures(
            root, module, original_interfaces[module]
        )
        original_lock = build_r2_module_lock(
            module, original_interfaces[module], original_interfaces,
            rules_data[module], offline_data[module],
        )
        if canonical_value_sha256(original_lock) != base_state["modules"][module]["module_lock_sha256"]:
            raise R3Error(f"cannot reconstruct pinned R2 module lock: {module}")
        original_locks[module] = original_lock
        current_lock = copy.deepcopy(original_lock)
        current_lock["status"] = "LOCKED" if module in LOCKED_MODULES else "OPEN"
        current_lock["interface_sha256"] = current_interfaces[module]["interface_sha256"]
        current_lock["dependency_interface_sha256"] = provider_interfaces(
            current_interfaces[module], current_interfaces
        )
        current_lock["focused_external_accept"] = False
        current_lock["frozen"] = False
        current_locks[module] = current_lock
        current_lock_bytes[module] = canonical_json_bytes(current_lock)

    if sum(fixture_counts.values()) != 127:
        raise R3Error(f"fixture specification count changed: {sum(fixture_counts.values())}/127")

    outputs: dict[str, bytes] = {}
    for module in MODULE_IDS:
        base = f"B1.1b/modules/{module}"
        outputs[f"{base}/INTERFACE.json"] = interface_outputs[module]
        outputs[f"{base}/MODULE-LOCK.json"] = current_lock_bytes[module]

    require_regular(root / INTEGRATION_LOCK_REL)
    # On a repeated run, the current file is R3.  Reconstruct and validate the
    # original R2 integration hash from the pinned state and module locks.
    integration_r2 = {
        "schema": "securelinux-policy-integration-lock/v1",
        "date": DATE,
        "baseline_sha256": base_state["baseline_sha256"],
        "r1_project_state_sha256": R1_PROJECT_STATE_SHA256,
        "r1_extraction_map_sha256": R1_MAP_SHA256,
        "r2_checker_sha256": R2_CHECKER_SHA256,
        "ownership_sha256": R2_OWNERSHIP_SHA256,
        "dag_sha256": R2_DAG_SHA256,
        "modules": {
            module: {
                "status": "OPEN",
                "content_sha256": original_interfaces[module]["content_sha256"],
                "interface_sha256": original_interfaces[module]["interface_sha256"],
                "rules_sha256": sha256_bytes(rules_data[module]),
                "offline_schema_sha256": sha256_bytes(offline_data[module]),
                "module_lock_sha256": canonical_value_sha256(original_locks[module]),
            }
            for module in MODULE_IDS
        },
        "all_modules_status": "OPEN",
        "normative_change": False,
        "open_findings": ["V8-01", "V8-EXT-01", "V8-EXT-02"],
    }
    if canonical_value_sha256(integration_r2) != R2_INTEGRATION_LOCK_SHA256:
        raise R3Error("cannot reconstruct pinned R2 integration lock")

    integration_r3 = copy.deepcopy(integration_r2)
    integration_r3["modules"] = {
        module: {
            "status": current_locks[module]["status"],
            "content_sha256": current_interfaces[module]["content_sha256"],
            "interface_sha256": current_interfaces[module]["interface_sha256"],
            "rules_sha256": sha256_bytes(rules_data[module]),
            "offline_schema_sha256": sha256_bytes(offline_data[module]),
            "module_lock_sha256": sha256_bytes(current_lock_bytes[module]),
        }
        for module in MODULE_IDS
    }
    integration_r3["all_modules_status"] = "MIXED_7_LOCKED_5_OPEN"
    integration_r3["r3_initial_lock"] = {
        "gate": "R3_INITIAL_LOCK_PASS",
        "locked_modules": list(LOCKED_MODULES),
        "open_modules": list(OPEN_MODULES),
        "modules_frozen": 0,
        "r2_integration_lock_sha256": R2_INTEGRATION_LOCK_SHA256,
    }
    outputs[INTEGRATION_LOCK_REL] = canonical_json_bytes(integration_r3)

    transitions: list[dict[str, Any]] = []
    for module in MODULE_IDS:
        before_export_digest = export_digest(original_interfaces[module])
        after_export_digest = export_digest(current_interfaces[module])
        if before_export_digest != after_export_digest:
            raise R3Error(f"R3 changed exported symbols: {module}")
        transitions.append({
            "module_id": module,
            "status_before": "OPEN",
            "status_after": "LOCKED" if module in LOCKED_MODULES else "OPEN",
            "classification": "INTERNAL_LIFECYCLE_ONLY" if module in LOCKED_MODULES else "UNCHANGED",
            "content_sha256": original_interfaces[module]["content_sha256"],
            "exports_sha256_before": before_export_digest,
            "exports_sha256_after": after_export_digest,
            "interface_sha256_before": original_interfaces[module]["interface_sha256"],
            "interface_sha256_after": current_interfaces[module]["interface_sha256"],
            "module_lock_sha256_before": canonical_value_sha256(original_locks[module]),
            "module_lock_sha256_after": sha256_bytes(current_lock_bytes[module]),
            "focused_external_accept": False,
            "frozen": False,
        })
    ledger = {
        "schema": "securelinux-policy-r3-lifecycle-transition-ledger/v1",
        "date": DATE,
        "gate": "R3_INITIAL_LOCK_PASS",
        "baseline_sha256": BASELINE_SHA256,
        "r2_project_state_sha256": R2_STATE_SHA256,
        "r2_integration_lock_sha256": R2_INTEGRATION_LOCK_SHA256,
        "transitions": transitions,
        "invariants": {
            "normative_change": False,
            "exported_symbol_changes": 0,
            "module_source_changes": 0,
            "rules_changes": 0,
            "schema_changes": 0,
            "fixture_changes": 0,
            "open_findings_closed": 0,
            "focused_external_accepts": 0,
            "modules_frozen": 0,
        },
    }
    outputs[R3_LEDGER_REL] = canonical_json_bytes(ledger)

    lock_state = {
        "schema": "securelinux-policy-r3-locked-modules/v1",
        "date": DATE,
        "gate": "R3_INITIAL_LOCK_PASS",
        "locked_modules": {
            module: {
                "content_sha256": current_interfaces[module]["content_sha256"],
                "interface_sha256": current_interfaces[module]["interface_sha256"],
                "exports_sha256": export_digest(current_interfaces[module]),
                "rules_sha256": sha256_bytes(rules_data[module]),
                "offline_schema_sha256": sha256_bytes(offline_data[module]),
                "module_lock_sha256": sha256_bytes(current_lock_bytes[module]),
                "fixture_specifications": fixture_counts[module],
                "focused_external_accept": False,
                "frozen": False,
            }
            for module in LOCKED_MODULES
        },
        "open_modules": list(OPEN_MODULES),
        "open_findings": {
            finding_id: list(owners) for finding_id, owners in sorted(findings.items())
        },
        "m0_rule": "LOCKED_AGAINST_EXACT_V9_IMPORTS; BREAKING_M6_EXPORT_REOPENS_M0",
    }
    outputs[R3_LOCK_STATE_REL] = canonical_json_bytes(lock_state)

    script_digest = sha256_bytes(script_data)
    tool_rel = f"B1.1b/tools/{SCRIPT_NAME}"
    outputs[tool_rel] = script_data
    outputs[tool_rel + ".sha256"] = f"{script_digest}  {SCRIPT_NAME}\n".encode("utf-8")

    base_state_data = canonical_json_bytes(base_state)
    if sha256_bytes(base_state_data) != R2_STATE_SHA256:
        raise R3Error("R2 state checkpoint serialization mismatch")
    outputs[R2_STATE_CHECKPOINT_REL] = base_state_data
    outputs[R2_STATE_CHECKPOINT_REL + ".sha256"] = (
        f"{R2_STATE_SHA256}  {PurePosixPath(R2_STATE_CHECKPOINT_REL).name}\n"
    ).encode("utf-8")

    readme_after = update_readme(readme_before)
    changelog_after = update_changelog(changelog_before)
    admin_ledger = {
        "schema": "securelinux-policy-r3-admin-docs-ledger/v1",
        "date": DATE,
        "classification": "ADMINISTRATIVE_NON_NORMATIVE",
        "allowed_paths": ["README.md", "CHANGELOG.md"],
        "changes": {
            "README.md": {
                "action": "UPDATE",
                "before_sha256": sha256_bytes(readme_before) if readme_before != readme_after else None,
                "after_sha256": sha256_bytes(readme_after),
                "after_size": len(readme_after),
            },
            "CHANGELOG.md": {
                "action": "UPDATE",
                "before_sha256": sha256_bytes(changelog_before) if changelog_before != changelog_after else None,
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
    # On repeat, retain the original before hashes from the installed ledger.
    existing_ledger_path = root / R3_ADMIN_LEDGER_REL
    if readme_before == readme_after and changelog_before == changelog_after and existing_ledger_path.is_file():
        existing_ledger = json.loads(require_regular(existing_ledger_path))
        for name in ("README.md", "CHANGELOG.md"):
            admin_ledger["changes"][name]["before_sha256"] = existing_ledger["changes"][name]["before_sha256"]
    outputs[R3_ADMIN_LEDGER_REL] = canonical_json_bytes(admin_ledger)
    outputs[R3_ADMIN_MANIFEST_REL] = (
        f"{sha256_bytes(readme_after)}  README.md\n"
        f"{sha256_bytes(changelog_after)}  CHANGELOG.md\n"
        f"{sha256_bytes(outputs[R3_ADMIN_LEDGER_REL])}  {R3_ADMIN_LEDGER_REL}\n"
    ).encode("utf-8")

    report = {
        "schema": "securelinux-policy-r3-initial-lock-report/v1",
        "date": DATE,
        "result": "R3_INITIAL_LOCK_PASS",
        "r2_interface_dag": "PASS",
        "v9_proposal_sha256": PROPOSAL_SHA256,
        "v9_schema_sha256": SCHEMA_SHA256,
        "module_interfaces": "12/12",
        "fixture_specifications": "127/127",
        "locked_modules": list(LOCKED_MODULES),
        "open_modules": list(OPEN_MODULES),
        "modules_locked": "7/12",
        "modules_open": "5/12",
        "modules_frozen": "0/12",
        "exported_symbol_changes": 0,
        "normative_changes": 0,
        "open_findings": ["V8-01", "V8-EXT-01", "V8-EXT-02"],
        "open_findings_closed": 0,
        "v9_selftest": "PASS",
        "regression_tests": "107/107_PASS",
        "next_phase": "R4_LOCALIZE_M6",
    }
    outputs[R3_REPORT_REL] = canonical_json_bytes(report)

    manifest_names = sorted(outputs)
    outputs[R3_OUTPUTS_REL] = "".join(
        f"{sha256_bytes(outputs[name])}  {name}\n" for name in manifest_names
    ).encode("utf-8")

    new_state = copy.deepcopy(base_state)
    new_state["current_phase"] = "R3_COMPLETE"
    new_state["current_next_step"] = "R4_LOCALIZE_M6"
    new_state["gates"]["R3_INITIAL_LOCK_PASS"] = True
    new_state["r3"] = {
        "locked_modules": "7/12",
        "open_modules": "5/12",
        "frozen_modules": "0/12",
        "locked_modules_sha256": sha256_bytes(outputs[R3_LOCK_STATE_REL]),
        "transition_ledger_sha256": sha256_bytes(outputs[R3_LEDGER_REL]),
        "integration_lock_sha256": sha256_bytes(outputs[INTEGRATION_LOCK_REL]),
        "report_sha256": sha256_bytes(outputs[R3_REPORT_REL]),
        "outputs_manifest_sha256": sha256_bytes(outputs[R3_OUTPUTS_REL]),
        "admin_docs_ledger_sha256": sha256_bytes(outputs[R3_ADMIN_LEDGER_REL]),
        "v9_selftest": "PASS",
        "regression_tests": "107/107_PASS",
        "normative_change": False,
    }
    for module in MODULE_IDS:
        new_state["modules"][module].update({
            "status": "LOCKED" if module in LOCKED_MODULES else "OPEN",
            "content_sha256": current_interfaces[module]["content_sha256"],
            "interface_sha256": current_interfaces[module]["interface_sha256"],
            "module_lock_sha256": sha256_bytes(current_lock_bytes[module]),
            "focused_external_accept": False,
            "frozen": False,
        })
    return outputs, new_state, {"README.md": readme_after, "CHANGELOG.md": changelog_after}


def apply_outputs(root: Path, outputs: dict[str, bytes], docs: dict[str, bytes], state_data: bytes) -> None:
    writes = {**outputs, **docs}
    before: dict[str, bytes | None] = {}
    applied: list[str] = []
    try:
        for relative in sorted(writes):
            path = root / relative
            previous = path.read_bytes() if path.is_file() and not path.is_symlink() else None
            if path.exists() and previous is None:
                raise R3Error(f"unsafe output target: {relative}")
            before[relative] = previous
            if previous != writes[relative]:
                atomic_replace(path, writes[relative], ".tmp-r3")
                applied.append(relative)
        state_path = root / STATE_REL
        before[STATE_REL] = require_regular(state_path)
        if before[STATE_REL] != state_data:
            atomic_replace(state_path, state_data, ".tmp-r3")
            applied.append(STATE_REL)
    except Exception:
        for relative in reversed(applied):
            path = root / relative
            previous = before[relative]
            if previous is None:
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            else:
                atomic_replace(path, previous, ".tmp-r3-rollback")
        raise


def verify_outputs(root: Path, outputs: dict[str, bytes], docs: dict[str, bytes], state_data: bytes) -> None:
    for relative, data in {**outputs, **docs}.items():
        if require_regular(root / relative) != data:
            raise R3Error(f"R3 output verification mismatch: {relative}")
    if require_regular(root / STATE_REL) != state_data:
        raise R3Error("R3 PROJECT-STATE verification mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project_root", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    root = arguments.project_root.resolve()
    if not root.is_dir() or not (root / "B1.1b").is_dir():
        raise R3Error(f"R2 project root missing: {root}")

    require_regular(root / "B1.1b/baseline/v9/BASELINE.json", BASELINE_SHA256)
    require_regular(root / FINDINGS_REL, OPEN_FINDINGS_SHA256)
    require_regular(root / PROPOSAL_REL, PROPOSAL_SHA256)
    require_regular(root / SCHEMA_REL, SCHEMA_SHA256)
    current_state_data = require_regular(root / STATE_REL)
    base_state, already_r3 = load_base_state(root, current_state_data)
    if arguments.verify_only and not already_r3:
        raise R3Error("--verify-only requires R3_COMPLETE")

    if not already_r3:
        verify_manifest(root, R2_OUTPUTS_REL, R2_OUTPUTS_SHA256)
        if sha256_file(root / INTEGRATION_LOCK_REL) != R2_INTEGRATION_LOCK_SHA256:
            raise R3Error("R2 integration lock mismatch")

    script_data = require_regular(Path(__file__).resolve())
    readme_before = require_regular(root / "README.md")
    changelog_before = require_regular(root / "CHANGELOG.md")
    outputs, new_state, docs = build_outputs(
        root, base_state, script_data, readme_before, changelog_before
    )
    outputs_repeat, new_state_repeat, docs_repeat = build_outputs(
        root, base_state, script_data, readme_before, changelog_before
    )
    if outputs != outputs_repeat or new_state != new_state_repeat or docs != docs_repeat:
        raise R3Error("R3 generation is not deterministic")
    new_state_data = canonical_json_bytes(new_state)

    snapshot_before = scan_project(root)
    run_tests(root)
    if scan_project(root) != snapshot_before:
        raise R3Error("tests changed the project snapshot")

    if already_r3:
        verify_outputs(root, outputs, docs, new_state_data)
    else:
        apply_outputs(root, outputs, docs, new_state_data)

    snapshot_after = scan_project(root)
    if already_r3:
        if snapshot_after != snapshot_before:
            raise R3Error("R3 verification changed the project snapshot")
    else:
        changed = changed_snapshot_paths(snapshot_before, snapshot_after)
        if changed != {"README.md", "CHANGELOG.md"}:
            raise R3Error(f"R3 changed paths outside its administrative overlay: {sorted(changed)}")
    verify_outputs(root, outputs, docs, new_state_data)
    if sha256_file(root / PROPOSAL_REL) != PROPOSAL_SHA256 or sha256_file(root / SCHEMA_REL) != SCHEMA_SHA256:
        raise R3Error("v9 normative source changed")

    print("RESULT=R3_INITIAL_LOCK_PASS")
    print("MODULES_LOCKED=7/12")
    print("LOCKED=M0,M1,M2,M3,M4,M5,M7")
    print("MODULES_OPEN=5/12")
    print("OPEN=M6.1,M6.2,M6.3,M6.4,M6.5")
    print("MODULES_FROZEN=0/12")
    print("OPEN_FINDINGS=3")
    print("EXPORTED_SYMBOL_CHANGES=0")
    print("NORMATIVE_CHANGES=0")
    print("FIXTURE_SPECIFICATIONS=127/127")
    print("V9_SELFTEST=PASS")
    print("FULL_REGRESSION_TESTS=107/107_PASS")
    print("README_MD=UPDATED_R3_STATE")
    print("CHANGELOG_MD=UPDATED_R3_STATE")
    print("SVG_PNG=UNCHANGED")
    print("TASK_B1_1_ACCEPTED=false")
    print("TASK_B1_2=NOT_STARTED")
    print("SELECTOR_INSTANCES_FROZEN=0/20")
    print(f"SHA256={sha256_bytes(outputs[R3_LOCK_STATE_REL])}  {R3_LOCK_STATE_REL}")
    print(f"SHA256={sha256_bytes(outputs[R3_LEDGER_REL])}  {R3_LEDGER_REL}")
    print(f"SHA256={sha256_bytes(outputs[INTEGRATION_LOCK_REL])}  {INTEGRATION_LOCK_REL}")
    print(f"SHA256={sha256_bytes(outputs[R3_REPORT_REL])}  {R3_REPORT_REL}")
    print(f"SHA256={sha256_bytes(outputs[R3_OUTPUTS_REL])}  {R3_OUTPUTS_REL}")
    print(f"SHA256={sha256_bytes(new_state_data)}  {STATE_REL}")
    print("CURRENT_NEXT_STEP=R4_LOCALIZE_M6")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (R3Error, OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"R3_FAIL={exc}", file=sys.stderr)
        raise SystemExit(1)
