#!/usr/bin/env python3
"""Create the immutable TASK-B1.1 R0/v9 modular baseline checkpoint.

The command is deliberately fail-closed.  It verifies the retained evidence,
the live v9 candidate, all checksum manifests, the v8->v9 normative diff,
the v9 self-test, and the full 107-test suite before it writes B1.1b/ state.
It never edits docs/, controls/, runtime/, src/, tests/, or sources/.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import unicodedata


SCRIPT_NAME = "SecureLinux-Policy-TASK-B1.1-R0-baseline-init-20260813.py"
DATE = "2026-08-13"

V8_ARCHIVE = "SecureLinux-Policy-TASK-B1.1-external-review-v8-20260813.tar.gz"
V8_ARCHIVE_SHA256 = "090a16dcb03399240237e0b9ecc50a8ab64bb20c3662aee3712ab810686e7335"
V8_PACKAGE_ROOT = "SecureLinux-Policy-TASK-B1.1-external-review-v8-20260813"
V8_EXPECTED_MEMBERS = 265
V8_EXPECTED_PROJECT_FILES = 243

V9_INSTALLER = "SecureLinux-Policy-TASK-B1.1b-v9-install-20260813.py"
V9_INSTALLER_SHA256 = "ae098668dfc26ce3742f756af3966c9a795628da76d7229f372a50a0fe3883ca"

INPUT_CLOSURE = "SecureLinux-Policy-TASK-B1.1-input-closure-20260812.tar.gz"
INPUT_CLOSURE_SHA256 = "5ca5c084e9689dbeff347bd57defe7a395292b9c30b9121a3c9532d5cf518069"
INPUT_CLOSURE_EXPECTED_MEMBERS = 138

INPUT_SUPPLEMENT = "SecureLinux-Policy-TASK-B1.1-input-closure-supplement-20260812.tar.gz"
INPUT_SUPPLEMENT_SHA256 = "072f9c1069c74fb96c06baf30fa0b4885f5967bd053e88937e326a12cc75fc86"
INPUT_SUPPLEMENT_EXPECTED_MEMBERS = 10

PINNED_CURRENT = {
    "docs/SecureLinux-Policy-TASK-B1.1-v8-external-review-checkpoint-20260813.md":
        "ec8a0ef4a28cbb2e15427e6ba03e3ffe31e133ada80c9a73ed0217a0936bab59",
    "docs/SecureLinux-Policy-TASK-B1.1-v8-external-review-checkpoint-20260813.md.sha256":
        "3778e002ca9451fbbed31b44b961d4036de292e9265c9d4079a68ada9d33e090",
    "docs/SecureLinux-Policy-TASK-B1.1a-state-outcome-taxonomy-proposal-v2.1-20260812.md":
        "f833c84155cbe0708240e800a7818381b023fae0f1344ddb0a8c53a0cdb476f5",
    "docs/SecureLinux-Policy-TASK-B1.1a-state-outcome-taxonomy-proposal-v2.1-20260812.md.sha256":
        "67f069e478d0888a2436d0b9784d47b18fb27732ab4c28cd5d1d1a9393679a25",
    "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-proposal-v9-20260813.md":
        "bb359806252163cc6cf29f3499ff828891d3ce11104fe9934704c7022f14abfb",
    "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-proposal-v9-20260813.md.sha256":
        "693e7d5474d9d71bac9ab983f721a163ef5d06a93048f3ccd7ee163b5f82ff00",
    "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-schema-v9-20260813.json":
        "2304b192d4f3c8e4fde056a42970ae4b2200df28012019445023c704c6375995",
    "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-schema-v9-20260813.json.sha256":
        "31ec691d8c948397e470b20533d08b3155bd06ad3f135bf16ae585a00bc4df7e",
    "docs/SecureLinux-Policy-TASK-B1.1b-v9-normative-transition-ledger-20260813.json":
        "b226527321b76f0eca440c91c77f26c382fabe9b6499aeb21c69e11976893bf9",
    "docs/SecureLinux-Policy-TASK-B1.1b-v9-normative-transition-ledger-20260813.json.sha256":
        "2035da7af70b693721badb4f96d41ae3586c61ea202158304d7e76287d9b5cdf",
    "docs/SecureLinux-Policy-TASK-B1.1b-v9-selftest-20260813.py":
        "5ed3b41f6f7fdf9a97bd82752eba085960e476f84ae7e60ae256b019cbecb1f9",
    "docs/SecureLinux-Policy-TASK-B1.1b-v9-selftest-20260813.py.sha256":
        "6e05925338eac441848e64ce7fe4b6ab7ef0b564a90fa8083b7197c86eafb795",
    "docs/SecureLinux-Policy-TASK-B1.1b-v9-normative-diff-and-closure-report-20260813.md":
        "72f1e7b6efb1fba319bb82d25765524478d2e939b1cd2b8031a65dbf5f7e5430",
    "docs/SecureLinux-Policy-TASK-B1.1b-v9-normative-diff-and-closure-report-20260813.md.sha256":
        "89d5497f0b3c549dc87597aab8d659d66152026d814f2a51057d2c1feec27478",
    "docs/SecureLinux-Policy-TASK-B1.1b-internal-cross-document-adversarial-review-v9-20260813.md":
        "c623e2612bce1a05bcf46b9a9fd9ecaa66eba14fc18c80a3ebbf70646a25bf4f",
    "docs/SecureLinux-Policy-TASK-B1.1b-internal-cross-document-adversarial-review-v9-20260813.md.sha256":
        "affbfdd76a32d5f886d0f012b19eb54fac90d192086a09f39f7ff318501b9453",
    "docs/SecureLinux-Policy-TASK-B1.1b-v9-SHA256SUMS":
        "224edce3c7ce311ba4679260cde98432f5ede59954394bc6851c2c4d301e649c",
    "docs/SecureLinux-Policy-TASK-B1.1b-v9-SHA256SUMS.sha256":
        "9a8faea1ccb14be3ab79578bef42cb76f2b6f7612d718b475c5ae05ee9083795",
    "docs/SecureLinux-Policy-VISUAL-MAP-20260813.md":
        "09353c61e9f6cb48ebbd565b421d309e1918913261c6a42b4de6554e06b186ed",
    "docs/SecureLinux-Policy-VISUAL-MAP-20260813.dot":
        "8cbf9d94262a4b55a114bae65bfa2a85d7b10e0065ff2ddcead61f88aadcdca0",
    "docs/SecureLinux-Policy-VISUAL-MAP-20260813.svg":
        "af984b3fce6b69d46e5d321e7ffcb4ec7b64d8c0189b8428e864a27c2b11f7db",
    "docs/SecureLinux-Policy-VISUAL-MAP-20260813.png":
        "74e145f6f2617d065c5f135d1a48c24dc49f910145036dc85c0e9ce8f8bb0c34",
    "docs/MAP-SHA256SUMS":
        "a57ec9157d4d10672b862212727c4035da412321f22c270b4f453e63d02a6521",
    "docs/AUDIT-STATE.md":
        "32f9e1ed6f1f7798188b6c321d7a99e429b52ec37b4984418fcf919f20bf5e20",
    "docs/roadmap.md":
        "19bc0735d962b27a4aace16aa770d36c4aef72e00bf4254308a5a3f90fcc0a36",
}

REQUIRED_GATE_MARKERS = {
    "docs/AUDIT-STATE.md": (
        "CURRENT_AUTHORITY=B1_1B_V9_CANDIDATE_20260813",
        "B1_1A_V2_1=ACCEPT",
        "B1_1B_V9_INDEPENDENT_REVIEW=false",
        "B1_1B_V9_ACCEPTED=false",
        "TASK_B1_1_ACCEPTED=false",
        "TASK_B1_2=NOT_STARTED",
        "SELECTOR_INSTANCES_FROZEN=0/20",
        "CANONICAL_CORPUS_MUTATION_ALLOWED=false",
        "VALIDATOR_MUTATION_ALLOWED=false",
        "RUNTIME_MUTATION_ALLOWED=false",
        "HOST_STATE_MUTATION_ALLOWED=false",
        "COMMIT_PUSH_ALLOWED=false",
    ),
    "docs/roadmap.md": (
        "B1_1A_V2_1=ACCEPT",
        "B1_1B_V9_ACCEPTED=false",
        "TASK_B1_1_ACCEPTED=false",
        "TASK_B1_2=NOT_STARTED",
        "SELECTOR_INSTANCES_FROZEN=0/20",
    ),
}

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


class R0Error(RuntimeError):
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


def canonical_key(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def safe_relative_name(name: str) -> bool:
    pure = PurePosixPath(name)
    return (
        bool(name)
        and not pure.is_absolute()
        and bool(pure.parts)
        and all(part not in ("", ".", "..") for part in pure.parts)
    )


def parse_checksum_records(data: bytes, label: str, allow_absolute_name: bool = False) -> list[tuple[str, str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise R0Error(f"checksum file is not UTF-8: {label}") from exc
    lines = text.splitlines()
    if not lines:
        raise R0Error(f"empty checksum file: {label}")
    records: list[tuple[str, str]] = []
    seen: set[str] = set()
    for number, line in enumerate(lines, 1):
        if len(line) < 67 or line[64:66] not in ("  ", " *"):
            raise R0Error(f"invalid checksum record: {label}:{number}")
        digest = line[:64].lower()
        name = line[66:]
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise R0Error(f"invalid SHA-256: {label}:{number}")
        if allow_absolute_name:
            if not name or PurePosixPath(name).name in ("", ".", ".."):
                raise R0Error(f"invalid checksum target: {label}:{number}")
            collision_name = PurePosixPath(name).name
        else:
            if not safe_relative_name(name):
                raise R0Error(f"unsafe checksum target: {label}:{number}: {name!r}")
            collision_name = name
        key = canonical_key(collision_name)
        if key in seen:
            raise R0Error(f"duplicate/colliding checksum target: {label}:{number}: {name!r}")
        seen.add(key)
        records.append((digest, name))
    return records


def verify_sidecar(path: Path, target: Path, expected_digest: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise R0Error(f"sidecar missing or unsafe: {path}")
    records = parse_checksum_records(path.read_bytes(), str(path), allow_absolute_name=True)
    if len(records) != 1:
        raise R0Error(f"sidecar must contain one record: {path}")
    digest, name = records[0]
    if digest != expected_digest or PurePosixPath(name).name != target.name:
        raise R0Error(f"sidecar does not pin {target.name}: {path}")


def verify_evidence_file(evidence_root: Path, name: str, expected_digest: str) -> Path:
    target = evidence_root / name
    sidecar = evidence_root / (name + ".sha256")
    if not target.is_file() or target.is_symlink():
        raise R0Error(f"retained evidence missing or unsafe: {target}")
    actual = sha256_file(target)
    if actual != expected_digest:
        raise R0Error(f"retained evidence hash mismatch: {target}: {actual} != {expected_digest}")
    verify_sidecar(sidecar, target, expected_digest)
    return target


def scan_tar_safety(path: Path, expected_members: int) -> dict[str, int]:
    seen: set[str] = set()
    canonical_seen: dict[str, str] = {}
    regular = 0
    directories = 0
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) != expected_members:
            raise R0Error(f"tar member count mismatch: {path}: {len(members)} != {expected_members}")
        for member in members:
            name = member.name.rstrip("/")
            if not safe_relative_name(name):
                raise R0Error(f"unsafe tar path: {path}: {member.name!r}")
            if name in seen:
                raise R0Error(f"duplicate tar member: {path}: {name!r}")
            seen.add(name)
            key = canonical_key(name)
            previous = canonical_seen.get(key)
            if previous is not None and previous != name:
                raise R0Error(f"tar casefold/Unicode collision: {path}: {previous!r} / {name!r}")
            canonical_seen[key] = name
            if member.isdir():
                directories += 1
            elif member.isreg():
                regular += 1
            else:
                raise R0Error(f"link or special tar member forbidden: {path}: {member.name!r}")
    return {"members": expected_members, "regular_files": regular, "directories": directories}


def tar_file_inventory(path: Path) -> tuple[dict[str, str], dict[str, int]]:
    hashes: dict[str, str] = {}
    sizes: dict[str, int] = {}
    roots: set[str] = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            name = member.name.rstrip("/")
            roots.add(PurePosixPath(name).parts[0])
            if not member.isreg():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                raise R0Error(f"cannot read tar member: {path}: {member.name}")
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
            if size != member.size:
                raise R0Error(f"tar member size mismatch: {path}: {member.name}")
            hashes[name] = digest.hexdigest()
            sizes[name] = size
    if roots != {V8_PACKAGE_ROOT}:
        raise R0Error(f"v8 package must have one pinned root: {sorted(roots)!r}")
    return hashes, sizes


def tar_member_bytes(path: Path, member_name: str) -> bytes:
    with tarfile.open(path, "r:gz") as archive:
        try:
            member = archive.getmember(member_name)
        except KeyError as exc:
            raise R0Error(f"tar member missing: {path}: {member_name}") from exc
        if not member.isreg():
            raise R0Error(f"tar member is not regular: {path}: {member_name}")
        stream = archive.extractfile(member)
        if stream is None:
            raise R0Error(f"cannot read tar member: {path}: {member_name}")
        return stream.read()


def archive_target_name(manifest_name: str, target_name: str) -> str:
    manifest = PurePosixPath(manifest_name)
    package_root = manifest.parts[0]
    project_prefix = PurePosixPath(package_root) / "project"
    target = PurePosixPath(target_name)
    if manifest.name == "SHA256SUMS" and len(manifest.parts) == 2:
        return (PurePosixPath(package_root) / target).as_posix()
    if manifest.name == "PROJECT-FILES.sha256" and len(manifest.parts) == 2:
        return (project_prefix / target).as_posix()
    if "/" in target_name:
        return (project_prefix / target).as_posix()
    return (manifest.parent / target).as_posix()


def verify_archive_manifest(
    manifest_name: str,
    manifest_data: bytes,
    inventory: dict[str, str],
) -> int:
    records = parse_checksum_records(manifest_data, manifest_name)
    for expected, target_name in records:
        resolved = archive_target_name(manifest_name, target_name)
        actual = inventory.get(resolved)
        if actual is None:
            raise R0Error(f"archive checksum target missing: {manifest_name}: {target_name}")
        if actual != expected:
            raise R0Error(f"archive checksum mismatch: {manifest_name}: {target_name}")
    return len(records)


def verify_v8_package(path: Path) -> dict[str, int]:
    safety = scan_tar_safety(path, V8_EXPECTED_MEMBERS)
    inventory, _ = tar_file_inventory(path)
    prefix = V8_PACKAGE_ROOT + "/"
    package_manifest = prefix + "SHA256SUMS"
    project_manifest = prefix + "PROJECT-FILES.sha256"
    package_count = verify_archive_manifest(
        package_manifest, tar_member_bytes(path, package_manifest), inventory
    )
    expected_package_targets = set(inventory) - {package_manifest}
    package_targets = {
        archive_target_name(package_manifest, name)
        for _, name in parse_checksum_records(tar_member_bytes(path, package_manifest), package_manifest)
    }
    if package_targets != expected_package_targets:
        missing = sorted(expected_package_targets - package_targets)[:5]
        extra = sorted(package_targets - expected_package_targets)[:5]
        raise R0Error(f"v8 package SHA256SUMS coverage mismatch: missing={missing}, extra={extra}")

    project_count = verify_archive_manifest(
        project_manifest, tar_member_bytes(path, project_manifest), inventory
    )
    if project_count != V8_EXPECTED_PROJECT_FILES:
        raise R0Error(f"v8 PROJECT-FILES count mismatch: {project_count} != {V8_EXPECTED_PROJECT_FILES}")
    project_files = {name for name in inventory if name.startswith(prefix + "project/")}
    project_targets = {
        archive_target_name(project_manifest, name)
        for _, name in parse_checksum_records(tar_member_bytes(path, project_manifest), project_manifest)
    }
    if project_targets != project_files:
        raise R0Error("v8 PROJECT-FILES does not exactly cover project/")

    internal_manifests = sorted(
        name for name in inventory
        if name.startswith(prefix + "project/")
        and (name.endswith(".sha256") or PurePosixPath(name).name.endswith("SHA256SUMS"))
    )
    internal_records = 0
    sidecars = 0
    for name in internal_manifests:
        records = parse_checksum_records(tar_member_bytes(path, name), name)
        internal_records += verify_archive_manifest(name, tar_member_bytes(path, name), inventory)
        if name.endswith(".sha256") and len(records) == 1:
            sidecars += 1

    required = (
        prefix + "project/docs/SecureLinux-Policy-TASK-B1.1b-v8-SHA256SUMS",
        prefix + "project/docs/MAP-SHA256SUMS",
        prefix + "project/controls/CANONICAL-SHA256SUMS",
        prefix + "project/sources/fstec/SHA256SUMS",
    )
    for name in required:
        if name not in inventory:
            raise R0Error(f"required v8 archive manifest missing: {name}")
    return {
        **safety,
        "package_manifest_records": package_count,
        "project_manifest_records": project_count,
        "internal_manifests": len(internal_manifests),
        "internal_manifest_records": internal_records,
        "single_record_sidecars": sidecars,
    }


def scan_project(root: Path) -> tuple[list[Path], list[Path]]:
    files: list[Path] = []
    directories: list[Path] = []
    seen: dict[str, str] = {}

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            rel = path.relative_to(root)
            if rel.parts[0] in (".git", "B1.1b"):
                continue
            name = rel.as_posix()
            if not safe_relative_name(name):
                raise R0Error(f"unsafe project path: {name!r}")
            key = canonical_key(name)
            previous = seen.get(key)
            if previous is not None and previous != name:
                raise R0Error(f"project casefold/Unicode collision: {previous!r} / {name!r}")
            seen[key] = name
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISLNK(mode):
                raise R0Error(f"project link forbidden: {name}")
            if stat.S_ISDIR(mode):
                directories.append(rel)
                visit(path)
            elif stat.S_ISREG(mode):
                files.append(rel)
            else:
                raise R0Error(f"project special entry forbidden: {name}")

    visit(root)
    return (
        sorted(files, key=lambda item: item.as_posix()),
        sorted(directories, key=lambda item: item.as_posix()),
    )


def project_inventory(root: Path, files: list[Path]) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for rel in files:
        path = root / rel
        result[rel.as_posix()] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    return result


def resolve_project_manifest_target(root: Path, manifest: Path, target_name: str) -> Path:
    target = PurePosixPath(target_name)
    if "/" in target_name:
        return root.joinpath(*target.parts)
    return manifest.parent.joinpath(*target.parts)


def verify_project_manifest(root: Path, manifest: Path) -> int:
    if not manifest.is_file() or manifest.is_symlink():
        raise R0Error(f"project manifest missing or unsafe: {manifest}")
    records = parse_checksum_records(manifest.read_bytes(), str(manifest))
    for expected, target_name in records:
        target = resolve_project_manifest_target(root, manifest, target_name)
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise R0Error(f"project checksum escapes root: {manifest}: {target_name}") from exc
        if not target.is_file() or target.is_symlink():
            raise R0Error(f"project checksum target missing or unsafe: {manifest}: {target_name}")
        actual = sha256_file(target)
        if actual != expected:
            raise R0Error(f"project checksum mismatch: {manifest}: {target_name}")
    return len(records)


def verify_all_project_manifests(root: Path, files: list[Path]) -> dict[str, object]:
    manifests = sorted(
        (root / rel for rel in files
         if rel.name.endswith("SHA256SUMS") or rel.name.endswith(".sha256")),
        key=lambda item: item.relative_to(root).as_posix(),
    )
    results: list[dict[str, object]] = []
    for manifest in manifests:
        results.append({
            "path": manifest.relative_to(root).as_posix(),
            "records": verify_project_manifest(root, manifest),
        })
    return {
        "manifest_count": len(results),
        "record_count": sum(int(item["records"]) for item in results),
        "manifests": results,
    }


def verify_pinned_live_state(root: Path) -> None:
    for relative, expected in PINNED_CURRENT.items():
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise R0Error(f"pinned v9 file missing or unsafe: {relative}")
        actual = sha256_file(path)
        if actual != expected:
            raise R0Error(f"pinned v9 mismatch: {relative}: {actual} != {expected}")
    for relative, markers in REQUIRED_GATE_MARKERS.items():
        text = (root / relative).read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                raise R0Error(f"gate marker missing: {relative}: {marker}")


def verify_v8_v9_diff(root: Path) -> dict[str, object]:
    docs = root / "docs"
    old_path = docs / "SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-proposal-v8-20260813.md"
    new_path = docs / "SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-proposal-v9-20260813.md"
    ledger_path = docs / "SecureLinux-Policy-TASK-B1.1b-v9-normative-transition-ledger-20260813.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    transition = next(
        (item for item in ledger.get("transitions", []) if item.get("transition") == "v8->v9"),
        None,
    )
    if transition is None:
        raise R0Error("v8->v9 transition missing from ledger")
    if transition.get("predecessor_sha256") != sha256_file(old_path):
        raise R0Error("v8 predecessor hash mismatch in transition ledger")
    if transition.get("successor_sha256") != sha256_file(new_path):
        raise R0Error("v9 successor hash mismatch in transition ledger")
    old_lines = old_path.read_text(encoding="utf-8").splitlines()
    new_lines = new_path.read_text(encoding="utf-8").splitlines()
    opcodes = [
        item for item in difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False).get_opcodes()
        if item[0] != "equal"
    ]
    blocks = transition.get("diff_blocks", [])
    if len(opcodes) != transition.get("diff_block_count") or len(blocks) != len(opcodes):
        raise R0Error("v8->v9 diff block count mismatch")
    classifications: dict[str, int] = {}
    for index, (opcode, block) in enumerate(zip(opcodes, blocks), 1):
        tag, old_start, old_end, new_start, new_end = opcode
        old_text = "\n".join(old_lines[old_start:old_end])
        new_text = "\n".join(new_lines[new_start:new_end])
        expected = {
            "opcode": tag,
            "old_start_line_zero_based": old_start,
            "old_end_line_zero_based_exclusive": old_end,
            "new_start_line_zero_based": new_start,
            "new_end_line_zero_based_exclusive": new_end,
            "old_sha256": sha256_bytes(old_text.encode("utf-8")),
            "new_sha256": sha256_bytes(new_text.encode("utf-8")),
            "old_text": old_text,
            "new_text": new_text,
        }
        for key, value in expected.items():
            if block.get(key) != value:
                raise R0Error(f"v8->v9 diff block {index} mismatch: {key}")
        classification = block.get("classification")
        if not isinstance(classification, str) or not classification:
            raise R0Error(f"v8->v9 diff block {index} has no classification")
        if not isinstance(block.get("reason"), str) or not block["reason"].strip():
            raise R0Error(f"v8->v9 diff block {index} has no reason")
        classifications[classification] = classifications.get(classification, 0) + 1
    return {
        "algorithm": "difflib.SequenceMatcher(lines,autojunk=false); non-equal opcodes",
        "diff_blocks": len(blocks),
        "classifications": classifications,
        "predecessor_sha256": sha256_file(old_path),
        "successor_sha256": sha256_file(new_path),
    }


def run_command(command: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        command,
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def run_v9_selftest(root: Path) -> dict[str, object]:
    selftest = root / "docs/SecureLinux-Policy-TASK-B1.1b-v9-selftest-20260813.py"
    result = run_command([sys.executable, str(selftest), str(root)], root)
    if result.returncode != 0 or "RESULT=B1_1B_V9_SELFTEST_PASS" not in result.stdout:
        raise R0Error("v9 self-test failed:\n" + result.stdout[-4000:])
    return {"result": "PASS", "returncode": 0, "marker": "RESULT=B1_1B_V9_SELFTEST_PASS"}


def run_regression_tests(root: Path) -> dict[str, object]:
    result = run_command(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        root,
    )
    match = re.search(r"Ran\s+(\d+)\s+tests?", result.stdout)
    count = int(match.group(1)) if match else None
    if result.returncode != 0 or count != 107 or not re.search(r"^OK$", result.stdout, re.MULTILINE):
        raise R0Error("107-test regression failed:\n" + result.stdout[-6000:])
    return {"result": "PASS", "returncode": 0, "tests": count}


def immutable_write(path: Path, data: bytes) -> None:
    if path.exists():
        if not path.is_file() or path.is_symlink():
            raise R0Error(f"immutable target is not a regular file: {path}")
        if path.read_bytes() != data:
            raise R0Error(f"immutable target already exists with different content: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp-r0")
    if temporary.exists():
        raise R0Error(f"stale temporary file blocks write: {temporary}")
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def create_layout(root: Path) -> None:
    base = root / "B1.1b"
    directories = [
        base / "baseline/v9",
        *(base / "modules" / module for module in MODULE_IDS),
        base / "integration",
        base / "state",
        base / "tools",
        base / "reports",
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


def create_state(
    root: Path,
    evidence: dict[str, object],
    project_files: list[Path],
    project_directories: list[Path],
    inventory: dict[str, dict[str, object]],
    manifests: dict[str, object],
    diff_result: dict[str, object],
    selftest_result: dict[str, object],
    regression_result: dict[str, object],
    script_path: Path,
) -> dict[str, str]:
    create_layout(root)
    base = root / "B1.1b"
    baseline_path = base / "baseline/v9/BASELINE.json"
    baseline_sidecar = base / "baseline/v9/BASELINE.sha256"
    findings_path = base / "state/OPEN-FINDINGS.json"
    state_path = base / "state/PROJECT-STATE.json"
    tool_path = base / "tools" / SCRIPT_NAME
    tool_sidecar = base / "tools" / (SCRIPT_NAME + ".sha256")

    script_data = script_path.read_bytes()
    script_digest = sha256_bytes(script_data)
    baseline = {
        "schema": "securelinux-policy-b1.1b-baseline/v1",
        "baseline_id": "TASK-B1.1b-v9-immutable-candidate-20260813",
        "date": DATE,
        "status": "IMMUTABLE_CANDIDATE_NOT_ACCEPTED",
        "gate": "R0_BASELINE_CLOSURE_PASS",
        "source_candidate": {
            "b1_1a": "ACCEPT",
            "b1_1b": "NOT_ACCEPTED",
            "task_b1_1": "NOT_ACCEPTED",
            "task_b1_2": "NOT_STARTED",
            "selector_instances_frozen": "0/20",
        },
        "retained_evidence": evidence,
        "pinned_current": dict(sorted(PINNED_CURRENT.items())),
        "project_snapshot": {
            "scope": "all regular project files except .git/ and B1.1b/",
            "file_count": len(project_files),
            "directory_count": len(project_directories),
            "files": [
                {"path": name, **inventory[name]}
                for name in sorted(inventory)
            ],
        },
        "checksum_verification": manifests,
        "normative_diff_v8_v9": diff_result,
        "v9_selftest": selftest_result,
        "regression_tests": regression_result,
        "r0_tool": {"name": SCRIPT_NAME, "sha256": script_digest},
        "mutation_assertion": {
            "canonical": False,
            "validator": False,
            "runtime": False,
            "host": False,
            "docs_existing_files": False,
        },
    }
    baseline_data = canonical_json_bytes(baseline)
    baseline_digest = sha256_bytes(baseline_data)

    findings = {
        "schema": "securelinux-policy-open-findings/v1",
        "baseline_id": baseline["baseline_id"],
        "baseline_sha256": baseline_digest,
        "candidate_claims_are_not_acceptance": True,
        "findings": [
            {
                "finding_id": "V8-01",
                "status": "OPEN_FOR_MODULAR_PROOF",
                "owners": ["M6.2-operation-algebra"],
                "requirement": "exact arity and unambiguous input-to-output mapping for every transformation operation",
                "closure_requires": ["rule_id", "exact_hash", "positive_fixtures", "negative_fixtures", "checker_pass", "external_verdict"],
            },
            {
                "finding_id": "V8-EXT-01",
                "status": "OPEN_FOR_MODULAR_PROOF",
                "owners": ["M6.3-enumeration-domains"],
                "requirement": "closed population model for host and adapter enumeration",
                "closure_requires": ["rule_id", "exact_hash", "positive_fixtures", "negative_fixtures", "checker_pass", "external_verdict"],
            },
            {
                "finding_id": "V8-EXT-02",
                "status": "OPEN_FOR_MODULAR_PROOF",
                "owners": ["M6.3-enumeration-domains", "M6.4-population-matrix"],
                "requirement": "exact semantics and admissibility matrix for input_population_mode, population_completeness, and resolution.kind",
                "closure_requires": ["rule_id", "exact_hash", "positive_fixtures", "negative_fixtures", "checker_pass", "external_verdict"],
            },
        ],
    }
    findings_data = canonical_json_bytes(findings)
    findings_digest = sha256_bytes(findings_data)

    project_state = {
        "schema": "securelinux-policy-project-state/v1",
        "date": DATE,
        "baseline_id": baseline["baseline_id"],
        "baseline_sha256": baseline_digest,
        "open_findings_sha256": findings_digest,
        "current_phase": "R0_COMPLETE",
        "current_next_step": "R1_MECHANICAL_EXTRACTION",
        "gates": {
            "R0_BASELINE_CLOSURE_PASS": True,
            "R1_EXTRACTION_EQUIVALENCE_PASS": False,
            "R2_INTERFACE_DAG_PASS": False,
            "R7_INTEGRATION_BUILD_PASS": False,
            "R8_FULL_MECHANICAL_PASS": False,
            "R9_INTEGRATION_AUDITOR_1_ACCEPT": False,
            "R9_INTEGRATION_AUDITOR_2_ACCEPT": False,
        },
        "project_gate": {
            "b1_1a": "ACCEPT",
            "b1_1b": "NOT_ACCEPTED",
            "task_b1_1": "NOT_ACCEPTED",
            "task_b1_2": "NOT_STARTED",
            "selector_instances_frozen": "0/20",
        },
        "modules": {module: {"status": "OPEN", "version": None} for module in MODULE_IDS},
        "forbidden": {
            "monolithic_v10_or_later": True,
            "b1_2_start": True,
            "canonical_mutation": True,
            "validator_mutation": True,
            "runtime_mutation": True,
            "host_mutation": True,
            "commit_push": True,
        },
    }
    state_data = canonical_json_bytes(project_state)

    immutable_write(tool_path, script_data)
    immutable_write(tool_sidecar, f"{script_digest}  {SCRIPT_NAME}\n".encode("utf-8"))
    immutable_write(baseline_path, baseline_data)
    immutable_write(baseline_sidecar, f"{baseline_digest}  BASELINE.json\n".encode("utf-8"))
    immutable_write(findings_path, findings_data)
    immutable_write(state_path, state_data)

    return {
        "baseline": baseline_digest,
        "findings": findings_digest,
        "state": sha256_bytes(state_data),
        "tool": script_digest,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project_root", type=Path)
    parser.add_argument("evidence_root", type=Path)
    args = parser.parse_args()
    root = args.project_root.resolve()
    evidence_root = args.evidence_root.resolve()
    script_path = Path(__file__).resolve()

    if not root.is_dir() or not (root / "docs").is_dir() or not (root / "tests").is_dir():
        raise R0Error(f"not a SecureLinux-Policy project root: {root}")
    if not evidence_root.is_dir():
        raise R0Error(f"evidence root missing: {evidence_root}")
    if not script_path.is_file() or script_path.is_symlink():
        raise R0Error(f"R0 script is missing or unsafe: {script_path}")

    archive = verify_evidence_file(evidence_root, V8_ARCHIVE, V8_ARCHIVE_SHA256)
    installer = verify_evidence_file(evidence_root, V9_INSTALLER, V9_INSTALLER_SHA256)
    input_closure = verify_evidence_file(evidence_root, INPUT_CLOSURE, INPUT_CLOSURE_SHA256)
    input_supplement = verify_evidence_file(evidence_root, INPUT_SUPPLEMENT, INPUT_SUPPLEMENT_SHA256)

    archive_result = verify_v8_package(archive)
    closure_tar_result = scan_tar_safety(input_closure, INPUT_CLOSURE_EXPECTED_MEMBERS)
    supplement_tar_result = scan_tar_safety(input_supplement, INPUT_SUPPLEMENT_EXPECTED_MEMBERS)
    evidence = {
        V8_ARCHIVE: {"sha256": V8_ARCHIVE_SHA256, **archive_result},
        V9_INSTALLER: {"sha256": V9_INSTALLER_SHA256, "size": installer.stat().st_size},
        INPUT_CLOSURE: {"sha256": INPUT_CLOSURE_SHA256, **closure_tar_result},
        INPUT_SUPPLEMENT: {"sha256": INPUT_SUPPLEMENT_SHA256, **supplement_tar_result},
    }

    verify_pinned_live_state(root)
    files_before, directories_before = scan_project(root)
    inventory_before = project_inventory(root, files_before)
    manifests = verify_all_project_manifests(root, files_before)
    diff_result = verify_v8_v9_diff(root)
    selftest_result = run_v9_selftest(root)
    regression_result = run_regression_tests(root)

    files_after, directories_after = scan_project(root)
    inventory_after = project_inventory(root, files_after)
    if files_after != files_before or directories_after != directories_before or inventory_after != inventory_before:
        raise R0Error("self-test or regression suite mutated the project tree")

    output_hashes = create_state(
        root,
        evidence,
        files_before,
        directories_before,
        inventory_before,
        manifests,
        diff_result,
        selftest_result,
        regression_result,
        script_path,
    )

    print("RESULT=R0_BASELINE_CLOSURE_PASS")
    print("B1_1B_V9=IMMUTABLE_CANDIDATE_NOT_ACCEPTED")
    print("TASK_B1_1_ACCEPTED=false")
    print("TASK_B1_2=NOT_STARTED")
    print("SELECTOR_INSTANCES_FROZEN=0/20")
    print(f"PROJECT_FILES={len(files_before)}")
    print(f"PROJECT_DIRECTORIES={len(directories_before)}")
    print(f"PROJECT_MANIFESTS={manifests['manifest_count']}")
    print(f"PROJECT_MANIFEST_RECORDS={manifests['record_count']}")
    print(f"V8_V9_DIFF_BLOCKS={diff_result['diff_blocks']}")
    print("V9_SELFTEST=PASS")
    print("FULL_REGRESSION_TESTS=107/107_PASS")
    print(f"SHA256={output_hashes['baseline']}  B1.1b/baseline/v9/BASELINE.json")
    print(f"SHA256={output_hashes['findings']}  B1.1b/state/OPEN-FINDINGS.json")
    print(f"SHA256={output_hashes['state']}  B1.1b/state/PROJECT-STATE.json")
    print(f"SHA256={output_hashes['tool']}  B1.1b/tools/{SCRIPT_NAME}")
    print("CURRENT_NEXT_STEP=R1_MECHANICAL_EXTRACTION")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except R0Error as exc:
        print(f"R0_FAIL={exc}", file=sys.stderr)
        raise SystemExit(1)
