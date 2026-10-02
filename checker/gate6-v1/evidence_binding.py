#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

METADATA_SCHEMA = "securelinux-policy-reference-vm-metadata-v1"
RESULT_SCHEMA = "securelinux-policy-probe-results-v1"

METADATA_KEYS = {
    "SCHEMA",
    "COLLECTED_AT",
    "HOSTNAME",
    "KERNEL",
    "ARCH",
    "PRETTY_NAME",
    "VERSION_ID",
    "PYTHON",
    "BPF_JIT_HARDEN_MODE",
    "BPF_JIT_HARDEN_OWNER",
    "PROBE_SHA256",
    "PROBE_PLAN_SHA256",
    "PROBE_RESULTS_ROOT_SHA256",
    "PROBE_RESULTS_UNPRIVILEGED_SHA256",
}

EVIDENCE_MEMBERS = {
    "CHECKER-OUTPUT.txt",
    "CHECKER-REPORT.json",
    "README.md",
    "RESULT.txt",
    "VM-METADATA.txt",
    "probe-results-root.json",
    "probe-results-unprivileged.json",
}

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_regular(path: Path) -> None:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"symlink forbidden: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"regular file required: {path}")


def parse_sha256s(path: Path) -> dict[str, str]:
    validate_regular(path)
    rows: dict[str, str] = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        if len(line) < 67 or line[64:66] != "  ":
            raise ValueError(f"bad SHA256SUMS line {lineno}")
        digest, name = line[:64], line[66:]
        if not HEX64.fullmatch(digest):
            raise ValueError(f"bad SHA-256 at line {lineno}")
        if "/" in name or name in {".", ".."}:
            raise ValueError(f"evidence SHA256SUMS must use basenames only: {name!r}")
        if name in rows:
            raise ValueError(f"duplicate SHA256SUMS member: {name}")
        rows[name] = digest
    return rows


def parse_metadata(path: Path) -> dict[str, str]:
    validate_regular(path)
    rows: dict[str, str] = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        if "=" not in line:
            raise ValueError(f"metadata line {lineno} must be KEY=VALUE")
        key, value = line.split("=", 1)
        if not key or not value:
            raise ValueError(f"metadata line {lineno} has empty key/value")
        if key in rows:
            raise ValueError(f"duplicate metadata key: {key}")
        rows[key] = value
    if set(rows) != METADATA_KEYS:
        raise ValueError(
            "metadata keys mismatch: "
            f"missing={sorted(METADATA_KEYS-set(rows))} "
            f"extra={sorted(set(rows)-METADATA_KEYS)}"
        )
    if rows["SCHEMA"] != METADATA_SCHEMA:
        raise ValueError(f"metadata SCHEMA must be {METADATA_SCHEMA}")
    for key in (
        "PROBE_SHA256",
        "PROBE_PLAN_SHA256",
        "PROBE_RESULTS_ROOT_SHA256",
        "PROBE_RESULTS_UNPRIVILEGED_SHA256",
    ):
        if not HEX64.fullmatch(rows[key]):
            raise ValueError(f"metadata {key} must be lowercase SHA-256")
    return rows


def parse_result(path: Path, label: str) -> dict:
    validate_regular(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"{label}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{label}: root must be object")
    expected = {"schema", "probe_kind", "read_only", "results"}
    if set(data) != expected:
        raise ValueError(
            f"{label}: root keys mismatch: "
            f"missing={sorted(expected-set(data))} extra={sorted(set(data)-expected)}"
        )
    if data["schema"] != RESULT_SCHEMA:
        raise ValueError(f"{label}: schema must be {RESULT_SCHEMA}")
    if data["probe_kind"] != "sysctl":
        raise ValueError(f"{label}: probe_kind must be sysctl")
    if data["read_only"] is not True:
        raise ValueError(f"{label}: read_only must be true")
    if not isinstance(data["results"], list):
        raise ValueError(f"{label}: results must be list")
    return data


def run_gate(project_root: Path, evidence_dir: Path) -> dict:
    errors: list[str] = []
    checks = 0
    metadata_bindings = 0
    result_documents = 0

    def check(fn):
        nonlocal checks
        checks += 1
        try:
            return fn()
        except Exception as exc:
            errors.append(str(exc))
            return None

    sums_path = evidence_dir / "SHA256SUMS"
    sums = check(lambda: parse_sha256s(sums_path))
    if sums is not None:
        if set(sums) != EVIDENCE_MEMBERS:
            errors.append(
                "evidence SHA256SUMS member set mismatch: "
                f"missing={sorted(EVIDENCE_MEMBERS-set(sums))} "
                f"extra={sorted(set(sums)-EVIDENCE_MEMBERS)}"
            )
        else:
            for name in sorted(EVIDENCE_MEMBERS):
                p = evidence_dir / name
                def verify_member(p=p, name=name):
                    validate_regular(p)
                    actual = sha256_file(p)
                    if actual != sums[name]:
                        raise ValueError(
                            f"evidence SHA mismatch for {name}: {actual} != {sums[name]}"
                        )
                check(verify_member)

    metadata = check(lambda: parse_metadata(evidence_dir / "VM-METADATA.txt"))

    root_result = check(
        lambda: parse_result(evidence_dir / "probe-results-root.json", "privileged result")
    )
    if root_result is not None:
        result_documents += 1
    unpriv_result = check(
        lambda: parse_result(
            evidence_dir / "probe-results-unprivileged.json", "unprivileged result"
        )
    )
    if unpriv_result is not None:
        result_documents += 1

    if metadata is not None:
        bindings = [
            (
                "PROBE_SHA256",
                project_root / "probes/sysctl-v1/probe.py",
            ),
            (
                "PROBE_PLAN_SHA256",
                project_root / "probes/sysctl-v1/probe-plan.tsv",
            ),
            (
                "PROBE_RESULTS_ROOT_SHA256",
                evidence_dir / "probe-results-root.json",
            ),
            (
                "PROBE_RESULTS_UNPRIVILEGED_SHA256",
                evidence_dir / "probe-results-unprivileged.json",
            ),
        ]
        for key, path in bindings:
            def verify_binding(key=key, path=path):
                validate_regular(path)
                actual = sha256_file(path)
                if metadata[key] != actual:
                    raise ValueError(
                        f"metadata binding mismatch {key}: "
                        f"{metadata[key]} != {actual}"
                    )
            before = len(errors)
            check(verify_binding)
            if len(errors) == before:
                metadata_bindings += 1

    return {
        "gate": 6,
        "name": "evidence_binding",
        "pass": not errors,
        "checks": checks,
        "evidence_members": len(EVIDENCE_MEMBERS),
        "metadata_bindings": metadata_bindings,
        "result_documents": result_documents,
        "vm_origin_attestation": False,
        "errors": errors,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="SecureLinux-Policy Gate 6 evidence binding")
    ap.add_argument("--project-root", default=".")
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--json-out")
    args = ap.parse_args()

    project_root = Path(args.project_root).resolve()
    evidence_dir = Path(args.evidence_dir)
    if not evidence_dir.is_absolute():
        evidence_dir = (project_root / evidence_dir).resolve()

    report = run_gate(project_root, evidence_dir)
    status = "PASS" if report["pass"] else "FAIL"
    print(
        f"GATE6={status} evidence_binding "
        f"checks={report['checks']} evidence_members={report['evidence_members']} "
        f"metadata_bindings={report['metadata_bindings']} "
        f"result_documents={report['result_documents']} "
        f"errors={len(report['errors'])}"
    )
    print("VM_ORIGIN_ATTESTATION=NOT_PROVEN")
    for err in report["errors"]:
        print(f"ERROR[GATE6]={err}")

    if args.json_out:
        out = Path(args.json_out)
        out.write_text(
            json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
