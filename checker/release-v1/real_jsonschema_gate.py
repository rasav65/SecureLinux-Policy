#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import platform
from pathlib import Path

EVIDENCE_SCHEMA = "securelinux-policy-real-jsonschema-release-evidence/v1"
DRAFT_URI = "https://json-schema.org/draft/2020-12/schema"
MIN_MATRIX_CASES = 50
MIN_NEWLINE_CASES = 16


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require_real_jsonschema(project_root: Path):
    try:
        import jsonschema
        from jsonschema import Draft202012Validator
    except Exception as exc:
        raise RuntimeError(f"jsonschema dependency unavailable: {exc}") from exc

    try:
        version = importlib.metadata.version("jsonschema")
    except Exception as exc:
        raise RuntimeError(
            f"cannot resolve jsonschema distribution version: {exc}"
        ) from exc
    if not version:
        raise RuntimeError("empty jsonschema distribution version")

    origin = Path(jsonschema.__file__).resolve()
    try:
        origin.relative_to(project_root.resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError("jsonschema module is shadowed from inside project tree")

    return Draft202012Validator, version


def run_gate(project_root: Path, dependency_loader=require_real_jsonschema) -> dict:
    root = project_root.resolve()
    errors: list[str] = []

    report = {
        "schema": EVIDENCE_SCHEMA,
        "pass": False,
        "draft": "2020-12",
        "draft_uri": DRAFT_URI,
        "validator_class": "Draft202012Validator",
        "jsonschema_version": None,
        "python_version": platform.python_version(),
        "inputs": {},
        "matrix": {},
        "active_controls": {},
        "checks": {},
        "errors": errors,
    }

    schema_path = root / "checker/gates-v3/CONTROL-SCHEMA.json"
    checker_path = root / "checker/gates-v3/checker.py"
    parity_path = root / "tests/gates-v3/test_schema_runtime_parity.py"
    gate_path = Path(__file__).resolve()

    for label, path in (
        ("control_schema", schema_path),
        ("checker", checker_path),
        ("parity_test", parity_path),
        ("release_gate", gate_path),
    ):
        if not path.is_file():
            errors.append(f"missing required input: {path}")
        else:
            report["inputs"][f"{label}_sha256"] = sha256_file(path)
    if errors:
        return report

    try:
        Validator, version = dependency_loader(root)
        report["jsonschema_version"] = version
    except Exception as exc:
        errors.append(str(exc))
        return report

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"cannot load CONTROL-SCHEMA.json: {exc}")
        return report

    if schema.get("$schema") != DRAFT_URI:
        errors.append(f"schema $schema must be {DRAFT_URI}")
        return report

    try:
        Validator.check_schema(schema)
        validator = Validator(schema)
        report["checks"]["draft202012_check_schema"] = True
    except Exception as exc:
        errors.append(f"Draft202012Validator.check_schema failed: {exc}")
        return report

    try:
        checker = load_module("slp_checker_release", checker_path)
        parity = load_module("slp_schema_runtime_parity_release", parity_path)
    except Exception as exc:
        errors.append(f"cannot load checker/parity modules: {exc}")
        return report

    generation_parity = (
        schema_path.read_text(encoding="utf-8") == checker.render_control_schema()
    )
    report["checks"]["schema_generation_parity"] = generation_parity
    if not generation_parity:
        errors.append(
            "committed schema differs from checker.render_control_schema()"
        )

    cases = list(parity.ALL_CASES)
    newline_cases = list(parity.NEWLINE_CASES)
    report["matrix"]["total_cases"] = len(cases)
    report["matrix"]["newline_cases"] = len(newline_cases)
    if len(cases) < MIN_MATRIX_CASES:
        errors.append(
            f"differential matrix shrank below {MIN_MATRIX_CASES} cases"
        )
    if len(newline_cases) < MIN_NEWLINE_CASES:
        errors.append(
            f"newline matrix shrank below {MIN_NEWLINE_CASES} cases"
        )

    kinds = set(checker.KIND_RULES)
    matrix_kinds = {
        rec.get("parameter", {}).get("kind")
        for _, rec in cases
        if isinstance(rec, dict)
    }
    missing_kinds = sorted(kinds - matrix_kinds)
    report["matrix"]["kind_count"] = len(kinds)
    report["matrix"]["missing_kinds"] = missing_kinds
    if missing_kinds:
        errors.append(f"differential matrix misses kinds: {missing_kinds}")

    runtime_real = []
    emulator_real = []
    accepted_by_kind = {kind: 0 for kind in kinds}
    rejected_by_kind = {kind: 0 for kind in kinds}

    for name, record in cases:
        runtime_accepts = not parity.runtime_errors(record)
        real_accepts = not list(validator.iter_errors(record))
        emulator_accepts = not parity.schema_errors(record, schema)

        kind = (
            record.get("parameter", {}).get("kind")
            if isinstance(record, dict)
            else None
        )
        if kind in kinds:
            if runtime_accepts:
                accepted_by_kind[kind] += 1
            else:
                rejected_by_kind[kind] += 1

        if runtime_accepts != real_accepts:
            runtime_real.append(name)
        if emulator_accepts != real_accepts:
            emulator_real.append(name)

    report["matrix"]["runtime_real_disagreements"] = runtime_real
    report["matrix"]["emulator_real_disagreements"] = emulator_real
    report["matrix"]["accepted_by_kind"] = accepted_by_kind
    report["matrix"]["rejected_by_kind"] = rejected_by_kind

    if runtime_real:
        errors.append(
            f"runtime vs real Draft202012Validator disagreements: {runtime_real}"
        )
    if emulator_real:
        errors.append(
            f"emulator vs real Draft202012Validator disagreements: {emulator_real}"
        )

    one_sided = sorted(
        kind
        for kind in kinds
        if accepted_by_kind[kind] == 0 or rejected_by_kind[kind] == 0
    )
    report["matrix"]["one_sided_kinds"] = one_sided
    if one_sided:
        errors.append(
            f"matrix lacks accept+reject coverage for kinds: {one_sided}"
        )

    try:
        records, files = checker.load_controls(root / "controls")
    except Exception as exc:
        errors.append(f"cannot load active controls: {exc}")
        return report

    runtime_invalid = []
    real_invalid = []
    for path, record in records:
        where = path.relative_to(root).as_posix()
        runtime_errors = checker.validate_record_schema(record, where)
        if not runtime_errors:
            runtime_errors = checker.validate_parameter_closure(record, where)
        real_errors = [e.message for e in validator.iter_errors(record)]
        if runtime_errors:
            runtime_invalid.append(where)
        if real_errors:
            real_invalid.append(where)

    report["active_controls"] = {
        "count": len(files),
        "runtime_invalid": runtime_invalid,
        "real_schema_invalid": real_invalid,
    }
    if runtime_invalid:
        errors.append(f"runtime-invalid active controls: {runtime_invalid}")
    if real_invalid:
        errors.append(f"real-schema-invalid active controls: {real_invalid}")

    report["checks"]["real_validator_required"] = True
    report["checks"]["runtime_real_parity"] = not runtime_real
    report["checks"]["emulator_real_parity"] = not emulator_real
    report["checks"]["all_kinds_bidirectional"] = (
        not one_sided and not missing_kinds
    )
    report["checks"]["active_controls_real_valid"] = not real_invalid
    report["checks"]["active_controls_runtime_valid"] = not runtime_invalid
    report["pass"] = not errors
    return report


def format_report(report: dict) -> str:
    status = "PASS" if report["pass"] else "FAIL"
    matrix = report.get("matrix", {})
    controls = report.get("active_controls", {})
    lines = [
        f"REAL_JSONSCHEMA_RELEASE_GATE={status}",
        f"JSONSCHEMA_VERSION={report.get('jsonschema_version') or 'UNAVAILABLE'}",
        f"VALIDATOR={report.get('validator_class')}",
        f"DRAFT={report.get('draft')}",
        f"MATRIX_CASES={matrix.get('total_cases', 0)}",
        f"NEWLINE_CASES={matrix.get('newline_cases', 0)}",
        f"KIND_COUNT={matrix.get('kind_count', 0)}",
        f"RUNTIME_REAL_DISAGREEMENTS={len(matrix.get('runtime_real_disagreements', []))}",
        f"EMULATOR_REAL_DISAGREEMENTS={len(matrix.get('emulator_real_disagreements', []))}",
        f"ACTIVE_CONTROLS={controls.get('count', 0)}",
        f"ACTIVE_REAL_SCHEMA_INVALID={len(controls.get('real_schema_invalid', []))}",
        f"ACTIVE_RUNTIME_INVALID={len(controls.get('runtime_invalid', []))}",
    ]
    for err in report["errors"]:
        lines.append(f"ERROR[REAL_JSONSCHEMA]={err}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Mandatory fail-closed real Draft 2020-12 release gate"
    )
    ap.add_argument("--project-root", default=".")
    ap.add_argument("--json-out")
    args = ap.parse_args()

    report = run_gate(Path(args.project_root))
    print(format_report(report), end="")
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(
                report,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
