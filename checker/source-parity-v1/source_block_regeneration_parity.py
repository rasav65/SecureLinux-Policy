#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import stat
import sys
from pathlib import Path

GENERATOR_REL = "tools/source_skeleton_generator.py"
TOOLS_SUMS_REL = "tools/SHA256SUMS"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_regular(path: Path) -> None:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"symlink forbidden: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"regular file required: {path}")


def load_manifest_hash(path: Path, wanted_name: str) -> str:
    validate_regular(path)
    matches = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("  ", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid SHA256SUMS line {lineno}: {path}")
        digest, name = parts
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"invalid SHA-256 at line {lineno}: {path}")
        if name == wanted_name:
            matches.append(digest)
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one {wanted_name} entry in {path}, got {len(matches)}"
        )
    return matches[0]


def load_generator(project_root: Path):
    path = project_root / GENERATOR_REL
    expected = load_manifest_hash(
        project_root / TOOLS_SUMS_REL, path.name
    )
    validate_regular(path)
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(
            f"source skeleton generator SHA mismatch: expected {expected}, got {actual}"
        )

    spec = importlib.util.spec_from_file_location(
        "source_skeleton_generator_for_parity", path
    )
    if spec is None or spec.loader is None:
        raise ValueError("cannot load source skeleton generator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    required = (
        "SUPPORTED_UNIT_KINDS",
        "STATE_REFUSED",
        "STATE_UNSUPPORTED",
        "load_normalizer",
        "load_index",
        "classify_row",
        "render_source_block",
    )
    missing = [name for name in required if not hasattr(module, name)]
    if missing:
        raise ValueError(f"source skeleton generator API missing: {missing}")
    return module


def resolve_input(project_root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else project_root / path


def discover_controls(path: Path) -> list[Path]:
    if path.is_symlink():
        raise ValueError(f"controls path symlink forbidden: {path}")
    if not path.exists() or not path.is_dir():
        raise ValueError(f"controls directory not found: {path}")
    controls = sorted(path.rglob("*.yaml"))
    if not controls:
        raise ValueError(f"no control YAML files found under {path}")
    for control in controls:
        validate_regular(control)
    return controls


def parse_source_block(text: str) -> tuple[str, str]:
    lines = text.split("\n")
    starts = [i for i, line in enumerate(lines) if line == "source:"]
    if len(starts) != 1:
        raise ValueError(f"expected exactly one top-level source: block, got {len(starts)}")
    start = starts[0]
    end = start + 1
    while end < len(lines):
        line = lines[end]
        if line.startswith("  "):
            end += 1
            continue
        break
    block = "\n".join(lines[start:end]) + "\n"

    index_lines = [
        line for line in lines[start + 1:end]
        if re.match(r"^  index_id\s*:", line)
    ]
    if len(index_lines) != 1:
        raise ValueError(
            f"expected exactly one source.index_id line, got {len(index_lines)}"
        )
    raw = index_lines[0].split(":", 1)[1].strip()
    try:
        index_id = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"source.index_id is not canonical JSON string: {exc}") from exc
    if not isinstance(index_id, str) or not index_id:
        raise ValueError("source.index_id must be a non-empty string")
    return block, index_id


def run_parity(
    project_root: Path,
    index_path: Path,
    controls_path: Path,
) -> tuple[bool, dict[str, int], list[str]]:
    generator = load_generator(project_root)
    normalize_text = generator.load_normalizer(project_root)
    rows, rows_by_id = generator.load_index(index_path)
    _ = rows
    controls = discover_controls(controls_path)

    counts = {
        "controls": len(controls),
        "supported": 0,
        "matched": 0,
        "unsupported": 0,
        "missing_index": 0,
        "mismatches": 0,
        "errors": 0,
    }
    details: list[str] = []

    for control in controls:
        label = control.relative_to(controls_path).as_posix()
        try:
            committed, index_id = parse_source_block(
                control.read_text(encoding="utf-8")
            )
        except Exception as exc:
            counts["errors"] += 1
            details.append(f"ERROR {label}: {exc}")
            continue

        row = rows_by_id.get(index_id)
        if row is None:
            counts["missing_index"] += 1
            details.append(f"MISSING_INDEX {label}: {index_id}")
            continue

        unit_kind = row["unit_kind"]
        try:
            result = generator.classify_row(project_root, row, normalize_text)
        except Exception as exc:
            counts["errors"] += 1
            details.append(
                f"ERROR {label}: {index_id} generation failed: {exc}"
            )
            continue

        if result.state == generator.STATE_UNSUPPORTED:
            counts["unsupported"] += 1
            details.append(
                f"UNSUPPORTED {label}: {index_id} unit_kind={unit_kind} "
                f"reason_code={result.reason_code}"
            )
            continue
        if result.state == generator.STATE_REFUSED:
            counts["errors"] += 1
            details.append(
                f"REFUSED {label}: {index_id} reason_code={result.reason_code}"
            )
            continue

        counts["supported"] += 1
        generated = generator.render_source_block(result.source_block)

        if committed == generated:
            counts["matched"] += 1
            details.append(f"MATCH {label}: {index_id} unit_kind={unit_kind}")
        else:
            counts["mismatches"] += 1
            details.append(
                f"MISMATCH {label}: {index_id} unit_kind={unit_kind}"
            )

    passed = (
        counts["controls"] > 0
        and counts["matched"] == counts["controls"]
        and counts["supported"] == counts["controls"]
        and counts["unsupported"] == 0
        and counts["missing_index"] == 0
        and counts["mismatches"] == 0
        and counts["errors"] == 0
    )
    return passed, counts, details


def main() -> int:
    parser = argparse.ArgumentParser(
        description="regenerate committed source: blocks and require byte parity"
    )
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--index", default="index/source-v4/SOURCE-INDEX.tsv")
    parser.add_argument("--controls", default="controls")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    index_path = resolve_input(project_root, args.index)
    controls_path = resolve_input(project_root, args.controls)

    try:
        passed, counts, details = run_parity(
            project_root, index_path, controls_path
        )
    except Exception as exc:
        print(f"SOURCE_BLOCK_REGENERATION_PARITY=FAIL setup_error=1")
        print(f"ERROR {exc}")
        return 1

    for detail in details:
        print(detail)
    print(
        "SOURCE_BLOCK_REGENERATION_PARITY="
        f"{'PASS' if passed else 'FAIL'} "
        f"controls={counts['controls']} "
        f"supported={counts['supported']} "
        f"matched={counts['matched']} "
        f"unsupported={counts['unsupported']} "
        f"missing_index={counts['missing_index']} "
        f"mismatches={counts['mismatches']} "
        f"errors={counts['errors']}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
