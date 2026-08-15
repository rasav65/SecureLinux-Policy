#!/usr/bin/env python3
from __future__ import annotations

import csv
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[2]
PARITY = ROOT / "checker/source-parity-v1/source_block_regeneration_parity.py"
INDEX = ROOT / "index/source-v4/SOURCE-INDEX.tsv"
CONTROLS = ROOT / "controls"
EXPECTED_PARITY_SHA = "f62ed3b2d0da629a8adc11b50637d23b7595014078994eb6b17a27be7c9d13cb"

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

assert sha(PARITY) == EXPECTED_PARITY_SHA


def run(*args: str):
    cp = subprocess.run(
        [
            sys.executable,
            "-B",
            str(PARITY),
            "--project-root",
            str(ROOT),
            *args,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    return cp.returncode, cp.stdout, cp.stderr


def load_parity():
    spec = importlib.util.spec_from_file_location(
        "source_block_parity_tested", PARITY
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def first_control():
    controls = sorted(CONTROLS.rglob("*.yaml"))
    assert len(controls) == 5
    path = controls[0]
    text = path.read_text(encoding="utf-8")
    module = load_parity()
    block, index_id = module.parse_source_block(text)
    assert block.startswith("source:\n")
    return path, text, index_id


def write_one_control(directory: Path, source_path: Path, text: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / source_path.name
    target.write_text(text, encoding="utf-8", newline="\n")
    return target


def mutate_source_field(text: str, field: str, mutate):
    lines = text.split("\n")
    start = lines.index("source:")
    hits = []
    for i in range(start + 1, len(lines)):
        if not lines[i].startswith("  "):
            break
        if lines[i].startswith(f"  {field}:"):
            hits.append(i)
    assert len(hits) == 1, (field, hits)
    i = hits[0]
    raw = lines[i].split(":", 1)[1].strip()
    value = json.loads(raw)
    lines[i] = f"  {field}: {json.dumps(mutate(value), ensure_ascii=False)}"
    return "\n".join(lines)


# Positive current tree: all five controls are supported and byte-identical.
rc, out, err = run()
assert rc == 0, (out, err)
assert (
    "SOURCE_BLOCK_REGENERATION_PARITY=PASS "
    "controls=5 supported=5 matched=5 unsupported=0 "
    "missing_index=0 mismatches=0 errors=0"
) in out
assert out.count("MATCH ") == 5

control_path, original, index_id = first_control()

# Negative 1: quote hand edit.
with tempfile.TemporaryDirectory(prefix="slp-parity-quote-") as td:
    controls = Path(td) / "controls"
    mutated = mutate_source_field(
        original, "quote", lambda value: value + " PARITY-MUTATION"
    )
    write_one_control(controls, control_path, mutated)
    rc, out, err = run("--controls", str(controls))
    assert rc == 1, (out, err)
    assert "MISMATCH " in out
    assert "controls=1 supported=1 matched=0" in out
    assert "mismatches=1 errors=0" in out

# Negative 2: quote_sha256 hand edit.
with tempfile.TemporaryDirectory(prefix="slp-parity-quote-sha-") as td:
    controls = Path(td) / "controls"
    mutated = mutate_source_field(
        original, "quote_sha256", lambda value: "0" * 64
    )
    write_one_control(controls, control_path, mutated)
    rc, out, err = run("--controls", str(controls))
    assert rc == 1, (out, err)
    assert "MISMATCH " in out
    assert "mismatches=1 errors=0" in out

# Negative 3: locator hand edit.
with tempfile.TemporaryDirectory(prefix="slp-parity-locator-") as td:
    controls = Path(td) / "controls"
    mutated = mutate_source_field(
        original, "locator", lambda value: value + ".999"
    )
    write_one_control(controls, control_path, mutated)
    rc, out, err = run("--controls", str(controls))
    assert rc == 1, (out, err)
    assert "MISMATCH " in out
    assert "mismatches=1 errors=0" in out

# Negative 4: a control whose index row has an unsupported unit_kind is
# explicitly classified UNSUPPORTED and fails closed.
with tempfile.TemporaryDirectory(prefix="slp-parity-unsupported-") as td:
    td = Path(td)
    controls = td / "controls"
    write_one_control(controls, control_path, original)

    alt_index = td / "SOURCE-INDEX.tsv"
    with INDEX.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    changed = 0
    for row in rows:
        if row["index_id"] == index_id:
            row["unit_kind"] = "main-numbered-clause"
            changed += 1
    assert changed == 1
    with alt_index.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=fields,
            delimiter="\t",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)

    rc, out, err = run(
        "--controls", str(controls), "--index", str(alt_index)
    )
    assert rc == 1, (out, err)
    assert "UNSUPPORTED " in out
    assert "unit_kind=main-numbered-clause" in out
    assert "unsupported=1" in out
    assert "mismatches=0 errors=0" in out

# Negative 5: a control referring to an absent row is explicitly
# classified MISSING_INDEX and fails closed.
with tempfile.TemporaryDirectory(prefix="slp-parity-missing-index-") as td:
    controls = Path(td) / "controls"
    mutated = mutate_source_field(
        original, "index_id", lambda value: "SRC-NOT-PRESENT"
    )
    write_one_control(controls, control_path, mutated)
    rc, out, err = run("--controls", str(controls))
    assert rc == 1, (out, err)
    assert "MISSING_INDEX " in out
    assert "missing_index=1" in out
    assert "mismatches=0 errors=0" in out

# Negative 6: malformed/duplicated top-level source block is an ERROR.
with tempfile.TemporaryDirectory(prefix="slp-parity-duplicate-source-") as td:
    controls = Path(td) / "controls"
    malformed = original.rstrip("\n") + "\nsource:\n  index_id: \"SRC-0016\"\n"
    write_one_control(controls, control_path, malformed)
    rc, out, err = run("--controls", str(controls))
    assert rc == 1, (out, err)
    assert "ERROR " in out
    assert "expected exactly one top-level source: block" in out
    assert "errors=1" in out

print(
    "SOURCE_BLOCK_PARITY_TESTS=PASS "
    "positive=5 negative_quote=1 negative_quote_sha=1 "
    "negative_locator=1 negative_unsupported_kind=1 "
    "negative_missing_index=1 negative_duplicate_source=1"
)
