#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL_REL = "tools/refresh-pins.py"
BASELINE = "tests/documentation-v1/CURRENT-MARKDOWN-REVIEW-BASELINE.tsv"
ADAPTER = "product/adapters/product-cron-command-paths-write-protection-check-v1.py"
REGISTRY = "product/ADAPTER-REGISTRY.tsv"


def run(root: Path, *args: str):
    return subprocess.run(["/usr/bin/python3", "-I", "-B", str(root / TOOL_REL), *args],
                          cwd=root, text=True, capture_output=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_state(root: Path) -> dict[str, tuple[str, int]]:
    listed = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                            cwd=root, text=True, capture_output=True, check=True).stdout.split("\0")
    return {rel: (sha256(root / rel), (root / rel).stat().st_mode & 0o7777)
            for rel in listed if rel and (root / rel).is_file()}


def fresh_copy(tmp: str) -> Path:
    copy = Path(tmp) / "repo"
    shutil.copytree(ROOT, copy, symlinks=True)
    # The copy's HEAD must equal its tree, whatever the state of the working tree
    # under test, so that "changed against HEAD" means only the fixture edits.
    for argv in (["git", "add", "-A"],
                 ["git", "-c", "user.name=refresh-pins-test", "-c", "user.email=refresh-pins-test@localhost",
                  "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "fixture base"]):
        cp = subprocess.run(argv, cwd=copy, text=True, capture_output=True)
        assert cp.returncode == 0, (argv, cp.stdout, cp.stderr)
    return copy


assert (ROOT / TOOL_REL).is_file(), TOOL_REL

# The tool's truth formula equals the one the documentation gate uses: on a
# consistent tree every state-document row carries the tool's value.
spec = importlib.util.spec_from_file_location("slp_refresh_pins", ROOT / TOOL_REL)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
truth_inputs, state_docs = tool.baseline_lists(ROOT)
truth = tool.truth_sha256(ROOT, truth_inputs)
rows = [line.split("\t") for line in (ROOT / BASELINE).read_text(encoding="utf-8").splitlines()[1:] if line]
state_rows = [r for r in rows if r[0] in state_docs]
assert len(state_rows) == len(state_docs), (len(state_rows), len(state_docs))
assert all(r[2] == truth for r in state_rows), "tool truth formula differs from the documentation gate"

with tempfile.TemporaryDirectory(prefix="slp-refresh-pins-") as tmp:
    copy = fresh_copy(tmp)

    # A consistent tree checks clean.
    cp = run(copy, "--check")
    assert cp.returncode == 0 and "REFRESH_PINS_RESULT=PASS" in cp.stdout, (cp.returncode, cp.stdout, cp.stderr)

    # An adapter edit: --check reports stale pins, --write refreshes all of them,
    # a second --check is clean.
    adapter = copy / ADAPTER
    adapter.write_bytes(adapter.read_bytes() + b"\n# refresh-pins fixture edit\n")
    cp = run(copy, "--check")
    assert cp.returncode == 1 and "STALE " + REGISTRY in cp.stdout, (cp.returncode, cp.stdout, cp.stderr)
    # Only SHA columns of the registry change, so truth_sha256 stays and no
    # --reviewed-truth is needed.
    truth_before = tool.truth_sha256(copy, truth_inputs)
    cp = run(copy, "--write")
    assert cp.returncode == 0 and "REFRESH_PINS_RESULT=PASS" in cp.stdout, (cp.returncode, cp.stdout, cp.stderr)
    assert tool.truth_sha256(copy, truth_inputs) == truth_before
    row = next(l.split("\t") for l in (copy / REGISTRY).read_text(encoding="utf-8").splitlines()
               if l.startswith("cron-command-paths-write-protection\t"))
    assert row[7] == sha256(adapter), row
    cp = run(copy, "--check")
    assert cp.returncode == 0, (cp.stdout, cp.stderr)

    # A changed review-bound document is refreshed only when named with --reviewed.
    # With an adapter edit in the same run, earlier stages (adapter pins, the
    # artifact, nested SHA256SUMS) write before the baseline stage refuses; the
    # refused --write leaves every file as it was.
    adapter.write_bytes(adapter.read_bytes() + b"# second fixture edit\n")
    doc = copy / "docs/README.md"
    doc.write_bytes(doc.read_bytes() + b"\n")
    before = tree_state(copy)
    cp = run(copy, "--write")
    assert cp.returncode == 2 and "--reviewed docs/README.md" in cp.stderr, (cp.returncode, cp.stdout, cp.stderr)
    assert "REFRESH_PINS_ROLLBACK=" in cp.stderr and "REFRESH_PINS_ROLLBACK=0" not in cp.stderr, cp.stderr
    assert tree_state(copy) == before
    cp = run(copy, "--write", "--reviewed", "docs/README.md")
    assert cp.returncode == 0, (cp.stdout, cp.stderr)
    cp = run(copy, "--check")
    assert cp.returncode == 0, (cp.stdout, cp.stderr)

with tempfile.TemporaryDirectory(prefix="slp-refresh-pins-") as tmp:
    copy = fresh_copy(tmp)
    # A composition change (a non-SHA cell of a truth input) changes truth_sha256:
    # --write without --reviewed-truth fails, with it passes.
    ledger = copy / "index/source-v4/DISPOSITION-LEDGER.tsv"
    lines = ledger.read_text(encoding="utf-8").split("\n")
    cells = lines[1].split("\t")
    cells[2] += " (fixture edit)"
    lines[1] = "\t".join(cells)
    ledger.write_text("\n".join(lines), encoding="utf-8")
    assert tool.truth_sha256(copy, truth_inputs) != truth
    cp = run(copy, "--write")
    assert cp.returncode == 2 and "--reviewed-truth" in cp.stderr, (cp.returncode, cp.stdout, cp.stderr)
    cp = run(copy, "--write", "--reviewed-truth")
    assert cp.returncode == 0 and "REFRESH_PINS_RESULT=PASS" in cp.stdout, (cp.returncode, cp.stdout, cp.stderr)

with tempfile.TemporaryDirectory(prefix="slp-refresh-pins-") as tmp:
    copy = fresh_copy(tmp)
    # A stale pin for a path that did not change against HEAD is an error.
    sums = copy / "tests/project-integrity-v1/SHA256SUMS"
    text = sums.read_text(encoding="utf-8")
    line = next(l for l in text.splitlines() if l.endswith("  README.md"))
    sums.write_text(text.replace(line, "0" * 64 + "  README.md"), encoding="utf-8")
    neighbour = copy / "tests/project-integrity-v1/test_pin_closure.py"
    neighbour.write_bytes(neighbour.read_bytes() + b"\n")
    cp = run(copy, "--write")
    assert cp.returncode == 2 and "unchanged against HEAD" in cp.stderr, (cp.returncode, cp.stdout, cp.stderr)

with tempfile.TemporaryDirectory(prefix="slp-refresh-pins-") as tmp:
    copy = fresh_copy(tmp)
    # A new file that no carrier lists is reported, not silently added.
    (copy / "tests/project-integrity-v1/unlisted.txt").write_text("x\n", encoding="utf-8")
    cp = run(copy, "--check")
    assert cp.returncode == 2 and "listed by no carrier" in cp.stderr, (cp.returncode, cp.stdout, cp.stderr)

with tempfile.TemporaryDirectory(prefix="slp-refresh-pins-") as tmp:
    copy = fresh_copy(tmp)
    # A control-yaml edit: the generator checks control SHA against
    # CONTROL-MANIFEST.tsv, so --write refreshes the manifest before the artifact.
    control = next((copy / "controls/fstec-core/linux-2022").glob("*-2.4.1-*.yaml"))
    control.write_bytes(control.read_bytes() + b"# refresh-pins fixture edit\n")
    cp = run(copy, "--write")
    assert cp.returncode == 0 and "REFRESH_PINS_RESULT=PASS" in cp.stdout, (cp.returncode, cp.stdout, cp.stderr)
    manifest = (copy / "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv").read_text(encoding="utf-8")
    assert sha256(control) in manifest
    cp = run(copy, "--check")
    assert cp.returncode == 0, (cp.stdout, cp.stderr)

# Каталог на документ: любой controls/fstec-core/<каталог>/CONTROL-MANIFEST.tsv — carrier.
for rel, expected in (
    ("controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv", True),
    ("controls/fstec-core/configuration-2026/CONTROL-MANIFEST.tsv", True),
    ("controls/fstec-core/CONTROL-MANIFEST.tsv", False),
    ("controls/fstec-core/a/b/CONTROL-MANIFEST.tsv", False),
    ("controls/fstec-core/Bad_Dir/CONTROL-MANIFEST.tsv", False),
):
    assert tool.is_control_manifest(rel) is expected, rel

print("REFRESH_PINS_TEST=PASS")
