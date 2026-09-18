#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/pin-closure.py"
BASELINE = "tests/documentation-v1/CURRENT-MARKDOWN-REVIEW-BASELINE.tsv"
BASELINE_MANIFEST = "tests/documentation-v1/SHA256SUMS"

# Pin carriers in scope: every SHA256SUMS, every *.sha256,
# tests/documentation-v1/CURRENT-MARKDOWN-REVIEW-BASELINE.tsv,
# controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv and the root manifests.
# SHA literals in tests and JSON are out of scope.
# Expected closures are literals: they change only by explicit decision.
CASES = (
    (
        (
            "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.1-group-mode.yaml",
            "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.1-passwd-mode.yaml",
            "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.1-shadow-go-rwx.yaml",
        ),
        {
            "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv",
            "controls/fstec-core/linux-2022/SHA256SUMS",
            "PROJECT-FILES.sha256",
            "SHA256SUMS",
        },
    ),
    (
        ("product/APPLY-KIND-REGISTRY.tsv",),
        {
            "product/SHA256SUMS",
            "PROJECT-FILES.sha256",
            "SHA256SUMS",
        },
    ),
    (
        ("tests/documentation-v1/CURRENT-MARKDOWN-REVIEW-BASELINE.tsv",),
        {
            "tests/documentation-v1/SHA256SUMS",
            "PROJECT-FILES.sha256",
            "SHA256SUMS",
        },
    ),
)


def run(argv, cwd):
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def closure(root: Path, tool: Path, inputs) -> list[str]:
    cp = run(
        ["/usr/bin/python3", "-I", "-S", "-B", str(tool), "--check", *inputs],
        root,
    )
    assert cp.returncode == 0, (inputs, cp.returncode, cp.stdout, cp.stderr)
    return cp.stdout.splitlines()


def assert_equal_sets(inputs, lines, expected) -> None:
    assert all(lines), (inputs, "empty output line", lines)
    actual = set(lines)
    assert len(actual) == len(lines), (inputs, "duplicate output line", lines)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    assert not missing and not extra, (inputs, "missing", missing, "extra", extra)


assert TOOL.is_file(), "tools/pin-closure.py is missing"

for inputs, expected in CASES:
    for rel in inputs:
        assert (ROOT / rel).is_file(), ("input missing", rel)
    assert_equal_sets(inputs, closure(ROOT, TOOL, inputs), expected)

# Case 4: the closure follows carrier paths, not hash freshness. In a copy of
# the tree the baseline bytes change so that its manifest pin is stale; the
# closure must stay equal to case 3.
stale_inputs, stale_expected = CASES[2]
assert stale_inputs == (BASELINE,), stale_inputs
with tempfile.TemporaryDirectory(prefix="slp-pin-closure-") as tmp:
    copy = Path(tmp) / "repo"
    shutil.copytree(ROOT, copy, symlinks=True)
    baseline = copy / BASELINE
    text = baseline.read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith("README.md\t"))
    stale_row = "README.md\t" + "0" * 64
    assert row != stale_row, row
    baseline.write_text(text.replace(row + "\n", stale_row + "\n", 1), encoding="utf-8")
    pinned = {
        line.split("  ", 1)[1]: line.split("  ", 1)[0]
        for line in (copy / BASELINE_MANIFEST).read_text(encoding="utf-8").splitlines()
        if line
    }
    assert pinned[Path(BASELINE).name] != sha256(baseline), "baseline pin is not stale"
    assert_equal_sets(
        stale_inputs, closure(copy, copy / "tools/pin-closure.py", stale_inputs), stale_expected
    )
assert not Path(tmp).exists(), tmp

print(f"PIN_CLOSURE_CASES=PASS_{len(CASES) + 1}")
