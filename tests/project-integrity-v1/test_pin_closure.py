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


def run_tool(root: Path, tool: Path, inputs):
    return run(
        ["/usr/bin/python3", "-I", "-S", "-B", str(tool), "--check", *inputs],
        root,
    )


def closure(root: Path, tool: Path, inputs) -> list[str]:
    cp = run_tool(root, tool, inputs)
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
    fields = row.split("\t")
    stale_row = "\t".join([fields[0], "0" * 64] + fields[2:])
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

# Cases 5-8: a path not yet recorded in any carrier is pinned by every
# SHA256SUMS ancestor whose scope covers it. The scope is read from bytes:
# TREE lists every git-visible file of the subtree, DIR has no entries with
# '/' and lists every file of its own directory; otherwise it is undefined
# and a new path below it fails closed with rc=2. The root manifests pin any
# git-visible path.
NEW_FILE_CASES = (
    (
        "tests/project-integrity-v1/case5-new.txt",
        {
            "tests/project-integrity-v1/SHA256SUMS",
            "PROJECT-FILES.sha256",
            "SHA256SUMS",
        },
    ),
    (
        "product/contracts/case6-new.json",
        {
            "product/SHA256SUMS",
            "PROJECT-FILES.sha256",
            "SHA256SUMS",
        },
    ),
    (
        "archive/engineering-review-20260731/review/case7-new.txt",
        {
            "archive/engineering-review-20260731/review/SHA256SUMS",
            "archive/engineering-review-20260731/SHA256SUMS",
            "PROJECT-FILES.sha256",
            "SHA256SUMS",
        },
    ),
)
UNDEFINED_SCOPE_MANIFEST = "tests/project-integrity-v1/SHA256SUMS"
UNDEFINED_SCOPE_DROPPED_ENTRY = "README.md"
UNDEFINED_SCOPE_NEW_FILE = "tests/project-integrity-v1/case8-new.txt"


def tree_copy(tmp: str) -> Path:
    copy = Path(tmp) / "repo"
    shutil.copytree(ROOT, copy, symlinks=True)
    return copy


def add_new_file(copy: Path, rel: str) -> None:
    path = copy / rel
    assert path.parent.is_dir(), ("directory missing", rel)
    assert not path.exists(), ("new path already exists", rel)
    path.write_text("new file\n", encoding="utf-8")
    ignored = run(["git", "check-ignore", "-q", "--", rel], copy)
    assert ignored.returncode == 1, ("new path is not git-visible", rel)


for new_rel, new_expected in NEW_FILE_CASES:
    with tempfile.TemporaryDirectory(prefix="slp-pin-closure-") as tmp:
        copy = tree_copy(tmp)
        add_new_file(copy, new_rel)
        assert_equal_sets(
            (new_rel,), closure(copy, copy / "tools/pin-closure.py", (new_rel,)), new_expected
        )
    assert not Path(tmp).exists(), tmp

# Case 8: an ancestor SHA256SUMS that no longer lists every file of its
# directory has an undefined scope; a new path below it is rc=2.
with tempfile.TemporaryDirectory(prefix="slp-pin-closure-") as tmp:
    copy = tree_copy(tmp)
    manifest = copy / UNDEFINED_SCOPE_MANIFEST
    lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
    kept = [
        line for line in lines
        if not line.endswith("  " + UNDEFINED_SCOPE_DROPPED_ENTRY + "\n")
    ]
    assert len(kept) == len(lines) - 1, (UNDEFINED_SCOPE_MANIFEST, lines)
    manifest.write_text("".join(kept), encoding="utf-8")
    add_new_file(copy, UNDEFINED_SCOPE_NEW_FILE)
    cp = run_tool(copy, copy / "tools/pin-closure.py", (UNDEFINED_SCOPE_NEW_FILE,))
    assert cp.returncode == 2, (UNDEFINED_SCOPE_NEW_FILE, cp.returncode, cp.stdout, cp.stderr)
assert not Path(tmp).exists(), tmp

print(f"PIN_CLOSURE_CASES=PASS_{len(CASES) + 1 + len(NEW_FILE_CASES) + 1}")
