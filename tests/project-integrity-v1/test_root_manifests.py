#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/rebuild-root-manifests.py"
IGNORED = (
    "archive/engineering-donor-v16.2.11/snapshot/.securelinux-ng-state/check.txt",
    "archive/engineering-donor-v16.2.11/snapshot/.securelinux-ng-state/report.json",
)


def run(argv, cwd):
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True)


cp = run([sys.executable, "-B", str(TOOL), "--project-root", str(ROOT), "--check"], ROOT)
assert cp.returncode == 0, cp.stdout + cp.stderr

for manifest in ("PROJECT-FILES.sha256", "SHA256SUMS"):
    text = (ROOT / manifest).read_text(encoding="utf-8")
    for ignored in IGNORED:
        assert ignored not in text, (manifest, ignored)

cp = run(["sha256sum", "-c", "SHA256SUMS"], ROOT)
assert cp.returncode == 0, cp.stdout + cp.stderr


# Synthetic nested .gitignore fixture.
with tempfile.TemporaryDirectory(prefix="slp-root-manifest-") as td:
    repo = Path(td) / "repo"
    repo.mkdir()
    assert run(["git", "init", "-q"], repo).returncode == 0

    (repo / ".gitignore").write_text(".runtime/\n", encoding="utf-8")
    (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    (repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    (repo / ".runtime").mkdir()
    (repo / ".runtime/state.txt").write_text("runtime\n", encoding="utf-8")

    assert run(["git", "add", ".gitignore", "tracked.txt"], repo).returncode == 0

    cp = run([sys.executable, "-B", str(TOOL), "--project-root", str(repo)], repo)
    assert cp.returncode == 0, cp.stdout + cp.stderr

    ptext = (repo / "PROJECT-FILES.sha256").read_text(encoding="utf-8")
    rtext = (repo / "SHA256SUMS").read_text(encoding="utf-8")
    assert "tracked.txt" in ptext
    assert "untracked.txt" in ptext
    assert ".runtime/state.txt" not in ptext
    assert ".runtime/state.txt" not in rtext

    cp = run(
        [sys.executable, "-B", str(TOOL), "--project-root", str(repo), "--check"],
        repo,
    )
    assert cp.returncode == 0, cp.stdout + cp.stderr

print("ROOT_MANIFEST_POLICY=PASS actual=1 fixture=1 ignored_runtime=2")
