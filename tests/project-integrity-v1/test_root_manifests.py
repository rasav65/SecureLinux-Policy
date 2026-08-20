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

# Every tracked test-local SHA256SUMS entry must resolve to a tracked regular
# file with matching bytes. Ignored runtime/cache files must never leak into
# current test manifests.
tracked = set(
    run(["git", "ls-files"], ROOT).stdout.splitlines()
)
for manifest_rel in sorted(
    rel for rel in tracked
    if rel.startswith("tests/") and rel.endswith("/SHA256SUMS")
):
    manifest_path = ROOT / manifest_rel
    for lineno, line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line:
            continue
        match = __import__("re").fullmatch(r"([0-9a-f]{64})  (.+)", line)
        assert match is not None, (manifest_rel, lineno, line)
        rel_target = str(
            (Path(manifest_rel).parent / match.group(2)).as_posix()
        )
        assert "__pycache__/" not in rel_target, (manifest_rel, lineno, rel_target)
        assert rel_target in tracked, (manifest_rel, lineno, rel_target)
        target = ROOT / rel_target
        assert target.is_file() and not target.is_symlink(), (
            manifest_rel, lineno, rel_target
        )
        cp = run(["sha256sum", rel_target], ROOT)
        assert cp.returncode == 0, cp.stdout + cp.stderr
        assert cp.stdout.split()[0] == match.group(1), (
            manifest_rel, lineno, rel_target
        )


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
