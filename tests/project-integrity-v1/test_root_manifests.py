#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/rebuild-root-manifests.py"
ROOT_IGNORED = (
    "archive/engineering-donor-v16.2.11/snapshot/.securelinux-ng-state/check.txt",
    "archive/engineering-donor-v16.2.11/snapshot/.securelinux-ng-state/report.json",
)
PINNED_HISTORICAL_MANIFEST_EXCEPTIONS = {
    (
        "archive/engineering-donor-v16.2.11/SHA256SUMS",
        "snapshot/.securelinux-ng-state/check.txt",
        "d04f6995e6e232a3fc6b546d24d0f0b0ad905bfd01f2836d0392b8502eaf9503",
    ),
    (
        "archive/engineering-donor-v16.2.11/SHA256SUMS",
        "snapshot/.securelinux-ng-state/report.json",
        "47622978f0c0ef811b65643db9a35e06b3d267042bff3717f1e751400610f035",
    ),
}


def run(argv, cwd):
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


cp = run([sys.executable, "-B", str(TOOL), "--project-root", str(ROOT), "--check"], ROOT)
assert cp.returncode == 0, cp.stdout + cp.stderr

for manifest in ("PROJECT-FILES.sha256", "SHA256SUMS"):
    text = (ROOT / manifest).read_text(encoding="utf-8")
    for ignored in ROOT_IGNORED:
        assert ignored not in text, (manifest, ignored)

cp = run(["sha256sum", "-c", "SHA256SUMS"], ROOT)
assert cp.returncode == 0, cp.stdout + cp.stderr

tracked = set(run(["git", "ls-files"], ROOT).stdout.splitlines())
local_manifests = sorted(
    rel for rel in tracked
    if rel != "SHA256SUMS" and rel.endswith("/SHA256SUMS")
)
checked_entries = 0
seen_exceptions = set()

for manifest_rel in local_manifests:
    manifest_path = ROOT / manifest_rel
    assert manifest_path.is_file() and not manifest_path.is_symlink(), manifest_rel
    base = Path(manifest_rel).parent
    for lineno, line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        assert match is not None, (manifest_rel, lineno, line)
        expected, local_text = match.groups()
        local = Path(local_text)
        assert not local.is_absolute(), (manifest_rel, lineno, local)
        assert ".." not in local.parts, (manifest_rel, lineno, local)

        exception_key = (manifest_rel, local_text, expected)
        if exception_key in PINNED_HISTORICAL_MANIFEST_EXCEPTIONS:
            rel_target = (base / local).as_posix()
            ignored = run(["git", "check-ignore", "-q", "--", rel_target], ROOT)
            assert ignored.returncode == 0, exception_key
            seen_exceptions.add(exception_key)
            continue

        rel_target = (base / local).as_posix()
        assert "__pycache__" not in Path(rel_target).parts, (
            manifest_rel, lineno, rel_target
        )
        assert not rel_target.endswith(".pyc"), (manifest_rel, lineno, rel_target)
        assert rel_target in tracked, (manifest_rel, lineno, rel_target)
        target = ROOT / rel_target
        assert target.is_file() and not target.is_symlink(), (
            manifest_rel, lineno, rel_target
        )
        assert sha256(target) == expected, (manifest_rel, lineno, rel_target)
        checked_entries += 1

assert seen_exceptions == PINNED_HISTORICAL_MANIFEST_EXCEPTIONS, (
    seen_exceptions,
    PINNED_HISTORICAL_MANIFEST_EXCEPTIONS,
)

# ACTIVE must mean current.
checker = run(
    [
        sys.executable, "-I", "-S", "-B",
        "checker/gates-v3/checker.py",
        "--project-root", ".",
        "--index", "index/source-v4/SOURCE-INDEX.tsv",
        "--controls", "controls/fstec-core/linux-2022",
    ],
    ROOT,
)
assert checker.returncode in (0, 1), checker.stdout + checker.stderr
assert checker.stderr == "", checker.stderr
assert "GATE1=PASS checked=17 errors=0" in checker.stdout
assert (
    "GATE2=FAIL total=349 controlled_closed=15 disposed_closed=0 "
    "uncovered=334 contracts=15 errors=334"
) in checker.stdout

for rel in (
    "ACTIVE-CHECKER-V3-NO-VM.txt",
    "checker/gates-v3/ACTIVE-NO-VM-EVIDENCE.txt",
):
    assert (ROOT / rel).read_text(encoding="utf-8") == checker.stdout, rel

# Synthetic root-manifest Git-ignore fixture.
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

print(
    "ROOT_MANIFEST_POLICY=PASS "
    f"actual=1 fixture=1 ignored_runtime=2 "
    f"local_manifests={len(local_manifests)} local_entries={checked_entries} "
    "pinned_historical_exceptions=2 active_checker_fresh=2"
)
