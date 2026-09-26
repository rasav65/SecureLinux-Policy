#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path
import os

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


def run(argv, cwd, env=None):
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, env=env)


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

visible_raw = set(
    run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        ROOT,
    ).stdout.splitlines()
)
visible = {
    rel for rel in visible_raw
    if (ROOT / rel).exists() or (ROOT / rel).is_symlink()
}
local_manifests = sorted(
    rel for rel in visible
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
        assert rel_target in visible, (manifest_rel, lineno, rel_target)
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

# Infer complete-subtree local manifests from the accepted base HEAD.
# A manifest that exactly covered its HEAD subtree remains complete; scoped/historical
# manifests retain their narrower population and continue to receive only one-way checks.
def manifest_target_set(manifest_rel: str, text: str) -> set[str]:
    base = Path(manifest_rel).parent
    targets = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        assert match is not None, (manifest_rel, lineno, line)
        local = Path(match.group(2))
        assert not local.is_absolute(), (manifest_rel, lineno, local)
        assert ".." not in local.parts, (manifest_rel, lineno, local)
        rel_target = (base / local).as_posix()
        assert rel_target not in targets, (manifest_rel, rel_target)
        targets.add(rel_target)
    return targets


complete_subtree_manifests = []
for manifest_rel in local_manifests:
    base = Path(manifest_rel).parent.as_posix()
    head_manifest = run(["git", "show", f"HEAD:{manifest_rel}"], ROOT)
    if head_manifest.returncode != 0:
        continue
    head_targets = manifest_target_set(manifest_rel, head_manifest.stdout)
    head_visible = set(
        run(["git", "ls-tree", "-r", "--name-only", "HEAD", "--", base], ROOT).stdout.splitlines()
    )
    head_expected = {rel for rel in head_visible if rel != manifest_rel}
    if head_targets != head_expected:
        continue

    current_targets = manifest_target_set(
        manifest_rel, (ROOT / manifest_rel).read_text(encoding="utf-8")
    )
    prefix = base + "/"
    current_expected = {
        rel for rel in visible
        if rel.startswith(prefix) and rel != manifest_rel
    }
    assert current_targets == current_expected, (
        manifest_rel,
        sorted(current_expected - current_targets),
        sorted(current_targets - current_expected),
    )
    complete_subtree_manifests.append(manifest_rel)

assert "product/SHA256SUMS" in complete_subtree_manifests
assert "controls/fstec-core/linux-2022/SHA256SUMS" in complete_subtree_manifests

# ACTIVE must mean current.
checker = run(
    [
        sys.executable, "-I", "-S", "-B",
        "checker/gates-v3/checker.py",
        "--project-root", ".",
        "--index", "index/source-v4/SOURCE-INDEX.tsv",
        "--controls", "controls/fstec-core",
    ],
    ROOT,
)
assert checker.returncode in (0, 1), checker.stdout + checker.stderr
assert checker.stderr == "", checker.stderr
for marker in (
    "GATE0=", "GATE1=", "GATE2=", "GATE3=", "GATE4=", "GATE5=", "OVERALL="
):
    assert marker in checker.stdout, marker

for rel in (
    "ACTIVE-CHECKER-V3-NO-VM.txt",
    "checker/gates-v3/ACTIVE-NO-VM-EVIDENCE.txt",
):
    assert (ROOT / rel).read_text(encoding="utf-8") == checker.stdout, rel

# Historical B1.1b sidecars are preserved records, not current reproducibility proof.
status_path = ROOT / "archive/B1.1b/ARCHIVAL-SIDECAR-STATUS.tsv"
with status_path.open(encoding="utf-8", newline="") as f:
    archival_rows = list(csv.DictReader(f, delimiter="\t"))
assert len(archival_rows) == 8
assert {row["status"] for row in archival_rows} == {"NON_REPRODUCIBLE_HISTORICAL_RECORD"}

visible_regular_hashes = {}
for rel in sorted(visible):
    path = ROOT / rel
    if path.is_file() and not path.is_symlink():
        visible_regular_hashes.setdefault(sha256(path), []).append(rel)

archival_mismatch_entries = 0
for row in archival_rows:
    sidecar_rel = row["sidecar"]
    sidecar = ROOT / sidecar_rel
    assert sidecar.is_file() and not sidecar.is_symlink(), sidecar_rel
    assert sha256(sidecar) == row["sidecar_sha256"], sidecar_rel
    entries = mismatches = missing = 0
    mismatch_expected = []
    for lineno, line in enumerate(sidecar.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        assert match is not None, (sidecar_rel, lineno, line)
        expected, target_text = match.groups()
        entries += 1
        if target_text.startswith("B1.1b/"):
            target = ROOT / "archive" / target_text
        else:
            target = ROOT / target_text
        if not target.is_file() or target.is_symlink():
            missing += 1
            continue
        if sha256(target) != expected:
            mismatches += 1
            mismatch_expected.append(expected)
    assert entries == int(row["entries"]), (sidecar_rel, entries, row["entries"])
    assert mismatches == int(row["mismatches"]), (sidecar_rel, mismatches, row["mismatches"])
    assert missing == int(row["missing"]), (sidecar_rel, missing, row["missing"])
    for expected in mismatch_expected:
        assert expected not in visible_regular_hashes, (sidecar_rel, expected, visible_regular_hashes.get(expected))
    archival_mismatch_entries += mismatches
assert archival_mismatch_entries == 40

# Frozen review README stays byte-exact; its five historical relative links resolve
# through three explicit current companion files that do not claim original archive bytes.
review_dir = ROOT / "archive/engineering-review-20260731/review"
review_readme = review_dir / "README.md"
review_text = review_readme.read_text(encoding="utf-8")
assert sha256(review_readme) == "1c4eae4b9db3c725b5e41e57e41cd1070ad379d217995f78dff4e9794e4b18fd"
review_links = re.findall(r"\]\((docs/(?:compatibility|fstec-mapping|restore-model)\.md)\)", review_text)
assert len(review_links) == 5, review_links
assert {rel for rel in review_links} == {
    "docs/compatibility.md", "docs/fstec-mapping.md", "docs/restore-model.md"
}
for rel in set(review_links):
    companion = review_dir / rel
    assert companion.is_file() and not companion.is_symlink(), rel
    body = companion.read_text(encoding="utf-8")
    assert "не являлся членом" in body
    assert "не выдаётся за original stage bytes" in body
    assert "7a62c1304a423e4431b08c34e999ed221777d63ecfb0aec180767fadf80759d2" in body

# Synthetic root-manifest Git-ignore fixture.
with tempfile.TemporaryDirectory(prefix="slp-root-manifest-") as td:
    repo = Path(td) / "repo"
    repo.mkdir()
    repo_env = os.environ.copy()
    repo_env.pop("GIT_INDEX_FILE", None)
    assert run(["git", "init", "-q"], repo, env=repo_env).returncode == 0
    (repo / ".gitignore").write_text(".runtime/\n", encoding="utf-8")
    (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    (repo / "tracked-deleted.txt").write_text("deleted-after-indexing\n", encoding="utf-8")
    (repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    (repo / ".runtime").mkdir()
    (repo / ".runtime/state.txt").write_text("runtime\n", encoding="utf-8")
    assert run(
        ["git", "add", ".gitignore", "tracked.txt", "tracked-deleted.txt"],
        repo,
        env=repo_env,
    ).returncode == 0
    (repo / "tracked-deleted.txt").unlink()

    cp = run(
        [sys.executable, "-B", str(TOOL), "--project-root", str(repo)],
        repo,
        env=repo_env,
    )
    assert cp.returncode == 0, cp.stdout + cp.stderr
    ptext = (repo / "PROJECT-FILES.sha256").read_text(encoding="utf-8")
    rtext = (repo / "SHA256SUMS").read_text(encoding="utf-8")
    assert "tracked.txt" in ptext
    assert "tracked-deleted.txt" not in ptext
    assert "tracked-deleted.txt" not in rtext
    assert "untracked.txt" in ptext
    assert ".runtime/state.txt" not in ptext
    assert ".runtime/state.txt" not in rtext

    cp = run(
        [sys.executable, "-B", str(TOOL), "--project-root", str(repo), "--check"],
        repo,
        env=repo_env,
    )
    assert cp.returncode == 0, cp.stdout + cp.stderr

print(
    "ROOT_MANIFEST_POLICY=PASS "
    f"actual=1 fixture=1 deleted_tracked=1 ignored_runtime=2 "
    f"local_manifests={len(local_manifests)} local_entries={checked_entries} "
    f"pinned_historical_exceptions=2 complete_subtree_manifests={len(complete_subtree_manifests)} "
    "active_checker_fresh=2 archival_sidecars_nonreproducible=8 archival_mismatch_entries=40 "
    "archival_review_links_resolved=5"
)
