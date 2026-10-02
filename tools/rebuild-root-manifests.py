#!/usr/bin/env python3
"""Build/check deterministic root manifests from Git-visible project files."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import subprocess
import tempfile
from pathlib import Path

PROJECT_MANIFEST = "PROJECT-FILES.sha256"
ROOT_MANIFEST = "SHA256SUMS"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def selected_paths(root: Path) -> list[str]:
    cp = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError(
            "git ls-files failed: " + cp.stderr.decode("utf-8", errors="replace").strip()
        )

    names = sorted({
        raw.decode("utf-8")
        for raw in cp.stdout.split(b"\0")
        if raw
    })

    selected = []
    for name in names:
        if "\n" in name or "\r" in name:
            raise ValueError(f"newline forbidden in root-manifest path: {name!r}")
        path = root / name
        try:
            st = path.lstat()
        except FileNotFoundError:
            # `git ls-files --cached` includes tracked paths deleted in the
            # current worktree. Root manifests bind current Git-visible bytes,
            # so an intentional unstaged deletion is outside the current
            # regular-file population.
            continue
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(f"symlink forbidden in root-manifest population: {name}")
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"regular file required in root-manifest population: {name}")
        selected.append(name)
    return selected


def render(root: Path, names: list[str], excluded: set[str]) -> str:
    return "".join(
        f"{sha256_file(root / name)}  {name}\n"
        for name in names
        if name not in excluded
    )


def atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.tmp.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
            os.fchmod(f.fileno(), 0o644)
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def expected_project(root: Path, names: list[str]) -> str:
    return render(root, names, {PROJECT_MANIFEST, ROOT_MANIFEST})


def expected_root(root: Path, names: list[str]) -> str:
    return render(root, names, {ROOT_MANIFEST})


def check(root: Path) -> tuple[int, int]:
    names = selected_paths(root)
    ep = expected_project(root, names)
    ap = (root / PROJECT_MANIFEST).read_text(encoding="utf-8")
    if ep != ap:
        raise RuntimeError(f"{PROJECT_MANIFEST} is stale")

    er = expected_root(root, names)
    ar = (root / ROOT_MANIFEST).read_text(encoding="utf-8")
    if er != ar:
        raise RuntimeError(f"{ROOT_MANIFEST} is stale")

    return len(ep.splitlines()), len(er.splitlines())


def rebuild(root: Path) -> tuple[int, int]:
    names = selected_paths(root)
    atomic_write(root / PROJECT_MANIFEST, expected_project(root, names))

    # PROJECT-FILES.sha256 changed, so recompute the root manifest afterwards.
    names = selected_paths(root)
    atomic_write(root / ROOT_MANIFEST, expected_root(root, names))
    return check(root)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root", default=".")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    if not (root / ".git").is_dir():
        raise RuntimeError("Git worktree required")

    if args.check:
        pcount, rcount = check(root)
        action = "CHECK"
    else:
        pcount, rcount = rebuild(root)
        action = "WRITE"

    print(f"ROOT_MANIFEST_ACTION={action}")
    print("ROOT_MANIFEST_SELECTION=GIT_VISIBLE_TRACKED_PLUS_NONIGNORED_UNTRACKED")
    print("GITIGNORED_RUNTIME_STATE=EXCLUDED")
    print(f"PROJECT_FILES_ENTRIES={pcount}")
    print(f"SHA256SUMS_ENTRIES={rcount}")
    print("RESULT=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"RESULT=FAIL: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1)
