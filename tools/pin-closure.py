#!/usr/bin/env python3
"""Print every file that pins the bytes of the given paths, directly or transitively.

Read-only. The project root is the current working directory. A carrier pins a
file by path, taken from the carrier's own format; hash values are not used to
link files. Carriers in scope:

- every SHA256SUMS and every *.sha256: lines "<sha256>  <path>", path relative
  to the carrier directory (for the root manifests that is the project root);
- tests/documentation-v1/CURRENT-MARKDOWN-REVIEW-BASELINE.tsv: header
  "path<TAB>sha256", path relative to the project root;
- controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv: column "file", path
  relative to the carrier directory.

A carrier line that cannot be parsed fails closed with rc=2.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

USAGE = "usage: pin-closure.py --check PATH..."
REVIEW_BASELINE = "tests/documentation-v1/CURRENT-MARKDOWN-REVIEW-BASELINE.tsv"
CONTROL_MANIFEST = "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv"
CHECKSUM_LINE = re.compile(r"[0-9a-f]{64}  (.+)")
SHA256 = re.compile(r"[0-9a-f]{64}")


class CarrierError(Exception):
    pass


def selected_paths(root: Path) -> list[str]:
    """Git-visible regular files, as in tools/rebuild-root-manifests.py."""
    if not (root / ".git").exists():
        raise CarrierError("Git worktree required: GIT_VISIBLE_TRACKED_PLUS_NONIGNORED_UNTRACKED")
    cp = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cp.returncode != 0:
        raise CarrierError(
            "git ls-files failed: " + cp.stderr.decode("utf-8", errors="replace").strip()
        )
    selected = []
    for raw in sorted(set(cp.stdout.split(b"\0"))):
        if not raw:
            continue
        name = raw.decode("utf-8")
        path = root / name
        if path.is_file() and not path.is_symlink():
            selected.append(name)
    return selected


def is_carrier(rel: str) -> bool:
    name = PurePosixPath(rel).name
    return (
        name == "SHA256SUMS"
        or name.endswith(".sha256")
        or rel in (REVIEW_BASELINE, CONTROL_MANIFEST)
    )


def join(base: PurePosixPath, local: str, carrier: str, lineno: int) -> str:
    if not local or local != local.strip():
        raise CarrierError(f"{carrier}:{lineno}: malformed path {local!r}")
    path = PurePosixPath(local)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise CarrierError(f"{carrier}:{lineno}: path must be relative and normalized: {local!r}")
    return (base / path).as_posix()


def carrier_lines(root: Path, rel: str) -> list[str]:
    raw = (root / rel).read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CarrierError(f"{rel}: not UTF-8: {exc}") from None
    if "\r" in text:
        raise CarrierError(f"{rel}: CR forbidden")
    if text and not text.endswith("\n"):
        raise CarrierError(f"{rel}: final newline required")
    return text.split("\n")[:-1] if text else []


def parse_checksums(root: Path, rel: str) -> set[str]:
    base = PurePosixPath(rel).parent
    pinned = set()
    for lineno, line in enumerate(carrier_lines(root, rel), 1):
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise CarrierError(f"{rel}:{lineno}: unparsable checksum line {line!r}")
        pinned.add(join(base, match.group(1), rel, lineno))
    return pinned


def parse_tsv(root: Path, rel: str, header: tuple[str, ...], column: str, base: PurePosixPath) -> set[str]:
    lines = carrier_lines(root, rel)
    if not lines or tuple(lines[0].split("\t")) != header:
        raise CarrierError(f"{rel}:1: unexpected header")
    index = header.index(column)
    digest = header.index("sha256")
    pinned = set()
    for lineno, line in enumerate(lines[1:], 2):
        fields = line.split("\t")
        if len(fields) != len(header) or SHA256.fullmatch(fields[digest]) is None:
            raise CarrierError(f"{rel}:{lineno}: unparsable row {line!r}")
        pinned.add(join(base, fields[index], rel, lineno))
    return pinned


def pinned_by(root: Path, rel: str) -> set[str]:
    if rel == REVIEW_BASELINE:
        return parse_tsv(root, rel, ("path", "sha256"), "path", PurePosixPath("."))
    if rel == CONTROL_MANIFEST:
        header = ("control_id", "index_id", "locator", "key", "expected", "file", "sha256")
        return parse_tsv(root, rel, header, "file", PurePosixPath(rel).parent)
    return parse_checksums(root, rel)


def closure(root: Path, inputs: list[str]) -> list[str]:
    edges = {
        rel: pinned_by(root, rel)
        for rel in selected_paths(root)
        if is_carrier(rel)
    }
    reached = set(inputs)
    frontier = set(inputs)
    while frontier:
        found = {
            carrier
            for carrier, pinned in edges.items()
            if carrier not in reached and pinned & frontier
        }
        reached |= found
        frontier = found
    return sorted(reached - set(inputs))


def normalize_input(arg: str) -> str:
    path = PurePosixPath(arg)
    if not arg or path.is_absolute() or ".." in path.parts or path.as_posix() != arg:
        raise ValueError(f"path must be relative to the project root and normalized: {arg!r}")
    return arg


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] != "--check":
        print(USAGE, file=sys.stderr)
        return 2
    try:
        inputs = [normalize_input(arg) for arg in argv[1:]]
    except ValueError as exc:
        print(f"{USAGE}\n{exc}", file=sys.stderr)
        return 2
    try:
        result = closure(Path.cwd(), inputs)
    except CarrierError as exc:
        print(f"RESULT=FAIL: {exc}", file=sys.stderr)
        return 2
    for rel in result:
        print(rel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
