#!/usr/bin/env python3
"""Write portable GNU sha256sum-compatible checksum files."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import tempfile
from typing import Iterable


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_input(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing symlink input: {path}")
    if not path.is_file():
        raise ValueError(f"input is not a regular file: {path}")


def build_lines(paths: Iterable[Path]) -> list[str]:
    paths = list(paths)
    basenames = [path.name for path in paths]

    if len(set(basenames)) != len(basenames):
        raise ValueError("duplicate basenames are not portable in one checksum file")

    return [
        f"{sha256_file(path)}  {path.name}\n"
        for path in paths
    ]


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.is_symlink():
        raise ValueError(f"refusing symlink output: {path}")

    fd, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.tmp.",
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)

        os.replace(temporary_name, path)

        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Write a GNU sha256sum-compatible file containing only "
            "portable basenames."
        )
    )
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="regular files to hash",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "checksum output path; for one input defaults to "
            "<input>.sha256"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    files = [path.expanduser().absolute() for path in args.files]

    for path in files:
        validate_input(path)

    if args.output is None:
        if len(files) != 1:
            raise ValueError("--output is required for multiple input files")
        output = files[0].with_name(files[0].name + ".sha256")
    else:
        output = args.output.expanduser().absolute()

    content = "".join(build_lines(files))
    atomic_write(output, content)

    print(f"CHECKSUM_FILE={output}")
    print(f"ENTRY_COUNT={len(files)}")
    for line in content.splitlines():
        print(f"CHECKSUM_ENTRY={line}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"ERROR={error}", file=__import__("sys").stderr)
        raise SystemExit(1)
