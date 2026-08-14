#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
import unicodedata
from pathlib import Path

NORM_VERSION = "norm-v1"

LIGATURE_MAP = str.maketrans({
    "\ufb00": "ff",
    "\ufb01": "fi",
    "\ufb02": "fl",
    "\ufb03": "ffi",
    "\ufb04": "ffl",
    "\ufb05": "st",
    "\ufb06": "st",
})

SPACE_LIKE = {
    "\u00a0": " ",
    "\u202f": " ",
    "\u2007": " ",
}

def normalize_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\f", "\n")
    text = text.replace("\u00ad", "")
    text = text.translate(LIGATURE_MAP)
    text = unicodedata.normalize("NFC", text)
    for src, dst in SPACE_LIKE.items():
        text = text.replace(src, dst)
    text = re.sub(r"\s+", " ", text, flags=re.UNICODE)
    return text.strip() + "\n"

def selftest() -> None:
    cases = [
        ("A\u00a0B\r\nC\tD\u00adE \ufb01 \ufb02\n", "A B C DE fi fl\n"),
        ("  один   два\nтри  ", "один два три\n"),
        ("по-настоящему\nтест", "по-настоящему тест\n"),
        ("№ 117 — К1/К2/К3", "№ 117 — К1/К2/К3\n"),
    ]
    for source, expected in cases:
        actual = normalize_text(source)
        if actual != expected:
            raise RuntimeError(
                f"{NORM_VERSION} selftest failed: "
                f"source={source!r} expected={expected!r} actual={actual!r}"
            )
        if normalize_text(actual) != actual:
            raise RuntimeError(f"{NORM_VERSION} is not idempotent")

def main() -> int:
    selftest()
    if len(sys.argv) != 3:
        print(f"USAGE: {Path(sys.argv[0]).name} INPUT.txt OUTPUT.txt", file=sys.stderr)
        return 2
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    text = src.read_text(encoding="utf-8")
    dst.write_text(normalize_text(text), encoding="utf-8", newline="\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
