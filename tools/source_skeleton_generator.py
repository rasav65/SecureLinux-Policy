#!/usr/bin/env python3
"""Generate the ``source:`` block of a control record from the source index.

Roadmap step ``INDEX_GENERIC_SOURCE_SKELETON_GENERATOR``.

Why this exists
---------------
Every field of ``source:`` is already determined by the index row and the
normalized corpus. Typing it by hand adds nothing and can only introduce
transcription errors, which Gate 1 would then have to catch one record at a
time. This generator is intended to become the single writer of that block;
the companion step ``SOURCE_BLOCK_REGENERATION_PARITY`` then regenerates and
compares, exactly as Gate 0 does for the schema, so a hand-edited quote becomes
impossible rather than merely unlikely.

Scope of this version
---------------------
Only ``unit_kind=numbered-position`` (74 index rows: 40 in fstec-linux-2022,
34 in fstec-perimeter-2026). The index declares thirteen unit kinds; a single
extraction rule for all of them would silently produce wrong quotes, so each
kind is added separately, with its own ground truth.

Ground truth for this kind is the five accepted pilot controls: regenerating
their ``source:`` blocks must reproduce the committed files byte for byte.
``--verify-pilot`` performs exactly that and is the reason to trust the rule.

Extraction rule (numbered-position)
-----------------------------------
The norm-v1 corpus of these documents is a single line. A unit begins at its
locator marker ``<locator>. `` and ends immediately before the next such
marker at the same or a shallower depth, or at end of document. Markers are
matched only when not preceded by a digit or a dot, so ``2.4.1`` inside a
sentence cannot start a unit. The extracted span is stripped of surrounding whitespace. A source-specific
terminal footer token may then be removed only when that exact token is the
final token of both the pinned normalized corpus and the extracted final unit.
The result is re-normalized with norm-v1 and required to be unchanged -- if
normalization would alter the span, the row is refused rather than guessed.

Output is refused, never approximated. A row that cannot be extracted exactly
is reported and skipped; it is not emitted with a best-effort quote. The
normalizer, source index, corpus manifests and normalized corpus hashes are
validated fail-closed before a block is emitted.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import re
import stat
import sys
from pathlib import Path

NORM_VERSION = "norm-v1"
NORMALIZER_SHA256 = "fdf11e5abc24c966e7b9c9abe318259fd29c06de026addf54cf3710cc937639a"
SUPPORTED_UNIT_KINDS = {"numbered-position"}

# Source-specific terminal page furniture that is visibly present in the pinned
# PDF but is not part of the normative numbered position. The rule is narrow:
# it applies only when the exact token is at end-of-corpus, so an underscore
# sequence inside normative text is never removed.
TERMINAL_PAGE_FURNITURE = {
    "fstec-linux-2022": "________________________",
}
INDEX_FIELDS = {
    "index_id", "source_id", "source_file", "source_sha256", "source_role",
    "unit_kind", "locator", "raw_match_line", "text_quality",
    "quote_anchor_ready", "status", "disposition", "reason", "note",
}

# A candidate marker is a dotted number that starts a whitespace-delimited
# token and is followed by whitespace. This alone is not sufficient: text such
# as "kernel.dmesg_restrict=1. Журнал" or "№ 1085. " also matches. Candidates
# are therefore filtered into an outline in outline_markers().
MARKER = re.compile(r"(?<![^\s])(\d+(?:\.\d+)*)\.(?=\s)")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_regular(path: Path) -> None:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"symlink forbidden: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"regular file required: {path}")


def load_normalizer(project_root: Path):
    path = project_root / "sources/extracted/normalizer-v1.py"
    validate_regular(path)
    if sha256_file(path) != NORMALIZER_SHA256:
        raise ValueError("normalizer-v1.py SHA mismatch")
    spec = importlib.util.spec_from_file_location("source_skeleton_normalizer_v1", path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load normalizer-v1.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "selftest") or not hasattr(module, "normalize_text"):
        raise ValueError("normalizer-v1.py missing required API")
    module.selftest()
    return module.normalize_text


def read_tsv(path: Path):
    validate_regular(path)
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    return fields, rows


def load_index(path: Path):
    fields, rows = read_tsv(path)
    if set(fields) != INDEX_FIELDS:
        raise ValueError(f"unexpected index fields: {fields}")
    by_id = {}
    for lineno, row in enumerate(rows, 2):
        index_id = row["index_id"]
        if index_id in by_id:
            raise ValueError(f"duplicate index_id at line {lineno}: {index_id}")
        by_id[index_id] = row
    return rows, by_id


def read_manifest(path: Path, key_field: str):
    fields, rows = read_tsv(path)
    if key_field not in fields:
        raise ValueError(f"manifest missing key field {key_field}: {path}")
    out = {}
    for lineno, row in enumerate(rows, 2):
        key = row[key_field]
        if key in out:
            raise ValueError(
                f"duplicate manifest key {key!r} at line {lineno}: {path}"
            )
        out[key] = row
    return out


def resolve_corpus(project_root: Path, row) -> Path:
    """Mirror Gate 1 corpus selection *and integrity checks*."""
    pdf = row["source_file"]
    pdf_sha = row["source_sha256"]

    if row["text_quality"] == "recovered-glyph-map-v1":
        manifest = read_manifest(
            project_root / "sources/recovered-v1/RECOVERY-MANIFEST.tsv",
            "source_id",
        )
        entry = manifest.get(row["source_id"])
        if entry is None:
            raise ValueError("recovery manifest entry missing")
        if entry["pdf"] != pdf or entry["pdf_sha256"] != pdf_sha:
            raise ValueError("recovery manifest source mismatch")
        if (
            entry["norm_version"] != NORM_VERSION
            or entry["normalizer_sha256"] != NORMALIZER_SHA256
        ):
            raise ValueError("recovery normalization mismatch")
        path = project_root / "sources/recovered-v1" / entry["norm_path"]
        validate_regular(path)
        if sha256_file(path) != entry["norm_sha256"]:
            raise ValueError("recovered norm SHA mismatch")
        return path

    manifest = read_manifest(
        project_root / "sources/extracted/EXTRACTION-MANIFEST.tsv",
        "pdf",
    )
    entry = manifest.get(pdf)
    if entry is None:
        raise ValueError("extraction manifest entry missing")
    if entry["pdf_sha256"] != pdf_sha:
        raise ValueError("extraction manifest source mismatch")
    if (
        entry["norm_version"] != NORM_VERSION
        or entry["normalizer_sha256"] != NORMALIZER_SHA256
    ):
        raise ValueError("extraction normalization mismatch")
    path = project_root / "sources/extracted" / entry["norm_path"]
    validate_regular(path)
    if sha256_file(path) != entry["norm_sha256"]:
        raise ValueError("extracted norm SHA mismatch")
    return path


def depth(locator: str) -> int:
    return locator.count(".") + 1


def parts(locator: str):
    return tuple(int(x) for x in locator.split("."))


def is_successor(previous, candidate) -> bool:
    """True when `candidate` can directly follow `previous` in a numbered
    outline: the first child, the next sibling, or the next sibling of any
    ancestor. Everything else - page numbers, decree numbers, values such as
    "=1." - is rejected."""
    if previous is None:
        return candidate == (1,)
    if candidate == previous + (1,):
        return True
    for cut in range(len(previous), 0, -1):
        head, last = previous[:cut - 1], previous[cut - 1]
        if candidate == head + (last + 1,):
            return True
    return False


def outline_markers(corpus: str):
    """Return [(offset, locator)] for the markers that form a valid outline.

    Deterministic single pass: a candidate is accepted only if it is a legal
    successor of the last accepted marker. This is what separates a real unit
    boundary from a number that merely looks like one."""
    accepted, previous = [], None
    for match in MARKER.finditer(corpus):
        candidate = parts(match.group(1))
        if is_successor(previous, candidate):
            accepted.append((match.start(), match.group(1)))
            previous = candidate
    return accepted


def extract_unit(corpus: str, locator: str):
    """Return the exact span of one numbered unit, or raise ValueError."""
    starts = outline_markers(corpus)
    hits = [i for i, (_, loc) in enumerate(starts) if loc == locator]
    if not hits:
        raise ValueError(f"locator {locator} not found in corpus")
    if len(hits) > 1:
        raise ValueError(f"locator {locator} occurs {len(hits)} times; ambiguous")
    index = hits[0]
    begin = starts[index][0]
    end = len(corpus)
    for offset, loc in starts[index + 1:]:
        if depth(loc) <= depth(locator):
            end = offset
            break
    return corpus[begin:end].strip()


def strip_terminal_page_furniture(corpus: str, quote: str, row) -> str:
    """Remove only a pinned source-specific terminal footer token.

    The token must be the exact final token of both the normalized corpus and
    the extracted unit. This makes the rule fail-closed and prevents generic
    punctuation/underscore stripping.
    """
    token = TERMINAL_PAGE_FURNITURE.get(row["source_id"])
    if token is None:
        return quote
    suffix = " " + token
    if corpus.endswith(suffix) and quote.endswith(suffix):
        return quote[:-len(suffix)].rstrip()
    return quote


def build_source_block(project_root: Path, row, normalize_text):
    if row["quote_anchor_ready"] != "YES":
        raise ValueError("index quote_anchor_ready != YES")
    corpus = resolve_corpus(project_root, row).read_text(encoding="utf-8")
    if corpus.endswith("\n"):
        corpus = corpus[:-1]
    quote = extract_unit(corpus, row["locator"])
    quote = strip_terminal_page_furniture(corpus, quote, row)

    # A unit that runs across a page break ends with the page number, which is
    # page furniture rather than normative text. Stripping it would be a guess
    # about which trailing integers are furniture, so the row is refused and
    # reported instead.
    if re.search(r"\s\d{1,3}$", quote):
        raise ValueError(
            "extracted span ends with a bare integer (page number across a "
            "page break); refusing rather than guessing"
        )

    canonical = normalize_text(quote)
    if canonical.endswith("\n"):
        canonical = canonical[:-1]
    if canonical != quote:
        raise ValueError("extracted span is not canonical under norm-v1")
    if quote not in corpus:
        raise ValueError("extracted quote is not a substring of the corpus")

    return {
        "index_id": row["index_id"],
        "doc_id": row["source_id"],
        "doc_sha256": row["source_sha256"],
        "locator": row["locator"],
        "quote": quote,
        "quote_sha256": sha256_text(quote),
        "norm": NORM_VERSION,
    }


def render_source_block(block) -> str:
    order = ["index_id", "doc_id", "doc_sha256", "locator",
             "quote", "quote_sha256", "norm"]
    lines = ["source:"]
    for key in order:
        lines.append(f"  {key}: {json.dumps(block[key], ensure_ascii=False)}")
    return "\n".join(lines) + "\n"


def parse_committed_source_block(text: str) -> str:
    """Return the ``source:`` block of an existing control file verbatim."""
    lines = text.split("\n")
    try:
        start = lines.index("source:")
    except ValueError:
        raise ValueError("control file has no source: block")
    end = start + 1
    while end < len(lines) and (lines[end].startswith("  ") or not lines[end].strip()):
        if not lines[end].strip():
            break
        end += 1
    return "\n".join(lines[start:end]) + "\n"


def verify_pilot(project_root: Path, rows_by_id, normalize_text) -> int:
    """Regenerating an accepted control must reproduce it byte for byte."""
    controls = sorted((project_root / "controls").rglob("*.yaml"))
    if not controls:
        print("PILOT_VERIFY=FAIL no control files found")
        return 1
    failures = 0
    for path in controls:
        text = path.read_text(encoding="utf-8")
        committed = parse_committed_source_block(text)
        index_id = re.search(r'^\s*index_id:\s*"([^"]+)"', text, re.M).group(1)
        row = rows_by_id.get(index_id)
        if row is None:
            print(f"  MISS  {path.name}: index_id {index_id} not in index")
            failures += 1
            continue
        if row["unit_kind"] not in SUPPORTED_UNIT_KINDS:
            print(f"  SKIP  {path.name}: unit_kind {row['unit_kind']} not supported yet")
            continue
        try:
            generated = render_source_block(
                build_source_block(project_root, row, normalize_text)
            )
        except Exception as exc:
            print(f"  FAIL  {path.name}: {exc}")
            failures += 1
            continue
        if generated == committed:
            print(f"  OK    {path.name}  {index_id}  {row['locator']}")
        else:
            failures += 1
            print(f"  DIFF  {path.name}  {index_id}")
            for a, b in zip(committed.split("\n"), generated.split("\n")):
                if a != b:
                    print(f"        committed: {a[:110]}")
                    print(f"        generated: {b[:110]}")
    print(f"PILOT_VERIFY={'PASS' if not failures else 'FAIL'} "
          f"controls={len(controls)} mismatches={failures}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="source: block generator")
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--index", default="index/source-v4/SOURCE-INDEX.tsv")
    ap.add_argument("--verify-pilot", action="store_true",
                    help="regenerate accepted controls and require byte identity")
    ap.add_argument("--index-id", help="emit the source: block for one index row")
    ap.add_argument("--coverage", action="store_true",
                    help="report how many rows this version can extract")
    args = ap.parse_args()

    project_root = Path(args.project_root).resolve()
    normalize_text = load_normalizer(project_root)
    rows, rows_by_id = load_index(project_root / args.index)

    if args.verify_pilot:
        return verify_pilot(project_root, rows_by_id, normalize_text)

    if args.index_id:
        row = rows_by_id.get(args.index_id)
        if row is None:
            print(f"UNKNOWN_INDEX_ID={args.index_id}", file=sys.stderr)
            return 2
        if row["unit_kind"] not in SUPPORTED_UNIT_KINDS:
            print(f"UNSUPPORTED_UNIT_KIND={row['unit_kind']}", file=sys.stderr)
            return 2
        sys.stdout.write(render_source_block(
            build_source_block(project_root, row, normalize_text)
        ))
        return 0

    if args.coverage:
        supported = [r for r in rows if r["unit_kind"] in SUPPORTED_UNIT_KINDS]
        ok, refused = 0, []
        for row in supported:
            try:
                build_source_block(project_root, row, normalize_text)
                ok += 1
            except Exception as exc:
                refused.append((row["index_id"], row["locator"], str(exc)))
        print(f"UNIT_KINDS_SUPPORTED={','.join(sorted(SUPPORTED_UNIT_KINDS))}")
        print(f"INDEX_ROWS_TOTAL={len(rows)}")
        print(f"ROWS_IN_SUPPORTED_KINDS={len(supported)}")
        print(f"EXTRACTED_EXACTLY={ok}")
        print(f"REFUSED={len(refused)}")
        for index_id, locator, why in refused:
            print(f"  REFUSED {index_id} {locator}: {why}")
        return 0

    ap.error("choose one of --verify-pilot, --index-id, --coverage")


if __name__ == "__main__":
    raise SystemExit(main())
