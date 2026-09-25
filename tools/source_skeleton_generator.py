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
``unit_kind=numbered-position`` and ``unit_kind=general-numbered-position``.
The index declares thirteen unit kinds; a single extraction rule for all of
them would silently produce wrong quotes, so each kind is added separately,
with its own ground truth.

Ground truth for this kind is the five accepted pilot controls: regenerating
their ``source:`` blocks must reproduce the committed files byte for byte.
``--verify-pilot`` performs exactly that and is the reason to trust the rule.

Extraction rule (numbered-position)
-----------------------------------
The norm-v1 corpus of these documents is a single line. A unit begins at its
locator marker ``<locator>. `` and ends immediately before the next such
marker at the same or a shallower depth, or at end of document. Markers are
matched only when not preceded by a digit or a dot, so ``2.4.1`` inside a
sentence cannot start a unit. The extracted span is stripped of surrounding whitespace. Source-specific
page furniture may then be removed only by exact pinned rules: a terminal
footer token at corpus EOF, an index-specific trailing page-number token, or
an index-specific inline page-number fragment with exact surrounding text.
The result is re-normalized with norm-v1 and required to be unchanged -- if
normalization would alter the span, the row is refused rather than guessed.

Extraction rule (general-numbered-position)
-------------------------------------------
The locator is ``<section>:<ordinal>`` rather than a dotted outline path.
The ordinal selects the N-th top-level marker of the accepted outline, so
the same successor filter decides unit boundaries for both kinds. A unit
ends at the next top-level marker; the last unit of a section has no such
marker and would otherwise run to end of corpus, swallowing the appendices.
Its end is therefore one exact pinned section terminator, required to occur
exactly once and after the start of the unit -- absence, duplication or a
position at or before the unit start is refused rather than approximated.

Coverage is typed, never approximated: each current index row is classified as
EXACT, REFUSED or UNSUPPORTED with a machine-readable reason code. REFUSED is
reserved for explicitly typed deliberate refusal; integrity failures remain
exceptions and terminate fail-closed. The normalizer, source index, corpus
manifests and normalized corpus hashes are validated before a block is emitted.
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
from typing import NamedTuple

NORM_VERSION = "norm-v1"
NORMALIZER_SHA256 = "fdf11e5abc24c966e7b9c9abe318259fd29c06de026addf54cf3710cc937639a"
SUPPORTED_UNIT_KINDS = {
    "numbered-position",
    "general-numbered-position",
    "numbered-subpoint",
}

STATE_EXACT = "EXACT"
STATE_REFUSED = "REFUSED"
STATE_UNSUPPORTED = "UNSUPPORTED"
REASON_EXACT_EXTRACTION = "EXACT_EXTRACTION"
REASON_BARE_TRAILING_PAGE_INTEGER = "BARE_TRAILING_PAGE_INTEGER"
REASON_UNIT_KIND_UNSUPPORTED = "UNIT_KIND_UNSUPPORTED"
REASON_BARE_INTEGER_INSIDE_UNIT = "BARE_INTEGER_INSIDE_UNIT"


class DeliberateRefusal(ValueError):
    """Typed deliberate refusal; integrity failures use ordinary exceptions."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


class CoverageResult(NamedTuple):
    state: str
    reason_code: str
    source_block: dict | None


def validate_coverage_result(result: CoverageResult) -> CoverageResult:
    allowed = {
        STATE_EXACT: {REASON_EXACT_EXTRACTION},
        STATE_REFUSED: {
            REASON_BARE_TRAILING_PAGE_INTEGER,
            REASON_BARE_INTEGER_INSIDE_UNIT,
        },
        STATE_UNSUPPORTED: {REASON_UNIT_KIND_UNSUPPORTED},
    }
    if result.state not in allowed:
        raise RuntimeError(f"unknown typed state: {result.state!r}")
    if result.reason_code not in allowed[result.state]:
        raise RuntimeError(
            f"unknown reason_code for {result.state}: {result.reason_code!r}"
        )
    if (result.state == STATE_EXACT) != (result.source_block is not None):
        raise RuntimeError(
            f"invalid typed result payload for state {result.state}"
        )
    return result

# Source-specific terminal page furniture that is visibly present in the pinned
# PDF but is not part of the normative numbered position. The rule is narrow:
# it applies only when the exact token is at end-of-corpus, so an underscore
# sequence inside normative text is never removed.
TERMINAL_PAGE_FURNITURE = {
    "fstec-linux-2022": "________________________",
    "fstec-configuration-2026": "____________________________",
}

# The last unit of a section has no following top-level marker. Its end is one
# exact pinned terminator, keyed by (source_id, section). Nothing is inferred:
# a missing, duplicated or misplaced terminator refuses the row.
SECTION_TERMINATOR = {
    ("fstec-logging-2025", "main"): "Приложение 1",
}

# Internal page-number furniture is never stripped generically. Each exception
# is pinned to one exact index row and one exact trailing token.
INDEX_TRAILING_PAGE_FURNITURE = {
    "SRC-0001": "3",
    "SRC-0049": "4",
}

# Inline page-number furniture is also never stripped generically. For an
# internal page break, both the raw fragment and the canonical replacement are
# pinned to one index row. This makes a recovery-layout change fail closed.
INDEX_INLINE_PAGE_FURNITURE = {
    "SRC-0008": (
        "путём изменения владельца командой chown root путь_к_файлу для 4 "
        "каждого исполняемого файла, который можно запускать",
        "путём изменения владельца командой chown root путь_к_файлу для "
        "каждого исполняемого файла, который можно запускать",
    ),
    "SRC-0014": (
        ".bash_profile, .bashrc, .profile, .bash_logout и т. п. - "
        "файлы 5 настройки оболочки, .rhosts",
        ".bash_profile, .bashrc, .profile, .bash_logout и т. п. - "
        "файлы настройки оболочки, .rhosts",
    ),
    "SRC-0048": (
        "требованиям по безопасности 3 ФСТЭК России",
        "требованиям по безопасности ФСТЭК России",
    ),
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

# numbered-subpoint: section heading "N." with a dot, subpoint "N.M" without a
# trailing dot (fstec-configuration-2026). Candidates pass the same outline
# successor filter as MARKER.
SUBPOINT_MARKER = re.compile(r"(?<![^\s])(?:(\d+)\.|(\d+\.\d+))(?=\s)")

# Any standalone integer token (of any length) inside a numbered subpoint may be
# a page number; such a subpoint is refused, never emitted as EXACT.
SUBPOINT_INTEGER_TOKEN = re.compile(r"(?<!\S)\d+(?!\S)")

# A candidate marker that directly follows one of these exact tokens is a table
# reference ("в таблице 2."), not an outline boundary. Pinned per source.
SUBPOINT_EXCLUDED_MARKER_PREFIXES = {
    "fstec-configuration-2026": ("таблице ", "Таблица "),
}

# A printed subpoint number that is a source typo takes its outline position
# from a pinned alias; the locator keeps the printed number. Pinned per source:
# fstec-configuration-2026 prints 9.4 as "8.4" after 9.3 in section 9.
SUBPOINT_PRINTED_ALIASES = {
    ("fstec-configuration-2026", "8.4"): "9.4",
}


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


def subpoint_markers(corpus: str, source_id: str):
    """Return [(offset, locator)] of the numbered-subpoint outline."""
    excluded = SUBPOINT_EXCLUDED_MARKER_PREFIXES.get(source_id, ())
    accepted, previous = [], None
    for match in SUBPOINT_MARKER.finditer(corpus):
        if excluded and corpus[:match.start()].endswith(excluded):
            continue
        locator = match.group(1) or match.group(2)
        candidate = parts(SUBPOINT_PRINTED_ALIASES.get((source_id, locator), locator))
        if is_successor(previous, candidate):
            accepted.append((match.start(), locator))
            previous = candidate
    return accepted


def extract_subpoint_unit(corpus: str, locator: str, source_id: str):
    """Return the exact span of one numbered subpoint, or raise ValueError."""
    starts = subpoint_markers(corpus, source_id)
    hits = [i for i, (_, loc) in enumerate(starts) if loc == locator]
    if len(hits) != 1:
        raise ValueError(f"subpoint locator {locator} matches={len(hits)}")
    index = hits[0]
    begin = starts[index][0]
    end = len(corpus)
    for offset, loc in starts[index + 1:]:
        if depth(loc) <= depth(locator):
            end = offset
            break
    return corpus[begin:end].strip()


def extract_general_unit(corpus: str, locator: str, source_id: str):
    """Return the exact span of one ``<section>:<ordinal>`` unit, or raise."""
    section, separator, ordinal_text = locator.partition(":")
    if not separator or not ordinal_text.isdigit():
        raise ValueError(f"malformed general locator {locator!r}")
    ordinal = int(ordinal_text)
    tops = [(offset, loc) for offset, loc in outline_markers(corpus)
            if depth(loc) == 1]
    if ordinal < 1 or ordinal > len(tops):
        raise ValueError(
            f"ordinal {ordinal} outside top-level outline of {len(tops)} markers"
        )
    begin = tops[ordinal - 1][0]
    if ordinal < len(tops):
        return corpus[begin:tops[ordinal][0]].strip()

    terminator = SECTION_TERMINATOR.get((source_id, section))
    if terminator is None:
        raise ValueError(
            f"no pinned section terminator for {source_id}:{section}; "
            "refusing rather than running to end of corpus"
        )
    hits = [m.start() for m in re.finditer(re.escape(terminator), corpus)]
    if len(hits) != 1:
        raise ValueError(
            f"pinned section terminator matches={len(hits)} for "
            f"{source_id}:{section}"
        )
    if hits[0] <= begin:
        raise ValueError("pinned section terminator precedes the unit start")
    return corpus[begin:hits[0]].strip()


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


def strip_index_trailing_page_furniture(quote: str, row) -> str:
    """Remove one exact trailing page-number token for a pinned index row.

    A configured row must actually end with its pinned token; mismatch is an
    error rather than a reason to guess. Unlisted rows are unchanged.
    """
    token = INDEX_TRAILING_PAGE_FURNITURE.get(row["index_id"])
    if token is None:
        return quote
    suffix = " " + token
    if not quote.endswith(suffix):
        raise ValueError(
            f"pinned trailing page furniture mismatch for {row['index_id']}"
        )
    return quote[:-len(suffix)].rstrip()


def strip_index_inline_page_furniture(quote: str, row) -> str:
    """Remove one exact inline page-number fragment for a pinned index row.

    The complete surrounding fragment is pinned. It must occur exactly once;
    absence or duplication is an error rather than a reason to guess.
    Unlisted rows are unchanged.
    """
    pair = INDEX_INLINE_PAGE_FURNITURE.get(row["index_id"])
    if pair is None:
        return quote
    raw_fragment, canonical_fragment = pair
    hits = quote.count(raw_fragment)
    if hits != 1:
        raise ValueError(
            f"pinned inline page furniture mismatch for {row['index_id']}: "
            f"matches={hits}"
        )
    return quote.replace(raw_fragment, canonical_fragment, 1)


def build_source_block(project_root: Path, row, normalize_text):
    if row["quote_anchor_ready"] != "YES":
        raise ValueError("index quote_anchor_ready != YES")
    corpus = resolve_corpus(project_root, row).read_text(encoding="utf-8")
    if corpus.endswith("\n"):
        corpus = corpus[:-1]
    if row["unit_kind"] == "numbered-subpoint":
        raw_quote = extract_subpoint_unit(
            corpus, row["locator"], row["source_id"]
        )
    elif row["unit_kind"] == "general-numbered-position":
        raw_quote = extract_general_unit(
            corpus, row["locator"], row["source_id"]
        )
    else:
        raw_quote = extract_unit(corpus, row["locator"])
    if raw_quote not in corpus:
        raise ValueError("raw extracted quote is not a substring of the corpus")

    quote = strip_terminal_page_furniture(corpus, raw_quote, row)
    quote = strip_index_trailing_page_furniture(quote, row)
    quote = strip_index_inline_page_furniture(quote, row)

    # An unpinned unit that runs across a page break ends with a page number,
    # which is page furniture rather than normative text. Stripping it
    # generically would be a guess, so every unpinned row is refused.
    if re.search(r"\s\d{1,3}$", quote):
        raise DeliberateRefusal(
            REASON_BARE_TRAILING_PAGE_INTEGER,
            "extracted span ends with a bare integer (page number across a "
            "page break); refusing rather than guessing",
        )

    # A numbered subpoint crossing a page break carries the page number inside
    # the span; no generic stripping, every standalone integer token refuses.
    if row["unit_kind"] == "numbered-subpoint" and SUBPOINT_INTEGER_TOKEN.search(quote):
        raise DeliberateRefusal(
            REASON_BARE_INTEGER_INSIDE_UNIT,
            "numbered subpoint contains a standalone integer token (possible "
            "page number); refusing rather than guessing",
        )

    canonical = normalize_text(quote)
    if canonical.endswith("\n"):
        canonical = canonical[:-1]
    if canonical != quote:
        raise ValueError("extracted span is not canonical under norm-v1")
    return {
        "index_id": row["index_id"],
        "doc_id": row["source_id"],
        "doc_sha256": row["source_sha256"],
        "locator": row["locator"],
        "quote": quote,
        "quote_sha256": sha256_text(quote),
        "norm": NORM_VERSION,
    }


def classify_row(project_root: Path, row, normalize_text) -> CoverageResult:
    """Return EXACT/REFUSED/UNSUPPORTED; integrity failures remain exceptions."""
    if row["quote_anchor_ready"] != "YES":
        raise ValueError("index quote_anchor_ready != YES")
    if row["unit_kind"] not in SUPPORTED_UNIT_KINDS:
        return validate_coverage_result(CoverageResult(
            STATE_UNSUPPORTED, REASON_UNIT_KIND_UNSUPPORTED, None
        ))
    try:
        block = build_source_block(project_root, row, normalize_text)
    except DeliberateRefusal as exc:
        return validate_coverage_result(CoverageResult(
            STATE_REFUSED, exc.reason_code, None
        ))
    return validate_coverage_result(CoverageResult(
        STATE_EXACT, REASON_EXACT_EXTRACTION, block
    ))


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
        try:
            result = classify_row(project_root, row, normalize_text)
        except Exception as exc:
            print(f"  FAIL  {path.name}: {exc}")
            failures += 1
            continue
        if result.state == STATE_UNSUPPORTED:
            print(
                f"  SKIP  {path.name}: state={result.state} "
                f"reason_code={result.reason_code} unit_kind={row['unit_kind']}"
            )
            continue
        if result.state == STATE_REFUSED:
            print(
                f"  FAIL  {path.name}: state={result.state} "
                f"reason_code={result.reason_code}"
            )
            failures += 1
            continue
        generated = render_source_block(result.source_block)
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
        result = classify_row(project_root, row, normalize_text)
        if result.state != STATE_EXACT:
            print(f"STATE={result.state}", file=sys.stderr)
            print(f"REASON_CODE={result.reason_code}", file=sys.stderr)
            if result.state == STATE_UNSUPPORTED:
                print(f"UNIT_KIND={row['unit_kind']}", file=sys.stderr)
            return 2
        sys.stdout.write(render_source_block(result.source_block))
        return 0

    if args.coverage:
        counts = {STATE_EXACT: 0, STATE_REFUSED: 0, STATE_UNSUPPORTED: 0}
        refused = []
        for row in rows:
            result = classify_row(project_root, row, normalize_text)
            counts[result.state] += 1
            if result.state == STATE_REFUSED:
                refused.append((
                    row["index_id"], row["locator"], result.reason_code
                ))
        print(f"UNIT_KINDS_SUPPORTED={','.join(sorted(SUPPORTED_UNIT_KINDS))}")
        print(f"INDEX_ROWS_TOTAL={len(rows)}")
        print(
            "ROWS_IN_SUPPORTED_KINDS="
            f"{counts[STATE_EXACT] + counts[STATE_REFUSED]}"
        )
        print(f"EXACT={counts[STATE_EXACT]}")
        print(f"REFUSED={counts[STATE_REFUSED]}")
        print(f"UNSUPPORTED={counts[STATE_UNSUPPORTED]}")
        for index_id, locator, reason_code in refused:
            print(
                f"  REFUSED {index_id} {locator} "
                f"REASON_CODE={reason_code}"
            )
        return 0

    ap.error("choose one of --verify-pilot, --index-id, --coverage")


if __name__ == "__main__":
    raise SystemExit(main())
