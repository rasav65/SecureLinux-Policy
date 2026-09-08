#!/usr/bin/env python3
from __future__ import annotations

import csv
import hashlib
import importlib.util
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROL_MANIFEST = ROOT / "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv"
GEN = ROOT / "tools/source_skeleton_generator.py"
EXPECTED_GEN_SHA = "f4c568c9d54a0bef9837f592c106029a2346b64154abcd3fe837d70e69e92532"
EXPECTED_SRC0018_SHA = "016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d"
EXPECTED_SRC0040_SHA = "f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d"
EXPECTED_SRC0001_SHA = "799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b"
EXPECTED_SRC0008_SHA = "0be87131f3aea07d4da4134cd82c960c608b16feff43b6996ea4817d9bb38dfe"
EXPECTED_SRC0014_SHA = "c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0"
EXPECTED_REFUSED = {"SRC-0133"}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()




def current_control_count() -> int:
    with CONTROL_MANIFEST.open(encoding="utf-8", newline="") as stream:
        return sum(1 for _ in csv.DictReader(stream, delimiter="\t"))



def load_gen():
    spec = importlib.util.spec_from_file_location(
        "source_skeleton_generator_tested", GEN
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_cli(*args: str):
    cp = subprocess.run(
        [sys.executable, "-B", str(GEN), "--project-root", str(ROOT), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    return cp.returncode, cp.stdout, cp.stderr


assert sha(GEN) == EXPECTED_GEN_SHA

gate = load_gen()
normalize_text = gate.load_normalizer(ROOT)
rows, by_id = gate.load_index(ROOT / "index/source-v4/SOURCE-INDEX.tsv")

assert len(rows) == 349
assert len({row["unit_kind"] for row in rows}) == 13
assert gate.SUPPORTED_UNIT_KINDS == {
    "numbered-position",
    "general-numbered-position",
}

# Positive ground truth: every current control is in the supported kind and
# regenerates byte-identically. The count comes from CONTROL-MANIFEST.tsv.
control_count = current_control_count()
rc, out, err = run_cli("--verify-pilot")
assert rc == 0, (out, err)
assert f"PILOT_VERIFY=PASS controls={control_count} mismatches=0" in out
assert out.count("  OK    ") == control_count
assert "  SKIP  " not in out
assert "  DIFF  " not in out

# Supported-kind coverage is deliberately partial and fail-closed.
supported = [
    row for row in rows
    if row["unit_kind"] in gate.SUPPORTED_UNIT_KINDS
]
assert supported

ok = []
refused = {}
for row in supported:
    try:
        gate.build_source_block(ROOT, row, normalize_text)
        ok.append(row["index_id"])
    except Exception as exc:
        refused[row["index_id"]] = str(exc)

assert len(ok) + len(refused) == len(supported)
assert set(refused) == EXPECTED_REFUSED
assert all("bare integer" in why for why in refused.values())

# Exact pinned internal page boundary for SRC-0001. The recovered corpus
# contains the page number "3" immediately before 2.1.2; only this exact
# index/token pair is admitted as page furniture.
block1 = gate.build_source_block(ROOT, by_id["SRC-0001"], normalize_text)
assert block1["quote_sha256"] == EXPECTED_SRC0001_SHA
assert block1["quote"].endswith("файл /etc/shadow.")
assert not block1["quote"].endswith(" 3")
raw1 = gate.extract_unit(
    gate.resolve_corpus(ROOT, by_id["SRC-0001"]).read_text(encoding="utf-8").rstrip("\n"),
    "2.1.1",
)
assert raw1.endswith("файл /etc/shadow. 3")

fixture_row1 = dict(by_id["SRC-0001"])
assert gate.strip_index_trailing_page_furniture("fixture 3", fixture_row1) == "fixture"
try:
    gate.strip_index_trailing_page_furniture("fixture 4", fixture_row1)
except ValueError as exc:
    assert "pinned trailing page furniture mismatch" in str(exc)
else:
    raise AssertionError("mismatched pinned page token was accepted")
fixture_row1["index_id"] = "SRC-0018"
assert gate.strip_index_trailing_page_furniture("fixture 3", fixture_row1) == "fixture 3"

# Exact pinned inline page boundary for SRC-0008.
block8 = gate.build_source_block(ROOT, by_id["SRC-0008"], normalize_text)
assert block8["quote_sha256"] == EXPECTED_SRC0008_SHA
assert "путь_к_файлу для каждого исполняемого файла" in block8["quote"]
assert "путь_к_файлу для 4 каждого исполняемого файла" not in block8["quote"]
raw8 = gate.extract_unit(
    gate.resolve_corpus(ROOT, by_id["SRC-0008"]).read_text(encoding="utf-8").rstrip("\n"),
    "2.3.4",
)
assert "путь_к_файлу для 4 каждого исполняемого файла" in raw8
fixture_row8 = dict(by_id["SRC-0008"])
raw_fragment8, canonical_fragment8 = gate.INDEX_INLINE_PAGE_FURNITURE["SRC-0008"]
assert gate.strip_index_inline_page_furniture(raw_fragment8, fixture_row8) == canonical_fragment8
try:
    gate.strip_index_inline_page_furniture(
        raw_fragment8.replace("для 4 каждого", "для 5 каждого"), fixture_row8
    )
except ValueError as exc:
    assert "pinned inline page furniture mismatch" in str(exc)
else:
    raise AssertionError("mismatched SRC-0008 page token was accepted")

# Exact pinned inline page boundary for SRC-0014. The recovered corpus contains
# page number "5" between "файлы" and "настройки оболочки"; only this exact
# index + surrounding fragment is admitted as page furniture.
block14 = gate.build_source_block(ROOT, by_id["SRC-0014"], normalize_text)
assert block14["quote_sha256"] == EXPECTED_SRC0014_SHA
assert "файлы настройки оболочки" in block14["quote"]
assert "файлы 5 настройки оболочки" not in block14["quote"]
raw14 = gate.extract_unit(
    gate.resolve_corpus(ROOT, by_id["SRC-0014"]).read_text(encoding="utf-8").rstrip("\n"),
    "2.3.10",
)
assert "файлы 5 настройки оболочки" in raw14

fixture_row14 = dict(by_id["SRC-0014"])
raw_fragment14, canonical_fragment14 = gate.INDEX_INLINE_PAGE_FURNITURE["SRC-0014"]
assert gate.strip_index_inline_page_furniture(
    raw_fragment14, fixture_row14
) == canonical_fragment14
try:
    gate.strip_index_inline_page_furniture(
        raw_fragment14.replace("файлы 5", "файлы 4"), fixture_row14
    )
except ValueError as exc:
    assert "pinned inline page furniture mismatch" in str(exc)
else:
    raise AssertionError("mismatched pinned inline page token was accepted")
try:
    gate.strip_index_inline_page_furniture(
        raw_fragment14 + " " + raw_fragment14, fixture_row14
    )
except ValueError as exc:
    assert "matches=2" in str(exc)
else:
    raise AssertionError("duplicated pinned inline page fragment was accepted")
fixture_row14["index_id"] = "SRC-0018"
assert gate.strip_index_inline_page_furniture(
    raw_fragment14, fixture_row14
) == raw_fragment14

# Exact known example.
block = gate.build_source_block(ROOT, by_id["SRC-0018"], normalize_text)
assert block["quote_sha256"] == EXPECTED_SRC0018_SHA
rendered = gate.render_source_block(block)
assert rendered.startswith('source:\n  index_id: "SRC-0018"\n')
assert '  norm: "norm-v1"\n' in rendered

# Exact terminal-unit boundary: the horizontal rule visible at the bottom of
# the pinned PDF page is page furniture, not part of numbered position 2.6.6.
block40 = gate.build_source_block(ROOT, by_id["SRC-0040"], normalize_text)
assert block40["quote_sha256"] == EXPECTED_SRC0040_SHA
assert block40["quote"].endswith("вредоносное поведение.")
assert "________________________" not in block40["quote"]
raw40 = gate.extract_unit(
    gate.resolve_corpus(ROOT, by_id["SRC-0040"]).read_text(encoding="utf-8").rstrip("\n"),
    "2.6.6",
)
assert raw40.endswith(" ________________________")

# Fail-closed negative: the token is removed only at exact EOF for the pinned
# source_id. Moving it away from EOF or changing source_id must preserve bytes.
fixture_row = dict(by_id["SRC-0040"])
fixture_corpus = "2.6.6. fixture ________________________"
assert gate.strip_terminal_page_furniture(
    fixture_corpus + " tail", fixture_corpus, fixture_row
) == fixture_corpus
fixture_row["source_id"] = "other-source"
assert gate.strip_terminal_page_furniture(
    fixture_corpus, fixture_corpus, fixture_row
) == fixture_corpus

# Index-generic path: the same common-contract index can be supplied from a
# different path. The generator must not depend on index/source-v4 as a
# hard-coded input location.
with tempfile.TemporaryDirectory(prefix="slp-index-generic-") as td:
    alt = Path(td) / "ANY-LAYER-INDEX.tsv"
    shutil.copy2(ROOT / "index/source-v4/SOURCE-INDEX.tsv", alt)
    rc, alt_out, alt_err = run_cli(
        "--index", str(alt), "--index-id", "SRC-0018"
    )
    assert rc == 0, (alt_out, alt_err)
    assert alt_out == rendered

# Negative: duplicate index identity.
with tempfile.TemporaryDirectory(prefix="slp-duplicate-index-") as td:
    dup = Path(td) / "SOURCE-INDEX.tsv"
    text = (
        ROOT / "index/source-v4/SOURCE-INDEX.tsv"
    ).read_text(encoding="utf-8")
    lines = text.splitlines()
    dup.write_text(
        text.rstrip("\n") + "\n" + lines[1] + "\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        gate.load_index(dup)
    except ValueError as exc:
        assert "duplicate index_id" in str(exc)
    else:
        raise AssertionError("duplicate index_id was accepted")

# Negative: source anchor not ready.
bad = dict(by_id["SRC-0018"])
bad["quote_anchor_ready"] = "NO"
try:
    gate.build_source_block(ROOT, bad, normalize_text)
except ValueError as exc:
    assert "quote_anchor_ready != YES" in str(exc)
else:
    raise AssertionError("non-ready quote anchor was accepted")

# Negative: altered normalizer.
with tempfile.TemporaryDirectory(prefix="slp-normalizer-tamper-") as td:
    temp_root = Path(td)
    dst = temp_root / "sources/extracted"
    dst.mkdir(parents=True)
    original = ROOT / "sources/extracted/normalizer-v1.py"
    (dst / "normalizer-v1.py").write_text(
        original.read_text(encoding="utf-8") + "\n# tamper fixture\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        gate.load_normalizer(temp_root)
    except ValueError as exc:
        assert "SHA mismatch" in str(exc)
    else:
        raise AssertionError("altered normalizer was accepted")

# Negative: corpus hash tampered in the recovery manifest.
with tempfile.TemporaryDirectory(prefix="slp-manifest-tamper-") as td:
    temp_root = Path(td)
    rec_src = ROOT / "sources/recovered-v1"
    rec_dst = temp_root / "sources/recovered-v1"
    shutil.copytree(rec_src, rec_dst)

    manifest = rec_dst / "RECOVERY-MANIFEST.tsv"
    with manifest.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        fields = list(reader.fieldnames or [])
        data = list(reader)

    target = by_id["SRC-0018"]["source_id"]
    changed = 0
    for row in data:
        if row["source_id"] == target:
            row["norm_sha256"] = "0" * 64
            changed += 1
    assert changed == 1

    with manifest.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=fields,
            delimiter="\t",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(data)

    try:
        gate.resolve_corpus(temp_root, by_id["SRC-0018"])
    except ValueError as exc:
        assert "norm SHA mismatch" in str(exc)
    else:
        raise AssertionError("corrupted norm SHA was accepted")

# Current documentation must not pin a historical supported/exact/refused
# population. Those values are derived above from current index/generator bytes.
doc_paths = (
    ROOT / "docs/source-skeleton-generator.md",
    ROOT / "docs/ROADMAP-v3.md",
    ROOT / "docs/disposition-ledger.md",
)
for doc_path in doc_paths:
    doc = doc_path.read_text(encoding="utf-8")
    lower = doc.lower()
    for stale in (
        "точных извлечений: 72",
        "отказов: 2",
        "две строки с отказом",
        "два известных явных отказа",
        "две строки поддержанного типа",
        "отказ без угадывания: `src-0001`, `src-0133`",
    ):
        assert stale not in lower, (doc_path, stale)
    assert not __import__("re").search(
        r"(?i)(?:supported|exact|refused|точн\w*\s+извлеч|отказ\w*)"
        r"[^\n]{0,36}(?:population|строк\w*|извлеч\w*|отказ\w*)?"
        r"\s*[:=—-]\s*`?\d+",
        doc,
    ), doc_path

source_doc = (ROOT / "docs/source-skeleton-generator.md").read_text(encoding="utf-8")
assert "больше не относится к refused population" in source_doc
assert "test-owned machine truth" in source_doc
assert "supported/exact/refused population" in source_doc.lower()

expected_summary = (
    "SOURCE_SKELETON_TESTS=PASS "
    f"pilot={control_count} unit_kinds={len(gate.SUPPORTED_UNIT_KINDS)}/{len({row['unit_kind'] for row in rows})} "
    f"supported_rows={len(supported)} exact={len(ok)} refused={len(refused)} "
    "index_generic_path=1 negative_duplicate_index=1 "
    "negative_quote_anchor=1 negative_normalizer_sha=1 "
    "negative_norm_sha=1 internal_page_exact=1 internal_page_negative=2 "
    "inline_page_exact=1 inline_page_negative=2 "
    "terminal_footer_exact=1 terminal_footer_negative=2 "
    "documentation_population_parity=3 test_results_fresh=1"
)
stored_summary = (ROOT / "tests/source-skeleton-v1/TEST-RESULTS.txt").read_text(encoding="utf-8").strip()
assert stored_summary == expected_summary, (stored_summary, expected_summary)
print(expected_summary)
