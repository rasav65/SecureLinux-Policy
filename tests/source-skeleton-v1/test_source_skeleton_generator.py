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
EXPECTED_GEN_SHA = "91de1029a8ca288ad1a9ade8764e260010c2b721b00fbfb3c6b910ef4a07a3b6"
EXPECTED_SRC0018_SHA = "016c676139eeb902737e3db80a31154aa84fd377203c0819614f1d54c9afb97d"
EXPECTED_SRC0040_SHA = "f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d"
EXPECTED_SRC0001_SHA = "799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b"
EXPECTED_SRC0008_SHA = "0be87131f3aea07d4da4134cd82c960c608b16feff43b6996ea4817d9bb38dfe"
EXPECTED_SRC0014_SHA = "c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0"
EXPECTED_REFUSED = {
    "SRC-0060", "SRC-0064", "SRC-0069", "SRC-0075", "SRC-0079",
    "SRC-0080", "SRC-0095", "SRC-0096", "SRC-0101",
    "SRC-0133",
}
EXPECTED_SRC0088_SHA = "8b03ebc02e6d0ad956759a0577eae939adb29e2a31024e70db9e3cd902ebfd06"
EXPECTED_SRC0055_SHA = "5d69bd0dac34a0629945d985db85e8ab7e83699d7692eb444ce361b8f052cf84"
EXPECTED_SRC0091_SHA = "a40740a4d2f728fd1f16a2e48ceb6c2ee8a49ec3eefa633d17b13af7863411c6"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()




def current_control_count() -> int:
    total = 0
    for manifest in sorted((ROOT / "controls/fstec-core").glob("*/CONTROL-MANIFEST.tsv")):
        with manifest.open(encoding="utf-8", newline="") as stream:
            total += sum(1 for _ in csv.DictReader(stream, delimiter="\t"))
    return total



def load_gen():
    spec = importlib.util.spec_from_file_location(
        "source_skeleton_generator_tested", GEN
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_cli_at(project_root: Path, *args: str):
    cp = subprocess.run(
        [
            sys.executable, "-B", str(GEN),
            "--project-root", str(project_root), *args,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    return cp.returncode, cp.stdout, cp.stderr


def run_cli(*args: str):
    return run_cli_at(ROOT, *args)


assert sha(GEN) == EXPECTED_GEN_SHA

gate = load_gen()
normalize_text = gate.load_normalizer(ROOT)
rows, by_id = gate.load_index(ROOT / "index/source-v4/SOURCE-INDEX.tsv")

assert len(rows) == 349
assert len({row["unit_kind"] for row in rows}) == 13
assert gate.SUPPORTED_UNIT_KINDS == {
    "numbered-position",
    "general-numbered-position",
    "numbered-subpoint",
    "linux-appendix2-position",
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

# Step 7B typed gate is exhaustive over the full current index population.
typed = {
    row["index_id"]: gate.classify_row(ROOT, row, normalize_text)
    for row in rows
}
state_counts = {
    state: sum(result.state == state for result in typed.values())
    for state in (gate.STATE_EXACT, gate.STATE_REFUSED, gate.STATE_UNSUPPORTED)
}
assert state_counts == {
    gate.STATE_EXACT: 126,
    gate.STATE_REFUSED: 10,
    gate.STATE_UNSUPPORTED: 213,
}
supported = [
    row for row in rows
    if row["unit_kind"] in gate.SUPPORTED_UNIT_KINDS
]
ok = [index_id for index_id, result in typed.items()
      if result.state == gate.STATE_EXACT]
refused = {
    index_id: result.reason_code
    for index_id, result in typed.items()
    if result.state == gate.STATE_REFUSED
}
unsupported = [
    index_id for index_id, result in typed.items()
    if result.state == gate.STATE_UNSUPPORTED
]
assert len(supported) == len(ok) + len(refused) == 136
assert set(refused) == EXPECTED_REFUSED
assert refused["SRC-0133"] == gate.REASON_BARE_TRAILING_PAGE_INTEGER
# SRC-0091 (8.4): two pinned inline page numbers (14, 15) and a pinned ordered
# sequence of example integers; without the pins the row refuses as before.
assert typed["SRC-0091"].state == gate.STATE_EXACT
assert typed["SRC-0091"].source_block["quote_sha256"] == EXPECTED_SRC0091_SHA
assert " 14 Файл " not in typed["SRC-0091"].source_block["quote"]
assert " 15 grep " not in typed["SRC-0091"].source_block["quote"]
assert "LogLevel VERBOSE." in typed["SRC-0091"].source_block["quote"]
_saved_tokens = gate.INDEX_SUBPOINT_INTEGER_TOKENS
gate.INDEX_SUBPOINT_INTEGER_TOKENS = {"SRC-0091": _saved_tokens["SRC-0091"][:-1]}
try:
    gate.classify_row(ROOT, by_id["SRC-0091"], normalize_text)
except ValueError as exc:
    assert "pinned subpoint integer tokens mismatch" in str(exc), exc
else:
    raise AssertionError("SRC-0091 extracted with a changed integer-token pin")
finally:
    gate.INDEX_SUBPOINT_INTEGER_TOKENS = _saved_tokens
_saved_inline = gate.INDEX_INLINE_PAGE_FURNITURE
gate.INDEX_INLINE_PAGE_FURNITURE = {k: v for k, v in _saved_inline.items() if k != "SRC-0091"}
gate.INDEX_SUBPOINT_INTEGER_TOKENS = {k: v for k, v in _saved_tokens.items() if k != "SRC-0091"}
try:
    _unpinned = gate.classify_row(ROOT, by_id["SRC-0091"], normalize_text)
finally:
    gate.INDEX_INLINE_PAGE_FURNITURE = _saved_inline
    gate.INDEX_SUBPOINT_INTEGER_TOKENS = _saved_tokens
assert _unpinned.state == gate.STATE_REFUSED
assert _unpinned.reason_code == gate.REASON_BARE_INTEGER_INSIDE_UNIT
# SRC-0055 (1.1): two pinned inline page numbers (3, 4) and a pinned ordered
# sequence of table-value integers. A changed sequence fails closed; without the
# pin the row refuses as before.
assert typed["SRC-0055"].state == gate.STATE_EXACT
assert typed["SRC-0055"].source_block["quote_sha256"] == EXPECTED_SRC0055_SHA
assert " 3 утилиту " not in typed["SRC-0055"].source_block["quote"]
_saved_tokens = gate.INDEX_SUBPOINT_INTEGER_TOKENS
gate.INDEX_SUBPOINT_INTEGER_TOKENS = {"SRC-0055": _saved_tokens["SRC-0055"][:-1]}
try:
    gate.classify_row(ROOT, by_id["SRC-0055"], normalize_text)
except ValueError as exc:
    assert "pinned subpoint integer tokens mismatch" in str(exc), exc
else:
    raise AssertionError("SRC-0055 extracted with a changed integer-token pin")
finally:
    gate.INDEX_SUBPOINT_INTEGER_TOKENS = _saved_tokens
gate.INDEX_SUBPOINT_INTEGER_TOKENS = {}
try:
    _unpinned = gate.classify_row(ROOT, by_id["SRC-0055"], normalize_text)
finally:
    gate.INDEX_SUBPOINT_INTEGER_TOKENS = _saved_tokens
assert _unpinned.state == gate.STATE_REFUSED
assert _unpinned.reason_code == gate.REASON_BARE_INTEGER_INSIDE_UNIT
assert len(unsupported) == 213

# linux-appendix2-position (fstec-logging-2025, приложение 2): 5 пунктов, EXACT.
for _sid, _head, _tail in (
    ("SRC-0050", "1. В случае отсутствия указанной службы", "apt-get install auditd"),
    ("SRC-0051", "2. После установки необходимо запустить", "sudo systemctl enable auditd"),
    ("SRC-0052", "3. Осуществить настройку службы Auditd", "журнальный файл аудита."),
    ("SRC-0053", "4. Настройку правил регистрации событий", "-p rwxa -k usb"),
    ("SRC-0054", "5. Для просмотра событий безопасности", "aureport option -if filename."),
):
    assert typed[_sid].state == gate.STATE_EXACT, (_sid, typed[_sid])
    _q = typed[_sid].source_block["quote"]
    assert _q.startswith(_head) and _q.endswith(_tail), (_sid, _q[:80], _q[-80:])
assert " 10 Категория " not in typed["SRC-0053"].source_block["quote"]
assert "-k passwd_modification Категория Аудит изменения" in typed["SRC-0053"].source_block["quote"]
# Без закреплённых правил SRC-0053 отказывает (целые числа внутри пункта).
_saved_inline_a2 = gate.INDEX_INLINE_PAGE_FURNITURE
_saved_tokens_a2 = gate.INDEX_SUBPOINT_INTEGER_TOKENS
gate.INDEX_INLINE_PAGE_FURNITURE = {k: v for k, v in _saved_inline_a2.items() if k != "SRC-0053"}
gate.INDEX_SUBPOINT_INTEGER_TOKENS = {k: v for k, v in _saved_tokens_a2.items() if k != "SRC-0053"}
try:
    _unpinned_a2 = gate.classify_row(ROOT, by_id["SRC-0053"], normalize_text)
finally:
    gate.INDEX_INLINE_PAGE_FURNITURE = _saved_inline_a2
    gate.INDEX_SUBPOINT_INTEGER_TOKENS = _saved_tokens_a2
assert _unpinned_a2.state == gate.STATE_REFUSED
assert _unpinned_a2.reason_code == gate.REASON_BARE_INTEGER_INSIDE_UNIT
# Якорь раздела: отсутствие, дублирование и не последний раздел — ошибка, не угадывание.
_corpus_a2 = gate.resolve_corpus(ROOT, by_id["SRC-0050"]).read_text(encoding="utf-8").rstrip("\n")
_anchor_a2 = gate.APPENDIX_SECTION_ANCHOR[("fstec-logging-2025", "appendix2-linux")]
for _bad, _msg in (
    (_corpus_a2.replace(_anchor_a2, "Приложение 2"), "matches=0"),
    (_corpus_a2 + " " + _anchor_a2, "matches=2"),
    (_corpus_a2 + " Приложение 3", "not the final section"),
):
    try:
        gate.extract_appendix_unit(_bad, "appendix2-linux:1", "fstec-logging-2025")
    except ValueError as exc:
        assert _msg in str(exc), exc
    else:
        raise AssertionError("appendix unit extracted from a tampered corpus: " + _msg)

# numbered-subpoint (fstec-configuration-2026): exact 9.1 span ends before 9.2.
src0088 = typed["SRC-0088"].source_block
assert src0088["quote"].startswith("9.1 Отключить авторизацию")
assert src0088["quote"].endswith("PasswordAuthentication no.")
assert src0088["quote_sha256"] == EXPECTED_SRC0088_SHA
# The table reference "в таблице 2." is not an outline boundary: 1.2 stays
# reachable; without the pinned prefix the outline breaks and 1.2 fails.
assert typed["SRC-0056"].state == gate.STATE_EXACT
assert typed["SRC-0056"].source_block["quote"].startswith("1.2 Обеспечить")
_saved_prefixes = gate.SUBPOINT_EXCLUDED_MARKER_PREFIXES
gate.SUBPOINT_EXCLUDED_MARKER_PREFIXES = {}
try:
    gate.classify_row(ROOT, by_id["SRC-0056"], normalize_text)
except ValueError as exc:
    assert "matches=0" in str(exc), exc
else:
    raise AssertionError("SRC-0056 extracted without the pinned table prefix")
finally:
    gate.SUBPOINT_EXCLUDED_MARKER_PREFIXES = _saved_prefixes
# The source prints 9.4 as "8.4" (typo); the pinned alias keeps it in the
# outline: 9.3 ends before it and 8.4 is extracted (page numbers inside are
# pinned for SRC-0091). Without the alias 8.4 is unreachable.
assert typed["SRC-0090"].state == gate.STATE_EXACT
assert typed["SRC-0090"].source_block["quote"].endswith("AllowUsers/AllowGroups.")
_corpus = gate.resolve_corpus(ROOT, by_id["SRC-0091"]).read_text(encoding="utf-8").rstrip("\n")
assert gate.extract_subpoint_unit(_corpus, "8.4", "fstec-configuration-2026").startswith("8.4 Организовать мониторинг")
_saved_aliases = gate.SUBPOINT_PRINTED_ALIASES
gate.SUBPOINT_PRINTED_ALIASES = {}
try:
    gate.extract_subpoint_unit(_corpus, "8.4", "fstec-configuration-2026")
except ValueError as exc:
    assert "matches=0" in str(exc), exc
else:
    raise AssertionError("8.4 extracted without the pinned alias")
finally:
    gate.SUBPOINT_PRINTED_ALIASES = _saved_aliases
# Any-length standalone integer inside or at the end of a subpoint refuses
# (a 4+ digit token must not pass as EXACT).
for _probe in ("9.9 Текст 1000 текст.", "9.9 Текст значение 1000"):
    assert gate.SUBPOINT_INTEGER_TOKEN.search(_probe), _probe
for _probe in ("9.9 Текст retry=3 и TLSv1.2.", "9.9 SMBv2 и 1000x."):
    assert not gate.SUBPOINT_INTEGER_TOKEN.search(_probe), _probe
# Terminal footer of fstec-configuration-2026 is not part of 12.3.
assert typed["SRC-0103"].state == gate.STATE_EXACT
assert "____" not in typed["SRC-0103"].source_block["quote"]

rc, coverage_out, coverage_err = run_cli("--coverage")
assert rc == 0, (coverage_out, coverage_err)
assert "INDEX_ROWS_TOTAL=349" in coverage_out
assert "ROWS_IN_SUPPORTED_KINDS=136" in coverage_out
assert "EXACT=126" in coverage_out
assert "REFUSED=10" in coverage_out
assert "UNSUPPORTED=213" in coverage_out
assert (
    "REFUSED SRC-0133 6.2 "
    "REASON_CODE=BARE_TRAILING_PAGE_INTEGER"
) in coverage_out

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

# Negative: source anchor readiness is an integrity invariant and is checked
# before UNSUPPORTED classification.
bad = dict(next(
    row for row in rows
    if row["unit_kind"] not in gate.SUPPORTED_UNIT_KINDS
))
bad["quote_anchor_ready"] = "NO"
try:
    gate.classify_row(ROOT, bad, normalize_text)
except ValueError as exc:
    assert "quote_anchor_ready != YES" in str(exc)
else:
    raise AssertionError("non-ready quote anchor became a coverage state")

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
    rc, tamper_out, tamper_err = run_cli_at(temp_root, "--coverage")
    assert rc != 0, (tamper_out, tamper_err)
    assert "REFUSED=" not in tamper_out
    assert "UNSUPPORTED=" not in tamper_out
    assert "normalizer-v1.py SHA mismatch" in tamper_err

# Negative: corpus/quote integrity failure must propagate and must not become
# REFUSED or UNSUPPORTED.
original_extract_unit = gate.extract_unit
gate.extract_unit = lambda corpus, locator: corpus + " NOT-A-SUBSTRING"
try:
    gate.classify_row(ROOT, by_id["SRC-0018"], normalize_text)
except ValueError as exc:
    assert "raw extracted quote is not a substring" in str(exc)
else:
    raise AssertionError("quote integrity failure became a coverage state")
finally:
    gate.extract_unit = original_extract_unit

# Negative: unknown typed state is terminal fail-closed.
try:
    gate.validate_coverage_result(gate.CoverageResult("UNKNOWN", "UNKNOWN", None))
except RuntimeError as exc:
    assert "unknown typed state" in str(exc)
else:
    raise AssertionError("unknown typed state was accepted")

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
    ROOT / "docs/ROADMAP.md",
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
assert "exact/refused/unsupported" in source_doc.lower()

expected_summary = (
    "SOURCE_SKELETON_TESTS=PASS "
    f"pilot={control_count} unit_kinds={len(gate.SUPPORTED_UNIT_KINDS)}/{len({row['unit_kind'] for row in rows})} "
    f"total_rows={len(rows)} supported_rows={len(supported)} "
    f"exact={len(ok)} refused={len(refused)} unsupported={len(unsupported)} "
    "typed_reason_codes=4 index_generic_path=1 negative_duplicate_index=1 "
    "negative_quote_anchor=1 negative_normalizer_sha=1 "
    "negative_normalizer_sha_coverage=1 negative_quote_integrity=1 "
    "negative_unknown_state=1 negative_norm_sha=1 internal_page_exact=1 "
    "internal_page_negative=2 inline_page_exact=1 inline_page_negative=2 "
    "terminal_footer_exact=1 terminal_footer_negative=2 "
    "documentation_population_parity=3 subpoint_exact=1 subpoint_table_prefix_negative=1 "
    "subpoint_printed_alias=2 subpoint_integer_token=4 subpoint_terminal_footer=1 subpoint_pinned_integer_tokens=3 "
    "appendix2_exact=5 appendix2_pinned_negative=1 appendix2_anchor_negative=3 test_results_fresh=1"
)
stored_summary = (ROOT / "tests/source-skeleton-v1/TEST-RESULTS.txt").read_text(encoding="utf-8").strip()
assert stored_summary == expected_summary, (stored_summary, expected_summary)
print(expected_summary)
