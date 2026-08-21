#!/usr/bin/env python3
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]

cp = subprocess.run(
    [
        "/usr/bin/python3", "-I", "-S", "-B",
        str(ROOT / "tools/render-current-docs.py"),
        "--project-root", str(ROOT), "--check",
    ],
    cwd=ROOT,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
assert cp.returncode == 0, cp.stdout + cp.stderr
assert "DOC_RENDER_RESULT=PASS" in cp.stdout
assert "DOC_RENDER_FILES=3" in cp.stdout

readme = (ROOT / "README.md").read_text(encoding="utf-8")
docs_index = (ROOT / "docs/README.md").read_text(encoding="utf-8")
policy = (ROOT / "docs/policy-layers.md").read_text(encoding="utf-8")
compat = (ROOT / "docs/compatibility.md").read_text(encoding="utf-8")
coverage = (ROOT / "docs/fstec-coverage.md").read_text(encoding="utf-8")
pmap = (ROOT / "docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")
product_readme = (ROOT / "product/README.md").read_text(encoding="utf-8")
controls_readme = (
    ROOT / "controls/fstec-core/linux-2022/README.md"
).read_text(encoding="utf-8")


# Relative Markdown links in the two entry points must resolve.
for source_path, text in ((ROOT / "README.md", readme), (ROOT / "docs/README.md", docs_index)):
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
        if "://" in target or target.startswith("#"):
            continue
        target_path = target.split("#", 1)[0]
        if not target_path:
            continue
        resolved = (source_path.parent / target_path).resolve()
        assert resolved.exists(), f"broken link {source_path.relative_to(ROOT)} -> {target}"

# Every docs/*.md except the index itself must appear exactly once in docs/README.
doc_names = sorted(
    p.name for p in (ROOT / "docs").glob("*.md") if p.name != "README.md"
)
for name in doc_names:
    assert docs_index.count(f"]({name})") == 1, name

# One primary map; donor runtime diagrams are explicitly not primary.
assert docs_index.count("**PRIMARY**") == 1
assert "PROJECT-MAP-v3.md" in readme
assert "donor/future runtime reference" in readme
assert "ARCHITECTURE-DIAGRAMS.md" in docs_index

assert "FSTEC core ≠ recommended ≠ corporate standard ≠ firewall" in policy
for marker in ("SUPPORTED", "TESTED", "UNSUPPORTED", "ubuntu-24.04-x86_64"):
    assert marker in compat, marker

assert "**GENERATED FILE.**" in coverage
assert "CONTROLLED_CLOSED_WITH_CONTRACT=" in coverage
assert "Готовность CHECK adapters" in coverage
assert "Canonical controls, ещё не закрывающие source row" in coverage
assert "## Покрытие по исходным документам" in coverage

import csv
with (ROOT / "index/source-v4/SOURCE-INDEX.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    source_rows = list(csv.DictReader(stream, delimiter="\t"))
with (ROOT / "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    manifest_rows = list(csv.DictReader(stream, delimiter="\t"))

by_source = {}
source_by_id = {row["index_id"]: row for row in source_rows}
for row in source_rows:
    bucket = by_source.setdefault(
        row["source_id"],
        {"total": 0, "controlled": 0, "disposed": 0, "open": 0, "controls": 0},
    )
    bucket["total"] += 1
    if row["status"] == "OPEN":
        bucket["open"] += 1
    elif row["disposition"].strip():
        bucket["disposed"] += 1
    else:
        bucket["controlled"] += 1
for control in manifest_rows:
    by_source[source_by_id[control["index_id"]]["source_id"]]["controls"] += 1
for source_id, bucket in by_source.items():
    expected = (
        f"| {source_id} | {bucket['total']} | {bucket['controlled']} | "
        f"{bucket['disposed']} | {bucket['open']} | {bucket['controls']} |"
    )
    assert expected in coverage, expected

# Product-facing docs must not retain the stale pilot presentation.
product_docs = "\n".join(
    [readme, pmap, product_readme, controls_readme, docs_index, coverage, compat, policy]
)
for stale in (
    "344 OPEN",
    "5 current controls",
    "ровно пять явно заданных sysctl-параметров",
    "Следующий отдельный gate после установки generator: CHECK-8",
):
    assert stale not in product_docs, stale

all_docs = "\n".join(
    q.read_text(encoding="utf-8") for q in sorted((ROOT / "docs").glob("*.md"))
)
for stale_current_claim in (
    "Current FSTEC pilot remains 349 total / 5 CLOSED / 344 OPEN.",
    "`349 total / 5 controlled CLOSED / 0 disposed CLOSED / 344 OPEN`.",
):
    assert stale_current_claim not in all_docs, stale_current_claim

assert "SRC-0005 / 2.3.1" in product_readme
assert "mode bits-clear 0077" in product_readme
assert "README не пинует\nручное число controls" in controls_readme

# Generated blocks exist exactly once.
assert readme.count("<!-- BEGIN GENERATED CURRENT STATUS -->") == 1
assert readme.count("<!-- END GENERATED CURRENT STATUS -->") == 1
assert pmap.count("<!-- BEGIN GENERATED MAP STATUS -->") == 1
assert pmap.count("<!-- END GENERATED MAP STATUS -->") == 1

current_map = pmap.split("## 6. Где мы находимся", 1)[1].split(
    "## Что является источником истины", 1
)[0]
assert current_map.count(":::current") == 1
assert "SRC-0005 / 2.3.1" in current_map
assert "CHECK-11" in current_map
assert "sysctl exact-eq batch" in current_map
assert "CHECK-17" in current_map
assert "SRC-0040 / 2.6.6" in current_map
assert "CHECK-18" in current_map
assert "SRC-0033 / 2.5.10" in current_map
assert "CHECK-19" in current_map
assert "kernel-cmdline exact-token batch" in current_map
assert "CHECK-28" in current_map
assert "МЫ ЗДЕСЬ<br/>systematic FSTEC expansion" in current_map
for stale in (
    "МЫ ЗДЕСЬ<br/>Step 7B",
    'implementation<br/>adapters"]:::future',
    'deterministic<br/>build"]:::future',
    "single distributable<br/>securelinux-ng.sh",
):
    assert stale not in current_map, stale
assert "путь к конечному `securelinux-ng.sh`" not in pmap
assert "Финальный `securelinux-ng.sh`" not in pmap

print(
    "DOCUMENTATION_BASELINE=PASS "
    f"docs_indexed={len(doc_names)} generated_files=3 primary_map=1"
)
