#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
text = (root / "docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")

assert text.count("```mermaid") == 5
assert text.count(":::current") == 1

assert 'S3["type/boolean<br/>contract cleanup"]:::closed' in text
assert 'S4["mandatory real-jsonschema<br/>release gate"]:::closed' in text
assert 'S5["index-generic<br/>source skeleton generator"]:::closed' in text
assert 'S6["МЫ ЗДЕСЬ<br/>source-block<br/>regeneration parity"]:::current' in text

required = (
    "raw-pdftotext",
    "10 документов",
    "glyph-id-cross-document-v1",
    "get_texttrace()",
    "ТОЛЬКО 2 документа",
    "raw-glyph-recovered",
    "sources/recovered-v1/norm-v1",
    "RECOVERY-MANIFEST.tsv",
    "EXTRACTION-MANIFEST.tsv",
    "SOURCE-INDEX.text_quality",
    "CLOSURE-CONTRACT.tsv",
    "disposed CLOSED + disposition + reason",
    "test_schema_runtime_parity.py",
    "semantic parity regression",
    "Draft202012Validator",
    "source skeleton generator",
    "single normative producer",
    "5 sysctl controls",
    "1 reference VM",
    "one sysctl-v1 evidence directory",
    "PROVENANCE.tsv",
    "PROJECT-SNAPSHOT.tsv",
    "git bundle verify",
    "git ls-tree vs PROJECT-SNAPSHOT.tsv",
    "clean-checkout reproducible",
    "controls that passed required gates",
    "DONOR_TO_V3_MAPPING",
    "REUSE / ADAPT / REJECT / DEFER",
    "МЫ ЗДЕСЬ",
    "type/boolean",
)
for marker in required:
    assert marker in text, marker

# Recovery must be a branch from PDF, not PDF -> extracted norm -> recovery.
assert "PDF --> RAWEXT --> EXNORM" in text
assert "PDF --> GLYPH --> RAWREC --> RECNORM" in text
assert "EXNORM --> REC" not in text
assert "PDF --> NORM --> REC" not in text

# Gate 0 must not be presented as semantic parity.
assert "Gate 0 PASS" in text
assert "только byte-generation parity" in text

readme = (root / "README.md").read_text(encoding="utf-8")
assert "docs/PROJECT-MAP-v3.md" in readme

print("PROJECT_MAP_V3=PASS mermaid_blocks=5 current_nodes=1 recovery_branches=2")
