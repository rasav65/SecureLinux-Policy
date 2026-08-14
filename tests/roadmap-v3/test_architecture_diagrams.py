#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[2]
text=(root/"docs/ARCHITECTURE-DIAGRAMS.md").read_text(encoding="utf-8")
assert text.count("```mermaid")==3
assert text.count("flowchart TB")==3
for marker in (
    'CLI["Аргументы CLI"]',
    'MODE{"MODE"}',
    'ENABLE_ADDITIONAL_MEASURES = 1?',
    'RESTORE["Режим restore"]',
    'APPLY["--apply"]',
    'manifest_init()',
    'backup_file_checked()',
    'Атомарное обновление manifest',
    'NEXT: type/boolean contract cleanup',
):
    assert marker in text, marker
assert "docs/ARCHITECTURE-DIAGRAMS.md" in (root/"README.md").read_text(encoding="utf-8")
print("ARCHITECTURE_DIAGRAMS=PASS mermaid_blocks=3")
