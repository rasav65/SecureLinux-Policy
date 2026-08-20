# FSTEC-LINUX-2022 canonical controls

Machine truth состава этого каталога — `CONTROL-MANIFEST.tsv`; README не пинует
ручное число controls.

Каждый canonical control относится к `fstec-core`, содержит source anchor и
имеет `apply.supported=false`. Наличие control само по себе не закрывает source
row: completeness задаётся `index/source-v4/CLOSURE-CONTRACT.tsv`.

Текущую human-readable карту покрытия и CHECK adapter support формирует
`docs/fstec-coverage.md` через `tools/render-current-docs.py`.
