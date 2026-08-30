# FSTEC-LINUX-2022 — канонические controls

Машинный источник истины состава этого каталога — `CONTROL-MANIFEST.tsv`; README не закрепляет
вручную число controls.

Каждый канонический control относится к `fstec-core`, содержит якорь source и
имеет `apply.supported=false`. Наличие control само по себе не закрывает строку source:
полнота задаётся `index/source-v4/CLOSURE-CONTRACT.tsv`.

Текущую человекочитаемую карту покрытия и поддержки адаптеров CHECK формирует
`docs/fstec-coverage.md` через `tools/render-current-docs.py`.
