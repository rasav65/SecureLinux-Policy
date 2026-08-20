# project-integrity-v1

Root-manifest reproducibility and Git-ignore population regression.

Current nested Git-visible `**/SHA256SUMS` проверяются repository-wide:
обычная запись обязана ссылаться на regular file из canonical population
`tracked + nonignored untracked` с совпадающим SHA-256; absolute/`..`,
`__pycache__` и `.pyc` запрещены.

Единственное исключение — ровно две pinned historical entries в
`archive/engineering-donor-v16.2.11/SHA256SUMS` для Git-ignored runtime-state
исходного donor snapshot (`check.txt`, `report.json`). Их manifest/path/SHA
зафиксированы точно; расширение списка исключений запрещено.

`product/SHA256SUMS` дополнительно проверяется в обратном направлении:
каждый Git-visible файл `product/`, кроме самого manifest, обязан присутствовать
в manifest. Это предотвращает незаметное добавление product-файла без SHA binding.

Два файла с маркировкой `ACTIVE` для gates-v3 обязаны побайтово совпадать со
свежим current checker stdout. Regression не пинует исторические числовые
значения Gate 1/Gate 2.
