# project-integrity-v1

Root-manifest reproducibility and Git-ignore population regression.

Current nested tracked `**/SHA256SUMS` проверяются repository-wide: каждая
обычная запись обязана ссылаться на tracked regular file с совпадающим SHA-256;
absolute/`..`, `__pycache__` и `.pyc` запрещены.

Единственное исключение — ровно две pinned historical entries в
`archive/engineering-donor-v16.2.11/SHA256SUMS` для Git-ignored runtime-state
исходного donor snapshot (`check.txt`, `report.json`). Их manifest/path/SHA
зафиксированы точно; расширение списка исключений запрещено.

Два tracked файла, в имени которых заявлено `ACTIVE` для gates-v3,
обязаны побайтово совпадать со свежим запуском current checker.
