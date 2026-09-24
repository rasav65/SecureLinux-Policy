# project-integrity-v1 — целостность проекта

Regression-проверка воспроизводимости корневых manifests и population с учётом Git-ignore.

Текущие вложенные Git-visible `**/SHA256SUMS` проверяются по всему репозиторию:
обычная запись обязана ссылаться на regular file из канонической population
`tracked + nonignored untracked` с совпадающим SHA-256; absolute/`..`,
`__pycache__` и `.pyc` запрещены.

Единственное исключение — ровно две закреплённые historical entries в
`archive/engineering-donor-v16.2.11/SHA256SUMS` для Git-ignored runtime-state
исходного snapshot донора (`check.txt`, `report.json`). Их manifest/path/SHA
зафиксированы точно; расширение списка исключений запрещено.

`product/SHA256SUMS` дополнительно проверяется в обратном направлении:
каждый Git-visible файл `product/`, кроме самого manifest, обязан присутствовать
в manifest. Это предотвращает незаметное добавление product-файла без SHA-привязки.

`test_refresh_pins.py` проверяет `tools/refresh-pins.py` на копии дерева: формула `truth_sha256`
совпадает с гейтом документации; согласованное дерево даёт `--check` PASS; правка адаптера даёт
`--check` STALE, после `--write` без `--reviewed-truth` — PASS, `truth_sha256` не меняется; смена
текста `reason` в `DISPOSITION-LEDGER.tsv` без `--reviewed-truth` — отказ, с ним — PASS; изменённый
документ обновляется только с `--reviewed`;
устаревший пин неизменённого пути и новый файл вне manifest — ошибка.

Два файла с маркировкой `ACTIVE` для gates-v3 обязаны побайтово совпадать со
свежим current checker stdout. Regression не пинует исторические числовые
значения Gate 1/Gate 2.
Восемь historical B1.1b `.sha256` отдельно классифицированы как
`NON_REPRODUCIBLE_HISTORICAL_RECORD`: regression пересчитывает их фактические
entry/mismatch/missing counts по `ARCHIVAL-SIDECAR-STATUS.tsv` и проверяет, что
несовпадающие stage digests не представлены иными Git-visible bytes. Это не
переписывает historical sidecar задним числом.

Frozen `archive/engineering-review-20260731/review/README.md` сохраняется
побайтово; пять его старых ссылок теперь разрешаются через три явно маркированных
link-resolution companion-файла, которые не выдаются за original archive members.
