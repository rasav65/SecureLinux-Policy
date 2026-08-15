# Регрессия disposition ledger v1

Проверяет усиленный альтернативный путь закрытия строки source index до первого
реального disposition.

Позитивная фикстура синтетически исполняет `disposed_closed=1`.
Отрицательные фикстуры проверяют enum, пустой `reason`, отсутствие ledger,
дубликаты, orphan-ссылки, конфликт control/disposition, конфликт с
`CLOSURE-CONTRACT.tsv`, несовпадение `disposition`, дрейф `reason` и строгий
UTC-формат `decided_at`, а после R1 также точную арность каждой TSV-строки:
`extra_data_field` и `short_data_row` обязаны fail-closed.

Реальный `index/source-v4/DISPOSITION-LEDGER.tsv` после Step 7A содержит только
заголовок. Поэтому прогресс FSTEC остаётся `349 / 5 / 344`.
