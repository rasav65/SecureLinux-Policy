# Регрессия disposition ledger v1

Проверяет усиленный альтернативный путь закрытия строки source index до первого
реального disposition.

Позитивная фикстура синтетически исполняет `disposed_closed=1`.
Отрицательные фикстуры проверяют enum, пустой `reason`, отсутствие ledger,
дубликаты, orphan-ссылки, конфликт control/disposition, конфликт с
`CLOSURE-CONTRACT.tsv`, несовпадение `disposition`, дрейф `reason` и строгий
UTC-формат `decided_at`, а после R1/R2 также физический TSV-контракт:
`extra_data_field`, `short_data_row`, `quoted_tab_basis`,
`quoted_newline_basis`, `quoted_cr_basis` и `quoted_tab_reason` обязаны
fail-closed. Кавычки не имеют CSV-семантики и не могут скрывать delimiter или
склеивать физические строки.

Negative-control правило для этого контракта: parser-level негативный случай сначала применяют к
наименее ограниченному полю (`basis`), затем минимум к одному дублируемому
свободнотекстовому полю (`reason`). Критерий PASS — буквальное соблюдение
заявленного инварианта, а не отсутствие видимого вреда из-за побочной проверки.

Реальный `index/source-v4/DISPOSITION-LEDGER.tsv` содержит записи аудированных
диспозиций; их число показывает генерируемый машинный статус. Этот README намеренно не закрепляет live-счётчики coverage: они
выводятся из `SOURCE-INDEX.tsv`, `CLOSURE-CONTRACT.tsv` и control manifest, а
человекочитаемое текущее покрытие формирует `docs/fstec-coverage.md`.
