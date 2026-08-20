# Паритет регенерации блока `source:`

Этап 6 roadmap закрывает разрыв между каноническим генератором `source:` и
закоммиченными control records.

## Инвариант

Для каждого закоммиченного control:

1. `source.index_id` должен разрешаться в выбранном source index общего
   контракта;
2. `unit_kind` строки должен поддерживаться каноническим генератором;
3. генератор должен заново построить полный семиполевой блок `source:`;
4. байты регенерированного блока должны совпасть с байтами закоммиченного
   `source:`.

Любой другой результат обрабатывается fail-closed.

Parity-checker:

`checker/source-parity-v1/source_block_regeneration_parity.py`

принимает явные пути `--index` и `--controls`. Текущие значения по умолчанию —
`index/source-v4/SOURCE-INDEX.tsv` и `controls`, но сам checker не ограничен
путём только к FSTEC index.

## Доказательства текущего закрытия

Текущих controls: 8.

Текущий результат:

`controls=8 supported=8 matched=8 unsupported=0 missing_index=0 mismatches=0 errors=0`

Следовательно, для всех восьми controls механически обеспечен паритет
регенерации.

Сам генератор `source:` пока поддерживает один из тринадцати текущих
`unit_kind` — `numbered-position`. Если закоммиченный control ссылается на
неподдерживаемый тип, parity выдаёт `UNSUPPORTED` и завершается неуспешно; такой
control никогда не пропускается молча.

Постоянная отрицательная регрессия покрывает:

- изменение `quote`;
- изменение `quote_sha256`;
- изменение `locator`;
- неподдерживаемый `unit_kind`;
- отсутствующую строку index;
- дублированный или некорректный top-level блок `source:`.

## Граница ответственности

Этот этап не создаёт controls, не изменяет source corpora, не меняет Gate 1–6
и не закрывает строки source index. Прогресс FSTEC остаётся:
349 всего / 8 controlled `CLOSED` / 341 `OPEN`.

Следующий этап roadmap — расширение FSTEC + corporate index / dispositions.
