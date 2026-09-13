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

Проверка паритета:

`checker/source-parity-v1/source_block_regeneration_parity.py`

принимает явные пути `--index` и `--controls`. Текущие значения по умолчанию —
`index/source-v4/SOURCE-INDEX.tsv` и `controls`, но сам checker не ограничен
путём только к FSTEC index.

## Доказательства текущего закрытия

Текущая control population читается непосредственно из
`controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv`; checker не содержит
ручного числа controls. Regression требует, чтобы `controls`, `supported` и
`matched` каждый раз равнялись фактическому числу строк current
`CONTROL-MANIFEST.tsv`, при `unsupported=0`, `missing_index=0`,
`mismatches=0`, `errors=0`.

Следовательно, для всей current manifest population механически обеспечен
паритет регенерации без исторического числового pin.

Сам генератор `source:` пока поддерживает часть текущих `unit_kind` —
`numbered-position` и `general-numbered-position`. Parity использует тот же Step 7B
typed-result API, что и coverage. Если закоммиченный control ссылается на
неподдерживаемый тип, parity выдаёт `UNSUPPORTED` с `reason_code` и завершается
неуспешно. Deliberate refusal выдаётся как `REFUSED` с `reason_code`; integrity
failure остаётся `ERROR`. Ни одно из этих состояний не пропускается молча.

Постоянная отрицательная регрессия покрывает:

- изменение `quote`;
- изменение `quote_sha256`;
- изменение `locator`;
- неподдерживаемый `unit_kind`;
- отсутствующую строку index;
- дублированный или некорректный top-level блок `source:`.

## Граница ответственности

Сам parity-checker не создаёт controls, не изменяет source corpora, не меняет
Gate 1–6 и не закрывает строки source index. Актуальный corpus progress не
дублируется вручную в этом документе: его machine truth —
`index/source-v4/PROGRESS.txt` и generated `docs/fstec-coverage.md`.
