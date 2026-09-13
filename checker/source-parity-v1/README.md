# Паритет регенерации блока `source:`

Этап 6 roadmap механически обеспечивает введённое на этапе 5 правило
единственного нормативного производителя для закоммиченных блоков `source:`.

Проверяющий модуль:

- загружает канонический генератор `source:` через `tools/SHA256SUMS`;
- загружает выбранный source index через общий index-контракт генератора;
- находит закоммиченные YAML controls;
- регенерирует `source:` для каждого control с поддерживаемым `unit_kind`;
- требует побайтового равенства с закоммиченным блоком;
- работает fail-closed при неподдерживаемом `unit_kind`, отсутствующей строке
  index, некорректном блоке `source:`, ошибке генерации или любом байтовом
  расхождении.

Текущая область проверки — вся current manifest population из
`controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv`; числовой размер checker
не пинит. Regression требует, чтобы `controls`, `supported` и `matched`
совпадали с фактической manifest population, а `unsupported`, `missing_index`,
`mismatches` и `errors` оставались нулевыми.

Parity использует тот же Step 7B typed-result API, что и coverage:
`EXACT | REFUSED | UNSUPPORTED` со стабильным `reason_code`. Для current
control population допустим только `EXACT`; `REFUSED`, `UNSUPPORTED` и
integrity failure завершают parity неуспешно и не пропускаются молча.

Этот checker не закрывает строки source index и не меняет семантику Gate 1–6.
Он защищает provenance-блок, который используют эти gates.
