# Индекс источников v1

`SOURCE-INDEX.tsv` является closure population новой модели SecureLinux-Policy.

Правила:
- одна строка соответствует одной независимо учитываемой структурной единице источника;
- строка начинается со статуса `OPEN`;
- строка может стать `CLOSED` только после того, как выполнено одно из условий:
  1. существует как минимум одна принятая record SecureLinux-Policy, либо
  2. существует явное disposition с причиной из точного enum Gate 2:
     `not-technical` / `organizational` / `external` / `out-of-scope` / `informational`;
- `CLOSED_INDEX_ROWS / TOTAL_INDEX_ROWS` является метрикой перехода проекта;
- framework-источники регистрируются отдельно в `FRAMEWORK-SOURCES.tsv` и не являются
  популяцией вида one-control-per-clause;
- Methodology Appendix 2 MEASURE_CLASS_MAP (96 measures, K3/K2/K1) остаётся
  отдельным будущим gate и не смешивается с control records;
- таблицы, рисунки и приложения, явно перечисленные в `SOURCE-INDEX.tsv`,
  сохраняются, чтобы они не исчезли только потому, что не являются обычными
  нумерованными положениями;
- ни одна строка Step 3 не является перенесённым control.

## Framework authority refresh 2026

`FRAMEWORK-SOURCES.tsv` регистрирует framework authority отдельно от
`SOURCE-INDEX.tsv`. Приказ ФСТЭК России от 8 мая 2026 г. № 137
`fstec-order-137-2026-amendments-to-117.pdf` изменяет framework source
`fstec-order-117-2025-requirements.pdf`.

Связь base/amendment и даты вступления в силу фиксируются в
`FRAMEWORK-AUTHORITY-RELATIONS.tsv`: основная часть изменений действует
с `2026-09-01`, а пункт 7 приложения — с `2027-03-01`.

Приказ № 137 является image-only PDF. Канонической authority остаются exact
bytes PDF; derived page-pinned visual transcription/provenance хранится в
`sources/visual-v1/` и не подменяет источник. Он не проходит через обычный
`pdftotext`/glyph-recovery pipeline и сам по себе не создаёт строки
`SOURCE-INDEX.tsv`.

Authority refresh не переоткрывает `SRC-0001…SRC-0040`: их technical-core
authority остаётся `fstec-linux-2022.pdf`, а CLOSED status меняется только при
прямом source mapping/invalidation evidence.

Известные blockers текстового слоя:
- fstec-linux-2022
- fstec-vulnerability-analysis-2025

Их числовая структура индексируема, но извлечённый кириллический текст искажён.
Поэтому эти строки имеют `quote_anchor_ready=NO`; Gate 1 не должен притворяться,
что человекочитаемую буквальную цитату можно доказать по этим повреждённым текстам norm-v1.

## Восстановление текста source-v2

`source-v2` заменяет только метаданные готовности quote-anchor из `source-v1`.
Population из 349 строк и все идентичности source/unit/locator остаются неизменными.

101 ранее заблокированная строка использует восстановленные представления
`norm-v1` из `sources/recovered-v1/`. Ни одна строка source не была закрыта и ни
один control не был создан.

## source-v3 — пилот sysctl на Step 5

Population остаётся равной 349 строкам. Ровно пять строк FSTEC-LINUX-2022 имеют
статус CLOSED, потому что каждую из них представляет один активный control.
Остальные 344 строки остаются OPEN.

## source-v4 — контракт полноты

Контролируемая строка CLOSED валидна только тогда, когда её набор активных control-ID точно
совпадает с `CLOSURE-CONTRACT.tsv`. `atomic-single` означает один полный
parameter; `exact-control-set` означает совместно обязательный набор нескольких
controls.
