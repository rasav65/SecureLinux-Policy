# SecureLinux-Policy v3 — основной план дальнейших работ

Это обязательный порядок работ после закрытия evidence на reference VM для
Step 5. Нельзя начинать более поздний этап, пока предыдущий не закрыт, если
этот roadmap не был отдельно пересмотрен и изменён.

1. Закрытие provenance-аудита Step 5
2. Gate 6 `evidence_binding`
3. Очистка контракта type/boolean
4. Обязательный release-gate с реальным `jsonschema`
5. Универсальный по индексу генератор блока `source:`
6. Gate паритета регенерации `source:`
7. Расширение FSTEC + corporate index / dispositions
8. Семантический контракт apply/restore
9. Implementation adapters
10. Детерминированная сборка
11. Единый распространяемый `securelinux-ng.sh`

Неизменяемые правила:

- нельзя начинать массовую работу по 344 строкам FSTEC со статусом `OPEN` до
  закрытия Gate 6, очистки boolean/type, генератора `source:` и паритета
  регенерации;
- Gate 6 доказывает привязку и целостность evidence, но не криптографическое
  происхождение от конкретной VM;
- генератор `source:` универсален по индексу и является единственным
  нормативным производителем блока;
- parity-gate регенерирует `source:` и сравнивает результат с закоммиченными
  controls;
- `211` — только измеренное количество строк
  `source_role=transitive-process` в source-v4, а не прогноз disposition;
- corporate — самостоятельный policy layer и должен иметь собственную
  популяцию index;
- семантика apply/restore должна быть определена до implementation adapters;
- финальный монолит — детерминированный артефакт сборки, а не источник истины;
- генерируемый результат не должен зависеть от timestamps, абсолютных путей,
  порядка обхода файловой системы или timing `unittest`;
- каждый сгенерированный блок несёт provenance: `control_id`, source locator,
  `quote_sha256`, идентификатор/версию implementation adapter;
- release/audit validation требует реального валидатора Draft 2020-12 и
  фиксирует его версию;
- будущие Git bundles должны активно проверяться и сравниваться по дереву со
  снимком проекта; сами по себе они не доказывают происхождение из конкретного
  remote.

ТЕКУЩИЙ СТАТУС: этапы roadmap 1–6 `CLOSED`; этап 7
FSTEC + corporate index expansion / dispositions имеет статус `NEXT`.

## Правило сохранения инженерного донора

Сохранённый проект SecureLinux-NG v16.2.11 остаётся **инженерным донором**, а
не нормативным источником. До начала этапа 8
(`apply/restore semantic contract`) проект ОБЯЗАН завершить и проверить
`DONOR_TO_V3_MAPPING` с решениями `REUSE | ADAPT | REJECT | DEFER`.

Mapping должен явно учитывать зрелые механизмы донора, перечисленные в
`docs/DONOR-V3-ADOPTION-POLICY.md`. Сам mapping закрывает 0 строк FSTEC или
corporate source index. Ни один implementation adapter не может обходить
контракт apply/restore только потому, что эквивалентный код существовал в
доноре.

## Закрытие Gate 6

Gate 6 `evidence_binding` реализован и проверен для текущего фактического
evidence `sysctl-v1` с reference VM.

Он доказывает следующую привязку:

`VM-METADATA -> probe.py -> probe-plan.tsv -> privileged/unprivileged results -> evidence SHA256SUMS`

Он **не** доказывает криптографическое происхождение от указанной VM.

TYPE/BOOLEAN CONTRACT CLEANUP: CLOSED.

## Закрытие очистки контракта type/boolean

Случайное общее преобразование строк `"true"` / `"false"` в boolean удалено.

Текущие и будущие контракты observation:

- sysctl: runner реализован; integer/string значения wire-format передаются как
  JSON strings; boolean не является допустимым типом sysctl control;
- systemd-unit-state: будущий runner должен выдавать JSON boolean для boolean
  `VALUE`;
- package-presence: будущий runner должен выдавать JSON boolean для boolean
  `VALUE`;
- file-kv boolean: явно отложен до тех пор, пока дизайн probe не определит
  source-specific текстовое отображение.

Этот этап не меняет ни одной записи `KIND_RULES` и ни одного байта
сгенерированного control-schema.

MANDATORY REAL-JSONSCHEMA RELEASE GATE: CLOSED.

## Закрытие обязательного release-gate с реальным `jsonschema`

Release/audit validation теперь работает fail-closed, если недоступен реальный
установленный `jsonschema.Draft202012Validator`.

Evidence закрытия фиксирует фактически использованную версию дистрибутива
`jsonschema`, hash schema/checker/differential-test, размеры матрицы и
результаты активных controls. Полная матрица runtime↔real-validator и матрица
emulator↔real-validator обязаны иметь нулевое число расхождений.

Это отдельное доказательство и не является Gate 0 generation parity.

INDEX-GENERIC SOURCE SKELETON GENERATOR: CLOSED.

## Закрытие универсального по индексу генератора `source:`

`tools/source_skeleton_generator.py` является каноническим производителем
`source:` для поддерживаемых `unit_kind`.

Текущая область намеренно узкая и измеримая:

- source index: 349 строк / 13 типов `unit_kind`;
- поддерживаемый тип: только `numbered-position`;
- строк поддерживаемого типа: 74;
- точных извлечений: 72;
- отказ без угадывания: `SRC-0001`, `SRC-0133`;
- текущие принятые controls воспроизводятся побайтово: 5/5.

Генератор принимает явный путь к index и использует его общий контракт. Он
fail-closed проверяет normalizer, corpus manifests и hash нормализованного
корпуса.

На этапе 5 «единственный производитель» был нормативным правилом авторинга.
Этап 6 теперь обеспечивает его механически для закоммиченных controls через
побайтовый паритет регенерации.

Это закрытие не меняет controls и закрывает 0 строк FSTEC source index.

SOURCE-BLOCK REGENERATION PARITY: CLOSED.

## Закрытие паритета регенерации блока `source:`

`checker/source-parity-v1/source_block_regeneration_parity.py` теперь
механически обеспечивает правило единственного нормативного производителя для
каждого закоммиченного control.

Результат текущего закрытия:

- controls: 5;
- supported: 5;
- побайтовых совпадений: 5;
- unsupported: 0;
- отсутствующих строк index: 0;
- mismatches: 0;
- errors: 0.

Будущий control, чей `unit_kind` ещё не поддерживается, классифицируется как
`UNSUPPORTED` и приводит к fail-closed, а не обходит parity.

Постоянные отрицательные fixtures покрывают изменения `quote`,
`quote_sha256`, `locator`, неподдерживаемые типы, отсутствующие строки index и
некорректные дублированные блоки `source:`.

Этот этап не меняет controls и закрывает 0 строк FSTEC source index.

## Step 7A — усиление disposition contract / ledger

Перед первым реальным disposition альтернативный путь Gate 2 обязан иметь
проверяемый артефакт, симметричный по строгости с completeness contract для
controlled-строк. Для этого используется соседний с index файл
`DISPOSITION-LEDGER.tsv`.

Минимальный контракт v1:

- одна ledger-запись на `index_id`; дубликаты и orphan-ссылки запрещены;
- disposed `CLOSED` без ledger-записи запрещён;
- controlled row с ledger-записью запрещён;
- `disposition` и `reason` должны совпадать с `SOURCE-INDEX.tsv`;
- `basis` и `decided_by` обязательны;
- `decided_at` имеет строгий UTC-формат `YYYY-MM-DDTHH:MM:SSZ` и реально
  разбирается как календарная дата;
- disposed row не может одновременно иметь `CLOSURE-CONTRACT.tsv`.

Позитивная синтетическая фикстура впервые исполняет `disposed_closed=1`;
реальный ledger source-v4 остаётся без записей. Архитектурное изменение
закрывает 0 строк FSTEC, поэтому состояние остаётся `349 / 5 / 344`.

Quote-anchor в ledger v1 не добавляется искусственно. Текущий generator умеет
канонически извлекать не все `unit_kind`, а две строки поддержанного типа
намеренно REFUSED. Пока невозможно машинно отличить все допустимые случаи
отказа от integrity failure единым стабильным состоянием, обязательный hash
создал бы ложную гарантию. Этот вопрос возвращается по мере расширения
канонического generator.

Multi-index/population descriptor не является частью 7A. Он вводится перед
первым реальным corporate primary source, когда понадобится убрать hard-coded
FSTEC source root и сохранить глобальный Gate 4.

### Step 7A R2 — исправление closed-schema после независимого аудита

Аудит R1 перевёл Step 7A из предварительного `CLOSED` в `REVISE` из-за
`S7A-R1-B01`: шестиколоночный header не гарантировал шестиколоночную строку
данных. Лишнее седьмое значение попадало в `csv.DictReader` под ключ `None` и
игнорировалось.

R2 требует одновременно:

- точный набор и порядок шести колонок header;
- **ровно шесть TSV-значений в каждой data-row**;
- fail-closed `7 fields` и `5 fields` fixtures;
- сохранение всех прежних disposition negative fixtures;
- полный прогон `tests/` до и после изменения без новых падений;
- `349 / 5 / 344`, real ledger rows `0`.

После реализации R2 статус Step 7A — `AWAITING_INDEPENDENT_REAUDIT`.
Step 7B и первый реальный disposition до повторного аудита запрещены.

Quote-anchor теперь имеет отдельный pre-real-disposition gate:
`REQUIRE_BEFORE_FIRST_REAL_DISPOSITION`. Будущий generator API должен
различать `EXACT`, `REFUSED`, `UNSUPPORTED`, а integrity failures должны
оставаться исключениями.

NEXT: FSTEC + corporate index expansion / dispositions.
