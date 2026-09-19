# SecureLinux-Policy — основной план дальнейших работ

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
8. Parent gate APPLY + проверка source-specific instance
9. Authority refresh 2026: приказ № 117 + изменения № 137
10. Модульная архитектура APPLY-contract для `SRC-0001`
11. Точные определения предиката и преобразования для `SRC-0001`
12. Определение условия внешнего снимка для `SRC-0001`
13. Определения блокировки, повторного чтения и идентичности объекта для `SRC-0001`
14. Определения метаданных, атомарной транзакции и сухого запуска с отчётом для `SRC-0001`
15. Адаптеры реализации APPLY
16. Детерминированная финальная упаковка
17. Единый распространяемый артефакт (имя не закреплено)
18. Переработка семантики CHECK для `SRC-0008 / 2.3.4`
19. Горизонт 1: APPLY для безопасных классов `fstec-linux-2022` + VM-прогоны

Неизменяемые правила:

- нельзя начинать массовую работу по текущим строкам FSTEC со статусом `OPEN` до
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
- семантика APPLY должна быть определена до implementation adapters;
- пользовательский режим RESTORE не входит в целевую архитектуру; аварийный откат после завершённого APPLY выполняется внешним snapshot rollback;
- локальный compensating rollback внутри незавершённой APPLY-транзакции допустим как механизм fail-safe и не является режимом RESTORE;
- финальный монолит — детерминированный артефакт сборки, а не источник истины;
- генерируемый результат не должен зависеть от timestamps, абсолютных путей,
  порядка обхода файловой системы или timing `unittest`;
- каждый сгенерированный блок несёт provenance: `control_id`, source locator,
  `quote_sha256`, идентификатор/версию implementation adapter;
- release/audit validation требует реального валидатора Draft 2020-12 и
  фиксирует его версию;
- будущие Git bundles должны активно проверяться и сравниваться по дереву со
  снимком проекта; сами по себе они не доказывают происхождение из конкретного
  удалённого репозитория.

ТЕКУЩИЙ СТАТУС: этапы roadmap 1–6 `CLOSED`. `NEXT` — этап 19
`HORIZON1_SAFE_CLASS_APPLY_AND_VM_RUNS` (горизонт 1): APPLY для безопасных классов
`fstec-linux-2022` и VM-прогоны механизмов. Макроэтап 7
`FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS` не завершён и имеет статус
`WAITING_FOR_HORIZON_1`: Step 7A закрыт, Step 7B ждёт закрытия горизонта 1.

Для `fstec-linux-2022` read-only CHECK принят, обязательный
`DONOR_TO_V3_MAPPING` принят и опубликован. Покрытие индекса источников
описывается тремя числами: 40 строк закрыты контролями, 211 закрыты
аудированной диспозицией, 98 остаются открытыми; это машинное состояние
индекса, а не процент готовности к требованиям ФСТЭК. Семантика CHECK для
`SRC-0008 / 2.3.4` переработана и принята: контроль использует
`root-owned-go-w-conditional`, шаг `SRC0008_CHECK_SEMANTIC_REWORK` закрыт. Этап 8
`APPLY_SEMANTIC_CONTRACT` имеет status `PARENT_GATE_CLOSED_SOURCE_INSTANCE_REVISE`:
parent schema/registry gate остаётся принят и не переоткрывается, а flat
source-specific contract-кандидат `SRC-0001` сохраняется только как `REVISE` input.
Решением DP-3 SRC-0001 выведен из product APPLY: его модульная архитектура, восемь
определений и композиция сохранены как historical bytes и в APPLY registries не входят.
Действующий APPLY задают механизмы `config-line-with-runtime-v1` и `file-mode-owner-v1`,
каждый со своим authority-документом формы `MECHANISM_AUTHORITY_V1`; состав и
количества берутся из APPLY registries и машинного статуса корневого README.
Этап 9 `AUTHORITY_2026_REFRESH` закрыт после интеграции приказа ФСТЭК
России № 137 как изменения к приказу № 117; это framework-only обновление и
оно не переоткрывает `SRC-0001…SRC-0040`.

Этап 10 `SRC0001_MODULAR_APPLY_CONTRACT_ARCHITECTURE` закрыт: компактный
`APPLY-KIND-REGISTRY.tsv` связывает `apply_kind`/`target_class` только с локальным
объектом архитектуры по SHA-256. Этап 11 `SRC0001_PREDICATE_TRANSFORM_DEFINITIONS`
также закрыт: predicate закрепляет **ровно пустое второе поле** соответствующей
`/etc/shadow` записи в exact population текущего CHECK, а transform выполняет
единственную замену байтов `"" -> "!"` только в выбранном втором поле. Все
невыбранные записи, непустые password fields, остальные поля, порядок записей и
остальные bytes файла обязаны сохраняться exact; stale/non-empty selected field
даёт `ABORT_NO_MUTATION`. Обе definition identity SHA-bound в architecture, а
transform отдельно SHA-bound к predicate. Этим P-03 закрыт. Этап 12
`SRC0001_SNAPSHOT_PRECONDITION_DEFINITION` также закрыт: до любой host mutation
обязателен caller-supplied read-only `SLP-EXTERNAL-SNAPSHOT-ATTESTATION-V1`.
Attestation связывает `SRC-0001`, control, `/etc/shadow`, текущий
`/etc/machine-id` и SHA-256 exact prestate bytes `/etc/shadow` с non-empty
external provider/snapshot id, scope `FULL_TARGET_HOST_OR_VM`, `state=READY` и
`rollback_capable=true`. Missing/malformed/mismatched/not-ready evidence всегда
`ABORT_NO_MUTATION`; product не создаёт и не восстанавливает snapshot, а evidence
явно является operator attestation, не provider-cryptographic proof. Этим P-04
закрыт. Этап 13 `SRC0001_LOCK_REREAD_OBJECT_IDENTITY_DEFINITIONS` также закрыт:
exclusive libc `lckpwdf(3)` password-database lock должен быть получен до under-lock reread и любой
host mutation; exact bytes и ordered selected usernames reread под lock обязаны
совпасть с pre-lock reference, иначе `ABORT_NO_MUTATION`. `/etc/shadow` обязан быть
regular non-symlink с `st_nlink == 1`; target и parent identities связываются через
`lstat` + nofollow fd/fstat и не могут дрейфовать до собственного atomic commit.
Этим P-05 закрыт. Этап 14 `SRC0001_METADATA_TRANSACTION_REPORT_DEFINITIONS` также закрыт: точные определения сохранения метаданных, атомарной транзакции и сухого запуска с отчётом привязаны по SHA-256 в архитектуре, а композиция связывает все восемь ролей со статусом `CLOSED`.

Этап 15 `APPLY_IMPLEMENTATION_ADAPTERS` был закрыт первой вертикалью `SRC-0001`: отдельный
implementation registry, binding и adapter были привязаны к композиции; generated CLI
прошёл dry-run, attested commit, post-check, idempotent NOOP и fail-closed VM cases.
На момент закрытия общая библиотека APPLY и вторая вертикаль не создавались. Позже
решением DP-3 эта вертикаль выведена из product APPLY, а APPLY перестроен на механизмы
`config-line-with-runtime-v1` и `file-mode-owner-v1`. Этап 16
`FINAL_DETERMINISTIC_PACKAGING` закрыт: исправленная APPLY provenance вошла в
generated CLI, семь случаев воспроизводимости сборки прошли, а права выдаваемых
CLI/sidecar проверены как `0755/0644`.

Этап 17 `SINGLE_DISTRIBUTABLE_ARTIFACT` закрыт существующим generated
`securelinux-policy.sh`: свежая генерация даёт byte-exact тот же CLI и sidecar,
а `--provenance` несёт требуемые source/adapter bindings. Sidecar остаётся
сопутствующим integrity metadata; новый архивный слой не создавался, архивный
формат не выбирался, имя будущего release/distributable не закреплено.
Текущая вертикаль достигла точки `DOCUMENT COMPLETE`.

Определение критерия. Для `fstec-linux-2022` `DOCUMENT COMPLETE` достигается,
когда все строки этого документа в `index/source-v4/SOURCE-INDEX.tsv` имеют
`status=CLOSED`, APPLY завершён в объёме, зафиксированном действующими APPLY registries, а этапы
`FINAL_DETERMINISTIC_PACKAGING` и `SINGLE_DISTRIBUTABLE_ARTIFACT` закрыты.
Настоящим решением APPLY для остальных строк `fstec-linux-2022` в критерий
`DOCUMENT COMPLETE` не входит. Для следующих документов критерий определяется
отдельно и автоматически не наследуется.

После `DOCUMENT COMPLETE` пауза Step 7B снята. Решением пользователя 19.09.2026
первым идёт горизонт 1 `HORIZON1_SAFE_CLASS_APPLY_AND_VM_RUNS`, а Step 7B
`FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS` ждёт его закрытия; оставшиеся
`OPEN` строки корпуса остаются в очереди source-first расширения. Исторические закрытия Step 7B
(`SRC-0005/CHECK-11`, sysctl batches, `kernel-cmdline` и последующие controls)
остаются принятыми фактами.

## Правило сохранения инженерного донора

Сохранённый проект SecureLinux-NG v16.2.11 остаётся **инженерным донором**, а
не нормативным источником. Обязательный `DONOR_TO_V3_MAPPING` с решениями
`REUSE | ADAPT | REJECT | DEFER` был завершён до APPLY-contract track и
остаётся входным engineering evidence для дальнейшей модульной архитектуры.

Mapping должен явно учитывать зрелые механизмы донора, перечисленные в
`docs/DONOR-ADOPTION-POLICY.md`. Сам mapping закрывает 0 строк FSTEC или
corporate source index. Ни один implementation adapter не может обходить
контракт APPLY только потому, что эквивалентный код существовал в
доноре.

## Модель отката для APPLY

Проект не реализует пользовательский режим `RESTORE`.

Эксплуатационный контракт текущей вертикали:

`external snapshot -> CHECK -> APPLY -> CHECK`

Если после успешно завершённого APPLY обнаружена несовместимость со сторонним
ПО или иная эксплуатационная проблема, восстановление системы выполняется
внешним snapshot rollback средствами инфраструктуры. SecureLinux-Policy не
создаёт snapshot, не восстанавливает snapshot и не заявляет собственный
RESTORE после APPLY.

При этом APPLY обязан оставаться транзакционно безопасным: до каждой mutation
проверяются preconditions, а ошибка внутри ещё не завершённой APPLY-транзакции
не должна молча оставлять частично применённое состояние. Точечный compensating
rollback текущей незавершённой транзакции допустим там, где exact rollback
доказуем; это внутренний failure-handling APPLY, а не отдельный RESTORE mode.

Историческая SRC-0001 APPLY-вертикаль, решением DP-3 выведенная из product APPLY,
определяла exact snapshot precondition в `product/contracts/src0001-apply/snapshot-precondition-v1.json`:
принималась только explicit caller-supplied attestation, привязанная к host identity и exact
`/etc/shadow` prestate SHA-256; отсутствие, malformed data, mismatch или state не `READY`
давали `ABORT_NO_MUTATION`. Это не выдавалось за криптографическое доказательство provider snapshot.

Exact lock/reread contract той же вертикали (`lckpwdf(3)` + exact `/etc/passwd`/`/etc/shadow` reread + precommit revalidation) определён `product/contracts/src0001-apply/lock-reread-v1.json`,
а object identity boundary — `product/contracts/src0001-apply/object-identity-v1.json`.
Lock требовался до reread/mutation; stale bytes/target-set или object/path drift всегда
останавливали попытку без mutation. Hardlink ambiguity (`st_nlink != 1`) была запрещена.
Действующие механизмы эти определения не используют; их preconditions задают
собственные authority-документы.

## Закрытие Gate 6

Gate 6 `evidence_binding` реализован и проверен для текущего фактического
evidence `sysctl-v1` с reference VM.

Он доказывает следующую привязку:

`VM-METADATA -> probe.py -> probe-plan.tsv -> privileged/unprivileged results -> evidence SHA256SUMS`

Он **не** доказывает криптографическое происхождение от указанной VM.

TYPE/BOOLEAN CONTRACT CLEANUP: CLOSED — этап закрыт.

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

MANDATORY REAL-JSONSCHEMA RELEASE GATE: CLOSED — этап закрыт.

## Закрытие обязательного release-gate с реальным `jsonschema`

Release/audit validation теперь работает fail-closed, если недоступен реальный
установленный `jsonschema.Draft202012Validator`.

Evidence закрытия фиксирует фактически использованную версию дистрибутива
`jsonschema`, hash schema/checker/differential-test, размеры матрицы и
результаты активных controls. Полная матрица runtime↔real-validator и матрица
emulator↔real-validator обязаны иметь нулевое число расхождений.

Это отдельное доказательство и не является Gate 0 generation parity.

INDEX-GENERIC SOURCE SKELETON GENERATOR: CLOSED — этап закрыт.

## Закрытие универсального по индексу генератора `source:`

`tools/source_skeleton_generator.py` является каноническим производителем
`source:` для поддерживаемых `unit_kind`.

Текущая область намеренно узкая и измеримая. Supported/exact/refused
population вычисляется regression-тестом из текущего index и не закрепляется
roadmap-числами или ручным списком refused identities. Поддерживаемый тип —
`numbered-position`; `SRC-0001` допускается только через exact pinned
page-furniture exception и не является current refused identity. Текущие
принятые controls воспроизводятся побайтово, а их population читается из
`CONTROL-MANIFEST.tsv`.

Генератор принимает явный путь к index и использует его общий контракт. Он
fail-closed проверяет normalizer, corpus manifests и hash нормализованного
корпуса.

На этапе 5 «единственный производитель» был нормативным правилом авторинга.
Этап 6 теперь обеспечивает его механически для закоммиченных controls через
побайтовый паритет регенерации.

Это закрытие не меняет controls и закрывает 0 строк FSTEC source index.

SOURCE-BLOCK REGENERATION PARITY: CLOSED — этап закрыт.

## Закрытие паритета регенерации блока `source:`

`checker/source-parity-v1/source_block_regeneration_parity.py` теперь
механически обеспечивает правило единственного нормативного производителя для
каждого закоммиченного control.

Результат на текущем HEAD вычисляется из `CONTROL-MANIFEST.tsv` и
`ADAPTER-REGISTRY.tsv`; roadmap не пинует число current controls, adapter kinds
или parity-result counters вручную.

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
канонически извлекать не все `unit_kind`, а deliberate REFUSED остаётся
fail-closed состоянием для части поддержанной population. Exact/refused set
вычисляется regression-тестом и не пинуется roadmap-текстом. Пока невозможно
машинно отличить все допустимые случаи отказа от integrity failure единым
стабильным состоянием, обязательный hash создал бы ложную гарантию. Этот вопрос
возвращается по мере расширения канонического generator.

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
- `349 / 5 / 344`, реальных строк ledger `0`.

Повторный аудит R2 выявил `S7A-R2-B01`: `csv.reader` с включённой
CSV quoting-семантикой позволял спрятать `TAB` внутри кавычек и объединять две
физические строки через quoted `CR/LF`. Поэтому Step 7A остаётся `REVISE`.

### Step 7A R3 — physical TSV без quoting

R3 требует:

- `csv.reader(..., delimiter="\t", quoting=csv.QUOTE_NONE)`;
- точный шестипольный header и ровно шесть значений каждой физической строки;
- quoted `TAB` в `basis` → FAIL;
- quoted `LF` и quoted `CR` в `basis` → FAIL;
- quoted `TAB` в `reason` → FAIL независимо от index↔ledger equality;
- полный `tests/` без новых регрессий;
- `349 / 5 / 344`, реальных строк ledger `0`.

Negative-control методика: parser-level негативные случаи проверяются прежде всего на
наименее ограниченном поле (`basis`), затем на других свободнотекстовых полях.
Критерий — буквальное выполнение объявленного инварианта, а не отсутствие
видимого вреда благодаря другой проверке.

Повторные независимые R3-аудиты дали `ACCEPT`: `S7A-R2-B01` закрыт,
новых блокеров `S7A-R3-Bxx` не выявлено. Статус Step 7A — `CLOSED`.

### Step 7B — расширение FSTEC

Step 7B возобновлён после достижения `DOCUMENT COMPLETE` текущей вертикали и
ждёт закрытия горизонта 1 (`WAITING_FOR_HORIZON_1`). Расширение FSTEC выполняется
только по source-first пути:

- новые технические controls должны проходить generator/parity/gates;
- disposition вносится только через `DISPOSITION-LEDGER.tsv` с построчным основанием;
- corporate multi-index/descriptor остаётся отложен до появления первого
  реального corporate primary source;
- roadmap/documentation regressions обязаны проверять machine truth и
  семантические инварианты, а не исторические точные фразы.

Quote-anchor реализован как typed generator API: он различает `EXACT`,
`REFUSED`, `UNSUPPORTED`, а integrity failures остаются исключениями.
Диспозиции процессных документов внесены в ledger по альтернативному пути
Gate 2; их число — в генерируемом машинном статусе.

Carry-forward non-blocking findings R3: NUL, `U+2028/U+2029`, VT/FF и CRLF
не запрещены текущим physical-TSV контрактом; их возможное ограничение —
отдельное расширение контракта, а не незакрытый blocker R3. Прежние замечания
по whitespace, future `decided_at`, силе `basis`, связи
`source_role ↔ disposition`, multi-index ledger и устаревшим notes сохраняются
в backlog и должны учитываться перед соответствующими изменениями.

### Горизонт 1 — APPLY для безопасных классов и VM-прогоны

Горизонт 1 (`HORIZON1_SAFE_CLASS_APPLY_AND_VM_RUNS`) охватывает APPLY для безопасных классов
`fstec-linux-2022` через механизмы `config-line-with-runtime-v1`,
`file-mode-owner-v1` и следующие механизмы того же рода, а также VM-прогоны
механизмов на матрице сред. Статус механизма определяется гейтами: `closed` —
после `--release` и восьмисредового VM-цикла, до этого — `current`. Контроли,
для которых APPLY небезопасен, остаются за границей продукта: продукт печатает
причину и возвращает решение администратору.

NEXT: `HORIZON1_SAFE_CLASS_APPLY_AND_VM_RUNS` (горизонт 1); затем
`FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS` (Step 7B).
`APPLY_IMPLEMENTATION_ADAPTERS`, `FINAL_DETERMINISTIC_PACKAGING` и
`SINGLE_DISTRIBUTABLE_ARTIFACT` закрыты; текущая вертикаль имеет `DOCUMENT COMPLETE`.
