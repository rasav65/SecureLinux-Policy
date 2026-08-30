# Обратный индекс инженерного донора v1

Этот index сохраняет и делает доступной для поиска инженерную работу из
`archive/securelinux-ng.sh`.

Он **не является нормативным source index** и не закрывает ни одной FSTEC row.

Закреплённый donor:

- SHA-256: `f3be8723cd5a2be499e9e8e6370fad712bdec8afd68050f27af6a3e2d6fbc34b`
- строк: `18928`

Содержимое:

- `FUNCTION-INDEX.tsv` — 310 объявлений shell functions с source ranges и SHA-256
  source segment до следующего объявления функции;
- `SOURCE-CHUNKS.tsv` — полное покрытие 18 928 строк donor детерминированными
  chunks по 100 строк; 190 rows;
- `SEMANTIC-CANDIDATES.tsv` — 141 ранее извлечённый parameter candidate;
- `RAW-EVIDENCE.tsv` — 478 raw evidence rows, использованных при выводе candidates;
- `ENGINEERING-CONTRACTS.tsv` — 20 проверенных implementation invariants, которые
  нужно сохранить или явно классифицировать при появлении APPLY в v3. Donor
  RESTORE-specific mechanisms являются evidence, а не обязательством current roadmap;
- `SOURCE.tsv` — provenance donor script, финального architecture review и четырёх
  проектных документов донора.

Важно:

1. Этот материал является engineering evidence, а не FSTEC truth.
2. Candidate rows не превращаются в controls автоматически.
3. `v3_status=PENDING_NOT_ACTIVE` означает, что invariant принят как будущий
   implementation contract, но не заявлен как реализованный текущим read-only pilot.
4. `index/source-v4` остаётся единственным active FSTEC coverage index на этом этапе.

## Класс переноса

Каждая строка `FUNCTION-INDEX.tsv` содержит `adoption_class` и `adoption_note`.
Класс *выводится* из других таблиц, а `test_donor_index.py` завершается FAIL,
если сохранённое значение расходится с derivation, поэтому колонка не может
дрейфовать независимо.

| class | смысл |
|---|---|
| `contracted` | функция указана как `evidence_function` в `ENGINEERING-CONTRACTS.tsv` |
| `candidate` | функция указана как `source_function` в `SEMANTIC-CANDIDATES.tsv` |
| `evidence-only` | функция указана как `source_function` только в `RAW-EVIDENCE.tsv` |
| `pending-review` | функция ещё не проверена на наличие v3 invariant |

`pending-review` в `FUNCTION-INDEX.tsv` — исходная классификация reverse index,
вычисляемая только из `ENGINEERING-CONTRACTS.tsv`, `SEMANTIC-CANDIDATES.tsv` и
`RAW-EVIDENCE.tsv`. После появления отдельного `DONOR-TO-V3-MAPPING.tsv` она
больше не является current-статусом mapping: решение по каждой функции хранится
только в mapping.

Исходное распределение reverse index остаётся неизменным: contracted 18,
candidate 31, evidence-only 53, pending-review 208. Всего 310.

## DONOR_TO_V3_MAPPING

`DONOR-TO-V3-MAPPING.tsv` — machine-readable mapping, принятый и опубликованный
перед началом отдельного семантического контракта APPLY. Он:

- покрывает все 310 donor-функций ровно по одному разу;
- покрывает все 38 donor test files;
- отдельно фиксирует все 16 mature families, обязательные по
  `docs/DONOR-V3-ADOPTION-POLICY.md`;
- использует только решения `REUSE | ADAPT | REJECT | DEFER`;
- связывает существующие `ENG-*` и `TST-*` contracts, когда они применимы;
- для каждой строки фиксирует `normative_effect=NONE` и `closes_source_rows=0`.

Статус `MAPPING_ACCEPTED_COMMITTED` означает, что mapping прошёл независимый review,
precommit и опубликован commit `1db91b0e17d6ef37e4c42cd41dca77eeb2b743da`
с tree `d3f624651bf13f1174619cef881fababbc768553`.
`APPLY_SEMANTIC_CONTRACT_ALLOWED=true` разрешает начать **только отдельный семантический
контракт APPLY**; это не разрешение реализации или изменения host state.
Machine truth mapping дополнительно фиксирует
`RESTORE_OPERATIONAL_CONTOUR=EXCLUDED` и
`POST_APPLY_RECOVERY_MODEL=EXTERNAL_SNAPSHOT`. В `ADAPT` rationale запрещена
operational RESTORE terminology: допускается только transaction-local
compensation незавершённого APPLY; donor restore-named identifiers сохраняются
лишь как exact historical/evidence references или явно ограниченные compensation
fragments. `password-policy-regression.sh` явно остаётся `DEFER` donor для
будущей corporate/APPLY-фазы и не переносится в current `fstec-linux-2022 CHECK`.

## Источники evidence, не являющиеся функциями

`source_function` не всегда является shell function. Четыре origin обозначают
top-level scope или configuration array: `TOPLEVEL`, `CRON_CRITICAL_TARGETS`,
`FAILLOCK_CONF_STRICT`, `GRUB_KERNEL_REQUIRED_PARAMS`. Они объявлены в test явно,
а не допускаются молча.

## Зарегистрированные donor documents

`restore-model.md` остаётся закреплённым donor evidence. Он больше не является
target design source для режима v3 RESTORE. Во время `DONOR_TO_V3_MAPPING` его
механизмы должны классифицироваться как `REJECT` для user-invokable RESTORE или
как `ADAPT` только там, где фрагмент нужен для transaction-local APPLY failure
handling. Документ и остальные три donor documents остаются закреплены SHA-256
в `SOURCE.tsv`.

`fstec-mapping.md` зарегистрирован как
`engineering-donor-claimed-mapping-non-normative`: это собственное заявление
donor о FSTEC coverage, смешивающее номера clauses FSTEC с нумерацией internal
standard. Для v3 это не нормативный source.
