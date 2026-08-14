# Changelog

Все существенные изменения активной архитектуры `SecureLinux-Policy-v3`
фиксируются в этом файле.

## [Unreleased]

### Added — visual architecture diagrams

- Added three GitHub-rendered Mermaid diagrams: CLI/runtime modes,
  module/additional-measures/restore flow, and apply/manifest/restore flow.
- Marked them as target runtime architecture inherited from the engineering
  donor, not as claims that every runtime mechanism is already implemented.
- README links directly to the rendered diagrams.
- No normative/runtime behavior changed.

### Added — Gate 6 evidence_binding

- Added a closed-schema evidence-binding checker for the factual `sysctl-v1`
  reference-VM evidence.
- Gate 6 verifies the evidence checksum set, VM metadata schema, current
  probe/plan hashes, both result hashes and `read_only=true` result roots.
- Added positive and nine negative regression cases.
- Gate 6 explicitly emits `VM_ORIGIN_ATTESTATION=NOT_PROVEN`; it proves
  integrity/binding, not cryptographic VM-origin attestation.
- No FSTEC/corporate source rows are closed by this change.
- Next roadmap step: `type/boolean contract cleanup`.

### Pinned — engineering donor adoption policy

- SecureLinux-NG v16.2.11 is formally pinned as an engineering donor, not a
  normative source of truth.
- Mature donor mechanisms must pass through
  `DONOR_TO_V3_MAPPING -> REUSE|ADAPT|REJECT|DEFER` before apply/restore
  contract and implementation-adapter work.
- `DONOR_TO_V3_MAPPING` is now a mandatory precondition to roadmap step 8.
- The donor mapping itself closes zero FSTEC/corporate source-index rows.
- Explicitly protected donor families include preflight, transactional apply,
  manifest/restore, atomic writes, backup fail-closed, package delta,
  preserve-stricter sysctl, isolated sysctl, network-online reapply, dry-run,
  run locking, layer/profile separation and preserved regression contracts.
- Final `securelinux-ng.sh` remains a deterministic generated artifact with
  machine-checkable provenance per emitted block.

### Recorded — Step 5 audit provenance closure

- Stored three Step 5 reference-VM ACCEPT verdict records.
- Did not claim "3 independent reviews": reviewer independence is provenance,
  not a count derived from verdict texts.
- Recorded the known limitation that one reviewer participated in v3 format
  design and authored two verdicts; exact review-id mapping is not asserted.
- Preserved 349 total / 5 controlled CLOSED / 344 OPEN.
- Added the authoritative forward roadmap.
- Next authorized engineering step: Gate 6 `evidence_binding`.

### Added — reference VM Gate 5 evidence

- Выполнен фактический read-only `sysctl-v1` probe на Ubuntu 24.04.4 LTS
  minimized (`testmin`, kernel `6.8.0-134-generic`).
- Непривилегированный прогон: 5 результатов, 4 `VALUE`, 1 `ERROR`;
  `/proc/sys/net/core/bpf_jit_harden` имеет mode `0600 root:root` и обычному
  пользователю не читается. Этот результат сохранён как environment evidence.
- Повторный read-only прогон через `sudo`: 5 `VALUE`, 0 `NOT_FOUND`,
  0 `ERROR`, 4 noncompliant observations.
- Активный checker с реальным evidence:
  `GATE5=PASS checked=5 value=5 not_found=0 noncompliant=4 errors=0`.
- `OVERALL=FAIL` ожидаем и вызван Gate 2: 344 source-index rows остаются OPEN.
- SHA-256 privileged evidence:
  `43c574a68d3478f35e4c7a5a50571ab4408d43a3e3a3cfed9ac3f50fbb1fc29c`.
- SHA-256 unprivileged evidence:
  `53e3bea08d07bcdf4210d125a026c1d1a4ce1481b2ee7d1415d4baf112389203`.

### Added — engineering donor preservation

- Полный SecureLinux-NG v16.2.11 test/development snapshot сохранён byte-for-byte
  и разложен в inspectable archive; source ZIP SHA-256
  `1b25f554a5ad1509037aa9613b7851a595159fd44291913cc2dba63280e50494`.
- Добавлен `index/engineering-tests-v1`: 38 test-файлов, 36 focused regressions,
  36/36 smoke wiring, 32 generalized engineering test contracts и отдельная
  donor VM evidence table.
- Добавлена `docs/testing-strategy.md`: differential, failure-injection,
  crash-consistency, filesystem safety и VM acceptance как разные test layers.
- Активно принят переносимый `tools/write-sha256.py` вместе с адаптированным
  regression-тестом; инструмент не зависит от старого монолитного скрипта.
- Старые donor tests, фиксирующие смешанную FSTEC mapping, явно помечены
  `historical-only` и не участвуют в v3 source coverage.
- Финальный architecture-review SecureLinux-NG сохранён byte-for-byte как
  историческое engineering evidence; он не является нормативным источником v3.
- Добавлен `index/engineering-donor-v1`: 310 функций, 190 source chunks,
  141 semantic candidate, 478 raw evidence rows и 15 будущих инженерных
  контрактов.
- Добавлен regression `tests/engineering-donor-v1/test_donor_index.py`,
  который сверяет reverse-index с pinned donor и запускает исходный
  `architecture-regression.sh` против pinned donor/docs.
- Зафиксировано, что donor-index не создаёт controls и не закрывает FSTEC rows.

### Pending

- Независимый аудит Step 0–5 с фактическим reference-VM evidence.
- Дальнейшее закрытие source-index rows только после прохождения
  соответствующих gates.

## [0.0.5-r3] — 2026-08-14

### Fixed after third independent audit

- B-R2-01: одной строки регулярного выражения недостаточно для одной семантики.
  Runtime сопоставляет шаблоны через `re.fullmatch`, а JSON Schema `pattern`
  имеет search-семантику, и в движке Python `$` совпадает также перед
  завершающим переводом строки. Из-за этого `key: "kernel.x\n"` отвергался
  runtime и принимался валидатором схемы. Достижимо: YAML-подмножество
  пропускает double-quoted скаляр через `json.loads`.
- Введён инвариант single-line: все машинные идентификаторы, локаторы и ключи
  несут явное утверждение об отсутствии CR/LF (`SINGLE_LINE`), которое ведёт
  себя одинаково при fullmatch, при поиске в Python и в ECMA-262.
- `parse_scalar` отвергает управляющие символы в скалярах — второй рубеж.
- Gate 0 переименован в `schema_generation_parity`: он проверяет байтовое
  равенство закоммиченной и порождённой схемы, а не семантический паритет.
  Семантический паритет обеспечивают дифференциальные тесты.

### Added

- 16 граничных случаев с CR/LF в дифференциальной матрице (всего 50).
- `PatternSemanticsTests`: для каждого шаблона fullmatch и search обязаны
  совпадать на 22 пограничных строках.
- `ParserInvariantTests`: управляющий символ в скаляре не проходит парсер.
- Прогон настоящим `jsonschema.Draft202012Validator`, когда библиотека
  установлена; при её отсутствии тесты пропускаются явно.

### Fixed

- `README.md`: устаревший SHA checker-v3; добавлен SHA схемы и правило,
  что схема не редактируется вручную.

### Preserved

- Pilot controls: 5, не изменялись. `index/source-v4`: не изменялся.
- Sysctl probe: не изменялся. 349 / CLOSED 5 / OPEN 344.
- Reference VM evidence: `NOT_YET_PROVIDED`.

### Checker

`checker/gates-v3/checker.py`

SHA-256:

`4c6012b7541923a682b6bb78bf5d8ccf5b241da54ecaa601f2c9d5479eafb5a6`

## [0.0.5-r2] — 2026-08-14

### Fixed after second independent audit

- B-R1-01: `CONTROL-SCHEMA.json` и runtime-проверка расходились в двух точках
  (`parameter.key` ровно `option::` и ровно `active_line::` принимались
  runtime и отвергались схемой).
- Устранена причина, а не два случая: kind-контракт вынесен в единственную
  таблицу `KIND_RULES` в `checker.py`. Из неё выводятся и
  `validate_parameter_closure`, и вся публикуемая схема.
- Добавлен `checker.py --emit-schema PATH` — генерация схемы из runtime-констант.
- Добавлен Gate 0 `schema_runtime_parity`: fail-closed, если закоммиченная
  схема не байт-идентична сгенерированной.
- `LAYER_ORDER` / `PROFILE_ORDER` / `APPLICABILITY_ORDER` задают
  детерминированный порядок enum в схеме.
- Схема: `$id` → `securelinux-policy-v3-control-schema-v3`; шаблоны приведены
  к якорной форме, эквивалентной `re.fullmatch` в runtime.

### Added

- `tests/gates-v3/test_schema_runtime_parity.py` — два независимых
  предохранителя: генерационный паритет и дифференциальная матрица из 34
  записей по всем восьми kinds в обе стороны (accept и reject).

### Preserved

- Pilot controls: 5, не изменялись.
- `index/source-v4`: не изменялся.
- Sysctl probe: не изменялся, SHA `e454d691e6433c2bfb8588884575fa4f5b880a6a0cb328682a5dbe1135dabd5e`.
- Source population: 349. CLOSED: 5. OPEN: 344.
- Reference VM evidence: `NOT_YET_PROVIDED`.

### Checker

`checker/gates-v3/checker.py`

SHA-256:

`0397a5e64a2e859bba1791a844feacad094120ee3375588ac2e31c597320edb7`

## [0.0.5-r1] — 2026-08-14

### Fixed after independent audit

- B-01 / A-01: controlled source row больше не закрывается просто по факту
  наличия одного control. Добавлен `index/source-v4/CLOSURE-CONTRACT.tsv`.
- B-02 / A-02: `checker/gates-v3/CONTROL-SCHEMA.json` заменён на полный
  nested JSON Schema для фактического runtime contract и 8 parameter kinds.
- B-03 / A-06: Gate 4 использует scoped identity
  `(layer, profile, kind, locator, key)`.
- Corporate profile-specific values учитываются как `profile_variants`.
- Divergent cross-layer values не разрешаются автоматически и fail-closed как
  `unresolved cross-scope parameter conflict`.

### Preserved

- Pilot controls: 5.
- Source population: 349.
- CLOSED: 5.
- OPEN: 344.
- Sysctl probe unchanged.
- Reference VM evidence: `NOT_YET_PROVIDED`.

### Checker

`checker/gates-v3/checker.py`

SHA-256:

`7217e741622690ac9f60521abf106b0250fecdb646537f3776dbf1d13ff00bdb`

## [0.0.5] — 2026-08-14

### Added

- Первый активный FSTEC-LINUX-2022 sysctl pilot.
- Пять controls:
  - `kernel.dmesg_restrict=1` — 2.4.1;
  - `kernel.kptr_restrict=2` — 2.4.2;
  - `net.core.bpf_jit_harden=2` — 2.4.8;
  - `kernel.perf_event_paranoid=3` — 2.5.2;
  - `kernel.kexec_load_disabled=1` — 2.5.4.
- `index/source-v3`.
- Read-only probe `probes/sysctl-v1/probe.py`.
- `checker/gates-v2` с Gate 5.
- Focused Gate-5 tests.

### Changed

- Source-index progress:
  - total: 349;
  - closed: 5;
  - open: 344;
  - closure ratio: `5/349`.
- Exact control quotes теперь формируются непосредственно из verified
  recovered FSTEC-LINUX-2022 corpus по locator и нормализуются `norm-v1`.

### Verification

- Gate 1: PASS для пяти pilot controls.
- Gate 2: FAIL expected, 344 uncovered.
- Gate 3: PASS.
- Gate 4: PASS.
- Gate 5 implementation synthetic selftest: PASS.
- Reference VM evidence: `NOT_YET_PROVIDED`.

### Fixed

- Исправлена первая версия Step-5 installer, которая сравнивала hardcoded
  quote с recovered corpus и корректно завершилась fail-closed до публикации.
- Исправленный Step-5 installer извлекает clause из
  `raw-glyph-recovered/fstec-linux-2022.txt`, применяет exact `norm-v1`,
  проверяет literal `key=value`, затем вычисляет quote SHA.

## [0.0.4] — 2026-08-14

### Added

- `checker/gates-v1`.
- Gates 1–4:
  - source/quote anchor;
  - reverse source coverage;
  - closed schema / parameter closure;
  - uniqueness / parameter conflicts.
- 13 positive/negative fixtures.

### Verification

На пустом active control corpus:

- Gate 1: PASS;
- Gate 2: FAIL expected — 349 uncovered;
- Gate 3: PASS;
- Gate 4: PASS;
- overall: FAIL expected.

Это зафиксировало fail-closed поведение до появления первых controls.

## [0.0.3] — 2026-08-14

### Added

- `index/source-v1` — первоначальная source-first population.
- `TOTAL_INDEX_ROWS=349`.
- Отдельная регистрация framework sources.
- Метрика перехода:
  `CLOSED_INDEX_ROWS / TOTAL_INDEX_ROWS`.
- `sources/recovered-v1` для non-OCR glyph-ID recovery.
- `index/source-v2`.

### Changed

- После recovery:
  - `QUOTE_ANCHOR_READY_ROWS=349`;
  - `QUOTE_ANCHOR_BLOCKED_ROWS=0`;
  - `CLOSED_INDEX_ROWS=0`.

### Verification

- `fstec-linux-2022`: 40/40 locators recovered.
- `fstec-vulnerability-analysis-2025`: 61/61 locators recovered.
- Double recovery: 2/2.
- Unresolved glyphs: 0.

## [0.0.2] — 2026-08-14

### Added

- Pinned FSTEC source bundle:
  - 10 PDF;
  - `sources/fstec/SHA256SUMS`.
- Deterministic `pdftotext` extraction.
- Raw extracted text.
- `norm-v1` normalized text.
- `EXTRACTION-MANIFEST.tsv`.
- Toolchain metadata.

### Verification

- Pinned source SHA verification: PASS.
- Double extraction: 10/10.
- Raw texts: 10.
- Norm texts: 10.
- `norm-v1` selftest/idempotence: PASS.

## [0.0.1] — 2026-08-14

### Added

- Новый sibling-проект `SecureLinux-Policy-v3`.
- Базовая структура:
  - `sources/`
  - `index/`
  - `controls/`
  - `probes/`
  - `checker/`
  - `tests/`
  - `archive/`
- Historical manifest старого проекта.
- Архивная копия B1.1b.
- Историческое отображение blocker IDs:
  - `N-01 -> B-06`
  - `N-02 -> B-07`
  - `N-03 -> B-08`
- Engineering donor `securelinux-ng.sh`.

### Policy

- Старая модель не конвертируется массово.
- Старые records рассматриваются только как candidate input.
- Новая активная модель строится source-first.
- Один control = один parameter.
- Источник и literal quote должны быть машинно проверяемы.
