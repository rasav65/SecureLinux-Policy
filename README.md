# SecureLinux-Policy

`SecureLinux-Policy` — source-first проект для построения проверяемой политики
безопасной настройки Linux и связанных технических контролей.

Проект не переносит старый корпус массовой конвертацией. Каждая активная запись
должна быть связана с конкретным источником, пройти машинные проверки и иметь
явно определённый наблюдаемый параметр.

## Текущий статус

Текущая активная стадия: **FSTEC + corporate index expansion / dispositions**.

Внутри этапа 7 первым обязательным подэтапом является
`DISPOSITION CONTRACT / LEDGER HARDENING`. Он усиливает альтернативный путь
закрытия строки source index до первого реального disposition: `CLOSED +
disposition + reason` больше недостаточно без проверяемой записи
`DISPOSITION-LEDGER.tsv`. Подэтап не меняет `SOURCE-INDEX.tsv` и не закрывает
ни одной строки FSTEC.

Состояние source index:

- `TOTAL_INDEX_ROWS=349`
- `CLOSED_INDEX_ROWS=5`
- `OPEN_INDEX_ROWS=344`
- `CLOSURE_RATIO=5/349`

Фактический read-only probe выполнен на reference VM Ubuntu 24.04.4 LTS
(minimized, kernel `6.8.0-134-generic`, host `testmin`):

- `REFERENCE_VM_EVIDENCE=PASS`
- `GATE5=PASS checked=5 value=5 not_found=0 noncompliant=4 errors=0`
- непривилегированный запуск сохранён отдельно: 4 `VALUE` + 1 `ERROR` из-за
  запрета чтения `/proc/sys/net/core/bpf_jit_harden` (mode `0600 root:root`);
- повторный read-only запуск через `sudo` дал 5/5 `VALUE`, 0 `ERROR`.

`OVERALL=FAIL` остаётся ожидаемым только из-за Gate 2: 344 source-index rows
ещё не закрыты. Синтетический selftest Gate 5 остаётся regression, но не
заменяет фактическое reference-VM evidence.

## Язык документации

Пользовательская документация проекта ведётся на русском языке. Английский
сохраняется только там, где он является частью машинного контракта или точного
технического имени: имена файлов и CLI, идентификаторы roadmap/gates, enum,
классы/API, поля schema и проверяемые machine-status строки.

Старые англоязычные пояснения переводятся постепенно отдельными
documentation-only проходами, без смешивания перевода с нормативными или
runtime-изменениями.

## Закрытие provenance-аудита Step 5

В пакете evidence Step 5 с reference VM сохранены три текста вердиктов
`ACCEPT` со значениями `ADMISSION=PASS`, `INTEGRITY=PASS` и `BLOCKERS=NONE`.

Проект намеренно **не** описывает это как «3 независимых аудита». Сохранённый
provenance указывает, что один reviewer участвовал в проектировании формата v3
и подготовил два вердикта, но точное соответствие reviewer ↔ три сохранённые
записи не установлено. Поэтому provenance хранится для каждой записи отдельно
в `audit/step5-reference-vm-evidence-20260814/PROVENANCE.tsv`.

Покрытие не изменилось: 349 всего / 5 controlled `CLOSED` / 344 `OPEN`.
Закрыты provenance Step 5, Gate 6 `evidence_binding`, обязательный release-gate
с реальным `jsonschema`, универсальный по индексу генератор `source:` и
паритет регенерации `source:`. Текущий разрешённый инженерный этап —
`FSTEC + corporate index expansion / dispositions`.

<!-- Совместимость с текущим status-test:
The current authorized engineering step is `FSTEC + corporate index expansion / dispositions`.
-->

Обязательный порядок дальнейших работ зафиксирован в `docs/ROADMAP-v3.md`.

## Правило инженерного донора

SecureLinux-NG v16.2.11 сохранён как **инженерный донор**, а не как
нормативный источник истины. Зрелые механизмы и tests не выбрасываются, но и
не копируются в v3 автоматически.

До этапа `apply/restore semantic contract` проект обязан построить и проверить
полный `DONOR_TO_V3_MAPPING` с решениями
`REUSE | ADAPT | REJECT | DEFER`. Сам mapping закрывает 0 строк source index.

Обязательная политика описана в `docs/DONOR-V3-ADOPTION-POLICY.md`.

## Gate 6 — привязка evidence

Gate 6 реализован для текущего фактического evidence `sysctl-v1` с reference
VM. Он механически связывает метаданные VM с текущим probe, probe plan,
привилегированным результатом, непривилегированным результатом и набором
контрольных сумм каталога evidence.

Gate 6 доказывает только целостность и привязку. Он явно фиксирует
`VM_ORIGIN_ATTESTATION=NOT_PROVEN`; криптографическое доказательство
происхождения от конкретной VM не заявляется.

Исторически после закрытия Gate 6 следующим этапом roadmap была очистка
контракта type/boolean; этот этап уже закрыт.

## Визуальная архитектура

GitHub отрисовывает Mermaid-схемы проекта непосредственно как диаграммы:

- [CLI и основные режимы](docs/ARCHITECTURE-DIAGRAMS.md#1-cli-и-основные-режимы)
- [Модули, дополнительные меры и restore](docs/ARCHITECTURE-DIAGRAMS.md#2-модули-дополнительные-меры-и-restore)
- [Apply → manifest → restore](docs/ARCHITECTURE-DIAGRAMS.md#3-apply--manifest--restore)

Схемы являются целевой runtime-архитектурой, сохранённой из engineering donor,
и не подменяют текущий статус реализации v3.

## Основная карта проекта v3

Главная наглядная схема текущего проекта:
[`docs/PROJECT-MAP-v3.md`](docs/PROJECT-MAP-v3.md).

Она показывает реальную архитектуру SecureLinux-Policy v3: первичные
источники, нормализацию/recovery, source index, controls, Gates 0–6,
reference-VM evidence, policy layers, engineering donor и путь к
детерминированно собираемому `securelinux-ng.sh`.

`docs/ARCHITECTURE-DIAGRAMS.md` сохранён как отдельный **donor runtime
reference**. Это не основная карта v3.

## Валидация релиза

Для закрытия релиза или аудита требуется реальный
`jsonschema.Draft202012Validator`; отсутствие зависимости является жёсткой
ошибкой, а не пропущенным тестом. Evidence текущего закрытия фиксирует
`jsonschema=4.10.3` в `checker/release-v1/RELEASE-EVIDENCE.json`.

Подробности: `docs/release-validation.md`.

## Архитектура

```text
SecureLinux-Policy-v3/
├── sources/   # pinned источники и проверенные текстовые представления
├── index/     # source-first closure population
├── controls/  # принятые parameter records
├── probes/    # read-only наблюдение
├── checker/   # Gates
├── tests/     # positive/negative fixtures
└── archive/   # исторические материалы старой модели
```

Активные provenance layers:

- `fstec-core`
- `recommended`
- `corporate`
- `firewall`

Слой определяет происхождение требования. Профиль определяет применимость
внутри соответствующего слоя. Классы ФСТЭК K1/K2/K3 не являются
корпоративными профилями `baseline/strict/paranoid`.

## Основной принцип

Одна активная control-запись описывает **один наблюдаемый параметр**.

Минимальная модель:

```yaml
id: CONTROL-ID
layer: fstec-core
profile: null
source:
  index_id: SRC-0000
  doc_id: source-id
  doc_sha256: "<sha256>"
  locator: "..."
  quote: "..."
  quote_sha256: "<sha256>"
  norm: norm-v1
requirement:
  stated: "..."
  derived: false
  justification: null
  applicability: technical
parameter:
  kind: sysctl
  locator: sysctl
  key: kernel.example
expected:
  op: eq
  value: 1
  type: integer
apply:
  supported: false
```

`derived=false` означает, что конкретное значение прямо задано источником.
Если значение выбрано или выведено проектом, требуется `derived=true` и
непустое `justification`.

## Источники

Pinned FSTEC bundle находится в:

```text
sources/fstec/
```

Состав закреплён `sources/fstec/SHA256SUMS`.

В bundle входят 10 PDF ФСТЭК, включая:

- рекомендации по безопасной настройке Linux (2022);
- рекомендации по регистрации событий безопасности (2025);
- рекомендации по устранению типовых ошибок конфигурации (2026);
- методологию 12.04.2026;
- требования к приказу ФСТЭК России № 117;
- документы по периметру, уязвимостям и тестированию обновлений.

## Нормализация текста

Step 2 закрепил `norm-v1`.

Нормализатор:

```text
sources/extracted/normalizer-v1.py
```

SHA-256:

```text
fdf11e5abc24c966e7b9c9abe318259fd29c06de026addf54cf3710cc937639a
```

`norm-v1` предназначен для машинного literal quote anchoring. Он не делает
семантических исправлений источника, OCR, case folding или произвольной
перезаписи пунктуации.

## Text recovery

Для двух PDF с повреждённым native text layer:

- `fstec-linux-2022`
- `fstec-vulnerability-analysis-2025`

используется non-OCR glyph-ID recovery:

```text
sources/recovered-v1/
```

Результат Step 3.1:

- recovered PDFs: 2;
- unresolved glyphs: 0;
- deterministic double recovery: 2/2;
- recovered index locators: 101/101;
- `source-v2`: 349/349 quote-anchor-ready.

Исходные PDF и `source-v1` не изменялись.

## Source index

Индекс строится от источника, а не от старого списка controls.

Текущий активный индекс:

```text
index/source-v4/SOURCE-INDEX.tsv
```

Для каждой controlled `CLOSED` строки обязателен completeness-contract:

```text
index/source-v4/CLOSURE-CONTRACT.tsv
```

`atomic-single` требует ровно один полный control, а `exact-control-set` — точный набор из двух и более controls. Наличие произвольного одного control само по себе больше не закрывает source row.

Метрика перехода:

```text
CLOSED_INDEX_ROWS / TOTAL_INDEX_ROWS
```

Строка может считаться закрытой только через машинно проверяемый механизм,
определённый Gate 2.

Framework sources (Order 117 и Methodology) учитываются отдельно и не
трактуются автоматически как one-control-per-clause population.

## Gates

### Gate 1 — source / quote anchor

Проверяет:

- source index identity;
- SHA-256 pinned PDF;
- locator;
- `norm-v1`;
- canonical quote;
- quote SHA-256;
- literal presence quote в проверенном normalized corpus.

### Gate 2 — reverse source coverage

Каждая source-index row должна быть закрыта:

- control-записью;
- либо допустимым explicit disposition с reason.

Открытая строка не считается закрытой автоматически.

### Gate 3 — closed schema / parameter closure

Проверяет закрытую структуру записи и совместимость:

```text
kind / locator / key / op / type
```

### Gate 4 — scoped uniqueness / conflicts

Проверяет:

- глобальную уникальность `id`;
- hard conflicts внутри `(layer, profile, kind, locator, key)`;
- допустимые corporate profile variants отдельно;
- divergent cross-layer значения fail-closed как unresolved cross-scope conflict.

### Gate 5 — probe executability

Текущая реализация добавлена для первого `sysctl` pilot.

Gate 5 различает:

- `VALUE` — значение прочитано;
- `NOT_FOUND` — параметр явно отсутствует;
- `ERROR` — probe выполнить корректно не удалось.

`VALUE`, не соответствующее policy, означает noncompliance, но не ошибку
исполняемости probe.

Фактический reference-VM прогон первого sysctl pilot:
`GATE5=PASS checked=5 value=5 not_found=0 noncompliant=4 errors=0`.
Evidence хранится в
`probes/sysctl-v1/evidence/ubuntu-24.04.4-minimal-testmin-20260814/`.
На этой VM `net.core.bpf_jit_harden` имеет mode `0600 root:root`, поэтому
полный read-only сбор этого параметра требует привилегированного чтения.

## Parameter kinds и observation contracts

Control schema знает восемь parameter kinds; текущий Gate 5 runner реализован только для `sysctl`:

- `sysctl`
- `file-kv`
- `file-mode-owner`
- `mount-option`
- `systemd-unit-state`
- `package-presence`
- `pam-line`
- `audit-rule`

GRUB token membership и UFW policy/rules намеренно не маскируются под
неподходящие типы. Для них требуется отдельный probe design.

Wire format probe observations задаётся отдельно от semantic `expected.type`. Для future `systemd-unit-state` и `package-presence` boolean VALUE зарезервирован JSON boolean; generic coercion строк `"true"`/`"false"` запрещён. См. `docs/observation-value-contract.md`.

## Step 5 pilot

В активный корпус добавлены пять FSTEC-LINUX-2022 sysctl controls:

| Source | Parameter | Expected |
|---|---|---:|
| 2.4.1 | `kernel.dmesg_restrict` | `1` |
| 2.4.2 | `kernel.kptr_restrict` | `2` |
| 2.4.8 | `net.core.bpf_jit_harden` | `2` |
| 2.5.2 | `kernel.perf_event_paranoid` | `3` |
| 2.5.4 | `kernel.kexec_load_disabled` | `1` |

Для всех пяти:

- exact quote получена из verified recovered corpus;
- значение прямо присутствует в источнике;
- `derived=false`;
- `apply.supported=false`.

Read-only probe:

```text
probes/sysctl-v1/probe.py
```

SHA-256:

```text
e454d691e6433c2bfb8588884575fa4f5b880a6a0cb328682a5dbe1135dabd5e
```

Текущий checker после независимого аудита:

```text
checker/gates-v3/checker.py
```

SHA-256:

```text
600a87ebf560060a4fc95d33686237b50a87ea7139d223269c61b8dc008cf092
```

`CONTROL-SCHEMA.json` в gates-v3 содержит полный закрытый nested contract и ограничения всех восьми parameter kinds.

SHA-256:

```text
faa6fad0754be36fcf2cbe7e44e9d366de12d643afe825df73abeb54cc47508b
```

Схема не редактируется вручную: она порождается из таблицы `KIND_RULES` в
`checker.py` командой `--emit-schema`, а Gate 0 `schema_generation_parity`
падает, если закоммиченный файл не байт-идентичен порождённому.

## Engineering donor: сохранение проверенных наработок

Старый `SecureLinux-NG` используется только как **engineering donor**, а не как
нормативный источник.

Машинный reverse-index:

```text
index/engineering-donor-v1/
```

Зафиксировано:

- donor `archive/securelinux-ng.sh`: 18 928 строк, SHA-256
  `f3be8723cd5a2be499e9e8e6370fad712bdec8afd68050f27af6a3e2d6fbc34b`;
- 310 функций;
- 190 chunk-записей, покрывающих все 18 928 строк;
- 141 semantic candidate;
- 478 строк raw evidence;
- 15 проверенных инженерных контрактов для будущих apply/restore.

Финальный architecture-review старого SecureLinux-NG сохранён byte-for-byte в
`archive/engineering-review-20260731/` с SHA-256
`7a62c1304a423e4431b08c34e999ed221777d63ecfb0aec180767fadf80759d2`.

Эти данные **не создают controls и не закрывают строки FSTEC source-index**.
Текущий нормативный прогресс остаётся 349 / CLOSED 5 / OPEN 344.

Подробно: `docs/engineering-donor.md`.

## Engineering donor: финальный regression suite v16.2.11

Полный загруженный проект SecureLinux-NG v16.2.11 сохранён как отдельный
engineering snapshot:

```text
archive/engineering-donor-v16.2.11/
```

Source ZIP SHA-256:

```text
1b25f554a5ad1509037aa9613b7851a595159fd44291913cc2dba63280e50494
```

Из него машинно зарегистрированы:

- 38 test-файлов / 11 420 строк;
- 36 focused `*-regression.sh`;
- `smoke.sh` вызывает все 36 regressions ровно по одному разу;
- 32 обобщённых test contracts для будущих apply/restore/runtime/CLI;
- историческая donor VM evidence вынесена отдельно и **не** заменяет v3 Gate 5.

Реестр:

```text
index/engineering-tests-v1/
```

Из donor suite уже можно безопасно использовать сейчас
`tools/write-sha256.py`: он пишет переносимые GNU `sha256sum -c`-совместимые
sidecar-файлы атомарно и отказывается от symlink/неоднозначных входов.
Его regression перенесён в `tests/engineering-tests-v1/`.

Старые `fstec-mapping-regression.sh` и `wheel-fstec-regression.sh` сохранены
только как historical evidence и не могут закрывать строки v3 FSTEC index.

Стратегия тестирования: `docs/testing-strategy.md`.

## Что не считается готовым

На текущей стадии:

- фактический reference-VM Gate 5 закрыт только для текущего пятизаписного
  `sysctl` pilot; остальные probe kinds ещё не имеют reference-VM evidence;
- 344 source-index rows остаются OPEN;
- старый corpus не считается автоматически перенесённым;
- apply/remediation не реализуются этим pilot;
- B1.1b/M0–M7 и старые registries/DAG остаются историческим evidence,
  а не активной архитектурой v3.

## Исторические материалы

Старая модель и donor script сохранены в:

```text
archive/
```

Они используются как evidence и engineering donor, но не являются
нормативным контрактом новой модели.

## Закрытие универсального по индексу генератора `source:`

Этап 5 roadmap закрыт в намеренно ограниченной области.

- канонический инструмент: `tools/source_skeleton_generator.py`;
- путь к common index задаётся явно через `--index`, а
  `index/source-v4` является только текущим значением по умолчанию;
- поддерживаемый `unit_kind`: `numbered-position` (1 из 13);
- строк этого типа: 74;
- точных извлечений: 72;
- явных отказов: `SRC-0001`, `SRC-0133`;
- текущие принятые controls воспроизводятся побайтово: 5/5;
- повреждение trust chain покрыто постоянными отрицательными tests.

Для поддерживаемых типов генератор является единственным нормативным
производителем `source:`. Этап 6 roadmap теперь механически обеспечивает это
правило: каждый закоммиченный блок control регенерируется и обязан совпасть
побайтово.

Это закрытие не изменяет controls и закрывает 0 строк FSTEC source index.

## Закрытие паритета регенерации блока `source:`

Этап 6 roadmap закрыт.

- checker: `checker/source-parity-v1/source_block_regeneration_parity.py`;
- текущих controls: 5;
- поддерживаемых: 5;
- побайтовых совпадений: 5;
- unsupported: 0;
- отсутствующих строк index: 0;
- mismatches: 0;
- errors: 0.

Неподдерживаемый `unit_kind` является явным fail-closed результатом и никогда
не пропускается молча. Постоянные отрицательные fixtures покрывают изменения
`quote`, `quote_sha256`, `locator`, неподдерживаемые типы, отсутствующие строки
index и некорректные дублированные блоки `source:`.

Это закрытие не изменяет controls и закрывает 0 строк FSTEC source index.

## Проверка текущего состояния

Основные точки проверки:

```text
sources/fstec/SHA256SUMS
sources/extracted/SHA256SUMS
sources/recovered-v1/SHA256SUMS
index/source-v4/PROGRESS.txt
index/source-v4/CLOSURE-CONTRACT.tsv
index/source-v4/SHA256SUMS
controls/fstec-core/linux-2022/SHA256SUMS
checker/source-parity-v1/SHA256SUMS
tests/source-parity-v1/SHA256SUMS
probes/sysctl-v1/SHA256SUMS
checker/gates-v2/SHA256SUMS
tests/gates-v2/SHA256SUMS
```

До перехода к следующему этапу результат каждого gate должен трактоваться
fail-closed.

## Инженерный донор — классификация принятия

Inventory инженерного донора теперь явно классифицирован для каждой
проиндексированной функции.

- покрытие donor script: 18 928 / 18 928 строк;
- классифицировано функций: 310 / 310;
- классы принятия: 19 `contracted`, 31 `candidate`, 53 `evidence-only`,
  207 `pending-review`;
- engineering contracts: 20;
- зарегистрированных donor sources: 6;
- `restore-model.md` зарегистрирован как вход будущего этапа
  `apply/restore semantic contract`;
- donor `fstec-mapping.md` остаётся
  `engineering-donor-claimed-mapping-non-normative`;
- это изменение закрывает 0 строк FSTEC source index.

`pending-review` означает «ещё не проверено для принятия инварианта», а не
«инварианта не существует».

Эта параллельная классификация инженерного донора сама по себе не продвигала
нормативный roadmap.

## Политика версий JSON Schema для релиза

Валидация релиза требует реального `jsonschema.Draft202012Validator` и
устанавливает минимальную поддерживаемую версию дистрибутива `4.10.3`.

Сохранённое evidence совместимости охватывает `jsonschema 4.10.3` и
`jsonschema 4.26.0`. Оба запуска обязаны показывать нулевое число расхождений
runtime↔real и emulator↔real и 0 активных controls, невалидных по реальной
schema.

Отсутствие зависимости и версия ниже минимальной обрабатываются fail-closed.
