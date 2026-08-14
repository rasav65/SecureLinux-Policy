# SecureLinux-Policy

`SecureLinux-Policy` — source-first проект для построения проверяемой политики
безопасной настройки Linux и связанных технических контролей.

Проект не переносит старый корпус массовой конвертацией. Каждая активная запись
должна быть связана с конкретным источником, пройти машинные проверки и иметь
явно определённый наблюдаемый параметр.

## Текущий статус

Текущая активная стадия: **Step 5 — sysctl pilot**.

Состояние source index:

- `TOTAL_INDEX_ROWS=349`
- `CLOSED_INDEX_ROWS=5`
- `OPEN_INDEX_ROWS=344`
- `CLOSURE_RATIO=5/349`

Фактический запуск read-only probe на reference VM ещё не выполнен:

- `REFERENCE_VM_EVIDENCE=NOT_YET_PROVIDED`

Синтетический selftest Gate 5 не считается evidence reference VM.

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

## Поддерживаемые probe kinds

Checker v1/v2 знает восемь базовых типов:

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
7217e741622690ac9f60521abf106b0250fecdb646537f3776dbf1d13ff00bdb
```

`CONTROL-SCHEMA.json` в gates-v3 содержит полный закрытый nested contract и ограничения всех восьми parameter kinds.

## Что не считается готовым

На текущей стадии:

- не выполнен фактический reference-VM Gate 5;
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
probes/sysctl-v1/SHA256SUMS
checker/gates-v2/SHA256SUMS
tests/gates-v2/SHA256SUMS
```

До перехода к следующему этапу результат каждого gate должен трактоваться
fail-closed.
