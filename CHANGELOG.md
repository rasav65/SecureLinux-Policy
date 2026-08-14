# Changelog

Все существенные изменения активной архитектуры `SecureLinux-Policy-v3`
фиксируются в этом файле.

## [Unreleased]

### Pending

- Фактический read-only запуск `sysctl-v1` probe на reference VM.
- Проверка реального Gate 5 evidence.
- Независимый аудит Step 0–5.
- Дальнейшее закрытие source-index rows только после прохождения
  соответствующих gates.

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
