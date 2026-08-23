# SecureLinux-Policy v3

> Система нормативной прослеживаемости и машинно-проверяемой политики
> безопасной настройки Linux, построенная от закреплённых первоисточников.
>
> Текущий product CHECK работает только по уже представленным требованиям и
> **не является заявлением о полном соответствии требованиям ФСТЭК**.

## Текущее состояние

<!-- BEGIN GENERATED CURRENT STATUS -->
```text
TOTAL_INDEX_ROWS=349
CONTROLLED_CLOSED_WITH_CONTRACT=36
DISPOSED_CLOSED_ROWS=0
OPEN_INDEX_ROWS=313
CLOSURE_RATIO=36/349
CANONICAL_CONTROLS=46
CLOSURE_CONTRACT_ROWS=36
ADAPTER_KINDS=13
CHECK_TARGET=ubuntu-24.04-x86_64
CHECK_STATUS=NON_RELEASE_PRODUCT_CANDIDATE
CHECK=IMPLEMENTED_READ_ONLY
APPLY=NOT_IMPLEMENTED
RESTORE=NOT_IMPLEMENTED
FULL_FSTEC_COMPLIANCE_CLAIM=false
```

CHECK охватывает только требования, представленные текущими canonical controls. Этот статус не является заявлением о полном соответствии требованиям ФСТЭК.
<!-- END GENERATED CURRENT STATUS -->

Полная машинно формируемая карта текущего покрытия:
[`docs/fstec-coverage.md`](docs/fstec-coverage.md).

---

## Назначение

SecureLinux-Policy строит проверяемую цепочку от первоисточника до исполняемой
read-only проверки:

```text
закреплённый PDF ФСТЭК
  → проверенное текстовое представление
  → source index
  → quote anchor
  → canonical control
  → semantic contract
  → adapter registry
  → read-only adapter
  → deterministic generator v2
  → tracked `securelinux-policy.sh`
  → pretty / raw / JSON result
```

Каждый controlled source row должен иметь проверяемый source-anchor и закрываться
ровно тем набором canonical controls, который указан в
`index/source-v4/CLOSURE-CONTRACT.tsv`. Простого наличия похожей проверки
недостаточно.

CHECK и изменение системы разделены принципиально. На текущей стадии реализован
только CHECK. APPLY и RESTORE относятся к будущему отдельному этапу и не
подразумеваются текущими гарантиями.

---

## Быстрый старт

Для обычного запуска генератор не нужен. Текущий read-only product entrypoint
уже находится в корне репозитория:

```text
securelinux-policy.sh
```

На поддерживаемом target-host (`ubuntu-24.04-x86_64`) полный CHECK запускается
одной командой:

```bash
sudo ./securelinux-policy.sh --check
```

Compliance execution contract: tracked CLI запускается **как executable**, чтобы kernel
применил shebang `#!/bin/bash -p`. Privileged-mode Bash не импортирует shell functions
из environment, поэтому функция `command` не может подменить pinned external calls.
Эквивалентный явный запуск — `/bin/bash -p ./securelinux-policy.sh ...`. Обычный
`bash securelinux-policy.sh ...` и `source securelinux-policy.sh` не являются поддерживаемым
режимом compliance execution.

По умолчанию вывод предназначен для человека: колонки `RESULT`, `CONTROL` и
`VALUE / DETAILS` имеют фиксированные позиции, а длинные details переносятся
под третьей колонкой.

Только проблемы:

```bash
sudo ./securelinux-policy.sh --check --failed
```

Машинные форматы:

```bash
sudo ./securelinux-policy.sh --check --format raw
sudo ./securelinux-policy.sh --check --format json
```

`raw` сохраняет wire-format `SLP-CHECK-V1`/`SLP-SUMMARY-V1`; `json` выдаёт
структурированный `SLP-REPORT-V1`. Краткий human-readable отчёт с `FAIL` и
`ERROR`:

```bash
sudo ./securelinux-policy.sh --report
```

Metadata и provenance не требуют запуска policy checks:

```bash
./securelinux-policy.sh --version
./securelinux-policy.sh --build-info
./securelinux-policy.sh --provenance
```

`--apply` и `--restore` уже зарезервированы в едином CLI, но сейчас обязаны
завершаться `NOT_IMPLEMENTED` с RC=2 и ничего не менять на хосте.

Sidecar текущего tracked artifact:

```bash
sha256sum -c securelinux-policy.sh.sha256
```

### Для разработчика: детерминированная пересборка

Current user-facing artifact строится `product/generate-product-check-v2.py`.
Tracked `securelinux-policy.sh` обязан побайтно совпадать со свежей генерацией;
это проверяется DEV regression. Для ручной проверки можно собрать копию вне
tracked root:

```bash
mkdir -p dist
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  product/generate-product-check-v2.py \
  --repo . \
  --out dist/securelinux-policy.sh

cmp -s securelinux-policy.sh dist/securelinux-policy.sh
echo "RC_PARITY=$?"
```

Historical `product/generate-product-check-v1.py` сохраняется как предыдущая
generator identity и не является текущей пользовательской точкой входа.

---

## Надёжность текущей product-line

| Гарантия | Статус | Чем проверяется |
|---|---|---|
| APPLY/RESTORE mutation modes не реализованы | PASS | CLI stubs + adapter contracts; forbidden-token scan — только defense-in-depth, а не формальное доказательство произвольного shell-кода |
| Детерминированная генерация CHECK | PASS | `tests/product-v1/test_product_generator.py` |
| Adapter/contract bytes закреплены SHA-256 | PASS | `ADAPTER-REGISTRY.tsv` + product regressions |
| CHECK provenance доступен машинно | PASS | generator regression / `--provenance` |
| Sysctl read-error не уходит в неструктурированный stderr | PASS | sysctl adapter regression |
| Неподдерживаемая target-платформа завершается до проверки | PASS | product generator regression, RC=3 |
| DEV test population имеет единую точку запуска | PASS | `tests/run-all.py` + `tests/run-all-selftest.py` |
| Реальный Draft 2020-12 валидатор обязателен для RELEASE | PASS | `tests/release-v1/test_real_jsonschema_gate.py` |
| Current nested `SHA256SUMS` валидны; 2 historical donor runtime entries пинованы как исключения | PASS | `tests/project-integrity-v1/test_root_manifests.py` |
| Gates-v3 evidence с маркировкой `ACTIVE` совпадает со свежим checker run | PASS | `tests/project-integrity-v1/test_root_manifests.py` |
| APPLY | NOT IMPLEMENTED | — |
| RESTORE | NOT IMPLEMENTED | — |

Гарантии относятся только к текущему scope. Конкретный policy-result CHECK
описывает состояние проверяемого хоста и не является свойством самого generator.

---

## Слои политики

Проект не смешивает происхождение и назначение требований:

```text
FSTEC core ≠ recommended ≠ corporate standard ≠ firewall
```

- **FSTEC core** — только требования с проверяемым якорем в первичном
  нормативном/техническом источнике ФСТЭК.
- **recommended** — рекомендации вне FSTEC core.
- **corporate standard** — внутренние требования и ужесточения; будущие
  `baseline / strict / paranoid` относятся только к этому слою.
- **firewall** — отдельная role-specific policy. UFW, nftables и iptables —
  реализации firewall-policy, а не автоматически требования FSTEC core.

Подробно: [`docs/policy-layers.md`](docs/policy-layers.md).

---

## Покрытие FSTEC core

Точные числа, закрытые source rows, canonical controls, parameter kinds и
CHECK-adapters формируются автоматически:
[`docs/fstec-coverage.md`](docs/fstec-coverage.md).

Важно различать:

- число source rows;
- число controlled CLOSED rows;
- число canonical controls;
- число controls, которые уже исполнимы текущими CHECK adapters.

Одна source row может закрываться набором из нескольких controls, поэтому эти
счётчики не обязаны совпадать.

Полный source corpus остаётся в `index/source-v4/SOURCE-INDEX.tsv`; generated
coverage document не дублирует вручную все строки индекса.

---

## Архитектура

Главная карта текущего проекта:
[`docs/PROJECT-MAP-v3.md`](docs/PROJECT-MAP-v3.md).

Она показывает:

```text
sources
  → corpus
  → source index
  → canonical controls / disposition
  → gates
  → semantic contracts
  → ADAPTER-REGISTRY.tsv
  → read-only adapters
  → tracked generator
  → generated CHECK
```

[`docs/ARCHITECTURE-DIAGRAMS.md`](docs/ARCHITECTURE-DIAGRAMS.md) сохранён как
**donor/future runtime reference** для будущего APPLY/RESTORE и не является
источником текущего product status.

Индекс всей документации и её ролей:
[`docs/README.md`](docs/README.md).

---

## Совместимость

Текущий target product CHECK задаётся самим generator и adapter contracts.
Документ совместимости разделяет три разных понятия:

- `SUPPORTED` — target, разрешённый текущим product contract;
- `TESTED` — среда, для которой имеется конкретное соответствующее evidence;
- `UNSUPPORTED` — target, который current CHECK обязан отклонить.

Подробно: [`docs/compatibility.md`](docs/compatibility.md).

Недостаточные права чтения системного параметра не превращаются в
`NOT_FOUND`: такая ситуация классифицируется как `ERROR`, чтобы CHECK не
выдавал ложную оценку.

---

## Тестовая модель

Tracked [`tests/run-all.py`](tests/run-all.py) — единая точка запуска всех
tracked Python regressions.

**DEV**:

- stdlib-only;
- должен быть полностью зелёным;
- проверяет фактическое выполнение тестов, а не только RC=0;
- неожиданные skip и `ResourceWarning` являются ошибкой.

**RELEASE**:

- сначала требует DEV PASS;
- использует зависимости из `requirements-release.txt`;
- отсутствие обязательной зависимости даёт `BLOCKED_ENVIRONMENT`, а не
  ложный project PASS.

Подробно: [`tests/README.md`](tests/README.md) и
[`docs/testing-strategy.md`](docs/testing-strategy.md).

---

## Структура проекта

```text
sources/    pinned source documents и проверенные text representations
index/      source index, closure contract, disposition ledger
controls/   canonical policy controls
checker/    schema и gates
tools/      project generators и integrity helpers
product/    semantic contracts, adapter registry, adapters, CHECK generator
securelinux-policy.sh  tracked read-only user entrypoint
dist/       optional derived rebuild output; gitignored
probes/     read-only probe infrastructure и historical/reference evidence line
tests/      DEV/RELEASE regression suites
docs/       product, engineering, donor-reference и roadmap documentation
step7b0/    historical assurance line; не current product authority
archive/    historical audit material и engineering donor
```

---

## Целостность

Корневые манифесты:

- `PROJECT-FILES.sha256` — canonical project population;
- `SHA256SUMS` — SHA-256 файлов этой population.

Проверка:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  tools/rebuild-root-manifests.py \
  --project-root . \
  --check
```

Machine-owned documentation blocks и coverage также проверяются отдельно:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  tools/render-current-docs.py \
  --project-root . \
  --check
```

После изменения source index, controls, closure contract или adapter registry
канонический порядок такой:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  tools/render-current-docs.py --project-root . --write

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  tests/run-all.py --dev
```

---

## Инженерный донор

SecureLinux-NG v16.2.11 сохранён как **engineering donor**, а не нормативный
источник. Донорская логика может попасть в v3 только через явное решение
`REUSE | ADAPT | REJECT | DEFER`.

Donor mapping сам по себе не создаёт FSTEC controls и не закрывает ни одной
source-index row.

См. [`docs/DONOR-V3-ADOPTION-POLICY.md`](docs/DONOR-V3-ADOPTION-POLICY.md) и
[`docs/engineering-donor.md`](docs/engineering-donor.md).

---

## Границы текущего состояния

На текущем этапе:

- полный FSTEC corpus **не закрыт**;
- current CHECK охватывает только represented controls;
- formal Gate 5 `--probe-results` для текущей product population остаётся
  отдельным контрактным артефактом;
- `SRC-0005 / 2.3.1` закрыт exact-control-set из трёх file-mode controls;
- APPLY и RESTORE не реализованы;
- historical Step 7B.0 не является current product authority;
- engineering donor не является нормативным доказательством.

Generated CHECK всегда строится из текущей `CONTROL-MANIFEST.tsv`; точная
population показана в machine-generated статусе выше. Текущий product-step —
систематическое расширение оставшихся `OPEN` строк FSTEC core. Семантика
`chmod go-rwx /etc/shadow` представлена как `mode bits-clear 0077` и не усилена
до выдуманного `0600`.

---

## Источники истины

| Область | Канонический источник |
|---|---|
| source population/status | `index/source-v4/SOURCE-INDEX.tsv` |
| completeness closure | `index/source-v4/CLOSURE-CONTRACT.tsv` |
| dispositions | `index/source-v4/DISPOSITION-LEDGER.tsv` |
| canonical controls | `controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv` + YAML |
| parameter schema | `checker/gates-v3/checker.py` → generated `CONTROL-SCHEMA.json` |
| CHECK adapter mapping | `product/ADAPTER-REGISTRY.tsv` |
| current CHECK/CLI generator | `product/generate-product-check-v2.py` |
| tracked user entrypoint | `securelinux-policy.sh` + `.sha256` |
| macro-roadmap | `docs/ROADMAP-v3.tsv` |
| generated current docs | `tools/render-current-docs.py` |

README является входной точкой для человека, но не заменяет эти machine-readable
источники истины.

---

## Документация

Начинать с [`docs/README.md`](docs/README.md): там каждый документ помечен как
`PRODUCT`, `ENGINEERING`, `DONOR-REFERENCE`, `ROADMAP` или `FUTURE/HISTORICAL`.

Пользовательская документация ведётся на русском. Имена файлов/CLI,
идентификаторы gates, enums, schema fields и machine-status strings остаются в
контрактном виде.
