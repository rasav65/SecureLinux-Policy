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
CONTROLLED_CLOSED_WITH_CONTRACT=40
DISPOSED_CLOSED_ROWS=0
OPEN_INDEX_ROWS=309
CLOSURE_RATIO=40/349
CANONICAL_CONTROLS=51
CLOSURE_CONTRACT_ROWS=40
ADAPTER_KINDS=18
CHECK_TARGET_FAMILY=linux-x86_64-supported-v1
SUPPORTED_ENVIRONMENTS=8
CHECK_STATUS=NON_RELEASE_PRODUCT_CANDIDATE
CHECK=IMPLEMENTED_READ_ONLY
APPLY=IMPLEMENTED
APPLY_SCOPE=SRC-0001_ONLY
APPLY_IMPLEMENTATION_COUNT=1
RESTORE=NOT_PLANNED
ROLLBACK_MODEL=EXTERNAL_SNAPSHOT
FULL_FSTEC_COMPLIANCE_CLAIM=false
```

CHECK охватывает только требования, представленные текущими canonical controls. Этот статус не является заявлением о полном соответствии требованиям ФСТЭК.
<!-- END GENERATED CURRENT STATUS -->

Для документа `fstec-linux-2022` read-only CHECK vertical принят; commit
`219b4cc3c0673c55575fb558e160431c11c2a681` опубликован, а milestone
`fstec-linux-2022-check-complete-v1` привязан к этому exact commit. Machine
truth и текущие counts для документа берутся из generated status выше и
`docs/fstec-coverage.md`; этот prose-блок не закрепляет live counts вручную.
`DONOR_TO_V3_MAPPING` принят, прошёл precommit и опубликован commit
`1db91b0e17d6ef37e4c42cd41dca77eeb2b743da` с tree
`d3f624651bf13f1174619cef881fababbc768553`. Parent-level APPLY gate закрыт.
Для `SRC-0001` закрыты и криптографически привязаны все восемь определений: предикат,
преобразование, условие внешнего снимка, блокировка и повторное чтение,
идентичность объекта, сохранение метаданных, атомарная транзакция и режим
сухого запуска с отчётом. `composition-v1.json` детерминированно связывает
архитектуру, текущий источник состава CHECK и все восемь определений.
Первая вертикаль APPLY для `SRC-0001` реализована, привязана отдельным реестром,
встроена в tracked CLI и проверена на поддерживаемых Ubuntu/Debian VM. Этап
`APPLY_IMPLEMENTATION_ADAPTERS` закрыт в scope `SRC-0001_ONLY`; следующий этап —
`FINAL_DETERMINISTIC_PACKAGING`. Пользовательский RESTORE в целевую архитектуру
не входит; восстановление после успешного APPLY выполняется внешним снимком.

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

CHECK и изменение системы разделены принципиально. CHECK остаётся read-only, а
APPLY реализован только для `SRC-0001` и вызывается отдельным режимом с точным
условием внешнего снимка. Пользовательский RESTORE не планируется; post-APPLY
rollback выполняется внешним snapshot recovery.

---

## Зависимость проверки системных путей

CHECK `standard-system-paths-mode` читает метаданные внутри Python, сохраняя
GNU find/readlink для обхода и разрешения путей. Перед запуском проверяется
`/usr/bin/python3`: отсутствие или недоступность исполнения даёт
`runtime:python3-missing`; сбой запуска после успешной проверки —
`runtime:observer-failed`. Словарь причин ERROR закреплён в семантическом контракте.
В роли exec ссылка на каталог с идентичностью exec-корня пропускается
по совпадению устройства и inode. Новое поле отчёта не добавляется.
Другие ссылки на каталоги и неразрешимые цели сохраняют ERROR.
Границы выполненных проверок описаны в [стратегии тестирования](docs/testing-strategy.md).

## Быстрый старт

Для обычного запуска генератор не нужен. Текущий product entrypoint
уже находится в корне репозитория:

```text
securelinux-policy.sh
```

На любом environment из `product/SUPPORTED-PLATFORMS.tsv` или `product/SUPPORTED-DESKTOPS.tsv` полный CHECK запускается
одной командой:

```bash
sudo ./securelinux-policy.sh --check
```

Контракт compliance execution: tracked CLI запускается **как executable**, чтобы kernel
применил shebang `#!/bin/bash -p`. Bash в privileged mode не импортирует shell-функции
из окружения, поэтому функция `command` не может подменить закреплённые внешние вызовы.
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
структурированный `SLP-REPORT-V1`. Каждый `ERROR` сохраняет fail-closed verdict и
обязательно несёт стабильный reason-code формата `domain:reason` в `VALUE / DETAILS`,
raw и JSON. Reason-code определяется точкой отказа и не строится из случайного stderr;
`-` для production `ERROR` запрещён. Краткий human-readable отчёт с `FAIL` и `ERROR`:

```bash
sudo ./securelinux-policy.sh --report
```

Metadata и provenance не требуют запуска policy checks:

```bash
./securelinux-policy.sh --version
./securelinux-policy.sh --build-info
./securelinux-policy.sh --provenance
```

APPLY ограничен `SRC-0001`. Сухой запуск не требует attestation и не пишет на хост:

```bash
sudo ./securelinux-policy.sh --apply --dry-run
```

Фактический APPLY требует caller-supplied attestation внешнего снимка:

```bash
sudo ./securelinux-policy.sh --apply --snapshot-attestation /path/to/attestation.json
```

Оба режима печатают один JSON-объект `SLP-APPLY-REPORT-V1`. Голый `--apply`,
`--dry-run` без `--apply` и несовместимые комбинации отвергаются с `RC=2` до
изменения системы. Пользовательского ключа `--restore` нет: operational RESTORE
исключён из v3.
Human-readable `--check` и `--report` явно показывают обнаруженную ОС, архитектуру и runtime platform. Для основной 7/7 матрицы выводится `PROFILE=FULL|MINIMIZED|SERVER`; для дополнительного Ubuntu 24.04 Desktop выводится `TYPE=DESKTOP`. Конкретная графическая оболочка не входит в support identity и не влияет на CHECK/APPLY routing.

Sidecar текущего tracked artifact:

```bash
sha256sum -c securelinux-policy.sh.sha256
```

### Для разработчика: детерминированная пересборка

Текущий пользовательский артефакт строится `product/generate-product-check-v2.py`.
Отслеживаемый `securelinux-policy.sh` обязан побайтно совпадать со свежей генерацией;
это проверяется DEV regression. Для ручной проверки можно собрать копию вне
отслеживаемого корня Git:

```bash
mkdir -p dist
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  product/generate-product-check-v2.py \
  --repo . \
  --out dist/securelinux-policy.sh

cmp -s securelinux-policy.sh dist/securelinux-policy.sh
echo "RC_PARITY=$?"
```

Исторический `product/generate-product-check-v1.py` сохраняется как предыдущая
generator identity и не является текущей пользовательской точкой входа.

---

## Надёжность текущей product-line

| Гарантия | Статус | Чем проверяется |
|---|---|---|
| APPLY реализован только для `SRC-0001`; RESTORE намеренно исключён | PASS | implementation registry + binding + adapter; generated CLI regressions; VM acceptance |
| Детерминированная генерация CHECK | PASS | `tests/product-v1/test_product_generator.py` |
| Adapter/contract bytes закреплены SHA-256 | PASS | `ADAPTER-REGISTRY.tsv` + product regressions |
| CHECK provenance доступен машинно | PASS | generator regression / `--provenance` |
| Sysctl read-error не уходит в неструктурированный stderr | PASS | sysctl adapter regression |
| Неподдерживаемая target-платформа завершается до проверки | PASS | product generator regression, RC=3 |
| DEV test population имеет единую точку запуска | PASS | `tests/run-all.py` + `tests/run-all-selftest.py` |
| Реальный Draft 2020-12 валидатор обязателен для RELEASE | PASS | `tests/release-v1/test_real_jsonschema_gate.py` |
| Current nested `SHA256SUMS` валидны; 2 historical donor runtime entries пинованы как исключения | PASS | `tests/project-integrity-v1/test_root_manifests.py` |
| Gates-v3 evidence с маркировкой `ACTIVE` совпадает со свежим checker run | PASS | `tests/project-integrity-v1/test_root_manifests.py` |
| APPLY | РЕАЛИЗОВАН ДЛЯ `SRC-0001` | `APPLY_SCOPE=SRC-0001_ONLY`; dry-run / attested commit / idempotent NOOP |
| RESTORE | НЕ ПЛАНИРУЕТСЯ / ВНЕ SCOPE | post-APPLY recovery = внешний snapshot |

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
  → CHECK/APPLY registries
  → read-only CHECK adapters + SRC-0001 APPLY adapter
  → tracked generator
  → generated unified CLI
```

[`docs/ARCHITECTURE-DIAGRAMS.md`](docs/ARCHITECTURE-DIAGRAMS.md) —
**historical donor runtime reference**, а не current project map и не future target
model. Он сохраняет проверяемую историю donor mechanics и отдельно фиксирует
границу v3: operational RESTORE исключён, post-APPLY recovery выполняется внешним
snapshot/backup-механизмом.

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

Отслеживаемый [`tests/run-all.py`](tests/run-all.py) — единая точка запуска всех
отслеживаемых Python regressions.

**DEV**:

- только stdlib;
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
product/    semantic contracts, CHECK/APPLY registries, adapters, unified generator
securelinux-policy.sh  tracked CHECK + SRC-0001 APPLY user entrypoint
dist/       optional derived rebuild output; gitignored
probes/     read-only probe infrastructure и historical/reference evidence line
tests/      DEV/RELEASE regression suites
docs/       product, engineering, donor-reference и roadmap documentation
step7b0/    historical assurance line; не current product authority
archive/    historical verification material и engineering donor
```

---

## Целостность

Корневые манифесты:

- `PROJECT-FILES.sha256` — каноническая project population;
- `SHA256SUMS` — SHA-256 файлов этой population.

Проверка:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  tools/rebuild-root-manifests.py \
  --project-root . \
  --check
```

Машинно формируемые блоки документации и coverage также проверяются отдельно:

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

Mapping донора сам по себе не создаёт FSTEC controls и не закрывает ни одной
строки source-index.

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
- APPLY реализован только для `SRC-0001`; RESTORE исключён из целевой архитектуры, rollback model — external snapshot;
- historical Step 7B.0 не является current product authority;
- engineering donor не является нормативным доказательством.

Сгенерированный CHECK всегда строится из текущей `CONTROL-MANIFEST.tsv`; точная
population показана в машинно сформированном статусе выше. Authority refresh 2026
закрыт: `fstec-order-117-2025-requirements` учитывается вместе с изменяющим его
`fstec-order-137-2026-amendments-to-117`, при этом `SRC-0001…SRC-0040` из
`fstec-linux-2022` не переоткрывались. Для модульной архитектуры `SRC-0001` закрыты и криптографически привязаны
точные определения предиката и преобразования, условия внешнего снимка, блокировки и повторного чтения, идентичности объекта, сохранения метаданных, атомарной транзакции и сухого запуска с отчётом.
Композиция связывает все восемь ролей определений; implementation registry,
binding и adapter связывают реализацию с этой композицией. Generated CLI выполняет
сухой запуск, attested commit, локальную post-check и idempotent NOOP для `SRC-0001`.
Этап `APPLY_IMPLEMENTATION_ADAPTERS` закрыт; `FINAL_DETERMINISTIC_PACKAGING` является следующим этапом.
Оставшиеся строки `OPEN` других документов ФСТЭК сохраняются в очереди и не
расширяются до `DOCUMENT COMPLETE` текущей вертикали.
Семантика `chmod go-rwx /etc/shadow` представлена как `mode bits-clear 0077` и
не усилена до выдуманного `0600`.

---

## Источники истины

| Область | Канонический источник |
|---|---|
| population/status источников | `index/source-v4/SOURCE-INDEX.tsv` |
| framework sources | `index/source-v4/FRAMEWORK-SOURCES.tsv` |
| связи base/amendment framework authority | `index/source-v4/FRAMEWORK-AUTHORITY-RELATIONS.tsv` |
| page-pinned evidence для image-only authority | `sources/visual-v1/PROVENANCE.tsv` |
| закрытие полноты | `index/source-v4/CLOSURE-CONTRACT.tsv` |
| решения | `index/source-v4/DISPOSITION-LEDGER.tsv` |
| канонические controls | `controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv` + YAML |
| схема параметров | `checker/gates-v3/checker.py` → generated `CONTROL-SCHEMA.json` |
| mapping адаптеров CHECK | `product/ADAPTER-REGISTRY.tsv` |
| привязка APPLY-kind к модульной архитектуре | `product/APPLY-KIND-REGISTRY.tsv` |
| модульная APPLY-архитектура `SRC-0001` | `product/contracts/src0001-apply/architecture-v1.json` |
| привязка реализации APPLY | `product/APPLY-IMPLEMENTATION-REGISTRY.tsv` |
| реализация APPLY `SRC-0001` | `product/apply-adapters/product-local-account-password-state-apply-v1.py` + binding |
| текущий генератор CHECK/CLI | `product/generate-product-check-v2.py` |
| отслеживаемая пользовательская точка входа | `securelinux-policy.sh` + `.sha256` |
| макро-roadmap | `docs/ROADMAP-v3.tsv` |
| сгенерированные current docs | `tools/render-current-docs.py` |

README является входной точкой для человека, но не заменяет эти машиночитаемые
источники истины.

---

## Документация

Начинать с [`docs/README.md`](docs/README.md): там каждый документ помечен как
`PRODUCT`, `ENGINEERING`, `DONOR-REFERENCE`, `ROADMAP` или `FUTURE/HISTORICAL`.

Пользовательская документация ведётся на русском. Имена файлов/CLI,
идентификаторы gates, enums, schema fields и machine-status strings остаются в
контрактном виде.
