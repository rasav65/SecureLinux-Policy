# Документация SecureLinux-Policy

Этот файл — индекс документации. Он отделяет продуктовые документы от
engineering contracts, roadmap и donor reference, чтобы несколько файлов не
конкурировали за роль «главного описания проекта».

Начало работы: [скачивание и запуск](../README.md#скачать).
Подробности реализации, источники истины и пересборка: [продуктовая линия](../product/README.md#readme-engineering-reference).

## PRODUCT — продуктовые документы

Документы, с которых следует начинать пользователю текущей product-line.

| Документ | Роль |
|---|---|
| [`PROJECT-MAP-v3.md`](PROJECT-MAP-v3.md) | **PRIMARY** архитектурная карта текущего проекта |
| [`policy-layers.md`](policy-layers.md) | границы FSTEC core / recommended / corporate / firewall |
| [`fstec-coverage.md`](fstec-coverage.md) | **GENERATED** карта текущего FSTEC coverage из machine truth |
| [`compatibility.md`](compatibility.md) | SUPPORTED / TESTED / UNSUPPORTED для current product target |

## ENGINEERING — инженерные документы

| Документ | Роль |
|---|---|
| [`evidence-binding.md`](evidence-binding.md) | binding фактического evidence к проверяемым bytes/contracts |
| [`observation-value-contract.md`](observation-value-contract.md) | формат и типизация observation values |
| [`release-validation.md`](release-validation.md) | обязательная release-validation и real jsonschema policy |
| [`root-manifest-policy.md`](root-manifest-policy.md) | canonical population корневых manifests |
| [`source-block-regeneration-parity.md`](source-block-regeneration-parity.md) | паритет сгенерированных блоков `source:` |
| [`source-skeleton-generator.md`](source-skeleton-generator.md) | контракт генератора source-skeleton |
| [`disposition-ledger.md`](disposition-ledger.md) | явный путь закрытия через disposition |

## ROADMAP — план работ

| Документ | Роль |
|---|---|
| [`ROADMAP-v3.md`](ROADMAP-v3.md) | человекочитаемое объяснение macro-roadmap |

Machine truth порядка и статуса roadmap находится в `ROADMAP-v3.tsv`.

## DONOR-REFERENCE — справочные материалы донора

Эти документы содержат инженерные знания донора и архитектурные ориентиры для
APPLY и его будущего расширения. Они **не являются источником current product
status**; фактический scope берётся из product registries, roadmap и primary map.
Historical RESTORE-механика хранится в donor archive/mapping, но не показывается
как operational/future ветвь целевой архитектуры v3.

| Документ | Роль |
|---|---|
| [`ARCHITECTURE-DIAGRAMS.md`](ARCHITECTURE-DIAGRAMS.md) | historical donor runtime reference + границы v3; не primary map и не future target model |
| [`DONOR-V3-ADOPTION-POLICY.md`](DONOR-V3-ADOPTION-POLICY.md) | правила REUSE / ADAPT / REJECT / DEFER |
| [`engineering-donor.md`](engineering-donor.md) | состав и индекс engineering donor |
| [`testing-strategy.md`](testing-strategy.md) | инварианты tests, полученные из донора, + текущий baseline DEV/RELEASE |

## Язык current-документации

Человекочитаемая current-документация ведётся по-русски. Технические identifiers,
filenames, CLI/schema/status tokens, exact donor labels и protocol/wire literals
сохраняются без перевода, когда это нужно для совместимости или machine binding.

Historical/frozen SHA-bound material не переводится на месте. В частности,
не выполняется in-place перевод `archive/**`, `audit/**`, superseded
`index/source-v1..v3`, reference-VM evidence и принятых `step7b0/BUILD-CONTRACT-*`.
Для них при необходимости создаётся отдельный русский companion, не меняющий
исходную identity.

В отдельном контролируемом documentation-only этапе текущий `CHANGELOG.md` был
русифицирован вместе с остальной редактируемой current-документацией, включая
накопленную секцию `[Не выпущено]` и старые release sections, которые остаются
частью текущего файла. Это не распространяется на frozen/SHA-bound historical
artifacts из исключённых областей выше. Exact donor labels, roadmap step/status
identifiers, CLI/schema/protocol tokens и source quotes сохраняются без перевода.

Documentation regression проверяет, что каждый Git-tracked current Markdown вне
этих historical/frozen классов содержит русскую человекочитаемую prose.

## Правило актуальности

Числа текущего coverage не должны поддерживаться вручную в нескольких местах.
`tools/render-current-docs.py` формирует machine-owned блоки README,
`PROJECT-MAP-v3.md` и весь `fstec-coverage.md`.

Проверка:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  tools/render-current-docs.py --project-root . --check
```

Если source index, closure contract, controls или adapter registry изменились,
сначала выполняется `--write`, затем DEV regression.
