# Документация SecureLinux-Policy

Этот файл — индекс документации. Он отделяет продуктовые документы от
engineering contracts, roadmap и donor reference, чтобы несколько файлов не
конкурировали за роль «главного описания проекта».

## PRODUCT

Документы, с которых следует начинать пользователю текущей product-line.

| Документ | Роль |
|---|---|
| [`PROJECT-MAP-v3.md`](PROJECT-MAP-v3.md) | **PRIMARY** архитектурная карта текущего проекта |
| [`policy-layers.md`](policy-layers.md) | границы FSTEC core / recommended / corporate / firewall |
| [`fstec-coverage.md`](fstec-coverage.md) | **GENERATED** карта текущего FSTEC coverage из machine truth |
| [`compatibility.md`](compatibility.md) | SUPPORTED / TESTED / UNSUPPORTED для current product target |

## ENGINEERING

| Документ | Роль |
|---|---|
| [`evidence-binding.md`](evidence-binding.md) | binding фактического evidence к проверяемым bytes/contracts |
| [`observation-value-contract.md`](observation-value-contract.md) | формат и типизация observation values |
| [`release-validation.md`](release-validation.md) | обязательная release-validation и real jsonschema policy |
| [`root-manifest-policy.md`](root-manifest-policy.md) | canonical population корневых manifests |
| [`source-block-regeneration-parity.md`](source-block-regeneration-parity.md) | parity generated `source:` blocks |
| [`source-skeleton-generator.md`](source-skeleton-generator.md) | contract source-skeleton generator |
| [`disposition-ledger.md`](disposition-ledger.md) | explicit disposition closure route |

## ROADMAP

| Документ | Роль |
|---|---|
| [`ROADMAP-v3.md`](ROADMAP-v3.md) | человекочитаемое объяснение macro-roadmap |

Machine truth порядка и статуса roadmap находится в `ROADMAP-v3.tsv`.

## DONOR-REFERENCE

Эти документы содержат инженерные знания донора и будущие runtime patterns.
Они **не описывают current product как уже реализованный APPLY**. RESTORE-схемы
в donor reference являются историческими и не входят в целевую архитектуру v3.

| Документ | Роль |
|---|---|
| [`ARCHITECTURE-DIAGRAMS.md`](ARCHITECTURE-DIAGRAMS.md) | donor/future runtime reference; не primary map |
| [`DONOR-V3-ADOPTION-POLICY.md`](DONOR-V3-ADOPTION-POLICY.md) | правила REUSE / ADAPT / REJECT / DEFER |
| [`engineering-donor.md`](engineering-donor.md) | состав и индекс engineering donor |
| [`testing-strategy.md`](testing-strategy.md) | donor-derived test invariants + current DEV/RELEASE baseline |

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
