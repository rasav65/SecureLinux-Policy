# Product CHECK line

Постоянная read-only product-line SecureLinux-Policy v3.

Она отделена от historical `step7b0/`: admitted bytes и historical adapter id
`sysctl-check-v1` не являются current product authority и здесь не изменяются.

## Текущий состав

- `contracts/file-mode-owner-check-semantic-v1.json` — read-only semantic
  contract для `file-mode-owner`;
- `contracts/sysctl-check-semantic-v1.json` — read-only semantic contract для
  `sysctl`;
- `adapters/product-file-mode-owner-check-v1.py` + JSON binding;
- `adapters/product-sysctl-check-v1.py` + JSON binding;
- `ADAPTER-REGISTRY.tsv` — единственный tracked mapping parameter kind →
  semantic contract / binding / implementation с SHA-256;
- `generate-product-check-v1.py` — tracked deterministic generator current
  product CHECK;
- `dist/` — derived gitignored output, не источник истины.

Generator читает текущий `CONTROL-MANIFEST.tsv`, проверяет canonical YAML и
registry SHA bindings и fail-closed выбирает adapter по `parameter.kind`.

## Текущий статус

CHECK по current manifest population реализован и regression-tested. Generated
artifact имеет статус `NON_RELEASE_PRODUCT_CANDIDATE` и target
`ubuntu-24.04-x86_64`.

CHECK не содержит APPLY/RESTORE. Policy noncompliance не равен execution
failure; `NOT_FOUND`/`ERROR` делают итог `UNEVALUATED`.

Принцип отсутствия — `proven-absence-only`: `NOT_FOUND` допустим только при
доказанном отсутствии имени. Нечитаемый объект, dangling symlink, symlink loop
или отсутствие обязательного observation tool классифицируются как `ERROR`.

## Текущее расширение FSTEC core

`SRC-0005 / 2.3.1` закрыт через `exact-control-set` из трёх canonical controls:

- `/etc/passwd` → `mode eq 0644`;
- `/etc/group` → `mode eq 0644`;
- `/etc/shadow` → `mode bits-clear 0077`.

`/etc/shadow = 0600` из source anchor не выводится. Все три controls используют
существующий read-only `product-file-mode-owner-check-v1`; APPLY/RESTORE по-прежнему
не реализованы.

После CHECK-11 product track перешёл к систематическому представлению
оставшихся `OPEN` source rows. Exact-eq batch использует существующий
`product-sysctl-check-v1` для `SRC-0030`, `SRC-0031`, `SRC-0036`–`SRC-0039`.
Следующий точечный шаг закрывает `SRC-0040 / 2.6.6` тем же read-only adapter:
`fs.suid_dumpable = 0`. Перед этим source-skeleton исключает только точный
конечный горизонтальный разделитель закреплённого PDF; нормативный quote
заканчивается фразой `вредоносное поведение.`, а не page furniture. Новый
adapter не создаётся. Exact current population всегда берётся из
`CONTROL-MANIFEST.tsv`. Formal `Gate 5 --probe-results` остаётся отдельным
контрактным артефактом и не подменяется выводом generated CHECK.

Тесты: `tests/product-v1/`.
