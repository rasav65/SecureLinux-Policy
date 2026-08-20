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

## Следующий product expansion point

`SRC-0005 / 2.3.1` остаётся `OPEN`. File-mode semantic contract и adapter уже
готовы; следующий технический шаг — три canonical controls:

- `/etc/passwd` → `mode eq 0644`;
- `/etc/group` → `mode eq 0644`;
- `/etc/shadow` → `mode bits-clear 0077`.

`/etc/shadow = 0600` из этого source anchor не выводится.

После добавления controls выполняется CHECK по расширенной manifest population и
только затем source closure через `exact-control-set`.

Тесты: `tests/product-v1/`.
