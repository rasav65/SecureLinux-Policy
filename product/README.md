# product line

Постоянная product-линия SecureLinux-Policy v3.

Отделена от `step7b0/`. `step7b0/` — historical assurance-line
(Build Contract v0.9.5, Phase A принята, Phase C item 19 = REVISE);
её adapter id `sysctl-check-v1` и её admitted bytes здесь не используются
и не изменяются.

Состав на текущем шаге:

- `contracts/file-mode-owner-check-semantic-v1.json` — семантика чтения
  режима файла; statuses `VALUE` / `NOT_FOUND` / `ERROR`;
- `adapters/product-file-mode-owner-check-v1.py` — read-only file-mode emitter;
- `adapters/product-file-mode-owner-check-v1.json` — binding file adapter;
- `contracts/sysctl-check-semantic-v1.json` — отдельная product-семантика
  read-only sysctl CHECK; historical `step7b0/.../check-semantic-v1.json`
  current product authority не является;
- `adapters/product-sysctl-check-v1.py` — read-only sysctl emitter с
  собственной identity `product-sysctl-check-v1`;
- `adapters/product-sysctl-check-v1.json` — binding sysctl adapter;
- `ADAPTER-REGISTRY.tsv` — единственный tracked mapping parameter kind
  на semantic contract, adapter binding и implementation вместе с SHA-256.

Ещё не создан и создаётся отдельным шагом: tracked generator product CHECK.

Принцип классификации отсутствия: `NOT_FOUND` только при доказанном
отсутствии имени в проходимом родительском каталоге. Всё, что нельзя
доказать как отсутствие (нечитаемый путь, висячая ссылка, цикл ссылок,
отсутствие `stat`), классифицируется как `ERROR`.

Тесты: `tests/product-v1/`.
