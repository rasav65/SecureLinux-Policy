# Source-block regeneration parity regression

Permanent regression for roadmap step 6.

Production coverage выводится из полной current population
`CONTROL-MANIFEST.tsv` и обязана регенерироваться byte-for-byte. Историческое
число controls не пинуется.

Поле `positive=5` в `TEST-RESULTS.txt` относится только к фиксированному
fixture harness. Оно НЕ является числом canonical controls. Полная production
parity проверяется отдельно по фактической current control population.

Negative fixtures prove fail-closed behavior for:

- `quote` mutation;
- `quote_sha256` mutation;
- `locator` mutation;
- unsupported `unit_kind`;
- missing index row;
- duplicate/malformed top-level `source:` block.
