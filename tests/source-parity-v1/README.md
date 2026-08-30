# Регрессия паритета регенерации source-блоков

Постоянный regression для шага 6 roadmap.

Production coverage выводится из полной текущей population
`CONTROL-MANIFEST.tsv` и обязана регенерироваться byte-for-byte. Историческое
число controls не пинуется.

Поле `positive=5` в `TEST-RESULTS.txt` относится только к фиксированному
fixture harness. Оно НЕ является числом canonical controls. Полная production
parity проверяется отдельно по фактической current control population.

Отрицательные fixtures доказывают fail-closed поведение для:

- изменения `quote`;
- изменения `quote_sha256`;
- изменения `locator`;
- неподдерживаемого `unit_kind`;
- отсутствующей строки index;
- дублированного/некорректного верхнеуровневого блока `source:`.
