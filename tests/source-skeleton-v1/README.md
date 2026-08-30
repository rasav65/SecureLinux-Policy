# Регрессия генератора source skeleton

Постоянный regression для roadmap step 5.

Он доказывает current scoped generator contract:

- поддерживается один `unit_kind` (`numbered-position`);
- supported/exact population выводится из current source index;
- explicit refused identities остаются fail-closed;
- каждый current control из `CONTROL-MANIFEST.tsv` регенерируется byte-identical;
- работает alternate index path;
- повреждение trust-chain завершается fail-closed.

Исторические numeric pins вроде `pilot=5`, `supported=74`, `exact=72` не являются
test contracts. Текущие значения могут совпадать с измеренными историческими
counts, но рассчитываются во время запуска.

Это отдельный механизм, не равный parity gate committed blocks на step 6.

- terminal page-furniture boundary для `SRC-0040 / 2.6.6`: exact EOF rule + negative fixtures;
- internal page-furniture boundary для `SRC-0001 / 2.1.1`: только exact pinned trailing token `3`; generic bare-integer stripping по-прежнему запрещён;
- internal inline page-furniture boundaries для `SRC-0008 / 2.3.4` и `SRC-0014 / 2.3.10`: только exact pinned surrounding fragments с page tokens `4`/`5`; generic inline-number stripping запрещён.

`TEST-RESULTS.txt` является fresh current evidence для этого regression и обязан побайтово совпадать с вычисленным summary текущего прогона; stale pilot/supported/exact/refused значения не допускаются.
