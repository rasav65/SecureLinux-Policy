# Source skeleton generator regression

Permanent regression for roadmap step 5.

It proves the current scoped generator contract:

- one supported `unit_kind` (`numbered-position`);
- supported/exact population is derived from the current source index;
- explicit refused identities remain fail-closed;
- every current control from `CONTROL-MANIFEST.tsv` regenerates byte-identically;
- alternate index path works;
- trust-chain corruption fails closed.

Historical numeric pins such as `pilot=5`, `supported=74`, `exact=72` are not
test contracts. The current values may still equal measured historical counts,
but they are calculated during the run.

This is distinct from the step-6 committed-block parity gate.

- terminal page-furniture boundary для `SRC-0040 / 2.6.6`: exact EOF rule + negative fixtures;
- internal page-furniture boundary для `SRC-0001 / 2.1.1`: только exact pinned trailing token `3`; generic bare-integer stripping по-прежнему запрещён.
- internal inline page-furniture boundaries для `SRC-0008 / 2.3.4` и `SRC-0014 / 2.3.10`: только exact pinned surrounding fragments с page tokens `4`/`5`; generic inline-number stripping запрещён.
