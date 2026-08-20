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
