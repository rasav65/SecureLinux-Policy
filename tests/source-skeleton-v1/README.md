# Source skeleton generator regression

Permanent regression for roadmap step 5.

It proves the current scoped generator contract:

- one supported `unit_kind` out of 13 (`numbered-position`);
- 74 rows in the supported kind;
- 72 exact extractions and 2 explicit refusals;
- all five current controls regenerate byte-identically;
- alternate index path works;
- trust-chain corruption fails closed.

This is not the step-6 committed-block parity gate. Step 6 is next.
