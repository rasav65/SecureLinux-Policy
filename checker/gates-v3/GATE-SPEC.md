# Gates 1–5 — checker-v3

## Gate 1 — live source / quote anchor
Semantics inherited from checker-v2.

## Gate 2 — reverse source coverage + completeness contract
A controlled CLOSED source row is valid only when:
1. at least one active control references its `index_id`;
2. the row is `CLOSED`;
3. disposition/reason are empty;
4. `CLOSURE-CONTRACT.tsv` has exactly one contract for that row;
5. the actual set of control IDs is exactly the set declared by the contract.

`coverage_mode`:
- `atomic-single` — exactly one control is the complete semantic coverage;
- `exact-control-set` — two or more controls are jointly required.

A disposition-closed row must not have a control completeness contract.

This prevents “one arbitrary control closes a composite source clause”.

## Gate 3 — closed schema / parameter closure
Runtime semantics are unchanged, but `CONTROL-SCHEMA.json` is now a complete
nested contract for all required fields, derived/justification rules,
layer/profile rule, expected value typing and all 8 parameter kinds.

## Gate 4 — scoped uniqueness and explicit cross-scope semantics
Hard same-scope identity:

`(layer, profile, kind, locator, key)`

Divergent expectations inside one scope fail.

Corporate `baseline/strict/paranoid` may intentionally have different values
for the same physical parameter; those are counted as `profile_variants`.

Divergent values across provenance layers are NOT automatically resolved.
They fail as `unresolved cross-scope parameter conflict` until a future
explicit adjudication mechanism records authority, chosen value and
justification.

## Gate 5 — probe executability
Semantics inherited from checker-v2. Current runtime runner: sysctl only.
