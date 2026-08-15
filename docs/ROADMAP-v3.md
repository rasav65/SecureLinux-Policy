# SecureLinux-Policy v3 — authoritative forward roadmap

This is the authoritative order after Step 5 reference-VM evidence closure.
Do not start a later step until the preceding step is closed unless this
roadmap is explicitly reviewed and changed.

1. Step 5 audit provenance closure
2. Gate 6 `evidence_binding`
3. type/boolean contract cleanup
4. mandatory real-jsonschema release gate
5. index-generic source skeleton generator
6. source-block regeneration parity gate
7. FSTEC + corporate index expansion / dispositions
8. apply/restore semantic contract
9. implementation adapters
10. deterministic build
11. single distributable `securelinux-ng.sh`

Non-negotiable rules:
- Do not begin mass work on the 344 OPEN FSTEC rows before Gate 6, boolean/type cleanup, the skeleton generator and source-block parity are closed.
- Gate 6 proves evidence binding/integrity, not cryptographic origin from a VM.
- The skeleton generator is index-generic and is the only writer of `source:`.
- A parity gate regenerates `source:` and compares it to committed controls.
- `211` is only the measured count of source_role=transitive-process in source-v4; it is not a disposition forecast.
- Corporate is a first-class layer and needs its own index population.
- apply/restore semantics must be defined before implementation adapters.
- The final monolith is a deterministic build artifact, never source of truth.
- Generated output must not depend on timestamps, absolute paths, filesystem traversal order or unittest timing.
- Every emitted block carries provenance: control_id, source locator, quote_sha256, implementation adapter identity/version.
- Release/audit validation requires a real Draft 2020-12 validator and records its version.
- Future git bundles must be actively verified and tree-compared to the project snapshot; they do not prove remote origin.

CURRENT STATUS: roadmap steps 1–6 are CLOSED; step 7 FSTEC + corporate index expansion / dispositions is NEXT.

## Engineering donor preservation rule

The preserved SecureLinux-NG v16.2.11 project remains an engineering donor,
not normative authority. Before roadmap step 8 (`apply/restore semantic
contract`) begins, the project MUST complete and review `DONOR_TO_V3_MAPPING`
using the decisions `REUSE | ADAPT | REJECT | DEFER`.

The mapping must account explicitly for the mature donor mechanisms listed in
`docs/DONOR-V3-ADOPTION-POLICY.md`. The mapping itself closes zero FSTEC or
corporate source-index rows. No implementation adapter may bypass the
apply/restore contract merely because equivalent code existed in the donor.

## Gate 6 closure

Gate 6 `evidence_binding` is implemented and verified for the current factual
`sysctl-v1` reference-VM evidence.

It proves the binding:

`VM-METADATA -> probe.py -> probe-plan.tsv -> privileged/unprivileged results -> evidence SHA256SUMS`

It does **not** prove cryptographic origin from the named VM.

TYPE/BOOLEAN CONTRACT CLEANUP: CLOSED.

## Type/boolean contract cleanup closure

The accidental generic `"true"` / `"false"` string coercion has been removed.

Current/forward observation contracts:

- sysctl: implemented runner; integer/string wire values are JSON strings;
  boolean is not a valid sysctl control type;
- systemd-unit-state: future runner must emit JSON boolean for boolean VALUE;
- package-presence: future runner must emit JSON boolean for boolean VALUE;
- file-kv boolean: explicitly deferred until its probe design defines
  source-specific textual mapping.

This stage changes no `KIND_RULES` entry and no generated control-schema byte.

MANDATORY REAL-JSONSCHEMA RELEASE GATE: CLOSED.

## Mandatory real-jsonschema release gate closure

Release/audit validation now fails closed unless a real installed
`jsonschema.Draft202012Validator` is available.

Closure evidence records the actual `jsonschema` distribution version used,
schema/checker/differential-test hashes, matrix counts and active-control
results. The full runtime↔real-validator matrix and emulator↔real-validator
matrix must both have zero disagreements.

This is separate from Gate 0 generation parity.

INDEX-GENERIC SOURCE SKELETON GENERATOR: CLOSED.

## Index-generic source skeleton generator closure

`tools/source_skeleton_generator.py` is now the canonical producer of
`source:` for supported unit kinds.

Current scope is deliberately narrow and measured:

- source index: 349 rows / 13 unit kinds;
- supported kind: `numbered-position` only;
- rows in supported kind: 74;
- exact extractions: 72;
- refused rather than guessed: `SRC-0001`, `SRC-0133`;
- current accepted controls reproduced byte-for-byte: 5/5.

The generator accepts an explicit index path and consumes the common index
field contract. It validates the normalizer, corpus manifests and normalized
corpus hashes fail-closed.

"Single writer" began as a normative authoring rule in step 5. Roadmap step 6
now mechanically enforces it for committed controls through byte-for-byte
regeneration parity.

This closure changes no controls and closes zero FSTEC source rows.

SOURCE-BLOCK REGENERATION PARITY: CLOSED.

## Source-block regeneration parity closure

`checker/source-parity-v1/source_block_regeneration_parity.py` now
mechanically enforces the single-writer rule for every committed control.

Current closure result:

- controls: 5;
- supported: 5;
- byte-identical matches: 5;
- unsupported: 0;
- missing index rows: 0;
- mismatches: 0;
- errors: 0.

A future control whose `unit_kind` is not yet supported is classified
`UNSUPPORTED` and fails closed rather than bypassing parity.

Permanent negative fixtures cover edits to `quote`, `quote_sha256` and
`locator`, plus unsupported kinds, missing index rows and malformed duplicate
`source:` blocks.

This step changes no controls and closes zero FSTEC source rows.

NEXT: FSTEC + corporate index expansion / dispositions.
