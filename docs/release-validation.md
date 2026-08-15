# Release validation policy

## Mandatory real JSON Schema dependency

For release/audit closure, SecureLinux-Policy v3 requires a real
`jsonschema.Draft202012Validator`.

The development differential suite keeps its optional behavior so lightweight
developer environments can still run the emulator checks. That optional path
is **not** sufficient for release.

The release gate:

`checker/release-v1/real_jsonschema_gate.py`

must pass without fallback.

## Why this is separate from Gate 0

Gate 0 proves only byte generation parity:

`committed CONTROL-SCHEMA.json == checker.render_control_schema()`

It does not independently prove that JSON Schema pattern/type semantics agree
with runtime validation.

The release gate therefore executes the full differential matrix against the
real Draft 2020-12 validator and records the installed `jsonschema`
distribution version.

This specifically preserves the lesson from prior regex/newline parity
failures: validator semantics are part of release evidence, not an assumed
environment detail.

## Current evidence

Current closure evidence is stored in:

`checker/release-v1/RELEASE-EVIDENCE.json`

The file records the validator version used on the machine that closed the
gate. A later release may use a different version, but must rerun the gate and
produce new evidence rather than treating an old PASS as timeless.

Current closure used `jsonschema` distribution version `4.10.3`.

## Version policy

Minimum supported `jsonschema` release: `4.10.3`.

System closure evidence is generated with 4.10.3. The same updated gate is
also run under an explicitly supplied 4.26.0 compatibility interpreter.

Both runs must use `Draft202012Validator`, pass the 50-case differential
matrix including 16 newline cases, show zero runtime↔real and emulator↔real
disagreements, and validate all five active controls.

Dependency absence, an unparseable version, or a version below 4.10.3 fails
closed.
