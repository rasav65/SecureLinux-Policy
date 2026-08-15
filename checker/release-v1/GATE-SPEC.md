# Mandatory real-jsonschema release gate

## Purpose

This gate turns the optional real-validator check used during development into
a **mandatory fail-closed release/audit gate**.

Development/unit tests may still skip real-jsonschema-specific cases when the
dependency is absent. Release/audit closure may not.

## Required dependency

The gate must successfully import the installed `jsonschema` distribution and
must use `jsonschema.Draft202012Validator`.

The distribution version is read with
`importlib.metadata.version("jsonschema")` and written to release evidence.

If the dependency is absent, shadowed by a project-local module, or its version
cannot be resolved, the gate fails. There is no emulator fallback.

## Checks

The gate verifies:

1. `CONTROL-SCHEMA.json` declares Draft 2020-12.
2. `Draft202012Validator.check_schema()` accepts the committed schema.
3. Gate 0 generation parity still holds:
   committed schema == `checker.render_control_schema()`.
4. The existing differential matrix has at least 50 cases and 16 newline/CR
   boundary cases.
5. Every current `KIND_RULES` kind has both accepting and rejecting coverage.
6. Runtime acceptance equals real Draft202012Validator acceptance for the
   entire matrix.
7. The internal schema emulator equals the real validator for the matrix.
8. Every active control is accepted both by runtime closure and by the real
   Draft202012Validator.

## Evidence

`RELEASE-EVIDENCE.json` records:

- installed jsonschema version;
- Python version;
- validator/draft;
- SHA-256 of schema, checker, differential test and release gate;
- matrix counts/disagreements;
- active-control validation counts;
- all check results.

No timestamp is emitted.

## Scope

This gate validates the current control schema/runtime contract. It does not
change FSTEC source coverage, close Gate 2 rows, or implement new probe kinds.

## Version floor

Minimum supported `jsonschema` distribution version: **4.10.3**.

The release gate accepts only stable `X.Y.Z` version strings and fails closed
for an unparseable version or a version below 4.10.3.

This floor is the lowest retained passing release evidence, not a claim that
all older versions are known-bad. Compatibility evidence for 4.26.0 is
retained under `audit/release-jsonschema-compat-20260815/`.
