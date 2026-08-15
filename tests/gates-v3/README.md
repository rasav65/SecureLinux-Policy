# gates-v3 tests

`test_audit_fixes.py` — focused tests for completeness-contract, full schema,
scope/profile conflicts and active pilot fail-closed behavior.

`test_schema_runtime_parity.py` — B-R1-01 and B-R2-01 regression:

- generation parity: `CONTROL-SCHEMA.json` is byte-identical to the schema
  generated from the runtime constants;
- differential acceptance: 50 records, including 16 CR/LF boundary cases,
  must be judged identically by the runtime and by the schema;
- pattern semantics: for every anchored pattern, `re.fullmatch` (runtime) and
  `re.search` (JSON Schema) must accept the same set of strings;
- parser invariant: a control character in a scalar is rejected at parse time;
- when `jsonschema` is installed, the same matrix is also run against a real
  `Draft202012Validator`; otherwise those two tests are skipped explicitly.

Observation-value contract tests ensure there is no generic boolean string coercion and reserve JSON-boolean wire values for future systemd/package runners.
