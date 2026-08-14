# Testing strategy inherited from SecureLinux-NG engineering evidence

The v16.2.11 donor contains 38 test files and 36 focused regression suites.
SecureLinux-Policy v3 adopts their **engineering invariants**, not the old
normative mapping.

## Test layers

1. Source/schema/unit tests — deterministic and host-independent.
2. Differential tests — compare two implementations of one contract directly.
3. Failure/crash-injection tests — exercise transaction boundaries before and
   after mutation.
4. VM acceptance — the only place where host/runtime behavior can close a VM
   execution gate.

Synthetic evidence never substitutes reference-VM evidence.

## Mandatory transaction test pattern for future apply/restore

Every mutation class should eventually have tests for:

- pre-state captured successfully before mutation;
- journal/manifest intent recorded before mutation;
- writer failure before mutation => target unchanged;
- crash after intent but before mutation => safe restore/no unintended change;
- crash after mutation but before commit => restore from pending state;
- commit records the actual result, not intended result;
- restore returns exact representable pre-state;
- irreversible state is explicit and never silently reported as restored.

## Filesystem safety matrix

Managed files must be tested against regular files, symlinks, dangling links,
hardlinks, metadata/xattrs, permission failures, and producer failures.
Replacement must be atomic and fail before target replacement on unexpected
metadata errors.

## Result-code semantics

Policy noncompliance and execution failure are distinct. A non-compliant check
may still execute successfully, while internal/preflight/report failures must
propagate a non-zero execution RC.

## Registry

See `index/engineering-tests-v1/TEST-CONTRACTS.tsv` for the machine-readable
32-contract donor registry and `TEST-INVENTORY.tsv` for every preserved test.

Legacy donor tests that assert the old mixed FSTEC mapping remain historical
evidence only.
