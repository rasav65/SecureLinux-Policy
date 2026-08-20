# Testing strategy

SecureLinux-Policy использует собственный current test baseline и сохраняет
проверенные инженерные invariants из SecureLinux-NG donor. Нормативная модель
старого проекта не наследуется.

## Current runner

Tracked `tests/run-all.py` — canonical точка запуска Python regressions.
Популяция test-файлов определяется из Git в момент запуска.

- DEV — stdlib-only, все project regressions кроме `release-v1`;
- RELEASE — DEV PASS + объявленные внешние зависимости и release gates.

RC=0 без доказательства фактического выполнения теста недостаточен. Unexpected
skip, `ResourceWarning`, untracked `test_*.py` и project failure делают DEV
красным.

## Test layers

1. Source/schema/unit tests — deterministic and host-independent.
2. Differential tests — compare two implementations of one contract directly.
3. Documentation parity — machine-owned current blocks must reproduce exactly.
4. Failure/crash-injection — future mutation transaction boundaries.
5. VM acceptance — host/runtime evidence for конкретного target и exact bytes.

Synthetic evidence never substitutes reference-VM evidence.

## Documentation parity

Current counts/status must come from machine truth, not from historical literals
inside tests. `tools/render-current-docs.py` derives README current status,
PROJECT-MAP current status and `docs/fstec-coverage.md` from source index,
closure contract, control manifest and adapter registry.

Regression compares expected and committed bytes. Changing `5 → 8 → 11` must
not require editing a test merely to replace one hardcoded count with another.

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

## Donor registry

See `index/engineering-tests-v1/TEST-CONTRACTS.tsv` for the machine-readable
32-contract donor registry and `TEST-INVENTORY.tsv` for preserved donor tests.
Legacy donor tests that assert the old mixed FSTEC mapping remain historical
evidence only.
