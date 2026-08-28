# Engineering donor adoption

SecureLinux-Policy v3 keeps the old SecureLinux-NG implementation as a
**non-normative engineering donor**.

Pinned donor:

- `archive/securelinux-ng.sh`
- SHA-256 `f3be8723cd5a2be499e9e8e6370fad712bdec8afd68050f27af6a3e2d6fbc34b`
- 18,928 lines

Pinned final architecture review:

- `archive/engineering-review-20260731/SecureLinux-NG-architecture-final-review-20260731-112906.tar.gz`
- SHA-256 `7a62c1304a423e4431b08c34e999ed221777d63ecfb0aec180767fadf80759d2`

## What is adopted now

The following are adopted as future APPLY implementation invariants, not as claims
that APPLY already exists:

- fail-closed backup before mutation;
- atomic critical-file replacement;
- exclusive locking for mutating runs;
- atomic manifest updates;
- explicit warnings and irreversible/partial changes;
- targeted sysctl APPLY plus live-value pre-state capture for transaction-local failure handling;
- package pre-state/delta tracking;
- exact compensating rollback inside a failed, uncommitted APPLY transaction where the contract proves it;
- external snapshot rollback after a completed APPLY; no user-invokable RESTORE mode;
- executable architecture regression tests.

Exact evidence is machine-indexed in
`index/engineering-donor-v1/ENGINEERING-CONTRACTS.tsv`.

## Reverse index

`index/engineering-donor-v1/` makes the donor mechanically traceable:

- all 310 detected shell function declarations;
- all 18,928 source lines covered by 190 deterministic 100-line chunks;
- 141 semantic candidates;
- 478 raw evidence rows;
- 20 engineering contracts.

This addresses preservation of the donor implementation without treating it as
normative truth.

## Final v16.2.11 regression suite

The complete uploaded v16.2.11 project is pinned under
`archive/engineering-donor-v16.2.11/`.

Source ZIP SHA-256:

`1b25f554a5ad1509037aa9613b7851a595159fd44291913cc2dba63280e50494`

The suite contains 38 test files and 36 focused regression scripts. The donor
`smoke.sh` wires all 36 regressions exactly once. The machine registry in
`index/engineering-tests-v1/` records every test, its SHA/size/line count,
adoption status, 32 generalized engineering contracts and historical donor VM
evidence.

One donor component is safe and useful immediately: `tools/write-sha256.py`
has been adopted as an active project helper together with its regression test.
It is independent of the old monolithic runtime.

Legacy mapping tests remain historical-only; they are never used as v3
normative evidence or source-row closure.

See `docs/testing-strategy.md`.


## DONOR_TO_V3_MAPPING

Перед roadmap step 8 построен machine-readable candidate
`index/engineering-donor-v1/DONOR-TO-V3-MAPPING.tsv`.

Текущий candidate mapping:

- покрывает 310/310 donor-функций;
- покрывает 38/38 donor test files;
- отдельно учитывает все 16 mature families из
  `docs/DONOR-V3-ADOPTION-POLICY.md`;
- связывает 20 existing engineering contracts и 32 generalized donor test
  contracts;
- использует только `REUSE | ADAPT | REJECT | DEFER`;
- имеет `normative_effect=NONE` и закрывает 0 source-index rows.

Статус mapping: `BUILT_AWAITING_REVIEW`. После APPLY-only correction: `REUSE=1`, `ADAPT=178`, `REJECT=91`, `DEFER=94`; `RESTORE_OPERATIONAL_CONTOUR=EXCLUDED`, post-APPLY recovery=`EXTERNAL_SNAPSHOT`. Поэтому
`APPLY_SEMANTIC_CONTRACT` пока остаётся запрещён до отдельного review.

`password-policy-regression.sh` остаётся donor `DEFER` для будущей
corporate/APPLY-фазы. В current `fstec-linux-2022 CHECK` он не переносится.
Сохранённые будущие engineering details: PAM multiarch, preflight словарей до
mutation, выбор активных аккаунтов и dry-run плана `chage`.

## What this does not change

This adoption does not:

- create controls;
- close FSTEC source rows;
- change `index/source-v4`;
- change Gate 1–5 semantics;
- provide reference-VM evidence;
- implement APPLY or RESTORE. RESTORE is not planned; APPLY remains future work.

Donor adoption itself closes zero FSTEC source rows. Current live coverage is
owned by `SOURCE-INDEX.tsv` and generated `docs/fstec-coverage.md`.
