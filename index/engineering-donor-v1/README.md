# Engineering donor reverse index v1

This index preserves and makes searchable the engineering work in
`archive/securelinux-ng.sh`.

It is **not a normative source index** and does not close any FSTEC row.

Pinned donor:

- SHA-256: `f3be8723cd5a2be499e9e8e6370fad712bdec8afd68050f27af6a3e2d6fbc34b`
- lines: `18928`

Contents:

- `FUNCTION-INDEX.tsv` — 310 shell function declarations with source ranges and
  SHA-256 of the source segment up to the next function declaration.
- `SOURCE-CHUNKS.tsv` — complete 18,928-line donor coverage in deterministic
  100-line chunks; 190 rows.
- `SEMANTIC-CANDIDATES.tsv` — 141 previously extracted parameter candidates.
- `RAW-EVIDENCE.tsv` — 478 raw evidence rows used to derive those candidates.
- `ENGINEERING-CONTRACTS.tsv` — 20 reviewed implementation invariants to
  preserve or explicitly classify when v3 gains APPLY. Donor RESTORE-specific
  mechanisms are evidence, not a current roadmap commitment.
- `SOURCE.tsv` — provenance of the donor script, the final architecture review
  and the four donor design documents.

Important:

1. This material is engineering evidence, not FSTEC truth.
2. Candidate rows do not become controls automatically.
3. `v3_status=PENDING_NOT_ACTIVE` means the invariant is adopted as a future
   implementation contract but is not claimed as implemented by the current
   read-only pilot.
4. `index/source-v4` remains the only active FSTEC coverage index at this stage.

## Adoption class

Every row of `FUNCTION-INDEX.tsv` carries `adoption_class` and `adoption_note`.
The class is *derived* from the other tables, and `test_donor_index.py` fails if
the stored value disagrees with that derivation, so the column cannot drift.

| class | meaning |
|---|---|
| `contracted` | named as `evidence_function` in `ENGINEERING-CONTRACTS.tsv` |
| `candidate` | named as `source_function` in `SEMANTIC-CANDIDATES.tsv` |
| `evidence-only` | named as `source_function` in `RAW-EVIDENCE.tsv` only |
| `pending-review` | not yet reviewed for a v3 invariant |

`pending-review` в `FUNCTION-INDEX.tsv` — исходная классификация reverse
index, вычисляемая только из `ENGINEERING-CONTRACTS.tsv`,
`SEMANTIC-CANDIDATES.tsv` и `RAW-EVIDENCE.tsv`. После появления отдельного
`DONOR-TO-V3-MAPPING.tsv` она больше не является current-статусом mapping:
решение по каждой функции хранится только в mapping.

Исходное распределение reverse index остаётся неизменным:
contracted 18, candidate 31, evidence-only 53, pending-review 208. Всего 310.

## DONOR_TO_V3_MAPPING

`DONOR-TO-V3-MAPPING.tsv` — machine-readable candidate mapping перед roadmap
step 8. Он:

- покрывает все 310 donor-функций ровно по одному разу;
- покрывает все 38 donor test files;
- отдельно фиксирует все 16 mature families, обязательные по
  `docs/DONOR-V3-ADOPTION-POLICY.md`;
- использует только решения `REUSE | ADAPT | REJECT | DEFER`;
- связывает существующие `ENG-*` и `TST-*` contracts, когда они применимы;
- для каждой строки фиксирует `normative_effect=NONE` и
  `closes_source_rows=0`.

Статус `BUILT_AWAITING_REVIEW` не разрешает начало
`APPLY_SEMANTIC_CONTRACT`: сначала mapping должен пройти отдельный review.
Machine truth mapping дополнительно фиксирует `RESTORE_OPERATIONAL_CONTOUR=EXCLUDED`
и `POST_APPLY_RECOVERY_MODEL=EXTERNAL_SNAPSHOT`. В `ADAPT` rationale operational
RESTORE terminology запрещена: допускается только transaction-local compensation
незавершённого APPLY; donor restore-named identifiers сохраняются лишь как exact
historical/evidence references или явно ограниченные compensation fragments.
`password-policy-regression.sh` явно остаётся `DEFER` donor для будущей
corporate/APPLY-фазы и не переносится в current `fstec-linux-2022 CHECK`.

## Non-function evidence origins

`source_function` is not always a shell function. Four origins name a top-level
scope or a configuration array: `TOPLEVEL`, `CRON_CRITICAL_TARGETS`,
`FAILLOCK_CONF_STRICT`, `GRUB_KERNEL_REQUIRED_PARAMS`. They are declared
explicitly in the test rather than silently tolerated.

## Registered donor documents

`restore-model.md` remains pinned donor evidence. It is no longer a target design
source for a v3 RESTORE mode. During `DONOR_TO_V3_MAPPING`, its mechanisms must
be classified as `REJECT` for user-invokable RESTORE or `ADAPT` only where a
fragment is needed for transaction-local APPLY failure handling. The document
and the other three donor documents remain pinned by SHA-256 in `SOURCE.tsv`.

`fstec-mapping.md` is registered as `engineering-donor-claimed-mapping-non-normative`:
it is the donor's own claim about FSTEC coverage and mixes FSTEC clause numbers
with internal-standard numbering. It is not a normative source for v3.
