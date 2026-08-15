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
  preserve when v3 eventually gains apply/restore.
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

`pending-review` is a statement about the review, not about the function.
It does **not** mean that no invariant is needed. Distinguishing the two is the
whole purpose of the column: before this, an unreviewed function and a function
deliberately judged uninteresting looked identical.

Current distribution: contracted 19, candidate 31, evidence-only 53,
pending-review 207. Total 310.

## Non-function evidence origins

`source_function` is not always a shell function. Four origins name a top-level
scope or a configuration array: `TOPLEVEL`, `CRON_CRITICAL_TARGETS`,
`FAILLOCK_CONF_STRICT`, `GRUB_KERNEL_REQUIRED_PARAMS`. They are declared
explicitly in the test rather than silently tolerated.

## Registered donor documents

`restore-model.md` is the design source for restore semantics and is the natural
input to roadmap step `APPLY_RESTORE_SEMANTIC_CONTRACT`. It and the other three
donor documents are now pinned by SHA-256 in `SOURCE.tsv`, so they are evidence
with provenance rather than files that merely happen to sit in `archive/`.

`fstec-mapping.md` is registered as `engineering-donor-claimed-mapping-non-normative`:
it is the donor's own claim about FSTEC coverage and mixes FSTEC clause numbers
with internal-standard numbering. It is not a normative source for v3.
