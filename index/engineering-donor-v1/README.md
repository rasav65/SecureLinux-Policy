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
- `ENGINEERING-CONTRACTS.tsv` — reviewed implementation invariants to preserve
  when v3 eventually gains apply/restore.
- `SOURCE.tsv` — provenance of the donor and the final architecture review.

Important:

1. This material is engineering evidence, not FSTEC truth.
2. Candidate rows do not become controls automatically.
3. `v3_status=PENDING_NOT_ACTIVE` means the invariant is adopted as a future
   implementation contract but is not claimed as implemented by the current
   read-only pilot.
4. `index/source-v4` remains the only active FSTEC coverage index at this stage.
