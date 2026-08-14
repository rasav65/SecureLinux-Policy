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
- Do not begin mass work on the 344 OPEN FSTEC rows before Gate 6, boolean/type cleanup and the skeleton generator are closed.
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

NEXT: Gate 6 `evidence_binding`.

## Engineering donor preservation rule

The preserved SecureLinux-NG v16.2.11 project remains an engineering donor,
not normative authority. Before roadmap step 8 (`apply/restore semantic
contract`) begins, the project MUST complete and review `DONOR_TO_V3_MAPPING`
using the decisions `REUSE | ADAPT | REJECT | DEFER`.

The mapping must account explicitly for the mature donor mechanisms listed in
`docs/DONOR-V3-ADOPTION-POLICY.md`. The mapping itself closes zero FSTEC or
corporate source-index rows. No implementation adapter may bypass the
apply/restore contract merely because equivalent code existed in the donor.
