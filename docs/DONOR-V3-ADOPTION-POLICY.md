# SecureLinux-Policy v3 — engineering donor adoption policy

## Status

This policy is mandatory project architecture.

The preserved SecureLinux-NG v16.2.11 project is an **engineering donor**.
It is not a normative source of truth and it does not close FSTEC or corporate
source-index rows merely because equivalent behavior existed in the old
monolith.

## Required adoption path

Every old mechanism considered for v3 must pass through:

`DONOR -> v3 contract mapping -> REUSE | ADAPT | REJECT | DEFER -> APPLY semantic contract -> implementation adapter -> tests -> deterministic build`

No donor mechanism is copied into the generated final script merely because it
was mature or previously tested.

## Mandatory precondition before roadmap step 8

Before `APPLY_SEMANTIC_CONTRACT` begins, the project MUST create and
review a complete `DONOR_TO_V3_MAPPING` over the preserved engineering donor.

For every adopted/rejected/deferred mechanism the mapping must identify, at
minimum:

- donor item/function/chunk reference;
- relevant donor regression test(s), when present;
- existing engineering contract reference, when present;
- decision: `REUSE`, `ADAPT`, `REJECT`, or `DEFER`;
- target v3 contract/adaptor family, when applicable;
- rationale;
- whether the mechanism has any normative effect (`NONE` by default);
- explicit statement that the mapping itself closes zero source-index rows.

The mapping is engineering provenance. It is not normative evidence.

## Donor capabilities that must not be silently lost

At minimum the mapping must explicitly account for these mature families from
SecureLinux-NG:

1. preflight / compatibility classification;
2. transactional apply;
3. manifest-backed state tracking;
4. transaction-local compensation from recorded pre-state;
5. atomic writes for critical files and manifests;
6. fail-closed backup before mutation;
7. exact package delta tracking;
8. preservation of already stricter sysctl values;
9. isolated per-module sysctl application;
10. runtime sysctl pre-state capture / transaction-local compensation;
11. network-online reapply for managed network sysctl;
12. dry-run with no host mutation;
13. exclusive APPLY run locking;
14. profile / additional-measures / corporate separation;
15. crash/journal patterns;
16. explicit partial/manual/reboot external-recovery classifications.

Donor RESTORE mechanisms are not an adoptable mature family. They are accounted
explicitly at function/test/contract level: user-invokable or post-APPLY RESTORE
mechanics are `REJECT`; only fragments required for compensation inside a failed
uncommitted APPLY may be `ADAPT`.

The project-level post-APPLY rollback model is `EXTERNAL_SNAPSHOT`. A successful
APPLY is not reversed by SecureLinux-Policy. Snapshot creation/restoration is
an infrastructure responsibility outside the product.

The mapping may conclude `REJECT` or `DEFER`; it may not omit a family without
an explicit reason.

## Adapter gate

No implementation adapter may be accepted unless:

- its relevant normative control has passed the required source gates;
- the APPLY semantic contract for that adapter family exists;
- its donor mapping decision is recorded when donor behavior is being reused;
- positive and negative tests exist;
- transaction-local failure/compensation behavior is explicit;
- post-APPLY rollback responsibility is explicitly external snapshot recovery;
- generated output can carry machine-checkable provenance.

## Final monolith rule

`securelinux-ng.sh` is a deterministic build artifact, never a hand-maintained
source of truth.

The build must not depend on:

- timestamps;
- absolute build-host paths;
- filesystem traversal order;
- unittest timing text;
- locale-dependent nondeterministic output.

Every emitted implementation block must carry machine-checkable provenance at
least for:

- `control_id`;
- source locator;
- `quote_sha256`;
- implementation adapter id/version.

## Relationship to the authoritative roadmap

This policy does not add or reorder roadmap stages.

The authoritative order remains:

1. Step 5 audit provenance closure
2. Gate 6 evidence_binding
3. type/boolean contract cleanup
4. mandatory real-jsonschema release gate
5. index-generic source skeleton generator
6. source-block regeneration parity gate
7. FSTEC + corporate index expansion / dispositions
8. APPLY semantic contract
9. APPLY implementation adapters
10. deterministic build
11. single distributable securelinux-ng.sh

`DONOR_TO_V3_MAPPING` is a mandatory precondition to starting step 8.

`RESTORE` is not a roadmap stage and MUST NOT be introduced by donor reuse. The preserved donor restore code remains evidence only unless a fragment is explicitly adapted for transaction-local APPLY failure handling.
