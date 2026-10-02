# SecureLinux-Policy — TASK-B1.1b Selector Meta-Contract Proposal v9

Дата: 2026-08-13

Статус: standalone revised read-only design candidate after the v8
external-review union `REVISE`.

```text
B1_1A_V2_1=ACCEPT
B1_1B_V6_EXTERNAL_AUDITOR_1=REVISE
B1_1B_V6_EXTERNAL_AUDITOR_2=REVISE
B1_1B_V7_EFFECTIVE=REVISE
V7_EXT_01=CLOSED_IN_V8
V8_EXTERNAL_REVIEW_UNION=REVISE_3_BLOCKERS
B1_1B_V8_EFFECTIVE=REVISE
B1_1B_V9_ACCEPTED=false
TASK_B1_1_ACCEPTED=false
TASK_B1_2=NOT_STARTED
SELECTOR_INSTANCES_FROZEN=0/20
CANONICAL_MUTATION=false
VALIDATOR_MUTATION=false
RUNTIME_MUTATION=false
ENGINE_CODE_GENERATION_ALLOWED=false
HOST_STATE_MUTATION=false
APPLY_RESTORE_ALLOWED=false
COMMIT_PUSH_ALLOWED=false
```

## 1. Authority, scope and paired schema

This document supersedes B1.1b v1-v8 as the current candidate. Earlier
revisions remain immutable evidence.

The exact structural companion is:

```text
SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-schema-v9-20260813.json
```

Conformance requires both artifacts:

```text
JSON Schema -> exact object shapes, required keys, tagged variants and enums
this document -> cross-object equality, behavior, coverage, ordering and policy rules
```

A contradiction is `CONTRACT_ERROR`; neither artifact silently overrides the
other. The paired schema is B1 model tooling, not the B2 validator or runtime.

v9 retains every v8 closure and closes the complete external v8 union:

```text
V8-01 exact tagged operation arity and unambiguous input-to-output bindings
V8-02 closed host/adapter enumeration domain and enumerate operation
V8-03 normative resolution-kind x population-mode x completeness matrix
```

No next B1 task is authorized by this candidate.

## 2. Retained facts and source status

```text
B1.1a v2.1 = ACCEPT
EXT-01…EXT-06 = retained closed
EXT2-01…EXT2-04 = retained closed
EXT3-01…EXT3-07 = retained closed
EXT4-01…EXT4-04 = retained closed
EXT5/V6/V7 blocker unions = retained closed
PRIMARY_SOURCE_INPUT_AVAILABILITY=PASS
PRIMARY_SOURCE_HASH_CLOSURE=PASS
B1_6_PRIMARY_SOURCE_ADJUDICATION=PENDING
B4_TRACEABILITY_IDS=488 retained
TOP_LEVEL_ROADMAP=B0-B7 only
TASK_B1_1_ACCEPTED=false
TASK_B1_2=NOT_STARTED
SELECTOR_INSTANCES_FROZEN=0/20
```

Presence and hash closure of source PDFs do not constitute selector
adjudication or selector freeze.

## 3. Exact recursive closure rule

Every object and tagged union obeys:

```text
required keys = enumerated
optional keys = enumerated
unknown keys = invalid
enum values = enumerated
aliases = invalid
implicit defaults = invalid
implicit coercion = invalid
free-form extension bags = invalid
```

Cross-object references must resolve to one registry entry of the required
schema. Missing, duplicate or type-incompatible registry entries prevent
selector instance freeze; they are not normalized to an S1 outcome.

## 4. Layer and machine-enforceable policy-free boundary

Selector machinery may consume only registered `identity`, `raw-fact`, and the
single declared `source-sequence` field. `policy-judgment` is forbidden.

Forbidden inputs, outputs, intermediate predicates and suppression criteria
include PASS/FAIL/NOT_APPLICABLE, compliant/non-compliant, approved/prohibited,
safe/unsafe, required/not-required, unused/needed, privileged/non-privileged,
and semantic equivalents.

Enforcement is structural and behavioral:

1. every resolver/adapter resolves to one section-7.7 behavior contract;
2. the behavior contract is bound to component identity and implementation
   SHA-256;
3. its input slots/populations equal the registry and concrete use-site;
4. it enumerates every allowed transformation and output field;
5. hidden inputs and unregistered reads are forbidden;
6. candidate suppression is forbidden outside an explicit section-7.7 membership decision or the section-19 filter stage;
7. any membership-changing classification requires an exact source-membership
   clause or reference-population authorization carried by the behavior
   contract;
8. output is exactly `selector-raw-candidate-population/v1` and every field is
   type/role checked;
9. mismatch is S0 `CONTRACT_ERROR`, never an S1 absence outcome.

A component with an unregistered implementation digest, undeclared input,
undeclared transformation, incomplete population rule, or unauthorized
membership decision cannot be used or frozen.

## 7. Supporting registries, exact population and behavior

## 22. Filter-reference coverage and authorization linkage

Every `operand.kind=reference` creates exactly one root filter-reference unit.
The postprocess operation depends on it. Its reference use, population contract
and authorization authority must be the same objects.

`reference-authority` basis with a non-reference operand is invalid. Therefore
no hidden authority population can affect runtime membership outside coverage.

## 23. Optionality and non-vacuity

Every selector has mandatory resolve and selector-postprocess operations;
union additionally has mandatory child and union-compose operations. Required
source-defined entries add source-entry and source-entry-resolve units.
Therefore `required_units` is never empty.

Optional resolver inputs and optional source entries are provenance-only. They
cannot add, remove or alter candidates, identity values, filter facts or
ordering values. A runtime resolver cannot decide optionality. Any optional
input that changes those values is `CONTRACT_ERROR` and prevents freeze.

## 27. Single roadmap authority and B4 traceability

The only top-level roadmap numbering is:

```text
B0 reopen v2.5A canonical closure
B1 model contracts and inventories
B2 validator plus negative/adversarial tests
B3 one canonical v2.5B amendment
B4 complete and canonicalize 488 traceability IDs
B5 refreeze, projection, manifests and independent audit
B6 runtime rebuild; revalidate I1/I2; rebuild I3/I4
B7 I5 redesign
```

`B1.1`, `B1.2`, ... are work packages inside B1, not competing top-level
roadmap stages. B1.2 remains unauthorized until TASK-B1.1 is independently
accepted.

## 28. Required B2 executable fixtures

These are normative requirements; v7 contains no B2 validator/runtime and
claims no executable B2 PASS.

```text
```

Executable fixtures belong to B2 only after TASK-B1.1 acceptance.

## 29. Current acceptance state

```text
B1_1A_V2_1=ACCEPT
B1_1B_V6_EXTERNAL_AUDITOR_1=REVISE
B1_1B_V6_EXTERNAL_AUDITOR_2=REVISE
B1_1B_V9_INTERNAL_CROSS_DOCUMENT_REVIEW_REQUIRED=true
B1_1B_V9_EXTERNAL_REVIEW_REQUIRED=true
B1_1B_V8_EFFECTIVE=REVISE
B1_1B_V9_ACCEPTED=false
TASK_B1_1_ACCEPTED=false
TASK_B1_2=NOT_STARTED
B1_ACCEPTANCE=false
PRIMARY_SOURCE_INPUT_AVAILABILITY=PASS
PRIMARY_SOURCE_HASH_CLOSURE=PASS
B1_6_PRIMARY_SOURCE_ADJUDICATION=PENDING
REFERENCE_REGISTRY_INSTANCE_FREEZE=B1_3
REFERENCE_ROLE_ENFORCEABILITY=BLOCKED_UNTIL_B1_3
FILTER_AUTHORIZATION_INSTANCE_FREEZE=B1_6
BEHAVIOR_CONTRACT_V3_INSTANCE_FREEZE=B1_2_B1_6
UPSTREAM_OBSERVATION_SELECTOR_FREEZE_ALLOWED=false
SELECTOR_INSTANCES_FROZEN=0/20
```

This v9 candidate and its self-review cannot accept themselves.
