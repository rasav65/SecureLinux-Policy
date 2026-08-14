## 8. Closed selector envelope

```yaml
selector_contract:
  schema: selector-contract/v2.5B-b1-v9
  selector_ref: <selector-id>
  source_statement_ref: <section-6 object | null>
  subject_type: <subject-type-id>
  resolution: <section-9 tagged resolution>
  filters: [<section-11 filter>, ...]
  identity:
    fields: [<field-ref>, ...]
    duplicate_policy: reject-conflicting-duplicates
  ordering: <section-20 ordering>
  outcome_contract: selector-resolution-outcome/v1
```

All top-level keys are required; optional keys: none.

Identity fields are non-empty and unique. Every selector has one immutable
resolution identity:

```text
(evaluation_snapshot_id, record_id, selector_ref)
```

`selector_ref` is the exact v2.5B representation of the logical
`selector_id` named by B1.1a; two independent identifiers are forbidden.

All consumers in one snapshot use that same result.

## 9. Exact resolution kinds and per-kind configs

Allowed `resolution.kind` values exactly:

```text
host-enumeration
adapter-enumeration
reference-membership
source-defined-enumeration
union
upstream-observation-membership
observed-event-stream
network-scope-enumeration
```

Binding object, used by resolver-backed kinds:

```yaml
slot_ref: <slot-id>
value_ref: <value-ref>
input_role: <section-7.4 role>
value_shape: <section-7.4 shape>
value_schema_ref: <schema-id>
element_schema_ref: <schema-id | null>
subject_type: <subject-type-id | null>
domain_ref: <domain-id | null>
  enumeration_domain_ref: <enumeration-domain-id | null>
  enumeration_operator_kind: <operator-kind | null>
```

Bindings are unique by `slot_ref`, sorted by `slot_ref`, contain each required
slot exactly once and each optional slot zero or one time.

### 9.1 `host-enumeration`

```yaml
kind: host-enumeration
config:
  resolver_ref: <resolver-id>
  enumeration_domain_use:
    enumeration_domain_ref: <domain-id>
    source_slot_ref: <required root slot-id>
    source_value_ref: <bound value-id>
    operator_kind: <exact domain operator kind>
  input_bindings: [<binding>, ...]
```

### 9.2 `adapter-enumeration`

```yaml
kind: adapter-enumeration
config:
  resolver_ref: <resolver-id>
  adapter_ref: <adapter-id>
  enumeration_domain_use:
    enumeration_domain_ref: <domain-id>
    source_slot_ref: <required adapter-source slot-id>
    source_value_ref: <bound finite population value-id>
    operator_kind: emit-population-elements
  input_bindings: [<binding>, ...]
```

Adapter output subject and output contract must equal resolver and selector
values. Runtime adapter availability must be represented by a required
`adapter-source` resolver slot; `adapter_ref` itself is S0 identity. Domain use, resolver v7, adapter v4, behavior v3 and the exact binding must agree.

### 9.3 `reference-membership`

```yaml
kind: reference-membership
config:
  membership_use: <exact reference use>
```

Rules:

```text
reference role != compliance-policy
population cardinality = zero-or-more
expected_output_subject_type = selector.subject_type
```

No resolver is present.

### 9.4 `source-defined-enumeration`

```yaml
kind: source-defined-enumeration
config:
  source_set_ref: <source-set-id>
  resolver_ref: <resolver-id>
  scope_use: <exact reference use | null>
  input_bindings: [<binding>, ...]
```

If non-null, `scope_use` requires reference role `scope-authority` and
population cardinality `zero-or-more`.

### 9.5 `union`

```yaml
kind: union
config:
  members:
    - node_ref: <id>
      resolution: <one non-union resolution>
```

Rules:

```text
members length >= 2
node_ref unique
members canonical-sorted by node_ref
nested union forbidden
child node_path = parent node_path + [node_ref]
```

### 9.6 `upstream-observation-membership`

```yaml
kind: upstream-observation-membership
config:
  resolver_ref: <resolver-id>
  producer_use:
    producer_record_ref: <record-id>
    producer_output_ref: <output-id>
    producer_output_schema_ref: <schema-id>
    producer_subject_type: <subject-type-id>
    snapshot_relation: same-evaluation-snapshot
  input_bindings: [<binding>, ...]
```

The producer-output binding must use the same record/output/schema/subject and
snapshot relation. Freeze prerequisites are in section 25.

### 9.7 `observed-event-stream`

```yaml
kind: observed-event-stream
config:
  resolver_ref: <resolver-id>
  event_type_use: <exact reference use>
  scope_use: <exact reference use>
  input_bindings: [<binding>, ...]
```

`event_type_use` role is `type-registry`; `scope_use` role is
`scope-authority`; both cardinalities are `zero-or-more`.

### 9.8 `network-scope-enumeration`

```yaml
kind: network-scope-enumeration
config:
  resolver_ref: <resolver-id>
  scope_use: <exact reference use>
  input_bindings: [<binding>, ...]
```

`scope_use` role is `scope-authority` and cardinality is `zero-or-more`.

## 24. Historical resolution-kind migration

```text
source-path-family
  -> source-defined-enumeration + selector-source-set/v5

observed-finding-set
  -> retired; Configuration 6.1 uses raw source-defined candidates

source-filename-class-with-system-scope
  -> source-defined-enumeration + filename-marker + typed scope_use
```

No aliases are accepted.

## 25. Upstream-observation freeze gate

Before an `upstream-observation-membership` instance freezes, all must freeze:

```text
producer record/output identity
typed producer output schema and subject type
producer evaluation ordering
provenance semantics
freshness semantics
dependency cycle detection
UNKNOWN propagation
ERROR propagation
same-snapshot consistency across producer and consumer
```

Owners:

```text
B1.2 -> producer output, field and subject contracts
B1.6 -> concrete producer-consumer adjudication and cycle proof
```

Until then:

```text
UPSTREAM_OBSERVATION_SELECTOR_FREEZE_ALLOWED=false
```

## 26. Exact 20 selector identities to candidate kinds

This table accounts for the complete current set of records carrying
`selector_semantics`. It assigns candidate kinds only; it does not freeze an
instance.

| # | Record | `selector_ref` | Candidate kind | Status |
|---:|---|---|---|---|
| 1 | FSTEC-2022-2.1.1 | sel-fstec-2022-2-1-1 | host-enumeration | NOT_FROZEN |
| 2 | FSTEC-2022-2.3.10 | sel-fstec-2022-2-3-10 | source-defined-enumeration | NOT_FROZEN |
| 3 | FSTEC-2022-2.3.11 | sel-fstec-2022-2-3-11 | host-enumeration | NOT_FROZEN |
| 4 | FSTEC-2022-2.3.2 | sel-fstec-2022-2-3-2 | host-enumeration | NOT_FROZEN |
| 5 | FSTEC-2022-2.3.3 | sel-fstec-2022-2-3-3 | host-enumeration | NOT_FROZEN |
| 6 | FSTEC-2022-2.3.4 | sel-fstec-2022-2-3-4 | host-enumeration | NOT_FROZEN |
| 7 | FSTEC-2022-2.3.5 | sel-fstec-2022-2-3-5 | union(source-defined-enumeration, adapter-enumeration) | NOT_FROZEN |
| 8 | FSTEC-2022-2.3.6 | sel-fstec-2022-2-3-6 | source-defined-enumeration | NOT_FROZEN |
| 9 | FSTEC-2022-2.3.7 | sel-fstec-2022-2-3-7 | host-enumeration | NOT_FROZEN |
| 10 | FSTEC-2022-2.3.9 | sel-fstec-2022-2-3-9 | host-enumeration | NOT_FROZEN |
| 11 | FSTEC-CONFIGURATION-2026-1.3-PRIVILEGED-2FA | sel-fstec-configuration-2026-1-3-privileged-2fa | reference-membership | NOT_FROZEN |
| 12 | FSTEC-CONFIGURATION-2026-12.1-DISABLE-UNUSED-ACCOUNTS | sel-fstec-configuration-2026-12-1-disable-unused-accounts | reference-membership | NOT_FROZEN |
| 13 | FSTEC-CONFIGURATION-2026-2.1-DB-AUTHENTICATION | sel-fstec-configuration-2026-2-1-db-authentication | adapter-enumeration | NOT_FROZEN |
| 14 | FSTEC-CONFIGURATION-2026-2.2-DB-GUEST-ACCOUNTS | sel-fstec-configuration-2026-2-2-db-guest-accounts | adapter-enumeration | NOT_FROZEN / B1.6-kind-recheck |
| 15 | FSTEC-CONFIGURATION-2026-3.4-SMB1-LEGACY-DEVICE | sel-fstec-configuration-2026-3-4-smb1-legacy-device | upstream-observation-membership | NOT_FROZEN / upstream-gate |
| 16 | FSTEC-CONFIGURATION-2026-6.1-PLAINTEXT-CREDENTIALS | sel-fstec-configuration-2026-6-1-plaintext-credentials | source-defined-enumeration | NOT_FROZEN |
| 17 | FSTEC-CONFIGURATION-2026-6.3-SCRIPT-CREDENTIALS | sel-fstec-configuration-2026-6-3-script-credentials | reference-membership | NOT_FROZEN |
| 18 | FSTEC-LOGGING-2025-3 | sel-fstec-logging-2025-3 | observed-event-stream | NOT_FROZEN |
| 19 | FSTEC-PERIMETER-2026-1-5 | sel-fstec-perimeter-2026-1-5 | network-scope-enumeration candidate IF identity retained | MODEL_DECISION_OPEN |
| 20 | FSTEC-PERIMETER-2026-1-8 | sel-fstec-perimeter-2026-1-8 | network-scope-enumeration | NOT_FROZEN |

```text
SELECTOR_IDENTITIES_ACCOUNTED=20/20
UNCONDITIONAL_KIND_ASSIGNMENTS=19/20
MODEL_DECISION_OPEN=1/20
SELECTOR_INSTANCES_FROZEN=0/20
```

