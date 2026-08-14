## 17. Raw candidate, field presence and exact value linkage

Raw candidate:

```yaml
subject_type: <subject-type-id>
identity_values:
  - field_ref: <field-ref>
    value: <scalar typed literal>
filter_facts:
  - field_ref: <field-ref>
    state: present
    value: <scalar typed literal>
  - field_ref: <field-ref>
    state: absent
ordering_values:
  - field_ref: <field-ref>
    value: <scalar typed literal>
provenance_refs: [<id>, ...]
```

Each filter-fact item is one of the two exact variants; `value` is forbidden
when absent.

Rules:

```text
candidate.subject_type == selector.subject_type
identity_values field list == identity.fields exactly, including order
identity fields are always present
filter_facts field set == exactly non-identity fields used by filters
ordering_values field list == exactly non-identity ordering keys
field refs within each array unique
every present value schema/domain == field registry schema/domain
provenance_refs non-empty, unique and canonical-sorted
```

Fields used both by filter and identity are read from `identity_values`, not
duplicated in `filter_facts`. Fields used both by filter and non-identity
ordering occur once in each purpose-specific array and values must be equal.

## 18. Identity-field role constraints

For lexicographic ordering:

```text
every identity.fields entry semantic_role=identity
```

For source-order:

```text
sequence_field_ref semantic_role=source-sequence
sequence_field_ref occurs exactly once in identity.fields
all other identity.fields entries semantic_role=identity
no other source-sequence field may occur in identity.fields
```

`raw-fact` and `policy-judgment` fields cannot be identity fields. This is
checked against B1.2 field registry before instance freeze.

## 19. Normative selector pipeline

When all postprocess dependencies complete, stages execute exactly:

```text
Stage 1 RAW COLLECTION
  ordinary non-source node: collect its completed root resolve candidates;
  source-defined node: collect completed source-entry-resolve candidates and
    never its aggregation-only root resolve;
  union: recursively collect child candidate-producing operations;
  canonical-byte sort; retain duplicates.

Stage 2 FILTERS
  apply filters in filter_ref order with logical AND;
  rejected candidates do not participate in deduplication.

Stage 3 DEDUPLICATION
  group survivors by identity tuple; merge or error under section 20.

Stage 4 ORDERING
  sort deduplicated survivors by the declared total order.

Stage 5 FINAL TARGETS
  completed selector-postprocess candidates equal Stage-4 output.
```

No implementation may reorder or partially execute these stages. For
incomplete coverage postprocess is not run; PARTIAL and ERROR evidence is
derived directly from all completed/error candidate-producing operations.

## 20. Deduplication, provenance and total ordering

Identity object:

```yaml
fields: [<field-ref>, ...]
duplicate_policy: reject-conflicting-duplicates
```

Identity tuple is the canonical array of `identity_values[].value` in declared
field order. No field name, provenance or source traversal order is added.

After filtering, candidates with equal identity tuple:

```text
equal filter_facts and equal ordering_values
  -> exactly one final candidate
  -> provenance_refs = sorted unique union

different filter_facts
  -> postprocess error_stage=deduplication
  -> FILTER_FACT_CONFLICT

different ordering_values
  -> postprocess error_stage=deduplication
  -> ORDERING_VALUE_CONFLICT
```

### 20.1 Lexicographic ordering

```yaml
kind: lexicographic
keys: [<field-ref>, ...]
direction: ascending
```

Rules:

```text
keys non-empty and unique
identity.fields is exact final suffix of keys
preceding keys semantic_role=raw-fact
preceding keys occur exactly in ordering_values
all key schemas are scalar
```

Field values are compared under their frozen schema:

```text
integer -> numeric
boolean -> false before true
string/path/identifier -> canonical string order
```

All targets use the same schema for a given key, so no cross-type comparison
exists. Identity suffix makes the order total after deduplication.

### 20.2 Source ordering

```yaml
kind: source-order
sequence_field_ref: <field-ref>
tie_breaker_keys: [<field-ref>, ...]
direction: ascending
```

Rules:

```text
sequence_field_ref semantic_role=source-sequence
sequence field schema is scalar
sequence_field_ref is in identity.fields exactly once
tie_breaker_keys == identity.fields with sequence field removed, same order
ordering_values=[]
```

Different sequence values are different identities. Equal identity tuples
cannot select an arbitrary source sequence during deduplication.

