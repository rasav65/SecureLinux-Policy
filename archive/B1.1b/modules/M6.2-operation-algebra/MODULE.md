### 7.7 Behavior contract and exact operation algebra — owner B1.1b

```yaml
schema: selector-component-behavior/v3
behavior_contract_ref: <id>
component_kind: resolver | adapter
component_ref: <registry-id>
resolution_kind: <one resolver-backed kind>
implementation_digest_sha256: <sha256>
input_slot_refs: [<slot-id>, ...]
input_population_mode: <section-7.6 value>
enumeration_domain_ref: <id | null>
enumeration_source_slot_ref: <slot-id | null>
enumeration_operator_kind: <operator-kind | null>
output_contract_ref: selector-raw-candidate-population/v1
output_subject_type: <subject-type-id>
output_field_refs: [<field-id>, ...]
population_completeness: extensional-exact | snapshot-exact
operation_graph_digest_sha256: <sha256>
operation_records: [<closed tagged record>, ...]
trace_schema_ref: selector-component-behavior-trace/v1
hidden_input_refs: []
unregistered_input_reads: false
unregistered_candidate_suppression: false
```

Registry, behavior and use-site interfaces are equal. Host/adapter records
start with exactly one `enumerate-domain` record; non-enumerating kinds forbid
that record. The remaining record variants are:

```text
enumerate-domain: one domain + one source slot -> one raw-member population
copy: one named input -> one named output field
typed-parse: one named input + one target schema -> one named output field
nfc-normalize: one named string input -> one named output field
lexical-path-compose: one named base + ordered non-empty named segments -> one output
basename-extract: one named path input -> one named output field
source-sequence-attach: one named sequence input -> one named output field
membership-decision: one named input population + one exact predicate
  (field, operator, operand) + one exact authorization -> one named output population
```

There are no generic multi-input/multi-output arrays. Every transformation has
one output field; path composition has named base/segment roles and one output.
Thus `[a,b] -> [x,y]` cannot mean two mappings. A membership record has no
field output, has one named input-population and one named output-population,
and carries its complete `Filter` plus matching
`FilterAuthorization`; filter ref, field, operator, canonical operand digest,
schema/domain, source clause or reference population and authorization ref
must all be equal. Its candidate source is one explicit earlier operation.
`include-on-match` retains exactly candidates for which the predicate is true;
`exclude-on-match` removes exactly those candidates and retains every false
candidate. Each input candidate is evaluated once and appears at most once in
the named output population before the global section-19 pipeline.

Exact pure-operation semantics:

```text
copy                    output canonical typed bytes equal input bytes
typed-parse             parse the one string with the exact target-schema grammar;
                        failure is CONTRACT_ERROR; no fallback/coercion
nfc-normalize           output is Unicode NFC(input), once
lexical-path-compose    base is absolute; segments are non-empty single path
                        components excluding slash, dot and dot-dot; output is
                        base + one slash + ordered segments (root handled once),
                        with no normalization or filesystem resolution
basename-extract        last non-empty lexical component; root has no basename
source-sequence-attach  copy the one declared signed-64 source ordinal exactly
```

A `typed-parse.target_schema_ref` must resolve to a B1.2 value-schema entry
that defines one canonical lexical grammar and canonical output bytes. A schema
without that grammar cannot be used by this operation or frozen.

Operation records are the normative total order. Refs are unique; every
predecessor is earlier; every operation output input names its predecessor and
single output field. Every required slot is consumed, every declared field has
exactly one producer, and membership records are the only behavior-level
population changes. The graph digest is SHA-256 of section-5 canonical JSON of
the complete ordered array. Hidden operations, inputs, output writes,
enumeration, suppression or membership changes are `CONTRACT_ERROR`.

The enumeration output, or the one bound population for a non-enumerating
mode, is the initial active population. Pure operations map over every active
member in order, add their single field and never alter membership or order.
A membership record's `input_population_ref` must equal the current active
population; its named output becomes the next active population. Reading an
older population after a membership decision is `CONTRACT_ERROR`.

