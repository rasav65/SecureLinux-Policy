### 7.1 Field registry entry — schema owner B1.1b, instances B1.2

```yaml
schema: selector-field/v2
instance_owner: B1.2
field_ref: <field-id>
subject_type: <subject-type-id>
semantic_role: identity | raw-fact | source-sequence | policy-judgment
value_schema_ref: <schema-id>
domain_ref: <domain-id>
```

Every field entry has exactly one scalar instance owner, B1.2. Within one
registry snapshot every `field_ref` is unique and entries are canonical-sorted
by that key. Duplicate keys are `CONTRACT_ERROR` before any lookup.

### 7.2 Resolver registry entry — schema owner B1.1b, instances B1.2

```yaml
schema: selector-resolver/v9
instance_owner: B1.2
resolver_ref: <resolver-id>
resolution_kind: host-enumeration | source-defined-enumeration |
  upstream-observation-membership | observed-event-stream |
  network-scope-enumeration
output_subject_type: <subject-type-id>
output_contract_ref: selector-raw-candidate-population/v1
behavior_contract_ref: <behavior-contract-id>
input_slots: [<closed input-slot>, ...]
output_field_refs: [<field-ref>, ...]
enumeration_domain_ref: <domain-id | null>
enumeration_source_slot_ref: <slot-id | null>
enumeration_operator_kind: <operator-kind | null>
```

`adapter-enumeration` is NOT a resolver registry kind. It is represented only
by `AdapterRegistryEntry` §7.3 so its finite source population, source type,
source domain and `emit-population-elements` obligation cannot be bypassed.

Each slot contains `slot_ref`, `input_role`, `requirement`, value shape/schema,
nullable element/subject/domain metadata plus nullable enumeration domain and
operator fields. `input_slots.slot_ref` and `output_field_refs` are unique and
canonical-sorted.

For `host-enumeration`, all three enumeration fields are non-null. The named
`enumeration_source_slot_ref` MUST identify exactly one required slot in
`input_slots`; the slot's non-null `enumeration_domain_ref` and
`enumeration_operator_kind` MUST equal the resolver fields. Every other resolver
kind has all three enumeration fields null. Missing slot, duplicate slot,
unsorted slot list, or unequal domain/operator is `CONTRACT_ERROR`.

Every resolver entry has exactly one scalar instance owner, B1.2. Within one
registry snapshot every `resolver_ref` is unique and entries are
canonical-sorted by `resolver_ref`.

### 7.3 Adapter registry entry — schema owner B1.1b, one instance owner B1.2 or B1.6

```yaml
schema: selector-adapter/v5
instance_owner: <B1.2 | B1.6>
adapter_ref: <adapter-id>
resolution_kind: adapter-enumeration
output_subject_type: <subject-type-id>
output_contract_ref: selector-raw-candidate-population/v1
behavior_contract_ref: <behavior-contract-id>
input_slots: [<closed input-slot>, ...]
output_field_refs: [<field-ref>, ...]
enumeration_domain_refs: [<domain-id>, ...]
enumeration_domain_ref: <domain-id>
enumeration_source_slot_ref: <required adapter-source slot-id>
enumeration_operator_kind: emit-population-elements
source_population_contract_ref: <finite adapter-source population contract>
source_element_schema_ref: <schema-id>
source_subject_type: <subject-type-id>
source_domain_ref: <domain-id>
```

Each adapter entry declares exactly one scalar instance owner, either B1.2 or
B1.6. The selected owner is the literal value of `instance_owner`; arrays,
multiple owners and implicit ownership are invalid.

The named source slot MUST exist exactly once, be `required`, have
`input_role=adapter-source`, `target.kind=adapter-population`, and repeat the
adapter reference plus source population contract, element schema, subject,
domain, enumeration domain and `emit-population-elements` operator exactly.
`enumeration_domain_ref` MUST occur in non-empty `enumeration_domain_refs`.
Adapter input slots and output fields are canonical-sorted by their key.

An adapter may not run a hidden query: the complete finite snapshot population
is the registered value bound to that adapter-source slot and its digest appears
in the trace.

Within one registry snapshot every `adapter_ref` is unique and entries are
canonical-sorted by `adapter_ref`.

### 7.4 Exact input-value interface, use-site linkage and owner matrix

```yaml
schema: selector-input-value/v5
instance_owner: <B1.2 | B1.3 | B1.6>
value_ref: <value-ref>
input_role: authority | reference | root | source | scope | adapter-source |
  producer-output | event-source | network-scope
value_shape: scalar | set | object | population | stream
value_schema_ref: <schema-id>
element_schema_ref: <schema-id | null>
subject_type: <subject-type-id | null>
domain_ref: <domain-id | null>
enumeration_domain_refs: [<domain-id>, ...]
target: <closed target variant>
```

`InputValueRegistryEntry` structurally enforces the `input_role × target.kind ×
instance_owner` matrix. Invalid combinations fail schema admission; they are not
deferred to an implicit runtime default.

| input_role | target.kind | required instance owner | exact rule |
|---|---|---|---|
| root | root | B1.2 | equals root registry metadata and domain list |
| source | selector-source-set | B1.6 | shape=object, schema=`selector-source-set/v5` |
| adapter-source | adapter-population | B1.6 | shape=population; equals adapter source fields |
| producer-output | producer-output | B1.2 | equals producer output schema/subject/domain |
| event-source | event-source | B1.6 | shape=stream; equals event-source registry metadata |
| scope, network-scope | reference-use | B1.3 | shape=population; role=`scope-authority` |
| authority | reference-use | B1.3 | shape=population; role membership/type/inventory |
| reference | reference-use | B1.3 | shape=population; role membership/type/inventory |

A `ReferenceUse` repeats `reference_ref`, `reference_role`, population contract,
subject, element schema and domain. For scope/network-scope the role MUST be
`scope-authority`; for authority/reference it MUST be one of
`membership-authority`, `type-registry`, `inventory`. `compliance-policy` is not
representable.

Binding repeats value metadata plus nullable enumeration domain/operator.
For every resolver or adapter instance:

- every required `InputSlot` has exactly one `Binding` with the same `slot_ref`;
- every optional slot has zero or one binding;
- no binding names an absent slot;
- `Slot ↔ Binding` equality is exact on role, value shape/schema, element
  schema, subject, domain, enumeration domain and enumeration operator;
- `Binding.value_ref` resolves exactly one `InputValueRegistryEntry`;
- `Binding ↔ Value` equality is exact on role, value shape/schema, element
  schema, subject and domain;
- a non-null binding enumeration domain MUST occur in the value entry's
  `enumeration_domain_refs`;
- all slot and binding arrays are canonical-sorted by `slot_ref`.

`enumeration_domain_refs` MAY be empty on input-value and root registry entries
when the value is not enumerated by the current contract. It is non-empty on an
adapter registry because adapter-enumeration always declares a finite source
domain. This asymmetry is intentional.

There is no separate undefined “config use” concept. The only M6.1 use-sites
are closed `InputSlot`, `Binding`, `ReferenceUse`, `ProducerUse` and target
records described here.

Every registry key is unique within one registry snapshot: `value_ref`,
`resolver_ref`, `adapter_ref`, `field_ref`, `reference_ref`,
`population_contract_ref`, `root_ref`, and `event_source_ref`. Duplicate key
values are `CONTRACT_ERROR` before lookup, even if the duplicate records are
byte-identical. Registry arrays are canonical-sorted by their key.

Embedded `InputSlot`, `Binding`, `ReferenceUse` and `ProducerUse` objects have
no independent instance owner; they inherit the scalar owner of their containing
registry/contract instance. `RootInputRegistryEntry` is B1.2 and
`EventSourceRegistryEntry` is B1.6. An `AdapterRegistryEntry` chooses exactly
one scalar owner B1.2 or B1.6.

### 7.9 Reference registry and exact reference use — owner B1.3

```yaml
schema: selector-reference/v2
instance_owner: B1.3
reference_ref: <reference-id>
reference_role: membership-authority | scope-authority | type-registry | inventory
output_subject_type: <subject-type-id>
element_schema_ref: <schema-id>
domain_ref: <domain-id>
population_contract_ref: <population-contract-id>
```

The corresponding `ReferenceUse` is:

```yaml
reference_ref: <reference-id>
reference_role: membership-authority | scope-authority | type-registry | inventory
population_contract_ref: <population-contract-id>
expected_output_subject_type: <subject-type-id>
expected_element_schema_ref: <schema-id>
expected_domain_ref: <domain-id>
```

Every use repeats and equals the registry role, subject, element schema, domain
and population contract. The referenced `PopulationContract` repeats the same
`reference_ref`, `reference_role`, subject, element schema and domain and uses
extensional-set membership. A mismatch at any use-site is `CONTRACT_ERROR`.

`compliance-policy` is outside selector population references and is not
representable by `ReferenceRegistryEntry`, `ReferenceUse`, or
`PopulationContract`.

Within one registry snapshot `reference_ref` and `population_contract_ref` are
individually unique and canonical-sorted.
