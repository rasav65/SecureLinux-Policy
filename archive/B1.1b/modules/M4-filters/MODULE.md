## 11. Closed filters and exact operator semantics

`filters` is required and may be empty.

```text
filters=[] -> no additional membership filtering
non-empty filters -> logical AND
filter_ref unique
filters canonical-sorted by filter_ref
```

Semantic duplicate tuple:

```text
(field_ref, operator, canonical operand bytes, authorization_ref)
```

Duplicate semantic tuples are `CONTRACT_ERROR` even if `filter_ref` differs.

Filter variants are exact tagged objects with common keys:

```yaml
filter_ref: <id>
field_ref: <field-ref>
operator: <closed operator>
authorization_ref: <authorization-id>
operand: <closed operand>
```

### 11.1 Operands

None:

```yaml
kind: none
```

Literal:

```yaml
kind: literal
value: <typed literal>
```

Reference population:

```yaml
kind: reference
use: <exact section-7.7 reference use>
```

### 11.2 Allowed combinations

| Operator | Operand | Exact rule |
|---|---|---|
| `exists` | `none` | true iff field state is `present` |
| `eq` | scalar literal | present field and type-strict canonical value equality |
| `ne` | scalar literal | present field and type-strict canonical value inequality |
| `in` | non-empty set literal or reference | present scalar field is a member |
| `not-in` | non-empty set literal or reference | present scalar field is not a member |
| `bit-set` | positive integer literal | present non-negative integer field and `(field & mask) == mask` |

For all operators except `exists`, absent field state evaluates to false. No
coercion, case folding, default value, path resolution or truthiness exists.

Reference operands are allowed only for `in/not-in`; population cardinality
must be `zero-or-more`; subject/schema/domain must match the field and
authorization.

`matches` remains removed in v7 because v5 had no frozen dialect, anchoring,
Unicode or case semantics and no selector instance is frozen. A future pattern
operator requires a new schema version and exact pattern contract.

### 11.3 Field compatibility

Filter field role must be `identity` or `raw-fact`; `source-sequence` and
`policy-judgment` are forbidden.

```text
eq/ne: field schema == scalar literal schema
in/not-in set literal: field schema == set element schema
in/not-in reference: field schema == reference element schema
bit-set: field schema == signed-64 integer; field value >=0; mask >0
all value comparisons: authorization domain == field domain
```

For a literal operand, `operand_schema_ref` equals its literal schema ID from
section 5.3; the field comparison uses that row's element schema ID. For a
reference operand, `operand_schema_ref` equals the population element schema.

Invalid typed data is `CONTRACT_ERROR`; it is not a non-match.

## 12. Non-bypass filter authorization

Authorization envelope:

```yaml
selector_filter_authorization:
  schema: selector-filter-authorization/v4
  authorization_ref: <id>
  selector_ref: <selector-id>
  filter_ref: <filter-id>
  field_ref: <field-ref>
  field_value_schema_ref: <schema-id>
  field_domain_ref: <domain-id>
  operator: eq | ne | in | not-in | exists | bit-set
  operand_binding: <tagged binding>
  basis: <tagged basis>
```

Operand-binding variants:

```yaml
kind: none
operand_digest_sha256: <sha256 of canonical {"kind":"none"}>
```

```yaml
kind: literal
operand_digest_sha256: <sha256>
operand_schema_ref: <schema-id>
operand_domain_ref: <domain-id>
```

```yaml
kind: reference
operand_digest_sha256: <sha256>
operand_schema_ref: <element-schema-id>
operand_domain_ref: <domain-id>
reference_ref: <reference-id>
population_contract_ref: <population-contract-id>
```

Source-statement basis:

```yaml
kind: source-statement
source_statement_ref: <non-null section-6 object>
source_membership_clause_ref: <clause-id>
```

Reference-authority basis:

```yaml
kind: reference-authority
authority_ref: <reference-id>
authority_population_contract_ref: <population-contract-id>
```

Exact basis restrictions:

```text
operand none/literal    -> source-statement basis only
operand reference       -> reference-authority basis only
source-statement basis  -> selector.source_statement_ref is non-null and equals
                           basis and source-clause source_statement_ref
authority_ref           == operand.use.reference_ref
authority population    == operand.use.population_contract_ref
authority role          != compliance-policy
```

Thus a reference-authority basis cannot hide an additional runtime reference;
the same population is carried by the filter-reference unit. A source-derived
literal never requires a fake authority.

All authorization fields, operand digest/schema/domain, source clause or
population metadata must match the concrete selector/filter exactly.

Schema owner: B1.1b. Registry dependencies: B1.2/B1.3. Concrete authorization
and source-clause owner: B1.6.

