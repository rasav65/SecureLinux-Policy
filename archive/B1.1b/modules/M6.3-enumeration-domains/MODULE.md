### 7.5 Closed enumeration-domain contract

```yaml
schema: selector-enumeration-domain/v1
enumeration_domain_ref: <id>
source_target: <exact root or adapter-population target>
source_value_shape: scalar | set | population
source_value_schema_ref: <schema-id>
source_element_schema_ref: <schema-id | null>
source_subject_type: <subject-type-id | null>
source_domain_ref: <domain-id | null>
operator: <one exact tagged operator>
output_element_schema_ref: <schema-id>
output_subject_type: <subject-type-id>
output_domain_ref: <domain-id>
```

Operators and exact populations:

| operator.kind | required source | exact emitted domain |
|---|---|---|
| `emit-single-value` | scalar | one member equal to the bound typed value |
| `emit-set-elements` | set | every unique set element, canonical value order |
| `emit-population-elements` | population | every member of the bound finite snapshot, canonical member-byte order |
| `emit-immediate-path-entries` | scalar absolute lexical POSIX path | every immediate directory entry, canonical full-path order |

The path operator requires `lstat-nofollow`, `recursion=false`,
`include_root=false`, and `entry_selection=all`. It performs one directory read
and non-following lstat of each immediate entry. It never recurses, follows a
symlink, applies a glob, name/type filter or hidden suppression. Root absence,
permission failure and malformed/I/O failure map through mandatory coverage to
missing, unavailable and error respectively. Mutation preventing a coherent
snapshot is error. Any recursive or filtered population requires a future
version or an explicit source-set contract; it is not an alternate execution.

Shape, schema, subject and domain metadata must equal the selected input value
and its root/adapter target. The output metadata must equal candidate input and
field-registry metadata. Domain contracts are B1.1b schema objects; concrete
instances are B1.2/B1.6. Unknown enumeration algorithms are invalid.

