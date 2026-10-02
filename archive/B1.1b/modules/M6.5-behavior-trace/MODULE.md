### 7.8 Closed execution trace — B2 evidence interface

```yaml
schema: selector-component-behavior-trace/v1
behavior_contract_ref: <id>
implementation_digest_sha256: <sha256>
operation_graph_digest_sha256: <sha256>
input_snapshot_digest_sha256: <sha256>
operation_traces: [<closed tagged trace in exact operation order>, ...]
final_population_digest_sha256: <sha256>
complete: true
```

Enumeration trace binds domain, source-value and emitted-population digests and
member count. Each pure transformation has its own tagged trace variant with
the same named arity as its operation record: unary operations have one
`input_binding`, and path composition has one `base_input_binding` plus ordered
segment bindings. Each binds the exact operation-record digest, its single
output field and value digest. Membership trace binds predicate and authorization digests,
input/output population digests and a canonical decision record for every
candidate identity. Trace operation refs/kinds/order equal the behavior graph;
no missing or extra trace is valid.

B1.1b defines this interface only. B2 must execute the registered digest and
validate graph/trace equality with positive and counterexample fixtures. A
self-declaration or JSON Schema alone is not behavioral proof.

