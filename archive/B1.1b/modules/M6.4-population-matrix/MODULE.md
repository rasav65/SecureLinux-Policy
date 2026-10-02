### 7.6 Exact population-mode and completeness matrix

Definitions:

```text
enumeration-domain       exactly the members emitted by one section-7.5 domain
each-required-source-entry exactly every item from each mandatory source entry
reference-population     exactly the bound B1.3 population-contract extension
producer-output          exactly the bound producer output in the same snapshot
event-stream             exactly every element of the bound finite event-source snapshot

extensional-exact        equality to a declared immutable/set/reference extension
snapshot-exact           equality to every member of the declared finite snapshot
```

These terms are relative only to registered inputs. They authorize no hidden
host discovery, query, window, default scope or filtering.

| resolution.kind | input_population_mode | population_completeness | enumeration domain |
|---|---|---|---|
| host-enumeration | enumeration-domain | extensional-exact for single/set; snapshot-exact for population/path | required |
| adapter-enumeration | enumeration-domain | snapshot-exact | required `emit-population-elements` |
| source-defined-enumeration | each-required-source-entry | extensional-exact | null |
| upstream-observation-membership | producer-output | snapshot-exact | null |
| observed-event-stream | event-stream | snapshot-exact | null |
| network-scope-enumeration | reference-population | extensional-exact | null |

`reference-membership` and `union` are intrinsic and have no behavior
contract. All other combinations are schema-invalid. `resolution_kind` is a
required behavior field, so the paired schema enforces this matrix.

