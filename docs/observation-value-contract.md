# Observation value / type contract

## Purpose

Control `expected.type` and probe `VALUE.value` are different contracts.

- `expected.type` is the semantic policy type stored in a control.
- `VALUE.value` is the JSON wire representation emitted by a probe.

The checker must not guess how a wire value becomes a semantic value.

## Current exact contracts

### sysctl — implemented

Current Gate 5 runner is sysctl-only.

| expected.type | `VALUE.value` JSON type | decoding |
|---|---|---|
| `integer` | string | Python integer parse of the string |
| `string` | string | identity |
| `boolean` | forbidden by `KIND_RULES` | none |

This preserves the factual sysctl-v1 evidence format.

### systemd-unit-state — wire format reserved, runner not implemented

When the first `systemd-unit-state` probe is implemented:

- control `expected.type` remains `boolean`;
- `VALUE.value` **MUST be a JSON boolean** (`true` / `false`, unquoted);
- strings `"true"` / `"false"` are invalid;
- numbers `0` / `1` are invalid.

The current checker still rejects this kind at Gate 5 because the runner is not
implemented. Defining the wire format does not claim executability.

### package-presence — wire format reserved, runner not implemented

When the first `package-presence` probe is implemented:

- control `expected.type` remains `boolean`;
- `VALUE.value` **MUST be a JSON boolean**;
- strings `"true"` / `"false"` are invalid;
- numbers `0` / `1` are invalid.

Again, this is a format contract, not a runner implementation.

### file-kv boolean — explicitly deferred

`file-kv` controls may have semantic boolean values, but file formats use
different textual conventions (`yes/no`, `true/false`, `on/off`, `0/1`, etc.).

Therefore no generic file-kv boolean observation coercion exists. A future
file-kv probe/adaptor must define its source-specific mapping first.

## Prohibited behavior

There is no project-wide conversion:

`"true" -> true` or `"false" -> false`

Such conversion used to exist accidentally in `_expected_compliance` and has
been removed.

## Relationship to schema

This cleanup does not change `KIND_RULES` and therefore does not change
`CONTROL-SCHEMA.json`.

- sysctl already excludes boolean;
- systemd-unit-state and package-presence remain semantic boolean kinds;
- schema generation parity must remain PASS;
- schema/runtime differential tests must remain PASS.

Any future change to `KIND_RULES` still requires schema regeneration through
`--emit-schema` and the differential suite.

## Next gate

Next roadmap stage: mandatory real-jsonschema release gate.
