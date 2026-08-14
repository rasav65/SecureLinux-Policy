## 6. Exact source-statement value

Within this meta-contract `source_statement_ref` is the exact object:

```yaml
source_id: <id>
source_hash: <sha256>
locator: <non-empty NFC string>
statement_hash: <sha256 | null>
```

All four keys are required; unknown keys are invalid. Equality is structural
equality after primitive validation. `statement_hash=null` remains a B4/B5
traceability dependency and cannot be treated as a frozen statement identity.

## 10. Total source-set, entry, adjudication and clause semantics

### 10.1 Selector source set — schema owner B1.1b, instances B1.6

```yaml
selector_source_set:
  schema: selector-source-set/v5
  source_set_ref: <source-set-id>
  selector_ref: <selector-id>
  source_statement_ref: <non-null section-6 object>
  adjudication_ref: <source-adjudication-id>
  entries: [<closed entry>, ...]
```

Entry refs are unique and sorted. Empty entries require an adjudication with
`population_disposition=empty`. Each entry carries an exact required/optional
decision bound to the same adjudication.

Every evaluated entry emits canonical `selector-source-item/v1` objects, never
RawCandidate directly. A path item carries entry ref, ordinal, typed lexical
path, non-following lstat type and provenance ref. A value item carries entry
ref, ordinal, one typed scalar and provenance ref. Ordinals start at zero and
are contiguous in the exact order below. Provenance is non-empty and binds the
source statement, adjudication, entry and concrete input value.

Each provenance ref resolves to exactly:

```yaml
schema: selector-source-item-provenance/v1
provenance_ref: <id>
selector_ref: <selector-id>
source_set_ref: <source-set-id>
source_statement_ref: <non-null section-6 object>
adjudication_ref: <source-adjudication-id>
entry_ref: <entry-id>
input_digest_sha256: <sha256 of canonical concrete input item>
```

All fields equal the source-set, entry and concrete item. Schema owner is
B1.1b; instances are B1.6. Every candidate emitted by source-entry-resolve
contains every consumed source-item provenance ref and its behavior-contract
ref; provenance cannot be replaced by a summary ref.

### 10.2 `literal-path`

`self` performs one non-following lstat and emits the exact path if present.
`self-and-immediate-files` emits the exact root first; if it is a directory, it
then enumerates immediate entries, non-following-lstats each and emits only
regular files by canonical basename order. It never recurses or follows a
symlink.

Required root absence is `missing`; optional absence contributes nothing.
Permission/availability failure is `unavailable`; malformed or I/O/invariant
failure is `error`. Successful items discovered before terminal failure remain
on the incomplete source-entry unit.

### 10.3 `single-decimal-slot-path`

The population is exactly `prefix + one ASCII digit + suffix` for every digit
from `digit_min` through `digit_max`, ascending. Each path receives one
non-following lstat. Absence is a non-match; a required entry is `missing` only
when every candidate is absent and no stronger terminal failure occurred.
Existing paths are emitted regardless of lstat type; a directory is one path
item and its contents are not enumerated. Any unavailable/error probe makes
the entry terminal with that state while preserving all successful earlier and
independently evaluated items. Glob, regex, recursion, implicit `rcS.d` and
multi-digit grammar are forbidden.

### 10.4 `filename-marker`

This entry contains an exact `input_population` tagged use: either a required
resolver slot whose element schema is `selector-source-path/v1`, or a prior
path-producing entry in the same source set. Entry-reference dependencies are
acyclic. The complete input population is evaluated once in canonical source
item order. Matching uses the lexical basename, NFC scalar comparison and
either exact equality or suffix. No filesystem discovery occurs. Matching
items are re-emitted with this entry's provenance and contiguous ordinals.
Required empty result is `missing`; upstream unavailable/error propagates with
already matched items preserved.

### 10.5 `literal-value`

A scalar literal emits exactly one value item. A set literal emits one scalar
item per element in section-5 canonical set order. It does not emit one set
valued target. Valid literal entries cannot be missing or unavailable;
type/schema failure is S0 `CONTRACT_ERROR`.

### 10.6 Source-entry to candidate mapping

For every required entry, one `source-entry` probe/enumeration unit is followed
by one `source-entry-resolve` operation. The operation applies the exact
resolver behavior contract to only that entry's complete/partial source items.
The source-entry is an evidence dependency: the operation may run after a
terminal `unavailable|error` entry only when its `source_items` is non-empty.
It cannot run after `missing` or a terminal entry with no items. This exception
is encoded separately from complete-required dependencies. The operation is
the sole RawCandidate carrier for that entry. The source-defined root `resolve`
operation is aggregation-only and always carries `[]`; therefore no candidate
is duplicated.

If one entry succeeds and a sibling is missing/unavailable/error, successful
entry-resolve operations remain completed and their candidates appear in
PARTIAL targets or ERROR diagnostics. A blocked entry-resolve carries `[]`.

### 10.7 Selector-source adjudication and membership clause

Adjudication schema is `selector-source-adjudication/v1`; it binds selector,
source set, non-null source statement, empty/enumerated disposition and the
exact sorted entry decision set. Decision refs and requirements equal source
entries.

Membership-clause schema is `selector-source-membership-clause/v1`; it binds
clause/adjudication/selector/source statement/filter/field/operator, operand
digest, schemas, domain and concrete none/literal operand. It is the only
source-derived membership authorization. Schema owner is B1.1b; concrete
instances and primary-source adjudication are B1.6.

