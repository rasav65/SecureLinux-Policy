## 13. Collision-free structured unit identity

No string concatenation is used. Root operations use `use_site=operation` and
local refs `resolve|union-compose|selector-postprocess`. Per-entry operations
use `use_site=source-entry-resolve` and `local_ref=entry_ref`. Other unit kinds
retain exact resolver-slot, intrinsic-reference, source-entry and
filter-operand use-sites.

All unit IDs contain selector ref, node path, unit kind, use site and local ref.
IDs are unique. Node paths use section-5 sequence order. Canonical unit order is
node path, unit-kind ordinal, use-site string, then local-ref string.

## 14. Required units, lifecycle, carriers and deterministic DAG

Completed root/per-entry operation units carry `candidate_targets`. Exact
carrier matrix:

```text
ordinary resolve completed/error       -> produced raw candidates
source-entry-resolve completed/error    -> candidates from that entry only
source-defined root resolve             -> [] always
union-compose completed/error            -> [] always
selector-postprocess completed           -> final targets
selector-postprocess filters error        -> []
selector-postprocess dedup/order error     -> exact Stage-2 survivors
```

A completed source-entry unit carries only `source_items`. An incomplete
source-entry unit carries all successfully discovered source items; `missing`
has `source_items=[]`. No other non-operation unit carries source items or
candidates. Thus source material and RawCandidates have separate, exact carrier
types.

Not-attempted units contain exact incomplete complete-required blockers and the
sorted unique transitive terminal reason union. Every chain terminates at
missing/unavailable/error. An evidence dependency is ready when its source-entry
is completed, or terminal unavailable/error with non-empty source items. It is
blocked for missing or an empty terminal carrier. Root operations never treat
evidence readiness as coverage completeness. Operation units are never
missing/unavailable.

Evaluation executes every dependency-ready unit in canonical order; an error
never skips an independent ready unit. After no unit is ready, all blocked
units and causal links are materialized. Execution short-circuit order cannot
alter coverage, reasons, source evidence or candidates.

## 15. Exact required-unit formulas

Every selector has one root postprocess depending on the root resolution and
all filter-reference units. Every non-union node has a root resolve operation.
Required resolver bindings create resolver-input units; intrinsic references
create their exact use-site unit.

For `source-defined-enumeration`, each required source entry creates:

1. one source-entry unit depending on its exact input population dependencies;
2. one source-entry-resolve operation with that source-entry as its sole
   evidence dependency and all required resolver inputs/scope as
   complete-required dependencies;
3. one aggregation-only root resolve depending exactly on every required
   source-entry unit and every source-entry-resolve operation.

Optional entries are provenance-only and cannot alter membership, identity,
filter facts or ordering. Filename-marker entry dependencies are included in
the DAG and must be acyclic.

Other per-kind formulas remain exact: host/adapter use required resolver slots plus one enumeration-domain use and one enumerate-domain operation;
reference-membership uses its intrinsic membership population; upstream uses
required slots plus producer output; event-stream uses required slots plus
event-type and scope; network-scope uses required slots plus scope. Union
compose depends on immediate child root resolve operations and carries `[]`.

Every runtime dependency capable of changing authoritative enumeration is
either immutable S0 identity or a mandatory coverage unit. No hidden input is
permitted.

## 16. Coverage object and total outcome decision

```yaml
coverage:
  required_units: [<required-unit>, ...]
  completed_units: [<completed-unit variant>, ...]
  incomplete_units: [<incomplete-unit variant>, ...]
  complete: true | false
```

Invariants:

```text
every required unit appears exactly once in completed or incomplete
completed and incomplete are disjoint
complete=true iff incomplete_units=[]
all arrays canonical-unit sorted
```

After S0 validation and final coverage, first matching rule wins:

| Priority | Condition | Result |
|---:|---|---|
| 0 | schema/identity/registry/invariant violation | `CONTRACT_ERROR` outside S1 |
| 1 | any incomplete unit has `state=error` | `ERROR` |
| 2 | complete and postprocess final targets non-empty | `RESOLVED` |
| 3 | complete and postprocess final targets empty | `RESOLVED_EMPTY` |
| 4 | incomplete and completed_units non-empty | `PARTIAL` |
| 5 | completed_units empty and any terminal cause is `missing` | `MISSING` |
| 6 | completed_units empty, no missing, and any terminal cause is `unavailable` | `UNAVAILABLE` |
| 7 | otherwise | `CONTRACT_ERROR` |

`terminal cause` means an incomplete unit reachable by zero or more
`blocked_by_unit_ids` edges whose state is exactly
`missing|unavailable|error`. This definition is machine-computable.

An all-missing union with no independently completed filter-reference unit
leaves child resolve operations, union-compose and postprocess not-attempted;
`completed_units=[]`; result `MISSING`. If another mandatory unit completed,
B1.1a requires `PARTIAL` instead.

Any completed mandatory unit with incomplete coverage and no error yields
`PARTIAL`.

For incomplete coverage:

```text
coverage_reason_codes = sorted unique union(incomplete_units.reason_codes)
```

Top-level PARTIAL/MISSING/UNAVAILABLE/ERROR reasons equal this exact non-empty
list.

## 21. B1.1a-compatible result payloads

Every S1 result has exactly outcome, targets, coverage and reason codes;
`ERROR` additionally has deterministic diagnostics.

`RESOLVED` and `RESOLVED_EMPTY` require complete coverage and completed
postprocess. `MISSING` and `UNAVAILABLE` have empty targets.

`PARTIAL.targets` is the canonical-byte-sorted multiset of RawCandidates from
all completed candidate-producing operations: ordinary resolve and
source-entry-resolve. Source-defined aggregation and union-compose contribute
none. Filters, deduplication and final ordering are not applied. These targets
are evidence-only and cannot yield a policy conclusion.

`ERROR.targets=[]`. Diagnostics are derived from final coverage only:

```text
raw_candidates = candidates from all completed/error candidate-producing ops
post_filter_candidates = candidates from error postprocess only at dedup/order
completed_unit_ids = completed coverage IDs
error_unit_ids = incomplete state=error IDs
blocked_unit_ids = incomplete state=not-attempted IDs
source_items = source items from completed/error source-entry units
```

All arrays use their declared canonical order. There is no temporal boundary.
Successful sibling source items and candidates survive PARTIAL, source-entry
error and union-compose error without duplication.

