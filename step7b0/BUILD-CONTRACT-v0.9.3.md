# SecureLinux-Policy v3 — Step 7B.0 Build Contract
## Errata draft v0.9.3 — targeted observer-method correction

**Status:** DRAFT v0.9.3-ERRATA  
**Scope:** architecture/design contract only; authoritative/admitted builder remains forbidden until the staged §34 admission lifecycle completes. After architectural ACCEPT and admission of the exact static prerequisite set, only a hash-frozen NON-RELEASE measurement candidate may be implemented for dependency measurement.  
**Mutation scope:** READ-ONLY only. APPLY/RESTORE are explicitly out of scope.  
**FSTEC scope:** current five controlled controls only; 344 OPEN rows are not expanded in Step 7B.0.  
**Experimental evidence ledger:** `SecureLinux-Policy-v3-Step7B0-EXPERIMENTAL-BUILDER-SPIKE-v0.2-EVIDENCE-LEDGER-20260816.md`, SHA-256 `8c8478caa3e2508cf0751ad2593941557696a0f6324eefa9c94850ba1b9c2660`.

---

## 0. Audit disposition and v0.9.3 errata scope

Build Contract v0.9.2 was independently accepted and frozen by exact byte identity. Subsequent real observer measurement and adversarial implementation audits exposed one **method defect**, not a failure of the project-path/provenance/write-boundary architecture: §18.6.1 made the first previously unknown syscall/event terminate admission analysis as FAIL, which forced iterative one-event-at-a-time policy/code changes and encouraged syscall-opcode modeling beyond the security properties Step 7B.0 actually needs to prove.

v0.9.3 is a **post-freeze errata under §34.5**. It changes only the builder dependency-observer method and the mechanically dependent item-9 schemas/references:

R4 incorporates the R1–R3 audit results and changes the **proof direction** for policy-admitted events. The R1–R3 hard-deny enumeration loop is closed by making safety depend on explicit positive admission, not on the absence of an event name from a blacklist. It remains a draft; no implementation authority follows from R4.

1. **Non-stopping `REVIEW_REQUIRED`:** an otherwise structurally decodable but not-yet-reviewed syscall/event no longer terminates parsing at first encounter. The parser must continue through the trustworthy remainder of the full trace, collect the complete review inventory, and return non-passing `REVIEW_REQUIRED`. `REVIEW_REQUIRED` never authorizes Phase A, Phase B, Phase C, Phase D, publication or authoritative status.
2. **Exactly two sources of `ADMITTED`:** an event may become `ADMITTED` only through non-overridable semantic invariant enforcement (`INVARIANT_ADMITTED`) or through one exact positively reviewed allowlist entry (`POLICY_ADMITTED`). Absence from a hard-deny list never creates admission.
3. **Fail-closed effect boundary remains:** trace loss/truncation, observer startup failure, undecodable arguments, uncertain FD/path/process attribution, parser ambiguity, known forbidden/effectful behavior, security-property violation and hard-deny events remain FAIL. Encountering a FAIL makes the run irreversibly non-passing; if the remaining trace is structurally trustworthy, parsing continues only to complete evidence/inventory.
4. **Classification policy remains hash-bound data:** exact operation-key extraction, positively reviewed safe entries and hard-deny defense-in-depth data live in one separate hash-bound Phase-A item-9 member, `build_dependency_observer_classification_policy`. Changing policy data requires item-9 re-admission/fitness and a new downstream freeze as applicable, but does not by itself require editing parser source or this Build Contract.
5. **Security-property guardrail:** observer requirements are justified by the seven exact Step-7B.0 properties in §18.6.1b. Classification-policy data cannot override those properties. An incomplete allowlist fails closed: an unlisted event remains `REVIEW_REQUIRED`.

This errata deliberately does **not** change §18.12 host-state semantics, §27 runtime-root choices, §30.2 VM semantics, the exact 16→candidate→4→Phase-D lifecycle, candidate-source immutability, `MEASUREMENT_BUILDER_PATHS`, project-root read-only requirements, external staging, FSTEC scope, emission/runtime separation or publication restrictions. §18.12 may be implemented by an aggregated perturbation campaign so long as each required pair receives the exact evidence already required by the unchanged text. §27 already permits an immutable independently reproducible digest-addressed runtime root. Generated-artifact gate implementations, including the §17.7 unsupported-target negative-test harness, remain gate-only under §19.3 rather than becoming new Phase-A prerequisite roles.

The implementation defects discovered during the v0.9.2 item-9 audit — FD attribution/declared sink enforcement, terminal process-trace closure, exact initial-interpreter binding, `observer_identity_id`, raw fitness-trace evidence and exact inventory verification — remain implementation blockers. This errata does not declare them fixed and does not weaken them.

### 0.1. Experimental evidence used as design input

The spike established, for the current five-control slice, that:

- byte-identical builds are achievable across different cwd/staging/umask;
- an isolated Python invocation can preserve exact output bytes without user-site state;
- Git/PATH dependency was real in v0.1 and removable in v0.2;
- project root can be physically read-only while output is produced externally;
- unsupported-target preflight can terminate before any `/proc/sys/` access;
- manifest/header/line-range/block hashes can be self-consistent;
- filtered runtime traces are useful evidence but **do not** satisfy either the full-syscall runtime observer or the stronger builder host-state closure required here.

The evidence ledger is informative design evidence. It is not itself a normative build input unless a later accepted lock explicitly makes it one.

### 0.2. Root contract identity

Root identity for this frozen working contract:

- `build_contract_id = step7b0-build-contract`;
- `build_contract_version = 0.9.3`.

The contract does not embed its own SHA-256.

After independent ACCEPT, the exact accepted Markdown bytes are pinned by the sidecar/admission evidence and then by the staged admission evidence and final `BUILD-INPUTS.lock`:

- final role `build_contract`, `consumption_scope=both`;
- BUILD-MANIFEST fields `build_contract_id`, `build_contract_version`, `build_contract_sha256`;
- VM evidence binding fields with the same identity.

### 0.3. Meaning of ACCEPT

`BUILD_CONTRACT_V0_9_3_ERRATA = ACCEPT` does **not** admit an authoritative builder.

It authorizes the exact staged lifecycle in §34 only:

1. create/audit the exact 16 static prerequisites;
2. only after all 16 are admitted, implement one hash-frozen NON-RELEASE measurement candidate solely for dependency/hermeticity measurement;
3. use that exact candidate SHA to create/audit the exact 4 dynamic prerequisites;
4. only after all 20 prerequisites and all final gates are admitted may a separate explicit authoritative-builder admission be considered.

Any candidate-source byte change after measurement invalidates its dynamic evidence and returns the lifecycle to measurement. The measurement candidate cannot publish, cannot be released, cannot be promoted by rename, and cannot claim authoritative status.

Architectural ACCEPT does **not** authorize publication, FSTEC expansion, real dispositions, APPLY or RESTORE.

## 1. Goal of Step 7B.0

Step 7B.0 proves one narrow, complete read-only vertical slice:

`source`
`→ source index`
`→ canonical control`
`→ existing gates`
`→ check-semantic-v1`
`→ build binding`
`→ check adapter`
`→ engineering runtime contracts`
`→ deterministic builder`
`→ external build staging`
`→ generated-artifact gates`
`→ read-only VM evidence`

The builder itself never publishes into project root. A future publication action may copy exact already-gated bytes from external staging to a release destination only under a separate accepted publication contract. Publication is not implied by build success.

Step 7B.0 uses the five already controlled FSTEC controls and must not turn any of the 344 OPEN rows into CLOSED.

Current protected state:

- source index rows: `349`;
- controlled CLOSED: `5`;
- disposed CLOSED: `0`;
- OPEN/uncovered: `344`;
- real disposition ledger data rows: `0`.

Step 7B.0 PASS requires these values to remain unchanged.

---

## 2. Normative controls versus engineering build metadata

The canonical control remains the normative source of:

- `id`;
- `layer`;
- `source.*`;
- `requirement.*`;
- `parameter.*`;
- `expected.*`;
- `apply.supported`.

The build contract does **not** put these engineering properties into
`controls/*.yaml` by default:

- adapter id;
- target id;
- emission node;
- generated block id;
- runtime CLI;
- build serialization;
- output formatting.

These belong to engineering registries/contracts unless an independent audit
later proves that one is actually control semantics.

---

## 3. Exactly two runtime origins

Every generated runtime block has exactly one `origin_type`:

- `fstec-control`;
- `engineering-contract`.

No third origin exists.

Forbidden origin aliases include:

- `template`;
- `builder`;
- `legacy`;
- `manual`;
- `misc`;
- `generated`;
- any unregistered equivalent.

### 3.1. Conditional exact schema — FSTEC origin

Required exact fields:

- `origin_type = "fstec-control"`;
- `origin_id`;
- `control_id`;
- `block_id`;
- `block_role`;
- `target_id`;
- `line_start`;
- `line_end`;
- `block_sha256`;
- `semantic_contract_id`;
- `adapter_id`;
- `adapter_contract_version`;
- `layer`;
- `index_id`;
- `doc_id`;
- `source_locator`;
- `quote_sha256`.

Invariants:

- `origin_id == control_id`;
- `block_role == "control_check"`;
- `engineering_contract_id` and `engineering_role` are forbidden;
- unknown field is forbidden.

The added source fields are a **manifest projection** of canonical
control/source identity. They do not become independent normative truth.

### 3.2. Conditional exact schema — engineering origin

Required exact fields:

- `origin_type = "engineering-contract"`;
- `origin_id`;
- `engineering_contract_id`;
- `engineering_contract_version`;
- `engineering_role`;
- `block_id`;
- `block_role`;
- `target_id`;
- `line_start`;
- `line_end`;
- `block_sha256`.

Invariants:

- `origin_id == engineering_contract_id`;
- `(engineering_role, engineering_contract_id,
  engineering_contract_version)` equals exactly one
  `ENGINEERING-BINDINGS.tsv` row;
- the role-to-block-role mapping is the exact mapping defined in §9;
- control-origin fields are forbidden;
- unknown field is forbidden.

The phrase “unless marked as references” is intentionally removed: an
engineering-origin record cannot carry control-origin identity fields.

## 4. First build target

First and only Step 7B.0 target:

`ubuntu-24.04-x86_64`

The target id intentionally includes:

- distribution family;
- distribution major/minor contract;
- architecture.

Target predicates:

- `/etc/os-release`: `ID=ubuntu`;
- `/etc/os-release`: `VERSION_ID=24.04`;
- architecture: `x86_64`.

A second platform requires a new accepted target contract and new VM evidence.
No wildcard target exists in v1.

---

## 5. Exact CLI and return-code contract — `cli-rc-v1`

Supported invocations:

- no arguments: run read-only policy checks;
- `--provenance`;
- `--provenance <control_id>`;
- `--build-info`;
- `--help`.

Forbidden/not present:

- `--apply`;
- `--restore`;
- `--output`;
- any mutating mode.

### 5.1. Supported process launch forms

The artifact-alone provenance guarantee applies when the script exists as a
filesystem object and is invoked in either form:

- direct path execution, for example
  `./securelinux-policy-check.sh --provenance`;
- `bash <path-to-securelinux-policy-check.sh> --provenance`.

Execution from stdin/pipe (`bash < script`, `cat script | bash`, `bash -s`)
is outside the supported interface and cannot be used as evidence for
`--provenance` self-containment.

### 5.2. Exact RC classes

`RC=0` — invocation completed successfully. For a policy run this means all
controls were observed/evaluated successfully; policy findings may still be
present and are reported through `POLICY_STATUS`.

`RC=1` — execution/observation/internal error prevented a complete honest
policy evaluation.

`RC=2` — CLI usage error: unknown option, invalid arity or missing required
argument.

`RC=3` — unsupported platform preflight.

This preserves the donor-reviewed invariant `TST-004`:
**policy noncompliance is not an execution error**.

### 5.3. Policy result is separate from RC

For a complete no-error policy run:

- `POLICY_STATUS=COMPLIANT`;
- or `POLICY_STATUS=NONCOMPLIANT`.

Both return `RC=0`.

If any observation is `NOT_FOUND` or `ERROR`, the overall policy result is
`POLICY_STATUS=UNEVALUATED` and `RC=1`.

### 5.4. Precedence

For a single invocation:

`USAGE_ERROR`
`> UNSUPPORTED_PLATFORM`
`> EXECUTION_ERROR`
`> completed policy evaluation`

Policy noncompliance does not participate in error precedence.

### 5.5. Unsupported platform

Before any FSTEC check:

- stderr contains exact machine token `UNSUPPORTED_PLATFORM`;
- RC is exactly `3`;
- no FSTEC result record is emitted;
- stdout cannot contain `POLICY_STATUS=COMPLIANT`;
- provenance/build-info/help remain available because they do not evaluate
  host policy.

## 6. Deterministic policy-output contract

No-argument policy run emits deterministic UTF-8/LF records.

Per control, in emitted execution order:

`SLP-CHECK-V1<TAB>control_id<TAB>status<TAB>value<TAB>compliance`

Allowed `status`:

- `VALUE`;
- `NOT_FOUND`;
- `ERROR`.

Allowed compliance field:

- `PASS`;
- `FAIL`;
- `NOT_FOUND`;
- `ERROR`.

For `NOT_FOUND`/`ERROR`, `value` is `-`.

Final record:

`SLP-SUMMARY-V1<TAB>TOTAL=5<TAB>PASS=n<TAB>FAIL=n<TAB>NOT_FOUND=n<TAB>ERROR=n<TAB>POLICY_STATUS=<value>`

No timestamps, localized text or unordered diagnostics are allowed in these
machine records.

Human-readable stderr details, when present, must follow an accepted
engineering formatting contract and cannot change RC semantics.

Golden byte fixtures are mandatory.

---

## 7. Eligible-control coverage closure and immutable Step 7B.0 set

Step 7B.0 uses **exactly the same five accepted controls** that existed before
this build-contract work.

The immutable membership is:

1. `FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT` → `SRC-0016`;
2. `FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT` → `SRC-0017`;
3. `FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN` → `SRC-0023`;
4. `FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID` → `SRC-0025`;
5. `FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED` → `SRC-0027`.

No replacement-by-another-five is allowed.

### 7.1. `STEP7B0-CONTROL-SET.lock`

A closed machine-readable lock must exist before Phase-B measurement-candidate implementation.

Exact fields:

- `control_set_contract_version`;
- `control_id`;
- `index_id`;
- `canonical_control_path`.

Exact constant:

`control_set_contract_version = step7b0-control-set-v1`

Exact row count: `5`.

Rows are sorted by UTF-8 bytes of `control_id`.

The five rows must correspond exactly to the five identities above and to the
canonical repository control paths.

The lock is:

- a `BUILD-INPUTS.lock` input with role `control_set_lock`;
- `consumption_scope = both`;
- hash-bound in BUILD-MANIFEST as `control_set_lock_sha256`.

### 7.2. Mechanical eligibility

The gate independently calculates controls satisfying all of:

- layer = `fstec-core`;
- canonical schema PASS;
- source row is controlled CLOSED;
- `parameter.kind = sysctl`;
- `parameter.locator = sysctl`;
- `expected.op = eq`;
- `expected.type = integer`;
- target contract accepts the adapter class;
- `apply.supported = false`.

Then all of these sets must be exactly equal:

`PINNED_CONTROL_SET_IDS`
`== MECHANICALLY_ELIGIBLE_CONTROL_IDS`
`== CHECK_BINDING_CONTROL_IDS`
`== FSTEC_EXECUTION_BLOCK_CONTROL_IDS`
`== FSTEC_MANIFEST_CONTROL_IDS`

Additionally, each pinned `control_id → index_id` relation must equal the
canonical control/source relation.

Therefore changing one original CLOSED row to OPEN and replacing it with a
different CLOSED row fails even if totals remain `349 / 5 / 344`.

### 7.3. Protected state

The following still must remain true:

- source index total `349`;
- controlled CLOSED `5`;
- disposed CLOSED `0`;
- OPEN `344`;
- real disposition ledger data rows `0`.

Count equality alone is never sufficient to prove protected membership.

## 8. Build-binding registry — `build-binding-v1`

Exact fields:

- `binding_contract_version`;
- `control_id`;
- `operation`;
- `target_id`;
- `semantic_contract_id`;
- `adapter_id`.

`emission_node_id` is intentionally **not** a binding field. Textual emission ordering is
owned by the emission-node registry; duplicating node identity in a binding
would create an unnecessary second source of truth. Runtime invocation is separately
owned by `runtime-invocation-v1`.

Exact constants for Step 7B.0:

- `binding_contract_version = build-binding-v1`;
- `operation = check`;
- `target_id = ubuntu-24.04-x86_64`;
- `semantic_contract_id = check-semantic-v1`.

Unknown or missing field is an error.

Fail-closed validation includes:

- duplicate logical binding;
- unknown control;
- control not in `STEP7B0-CONTROL-SET.lock`;
- ineligible control;
- unknown target;
- unknown semantic contract;
- unknown adapter;
- parameter-kind mismatch;
- adapter target mismatch;
- adapter semantic-contract mismatch.

### 8.1. Derived binding→block→emission-node relation

For each valid binding `B`, derive exactly:

`EXPECTED_BLOCK_ID`
`= fstec-control::<B.control_id>::check::<B.target_id>`

The emission-node registry must contain exactly one node with:

`node.block_id == EXPECTED_BLOCK_ID`

No separate binding-side node id is permitted.

The FSTEC manifest record for the binding must use the same
`EXPECTED_BLOCK_ID`.

This relation is checked independently of general set coverage.

## 9. Engineering ownership and exact emission mapping

Before Phase-B measurement-candidate implementation there must be a closed
`ENGINEERING-BINDINGS.tsv`.

Exact fields:

- `role`;
- `engineering_contract_id`;
- `contract_version`;
- `emission_kind`;
- `block_role`;
- `multiplicity`.

### 9.1. Exact role set and mapping v1

| role | emission_kind | block_role | multiplicity |
|---|---|---|---|
| `launcher` | `launcher-line` | `-` | `1` |
| `cli_rc` | `runtime-block` | `cli_rc` | `1` |
| `target_preflight` | `runtime-block` | `target_preflight` | `1` |
| `result_aggregation` | `runtime-block` | `result_aggregation` | `1` |
| `machine_output_format` | `runtime-block` | `machine_output_format` | `1` |
| `provenance_query` | `runtime-block` | `provenance_query` | `1` |
| `build_info` | `runtime-block` | `build_info` | `1` |
| `readonly_runtime` | `build-only` | `-` | `0` |
| `generated_block_framing` | `build-only` | `-` | `0` |
| `main_dispatch` | `runtime-block` | `main_dispatch` | `1` |

No other role, emission kind or block role is accepted in v1.

### 9.2. Closure rules

- every role appears exactly once in `ENGINEERING-BINDINGS.tsv`;
- every `runtime-block` row emits exactly one engineering generated block;
- every engineering generated block resolves to exactly one `runtime-block`
  row;
- `launcher` owns exactly the line-1 shebang and emits no generated block;
- `build-only` roles emit no runtime block but remain accepted build inputs;
- the `provenance_query` runtime block contains both the query implementation
  and the canonical embedded provenance data records;
- the structural preflight rule uses the single identity
  `engineering_role=target_preflight` and `block_role=target_preflight`.

Existing `ENG-001…ENG-020` are not activated automatically. A referenced
contract must be explicitly accepted for its exact role.

## 10. Launcher/shebang ownership and the only executable non-block exception

Exact launcher line v1:

`#!/bin/bash`

including LF.

It is owned by the engineering binding row `role=launcher`.

BUILD-MANIFEST contains:

- `launcher_contract_id`;
- `launcher_contract_version`;
- `launcher_line = 1`;
- `launcher_sha256`.

`launcher_sha256` hashes the exact launcher line including LF.

### 10.1. Executable-origin gate outside generated blocks

A non-empty non-comment executable line outside generated blocks is permitted
**only** when all are true:

1. it is physical line `1`;
2. it is byte-identical to `#!/bin/bash\n`;
3. it matches the accepted `launcher` engineering contract;
4. its hash equals `launcher_sha256`.

Every other executable line outside generated blocks is FAIL.

A line beginning with `#!` anywhere else is not a generic exception.

The launcher is also included in `scaffolding_sha256`; duplicate integrity
coverage is intentional.

## 11. `check-semantic-v1` is a machine contract, not a label

Before Phase-B measurement-candidate implementation, `check-semantic-v1` must exist as a separate
versioned machine-readable contract with positive, negative and golden
fixtures.

It must freeze at minimum:

- sysctl key → read-path derivation;
- input byte decoding;
- exact whitespace/newline semantics;
- exact integer lexical grammar;
- typed integer conversion;
- missing-key behavior;
- read-error behavior;
- `VALUE | NOT_FOUND | ERROR`;
- `PASS | FAIL | NOT_FOUND | ERROR`;
- equality computation.

The builder/adapter may not define these semantics independently.

### 11.1. Probe compatibility is a required pre-builder gate

The existing reference probe is evidence, but its current implementation
cannot silently become the semantics source.

Before builder code:

1. extract fixtures from current probe behavior;
2. run them against `check-semantic-v1`;
3. classify every mismatch;
4. either make the machine semantic contract intentionally preserve the probe
   behavior or revise the probe in a separately reviewed compatibility change.

No generated adapter may be written while probe semantics and
`check-semantic-v1` disagree without an explicit accepted disposition.

---

## 12. Adapter contract

Adapter identity key:

`operation × parameter.kind × target_id`

For Step 7B.0:

`check × sysctl × ubuntu-24.04-x86_64`

Each adapter contract has exact fields:

- `adapter_contract_version`;
- `adapter_id`;
- `operation`;
- `parameter_kind`;
- `target_id`;
- `semantic_contract_id`;
- implementation path/id;
- implementation SHA-256;
- input schema id/version;
- output schema id/version.

Control-specific shell implementation is forbidden.

A control supplies only canonical declarative data to the shared adapter.

### 12.1. Phase-A item 17 is one closed adapter bundle

Phase-A prerequisite item 17 is a **logical admission bundle**, not a claim that one prerequisite equals one file. Its exact member set is:

1. the accepted adapter contract bytes;
2. the exact adapter implementation regular file identified by that contract.

The adapter contract's implementation path/id/SHA-256 must equal the implementation member identity field-for-field. The implementation member must exist, be a regular non-symlink project file, and match the declared SHA-256. A missing member, additional undeclared member, mismatched path/id/hash, or implementation bytes changed without a contract identity update is FAIL.

Item 17 is admitted only when **both** members are admitted together. The two member identities count as one prerequisite item for §34 accounting but remain two independently hash-bound project-file identities. Any item-17 member with `consumption_scope in {builder,both}` is included in `MEASUREMENT_BUILDER_PATHS`.

---

## 13. Template grammar — exact and inert

Template contains **no shebang**.

Allowed lines are exactly one of:

1. empty line;
2. comment line beginning with `#` that is not a reserved generated marker,
   manifest-hash header or embedded-provenance record;
3. exact full-line placeholder:
   `{{SLP_SLOT:MANIFEST_SHA256_HEADER}}`;
4. exact full-line placeholder:
   `{{SLP_SLOT:GENERATED_BLOCKS}}`.

Both placeholders must appear exactly once.

No other `{`, `}`, placeholder name or inline placeholder is accepted.

Any non-comment shell token in template is a blocker.

### 13.1. Exact manifest-hash header placeholder bytes

The `MANIFEST_SHA256_HEADER` slot expands initially to exactly:

`# BUILD-MANIFEST-SHA256: ________________________________________________________________`

The suffix is **exactly 64 ASCII underscore bytes**.

The final header line is exactly:

`# BUILD-MANIFEST-SHA256: <64 lowercase hexadecimal bytes>`

Requirements:

- placeholder suffix length = 64 bytes;
- final hex length = 64 bytes;
- header line count is exactly one;
- replacing placeholder with final hex cannot change line count;
- a golden byte fixture covers both placeholder and final-header forms.

Therefore template cannot contain runtime logic such as function bodies,
assignments, branches, loops, `set`, `trap`, command substitutions,
redirections or external commands.

Template gate runs independently of builder.

### 13.2. Phase-A item 12 is one closed serializer/template bundle

Phase-A prerequisite item 12 is the closed bundle:

1. exact `serializer-contract-v1` bytes;
2. one exact inert template regular file satisfying §13;
3. the exact non-empty closed set of serializer/template golden fixture files enumerated by the accepted serializer contract.

The serializer contract must enumerate every template/fixture member by canonical project path and SHA-256. The Phase-A admission evidence additionally binds the serializer-contract file's own canonical path/SHA-256, so there is no self-hash field inside the serializer contract itself. Unknown extra fixture files do not become members implicitly.

Item 12 is admitted only when every declared member exists as a regular non-symlink file, every hash matches, all golden fixtures pass, and the declared member set equals the admitted member set exactly. Each builder-consumed member is an independent identity in `MEASUREMENT_BUILDER_PATHS`; gate-only fixture members remain gate-only and must not be read by the candidate.

## 14. Stable identifiers and `block_id`

All identifier components used in block ids must match:

`[A-Za-z0-9._-]+`

Colon `:` is forbidden inside every component.

No component may be empty.

### 14.1. FSTEC execution block

`block_id = fstec-control::<control_id>::check::<target_id>`

### 14.2. Engineering block

`block_id = engineering-contract::<engineering_contract_id>::<block_role>::<target_id>`

This derivation uses only stable identities.

Forbidden block-id inputs:

- sequence number;
- emitted position;
- line number;
- filesystem order;
- timestamp;
- random value.

Changing block position cannot change block id.

---

## 15. Generated block markers, parsing and hashes

Exact markers:

`# BEGIN GENERATED BLOCK <block_id>`
`# END GENERATED BLOCK <block_id>`

Both are comments and are included in block bytes.

Manifest line numbers are:

- 1-based;
- inclusive start;
- inclusive end.

`line_start` points at BEGIN marker.

`line_end` points at END marker.

`block_sha256` is SHA-256 of exact UTF-8/LF bytes from BEGIN marker through
END marker, including final LF after END marker.

CRLF is forbidden in generated artifact.

Block hash is never embedded inside the same block.

### 15.1. Marker grammar is reserved

Inside a generated block body, no line other than that block's own opening and
closing marker may match either reserved marker grammar.

Nested blocks are forbidden.

A marker for another block appearing inside a block body is FAIL, even if
manifest line ranges could otherwise make the hashes consistent.

### 15.2. Parsing authority

Verification uses both:

1. manifest-declared line ranges;
2. an independent full-script marker scan.

They must produce exactly the same non-overlapping ordered block segmentation
and the same `block_id` sequence.

A manifest range that hashes correctly but disagrees with marker scanning is
FAIL.

This prevents two conforming verifiers from disagreeing on block boundaries.

## 16. Embedded provenance must be inside the hashed provenance block

There is exactly one engineering runtime block with:

- `engineering_role = provenance_query`;
- `block_role = provenance_query`.

The same block contains the canonical embedded provenance records.

Normative provenance data outside this block is forbidden.

### 16.1. Embedded record format

Each FSTEC provenance record is a comment line inside that block:

`# SLP-PROVENANCE-V1 <canonical-json>`

The JSON object exact fields are:

- `control_id`;
- `layer`;
- `index_id`;
- `doc_id`;
- `source_locator`;
- `quote_sha256`;
- `execution_block_id`;
- `adapter_id`;
- `adapter_contract_version`;
- `target_id`.

Records are sorted by UTF-8 bytes of `control_id`.

### 16.2. Exact field-wise parity

No structural equality between different schemas is required.

For every FSTEC provenance record `E`, its manifest FSTEC block record `M`
and canonical control/source projection `C`, all of the following must hold:

- `E.control_id == M.control_id == C.control_id`;
- `E.layer == M.layer == C.layer`;
- `E.index_id == M.index_id == C.index_id`;
- `E.doc_id == M.doc_id == C.doc_id`;
- `E.source_locator == M.source_locator == C.source_locator`;
- `E.quote_sha256 == M.quote_sha256 == C.quote_sha256`;
- `E.execution_block_id == M.block_id`;
- `E.adapter_id == M.adapter_id`;
- `E.adapter_contract_version == M.adapter_contract_version`;
- `E.target_id == M.target_id`.

Any mismatch is FAIL.

### 16.3. Self-contained query, not self-authentication

`--provenance` and `--provenance <control_id>` must work using only the
generated script file under the supported launch forms.

No repository, external BUILD-MANIFEST, sidecar or network may be required to
**query** the embedded provenance.

This does **not** mean that an isolated `.sh` cryptographically authenticates
its own provenance. Independent integrity verification of a release requires
the corresponding BUILD-MANIFEST / BUILD-SHA256 and whatever trusted
admission/release checksum channel is in scope.

The contract therefore distinguishes:

- `artifact-alone provenance query`;
- `release-package provenance verification`.

## 17. Emission-order model and separate runtime invocation contract

Emission order and runtime invocation order are different semantics and have different authorities.

The emission graph answers only: **in what textual order are generated blocks laid out in the final script?**

The runtime invocation contract answers only: **in what call sequence are runtime roles/controls invoked after CLI dispatch?**

No runtime correctness claim may be inferred from the emission graph.

### 17.1. Emission node registry

Exact fields:

- `emission_order_contract_version`;
- `emission_node_id`;
- `block_id`.

Required uniqueness:

- `emission_node_id` is globally unique;
- `block_id` is globally unique in the registry;
- each `emission_node_id` resolves to exactly one row;
- each `block_id` resolves to exactly one row.

Exact-one closure:

`EMITTED_GENERATED_BLOCK_IDS == EMISSION_NODE_BLOCK_IDS`

No graph node without generated block. No generated block without graph node. Each generated block has exactly one emission node.

The launcher line is not a generated block and therefore is not an emission node.

For each FSTEC binding, §8.1 additionally requires the derived FSTEC `block_id` to resolve to exactly one emission node.

### 17.2. Emission edge registry and exact semantics

Exact fields:

- `edge_type`;
- `from_emission_node_id`;
- `to_emission_node_id`.

Allowed edge types:

- `emit_before`;
- `emit_after`;
- `emit_requires`.

Every endpoint resolves to exactly one globally unique emission node.

The three surface forms normalize to one canonical emission precedence relation `A ≺emit B`, meaning only “block A is emitted textually before block B”:

- `emit_before`, `from=A`, `to=B` → `A ≺emit B`;
- `emit_after`, `from=A`, `to=B` → `B ≺emit A`;
- `emit_requires`, `from=A`, `to=B` → `B ≺emit A`.

`emit_requires` is an emission dependency only. It is **not** a runtime call dependency.

All duplicate, contradiction and cycle checks operate on normalized `≺emit` relations.

Gate rejects:

- unknown/ambiguous endpoint;
- self-edge after normalization;
- duplicate normalized edge;
- both `A ≺emit B` and `B ≺emit A`;
- any emission cycle.

### 17.3. Deterministic emission order

Topological sort operates only on the normalized emission graph.

When multiple emission nodes are ready, tie-break is bytewise lexicographic comparison of UTF-8 `block_id`.

Locale, filesystem enumeration and hash/dict iteration are not ordering semantics.

Define `FINAL_EMISSION_BLOCK_ORDER` as that exact textual block order.

### 17.4. Textual structural preflight rule

In emitted text:

`position(engineering_role=target_preflight)`
`< position(each origin_type=fstec-control block)`

The identified block must also have `block_role=target_preflight`.

This is a structural/readability invariant only. It is not runtime-order evidence.

### 17.5. `runtime-invocation-v1`

Runtime invocation has a separate exact registry/contract.

Exact row fields:

- `runtime_contract_version`;
- `runtime_sequence`;
- `runtime_phase`;
- `block_id`;
- `control_id`.

Allowed `runtime_phase`:

- `target_preflight`;
- `control`;
- `aggregation`.

Base conditional schema:

- `control` row: `control_id` is a non-empty exact canonical control id;
- non-control row: `control_id = null`.

Every row is resolved against the final generated-block registry/manifest by exact `block_id`. Resolution is part of the schema/admission relation, not a later runtime-only check.

Required conditional cross-registry equalities:

**`runtime_phase=control`**

- resolved block `origin_type = fstec-control`;
- resolved block `origin_id == row.control_id`;
- resolved block `control_id == row.control_id`;
- resolved block `block_role = control_check`;
- resolved block `block_id == row.block_id`;
- resolved block `target_id` equals the accepted Step 7B.0 target;
- engineering-origin identity fields are forbidden by the resolved block schema.

**`runtime_phase=target_preflight`**

- `row.control_id = null`;
- resolved block `origin_type = engineering-contract`;
- resolved block `engineering_role = target_preflight`;
- resolved block `block_role = target_preflight`;
- resolved block `block_id == row.block_id`;
- its engineering contract/version equals the exact `ENGINEERING-BINDINGS.tsv` row for `target_preflight`.

**`runtime_phase=aggregation`**

- `row.control_id = null`;
- resolved block `origin_type = engineering-contract`;
- resolved block `engineering_role = result_aggregation`;
- resolved block `block_role = result_aggregation`;
- resolved block `block_id == row.block_id`;
- its engineering contract/version equals the exact `ENGINEERING-BINDINGS.tsv` row for `result_aggregation`.

Required closure:

- `runtime_sequence` is a positive integer;
- values are contiguous `1..N` with no duplicate/gap;
- every `block_id` resolves to exactly one generated runtime block;
- every runtime row uses a unique `block_id`; duplicate callable block identity is FAIL;
- exactly one `target_preflight` row exists and is sequence `1`;
- exactly one `aggregation` row exists and is sequence `N`;
- current slice has exactly five `control` rows;
- control-row IDs equal `STEP7B0-CONTROL-SET.lock` exactly once each;
- the five resolved FSTEC blocks equal the five control rows by the field-wise equalities above;
- `main_dispatch` is generated from this registry/contract, not from emission edges.

A registry that swaps two valid control `block_id` values while leaving `control_id` values in place is FAIL even if both blocks exist and later runtime tests would happen to expose the swap.

Define `FINAL_RUNTIME_INVOCATION_ORDER` as registry rows in increasing `runtime_sequence`.

There is **no required equality** between `FINAL_EMISSION_BLOCK_ORDER` and `FINAL_RUNTIME_INVOCATION_ORDER`. Any coincidental equality is not semantic authority.

### 17.6. Runtime policy-run control-flow invariant

For the no-argument policy run:

1. CLI usage is parsed;
2. `main_dispatch` invokes runtime rows in `FINAL_RUNTIME_INVOCATION_ORDER`;
3. `target_preflight` must succeed before any `control` row may be invoked;
4. each control observation emits exactly one result record;
5. aggregation follows completed control observations.

FSTEC execution blocks are definition-only until called by accepted dispatch flow.

`main_dispatch` and `target_preflight` engineering contracts must contain positive/negative call-order fixtures.

### 17.7. Unsupported-target zero-control gate

On an unsupported distro/version/architecture:

- RC must be `3`;
- token `UNSUPPORTED_PLATFORM` must be emitted;
- zero FSTEC result records are allowed;
- zero FSTEC adapter invocations are allowed;
- runtime observer must show zero artifact-process access beneath `/proc/sys/` by any canonicalized path form;
- an instrumented adapter/control-call sentinel must observe zero control calls.

The observer/path normalizer resolves `.`/`..` and symlink aliases before classification.

A script that performs any `/proc/sys/` observation and only later returns RC 3 is FAIL.

### 17.8. Supported-target runtime-order and observation evidence

On the reference supported VM, generated-artifact tests must prove:

- target preflight succeeds before first control invocation;
- observed runtime invocation sequence equals `FINAL_RUNTIME_INVOCATION_ORDER` exactly;
- each of the five controls is invoked exactly once;
- aggregation occurs only after the last control result;
- every artifact-process access beneath `/proc/sys/` is attributed to exactly one active `runtime_phase=control` row;
- the canonicalized `/proc/sys/` path for that access equals the exact sysctl observation path derived from that row's bound canonical control + accepted sysctl adapter contract;
- no `/proc/sys/` access exists outside the union of those five bound control paths;
- preflight, aggregation, CLI, provenance and build-info phases perform zero `/proc/sys/` access unless a future independently audited contract explicitly changes the rule.

Multiple low-level read-only syscalls needed to inspect one bound sysctl path may be attributed to the same control row, but each event has exactly one attribution and no event may be unattributed or multiply attributed.

This is runtime evidence independent of textual emission order. A hidden sixth `/proc/sys/` observation is FAIL even if the five required result records and runtime invocation order are otherwise correct.

## 18. `BUILD-INPUTS.lock` and closed build dependency universe

`BUILD-INPUTS.lock` is the root descriptor of declared project build inputs. It is deliberately outside its own record universe.

Exact record fields:

- `input_id`;
- `role`;
- `canonical_path`;
- `sha256`;
- `contract_version`;
- `consumption_scope`.

Allowed `consumption_scope`:

- `builder`;
- `gate`;
- `both`.

Semantics:

- `builder`: exact bytes are consumed by builder; release gates verify identity;
- `gate`: builder must not consume the file; builder dependency observer seeing it is FAIL;
- `both`: exact bytes are consumed by builder and independently verified/used by gates.

Unknown field/value is forbidden.

Role enum v1 includes:

- `build_contract`;
- `build_environment_contract`;
- `build_runtime_lock`;
- `control_set_lock`;
- `control`;
- `control_manifest`;
- `control_schema`;
- `source_index`;
- `closure_contract`;
- `binding_registry`;
- `engineering_bindings`;
- `engineering_contract`;
- `semantic_contract`;
- `adapter_contract`;
- `adapter_implementation`;
- `target_contract`;
- `cli_rc_contract`;
- `readonly_command_policy`;
- `readonly_runtime_observer`;
- `build_dependency_observer`;
- `emission_node_registry`;
- `emission_edge_registry`;
- `runtime_invocation_registry`;
- `template`;
- `serializer_contract`;
- `toolchain_lock`;
- `builder`.

### 18.1. Root-descriptor self-reference rule

There is no record for `BUILD-INPUTS.lock` inside itself.

Its exact bytes are bound externally by:

`BUILD-MANIFEST.build_inputs_lock_sha256`

This is the only permitted self-reference exception.

### 18.2. Canonical project-path contract

A project `canonical_path` is:

- UTF-8;
- POSIX `/` separators;
- relative to canonical project root;
- no empty component;
- no `.` or `..`;
- not absolute;
- resolves to a regular file;
- no symlink in any path component;
- resolved path stays inside project root.

Two textual paths resolving to the same file are forbidden duplicates.

### 18.3. Root Build Contract is an exact `both` input

The accepted Build Contract file is a required final lock record. During the measurement-candidate stage its exact id/version/SHA is instead bound in the measurement evidence envelope; after dynamic admission the same identity becomes the required final lock record:

- `role = build_contract`;
- `consumption_scope = both`;
- `contract_version = 0.9.3`;
- `sha256 = exact SHA-256 of independently accepted v0.9.3 Markdown bytes`.

The builder reads the exact file, recomputes SHA-256, checks the accepted id/version/SHA tuple, and only then emits that tuple into BUILD-MANIFEST.

No weaker `gate` scope is allowed because manifest bytes contain this identity.

There is no unverifiable rule such as “output may depend only through identity”. The observable rule is:

- same complete accepted input byte set + same fixed build-environment contract must produce identical core output bytes;
- any changed Build Contract bytes necessarily change the pinned input set and therefore constitute a different build input identity.

### 18.4. `build-environment-v1` is an exact `both` input

Because BUILD-MANIFEST emits `build_environment_contract_id`, `version` and `sha256`, the exact accepted `build-environment-v1` file is mandatory. During measurement-candidate execution its exact id/version/SHA is bound in the measurement evidence envelope; final admission additionally requires:

- `role = build_environment_contract`;
- `consumption_scope = both`;
- exact SHA-256 pinned in `BUILD-INPUTS.lock`.

`gate`-only scope for this file is structurally invalid.

Builder reads and verifies its exact bytes before emission; gates independently verify the same bytes/hash and manifest tuple.

### 18.5. Required-set closure

There are two machine-distinct input-closure stages.

**Measurement-candidate closure** is derived only after the exact 16 static §34 prerequisites are admitted. Its evidence envelope binds at minimum:

- accepted root Build Contract;
- accepted `build-environment-v1`;
- exact measurement-candidate source SHA-256;
- all admitted static prerequisite identities/hashes actually consumed by the candidate;
- the external staging identity as evidence metadata only.

It does **not** claim final `BUILD-INPUTS.lock`, `build-runtime-v1` or `TOOLCHAIN.lock` admission.

**Final authoritative closure** is derived only after dynamic measurement and includes:

- accepted root Build Contract;
- accepted `build-environment-v1`;
- accepted `build-runtime-v1`/runtime lock;
- accepted `TOOLCHAIN.lock`;
- every Phase-A member with `admission_only=false` projected exactly under §18.5.2;
- `STEP7B0-CONTROL-SET.lock`;
- eligible controls;
- required engineering bindings/emission mapping;
- target contract;
- build bindings;
- adapter registry;
- emission order registries;
- `runtime-invocation-v1` registry.

Final required paths/roles/scopes must equal final `BUILD-INPUTS.lock` records exactly.

No final-authoritative closure may be inferred from the measurement envelope, and no dynamic runtime lock is required in order to create the code whose exact SHA must first be measured.

#### 18.5.1. Prerequisite item versus file-member identity

The exact §34 count is a count of **logical prerequisite items**, not a promise that each item has one physical file. A static prerequisite may be a closed bundle of project-file members. Every Phase-A project-file member admission row has exactly these fields:

- `prerequisite_item_number`;
- `member_role`;
- `canonical_path`;
- `sha256`;
- `consumption_scope`;
- `build_inputs_role`;
- `admission_only`.

`canonical_path` obeys §18.2 and is globally unique across Phase-A member rows. `sha256` is the exact file-byte SHA-256. Unknown fields are forbidden.

Exactly one projection mode is valid for every member:

1. **final-lock member:** `admission_only=false` and `build_inputs_role` is one exact allowed §18 role. Final `BUILD-INPUTS.lock` must contain exactly one row with the same `canonical_path`, `sha256`, exact `consumption_scope`, and `role == build_inputs_role`;
2. **admission-only member:** `admission_only=true` and `build_inputs_role=null`. The member is evidence/fixture material for prerequisite admission. Its `canonical_path` must be absent from final `BUILD-INPUTS.lock` entirely; no later role inference or independent adoption of the same Phase-A member path is permitted without revising this contract.

`admission_only=true` with non-null `build_inputs_role`, or `admission_only=false` with null/unknown `build_inputs_role`, is FAIL. No verifier may infer a projection from filename, directory, content, or neighboring rows.

Multiplicity tokens below are exact:

- `exactly_one` = cardinality exactly 1;
- `one_or_more` = cardinality >= 1;
- `zero_or_more` = cardinality >= 0.

#### 18.5.2. Closed Phase-A `member_role` schema v1

The following table is the complete allowed `member_role` universe for the exact 16 Phase-A logical items. A token valid for one item is invalid under every other item unless a separate row below explicitly allows it.

| item | `member_role` | exact `consumption_scope` | multiplicity | `build_inputs_role` | `admission_only` |
|---:|---|---|---|---|---|
| 1 | `control_set_lock` | `both` | `exactly_one` | `control_set_lock` | `false` |
| 2 | `semantic_contract` | `builder` | `exactly_one` | `semantic_contract` | `false` |
| 2 | `semantic_positive_fixture` | `gate` | `one_or_more` | `null` | `true` |
| 2 | `semantic_negative_fixture` | `gate` | `one_or_more` | `null` | `true` |
| 2 | `semantic_golden_fixture` | `gate` | `one_or_more` | `null` | `true` |
| 3 | `cli_rc_contract` | `builder` | `exactly_one` | `cli_rc_contract` | `false` |
| 3 | `cli_rc_golden_fixture` | `gate` | `one_or_more` | `null` | `true` |
| 4 | `target_contract` | `builder` | `exactly_one` | `target_contract` | `false` |
| 5 | `engineering_bindings` | `builder` | `exactly_one` | `engineering_bindings` | `false` |
| 6 | `engineering_contract` | `builder` | `one_or_more` | `engineering_contract` | `false` |
| 6 | `engineering_contract_fixture` | `gate` | `zero_or_more` | `null` | `true` |
| 7 | `readonly_command_policy` | `both` | `exactly_one` | `readonly_command_policy` | `false` |
| 8 | `readonly_runtime_observer_contract` | `gate` | `exactly_one` | `readonly_runtime_observer` | `false` |
| 9 | `build_dependency_observer_contract` | `gate` | `exactly_one` | `build_dependency_observer` | `false` |
| 9 | `build_dependency_observer_identity` | `gate` | `exactly_one` | `build_dependency_observer` | `false` |
| 9 | `build_dependency_observer_parser` | `gate` | `exactly_one` | `build_dependency_observer` | `false` |
| 9 | `build_dependency_observer_profile` | `gate` | `exactly_one` | `build_dependency_observer` | `false` |
| 9 | `build_dependency_observer_classification_policy` | `gate` | `exactly_one` | `build_dependency_observer` | `false` |
| 9 | `build_dependency_observer_fitness_fixture` | `gate` | `one_or_more` | `null` | `true` |
| 9 | `build_dependency_observer_fitness_evidence` | `gate` | `exactly_one` | `null` | `true` |
| 10 | `build_environment_contract` | `both` | `exactly_one` | `build_environment_contract` | `false` |
| 12 | `serializer_contract` | `builder` | `exactly_one` | `serializer_contract` | `false` |
| 12 | `template` | `builder` | `exactly_one` | `template` | `false` |
| 12 | `serializer_golden_fixture` | `gate` | `one_or_more` | `null` | `true` |
| 14 | `build_binding_schema` | `gate` | `exactly_one` | `null` | `true` |
| 14 | `binding_registry` | `builder` | `exactly_one` | `binding_registry` | `false` |
| 15 | `emission_node_schema` | `gate` | `exactly_one` | `null` | `true` |
| 15 | `emission_node_registry` | `builder` | `exactly_one` | `emission_node_registry` | `false` |
| 15 | `emission_edge_schema` | `gate` | `exactly_one` | `null` | `true` |
| 15 | `emission_edge_registry` | `builder` | `exactly_one` | `emission_edge_registry` | `false` |
| 16 | `runtime_invocation_schema` | `gate` | `exactly_one` | `null` | `true` |
| 16 | `runtime_invocation_registry` | `builder` | `exactly_one` | `runtime_invocation_registry` | `false` |
| 17 | `adapter_contract` | `builder` | `exactly_one` | `adapter_contract` | `false` |
| 17 | `adapter_implementation` | `builder` | `exactly_one` | `adapter_implementation` | `false` |
| 20 | `write_boundary_positive_fixture` | `gate` | `one_or_more` | `null` | `true` |
| 20 | `write_boundary_negative_fixture` | `gate` | `one_or_more` | `null` | `true` |
| 20 | `write_boundary_fixture_evidence` | `gate` | `exactly_one` | `null` | `true` |

The table is normative and closed. For each of the exact 16 Phase-A item numbers, the admitted member multiset must satisfy every required multiplicity above and contain no other member-role token. `zero_or_more` authorizes only the listed role token; it does not authorize unknown roles.

The optional item-6 `engineering_contract_fixture` role is permitted only for fixture bytes that are external to the exact engineering-contract member bytes; fixtures embedded in an engineering contract do not create a separate member. No other item may use this token.

For final-lock members, the projection is field-wise and mechanical. For admission-only members, any final-lock appearance of the same `canonical_path` is FAIL. A final-lock member omitted from final `BUILD-INPUTS.lock`, projected under a different role/scope, or represented more than once is FAIL.

The Phase-A member schema does not turn pre-existing admitted control manifest/five-control YAML inputs into new prerequisite items; those remain governed by §18.8.

#### 18.5.3. Canonical admission fixture-set digest

Whenever this contract binds a closed Phase-A fixture set by a single digest, the digest input is an exact JSON array. Each array element has exactly these fields:

- `canonical_path`;
- `member_role`;
- `sha256`.

The array contains exactly one element for every admitted fixture member in the referenced set and no evidence-file member. Elements are sorted by UTF-8 byte order of `canonical_path`; duplicate paths are forbidden by §18.5.1. Each object contains no unknown field.

The serialized bytes are the §26.1 canonical JSON serialization of that array as a standalone JSON value, including exactly one final LF. Define:

`fixture_set_sha256 = SHA256(exact canonical JSON bytes including final LF)`.

No textual tuple/list notation, implementation-language object representation, pretty printing, locale ordering or alternate newline convention is an accepted serialization.

#### 18.5.4. Closed item-20 write-boundary evidence

The exact item-20 `write_boundary_fixture_evidence` member uses closed `write-boundary-fixture-evidence-v1` fields:

- `evidence_contract_version = write-boundary-fixture-evidence-v1`;
- `fixture_set_sha256`;
- `fixture_results`;
- `overall_result`.

No unknown field is permitted. The referenced fixture set is exactly all admitted item-20 members with `member_role in {write_boundary_positive_fixture, write_boundary_negative_fixture}` and is digested under §18.5.3.

`fixture_results` is an exact array sorted by UTF-8 byte order of `canonical_path`. Each result object has exactly:

- `canonical_path`;
- `fixture_sha256`;
- `fixture_role`;
- `expected_result`;
- `observed_result`.

Allowed `fixture_role` values are exactly `write_boundary_positive_fixture | write_boundary_negative_fixture`. For a positive fixture, `expected_result=PASS`; for a negative fixture, `expected_result=FAIL`. `observed_result` is exactly `PASS | FAIL`.

The result array must have exact one-to-one set equality with the admitted item-20 fixture set by `(canonical_path,fixture_sha256,fixture_role)`. Missing, extra, duplicate, wrong-hash or relabeled result records are FAIL. Every record requires `observed_result == expected_result`. `overall_result` equals exact token `PASS` if and only if all those conditions hold; otherwise item 20 is not admitted. The evidence file itself is not included in `fixture_set_sha256`.

### 18.6. `build-dependency-observer-v1`

A separate accepted pre-builder observer contract monitors the **entire process tree** of the hash-frozen measurement candidate and, later, the final admission run.

#### 18.6.1. Full-syscall capture, cryptographic execution identity and review semantics

The observer must capture the **full syscall stream** of the candidate process tree. A filtered `%file`, `%process`, named-syscall subset, sampling profiler, or best-effort trace is not admissible closure evidence. v0.9.3 changes only evaluation of a previously unknown but structurally trustworthy event; it does not permit filtered capture.

Phase-A item 9 is a closed cryptographic observer bundle. Its `build_dependency_observer_identity` member is an exact machine-readable `build-dependency-observer-execution-identity-v1` descriptor. No unknown fields are allowed.

Common required identity fields:

- `observer_identity_contract_version = build-dependency-observer-execution-identity-v1`;
- `observer_identity_id`;
- `observer_tool_name`;
- `observer_tool_version`;
- `execution_identity_kind`;
- `observer_contract_path`;
- `observer_contract_sha256`;
- `parser_path`;
- `parser_sha256`;
- `profile_path`;
- `profile_sha256`;
- `executable_sha256`;
- `runtime_members`;
- `runtime_members_sha256`.

`observer_contract_path`, `parser_path` and `profile_path` are project canonical paths under §18.2. Their SHA fields must equal the exact admitted item-9 `build_dependency_observer_contract`, `build_dependency_observer_parser` and `build_dependency_observer_profile` members respectively. Every SHA field is exactly 64 lowercase hexadecimal bytes. The separate classification-policy member is bound by the Phase-A member set and fitness evidence under §18.6.1a; it is intentionally **not** an extra execution-identity-descriptor field.

`runtime_members` is an exact array of zero or more records, each with exact fields `runtime_member_kind`, `canonical_external_path`, `sha256`. Allowed `runtime_member_kind` is exactly `loader | library | config | runtime_data`. `canonical_external_path` is an absolute UTF-8 POSIX path outside project root after `.`/`..` normalization and symlink resolution, and it resolves to the exact regular file whose bytes are hashed. Records are sorted by UTF-8 bytes of `canonical_external_path`; duplicate resolved paths are forbidden. `runtime_members_sha256` is SHA-256 of the exact §18.5.3 standalone canonical JSON-value serialization of that array: §26.1 canonical JSON bytes with exactly one final LF included in the hashed byte sequence. An empty array is valid only when the admitted execution mode proves that no behavior-affecting byte exists outside the executable/digest runtime root and the separately bound item-9 project members.

Conditional exact identity schemas:

1. `execution_identity_kind = binary_closure` adds exactly one field `executable_absolute_path`. It is the canonical absolute executable path after symlink resolution. Fields `runtime_root_sha256` and `executable_relative_path` are forbidden. `runtime_members` must enumerate every behavior-affecting external loader/library/config/runtime regular-file byte identity used by that observer execution;
2. `execution_identity_kind = digest_runtime_root` adds exactly `runtime_root_sha256` and `executable_relative_path`. `runtime_root_sha256` is exactly the lowercase SHA-256 digest of the immutable independently reproducible runtime-root representation accepted by the item-9 contract. `executable_relative_path` is a normalized relative POSIX path inside that root with no empty/`.`/`..` component. Field `executable_absolute_path` is forbidden. Bytes inside that root are covered by the root digest; any behavior-affecting runtime/config byte outside it must appear in `runtime_members`.

Exact executable-byte equality is mandatory in both modes:

- for `binary_closure`, let `ACTUAL_OBSERVER_EXECUTABLE` be the regular file reached by the already-canonicalized `executable_absolute_path`; immediately before launch, `SHA256(bytes(ACTUAL_OBSERVER_EXECUTABLE)) == executable_sha256` is required;
- for `digest_runtime_root`, the harness first verifies/materializes the exact admitted `runtime_root_sha256`, resolves `executable_relative_path` inside that verified root without symlink escape, requires a regular file, and immediately before launch requires `SHA256(bytes(resolved executable)) == executable_sha256`.

In `binary_closure` mode every `runtime_members` path is likewise re-read immediately before launch and its exact bytes must match that row's `sha256`; the recomputed canonical-array digest must equal `runtime_members_sha256`. In `digest_runtime_root` mode the runtime-root digest is reverified immediately before launch and every external `runtime_members` record is checked the same way. The separately bound observer contract/parser/profile project files are rehashed against the descriptor, and the exact classification-policy bytes are independently rehashed against the admitted item-9 member SHA before every observer/fitness/measurement evaluation.

No other identity-descriptor fields are permitted.

A package name, tool version, executable basename, PATH resolution, mutable host directory, or "normally installed" identity is never sufficient. If the selected observer execution can depend on a runtime/config byte that is neither enumerated in `runtime_members` nor contained in the admitted digest-addressed runtime root nor separately bound by the exact item-9 project members, item 9 admission FAILS.

Immediately before every observer launch, including every §18.6.1a fitness-suite launch and every Phase-B/Phase-D launch, all execution-identity byte equalities above are recomputed from the actual launch target/runtime and exact project members. A cached prior verification, version string, filename or descriptor-only comparison is insufficient. Same version with different executable bytes/SHA, runtime-root digest, runtime-member bytes/digest, parser bytes/SHA, profile bytes/SHA, or behavior-affecting runtime/config bytes is FAIL before candidate execution. Classification-policy byte equality is separately reverified before evaluation; policy drift prevents PASS even when execution identity is unchanged.

The accepted observer contract additionally pins exact:

- invocation/selector semantics;
- full process-tree following semantics;
- FD→path/process attribution rules;
- loss/truncation/error detection;
- the classification-policy interface and `EVENT_OPERATION_KEY` extraction needed by §18.6.1b.

Every captured syscall/event receives exactly one evaluation disposition:

1. `ADMITTED` — behavior is admitted read-only/bootstrap or an admitted write to the exact external staging/declared stdout/stderr sink under the security-property rules;
2. `FORBIDDEN` — known behavior violates a security property, matches a hard-deny rule, or is otherwise explicitly forbidden;
3. `REVIEW_REQUIRED` — the event/operation is structurally trustworthy and fully attributable but has no admitted classification yet.

Run outcome precedence is exact: `FAIL > REVIEW_REQUIRED > PASS`.

- `FORBIDDEN`, trace loss/truncation, observer startup failure, undecodable arguments, uncertain FD/path/process attribution, parser ambiguity/uncertainty, or another security-property violation makes the run irrevocably `FAIL`.
- An unknown/unreviewed but otherwise decodable and attributable syscall/event makes the run at least `REVIEW_REQUIRED`, **not PASS and not an early parser abort**. The parser must continue through every remaining structurally trustworthy record and emit the complete review inventory.
- `REVIEW_REQUIRED` cannot satisfy item-9 admission, Phase-B measurement admission, Phase-C derivation, Phase-D admission, publication or release. It exists only to collect all unreviewed event/operation keys in one trustworthy run.
- After any `FAIL` disposition, a parser may stop only when trustworthy continuation is impossible (for example actual trace loss or structurally undecodable framing). Otherwise it continues only to complete evidence; final outcome remains `FAIL`.

#### 18.6.1a. Observer fitness is cryptographically bound admission evidence

Normative fail-closed wording is insufficient by itself. Phase-A item 9 is not admitted until the exact cryptographic observer identity from §18.6.1 and the exact classification policy from §18.6.1b pass a machine-executed fitness suite.

The suite includes:

- a positive synthetic process/trace with a known exact event inventory and exact classifications;
- an unknown-event fixture in which one unreviewed event appears **before** at least one known sentinel event; expected outcome is `REVIEW_REQUIRED`, the unknown `EVENT_OPERATION_KEY` must appear in the review inventory, and the later sentinel must still appear, proving that parsing did not stop at the first unknown;
- negative fixtures in which each of the following must produce FAIL: observer startup failure, injected trace truncation/explicit event loss, undecodable syscall arguments, uncertain FD→path/process attribution, parser uncertainty/ambiguous record;
- at least one hard-deny event proving that classification-policy hard-deny data cannot be converted to `REVIEW_REQUIRED` or `ADMITTED`;
- adversarial cases proving that reviewed-safe policy entries cannot override project-write, staging/sink, network, exec, project-dependency, process-tree or external-dependency security-property enforcement;
- an `invariant_scope_overreach` fixture in which one invariant resolves one aspect of the event while another effect-relevant argument/field remains uncovered; expected outcome is `REVIEW_REQUIRED`, proving that partial invariant success cannot create `INVARIANT_ADMITTED`.

The positive fixture must prove that the parser returns the exact expected event count/classification and does not silently drop a known record.

The exact item-9 `build_dependency_observer_fitness_evidence` member uses closed `build-dependency-observer-fitness-evidence-v3` fields:

- `fitness_evidence_contract_version = build-dependency-observer-fitness-evidence-v3`;
- `observer_identity_descriptor_sha256`;
- `observer_executable_sha256`;
- `runtime_root_sha256`;
- `runtime_members_sha256`;
- `observer_contract_sha256`;
- `parser_sha256`;
- `profile_sha256`;
- `classification_policy_sha256`;
- `fitness_fixture_set_sha256`;
- `prelaunch_identity_verification`;
- `positive_inventory_result`;
- `review_required_inventory_result`;
- `invariant_scope_overreach_result`;
- `negative_case_results`.

No unknown field is permitted. `observer_identity_descriptor_sha256` is SHA-256 of the exact admitted identity-descriptor member bytes. `observer_executable_sha256`, `runtime_members_sha256`, contract/parser/profile hashes, and `runtime_root_sha256` when applicable equal the descriptor field-wise; `runtime_root_sha256=null` in `binary_closure` mode. `classification_policy_sha256` equals SHA-256 of the exact admitted item-9 `build_dependency_observer_classification_policy` member. `fitness_fixture_set_sha256` is the §18.5.3 `fixture_set_sha256` computed over exactly every admitted item-9 `build_dependency_observer_fitness_fixture` member.

`prelaunch_identity_verification` must equal exact token `PASS` and is valid only if the §18.6.1 actual-byte execution-identity verification and exact classification-policy member rehash succeeded before every relevant fitness launch/evaluation. `positive_inventory_result` must equal exact token `PASS`. `review_required_inventory_result` must equal exact token `PASS` only when the unknown-event fixture produced final outcome `REVIEW_REQUIRED`, emitted the expected complete review inventory, and retained the required later sentinel event. `invariant_scope_overreach_result` must equal exact token `EXPECTED_REVIEW_REQUIRED_OBSERVED_REVIEW_REQUIRED` only when one invariant intentionally resolves one aspect of a structurally valid event while another effect-relevant argument/field is left outside complete invariant coverage; expected final outcome is `REVIEW_REQUIRED`, never `ADMITTED`/PASS. `negative_case_results` is a closed object with exactly these keys, each equal exact token `EXPECTED_FAIL_OBSERVED_FAIL`: `startup_failure`, `trace_loss_or_truncation`, `undecodable_args`, `uncertain_attribution`, `parser_uncertainty`, `hard_deny`, `policy_override_attempt`, `invalid_effect_scope`, `review_evidence_binding`, `unsafe_policy_admission`.

`invalid_effect_scope` must prove that an unknown/non-enum `effect_scope` cannot be admitted. `review_evidence_binding` must prove that a missing fixture, wrong path, wrong SHA or fixture that does not reproduce the exact referenced `EVENT_OPERATION_KEY` cannot be admitted. `unsafe_policy_admission` must prove that an exact policy entry cannot admit a namespace/root/credential/filesystem/network/exec/host-global/external-I/O effect or an event whose effect class depends on arguments not captured by its exact review key.

Fitness evidence is reusable only for that exact observer execution identity, exact parser/profile/contract bytes and exact classification-policy bytes. Any observer executable/runtime/config/parser/profile/classification-policy byte change invalidates item-9 admission and requires rerunning the applicable fitness suite before Phase B.

#### 18.6.1b. Hash-bound classification policy and security-property guardrail

Phase-A item 9 contains exactly one `build_dependency_observer_classification_policy` project member. Its bytes are gate-only observer-policy data; the measurement candidate does not consume them.

The file is canonical JSON with exactly these top-level fields and no others:

- `classification_policy_contract_version = build-dependency-observer-classification-policy-v2`;
- `policy_id` — non-empty stable UTF-8 identifier;
- `security_properties`;
- `review_key_mode = event_name_plus_operation_or_null`;
- `operation_sensitive_events`;
- `hard_fail_exact_syscalls`;
- `hard_fail_syscall_prefixes`;
- `reviewed_safe_events`;
- `unknown_event_disposition = REVIEW_REQUIRED`.

`security_properties` is the exact ordered array:

1. `project_root_immutable`;
2. `writes_only_declared_staging_or_capture_sinks`;
3. `network_dependency_absent`;
4. `undeclared_exec_absent`;
5. `project_dependency_set_exact`;
6. `process_tree_complete`;
7. `external_dependencies_inventoried`.

These are observer-design guardrails, not seven new independent prerequisite items or gates. A future observer/parser policy requirement is admitted only if it protects at least one property above or is required by another explicit Build Contract invariant. Classification-policy data cannot override enforcement of any property above.

Define exact review identity:

`EVENT_OPERATION_KEY = (event_name, operation_or_null)`.

`event_name` is the exact decoded syscall/event name. Whether an event is operation-sensitive is determined **only** by the exact `operation_sensitive_events` policy field; parser source/profile may implement the declared extraction grammar but may not independently add or remove operation-sensitive event names. An event absent from `operation_sensitive_events` always has JSON `null` as `operation_or_null`.

`operation_sensitive_events` is an exact array of unique objects with exactly these fields and no others: `event_name`, `operation_argument_index`. `event_name` is non-empty UTF-8. `operation_argument_index` is an integer `>= 0` selecting the zero-based top-level syscall argument. The array is sorted by UTF-8 bytes of `event_name`; duplicate `event_name` is FAIL. The admitted parser must first prove the complete top-level argument boundaries using its structural trace parser. For an operation-sensitive event, `operation_or_null` is the exact UTF-8 text of the selected top-level argument after removing only leading/trailing ASCII space or tab outside quoted/nested syntax; every remaining character, token order, letter case and numeric/symbolic representation is preserved exactly as emitted by the admitted observer. No semantic lookup table, symbolic-constant recognition or numeric canonicalization is required to form the key. Thus `TCGETS`, `0x5401`, `_IOC(...)` and `ATOM|0x40` are all representable without a parser/schema change when they are structurally complete. Example: for `ioctl(fd, request, arg)`, `operation_argument_index=1` selects the zero-based `request` argument.

If the selected top-level argument is truncated, its boundary cannot be proven, its trace text cannot be decoded unambiguously, or record framing is structurally uncertain, outcome is FAIL. A fully and unambiguously extracted selector that simply has no admitted classification is **not** a decode failure: its exact `EVENT_OPERATION_KEY` is emitted and the event becomes `REVIEW_REQUIRED`. For every event absent from `operation_sensitive_events`, `operation_or_null` is JSON `null`. Thus adding a newly observed operation for an already-declared operation-sensitive event changes only reviewed policy data when later admitted; it does not require parser-source or selector-grammar revision.

There are exactly two mutually exclusive sources of `ADMITTED`:

1. `INVARIANT_ADMITTED` — the event is resolved completely by one or more non-overridable semantic invariants required elsewhere in this contract;
2. `POLICY_ADMITTED` — the event is not governed by an effect-sensitive invariant and its exact `EVENT_OPERATION_KEY` has exactly one valid entry in `reviewed_safe_events`.

For invariant admission, `invariant_coverage` is exactly `COMPLETE` or `INCOMPLETE`.

The closed effect-coverage category universe is exactly the union of:

- the six `effect_scope` tokens defined below; and
- the seven exact `security_properties` tokens defined above.

`invariant_coverage = COMPLETE` only when every top-level argument and every decoded nested field/structure that can change the disposition of the record is either:

- classified by the applicable invariant set into one or more of those thirteen closed categories and resolved without violation; or
- explicitly proven effect-irrelevant, meaning that varying that argument/field over every structurally valid value cannot change disposition in any of those thirteen categories.

A partial successful invariant never creates `ADMITTED`. If any effect-relevant argument/field is uncovered, ambiguously classified, belongs to no closed category, or cannot be proven effect-irrelevant, `invariant_coverage = INCOMPLETE` and the event is `REVIEW_REQUIRED`. Any known invariant/security-property violation is `FORBIDDEN` and therefore FAIL. Thus `INVARIANT_ADMITTED` requires `invariant_coverage = COMPLETE`; process-tree coverage alone, for example, cannot admit a record whose namespace/root/credential or other effect remains unresolved.

Invariant enforcement is evaluated before policy admission. A key governed by an effect-sensitive invariant may not be admitted by `reviewed_safe_events`; an attempted policy entry for such a key is invalid policy and item 9 FAILS. Policy can never weaken, replace or bypass an invariant.

`reviewed_safe_events` is an exact array of unique objects with exactly these fields and no others:

- `event_name`;
- `operation`;
- `effect_scope`;
- `review_evidence_fixture_path`;
- `review_evidence_fixture_sha256`.

`event_name` and `operation` together equal the exact `EVENT_OPERATION_KEY`; `operation` is non-empty UTF-8 or `null`. The array is sorted by the tuple `(UTF8(event_name), operation_sort_key)`, where `operation_sort_key` is byte `0x00` for JSON `null` and byte `0x01 || UTF8(operation)` for a string. Duplicate `(event_name,operation)` is FAIL.

`effect_scope` is exactly one of this closed allowlist:

- `process_memory_local`;
- `thread_synchronization_local`;
- `process_signal_state_local`;
- `process_fd_metadata_query_local`;
- `process_identity_query`;
- `process_resource_query`.

The scopes have exact safety meaning:

- `process_memory_local` — effect is confined to private address-space/runtime-memory bookkeeping of the traced process; it does not perform external I/O, mutate host-global state, alter namespaces/root/credentials/process-tree topology, or create a writable/shared file-backed effect;
- `thread_synchronization_local` — effect is confined to synchronization within the already traced process tree and does not use a filesystem/network/external-I/O object;
- `process_signal_state_local` — effect is confined to signal mask/handler state of the traced process/thread and does not deliver/control signals outside the traced process tree;
- `process_fd_metadata_query_local` — read-only query of process-local descriptor metadata only; it does not perform I/O through the descriptor, inspect/mutate the external referenced object, change FD topology, duplicate/close/open descriptors, or change attribution;
- `process_identity_query` — read-only query of process/thread identity; returned host-state values remain independently subject to unchanged §18.12;
- `process_resource_query` — read-only query of resource limits/accounting visible to the process; returned host-state values remain independently subject to unchanged §18.12.

No scope includes or can be interpreted to include filesystem/object mutation, external reads/writes, network activity, namespace/root/credential transitions, exec, process-tree creation/escape, mount topology, kernel/module/global subsystem mutation, device control, external object state, or another host-global/external-I/O effect. If the effect of an event cannot be proven to fit wholly inside one exact allowed scope, that key is ineligible for `POLICY_ADMITTED` and remains `REVIEW_REQUIRED` unless a non-overridable invariant resolves it.

Argument-dependent safety is fail-closed. A key is eligible for `reviewed_safe_events` only when its `EVENT_OPERATION_KEY` captures every argument dimension necessary to prove that **every structurally valid record sharing that exact key** stays within the declared `effect_scope`. If additional arguments, pointed-to structures, nested flags or hidden object state can change the effect class, the key is ineligible for policy admission and must be handled by a non-overridable invariant or remain `REVIEW_REQUIRED`. This specifically prevents a broad key from admitting a safe-looking instance while also covering namespace/root/credential or other effectful variants.

`review_evidence_fixture_path` is a canonical project path to exactly one admitted Phase-A item-9 member whose role is `build_dependency_observer_fitness_fixture`. `review_evidence_fixture_sha256` must equal SHA-256 of that exact fixture member bytes. Replaying the exact admitted parser/profile against that fixture must reproduce the referenced `EVENT_OPERATION_KEY` at least once without trace loss, truncation or structural uncertainty. Missing fixture membership, wrong path/SHA, a fixture that does not reproduce the key, or evidence bytes not included in the admitted item-9 fixture set is FAIL. The fixture proves the reviewed trace shape/key binding; the independent item-9 policy review remains responsible for the truth of the declared `effect_scope`.

A policy entry is therefore positive evidence, not an exemption. Incompleteness of `reviewed_safe_events` is safe by construction: an absent key is never admitted merely because it is absent from a deny-list.

`hard_fail_exact_syscalls` and `hard_fail_syscall_prefixes` are exact UTF-8-byte-sorted unique string arrays. The admitted policy may contain additional reviewed hard-deny entries, but it must contain at least these exact syscall names:

`add_key` | `bpf` | `capset` | `chroot` | `delete_module` | `finit_module` | `fsconfig` | `fsmount` | `fsopen` | `init_module` | `kcmp` | `kexec_file_load` | `kexec_load` | `keyctl` | `memfd_create` | `mount` | `mount_setattr` | `move_mount` | `name_to_handle_at` | `open_by_handle_at` | `open_tree` | `perf_event_open` | `personality` | `pivot_root` | `process_vm_readv` | `process_vm_writev` | `ptrace` | `quotactl` | `reboot` | `request_key` | `seccomp` | `setfsgid` | `setfsuid` | `setgid` | `setgroups` | `setns` | `setregid` | `setresgid` | `setresuid` | `setreuid` | `setuid` | `syslog` | `umount2` | `unshare` | `userfaultfd`.

It must also contain at least these exact prefixes:

`io_uring_` | `landlock_` | `pidfd_`.

A matching hard-deny event is `FORBIDDEN` regardless of `reviewed_safe_events` and therefore makes final outcome FAIL. The hard-deny lists are **defense in depth and an early-rejection optimization, not the completeness premise of the safety proof**. Absence of an event name/prefix from these lists never creates `ADMITTED`, never makes a key eligible for `reviewed_safe_events`, and is not evidence of non-effectfulness. A dangerous event omitted from hard-deny still cannot PASS unless it independently satisfies one of the two exact admission routes above; if it fits neither, it remains `REVIEW_REQUIRED` or is rejected by an invariant.

A syscall/event not resolved by non-overridable invariant enforcement, hard-deny data or one valid `reviewed_safe_events` entry becomes `REVIEW_REQUIRED`; it is never silently admitted. Consequently completeness of the hard-deny enumeration is not required for safety: incompleteness fails closed rather than open.

Before Phase B and again before Phase D, the admitted parser/profile/policy are replayed against the admitted item-9 regression/fitness corpus and the exact `EVENT_OPERATION_KEY` inventory is compared to the admitted invariant resolution and exact `reviewed_safe_events` allowlist. Any newly unresolved key blocks the lifecycle as `REVIEW_REQUIRED` before authoritative use. If a genuinely new key appears only during a later full measurement, that run must still be read to completion when structurally trustworthy so that all unresolved keys are reported together.

Changing classification-policy bytes under the same accepted Build Contract does not require editing parser source merely to add reviewed data, but it **does** create new item-9 subject bytes: item 9 is `RERUN`, fitness/evidence are regenerated, old item-9 admission is stale, and any downstream freeze/evidence that binds the old item-9 member set is reissued or invalidated according to §34.5. Candidate-source bytes are not changed by policy review alone.

#### 18.6.2. Project-root dependency classification

From the full stream, project-root dependency classification includes at minimum:

- `open`, `openat`, `openat2`;
- `execve`, `execveat`;
- `stat`, `lstat`, `newfstatat`/`fstatat`, `statx`;
- `access`, `faccessat*`;
- `readlink`, `readlinkat`;
- xattr reads;
- directory enumeration (`getdents*`) with FD→path resolution;
- equivalent path existence/metadata queries.

Unknown project-root dependency event => FAIL.

#### 18.6.3. Non-project and non-syscall closure

The full syscall observer is necessary but **not sufficient** for host-state closure. §§18.9–18.12 and accepted `build-environment-v1`/`build-runtime-v1` additionally define the mandatory host-state surface, including channels that may be satisfied without an observable syscall (for example vDSO, auxv, runtime-library bootstrap or direct CPU-feature instructions).

Absence from the syscall trace is never evidence that a mandatory host-state class does not exist.

### 18.7. Directory enumeration is forbidden to the builder

Builder consumes exact locked files; it must not discover project inputs by enumerating project directories.

Any project-root directory enumeration by builder process tree is FAIL.

### 18.8. Machine-observable project dependency closure

The dependency observer normalizes every project-root dependency event to a canonical path.

Two distinct admitted sets exist.

Define the exact pre-existing admitted project inputs for the current Phase-B builder slice:

`PREEXISTING_ADMITTED_BUILDER_INPUTS = {`

- exact current `controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv`;
- exact five canonical control YAML files named by the accepted five-control set;

`}`

These bytes were admitted by earlier project stages and do not become new §34 prerequisite items. Their exact path/SHA identities are rebound in the Phase-B measurement evidence envelope and later become final `BUILD-INPUTS.lock` rows with the accepted role/scope. `CONTROL-SCHEMA.json`, source index, closure contract and reference probe files remain gate-only under §19.3 and are **not** members of this set.

Then:

`MEASUREMENT_BUILDER_PATHS =`

1. exact accepted root Build Contract path;
2. exact accepted `build-environment-v1` path;
3. every Phase-A prerequisite member whose admitted `consumption_scope in {builder,both}` (including every builder-consumed member of items 12 and 17);
4. every path in `PREEXISTING_ADMITTED_BUILDER_INPUTS`;
5. the exact frozen Phase-B candidate source path.

`LOCK_BUILDER_PATHS` is the final `BUILD-INPUTS.lock` project path set where `consumption_scope in {builder,both}`, available only after Phase-C dynamic admission.

**Phase-B measurement relations:**

- the normalized set of project-root dependency paths observed from the candidate process tree equals `MEASUREMENT_BUILDER_PATHS` exactly;
- repeated metadata/read events on one admitted path do not create additional path identities;
- every required measurement project file is observed with permitted dependency class(es) defined by its accepted role/member contract;
- a builder/both bundle member omitted from observed dependencies is FAIL;
- any observed project-root path outside `MEASUREMENT_BUILDER_PATHS` is FAIL;
- final `BUILD-INPUTS.lock` is a Phase-C dynamic prerequisite, is not a Phase-B member, and must not be fabricated merely to start measurement;
- a gate-only project path observed by candidate is FAIL;
- undeclared project helper execution is FAIL;
- undeclared project metadata/path dependency is FAIL.

**Final-authoritative relations:**

- every required builder/both project file is observed with permitted dependency class(es) defined by role contract;
- every observed project-root dependency path is either a permitted `LOCK_BUILDER_PATHS` file or final `BUILD-INPUTS.lock` itself;
- final `BUILD-INPUTS.lock` is expected to be read but remains outside its own row universe;
- a `gate`-only project path observed by builder is FAIL;
- undeclared project helper execution is FAIL;
- undeclared project metadata/path dependency is FAIL.

The Phase-B set may not be used as evidence that final `LOCK_BUILDER_PATHS` is complete. Final closure is independently re-observed after Phase-C dynamic inputs exist.

### 18.9. Metadata/path perturbation

Determinism harness varies, without changing accepted input bytes:

- input mtimes;
- permissible input file modes;
- parent-directory mtimes;
- cwd;
- temporary/external staging paths.

Generated core output bytes must remain identical or the build must explicitly FAIL before publication. Silent byte variation is forbidden.

### 18.10. `build-environment-v1` — exact process environment and write boundary

The accepted environment contract defines the exact authoritative builder invocation envelope.

**Environment**

- start from a sanitized environment rather than inherited caller environment;
- exact allowed variable names and exact values are declared;
- undeclared variables are absent;
- user-site/site customization is disabled;
- locale/timezone/home semantics are exact;
- caller PATH is not a tool-selection authority.

Spike evidence shows an isolated Python baseline is viable, but v0.9.3 does not hard-code guessed runtime file paths from that experiment.

**Process execution**

- initial interpreter executable path is exact and pinned;
- builder may not discover or execute helper tools through caller PATH;
- unless an accepted role explicitly requires a child tool, descendant `execve/execveat` is forbidden;
- every permitted child executable, if any, has exact pinned identity.

**File descriptors**

- stdin is an exact declared read-only source, normally `/dev/null`;
- stdout/stderr are declared capture sinks;
- all other inherited FDs are closed;
- unexpected inherited FD => FAIL.

**Network**

- builder process tree has no network requirement;
- network access is unavailable or denied by sandbox;
- network syscall/connection attempt not explicitly classified as harmless bootstrap is FAIL; no network result may select emitted bytes.

**Write boundary**

- canonical project root is read-only for builder process tree;
- builder accepts an explicit external staging root;
- staging root must be outside project root after canonical path resolution;
- staging root must be empty/new according to its subordinate contract;
- builder writes only the three admitted build products and explicitly allowed temporary files beneath staging;
- builder must not create, modify or delete `dist/` or any other project-root path;
- staging executability (`exec` versus `noexec`) is not build semantics.

### 18.11. `build-runtime-v1` — measured non-project filesystem/tool closure

Non-project runtime dependencies are not guessed from documentation or a hand-written list.

`build-runtime-v1` is a **dynamic prerequisite**. It is created only from a hash-frozen NON-RELEASE measurement candidate after the exact 16 static prerequisites in §34 are independently admitted.

Measurement/admission sequence:

1. admit the exact 16 static prerequisites and their hashes;
2. implement one NON-RELEASE measurement candidate consistent with those contracts;
3. freeze and record the candidate source SHA-256 before dependency measurement;
4. execute that exact candidate under the accepted full-syscall dependency observer and exact `build-environment-v1` envelope;
5. canonicalize every non-project path/exec/metadata dependency and collect the mandatory host-state surface from §18.12;
6. derive and classify a candidate closure;
7. crypto-pin every admitted output-relevant regular file, or bind it through an accepted digest-addressed runtime-root identity;
8. create candidate `build-runtime-v1` and `TOOLCHAIN.lock` identities;
9. rerun the **same candidate source SHA** under the candidate closure and require observed closure ⊆ admitted closure with no unresolved `REVIEW_REQUIRED` event/channel;
10. perturb/remove undeclared external paths and required host-state classes and require either no effect under an admitted disposition or explicit fail-closed behavior;
11. finalize dynamic prerequisites (§34 items 11, 13, 18, 19);
12. run final admission again with those dynamic bytes present. Any new external dependency, host-state channel or changed candidate source SHA resets dynamic admission.

The measurement candidate is not an authoritative builder and may not publish. Its core outputs/evidence are NON-RELEASE. It is nevertheless the exact source candidate whose dependency closure is being measured; a later authoritative admission may consider only the **same source SHA**. Any source-byte change requires remeasurement from step 3.

Every admitted external value that can affect output must be one of:

- `fixed_literal` — exact contract constant;
- `pinned_bytes` — exact cryptographic identity;
- `derived` — deterministic function solely of fixed literals and pinned bytes.

There is no `declared_but_floating` class.

A path that is merely “known”, “versioned by package name” or “normally present” is not pinned.

### 18.12. Non-path and non-syscall host-state closure

Host-state closure is defined by an **accepted mandatory surface**, not merely by events that happen to appear in a tracer output.

`build-environment-v1` owns `STATIC_HOST_STATE_ROWS`; `build-runtime-v1` owns `DYNAMIC_HOST_STATE_ROWS`. Both use exact `host-state-surface-v1` row fields:

- `class_id`;
- `channel_kind`;
- `ordering_sensitive`;
- `disposition`;
- `coverage_mechanism`;
- `fixed_value_or_fixture_ref`.

The machine identity is exact:

`HOST_STATE_ROW_KEY = (class_id, channel_kind)`

Rules:

- the key is unique within `STATIC_HOST_STATE_ROWS`;
- the key is unique within `DYNAMIC_HOST_STATE_ROWS`;
- `STATIC_HOST_STATE_ROWS` and `DYNAMIC_HOST_STATE_ROWS` are disjoint by key; collision is FAIL — there is no overwrite, precedence or “dynamic wins” rule;
- rows sharing one `class_id` must agree on `ordering_sensitive`; disagreement is FAIL;
- disposition and coverage are per **pair**, so different channels of one class may use different admitted mechanisms.

Allowed `channel_kind` enum v1 is exactly:

- `syscall`;
- `vdso`;
- `auxv`;
- `procfs_or_sysfs_host_state`;
- `runtime_library`;
- `cpu_instruction_or_feature_dispatch`;
- `environment_bootstrap`.

Unknown channel kind is FAIL until this contract/runtime design is revised and independently admitted.

The mandatory class universe includes at minimum, regardless of whether a syscall is observed:

- kernel/OS/architecture identity (`uname`-equivalent);
- wall/monotonic/timezone/time sources, including vDSO-backed time;
- randomness/entropy/runtime seeding (`getrandom`, urandom-equivalent, runtime seed);
- uid/euid/gid/egid and credential identity;
- pid/ppid/process identity;
- resource limits (`getrlimit`/`prlimit64` equivalents);
- scheduler/affinity/CPU-count/topology/getcpu-like state;
- `auxv`/process-bootstrap values exposed by the kernel/runtime;
- namespace/cgroup/hostname/container identity;
- CPU feature/dispatch state that can select implementation paths;
- equivalent kernel/runtime/library-provided host state.

The accepted static design must instantiate `MANDATORY_APPLICABLE_HOST_STATE_PAIRS`: every `(class_id, channel_kind)` known to be applicable to the accepted target/runtime, including non-syscall channels even if no trace event is expected. Unresolved applicability is FAIL, not omission.

Measurement may discover additional applicable pairs. Define:

`FINAL_HOST_STATE_PAIR_UNIVERSE = MANDATORY_APPLICABLE_HOST_STATE_PAIRS ∪ DISCOVERED_HOST_STATE_PAIRS`.

A discovered pair absent from `STATIC_HOST_STATE_ROWS` is permitted only if Phase C adds exactly one matching row to `DYNAMIC_HOST_STATE_ROWS` and supplies its disposition/evidence. A discovered pair already owned by a static row may add evidence referencing that key but may not redefine the row. If measurement contradicts the admitted static row, Phase C FAILS and the lifecycle returns to Phase A for contract revision/remeasurement.

A mandatory applicable pair that is never observed still requires exactly one row and an admitted disposition. Absence from syscall/full-trace evidence is never a reason to omit a mandatory pair.

Final exact coverage requires:

`keys(STATIC_HOST_STATE_ROWS ∪ DYNAMIC_HOST_STATE_ROWS) == FINAL_HOST_STATE_PAIR_UNIVERSE`.

Duplicate pair, uncovered pair, extra non-applicable pair, unknown pair/channel, or ambiguous ownership => FAIL.

For every final pair exactly one accepted disposition is required:

1. `DENIED` — accepted sandbox/runtime boundary prevents that channel and candidate still passes;
2. `FIXED` — accepted sandbox/wrapper/runtime root makes the relevant returned/exposed value exact and the fixed identity/value is part of the admitted environment/runtime;
3. `PERTURBED_NONINFLUENTIAL` — only for `ordering_sensitive=false`: controlled runs expose meaningfully different values through that pair while every accepted byte input remains identical and the three core outputs remain byte-identical.

If `ordering_sensitive=true`, allowed dispositions are only `DENIED` or `FIXED`. Ordering/iteration/selection-sensitive state must never be admitted merely because two perturbation runs happened to produce the same bytes.

`coverage_mechanism` must explain machine-checkably how the **pair** is controlled or perturbed. For non-syscall channels this cannot be satisfied by a syscall trace alone; it requires an accepted sandbox/runtime-root/wrapper/virtualization mechanism or controlled perturbation fixture that actually changes/denies/fixes that channel.

If a variable host-state pair cannot be denied, fixed or (where allowed) meaningfully perturbed, admission is FAIL until a stronger sandbox/runtime design is provided.

Unknown/unclassified host-state event or exposed channel => FAIL. Failure to establish exact pair coverage for any mandatory applicable or discovered pair => FAIL.

### 18.13. Hermeticity adversarial gate

At minimum the harness tests:

- extra caller environment variables;
- different caller `HOME`;
- user-site/site customization presence;
- caller PATH containing a malicious same-name helper;
- undeclared external feature file;
- undeclared external executable;
- unexpected inherited FD;
- network available versus blocked;
- different cwd/staging path;
- read-only project root;
- every mandatory variable host-state class from `host-state-surface-v1`, not only classes observed by a syscall tracer;
- representative non-syscall channels including vDSO/auxv/runtime-library/CPU-feature paths where applicable to the accepted runtime;
- explicit proof that every `ordering_sensitive=true` class is `DENIED` or `FIXED`;
- floating external file/version substitution.

Each case must be inaccessible/ignored, fixed/pinned, produce byte-identical output under an allowed perturbation proof, or explicitly FAIL. Silent output variation is forbidden. A missing perturbation/control mechanism for a mandatory class is itself FAIL.

## 19. Explicit build-input classes for the current slice

The exact path list is instantiated by `BUILD-INPUTS.lock`; this section fixes role/scope expectations for Step 7B.0.

### 19.1. Mandatory `both` inputs

At minimum:

- accepted root Build Contract v0.9.3;
- accepted `build-environment-v1`.

If another input identity is emitted directly into BUILD-MANIFEST as an independent id/version/SHA tuple, that input must also be `both` unless this contract explicitly states otherwise.

### 19.2. Builder-consumed inputs

At minimum as required by the accepted subordinate design:

- `STEP7B0-CONTROL-SET.lock`;
- exact current control manifest if selected by design;
- exact five control YAML files;
- build-binding registry;
- engineering-role bindings;
- every selected engineering contract;
- target contract;
- CLI/RC contract;
- `check-semantic-v1`;
- `readonly-command-policy-v1`;
- adapter contract and implementation;
- emission node/edge registries;
- `runtime-invocation-v1` registry;
- exact template;
- serializer contract/fixtures used by builder;
- accepted builder source;
- any exact toolchain/runtime lock bytes the builder consumes.

For Phase B, the exact pre-existing builder inputs are fixed by §18.8 to the current control manifest plus the exact five canonical control YAMLs. They are earlier-admitted project artifacts rebound into measurement evidence; they do not increase the §34 prerequisite count. Adapter implementation and template are not “pre-existing exceptions”: they are explicit members of Phase-A bundles 17 and 12 respectively.

### 19.3. Gate-only inputs unless a later accepted design changes scope

Current evidence supports keeping these out of builder emission path:

- `CONTROL-SCHEMA.json`;
- source index;
- closure contract;
- reference probe implementation;
- reference probe plan;
- generated-artifact gate implementations.

If dependency observer sees a gate-only project file during authoritative build, admission is FAIL until `BUILD-INPUTS.lock` and contract scopes are deliberately revised and re-audited.

### 19.4. Non-project dependencies

Non-project interpreter/runtime files are not represented by vague classes such as “system Python”. They are closed by accepted `build-runtime-v1`/`TOOLCHAIN.lock` evidence and exact cryptographic/runtime-root identity according to §18.11.

Directory-level phrases such as “all sources”, “system libraries” or “all controls” are not valid identities.

## 20. BUILD-MANIFEST v1 exact schema and dual-order closure

`manifest_contract_version = build-manifest-v1`

No unknown fields.

Manifest-level exact fields:

- `manifest_contract_version`;
- `build_contract_id`;
- `build_contract_version`;
- `build_contract_sha256`;
- `artifact_name`;
- `artifact_role`;
- `target_id`;
- `builder_id`;
- `builder_sha256`;
- `build_inputs_lock_sha256`;
- `build_environment_contract_id`;
- `build_environment_contract_version`;
- `build_environment_contract_sha256`;
- `control_set_lock_sha256`;
- `template_sha256`;
- `launcher_contract_id`;
- `launcher_contract_version`;
- `launcher_line`;
- `launcher_sha256`;
- `script_line_count`;
- `scaffolding_sha256`;
- `emission_block_ids`;
- `runtime_invocation_block_ids`;
- `blocks`.

Exact constants:

- `build_contract_id = step7b0-build-contract`;
- `build_contract_version = 0.9.3`;
- `artifact_name = securelinux-policy-check.sh`;
- `artifact_role = read-only-check`;
- `launcher_line = 1`.

`build_contract_sha256` equals the accepted Build Contract `both` lock row.

Build-environment identity fields equal the accepted `build-environment-v1` `both` lock row.

`control_set_lock_sha256` equals the exact `STEP7B0-CONTROL-SET.lock` input hash.

No timestamp, username, cwd, hostname, random value, pid or absolute build/staging path may appear.

FSTEC and engineering block records use the conditional exact schemas from §3.

### 20.1. Exact emission-order equalities

Let:

- `E = FINAL_EMISSION_BLOCK_ORDER`;
- `S = block_id sequence obtained by scanning final script blocks in increasing physical line_start`;
- `O = BUILD-MANIFEST.emission_block_ids`;
- `M = block_id sequence of BUILD-MANIFEST.blocks array in array order`.

Required:

`E == S == O == M`

Additionally:

- `emission_block_ids` contains every emitted generated block exactly once;
- `blocks` array contains every emitted generated block exactly once;
- manifest block `line_start` values are strictly increasing in array order;
- line ranges do not overlap;
- no implementation may choose an alternative canonical emission order for `blocks`.

### 20.2. Exact runtime-order equality

Let:

- `R = block_id sequence of FINAL_RUNTIME_INVOCATION_ORDER`;
- `V = BUILD-MANIFEST.runtime_invocation_block_ids`.

Required:

`R == V`

`R`/`V` contains only callable rows of `runtime-invocation-v1` and does not include blocks that are query/help/build-info-only unless the runtime contract explicitly invokes them in no-argument policy run.

No equality between `E` and `R` is required or implied.

## 21. Full-script integrity and exact byte ownership

Every final script byte must be integrity-bound.

There are three binding classes:

1. generated-block bytes — directly covered by exactly one `block_sha256`;
2. non-block/scaffolding bytes other than the 64 final manifest-digest bytes —
   covered by normalized `scaffolding_sha256`;
3. the 64 final manifest-digest bytes — bound by the independent equality
   `HEADER_MANIFEST_SHA256 == SHA256(BUILD-MANIFEST.json)` from §22.1 and by
   the final script checksum in BUILD-SHA256.

The line-1 launcher is scaffolding bytes with additional
`launcher_sha256`/engineering provenance.

This wording deliberately does **not** claim that the raw 64 header digest
bytes are directly covered by `scaffolding_sha256`, because that hash
normalizes them to the placeholder.

### 21.1. Exact manifest-hash header uniqueness

The final script contains exactly one line matching:

`# BUILD-MANIFEST-SHA256: <64 lowercase hex>`

Zero or more than one matching line is FAIL.

The line is outside generated blocks.

### 21.2. Scaffolding hash

To compute `scaffolding_sha256`:

1. parse final script as exact LF-terminated lines;
2. exclude all inclusive generated-block line ranges;
3. locate the single manifest-hash header;
4. replace its 64-hex suffix with the exact 64-underscore placeholder;
5. concatenate all remaining lines in original order with LF;
6. SHA-256 the resulting bytes.

`script_line_count` is stored and verified.

Changing one ordinary comment byte outside a block must change
`scaffolding_sha256`.

## 22. Manifest-hash cycle and mandatory header equality

BUILD-MANIFEST does not contain final script SHA-256.

Build sequence:

1. load and verify all accepted root/pre-builder identities required before
   emission;
2. finalize exact eligible controls, bindings, emission graph, runtime-invocation registry and engineering
   role mapping;
3. finalize the complete embedded provenance record set;
4. canonical-serialize the provenance records that will be embedded;
5. derive final generated block bodies from those fixed inputs;
6. emit launcher;
7. emit template scaffolding;
8. emit the exact 64-underscore manifest-hash placeholder line;
9. emit generated blocks in `FINAL_EMISSION_BLOCK_ORDER`;
10. finalize line layout and manifest line ranges;
11. calculate block hashes;
12. calculate normalized scaffolding hash;
13. canonical-serialize BUILD-MANIFEST;
14. compute SHA-256 of exact BUILD-MANIFEST bytes;
15. replace exactly the 64 underscore bytes in the unique header with the
    64 lowercase hex digest;
16. verify byte count and line count remain unchanged;
17. hash final script;
18. create `BUILD-SHA256`.

No provenance record may be added/removed/reshaped after step 3 without
restarting layout/hash calculation from step 3.

### 22.1. Mandatory release equality

An independent gate must parse the unique final header and require:

`HEADER_MANIFEST_SHA256`
`== SHA256(exact BUILD-MANIFEST.json bytes)`

This check is independent of block hashes and normalized scaffolding hash.

Changing only the header hash and recomputing script SHA must FAIL.

A golden/adversarial fixture `alter_header_manifest_sha` is mandatory.

## 23. BUILD-SHA256 contract

`BUILD-SHA256` contains exactly two records:

- `BUILD-MANIFEST.json`;
- `securelinux-policy-check.sh`.

Records are basename-only, GNU `sha256sum` compatible, two spaces between
hash and basename, sorted by UTF-8 bytes basename, LF terminated.

`BUILD-SHA256` does not hash itself.

Its portable format is aligned with the already adopted donor test pattern
`TST-024`, but generated-artifact tests are new v3 tests.

---

## 24. Read-only static policy

Step 7B.0 uses a versioned closed allow-list:

`readonly-command-policy-v1`

It is a build input.

A generated runtime block may use only shell constructs, builtins, external
commands and redirections explicitly permitted by that policy.

Any unlisted construct is FAIL.

The policy must distinguish read-only and mutating forms of the same tool.

Examples that must not accidentally become allowed by a generic tool name:

- `sysctl -w`;
- output file redirection;
- `tee`;
- `install`;
- `truncate`;
- `chmod/chown`;
- package mutation;
- systemd mutation.

The examples are explanatory only; the closed policy file is authoritative.

Input redirection used to read `$0` for provenance may be explicitly allowed.

---

## 25. Runtime read-only observer contract — full process-tree classification

Static command policy is necessary but not sufficient.

`readonly-runtime-observer-v1` is a separate pre-builder subordinate **gate** input.
The generated builder/candidate does not consume this contract; final gates do.

It pins:

- observer tool and exact version/build identity;
- exact invocation;
- trace parser version/hash;
- full process-tree following;
- FD baseline;
- syscall/event classification policy;
- loss/truncation/error behavior.

### 25.1. Full-trace requirement

The observer must capture the **full syscall stream** of the generated script
process tree, not only `%file` events.

Every observed syscall/event must be one of:

- explicitly allowed read-only event;
- explicitly allowed stdout/stderr write event;
- explicitly classified forbidden event.

Unknown/unclassified syscall, undecodable arguments, trace loss or parser
uncertainty => FAIL.

### 25.2. FD baseline

The harness starts the artifact with:

- stdin attached to a defined read-only source such as `/dev/null`;
- stdout and stderr captured as the only writable inherited sinks;
- all other inherited FDs closed.

Therefore writes to an inherited unexpected FD cannot be silently accepted.

### 25.3. Minimum forbidden write/mutation families

The closed observer policy must at minimum classify and reject host-state
mutation through:

**File/FD write families**
- `write`, `pwrite*`, `writev`, `pwritev`;
- `copy_file_range`;
- `sendfile`/`splice` when destination is a regular file;
- `mmap`/`mmap2` with writable shared mapping;
- open-family including `open`, `openat`, `openat2` with
  `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_APPEND`, `O_TMPFILE`;
- create/truncate families;
- rename/unlink/link/symlink families;
- mkdir/rmdir/mknod families;
- chmod/chown families;
- xattr mutation;
- mount/umount.

**Non-filesystem host-state mutation**
- hostname/domainname mutation;
- clock/time-setting mutation;
- module/kernel loading or unloading;
- BPF/perf/kernel-object mutation not explicitly approved as read-only;
- ptrace/process-control mutation;
- signals sent to external processes;
- network configuration or state mutation, including mutating netlink/ioctl;
- namespace/cgroup mutation;
- reboot/power-state mutation;
- any other syscall not explicitly classified read-only for this target.

Because the policy is closed, this list is a minimum, not a deny-list ceiling.

### 25.4. Network rule for Step 7B.0

The five sysctl checks require no network access.

Network socket creation/transmission is therefore not an allowed runtime
behavior in Step 7B.0 unless a later audited observer/engineering contract
adds it.

### 25.5. Fail-closed observer behavior

Observer startup failure, missing tool, unsupported version, parser failure,
truncated/lost trace, unknown syscall/event or uncertain FD target => FAIL.

Step 7B.0 has no filesystem output exception.

The only runtime write sinks are the harness-provided stdout and stderr.

## 26. Canonical serialization contract

`serializer-contract-v1` freezes bytes.

### 26.1. JSON

- UTF-8;
- no BOM;
- LF;
- `ensure_ascii=false`;
- sorted keys;
- exact separators `(",", ":")`;
- no indentation;
- exactly one final LF when JSON is a standalone file;
- no locale-dependent number/string formatting.

### 26.2. Embedded provenance JSON

Each record is compact canonical JSON using the same key ordering/separators,
but without an embedded LF inside the JSON value. It is appended after exact
prefix:

`# SLP-PROVENANCE-V1 `

The comment line ends with one LF.

### 26.3. Golden fixtures

Mandatory byte-for-byte fixtures:

- minimal BUILD-MANIFEST;
- one FSTEC block;
- one engineering block;
- one embedded provenance line;
- template placeholder file;
- BUILD-SHA256.

Same contract version + different bytes is FAIL.

---

## 27. `TOOLCHAIN.lock` and measured build-runtime closure

Before authoritative builder **admission**, exact toolchain/runtime identities must exist. They are derived during the §34 measurement-candidate stage; they are not prerequisites for writing the measurement candidate itself.

`TOOLCHAIN.lock` pins at minimum:

- Bash version policy for generated target runtime;
- ShellCheck exact version;
- ShellCheck config SHA-256;
- exact ShellCheck args;
- runtime observer exact version/profile;
- `build_dependency_observer_identity_sha256` equal to SHA-256 of the exact admitted Phase-A item-9 `build_dependency_observer_identity` descriptor bytes;
- build-dependency observer executable SHA-256 and, according to identity mode, exact runtime-root digest or `runtime_members_sha256`, all field-wise equal to the admitted Phase-A item-9 identity;
- build-dependency observer parser SHA-256 and profile SHA-256 field-wise equal to the admitted Phase-A item-9 identity;
- build-dependency observer classification-policy SHA-256 equal to the exact admitted Phase-A item-9 `build_dependency_observer_classification_policy` member;
- build-sandbox/hermeticity tool exact version/profile;
- builder interpreter exact executable path/version/SHA-256;
- exact canonical interpreter flags;
- serializer implementation/version if external to builder;
- `build-runtime-v1` identity/digest.

`TOOLCHAIN.lock` must **repeat**, not redefine or re-resolve, the exact Phase-A item-9 observer identity. Equality is checked against the admitted descriptor and fitness evidence. Same tool/version/profile with a different executable SHA, runtime-root digest, `runtime_members_sha256`, parser SHA, profile SHA or classification-policy SHA is FAIL and returns the lifecycle to Phase A before any authoritative admission.

`build-runtime-v1` is derived from measurement, not guessed. It binds the admitted non-project runtime closure from §18.11 by either:

- exact path + SHA-256 records for every relevant regular file, plus exact metadata rules where metadata is consumed; or
- one accepted digest-addressed runtime-root identity whose contents are immutable and independently reproducible, plus exact executable paths within that root.

Any observed external regular file not covered by this closure is FAIL.

No “latest”, “default config”, package-name-only identity or unversioned tool is accepted.

Changing any pinned runtime/tool identity requires rerunning affected build/hermeticity/determinism gates.

## 28. Deterministic double-build and hermeticity perturbation gate

One admission gate run includes at minimum:

1. identical accepted project input bytes;
2. identical accepted `build-environment-v1` bytes;
3. identical accepted `build-runtime-v1`/toolchain identities;
4. clean external staging directory A;
5. clean external staging directory B;
6. intentionally different cwd and staging absolute paths;
7. project root read-only in at least one build;
8. build A and B;
9. compare byte-for-byte:
   - generated script;
   - BUILD-MANIFEST;
   - BUILD-SHA256;
10. compare produced modes;
11. scan core outputs for forbidden absolute/caller/host-derived material.

Builder explicitly sets produced modes:

- `.sh`: `0755`;
- JSON/checksum metadata: `0644`.

Harness additionally varies or injects, as applicable:

- caller environment variables not permitted by build environment;
- caller `HOME`;
- user-site/site customization;
- malicious PATH shadow helper;
- umask;
- input mtimes;
- permissible input modes;
- parent-directory mtimes;
- cwd;
- external staging path;
- undeclared non-project feature files;
- network availability versus blocked network;
- representative observed variable host-state classes according to §18.12;
- candidate floating external runtime file/version substitution.

For every perturbation case, the accepted outcome is exactly one of:

- same accepted inputs and byte-identical core outputs; or
- explicit fail-closed rejection before publication.

Silent output variation is forbidden.

A host-state class using disposition `PERTURBED_NONINFLUENTIAL` must show different observed return values across controlled runs while the three core output files remain byte-identical.

Git checkout mode is not evidence for produced-file mode.

## 29. VM probe ↔ generated observation parity

Step 7B.0 must not merely compare final PASS/FAIL.

On the same reference VM state, gate obtains per-control observations from:

1. canonical reference probe;
2. generated script.

For each of five controls compare at minimum:

- control id;
- observation status;
- typed observed value.

Any mismatch is FAIL unless a previously accepted `check-semantic-v1`
compatibility decision explicitly changes the reference probe first.

This parity evidence is tied to exact script/probe hashes.

---

## 30. VM evidence binding and installation variants

Read-only VM evidence requires its own integrity gate.

Evidence must bind at minimum:

- `build_contract_id`;
- `build_contract_version`;
- `build_contract_sha256`;
- build-environment contract id/version/SHA;
- build-runtime/toolchain identity;
- `STEP7B0-CONTROL-SET.lock` SHA-256;
- generated script SHA-256;
- BUILD-MANIFEST SHA-256;
- BUILD-SHA256;
- BUILD-INPUTS.lock SHA-256;
- builder SHA-256;
- target contract id/version;
- `installation_variant`;
- `installed_package_set_sha256`;
- runtime-invocation registry SHA-256;
- VM metadata;
- probe SHA-256;
- probe observations;
- generated observations;
- probe↔generated parity result;
- unsupported-target zero-control test evidence;
- supported-target runtime invocation-order evidence;
- runtime observer tool/version;
- observer invocation;
- raw full-syscall observer trace SHA-256;
- parsed read-only result;
- build-dependency observer contract/version for the producing build;
- hermetic build-environment admission result;
- external build staging identity only as evidence metadata, never as semantic input;
- evidence SHA256SUMS.

### 30.1. Exact Step 7B.0 installation-variant universe

Step 7B.0 still has exactly one target id: `ubuntu-24.04-x86_64`. Installation variant is **compatibility-test environment identity only**; it is not a second target authority, installer provenance, or a production security property. For that target the required variant enum and required evidence-pair set are exactly:

- `installation_variant = server`;
- `installation_variant = server-minimized`.

The laboratory VM test procedure/workpack is responsible for preparing a normal Ubuntu Server reference environment for `server` and a reduced-package Ubuntu Server reference environment corresponding to the installer Minimized use case for `server-minimized`. The Build Contract evaluates the resulting machine state and does not attest which ISO, installer workflow, cloud image, or provisioning path produced it.

Each required VM evidence package binds `installed_package_set_sha256`, defined as SHA-256 of a canonical installed-package snapshot from the tested machine. The snapshot contains exactly one UTF-8 record for every dpkg package whose status is exactly `install ok installed`, serialized as `<binary-package-name>\t<version>\n`, sorted by the UTF-8 bytes of the full record under locale-independent byte ordering, with no header, no blank lines and exactly one LF terminating every record. No package in any other dpkg state is included. The package snapshot is evidence metadata and is not a runtime input to the generated artifact.

Required Step 7B.0 VM evidence coverage is exact over:

`{(ubuntu-24.04-x86_64,server),(ubuntu-24.04-x86_64,server-minimized)}`.

A single VM run cannot satisfy both pair identities. The two required evidence packages must bind **different** `installed_package_set_sha256` values. Unknown/missing variant, duplicate pair standing in for the other variant, reused identical package-set digest, or missing/malformed package-set digest is FAIL. Correct laboratory image/installer selection is enforced by the VM test procedure/workpack rather than by Build Contract installer-provenance logic. Future Ubuntu 22.04/26.04 or Debian targets are outside Step 7B.0 and require their own accepted target contracts before they can enter this matrix.

### 30.2. Per-variant gate and outcome semantics

Every required `(target_id,installation_variant)` pair independently runs all applicable supported-target/read-only VM gates. At minimum each pair's evidence must independently contain and PASS:

- §29 probe↔generated parity;
- §17.8 supported-target runtime invocation/order and exact `/proc/sys/` attribution;
- the read-only/full-syscall runtime gate required by §§25/31;
- the §17.7 unsupported-target zero-control negative test under its accepted test harness/fixture;
- the integrity bindings listed in §30.

For the supported no-argument policy run on each required variant, VM-matrix acceptance requires a **complete evaluation**: `POLICY_STATUS` is exactly `COMPLIANT` or `NONCOMPLIANT`, and process RC is exactly `0`. Individual control `FAIL` findings are permitted and do not fail the matrix when evaluation is complete.

If any of the five required controls yields `NOT_FOUND` or `ERROR`, §5.3 still truthfully requires `POLICY_STATUS=UNEVALUATED` and `RC=1`; that runtime behavior is correct fail-closed behavior, but the required installation variant does **not** satisfy the Step 7B.0 VM matrix and the VM evidence gate is FAIL until the cause is resolved or a later audited target/applicability contract explicitly changes the requirement.

The evidence gate requires build-contract, build-environment and build-runtime identities to equal accepted root inputs pinned by release admission.

This proves binding/integrity of the evidence package, not cryptographic VM attestation.

Experimental filtered traces from Builder Spike v0.2 do not satisfy the mandatory full-syscall observer field for an authoritative PASS.

## 31. Generated-artifact gates

A Step 7B.0 authoritative artifact is not PASS until all are PASS:

1. accepted root Build Contract identity/SHA;
2. accepted build-environment contract as exact `both` input;
3. accepted measured build-runtime/toolchain closure;
4. external staging is outside read-only project root;
5. builder performs zero project-root writes;
6. protected FSTEC state invariant;
7. exact `STEP7B0-CONTROL-SET.lock` membership;
8. mechanical eligibility == pinned control set;
9. eligible-control/binding/block/manifest coverage closure;
10. build-binding closed schema;
11. derived binding→FSTEC block→emission-node exact relation;
12. emission-node global uniqueness;
13. exact normalized emission-edge semantics;
14. emission DAG closed/acyclic;
15. UTF-8-byte deterministic emission tie-break;
16. separate `runtime-invocation-v1` registry closure;
17. runtime order is not derived from emission DAG;
18. engineering-role closed set and exact emission mapping;
19. concrete accepted engineering-contract resolution;
20. target contract;
21. exact CLI/RC contract;
22. `check-semantic-v1`;
23. adapter compatibility;
24. origin conditional schema;
25. launcher ownership and line-1 exact exception;
26. template grammar/inertness;
27. exact 64-byte header placeholder fixture;
28. stable block-id derivation;
29. block marker/line schema;
30. marker-scan == manifest-range segmentation;
31. emitted-block ↔ emission-node exact closure;
32. textual structural preflight-before-FSTEC rule;
33. runtime dispatch preflight-before-control rule;
34. unsupported-target zero adapter/control and zero `/proc/sys/` access;
35. supported-target runtime sequence == `FINAL_RUNTIME_INVOCATION_ORDER`;
36. BUILD-INPUTS.lock required-set closure;
37. BUILD-INPUTS root-descriptor/self-cycle rule;
38. project dependency observer closure;
39. gate-only project inputs are not observed by builder;
40. project directory enumeration forbidden;
41. canonical sanitized environment;
42. exact interpreter/tool executable resolution;
43. no undeclared descendant helper exec;
44. inherited-FD closure;
45. builder network closure;
46. measured non-project path dependency closure;
47. every output-affecting external value is fixed/pinned/derived only;
48. non-path host-state event closure;
49. BUILD-MANIFEST exact schema;
50. `E == S == O == M` emission-order equality;
51. `R == V` runtime-order equality;
52. block SHA verification;
53. scaffolding SHA verification;
54. line-count/byte-binding verification;
55. exactly one manifest-hash header;
56. header manifest SHA == exact manifest file SHA;
57. embedded provenance field-wise parity;
58. engineering-role ↔ block-role provenance closure;
59. canonical serialization golden fixtures;
60. provenance-record-set-before-layout invariant;
61. deterministic double-build;
62. environment/metadata/path/host-state perturbation gate;
63. produced mode determinism;
64. `bash -n`;
65. pinned ShellCheck;
66. generated-artifact regression suite;
67. unsupported-platform fail-closed;
68. static read-only allow-list;
69. full-process-tree **full-syscall** runtime observer;
70. runtime inherited-FD baseline;
71. runtime observer loss/unknown-event fail-closed;
72. runtime network/host-state mutation closure;
73. probe↔generated observation parity;
74. VM evidence binding/integrity including root build/build-environment/build-runtime identities;
75. core build products exist only in external staging during builder execution;
76. publication has not been performed by builder.

Missing mandatory tool or evidence means FAIL, never SKIP/PASS.

## 32. Step 7B.0 build-product set and publication boundary

The authoritative builder, when eventually admitted, produces exactly these core files beneath one explicit **external staging root** outside project root:

- `securelinux-policy-check.sh`;
- `BUILD-MANIFEST.json`;
- `BUILD-SHA256`.

The staging root path itself is not serialized and is not semantic input.

The builder must not create or modify:

- project-root `dist/`;
- any other project-root file;
- a file named `securelinux-ng.sh`.

A future `publication-v1` contract may define a separate post-gate copy of exact, checksum-verified bytes from accepted staging into a release destination such as project `dist/` or a release package. Publication:

- is not builder behavior;
- must not transform bytes or modes;
- requires its own admission/authorization;
- is forbidden while this draft remains unaccepted and while authoritative builder is not admitted.

The name `securelinux-ng.sh` remains reserved for a future artifact whose APPLY/RESTORE semantic contracts, adapters and VM release gates are accepted.

## 33. Explicitly forbidden scope in Step 7B.0

Step 7B.0 does not:

- close any new FSTEC row;
- add a real disposition;
- implement quote-anchor;
- implement APPLY;
- implement RESTORE;
- publish generated build products into project root/release channels;
- activate mutating engineering contracts;
- build corporate population;
- introduce multi-index descriptor;
- copy donor implementation into template;
- claim a percentage of final-project completion.

---

## 34. Staged pre-builder admission lifecycle — exact 20 prerequisites

Build Contract v0.9.3 retains the v0.7/v0.8/v0.9 staged lifecycle unchanged: static admission, measurement-candidate implementation, dynamic admission and authoritative admission.

The prerequisite universe is exactly **20 logical items**. A prerequisite item may be a closed bundle containing multiple file-member identities under §18.5.1. Therefore `20 prerequisites` does **not** mean `20 physical files`; bundle members do not create implicit items 21/22.

### 34.1. Phase A — exact 16 static prerequisites

Architectural `BUILD_CONTRACT_V0_9_3_ERRATA = ACCEPT` authorizes creation/audit of exactly these 16 static items:

1. `STEP7B0-CONTROL-SET.lock`;
2. `check-semantic-v1`;
3. `cli-rc-v1`;
4. target contract `ubuntu-24.04-x86_64`;
5. exact `ENGINEERING-BINDINGS.tsv`;
6. required new/updated engineering contracts, including exact `main_dispatch` semantics;
7. `readonly-command-policy-v1`;
8. `readonly-runtime-observer-v1` with full-syscall parser/event policy and FD baseline;
9. `build-dependency-observer-v1` **closed cryptographic bundle/admission unit**, including exact observer contract, `build-dependency-observer-execution-identity-v1` descriptor, exact parser, exact profile/selector bytes, exactly one hash-bound `build-dependency-observer-classification-policy-v2` member, exact observer executable/runtime/config cryptographic identity, §18.6.1a fitness fixtures and fitness evidence bound to that identity and policy;
10. `build-environment-v1` with sanitized environment, exact interpreter invocation, inherited-FD/network rules, external-staging write boundary and static `host-state-surface-v1` pair requirements;
12. **serializer bundle**: exact `serializer-contract-v1` + exact inert template + exact closed golden-fixture member set (§13.2);
14. build-binding schema/instance for the five pinned controls;
15. emission node/edge schemas/instances with normalized emission-only semantics;
16. `runtime-invocation-v1` schema/instance with the §17.5 cross-registry identity equalities;
17. **adapter bundle**: exact adapter contract for `check × sysctl × ubuntu-24.04-x86_64` + exact adapter implementation bytes/SHA bound by that contract (§12.1);
20. positive/negative fixtures proving project-root write rejection and external-staging-only output, plus exact PASS evidence bound to that closed fixture set.

All 16 logical items must be independently admitted before Phase B. One checker invocation/workpack run may evaluate all 16, but its output must contain exactly one independent admission result for each item number in `{1,2,3,4,5,6,7,8,9,10,12,14,15,16,17,20}`. Each item result must bind/reference the complete §18.5.1 member rows for that item, including exact path/SHA/scope/projection, and must be independently `PASS` or `FAIL`. `PHASE_A_ACCEPTED` is true only when the item-number set is exact and every one of the 16 item results is `PASS`; one aggregate PASS, a missing item record, duplicate item record or inherited group-level status is insufficient.

For a bundle, `admitted` means every required member identity is hash-verified, its closed member relation is exact, all cross-member equalities hold, and all mandatory item fixtures/evidence PASS. Partial bundle admission is forbidden. Merely drafting a contract, listing member filenames, or passing other items cannot compensate for one failed/missing bundle member.

In particular, item 9 cannot be admitted unless the exact cryptographic observer execution identity passes all §18.6.1a fitness fixtures and the fitness evidence binds that same identity; item 20 cannot be admitted unless §18.5.4 evidence PASSes for the exact closed write-boundary fixture set. A text review, tool version string, unbound prior fitness result or workpack-level aggregate status is insufficient.

For §§34.2–34.3 the two Phase-A aggregate binding digests have exact byte subjects:

- `phase_a_members_sha256 = SHA256(exact bytes of step7b0/phase-a/PHASE-A-MEMBERS.json)`;
- `phase_a_admission_sha256 = SHA256(exact bytes of step7b0/phase-a/PHASE-A-ADMISSION.json)`.

Both named artifacts are the single accepted current Phase-A machine-evidence files at those canonical project paths, serialized as canonical JSON under §26.1 with exactly one final LF. The digest is over the **file bytes themselves**, not over a reconstructed projection, in-memory object, pretty-printed form, subset of rows, concatenation of item records or alternate serialization. Before Phase-B freeze creation the verifier must validate those artifacts under the current Build Contract and then hash the same validated bytes. A missing file, alternate path, non-canonical serialization, failed current-contract validation or byte change is FAIL.

### 34.2. Phase B — NON-RELEASE measurement candidate

Only after all 16 static prerequisites are admitted may one implementation candidate be written for measurement.

Requirements:

- status is exactly `NON_RELEASE_MEASUREMENT_CANDIDATE`;
- candidate source bytes are frozen and SHA-256 recorded **before** dependency measurement;
- candidate runs only under accepted `build-environment-v1` + `build-dependency-observer-v1`;
- the Phase-B freeze and measurement envelope bind exact `MEASUREMENT_BUILDER_PATHS` from §18.8, including all builder/both Phase-A bundle members and the earlier-admitted control manifest + five canonical control YAMLs;
- because item-9 classification policy is deliberately gate-only and therefore absent from `MEASUREMENT_BUILDER_PATHS`, the Phase-B freeze and every Phase-B measurement-evidence envelope additionally record and verify exact `phase_a_admission_sha256` and `phase_a_members_sha256` with the byte subjects defined in §34.1, plus exact `item9_classification_policy_sha256`; the policy SHA must equal the exact admitted item-9 `build_dependency_observer_classification_policy` member SHA;
- source index, closure contract, control schema and reference probe files remain gate-only and any candidate read of them is FAIL;
- candidate writes only to external staging and has no publication path;
- candidate cannot write `dist/`, cannot release, cannot APPLY/RESTORE, cannot expand FSTEC or create real dispositions;
- measurement outputs/evidence cannot be treated as release artifacts;
- experimental spike v0.1/v0.2 cannot be substituted for this candidate by rename;
- candidate is not authoritative and cannot claim authoritative status.

The candidate may implement the intended builder logic because that exact source SHA is what must be measured. This is not authoritative admission.

### 34.3. Phase C — exact 4 dynamic prerequisites

Using only the exact frozen candidate SHA from Phase B, create/audit exactly these four remaining items:

11. measured `build-runtime-v1` closure for external Python/runtime files plus complete mandatory/discovered host-state disposition surface;
13. `TOOLCHAIN.lock` bound to the measured build runtime and exact observer/sandbox identities;
18. final `BUILD-INPUTS.lock` schema/instance, root-descriptor rule and exact role/scope closure;
19. hermeticity perturbation matrix/evidence covering every admitted variable host-state class and every required non-syscall coverage mechanism.

After these four are drafted, rerun the same candidate source SHA under the proposed final dynamic closure. Any new dependency/channel, changed source SHA, trace loss, unresolved `REVIEW_REQUIRED` event or failed perturbation invalidates Phase C.

Additionally, the accepted Phase-B freeze and measurement envelope record the exact SHA-256 of every `MEASUREMENT_BUILDER_PATHS` member plus the exact `phase_a_admission_sha256`, `phase_a_members_sha256`, and `item9_classification_policy_sha256` required by §34.2. If the SHA-256 of **any** `MEASUREMENT_BUILDER_PATHS` member changes, or if any of those three Phase-A/item-9 binding hashes changes, prior Phase-B measurement evidence and all Phase-C dynamic prerequisite admissions derived from it are invalidated even when the canonical path set and candidate source SHA are unchanged. A gate-only classification-policy byte change therefore cannot reuse old Phase-B evidence merely because `MEASUREMENT_BUILDER_PATHS` is unchanged. Phase B measurement and Phase C derivation/rerun must then be repeated against the new exact admitted state before Phase D eligibility can be considered.

### 34.4. Phase D — authoritative admission

Only when all exact 20 prerequisites are independently admitted and all §31/§35 gates pass may the same frozen candidate source SHA become **eligible for a separate explicit authoritative-builder admission**.

Eligibility is not admission. No authoritative status is inferred from successful measurement.

Any candidate source-byte change after Phase C requires returning to Phase B/C and remeasuring dynamic closure before authoritative admission can be considered.

The accepted Build Contract v0.9.3 and accepted build-environment contract are exact `both` root inputs and must be pinned by exact SHA in final `BUILD-INPUTS.lock` before authoritative admission.

Architectural ACCEPT alone therefore authorizes Phase A work and, only after Phase A admission, Phase B measurement-candidate implementation. It never authorizes publication or authoritative status.

### 34.5. Post-freeze errata and evidence invalidation

An accepted Build Contract is immutable by byte identity. A real defect found after freeze is corrected only by a new version/SHA (for example a later `0.9.4-errata`); accepted contract bytes are never edited in place under the old identity.

Errata triage has exactly these operational classes:

- `REUSED` — permitted only for an individual Phase-A prerequisite admission whose exact subject/member bytes and member identities are unchanged, whose governing normative invariants are unchanged by the errata, and whose explicit impact check is `PASS`. Under the new contract version a new admission record references the reused underlying evidence; the old contract-bound admission record is not silently relabeled.
- `RERUN` — required whenever subject bytes, governing invariants, fixtures/evidence schema, or any required gate relevant to that item changed.
- `INVALIDATED` — old evidence cannot support the new contract identity and is retained only as historical evidence.

`REUSED` is never permitted for a generated BUILD-MANIFEST, final `BUILD-INPUTS.lock`, Phase-B measurement evidence, Phase-C dynamic prerequisite/evidence, or §30 VM evidence package when `build_contract_sha256` changed. Those objects bind/consume the Build Contract identity and must be regenerated or rerun under the new contract identity.

Independent of the reason for errata, §34.3 byte-drift invalidation applies: if any `MEASUREMENT_BUILDER_PATHS` member SHA changes, Phase-B measurement and all derived Phase-C admission are invalidated and repeated. Unchanged candidate source bytes may keep their source SHA, but that does not authorize reuse of measurement/dynamic evidence produced with a different measurement-input byte set.

No errata procedure authorizes publication, FSTEC expansion, real dispositions, APPLY/RESTORE or Phase-D authoritative status by itself.

## 35. Machine-checkable acceptance criteria

`B0-01` — root Build Contract v0.9.3 id/version/SHA is pinned and consumed as `both`.  
`B0-02` — accepted build-environment-v1 id/version/SHA is pinned and consumed as `both`.  
`B0-03` — FSTEC remains `349 / 5 / 344`, ledger rows `0`.  
`B0-04` — exact five control IDs/index IDs equal `STEP7B0-CONTROL-SET.lock`.  
`B0-05` — pinned set == mechanical eligibility == bindings == FSTEC blocks == manifest control records.  
`B0-06` — every runtime block has exactly one allowed origin.  
`B0-07` — conditional origin identity equality holds.  
`B0-08` — launcher/shebang has accepted engineering provenance.  
`B0-09` — only exact line-1 launcher may be executable outside generated blocks.  
`B0-10` — template matches exact inert grammar/placeholders.  
`B0-11` — manifest header placeholder is exactly 64 underscore bytes.  
`B0-12` — every engineering role resolves exactly once with exact emission mapping.  
`B0-13` — no PENDING donor contract is activated implicitly.  
`B0-14` — CLI/RC golden tests pass.  
`B0-15` — unsupported platform is RC 3 and executes zero FSTEC checks/adapters.  
`B0-16` — unsupported platform performs zero artifact-process `/proc/sys/` access.  
`B0-17` — policy findings are distinct from execution errors.  
`B0-18` — check-semantic-v1 is closed and machine-tested.  
`B0-19` — probe compatibility has no undisposed semantic mismatch.  
`B0-20` — one shared sysctl check adapter matches target/kind/semantic contract.  
`B0-21` — build binding derives exactly one matching FSTEC block and emission node.  
`B0-22` — emission_node_id and block_id are globally unique in emission node registry.  
`B0-23` — every emission edge endpoint resolves to exactly one emission node.  
`B0-24` — emit_before/emit_after/emit_requires normalize to exact `≺emit` relation.  
`B0-25` — emission DAG is closed and acyclic.  
`B0-26` — emission order uses UTF-8-byte block-id tie-break.  
`B0-27` — runtime-invocation-v1 has contiguous exact-one sequence closure and unique callable `block_id` rows.  
`B0-28` — runtime invocation authority is independent of emission DAG.  
`B0-29` — successful target_preflight precedes every runtime control invocation.  
`B0-30` — supported-target runtime invocation sequence equals runtime registry exactly and every `/proc/sys/` event is exactly attributed to its registered control row/path.  
`B0-31` — block ids derive only from stable identity components.  
`B0-32` — marker scan and manifest ranges produce identical segmentation.  
`B0-33` — block marker bytes/line ranges/hash semantics are exact.  
`B0-34` — embedded provenance is entirely inside hashed provenance_query block.  
`B0-35` — every provenance/source field satisfies exact field-wise parity.  
`B0-36` — emitted generated blocks == emission nodes exactly.  
`B0-37` — BUILD-INPUTS.lock exact required set/role/scope is reproducible.  
`B0-38` — BUILD-INPUTS.lock is excluded from its own record universe and manifest-bound.  
`B0-39` — build_contract and build_environment_contract cannot be gate-only when emitted.  
`B0-40` — build dependency observer captures the full process-tree syscall stream and derives declared project path/metadata/exec dependencies from it.  
`B0-41` — project directory enumeration by builder is forbidden.  
`B0-42` — gate-only project paths are not consumed by builder.  
`B0-43` — canonical environment suppresses undeclared caller/user-site state.  
`B0-44` — initial interpreter executable is exact/pinned and caller PATH cannot select builder tools.  
`B0-45` — no undeclared descendant helper executable can run.  
`B0-46` — inherited builder FDs match exact baseline.  
`B0-47` — builder network dependency is unavailable/fail-closed.  
`B0-48` — external non-project path closure is measured from the hash-frozen Phase-B candidate before being pinned, without requiring dynamic locks to create that candidate.  
`B0-49` — every admitted external regular-file dependency is crypto-pinned or runtime-root-bound.  
`B0-50` — no declared-but-floating output-affecting value exists.  
`B0-51` — every mandatory applicable or discovered host-state `(class_id, channel_kind)` pair has exactly one accepted disposition; absence from syscall trace is not exemption.  
`B0-52` — unknown/unclassified host-state event, channel, trace loss or missing mandatory-class coverage cannot PASS.  
`B0-53` — project root is read-only and builder writes only beneath external staging.  
`B0-54` — builder performs zero write/create/delete operations beneath project root.  
`B0-55` — BUILD-MANIFEST is exact closed build-manifest-v1.  
`B0-56` — manifest root-contract/build-environment/control-set identities equal locked accepted inputs.  
`B0-57` — `E == S == O == M` emission-order equality holds.  
`B0-58` — `R == V` runtime-order equality holds independently.  
`B0-59` — every generated block hash matches final script bytes.  
`B0-60` — scaffolding hash detects changed ordinary non-block bytes.  
`B0-61` — exactly one manifest-hash header exists.  
`B0-62` — header manifest SHA equals SHA-256 of exact BUILD-MANIFEST bytes.  
`B0-63` — script line count and byte-integrity binding are exact.  
`B0-64` — serializers/markers/checksum files match golden bytes.  
`B0-65` — provenance record set is finalized before final layout/hash calculation.  
`B0-66` — artifact-alone provenance query works under supported launch forms.  
`B0-67` — artifact has no apply/restore/output-filesystem surface.  
`B0-68` — static read-only allow-list rejects every unregistered construct.  
`B0-69` — runtime observer captures/classifies full process-tree **full syscall stream**.  
`B0-70` — runtime inherited FDs are restricted to defined stdin/stdout/stderr baseline.  
`B0-71` — file/FD/network/non-filesystem host-state mutations are rejected.  
`B0-72` — observer missing/loss/unknown event cannot PASS.  
`B0-73` — two clean admitted builds are byte-identical.  
`B0-74` — environment/metadata/path/host-state perturbations cover the mandatory surface and produce identical bytes or explicit FAIL.  
`B0-75` — produced modes are deterministic.  
`B0-76` — `bash -n` PASS.  
`B0-77` — pinned ShellCheck PASS.  
`B0-78` — generated-artifact regression suite PASS.  
`B0-79` — probe↔generated observations match on reference VM.  
`B0-80` — VM evidence binding includes exact root Build Contract, build-environment and build-runtime identities.  
`B0-81` — builder core product names are exact and exist only beneath external staging during build.  
`B0-82` — builder never publishes into `dist/` or another project/release destination.  
`B0-83` — Step 7B.0 closes zero additional FSTEC rows and creates zero real dispositions.  
`B0-84` — §34 lifecycle is exact: 16 static prerequisites → hash-frozen NON-RELEASE candidate → 4 dynamic prerequisites → separate authoritative admission; no bootstrap cycle remains.  
`B0-85` — every runtime-invocation row satisfies exact phase↔resolved-block field equalities; swapped control blocks and wrong engineering phase blocks are rejected structurally.  
`B0-86` — builder observer capture remains full-syscall/full-process-tree/exact-pinned; structural loss/undecodable/uncertain/forbidden events FAIL, while an otherwise trustworthy unknown event yields non-passing `REVIEW_REQUIRED` and does not stop complete inventory collection.  
`B0-87` — mandatory non-syscall host-state channels (including applicable vDSO/auxv/runtime-library/CPU-feature channels) are covered independently of syscall observation.  
`B0-88` — on supported target, every `/proc/sys/` access belongs to exactly one registered control invocation and exact bound sysctl path; no extra path is observed.  
`B0-89` — every `ordering_sensitive=true` host-state class is `DENIED` or `FIXED`; `PERTURBED_NONINFLUENTIAL` is forbidden for such classes.  
`B0-90` — Phase-A logical prerequisite bundles have exact closed member identities; item 12 binds serializer+template+golden fixtures and item 17 binds adapter contract+implementation without creating hidden prerequisite items.  
`B0-91` — Phase-B normalized project dependency path set equals exact `MEASUREMENT_BUILDER_PATHS`, including builder/both bundle members, root/environment inputs, exact pre-existing control manifest+five YAMLs and frozen candidate source; gate-only source/index/schema/probe paths are absent.  
`B0-92` — `HOST_STATE_ROW_KEY=(class_id,channel_kind)` is globally exact across disjoint static/dynamic row sets, and final keys equal mandatory-applicable ∪ discovered pairs including unobserved mandatory pairs.  
`B0-93` — Phase-A item 9 fitness proves exact positive inventory, unknown-event `REVIEW_REQUIRED` with a later sentinel still observed, `invariant_scope_overreach` → `REVIEW_REQUIRED`, and FAIL for startup/loss/undecodable/uncertain-attribution/parser-uncertainty/hard-deny/policy-override/invalid-effect-scope/review-evidence-binding/unsafe-policy-admission cases before Phase B.  
`B0-94` — Phase-A item 9 binds the exact observer executable/runtime/config cryptographic identity plus exact parser/profile/contract and separate classification-policy member used by fitness and Phase B; drift in any bound bytes cannot PASS.  
`B0-95` — Phase-C `TOOLCHAIN.lock` repeats the exact admitted Phase-A item-9 observer identity field-wise/digest-wise and separately repeats the exact classification-policy SHA; it cannot re-resolve identity or policy from version/profile labels.  
`B0-96` — every Phase-A project-file member matches exactly one allowed §18.5.2 item/`member_role` row with exact scope and multiplicity and exactly one unambiguous final-lock or admission-only disposition.  
`B0-97` — every non-admission-only Phase-A member projects to exactly one final `BUILD-INPUTS.lock` row with exact path/hash/scope/role, while every admission-only member path is absent from final `BUILD-INPUTS.lock`.  
`B0-98` — immediately before every observer launch/evaluation, explicitly including every §18.6.1a fitness-suite launch and every Phase-B/Phase-D launch, actual executable/runtime/parser/profile bytes are reverified under §18.6.1 and classification-policy bytes equal the admitted item-9 member SHA; fitness evidence records `prelaunch_identity_verification=PASS` only from those actual checks.  
`B0-99` — item-9 and item-20 fixture-set digests use the exact §18.5.3 canonical JSON bytes; two conforming implementations cannot choose different list serialization.  
`B0-100` — item-20 write-boundary evidence has exact one-to-one fixture/result closure and `overall_result=PASS` only when every positive fixture PASSes and every negative fixture FAILs as expected.  
`B0-101` — Phase A has exactly 16 independent item admission results for the exact §34.1 item-number set; a group/workpack aggregate cannot replace any item result.  
`B0-102` — VM compatibility evidence covers exactly both required `(ubuntu-24.04-x86_64,installation_variant)` pairs `server` and `server-minimized`; each binds an exact `installed_package_set_sha256`, the two required digests are different, and Build Contract does not treat installer/image provenance as a product security property.  
`B0-103` — every required installation variant independently satisfies §29, §17.8, read-only/full-syscall runtime evidence and §17.7 negative evidence; supported-run `UNEVALUATED/RC=1` fails the required VM matrix while complete policy FAIL findings with RC 0 are allowed.  
`B0-104` — any SHA change of any `MEASUREMENT_BUILDER_PATHS` member invalidates prior Phase-B measurement and all derived Phase-C admission regardless of unchanged path set/source SHA.  
`B0-105` — post-freeze errata uses a new Build Contract version/SHA; reuse is limited to unaffected Phase-A evidence under §34.5 and contract-bound BUILD-MANIFEST/BUILD-INPUTS/Phase-B/C/VM evidence is not reused across changed `build_contract_sha256`.  
`B0-106` — `runtime_members_sha256` is computed over exactly the standalone canonical JSON-value bytes specified by §18.5.3/§26.1, including exactly one final LF; alternate no-LF/CRLF/pretty representations cannot PASS.  
`B0-107` — `REVIEW_REQUIRED` is non-passing and can never authorize Phase A/B/C/D or publication; a trustworthy unknown event is inventoried without early parser termination, while any later forbidden/structural failure still dominates final outcome as FAIL.  
`B0-108` — the exact hash-bound item-9 classification policy cannot override the seven §18.6.1b security properties; `ADMITTED` has exactly the two R4 sources `INVARIANT_ADMITTED` and `POLICY_ADMITTED`; reviewed-safe data changes are item-9 subject changes, not parser-source edits or silent policy drift.  
`B0-109` — `operation_sensitive_events` is a closed hash-bound policy mapping from event name to exact zero-based top-level argument index; the operation component is the exact structurally extracted selected-argument text, so symbolic, hexadecimal, `_IOC(...)`, mixed-mask and future structurally valid forms need no selector-grammar/parser revision merely to enter `REVIEW_REQUIRED`; `EVENT_OPERATION_KEY` and `reviewed_safe_events` ordering are deterministic across conforming implementations.  
`B0-110` — every Phase-B freeze and measurement-evidence envelope binds SHA-256 of the exact validated bytes at `step7b0/phase-a/PHASE-A-ADMISSION.json`, SHA-256 of the exact validated bytes at `step7b0/phase-a/PHASE-A-MEMBERS.json`, and exact `item9_classification_policy_sha256`; drift in any of these invalidates prior Phase-B measurement/derived Phase-C evidence even when `MEASUREMENT_BUILDER_PATHS` and candidate source SHA are unchanged.  
`B0-111` — `POLICY_ADMITTED` requires an exact `reviewed_safe_events` key, one closed safe `effect_scope`, exact admitted item-9 fixture path/SHA that reproduces the key, and proof that all records sharing the key stay inside that scope; hard-deny completeness is not a safety premise and an omitted dangerous event cannot PASS by omission.  
`B0-112` — `INVARIANT_ADMITTED` requires `invariant_coverage=COMPLETE` against the exact closed union of six `effect_scope` tokens and seven `security_properties`; partial invariant success, uncovered/ambiguous effect-relevant arguments or fields, or an effect outside that closed universe cannot PASS and yields `REVIEW_REQUIRED` unless a known invariant violation makes the record FAIL.  

Any violation is `REVISE`, not warning.

## 36. Mandatory adversarial audit cases

Auditor must at least try the following.

### 36.1. Write boundary / publication

- choose staging inside project root;
- symlink staging back into project root;
- make builder create `dist/`;
- make builder overwrite an existing project file;
- run with project root physically read-only;
- run on a `noexec` but writable staging and ensure build itself remains valid;
- attempt to treat successful build as implicit publication.

### 36.2. Root inputs / scope

- mark root Build Contract `gate` while manifest still emits its identity;
- mark build-environment contract `gate` while manifest still emits its identity;
- alter accepted root/build-environment bytes without changing pinned SHA and require fail-closed;
- add unknown `consumption_scope`.

### 36.3. Environment/runtime closure and staged measurement

- require `build-runtime-v1` before Phase-B candidate exists and verify the cycle is rejected;
- attempt Phase-B candidate before all exact 16 static prerequisites are admitted;
- change one candidate source byte after runtime measurement and try to reuse Phase-C evidence;
- try to treat a successful measurement candidate as authoritative or published;
- add caller env variable and branch on it;
- change caller HOME;
- enable user-site/sitecustomize;
- shadow a helper in caller PATH;
- add undeclared external file;
- substitute an external runtime file without updating pin;
- use package/version label without byte/digest pin;
- inherit unexpected writable FD;
- permit network and branch on result;
- vary cwd/staging path.

### 36.4. Non-path and non-syscall host state

Attempt to make the build observer use a `%file`/named-syscall filter and require FAIL.

For every mandatory class — including one not visible as an ordinary syscall — attempt an unclassified or floating case involving representative:

- `getrandom`;
- time source;
- uid/gid;
- pid/ppid;
- uname;
- rlimit;
- affinity/sysinfo;
- vDSO-backed time;
- auxv/bootstrap identity;
- runtime-library/CPU-feature dispatch.

Try omitting a mandatory applicable `(class_id, channel_kind)` pair solely because the syscall trace did not show it; this must FAIL.

For a multi-channel class such as time, require separate exact coverage for applicable `syscall` and `vdso` pairs. Try representing both with one class-only row, duplicate the same pair, collide static/dynamic ownership of one pair, or discover a Phase-C pair without adding its required dynamic row/evidence; each must FAIL.

Try marking an ordering/iteration/selection-sensitive class `PERTURBED_NONINFLUENTIAL`; this must FAIL.

A non-ordering-sensitive class may PASS only through accepted `DENIED`, `FIXED` or `PERTURBED_NONINFLUENTIAL` disposition with required evidence. An ordering-sensitive class may PASS only through `DENIED` or `FIXED`.

### 36.5. Emission order versus runtime order

- change emission graph while preserving runtime registry and verify runtime authority does not silently follow graph;
- change runtime registry while preserving emission graph and verify runtime tests detect it;
- duplicate emission_node_id;
- ambiguous emission edge endpoint;
- verify `emit_after A→B` normalizes as `B ≺emit A`;
- verify `emit_requires A→B` normalizes as `B ≺emit A` only for emission;
- create emission contradiction/cycle;
- create runtime sequence gap/duplicate;
- swap two valid control `block_id` values while keeping their `control_id` values unchanged;
- point `target_preflight` row at a different valid engineering runtime block;
- point `aggregation` row at a different valid engineering runtime block;
- call one control before preflight while text order remains correct;
- reorder runtime controls relative to runtime registry while emission bytes remain structurally valid.

### 36.6. Pinned control membership / coverage

- replace one original CLOSED control with a different CLOSED control while preserving `349 / 5 / 344`;
- change one pinned control_id→index_id mapping;
- remove/add/duplicate binding;
- make mechanical eligibility differ from control-set lock.

### 36.7. Build dependency closure and observer fitness

- use filtered builder tracing and falsely claim full closure;
- hide a dependency in a vDSO/auxv/runtime-library channel not visible to syscall filtering;
- inject observer startup failure and require FAIL;
- inject trace truncation/event loss and require FAIL;
- feed an unknown syscall/event followed by a known sentinel and require final `REVIEW_REQUIRED`, complete review inventory containing the unknown key, and the later sentinel still observed;
- feed undecodable arguments and require FAIL;
- create uncertain FD→path/process attribution and require FAIL;
- create parser ambiguity/uncertainty and require FAIL;
- place a hard-deny event in `reviewed_safe_events` and require FAIL;
- omit a dangerous event such as `acct`, `swapon` or a namespace-creating `clone3` form from hard-deny and verify that omission alone cannot produce `ADMITTED`;
- give a reviewed-safe entry an unknown `effect_scope` and require FAIL;
- give a reviewed-safe entry a missing/wrong fixture path or SHA, or a fixture that does not reproduce the exact key, and require FAIL;
- try to policy-admit an argument-dependent event using a key that does not capture the effect-changing argument/structure and require FAIL or `REVIEW_REQUIRED`, never `ADMITTED`;
- resolve only one aspect of an event by invariant while leaving another effect-relevant argument/field outside the thirteen closed effect-coverage categories or otherwise unresolved; require `REVIEW_REQUIRED`, never `INVARIANT_ADMITTED`;
- attempt to use a reviewed-non-effectful entry to bypass project-write, undeclared sink, network, exec, directory-enumeration or process-tree closure and require FAIL;
- change classification-policy bytes without item-9 re-admission/fitness and require FAIL before Phase B;
- positive synthetic fixture: remove one known event and verify exact event-inventory comparison fails rather than silently accepting the shorter trace;
- replace the observer executable with different bytes reporting the same tool/version and require FAIL before Phase B;
- keep descriptor/version unchanged but alter the actual resolved executable bytes and verify direct pre-launch `SHA256(actual bytes) == executable_sha256` fails in both identity modes;
- run the §18.6.1a fitness suite with actual observer executable bytes whose SHA differs from admitted `executable_sha256`, while descriptor/version fields still match, and require FAIL before the fitness launch/evidence can PASS;
- serialize `runtime_members` canonical JSON without the required final LF (or with CRLF/pretty JSON) and require `runtime_members_sha256` mismatch/FAIL;
- keep the same item-9 fixture members but serialize their aggregate set using tuple text, pretty JSON, CRLF or another ordering and require digest mismatch/FAIL;
- replace one behavior-affecting observer runtime/library/config byte without updating the admitted binary-closure/runtime-root identity and require FAIL;
- reuse fitness evidence after changing observer executable/runtime-root/parser/profile identity and require FAIL;
- create a Phase-C `TOOLCHAIN.lock` whose observer version/profile matches but executable/runtime-root/runtime-members/parser/profile digest differs from Phase-A item 9 and require FAIL;
- add an unknown Phase-A `member_role` and require FAIL;
- move a valid `member_role` token under the wrong prerequisite item and require FAIL;
- change a member's exact `consumption_scope` and require FAIL;
- violate an `exactly_one`/`one_or_more` multiplicity and require FAIL;
- omit or ambiguously set `build_inputs_role`/`admission_only` projection and require FAIL;
- place an `admission_only=true` member path into final `BUILD-INPUTS.lock` under any role and require FAIL;
- omit or role/scope-misproject a required final-lock member and require FAIL;
- `stat/access/readlink/xattr/execve` undeclared project file;
- enumerate project directory;
- omit adapter implementation or exact template from the admitted Phase-A bundle and then attempt to read it in Phase B;
- mutate a bundle member without updating its bound SHA;
- read one of the five canonical control YAMLs while omitting it from `MEASUREMENT_BUILDER_PATHS`;
- read `CONTROL-SCHEMA.json`, source index, closure contract or reference probe as if it were a Phase-B builder input;
- query undeclared external host file;
- execute undeclared helper;
- use caller PATH to select another executable;
- depend on network availability;
- depend on caller env variable.

### 36.8. Phase-A admission, write-boundary evidence, VM variants and errata

- emit one workpack-level PASS while omitting one of the exact 16 independent Phase-A item results and require FAIL;
- duplicate one Phase-A item result and omit another while preserving count 16 and require exact item-set FAIL;
- omit one item-20 negative fixture result while leaving `overall_result=PASS` and require FAIL;
- relabel an item-20 negative fixture as positive without changing its bytes/path and require fixture-set/evidence mismatch FAIL;
- add an extra result not present in the admitted item-20 fixture set and require FAIL;
- provide only `installation_variant=server` evidence and claim Step 7B.0 VM matrix complete; require FAIL;
- reuse one VM run/evidence package for both installation-variant identities; require FAIL;
- give both required variant evidence packages the same `installed_package_set_sha256` while changing only the `installation_variant` label and require FAIL;
- omit or malform `installed_package_set_sha256` and require FAIL;
- on `server-minimized`, force one required sysctl observation to `NOT_FOUND`, obtain truthful `UNEVALUATED/RC=1`, and verify that the required variant matrix FAILS rather than treating fail-closed runtime behavior as matrix PASS;
- change bytes/SHA of a non-source `MEASUREMENT_BUILDER_PATHS` member without changing any path or candidate source SHA and attempt to reuse Phase-C evidence; require FAIL;
- change `build_contract_sha256` under an errata and attempt to reuse old BUILD-MANIFEST, final BUILD-INPUTS.lock or VM evidence as current evidence; require FAIL;
- reuse an unchanged Phase-A admission under errata without an explicit unchanged-invariants impact PASS; require FAIL.

### 36.9. Manifest/order/integrity

- reverse only `emission_block_ids`;
- alter only `runtime_invocation_block_ids`;
- permute only blocks array;
- marker-like line inside block body;
- marker scan disagreement;
- second manifest-hash header;
- alter only header manifest SHA;
- mutate provenance record set after layout.

### 36.10. Origin/provenance

- mismatch origin id;
- use third origin type;
- alter locator/quote/index/adapter field only;
- provenance outside provenance_query block;
- make provenance query depend on sidecar.

### 36.11. Read-only runtime

- output redirection to filesystem;
- sysctl -w;
- tee/truncate/chmod/chown;
- write-family syscall;
- writable shared mmap;
- unexpected inherited FD;
- signal external process;
- netlink/ioctl/time/hostname/BPF/module mutation;
- observer startup failure;
- truncated/unknown trace event;
- show that a `%file`-only trace cannot be accepted as full-syscall proof;
- on a supported target, add a hidden sixth read under `/proc/sys/` while keeping five valid result records and require FAIL.

### 36.12. Determinism / serialization

- different allowed staging/cwd;
- input mtime/mode/parent mtime changes;
- variable host-state perturbation;
- JSON separators/ensure_ascii changes;
- checksum order change;
- produced mode change;
- ShellCheck config change without pinned input update.

The auditor must attack the least-constrained relevant field/layer first and must not classify a case as safe merely because a later unrelated check rejects it.

## 37. Questions for independent audit of v0.9.3 errata

This is a targeted post-freeze errata audit. The auditor must compare exact v0.9.2 frozen bytes against v0.9.3 and attack both the changed observer semantics and any unintended downstream inconsistency.

1. Does a trustworthy unknown/unreviewed syscall/event produce non-passing `REVIEW_REQUIRED` while parsing continues through later trustworthy records, rather than PASS or first-unknown early termination?
2. Do loss/truncation/startup failure, undecodable arguments, uncertain FD/path/process attribution, parser uncertainty, security-property violations and hard-deny events remain FAIL with precedence over `REVIEW_REQUIRED`?
3. Can `REVIEW_REQUIRED` ever authorize Phase A/B/C/D, publication, release or authoritative status? Any such path is a blocker.
4. Is `build_dependency_observer_classification_policy` exactly one closed item-9 hash-bound member, absent from builder consumption, bound into fitness evidence and repeated by `TOOLCHAIN.lock`, without illegally extending the execution-identity descriptor?
5. Can `reviewed_safe_events` override any of the seven §18.6.1b security properties or any non-overridable invariant? It must not. Are the only two `ADMITTED` sources exactly `INVARIANT_ADMITTED` and `POLICY_ADMITTED`?
6. Are `operation_sensitive_events`, `EVENT_OPERATION_KEY`, exact zero-based argument selection, exact selected-argument text extraction, deterministic reviewed-safe sorting, structural decode failure, hard-deny precedence and unknown-event disposition sufficiently closed for independent implementations to agree, including symbolic, hexadecimal, `_IOC(...)` and mixed-mask selector text?
7. Does the positive allowlist model fail closed when hard-deny is incomplete? Attack with `acct`, `swapon`, namespace-creating `clone/clone3`, or another omitted dangerous event. Absence from hard-deny must never be enough for `ADMITTED`; invalid/unknown effect scope, insufficient argument discrimination, invariant-governed behavior or bad review-evidence binding must block policy admission.
8. Does the unknown-event fitness fixture prove complete inventory by requiring a later sentinel after the unknown event?
9. Is a classification-policy byte change correctly treated as item-9 `RERUN` and does the Phase-B freeze/evidence explicitly bind the exact-byte subjects `step7b0/phase-a/PHASE-A-ADMISSION.json` and `step7b0/phase-a/PHASE-A-MEMBERS.json` plus `item9_classification_policy_sha256`, forcing downstream re-freeze/invalidation rather than parser-source edit or silent policy mutation?
10. Are §18.12, §27 and §30.2 normative semantics unchanged apart from mechanical root-version references, with aggregated perturbation/runtime-root/gate-only implementation choices remaining legal under their existing text?
11. Does §34.5 correctly invalidate contract-bound Phase-B/C/VM evidence across the changed Build Contract SHA while allowing only explicit per-item `REUSED` decisions for unaffected Phase-A prerequisites?
12. Are the v0.9.2 implementation blockers (`observer_identity_id`, FD/sink attribution, terminal trace closure, exact interpreter binding, raw fitness evidence/exact inventory) still required rather than accidentally waived by the errata?
13. Apart from the explicit errata and mechanically required version/cross-reference text, is unaffected v0.9.2 normative content bytewise unchanged?

## 38. Required audit verdict

Return exactly one top-level verdict:

`BUILD_CONTRACT_V0_9_3_ERRATA = ACCEPT`

or

`BUILD_CONTRACT_V0_9_3_ERRATA = REVISE`

For every blocker include:

- `B0C93E-Bxx`;
- literal violated invariant;
- minimum counterexample;
- class: schema/model/semantic/ordering/provenance/integrity/runtime/serialization/hermeticity/publication;
- minimum contract correction;
- explanation of why safety must not depend on a later unrelated check.

`ACCEPT` authorizes only the **staged lifecycle in §34**:

- Phase A: creation/audit of the exact 16 static prerequisites under the closed v0.9.3 errata member schema;
- after all 16 are independently admitted, Phase B: implementation of one hash-frozen NON-RELEASE measurement candidate;
- Phase C: creation/audit of the exact 4 dynamic prerequisites from that same candidate SHA.

`ACCEPT` does **not** itself authorize authoritative-builder status. Authoritative admission remains a separate Phase-D decision after all exact 20 prerequisites and all required gates pass.

It also does **not** authorize:

- publication;
- FSTEC mass expansion;
- real dispositions;
- APPLY/RESTORE.
