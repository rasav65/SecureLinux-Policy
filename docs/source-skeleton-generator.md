# Index-generic source skeleton generator

Roadmap step 5 introduces the canonical producer of a control record's
`source:` block.

## Contract

For a supported source-index row, `tools/source_skeleton_generator.py`
derives:

- `index_id`;
- `doc_id`;
- `doc_sha256`;
- `locator`;
- canonical `quote`;
- `quote_sha256`;
- `norm`.

The index path is an explicit CLI input (`--index`); `index/source-v4` is only
the current default. The generator therefore consumes the common source-index
contract rather than a FSTEC-only hard-coded index path.

The generator is the **single normative producer** of `source:` for supported
unit kinds. This step does not yet make a hand-edited committed block
mechanically impossible. That enforcement belongs to the immediately following
`SOURCE_BLOCK_REGENERATION_PARITY` step.

## Current extraction scope

The current source index contains 349 rows and 13 `unit_kind` values.

This version supports exactly one kind:

`numbered-position`

Current measured scope:

- rows of this kind: 74;
- exact extraction: 72;
- refused: 2;
- current accepted pilot controls reproduced byte-for-byte: 5/5.

The two refused rows are:

- `SRC-0001` / `2.1.1`;
- `SRC-0133` / `6.2`.

Both spans cross page furniture and end with a bare page number in `norm-v1`.
The generator refuses rather than guessing which trailing integer is page
furniture.

The other 12 unit kinds remain unsupported by this version. No claim of
automatic quote generation is made for those rows.

## Boundary rule for numbered-position

A number-looking token becomes an outline boundary only if it is a legal
structural successor of the previous accepted marker: first child, next
sibling, or next sibling of an ancestor.

This prevents values such as `kernel.dmesg_restrict=1.` and document/page
numbers from silently becoming unit boundaries.

## Trust chain

Before emitting a block, the generator validates fail-closed:

- exact source-index field contract and unique `index_id`;
- `quote_anchor_ready=YES`;
- pinned `normalizer-v1.py` SHA and its selftest;
- recovered/extracted corpus selection by `text_quality`;
- manifest source SHA and normalization metadata;
- normalized-corpus SHA;
- canonical norm-v1 quote;
- quote substring membership in the selected normalized corpus.

Physical verification of the pinned PDF file itself remains Gate 1's
responsibility; the generator deliberately does not hard-code a FSTEC PDF
directory so that the index input remains layer-generic.

## Regression evidence

`tests/source-skeleton-v1/test_source_skeleton_generator.py` permanently checks:

- five byte-identical pilot blocks;
- 72 exact / 2 refused supported rows;
- the known `SRC-0018` quote hash;
- use of an alternate index path;
- duplicate-index rejection;
- `quote_anchor_ready != YES` rejection;
- altered-normalizer rejection;
- corrupted normalized-corpus hash rejection.

This step closes zero FSTEC source rows. Normative progress remains
349 total / 5 controlled CLOSED / 344 OPEN.
