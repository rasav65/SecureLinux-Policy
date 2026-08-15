# Source-block regeneration parity

Roadmap step 6 mechanically enforces the step-5 single-writer rule for
committed `source:` blocks.

The checker:

- loads the canonical source skeleton generator through `tools/SHA256SUMS`;
- loads the selected source index through the generator's common index
  contract;
- discovers committed control YAML files;
- regenerates `source:` for every control whose `unit_kind` is supported;
- requires byte-for-byte equality with the committed block;
- fails closed for unsupported unit kinds, missing index rows, malformed
  `source:` blocks, generation errors, or any byte mismatch.

Current closure scope is the five existing pilot controls. All five use
`unit_kind=numbered-position`, which is supported by the generator, and all
five match byte-for-byte.

An unsupported control is not silently skipped. It is reported as
`UNSUPPORTED` and makes parity fail until that unit kind has a reviewed
generator rule.

This checker does not close source-index rows and does not change Gate 1–6
semantics. It protects the provenance block that those gates consume.
