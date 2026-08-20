# Source-block regeneration parity regression

Permanent regression for roadmap step 6.

Positive coverage requires the complete current control population from
`CONTROL-MANIFEST.tsv` to regenerate byte-for-byte. The regression must not
pin a historical control count.

Negative fixtures prove fail-closed behavior for:

- `quote` mutation;
- `quote_sha256` mutation;
- `locator` mutation;
- unsupported `unit_kind`;
- missing index row;
- duplicate/malformed top-level `source:` block.
