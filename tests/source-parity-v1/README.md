# Source-block regeneration parity regression

Permanent regression for roadmap step 6.

Positive coverage requires all five current controls to regenerate
byte-for-byte.

Negative fixtures prove fail-closed behavior for:

- `quote` mutation;
- `quote_sha256` mutation;
- `locator` mutation;
- unsupported `unit_kind`;
- missing index row;
- duplicate/malformed top-level `source:` block.
