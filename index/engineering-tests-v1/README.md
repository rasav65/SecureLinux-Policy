# engineering-tests-v1

Machine inventory of the final SecureLinux-NG v16.2.11 regression suite used
only as an engineering donor for SecureLinux-Policy v3.

Facts pinned from the uploaded artifact:

- ZIP SHA-256: `1b25f554a5ad1509037aa9613b7851a595159fd44291913cc2dba63280e50494`
- donor script: 18 928 lines, SHA-256 `f3be8723cd5a2be499e9e8e6370fad712bdec8afd68050f27af6a3e2d6fbc34b`
- 38 test files / 11 420 lines / 305 334 bytes
- 36 `*-regression.sh` files
- `tests/smoke.sh` invokes all 36 regression files exactly once
- 32 generalized engineering test contracts

Normative isolation is mandatory: legacy `fstec-mapping-regression.sh` and
`wheel-fstec-regression.sh` are historical evidence only. They cannot create
or close v3 FSTEC source-index rows.

`DONOR-VM-EVIDENCE.tsv` records donor-project VM history only; it never
substitutes v3 Gate 5 or the v3 final VM matrix.
