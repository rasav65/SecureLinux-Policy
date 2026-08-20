# roadmap-v3 regressions

These tests protect semantic roadmap/documentation invariants without pinning
presentation details such as exact Russian status phrases or Mermaid block
counts.

They verify:

- authoritative roadmap order and statuses from `ROADMAP-v3.tsv`;
- current source/control/adapter counts against machine truth;
- `PROJECT-MAP-v3.md` as the primary current architecture map;
- `ARCHITECTURE-DIAGRAMS.md` as donor/future runtime reference;
- engineering donor adoption as non-normative provenance.
