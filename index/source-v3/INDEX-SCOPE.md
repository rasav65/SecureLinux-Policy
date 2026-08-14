# Source index v1

`SOURCE-INDEX.tsv` is the closure population for the new v3 model.

Rules:
- one row is one independently accountable source structural unit;
- a row starts `OPEN`;
- a row may become `CLOSED` only after it has either:
  1. at least one accepted v3 record, or
  2. an explicit non-technical / organizational / external / out-of-scope /
     informational disposition with a reason;
- `CLOSED_INDEX_ROWS / TOTAL_INDEX_ROWS` is the project transition metric;
- framework sources are registered separately in `FRAMEWORK-SOURCES.tsv`
  and are not one-control-per-clause populations;
- Methodology Appendix 2 MEASURE_CLASS_MAP (96 measures, K3/K2/K1) remains
  a separate future gate and is not mixed into control records;
- tables, figures and appendices explicitly listed in SOURCE-INDEX.tsv are
  retained so they cannot disappear merely because they are not ordinary
  numbered clauses;
- no row in Step 3 is a migrated control.

Known text-layer blockers:
- fstec-linux-2022
- fstec-vulnerability-analysis-2025

Their numeric structure is indexable, but the extracted Cyrillic text is
garbled. Therefore their rows have `quote_anchor_ready=NO`; Gate 1 must not
pretend that a human-readable literal quote can be proven against those
garbled norm-v1 texts.

## source-v2 text recovery

`source-v2` supersedes only the quote-anchor readiness metadata of `source-v1`.
The 349-row population and every source/unit/locator identity are unchanged.

The 101 formerly blocked rows use the recovered `norm-v1` representations under
`sources/recovered-v1/`. No source row was closed and no control was created.

## source-v3 — Step 5 sysctl pilot

Population remains 349 rows. Exactly five FSTEC-LINUX-2022 rows are CLOSED because one active control represents each row. The other 344 rows remain OPEN.
