# engineering-donor-v1 tests

`test_donor_index.py` verifies:

- exact donor SHA and 18,928-line count;
- all 310 function-index rows against the donor source;
- complete 190-chunk coverage of all donor bytes/lines;
- 141 semantic candidate rows and 478 raw-evidence rows;
- all engineering contracts point at real donor markers and remain
  `PENDING_NOT_ACTIVE`;
- the original final architecture review archive SHA and extracted member SHA;
- the archived `architecture-regression.sh` passes unchanged against the pinned
  donor script and archived `docs/architecture.md`.

The test does not treat any donor item as a FSTEC control.

`test_donor_index.py` дополнительно проверяет candidate `DONOR_TO_V3_MAPPING`:

- 310/310 donor-функций с exact segment SHA;
- 38/38 donor test files с exact SHA;
- все 20 `ENG-*` и 32 `TST-*` contracts;
- все 16 mandatory mature families;
- только `REUSE | ADAPT | REJECT | DEFER`;
- `normative_effect=NONE`, `closes_source_rows=0`;
- `password-policy-regression.sh` остаётся `DEFER` для будущей
  corporate/APPLY-фазы;
- status `BUILT_AWAITING_REVIEW` не разрешает roadmap step 8.
