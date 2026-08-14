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
