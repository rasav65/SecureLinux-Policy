# engineering-tests-v1 tests

`test_donor_test_suite.py` mechanically verifies the pinned v16.2.11 ZIP,
all 38 donor tests, the 36/36 smoke wiring, the 32 generalized contract rows,
legacy normative isolation, and the active portable SHA helper.

`portable-sha256-regression.sh` is the donor test adopted directly because it
tests only `tools/write-sha256.py` and has no dependency on the old monolithic
script.

These tests do not claim that future apply/restore contracts are implemented.
They only prevent losing the donor evidence and registry while v3 is built.
