# jsonschema 4.26.0 compatibility evidence — 2026-08-15

This directory retains a compatibility run of the updated mandatory
real-jsonschema release gate using `jsonschema==4.26.0`.

The compatibility interpreter is supplied explicitly to the installer and is
verified to contain exactly version 4.26.0 before the run.

An earlier attempt from a venv under `/tmp` is intentionally not retained as
validator evidence: on the tested host `/tmp` is mounted `noexec`, so the
native `rpds` extension could not be mapped. The retained PASS is produced from
an executable filesystem.

This evidence is compatibility evidence and closes 0 FSTEC source rows.
