# Evidence binding

`Gate 6 / evidence_binding` closes the gap between a valid probe-results JSON
and the evidence package that claims to describe how it was produced.

It binds:

`VM-METADATA.txt -> probe.py -> probe-plan.tsv -> privileged result -> unprivileged result -> evidence/SHA256SUMS`

This is an integrity/binding guarantee only. It is intentionally **not** a
cryptographic attestation that the files originated from the named VM.

The current implementation is scoped to the factual `sysctl-v1` pilot
evidence. New probe kinds must define their own evidence metadata/result
contracts before being accepted by this gate.
