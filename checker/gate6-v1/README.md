# Gate 6 — evidence binding

Run:

```bash
python3 -B checker/gate6-v1/evidence_binding.py \
  --project-root . \
  --evidence-dir probes/sysctl-v1/evidence/ubuntu-24.04.4-minimal-testmin-20260814
```

Expected current result:

`GATE6=PASS evidence_binding ... metadata_bindings=4 result_documents=2 errors=0`

The line `VM_ORIGIN_ATTESTATION=NOT_PROVEN` is mandatory and is not a failure.
