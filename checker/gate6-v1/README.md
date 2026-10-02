# Gate 6 — привязка evidence

Запуск:

```bash
python3 -B checker/gate6-v1/evidence_binding.py \
  --project-root . \
  --evidence-dir probes/sysctl-v1/evidence/ubuntu-24.04.4-minimal-testmin-20260814
```

Ожидаемый current result:

`GATE6=PASS evidence_binding ... metadata_bindings=4 result_documents=2 errors=0`

Строка `VM_ORIGIN_ATTESTATION=NOT_PROVEN` обязательна и не является failure.
