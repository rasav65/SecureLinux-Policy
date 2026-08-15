# release-v1

Mandatory release/audit validation with a real JSON Schema Draft 2020-12
implementation.

Run:

```bash
python3 -B checker/release-v1/real_jsonschema_gate.py \
  --project-root . \
  --json-out checker/release-v1/RELEASE-EVIDENCE.json
```

`jsonschema` absence is a hard failure, never a skip.
