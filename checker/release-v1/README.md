# release-v1

Обязательная release/audit validation с реальной реализацией JSON Schema Draft
2020-12.

Запуск:

```bash
python3 -B checker/release-v1/real_jsonschema_gate.py \
  --project-root . \
  --json-out checker/release-v1/RELEASE-EVIDENCE.json
```

Отсутствие `jsonschema` является hard failure и никогда не превращается в skip.

Минимальная поддерживаемая version distribution: `jsonschema 4.10.3`; более
низкие или непарсируемые versions завершаются fail-closed.
