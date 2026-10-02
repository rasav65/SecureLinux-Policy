# Тесты release-v1

`test_real_jsonschema_gate.py` является регрессионным тестом только для RELEASE.

Он требует реально установленный `jsonschema.Draft202012Validator`,
соответствующий минимальной версии из `requirements-release.txt`. Тест также
моделирует отсутствие зависимости и версию ниже минимальной, чтобы доказать
fail-closed поведение.

Запуск через общий runner:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B tests/run-all.py --release
```

`BLOCKED_ENVIRONMENT` означает, что эта машина не может выполнить
RELEASE-валидацию; это не превращает RELEASE-gate в ошибку проекта на этапе DEV.
