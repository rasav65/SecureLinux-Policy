# Обязательный release gate с реальным jsonschema

## Назначение

Этот gate превращает optional real-validator check, используемый при
разработке, в **обязательный fail-closed release/audit gate**.

Тесты разработки/unit tests по-прежнему могут пропускать случаи, специфичные для
реального `jsonschema`, при отсутствии зависимости. Закрытие release/audit — не может.

## Обязательная зависимость

Gate обязан успешно импортировать установленный distribution `jsonschema` и
использовать `jsonschema.Draft202012Validator`.

Версия distribution читается через `importlib.metadata.version("jsonschema")` и
записывается в release evidence.

Если зависимость отсутствует, затенена локальным модулем проекта или её версия не
может быть определена, gate завершается FAIL. Резервного перехода на emulator нет.

## Проверки

Gate проверяет:

1. `CONTROL-SCHEMA.json` объявляет Draft 2020-12.
2. `Draft202012Validator.check_schema()` принимает committed schema.
3. Сохраняется parity generation Gate 0: committed schema == `checker.render_control_schema()`.
4. Существующая differential matrix содержит как минимум 50 случаев и 16 граничных случаев newline/CR.
5. Каждый current `kind` из `KIND_RULES` имеет принимающее и отклоняющее покрытие.
6. Runtime-решение совпадает с решением реального `Draft202012Validator` для всей matrix.
7. Внутренний schema emulator совпадает с реальным validator для matrix.
8. Каждый active control принимается и runtime closure, и реальным `Draft202012Validator`.

## Доказательства

`RELEASE-EVIDENCE.json` фиксирует:

- установленную версию `jsonschema`;
- версию Python;
- валидатор/черновик;
- SHA-256 schema, checker, differential test и release gate;
- числа и расхождения matrix;
- числа проверок active controls;
- результаты всех проверок.

Timestamp не записывается.

## Область действия

Этот gate валидирует current control schema/runtime contract. Он не меняет FSTEC
source coverage, не закрывает rows Gate 2 и не реализует новые probe kinds.

## Минимальная версия

Минимальная поддерживаемая version distribution `jsonschema`: **4.10.3**.

Release gate принимает только стабильные строки версии `X.Y.Z` и работает
fail-closed для непарсируемой версии или версии ниже 4.10.3.

Этот нижний предел — минимальная версия, для которой сохранён успешный release evidence,
а не утверждение, что все более старые версии заведомо неисправны. Evidence
совместимости для 4.26.0 хранится в `audit/release-jsonschema-compat-20260815/`.
