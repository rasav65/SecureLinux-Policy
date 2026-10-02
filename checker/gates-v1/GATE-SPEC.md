# Gates 1–4 — checker-v1

## Gate 1 — действующий source / якорь цитаты
Проверяются index_id, doc_id, SHA PDF, locator, norm-v1, canonical quote,
quote SHA и буквальное вхождение quote в проверенный norm-v1 corpus.

## Gate 2 — обратное покрытие source
Каждая строка source index должна быть CLOSED:
- либо её представляет control, тогда disposition/reason пусты;
- либо control нет, но есть допустимый disposition + непустой reason.

Допустимые disposition:
`not-technical`, `organizational`, `external`, `out-of-scope`, `informational`.

OPEN никогда не считается закрытым только из-за наличия candidate/control.

## Gate 3 — закрытая схема + замыкание параметров
Проверяется закрытая структура записи и совместимость
`kind/locator/key/op/type`.

## Gate 4 — уникальность
`id` уникален. Одинаковый `(kind, locator, key)` допустим только при полностью
одинаковом `(op, type, value)`. Разные ожидаемые значения — конфликт.

Gate 5 здесь отсутствует. Он появляется только с первым реальным средством наблюдения (`probe`).
