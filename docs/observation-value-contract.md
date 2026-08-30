# Контракт значения и типа наблюдения

## Назначение

`expected.type` контроля и `VALUE.value` probe — разные контракты.

- `expected.type` — семантический тип политики, сохранённый в контроле.
- `VALUE.value` — JSON wire-представление, выдаваемое probe.

Checker не должен угадывать, как wire-значение преобразуется в семантическое значение.

## Текущие точные контракты

### sysctl — реализовано

Текущий runner Gate 5 работает только с sysctl.

| `expected.type` | JSON-тип `VALUE.value` | декодирование |
|---|---|---|
| `integer` | string | разбор строки как Python integer |
| `string` | string | без преобразования |
| `boolean` | запрещён `KIND_RULES` | отсутствует |

Это сохраняет фактический формат evidence sysctl-v1.

### systemd-unit-state — wire-формат зарезервирован, runner не реализован

Когда будет реализован первый probe `systemd-unit-state`:

- `expected.type` контроля остаётся `boolean`;
- `VALUE.value` **ДОЛЖЕН быть JSON boolean** (`true` / `false`, без кавычек);
- строки `"true"` / `"false"` недопустимы;
- числа `0` / `1` недопустимы.

Текущий checker по-прежнему отклоняет этот kind на Gate 5, потому что runner не реализован. Определение wire-формата не является утверждением об исполнимости.

### package-presence — wire-формат зарезервирован, runner не реализован

Когда будет реализован первый probe `package-presence`:

- `expected.type` контроля остаётся `boolean`;
- `VALUE.value` **ДОЛЖЕН быть JSON boolean**;
- строки `"true"` / `"false"` недопустимы;
- числа `0` / `1` недопустимы.

Это контракт формата, а не реализация runner.

### boolean для file-kv — явно отложено

Контроли `file-kv` могут иметь семантические boolean-значения, но файловые форматы используют разные текстовые соглашения (`yes/no`, `true/false`, `on/off`, `0/1` и т. п.).

Поэтому универсального приведения boolean-наблюдений `file-kv` нет. Будущий probe/adapter `file-kv` сначала должен определить собственное отображение, зависящее от источника.

## Запрещённое поведение

В проекте нет общего преобразования:

`"true" -> true` или `"false" -> false`

Такое преобразование ранее случайно существовало в `_expected_compliance` и было удалено.

## Связь со схемой

Эта очистка не меняет `KIND_RULES` и поэтому не меняет `CONTROL-SCHEMA.json`.

- sysctl уже исключает boolean;
- `systemd-unit-state` и `package-presence` остаются семантическими boolean-kinds;
- паритет генерации схемы должен оставаться PASS;
- differential tests schema/runtime должны оставаться PASS.

Любое будущее изменение `KIND_RULES` по-прежнему требует регенерации схемы через `--emit-schema` и запуска differential suite.

## Статус этапа

Обязательный release gate с реальным `jsonschema` уже закрыт. Этот observation-контракт сохраняется как действующий инженерный контракт; текущий substantive этап проекта — отдельный `APPLY semantic contract` для принятой вертикали `fstec-linux-2022`.
