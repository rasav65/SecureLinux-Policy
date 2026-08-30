# Gates 1–5 — checker-v3

## Gate 1 — действующий источник / якорь цитаты

Семантика наследуется от checker-v2.

## Gate 2 — обратное покрытие источника + контракт полноты

Управляемая строка источника со статусом `CLOSED` допустима только когда:

1. хотя бы один активный контроль ссылается на её `index_id`;
2. строка имеет статус `CLOSED`;
3. `disposition` и `reason` пусты;
4. `CLOSURE-CONTRACT.tsv` содержит ровно один контракт для этой строки;
5. фактическое множество ID контролей в точности равно множеству, объявленному контрактом.

`coverage_mode`:

- `atomic-single` — один контроль полностью покрывает семантику строки;
- `exact-control-set` — совместно обязательны два или более контролей.

Строка, закрытая через disposition, не должна иметь контракт полноты контролей.

Это не позволяет «закрыть составной пункт источника одним произвольным контролем».

## Gate 3 — закрытая схема / замыкание параметров

Runtime-семантика не изменена, но `CONTROL-SCHEMA.json` теперь является полным вложенным контрактом для всех обязательных полей, правил `derived/justification`, правила `layer/profile`, типизации ожидаемых значений и всех 8 видов параметров.

Authority-backed product mechanisms не маскируются под дословное source-значение. Если `parameter`/`expected` опираются на локальный authority для разрешения source placeholder, open-ended population, reviewed policy или procedural prerequisite, record обязан иметь `requirement.derived=true` и непустой `justification`. Runtime KIND rules и публикуемая JSON Schema проверяют это fail-closed.

## Gate 4 — уникальность в scope и явная межscope-семантика

Жёсткая идентичность внутри одного scope:

`(layer, profile, kind, locator, key)`

Расходящиеся ожидания внутри одного scope приводят к ошибке.

Корпоративные профили `baseline/strict/paranoid` могут намеренно задавать разные значения одного физического параметра; такие случаи учитываются как `profile_variants`.

Расходящиеся значения между provenance layers автоматически НЕ разрешаются. Они приводят к `unresolved cross-scope parameter conflict`, пока будущий явный механизм разрешения не зафиксирует authority, выбранное значение и обоснование.

## Gate 5 — исполнимость probe

Семантика наследуется от checker-v2. Текущий runtime-runner: только sysctl.

### Кодирование значения наблюдения

Семантические типы контроля и wire-значения probe — разные контракты. Точные правила кодирования определены в `docs/observation-value-contract.md`.

Текущий runner Gate 5 остаётся **только sysctl**:

- integer/string-наблюдения sysctl приходят как JSON strings;
- boolean для sysctl запрещён `KIND_RULES`.

Зарезервированные форматы для будущих runners:

- логическое значение `systemd-unit-state` -> JSON boolean;
- логическое значение `package-presence` -> JSON boolean.

Строки `"true"` / `"false"` и числовые `0/1` не принимаются как boolean-наблюдения. Отображение boolean-наблюдений для `file-kv` явно отложено до появления дизайна соответствующего `file-kv` probe.
