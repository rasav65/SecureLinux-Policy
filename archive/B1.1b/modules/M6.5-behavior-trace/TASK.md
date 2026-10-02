# R5-M6.5-BEHAVIOR-TRACE-BOUNDARY

Статус: `OPEN`

Модуль: `M6.5-behavior-trace`

Цель: Закрепить trace и границу B1/B2 после стабилизации M6.2–M6.4.

Находки: нет прямой находки.

## Границы

Разрешены изменения только собственного нормативного текста, schema-фрагмента, fixtures и производных файлов модуля. Изменение export требует автоматической классификации и переоткрытия потребителей при `BREAKING`.

Запрещены изменения baseline v9, других модулей, canonical corpus, validator, runtime, src, tests, sources, host, SVG/PNG, gates B1.1/B1.2, commit и push.

Результат: `RESULT.md`, точечный installer/patch с SHA-256, checker report, test results и обновлённый module lock.
