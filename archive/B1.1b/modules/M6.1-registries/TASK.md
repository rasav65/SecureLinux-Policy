# R5-M6.1-REGISTRY-VALUE-REF-LINKAGE

Статус: `LOCKED` (internal lock candidate v2; external focused ACCEPT отсутствует).

Модуль: `M6.1-registries`

Цель: замкнуть registry/value_ref contract до изменения потребителей.

Закрываемый внешний набор: `B-01…B-05` плюс связанные major findings по role×target matrix, slot/domain/binding linkage, inline Id imports, fixture ownership, enumeration-domain asymmetry, instance ownership и direct source pinning.

## Границы

Разрешены изменения только собственного нормативного текста, schema-фрагмента, fixtures и производных файлов M6.1. При `BREAKING` разрешено изменить только lifecycle/hash-поля locks и project state потребителя на `REOPENED`; нормативное содержание потребителя остаётся byte-identical.

Запрещены изменения baseline v9, нормативного содержания других модулей, canonical corpus, validator, runtime, `src/`, `tests/`, `sources/`, host, SVG/PNG, gates B1.1/B1.2, commit и push.

Результат: `LOCK_CANDIDATE`; M6.1=`LOCKED`, M0=`REOPENED`, `FROZEN=false`, focused external ACCEPT=false.
