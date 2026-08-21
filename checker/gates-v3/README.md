# checker/gates-v3

Сохранены исправления независимого аудита B-01/B-02/B-03, а также исправления паритета R2/R3.

Gate 5 в текущем состоянии исполняется только для sysctl-пилота. Типы wire-значений наблюдений больше не приводятся универсально: `sysctl` использует строковые wire-значения, а будущие boolean-пробы `systemd-unit-state` и `package-presence` зарезервированы для выдачи JSON boolean. См. `docs/observation-value-contract.md`.
