# Acceptance — R5-M6.2-EXACT-OPERATION-ALGEBRA

Модуль: `M6.2-operation-algebra`.

- Каждый operation kind имеет отдельную tagged-схему и точную арность.
- Каждая операция задаёт единственное проверяемое input-to-output mapping.
- Membership-changing операция точно связывает field, value, operator и authorization.
- Контрпример с перестановкой входов/выходов отклоняется.
- Все положительные и отрицательные fixtures модуля проходят.
- Checker подтверждает schema closure, owners, imports и отсутствие потерь fixtures.
- Изменения и удаления exports полностью отражены в transition ledger.
- Нормативные файлы других модулей и project gates не изменены.
- `LOCKED` или `FROZEN` не выставляется до выполнения соответствующего gate.
