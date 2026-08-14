# Acceptance — R5-M6.4-POPULATION-MATRIX

Модуль: `M6.4-population-matrix`.

- Матрица input_population_mode × population_completeness × resolution.kind тотальна.
- Строки матрицы взаимно исключаются; implicit fallback отсутствует.
- Coverage causality и B1.1a outcomes сохраняются без ложного PARTIAL.
- Все положительные и отрицательные fixtures модуля проходят.
- Checker подтверждает schema closure, owners, imports и отсутствие потерь fixtures.
- Изменения и удаления exports полностью отражены в transition ledger.
- Нормативные файлы других модулей и project gates не изменены.
- `LOCKED` или `FROZEN` не выставляется до выполнения соответствующего gate.
