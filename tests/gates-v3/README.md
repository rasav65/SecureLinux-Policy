# Тесты gates-v3

`test_audit_fixes.py` — точечные тесты контракта полноты, полной схемы, конфликтов scope/profile и fail-closed поведения активного дерева. Текущие счётчики population вычисляются из контрактов source/index, а не закрепляются вручную.

`test_schema_runtime_parity.py` — regression B-R1-01 и B-R2-01:

- паритет генерации: `CONTROL-SCHEMA.json` побайтово совпадает со схемой, сгенерированной из runtime-констант;
- differential acceptance: текущая матрица, включая 16 граничных случаев CR/LF, должна одинаково оцениваться runtime и схемой;
- semantics pattern: для каждого anchored pattern `re.fullmatch` (runtime) и `re.search` (JSON Schema) должны принимать одно и то же множество строк;
- инвариант parser: управляющий символ в scalar отклоняется на этапе разбора;
- если установлен `jsonschema`, та же матрица дополнительно выполняется через реальный `Draft202012Validator`; иначе эти два теста явно пропускаются.

Тесты контракта значений наблюдений подтверждают отсутствие универсального преобразования boolean-строк и резервируют JSON-boolean wire-значения для будущих systemd/package runners.

Текущая матрица включает положительные и отрицательные случаи `kernel-cmdline`: exact `/proc/cmdline`, безопасный синтаксис key/value, строковое отношение `eq`, boolean-отношение `present=true` и отношение `one-of` для SRC-0026.
