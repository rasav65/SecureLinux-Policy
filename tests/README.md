# Тестовая модель SecureLinux-Policy

`tests/run-all.py` — единая точка запуска отслеживаемых Python regressions.
Популяция определяется через Git в момент запуска; число test-файлов здесь не
пинуется вручную.

## DEV

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B tests/run-all.py --dev
```

DEV включает все отслеживаемые `tests/*/test_*.py`, кроме `tests/release-v1/`.
DEV обязан быть зелёным без внешних Python-зависимостей сверх stdlib.

Runner не считает одного `RC=0` достаточным доказательством выполнения:
`unittest`-файл обязан вывести `Ran N tests` с `N>0` и `OK`. Standalone
regression обязан иметь непустой stdout и либо executable `assert`, либо
единственный machine-result marker `RESULT=..._OK`. Нетрекнутый
`tests/*/test_*.py` является ошибкой test population.

Разрешённые внутренние skip:

- `tests/gates-v3/test_schema_runtime_parity.py`: ровно 2 случая real-jsonschema
  в DEV-интерпретаторе только со stdlib;
- `tests/product-v1/test_file_mode_owner_adapter.py`: ровно 2 permission-сценария
  только при запуске DEV от root.

Любой другой или дополнительный skip, а также любой `ResourceWarning`, делает DEV красным.

Baseline документации входит в DEV через `tests/documentation-v1/` и требует
точного паритета machine-owned README/map/coverage с `tools/render-current-docs.py`.

## RELEASE

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B tests/run-all.py --release
```

RELEASE сначала требует DEV=PASS, затем использует `/usr/bin/python3 -I -B`
без `-S` и проверяет зависимости из `requirements-release.txt`.

Коды runner:

- `0` — DEV и RELEASE PASS;
- `1` — ошибка проекта на этапе DEV;
- `2` — ошибка проекта на этапе RELEASE при доступной release-среде;
- `3` — `BLOCKED_ENVIRONMENT`, release-зависимость недоступна/слишком стара.

Отсутствие `jsonschema>=4.10.3` не объявляется дефектом проекта, но выпуск
релиза с этой машины запрещён.

`tests/run-all-selftest.py` отдельно проверяет RC 0/1/2/3 и parser версии.
