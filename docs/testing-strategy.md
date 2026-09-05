# Стратегия тестирования

SecureLinux-Policy использует собственный current test baseline и сохраняет
проверенные инженерные invariants из SecureLinux-NG donor. Нормативная модель
старого проекта не наследуется.

## Текущий runner

Tracked `tests/run-all.py` — canonical точка запуска Python regressions.
Population test-файлов определяется из Git в момент запуска.

- DEV — stdlib-only, все project regressions кроме `release-v1`;
- RELEASE — DEV PASS + объявленные внешние зависимости и release gates.

RC=0 без доказательства фактического выполнения теста недостаточен. Unexpected
skip, `ResourceWarning`, untracked `test_*.py` и project failure делают DEV
красным.

## Слои тестирования

1. Source/schema/unit tests — детерминированные и независимые от host.
2. Differential tests — напрямую сравнивают две реализации одного contract.
3. Documentation parity — machine-owned current blocks должны воспроизводиться byte-exact.
4. Failure/crash-injection — границы mutation transaction; для `SRC-0001`
   проверены отказ при drift, xattr и несовпадении временного файла до commit.
5. VM acceptance — host/runtime evidence для конкретного target и exact bytes.

Синтетическое evidence никогда не заменяет evidence с reference VM.

## Parity документации

Текущие counts/status должны выводиться из machine truth, а не из исторических
literal значений внутри tests. `tools/render-current-docs.py` формирует current
status README, current status PROJECT-MAP и `docs/fstec-coverage.md` из source
index, closure contract, control manifest и adapter registry.

Regression сравнивает ожидаемые и committed bytes. Изменение `5 → 8 → 11` не
должно требовать правки теста только ради замены одного hardcoded count другим.

## Обязательный шаблон transaction tests для APPLY

Каждый класс mutation со временем должен иметь tests для следующих случаев:

- external snapshot precondition представлен честно; fake snapshot evidence не синтезируется;
- pre-state, необходимый для transaction-local safety, успешно захватывается до mutation;
- journal/intent записывается до mutation, когда этого требует APPLY contract;
- writer failure до mutation => target unchanged;
- crash/failure после intent, но до mutation => no unintended target change;
- crash/failure после mutation, но до transaction commit => exact local compensating rollback, когда это доказано APPLY contract, иначе явный failure с требованием external snapshot recovery;
- transaction commit фиксирует фактический результат, а не intended result;
- repeated APPLY idempotent и не создаёт лишних mutation;
- public/user-invokable RESTORE path отсутствует;
- post-APPLY recovery явно равен `EXTERNAL_SNAPSHOT` и находится вне product mutation code.

Для первой вертикали `SRC-0001` function-level VM run подтвердил happy path и
fail-closed ветви до commit; targeted run подтвердил xattr, stale reread и два
варианта несовпадения временного файла. Generated CLI дополнительно подтвердил
dry-run, attested commit, локальную post-check и повторный NOOP на Ubuntu 22,
Ubuntu 24, Ubuntu 26, Debian 12 и Debian 13; Ubuntu 24 Desktop подтвердил routing
`TYPE=DESKTOP` и dry-run без изменения `/etc/shadow`. Эти результаты относятся к
exact CLI SHA-256 `98a4c67aeb392bff4e2b617f0f6593b8ff8fb149ce6bb156d9adbebd94e86928`.
Полный commit-path не заявляется проверенным на каждом из восьми profile/type
состояний: матрица содержит шесть VM identities и восемь поддерживаемых состояний.

## Матрица безопасности файловой системы

Managed files должны проверяться для regular files, symlinks, dangling links,
hardlinks, metadata/xattrs, permission failures и producer failures.
Replacement должен быть atomic и при неожиданных metadata errors завершаться до
замены target.

## Семантика result code

Policy noncompliance и execution failure различаются. Non-compliant check может
успешно выполниться как программа, а internal/preflight/report failures обязаны
возвращать ненулевой execution RC.

## Registry донора

Machine-readable registry из 32 donor contracts находится в
`index/engineering-tests-v1/TEST-CONTRACTS.tsv`, а сохранённые donor tests — в
`TEST-INVENTORY.tsv`. Legacy donor tests, утверждающие старый смешанный FSTEC
mapping, остаются только historical evidence.

## Замеры производительности CHECK на Debian 13 SERVER

Замеры относятся к CLI SHA-256
`98a4c67aeb392bff4e2b617f0f6593b8ff8fb149ce6bb156d9adbebd94e86928`.
Три полных CHECK без трассировки заняли 16628.845, 16704.549 и 16450.152 мс.
Каждый вернул RC=1, 53 строки и пустой stderr; итог policy — UNEVALUATED
с 18 PASS, 25 FAIL и 8 ERROR. Различается только значение `forks` в строке
контроля процессов: оно читается из поля `processes` в `/proc/stat`.

В отдельном прогоне исходных CHECK-функций при LC_ALL=C контроль 2.3.8
STANDARD-SYSTEM-PATHS-MODE занял 15349.596 мс; остальные 50 функций вместе —
516.724 мс. Сумма — 15866.320 мс, доля контроля 2.3.8 — 96.74% этой суммы.
Эти числа не являются разбиением времени одного из трёх полных CHECK.
В сохранённой трассе внутри контроля 2.3.8 распознано 11780 из 11853
внешних вызовов `/usr/bin/stat`; число вызовов не определяет долю времени.

Архивы результатов хранятся вне product population:

- `slp-check-perf-measurements-v2.zip`, SHA-256
  `dbce317ce02601a10817ff03fa9f3ac69da7af7914ac105bf2a81ea08931ef7f`;
- `slp-control-timing-iEdBw8.zip`, SHA-256
  `ff5490be905741801746660cc53bb4a47b5313a2d9e833d39d09f90e51a4ed0f`.

Диагностический Python-обход за 95 мс не воспроизводит весь контракт контроля
и не доказывает эквивалентность реализации. В диагностическом разборе трассы
обнаружено сохранение внешних кавычек в имени `/usr/bin/[`; результаты такого
повторного обращения нельзя считать отказом исходного CHECK.
Оптимизация не выполнена. Будущий замер изменённой реализации должен отдельно
подтвердить сохранение семантики, включая ошибки, и фактическое время выполнения.
