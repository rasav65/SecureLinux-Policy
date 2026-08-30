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
4. Failure/crash-injection — будущие границы mutation transaction.
5. VM acceptance — host/runtime evidence для конкретного target и exact bytes.

Синтетическое evidence никогда не заменяет evidence с reference VM.

## Parity документации

Текущие counts/status должны выводиться из machine truth, а не из исторических
literal значений внутри tests. `tools/render-current-docs.py` формирует current
status README, current status PROJECT-MAP и `docs/fstec-coverage.md` из source
index, closure contract, control manifest и adapter registry.

Regression сравнивает ожидаемые и committed bytes. Изменение `5 → 8 → 11` не
должно требовать правки теста только ради замены одного hardcoded count другим.

## Обязательный шаблон transaction tests для будущего APPLY

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
