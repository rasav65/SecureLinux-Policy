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

Исключение — механизмы, мутация которых только ужесточает состояние:
`file-mode-owner-v1`, `optional-file-root-files-mode-v1` и
`suid-sgid-applications-mode-v1`. Компенсация для них
запрещена, потому что возврат прежнего, более слабого значения ослабил бы защиту.
Модель — `fchmod` на объект, проверка постусловия и отказ без отката; у
`optional-file-root-files-mode-v1` и `suid-sgid-applications-mode-v1` ошибка одного
объекта не останавливает остальные (`APPLIED_PARTIAL`), `EROFS` прерывает прогон сразу. Пункты о
journal/intent и компенсации к ним не применяются.

Историческое: решением DP-3 APPLY для `SRC-0001` выведен из продукта, текущий
APPLY задают механизмы `config-line-with-runtime-v1`, `file-mode-owner-v1`, `optional-file-root-files-mode-v1` и `suid-sgid-applications-mode-v1`.
Каждый механизм проверяется сквозным тестом встроенного dispatcher
(`tests/product-v1/test_apply_dispatch_integration.py`) и VM-прогоном.

Для первой вертикали `SRC-0001` function-level VM run подтвердил happy path и
fail-closed ветви до commit; targeted run подтвердил xattr, stale reread и два
варианта несовпадения временного файла. Generated CLI дополнительно подтвердил
dry-run, attested commit, локальную post-check и повторный NOOP на Ubuntu 22,
Ubuntu 24, Ubuntu 26, Debian 12 и Debian 13; Ubuntu 24 Desktop подтвердил FIELD_COMPATIBILITY routing
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
Эти замеры относятся к исходной реализации. Метаданные SRC-0012 теперь
читаются внутри Python; GNU find/readlink сохранены. Время полного CHECK для
новых байтов должно подтверждаться отдельным отчётом.


## SRC-0012: зависимость Python и причины ERROR

Перед вызовом наблюдателя выполняется `[[ ! -x /usr/bin/python3 ]]`.
Проверка следует после EUID, PATH и uname. Причина `runtime:python3-missing`
означает отсутствие пути либо недоступность исполнения текущему пользователю;
успешный guard не гарантирует успешный запуск. Последующий сбой запуска
сохраняет `runtime:observer-failed`. Перечень `error_reasons` в контракте
включает причины оболочки и Python-наблюдателя. Удалённые при оптимизации
ветви `target:mode-read-failed` и `scan:invalid-marker` не восстанавливаются.

В существующий набор product-тестов включены временные фикстуры отсутствующего
и неисполняемого интерпретатора. Для проверки сбоя запуска используется
существующий /usr/bin/false: исполнение из временного каталога не требуется.
Проверяются неверное количество аргументов и совпадение словаря причин
с рендером. Системный Python не изменяется: путь заменяется только
в отрендеренном тексте тестовой фикстуры.

До добавления guard кандидат с SHA-256
`c7eb01a2a026d830dbf8289a8df5a98515e98f271ee5425a0f2224f21c7f92c1`
прошёл по 10 существующих тестов вместе с исходным адаптером и 16 сценариев
побайтового сравнения на ПК. Архив отчёта
`slp-src0012-observer-probe-v1-report.zip`, SHA-256
`16bbce7f255aed53a497553838eea0016002bf749329905cd341c46c5054b9aa`.
Замер на 259 временных объектах: 1692.399 мс исходный адаптер, 43.243 мс кандидат.
Это не замер полного CHECK.

Прежняя серия с кандидатом без guard сохраняется как историческое evidence.
Последующая серия после guard и исключения для ссылки на exec-корень
описана ниже; результаты разных байтов и состояний хоста не смешиваются.


## SRC-0012: исключение для exec-корня и новая VM-серия

Исключение применяется только к ссылке в роли exec, разрешившейся в каталог
с dev:inode exec-корня. Она не включается в число regular targets и не создаёт
дополнительного поля VALUE. Другие каталоги, включая подкаталог корня, а также
недопустимые цели в ролях library/module сохраняют ERROR. Dangling links и
ошибки разрешения не пропускаются. Новая документальная запись не меняет код.

База адаптера: `e021b632f1db643ab9f6349c777eefecc1defb0cc179376f7f476c825cf0b48e`.
Кандидат: `7a823bb1721f774c7f26963c67dfc9a1ea2ca9cde33285141f77fcfcbb43cb56`.
Блок кандидата: `5d373bfc08336f650d4789fe336d4943e22cb51c81b30f75fc463798c0659d04`.
CLI замеров: `02198905acd974a57dd92ada715a4c5c577f6e02d457412f18e38bd15170abc0`.

На семи серверных состояниях по три запуска базы и кандидата дали одинаковый
stdout, равные RC и пустой stderr. Имена файлов задают заявленное состояние;
сами отчёты не содержат machine-id и полной OS identity, поэтому не являются
самостоятельным доказательством идентичности ВМ. Паритет не заменяет проверку
семантики. Значение RESULT=PASS коллектора не заменяет PARITY_VERDICT.

На исходном Desktop база вернула `target:invalid-type`, кандидат —
`target:resolve-failed`. В состоянии `desktop-no-dangling` база сохранила
`target:invalid-type`, кандидат завершил наблюдение с итогом `VALUE/FAIL`:

```text
roots_present=16;roots_absent=2;aliases=8;exec=2662;libraries=5720;modules=6483;checked=14865;violations=1
```
 Это намеренное отличие, а не
побайтовый паритет. Результат очищенного состояния не переносится на исходный
образ. Усечённый PATH не используется как приёмка канонной популяции.
Точный объект нарушения прав не записан в этих агрегатных отчётах.

Полный CHECK измерялся пять раз; ниже минимум и максимум, а не гарантированное
время запуска. RC всех запусков равен 1, stderr пуст; стабильные строки
совпали по методике коллектора. Динамическая строка процессов не объявляется
побайтово неизменной. Причины различия времени между повторами не установлены.

| Состояние из имени отчёта | Минимум, мс | Максимум, мс |
|---|---:|---:|
| debian-12-x86_64-server | 759.2 | 1847.1 |
| debian-13-x86_64-server | 843.0 | 1285.8 |
| ubuntu-22.04-x86_64-full | 1125.8 | 2448.9 |
| ubuntu-24.04-x86_64-desktop-no-dangling | 3823.4 | 5048.3 |
| ubuntu-24.04-x86_64-desktop | 2062.6 | 13097.0 |
| ubuntu-24.04-x86_64-full | 1428.6 | 3645.4 |
| ubuntu-24.04-x86_64-minimized | 1115.7 | 2592.3 |
| ubuntu-26.04-x86_64-full | 1760.7 | 4202.3 |
| ubuntu-26.04-x86_64-minimized | 1549.1 | 3703.6 |

Отчёты находятся вне product population в
`dashboard/src0009-vm-evidence/`. Их sidecar проверяются отдельно от корневых
манифестов. Архив предоставленной серии имеет SHA-256
`ecfc47798c31b2ccfab860c2215a6842158114ef47f92ca9996356295f0e26e0`.
Имена и SHA-256 прочитанных отчётов:

```text
a40fd40853b6cf8612c79938be7a4728a4efdf7e07abe2401cd75d6c9cb4935d  slp-src0012-parity-v2-debian-12-x86_64-server.txt
bdd216222a8dcf913d0cd5ee82ef3aa4355ca3a17800d84a06d4a2d6da7f4970  slp-src0012-parity-v2-debian-13-x86_64-server.txt
d3ccdcdc14a140e1dfc0bc8be8065bf7816c7e4022f130b366bef7dd73cb84b7  slp-src0012-parity-v2-ubuntu-22.04-x86_64-full.txt
cb2cdf23897d57ee5e9ea01491ffcda5b9391ed2614f32ddbfa68d73bad4bc32  slp-src0012-parity-v2-ubuntu-24.04-x86_64-desktop-no-dangling.txt
d7e1453ae24c48d3ea579832d0578d39c469b63c170303574cbb7420b95b56b9  slp-src0012-parity-v2-ubuntu-24.04-x86_64-desktop.txt
2f98f49e6c4214f73bbb8b0b7e0b026ec2eb062a0fc132281e353480cef95daf  slp-src0012-parity-v2-ubuntu-24.04-x86_64-full.txt
fcdc7c1bafd2acdfa6f16d176eb7a0446a94bc3b5e50e525f119b54e46f232e8  slp-src0012-parity-v2-ubuntu-24.04-x86_64-minimized.txt
75e3933cb4df43e1c391fb645790ff33b3d97cac2147ffecb32cd6164df0a5c6  slp-src0012-parity-v2-ubuntu-26.04-x86_64-full.txt
b9ab976d14b61e6211e7e51c6beadde8a1fc9b6bb9c787616aa52fec71b2f2de  slp-src0012-parity-v2-ubuntu-26.04-x86_64-minimized.txt
daaad3d166d79375ddca216e442828424141a72212f32e5b34a3a19997e6bbff  slp-src0012-timing-v1-debian-12-x86_64-server.txt
9f2d37383d2e714b3fffef2e3344c0f9829bb3f56c85a545cac64b51d0e0afba  slp-src0012-timing-v1-debian-13-x86_64-server.txt
069740e4c1f0208125d771b8aebd594b7d33f74afd9ab9bcf327bb1d70f824b8  slp-src0012-timing-v1-ubuntu-22.04-x86_64-full.txt
bd802966ad08daacbcc89c46dcb2f4789bd9311c0b1bd17df38e7e2dc5eb3d6c  slp-src0012-timing-v1-ubuntu-24.04-x86_64-desktop-no-dangling.txt
3f90072521a0d22d5d52f9614ffd762909c2d5a8bbcb59fbb322aa4996903507  slp-src0012-timing-v1-ubuntu-24.04-x86_64-desktop.txt
a22bd38259cd9a4136a0eab3e6a01956da8385f79a3a39a3f2d7967215daeb57  slp-src0012-timing-v1-ubuntu-24.04-x86_64-full.txt
1fd3d46b37a3ac7c5fc504b48b5740861fc9e29afa0224a4e9189bc0b50e205f  slp-src0012-timing-v1-ubuntu-24.04-x86_64-minimized.txt
64f3d238eab7c33214729235801d138ba9a3f94c91ddf10c656435b300e8c861  slp-src0012-timing-v1-ubuntu-26.04-x86_64-full.txt
714ef450069f33ee0e7fd14874d59222daadc83695f900b160eca73efe1953ed  slp-src0012-timing-v1-ubuntu-26.04-x86_64-minimized.txt
```
