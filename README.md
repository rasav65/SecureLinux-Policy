# SecureLinux-Policy v3

Проверка безопасной настройки Debian и Ubuntu по требованиям, представленным в политике проекта. Скрипт показывает нарушения и ошибки проверки; APPLY текущей интеграционной вертикали обрабатывает 17 sysctl-controls через общий механизм `config-line-with-runtime-v1`.

> **Статус:** кандидат продукта, не выпуск. Полное соответствие требованиям ФСТЭК не заявляется. Проверка не изменяет настройки системы.

[Скачать](#скачать) · [Быстрый старт](#быстрый-старт) · [Применение изменений](#применение-изменений) · [Документация](#документация)

## Возможности

| Режим | Назначение |
|---|---|
| `--check` | Проверить требования текущей политики |
| `--check --failed` | Показать только проблемы |
| `--report` | Получить краткий отчёт |
| `--check --format json` | Получить машинный отчёт |
| `--apply --dry-run` | Рассчитать APPLY для всех текущих `apply.supported=true` controls без target-мутаций |
| `--apply` | Применить все текущие `apply.supported=true` controls |

Покрытие и ограничения перечислены в [карте требований](docs/fstec-coverage.md). Наличие проверки не означает наличия автоматического исправления.

## Поддерживаемые системы

Архитектура — `x86_64`.

| Система | Поддерживаемые состояния |
|---|---|
| Debian 12 и 13 | SERVER |
| Ubuntu 22.04 | FULL |
| Ubuntu 24.04 | `FULL`, `MINIMIZED`, Desktop |
| Ubuntu 26.04 | FULL, MINIMIZED |

FULL, MINIMIZED, SERVER и Desktop обозначают состояния среды, а не уровни строгости политики. Подробности — в [совместимости](docs/compatibility.md).

## Требования

- Bash и системные утилиты поддерживаемой ОС.
- Исполняемый `/usr/bin/python3`: используется проверкой системных путей и реализацией APPLY.
- Для полного доступа к проверяемым объектам — запуск через `sudo`.
- Генератор и среда разработки для запуска готового скрипта не нужны.

## Скачать

Репозиторий частный: требуется предоставленный доступ и настроенная авторизация Git. Используйте тот же способ авторизации, с которым у Вас работают `git fetch` и `git push`. Не помещайте токены и пароли в команды, файлы проекта или отчёты.

Ниже закреплён проверенный коммит `a4772f586d9c0f8d6c5980ba02411b1af8124a7f`. Для скачивания нужен Git. Создаётся отдельный каталог; в рабочее дерево извлекаются только скрипт и его контрольная сумма. Git также загружает необходимые данные репозитория.

```bash
git clone --filter=blob:none --no-checkout https://github.com/rasav65/SecureLinux-Policy.git securelinux-policy-download &&
cd securelinux-policy-download &&
git checkout a4772f586d9c0f8d6c5980ba02411b1af8124a7f -- securelinux-policy.sh securelinux-policy.sh.sha256 &&
sha256sum -c securelinux-policy.sh.sha256
```

Каталог `securelinux-policy-download` должен отсутствовать либо быть пустым. Продолжайте только после успешной проверки суммы. Она проверяет совпадение файлов, но не заменяет проверку доверия к источнику скачивания.

## Быстрый старт

В каталоге скачанного скрипта:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --check
```

Явный `/bin/bash -p` сохраняет требуемый режим Bash и не требует исполнения файла с файловой системы. Обычный `bash` без `-p` и подключение скрипта через `source` не являются поддерживаемым способом запуска.

Только проблемы:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --check --failed
```

Отчёт в JSON:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --check --format json
```

Сведения о сборке без проверки системы:

```bash
/bin/bash -p ./securelinux-policy.sh --build-info
```

## Как читать результат

| Результат | Значение |
|---|---|
| `PASS` | Проверенное условие выполнено |
| `FAIL` | Проверенное условие не выполнено |
| `ERROR` | Проверка не смогла дать определённую оценку; изучите причину `domain:reason` |
| `NOT_FOUND` | Объект наблюдения не найден; оценка зависит от контракта конкретной проверки |

Ошибку чтения нельзя считать отсутствием нарушения. Итог `UNEVALUATED` означает, что полная оценка не получена. Ненулевой код завершения CHECK сам по себе не доказывает поломку скрипта.

## Применение изменений

**Текущий APPLY scope вычисляется из корпуса: 17 controls `parameter.kind=sysctl` имеют `apply.supported=true` и маршрутизируются в механизм `config-line-with-runtime-v1`. `SRC-0001` из продуктового APPLY выведен; его прежние APPLY-артефакты сохранены только как история.**

Сухой запуск выполняет те же наблюдения и расчёт без target-мутаций:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --apply --dry-run
```

Фактическое применение всех текущих применимых controls:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --apply
```

Продуктовый dispatcher продолжает прогон после отказа отдельного контроля и формирует единый отчёт `/var/log/securelinux-policy/report.json`; журналы — `apply.log` и `debug.log` в том же каталоге. Пользовательского `--restore` нет. Operational recovery после завершённого APPLY остаётся внешним snapshot/backup-механизмом администратора.

## Ограничения

- Проверяются только требования текущего состава политики.
- Проверка и применение имеют разный объём реализации.
- Для проверки системных путей недоступный Python даёт `runtime:python3-missing`.
- Висячие ссылки и другие препятствия полному наблюдению могут приводить к `ERROR`.
- В роли исполняемых файлов ссылка на каталог, совпадающий по устройству и inode с исполняемым корнем, пропускается. Остальные ограничения целей сохраняются.

Результаты испытаний, особенности Desktop и замеры скорости — в [стратегии тестирования](docs/testing-strategy.md).

## Документация

| Тема | Документ |
|---|---|
| Полный указатель | [Документация проекта](docs/README.md) |
| Покрытие требований | [Карта покрытия](docs/fstec-coverage.md) |
| Поддерживаемые среды | [Совместимость](docs/compatibility.md) |
| Устройство проекта | [Карта проекта](docs/PROJECT-MAP-v3.md) |
| Инженерные сведения и пересборка | [Продуктовая линия](product/README.md#readme-engineering-reference) |
| Исторические схемы донора | [Архитектурные схемы](docs/ARCHITECTURE-DIAGRAMS.md) |
| Источники и уровни политики | [Слои политики](docs/policy-layers.md) |
| Проверки и испытания | [Стратегия тестирования](docs/testing-strategy.md) |
| Запуск тестов разработчиком | [Тесты](tests/README.md) |
| Дальнейшие этапы | [Дорожная карта](docs/ROADMAP-v3.md) |
| Изменения версий | [История изменений](CHANGELOG.md) |

## Сообщить о проблеме

При обращении укажите ОС, архитектуру, команду запуска, код возврата, вывод `--build-info` и строку ошибки. Не прикладывайте пароли, ключи и содержимое `/etc/shadow`.

Обращения по проекту: [репозиторий SecureLinux-Policy](https://github.com/rasav65/SecureLinux-Policy).

## Лицензия

Отдельный файл лицензии в корне этой версии отсутствует. Лицензия инженерного донора не обозначает автоматически лицензию этого проекта.


## Машинный статус проекта

<details>
<summary>Покрытие, область применения и статус сборки</summary>

<!-- BEGIN GENERATED CURRENT STATUS -->
```text
TOTAL_INDEX_ROWS=349
CONTROLLED_CLOSED_WITH_CONTRACT=40
DISPOSED_CLOSED_ROWS=0
OPEN_INDEX_ROWS=309
CLOSURE_RATIO=40/349
CANONICAL_CONTROLS=51
CLOSURE_CONTRACT_ROWS=40
ADAPTER_KINDS=18
CHECK_TARGET_FAMILY=linux-x86_64-supported-v1
SUPPORTED_ENVIRONMENTS=8
CHECK_STATUS=NON_RELEASE_PRODUCT_CANDIDATE
CHECK=IMPLEMENTED_READ_ONLY
APPLY=IMPLEMENTED
APPLY_KINDS=config-line-with-runtime-v1
APPLY_CONTROL_COUNT=17
APPLY_IMPLEMENTATION_COUNT=1
RESTORE=NOT_PLANNED
ROLLBACK_MODEL=EXTERNAL_SNAPSHOT
FULL_FSTEC_COMPLIANCE_CLAIM=false
```

CHECK охватывает только требования, представленные текущими canonical controls. Этот статус не является заявлением о полном соответствии требованиям ФСТЭК.
<!-- END GENERATED CURRENT STATUS -->

</details>
