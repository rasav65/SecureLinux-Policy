# SecureLinux-Policy

> Инструмент проверки и безопасного применения настроек Debian и Ubuntu по требованиям, представленным в политике проекта. CHECK работает без изменения системы; автоматический APPLY реализован для параметров `sysctl`, режимов доступа файлов `/etc/passwd`, `/etc/group`, `/etc/shadow`, системных файлов заданий cron, SUID/SGID-приложений, стандартных системных путей, файлов запуска и части параметров ядра в командной строке загрузки (через GRUB, вступают в силу после перезагрузки).

![Статус](https://img.shields.io/badge/status-product%20candidate-orange) ![ОС](https://img.shields.io/badge/ОС-Debian%2012%2F13%20%7C%20Ubuntu%2022.04%2F24.04%2F26.04-informational) ![CHECK](https://img.shields.io/badge/CHECK-read--only-blue) ![APPLY](https://img.shields.io/badge/APPLY-sysctl%20%7C%20file%20modes-green) ![Лицензия](https://img.shields.io/badge/license-MIT-lightgrey)

> **Статус:** проект находится в активной разработке и пока не является выпуском. Полное соответствие требованиям ФСТЭК не заявляется. CHECK и APPLY имеют разный объём реализации.

[Скачать](#скачать) · [Быстрый старт](#быстрый-старт) · [Возможности](#возможности) · [Применение изменений](#применение-изменений) · [Поддерживаемые системы](#поддерживаемые-системы) · [Документация](#документация)

---

## Назначение

SecureLinux-Policy предназначен для проверки конфигурации Linux-хоста и безопасного применения тех настроек политики, для которых уже реализован автоматический APPLY.

Ключевые возможности:

- read-only CHECK текущей политики;
- вывод только найденных проблем;
- JSON-отчёт для автоматизации;
- dry-run перед изменением системы;
- автоматический APPLY параметров `sysctl`, режимов доступа файлов учётных записей, системных файлов заданий cron, SUID/SGID-приложений, стандартных системных путей и файлов запуска;
- единый standalone-скрипт `securelinux-policy.sh`;
- отчёт и журналы результатов применения.

Наличие CHECK для требования не означает, что это требование уже изменяется автоматически.

---

## Скачать

```bash
wget https://github.com/rasav65/SecureLinux-Policy/archive/refs/heads/main.tar.gz
tar -xzf main.tar.gz
cd SecureLinux-Policy-main
```

---

## Быстрый старт

> **⚠ На рабочих серверах перед фактическим APPLY сначала выполните CHECK и dry-run. Перед изменениями рекомендуется иметь внешний snapshot/backup системы.**

Проверка согласованности скачанного product-script:

```bash
sha256sum -c securelinux-policy.sh.sha256
```

Продолжайте только после успешной проверки контрольной суммы.

Проверка системы:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --check
```

Только проблемы:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --check --failed
```

JSON-отчёт:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --check --format json
```

Просмотр поддерживаемых изменений без их применения:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --apply --dry-run
```

Фактическое применение поддерживаемых изменений:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --apply
```

Сведения о сборке:

```bash
/bin/bash -p ./securelinux-policy.sh --build-info
```

Явный `/bin/bash -p` сохраняет требуемый режим Bash и не требует исполнения файла с файловой системы. Подключение скрипта через `source` не является поддерживаемым способом запуска.

---

## Возможности

| Режим | Назначение |
|---|---|
| `--check` | Проверить требования текущей политики |
| `--check --failed` | Показать только проблемы |
| `--report` | Получить краткий отчёт |
| `--check --format json` | Получить машинный JSON-отчёт |
| `--apply --dry-run` | Рассчитать поддерживаемый APPLY без target-мутаций |
| `--apply` | Применить controls с явно поддерживаемой APPLY-семантикой |
| `--build-info` | Показать сведения о сборке |

Покрытие и ограничения перечислены в [карте требований](docs/fstec-coverage.md).

---

## Поддерживаемые системы

Архитектура — `x86_64`.

| Система | Поддерживаемые состояния |
|---|---|
| Debian 12 и 13 | SERVER |
| Ubuntu 22.04 | FULL |
| Ubuntu 24.04 | `FULL`, `MINIMIZED` |
| Ubuntu 24.04 Desktop | `FIELD_COMPATIBILITY` |
| Ubuntu 26.04 | FULL, MINIMIZED |

`FULL`, `MINIMIZED` и `SERVER` — clean-reference состояния нормативного acceptance.

> **⚠ Ubuntu 24.04 Desktop — `FIELD_COMPATIBILITY`, а не гарантированно поддерживаемое состояние.** Desktop-система может содержать установленные пользователем пакеты, службы, настройки и другие изменения относительно штатной установки. Проект не гарантирует корректность всех CHECK/APPLY-сценариев на произвольно изменённой Desktop-системе. Реальный `--apply` разрешён, но перед первой мутацией CLI выводит отдельное предупреждение; рекомендуется предварительный `--apply --dry-run` и внешний snapshot/backup.

Подробности — в [совместимости](docs/compatibility.md).

---

## Требования

- Bash и системные утилиты поддерживаемой ОС.
- Исполняемый `/usr/bin/python3`: используется частью проверок и реализацией APPLY.
- Для полного доступа к проверяемым объектам — запуск через `sudo`.
- Генератор и среда разработки для запуска готового скрипта не нужны.

---

## Как читать результат

| Результат | Значение |
|---|---|
| `PASS` | Проверенное условие выполнено |
| `FAIL` | Проверенное условие не выполнено |
| `ERROR` | Проверка не смогла дать определённую оценку; изучите причину `domain:reason` |
| `NOT_FOUND` | Объект наблюдения не найден; оценка зависит от контракта конкретной проверки |
| `NOT_APPLICABLE` | Проверяемая популяция вычислена полностью и пуста; это определённый результат, а не ошибка |

Ошибка чтения или неполное наблюдение не должны превращаться в ложный PASS. Итог `UNEVALUATED` означает, что полная оценка не получена.

---

## Применение изменений

Автоматический APPLY выполняется механизмами `config-line-with-runtime-v1` (sysctl), `file-mode-owner-v1` (режим файлов), `optional-file-root-files-mode-v1` (режимы системных файлов cron), `suid-sgid-applications-mode-v1` (режимы SUID/SGID-приложений), `standard-system-paths-mode-v1` (режимы стандартных системных путей) `startup-files-write-protection-v1` (режимы файлов запуска) и `kernel-cmdline-grub-v1` (параметры ядра в командной строке загрузки: файл `/etc/default/grub.d/zz-securelinux-policy.cfg` и `update-grub`, вступают в силу после перезагрузки; `mitigations`, три `iommu`, `tsx` и `debugfs` не пишутся и выводятся блоком «требуется решение администратора») и `pam-wheel-su-v1` (доступ к `su` только для группы `wheel` с `root`: `/etc/pam.d/su` меняется, только если совпадает с файлом пакета, и только при наличии пользователей в группе `sudo` или `admin`; иначе — блок «требуется решение администратора»); состав берётся из APPLY registries, количества — из машинного статуса ниже. Остальные controls могут участвовать в CHECK, но не изменяются автоматически без явно поддерживаемой APPLY-семантики.

Сухой запуск:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --apply --dry-run
```

Фактическое применение:

```bash
sudo /bin/bash -p ./securelinux-policy.sh --apply
```

Единый отчёт формируется в `/var/log/securelinux-policy/report.json`; журналы APPLY — `apply.log` и `debug.log` в том же каталоге. Каталог проверяется до записи (владелец root, без `022`, не симлинк), одновременный второй запуск отклоняется блокировкой `.lock`.

Пользовательского `--restore` в SecureLinux-Policy нет. После завершённого APPLY operational recovery остаётся внешним snapshot/backup-механизмом администратора.

---

## Надёжность и безопасность применения

- CHECK не изменяет целевую систему.
- `--apply --dry-run` выполняет наблюдения и расчёт без target-мутаций.
- APPLY выполняется только для controls с явно поддерживаемой семантикой.
- Неопределённое или неполное наблюдение не трактуется как успешное соответствие.
- Перед изменением production-системы рекомендуется внешний snapshot/backup.
- Пользовательский универсальный restore намеренно не заявляется как возможность продукта.

Подробности испытаний и acceptance — в [стратегии тестирования](docs/testing-strategy.md).

---

## Ограничения и границы соответствия

SecureLinux-Policy автоматизирует только технические меры, представленные текущей политикой проекта.

Проект **не заявляет полного соответствия требованиям ФСТЭК целиком**. Итоговая оценка защищённости зависит также от архитектуры системы, установленных сервисов, корпоративных политик, организационных процедур и требований вне автоматически проверяемого hardening ОС.

Дополнительно:

- CHECK и APPLY имеют разный объём реализации;
- не каждый FAIL может или должен исправляться автоматически;
- препятствия полному наблюдению могут приводить к `ERROR`;
- для проверки системных путей недоступный Python даёт `runtime:python3-missing`;
- новые APPLY-механизмы добавляются по мере завершения их контрактов, тестов и acceptance.

---

## Документация

| Тема | Документ |
|---|---|
| Полный указатель | [Документация проекта](docs/README.md) |
| Покрытие требований | [Карта покрытия](docs/fstec-coverage.md) |
| Поддерживаемые среды | [Совместимость](docs/compatibility.md) |
| Основная карта проекта | [Карта проекта](docs/PROJECT-MAP.md) |
| Инженерные сведения и пересборка | [Продуктовая линия](product/README.md#readme-engineering-reference) |
| Исторический runtime-reference донора | [Архитектурные схемы](docs/ARCHITECTURE-DIAGRAMS.md) |
| Источники и уровни политики | [Слои политики](docs/policy-layers.md) |
| Проверки и испытания | [Стратегия тестирования](docs/testing-strategy.md) |
| Запуск тестов разработчиком | [Тесты](tests/README.md) |
| Дальнейшие этапы | [Дорожная карта](docs/ROADMAP.md) |
| История изменений | [CHANGELOG.md](CHANGELOG.md) |

---

## Обратная связь

Замечания по совместимости, результатам CHECK/APPLY, документации и архитектуре проекта приветствуются.

При сообщении о проблеме укажите ОС, архитектуру, команду запуска, код возврата, вывод `--build-info` и минимальный релевантный фрагмент отчёта или ошибки. Не публикуйте пароли, ключи, токены, содержимое `/etc/shadow` и другие секреты.

Репозиторий: [rasav65/SecureLinux-Policy](https://github.com/rasav65/SecureLinux-Policy).

---

## Лицензия

Проект распространяется на условиях [MIT License](LICENSE).

---

## Машинный статус проекта

<details>
<summary>Покрытие, область применения и статус сборки</summary>

<!-- BEGIN GENERATED CURRENT STATUS -->
```text
TOTAL_INDEX_ROWS=349
CONTROLLED_CLOSED_WITH_CONTRACT=40
DISPOSED_CLOSED_ROWS=211
OPEN_INDEX_ROWS=98
CLOSURE_RATIO=251/349
CANONICAL_CONTROLS=49
CLOSURE_CONTRACT_ROWS=40
ADAPTER_KINDS=17
CHECK_TARGET_FAMILY=linux-x86_64-supported-v1
SUPPORTED_ENVIRONMENTS=7
FIELD_COMPATIBILITY_ENVIRONMENTS=1
CHECK_STATUS=NON_RELEASE_PRODUCT_CANDIDATE
CHECK=IMPLEMENTED_READ_ONLY
APPLY=IMPLEMENTED
APPLY_KINDS=config-line-with-runtime-v1,file-mode-owner-v1,kernel-cmdline-grub-v1,optional-file-root-files-mode-v1,pam-wheel-su-v1,standard-system-paths-mode-v1,startup-files-write-protection-v1,suid-sgid-applications-mode-v1
APPLY_CONTROL_COUNT=40
APPLY_IMPLEMENTATION_COUNT=8
RESTORE=NOT_PLANNED
ROLLBACK_MODEL=EXTERNAL_SNAPSHOT
FULL_FSTEC_COMPLIANCE_CLAIM=false
```

CHECK охватывает только требования, представленные текущими canonical controls. Этот статус не является заявлением о полном соответствии требованиям ФСТЭК.
<!-- END GENERATED CURRENT STATUS -->

</details>
