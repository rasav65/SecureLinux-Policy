# Архитектура SecureLinux-NG

## Назначение

SecureLinux-NG — framework для безопасной настройки Linux-хостов с опорой на требования и рекомендации ФСТЭК, с обязательной проверкой совместимости до применения изменений, фиксацией действий в manifest/report и контролируемым откатом там, где это возможно.

Дополнительные меры отделены от основного набора hardening и по умолчанию отключены. Для текущего запуска `--apply` они включаются CLI-флагом `--enable-additional-measures` либо параметром `ENABLE_ADDITIONAL_MEASURES=1` в config-файле. Отдельная корпоративная парольная политика включается CLI-флагом `--enable-corporate-password-policy` либо параметром `ENABLE_CORPORATE_PASSWORD_POLICY=1`. Оба CLI-флага имеют высший приоритет над config-файлом и могут применяться совместно.

## Текущая версия: 16.2.11

Framework реализован; в проектном реестре реализованы 59 из 60 позиций. История изменений по версиям — в CHANGELOG.md.

## Среда выполнения

Основной скрипт задаёт системный `PATH`: `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.

Это исключает зависимость от пользовательского `PATH` и обеспечивает обнаружение `visudo`, `sysctl` и других административных команд на Debian.

## Основные режимы

Поддерживаемые режимы:
- `--help`
- `--version`
- `--check`
- `--apply`
- `--restore`
- `--report`

Поддерживаемые опции framework-уровня:
- `--dry-run`
- `--enable-additional-measures` — включает 17 дополнительных модулей только для `--apply`
- `--enable-corporate-password-policy` — включает корпоративную парольную политику и `pam_faillock` только для `--apply`
- `--profile=baseline|strict|paranoid`
- `--config <file>`
- `--manifest <file>` — явный manifest для `--restore`


## Общая схема выполнения

Схема отражает фактический поток `main()`. Режимы `--help` и `--version`
завершаются непосредственно в `parse_args()` и не переходят к основным режимам.

```mermaid
flowchart TB
    CLI["Аргументы CLI"] --> PARSE["parse_args()"]
    PARSE --> EARLY{"--help или --version?"}

    EARLY -- "да" --> EXIT["Вывод результата<br/>exit 0"]
    EARLY -- "нет" --> COMMON["require_cmds()<br/>validate_args()<br/>load_config()<br/>validate_args_post_config()<br/>validate_execution_context()<br/>finalize_paths()"]

    COMMON --> MODE{"MODE"}

    MODE --> CHECK["run_check_mode()"]
    CHECK --> CHECK_PRE["run_preflight()"]
    CHECK_PRE --> CHECK_MODULES["Проверка основных<br/>и включённых дополнительных модулей"]
    CHECK_MODULES --> CHECK_OUT["check-report<br/>JSON report<br/>stdout summary"]

    MODE --> APPLY["run_apply_mode()"]
    APPLY --> APPLY_PRE["run_preflight()<br/>check_memory_requirements()"]
    APPLY_PRE --> APPLY_STATE["ensure_state_dir()<br/>acquire_run_lock()<br/>manifest_init()"]
    APPLY_STATE --> APPLY_MODULES["Применение основных<br/>и включённых дополнительных модулей"]
    APPLY_MODULES --> APPLY_OUT["Manifest<br/>JSON report<br/>stdout summary"]

    MODE --> RESTORE["run_restore_mode()"]
    RESTORE --> RESTORE_PRE["run_preflight()<br/>resolve_restore_manifest()"]
    RESTORE_PRE --> RESTORE_STATE["ensure_state_dir()<br/>acquire_run_lock()<br/>чтение параметров manifest"]
    RESTORE_STATE --> RESTORE_MODULES["Откат модулей<br/>по данным manifest"]
    RESTORE_MODULES --> RESTORE_OUT["JSON report<br/>stdout summary"]

    MODE --> REPORT["run_report_mode()"]
    REPORT --> REPORT_PRE["run_preflight()<br/>ensure_state_dir()"]
    REPORT_PRE --> REPORT_OUT["Статическое покрытие ФСТЭК<br/>JSON report<br/>stdout summary"]
```


## Карта модулей усиления безопасности

Группировка ниже отражает назначение модулей. Точный порядок вызовов задаётся
функциями `run_check_mode()`, `run_apply_mode()` и `run_restore_mode()`.

```mermaid
flowchart TB
    CHECK_APPLY["Режимы check и apply"] --> CORE["Основной набор модулей<br/>(вызывается всегда)"]
    CHECK_APPLY --> FLAG{"ENABLE_ADDITIONAL_MEASURES = 1?"}

    FLAG -- "да" --> EXTRA["Дополнительные семейства модулей"]
    FLAG -- "нет" --> EXTRA_SKIP["Дополнительные модули пропускаются"]

    CORE --> ACCESS["Учётные записи и доступ<br/>пустые пароли · SSH root login · pam_wheel · sudo"]
    CORE --> CORP_FLAG{"ENABLE_CORPORATE_PASSWORD_POLICY = 1?"}
    CORP_FLAG -- "да" --> CORP["Корпоративная парольная политика<br/>password policy · password aging<br/>faillock только для strict/paranoid"]
    CORP_FLAG -- "нет" --> CORP_SKIP["Корпоративная парольная политика пропускается"]
    CORE --> FILES["Файлы и пути<br/>критические файлы · runtime-пути · домашние каталоги<br/>sudo/cron PATH · пользовательский cron · системные пути<br/>SUID/SGID · cron targets · systemd units"]
    CORE --> KERNEL["Ядро и загрузка<br/>kernel sysctl · параметры GRUB<br/>attack-surface sysctl · userspace-protection sysctl<br/>kernel.modules_disabled (временно SKIP)"]

    EXTRA --> SERVICES["Службы и аудит<br/>SSH hardening · account audit · auditd<br/>rsyslog · chrony · unattended-upgrades"]
    EXTRA --> PROTECTION["Средства защиты<br/>AppArmor · AIDE · Fail2ban · rkhunter"]
    EXTRA --> PLATFORM["Платформа и сеть<br/>blacklist опасных kernel modules · mount hardening · /tmp tmpfs<br/>UFW · Apport · coredump · network sysctl"]

    RESTORE["Режим restore"] --> CORE_RESTORE["Откат обязательных модулей<br/>по данным manifest"]
    RESTORE --> MANIFEST_FLAG{"manifest:<br/>additional_measures_enabled"}
    MANIFEST_FLAG -- "true" --> EXTRA_RESTORE["Откат дополнительных модулей"]
    MANIFEST_FLAG -- "false" --> EXTRA_RESTORE_SKIP["Откат дополнительных модулей пропускается"]

    REPORT["Режим report"] --> STATIC["Только статическое покрытие ФСТЭК<br/>модули не проверяются и не применяются"]
```


## Поток apply, manifest и restore

Для операций, поддерживающих автоматический откат, до изменения сохраняется
исходное состояние. Manifest обновляется атомарно и связывает restore с backup,
снимками состояния и объектами, созданными текущим apply.

```mermaid
flowchart TB
    APPLY["--apply"] --> INIT["manifest_init()"]

    INIT --> PRESTATE["Фиксация исходного состояния"]
    PRESTATE --> FILE_BACKUP["Файлы<br/>backup_file_checked()"]
    PRESTATE --> SNAPSHOTS["Metadata и runtime snapshots<br/>права · sysctl · password aging"]
    PRESTATE --> PACKAGES["Список пакетов<br/>до установки"]
    PACKAGES --> PACKAGE_PENDING["Durable package intent<br/>pending_package_transactions"]
    PACKAGE_PENDING --> PACKAGE_INSTALL["apt-get install"]
    PACKAGE_INSTALL --> PACKAGE_COMMIT["Фактическая разница<br/>installed_packages + remove pending"]

    FILE_BACKUP --> BACKUP_OK{"Backup успешен?"}
    BACKUP_OK -- "нет" --> SKIP["Изменение объекта пропускается<br/>warning записывается в manifest"]
    BACKUP_OK -- "да" --> CHANGE["Применение изменения"]
    SNAPSHOTS --> CHANGE

    CHANGE --> RECORD["Атомарное обновление manifest"]
    RECORD --> MANIFEST["backups · pending_created_files · created_files<br/>pending_created_groups · created_groups<br/>pending_group_memberships · added_group_memberships<br/>pending_package_transactions · installed_packages<br/>modified_files · password_aging_snapshots<br/>apply_report · warnings · irreversible_changes"]
    PACKAGE_COMMIT --> MANIFEST

    RESTORE["--restore"] --> RESOLVE["Выбор manifest<br/>--manifest FILE<br/>последний manifest-*.json<br/>manifest.json<br/>последний *.json.bak-TIMESTAMP"]
    RESOLVE --> READ["Чтение profile<br/>additional_measures_enabled<br/>и записей исходного состояния"]
    READ --> MODULES["Модульный restore"]

    MANIFEST -. "используется последующим --restore" .-> RESOLVE

    MODULES --> FILES["Восстановление файлов<br/>из backup"]
    MODULES --> CREATED["Удаление объектов,<br/>созданных текущим apply"]
    MODULES --> METADATA["Восстановление владельцев,<br/>групп и режимов доступа"]
    MODULES --> RUNTIME["Адресный runtime restore<br/>sysctl и password aging"]
    MODULES --> PACKAGE_DIFF["Committed/pending package diff<br/>auto-purge: password-policy · auditd · fail2ban<br/>точный manual list: остальные модули"]
    MODULES --> LIMITS["Partial, manual или reboot<br/>для несимметричных изменений"]

    FILES --> REPORT["Restore report и stdout summary"]
    CREATED --> REPORT
    METADATA --> REPORT
    RUNTIME --> REPORT
    PACKAGE_DIFF --> REPORT
    LIMITS --> REPORT
```

## Модель профилей

Проект использует три профиля:
- `baseline`
- `strict`
- `paranoid`

Назначение профилей:
- `baseline` — минимально необходимый и максимально совместимый уровень;
- `strict` — усиленный уровень с большим количеством ограничений;
- `paranoid` — максимально жёсткий профиль, допускающий дополнительные compatibility-ограничения.


## Модель конфигурации

Приоритет источников конфигурации:
1. defaults внутри скрипта;
2. внешний config file;
3. CLI overrides.

CLI `--profile` всегда имеет приоритет над значением из config-файла через `_PROFILE_SET_BY_CLI`. CLI-флаг `--enable-additional-measures` устанавливает `_ADDITIONAL_MEASURES_SET_BY_CLI=1` и не может быть выключен значением `ENABLE_ADDITIONAL_MEASURES=0` из config-файла. CLI-флаг `--enable-corporate-password-policy` устанавливает `_CORPORATE_PASSWORD_POLICY_SET_BY_CLI=1` и не может быть выключен значением `ENABLE_CORPORATE_PASSWORD_POLICY=0` из config-файла.

Ключевые параметры:

- `PROFILE` — профиль `baseline`, `strict` или `paranoid`;
- `STATE_DIR`, `REPORT_FILE` — пути manifest, backup, логов и отчёта;
- `secure_state_dir()` создаёт/открывает `STATE_DIR` с `O_NOFOLLOW`, сверяет inode через `fstat/lstat`, owner с текущим EUID и принудительно подтверждает mode `0700`; symlink, чужой owner и не-каталог отклоняются;
- `ENABLE_CORPORATE_PASSWORD_POLICY` — включает дополнительную корпоративную парольную политику; по умолчанию `0`; CLI-флаг `--enable-corporate-password-policy` имеет приоритет;
- `ENABLE_ADDITIONAL_MEASURES` — включает 17 дополнительных модулей; по умолчанию `0`; CLI-флаг `--enable-additional-measures` имеет приоритет;
- `WHEEL_USERS` — необязательный явный список существующих администраторов для безопасного включения `pam_wheel`; при пустом значении обычный запуск через `sudo` использует проверенного `SUDO_USER`;
- `USER_NAMESPACES_LIMIT` — значение `user.max_user_namespaces`;
- `UFW_EXTRA_RULES` — дополнительные разрешения UFW вида `порт/протокол:комментарий`; правила применяются без ограничения по адресу источника.

## Блокировки apt/dpkg

Установка пакетов выполняется синхронно. Перед пакетной операцией скрипт проверяет:

- `/var/lib/dpkg/lock-frontend`;
- `/var/lib/dpkg/lock`;
- `/var/cache/apt/archives/lock`.

Владелец определяется через `fuser`, а при его отсутствии — через `lslocks`. Скрипт ждёт фактического освобождения блокировки и не завершает чужие процессы. `DPkg::Lock::Timeout=300` дополнительно защищает от гонки непосредственно перед запуском `apt-get`.

Пакетная мутация имеет двухфазный журнал: полный список пакетов сохраняется в root-only snapshot, затем `{module, snapshot}` durable-записью помещается в `pending_package_transactions`, и только после этого выполняется `apt-get install`. Фактическая разница `after − before` и удаление pending intent записываются одним атомарным commit. Поэтому авария после частичной установки не оставляет пакетную мутацию без restore-состояния.

Минимально поддерживаемые ключи config:
- `PROFILE`
- `STATE_DIR`
- `REPORT_FILE`
- `MANIFEST_FILE`
- `USER_NAMESPACES_LIMIT`
- `ENABLE_CORPORATE_PASSWORD_POLICY`
- `ENABLE_ADDITIONAL_MEASURES`
- `WHEEL_USERS`
- `UFW_EXTRA_RULES` — список правил вида `порт/протокол:комментарий`, разделённых пробелами

Требования к config:
- формат `KEY=VALUE`;
- пустые строки и комментарии допустимы;
- неизвестные ключи не должны ломать выполнение, но должны отражаться как warning.

## Preflight / compatibility model

Перед применением hardening-мер должен выполняться preflight-анализ среды.

Минимум, что должен определять preflight:
- семейство ОС;
- версия ОС;
- container / non-container;
- desktop / server-like environment;
- Docker;
- Podman;
- Kubernetes node.

Результат preflight должен раскладываться минимум на 4 категории:
- `safe`
- `risky`
- `skipped`
- `requires_confirmed_policy`

Принцип:
- framework не должен молча применять потенциально опасные меры;
- сомнительные меры маркируются через `policy_gate` — запись в отчёт с предупреждением;
- автоматического запрета мер по среде нет: решение о применении остаётся за администратором.

## Manifest model

Manifest должен быть машинно-читаемым и пригодным для restore/report.

Все записи в manifest выполняются атомарно (temp file + `fsync` + `os.replace`), чтобы прерывание процесса не могло повредить JSON.

Для managed-файлов, отсутствовавших до apply, используется двухфазный журнал: `pending_created_files` записывается и синхронизируется до первой файловой мутации, а после успешной записи и проверки путь переносится в `created_files`. При аварийном завершении restore считает оба списка основанием для удаления созданного объекта.

Для `wheel` применяется тот же crash-safe принцип: `pending_created_groups` фиксируется до `groupadd`, а `pending_group_memberships` — до `gpasswd -a`. После успешной мутации записи атомарно переводятся в `created_groups` и `added_group_memberships`. Restore объединяет pending и committed состояния, сначала удаляет добавленные membership, затем удаляет созданную пустую группу.

Минимальные поля manifest:
- `version`
- `profile`
- `mode`
- `timestamp`
- `backups`
- `pending_created_files`
- `created_files`
- `pending_created_groups`
- `created_groups`
- `pending_group_memberships`
- `modified_files` — информационный best-effort список; restore его не использует, а ошибка записи отражается предупреждением
- `systemd_units`
- `sysctl_configs`
- `grub_backups`
- `module_state`
- `apply_report`
- `additional_measures_enabled`
- `corporate_password_policy_enabled`
- `installed_packages`
- `added_group_memberships`
- `password_aging_snapshots`
- `warnings`
- `irreversible_changes`

`module_state` хранит типизированные restore-критические признаки. Для `mount_hardening` и `tmp_tmpfs` поле `restore_required=true` записывается после регистрации общего backup `/etc/fstab`, но до первой мутации. Для `firewall` до stop/mask nftables, изменения правил и enable UFW записываются pre-state и intent-флаги active/enabled. `apply_report` остаётся только человекочитаемым журналом и не определяет необходимость restore этих модулей.


## Restore model

Restore в SecureLinux-NG должен опираться не на догадки, а на manifest.

Restore-модель должна предполагать:
- восстановление изменённых файлов из backup;
- удаление созданных файлов;
- удаление созданных групп;
- удаление созданных systemd unit/drop-in;
- удаление созданных sysctl drop-in;
- восстановление исходных runtime sysctl-значений из snapshot, сохранённого перед apply;
- отдельную маркировку действий, которые автоматически неоткатны.

Restore-модель не является полностью симметричной для всех мер:
- часть изменений откатывается только частично;
- часть изменений требует ручных действий;
- часть runtime-эффектов не должна восстанавливаться автоматически по соображениям безопасности.

Примеры асимметричного restore:
- пакеты дополнительных модулей (`rkhunter`, `unattended-upgrades`, `chrony`, `rsyslog`) не удаляются автоматически; исключение — зависимости корпоративной парольной политики, впервые установленные текущим apply и записанные в `installed_packages`;
- typed `module_state.firewall` возвращает active/enabled UFW и nftables, но restore остаётся partial по ruleset/default policy и не удаляет существующие правила заранее активного UFW;
- пустые поля пароля в `/etc/shadow` не восстанавливаются автоматически по соображениям безопасности;
- `kernel.kexec_load_disabled=1` является write-once и не возвращается в `0` без перезагрузки.

Если откат невозможен, это должно быть явно отражено в manifest/report.

При повторном `--apply` с существующим manifest — администратор подтверждает продолжение, после чего существующий manifest архивируется в `.bak-<timestamp>` и создаётся новый.

## Report model

После `--check`, `--apply`, `--restore` и `--report` должен существовать единый формат итогового report.

Минимальные разделы report:
- версия;
- профиль;
- режим;
- сведения о среде;
- `safe`;
- `risky`;
- `skipped`;
- `requires_confirmed_policy`;
- `warnings`;
- `errors`.

На этапе dry-run report может не писаться на диск, но summary должен печататься в stdout.

## Защита от параллельного запуска

Режимы `--apply` и `--restore` защищены через `flock` (`acquire_run_lock`). При обнаружении параллельного экземпляра — немедленное завершение с ошибкой.

## Гарантия backup при apply

Все backup-операции перед перезаписью конфигов выполняются через `backup_file_checked()` с проверкой успеха `cp`. Если backup не удался (диск заполнен, ошибки I/O) — модуль пропускается, а не продолжает с потерянным оригиналом. Это критично для PAM, SSH, sudoers, sysctl dropin-файлов.

`record_manifest_backup()` связывает исходный путь с backup до начала мутации. Если последующая подготовка не была зафиксирована, `remove_manifest_backup()` удаляет mapping. `restore_manifest_has_path()` различает штатное отсутствие записи и ошибку чтения manifest, поэтому restore не трактует повреждённый JSON как неприменённый модуль.

## Атомарная запись критичных файлов

`atomic_write_command_output()` формирует содержимое во временном файле в каталоге цели, применяет mode/uid/gid, выполняет `fsync` и только после успешного завершения генератора вызывает `os.replace`.

Для символьной ссылки helper намеренно не выполняет `resolve()`: временный файл заменяет сам управляемый pathname, а содержимое файла-цели ссылки остаётся неизменным. Метаданные выбираются только по `lstat()` управляемого pathname: mode/uid/gid/xattrs наследуются исключительно от существующего обычного файла; для любой рабочей или висячей ссылки применяются `default_mode` и текущие EUID/EGID, а xattrs файла-цели не читаются. Это исключает создание world-writable managed-файла при ссылке на `/dev/null`, каталог или файл с ослабленными правами. Backup создаётся через `cp -a` и сохраняет тип ссылки и её target. При restore текущий объект удаляется, затем исходная ссылка возвращается из backup через `cp -a`. Та же модель применяется к GRUB и трём managed-файлам coredump. Висячие ссылки учитываются как существующие объекты транзакции.

Модификация обычного `/etc/shadow` (блокировка пустых паролей) выполняется через атомарную запись: temp file + `fsync` + `os.replace`. Symlink pathname отклоняется до мутации. Restore-критичный журнал затронутых УЗ хранится в typed `module_state.empty_passwords`; generic `backups` остаётся только для реальных файловых backup и metadata snapshot.

UFW использует typed `module_state.firewall`: исходные active/enabled-состояния UFW и nftables записываются до первой мутации, а intent-флаги — до stop/mask, изменения правил и enable. Если последний `systemctl enable ufw` неуспешен, apply пытается локально отключить UFW и в любом случае возвращает RC=1; restore использует typed marker, а legacy `apply_report` читается только как fallback для старых manifest.

## Повторное применение сетевых sysctl после network-online

`systemd-sysctl` применяет `/etc/sysctl.d/*.conf` на раннем этапе загрузки.
После этого NetworkManager, systemd-networkd, cloud-init, VPN, контейнерные
платформы и другие сетевые компоненты могут создать или повторно поднять
интерфейсы и изменить параметры `/proc/sys/net/*`.

Поэтому SecureLinux-NG создаёт oneshot-unit:

`/etc/systemd/system/securelinux-ng-sysctl.service`

Unit запускается после `network-online.target` и выполняет только:

`/sbin/sysctl -p /etc/sysctl.d/62-securelinux-ng-network.conf`

Глобальный `sysctl --system` не используется. Параметры других приложений и
чужие sysctl drop-in-файлы повторно не применяются.

Состояние `active (exited)` является нормальным для `Type=oneshot` с
`RemainAfterExit=yes`: команда уже успешно выполнена, постоянно работающий
процесс не требуется.

Без этого unit или эквивалентного hook-механизма нельзя гарантировать, что
сетевые параметры hardening сохранятся после завершения настройки сети и
создания дополнительных интерфейсов.

Возможные альтернативы — dispatcher-скрипты NetworkManager, hooks
systemd-networkd или отдельные обработчики конкретного сетевого стека.
Отдельный systemd-unit выбран как единый механизм для поддерживаемых Debian
и Ubuntu независимо от используемого сетевого менеджера.

## Изолированная модель sysctl

Каждый sysctl-модуль применяет только собственный managed drop-in через `sysctl -p <file>`. Глобальный `sysctl --system` не используется.

Перед применением сохраняются текущие live-значения параметров в `sysctl-runtime-<module>-<timestamp>.json`. Путь к snapshot фиксируется в `apply_report` manifest. При restore значения возвращаются адресно через `sysctl -w`.

Исключение: write-once параметры ядра, включая `kernel.kexec_load_disabled`, могут не восстановиться до перезагрузки и поэтому имеют статус `partial`.

## Dry-run model

`--dry-run` допустим только вместе с `--apply`.

В dry-run framework обязан:
- ничего не менять в системе;
- показывать, что было бы создано;
- показывать, что было бы изменено;
- показывать, какие артефакты manifest/report были бы созданы;
- печатать итоговую summary без требования реального наличия report-файла.

## Разделение framework и hardening

Правило проекта: framework и hardening не смешивать. Все шесть этапов разработки пройдены: framework, preflight, config/report/manifest, hardening-модули, coverage checks, restore verification.

## Группы hardening-модулей

### Реализованы
1. **identity / auth / PAM / SSH** — обязательные 2.1.1 и 2.1.2, SSH hardening, 2.2.1 с администраторами из явного `WHEEL_USERS` либо проверенного `SUDO_USER`, 2.2.2; опционально по `--enable-corporate-password-policy` либо `ENABLE_CORPORATE_PASSWORD_POLICY=1`: faillock, pwquality, login.defs, `chage` с manifest-снимком aging и нормализация `common-password`
2. **file permissions / ownership** — 2.3.1–2.3.11
3. **kernel / sysctl / boot** — 2.4.x, 2.5.x, 2.6.x, GRUB apply
4. **audit** — auditd baseline (identity, sudo, sshd, modules, privileged, network bind/connect, usb_devices) + extended
5. **firewall** — UFW
6. **mount hardening** — /tmp tmpfs, /dev/shm, /var/tmp
7. **kernel modules** — blacklist неиспользуемых ФС и протоколов
8. **intrusion detection** — fail2ban, AIDE, rkhunter
9. **mandatory access control** — AppArmor enforce
10. **reporting** — account audit, coverage report
11. **network hardening** — sysctl network (ip_forward, log_martians, rp_filter, redirects, tcp_syncookies, icmp_echo_ignore_broadcasts, icmp_ignore_bogus_error_responses, tcp_syn_retries)
12. **core dumps** — limits.d + systemd coredump.conf + kernel.core_pattern sysctl dropin

## Трассировка требований

Каждый hardening-блок должен иметь:
- ссылку на пункт ФСТЭК;
- статус покрытия;
- проверку результата;
- отражение в `docs/fstec-mapping.md`.

Блок не считается реализованным окончательно без:
- кода;
- проверки;
- отражения в mapping.

## Структура main()

Порядок вызовов в `main()`:
1. `parse_args` — разбор CLI (включая `--help`/`--version`, которые завершаются сразу);
2. `require_cmds` — проверка наличия обязательных команд;
3. `validate_args` — проверка аргументов;
4. `load_config` — загрузка внешнего config;
5. `validate_args_post_config` — проверка профиля после загрузки конфига;
6. `validate_execution_context` — проверка root для apply/restore;
7. `finalize_paths` — вычисление путей report/manifest/log.

`--help` и `--version` работают без проверки наличия системных команд.

## Документационный принцип

Для SecureLinux-NG порядок должен быть таким:
1. сначала фиксируется архитектура;
2. затем меняется код;
3. затем добавляются тесты;
4. затем обновляются README / CHANGELOG / mapping.

## Report coverage model

Итоговый `report` должен включать не только среду и warnings/errors, но и отдельный блок покрытия ФСТЭК:
- `fstec_items`
- `fstec_summary`

Это позволяет видеть текущий фактический объём реализованных модулей без чтения `docs/fstec-mapping.md`.

## Уточнения архитектуры v16.2.11

### Gate дополнительных мер

Обычный `--apply` сохраняет безопасное значение `ENABLE_ADDITIONAL_MEASURES=0` и выполняет основной набор hardening без дополнительного блока.

CLI-флаг `--enable-additional-measures` допустим только вместе с `--apply`, имеет приоритет над config-файлом и включает 17 модулей:

1. расширенное укрепление SSH;
2. аудит учётных записей;
3. AppArmor;
4. AIDE;
5. fail2ban;
6. rkhunter;
7. отключение опасных модулей ядра;
8. укрепление параметров монтирования;
9. защищённый `/tmp` как `tmpfs`;
10. UFW;
11. auditd и правила аудита;
12. rsyslog;
13. chrony;
14. unattended-upgrades;
15. отключение apport;
16. ограничение core dump;
17. дополнительные сетевые sysctl.

Фактическое состояние сохраняется в manifest-поле `additional_measures_enabled`. При запуске с CLI-флагом записывается `true`, без него и при значении config `0` — `false`.

Если apply выполнялся со значением `false`, restore пропускает дополнительные модули, которые не применялись. Для старых manifest без этого поля используется совместимое прежнее поведение полного restore дополнительных модулей.

### Gate корпоративной парольной политики

Корпоративная парольная политика является отдельным opt-in-блоком и не входит в 17 модулей `--enable-additional-measures`.

CLI-флаг `--enable-corporate-password-policy` допустим только с `--apply`, устанавливает `ENABLE_CORPORATE_PASSWORD_POLICY=1` с приоритетом над config-файлом и включает:

1. password policy, password aging, `pam_pwquality`, `pam_pwhistory` и нормализацию `pam_unix` для всех профилей;
2. `pam_faillock` для профилей `strict` и `paranoid`.

Фактическое состояние сохраняется в manifest-поле `corporate_password_policy_enabled`. Поле подтверждает выбранный apply-режим; restore корпоративных изменений остаётся manifest-driven и использует конкретные backup, package и password-aging записи.

Флаги `--enable-additional-measures` и `--enable-corporate-password-policy` независимы и могут применяться совместно.

### Crash-consistent package journal

Все десять package-install путей используют `install_packages_transactionally()`. До `apt-get install` полный список пакетов и путь snapshot фиксируются в `pending_package_transactions`; после операции один атомарный commit переносит фактическую разницу в `installed_packages` и удаляет pending intent.

При restore `password-policy`, `auditd` и `fail2ban` автоматически удаляют committed-разницу либо вычисленную по pending snapshot разницу. AppArmor, AIDE, rkhunter, UFW, rsyslog, chrony и unattended-upgrades сохраняют прежнюю ручную policy, но restore детектирует package journal и выводит точный список оставшихся пакетов.

Для password policy после пакетного restore восстанавливаются `pwquality.conf`, `login.defs`, `common-password` и password aging.

Состояние `/etc/security/pwquality.conf` фиксируется до установки
зависимостей, поскольку `libpwquality-common` способен создать файл.

### Сохранение более строгих sysctl

Для `kernel.perf_event_paranoid`,
`kernel.unprivileged_bpf_disabled` и `vm.mmap_min_addr`
apply не понижает уже действующее более строгое числовое значение.
Check считает равное или более строгое значение соответствующим.

### Restore GRUB

Backup создаётся для `/etc/default/grub`. После восстановления
выполняется `update-grub` или `grub2-mkconfig`.

Функциональная конфигурация и активная командная строка ядра после
reboot возвращаются к исходным, но generated-файл
`/boot/grub/grub.cfg` не резервируется и не обязан совпадать побайтово.


### Durable service-state intent

Для простых systemd-мутаций используется двухфазный журнал `pending_service_transactions → service_transactions`. Pending запись содержит module, unit, operation, `enabled_before` и `active_before` и сохраняется до `systemctl`. Commit выполняется после попытки мутации независимо от её RC, чтобы частично изменённое состояние не осталось без restore-маркера.

Автоматический `--restore` сохраняет прежний порядок выбора активных `manifest-*.json` и `manifest.json`, а при их отсутствии ищет последний обычный файл `*.json.bak-YYYYMMDD-HHMMSS`. Symlink-кандидаты игнорируются. Архивный manifest появляется при подтверждённом повторном apply до создания нового manifest, поэтому fallback закрывает окно `archive → manifest_init`.

Typed service-state охватывает network sysctl unit, AppArmor, rsyslog, chrony, unattended-upgrades и apport. Restore обрабатывает и pending, и committed intent. Специализированные транзакции fail2ban, auditd и UFW/nftables остаются отдельными, поскольку дополнительно восстанавливают правила и связанные объекты.

Для `fs.suid_dumpable=0` одного раннего `/etc/sysctl.d` недостаточно на Ubuntu 24.04: `apport.service` запускается позже `systemd-sysctl.service` и устанавливает runtime-значение `2`. Базовый модуль 2.6 добавляет штатный systemd drop-in `/etc/systemd/system/apport.service.d/60-securelinux-ng-suid-dumpable.conf` с `ExecStartPost=/usr/sbin/sysctl -q -w fs.suid_dumpable=0`. Хук выполняется после каждого успешного `ExecStart` Apport, поэтому покрывает boot, последующий `start` и `restart` без отдельного unit и без изменения enabled/active state. Файл защищён created-file/backup транзакцией и автоматически восстанавливается или удаляется при restore.

### Hardlink safety boundary

Manifest хранит content-backup и metadata отдельного пути, но не сохраняет множество имён одного inode. Поэтому `validate_managed_file_hardlinks()` использует `lstat()` и отклоняет обычный файл с `st_nlink > 1` до backup, atomic replace или restore removal. `atomic_write_command_output()` повторяет проверку непосредственно перед созданием временного файла, чтобы direct-write пути не обходили общий backup helper.

Restore отдельно проверяет backup, существующую цель и удаляемый created-file target. При обнаружении нескольких hardlink-имён операция возвращает RC=1 и оставляет все связанные пути без изменений.

### Extended metadata preservation

`atomic_write_command_output()` сохраняет не только mode, uid и gid существующего managed-файла. Перед созданием нового inode helper считывает все доступные через `os.listxattr()` атрибуты, переносит их на открытый временный descriptor через `os.setxattr()` и побайтово проверяет через `os.getxattr()` до `fsync` и `os.replace`.

В Linux POSIX ACL (`system.posix_acl_access`), file capabilities (`security.capability`) и security labels (`security.selinux`, если применимо) представлены extended attributes. Поэтому единый механизм сохраняет их без зависимости от наличия CLI-утилит `getfacl`, `setfacl`, `getcap` или `setcap`.

Если файловая система явно сообщает `ENOTSUP`, `EOPNOTSUPP` либо `ENOSYS` на этапе `os.listxattr()`, helper рассматривает это как отсутствие поддержки xattrs и продолжает атомарную запись без расширенных атрибутов. Любая иная ошибка перечисления, включая `EACCES`/`EPERM`, а также ошибка чтения, записи или проверки существующего xattr сохраняет fail-before-replace: временный файл удаляется, managed-path не заменяется и apply получает ненулевой RC.

Content-backup и restore по-прежнему используют `cp -a`, который возвращает исходный объект и его metadata. Atomic helper закрывает отдельное окно apply, когда новый hardened-файл должен сохранить расширенную metadata прежнего inode.

### Portable release checksum

`tools/write-sha256.py` формирует GNU `sha256sum -c`-совместимый checksum-файл и записывает для каждого артефакта только `Path.name`, без абсолютного или относительного каталога машины сборки.

Один входной файл по умолчанию получает соседний `<artifact>.sha256`. Несколько входов требуют явного `--output`; одинаковые basename отклоняются, поскольку после переноса в один каталог такая checksum-карта была бы неоднозначной.

Входной артефакт и выходной checksum не могут быть symlink. Сам checksum записывается атомарно через временный файл, `fsync`, `os.replace` и `fsync` каталога.

### Внутренние сбои режима `--check`

Check-модули не оборачиваются массово в `run_mode_step`, поскольку часть
из них использует ненулевой локальный результат для представления policy
findings. Такие результаты остаются `RISKY` и не являются ошибкой запуска.

Внутренние сбои, после которых модуль не может завершить проверку, обязаны
вызывать `add_error`. В частности, это относится к отказу
`systemd_unit_candidates()` и невозможности разобрать `WHEEL_USERS` в
`check_pam_wheel_module()`. Финальная проверка массива `ERRORS` в
`run_check_mode()` преобразует такие случаи в ненулевой итоговый RC, не
изменяя семантику обычных risky-находок.

## Profile-aware dry-run и sudoers portability

Полностью профильные apply-модули выполняют `profile_allows` до
ветки `DRY_RUN`. Поэтому dry-run показывает тот же допустимый набор
модулей, что и реальный apply:

- AppArmor и AIDE — `strict+`;
- fail2ban, rkhunter, mount hardening и `/tmp` tmpfs — `paranoid`.

SSH hardening, network sysctl, kernel blacklist и auditd являются
смешанными модулями: они выполняются во всех профилях, а профиль
определяет формируемое содержимое.

Managed sudoers policy атомарно проверяется активным `visudo`. Для
совместимости классического sudo и `sudo-rs` используется общий
поддерживаемый набор директив; необязательная директива `logfile`
исключена.
