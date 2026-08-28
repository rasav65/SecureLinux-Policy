# Важно: это donor runtime reference, а не основная карта v3

Основная карта текущего SecureLinux-Policy v3:
[`PROJECT-MAP-v3.md`](PROJECT-MAP-v3.md).

Схемы ниже сохранены как полезная целевая runtime-модель из старого
SecureLinux-NG. Они не описывают текущую структуру v3 целиком и не являются
источником статуса проекта.

---

# SecureLinux-Policy v3 — визуальная архитектура

> **Статус:** целевая runtime-архитектура, сохранённая из инженерного донора
> SecureLinux-NG. Она сохранена как donor evidence и **не закрепляет RESTORE как цель v3**.
>
> Эти схемы не утверждают, что все показанные runtime-механизмы уже реализованы
> в v3. Их перенос идёт через `DONOR_TO_V3_MAPPING`. Будущий v3 runtime имеет
> только APPLY semantic contract; показанные ниже RESTORE-ветви являются
> историческими donor-механизмами и не входят в целевую архитектуру.
>
> GitHub отрисовывает блоки `mermaid` ниже как диаграммы.

## 1. CLI и основные режимы

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
    REPORT_PRE --> REPORT_OUT["Статическое покрытие политики<br/>JSON report<br/>stdout summary"]
```

## 2. Модули, дополнительные меры и restore

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
    CORE --> KERNEL["Ядро и загрузка<br/>kernel sysctl · параметры GRUB<br/>kernel-hardening sysctl · userspace-protection sysctl<br/>kernel.modules_disabled"]

    EXTRA --> SERVICES["Службы и аудит<br/>SSH hardening · account audit · auditd<br/>rsyslog · chrony · unattended-upgrades"]
    EXTRA --> PROTECTION["Средства защиты<br/>AppArmor · AIDE · Fail2ban · rkhunter"]
    EXTRA --> PLATFORM["Платформа и сеть<br/>blacklist kernel modules · mount hardening · /tmp tmpfs<br/>firewall · Apport · coredump · network sysctl"]

    RESTORE["Режим restore"] --> CORE_RESTORE["Откат обязательных модулей<br/>по данным manifest"]
    RESTORE --> MANIFEST_FLAG{"manifest:<br/>additional_measures_enabled"}
    MANIFEST_FLAG -- "true" --> EXTRA_RESTORE["Откат дополнительных модулей"]
    MANIFEST_FLAG -- "false" --> EXTRA_RESTORE_SKIP["Дополнительные модули не откатываются,<br/>если не применялись"]

    REPORT["Режим report"] --> STATIC["Статическое покрытие политики<br/>модули не проверяются и не применяются"]
```

## 3. Apply → manifest → restore

```mermaid
flowchart TB
    APPLY["--apply"] --> INIT["manifest_init()"]

    INIT --> PRESTATE["Фиксация исходного состояния"]
    PRESTATE --> FILE_BACKUP["Файлы<br/>backup_file_checked()"]
    PRESTATE --> SNAPSHOTS["Metadata и runtime snapshots<br/>права · sysctl · password aging"]
    PRESTATE --> PACKAGES["Список пакетов<br/>до установки"]

    FILE_BACKUP --> BACKUP_OK{"Backup успешен?"}
    BACKUP_OK -- "нет" --> SKIP["Изменение объекта пропускается<br/>warning записывается в manifest"]
    BACKUP_OK -- "да" --> CHANGE["Применение изменения"]
    SNAPSHOTS --> CHANGE
    PACKAGES --> CHANGE

    CHANGE --> RECORD["Атомарное обновление manifest"]
    RECORD --> MANIFEST["backups · created_files · created_groups<br/>modified_files · added_group_memberships<br/>password_aging_snapshots · installed_packages<br/>apply_report · warnings · irreversible_changes"]

    RESTORE["--restore"] --> RESOLVE["Выбор manifest<br/>--manifest FILE<br/>последний manifest-*.json<br/>manifest.json"]
    RESOLVE --> READ["Чтение profile<br/>additional_measures_enabled<br/>и записей исходного состояния"]
    READ --> MODULES["Модульный restore"]

    MANIFEST --> MODULES

    MODULES --> FILES["Восстановление файлов<br/>из backup"]
    MODULES --> CREATED["Удаление объектов,<br/>созданных текущим apply"]
    MODULES --> METADATA["Восстановление владельцев,<br/>групп и режимов доступа"]
    MODULES --> RUNTIME["Адресный runtime restore<br/>sysctl и password aging"]
    MODULES --> PACKAGE_DIFF["Purge только новых пакетов,<br/>установленных текущим apply"]
    MODULES --> LIMITS["Partial · manual · reboot<br/>для несимметричных изменений"]

    FILES --> REPORT["Restore report и stdout summary"]
    CREATED --> REPORT
    METADATA --> REPORT
    RUNTIME --> REPORT
    PACKAGE_DIFF --> REPORT
    LIMITS --> REPORT
```

## Текущее место в проекте

Эти donor runtime diagrams не являются источником текущего статуса.
Актуальная primary-карта — [`PROJECT-MAP-v3.md`](PROJECT-MAP-v3.md), а
машинный macro-roadmap — `ROADMAP-v3.tsv`.

До открытия `APPLY semantic contract` показанные APPLY-ветви остаются donor/future
reference. Показанные RESTORE-ветви — только историческая donor reference:
пользовательский RESTORE в v3 не планируется, post-APPLY recovery выполняется
внешним snapshot rollback.
