# Restore model — SecureLinux-NG

## Зачем нужен сетевой systemd-unit

Сетевой systemd-unit нужен не для постоянного фонового процесса, а для
однократного повторного применения `/etc/sysctl.d/62-securelinux-ng-network.conf`
после `network-online.target`.

Состояние `active (exited)` означает успешное завершение oneshot-команды.
Постоянно работающий процесс в памяти не требуется.

Без этого unit допустим только эквивалентный механизм сетевого менеджера,
который повторно применяет те же параметры после создания и поднятия
интерфейсов.

## Текущий охват --restore

| Модуль | Файл/объект | Метод restore |
|---|---|---|
| 2.1.2 SSH root | `/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf` | backup |
| 2.1.2 SSH hardening | `/etc/ssh/sshd_config.d/61-securelinux-ng-ssh-hardening.conf` | backup |
| Corporate faillock | `/etc/security/faillock.conf` | backup; применяется только при включённой корпоративной политике и strict+ |
| Corporate password policy | `/etc/security/pwquality.conf`, `/etc/login.defs`, `/etc/pam.d/common-password` | исходное состояние фиксируется до установки зависимостей; backup либо удаление созданного файла; применяется только по флагу |
| Corporate password aging | `password_aging_snapshots` в manifest | восстановление исходных параметров через `chage` |
| Password policy packages | `installed_packages` в manifest | purge только пакетов и зависимостей, отсутствовавших до apply |
| 2.2.1 PAM wheel | `/etc/pam.d/su` | backup; PAM-блок активируется только после добавления проверенного администратора |
| 2.2.1 членства wheel | `added_group_memberships` в manifest | удаляются только членства, добавленные текущим apply |
| 2.2.1 группа wheel | группа `wheel` | `groupdel`, только если группа создана скриптом и осталась пустой |
| 2.2.2 sudoers | `/etc/sudoers.d/60-securelinux-ng-policy` | backup |
| 2.3.1 | `/etc/passwd`, `/etc/group`, `/etc/shadow` | metadata snapshot |
| 2.3.5 | targets в `/etc/systemd/system` | metadata snapshot |
| 2.3.6 | системные cron targets | metadata snapshot |
| 2.4.1/2/8 | `/etc/sysctl.d/60-securelinux-ng-kernel.conf` | backup файла + runtime snapshot + адресный restore через `sysctl -w` |
| 2.5.x | `/etc/sysctl.d/61-securelinux-ng-attack-surface.conf` | backup файла + runtime snapshot; `kernel.kexec_load_disabled` и `kernel.unprivileged_bpf_disabled` требуют reboot для полного runtime-отката |
| 2.6.x | `/etc/sysctl.d/99-securelinux-ng-userspace-protection.conf`, `/etc/systemd/system/apport.service.d/60-securelinux-ng-suid-dumpable.conf` | backup + runtime snapshot; Apport drop-in восстанавливается/удаляется через created-file/backup transaction и `daemon-reload` до runtime restore; service-state Apport не меняется; `kernel.yama.ptrace_scope=3` требует reboot для полного runtime-отката |
| firewall (UFW) | typed `module_state.firewall`: pre-state и intent-флаги UFW/nftables | возвращает runtime/service active/enabled UFW и active/enabled nftables; ruleset/default policy не архивируются, поэтому для правил restore остаётся partial; legacy `apply_report` используется только для старых manifest |
| /tmp tmpfs | `/etc/fstab` | backup + перезагрузка |
| mount hardening | `/etc/fstab` | backup + перезагрузка; `/dev/shm` и `/var/tmp` монтируются как отдельные `tmpfs` |
| kernel module blacklist | `/etc/modprobe.d/60-securelinux-ng-blacklist.conf` | backup |
| fail2ban | `/etc/fail2ban/jail.local` | backup |
| AIDE | — | ручное удаление `/var/lib/aide/aide.db` |
| AppArmor | — | `aa-complain /etc/apparmor.d/*` вручную |
| 2.1.1 empty_passwords | typed `module_state.empty_passwords`: `users_file`, `shadow_path`, `restore_policy=security-preserving-nonrestore` | пустые поля пароля не восстанавливаются автоматически; список затронутых УЗ не смешивается с generic `backups` |
| 2.3.2 runtime_paths | файлы запущенных процессов | metadata snapshot |
| 2.3.3 cron_command_paths | файлы из cron | metadata snapshot |
| 2.3.4 sudo_command_paths | файлы из sudoers | metadata snapshot |
| 2.3.8 standard_system_paths | системные бинари/библиотеки | metadata snapshot |
| 2.3.9 suid_sgid | SUID/SGID файлы | metadata snapshot |
| 2.3.10/11 home_permissions | home dirs и sensitive files | metadata snapshot |
| 2.3.7 user_cron | user cron files | metadata snapshot |
| 2.4.3–2.4.7 GRUB | `/etc/default/grub` | backup + update-grub (reboot); generated `grub.cfg` может не совпасть побайтово |
| account audit | `/var/log/securelinux-ng/account_audit.txt` | backup и восстановление, если файл существовал; удаление, только если файл создан скриптом |
| auditd | `/etc/audit/rules.d/60-securelinux-ng.rules` | backup |
| auditd extended | `/etc/audit/rules.d/61-securelinux-ng-extended.rules` | backup |
| network sysctl | `/etc/sysctl.d/62-securelinux-ng-network.conf` | backup файла + runtime snapshot + адресный restore через `sysctl -w` |
| network sysctl unit | `/etc/systemd/system/securelinux-ng-sysctl.service` | backup содержимого и состояния enabled/disabled/masked; удаление только если unit создан скриптом |
| coredump | `/etc/security/limits.d/99-securelinux-ng-coredump.conf`, `/etc/systemd/coredump.conf.d/99-securelinux-ng.conf`, `/etc/sysctl.d/98-securelinux-ng-coredump.conf` | backup файлов + восстановление прежнего runtime `kernel.core_pattern` через `sysctl -w` |
| rkhunter | — | пакет не удаляется автоматически |
| 4.3 pam_pwhistory | `/etc/pam.d/common-password` | входит в backup Corporate password policy |
| п.15.1 kernel.modules_disabled | — | временно не применяется; dropin не создаётся |

## Защита каталога состояния

Перед чтением или записью manifest функция `secure_state_dir()` открывает `STATE_DIR` с `O_NOFOLLOW`, сверяет открытый inode с `lstat`, проверяет owner и устанавливает mode `0700` через `fchmod`. Для `apply` и `restore` ожидаемый owner — `root`; symlink, обычный файл либо каталог другого владельца приводят к ненулевому RC до системных мутаций. Режимы `check/report` и restore с явным `--manifest` могут перейти только на так же проверенный локальный fallback.

## Источник manifest

1. `--manifest FILE` — явный путь
2. иначе — последний обычный файл `manifest-*.json` в `STATE_DIR`
3. иначе — обычный файл `manifest.json` в `STATE_DIR`
4. иначе — последний обычный файл `*.json.bak-YYYYMMDD-HHMMSS` в `STATE_DIR`; это fallback после архивирования прежнего manifest перед повторным apply

Symlink-кандидаты при автоматическом выборе игнорируются. Если новый `manifest_init()` не состоялся после архивирования прежнего manifest, archive fallback сохраняет возможность restore.

## Что хранится в manifest

- `backups`: `[{original, backup}, ...]`
- `pending_created_files`: пути, зарегистрированные до первой мутации отсутствующего managed-файла; restore учитывает их после аварийного завершения apply
- `created_files`: файлы, успешно созданные и подтверждённые скриптом (удаляются при restore)
- `pending_created_groups`: intent создать группу, записанный до `groupadd`; restore учитывает его после аварийного завершения apply
- `created_groups`: группы, успешно созданные скриптом
- `pending_group_memberships`: intent добавить membership, записанный до `gpasswd -a`; restore учитывает его вместе с committed-записями
- `modified_files`: информационный best-effort список изменённых путей; restore его не читает, а отказ обновления фиксируется в runtime warnings и не отменяет уже завершённую файловую мутацию
- `warnings`, `irreversible_changes`
- `module_state`: типизированные restore-критические признаки; для `mount_hardening` и `tmp_tmpfs` хранится `restore_required=true`
- `apply_report`: только человекочитаемый журнал; его строки не используются как restore-база для `/etc/fstab`
- `additional_measures_enabled`: фактическое состояние дополнительного блока — `true` при `--enable-additional-measures` или config-значении `1`, `false` при обычном apply
- `pending_package_transactions`: `{module, snapshot}` до запуска `apt-get install`; pending-запись позволяет вычислить фактическую пакетную разницу после аварии между установкой и commit manifest
- `installed_packages`: committed-разница пакетов для каждого package-модуля
- `added_group_memberships`: успешно добавленные в wheel членства
- `password_aging_snapshots`: исходные значения aging
- пути к `sysctl-runtime-<module>-<timestamp>.json` для восстановления live sysctl-значений

## Metadata snapshot (для модулей прав доступа)

При apply сохраняется: `TARGET=`, `MODE=`, `UID=`, `GID=`.
При restore: `chown uid:gid` + `chmod mode`.
Fallback на старый текстовый формат `stat` сохранён для совместимости.

## Символьные ссылки в файловом restore

Если управляемый путь является символьной ссылкой, транзакция сохраняет именно объект ссылки:

1. `backup_file_checked()` выполняет `cp -a`, поэтому backup остаётся ссылкой с исходным link target.
2. `atomic_write_command_output()` не разыменовывает путь. Во время apply ссылка заменяется обычным managed-файлом, а файл-цель ссылки не изменяется.
3. `restore_file_from_manifest()` удаляет текущий объект и выполняет `cp -a` из backup, возвращая исходную относительную, абсолютную либо висячую ссылку.

Для любой рабочей или висячей ссылки новый managed-файл получает mode, заданный модулем по умолчанию, и текущие EUID/EGID. Mode, владелец и xattrs файла-цели ссылки намеренно не наследуются. Это предотвращает перенос `0666` от `/dev/null` или другого ослабленного target на конфигурацию в `/etc`. Ошибка генератора не заменяет путь и не оставляет временный файл.

Эта модель применяется также к `/etc/default/grub` и managed-файлам coredump.

## Ограничения

- **sysctl restore**: перед apply сохраняются live-значения каждого managed sysctl-модуля. После восстановления файла значения возвращаются адресно через `sysctl -w`; глобальный `sysctl --system` не используется.
- Подтверждённое по точной таблице невозможное понижение write-once sysctl к сохранённому значению классифицируется как штатный partial: managed-файл восстанавливается, добавляются warning и запись `irreversible_changes`, а `--restore` возвращает `RC=0`, если других ошибок нет.
- Обычная ошибка `sysctl -w`, неизвестный переход write-once-ключа, отсутствующий или read-only `/proc/sys` и смешанный случай write-once + обычная ошибка сохраняют `RC=1`.
- `kernel.kexec_load_disabled`, `kernel.unprivileged_bpf_disabled` и `kernel.yama.ptrace_scope` полностью возвращаются к сохранённому runtime-состоянию после reboot.
- GRUB: вступает в силу только после перезагрузки.
- auditd: правила перезагружаются через `augenrules --load` или `systemctl restart auditd`.
- 2.3.2/3/4/8/9: restore возвращает прежние права, но не гарантирует безопасность если файлы изменились.
- Пакеты дополнительных модулей автоматически не удаляются. Исключения — `password-policy`, `auditd` и `fail2ban`: для них restore выполняет purge committed-разницы и разницы незавершённого pending snapshot.
- Для AppArmor, AIDE, rkhunter, UFW, rsyslog, chrony и unattended-upgrades restore читает committed/pending package journal и перечисляет фактически оставшиеся пакеты для ручного удаления.
- rkhunter: пакет не удаляется при restore автоматически; при необходимости удалите вручную: `apt-get remove rkhunter`.
- `kernel.modules_disabled=1`: временно не применяется автоматически — dropin не создаётся.


## Typed restore UFW и nftables

До первой мутации firewall-модуль записывает `module_state.firewall`: был ли UFW активен, была ли включена его systemd-служба, были ли nftables active/enabled, а также intent-флаги stop/mask, изменения правил, runtime enable и service enable. Writer вызывается до соответствующей операции; при его отказе мутация не начинается.

Если `ufw --force enable` уже успешен, но `systemctl enable ufw` завершается ошибкой, apply выполняет локальный `ufw --force disable` и возвращает RC=1. Если локальный rollback также неуспешен, typed `ufw_enable_attempted=true` остаётся в manifest, и последующий restore отключает UFW. Состояния active/enabled nftables и enabled-службы UFW возвращаются к pre-state.

Полный ruleset и default policy UFW не архивируются и не сбрасываются через `ufw reset`. Поэтому правила заранее активного UFW и правила, подготовленные до сбоя initial enable, остаются документированным partial-ограничением.

## Атомарная запись /etc/shadow

Модуль `2.1.1 empty_passwords` записывает обычный `/etc/shadow` атомарно: через временный файл + `fsync` + `os.replace`. Если управляемый pathname является symlink, apply отклоняется до мутации; target ссылки не изменяется. Список затронутых УЗ хранится в typed `module_state.empty_passwords`, а не в generic `backups`.

## Restore парольной политики и wheel

- Перед изменением активной локальной учётной записи через `chage` исходные поля `last_change`, `min_days`, `max_days`, `warn_days`, `inactive_days` и `expire_date` сохраняются в `password_aging_snapshots` manifest. Restore восстанавливает их через `chage`.
- Manifest старых запусков без `password_aging_snapshots` не содержит данных для обратного восстановления aging; в этом случае модуль сообщает о пропуске.
- Явный `WHEEL_USERS` имеет приоритет. При пустом значении обычный запуск через `sudo` автоматически использует проверенного `SUDO_USER`; ошибка регистрируется только при невозможности безопасного определения администратора.
- Для `wheel` manifest хранит pending и committed состояния группы и membership. Restore сначала возвращает `/etc/pam.d/su`, затем удаляет membership из объединения `pending_group_memberships` и `added_group_memberships`, после чего удаляет `wheel` только если она отмечена в `pending_created_groups` или `created_groups` и осталась пустой.

## Уточнения restore v16.2.11

### Дополнительные меры

Обычный `--apply` выполняет основной набор hardening при
`ENABLE_ADDITIONAL_MEASURES=0`.

CLI-флаг `--enable-additional-measures` допустим только вместе с
`--apply`, имеет приоритет над config-файлом и включает 17 модулей:

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

Без CLI-флага дополнительный блок можно включить config-параметром
`ENABLE_ADDITIONAL_MEASURES=1`.

Manifest хранит фактическое состояние в поле
`additional_measures_enabled`: при включённом блоке — `true`, при
обычном apply — `false`.

Флаг не передаётся команде `--restore`. Restore определяет необходимый
объём отката только по manifest. Если поле равно `false`, дополнительные
модули, которые не применялись, пропускаются.

Для старых manifest без этого поля сохраняется совместимое прежнее
поведение полного restore дополнительных модулей.

### Пакетные транзакции

Для каждого package-модуля до `apt-get install` создаётся защищённый snapshot полного списка установленных пакетов. Путь snapshot атомарно записывается в `pending_package_transactions` **до первой пакетной мутации**.

После завершения `apt-get`, включая частично успешный запуск с ненулевым RC, повторно снимается список пакетов. Одним manifest commit выполняются две операции: фактическая разница добавляется в `installed_packages`, а соответствующий pending intent удаляется.

Если процесс завершился между установкой и commit, restore читает pending snapshot и вычисляет `current − before`. Для `password-policy`, `auditd` и `fail2ban` эта разница удаляется автоматически. Для модулей с ручной package-policy restore не удаляет пакеты, но выводит фактический список для безопасного ручного отката. Отсутствующий, symlink или находящийся вне каталога manifest snapshot считается повреждённым состоянием и даёт RC=1 без purge.

На Ubuntu Server для password policy ранее подтверждалось удаление шести новых пакетов, на Debian — пяти, поскольку `wamerican` уже присутствовал, а на Ubuntu Minimal — девяти, включая зависимости `file` и `libmagic`.

### pwquality.conf

Существование `/etc/security/pwquality.conf` определяется до запуска
`apt-get`. Если файл отсутствовал и был создан `libpwquality-common`,
он записывается как созданный и после purge остаётся отсутствующим.

Если файл существовал, сохраняется его исходная копия.

### Runtime sysctl

`kernel.kexec_load_disabled` и `kernel.yama.ptrace_scope` могут
не вернуться к исходному live-значению в текущей загрузке.
После удаления managed drop-in полный возврат завершается reboot.

### GRUB

Restore возвращает `/etc/default/grub` и запускает генератор
конфигурации. Параметры SecureLinux удаляются из `grub.cfg`
и из `/proc/cmdline` после reboot.

`/boot/grub/grub.cfg` не сохраняется как content-backup, поэтому
побайтовое совпадение с исходным generated-файлом не гарантируется.
Функциональный restore и идемпотентная повторная генерация подтверждены.


### Systemd service-state transactions

Перед управляемой операцией systemd manifest получает `pending_service_transactions`. Запись фиксирует исходные `systemctl is-enabled` и `systemctl is-active`, а также ожидаемую операцию `enable-now`, `enable-only` или `disable-now`. После попытки systemctl запись атомарно переносится в `service_transactions`.

Restore принимает как committed, так и pending запись. Pending до фактической мутации безопасен: повторное применение исходного состояния идемпотентно. Pending после мутации закрывает crash-window до commit. Для manifest старого формата network sysctl и apport сохраняют legacy fallback; новые managed-файлы без backup/created-file записи безопасно пропускаются. Пакеты модулей с manual package-policy автоматически не удаляются.

### Обычные файлы с несколькими hardlink-именами

Автоматический restore не пытается реконструировать hardlink topology, поскольку manifest не хранит inode-группы и полный набор связанных путей. Если backup либо существующая restore-цель является обычным файлом с `st_nlink > 1`, restore завершается с RC=1 до `rm` или `cp`. То же правило применяется при удалении файла из `created_files`/`pending_created_files`.

Администратор должен сначала вручную подтвердить назначение всех hardlink-имён и привести объект к однозначной topology. Символьные ссылки этим ограничением не затрагиваются.

### ACL, xattrs, capabilities и security labels

При apply существующего managed-файла атомарный helper переносит на временный inode все читаемые extended attributes и проверяет их до замены пути. POSIX ACL, file capabilities и Linux security labels входят в этот контракт как соответствующие `system.*`/`security.*` xattrs. Невозможность перенести хотя бы один существующий атрибут считается ошибкой: `os.replace` не выполняется, исходный объект остаётся неизменным.

При restore исходный объект возвращается из `cp -a` backup. Таким образом, расширенная metadata сохраняется как в активном hardened-состоянии, так и при откате. На файловой системе без поддержки xattrs дополнительных атрибутов нет; regression-тест фиксирует это как явный skip динамической xattr-проверки, сохраняя статическую проверку fail-before-replace контракта.

## Изменения dry-run/sudoers и restore

Исключение неподдерживаемой директивы sudoers не меняет объект
restore: `/etc/sudoers.d/60-securelinux-ng-policy` по-прежнему
восстанавливается из backup либо удаляется как созданный файл.

Перенос profile gate перед `DRY_RUN` меняет только планирование и
вывод dry-run. Формат manifest, порядок реального apply и контракт
restore этих модулей не изменяются.
