# Покрытие FSTEC core

> **СГЕНЕРИРОВАННЫЙ ФАЙЛ.** Формируется `tools/render-current-docs.py` из `SOURCE-INDEX.tsv`, `CLOSURE-CONTRACT.tsv`, `CONTROL-MANIFEST.tsv` и `ADAPTER-REGISTRY.tsv`. Ручное редактирование запрещено.

## Сводка

```text
TOTAL_INDEX_ROWS=349
CONTROLLED_CLOSED_WITH_CONTRACT=54
DISPOSED_CLOSED_ROWS=295
OPEN_INDEX_ROWS=0
CANONICAL_CONTROLS=86
```

Число canonical controls и число закрытых source rows — разные величины: одна строка источника может требовать `exact-control-set` из нескольких controls, а строка `covered-by-controls` своих controls не имеет — её требование выполняют controls других строк.

## Controlled CLOSED строки

| Строка source | Locator | Режим coverage | Canonical controls | Parameter kind | Адаптер CHECK |
|---|---|---|---|---|---|
| SRC-0001 | 2.1.1 | atomic-single | `FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE` | `local-account-password-state` | `product-local-account-password-state-check-v2` |
| SRC-0002 | 2.1.2 | atomic-single | `FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN` | `sshd-root-login` | `product-sshd-root-login-check-v1` |
| SRC-0003 | 2.2.1 | atomic-single | `FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS` | `pam-wheel-access` | `product-pam-wheel-access-check-v2` |
| SRC-0004 | 2.2.2 | atomic-single | `FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY` | `sudoers-reviewed-policy` | `product-sudoers-reviewed-policy-check-v1` |
| SRC-0005 | 2.3.1 | exact-control-set | `FSTEC-LINUX-2022-2.3.1-GROUP-MODE`<br>`FSTEC-LINUX-2022-2.3.1-PASSWD-MODE`<br>`FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX` | `file-mode-owner` | `product-file-mode-owner-check-v2` |
| SRC-0006 | 2.3.2 | atomic-single | `FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION` | `running-process-paths-write-protection` | `product-running-process-paths-write-protection-check-v1` |
| SRC-0007 | 2.3.3 | atomic-single | `FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION` | `cron-command-paths-write-protection` | `product-cron-command-paths-write-protection-check-v1` |
| SRC-0008 | 2.3.4 | atomic-single | `FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION` | `sudo-root-command-files-protection` | `product-sudo-root-command-files-protection-check-v2` |
| SRC-0009 | 2.3.5 | atomic-single | `FSTEC-LINUX-2022-2.3.5-STARTUP-FILES-WRITE-PROTECTION` | `startup-files-write-protection` | `product-startup-files-write-protection-check-v1` |
| SRC-0010 | 2.3.6 | exact-control-set | `FSTEC-LINUX-2022-2.3.6-CRONTAB`<br>`FSTEC-LINUX-2022-2.3.6-CRON-D`<br>`FSTEC-LINUX-2022-2.3.6-CRON-HOURLY`<br>`FSTEC-LINUX-2022-2.3.6-CRON-DAILY`<br>`FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY`<br>`FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY` | `optional-file-root-files-mode` | `product-optional-file-root-files-mode-check-v1` |
| SRC-0011 | 2.3.7 | atomic-single | `FSTEC-LINUX-2022-2.3.7-USER-CRON-FILES-MODE` | `user-cron-files-mode` | `product-user-cron-files-mode-check-v2` |
| SRC-0012 | 2.3.8 | atomic-single | `FSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE` | `standard-system-paths-mode` | `product-standard-system-paths-mode-check-v2` |
| SRC-0013 | 2.3.9 | atomic-single | `FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE` | `suid-sgid-applications` | `product-suid-sgid-applications-check-v2` |
| SRC-0014 | 2.3.10 | atomic-single | `FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE` | `home-sensitive-files-mode` | `product-home-sensitive-files-mode-check-v2` |
| SRC-0015 | 2.3.11 | exact-control-set | `FSTEC-LINUX-2022-2.3.11-DIR-MODE`<br>`FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE`<br>`FSTEC-LINUX-2022-2.3.11-HOME-MODE` | `adduser-conf-option`<br>`home-directories-mode`<br>`login-defs-option` | `product-adduser-conf-option-check-v1`<br>`product-home-directories-mode-check-v2`<br>`product-login-defs-option-check-v1` |
| SRC-0016 | 2.4.1 | atomic-single | `FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0017 | 2.4.2 | atomic-single | `FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0018 | 2.4.3 | atomic-single | `FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC` | `kernel-cmdline` | `product-kernel-cmdline-check-v2` |
| SRC-0019 | 2.4.4 | atomic-single | `FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE` | `kernel-cmdline` | `product-kernel-cmdline-check-v2` |
| SRC-0020 | 2.4.5 | exact-control-set | `FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE`<br>`FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT`<br>`FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH` | `kernel-cmdline` | `product-kernel-cmdline-check-v2` |
| SRC-0021 | 2.4.6 | atomic-single | `FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET` | `kernel-cmdline` | `product-kernel-cmdline-check-v2` |
| SRC-0022 | 2.4.7 | atomic-single | `FSTEC-LINUX-2022-2.4.7-MITIGATIONS` | `kernel-cmdline` | `product-kernel-cmdline-check-v2` |
| SRC-0023 | 2.4.8 | atomic-single | `FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0024 | 2.5.1 | atomic-single | `FSTEC-LINUX-2022-2.5.1-VSYSCALL` | `kernel-cmdline` | `product-kernel-cmdline-check-v2` |
| SRC-0025 | 2.5.2 | atomic-single | `FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0026 | 2.5.3 | atomic-single | `FSTEC-LINUX-2022-2.5.3-DEBUGFS` | `kernel-cmdline` | `product-kernel-cmdline-check-v2` |
| SRC-0027 | 2.5.4 | atomic-single | `FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0028 | 2.5.5 | atomic-single | `FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0029 | 2.5.6 | atomic-single | `FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0030 | 2.5.7 | atomic-single | `FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0031 | 2.5.8 | atomic-single | `FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0032 | 2.5.9 | atomic-single | `FSTEC-LINUX-2022-2.5.9-TSX` | `kernel-cmdline` | `product-kernel-cmdline-check-v2` |
| SRC-0033 | 2.5.10 | atomic-single | `FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0034 | 2.5.11 | atomic-single | `FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0035 | 2.6.1 | atomic-single | `FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0036 | 2.6.2 | atomic-single | `FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0037 | 2.6.3 | atomic-single | `FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0038 | 2.6.4 | atomic-single | `FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0039 | 2.6.5 | atomic-single | `FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0040 | 2.6.6 | atomic-single | `FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0041 | main:1 | covered-by-controls | `FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES` | `auditd-package-service`<br>`auditd-rules` | `product-auditd-package-service-check-v1`<br>`product-auditd-rules-check-v1` |
| SRC-0043 | main:3 | covered-by-controls | `FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT` | `auditd-conf-option`<br>`auditd-package-service` | `product-auditd-conf-option-check-v1`<br>`product-auditd-package-service-check-v1` |
| SRC-0044 | main:4 | covered-by-controls | `FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION` | `auditd-conf-option` | `product-auditd-conf-option-check-v1` |
| SRC-0045 | main:5 | atomic-single | `FSTEC-LOGGING-2025-MAIN-5-AUDIT-LOG-FREE-SPACE` | `auditd-log-free-space` | `product-auditd-log-free-space-check-v1` |
| SRC-0047 | main:7 | covered-by-controls | `FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES` | `auditd-conf-option`<br>`auditd-package-service`<br>`auditd-rules` | `product-auditd-conf-option-check-v1`<br>`product-auditd-package-service-check-v1`<br>`product-auditd-rules-check-v1` |
| SRC-0050 | appendix2-linux:1 | atomic-single | `FSTEC-LOGGING-2025-APPENDIX2-LINUX-1-AUDITD-PACKAGE` | `auditd-package-service` | `product-auditd-package-service-check-v1` |
| SRC-0051 | appendix2-linux:2 | atomic-single | `FSTEC-LOGGING-2025-APPENDIX2-LINUX-2-AUDITD-SERVICE` | `auditd-package-service` | `product-auditd-package-service-check-v1` |
| SRC-0052 | appendix2-linux:3 | exact-control-set | `FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-ADMIN-SPACE-LEFT-ACTION`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-DISK-FULL-ACTION`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FILE`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-FORMAT`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-LOG-GROUP`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-MAX-LOG-FILE-ACTION`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-NUM-LOGS`<br>`FSTEC-LOGGING-2025-APPENDIX2-LINUX-3-SPACE-LEFT-ACTION` | `auditd-conf-option` | `product-auditd-conf-option-check-v1` |
| SRC-0053 | appendix2-linux:4 | atomic-single | `FSTEC-LOGGING-2025-APPENDIX2-LINUX-4-AUDIT-RULES` | `auditd-rules` | `product-auditd-rules-check-v1` |
| SRC-0055 | 1.1 | exact-control-set | `FSTEC-CONFIGURATION-2026-1.1-ENCRYPT-METHOD`<br>`FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGE`<br>`FSTEC-CONFIGURATION-2026-1.1-EXISTING-PASSWORD-AGING`<br>`FSTEC-CONFIGURATION-2026-1.1-PASS-MAX-DAYS`<br>`FSTEC-CONFIGURATION-2026-1.1-PASS-MIN-DAYS`<br>`FSTEC-CONFIGURATION-2026-1.1-PASS-WARN-AGE`<br>`FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-DCREDIT`<br>`FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-ENFORCE-FOR-ROOT`<br>`FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-LCREDIT`<br>`FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-MINLEN`<br>`FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-OCREDIT`<br>`FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-RETRY`<br>`FSTEC-CONFIGURATION-2026-1.1-PWQUALITY-UCREDIT` | `local-account-password-age`<br>`local-account-password-aging`<br>`login-defs-option`<br>`pam-pwquality-option` | `product-local-account-password-age-check-v1`<br>`product-local-account-password-aging-check-v1`<br>`product-login-defs-option-check-v1`<br>`product-pam-pwquality-option-check-v1` |
| SRC-0056 | 1.2 | exact-control-set | `FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-ENFORCE-FOR-ROOT`<br>`FSTEC-CONFIGURATION-2026-1.2-PWHISTORY-REMEMBER` | `pam-pwhistory-remember` | `product-pam-pwhistory-remember-check-v1` |
| SRC-0088 | 9.1 | exact-control-set | `FSTEC-CONFIGURATION-2026-9.1-SSH-PASSWORD-AUTHENTICATION`<br>`FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-EMPTY-PASSWORDS`<br>`FSTEC-CONFIGURATION-2026-9.1-SSH-PERMIT-ROOT-LOGIN` | `sshd-config-option` | `product-sshd-config-option-check-v2` |
| SRC-0091 | 8.4 | atomic-single | `FSTEC-CONFIGURATION-2026-8.4-SSH-LOG-LEVEL` | `sshd-config-option` | `product-sshd-config-option-check-v2` |
| SRC-0098 | 11.2 | exact-control-set | `FSTEC-CONFIGURATION-2026-11.2-TELNET`<br>`FSTEC-CONFIGURATION-2026-11.2-FTP`<br>`FSTEC-CONFIGURATION-2026-11.2-SNMP` | `network-service-disabled` | `product-network-service-disabled-check-v1` |

## Canonical controls, которые ещё не закрывают строку source

Сейчас таких controls нет.

## Готовность адаптеров CHECK

| Parameter kind | Adapter | Только чтение | Canonical controls сейчас |
|---|---|---:|---:|
| `adduser-conf-option` | `product-adduser-conf-option-check-v1` | да | 1 |
| `auditd-conf-option` | `product-auditd-conf-option-check-v1` | да | 9 |
| `auditd-log-free-space` | `product-auditd-log-free-space-check-v1` | да | 1 |
| `auditd-package-service` | `product-auditd-package-service-check-v1` | да | 2 |
| `auditd-rules` | `product-auditd-rules-check-v1` | да | 1 |
| `cron-command-paths-write-protection` | `product-cron-command-paths-write-protection-check-v1` | да | 1 |
| `file-mode-owner` | `product-file-mode-owner-check-v2` | да | 3 |
| `home-directories-mode` | `product-home-directories-mode-check-v2` | да | 1 |
| `home-sensitive-files-mode` | `product-home-sensitive-files-mode-check-v2` | да | 1 |
| `kernel-cmdline` | `product-kernel-cmdline-check-v2` | да | 10 |
| `local-account-password-age` | `product-local-account-password-age-check-v1` | да | 1 |
| `local-account-password-aging` | `product-local-account-password-aging-check-v1` | да | 1 |
| `local-account-password-state` | `product-local-account-password-state-check-v2` | да | 1 |
| `login-defs-option` | `product-login-defs-option-check-v1` | да | 5 |
| `network-service-disabled` | `product-network-service-disabled-check-v1` | да | 3 |
| `optional-file-root-files-mode` | `product-optional-file-root-files-mode-check-v1` | да | 6 |
| `pam-pwhistory-remember` | `product-pam-pwhistory-remember-check-v1` | да | 2 |
| `pam-pwquality-option` | `product-pam-pwquality-option-check-v1` | да | 7 |
| `pam-wheel-access` | `product-pam-wheel-access-check-v2` | да | 1 |
| `running-process-paths-write-protection` | `product-running-process-paths-write-protection-check-v1` | да | 1 |
| `sshd-config-option` | `product-sshd-config-option-check-v2` | да | 4 |
| `sshd-root-login` | `product-sshd-root-login-check-v1` | да | 1 |
| `standard-system-paths-mode` | `product-standard-system-paths-mode-check-v2` | да | 1 |
| `startup-files-write-protection` | `product-startup-files-write-protection-check-v1` | да | 1 |
| `sudo-root-command-files-protection` | `product-sudo-root-command-files-protection-check-v2` | да | 1 |
| `sudoers-reviewed-policy` | `product-sudoers-reviewed-policy-check-v1` | да | 1 |
| `suid-sgid-applications` | `product-suid-sgid-applications-check-v2` | да | 1 |
| `sysctl` | `product-sysctl-check-v2` | да | 17 |
| `user-cron-files-mode` | `product-user-cron-files-mode-check-v2` | да | 1 |

## Покрытие по исходным документам

| Документ source | Всего строк | Controlled CLOSED | Disposed CLOSED | OPEN | Canonical controls |
|---|---:|---:|---:|---:|---:|
| fstec-configuration-2026 | 49 | 5 | 44 | 0 | 22 |
| fstec-linux-2022 | 40 | 40 | 0 | 0 | 51 |
| fstec-logging-2025 | 14 | 9 | 5 | 0 | 13 |
| fstec-perimeter-2026 | 35 | 0 | 35 | 0 | 0 |
| fstec-security-update-testing-2022 | 70 | 0 | 70 | 0 | 0 |
| fstec-vulnerability-analysis-2025 | 61 | 0 | 61 | 0 | 0 |
| fstec-vulnerability-criticality-2025 | 28 | 0 | 28 | 0 | 0 |
| fstec-vulnerability-management-2023 | 52 | 0 | 52 | 0 | 0 |

Эта таблица описывает фактическую структуру корпуса, а не обещание превратить каждую `OPEN` строку в host CHECK. По контракту source index строка закрывается canonical control-set либо explicit disposition; выбор зависит от source semantics.

## Раскрытие отклонений и границ

- Минимальная длина пароля: продукт проверяет `minlen` не менее 12 символов (контроль `PWQUALITY-MINLEN` и связанные контроли пункта 1.1). Пункт 1.1 `fstec-configuration-2026` (SRC-0055) рекомендует 15 символов. Значение 12 принято по требованию компании для пользователей и совпадает с методикой ФСТЭК 2026 года (`fstec-methodology-2026-04-12`: длина пароля не менее 12 символов для доступа в информационную систему). Отклонение от пункта 1.1 сознательное.
- Межсетевой экран (SRC-0083, пункт 7.3 `fstec-configuration-2026`): класс `out-of-scope`. Продукт не настраивает и не проверяет фильтрацию портов (firewalld, iptables, nftables); настраивает администратор принимающей стороны.
- Пункт 10.5 `fstec-configuration-2026` (объекты, доступные всем на запись; правило auditd `-w / -p w`): правило не включено. По замеру 30.09.2026 на шести средах ВМ журнал auditd за три месяца с правилом занимает 25,7–48,5 GiB, без правила — 2,4–6,6 GiB (скорость записи в фазах замера при пробной нагрузке скрипта — 200 временных файлов, apt-get update, запись в журнал logger; около 190 секунд на среду, экстраполирована на 92 дня). Порог свободного места журнала — 7 GiB. Такой объём журнала на все серверы по умолчанию не закладывается: его выделяет и настраивает администратор по внутреннему регламенту организации. Регулярное сканирование доступных всем на запись каталогов и файлов выполняет администратор принимающей стороны; продукт этого не делает и не обязан.
- Пункт 2.3.9 (SUID/SGID): снятие лишних программ с правом SUID и ведение списка разрешённых программ выполняет администратор принимающей стороны по внутреннему регламенту организации. Продукт список не читает и этого не делает; APPLY снимает только биты `0022` (права записи группы и прочих).

## Открытая часть корпуса

`0` source rows остаются `OPEN`. Полный перечень и их source metadata находятся в `index/source-v4/SOURCE-INDEX.tsv`; этот документ не дублирует 349 строк вручную.

Наличие adapter или canonical control само по себе не закрывает source row: закрытие определяется source status и `CLOSURE-CONTRACT.tsv` либо explicit disposition.
