# Совместимость текущей product-line

Этот документ разделяет **SUPPORTED**, **TESTED** и **UNSUPPORTED**. Эти статусы
не являются синонимами.

## SUPPORTED

Текущий target contract product CHECK:

```text
ubuntu-24.04-x86_64
```

Target задаётся current `product/generate-product-check-v2.py` и binding/semantic
contracts adapters. Tracked `securelinux-policy.sh` является byte-exact output этого
generator и выполняет target preflight до проверки controls. Historical v1
generator остаётся предыдущей product identity.

`SUPPORTED` означает: текущий product contract разрешает этот target. Это не
утверждение, что все возможные варианты Ubuntu 24.04 уже прошли VM acceptance.

## TESTED

Для статуса `TESTED` требуется конкретное evidence, связанное с точными bytes
проверяемой product population и средой выполнения.

На Documentation Baseline **нет tracked VM evidence для полного текущего
product CHECK по всем current controls**, поэтому общий target не повышается до
универсального `TESTED` только на основании одного локального запуска.

В проекте существует historical/reference VM evidence для более раннего
пяти-sysctl pilot. Оно остаётся полезным инженерным evidence, но не подменяет
тестирование текущей product population.

Локальный CHECK может зависеть от прав чтения наблюдаемого объекта. По semantic
contract невозможность чтения — `ERROR`, а не `NOT_FOUND`; поэтому ограничение
прав не приводит к ложной оценке соответствия.

## UNSUPPORTED

Любой target, не равный current target contract, должен быть отклонён generated
CHECK с RC=3 до выполнения policy checks.

Добавление новой ОС/архитектуры требует отдельного target contract и
соответствующих tests/evidence. Категории `server`, `desktop`, `container`,
`Docker` или `Kubernetes` заранее не объявляются поддержанными только по названию
окружения.

## Evidence rule

Чтобы строка появилась здесь как `TESTED`, запись должна указывать минимум:

- OS и версию;
- архитектуру;
- тип среды;
- дату;
- exact product/control identity;
- ссылку на tracked evidence или его SHA-256.
## VM-наблюдения layout для SRC-0011

Это **не** расширение `SUPPORTED` target и не acceptance полного product CHECK. Наблюдения используются только для проверки population/layout assumptions требования 2.3.7.

| ОС | Тип установки | cron | `/var/spool/cron` | `/var/spool/cron/crontabs` | Regular files | Traversal errors |
|---|---|---|---|---|---:|---:|
| Ubuntu 22.04.5 LTS | **FULL** | `3.0pl1-137ubuntu3` | `0755 root:root` | `1730 root:gid112` | 0 | 0 |
| Ubuntu 24.04.4 LTS | **MINIMIZED** | не установлен | отсутствует | отсутствует | 0 | 0 |
| Ubuntu 24.04.4 LTS | **FULL** | `3.0pl1-184ubuntu2` | `0755 root:root` | `1730 root:gid990` | 0 | 0 |
| Ubuntu 26.04 LTS | **MINIMIZED** | не установлен | отсутствует | отсутствует | 0 | 0 |
| Ubuntu 26.04 LTS | **FULL** | `3.0pl1-200ubuntu1` | `0755 root:root` | `1730 root:gid986` | 0 | 0 |
| Debian 12 (bookworm) | **SERVER** | `3.0pl1-162` | `0755 root:root` | `1730 root:gid101` | 0 | 0 |
| Debian 13.4 (trixie) | **GNOME** | `3.0pl1-197` | `0755 root:root` | `1730 root:gid997` | 0 | 0 |

Вывод для semantics: оба roots являются optional discovery roots; штатное отсутствие обоих roots и штатно пустая population должны давать compliant результат. Конкретный GID каталога `crontabs` различается между установками и поэтому не является policy condition SRC-0011.

## VM-наблюдения layout для SRC-0012

Это **не** расширение `SUPPORTED` target и не acceptance полного product CHECK. Наблюдения подтверждают topology/population assumptions требования 2.3.8. Диагностический probe был read-only и выполнялся привилегированно только на отдельных ВМ; на основном ПК пользователя привилегированные проверки не выполняются.

Во всех семи ВМ наблюдался merged-`/usr`: `/bin → /usr/bin`, `/sbin → /usr/sbin`, `/lib → /usr/lib`, `/lib64 → /usr/lib64`. Current-kernel `/lib/modules/<uname-r>` присутствовал и разрешался в `/usr/lib/modules/<uname-r>`. Во всех просканированных standard roots `REGULAR_GO_W=0`, `SYMLINK_TARGET_REGULAR_GO_W=0`, dangling links и traversal/stat errors отсутствовали.

| ОС | Тип установки | Ядро | Privileged root PATH | Диагностические unique regular targets | Ошибки обхода |
|---|---|---|---|---:|---:|
| Ubuntu 22.04.5 LTS | **FULL** | `5.15.0-173-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 21515 | 0 |
| Ubuntu 24.04.4 LTS | **MINIMIZED** | `6.8.0-134-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 19082 | 0 |
| Ubuntu 24.04.4 LTS | **FULL** | `6.8.0-137-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 26394 | 0 |
| Ubuntu 26.04 LTS | **MINIMIZED** | `7.0.0-29-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 28293 | 0 |
| Ubuntu 26.04 LTS | **FULL** | `7.0.0-29-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 29116 | 0 |
| Debian 12 (bookworm) | **SERVER** | `6.1.0-44-amd64` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | 13613 | 0 |
| Debian 13 (trixie) | **GNOME** | `6.12.74+deb13+1-amd64` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | 13760 | 0 |

Вывод для semantics: canonical OS executable roots текущего control — `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`. Они входят и в fixed donor defaults, и во все наблюдавшиеся privileged root PATH. `/usr/local/*` и `/snap/bin` не включаются в current OS-owned population: это local/admin и application paths, а не фиксированные пути файлов ОС текущего target contract. Library roots — `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`; current-kernel module root определяется через `uname -r`.


## VM-наблюдения для SRC-0013

Это **не** расширение `SUPPORTED` target и не acceptance полного product CHECK. Evidence v2 снималось привилегированным read-only batch; основной ПК пользователя не использовался для privileged проверки.

Population определялась по mounted filesystems, на которых SUID/SGID semantics не отключена `nosuid`; pseudo/virtual filesystems исключались. На Ubuntu 22 FULL в population также попали SUID/SGID-файлы read-only snap squashfs mounts, что подтвердило недостаточность сканирования только root filesystem.

| ОС | Тип установки | SUID/SGID regular | SUID | SGID | `GO_W` | Scan errors |
|---|---|---:|---:|---:|---:|---:|
| Ubuntu 22.04.5 LTS | **FULL** | 38 | 26 | 12 | 0 | 0 |
| Ubuntu 24.04.4 LTS | **MINIMIZED** | 18 | 13 | 5 | 0 | 0 |
| Ubuntu 24.04.4 LTS | **FULL** | 19 | 13 | 6 | 0 | 0 |
| Ubuntu 26.04 LTS | **MINIMIZED** | 18 | 13 | 5 | 0 | 0 |
| Ubuntu 26.04 LTS | **FULL** | 20 | 14 | 6 | 0 | 0 |
| Debian 12 (bookworm) | **SERVER** | 17 | 11 | 6 | 0 | 0 |
| Debian 13 (trixie) | **GNOME** | 18 | 11 | 7 | 0 | 0 |

Вывод для semantics: численный состав SUID/SGID population нельзя фиксировать как нормативный baseline — он зависит от пакетов и installation class. Универсальная часть 2.3.9 — отсутствие group/other write. Решение о том, какое найденное приложение является «лишним», требует отдельного локального authority и не выводится автоматически из package ownership или из этой VM-матрицы.

### SRC-0014 / 2.3.10 — sensitive files in selected user homes

Перед closure выполнен privileged read-only evidence batch на 7 installation classes. Во всех runs selector `root OR UID>=UID_MIN`, interactive shell и absolute home дал 2 candidate accounts; `HOME_SCAN_ERRORS=0`, host mutation отсутствовала. Source-exact present entries / `go-rwx` violations: Ubuntu 22.04.5 FULL `6/5`; Ubuntu 24.04.4 MINIMIZED `7/5`, FULL `7/5`; Ubuntu 26.04 MINIMIZED `5/5`, FULL `6/5`; Debian 12 SERVER `7/5`; Debian 13 GNOME `6/5`. Эти observed modes не являются normative baseline: нормативное отношение берётся только из source (`bits-clear 0077`).

Открытые `и т. п.` выражены обязательным локальным inventory `/etc/securelinux-policy/home-sensitive-files-v1`; без него CHECK даёт `ERROR`, а не делает ложный вывод о полноте восьми примеров. NSS/network-only accounts v1 не включены в current local-account population и требуют отдельной authority model до расширения product scope.

## SRC-0015 / 2.3.11 — mode home directory

Current CHECK использует тот же локальный account selector, что и SRC-0014: `root` плюс normal interactive local accounts по `UID_MIN` из `/etc/login.defs`. Это инженерная operationalization source-термина «пользователей», а не расширение target support.

Для каждого существующего selected home требуется exact `0700`, потому что source приводит именно `chmod 700`. Отсутствие home path не объявляется нарушением существования; symlink/non-directory/stat ambiguity даёт `ERROR`. Ownership не добавляется.

Семь privileged read-only VM runs подтвердили layout assumptions: Debian 12 `SERVER` и Debian 13 `GNOME` имели `/root` и `/home/user` mode `0700`; Ubuntu 22 `FULL`, Ubuntu 24 `MINIMIZED/FULL` и Ubuntu 26 `MINIMIZED/FULL` имели `/root=0700`, `/home/user=0750`. Эти наблюдения не расширяют current product target и не заменяют source-exact expected `0700`.

## SRC-0002 / SSH root login — privileged evidence matrix

Read-only evidence helper `slp-vm-batch-src0002-src0004-evidence-v1` выполнен на семи reference installations: Ubuntu 22 FULL, Ubuntu 24 MINIMIZED/FULL, Ubuntu 26 MINIMIZED/FULL, Debian 12 SERVER, Debian 13 GNOME. Во всех runs main `/etc/ssh/sshd_config` не содержал active global `PermitRootLogin`; syntax `sshd -t` был valid. Effective root-context был `without-password` на Ubuntu 22/24 и Debian 12/13, `prohibit-password` на Ubuntu 26. Поэтому все семь являются отрицательными current-state примерами относительно source-exact expected `no`. Эти наблюдения подтверждают необходимость effective-config semantics, но не расширяют current product target `ubuntu-24.04-x86_64`.
