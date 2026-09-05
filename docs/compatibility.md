# Совместимость текущей product-line

Этот документ разделяет **SUPPORTED**, **TESTED** и **UNSUPPORTED**. Эти статусы
не являются синонимами.

## SUPPORTED

Текущая product-line использует **один** tracked `securelinux-policy.sh` для всей
поддерживаемой Linux-матрицы. Build-time target family:

```text
linux-x86_64-supported-v1
```

Основная machine-readable authority: `product/SUPPORTED-PLATFORMS.tsv`. В ней поддержаны ровно
семь проверенных environments:

| ОС | Профиль | Runtime platform | Статус |
|---|---|---|---|
| Ubuntu 22.04 | **FULL** | `ubuntu-22.04-x86_64` | `SUPPORTED` |
| Ubuntu 24.04 | **MINIMIZED** | `ubuntu-24.04-x86_64` | `SUPPORTED` |
| Ubuntu 24.04 | **FULL** | `ubuntu-24.04-x86_64` | `SUPPORTED` |
| Ubuntu 26.04 | **MINIMIZED** | `ubuntu-26.04-x86_64` | `SUPPORTED` |
| Ubuntu 26.04 | **FULL** | `ubuntu-26.04-x86_64` | `SUPPORTED` |
| Debian 12 | **SERVER** | `debian-12-x86_64` | `SUPPORTED` |
| Debian 13 | **SERVER** | `debian-13-x86_64` | `SUPPORTED` |

Дополнительная desktop authority — `product/SUPPORTED-DESKTOPS.tsv`:

| Система | Type | Platform | Статус |
|---|---|---|---|
| Ubuntu 24.04 | **DESKTOP** | `ubuntu-24.04-x86_64` | `SUPPORTED` |

`DESKTOP` не является значением `PROFILE`: основной 7/7 контур сохраняет `FULL | MINIMIZED | SERVER` без переименования. Конкретная графическая оболочка не входит в support identity и не влияет на routing CHECK/APPLY. Desktop-классификация Ubuntu 24.04 основана только на DE-независимом package-role fingerprint: `ubuntu-server-minimal` отсутствует, `ubuntu-minimal` и `ubuntu-standard` установлены.

Runtime preflight сам определяет `ID`, `VERSION_ID`, архитектуру и installation
profile. Для Ubuntu профиль определяется fail-closed по принятому package fingerprint:

- `FULL` основной 7/7 матрицы: установлены `ubuntu-server-minimal`, `ubuntu-minimal`, `ubuntu-standard`;
- `MINIMIZED`: установлен `ubuntu-server-minimal`, а `ubuntu-minimal` и
  `ubuntu-standard` отсутствуют;
- смешанная/неоднозначная комбинация => `UNSUPPORTED_PROFILE`;
- Debian 12/13 в принятой матрице классифицируются как `SERVER`.

Это project runtime classifier, выведенный из принятого VM evidence; он не выдаётся
за отдельный нормативный маркер Ubuntu. Его задача — не смешивать FULL и MINIMIZED
при CHECK и APPLY. MINIMIZED не должен неявно расширяться установкой пакетов только
ради hardening.

## TESTED

Принятая VM evidence matrix имеет статус `COMPLETE_7_OF_7`. Профили FULL и
MINIMIZED проверяются и учитываются раздельно; Debian 12/13 относятся к SERVER.
Эти VM runs подтверждают runtime/layout assumptions текущих CHECK mechanisms и
поддержанную platform/profile matrix, но не являются утверждением, что исходное
состояние каждой reference VM уже compliant по всем canonical controls.

Для exact generated CLI SHA-256
`98a4c67aeb392bff4e2b617f0f6593b8ff8fb149ce6bb156d9adbebd94e86928`
полный `SRC-0001` commit/noop run подтверждён на Ubuntu 22, Ubuntu 24,
Ubuntu 26, Debian 12 и Debian 13. Ubuntu 24 Desktop отдельно подтвердил
`TYPE=DESKTOP` routing и dry-run без изменения `/etc/shadow`. Это не означает,
что полный commit-path выполнен на каждом из восьми profile/type состояний.

Локальный CHECK может зависеть от прав чтения наблюдаемого объекта. По semantic
contract невозможность чтения — `ERROR`, а не `NOT_FOUND`; поэтому ограничение
прав не приводит к ложной оценке соответствия.

## UNSUPPORTED

Generated CHECK отклоняет с RC=3 до policy checks. Причина различается fail-closed:

- `UNSUPPORTED_PLATFORM`: ОС/версия/архитектура вне `product/SUPPORTED-PLATFORMS.tsv`;
- `UNSUPPORTED_PROFILE`: Ubuntu 22 `MINIMIZED` (для неё нет принятого VM environment);
- `UNSUPPORTED_PROFILE`: Ubuntu с неоднозначным/mixed package fingerprint FULL/MINIMIZED;
- `UNSUPPORTED_PLATFORM`: любая архитектура кроме `x86_64`;
- `UNSUPPORTED_PROFILE`: неизвестный или недоказуемый installation profile внутри основного профилируемого контура;
- `UNSUPPORTED_TYPE`: Ubuntu с non-server package-role, но без принятого Desktop support contract (например, Ubuntu 22/26 Desktop пока не добавлены как отдельные desktop targets).

Добавление новой platform/profile выполняется обновлением матрицы и новой версией
того же единого script artifact, а не созданием отдельного скрипта под систему.

## Правило evidence

Чтобы строка появилась здесь как `TESTED`, запись должна указывать минимум:

- OS и версию;
- архитектуру;
- тип среды;
- дату;
- exact identity продукта/control;
- ссылку на tracked evidence или его SHA-256.
## VM-наблюдения layout для SRC-0011

Это evidence поддерживаемой VM-матрицы, но не нормативный baseline полного product CHECK. Наблюдения используются только для проверки population/layout assumptions требования 2.3.7.

| ОС | Тип установки | cron | `/var/spool/cron` | `/var/spool/cron/crontabs` | Regular files | Traversal errors |
|---|---|---|---|---|---:|---:|
| Ubuntu 22.04.5 LTS | **FULL** | `3.0pl1-137ubuntu3` | `0755 root:root` | `1730 root:gid112` | 0 | 0 |
| Ubuntu 24.04.4 LTS | **MINIMIZED** | не установлен | отсутствует | отсутствует | 0 | 0 |
| Ubuntu 24.04.4 LTS | **FULL** | `3.0pl1-184ubuntu2` | `0755 root:root` | `1730 root:gid990` | 0 | 0 |
| Ubuntu 26.04 LTS | **MINIMIZED** | не установлен | отсутствует | отсутствует | 0 | 0 |
| Ubuntu 26.04 LTS | **FULL** | `3.0pl1-200ubuntu1` | `0755 root:root` | `1730 root:gid986` | 0 | 0 |
| Debian 12 (bookworm) | **SERVER** | `3.0pl1-162` | `0755 root:root` | `1730 root:gid101` | 0 | 0 |
| Debian 13.4 (trixie) | **SERVER** | `3.0pl1-197` | `0755 root:root` | `1730 root:gid997` | 0 | 0 |

Вывод для semantics: `/var/spool/cron/crontabs` является canonical user-crontab discovery root для current Ubuntu target; parent `/var/spool/cron` фиксируется как layout evidence, но не является population root. Штатное отсутствие canonical root и штатно пустая population дают compliant результат. Конкретный GID каталога `crontabs` различается между установками и поэтому не является policy condition SRC-0011.

## VM-наблюдения layout для SRC-0012

Это evidence поддерживаемой VM-матрицы, но не нормативный baseline полного product CHECK. Наблюдения подтверждают topology/population assumptions требования 2.3.8. Диагностический probe был read-only и выполнялся привилегированно только на отдельных ВМ; на основном ПК пользователя привилегированные проверки не выполняются.

Во всех семи ВМ наблюдался merged-`/usr`: `/bin → /usr/bin`, `/sbin → /usr/sbin`, `/lib → /usr/lib`, `/lib64 → /usr/lib64`. Current-kernel `/lib/modules/<uname-r>` присутствовал и разрешался в `/usr/lib/modules/<uname-r>`. Во всех просканированных standard roots `REGULAR_GO_W=0`, `SYMLINK_TARGET_REGULAR_GO_W=0`, dangling links и traversal/stat errors отсутствовали.

| ОС | Тип установки | Ядро | Privileged root PATH | Диагностические unique regular targets | Ошибки обхода |
|---|---|---|---|---:|---:|
| Ubuntu 22.04.5 LTS | **FULL** | `5.15.0-173-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 21515 | 0 |
| Ubuntu 24.04.4 LTS | **MINIMIZED** | `6.8.0-134-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 19082 | 0 |
| Ubuntu 24.04.4 LTS | **FULL** | `6.8.0-137-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 26394 | 0 |
| Ubuntu 26.04 LTS | **MINIMIZED** | `7.0.0-29-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 28293 | 0 |
| Ubuntu 26.04 LTS | **FULL** | `7.0.0-29-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 29116 | 0 |
| Debian 12 (bookworm) | **SERVER** | `6.1.0-44-amd64` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | 13613 | 0 |
| Debian 13 (trixie) | **SERVER** | `6.12.74+deb13+1-amd64` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | 13760 | 0 |

Вывод после retrospective correction: evidence показало, что fixed roots недостаточно для literal `$PATH root` anchor. Current v2 executable population включает canonical roots и каждый absolute entry фактического root-process `$PATH`, поэтому наблюдавшиеся `/usr/local/bin`, `/usr/local/sbin` и `/snap/bin` больше не отбрасываются только из-за прежнего fixed list. Library roots дополнены `/usr/local/lib` и `/usr/local/lib64`; current-kernel module root определяется через `uname -r`. VM numbers остаются diagnostic evidence, не нормативным baseline.


## VM-наблюдения для SRC-0013

Это evidence поддерживаемой VM-матрицы, но не нормативный baseline полного product CHECK. Evidence v2 снималось привилегированным read-only batch; основной ПК пользователя не использовался для privileged проверки.

Исторический evidence batch исключал `nosuid` mounts. Retrospective audit показал, что это сужало буквальную source population; current v2 исключает только pseudo/virtual filesystems и **не** исключает `nosuid`. Поэтому прежние численные VM counts ниже сохраняются только как historical layout evidence и не являются current v2 population counts. На Ubuntu 22 FULL в population также попали SUID/SGID-файлы read-only snap squashfs mounts, что подтвердило недостаточность сканирования только root filesystem.

| ОС | Тип установки | SUID/SGID regular | SUID | SGID | `GO_W` | Scan errors |
|---|---|---:|---:|---:|---:|---:|
| Ubuntu 22.04.5 LTS | **FULL** | 38 | 26 | 12 | 0 | 0 |
| Ubuntu 24.04.4 LTS | **MINIMIZED** | 18 | 13 | 5 | 0 | 0 |
| Ubuntu 24.04.4 LTS | **FULL** | 19 | 13 | 6 | 0 | 0 |
| Ubuntu 26.04 LTS | **MINIMIZED** | 18 | 13 | 5 | 0 | 0 |
| Ubuntu 26.04 LTS | **FULL** | 20 | 14 | 6 | 0 | 0 |
| Debian 12 (bookworm) | **SERVER** | 17 | 11 | 6 | 0 | 0 |
| Debian 13 (trixie) | **SERVER** | 18 | 11 | 7 | 0 | 0 |

Вывод для semantics: численный состав SUID/SGID population нельзя фиксировать как нормативный baseline — он зависит от пакетов и installation class. Универсальная часть 2.3.9 — отсутствие group/other write. Решение о том, какое найденное приложение является «лишним», требует отдельного локального authority и не выводится автоматически из package ownership или из этой VM-матрицы.

### SRC-0014 / 2.3.10 — чувствительные файлы в домашних каталогах локальных пользователей

Исторический VM batch использовал selector `root OR UID>=UID_MIN` + interactive shell; retrospective audit признал это source-unanchored сужением. **Current v2 не использует этот selector:** в population входят все syntactically valid local `/etc/passwd` accounts с absolute home, включая service/system accounts. Старые 7-run counts сохраняются только как historical evidence и не доказывают current v2 population.

Open-ended `и т. п.` больше не доверяется одному inventory: восемь source examples остаются mandatory authority entries, а read-only traversal дополнительно обнаруживает standard common-shell history/config artifacts для Bash/zsh/ksh/csh/tcsh/fish/Nushell/Xonsh/Elvish; custom/XDG override paths остаются через local inventory, ambiguity fail-closed. NSS/network-only accounts по-прежнему требуют отдельной authority model и не выводятся из локального `/etc/passwd`.

## SRC-0015 / 2.3.11 — режим доступа домашнего каталога

Current v2 использует все syntactically valid local `/etc/passwd` accounts с absolute home path, включая service/system accounts; прежние `UID_MIN`/interactive-shell exclusions удалены. Для каждого существующего real home требуется exact `0700`; absent path не создаётся, а symlink/non-directory/stat ambiguity => `ERROR`.

Семь ранее собранных VM runs остаются historical layout evidence: они проверяли более узкий selector и потому не используются как доказательство полноты current v2 population.

## SRC-0002 / SSH root login — матрица привилегированного evidence

Read-only evidence helper `slp-vm-batch-src0002-src0004-evidence-v1` выполнен на семи reference installations: Ubuntu 22 FULL, Ubuntu 24 MINIMIZED/FULL, Ubuntu 26 MINIMIZED/FULL, Debian 12 SERVER, Debian 13 SERVER. Во всех runs main `/etc/ssh/sshd_config` не содержал active global `PermitRootLogin`; syntax `sshd -t` был valid. Effective root-context был `without-password` на Ubuntu 22/24 и Debian 12/13, `prohibit-password` на Ubuntu 26. Поэтому все семь являются отрицательными current-state примерами относительно source-exact expected `no`. Эти наблюдения подтверждают необходимость effective-config semantics внутри принятой поддерживаемой матрицы.

## SRC-0003 / pam_wheel — матрица привилегированного evidence

Тот же read-only batch имеет integrity-verified evidence `7/7` для 2.2.1. На всех семи installations `/etc/pam.d/su` и `/etc/group` были regular root-owned files mode `0644`; active `pam_wheel` lines и exact required line count равнялись `0`, local `wheel` group count равнялся `0`, при этом `pam_wheel.so` module был обнаружен в standard security-module paths. Поэтому baseline однозначно `FAIL` ещё до необходимости локальной `<user list>` authority. Наличие module file само по себе compliance не доказывает. Evidence подтверждает assumptions CHECK внутри принятой поддерживаемой матрицы.

## SRC-0004 / sudoers reviewed policy — матрица привилегированного evidence

Read-only evidence `slp-vm-evidence-src0002-src0004-v1-*` integrity-verified `7/7`: Ubuntu 22 FULL, Ubuntu 24 MINIMIZED/FULL, Ubuntu 26 MINIMIZED/FULL, Debian 12 SERVER, Debian 13 SERVER. Во всех семи `/etc/sudoers` существовал как regular `0440 root:root`, присутствовал active `@includedir /etc/sudoers.d`, полный `visudo` check завершался `RC=0`. На Ubuntu 26 `sudo`/`visudo` предоставлялись через alternatives symlinks. Эти host facts подтверждают способ discovery/validation; они не задают универсальный approved user/command set.

## Процедурный authority SRC-0034

`SRC-0034 / 2.5.11` не получает OS-specific default: source qualifier `после тестирования` представлен explicit local authority `/etc/securelinux-policy/tested-setting-attestations-v1`. Это не VM observation и не предположение о distro defaults. CHECK не запускает тестирование и не изменяет `kernel.randomize_va_space`; отсутствие доверяемой target attestation даёт `ERROR`.
