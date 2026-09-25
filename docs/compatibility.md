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

Дополнительная desktop authority — `product/FIELD-COMPATIBILITY-DESKTOPS.tsv`:

| Система | Type | Platform | Статус |
|---|---|---|---|
| Ubuntu 24.04 | **DESKTOP** | `ubuntu-24.04-x86_64` | `FIELD_COMPATIBILITY` |

`DESKTOP` не является значением `PROFILE`: основной 7/7 контур сохраняет `FULL | MINIMIZED | SERVER` без переименования. Конкретная графическая оболочка не входит в support identity и не влияет на routing CHECK/APPLY. Desktop-классификация Ubuntu 24.04 основана только на DE-независимом package-role fingerprint: `ubuntu-server-minimal` отсутствует, `ubuntu-minimal` и `ubuntu-standard` установлены.

`FIELD_COMPATIBILITY` не входит в clean-reference acceptance и не является гарантией корректной работы на любой Desktop-системе. Пользовательские пакеты, службы и локальные изменения конфигурации могут менять наблюдаемое состояние и поведение CHECK/APPLY. `--check`, `--apply --dry-run` и реальный `--apply` разрешены; перед реальным Desktop APPLY CLI обязан крупно предупредить, что корректность APPLY в таком состоянии не гарантируется. Для фактического APPLY рекомендуется внешний snapshot/backup.

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

Историческое evidence: для exact generated CLI SHA-256
`98a4c67aeb392bff4e2b617f0f6593b8ff8fb149ce6bb156d9adbebd94e86928`
полный `SRC-0001` commit/noop run подтверждён на Ubuntu 22, Ubuntu 24,
Ubuntu 26, Debian 12 и Debian 13. Ubuntu 24 Desktop отдельно подтвердил
`TYPE=DESKTOP` routing и dry-run без изменения `/etc/shadow`. Решением DP-3
APPLY для `SRC-0001` выведен из продукта; этот результат сохраняется как история и
не относится к текущим механизмам.

Механизм `file-mode-owner-v1` принят на одной среде: `ubuntu-24.04-x86_64-minimized`,
`x86_64`, clean-reference VM, 19.09.2026, кандидат SHA-256
`0095dae6b618fa5aa0319beaa8b83378b889caba79e3aad929ce92065ec1612e`, evidence
`slp-vm-mech2-u2404min-v1-20260919-123103.tar.gz` с SHA-256
`79f636ca4ddc8b643728b2e47cfaa76b1a2756796616cb5ecde721f8a4003405`.
Текущий CLI отличается от этого кандидата отображением и составом механизмов.
Механизмы `optional-file-root-files-mode-v1`, `suid-sgid-applications-mode-v1` и
`standard-system-paths-mode-v1` приняты на той же среде 20.09.2026; у
`startup-files-write-protection-v1` и `kernel-cmdline-grub-v1` 24.09.2026, у `pam-wheel-su-v1` 25.09.2026 выполнен прогон на семи средах. Приёмка
механизмов APPLY на остальных средах матрицы впереди.

Первое принятие `standard-system-paths-mode-v1` относится к кандидату
`e170aae19cf261f37c1ca0a2f10c72b1dc373bef4eae263c6653bd690e35dd38`. Затем перечислитель
механизма исправлен (ошибка чтения подкаталога — отказ `scan:find-failed`). Повторный
прогон на той же среде принят на кандидате
`ba96131bcf5b3a6d9906052a5163e2a5dca784ae3f16982a7a12df6dfb03a55b` (runner SHA-256
`e6abdf226461353d313eb5fabcb0bd8285bf2881d611924538c11bbbaeaa4a3d`, evidence
`slp-vm-mech5-u2404min-v1-20260920-175045.tar.gz` SHA-256
`eddd6bd11da96bf024193db7d005a6cab4932e33621befef94b36d1ab1c231d4`).
Кандидат `be828daef92615bfce44ac3a5ccdc894f9cfa0f276fcb656add1abc6eeb05128`
отличался от обоих: CHECK-адаптеры `sysctl`, `kernel-cmdline`, `home-directories-mode`,
`home-sensitive-files-mode`, `pam-wheel-access` и `sshd-root-login` больше не принимают
недоступность за отсутствие; `pam-wheel-access` разбирает те же байты, что проверил, без
повторного открытия файла; APPLY-dispatcher проверяет каталог состояния и берёт блокировку.
Адаптеры APPLY не менялись. ВМ-прогон на нём не выполнен.
Кандидат `a64e662a5cea05e53f6e158182188fcfac76f3dbc29b0ffd27af4f30f887c4b9`
устранял то же повторное открытие файла после проверки через `od` ещё в семи
CHECK-адаптерах (`home-directories-mode`, `home-sensitive-files-mode`,
`local-account-password-state`, `sshd-root-login`, `sudoers-reviewed-policy`,
`suid-sgid-applications`, `tested-setting-attestation`) и переводил записи
APPLY-dispatcher (отчёт, журналы) на дескриптор проверенного каталога состояния
вместо строки пути. Адаптеры APPLY не менялись. ВМ-прогон на нём не выполнен.
Кандидат `5e0dacf6…85a` переводил популяцию `home-directories-mode` (2.3.11) с
обхода `/etc/passwd` на прямые элементы `/home` (решение 22.09.2026). ВМ-прогон
на нём тоже не выполнен.
Кандидат `e683fe2bc0823eb795a8436b86c16621f46277a2dbc8bd2f73105add5b872cfc`
(репарация по аудиту Codex диапазона `6780086..3215d1c`) устраняет то же
повторное открытие файла после проверки через `od` ещё в двух CHECK-адаптерах
(`kernel-cmdline`, `sysctl` — decode-once по образцу остальных); корень `/home`
и каждый прямой элемент в `home-directories-mode` определяют отсутствие/тип
только по доказанному ENOENT (разбор текста ошибки `stat -c %F`), а не по
`[[ ! -e ]]`/`[[ -L ]]`, которые не отличают доказанное отсутствие от прочих
ошибок stat; захват цели `readlink` для 2.3.11 больше не теряет её собственный
завершающий перевод строки; `slp_collect_policy` принимает у `reason`
необязательный третий сегмент полезной нагрузки (`domain:reason:payload`) без
управляющих байтов. Адаптеры APPLY не менялись. ВМ-прогон на нём не выполнен.
Последующие кандидаты меняли только CHECK: 2.3.11 и 2.3.10 — популяция из прямых
элементов `/home`; 2.2.1 — разобранный стек без `pam_wheel.so` даёт `FAIL`, затем
`pam_rootok` перед `pam_wheel` допустим; 2.3.10, 2.3.4, 2.2.2 и 2.2.1 не читают
authority-файлы; контроли 2.5.11 TESTED-BEFORE-USE и 2.3.9 SUID-SGID-ALLOWLIST
выведены. Текущий кандидат — трекнутый `securelinux-policy.sh`, его SHA-256 — в
`securelinux-policy.sh.sha256`. Адаптеры APPLY не менялись; ВМ-прогон на этих
кандидатах не выполнен.

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
- `UNSUPPORTED_TYPE`: Ubuntu с non-server package-role, но без принятого Desktop FIELD_COMPATIBILITY contract (например, Ubuntu 22/26 Desktop пока не добавлены как отдельные desktop targets).

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

Вывод для semantics: численный состав SUID/SGID population нельзя фиксировать как нормативный baseline — он зависит от пакетов и installation class. Универсальная часть 2.3.9 — отсутствие group/other write; только она и проверяется. Решение о том, какое найденное приложение является «лишним», остаётся за администратором: источник приводит «белый» список как пример, CHECK не читает для 2.3.9 никаких файлов администратора.

### SRC-0014 / 2.3.10 — чувствительные файлы в домашних каталогах локальных пользователей

Исторический VM batch использовал selector `root OR UID>=UID_MIN` + interactive shell; retrospective audit признал это source-unanchored сужением. Решением человека 23.09.2026 (по прецеденту 2.3.11) популяция переведена с обхода `/etc/passwd` на непосредственные (mindepth=1,maxdepth=1) элементы `/home`, включая service/system home-директории; `/etc/passwd` не читается. Старые 7-run counts сохраняются только как historical evidence и не доказывают current v2 population.

Проверяемые имена — замкнутый встроенный список (решение человека 23.09.2026, шаг (б)); authority-файл `/etc/securelinux-policy/home-sensitive-files-v1` не читается, его отсутствие на результат не влияет. Список:

- восемь обязательных имён источника: `.bash_history`, `.history`, `.sh_history`, `.bash_profile`, `.bashrc`, `.profile`, `.bash_logout`, `.rhosts`;
- распространённые имена оболочек (`COMMON_SHELL_BASENAMES`): `.bash_login`, `.xonshrc`, `.zsh_history`, `.zshrc`, `.zprofile`, `.zlogin`, `.zlogout`, `.zshenv`, `.ksh_history`, `.kshrc`, `.mkshrc`, `.cshrc`, `.tcshrc`, `.login`, `.logout`.

Проверяются только непосредственные элементы каждого домашнего каталога с одним из этих имён; файлы глубже первого уровня (например, `.config/fish/*.fish`, история Nushell/Xonsh/Elvish в XDG-каталогах) вне охвата. Выбранный объект-симлинк или не обычный файл — `ERROR`. Поле VALUE: `homes=N;discovered=N;checked=N;violations=N`.

## SRC-0015 / 2.3.11 — режим доступа домашнего каталога

Решением от 22.09.2026 популяция переведена с обхода `/etc/passwd` на прямые
элементы `/home` (по прецеденту `archive/securelinux-ng.sh`,
`home_targets_scan`): `/etc/passwd` больше не читается, `home=` учётной записи
на результат не влияет. Непосредственный элемент `/home`, который является
симлинком или не каталогом, — `ERROR` (`home:symlink:<путь>-><цель readlink>`
/ `home:not-directory:<путь>`), симлинк не разрешается для классификации типа.
Для каждого каталога-элемента требуется exact `0700`. Отсутствующий или
пустой `/home` — вне популяции, `VALUE/PASS` с `checked=0;violations=0`.

Репарация 22.09.2026 (аудит Codex, диапазон `6780086..3215d1c`, B-02/B-03):
отсутствие `/home` и тип каждого элемента определяются только доказанным
`ENOENT` — `stat -c %F` без `-L` (семантика `lstat`, символическая ссылка не
разрешается) и буквальный разбор текста ошибки (`: No such file or directory`
как единственное доказательство отсутствия), а не `[[ ! -e ]]`/`[[ -L ]]`,
которые не отличают доказанное отсутствие от прочих ошибок `stat` (например
`EIO`) и трактовали любую такую ошибку как «объекта нет», уходя в `PASS` по
недоказанной популяции. Любая иная ошибка `stat` — `ERROR`, а не `PASS` и не
прежняя классификация по типу: для корня `home-base:stat-failed:<path>` (сам
`/home`) или `home-base:ancestor-stat-failed:<path>` (ближайший предок при
доказанном отсутствии `/home`); для элемента — `home:stat-failed:<path>`, в
том числе если элемент исчез между тем, как его нашёл `find`, и классификацией
(TOCTOU). Символическая ссылка/не-каталог на месте самого `/home` (а не
элемента) — `home-base:symlink` / `home-base:invalid-type`, для ближайшего
доступного предка — `home-base:ancestor-symlink` /
`home-base:ancestor-invalid-type` / `home-base:ancestor-unsearchable`. Имя
элемента или цель `readlink` с байтами табуляции/CR/LF — `home:invalid-name`
(сырые байты не попадают в поле `reason`). Тем же решением захват цели
`readlink` через sentinel-символ перестал терять её собственный завершающий
перевод строки (раньше `$(readlink …)` срезал все завершающие LF, включая
значащий).

Раздела блоков APPLY («block — не применено автоматически …», таблица
control | type | message) у CHECK нет — он существует только
у встроенного APPLY-dispatcher и только для исходов `ABORTED_PRECONDITION_*`;
для ERROR по 2.3.11 путь и цель readlink передаются прямо в поле `reason`.
Такое состояние (симлинк/не каталог на месте домашнего каталога) — вне модели
продукта: 2.3.11 не выполняется, решение остаётся за администратором.

Семь ранее собранных VM runs остаются historical evidence прежнего,
passwd-based selector (см. `product/contracts/home-directories-mode-check-semantic-v2.json`,
`vm_evidence`) и не используются как доказательство полноты текущей,
/home-based популяции.

## SRC-0002 / SSH root login — матрица привилегированного evidence

Read-only evidence helper `slp-vm-batch-src0002-src0004-evidence-v1` выполнен на семи reference installations: Ubuntu 22 FULL, Ubuntu 24 MINIMIZED/FULL, Ubuntu 26 MINIMIZED/FULL, Debian 12 SERVER, Debian 13 SERVER. Во всех runs main `/etc/ssh/sshd_config` не содержал active global `PermitRootLogin`; syntax `sshd -t` был valid. Effective root-context был `without-password` на Ubuntu 22/24 и Debian 12/13, `prohibit-password` на Ubuntu 26. Поэтому все семь являются отрицательными current-state примерами относительно source-exact expected `no`. Эти наблюдения подтверждают необходимость effective-config semantics внутри принятой поддерживаемой матрицы.

## SRC-0003 / pam_wheel — матрица привилегированного evidence

Тот же read-only batch имеет integrity-verified evidence `7/7` для 2.2.1. На всех семи installations `/etc/pam.d/su` и `/etc/group` были regular root-owned files mode `0644`; active `pam_wheel` lines и exact required line count равнялись `0`, local `wheel` group count равнялся `0`, при этом `pam_wheel.so` module был обнаружен в standard security-module paths. Поэтому baseline однозначно `FAIL`; `<user list>` продукт не оценивает, authority-файл не читается. Наличие module file само по себе compliance не доказывает. Evidence подтверждает assumptions CHECK внутри принятой поддерживаемой матрицы.

Штатный `/etc/pam.d/su` Ubuntu 24.04 (`auth sufficient pam_rootok.so` первой
auth-строкой, `@include common-auth`/`common-account`/`common-session`, без
`pam_wheel.so`) до исправления Н-3 давал `ERROR pam:ambiguous-stack`: гейт
«sufficient/include/substack/`[...]` как первая auth-строка» и отдельно
`@include` при ещё не найденном exact-правиле обрывали разбор `break`'ом
раньше, чем адаптер успевал убедиться, что `pam_wheel.so` в файле попросту
нет. Правка заменила `break` на пометку `_slp_hazard`: разбор доходит до
конца файла, и если `pam_wheel.so` ни в какой форме не встретилась —
вердикт `VALUE/FAIL`. С 23.09.2026 payload —
`pam_wheel=<present|absent|no-use_uid>;wheel=<absent|gid N>;root=<member|missing>`
(на этой конфигурации — `pam_wheel=absent;wheel=absent;root=missing`; номер
gid 10 больше не требуется и не выводится: на всех семи средах он занят
`uucp`), а строка `auth sufficient pam_rootok.so` перед
`auth required pam_wheel.so use_uid` больше не считается hazard — такой стек
с `root` в `wheel` даёт `PASS`. `ERROR
pam:ambiguous-stack` остаётся при любом реальном парсинг-сбое, а также если
`pam_wheel.so` найдена в неэталонной форме (независимо от порядка
относительно hazard-строки) или найдена в эталонной форме именно после
hazard-строки: в обоих случаях реальная достижимость PAM-движком не
доказана. Исключение — `auth required pam_wheel.so` без аргумента `use_uid`
при отсутствии эталонной строки: это `FAIL` `pam_wheel=no-use_uid`.

## SRC-0004 / sudoers — матрица привилегированного evidence

Read-only evidence `slp-vm-evidence-src0002-src0004-v1-*` integrity-verified `7/7`: Ubuntu 22 FULL, Ubuntu 24 MINIMIZED/FULL, Ubuntu 26 MINIMIZED/FULL, Debian 12 SERVER, Debian 13 SERVER. Во всех семи `/etc/sudoers` существовал как regular `0440 root:root`, присутствовал active `@includedir /etc/sudoers.d`, полный `visudo` check завершался `RC=0`. На Ubuntu 26 `sudo`/`visudo` предоставлялись через alternatives symlinks. Эти host facts подтверждают способ discovery/validation.

С 23.09.2026 контроль допускает только штатные правила `root ALL=(ALL:ALL) ALL`, `%sudo ALL=(ALL:ALL) ALL` и `%admin ALL=(ALL) ALL`; authority-файл не читается. Штатные `/etc/sudoers` Ubuntu 24.04 и Debian 12 дают `PASS`. Представление правил `cvtsudoers` проверено на sudo 1.9.15p5 этого ПК; на ВМ с другими версиями sudo (Ubuntu 22/26, Debian 13) не прогонялось.

## SRC-0034 / 2.5.11

`SRC-0034 / 2.5.11` проверяется одним контролем `sysctl eq 2`: результат зависит только от текущего значения `kernel.randomize_va_space`. Слова источника «после тестирования» — порядок действий администратора; файлы в `/etc/securelinux-policy/` для 2.5.11 не читаются, OS-specific default не вводится.
