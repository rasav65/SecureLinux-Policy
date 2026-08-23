# Product CHECK line

Постоянная read-only product-line SecureLinux-Policy v3.

Она отделена от historical `step7b0/`: admitted bytes и historical adapter id
`sysctl-check-v1` не являются current product authority и здесь не изменяются.

## Текущий состав

- `contracts/file-mode-owner-check-semantic-v1.json` — read-only semantic
  contract для `file-mode-owner`;
- `contracts/sysctl-check-semantic-v2.json` — current read-only semantic contract для
  `sysctl`; `eq` сохраняет exact semantics, `ge` разрешён только для integer lower bounds;
- `contracts/kernel-cmdline-check-semantic-v2.json` — current read-only exact-token contract
  для фактической загрузочной строки `/proc/cmdline`; `one-of` кодирует ordered alternatives через `|`, где первое значение preferred, но все перечисленные значения compliant; v1 сохранён как предыдущая product identity;
- `contracts/optional-file-root-files-mode-check-semantic-v1.json` — read-only contract для optional system-cron root + direct regular files; missing root = `VALUE/PASS`, неоднозначный nested/symlink/special population = `ERROR`;
- `contracts/local-account-password-state-check-semantic-v1.json` — read-only aggregate contract для локальных `/etc/passwd` accounts + source-anchored `/etc/shadow`; empty password field = `FAIL`, неполная/неоднозначная mapping = `ERROR`;
- `contracts/sshd-root-login-check-semantic-v1.json` — read-only source-faithful contract SRC-0002: main `/etc/ssh/sshd_config` обязан содержать global `PermitRootLogin no`, а `sshd -t/-T` подтверждают синтаксис и effective `no`; Include/Match ambiguity fail-closed;
- `contracts/pam-wheel-access-check-semantic-v1.json` — read-only aggregate contract SRC-0003: source-exact PAM rule + local `wheel` membership against explicit local authority;
- `contracts/standard-system-paths-mode-check-semantic-v1.json` — read-only aggregate contract SRC-0012 для standard executable/library/current-kernel-module population с merged-`/usr` aliases, target deduplication и fail-closed observation errors;
- `contracts/suid-sgid-applications-check-semantic-v1.json` — read-only contract SRC-0013: effective SUID/SGID population, `go-w` mode check и отдельная allowlist-authority проверка отсутствия лишних приложений;
- `adapters/product-file-mode-owner-check-v1.py` + JSON binding;
- `adapters/product-sysctl-check-v2.py` + JSON binding (v1 сохранён как предыдущая product identity);
- `adapters/product-kernel-cmdline-check-v2.py` + JSON binding; только чтение
  `/proc/cmdline`, без GRUB/APPLY/RESTORE; v1 сохранён как предыдущая product identity;
- `adapters/product-optional-file-root-files-mode-check-v1.py` + JSON binding; только `stat/find/sort`, без chmod/chown/APPLY;
- `adapters/product-local-account-password-state-check-v1.py` + JSON binding; только чтение `/etc/passwd` и `/etc/shadow`, без passwd/usermod/APPLY;
- `adapters/product-sshd-root-login-check-v1.py` + JSON binding; только чтение SSH config tree и `sshd -t/-T`, без записи/reload/restart/APPLY;
- `adapters/product-pam-wheel-access-check-v1.py` + JSON binding; только чтение `/etc/pam.d/su`, `/etc/group` и local authority, без group/PAM mutation/APPLY;
- `adapters/product-standard-system-paths-mode-check-v1.py` + JSON binding; только `uname/readlink/find/sort/stat`, без chmod/chown/APPLY;
- `adapters/product-suid-sgid-applications-check-v1.py` + JSON binding; только чтение mountinfo/allowlist и `find/sort/stat`, без chmod/chown/remount/APPLY;
- `ADAPTER-REGISTRY.tsv` — единственный tracked mapping parameter kind →
  semantic contract / binding / implementation с SHA-256;
- `generate-product-check-v2.py` — current tracked deterministic generator единого read-only CLI;
- `generate-product-check-v1.py` — сохранённая предыдущая generator identity;
- `/securelinux-policy.sh` + `/securelinux-policy.sh.sha256` — tracked byte-exact user entrypoint current product population;
- `dist/` — optional derived gitignored rebuild output, не источник истины.

Generator читает текущий `CONTROL-MANIFEST.tsv`, проверяет canonical YAML и
registry SHA bindings и fail-closed выбирает adapter по `parameter.kind`.


## Unified CLI / Quick Start v1

Текущая пользовательская точка входа — один tracked executable
`securelinux-policy.sh`. Для обычного CHECK пользователь не запускает Python
generator. Compliance execution выполняется как executable (`./securelinux-policy.sh`)
или явно `/bin/bash -p ./securelinux-policy.sh`: shebang `#!/bin/bash -p` запрещает
импорт environment shell functions до выполнения generated checks. Plain `bash script`
и `source script` не являются поддерживаемым compliance execution path.

- `--check` — pretty table с фиксированными колонками `RESULT`, `CONTROL`, `VALUE / DETAILS`;
- `--check --failed` — только `FAIL` и `ERROR`;
- `--check --format raw` — прежний стабильный `SLP-CHECK-V1` TSV;
- `--check --format json` — `SLP-REPORT-V1`;
- `--report` — compact human report с `FAIL`/`ERROR`;
- `--build-info`, `--provenance`, `--version`, `--help` — metadata/UI;
- `--apply`, `--restore` — fail-closed `NOT_IMPLEMENTED`, RC=2, mutation implementation отсутствует.

`tests/product-v1/test_product_generator.py` содержит `UnifiedCliArtifact`, который
детерминированно пересобирает artifact в temp и требует byte-exact equality с tracked root script и sidecar.

## Текущий статус

CHECK по current manifest population реализован и regression-tested. Generated
artifact имеет статус `NON_RELEASE_PRODUCT_CANDIDATE` и target
`ubuntu-24.04-x86_64`.

CHECK не содержит APPLY/RESTORE. Policy noncompliance не равен execution
failure; `NOT_FOUND`/`ERROR` делают итог `UNEVALUATED`.

Принцип отсутствия — `proven-absence-only`: `NOT_FOUND` допустим только при
доказанном отсутствии имени. Нечитаемый объект, dangling symlink, symlink loop
или отсутствие обязательного observation tool классифицируются как `ERROR`.

## Текущее расширение FSTEC core

`SRC-0005 / 2.3.1` закрыт через `exact-control-set` из трёх canonical controls:

- `/etc/passwd` → `mode eq 0644`;
- `/etc/group` → `mode eq 0644`;
- `/etc/shadow` → `mode bits-clear 0077`.

`/etc/shadow = 0600` из source anchor не выводится. Все три controls используют
существующий read-only `product-file-mode-owner-check-v1`; APPLY/RESTORE по-прежнему
не реализованы.

После CHECK-11 product track перешёл к систематическому представлению
оставшихся `OPEN` source rows. Exact-eq batch закрыл `SRC-0030`, `SRC-0031`,
`SRC-0036`–`SRC-0039`; затем `SRC-0040 / 2.6.6` закрыт через
`fs.suid_dumpable eq 0` после точечного удаления terminal page furniture.

Текущий sysctl adapter v2 добавляет только source-faithful integer lower-bound
оператор `ge`. Он нужен для `SRC-0033 / 2.5.10`: источник требует
`vm.mmap_min_addr = 4096 или больше`, поэтому подмена на `eq 4096` запрещена.
`eq`-controls не меняют своей semantics. Exact current population всегда
берётся из `CONTROL-MANIFEST.tsv`.

Текущий read-only kind `kernel-cmdline` принят после сверки с pinned
engineering donor: donor уже читал `/proc/cmdline`, делил его на whitespace
tokens и проверял exact boot tokens. В v3 этот механизм ужесточён fail-closed:
для `eq` конфликтующие дубли одного key дают `ERROR`, отсутствие требуемого
key — наблюдаемое `VALUE/FAIL`; для bare flag `present` отсутствие также
`VALUE/FAIL`. v2 добавляет `one-of`: expected list кодируется как `|`-separated
exact token values; первое значение является preferred, но preference не меняет
compliance остальных перечисленных значений. Сам donor остаётся только
implementation precedent.

Через этот kind source-faithful закрываются `SRC-0018`, `SRC-0019`,
`SRC-0020`, `SRC-0021`, `SRC-0022`, `SRC-0024`, `SRC-0026`, `SRC-0032`. Для
`SRC-0026 / 2.5.3` exact policy — `off|no-mount`: `off` preferred, оба значения
PASS; adapter не пытается определить, возможно ли `off` для конкретного ядра.

Formal `Gate 5 --probe-results` остаётся отдельным контрактным артефактом и не
подменяется выводом generated CHECK. APPLY/RESTORE не реализованы.

Тесты: `tests/product-v1/`.

## SRC-0010 / 2.3.6

Шесть перечисленных source roots представлены exact-control-set. Проверка использует только source-exact `go-wx` → `bits-clear 0033`; donor `600/700 root:root` не переносится. Для directory root проверяются root + direct regular files. Nested directory, symlink, special entry или incomplete traversal дают `ERROR`; отсутствие перечисленного root разрешено источником и даёт `VALUE/PASS`.

## SRC-0001 / 2.1.1

Один aggregate control проверяет локальную account population из `/etc/passwd` против source-anchored `/etc/shadow`. Для каждого локального пользователя требуется определимая shadow-запись с непустым password field. Empty field → `VALUE/FAIL`; missing/unreadable/symlink/malformed/duplicate mapping → fail-closed `ERROR`. APPLY/RESTORE не реализованы.
## SRC-0011 / 2.3.7

Один aggregate control `user-cron-files-mode` проверяет только пользовательские cron-файлы под двумя donor-подтверждёнными optional discovery roots: `/var/spool/cron` и `/var/spool/cron/crontabs`. Обычные файлы обнаруживаются рекурсивно, пересечение roots дедуплицируется по абсолютному пути, а вложенные каталоги служат только контейнерами population. Точное source-отношение `chmod go-w` представлено как `mode bits-clear 0022`; требования к owner/group или к режиму root-каталогов не добавляются.

Пустая population compliant: на Ubuntu 24/26 `MINIMIZED` пакет `cron` отсутствовал вместе с обоими roots; на Ubuntu 22 `FULL`, Ubuntu 24 `FULL`, Ubuntu 26 `FULL`, Debian 12 `SERVER` и Debian 13 `GNOME` roots присутствовали, но regular cron-файлов на момент диагностики не было. Эти VM-факты подтверждают layout assumptions, но не расширяют current product target. Symlink/special object, traversal/stat error или неоднозначность population дают `ERROR`; молчаливые donor-skips не переносятся.
## SRC-0012 / 2.3.8

Один aggregate control `standard-system-paths-mode` проверяет системные executable roots `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, library roots `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64` и current-kernel root `/lib/modules/<uname-r>`. merged-`/usr` root aliases разрешаются и дедуплицируются по `dev:inode`; regular symlink targets также дедуплицируются.

Для executable roots любой non-directory entry является candidate и должен разрешаться в regular target. Для library roots candidate-name ограничен `*.so`, `*.so.*`, `*.a`; для kernel modules — `*.ko`, `*.ko.*`. Это не превращает package metadata под `/usr/lib` или `/lib/modules` в дополнительные policy requirements. Candidate dangling/special target, incomplete traversal или stat/readlink ambiguity дают `ERROR`.

2.3.8 требует «анализа корректности прав», но не задаёт точный mode. Current operational criterion — `bits-clear 0022`: системный executable/library/module target не должен быть writable для group/other. Это минимальная инженерная интерпретация, согласованная с pinned donor и соседними 2.3.2/2.3.9; owner/group и более строгие mode значения не добавляются. Проверка parent directories из donor намеренно не переносится, потому что источник явно требует её в 2.3.2, но не в 2.3.8.

`$PATH` непривилегированного процесса generated CHECK не используется как authority для root PATH. Семь VM-наблюдений подтвердили, что fixed canonical executable roots входят в privileged root PATH на Ubuntu 22/24/26 и Debian 12/13; `/usr/local/*` и `/snap/bin` остаются вне current OS-owned population.


## SRC-0013 / 2.3.9

Два controls одного kind `suid-sgid-applications` представляют обе части исходной рекомендации отдельно.

`SUID-SGID-MODE` читает `/proc/self/mountinfo`, исключает pseudo/virtual filesystems и mounts с `nosuid`, затем выполняет xdev-поиск regular files с SUID/SGID bits на каждом оставшемся mount root. Один underlying file дедуплицируется по `dev:inode`. Для каждого найденного приложения требуется `bits-clear 0022`; нулевая полностью определённая population допустима, а неполный обход/stat/mountinfo ambiguity даёт `ERROR`.

`SUID-SGID-ALLOWLIST` использует ту же population, но проверяет только `population ⊆ approved set`. Источник требует убедиться, что нет «лишних» SUID/SGID-приложений, но не задаёт универсальный машинный критерий необходимости. Поэтому generated CHECK не угадывает его: authority — явный локальный read-only список `/etc/securelinux-policy/suid-sgid.allowlist-v1`, по одному exact absolute path на строку; comments `#` и пустые строки разрешены. Отсутствующий, symlink, нечитаемый или malformed список означает `ERROR`, а unlisted detected application — `VALUE/FAIL`. Сам путь allowlist является механизмом current product, а не дополнительным требованием ФСТЭК.

Pinned donor использован только как precedent для `mode & 0022`. Его автоматическая трактовка SUID non-root owner как нарушения отклонена: 2.3.9 такого универсального owner rule не устанавливает. Семь privileged VM runs подтвердили, что mode condition штатно имеет `GO_W=0`, а population зависит от состава ОС и установленных пакетов.

## SRC-0014 / 2.3.10 — sensitive user-home files

- `home-sensitive-files-mode` — read-only aggregate CHECK для source-отношения `chmod go-rwx`, то есть `mode & 0077 == 0`.
- Population пользователей: локальный `/etc/passwd`, `root` плюс обычные interactive accounts по `UID_MIN` из `/etc/login.defs`; service accounts с `nologin`/`false` не считаются human-user homes.
- Source `и т. п.` не урезается до восьми примеров: `/etc/securelinux-policy/home-sensitive-files-v1` — обязательный локальный inventory относительных sensitive paths; он обязан содержать восемь явно названных source entries и может/должен расширяться локально.
- Отсутствующий/malformed inventory, symlink/ambiguous path или неполный доступ дают `ERROR`; present regular members с group/other rwx дают `VALUE/FAIL`.
- Owner/group не проверяются: это не требование 2.3.10. Режим самой home directory `0700` относится к `SRC-0015`. APPLY/RESTORE не создаются.

## SRC-0015 / 2.3.11 — режим домашних директорий пользователей

- `home-directories-mode` — read-only aggregate CHECK exact source-команды `chmod 700 домашняя_директория`, то есть строгого `mode == 0700`.
- Population пользователей совпадает с уже принятой для SRC-0014: локальный `/etc/passwd`, `root` плюс normal interactive accounts по `UID_MIN` из `/etc/login.defs`; это избегает donor `/home`-only restriction и не превращает service-account state directories в human homes.
- Отсутствующий home path пропускается: 2.3.11 регулирует права существующей home directory, а не её обязательное наличие. Existing symlink/non-directory/stat ambiguity даёт `ERROR`.
- Owner/group не проверяются. Sensitive-file modes не дублируются: они принадлежат SRC-0014. APPLY/RESTORE не создаются.

## SRC-0002 / 2.1.2

Один aggregate control `sshd-root-login` представляет source-exact требование `PermitRootLogin no` именно в основном `/etc/ssh/sshd_config`. Простого grep и наличия managed drop-in недостаточно: CHECK рекурсивно учитывает активные `Include` в явном лексикографическом порядке путей, восстанавливает `Match`-scope содержащего файла после каждого Include, проверяет `sshd -t` и effective root-context через `sshd -T -C`. Main-файл должен содержать активную global директиву с семантическим значением `no`; effective value также должен быть `no`.

Global duplicates не объявляются ошибкой сами по себе: first-obtained-value semantics проверяется effective выводом OpenSSH. Parser проверяемых SSH-директив поддерживает whitespace/один `=` как separator, quoted/escaped arguments, CRLF и token-boundary comment semantics (`#` внутри token не обрезается). Glob population получает явную сортировку; function-shadowing `compgen`, ошибка sort/find/compgen и pathname с переводом строки не могут тихо скрыть Include — это fail-closed `ERROR`. `Match`-scope `PermitRootLogin no` безопасен; non-`no` conditional value, include-cycle, symlink/unreadable/malformed config или иная parser ambiguity дают `ERROR`, а не ложный PASS. APPLY/RESTORE, reload/restart SSH отсутствуют.

## SRC-0003 / 2.2.1

Один aggregate control `pam-wheel-access` представляет обе source-explicit части: активную rule `auth required pam_wheel.so use_uid` непосредственно в `/etc/pam.d/su` и local запись `wheel` в `/etc/group`.

`root` обязателен непосредственно в fourth field wheel record. Placeholder `<user list>` не угадывается из текущих sudo/admin accounts: current product authority — `/etc/securelinux-policy/wheel-users.allowlist-v1`, по одному дополнительному разрешённому имени на строку. После обязательного `root` фактический supplementary-members set должен точно совпасть с authority; missing/extra member даёт `VALUE/FAIL`. Если PAM/wheel/root уже явно отсутствуют, это definitive `FAIL` без authority; когда structural conditions выполнены, missing/malformed authority даёт `ERROR`.

GID `10` из source-record не фиксируется как portable compliance condition: adapter требует числовой GID, но `pam_wheel` выбирает группу по имени `wheel`, а системные GID allocations различаются. Иной active `pam_wheel.so` rule (`deny`, `trust`, `group=...`, absolute module path, иной control) не заменяет source-exact rule и даёт fail-closed `ERROR`. Donor auto-create/group membership mutation, `WHEEL_USERS` и `SUDO_USER` discovery не переносятся. APPLY/RESTORE отсутствуют.
