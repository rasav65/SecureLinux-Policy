# Продуктовая линия CHECK

Постоянная read-only product-line SecureLinux-Policy v3.

Она отделена от historical `step7b0/`: admitted bytes и historical adapter id
`sysctl-check-v1` не являются current product authority и здесь не изменяются.
Сохранённые `sysctl-check-semantic-v1`, `kernel-cmdline-check-semantic-v1` и
`local-account-password-state-check-semantic-v1` имеют lifecycle
`HISTORICAL_UNREGISTERED`: они не зарегистрированы в `ADAPTER-REGISTRY.tsv` и
не являются active semantic authority.

## Текущий состав

- `contracts/file-mode-owner-check-semantic-v2.json` — current read-only semantic contract для `file-mode-owner`; dereferenced selected object обязан быть regular file до проверки mode; v1 сохранён как предыдущая identity;
- `contracts/sysctl-check-semantic-v2.json` — current read-only semantic contract для
  `sysctl`; `eq` сохраняет exact semantics, `ge` разрешён только для integer lower bounds;
- `contracts/kernel-cmdline-check-semantic-v2.json` — текущий read-only контракт точных токенов
  для фактической загрузочной строки `/proc/cmdline`; `one-of` кодирует ordered alternatives через `|`, где первое значение preferred, но все перечисленные значения compliant; v1 сохранён как предыдущая product identity;
- `contracts/optional-file-root-files-mode-check-semantic-v1.json` — read-only contract для optional system-cron root + direct regular files; missing root = `VALUE/PASS`, неоднозначный nested/symlink/special population = `ERROR`;
- `contracts/local-account-password-state-check-semantic-v2.json` — current read-only aggregate contract для локальных `/etc/passwd` accounts + source-anchored `/etc/shadow`; NUL/CR и malformed mapping отвергаются до Bash line parsing; empty password field = `FAIL`;
- `contracts/sshd-root-login-check-semantic-v1.json` — read-only source-faithful contract SRC-0002: main `/etc/ssh/sshd_config` обязан содержать global `PermitRootLogin no`, а `sshd -t/-T` подтверждают синтаксис и effective `no`; Include/Match ambiguity fail-closed;
- `contracts/pam-wheel-access-check-semantic-v2.json` — current read-only aggregate contract SRC-0003: source-exact PAM rule + local `wheel` record с literal numeric GID `10` + explicit local authority; group password field не является source predicate; prior `auth`/`-auth` success-short-circuit/include ambiguity fails closed;
- `contracts/sudoers-reviewed-policy-check-semantic-v1.json` — read-only aggregate contract SRC-0004: точное активное дерево policy sudoers сверяется с явным локальным reviewed authority;
- `contracts/cron-command-paths-write-protection-check-semantic-v1.json` — read-only aggregate contract SRC-0007 для persistent cron command target population и exact `go-w` file protection;
- `contracts/user-cron-files-mode-check-semantic-v2.json` — текущий read-only aggregate contract SRC-0011: только прямая population regular user-cron; рекурсивный обход соседних spool, таких как `atjobs/atspool`, исключён;
- `contracts/running-process-paths-write-protection-check-semantic-v1.json` — read-only aggregate contract SRC-0006 для executable/library population текущих процессов и containing/all-parent directory write protection;
- `contracts/standard-system-paths-mode-check-semantic-v2.json` — текущий read-only aggregate contract SRC-0012: executable regular targets из canonical/root `$PATH`, standard/local library roots и модулей current kernel; non-executable regular data под exec roots исключены; числовой критерий mode явно derived;
- `contracts/suid-sgid-applications-check-semantic-v2.json` — текущий read-only contract SRC-0013: SUID/SGID population на всех non-pseudo mounts, включая `nosuid`, проверка mode `go-w` и отдельная проверка authority allowlist;
- `contracts/home-sensitive-files-mode-check-semantic-v2.json` — current SRC-0014 contract: все local passwd accounts плюс mandatory inventory и explicit common shell-history/config discovery для Bash/zsh/ksh/csh/tcsh/fish/Nushell/Xonsh/Elvish; broad suffix matching вроде `*rc` запрещён;
- `contracts/home-directories-mode-check-semantic-v2.json` — текущий contract SRC-0015: точный `0700` для каждого существующего домашнего каталога локальной passwd-записи, включая service/system accounts;
- `contracts/tested-setting-attestation-check-semantic-v1.json` — read-only procedural-fact contract SRC-0034: explicit local authority должен подтвердить `TESTED-BEFORE-USE` для exact `kernel.randomize_va_space=2`; authority не подменяет отсутствующую в source методику тестирования;
- `adapters/product-file-mode-owner-check-v2.py` + JSON binding; v1 сохранён как предыдущая identity;
- `adapters/product-sysctl-check-v2.py` + JSON binding (v1 сохранён как предыдущая product identity);
- `adapters/product-kernel-cmdline-check-v2.py` + JSON binding; только чтение
  `/proc/cmdline`, без GRUB/APPLY/RESTORE; v1 сохранён как предыдущая product identity;
- `adapters/product-optional-file-root-files-mode-check-v1.py` + JSON binding; только `stat/find/sort`, без chmod/chown/APPLY;
- `adapters/product-local-account-password-state-check-v2.py` + JSON binding; raw-byte validation + read-only `/etc/passwd`/`/etc/shadow`, без passwd/usermod/APPLY;
- `adapters/product-sshd-root-login-check-v1.py` + JSON binding; только чтение SSH config tree и `sshd -t/-T`, без записи/reload/restart/APPLY;
- `adapters/product-pam-wheel-access-check-v2.py` + JSON binding; только чтение `/etc/pam.d/su`, `/etc/group` и local authority; `-auth` учитывается в PAM stack semantics, group password field не фиксируется в `x`; без group/PAM mutation/APPLY;
- `adapters/product-tested-setting-attestation-check-v1.py` + JSON binding; только чтение `/etc/securelinux-policy/tested-setting-attestations-v1`, без запуска тестов, изменения sysctl или записи authority;
- `adapters/product-sudoers-reviewed-policy-check-v1.py` + JSON binding; только `visudo -c`/read/hash active sudoers closure и reviewed authority, без sudoers mutation/APPLY;
- `adapters/product-cron-command-paths-write-protection-check-v1.py` + JSON binding; isolated `/usr/bin/python3` read-only parser canonical Ubuntu cron sources, fail-closed command resolution и direct `run-parts` target expansion; без host mutation/APPLY;
- `adapters/product-user-cron-files-mode-check-v2.py` + JSON binding; direct-only read-only traversal admitted cron roots, без recursive `atd` subtree capture и без chmod/chown/APPLY;
- `adapters/product-running-process-paths-write-protection-check-v1.py` + JSON binding; isolated `/usr/bin/python3` read-only observation `/proc` принимает все executable file-backed mappings независимо от basename, строго валидирует maps grammar и binding `dev:inode`, контролирует transient process creation через `/proc/stat` `processes`, повторно сверяет per-PID exe/maps и file/parent identity перед verdict; без host mutation/APPLY;
- `adapters/product-standard-system-paths-mode-check-v2.py` + JSON binding; читает root-process `$PATH`, включает в exec population только regular targets с `(mode & 0111) != 0` и использует только read-only `uname/readlink/find/sort/stat`, без chmod/chown/APPLY;
- `adapters/product-suid-sgid-applications-check-v2.py` + JSON binding; только чтение mountinfo/allowlist и `find/sort/stat`, без chmod/chown/remount/APPLY;
- `adapters/product-home-sensitive-files-mode-check-v2.py` + JSON binding; local passwd + inventory + read-only home traversal с explicit shell-artifact classifier для стандартных Bash/zsh/ksh/csh/tcsh/fish/Nushell/Xonsh/Elvish artifacts и без broad `*rc/*env`;
- `adapters/product-home-directories-mode-check-v2.py` + JSON binding; локальный passwd + read-only наблюдение mode;
- `ADAPTER-REGISTRY.tsv` — единственный tracked mapping parameter kind →
  semantic contract / binding / implementation с SHA-256;
- `contracts/apply-semantic-contract-v1.schema.json` — parent JSON Schema будущих source-specific APPLY semantic contracts; schema сама не разрешает host mutation;
- `APPLY-KIND-REGISTRY.tsv` — machine-readable registry допустимых `apply_kind`; RELEASE gate автоматически связывает каждый future/current source-specific APPLY contract с exact registry row и fail-closed отвергает незарегистрированный kind или несовпадающие kind-level ограничения; текущий parent gate содержит только `local-account-password-lock`, но source-specific APPLY contract и implementation ещё отсутствуют;
- `SUPPORTED-PLATFORMS.tsv` — machine-readable authority основной проверенной 7/7 runtime-матрицы (`FULL | MINIMIZED | SERVER`);
- `SUPPORTED-DESKTOPS.tsv` — отдельная machine-readable authority дополнительного Ubuntu 24.04 x86_64 `TYPE=DESKTOP`; desktop environment/GUI shell не является support discriminator;
- `generate-product-check-v2.py` — текущий отслеживаемый детерминированный generator единого read-only CLI; runtime preflight определяет OS/version/arch, затем либо основной FULL/MINIMIZED/SERVER profile, либо дополнительный `TYPE=DESKTOP`;
- `generate-product-check-v1.py` — сохранённая предыдущая generator identity;
- `/securelinux-policy.sh` + `/securelinux-policy.sh.sha256` — отслеживаемая byte-exact пользовательская точка входа текущей product population;
- `dist/` — optional derived gitignored rebuild output, не источник истины.

Generator читает текущий `CONTROL-MANIFEST.tsv`, проверяет canonical YAML и
registry SHA bindings и fail-closed выбирает adapter по `parameter.kind`.


## Единый CLI / быстрый старт v1

Текущая пользовательская точка входа — один tracked executable
`securelinux-policy.sh`. Для обычного CHECK пользователь не запускает Python
generator. Compliance execution выполняется как executable (`./securelinux-policy.sh`)
или явно `/bin/bash -p ./securelinux-policy.sh`: shebang `#!/bin/bash -p` запрещает
импорт environment shell functions до выполнения generated checks. Plain `bash script`
и `source script` не являются поддерживаемым compliance execution path.

- `--check` — pretty table с обнаруженной ОС, архитектурой и runtime platform; основной 7/7 contour показывает `PROFILE`, Ubuntu 24.04 Desktop — `TYPE=DESKTOP`; один script обслуживает обе support authorities;
- `--check --failed` — только `FAIL` и `ERROR`;
- `--check --format raw` — `SLP-PLATFORM-V1` identity record + стабильные `SLP-CHECK-V1` TSV records;
- `--check --format json` — `SLP-REPORT-V1` с отдельным `platform` object;
- `--report` — compact human report с `FAIL`/`ERROR`;
- каждый `ERROR` имеет обязательный стабильный `domain:reason` в `VALUE / DETAILS`, raw и JSON; `ERROR` с `-` считается внутренне некорректным результатом и rejected fail-closed; reason-code не зависит от stderr;
- raw-byte preflight выполняется до Bash line parsing: NUL отвергается для sysctl,
  kernel cmdline и SSH config; SSH допускает CR только в canonical CRLF, а sysctl
  сохраняет разрешённый CR как edge whitespace; `/etc/os-release` до parsing
  проверяется на недопустимые C0 bytes и корректный UTF-8, а `ID`/`VERSION_ID`/
  `PRETTY_NAME` читаются без `source` с поддержкой разрешённых single/double quotes
  и shell-style escaping; malformed identity даёт `UNSUPPORTED_PLATFORM`;
- dpkg `${Status}` принимается только как полная тройка с error flag `ok`:
  `installed` означает installed, `not-installed`/`config-files` — absent, а
  промежуточные или повреждённые состояния дают `UNSUPPORTED_PROFILE`;
- `--build-info`, `--provenance`, `--version`, `--help` — metadata/UI;
- `--apply` — fail-closed `NOT_IMPLEMENTED`, RC=2, зарезервирован для будущей mutation-line; `--restore` отсутствует в current CLI, потому что operational RESTORE исключён из v3.

`tests/product-v1/test_product_generator.py` содержит `UnifiedCliArtifact`, который
детерминированно пересобирает artifact в temp и требует byte-exact equality с tracked root script и sidecar.

## Текущий статус

CHECK для current population из manifest реализован и покрыт regression tests. Generated
artifact имеет статус `NON_RELEASE_PRODUCT_CANDIDATE`; один target family
`linux-x86_64-supported-v1` охватывает основную проверенную матрицу 7/7 из `SUPPORTED-PLATFORMS.tsv` и дополнительный Ubuntu 24.04 x86_64 Desktop из `SUPPORTED-DESKTOPS.tsv`; всего current supported environments — 8.

CHECK не содержит APPLY implementation. Parent schema/registry APPLY semantic contracts уже существуют, но source-specific APPLY contract ещё не принят. RESTORE не входит в целевую mutation-архитектуру. Policy noncompliance не равен execution
failure. Result `NOT_FOUND`/`ERROR` делает итог `UNEVALUATED`; observation `NOT_FOUND`
может быть definitive `FAIL`, если active semantic contract прямо определяет отсутствие
обязательного объекта/технологии как noncompliance (в частности SSH/PAM).

Принцип отсутствия — `proven-absence-only`: `NOT_FOUND` допустим только при
доказанном отсутствии имени. Нечитаемый объект, dangling symlink, symlink loop
или отсутствие обязательного observation tool классифицируются как `ERROR`.

## Принятое покрытие FSTEC core для `fstec-linux-2022`

`SRC-0005 / 2.3.1` закрыт через `exact-control-set` из трёх canonical controls:

- `/etc/passwd` → `mode eq 0644`;
- `/etc/group` → `mode eq 0644`;
- `/etc/shadow` → `mode bits-clear 0077`.

`/etc/shadow = 0600` из source anchor не выводится. Все три controls используют
current read-only `product-file-mode-owner-check-v2`; APPLY/RESTORE по-прежнему
не реализованы.

После CHECK-11 CHECK-линия продолжила закрытие строк текущего документа и в итоге
достигла `fstec-linux-2022 CHECK COMPLETE` (`40/40 CLOSED`). В этой истории
exact-eq batch закрыл `SRC-0030`, `SRC-0031`,
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
`VALUE/FAIL`. v2 добавляет ordered `one-of`: expected list кодируется как
`|`-separated exact token values. Первое значение является безусловно preferred
и при совпадении даёт PASS; более поздний source-listed fallback не считается
автоматически compliant, если источник связывает его с условием, которое adapter
не умеет доказать — тогда результат fail-closed ERROR. Сам donor остаётся только
прецедент реализации.

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

Один aggregate control `user-cron-files-mode` v2 проверяет пользовательские cron-файлы только в canonical target root `/var/spool/cron/crontabs`. В population входят direct regular non-symlink files (`maxdepth 1`); parent `/var/spool/cron` не является population root, поэтому unrelated direct objects и `atd` siblings/subtrees не могут быть ошибочно классифицированы как user crontabs. Точное source-отношение `chmod go-w` представлено как `mode bits-clear 0022`; требования к owner/group или к режиму root-каталога не добавляются.

Пустая population compliant: на Ubuntu 24/26 `MINIMIZED` пакет `cron` отсутствовал; на Ubuntu 22 `FULL`, Ubuntu 24 `FULL`, Ubuntu 26 `FULL`, Debian 12 `SERVER` и Debian 13 `SERVER` `/var/spool/cron/crontabs` присутствовал, но regular user-crontab files на момент диагностики отсутствовали. Эти VM-факты подтверждают layout assumptions, но являются evidence поддерживаемой runtime-матрицы. Symlink/special direct object, traversal/stat error или неоднозначность canonical population дают `ERROR`; молчаливые donor-skips не переносятся.
## SRC-0007 / 2.3.3

Один aggregate control `cron-command-paths-write-protection` проверяет persistent configured cron job targets read-only. Canonical source layout — `/etc/crontab`, active-name entries `[A-Za-z0-9_-]+` непосредственно в `/etc/cron.d` и user crontabs `/var/spool/cron/crontabs`, имена которых соответствуют локальному `/etc/passwd`. System rows содержат explicit user field; user-spool rows исполняются от имени соответствующей account. Отсутствие optional cron sources означает пустую соответствующую population, а не `NOT_FOUND`.

Каждый однозначно разрешённый direct external command target должен удовлетворять exact source relation `chmod go-w` → `(mode & 0022) == 0`. Absolute command path поддерживается для любого job user; bare command разрешается только для uid `0` при explicit absolute `PATH=` в том же crontab. Первый unescaped `%` завершает executable command portion; cron stdin tail не трактуется как новая команда. Для direct `run-parts` дополнительно включаются executable regular members с active Debian/Ubuntu names `[A-Za-z0-9_-]+` из указанной absolute directory.

Parser намеренно fail-closed: shell expansion/substitution, redirection, non-`/bin/sh` `SHELL` override, interpreter families (включая versioned names) и известные launcher/wrapper forms дают `ERROR`; symlink alias и absolute wrapper path не обходят это правило: классификация выполняется по basename конечной regular-file цели после symlink resolution. Resolved external command с `st_nlink != 1` также даёт `ERROR`, потому что hardlink alias не позволяет однозначно доказать path-role semantics для interpreter/wrapper/`run-parts`. Non-empty crontab без final LF также даёт `ERROR`. Source files, source directories, PATH directories и resolved targets снимаются дважды с object/byte state; pathset или object drift запрещает PASS. Для `&&`/`||` и других поддержанных separators conservative configured population включает все syntactically reachable external segments, то есть dormant branch не используется как основание скрыть потенциальный target.

Права самих system cron configuration files принадлежат SRC-0010, а user crontab-file modes — SRC-0011; они не подменяют SRC-0007 target-file check. APPLY/RESTORE отсутствуют.

## SRC-0006 / 2.3.2

Один aggregate control `running-process-paths-write-protection` реализует read-only проверку exact source semantics. Bounded observation начинается с `/proc/stat` `processes` counter и exact ASCII-decimal PID→starttime snapshot; `/proc/<pid>/stat` принимается только в полном 52-field layout с exact PID prefix, single-space separators и без пустых/сдвинутых полей; counter и population повторно сверяются после per-PID обхода и перед verdict. Поэтому PID addition/removal/reuse и transient process creation внутри observation window дают `ERROR`. Kernel threads и zombies исключаются только при явном подтверждении status и повторной identity-проверке.

Executable target обязан быть absolute existing regular file; `/proc/<pid>/exe` target и object identity повторно сверяются перед verdict. Runtime-code population берётся из каждого executable file-backed `/proc/<pid>/maps` record независимо от basename. Для каждой строки строго валидируются address range, perms, offset, device, ASCII-decimal inode и pathname; proc octal escaping декодируется, а maps-declared `dev major:minor + inode` обязан совпадать с фактическим target. Deleted/unresolvable/malformed/mismatched mapping даёт `ERROR`. Exact parsed executable maps set каждого PID перечитывается перед verdict, поэтому same-PID `exec`/`mmap` drift не может дать stale `PASS`. File mode condition дословно представляет `chmod go-w`: `(mode & 0022) == 0`.

Для containing directory и всех parent directories до `/` проверяется effective возможность изменения directory entries: permission class должен иметь одновременно write+search (`wx`). Non-root owner `wx` и `other wx` являются доказанным `VALUE/FAIL`. `group wx` по mode alone не доказывает конкретного непривилегированного principal/ACL binding, поэтому при отсутствии уже доказанного нарушения current v1 возвращает fail-closed `ERROR`, а не conservative false `FAIL`. Write без search не выдаётся за фактическую возможность изменения entries. File и parent snapshots повторно сверяются по dev/inode/uid/gid/mode/ctime; один file inode дедуплицируется для file-mode проверки, но distinct resolved paths сохраняют свои parent chains. Полностью определённая стабильная population с доказанными нарушениями даёт `VALUE/FAIL`, без нарушений и ambiguity — `VALUE/PASS`; partial/ambiguous/изменившаяся observation никогда не становится PASS.

Pinned donor использован только как precedent для `/proc/<pid>/exe` + `/proc/<pid>/maps` discovery. Его silent exception handling и exclusions `/tmp`, `/run`, `/var/tmp`, `/dev/shm`, `/var/log` намеренно не переносятся. APPLY/RESTORE не реализуются.

## SRC-0012 / 2.3.8

`standard-system-paths-mode` v2 устраняет прежнее сужение population. Executable roots включают `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` **и каждый absolute entry фактического `$PATH` процесса root**; в exec population входят только regular targets с хотя бы одним execute bit `(mode & 0111) != 0`, а обычные non-executable data files исключаются. Запуск не от EUID 0 даёт `ERROR`, а не использует PATH непривилегированного пользователя. Library roots: `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, `/usr/local/lib`, `/usr/local/lib64`; modules: `/lib/modules/<uname-r>`. merged-`/usr` aliases и targets дедуплицируются по `dev:inode`.

Источник требует «анализа корректности прав», но не задаёт числовой mode. Поэтому `(mode & 0022) == 0` теперь явно обозначен как **derived operational criterion** с justification в control, а не как дословная source semantics. Candidate dangling/special target, incomplete traversal, invalid/non-absolute root PATH или stat/readlink ambiguity => `ERROR`. Parent-directory правило 2.3.2 сюда не переносится. APPLY/RESTORE отсутствуют.

## SRC-0013 / 2.3.9

Оба controls v2 используют одну population: все regular SUID/SGID files на всех **non-pseudo mounted filesystems**, включая mounts с `nosuid`. `nosuid` изменяет execution semantics, но не удаляет файл из буквального source-аудита SUID/SGID-приложений. Один underlying file дедуплицируется по `dev:inode`; scan/stat/mountinfo ambiguity => `ERROR`.

`SUID-SGID-MODE` проверяет exact source relation `chmod go-w` → `bits-clear 0022`. `SUID-SGID-ALLOWLIST` отдельно проверяет `population ⊆ approved set` против explicit local `/etc/securelinux-policy/suid-sgid.allowlist-v1`; missing/malformed authority => `ERROR`, unlisted application => `FAIL`. Owner=root не добавляется. APPLY/RESTORE отсутствуют.

## SRC-0014 / 2.3.10 — чувствительные файлы домашних каталогов пользователей

- v2 включает **все** syntactically valid local `/etc/passwd` accounts с absolute home, включая service/system accounts; `UID_MIN`, `nologin` и `false` больше не являются source-unanchored exclusions.
- Exact mode relation остаётся source `chmod go-rwx` → `(mode & 0077) == 0`.
- Восемь явно названных source entries обязательны в `/etc/securelinux-policy/home-sensitive-files-v1`, но inventory больше не считается доказательством полноты сам по себе: read-only traversal дополнительно обнаруживает explicit common shell artifacts для Bash (`.bash_login`), zsh/ksh/csh/tcsh, fish, Linux-default Nushell config/autoload/history, Xonsh rc/history и Elvish rc/history. Broad suffix matching (`*rc`, `*env`) запрещён, поэтому несвязанный `.vimrc` не попадает в population. Custom XDG/override paths остаются в обязательном local inventory augmentation channel.
- Open-ended «и т. п.» population явно помечена `derived:true` с justification; NUL/CR, malformed passwd/inventory, traversal failure, selected symlink/nonregular object => `ERROR`.
- Owner/group и home-directory mode сюда не добавляются; APPLY/RESTORE отсутствуют.

## SRC-0015 / 2.3.11 — режим домашних директорий пользователей

`home-directories-mode` v2 проверяет exact source `chmod 700` как `mode == 0700` для каждой существующей real home directory **каждой syntactically valid local `/etc/passwd` account** с absolute home path, включая service/system accounts. `UID_MIN` и shell-type exclusions удалены как не указанные источником. Absent home не создаётся и не объявляется mode violation; symlink/non-directory/stat ambiguity и malformed NUL/CR passwd input => `ERROR`. Owner/group и sensitive-file modes не добавляются. APPLY/RESTORE отсутствуют.

## SRC-0002 / 2.1.2

Один aggregate control `sshd-root-login` представляет source-exact требование `PermitRootLogin no` именно в основном `/etc/ssh/sshd_config`. Простого grep и наличия managed drop-in недостаточно: CHECK рекурсивно учитывает активные `Include` в явном лексикографическом порядке путей, восстанавливает `Match`-scope содержащего файла после каждого Include, проверяет `sshd -t` и effective root-context через `sshd -T -C`. Main-файл должен содержать активную global директиву с семантическим значением `no`; effective value также должен быть `no`.

Глобальные дубли сами по себе не объявляются ошибкой: семантика первого полученного значения проверяется effective-выводом OpenSSH. Парсер проверяемых SSH-директив поддерживает whitespace/один `=` как separator, quoted/escaped arguments, CRLF и token-boundary comment semantics (`#` внутри token не обрезается). Glob population получает явную сортировку; function-shadowing `compgen`, ошибка sort/find/compgen и pathname с переводом строки не могут тихо скрыть Include — это fail-closed `ERROR`. `Match`-scope `PermitRootLogin no` безопасен; non-`no` conditional value, include-cycle, symlink/unreadable/malformed config или иная parser ambiguity дают `ERROR`, а не ложный PASS. APPLY/RESTORE, reload/restart SSH отсутствуют.

## SRC-0003 / 2.2.1

Один aggregate control `pam-wheel-access` представляет обе source-explicit части: активную rule `auth required pam_wheel.so use_uid` непосредственно в `/etc/pam.d/su` и local запись `wheel` в `/etc/group`.

`root` обязателен непосредственно в fourth field wheel record. Placeholder `<user list>` не угадывается из текущих sudo/admin accounts: current product authority — `/etc/securelinux-policy/wheel-users.allowlist-v1`, по одному дополнительному разрешённому имени на строку. После обязательного `root` фактический supplementary-members set должен точно совпасть с authority; missing/extra member даёт `VALUE/FAIL`. Если PAM/wheel/root уже явно отсутствуют, это definitive `FAIL` без authority; когда structural conditions выполнены, missing/malformed authority даёт `ERROR`.

v2 сохраняет source-exact numeric GID `10`, но не усиливает example password field до literal `x`: `wheel::10:<members>` и иное syntactically valid passwd field допустимы; иной numeric GID даёт `VALUE/FAIL`. До первой exact `auth required pam_wheel.so use_uid` rule нераскрытые `@include`, `auth/-auth include`, `auth/-auth substack`, `auth/-auth sufficient` и `auth/-auth` extended-control forms дают `ERROR`, чтобы presence строки не маскировал permissive earlier stack. Leading `-` у PAM type не исключает строку из stack-semantics анализа. Include после уже обязательной `required` rule допустим. Иной active `pam_wheel.so` variant также `ERROR`. Donor mutation/discovery не переносится; APPLY/RESTORE отсутствуют.
## SRC-0004 / 2.2.2

Один aggregate control `sudoers-reviewed-policy` представляет source-требование пересмотра `/etc/sudoers` без выдумывания универсального списка sudo-пользователей или команд. Current local decision задаётся authority `/etc/securelinux-policy/sudoers-reviewed-policy-v1`: header `SLP-SUDOERS-REVIEWED-POLICY-V1`, затем exact SHA-256 и absolute path каждого утверждённого active sudoers-файла.

CHECK запускает pinned `/usr/sbin/visudo -c -f /etc/sudoers` под `LC_ALL=C`; PASS требует successful syntax validation и exact equality фактической parse closure (`/etc/sudoers` + реально разобранные include/includedir files) с authority по pathset и bytes. До line parsing authority raw bytes допускают только structural TAB/LF и canonical CRLF, а `visudo` stdout сначала переводится pinned `/usr/bin/od` в hex и проверяется как raw-byte stream, чтобы Bash command substitution не мог скрыть NUL/control-byte corruption. Missing/extra file или digest drift даёт `VALUE/FAIL`. Missing/malformed authority, embedded nonstructural control byte, NUL/invalid framing в observation, unexpected/duplicate visudo closure, symlink/nonregular/unreadable policy member либо tool failure дают `ERROR`; reason-code различает конкретный класс ошибки closure/member, а не сводит их к общему `visudo:invalid-output`. `%sudo`, `%wheel`, `SUDO_USER`, donor и VM defaults не используются как approved-policy authority. APPLY/RESTORE отсутствуют.

Семь ранее собранных privileged VM runs подтвердили discovery baseline: `/etc/sudoers` regular `0440 root:root`, `@includedir /etc/sudoers.d` присутствует, `visudo` full check `RC=0` на всех 7/7; это не определяет approved local policy.


## SRC-0008 / 2.3.4
`Defaults runas_default`, override `case_insensitive_user` и command `NOTBEFORE/NOTAFTER` не over-approximate: v1 возвращает `ERROR`, если exact effective applicability не доказуема; default case-insensitive spelling `ROOT` сохраняет root semantics.


Один aggregate control `sudo-root-command-files-protection` проверяет executable command paths из exact reviewed active sudoers tree. Сначала active `visudo` closure exact-byte/pathset сверяется с `/etc/securelinux-policy/sudoers-reviewed-policy-v1`; затем `/usr/bin/cvtsudoers -c /dev/null -e -s aliases -f json` используется как parser authority для alias-expanded policy representation.

В population входят только rules с детерминированными explicit username/userid selector: ordinary invoker + root runas. Root-only invoking-user rules и explicit non-root-only runas не добавляют targets; group/netgroup/non-Unix membership и selector negation дают `ERROR`, а не over-approximation. Positive `ALL`, regex/wildcard/directory executable path, negated command entry, command digest и иная форма, для которой нельзя доказать exact applicable finite path population, дают `ERROR`, а не partial PASS/over-check FAIL. Для `VALUE` поддерживается только exact alias-expanded `Host_List=[hostname: ALL]`; любая host-qualified hostname/network/netgroup/negation форма даёт `ERROR`, потому что v1 не переimplements current-host matching и не может включать чужой host rule без риска false FAIL. Любой enabled `runchroot`/`CHROOT` в Defaults либо Cmnd_Spec даёт `ERROR`, потому что меняет file object, адресуемый absolute command path. Поскольку JSON `cvtsudoers` объединяет pathname и arguments и снимает escaping пробелов, boundary executable path определяется только если существует ровно один executable regular-file prefix; zero/multiple candidates дают `ERROR`.

Для каждого stable executable regular target требуется `st_uid == 0` и `(mode & 0022) == 0`. Symlink проверяется по final regular target. Known interpreter/execution frontend, multilink target и shebang-script дают `ERROR`: v1 не возвращает PASS для execution chain, которую не может доказательно раскрыть до конечного executable. Missing/nonregular/non-executable target, policy/tool/JSON ambiguity или source/target drift => `ERROR`. CHECK не выполняет `chown`, `chmod`, APPLY или RESTORE.

- `product/contracts/sudo-root-command-files-protection-check-semantic-v1.json` — семантический контракт SRC-0008.
- `product/adapters/product-sudo-root-command-files-protection-check-v1.py` — read-only adapter для SRC-0008.


## SRC-0034 / 2.5.11

Source clause `2.5.11` содержит не только конечное значение `kernel.randomize_va_space = 2`, но и прямой procedural qualifier `после тестирования`. Поэтому current closure — exact два read-only controls: обычный `sysctl eq 2` проверяет только фактическое текущее значение, а `tested-setting-attestation` отдельно проверяет explicit local procedural fact.

Canonical authority `/etc/securelinux-policy/tested-setting-attestations-v1` начинается строкой `SLP-TESTED-SETTING-ATTESTATIONS-V1`; далее строки имеют вид `SRC-NNNN<TAB>setting<TAB>state`. Для `SRC-0034` допустим exact setting `kernel.randomize_va_space=2` и states `TESTED-BEFORE-USE` / `NOT-TESTED-BEFORE-USE`. Первый даёт PASS только при exact binding; второй или wrong setting — FAIL; missing/malformed/duplicate/symlink/unreadable authority или отсутствующая target row — ERROR.

Этот authority является product mechanism для явного представления локального факта «тестирование выполнено до использования». Он не вводит новую норму ФСТЭК, не задаёт отсутствующую в source методику тестирования и не утверждает, что CHECK способен независимо реконструировать историческое тестирование. APPLY/RESTORE и запуск тестов отсутствуют.


## SRC-0009 / 2.3.5

Один aggregate control `startup-files-write-protection` представляет source-exact `chmod o-w`: единственный compliance predicate — отсутствие бита other-write `0002`. Owner/group, запрет group-write и фиксированный mode не добавляются.

Population состоит из direct file-like entries в `/etc/rc0.d`…`/etc/rc6.d` и direct `*.service` в unit load paths, которые возвращает `systemd-analyze unit-paths`. `/etc/rcS.d` остаётся diagnostic-only; `.wants/.requires` не рекурсируются как дополнительные unit files. Merged-`/usr` aliases unit roots и regular targets дедуплицируются по `dev:inode`. Symlink на regular target проверяется по final target; systemd mask, разрешающийся в `/dev/null`, учитывается отдельно и не приводит к проверке `/dev/null`. Dangling/special/unreadable population, discovery ambiguity или snapshot drift дают `ERROR`. CHECK не выполняет `chmod`, APPLY или RESTORE.

Семь read-only v3 layout captures (Ubuntu 22 FULL; Ubuntu 24.04.4 MINIMIZED/FULL; Ubuntu 26 MINIMIZED/FULL; Debian 12; Debian 13) подтвердили необходимые layout edge cases: merged-`/usr` duplicate unit roots на Ubuntu 22/Debian 12, masked units, runtime/generator roots и dangling recursive dependency reference. Эти наблюдения определяют только безопасный discovery contract, а не дополнительные policy predicates.

- `product/contracts/startup-files-write-protection-check-semantic-v1.json` — семантический контракт SRC-0009.
- `product/adapters/product-startup-files-write-protection-check-v1.py` — read-only adapter для SRC-0009.
