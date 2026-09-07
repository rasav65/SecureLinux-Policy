# Продуктовая линия CHECK и SRC-0001 APPLY

Постоянная read-only CHECK product-line и первая ограниченная APPLY-вертикаль
SecureLinux-Policy v3.

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
- `adapters/product-standard-system-paths-mode-check-v2.py` + JSON binding; читает root-process `$PATH`, включает в exec population regular targets с `(mode & 0111) != 0`; метаданные читает внутри Python, обход и разрешение путей выполняет через GNU find/readlink, версию ядра получает через uname. Guard `[[ ! -x /usr/bin/python3 ]]` даёт `runtime:python3-missing` при отсутствии или недоступности исполнения; последующий сбой запуска даёт `runtime:observer-failed`. Причины ERROR перечислены в `error_reasons` семантического контракта; изменения состояния хоста не выполняются. В роли exec ссылка на каталог с dev:inode exec-корня пропускается без нового поля отчёта; другие недопустимые directory targets сохраняют ERROR. Применимость VM-результатов описана в `docs/testing-strategy.md`.
- `adapters/product-suid-sgid-applications-check-v2.py` + JSON binding; только чтение mountinfo/allowlist и `find/sort/stat`, без chmod/chown/remount/APPLY;
- `adapters/product-home-sensitive-files-mode-check-v2.py` + JSON binding; local passwd + inventory + read-only home traversal с explicit shell-artifact classifier для стандартных Bash/zsh/ksh/csh/tcsh/fish/Nushell/Xonsh/Elvish artifacts и без broad `*rc/*env`;
- `adapters/product-home-directories-mode-check-v2.py` + JSON binding; локальный passwd + read-only наблюдение mode;
- `ADAPTER-REGISTRY.tsv` — единственный tracked mapping parameter kind →
  semantic contract / binding / implementation с SHA-256;
- `contracts/apply-semantic-contract-v1.schema.json` — parent JSON Schema source-specific APPLY semantic contracts; schema сама не разрешает host mutation;
- `contracts/local-account-password-state-apply-semantic-v1.json` — flat source-specific APPLY contract-кандидат для `SRC-0001`; сохраняется как `REVISE_INPUT_NOT_FINAL_AUTHORITY`, а финальная semantic authority строится через модульные definitions;
- `APPLY-KIND-REGISTRY.tsv` — компактная машиночитаемая привязка: `apply_kind` + `target_class` → exact объект архитектуры `SRC-0001` + SHA-256; низкоуровневые semantics `predicate`/`transform`/path/lock/transaction больше не дублируются в registry;
- `contracts/src0001-apply/architecture-v1.json` — принятая узкая модульная архитектура только для `SRC-0001`: все восемь локальных ролей имеют state `CLOSED` и exact SHA, implementation registry имеет state `PRESENT`;
- `contracts/src0001-apply/predicate-empty-second-shadow-field-v1.json` — exact P-03 predicate: population берётся только из bound current CHECK semantic v2; выбирается ровно password field №2 с byte-length `0`; CHECK ERROR/ambiguity → `ABORT_NO_MUTATION`, CHECK PASS → `NOOP_SUCCESS`;
- `contracts/src0001-apply/transform-empty-second-shadow-field-to-bang-v1.json` — exact P-03 transform, SHA-bound к predicate: только выбранное поле `"" -> "!"` (`0x21`); non-selected/non-empty fields, остальные поля/records/order/delimiters и все bytes вне выбранных вторых полей сохраняются `EXACT`;
- `contracts/src0001-apply/snapshot-precondition-v1.json` — exact P-04 precondition: до host mutation обязателен caller-supplied read-only JSON attestation `SLP-EXTERNAL-SNAPSHOT-ATTESTATION-V1`, exact bound к host `/etc/machine-id` и SHA-256 текущих `/etc/shadow` bytes, с `FULL_TARGET_HOST_OR_VM`, `READY`, `rollback_capable=true`; missing/malformed/mismatch/not-ready → `ABORT_NO_MUTATION`; attestation не объявляется provider-cryptographic proof; product snapshot не создаёт и не восстанавливает;
- `contracts/src0001-apply/lock-reread-v1.json` — exact P-05 libc `lckpwdf(3)`/`ulckpwdf(3)` password-database lock + under-lock reread comparator; `/etc/passwd` и `/etc/shadow` exact bytes, ordered selected usernames и final precommit revalidation обязаны совпасть, иначе `ABORT_NO_MUTATION`;
- `contracts/src0001-apply/object-identity-v1.json` — exact P-05 `/etc` + `/etc/shadow` identity boundary: final target regular non-symlink, `st_nlink == 1`, nofollow fd/fstat identity binding, prelock→under-lock drift запрещён;
- `contracts/src0001-apply/metadata-preservation-v1.json` — точная граница P-06 для допустимости и сохранения метаданных проверенного `/etc/shadow`; владелец, группа и режим сохраняются, а расширенный ACL, xattr или неразрешимое состояние метаданных завершают APPLY до фиксации изменения;
- `contracts/src0001-apply/atomic-transaction-v1.json` — точная P-06 транзакция с единственной атомарной заменой в том же каталоге: проверка временного файла, финальная повторная проверка P-05, переименование, `fsync` родительского каталога, постпроверка при удерживаемой блокировке и освобождение блокировки до итогового отчёта;
- `contracts/src0001-apply/dry-run-report-v1.json` — точный P-06 сухой запуск без записи и `SLP-APPLY-REPORT-V1` с закрытым множеством состояний, привязкой источника ошибки и приоритетом постпроверки;
- `contracts/src0001-apply/composition-v1.schema.json` + `composition-v1.json` — схема Draft 2020-12 и привязанная по SHA-256 композиция всех восьми ролей определений со статусом `CLOSED`;
- `APPLY-IMPLEMENTATION-REGISTRY.tsv` — семипольная exact-привязка kind/composition/adapter к binding и implementation SHA-256;
- `apply-adapters/product-local-account-password-state-apply-v1.json` — binding реализации к exact композиции;
- `apply-adapters/product-local-account-password-state-apply-v1.py` — реализация `SRC-0001`: dry-run, external-snapshot attestation, `lckpwdf(3)`, under-lock reread, atomic replacement, directory fsync, post-check и idempotent NOOP;
- `tools/rebuild-apply-contract-bindings.py` — с отказом при несоответствии проверяет точные идентификаторы и SHA-256 всех восьми определений, связи зависимостей и композицию; `--write` детерминированно пересобирает композицию и SHA-256 архитектуры в компактном реестре;
- `SUPPORTED-PLATFORMS.tsv` — machine-readable authority основной проверенной 7/7 runtime-матрицы (`FULL | MINIMIZED | SERVER`);
- `SUPPORTED-DESKTOPS.tsv` — отдельная machine-readable authority дополнительного Ubuntu 24.04 x86_64 `TYPE=DESKTOP`; desktop environment/GUI shell не является support discriminator;
- `generate-product-check-v2.py` — текущий отслеживаемый детерминированный generator единого CLI с read-only CHECK и `SRC-0001` APPLY; runtime preflight определяет OS/version/arch, затем либо основной FULL/MINIMIZED/SERVER profile, либо дополнительный `TYPE=DESKTOP`;
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
- `--apply --dry-run` — `SRC-0001` dry-run без attestation и без записи;
- `--apply --snapshot-attestation <path>` — `SRC-0001` commit только после exact внешней attestation; отчёт — единственный `SLP-APPLY-REPORT-V1` JSON на stdout;
- голый `--apply`, `--dry-run` без `--apply` и несовместимые комбинации дают `RC=2` до mutation; `--restore` отсутствует, потому что operational RESTORE исключён из v3.

`tests/product-v1/test_product_generator.py` содержит `UnifiedCliArtifact`, который
детерминированно пересобирает artifact в temp и требует byte-exact equality с tracked root script и sidecar.

## Текущий статус

CHECK для current population из manifest реализован и покрыт regression tests. Generated
artifact имеет статус `NON_RELEASE_PRODUCT_CANDIDATE`; один target family
`linux-x86_64-supported-v1` охватывает основную проверенную матрицу 7/7 из `SUPPORTED-PLATFORMS.tsv` и дополнительный Ubuntu 24.04 x86_64 Desktop из `SUPPORTED-DESKTOPS.tsv`; всего current supported environments — 8.

Родительская схема, реестр kind, модульная архитектура и все восемь определений приняты; плоский кандидат для конкретного источника остаётся входом со статусом `REVISE`. `APPLY-IMPLEMENTATION-REGISTRY.tsv`, binding и adapter связывают реализацию `SRC-0001` с exact композицией. Generated CLI реализует scope `SRC-0001_ONLY`; VM acceptance подтвердил dry-run, attested commit, локальную post-check, повторный NOOP и fail-closed ветви до commit. Этап `APPLY_IMPLEMENTATION_ADAPTERS` закрыт; следующий этап — `FINAL_DETERMINISTIC_PACKAGING`. RESTORE не входит в целевую mutation-архитектуру. Policy noncompliance не равен execution
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
подменяется выводом generated CHECK. Для kernel-cmdline APPLY отсутствует; RESTORE
не входит в продукт.

Тесты: `tests/product-v1/`.

## SRC-0010 / 2.3.6

Шесть перечисленных source roots представлены exact-control-set. Проверка использует только source-exact `go-wx` → `bits-clear 0033`; donor `600/700 root:root` не переносится. Для directory root проверяются root + direct regular files. Nested directory, symlink, special entry или incomplete traversal дают `ERROR`; отсутствие перечисленного root разрешено источником и даёт `VALUE/PASS`.

## SRC-0001 / 2.1.1

Один aggregate control проверяет локальную account population из `/etc/passwd` против source-anchored `/etc/shadow`. Для каждого локального пользователя требуется определимая shadow-запись с непустым password field. Empty field → `VALUE/FAIL`; missing/unreadable/symlink/malformed/duplicate mapping → fail-closed `ERROR`. APPLY для этого control реализован в scope `SRC-0001_ONLY`: пустое второе поле заменяется exact байтом `!`; dry-run не пишет, commit требует external-snapshot attestation, повторный запуск даёт NOOP. RESTORE не входит в продукт.
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

---

<a id="readme-engineering-reference"></a>

## Инженерная справка, перенесённая с главной страницы

Ниже сохранены подробные сведения прежнего корневого README. Команды пересборки и проверки целостности выполняются из корня репозитория. Пользовательская последовательность скачивания и запуска находится в [главном README](../README.md).

## SecureLinux-Policy v3

> Система нормативной прослеживаемости и машинно-проверяемой политики
> безопасной настройки Linux, построенная от закреплённых первоисточников.
>
> Текущий product CHECK работает только по уже представленным требованиям и
> **не является заявлением о полном соответствии требованиям ФСТЭК**.

### Текущее состояние

Текущий машинный статус находится в [корневом README](../README.md#машинный-статус-проекта).

Для документа `fstec-linux-2022` read-only CHECK vertical принят; commit
`219b4cc3c0673c55575fb558e160431c11c2a681` опубликован, а milestone
`fstec-linux-2022-check-complete-v1` привязан к этому exact commit. Machine
truth и текущие counts для документа берутся из машинного статуса корневого README и
`docs/fstec-coverage.md`; этот prose-блок не закрепляет live counts вручную.
`DONOR_TO_V3_MAPPING` принят, прошёл precommit и опубликован commit
`1db91b0e17d6ef37e4c42cd41dca77eeb2b743da` с tree
`d3f624651bf13f1174619cef881fababbc768553`. Parent-level APPLY gate закрыт.
Для `SRC-0001` закрыты и криптографически привязаны все восемь определений: предикат,
преобразование, условие внешнего снимка, блокировка и повторное чтение,
идентичность объекта, сохранение метаданных, атомарная транзакция и режим
сухого запуска с отчётом. `composition-v1.json` детерминированно связывает
архитектуру, текущий источник состава CHECK и все восемь определений.
Первая вертикаль APPLY для `SRC-0001` реализована, привязана отдельным реестром,
встроена в tracked CLI и проверена на поддерживаемых Ubuntu/Debian VM. Этап
`APPLY_IMPLEMENTATION_ADAPTERS` закрыт в scope `SRC-0001_ONLY`; следующий этап —
`FINAL_DETERMINISTIC_PACKAGING`. Пользовательский RESTORE в целевую архитектуру
не входит; восстановление после успешного APPLY выполняется внешним снимком.

Полная машинно формируемая карта текущего покрытия:
[`docs/fstec-coverage.md`](../docs/fstec-coverage.md).

---

### Назначение

SecureLinux-Policy строит проверяемую цепочку от первоисточника до исполняемой
read-only проверки:

```text
закреплённый PDF ФСТЭК
  → проверенное текстовое представление
  → source index
  → quote anchor
  → canonical control
  → semantic contract
  → adapter registry
  → read-only adapter
  → deterministic generator v2
  → tracked `securelinux-policy.sh`
  → pretty / raw / JSON result
```

Каждый controlled source row должен иметь проверяемый source-anchor и закрываться
ровно тем набором canonical controls, который указан в
`index/source-v4/CLOSURE-CONTRACT.tsv`. Простого наличия похожей проверки
недостаточно.

CHECK и изменение системы разделены принципиально. CHECK остаётся read-only, а
APPLY реализован только для `SRC-0001` и вызывается отдельным режимом с точным
условием внешнего снимка. Пользовательский RESTORE не планируется; post-APPLY
rollback выполняется внешним snapshot recovery.

---

### Зависимость проверки системных путей

CHECK `standard-system-paths-mode` читает метаданные внутри Python, сохраняя
GNU find/readlink для обхода и разрешения путей. Перед запуском проверяется
`/usr/bin/python3`: отсутствие или недоступность исполнения даёт
`runtime:python3-missing`; сбой запуска после успешной проверки —
`runtime:observer-failed`. Словарь причин ERROR закреплён в семантическом контракте.
В роли exec ссылка на каталог с идентичностью exec-корня пропускается
по совпадению устройства и inode. Новое поле отчёта не добавляется.
Другие ссылки на каталоги и неразрешимые цели сохраняют ERROR.
Границы выполненных проверок описаны в [стратегии тестирования](../docs/testing-strategy.md).

### Быстрый старт

Для обычного запуска генератор не нужен. Текущий product entrypoint
уже находится в корне репозитория:

```text
securelinux-policy.sh
```

На любом environment из `product/SUPPORTED-PLATFORMS.tsv` или `product/SUPPORTED-DESKTOPS.tsv` полный CHECK запускается
одной командой:

```bash
sudo ./securelinux-policy.sh --check
```

Контракт compliance execution: tracked CLI запускается **как executable**, чтобы kernel
применил shebang `#!/bin/bash -p`. Bash в privileged mode не импортирует shell-функции
из окружения, поэтому функция `command` не может подменить закреплённые внешние вызовы.
Эквивалентный явный запуск — `/bin/bash -p ./securelinux-policy.sh ...`. Обычный
`bash securelinux-policy.sh ...` и `source securelinux-policy.sh` не являются поддерживаемым
режимом compliance execution.

По умолчанию вывод предназначен для человека: колонки `RESULT`, `CONTROL` и
`VALUE / DETAILS` имеют фиксированные позиции, а длинные details переносятся
под третьей колонкой.

Только проблемы:

```bash
sudo ./securelinux-policy.sh --check --failed
```

Машинные форматы:

```bash
sudo ./securelinux-policy.sh --check --format raw
sudo ./securelinux-policy.sh --check --format json
```

`raw` сохраняет wire-format `SLP-CHECK-V1`/`SLP-SUMMARY-V1`; `json` выдаёт
структурированный `SLP-REPORT-V1`. Каждый `ERROR` сохраняет fail-closed verdict и
обязательно несёт стабильный reason-code формата `domain:reason` в `VALUE / DETAILS`,
raw и JSON. Reason-code определяется точкой отказа и не строится из случайного stderr;
`-` для production `ERROR` запрещён. Краткий human-readable отчёт с `FAIL` и `ERROR`:

```bash
sudo ./securelinux-policy.sh --report
```

Metadata и provenance не требуют запуска policy checks:

```bash
./securelinux-policy.sh --version
./securelinux-policy.sh --build-info
./securelinux-policy.sh --provenance
```

APPLY ограничен `SRC-0001`. Сухой запуск не требует attestation и не пишет на хост:

```bash
sudo ./securelinux-policy.sh --apply --dry-run
```

Фактический APPLY требует caller-supplied attestation внешнего снимка:

```bash
sudo ./securelinux-policy.sh --apply --snapshot-attestation /path/to/attestation.json
```

Оба режима печатают один JSON-объект `SLP-APPLY-REPORT-V1`. Голый `--apply`,
`--dry-run` без `--apply` и несовместимые комбинации отвергаются с `RC=2` до
изменения системы. Пользовательского ключа `--restore` нет: operational RESTORE
исключён из v3.
Human-readable `--check` и `--report` явно показывают обнаруженную ОС, архитектуру и runtime platform. Для основной 7/7 матрицы выводится `PROFILE=FULL|MINIMIZED|SERVER`; для дополнительного Ubuntu 24.04 Desktop выводится `TYPE=DESKTOP`. Конкретная графическая оболочка не входит в support identity и не влияет на CHECK/APPLY routing.

Sidecar текущего tracked artifact:

```bash
sha256sum -c securelinux-policy.sh.sha256
```

#### Для разработчика: детерминированная пересборка

Текущий пользовательский артефакт строится `product/generate-product-check-v2.py`.
Отслеживаемый `securelinux-policy.sh` обязан побайтно совпадать со свежей генерацией;
это проверяется DEV regression. Для ручной проверки можно собрать копию вне
отслеживаемого корня Git:

```bash
mkdir -p dist
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  product/generate-product-check-v2.py \
  --repo . \
  --out dist/securelinux-policy.sh

cmp -s securelinux-policy.sh dist/securelinux-policy.sh
echo "RC_PARITY=$?"
```

Исторический `product/generate-product-check-v1.py` сохраняется как предыдущая
generator identity и не является текущей пользовательской точкой входа.

---

### Надёжность текущей product-line

| Гарантия | Статус | Чем проверяется |
|---|---|---|
| APPLY реализован только для `SRC-0001`; RESTORE намеренно исключён | PASS | implementation registry + binding + adapter; generated CLI regressions; VM acceptance |
| Детерминированная генерация CHECK | PASS | `tests/product-v1/test_product_generator.py` |
| Adapter/contract bytes закреплены SHA-256 | PASS | `ADAPTER-REGISTRY.tsv` + product regressions |
| CHECK provenance доступен машинно | PASS | generator regression / `--provenance` |
| Sysctl read-error не уходит в неструктурированный stderr | PASS | sysctl adapter regression |
| Неподдерживаемая target-платформа завершается до проверки | PASS | product generator regression, RC=3 |
| DEV test population имеет единую точку запуска | PASS | `tests/run-all.py` + `tests/run-all-selftest.py` |
| Реальный Draft 2020-12 валидатор обязателен для RELEASE | PASS | `tests/release-v1/test_real_jsonschema_gate.py` |
| Current nested `SHA256SUMS` валидны; 2 historical donor runtime entries пинованы как исключения | PASS | `tests/project-integrity-v1/test_root_manifests.py` |
| Gates-v3 evidence с маркировкой `ACTIVE` совпадает со свежим checker run | PASS | `tests/project-integrity-v1/test_root_manifests.py` |
| APPLY | РЕАЛИЗОВАН ДЛЯ `SRC-0001` | `APPLY_SCOPE=SRC-0001_ONLY`; dry-run / attested commit / idempotent NOOP |
| RESTORE | НЕ ПЛАНИРУЕТСЯ / ВНЕ SCOPE | post-APPLY recovery = внешний snapshot |

Гарантии относятся только к текущему scope. Конкретный policy-result CHECK
описывает состояние проверяемого хоста и не является свойством самого generator.

---

### Слои политики

Проект не смешивает происхождение и назначение требований:

```text
FSTEC core ≠ recommended ≠ corporate standard ≠ firewall
```

- **FSTEC core** — только требования с проверяемым якорем в первичном
  нормативном/техническом источнике ФСТЭК.
- **recommended** — рекомендации вне FSTEC core.
- **corporate standard** — внутренние требования и ужесточения; будущие
  `baseline / strict / paranoid` относятся только к этому слою.
- **firewall** — отдельная role-specific policy. UFW, nftables и iptables —
  реализации firewall-policy, а не автоматически требования FSTEC core.

Подробно: [`docs/policy-layers.md`](../docs/policy-layers.md).

---

### Покрытие FSTEC core

Точные числа, закрытые source rows, canonical controls, parameter kinds и
CHECK-adapters формируются автоматически:
[`docs/fstec-coverage.md`](../docs/fstec-coverage.md).

Важно различать:

- число source rows;
- число controlled CLOSED rows;
- число canonical controls;
- число controls, которые уже исполнимы текущими CHECK adapters.

Одна source row может закрываться набором из нескольких controls, поэтому эти
счётчики не обязаны совпадать.

Полный source corpus остаётся в `index/source-v4/SOURCE-INDEX.tsv`; generated
coverage document не дублирует вручную все строки индекса.

---

### Архитектура

Главная карта текущего проекта:
[`docs/PROJECT-MAP-v3.md`](../docs/PROJECT-MAP-v3.md).

Она показывает:

```text
sources
  → corpus
  → source index
  → canonical controls / disposition
  → gates
  → semantic contracts
  → CHECK/APPLY registries
  → read-only CHECK adapters + SRC-0001 APPLY adapter
  → tracked generator
  → generated unified CLI
```

[`docs/ARCHITECTURE-DIAGRAMS.md`](../docs/ARCHITECTURE-DIAGRAMS.md) —
**historical donor runtime reference**, а не current project map и не future target
model. Он сохраняет проверяемую историю donor mechanics и отдельно фиксирует
границу v3: operational RESTORE исключён, post-APPLY recovery выполняется внешним
snapshot/backup-механизмом.

Индекс всей документации и её ролей:
[`docs/README.md`](../docs/README.md).

---

### Совместимость

Текущий target product CHECK задаётся самим generator и adapter contracts.
Документ совместимости разделяет три разных понятия:

- `SUPPORTED` — target, разрешённый текущим product contract;
- `TESTED` — среда, для которой имеется конкретное соответствующее evidence;
- `UNSUPPORTED` — target, который current CHECK обязан отклонить.

Подробно: [`docs/compatibility.md`](../docs/compatibility.md).

Недостаточные права чтения системного параметра не превращаются в
`NOT_FOUND`: такая ситуация классифицируется как `ERROR`, чтобы CHECK не
выдавал ложную оценку.

---

### Тестовая модель

Отслеживаемый [`tests/run-all.py`](../tests/run-all.py) — единая точка запуска всех
отслеживаемых Python regressions.

**DEV**:

- только stdlib;
- должен быть полностью зелёным;
- проверяет фактическое выполнение тестов, а не только RC=0;
- неожиданные skip и `ResourceWarning` являются ошибкой.

**RELEASE**:

- сначала требует DEV PASS;
- использует зависимости из `requirements-release.txt`;
- отсутствие обязательной зависимости даёт `BLOCKED_ENVIRONMENT`, а не
  ложный project PASS.

Подробно: [`tests/README.md`](../tests/README.md) и
[`docs/testing-strategy.md`](../docs/testing-strategy.md).

---

### Структура проекта

```text
sources/    pinned source documents и проверенные text representations
index/      source index, closure contract, disposition ledger
controls/   canonical policy controls
checker/    schema и gates
tools/      project generators и integrity helpers
product/    semantic contracts, CHECK/APPLY registries, adapters, unified generator
securelinux-policy.sh  tracked CHECK + SRC-0001 APPLY user entrypoint
dist/       optional derived rebuild output; gitignored
probes/     read-only probe infrastructure и historical/reference evidence line
tests/      DEV/RELEASE regression suites
docs/       product, engineering, donor-reference и roadmap documentation
step7b0/    historical assurance line; не current product authority
archive/    historical verification material и engineering donor
```

---

### Целостность

Корневые манифесты:

- `PROJECT-FILES.sha256` — каноническая project population;
- `SHA256SUMS` — SHA-256 файлов этой population.

Проверка:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  tools/rebuild-root-manifests.py \
  --project-root . \
  --check
```

Машинно формируемые блоки документации и coverage также проверяются отдельно:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  tools/render-current-docs.py \
  --project-root . \
  --check
```

После изменения source index, controls, closure contract или adapter registry
канонический порядок такой:

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  tools/render-current-docs.py --project-root . --write

PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -I -S -B \
  tests/run-all.py --dev
```

---

### Инженерный донор

SecureLinux-NG v16.2.11 сохранён как **engineering donor**, а не нормативный
источник. Донорская логика может попасть в v3 только через явное решение
`REUSE | ADAPT | REJECT | DEFER`.

Mapping донора сам по себе не создаёт FSTEC controls и не закрывает ни одной
строки source-index.

См. [`docs/DONOR-V3-ADOPTION-POLICY.md`](../docs/DONOR-V3-ADOPTION-POLICY.md) и
[`docs/engineering-donor.md`](../docs/engineering-donor.md).

---

### Границы текущего состояния

На текущем этапе:

- полный FSTEC corpus **не закрыт**;
- current CHECK охватывает только represented controls;
- formal Gate 5 `--probe-results` для текущей product population остаётся
  отдельным контрактным артефактом;
- `SRC-0005 / 2.3.1` закрыт exact-control-set из трёх file-mode controls;
- APPLY реализован только для `SRC-0001`; RESTORE исключён из целевой архитектуры, rollback model — external snapshot;
- historical Step 7B.0 не является current product authority;
- engineering donor не является нормативным доказательством.

Сгенерированный CHECK всегда строится из текущей `CONTROL-MANIFEST.tsv`; точная
population показана в машинно сформированном статусе корневого README. Authority refresh 2026
закрыт: `fstec-order-117-2025-requirements` учитывается вместе с изменяющим его
`fstec-order-137-2026-amendments-to-117`, при этом `SRC-0001…SRC-0040` из
`fstec-linux-2022` не переоткрывались. Для модульной архитектуры `SRC-0001` закрыты и криптографически привязаны
точные определения предиката и преобразования, условия внешнего снимка, блокировки и повторного чтения, идентичности объекта, сохранения метаданных, атомарной транзакции и сухого запуска с отчётом.
Композиция связывает все восемь ролей определений; implementation registry,
binding и adapter связывают реализацию с этой композицией. Generated CLI выполняет
сухой запуск, attested commit, локальную post-check и idempotent NOOP для `SRC-0001`.
Этап `APPLY_IMPLEMENTATION_ADAPTERS` закрыт; `FINAL_DETERMINISTIC_PACKAGING` является следующим этапом.
Оставшиеся строки `OPEN` других документов ФСТЭК сохраняются в очереди и не
расширяются до `DOCUMENT COMPLETE` текущей вертикали.
Семантика `chmod go-rwx /etc/shadow` представлена как `mode bits-clear 0077` и
не усилена до выдуманного `0600`.

---

### Источники истины

| Область | Канонический источник |
|---|---|
| population/status источников | `index/source-v4/SOURCE-INDEX.tsv` |
| framework sources | `index/source-v4/FRAMEWORK-SOURCES.tsv` |
| связи base/amendment framework authority | `index/source-v4/FRAMEWORK-AUTHORITY-RELATIONS.tsv` |
| page-pinned evidence для image-only authority | `sources/visual-v1/PROVENANCE.tsv` |
| закрытие полноты | `index/source-v4/CLOSURE-CONTRACT.tsv` |
| решения | `index/source-v4/DISPOSITION-LEDGER.tsv` |
| канонические controls | `controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv` + YAML |
| схема параметров | `checker/gates-v3/checker.py` → generated `CONTROL-SCHEMA.json` |
| mapping адаптеров CHECK | `product/ADAPTER-REGISTRY.tsv` |
| привязка APPLY-kind к модульной архитектуре | `product/APPLY-KIND-REGISTRY.tsv` |
| модульная APPLY-архитектура `SRC-0001` | `product/contracts/src0001-apply/architecture-v1.json` |
| привязка реализации APPLY | `product/APPLY-IMPLEMENTATION-REGISTRY.tsv` |
| реализация APPLY `SRC-0001` | `product/apply-adapters/product-local-account-password-state-apply-v1.py` + binding |
| текущий генератор CHECK/CLI | `product/generate-product-check-v2.py` |
| отслеживаемая пользовательская точка входа | `securelinux-policy.sh` + `.sha256` |
| макро-roadmap | `docs/ROADMAP-v3.tsv` |
| сгенерированные current docs | `tools/render-current-docs.py` |

README является входной точкой для человека, но не заменяет эти машиночитаемые
источники истины.

---

### Документация

Начинать с [`docs/README.md`](../docs/README.md): там каждый документ помечен как
`PRODUCT`, `ENGINEERING`, `DONOR-REFERENCE`, `ROADMAP` или `FUTURE/HISTORICAL`.

Пользовательская документация ведётся на русском. Имена файлов/CLI,
идентификаторы gates, enums, schema fields и machine-status strings остаются в
контрактном виде.
