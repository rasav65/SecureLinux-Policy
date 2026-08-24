# Журнал изменений

- Test harness SRC-0007 больше не требует `chown` или mapped UID/GID `1000:1000`: synthetic user-crontab остаётся владельцем текущего runner, а non-root bare-command семантика проверяется отдельным system-cron synthetic UID; production semantics не изменены.
Формат основан на Keep a Changelog. Записи фиксируют факты, а не намерения:
каждая запись обязана указывать, сколько строк source index она закрыла, и не
приписывать себе продвижение, которого не было.

Раздел `[Unreleased]` содержит проверяемые изменения, уже выполненные в
рабочем дереве, но ещё не включённые в датированную версию. Незавершённые планы
не записываются как свершившиеся факты.

## [Unreleased]

### Добавлено — read-only CHECK SRC-0007 / 2.3.3

- `SRC-0007` переводится `OPEN → CLOSED` одним aggregate control `FSTEC-LINUX-2022-2.3.3-CRON-COMMAND-PATHS-WRITE-PROTECTION`; exact source `chmod go-w` представлен как `(mode & 0022) == 0` для однозначно разрешённых target-файлов/команд из persistent cron definitions.
- Canonical population строится read-only из `/etc/crontab`, active-name entries `/etc/cron.d` и user crontabs `/var/spool/cron/crontabs`, привязанных к `/etc/passwd`; отсутствующие optional sources дают пустую соответствующую population.
- Cron parser учитывает schedule/user fields, `PATH=`, `%` stdin boundary и direct shell command segments. Bare command разрешается только для uid 0 при explicit absolute `PATH`; non-root bare command, shell expansion/substitution, redirection, non-`/bin/sh` `SHELL`, interpreter families и known launcher/wrapper forms дают `ERROR`. Interpreter/wrapper/`run-parts` classification выполняется после symlink resolution; resolved external command с `st_nlink != 1` также даёт `ERROR`, чтобы symlink/hardlink alias indirection не могла превратить partial population в PASS.
- Direct `run-parts` дополнительно раскрывает executable regular members с active Debian/Ubuntu names `[A-Za-z0-9_-]+`; source/config/PATH/target snapshots выполняются дважды и любой drift даёт `ERROR`. Non-empty crontab без final LF также считается parser/daemon ambiguity и даёт `ERROR`.
- Regression suite добавляет 25 targeted SRC-0007 fixtures, включая direct/periodic write violation, user/system jobs, PATH ambiguity, `%`, cron.d names, launcher/wrapper families, symlink-alias interpreter/wrapper/`run-parts` classification, hardlink-alias interpreter/`run-parts` fail-closed cases, versioned interpreters, `SHELL` override и line framing. APPLY/RESTORE отсутствуют.
- После шага: `349 / 38 controlled CLOSED / 311 OPEN`; canonical controls `48`; adapters `15`. Formal Gate5 probe-results не создаются.

### Исправлено — SRC-0006 robustness review

- Удалена basename-эвристика `.so`: runtime population теперь включает каждый executable file-backed mapping из `/proc/<pid>/maps`, а proc octal escaping декодируется строго; неоднозначный/deleted path даёт `ERROR`.
- Bounded observation закрывается exact PID→starttime snapshot до/после обхода и после file/parent recheck; добавление, исчезновение или reuse PID даёт `ERROR`.
- Для каждого включённого PID требуется собственная complete executable file-backed maps population; глобальный library count больше не скрывает неполное наблюдение отдельного PID.
- File и parent records повторно сверяются по resolved path, dev/inode, owner, mode и ctime перед verdict; drift даёт `ERROR`, а не stale `PASS`.
- Добавлены negative-control fixtures для non-`.so` executable mappings, proc octal escaping, malformed escapes, PID population growth, no-exe identity drift и file/parent snapshot drift. Source quote/control identity и read-only scope не меняются.
- Test fixture setup строит полный synthetic fs/proc state до снятия write bits с parent directories; это устраняет зависимость regression-тестов от прав рабочего каталога и не меняет production adapter semantics.
- No-exe identity-drift fixture теперь детерминированно выполняет actual embedded `classify_no_exe()` из adapter `_PY` с контролируемым `read_start`: неизменный starttime даёт `excluded`, изменённый — `ERROR`; FIFO/timing dependency удалена без изменения production adapter semantics.
- Re-audit hardening связывает каждый executable file-backed maps record с фактическими `dev major:minor + inode`, валидирует полную используемую грамматику `address/perms/offset/dev/inode/path` и даёт `ERROR` при identity mismatch или malformed field.
- Bounded process-lifecycle observation дополнено монотонным `/proc/stat` `processes` counter: любое создание процесса между начальным snapshot и финальным verdict, включая transient PID между дискретными PID snapshots, даёт `ERROR`.
- Для каждого включённого PID перед verdict повторно сверяются `/proc/<pid>/exe` target/object identity и exact parsed executable maps set; same-PID `exec`/`mmap` drift больше не может завершиться stale `PASS`.
- File/parent snapshot теперь включает `ctime_ns` вместе с dev/inode/uid/gid/mode, чтобы replacement с повторным использованием inode не выглядел неизменным объектом.
- Product README синхронизирован с фактическим SRC-0006 mechanism; source closure/control identity не меняются и новых source rows этот hardening не закрывает.

- Финальный parser hardening требует ASCII decimal для maps inode и `/proc/<pid>/stat` starttime; Unicode-цифры и ненумерический starttime теперь дают `ERROR`; добавлены два regression-теста.
- `/proc/<pid>/stat` parser дополнительно фиксирует полный 52-field layout: exact PID prefix, single-space field boundaries и отсутствие пустых/сдвинутых полей; missing starttime при сохранённых field 23+ теперь даёт `ERROR`; добавлен regression-тест.

### Добавлено — read-only CHECK SRC-0006 / 2.3.2

- Добавлен aggregate control `running-process-paths-write-protection`: dynamic population executable files текущих процессов берётся из `/proc/<pid>/exe`, runtime-library candidates — из `/proc/<pid>/maps`; PID identity повторно сверяется по starttime.
- Exact source `chmod go-w` представлен как file mode `bits-clear 0022`. Для containing/all-parent directories проверяется отсутствие group/other write и owner-write у non-root owner; incomplete/ambiguous observation даёт `ERROR`, partial PASS запрещён.
- Добавлены semantic contract, adapter binding/implementation и positive/negative fixtures. Donor используется только как engineering precedent; его silent skips и parent exclusions не перенесены. APPLY/RESTORE отсутствуют.
- SRC-0006 закрывается одним `atomic-single` control; current counts после шага: `37/349 CLOSED`, `47 controls`, `14 adapters`.

### Добавлено — подготовка closed parameter kind для SRC-0006 / 2.3.2

- В canonical control schema добавлен новый closed kind `running-process-paths-write-protection` с locator `/proc/<pid>/exe|/proc/<pid>/maps`, key `write-protection`, op `runtime-paths-safe` и exact expected token `file-go-w;parent-unprivileged-write-denied`.
- Это только parent-schema decision point перед экземпляром SRC-0006: source closure, canonical controls, product adapter registry и generated CLI пока не меняются; закрыто **0** source rows.
- Schema/runtime parity дополнена positive/negative cases для locator/key/op/expected и newline boundary. Existing kinds не расширены и не переопределены.
- Семантическая причина отдельного kind: 2.3.2 требует dynamic population исполняемых файлов запущенных процессов и соответствующих библиотек плюс проверку containing/all-parent directories; fixed `standard-system-paths-mode` и single-path `file-mode-owner` эту population не выражают.

### Исправлено — нейтральная терминология current review surface

- Current non-frozen code, tests и human-readable documentation переведены на neutral naming для robustness/negative-control/isolation semantics без изменения проверяемого поведения.
- Frozen Step 7B.0 exact-byte contracts/fixtures, donor-derived indexes и evidence-bound `probes/sysctl-v1/probe.py` не переименовываются in place: их идентичность остаётся доказательным фактом.
- Следующие targeted review slices не должны включать unrelated frozen/donor material; integrity root manifests подтверждается отдельным hash/check evidence, когда полный manifest не нужен decision point.
- Source closure и закрытые source rows этим cleanup не меняются.

### Добавлено — SRC-0004 / 2.2.2: reviewed sudoers policy

- `SRC-0004` переводится `OPEN → CLOSED` одним aggregate control `FSTEC-LINUX-2022-2.2.2-SUDOERS-REVIEWED-POLICY`.
- Новый read-only kind `sudoers-reviewed-policy` не выводит approved set из `%sudo`, `%wheel`, `SUDO_USER`, donor или VM defaults: локальное решение задаётся explicit reviewed authority `/etc/securelinux-policy/sudoers-reviewed-policy-v1`.
- Pinned `visudo -c -f /etc/sudoers` определяет и валидирует active include/includedir closure; exact pathset и SHA-256 bytes каждого parsed policy file должны совпасть с authority. Drift даёт `VALUE/FAIL`, authority/closure/visudo ambiguity — `ERROR`.
- 7/7 previously collected privileged VM evidence подтверждают `/etc/sudoers` regular `0440 root:root`, active `@includedir /etc/sudoers.d` и successful full `visudo` check; это evidence discovery assumptions, не normative approved policy.
- Independent targeted robustness audit SRC-0004 выявил и исправил два fail-open дефекта implementation без изменения source semantics/contract identity: authority теперь отвергает nonstructural C0/DEL control bytes, а raw stdout `visudo` проверяется через pinned `/usr/bin/od` до Bash line parsing, поэтому NUL больше не может быть silently stripped command substitution.
- Targeted SRC-0004 assurance расширен с 8 до 10 fixtures: добавлены regression для authority path с `0x01` и regression для `<path><NUL>: parsed OK`; оба требуют `ERROR`.
- После шага: `349 / 36 controlled CLOSED / 313 OPEN`; canonical controls `46`; adapters `13`. Formal Gate5 probe-results, APPLY и RESTORE не создаются.

### Исправлено — fail-closed hardening перед SRC-0004

- `file-mode-owner` и остальные current adapters вызывают pinned external tools через shell builtin `command`; slash-named functions вроде `/usr/bin/stat` и `/usr/bin/od` больше не подменяют runtime observation внутри adapter fixtures.
- Tracked unified CLI переведён на `#!/bin/bash -p`: supported executable launch не импортирует environment shell functions, поэтому экспортированная функция `command` больше не может превратить pinned external observation в ложный PASS. Plain `bash script`/`source script` не объявляются supported compliance execution.
- `pam-wheel-access`, `suid-sgid-applications`, `home-sensitive-files-mode` и `home-directories-mode` проверяют NUL до Bash line parsing через pinned `od` под тем же protected executable boundary; удаление NUL shell-ом больше не может превратить malformed input в PASS.
- PAM raw-byte prevalidation разрешает `CR` только непосредственно перед `LF`; bare CR at EOF и internal CR дают fail-closed `ERROR`, canonical CRLF остаётся допустимым.
- Generator отклоняет коллизии shell-function names после нормализации control ID и усиливает defense-in-depth scan против quote-splitting; документация больше не объявляет этот scan формальным доказательством read-only.
- Добавлены negative-control regressions для stat shadowing, NUL/internal-CR, `A-B`/`A.B` collision и `ch''mod`. Source closure не меняется: это implementation/assurance errata уже закрытых controls.

### Добавлено — SRC-0011 / 2.3.7: пользовательские cron-файлы

- Добавлен aggregate kind `user-cron-files-mode` с read-only adapter `product-user-cron-files-mode-check-v1`.
- Source-exact `chmod go-w` представлен как `bits-clear 0022`; owner/group и режимы root-каталогов не усиливаются.
- Population рекурсивно включает regular non-symlink files под optional roots `/var/spool/cron` и `/var/spool/cron/crontabs`; overlap дедуплицируется. Пустая/отсутствующая population — PASS, неоднозначность или ошибка обхода/stat — ERROR.
- Layout assumptions сверены отдельно на Ubuntu 22 FULL, Ubuntu 24 MINIMIZED/FULL, Ubuntu 26 MINIMIZED/FULL, Debian 12 SERVER и Debian 13 GNOME; эти наблюдения не расширяют current product target.

### Добавлено — SRC-0003 / 2.2.1: ограничение su через pam_wheel

- `SRC-0003` переводится `OPEN → CLOSED` одним aggregate control `FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS`.
- Новый read-only kind `pam-wheel-access` проверяет активную source-exact семантику `auth required pam_wheel.so use_uid` в `/etc/pam.d/su` и local запись `wheel` в `/etc/group`.
- `root` обязателен непосредственно в members field; placeholder `<user list>` задаётся только явной local authority `/etc/securelinux-policy/wheel-users.allowlist-v1`, без вывода из `sudo`, `admin`, `WHEEL_USERS` или `SUDO_USER`.
- GID `10` не превращён в portable compliance condition; числовой GID валидируется синтаксически, а relevant PAM/group/authority ambiguity даёт fail-closed `ERROR`.
- Семь ранее собранных privileged read-only VM evidence имеют integrity `7/7`: во всех active pam_wheel=0 и local wheel=0 при установленном module; это definitive baseline `FAIL`, но не расширение product target.
- После шага: `349 / 35 controlled CLOSED / 314 OPEN`; canonical controls `45`; adapters `12`. Formal Gate5 probe-results, APPLY и RESTORE не создаются.

### Added — SRC-0002 / 2.1.2 SSH root-login CHECK

- `SRC-0002` переводится `OPEN → CLOSED` одним aggregate control `FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN`.
- Source-exact `PermitRootLogin no` закреплён именно за main `/etc/ssh/sshd_config`; managed drop-in без main directive source row не закрывает.
- Новый read-only kind `sshd-root-login` обрабатывает active `Include`, проверяет `sshd -t` и effective root-context `sshd -T -C`; PASS требует main global `no` и effective `no`.
- Conditional Match non-`no` и parser/read ambiguity дают fail-closed `ERROR`; global duplicates adjudicated OpenSSH effective semantics, а не простым grep.
- Privileged evidence matrix 7/7 показала отрицательные default states: `without-password` на Ubuntu 22/24 и Debian 12/13, `prohibit-password` на Ubuntu 26; ни одна reference installation не имела source-exact main `no`.
- SSH test fixture создаёт fake `sshd` во временном каталоге внутри test workspace, поэтому DEV/RELEASE не зависят от системного `/tmp` с `noexec`; product/adapter semantics не меняются.
- После шага: `349 / 34 controlled CLOSED / 315 OPEN`; canonical controls `44`; adapters `11`. Formal Gate5 probe-results, APPLY/RESTORE и SSH reload/restart не создаются.

### Исправлено — SRC-0002 parser hardening после robustness review

- Исправлена OpenSSH Include-scope семантика: каждый included file наследует текущий `Match`-scope содержащего файла, но его собственные `Match` не протекают обратно.
- Tokenizer больше не обрезает `#` внутри token; поддерживает quoted/escaped arguments, CRLF и whitespace/один `=` как separator для проверяемых SSH-директив.
- Include-glob fail-closed hardened: `builtin compgen`, явный `LC_ALL=C` sort с проверяемым RC, pinned `find/readlink`, проверка newline pathnames; ошибки discovery/sort не могут превратиться в PASS.
- Неверный lexical-order oracle заменён на scope-restoration fixture; добавлены negative fixtures для `#` в имени, quoted Include, compgen shadowing, sort failure, newline pathname, quoted/CRLF `PermitRootLogin`.
- Project-integrity reverse-completeness обобщена: полный local `SHA256SUMS` определяется по принятому base HEAD и затем обязан покрывать весь текущий Git-visible subtree; scoped/historical manifests сохраняют собственную population.

### Исправлено — SRC-0002 audit hardening

- Include-glob теперь сортируется явно в лексикографическом порядке перед рекурсивным разбором; ambient shell glob order не может изменить CHECK semantics.
- Parser проверяемых SSH-директив принимает OpenSSH-разделение keyword/value пробелом или одним `=`; malformed relevant directives остаются fail-closed `ERROR`.
- В `controls/fstec-core/linux-2022/SHA256SUMS` восстановлены пять ранее потерянных действующих YAML; project-integrity теперь проверяет полноту этого local manifest в обе стороны.
- Добавлены negative fixtures для reverse Include-glob order, `=`-форм и malformed `PermitRootLogin`.

### Added — UNIFIED CLI / QUICK START v1

- Добавлен tracked user-facing `securelinux-policy.sh` с sidecar SHA-256; обычному пользователю для current CHECK больше не требуется запускать Python generator.
- Current generator — `product/generate-product-check-v2.py`; v1 сохраняется как предыдущая deterministic generator identity.
- `--check` по умолчанию выдаёт выровненную таблицу с фиксированными колонками `RESULT`, `CONTROL`, `VALUE / DETAILS`; длинные semicolon-delimited details переносятся под третьей колонкой без внешней `column`.
- Добавлены `--check --failed`, `--check --format raw`, `--check --format json`, `--report`, `--version`; `--build-info` и `--provenance` сохранены.
- Raw mode сохраняет wire-format `SLP-CHECK-V1`/`SLP-SUMMARY-V1`; JSON mode вводит `SLP-REPORT-V1`.
- `--apply` и `--restore` зарезервированы как fail-closed `NOT_IMPLEMENTED` stubs с RC=2; mutation implementation и host-state changes не добавлены.
- Расширен `tests/product-v1/test_product_generator.py`: byte-exact rebuild parity unified CLI, pretty/raw/json, sidecar/mode и fail-closed stubs без увеличения tracked test-file population.
- Source index/controls/closure не меняются: этим product-interface шагом закрыто **0** source rows; состояние остаётся `349 / 33 controlled CLOSED / 316 OPEN`, canonical controls `43`, adapters `10`.

### Added — SRC-0015 / 2.3.11 user home-directory mode CHECK

- `SRC-0015` переводится `OPEN → CLOSED` одним aggregate control `FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE`.
- Exact source command `chmod 700 домашняя_директория` представлен как строгий `mode == 0700`; `0750`, special bits и другие mode значения не считаются эквивалентными.
- Population пользователей повторно использует уже принятую для соседнего SRC-0014 трактовку той же фразы «домашним директориям пользователей»: локальный `/etc/passwd`, `root` плюс normal interactive local accounts по `UID_MIN` из `/etc/login.defs`; service-account state directories исключены.
- Отсутствующий home path не объявляется нарушением mode: 2.3.11 не требует создания home directory. Existing symlink/non-directory/stat ambiguity даёт fail-closed `ERROR`.
- Owner/group и sensitive-file modes не добавляются: первое отсутствует в 2.3.11, второе уже относится к SRC-0014.
- Семь privileged read-only VM runs подтверждают selector/layout assumptions: Debian 12 `SERVER` и Debian 13 `GNOME` имели оба selected homes `0700`; Ubuntu 22/24/26 в проверенных установках имели `/root=0700`, `/home/user=0750`. Observed modes являются evidence, а normative expected остаётся exact `0700` из source.
- После шага: `349 / 33 controlled CLOSED / 316 OPEN`; canonical controls `43`; adapters `10`. Formal Gate5 probe-results, APPLY и RESTORE не создаются.

### Added — SRC-0014 / 2.3.10 sensitive user-home files CHECK

- `SRC-0014` переводится `OPEN → CLOSED` одним aggregate control `FSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE`.
- Exact source relation `chmod go-rwx` представлено как `mode & 0077 == 0`; owner/group и mode home directory `0700` не добавляются.
- Новый read-only kind `home-sensitive-files-mode` выводит local-user home population из `/etc/passwd` + `UID_MIN`: root плюс normal interactive local accounts, без `/home`-only donor restriction.
- Два source `и т. п.` не урезаются до восьми имён: обязательный `/etc/securelinux-policy/home-sensitive-files-v1` закрепляет полный локально применимый sensitive-path inventory и обязан включать восемь exact source examples. Отсутствующий/malformed inventory и symlink/ambiguous paths дают fail-closed `ERROR`.
- Семь privileged read-only VM runs использованы как engineering evidence selector/path assumptions; observed file modes не превращаются в нормативные значения.
- Historical `checker/gates-v1` не изменяется и остаётся не-current authority: его active-corpus regression ожидает ровно один Gate1 fail-closed на canonical SRC-0014 quote, потому что legacy Gate1 не знает pinned inline page-furniture correction; current `gates-v3` Gate1 остаётся PASS.
- После шага: `349 / 32 controlled CLOSED / 317 OPEN`; canonical controls `42`; adapters `9`. Formal Gate5 probe-results, APPLY и RESTORE не создаются.

### Исправлено — source boundary SRC-0014 / 2.3.10

- В recovered `fstec-linux-2022` подтверждён внутренний page token `5` между словами `файлы` и `настройки оболочки`; соседние page tokens `3`, `4`, `6`, `7` подтверждают структуру page furniture.
- `source_skeleton_generator.py` удаляет этот token только для `SRC-0014` по exact pinned surrounding fragment; generic inline-number stripping запрещён, отсутствие или дублирование pinned fragment дают fail-closed ошибку.
- Canonical quote SHA-256 после удаления только page furniture: `c243edbafcfee7fadede64b0dec702e3f8f92553d6240a89c36575934958b5f0`.
- Добавлены positive/negative regression fixtures для inline boundary; `SRC-0014` остаётся `OPEN`, этим errata закрыто `0` source rows.

### Добавлено — SRC-0013 / 2.3.9: аудит SUID/SGID-приложений

- `SRC-0013` переводится `OPEN → CLOSED` через exact-control-set из двух controls одного read-only kind `suid-sgid-applications`.
- `SUID-SGID-MODE` охватывает всю effective SUID/SGID regular-file population по mounted filesystems без `nosuid` и требует точное source-отношение `mode & 0022 == 0` (`chmod go-w`); scan/stat/mountinfo ambiguity даёт fail-closed `ERROR`.
- `SUID-SGID-ALLOWLIST` представляет отдельное требование об отсутствии «лишних» приложений как `population ⊆ approved set`. Источник не задаёт универсального критерия «лишний», поэтому current CHECK читает только явный локальный authority `/etc/securelinux-policy/suid-sgid.allowlist-v1`; его отсутствие/нечитаемость/неоднозначность даёт `ERROR`, а не ложный `PASS`.
- Donor condition `SUID owner != root` не переносится: источник подчёркивает повышенный риск root-owned SUID, но не требует универсального `owner=root`.
- VM evidence v2 собрано одним batch на Ubuntu 22 `FULL`, Ubuntu 24 `MINIMIZED/FULL`, Ubuntu 26 `MINIMIZED/FULL`, Debian 12 `SERVER`, Debian 13 `GNOME`. Во всех семи runs `GO_W=0`, scan errors `0`; число effective SUID/SGID regular files различается по составу установки.
- После batch: `349 / 31 controlled CLOSED / 318 OPEN`; canonical controls `41`; current adapters `8`. CHECK остаётся read-only; APPLY/RESTORE и formal Gate5 probe-results не создаются.

### Добавлено — SRC-0012 / 2.3.8: проверка стандартных системных путей

- `SRC-0012` переводится `OPEN → CLOSED` одним aggregate control `standard-system-paths-mode`.
- Canonical population охватывает `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64` и `/lib/modules/<текущее-ядро>` с поддержкой merged-`/usr` aliases и дедупликацией underlying targets.
- Для executable roots проверяются regular targets всех non-directory entries; для библиотек — `*.so`, `*.so.*`, `*.a`; для модулей ядра — `*.ko`, `*.ko.*`.
- Источник 2.3.8 не задаёт числовой mode; минимальный operational criterion `mode & 0022 == 0` зафиксирован как инженерная интерпретация, согласованная с pinned donor и соседними 2.3.2/2.3.9. Более строгие owner/group/mode требования не добавлены.
- Parent-directory condition из donor не переносится: оно явно содержится в 2.3.2, но отсутствует в 2.3.8. Traversal/stat/readlink ambiguity даёт fail-closed `ERROR`.
- VM layout evidence собрано отдельно для Ubuntu 22 `FULL`, Ubuntu 24 `MINIMIZED/FULL`, Ubuntu 26 `MINIMIZED/FULL`, Debian 12 `SERVER` и Debian 13 `GNOME`; это evidence assumptions, а не расширение `SUPPORTED` target.
- После batch: `349 / 30 controlled CLOSED / 319 OPEN`; canonical controls `39`; current adapters `7`. CHECK остаётся read-only; APPLY/RESTORE и formal Gate5 probe-results не создаются.

### Изменено — русский язык актуальной v3-документации

- Человекочитаемый текст действующего контура `checker/gates-v3`, контракта значений наблюдений и соответствующего README тестов переведён на русский язык.
- Технические идентификаторы, имена полей, wire/protocol-маркеры и значения схем сохранены без перевода.
- Добавлена regression-проверка, запрещающая возврат прежних английских абзацев в этом актуальном v3-контуре.
- Исторические v1/v2 и pinned donor/evidence артефакты этим изменением не переписываются.

### Added — SRC-0026 / 2.5.3 debugfs kernel-cmdline CHECK

- Закрыт `SRC-0026 / 2.5.3`: `debugfs=no-mount (по возможности off)` представлен одним `kernel-cmdline` control с `op=one-of` и ordered value `off|no-mount`; `off` сохраняется как preferred, оба source-разрешённых значения дают PASS.
- `kernel-cmdline` product adapter/semantic contract подняты до v2: `eq`/`present` совместимы с v1, добавлен read-only `one-of`, конфликтующие дубли остаются `ERROR`, APPLY/RESTORE не добавлены.

### Added — SRC-0034 / 2.5.11 ASLR sysctl CHECK

- `SRC-0034` переводится `OPEN → CLOSED` одним существующим `sysctl` control.
- Source-exact requirement `kernel.randomize_va_space = 2` представлено без расширения semantics как `sysctl / eq / integer 2`.
- Новый adapter/contract не создаётся; используется current `product-sysctl-check-v2`.
- После batch: `349 / 27 controlled CLOSED / 322 OPEN`; canonical controls `36`; current adapters `5`.
- CHECK остаётся read-only; APPLY/RESTORE и formal Gate5 probe-results не создаются.

### Added — SRC-0001 / 2.1.1 local account password-state CHECK

- `SRC-0001` переводится `OPEN → CLOSED` одним aggregate control.
- Новый kind `local-account-password-state` использует локальную population `/etc/passwd` и source-anchored state `/etc/shadow`.
- Для каждого локального пользователя matching shadow password field должен быть непустым; empty field → `VALUE/FAIL`.
- Missing/unreadable/symlink/malformed/duplicate account-state mapping → fail-closed `ERROR`; partial PASS запрещён.
- Adapter read-only: никаких `passwd`/`usermod`/`chpasswd`/APPLY/RESTORE.
- После batch: `349 / 26 controlled CLOSED / 323 OPEN`; canonical controls `35`; current adapters `5`.

### Fixed — SRC-0001 source quote boundary

- `source_skeleton_generator.py` получил одну exact pinned exception для `SRC-0001`: trailing page token `3` после `/etc/shadow.` удаляется как page furniture только для этой строки.
- Generic удаление bare integers по-прежнему запрещено; `SRC-0133` остаётся fail-closed `REFUSED`.
- Canonical quote SHA-256 для `SRC-0001 / 2.1.1` после удаления page furniture: `799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b`.
- `tests/source-skeleton-v1/TEST-RESULTS.txt` синхронизирован с current regression (`pilot=34`, `exact=73`, `refused=1`).
- Coverage не меняется: `349 / 25 controlled CLOSED / 324 OPEN`, controls `34`.

### Added — SRC-0010 / 2.3.6 system cron file-set CHECK

- `SRC-0010` переводится `OPEN → CLOSED` через exact-control-set из шести source-listed roots.
- Новый kind `optional-file-root-files-mode` выражает только `bits-clear 0033` (`chmod go-wx`): regular-file root проверяется сам; directory root — сам + direct regular files.
- Отсутствие source-listed root допускается источником и даёт `VALUE/PASS`; nested directory, symlink, special entry, stat/traversal error дают fail-closed `ERROR`.
- Pinned donor использован только как engineering precedent для cron targets/stat; его более строгие `600/700 root:root` не являются requirement v3.
- После batch: `349 / 25 controlled CLOSED / 324 OPEN`; canonical controls: `34`; current adapters: `4`.
- APPLY/RESTORE и formal Gate5 probe-results не создаются.

### Текущее незавершённое состояние

- После SRC-0010 / file-set batch остаются `324` `OPEN` source rows; текущий
  product checkpoint — систематическое FSTEC expansion по machine source truth.
- Formal `Gate 5 --probe-results` для current product population остаётся
  отдельным контрактным артефактом.
- Step 7B.0 остаётся historical assurance line: Phase C item 19 — `REVISE`;
  authoritative builder не признан, публикация не выполнялась.
- Build Contract v0.9.6 существует только как черновик и не является current
  product authority.

### Известные незакрытые замечания

- `eq`-controls продолжают следовать буквальному равенству источника и могут
  дать `FAIL` на более строгом состоянии системы. На CHECK-8 это наблюдалось
  для `kernel.unprivileged_bpf_disabled=2` при expected `1` и
  `kernel.perf_event_paranoid=4` при expected `3`. Оператор `ge` добавлен
  только для source clauses, которые сами задают нижнюю границу; существующие
  `eq` controls задним числом не меняются.
- Устаревшее примечание `Gate-1 quote blocked ...` осталось в строках индекса,
  для которых восстановленный текстовый источник уже указан.
- Две historical observer fixtures из frozen Step 7B.0 Phase A не входят в current Phase-A набор и под действующей
  политикой дают несоответствия. Они не помечены как superseded.

## [0.0.20] — 2026-08-21

### Added — read-only kernel command-line CHECK

- Добавлен новый current parameter kind `kernel-cmdline` для фактической
  загрузочной строки `/proc/cmdline`.
- Semantic contract `kernel-cmdline-check-semantic-v1` поддерживает:
  - `eq` — exact `key=value` token;
  - `present` — exact bare token.
- Adapter `product-kernel-cmdline-check-v1` только читает `/proc/cmdline`.
  GRUB, загрузчик, APPLY и RESTORE не изменяются.
- Отсутствие требуемого boot token — наблюдаемое `VALUE/FAIL`, а не
  `NOT_FOUND`; конфликтующие значения одного key дают `ERROR`.

### Added — exact boot-token batch

- `SRC-0018 / 2.4.3` → `init_on_alloc=1`.
- `SRC-0019 / 2.4.4` → bare flag `slab_nomerge`.
- `SRC-0020 / 2.4.5` → exact-control-set:
  `iommu=force`, `iommu.strict=1`, `iommu.passthrough=0`.
- `SRC-0021 / 2.4.6` → `randomize_kstack_offset=1`.
- `SRC-0022 / 2.4.7` → `mitigations=auto,nosmt` для current x86_64 target.
- `SRC-0024 / 2.5.1` → `vsyscall=none`.
- `SRC-0032 / 2.5.9` → `tsx=off`.
- Corpus после batch: `349 / 24 controlled CLOSED / 325 OPEN`;
  canonical controls: `28`.

### Donor review

- Pinned SecureLinux-NG v16.2.11 использован только как engineering precedent:
  его `grub_kernel_params_check_module` уже читает `/proc/cmdline`, выполняет
  whitespace tokenization и проверяет exact tokens.
- v3 не копирует GRUB remediation и усиливает observation semantics для
  конфликтующих duplicate key values.
- `SRC-0026 / 2.5.3` намеренно остаётся `OPEN`: формулировка
  `debugfs=no-mount (по возможности off)` требует отдельной semantics
  альтернатив/предпочтения и не подменяется одним exact token.
- `SRC-0034 / 2.5.11` остаётся `OPEN` из-за procedural qualifier
  `после тестирования`.

### Tested

- Schema/runtime parity включает positive/negative `kernel-cmdline` cases.
- Product generator registry содержит 3 current adapters и 28 controls.
- Kernel-cmdline adapter selftest покрывает exact match, absence, duplicate
  identical/conflicting values и bare-vs-keyed ambiguity.
- Устранены два stale regression pin после добавления нового adapter/kind:
  `test_audit_fixes.py` теперь сверяет schema enum с current `KIND_RULES`, а
  `test_sysctl_adapter.py` проверяет уникальность и SHA bindings registry без
  фиксации исторического глобального числа adapter rows.
- Нормализован EOF двух обновлённых test README до одного завершающего LF;
  installer v2 корректно откатился на `git diff --check` из-за лишней пустой
  строки в конце файлов.
- Source-block production parity и source-skeleton verify: `28/28`.
- Gate 1/3/4 должны пройти на 28 controls; Gate 2 ожидаемо остаётся FAIL из-за
  325 OPEN; formal Gate 5 без `probe-results` остаётся fail-closed.
- DEV/RELEASE/root manifests проверяются installer после real-tree rebuild.
- Закрыто строк source index этим шагом: **7**.

## [0.0.19] — 2026-08-20

### Added — source-faithful sysctl lower bound / SRC-0033

- Добавлен current read-only `product-sysctl-check-v2` и semantic contract v2:
  `eq` сохраняет exact integer semantics; новый `ge` реализует математическое
  сравнение signed base10 без зависимости от machine-word width.
- `SRC-0033 / 2.5.10` переведён `OPEN → CLOSED` через
  `FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR`:
  `vm.mmap_min_addr ge 4096`.
- Source quote SHA-256: `5b55fd931f99da5241c6bc05e33c7131ff091a282547b95f0699b17f515a6729`; фраза `4096 или больше` не подменяется
  `eq 4096`.
- Старый engineering donor используется только как corroborating implementation
  precedent: в SecureLinux-NG `vm.mmap_min_addr` уже сравнивался как
  `actual >= expected`; нормативным основанием остаётся pinned FSTEC source.

### Changed — generated coverage

- `docs/fstec-coverage.md` теперь содержит генерируемую таблицу по каждому
  `source_id`: total / controlled CLOSED / disposed CLOSED / OPEN /
  canonical controls.
- Таблица устраняет двусмысленность общего знаменателя 349, не утверждая, что
  каждая `OPEN` строка обязана стать host CHECK.
- Текущий corpus: `349 / 17 controlled CLOSED / 332 OPEN`; controls: `19`.

### Fixed — current documentation / regressions

- `product/README.md` больше не описывает уже завершённый SRC-0040 как следующий
  шаг и фиксирует current sysctl adapter v2.
- Source-skeleton/source-parity/roadmap docs больше не пинят исторические
  `18/18` или `8/8`; population выводится из current manifests.
- Schema/runtime parity добавляет positive `sysctl ge integer` и negative
  `sysctl ge string` cases.
- Product adapter regression покрывает equal/greater/less, отрицательные и
  200-digit lower-bound cases.

### Tested

- Source-skeleton verify: `19/19`.
- Production source-block regeneration parity: `19/19`.
- Schema/runtime differential parity: PASS; real jsonschema остаётся
  обязательным RELEASE gate.
- Product sysctl adapter v2 и generator regressions: PASS.
- Gate 1/3/4 должны пройти на 19 controls; Gate 2 ожидаемо остаётся FAIL из-за
  332 OPEN; formal Gate 5 без `probe-results` остаётся fail-closed.
- Закрыто строк source index этим шагом: **1**.

## [0.0.18] — 2026-08-20

### Fixed — terminal source boundary / SRC-0040

- `fstec-linux-2022` source-skeleton удаляет точный terminal token
  `________________________` только как exact EOF page furniture после `2.6.6`.
- `SRC-0040 / 2.6.6` переведён `OPEN → CLOSED`; canonical quote имеет SHA-256
  `f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d`.

### Added — SRC-0040 / CHECK-18

- Добавлен `FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE`:
  `sysctl / fs.suid_dumpable / eq / 0`.
- Используется существующий read-only sysctl adapter без расширения semantic contract.
- Corpus: `349 / 16 controlled CLOSED / 333 OPEN`; controls: `18`.

### Fixed — regression semantics

- Project-integrity больше не пинует исторические числа `17 / 15 / 334`.
- `product/SHA256SUMS` получил обратную проверку полноты.
- Local-manifest target population согласована с root-manifest policy:
  tracked + nonignored untracked, чтобы новый control проверялся до commit.
- Source-parity fixture report сохраняет фактическое `positive=5`; production
  parity проверяется отдельно `18/18`.

### Tested

- Source-skeleton verify: `18/18`.
- Production source-block regeneration parity: `18/18`; fixture harness `positive=5`.
- Gate 1/3/4 PASS; Gate 2 ожидаемо FAIL из-за 333 OPEN; Gate 5 остаётся fail-closed.
- Project-integrity, DEV 21/21, RELEASE и root manifests PASS.
- CHECK-18 выполняется read-only; formal Gate5 probe-results не создаются.
- Закрыто строк source index этим шагом: **1**.

## [0.0.17] — 2026-08-20

### Fixed — local SHA256SUMS / ACTIVE checker evidence errata

- Исправлен stale SHA `product/README.md` в `product/SHA256SUMS`; product bytes
  и source/canonical semantics этим исправлением не меняются.
- `ACTIVE-CHECKER-V3-NO-VM.txt` и
  `checker/gates-v3/ACTIVE-NO-VM-EVIDENCE.txt` перестраиваются из фактического
  current checker run и больше не содержат историческое состояние 5/344.
- `tests/project-integrity-v1/test_root_manifests.py` расширен с
  `tests/**/SHA256SUMS` на repository-wide current nested manifests; ровно две
  historical donor runtime entries разрешены только как pinned exceptions с
  точными manifest/path/SHA; отдельно требуется byte-exact freshness обоих
  gates-v3 `ACTIVE` snapshots.
- Corpus остаётся `349 / 15 controlled CLOSED / 334 OPEN`; canonical controls:
  `17`; закрыто строк source index этим шагом: **0**.

### Tested

- До mutation repository-wide local-manifest scan обязан находить ровно известный
  stale `product/SHA256SUMS -> README.md`, иначе шаг fail-closed останавливается.
- После исправления current local-manifest scan: 0 ошибок; historical donor
  exception population: ровно 2 pinned entries.
- Оба `ACTIVE` snapshots побайтово равны свежему gates-v3 checker stdout для
  текущего состояния 17/15/334.
- DEV baseline: 21/21 PASS; RELEASE baseline: PASS.
- Root manifests: 742/743 PASS; Gate 2 и Gate 5 остаются ожидаемо FAIL по
  текущим контрактным причинам.

## [0.0.16] — 2026-08-20

### Added — sysctl exact-eq expansion batch / CHECK-17

- Шесть source rows представлены существующим read-only `sysctl eq` adapter без
  расширения semantic contract:
  - `SRC-0030 / 2.5.7` → `vm.unprivileged_userfaultfd = 0`;
  - `SRC-0031 / 2.5.8` → `dev.tty.ldisc_autoload = 0`;
  - `SRC-0036 / 2.6.2` → `fs.protected_symlinks = 1`;
  - `SRC-0037 / 2.6.3` → `fs.protected_hardlinks = 1`;
  - `SRC-0038 / 2.6.4` → `fs.protected_fifos = 2`;
  - `SRC-0039 / 2.6.5` → `fs.protected_regular = 2`.
- `SRC-0034 / 2.5.11` намеренно оставлен `OPEN`: фраза `после тестирования`
  задаёт процедурное условие, которое один read-only runtime-value control не
  доказывает.
- `SRC-0033 / 2.5.10` остаётся `OPEN`: source требует `4096 или больше`, поэтому
  существующий `eq` adapter не подменяет отношение `>=` равенством.
- `SRC-0040 / 2.6.6` остаётся `OPEN`: текущий source-skeleton захватывает
  разделительную строку после последнего numbered-position; сначала требуется
  исправить границу извлечения, а не закреплять page furniture как quote.

### Changed

- Corpus state: `349 / 15 controlled CLOSED / 334 OPEN`; canonical controls: `17`.
- Generated README/map/coverage перестроены из machine truth.
- PRIMARY map сохраняет текущую точку `systematic FSTEC expansion`, но отдельно
  фиксирует завершённый exact-eq batch и CHECK-17 как уже пройденный checkpoint.
- `docs/ROADMAP-v3.md` и TSV больше не закрепляют имя будущего артефакта
  `securelinux-ng.sh`; будущие steps 9–11 явно относятся к APPLY/RESTORE и
  финальной упаковке, а не к уже существующим CHECK adapters/generator.
- Документы source-skeleton/source-parity больше не содержат быстро устаревающие
  ручные значения corpus progress; current population определяется из manifests.

### Tested

- Gate 1/3/4 проходят на 17 controls; Gate 2 ожидаемо `FAIL` только из-за 334
  оставшихся `OPEN`; formal Gate 5 без `--probe-results` остаётся fail-closed.
- Source-block regeneration parity: `controls=17 supported=17 matched=17`.
- Source skeleton pilot verification: `controls=17 mismatches=0`.
- Product generator regression закрепляет exact semantics всех шести controls
  этого batch и сохраняет запрет на mutating shell tokens.
- CHECK-17 выполняется read-only; host-specific вывод сохраняется как derived
  evidence и не создаёт formal Gate 5 `probe-results`.
- Закрыто строк source index этим шагом: **6**.

## [0.0.15] — 2026-08-20

### Fixed — TEST SHA256SUMS cache contamination errata

- Удалены четыре ошибочные `__pycache__/*.pyc` записи из tracked test-local
  `SHA256SUMS`; сами cache-файлы не являются tracked project bytes.
- `tests/project-integrity-v1/test_root_manifests.py` теперь fail-closed
  проверяет все tracked `tests/**/SHA256SUMS`: target должен существовать,
  быть tracked regular file, не находиться в `__pycache__` и иметь совпадающий
  SHA-256.
- Product/corpus semantics не изменены: 11 canonical controls, 9 controlled
  CLOSED source rows, 340 OPEN; CHECK-11 evidence остаётся неизменным.
- Закрыто строк source index: **0**.

## [0.0.14] — 2026-08-20

### Added — SRC-0005 / CHECK-11

- `SRC-0005 / 2.3.1` представлен `exact-control-set` из трёх canonical controls:
  - `FSTEC-LINUX-2022-2.3.1-PASSWD-MODE` → `/etc/passwd`, `mode eq 0644`;
  - `FSTEC-LINUX-2022-2.3.1-GROUP-MODE` → `/etc/group`, `mode eq 0644`;
  - `FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX` → `/etc/shadow`, `mode bits-clear 0077`.
- Все три controls используют существующий read-only
  `product-file-mode-owner-check-v1`; новый adapter не создавался.
- `chmod go-rwx /etc/shadow` намеренно не усилен до неследующего из source anchor
  равенства `/etc/shadow = 0600`.

### Changed

- `SRC-0005` переведён `OPEN → CLOSED`; прогресс корпуса теперь `349 / 9 / 340`.
- `CONTROL-MANIFEST.tsv` содержит 11 canonical controls; closure contract содержит
  9 controlled source rows.
- Generated README/map/coverage перестроены из machine truth; CHECK-11 завершает
  этот точечный expansion step, после чего current checkpoint — systematic FSTEC expansion.

### Tested

- Gate 1/3/4 проходят на 11 controls; Gate 2 остаётся ожидаемо красным только из-за
  340 оставшихся `OPEN`; formal Gate 5 без `--probe-results` остаётся fail-closed.
- Source-block regeneration parity: `controls=11 supported=11 matched=11`.
- Source skeleton pilot verification: `controls=11 mismatches=0`.
- Product generator regression больше не пинует историческое число 8 и отдельно
  проверяет exact SRC-0005 file-mode semantics.
- Historical gates-v1 regression теперь явно требует fail-closed на новом
  `file-mode-owner/bits-clear`, вместо ложного требования принять current v3 corpus.
- CHECK-11 выполняется read-only на target host; host-specific summary сохраняется
  только как derived evidence и не подменяет formal Gate 5 `probe-results`.
- Закрыто строк source index этим шагом: **1**.

## [0.0.13] — 2026-08-20

### Fixed — DOCUMENTATION BASELINE ERRATA

- Исправлена PRIMARY `docs/PROJECT-MAP-v3.md`: раздел «Где мы находимся»
  теперь показывает текущий product checkpoint `SRC-0005 / 2.3.1`, а уже
  реализованные read-only adapters, tracked generator и CHECK-8 находятся до
  current node, не в future.
- Следующий checkpoint на карте — `CHECK-11`; systematic FSTEC expansion и
  будущие APPLY/RESTORE этапы идут после него.
- Убрано утверждение, что конечный артефакт v3 уже обязан называться
  `securelinux-ng.sh`; имя будущего distributable artifact пока не закреплено.
- В macro-roadmap явно разъяснено, что будущие roadmap steps 8–11 относятся к
  APPLY/RESTORE/final packaging и не описывают уже существующую CHECK line.
- Semantic часть current FSTEC controls больше не помечена на PRIMARY map как
  future.
- Закрыто строк source index: **0**.

### Tested

- Roadmap regression проверяет порядок
  `CHECK-8 → TEST BASELINE → DOCUMENTATION BASELINE → SRC-0005 → CHECK-11`.
- Current-status regression требует, чтобы на этом checkpoint `SRC-0005`
  оставался `OPEN`, ещё не имел canonical controls, при этом
  `file-mode-owner` adapter и tracked generator уже существовали.
- Documentation regression запрещает прежний current-node Step 7B и future
  labels для уже реализованных CHECK adapters/generator.

## [0.0.12] — 2026-08-20

### Added — TEST BASELINE

- Добавлен tracked `tests/run-all.py` как canonical точка запуска tracked
  Python regressions.
- Test population разделена на DEV и RELEASE; release dependency объявлена в
  `requirements-release.txt` как `jsonschema>=4.10.3`.
- Добавлен `tests/run-all-selftest.py`, проверяющий runner RC `0/1/2/3`.
- Runner требует доказательство фактического выполнения test-file, запрещает
  неожиданные skip, `ResourceWarning` и untracked `test_*.py`.

### Fixed — TEST BASELINE

- Удалены historical numeric pins на `controls=5` и `74/72`; ожидаемые
  populations берутся из current machine truth.
- Четыре roadmap regressions больше не пинуют exact русские status-фразы и
  число Mermaid blocks.
- Устранены четыре `ResourceWarning` в file-mode-owner regression.
- `PROJECT-MAP-v3.md` синхронизирован с current product CHECK line.
- Закрыто строк source index: **0**.

### Added — DOCUMENTATION BASELINE

- Добавлен `docs/README.md`, который классифицирует документы как PRODUCT,
  ENGINEERING, ROADMAP и DONOR-REFERENCE.
- `docs/PROJECT-MAP-v3.md` закреплён как единственная PRIMARY current project
  map; `ARCHITECTURE-DIAGRAMS.md` остаётся donor/future runtime reference.
- Добавлены `docs/policy-layers.md` и явный инвариант
  `FSTEC core ≠ recommended ≠ corporate standard ≠ firewall`.
- Добавлен `docs/compatibility.md` с раздельными статусами SUPPORTED / TESTED /
  UNSUPPORTED.
- Добавлен stdlib-only `tools/render-current-docs.py`. Он формирует
  machine-owned current-status blocks README/PROJECT-MAP и generated
  `docs/fstec-coverage.md` из source index, closure contract, control manifest
  и adapter registry.
- Добавлен focused regression `tests/documentation-v1/`, требующий exact
  documentation parity и полноту docs index.

### Changed — DOCUMENTATION BASELINE

- Root README перестроен в product-facing форму: назначение, generated current
  status, quick start, гарантии с проверками, policy layers, coverage,
  compatibility, architecture, test model, integrity, boundaries и docs index.
- Current numeric coverage удалён из вручную поддерживаемых Mermaid nodes;
  текущие числа находятся только в machine-owned blocks/generated coverage.
- `product/README.md`, controls README, `tests/README.md` и
  `docs/testing-strategy.md` актуализированы под current product/test model.
- Закрыто строк source index: **0**.

### Tested

- TEST BASELINE A1 на development host: DEV `20/20 PASS`, RELEASE `PASS`;
  release interpreter использовал `jsonschema 4.10.3`.
- A1 local CHECK-8 diagnostic воспроизвёл ровно один execution `ERROR`:
  `FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN`,
  `/proc/sys/net/core/bpf_jit_harden`, mode `0600`, read `EACCES`/errno 13.
  Это host evaluability observation, не defect canonical control и не
  compatibility evidence.
- Documentation renderer проходит `--write → --check`; documentation regression
  проверяет exact parity и отсутствие известных stale product-status strings.
- Documentation Baseline добавляет один DEV test-file; успешный commit требует
  полного current DEV PASS и RELEASE PASS.

### Docs

- README является human entry point, но machine-readable registries остаются
  источниками истины для counts/status.
- `fstec-coverage.md` не редактируется вручную и после расширения controls
  должен регенерироваться до DEV run.
- `compatibility.md` не повышает один локальный запуск до общего `TESTED`;
  TESTED требует конкретного evidence exact product population/target.

## [0.0.11] — 2026-08-20

### Добавлено — product-line Step 3

- Создан tracked deterministic generator
  `product/generate-product-check-v1.py`.
- Generator читает `CONTROL-MANIFEST.tsv` и единственный
  `product/ADAPTER-REGISTRY.tsv`, проверяет SHA semantic contract, binding и
  implementation и fail-closed выбирает adapter по `parameter.kind`.
- `dist/` добавлен в `.gitignore`: generated CHECK является derived output и
  не входит в tracked tree/root manifests.
- Добавлен `tests/product-v1/test_product_generator.py`.

### Проверено — CHECK-8 regression

- `product-v1`: 40 тестов, итог `OK`.
- Generator SHA-256: `cc75c216e685c792e5dd14a1b056e9f8f6602f772bc8622f04be95bc88d501d3`.
- Adapter registry SHA-256: `e1fabfad1cd66770783b4096f7cdaebe562b5861e43d71e9f9bc55df0dcbbc2f`.
- Generated CHECK SHA-256: `cc58acae18a79b92c7d4b234dc0505bb065a42209392d7c7541e21ea328511d5`.
- Deterministic rebuild дал те же bytes; sidecar SHA совпал; `bash -n`,
  `--help`, `--build-info`, `--provenance` для восьми controls и usage-RC
  прошли.
- Реальный read-only запуск на target-хосте: `SLP-SUMMARY-V1	TOTAL=8	PASS=2	FAIL=5	NOT_FOUND=0	ERROR=1	POLICY_STATUS=UNEVALUATED`, RC=1.
  Policy result описывает состояние хоста и не является ошибкой generator.
- Неструктурированный stderr отсутствовал; P-01 не воспроизвёлся.
- Снимки наблюдаемых sysctl до/после совпали; CHECK host state не изменил.
- Historical `step7b0/`, controls, source index и checker не изменялись.
- Post-Step3 gates сохраняют ожидаемое состояние: `GATE0 PASS`,
  `GATE1 PASS checked=8`, `GATE3 PASS`, `GATE4 PASS`; `GATE2 FAIL` из-за
  341 `OPEN`, `GATE5 FAIL` из-за отсутствующего formal `probe-results`.
- Закрыто строк source index: **0**.

## [0.0.10] — 2026-08-20

### Добавлено — product-line Step 2

- Создан отдельный product semantic contract
  `product/contracts/sysctl-check-semantic-v1.json`.
- Создан read-only sysctl adapter
  `product/adapters/product-sysctl-check-v1.py` с собственной identity
  `product-sysctl-check-v1` и отдельным JSON binding.
- Создан `product/ADAPTER-REGISTRY.tsv` — единственный tracked mapping для
  `file-mode-owner` и `sysctl`, связывающий parameter kind, adapter identity,
  semantic contract, binding, implementation и их SHA-256.
- Добавлен `tests/product-v1/test_sysctl_adapter.py`.

### Исправлено

- P-01 закрыт в текущей product-line: ошибка чтения sysctl теперь даёт
  структурированный `ERROR` без неструктурированного stderr bash.
- Historical `step7b0/phase-a` и внешний диагностический CHECK-8 не изменялись.

### Проверено

- `product-v1`: 30 тестов, итог `OK`.
- Sysctl adapter self-test: `PASS`.
- Корневые манифесты после Step 2:
  `PROJECT_FILES_ENTRIES=719`, `SHA256SUMS_ENTRIES=720`, `--check=PASS`.
- Post-Step2 gates: `GATE0 PASS`, `GATE1 PASS checked=8`,
  `GATE3 PASS`, `GATE4 PASS`; `GATE2 FAIL` ожидаемо из-за 341 `OPEN`,
  `GATE5 FAIL` ожидаемо из-за отсутствующего formal `probe-results`.
- Controls, source index, checker и historical Step 7B.0 не изменялись.
- Tracked product generator и canonical controls `SRC-0005` ещё не созданы.
- Закрыто строк source index: **0**.

## [0.0.9] — 2026-08-20

### Добавлено — product-line Step 1

- Создан отдельный semantic contract
  `product/contracts/file-mode-owner-check-semantic-v1.json`.
- Создан отдельный read-only adapter
  `product/adapters/product-file-mode-owner-check-v1.py` с собственной
  identity `product-file-mode-owner-check-v1` и JSON binding.
- Adapter поддерживает только `key=mode`, `op=eq|bits-clear`; поля
  `owner`, `group`, `owner_group` fail-closed отклоняются.
- Добавлены `tests/product-v1`: 19 тестов, итог `OK`, без пропусков.
- Отдельная negative-control проба механизма перед фиксацией контракта:
  25/25 `PASS`, запуск от обычного пользователя, без mutation.
- Добавлены каталожные `product/SHA256SUMS` и `tests/product-v1/SHA256SUMS`.

### Проверено

- Корневые манифесты после Step 1: `PROJECT_FILES_ENTRIES=714`,
  `SHA256SUMS_ENTRIES=715`, `--check=PASS`.
- Post-Step1 gates: `GATE0 PASS`, `GATE1 PASS checked=8`,
  `GATE3 PASS`, `GATE4 PASS`; `GATE2 FAIL` ожидаемо из-за 341 `OPEN`,
  `GATE5 FAIL` ожидаемо из-за отсутствующего formal `probe-results`.
- Historical `step7b0/`, controls, source index и checker не изменялись.
- Product sysctl adapter, `ADAPTER-REGISTRY.tsv`, tracked generator и
  canonical controls `SRC-0005` этим шагом не создавались.
- Закрыто строк source index: **0**.

## [0.0.8] — 2026-08-19

### Документация — нормализация `[Unreleased]`

- Исправлена структура CHANGELOG: из `[Unreleased]` перенесены уже завершённые
  проверяемые факты Step 7B.0; наверху оставлены только реально незавершённые
  состояния и открытые замечания.
- Зафиксирована ранее завершённая последовательность Build Contract
  v0.9.2 → v0.9.3 R4-FINAL → v0.9.4 → v0.9.5; принятой остаётся
  `step7b0/BUILD-CONTRACT-v0.9.5.md`.
- Зафиксировано ранее завершённое состояние Phase A под v0.9.5:
  16 статических предусловий, SHA-bound member/admission; Item 9 закрыт
  fail-closed observer policy.
- Зафиксирован ранее выполненный Phase-B measurement: прежний
  `(futex, null)` разрешён только как exact `FUTEX_WAKE_PRIVATE` с
  `thread_synchronization_local`; shared/wait/альтернативные формы не получили
  безусловного допуска.
- Зафиксирована ранее выполненная Cross-VM диагностика: при изменении ядра,
  CPU flags и AUXV три выходных файла builder'а остались побайтово идентичными;
  это design evidence, а не acceptance Phase C.
- Никакие historical Step7B0 bytes, controls, source index, checker semantics,
  probes или runtime не изменены. Закрыто строк source index: **0**.

## [0.0.7] — 2026-08-19

### Проверено — отдельный product CHECK-8

- Собран отдельный read-only product/corpus CHECK для всех восьми текущих
  sysctl-controls со статусом `NON_RELEASE_DIAGNOSTIC_CANDIDATE`.
- Он явно фиксирует
  `STEP7B0_BUILD_CONTRACT_IDENTITY_USED=false`,
  `PHASE_B_C_IDENTITY_USED=false`, `AUTHORITATIVE=false`,
  `RELEASE=false`, `MUTATION_CAPABILITY=false`.
- На Ubuntu 24.04.4 VM непривилегированный запуск дал
  `TOTAL=8 PASS=1 FAIL=6 ERROR=1 POLICY_STATUS=UNEVALUATED`; запуск через
  `sudo` — `TOTAL=8 PASS=1 FAIL=7 ERROR=0 POLICY_STATUS=NONCOMPLIANT`.
  Семь `FAIL` описывают состояние VM, а не ошибку CHECK.
- Снимки восьми sysctl до и после запусков побайтово совпали; CHECK не изменил
  host state. Raw evidence сохранено отдельно, но формальный Gate 5
  `probe-results` для восьми controls ещё не создан.

### Изменено — closed schema `file-mode-owner`

- Для `key=mode` добавлен `op=bits-clear`; существующий `op=eq` сохранён.
- `bits-clear` разрешён только для `key=mode`, `type=string`, ненулевой
  четырёхзначной octal-маски. `"0000"`, короткие/non-octal маски и
  `owner|group|owner_group + bits-clear` fail-closed отклоняются.
- Relation-правило находится в едином `KIND_RULES`; из него согласованно
  выводятся runtime validation и `CONTROL-SCHEMA.json`.
- Минимальный schema-emulator дополнен keyword `not`; 12 parity-tests прошли,
  включая согласие runtime, emulator и реального `Draft202012Validator`.
- После изменения: `GATE0 PASS`, `GATE1 PASS checked=8`, `GATE3 PASS`,
  `GATE4 PASS`; `GATE2 FAIL` остаётся из-за 341 `OPEN`, `GATE5 FAIL` —
  из-за отсутствия formal probe-results.
- `SRC-0005` этим изменением не закрыт, file-permission CHECK-adapter и
  canonical controls ещё не созданы. Закрыто строк source index: **0**.
  Состояние корпуса остаётся `349 / 8 / 341`.

## [0.0.6] — 2026-08-19

### Добавлено

- Три новых контроля FSTEC-LINUX-2022, закрывающие три строки source index:
  - `SRC-0028` / 2.5.5 — `user.max_user_namespaces=0`;
  - `SRC-0029` / 2.5.6 — `kernel.unprivileged_bpf_disabled=1`;
  - `SRC-0035` / 2.6.1 — `kernel.yama.ptrace_scope=3`.
- Для каждого: дословная цитата и её SHA-256 получены каноническим
  генератором `source:`, `derived=false`, `apply.supported=false`, вид
  параметра `sysctl`, существующий адаптер изменений не потребовал.
- Записи `atomic-single` в `CLOSURE-CONTRACT.tsv` для всех трёх строк.
- Файл `.gitignore` в дереве проекта.

### Изменено

- Прогресс корпуса: `349 / 8 / 341`, `CLOSURE_RATIO=8/349`.
- Исключения проекта перенесены из локального `.git/info/exclude` в
  версионируемый `.gitignore`, поэтому популяция корневых манифестов теперь
  воспроизводится в свежем клоне.
- Корневые манифесты и каталожные `SHA256SUMS` пересобраны; `PROGRESS.txt`
  приведён к фактическому состоянию.

### Проверено

- Гейты v3 на дереве после изменения: `GATE0 PASS`, `GATE1 PASS checked=8`,
  `GATE2 FAIL controlled_closed=8 disposed_closed=0 uncovered=341 contracts=8`,
  `GATE3 PASS checked=8`, `GATE4 PASS checked=8`, `GATE5 FAIL` из-за
  отсутствия probe-results, `OVERALL FAIL` как ожидаемое состояние.
- Расширение проверялось сначала на теневой копии дерева; оригинал изменялся
  только после совпадения ожидаемых значений.
- Первый диагностический прогон сгенерированного CHECK-скрипта на Ubuntu
  24.04.4 LTS server-minimized (`testmin`, ядро `6.8.0-134-generic`):
  синтаксис, `--help`, `--build-info`, `--provenance` целиком и с фильтром,
  RC=2 на неверный аргумент и арность, RC=3 и отсутствие проверок на
  неподдерживаемой платформе, стабильность вывода при повторе, неизменность
  состояния пяти параметров до и после прогона по совпадающему SHA.
  Непривилегированный прогон дал `UNEVALUATED` и RC=1 из-за нечитаемого
  `net.core.bpf_jit_harden`; прогон через `sudo` — пять `VALUE`, RC=0,
  вердикт `NONCOMPLIANT`.
- Скрипт при этом остаётся `NON_RELEASE_MEASUREMENT_CANDIDATE` и собран из пяти
  контролей: пересборка на восьми не выполнялась.

### Зафиксировано

- Прослеживаемость инженерного донора измерена: из 148 функций
  `check_`/`apply_`/`restore_` локатор ФСТЭК заявлен у 32, все 23 заявленных
  локатора присутствуют в корпусе. Донор контролей не создаёт и строк не
  закрывает.
- Публикация репозитория не является publication в смысле Build Contract.

## [0.0.5-r4] — 2026-08-15

### Статус — Step 7A CLOSED после R3 re-audit

- Несколько независимых R3-аудитов подтвердили исправление `S7A-R2-B01`;
  новых блокеров `S7A-R3-Bxx` не выявлено.
- Step 7A переведён в `CLOSED`.
- Step 7B разрешён **только для FSTEC expansion**; real dispositions остаются
  запрещены.
- Реальный disposition ledger остаётся header-only; состояние FSTEC не
  изменилось: `349 / 5 / 344`.
- Первый real disposition по-прежнему блокирован до машинного quote-anchor
  contract/API (`EXACT | REFUSED | UNSUPPORTED`), где integrity failures
  остаются исключениями.
- Corporate multi-index/descriptor остаётся отложен до первого реального
  corporate primary source.
- R3 non-blocking findings по NUL/Unicode line separators/CRLF и прежние
  замечания disposition-контракта сохранены как backlog, но не расширяют
  закрытый scope Step 7A задним числом.

### Исправлено — Step 7A R3: physical TSV без CSV quoting

- Повторный аудит R2 выявил `S7A-R2-B01`: `csv.reader` сохранял CSV
  quoting-семантику, поэтому quoted `TAB` в свободнотекстовом `basis` не менял
  логическую арность, а quoted `CR/LF` мог объединять физические строки.
- Loader теперь использует `quoting=csv.QUOTE_NONE`: кавычки — обычные данные,
  delimiter и границы физических строк больше нельзя скрыть quoting-механизмом.
- Добавлены четыре постоянные negative fixtures:
  `quoted_tab_basis`, `quoted_newline_basis`, `quoted_cr_basis`,
  `quoted_tab_reason`.
- Negative-control правило зафиксировано явно: parser-level негативные случаи сначала применяются
  к наименее ограниченному полю, а PASS означает соблюдение объявленного
  инварианта, не просто отсутствие видимого вреда.
- После R3 Step 7A остаётся `AWAITING_INDEPENDENT_REAUDIT_R3`; Step 7B и первый
  real disposition заблокированы.
- Quote-anchor policy не меняется:
  `REQUIRE_BEFORE_FIRST_REAL_DISPOSITION`.

### Исправлено — Step 7A R2: закрытая схема строк disposition ledger

- Независимый аудит R1 нашёл обход closed-schema: при корректном шестиколоночном
  заголовке `csv.DictReader` принимал строку данных с седьмым значением и
  помещал его под ключ `None`; loader это значение игнорировал.
- Loader теперь проверяет **арность каждой физической TSV-строки**: ровно шесть
  значений, соответствующих объявленным полям ledger.
- Добавлены две постоянные negative fixtures:
  `extra_data_field` (7 значений) и `short_data_row` (5 значений).
- Ошибка короткой строки теперь диагностируется как нарушение контракта, а не
  как внутренний `NoneType.strip()` через общий exception path.
- После R2 Step 7A не объявляется принятым до повторного независимого аудита.
  Step 7B и первый реальный disposition остаются заблокированы.
- Решение по quote-anchor усилено: до первого реального disposition требуется
  отдельный машинный anchor-state API (`EXACT | REFUSED | UNSUPPORTED`), при
  этом integrity failures не должны преобразовываться в эти состояния.

### Добавлено — Step 7A: усиление disposition contract

- Добавлен `index/source-v4/DISPOSITION-LEDGER.tsv` как обязательный
  проверяемый артефакт альтернативного пути закрытия строки source index.
- Gate 2 теперь требует ровно одну ledger-запись для каждого disposed `CLOSED`
  и запрещает ledger-запись у строки, закрытой control coverage.
- `disposition` и `reason` в ledger обязаны совпадать со значениями
  `SOURCE-INDEX.tsv`; `basis` и `decided_by` обязательны, `decided_at`
  проверяется как реальная UTC-дата формата `YYYY-MM-DDTHH:MM:SSZ`.
- Добавлена синтетическая позитивная фикстура `disposed_closed=1` и набор
  fail-closed отрицательных fixtures: enum, пустой reason, отсутствие ledger,
  дубликат, orphan, control/disposition conflict, ledger у controlled row,
  отсутствующий ledger-файл, completeness-contract у disposed row, mismatch
  disposition/reason и некорректная дата.
- Реальный disposition ledger остаётся пустым; `SOURCE-INDEX.tsv` не изменён,
  прогресс FSTEC остаётся `349 / 5 / 344`.
- Quote-anchor в ledger v1 намеренно не имитируется: канонический генератор
  пока покрывает только часть unit kinds и имеет два deliberate-refusal случая.
  До появления машинно-однозначного anchor-state фиктивный hash не вводится.

### Документация — первый проход на русском

- Зафиксировано правило: пользовательская документация проекта ведётся на
  русском языке; точные machine identifiers, CLI, enum, API и проверяемые
  status-строки сохраняются без перевода.
- Переведены наиболее заметные актуальные разделы `README.md`, основной
  roadmap, release-validation и документация генератора/parity `source:`.
- Переведён README parity-checker и часть актуального `[Unreleased]` changelog.
- Старые исторические разделы и часть англоязычных подписей архитектурной
  карты оставлены для следующих documentation-only проходов.
- Нормативные данные, controls, indexes, corpora, probes, checker logic и
  roadmap statuses не изменяются.

### Добавлено — паритет регенерации блока `source:`

- Добавлен постоянный checker, который регенерирует полный закоммиченный блок
  `source:` через канонический универсальный по индексу генератор и требует
  побайтового равенства.
- Результат закрытия: 5/5 controls совпадают; неподдерживаемых строк,
  отсутствующих строк index, расхождений и ошибок — 0.
- Неподдерживаемый `unit_kind` является явной fail-closed классификацией и
  никогда не пропускается молча.
- Добавлены отрицательные fixtures для изменений `quote`, `quote_sha256`,
  `locator`, неподдерживаемого типа, отсутствующей строки index и
  дублированного/некорректного блока `source:`.
- Этап 6 roadmap имеет статус `CLOSED`; этап 7
  `FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS` теперь `NEXT`.
- Controls, строки source index, source corpora, probes и семантика Gate 1–6
  не изменены; прогресс FSTEC остаётся 349 / 5 / 344.

### Добавлено — универсальный по индексу генератор `source:`

- Добавлен канонический `tools/source_skeleton_generator.py` как единственный
  нормативный производитель блоков `source:` для поддерживаемых `unit_kind`.
- Область извлечения явно ограничена
  `unit_kind=numbered-position`: 74 строки, 72 точных извлечения и два
  fail-closed отказа (`SRC-0001`, `SRC-0133`).
- Все пять принятых пилотных controls воспроизводятся побайтово.
- Добавлены fail-closed проверки уникальности index, `quote_anchor_ready`,
  закреплённого SHA/selftest normalizer, provenance manifest и SHA
  нормализованного корпуса.
- Добавлены постоянные positive/negative regression tests и проверка
  альтернативного пути к index для сохранения index-generic свойства.
- Этап 5 roadmap закрыт в этой ограниченной области; этап 6
  `SOURCE_BLOCK_REGENERATION_PARITY` переведён в `NEXT`.
- Controls, строки source index, source corpora, probes и checker gates не
  изменены; прогресс FSTEC остаётся 349 / 5 / 344.

### Исправлено — политика версий `jsonschema` для релиза

- Добавлена fail-closed минимальная поддерживаемая версия `jsonschema 4.10.3`.
- Добавлена отрицательная регрессия для версии ниже минимальной.
- Системное release evidence пересоздано при активной проверке нижней границы
  версии.
- Добавлено evidence совместимости, полученное обновлённым gate под
  `jsonschema 4.26.0`.
- Версии 4.10.3 и 4.26.0 сохраняют 0 расхождений runtime/real и emulator/real
  и успешно валидируют все пять активных controls.
- Это follow-up изменение закрывает 0 строк FSTEC source index.

### Добавлено — обязательный release-gate с реальным `jsonschema`

- Добавлен fail-closed release/audit gate, который требует установленный
  дистрибутив `jsonschema` и `Draft202012Validator`; отсутствие зависимости
  больше нельзя трактовать как пропущенную проверку релиза.
- В release evidence записываются точная версия дистрибутива `jsonschema` и
  версия Python.
- Gate выполняет self-validation schema Draft 2020-12, паритет генерации
  Gate 0, полную schema/runtime differential matrix, parity emulator-vs-real и
  проверку всех активных controls реальным валидатором.
- Требуется не менее 50 differential cases, 16 случаев на границах newline/CR
  и двунаправленное accept/reject покрытие каждого текущего parameter kind.
- Добавлена отрицательная регрессия, доказывающая fail-closed при отсутствии
  реального валидатора.
- Roadmap был переведён к `index-generic source skeleton generator`.
- Строки source index не закрывались; семантика controls/checker/probes не
  изменялась.

### Добавлено — классификация принятия инженерного донора

- Все 310 проиндексированных функций донора классифицированы с явными
  `adoption_class` и `adoption_note`.
- Распределение: 19 `contracted`, 31 `candidate`, 53 `evidence-only`,
  207 `pending-review`.
- По SHA-256 зарегистрированы четыре документа donor; всего
  зарегистрированных donor sources — 6.
- `restore-model.md` зарегистрирован для будущего этапа
  `apply/restore semantic contract`.
- Donor `fstec-mapping.md` явно помечен как ненормативный.
- Добавлены engineering contracts ENG-016..ENG-020 для registry необратимых
  изменений, preserve-stricter semantics, profile gating, транзакционной
  семантики созданных файлов и order-sensitive политики faillock.
- Валидация donor index усилена: неизвестный `source_function` приводит к
  fail-closed.
- Controls, строки source-v4, семантика checker, probes, evidence и source PDF
  не изменялись; закрыто 0 строк FSTEC source index.

### Fixed — type/boolean observation contract cleanup

- Removed accidental global `"true"` / `"false"` string-to-boolean coercion
  from `_expected_compliance`.
- Separated control semantic `expected.type` from probe `VALUE.value` wire
  encoding.
- Preserved sysctl wire behavior: integer/string observations are JSON strings;
  sysctl boolean remains forbidden by `KIND_RULES`.
- Reserved exact future boolean wire format for `systemd-unit-state` and
  `package-presence`: JSON boolean only, not quoted strings and not `0/1`.
- Kept both future runners unimplemented; format definition does not claim
  Gate 5 executability.
- Marked file-kv boolean observation mapping explicitly deferred until a
  file-kv probe design defines source-specific textual semantics.
- `KIND_RULES` and generated `CONTROL-SCHEMA.json` are unchanged.
- Added focused observation-contract regression tests.
- Advanced the roadmap to the mandatory real-jsonschema release gate.
- No source-index rows were closed.

### Fixed — project-map audit findings and clean-checkout manifests

- Corrected the text-corpus graph: normal pdftotext/norm-v1 covers 10 pinned
  PDFs, while glyph recovery is a separate PDF-origin branch for exactly two
  documents and is normalized separately under `recovered-v1/norm-v1`.
- Added Gate 1 corpus selection by `SOURCE-INDEX.text_quality` and the exact
  extraction/recovery manifests.
- Added `CLOSURE-CONTRACT.tsv` and explicit disposition+reason as the two Gate 2
  closure mechanisms.
- Added the schema/runtime differential suite and separated it from Gate 0
  generation parity; mandatory real Draft202012Validator remains the next
  release-validation roadmap item after type/boolean cleanup.
- Scoped Gate 5 to the five-sysctl/one-VM pilot and Gate 6 to the current
  sysctl-v1 evidence directory.
- Added audit/Git/bundle provenance and clean-checkout reproducibility to the
  project map.
- Replaced the direct index->control implication with a dashed "currently
  manual" relationship.
- Connected the future adapter branch to an explicit normative controls input.
- Fixed root manifests so Git-ignored donor runtime state is excluded by a
  canonical Git-visible population builder.
- Removed stale README/ROADMAP status text; the single current stage is
  `type/boolean contract cleanup`.
- No controls, source-index rows, checker semantics, probes, source PDFs or
  engineering-donor data objects were changed.

### Added — project-native v3 architecture map

- Added `docs/PROJECT-MAP-v3.md` as the primary visual map of the current
  SecureLinux-Policy v3 project.
- The map covers sources, normalization/recovery, source-v4, controls,
  Gates 0–6, reference-VM evidence, policy layers, engineering donor flow and
  the future deterministic build.
- Exactly one roadmap node is marked current: `type/boolean contract cleanup`.
- Existing `docs/ARCHITECTURE-DIAGRAMS.md` is explicitly reclassified as a
  donor runtime reference, not the primary v3 project map.
- No normative/runtime behavior changed.

### Added — visual architecture diagrams

- Added three GitHub-rendered Mermaid diagrams: CLI/runtime modes,
  module/additional-measures/restore flow, and apply/manifest/restore flow.
- Marked them as target runtime architecture inherited from the engineering
  donor, not as claims that every runtime mechanism is already implemented.
- README links directly to the rendered diagrams.
- No normative/runtime behavior changed.

### Added — Gate 6 evidence_binding

- Added a closed-schema evidence-binding checker for the factual `sysctl-v1`
  reference-VM evidence.
- Gate 6 verifies the evidence checksum set, VM metadata schema, current
  probe/plan hashes, both result hashes and `read_only=true` result roots.
- Added positive and nine negative regression cases.
- Gate 6 explicitly emits `VM_ORIGIN_ATTESTATION=NOT_PROVEN`; it proves
  integrity/binding, not cryptographic VM-origin attestation.
- No FSTEC/corporate source rows are closed by this change.
- Next roadmap step: `type/boolean contract cleanup`.

### Pinned — engineering donor adoption policy

- SecureLinux-NG v16.2.11 is formally pinned as an engineering donor, not a
  normative source of truth.
- Mature donor mechanisms must pass through
  `DONOR_TO_V3_MAPPING -> REUSE|ADAPT|REJECT|DEFER` before apply/restore
  contract and implementation-adapter work.
- `DONOR_TO_V3_MAPPING` is now a mandatory precondition to roadmap step 8.
- The donor mapping itself closes zero FSTEC/corporate source-index rows.
- Explicitly protected donor families include preflight, transactional apply,
  manifest/restore, atomic writes, backup fail-closed, package delta,
  preserve-stricter sysctl, isolated sysctl, network-online reapply, dry-run,
  run locking, layer/profile separation and preserved regression contracts.
- Final `securelinux-ng.sh` remains a deterministic generated artifact with
  machine-checkable provenance per emitted block.

### Recorded — Step 5 audit provenance closure

- Stored three Step 5 reference-VM ACCEPT verdict records.
- Did not claim "3 independent reviews": reviewer independence is provenance,
  not a count derived from verdict texts.
- Recorded the known limitation that one reviewer participated in v3 format
  design and authored two verdicts; exact review-id mapping is not asserted.
- Preserved 349 total / 5 controlled CLOSED / 344 OPEN.
- Added the authoritative forward roadmap.
- Next authorized engineering step: Gate 6 `evidence_binding`.

### Added — reference VM Gate 5 evidence

- Выполнен фактический read-only `sysctl-v1` probe на Ubuntu 24.04.4 LTS
  minimized (`testmin`, kernel `6.8.0-134-generic`).
- Непривилегированный прогон: 5 результатов, 4 `VALUE`, 1 `ERROR`;
  `/proc/sys/net/core/bpf_jit_harden` имеет mode `0600 root:root` и обычному
  пользователю не читается. Этот результат сохранён как environment evidence.
- Повторный read-only прогон через `sudo`: 5 `VALUE`, 0 `NOT_FOUND`,
  0 `ERROR`, 4 noncompliant observations.
- Активный checker с реальным evidence:
  `GATE5=PASS checked=5 value=5 not_found=0 noncompliant=4 errors=0`.
- `OVERALL=FAIL` ожидаем и вызван Gate 2: 344 source-index rows остаются OPEN.
- SHA-256 privileged evidence:
  `43c574a68d3478f35e4c7a5a50571ab4408d43a3e3a3cfed9ac3f50fbb1fc29c`.
- SHA-256 unprivileged evidence:
  `53e3bea08d07bcdf4210d125a026c1d1a4ce1481b2ee7d1415d4baf112389203`.

### Added — engineering donor preservation

- Полный SecureLinux-NG v16.2.11 test/development snapshot сохранён byte-for-byte
  и разложен в inspectable archive; source ZIP SHA-256
  `1b25f554a5ad1509037aa9613b7851a595159fd44291913cc2dba63280e50494`.
- Добавлен `index/engineering-tests-v1`: 38 test-файлов, 36 focused regressions,
  36/36 smoke wiring, 32 generalized engineering test contracts и отдельная
  donor VM evidence table.
- Добавлена `docs/testing-strategy.md`: differential, failure-injection,
  crash-consistency, filesystem safety и VM acceptance как разные test layers.
- Активно принят переносимый `tools/write-sha256.py` вместе с адаптированным
  regression-тестом; инструмент не зависит от старого монолитного скрипта.
- Старые donor tests, фиксирующие смешанную FSTEC mapping, явно помечены
  `historical-only` и не участвуют в v3 source coverage.
- Финальный architecture-review SecureLinux-NG сохранён byte-for-byte как
  историческое engineering evidence; он не является нормативным источником v3.
- Добавлен `index/engineering-donor-v1`: 310 функций, 190 source chunks,
  141 semantic candidate, 478 raw evidence rows и 15 будущих инженерных
  контрактов.
- Добавлен regression `tests/engineering-donor-v1/test_donor_index.py`,
  который сверяет reverse-index с pinned donor и запускает исходный
  `architecture-regression.sh` против pinned donor/docs.
- Зафиксировано, что donor-index не создаёт controls и не закрывает FSTEC rows.

### Pending

- Независимый аудит Step 0–5 с фактическим reference-VM evidence.
- Дальнейшее закрытие source-index rows только после прохождения
  соответствующих gates.

## [0.0.5-r3] — 2026-08-14

### Fixed after third independent audit

- B-R2-01: одной строки регулярного выражения недостаточно для одной семантики.
  Runtime сопоставляет шаблоны через `re.fullmatch`, а JSON Schema `pattern`
  имеет search-семантику, и в движке Python `$` совпадает также перед
  завершающим переводом строки. Из-за этого `key: "kernel.x\n"` отвергался
  runtime и принимался валидатором схемы. Достижимо: YAML-подмножество
  пропускает double-quoted скаляр через `json.loads`.
- Введён инвариант single-line: все машинные идентификаторы, локаторы и ключи
  несут явное утверждение об отсутствии CR/LF (`SINGLE_LINE`), которое ведёт
  себя одинаково при fullmatch, при поиске в Python и в ECMA-262.
- `parse_scalar` отвергает управляющие символы в скалярах — второй рубеж.
- Gate 0 переименован в `schema_generation_parity`: он проверяет байтовое
  равенство закоммиченной и порождённой схемы, а не семантический паритет.
  Семантический паритет обеспечивают дифференциальные тесты.

### Added

- 16 граничных случаев с CR/LF в дифференциальной матрице (всего 50).
- `PatternSemanticsTests`: для каждого шаблона fullmatch и search обязаны
  совпадать на 22 пограничных строках.
- `ParserInvariantTests`: управляющий символ в скаляре не проходит парсер.
- Прогон настоящим `jsonschema.Draft202012Validator`, когда библиотека
  установлена; при её отсутствии тесты пропускаются явно.

### Fixed

- `README.md`: устаревший SHA checker-v3; добавлен SHA схемы и правило,
  что схема не редактируется вручную.

### Preserved

- Pilot controls: 5, не изменялись. `index/source-v4`: не изменялся.
- Sysctl probe: не изменялся. 349 / CLOSED 5 / OPEN 344.
- Reference VM evidence: `NOT_YET_PROVIDED`.

### Checker

`checker/gates-v3/checker.py`

SHA-256:

`4c6012b7541923a682b6bb78bf5d8ccf5b241da54ecaa601f2c9d5479eafb5a6`

## [0.0.5-r2] — 2026-08-14

### Fixed after second independent audit

- B-R1-01: `CONTROL-SCHEMA.json` и runtime-проверка расходились в двух точках
  (`parameter.key` ровно `option::` и ровно `active_line::` принимались
  runtime и отвергались схемой).
- Устранена причина, а не два случая: kind-контракт вынесен в единственную
  таблицу `KIND_RULES` в `checker.py`. Из неё выводятся и
  `validate_parameter_closure`, и вся публикуемая схема.
- Добавлен `checker.py --emit-schema PATH` — генерация схемы из runtime-констант.
- Добавлен Gate 0 `schema_runtime_parity`: fail-closed, если закоммиченная
  схема не байт-идентична сгенерированной.
- `LAYER_ORDER` / `PROFILE_ORDER` / `APPLICABILITY_ORDER` задают
  детерминированный порядок enum в схеме.
- Схема: `$id` → `securelinux-policy-v3-control-schema-v3`; шаблоны приведены
  к якорной форме, эквивалентной `re.fullmatch` в runtime.

### Added

- `tests/gates-v3/test_schema_runtime_parity.py` — два независимых
  предохранителя: генерационный паритет и дифференциальная матрица из 34
  записей по всем восьми kinds в обе стороны (accept и reject).

### Preserved

- Pilot controls: 5, не изменялись.
- `index/source-v4`: не изменялся.
- Sysctl probe: не изменялся, SHA `e454d691e6433c2bfb8588884575fa4f5b880a6a0cb328682a5dbe1135dabd5e`.
- Source population: 349. CLOSED: 5. OPEN: 344.
- Reference VM evidence: `NOT_YET_PROVIDED`.

### Checker

`checker/gates-v3/checker.py`

SHA-256:

`0397a5e64a2e859bba1791a844feacad094120ee3375588ac2e31c597320edb7`

## [0.0.5-r1] — 2026-08-14

### Fixed after independent audit

- B-01 / A-01: controlled source row больше не закрывается просто по факту
  наличия одного control. Добавлен `index/source-v4/CLOSURE-CONTRACT.tsv`.
- B-02 / A-02: `checker/gates-v3/CONTROL-SCHEMA.json` заменён на полный
  nested JSON Schema для фактического runtime contract и 8 parameter kinds.
- B-03 / A-06: Gate 4 использует scoped identity
  `(layer, profile, kind, locator, key)`.
- Corporate profile-specific values учитываются как `profile_variants`.
- Divergent cross-layer values не разрешаются автоматически и fail-closed как
  `unresolved cross-scope parameter conflict`.

### Preserved

- Pilot controls: 5.
- Source population: 349.
- CLOSED: 5.
- OPEN: 344.
- Sysctl probe unchanged.
- Reference VM evidence: `NOT_YET_PROVIDED`.

### Checker

`checker/gates-v3/checker.py`

SHA-256:

`7217e741622690ac9f60521abf106b0250fecdb646537f3776dbf1d13ff00bdb`

## [0.0.5] — 2026-08-14

### Added

- Первый активный FSTEC-LINUX-2022 sysctl pilot.
- Пять controls:
  - `kernel.dmesg_restrict=1` — 2.4.1;
  - `kernel.kptr_restrict=2` — 2.4.2;
  - `net.core.bpf_jit_harden=2` — 2.4.8;
  - `kernel.perf_event_paranoid=3` — 2.5.2;
  - `kernel.kexec_load_disabled=1` — 2.5.4.
- `index/source-v3`.
- Read-only probe `probes/sysctl-v1/probe.py`.
- `checker/gates-v2` с Gate 5.
- Focused Gate-5 tests.

### Changed

- Source-index progress:
  - total: 349;
  - closed: 5;
  - open: 344;
  - closure ratio: `5/349`.
- Exact control quotes теперь формируются непосредственно из verified
  recovered FSTEC-LINUX-2022 corpus по locator и нормализуются `norm-v1`.

### Verification

- Gate 1: PASS для пяти pilot controls.
- Gate 2: FAIL expected, 344 uncovered.
- Gate 3: PASS.
- Gate 4: PASS.
- Gate 5 implementation synthetic selftest: PASS.
- Reference VM evidence: `NOT_YET_PROVIDED`.

### Fixed

- Исправлена первая версия Step-5 installer, которая сравнивала hardcoded
  quote с recovered corpus и корректно завершилась fail-closed до публикации.
- Исправленный Step-5 installer извлекает clause из
  `raw-glyph-recovered/fstec-linux-2022.txt`, применяет exact `norm-v1`,
  проверяет literal `key=value`, затем вычисляет quote SHA.

## [0.0.4] — 2026-08-14

### Added

- `checker/gates-v1`.
- Gates 1–4:
  - source/quote anchor;
  - reverse source coverage;
  - closed schema / parameter closure;
  - uniqueness / parameter conflicts.
- 13 positive/negative fixtures.

### Verification

На пустом active control corpus:

- Gate 1: PASS;
- Gate 2: FAIL expected — 349 uncovered;
- Gate 3: PASS;
- Gate 4: PASS;
- overall: FAIL expected.

Это зафиксировало fail-closed поведение до появления первых controls.

## [0.0.3] — 2026-08-14

### Added

- `index/source-v1` — первоначальная source-first population.
- `TOTAL_INDEX_ROWS=349`.
- Отдельная регистрация framework sources.
- Метрика перехода:
  `CLOSED_INDEX_ROWS / TOTAL_INDEX_ROWS`.
- `sources/recovered-v1` для non-OCR glyph-ID recovery.
- `index/source-v2`.

### Changed

- После recovery:
  - `QUOTE_ANCHOR_READY_ROWS=349`;
  - `QUOTE_ANCHOR_BLOCKED_ROWS=0`;
  - `CLOSED_INDEX_ROWS=0`.

### Verification

- `fstec-linux-2022`: 40/40 locators recovered.
- `fstec-vulnerability-analysis-2025`: 61/61 locators recovered.
- Double recovery: 2/2.
- Unresolved glyphs: 0.

## [0.0.2] — 2026-08-14

### Added

- Pinned FSTEC source bundle:
  - 10 PDF;
  - `sources/fstec/SHA256SUMS`.
- Deterministic `pdftotext` extraction.
- Raw extracted text.
- `norm-v1` normalized text.
- `EXTRACTION-MANIFEST.tsv`.
- Toolchain metadata.

### Verification

- Pinned source SHA verification: PASS.
- Double extraction: 10/10.
- Raw texts: 10.
- Norm texts: 10.
- `norm-v1` selftest/idempotence: PASS.

## [0.0.1] — 2026-08-14

### Added

- Новый sibling-проект `SecureLinux-Policy-v3`.
- Базовая структура:
  - `sources/`
  - `index/`
  - `controls/`
  - `probes/`
  - `checker/`
  - `tests/`
  - `archive/`
- Historical manifest старого проекта.
- Архивная копия B1.1b.
- Историческое отображение blocker IDs:
  - `N-01 -> B-06`
  - `N-02 -> B-07`
  - `N-03 -> B-08`
- Engineering donor `securelinux-ng.sh`.

### Policy

- Старая модель не конвертируется массово.
- Старые records рассматриваются только как candidate input.
- Новая активная модель строится source-first.
- Один control = один parameter.
- Источник и literal quote должны быть машинно проверяемы.
