# Журнал изменений

Формат основан на Keep a Changelog. Записи фиксируют факты, а не намерения:
каждая запись обязана указывать, сколько строк source index она закрыла, и не
приписывать себе продвижение, которого не было.

Раздел `[Не выпущено]` содержит проверяемые изменения, уже выполненные в
рабочем дереве, но ещё не включённые в датированную версию. Незавершённые планы
не записываются как свершившиеся факты.

## [Unreleased]

- 2.3.9 (SRC-0013) — решение человека 23.09.2026: контроль
  `FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST` выведен из активного состава.
  Основание: в тексте ФСТЭК 2.3.9 обязательное — права SUID/SGID-приложений
  не позволяют остальным изменять содержимое (`chmod go-w`); про «лишние»
  приложения сказано «например, если определен «белый» список» — список
  необязателен, а продукт не читает входных данных администратора. SRC-0013
  закрывается одной проверкой `FSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE`
  (`bits-clear 0022`): результат зависит только от прав SUID/SGID-файлов,
  файлы в `/etc/securelinux-policy/` для 2.3.9 не читаются.

  Удалены control-yaml и строка `CONTROL-MANIFEST.tsv`; ветка op
  `subset-of-file` удалена из `required_display` генератора. CHECK-адаптер
  `product-suid-sgid-applications-check-v2` общий с MODE, поэтому строка
  `ADAPTER-REGISTRY.tsv`, байты адаптера, binding и контракт не менялись:
  ветка `subset-of-file` в адаптере (и `allowlist_control` в контракте)
  сохранена, ни один контроль её не использует. Не менялись также
  `product/apply-adapters/product-suid-sgid-applications-mode-apply-v1.py`
  (SHA привязан к пройденному ВМ-прогону; комментарий о `…-ALLOWLIST` на
  строке 11 остался) и kind `approved-set` / op `subset-of-file` в
  `checker/gates-v3/checker.py` и `CONTROL-SCHEMA.json`.
  `CLOSURE-CONTRACT.tsv`: SRC-0013 `exact-control-set` → `atomic-single`.
  `SOURCE-INDEX.tsv`: note SRC-0013 переписана без allowlist. Сгенерированные
  блоки `README.md`, `docs/PROJECT-MAP.md`, `docs/fstec-coverage.md` — через
  `tools/render-current-docs.py`; вручную — секция SRC-0013 и два пункта
  перечня в `product/README.md`, вывод секции SRC-0013 в
  `docs/compatibility.md`, строка G5 в `docs/PROJECT-MAP.md`.

  Тесты: в `test_product_generator.py` модель SRC-0013 — один контроль;
  добавлены `test_src0013_suid_sgid_is_decided_by_mode_only` (единственная
  CHECK-функция 2.3.9 в артефакте — SUID-SGID-MODE, артефакт не содержит
  `suid-sgid.allowlist-v1`, функция не читает allowlist-файл и
  `/etc/securelinux-policy`; её байты из артефакта с подменой только пути
  mountinfo на фикстуру дают `violations=0 PASS` при `4755` и
  `violations=1 FAIL` при `4775`) и
  `test_retired_suid_sgid_allowlist_control_is_absent`; пин числа canonical
  controls 50 → 49; `required_display("subset-of-file")` — `RuntimeError`. До
  правки падали 4 теста в `test_product_generator.py`. Записанные выводы
  пересобраны: `ACTIVE-CHECKER-V3-NO-VM.txt` и
  `checker/gates-v3/ACTIVE-NO-VM-EVIDENCE.txt` (`checked=49`),
  `tests/source-skeleton-v1/TEST-RESULTS.txt` (`pilot=49`). Canonical
  controls: 50 → 49. Новый `CHECK_SHA256`
  `2f6d78ab44ec69b35f51e96a8c5bc42d06e4d7117f7404d6eba4e595bab5f119`.
  Закрыто строк source index: 0 (SRC-0013 уже CLOSED, меняется состав
  закрытия).

- 2.5.11 (SRC-0034) — решение человека 23.09.2026: контроль
  `FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE` выведен из
  активного состава. Основание: в тексте ФСТЭК «путём использования команды
  после тестирования kernel.randomize_va_space = 2» слова «после тестирования»
  — порядок действий администратора, а не объект проверки; те же слова
  («рекомендуется предварительно проверить на тестовой системе») стоят в 2.5.5
  и 2.5.6, где подтверждения проект не требует. SRC-0034 закрывается одной
  проверкой `FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE` (`sysctl eq 2`):
  результат зависит только от значения параметра, файлы в
  `/etc/securelinux-policy/` для 2.5.11 не читаются.

  Удалены control-yaml и строка `CONTROL-MANIFEST.tsv`; строка
  `tested-setting-attestation` удалена из `ADAPTER-REGISTRY.tsv`; ветка op
  `tested-before-use` удалена из `required_display` генератора.
  `product/adapters/product-tested-setting-attestation-check-v1.{py,json}` и
  `product/contracts/tested-setting-attestation-check-semantic-v1.json`
  оставлены на диске как historical bytes — по конвенции прежней SRC-0001
  APPLY-цепочки; `product/README.md` помечает их так же. Kind
  `tested-setting-attestation` в `checker/gates-v3/checker.py` и
  `CONTROL-SCHEMA.json` не трогался (в объём шага не входил).
  `CLOSURE-CONTRACT.tsv`: SRC-0034 `exact-control-set` → `atomic-single`.
  `SOURCE-INDEX.tsv`: note SRC-0034 переписана без attestation; заодно note
  SRC-0015 (2.3.11) приведена к коду `3215d1c` — популяция из прямых
  элементов `/home`, `/etc/passwd` не читается (код не менялся).
  Сгенерированные блоки `README.md`, `docs/PROJECT-MAP.md`,
  `docs/fstec-coverage.md` — через `tools/render-current-docs.py`; вручную —
  секция SRC-0034 в `product/README.md` и `docs/compatibility.md`, строка G5 в
  `docs/PROJECT-MAP.md`, `tests/product-v1/README.md`.

  Тесты: удалены классы `TestedSettingAttestationFixtures` и
  `TestedSettingAttestationSingleReadFixtures` (адаптер вне продукта);
  добавлены `test_src0034_randomize_va_space_is_decided_by_parameter_value_only`
  (единственная CHECK-функция 2.5.11 в артефакте — sysctl, не ссылается на
  `/etc/securelinux-policy`, её строка совпадает со значением
  `/proc/sys/kernel/randomize_va_space`) и
  `test_retired_tested_setting_attestation_is_historical_only`; пин числа
  canonical controls 51 → 50; kind убран из списков в
  `test_control_contract_binding.py` (`OPS_DECLARATION_GAPS`) и
  `test_current_status.py`. До правки падали 4 теста в
  `test_product_generator.py`, 1 — в `test_control_contract_binding.py`, 1 —
  в `test_current_status.py`. Записанные выводы пересобраны по текущему
  состоянию: `ACTIVE-CHECKER-V3-NO-VM.txt` и
  `checker/gates-v3/ACTIVE-NO-VM-EVIDENCE.txt` (вывод checker, `checked=50`),
  `tests/source-skeleton-v1/TEST-RESULTS.txt` (`pilot=50`); запись
  `checker/source-parity-v1/RESULT.txt` (`controls=51`) — исторический
  снимок, тестами не сверяется, не менялась. Canonical controls: 51 → 50. Новый
  `CHECK_SHA256`
  `2e7c3eb2aa11239971f543ad3b05274f75ea75408a48a9bf37f49b53d3ccaabd`.
  Закрыто строк source index: 0 (SRC-0034 уже CLOSED, меняется состав
  закрытия).

- 2.3.10 HOME-SENSITIVE-FILES-MODE (`product-home-sensitive-files-mode-check-v2.py`,
  SRC-0014), шаг (б) — решение человека 23.09.2026: проверяемые имена —
  замкнутый встроенный набор, authority-файл
  `/etc/securelinux-policy/home-sensitive-files-v1` больше не читается.
  Набор — восемь имён источника (`MANDATORY_SOURCE_NAMES`: `.bash_history`,
  `.history`, `.sh_history`, `.bash_profile`, `.bashrc`, `.profile`,
  `.bash_logout`, `.rhosts`) плюс 15 имён `COMMON_SHELL_BASENAMES`. В каждом
  home отбираются только непосредственные элементы (`find -P -xdev
  -mindepth 1 -maxdepth 1`); рекурсивный обход и
  `COMMON_SHELL_RELATIVE_PATTERNS` (fish/Nushell/Xonsh/Elvish в XDG-каталогах)
  удалены — файлы глубже первого уровня вне охвата. Удалены
  `CANONICAL_INVENTORY` и весь разбор authority-файла (причины
  `inventory:*` больше не возникают). Поле VALUE `names=` убрано (считало
  строки authority-файла); новый формат —
  `homes=N;discovered=N;checked=N;violations=N`. Популяция home-директорий
  (прямые элементы `/home`) и классификация объектов не менялись.

  Локатор `/home|/etc/securelinux-policy/home-sensitive-files-v1` → `/home`;
  синхронизированы control-yaml SRC-0014 (`parameter.locator`,
  `justification`), контракт `home-sensitive-files-mode-check-semantic-v2.json`
  (`canonical_locator`, `sensitive_file_population`: сняты `authority_path`,
  `authority_role`, `missing_authority`, `dynamic_discovery`, добавлены
  `common_shell_basenames`, `name_set`, `depth`; `wire_value`,
  `absent_root`), `checker/gates-v3/checker.py` (`KIND_RULES`),
  `CONTROL-SCHEMA.json` (совпадает с `--emit-schema`),
  `tests/gates-v3/test_schema_runtime_parity.py`, `ADAPTER-REGISTRY.tsv`,
  JSON binding адаптера, `CONTROL-MANIFEST.tsv`, `SOURCE-INDEX.tsv` (note
  SRC-0014). Docs: `docs/compatibility.md` перечисляет все проверяемые имена,
  `product/README.md` — упоминания authority-файла сняты.

  Тесты первыми: в `HomeSensitiveFilesAdapterFixtures` добавлено 5 тестов
  (без authority-файла проверка выполняется; восемь имён источника — литерал;
  нарушение 0077 на каждом из восьми имён → FAIL; каждое имя
  `COMMON_SHELL_BASENAMES` проверяется; файлы глубже первого уровня не
  проверяются), удалено 8, ставших неприменимыми (inventory и рекурсивное
  обнаружение), класс 18 → 15; класс `HomeSensitiveSingleReadFixtures`
  (3 теста, однократное чтение authority-файла) удалён целиком. До правки
  2 FAIL + 40 ERROR, после — 16/16 OK. Строк source index закрыто: 0.
  Новый `CHECK_SHA256`
  `725b250b48aa9048e1e9a5156766b99286dddd1d82effb6fbb88918830dc577d`.

- 2.3.10 HOME-SENSITIVE-FILES-MODE (`product-home-sensitive-files-mode-check-v2.py`,
  SRC-0014): популяция home-директорий переведена с обхода `/etc/passwd` на
  непосредственные (mindepth=1,maxdepth=1) элементы `/home`, по прецеденту
  2.3.11 (коммит `3215d1c`) — решение человека 23.09.2026. Прямой элемент
  `/home`, который симлинк или не каталог, — `ERROR` с путём и (для симлинка)
  целью `readlink` прямо в `reason` (`home:symlink:<путь>-><цель>` /
  `home:not-directory:<путь>`; байт-опасное имя/цель — `home:invalid-name`),
  классификация — по прецеденту (`stat -c %F`, ENOENT-устойчивый разбор
  предков /home). Authority-файл `/etc/securelinux-policy/home-sensitive-files-v1`
  и отбор файлов внутри каждого home (MANDATORY_SOURCE_NAMES,
  COMMON_SHELL_BASENAMES, относительные паттерны) не изменены — продолжают
  читаться/применяться как раньше. Отсутствующий/пустой `/home` — вне
  популяции, `VALUE/PASS`. Поле VALUE `accounts=` убрано (концепция учётной
  записи в популяции больше не участвует), `homes=` считает валидные прямые
  элементы `/home`; новый формат — `homes=N;names=N;discovered=N;checked=N;
  violations=N`.

  Синхронизированы локатор-связанные артефакты: control-yaml SRC-0014
  (`parameter.locator` → `/home|/etc/securelinux-policy/home-sensitive-files-v1`),
  контракт `home-sensitive-files-mode-check-semantic-v2.json` (`canonical_locator`,
  `population`, `wire_value`, снят устаревший `account_population`),
  `checker/gates-v3/checker.py` (`KIND_RULES` locator), `CONTROL-SCHEMA.json`
  (перегенерирован `--emit-schema`), `product/ADAPTER-REGISTRY.tsv`,
  `CONTROL-MANIFEST.tsv`, `SOURCE-INDEX.tsv` (note SRC-0014). Попутно
  поправлены две фразы, ставшие фактически неверными после смены популяции
  (`product/README.md`, `docs/compatibility.md`: «все local /etc/passwd
  accounts» → прямые элементы `/home`) — этого потребовал обязательный
  гейт `test_documentation_baseline.py` (общий `truth_sha256` по всем
  `STATE_DOCS`); остальная нарративная правка docs (`docs/PROJECT-MAP.md` и
  далее) в этот шаг не входит.

  Тесты первыми: класс `HomeSensitiveFilesAdapterFixtures` переписан (пустой/
  отсутствующий `/home` → PASS, прямой symlink/not-directory → ERROR, `/etc/passwd`
  не читается и не влияет на результат); `UnprovenAbsenceIsErrorFixtures`
  (`test_home_sensitive_unreachable_home_base_is_error` заменил passwd-based
  вариант, мёртвый `passwd_with` удалён); `HomeSensitiveSingleReadFixtures`
  сокращён до inventory-only (passwd-специфичные подтесты удалены, адаптер
  их больше не читает); `test_schema_runtime_parity.py` (locator в
  accepted/rejected/newline-кейсах). Все новые/изменённые тесты падали на
  прежнем адаптере до правки. Новый `CHECK_SHA256`
  `017d85b36646d7959e0bc1e23abe54183795eaa1b02f4c228169a2e4c98238f9`. DEV
  31/31, RELEASE PASS.

- Формулировки о числе сред (`docs/PROJECT-MAP.md`, `docs/testing-strategy.md`,
  `product/README.md`, пины `tests/roadmap-v1/test_project_map.py`): число сред
  приёмки указывалось плоско (8 сред, восьмисредовый VM-цикл, восьми
  поддерживаемых состояний) без разделения состава. Поддерживаемых
  clean-reference сред семь (`SUPPORTED-PLATFORMS.tsv`); Ubuntu 24.04 x86_64
  Desktop из `FIELD-COMPATIBILITY-DESKTOPS.tsv` — отдельный `FIELD_COMPATIBILITY`
  environment, число supported clean-reference environments он не увеличивает.
  Приведено к «приёмка семи сред» в узлах карты и «приёмка семи поддерживаемых
  сред (Desktop — FIELD_COMPATIBILITY, отдельной строкой)» в тексте. Изменены
  только формулировки: байты продукта, контроли, статусы механизмов и
  результаты ВМ-прогонов не менялись. Прежние записи журнала не переписывались.

- Н-3, `FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS` (`product-pam-wheel-access-check-v2.py`):
  разобранный и разрешённый стек `/etc/pam.d/su` без активной `pam_wheel.so`
  давал `ERROR pam:ambiguous-stack`, а не `VALUE/FAIL`. Причина — гейт «первая
  auth-строка sufficient/include/substack/`[...]`» (и отдельно `@include` при
  ещё не найденном exact-правиле) обрывал разбор `break`'ом, не давая
  убедиться, что `pam_wheel.so` в файле попросту нет; штатный
  `/etc/pam.d/su` Ubuntu 24.04 (`auth sufficient pam_rootok.so` первой
  auth-строкой, `@include common-auth/common-account/common-session`)
  попадал именно в эту ловушку. Правка: обе точки вместо `_slp_error=1;
  break` только выставляют `_slp_hazard=1` и разбор продолжается до конца
  файла; если `pam_wheel.so` ни в какой форме не встретилась — `VALUE/FAIL`
  с payload `pam_wheel=absent;wheel=<absent|gid N>;gid10=<имя|free>` (wheel/
  gid10 — из уже пройденного разбора `/etc/group`, generic-скан gid10
  включён только при `_slp_exact==0`, чтобы не расширять поверхность ошибок
  на уже протестированных PASS/FAIL-ветках); `ERROR ambiguous-stack`
  остаётся, если `pam_wheel.so` найдена (в любой форме) после hazard-строки
  — её реальная достижимость PAM-движком не доказана (7 существующих
  regression-тестов `test_prior_include_or_success_short_circuit_fails_closed`
  не менялись и остались зелёными). Имя владельца gid 10 в payload проверяется
  той же `_slp_name_has_forbidden_separator`, что и раньше защищала
  member/authority-имена; в неё же добавлен байт DEL (0x7F) — раньше
  функция ловила TAB/CR/VT/FF/пробел/двоеточие/запятую/`#`/unicode-пробелы,
  но не DEL. Payload старого формата `pam_exact=0;wheel=%d;members=%d;
  authority=not-needed` для случая `_slp_exact==0` заменён новым везде (не
  только там, где раньше была ошибка) — один существующий тест
  (`test_missing_exact_pam_is_definitive_fail_without_authority`) обновлён
  под новую строку. Новые тесты в `PamWheelAccessAdapterFixtures` (7 методов,
  включая параметризованный на 2 байта): штатный стек 24.04 → FAIL +
  точный payload; wheel с произвольным gid; gid10 занят другим именем/
  свободен; закомментированная `pam_wheel.so` не считается активной;
  байт-опасное имя владельца gid10 → `ERROR group:invalid-record`; до
  правки 8 подтестов падали (6 методов + 2 байта параметризованного).
  Новый класс `PamWheelAbsentReasonRenderFormat` (2 теста) доказывает, что
  новый payload проходит raw/JSON/pretty без потери байт — уже проходил, не
  тест-на-падение (VALUE-строки не подпадают под regex control-байт
  коллектора, который применяется только к `_slp_comp == ERROR`).
  `docs/compatibility.md` (секция SRC-0003) приведена к фактическому выводу:
  штатный стек 24.04 теперь даёт `pam_wheel=absent;wheel=absent;gid10=uucp`.
  Новый `CHECK_SHA256`
  `d45437179aaea5ee716c55f8fcaf518c93e8e60e0455b4656246a148b1415d5b`.

- Repair-step по аудиту Codex диапазона `3215d1c..cc90fd6` (`RESULT=REVISE`,
  3 блокера; **B-02** — диагностика, без правки продукта). **B-01**: адаптер
  `product-home-directories-mode-check-v2.py` (2.3.11) фильтровал
  байт-опасные TAB/LF/CR в имени элемента `/home` только на ветках
  error/symlink/not-directory — ветка совместимого каталога (проверка mode)
  пропускала такое имя без проверки вовсе; DEL (0x7F) не проверялся в имени
  ни на одной ветке; цель readlink с TAB/LF/CR давала урезанный
  `home:symlink:<путь>` без цели вместо `home:invalid-name`, а с DEL —
  сырой control-байт прямо в reason, ломающий регекс `slp_collect_policy`
  (`CHECK_INTERNAL_ERROR` на сгенерированном CLI). Правка: единая проверка
  TAB/LF/CR/DEL на имени элемента применяется на всех ветках классификации,
  включая директорию; цель readlink с любым из этих байт даёт
  `home:invalid-name` без payload. Тесты — параметризованные (4 байта ×
  ветки directory/symlink/not-directory/error для имени, 4 байта для цели
  readlink) в `HomeDirectoriesModeAdapterFixtures`, 6 новых методов (19→25);
  до правки 11 подтестов падали. **B-02** (только диагностика, без правки):
  предположение Codex «корневой CHECK-артефакт обязан входить в
  `product/SHA256SUMS`» не подтвердилось — отдельного генератора
  `product/SHA256SUMS` нет (не найден ни в одном из двух
  `generate-product-check-v*.py`), манифест — вручную сопровождаемый
  вложенный TREE-манифест по правилам `tools/pin-closure.py`; по
  `tests/project-integrity-v1/test_root_manifests.py:152` его охват —
  строго файлы с префиксом `product/`, а `securelinux-policy.sh` лежит вне
  этого дерева и пинуется корневыми `SHA256SUMS`/`PROJECT-FILES.sha256`; ни
  один документ не предписывает иного (`grep -rn securelinux-policy.sh
  docs/*.md | grep -i sha256sums` — пусто). Не дефект. **B-03**: три
  опровергнутых факта в `CHANGELOG.md` записи коммита `cc90fd6` — «16
  sysctl-контролей» исправлено на 17 (механический подсчёт
  `grep -l 'kind: "sysctl"' controls/fstec-core/linux-2022/*.yaml`); заявление
  о тестах цели readlink с TAB/внутренним/завершающим LF снято — такие тесты
  диапазон `6780086..3215d1c` не добавлял, а с B-01 этого шага любой из
  TAB/LF/CR/DEL в цели даёт `home:invalid-name` без payload, отдельный тест
  на сохранение «сырого» target с этими байтами больше не нужен; строка про
  «control-байт даёт `home:invalid-name`» дополнена явным перечислением
  TAB/LF/CR/DEL. Закрыты 4 пробела теста: `test_pretty_does_not_lose_bytes_of_wrapped_reason`
  (было — совпадение двух фрагментов, которые оба умещаются в первую строку
  переноса; стало — побайтовая реконструкция полного reason по всем
  перенесённым строкам `slp_render_pretty`, ширины читаются из самого
  прогона); `test_control_byte_in_entry_name_is_invalid_name_on_*` доказывают
  преобразование control-byte самим адаптером, а не только отказ
  `slp_collect_policy`; новый динамический тест
  `test_home_ancestor_stat_failure_other_than_enoent_is_error` (ветка
  `home-base:ancestor-stat-failed` раньше проверялась только статическим
  grep по тексту адаптера); `test_second_instance_is_refused_while_first_dispatcher_run_holds_lock`
  в `tests/product-v1/test_apply_dispatch_integration.py` доказывает удержание
  flock во время реальной конкуренции двух прогонов dispatcher (первый
  держит блокировку, взятую внутри собственного `ensure_state_dir()`, пока
  идёт второй) — прежний тест лишь сравнивал inode `.lock` после того, как
  первый процесс уже завершился. Обновлены `product/ADAPTER-REGISTRY.tsv`
  (implementation/adapter_contract sha адаптера 2.3.11), `product/SHA256SUMS`,
  `tests/product-v1/SHA256SUMS`, корневые манифесты; новый `CHECK_SHA256`
  `5dc6da078546ec2b7abee025b506c65d7171812e749edab9a22cdf6ac94c7a21`.

- Repair-step по аудиту Codex диапазона `6780086..3215d1c` (`RESULT=REVISE`,
  4 блокера). **B-01**: `home:symlink:<путь>-><цель>`/`home:not-directory:<путь>`
  (адаптер 2.3.11) отвергались regex `slp_collect_policy`
  (`^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$`) → `CHECK_INTERNAL_ERROR` на
  сгенерированном CLI. Regex теперь допускает необязательный третий сегмент
  полезной нагрузки (`<seg>:<seg>[:payload]`), payload без control-байт
  (`[:cntrl:]`, локаль фиксируется `local LC_ALL=C`); payload с control-байтом
  даёт `home:invalid-name`, как и раньше (сам адаптер 2.3.11 с репарации по
  аудиту Codex диапазона `3215d1c..cc90fd6`, B-01, явно фильтрует TAB/LF/CR/DEL
  — 0x09/0x0A/0x0D/0x7F — в имени элемента и в цели readlink раньше, чем
  reason доходит до этого регекса). Тест — сквозной через сгенерированный
  CLI (`SlpCollectPolicyReasonFormat`, 5 методов: raw/JSON/pretty с путём и
  пробелом в цели, control-байт по-прежнему отвергается, plain two-segment
  reason не регрессировал); до правки 3 из 5 падали. **B-02**: отсутствие
  `/home` и тип каждого элемента определялись `[[ ! -e ]]`/`[[ -L ]]`/
  `[[ ! -d ]]`, которые не отличают доказанный `ENOENT` от прочих ошибок
  `stat`/`lstat` (например `EIO`) — любая такая ошибка трактовалась как
  «объекта нет», уходя в `PASS`/`home:not-directory` по недоказанной
  популяции. Правка: `stat -c %F` (без `-L`) плюс буквальный разбор текста
  ошибки (`: No such file or directory` — единственное доказательство
  `ENOENT`); недоказанная ошибка — `ERROR` (`home-base:stat-failed:<path>` /
  `home-base:ancestor-stat-failed:<path>` для корня, `home:stat-failed:<path>`
  для элемента, включая TOCTOU-исчезновение между `find` и классификацией).
  Тесты — обёртка `/usr/bin/stat`, подменяющая ответ только для целевого
  пути (`install_command_shim`, `_stat_fail_shim_text`, `_stat_vanish_shim_text`),
  4 новых метода в `HomeDirectoriesModeAdapterFixtures`, до правки красные.
  Один существующий тест (`test_home_directories_unreachable_home_base_is_error`)
  осознанно обновлён: `home-base:ancestor-unsearchable` →
  `home-base:stat-failed:<path>` — прежнее поведение шло в обход предков даже
  при недоказанном `ENOENT` на самом `/home`, это и есть чинимая небезопасность.
  Список прочих адаптеров с тем же приёмом («доступный предок +
  `[[ -e ]]`/`[[ -L ]]`» вместо доказанного `ENOENT`) для доказательства
  отсутствия, без правки (см. отчёт задачи): `product-kernel-cmdline-check-v2.py:82`
  (10 контролей 2.4.x/2.5.x), `product-sysctl-check-v2.py:96` (17 контролей
  2.4.x–2.6.x), `product-file-mode-owner-check-v2.py:98` (SRC-0005, 3
  контроля), `product-sshd-root-login-check-v1.py:62,87` (SRC-0002),
  `product-home-sensitive-files-mode-check-v2.py:168` (SRC-0014),
  `product-pam-wheel-access-check-v2.py:58,65` (SRC-0003). **B-03**: `$(readlink …)`
  срезал завершающий LF цели символической ссылки до проверки байт-опасности
  (`$(...)` вырезает ВСЕ завершающие переводы строк, а не только терминатор
  команды). Правка — захват через sentinel (`&& printf x`), снимается ровно
  один служебный символ, затем ровно один служебный `\n`. Тестов, отдельно
  проверяющих цель с TAB/внутренним LF/сохранением завершающего LF, этот шаг
  не добавлял (опровергнуто репарацией по аудиту Codex диапазона
  `3215d1c..cc90fd6`, B-03 документации); с репарации того же диапазона
  (B-01) любой из TAB/LF/CR/DEL в цели readlink даёт `home:invalid-name` без
  payload, поэтому отдельного теста на сохранение «сырого» target с такими
  байтами больше не требуется — параметризованные тесты на это в
  `HomeDirectoriesModeAdapterFixtures.test_control_byte_in_symlink_target_is_invalid_name`.
  **B-04**: единичный `read -r var < file` после `od`-валидации в
  `kernel-cmdline-check-v2.py` (91→107) и `sysctl-check-v2.py` (105→117) не
  ловил подмену содержимого файла между проверкой и разбором (TOCTOU
  content-substitution) — только полную потерю ошибки чтения, не подмену
  байт. Правка — decode-once по образцу остальных 7 адаптеров (`759b041`):
  `od`-байты декодируются в текст (`_slp_load_text`) и разбираются без
  повторного открытия; воспроизведена точная семантика прежнего `read -r`
  (успех, только если в тексте есть хотя бы один `\n`; иначе, включая пустой
  текст, — `read-failed`). Тесты — обёртка `/usr/bin/od`, которая после
  настоящего вызова удаляет файл или подменяет его содержимое
  (`_od_vanish_shim_text`, новый `_od_swap_shim_text`) — 6 новых методов
  (`KernelCmdlineSingleReadFixtures`), до правки 3 из 3 «vanish»/«swap»/
  «od-failure» красные (`test_sysctl_adapter.py::SingleReadFixtures` — тот же
  набор, тот же результат). Встроенный `_selftest()` обоих адаптеров и
  `test_read_only_and_p01_guard` обновлены под две `$(...)`-подстановки (`od`
  + decode) вместо одной. Пробелы тестов из прошлой диагностики закрыты:
  partial-prefix для ВТОРОГО из двух `od`-вызовов (сбой ограничен только
  вторым файлом — первый проходит штатно) в `home-sensitive-files-mode`
  (inventory), `local-account-password-state` (shadow),
  `suid-sgid-applications` (allowlist) — новый
  `_od_fail_after_prefix_for_target_shim_text(target)`, 3 новых теста;
  state-dir тест дополнен: `debug.log` и `.lock` тоже остаются в исходном
  (переименованном при атаке подменой) каталоге, а не в новом по старому
  пути (`StateDirDescriptorPinning`, 2 новых теста), плюс явная проверка, что
  `.lock` после атаки — другой inode, чем каталог по прежнему пути. Новый
  `CHECK_SHA256` `e683fe2bc0823eb795a8436b86c16621f46277a2dbc8bd2f73105add5b872cfc`.
  Адаптеры APPLY и dispatcher-маршрутизация APPLY не менялись, ВМ-прогон на
  новых байтах не выполнен (перекроет приёмка 8 сред).

- `home-directories-mode-check-v2` (2.3.11, SRC-0015): популяция переведена с
  обхода `/etc/passwd` на непосредственные (`mindepth=1,maxdepth=1`) элементы
  `/home` (решение человека 22.09.2026, по прецеденту
  `archive/securelinux-ng.sh`, `home_targets_scan`); `/etc/passwd` адаптер
  больше не читает, `home=` учётной записи на результат не влияет. Прямой
  элемент `/home`, который является симлинком или не каталогом, не
  разрешается для классификации типа и даёт `ERROR` с путём и (для симлинка)
  целью `readlink` прямо в поле `reason`: `home:symlink:<путь>-><цель>` /
  `home:not-directory:<путь>`; имя элемента или цель симлинка с байтом
  табуляции/CR/LF ломали бы TSV-строку вывода — такой объект получает
  `home:invalid-name` вместо внедрения сырых байт. Раздела «blocks» у CHECK
  нет (он существует только у встроенного APPLY-dispatcher и только для
  `ABORTED_PRECONDITION_CONFLICT` — проверено чтением `_block_entry()` в
  `product/generate-product-check-v2.py`; решение человека 22.09.2026: не
  заводить для CHECK новую общую сущность, пояснение «вне модели продукта» —
  одной строкой в `docs/compatibility.md`, не в `reason`). Отсутствующий или
  пустой `/home` (с доступным для поиска предком) — вне популяции,
  `VALUE/PASS`, `checked=0;violations=0`; ошибка обхода — `scan:find-failed`/
  `scan:sort-failed`, не мутация по неполной популяции. `parameter.locator`
  контроля сменён с `/etc/passwd` на `/home`
  (`controls/fstec-core/linux-2022/fstec-linux-2022-2.3.11-home-directories-mode.yaml`);
  `checker/gates-v3/checker.py` (`KIND_RULES["home-directories-mode"]["locator"]`)
  и перегенерированный `CONTROL-SCHEMA.json` (`--emit-schema`) — тоже; тестовая
  матрица `tests/gates-v3/test_schema_runtime_parity.py` обновлена (accepted-кейс
  home-directories-mode использовал устаревший `/etc/passwd`, оставался
  единственным для этого kind — без правки `--release` падал на
  `one_sided_kinds`). Тесты добавлены/переписаны первыми: 26 в новом
  `HomeDirectoriesModeAdapterFixtures` + 2 адаптированных метода
  `UnprovenAbsenceIsErrorFixtures` (все 15 новых до правки падали на старом
  адаптере — подтверждено временным откатом на git HEAD). Устаревший класс
  `HomeDirectoriesSingleReadFixtures` (REREAD_UNCHECKED конкретно для
  passwd-парсинга) удалён — адаптер больше не читает файловый контент вообще,
  только `find`/`readlink`/`stat`. Semantic contract переписан
  (`product/contracts/home-directories-mode-check-semantic-v2.json`); прежние
  7 VM-замеров population сохранены как historical evidence прежней,
  passwd-based модели и не используются как доказательство полноты текущей
  популяции. Диагностика (Н-1, suid-dumpable C2/unassigned-primary; Н-3,
  pam-wheel ambiguous-stack на `pam_rootok.so sufficient`) дефектов не нашла:
  оба поведения — by design, уже протестированы (`test_d17_aux_profiles_exact_changed_missing_extra_and_raw_targets`,
  `test_prior_include_or_success_short_circuit_fails_closed`); GID 10 в 2.2.1 —
  прямая цитата источника, PASS 2.2.1 на стоковой Ubuntu 24.04 недостижим без
  ручного администрирования PAM/group (вне продукта). Новый `CHECK_SHA256`
  `5e0dacf619b1d9134458cf9fca752949c37efae336ba114668234b6854c9b85a`. Адаптеры
  APPLY не менялись, ВМ-прогон на новых байтах не выполнен (перекроет приёмка
  8 сред).

- Исправления по аудиту Codex коммита `6780086`. **REREAD_UNCHECKED** (тот же
  класс дефекта, что у `pam-wheel-access-v2`) устранён по тому же образцу ещё
  в семи CHECK-адаптерах: `home-directories-mode-check-v2` (passwd),
  `home-sensitive-files-mode-check-v2` (inventory, passwd),
  `local-account-password-state-check-v2` (shadow, passwd — через `mapfile`;
  по `man bash` `mapfile` не сигнализирует ошибкой `read()` после уже
  принятого префикса строк, значит небезопасен так же, как `while read`),
  `sshd-root-login-check-v1` (sshd_config, включая рекурсивный разбор
  `Include`; `done < file || {...}` не ловил ошибку после префикса — компаунд
  `while` отдаёт код последней команды тела, а не терминирующего `read`),
  `sudoers-reviewed-policy-check-v1` (authority),
  `suid-sgid-applications-check-v2` (allowlist, mountinfo),
  `tested-setting-attestation-check-v1` (authority; заодно убрана третья,
  избыточная реоткрытие — отдельный `read -r header < file` — разбор
  заголовка теперь идёт по тому же декодированному тексту). Проверенные `od`
  байты декодируются в текст (`_slp_load_text`/аналог) один раз и разбираются
  без повторного открытия файла; для корректных входов семантика не
  изменилась (проверено регрессией всех существующих тестов адаптеров).
  Тесты добавлены первыми (обёртка `od`, которая после чтения удаляет файл, и
  обёртка, которая печатает корректный префикс и завершается ненулевым кодом)
  и до правки падали: 10 из 10 «vanish»-тестов (по одному на каждый
  REREAD_UNCHECKED сайт), 14 «baseline»/«od-failure» тестов проходили и до, и
  после. **B-01**: встроенный APPLY-dispatcher после проверки каталога
  состояния и взятия `flock` держит дескриптор проверенного каталога
  (`_STATE_DFD`) открытым до конца работы; отчёт, журналы и временный файл
  отчёта открываются/переименовываются только через `dir_fd=_STATE_DFD`, а не
  по строке `STATE_DIR`. Тест добавлен первым (сразу после `ensure_state_dir()`
  каталог переименовывается, на его месте создаётся новый) и до правки падал:
  запись уходила в подменённый каталог; после правки остаётся в исходном
  (переименованном) inode, новый каталог остаётся пустым. **B-02**: ast-подсчёт
  `test_*` в классе `UnprovenAbsenceIsErrorFixtures` дал на `e420aee` и на
  `6780086` одинаковое число — 11; в `6780086` в этот класс метод не
  добавлен, пять новых тестов коммита лежат в отдельном новом классе
  `PamWheelSingleReadFixtures`. Замечание аудитора Codex о «12 тестов» не
  подтверждено; историческая запись CHANGELOG за `e420aee` («7 из 11»)
  остаётся верной и не правится. `docs/PROJECT-MAP.md` и `docs/compatibility.md`
  реклассифицируют кандидат `be828dae…5128` в исторический и описывают
  текущий кандидат. Новый `CHECK_SHA256`
  `a64e662a5cea05e53f6e158182188fcfac76f3dbc29b0ffd27af4f30f887c4b9`; адаптеры
  APPLY и dispatcher-маршрутизация APPLY не менялись, ВМ-прогон на новых
  байтах не выполнен (перекроет приёмка 8 сред).

- `pam-wheel-access-v2`: файл читается один раз (решение человека). Раньше `od` проверял байты, а затем файл заново открывался в `while read … < file`; при исчезновении файла между обращениями перенаправление не удавалось, цикл не выполнялся и контроль выдавал `VALUE/FAIL` вместо `ERROR`. Теперь проверенные `od` байты декодируются в текст, который разбирается построчно без повторного открытия (`pam`, `group`, `authority`); для корректных файлов семантика PASS/FAIL не изменилась (проверены файл без конечного `\n`, продолжение строки в конце файла, пустой файл). Каталог состояния `/var/log/securelinux-policy` во встроенном APPLY-dispatcher: существующий каталог обязан быть не симлинком, каталогом, принадлежать root и не иметь битов `022`; родитель `/var/log` — владелец root, без `o+w`, при `g+w` группа `root` или `syslog` (на Ubuntu `/var/log` — `root:syslog 0775`, буквальное «без `022`» отказывало бы APPLY на каждой Ubuntu; решение человека). Иначе отказ `REFUSED reporting:state-…` до любой записи, `RC=1`. Блокировка `flock(LOCK_EX|LOCK_NB)` на `.lock` в каталоге состояния для `--apply` и `--apply --dry-run`: второй экземпляр — `REFUSED reporting:already-running`, без мутаций и без записи отчёта. Тесты добавлены первыми и до правки падали: 3 из 5 в `PamWheelSingleReadFixtures` (`test_product_generator.py`; остальные два — базовый PASS и граничные случаи — проходили и до, и после) и 11 из 12 в `StateDirGuard` (`test_apply_dispatch_integration.py`; парный «блокировка снята после выхода держателя» проходил и до). Существующие тесты dispatcher подставляют `TRUSTED_UID = PARENT_TRUSTED_UID` пользователя прогона. Адаптеры APPLY не менялись, ВМ-прогоны на одной среде не повторялись — их перекроет приёмка 8 сред. Новый `CHECK_SHA256` `be828dae…5128`; ВМ-прогон на нём не выполнен.
- CHECK-адаптеры больше не принимают недоступность за отсутствие (находки аудитора Codex, статический анализ). Раньше `[[ ! -e path ]]` не отличал отсутствующее имя от имени под недоступным предком: `sysctl-v2`, `kernel-cmdline-v2`, `pam-wheel-access-v2`, `sshd-root-login-v1` отвечали `NOT_FOUND`, а `home-directories-mode-v2` и `home-sensitive-files-mode-v2` молча пропускали такой home, то есть возможен был `VALUE/PASS` по неполной популяции. Теперь `NOT_FOUND`/пропуск только при доказанном отсутствии (родитель — доступный для поиска каталог, как в `file-mode-owner`); иначе `ERROR` с уже существующей в коде адаптера причиной (контракты перечисляют только форму `<domain>:<reason>`): `sysctl:read-failed`, `cmdline:read-failed`, `pam:read-failed`/`group:read-failed`, `sshd-config:unreadable`/`sshd-binary:resolve-failed`, `home:identity-failed`. Новых причин нет. Тесты добавлены первыми (недоступный предок — `chmod 000`, доступ проверяется зондом от непривилегированного пользователя) и до правки падали: 7 из 11 в `test_product_generator.py` и 1 из 2 в `test_sysctl_adapter.py`; парные тесты «отсутствует в доступном каталоге — `NOT_FOUND`» проходили и до, и после. Подозрение на потерю ошибки в `while read … < file` проверено внедрением: home-directories, home-sensitive и tested-setting-attestation отдают `ERROR` (не дефект, код не менялся); в pam-wheel-access ошибка перенаправления теряется (`VALUE/FAIL`) — способ исправления вынесен на решение человека, код циклов не менялся. Новый `CHECK_SHA256` `9b886b9d…08fd`; ВМ-прогон на нём не выполнен.

- Механизм APPLY `standard-system-paths-mode-v1`: повторный ВМ-прогон на текущем кандидате `securelinux-policy.sh` `ba96131b…a55b` (среда `ubuntu-24.04-x86_64-minimized`, 20.09.2026) — `RESULT=PASS`; runner `dashboard/slp-vm-mech5-u2404min-v1.sh` `e6abdf22…4a3d` (перепривязан к новому кандидату), acceptance `c7900db8…12d8`, evidence `dashboard/src0009-vm-evidence/slp-vm-mech5-u2404min-v1-20260920-175045.tar.gz` `eddd6bd1…31d4`. Популяция 8300 файлов; фаза d — `APPLIED`, применён один файл (`/usr/bin/[` `0775` → `0755`); фаза f — `ALREADY_COMPLIANT`; `d.exercised` выполнен. Прежний ВМ-PASS относится к кандидату `e170aae1…dd38`. Коммит `8147d89` вернул адаптеру `product-standard-system-paths-mode-apply-v1.py` режим `100755` (находка аудитора Codex; содержимое не менялось).

- Исправлен дефект механизма APPLY `standard-system-paths-mode-v1`, найденный аудитором: при ошибке чтения подкаталога перечислитель (`os.walk` без `onerror`) молча пропускал его, CHECK возвращал `ERROR scan:find-failed`, а APPLY применял `APPLIED`/`COMMITTED` по неполной популяции. Теперь `_entries` завершает контроль отказом `scan:find-failed` до мутаций (`onerror` → `_ObservationError`); семантика CHECK и границы мутации не менялись. Тесты добавлены первыми и до правки падали (3 теста №5: apply, dry-run, observe); для `optional-file-root-files-mode-v1` (ошибка `os.scandir` корня), `suid-sgid-applications-mode-v1` (ошибка чтения каталога в `_scan_mount`) и `config-line-with-runtime-v1` (ошибка `os.scandir` каталога sysctl-источников) код верен, тесты прошли сразу. Новый `CHECK_SHA256` `ba96131b…a55b`; прежний ВМ-PASS №5 относится к кандидату `e170aae1…dd38`; повторный ВМ-прогон на новых байтах выполнен — PASS (запись выше).

- Добавлен пятый механизм APPLY `standard-system-paths-mode-v1` для контроля `2.3.8-STANDARD-SYSTEM-PATHS-MODE` (SRC-0012, снятие битов `0022` со стандартных системных путей); механизм доведён до работы в собранном CLI и принят на ВМ `ubuntu-24.04-x86_64-minimized` (одна среда; приёмка восьми сред впереди). Коммиты после `cc53fd9`: `9148a0d` — адаптер: перечислитель — Python-копия CHECK-наблюдателя (exec-корни и каждый absolute entry PATH root, lib-корни `.so`/`.so.*`/`.a`, модули `/lib/modules/<uname-r>` `.ko`/`.ko.*`; рекурсивно, симлинки разрешаются в конечную цель, дедупликация по `dev:ino`), план до мутаций, `fchmod` через `O_NOFOLLOW`, без компенсации; граница мутации — объекты, чей разрешённый путь внутри канонических корней (корни разбираются из локатора контроля и совпадают с константами CHECK-адаптера), дополнительные элементы PATH root и цели симлинков вне корней пропускаются с причиной `outside-canonical-roots`; `st_nlink>1` — пропуск; перед `fchmod` ревалидация на дескрипторе в порядке `S_ISREG` → `dev/ino` → биты `0022`; ошибка объекта — `APPLIED_PARTIAL`, `EROFS` и не root — остановка, ошибка популяции CHECK (dangling-симлинк, ссылка на не-файл) — отказ без мутаций; `apply.supported=true` у одного контроля, `APPLY_CONTROL_COUNT` 27 → 28, пять механизмов; в CHECK-тестах добавлена дедупликация по `dev:ino` (hardlink) литералом, CHECK не менялся; `518a4c2` — узел механизма в карте проекта. ВМ-прогон на кандидате `securelinux-policy.sh` `e170aae19cf261f37c1ca0a2f10c72b1dc373bef4eae263c6653bd690e35dd38` (runner `slp-vm-mech5-u2404min-v1.sh` `fc34eb8183b32692065eb8a6f5694f59a9646a9421f123016d9dedae77d6f54d`, acceptance `slp-mech5-acceptance-v1.py` `c7900db8eb33c8a589288e72f6781d3d5fc1b72fbdec8cab1a5737e241e212d8`, evidence `slp-vm-mech5-u2404min-v1-20260920-125650.tar.gz` `4ae51e8b8b2c1e4dcc4386d5a2f5fafd864ca1c043e690e806be94d34b19aa36`) дал `RESULT=PASS`: популяция на ВМ — 16 корней (2 отсутствуют, 8 алиасов), 8300 файлов (1065 exec, 761 lib, 6474 модулей), нарушителей нет, счётчики CHECK совпали с независимым перечислителем целиком; подготовка добавила один бит маски исполняемому файлу `/usr/bin/[` (hardlink=1, `0755` → `0775`); dry-run не изменил stat и дал `DRY_RUN_WOULD_APPLY`; `--apply` дал `APPLIED`, применён один файл, пропусков и ошибок нет, режим вернулся к исходному `0755`, `dev/ino` и содержимое прежние; CHECK после применения — PASS (`checked=8300;violations=0`); повторный `--apply` — `ALREADY_COMPLIANT` без изменений. У остальных 27 контролей `FAILED_*` нет, `suid-dumpable` — `ABORTED_PRECONDITION_CONFLICT`; снимок восстановлен. Информационно: `unix_chkpwd` в фазе g снова вернул rc=9 (`--apply` применяет и `/etc/shadow` 0640 → 0600). Закрыто source rows: 0.

- Добавлен четвёртый механизм APPLY `suid-sgid-applications-mode-v1` для контроля `2.3.9-SUID-SGID-MODE` (SRC-0013, снятие битов `0022` с SUID/SGID-приложений); механизм доведён до работы в собранном CLI и принят на ВМ `ubuntu-24.04-x86_64-minimized` (одна среда; приёмка восьми сред впереди). Коммиты после `b40f591`: `b8ae1aa` — адаптер: перечислитель — Python-копия CHECK-наблюдателя (`find -P -xdev -type f -perm /6000` по непсевдо-точкам mountinfo, дедупликация точек и файлов по `dev:ino`), план до мутаций, `fchmod` через `O_NOFOLLOW`, без компенсации; `st_nlink>1` — пропуск с записью, ошибка объекта — `APPLIED_PARTIAL`, `EROFS` и не root — остановка; перед `fchmod` ревалидация на дескрипторе в порядке `S_ISREG` → `dev/ino` из плана → биты `06000`, иначе пропуск с причиной; `2.3.9-SUID-SGID-ALLOWLIST` и любой иной op — `NOT_ELIGIBLE_APPLY_UNSUPPORTED`; `apply.supported=true` у одного контроля, `APPLY_CONTROL_COUNT` 26 → 27, четыре механизма; `c1769df` — исправлен недетерминированный тест `identity-drift` (unlink с последующим созданием файла переиспользовал инод на раннере CI; подменыш теперь ставится через `os.replace`), адаптер не менялся; `37128ca` — узел механизма в карте проекта; `cf7b911` — определение класса G6 в карте (cron и SUID/SGID); `44a2639` — в CI второй job `release`: `jsonschema` из `requirements-release.txt`, `tests/run-all.py --release`, хвост `RELEASE_*`; `8d70554` — определение G6 расширено до системных объектов (корни cron, файлы запуска, стандартные системные пути, SUID/SGID-файлы непсевдо-точек монтирования), CHECK suid-sgid получил тесты с ожидаемыми значениями-литералами для hardlink, symlink, вложенного каталога, псевдо-ФС, дубля точки монтирования и `mounts>1` (CHECK не менялся). ВМ-прогон на кандидате `securelinux-policy.sh` `b3d173d5d751252536867423ca1bab0480fa6865ebd753a44b5a54fa9723b927` (runner `slp-vm-mech4-u2404min-v1.sh` `43c50b02c032f3d4147164139d6d924f64e05e5b0383a9b3261a1817bcd3fa19`, acceptance `slp-mech4-acceptance-v1.py` `c636107674a23095d63dd83a91b200d82dc147607e9e2a3e7ceb81dfb77acd82`, evidence `slp-vm-mech4-u2404min-v1-20260920-114629.tar.gz` `35573e693e0d86c004685b461be9b99ca163114e45d4004c494f2207fb1c6db2`) дал `RESULT=PASS`: популяция на ВМ — 7 непсевдо-точек монтирования, 18 SUID/SGID-файлов, нарушителей нет, значения CHECK совпали с независимым перечислителем; подготовка добавила один бит маски файлу `/usr/bin/chage` (hardlink=1, `2755` → `2775`); dry-run не изменил stat и дал `DRY_RUN_WOULD_APPLY`; `--apply` дал `APPLIED`, применён один файл, пропусков и ошибок нет, режим вернулся к исходному `2755`, SUID/SGID-биты сохранены, `dev/ino` прежние; CHECK после применения — PASS (`mounts=7;checked=18;violations=0`); повторный `--apply` — `ALREADY_COMPLIANT` без изменений. У остальных 26 контролей `FAILED_*` нет, `suid-dumpable` — `ABORTED_PRECONDITION_CONFLICT`; снимок восстановлен. Информационно: `unix_chkpwd` в фазе g снова вернул rc=9 (`--apply` применяет и `/etc/shadow` 0640 → 0600). Закрыто source rows: 0.

- Добавлен третий механизм APPLY `optional-file-root-files-mode-v1` для шести контролей 2.3.6 (SRC-0010: корни cron `/etc/cron.d`, `cron.daily`, `cron.hourly`, `cron.monthly`, `cron.weekly` и `/etc/crontab`); механизм доведён до работы в собранном CLI и принят на ВМ `ubuntu-24.04-x86_64-minimized` (одна среда; приёмка восьми сред впереди). Коммиты после `a7121fc`: `570203b` — адаптер снимает биты 0033 с корня и его прямых файлов: план до мутаций, `fchmod` через `O_NOFOLLOW`, без компенсации; symlink или не тот тип — `ABORTED_PRECONDITION_CONFLICT`, hardlink>1 — пропуск с записью, ошибка объекта — `APPLIED_PARTIAL`, `EROFS` — остановка; перечислитель популяции — Python-копия CHECK-адаптера, паритет проверяется тестом; `apply.supported=true` у шести контролей, `APPLY_CONTROL_COUNT` 20 → 26, три механизма; `882ad9d` — в `_compact_outcome` ключ `DRY_RUN_WOULD_APPLY` вместо `WOULD_APPLY`, ключи сверяются с исходами адаптеров реестра тестом `test_compact_outcome_keys_are_adapter_outcomes`; `841674a` — корневые манифесты пинуют `.gitignore` по HEAD (CI на `570203b` падал на незакоммиченном `.gitignore`; CI на `841674a` — success). ВМ-прогон на кандидате `securelinux-policy.sh` `73e05c5587966e2760f855b4bab44c8bf52d5b6b70674c779bc1798e94e2ca23` (runner `slp-vm-mech3-u2404min-v1.sh` `121a5f25f41379d56f87b801361f1803fa04c5dcda4849f0941c8df1a1a10470`, acceptance `slp-mech3-acceptance-v1.py` `dc86e4469ca0324aef2b59e60709b044e297ab4d60f7b351643cf9b7ad2183e5`, evidence `slp-vm-mech3-u2404min-v1-20260920-101859.tar.gz` `8ed4d76832b5911c3d50e10201c45ec687ce907f463971cdb1601e52f8ffb389`) дал `RESULT=PASS`: dry-run не изменил stat (`DRY_RUN_WOULD_APPLY` у `cron.d` и `cron.daily`); `--apply` дал `APPLIED` у `/etc/cron.d` (2 объекта) и `/etc/cron.daily` (4 объекта), пропусков и ошибок нет, остальные четыре корня отсутствуют — `ALREADY_COMPLIANT`; CHECK после применения — 6×PASS, identity и содержимое прежние; повторный `--apply` — `ALREADY_COMPLIANT` без изменений. Среди остальных 20 контролей `FAILED_*` нет, `suid-dumpable` — `ABORTED_PRECONDITION_CONFLICT`; снимок восстановлен. Информационно: `--apply` применяет и `/etc/shadow` 0640 → 0600, поэтому `unix_chkpwd` в фазе g вернул rc=9 (см. запись о `file-mode-owner-v1`). Значения runner `f7c8fd28…` и acceptance `d9d3cd1d…` в отчёте от 19.09.2026 были ошибочными: прогон шёл на файлах с SHA, указанными выше. Закрыто source rows: 0.

- Добавлен второй механизм APPLY `file-mode-owner-v1` для трёх контролей SRC-0005 (2.3.1: `/etc/group` и `/etc/passwd` — режим 0644, `/etc/shadow` — снятие битов 0077); механизм доведён до работы в собранном CLI и принят на ВМ `ubuntu-24.04-x86_64-minimized`. Коммиты после `9340532`: `5fda8ca` — в проводной протокол CHECK добавлен статус `NOT_APPLICABLE` (популяция вычислена полностью и пуста): собственный счётчик, поля в `SLP-SUMMARY-V1` и `SLP-REPORT-V1`, `POLICY_STATUS` не переводится в `UNEVALUATED`; `f20eec4` — CHECK v2 для SRC-0008 (отдельная запись ниже); `4e5f3ca` — рукописные страницы описывают покрытие индекса тремя числами (40 строк закрыты контролями, 211 диспозицией, 98 открыты) и семантику SRC-0008 v2; `2727ae8` — механизм `file-mode-owner-v1`: один `fchmod` на дескрипторе, открытом с `O_NOFOLLOW`, только снятие битов, без компенсации, `APPLY_CONTROL_COUNT=20`; `2ad44ee` — SRC-0001 APPLY описан как история решения DP-3, ручные счётчики APPLY убраны из прозы; `0747f88`, `51856de` — `tools/pin-closure.py --check` печатает носители, пинующие изменённые пути прямо или транзитивно, в том числе для новых файлов по области `SHA256SUMS` (TREE/DIR); `5bbf0ff` — authority механизмов APPLY сокращены до полей, которые читает код, схема `apply-semantic-contract-v2` удалена, ожидания перенесены литералами в тесты; `a056683` — исправлен дефект: в собранном `securelinux-policy.sh` `--apply` и `--apply --dry-run` падали на всех трёх контролях SRC-0005 (dispatcher вызывал `execute_control` без `target`, адаптер не отдавал `actions_attempted`, `step_rc`, `mutation_performed`, `transaction_commit`); адаптер получил таблицу control_id → путь, новый `test_apply_dispatch_integration.py` исполняет встроенный dispatcher для каждого apply_kind реестра. ВМ-прогон механизма на кандидате `securelinux-policy.sh` `0095dae6b618fa5aa0319beaa8b83378b889caba79e3aad929ce92065ec1612e` (runner `slp-vm-mech2-u2404min-v1.sh` `045db4a6452fb4a9a9c4688f56a09da407e43375b980e3aed08e8a04a51758c9`, acceptance `slp-mech2-acceptance-v1.py` `6a2829bb53fb81ff69b0c66c46825eea988ca7608a21b57b6e083c3bdd120a86`, evidence `slp-vm-mech2-u2404min-v1-20260919-123103.tar.gz` `79f636ca4ddc8b643728b2e47cfaa76b1a2756796616cb5ecde721f8a4003405`) дал `RESULT=PASS`: dry-run не изменил stat и назвал ровно три цели; `--apply` дал `APPLIED` по трём контролям, изменился только режим (`/etc/group` и `/etc/passwd` 0644, `/etc/shadow` 0600), владелец, inode, число ссылок и содержимое прежние; CHECK 3×PASS; повторный `--apply` — `ALREADY_COMPLIANT` без изменений. Из 17 остальных контролей 16 `APPLIED`, `suid-dumpable` — `ABORTED_PRECONDITION_CONFLICT` (параметром управляет Apport); снимок восстановлен. Первый прогон (`slp-vm-mech2-u2404min-v1-20260919-121801`) не собрал evidence фаз d–f: снимок хранит память ВМ, часы гостя после восстановления отставали примерно на 77 суток и скачком синхронизировались во время фазы d, после чего `sudo -n` требовал пароль. Runner теперь ждёт сходимости часов ВМ с ПК до `sudo -v`; в принятом прогоне `sudo -n` до и после каждой фазы вернул 0. Информационно: после `/etc/shadow` 0600 `unix_chkpwd <user> chkexpiry` от имени пользователя возвращает rc=9 — проверить на Desktop при приёмке. Генератор не менялся (`GENERATOR_SHA256=a9cc6ae2…5902`). DEV 28/28, RELEASE PASS. Закрыто source rows: 0.

- Семантика CHECK для SRC-0008 переработана по принятому design-пакету `slp-src0008-design-review-pack-v3-r1-ru.md` (sha256 `af46c64db769f9b469604296172061d1607dbd1c0e959382df6dc0a4f072ae01`). Контроль `FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION` переведён с `root-owned-go-w` / `uid0;bits-clear-0022` на `root-owned-go-w-conditional` / `owner-if-regular-user;go-w-if-other-write`: OWNER считается нарушением только когда владелец — обычный пользователь по диапазонам `/etc/login.defs` и `/etc/adduser.conf`, MODE — только по биту other-write. Добавлены контракт `sudo-root-command-files-protection-check-semantic-v2.json` и пара адаптера `product-sudo-root-command-files-protection-check-v2.{py,json}`; строка `ADAPTER-REGISTRY.tsv` перепривязана, пара v1 осталась на диске как историческая и реестром не упоминается. Наблюдатель возвращает `NOT_APPLICABLE`, когда популяция вычислена полностью и пуста, и `ERROR` там, где применимость правила не доказуема (аргументы в пути команды, alias с аргументами, digest, negated, host-квалификация, временное окно, `runas_default`, `runchroot`, неразборная форма `Defaults`). Ядро прогнано на всех 24 кейсах архива фактов `cvtsudoers` v2 в двух вариантах UID-диапазона: 48 прогонов, расхождений с объявленными ожиданиями нет. Класс регрессий `SudoRootCommandFilesProtectionFixtures` переписан под новую семантику (32 теста). APPLY по SRC-0008 остаётся запрещённым: `apply.supported=false`, `forbidden.operations` контракта. Roadmap-шаг `SRC0008_CHECK_SEMANTIC_REWORK` закрыт. DEV 24/24, RELEASE PASS. Закрыто source rows: 0.

- Закрыт объём процессных документов аудированной диспозицией по альтернативному пути Gate 2: `fstec-vulnerability-management-2023` (52 строки: 34 `organizational`, 18 `informational`), `fstec-vulnerability-analysis-2025` (61 `organizational`), `fstec-vulnerability-criticality-2025` (28: 25 `organizational`, 3 `informational`), `fstec-security-update-testing-2022` (70 `organizational`). Основание каждого решения — построчный просмотр всех формулировок документа; технических требований к конфигурации операционной системы не выявлено. Заполнены `DISPOSITION-LEDGER.tsv` (211 строк, `decided_by=rasav65`) и `PROGRESS.txt`; Gate 2 `uncovered` 309 → 98. Machine state: `251 CLOSED / 98 OPEN`, из них контролями 40, диспозицией 211. Закрыто source rows: 211.

- Зафиксированы машинными регрессиями инварианты, ранее существовавшие только как соглашение. `tests/product-v1/test_contract_lifecycle_binding.py` выводит активный набор контрактов и адаптеров исключительно из `product/ADAPTER-REGISTRY.tsv`, запрещает ссылку активной строки на объект с `lifecycle_status=HISTORICAL_UNREGISTERED` и упоминание исторических объектов в реестрах. `tests/product-v1/test_control_contract_binding.py` проверяет разрешение каждого контроля в единственный существующий контракт через `parameter.kind` и вхождение операции контроля в `supported_ops` контракта там, где словарь объявлен; список из девяти активных контрактов без `supported_ops` зафиксирован как сокращаемый. Байты контролей, контрактов и адаптеров не изменялись. Закрыто source rows: 0.

- Добавлен CI (GitHub Actions, job `dev`): DEV-набор, пересборка корневых манифестов с падением при расхождении, проверка сгенерированной документации и блокировка при непустом рабочем дереве. В `product/README.md` и `docs/ROADMAP-v3.md` рядом с числом `40/40 CLOSED` зафиксировано, что семантика `SRC-0008 / 2.3.4` признана недействительной и document-level CHECK acceptance не считается действующим; в `docs/ROADMAP-v3.tsv` добавлен шаг `SRC0008_CHECK_SEMANTIC_REWORK` со статусом `SEMANTIC_REWORK_IN_PROGRESS` при сохранении единственного `NEXT`. В 81 строке индекса устаревшая пометка `Gate-1 quote blocked until readable verified text representation exists.` заменена записью о снятии блокировки glyph-ID recovery v1; статусы и покрытие не изменялись. Закрыто source rows: 0.

- Исправлен support-contract Ubuntu 24.04 Desktop: состояние переведено из `SUPPORTED` в `FIELD_COMPATIBILITY`; Desktop исключён из clean-reference acceptance, CLI/JSON/raw маркируют ограниченный статус, а перед реальным Desktop `--apply` выводится явное предупреждение об отсутствии гарантии на произвольно изменённой пользователем системе.
- README public download flow упрощён до единственного маршрута текущей ветки `main`: `wget main.tar.gz` → `tar -xzf main.tar.gz` → `cd SecureLinux-Policy-main`. Git clone/checkout и закреплённый commit-download удалены из публичного entrypoint. Проверка `securelinux-policy.sh.sha256` сохранена в Quick Start перед CHECK. Documentation regression и CURRENT-MARKDOWN-REVIEW-BASELINE обновлены синхронно. Закрыто строк источника: 0.
- Terminal presentation completion: CHECK и APPLY psql-таблицы теперь имеют закрытую правую границу (`|` для строк, `+` для separator) при сохранении точной ширины TTY; секция `blocks` оформлена отдельной psql-таблицей `control | type | message |` между основной APPLY-таблицей и `TOTAL`. Автоширина и UTF-8 padding сохраняются; поведенческие проверки охватывают 80/116/139/142/160 колонок, включая правую границу. Raw/JSON/report/provenance, canonical control_id и machine semantics не менялись. Закрыто строк источника: 0.
- Terminal presentation refactor: CHECK сохраняет `reason` в той же логической ячейке `current` (`not-determined; reason: ...`), а APPLY держит основную psql-таблицу только для `st/source/control/current/required`; все `block`-исходы выводятся после таблицы в секции `blocks` и до `TOTAL`. Автоширина и psql-границы проверяются поведенческими regression-cases на 80/116/139/160 колонках для CHECK и APPLY; non-TTY fallback остаётся 116. Raw/JSON/report/provenance, canonical control_id и machine semantics не менялись. Закрыто строк источника: 0. CHECK-renderer изолирует только presentation-срезы в `C.UTF-8`, сохраняя `C` для остальной логики; padding считает UTF-8 characters и bytes раздельно. Добавлены locale-regressions `LC_ALL=C` и `C.UTF-8` для одно- и двухзначных locator на ширинах 80/116/139/160, чтобы исключить разрез UTF-8 и сдвиг psql-границ.
- Terminal-view CHECK/APPLY переведён на автоматическую ширину: при выводе в TTY CHECK определяет число колонок через `/usr/bin/stty size`, APPLY — через `os.get_terminal_size`; для перенаправленного вывода сохраняется детерминированный fallback 116 колонок. При ширине 120+ расширяются `control/current/required`, при 90–119 используется компактная таблица, ниже 90 — вертикальное представление. Неопределённое текущее состояние теперь печатается явно как `not-determined`; для строк со статусом `err` диагностическое пояснение выводится как `reason:`, а `detail:` сохраняется для содержательных деталей других исходов. Для CHECK исправлено определение ширины TTY: проверка `-t 1` остаётся в вызывающем shell, а чтение `stty size` внутри command substitution больше не ошибочно сваливается в fallback 116; `reason:` выровнен под колонкой `current`. Regression различает прямое чтение controlling TTY и контракт non-TTY fallback=116 на уровне `slp_pretty_layout_init`. APPLY-renderer не менялся. Raw/JSON/report/provenance и canonical control_id не менялись; семантика CHECK/APPLY и правила изменения системы не менялись. Закрыто строк источника: 0. Pretty-вывод CHECK и APPLY унифицирован в psql-style: пять колонок разделены `|`, заголовок — `+`-separator, continuation/reason/detail/note остаются внутри тех же границ. Для CHECK устранено визуальное смещение source при двухзначных locator (`§2.3.10`, `§2.3.11`, `§2.5.11`) за счёт byte-aware padding символа `§`; `reason:` теперь является отдельной psql-строкой строго в колонке `current`. Для APPLY `detail:` и operator-decision notes также выводятся как psql-строки. При 139 колонках layout: `5|24|36|43|18`; non-TTY fallback остаётся 116. Raw/JSON/report/provenance и machine semantics не менялись.

- Исправлен вывод применения: сгенерированный скрипт показывает результат каждого поддерживаемого контроля и итоговую сводку; `debug.log` создаётся при инициализации журналов даже без диагностических событий. Семантика механизмов применения, выбор контролей и правила изменения системы не менялись.

- Публичная точка входа README переработана без изменения product semantics: добавлены понятные Назначение/Скачать/Быстрый старт, donor-style GitHub archive для ознакомления с main, сохранён безопасный pinned-download product-checkpoint, явные CHECK/APPLY/dry-run сценарии, badges, ограничения, обратная связь и MIT License. Функциональные product bytes не изменены.

- Реализован G0 Step 7B typed quote-anchor gate: генератор и source-parity используют единый machine-readable результат `EXACT | REFUSED | UNSUPPORTED` со стабильным `reason_code`; deliberate refusal отделён от integrity failures, которые остаются terminal fail-closed. Targeted regression подтверждает current baseline `82 EXACT / 1 REFUSED (SRC-0133) / 266 UNSUPPORTED`, byte identity 51 current controls и source parity `51/51`. Это implementation-targeted PASS; G0 block boundary ещё не закрыт до required manifests, full DEV и RELEASE. Source index и control population не изменены. Закрыто строк источника: 0.
- Интегрирована mechanism-oriented APPLY-вертикаль `config-line-with-runtime-v1`: 17 canonical sysctl-controls переведены в `apply.supported=true`, SRC-0001 выведен из active product APPLY и оставлен historical; добавлена r17 `MECHANISM_AUTHORITY_V1`, маршрутизация `parameter_kind → apply_kind`, обобщён единый verifier APPLY bindings и generated CLI переведён на product-owned цикл `slp_run_apply` с вычисляемыми `APPLY_KINDS` и `APPLY_CONTROL_COUNT`. Legacy `APPLY_SCOPE=SRC-0001_ONLY`, snapshot-attestation CLI и SRC-0001 registry bindings удалены из active path. Operational RESTORE по-прежнему отсутствует; приёмка интеграции и восьмисредовый VM-cycle выполняются отдельными gates. Закрыто строк источника: 0.
- Канонический генератор `source:` расширен на `unit_kind` `general-numbered-position`: локатор `<секция>:<порядковый номер>` выбирает N-й маркер верхнего уровня уже принятого outline, единица заканчивается перед следующим таким маркером, а последняя единица секции — на одном точном закреплённом терминаторе секции, обязанном встречаться ровно один раз и после начала единицы. Отсутствие, дублирование или положение не позже начала единицы дают отказ. Для `SRC-0048` и `SRC-0049` добавлены записи в существующие механизмы inline и trailing page furniture; новых механизмов не вводилось. `linux-appendix2-position` не затрагивался. Извлечение девяти строк `fstec-logging-2025` проверено на каноничность под norm-v1. Контрольные файлы не создавались. Закрыто строк источника: 0.
- Зафиксировано определение критерия `DOCUMENT COMPLETE` для `fstec-linux-2022`: критерий выполнен, когда все строки документа в `index/source-v4/SOURCE-INDEX.tsv` имеют `status=CLOSED`, APPLY завершён в принятом scope `SRC-0001_ONLY`, а этапы `FINAL_DETERMINISTIC_PACKAGING` и `SINGLE_DISTRIBUTABLE_ARTIFACT` закрыты. APPLY для остальных строк документа в критерий не входит; для следующих документов критерий определяется отдельно и не наследуется. Определение привязано к machine truth регрессией в `tests/roadmap-v3/test_roadmap.py`, читающей `SOURCE-INDEX.tsv`. Статусы этапов и продуктовые байты не изменялись. Закрыто строк источника: 0.
- Закрыт этап 17 `SINGLE_DISTRIBUTABLE_ARTIFACT` без нового архивного слоя: существующий generated `securelinux-policy.sh` подтверждён как current single distributable artifact по действующему donor-policy contract; exact SHA сохраняет применимость семи stage16 reproducibility cases, свежая генерация совпадает побайтово, sidecar/modes и provenance проверены. Текущая вертикаль достигла `DOCUMENT COMPLETE`; Step 7B `FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS` возвращён в `NEXT`. Имя будущего release/distributable и архивный формат не закреплялись. Закрыто строк источника: 0.
- Закрыт этап 16 `FINAL_DETERMINISTIC_PACKAGING`: итоговая сверка stage16 подтвердила исправленную APPLY provenance, семь случаев воспроизводимости сборки и права выдаваемых CLI/sidecar `0755/0644`; итоговый архив применения принят. Этап 17 `SINGLE_DISTRIBUTABLE_ARTIFACT` переведён в `NEXT`; canonical archive modes остаются его задачей и не объявляются выполненными. Закрыто строк источника: 0.
- Исправлена provenance APPLY для `SRC-0001`: существующая запись control дополнена объектом `apply` с id/version адаптера, SHA-256 реализации, id композиции и привязкой к источнику; генератор проверяет `ADAPTER_CONTRACT_VERSION`. Общее число provenance-записей и выбор по `CONTROL_ID` сохранены. Закрыто строк источника: 0.
- Существующие регрессии сборки дополнены вариантами `umask=0022/0077`, проверками прав обоих сгенерированных файлов и полной APPLY-provenance в общем и адресном выводе. Это изменение тестов не является записью об их прохождении. Закрыто строк источника: 0.
- Уточнена применимость требования к правам упаковки: этап 16 задаёт права выдаваемых файлов, а canonical archive modes относятся к этапу 17 при выборе архивного формата. Требование сохранено; его выполнение для архива не заявлено. Этап 16 этой записью не закрывается. Закрыто строк источника: 0.

- Главный README перестроен для пользователя: добавлены скачивание закреплённого скрипта через авторизованный Git-доступ с проверкой SHA-256, требования, поддерживаемые среды, команды запуска, пояснения результатов и границы APPLY. Инженерные сведения перенесены в `product/README.md`; машинный статус сохранён на главной в раскрываемом блоке. Обновлены указатель документации и проверки оформления. Код скрипта, политика и дорожная карта не изменены. Закрыто строк источника: 0.

- Описано исключение CHECK `SRC-0012` для ссылки в роли exec на каталог с идентичностью exec-корня: сравнение по dev:inode, без нового поля отчёта. Другие недопустимые цели сохраняют ERROR. Для адаптера `7a823bb1721f774c7f26963c67dfc9a1ea2ca9cde33285141f77fcfcbb43cb56` сохранён побайтовый паритет на семи серверных состояниях; на Ubuntu Desktop зарегистрировано намеренное отличие, отдельно для исходного и очищенного от висячих ссылок состояния. Замеры полного CHECK привязаны к CLI `02198905acd974a57dd92ada715a4c5c577f6e02d457412f18e38bd15170abc0`. Подробности и SHA отчётов внесены в стратегию тестирования. Закрыто строк источника: 0.

- Зафиксирована оптимизация CHECK `SRC-0012`: повторные внешние stat заменены чтением метаданных внутри Python; GNU find/readlink сохранены. Добавлен guard доступности исполнения `/usr/bin/python3` с причиной `runtime:python3-missing`; в семантическом контракте явно перечислены причины ERROR. Добавлены фикстуры зависимости Python, сбоя запуска и аргументов наблюдателя. Обновлены SHA-привязки и tracked CLI. Популяция и критерий прав не изменены; новые байты требуют повторной проверки на ВМ. Закрыто строк источника: 0.

- Исправлена формулировка завершённого этапа в README: вместо ручного номера используется идентификатор `APPLY_IMPLEMENTATION_ADAPTERS`. В карте проекта восстановлено русское обозначение будущего итогового распространяемого артефакта. В стратегии тестирования зафиксированы замеры текущего CHECK на Debian 13 SERVER с привязкой к SHA-256 CLI и архивов результатов; оптимизация реализации не выполнялась. Закрыто строк источника: 0.

- Закрыт этап 15 `APPLY_IMPLEMENTATION_ADAPTERS` в scope `SRC-0001_ONLY`: создана SHA-bound цепочка `APPLY-IMPLEMENTATION-REGISTRY.tsv` → binding → `product-local-account-password-state-apply-v1.py`, генератор встроил её в tracked CLI SHA-256 `98a4c67aeb392bff4e2b617f0f6593b8ff8fb149ce6bb156d9adbebd94e86928`. Function-level VM runs подтвердили dry-run, attested commit, post-check, idempotent NOOP и fail-closed ветви xattr/stale/temp verification; generated CLI дал `11/11 PASS` на Ubuntu 22, Ubuntu 24, Ubuntu 26, Debian 12 и Debian 13, а Ubuntu 24 Desktop подтвердил `TYPE=DESKTOP` и dry-run без изменения `/etc/shadow`. Полный commit-path не объявляется выполненным для каждого из восьми profile/type состояний. Следующий этап — `FINAL_DETERMINISTIC_PACKAGING`. Закрыто строк источника: 0.

- Линия obligation-generator / method regression / rescan / annotations / design v5 закрыта; approved plan rev3 отменён как ошибочная процессная надстройка; её артефакты сохраняются вне product gates. Закрыто строк источника: 0.

- Этап 15 `APPLY_IMPLEMENTATION_ADAPTERS` сохраняет идентификатор и статус `NEXT`, но сужен до одной вертикали: реализация APPLY для `SRC-0001` по закрытым восьми определениям и композиции. Реализация APPLY и изменение системы не добавлены. Закрыто строк источника: 0.

- Закрыт P-06 для `SRC-0001`: добавлены точные, привязанные по SHA-256 `metadata-preservation-v1.json`, `atomic-transaction-v1.json` и `dry-run-report-v1.json`; архитектура теперь содержит восемь ролей определений со статусом `CLOSED`, а `composition-v1.json` детерминированно связывает архитектуру, текущий источник состава CHECK и все восемь определений. Закреплены допустимость и сохранение метаданных с порядком ошибок, единственная атомарная замена через временный файл в том же каталоге, сухой запуск без записи, постпроверка при удерживаемой блокировке и протокол `SLP-APPLY-REPORT-V1`. Реализация APPLY и изменение системы не добавлены; следующий этап — `APPLY_IMPLEMENTATION_ADAPTERS`. Закрыто строк источника: 0.

- Закрыт P-05 для `SRC-0001`: добавлены SHA-bound `lock-reread-v1.json` и `object-identity-v1.json`. Exclusive libc `lckpwdf(3)` password-database lock обязан предшествовать under-lock reread и любой host mutation; exact `/etc/passwd` + `/etc/shadow` bytes, ordered selected usernames и final precommit revalidation должны совпадать с pre-lock reference, иначе `ABORT_NO_MUTATION`. `lckpwdf` сериализует только writers, соблюдающие этот password-database lock; прямые noncooperating writers не выдаются за покрытые lock guarantee. `/etc/shadow` допускается только как regular non-symlink single-link object (`st_nlink == 1`) с nofollow fd/fstat identity binding; symlink/hardlink/path/object drift до собственного atomic commit запрещён. Composition/implementation отсутствуют. Закрыто source rows: 0.

- Закрыт P-04 для `SRC-0001`: добавлен SHA-bound `product/contracts/src0001-apply/snapshot-precondition-v1.json`. До любой host mutation требуется caller-supplied read-only `SLP-EXTERNAL-SNAPSHOT-ATTESTATION-V1`, bound к exact `/etc/machine-id` и SHA-256 prestate `/etc/shadow`, с non-empty external provider/snapshot id, scope `FULL_TARGET_HOST_OR_VM`, `READY` и `rollback_capable=true`; missing/malformed/mismatch/not-ready evidence → `ABORT_NO_MUTATION`. Attestation честно классифицирована как operator assertion, не provider-cryptographic proof; product не создаёт/не восстанавливает snapshot. Закрыто source rows: 0.

- Закрыт P-03 для `SRC-0001`: добавлены отдельные SHA-bound definitions `predicate-empty-second-shadow-field-v1.json` и `transform-empty-second-shadow-field-to-bang-v1.json`. Predicate выбирает ровно пустое второе поле bound `/etc/shadow` record из exact population текущего CHECK; transform выполняет только byte-exact `"" -> "!"`, сохраняет non-selected/non-empty fields и все остальные bytes, а stale/non-empty selected field приводит к `ABORT_NO_MUTATION`. Architecture отмечает только `predicate`/`transform` как `CLOSED`; остальные шесть roles остаются `PENDING`, composition/implementation отсутствуют. Закрыто source rows: 0.

- Закрыта узкая архитектура `SRC0001_MODULAR_APPLY_CONTRACT_ARCHITECTURE`: `APPLY-KIND-REGISTRY.tsv` сокращён до compact `apply_kind`/`target_class` → architecture identity/path/SHA binding; добавлены source-local architecture object и Draft 2020-12 composition schema с восемью обязательными definition roles, deterministic binding checker со stale-SHA negative regression и решение о separate implementation registry до первого implementation. Flat SRC-0001 contract SHA `48e008ac…` сохранён как `REVISE` input, accepted CHECK population authority не менялась; P-03…P-06 остаются открытыми, следующий этап — exact predicate/transform definitions; закрыто source rows: 0.

- Закрыт `AUTHORITY_2026_REFRESH` (A0.5): в pinned authority добавлен image-only приказ ФСТЭК России от 8 мая 2026 г. № 137 с exact SHA-256 `eea32d569889ed57e9b7081b3a69fd31e44d0422d23349fefa3521427401c61a`, изменяющий приказ № 117; основная часть действует с `2026-09-01`, пункт 7 приложения — с `2027-03-01`. Созданы отдельные page-pinned visual transcription/provenance bytes и machine-readable relation `117 -> 137`; № 137 зарегистрирован только как framework authority и не добавляет строки `SOURCE-INDEX.tsv`. Регрессия подтверждает сохранение `SRC-0001…SRC-0040` в `fstec-linux-2022` как `40/40 CLOSED`. Текущие README/PROJECT-MAP/roadmap и их regressions переведены с прежнего `APPLY implementation = NEXT` на `SRC0001_MODULAR_APPLY_CONTRACT_ARCHITECTURE = NEXT`; machine roadmap одновременно различает принятый parent gate и flat SRC-0001 instance со статусом `REVISE`; implementation остаётся `BLOCKED_BY_PREVIOUS`. Regular files в `sources/fstec/` нормализуются к worktree mode `0644`; Git executable semantics не меняются. Закрыто source rows: 0.

- Сформирован первый flat source-specific `APPLY semantic contract`-кандидат `product/contracts/local-account-password-state-apply-semantic-v1.json` для `SRC-0001 / 2.1.1`. Parent schema/registry binding и RELEASE fixtures проходят, при этом статус остаётся `REVISE`: P-03…P-07 остаются открытыми, поэтому instance не считается принятым финальным semantic authority и сохраняется как вход/evidence для `SRC0001_MODULAR_APPLY_CONTRACT_ARCHITECTURE`. APPLY implementation и host mutation не добавлены; accepted CHECK semantics не менялись; закрыто source rows: 0.

- Начат roadmap `APPLY_SEMANTIC_CONTRACT` только с parent-level gate: добавлены единая `apply-semantic-contract-v1.schema.json` и `APPLY-KIND-REGISTRY.tsv`; зарегистрирован первый kind `local-account-password-lock` для будущего SRC-0001 instance. После проверки parent gate RELEASE regression дополнен автоматической schema+registry binding-проверкой всех source-specific APPLY contracts и 9 negative fixtures на незарегистрированный kind и расхождение kind-level ограничений. Source-specific APPLY contract, implementation и host mutation не добавлены; accepted CHECK semantics не менялись; закрыто source rows: 0.

- Закрыты три blocker-класса full verification candidate `2a24e666`: unified collector теперь принимает contract-valid `NOT_FOUND/FAIL` для обязательных SSH/PAM объектов и сохраняет итог `NONCOMPLIANT`; `/etc/os-release` preflight до Bash parsing проверяет корректный UTF-8; безопасный parser без `source` поддерживает разрешённые single/double quotes и shell-style escaping для `ID`/`VERSION_ID`/`PRETTY_NAME`. Добавлены regressions на missing SSH/PAM wire, invalid/truncated UTF-8, valid Unicode и quoted/escaped os-release identity. Source/control coverage и число CLOSED source rows не изменены; закрыто source rows: 0.

- Закрыты три blocker-класса full verification candidate `80a753e7`: PAM wheel parser больше не зависит от caller locale при проверке whitespace в group/authority usernames; `/etc/os-release` preflight fail-closed отклоняет недопустимые C0 bytes до Bash parsing и сохраняет фиксированный raw platform framing; package-profile observation вызывает `/usr/bin/dpkg-query` с явными `--root=/` и `--admindir=/var/lib/dpkg`, поэтому caller `DPKG_ROOT`/`DPKG_ADMINDIR` не меняют support profile/type. Добавлены negative-control regressions для U+2003/U+3000, TAB/BS/FF/ESC и dpkg database redirection. Source/control verdict semantics и число закрытых source rows не изменены; закрыто source rows: 0.

- Закрыты три blocker-класса verification candidate `b1888ba1`: sysctl integer lexical parsing и SSH config lexical parsing закреплены в locale-independent semantics, поэтому Unicode whitespace больше не меняет verdict в зависимости от caller locale; `--help` и `--provenance` больше не исполняют `cat` из caller-controlled `PATH`; JSON renderer экранирует все C0 control bytes, представимые в Bash-строке. Добавлены regressions на Unicode whitespace, caller-controlled `PATH` и JSON C0 round-trip. Source/control verdict semantics и число закрытых source rows не изменены; закрыто source rows: 0.
- Финализирован residual R-04 после capable-environment self-audit: пять `observation:file-changed` и три `observation:parent-changed` больше не смешивают repeat-observation с recheck-стадиями; parent recheck type и snapshot разделены. `path:outside-scope` и `proc:invalid-path-escape` сохранены как единые semantic failure modes. Source/control verdict semantics не изменены; закрыто source rows: 0.
- Исправлены четыре blocker-класса reconciliation для candidate `e2c60a9f`: raw-byte preflight до Bash parsing добавлен для sysctl, kernel cmdline, SSH config tree и `/etc/os-release`; dpkg `${Status}` теперь классифицируется по полной тройке want/error/status и отвергает промежуточные или повреждённые состояния; пять active semantic contracts согласованы с runtime `ERROR.value=<domain>:<reason>` при сохранении `NOT_FOUND.value=-`, а три незарегистрированных v1 явно отмечены historical; 21 неодинаковая ветвь SRC-0006 больше не схлопывается в `observation:process-changed`. Добавлены negative и exact branch-specific regressions; source/control verdict semantics и число закрытых source rows не изменены; закрыто source rows: 0.
- Исправлен pre-commit диагностический blocker current CHECK: все active adapters теперь возвращают для `ERROR` стабильный machine-readable reason-code `domain:reason`, который одинаково сохраняется в pretty `VALUE / DETAILS`, raw и JSON. Central collector fail-closed отвергает production `ERROR` с `-` или некорректным reason-code; `NOT_FOUND` semantics не изменены. Причины привязаны к точкам установленного failure mode и не формируются из stderr. После full self-audit исправлены ложные branch→reason mappings в `local-account-password-state`, `optional-file-root-files-mode`, `suid-sgid-applications`, `sudoers-reviewed-policy` и `sudo-root-command-files-protection`; устранено схлопывание разных failure modes в общие coarse-коды, а для multi-input/stage checks reason-code теперь различает конкретный статический вход или этап (`passwd`/`inventory`, PAM/group/authority, `sshd -t`/`sshd -T`, attestation authority). Добавлены exact branch-specific regressions, чтобы валидный по regex, но неверный или неоднозначный по смыслу reason-code больше не считался достаточным. Source/control verdict semantics и число закрытых source rows не изменены; закрыто source rows: 0.
- Исправлен runtime blocker candidate `a57faaea`: `ubuntu-server-minimal` больше не требуется для дополнительного Ubuntu 24.04 Desktop. Основная 7/7 матрица `FULL | MINIMIZED | SERVER` сохранена без переименования; Desktop вынесен в отдельный `TYPE=DESKTOP` и `product/FIELD-COMPATIBILITY-DESKTOPS.tsv`. Графическая оболочка не участвует в support identity. Добавлен отдельный fail-closed `UNSUPPORTED_TYPE`; `UNSUPPORTED_PROFILE` и `UNSUPPORTED_PLATFORM` сохраняются раздельно.

### Исправлено — единый multi-platform runtime target

- Удалена single-target привязка current product-line к `ubuntu-24.04-x86_64`: один `securelinux-policy.sh` runtime-определяет OS/version/arch и profile по `product/SUPPORTED-PLATFORMS.tsv`. Поддержанная VM matrix — 7/7: Ubuntu 22 FULL; Ubuntu 24 MINIMIZED/FULL; Ubuntu 26 MINIMIZED/FULL; Debian 12 SERVER; Debian 13 SERVER.
- Ubuntu primary-profile classifier fail-closed: `FULL` основной 7/7 матрицы требует `ubuntu-server-minimal + ubuntu-minimal + ubuntu-standard`, `MINIMIZED` — `ubuntu-server-minimal` при отсутствии двух последних; mixed state отклоняется как `UNSUPPORTED_PROFILE`. Отдельно Ubuntu 24.04 с отсутствующим `ubuntu-server-minimal` и установленными `ubuntu-minimal + ubuntu-standard` классифицируется как `TYPE=DESKTOP`.
- `--restore` остаётся удалён из current CLI; CHECK/REPORT выводят фактическую system identity и profile.

- Уточнён current CLI после полного аудита: human-readable `--check`/`--report` теперь явно выводят обнаруженную ОС, архитектуру, profile и runtime platform; пользовательский ключ `--restore` полностью удалён из current CLI/help вместо compatibility stub. `--apply` остаётся fail-closed `NOT_IMPLEMENTED`; operational RESTORE по-прежнему исключён из v3. Закрыто source rows: 0.
- По current semantic audit пять controls с локальным authority-product-mechanism переведены на `requirement.derived=true` с явным `justification`; `2.3.10` уже был классифицирован так. Gate 3 теперь fail-closed требует эту provenance-классификацию для authority-backed resolver semantics. Source quotes, closure identities и runtime adapter logic не усилены; unified CHECK меняет только provenance/control-manifest binding. Закрыто source rows: 0.
- По полному self-re-audit tree `6f4e3e19…` current Markdown population расширена до Git-visible tracked + non-ignored untracked candidate paths, чтобы новый документ до commit не обходил review-bound semantic gate. Три current `PROGRESS.txt` (`source-v4`, `engineering-donor-v1`, `engineering-tests-v1`) переведены на exact fail-closed key-set/value parity с запретом duplicate/malformed/extra/stale machine truth. Historical PROGRESS не переписывались; source/control/mapping/CHECK authorities не изменены; закрыто 0 source rows.
- По полному self-re-audit после tree `1fcb1b4…` natural-language contradiction guards переведены в fail-closed двухслойную модель: существующие semantic detectors сохранены, а exact bytes всей current Markdown population дополнительно закреплены review-bound baseline, который не обновляется generic root-manifest rebuild. Любая новая current prose требует отдельного semantic re-review; это закрывает неизвестные synonym/rephrase false-PASS без выдачи byte-baseline за semantic proof. Source/control/mapping/CHECK authorities не изменены; закрыто 0 source rows.
- По собственному полному re-audit candidate `09ea7b13…` закрыты два новых blocker-класса: contradiction-aware documentation guard расширен на весь current Markdown и новые естественные перефразирования current counts/roadmap/RESTORE/determinism/future-name claims; source-skeleton documentation больше не пинит исторические `72 exact / 2 refused` и `SRC-0001` как refused. `SRC-0001` отражён как exact pinned page-furniture exception, а supported/exact/refused population и свежесть `TEST-RESULTS.txt` теперь проверяются машинно current regression-тестом. Source/control/mapping/CHECK authorities не изменены; закрыто 0 source rows.
- По последнему полному recheck усилены contradiction-aware documentation guards ещё для семи естественных перефразирований: повторной активации Step 7B, отмены APPLY-adapters через «не предусмотрена», встроенного возврата исходной конфигурации после успешного APPLY, обесценивания donor RESTORE как прототипа, отрицания детерминизма через «не гарантирует одинаковый результат», произвольного имени будущего executable и того же post-APPLY recovery в Mermaid. Current project claims и machine/runtime authorities не менялись.
- По отдельной проверке устранена неоднозначность historical Step 7B.0: `step7b0/ARTIFACT-STATUS-RU.md` теперь явно `HISTORICAL_REFERENCE_ONLY`, `CURRENT_PROJECT_AUTHORITY=false`; внутренние `ACTIVE`/«текущий»/«следующий шаг» квалифицированы как historical snapshots и больше не могут конкурировать с `docs/ROADMAP-v3.tsv`/current machine authority. Исправлена ложная ссылка на `.git/info/exclude`; historical Build Contract/freeze bytes не переписывались.
- После полной проверки усилены fail-closed documentation guards для inline-code live counts, любого будущего `.sh` distributable-name pin, post-APPLY «возврата состояния» и отмены будущего этапа APPLY-adapters. Восемь невоспроизводимых B1.1b stage-sidecar сохранены byte-exact и явно классифицированы как historical records с машинной проверкой 40 несовпадений; frozen engineering-review README не изменён, а пять старых относительных ссылок разрешены через три явно маркированных companion-файла, не выдаваемых за original archive bytes. Source/mapping/CHECK semantics не изменены.
- Дочищена русская presentation-prose: исправлены остаточная грамматика disposition ledger, формулировки Gate 6, recovery method и RELEASE README, а также терминология элемента 9 в историческом status/changelog; технические identifiers и machine semantics не изменены.
- Исправлена визуальная семантика `PROJECT-MAP-v3.md`: принятый `DONOR_TO_V3_MAPPING` не только помечен `:::closed`, но и получает определение класса `closed` в том же Mermaid-блоке; также исправлена грамматика списка детерминизма в donor policy. Mapping/runtime semantics не изменены.
- Исправлен consolidated documentation parity review: machine roadmap теперь однозначно ставит `APPLY_SEMANTIC_CONTRACT=NEXT`, а Step 7B — `PAUSED_BY_CURRENT_DOCUMENT_APPLY`; устранены stale current-status claims, mapping в PROJECT-MAP помечен как `ACCEPTED + COMMITTED`, исправлена семантика `--report`, восстановлены ослабленные semantic guards документационных tests, исправлены доказанные ошибки перевода/грамматики. Mapping TSV и generated CHECK semantics не изменены.
- Актуализирован current status после принятого и опубликованного `DONOR_TO_V3_MAPPING`: mapping отмечен `ACCEPTED + COMMITTED` на commit `1db91b0…`, а следующим substantive этапом показан отдельный `APPLY semantic contract`; accepted CHECK semantics не менялись.
- После documentation parity recheck v3 исправлены три подтверждённых blocker-класса: удалены ручные live-count copies из root README/roadmap, `docs/ARCHITECTURE-DIAGRAMS.md` возвращён к роли historical donor runtime reference и явно не является future target model, а semantic guards усилены против rephrase false-PASS для недетерминированного distributable, обесценивания зрелого donor RESTORE и встроенного post-APPLY recovery. Operational RESTORE в v3 остаётся исключённым; post-APPLY recovery — `EXTERNAL_SNAPSHOT`.
- Русифицирована текущая редактируемая документация, которая оставалась полностью или преимущественно англоязычной: donor policy/index/test docs, Gate 6, gates-v2, release-v1, source-v4 scope и glyph-recovery method. Technical identifiers/tokens и 16 exact `donor_label` сохранены без перевода. Добавлен documentation regression, запрещающий полностью англоязычный current Markdown вне явно historical/frozen классов; normative semantics, mapping decisions и source-row closure не изменены.
- Исправлена function-level provenance donor-тестов для 10 доказанных FUNCTION-строк: `profile_allows` теперь ссылается только на профильный `TST-022`; добавлены byte-backed `TST-020` для `add_restore_irreversible`, `TST-027` для четырёх runtime-path APPLY-функций и `TST-022` для четырёх profile-aware additional-measures функций. `TST-028` у file-permission функций сохранён; historical-only `TST-010/TST-032` не добавлялись. Добавлен fail-closed regression на этот exact доказанный provenance-set без недоказанного универсального правила по упоминанию имени функции. Решения mapping, capability-граф и закрытие source rows не изменены.
- Исправлена stale capability-метка `CAP-12` у активной `MAP-FUNC-0016 profile_allows`: функция остаётся связана только с `CAP-14`, где её profile/policy gating действительно используется. Добавлен общий fail-closed regression: для каждой non-REJECT FUNCTION capability-метки обязан существовать current `MATURE_FAMILY -> FUNCTION` forward-edge; REJECT/historical function-side метки разрешены как исторические. Решения mapping и закрытие source rows не изменены.
- Исправлена полнота capability cross-reference: каждый текущий `MATURE_FAMILY donor_ref` теперь отражён в `mandatory_capability_refs` соответствующей FUNCTION-строки; добавлен общий fail-closed regression для направления `MAP-CAP -> MAP-FUNC`. Исторические function-side capability-метки не удаляются. Решения mapping и закрытие source rows не изменены.
- Исправлены три blocker’а mapping recheck: `PROGRESS.txt` синхронизирован с derived function index (`contracted=18`, `pending-review=208`); `MAP-CAP-12` теперь ссылается на donor-функции с фактической обработкой `DRY_RUN`; `MAP-FUNC-0269 restore_manifest_has_report_text` остаётся `REJECT`, потому что проверяет free-text `apply_report`, а не recorded pre-state, пригодный для transaction-local compensation. Решения остаются `REUSE=1`, `ADAPT=178`, `REJECT=91`, `DEFER=94`; закрытие source rows остаётся `0`.
- Исправление по fresh mapping review: source-faithful families теперь связывают `acquire_run_lock` с `apply-foundation/run-lock`, а `profile_allows` — с `apply-foundation/policy-layer-gating`; active/deferred mature families больше не ссылаются на rejected `run_apply_mode` или `restore_sysctl_network_module`; evidence `ENG-015` перепривязан к принятому `manifest_init`. Добавлены общие regressions, запрещающие non-historical contracts и active/deferred mature families зависеть от rejected function mappings. Решения/counts mapping и закрытие source rows не изменены.
- Исправлена provenance donor mapping tests: active `REUSE/ADAPT` rows больше не могут ссылаться на historical-only donor test contracts; `MAP-FUNC-0110..0113` больше не цитируют evidence `TST-010` для manifest resolution.
- Post-review semantic cleanup удалил остаточную operational RESTORE wording из принятого rationale `ADAPT`: `run_mode_step` больше не сохраняет restore sequencing; file/sysctl/service/group/cron/package mechanics описываются только как failed-uncommitted APPLY compensation. `ENG-012` имеет статус `historical-only`; active terminology `TST-002/TST-019` — transaction/package compensation. Решения/counts mapping и закрытие source rows не изменены.
- `DONOR_TO_V3_MAPPING` построен как отдельный machine-readable candidate перед roadmap step 8: покрыты 310/310 donor-функций, 38/38 donor test files и все 16 mandatory mature families; решения ограничены `REUSE | ADAPT | REJECT | DEFER`, normative effect=`NONE`, source rows closed=`0`. После APPLY-only correction решения: `REUSE=1`, `ADAPT=178`, `REJECT=91`, `DEFER=94`; статус `BUILT_AWAITING_REVIEW`; APPLY semantic contract ещё не разрешён, `RESTORE_OPERATIONAL_CONTOUR=EXCLUDED`. `password-policy-regression.sh` сохранён как `DEFER` donor для будущей corporate/APPLY-фазы.
- Архитектурное решение: будущая mutation-line становится APPLY-only. Пользовательский RESTORE исключён из roadmap; post-APPLY recovery закреплён за внешним snapshot rollback. Внутренний exact compensating rollback незавершённой APPLY-транзакции остаётся допустимым failure-handling, но не отдельным режимом RESTORE. Принятый `fstec-linux-2022` CHECK и tag `fstec-linux-2022-check-complete-v1` не изменяются.
- Исправлен DEV runner contract после SRC-0005 root-run correction: `tests/run-all.py` больше не ожидает два внутренних skip для `test_file_mode_owner_adapter.py` при EUID=0; self-test отдельно фиксирует ожидаемые `0` skip для этого теста даже при смоделированном root-run.
- Финальные blocker’ы all-40 robustness re-audit: regressions `SRC-0005` для parent traversal обычного пользователя больше не используют root-only skips и выполняются через непривилегированный child при запуске suite от root; explicit common-shell discovery для `SRC-0014` теперь включает стандартный Xonsh `~/.xonshrc` и regression, доказывающий обнаружение mode `0644` как нарушения.
- SRC-0014 robustness correction: explicit common-shell classifier теперь дополнительно покрывает Bash `.bash_login`, Linux-default Nushell config/autoload/history, Xonsh rc/history и Elvish rc/history; broad `*rc/*env` по-прежнему запрещён, custom/XDG override paths остаются через local inventory.
- Надёжность tests SRC-0006: прежнее увеличение timeout FIFO snapshot-drift с 5 до 20 секунд не устраняло scheduler race. Regression переработан без production hooks: первый snapshot и recheck используют две отдельные `FIFO-generation` с явным `threading.Event` handshake; mutation выполняется только после подтверждения первого snapshot, а `path:recheck-snapshot-changed` и `parent:recheck-snapshot-changed` дополнительно проверяются отдельными детерминированными reason-code tests. Production bytes и compliance semantics не изменены.
- Расширение robustness для SRC-0008: command `NOTBEFORE/NOTAFTER`, `Defaults runas_default` и явные overrides `case_insensitive_user` теперь работают fail-closed вместо over-approximation; default case-insensitive identity `ROOT` сохраняется.
- SRC-0008: all-40 robustness review дополнительно обнаружил, что `Defaults runas_default` может сделать неявный Runas_Spec non-root, тогда как checker предполагал root; current v1 теперь работает fail-closed с `ERROR` и имеет отдельный regression.

### Исправлено — сводные ретроспективные findings по 40 строкам

- Fresh all-40 robustness review: проверка parent-directory для `SRC-0006` больше не приравнивает каждый group/other write bit к доказанному непривилегированному write access. Однозначный non-root-owner/other `wx` остаётся `FAIL`; group-class `wx` без доказательства principal/ACL даёт fail-closed `ERROR`; write без search не выдаётся ошибочно за эффективную запись в каталог.

- Fresh all-40 robustness review: каноническая population `SRC-0011` сужена до `/var/spool/cron/crontabs`; прямые посторонние объекты в родительском `/var/spool/cron` больше не создают ложный `FAIL`. Regression явно фиксирует границу nonpopulation родительского spool.

- Исправлены подтверждённые source-faithfulness defects `SRC-0003`, `SRC-0008`, `SRC-0011`, `SRC-0012` и `SRC-0014`: PAM `-auth` short-circuit учитывается fail-closed; group password field больше не фиксируется в literal `x`; inline page token `4` удаляется только через exact pinned source boundary; user-cron v2 не рекурсирует в `atd` subtrees; exec population SRC-0012 исключает non-executable regular data; SRC-0014 использует explicit shell-artifact discovery без broad `*rc/*env` и включает Nushell config paths.

- Дополнительно исправлена population-semantics `SRC-0008`: host-qualified и membership/negation-зависимые sudo selectors больше не over-approximate в `VALUE/FAIL`; v1 возвращает `ERROR`, если exact applicability к текущему host/ordinary invoker/root runas не доказуема. Добавлены adversarial regressions для чужого host, group-based invoker/runas, command negation и digest applicability.
- `SRC-0034 / 2.5.11` возвращён `CLOSED → OPEN`: current `sysctl eq 2` не представляет source qualifier `после тестирования`; control/closure удалены, вместо выдумывания procedural semantics.
- Добавлены targeted negative-control regressions для каждого нового воспроизводимого counterexample. APPLY/RESTORE не добавляются.
- Ordinary-user permission regressions для SRC-0011 и SRC-0012 теперь выполняют непривилегированный child process даже при root-run test suite; silent `OK` через `geteuid()==0` больше невозможен.
- Текущее machine state после correction: `349` source rows; `39 CLOSED / 310 OPEN`; `49` canonical controls; `17` adapter kinds. `fstec-linux-2022` остаётся `39/40`, поэтому document-level CHECK acceptance ещё не достигнут.
- Последующим отдельным decision point `SRC-0034 / 2.5.11` снова закрыт, но уже source-faithful exact двухконтрольным набором: `sysctl kernel.randomize_va_space=2` + новый read-only kind `tested-setting-attestation`, который требует explicit local `TESTED-BEFORE-USE` для exact setting. Authority path/format — product mechanism представления procedural fact, а не придуманная методика тестирования ФСТЭК; missing/malformed authority даёт `ERROR`, explicit `NOT-TESTED-BEFORE-USE`/wrong setting — `FAIL`.
- Текущее machine state после SRC-0034 decision point: `349` source rows; `40 CLOSED / 309 OPEN`; `51` canonical controls; `18` adapter kinds. `fstec-linux-2022` machine-closed `40/40`, но document-level CHECK acceptance/milestone всё ещё запрещены до свежего adversarial recheck всех 40 source rows.

## Ретроспективное исправление — закрытие CHECK для fstec-linux-2022

- Исправлены независимо воспроизведённые blockers SRC-0001/0003/0005/0012/0013/0014/0015 без изменения source quotes и числа CLOSED rows. Для затронутых parameter kinds введены v2 adapter/semantic-contract identities; v1 bytes сохранены как предыдущие identities.
- SRC-0001 теперь отвергает NUL/CR до line parsing; SRC-0003 сохраняет literal `wheel:x:10:` и fail-closed prior PAM include/success-short-circuit semantics; `file-mode-owner` требует regular final object.
- SRC-0012 включает actual root-process `$PATH`, `/usr/local/lib*` и явно маркирует numeric `bits-clear 0022` как derived с justification; current generator v2 принимает schema-valid derived requirements.
- Semantic contract SRC-0012 синхронизирован с фактической v2 population: `canonical_population.library_roots` теперь явно включает `/usr/local/lib` и `/usr/local/lib64`; regression связывает contract roots с `CANONICAL_LIB_ROOTS`.
- SRC-0013 больше не исключает `nosuid`; SRC-0014/0015 больше не исключают service/system local accounts; SRC-0014 дополняет mandatory inventory dynamic shell-history/config discovery, включая unlisted `.zsh_history`.
- Добавлены negative-control regressions для каждого reproduced failure mode. APPLY/RESTORE не добавлялись; на этом промежуточном этапе machine state был `40/40` candidate до последующего retrospective recheck.

## SRC-0009 / 2.3.5 — read-only защита startup-файлов от записи

- Добавлен source-exact CHECK `startup-files-write-protection`: direct `/etc/rc0.d`…`/etc/rc6.d` file-like entries и direct `*.service` из `systemd-analyze unit-paths` проверяются только на `bits-clear 0002`.
- Merged-`/usr` unit-root aliases и regular targets дедуплицируются; masked `.service -> /dev/null` не превращает `/dev/null` в compliance target; recursive `.wants/.requires` references не входят в unit-file population. Dangling/special/discovery/snapshot ambiguity => `ERROR`.
- Read-only v3 VM matrix собрана на 7/7 установках: Ubuntu 22 FULL; Ubuntu 24.04.4 MINIMIZED/FULL; Ubuntu 26 MINIMIZED/FULL; Debian 12; Debian 13. APPLY/RESTORE отсутствуют.
- После шага: `349 / 40 controlled CLOSED / 309 OPEN`; canonical controls `50`; adapters `17`.

- Test harness SRC-0007 больше не требует `chown` или mapped UID/GID `1000:1000`: synthetic user-crontab остаётся владельцем текущего runner, а non-root bare-command семантика проверяется отдельным system-cron synthetic UID; production semantics не изменены.


### Добавлено — read-only CHECK SRC-0008 / 2.3.4

- `SRC-0008` переводится `OPEN → CLOSED` одним aggregate control `FSTEC-LINUX-2022-2.3.4-SUDO-ROOT-COMMAND-FILES-PROTECTION`; source `chown root` и `chmod go-w` представлены read-only predicates `st_uid == 0` и `(mode & 0022) == 0`.
- Population строится из exact reviewed active sudoers tree: `visudo` closure обязан побайтно/pathset совпасть с `/etc/securelinux-policy/sudoers-reviewed-policy-v1`, после чего pinned `/usr/bin/cvtsudoers -c /dev/null -e -f json` даёт alias-expanded representation.
- Rules, которые могут относиться к ordinary invoking user и допускают root runas, включаются; root-only invoking-user rules исключаются. `ALL`, regex/wildcard/directory paths, неоднозначная executable/arguments boundary и иные неограниченные формы дают `ERROR`, а не partial PASS. Spaced executable pathname не обрезается по первому пробелу.
- Для stable executable regular targets non-root owner или group/other write дают `VALUE/FAIL`; missing/nonregular/non-executable target, reviewed-policy/tool/JSON ambiguity и snapshot drift дают `ERROR`. Symlink проверяется по final target.
- Добавлены parameter kind, semantic contract, adapter и 20 targeted fixtures. Shebang execution chain теперь fail-closed (`ERROR`), чтобы sudo-authorized script не давал ложный PASS при непроверенном interpreter. APPLY/RESTORE и protected-state writes отсутствуют. После шага: `349 / 39 controlled CLOSED / 310 OPEN`; canonical controls `49`; adapters `16`.



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
- Targeted robustness check SRC-0004 выявил и исправил два fail-open дефекта implementation без изменения source semantics/contract identity: authority теперь отвергает nonstructural C0/DEL control bytes, а raw stdout `visudo` проверяется через pinned `/usr/bin/od` до Bash line parsing, поэтому NUL больше не может быть silently stripped command substitution.
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
- Layout assumptions сверены отдельно на Ubuntu 22 FULL, Ubuntu 24 MINIMIZED/FULL, Ubuntu 26 MINIMIZED/FULL, Debian 12 SERVER и Debian 13 SERVER; эти наблюдения не расширяют current product target.

### Добавлено — SRC-0003 / 2.2.1: ограничение su через pam_wheel

- `SRC-0003` переводится `OPEN → CLOSED` одним aggregate control `FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS`.
- Новый read-only kind `pam-wheel-access` проверяет активную source-exact семантику `auth required pam_wheel.so use_uid` в `/etc/pam.d/su` и local запись `wheel` в `/etc/group`.
- `root` обязателен непосредственно в members field; placeholder `<user list>` задаётся только явной local authority `/etc/securelinux-policy/wheel-users.allowlist-v1`, без вывода из `sudo`, `admin`, `WHEEL_USERS` или `SUDO_USER`.
- GID `10` не превращён в portable compliance condition; числовой GID валидируется синтаксически, а relevant PAM/group/authority ambiguity даёт fail-closed `ERROR`.
- Семь ранее собранных privileged read-only VM evidence имеют integrity `7/7`: во всех active pam_wheel=0 и local wheel=0 при установленном module; это definitive baseline `FAIL`, но не расширение product target.
- После шага: `349 / 35 controlled CLOSED / 314 OPEN`; canonical controls `45`; adapters `12`. Formal Gate5 probe-results, APPLY и RESTORE не создаются.

### Добавлено — SRC-0002 / 2.1.2 read-only CHECK root-login SSH

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

### Добавлено — единый CLI / QUICK START v1

- Добавлен tracked user-facing `securelinux-policy.sh` с sidecar SHA-256; обычному пользователю для current CHECK больше не требуется запускать Python generator.
- Current generator — `product/generate-product-check-v2.py`; v1 сохраняется как предыдущая deterministic generator identity.
- `--check` по умолчанию выдаёт выровненную таблицу с фиксированными колонками `RESULT`, `CONTROL`, `VALUE / DETAILS`; длинные semicolon-delimited details переносятся под третьей колонкой без внешней `column`.
- Добавлены `--check --failed`, `--check --format raw`, `--check --format json`, `--report`, `--version`; `--build-info` и `--provenance` сохранены.
- Raw mode сохраняет wire-format `SLP-CHECK-V1`/`SLP-SUMMARY-V1`; JSON mode вводит `SLP-REPORT-V1`.
- `--apply` и `--restore` зарезервированы как fail-closed `NOT_IMPLEMENTED` stubs с RC=2; mutation implementation и host-state changes не добавлены.
- Расширен `tests/product-v1/test_product_generator.py`: byte-exact rebuild parity unified CLI, pretty/raw/json, sidecar/mode и fail-closed stubs без увеличения tracked test-file population.
- Source index/controls/closure не меняются: этим product-interface шагом закрыто **0** source rows; состояние остаётся `349 / 33 controlled CLOSED / 316 OPEN`, canonical controls `43`, adapters `10`.

### Добавлено — SRC-0015 / 2.3.11 CHECK режима домашних каталогов пользователей

- `SRC-0015` переводится `OPEN → CLOSED` одним aggregate control `FSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE`.
- Exact source command `chmod 700 домашняя_директория` представлен как строгий `mode == 0700`; `0750`, special bits и другие mode значения не считаются эквивалентными.
- Population пользователей повторно использует уже принятую для соседнего SRC-0014 трактовку той же фразы «домашним директориям пользователей»: локальный `/etc/passwd`, `root` плюс normal interactive local accounts по `UID_MIN` из `/etc/login.defs`; service-account state directories исключены.
- Отсутствующий home path не объявляется нарушением mode: 2.3.11 не требует создания home directory. Existing symlink/non-directory/stat ambiguity даёт fail-closed `ERROR`.
- Owner/group и sensitive-file modes не добавляются: первое отсутствует в 2.3.11, второе уже относится к SRC-0014.
- Семь privileged read-only VM runs подтверждают selector/layout assumptions: Debian 12 `SERVER` и Debian 13 `SERVER` имели оба selected homes `0700`; Ubuntu 22/24/26 в проверенных установках имели `/root=0700`, `/home/user=0750`. Observed modes являются evidence, а normative expected остаётся exact `0700` из source.
- После шага: `349 / 33 controlled CLOSED / 316 OPEN`; canonical controls `43`; adapters `10`. Formal Gate5 probe-results, APPLY и RESTORE не создаются.

### Добавлено — SRC-0014 / 2.3.10 CHECK чувствительных файлов в домашних каталогах

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
- VM evidence v2 собрано одним batch на Ubuntu 22 `FULL`, Ubuntu 24 `MINIMIZED/FULL`, Ubuntu 26 `MINIMIZED/FULL`, Debian 12 `SERVER`, Debian 13 `SERVER`. Во всех семи runs `GO_W=0`, scan errors `0`; число effective SUID/SGID regular files различается по составу установки.
- После batch: `349 / 31 controlled CLOSED / 318 OPEN`; canonical controls `41`; current adapters `8`. CHECK остаётся read-only; APPLY/RESTORE и formal Gate5 probe-results не создаются.

### Добавлено — SRC-0012 / 2.3.8: проверка стандартных системных путей

- `SRC-0012` переводится `OPEN → CLOSED` одним aggregate control `standard-system-paths-mode`.
- Canonical population охватывает `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64` и `/lib/modules/<текущее-ядро>` с поддержкой merged-`/usr` aliases и дедупликацией underlying targets.
- Для executable roots проверяются regular targets всех non-directory entries; для библиотек — `*.so`, `*.so.*`, `*.a`; для модулей ядра — `*.ko`, `*.ko.*`.
- Источник 2.3.8 не задаёт числовой mode; минимальный operational criterion `mode & 0022 == 0` зафиксирован как инженерная интерпретация, согласованная с pinned donor и соседними 2.3.2/2.3.9. Более строгие owner/group/mode требования не добавлены.
- Parent-directory condition из donor не переносится: оно явно содержится в 2.3.2, но отсутствует в 2.3.8. Traversal/stat/readlink ambiguity даёт fail-closed `ERROR`.
- VM layout evidence собрано отдельно для Ubuntu 22 `FULL`, Ubuntu 24 `MINIMIZED/FULL`, Ubuntu 26 `MINIMIZED/FULL`, Debian 12 `SERVER` и Debian 13 `SERVER`; это evidence assumptions, а не расширение `SUPPORTED` target.
- После batch: `349 / 30 controlled CLOSED / 319 OPEN`; canonical controls `39`; current adapters `7`. CHECK остаётся read-only; APPLY/RESTORE и formal Gate5 probe-results не создаются.

### Изменено — русский язык актуальной v3-документации

- Человекочитаемый текст действующего контура `checker/gates-v3`, контракта значений наблюдений и соответствующего README тестов переведён на русский язык.
- Технические идентификаторы, имена полей, wire/protocol-маркеры и значения схем сохранены без перевода.
- Добавлена regression-проверка, запрещающая возврат прежних английских абзацев в этом актуальном v3-контуре.
- Исторические v1/v2 и pinned donor/evidence артефакты этим изменением не переписываются.

### Добавлено — SRC-0026 / 2.5.3 CHECK параметра kernel-cmdline для debugfs

- Закрыт `SRC-0026 / 2.5.3`: `debugfs=no-mount (по возможности off)` представлен одним `kernel-cmdline` control с `op=one-of` и ordered value `off|no-mount`; `off` сохраняется как preferred, оба source-разрешённых значения дают PASS.
- `kernel-cmdline` product adapter/semantic contract подняты до v2: `eq`/`present` совместимы с v1, добавлен read-only `one-of`, конфликтующие дубли остаются `ERROR`, APPLY/RESTORE не добавлены.

### Добавлено — SRC-0034 / 2.5.11 CHECK sysctl для ASLR

- `SRC-0034` переводится `OPEN → CLOSED` одним существующим `sysctl` control.
- Source-exact requirement `kernel.randomize_va_space = 2` представлено без расширения semantics как `sysctl / eq / integer 2`.
- Новый adapter/contract не создаётся; используется current `product-sysctl-check-v2`.
- После batch: `349 / 27 controlled CLOSED / 322 OPEN`; canonical controls `36`; current adapters `5`.
- CHECK остаётся read-only; APPLY/RESTORE и formal Gate5 probe-results не создаются.

### Добавлено — SRC-0001 / 2.1.1 CHECK состояния паролей локальных учётных записей

- `SRC-0001` переводится `OPEN → CLOSED` одним aggregate control.
- Новый kind `local-account-password-state` использует локальную population `/etc/passwd` и source-anchored state `/etc/shadow`.
- Для каждого локального пользователя matching shadow password field должен быть непустым; empty field → `VALUE/FAIL`.
- Missing/unreadable/symlink/malformed/duplicate account-state mapping → fail-closed `ERROR`; partial PASS запрещён.
- Adapter read-only: никаких `passwd`/`usermod`/`chpasswd`/APPLY/RESTORE.
- После batch: `349 / 26 controlled CLOSED / 323 OPEN`; canonical controls `35`; current adapters `5`.

### Исправлено — SRC-0001: граница source quote

- `source_skeleton_generator.py` получил одну exact pinned exception для `SRC-0001`: trailing page token `3` после `/etc/shadow.` удаляется как page furniture только для этой строки.
- Generic удаление bare integers по-прежнему запрещено; `SRC-0133` остаётся fail-closed `REFUSED`.
- Canonical quote SHA-256 для `SRC-0001 / 2.1.1` после удаления page furniture: `799b85637928264e6f43d5e32d8cc6b48af6694e30f6fbf5e4c6ddef3a207f3b`.
- `tests/source-skeleton-v1/TEST-RESULTS.txt` синхронизирован с current regression (`pilot=34`, `exact=73`, `refused=1`).
- Coverage не меняется: `349 / 25 controlled CLOSED / 324 OPEN`, controls `34`.

### Добавлено — SRC-0010 / 2.3.6 CHECK набора системных cron-файлов

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
  источником истины продукта.

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

### Добавлено — read-only CHECK командной строки ядра

- Добавлен новый current parameter kind `kernel-cmdline` для фактической
  загрузочной строки `/proc/cmdline`.
- Semantic contract `kernel-cmdline-check-semantic-v1` поддерживает:
  - `eq` — точный токен `key=value`;
  - `present` — точный отдельный токен.
- Adapter `product-kernel-cmdline-check-v1` только читает `/proc/cmdline`.
  GRUB, загрузчик, APPLY и RESTORE не изменяются.
- Отсутствие требуемого boot token — наблюдаемое `VALUE/FAIL`, а не
  `NOT_FOUND`; конфликтующие значения одного key дают `ERROR`.

### Добавлено — пакет exact boot-token

- `SRC-0018 / 2.4.3` → `init_on_alloc=1`.
- `SRC-0019 / 2.4.4` → отдельный флаг `slab_nomerge`.
- `SRC-0020 / 2.4.5` → `exact-control-set`:
  `iommu=force`, `iommu.strict=1`, `iommu.passthrough=0`.
- `SRC-0021 / 2.4.6` → `randomize_kstack_offset=1`.
- `SRC-0022 / 2.4.7` → `mitigations=auto,nosmt` для current x86_64 target.
- `SRC-0024 / 2.5.1` → `vsyscall=none`.
- `SRC-0032 / 2.5.9` → `tsx=off`.
- Corpus после batch: `349 / 24 controlled CLOSED / 325 OPEN`;
  канонические controls: `28`.

### Проверка инженерного донора

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

### Проверено

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

### Добавлено — source-faithful нижняя граница sysctl / SRC-0033

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

### Изменено — generated coverage

- `docs/fstec-coverage.md` теперь содержит генерируемую таблицу по каждому
  `source_id`: всего / controlled CLOSED / disposed CLOSED / OPEN /
  канонические controls.
- Таблица устраняет двусмысленность общего знаменателя 349, не утверждая, что
  каждая `OPEN` строка обязана стать host CHECK.
- Текущий corpus: `349 / 17 controlled CLOSED / 332 OPEN`; controls: `19`.

### Исправлено — текущая документация / regressions

- `product/README.md` больше не описывает уже завершённый SRC-0040 как следующий
  шаг и фиксирует current sysctl adapter v2.
- Source-skeleton/source-parity/roadmap docs больше не пинят исторические
  `18/18` или `8/8`; population выводится из current manifests.
- Schema/runtime parity добавляет positive `sysctl ge integer` и negative
  случаи `sysctl ge string`.
- Product adapter regression покрывает equal/greater/less, отрицательные и
  случаи с 200-значной нижней границей.

### Проверено

- Проверка Source-skeleton: `19/19`.
- Production-паритет регенерации блока `source:`: `19/19`.
- Schema/runtime differential parity: PASS; real jsonschema остаётся
  обязательным RELEASE gate.
- Product sysctl adapter v2 и generator regressions: PASS.
- Gate 1/3/4 должны пройти на 19 controls; Gate 2 ожидаемо остаётся FAIL из-за
  332 OPEN; formal Gate 5 без `probe-results` остаётся fail-closed.
- Закрыто строк source index этим шагом: **1**.

## [0.0.18] — 2026-08-20

### Исправлено — конечная граница source / SRC-0040

- `fstec-linux-2022` source-skeleton удаляет точный terminal token
  `________________________` только как exact EOF page furniture после `2.6.6`.
- `SRC-0040 / 2.6.6` переведён `OPEN → CLOSED`; canonical quote имеет SHA-256
  `f80b7efd3664eb281eb19792dcfccaa16d2e712980e7d9fe4717b7e25924cc0d`.

### Добавлено — SRC-0040 / CHECK-18

- Добавлен `FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE`:
  `sysctl / fs.suid_dumpable / eq / 0`.
- Используется существующий read-only sysctl adapter без расширения semantic contract.
- Корпус: `349 / 16 controlled CLOSED / 333 OPEN`; controls: `18`.

### Исправлено — regression semantics

- Project-integrity больше не пинует исторические числа `17 / 15 / 334`.
- `product/SHA256SUMS` получил обратную проверку полноты.
- Local-manifest target population согласована с root-manifest policy:
  tracked + nonignored untracked, чтобы новый control проверялся до commit.
- Source-parity fixture report сохраняет фактическое `positive=5`; production
  parity проверяется отдельно `18/18`.

### Проверено

- Проверка Source-skeleton: `18/18`.
- Production-паритет регенерации блока `source:`: `18/18`; fixture harness `positive=5`.
- Gate 1/3/4 PASS; Gate 2 ожидаемо FAIL из-за 333 OPEN; Gate 5 остаётся fail-closed.
- Project-integrity, DEV 21/21, RELEASE и root manifests PASS.
- CHECK-18 выполняется read-only; formal Gate5 probe-results не создаются.
- Закрыто строк source index этим шагом: **1**.

## [0.0.17] — 2026-08-20

### Исправлено — локальные SHA256SUMS / errata ACTIVE checker evidence

- Исправлен stale SHA `product/README.md` в `product/SHA256SUMS`; product bytes
  и source/canonical semantics этим исправлением не меняются.
- `ACTIVE-CHECKER-V3-NO-VM.txt` и
  `checker/gates-v3/ACTIVE-NO-VM-EVIDENCE.txt` перестраиваются из фактического
  current checker run и больше не содержат историческое состояние 5/344.
- `tests/project-integrity-v1/test_root_manifests.py` расширен с
  `tests/**/SHA256SUMS` на repository-wide current nested manifests; ровно две
  historical donor runtime entries разрешены только как pinned exceptions с
  точными manifest/path/SHA; отдельно требуется byte-exact freshness обоих
  снимки `ACTIVE` gates-v3.
- Corpus остаётся `349 / 15 controlled CLOSED / 334 OPEN`; canonical controls:
  `17`; закрыто строк source index этим шагом: **0**.

### Проверено

- До mutation repository-wide local-manifest scan обязан находить ровно известный
  stale `product/SHA256SUMS -> README.md`, иначе шаг fail-closed останавливается.
- После исправления current local-manifest scan: 0 ошибок; historical donor
  exception population: ровно 2 pinned entries.
- Оба `ACTIVE` snapshots побайтово равны свежему gates-v3 checker stdout для
  текущего состояния 17/15/334.
- Базовая линия DEV: 21/21 PASS; базовая линия RELEASE: PASS.
- Root manifests: 742/743 PASS; Gate 2 и Gate 5 остаются ожидаемо FAIL по
  текущим контрактным причинам.

## [0.0.16] — 2026-08-20

### Добавлено — пакет расширения sysctl exact-eq / CHECK-17

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

### Изменено

- Состояние корпуса: `349 / 15 controlled CLOSED / 334 OPEN`; canonical controls: `17`.
- Generated README/map/coverage перестроены из machine truth.
- PRIMARY map сохраняет текущую точку `systematic FSTEC expansion`, но отдельно
  фиксирует завершённый exact-eq batch и CHECK-17 как уже пройденный checkpoint.
- `docs/ROADMAP-v3.md` и TSV больше не закрепляют имя будущего артефакта
  `securelinux-ng.sh`; будущие steps 9–11 явно относятся к APPLY/RESTORE и
  финальной упаковке, а не к уже существующим CHECK adapters/generator.
- Документы source-skeleton/source-parity больше не содержат быстро устаревающие
  ручные значения corpus progress; current population определяется из manifests.

### Проверено

- Gate 1/3/4 проходят на 17 controls; Gate 2 ожидаемо `FAIL` только из-за 334
  оставшихся `OPEN`; formal Gate 5 без `--probe-results` остаётся fail-closed.
- Паритет регенерации блока source: `controls=17 supported=17 matched=17`.
- Проверка pilot source skeleton: `controls=17 mismatches=0`.
- Product generator regression закрепляет exact semantics всех шести controls
  этого batch и сохраняет запрет на mutating shell tokens.
- CHECK-17 выполняется read-only; host-specific вывод сохраняется как derived
  evidence и не создаёт formal Gate 5 `probe-results`.
- Закрыто строк source index этим шагом: **6**.

## [0.0.15] — 2026-08-20

### Исправлено — errata загрязнения TEST SHA256SUMS cache-данными

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

### Добавлено — SRC-0005 / CHECK-11

- `SRC-0005 / 2.3.1` представлен `exact-control-set` из трёх canonical controls:
  - `FSTEC-LINUX-2022-2.3.1-PASSWD-MODE` → `/etc/passwd`, `mode eq 0644`;
  - `FSTEC-LINUX-2022-2.3.1-GROUP-MODE` → `/etc/group`, `mode eq 0644`;
  - `FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX` → `/etc/shadow`, `mode bits-clear 0077`.
- Все три controls используют существующий read-only
  `product-file-mode-owner-check-v1`; новый adapter не создавался.
- `chmod go-rwx /etc/shadow` намеренно не усилен до неследующего из source anchor
  равенства `/etc/shadow = 0600`.

### Изменено

- `SRC-0005` переведён `OPEN → CLOSED`; прогресс корпуса теперь `349 / 9 / 340`.
- `CONTROL-MANIFEST.tsv` содержит 11 canonical controls; closure contract содержит
  9 контролируемых строк source.
- Generated README/map/coverage перестроены из machine truth; CHECK-11 завершает
  этот точечный expansion step, после чего current checkpoint — systematic FSTEC expansion.

### Проверено

- Gate 1/3/4 проходят на 11 controls; Gate 2 остаётся ожидаемо красным только из-за
  340 оставшихся `OPEN`; formal Gate 5 без `--probe-results` остаётся fail-closed.
- Паритет регенерации блока source: `controls=11 supported=11 matched=11`.
- Проверка pilot source skeleton: `controls=11 mismatches=0`.
- Product generator regression больше не пинует историческое число 8 и отдельно
  проверяет exact SRC-0005 file-mode semantics.
- Historical gates-v1 regression теперь явно требует fail-closed на новом
  `file-mode-owner/bits-clear`, вместо ложного требования принять current v3 corpus.
- CHECK-11 выполняется read-only на target host; host-specific summary сохраняется
  только как derived evidence и не подменяет formal Gate 5 `probe-results`.
- Закрыто строк source index этим шагом: **1**.

## [0.0.13] — 2026-08-20

### Исправлено — ERRATA базовой линии документации

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
  будущее.
- Закрыто строк source index: **0**.

### Проверено

- Roadmap regression проверяет порядок
  `CHECK-8 → TEST BASELINE → DOCUMENTATION BASELINE → SRC-0005 → CHECK-11`.
- Current-status regression требует, чтобы на этом checkpoint `SRC-0005`
  оставался `OPEN`, ещё не имел canonical controls, при этом
  `file-mode-owner` adapter и tracked generator уже существовали.
- Documentation regression запрещает прежний current-node Step 7B и future
  labels для уже реализованных CHECK adapters/generator.

## [0.0.12] — 2026-08-20

### Добавлено — базовая линия тестирования

- Добавлен tracked `tests/run-all.py` как canonical точка запуска tracked
  регрессии Python.
- Test population разделена на DEV и RELEASE; release dependency объявлена в
  `requirements-release.txt` как `jsonschema>=4.10.3`.
- Добавлен `tests/run-all-selftest.py`, проверяющий runner RC `0/1/2/3`.
- Runner требует доказательство фактического выполнения test-file, запрещает
  неожиданные skip, `ResourceWarning` и untracked `test_*.py`.

### Исправлено — базовая линия тестирования

- Удалены historical numeric pins на `controls=5` и `74/72`; ожидаемые
  populations берутся из current machine truth.
- Четыре roadmap regressions больше не пинуют exact русские status-фразы и
  число Mermaid blocks.
- Устранены четыре `ResourceWarning` в file-mode-owner regression.
- `PROJECT-MAP-v3.md` синхронизирован с current product CHECK line.
- Закрыто строк source index: **0**.

### Добавлено — базовая линия документации

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

### Изменено — базовая линия документации

- Root README перестроен в product-facing форму: назначение, generated current
  status, quick start, гарантии с проверками, policy layers, coverage,
  compatibility, architecture, test model, integrity, boundaries и docs index.
- Current numeric coverage удалён из вручную поддерживаемых Mermaid nodes;
  текущие числа находятся только в machine-owned blocks/generated coverage.
- `product/README.md`, controls README, `tests/README.md` и
  `docs/testing-strategy.md` актуализированы под current product/test model.
- Закрыто строк source index: **0**.

### Проверено

- TEST BASELINE A1 на development host: DEV `20/20 PASS`, RELEASE `PASS`;
  release interpreter использовал `jsonschema 4.10.3`.
- A1 local CHECK-8 diagnostic воспроизвёл ровно один execution `ERROR`:
  `FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN`,
  `/proc/sys/net/core/bpf_jit_harden`, режим `0600`, чтение `EACCES`/errno 13.
  Это host evaluability observation, не defect canonical control и не
  доказательства совместимости.
- Documentation renderer проходит `--write → --check`; documentation regression
  проверяет exact parity и отсутствие известных stale product-status strings.
- Documentation Baseline добавляет один DEV test-file; успешный commit требует
  полного current DEV PASS и RELEASE PASS.

### Документация

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
- SHA-256 генератора: `cc75c216e685c792e5dd14a1b056e9f8f6602f772bc8622f04be95bc88d501d3`.
- SHA-256 реестра адаптеров: `e1fabfad1cd66770783b4096f7cdaebe562b5861e43d71e9f9bc55df0dcbbc2f`.
- SHA-256 сгенерированного CHECK: `cc58acae18a79b92c7d4b234dc0505bb065a42209392d7c7541e21ea328511d5`.
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
- Самотест адаптера sysctl: `PASS`.
- Корневые манифесты после Step 2:
  `PROJECT_FILES_ENTRIES=719`, `SHA256SUMS_ENTRIES=720`, `--check=PASS`.
- Гейты после Step2: `GATE0 PASS`, `GATE1 PASS checked=8`,
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
- Гейты после Step1: `GATE0 PASS`, `GATE1 PASS checked=8`,
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
  16 статических предусловий, SHA-bound member/admission; элемент 9 закрыт
  политика наблюдения fail-closed.
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

- Несколько R3-проверок подтвердили исправление `S7A-R2-B01`;
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
  первичный источник corporate.
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
- После R3 Step 7A ещё не объявляется принятым; Step 7B и первый
  real disposition заблокированы.
- Quote-anchor policy не меняется:
  `REQUIRE_BEFORE_FIRST_REAL_DISPOSITION`.

### Исправлено — Step 7A R2: закрытая схема строк disposition ledger

- Проверка R1 нашёл обход closed-schema: при корректном шестиколоночном
  заголовке `csv.DictReader` принимал строку данных с седьмым значением и
  помещал его под ключ `None`; loader это значение игнорировал.
- Loader теперь проверяет **арность каждой физической TSV-строки**: ровно шесть
  значений, соответствующих объявленным полям ledger.
- Добавлены две постоянные negative fixtures:
  `extra_data_field` (7 значений) и `short_data_row` (5 значений).
- Ошибка короткой строки теперь диагностируется как нарушение контракта, а не
  как внутренний `NoneType.strip()` через общий exception path.
- После R2 Step 7A не объявляется принятым до повторной проверки.
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
  в режиме fail-closed.
- Controls, строки source-v4, семантика checker, probes, evidence и source PDF
  не изменялись; закрыто 0 строк FSTEC source index.

### Исправлено — очистка контракта наблюдений type/boolean

- Удалено случайное глобальное преобразование строк `"true"` / `"false"` в boolean
  внутри `_expected_compliance`.
- Семантический `expected.type` control отделён от wire-кодирования
  `VALUE.value` пробой.
- Сохранено wire-поведение sysctl: integer/string-наблюдения передаются как JSON-строки;
  boolean для sysctl по-прежнему запрещён `KIND_RULES`.
- Для будущих `systemd-unit-state` и `package-presence` закреплён точный boolean
  wire-формат: только JSON boolean, не строки в кавычках и не `0/1`.
- Оба будущих runner остаются нереализованными; определение формата не заявляет
  их исполнимость для Gate 5.
- Отображение boolean-наблюдений file-kv явно отложено до появления дизайна
  file-kv probe с source-specific текстовой семантикой.
- `KIND_RULES` и сгенерированный `CONTROL-SCHEMA.json` не изменены.
- Добавлены целевые regression-тесты контракта наблюдений.
- Roadmap продвинут к обязательному release-gate с реальным `jsonschema`.
- Строки source index этим изменением не закрывались.

### Исправлено — findings аудита project map и manifests чистого checkout

- Исправлен граф текстового корпуса: обычный `pdftotext/norm-v1` покрывает 10 закреплённых
  PDF, а glyph recovery является отдельной ветвью PDF-origin ровно для двух
  документов и отдельно нормализуется в `recovered-v1/norm-v1`.
- В Gate 1 добавлен выбор корпуса по `SOURCE-INDEX.text_quality` и точным
  извлечение/восстановление manifests.
- Добавлены `CLOSURE-CONTRACT.tsv` и явные disposition+reason как два механизма
  закрытия Gate 2.
- Добавлен differential-набор schema/runtime и отделён от generation parity Gate 0;
  обязательный реальный `Draft202012Validator` остаётся следующим пунктом
  release-validation roadmap после очистки type/boolean.
- Gate 5 ограничен pilot из пяти sysctl на одной VM, а Gate 6 — текущим
  каталогом evidence `sysctl-v1`.
- В project map добавлены provenance audit/Git/bundle и воспроизводимость из
  чистого checkout.
- Прямая импликация index→control заменена пунктирной связью «в настоящее время
  вручную».
- Будущая ветвь adapter соединена с явным нормативным входом controls.
- Исправлены корневые manifests: Git-ignored runtime state донора исключается
  каноническим builder Git-visible population.
- Удалён stale status-текст README/ROADMAP; единственный текущий этап —
  `type/boolean contract cleanup`.
- Controls, строки source index, семантика checker, probes, source PDF и
  объекты engineering-donor не изменялись.

### Добавлено — нативная для v3 архитектурная карта проекта

- `docs/PROJECT-MAP-v3.md` добавлен как основная визуальная карта текущего
  проекта SecureLinux-Policy v3.
- Карта охватывает sources, normalization/recovery, source-v4, controls,
  Gates 0–6, reference-VM evidence, policy layers, поток engineering donor и
  будущую детерминированную сборку.
- Ровно один узел roadmap отмечен текущим: `type/boolean contract cleanup`.
- Существующий `docs/ARCHITECTURE-DIAGRAMS.md` явно переклассифицирован как
  donor runtime reference, а не основная project map v3.
- Нормативное/runtime-поведение не изменено.

### Добавлено — визуальные архитектурные схемы

- Добавлены три Mermaid-схемы, отображаемые GitHub: режимы CLI/runtime,
  поток module/additional-measures/restore и поток apply/manifest/restore.
- Они были обозначены как целевая runtime-архитектура, унаследованная от engineering
  donor, а не как заявление, что каждый runtime-механизм уже реализован.
- README содержит прямую ссылку на отображаемые схемы.
- Нормативное/runtime-поведение не изменено.

### Добавлено — Gate 6 `evidence_binding`

- Добавлен checker привязки evidence с закрытой схемой для фактического
  evidence эталонной VM `sysctl-v1`.
- Gate 6 проверяет набор checksum evidence, схему metadata VM, текущие
  hashes probe/plan, оба result hash и корневые `read_only=true` в результатах.
- Добавлены положительный и девять отрицательных regression-cases.
- Gate 6 явно выводит `VM_ORIGIN_ATTESTATION=NOT_PROVEN`: он доказывает
  integrity/binding, а не криптографическую аттестацию происхождения от VM.
- Это изменение не закрывает строки FSTEC/corporate source.
- Следующий шаг roadmap: `type/boolean contract cleanup`.

### Закреплено — политика переноса инженерного донора

- SecureLinux-NG v16.2.11 формально закреплён как engineering donor, а не как
  нормативный источник истины.
- Зрелые механизмы донора обязаны пройти через
  `DONOR_TO_V3_MAPPING -> REUSE|ADAPT|REJECT|DEFER` до работ над apply/restore
  contract и implementation-adapter.
- `DONOR_TO_V3_MAPPING` стал обязательным precondition шага 8 roadmap.
- Сам donor mapping закрывает ноль строк FSTEC/corporate source index.
- Явно защищённые donor families включают preflight, transactional apply,
  manifest/restore, атомарные записи, fail-closed backup, delta пакетов,
  сохранение более строгих sysctl, изолированный sysctl, повторное применение network-online, dry-run,
  run locking, layer/profile separation и сохранённые regression contracts.
- Итоговый `securelinux-ng.sh` остаётся детерминированным generated artifact с
  machine-checkable provenance для каждого выдаваемого блока.

### Зафиксировано — состояние Step 5

- Сохранены три записи verdict `ACCEPT` для reference VM Step 5.
- Сохранено состояние: 349 всего / 5 controlled CLOSED / 344 OPEN.
- Добавлен authoritative forward roadmap.
- Следующий разрешённый engineering step: Gate 6 `evidence_binding`.

### Добавлено — reference VM Gate 5 evidence

- Выполнен фактический read-only `sysctl-v1` probe на Ubuntu 24.04.4 LTS
  в минимальной установке (`testmin`, kernel `6.8.0-134-generic`).
- Непривилегированный прогон: 5 результатов, 4 `VALUE`, 1 `ERROR`;
  `/proc/sys/net/core/bpf_jit_harden` имеет mode `0600 root:root` и обычному
  пользователю не читается. Этот результат сохранён как environment evidence.
- Повторный read-only прогон через `sudo`: 5 `VALUE`, 0 `NOT_FOUND`,
  0 `ERROR`, 4 несоответствующих наблюдения.
- Активный checker с реальным evidence:
  `GATE5=PASS checked=5 value=5 not_found=0 noncompliant=4 errors=0`.
- `OVERALL=FAIL` ожидаем и вызван Gate 2: 344 source-index rows остаются OPEN.
- SHA-256 привилегированного evidence:
  `43c574a68d3478f35e4c7a5a50571ab4408d43a3e3a3cfed9ac3f50fbb1fc29c`.
- SHA-256 непривилегированного evidence:
  `53e3bea08d07bcdf4210d125a026c1d1a4ce1481b2ee7d1415d4baf112389203`.

### Добавлено — engineering donor preservation

- Полный SecureLinux-NG v16.2.11 test/development snapshot сохранён byte-for-byte
  и разложен в inspectable archive; source ZIP SHA-256
  `1b25f554a5ad1509037aa9613b7851a595159fd44291913cc2dba63280e50494`.
- Добавлен `index/engineering-tests-v1`: 38 test-файлов, 36 focused regressions,
  36/36 smoke wiring, 32 generalized engineering test contracts и отдельная
  таблица VM-evidence донора.
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

### Ожидает выполнения

- Проверка Step 0–5 с фактическим reference-VM evidence.
- Дальнейшее закрытие source-index rows только после прохождения
  соответствующих gates.

## [0.0.5-r3] — 2026-08-14

### Исправлено — третья серия замечаний

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

### Добавлено

- 16 граничных случаев с CR/LF в дифференциальной матрице (всего 50).
- `PatternSemanticsTests`: для каждого шаблона fullmatch и search обязаны
  совпадать на 22 пограничных строках.
- `ParserInvariantTests`: управляющий символ в скаляре не проходит парсер.
- Прогон настоящим `jsonschema.Draft202012Validator`, когда библиотека
  установлена; при её отсутствии тесты пропускаются явно.

### Исправлено

- `README.md`: устаревший SHA checker-v3; добавлен SHA схемы и правило,
  что схема не редактируется вручную.

### Сохранено

- Pilot controls: 5, не изменялись. `index/source-v4`: не изменялся.
- Sysctl probe: не изменялся. 349 / CLOSED 5 / OPEN 344.
- Evidence эталонной VM: `NOT_YET_PROVIDED`.

### Проверяющий модуль

`checker/gates-v3/checker.py`

SHA-256:

`4c6012b7541923a682b6bb78bf5d8ccf5b241da54ecaa601f2c9d5479eafb5a6`

## [0.0.5-r2] — 2026-08-14

### Исправлено — вторая серия замечаний

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

### Добавлено

- `tests/gates-v3/test_schema_runtime_parity.py` — два независимых
  предохранителя: генерационный паритет и дифференциальная матрица из 34
  записей по всем восьми kinds в обе стороны (accept и reject).

### Сохранено

- Pilot controls: 5, не изменялись.
- `index/source-v4`: не изменялся.
- Sysctl probe: не изменялся, SHA `e454d691e6433c2bfb8588884575fa4f5b880a6a0cb328682a5dbe1135dabd5e`.
- Population source: 349. Статусы: CLOSED 5 / OPEN 344.
- Evidence эталонной VM: `NOT_YET_PROVIDED`.

### Проверяющий модуль

`checker/gates-v3/checker.py`

SHA-256:

`0397a5e64a2e859bba1791a844feacad094120ee3375588ac2e31c597320edb7`

## [0.0.5-r1] — 2026-08-14

### Исправлено — первая серия замечаний

- B-01 / A-01: controlled source row больше не закрывается просто по факту
  наличия одного control. Добавлен `index/source-v4/CLOSURE-CONTRACT.tsv`.
- B-02 / A-02: `checker/gates-v3/CONTROL-SCHEMA.json` заменён на полный
  nested JSON Schema для фактического runtime contract и 8 parameter kinds.
- B-03 / A-06: Gate 4 использует scoped identity
  `(layer, profile, kind, locator, key)`.
- Corporate profile-specific values учитываются как `profile_variants`.
- Divergent cross-layer values не разрешаются автоматически и fail-closed как
  `unresolved cross-scope parameter conflict`.

### Сохранено

- Пилотные controls: 5.
- Популяция source: 349.
- CLOSED: 5.
- OPEN: 344.
- Проба sysctl не изменена.
- Evidence эталонной VM: `NOT_YET_PROVIDED`.

### Проверяющий модуль

`checker/gates-v3/checker.py`

SHA-256:

`7217e741622690ac9f60521abf106b0250fecdb646537f3776dbf1d13ff00bdb`

## [0.0.5] — 2026-08-14

### Добавлено

- Первый активный FSTEC-LINUX-2022 sysctl pilot.
- Пять controls:
  - `kernel.dmesg_restrict=1` — 2.4.1;
  - `kernel.kptr_restrict=2` — 2.4.2;
  - `net.core.bpf_jit_harden=2` — 2.4.8;
  - `kernel.perf_event_paranoid=3` — 2.5.2;
  - `kernel.kexec_load_disabled=1` — 2.5.4.
- `index/source-v3`.
- Read-only проба `probes/sysctl-v1/probe.py`.
- `checker/gates-v2` с Gate 5.
- Точечные тесты Gate 5.

### Изменено

- Прогресс source-index:
  - всего: 349;
  - закрыто: 5;
  - открыто: 344;
  - доля закрытия: `5/349`.
- Exact control quotes теперь формируются непосредственно из verified
  recovered FSTEC-LINUX-2022 corpus по locator и нормализуются `norm-v1`.

### Проверка

- Gate 1: PASS для пяти pilot controls.
- Gate 2: ожидаемый FAIL, 344 строки без покрытия.
- Gate 3: PASS.
- Gate 4: PASS.
- Синтетический self-test реализации Gate 5: PASS.
- Evidence эталонной VM: `NOT_YET_PROVIDED`.

### Исправлено

- Исправлена первая версия Step-5 installer, которая сравнивала hardcoded
  quote с recovered corpus и корректно завершилась fail-closed до публикации.
- Исправленный Step-5 installer извлекает clause из
  `raw-glyph-recovered/fstec-linux-2022.txt`, применяет exact `norm-v1`,
  проверяет literal `key=value`, затем вычисляет quote SHA.

## [0.0.4] — 2026-08-14

### Добавлено

- `checker/gates-v1`.
- Gate 1–4:
  - якорь source/quote;
  - обратное покрытие source;
  - закрытая schema / замыкание параметров;
  - уникальность / конфликты параметров.
- 13 положительных/отрицательных fixtures.

### Проверка

На пустом active control corpus:

- Gate 1: PASS;
- Gate 2: ожидаемый FAIL — 349 строк без покрытия;
- Gate 3: PASS;
- Gate 4: PASS;
- итоговый FAIL ожидаем.

Это зафиксировало fail-closed поведение до появления первых controls.

## [0.0.3] — 2026-08-14

### Добавлено

- `index/source-v1` — первоначальная source-first population.
- `TOTAL_INDEX_ROWS=349`.
- Отдельная регистрация framework sources.
- Метрика перехода:
  `CLOSED_INDEX_ROWS / TOTAL_INDEX_ROWS`.
- `sources/recovered-v1` для non-OCR glyph-ID recovery.
- `index/source-v2`.

### Изменено

- После recovery:
  - `QUOTE_ANCHOR_READY_ROWS=349`;
  - `QUOTE_ANCHOR_BLOCKED_ROWS=0`;
  - `CLOSED_INDEX_ROWS=0`.

### Проверка

- `fstec-linux-2022`: восстановлено 40/40 локаторов.
- `fstec-vulnerability-analysis-2025`: восстановлено 61/61 локаторов.
- Двойное восстановление: 2/2.
- Неразрешённых глифов: 0.

## [0.0.2] — 2026-08-14

### Добавлено

- Закреплённый пакет источников FSTEC:
  - 10 PDF;
  - `sources/fstec/SHA256SUMS`.
- Детерминированное извлечение `pdftotext`.
- Сырой извлечённый текст.
- Нормализованный текст `norm-v1`.
- `EXTRACTION-MANIFEST.tsv`.
- Метаданные toolchain.

### Проверка

- Проверка SHA закреплённых источников: PASS.
- Двойное извлечение: 10/10.
- Сырых текстов: 10.
- Текстов norm-v1: 10.
- Самотест/идемпотентность `norm-v1`: PASS.

## [0.0.1] — 2026-08-14

### Добавлено

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
- Инженерный donor `securelinux-ng.sh`.

### Политика

- Старая модель не конвертируется массово.
- Старые records рассматриваются только как candidate input.
- Новая активная модель строится source-first.
- Один control = один parameter.
- Источник и literal quote должны быть машинно проверяемы.
