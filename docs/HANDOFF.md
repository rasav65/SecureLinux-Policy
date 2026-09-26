# Передача работы

Порядок работы, особенности рабочего ПК и текущая очередь — чтобы продолжать проект
без восстановления контекста по журналам. Статус продукта здесь не определяется:
источники истины — product registries, `ROADMAP.tsv` и [`PROJECT-MAP.md`](PROJECT-MAP.md).
Документ обновляется в том же коммите, который меняет порядок работы или очередь.

## Порядок работы

- Шаг правки готовится как каталог шага: `step.env`, `edit.py`, `expected.txt`,
  `commit-msg.txt` (формат — в заголовке [`tools/run-edit-step.sh`](../tools/run-edit-step.sh)).
  Человек запускает на ПК `tools/run-edit-step.sh КАТАЛОГ_ШАГА`, при `RESULT=PASS`
  делает коммит и push.
- Один контроль — один коммит. Семантику контроля меняет только человек; объект
  ERROR называется до правки.
- Порядок правки: код → `CHANGELOG.md` → `tools/refresh-pins.py --write
  [--reviewed DOC ...] [--reviewed-truth]`. `--reviewed` принимает список через пробел.
  Новый файл до `refresh-pins` вписывается в свой `SHA256SUMS` и регистрируется
  `git add -N` (в `step.env` — `NEW_FILES`).
- `edit.py` меняет файлы по exact bytes: якорь должен встречаться ровно один раз.
  `sed -i` не используется.
- `expected.txt` снимается на чистой копии того же коммита; совпадение байтов на ПК —
  условие `RESULT=PASS`.
- `render-current-docs.py --write` выполняется до `refresh-pins` и сверяет SHA
  control-yaml с `CONTROL-MANIFEST.tsv`, а APPLY-реестры — с файлами. Поэтому `edit.py`,
  который меняет control-yaml или добавляет механизм APPLY, сам пишет эти SHA
  (пример — шаг `pam-wheel-su-v1`, коммит `0b8cb6a`).
- После push файлы шага удаляются командой с проверкой
  `git merge-base --is-ancestor HEAD origin/main`.

## Рабочий ПК

- `DOWNLOADS=/mnt/300GB/Загрузки`, `REPO=$DOWNLOADS/SecureLinux-Policy-v3`;
  evidence ВМ — `$REPO/dashboard/src0009-vm-evidence` (каталог вне Git).
- `umask 0002`. Тесты задают права создаваемых файлов явно. `git reset --hard` и
  `git checkout` пересоздают файлы с правами `0664`, а тест артефакта требует `0644`:
  перед ними — `umask 0022`, при отказе `MODE_PRECHECK` —
  `git ls-files -z | xargs -0 chmod go-w`.
- `/tmp` смонтирован с `noexec`: `os.access(X_OK)` для файла во временном каталоге
  ложен; исполняемость проверяется по типу файла и битам режима.
- DEV запускается не от root: под uid 0 три файла `tests/product-v1/` дают FAIL
  (проверено 25.09.2026 на клоне `d8d2ef6`).

## ВМ-прогоны

- 7 сред: Ubuntu 22.04 full, Ubuntu 24.04 mini и full, Ubuntu 26.04 mini и full,
  Debian 12, Debian 13; снимки `upd-20260924`.
- Сценарий прогона APPLY на ВМ находится в файле
  [`tools/vm-runner/slp-vm-apply-supported7-v18.sh`](../tools/vm-runner/slp-vm-apply-supported7-v18.sh), порядок:
  восстановление снимка → CHECK → `--apply --dry-run` → `--apply` → перезагрузка (смена
  `boot_id`) → CHECK → `--apply` → возврат к снимку. Пути, имена ВМ и UUID снимков
  встроены для рабочего ПК; запуск — из репозитория. Кандидат задаётся
  `EXPECTED_CHECK_SHA256` явно: значение по умолчанию в сценарии устарело. Одна среда —
  `ONLY=N`; `FIXTURES=1` (по умолчанию) создаёт нарушения для 2.3.5, 2.3.8 и 2.3.9.
  Пароль user вводится один раз (регламент v27 §25). `RESULT=PASS` сценария не
  оценивает вердикты CHECK: число `ERROR` проверяется по архиву.
  v18: до CHECK фазы 1 в `~user/.ssh/authorized_keys` дописывается временный ключ ПК
  (создаётся в рабочем каталоге, в архив не попадает); фаза 2 — вход только по ключу;
  после перезагрузки — попытка входа по паролю (`pwlogin.txt`, `PASSWORD_LOGIN_RC`,
  ожидается не 0); `env1`/`env2` — `sshd -T` и активные строки трёх ключей.
- Версии v15, v16 и v17 в `tools/vm-runner/` — исторические (заменены v18; отличия версий —
  в заголовке v18), для прогонов не используются.
- Прогон 24.09.2026, артефакт `d840ede3…c8aa`: на всех 7 средах после перезагрузки
  `init_on_alloc=1 slab_nomerge randomize_kstack_offset=1 vsyscall=none` в
  `/proc/cmdline`, повторный APPLY — без `APPLIED` и `FAILED_*`. Архивы
  `slp-vm-apply-v15-work.tar.gz` (среды 1, 3–7) и
  `slp-vm-apply-supported7-v15-states2-20260924-235858.tar.gz` (среда 2) — в evidence.
- Прогон 25.09.2026, артефакт `9a42418f…67ab`, все 7 сред: архив
  `slp-vm-apply-supported7-v15-states1-7-20260925-105923.tar.gz` (SHA `cb1fe630…8ab4`) —
  в evidence; принят 25.09.2026 (статусы узлов — `PROJECT-MAP.md`).
- Runner v16 (исторический): пароль вводится один раз, мастер-соединение ssh повторяется
  до 5 раз.
- Прогон кандидата `1836091` (артефакт `d348b953…32be7`) принят 25.09.2026: среды 1, 3–7 —
  runner v15, `slp-vm-apply-supported7-v15-20260925-135344-work.tar.gz` (SHA
  `3146b071…c5e8`); среда 2 — runner v16,
  `slp-vm-apply-supported7-v16-states2-20260925-150156.tar.gz` (SHA `e59ff0b7…4a18`).
  Везде CHECK после APPLY без `ERROR`, повторный APPLY без `APPLIED`/`FAILED_*`.
  Прогон среды 2 в 14:11 (`…-141127.tar.gz`, SHA `c3737287…edfd`) дал `ERROR
  pid-population:final-snapshot-changed` в 2.3.2 — популяция процессов изменилась
  во время CHECK после загрузки; повтор — PASS. Устранено повтором наблюдения
  2.3.2 в адаптере (см. «Закрыто»).
- Runner v17: v16 плюс `FIXTURES=1` (по умолчанию) — подготовленные нарушения для 2.3.5, 2.3.8 и 2.3.9.
  Прогон 25.09.2026 (артефакт `74f333d5…d1ae`, архив `…-v17-states1-7-20260925-162722.tar.gz`,
  SHA `b82a9d8c…3ead`) принят для этих трёх механизмов на 7 средах.

## Очередь

Решения 25.09.2026 приняты по делегированию человека. Источник пунктов
вне репозитория — файл очереди `SecureLinux-Policy-20260923-v70.txt` (далее v70).

1. Step 7B `FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS`: 14 OPEN-строк
   `index/source-v4/SOURCE-INDEX.tsv`, все `technical-core` — кандидаты в контроли:
   fstec-configuration-2026 п.1.1 (парольная политика `login.defs`, `pam_pwquality`,
   `pam_faillock`), 1.2 (история паролей), 10.5 (правило auditd для записи в `/`),
   8.4 (события SSH), 11.2 (Telnet, FTP, SNMPv1/v2c);
   fstec-logging-2025 п.1, 3, 4, 5, 7 и приложение 2 п.1–4 (auditd).
   Решения пользователя 25.09.2026: контроли каждого документа — в своём каталоге
   (`controls/fstec-core/configuration-2026`, `controls/fstec-core/logging-2025`) со
   своим `CONTROL-MANIFEST.tsv`; `linux-2022` не меняется. Пункт 9.1: три контроля —
   `PermitEmptyPasswords no`, `PermitRootLogin no`, `PasswordAuthentication no` — с
   APPLY, требование политики компании. Порядок работ по 9.1:
   0) выполнено: генератор, `render-current-docs.py`, `refresh-pins.py`, `pin-closure.py`
   читают все `controls/fstec-core/<каталог>/CONTROL-MANIFEST.tsv`;
   а) выполнено: `tools/source_skeleton_generator.py` поддерживает
   `unit_kind=numbered-subpoint`, для SRC-0088 — `EXACT`;
   б) выполнено: CHECK-адаптер `sshd-config-option` по образцу `sshd-root-login` (директива в
   основном `/etc/ssh/sshd_config` в глобальной области и эффективное значение
   `sshd -T`); по этой семантике на 7 средах ожидается FAIL всех трёх контролей;
   в) механизм APPLY `sshd-config-option-v1` выполнен; ВМ-прогон — сценарием v18: до APPLY
   временный ключ SSH для `user`, иначе после `PasswordAuthentication no` вход по паролю
   закрыт. Ожидание: CHECK до — FAIL трёх контролей, APPLY — `APPLIED`, CHECK после
   перезагрузки — PASS, повторный APPLY — `ALREADY_COMPLIANT`. Разведка 26.09.2026 (архив
   `slp-vm-probe-supported7-v2-states1-7-20260926-131539.tar.gz`, SHA `5000d569…3dc8`): на 5
   Ubuntu `/etc/ssh/sshd_config.d/50-cloud-init.conf` = `PasswordAuthentication yes` (SHA
   `6bf43c75…ac1d`, `600 root:root`, пакету не принадлежит, дата — установка); cloud-init на
   24.04 и 26.04 выключен файлом `/etc/cloud/cloud-init.disabled`, на 22.04 включён,
   `config_set_passwords` выполнен при установке; на Debian cloud-init и drop-in нет; в
   основном `sshd_config` на всех 7 средах есть шаблоны `#PermitRootLogin`,
   `#PasswordAuthentication`, `#PermitEmptyPasswords` после `Include`; `~user/.ssh/authorized_keys`
   пуст (Ubuntu) или отсутствует (Debian).
   Граница проверки ключа администратора (решение пользователя 26.09.2026, принят остаточный
   риск): вне объёма — ACL, SELinux/AppArmor, NSS не из файлов (LDAP/SSSD),
   `AuthorizedKeysCommand`; настройка, которую механизм проверить не может, — администратор не
   засчитывается, APPLY отказывает. Дальнейшие ошибки механизма выявляет ВМ-прогон.
   Факты разведки 25.09.2026 (7 сред, `docs/testing-strategy.md`): auditd, libpam-pwquality,
   telnetd, vsftpd, snmpd, fail2ban отсутствуют; `pam_faillock.so` и `pam_pwhistory.so`
   есть, но в `common-auth`/`common-password` не подключены; `common-auth` — `pam_unix.so
   nullok`; `login.defs` — `PASS_MAX_DAYS 99999`, `PASS_MIN_DAYS 0`, `PASS_WARN_AGE 7`,
   `PASS_MIN_LEN` нет; `sshd -T` — `permitemptypasswords no`, `passwordauthentication yes`,
   `loglevel INFO`.

Решения пользователя 26.09.2026 (очередь по порядку):

1. fstec-configuration-2026 п.11.2 — CHECK: Telnet, FTP, SNMP не установлены или выключены;
   APPLY: остановить и замаскировать найденные службы.
2. Парольная политика: `/etc/login.defs` — `PASS_MAX_DAYS 90` (п.1.1 таблица 2; методический
   документ ФСТЭК 2026 — смена не более чем через 90 дней), `PASS_MIN_DAYS 1`, `PASS_WARN_AGE 7`,
   `ENCRYPT_METHOD` SHA512 или YESCRYPT; `pam_pwquality` (пакет `libpam-pwquality` ставится):
   `minlen=12` (методический документ — не менее 12 символов; требование компании; п.1.1
   рекомендует 15), `ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1`, `retry=3`; п.1.2 —
   `pam_pwhistory remember=5` (таблица 1: не менее 5–10). Существующим записям срок через
   `chage` не задаётся автоматически — блок «решение администратора». `pam_faillock` не
   применяется: требования компании нет (методический документ: 5 попыток, 15 минут).
3. APPLY 2.3.10 (`chmod go-rwx` перечисленных файлов), 2.3.11 (`chmod 700` домашних каталогов
   пользователей с UID ≥ 1000 из `/etc/passwd`, прочие — решение администратора;
   `HOME_MODE 0700`), 2.3.3 (`chmod go-w` исполняемых файлов cron), 2.3.7, 2.3.4.
   2.3.2 — без APPLY, причина «на усмотрение администратора».
4. п.8.4 — частично: `LogLevel VERBOSE` в `sshd_config` механизмом `sshd-config-option-v1`.
5. auditd: установка пакета, правила приложения 2 fstec-logging-2025 и п.10.5.
6. `--report` с разделом причин «оставлено без изменений»; APPLY 2.1.1 (блокировка по паролю
   пустых паролей; `sudo`/`admin` и root — решение администратора); сценарий ВМ v18.

Закрыто 25.09.2026:

- SRC-0089 (fstec-configuration-2026 п.9.2, доступ только по SSH-ключам) — `organizational`:
  решение пользователя, настраивается администраторами подразделений.
- Step 7B, диспозиция 82 строк (`DISPOSITION-LEDGER.tsv`; п.3.2 — Samba отсутствует на 7 средах): fstec-perimeter-2026 —
  все 35 (`external` — сетевые устройства, `organizational` — процессы);
  fstec-configuration-2026 — 42 (Windows и СУБД — `out-of-scope`, межсетевой экран —
  `out-of-scope` по регламенту v27 §2.2 п.5, процессы и перечни администратора —
  `organizational`); fstec-logging-2025 — 5.
- Горизонт 1 `HORIZON1_SAFE_CLASS_APPLY_AND_VM_RUNS` — `CLOSED`, Step 7B — `NEXT`
  (`docs/ROADMAP.tsv`); G3 и G7 — вне горизонта 1, основание — в `PROJECT-MAP.md`.
- 2.3.1: APPLY только снимает биты (класс G2 в `PROJECT-MAP.md`); добавление битов
  расширяет доступ, решение остаётся администратору (регламент v26 §30). Не отклонение.
- 2.6.6: при обнаруженном Apport APPLY возвращает решение администратору
  (`PROJECT-MAP.md`, карта сегментации; v70 §6; регламент v26 §30).
- Приёмка ВМ-прогона 25.09.2026: узлы APPLY1–APPLY3, APPLY7, APPLY8 — `closed`;
  APPLY4–APPLY6 — только `ALREADY_COMPLIANT`, см. пункт 4. 2.3.2 на Ubuntu 26.04
  minimized — PASS до и после APPLY. Прогон 24.09.2026 (архивы
  `slp-vm-apply-v15-work.tar.gz` SHA `2fda8aa6…dab5`,
  `slp-vm-apply-supported7-v15-states2-20260924-235858.tar.gz` SHA `d4e4d251…97ac`)
  относится к прежнему кандидату `d840ede3…c8aa` и заменён прогоном 25.09.2026.
- B-02 (v70 §7 п.4): отсутствие — только доказанный ENOENT в пяти CHECK-адаптерах
  (`912c543`, `f7eb765`, `691be9b`, `105bdbb`, `41c3061`, `1836091`); аудит
  `6afb18e..41c3061` — REVISE (B-01), `41c3061..1836091` — PASS; ВМ-прогон кандидата
  `1836091` на 7 средах принят. Узлы APPLY в `PROJECT-MAP.md` не меняются.

- Инфраструктура ВМ: runner — `tools/vm-runner/slp-vm-apply-supported7-v18.sh`
  (v15, v16, v17 — исторические); 7 сред — `product/SUPPORTED-PLATFORMS.tsv` и тесты генератора;
  evidence — постоянный каталог `dashboard/src0009-vm-evidence` (регламент v27 §1),
  SHA архивов — `CHANGELOG.md`. Отдельный тест набора сред не вводится: состав уже
  проверяется по `SUPPORTED-PLATFORMS.tsv`.

- `OPS_DECLARATION_GAPS`: все активные семантические контракты CHECK объявляют
  `supported_ops` (список пуст).

- Описание APPLY-адаптера 2.3.9 больше не называет выведенный контроль
  `…-SUID-SGID-ALLOWLIST` (v70 §7 п.5).

- Путь с изменением прав у 2.3.5, 2.3.8, 2.3.9 на семи средах (runner v17); все восемь
  узлов механизмов APPLY — `closed`.

- 2.3.2: наблюдение, прерванное сменой популяции процессов (`RETRY_REASONS` адаптера),
  повторяется целиком, не более 3 попыток с паузой 1 с; VALUE — только по одной
  стабильной попытке, иначе `ERROR` последней попытки; смена файлов и каталогов не
  повторяется. Решение по делегированию человека 25.09.2026 (регламент v26 §4):
  правило вердикта для отдельного наблюдения не меняется. ВМ-прогон 25.09.2026
  runner v17 на кандидате `dcf6ceaf…ef28` (архив
  `slp-vm-apply-supported7-v17-states1-7-20260925-175302.tar.gz` SHA `fee52469…2276`): CHECK до и после APPLY на 7 средах без
  `ERROR`, 2.3.2 — PASS во всех 14 проверках.

Вне репозитория, статус UNKNOWN: v70 §7 п.6 (пункты P3–P9 очереди v68);
v70 §7 п.7 (три несогласованности регламента v26).
