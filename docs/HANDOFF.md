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
  [`tools/vm-runner/slp-vm-apply-supported7-v17.sh`](../tools/vm-runner/slp-vm-apply-supported7-v17.sh), порядок:
  восстановление снимка → CHECK → `--apply --dry-run` → `--apply` → перезагрузка (смена
  `boot_id`) → CHECK → `--apply` → возврат к снимку. Пути, имена ВМ и UUID снимков
  встроены для рабочего ПК; запуск — из репозитория. Кандидат задаётся
  `EXPECTED_CHECK_SHA256` явно: значение по умолчанию в сценарии устарело. Одна среда —
  `ONLY=N`; `FIXTURES=1` (по умолчанию) создаёт нарушения для 2.3.5, 2.3.8 и 2.3.9.
  Пароль user вводится один раз (регламент v27 §25). `RESULT=PASS` сценария не
  оценивает вердикты CHECK: число `ERROR` проверяется по архиву.
- Версии v15 и v16 в `tools/vm-runner/` — исторические (заменены v17; отличия версий —
  в заголовке v17), для прогонов не используются.
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

1. Step 7B `FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS`: 17 OPEN-строк
   `index/source-v4/SOURCE-INDEX.tsv`, все `technical-core` — кандидаты в контроли:
   fstec-configuration-2026 п.1.1 (парольная политика `login.defs`, `pam_pwquality`,
   `pam_faillock`), 1.2 (история паролей), 10.5 (правило auditd для записи в `/`), 3.2 (Samba — нужна проверка наличия на 7
   средах), 8.4 (события SSH), 9.1 и 9.2 (`sshd_config`), 11.2 (Telnet, FTP, SNMPv1/v2c);
   fstec-logging-2025 п.1, 3, 4, 5, 7 и приложение 2 п.1–4 (auditd; наличие на 7
   средах не проверено).

Закрыто 25.09.2026:

- Step 7B, диспозиция 81 строки (`DISPOSITION-LEDGER.tsv`): fstec-perimeter-2026 —
  все 35 (`external` — сетевые устройства, `organizational` — процессы);
  fstec-configuration-2026 — 41 (Windows и СУБД — `out-of-scope`, межсетевой экран —
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

- Инфраструктура ВМ: runner — `tools/vm-runner/slp-vm-apply-supported7-v17.sh`
  (v15, v16 — исторические); 7 сред — `product/SUPPORTED-PLATFORMS.tsv` и тесты генератора;
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
