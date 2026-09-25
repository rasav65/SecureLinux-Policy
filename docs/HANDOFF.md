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
  [`tools/vm-runner/slp-vm-apply-supported7-v15.sh`](../tools/vm-runner/slp-vm-apply-supported7-v15.sh), порядок:
  восстановление снимка → CHECK → `--apply --dry-run` → `--apply` → перезагрузка (смена
  `boot_id`) → CHECK → `--apply` → возврат к снимку. Пути, имена ВМ и UUID снимков
  встроены для рабочего ПК; запуск — копией из `$DOWNLOADS`. Кандидат задаётся
  `EXPECTED_CHECK_SHA256` (по умолчанию `d840ede3…c8aa`; для `0b8cb6a` —
  `9a42418f2d3e644d4409458fd72fcf3c2cf9ed95996d28ec7c3d7463b7b867ab`), одна среда — `ONLY=N`.
- Прогон 24.09.2026, артефакт `d840ede3…c8aa`: на всех 7 средах после перезагрузки
  `init_on_alloc=1 slab_nomerge randomize_kstack_offset=1 vsyscall=none` в
  `/proc/cmdline`, повторный APPLY — без `APPLIED` и `FAILED_*`. Архивы
  `slp-vm-apply-v15-work.tar.gz` (среды 1, 3–7) и
  `slp-vm-apply-supported7-v15-states2-20260924-235858.tar.gz` (среда 2) — в evidence.
- Прогон 25.09.2026, артефакт `9a42418f…67ab`, все 7 сред: архив
  `slp-vm-apply-supported7-v15-states1-7-20260925-105923.tar.gz` (SHA `cb1fe630…8ab4`) —
  в evidence; принят 25.09.2026 (статусы узлов — `PROJECT-MAP.md`).
- Сценарий v16 находится в файле
  [`tools/vm-runner/slp-vm-apply-supported7-v16.sh`](../tools/vm-runner/slp-vm-apply-supported7-v16.sh): пароль
  user вводится один раз (ssh — через `SSH_ASKPASS`, sudo на ВМ — через stdin,
  `sudo -S -p ''`), мастер-соединение ssh повторяется до 5 раз. Пароль в окружении
  процесса ssh — отступление от регламента v26 §25 по указанию человека 25.09.2026.
  Запуск — копией из `$DOWNLOADS` (байты прогона на 1 перевод строки длиннее копии в
  репозитории).
- Прогон кандидата `a5bffb4` (артефакт `d348b953…32be7`) принят 25.09.2026: среды 1, 3–7 —
  runner v15, `slp-vm-apply-supported7-v15-20260925-135344-work.tar.gz` (SHA
  `3146b071…c5e8`); среда 2 — runner v16,
  `slp-vm-apply-supported7-v16-states2-20260925-150156.tar.gz` (SHA `e59ff0b7…4a18`).
  Везде CHECK после APPLY без `ERROR`, повторный APPLY без `APPLIED`/`FAILED_*`.
  Прогон среды 2 в 14:11 (`…-141127.tar.gz`, SHA `c3737287…edfd`) дал `ERROR
  pid-population:final-snapshot-changed` в 2.3.2 — популяция процессов изменилась
  во время CHECK после загрузки; повтор — PASS. При повторении — ожидание
  `systemctl is-system-running --wait` перед фазой 2.

## Очередь

Решения 25.09.2026 приняты по делегированию человека. Источник пунктов
вне репозитория — файл очереди `SecureLinux-Policy-20260923-v70.txt` (далее v70).

1. Комментарий `product/apply-adapters/product-suid-sgid-applications-mode-apply-v1.py`
   (строки 9–11) называет выведенный контроль `…-SUID-SGID-ALLOWLIST` (v70 §7 п.5).
2. ВМ-проверка пути с изменением прав у `suid-sgid-applications-mode-v1`,
   `standard-system-paths-mode-v1`, `startup-files-write-protection-v1` на семи средах
   (подготовленное нарушение после восстановления снимка).
3. Инфраструктура: эталонный набор 7 сред в тестах, evidence в репозитории.
4. Step 7B `FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS`: OPEN-строки
   `index/source-v4/SOURCE-INDEX.tsv` — 63 `technical-core` и 35 `technical-perimeter`.

Закрыто 25.09.2026:

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
  (`93d886e`, `0707aea`, `42bb7a2`, `dfd600e`, `3c70ab1`, `a5bffb4`); аудит
  `d22a663..3c70ab1` — REVISE (B-01), `3c70ab1..a5bffb4` — PASS; ВМ-прогон кандидата
  `a5bffb4` на 7 средах принят. Узлы APPLY в `PROJECT-MAP.md` не меняются.

- `OPS_DECLARATION_GAPS`: все активные семантические контракты CHECK объявляют
  `supported_ops` (список пуст).

Вне репозитория, статус UNKNOWN: v70 §7 п.6 (пункты P3–P9 очереди v68);
v70 §7 п.7 (три несогласованности регламента v26).
