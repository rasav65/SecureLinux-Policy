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

## ВМ-прогоны

- 7 сред: Ubuntu 22.04 full, Ubuntu 24.04 mini и full, Ubuntu 26.04 mini и full,
  Debian 12, Debian 13; снимки `upd-20260924`.
- Runner APPLY `slp-vm-apply-supported7-v15.sh` (пока вне репозитория): восстановление
  снимка → CHECK → `--apply --dry-run` → `--apply` → перезагрузка (смена `boot_id`) →
  CHECK → `--apply` → возврат к снимку. Кандидат задаётся `EXPECTED_CHECK_SHA256`.
- Прогон 24.09.2026, артефакт `d840ede3…c8aa`: на всех 7 средах после перезагрузки
  `init_on_alloc=1 slab_nomerge randomize_kstack_offset=1 vsyscall=none` в
  `/proc/cmdline`, повторный APPLY — без `APPLIED` и `FAILED_*`. Архивы
  `slp-vm-apply-v15-work.tar.gz` (среды 1, 3–7) и
  `slp-vm-apply-supported7-v15-states2-20260924-235858.tar.gz` (среда 2) — в evidence.

## Очередь

1. APPLY 2.2.1 `su-wheel-access`; B-02 (нужен текст от человека); отклонения 2.3.1 и 2.6.6.
2. Инфраструктура: эталонный набор 7 сред в тестах, runner ВМ в `tools/vm-runner/`, evidence;
   ВМ-проверка пути с изменением прав у `startup-files-write-protection-v1`.
3. 63 OPEN-пункта.
