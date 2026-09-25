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

## Очередь

1. ВМ-прогон `pam-wheel-su-v1` (коммит `0b8cb6a`) runner v15 на 7 средах; решение человека,
   считать ли прогон 24.09.2026 приёмкой механизмов (статус узлов `PROJECT-MAP.md`).
2. B-02 (нужен текст от человека); отклонения 2.3.1 и 2.6.6.
3. Инфраструктура: эталонный набор 7 сред в тестах, evidence в репозитории;
   ВМ-проверка пути с изменением прав у `startup-files-write-protection-v1`.
4. 63 OPEN-пункта.
