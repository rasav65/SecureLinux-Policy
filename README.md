# SecureLinux-Policy v3

Проверяемая политика безопасной настройки Linux, построенная от первоисточника.

Каждая активная запись контроля связана с конкретным местом документа ФСТЭК,
несёт дословную цитату и её SHA-256, описывает ровно один наблюдаемый параметр
и проходит машинные гейты. Массовый перенос старого корпуса запрещён.

---

## Что это по существу

Цепочка, которую строит проект:

```text
первоисточник ФСТЭК (pinned PDF)
  → нормализованный корпус (norm-v1, при повреждённом слое — glyph recovery)
  → source index (одна строка = одно нормативное место)
  → quote anchor (дословная цитата + SHA-256)
  → canonical control (один наблюдаемый параметр)
  → адаптер проверки
  → сгенерированный read-only скрипт
  → прогон на целевой системе
```

Проект намеренно разделяет **проверку** (CHECK) и **изменение** системы
(APPLY/RESTORE). Реализуется только CHECK. APPLY и RESTORE — отдельный будущий
этап со своими контрактами: precondition, postcondition, rollback,
идемпотентность, evidence.

---

## Текущее состояние

Корпус первоисточника:

```text
TOTAL_INDEX_ROWS=349
CLOSED_INDEX_ROWS=8
OPEN_INDEX_ROWS=341
CLOSURE_RATIO=8/349
```

Активные контроли — восемь sysctl-мер из `fstec-linux-2022`:

| Локатор | Параметр | Ожидание |
|---|---|---:|
| 2.4.1 | `kernel.dmesg_restrict` | `1` |
| 2.4.2 | `kernel.kptr_restrict` | `2` |
| 2.4.8 | `net.core.bpf_jit_harden` | `2` |
| 2.5.2 | `kernel.perf_event_paranoid` | `3` |
| 2.5.4 | `kernel.kexec_load_disabled` | `1` |
| 2.5.5 | `user.max_user_namespaces` | `0` |
| 2.5.6 | `kernel.unprivileged_bpf_disabled` | `1` |
| 2.6.1 | `kernel.yama.ptrace_scope` | `3` |

Гейты v3 на текущем дереве:

```text
GATE0 PASS  schema_generation_parity
GATE1 PASS  checked=8
GATE2 FAIL  controlled_closed=8 disposed_closed=0 uncovered=341 contracts=8
GATE3 PASS  checked=8
GATE4 PASS  checked=8
GATE5 FAIL  требует probe-results (прогон на VM выполняется отдельно)
OVERALL FAIL
```

`OVERALL=FAIL` — конструктивное состояние, а не поломка: пока хотя бы одна из
341 строки не закрыта, общий вердикт обязан быть отрицательным.

Отдельный product/corpus CHECK собран из всех восьми текущих sysctl-controls
и проверен на Ubuntu 24.04.4 VM. Он имеет статус
`NON_RELEASE_DIAGNOSTIC_CANDIDATE`, явно не использует identity Step 7B.0
Build Contract / Phase B/C и не является authoritative или release. Снимки
восьми sysctl до и после прогонов совпали, поэтому read-only свойство
диагностического CHECK подтверждено фактическим запуском.

Реальный disposition ledger пуст: `DISPOSITION-LEDGER.tsv` содержит только
заголовок. Альтернативный путь закрытия строки (явный disposition вместо
контроля) пока не использован ни разу.

---

## Как закрывается одна строка корпуса

Пять обязательных шагов, каждый проверяется машинно:

1. **Quote anchor.** `tools/source_skeleton_generator.py` извлекает дословную
   цитату из проверенного корпуса и вычисляет её SHA-256. Поддержан один
   `unit_kind` из тринадцати — `numbered-position`: 74 строки, 72 точных
   извлечения, два принципиальных отказа (`SRC-0001`, `SRC-0133`, обрыв на
   номере страницы). Отказ — корректный результат, подгонка запрещена.
2. **Canonical control** в `controls/<layer>/<doc>/` — один параметр, блок
   `source` с якорем, `expected` с операцией и типом.
3. **Регистрация** в `CONTROL-MANIFEST.tsv` и, для контролей текущего
   сборочного набора, в `step7b0/phase-a/STEP7B0-CONTROL-SET.lock`.
4. **Статус** строки в `SOURCE-INDEX.tsv` переводится в `CLOSED`; поля
   `disposition` и `reason` у controlled-строки обязаны остаться пустыми.
5. **Completeness contract** в `CLOSURE-CONTRACT.tsv`: `atomic-single` —
   ровно один полный контроль, `exact-control-set` — точный набор из двух и
   более. Наличие произвольного контроля само по себе строку не закрывает.

Пропуск любого шага виден в Gate 2 как отдельная ошибка.

---

## Гейты

| Гейт | Что проверяет |
|---|---|
| 0 | байтовое равенство закоммиченной и порождённой `CONTROL-SCHEMA.json` |
| 1 | source identity, SHA закреплённого PDF, локатор, `norm-v1`, дословное присутствие цитаты в корпусе |
| 2 | обратное покрытие: каждая строка индекса закрыта контролем либо явным disposition |
| 3 | закрытая схема записи и совместимость `kind / locator / key / op / type` |
| 4 | глобальная уникальность `id`, конфликты внутри `(layer, profile, kind, locator, key)`, cross-layer расхождения fail-closed |
| 5 | исполнимость probe: `VALUE` / `NOT_FOUND` / `ERROR`; несоответствие значения — не ошибка исполнимости |

Запуск:

```sh
python3 checker/gates-v3/checker.py \
  --project-root . \
  --index index/source-v4/SOURCE-INDEX.tsv \
  --controls controls/fstec-core/linux-2022
```

`CONTROL-SCHEMA.json` не редактируется руками: она порождается из таблицы
`KIND_RULES` в `checker.py` через `--emit-schema`, а Gate 0 падает при любом
расхождении байтов.

Схема знает восемь видов параметров — `sysctl`, `file-kv`, `file-mode-owner`,
`mount-option`, `systemd-unit-state`, `package-presence`, `pam-line`,
`audit-rule`. Для `file-mode-owner` реализована relation-семантика:
`key=mode` разрешает `op=eq|bits-clear`; `bits-clear` принимает только
ненулевую четырёхзначную octal-маску, а для `owner`, `group`, `owner_group`
остаётся только `op=eq`. Runtime, сгенерированная Draft 2020-12 schema,
минимальный schema-emulator и реальный `Draft202012Validator` дают одинаковые
verdict на positive/negative fixtures.

Текущая product-line содержит отдельные semantic contracts и read-only
адаптеры для `file-mode-owner` и `sysctl`. Sysctl product adapter имеет
собственную identity `product-sysctl-check-v1`; historical
`step7b0/phase-a/adapter/sysctl-check-adapter-v1.py` не изменён и current
product authority не является. `product/ADAPTER-REGISTRY.tsv` — единственный
tracked mapping `parameter_kind → adapter/contract/implementation → SHA-256`.
Tracked product generator ещё не создан.

---

## Сборка CHECK-скрипта

Tracked generator текущей product-line ещё не создан — это следующий шаг.
Ниже описана historical assurance-line Step 7B.0; она не является текущим
product generator.

Скрипт не пишется руками. Historical builder собирает его из принятых входов,
а порядок допуска builder'а описан в Build Contract
(`step7b0/BUILD-CONTRACT-v0.9.5.md`).
Модель этапов: Phase A — статические предусловия, Phase B — измерение
зависимостей кандидата под наблюдателем, Phase C — динамические предусловия,
Phase D — authoritative admission.

Текущий фактический статус: Phase A принята под v0.9.5; Phase C открыта,
item 19 (host-state hermeticity) находится в состоянии REVISE; authoritative
builder не признан, публикация не выполнялась.

Целевой артефакт — один файл на один `target_id`. Текущий target —
`ubuntu-24.04-x86_64`. На неподдерживаемой платформе скрипт обязан завершиться
с RC=3, не выполнив ни одной проверки.

Коды возврата скрипта:

| RC | Значение |
|---:|---|
| 0 | все параметры прочитаны, вердикт `COMPLIANT` или `NONCOMPLIANT` |
| 1 | есть `NOT_FOUND` или `ERROR`, вердикт `UNEVALUATED` |
| 2 | неверный аргумент или арность |
| 3 | неподдерживаемая платформа |

Несоответствие контроля само по себе RC не повышает: это результат проверки, а
не сбой.

---

## Структура

```text
sources/    закреплённые первоисточники и проверенные текстовые представления
index/      source index, closure contract, disposition ledger
controls/   принятые записи контролей
probes/     read-only наблюдение
checker/    гейты
tools/      генератор source-блоков, пересборка корневых манифестов
product/    текущая product-line: semantic contracts и read-only adapters
step7b0/    Build Contract и артефакты допуска builder'а
tests/      позитивные и негативные фикстуры
archive/    исторические материалы и инженерный донор
docs/       карта проекта, roadmap, отдельные политики
```

Слой (`layer`) определяет происхождение требования, профиль — применимость
внутри слоя. Классы ФСТЭК K1/K2/K3 не являются профилями `baseline/strict/paranoid`.

---

## Проверка целостности

Точные значения хранятся в манифестах, а не в этом файле — здесь они устарели
бы при первом же изменении:

```text
SHA256SUMS                      корневой манифест
PROJECT-FILES.sha256            популяция проекта
sources/fstec/SHA256SUMS
sources/extracted/SHA256SUMS
sources/recovered-v1/SHA256SUMS
index/source-v4/SHA256SUMS
controls/fstec-core/linux-2022/SHA256SUMS
checker/gates-v3/SHA256SUMS
```

Популяция корневых манифестов строится из видимых git файлов — отслеживаемых
плюс неигнорируемых неотслеживаемых. Исключения проекта живут в версионируемом
`.gitignore`, а не в локальном `.git/info/exclude`, иначе результат
`tools/rebuild-root-manifests.py --check` не воспроизводится в свежем клоне.

Валидация релиза требует установленного `jsonschema` не ниже `4.10.3` и
реального `Draft202012Validator`. Отсутствие зависимости — жёсткая ошибка, а не
пропущенная проверка.

---

## Инженерный донор

`securelinux-ng.sh` v16.2.11 (18 928 строк, SHA-256
`f3be8723cd5a2be499e9e8e6370fad712bdec8afd68050f27af6a3e2d6fbc34b`) сохранён
как **инженерный донор**, а не как нормативный источник. Проверенные механизмы
переносятся только через явное решение `REUSE | ADAPT | REJECT | DEFER`.

Его прослеживаемость до документа неполна: из 148 функций `check_`/`apply_`/
`restore_` локатор ФСТЭК заявлен у 32, и заявлен он в тексте лог-сообщений, а
не в проверяемых полях. Все 23 заявленных локатора присутствуют в корпусе, что
и делает донора полезным источником заявок на расширение.

Донор не создаёт контролей и не закрывает строк индекса.

---

## Что не сделано

- 341 строка корпуса остаётся `OPEN`;
- semantic contracts и read-only product adapters для `file-mode-owner` и
  `sysctl` созданы и проверены; единый `ADAPTER-REGISTRY.tsv` создан;
  tracked generator ещё не создан;
- `SRC-0005 / 2.3.1` остаётся `OPEN`: три canonical controls и
  `exact-control-set` closure ещё не созданы; Step 1 закрыл строк source index: **0**;
- raw CHECK-8 evidence сохранено отдельно, но формальный текущий
  `Gate 5 --probe-results` для восьми controls ещё не создан;
- Phase C Step 7B.0 не закрыта, authoritative builder не признан,
  публикации не было;
- APPLY и RESTORE не реализуются и не проектируются на этом этапе;
- поддержан один `unit_kind` из тринадцати; остальные вводятся по одному со
  своим эталоном.

---

## Язык

Пользовательская документация ведётся на русском. Без перевода остаются имена
файлов и CLI, идентификаторы гейтов и roadmap, enum, поля схем, API и
проверяемые машиной строки статуса — они являются частью контракта.
