# SecureLinux-Policy v3 — политика переноса инженерного донора

## Статус

Эта политика является обязательной частью архитектуры проекта.

Сохранённый проект SecureLinux-NG v16.2.11 используется как **ненормативный
инженерный донор**. Он не является нормативным источником истины и сам по себе
не закрывает строки FSTEC или корпоративного source index только потому, что
эквивалентное поведение существовало в старом монолите.

## Обязательный путь переноса

Каждый старый механизм, рассматриваемый для v3, обязан пройти цепочку:

`DONOR -> v3 contract mapping -> REUSE | ADAPT | REJECT | DEFER -> APPLY semantic contract -> implementation adapter -> tests -> deterministic build`

Ни один механизм донора не копируется в итоговый сгенерированный скрипт только
потому, что он был зрелым или ранее протестированным.

## Обязательное предварительное условие перед шагом 8 roadmap

До начала `APPLY_SEMANTIC_CONTRACT` проект ОБЯЗАН создать и проверить полный
`DONOR_TO_V3_MAPPING` по всему сохранённому инженерному донору.

Для каждого принятого, отклонённого или отложенного механизма mapping должен как
минимум указывать:

- ссылку на элемент/функцию/фрагмент донора;
- релевантные regression tests донора, если они существуют;
- ссылку на существующий инженерный contract, если он существует;
- решение: `REUSE`, `ADAPT`, `REJECT` или `DEFER`;
- целевое семейство contract/adapter v3, когда применимо;
- обоснование;
- наличие нормативного эффекта (`NONE` по умолчанию);
- явное утверждение, что сам mapping закрывает 0 строк source index.

Mapping является инженерной трассировкой происхождения. Он не является нормативным evidence.

## Parent gate для APPLY semantic contracts

До принятия первого source-specific APPLY semantic contract действует одна parent schema
`product/contracts/apply-semantic-contract-v1.schema.json` и один machine-readable registry
`product/APPLY-KIND-REGISTRY.tsv`. Registry задаёт допустимые `apply_kind` и их
kind-level ограничения; source-specific contract обязан ссылаться на зарегистрированный kind.
RELEASE gate автоматически проверяет каждый current source-specific APPLY semantic contract
сначала по parent schema, затем по exact registry row; незарегистрированный kind или расхождение
`allowed_paths` / `predicate_id` / `transform_id` / `commit_model` / `privilege` /
`exclusive_lock` / compensation / dry-run policy являются FAIL.

Текущий parent gate регистрирует первый kind `local-account-password-lock`, но сам по себе
не создаёт source-specific contract, не реализует APPLY, не изменяет host state и закрывает
0 строк source index. Первый instance может появиться только отдельным следующим decision point
после проверки parent schema/registry.

## Семейства возможностей донора, которые нельзя потерять молча

Как минимум mapping обязан явно учесть следующие зрелые семейства из
SecureLinux-NG. Подписи ниже сохраняются без перевода, потому что они являются
точными `donor_label`, связанными с `DONOR-TO-V3-MAPPING.tsv`.

<!-- BEGIN MATURE DONOR FAMILIES -->
1. preflight / compatibility classification;
2. transactional apply;
3. manifest-backed state tracking;
4. transaction-local compensation from recorded pre-state;
5. atomic writes for critical files and manifests;
6. fail-closed backup before mutation;
7. exact package delta tracking;
8. preservation of already stricter sysctl values;
9. isolated per-module sysctl application;
10. runtime sysctl pre-state capture / transaction-local compensation;
11. network-online reapply for managed network sysctl;
12. dry-run with no host mutation;
13. exclusive APPLY run locking;
14. profile / additional-measures / corporate separation;
15. crash/journal patterns;
16. explicit partial/manual/reboot external-recovery classifications.
<!-- END MATURE DONOR FAMILIES -->

RESTORE у донора был зрелым и протестированным operational-семейством, но v3
не принимает его как user-invokable или post-APPLY RESTORE. Все механизмы этого
семейства учитываются явно на уровне functions/tests/contracts: operational
RESTORE-механизмы получают `REJECT`; только доказанные fragments, необходимые
для compensation внутри failed/uncommitted APPLY, могут получить `ADAPT`.

Модель отката после успешно завершённого APPLY на уровне проекта —
`EXTERNAL_SNAPSHOT`. Успешный APPLY не откатывается средствами
SecureLinux-Policy. Создание и восстановление snapshot — ответственность
инфраструктуры вне продукта.

Mapping может завершиться решением `REJECT` или `DEFER`, но не может пропустить
семейство без явного обоснования.

## Gate для адаптера

Адаптер реализации может быть принят только если одновременно выполнены условия:

- соответствующий нормативный control прошёл требуемые source gates;
- существует APPLY semantic contract для семейства этого адаптера;
- зафиксировано решение donor mapping, если переиспользуется поведение донора;
- существуют положительные и отрицательные tests;
- явно определено поведение transaction-local failure/compensation;
- ответственность за post-APPLY rollback явно отнесена к external snapshot recovery;
- сгенерированный output способен нести машинно проверяемую provenance.

## Правило итогового распространяемого артефакта

Итоговый распространяемый артефакт v3 (имя пока не закреплено) должен быть
детерминированным артефактом сборки, а не вручную поддерживаемым источником истины.
`securelinux-ng.sh` остаётся именем исторического donor artifact и не закрепляет
имя будущего distributable v3.

Сборка не должна зависеть от:

- временных меток;
- абсолютных путей хоста сборки;
- порядка обхода файловой системы;
- текста времени выполнения unittest;
- зависящего от locale недетерминированного output.

Каждый выдаваемый блок реализации должен нести машинно проверяемую
provenance как минимум для:

- `control_id`;
- locator источника;
- `quote_sha256`;
- id/version адаптера реализации.

## Связь с утверждённым roadmap

Эта политика не дублирует текущие статусы roadmap. Канонический порядок, `step_id`
и статус каждой строки берутся только из `ROADMAP-v3.tsv`; человекочитаемый current
checkpoint показывает `PROJECT-MAP-v3.md`. Изменение roadmap должно сначала менять
machine truth, а не ручную копию статусов в этой policy.

`DONOR_TO_V3_MAPPING` является обязательным предварительным условием шага 8 и уже
принят/опубликован. Это разрешает начать semantic-contract gate, но не реализацию
APPLY и не mutation host state.

`RESTORE` не является этапом roadmap и НЕ ДОЛЖЕН появляться вследствие повторного
использования донора. При этом исторический `SecureLinux-NG` имел полноценный
standalone operational-контур RESTORE с manifest/backups, модульным восстановлением
и специализированными regression-тестами. В v3 этот operational-контур целиком не
переносится: он остаётся historical evidence; отдельные доказанные primitives могут
быть `ADAPT` исключительно для transaction-local compensation внутри
failed/uncommitted APPLY.
