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

Parent schema `product/contracts/apply-semantic-contract-v1.schema.json` — историческая
coarse gate: код валидирует ею только flat SRC-0001 semantic-кандидат. Действующие механизмы
APPLY описаны документами формы `MECHANISM_AUTHORITY_V1` и схемой не валидируются;
authority-документ содержит только поля, которые читает код. Схема
`apply-semantic-contract-v2.schema.json` удалена решением B: код её не читал.
`product/APPLY-KIND-REGISTRY.tsv` не дублирует low-level
predicate/transform/path/lock/transaction semantics: каждая строка связывает `apply_kind` +
`target_class` с authority-документом механизма по SHA-256.

Историческая SRC-0001 APPLY-вертикаль решением DP-3 выведена из product APPLY; её bytes
сохранены как evidence и в APPLY registries не входят. Ниже описано её состояние на момент
закрытия. Для kind `local-account-password-lock` registry связывал exact
`product/contracts/src0001-apply/architecture-v1.json`. Architecture object пинует
parent schema, flat SRC-0001 `REVISE` candidate, CHECK population authority и
Draft 2020-12 composition schema; восемь low-level definition roles были локальными для `SRC-0001` до
второго доказанного случая использования. `target_class` должен был совпадать между registry и architecture;
устаревшая SHA-привязка давала `FAIL`. Predicate и transform были отдельно закреплены
как closed SHA-bound definitions: exact empty second shadow field и exact `"" -> "!"`
с сохранением всех невыбранных bytes. Это закрыло P-03, не перенося donor semantics.

P-04 был закрыт отдельным `snapshot-precondition-v1.json`: caller-supplied read-only attestation
требовалась до host mutation и exact связывала host identity и `/etc/shadow` prestate SHA-256
с external provider/snapshot id и READY rollback-capable full-host/VM snapshot. Missing, malformed,
mismatched или not-ready evidence → `ABORT_NO_MUTATION`; attestation явно не выдавалась за
provider-cryptographic proof. P-05 был закрыт отдельными `lock-reread-v1.json` и
`object-identity-v1.json`: exclusive libc `lckpwdf(3)` password-database lock предшествовал under-lock reread обеих `/etc/passwd` и `/etc/shadow`,
bytes/selected-set drift означал stale abort, а `/etc/shadow` должен был оставаться regular,
non-symlink, single-link object с nofollow fd/fstat identity binding. P-06 был закрыт exact metadata-preservation, atomic-transaction и dry-run/report definitions;
composition связывает все восемь `CLOSED` roles по SHA-256. Implementation
`product-local-account-password-state-apply-v1` была привязана отдельным
`APPLY-IMPLEMENTATION-REGISTRY.tsv`, binding и SHA-256, была встроена в generated CLI
и закрыла этап `APPLY_IMPLEMENTATION_ADAPTERS`. Решением DP-3 эта строка из реестра и
цепочка из generated CLI удалены; действующие механизмы перечислены в APPLY registries.
Это не закрывает дополнительных строк source index.

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
