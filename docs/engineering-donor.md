# Перенос инженерного донора

SecureLinux-Policy v3 сохраняет старую реализацию SecureLinux-NG как
**ненормативный инженерный донор**.

Закреплённый инженерный donor:

- `archive/securelinux-ng.sh`
- SHA-256 `f3be8723cd5a2be499e9e8e6370fad712bdec8afd68050f27af6a3e2d6fbc34b`
- 18 928 строк

Закреплённый финальный обзор архитектуры:

- `archive/engineering-review-20260731/SecureLinux-NG-architecture-final-review-20260731-112906.tar.gz`
- SHA-256 `7a62c1304a423e4431b08c34e999ed221777d63ecfb0aec180767fadf80759d2`

## Что принято сейчас

Следующие свойства приняты как invariants APPLY. Для `SRC-0001` применимая часть
была реализована и привязана к локальной композиции; решением DP-3 эта вертикаль
выведена из product APPLY и сохранена как historical bytes. Действующие механизмы
перечислены в APPLY registries; остальные пункты не объявляются реализованными
для других будущих classes:

- fail-closed backup до mutation;
- atomic replacement критических файлов;
- exclusive locking для mutating runs;
- атомарные обновления manifest;
- явные warnings и классификация irreversible/partial changes;
- targeted sysctl APPLY с захватом live-value pre-state для transaction-local failure handling;
- отслеживание package pre-state/delta;
- exact compensating rollback внутри failed, uncommitted APPLY transaction, когда это доказано contract;
- external snapshot rollback после завершённого APPLY; без user-invokable RESTORE mode;
- исполняемые architecture regression tests.

Точный evidence машинно индексируется в
`index/engineering-donor-v1/ENGINEERING-CONTRACTS.tsv`.

## Обратный индекс

`index/engineering-donor-v1/` делает donor механически прослеживаемым:

- все 310 найденных объявлений shell functions;
- все 18 928 строк source, покрытые 190 детерминированными chunks по 100 строк;
- 141 семантический кандидат;
- 478 строк raw evidence;
- 20 инженерных contracts.

Это обеспечивает сохранность donor implementation без объявления его
нормативной истиной.

## Финальный набор регрессий v16.2.11

Полный загруженный проект v16.2.11 закреплён в
`archive/engineering-donor-v16.2.11/`.

SHA-256 исходного ZIP:

`1b25f554a5ad1509037aa9613b7851a595159fd44291913cc2dba63280e50494`

Набор содержит 38 test-файлов и 36 точечных regression-скриптов. Donor `smoke.sh`
подключает все 36 regressions ровно по одному разу. Машинный реестр в
`index/engineering-tests-v1/` фиксирует каждый test, его SHA/size/line count,
adoption status, 32 generalized engineering contracts и исторические доказательства donor VM.

Один donor component безопасен и полезен уже сейчас: `tools/write-sha256.py`
принят как active project helper вместе со своим regression test. Он не зависит
от старого монолитного runtime.

Исторические mapping-тесты остаются `historical-only`; они никогда не используются как
v3 normative evidence или для закрытия source rows.

См. `docs/testing-strategy.md`.

## DONOR_TO_V3_MAPPING

Перед roadmap step 8 построен machine-readable candidate
`index/engineering-donor-v1/DONOR-TO-V3-MAPPING.tsv`.

Текущий принятый mapping:

- покрывает 310/310 donor-функций;
- покрывает 38/38 donor test files;
- отдельно учитывает все 16 mature families из
  `docs/DONOR-V3-ADOPTION-POLICY.md`;
- связывает 20 существующих engineering contracts и 32 обобщённых donor test
  контракта;
- использует только `REUSE | ADAPT | REJECT | DEFER`;
- имеет `normative_effect=NONE` и закрывает 0 source-index rows.

Статус mapping: `MAPPING_ACCEPTED_COMMITTED`. Он прошёл независимый review и precommit,
затем опубликован commit `1db91b0e17d6ef37e4c42cd41dca77eeb2b743da`
с tree `d3f624651bf13f1174619cef881fababbc768553`.
Решения: `REUSE=1`, `ADAPT=178`, `REJECT=91`, `DEFER=94`;
`RESTORE_OPERATIONAL_CONTOUR=EXCLUDED`, восстановление после APPLY=`EXTERNAL_SNAPSHOT`.
`APPLY_SEMANTIC_CONTRACT_ALLOWED=true`: разрешено начать отдельный семантический
контракт APPLY, но реализация APPLY и изменение host state этим не разрешены.

`password-policy-regression.sh` остаётся donor `DEFER` для будущей
corporate/APPLY-фазы. В current `fstec-linux-2022 CHECK` он не переносится.
Сохранённые будущие engineering details: PAM multiarch, preflight словарей до
mutation, выбор активных аккаунтов и dry-run плана `chage`.

## Что это не меняет

Этот перенос не:

- создаёт controls;
- закрывает FSTEC source rows;
- меняет `index/source-v4`;
- меняет семантику Gate 1–5;
- предоставляет reference-VM evidence;
- сам по себе реализует APPLY или RESTORE. RESTORE не планируется; любая
  APPLY-реализация допускается только через отдельные v3 contracts, registry,
  binding и tests. Прежняя `SRC-0001` APPLY-реализация решением DP-3 выведена
  из product APPLY.

Сам donor adoption закрывает 0 FSTEC source rows. Текущим фактическим покрытием управляют
`SOURCE-INDEX.tsv` и generated `docs/fstec-coverage.md`.
