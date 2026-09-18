# Регрессии roadmap-v3

Набор проверяет архитектурные и roadmap invariants без фиксации presentation
деталей: точных русских status-фраз, числа Mermaid-блоков или исторических
счётчиков controls.

Текущие числа source/controls/adapters берутся из machine truth; root README и
PROJECT-MAP содержат machine-owned blocks, которые формирует
`tools/render-current-docs.py`.

Проверяются: primary project map, donor/non-normative policy, macro-roadmap
order и согласованность текущего product status.

Errata 0.0.13: `test_project_map_v3.py` дополнительно запрещает изображать уже реализованные CHECK adapters/generator как future и проверяет завершённую цепочку `SRC-0005 → CHECK-11`; `test_current_status.py` связывает текущий checkpoint с current SOURCE-INDEX/CONTROL-MANIFEST/ADAPTER-REGISTRY и machine-readable roadmap.

Регрессия текущего checkpoint требует, чтобы принятые CHECK milestones оставались
завершённой историей, `DONOR_TO_V3_MAPPING` был `ACCEPTED_COMMITTED`, authority refresh
`AUTHORITY_2026_REFRESH`, `SRC0001_MODULAR_APPLY_CONTRACT_ARCHITECTURE`,
`SRC0001_PREDICATE_TRANSFORM_DEFINITIONS`, `SRC0001_SNAPSHOT_PRECONDITION_DEFINITION`,
`SRC0001_LOCK_REREAD_OBJECT_IDENTITY_DEFINITIONS`, `SRC0001_METADATA_TRANSACTION_REPORT_DEFINITIONS`,
`APPLY_IMPLEMENTATION_ADAPTERS`, `FINAL_DETERMINISTIC_PACKAGING` и
`SINGLE_DISTRIBUTABLE_ARTIFACT` имели `CLOSED`; текущая вертикаль достигла
`DOCUMENT COMPLETE`, а единственный `NEXT` — Step 7B
`FSTEC_AND_CORPORATE_INDEX_EXPANSION_DISPOSITIONS`. Историческая SRC-0001 APPLY-вертикаль,
решением DP-3 выведенная из product APPLY, сохраняется побайтово: восемь ролей определений
и композиция остаются точно привязанными по SHA-256, а `local-account-password-lock`
обязан отсутствовать в обоих APPLY registries.

Дополнительно проверяется framework authority chain
`fstec-order-117-2025-requirements` + `fstec-order-137-2026-amendments-to-117`,
image-only page-pinned provenance и отсутствие автоматического переоткрытия
`SRC-0001…SRC-0040`.

Current `index/source-v4/PROGRESS.txt` проверяется как exact six-key machine truth,
включая `DISPOSED_CLOSED_ROWS`; stale, duplicate и extra keys запрещены.
