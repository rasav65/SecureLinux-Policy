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

Регрессия текущего checkpoint требует, чтобы принятые CHECK milestones оставались завершённой историей, `DONOR_TO_V3_MAPPING` был `ACCEPTED_COMMITTED`, макроэтап Step 7B имел статус `PAUSED_BY_CURRENT_DOCUMENT_APPLY`, а единственным `NEXT` был `APPLY_SEMANTIC_CONTRACT`.

Current `index/source-v4/PROGRESS.txt` проверяется как exact six-key machine truth, включая `DISPOSED_CLOSED_ROWS`; stale, duplicate и extra keys запрещены.
