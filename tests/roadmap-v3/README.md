# roadmap-v3 regressions

Набор проверяет архитектурные и roadmap invariants без фиксации presentation
деталей: точных русских status-фраз, числа Mermaid-блоков или исторических
счётчиков controls.

Текущие числа source/controls/adapters берутся из machine truth; root README и
PROJECT-MAP содержат machine-owned blocks, которые формирует
`tools/render-current-docs.py`.

Проверяются: primary project map, donor/non-normative policy, macro-roadmap
order и согласованность текущего product status.

Errata 0.0.13: `test_project_map_v3.py` дополнительно запрещает изображать уже реализованные CHECK adapters/generator как future и проверяет current product checkpoint `SRC-0005 → CHECK-11`; `test_current_status.py` связывает этот checkpoint с current SOURCE-INDEX/CONTROL-MANIFEST/ADAPTER-REGISTRY.

Current checkpoint regression requires SRC-0005/CHECK-11 and the six-row sysctl exact-eq CHECK-17 batch to be DONE before systematic FSTEC expansion remains the single current node.
