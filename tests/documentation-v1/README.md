# documentation-v1

Focused regression для Documentation Baseline.

Проверяет exact parity `tools/render-current-docs.py --check`, полноту
`docs/README.md`, единственную primary project map, policy-layer boundary,
compatibility terminology и отсутствие известных stale product-status строк.

Тест входит в DEV автоматически через tracked `tests/*/test_*.py` population.
