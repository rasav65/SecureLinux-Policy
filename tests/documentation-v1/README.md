# documentation-v1

Focused regression для Documentation Baseline.

Проверяет exact parity `tools/render-current-docs.py --check`, полноту
`docs/README.md`, единственную primary project map, policy-layer boundary,
compatibility terminology и отсутствие известных stale product-status строк.

Тест входит в DEV автоматически через tracked `tests/*/test_*.py` population.

Errata 0.0.13: regression также проверяет, что PRIMARY current map не показывает historical Step 7B node как текущий product checkpoint и не переносит имя donor `securelinux-ng.sh` на будущий distributable artifact.

Current-product regression: generated docs must match machine truth, keep SRC-0005/CHECK-11 as completed history, include CHECK-17, SRC-0040/CHECK-18, SRC-0033/CHECK-19 and the kernel-cmdline exact-token CHECK-28 batch, expose per-source-document coverage, and leave systematic FSTEC expansion as the single current checkpoint.
