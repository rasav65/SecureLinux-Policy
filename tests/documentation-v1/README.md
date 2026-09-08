# documentation-v1 — проверки документации

Целевая regression-проверка базовой линии документации.

Проверяет exact parity `tools/render-current-docs.py --check`, полноту
`docs/README.md`, единственную primary project map, policy-layer boundary,
compatibility terminology и отсутствие известных stale product-status строк.

Тест входит в DEV автоматически через tracked `tests/*/test_*.py` population.

Errata 0.0.13: regression также проверяет, что PRIMARY current map не показывает historical Step 7B node как текущий product checkpoint и не переносит имя donor `securelinux-ng.sh` на будущий distributable artifact.

Регрессия текущего продукта требует, чтобы сгенерированные документы совпадали с machine truth, сохраняли SRC-0005/CHECK-11, CHECK-17, SRC-0040/CHECK-18, SRC-0033/CHECK-19 и kernel-cmdline CHECK-28 как завершённую историю, показывали coverage по каждому source document, фиксировали `AUTHORITY_2026_REFRESH`, все этапы definitions, `APPLY_IMPLEMENTATION_ADAPTERS`, `FINAL_DETERMINISTIC_PACKAGING` и `SINGLE_DISTRIBUTABLE_ARTIFACT` как закрытые, точку `DOCUMENT COMPLETE` текущей вертикали и Step 7B как единственный текущий `NEXT`.

Русский documentation baseline: действующий контур `checker/gates-v3`, `docs/observation-value-contract.md` и README его тестов обязан сохранять русский человекочитаемый текст; технические identifiers/wire markers переводить не требуется.

Contradiction-aware baseline дополнительно сканирует весь current Markdown вне явно historical/current-authority=false областей: inline-code не скрывает live-count claims, а противоположные current утверждения об APPLY-adapters, Step 7B, post-APPLY recovery, зрелости donor RESTORE, детерминизме и имени будущего executable должны завершаться fail-closed. Fixture counts не считаются semantic proof.

Дополнительная fail-closed граница `CURRENT-MARKDOWN-REVIEW-BASELINE.tsv`
фиксирует exact bytes всей current human-readable Markdown population, кроме
`CHANGELOG.md` и явно historical step7b0 status-документа.
Это **не semantic proof** и не machine truth: baseline является review-bound
change-control артефактом. Обычная пересборка корневых manifests не обновляет его.
Любое изменение current Markdown обязано снова пройти semantic review и только
после этого может получить новую baseline identity; неизвестная перефразировка
не становится PASS только потому, что её синонима нет в regex.

Git-visible population для current Markdown включает tracked и non-ignored untracked candidate paths; новый документ до commit не может обойти language/semantic/review-bound gates.
