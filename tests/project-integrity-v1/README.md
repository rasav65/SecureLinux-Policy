# project-integrity-v1

Root-manifest reproducibility and Git-ignore population regression.

Дополнительно проверяется, что каждый tracked `tests/**/SHA256SUMS` ссылается только на tracked regular files с совпадающими SHA-256; `__pycache__` и иные ignored runtime/cache paths в test manifests запрещены.
