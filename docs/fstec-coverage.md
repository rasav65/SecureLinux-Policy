# Покрытие FSTEC core

> **GENERATED FILE.** Формируется `tools/render-current-docs.py` из `SOURCE-INDEX.tsv`, `CLOSURE-CONTRACT.tsv`, `CONTROL-MANIFEST.tsv` и `ADAPTER-REGISTRY.tsv`. Ручное редактирование запрещено.

## Сводка

```text
TOTAL_INDEX_ROWS=349
CONTROLLED_CLOSED_WITH_CONTRACT=8
DISPOSED_CLOSED_ROWS=0
OPEN_INDEX_ROWS=341
CANONICAL_CONTROLS=8
```

Число canonical controls и число закрытых source rows — разные величины: одна строка источника может требовать `exact-control-set` из нескольких controls.

## Controlled CLOSED

| Source row | Locator | Coverage mode | Canonical controls | Parameter kind | CHECK adapter |
|---|---|---|---|---|---|
| SRC-0016 | 2.4.1 | atomic-single | `FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0017 | 2.4.2 | atomic-single | `FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0023 | 2.4.8 | atomic-single | `FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0025 | 2.5.2 | atomic-single | `FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0027 | 2.5.4 | atomic-single | `FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0028 | 2.5.5 | atomic-single | `FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0029 | 2.5.6 | atomic-single | `FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0035 | 2.6.1 | atomic-single | `FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE` | `sysctl` | `product-sysctl-check-v1` |

## Canonical controls, ещё не закрывающие source row

Сейчас таких controls нет.

## Готовность CHECK adapters

| Parameter kind | Adapter | Read-only | Canonical controls сейчас |
|---|---|---:|---:|
| `file-mode-owner` | `product-file-mode-owner-check-v1` | yes | 0 |
| `sysctl` | `product-sysctl-check-v1` | yes | 8 |

## Открытая часть корпуса

`341` source rows остаются `OPEN`. Полный перечень и их source metadata находятся в `index/source-v4/SOURCE-INDEX.tsv`; этот документ не дублирует 349 строк вручную.

Наличие adapter или canonical control само по себе не закрывает source row: закрытие определяется source status и `CLOSURE-CONTRACT.tsv` либо explicit disposition.
