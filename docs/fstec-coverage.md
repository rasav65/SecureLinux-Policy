# Покрытие FSTEC core

> **GENERATED FILE.** Формируется `tools/render-current-docs.py` из `SOURCE-INDEX.tsv`, `CLOSURE-CONTRACT.tsv`, `CONTROL-MANIFEST.tsv` и `ADAPTER-REGISTRY.tsv`. Ручное редактирование запрещено.

## Сводка

```text
TOTAL_INDEX_ROWS=349
CONTROLLED_CLOSED_WITH_CONTRACT=15
DISPOSED_CLOSED_ROWS=0
OPEN_INDEX_ROWS=334
CANONICAL_CONTROLS=17
```

Число canonical controls и число закрытых source rows — разные величины: одна строка источника может требовать `exact-control-set` из нескольких controls.

## Controlled CLOSED

| Source row | Locator | Coverage mode | Canonical controls | Parameter kind | CHECK adapter |
|---|---|---|---|---|---|
| SRC-0005 | 2.3.1 | exact-control-set | `FSTEC-LINUX-2022-2.3.1-GROUP-MODE`<br>`FSTEC-LINUX-2022-2.3.1-PASSWD-MODE`<br>`FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX` | `file-mode-owner` | `product-file-mode-owner-check-v1` |
| SRC-0016 | 2.4.1 | atomic-single | `FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0017 | 2.4.2 | atomic-single | `FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0023 | 2.4.8 | atomic-single | `FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0025 | 2.5.2 | atomic-single | `FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0027 | 2.5.4 | atomic-single | `FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0028 | 2.5.5 | atomic-single | `FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0029 | 2.5.6 | atomic-single | `FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0030 | 2.5.7 | atomic-single | `FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0031 | 2.5.8 | atomic-single | `FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0035 | 2.6.1 | atomic-single | `FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0036 | 2.6.2 | atomic-single | `FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0037 | 2.6.3 | atomic-single | `FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0038 | 2.6.4 | atomic-single | `FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS` | `sysctl` | `product-sysctl-check-v1` |
| SRC-0039 | 2.6.5 | atomic-single | `FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR` | `sysctl` | `product-sysctl-check-v1` |

## Canonical controls, ещё не закрывающие source row

Сейчас таких controls нет.

## Готовность CHECK adapters

| Parameter kind | Adapter | Read-only | Canonical controls сейчас |
|---|---|---:|---:|
| `file-mode-owner` | `product-file-mode-owner-check-v1` | yes | 3 |
| `sysctl` | `product-sysctl-check-v1` | yes | 14 |

## Открытая часть корпуса

`334` source rows остаются `OPEN`. Полный перечень и их source metadata находятся в `index/source-v4/SOURCE-INDEX.tsv`; этот документ не дублирует 349 строк вручную.

Наличие adapter или canonical control само по себе не закрывает source row: закрытие определяется source status и `CLOSURE-CONTRACT.tsv` либо explicit disposition.
