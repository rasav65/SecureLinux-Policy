# Покрытие FSTEC core

> **GENERATED FILE.** Формируется `tools/render-current-docs.py` из `SOURCE-INDEX.tsv`, `CLOSURE-CONTRACT.tsv`, `CONTROL-MANIFEST.tsv` и `ADAPTER-REGISTRY.tsv`. Ручное редактирование запрещено.

## Сводка

```text
TOTAL_INDEX_ROWS=349
CONTROLLED_CLOSED_WITH_CONTRACT=26
DISPOSED_CLOSED_ROWS=0
OPEN_INDEX_ROWS=323
CANONICAL_CONTROLS=35
```

Число canonical controls и число закрытых source rows — разные величины: одна строка источника может требовать `exact-control-set` из нескольких controls.

## Controlled CLOSED

| Source row | Locator | Coverage mode | Canonical controls | Parameter kind | CHECK adapter |
|---|---|---|---|---|---|
| SRC-0001 | 2.1.1 | atomic-single | `FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE` | `local-account-password-state` | `product-local-account-password-state-check-v1` |
| SRC-0005 | 2.3.1 | exact-control-set | `FSTEC-LINUX-2022-2.3.1-GROUP-MODE`<br>`FSTEC-LINUX-2022-2.3.1-PASSWD-MODE`<br>`FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX` | `file-mode-owner` | `product-file-mode-owner-check-v1` |
| SRC-0010 | 2.3.6 | exact-control-set | `FSTEC-LINUX-2022-2.3.6-CRONTAB`<br>`FSTEC-LINUX-2022-2.3.6-CRON-D`<br>`FSTEC-LINUX-2022-2.3.6-CRON-HOURLY`<br>`FSTEC-LINUX-2022-2.3.6-CRON-DAILY`<br>`FSTEC-LINUX-2022-2.3.6-CRON-WEEKLY`<br>`FSTEC-LINUX-2022-2.3.6-CRON-MONTHLY` | `optional-file-root-files-mode` | `product-optional-file-root-files-mode-check-v1` |
| SRC-0016 | 2.4.1 | atomic-single | `FSTEC-LINUX-2022-2.4.1-DMESG-RESTRICT` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0017 | 2.4.2 | atomic-single | `FSTEC-LINUX-2022-2.4.2-KPTR-RESTRICT` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0018 | 2.4.3 | atomic-single | `FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC` | `kernel-cmdline` | `product-kernel-cmdline-check-v1` |
| SRC-0019 | 2.4.4 | atomic-single | `FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE` | `kernel-cmdline` | `product-kernel-cmdline-check-v1` |
| SRC-0020 | 2.4.5 | exact-control-set | `FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE`<br>`FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT`<br>`FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH` | `kernel-cmdline` | `product-kernel-cmdline-check-v1` |
| SRC-0021 | 2.4.6 | atomic-single | `FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET` | `kernel-cmdline` | `product-kernel-cmdline-check-v1` |
| SRC-0022 | 2.4.7 | atomic-single | `FSTEC-LINUX-2022-2.4.7-MITIGATIONS` | `kernel-cmdline` | `product-kernel-cmdline-check-v1` |
| SRC-0023 | 2.4.8 | atomic-single | `FSTEC-LINUX-2022-2.4.8-BPF-JIT-HARDEN` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0024 | 2.5.1 | atomic-single | `FSTEC-LINUX-2022-2.5.1-VSYSCALL` | `kernel-cmdline` | `product-kernel-cmdline-check-v1` |
| SRC-0025 | 2.5.2 | atomic-single | `FSTEC-LINUX-2022-2.5.2-PERF-EVENT-PARANOID` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0027 | 2.5.4 | atomic-single | `FSTEC-LINUX-2022-2.5.4-KEXEC-LOAD-DISABLED` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0028 | 2.5.5 | atomic-single | `FSTEC-LINUX-2022-2.5.5-MAX-USER-NAMESPACES` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0029 | 2.5.6 | atomic-single | `FSTEC-LINUX-2022-2.5.6-UNPRIVILEGED-BPF-DISABLED` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0030 | 2.5.7 | atomic-single | `FSTEC-LINUX-2022-2.5.7-UNPRIVILEGED-USERFAULTFD` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0031 | 2.5.8 | atomic-single | `FSTEC-LINUX-2022-2.5.8-LDISC-AUTOLOAD` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0032 | 2.5.9 | atomic-single | `FSTEC-LINUX-2022-2.5.9-TSX` | `kernel-cmdline` | `product-kernel-cmdline-check-v1` |
| SRC-0033 | 2.5.10 | atomic-single | `FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0035 | 2.6.1 | atomic-single | `FSTEC-LINUX-2022-2.6.1-PTRACE-SCOPE` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0036 | 2.6.2 | atomic-single | `FSTEC-LINUX-2022-2.6.2-PROTECTED-SYMLINKS` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0037 | 2.6.3 | atomic-single | `FSTEC-LINUX-2022-2.6.3-PROTECTED-HARDLINKS` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0038 | 2.6.4 | atomic-single | `FSTEC-LINUX-2022-2.6.4-PROTECTED-FIFOS` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0039 | 2.6.5 | atomic-single | `FSTEC-LINUX-2022-2.6.5-PROTECTED-REGULAR` | `sysctl` | `product-sysctl-check-v2` |
| SRC-0040 | 2.6.6 | atomic-single | `FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE` | `sysctl` | `product-sysctl-check-v2` |

## Canonical controls, ещё не закрывающие source row

Сейчас таких controls нет.

## Готовность CHECK adapters

| Parameter kind | Adapter | Read-only | Canonical controls сейчас |
|---|---|---:|---:|
| `file-mode-owner` | `product-file-mode-owner-check-v1` | yes | 3 |
| `kernel-cmdline` | `product-kernel-cmdline-check-v1` | yes | 9 |
| `local-account-password-state` | `product-local-account-password-state-check-v1` | yes | 1 |
| `optional-file-root-files-mode` | `product-optional-file-root-files-mode-check-v1` | yes | 6 |
| `sysctl` | `product-sysctl-check-v2` | yes | 16 |

## Покрытие по исходным документам

| Source document | Total rows | Controlled CLOSED | Disposed CLOSED | OPEN | Canonical controls |
|---|---:|---:|---:|---:|---:|
| fstec-configuration-2026 | 49 | 0 | 0 | 49 | 0 |
| fstec-linux-2022 | 40 | 26 | 0 | 14 | 35 |
| fstec-logging-2025 | 14 | 0 | 0 | 14 | 0 |
| fstec-perimeter-2026 | 35 | 0 | 0 | 35 | 0 |
| fstec-security-update-testing-2022 | 70 | 0 | 0 | 70 | 0 |
| fstec-vulnerability-analysis-2025 | 61 | 0 | 0 | 61 | 0 |
| fstec-vulnerability-criticality-2025 | 28 | 0 | 0 | 28 | 0 |
| fstec-vulnerability-management-2023 | 52 | 0 | 0 | 52 | 0 |

Эта таблица описывает фактическую структуру корпуса, а не обещание превратить каждую `OPEN` строку в host CHECK. По контракту source index строка закрывается canonical control-set либо explicit disposition; выбор зависит от source semantics.

## Открытая часть корпуса

`323` source rows остаются `OPEN`. Полный перечень и их source metadata находятся в `index/source-v4/SOURCE-INDEX.tsv`; этот документ не дублирует 349 строк вручную.

Наличие adapter или canonical control само по себе не закрывает source row: закрытие определяется source status и `CLOSURE-CONTRACT.tsv` либо explicit disposition.
