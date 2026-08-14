# sysctl-v1 read-only probe

Probe only reads `/proc/sys`; it does not call `sysctl -w`, write `/proc/sys`, or change configuration. `VALUE` and `NOT_FOUND` are valid execution outcomes.

Reference VM:
`python3 probe.py --selftest`
`python3 probe.py --plan probe-plan.tsv --output probe-results.json`

Первый фактический reference-VM прогон сохранён в
`evidence/ubuntu-24.04.4-minimal-testmin-20260814/`.

На Ubuntu 24.04.4 Minimal файл `/proc/sys/net/core/bpf_jit_harden` оказался
`0600 root:root`: непривилегированный read-only прогон корректно вернул
`ERROR`, а повторный read-only прогон через `sudo` дал 5/5 `VALUE`.
Gate 5 для privileged evidence: PASS; четыре policy noncompliance не являются
ошибкой исполнимости probe.
