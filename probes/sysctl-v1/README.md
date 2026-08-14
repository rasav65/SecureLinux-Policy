# sysctl-v1 read-only probe

Probe only reads `/proc/sys`; it does not call `sysctl -w`, write `/proc/sys`, or change configuration. `VALUE` and `NOT_FOUND` are valid execution outcomes.

Reference VM:
`python3 probe.py --selftest`
`python3 probe.py --plan probe-plan.tsv --output probe-results.json`
