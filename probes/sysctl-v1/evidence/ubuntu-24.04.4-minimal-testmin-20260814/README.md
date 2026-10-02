# Reference VM evidence — sysctl-v1

This directory preserves the first factual v3 Gate 5 run for the five-control
sysctl pilot.

Environment: Ubuntu 24.04.4 LTS minimized, host `testmin`,
kernel `6.8.0-134-generic`.

Evidence:
- `probe-results-unprivileged.json` — read-only run as ordinary user;
  four VALUE observations and one ERROR because
  `/proc/sys/net/core/bpf_jit_harden` is `0600 root:root`.
- `probe-results-root.json` — repeated read-only run through `sudo`;
  five VALUE observations, zero ERROR, four policy noncompliance observations.
- `VM-METADATA.txt` — machine-generated environment and checksum metadata.
- `CHECKER-OUTPUT.txt` / `CHECKER-REPORT.json` — active gates-v3 checker result.
- `RESULT.txt` — compact gate summary.

Gate 5 PASS proves executable, internally consistent evidence for this pilot.
It does not claim that the reference VM is policy-compliant and it does not
close the remaining 344 source-index rows.
