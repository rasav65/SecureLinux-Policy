# checker/gates-v3

Independent-audit repairs B-01/B-02/B-03 plus R2/R3 parity repairs are retained.

Gate 5 is currently executable for the sysctl pilot only. Observation wire
types are no longer generically coerced: `sysctl` uses string wire values,
while future `systemd-unit-state` and `package-presence` boolean probes are
reserved to emit JSON booleans. See `docs/observation-value-contract.md`.
