# Gate 6 — evidence_binding

Gate 6 proves **integrity and binding** of a stored reference-VM evidence
package. It does not prove that the evidence cryptographically originated from
the named VM.

For the current `sysctl-v1` evidence it requires:

1. evidence `SHA256SUMS` has the exact expected basename set and every digest
   matches the stored file;
2. `VM-METADATA.txt` is a closed `KEY=VALUE` record using
   `securelinux-policy-reference-vm-metadata-v1`;
3. metadata `PROBE_SHA256` equals the current `probes/sysctl-v1/probe.py`;
4. metadata `PROBE_PLAN_SHA256` equals the current
   `probes/sysctl-v1/probe-plan.tsv`;
5. metadata privileged/unprivileged result hashes equal the two stored JSON
   result files;
6. both JSON result roots are closed, use the expected result schema,
   `probe_kind=sysctl`, and `read_only=true`.

Gate 6 explicitly emits `VM_ORIGIN_ATTESTATION=NOT_PROVEN`.

The gate does not replace Gate 5. Gate 5 evaluates probe observations against
controls; Gate 6 binds the evidence files to the recorded metadata and current
probe/plan.
