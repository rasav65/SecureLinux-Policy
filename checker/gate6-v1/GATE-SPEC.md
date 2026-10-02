# Gate 6 — evidence_binding

Gate 6 доказывает **целостность и привязку** сохранённого пакета reference-VM
evidence. Он не доказывает криптографически, что evidence действительно был
получен на указанной VM.

Для текущего evidence `sysctl-v1` требуется:

1. evidence `SHA256SUMS` содержит точный ожидаемый набор basename, и каждый digest
   совпадает с сохранённым файлом;
2. `VM-METADATA.txt` является закрытой записью `KEY=VALUE` с форматом
   `securelinux-policy-reference-vm-metadata-v1`;
3. metadata `PROBE_SHA256` равен текущему `probes/sysctl-v1/probe.py`;
4. metadata `PROBE_PLAN_SHA256` равен текущему `probes/sysctl-v1/probe-plan.tsv`;
5. metadata hashes privileged/unprivileged results равны двум сохранённым JSON-
   файлам результатов;
6. оба корневых JSON-документа имеют закрытую структуру, используют ожидаемую
   схему результата, `probe_kind=sysctl` и `read_only=true`.

Gate 6 явно выводит `VM_ORIGIN_ATTESTATION=NOT_PROVEN`.

Gate не заменяет Gate 5. Gate 5 оценивает probe observations относительно
controls; Gate 6 связывает evidence files с записанными metadata и текущими
пробой/планом.
