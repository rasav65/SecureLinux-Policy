# Привязка evidence

`Gate 6 / evidence_binding` закрывает разрыв между валидным probe-results JSON и
пакетом evidence, который утверждает, что описывает способ его получения.

Он связывает:

`VM-METADATA.txt -> probe.py -> probe-plan.tsv -> privileged result -> unprivileged result -> evidence/SHA256SUMS`

Это только гарантия целостности и привязки. Она намеренно **не является**
криптографической аттестацией того, что файлы действительно были получены на
указанной VM.

Текущая реализация ограничена фактическим pilot evidence `sysctl-v1`. Новые
probe kinds до принятия этим gate обязаны определить собственные контракты
metadata/results для evidence.
