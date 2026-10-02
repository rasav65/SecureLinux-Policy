# Gates 1–5 — checker-v2

Gates 1–4 наследуют семантику checker-v1 без изменений.

Gate 5 является execution-only: каждый active control обязан иметь ровно один
read-only probe result. `VALUE` и явный `NOT_FOUND` являются успешными outcomes
выполнения. VALUE может быть policy-compliant или noncompliant; compliance
считается отдельно. `ERROR`, missing/duplicate/mismatched evidence приводят к
FAIL для Gate 5.

checker-v2 сейчас имеет runtime runner только для `sysctl`.
