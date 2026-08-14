# Gates 1–5 — checker-v2

Gates 1–4 inherit checker-v1 semantics unchanged.

Gate 5 is execution-only: every active control must have exactly one read-only probe result. `VALUE` and explicit `NOT_FOUND` are successful execution outcomes. A VALUE may be policy-compliant or noncompliant; compliance is counted separately. `ERROR`, missing/duplicate/mismatched evidence fails Gate 5.
checker-v2 currently has a runtime runner only for `sysctl`.
