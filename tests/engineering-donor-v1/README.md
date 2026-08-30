# Тесты engineering-donor-v1

`test_donor_index.py` проверяет:

- exact donor SHA и число строк 18 928;
- все 310 function-index rows относительно donor source;
- полное покрытие всех donor bytes/lines через 190 chunks;
- 141 semantic candidate rows и 478 raw-evidence rows;
- все engineering contracts ссылаются на реальные donor markers и остаются
  `PENDING_NOT_ACTIVE`;
- SHA исходного финального architecture review archive и SHA извлечённого member;
- архивный `architecture-regression.sh` без изменений проходит на закреплённом
  donor script и архивном `docs/architecture.md`.

Тест не считает ни один donor item FSTEC control.

`test_donor_index.py` дополнительно проверяет candidate `DONOR_TO_V3_MAPPING`:

- 310/310 donor-функций с exact segment SHA;
- 38/38 donor test files с exact SHA;
- все 20 `ENG-*` и 32 `TST-*` contracts;
- все 16 mandatory mature families;
- только `REUSE | ADAPT | REJECT | DEFER`;
- `normative_effect=NONE`, `closes_source_rows=0`;
- `password-policy-regression.sh` остаётся `DEFER` для будущей
  corporate/APPLY-фазы;
- status `MAPPING_ACCEPTED_COMMITTED` привязан к commit `1db91b0…` / tree `d3f62465…`; `APPLY_SEMANTIC_CONTRACT_ALLOWED=true` разрешает только следующий design-gate семантического контракта APPLY.

Current `PROGRESS.txt` разбирается fail-closed: полный key-set, уникальные ключи и derived/pinned values обязаны совпадать; stale, duplicate, malformed и extra keys запрещены.
