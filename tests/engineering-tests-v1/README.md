# Тесты engineering-tests-v1

`test_donor_test_suite.py` механически проверяет закреплённый ZIP v16.2.11, все
38 donor tests, wiring 36/36 через smoke, 32 generalized contract rows,
изоляцию legacy normative evidence и active portable SHA helper.

`portable-sha256-regression.sh` — donor test, принятый напрямую, потому что он
проверяет только `tools/write-sha256.py` и не зависит от старого монолитного
скрипта.

Эти tests не утверждают, что future APPLY или contracts failed-transaction
compensation уже реализованы. Они только не дают потерять donor evidence и
registry в процессе построения SecureLinux-Policy. Post-APPLY RESTORE остаётся исключённым.

Current `PROGRESS.txt` проверяется как exact machine contract: полный key-set и derived counts должны совпадать с ZIP/inventory/contracts; stale, duplicate и extra keys завершаются fail-closed.
