# engineering-tests-v1

Machine inventory финального regression suite SecureLinux-NG v16.2.11,
используемого только как инженерный donor для SecureLinux-Policy v3.

Факты, закреплённые из загруженного artifact:

- ZIP SHA-256: `1b25f554a5ad1509037aa9613b7851a595159fd44291913cc2dba63280e50494`
- donor script: 18 928 строк, SHA-256 `f3be8723cd5a2be499e9e8e6370fad712bdec8afd68050f27af6a3e2d6fbc34b`
- 38 test files / 11 420 строк / 305 334 bytes
- 36 файлов `*-regression.sh`
- `tests/smoke.sh` вызывает все 36 regression files ровно по одному разу
- 32 обобщённых инженерных test contracts

Нормативная изоляция обязательна: legacy `fstec-mapping-regression.sh` и
`wheel-fstec-regression.sh` являются только historical evidence. Они не могут
создавать или закрывать v3 FSTEC source-index rows. Donor filenames/classes,
содержащие `restore`, сохраняются как evidence identifiers там, где это нужно;
active future contract areas используют terminology APPLY compensation /
external recovery, а не отдельный RESTORE stage.

`DONOR-VM-EVIDENCE.tsv` фиксирует только VM history donor project; он никогда не
заменяет v3 Gate 5 или финальную VM matrix v3.
