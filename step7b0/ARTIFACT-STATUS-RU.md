# SecureLinux-Policy v3 — Step 7B.0


## ОБНОВЛЕНИЕ 2026-08-18 — текущая линия v0.9.4-R1

Этот раздел имеет приоритет над более ранними историческими разделами этого
файла. Ранее созданные v0.9.3 Phase-B/Phase-C артефакты сохраняются только как
история и **не являются текущим evidence** под v0.9.4-R1.

Текущая нормативная identity:

- `step7b0/BUILD-CONTRACT-v0.9.4.md`;
- SHA-256 `3f5264eca11a471bdcc87494b7b2399d7d6136af02296b6fd39dd444c5955cbf`;
- Phase A: `16/16 PASS`, independently accepted;
- `PHASE-A-MEMBERS.json` SHA-256 `d70060648c4e58fe6c49b02184ee96093eac82247dd089dc31a95f0b576f9080`;
- `PHASE-A-ADMISSION.json` SHA-256 `4d9bfb9a20f25f3e96723067d9fcd00ddec9d6414f6688b24d7a86514a3c88f7`;
- item 10: `build-environment-v2`, SHA-256 `9fa66d73a492eb0c3562610fb9813c29694a2db5a8c722851ad13243d71c5b98`.

Текущая Phase-B линия:

- NON-RELEASE candidate:
  `step7b0/phase-b/securelinux-policy-builder-measurement-candidate-v5.py`;
- candidate SHA-256 `c8d6a0859445bbb1945daa2765591c21436cf970efdc0289b72198ac63a3d71d`;
- freeze:
  `step7b0/phase-b/PHASE-B-MEASUREMENT-CANDIDATE-FREEZE-v3.json`;
- freeze SHA-256 `18da6d13a62ecf53ffa724fdf927534783393aeb79e4f5d3495a88d1ba546000`;
- `measurement_performed=false`;
- `authoritative=false`;
- `publication_performed=false`.

Исторические и не-current под v0.9.4-R1:

- `step7b0/phase-b/securelinux-policy-builder-measurement-candidate-v4.py` — SHA-256 `678a8123261dd2d8419c738a14e7bf8923576c3ed26399f0a954d0e4eb6f561e`;
- `step7b0/phase-b/PHASE-B-MEASUREMENT-CANDIDATE-FREEZE-v2.json` — SHA-256 `2518b45676af3a97366e2ea242fd9e589772a1caf136e6623b8556317ac9e037`;
- все v0.9.3 contract-bound Phase-B measurement и Phase-C evidence.

Следующий разрешённый шаг после локальной проверки этого freeze —
**новое Phase-B measurement под v0.9.4-R1**. Старый v0.9.3 Step10B,
Phase D, publication, FSTEC expansion, APPLY/RESTORE запрещены.

## Статус артефактов после создания Phase-B freeze

Дата фиксации классификации: 2026-08-17.

Этот документ не изменяет нормативное содержание Build Contract и не заменяет
криптографические identity. Его задача — однозначно отделить текущие,
исторические и заменённые артефакты рабочего дерева.

## 1. ACTIVE — текущая рабочая линия

- `step7b0/BUILD-CONTRACT-v0.9.3.md` — принятые точные байты Build Contract
  v0.9.3 R4-FINAL; SHA-256
  `aa1030729cfd96f804442143af354df8cf4ac97ebb4b02c551f9c071324a9729`.
- `step7b0/phase-a/PHASE-A-MEMBERS.json` — текущий состав Phase A.
- `step7b0/phase-a/PHASE-A-ADMISSION.json` — текущий admission Phase A.
- `step7b0/phase-b/securelinux-policy-builder-measurement-candidate-v4.py` —
  текущий measurement candidate под Build Contract v0.9.3; SHA-256
  `678a8123261dd2d8419c738a14e7bf8923576c3ed26399f0a954d0e4eb6f561e`.

Candidate v4 пока не является authoritative builder и не разрешён к публикации.
Phase-B freeze создан для exact candidate v4. Phase-B measurement до независимого аудита freeze не выполняется.

## 2. HISTORICAL — сохраняются как история и доказательная трасса

- `step7b0/BUILD-CONTRACT-v0.9.2.md`.
- `step7b0/phase-b/securelinux-policy-builder-measurement-candidate-v3.py`.
- `step7b0/phase-a/fixtures/traces/real-candidate-v3-trace-v1.json`.
- `step7b0/phase-a/fixtures/traces/real-candidate-v3-trace-v1.strace`.
- `step7b0/phase-a/fixtures/traces/real-candidate-v3-trace-v1.strace.sha256`.
- весь каталог `experiments/step7b0-builder-spike-v0.1/`.

Каталог `experiments/` локально исключён через `.git/info/exclude`, поэтому
не входит в Git-visible population и корневые manifests. Он сохраняется только
на рабочем ПК как локальная история экспериментов.

Исторический `real-candidate-v3-trace-v1.strace` одновременно остаётся членом
текущего `PHASE-A-MEMBERS.json`. Поэтому его историческое происхождение не
означает, что файл можно удалить, переместить или изменить.

## 3. SUPERSEDED — заменены и не являются текущими тестами/evidence

Следующие точные байты сохраняются только как история развития Item 9 и не
должны использоваться как текущий fitness/evidence набор:

- `step7b0/phase-a/fixtures/observer-adversarial-fitness-v2.json`;
- `step7b0/phase-a/fixtures/observer-fitness-v1.json`;
- `step7b0/phase-a/evidence/build-dependency-observer-fitness-evidence-v1.json`.

Они не входят в текущие 43 строки `PHASE-A-MEMBERS.json` и не имеют ссылок из
текущей активной поверхности. Их наличие в дереве не означает требование
прогонять их как действующий test suite.

## 4. Правило для стороннего аудита

Для решения о новом Phase-B freeze аудитор должен оценивать текущую ACTIVE
линию и текущий набор Phase-A members/admission. HISTORICAL и SUPERSEDED
артефакты проверяются только как история/provenance, если это требуется
конкретной проверкой.

## 5. Язык документации

Новая и редактируемая человекочитаемая документация проекта ведётся на русском
языке. Англоязычные документы, чьи точные байты уже являются принятой или
исторической identity, не переводятся путём изменения оригинала. Для них
создаются отдельные русские companion-переводы, не меняющие исходную identity.

Машинные ключи, имена полей, verdict tokens, CLI-параметры, код и контрактные
литералы сохраняются без перевода там, где перевод нарушил бы совместимость или
криптографическую идентичность.

## 6. Текущий Phase-B freeze

Создан machine-readable freeze:

- `step7b0/phase-b/PHASE-B-MEASUREMENT-CANDIDATE-FREEZE-v2.json`;
- SHA-256 `962e386816d7672e211e93d6a306e810f448b49cf785dac8d8d5085c829db897`;
- status `NON_RELEASE_MEASUREMENT_CANDIDATE`;
- candidate v4 SHA-256
  `678a8123261dd2d8419c738a14e7bf8923576c3ed26399f0a954d0e4eb6f561e`;
- Phase-A members SHA-256
  `04e23e3ab956eeb16406619edeaa1297cb2f9e8c3af8ab16526c26a6e9f54c05`;
- Phase-A admission SHA-256
  `4f2a7d18b0c18348985ca9308e45a49ae11ce987efad3b4a6e73397de235398d`;
- item-9 classification policy SHA-256
  `145655d166e494ba8ffc0dbc893e0b67c0f9302571a5729e100f63ee384b1174`;
- `MEASUREMENT_BUILDER_PATHS` = 24 exact path/SHA rows.

На момент создания freeze:

- Phase-B measurement не выполнялся;
- measurement evidence не создавался;
- authoritative-builder admission отсутствует;
- публикация не выполнялась;
- commit/push не выполнялись.

Следующий gate — независимый targeted audit exact freeze. Запуск Phase-B
measurement допустим только после `SAFE_TO_RUN_PHASE_B_MEASUREMENT=YES`.

## 7. Phase-B futex review и переиздание freeze

Первый trustworthy Phase-B measurement обнаружил один unresolved
`EVENT_OPERATION_KEY`: `(futex,null)`. После механического анализа raw trace
все 17 наблюдённых `futex` records имели exact operation
`FUTEX_WAKE_PRIVATE`.

В Item 9 выполнен policy-data RERUN без изменения parser/candidate:

- `futex` стал operation-sensitive по top-level argument index `1`;
- разрешён только exact key `(futex,FUTEX_WAKE_PRIVATE)`;
- effect scope: `thread_synchronization_local`;
- добавлен admitted fitness fixture `step7b0/phase-a/fixtures/observer-futex-review-fitness-v1.json`;
- `FUTEX_WAKE`, `FUTEX_WAIT_PRIVATE` и альтернативная textual форма
  `FUTEX_WAKE|FUTEX_PRIVATE_FLAG` остаются `REVIEW_REQUIRED`.

Новые bindings:

- classification policy SHA-256 `555d93dcea0d93505b188f40b4b80c7b292fef833c59770dba47210bb47cc5a0`;
- fitness evidence SHA-256 `d713d26a8c2d76988499fcdefd63de5372812cbc1f3da1e8a88b1c3a14e000c5`;
- Phase-A members SHA-256 `a36ff11efa1d7cbe4d3d8ce5273a3b45ce05c09310f675e459765d25b66e8329`;
- Phase-A admission SHA-256 `76917d7c86929230f6a04f4528bcc73568297f11ff13b2959f76872978aebd57`.

Предыдущий freeze SHA-256 `962e386816d7672e211e93d6a306e810f448b49cf785dac8d8d5085c829db897` более не является действующим
для нового Item-9 state. Canonical freeze переиздан по тому же пути с SHA-256
`2518b45676af3a97366e2ea242fd9e589772a1caf136e6623b8556317ac9e037` и связывает новые Phase-A/item-9 hashes. Candidate v4 bytes
не изменены.

Повторный Phase-B measurement запрещён до независимого targeted audit с
`SAFE_TO_RERUN_PHASE_B_MEASUREMENT=YES`.
