# SecureLinux-Policy v3 — карта проекта и взаимодействий

> **Это основная архитектурная карта текущего SecureLinux-Policy v3.**
>
> Карта показывает действующие источники истины, текстовые корпуса, source
> index, controls, механические gates, reference-VM evidence, audit provenance,
> policy layers, engineering donor, текущую read-only CHECK product-line и путь к будущему distributable artifact.
>
> Старый SecureLinux-NG присутствует только как **engineering donor**. Его
> runtime-архитектура не является нормативной архитектурой v3 и сама по себе
> не закрывает source-index rows.

<!-- BEGIN GENERATED MAP STATUS -->
`source rows=349 · controlled CLOSED=40 · OPEN=309 · canonical controls=51 · adapters=18 · target=ubuntu-24.04-x86_64`

Точные таблицы покрытия: [`docs/fstec-coverage.md`](fstec-coverage.md).
<!-- END GENERATED MAP STATUS -->

Продуктовые правила слоёв: [`docs/policy-layers.md`](policy-layers.md).
Machine-generated coverage: [`docs/fstec-coverage.md`](fstec-coverage.md).
Текущая target-совместимость: [`docs/compatibility.md`](compatibility.md).

## Легенда

- зелёный — PASS/CLOSED **в явно указанном текущем scope**;
- серый — будущий этап;
- синий — действующий структурный компонент;
- фиолетовый — engineering donor;
- оранжевый используется **только в разделе «Где мы находимся»** и ровно один
  раз обозначает текущее место работы.

## 1. Источники → текстовые корпуса → index → controls → Gates

```mermaid
flowchart LR
    subgraph SRC["1. ПЕРВИЧНЫЕ ИСТОЧНИКИ"]
        PDF["sources/fstec/<br/>10 pinned PDF"]:::component
        PHASH["sources/fstec/SHA256SUMS"]:::component
        PDF --> PHASH
    end

    subgraph TEXT["2. ДВЕ ВЕТКИ ПОЛУЧЕНИЯ НОРМАЛИЗОВАННОГО ТЕКСТА"]
        RAWEXT["raw-pdftotext<br/>обычное извлечение<br/>10 документов"]:::component
        EXNORM["sources/extracted/norm-v1<br/>нормализованный extracted corpus<br/>10 документов"]:::component

        GLYPH["glyph-id-cross-document-v1<br/>PyMuPDF get_texttrace()<br/>ТОЛЬКО 2 документа"]:::component
        RAWREC["raw-glyph-recovered<br/>fstec-linux-2022<br/>fstec-vulnerability-analysis-2025"]:::component
        RECNORM["sources/recovered-v1/norm-v1<br/>нормализованный recovered corpus<br/>2 документа"]:::component

        PDF --> RAWEXT --> EXNORM
        PDF --> GLYPH --> RAWREC --> RECNORM
    end

    subgraph SELECT["3. ВЫБОР КОРПУСА ДЛЯ SOURCE ANCHOR"]
        QUALITY{"Gate 1 corpus selector<br/>по SOURCE-INDEX.text_quality"}:::component
        EXMAN["sources/extracted/<br/>EXTRACTION-MANIFEST.tsv"]:::component
        RECMAN["sources/recovered-v1/<br/>RECOVERY-MANIFEST.tsv"]:::component

        EXNORM --> EXMAN --> QUALITY
        RECNORM --> RECMAN --> QUALITY
    end

    subgraph INDEX["4. SOURCE INDEX"]
        IDX["index/source-v4<br/>machine source truth"]:::component
        CLOSED["controlled CLOSED<br/>machine-rendered status"]:::closed
        OPEN["OPEN rows<br/>machine-rendered status"]:::component
        QUALITY --> IDX
        IDX --> CLOSED
        IDX --> OPEN
    end

    subgraph CONTROL["5. CONTROL RECORDS / SCHEMA"]
        CTRL["controls/<br/>manifest-driven current population"]:::component
        KIND["KIND_RULES<br/>canonical parameter-kind contract"]:::component
        SCHEMA["CONTROL-SCHEMA.json<br/>generated from KIND_RULES"]:::component
        DIFF["tests/gates-v3/<br/>test_schema_runtime_parity.py<br/>50 records · 16 CR/LF cases<br/>pattern semantics"]:::component
        SEMPAR["schema ↔ runtime<br/>semantic parity regression"]:::component
        REALJSON["Release gate PASS<br/>real Draft202012Validator<br/>jsonschema 4.10.3 recorded in evidence"]:::closed

        KIND --> SCHEMA
        KIND --> DIFF
        SCHEMA --> DIFF --> SEMPAR --> REALJSON
        IDX --> SGEN["source skeleton generator<br/>step 5 CLOSED · numbered-position<br/>manifest-driven population"]:::closed
        SGEN --> SPAR["source-block parity<br/>step 6 CLOSED · manifest-driven population"]:::closed
        SPAR --> CTRL
        KIND --> CTRL
    end

    subgraph GATES["6. MACHINE GATES"]
        G0["Gate 0 PASS<br/>schema_generation_parity<br/>только byte-generation parity"]:::closed
        G1["Gate 1 PASS<br/>source/quote anchor<br/>current manifest population"]:::closed
        G2["Gate 2 FAIL<br/>reverse source coverage<br/>OPEN rows remain"]:::component
        G3["Gate 3 PASS<br/>parameter closure<br/>current manifest population"]:::closed
        G4["Gate 4 PASS<br/>uniqueness/conflicts<br/>current manifest population"]:::closed
        G5["Gate 5 historical admitted pilot<br/>5 sysctl controls · 1 reference VM<br/>current no-probe invocation FAIL-closed"]:::component
        G6["Gate 6 PASS — CURRENT EVIDENCE SCOPE<br/>one sysctl-v1 evidence directory"]:::closed

        CLOSURE["index/source-v4/<br/>CLOSURE-CONTRACT.tsv<br/>exact expected control set<br/>for controlled CLOSED rows"]:::component
        DISP["second closure path:<br/>disposed CLOSED + disposition + reason<br/>DISPOSITION-LEDGER.tsv required · 0 real rows"]:::component

        SCHEMA --> G0
        IDX --> G1
        CTRL --> G1

        IDX --> G2
        CTRL --> G2
        CLOSURE --> G2
        DISP --> G2

        CTRL --> G3
        CTRL --> G4
        CTRL --> G5
    end

    subgraph EVID["7. READ-ONLY REFERENCE-VM EVIDENCE"]
        PLAN["probes/sysctl-v1/probe-plan.tsv"]:::component
        PROBE["probes/sysctl-v1/probe.py<br/>read-only"]:::component
        VM["Ubuntu 24.04.4 Minimal<br/>reference VM"]:::component
        PRIV["privileged result<br/>5 VALUE / 0 ERROR"]:::component
        UNPRIV["unprivileged result<br/>4 VALUE / 1 ERROR"]:::component
        META["VM-METADATA.txt"]:::component
        SUMS["evidence/SHA256SUMS"]:::component

        CTRL --> PLAN --> PROBE --> VM
        VM --> PRIV
        VM --> UNPRIV
        VM --> META

        PRIV --> G5

        META --> G6
        PROBE --> G6
        PLAN --> G6
        PRIV --> G6
        UNPRIV --> G6
        SUMS --> G6
    end

    classDef closed fill:#d9f7df,stroke:#2f7d32,color:#111,stroke-width:2px;
    classDef component fill:#dcecff,stroke:#3e6ea8,color:#111;
    classDef future fill:#eeeeee,stroke:#888,color:#444,stroke-dasharray: 5 5;
```

### Что важно в первой схеме

`recovered-v1` не является продолжением обычного `extracted/norm-v1`.
Восстановление читает PDF отдельным glyph-based путём только для двух
документов, затем отдельно нормализуется в `recovered-v1/norm-v1`.

Gate 1 выбирает нужный корпус по `SOURCE-INDEX.text_quality`:
`recovered-glyph-map-v1` ведёт через `RECOVERY-MANIFEST.tsv`; обычные readable
rows — через `EXTRACTION-MANIFEST.tsv`.

Gate 0 и differential suite — разные доказательства. Gate 0 проверяет
байтовую воспроизводимость schema generation. Семантическое совпадение
runtime/schema проверяет отдельная differential matrix. Roadmap step 4 сделал
реальный `Draft202012Validator` обязательным для release/audit.

Gate 2 имеет два допустимых пути закрытия строки: control coverage с точным
`CLOSURE-CONTRACT.tsv` либо explicit disposition + reason, подтверждённый
ровно одной записью `DISPOSITION-LEDGER.tsv`. Реальных disposed-строк пока 0.

## 2. Слои политики и единый index-конвейер

```mermaid
flowchart TB
    FSTEC["FSTEC core<br/>primary FSTEC sources"]:::component
    RECOMMENDED["recommended<br/>recommended measures"]:::future
    CORPORATE["corporate<br/>internal Standard / additional sources"]:::future
    FIREWALL["firewall<br/>role-specific policy"]:::future

    FSTEC --> CONTRACT["common index contract"]:::component
    RECOMMENDED --> CONTRACT
    CORPORATE --> CONTRACT
    FIREWALL --> CONTRACT

    CONTRACT --> INDEXES["layer-specific indexes<br/>FSTEC: source-v4 exists<br/>corporate: not built yet"]:::component
    INDEXES --> GENERATOR["index-generic<br/>source skeleton generator<br/>step 5 CLOSED"]:::component
    GENERATOR --> SOURCE["source:<br/>generator output<br/>single normative producer"]:::component
    SOURCE --> PARITY["source-block<br/>regeneration parity<br/>step 6 CLOSED"]:::closed
    PARITY --> SEM["requirement / parameter / expected<br/>semantic part of current FSTEC controls"]:::component
    SEM --> CONTROLS["controls/<br/>layer + profile"]:::component
    CONTROLS --> CHECKER["checker / gates<br/>fail-closed"]:::component

    DISP2["explicit dispositions<br/>DISPOSITION-LEDGER.tsv required<br/>alternative closure route"]:::component
    INDEXES --> DISP2
    DISP2 --> CHECKER

    classDef closed fill:#d9f7df,stroke:#2f7d32,color:#111,stroke-width:2px;
    classDef component fill:#dcecff,stroke:#3e6ea8,color:#111;
    classDef future fill:#eeeeee,stroke:#888,color:#444,stroke-dasharray: 5 5;
```

## 3. Текущая read-only product-line CHECK

```mermaid
flowchart LR
    CTRLNOW["canonical controls<br/>manifest-driven fstec-core population"]:::component
    REG["product/ADAPTER-REGISTRY.tsv<br/>single tracked adapter mapping"]:::component
    SYS["product-sysctl-check-v2<br/>read-only eq + integer ge"]:::closed
    FILE["product-file-mode-owner-check-v1<br/>read-only"]:::closed
    GEN1["product/generate-product-check-v1.py<br/>previous generator identity"]:::note
    GEN2["product/generate-product-check-v2.py<br/>current deterministic generator"]:::closed
    CLI["securelinux-policy.sh<br/>tracked unified read-only CLI<br/>NON_RELEASE_PRODUCT_CANDIDATE<br/>pretty · raw · JSON"]:::closed

    CTRLNOW --> REG
    REG --> SYS
    REG --> FILE
    SYS --> GEN2
    FILE --> GEN2
    CTRLNOW --> GEN2 --> CLI
    GEN1 -. historical .-> GEN2

    classDef closed fill:#d9f7df,stroke:#2f7d32,color:#111,stroke-width:2px;
    classDef component fill:#dcecff,stroke:#3e6ea8,color:#111;
    classDef note fill:#fff8d8,stroke:#9d8730,color:#111;
```

Эта product-line отделена от historical Step 7B.0. `ADAPTER-REGISTRY.tsv`
пинует semantic contract, adapter binding и implementation по SHA-256.
Tracked `securelinux-policy.sh` и sidecar входят в root manifests и обязаны
byte-exact совпадать со свежим generator-v2 output. `dist/` остаётся optional
gitignored rebuild output. APPLY mutation capability здесь отсутствует. Принятый
CHECK CLI сохраняет `--apply`/`--restore` как fail-closed `NOT_IMPLEMENTED` stubs;
`--restore` не является future feature.

## 4. Инженерный донор → будущий APPLY runtime

```mermaid
flowchart LR
    OLD["SecureLinux-NG v16.2.11<br/>OLD PROJECT"]:::donor

    ARCHIVE["archive/engineering-donor-*<br/>byte-preserved donor"]:::component
    DONOR_INDEX["index/engineering-donor-v1<br/>310 functions · 190 chunks<br/>141 semantic candidates"]:::component
    DONOR_TESTS["engineering-tests-v1<br/>38 donor tests<br/>32 generalized contracts"]:::component

    MAP["DONOR_TO_V3_MAPPING<br/>REUSE / ADAPT / REJECT / DEFER"]:::future
    APPLY["APPLY<br/>semantic contract"]:::future
    ADAPTERS["future APPLY implementation adapters"]:::future
    BUILD["future final distributable build"]:::future
    SCRIPT["future final<br/>distributable artifact"]:::future

    OLD --> ARCHIVE
    ARCHIVE --> DONOR_INDEX
    ARCHIVE --> DONOR_TESTS
    DONOR_INDEX --> MAP
    DONOR_TESTS --> MAP

    MAP --> APPLY --> ADAPTERS --> BUILD --> SCRIPT

    NORMIN["external input from normative branch:<br/>controls that passed required gates"]:::component
    NORMIN --> ADAPTERS

    PROVOUT["every emitted block provenance:<br/>control_id · locator · quote_sha256<br/>adapter id/version"]:::component
    PROVOUT --> BUILD

    ZERO["DONOR mapping itself<br/>closes 0 source-index rows"]:::note
    MAP -.-> ZERO

    classDef donor fill:#efe3ff,stroke:#7651a8,color:#111,stroke-width:2px;
    classDef component fill:#dcecff,stroke:#3e6ea8,color:#111;
    classDef future fill:#eeeeee,stroke:#888,color:#444,stroke-dasharray: 5 5;
    classDef note fill:#fff8d8,stroke:#9d8730,color:#111;
```

## 5. Provenance, Git checkpoint и воспроизводимость дерева

```mermaid
flowchart LR
    REVIEW["audit/step5-reference-vm-evidence-*/<br/>PROVENANCE.tsv<br/>verdict provenance;<br/>independent count NOT inferred"]:::component
    COMMIT["Git commit checkpoint<br/>content-addressed tree"]:::component
    PKG["external audit package<br/>PROJECT-SNAPSHOT.tsv"]:::component
    BUNDLE["full Git bundle<br/>external handoff artifact"]:::component

    VERIFY["independent verification:<br/>git bundle verify<br/>git fsck --full<br/>git ls-tree vs PROJECT-SNAPSHOT.tsv"]:::component
    ROOTMAN["root manifests<br/>canonical Git-visible population<br/>clean-checkout reproducible"]:::component
    TRUST["verified commit/tree consistency<br/>and package/tree agreement"]:::closed
    LIMIT["boundary:<br/>does NOT cryptographically prove<br/>origin from a particular remote/VM"]:::note

    REVIEW --> TRUST
    COMMIT --> BUNDLE --> VERIFY
    PKG --> VERIFY
    VERIFY --> TRUST
    ROOTMAN --> TRUST
    TRUST -.-> LIMIT

    classDef closed fill:#d9f7df,stroke:#2f7d32,color:#111,stroke-width:2px;
    classDef component fill:#dcecff,stroke:#3e6ea8,color:#111;
    classDef note fill:#fff8d8,stroke:#9d8730,color:#111;
```

Git bundle — внешний артефакт для аудита и handoff, а не утверждение, что
репозиторий хранит каждый созданный bundle. Проверка bundle доказывает
внутреннюю согласованность commit/tree и позволяет независимо сравнить дерево,
но не доказывает, что commit был получен из конкретного remote.

## 6. Где мы находимся

Эта схема показывает **текущий product checkpoint внутри макроэтапа Step 7B**.
Она не повторяет историческую последовательность gates и не изображает уже
реализованные CHECK adapters/generator как будущую работу.

```mermaid
flowchart LR
    P1["CHECK-8 product-line<br/>read-only adapters + tracked generator<br/>DONE"]:::closed
    P2["TEST BASELINE<br/>DEV / RELEASE runner<br/>DONE"]:::closed
    P3["DOCUMENTATION BASELINE<br/>machine-parity docs<br/>DONE"]:::closed
    P4["SRC-0005 / 2.3.1<br/>3 canonical file-mode controls<br/>DONE"]:::closed
    P5["CHECK-11<br/>regenerate + read-only run<br/>DONE"]:::closed
    P6["sysctl exact-eq batch<br/>SRC-0030,0031,0036–0039 + CHECK-17<br/>DONE"]:::closed
    P7["SRC-0040 / 2.6.6<br/>terminal source-boundary fix + CHECK-18<br/>DONE"]:::closed
    P8["SRC-0033 / 2.5.10<br/>sysctl lower-bound ge 4096 + CHECK-19<br/>DONE"]:::closed
    P9["kernel-cmdline exact-token batch<br/>7 source rows · 9 controls + CHECK-28<br/>DONE"]:::closed
    P9A["SRC-0010 / 2.3.6<br/>system cron roots + direct files · 6 controls<br/>DONE"]:::closed
    P9B["UNIFIED CLI / QUICK START v1<br/>securelinux-policy.sh · pretty/raw/json<br/>DONE"]:::closed
    P10["fstec-linux-2022 CHECK COMPLETE<br/>tag fstec-linux-2022-check-complete-v1<br/>DONE"]:::closed
    P10A["МЫ ЗДЕСЬ<br/>DONOR_TO_V3_MAPPING<br/>precondition"]:::current
    P11["APPLY semantic contract<br/>future"]:::future
    P12["APPLY implementation<br/>future"]:::future
    P13["final distributable artifact<br/>future"]:::future
    SNAP["post-APPLY rollback<br/>EXTERNAL SNAPSHOT<br/>outside product"]:::note

    P1 --> P2 --> P3 --> P4 --> P5 --> P6 --> P7 --> P8 --> P9 --> P9A --> P9B --> P10 --> P10A --> P11 --> P12 --> P13
    P12 -. operational recovery boundary .-> SNAP

    classDef closed fill:#d9f7df,stroke:#2f7d32,color:#111,stroke-width:2px;
    classDef current fill:#ffe2a8,stroke:#c77800,color:#111,stroke-width:4px;
    classDef future fill:#eeeeee,stroke:#888,color:#444,stroke-dasharray: 5 5;
    classDef note fill:#fff8d8,stroke:#9d8730,color:#111;
```

`fstec-linux-2022` read-only CHECK vertical принят и закреплён tag
`fstec-linux-2022-check-complete-v1` на commit
`219b4cc3c0673c55575fb558e160431c11c2a681`. Project-wide source index при этом
по-прежнему содержит OPEN rows других документов, но следующий source-scoped
этап — не новый нормативный документ: сначала завершается `DONOR_TO_V3_MAPPING`,
затем отдельные APPLY semantic contract и implementation для уже принятого
`fstec-linux-2022`. Read-only CHECK bytes/controls/adapters при этом не меняются.
Unified read-only CLI не открывает будущий APPLY track; RESTORE исключён из
целевой архитектуры.

Операционная модель rollback после завершённого APPLY — внешний snapshot.
Транзакционно-локальный compensating rollback внутри незавершённого APPLY
остаётся допустимым failure-handling mechanism, но отдельного RESTORE mode нет.

## Что является источником истины

Финальный distributable artifact пока не реализован и его имя не закреплено
как current product contract. В будущем он должен получаться детерминированной
сборкой из проверенных нормативных controls, инженерных semantic contracts,
implementation adapters и tests.

Направление проекта:

`source → text corpus → index → control/disposition → gates → semantic contract → read-only adapter → generator v2 → tracked unified CHECK CLI → future APPLY`

а не:

`old shell script → manual edits → new shell script`.
