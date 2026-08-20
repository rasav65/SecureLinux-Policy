# SecureLinux-Policy v3 — карта проекта и взаимодействий

> **Это основная архитектурная карта текущего SecureLinux-Policy v3.**
>
> Карта показывает действующие источники истины, текстовые корпуса, source
> index, controls, механические gates, reference-VM evidence, audit provenance,
> policy layers, engineering donor и путь к конечному `securelinux-ng.sh`.
>
> Старый SecureLinux-NG присутствует только как **engineering donor**. Его
> runtime-архитектура не является нормативной архитектурой v3 и сама по себе
> не закрывает source-index rows.

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
        IDX["index/source-v4<br/>349 rows"]:::component
        CLOSED["8 controlled CLOSED"]:::closed
        OPEN["341 OPEN"]:::component
        QUALITY --> IDX
        IDX --> CLOSED
        IDX --> OPEN
    end

    subgraph CONTROL["5. CONTROL RECORDS / SCHEMA"]
        CTRL["controls/<br/>8 current controls"]:::component
        KIND["KIND_RULES<br/>canonical parameter-kind contract"]:::component
        SCHEMA["CONTROL-SCHEMA.json<br/>generated from KIND_RULES"]:::component
        DIFF["tests/gates-v3/<br/>test_schema_runtime_parity.py<br/>50 records · 16 CR/LF cases<br/>pattern semantics"]:::component
        SEMPAR["schema ↔ runtime<br/>semantic parity regression"]:::component
        REALJSON["Release gate PASS<br/>real Draft202012Validator<br/>jsonschema 4.10.3 recorded in evidence"]:::closed

        KIND --> SCHEMA
        KIND --> DIFF
        SCHEMA --> DIFF --> SEMPAR --> REALJSON
        IDX --> SGEN["source skeleton generator<br/>step 5 CLOSED · numbered-position<br/>current controls 8/8"]:::closed
        SGEN --> SPAR["source-block parity<br/>step 6 CLOSED · current controls 8/8"]:::closed
        SPAR --> CTRL
        KIND --> CTRL
    end

    subgraph GATES["6. MACHINE GATES"]
        G0["Gate 0 PASS<br/>schema_generation_parity<br/>только byte-generation parity"]:::closed
        G1["Gate 1 PASS<br/>source/quote anchor<br/>current 8 controls"]:::closed
        G2["Gate 2 FAIL<br/>reverse source coverage<br/>341 uncovered"]:::component
        G3["Gate 3 PASS<br/>parameter closure<br/>current 8 controls"]:::closed
        G4["Gate 4 PASS<br/>uniqueness/conflicts<br/>current 8 controls"]:::closed
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
    PARITY --> SEM["requirement / parameter / expected<br/>semantic part of control"]:::future
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
    CTRLNOW["8 canonical controls<br/>fstec-core"]:::component
    REG["product/ADAPTER-REGISTRY.tsv<br/>single tracked adapter mapping"]:::component
    SYS["product-sysctl-check-v1<br/>read-only"]:::closed
    FILE["product-file-mode-owner-check-v1<br/>read-only"]:::closed
    GEN["product/generate-product-check-v1.py<br/>tracked deterministic generator"]:::closed
    CHECK["generated CHECK-8<br/>NON_RELEASE_PRODUCT_CANDIDATE"]:::closed

    CTRLNOW --> REG
    REG --> SYS
    REG --> FILE
    SYS --> GEN
    FILE --> GEN
    CTRLNOW --> GEN --> CHECK

    classDef closed fill:#d9f7df,stroke:#2f7d32,color:#111,stroke-width:2px;
    classDef component fill:#dcecff,stroke:#3e6ea8,color:#111;
```

Эта product-line отделена от historical Step 7B.0. `ADAPTER-REGISTRY.tsv`
пинует semantic contract, adapter binding и implementation по SHA-256.
Generated `dist/` является derived output и не входит в root manifests.
APPLY/RESTORE здесь отсутствуют.

## 4. Инженерный донор → будущий APPLY/RESTORE runtime

```mermaid
flowchart LR
    OLD["SecureLinux-NG v16.2.11<br/>OLD PROJECT"]:::donor

    ARCHIVE["archive/engineering-donor-*<br/>byte-preserved donor"]:::component
    DONOR_INDEX["index/engineering-donor-v1<br/>310 functions · 190 chunks<br/>141 semantic candidates"]:::component
    DONOR_TESTS["engineering-tests-v1<br/>38 donor tests<br/>32 generalized contracts"]:::component

    MAP["DONOR_TO_V3_MAPPING<br/>REUSE / ADAPT / REJECT / DEFER"]:::future
    APPLY["apply/restore<br/>semantic contract"]:::future
    ADAPTERS["future APPLY implementation adapters"]:::future
    BUILD["future final distributable build"]:::future
    SCRIPT["securelinux-ng.sh<br/>single distributable artifact"]:::future

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

```mermaid
flowchart LR
    S1["Step 5<br/>audit provenance closure"]:::closed
    S2["Gate 6<br/>evidence_binding"]:::closed
    S3["type/boolean<br/>contract cleanup"]:::closed
    S4["mandatory real-jsonschema<br/>release gate"]:::closed
    S5["index-generic<br/>source skeleton generator"]:::closed
    S6["source-block<br/>regeneration parity"]:::closed
    S7["МЫ ЗДЕСЬ<br/>Step 7B<br/>FSTEC expansion<br/>real dispositions blocked"]:::current
    S8["apply/restore<br/>semantic contract"]:::future
    S9["implementation<br/>adapters"]:::future
    S10["deterministic<br/>build"]:::future
    S11["single distributable<br/>securelinux-ng.sh"]:::future

    S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9 --> S10 --> S11

    classDef closed fill:#d9f7df,stroke:#2f7d32,color:#111,stroke-width:2px;
    classDef current fill:#ffe2a8,stroke:#c77800,color:#111,stroke-width:4px;
    classDef future fill:#eeeeee,stroke:#888,color:#444,stroke-dasharray: 5 5;
```

Текущий orange node обозначает macro-roadmap Step 7B, а не утверждает, что
внутри него не существует завершённых product checkpoints. На текущем HEAD
read-only product-line Steps 1–3 и CHECK-8 уже реализованы; APPLY/RESTORE
по-прежнему не открыты.

## Что является источником истины

Финальный `securelinux-ng.sh` не редактируется вручную. Он должен получаться
детерминированной сборкой из проверенных нормативных controls, инженерных
semantic contracts, implementation adapters и tests.

Направление проекта:

`source → text corpus → index → control/disposition → gates → semantic contract → adapter → deterministic build → script`

а не:

`old shell script → manual edits → new shell script`.
