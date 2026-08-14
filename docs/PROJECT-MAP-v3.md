# SecureLinux-Policy v3 — карта проекта и взаимодействий

> **Это основная архитектурная карта текущего SecureLinux-Policy v3.**
>
> Она показывает действующие источники истины, индексы, controls, Gates,
> reference-VM evidence, policy layers, engineering donor и путь к конечному
> `securelinux-ng.sh`.
>
> Старый SecureLinux-NG здесь присутствует только как **engineering donor**.
> Его runtime-архитектура не является архитектурой v3 и не закрывает
> нормативные строки автоматически.

## Легенда

- зелёный — закрытый этап/гейт;
- **оранжевый — единственное текущее место работы**;
- серый — будущий этап;
- синий — действующий структурный компонент;
- фиолетовый — engineering donor.

## 1. Как устроен проект v3 сейчас

```mermaid
flowchart LR
    subgraph SRC["1. ПЕРВИЧНЫЕ ИСТОЧНИКИ"]
        PDF["sources/fstec/<br/>10 закреплённых PDF"]:::component
        HASH["sources/fstec/SHA256SUMS"]:::component
        PDF --> HASH
    end

    subgraph TEXT["2. ДЕТЕРМИНИРОВАННЫЙ ТЕКСТ"]
        NORM["norm-v1<br/>детерминированная нормализация"]:::component
        REC["recovered-v1<br/>восстановление проблемного текста<br/>без OCR"]:::component
        PDF --> NORM --> REC
    end

    subgraph INDEX["3. SOURCE INDEX"]
        IDX["index/source-v4<br/>349 строк"]:::component
        CLOSED["5 controlled CLOSED"]:::closed
        OPEN["344 OPEN"]:::component
        REC --> IDX
        IDX --> CLOSED
        IDX --> OPEN
    end

    subgraph CONTROL["4. CONTROL RECORDS"]
        CTRL["controls/<br/>5 pilot controls"]:::component
        KIND["KIND_RULES<br/>единый kind-контракт"]:::component
        SCHEMA["CONTROL-SCHEMA.json<br/>генерируется из KIND_RULES"]:::component
        KIND --> SCHEMA
        KIND --> CTRL
        IDX --> CTRL
    end

    subgraph GATES["5. MACHINE GATES"]
        G0["Gate 0<br/>schema_generation_parity"]:::closed
        G1["Gate 1<br/>source/quote anchor"]:::closed
        G2["Gate 2<br/>reverse source coverage<br/>344 OPEN"]:::component
        G3["Gate 3<br/>parameter closure"]:::closed
        G4["Gate 4<br/>uniqueness/conflicts"]:::closed
        G5["Gate 5<br/>probe executability"]:::closed
        G6["Gate 6<br/>evidence_binding"]:::closed

        SCHEMA --> G0
        IDX --> G1
        CTRL --> G1
        IDX --> G2
        CTRL --> G2
        CTRL --> G3
        CTRL --> G4
        CTRL --> G5
    end

    subgraph EVID["6. READ-ONLY REFERENCE-VM EVIDENCE"]
        PLAN["probe-plan.tsv"]:::component
        PROBE["probe.py<br/>read-only"]:::component
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

    G2 -. "закрывается только<br/>controls/dispositions" .-> OPEN

    classDef closed fill:#d9f7df,stroke:#2f7d32,color:#111,stroke-width:2px;
    classDef component fill:#dcecff,stroke:#3e6ea8,color:#111;
```

## 2. Слои политики и единый конвейер

```mermaid
flowchart TB
    FSTEC["FSTEC core<br/>первичные источники ФСТЭК"]:::component
    RECOMMENDED["recommended<br/>рекомендованные меры"]:::future
    CORPORATE["corporate<br/>внутренний Стандарт / доп. источники"]:::future
    FIREWALL["firewall<br/>role-specific policy"]:::future

    FSTEC --> CONTRACT["единый index contract"]:::component
    RECOMMENDED --> CONTRACT
    CORPORATE --> CONTRACT
    FIREWALL --> CONTRACT

    CONTRACT --> INDEXES["layer-specific indexes<br/>FSTEC: source-v4 уже существует<br/>corporate: ещё предстоит"]:::component
    INDEXES --> GENERATOR["index-generic<br/>source skeleton generator"]:::future
    GENERATOR --> SOURCE["source:<br/>генерируется автоматически<br/>единственный writer"]:::future
    SOURCE --> PARITY["source-block<br/>regeneration parity"]:::future
    PARITY --> SEM["requirement / parameter / expected<br/>осмысленная часть control"]:::future
    SEM --> CONTROLS["controls/<br/>layer + profile"]:::component
    CONTROLS --> CHECKER["checker / Gates<br/>fail-closed"]:::component

    classDef component fill:#dcecff,stroke:#3e6ea8,color:#111;
    classDef future fill:#eeeeee,stroke:#888,color:#444,stroke-dasharray: 5 5;
```

## 3. Engineering donor и путь к runtime

```mermaid
flowchart LR
    OLD["SecureLinux-NG v16.2.11<br/>СТАРЫЙ ПРОЕКТ"]:::donor

    ARCHIVE["archive/engineering-donor-*<br/>byte-preserved"]:::component
    DONOR_INDEX["index/engineering-donor-v1<br/>310 functions · 190 chunks<br/>141 semantic candidates"]:::component
    DONOR_TESTS["engineering-tests-v1<br/>38 donor tests<br/>32 generalized contracts"]:::component

    MAP["DONOR_TO_V3_MAPPING<br/>REUSE / ADAPT / REJECT / DEFER"]:::future
    APPLY["apply/restore<br/>semantic contract"]:::future
    ADAPTERS["implementation adapters"]:::future
    BUILD["deterministic build"]:::future
    SCRIPT["securelinux-ng.sh<br/>единый distributable artifact"]:::future

    OLD --> ARCHIVE
    ARCHIVE --> DONOR_INDEX
    ARCHIVE --> DONOR_TESTS
    DONOR_INDEX --> MAP
    DONOR_TESTS --> MAP

    MAP --> APPLY --> ADAPTERS --> BUILD --> SCRIPT

    VERIFIED["проверенные controls"]:::component --> ADAPTERS
    PROV["provenance каждого блока:<br/>control_id · locator · quote_sha256<br/>adapter id/version"]:::component --> BUILD

    ZERO["DONOR mapping<br/>сам по себе закрывает<br/>0 source-index rows"]:::note
    MAP -.-> ZERO

    classDef donor fill:#efe3ff,stroke:#7651a8,color:#111,stroke-width:2px;
    classDef component fill:#dcecff,stroke:#3e6ea8,color:#111;
    classDef future fill:#eeeeee,stroke:#888,color:#444,stroke-dasharray: 5 5;
    classDef note fill:#fff8d8,stroke:#9d8730,color:#111;
```

## 4. Где мы находимся

```mermaid
flowchart LR
    S1["Step 5<br/>audit provenance closure"]:::closed
    S2["Gate 6<br/>evidence_binding"]:::closed
    S3["МЫ ЗДЕСЬ<br/>type/boolean<br/>contract cleanup"]:::current
    S4["mandatory real-jsonschema<br/>release gate"]:::future
    S5["index-generic<br/>source skeleton generator"]:::future
    S6["source-block<br/>regeneration parity"]:::future
    S7["FSTEC + corporate<br/>index expansion / dispositions"]:::future
    S8["apply/restore<br/>semantic contract"]:::future
    S9["implementation<br/>adapters"]:::future
    S10["deterministic<br/>build"]:::future
    S11["single distributable<br/>securelinux-ng.sh"]:::future

    S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9 --> S10 --> S11

    classDef closed fill:#d9f7df,stroke:#2f7d32,color:#111,stroke-width:2px;
    classDef current fill:#ffe2a8,stroke:#c77800,color:#111,stroke-width:4px;
    classDef future fill:#eeeeee,stroke:#888,color:#444,stroke-dasharray: 5 5;
```

## Что является источником истины

Финальный `securelinux-ng.sh` не редактируется вручную. Он должен получаться
детерминированной сборкой из проверенных нормативных controls, инженерных
semantic contracts, implementation adapters и tests.

То есть направление проекта:

`источник → index → control → gates → semantic contract → adapter → build → script`

а не:

`старый shell-скрипт → правки вручную → новый shell-скрипт`.
