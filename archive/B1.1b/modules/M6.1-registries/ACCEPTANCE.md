# Acceptance — R5-M6.1-REGISTRY-VALUE-REF-LINKAGE

Модуль: `M6.1-registries`.

- Каждая registry entry имеет закрытую схему и ровно одного scalar instance owner.
- Каждый registry key (`value_ref`, `resolver_ref`, `adapter_ref`, `field_ref`, `reference_ref`, `population_contract_ref`, `root_ref`, `event_source_ref`) уникален в snapshot; duplicate → `CONTRACT_ERROR`.
- `ReferenceUse` повторяет `reference_role` и все reference/population metadata; role mismatch → `CONTRACT_ERROR`.
- `compliance-policy` структурно не представим selector reference contract.
- `adapter-enumeration` представим только `AdapterRegistryEntry`, не `ResolverRegistryEntry`.
- Матрица `input_role × target.kind × owner` структурно закрыта: 9 legal, 45 illegal combinations rejected.
- `enumeration_source_slot_ref`, slot/domain/operator, Binding↔Slot и Binding↔Value linkage заданы точно.
- Все использования `Id` импортируются из M1; inline-копий Id pattern нет.
- Экспорты, imports, MODULE, schema, offline refs, RULES и fixtures согласованы; мёртвые exports отсутствуют.
- Все positive/negative fixtures и focused checker проходят.
- MODULE.md, schema.json и registry invariants напрямую pinned в module lock.
- Изменения/удаления exports полностью отражены в transition ledger; BREAKING consumer M0 → `REOPENED`.
- Нормативные файлы M0/M1 и project gates B1.1/B1.2 не изменены.
- M6.1 может стать только internal `LOCKED`; `FROZEN=false`, external ACCEPT=false.
