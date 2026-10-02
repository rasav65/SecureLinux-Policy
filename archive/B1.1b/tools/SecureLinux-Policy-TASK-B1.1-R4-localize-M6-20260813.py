#!/usr/bin/env python3
"""R4: localize all remaining B1.1b work to M6 task packages.

No normative source, schema, module interface, module lock, integration lock,
fixture, canonical corpus, validator, runtime, tests, source PDF, SVG or PNG is
changed.  The script creates five focused task packages, an exact M6 dependency
slice, a machine-readable active-workstream checkpoint, an audit report, and a
recorded README/CHANGELOG administrative overlay.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any


SCRIPT_NAME = "SecureLinux-Policy-TASK-B1.1-R4-localize-M6-20260813.py"
DATE = "2026-08-13"

BASELINE_SHA256 = "3daac5da494cabb9551b269dcb56df83469ee79491a83c3445bcd33bae0274e3"
OPEN_FINDINGS_SHA256 = "5b9bd4da4cb22aad60e75b79851bc8b58b707b6695cceca47dcc47e1540df53a"
R3_STATE_SHA256 = "ceeeefc90a13cc788171bfb831788581af6dbb1a4d486c0e957a120ab0876c8a"
R3_LOCKED_MODULES_SHA256 = "c0bc429a3895ecec68c57ec04f535e6b77b066a7c8cf4e3b401504042894c59f"
R3_LEDGER_SHA256 = "8069e1bb0f59eda2868644fb2fa343e3c5f448e2dec58620eda02bd3c04a4893"
R3_INTEGRATION_LOCK_SHA256 = "b2c18a968bf552c61d44bc03f5badcce919f21f1e543455deabfb62738ea261f"
R3_REPORT_SHA256 = "5a5b9c508e7eba7744a0b404b7059ea7f68cc0002938888eeb658b5a1e373794"
R3_OUTPUTS_SHA256 = "5d6d661aafa09ca3115c3453b6301ba56e54dc044c12d2d045f6864df612e59f"
R3_INSTALLER_SHA256 = "6658c0171d1421b5afda6351cacf5a2070c1da381545c9fdd2a771f9635a453f"

PROPOSAL_REL = "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-proposal-v9-20260813.md"
PROPOSAL_SHA256 = "bb359806252163cc6cf29f3499ff828891d3ce11104fe9934704c7022f14abfb"
SCHEMA_REL = "docs/SecureLinux-Policy-TASK-B1.1b-selector-meta-contract-schema-v9-20260813.json"
SCHEMA_SHA256 = "2304b192d4f3c8e4fde056a42970ae4b2200df28012019445023c704c6375995"
SELFTEST_REL = "docs/SecureLinux-Policy-TASK-B1.1b-v9-selftest-20260813.py"

STATE_REL = "B1.1b/state/PROJECT-STATE.json"
FINDINGS_REL = "B1.1b/state/OPEN-FINDINGS.json"
R3_INSTALLER_REL = "B1.1b/tools/SecureLinux-Policy-TASK-B1.1-R3-initial-lock-20260813.py"
R3_LOCKED_MODULES_REL = "B1.1b/state/R3-LOCKED-MODULES.json"
R3_LEDGER_REL = "B1.1b/state/R3-LIFECYCLE-TRANSITION-LEDGER.json"
INTEGRATION_LOCK_REL = "B1.1b/integration/INTEGRATION.lock.json"
R3_REPORT_REL = "B1.1b/reports/R3-INITIAL-LOCK-REPORT.json"
R3_OUTPUTS_REL = "B1.1b/reports/R3-OUTPUTS.sha256"
R3_STATE_CHECKPOINT_REL = "B1.1b/state/R3-PROJECT-STATE.json"

R2_DAG_REL = "B1.1b/integration/R2-SYMBOL-DAG.json"
R2_DAG_SHA256 = "ea1b4035a3c7473f7a4974b2aa4071a8369927bd7432d6ebf57eec4596421369"

R4_WORKSTREAM_REL = "B1.1b/state/R4-ACTIVE-WORKSTREAM.json"
R4_DEPENDENCY_SLICE_REL = "B1.1b/integration/R4-M6-DEPENDENCY-SLICE.json"
R4_REPORT_REL = "B1.1b/reports/R4-LOCALIZATION-REPORT.json"
R4_OUTPUTS_REL = "B1.1b/reports/R4-OUTPUTS.sha256"
R4_ADMIN_LEDGER_REL = "B1.1b/state/R4-ADMIN-DOCS-LEDGER.json"
R4_ADMIN_MANIFEST_REL = "B1.1b/state/R4-ADMIN-DOCS.sha256"

MODULE_IDS = (
    "M0-integration-invariants",
    "M1-primitives",
    "M2-outcomes",
    "M3-source-set",
    "M4-filters",
    "M5-pipeline",
    "M6.1-registries",
    "M6.2-operation-algebra",
    "M6.3-enumeration-domains",
    "M6.4-population-matrix",
    "M6.5-behavior-trace",
    "M7-selector-mapping",
)

LOCKED_MODULES = (
    "M0-integration-invariants",
    "M1-primitives",
    "M2-outcomes",
    "M3-source-set",
    "M4-filters",
    "M5-pipeline",
    "M7-selector-mapping",
)

M6_MODULES = (
    "M6.1-registries",
    "M6.2-operation-algebra",
    "M6.3-enumeration-domains",
    "M6.4-population-matrix",
    "M6.5-behavior-trace",
)

# The R2 symbol DAG requires M6.3 before M6.2 because M6.2 imports M6.3.
DEPENDENCY_SAFE_ORDER = (
    "M6.1-registries",
    "M6.3-enumeration-domains",
    "M6.2-operation-algebra",
    "M6.4-population-matrix",
    "M6.5-behavior-trace",
)

FINDING_OWNERS = {
    "V8-01": ("M6.2-operation-algebra",),
    "V8-EXT-01": ("M6.3-enumeration-domains",),
    "V8-EXT-02": ("M6.3-enumeration-domains", "M6.4-population-matrix"),
}

TASK_SPECS = {
    "M6.1-registries": {
        "task_id": "R5-M6.1-REGISTRY-VALUE-REF-LINKAGE",
        "objective": "Закрепить замкнутые registry/value_ref связи до изменения потребителей.",
        "findings": [],
        "acceptance": [
            "Каждая registry entry имеет точную закрытую схему и единственного владельца.",
            "Каждый value_ref однозначно связан с role, target kind, shape, schema, subject и domain.",
            "Все недопустимые сочетания дают CONTRACT_ERROR; implicit defaults отсутствуют.",
        ],
    },
    "M6.2-operation-algebra": {
        "task_id": "R5-M6.2-EXACT-OPERATION-ALGEBRA",
        "objective": "Закрыть V8-01: точная арность и однозначная связь входов с выходами каждой операции.",
        "findings": ["V8-01"],
        "acceptance": [
            "Каждый operation kind имеет отдельную tagged-схему и точную арность.",
            "Каждая операция задаёт единственное проверяемое input-to-output mapping.",
            "Membership-changing операция точно связывает field, value, operator и authorization.",
            "Контрпример с перестановкой входов/выходов отклоняется.",
        ],
    },
    "M6.3-enumeration-domains": {
        "task_id": "R5-M6.3-ENUMERATION-DOMAINS",
        "objective": "Закрыть V8-EXT-01 и свою часть V8-EXT-02: точная population model перечисления.",
        "findings": ["V8-EXT-01", "V8-EXT-02"],
        "acceptance": [
            "Host и adapter enumeration имеют закрытые domain и enumeration operation.",
            "Population source, member identity, ordering и coverage определены однозначно.",
            "input_population_mode и population_completeness имеют точные определения владельца.",
            "Необъявленный обход или источник кандидатов структурно невозможен.",
        ],
    },
    "M6.4-population-matrix": {
        "task_id": "R5-M6.4-POPULATION-MATRIX",
        "objective": "Закрыть V8-EXT-02: тотальная матрица population mode/completeness/outcome.",
        "findings": ["V8-EXT-02"],
        "acceptance": [
            "Матрица input_population_mode × population_completeness × resolution.kind тотальна.",
            "Строки матрицы взаимно исключаются; implicit fallback отсутствует.",
            "Coverage causality и B1.1a outcomes сохраняются без ложного PARTIAL.",
        ],
    },
    "M6.5-behavior-trace": {
        "task_id": "R5-M6.5-BEHAVIOR-TRACE-BOUNDARY",
        "objective": "Закрепить trace и границу B1/B2 после стабилизации M6.2–M6.4.",
        "findings": [],
        "acceptance": [
            "Trace закрыт, детерминирован и lossless относительно объявленных операций и evidence.",
            "B1 описывает данные, операции и инварианты; B2 доказывает соответствие реализации.",
            "Декларации B1 не выдаются за доказательство поведения исполняемого компонента.",
        ],
    },
}


class R4Error(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def canonical_value_sha256(value: object) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def interface_hash(interface: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(interface)
    unsigned.pop("interface_sha256", None)
    return canonical_value_sha256(unsigned)


def require_regular(path: Path, expected_sha256: str | None = None) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise R4Error(f"missing or unsafe regular file: {path}")
    data = path.read_bytes()
    if expected_sha256 is not None and sha256_bytes(data) != expected_sha256:
        raise R4Error(f"SHA-256 mismatch: {path}")
    return data


def atomic_replace(path: Path, data: bytes, suffix: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + suffix)
    if temporary.exists():
        raise R4Error(f"stale temporary file: {temporary}")
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def safe_relative_name(name: str) -> bool:
    pure = PurePosixPath(name)
    return bool(name) and not pure.is_absolute() and all(part not in ("", ".", "..") for part in pure.parts)


def parse_manifest(data: bytes, label: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for number, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if len(line) < 67 or line[64:66] not in ("  ", " *"):
            raise R4Error(f"invalid manifest line: {label}:{number}")
        digest = line[:64].lower()
        name = line[66:]
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise R4Error(f"invalid manifest digest: {label}:{number}")
        if not safe_relative_name(name) or name in seen:
            raise R4Error(f"unsafe or duplicate manifest path: {label}:{number}: {name!r}")
        seen.add(name)
        result.append((digest, name))
    return result


def verify_manifest(root: Path, relative: str, expected_sha256: str) -> int:
    data = require_regular(root / relative, expected_sha256)
    records = parse_manifest(data, relative)
    for digest, name in records:
        if sha256_file(root / name) != digest:
            raise R4Error(f"manifest target mismatch: {relative}: {name}")
    return len(records)


def scan_project(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            relative = path.relative_to(root)
            if relative.parts[0] in (".git", "B1.1b"):
                continue
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise R4Error(f"project link forbidden: {relative.as_posix()}")
            if stat.S_ISDIR(metadata.st_mode):
                visit(path)
            elif stat.S_ISREG(metadata.st_mode):
                result[relative.as_posix()] = {"sha256": sha256_file(path), "size": metadata.st_size}
            else:
                raise R4Error(f"project special entry forbidden: {relative.as_posix()}")

    visit(root)
    return result


def run_checked(command: list[str], root: Path, marker: str, label: str) -> str:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0 or marker not in result.stdout:
        raise R4Error(f"{label} failed:\n" + result.stdout[-6000:])
    return result.stdout


def run_r3_verify(root: Path) -> None:
    installer = root / R3_INSTALLER_REL
    require_regular(installer, R3_INSTALLER_SHA256)
    run_checked(
        [sys.executable, str(installer), str(root), "--verify-only"],
        root,
        "RESULT=R3_INITIAL_LOCK_PASS",
        "R3 verification",
    )


def run_tests(root: Path) -> None:
    run_checked(
        [sys.executable, str(root / SELFTEST_REL), str(root)],
        root,
        "RESULT=B1_1B_V9_SELFTEST_PASS",
        "v9 self-test",
    )
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    match = re.search(r"Ran\s+(\d+)\s+tests?", result.stdout)
    count = int(match.group(1)) if match else None
    if result.returncode != 0 or count != 107 or not re.search(r"^OK$", result.stdout, re.MULTILINE):
        raise R4Error("107-test regression failed:\n" + result.stdout[-6000:])


def verify_r3_artifacts(root: Path, state: dict[str, Any]) -> None:
    pinned = {
        R3_LOCKED_MODULES_REL: R3_LOCKED_MODULES_SHA256,
        R3_LEDGER_REL: R3_LEDGER_SHA256,
        INTEGRATION_LOCK_REL: R3_INTEGRATION_LOCK_SHA256,
        R3_REPORT_REL: R3_REPORT_SHA256,
        R3_OUTPUTS_REL: R3_OUTPUTS_SHA256,
        R2_DAG_REL: R2_DAG_SHA256,
    }
    for relative, digest in pinned.items():
        require_regular(root / relative, digest)
    r3 = state.get("r3", {})
    claims = {
        "locked_modules_sha256": R3_LOCKED_MODULES_SHA256,
        "transition_ledger_sha256": R3_LEDGER_SHA256,
        "integration_lock_sha256": R3_INTEGRATION_LOCK_SHA256,
        "report_sha256": R3_REPORT_SHA256,
        "outputs_manifest_sha256": R3_OUTPUTS_SHA256,
    }
    for key, expected in claims.items():
        if r3.get(key) != expected:
            raise R4Error(f"R3 state claim mismatch: {key}")
    if state.get("gates", {}).get("R3_INITIAL_LOCK_PASS") is not True:
        raise R4Error("R3 gate is not PASS")
    if state.get("project_gate") != {
        "b1_1a": "ACCEPT",
        "b1_1b": "NOT_ACCEPTED",
        "selector_instances_frozen": "0/20",
        "task_b1_1": "NOT_ACCEPTED",
        "task_b1_2": "NOT_STARTED",
    }:
        raise R4Error("project gate changed before R4")


def load_r3_state(root: Path, current_data: bytes) -> tuple[dict[str, Any], bool]:
    current = json.loads(current_data)
    if current.get("current_phase") == "R3_COMPLETE":
        if sha256_bytes(current_data) != R3_STATE_SHA256:
            raise R4Error("R3 PROJECT-STATE is not the pinned checkpoint")
        run_r3_verify(root)
        base_data = current_data
        already_r4 = False
    elif current.get("current_phase") == "R4_COMPLETE":
        base_data = require_regular(root / R3_STATE_CHECKPOINT_REL, R3_STATE_SHA256)
        sidecar = require_regular(root / (R3_STATE_CHECKPOINT_REL + ".sha256"))
        expected = f"{R3_STATE_SHA256}  {PurePosixPath(R3_STATE_CHECKPOINT_REL).name}\n".encode("utf-8")
        if sidecar != expected:
            raise R4Error("R3 checkpoint sidecar mismatch")
        already_r4 = True
    else:
        raise R4Error("R4 requires R3_COMPLETE or verifies R4_COMPLETE")
    base = json.loads(base_data)
    if base.get("current_phase") != "R3_COMPLETE" or base.get("current_next_step") != "R4_LOCALIZE_M6":
        raise R4Error("R3 checkpoint phase changed")
    verify_r3_artifacts(root, base)
    return base, already_r4


def verify_findings(root: Path) -> dict[str, tuple[str, ...]]:
    document = json.loads(require_regular(root / FINDINGS_REL, OPEN_FINDINGS_SHA256))
    actual = {
        str(item["finding_id"]): tuple(item.get("owners", []))
        for item in document.get("findings", [])
    }
    if actual != FINDING_OWNERS:
        raise R4Error(f"open finding ownership mismatch: {actual}")
    return actual


def verify_module_state(root: Path, state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    interfaces: dict[str, dict[str, Any]] = {}
    for module in MODULE_IDS:
        base = root / "B1.1b/modules" / module
        interface_data = require_regular(base / "INTERFACE.json")
        lock_data = require_regular(base / "MODULE-LOCK.json")
        rules_data = require_regular(base / "RULES.json")
        offline_data = require_regular(base / "schema.offline.json")
        interface = json.loads(interface_data)
        lock = json.loads(lock_data)
        state_entry = state["modules"][module]
        expected_status = "OPEN" if module in M6_MODULES else "LOCKED"
        if interface.get("module_id") != module or lock.get("module_id") != module:
            raise R4Error(f"module identity mismatch: {module}")
        if interface.get("interface_sha256") != interface_hash(interface):
            raise R4Error(f"interface self-hash mismatch: {module}")
        if interface.get("status") != expected_status or lock.get("status") != expected_status:
            raise R4Error(f"module lifecycle mismatch: {module}")
        if state_entry.get("status") != expected_status:
            raise R4Error(f"state lifecycle mismatch: {module}")
        if state_entry.get("interface_sha256") != interface.get("interface_sha256"):
            raise R4Error(f"state interface hash mismatch: {module}")
        if state_entry.get("module_lock_sha256") != sha256_bytes(lock_data):
            raise R4Error(f"state module-lock hash mismatch: {module}")
        if state_entry.get("content_sha256") != interface.get("content_sha256"):
            raise R4Error(f"module content hash mismatch: {module}")
        if lock.get("interface_sha256") != interface.get("interface_sha256"):
            raise R4Error(f"module lock interface hash mismatch: {module}")
        if lock.get("rules_sha256") != sha256_bytes(rules_data):
            raise R4Error(f"module rules hash mismatch: {module}")
        if lock.get("offline_schema_sha256") != sha256_bytes(offline_data):
            raise R4Error(f"module offline schema hash mismatch: {module}")
        if state_entry.get("frozen") is not False or state_entry.get("focused_external_accept") is not False:
            raise R4Error(f"premature freeze/accept: {module}")
        interfaces[module] = interface
    return interfaces


def dependency_slice(root: Path) -> dict[str, Any]:
    dag = json.loads(require_regular(root / R2_DAG_REL, R2_DAG_SHA256))
    edges = dag.get("edges", [])
    selected = [
        edge for edge in edges
        if edge.get("consumer") in set(M6_MODULES) | {"M0-integration-invariants"}
        and edge.get("provider") in set(MODULE_IDS)
    ]
    m62_from_m63 = any(
        edge.get("consumer") == "M6.2-operation-algebra"
        and edge.get("provider") == "M6.3-enumeration-domains"
        for edge in selected
    )
    if not m62_from_m63:
        raise R4Error("required M6.2 -> M6.3 dependency is absent")
    order_position = {module: index for index, module in enumerate(DEPENDENCY_SAFE_ORDER)}
    for edge in selected:
        consumer = edge["consumer"]
        provider = edge["provider"]
        if consumer in order_position and provider in order_position:
            if order_position[provider] >= order_position[consumer]:
                raise R4Error(f"dependency-safe work order violation: {consumer} imports {provider}")
    return {
        "schema": "securelinux-policy-r4-m6-dependency-slice/v1",
        "date": DATE,
        "source_dag_sha256": R2_DAG_SHA256,
        "nodes": list(M6_MODULES) + ["M0-integration-invariants"],
        "edges": selected,
        "dependency_safe_work_order": list(DEPENDENCY_SAFE_ORDER),
        "ordering_reason": "M6.2 imports M6.3; providers are processed before consumers",
        "m0_reopen_rule": "Any breaking change to an M6 export imported by M0 sets M0=REOPENED",
    }


def task_markdown(module: str, spec: dict[str, Any]) -> bytes:
    findings = ", ".join(f"`{item}`" for item in spec["findings"]) or "нет прямой находки"
    return (
        f"# {spec['task_id']}\n\n"
        f"Статус: `OPEN`\n\n"
        f"Модуль: `{module}`\n\n"
        f"Цель: {spec['objective']}\n\n"
        f"Находки: {findings}.\n\n"
        "## Границы\n\n"
        "Разрешены изменения только собственного нормативного текста, schema-фрагмента, fixtures и производных файлов модуля. "
        "Изменение export требует автоматической классификации и переоткрытия потребителей при `BREAKING`.\n\n"
        "Запрещены изменения baseline v9, других модулей, canonical corpus, validator, runtime, src, tests, sources, host, "
        "SVG/PNG, gates B1.1/B1.2, commit и push.\n\n"
        "Результат: `RESULT.md`, точечный installer/patch с SHA-256, checker report, test results и обновлённый module lock.\n"
    ).encode("utf-8")


def acceptance_markdown(module: str, spec: dict[str, Any]) -> bytes:
    lines = "".join(f"- {item}\n" for item in spec["acceptance"])
    return (
        f"# Acceptance — {spec['task_id']}\n\n"
        f"Модуль: `{module}`.\n\n"
        f"{lines}"
        "- Все положительные и отрицательные fixtures модуля проходят.\n"
        "- Checker подтверждает schema closure, owners, imports и отсутствие потерь fixtures.\n"
        "- Изменения и удаления exports полностью отражены в transition ledger.\n"
        "- Нормативные файлы других модулей и project gates не изменены.\n"
        "- `LOCKED` или `FROZEN` не выставляется до выполнения соответствующего gate.\n"
    ).encode("utf-8")


def update_readme(source: bytes) -> bytes:
    text = source.decode("utf-8")
    if "Следующий этап — `R5_M6_1_REGISTRY_VALUE_REF_LINKAGE`." in text:
        return source
    old = (
        "Этапы `R0`–`R3` завершены: 7/12 модулей имеют статус `LOCKED`; `M6.1`–`M6.5` "
        "остаются `OPEN`, все модули остаются `NOT_FROZEN`. Следующий этап — `R4_LOCALIZE_M6`."
    )
    new = (
        "Этапы `R0`–`R4` завершены: работа локализована в `M6.1`–`M6.5`, остальные 7 модулей "
        "остаются `LOCKED`, все модули остаются `NOT_FROZEN`. Следующий этап — "
        "`R5_M6_1_REGISTRY_VALUE_REF_LINKAGE`."
    )
    if text.count(old) != 1:
        raise R4Error("README R3 stage paragraph changed")
    text = text.replace(old, new)
    old_line = "5. `R4`–`R6` — локализация, исправление и focused-аудит M6;"
    new_line = (
        "5. `R4` — локализация работы в M6 — `PASS`;\n"
        "6. `R5`–`R6` — исправление и focused-аудит M6;"
    )
    if text.count(old_line) != 1:
        raise R4Error("README R4 workflow line changed")
    text = text.replace(old_line, new_line)
    text = text.replace("6. `R7`–`R8`", "7. `R7`–`R8`")
    text = text.replace("7. `R9`", "8. `R9`")
    text = text.replace("8. `R10`", "9. `R10`")
    return text.encode("utf-8")


def update_changelog(source: bytes) -> bytes:
    text = source.decode("utf-8")
    if "`R4_M6_LOCALIZATION_PASS`" in text:
        return source
    added = "### Added\n\n"
    changed = "### Changed\n\n"
    verified = "### Verified\n\n"
    if text.count(added) != 1 or text.count(changed) != 1 or text.count(verified) != 1:
        raise R4Error("CHANGELOG section structure changed")
    text = text.replace(
        added,
        added + "- R4: focused task packages, exact input locks and dependency slice for M6.1–M6.5.\n",
        1,
    )
    text = text.replace(
        changed,
        changed + "- R4: remaining B1.1b work localized to M6; dependency-safe order places M6.3 before M6.2.\n",
        1,
    )
    text = text.replace(verified, verified + "- `R4_M6_LOCALIZATION_PASS`.\n", 1)
    return text.encode("utf-8")


def build_outputs(
    root: Path,
    base_state: dict[str, Any],
    script_data: bytes,
    readme_before: bytes,
    changelog_before: bytes,
) -> tuple[dict[str, bytes], dict[str, Any], dict[str, bytes]]:
    findings = verify_findings(root)
    interfaces = verify_module_state(root, base_state)
    dep_slice = dependency_slice(root)
    outputs: dict[str, bytes] = {R4_DEPENDENCY_SLICE_REL: canonical_json_bytes(dep_slice)}

    task_locks: dict[str, str] = {}
    for module in M6_MODULES:
        spec = TASK_SPECS[module]
        task_data = task_markdown(module, spec)
        acceptance_data = acceptance_markdown(module, spec)
        module_base = root / "B1.1b/modules" / module
        interface_data = require_regular(module_base / "INTERFACE.json")
        module_lock_data = require_regular(module_base / "MODULE-LOCK.json")
        rules_data = require_regular(module_base / "RULES.json")
        offline_data = require_regular(module_base / "schema.offline.json")
        interface = interfaces[module]
        module_lock = json.loads(module_lock_data)
        imported_modules = sorted({str(item["from_module_id"]) for item in interface.get("imports", [])})
        input_lock: dict[str, Any] = {
            "schema": "securelinux-policy-r4-task-input-lock/v1",
            "date": DATE,
            "task_id": spec["task_id"],
            "module_id": module,
            "module_status": "OPEN",
            "module_content_sha256": interface["content_sha256"],
            "interface_sha256": interface["interface_sha256"],
            "interface_file_sha256": sha256_bytes(interface_data),
            "module_lock_sha256": sha256_bytes(module_lock_data),
            "rules_sha256": sha256_bytes(rules_data),
            "offline_schema_sha256": sha256_bytes(offline_data),
            "task_sha256": sha256_bytes(task_data),
            "acceptance_sha256": sha256_bytes(acceptance_data),
            "imports": interface.get("imports", []),
            "dependency_interfaces": module_lock.get("dependency_interface_sha256", {}),
            "dependency_status": {
                imported: base_state["modules"][imported]["status"] for imported in imported_modules
            },
            "open_findings": list(spec["findings"]),
            "project_gate": copy.deepcopy(base_state["project_gate"]),
            "forbidden_mutations": [
                "baseline-v9", "other-modules", "canonical", "validator", "runtime",
                "src", "tests", "sources", "host", "svg-png", "b1.2", "commit-push",
            ],
        }
        input_lock["input_lock_sha256"] = canonical_value_sha256(input_lock)
        base_rel = f"B1.1b/modules/{module}"
        outputs[f"{base_rel}/TASK.md"] = task_data
        outputs[f"{base_rel}/ACCEPTANCE.md"] = acceptance_data
        outputs[f"{base_rel}/INPUTS.lock.json"] = canonical_json_bytes(input_lock)
        task_locks[module] = sha256_bytes(outputs[f"{base_rel}/INPUTS.lock.json"])

    workstream = {
        "schema": "securelinux-policy-r4-active-workstream/v1",
        "date": DATE,
        "gate": "R4_M6_LOCALIZATION_PASS",
        "baseline_sha256": BASELINE_SHA256,
        "r3_project_state_sha256": R3_STATE_SHA256,
        "scope": list(M6_MODULES),
        "dependency_safe_work_order": list(DEPENDENCY_SAFE_ORDER),
        "current_task": "R5-M6.1-REGISTRY-VALUE-REF-LINKAGE",
        "task_input_locks": task_locks,
        "open_findings": {key: list(value) for key, value in sorted(findings.items())},
        "locked_modules": list(LOCKED_MODULES),
        "m0": {
            "status": "LOCKED",
            "reopen_trigger": "BREAKING change to an imported M6 export",
        },
        "gates_unchanged": {
            "b1_1b": "NOT_ACCEPTED",
            "task_b1_1": "NOT_ACCEPTED",
            "task_b1_2": "NOT_STARTED",
            "selector_instances_frozen": "0/20",
            "modules_frozen": "0/12",
        },
    }
    outputs[R4_WORKSTREAM_REL] = canonical_json_bytes(workstream)

    script_digest = sha256_bytes(script_data)
    tool_rel = f"B1.1b/tools/{SCRIPT_NAME}"
    outputs[tool_rel] = script_data
    outputs[tool_rel + ".sha256"] = f"{script_digest}  {SCRIPT_NAME}\n".encode("utf-8")
    base_state_data = canonical_json_bytes(base_state)
    if sha256_bytes(base_state_data) != R3_STATE_SHA256:
        raise R4Error("R3 checkpoint serialization mismatch")
    outputs[R3_STATE_CHECKPOINT_REL] = base_state_data
    outputs[R3_STATE_CHECKPOINT_REL + ".sha256"] = (
        f"{R3_STATE_SHA256}  {PurePosixPath(R3_STATE_CHECKPOINT_REL).name}\n"
    ).encode("utf-8")

    readme_after = update_readme(readme_before)
    changelog_after = update_changelog(changelog_before)
    admin = {
        "schema": "securelinux-policy-r4-admin-docs-ledger/v1",
        "date": DATE,
        "classification": "ADMINISTRATIVE_NON_NORMATIVE",
        "allowed_paths": ["README.md", "CHANGELOG.md"],
        "changes": {
            "README.md": {
                "before_sha256": sha256_bytes(readme_before) if readme_before != readme_after else None,
                "after_sha256": sha256_bytes(readme_after),
            },
            "CHANGELOG.md": {
                "before_sha256": sha256_bytes(changelog_before) if changelog_before != changelog_after else None,
                "after_sha256": sha256_bytes(changelog_after),
            },
        },
        "mutation_assertion": {
            "normative": False, "module_interfaces": False, "module_locks": False,
            "integration_lock": False, "canonical": False, "validator": False,
            "runtime": False, "src": False, "tests": False, "sources": False,
            "svg_png": False, "host": False,
        },
    }
    existing = root / R4_ADMIN_LEDGER_REL
    if readme_before == readme_after and changelog_before == changelog_after and existing.is_file():
        previous = json.loads(require_regular(existing))
        for name in ("README.md", "CHANGELOG.md"):
            admin["changes"][name]["before_sha256"] = previous["changes"][name]["before_sha256"]
    outputs[R4_ADMIN_LEDGER_REL] = canonical_json_bytes(admin)
    outputs[R4_ADMIN_MANIFEST_REL] = (
        f"{sha256_bytes(readme_after)}  README.md\n"
        f"{sha256_bytes(changelog_after)}  CHANGELOG.md\n"
        f"{sha256_bytes(outputs[R4_ADMIN_LEDGER_REL])}  {R4_ADMIN_LEDGER_REL}\n"
    ).encode("utf-8")

    report = {
        "schema": "securelinux-policy-r4-localization-report/v1",
        "date": DATE,
        "result": "R4_M6_LOCALIZATION_PASS",
        "active_modules": "M6.1-M6.5",
        "focused_task_packages": "5/5",
        "task_input_locks": "5/5",
        "dependency_safe_work_order": list(DEPENDENCY_SAFE_ORDER),
        "locked_modules_unchanged": "7/7",
        "open_modules_unchanged": "5/5",
        "modules_frozen": "0/12",
        "open_findings": "3/3",
        "normative_changes": 0,
        "interface_changes": 0,
        "module_lock_changes": 0,
        "integration_lock_changes": 0,
        "v9_selftest": "PASS",
        "regression_tests": "107/107_PASS",
        "next_phase": "R5_M6_1_REGISTRY_VALUE_REF_LINKAGE",
    }
    outputs[R4_REPORT_REL] = canonical_json_bytes(report)
    manifest_names = sorted(outputs)
    outputs[R4_OUTPUTS_REL] = "".join(
        f"{sha256_bytes(outputs[name])}  {name}\n" for name in manifest_names
    ).encode("utf-8")

    new_state = copy.deepcopy(base_state)
    new_state["current_phase"] = "R4_COMPLETE"
    new_state["current_next_step"] = "R5_M6_1_REGISTRY_VALUE_REF_LINKAGE"
    new_state["gates"]["R4_M6_LOCALIZATION_PASS"] = True
    new_state["r4"] = {
        "active_workstream_sha256": sha256_bytes(outputs[R4_WORKSTREAM_REL]),
        "dependency_slice_sha256": sha256_bytes(outputs[R4_DEPENDENCY_SLICE_REL]),
        "report_sha256": sha256_bytes(outputs[R4_REPORT_REL]),
        "outputs_manifest_sha256": sha256_bytes(outputs[R4_OUTPUTS_REL]),
        "admin_docs_ledger_sha256": sha256_bytes(outputs[R4_ADMIN_LEDGER_REL]),
        "focused_task_packages": "5/5",
        "task_input_locks": task_locks,
        "normative_change": False,
        "module_status_change": False,
    }
    return outputs, new_state, {"README.md": readme_after, "CHANGELOG.md": changelog_after}


def apply_outputs(root: Path, outputs: dict[str, bytes], docs: dict[str, bytes], state_data: bytes) -> None:
    writes = {**outputs, **docs}
    previous: dict[str, bytes | None] = {}
    applied: list[str] = []
    try:
        for relative in sorted(writes):
            path = root / relative
            old = path.read_bytes() if path.is_file() and not path.is_symlink() else None
            if path.exists() and old is None:
                raise R4Error(f"unsafe output target: {relative}")
            previous[relative] = old
            if old != writes[relative]:
                atomic_replace(path, writes[relative], ".tmp-r4")
                applied.append(relative)
        previous[STATE_REL] = require_regular(root / STATE_REL)
        if previous[STATE_REL] != state_data:
            atomic_replace(root / STATE_REL, state_data, ".tmp-r4")
            applied.append(STATE_REL)
    except Exception:
        for relative in reversed(applied):
            path = root / relative
            old = previous[relative]
            if old is None:
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            else:
                atomic_replace(path, old, ".tmp-r4-rollback")
        raise


def verify_outputs(root: Path, outputs: dict[str, bytes], docs: dict[str, bytes], state_data: bytes) -> None:
    for relative, data in {**outputs, **docs}.items():
        if require_regular(root / relative) != data:
            raise R4Error(f"R4 output mismatch: {relative}")
    if require_regular(root / STATE_REL) != state_data:
        raise R4Error("R4 PROJECT-STATE mismatch")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project_root", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    root = arguments.project_root.resolve()
    if not root.is_dir() or not (root / "B1.1b").is_dir():
        raise R4Error(f"R3 project root missing: {root}")

    require_regular(root / "B1.1b/baseline/v9/BASELINE.json", BASELINE_SHA256)
    require_regular(root / FINDINGS_REL, OPEN_FINDINGS_SHA256)
    require_regular(root / PROPOSAL_REL, PROPOSAL_SHA256)
    require_regular(root / SCHEMA_REL, SCHEMA_SHA256)
    current_data = require_regular(root / STATE_REL)
    base_state, already_r4 = load_r3_state(root, current_data)
    if arguments.verify_only and not already_r4:
        raise R4Error("--verify-only requires R4_COMPLETE")
    verify_manifest(root, R3_OUTPUTS_REL, R3_OUTPUTS_SHA256)

    script_data = require_regular(Path(__file__).resolve())
    readme_before = require_regular(root / "README.md")
    changelog_before = require_regular(root / "CHANGELOG.md")
    outputs, new_state, docs = build_outputs(root, base_state, script_data, readme_before, changelog_before)
    outputs2, new_state2, docs2 = build_outputs(root, base_state, script_data, readme_before, changelog_before)
    if outputs != outputs2 or new_state != new_state2 or docs != docs2:
        raise R4Error("R4 generation is not deterministic")
    state_after = canonical_json_bytes(new_state)

    snapshot_before = scan_project(root)
    run_tests(root)
    if scan_project(root) != snapshot_before:
        raise R4Error("tests changed the project snapshot")
    if already_r4:
        verify_outputs(root, outputs, docs, state_after)
    else:
        apply_outputs(root, outputs, docs, state_after)
    snapshot_after = scan_project(root)
    if already_r4:
        if snapshot_after != snapshot_before:
            raise R4Error("R4 verification changed the project snapshot")
    else:
        changed = {name for name in set(snapshot_before) | set(snapshot_after) if snapshot_before.get(name) != snapshot_after.get(name)}
        if changed != {"README.md", "CHANGELOG.md"}:
            raise R4Error(f"R4 changed paths outside administrative overlay: {sorted(changed)}")
    verify_outputs(root, outputs, docs, state_after)
    if sha256_file(root / INTEGRATION_LOCK_REL) != R3_INTEGRATION_LOCK_SHA256:
        raise R4Error("R4 changed integration lock")
    if sha256_file(root / PROPOSAL_REL) != PROPOSAL_SHA256 or sha256_file(root / SCHEMA_REL) != SCHEMA_SHA256:
        raise R4Error("R4 changed v9 normative source")

    print("RESULT=R4_M6_LOCALIZATION_PASS")
    print("ACTIVE_MODULES=M6.1,M6.2,M6.3,M6.4,M6.5")
    print("DEPENDENCY_SAFE_ORDER=M6.1,M6.3,M6.2,M6.4,M6.5")
    print("FOCUSED_TASK_PACKAGES=5/5")
    print("TASK_INPUT_LOCKS=5/5")
    print("MODULES_LOCKED=7/12_UNCHANGED")
    print("MODULES_OPEN=5/12_UNCHANGED")
    print("MODULES_FROZEN=0/12")
    print("OPEN_FINDINGS=3/3")
    print("NORMATIVE_CHANGES=0")
    print("INTERFACE_CHANGES=0")
    print("MODULE_LOCK_CHANGES=0")
    print("INTEGRATION_LOCK_CHANGES=0")
    print("V9_SELFTEST=PASS")
    print("FULL_REGRESSION_TESTS=107/107_PASS")
    print("README_MD=UPDATED_R4_STATE")
    print("CHANGELOG_MD=UPDATED_R4_STATE")
    print("SVG_PNG=UNCHANGED")
    print("TASK_B1_1_ACCEPTED=false")
    print("TASK_B1_2=NOT_STARTED")
    print("SELECTOR_INSTANCES_FROZEN=0/20")
    print(f"SHA256={sha256_bytes(outputs[R4_WORKSTREAM_REL])}  {R4_WORKSTREAM_REL}")
    print(f"SHA256={sha256_bytes(outputs[R4_DEPENDENCY_SLICE_REL])}  {R4_DEPENDENCY_SLICE_REL}")
    print(f"SHA256={sha256_bytes(outputs[R4_REPORT_REL])}  {R4_REPORT_REL}")
    print(f"SHA256={sha256_bytes(outputs[R4_OUTPUTS_REL])}  {R4_OUTPUTS_REL}")
    print(f"SHA256={sha256_bytes(state_after)}  {STATE_REL}")
    print("CURRENT_NEXT_STEP=R5_M6_1_REGISTRY_VALUE_REF_LINKAGE")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (R4Error, OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"R4_FAIL={exc}", file=sys.stderr)
        raise SystemExit(1)
