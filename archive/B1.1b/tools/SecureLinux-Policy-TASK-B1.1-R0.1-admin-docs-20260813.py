#!/usr/bin/env python3
"""R0.1: synchronize root project documentation without changing R0.

The immutable R0/v9 baseline remains byte-for-byte unchanged.  This command
updates only README.md, creates CHANGELOG.md, records an administrative overlay
ledger under B1.1b/state/, and advances PROJECT-STATE to R0_1_COMPLETE.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


SCRIPT_NAME = "SecureLinux-Policy-TASK-B1.1-R0.1-admin-docs-20260813.py"
DATE = "2026-08-13"

BASELINE_SHA256 = "3daac5da494cabb9551b269dcb56df83469ee79491a83c3445bcd33bae0274e3"
OPEN_FINDINGS_SHA256 = "5b9bd4da4cb22aad60e75b79851bc8b58b707b6695cceca47dcc47e1540df53a"
R0_PROJECT_STATE_SHA256 = "b8e603e46df9fafd7737a8358f9fdb2fd14ccdc6a4e219bf2aacf0ba9e0439c7"
R0_TOOL_SHA256 = "5374feee2c083ce70553d23c320d8a73478b64ba59872d27ca48e08cc2aff0a8"
ORIGINAL_README_SHA256 = "a44c65e645fde504691f015d0d6aee07752e115defe250d25b686b047e4cf6c1"
ORIGINAL_README_SIZE = 6365

SELFTEST_REL = "docs/SecureLinux-Policy-TASK-B1.1b-v9-selftest-20260813.py"

LEDGER_REL = "B1.1b/state/R0.1-ADMIN-DOCS-LEDGER.json"
MANIFEST_REL = "B1.1b/state/R0.1-ADMIN-DOCS.sha256"
STATE_REL = "B1.1b/state/PROJECT-STATE.json"


class R01Error(RuntimeError):
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


def require_regular(path: Path, expected_sha256: str | None = None) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise R01Error(f"missing or unsafe regular file: {path}")
    data = path.read_bytes()
    if expected_sha256 is not None and sha256_bytes(data) != expected_sha256:
        raise R01Error(f"SHA-256 mismatch: {path}")
    return data


def atomic_replace(path: Path, data: bytes, suffix: str) -> None:
    temporary = path.with_name(path.name + suffix)
    if temporary.exists():
        raise R01Error(f"stale temporary file: {temporary}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def immutable_write(path: Path, data: bytes) -> None:
    if path.exists():
        if not path.is_file() or path.is_symlink() or path.read_bytes() != data:
            raise R01Error(f"existing R0.1 artifact differs: {path}")
        return
    atomic_replace(path, data, ".tmp-r0.1")


def baseline_inventory(baseline: dict[str, object]) -> dict[str, dict[str, object]]:
    records = baseline.get("project_snapshot", {}).get("files")
    if not isinstance(records, list):
        raise R01Error("baseline project inventory missing")
    result: dict[str, dict[str, object]] = {}
    for item in records:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise R01Error("invalid baseline inventory record")
        result[str(item["path"])] = {"sha256": item["sha256"], "size": item["size"]}
    return result


def scan_snapshot(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            relative = path.relative_to(root)
            if relative.parts[0] in (".git", "B1.1b"):
                continue
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise R01Error(f"project link forbidden: {relative.as_posix()}")
            if stat.S_ISDIR(metadata.st_mode):
                visit(path)
            elif stat.S_ISREG(metadata.st_mode):
                result[relative.as_posix()] = {
                    "sha256": sha256_file(path),
                    "size": metadata.st_size,
                }
            else:
                raise R01Error(f"project special entry forbidden: {relative.as_posix()}")

    visit(root)
    return result


def snapshot_diff(expected: dict[str, object], actual: dict[str, object]) -> str:
    missing = sorted(set(expected) - set(actual))[:5]
    extra = sorted(set(actual) - set(expected))[:5]
    changed = sorted(name for name in set(expected) & set(actual) if expected[name] != actual[name])[:5]
    return f"missing={missing}, extra={extra}, changed={changed}"


CURRENT_SECTION = """## Текущий этап

Текущая рабочая линия — модульное закрытие `TASK-B1.1` перед началом `B1.2`.

- `B1.1a v2.1 = ACCEPT`;
- `B1.1b v9 = IMMUTABLE_CANDIDATE_NOT_ACCEPTED`;
- `TASK-B1.1 = NOT_ACCEPTED`;
- `B1.2 = NOT_STARTED`;
- `SELECTOR_INSTANCES_FROZEN = 0/20`.

Этап `R0` завершён: baseline v9, открытые находки и machine-readable state закреплены в `B1.1b/`. Следующий этап — `R1_MECHANICAL_EXTRACTION`: механическое разбиение v9 на модули без изменения нормативной семантики.

Открыты три находки: точная алгебра операций `V8-01`, модель enumeration domains `V8-EXT-01` и матрица population semantics `V8-EXT-02`. Их владельцы — модули `M6.2`, `M6.3` и `M6.4`.

Актуальное состояние определяется файлами `B1.1b/state/PROJECT-STATE.json`, `B1.1b/state/OPEN-FINDINGS.json` и immutable baseline `B1.1b/baseline/v9/BASELINE.json`. История существенных изменений ведётся в корневом `CHANGELOG.md`.

Canonical corpus, validator, runtime, host state, commit/push и переход к `B1.2` остаются заблокированы. Монолитные редакции `B1.1b v10+` не выпускаются.

"""


FINAL_SECTION = """## Модульный workflow B1.1b

Работа ведётся по этапам `R0`–`R10` в каталоге `B1.1b/`:

1. `R0` — immutable checkpoint v9 — `PASS`;
2. `R1` — механическое извлечение модулей — следующий шаг;
3. `R2` — интерфейсы, symbol-level DAG и checker;
4. `R3`–`R6` — локализация, исправление и focused-аудит M6;
5. `R7`–`R8` — интеграционная сборка и полный механический прогон;
6. `R9` — два независимых интеграционных `ACCEPT` одного immutable пакета;
7. `R10` — разрешение открыть `B1.2`.

`README.md` показывает текущую точку проекта, `CHANGELOG.md` хранит историю изменений, а machine-readable файлы в `B1.1b/state/` являются источником истины для gates и статусов.

Commit/push и release разрешаются только отдельным решением после прохождения соответствующих gates.
"""


CHANGELOG_DATA = """# Changelog

Все существенные изменения SecureLinux-Policy фиксируются в этом файле.

Формат основан на Keep a Changelog. До появления первого разрешённого release изменения ведутся в разделе `Unreleased`; датированные audit-артефакты в `docs/` остаются доказательствами отдельных этапов.

## [Unreleased]

### Added

- Модульный workspace `B1.1b/` с каталогами baseline, modules, integration, state, tools и reports.
- Immutable candidate baseline B1.1b v9 и machine-readable файлы `BASELINE.json`, `OPEN-FINDINGS.json`, `PROJECT-STATE.json`.
- Административный overlay R0.1 для синхронизации корневой документации без изменения baseline R0.

### Changed

- `README.md` синхронизирован с текущим gate: `B1.1b v9 = NOT_ACCEPTED`, `TASK-B1.1 = NOT_ACCEPTED`, `B1.2 = NOT_STARTED`.
- Разработка B1.1b переведена с монолитных редакций на модули M0–M7 и этапы R0–R10.

### Fixed

- Удалены устаревшие указания, называвшие I5 или recovery v2.5A→v2.5B текущим следующим шагом.

### Verified

- `R0_BASELINE_CLOSURE_PASS`.
- B1.1b v9 self-test — PASS.
- Полный regression suite — 107/107 PASS.

### Current gates

- `B1.1a v2.1 = ACCEPT`.
- `B1.1b v9 = IMMUTABLE_CANDIDATE_NOT_ACCEPTED`.
- `TASK-B1.1 = NOT_ACCEPTED`.
- `B1.2 = NOT_STARTED`.
- `SELECTOR_INSTANCES_FROZEN = 0/20`.
""".encode("utf-8")


def build_readme(original: bytes) -> bytes:
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise R01Error("README.md is not UTF-8") from exc
    current_heading = "## Текущий этап\n"
    architecture_heading = "## Архитектура\n"
    recovery_heading = "## Recovery checkpoint: v2.5A → v2.5B\n"
    for heading in (current_heading, architecture_heading, recovery_heading):
        if text.count(heading) != 1:
            raise R01Error(f"README heading missing or duplicated: {heading.strip()}")
    current_at = text.index(current_heading)
    architecture_at = text.index(architecture_heading)
    recovery_at = text.index(recovery_heading)
    if not (current_at < architecture_at < recovery_at):
        raise R01Error("README section order is invalid")
    result = text[:current_at] + CURRENT_SECTION + text[architecture_at:recovery_at].rstrip() + "\n\n" + FINAL_SECTION
    return result.encode("utf-8")


def verify_foundations(root: Path) -> tuple[dict[str, object], dict[str, object], bytes]:
    baseline_data = require_regular(root / "B1.1b/baseline/v9/BASELINE.json", BASELINE_SHA256)
    if require_regular(root / "B1.1b/baseline/v9/BASELINE.sha256") != f"{BASELINE_SHA256}  BASELINE.json\n".encode():
        raise R01Error("BASELINE.sha256 mismatch")
    findings_data = require_regular(root / "B1.1b/state/OPEN-FINDINGS.json", OPEN_FINDINGS_SHA256)
    r0_tool = require_regular(
        root / "B1.1b/tools/SecureLinux-Policy-TASK-B1.1-R0-baseline-init-20260813.py",
        R0_TOOL_SHA256,
    )
    if not r0_tool:
        raise R01Error("R0 tool is empty")
    baseline = json.loads(baseline_data)
    findings = json.loads(findings_data)
    state_data = require_regular(root / STATE_REL)
    state = json.loads(state_data)
    if baseline.get("gate") != "R0_BASELINE_CLOSURE_PASS":
        raise R01Error("R0 baseline gate is not PASS")
    if state.get("baseline_sha256") != BASELINE_SHA256:
        raise R01Error("PROJECT-STATE baseline reference mismatch")
    if state.get("open_findings_sha256") != OPEN_FINDINGS_SHA256:
        raise R01Error("PROJECT-STATE findings reference mismatch")
    if {item.get("finding_id") for item in findings.get("findings", [])} != {"V8-01", "V8-EXT-01", "V8-EXT-02"}:
        raise R01Error("open finding set changed")
    return baseline, state, state_data


def run_tests(root: Path) -> None:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    selftest = subprocess.run(
        [sys.executable, str(root / SELFTEST_REL), str(root)],
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if selftest.returncode != 0 or "RESULT=B1_1B_V9_SELFTEST_PASS" not in selftest.stdout:
        raise R01Error("v9 self-test failed:\n" + selftest.stdout[-4000:])
    regression = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        cwd=root,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    count_match = re.search(r"Ran\s+(\d+)\s+tests?", regression.stdout)
    count = int(count_match.group(1)) if count_match else None
    if regression.returncode != 0 or count != 107 or not re.search(r"^OK$", regression.stdout, re.MULTILINE):
        raise R01Error("107-test regression failed:\n" + regression.stdout[-5000:])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project_root", type=Path)
    arguments = parser.parse_args()
    root = arguments.project_root.resolve()
    script_path = Path(__file__).resolve()
    if not root.is_dir() or not (root / "B1.1b").is_dir():
        raise R01Error(f"R0 project root missing: {root}")

    baseline, state, state_data = verify_foundations(root)
    inventory = baseline_inventory(baseline)
    if inventory.get("README.md") != {"sha256": ORIGINAL_README_SHA256, "size": ORIGINAL_README_SIZE}:
        raise R01Error("R0 baseline does not contain the pinned README.md")
    if "CHANGELOG.md" in inventory:
        raise R01Error("R0 baseline unexpectedly contains CHANGELOG.md")

    readme_path = root / "README.md"
    changelog_path = root / "CHANGELOG.md"
    current_readme = require_regular(readme_path)
    current_readme_hash = sha256_bytes(current_readme)
    if current_readme_hash == ORIGINAL_README_SHA256:
        new_readme = build_readme(current_readme)
    elif "## Модульный workflow B1.1b\n" in current_readme.decode("utf-8"):
        new_readme = current_readme
    else:
        raise R01Error("README.md is neither the R0 version nor the R0.1 version")

    expected_overlay = dict(inventory)
    expected_overlay["README.md"] = {"sha256": sha256_bytes(new_readme), "size": len(new_readme)}
    expected_overlay["CHANGELOG.md"] = {"sha256": sha256_bytes(CHANGELOG_DATA), "size": len(CHANGELOG_DATA)}
    actual_before = scan_snapshot(root)
    baseline_snapshot = actual_before == inventory
    overlay_snapshot = actual_before == expected_overlay
    if not baseline_snapshot and not overlay_snapshot:
        raise R01Error("live project differs from both R0 and R0.1 overlay: " + snapshot_diff(expected_overlay, actual_before))

    if state.get("current_phase") == "R0_COMPLETE":
        if sha256_bytes(state_data) != R0_PROJECT_STATE_SHA256:
            raise R01Error("R0 PROJECT-STATE hash mismatch")
    elif state.get("current_phase") != "R0_1_COMPLETE":
        raise R01Error("R0.1 may run only from R0_COMPLETE or verify R0_1_COMPLETE")

    script_data = require_regular(script_path)
    script_digest = sha256_bytes(script_data)
    tool_rel = f"B1.1b/tools/{SCRIPT_NAME}"
    tool_sidecar_rel = tool_rel + ".sha256"

    ledger = {
        "schema": "securelinux-policy-r0.1-admin-docs-ledger/v1",
        "date": DATE,
        "classification": "ADMINISTRATIVE_NON_NORMATIVE",
        "baseline_sha256": BASELINE_SHA256,
        "allowed_paths": ["README.md", "CHANGELOG.md"],
        "changes": {
            "README.md": {
                "action": "UPDATE",
                "before_sha256": ORIGINAL_README_SHA256,
                "before_size": ORIGINAL_README_SIZE,
                "after_sha256": sha256_bytes(new_readme),
                "after_size": len(new_readme),
            },
            "CHANGELOG.md": {
                "action": "CREATE",
                "after_sha256": sha256_bytes(CHANGELOG_DATA),
                "after_size": len(CHANGELOG_DATA),
            },
        },
        "mutation_assertion": {
            "baseline": False,
            "proposal": False,
            "schema": False,
            "canonical": False,
            "validator": False,
            "runtime": False,
            "src": False,
            "tests": False,
            "sources": False,
            "host": False,
        },
        "gates_unchanged": {
            "b1_1b": "NOT_ACCEPTED",
            "task_b1_1": "NOT_ACCEPTED",
            "task_b1_2": "NOT_STARTED",
            "selector_instances_frozen": "0/20",
        },
        "next_phase": "R1_MECHANICAL_EXTRACTION",
    }
    ledger_data = canonical_json_bytes(ledger)
    manifest_data = (
        f"{sha256_bytes(new_readme)}  README.md\n"
        f"{sha256_bytes(CHANGELOG_DATA)}  CHANGELOG.md\n"
        f"{sha256_bytes(ledger_data)}  {LEDGER_REL}\n"
    ).encode("utf-8")

    immutable_write(root / tool_rel, script_data)
    immutable_write(root / tool_sidecar_rel, f"{script_digest}  {SCRIPT_NAME}\n".encode())
    immutable_write(root / LEDGER_REL, ledger_data)
    immutable_write(root / MANIFEST_REL, manifest_data)

    changed_now = False
    old_readme = current_readme
    try:
        if baseline_snapshot:
            atomic_replace(readme_path, new_readme, ".tmp-r0.1")
            if changelog_path.exists():
                raise R01Error("CHANGELOG.md appeared during R0.1")
            atomic_replace(changelog_path, CHANGELOG_DATA, ".tmp-r0.1")
            changed_now = True
        else:
            if require_regular(readme_path) != new_readme or require_regular(changelog_path) != CHANGELOG_DATA:
                raise R01Error("existing R0.1 documentation differs")

        if scan_snapshot(root) != expected_overlay:
            raise R01Error("R0.1 changed a path outside the administrative overlay")
        run_tests(root)
        if scan_snapshot(root) != expected_overlay:
            raise R01Error("tests changed the project snapshot")
    except Exception:
        if changed_now:
            atomic_replace(readme_path, old_readme, ".tmp-r0.1-rollback")
            try:
                changelog_path.unlink()
            except FileNotFoundError:
                pass
        raise

    new_state = json.loads(json.dumps(state))
    new_state["current_phase"] = "R0_1_COMPLETE"
    new_state["current_next_step"] = "R1_MECHANICAL_EXTRACTION"
    new_state.setdefault("gates", {})["R0_1_ADMIN_DOCS_OVERLAY_PASS"] = True
    new_state["r0_1_admin_docs"] = {
        "classification": "ADMINISTRATIVE_NON_NORMATIVE",
        "ledger_sha256": sha256_bytes(ledger_data),
        "manifest_sha256": sha256_bytes(manifest_data),
        "readme_sha256": sha256_bytes(new_readme),
        "changelog_sha256": sha256_bytes(CHANGELOG_DATA),
        "v9_selftest": "PASS",
        "regression_tests": "107/107_PASS",
    }
    new_state_data = canonical_json_bytes(new_state)
    current_state_data = require_regular(root / STATE_REL)
    if current_state_data != new_state_data:
        if current_state_data != state_data or state.get("current_phase") != "R0_COMPLETE":
            raise R01Error("PROJECT-STATE is neither pinned R0 nor expected R0.1")
        atomic_replace(root / STATE_REL, new_state_data, ".tmp-r0.1")

    if require_regular(root / "B1.1b/baseline/v9/BASELINE.json", BASELINE_SHA256) != canonical_json_bytes(baseline):
        raise R01Error("immutable baseline changed")

    print("RESULT=R0_1_ADMIN_DOCS_OVERLAY_PASS")
    print("README_MD=UPDATED_CURRENT_STATE")
    print("CHANGELOG_MD=CREATED")
    print("R0_BASELINE=UNCHANGED")
    print("V9_SELFTEST=PASS")
    print("FULL_REGRESSION_TESTS=107/107_PASS")
    print("B1_1B_V9=IMMUTABLE_CANDIDATE_NOT_ACCEPTED")
    print("TASK_B1_1_ACCEPTED=false")
    print("TASK_B1_2=NOT_STARTED")
    print("SELECTOR_INSTANCES_FROZEN=0/20")
    print(f"SHA256={sha256_bytes(new_readme)}  README.md")
    print(f"SHA256={sha256_bytes(CHANGELOG_DATA)}  CHANGELOG.md")
    print(f"SHA256={sha256_bytes(ledger_data)}  {LEDGER_REL}")
    print(f"SHA256={sha256_bytes(manifest_data)}  {MANIFEST_REL}")
    print(f"SHA256={sha256_bytes(new_state_data)}  {STATE_REL}")
    print("CURRENT_NEXT_STEP=R1_MECHANICAL_EXTRACTION")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (R01Error, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"R0_1_FAIL={exc}", file=sys.stderr)
        raise SystemExit(1)
