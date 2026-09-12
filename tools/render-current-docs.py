#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

README_BEGIN = "<!-- BEGIN GENERATED CURRENT STATUS -->"
README_END = "<!-- END GENERATED CURRENT STATUS -->"
MAP_BEGIN = "<!-- BEGIN GENERATED MAP STATUS -->"
MAP_END = "<!-- END GENERATED MAP STATUS -->"


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise RuntimeError(f"refuse symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = (path.stat().st_mode & 0o7777) if path.exists() else 0o644
    fd, tmp_name = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def parse_progress(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw:
            continue
        if "=" not in raw:
            raise RuntimeError(f"bad PROGRESS line {lineno}")
        key, value = raw.split("=", 1)
        if not key or key in out:
            raise RuntimeError(f"bad/duplicate PROGRESS key {key!r}")
        out[key] = value
    return out


def parse_generator_constants(path: Path) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    wanted = {"PRODUCT_STATUS", "TARGET_FAMILY_ID", "GENERATOR_ID"}
    out: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in wanted:
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            raise RuntimeError(f"generator constant {target.id} is not a literal string")
        out[target.id] = node.value.value
    missing = wanted - out.keys()
    if missing:
        raise RuntimeError("generator constants missing: " + ",".join(sorted(missing)))
    return out


def yaml_scalar(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value.startswith('"') and value.endswith('"'):
        return json.loads(value)
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    return value


def parse_control_kind(path: Path) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    in_parameter = False
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            in_parameter = raw.strip() == "parameter:"
            continue
        if in_parameter and raw.startswith("  kind:"):
            return yaml_scalar(raw.split(":", 1)[1])
        if in_parameter and raw.startswith("  ") and not raw.startswith("    "):
            continue
    raise RuntimeError(f"parameter.kind not found: {path}")


def parse_control_apply_supported(path: Path) -> bool:
    lines = path.read_text(encoding="utf-8").splitlines()
    in_apply = False
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            in_apply = raw.strip() == "apply:"
            continue
        if in_apply and raw.startswith("  supported:"):
            value = yaml_scalar(raw.split(":", 1)[1]).lower()
            if value == "true":
                return True
            if value == "false":
                return False
            raise RuntimeError(f"invalid apply.supported: {path}")
    raise RuntimeError(f"apply.supported not found: {path}")


def split_control_ids(raw: str) -> list[str]:
    ids = [x.strip() for x in raw.split(",") if x.strip()]
    if not ids:
        raise RuntimeError("closure expected_control_ids empty")
    return ids


def collect_state(root: Path) -> dict:
    source_rows = read_tsv(root / "index/source-v4/SOURCE-INDEX.tsv")
    if not source_rows:
        raise RuntimeError("empty SOURCE-INDEX")
    source_by_id = {row["index_id"]: row for row in source_rows}
    if len(source_by_id) != len(source_rows):
        raise RuntimeError("duplicate SOURCE-INDEX id")

    controlled_closed = [
        row for row in source_rows
        if row["status"] == "CLOSED" and not row["disposition"].strip()
    ]
    disposed_closed = [
        row for row in source_rows
        if row["status"] == "CLOSED" and row["disposition"].strip()
    ]
    open_rows = [row for row in source_rows if row["status"] == "OPEN"]
    if len(controlled_closed) + len(disposed_closed) + len(open_rows) != len(source_rows):
        raise RuntimeError("SOURCE-INDEX has unsupported status population")

    progress = parse_progress(root / "index/source-v4/PROGRESS.txt")
    expected_progress = {
        "TOTAL_INDEX_ROWS": str(len(source_rows)),
        "CLOSED_INDEX_ROWS": str(len(controlled_closed) + len(disposed_closed)),
        "OPEN_INDEX_ROWS": str(len(open_rows)),
        "CLOSURE_RATIO": f"{len(controlled_closed) + len(disposed_closed)}/{len(source_rows)}",
        "CONTROLLED_CLOSED_WITH_CONTRACT": str(len(controlled_closed)),
        "DISPOSED_CLOSED_ROWS": str(len(disposed_closed)),
    }
    if set(progress) != set(expected_progress):
        missing = sorted(set(expected_progress) - set(progress))
        extra = sorted(set(progress) - set(expected_progress))
        raise RuntimeError(f"PROGRESS key-set mismatch missing={missing} extra={extra}")
    for key, expected in expected_progress.items():
        if progress[key] != expected:
            raise RuntimeError(f"PROGRESS mismatch {key}: {progress[key]!r} != {expected!r}")

    controls = read_tsv(root / "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv")
    control_by_id = {row["control_id"]: row for row in controls}
    if len(control_by_id) != len(controls):
        raise RuntimeError("duplicate control id in CONTROL-MANIFEST")

    kinds: dict[str, str] = {}
    apply_supported: dict[str, bool] = {}
    for row in controls:
        path = root / "controls/fstec-core/linux-2022" / row["file"]
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"control file missing/non-regular: {row['file']}")
        if sha256(path) != row["sha256"]:
            raise RuntimeError(f"control manifest SHA mismatch: {row['control_id']}")
        kinds[row["control_id"]] = parse_control_kind(path)
        apply_supported[row["control_id"]] = parse_control_apply_supported(path)
        src = source_by_id.get(row["index_id"])
        if not src:
            raise RuntimeError(f"control references unknown source: {row['control_id']}")
        if src["locator"] != row["locator"]:
            raise RuntimeError(f"control/source locator mismatch: {row['control_id']}")

    closure = read_tsv(root / "index/source-v4/CLOSURE-CONTRACT.tsv")
    closure_by_id = {row["index_id"]: row for row in closure}
    if len(closure_by_id) != len(closure):
        raise RuntimeError("duplicate closure contract index_id")
    controlled_ids = {row["index_id"] for row in controlled_closed}
    if set(closure_by_id) != controlled_ids:
        raise RuntimeError("closure contract population != controlled CLOSED population")

    for index_id, row in closure_by_id.items():
        ids = split_control_ids(row["expected_control_ids"])
        actual_ids = sorted(
            control["control_id"] for control in controls if control["index_id"] == index_id
        )
        if sorted(ids) != actual_ids:
            raise RuntimeError(f"closure/control population mismatch: {index_id}")

    adapters = read_tsv(root / "product/ADAPTER-REGISTRY.tsv")
    adapter_by_kind = {row["parameter_kind"]: row for row in adapters}
    if len(adapter_by_kind) != len(adapters):
        raise RuntimeError("duplicate parameter_kind in ADAPTER-REGISTRY")
    for row in adapters:
        for path_key, sha_key in (
            ("semantic_contract_path", "semantic_contract_sha256"),
            ("adapter_contract_path", "adapter_contract_sha256"),
            ("implementation_path", "implementation_sha256"),
        ):
            p = root / row[path_key]
            if not p.is_file() or p.is_symlink():
                raise RuntimeError(f"registry target missing/non-regular: {row[path_key]}")
            if sha256(p) != row[sha_key]:
                raise RuntimeError(f"registry SHA mismatch: {row[path_key]}")

    kind_registry = root / "product/APPLY-KIND-REGISTRY.tsv"
    kind_expected_fields = (
        "apply_kind", "parameter_kind", "target_class", "authority_form",
        "architecture_id", "architecture_path", "architecture_sha256",
    )
    with kind_registry.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if tuple(reader.fieldnames or ()) != kind_expected_fields:
            raise RuntimeError("APPLY kind registry field-set mismatch")
        kind_rows = list(reader)
    if not kind_rows:
        raise RuntimeError("APPLY kind registry is empty")
    if len({row["apply_kind"] for row in kind_rows}) != len(kind_rows):
        raise RuntimeError("duplicate apply_kind in APPLY kind registry")
    if len({row["parameter_kind"] for row in kind_rows}) != len(kind_rows):
        raise RuntimeError("duplicate parameter_kind in APPLY kind registry")
    for row in kind_rows:
        if any(not row[field] for field in kind_expected_fields):
            raise RuntimeError("empty field in APPLY kind registry")
        if row["authority_form"] != "MECHANISM_AUTHORITY_V1":
            raise RuntimeError("unsupported APPLY authority_form")
        p = root / row["architecture_path"]
        if not p.is_file() or p.is_symlink():
            raise RuntimeError(f"APPLY authority missing/non-regular: {row['architecture_path']}")
        if sha256(p) != row["architecture_sha256"]:
            raise RuntimeError(f"APPLY authority SHA mismatch: {row['architecture_path']}")

    implementation_registry = root / "product/APPLY-IMPLEMENTATION-REGISTRY.tsv"
    with implementation_registry.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        implementation_expected_fields = (
            "apply_kind", "composition_contract_id", "adapter_id", "binding_path",
            "binding_sha256", "implementation_path", "implementation_sha256",
        )
        if tuple(reader.fieldnames or ()) != implementation_expected_fields:
            raise RuntimeError("APPLY implementation registry field-set mismatch")
        implementation_rows = list(reader)
    if not implementation_rows:
        raise RuntimeError("APPLY implementation registry is empty")
    if len({row["apply_kind"] for row in implementation_rows}) != len(implementation_rows):
        raise RuntimeError("duplicate apply_kind in APPLY implementation registry")
    if len({row["adapter_id"] for row in implementation_rows}) != len(implementation_rows):
        raise RuntimeError("duplicate adapter_id in APPLY implementation registry")
    for row in implementation_rows:
        if any(not row[field] for field in implementation_expected_fields):
            raise RuntimeError("empty field in APPLY implementation registry")
        for path_key, sha_key in (
            ("binding_path", "binding_sha256"),
            ("implementation_path", "implementation_sha256"),
        ):
            p = root / row[path_key]
            if not p.is_file() or p.is_symlink():
                raise RuntimeError(f"APPLY registry target missing/non-regular: {row[path_key]}")
            if sha256(p) != row[sha_key]:
                raise RuntimeError(f"APPLY registry SHA mismatch: {row[path_key]}")
    kind_by_apply = {row["apply_kind"]: row for row in kind_rows}
    impl_by_apply = {row["apply_kind"]: row for row in implementation_rows}
    if set(kind_by_apply) != set(impl_by_apply):
        raise RuntimeError("APPLY registries are not paired by apply_kind")

    enabled_controls = [row for row in controls if apply_supported[row["control_id"]]]
    route_by_parameter_kind = {row["parameter_kind"]: row for row in kind_rows}
    active_apply_kinds = sorted(
        {row["apply_kind"] for row in kind_rows},
        key=lambda value: value.encode("utf-8"),
    )

    generator = parse_generator_constants(root / "product/generate-product-check-v2.py")
    platform_rows = read_tsv(root / "product/SUPPORTED-PLATFORMS.tsv")
    if len(platform_rows) != 7 or any(r.get("status") != "SUPPORTED" for r in platform_rows):
        raise RuntimeError("supported platform matrix mismatch")
    desktop_rows = read_tsv(root / "product/SUPPORTED-DESKTOPS.tsv")
    if desktop_rows != [{
        "environment_id": "ubuntu-24.04-x86_64-desktop",
        "os_id": "ubuntu",
        "version_id": "24.04",
        "arch": "x86_64",
        "type": "DESKTOP",
        "status": "SUPPORTED",
    }]:
        raise RuntimeError("supported desktop matrix mismatch")
    for row in adapters:
        contract = json.loads((root / row["semantic_contract_path"]).read_text(encoding="utf-8"))
        if contract.get("target_id") != generator["TARGET_FAMILY_ID"]:
            raise RuntimeError(f"adapter target mismatch: {row['parameter_kind']}")
        if contract.get("read_only") is not True:
            raise RuntimeError(f"adapter semantic contract is not read_only: {row['parameter_kind']}")

    controls_by_kind: dict[str, list[str]] = {}
    for cid, kind in kinds.items():
        controls_by_kind.setdefault(kind, []).append(cid)

    return {
        "source_rows": source_rows,
        "source_by_id": source_by_id,
        "controlled_closed": controlled_closed,
        "disposed_closed": disposed_closed,
        "open_rows": open_rows,
        "controls": controls,
        "control_by_id": control_by_id,
        "control_kind": kinds,
        "closure": closure,
        "closure_by_id": closure_by_id,
        "adapters": adapters,
        "apply_kind_rows": kind_rows,
        "implementation_rows": implementation_rows,
        "apply_supported": apply_supported,
        "enabled_apply_controls": enabled_controls,
        "active_apply_kinds": active_apply_kinds,
        "adapter_by_kind": adapter_by_kind,
        "controls_by_kind": controls_by_kind,
        "generator": generator,
        "platform_rows": platform_rows,
        "desktop_rows": desktop_rows,
    }


def render_status_block(state: dict) -> str:
    total = len(state["source_rows"])
    controlled = len(state["controlled_closed"])
    disposed = len(state["disposed_closed"])
    open_count = len(state["open_rows"])
    controls = len(state["controls"])
    closure_count = len(state["closure"])
    adapters = len(state["adapters"])
    target = state["generator"]["TARGET_FAMILY_ID"]
    product_status = state["generator"]["PRODUCT_STATUS"]
    lines = [
        README_BEGIN,
        "```text",
        f"TOTAL_INDEX_ROWS={total}",
        f"CONTROLLED_CLOSED_WITH_CONTRACT={controlled}",
        f"DISPOSED_CLOSED_ROWS={disposed}",
        f"OPEN_INDEX_ROWS={open_count}",
        f"CLOSURE_RATIO={controlled + disposed}/{total}",
        f"CANONICAL_CONTROLS={controls}",
        f"CLOSURE_CONTRACT_ROWS={closure_count}",
        f"ADAPTER_KINDS={adapters}",
        f"CHECK_TARGET_FAMILY={target}",
        f"SUPPORTED_ENVIRONMENTS={len(state['platform_rows']) + len(state['desktop_rows'])}",
        f"CHECK_STATUS={product_status}",
        "CHECK=IMPLEMENTED_READ_ONLY",
        "APPLY=IMPLEMENTED",
        f"APPLY_KINDS={','.join(state['active_apply_kinds'])}",
        f"APPLY_CONTROL_COUNT={len(state['enabled_apply_controls'])}",
        f"APPLY_IMPLEMENTATION_COUNT={len(state['implementation_rows'])}",
        "RESTORE=NOT_PLANNED",
        "ROLLBACK_MODEL=EXTERNAL_SNAPSHOT",
        "FULL_FSTEC_COMPLIANCE_CLAIM=false",
        "```",
        "",
        "CHECK охватывает только требования, представленные текущими canonical controls. "
        "Этот статус не является заявлением о полном соответствии требованиям ФСТЭК.",
        README_END,
    ]
    return "\n".join(lines)


def render_map_status_block(state: dict) -> str:
    total = len(state["source_rows"])
    controlled = len(state["controlled_closed"])
    open_count = len(state["open_rows"])
    controls = len(state["controls"])
    adapters = len(state["adapters"])
    target = state["generator"]["TARGET_FAMILY_ID"]
    return "\n".join([
        MAP_BEGIN,
        f"`строки source={total} · controlled CLOSED={controlled} · OPEN={open_count} · "
        f"canonical controls={controls} · adapters={adapters} · target-family={target}`",
        "",
        "Точные таблицы покрытия: [`docs/fstec-coverage.md`](fstec-coverage.md).",
        MAP_END,
    ])


def md_cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_coverage(state: dict) -> str:
    total = len(state["source_rows"])
    controlled = len(state["controlled_closed"])
    disposed = len(state["disposed_closed"])
    open_count = len(state["open_rows"])
    controls = len(state["controls"])

    lines = [
        "# Покрытие FSTEC core",
        "",
        "> **СГЕНЕРИРОВАННЫЙ ФАЙЛ.** Формируется `tools/render-current-docs.py` из "
        "`SOURCE-INDEX.tsv`, `CLOSURE-CONTRACT.tsv`, `CONTROL-MANIFEST.tsv` и "
        "`ADAPTER-REGISTRY.tsv`. Ручное редактирование запрещено.",
        "",
        "## Сводка",
        "",
        "```text",
        f"TOTAL_INDEX_ROWS={total}",
        f"CONTROLLED_CLOSED_WITH_CONTRACT={controlled}",
        f"DISPOSED_CLOSED_ROWS={disposed}",
        f"OPEN_INDEX_ROWS={open_count}",
        f"CANONICAL_CONTROLS={controls}",
        "```",
        "",
        "Число canonical controls и число закрытых source rows — разные величины: "
        "одна строка источника может требовать `exact-control-set` из нескольких controls.",
        "",
        "## Controlled CLOSED строки",
        "",
        "| Строка source | Locator | Режим coverage | Canonical controls | Parameter kind | Адаптер CHECK |",
        "|---|---|---|---|---|---|",
    ]

    source_order = {row["index_id"]: i for i, row in enumerate(state["source_rows"])}
    for row in sorted(state["closure"], key=lambda r: source_order[r["index_id"]]):
        index_id = row["index_id"]
        src = state["source_by_id"][index_id]
        ids = split_control_ids(row["expected_control_ids"])
        kinds = sorted({state["control_kind"][cid] for cid in ids})
        adapter_ids = []
        for kind in kinds:
            adapter = state["adapter_by_kind"].get(kind)
            adapter_ids.append(adapter["adapter_id"] if adapter else "—")
        lines.append(
            "| " + " | ".join([
                md_cell(index_id),
                md_cell(src["locator"]),
                md_cell(row["coverage_mode"]),
                md_cell("<br>".join(f"`{cid}`" for cid in ids)),
                md_cell("<br>".join(f"`{kind}`" for kind in kinds)),
                md_cell("<br>".join(f"`{aid}`" if aid != "—" else "—" for aid in adapter_ids)),
            ]) + " |"
        )

    pending = []
    for control in state["controls"]:
        src = state["source_by_id"][control["index_id"]]
        if src["status"] != "CLOSED" or control["index_id"] not in state["closure_by_id"]:
            pending.append(control)

    lines.extend([
        "",
        "## Canonical controls, которые ещё не закрывают строку source",
        "",
    ])
    if not pending:
        lines.append("Сейчас таких controls нет.")
    else:
        lines.extend([
            "| Control | Строка source | Locator | Kind | Статус source |",
            "|---|---|---|---|---|",
        ])
        for control in pending:
            src = state["source_by_id"][control["index_id"]]
            lines.append(
                f"| `{md_cell(control['control_id'])}` | {md_cell(control['index_id'])} | "
                f"{md_cell(control['locator'])} | `{md_cell(state['control_kind'][control['control_id']])}` | "
                f"{md_cell(src['status'])} |"
            )

    lines.extend([
        "",
        "## Готовность адаптеров CHECK",
        "",
        "| Parameter kind | Adapter | Только чтение | Canonical controls сейчас |",
        "|---|---|---:|---:|",
    ])
    for adapter in sorted(state["adapters"], key=lambda r: r["parameter_kind"].encode("utf-8")):
        kind = adapter["parameter_kind"]
        count = len(state["controls_by_kind"].get(kind, []))
        lines.append(
            f"| `{md_cell(kind)}` | `{md_cell(adapter['adapter_id'])}` | да | {count} |"
        )

    lines.extend([
        "",
        "## Покрытие по исходным документам",
        "",
        "| Документ source | Всего строк | Controlled CLOSED | Disposed CLOSED | OPEN | Canonical controls |",
        "|---|---:|---:|---:|---:|---:|",
    ])

    by_source: dict[str, dict[str, int]] = {}
    for src in state["source_rows"]:
        bucket = by_source.setdefault(
            src["source_id"],
            {"total": 0, "controlled": 0, "disposed": 0, "open": 0, "controls": 0},
        )
        bucket["total"] += 1
        if src["status"] == "OPEN":
            bucket["open"] += 1
        elif src["disposition"].strip():
            bucket["disposed"] += 1
        else:
            bucket["controlled"] += 1

    for control in state["controls"]:
        source_id = state["source_by_id"][control["index_id"]]["source_id"]
        by_source[source_id]["controls"] += 1

    for source_id in sorted(by_source, key=lambda s: s.encode("utf-8")):
        bucket = by_source[source_id]
        lines.append(
            f"| {md_cell(source_id)} | {bucket['total']} | {bucket['controlled']} | "
            f"{bucket['disposed']} | {bucket['open']} | {bucket['controls']} |"
        )

    lines.extend([
        "",
        "Эта таблица описывает фактическую структуру корпуса, а не обещание превратить "
        "каждую `OPEN` строку в host CHECK. По контракту source index строка закрывается "
        "canonical control-set либо explicit disposition; выбор зависит от source semantics.",
        "",
        "## Открытая часть корпуса",
        "",
        f"`{open_count}` source rows остаются `OPEN`. Полный перечень и их source metadata "
        "находятся в `index/source-v4/SOURCE-INDEX.tsv`; этот документ не дублирует 349 строк "
        "вручную.",
        "",
        "Наличие adapter или canonical control само по себе не закрывает source row: "
        "закрытие определяется source status и `CLOSURE-CONTRACT.tsv` либо explicit disposition.",
        "",
    ])
    return "\n".join(lines)


def replace_block(text: str, begin: str, end: str, block: str, label: str) -> str:
    if text.count(begin) != 1 or text.count(end) != 1:
        raise RuntimeError(f"{label}: expected exactly one marker pair")
    start = text.index(begin)
    stop = text.index(end, start) + len(end)
    return text[:start] + block + text[stop:]


def expected_outputs(root: Path) -> dict[Path, bytes]:
    state = collect_state(root)
    readme = root / "README.md"
    pmap = root / "docs/PROJECT-MAP-v3.md"
    readme_text = readme.read_text(encoding="utf-8")
    map_text = pmap.read_text(encoding="utf-8")
    new_readme = replace_block(
        readme_text, README_BEGIN, README_END, render_status_block(state), "README"
    )
    new_map = replace_block(
        map_text, MAP_BEGIN, MAP_END, render_map_status_block(state), "PROJECT-MAP"
    )
    return {
        readme: new_readme.encode("utf-8"),
        pmap: new_map.encode("utf-8"),
        root / "docs/fstec-coverage.md": render_coverage(state).encode("utf-8"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Render machine-owned current documentation blocks.")
    ap.add_argument("--project-root", required=True)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = ap.parse_args()

    root = Path(args.project_root).resolve()
    outputs = expected_outputs(root)
    if args.check:
        mismatches = []
        for path, expected in outputs.items():
            actual = path.read_bytes() if path.is_file() and not path.is_symlink() else None
            if actual != expected:
                mismatches.append(str(path.relative_to(root)))
        if mismatches:
            print("DOC_RENDER_RESULT=FAIL")
            print("DOC_RENDER_MISMATCH=" + ",".join(mismatches))
            return 1
        print("DOC_RENDER_RESULT=PASS")
        print("DOC_RENDER_FILES=3")
        return 0

    for path, data in outputs.items():
        atomic_write(path, data)
    print("DOC_RENDER_RESULT=PASS")
    print("DOC_RENDER_FILES=3")
    print("DOC_RENDER_WRITE=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
