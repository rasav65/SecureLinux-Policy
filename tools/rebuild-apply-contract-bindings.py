#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import os
import tempfile
from pathlib import Path, PurePosixPath

KIND_REGISTRY_REL = "product/APPLY-KIND-REGISTRY.tsv"
IMPLEMENTATION_REGISTRY_REL = "product/APPLY-IMPLEMENTATION-REGISTRY.tsv"
KIND_REGISTRY_FIELDS = (
    "apply_kind", "parameter_kind", "target_class", "authority_form",
    "architecture_id", "architecture_path", "architecture_sha256",
)
IMPLEMENTATION_REGISTRY_FIELDS = (
    "apply_kind", "composition_contract_id", "adapter_id", "binding_path",
    "binding_sha256", "implementation_path", "implementation_sha256",
)
BINDING_FIELDS = {
    "adapter_id", "binding_contract_id",
    "composition_contract_path", "composition_contract_sha256",
}
SUPPORTED_AUTHORITY_FORMS = {"MECHANISM_AUTHORITY_V1"}
TARGET_ID = "linux-x86_64-supported-v1"
HEX64 = set("0123456789abcdef")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_regular(path: Path, label: str) -> None:
    st = os.lstat(path)
    if path.is_symlink() or not path.is_file() or st.st_size <= 0:
        raise RuntimeError(f"{label}: regular non-symlink nonempty file required: {path}")


def safe_repo_rel(raw: str, prefix: str) -> str:
    p = PurePosixPath(raw)
    if p.is_absolute() or ".." in p.parts or "." in p.parts or not raw.startswith(prefix):
        raise RuntimeError(f"unsafe registry path: {raw!r}")
    return raw


def canonical_json(item: dict) -> str:
    return json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def read_registry(path: Path, fields: tuple[str, ...], label: str) -> list[dict[str, str]]:
    require_regular(path, label)
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if tuple(reader.fieldnames or ()) != fields:
            raise RuntimeError(f"{label}: unexpected fields: {reader.fieldnames!r}")
        rows = list(reader)
    if not rows:
        raise RuntimeError(f"{label}: empty registry")
    for row in rows:
        if any(not row[field] for field in fields):
            raise RuntimeError(f"{label}: empty field in apply_kind={row.get('apply_kind')!r}")
    return rows


def canonical_registry(fields: tuple[str, ...], rows: list[dict[str, str]]) -> str:
    ordered = sorted(rows, key=lambda r: r["apply_kind"].encode("utf-8"))
    lines = ["\t".join(fields)]
    for row in ordered:
        lines.append("\t".join(row[field] for field in fields))
    return "\n".join(lines) + "\n"


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def validate_hex64(value: str, label: str) -> None:
    if len(value) != 64 or any(ch not in HEX64 for ch in value):
        raise RuntimeError(f"{label}: invalid SHA256")


def load_authority(root: Path, row: dict[str, str]) -> tuple[dict, Path]:
    form = row["authority_form"]
    if form not in SUPPORTED_AUTHORITY_FORMS:
        raise RuntimeError(f"unsupported authority_form: {form}")
    rel = safe_repo_rel(row["architecture_path"], "product/contracts/")
    path = root / rel
    require_regular(path, "APPLY authority")
    authority = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(authority, dict):
        raise RuntimeError("APPLY authority: object required")
    if authority.get("authority_form") != form:
        raise RuntimeError("APPLY authority form mismatch")
    rb = authority.get("registry_binding")
    required = {
        "apply_kind", "parameter_kind", "target_class", "architecture_id",
        "composition_contract_id", "authority_path", "legacy_column_semantics",
        "adapter_id", "binding_contract_id",
    }
    if not isinstance(rb, dict) or set(rb) != required:
        raise RuntimeError("APPLY authority registry_binding fields mismatch")
    for field in ("apply_kind", "parameter_kind", "target_class", "architecture_id"):
        if rb[field] != row[field]:
            raise RuntimeError(f"APPLY authority identity mismatch: {field}")
    if rb["authority_path"] != rel:
        raise RuntimeError("APPLY authority path mismatch")
    if authority.get("mechanism_id") != rb["apply_kind"]:
        raise RuntimeError("APPLY authority mechanism/apply_kind mismatch")
    validate_hex64(row["architecture_sha256"], "APPLY kind registry architecture_sha256")
    return authority, path


def load_module(root: Path, impl_row: dict[str, str], authority: dict):
    rb = authority["registry_binding"]
    if impl_row["apply_kind"] != rb["apply_kind"]:
        raise RuntimeError("APPLY implementation apply_kind mismatch")
    if impl_row["composition_contract_id"] != rb["composition_contract_id"]:
        raise RuntimeError("APPLY composition identity mismatch")
    if impl_row["adapter_id"] != rb["adapter_id"]:
        raise RuntimeError("APPLY adapter identity mismatch")
    impl_rel = safe_repo_rel(impl_row["implementation_path"], "product/apply-adapters/")
    impl_path = root / impl_rel
    require_regular(impl_path, "APPLY implementation")
    validate_hex64(impl_row["implementation_sha256"], "APPLY implementation_sha256")
    spec = importlib.util.spec_from_file_location(
        "_slp_apply_" + rb["parameter_kind"].replace("-", "_"), impl_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load APPLY implementation")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for attr, expected in (
        ("ADAPTER_ID", rb["adapter_id"]),
        ("MECHANISM_ID", authority["mechanism_id"]),
        ("TARGET_ID", TARGET_ID),
    ):
        if getattr(mod, attr, None) != expected:
            raise RuntimeError(f"APPLY implementation {attr} mismatch")
    for fn in ("execute_control", "control_result_to_report"):
        if not callable(getattr(mod, fn, None)):
            raise RuntimeError(f"APPLY implementation API missing: {fn}")
    return mod, impl_path


def build_expected(root: Path):
    kind_path = root / KIND_REGISTRY_REL
    impl_path = root / IMPLEMENTATION_REGISTRY_REL
    kind_rows = read_registry(kind_path, KIND_REGISTRY_FIELDS, "APPLY kind registry")
    impl_rows = read_registry(impl_path, IMPLEMENTATION_REGISTRY_FIELDS, "APPLY implementation registry")

    kind_by_apply = {}
    parameter_kinds = set()
    architecture_ids = set()
    for row in kind_rows:
        apply_kind = row["apply_kind"]
        if apply_kind in kind_by_apply:
            raise RuntimeError(f"duplicate apply_kind in APPLY kind registry: {apply_kind}")
        if row["parameter_kind"] in parameter_kinds:
            raise RuntimeError(f"duplicate parameter_kind route: {row['parameter_kind']}")
        if row["architecture_id"] in architecture_ids:
            raise RuntimeError(f"duplicate architecture_id: {row['architecture_id']}")
        kind_by_apply[apply_kind] = row
        parameter_kinds.add(row["parameter_kind"])
        architecture_ids.add(row["architecture_id"])

    impl_by_apply = {}
    adapter_ids = set()
    for row in impl_rows:
        apply_kind = row["apply_kind"]
        if apply_kind in impl_by_apply:
            raise RuntimeError(f"duplicate apply_kind in APPLY implementation registry: {apply_kind}")
        if row["adapter_id"] in adapter_ids:
            raise RuntimeError(f"duplicate APPLY adapter_id: {row['adapter_id']}")
        impl_by_apply[apply_kind] = row
        adapter_ids.add(row["adapter_id"])

    if set(kind_by_apply) != set(impl_by_apply):
        missing_impl = sorted(set(kind_by_apply) - set(impl_by_apply))
        missing_kind = sorted(set(impl_by_apply) - set(kind_by_apply))
        raise RuntimeError(
            "unpaired APPLY registry row: "
            f"missing_implementation={missing_impl!r} missing_kind={missing_kind!r}"
        )

    expected_kind_rows = []
    expected_impl_rows = []
    expected_bindings = []
    processed = 0
    for apply_kind in sorted(kind_by_apply, key=lambda s: s.encode("utf-8")):
        kind_row = dict(kind_by_apply[apply_kind])
        impl_row = dict(impl_by_apply[apply_kind])
        authority, authority_path = load_authority(root, kind_row)
        rb = authority["registry_binding"]
        _mod, implementation_path = load_module(root, impl_row, authority)

        authority_sha = sha256_file(authority_path)
        binding_rel = safe_repo_rel(impl_row["binding_path"], "product/apply-adapters/")
        binding_path = root / binding_rel
        expected_binding = {
            "adapter_id": rb["adapter_id"],
            "binding_contract_id": rb["binding_contract_id"],
            "composition_contract_path": rb["authority_path"],
            "composition_contract_sha256": authority_sha,
        }
        binding_text = canonical_json(expected_binding)
        binding_sha = hashlib.sha256(binding_text.encode("utf-8")).hexdigest()
        impl_sha = sha256_file(implementation_path)

        kind_row["architecture_sha256"] = authority_sha
        impl_row["binding_sha256"] = binding_sha
        impl_row["implementation_sha256"] = impl_sha
        expected_kind_rows.append(kind_row)
        expected_impl_rows.append(impl_row)
        expected_bindings.append((binding_path, binding_text))
        processed += 1

    if processed != len(kind_rows) or processed != len(impl_rows):
        raise RuntimeError("not all APPLY registry rows were processed")
    return (
        canonical_registry(KIND_REGISTRY_FIELDS, expected_kind_rows),
        canonical_registry(IMPLEMENTATION_REGISTRY_FIELDS, expected_impl_rows),
        expected_bindings,
        processed,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()

    root = Path(args.project_root).resolve()
    if not (root / ".git").is_dir() and not (root / "product").is_dir():
        raise RuntimeError("project root required")

    kind_text, impl_text, bindings, processed = build_expected(root)
    kind_path = root / KIND_REGISTRY_REL
    impl_path = root / IMPLEMENTATION_REGISTRY_REL

    if args.check:
        if kind_path.read_text(encoding="utf-8") != kind_text:
            raise RuntimeError("APPLY kind registry binding is stale")
        if impl_path.read_text(encoding="utf-8") != impl_text:
            raise RuntimeError("APPLY implementation registry binding is stale")
        for path, expected in bindings:
            if not path.is_file() or path.is_symlink():
                raise RuntimeError(f"APPLY binding missing/non-regular: {path}")
            if path.read_text(encoding="utf-8") != expected:
                raise RuntimeError(f"APPLY binding is stale: {path}")
        print("APPLY_BINDING_ACTION=CHECK")
    else:
        for path, expected in bindings:
            atomic_write(path, expected)
        atomic_write(kind_path, kind_text)
        atomic_write(impl_path, impl_text)
        # Verify exact post-write state using the same pure derivation.
        check_kind, check_impl, check_bindings, check_processed = build_expected(root)
        if check_processed != processed or check_kind != kind_text or check_impl != impl_text:
            raise RuntimeError("APPLY registry write verification failed")
        for path, expected in check_bindings:
            if path.read_text(encoding="utf-8") != expected:
                raise RuntimeError(f"APPLY binding write verification failed: {path}")
        print("APPLY_BINDING_ACTION=WRITE")

    print(f"APPLY_BINDING_ARCHITECTURES={processed}")
    print(f"APPLY_BINDING_KIND_ROWS={processed}")
    print(f"APPLY_BINDING_IMPLEMENTATION_ROWS={processed}")
    print("APPLY_BINDING_RESULT=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"APPLY_BINDING_RESULT=FAIL: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1)
