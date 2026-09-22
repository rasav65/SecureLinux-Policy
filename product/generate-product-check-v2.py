#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath

GENERATOR_ID = "product-check-generator-v2"
PRODUCT_CLI_ID = "product-cli-v1"
PRODUCT_STATUS = "NON_RELEASE_PRODUCT_CANDIDATE"
TARGET_FAMILY_ID = "linux-x86_64-supported-v1"
PLATFORM_MATRIX_REL = "product/SUPPORTED-PLATFORMS.tsv"
DESKTOP_MATRIX_REL = "product/FIELD-COMPATIBILITY-DESKTOPS.tsv"

MANIFEST_REL = "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv"
CONTROL_DIR_REL = "controls/fstec-core/linux-2022"
REGISTRY_REL = "product/ADAPTER-REGISTRY.tsv"
APPLY_KIND_REGISTRY_REL = "product/APPLY-KIND-REGISTRY.tsv"
APPLY_REGISTRY_REL = "product/APPLY-IMPLEMENTATION-REGISTRY.tsv"
AUTHORITY_FORM_MECHANISM_V1 = "MECHANISM_AUTHORITY_V1"

MANIFEST_FIELDS = [
    "control_id", "index_id", "locator", "key", "expected", "file", "sha256"
]
REGISTRY_FIELDS = [
    "parameter_kind",
    "adapter_id",
    "semantic_contract_path",
    "semantic_contract_sha256",
    "adapter_contract_path",
    "adapter_contract_sha256",
    "implementation_path",
    "implementation_sha256",
]
APPLY_KIND_REGISTRY_FIELDS = [
    "apply_kind",
    "parameter_kind",
    "target_class",
    "authority_form",
    "architecture_id",
    "architecture_path",
    "architecture_sha256",
]
APPLY_REGISTRY_FIELDS = [
    "apply_kind",
    "composition_contract_id",
    "adapter_id",
    "binding_path",
    "binding_sha256",
    "implementation_path",
    "implementation_sha256",
]
APPLY_BINDING_FIELDS = {
    "adapter_id", "binding_contract_id",
    "composition_contract_path", "composition_contract_sha256",
}

CONTROL_ID_RE = re.compile(r"^(?!.*[\r\n])[A-Za-z0-9._-]+$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
FIELD_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")

ROOT_FIELDS = {"id", "layer", "profile", "source", "requirement", "parameter", "expected", "apply"}
SOURCE_FIELDS = {"index_id", "doc_id", "doc_sha256", "locator", "quote", "quote_sha256", "norm"}
REQUIREMENT_FIELDS = {"stated", "derived", "justification", "applicability"}
PARAMETER_FIELDS = {"kind", "locator", "key"}
EXPECTED_FIELDS = {"op", "value", "type"}
APPLY_FIELDS = {"supported"}

MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee /proc/sys", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "rmdir ", "mv ", "cp ", "touch ",
    "truncate ", "dd ", "sed -i", ">>",
)


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_regular(path: Path, label: str) -> None:
    st = os.lstat(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label}: regular non-symlink file required: {path}")
    if st.st_size <= 0:
        raise RuntimeError(f"{label}: empty file: {path}")


def parse_scalar(value: str, path: Path, lineno: int):
    value = value.strip()
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if re.fullmatch(r"-?[0-9]+", value):
        return int(value)
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{path}:{lineno}: invalid JSON-quoted scalar: {exc}") from exc
        if not isinstance(parsed, str):
            raise RuntimeError(f"{path}:{lineno}: quoted scalar must be string")
        if any(ch in parsed for ch in "\r\n\t\x00"):
            raise RuntimeError(f"{path}:{lineno}: control characters forbidden")
        return parsed
    if value.startswith("'"):
        raise RuntimeError(f"{path}:{lineno}: single-quoted scalars unsupported")
    if value == "":
        raise RuntimeError(f"{path}:{lineno}: empty scalar")
    if " #" in value or value.startswith("#"):
        raise RuntimeError(f"{path}:{lineno}: inline comments unsupported")
    return value


def parse_yaml_subset(path: Path) -> dict:
    require_regular(path, "control")
    raw = path.read_bytes()
    if b"\r" in raw:
        raise RuntimeError(f"{path}: CR bytes forbidden")
    text = raw.decode("utf-8")
    if not text.endswith("\n"):
        raise RuntimeError(f"{path}: final LF required")
    root = {}
    stack = [(-2, root)]
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if "\t" in raw_line:
            raise RuntimeError(f"{path}:{lineno}: tabs forbidden")
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent % 2:
            raise RuntimeError(f"{path}:{lineno}: indentation must be multiple of 2")
        stripped = raw_line.strip()
        if ":" not in stripped:
            raise RuntimeError(f"{path}:{lineno}: expected key: value")
        key, value = stripped.split(":", 1)
        key = key.strip()
        if not FIELD_KEY_RE.fullmatch(key):
            raise RuntimeError(f"{path}:{lineno}: invalid key {key!r}")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            raise RuntimeError(f"{path}:{lineno}: indentation underflow")
        parent_indent, parent = stack[-1]
        if indent != parent_indent + 2:
            raise RuntimeError(f"{path}:{lineno}: indentation jump")
        if key in parent:
            raise RuntimeError(f"{path}:{lineno}: duplicate key {key!r}")
        if value.strip() == "":
            child = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = parse_scalar(value, path, lineno)
    return root


def require_exact_fields(obj: dict, expected: set[str], label: str) -> None:
    if not isinstance(obj, dict) or set(obj) != expected:
        got = sorted(obj) if isinstance(obj, dict) else str(type(obj))
        raise RuntimeError(f"{label}: exact fields required, got {got}")


def safe_repo_rel(raw: str, prefix: str) -> str:
    p = PurePosixPath(raw)
    if p.is_absolute() or ".." in p.parts or "." in p.parts or not raw.startswith(prefix):
        raise RuntimeError(f"unsafe registry path: {raw!r}")
    return raw


def load_manifest(repo: Path):
    path = repo / MANIFEST_REL
    require_regular(path, "control manifest")
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        if reader.fieldnames != MANIFEST_FIELDS:
            raise RuntimeError(f"unexpected CONTROL-MANIFEST fields: {reader.fieldnames!r}")
        rows = list(reader)
    if not rows:
        raise RuntimeError("empty CONTROL-MANIFEST")
    ids = [r["control_id"] for r in rows]
    files = [r["file"] for r in rows]
    if len(set(ids)) != len(ids) or len(set(files)) != len(files):
        raise RuntimeError("duplicate control id/file in manifest")
    if ids != sorted(ids, key=lambda s: s.encode("utf-8")):
        raise RuntimeError("manifest controls are not UTF-8-byte sorted by control_id")
    for row in rows:
        if not CONTROL_ID_RE.fullmatch(row["control_id"]):
            raise RuntimeError(f"invalid control_id: {row['control_id']!r}")
        if not HEX64_RE.fullmatch(row["sha256"]):
            raise RuntimeError(f"invalid control SHA: {row['control_id']}")
        if "/" in row["file"] or row["file"] in (".", "..") or not row["file"].endswith(".yaml"):
            raise RuntimeError(f"invalid control filename: {row['file']!r}")
    actual_files = sorted(p.name for p in (repo / CONTROL_DIR_REL).glob("*.yaml"))
    if sorted(files) != actual_files:
        raise RuntimeError(
            f"manifest/YAML population mismatch manifest={sorted(files)!r} actual={actual_files!r}"
        )
    return rows, sha_file(path)


def load_control(repo: Path, row: dict[str, str]) -> dict[str, object]:
    path = repo / CONTROL_DIR_REL / row["file"]
    require_regular(path, "control")
    actual_sha = sha_file(path)
    if actual_sha != row["sha256"]:
        raise RuntimeError(f"control SHA mismatch {row['file']}: {actual_sha} != {row['sha256']}")
    rec = parse_yaml_subset(path)
    require_exact_fields(rec, ROOT_FIELDS, "control root")
    for sec, fields in (
        ("source", SOURCE_FIELDS),
        ("requirement", REQUIREMENT_FIELDS),
        ("parameter", PARAMETER_FIELDS),
        ("expected", EXPECTED_FIELDS),
        ("apply", APPLY_FIELDS),
    ):
        require_exact_fields(rec[sec], fields, sec)

    cid = rec["id"]
    source = rec["source"]
    requirement = rec["requirement"]
    parameter = rec["parameter"]
    expected = rec["expected"]
    apply = rec["apply"]

    if cid != row["control_id"]:
        raise RuntimeError(f"control id mismatch: {row['file']}")
    if rec["layer"] != "fstec-core" or rec["profile"] is not None:
        raise RuntimeError(f"unsupported layer/profile: {cid}")
    if source["index_id"] != row["index_id"] or source["locator"] != row["locator"]:
        raise RuntimeError(f"source identity mismatch: {cid}")
    if source["norm"] != "norm-v1":
        raise RuntimeError(f"unsupported source norm: {cid}")
    for field in ("doc_id", "doc_sha256", "quote", "quote_sha256"):
        if not isinstance(source[field], str) or not source[field]:
            raise RuntimeError(f"invalid source.{field}: {cid}")
    if not HEX64_RE.fullmatch(source["doc_sha256"]) or not HEX64_RE.fullmatch(source["quote_sha256"]):
        raise RuntimeError(f"invalid source SHA: {cid}")
    if sha_bytes(source["quote"].encode("utf-8")) != source["quote_sha256"]:
        raise RuntimeError(f"quote SHA mismatch: {cid}")
    if requirement["stated"] != source["quote"]:
        raise RuntimeError(f"requirement.stated != source.quote: {cid}")
    derived = requirement["derived"]
    justification = requirement["justification"]
    if derived is False:
        if justification is not None:
            raise RuntimeError(f"non-derived requirement has justification: {cid}")
    elif derived is True:
        if not isinstance(justification, str) or not justification.strip():
            raise RuntimeError(f"derived requirement missing justification: {cid}")
    else:
        raise RuntimeError(f"invalid requirement.derived: {cid}")
    if requirement["applicability"] != "technical":
        raise RuntimeError(f"unsupported applicability: {cid}")
    if not isinstance(parameter["kind"], str) or not parameter["kind"]:
        raise RuntimeError(f"invalid parameter.kind: {cid}")
    if str(parameter["key"]) != row["key"]:
        raise RuntimeError(f"parameter.key mismatch: {cid}")
    if str(expected["value"]) != row["expected"]:
        raise RuntimeError(f"expected.value mismatch: {cid}")
    if not isinstance(apply["supported"], bool):
        raise RuntimeError(f"invalid apply.supported: {cid}")

    return {
        "control_id": cid,
        "index_id": source["index_id"],
        "source_locator": source["locator"],
        "doc_id": source["doc_id"],
        "doc_sha256": source["doc_sha256"],
        "quote_sha256": source["quote_sha256"],
        "parameter_kind": parameter["kind"],
        "parameter_locator": parameter["locator"],
        "parameter_key": parameter["key"],
        "expected_op": expected["op"],
        "expected_value": expected["value"],
        "expected_type": expected["type"],
        "control_sha256": actual_sha,
        "apply_supported": apply["supported"],
    }


def load_registry(repo: Path):
    path = repo / REGISTRY_REL
    require_regular(path, "adapter registry")
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        if reader.fieldnames != REGISTRY_FIELDS:
            raise RuntimeError(f"unexpected registry fields: {reader.fieldnames!r}")
        rows = list(reader)
    if not rows:
        raise RuntimeError("empty adapter registry")
    kinds = [r["parameter_kind"] for r in rows]
    ids = [r["adapter_id"] for r in rows]
    if len(set(kinds)) != len(kinds) or len(set(ids)) != len(ids):
        raise RuntimeError("duplicate parameter_kind/adapter_id in registry")

    adapters = {}
    for row in rows:
        for sha_key in (
            "semantic_contract_sha256",
            "adapter_contract_sha256",
            "implementation_sha256",
        ):
            if not HEX64_RE.fullmatch(row[sha_key]):
                raise RuntimeError(f"invalid registry SHA {sha_key}: {row['parameter_kind']}")
        semantic_rel = safe_repo_rel(row["semantic_contract_path"], "product/contracts/")
        binding_rel = safe_repo_rel(row["adapter_contract_path"], "product/adapters/")
        impl_rel = safe_repo_rel(row["implementation_path"], "product/adapters/")
        semantic_path = repo / semantic_rel
        binding_path = repo / binding_rel
        impl_path = repo / impl_rel
        for p, label in (
            (semantic_path, "semantic contract"),
            (binding_path, "adapter binding"),
            (impl_path, "adapter implementation"),
        ):
            require_regular(p, label)
        if sha_file(semantic_path) != row["semantic_contract_sha256"]:
            raise RuntimeError(f"semantic SHA mismatch: {row['parameter_kind']}")
        if sha_file(binding_path) != row["adapter_contract_sha256"]:
            raise RuntimeError(f"binding SHA mismatch: {row['parameter_kind']}")
        if sha_file(impl_path) != row["implementation_sha256"]:
            raise RuntimeError(f"implementation SHA mismatch: {row['parameter_kind']}")

        semantic = json.loads(semantic_path.read_text(encoding="utf-8"))
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        if binding.get("parameter_kind") != row["parameter_kind"]:
            raise RuntimeError(f"binding parameter_kind mismatch: {row['parameter_kind']}")
        if binding.get("adapter_id") != row["adapter_id"]:
            raise RuntimeError(f"binding adapter_id mismatch: {row['parameter_kind']}")
        if binding.get("semantic_contract_path") != semantic_rel:
            raise RuntimeError(f"binding semantic path mismatch: {row['parameter_kind']}")
        if binding.get("semantic_contract_sha256") != row["semantic_contract_sha256"]:
            raise RuntimeError(f"binding semantic SHA mismatch: {row['parameter_kind']}")
        if binding.get("implementation_path") != impl_rel:
            raise RuntimeError(f"binding implementation path mismatch: {row['parameter_kind']}")
        if binding.get("implementation_sha256") != row["implementation_sha256"]:
            raise RuntimeError(f"binding implementation SHA mismatch: {row['parameter_kind']}")
        if semantic.get("semantic_contract_id") != binding.get("semantic_contract_id"):
            raise RuntimeError(f"semantic id mismatch: {row['parameter_kind']}")
        if semantic.get("target_id") != TARGET_FAMILY_ID:
            raise RuntimeError(f"semantic target mismatch: {row['parameter_kind']}")
        if binding.get("operation") != "check" or binding.get("target_id") != TARGET_FAMILY_ID:
            raise RuntimeError(f"binding operation/target mismatch: {row['parameter_kind']}")

        spec = importlib.util.spec_from_file_location(
            "_slp_adapter_" + re.sub(r"[^A-Za-z0-9_]", "_", row["parameter_kind"]),
            impl_path,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load adapter: {row['parameter_kind']}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if getattr(mod, "ADAPTER_ID", None) != row["adapter_id"]:
            raise RuntimeError(f"implementation adapter id mismatch: {row['parameter_kind']}")
        if getattr(mod, "PARAMETER_KIND", None) != row["parameter_kind"]:
            raise RuntimeError(f"implementation parameter kind mismatch: {row['parameter_kind']}")
        if getattr(mod, "TARGET_ID", None) != TARGET_FAMILY_ID:
            raise RuntimeError(f"implementation target mismatch: {row['parameter_kind']}")
        if not callable(getattr(mod, "shell_function", None)):
            raise RuntimeError(f"adapter shell_function missing: {row['parameter_kind']}")

        adapters[row["parameter_kind"]] = {
            "row": row,
            "binding": binding,
            "semantic": semantic,
            "module": mod,
        }
    return adapters, sha_file(path)


def _load_tsv_registry(path: Path, fields: list[str], label: str) -> list[dict[str, str]]:
    require_regular(path, label)
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        if reader.fieldnames != fields:
            raise RuntimeError(f"unexpected {label} fields: {reader.fieldnames!r}")
        rows = list(reader)
    if not rows:
        raise RuntimeError(f"empty {label}")
    for row in rows:
        if any(not row[field] for field in fields):
            raise RuntimeError(f"empty {label} field: {row.get('apply_kind')!r}")
    return rows


def load_apply_mechanisms(repo: Path):
    kind_path = repo / APPLY_KIND_REGISTRY_REL
    impl_path = repo / APPLY_REGISTRY_REL
    kind_rows = _load_tsv_registry(kind_path, APPLY_KIND_REGISTRY_FIELDS, "APPLY kind registry")
    impl_rows = _load_tsv_registry(impl_path, APPLY_REGISTRY_FIELDS, "APPLY implementation registry")

    kind_by_apply = {}
    parameter_kinds = set()
    architecture_ids = set()
    for row in kind_rows:
        if row["apply_kind"] in kind_by_apply:
            raise RuntimeError(f"duplicate APPLY apply_kind: {row['apply_kind']}")
        if row["parameter_kind"] in parameter_kinds:
            raise RuntimeError(f"duplicate APPLY parameter_kind route: {row['parameter_kind']}")
        if row["architecture_id"] in architecture_ids:
            raise RuntimeError(f"duplicate APPLY architecture_id: {row['architecture_id']}")
        if row["authority_form"] != AUTHORITY_FORM_MECHANISM_V1:
            raise RuntimeError(f"unsupported APPLY authority_form: {row['authority_form']}")
        kind_by_apply[row["apply_kind"]] = row
        parameter_kinds.add(row["parameter_kind"])
        architecture_ids.add(row["architecture_id"])

    impl_by_apply = {}
    adapter_ids = set()
    for row in impl_rows:
        if row["apply_kind"] in impl_by_apply:
            raise RuntimeError(f"duplicate APPLY implementation apply_kind: {row['apply_kind']}")
        if row["adapter_id"] in adapter_ids:
            raise RuntimeError(f"duplicate APPLY adapter_id: {row['adapter_id']}")
        impl_by_apply[row["apply_kind"]] = row
        adapter_ids.add(row["adapter_id"])
    if set(kind_by_apply) != set(impl_by_apply):
        raise RuntimeError(
            "unpaired APPLY registry row: "
            f"kind_only={sorted(set(kind_by_apply)-set(impl_by_apply))!r} "
            f"implementation_only={sorted(set(impl_by_apply)-set(kind_by_apply))!r}"
        )

    by_parameter_kind = {}
    for apply_kind in sorted(kind_by_apply, key=lambda x: x.encode("utf-8")):
        kind_row = kind_by_apply[apply_kind]
        impl_row = impl_by_apply[apply_kind]
        authority_rel = safe_repo_rel(kind_row["architecture_path"], "product/contracts/")
        authority_path = repo / authority_rel
        require_regular(authority_path, "APPLY authority")
        if not HEX64_RE.fullmatch(kind_row["architecture_sha256"]):
            raise RuntimeError("invalid APPLY authority SHA")
        if sha_file(authority_path) != kind_row["architecture_sha256"]:
            raise RuntimeError("APPLY authority SHA mismatch")
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        if authority.get("authority_form") != AUTHORITY_FORM_MECHANISM_V1:
            raise RuntimeError("APPLY authority form mismatch")
        rb = authority.get("registry_binding")
        expected_rb_fields = {
            "apply_kind", "parameter_kind", "target_class", "architecture_id",
            "composition_contract_id", "authority_path", "legacy_column_semantics",
            "adapter_id", "binding_contract_id",
        }
        if not isinstance(rb, dict) or set(rb) != expected_rb_fields:
            raise RuntimeError("APPLY authority registry_binding fields mismatch")
        for field in ("apply_kind", "parameter_kind", "target_class", "architecture_id"):
            if rb[field] != kind_row[field]:
                raise RuntimeError(f"APPLY authority identity mismatch: {field}")
        if rb["authority_path"] != authority_rel:
            raise RuntimeError("APPLY authority path mismatch")
        if authority.get("mechanism_id") != apply_kind:
            raise RuntimeError("APPLY authority mechanism/apply_kind mismatch")
        if impl_row["composition_contract_id"] != rb["composition_contract_id"]:
            raise RuntimeError("APPLY authority composition identity mismatch")
        if impl_row["adapter_id"] != rb["adapter_id"]:
            raise RuntimeError("APPLY authority adapter identity mismatch")

        binding_rel = safe_repo_rel(impl_row["binding_path"], "product/apply-adapters/")
        implementation_rel = safe_repo_rel(impl_row["implementation_path"], "product/apply-adapters/")
        binding_path = repo / binding_rel
        implementation_path = repo / implementation_rel
        for candidate, label in ((binding_path, "APPLY binding"), (implementation_path, "APPLY implementation")):
            cursor = repo
            for part in candidate.relative_to(repo).parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise RuntimeError(f"{label}: symlink component forbidden: {candidate}")
            require_regular(candidate, label)
        for sha_key in ("binding_sha256", "implementation_sha256"):
            if not HEX64_RE.fullmatch(impl_row[sha_key]):
                raise RuntimeError(f"invalid APPLY registry SHA: {sha_key}")
        if sha_file(binding_path) != impl_row["binding_sha256"]:
            raise RuntimeError("APPLY binding SHA mismatch")
        if sha_file(implementation_path) != impl_row["implementation_sha256"]:
            raise RuntimeError("APPLY implementation SHA mismatch")
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
        if not isinstance(binding, dict) or set(binding) != APPLY_BINDING_FIELDS:
            raise RuntimeError("unexpected APPLY binding fields")
        if binding["adapter_id"] != impl_row["adapter_id"]:
            raise RuntimeError("APPLY binding adapter id mismatch")
        if binding["binding_contract_id"] != rb["binding_contract_id"]:
            raise RuntimeError("APPLY binding contract id mismatch")
        if binding["composition_contract_path"] != authority_rel:
            raise RuntimeError("APPLY binding authority path mismatch")
        if binding["composition_contract_sha256"] != kind_row["architecture_sha256"]:
            raise RuntimeError("APPLY binding authority SHA mismatch")

        spec = importlib.util.spec_from_file_location(
            "_slp_apply_" + re.sub(r"[^A-Za-z0-9_]", "_", kind_row["parameter_kind"]),
            implementation_path,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load APPLY implementation")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for attr, expected in (
            ("ADAPTER_ID", impl_row["adapter_id"]),
            ("MECHANISM_ID", authority["mechanism_id"]),
            ("TARGET_ID", TARGET_FAMILY_ID),
        ):
            if getattr(mod, attr, None) != expected:
                raise RuntimeError(f"APPLY implementation {attr} mismatch")
        for fn in ("execute_control", "control_result_to_report"):
            if not callable(getattr(mod, fn, None)):
                raise RuntimeError(f"APPLY implementation API missing: {fn}")
        by_parameter_kind[kind_row["parameter_kind"]] = {
            "kind_row": kind_row,
            "implementation_row": impl_row,
            "authority": authority,
            "binding": binding,
            "module": mod,
            "implementation_source": implementation_path.read_bytes(),
        }
    return by_parameter_kind, sha_file(kind_path), sha_file(impl_path)


PLATFORM_MATRIX_FIELDS = ["environment_id", "os_id", "version_id", "arch", "profile", "status"]


def load_platform_matrix(repo: Path):
    path = repo / PLATFORM_MATRIX_REL
    require_regular(path, "supported platform matrix")
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        if reader.fieldnames != PLATFORM_MATRIX_FIELDS:
            raise RuntimeError(f"unexpected platform matrix fields: {reader.fieldnames!r}")
        rows = list(reader)
    if len(rows) != 7:
        raise RuntimeError(f"supported platform matrix must contain exact accepted 7 environments, got {len(rows)}")
    ids = [r["environment_id"] for r in rows]
    if len(set(ids)) != len(ids):
        raise RuntimeError("duplicate environment_id in supported platform matrix")
    expected = {
        "ubuntu-22.04-x86_64-full",
        "ubuntu-24.04-x86_64-minimized",
        "ubuntu-24.04-x86_64-full",
        "ubuntu-26.04-x86_64-minimized",
        "ubuntu-26.04-x86_64-full",
        "debian-12-x86_64-server",
        "debian-13-x86_64-server",
    }
    if set(ids) != expected:
        raise RuntimeError(f"supported platform matrix identity mismatch: {sorted(ids)!r}")
    for row in rows:
        if row["status"] != "SUPPORTED" or row["arch"] != "x86_64":
            raise RuntimeError(f"unsupported matrix row state: {row['environment_id']}")
        if row["profile"] not in {"FULL", "MINIMIZED", "SERVER"}:
            raise RuntimeError(f"invalid profile: {row['environment_id']}")
        expected_id = f"{row['os_id']}-{row['version_id']}-{row['arch']}-{row['profile'].lower()}"
        if row["environment_id"] != expected_id:
            raise RuntimeError(f"environment_id fields mismatch: {row['environment_id']}")
    return rows, sha_file(path)


DESKTOP_MATRIX_FIELDS = ["environment_id", "os_id", "version_id", "arch", "type", "status"]


def load_desktop_matrix(repo: Path):
    path = repo / DESKTOP_MATRIX_REL
    require_regular(path, "field compatibility desktop matrix")
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        if reader.fieldnames != DESKTOP_MATRIX_FIELDS:
            raise RuntimeError(f"unexpected desktop matrix fields: {reader.fieldnames!r}")
        rows = list(reader)
    if len(rows) != 1:
        raise RuntimeError(f"field compatibility desktop matrix must contain exact accepted 1 environment, got {len(rows)}")
    expected = {
        "environment_id": "ubuntu-24.04-x86_64-desktop",
        "os_id": "ubuntu",
        "version_id": "24.04",
        "arch": "x86_64",
        "type": "DESKTOP",
        "status": "FIELD_COMPATIBILITY",
    }
    if rows[0] != expected:
        raise RuntimeError(f"field compatibility desktop matrix identity mismatch: {rows[0]!r}")
    return rows, sha_file(path)


def sh_single(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def mutation_scan_view(block: str) -> str:
    # Defense-in-depth only. It catches simple quote/backslash spelling tricks
    # around known mutating commands; it is not a formal shell-language proof.
    return block.replace("'", "").replace('"', "").replace("\\", "")


def find_known_mutating_token(block: str):
    view = mutation_scan_view(block)
    for phrase in ("sysctl -w", "sysctl --write", "tee /proc/sys", "sed -i"):
        if phrase in view:
            return phrase
    m = re.search(r"(?<![A-Za-z0-9_./-])(chmod|chown|chgrp|setfacl|rm|rmdir|mv|cp|touch|truncate|dd)(?=[ \t])", view)
    return m.group(1) if m else None


def shell_function_name(control_id: str) -> str:
    return "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)


def required_display(op, value) -> str:
    """Render one short human requirement directly from control machine truth."""
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, int) and not isinstance(value, bool):
        rendered = str(value)
    elif isinstance(value, str):
        rendered = value
    else:
        raise RuntimeError(f"unsupported requirement value type: {type(value).__name__}")
    if not rendered or any(ch in rendered for ch in "\r\n\t\x00"):
        raise RuntimeError("invalid requirement display scalar")

    if op == "eq":
        return "= " + rendered
    if op == "ge":
        return ">= " + rendered
    if op == "bits-clear":
        return "bits " + rendered + " = 0"
    if op == "present":
        return "present"
    if op == "one-of":
        return "one of: " + rendered
    if op == "all-nonempty":
        return "all non-empty"
    if op == "eq-authority-file":
        return "authority: " + rendered
    if op == "eq-reviewed-policy":
        return "reviewed: " + rendered
    if op == "runtime-paths-safe":
        return "runtime paths safe"
    if op == "cron-command-paths-safe":
        return "cron command paths safe"
    if op == "root-owned-go-w-conditional":
        return "owner root if regular user; go-w if other-writable"
    if op == "subset-of-file":
        return "subset: " + rendered
    if op == "tested-before-use":
        return "tested: " + rendered
    raise RuntimeError(f"unsupported requirement op: {op!r}")


def terminal_identity(control) -> tuple[str, str]:
    """Derive compact pretty identity from canonical source machine truth."""
    control_id = str(control["control_id"])
    doc_id = str(control["doc_id"])
    locator = str(control["source_locator"])
    for value, label in ((control_id, "control_id"), (doc_id, "doc_id"), (locator, "source_locator")):
        if not value or any(ch in value for ch in "\r\n\t\x00"):
            raise RuntimeError(f"invalid terminal identity {label}")
    prefix = doc_id.upper() + "-" + locator + "-"
    if control_id.startswith(prefix):
        short = control_id[len(prefix):]
        if not short:
            raise RuntimeError("empty compact control identity")
    else:
        # Fail-safe presentation fallback for synthetic/custom IDs:
        # source still comes from machine truth; the full control_id is retained.
        short = control_id
    return f"{doc_id.lower()} §{locator}", short.lower()


def render_product_apply_dispatcher(apply_controls, apply_mechanisms) -> str:
    controls_payload = []
    used_parameter_kinds = set()
    for c in apply_controls:
        source_display, control_display = terminal_identity(c)
        controls_payload.append({
            "control_id": c["control_id"],
            "parameter_kind": c["parameter_kind"],
            "key": c["parameter_key"],
            "op": c["expected_op"],
            "expected": c["expected_value"],
            "required": required_display(c["expected_op"], c["expected_value"]),
            "source": source_display,
            "display_control": control_display,
        })
        if c["parameter_kind"] in apply_mechanisms:
            used_parameter_kinds.add(c["parameter_kind"])
    routes_payload = {}
    for parameter_kind in sorted(used_parameter_kinds, key=lambda x: x.encode("utf-8")):
        item = apply_mechanisms[parameter_kind]
        routes_payload[parameter_kind] = {
            "apply_kind": item["kind_row"]["apply_kind"],
            "mechanism_id": item["authority"]["mechanism_id"],
            "adapter_id": item["implementation_row"]["adapter_id"],
            "implementation_sha256": item["implementation_row"]["implementation_sha256"],
            "source_b64": base64.b64encode(item["implementation_source"]).decode("ascii"),
        }
    controls_json = json.dumps(controls_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    routes_json = json.dumps(routes_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    source = r'''import base64
import datetime
import fcntl
import grp
import json
import os
import stat
import sys
import tempfile
import traceback

MODE = sys.argv[1] if len(sys.argv) == 2 else ""
if MODE not in {"APPLY", "DRY_RUN"}:
    raise SystemExit(2)
DRY_RUN = MODE == "DRY_RUN"
STATE_DIR = "/var/log/securelinux-policy"
APPLY_LOG = "apply.log"
DEBUG_LOG = "debug.log"
REPORT_PATH = "report.json"
TRUSTED_UID = PARENT_TRUSTED_UID = 0
PARENT_WRITABLE_GROUPS = ("root", "syslog")
LOCK_NAME = ".lock"
LOCK_PATH = os.path.join(STATE_DIR, LOCK_NAME)
_LOCK_FD = None
_STATE_DFD = None
APPLY_CONTROLS = @@APPLY_CONTROLS_JSON@@
ROUTES = @@APPLY_ROUTES_JSON@@
COMMON = {
    "control_id", "outcome", "reason", "actions_attempted", "step_rc",
    "mutation_performed", "transaction_commit", "started_at", "finished_at",
}

def now():
    return datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat(timespec="seconds")

class StateRefused(Exception):
    pass

def _refuse(reason, detail):
    raise StateRefused(reason, detail)

def _check_parent():
    parent = os.path.dirname(STATE_DIR)
    try:
        st = os.stat(parent)
    except OSError as exc:
        _refuse("reporting:state-parent-unavailable", f"{parent}: {exc.strerror}")
    if st.st_uid != PARENT_TRUSTED_UID:
        _refuse("reporting:state-parent-owner", f"{parent} owner uid={st.st_uid}, expected {PARENT_TRUSTED_UID}")
    if st.st_mode & 0o002:
        _refuse("reporting:state-parent-mode", f"{parent} is world-writable (mode {st.st_mode & 0o7777:04o})")
    if st.st_mode & 0o020:
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = None
        if st.st_gid != 0 and group not in PARENT_WRITABLE_GROUPS:
            _refuse("reporting:state-parent-mode", f"{parent} is group-writable by gid={st.st_gid} (mode {st.st_mode & 0o7777:04o})")

def _acquire_lock(dir_st):
    # dfd остаётся открытым до конца работы (см. _STATE_DFD): все последующие
    # записи (отчёт, журналы) идут относительно него, а не по строке STATE_DIR,
    # иначе подмена каталога после проверки уходит мимо проверенного inode.
    global _LOCK_FD, _STATE_DFD
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    dfd = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    ok = False
    try:
        opened = os.fstat(dfd)
        if (opened.st_dev, opened.st_ino) != (dir_st.st_dev, dir_st.st_ino):
            _refuse("reporting:state-dir-invalid", f"{STATE_DIR} changed during validation")
        fd = os.open(LOCK_NAME, flags, 0o600, dir_fd=dfd)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != TRUSTED_UID or st.st_mode & 0o022:
            os.close(fd)
            _refuse("reporting:state-lock-invalid", f"{LOCK_PATH} is not a regular root-owned single-link file without group/other write")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            _refuse("reporting:already-running", f"another instance already running (lock {LOCK_PATH})")
        _LOCK_FD = fd
        _STATE_DFD = dfd
        ok = True
    finally:
        if not ok:
            os.close(dfd)

def ensure_state_dir():
    _check_parent()
    try:
        os.mkdir(STATE_DIR, 0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        _refuse("reporting:state-dir-unavailable", f"{STATE_DIR}: {exc.strerror}")
    st = os.lstat(STATE_DIR)
    if stat.S_ISLNK(st.st_mode):
        _refuse("reporting:state-dir-symlink", f"{STATE_DIR} is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        _refuse("reporting:state-dir-invalid", f"{STATE_DIR} is not a directory")
    if st.st_uid != TRUSTED_UID:
        _refuse("reporting:state-dir-owner", f"{STATE_DIR} owner uid={st.st_uid}, expected {TRUSTED_UID}")
    if st.st_mode & 0o022:
        _refuse("reporting:state-dir-mode", f"{STATE_DIR} is group/other-writable (mode {st.st_mode & 0o7777:04o})")
    try:
        _acquire_lock(st)
    except OSError as exc:
        _refuse("reporting:state-lock-unavailable", f"{LOCK_PATH}: {exc.strerror}")

def _mkstemp_at(dfd, prefix):
    # Аналог tempfile.mkstemp, но относительно удерживаемого дескриптора
    # каталога (dir_fd), а не по строке пути.
    for _ in range(100):
        name = prefix + os.urandom(8).hex()
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        except FileExistsError:
            continue
        return fd, name
    raise OSError("reporting:tmp-name-exhausted")

def atomic_report(payload):
    fd, tmp = _mkstemp_at(_STATE_DFD, ".report.json.")
    try:
        data = (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, REPORT_PATH, src_dir_fd=_STATE_DFD, dst_dir_fd=_STATE_DFD)
        os.fsync(_STATE_DFD)
    except Exception:
        try:
            os.unlink(tmp, dir_fd=_STATE_DFD)
        except FileNotFoundError:
            pass
        raise

def append_log(name, message):
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=_STATE_DFD)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise RuntimeError("reporting:log-target-invalid")
        os.write(fd, (f"[{now()}] {message}\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)

def ensure_log_file(name):
    flags = os.O_WRONLY | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=_STATE_DFD)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise RuntimeError("reporting:log-target-invalid")
        os.fsync(fd)
    finally:
        os.close(fd)

def load_route(meta):
    raw = base64.b64decode(meta["source_b64"], validate=True)
    if __import__("hashlib").sha256(raw).hexdigest() != meta["implementation_sha256"]:
        raise RuntimeError("routing:embedded-implementation-sha-mismatch")
    ns = {"__name__": "_slp_embedded_" + meta["mechanism_id"].replace("-", "_"), "__file__": "<embedded>"}
    exec(compile(raw, "<embedded:" + meta["mechanism_id"] + ">", "exec"), ns)
    if ns.get("MECHANISM_ID") != meta["mechanism_id"] or ns.get("ADAPTER_ID") != meta["adapter_id"]:
        raise RuntimeError("routing:embedded-implementation-identity-mismatch")
    if not callable(ns.get("execute_control")) or not callable(ns.get("control_result_to_report")):
        raise RuntimeError("routing:embedded-implementation-api-missing")
    return ns

def unavailable_record(control, started, finished):
    return {
        "control_id": control["control_id"],
        "mechanism_id": None,
        "outcome": "ABORTED_PRECONDITION_OTHER",
        "reason": "routing:mechanism-unavailable",
        "actions_attempted": ["P0_ELIGIBILITY"],
        "step_rc": "nonzero",
        "mutation_performed": False,
        "transaction_commit": "NOT_STARTED",
        "started_at": started,
        "finished_at": finished,
        "mechanism_result": {"parameter_kind": control["parameter_kind"]},
    }

def crash_record(control, meta, started, finished, exc):
    return {
        "control_id": control["control_id"],
        "mechanism_id": None if meta is None else meta["mechanism_id"],
        "outcome": "FAILED_NOT_COMMITTED",
        "reason": "mechanism:unhandled-exception",
        "actions_attempted": [],
        "step_rc": "nonzero",
        "mutation_performed": None,
        "transaction_commit": "UNKNOWN",
        "started_at": started,
        "finished_at": finished,
        "mechanism_result": {"error_type": type(exc).__name__, "error_message": str(exc)},
    }

def _terminal_scalar(value, label):
    if value is None or isinstance(value, (dict, list, tuple, set)):
        raise RuntimeError("presentation:" + label + "-invalid")
    text = str(value)
    if not text or "\n" in text or "\r" in text:
        raise RuntimeError("presentation:" + label + "-invalid")
    return text

def _compact_outcome(outcome):
    exact = _terminal_scalar(outcome, "outcome")
    mapping = {
        "ALREADY_COMPLIANT": "ok",
        "APPLIED": "done",
        "APPLIED_PARTIAL": "part",
        "DRY_RUN_WOULD_APPLY": "would",
        "ABORTED_PRECONDITION_CONFLICT": "block",
        "ABORTED_PRECONDITION_OTHER": "abort",
        "FAILED_NOT_COMMITTED": "fail",
        "FAILED_COMPENSATION": "fail",
    }
    return mapping.get(exact, exact.lower())

def _table_chunks(value, width, label):
    text = _terminal_scalar(value, label) if value != "" else ""
    if not text:
        return [""]
    return [text[i:i + width] for i in range(0, len(text), width)]

def _terminal_columns():
    try:
        cols = os.get_terminal_size(sys.stdout.fileno()).columns
    except (OSError, ValueError):
        return 116
    if not isinstance(cols, int) or cols < 40 or cols > 1000:
        return 116
    return cols

PRETTY_COLUMNS = _terminal_columns()
PRETTY_IS_TTY = sys.stdout.isatty()
BLOCKS = []

def _terminal_layout(columns=None):
    if columns is None and not PRETTY_IS_TTY:
        columns = 116
    cols = PRETTY_COLUMNS if columns is None else columns
    if cols < 90:
        return ("vertical", cols, (8, cols - 14))
    if cols < 100:
        wsrc, wc, req_min = 18, 24, 10
    elif cols < 110:
        wsrc, wc, req_min = 22, 28, 12
    elif cols < 120:
        wsrc, wc, req_min = 24, 32, 14
    else:
        wsrc, wc, req_min = 24, 36, 16
    ws = 5
    available = cols - 15
    remaining = available - ws - wsrc - wc
    if remaining <= req_min:
        raise RuntimeError("presentation:terminal-width-invalid")
    wcur_base = min(43, remaining - req_min)
    # current отдаёт required 10 символов, но не становится уже 12.
    wcur = max(min(12, wcur_base), wcur_base - 10)
    wreq = remaining - wcur
    return ("table", cols, (ws, wsrc, wc, wcur, wreq))

def _emit_vertical_field(label, value, widths):
    wfield, wvalue = widths
    chunks = _table_chunks(value, wvalue, label) if value else [""]
    for i, chunk in enumerate(chunks):
        field = label if i == 0 else ""
        print(f" {field:<{wfield}} | {chunk:<{wvalue}} |")

def _emit_table_row(st, source, control, current, required):
    mode, _cols, widths = _terminal_layout()
    if mode == "vertical":
        if st == "st" and source == "source" and control == "control":
            wfield, wvalue = widths
            print(f" {'field':<{wfield}} | {'value':<{wvalue}} |")
            return
        _emit_vertical_field("st", st, widths)
        _emit_vertical_field("source", source, widths)
        _emit_vertical_field("control", control, widths)
        _emit_vertical_field("current", current, widths)
        _emit_vertical_field("required", required, widths)
        return
    ws, wsrc, wc, wcur, wreq = widths
    values = (st, source, control, current, required)
    labels = ("st", "source", "display-control", "current", "required")
    chunks = [_table_chunks(value, width, label) for value, width, label in zip(values, widths, labels)]
    rows = max(len(item) for item in chunks)
    for i in range(rows):
        parts = [item[i] if i < len(item) else "" for item in chunks]
        print(
            f" {parts[0]:<{ws}} | {parts[1]:<{wsrc}} | {parts[2]:<{wc}} | "
            f"{parts[3]:<{wcur}} | {parts[4]:<{wreq}} |"
        )

def _emit_separator():
    mode, _cols, widths = _terminal_layout()
    if mode == "vertical":
        wfield, wvalue = widths
        print("-" * (wfield + 2) + "+" + "-" * (wvalue + 2) + "+")
        return
    ws, wsrc, wc, wcur, wreq = widths
    print(
        "-" * (ws + 2) + "+"
        + "-" * (wsrc + 2) + "+"
        + "-" * (wc + 2) + "+"
        + "-" * (wcur + 2) + "+"
        + "-" * (wreq + 2) + "+"
    )

def _current_display(record):
    mechanism_result = record.get("mechanism_result")
    if not isinstance(mechanism_result, dict):
        return "not-determined"
    # sysctl отдаёт runtime_*, режимы файлов — resulting_mode/current_mode.
    for field in ("runtime_after", "runtime_before", "resulting_mode", "current_mode"):
        value = mechanism_result.get(field)
        if value is not None:
            return _terminal_scalar(value, "current")
    return "not-determined"

def _block_entry(record, control):
    if record.get("outcome") != "ABORTED_PRECONDITION_CONFLICT":
        return None
    if record.get("step_rc") == "0" or record.get("mutation_performed") is not False:
        raise RuntimeError("presentation:block-invariant")
    record_id = _terminal_scalar(record.get("control_id"), "control-id")
    control_id = _terminal_scalar(control.get("control_id"), "control-id")
    if record_id != control_id:
        raise RuntimeError("presentation:control-id-mismatch")
    display_control = _block_control_label(control)
    detail = _terminal_scalar(record.get("reason"), "reason")
    notes = []
    mechanism_result = record.get("mechanism_result")
    if not isinstance(mechanism_result, dict):
        raise RuntimeError("presentation:block-mechanism-result-invalid")
    decision = mechanism_result.get("operator_decision")
    if decision is not None:
        if not isinstance(decision, dict):
            raise RuntimeError("presentation:operator-decision-invalid")
        if decision.get("class") != "SERVICE_MANAGED_PARAMETER" or decision.get("required") is not True:
            raise RuntimeError("presentation:operator-decision-invalid")
        service = _terminal_scalar(decision.get("service"), "service")
        parameter = _terminal_scalar(decision.get("parameter"), "parameter")
        current_value = _terminal_scalar(decision.get("current_value"), "current-value")
        notes.append(
            f"{parameter}={current_value}: обнаружен штатный механизм {service}, управляющий этим параметром."
        )
        notes.append("Автоматическое изменение пропущено. Требуется решение администратора.")
    return {"control": display_control, "detail": detail, "notes": notes}

def _block_control_label(control):
    source = _terminal_scalar(control.get("source"), "source")
    if "§" not in source:
        raise RuntimeError("presentation:block-locator-missing")
    display_control = _terminal_scalar(control.get("display_control"), "display-control")
    return "§" + source.rsplit("§", 1)[1] + " " + display_control

def _blocks_layout():
    cols = PRETTY_COLUMNS if PRETTY_IS_TTY else 116
    wtype = 6
    need = max((len(_block_control_label(c)) for c in APPLY_CONTROLS), default=12)
    wcontrol = min(max(12, need), max(12, cols // 3))
    wmessage = cols - 9 - wcontrol - wtype
    if wmessage < 12:
        raise RuntimeError("presentation:blocks-terminal-width-invalid")
    return cols, (wcontrol, wtype, wmessage)

def _emit_blocks_row(control, kind, message):
    _cols, widths = _blocks_layout()
    wcontrol, wtype, wmessage = widths
    control_chunks = _table_chunks(control, wcontrol, "block-control")
    kind_chunks = _table_chunks(kind, wtype, "block-type")
    message_chunks = _table_chunks(message, wmessage, "block-message")
    rows = max(len(control_chunks), len(kind_chunks), len(message_chunks))
    for i in range(rows):
        c = control_chunks[i] if i < len(control_chunks) else ""
        k = kind_chunks[i] if i < len(kind_chunks) else ""
        m = message_chunks[i] if i < len(message_chunks) else ""
        print(f" {c:<{wcontrol}} | {k:<{wtype}} | {m:<{wmessage}} |")

def _emit_blocks_separator():
    _cols, widths = _blocks_layout()
    wcontrol, wtype, wmessage = widths
    print(
        "-" * (wcontrol + 2) + "+"
        + "-" * (wtype + 2) + "+"
        + "-" * (wmessage + 2) + "+"
    )

def emit_blocks():
    if not BLOCKS:
        return
    print("blocks")
    _emit_blocks_row("control", "type", "message")
    _emit_blocks_separator()
    for entry in BLOCKS:
        _emit_blocks_row(entry["control"], "detail", entry["detail"])
        for note in entry["notes"]:
            _emit_blocks_row("", "note", note)
    _emit_blocks_separator()

def emit_control_result(record, control):
    control_id = _terminal_scalar(record.get("control_id"), "control-id")
    if control_id != _terminal_scalar(control.get("control_id"), "control-id"):
        raise RuntimeError("presentation:control-id-mismatch")
    outcome = _compact_outcome(record.get("outcome"))
    source = _terminal_scalar(control.get("source"), "source")
    display_control = _terminal_scalar(control.get("display_control"), "display-control")
    current = _current_display(record)
    required = _terminal_scalar(control.get("required"), "required")
    _emit_table_row(outcome, source, display_control, current, required)
    block = _block_entry(record, control)
    if block is not None:
        BLOCKS.append(block)

def emit_summary(payload):
    controls = payload.get("controls")
    if not isinstance(controls, list):
        raise RuntimeError("presentation:controls-invalid")
    counts = {}
    for record in controls:
        if not isinstance(record, dict):
            raise RuntimeError("presentation:record-invalid")
        outcome = _terminal_scalar(record.get("outcome"), "outcome")
        counts[outcome] = counts.get(outcome, 0) + 1
    parts = [f"{name}={counts[name]}" for name in sorted(counts)]
    rc_text = "0" if payload.get("rc_zero") is True else "NONZERO"
    middle = (" " + " ".join(parts)) if parts else ""
    print(f"TOTAL={len(controls)}{middle} RC={rc_text}")

started_at = now()
payload = {
    "schema": "SLP-APPLY-REPORT-V2",
    "dry_run": DRY_RUN,
    "apply_kinds": sorted({meta["apply_kind"] for meta in ROUTES.values()}),
    "apply_control_count": len(APPLY_CONTROLS),
    "started_at": started_at,
    "finished_at": None,
    "complete": False,
    "rc_zero": None,
    "run_error": None,
    "controls": [],
}
try:
    ensure_state_dir()
except StateRefused as exc:
    print(f"REFUSED {exc.args[0]}: {exc.args[1]}", file=sys.stderr)
    raise SystemExit(1)
atomic_report(payload)
try:
    ensure_log_file(APPLY_LOG)
    ensure_log_file(DEBUG_LOG)
    append_log(APPLY_LOG, f"product apply start dry_run={str(DRY_RUN).lower()} controls={len(APPLY_CONTROLS)}")
    print(f"MODE={MODE} APPLY_CONTROLS={len(APPLY_CONTROLS)}")
    _emit_table_row("st", "source", "control", "current", "required")
    _emit_separator()
    loaded = {}
    for control in APPLY_CONTROLS:
        c_started = now()
        meta = ROUTES.get(control["parameter_kind"])
        if meta is None:
            record = unavailable_record(control, c_started, now())
        else:
            try:
                ns = loaded.get(control["parameter_kind"])
                if ns is None:
                    ns = load_route(meta)
                    loaded[control["parameter_kind"]] = ns
                append_log(APPLY_LOG, f"control start {control['control_id']} mechanism={meta['mechanism_id']}")
                result = ns["execute_control"](
                    control["control_id"], control["key"], control["op"], control["expected"], True,
                    dry_run=DRY_RUN,
                )
                c_finished = now()
                raw = ns["control_result_to_report"](result, c_started, c_finished)
                mechanism_result = {k: v for k, v in raw.items() if k not in COMMON}
                record = {
                    "control_id": raw["control_id"],
                    "mechanism_id": meta["mechanism_id"],
                    "outcome": raw["outcome"],
                    "reason": raw["reason"],
                    "actions_attempted": raw["actions_attempted"],
                    "step_rc": raw["step_rc"],
                    "mutation_performed": raw["mutation_performed"],
                    "transaction_commit": raw["transaction_commit"],
                    "started_at": raw["started_at"],
                    "finished_at": raw["finished_at"],
                    "mechanism_result": mechanism_result,
                }
            except BaseException as exc:
                c_finished = now()
                append_log(DEBUG_LOG, traceback.format_exc().rstrip())
                record = crash_record(control, meta, c_started, c_finished, exc)
        payload["controls"].append(record)
        atomic_report(payload)
        emit_control_result(record, control)
        append_log(APPLY_LOG, f"control finish {control['control_id']} outcome={record['outcome']} step_rc={record['step_rc']}")
    payload["finished_at"] = now()
    payload["complete"] = True
    payload["rc_zero"] = all(item["step_rc"] == "0" for item in payload["controls"])
    atomic_report(payload)
    append_log(APPLY_LOG, f"product apply finish rc_zero={str(payload['rc_zero']).lower()}")
    _emit_separator()
    emit_blocks()
    emit_summary(payload)
    raise SystemExit(0 if payload["rc_zero"] else 1)
except SystemExit:
    raise
except BaseException as exc:
    payload["run_error"] = {"type": type(exc).__name__, "message": str(exc), "phase": "product-dispatch"}
    payload["finished_at"] = now()
    payload["complete"] = False
    payload["rc_zero"] = False
    try:
        atomic_report(payload)
        append_log(DEBUG_LOG, traceback.format_exc().rstrip())
    except Exception:
        pass
    raise
'''
    return source.replace("@@APPLY_CONTROLS_JSON@@", controls_json).replace("@@APPLY_ROUTES_JSON@@", routes_json)


def render_script(
    controls,
    adapters,
    manifest_sha: str,
    registry_sha: str,
    generator_sha: str,
    platform_rows=None,
    platform_matrix_sha: str | None = None,
    desktop_rows=None,
    desktop_matrix_sha: str | None = None,
    apply_mechanisms=None,
    apply_kind_registry_sha: str | None = None,
    apply_registry_sha: str | None = None,
    apply_controls=None,
) -> bytes:
    if platform_rows is None or platform_matrix_sha is None or desktop_rows is None or desktop_matrix_sha is None:
        repo = Path(__file__).resolve(strict=True).parents[1]
        platform_rows, platform_matrix_sha = load_platform_matrix(repo)
        desktop_rows, desktop_matrix_sha = load_desktop_matrix(repo)
    if apply_mechanisms is None or apply_kind_registry_sha is None or apply_registry_sha is None or apply_controls is None:
        repo = Path(__file__).resolve(strict=True).parents[1]
        apply_mechanisms, apply_kind_registry_sha, apply_registry_sha = load_apply_mechanisms(repo)
        current_rows, _current_manifest_sha = load_manifest(repo)
        current_controls = [load_control(repo, row) for row in current_rows]
        apply_controls = [item for item in current_controls if item["apply_supported"]]
    blocks = []
    function_names = []
    function_owners = {}
    provenance_lines = []

    for c in controls:
        kind = c["parameter_kind"]
        if kind not in adapters:
            raise RuntimeError(f"no registered adapter for parameter.kind={kind!r}")
        a = adapters[kind]
        mod = a["module"]
        block = mod.shell_function(
            c["control_id"],
            c["parameter_locator"],
            c["parameter_key"],
            c["expected_op"],
            c["expected_value"],
        )
        if not isinstance(block, str) or not block.endswith("\n"):
            raise RuntimeError(f"adapter returned invalid shell block: {c['control_id']}")
        mutating = find_known_mutating_token(block)
        if mutating is not None:
            raise RuntimeError(f"mutating token {mutating!r} emitted for {c['control_id']}")
        fn_name = shell_function_name(c["control_id"])
        previous = function_owners.get(fn_name)
        if previous is not None and previous != c["control_id"]:
            raise RuntimeError(
                f"shell function name collision: {previous!r} and {c['control_id']!r} -> {fn_name!r}"
            )
        function_owners[fn_name] = c["control_id"]
        blocks.append(block.rstrip("\n"))
        function_names.append(fn_name)

        row = a["row"]
        prov = {
            "adapter_contract_sha256": row["adapter_contract_sha256"],
            "adapter_id": row["adapter_id"],
            "adapter_implementation_sha256": row["implementation_sha256"],
            "control_id": c["control_id"],
            "control_manifest_sha256": manifest_sha,
            "control_sha256": c["control_sha256"],
            "doc_id": c["doc_id"],
            "doc_sha256": c["doc_sha256"],
            "expected_op": c["expected_op"],
            "expected_type": c["expected_type"],
            "expected_value": c["expected_value"],
            "index_id": c["index_id"],
            "parameter_key": c["parameter_key"],
            "parameter_kind": kind,
            "parameter_locator": c["parameter_locator"],
            "product_status": PRODUCT_STATUS,
            "quote_sha256": c["quote_sha256"],
            "registry_sha256": registry_sha,
            "semantic_contract_sha256": row["semantic_contract_sha256"],
            "source_locator": c["source_locator"],
            "target_id": TARGET_FAMILY_ID,
        }
        if c["apply_supported"]:
            route = apply_mechanisms.get(kind)
            if route is None:
                prov["apply"] = {
                    "route_status": "UNAVAILABLE",
                    "parameter_kind": kind,
                    "control_id": c["control_id"],
                }
            else:
                kind_row = route["kind_row"]
                impl_row = route["implementation_row"]
                prov["apply"] = {
                    "route_status": "BOUND",
                    "parameter_kind": kind,
                    "apply_kind": kind_row["apply_kind"],
                    "mechanism_id": route["authority"]["mechanism_id"],
                    "authority_form": kind_row["authority_form"],
                    "authority_sha256": kind_row["architecture_sha256"],
                    "adapter_id": impl_row["adapter_id"],
                    "implementation_sha256": impl_row["implementation_sha256"],
                    "control_id": c["control_id"],
                }
        provenance_lines.append(
            json.dumps(prov, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        )

    apply_dispatcher = render_product_apply_dispatcher(apply_controls, apply_mechanisms)
    active_apply_kinds = sorted(
        {item["kind_row"]["apply_kind"] for item in apply_mechanisms.values()},
        key=lambda x: x.encode("utf-8"),
    )
    apply_kinds_text = ",".join(active_apply_kinds)

    prov_all = "\n".join(provenance_lines)
    prov_cases = []
    for c, line in zip(controls, provenance_lines):
        prov_cases.append(
            "    "
            + sh_single(c["control_id"])
            + ") printf '%s\\n' "
            + sh_single(line)
            + " ;;"
        )
    fn_words = " ".join(sh_single(x) for x in function_names)
    cid_words = " ".join(sh_single(c["control_id"]) for c in controls)
    presentation_cases = []
    for c in controls:
        source_display, control_display = terminal_identity(c)
        payload = source_display + "\t" + control_display + "\t" + required_display(c["expected_op"], c["expected_value"])
        presentation_cases.append(
            "    " + sh_single(c["control_id"]) + ") printf '%s' " + sh_single(payload) + " ;;"
        )
    supported_cases = "|".join(sh_single(r["environment_id"]) for r in (platform_rows + desktop_rows)) + ") ;;"

    template = r'''#!/bin/bash -p
# SecureLinux-Policy unified product CLI
# STATUS=@@PRODUCT_STATUS@@
# PRODUCT_CLI=@@PRODUCT_CLI_ID@@
# GENERATOR_ID=@@GENERATOR_ID@@
# GENERATOR_SHA256=@@GENERATOR_SHA@@
# CONTROL_MANIFEST_SHA256=@@MANIFEST_SHA@@
# ADAPTER_REGISTRY_SHA256=@@REGISTRY_SHA@@
# APPLY_KINDS=@@APPLY_KINDS@@
# APPLY_CONTROL_COUNT=@@APPLY_CONTROL_COUNT@@
# APPLY_KIND_REGISTRY_SHA256=@@APPLY_KIND_REGISTRY_SHA@@
# APPLY_IMPLEMENTATION_REGISTRY_SHA256=@@APPLY_REGISTRY_SHA@@
# TARGET_FAMILY_ID=@@TARGET_FAMILY_ID@@
# PLATFORM_MATRIX_SHA256=@@PLATFORM_MATRIX_SHA@@
# DESKTOP_MATRIX_SHA256=@@DESKTOP_MATRIX_SHA@@

set -u

@@BLOCKS@@

SLP_SYSTEM_ID=''
SLP_SYSTEM_VERSION_ID=''
SLP_SYSTEM_PRETTY_NAME=''
SLP_SYSTEM_ARCH=''
SLP_SYSTEM_PROFILE=''
SLP_SYSTEM_TYPE=''
SLP_SYSTEM_PLATFORM=''
SLP_SYSTEM_ENVIRONMENT=''
SLP_CLASSIFY_REASON=''

slp_classify_dpkg_status() {
  local _slp_out=$1 _slp_want='' _slp_eflag='' _slp_status='' _slp_extra=''
  [[ $_slp_out != *$'\n'* && $_slp_out != *$'\r'* ]] || return 1
  IFS=' ' read -r _slp_want _slp_eflag _slp_status _slp_extra <<< "$_slp_out"
  [[ -n $_slp_want && -n $_slp_eflag && -n $_slp_status && -z $_slp_extra ]] || return 1
  case "$_slp_want" in
    unknown|install|hold|deinstall|purge) ;;
    *) return 1 ;;
  esac
  [[ $_slp_eflag == ok ]] || return 1
  case "$_slp_status" in
    installed) printf '%s' installed ;;
    not-installed|config-files) printf '%s' absent ;;
    *) return 1 ;;
  esac
}

slp_dpkg_package_state() {
  local _slp_pkg=$1 _slp_out='' _slp_rc=0
  [[ -x /usr/bin/dpkg-query ]] || return 1
  _slp_out=$(LC_ALL=C command /usr/bin/dpkg-query --root=/ --admindir=/var/lib/dpkg -W -f='${Status}' -- "$_slp_pkg" 2>/dev/null)
  _slp_rc=$?
  if (( _slp_rc == 0 )); then
    slp_classify_dpkg_status "$_slp_out"
    return $?
  fi
  if (( _slp_rc == 1 )); then
    printf '%s' absent
    return 0
  fi
  return 1
}

slp_classify_environment() {
  local _slp_id=$1 _slp_version=$2 _slp_arch=$3
  local _slp_server_minimal=$4 _slp_ubuntu_minimal=$5 _slp_ubuntu_standard=$6
  local _slp_profile='' _slp_type='' _slp_platform='' _slp_environment=''
  SLP_CLASSIFY_REASON=''
  SLP_SYSTEM_ID=$_slp_id
  SLP_SYSTEM_VERSION_ID=$_slp_version
  SLP_SYSTEM_ARCH=$_slp_arch
  SLP_SYSTEM_PROFILE=''
  SLP_SYSTEM_TYPE=''
  SLP_SYSTEM_PLATFORM=''
  SLP_SYSTEM_ENVIRONMENT=''
  if [[ $_slp_arch != x86_64 ]]; then
    SLP_CLASSIFY_REASON=PLATFORM
    return 3
  fi
  _slp_platform="$_slp_id-$_slp_version-$_slp_arch"
  case "$_slp_id:$_slp_version" in
    ubuntu:22.04|ubuntu:24.04|ubuntu:26.04)
      SLP_SYSTEM_PLATFORM=$_slp_platform
      if [[ $_slp_server_minimal == installed ]]; then
        if [[ $_slp_ubuntu_minimal == installed && $_slp_ubuntu_standard == installed ]]; then
          _slp_profile=FULL
        elif [[ $_slp_ubuntu_minimal == absent && $_slp_ubuntu_standard == absent ]]; then
          _slp_profile=MINIMIZED
        else
          SLP_SYSTEM_PROFILE=UNKNOWN
          SLP_CLASSIFY_REASON=PROFILE
          return 3
        fi
      elif [[ $_slp_server_minimal == absent && $_slp_ubuntu_minimal == installed && $_slp_ubuntu_standard == installed ]]; then
        if [[ $_slp_version == 24.04 ]]; then
          _slp_type=DESKTOP
        else
          SLP_SYSTEM_TYPE=UNKNOWN
          SLP_CLASSIFY_REASON=TYPE
          return 3
        fi
      else
        SLP_SYSTEM_TYPE=UNKNOWN
        SLP_CLASSIFY_REASON=TYPE
        return 3
      fi
      ;;
    debian:12|debian:13)
      _slp_profile=SERVER
      ;;
    *)
      SLP_CLASSIFY_REASON=PLATFORM
      return 3
      ;;
  esac
  if [[ -n $_slp_type ]]; then
    _slp_environment="$_slp_platform-${_slp_type,,}"
  else
    _slp_environment="$_slp_platform-${_slp_profile,,}"
  fi
  case "$_slp_environment" in
    @@SUPPORTED_CASES@@
    *)
      if [[ -n $_slp_type ]]; then
        SLP_SYSTEM_TYPE=UNKNOWN
        SLP_CLASSIFY_REASON=TYPE
      else
        SLP_SYSTEM_PROFILE=UNKNOWN
        SLP_CLASSIFY_REASON=PROFILE
      fi
      SLP_SYSTEM_PLATFORM=$_slp_platform
      return 3
      ;;
  esac
  SLP_SYSTEM_PROFILE=$_slp_profile
  SLP_SYSTEM_TYPE=$_slp_type
  SLP_SYSTEM_PLATFORM=$_slp_platform
  SLP_SYSTEM_ENVIRONMENT=$_slp_environment
  return 0
}

slp_preflight_validate_text_bytes() {
  local _slp_v_path=$1 _slp_v_hex _slp_v_byte _slp_v_n=0
  local _slp_v_need=0 _slp_v_min=128 _slp_v_max=191
  if ! _slp_v_hex=$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null); then return 2; fi
  for _slp_v_byte in $_slp_v_hex; do
    [[ $_slp_v_byte =~ ^[0-9a-f][0-9a-f]$ ]] || return 1
    case "$_slp_v_byte" in
      00|01|02|03|04|05|06|07|08|09|0b|0c|0d|0e|0f|10|11|12|13|14|15|16|17|18|19|1a|1b|1c|1d|1e|1f) return 1 ;;
    esac
    _slp_v_n=$((16#$_slp_v_byte))
    if (( _slp_v_need > 0 )); then
      (( _slp_v_n >= _slp_v_min && _slp_v_n <= _slp_v_max )) || return 1
      ((_slp_v_need-=1))
      _slp_v_min=128 _slp_v_max=191
      continue
    fi
    if (( _slp_v_n <= 127 )); then
      continue
    elif (( _slp_v_n >= 194 && _slp_v_n <= 223 )); then
      _slp_v_need=1
    elif (( _slp_v_n == 224 )); then
      _slp_v_need=2 _slp_v_min=160
    elif (( (_slp_v_n >= 225 && _slp_v_n <= 236) || (_slp_v_n >= 238 && _slp_v_n <= 239) )); then
      _slp_v_need=2
    elif (( _slp_v_n == 237 )); then
      _slp_v_need=2 _slp_v_max=159
    elif (( _slp_v_n == 240 )); then
      _slp_v_need=3 _slp_v_min=144
    elif (( _slp_v_n >= 241 && _slp_v_n <= 243 )); then
      _slp_v_need=3
    elif (( _slp_v_n == 244 )); then
      _slp_v_need=3 _slp_v_max=143
    else
      return 1
    fi
  done
  (( _slp_v_need == 0 )) || return 1
  return 0
}

SLP_OS_RELEASE_VALUE=''
SLP_OS_RELEASE_ID=''
SLP_OS_RELEASE_VERSION_ID=''
SLP_OS_RELEASE_PRETTY_NAME=''

slp_parse_os_release_value() {
  local LC_ALL=C
  local _slp_in=$1 _slp_mode=unquoted _slp_body='' _slp_out='' _slp_ch='' _slp_next=''
  local _slp_len=${#1}
  SLP_OS_RELEASE_VALUE=''
  if (( _slp_len > 0 )) && [[ ${_slp_in:0:1} == '"' ]]; then
    (( _slp_len >= 2 )) || return 1
    [[ ${_slp_in: -1} == '"' ]] || return 1
    _slp_mode=double
    _slp_body=${_slp_in:1:_slp_len-2}
  elif (( _slp_len > 0 )) && [[ ${_slp_in:0:1} == "'" ]]; then
    (( _slp_len >= 2 )) || return 1
    [[ ${_slp_in: -1} == "'" ]] || return 1
    _slp_mode=single
    _slp_body=${_slp_in:1:_slp_len-2}
  else
    _slp_body=$_slp_in
  fi
  if [[ $_slp_mode == single ]]; then
    [[ $_slp_body != *"'"* ]] || return 1
    SLP_OS_RELEASE_VALUE=$_slp_body
    return 0
  fi
  while [[ -n $_slp_body ]]; do
    _slp_ch=${_slp_body:0:1}
    _slp_body=${_slp_body:1}
    if [[ $_slp_ch == '\' ]]; then
      [[ -n $_slp_body ]] || return 1
      _slp_next=${_slp_body:0:1}
      if [[ $_slp_mode == double ]]; then
        case "$_slp_next" in
          '$'|'`'|'"'|'\') _slp_out+=$_slp_next; _slp_body=${_slp_body:1} ;;
          *) _slp_out+='\' ;;
        esac
      else
        _slp_out+=$_slp_next
        _slp_body=${_slp_body:1}
      fi
      continue
    fi
    if [[ $_slp_mode == double ]]; then
      case "$_slp_ch" in
        '"'|'$'|'`') return 1 ;;
      esac
    else
      case "$_slp_ch" in
        "'"|'"'|'$'|'`'|' '|$'\t'|';') return 1 ;;
      esac
    fi
    _slp_out+=$_slp_ch
  done
  SLP_OS_RELEASE_VALUE=$_slp_out
  return 0
}

slp_parse_os_release_file() {
  local _slp_p_path=$1 _slp_p_line='' _slp_p_key='' _slp_p_raw=''
  SLP_OS_RELEASE_ID=''
  SLP_OS_RELEASE_VERSION_ID=''
  SLP_OS_RELEASE_PRETTY_NAME=''
  while IFS= read -r _slp_p_line || [[ -n $_slp_p_line ]]; do
    [[ $_slp_p_line == *=* ]] || continue
    _slp_p_key=${_slp_p_line%%=*}
    case "$_slp_p_key" in
      ID|VERSION_ID|PRETTY_NAME)
        _slp_p_raw=${_slp_p_line#*=}
        slp_parse_os_release_value "$_slp_p_raw" || return 1
        case "$_slp_p_key" in
          ID) SLP_OS_RELEASE_ID=$SLP_OS_RELEASE_VALUE ;;
          VERSION_ID) SLP_OS_RELEASE_VERSION_ID=$SLP_OS_RELEASE_VALUE ;;
          PRETTY_NAME) SLP_OS_RELEASE_PRETTY_NAME=$SLP_OS_RELEASE_VALUE ;;
        esac
        ;;
    esac
  done < "$_slp_p_path"
  return 0
}

slp_target_preflight() {
  local _slp_id='' _slp_version='' _slp_pretty='' _slp_arch='' _slp_k _slp_v _slp_vrc=0
  local _slp_server_minimal=na _slp_ubuntu_minimal=na _slp_ubuntu_standard=na
  if [[ ! -r /etc/os-release ]]; then
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  fi
  slp_preflight_validate_text_bytes /etc/os-release; _slp_vrc=$?
  if (( _slp_vrc != 0 )); then
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  fi
  slp_parse_os_release_file /etc/os-release || {
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  }
  _slp_id=$SLP_OS_RELEASE_ID
  _slp_version=$SLP_OS_RELEASE_VERSION_ID
  _slp_pretty=$SLP_OS_RELEASE_PRETTY_NAME
  _slp_arch=$(command /usr/bin/uname -m 2>/dev/null) || {
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  }
  case "$_slp_id:$_slp_version:$_slp_arch" in
    ubuntu:22.04:x86_64|ubuntu:24.04:x86_64|ubuntu:26.04:x86_64|debian:12:x86_64|debian:13:x86_64) ;;
    *)
      printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
      return 3
      ;;
  esac
  if [[ $_slp_id == ubuntu ]]; then
    _slp_server_minimal=$(slp_dpkg_package_state ubuntu-server-minimal) || {
      printf '%s\n' 'UNSUPPORTED_PROFILE' >&2
      return 3
    }
    _slp_ubuntu_minimal=$(slp_dpkg_package_state ubuntu-minimal) || {
      printf '%s\n' 'UNSUPPORTED_PROFILE' >&2
      return 3
    }
    _slp_ubuntu_standard=$(slp_dpkg_package_state ubuntu-standard) || {
      printf '%s\n' 'UNSUPPORTED_PROFILE' >&2
      return 3
    }
  fi
  slp_classify_environment "$_slp_id" "$_slp_version" "$_slp_arch" \
    "$_slp_server_minimal" "$_slp_ubuntu_minimal" "$_slp_ubuntu_standard" || {
    case "$SLP_CLASSIFY_REASON" in
      PROFILE) printf '%s\n' 'UNSUPPORTED_PROFILE' >&2 ;;
      TYPE) printf '%s\n' 'UNSUPPORTED_TYPE' >&2 ;;
      *) printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2 ;;
    esac
    return 3
  }
  [[ -n $_slp_pretty ]] || _slp_pretty="$_slp_id $_slp_version"
  SLP_SYSTEM_PRETTY_NAME=$_slp_pretty
  return 0
}

slp_provenance_all() {
  command /usr/bin/cat <<'SLP_PROVENANCE_EOF'
@@PROV_ALL@@
SLP_PROVENANCE_EOF
}

slp_provenance_one() {
  case "$1" in
@@PROV_CASES@@
    *) return 2 ;;
  esac
}

slp_build_info() {
  printf '%s\n' \
    'STATUS=@@PRODUCT_STATUS@@' \
    'PRODUCT_CLI=@@PRODUCT_CLI_ID@@' \
    'GENERATOR_ID=@@GENERATOR_ID@@' \
    'GENERATOR_SHA256=@@GENERATOR_SHA@@' \
    'CONTROL_COUNT=@@CONTROL_COUNT@@' \
    'CONTROL_MANIFEST_SHA256=@@MANIFEST_SHA@@' \
    'ADAPTER_COUNT=@@ADAPTER_COUNT@@' \
    'ADAPTER_REGISTRY_SHA256=@@REGISTRY_SHA@@' \
    'APPLY_KINDS=@@APPLY_KINDS@@' \
    'APPLY_CONTROL_COUNT=@@APPLY_CONTROL_COUNT@@' \
    'APPLY_IMPLEMENTATION_COUNT=@@APPLY_IMPLEMENTATION_COUNT@@' \
    'APPLY_KIND_REGISTRY_SHA256=@@APPLY_KIND_REGISTRY_SHA@@' \
    'APPLY_IMPLEMENTATION_REGISTRY_SHA256=@@APPLY_REGISTRY_SHA@@' \
    'TARGET_FAMILY_ID=@@TARGET_FAMILY_ID@@' \
    'SUPPORTED_PROFILE_ENVIRONMENTS=@@SUPPORTED_PROFILE_COUNT@@' \
    'FIELD_COMPATIBILITY_ENVIRONMENTS=@@SUPPORTED_DESKTOP_COUNT@@' \
    'SUPPORTED_ENVIRONMENTS=@@SUPPORTED_COUNT@@' \
    'PLATFORM_MATRIX_SHA256=@@PLATFORM_MATRIX_SHA@@' \
    'DESKTOP_MATRIX_SHA256=@@DESKTOP_MATRIX_SHA@@'
}

slp_help() {
  command /usr/bin/cat <<'SLP_HELP_EOF'
SecureLinux-Policy — единый product CLI

Использование:
  ./securelinux-policy.sh --check [--failed] [--format pretty|raw|json]
  ./securelinux-policy.sh --report
  ./securelinux-policy.sh --build-info
  ./securelinux-policy.sh --provenance [CONTROL_ID]
  ./securelinux-policy.sh --version
  ./securelinux-policy.sh --help
  ./securelinux-policy.sh --apply
  ./securelinux-policy.sh --apply --dry-run

Режимы:
  --check               read-only проверка текущих canonical controls
  --check --failed      показать только FAIL и ERROR
  --format pretty       выровненная таблица для человека (по умолчанию)
  --format raw          стабильный SLP-CHECK-V1 TSV для автоматизации
  --format json         структурированный JSON-отчёт
  --report              краткая сводка + FAIL/ERROR
  --build-info          metadata сборки
  --provenance          provenance всех controls или одного CONTROL_ID
  --version             версия product CLI
  --apply               применить все controls с apply.supported=true
  --apply --dry-run     выполнить те же наблюдения и расчёт без target-мутаций

Без аргументов печатается эта справка. CHECK не изменяет состояние хоста.
SLP_HELP_EOF
}

slp_version() {
  printf '%s\n' \
    'PRODUCT=SecureLinux-Policy-v3' \
    'PRODUCT_CLI=@@PRODUCT_CLI_ID@@' \
    'STATUS=@@PRODUCT_STATUS@@' \
    'CONTROL_COUNT=@@CONTROL_COUNT@@' \
    'TARGET_FAMILY_ID=@@TARGET_FAMILY_ID@@'
}

slp_json_escape() {
  local _slp_s=$1
  _slp_s=${_slp_s//\\/\\\\}
  _slp_s=${_slp_s//\"/\\\"}
  _slp_s=${_slp_s//$'\x01'/\\u0001}
  _slp_s=${_slp_s//$'\x02'/\\u0002}
  _slp_s=${_slp_s//$'\x03'/\\u0003}
  _slp_s=${_slp_s//$'\x04'/\\u0004}
  _slp_s=${_slp_s//$'\x05'/\\u0005}
  _slp_s=${_slp_s//$'\x06'/\\u0006}
  _slp_s=${_slp_s//$'\x07'/\\u0007}
  _slp_s=${_slp_s//$'\x08'/\\b}
  _slp_s=${_slp_s//$'\t'/\\t}
  _slp_s=${_slp_s//$'\n'/\\n}
  _slp_s=${_slp_s//$'\x0b'/\\u000b}
  _slp_s=${_slp_s//$'\x0c'/\\f}
  _slp_s=${_slp_s//$'\r'/\\r}
  _slp_s=${_slp_s//$'\x0e'/\\u000e}
  _slp_s=${_slp_s//$'\x0f'/\\u000f}
  _slp_s=${_slp_s//$'\x10'/\\u0010}
  _slp_s=${_slp_s//$'\x11'/\\u0011}
  _slp_s=${_slp_s//$'\x12'/\\u0012}
  _slp_s=${_slp_s//$'\x13'/\\u0013}
  _slp_s=${_slp_s//$'\x14'/\\u0014}
  _slp_s=${_slp_s//$'\x15'/\\u0015}
  _slp_s=${_slp_s//$'\x16'/\\u0016}
  _slp_s=${_slp_s//$'\x17'/\\u0017}
  _slp_s=${_slp_s//$'\x18'/\\u0018}
  _slp_s=${_slp_s//$'\x19'/\\u0019}
  _slp_s=${_slp_s//$'\x1a'/\\u001a}
  _slp_s=${_slp_s//$'\x1b'/\\u001b}
  _slp_s=${_slp_s//$'\x1c'/\\u001c}
  _slp_s=${_slp_s//$'\x1d'/\\u001d}
  _slp_s=${_slp_s//$'\x1e'/\\u001e}
  _slp_s=${_slp_s//$'\x1f'/\\u001f}
  printf '%s' "$_slp_s"
}

slp_presentation_for_control() {
  local _slp_cid=$1
  case "$_slp_cid" in
@@PRESENTATION_CASES@@
    *) return 1 ;;
  esac
}

slp_pretty_status() {
  case "$1" in
    PASS) printf '%s' ok ;;
    FAIL) printf '%s' fail ;;
    ERROR) printf '%s' err ;;
    NOT_FOUND) printf '%s' nf ;;
    NOT_APPLICABLE) printf '%s' na ;;
    *) return 1 ;;
  esac
}

SLP_PRETTY_COLS=116
SLP_PRETTY_MODE=table
SLP_PRETTY_WS=5
SLP_PRETTY_WSRC=24
SLP_PRETTY_WC=32
SLP_PRETTY_WCUR=26
SLP_PRETTY_WREQ=16
SLP_PRETTY_VFIELD=8
SLP_PRETTY_VVALUE=104

slp_terminal_columns() {
  local _slp_size='' _slp_rows='' _slp_cols='' _slp_extra=''
  if [[ -r /dev/tty && -x /usr/bin/stty ]]; then
    _slp_size=$(command /usr/bin/stty size < /dev/tty 2>/dev/null) || _slp_size=''
    if [[ -n $_slp_size ]]; then
      read -r _slp_rows _slp_cols _slp_extra <<< "$_slp_size"
      if [[ $_slp_rows =~ ^[0-9]+$ && $_slp_cols =~ ^[0-9]+$ && -z $_slp_extra ]] && (( _slp_cols >= 40 && _slp_cols <= 1000 )); then
        printf '%s\n' "$_slp_cols"
        return 0
      fi
    fi
  fi
  printf '116\n'
}

slp_pretty_layout_for_cols() {
  local _slp_cols=$1 _slp_available _slp_remaining _slp_req_min
  [[ $_slp_cols =~ ^[0-9]+$ ]] || return 1
  (( _slp_cols >= 40 && _slp_cols <= 1000 )) || return 1
  SLP_PRETTY_COLS=$_slp_cols
  SLP_PRETTY_WS=5
  if (( _slp_cols < 90 )); then
    SLP_PRETTY_MODE=vertical
    SLP_PRETTY_VFIELD=8
    SLP_PRETTY_VVALUE=$((_slp_cols - SLP_PRETTY_VFIELD - 6))
    (( SLP_PRETTY_VVALUE > 0 )) || return 1
    return 0
  fi
  SLP_PRETTY_MODE=table
  if (( _slp_cols < 100 )); then
    SLP_PRETTY_WSRC=18
    SLP_PRETTY_WC=24
    _slp_req_min=10
  elif (( _slp_cols < 110 )); then
    SLP_PRETTY_WSRC=22
    SLP_PRETTY_WC=28
    _slp_req_min=12
  elif (( _slp_cols < 120 )); then
    SLP_PRETTY_WSRC=24
    SLP_PRETTY_WC=32
    _slp_req_min=14
  else
    SLP_PRETTY_WSRC=24
    SLP_PRETTY_WC=36
    _slp_req_min=16
  fi
  _slp_available=$((_slp_cols - 15))
  _slp_remaining=$((_slp_available - SLP_PRETTY_WS - SLP_PRETTY_WSRC - SLP_PRETTY_WC))
  (( _slp_remaining > _slp_req_min )) || return 1
  SLP_PRETTY_WCUR=$((_slp_remaining - _slp_req_min))
  (( SLP_PRETTY_WCUR > 43 )) && SLP_PRETTY_WCUR=43
  # current отдаёт required 10 символов, но не становится уже 12.
  if (( SLP_PRETTY_WCUR - 10 > 12 )); then
    SLP_PRETTY_WCUR=$((SLP_PRETTY_WCUR - 10))
  elif (( SLP_PRETTY_WCUR > 12 )); then
    SLP_PRETTY_WCUR=12
  fi
  SLP_PRETTY_WREQ=$((_slp_remaining - SLP_PRETTY_WCUR))
}

slp_pretty_layout_init() {
  local _slp_cols
  if [[ ! -t 1 ]]; then
    slp_pretty_layout_for_cols 116
    return $?
  fi
  _slp_cols=$(slp_terminal_columns) || return 1
  slp_pretty_layout_for_cols "$_slp_cols"
}

slp_repeat_dash() {
  local _slp_n=$1 _slp_out
  printf -v _slp_out '%*s' "$_slp_n" ''
  printf '%s' "${_slp_out// /-}"
}

slp_pretty_separator() {
  if [[ $SLP_PRETTY_MODE == vertical ]]; then
    slp_repeat_dash $((SLP_PRETTY_VFIELD + 2))
    printf '+'
    slp_repeat_dash $((SLP_PRETTY_VVALUE + 2))
    printf '+\n'
    return 0
  fi
  slp_repeat_dash $((SLP_PRETTY_WS + 2))
  printf '+'
  slp_repeat_dash $((SLP_PRETTY_WSRC + 2))
  printf '+'
  slp_repeat_dash $((SLP_PRETTY_WC + 2))
  printf '+'
  slp_repeat_dash $((SLP_PRETTY_WCUR + 2))
  printf '+'
  slp_repeat_dash $((SLP_PRETTY_WREQ + 2))
  printf '+\n'
}

slp_pretty_cell() {
  local _slp_text=$1 _slp_width=$2 _slp_chars _slp_bytes _slp_printf_width
  local LC_ALL=C.UTF-8
  _slp_chars=${#_slp_text}
  LC_ALL=C
  _slp_bytes=${#_slp_text}
  _slp_printf_width=$((_slp_width + _slp_bytes - _slp_chars))
  printf '%-*s' "$_slp_printf_width" "$_slp_text"
}

slp_pretty_vertical_field() {
  local LC_ALL=C.UTF-8
  local _slp_label=$1 _slp_text=$2 _slp_chunk
  if [[ -z $_slp_text ]]; then
    printf ' '
    slp_pretty_cell "$_slp_label" "$SLP_PRETTY_VFIELD"
    printf ' | '
    slp_pretty_cell '' "$SLP_PRETTY_VVALUE"
    printf ' |\n'
    return 0
  fi
  while [[ -n $_slp_text ]]; do
    _slp_chunk=${_slp_text:0:SLP_PRETTY_VVALUE}
    _slp_text=${_slp_text:SLP_PRETTY_VVALUE}
    printf ' '
    slp_pretty_cell "$_slp_label" "$SLP_PRETTY_VFIELD"
    printf ' | '
    slp_pretty_cell "$_slp_chunk" "$SLP_PRETTY_VVALUE"
    printf ' |\n'
    _slp_label=''
  done
}

slp_pretty_row() {
  local LC_ALL=C.UTF-8
  local _slp_st=$1 _slp_source=$2 _slp_control=$3 _slp_current=$4 _slp_required=$5
  local _slp_a _slp_b _slp_c _slp_d _slp_e
  if [[ $SLP_PRETTY_MODE == vertical ]]; then
    if [[ $_slp_st == st && $_slp_source == source && $_slp_control == control ]]; then
      printf ' '
      slp_pretty_cell field "$SLP_PRETTY_VFIELD"
      printf ' | '
      slp_pretty_cell value "$SLP_PRETTY_VVALUE"
      printf ' |\n'
      return 0
    fi
    slp_pretty_vertical_field st "$_slp_st"
    slp_pretty_vertical_field source "$_slp_source"
    slp_pretty_vertical_field control "$_slp_control"
    slp_pretty_vertical_field current "$_slp_current"
    slp_pretty_vertical_field required "$_slp_required"
    return 0
  fi
  while [[ -n $_slp_st || -n $_slp_source || -n $_slp_control || -n $_slp_current || -n $_slp_required ]]; do
    _slp_a=${_slp_st:0:SLP_PRETTY_WS}; _slp_st=${_slp_st:SLP_PRETTY_WS}
    _slp_b=${_slp_source:0:SLP_PRETTY_WSRC}; _slp_source=${_slp_source:SLP_PRETTY_WSRC}
    _slp_c=${_slp_control:0:SLP_PRETTY_WC}; _slp_control=${_slp_control:SLP_PRETTY_WC}
    _slp_d=${_slp_current:0:SLP_PRETTY_WCUR}; _slp_current=${_slp_current:SLP_PRETTY_WCUR}
    _slp_e=${_slp_required:0:SLP_PRETTY_WREQ}; _slp_required=${_slp_required:SLP_PRETTY_WREQ}
    printf ' '
    slp_pretty_cell "$_slp_a" "$SLP_PRETTY_WS"
    printf ' | '
    slp_pretty_cell "$_slp_b" "$SLP_PRETTY_WSRC"
    printf ' | '
    slp_pretty_cell "$_slp_c" "$SLP_PRETTY_WC"
    printf ' | '
    slp_pretty_cell "$_slp_d" "$SLP_PRETTY_WCUR"
    printf ' | '
    slp_pretty_cell "$_slp_e" "$SLP_PRETTY_WREQ"
    printf ' |\n'
  done
}

slp_collect_policy() {
  # reason допускает необязательный третий сегмент-payload (путь, цель
  # readlink и т. п.): <domain>:<reason>[:<payload>]. Payload может содержать
  # любые байты, кроме control-байт (0x00-0x1F, 0x7F) — они ломают
  # табличный/TSV вывод. Локаль фиксируется явно: классификация [:cntrl:]
  # обязана быть побайтовой, не зависеть от окружения вызова.
  local LC_ALL=C
  local _slp_fn _slp_expected_cid _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_extra
  local _slp_i
  local -a _slp_fns=(@@FN_WORDS@@)
  local -a _slp_ids=(@@CID_WORDS@@)

  SLP_RESULTS=()
  SLP_TOTAL=0 SLP_PASS=0 SLP_FAIL=0 SLP_NF=0 SLP_NA=0 SLP_ERR=0 SLP_POLICY_STATUS='' SLP_POLICY_RC=0

  for ((_slp_i=0; _slp_i<${#_slp_fns[@]}; _slp_i++)); do
    _slp_fn=${_slp_fns[$_slp_i]}
    _slp_expected_cid=${_slp_ids[$_slp_i]}
    if ! _slp_line="$($_slp_fn)"; then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    _slp_tag='' _slp_cid='' _slp_status='' _slp_value='' _slp_comp='' _slp_extra=''
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_extra <<< "$_slp_line"
    if [[ $_slp_tag != SLP-CHECK-V1 || $_slp_cid != "$_slp_expected_cid" || -n $_slp_extra ]]; then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    case "$_slp_status:$_slp_comp" in
      VALUE:PASS|VALUE:FAIL|NOT_FOUND:FAIL|NOT_FOUND:NOT_FOUND|NOT_APPLICABLE:NOT_APPLICABLE|ERROR:ERROR) ;;
      *)
        printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
        return 1
        ;;
    esac
    if [[ $_slp_comp == ERROR ]]; then
      if [[ ! $_slp_value =~ ^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*(:[^[:cntrl:]]*)?$ ]]; then
        printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
        return 1
      fi
    fi
    SLP_RESULTS+=("$_slp_line")
    ((SLP_TOTAL+=1))
    case "$_slp_comp" in
      PASS) ((SLP_PASS+=1)) ;;
      FAIL) ((SLP_FAIL+=1)) ;;
      NOT_FOUND) ((SLP_NF+=1)) ;;
      NOT_APPLICABLE) ((SLP_NA+=1)) ;;
      ERROR) ((SLP_ERR+=1)) ;;
      *) return 1 ;;
    esac
  done

  if (( SLP_NF > 0 || SLP_ERR > 0 )); then
    SLP_POLICY_STATUS=UNEVALUATED
    SLP_POLICY_RC=1
  elif (( SLP_FAIL > 0 )); then
    SLP_POLICY_STATUS=NONCOMPLIANT
    SLP_POLICY_RC=0
  else
    SLP_POLICY_STATUS=COMPLIANT
    SLP_POLICY_RC=0
  fi
  return 0
}

slp_selected() {
  local _slp_result=$1 _slp_failed_only=$2
  if (( _slp_failed_only == 0 )); then return 0; fi
  [[ $_slp_result == FAIL || $_slp_result == ERROR ]]
}

slp_support_class() {
  if [[ $SLP_SYSTEM_TYPE == DESKTOP ]]; then
    printf '%s' FIELD_COMPATIBILITY
  else
    printf '%s' SUPPORTED
  fi
}

slp_render_raw() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp
  printf 'SLP-PLATFORM-V1\tSYSTEM=%s\tID=%s\tVERSION_ID=%s\tARCH=%s\tPROFILE=%s\tTYPE=%s\tPLATFORM=%s\tENVIRONMENT=%s\tSUPPORT=%s\n' \
    "$SLP_SYSTEM_PRETTY_NAME" "$SLP_SYSTEM_ID" "$SLP_SYSTEM_VERSION_ID" "$SLP_SYSTEM_ARCH" \
    "$SLP_SYSTEM_PROFILE" "$SLP_SYSTEM_TYPE" "$SLP_SYSTEM_PLATFORM" "$SLP_SYSTEM_ENVIRONMENT" "$(slp_support_class)"
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    printf '%s\n' "$_slp_line"
  done
  printf 'SLP-SUMMARY-V1\tTOTAL=%d\tPASS=%d\tFAIL=%d\tNOT_FOUND=%d\tNOT_APPLICABLE=%d\tERROR=%d\tPOLICY_STATUS=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_NA" "$SLP_ERR" "$SLP_POLICY_STATUS"
}

slp_render_pretty() {
  local _slp_failed_only=$1 _slp_title=$2 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp
  local _slp_current _slp_required _slp_meta _slp_source _slp_control _slp_extra _slp_st
  printf '=== SecureLinux Policy — %s ===\n' "$_slp_title"
  printf 'SUPPORT=%s\n' "$(slp_support_class)"
  printf 'SYSTEM=%s ARCH=%s\n' "$SLP_SYSTEM_PRETTY_NAME" "$SLP_SYSTEM_ARCH"
  printf 'PLATFORM=%s\n' "$SLP_SYSTEM_PLATFORM"
  if [[ -n $SLP_SYSTEM_TYPE ]]; then
    printf 'TYPE=%s\n\n' "$SLP_SYSTEM_TYPE"
  else
    printf 'PROFILE=%s\n\n' "$SLP_SYSTEM_PROFILE"
  fi
  slp_pretty_layout_init || return 1
  slp_pretty_row 'st' 'source' 'control' 'current' 'required'
  slp_pretty_separator
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    if ! _slp_meta=$(slp_presentation_for_control "$_slp_cid"); then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    IFS=$'\t' read -r _slp_source _slp_control _slp_required _slp_extra <<< "$_slp_meta"
    if [[ -z $_slp_source || -z $_slp_control || -z $_slp_required || -n $_slp_extra ]]; then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    if ! _slp_st=$(slp_pretty_status "$_slp_comp"); then
      printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
      return 1
    fi
    case "$_slp_status" in
      VALUE) _slp_current=$_slp_value ;;
      NOT_FOUND) _slp_current='<absent>' ;;
      NOT_APPLICABLE) _slp_current='<not-applicable>' ;;
      ERROR) _slp_current="not-determined; reason: $_slp_value" ;;
      *) printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2; return 1 ;;
    esac
    slp_pretty_row "$_slp_st" "$_slp_source" "$_slp_control" "$_slp_current" "$_slp_required"
  done
  slp_pretty_separator
  printf 'TOTAL=%d   PASS=%d   FAIL=%d   NOT_FOUND=%d   NOT_APPLICABLE=%d   ERROR=%d   POLICY=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_NA" "$SLP_ERR" "$SLP_POLICY_STATUS"
}

slp_render_json() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_first=1 _slp_filter=all
  (( _slp_failed_only == 1 )) && _slp_filter=failed
  printf '{"schema":"SLP-REPORT-V1","filter":"%s","platform":{"system":"%s","id":"%s","version_id":"%s","arch":"%s","profile":"%s","type":"%s","platform_id":"%s","environment_id":"%s","support":"%s"},"policy_status":"%s","summary":{"total":%d,"pass":%d,"fail":%d,"not_found":%d,"not_applicable":%d,"error":%d},"results":[' \
    "$_slp_filter" "$(slp_json_escape "$SLP_SYSTEM_PRETTY_NAME")" "$(slp_json_escape "$SLP_SYSTEM_ID")" \
    "$(slp_json_escape "$SLP_SYSTEM_VERSION_ID")" "$(slp_json_escape "$SLP_SYSTEM_ARCH")" \
    "$(slp_json_escape "$SLP_SYSTEM_PROFILE")" "$(slp_json_escape "$SLP_SYSTEM_TYPE")" "$(slp_json_escape "$SLP_SYSTEM_PLATFORM")" \
    "$(slp_json_escape "$SLP_SYSTEM_ENVIRONMENT")" "$(slp_json_escape "$(slp_support_class)")" "$SLP_POLICY_STATUS" "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_NA" "$SLP_ERR"
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    if (( _slp_first == 0 )); then printf ','; fi
    _slp_first=0
    printf '{"control_id":"%s","observation":"%s","value":"%s","result":"%s"}' \
      "$(slp_json_escape "$_slp_cid")" "$(slp_json_escape "$_slp_status")" "$(slp_json_escape "$_slp_value")" "$(slp_json_escape "$_slp_comp")"
  done
  printf ']}\n'
}

slp_run_check() {
  local _slp_format=$1 _slp_failed_only=$2 _slp_title=${3:-CHECK}
  slp_target_preflight || return $?
  slp_collect_policy || return $?
  case "$_slp_format" in
    pretty) slp_render_pretty "$_slp_failed_only" "$_slp_title" ;;
    raw) slp_render_raw "$_slp_failed_only" ;;
    json) slp_render_json "$_slp_failed_only" ;;
    *) return 2 ;;
  esac
  return "$SLP_POLICY_RC"
}

slp_run_apply() {
  local _slp_mode=$1
  slp_target_preflight || return $?
  if [[ $_slp_mode == APPLY && $SLP_SYSTEM_TYPE == DESKTOP ]]; then
    {
      printf '\n%s\n' '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
      printf '%s\n' '!!! ВНИМАНИЕ: UBUNTU DESKTOP = FIELD_COMPATIBILITY !!!'
      printf '%s\n' '!!! КОРРЕКТНОСТЬ APPLY НА ИЗМЕНЁННОЙ ПОЛЬЗОВАТЕЛЕМ DESKTOP-СИСТЕМЕ НЕ ГАРАНТИРУЕТСЯ. !!!'
      printf '%s\n' 'Установленные пакеты, службы и локальные настройки могут изменить поведение CHECK/APPLY.'
      printf '%s\n' 'Перед APPLY выполните --apply --dry-run и обеспечьте внешний snapshot/backup.'
      printf '%s\n\n' '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
    } >&2
  fi
  command /usr/bin/python3 -I -S -B - "$_slp_mode" <<'SLP_PRODUCT_APPLY_EOF'
@@APPLY_DISPATCHER@@
SLP_PRODUCT_APPLY_EOF
  return $?
}

slp_main() {
  local _slp_format=pretty _slp_failed_only=0
  if (( $# == 0 )); then
    slp_help
    return 0
  fi
  case "$1" in
    --help)
      (( $# == 1 )) || return 2
      slp_help
      return 0
      ;;
    --version)
      (( $# == 1 )) || return 2
      slp_version
      return 0
      ;;
    --build-info)
      (( $# == 1 )) || return 2
      slp_build_info
      return 0
      ;;
    --provenance)
      if (( $# == 1 )); then
        slp_provenance_all
      elif (( $# == 2 )); then
        slp_provenance_one "$2" || return 2
      else
        return 2
      fi
      return 0
      ;;
    --apply)
      shift
      if (( $# == 0 )); then
        slp_run_apply APPLY
        return $?
      fi
      if (( $# == 1 )) && [[ $1 == --dry-run ]]; then
        slp_run_apply DRY_RUN
        return $?
      fi
      return 2
      ;;
    --report)
      (( $# == 1 )) || return 2
      slp_run_check pretty 1 REPORT
      return $?
      ;;
    --check)
      shift
      while (( $# > 0 )); do
        case "$1" in
          --failed)
            (( _slp_failed_only == 0 )) || return 2
            _slp_failed_only=1
            ;;
          --format)
            shift
            (( $# > 0 )) || return 2
            case "$1" in pretty|raw|json) _slp_format=$1 ;; *) return 2 ;; esac
            ;;
          --format=*)
            _slp_format=${1#--format=}
            case "$_slp_format" in pretty|raw|json) ;; *) return 2 ;; esac
            ;;
          *) return 2 ;;
        esac
        shift
      done
      slp_run_check "$_slp_format" "$_slp_failed_only" CHECK
      return $?
      ;;
    *)
      return 2
      ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  slp_main "$@"
  exit $?
fi
'''
    replacements = {
        "@@PRODUCT_STATUS@@": PRODUCT_STATUS,
        "@@PRODUCT_CLI_ID@@": PRODUCT_CLI_ID,
        "@@GENERATOR_ID@@": GENERATOR_ID,
        "@@GENERATOR_SHA@@": generator_sha,
        "@@MANIFEST_SHA@@": manifest_sha,
        "@@REGISTRY_SHA@@": registry_sha,
        "@@APPLY_KINDS@@": apply_kinds_text,
        "@@APPLY_CONTROL_COUNT@@": str(len(apply_controls)),
        "@@APPLY_IMPLEMENTATION_COUNT@@": str(len(apply_mechanisms)),
        "@@APPLY_KIND_REGISTRY_SHA@@": apply_kind_registry_sha,
        "@@APPLY_REGISTRY_SHA@@": apply_registry_sha,
        "@@APPLY_DISPATCHER@@": apply_dispatcher,
        "@@TARGET_FAMILY_ID@@": TARGET_FAMILY_ID,
        "@@PLATFORM_MATRIX_SHA@@": platform_matrix_sha,
        "@@DESKTOP_MATRIX_SHA@@": desktop_matrix_sha,
        "@@SUPPORTED_PROFILE_COUNT@@": str(len(platform_rows)),
        "@@SUPPORTED_DESKTOP_COUNT@@": str(len(desktop_rows)),
        "@@SUPPORTED_COUNT@@": str(len(platform_rows)),
        "@@SUPPORTED_CASES@@": supported_cases,
        "@@CONTROL_COUNT@@": str(len(controls)),
        "@@ADAPTER_COUNT@@": str(len(adapters)),
        "@@BLOCKS@@": "\n\n".join(blocks),
        "@@PROV_ALL@@": prov_all,
        "@@PROV_CASES@@": "\n".join(prov_cases),
        "@@FN_WORDS@@": fn_words,
        "@@CID_WORDS@@": cid_words,
        "@@PRESENTATION_CASES@@": "\n".join(presentation_cases),
    }
    scaffolding = template
    for key, value in replacements.items():
        if key not in scaffolding:
            raise RuntimeError("template placeholder missing: " + key)
        scaffolding = scaffolding.replace(key, value)
    if "\r" in scaffolding:
        raise RuntimeError("generated script contains CR")
    mutating = find_known_mutating_token(scaffolding.replace(apply_dispatcher, ""))
    if mutating is not None:
        raise RuntimeError(f"known mutating token leaked into generated CHECK: {mutating!r}")
    return scaffolding.encode("utf-8")


def output_is_ignored_if_inside_repo(repo: Path, out: Path) -> None:
    try:
        rel = out.relative_to(repo)
    except ValueError:
        return
    cp = subprocess.run(
        ["git", "check-ignore", "-q", "--", rel.as_posix()],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"output inside repo is not gitignored: {rel.as_posix()}")


def write_exclusive(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    os.chmod(path, mode)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate deterministic SecureLinux-Policy unified product CLI."
    )
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    repo = Path(args.repo).expanduser().resolve(strict=True)
    if not (repo / ".git").is_dir():
        raise RuntimeError("Git worktree required")
    out = Path(args.out).expanduser().resolve()
    side = out.with_name(out.name + ".sha256")
    if out.exists() or side.exists():
        raise RuntimeError("refusing to overwrite output or sidecar")
    output_is_ignored_if_inside_repo(repo, out)
    output_is_ignored_if_inside_repo(repo, side)

    rows, manifest_sha = load_manifest(repo)
    platform_rows, platform_matrix_sha = load_platform_matrix(repo)
    desktop_rows, desktop_matrix_sha = load_desktop_matrix(repo)
    adapters, registry_sha = load_registry(repo)
    controls = [load_control(repo, row) for row in rows]
    for c in controls:
        if c["parameter_kind"] not in adapters:
            raise RuntimeError(
                f"no adapter for current control {c['control_id']} kind={c['parameter_kind']}"
            )
    apply_mechanisms, apply_kind_registry_sha, apply_registry_sha = load_apply_mechanisms(repo)
    apply_controls = [control for control in controls if control["apply_supported"]]

    generator_sha = sha_file(Path(__file__).resolve(strict=True))
    script = render_script(
        controls, adapters, manifest_sha, registry_sha, generator_sha,
        platform_rows=platform_rows, platform_matrix_sha=platform_matrix_sha,
        desktop_rows=desktop_rows, desktop_matrix_sha=desktop_matrix_sha,
        apply_mechanisms=apply_mechanisms,
        apply_kind_registry_sha=apply_kind_registry_sha,
        apply_registry_sha=apply_registry_sha,
        apply_controls=apply_controls,
    )

    write_exclusive(out, script, 0o755)
    script_sha = sha_bytes(script)
    write_exclusive(side, (script_sha + "  " + out.name + "\n").encode("utf-8"), 0o644)

    print("STATUS=" + PRODUCT_STATUS)
    print("GENERATOR_ID=" + GENERATOR_ID)
    print("GENERATOR_SHA256=" + generator_sha)
    print("CONTROL_MANIFEST_SHA256=" + manifest_sha)
    print("CONTROL_COUNT=" + str(len(controls)))
    print("ADAPTER_COUNT=" + str(len(adapters)))
    print("ADAPTER_REGISTRY_SHA256=" + registry_sha)
    active_apply_kinds = sorted(
        {item["kind_row"]["apply_kind"] for item in apply_mechanisms.values()},
        key=lambda x: x.encode("utf-8"),
    )
    print("APPLY_KINDS=" + ",".join(active_apply_kinds))
    print("APPLY_CONTROL_COUNT=" + str(len(apply_controls)))
    print("APPLY_IMPLEMENTATION_COUNT=" + str(len(apply_mechanisms)))
    print("APPLY_KIND_REGISTRY_SHA256=" + apply_kind_registry_sha)
    print("APPLY_IMPLEMENTATION_REGISTRY_SHA256=" + apply_registry_sha)
    print("TARGET_FAMILY_ID=" + TARGET_FAMILY_ID)
    print("SUPPORTED_PROFILE_ENVIRONMENTS=" + str(len(platform_rows)))
    print("FIELD_COMPATIBILITY_ENVIRONMENTS=" + str(len(desktop_rows)))
    print("SUPPORTED_ENVIRONMENTS=" + str(len(platform_rows)))
    print("PLATFORM_MATRIX_SHA256=" + platform_matrix_sha)
    print("DESKTOP_MATRIX_SHA256=" + desktop_matrix_sha)
    print("CHECK_SHA256=" + script_sha)
    print("CHECK_PATH=" + str(out))
    print("SIDECAR_PATH=" + str(side))
    print("TRACKED_REPO_MODIFIED=false")
    print("DERIVED_OUTPUT_WRITTEN=true")
    print("MUTATION_CAPABILITY=true")
    print("RELEASE=false")
    print("RESULT=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            "PRODUCT_CHECK_GENERATOR_FAIL=" + type(exc).__name__ + ":" + str(exc),
            file=__import__("sys").stderr,
        )
        raise SystemExit(1)
