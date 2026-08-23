#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
TARGET_ID = "ubuntu-24.04-x86_64"

MANIFEST_REL = "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv"
CONTROL_DIR_REL = "controls/fstec-core/linux-2022"
REGISTRY_REL = "product/ADAPTER-REGISTRY.tsv"

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
    if requirement["derived"] is not False or requirement["justification"] is not None:
        raise RuntimeError(f"derived requirement unsupported: {cid}")
    if requirement["applicability"] != "technical":
        raise RuntimeError(f"unsupported applicability: {cid}")
    if not isinstance(parameter["kind"], str) or not parameter["kind"]:
        raise RuntimeError(f"invalid parameter.kind: {cid}")
    if str(parameter["key"]) != row["key"]:
        raise RuntimeError(f"parameter.key mismatch: {cid}")
    if str(expected["value"]) != row["expected"]:
        raise RuntimeError(f"expected.value mismatch: {cid}")
    if apply["supported"] is not False:
        raise RuntimeError(f"mutating control forbidden: {cid}")

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
        if binding.get("operation") != "check" or binding.get("target_id") != TARGET_ID:
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
        if getattr(mod, "TARGET_ID", None) != TARGET_ID:
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


def render_script(
    controls,
    adapters,
    manifest_sha: str,
    registry_sha: str,
    generator_sha: str,
) -> bytes:
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
            "target_id": TARGET_ID,
        }
        provenance_lines.append(
            json.dumps(prov, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        )

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

    template = r'''#!/bin/bash -p
# SecureLinux-Policy v3 unified read-only product CLI
# STATUS=@@PRODUCT_STATUS@@
# PRODUCT_CLI=@@PRODUCT_CLI_ID@@
# GENERATOR_ID=@@GENERATOR_ID@@
# GENERATOR_SHA256=@@GENERATOR_SHA@@
# CONTROL_MANIFEST_SHA256=@@MANIFEST_SHA@@
# ADAPTER_REGISTRY_SHA256=@@REGISTRY_SHA@@
# TARGET_ID=@@TARGET_ID@@

set -u

@@BLOCKS@@

slp_target_preflight() {
  local _slp_id='' _slp_version='' _slp_arch='' _slp_k _slp_v
  if [[ ! -r /etc/os-release ]]; then
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  fi
  while IFS='=' read -r _slp_k _slp_v; do
    case "$_slp_k" in
      ID)
        _slp_v=${_slp_v#\"}
        _slp_v=${_slp_v%\"}
        _slp_id=$_slp_v
        ;;
      VERSION_ID)
        _slp_v=${_slp_v#\"}
        _slp_v=${_slp_v%\"}
        _slp_version=$_slp_v
        ;;
    esac
  done < /etc/os-release
  _slp_arch=$(command /usr/bin/uname -m 2>/dev/null) || {
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  }
  if [[ $_slp_id != ubuntu || $_slp_version != 24.04 || $_slp_arch != x86_64 ]]; then
    printf '%s\n' 'UNSUPPORTED_PLATFORM' >&2
    return 3
  fi
  return 0
}

slp_provenance_all() {
  cat <<'SLP_PROVENANCE_EOF'
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
    'TARGET_ID=@@TARGET_ID@@' \
    'MUTATING_MODES=NONE'
}

slp_help() {
  cat <<'SLP_HELP_EOF'
SecureLinux-Policy v3 — единый read-only CLI

Использование:
  ./securelinux-policy.sh --check [--failed] [--format pretty|raw|json]
  ./securelinux-policy.sh --report
  ./securelinux-policy.sh --build-info
  ./securelinux-policy.sh --provenance [CONTROL_ID]
  ./securelinux-policy.sh --version
  ./securelinux-policy.sh --help
  ./securelinux-policy.sh --apply
  ./securelinux-policy.sh --restore

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
  --apply               NOT_IMPLEMENTED; ничего не изменяет
  --restore             NOT_IMPLEMENTED; ничего не изменяет

Без аргументов печатается эта справка. CHECK не изменяет состояние хоста.
SLP_HELP_EOF
}

slp_version() {
  printf '%s\n' \
    'PRODUCT=SecureLinux-Policy-v3' \
    'PRODUCT_CLI=@@PRODUCT_CLI_ID@@' \
    'STATUS=@@PRODUCT_STATUS@@' \
    'CONTROL_COUNT=@@CONTROL_COUNT@@' \
    'TARGET_ID=@@TARGET_ID@@'
}

slp_json_escape() {
  local _slp_s=$1
  _slp_s=${_slp_s//\\/\\\\}
  _slp_s=${_slp_s//\"/\\\"}
  _slp_s=${_slp_s//$'\t'/\\t}
  _slp_s=${_slp_s//$'\r'/\\r}
  _slp_s=${_slp_s//$'\n'/\\n}
  printf '%s' "$_slp_s"
}

slp_pretty_row() {
  local _slp_result=$1 _slp_cid=$2 _slp_value=$3
  local _slp_width=56 _slp_part _slp_piece _slp_line=''
  local _slp_first=1
  local -a _slp_parts=()
  IFS=';' read -r -a _slp_parts <<< "$_slp_value"
  if (( ${#_slp_parts[@]} <= 1 )); then
    printf '%-7s  %-52s  %s\n' "$_slp_result" "$_slp_cid" "$_slp_value"
    return 0
  fi
  for _slp_part in "${_slp_parts[@]}"; do
    if [[ -z $_slp_line ]]; then
      _slp_line=$_slp_part
      continue
    fi
    _slp_piece=";$_slp_part"
    if (( ${#_slp_line} + ${#_slp_piece} <= _slp_width )); then
      _slp_line+="$_slp_piece"
    else
      if (( _slp_first == 1 )); then
        printf '%-7s  %-52s  %s\n' "$_slp_result" "$_slp_cid" "$_slp_line"
        _slp_first=0
      else
        printf '%-7s  %-52s  %s\n' '' '' "$_slp_line"
      fi
      _slp_line=$_slp_part
    fi
  done
  if (( _slp_first == 1 )); then
    printf '%-7s  %-52s  %s\n' "$_slp_result" "$_slp_cid" "$_slp_line"
  else
    printf '%-7s  %-52s  %s\n' '' '' "$_slp_line"
  fi
}

slp_collect_policy() {
  local _slp_fn _slp_expected_cid _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_extra
  local _slp_i
  local -a _slp_fns=(@@FN_WORDS@@)
  local -a _slp_ids=(@@CID_WORDS@@)

  SLP_RESULTS=()
  SLP_TOTAL=0 SLP_PASS=0 SLP_FAIL=0 SLP_NF=0 SLP_ERR=0 SLP_POLICY_STATUS='' SLP_POLICY_RC=0

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
      VALUE:PASS|VALUE:FAIL|NOT_FOUND:NOT_FOUND|ERROR:ERROR) ;;
      *)
        printf '%s\n' 'CHECK_INTERNAL_ERROR' >&2
        return 1
        ;;
    esac
    SLP_RESULTS+=("$_slp_line")
    ((SLP_TOTAL+=1))
    case "$_slp_comp" in
      PASS) ((SLP_PASS+=1)) ;;
      FAIL) ((SLP_FAIL+=1)) ;;
      NOT_FOUND) ((SLP_NF+=1)) ;;
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

slp_render_raw() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    printf '%s\n' "$_slp_line"
  done
  printf 'SLP-SUMMARY-V1\tTOTAL=%d\tPASS=%d\tFAIL=%d\tNOT_FOUND=%d\tERROR=%d\tPOLICY_STATUS=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_ERR" "$SLP_POLICY_STATUS"
}

slp_render_pretty() {
  local _slp_failed_only=$1 _slp_title=$2 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp
  printf '=== SecureLinux Policy — %s ===\n\n' "$_slp_title"
  printf '%-7s  %-52s  %s\n' 'RESULT' 'CONTROL' 'VALUE / DETAILS'
  printf '%-7s  %-52s  %s\n' '------' '----------------------------------------------------' '--------------------------------------------------------'
  for _slp_line in "${SLP_RESULTS[@]}"; do
    IFS=$'\t' read -r _slp_tag _slp_cid _slp_status _slp_value _slp_comp <<< "$_slp_line"
    slp_selected "$_slp_comp" "$_slp_failed_only" || continue
    slp_pretty_row "$_slp_comp" "$_slp_cid" "$_slp_value"
  done
  printf '%s\n' '-------------------------------------------------------------------------------------------------------------------------'
  printf 'TOTAL=%d   PASS=%d   FAIL=%d   NOT_FOUND=%d   ERROR=%d   POLICY=%s\n' \
    "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_ERR" "$SLP_POLICY_STATUS"
}

slp_render_json() {
  local _slp_failed_only=$1 _slp_line _slp_tag _slp_cid _slp_status _slp_value _slp_comp _slp_first=1 _slp_filter=all
  (( _slp_failed_only == 1 )) && _slp_filter=failed
  printf '{"schema":"SLP-REPORT-V1","filter":"%s","policy_status":"%s","summary":{"total":%d,"pass":%d,"fail":%d,"not_found":%d,"error":%d},"results":[' \
    "$_slp_filter" "$SLP_POLICY_STATUS" "$SLP_TOTAL" "$SLP_PASS" "$SLP_FAIL" "$SLP_NF" "$SLP_ERR"
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

slp_not_implemented() {
  local _slp_mode=$1
  printf 'NOT_IMPLEMENTED: %s; host state was not changed.\n' "$_slp_mode" >&2
  return 2
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
      (( $# == 1 )) || return 2
      slp_not_implemented APPLY
      return $?
      ;;
    --restore)
      (( $# == 1 )) || return 2
      slp_not_implemented RESTORE
      return $?
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
        "@@TARGET_ID@@": TARGET_ID,
        "@@CONTROL_COUNT@@": str(len(controls)),
        "@@ADAPTER_COUNT@@": str(len(adapters)),
        "@@BLOCKS@@": "\n\n".join(blocks),
        "@@PROV_ALL@@": prov_all,
        "@@PROV_CASES@@": "\n".join(prov_cases),
        "@@FN_WORDS@@": fn_words,
        "@@CID_WORDS@@": cid_words,
    }
    scaffolding = template
    for key, value in replacements.items():
        if key not in scaffolding:
            raise RuntimeError("template placeholder missing: " + key)
        scaffolding = scaffolding.replace(key, value)
    if "\r" in scaffolding:
        raise RuntimeError("generated script contains CR")
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
        description="Generate deterministic read-only SecureLinux-Policy unified product CLI."
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
    adapters, registry_sha = load_registry(repo)
    controls = [load_control(repo, row) for row in rows]
    for c in controls:
        if c["parameter_kind"] not in adapters:
            raise RuntimeError(
                f"no adapter for current control {c['control_id']} kind={c['parameter_kind']}"
            )

    generator_sha = sha_file(Path(__file__).resolve(strict=True))
    script = render_script(controls, adapters, manifest_sha, registry_sha, generator_sha)

    mutating = find_known_mutating_token(script.decode("utf-8"))
    if mutating is not None:
        raise RuntimeError(f"known mutating token leaked into generated CHECK: {mutating!r}")

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
    print("CHECK_SHA256=" + script_sha)
    print("CHECK_PATH=" + str(out))
    print("SIDECAR_PATH=" + str(side))
    print("TRACKED_REPO_MODIFIED=false")
    print("DERIVED_OUTPUT_WRITTEN=true")
    print("MUTATION_CAPABILITY=false")
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
