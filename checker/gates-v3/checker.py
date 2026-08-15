#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
from datetime import datetime
import json
import re
import stat
import sys
from collections import Counter, defaultdict
from pathlib import Path

NORM_VERSION = "norm-v1"
NORMALIZER_SHA256 = "fdf11e5abc24c966e7b9c9abe318259fd29c06de026addf54cf3710cc937639a"

TOP_KEYS = {"id","layer","profile","source","requirement","parameter","expected","apply"}
SOURCE_KEYS = {"index_id","doc_id","doc_sha256","locator","quote","quote_sha256","norm"}
REQ_KEYS = {"stated","derived","justification","applicability"}
PARAM_KEYS = {"kind","locator","key"}
EXPECTED_KEYS = {"op","value","type"}
APPLY_KEYS = {"supported"}

LAYER_ORDER = ["fstec-core","recommended","corporate","firewall"]
PROFILE_ORDER = ["baseline","strict","paranoid"]
APPLICABILITY_ORDER = ["technical","monitoring","firewall"]
LAYERS = set(LAYER_ORDER)
PROFILES = set(PROFILE_ORDER)
APPLICABILITY = set(APPLICABILITY_ORDER)
DISPOSITIONS = {"not-technical","organizational","external","out-of-scope","informational"}
DISPOSITION_LEDGER_FIELDS = ["index_id","disposition","reason","basis","decided_by","decided_at"]

# Machine identifiers, locators and keys are single-line by contract.
#
# Runtime matches patterns with re.fullmatch; JSON Schema `pattern` has search
# semantics, and in the Python regex engine `$` also matches just before a
# trailing newline. Sharing one pattern string is therefore not enough to
# share one meaning: "kernel.x\n" would be rejected by fullmatch and accepted
# by a searching validator. Every anchored pattern below carries an explicit
# no-CR/LF assertion, which behaves identically under fullmatch, under Python
# search and under ECMA-262, so the two sides accept exactly the same strings.
# parse_scalar rejects control characters as well, as defence in depth.
SINGLE_LINE = r"(?![\s\S]*[\r\n])"

def single_line(body: str) -> str:
    return "^" + SINGLE_LINE + body + "$"


ID_PATTERN = single_line(r"[A-Z0-9][A-Z0-9._-]{2,127}")
SHA_PATTERN = single_line(r"[0-9a-f]{64}")
INDEX_ID_PATTERN = single_line(r"SRC-[0-9]{4}")
NONEMPTY_PATTERN = r".*\S.*"
SYSCTL_KEY_PATTERN = single_line(r"[A-Za-z0-9_.-]+")
UNIT_PATTERN = single_line(r"[A-Za-z0-9_.@:-]+\.(?:service|socket|timer|path|mount|target)")
PKG_PATTERN = single_line(r"[A-Za-z0-9][A-Za-z0-9+._:-]*")
ABSOLUTE_PATH_PATTERN = single_line(r"/.*")
MOUNT_OPTION_KEY_PATTERN = single_line(r"option::.+")
PAM_LINE_KEY_PATTERN = single_line(r"active_line::.+")


ID_RE = re.compile(ID_PATTERN)
SHA_RE = re.compile(SHA_PATTERN)
INDEX_ID_RE = re.compile(INDEX_ID_PATTERN)
DECIDED_BY_RE = re.compile(single_line(r"[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}"))
DECIDED_AT_RE = re.compile(single_line(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"))

# Single source of truth for the per-kind parameter contract.
#
# Both the runtime closure check (validate_parameter_closure) and the published
# JSON Schema (build_control_schema / --emit-schema) are derived from this
# table, so the two cannot diverge. Constraints use a deliberately small
# vocabulary that has an exact equivalent on both sides:
#   {"const": x}   {"enum": [...]}   {"pattern": "..."}   {"anyOf": [...]}
# A None constraint means the field carries no kind-specific restriction
# beyond the base schema.
KIND_RULES = {
    "sysctl": {
        "locator": {"const": "sysctl"},
        "key": {"pattern": SYSCTL_KEY_PATTERN},
        "op": {"const": "eq"},
        "type": {"enum": ["integer", "string"]},
    },
    "file-kv": {
        "locator": {"pattern": ABSOLUTE_PATH_PATTERN},
        "key": None,
        "op": {"const": "eq"},
        "type": {"enum": ["integer", "string", "boolean"]},
    },
    "file-mode-owner": {
        "locator": {"pattern": ABSOLUTE_PATH_PATTERN},
        "key": {"enum": ["mode", "owner", "group", "owner_group"]},
        "op": {"const": "eq"},
        "type": {"const": "string"},
    },
    "mount-option": {
        "locator": {"pattern": ABSOLUTE_PATH_PATTERN},
        "key": {"anyOf": [{"const": "fstype"},
                          {"pattern": MOUNT_OPTION_KEY_PATTERN}]},
        "op": {"const": "eq"},
        "type": {"const": "string"},
    },
    "systemd-unit-state": {
        "locator": {"pattern": UNIT_PATTERN},
        "key": {"enum": ["active", "enabled", "masked"]},
        "op": {"const": "eq"},
        "type": {"const": "boolean"},
    },
    "package-presence": {
        "locator": {"pattern": PKG_PATTERN},
        "key": {"const": "installed"},
        "op": {"const": "eq"},
        "type": {"const": "boolean"},
    },
    "pam-line": {
        "locator": {"pattern": ABSOLUTE_PATH_PATTERN},
        "key": {"pattern": PAM_LINE_KEY_PATTERN},
        "op": {"const": "contains"},
        "type": {"const": "string"},
    },
    "audit-rule": {
        "locator": {"pattern": ABSOLUTE_PATH_PATTERN},
        "key": None,
        "op": {"const": "contains"},
        "type": {"const": "string"},
    },
}

PARAMETER_KINDS = list(KIND_RULES)

# Probe observation value contracts are separate from the control schema.
#
# `expected.type` describes the semantic policy value. `VALUE.value` describes
# the JSON wire value emitted by a probe. Those are not interchangeable.
#
# There is deliberately no global "true"/"false" string coercion. Each probe
# kind must define its own value encoding before a runner for that kind can be
# admitted.
OBSERVATION_VALUE_CONTRACTS = {
    "sysctl": {
        "runner_status": "implemented",
        "encodings": {
            "integer": "json-string-parse-int",
            "string": "json-string-literal",
        },
    },
    "systemd-unit-state": {
        "runner_status": "not-implemented",
        "encodings": {
            "boolean": "json-boolean",
        },
    },
    "package-presence": {
        "runner_status": "not-implemented",
        "encodings": {
            "boolean": "json-boolean",
        },
    },
}

# file-kv may carry semantic booleans in a control, but a future file-kv probe
# must define source-specific textual mapping before boolean observations are
# executable. No generic boolean coercion is allowed in the meantime.
DEFERRED_OBSERVATION_VALUE_CONTRACTS = {
    "file-kv": {
        "boolean": "UNDEFINED_UNTIL_FILE_KV_PROBE_DESIGN",
    },
}


def constraint_ok(value, constraint) -> bool:
    """Evaluate one constraint with exactly the semantics the emitted JSON
    Schema keyword has. Patterns are anchored in the table and matched with
    fullmatch so that runtime and schema accept the same set of strings."""
    if constraint is None:
        return True
    if "const" in constraint:
        return value == constraint["const"]
    if "enum" in constraint:
        return any(value == x for x in constraint["enum"])
    if "pattern" in constraint:
        return isinstance(value, str) and re.fullmatch(constraint["pattern"], value) is not None
    if "anyOf" in constraint:
        return any(constraint_ok(value, c) for c in constraint["anyOf"])
    raise ValueError(f"unsupported constraint {constraint!r}")


def describe_constraint(constraint) -> str:
    if constraint is None:
        return "unconstrained"
    if "const" in constraint:
        return f"must be {constraint['const']!r}"
    if "enum" in constraint:
        return "must be one of " + ", ".join(repr(x) for x in constraint["enum"])
    if "pattern" in constraint:
        return f"must match {constraint['pattern']}"
    if "anyOf" in constraint:
        return " or ".join(describe_constraint(c) for c in constraint["anyOf"])
    raise ValueError(f"unsupported constraint {constraint!r}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_regular(path: Path) -> None:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"symlink forbidden: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"regular file required: {path}")


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
            raise ValueError(f"{path}:{lineno}: invalid JSON-quoted scalar: {exc}")
        if not isinstance(parsed, str):
            raise ValueError(f"{path}:{lineno}: quoted scalar must be a string")
        if any(ch in parsed for ch in "\r\n\t\x00"):
            raise ValueError(
                f"{path}:{lineno}: control characters are forbidden in scalars"
            )
        return parsed
    if value.startswith("'"):
        raise ValueError(f"{path}:{lineno}: single-quoted scalars are not supported")
    if value == "":
        raise ValueError(f"{path}:{lineno}: empty scalar")
    if " #" in value or value.startswith("#"):
        raise ValueError(f"{path}:{lineno}: inline comments are not supported")
    return value


def parse_yaml_subset(path: Path) -> dict:
    validate_regular(path)
    root = {}
    stack = [(-2, root)]
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            raise ValueError(f"{path}:{lineno}: tabs are forbidden")
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2:
            raise ValueError(f"{path}:{lineno}: indentation must be multiples of 2")
        stripped = raw.strip()
        if ":" not in stripped:
            raise ValueError(f"{path}:{lineno}: expected key: value")
        key, value = stripped.split(":", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key):
            raise ValueError(f"{path}:{lineno}: invalid key {key!r}")
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            raise ValueError(f"{path}:{lineno}: indentation underflow")
        parent_indent, parent = stack[-1]
        if indent != parent_indent + 2:
            raise ValueError(f"{path}:{lineno}: indentation jump")
        if key in parent:
            raise ValueError(f"{path}:{lineno}: duplicate key {key!r}")
        if value.strip() == "":
            child = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = parse_scalar(value, path, lineno)
    return root


def load_controls(root: Path):
    if not root.is_dir():
        raise ValueError(f"controls root is not a directory: {root}")
    records, files = [], []
    for p in sorted(root.rglob("*.yaml"), key=lambda x: x.as_posix()):
        validate_regular(p)
        files.append(p)
        try:
            records.append((p, parse_yaml_subset(p)))
        except Exception as exc:
            records.append((p, {"__parse_error__": str(exc)}))
    return records, files


def load_index(path: Path):
    validate_regular(path)
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        rows = list(reader)
        fields = list(reader.fieldnames or [])
    required = {
        "index_id","source_id","source_file","source_sha256","source_role",
        "unit_kind","locator","raw_match_line","text_quality","quote_anchor_ready",
        "status","disposition","reason","note",
    }
    if set(fields) != required:
        raise ValueError(f"unexpected index fields: {fields}")
    by_id = {}
    for row in rows:
        if row["index_id"] in by_id:
            raise ValueError(f"duplicate index_id: {row['index_id']}")
        by_id[row["index_id"]] = row
    return rows, by_id


def exact_keys(obj, expected, where, errors):
    if not isinstance(obj, dict):
        errors.append(f"{where}: mapping required")
        return False
    missing = sorted(expected - set(obj))
    extra = sorted(set(obj) - expected)
    if missing:
        errors.append(f"{where}: missing keys {missing}")
    if extra:
        errors.append(f"{where}: unknown keys {extra}")
    return not missing and not extra


def is_nonempty_string(v):
    return isinstance(v, str) and bool(v.strip())


def validate_record_schema(record, where):
    errors = []
    if "__parse_error__" in record:
        return [f"{where}: {record['__parse_error__']}"]
    if not exact_keys(record, TOP_KEYS, where, errors):
        return errors
    for key, expected in [
        ("source", SOURCE_KEYS),
        ("requirement", REQ_KEYS),
        ("parameter", PARAM_KEYS),
        ("expected", EXPECTED_KEYS),
        ("apply", APPLY_KEYS),
    ]:
        exact_keys(record.get(key), expected, f"{where}.{key}", errors)
    if errors:
        return errors

    if not isinstance(record["id"], str) or not ID_RE.fullmatch(record["id"]):
        errors.append(f"{where}.id: invalid identifier")
    if record["layer"] not in LAYERS:
        errors.append(f"{where}.layer: unsupported layer {record['layer']!r}")
    profile = record["profile"]
    if record["layer"] == "corporate":
        if profile not in PROFILES:
            errors.append(f"{where}.profile: corporate requires baseline|strict|paranoid")
    elif profile is not None:
        errors.append(f"{where}.profile: must be null outside corporate layer")

    s = record["source"]
    if not isinstance(s["index_id"], str) or not INDEX_ID_RE.fullmatch(s["index_id"]):
        errors.append(f"{where}.source.index_id: invalid")
    if not is_nonempty_string(s["doc_id"]):
        errors.append(f"{where}.source.doc_id: nonempty string required")
    if not isinstance(s["doc_sha256"], str) or not SHA_RE.fullmatch(s["doc_sha256"]):
        errors.append(f"{where}.source.doc_sha256: lowercase SHA-256 required")
    if not is_nonempty_string(s["locator"]):
        errors.append(f"{where}.source.locator: nonempty string required")
    if not is_nonempty_string(s["quote"]):
        errors.append(f"{where}.source.quote: nonempty string required")
    if not isinstance(s["quote_sha256"], str) or not SHA_RE.fullmatch(s["quote_sha256"]):
        errors.append(f"{where}.source.quote_sha256: lowercase SHA-256 required")
    if s["norm"] != NORM_VERSION:
        errors.append(f"{where}.source.norm: must be {NORM_VERSION}")

    q = record["requirement"]
    if not is_nonempty_string(q["stated"]):
        errors.append(f"{where}.requirement.stated: nonempty string required")
    if not isinstance(q["derived"], bool):
        errors.append(f"{where}.requirement.derived: boolean required")
    elif q["derived"]:
        if not is_nonempty_string(q["justification"]):
            errors.append(f"{where}.requirement.justification: required when derived=true")
    elif q["justification"] is not None:
        errors.append(f"{where}.requirement.justification: must be null when derived=false")
    if q["applicability"] not in APPLICABILITY:
        errors.append(f"{where}.requirement.applicability: unsupported value")

    p = record["parameter"]
    for k in ("kind","locator","key"):
        if not is_nonempty_string(p[k]):
            errors.append(f"{where}.parameter.{k}: nonempty string required")

    e = record["expected"]
    if not is_nonempty_string(e["op"]):
        errors.append(f"{where}.expected.op: nonempty string required")
    if e["type"] == "integer":
        if not isinstance(e["value"], int) or isinstance(e["value"], bool):
            errors.append(f"{where}.expected.value: integer required")
    elif e["type"] == "string":
        if not isinstance(e["value"], str):
            errors.append(f"{where}.expected.value: string required")
    elif e["type"] == "boolean":
        if not isinstance(e["value"], bool):
            errors.append(f"{where}.expected.value: boolean required")
    else:
        errors.append(f"{where}.expected.type: unsupported value")

    if not isinstance(record["apply"]["supported"], bool):
        errors.append(f"{where}.apply.supported: boolean required")
    return errors


def validate_parameter_closure(record, where):
    """Kind-specific closure. Driven entirely by KIND_RULES so that the
    published CONTROL-SCHEMA.json and this check cannot disagree."""
    p, e = record["parameter"], record["expected"]
    kind = p["kind"]
    rules = KIND_RULES.get(kind)
    if rules is None:
        return [f"{where}: unsupported parameter.kind {kind!r}"]
    errors = []
    for field, value in (
        ("parameter.locator", p["locator"]),
        ("parameter.key", p["key"]),
        ("expected.op", e["op"]),
        ("expected.type", e["type"]),
    ):
        constraint = rules[field.split(".")[1]]
        if not constraint_ok(value, constraint):
            errors.append(
                f"{where}: {kind} {field} {describe_constraint(constraint)}"
            )
    return errors


def build_control_schema():
    """Derive the published JSON Schema from the same runtime constants used
    by validate_record_schema and validate_parameter_closure."""
    def nonempty_string():
        return {"pattern": NONEMPTY_PATTERN, "type": "string"}

    def obj(properties, required):
        return {
            "additionalProperties": False,
            "properties": properties,
            "required": list(required),
            "type": "object",
        }

    kind_branches = []
    for kind, rules in KIND_RULES.items():
        parameter_props = {}
        for field in ("locator", "key"):
            if rules[field] is not None:
                parameter_props[field] = dict(rules[field])
        expected_props = {
            "op": dict(rules["op"]),
            "type": dict(rules["type"]),
        }
        then = {"properties": {"expected": {"properties": expected_props}}}
        if parameter_props:
            then["properties"]["parameter"] = {"properties": parameter_props}
        kind_branches.append({
            "if": {"properties": {"parameter": {
                "properties": {"kind": {"const": kind}},
                "required": ["kind"],
            }}},
            "then": then,
        })

    value_branches = [
        {
            "if": {"properties": {"expected": {
                "properties": {"type": {"const": t}},
                "required": ["type"],
            }}},
            "then": {"properties": {"expected": {
                "properties": {"value": {"type": t}}
            }}},
        }
        for t in ("integer", "string", "boolean")
    ]

    return {
        "$id": "securelinux-policy-v3-control-schema-v3",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"layer": {"const": "corporate"}},
                       "required": ["layer"]},
                "then": {"properties": {"profile": {"enum": list(PROFILE_ORDER)}}},
                "else": {"properties": {"profile": {"type": "null"}}},
            },
            {
                "if": {"properties": {"requirement": {
                    "properties": {"derived": {"const": True}},
                    "required": ["derived"],
                }}},
                "then": {"properties": {"requirement": {
                    "properties": {"justification": nonempty_string()}
                }}},
                "else": {"properties": {"requirement": {
                    "properties": {"justification": {"type": "null"}}
                }}},
            },
        ] + value_branches + kind_branches,
        "properties": {
            "apply": obj({"supported": {"type": "boolean"}}, ["supported"]),
            "expected": obj({
                "op": nonempty_string(),
                "type": {"enum": ["integer", "string", "boolean"]},
                "value": {},
            }, ["op", "value", "type"]),
            "id": {"pattern": ID_PATTERN, "type": "string"},
            "layer": {"enum": list(LAYER_ORDER)},
            "parameter": obj({
                "key": nonempty_string(),
                "kind": {"enum": PARAMETER_KINDS},
                "locator": nonempty_string(),
            }, ["kind", "locator", "key"]),
            "profile": {"enum": [None] + list(PROFILE_ORDER)},
            "requirement": obj({
                "applicability": {"enum": list(APPLICABILITY_ORDER)},
                "derived": {"type": "boolean"},
                "justification": {"type": ["string", "null"]},
                "stated": nonempty_string(),
            }, ["stated", "derived", "justification", "applicability"]),
            "source": obj({
                "doc_id": nonempty_string(),
                "doc_sha256": {"pattern": SHA_PATTERN, "type": "string"},
                "index_id": {"pattern": INDEX_ID_PATTERN, "type": "string"},
                "locator": nonempty_string(),
                "norm": {"const": NORM_VERSION},
                "quote": nonempty_string(),
                "quote_sha256": {"pattern": SHA_PATTERN, "type": "string"},
            }, ["index_id", "doc_id", "doc_sha256", "locator",
                "quote", "quote_sha256", "norm"]),
        },
        "required": ["id", "layer", "profile", "source",
                     "requirement", "parameter", "expected", "apply"],
        "title": "SecureLinux-Policy v3 control record",
        "type": "object",
    }


def render_control_schema() -> str:
    return json.dumps(build_control_schema(), ensure_ascii=False,
                      indent=2, sort_keys=True) + "\n"


def schema_parity_errors(schema_path: Path):
    """Fail closed when the committed schema is not the one this checker
    derives from its own constants."""
    try:
        validate_regular(schema_path)
        actual = schema_path.read_text(encoding="utf-8")
    except Exception as exc:
        return [f"{schema_path}: cannot read published schema: {exc}"]
    if actual != render_control_schema():
        return [
            f"{schema_path}: published schema differs from the schema derived "
            f"from runtime constants (regenerate with --emit-schema)"
        ]
    return []


def load_normalizer(project_root: Path):
    p = project_root / "sources/extracted/normalizer-v1.py"
    validate_regular(p)
    if sha256_file(p) != NORMALIZER_SHA256:
        raise ValueError("normalizer-v1.py SHA mismatch")
    ns = {"__name__": "gate_checker_norm"}
    exec(compile(p.read_text(encoding="utf-8"), str(p), "exec"), ns, ns)
    ns["selftest"]()
    return ns["normalize_text"]


def read_manifest(path: Path, key_field: str):
    validate_regular(path)
    with path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    out = {}
    for row in rows:
        key = row[key_field]
        if key in out:
            raise ValueError(f"duplicate manifest key {key!r}")
        out[key] = row
    return out


def resolve_norm_corpus(project_root: Path, row: dict):
    pdf, pdf_sha = row["source_file"], row["source_sha256"]
    if row["text_quality"] == "recovered-glyph-map-v1":
        m = read_manifest(project_root / "sources/recovered-v1/RECOVERY-MANIFEST.tsv", "source_id")
        x = m.get(row["source_id"])
        if x is None:
            raise ValueError("recovery manifest entry missing")
        if x["pdf"] != pdf or x["pdf_sha256"] != pdf_sha:
            raise ValueError("recovery manifest source mismatch")
        if x["norm_version"] != NORM_VERSION or x["normalizer_sha256"] != NORMALIZER_SHA256:
            raise ValueError("recovery normalization mismatch")
        p = project_root / "sources/recovered-v1" / x["norm_path"]
        validate_regular(p)
        if sha256_file(p) != x["norm_sha256"]:
            raise ValueError("recovered norm SHA mismatch")
        return p
    m = read_manifest(project_root / "sources/extracted/EXTRACTION-MANIFEST.tsv", "pdf")
    x = m.get(pdf)
    if x is None:
        raise ValueError("extraction manifest entry missing")
    if x["pdf_sha256"] != pdf_sha:
        raise ValueError("extraction manifest source mismatch")
    if x["norm_version"] != NORM_VERSION or x["normalizer_sha256"] != NORMALIZER_SHA256:
        raise ValueError("extraction normalization mismatch")
    p = project_root / "sources/extracted" / x["norm_path"]
    validate_regular(p)
    if sha256_file(p) != x["norm_sha256"]:
        raise ValueError("extracted norm SHA mismatch")
    return p


def gate1(project_root, index_by_id, records):
    normalize_text = load_normalizer(project_root)
    errors, passed = [], 0
    for path, record in records:
        where = path.as_posix()
        if validate_record_schema(record, where):
            errors.append(f"{where}: Gate1 cannot evaluate invalid closed schema")
            continue
        s = record["source"]
        row = index_by_id.get(s["index_id"])
        if row is None:
            errors.append(f"{where}: unknown source.index_id {s['index_id']}")
            continue
        local = []
        if row["quote_anchor_ready"] != "YES":
            local.append("index quote_anchor_ready != YES")
        if s["doc_id"] != row["source_id"]:
            local.append("doc_id != index source_id")
        if s["doc_sha256"] != row["source_sha256"]:
            local.append("doc_sha256 != index source_sha256")
        if s["locator"] != row["locator"]:
            local.append("locator != index locator")
        pdf = project_root / "sources/fstec" / row["source_file"]
        try:
            validate_regular(pdf)
            if sha256_file(pdf) != row["source_sha256"]:
                local.append("pinned PDF actual SHA != index SHA")
        except Exception as exc:
            local.append(f"pinned PDF verification failed: {exc}")
        canonical = normalize_text(s["quote"])
        if canonical.endswith("\n"):
            canonical = canonical[:-1]
        if s["quote"] != canonical:
            local.append("stored quote is not canonical norm-v1 quote")
        if sha256_text(s["quote"]) != s["quote_sha256"]:
            local.append("quote_sha256 mismatch")
        try:
            corpus = resolve_norm_corpus(project_root, row).read_text(encoding="utf-8")
            if corpus.endswith("\n"):
                corpus = corpus[:-1]
            if s["quote"] not in corpus:
                local.append("normalized quote not found in normalized source corpus")
        except Exception as exc:
            local.append(f"norm corpus verification failed: {exc}")
        if local:
            errors.extend(f"{where}: {e}" for e in local)
        else:
            passed += 1
    return {"gate":1,"name":"source_quote_anchor_live","pass":not errors,
            "checked_records":len(records),"passed_records":passed,"errors":errors}


def load_closure_contract(path: Path):
    validate_regular(path)
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        fields = list(reader.fieldnames or [])
        rows = list(reader)

    expected_fields = [
        "index_id","coverage_mode","expected_control_ids","basis"
    ]
    if fields != expected_fields:
        raise ValueError(
            f"closure contract fields mismatch: expected={expected_fields} actual={fields}"
        )

    out = {}
    for lineno, row in enumerate(rows, 2):
        idx = row["index_id"].strip()
        mode = row["coverage_mode"].strip()
        basis = row["basis"].strip()
        ids = [x.strip() for x in row["expected_control_ids"].split(",") if x.strip()]

        if not INDEX_ID_RE.fullmatch(idx):
            raise ValueError(f"closure contract line {lineno}: invalid index_id {idx!r}")
        if idx in out:
            raise ValueError(f"closure contract line {lineno}: duplicate index_id {idx}")
        if mode not in {"atomic-single","exact-control-set"}:
            raise ValueError(
                f"closure contract line {lineno}: unsupported coverage_mode {mode!r}"
            )
        if not basis:
            raise ValueError(f"closure contract line {lineno}: basis is required")
        if not ids:
            raise ValueError(
                f"closure contract line {lineno}: expected_control_ids must not be empty"
            )
        if len(ids) != len(set(ids)):
            raise ValueError(
                f"closure contract line {lineno}: duplicate expected control IDs"
            )
        for cid in ids:
            if not ID_RE.fullmatch(cid):
                raise ValueError(
                    f"closure contract line {lineno}: invalid control id {cid!r}"
                )
        if mode == "atomic-single" and len(ids) != 1:
            raise ValueError(
                f"closure contract line {lineno}: atomic-single requires exactly one control"
            )
        if mode == "exact-control-set" and len(ids) < 2:
            raise ValueError(
                f"closure contract line {lineno}: exact-control-set requires at least two controls"
            )
        out[idx] = {
            "coverage_mode": mode,
            "expected_control_ids": frozenset(ids),
            "basis": basis,
        }
    return out


def load_disposition_ledger(path: Path):
    """Load the audited alternative-closure ledger fail-closed.

    The ledger deliberately contains no synthetic quote anchor in v1. Current
    canonical quote generation covers only part of the source index, and the
    generator does not yet expose a stable machine distinction between
    unsupported unit kinds, deliberate extraction refusals and integrity
    failures. The v1 contract therefore uses the minimum machine-verifiable
    assertions agreed for Step 7A: one row per index_id, exact disposition and
    reason agreement with SOURCE-INDEX, an explicit decision basis/actor, and
    a strictly parsed UTC timestamp.
    """
    validate_regular(path)
    with path.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    if fields != DISPOSITION_LEDGER_FIELDS:
        raise ValueError(
            f"unexpected disposition ledger fields: {fields}; "
            f"expected {DISPOSITION_LEDGER_FIELDS}"
        )
    out = {}
    for lineno, row in enumerate(rows, 2):
        idx_raw = row["index_id"]
        disp_raw = row["disposition"]
        reason = row["reason"].strip()
        basis = row["basis"].strip()
        decided_by_raw = row["decided_by"]
        decided_at_raw = row["decided_at"]

        idx = idx_raw.strip()
        disposition = disp_raw.strip()
        decided_by = decided_by_raw.strip()
        decided_at = decided_at_raw.strip()

        if idx_raw != idx or not INDEX_ID_RE.fullmatch(idx):
            raise ValueError(
                f"disposition ledger line {lineno}: invalid index_id {idx_raw!r}"
            )
        if idx in out:
            raise ValueError(
                f"disposition ledger line {lineno}: duplicate index_id {idx}"
            )
        if disp_raw != disposition or disposition not in DISPOSITIONS:
            raise ValueError(
                f"disposition ledger line {lineno}: unsupported disposition {disp_raw!r}"
            )
        if not reason:
            raise ValueError(
                f"disposition ledger line {lineno}: reason is required"
            )
        if not basis:
            raise ValueError(
                f"disposition ledger line {lineno}: basis is required"
            )
        if decided_by_raw != decided_by or not DECIDED_BY_RE.fullmatch(decided_by):
            raise ValueError(
                f"disposition ledger line {lineno}: invalid decided_by {decided_by_raw!r}"
            )
        if decided_at_raw != decided_at or not DECIDED_AT_RE.fullmatch(decided_at):
            raise ValueError(
                f"disposition ledger line {lineno}: decided_at must be YYYY-MM-DDTHH:MM:SSZ"
            )
        try:
            datetime.strptime(decided_at, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise ValueError(
                f"disposition ledger line {lineno}: invalid decided_at {decided_at!r}"
            ) from exc

        out[idx] = {
            "disposition": disposition,
            "reason": reason,
            "basis": basis,
            "decided_by": decided_by,
            "decided_at": decided_at,
        }
    return out


def gate2(index_rows, index_by_id, records, closure_contract_path, disposition_ledger_path):
    errors = []
    refs = defaultdict(set)

    for path, record in records:
        if validate_record_schema(record, path.as_posix()):
            continue
        idx = record["source"]["index_id"]
        cid = record["id"]
        if idx not in index_by_id:
            errors.append(f"{path}: Gate2 unknown index reference {idx}")
        else:
            refs[idx].add(cid)

    try:
        contracts = load_closure_contract(closure_contract_path)
    except Exception as exc:
        return {
            "gate":2,
            "name":"reverse_source_coverage",
            "pass":False,
            "total_index_rows":len(index_rows),
            "controlled_closed_rows":0,
            "disposed_closed_rows":0,
            "uncovered_rows":len(index_rows),
            "contract_rows":0,
            "disposition_ledger_rows":0,
            "errors":[f"closure contract invalid: {exc}"],
        }

    try:
        disposition_ledger = load_disposition_ledger(disposition_ledger_path)
    except Exception as exc:
        return {
            "gate":2,
            "name":"reverse_source_coverage",
            "pass":False,
            "total_index_rows":len(index_rows),
            "controlled_closed_rows":0,
            "disposed_closed_rows":0,
            "uncovered_rows":len(index_rows),
            "contract_rows":len(contracts),
            "disposition_ledger_rows":0,
            "errors":[f"disposition ledger invalid: {exc}"],
        }

    unknown_contracts = sorted(set(contracts) - set(index_by_id))
    for idx in unknown_contracts:
        errors.append(f"closure contract references unknown index row {idx}")
    unknown_ledger = sorted(set(disposition_ledger) - set(index_by_id))
    for idx in unknown_ledger:
        errors.append(f"disposition ledger references unknown index row {idx}")

    controlled = 0
    disposed = 0
    uncovered = []

    for row in index_rows:
        idx = row["index_id"]
        status = row["status"]
        disposition = row["disposition"].strip()
        reason = row["reason"].strip()
        actual_ids = refs.get(idx, set())
        contract = contracts.get(idx)
        ledger_entry = disposition_ledger.get(idx)

        if actual_ids:
            if status != "CLOSED":
                uncovered.append(
                    f"{idx}: represented but status={status!r}, expected CLOSED"
                )
                continue
            if disposition or reason:
                uncovered.append(
                    f"{idx}: controlled row must not carry disposition/reason"
                )
                continue
            if ledger_entry is not None:
                uncovered.append(
                    f"{idx}: controlled row must not carry a disposition ledger entry"
                )
                continue
            if contract is None:
                uncovered.append(
                    f"{idx}: controlled CLOSED row has no completeness contract"
                )
                continue
            expected_ids = set(contract["expected_control_ids"])
            if actual_ids != expected_ids:
                uncovered.append(
                    f"{idx}: control set does not satisfy completeness contract "
                    f"expected={sorted(expected_ids)} actual={sorted(actual_ids)}"
                )
                continue
            controlled += 1
            continue

        if status == "CLOSED" and disposition in DISPOSITIONS and reason:
            if contract is not None:
                uncovered.append(
                    f"{idx}: disposed CLOSED row must not carry a control completeness contract"
                )
                continue
            if ledger_entry is None:
                uncovered.append(
                    f"{idx}: disposed CLOSED row has no disposition ledger entry"
                )
                continue
            if ledger_entry["disposition"] != disposition:
                uncovered.append(
                    f"{idx}: disposition ledger mismatch "
                    f"index={disposition!r} ledger={ledger_entry['disposition']!r}"
                )
                continue
            if ledger_entry["reason"] != reason:
                uncovered.append(
                    f"{idx}: disposition ledger reason mismatch"
                )
                continue
            disposed += 1
            continue

        if ledger_entry is not None:
            uncovered.append(
                f"{idx}: disposition ledger entry exists but row is not a valid disposed CLOSED row"
            )
            continue

        if contract is not None:
            uncovered.append(
                f"{idx}: completeness contract exists but no active control represents the row"
            )
            continue

        uncovered.append(
            f"{idx}: no control and no valid CLOSED disposition+reason "
            f"(status={status!r}, disposition={disposition!r})"
        )

    errors.extend(uncovered)
    return {
        "gate":2,
        "name":"reverse_source_coverage",
        "pass":not errors,
        "total_index_rows":len(index_rows),
        "controlled_closed_rows":controlled,
        "disposed_closed_rows":disposed,
        "uncovered_rows":len(uncovered),
        "contract_rows":len(contracts),
        "disposition_ledger_rows":len(disposition_ledger),
        "errors":errors,
    }



def gate3(records):
    errors, passed = [], 0
    for path, record in records:
        where = path.as_posix()
        local = validate_record_schema(record, where)
        if not local:
            local = validate_parameter_closure(record, where)
        if local:
            errors.extend(local)
        else:
            passed += 1
    return {"gate":3,"name":"closed_schema_parameter_closure","pass":not errors,
            "checked_records":len(records),"passed_records":passed,"errors":errors}


def gate4(records):
    errors = []
    ids = defaultdict(list)
    scoped = defaultdict(list)
    physical = defaultdict(list)

    for path, record in records:
        if validate_record_schema(record, path.as_posix()):
            continue

        rid = record["id"]
        ids[rid].append(path.as_posix())

        p = record["parameter"]
        e = record["expected"]
        signature = (
            e["op"],
            e["type"],
            json.dumps(e["value"], ensure_ascii=False, sort_keys=True),
        )
        scoped_identity = (
            record["layer"],
            record["profile"],
            p["kind"],
            p["locator"],
            p["key"],
        )
        physical_identity = (p["kind"], p["locator"], p["key"])

        scoped[scoped_identity].append(
            (signature, rid, path.as_posix())
        )
        physical[physical_identity].append(
            (
                record["layer"],
                record["profile"],
                signature,
                rid,
                path.as_posix(),
            )
        )

    for rid, paths in sorted(ids.items()):
        if len(paths) > 1:
            errors.append(f"duplicate control id {rid}: {paths}")

    scope_conflicts = 0
    for identity, values in sorted(scoped.items(), key=lambda x: repr(x[0])):
        signatures = {v[0] for v in values}
        if len(signatures) > 1:
            scope_conflicts += 1
            errors.append(
                f"same-scope parameter conflict {identity}: "
                + "; ".join(f"{rid}={sig}" for sig, rid, _ in values)
            )

    profile_variants = 0
    cross_scope_conflicts = 0

    for identity, values in sorted(physical.items(), key=lambda x: repr(x[0])):
        signatures = {v[2] for v in values}
        if len(signatures) <= 1:
            continue

        scopes = {(v[0], v[1]) for v in values}
        if len(scopes) == 1:
            # Divergence is wholly inside one scope and was already reported
            # by the scoped-identity check above.
            continue

        all_corporate_profiles = (
            all(layer == "corporate" and profile in PROFILES
                for layer, profile in scopes)
            and len(scopes) == len({profile for _, profile in scopes})
        )

        if all_corporate_profiles:
            profile_variants += 1
            continue

        # Divergence across provenance layers is not auto-resolved. It is
        # intentionally fail-closed until a future explicit adjudication
        # mechanism records authority, chosen value and justification.
        cross_scope_conflicts += 1
        errors.append(
            f"unresolved cross-scope parameter conflict {identity}: "
            + "; ".join(
                f"scope=({layer},{profile}) {rid}={sig}"
                for layer, profile, sig, rid, _ in values
            )
        )

    return {
        "gate":4,
        "name":"uniqueness_no_parameter_conflicts",
        "pass":not errors,
        "checked_records":len(records),
        "unique_ids":len(ids),
        "scoped_parameter_identities":len(scoped),
        "physical_parameter_identities":len(physical),
        "scope_conflicts":scope_conflicts,
        "profile_variants":profile_variants,
        "cross_scope_conflicts":cross_scope_conflicts,
        "conflicts":scope_conflicts + cross_scope_conflicts,
        "errors":errors,
    }


PROBE_RESULTS_SCHEMA = "securelinux-policy-probe-results-v1"
PROBE_RESULT_KEYS = {
    "control_id","kind","locator","key","status","value",
    "compliance","evidence_path"
}


def load_probe_results(path: Path):
    validate_regular(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid probe-results JSON: {exc}")
    if not isinstance(data, dict):
        raise ValueError("probe-results root must be object")
    expected_root = {"schema","probe_kind","read_only","results"}
    if set(data) != expected_root:
        raise ValueError(
            f"probe-results root keys mismatch: "
            f"missing={sorted(expected_root-set(data))} "
            f"extra={sorted(set(data)-expected_root)}"
        )
    if data["schema"] != PROBE_RESULTS_SCHEMA:
        raise ValueError(f"probe-results schema must be {PROBE_RESULTS_SCHEMA}")
    if data["probe_kind"] != "sysctl":
        raise ValueError("probe-results probe_kind must be sysctl")
    if data["read_only"] is not True:
        raise ValueError("probe-results read_only must be true")
    if not isinstance(data["results"], list):
        raise ValueError("probe-results results must be list")
    return data


def _typed_observation_value(record, raw_value):
    """Decode one probe VALUE according to an explicit kind/type wire contract.

    Returns (ok, typed_value). There is no generic string-to-boolean coercion.
    """
    kind = record["parameter"]["kind"]
    typ = record["expected"]["type"]
    contract = OBSERVATION_VALUE_CONTRACTS.get(kind)
    if contract is None:
        return False, None
    encoding = contract["encodings"].get(typ)
    if encoding is None:
        return False, None

    if encoding == "json-string-parse-int":
        if not isinstance(raw_value, str):
            return False, None
        try:
            return True, int(raw_value)
        except Exception:
            return False, None

    if encoding == "json-string-literal":
        if not isinstance(raw_value, str):
            return False, None
        return True, raw_value

    if encoding == "json-boolean":
        # `type(x) is bool` intentionally rejects JSON numbers 0/1. In Python,
        # bool is a subclass of int, so isinstance(x, bool) is too permissive
        # for a wire-format boundary.
        if type(raw_value) is not bool:
            return False, None
        return True, raw_value

    raise ValueError(f"unsupported observation encoding {encoding!r}")


def _expected_compliance(record, raw_value):
    ok, actual = _typed_observation_value(record, raw_value)
    if not ok:
        return None
    expected = record["expected"]["value"]
    return "PASS" if actual == expected else "FAIL"


def gate5(records, probe_results_path):
    errors = []
    valid = []
    for path, record in records:
        where = path.as_posix()
        local = validate_record_schema(record, where)
        if not local:
            local = validate_parameter_closure(record, where)
        if local:
            errors.append(f"{where}: Gate5 cannot evaluate invalid record")
        else:
            valid.append((path, record))

    if probe_results_path is None:
        errors.append("probe-results file is required for Gate5")
        return {
            "gate":5,
            "name":"probe_executability",
            "pass":False,
            "checked_records":len(valid),
            "value_observations":0,
            "not_found_observations":0,
            "noncompliant_observations":0,
            "errors":errors,
        }

    try:
        data = load_probe_results(probe_results_path)
    except Exception as exc:
        errors.append(str(exc))
        return {
            "gate":5,
            "name":"probe_executability",
            "pass":False,
            "checked_records":len(valid),
            "value_observations":0,
            "not_found_observations":0,
            "noncompliant_observations":0,
            "errors":errors,
        }

    by_id = {}
    for i, item in enumerate(data["results"]):
        where = f"probe-results[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{where}: object required")
            continue
        if set(item) != PROBE_RESULT_KEYS:
            errors.append(
                f"{where}: keys mismatch "
                f"missing={sorted(PROBE_RESULT_KEYS-set(item))} "
                f"extra={sorted(set(item)-PROBE_RESULT_KEYS)}"
            )
            continue
        cid = item["control_id"]
        if not isinstance(cid, str) or not cid:
            errors.append(f"{where}: control_id must be nonempty string")
            continue
        if cid in by_id:
            errors.append(f"{where}: duplicate control_id {cid}")
            continue
        by_id[cid] = item

    active_ids = {record["id"] for _, record in valid}
    extra_ids = sorted(set(by_id) - active_ids)
    if extra_ids:
        errors.append(f"probe-results contain unknown/extra control ids: {extra_ids}")

    values = 0
    not_found = 0
    noncompliant = 0

    for path, record in valid:
        where = path.as_posix()
        rid = record["id"]
        p = record["parameter"]

        if p["kind"] != "sysctl":
            errors.append(
                f"{where}: Gate5 checker-v2 has only sysctl runner, got {p['kind']!r}"
            )
            continue

        item = by_id.get(rid)
        if item is None:
            errors.append(f"{where}: missing probe result for {rid}")
            continue

        for key, expected in (
            ("kind", p["kind"]),
            ("locator", p["locator"]),
            ("key", p["key"]),
        ):
            if item[key] != expected:
                errors.append(
                    f"{where}: probe result {key}={item[key]!r} "
                    f"!= control {expected!r}"
                )

        expected_path = "/proc/sys/" + p["key"].replace(".", "/")
        if item["evidence_path"] != expected_path:
            errors.append(
                f"{where}: evidence_path={item['evidence_path']!r} "
                f"!= {expected_path!r}"
            )

        status = item["status"]
        if status == "VALUE":
            values += 1
            expected_compliance = _expected_compliance(record, item["value"])
            if expected_compliance is None:
                errors.append(
                    f"{where}: probe value {item['value']!r} violates observation "
                    f"contract for kind={p['kind']!r} "
                    f"expected.type={record['expected']['type']!r}"
                )
                continue
            if item["compliance"] != expected_compliance:
                errors.append(
                    f"{where}: compliance={item['compliance']!r} "
                    f"!= computed {expected_compliance!r}"
                )
            if expected_compliance == "FAIL":
                noncompliant += 1
        elif status == "NOT_FOUND":
            not_found += 1
            if item["value"] is not None:
                errors.append(f"{where}: NOT_FOUND requires value=null")
            if item["compliance"] != "NOT_FOUND":
                errors.append(f"{where}: NOT_FOUND requires compliance=NOT_FOUND")
        elif status == "ERROR":
            errors.append(f"{where}: probe returned ERROR")
        else:
            errors.append(f"{where}: unsupported status {status!r}")

    return {
        "gate":5,
        "name":"probe_executability",
        "pass":not errors,
        "checked_records":len(valid),
        "value_observations":values,
        "not_found_observations":not_found,
        "noncompliant_observations":noncompliant,
        "errors":errors,
    }

def run_all(project_root: Path, index_path: Path, controls_root: Path, probe_results_path=None):
    index_rows, index_by_id = load_index(index_path)
    records, files = load_controls(controls_root)
    closure_contract_path = index_path.resolve().parent / "CLOSURE-CONTRACT.tsv"
    disposition_ledger_path = index_path.resolve().parent / "DISPOSITION-LEDGER.tsv"
    schema_path = Path(__file__).resolve().parent / "CONTROL-SCHEMA.json"
    parity = schema_parity_errors(schema_path)
    gates = [
        {"gate": 0, "name": "schema_generation_parity", "pass": not parity,
         "schema_path": str(schema_path), "errors": parity},
        gate1(project_root.resolve(), index_by_id, records),
        gate2(
            index_rows, index_by_id, records,
            closure_contract_path, disposition_ledger_path,
        ),
        gate3(records),
        gate4(records),
        gate5(records, probe_results_path),
    ]
    return {
        "overall_pass": all(g["pass"] for g in gates),
        "project_root": str(project_root.resolve()),
        "schema_path": str(schema_path),
        "index_path": str(index_path.resolve()),
        "closure_contract_path": str(closure_contract_path),
        "disposition_ledger_path": str(disposition_ledger_path),
        "controls_root": str(controls_root.resolve()),
        "probe_results_path": None if probe_results_path is None else str(Path(probe_results_path).resolve()),
        "control_files": len(files),
        "gates": gates,
    }


def format_report(report):
    by = {g["gate"]: g for g in report["gates"]}
    g0,g1,g2,g3,g4,g5 = by[0],by[1],by[2],by[3],by[4],by[5]
    lines = [
        f"GATE0={'PASS' if g0['pass'] else 'FAIL'} schema_generation_parity errors={len(g0['errors'])}",
        f"GATE1={'PASS' if g1['pass'] else 'FAIL'} checked={g1['checked_records']} errors={len(g1['errors'])}",
        f"GATE2={'PASS' if g2['pass'] else 'FAIL'} total={g2['total_index_rows']} controlled_closed={g2['controlled_closed_rows']} disposed_closed={g2['disposed_closed_rows']} uncovered={g2['uncovered_rows']} contracts={g2['contract_rows']} errors={len(g2['errors'])}",
        f"GATE3={'PASS' if g3['pass'] else 'FAIL'} checked={g3['checked_records']} errors={len(g3['errors'])}",
        f"GATE4={'PASS' if g4['pass'] else 'FAIL'} checked={g4['checked_records']} unique_ids={g4['unique_ids']} scoped_identities={g4['scoped_parameter_identities']} physical_identities={g4['physical_parameter_identities']} scope_conflicts={g4['scope_conflicts']} profile_variants={g4['profile_variants']} cross_scope_conflicts={g4['cross_scope_conflicts']} errors={len(g4['errors'])}",
        f"GATE5={'PASS' if g5['pass'] else 'FAIL'} checked={g5['checked_records']} value={g5['value_observations']} not_found={g5['not_found_observations']} noncompliant={g5['noncompliant_observations']} errors={len(g5['errors'])}",
        f"OVERALL={'PASS' if report['overall_pass'] else 'FAIL'}",
    ]
    for g in report["gates"]:
        for err in g["errors"][:20]:
            lines.append(f"ERROR[GATE{g['gate']}]={err}")
        if len(g["errors"]) > 20:
            lines.append(f"ERROR[GATE{g['gate']}]=... {len(g['errors'])-20} more")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-root")
    ap.add_argument("--index")
    ap.add_argument("--controls")
    ap.add_argument("--emit-schema", metavar="PATH",
                    help="write the schema derived from runtime constants and exit")
    ap.add_argument("--probe-results")
    ap.add_argument("--json-out")
    args = ap.parse_args()

    if args.emit_schema:
        Path(args.emit_schema).write_text(render_control_schema(),
                                          encoding="utf-8", newline="\n")
        return 0

    for required in ("project_root", "index", "controls"):
        if getattr(args, required) is None:
            ap.error(f"--{required.replace('_','-')} is required")

    probe_results = None if args.probe_results is None else Path(args.probe_results)
    report = run_all(
        Path(args.project_root),
        Path(args.index),
        Path(args.controls),
        probe_results,
    )
    sys.stdout.write(format_report(report))
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n"
        )
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
