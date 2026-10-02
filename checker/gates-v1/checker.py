#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
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

LAYERS = {"fstec-core","recommended","corporate","firewall"}
PROFILES = {"baseline","strict","paranoid"}
APPLICABILITY = {"technical","monitoring","firewall"}
DISPOSITIONS = {"not-technical","organizational","external","out-of-scope","informational"}

ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,127}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
INDEX_ID_RE = re.compile(r"^SRC-[0-9]{4}$")
SYSCTL_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
UNIT_RE = re.compile(r"^[A-Za-z0-9_.@:-]+\.(?:service|socket|timer|path|mount|target)$")
PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:-]*$")


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
    errors = []
    p, e = record["parameter"], record["expected"]
    kind, locator, key, op, typ = p["kind"], p["locator"], p["key"], e["op"], e["type"]
    if kind == "sysctl":
        if locator != "sysctl":
            errors.append(f"{where}: sysctl locator must be 'sysctl'")
        if not SYSCTL_KEY_RE.fullmatch(key):
            errors.append(f"{where}: invalid sysctl key")
        if op != "eq" or typ not in {"integer","string"}:
            errors.append(f"{where}: sysctl requires op=eq and type integer|string")
    elif kind == "file-kv":
        if not locator.startswith("/"):
            errors.append(f"{where}: file-kv locator must be absolute")
        if op != "eq" or typ not in {"integer","string","boolean"}:
            errors.append(f"{where}: file-kv requires op=eq and scalar type")
    elif kind == "file-mode-owner":
        if not locator.startswith("/"):
            errors.append(f"{where}: file-mode-owner locator must be absolute")
        if key not in {"mode","owner","group","owner_group"}:
            errors.append(f"{where}: file-mode-owner key unsupported")
        if op != "eq" or typ != "string":
            errors.append(f"{where}: file-mode-owner requires op=eq type=string")
    elif kind == "mount-option":
        if not locator.startswith("/"):
            errors.append(f"{where}: mount-option locator must be absolute mount point")
        if not (key == "fstype" or key.startswith("option::")):
            errors.append(f"{where}: mount-option key must be fstype or option::<name>")
        if op != "eq" or typ != "string":
            errors.append(f"{where}: mount-option requires op=eq type=string")
    elif kind == "systemd-unit-state":
        if not UNIT_RE.fullmatch(locator):
            errors.append(f"{where}: invalid systemd unit locator")
        if key not in {"active","enabled","masked"}:
            errors.append(f"{where}: systemd state key unsupported")
        if op != "eq" or typ != "boolean":
            errors.append(f"{where}: systemd-unit-state requires op=eq type=boolean")
    elif kind == "package-presence":
        if not PKG_RE.fullmatch(locator):
            errors.append(f"{where}: invalid package locator")
        if key != "installed":
            errors.append(f"{where}: package-presence key must be installed")
        if op != "eq" or typ != "boolean":
            errors.append(f"{where}: package-presence requires op=eq type=boolean")
    elif kind == "pam-line":
        if not locator.startswith("/"):
            errors.append(f"{where}: pam-line locator must be absolute")
        if not key.startswith("active_line::"):
            errors.append(f"{where}: pam-line key must start active_line::")
        if op != "contains" or typ != "string":
            errors.append(f"{where}: pam-line requires op=contains type=string")
    elif kind == "audit-rule":
        if not locator.startswith("/"):
            errors.append(f"{where}: audit-rule locator must be absolute")
        if op != "contains" or typ != "string":
            errors.append(f"{where}: audit-rule requires op=contains type=string")
    else:
        errors.append(f"{where}: unsupported parameter.kind {kind!r}")
    return errors


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


def gate2(index_rows, index_by_id, records):
    errors, refs = [], Counter()
    for path, record in records:
        if validate_record_schema(record, path.as_posix()):
            continue
        idx = record["source"]["index_id"]
        if idx not in index_by_id:
            errors.append(f"{path}: Gate2 unknown index reference {idx}")
        else:
            refs[idx] += 1
    controlled, disposed, uncovered = 0, 0, []
    for row in index_rows:
        idx = row["index_id"]
        status = row["status"]
        disposition = row["disposition"].strip()
        reason = row["reason"].strip()
        if refs[idx]:
            if status != "CLOSED":
                uncovered.append(f"{idx}: represented but status={status!r}, expected CLOSED")
            elif disposition or reason:
                uncovered.append(f"{idx}: controlled row must not carry disposition/reason")
            else:
                controlled += 1
        elif status == "CLOSED" and disposition in DISPOSITIONS and reason:
            disposed += 1
        else:
            uncovered.append(
                f"{idx}: no control and no valid CLOSED disposition+reason "
                f"(status={status!r}, disposition={disposition!r})"
            )
    errors.extend(uncovered)
    return {"gate":2,"name":"reverse_source_coverage","pass":not errors,
            "total_index_rows":len(index_rows),"controlled_closed_rows":controlled,
            "disposed_closed_rows":disposed,"uncovered_rows":len(uncovered),"errors":errors}


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
    ids, params = defaultdict(list), defaultdict(list)
    for path, record in records:
        if validate_record_schema(record, path.as_posix()):
            continue
        ids[record["id"]].append(path.as_posix())
        p, e = record["parameter"], record["expected"]
        ident = (p["kind"], p["locator"], p["key"])
        sig = (e["op"], e["type"], json.dumps(e["value"], ensure_ascii=False, sort_keys=True))
        params[ident].append((sig, record["id"], path.as_posix()))
    for rid, paths in sorted(ids.items()):
        if len(paths) > 1:
            errors.append(f"duplicate control id {rid}: {paths}")
    conflicts = 0
    for ident, vals in sorted(params.items(), key=lambda x: repr(x[0])):
        sigs = {v[0] for v in vals}
        if len(sigs) > 1:
            conflicts += 1
            errors.append(
                f"conflicting parameter {ident}: "
                + "; ".join(f"{rid}={sig}" for sig, rid, _ in vals)
            )
    return {"gate":4,"name":"uniqueness_no_parameter_conflicts","pass":not errors,
            "checked_records":len(records),"unique_ids":len(ids),
            "parameter_identities":len(params),"conflicts":conflicts,"errors":errors}


def run_all(project_root: Path, index_path: Path, controls_root: Path):
    index_rows, index_by_id = load_index(index_path)
    records, files = load_controls(controls_root)
    gates = [
        gate1(project_root.resolve(), index_by_id, records),
        gate2(index_rows, index_by_id, records),
        gate3(records),
        gate4(records),
    ]
    return {
        "overall_pass": all(g["pass"] for g in gates),
        "project_root": str(project_root.resolve()),
        "index_path": str(index_path.resolve()),
        "controls_root": str(controls_root.resolve()),
        "control_files": len(files),
        "gates": gates,
    }


def format_report(report):
    by = {g["gate"]: g for g in report["gates"]}
    g1,g2,g3,g4 = by[1],by[2],by[3],by[4]
    lines = [
        f"GATE1={'PASS' if g1['pass'] else 'FAIL'} checked={g1['checked_records']} errors={len(g1['errors'])}",
        f"GATE2={'PASS' if g2['pass'] else 'FAIL'} total={g2['total_index_rows']} controlled_closed={g2['controlled_closed_rows']} disposed_closed={g2['disposed_closed_rows']} uncovered={g2['uncovered_rows']} errors={len(g2['errors'])}",
        f"GATE3={'PASS' if g3['pass'] else 'FAIL'} checked={g3['checked_records']} errors={len(g3['errors'])}",
        f"GATE4={'PASS' if g4['pass'] else 'FAIL'} checked={g4['checked_records']} unique_ids={g4['unique_ids']} parameter_identities={g4['parameter_identities']} conflicts={g4['conflicts']} errors={len(g4['errors'])}",
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
    ap.add_argument("--project-root", required=True)
    ap.add_argument("--index", required=True)
    ap.add_argument("--controls", required=True)
    ap.add_argument("--json-out")
    args = ap.parse_args()
    report = run_all(Path(args.project_root), Path(args.index), Path(args.controls))
    sys.stdout.write(format_report(report))
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n"
        )
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
