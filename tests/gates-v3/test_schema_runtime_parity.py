#!/usr/bin/env python3
"""B-R1-01 regression: the published CONTROL-SCHEMA.json and the runtime
closure check must accept exactly the same records.

Two independent guards:

1. Generation parity - the committed schema is byte-identical to the one the
   checker derives from its own constants (KIND_RULES et al). This makes
   drift structurally impossible rather than merely detectable.
2. Differential acceptance - a matrix of records is evaluated by the runtime
   and by a minimal evaluator for the JSON Schema keyword subset the schema
   uses. Any disagreement fails. This is the backstop in case the generator
   itself is wrong.
"""
from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

try:  # prefer a real Draft 2020-12 validator when it is installed
    import jsonschema
    HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover - environment dependent
    jsonschema = None
    HAVE_JSONSCHEMA = False

PROJECT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT / "checker/gates-v3/CONTROL-SCHEMA.json"

_spec = importlib.util.spec_from_file_location(
    "checker_v3", PROJECT / "checker/gates-v3/checker.py"
)
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)

SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def schema_errors(instance, schema):
    """Minimal evaluator for the keyword subset used by CONTROL-SCHEMA.json:
    type, const, enum, pattern, required, properties, additionalProperties,
    anyOf, allOf, not, if/then/else. `pattern` uses search semantics, as in
    JSON Schema."""
    errors = []
    if "type" in schema:
        wanted = schema["type"]
        wanted = wanted if isinstance(wanted, list) else [wanted]
        ok = False
        for t in wanted:
            if t == "integer":
                ok = ok or (isinstance(instance, int) and not isinstance(instance, bool))
            elif t == "boolean":
                ok = ok or isinstance(instance, bool)
            elif t == "null":
                ok = ok or instance is None
            elif t == "string":
                ok = ok or isinstance(instance, str)
            elif t == "object":
                ok = ok or isinstance(instance, dict)
            elif t == "array":
                ok = ok or isinstance(instance, list)
        if not ok:
            errors.append("type")
    if "const" in schema and instance != schema["const"]:
        errors.append("const")
    if "enum" in schema and not any(instance == x for x in schema["enum"]):
        errors.append("enum")
    if "pattern" in schema and isinstance(instance, str):
        if re.search(schema["pattern"], instance) is None:
            errors.append("pattern")
    if "required" in schema and isinstance(instance, dict):
        for key in schema["required"]:
            if key not in instance:
                errors.append(f"required:{key}")
    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for key, value in instance.items():
            if key in props:
                errors.extend(schema_errors(value, props[key]))
            elif schema.get("additionalProperties") is False and "properties" in schema:
                errors.append(f"additional:{key}")
    if "anyOf" in schema and not any(not schema_errors(instance, s) for s in schema["anyOf"]):
        errors.append("anyOf")
    if "not" in schema and not schema_errors(instance, schema["not"]):
        errors.append("not")
    for sub in schema.get("allOf", []):
        errors.extend(schema_errors(instance, sub))
    if "if" in schema:
        branch = "then" if not schema_errors(instance, schema["if"]) else "else"
        if branch in schema:
            errors.extend(schema_errors(instance, schema[branch]))
    return errors


def real_schema_errors(instance, schema):
    validator = jsonschema.Draft202012Validator(schema)
    return [e.message for e in validator.iter_errors(instance)]


def runtime_errors(record):
    errors = checker.validate_record_schema(record, "test")
    if errors:
        return errors
    return checker.validate_parameter_closure(record, "test")


def record(kind, locator, key, op, value, value_type,
           layer="fstec-core", profile=None, derived=False, justification=None):
    return {
        "id": "TEST.RECORD-1",
        "layer": layer,
        "profile": profile,
        "source": {
            "index_id": "SRC-0001", "doc_id": "doc", "doc_sha256": "0" * 64,
            "locator": "1.1", "quote": "quote", "quote_sha256": "1" * 64,
            "norm": "norm-v1",
        },
        "requirement": {
            "stated": "stated", "derived": derived,
            "justification": justification, "applicability": "technical",
        },
        "parameter": {"kind": kind, "locator": locator, "key": key},
        "expected": {"op": op, "value": value, "type": value_type},
        "apply": {"supported": False},
    }


CASES = [
    ("sysctl accepted", record("sysctl", "sysctl", "kernel.dmesg_restrict", "eq", 1, "integer")),
    ("sysctl ge integer accepted", record("sysctl", "sysctl", "vm.mmap_min_addr", "ge", 4096, "integer")),
    ("sysctl ge string rejected", record("sysctl", "sysctl", "kernel.x", "ge", "4096", "string")),
    ("sysctl locator rejected", record("sysctl", "/proc/sys", "kernel.x", "eq", 1, "integer")),
    ("sysctl key rejected", record("sysctl", "sysctl", "kernel x", "eq", 1, "integer")),
    ("sysctl op rejected", record("sysctl", "sysctl", "kernel.x", "contains", "1", "string")),
    ("sysctl type rejected", record("sysctl", "sysctl", "kernel.x", "eq", True, "boolean")),
    ("kernel-cmdline eq accepted", record("kernel-cmdline", "/proc/cmdline", "init_on_alloc", "eq", "1", "string")),
    ("kernel-cmdline present accepted", record("kernel-cmdline", "/proc/cmdline", "slab_nomerge", "present", True, "boolean")),
    ("kernel-cmdline locator rejected", record("kernel-cmdline", "/etc/default/grub", "init_on_alloc", "eq", "1", "string")),
    ("kernel-cmdline key rejected", record("kernel-cmdline", "/proc/cmdline", "bad key", "eq", "1", "string")),
    ("kernel-cmdline eq boolean rejected", record("kernel-cmdline", "/proc/cmdline", "init_on_alloc", "eq", True, "boolean")),
    ("kernel-cmdline eq whitespace rejected", record("kernel-cmdline", "/proc/cmdline", "mitigations", "eq", "auto nosmt", "string")),
    ("kernel-cmdline present false rejected", record("kernel-cmdline", "/proc/cmdline", "slab_nomerge", "present", False, "boolean")),
    ("kernel-cmdline present string rejected", record("kernel-cmdline", "/proc/cmdline", "slab_nomerge", "present", "true", "string")),
    ("file-kv accepted", record("file-kv", "/etc/ssh/sshd_config", "PermitRootLogin", "eq", "no", "string")),
    ("file-kv relative locator rejected", record("file-kv", "etc/f", "K", "eq", "v", "string")),
    ("file-mode-owner accepted", record("file-mode-owner", "/etc/shadow", "mode", "eq", "0640", "string")),
    ("file-mode-owner bits-clear accepted", record("file-mode-owner", "/etc/shadow", "mode", "bits-clear", "0077", "string")),
    ("file-mode-owner bits-clear zero mask rejected", record("file-mode-owner", "/etc/shadow", "mode", "bits-clear", "0000", "string")),
    ("file-mode-owner bits-clear short mask rejected", record("file-mode-owner", "/etc/shadow", "mode", "bits-clear", "077", "string")),
    ("file-mode-owner bits-clear non-octal rejected", record("file-mode-owner", "/etc/shadow", "mode", "bits-clear", "0080", "string")),
    ("file-mode-owner bits-clear owner rejected", record("file-mode-owner", "/etc/shadow", "owner", "bits-clear", "0077", "string")),
    ("file-mode-owner bits-clear group rejected", record("file-mode-owner", "/etc/shadow", "group", "bits-clear", "0077", "string")),
    ("file-mode-owner bits-clear owner_group rejected", record("file-mode-owner", "/etc/shadow", "owner_group", "bits-clear", "0077", "string")),
    ("file-mode-owner bits-clear wrong type rejected", record("file-mode-owner", "/etc/shadow", "mode", "bits-clear", 63, "integer")),
    ("file-mode-owner op rejected", record("file-mode-owner", "/etc/shadow", "mode", "contains", "0077", "string")),
    ("file-mode-owner key rejected", record("file-mode-owner", "/etc/shadow", "perm", "eq", "0640", "string")),
    ("file-mode-owner type rejected", record("file-mode-owner", "/etc/shadow", "mode", "eq", 640, "integer")),
    ("mount-option fstype accepted", record("mount-option", "/tmp", "fstype", "eq", "tmpfs", "string")),
    ("mount-option named accepted", record("mount-option", "/tmp", "option::noexec", "eq", "noexec", "string")),
    ("mount-option empty suffix rejected", record("mount-option", "/tmp", "option::", "eq", "x", "string")),
    ("mount-option key rejected", record("mount-option", "/tmp", "opt", "eq", "x", "string")),
    ("systemd accepted", record("systemd-unit-state", "auditd.service", "enabled", "eq", True, "boolean")),
    ("systemd unit rejected", record("systemd-unit-state", "auditd.svc", "enabled", "eq", True, "boolean")),
    ("systemd key rejected", record("systemd-unit-state", "auditd.service", "running", "eq", True, "boolean")),
    ("package accepted", record("package-presence", "auditd", "installed", "eq", True, "boolean")),
    ("package key rejected", record("package-presence", "auditd", "present", "eq", True, "boolean")),
    ("package locator rejected", record("package-presence", "au ditd", "installed", "eq", True, "boolean")),
    ("pam-line accepted", record("pam-line", "/etc/pam.d/common-auth", "active_line::auth", "contains", "pam_faillock", "string")),
    ("pam-line empty suffix rejected", record("pam-line", "/etc/pam.d/common-auth", "active_line::", "contains", "x", "string")),
    ("pam-line key rejected", record("pam-line", "/etc/pam.d/common-auth", "line", "contains", "x", "string")),
    ("pam-line op rejected", record("pam-line", "/etc/pam.d/common-auth", "active_line::auth", "eq", "x", "string")),
    ("audit-rule accepted", record("audit-rule", "/etc/audit/rules.d/base.rules", "any", "contains", "-w /etc/passwd", "string")),
    ("audit-rule locator rejected", record("audit-rule", "rules", "any", "contains", "-w /etc/passwd", "string")),
    ("unknown kind rejected", record("selinux-boolean", "/x", "k", "eq", "v", "string")),
    ("corporate with profile accepted", record("sysctl", "sysctl", "kernel.x", "eq", 1, "integer", layer="corporate", profile="strict")),
    ("corporate without profile rejected", record("sysctl", "sysctl", "kernel.x", "eq", 1, "integer", layer="corporate")),
    ("firewall with profile rejected", record("sysctl", "sysctl", "kernel.x", "eq", 1, "integer", layer="firewall", profile="strict")),
    ("derived without justification rejected", record("sysctl", "sysctl", "kernel.x", "eq", 1, "integer", derived=True)),
    ("derived with justification accepted", record("sysctl", "sysctl", "kernel.x", "eq", 1, "integer", derived=True, justification="engineering decision")),
    ("non-derived with justification rejected", record("sysctl", "sysctl", "kernel.x", "eq", 1, "integer", justification="unexpected")),
    ("type and value mismatch rejected", record("sysctl", "sysctl", "kernel.x", "eq", "1", "integer")),
]

# B-R2-01 boundary cases. Runtime matches patterns with re.fullmatch while
# JSON Schema `pattern` searches, and in the Python regex engine `$` also
# matches before a trailing newline. Without an explicit single-line
# assertion the two sides disagree on every one of these.
FILE_MODE_OWNER_BITS_CLEAR_EXPECTATIONS = {
    "file-mode-owner accepted": True,
    "file-mode-owner bits-clear accepted": True,
    "file-mode-owner bits-clear zero mask rejected": False,
    "file-mode-owner bits-clear short mask rejected": False,
    "file-mode-owner bits-clear non-octal rejected": False,
    "file-mode-owner bits-clear owner rejected": False,
    "file-mode-owner bits-clear group rejected": False,
    "file-mode-owner bits-clear owner_group rejected": False,
    "file-mode-owner bits-clear wrong type rejected": False,
    "file-mode-owner op rejected": False,
}

NEWLINE_CASES = [
    ("sysctl key with trailing LF", record("sysctl", "sysctl", "kernel.x\n", "eq", 1, "integer")),
    ("sysctl key with trailing CR", record("sysctl", "sysctl", "kernel.x\r", "eq", 1, "integer")),
    ("sysctl key with embedded LF", record("sysctl", "sysctl", "kernel\n.x", "eq", 1, "integer")),
    ("file-kv locator with trailing LF", record("file-kv", "/etc/f\n", "K", "eq", "v", "string")),
    ("file-mode-owner locator with LF", record("file-mode-owner", "/etc/f\n", "mode", "eq", "0600", "string")),
    ("mount-option locator with LF", record("mount-option", "/tmp\n", "fstype", "eq", "tmpfs", "string")),
    ("mount-option key with LF", record("mount-option", "/tmp", "option::noexec\n", "eq", "noexec", "string")),
    ("pam-line locator with LF", record("pam-line", "/etc/pam.d/x\n", "active_line::a", "contains", "x", "string")),
    ("pam-line key with LF", record("pam-line", "/etc/pam.d/x", "active_line::a\n", "contains", "x", "string")),
    ("audit-rule locator with LF", record("audit-rule", "/etc/audit/x.rules\n", "k", "contains", "-w /x", "string")),
    ("systemd locator with LF", record("systemd-unit-state", "x.service\n", "enabled", "eq", True, "boolean")),
    ("package locator with LF", record("package-presence", "auditd\n", "installed", "eq", True, "boolean")),
]


def _with(record_, **overrides):
    out = json.loads(json.dumps(record_))
    for dotted, value in overrides.items():
        section, field = dotted.split("__")
        out[section][field] = value
    return out


_BASE = record("sysctl", "sysctl", "kernel.x", "eq", 1, "integer")
NEWLINE_CASES += [
    ("id with trailing LF", {**json.loads(json.dumps(_BASE)), "id": "TEST.RECORD-1\n"}),
    ("index_id with trailing LF", _with(_BASE, source__index_id="SRC-0001\n")),
    ("doc_sha256 with trailing LF", _with(_BASE, source__doc_sha256="0" * 64 + "\n")),
    ("quote_sha256 with trailing LF", _with(_BASE, source__quote_sha256="1" * 64 + "\n")),
]

ALL_CASES = CASES + NEWLINE_CASES


class GenerationParityTests(unittest.TestCase):
    def test_committed_schema_is_the_generated_schema(self):
        self.assertEqual(
            SCHEMA_PATH.read_text(encoding="utf-8"),
            checker.render_control_schema(),
            "CONTROL-SCHEMA.json is not the schema derived from runtime "
            "constants; regenerate with --emit-schema",
        )

    def test_gate0_reports_parity(self):
        self.assertEqual(checker.schema_parity_errors(SCHEMA_PATH), [])

    def test_every_kind_is_covered_by_the_schema(self):
        kinds_in_schema = set(
            SCHEMA["properties"]["parameter"]["properties"]["kind"]["enum"]
        )
        self.assertEqual(kinds_in_schema, set(checker.KIND_RULES))
        branch_kinds = {
            branch["if"]["properties"]["parameter"]["properties"]["kind"]["const"]
            for branch in SCHEMA["allOf"]
            if "parameter" in branch.get("if", {}).get("properties", {})
        }
        self.assertEqual(branch_kinds, set(checker.KIND_RULES))


class DifferentialAcceptanceTests(unittest.TestCase):
    def test_runtime_and_schema_agree_on_every_case(self):
        disagreements = []
        for name, rec in ALL_CASES:
            runtime_accepts = not runtime_errors(rec)
            schema_accepts = not schema_errors(rec, SCHEMA)
            if runtime_accepts != schema_accepts:
                disagreements.append(
                    f"{name}: runtime={'accept' if runtime_accepts else 'reject'} "
                    f"schema={'accept' if schema_accepts else 'reject'}"
                )
        self.assertEqual(disagreements, [])

    def test_file_mode_owner_bits_clear_verdicts_are_explicit(self):
        by_name = dict(CASES)
        for name, expected_accept in FILE_MODE_OWNER_BITS_CLEAR_EXPECTATIONS.items():
            with self.subTest(name):
                rec = by_name[name]
                runtime_accepts = not runtime_errors(rec)
                schema_accepts = not schema_errors(rec, SCHEMA)
                self.assertEqual(
                    runtime_accepts,
                    expected_accept,
                    f"{name}: unexpected runtime verdict",
                )
                self.assertEqual(
                    schema_accepts,
                    expected_accept,
                    f"{name}: unexpected schema verdict",
                )

    def test_matrix_exercises_all_kinds_in_both_directions(self):
        kinds = {rec["parameter"]["kind"] for _, rec in ALL_CASES}
        self.assertTrue(set(checker.KIND_RULES).issubset(kinds))
        accepted = sum(1 for _, rec in ALL_CASES if not runtime_errors(rec))
        rejected = len(ALL_CASES) - accepted
        self.assertGreaterEqual(accepted, len(checker.KIND_RULES))
        self.assertGreaterEqual(rejected, len(checker.KIND_RULES))

    def test_every_newline_case_is_rejected_by_both_sides(self):
        for name, rec in NEWLINE_CASES:
            with self.subTest(name):
                self.assertTrue(runtime_errors(rec), f"{name}: runtime accepted")
                self.assertTrue(schema_errors(rec, SCHEMA), f"{name}: schema accepted")

    @unittest.skipUnless(HAVE_JSONSCHEMA,
                         "jsonschema is not installed; the emulator result stands alone")
    def test_real_draft202012_validator_agrees_with_runtime(self):
        disagreements = []
        for name, rec in ALL_CASES:
            runtime_accepts = not runtime_errors(rec)
            schema_accepts = not real_schema_errors(rec, SCHEMA)
            if runtime_accepts != schema_accepts:
                disagreements.append(
                    f"{name}: runtime={'accept' if runtime_accepts else 'reject'} "
                    f"schema={'accept' if schema_accepts else 'reject'}"
                )
        self.assertEqual(disagreements, [])

    def test_emulator_matches_real_validator_when_available(self):
        if not HAVE_JSONSCHEMA:
            self.skipTest("jsonschema is not installed")
        for name, rec in ALL_CASES:
            with self.subTest(name):
                self.assertEqual(
                    not schema_errors(rec, SCHEMA),
                    not real_schema_errors(rec, SCHEMA),
                    f"{name}: emulator disagrees with Draft202012Validator",
                )


class ParserInvariantTests(unittest.TestCase):
    """Defence in depth: a control file cannot even carry a control character
    in a scalar, so the newline class is unreachable through load_controls."""

    def test_parser_rejects_control_characters_in_scalars(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "record.yaml"
            path.write_text(
                'id: "TEST.A"\n'
                'parameter:\n'
                '  kind: "sysctl"\n'
                '  locator: "sysctl"\n'
                '  key: "kernel.x\\n"\n',
                encoding="utf-8",
            )
            with self.assertRaises(ValueError) as ctx:
                checker.parse_yaml_subset(path)
            self.assertIn("control characters", str(ctx.exception))

    def test_parser_accepts_the_same_scalar_without_control_characters(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "record.yaml"
            path.write_text(
                'id: "TEST.A"\n'
                'parameter:\n'
                '  kind: "sysctl"\n'
                '  locator: "sysctl"\n'
                '  key: "kernel.x"\n',
                encoding="utf-8",
            )
            parsed = checker.parse_yaml_subset(path)
            self.assertEqual(parsed["parameter"]["key"], "kernel.x")


class PatternSemanticsTests(unittest.TestCase):
    """fullmatch (runtime) and search (JSON Schema) must accept the same set."""

    PATTERNS = [
        "ID_PATTERN", "SHA_PATTERN", "INDEX_ID_PATTERN", "SYSCTL_KEY_PATTERN",
        "UNIT_PATTERN", "PKG_PATTERN", "ABSOLUTE_PATH_PATTERN",
        "MOUNT_OPTION_KEY_PATTERN", "PAM_LINE_KEY_PATTERN",
    ]
    SAMPLES = [
        "kernel.x", "kernel.x\n", "\nkernel.x", "kernel\n.x", "kernel.x\r",
        "/etc/f", "/etc/f\n", "TEST.A", "TEST.A\n", "SRC-0001", "SRC-0001\n",
        "0" * 64, "0" * 64 + "\n", "x.service", "x.service\n", "auditd",
        "auditd\n", "option::a", "option::a\n", "active_line::a",
        "active_line::a\n", "", " ",
    ]

    def test_fullmatch_and_search_agree_on_every_pattern(self):
        for name in self.PATTERNS:
            pattern = getattr(checker, name)
            for sample in self.SAMPLES:
                with self.subTest(pattern=name, sample=sample):
                    self.assertEqual(
                        re.fullmatch(pattern, sample) is not None,
                        re.search(pattern, sample) is not None,
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
