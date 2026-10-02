#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "checker/gates-v3/checker.py"

spec = importlib.util.spec_from_file_location("checker_v3", CHECKER)
checker = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(checker)


def rec(kind, typ, value):
    return {
        "parameter": {"kind": kind},
        "expected": {"type": typ, "value": value},
    }


assert checker.KIND_RULES["sysctl"]["type"] == {"enum": ["integer", "string"]}
assert checker.KIND_RULES["systemd-unit-state"]["type"] == {"const": "boolean"}
assert checker.KIND_RULES["package-presence"]["type"] == {"const": "boolean"}

assert checker._expected_compliance(rec("sysctl", "integer", 1), "1") == "PASS"
assert checker._expected_compliance(rec("sysctl", "integer", 1), "2") == "FAIL"
assert checker._expected_compliance(rec("sysctl", "integer", 1), 1) is None
assert checker._expected_compliance(rec("sysctl", "string", "on"), "on") == "PASS"
assert checker._expected_compliance(rec("sysctl", "boolean", True), "true") is None
assert checker._expected_compliance(rec("sysctl", "boolean", True), True) is None

assert checker.OBSERVATION_VALUE_CONTRACTS["systemd-unit-state"] == {
    "runner_status": "not-implemented",
    "encodings": {"boolean": "json-boolean"},
}
assert checker.OBSERVATION_VALUE_CONTRACTS["package-presence"] == {
    "runner_status": "not-implemented",
    "encodings": {"boolean": "json-boolean"},
}
assert checker._expected_compliance(
    rec("systemd-unit-state", "boolean", True), True
) == "PASS"
assert checker._expected_compliance(
    rec("systemd-unit-state", "boolean", True), False
) == "FAIL"
assert checker._expected_compliance(
    rec("systemd-unit-state", "boolean", True), "true"
) is None
assert checker._expected_compliance(
    rec("systemd-unit-state", "boolean", False), 0
) is None
assert checker._expected_compliance(
    rec("package-presence", "boolean", True), True
) == "PASS"
assert checker._expected_compliance(
    rec("package-presence", "boolean", True), "true"
) is None

assert checker.DEFERRED_OBSERVATION_VALUE_CONTRACTS["file-kv"]["boolean"] == (
    "UNDEFINED_UNTIL_FILE_KV_PROBE_DESIGN"
)
assert checker._expected_compliance(rec("file-kv", "boolean", True), True) is None
assert checker._expected_compliance(rec("file-kv", "boolean", True), "true") is None

source = CHECKER.read_text(encoding="utf-8")
assert 'raw_value == "true"' not in source
assert 'raw_value == "false"' not in source

print("TYPE_BOOLEAN_CONTRACT_TESTS=PASS cases=18")
