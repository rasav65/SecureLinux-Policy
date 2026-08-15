#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = ROOT / "checker/release-v1/real_jsonschema_gate.py"

spec = importlib.util.spec_from_file_location(
    "real_jsonschema_gate_tested", GATE_PATH
)
gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(gate)

report = gate.run_gate(ROOT)
assert report["pass"] is True, report
assert report["jsonschema_version"]
assert report["minimum_jsonschema_version"] == "4.10.3"
assert gate.parse_jsonschema_release(report["jsonschema_version"]) >= (4, 10, 3)
assert report["validator_class"] == "Draft202012Validator"
assert report["draft"] == "2020-12"
assert report["checks"]["draft202012_check_schema"] is True
assert report["checks"]["schema_generation_parity"] is True
assert report["checks"]["runtime_real_parity"] is True
assert report["checks"]["emulator_real_parity"] is True
assert report["checks"]["all_kinds_bidirectional"] is True
assert report["matrix"]["total_cases"] >= 50
assert report["matrix"]["newline_cases"] >= 16
assert report["matrix"]["runtime_real_disagreements"] == []
assert report["matrix"]["emulator_real_disagreements"] == []
assert report["matrix"]["missing_kinds"] == []
assert report["matrix"]["one_sided_kinds"] == []

expected_active = len(list((ROOT / "controls").rglob("*.yaml")))
assert report["active_controls"]["count"] == expected_active
assert report["active_controls"]["runtime_invalid"] == []
assert report["active_controls"]["real_schema_invalid"] == []


def missing(_root):
    raise RuntimeError("simulated jsonschema absence")


negative = gate.run_gate(ROOT, dependency_loader=missing)
assert negative["pass"] is False
assert negative["jsonschema_version"] is None
assert any(
    "simulated jsonschema absence" in err
    for err in negative["errors"]
)

real_validator, _real_version = gate.require_real_jsonschema(ROOT)

def below_minimum(_root):
    return real_validator, "4.10.2"

negative_version = gate.run_gate(ROOT, dependency_loader=below_minimum)
assert negative_version["pass"] is False
assert negative_version["jsonschema_version"] is None
assert any(
    "below minimum supported 4.10.3" in err
    for err in negative_version["errors"]
)

print(
    "REAL_JSONSCHEMA_RELEASE_TESTS=PASS "
    f"version={report['jsonschema_version']} "
    "positive=1 negative_missing_dependency=1 negative_below_minimum=1"
)
