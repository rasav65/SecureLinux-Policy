#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests/run-all.py"

spec = importlib.util.spec_from_file_location("slp_run_all", RUNNER)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

assert mod.release_rc(dev_ok=True, env_ok=True, release_ok=True) == 0
assert mod.release_rc(dev_ok=False, env_ok=True, release_ok=True) == 1
assert mod.release_rc(dev_ok=True, env_ok=True, release_ok=False) == 2
assert mod.release_rc(dev_ok=True, env_ok=False, release_ok=False) == 3

assert mod.parse_version("4.10.3") == (4, 10, 3)
assert mod.parse_version("4.25.1.post1") == (4, 25, 1)
assert mod.parse_version("unknown") is None

assert mod.DEV_EXPECTED_INTERNAL_SKIPS == {
    "tests/gates-v3/test_schema_runtime_parity.py": 2,
}
assert mod.expected_internal_skips("tests/gates-v3/test_schema_runtime_parity.py") == 2
assert mod.expected_internal_skips("tests/product-v1/test_file_mode_owner_adapter.py") == 0
assert mod.expected_internal_skips("tests/product-v1/test_product_generator.py") == 0

print("RUN_ALL_SELFTEST=PASS release_rc=0/1/2/3 version_parser=3 skip_policy=3")
