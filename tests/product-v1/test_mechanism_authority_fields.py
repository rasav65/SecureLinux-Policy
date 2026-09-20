#!/usr/bin/env python3
"""APPLY mechanism authority documents carry only fields that code reads.

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY
HOST_MUTATION=false

Prose and unread structure do not belong in authority. The apply semantic
contract schema v2 is not read by code and must be absent.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

CONFIG_LINE_AUTHORITY = ROOT / "product/contracts/mechanism-config-line-runtime-v1.json"
FILE_MODE_AUTHORITY = ROOT / "product/contracts/mechanism-file-mode-owner-v1.json"
OPTIONAL_ROOT_AUTHORITY = ROOT / "product/contracts/mechanism-optional-file-root-files-mode-v1.json"
SUID_SGID_AUTHORITY = ROOT / "product/contracts/mechanism-suid-sgid-applications-mode-v1.json"
STANDARD_PATHS_AUTHORITY = ROOT / "product/contracts/mechanism-standard-system-paths-mode-v1.json"
SCHEMA_V2 = ROOT / "product/contracts/apply-semantic-contract-v2.schema.json"

# Expected field sets are literals: they change only by explicit decision,
# together with the code that reads the new field.
CONFIG_LINE_TOP_LEVEL = {"authority_form", "mechanism_id", "registry_binding"}
FILE_MODE_TOP_LEVEL = {
    "authority_form", "mechanism_id", "apply_kind", "registry_binding", "mutation",
}
FILE_MODE_MUTATION = {"allowed_paths"}
OPTIONAL_ROOT_TOP_LEVEL = {"authority_form", "mechanism_id", "registry_binding"}
SUID_SGID_TOP_LEVEL = {"authority_form", "mechanism_id", "registry_binding"}
STANDARD_PATHS_TOP_LEVEL = {"authority_form", "mechanism_id", "registry_binding"}


def load(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise AssertionError(f"{path.relative_to(ROOT)}: object required")
    return doc


class MechanismAuthorityFields(unittest.TestCase):
    def assert_keys(self, label: str, actual, expected: set[str]) -> None:
        self.assertIsInstance(actual, dict, f"{label}: object required")
        keys = set(actual)
        extra = sorted(keys - expected)
        missing = sorted(expected - keys)
        self.assertFalse(
            extra or missing,
            f"{label}: extra={extra} missing={missing}",
        )

    def test_config_line_authority_top_level(self):
        doc = load(CONFIG_LINE_AUTHORITY)
        self.assert_keys(
            "mechanism-config-line-runtime-v1.json", doc, CONFIG_LINE_TOP_LEVEL
        )

    def test_file_mode_authority_top_level(self):
        doc = load(FILE_MODE_AUTHORITY)
        self.assert_keys(
            "mechanism-file-mode-owner-v1.json", doc, FILE_MODE_TOP_LEVEL
        )

    def test_file_mode_authority_mutation(self):
        doc = load(FILE_MODE_AUTHORITY)
        self.assert_keys(
            "mechanism-file-mode-owner-v1.json:mutation",
            doc.get("mutation"),
            FILE_MODE_MUTATION,
        )

    def test_optional_root_authority_top_level(self):
        doc = load(OPTIONAL_ROOT_AUTHORITY)
        self.assert_keys(
            "mechanism-optional-file-root-files-mode-v1.json", doc, OPTIONAL_ROOT_TOP_LEVEL
        )

    def test_suid_sgid_authority_top_level(self):
        doc = load(SUID_SGID_AUTHORITY)
        self.assert_keys(
            "mechanism-suid-sgid-applications-mode-v1.json", doc, SUID_SGID_TOP_LEVEL
        )

    def test_standard_paths_authority_top_level(self):
        doc = load(STANDARD_PATHS_AUTHORITY)
        self.assert_keys(
            "mechanism-standard-system-paths-mode-v1.json", doc, STANDARD_PATHS_TOP_LEVEL
        )

    def test_schema_v2_absent(self):
        self.assertFalse(
            SCHEMA_V2.exists(),
            "product/contracts/apply-semantic-contract-v2.schema.json must be absent",
        )


if __name__ == "__main__":
    unittest.main()
