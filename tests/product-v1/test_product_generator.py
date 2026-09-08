#!/usr/bin/env python3
"""product-v1 tests for the tracked unified product CLI generator."""
import ast
import contextlib
import errno
import io
import hashlib
import importlib.util
import json
import os
import re
import shutil
import shlex
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = ROOT / "product" / "generate-product-check-v2.py"
FILESET_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-optional-file-root-files-mode-check-v1.py"
SHADOW_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-local-account-password-state-check-v2.py"
USER_CRON_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-user-cron-files-mode-check-v2.py"
STANDARD_PATHS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-standard-system-paths-mode-check-v2.py"
SUID_SGID_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-suid-sgid-applications-check-v2.py"
HOME_SENSITIVE_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-home-sensitive-files-mode-check-v2.py"
HOME_DIRECTORIES_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-home-directories-mode-check-v2.py"
SSHD_ROOT_LOGIN_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-sshd-root-login-check-v1.py"
PAM_WHEEL_ACCESS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-pam-wheel-access-check-v2.py"
SUDOERS_REVIEWED_POLICY_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-sudoers-reviewed-policy-check-v1.py"
TESTED_SETTING_ATTESTATION_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-tested-setting-attestation-check-v1.py"
RUNNING_PROCESS_PATHS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-running-process-paths-write-protection-check-v1.py"
CRON_COMMAND_PATHS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-cron-command-paths-write-protection-check-v1.py"
SUDO_ROOT_COMMAND_FILES_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-sudo-root-command-files-protection-check-v1.py"
STARTUP_FILES_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-startup-files-write-protection-check-v1.py"
BASH = shutil.which("bash")

ERROR_REASON_RE = re.compile(r"^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$")

def assert_stable_error_record(testcase, text, expected_control=None, expected_reason=None):
    lines = [line for line in text.strip().splitlines() if line]
    testcase.assertTrue(lines, text)
    matches = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) == 5 and fields[0] == "SLP-CHECK-V1" and fields[2] == "ERROR" and fields[4] == "ERROR":
            testcase.assertRegex(fields[3], ERROR_REASON_RE)
            testcase.assertNotEqual(fields[3], "-")
            matches.append(fields)
    testcase.assertTrue(matches, text)
    if expected_control is not None:
        testcase.assertTrue(any(fields[1] == expected_control for fields in matches), text)
    if expected_reason is not None:
        testcase.assertTrue(any(fields[3] == expected_reason for fields in matches), text)


def load_generator():
    spec = importlib.util.spec_from_file_location("slp_product_generator", GEN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GEN = load_generator()


def load_generator_v2():
    path = ROOT / "product/generate-product-check-v2.py"
    spec = importlib.util.spec_from_file_location("slp_product_generator_v2", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GEN_V2_CURRENT = load_generator_v2()


def load_fileset_adapter():
    spec = importlib.util.spec_from_file_location("slp_fileset_adapter", FILESET_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FILESET = load_fileset_adapter()

def load_shadow_adapter():
    spec = importlib.util.spec_from_file_location("slp_shadow_adapter", SHADOW_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

SHADOW = load_shadow_adapter()

def load_user_cron_adapter():
    spec = importlib.util.spec_from_file_location("slp_user_cron_adapter", USER_CRON_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

USER_CRON = load_user_cron_adapter()

def load_standard_paths_adapter():
    spec = importlib.util.spec_from_file_location("slp_standard_paths_adapter", STANDARD_PATHS_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

STANDARD_PATHS = load_standard_paths_adapter()

def load_suid_sgid_adapter():
    spec = importlib.util.spec_from_file_location("slp_suid_sgid_adapter", SUID_SGID_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

SUID_SGID = load_suid_sgid_adapter()

def load_home_sensitive_adapter():
    spec = importlib.util.spec_from_file_location("slp_home_sensitive_adapter", HOME_SENSITIVE_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

HOME_SENSITIVE = load_home_sensitive_adapter()

def load_home_directories_adapter():
    spec = importlib.util.spec_from_file_location("slp_home_directories_adapter", HOME_DIRECTORIES_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

HOME_DIRECTORIES = load_home_directories_adapter()

def load_sshd_root_login_adapter():
    spec = importlib.util.spec_from_file_location("slp_sshd_root_login_adapter", SSHD_ROOT_LOGIN_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

SSHD_ROOT_LOGIN = load_sshd_root_login_adapter()


def load_pam_wheel_access_adapter():
    spec = importlib.util.spec_from_file_location("slp_pam_wheel_access_adapter", PAM_WHEEL_ACCESS_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PAM_WHEEL_ACCESS = load_pam_wheel_access_adapter()

def load_sudoers_reviewed_policy_adapter():
    spec = importlib.util.spec_from_file_location("slp_sudoers_reviewed_policy_adapter", SUDOERS_REVIEWED_POLICY_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

SUDOERS_REVIEWED_POLICY = load_sudoers_reviewed_policy_adapter()

def load_tested_setting_attestation_adapter():
    spec = importlib.util.spec_from_file_location("slp_tested_setting_attestation_adapter", TESTED_SETTING_ATTESTATION_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

TESTED_SETTING_ATTESTATION = load_tested_setting_attestation_adapter()

def load_running_process_paths_adapter():
    spec = importlib.util.spec_from_file_location("slp_running_process_paths_adapter", RUNNING_PROCESS_PATHS_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

RUNNING_PROCESS_PATHS = load_running_process_paths_adapter()

def load_cron_command_paths_adapter():
    spec = importlib.util.spec_from_file_location("slp_cron_command_paths_adapter", CRON_COMMAND_PATHS_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

CRON_COMMAND_PATHS = load_cron_command_paths_adapter()

def load_sudo_root_command_files_adapter():
    spec = importlib.util.spec_from_file_location("slp_sudo_root_command_files_adapter", SUDO_ROOT_COMMAND_FILES_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

SUDO_ROOT_COMMAND_FILES = load_sudo_root_command_files_adapter()

def load_startup_files_adapter():
    spec = importlib.util.spec_from_file_location("slp_startup_files_adapter", STARTUP_FILES_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

STARTUP_FILES = load_startup_files_adapter()


def load_current():
    rows, manifest_sha = GEN.load_manifest(ROOT)
    adapters, registry_sha = GEN.load_registry(ROOT)
    controls = [GEN.load_control(ROOT, row) for row in rows]
    return rows, manifest_sha, adapters, registry_sha, controls


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class GeneratorModel(unittest.TestCase):
    def load_current(self):
        return load_current()

    def test_current_population_and_registry(self):
        rows, manifest_sha, adapters, registry_sha, controls = self.load_current()
        self.assertEqual(len(rows), len(controls))
        self.assertGreaterEqual(len(controls), 8)
        self.assertTrue({"sysctl", "file-mode-owner", "kernel-cmdline", "optional-file-root-files-mode", "local-account-password-state", "user-cron-files-mode", "standard-system-paths-mode", "running-process-paths-write-protection", "cron-command-paths-write-protection", "suid-sgid-applications", "home-sensitive-files-mode", "home-directories-mode", "sshd-root-login", "pam-wheel-access", "sudoers-reviewed-policy", "sudo-root-command-files-protection", "startup-files-write-protection", "tested-setting-attestation"} <= set(adapters))
        self.assertEqual({c["parameter_kind"] for c in controls}, {"sysctl", "file-mode-owner", "kernel-cmdline", "optional-file-root-files-mode", "local-account-password-state", "user-cron-files-mode", "standard-system-paths-mode", "running-process-paths-write-protection", "cron-command-paths-write-protection", "suid-sgid-applications", "home-sensitive-files-mode", "home-directories-mode", "sshd-root-login", "pam-wheel-access", "sudoers-reviewed-policy", "sudo-root-command-files-protection", "startup-files-write-protection", "tested-setting-attestation"})
        src0002 = [c for c in controls if c["index_id"] == "SRC-0002"]
        self.assertEqual(len(src0002), 1)
        self.assertEqual(
            (src0002[0]["parameter_kind"], src0002[0]["parameter_locator"], src0002[0]["parameter_key"], src0002[0]["expected_op"], src0002[0]["expected_value"]),
            ("sshd-root-login", "/etc/ssh/sshd_config", "PermitRootLogin", "eq", "no"),
        )
        src0003 = [c for c in controls if c["index_id"] == "SRC-0003"]
        self.assertEqual(len(src0003), 1)
        self.assertEqual(
            (src0003[0]["parameter_kind"], src0003[0]["parameter_locator"], src0003[0]["parameter_key"], src0003[0]["expected_op"], src0003[0]["expected_value"]),
            ("pam-wheel-access", "/etc/pam.d/su|/etc/group", "policy", "eq-authority-file", "/etc/securelinux-policy/wheel-users.allowlist-v1"),
        )
        src0004 = [c for c in controls if c["index_id"] == "SRC-0004"]
        self.assertEqual(len(src0004), 1)
        self.assertEqual(
            (src0004[0]["parameter_kind"], src0004[0]["parameter_locator"], src0004[0]["parameter_key"], src0004[0]["expected_op"], src0004[0]["expected_value"]),
            ("sudoers-reviewed-policy", "/etc/sudoers", "policy-tree", "eq-reviewed-policy", "/etc/securelinux-policy/sudoers-reviewed-policy-v1"),
        )
        src0006 = [c for c in controls if c["index_id"] == "SRC-0006"]
        self.assertEqual(len(src0006), 1)
        self.assertEqual(
            (src0006[0]["parameter_kind"], src0006[0]["parameter_locator"], src0006[0]["parameter_key"], src0006[0]["expected_op"], src0006[0]["expected_value"]),
            ("running-process-paths-write-protection", "/proc/<pid>/exe|/proc/<pid>/maps", "write-protection", "runtime-paths-safe", "file-go-w;parent-unprivileged-write-denied"),
        )
        src0008 = [c for c in controls if c["index_id"] == "SRC-0008"]
        self.assertEqual(len(src0008), 1)
        self.assertEqual(
            (src0008[0]["parameter_kind"], src0008[0]["parameter_locator"], src0008[0]["parameter_key"], src0008[0]["expected_op"], src0008[0]["expected_value"]),
            ("sudo-root-command-files-protection", "/etc/sudoers|/etc/securelinux-policy/sudoers-reviewed-policy-v1", "root-command-files", "root-owned-go-w", "uid0;bits-clear-0022"),
        )
        src0009 = [c for c in controls if c["index_id"] == "SRC-0009"]
        self.assertEqual(len(src0009), 1)
        self.assertEqual(
            (src0009[0]["parameter_kind"], src0009[0]["parameter_locator"], src0009[0]["parameter_key"], src0009[0]["expected_op"], src0009[0]["expected_value"]),
            ("startup-files-write-protection", "/etc/rc[0-6].d|systemd-unit-paths", "other-write", "bits-clear", "0002"),
        )
        src0001 = [c for c in controls if c["index_id"] == "SRC-0001"]
        self.assertEqual(len(src0001), 1)
        self.assertEqual(
            (src0001[0]["parameter_kind"], src0001[0]["parameter_locator"], src0001[0]["parameter_key"], src0001[0]["expected_op"], src0001[0]["expected_value"]),
            ("local-account-password-state", "/etc/shadow", "password-field", "all-nonempty", True),
        )
        src0010 = [c for c in controls if c["index_id"] == "SRC-0010"]
        self.assertEqual(len(src0010), 6)
        self.assertEqual(
            {c["parameter_locator"] for c in src0010},
            {"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"},
        )
        self.assertTrue(all(c["parameter_kind"] == "optional-file-root-files-mode" for c in src0010))
        self.assertTrue(all(c["parameter_key"] == "mode" and c["expected_op"] == "bits-clear" and c["expected_value"] == "0033" for c in src0010))
        src0011 = [c for c in controls if c["index_id"] == "SRC-0011"]
        self.assertEqual(len(src0011), 1)
        self.assertEqual(
            (src0011[0]["parameter_kind"], src0011[0]["parameter_locator"], src0011[0]["parameter_key"], src0011[0]["expected_op"], src0011[0]["expected_value"]),
            ("user-cron-files-mode", "/var/spool/cron/crontabs", "mode", "bits-clear", "0022"),
        )
        src0012 = [c for c in controls if c["index_id"] == "SRC-0012"]
        self.assertEqual(len(src0012), 1)
        self.assertEqual(
            (src0012[0]["parameter_kind"], src0012[0]["parameter_locator"], src0012[0]["parameter_key"], src0012[0]["expected_op"], src0012[0]["expected_value"]),
            ("standard-system-paths-mode", "/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>", "mode", "bits-clear", "0022"),
        )
        src0013 = [c for c in controls if c["index_id"] == "SRC-0013"]
        self.assertEqual(len(src0013), 2)
        self.assertEqual(
            {(c["parameter_kind"], c["parameter_locator"], c["parameter_key"], c["expected_op"], c["expected_value"]) for c in src0013},
            {
                ("suid-sgid-applications", "/proc/self/mountinfo", "mode", "bits-clear", "0022"),
                ("suid-sgid-applications", "/proc/self/mountinfo", "approved-set", "subset-of-file", "/etc/securelinux-policy/suid-sgid.allowlist-v1"),
            },
        )
        src0014 = [c for c in controls if c["index_id"] == "SRC-0014"]
        self.assertEqual(len(src0014), 1)
        self.assertEqual(
            (src0014[0]["parameter_kind"], src0014[0]["parameter_locator"], src0014[0]["parameter_key"], src0014[0]["expected_op"], src0014[0]["expected_value"]),
            ("home-sensitive-files-mode", "/etc/passwd|/etc/securelinux-policy/home-sensitive-files-v1", "mode", "bits-clear", "0077"),
        )
        src0015 = [c for c in controls if c["index_id"] == "SRC-0015"]
        self.assertEqual(len(src0015), 1)
        self.assertEqual(
            (src0015[0]["parameter_kind"], src0015[0]["parameter_locator"], src0015[0]["parameter_key"], src0015[0]["expected_op"], src0015[0]["expected_value"]),
            ("home-directories-mode", "/etc/passwd", "mode", "eq", "0700"),
        )
        src0005 = [c for c in controls if c["index_id"] == "SRC-0005"]
        self.assertEqual(len(src0005), 3)
        self.assertEqual(
            {(c["parameter_locator"], c["parameter_key"], c["expected_op"], c["expected_value"]) for c in src0005},
            {
                ("/etc/passwd", "mode", "eq", "0644"),
                ("/etc/group", "mode", "eq", "0644"),
                ("/etc/shadow", "mode", "bits-clear", "0077"),
            },
        )
        exact_eq_batch = {
            c["index_id"]: (
                c["parameter_locator"],
                c["parameter_key"],
                c["expected_op"],
                c["expected_value"],
            )
            for c in controls
            if c["index_id"] in {"SRC-0030", "SRC-0031", "SRC-0036", "SRC-0037", "SRC-0038", "SRC-0039"}
        }
        self.assertEqual(
            exact_eq_batch,
            {
                "SRC-0030": ("sysctl", "vm.unprivileged_userfaultfd", "eq", 0),
                "SRC-0031": ("sysctl", "dev.tty.ldisc_autoload", "eq", 0),
                "SRC-0036": ("sysctl", "fs.protected_symlinks", "eq", 1),
                "SRC-0037": ("sysctl", "fs.protected_hardlinks", "eq", 1),
                "SRC-0038": ("sysctl", "fs.protected_fifos", "eq", 2),
                "SRC-0039": ("sysctl", "fs.protected_regular", "eq", 2),
            },
        )
        src0033 = [c for c in controls if c["index_id"] == "SRC-0033"]
        self.assertEqual(len(src0033), 1)
        self.assertEqual(
            (
                src0033[0]["parameter_locator"],
                src0033[0]["parameter_key"],
                src0033[0]["expected_op"],
                src0033[0]["expected_value"],
            ),
            ("sysctl", "vm.mmap_min_addr", "ge", 4096),
        )
        src0034 = [c for c in controls if c["index_id"] == "SRC-0034"]
        self.assertEqual(len(src0034), 2)
        self.assertEqual(
            {(c["parameter_kind"], c["parameter_locator"], c["parameter_key"], c["expected_op"], c["expected_value"]) for c in src0034},
            {
                ("sysctl", "sysctl", "kernel.randomize_va_space", "eq", 2),
                ("tested-setting-attestation", "/etc/securelinux-policy/tested-setting-attestations-v1", "SRC-0034", "tested-before-use", "kernel.randomize_va_space=2"),
            },
        )
        src0040 = [c for c in controls if c["index_id"] == "SRC-0040"]
        self.assertEqual(len(src0040), 1)
        self.assertEqual(
            (
                src0040[0]["parameter_locator"],
                src0040[0]["parameter_key"],
                src0040[0]["expected_op"],
                src0040[0]["expected_value"],
            ),
            ("sysctl", "fs.suid_dumpable", "eq", 0),
        )
        self.assertEqual(
            [c["index_id"] for c in controls if c["parameter_kind"] == "sysctl" and c["expected_op"] == "ge"],
            ["SRC-0033"],
        )
        kernel_rows = {
            c["control_id"]: (
                c["index_id"],
                c["parameter_locator"],
                c["parameter_key"],
                c["expected_op"],
                c["expected_value"],
            )
            for c in controls
            if c["parameter_kind"] == "kernel-cmdline"
        }
        self.assertEqual(
            kernel_rows,
            {
                "FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC": ("SRC-0018", "/proc/cmdline", "init_on_alloc", "eq", "1"),
                "FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE": ("SRC-0019", "/proc/cmdline", "slab_nomerge", "present", True),
                "FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE": ("SRC-0020", "/proc/cmdline", "iommu", "eq", "force"),
                "FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT": ("SRC-0020", "/proc/cmdline", "iommu.strict", "eq", "1"),
                "FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH": ("SRC-0020", "/proc/cmdline", "iommu.passthrough", "eq", "0"),
                "FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET": ("SRC-0021", "/proc/cmdline", "randomize_kstack_offset", "eq", "1"),
                "FSTEC-LINUX-2022-2.4.7-MITIGATIONS": ("SRC-0022", "/proc/cmdline", "mitigations", "eq", "auto,nosmt"),
                "FSTEC-LINUX-2022-2.5.1-VSYSCALL": ("SRC-0024", "/proc/cmdline", "vsyscall", "eq", "none"),
                "FSTEC-LINUX-2022-2.5.3-DEBUGFS": ("SRC-0026", "/proc/cmdline", "debugfs", "one-of", "off|no-mount"),
                "FSTEC-LINUX-2022-2.5.9-TSX": ("SRC-0032", "/proc/cmdline", "tsx", "eq", "off"),
            },
        )
        self.assertEqual(
            manifest_sha,
            sha256_file(ROOT / "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv"),
        )
        self.assertEqual(registry_sha, sha256_file(ROOT / "product/ADAPTER-REGISTRY.tsv"))

    def test_active_semantic_contract_error_values_and_historical_v1_status(self):
        lines = (ROOT / "product/ADAPTER-REGISTRY.tsv").read_text(encoding="utf-8").splitlines()
        header = lines[0].split("\t")
        active_paths = {
            dict(zip(header, line.split("\t")))["semantic_contract_path"]
            for line in lines[1:]
            if line
        }

        error_value_count = 0

        def inspect(value):
            nonlocal error_value_count
            if isinstance(value, dict):
                if value.get("status") == "ERROR" and "value" in value:
                    error_value_count += 1
                    self.assertEqual(value["value"], "<domain>:<reason>")
                for nested in value.values():
                    inspect(nested)
            elif isinstance(value, list):
                for nested in value:
                    inspect(nested)

        for relative in active_paths:
            contract = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            inspect(contract)
            wire_values = contract.get("wire_values", {})
            if "error" in wire_values:
                self.assertNotEqual(wire_values["error"], "-")

        self.assertEqual(error_value_count, 10)
        historical = {
            "product/contracts/sysctl-check-semantic-v1.json",
            "product/contracts/kernel-cmdline-check-semantic-v1.json",
            "product/contracts/local-account-password-state-check-semantic-v1.json",
        }
        self.assertTrue(historical.isdisjoint(active_paths))
        for relative in historical:
            contract = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            self.assertEqual(contract.get("lifecycle_status"), "HISTORICAL_UNREGISTERED")

    def test_render_is_deterministic(self):
        _, manifest_sha, adapters, registry_sha, controls = self.load_current()
        generator_sha = sha256_file(GEN_PATH)
        one = GEN.render_script(controls, adapters, manifest_sha, registry_sha, generator_sha)
        two = GEN.render_script(controls, adapters, manifest_sha, registry_sha, generator_sha)
        self.assertEqual(one, two)
        self.assertIn(f"CONTROL_COUNT={len(controls)}".encode("ascii"), one)
        self.assertIn(f"ADAPTER_COUNT={len(adapters)}".encode("ascii"), one)
        self.assertIn(b"TOTAL=%d", one)
        self.assertIn(b"SLP-APPLY-REPORT-V1", one)
        for c in controls:
            self.assertGreaterEqual(one.count(c["control_id"].encode("utf-8")), 2)

    def test_file_mode_dispatch_is_supported(self):
        _, manifest_sha, adapters, registry_sha, controls = self.load_current()
        sample = dict(controls[0])
        sample.update(
            {
                "control_id": "TEST-FILE-MODE",
                "parameter_kind": "file-mode-owner",
                "parameter_locator": "/etc/shadow",
                "parameter_key": "mode",
                "expected_op": "bits-clear",
                "expected_value": "0077",
                "expected_type": "string",
            }
        )
        rendered = GEN.render_script(
            [sample],
            adapters,
            manifest_sha,
            registry_sha,
            sha256_file(GEN_PATH),
        )
        self.assertIn(b"/usr/bin/stat -L -c %a", rendered)
        self.assertIn(b"8#$_slp_mode & 8#$_slp_expected", rendered)
        self.assertIn(b'"parameter_kind":"file-mode-owner"', rendered)

    def test_kernel_cmdline_adapter_selftest_and_render(self):
        adapter_path = ROOT / "product/adapters/product-kernel-cmdline-check-v2.py"
        cp = subprocess.run(
            [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B", str(adapter_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stderr, "")
        self.assertIn("ADAPTER_SELFTEST=PASS", cp.stdout)

        _, manifest_sha, adapters, registry_sha, controls = self.load_current()
        sample = next(c for c in controls if c["parameter_kind"] == "kernel-cmdline")
        rendered = GEN.render_script(
            [sample],
            adapters,
            manifest_sha,
            registry_sha,
            sha256_file(GEN_PATH),
        )
        self.assertIn(b"/proc/cmdline", rendered)
        self.assertIn(b"read -r -a _slp_tokens", rendered)
        self.assertIn(b'"parameter_kind":"kernel-cmdline"', rendered)

        one = next(c for c in controls if c["index_id"] == "SRC-0026")
        rendered_one = GEN.render_script(
            [one], adapters, manifest_sha, registry_sha, sha256_file(GEN_PATH)
        )
        self.assertIn(b"IFS='|' read -r -a _slp_choices", rendered_one)
        self.assertIn(b"off|no-mount", rendered_one)

        spec = importlib.util.spec_from_file_location("slp_kernel_cmdline_v2_raw", adapter_path)
        cmdline = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cmdline)
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            target = Path(td) / "cmdline"
            target.write_bytes(b"init_on_alloc=1\x00\n")
            block = cmdline.shell_function("CMD.RAW", "/proc/cmdline", "init_on_alloc", "eq", "1")
            block = block.replace(repr("/proc/cmdline"), repr(str(target)), 1)
            cp = subprocess.run(
                [BASH, "-c", "set -u\n" + block + "\nslp_check_CMD_RAW\n"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            self.assertEqual(cp.stdout.strip().split("\t")[2:], ["ERROR", "cmdline:invalid-bytes", "ERROR"])

    def test_kernel_cmdline_v2_preserves_v1_eq_present_model(self):
        def load_adapter(name, filename):
            path = ROOT / "product" / "adapters" / filename
            spec = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod

        v1 = load_adapter("slp_kernel_cmdline_v1", "product-kernel-cmdline-check-v1.py")
        v2 = load_adapter("slp_kernel_cmdline_v2", "product-kernel-cmdline-check-v2.py")
        cases = [
            (["init_on_alloc=1"], "init_on_alloc", "eq", "1"),
            (["init_on_alloc=0"], "init_on_alloc", "eq", "1"),
            ([], "init_on_alloc", "eq", "1"),
            (["iommu=force", "iommu=force"], "iommu", "eq", "force"),
            (["iommu=force", "iommu=pt"], "iommu", "eq", "force"),
            (["iommu", "iommu=force"], "iommu", "eq", "force"),
            (["slab_nomerge"], "slab_nomerge", "present", True),
            ([], "slab_nomerge", "present", True),
            (["slab_nomerge=1"], "slab_nomerge", "present", True),
        ]
        for case in cases:
            current = v2._model(*case)
            historical = v1._model(*case)
            self.assertEqual(current[0], historical[0], case)
            self.assertEqual(current[2], historical[2], case)
            if historical[2] == "ERROR":
                expected_reason = "cmdline:unexpected-value-form" if case[2] == "present" else "cmdline:ambiguous-value"
                self.assertEqual(current[1], expected_reason, case)
            else:
                self.assertEqual(current, historical, case)

    def test_error_reason_sources_do_not_collapse_distinct_failure_modes(self):
        forbidden = (
            "cron:observation-failed", "cron:discovery-failed",
            "startup:observation-failed", "target:observation-failed",
            "path:observation-failed", "scan:execution-failed",
            "sudo-policy:unsupported-semantics",
            "proc:invalid-stat", "proc:invalid-counter", "proc:invalid-population",
            "proc:ambiguous-no-exe", "proc:invalid-maps", "proc:invalid-exe",
            "observation:process-changed",
            "input:unreadable", "input:read-failed", "input:invalid-bytes",
            "pam:symlink-input", "pam:unreadable-input",
            '"population:incomplete"', '"cron-root:ancestor-invalid"',
            '"sshd-config:parse-failed"',
        )
        for path in sorted((ROOT / "product/adapters").glob("product-*.py")):
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, text, f"{path}: {marker}")

    def test_error_reason_object_state_and_stage_pairs_are_distinct(self):
        expected = {
            "product-home-directories-mode-check-v2.py": (
                ('[[ -L "$_slp_passwd" ]]', '"passwd:symlink"'),
                ('[[ ! -e "$_slp_passwd" ]]', '"passwd:not-found"'),
                ('[[ ! -f "$_slp_passwd" ]]', '"passwd:invalid-type"'),
                ('[[ ! -r "$_slp_passwd" ]]', '"passwd:unreadable"'),
                ('[[ -L "$_slp_home" ]]', '"home:symlink"'),
                ('[[ ! -d "$_slp_home" ]]', '"home:invalid-type"'),
            ),
            "product-home-sensitive-files-mode-check-v2.py": (
                ('[[ ! -r "$_slp_home" ]]', '"home:unreadable"'),
                ('[[ ! -x "$_slp_home" ]]', '"home:unsearchable"'),
                ('[[ -L "$_slp_entry" ]]', '"target:symlink"'),
            ),
            "product-optional-file-root-files-mode-check-v1.py": (
                ('[[ -L "$_slp_path" ]]', '"root:symlink"'),
                ('[[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]', '"root:parent-not-found"'),
                ('[[ ! -d "$_slp_parent" ]]', '"root:parent-invalid-type"'),
                ('[[ ! -x "$_slp_parent" ]]', '"root:parent-unsearchable"'),
                ('"root:state-changed"', '"root:state-changed"'),
            ),
            "product-standard-system-paths-mode-check-v2.py": (
                ('_slp_exec == 0', '"population:missing-exec"'),
                ('_slp_libraries == 0', '"population:missing-libraries"'),
                ('_slp_modules == 0', '"population:missing-modules"'),
            ),
            "product-suid-sgid-applications-check-v2.py": (
                ('[[ -L "$_slp_mountinfo" ]]', '"mountinfo:symlink"'),
                ('[[ ! -e "$_slp_mountinfo" ]]', '"mountinfo:not-found"'),
                ('[[ ! -f "$_slp_mountinfo" ]]', '"mountinfo:invalid-type"'),
                ('[[ ! -r "$_slp_mountinfo" ]]', '"mountinfo:unreadable"'),
            ),
            "product-user-cron-files-mode-check-v2.py": (
                ('[[ -L "$_slp_probe" ]]', '"cron-root:ancestor-symlink"'),
                ('[[ ! -d "$_slp_probe" ]]', '"cron-root:ancestor-invalid-type"'),
                ('[[ ! -x "$_slp_probe" ]]', '"cron-root:ancestor-unsearchable"'),
            ),
            "product-sshd-root-login-check-v1.py": (
                ('_slp_parser_reason=sshd-config:include-depth', 'sshd-config:include-depth'),
                ('_slp_parser_reason=sshd-config:include-cycle', 'sshd-config:include-cycle'),
                ('_slp_parser_reason=sshd-config:include-glob-failed', 'sshd-config:include-glob-failed'),
                ('_slp_parser_reason=sshd-config:read-failed', 'sshd-config:read-failed'),
            ),
        }
        for filename, pairs in expected.items():
            text = (ROOT / "product" / "adapters" / filename).read_text(encoding="utf-8")
            for condition, reason in pairs:
                with self.subTest(filename=filename, condition=condition, reason=reason):
                    self.assertIn(condition, text)
                    self.assertIn(reason, text)
        for filename in (
            "product-cron-command-paths-write-protection-check-v1.py",
            "product-running-process-paths-write-protection-check-v1.py",
        ):
            text = (ROOT / "product" / "adapters" / filename).read_text(encoding="utf-8")
            self.assertIn('if (( _slp_rc != 0 )); then', text)
            self.assertIn('"observer:execution-failed"', text)
            self.assertIn('if [[ -z $_slp_obs ||', text)
            self.assertIn('"observer:invalid-output"', text)

    def test_unknown_kind_fails_closed(self):
        _, manifest_sha, adapters, registry_sha, controls = self.load_current()
        bad = dict(controls[0])
        bad["parameter_kind"] = "unknown-kind"
        with self.assertRaises(RuntimeError):
            GEN.render_script([bad], adapters, manifest_sha, registry_sha, sha256_file(GEN_PATH))

    def test_no_mutating_shell_tokens(self):
        _, manifest_sha, adapters, registry_sha, controls = self.load_current()
        rendered = GEN.render_script(
            controls, adapters, manifest_sha, registry_sha, sha256_file(GEN_PATH)
        ).decode("utf-8")
        for token in ("sysctl -w", "sysctl --write", "tee /proc/sys", "sed -i"):
            self.assertNotIn(token, rendered)

    def _load_current_v2(self):
        rows, manifest_sha = GEN_V2_CURRENT.load_manifest(ROOT)
        adapters, registry_sha = GEN_V2_CURRENT.load_registry(ROOT)
        controls = [GEN_V2_CURRENT.load_control(ROOT, row) for row in rows]
        return rows, manifest_sha, adapters, registry_sha, controls

    def test_v2_shell_function_name_collision_is_rejected(self):
        _, manifest_sha, adapters, registry_sha, controls = self._load_current_v2()
        one_control = dict(controls[0]); two_control = dict(controls[0])
        one_control["control_id"] = "COLLIDE-A.B"
        two_control["control_id"] = "COLLIDE-A-B"
        with self.assertRaisesRegex(RuntimeError, "shell function name collision"):
            GEN_V2_CURRENT.render_script([one_control, two_control], adapters, manifest_sha, registry_sha, sha256_file(ROOT / "product/generate-product-check-v2.py"))

    def test_v2_quote_split_mutating_command_is_rejected(self):
        _, manifest_sha, adapters, registry_sha, controls = self._load_current_v2()
        control = dict(controls[0]); kind = control["parameter_kind"]
        original = adapters[kind]["module"].shell_function
        try:
            adapters[kind]["module"].shell_function = lambda *args: "slp_check_X(){ ch''mod 0600 /tmp/x; }\n"
            with self.assertRaisesRegex(RuntimeError, "mutating token"):
                GEN_V2_CURRENT.render_script([control], adapters, manifest_sha, registry_sha, sha256_file(ROOT / "product/generate-product-check-v2.py"))
        finally:
            adapters[kind]["module"].shell_function = original


@unittest.skipIf(BASH is None, "bash not available")
class OptionalFileRootFilesAdapterFixtures(unittest.TestCase):
    def run_fileset(self, path: Path):
        source = FILESET.shell_function("TEST-FILESET", str(path), "mode", "bits-clear", "0033")
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_FILESET"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_missing_optional_root_is_value_pass(self):
        with tempfile.TemporaryDirectory() as td:
            cp = self.run_fileset(Path(td) / "missing")
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-FILESET\tVALUE\t<absent>\tPASS")

    def test_regular_file_pass_and_fail(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "crontab"; p.write_text("x\n"); os.chmod(p, 0o644)
            self.assertIn("\tVALUE\tchecked=1;violations=0\tPASS", self.run_fileset(p).stdout)
            os.chmod(p, 0o664)
            self.assertIn("\tVALUE\tchecked=1;violations=1\tFAIL", self.run_fileset(p).stdout)

    def test_directory_root_and_direct_regular_files(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "cron.d"; p.mkdir(); os.chmod(p, 0o700)
            a = p / "a"; a.write_text("x\n"); os.chmod(a, 0o600)
            b = p / "b"; b.write_text("x\n"); os.chmod(b, 0o644)
            self.assertIn("\tVALUE\tchecked=3;violations=0\tPASS", self.run_fileset(p).stdout)
            os.chmod(b, 0o655)
            self.assertIn("\tVALUE\tchecked=3;violations=1\tFAIL", self.run_fileset(p).stdout)

    def test_nested_directory_symlink_and_special_are_error(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            d = base / "nested-case"; d.mkdir(); os.chmod(d, 0o700); (d / "nested").mkdir()
            assert_stable_error_record(self, self.run_fileset(d).stdout, "TEST-FILESET", "target:invalid-type")
            target = base / "target"; target.write_text("x\n")
            link = base / "link"; link.symlink_to(target)
            assert_stable_error_record(self, self.run_fileset(link).stdout, "TEST-FILESET", "root:symlink")
            s = base / "symlink-child"; s.mkdir(); os.chmod(s, 0o700); (s / "l").symlink_to(target)
            assert_stable_error_record(self, self.run_fileset(s).stdout, "TEST-FILESET", "target:symlink")
            if hasattr(os, "mkfifo"):
                f = base / "special"; f.mkdir(); os.chmod(f, 0o700); os.mkfifo(f / "pipe")
                assert_stable_error_record(self, self.run_fileset(f).stdout, "TEST-FILESET", "target:invalid-type")

    def test_generation_rejects_wrong_contract_fields(self):
        for args in (
            ("TEST", "/tmp/x", "owner", "bits-clear", "0033"),
            ("TEST", "/tmp/x", "mode", "eq", "0033"),
            ("TEST", "/tmp/x", "mode", "bits-clear", "0077"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    FILESET.shell_function(*args)



@unittest.skipIf(BASH is None, "bash not available")
class UserCronFilesModeFixtures(unittest.TestCase):
    def run_user_cron(self, roots, *, ordinary_user=False):
        source = USER_CRON._shell_function_for_roots("TEST-USER-CRON", [str(x) for x in roots])
        kwargs = {}
        if ordinary_user and os.geteuid() == 0:
            kwargs = {"user": 65534, "group": 65534, "extra_groups": []}
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_USER_CRON"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **kwargs,
        )

    def test_root_absent_is_empty_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "crontabs"
            cp = self.run_user_cron([root])
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            self.assertEqual(
                cp.stdout.strip(),
                "SLP-CHECK-V1\tTEST-USER-CRON\tVALUE\troots_present=0;roots_absent=1;checked=0;violations=0\tPASS",
            )

    def test_canonical_root_empty_and_direct_regular_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "crontabs"; root.mkdir()
            cp = self.run_user_cron([root])
            self.assertEqual(cp.stderr, "")
            self.assertIn("roots_present=1;roots_absent=0;checked=0;violations=0\tPASS", cp.stdout)

            user_file = root / "alice"; user_file.write_text("x\n", encoding="utf-8"); os.chmod(user_file, 0o640)
            self.assertIn("checked=1;violations=0\tPASS", self.run_user_cron([root]).stdout)
            os.chmod(user_file, 0o662)
            self.assertIn("checked=1;violations=1\tFAIL", self.run_user_cron([root]).stdout)

    def test_parent_spool_objects_are_not_user_cron_population(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); cron = base / "cron"; cron.mkdir(); crontabs = cron / "crontabs"; crontabs.mkdir()
            unrelated = cron / "unrelated"; unrelated.write_text("x\n", encoding="utf-8"); os.chmod(unrelated, 0o666)
            atjobs = cron / "atjobs"; atjobs.mkdir(); (atjobs / "job").write_text("x\n", encoding="utf-8")
            cp = self.run_user_cron([crontabs])
            self.assertEqual(cp.stderr, "")
            self.assertIn("checked=0;violations=0\tPASS", cp.stdout)

    def test_symlink_special_root_file_and_population_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            target = base / "target"; target.write_text("x\n", encoding="utf-8")
            root_link = base / "root-link"; root_link.symlink_to(base, target_is_directory=True)
            assert_stable_error_record(self, self.run_user_cron([root_link]).stdout, "TEST-USER-CRON")

            root = base / "crontabs"; root.mkdir(); (root / "link").symlink_to(target)
            assert_stable_error_record(self, self.run_user_cron([root]).stdout, "TEST-USER-CRON")
            (root / "link").unlink()

            if hasattr(os, "mkfifo"):
                os.mkfifo(root / "pipe")
                assert_stable_error_record(self, self.run_user_cron([root]).stdout, "TEST-USER-CRON")
                (root / "pipe").unlink()

            bad_root = base / "file-root"; bad_root.write_text("x\n", encoding="utf-8")
            assert_stable_error_record(self, self.run_user_cron([bad_root]).stdout, "TEST-USER-CRON")

            # v2 does not recurse into directory entries below the canonical root.
            locked = root / "locked"; locked.mkdir(); os.chmod(locked, 0)
            try:
                cp = self.run_user_cron([root])
                self.assertEqual(cp.stderr, "")
                self.assertIn("checked=0;violations=0\tPASS", cp.stdout)
            finally:
                os.chmod(locked, 0o700)

            # Inability to enumerate the canonical admitted root is observation ambiguity.
            if os.geteuid() == 0:
                os.chmod(base, 0o755)
            os.chmod(root, 0)
            try:
                cp = self.run_user_cron([root], ordinary_user=True)
                assert_stable_error_record(self, cp.stdout, "TEST-USER-CRON")
            finally:
                os.chmod(root, 0o700)

    def test_generation_rejects_wrong_contract_fields(self):
        good = "/var/spool/cron/crontabs"
        for args in (
            ("TEST", "/var/spool/cron", "mode", "bits-clear", "0022"),
            ("TEST", "/var/spool/cron|/var/spool/cron/crontabs", "mode", "bits-clear", "0022"),
            ("TEST", good, "owner", "bits-clear", "0022"),
            ("TEST", good, "mode", "eq", "0022"),
            ("TEST", good, "mode", "bits-clear", "0033"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    USER_CRON.shell_function(*args)


@unittest.skipIf(BASH is None, "bash not available")
class StandardSystemPathsModeFixtures(unittest.TestCase):
    def run_standard(self, exec_roots, lib_roots, module_root, *, ordinary_user=False):
        source = STANDARD_PATHS._shell_function_for_layout(
            "TEST-STANDARD-PATHS",
            [str(x) for x in exec_roots],
            [str(x) for x in lib_roots],
            str(module_root),
        )
        kwargs = {}
        if ordinary_user and os.geteuid() == 0:
            kwargs = {"user": 65534, "group": 65534, "extra_groups": []}
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_STANDARD_PATHS"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **kwargs,
        )

    def make_layout(self, base):
        exe = base / "usr-bin"; exe.mkdir()
        lib = base / "usr-lib"; lib.mkdir()
        mod = base / "modules"; mod.mkdir()
        tool = exe / "tool"; tool.write_text("x\n", encoding="utf-8"); os.chmod(tool, 0o755)
        library = lib / "libdemo.so.1"; library.write_text("x\n", encoding="utf-8"); os.chmod(library, 0o644)
        module = mod / "demo.ko.zst"; module.write_text("x\n", encoding="utf-8"); os.chmod(module, 0o644)
        return exe, lib, mod, tool, library, module

    def test_pass_and_merged_root_alias_deduplication(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            exe_alias = base / "bin"; exe_alias.symlink_to(exe, target_is_directory=True)
            lib_alias = base / "lib"; lib_alias.symlink_to(lib, target_is_directory=True)
            cp = self.run_standard([exe_alias, exe], [lib_alias, lib], mod)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            self.assertIn("roots_present=5;roots_absent=0;aliases=2;exec=1;libraries=1;modules=1;checked=3;violations=0\tPASS", cp.stdout)

    def test_each_role_violation_is_fail(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, tool, library, module = self.make_layout(base)
            for path in (tool, library, module):
                original = path.stat().st_mode & 0o7777
                os.chmod(path, original | 0o020)
                cp = self.run_standard([exe], [lib], mod)
                self.assertEqual(cp.stderr, "")
                self.assertIn("violations=1\tFAIL", cp.stdout)
                os.chmod(path, original)

    def test_additional_root_path_entry_is_in_population(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            extra = base / "usr-local-bin"; extra.mkdir()
            tool = extra / "local-tool"; tool.write_text("x\n", encoding="utf-8"); os.chmod(tool, 0o775)
            cp = self.run_standard([exe, extra], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertIn("exec=2", cp.stdout)
            self.assertIn("violations=1\tFAIL", cp.stdout)

    def test_non_executable_regular_file_under_exec_root_is_outside_population(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            data = exe / "README.data"; data.write_text("x\n", encoding="utf-8"); os.chmod(data, 0o664)
            cp = self.run_standard([exe], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertIn("exec=1;libraries=1;modules=1;checked=3;violations=0\tPASS", cp.stdout)

    def test_production_contract_reads_root_process_path(self):
        source = STANDARD_PATHS.shell_function(
            "TEST-STANDARD-PATHS", STANDARD_PATHS.CANONICAL_LOCATOR, "mode", "bits-clear", "0022"
        )
        self.assertIn("EUID != 0", source)
        self.assertIn("${PATH-}", source)
        self.assertIn("_slp_exec_roots+=(", source)
        semantic = json.loads((ROOT / "product/contracts/standard-system-paths-mode-check-semantic-v2.json").read_text(encoding="utf-8"))
        self.assertEqual(
            semantic["canonical_population"]["library_roots"],
            list(STANDARD_PATHS.CANONICAL_LIB_ROOTS),
        )

    def test_library_and_module_population_filters_non_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            data = lib / "package-data.conf"; data.write_text("x\n", encoding="utf-8"); os.chmod(data, 0o666)
            meta = mod / "modules.dep"; meta.write_text("x\n", encoding="utf-8"); os.chmod(meta, 0o666)
            cp = self.run_standard([exe], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertIn("libraries=1;modules=1;checked=3;violations=0\tPASS", cp.stdout)

    def test_candidate_symlink_target_is_checked_and_dangling_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            outside = base / "outside.so"; outside.write_text("x\n", encoding="utf-8"); os.chmod(outside, 0o664)
            link = lib / "liboutside.so"; link.symlink_to(outside)
            cp = self.run_standard([exe], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertIn("violations=1\tFAIL", cp.stdout)
            link.unlink(); link.symlink_to(base / "missing.so")
            cp = self.run_standard([exe], [lib], mod)
            assert_stable_error_record(self, cp.stdout, "TEST-STANDARD-PATHS")

    def test_exec_symlink_to_observed_exec_root_is_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            baseline = self.run_standard([exe], [lib], mod)
            self.assertEqual(baseline.stderr, "")
            self.assertIn("exec=1;libraries=1;modules=1;checked=3;violations=0\tPASS", baseline.stdout)

            own = exe / "X11"; own.symlink_to(exe, target_is_directory=True)
            cp = self.run_standard([exe], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertEqual(cp.stdout, baseline.stdout)

            other_root = base / "usr-sbin"; other_root.mkdir()
            tool2 = other_root / "tool2"; tool2.write_text("x\n", encoding="utf-8"); os.chmod(tool2, 0o755)
            cross_root = exe / "sbinlink"; cross_root.symlink_to(other_root, target_is_directory=True)
            cp = self.run_standard([exe, other_root], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertIn("exec=2;libraries=1;modules=1;checked=4;violations=0\tPASS", cp.stdout)
            cross_root.unlink()

    def test_directory_symlink_outside_exception_stays_error(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            outside = base / "other"; outside.mkdir()
            sub = exe / "sub"; sub.mkdir()
            cases = (
                (exe / "badlink", outside),
                (exe / "sublink", sub),
                (exe / "liblink", lib),
                (lib / "libroot.so", lib),
                (mod / "root.ko", mod),
            )
            for link, target in cases:
                with self.subTest(link=link.name):
                    link.symlink_to(target, target_is_directory=True)
                    try:
                        cp = self.run_standard([exe], [lib], mod)
                        self.assertEqual(cp.stderr, "")
                        assert_stable_error_record(self, cp.stdout, "TEST-STANDARD-PATHS", "target:invalid-type")
                    finally:
                        link.unlink()

    def test_missing_role_and_candidate_special_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            empty_mod = base / "empty-mod"; empty_mod.mkdir()
            cp = self.run_standard([exe], [lib], empty_mod)
            assert_stable_error_record(self, cp.stdout, "TEST-STANDARD-PATHS")
            if hasattr(os, "mkfifo"):
                os.mkfifo(exe / "pipe")
                cp = self.run_standard([exe], [lib], mod)
                assert_stable_error_record(self, cp.stdout, "TEST-STANDARD-PATHS")

    def test_traversal_error_fail_closed_for_ordinary_user(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            if os.geteuid() == 0:
                os.chmod(base, 0o755)
            locked = lib / "locked"; locked.mkdir(); os.chmod(locked, 0)
            try:
                cp = self.run_standard([exe], [lib], mod, ordinary_user=True)
                assert_stable_error_record(self, cp.stdout, "TEST-STANDARD-PATHS")
            finally:
                os.chmod(locked, 0o700)

    def test_python_dependency_failure_records(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            source = STANDARD_PATHS._shell_function_for_layout(
                "TEST-STANDARD-PATHS", [str(exe)], [str(lib)], str(mod))
            missing = base / "missing-python"
            nonexec = base / "nonexec-python"
            nonexec.write_bytes(b"#!/bin/sh\n")
            os.chmod(nonexec, 0o644)
            # Existing executable avoids requiring execution from temporary mounts.
            failing = Path("/usr/bin/false")
            self.assertTrue(os.access(failing, os.X_OK), str(failing))
            for path, reason in (
                (missing, "runtime:python3-missing"),
                (nonexec, "runtime:python3-missing"),
                (failing, "runtime:observer-failed"),
            ):
                with self.subTest(reason=reason, path=path.name):
                    # Substitute the interpreter only inside this temporary fixture.
                    self.assertEqual(source.count("/usr/bin/python3"), 2)
                    altered = source.replace("/usr/bin/python3", str(path))
                    cp = subprocess.run(
                        [BASH, "-p", "-c", altered + "\nslp_check_TEST_STANDARD_PATHS"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.assertEqual(cp.returncode, 0, cp.stderr)
                    self.assertEqual(cp.stderr, "")
                    self.assertEqual(cp.stdout,
                        "SLP-CHECK-V1\tTEST-STANDARD-PATHS\tERROR\t" + reason + "\tERROR\n")

    def test_observer_invalid_argument_count(self):
        cp = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-B", "-", "TEST-STANDARD-PATHS",
             "0022", "1", "1"],
            input=STANDARD_PATHS._OBSERVER, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        self.assertEqual(cp.stdout,
            "SLP-CHECK-V1\tTEST-STANDARD-PATHS\tERROR\truntime:observer-arguments\tERROR\n")

    def test_error_vocabulary_matches_rendered_reasons(self):
        semantic = json.loads((ROOT /
            "product/contracts/standard-system-paths-mode-check-semantic-v2.json").read_text())
        source = STANDARD_PATHS.shell_function(
            "TEST-STANDARD-PATHS", STANDARD_PATHS.CANONICAL_LOCATOR,
            "mode", "bits-clear", "0022")
        reasons = set(re.findall(
            r"""["']((?:runtime|path|kernel|root|target|scan|population):[a-z0-9-]+)["']""",
            source))
        # resolve() constructs these reasons for its two caller roles.
        for role in ("root", "target"):
            for suffix in ("resolve-failed", "resolve-empty"):
                reasons.add(role + ":" + suffix)
        self.assertEqual(set(semantic["error_reasons"]), reasons)
        self.assertTrue(all(isinstance(v, str) and v for v in semantic["error_reasons"].values()))
        self.assertNotIn("target:mode-read-failed", reasons)
        self.assertNotIn("scan:invalid-marker", reasons)
        dependency = semantic["runtime_dependency"]
        self.assertEqual(dependency["path"], "/usr/bin/python3")
        self.assertEqual(dependency["error"], "runtime:python3-missing")
        guard = "if " + dependency["check"] + "; then"
        self.assertIn(guard, source)
        self.assertLess(source.index(guard), source.index("command /usr/bin/python3"))
        self.assertGreater(source.index(guard), source.index("command /usr/bin/uname -r"))

    def test_generation_rejects_wrong_contract_fields(self):
        good = "/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>"
        for args in (
            ("TEST", "/bin", "mode", "bits-clear", "0022"),
            ("TEST", good, "owner", "bits-clear", "0022"),
            ("TEST", good, "mode", "eq", "0022"),
            ("TEST", good, "mode", "bits-clear", "0033"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    STANDARD_PATHS.shell_function(*args)


@unittest.skipIf(BASH is None, "bash not available")
class SuidSgidApplicationsFixtures(unittest.TestCase):
    def make_mountinfo(self, base: Path):
        mountinfo = base / "mountinfo"
        mountinfo.write_text(
            f"1 0 0:1 / {base} rw,relatime - ext4 /dev/test rw\n",
            encoding="utf-8",
        )
        return mountinfo

    def run_fixture(self, base: Path, key: str, op: str, expected: str):
        mountinfo = self.make_mountinfo(base)
        source = SUID_SGID._shell_function_for_fixture(
            "TEST-SUID-SGID", key, op, expected, str(mountinfo)
        )
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_SUID_SGID"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_mode_pass_and_fail(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            app = base / "app"; app.write_text("x\n", encoding="utf-8")
            os.chmod(app, 0o4755)
            cp = self.run_fixture(base, "mode", "bits-clear", "0022")
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            self.assertIn("checked=1;violations=0\tPASS", cp.stdout)
            os.chmod(app, 0o4775)
            cp = self.run_fixture(base, "mode", "bits-clear", "0022")
            self.assertIn("checked=1;violations=1\tFAIL", cp.stdout)

    def test_allowlist_pass_and_extra_fail(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            app = base / "app"; app.write_text("x\n", encoding="utf-8"); os.chmod(app, 0o4755)
            allow = base / "allowlist"
            allow.write_text(str(app) + "\n", encoding="utf-8")
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(allow))
            self.assertEqual(cp.stderr, "")
            self.assertIn("checked=1;extras=0\tPASS", cp.stdout)
            extra = base / "extra"; extra.write_text("x\n", encoding="utf-8"); os.chmod(extra, 0o2755)
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(allow))
            self.assertIn("checked=2;extras=1\tFAIL", cp.stdout)

    def test_missing_or_malformed_allowlist_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            app = base / "app"; app.write_text("x\n", encoding="utf-8"); os.chmod(app, 0o4755)
            missing = base / "missing"
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(missing))
            assert_stable_error_record(self, cp.stdout, "TEST-SUID-SGID", "allowlist:not-found")
            allow = base / "allowlist"
            allow.write_text("relative/path\n", encoding="utf-8")
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(allow))
            assert_stable_error_record(self, cp.stdout, "TEST-SUID-SGID", "allowlist:invalid-path")
            allow.unlink()
            allow.symlink_to(base / "missing-target")
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(allow))
            assert_stable_error_record(self, cp.stdout, "TEST-SUID-SGID", "allowlist:symlink")

    def test_nosuid_mount_is_included(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            app = base / "app"; app.write_text("x\n", encoding="utf-8"); os.chmod(app, 0o4777)
            mountinfo = base / "mountinfo"
            mountinfo.write_text(
                f"1 0 0:1 / {base} rw,nosuid,relatime - ext4 /dev/test rw\n",
                encoding="utf-8",
            )
            source = SUID_SGID._shell_function_for_fixture(
                "TEST-SUID-SGID", "mode", "bits-clear", "0022", str(mountinfo)
            )
            cp = subprocess.run(
                [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_SUID_SGID"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(cp.stderr, "")
            self.assertIn("mounts=1;checked=1;violations=1\tFAIL", cp.stdout)

    def test_nul_in_allowlist_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            app = base / "app"; app.write_text("x\n", encoding="utf-8"); os.chmod(app, 0o4755)
            allow = base / "allowlist"
            allow.write_bytes(str(app).encode("utf-8") + b"\x00\n")
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(allow))
            assert_stable_error_record(self, cp.stdout, "TEST-SUID-SGID", "allowlist:invalid-bytes")

    def test_generation_rejects_wrong_contract_fields(self):
        for args in (
            ("TEST", "/proc/mounts", "mode", "bits-clear", "0022"),
            ("TEST", "/proc/self/mountinfo", "owner", "bits-clear", "0022"),
            ("TEST", "/proc/self/mountinfo", "mode", "eq", "0022"),
            ("TEST", "/proc/self/mountinfo", "mode", "bits-clear", "0033"),
            ("TEST", "/proc/self/mountinfo", "approved-set", "subset-of-file", "/tmp/list"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    SUID_SGID.shell_function(*args)


@unittest.skipIf(BASH is None, "bash not available")
class LocalAccountPasswordStateFixtures(unittest.TestCase):
    def run_shadow(self, passwd_text, shadow_text):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            passwd = base / "passwd"
            shadow = base / "shadow"
            passwd.write_bytes(passwd_text if isinstance(passwd_text, bytes) else passwd_text.encode("utf-8"))
            shadow.write_bytes(shadow_text if isinstance(shadow_text, bytes) else shadow_text.encode("utf-8"))
            source = SHADOW._shell_function_for_paths(
                "TEST-SHADOW", str(passwd), str(shadow),
                "password-field", "all-nonempty", True,
            )
            return subprocess.run(
                [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_SHADOW"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )

    def test_pass_nonempty_hash_and_lock_markers(self):
        cp = self.run_shadow(
            "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",
            "root:!:1:0:99999:7:::\nuser:$6$abc:1:0:99999:7:::\n",
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        self.assertIn("\tVALUE\taccounts=2;empty=0\tPASS", cp.stdout)

    def test_empty_password_is_fail(self):
        cp = self.run_shadow(
            "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",
            "root:!:1:0:99999:7:::\nuser::1:0:99999:7:::\n",
        )
        self.assertEqual(cp.stderr, "")
        self.assertIn("\tVALUE\taccounts=2;empty=1\tFAIL", cp.stdout)

    def test_missing_mapping_and_malformed_are_error(self):
        cp = self.run_shadow(
            "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n",
            "root:!:1:0:99999:7:::\n",
        )
        assert_stable_error_record(self, cp.stdout, "TEST-SHADOW", "passwd:missing-shadow-account")
        cp = self.run_shadow("broken\n", "root:!:1:0:99999:7:::\n")
        assert_stable_error_record(self, cp.stdout, "TEST-SHADOW", "passwd:invalid-fields")

    def test_nul_and_cr_bytes_fail_closed(self):
        passwd = b"root:x:0:0:root:/root:/bin/bash\n"
        for shadow in (
            b"root:!:1:0:99999:7:::\x00\n",
            b"root:!:1:0:99999:7:::\r\n",
        ):
            with self.subTest(shadow=shadow):
                cp = self.run_shadow(passwd, shadow)
                assert_stable_error_record(self, cp.stdout, "TEST-SHADOW", "shadow:invalid-bytes")

    def test_unreadable_and_symlink_reason_domains_match_the_observed_file(self):
        src = SHADOW._shell_function_for_paths(
            "TEST-SHADOW", "/tmp/passwd", "/tmp/shadow",
            "password-field", "all-nonempty", True,
        )
        for marker in (
            '[[ -L "$_slp_passwd" ]]', '"passwd:symlink"',
            '[[ -L "$_slp_shadow" ]]', '"shadow:symlink"',
            '[[ ! -e "$_slp_passwd" ]]', '"passwd:not-found"',
            '[[ ! -f "$_slp_passwd" ]]', '"passwd:invalid-type"',
            '[[ ! -r "$_slp_passwd" ]]', '"passwd:unreadable"',
            '[[ ! -e "$_slp_shadow" ]]', '"shadow:not-found"',
            '[[ ! -f "$_slp_shadow" ]]', '"shadow:invalid-type"',
            '[[ ! -r "$_slp_shadow" ]]', '"shadow:unreadable"',
        ):
            self.assertIn(marker, src)

    def test_generation_rejects_wrong_contract_fields(self):
        for args in (
            ("TEST", "/tmp/shadow", "password-field", "all-nonempty", True),
            ("TEST", "/etc/shadow", "password", "all-nonempty", True),
            ("TEST", "/etc/shadow", "password-field", "eq", True),
            ("TEST", "/etc/shadow", "password-field", "all-nonempty", False),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    SHADOW.shell_function(*args)


@unittest.skipIf(BASH is None, "bash not available")
class TestedSettingAttestationFixtures(unittest.TestCase):
    def run_authority(self, content=None, *, symlink=False):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            authority = base / "tested-setting-attestations-v1"
            if symlink:
                target = base / "target"
                target.write_text(
                    "SLP-TESTED-SETTING-ATTESTATIONS-V1\n"
                    "SRC-0034\tkernel.randomize_va_space=2\tTESTED-BEFORE-USE\n",
                    encoding="utf-8",
                )
                authority.symlink_to(target)
            elif content is not None:
                if isinstance(content, bytes):
                    authority.write_bytes(content)
                else:
                    authority.write_text(content, encoding="utf-8")
            source = TESTED_SETTING_ATTESTATION._shell_function_for_fixture("TEST-ATTEST", str(authority))
            return subprocess.run(
                [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_ATTEST"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )

    def test_tested_before_use_pass(self):
        cp = self.run_authority(
            "SLP-TESTED-SETTING-ATTESTATIONS-V1\n"
            "SRC-0034\tkernel.randomize_va_space=2\tTESTED-BEFORE-USE\n"
        )
        self.assertEqual(cp.stderr, "")
        self.assertEqual(
            cp.stdout.strip(),
            "SLP-CHECK-V1\tTEST-ATTEST\tVALUE\tauthority_rows=1;target_rows=1;setting_match=1;tested_before_use=1\tPASS",
        )

    def test_explicit_not_tested_or_wrong_setting_fail(self):
        cases = (
            "SRC-0034\tkernel.randomize_va_space=2\tNOT-TESTED-BEFORE-USE\n",
            "SRC-0034\tkernel.randomize_va_space=1\tTESTED-BEFORE-USE\n",
        )
        for row in cases:
            with self.subTest(row=row):
                cp = self.run_authority("SLP-TESTED-SETTING-ATTESTATIONS-V1\n" + row)
                self.assertEqual(cp.stderr, "")
                self.assertTrue(cp.stdout.rstrip().endswith("\tFAIL"), cp.stdout)

    def test_missing_target_malformed_duplicate_symlink_and_control_bytes_error(self):
        cases = (
            None,
            "SLP-TESTED-SETTING-ATTESTATIONS-V1\nSRC-0028\tkernel.kptr_restrict=2\tTESTED-BEFORE-USE\n",
            "SLP-TESTED-SETTING-ATTESTATIONS-V1\nBROKEN\n",
            "SLP-TESTED-SETTING-ATTESTATIONS-V1\nSRC-0034\tkernel.randomize_va_space=2\tTESTED-BEFORE-USE\nSRC-0034\tkernel.randomize_va_space=2\tTESTED-BEFORE-USE\n",
            b"SLP-TESTED-SETTING-ATTESTATIONS-V1\nSRC-0034\tkernel.randomize_va_space=2\tTESTED-BEFORE-USE\x00\n",
            b"SLP-TESTED-SETTING-ATTESTATIONS-V1\r\nSRC-0034\tkernel.randomize_va_space=2\tTESTED-BEFORE-USE\r\n",
        )
        for content in cases:
            with self.subTest(content=content):
                cp = self.run_authority(content)
                if content is None:
                    assert_stable_error_record(self, cp.stdout, "TEST-ATTEST", "authority:not-found")
                else:
                    assert_stable_error_record(self, cp.stdout, "TEST-ATTEST")
        cp = self.run_authority(symlink=True)
        assert_stable_error_record(self, cp.stdout, "TEST-ATTEST", "authority:symlink")

    def test_generation_rejects_wrong_contract_fields_and_adapter_is_read_only(self):
        src = TESTED_SETTING_ATTESTATION.shell_function(
            "TEST", "/etc/securelinux-policy/tested-setting-attestations-v1", "SRC-0034",
            "tested-before-use", "kernel.randomize_va_space=2",
        )
        self.assertIn("TESTED-BEFORE-USE", src)
        for token in TESTED_SETTING_ATTESTATION.MUTATING_TOKENS:
            self.assertNotIn(token, src)
        for args in (
            ("TEST", "/tmp/attest", "SRC-0034", "tested-before-use", "kernel.randomize_va_space=2"),
            ("TEST", "/etc/securelinux-policy/tested-setting-attestations-v1", "SRC-0028", "tested-before-use", "kernel.randomize_va_space=2"),
            ("TEST", "/etc/securelinux-policy/tested-setting-attestations-v1", "SRC-0034", "eq", "kernel.randomize_va_space=2"),
            ("TEST", "/etc/securelinux-policy/tested-setting-attestations-v1", "SRC-0034", "tested-before-use", "kernel.randomize_va_space=1"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    TESTED_SETTING_ATTESTATION.shell_function(*args)


@unittest.skipIf(BASH is None, "bash not available")
class HomeSensitiveFilesAdapterFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.passwd = self.base / "passwd"
        self.inventory = self.base / "inventory"
        self.root_home = self.base / "root"
        self.service_home = self.base / "service"
        self.user_home = self.base / "user"
        for h in (self.root_home, self.service_home, self.user_home): h.mkdir()
        self.inventory.write_text("\n".join(HOME_SENSITIVE.MANDATORY_SOURCE_NAMES) + "\n", encoding="utf-8")
        self.passwd.write_text(
            f"root:x:0:0:root:{self.root_home}:/bin/bash\n"
            f"svc:x:500:500:service:{self.service_home}:/usr/sbin/nologin\n"
            f"user:x:1000:1000:user:{self.user_home}:/bin/bash\n",
            encoding="utf-8",
        )

    def tearDown(self): self.tmp.cleanup()

    def run_check(self):
        block = HOME_SENSITIVE._shell_function_for_fixture(
            "TEST.HOME", str(self.passwd), str(self.inventory)
        )
        script = self.base / "check.sh"
        script.write_text(block + "\nslp_check_TEST_HOME\n", encoding="utf-8")
        return subprocess.run([BASH, str(script)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_positive_includes_service_account(self):
        for p in (self.root_home / ".bashrc", self.service_home / ".profile", self.user_home / ".bash_history"):
            p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o600)
        cp = self.run_check()
        self.assertEqual(cp.returncode, 0); self.assertEqual(cp.stderr, "")
        self.assertIn("accounts=3;homes=3;names=8;discovered=3;checked=3;violations=0\tPASS", cp.stdout)

    def test_service_account_sensitive_file_is_checked(self):
        p = self.service_home / ".bashrc"; p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o644)
        cp = self.run_check()
        self.assertIn("violations=1\tFAIL", cp.stdout)

    def test_unlisted_zsh_history_is_discovered(self):
        p = self.user_home / ".zsh_history"; p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o644)
        cp = self.run_check()
        self.assertIn("discovered=1;checked=1;violations=1\tFAIL", cp.stdout)

    def test_vimrc_is_not_misclassified_as_shell_config(self):
        p = self.user_home / ".vimrc"; p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o644)
        cp = self.run_check()
        self.assertIn("discovered=0;checked=0;violations=0\tPASS", cp.stdout)

    def test_nushell_config_is_discovered(self):
        d = self.user_home / ".config" / "nushell"; d.mkdir(parents=True)
        p = d / "config.nu"; p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o644)
        cp = self.run_check()
        self.assertIn("discovered=1;checked=1;violations=1\tFAIL", cp.stdout)

    def test_additional_common_shell_artifacts_are_discovered(self):
        paths = (
            ".bash_login",
            ".xonshrc",
            ".config/nushell/autoload/local.nu",
            ".local/share/nushell/vendor/autoload/vendor.nu",
            ".config/nushell/history.txt",
            ".config/nushell/history.sqlite3",
            ".config/xonsh/rc.xsh",
            ".config/xonsh/rc.d/local.xsh",
            ".config/xonsh/rc.d/local.py",
            ".local/share/xonsh/history_json/xonsh-session.json",
            ".local/share/xonsh/xonsh-legacy.json",
            ".local/share/xonsh/xonsh-history.sqlite",
            ".config/elvish/rc.elv",
            ".elvish/rc.elv",
            ".local/state/elvish/db.bolt",
            ".elvish/db",
        )
        for rel in paths:
            with self.subTest(rel=rel):
                p = self.user_home / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x\n", encoding="utf-8")
                os.chmod(p, 0o644)
                cp = self.run_check()
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertIn("discovered=1;checked=1;violations=1\tFAIL", cp.stdout)
                p.unlink()

    def test_group_other_bits_fail(self):
        p = self.user_home / ".profile"; p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o644)
        self.assertIn("violations=1\tFAIL", self.run_check().stdout)

    def test_missing_inventory_fails_closed(self):
        self.inventory.unlink()
        assert_stable_error_record(self, self.run_check().stdout, "TEST.HOME", "inventory:not-found")

    def test_inventory_must_cover_all_source_examples(self):
        self.inventory.write_text(".bashrc\n", encoding="utf-8")
        assert_stable_error_record(self, self.run_check().stdout)

    def test_additional_nested_inventory_member_is_checked(self):
        self.inventory.write_text("\n".join(HOME_SENSITIVE.MANDATORY_SOURCE_NAMES) + "\n.config/fish/config.fish\n", encoding="utf-8")
        d=self.user_home / ".config" / "fish"; d.mkdir(parents=True)
        p=d / "config.fish"; p.write_text("x\n", encoding="utf-8"); os.chmod(p,0o600)
        cp=self.run_check()
        self.assertIn("names=9", cp.stdout); self.assertIn("checked=1;violations=0\tPASS", cp.stdout)

    def test_symlink_member_fails_closed(self):
        outside=self.base / "outside"; outside.write_text("x\n",encoding="utf-8")
        (self.user_home / ".bashrc").symlink_to(outside)
        assert_stable_error_record(self, self.run_check().stdout)

    def test_nul_or_cr_in_passwd_or_inventory_is_error(self):
        original = self.passwd.read_bytes()
        self.passwd.write_bytes(original + b"bad:x:2:2::/tmp/bad:/bin/sh\x00\n")
        assert_stable_error_record(self, self.run_check().stdout, "TEST.HOME", "passwd:invalid-bytes")
        self.passwd.write_bytes(original)
        self.inventory.write_bytes(("\n".join(HOME_SENSITIVE.MANDATORY_SOURCE_NAMES) + "\r\n").encode("utf-8"))
        assert_stable_error_record(self, self.run_check().stdout, "TEST.HOME", "inventory:invalid-bytes")

    def test_generation_rejects_wrong_contract_fields(self):
        for args in (
            ("TEST", "/etc/passwd", "mode", "bits-clear", "0077"),
            ("TEST", HOME_SENSITIVE.CANONICAL_LOCATOR, "owner", "bits-clear", "0077"),
            ("TEST", HOME_SENSITIVE.CANONICAL_LOCATOR, "mode", "eq", "0077"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError): HOME_SENSITIVE.shell_function(*args)

@unittest.skipIf(BASH is None, "bash not available")
class HomeDirectoriesModeAdapterFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.passwd = self.base / "passwd"
        self.root_home = self.base / "root"
        self.service_home = self.base / "service"
        self.user_home = self.base / "user"
        for h in (self.root_home, self.service_home, self.user_home):
            h.mkdir(); os.chmod(h, 0o700)
        self.passwd.write_text(
            f"root:x:0:0:root:{self.root_home}:/bin/bash\n"
            f"svc:x:500:500:service:{self.service_home}:/usr/sbin/nologin\n"
            f"user:x:1000:1000:user:{self.user_home}:/bin/bash\n",
            encoding="utf-8",
        )
    def tearDown(self): self.tmp.cleanup()
    def run_check(self):
        block = HOME_DIRECTORIES._shell_function_for_fixture("TEST.HOME.DIR", str(self.passwd))
        script = self.base / "check-home-dir.sh"
        script.write_text(block + "\nslp_check_TEST_HOME_DIR\n", encoding="utf-8")
        return subprocess.run([BASH, str(script)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def test_positive_includes_service_account(self):
        cp=self.run_check(); self.assertEqual(cp.returncode,0); self.assertEqual(cp.stderr,"")
        self.assertIn("accounts=3;homes=3;violations=0\tPASS",cp.stdout)
    def test_non_0700_service_home_fails(self):
        os.chmod(self.service_home,0o755); cp=self.run_check()
        self.assertIn("accounts=3;homes=3;violations=1\tFAIL",cp.stdout)
    def test_absent_selected_home_is_outside_mode_population(self):
        self.user_home.rmdir(); cp=self.run_check(); self.assertIn("accounts=3;homes=2;violations=0\tPASS",cp.stdout)
    def test_symlink_home_fails_closed(self):
        self.user_home.rmdir(); self.user_home.symlink_to(self.root_home,target_is_directory=True)
        assert_stable_error_record(self, self.run_check().stdout)
    def test_nul_or_cr_in_passwd_is_error(self):
        raw=self.passwd.read_bytes()
        for bad in (raw+b"bad:x:2:2::/tmp/bad:/bin/sh\x00\n", raw.replace(b"\n",b"\r\n",1)):
            self.passwd.write_bytes(bad)
            assert_stable_error_record(self, self.run_check().stdout)
        self.passwd.write_bytes(raw)
    def test_generation_rejects_wrong_contract_fields(self):
        for args in (("TEST","/etc/passwd|/etc/login.defs","mode","eq","0700"),("TEST",HOME_DIRECTORIES.CANONICAL_LOCATOR,"owner","eq","0700"),("TEST",HOME_DIRECTORIES.CANONICAL_LOCATOR,"mode","bits-clear","0700"),("TEST",HOME_DIRECTORIES.CANONICAL_LOCATOR,"mode","eq","0750")):
            with self.subTest(args=args):
                with self.assertRaises(ValueError): HOME_DIRECTORIES.shell_function(*args)

class GeneratedArtifact(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="slp-product-generator-test-"))
        cls.out = cls.tmp / "securelinux-policy-check.sh"
        cp = subprocess.run(
            [
                os.environ.get("PYTHON", "/usr/bin/python3"),
                "-I",
                "-S",
                "-B",
                str(GEN_PATH),
                "--repo",
                str(ROOT),
                "--out",
                str(cls.out),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if cp.returncode != 0:
            raise RuntimeError("generator failed:\n" + cp.stdout + cp.stderr)
        cls.generator_stdout = cp.stdout

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_check(self, *args):
        return subprocess.run(
            [BASH, str(self.out), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_generator_cli_and_sidecar(self):
        rows, _, _, _, _ = load_current()
        self.assertIn(f"CONTROL_COUNT={len(rows)}\n", self.generator_stdout)
        self.assertIn(f"ADAPTER_COUNT={len(load_current()[2])}\n", self.generator_stdout)
        self.assertIn("RESULT=PASS\n", self.generator_stdout)
        side = self.out.with_name(self.out.name + ".sha256")
        self.assertTrue(side.is_file())
        expected = side.read_text(encoding="utf-8").split()[0]
        self.assertEqual(expected, sha256_file(self.out))
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o755)

    def test_bash_syntax(self):
        cp = subprocess.run([BASH, "-n", str(self.out)], capture_output=True, text=True)
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def test_help_and_usage_rc(self):
        cp = self.run_check("--help")
        self.assertEqual(cp.returncode, 0)
        self.assertEqual(cp.stderr, "")
        self.assertIn("единый product CLI", cp.stdout)
        self.assertEqual(self.run_check("--bogus").returncode, 2)
        self.assertEqual(self.run_check("--help", "extra").returncode, 2)

    def test_build_info(self):
        cp = self.run_check("--build-info")
        self.assertEqual(cp.returncode, 0)
        self.assertEqual(cp.stderr, "")
        self.assertIn("GENERATOR_ID=product-check-generator-v2\n", cp.stdout)
        rows, _, _, _, _ = load_current()
        self.assertIn(f"CONTROL_COUNT={len(rows)}\n", cp.stdout)
        self.assertIn(f"ADAPTER_COUNT={len(load_current()[2])}\n", cp.stdout)
        self.assertIn("APPLY_SCOPE=SRC-0001_ONLY\n", cp.stdout)
        self.assertIn("APPLY_IMPLEMENTATION_COUNT=1\n", cp.stdout)
        self.assertIn("MUTATING_MODES=APPLY_SRC0001_ONLY\n", cp.stdout)

    def test_provenance_all_and_one(self):
        cp = self.run_check("--provenance")
        self.assertEqual(cp.returncode, 0)
        lines = cp.stdout.splitlines()
        rows, _, _, _, controls = load_current()
        self.assertEqual(len(lines), len(rows))
        objs = [json.loads(line) for line in lines]
        ids = [obj["control_id"] for obj in objs]
        self.assertEqual(len(set(ids)), len(rows))
        self.assertEqual({obj["parameter_kind"] for obj in objs}, {c["parameter_kind"] for c in controls})
        for obj in objs:
            self.assertEqual(len(obj["quote_sha256"]), 64)
            self.assertEqual(len(obj["registry_sha256"]), 64)
        one = self.run_check("--provenance", ids[0])
        self.assertEqual(one.returncode, 0)
        self.assertEqual(json.loads(one.stdout)["control_id"], ids[0])
        self.assertEqual(self.run_check("--provenance", "NO-SUCH-CONTROL").returncode, 2)


@unittest.skipIf(BASH is None, "bash not available")
class PamWheelAccessAdapterFixtures(unittest.TestCase):
    def run_fixture(self, pam_text=None, group_text=None, authority_text=None, symlink=None, prelude="", env=None):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            pam = root / "su"
            group = root / "group"
            authority = root / "wheel-users.allowlist-v1"
            if pam_text is not None:
                pam.write_bytes(pam_text if isinstance(pam_text, bytes) else pam_text.encode("utf-8"))
            if group_text is not None:
                group.write_bytes(group_text if isinstance(group_text, bytes) else group_text.encode("utf-8"))
            if authority_text is not None:
                authority.write_bytes(authority_text if isinstance(authority_text, bytes) else authority_text.encode("utf-8"))
            if symlink == "pam":
                target = root / "pam-real"
                target.write_text(pam_text or "", encoding="utf-8")
                if pam.exists():
                    pam.unlink()
                pam.symlink_to(target)
            elif symlink == "group":
                target = root / "group-real"
                target.write_text(group_text or "", encoding="utf-8")
                if group.exists():
                    group.unlink()
                group.symlink_to(target)
            elif symlink == "authority":
                target = root / "authority-real"
                target.write_text(authority_text or "", encoding="utf-8")
                if authority.exists():
                    authority.unlink()
                authority.symlink_to(target)
            block = PAM_WHEEL_ACCESS._shell_function_for_fixture(
                "PAM.WHEEL.TEST", str(pam), str(group), str(authority)
            )
            cp = subprocess.run(
                [BASH, "-c", "set -u\n" + prelude + "\n" + block + "\nslp_check_PAM_WHEEL_TEST\n"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=env,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            row = cp.stdout.strip().split("\t")
            self.assertEqual(len(row), 5, cp.stdout)
            return row

    def test_positive_root_only_empty_authority_and_include_after_wheel(self):
        row = self.run_fixture(
            "# comment\nauth required pam_wheel.so use_uid # exact\n@include common-auth\n",
            "root:x:0:\nwheel:x:10:root\n",
            "# no additional users\n",
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("approved=0", row[3])

    def test_positive_explicit_users_literal_gid10_and_crlf(self):
        row = self.run_fixture(
            "auth required pam_wheel.so use_uid\r\n",
            "wheel:x:10:root,alice,bob\r\n",
            "alice\r\nbob\r\n",
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("gid=10", row[3])

    def test_empty_group_password_field_is_not_a_source_predicate(self):
        row = self.run_fixture(
            "auth required pam_wheel.so use_uid\n",
            "wheel::10:root\n",
            "",
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))

    def test_duplicate_exact_pam_rule_is_redundant_but_compliant(self):
        row = self.run_fixture(
            "auth required pam_wheel.so use_uid\nauth required pam_wheel.so use_uid\n",
            "wheel:x:10:root\n", "",
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("pam_exact=2", row[3])

    def test_escaped_line_continuation_preserves_exact_rule(self):
        row = self.run_fixture(
            "auth required pam_wheel.so \\\nuse_uid\n", "wheel:x:10:root\n", "",
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))

    def test_missing_exact_pam_is_definitive_fail_without_authority(self):
        row = self.run_fixture("auth required pam_unix.so\n", "wheel:x:10:root\n", None)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("authority=not-needed", row[3])

    def test_comment_backslash_does_not_continue_comment_text(self):
        row = self.run_fixture(
            "# disabled pam_wheel \\\n"
            "auth required pam_wheel.so use_uid\n",
            "wheel:x:10:root\n", "",
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))

    def test_non_source_pam_wheel_variants_are_error(self):
        variants = (
            "auth required pam_wheel.so use_uid group=wheel\n",
            "auth sufficient pam_wheel.so use_uid\n",
            "auth required /lib/security/pam_wheel.so use_uid\n",
            "auth [success=ok default=bad] pam_wheel.so use_uid\n",
            "-auth required pam_wheel.so use_uid\n",
        )
        for pam_text in variants:
            with self.subTest(pam_text=pam_text):
                row = self.run_fixture(pam_text, "wheel:x:10:root\n", "")
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_non_source_gid_is_definitive_fail(self):
        row = self.run_fixture(
            "auth required pam_wheel.so use_uid\n",
            "wheel:x:1234:root\n",
            None,
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("expected_gid=10", row[3])

    def test_prior_include_or_success_short_circuit_fails_closed(self):
        variants = (
            "@include permissive\nauth required pam_wheel.so use_uid\n",
            "auth sufficient pam_permit.so\nauth required pam_wheel.so use_uid\n",
            "-auth sufficient pam_permit.so\nauth required pam_wheel.so use_uid\n",
            "auth include permissive\nauth required pam_wheel.so use_uid\n",
            "-auth include permissive\nauth required pam_wheel.so use_uid\n",
            "auth substack permissive\nauth required pam_wheel.so use_uid\n",
            "auth [success=done default=ignore] pam_permit.so\nauth required pam_wheel.so use_uid\n",
        )
        for pam_text in variants:
            with self.subTest(pam_text=pam_text):
                row = self.run_fixture(pam_text, "wheel:x:10:root\n", "")
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_missing_wheel_is_definitive_fail_without_authority(self):
        row = self.run_fixture("auth required pam_wheel.so use_uid\n", "root:x:0:\n", None)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_missing_root_member_is_definitive_fail_without_authority(self):
        row = self.run_fixture("auth required pam_wheel.so use_uid\n", "wheel:x:10:alice\n", None)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("root=missing", row[3])

    def test_membership_must_equal_root_plus_authority(self):
        for group_text, authority_text in (
            ("wheel:x:10:root,extra\n", ""),
            ("wheel:x:10:root\n", "alice\n"),
            ("wheel:x:10:root,alice,extra\n", "alice\n"),
        ):
            with self.subTest(group_text=group_text, authority_text=authority_text):
                row = self.run_fixture("auth required pam_wheel.so use_uid\n", group_text, authority_text)
                self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_missing_authority_is_error_only_after_structural_requirements(self):
        row = self.run_fixture("auth required pam_wheel.so use_uid\n", "wheel:x:10:root\n", None)
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "authority:not-found", "ERROR"))

    def test_malformed_authority_is_error(self):
        for authority_text in ("root\n", "alice\nalice\n", "alice,bob\n", "alice bob\n", "ali#ce\n"):
            with self.subTest(authority_text=authority_text):
                row = self.run_fixture("auth required pam_wheel.so use_uid\n", "wheel:x:10:root,alice\n", authority_text)
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_duplicate_or_malformed_wheel_is_error(self):
        for group_text in (
            "wheel:x:10:root\nwheel:x:11:root\n",
            "wheel:x:not-a-gid:root\n",
            "wheel:x:10:root,\n",
            "wheel:x:10:root,root\n",
        ):
            with self.subTest(group_text=group_text):
                row = self.run_fixture("auth required pam_wheel.so use_uid\n", group_text, "")
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_unicode_whitespace_in_names_is_locale_independent_error(self):
        locales = subprocess.run(["/usr/bin/locale", "-a"], capture_output=True, text=True, check=True).stdout.splitlines()
        utf8_locale = next((name for name in locales if name.lower() in {"c.utf8", "c.utf-8"}), None)
        self.assertIsNotNone(utf8_locale, locales)
        cases = (
            ("wheel:x:10:root,user\u2003name\n", "user\u2003name\n", "group:invalid-members"),
            ("wheel:x:10:root,user\u3000name\n", "user\u3000name\n", "group:invalid-members"),
            ("wheel:x:10:root,alice\n", "ali\u2003ce\n", "authority:invalid-record"),
            ("wheel:x:10:root,alice\n", "ali\u3000ce\n", "authority:invalid-record"),
        )
        for group_text, authority_text, reason in cases:
            observed = []
            for lc_all in ("C", utf8_locale):
                env = os.environ.copy()
                env["LC_ALL"] = lc_all
                row = self.run_fixture(
                    "auth required pam_wheel.so use_uid\n", group_text, authority_text, env=env
                )
                observed.append(row)
                self.assertEqual((row[2], row[3], row[4]), ("ERROR", reason, "ERROR"))
            self.assertEqual(observed[0], observed[1])

    def test_symlink_inputs_fail_closed(self):
        expected = {"pam": "pam:symlink", "group": "group:symlink", "authority": "authority:symlink"}
        for which, reason in expected.items():
            with self.subTest(which=which):
                row = self.run_fixture("auth required pam_wheel.so use_uid\n", "wheel:x:10:root\n", "", symlink=which)
                self.assertEqual((row[2], row[3], row[4]), ("ERROR", reason, "ERROR"))

    def test_nul_and_internal_cr_fail_closed(self):
        cases = (
            (b"auth required pam_wheel.so\x00 use_uid\n", b"wheel:x:10:root\n", b"", "pam:invalid-bytes"),
            (b"auth required pam_wheel.so use_uid\nfoo\rbar\n", b"wheel:x:10:root\n", b"", "pam:invalid-bytes"),
            (b"auth required pam_wheel.so use_uid\n", b"wheel:x:10:root\x00\n", b"", "group:invalid-bytes"),
            (b"auth required pam_wheel.so use_uid\n", b"wheel:x:10:root\n", b"alice\x00\n", "authority:invalid-bytes"),
        )
        for pam_text, group_text, authority_text, reason in cases:
            with self.subTest(pam_text=pam_text, group_text=group_text, authority_text=authority_text):
                row = self.run_fixture(pam_text, group_text, authority_text)
                self.assertEqual((row[2], row[3], row[4]), ("ERROR", reason, "ERROR"))

    def test_slash_named_od_function_cannot_override_nul_validation(self):
        row = self.run_fixture(
            b"auth required pam_wheel.so\x00 use_uid\n",
            b"wheel:x:10:root\n",
            b"",
            prelude='function /usr/bin/od(){ printf "61 62 63\n"; }',
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_bare_cr_at_eof_is_error_for_all_pam_inputs(self):
        cases = (
            (b"auth required pam_wheel.so use_uid\r", b"wheel:x:10:root\n", b""),
            (b"auth required pam_wheel.so use_uid\n", b"wheel:x:10:root\r", b""),
            (b"auth required pam_wheel.so use_uid\n", b"wheel:x:10:root,alice\n", b"alice\r"),
        )
        for pam_text, group_text, authority_text in cases:
            with self.subTest(pam_text=pam_text, group_text=group_text, authority_text=authority_text):
                row = self.run_fixture(pam_text, group_text, authority_text)
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_generated_cli_has_no_direct_external_tool_invocations(self):
        rendered = (ROOT / "securelinux-policy.sh").read_text(encoding="utf-8")
        forbidden = (
            "$(/usr/bin/", "$(/usr/sbin/", "LC_ALL=C /usr/bin/", "LC_ALL=C /usr/sbin/",
            '| LC_ALL=C /usr/bin/', '| LC_ALL=C /usr/sbin/',
            '  "$_slp_sshd" -t', '$("$_slp_sshd" -T', 'LC_ALL=C "$_slp_sort"',
        )
        for token in forbidden:
            self.assertNotIn(token, rendered, token)

    def test_missing_required_config_is_not_found_fail(self):
        row = self.run_fixture(None, "wheel:x:10:root\n", "")
        self.assertEqual((row[2], row[4]), ("NOT_FOUND", "FAIL"))

    def test_generation_rejects_wrong_contract_fields(self):
        cases = (
            ("/etc/pam.d/su", PAM_WHEEL_ACCESS.CANONICAL_KEY, PAM_WHEEL_ACCESS.CANONICAL_OP, PAM_WHEEL_ACCESS.CANONICAL_AUTHORITY),
            (PAM_WHEEL_ACCESS.CANONICAL_LOCATOR, "members", PAM_WHEEL_ACCESS.CANONICAL_OP, PAM_WHEEL_ACCESS.CANONICAL_AUTHORITY),
            (PAM_WHEEL_ACCESS.CANONICAL_LOCATOR, PAM_WHEEL_ACCESS.CANONICAL_KEY, "eq", PAM_WHEEL_ACCESS.CANONICAL_AUTHORITY),
            (PAM_WHEEL_ACCESS.CANONICAL_LOCATOR, PAM_WHEEL_ACCESS.CANONICAL_KEY, PAM_WHEEL_ACCESS.CANONICAL_OP, "/tmp/wheel"),
        )
        for args in cases:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    PAM_WHEEL_ACCESS.shell_function("TEST", *args)


class SudoersReviewedPolicyAdapterFixtures(unittest.TestCase):
    def run_fixture(self, files, authority_text, visudo_lines=None, visudo_rc=0, symlink_path=None, authority_bytes=None, prelude=""):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            sudoers = root / "sudoers"
            authority = root / "authority"
            for rel, data in files.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data if isinstance(data, bytes) else data.encode())
            if not sudoers.exists():
                sudoers.write_text("Defaults env_reset\n", encoding="utf-8")
            if symlink_path:
                target = root / (symlink_path + ".target")
                target.write_text("x\n", encoding="utf-8")
                path = root / symlink_path
                if path.exists() or path.is_symlink(): path.unlink()
                path.symlink_to(target)
            if authority_bytes is not None:
                authority.write_bytes(authority_bytes)
            elif authority_text is not None:
                authority.write_text(authority_text, encoding="utf-8", newline="")
            fake = root / "visudo"
            lines = visudo_lines
            if lines is None:
                lines = [str(root / rel) for rel in files]
                if str(sudoers) not in lines: lines.insert(0, str(sudoers))
            body = ["#!/bin/bash", "[[ \"$1\" == -c && \"$2\" == -f ]] || exit 64"]
            if visudo_rc == 0:
                for path in lines:
                    body.append("printf '%s\\n' " + shlex.quote(str(path) + ": parsed OK"))
                body.append("exit 0")
            else:
                body.append("printf '%s\\n' 'parse error' >&2")
                body.append(f"exit {visudo_rc}")
            fake.write_text("\n".join(body) + "\n", encoding="utf-8")
            fake.chmod(0o755)
            src = SUDOERS_REVIEWED_POLICY._render("TEST-SUDOERS", str(sudoers), str(authority), str(fake))
            script = root / "run.sh"
            script.write_text("#!/bin/bash -p\n" + prelude + "\n" + src + "\nslp_check_TEST_SUDOERS\n", encoding="utf-8")
            script.chmod(0o755)
            cp = subprocess.run([str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            rows = [line.split("\t") for line in cp.stdout.splitlines() if line.startswith("SLP-CHECK-V1\t")]
            self.assertEqual(len(rows), 1, cp.stdout + cp.stderr)
            return rows[0], root

    @staticmethod
    def authority_for(root, rels):
        lines = ["SLP-SUDOERS-REVIEWED-POLICY-V1"]
        for rel in rels:
            p = root / rel
            lines.append(hashlib.sha256(p.read_bytes()).hexdigest() + "\t" + str(p))
        return "\n".join(lines) + "\n"

    def test_exact_active_tree_passes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); (root/"sudoers.d").mkdir();
            (root/"sudoers").write_text("Defaults env_reset\n", encoding="utf-8")
            (root/"sudoers.d/site").write_text("alice ALL=(root) /usr/bin/id\n", encoding="utf-8")
            authority = root/"authority"; fake=root/"visudo"
            rels=["sudoers","sudoers.d/site"]
            authority.write_text(self.authority_for(root, rels), encoding="utf-8")
            fake.write_text("#!/bin/bash\nprintf '%s\\n' " + shlex.quote(str(root/"sudoers")+": parsed OK") + "\nprintf '%s\\n' " + shlex.quote(str(root/"sudoers.d/site")+": parsed OK") + "\n", encoding="utf-8"); fake.chmod(0o755)
            src=SUDOERS_REVIEWED_POLICY._render("TEST-SUDOERS",str(root/"sudoers"),str(authority),str(fake))
            script=root/"run.sh"; script.write_text("#!/bin/bash -p\n"+src+"\nslp_check_TEST_SUDOERS\n",encoding="utf-8"); script.chmod(0o755)
            cp=subprocess.run([str(script)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            self.assertEqual(cp.returncode,0,cp.stderr); row=cp.stdout.strip().split("\t")
            self.assertEqual((row[2],row[4]),("VALUE","PASS")); self.assertIn("mismatch=0",row[3])

    def test_byte_drift_and_pathset_drift_fail(self):
        for mode in ("bytes", "pathset"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=ROOT) as td:
                root=Path(td); (root/"sudoers").write_text("Defaults env_reset\n",encoding="utf-8"); (root/"site").write_text("alice ALL=ALL\n",encoding="utf-8")
                authority=root/"authority"; fake=root/"visudo"
                rels=["sudoers","site"]
                approved=self.authority_for(root,rels)
                if mode=="bytes": (root/"site").write_text("alice ALL=(root) /usr/bin/id\n",encoding="utf-8")
                else: approved="SLP-SUDOERS-REVIEWED-POLICY-V1\n"+hashlib.sha256((root/"sudoers").read_bytes()).hexdigest()+"\t"+str(root/"sudoers")+"\n"
                authority.write_text(approved,encoding="utf-8")
                fake.write_text("#!/bin/bash\nprintf '%s\\n' "+shlex.quote(str(root/"sudoers")+": parsed OK")+"\nprintf '%s\\n' "+shlex.quote(str(root/"site")+": parsed OK")+"\n",encoding="utf-8"); fake.chmod(0o755)
                src=SUDOERS_REVIEWED_POLICY._render("TEST-SUDOERS",str(root/"sudoers"),str(authority),str(fake)); script=root/"run.sh"; script.write_text("#!/bin/bash -p\n"+src+"\nslp_check_TEST_SUDOERS\n",encoding="utf-8"); script.chmod(0o755)
                cp=subprocess.run([str(script)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True); row=cp.stdout.strip().split("\t")
                self.assertEqual((row[2],row[4]),("VALUE","FAIL"))

    def test_authority_visudo_and_closure_ambiguity_error(self):
        cases={
            "missing-authority": "authority:not-found",
            "bad-header": "authority:invalid-header",
            "visudo-fail": "visudo:validation-failed",
            "unexpected-output": "visudo:unexpected-line",
            "duplicate-path": "visudo-path:duplicate-path",
        }
        for case, expected_reason in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=ROOT) as td:
                root=Path(td); sudoers=root/"sudoers"; sudoers.write_text("Defaults env_reset\n",encoding="utf-8"); authority=root/"authority"; fake=root/"visudo"
                if case!="missing-authority": authority.write_text("BAD\n" if case=="bad-header" else "SLP-SUDOERS-REVIEWED-POLICY-V1\n"+hashlib.sha256(sudoers.read_bytes()).hexdigest()+"\t"+str(sudoers)+"\n",encoding="utf-8")
                if case=="visudo-fail": body="#!/bin/bash\nexit 1\n"
                elif case=="unexpected-output": body="#!/bin/bash\nprintf '%s\\n' warning\n"
                elif case=="duplicate-path": body="#!/bin/bash\nprintf '%s\\n' "+shlex.quote(str(sudoers)+": parsed OK")+"\nprintf '%s\\n' "+shlex.quote(str(sudoers)+": parsed OK")+"\n"
                else: body="#!/bin/bash\nprintf '%s\\n' "+shlex.quote(str(sudoers)+": parsed OK")+"\n"
                fake.write_text(body,encoding="utf-8"); fake.chmod(0o755)
                src=SUDOERS_REVIEWED_POLICY._render("TEST-SUDOERS",str(sudoers),str(authority),str(fake)); script=root/"run.sh"; script.write_text("#!/bin/bash -p\n"+src+"\nslp_check_TEST_SUDOERS\n",encoding="utf-8"); script.chmod(0o755)
                cp=subprocess.run([str(script)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True); row=cp.stdout.strip().split("\t")
                self.assertEqual((row[2],row[4]),("ERROR","ERROR"))
                self.assertEqual(row[3], expected_reason)

    def test_symlink_member_and_binary_authority_error(self):
        expected = {"symlink": "visudo-path:symlink", "nul": "authority:invalid-bytes", "bare-cr": "authority:invalid-bytes"}
        for case in ("symlink","nul","bare-cr"):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=ROOT) as td:
                root=Path(td); sudoers=root/"sudoers"; sudoers.write_text("Defaults env_reset\n",encoding="utf-8"); member=root/"site.target"; member.write_text("alice ALL=ALL\n",encoding="utf-8"); site=root/"site"; site.symlink_to(member); authority=root/"authority"; fake=root/"visudo"
                if case=="nul": authority.write_bytes(b"SLP-SUDOERS-REVIEWED-POLICY-V1\n"+b"0"*64+b"\t/x\x00\n")
                elif case=="bare-cr": authority.write_bytes(b"SLP-SUDOERS-REVIEWED-POLICY-V1\r")
                else: authority.write_text("SLP-SUDOERS-REVIEWED-POLICY-V1\n"+hashlib.sha256(sudoers.read_bytes()).hexdigest()+"\t"+str(sudoers)+"\n"+hashlib.sha256(member.read_bytes()).hexdigest()+"\t"+str(site)+"\n",encoding="utf-8")
                lines=[str(sudoers)] if case!="symlink" else [str(sudoers),str(site)]
                fake.write_text("#!/bin/bash\n"+"".join("printf '%s\\n' "+shlex.quote(x+": parsed OK")+"\n" for x in lines),encoding="utf-8"); fake.chmod(0o755)
                src=SUDOERS_REVIEWED_POLICY._render("TEST-SUDOERS",str(sudoers),str(authority),str(fake)); script=root/"run.sh"; script.write_text("#!/bin/bash -p\n"+src+"\nslp_check_TEST_SUDOERS\n",encoding="utf-8"); script.chmod(0o755)
                cp=subprocess.run([str(script)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True); row=cp.stdout.strip().split("\t")
                self.assertEqual((row[2],row[4]),("ERROR","ERROR"))
                self.assertEqual(row[3], expected[case])

    def test_visudo_reported_member_object_state_reasons_are_distinct(self):
        cases = {"missing": "visudo-path:not-found", "directory": "visudo-path:invalid-type"}
        for case, expected_reason in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=ROOT) as td:
                root = Path(td)
                sudoers = root / "sudoers"
                sudoers.write_text("Defaults env_reset\n", encoding="utf-8")
                member = root / "member"
                if case == "directory":
                    member.mkdir()
                authority = root / "authority"
                authority.write_text(
                    "SLP-SUDOERS-REVIEWED-POLICY-V1\n"
                    + hashlib.sha256(sudoers.read_bytes()).hexdigest() + "\t" + str(sudoers) + "\n",
                    encoding="utf-8",
                )
                fake = root / "visudo"
                fake.write_text(
                    "#!/bin/bash\n"
                    + "printf '%s\n' " + shlex.quote(str(sudoers) + ": parsed OK") + "\n"
                    + "printf '%s\n' " + shlex.quote(str(member) + ": parsed OK") + "\n",
                    encoding="utf-8",
                )
                fake.chmod(0o755)
                src = SUDOERS_REVIEWED_POLICY._render("TEST-SUDOERS", str(sudoers), str(authority), str(fake))
                script = root / "run.sh"
                script.write_text("#!/bin/bash -p\n" + src + "\nslp_check_TEST_SUDOERS\n", encoding="utf-8")
                script.chmod(0o755)
                cp = subprocess.run([str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.assertEqual(cp.returncode, 0, cp.stderr)
                assert_stable_error_record(self, cp.stdout, "TEST-SUDOERS", expected_reason)

    def test_sudoers_visudo_reason_contract_is_branch_specific(self):
        src = SUDOERS_REVIEWED_POLICY._render("TEST-SUDOERS", "/tmp/sudoers", "/tmp/authority", "/tmp/visudo")
        for reason in (
            "visudo:unexpected-line", "visudo:empty-output", "visudo:incomplete-output",
            "visudo-path:invalid-path", "visudo-path:duplicate-path", "visudo-path:symlink",
            "visudo-path:not-found", "visudo-path:invalid-type", "visudo-path:unreadable",
            "visudo-path:hash-failed", "visudo-path:invalid-hash", "authority:read-failed",
        ):
            self.assertIn(reason, src)
        self.assertNotIn('[[ -e "$_slp_path" && -f "$_slp_path" && ! -L "$_slp_path" && -r "$_slp_path" ]]', src)

    def test_slash_named_od_function_cannot_override_binary_authority_validation(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            sudoers = root / "sudoers"
            sudoers.write_text("Defaults env_reset\n", encoding="utf-8")
            authority = root / "authority"
            authority.write_bytes(
                b"SLP-SUDOERS-REVIEWED-POLICY-V1\n"
                + b"0" * 64 + b"\t" + str(sudoers).encode() + b"\x00\n"
            )
            fake = root / "visudo"
            fake.write_text(
                "#!/bin/bash\nprintf '%s\\n' "
                + shlex.quote(str(sudoers) + ": parsed OK") + "\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            src = SUDOERS_REVIEWED_POLICY._render(
                "TEST-SUDOERS", str(sudoers), str(authority), str(fake)
            )
            script = root / "run.sh"
            script.write_text(
                "#!/bin/bash -p\n"
                "function /usr/bin/od(){ printf '61 62 63\\n'; }\n"
                + src + "\nslp_check_TEST_SUDOERS\n",
                encoding="utf-8",
            )
            script.chmod(0o755)
            cp = subprocess.run(
                [str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            row = cp.stdout.strip().split("\t")
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_slash_named_sha256sum_function_cannot_hide_policy_byte_drift(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            sudoers = root / "sudoers"
            sudoers.write_text("Defaults env_reset\n", encoding="utf-8")
            approved_digest = hashlib.sha256(sudoers.read_bytes()).hexdigest()
            authority = root / "authority"
            authority.write_text(
                "SLP-SUDOERS-REVIEWED-POLICY-V1\n"
                + approved_digest + "\t" + str(sudoers) + "\n",
                encoding="utf-8",
            )
            sudoers.write_text("Defaults env_reset\nalice ALL=(root) /usr/bin/id\n", encoding="utf-8")
            fake = root / "visudo"
            fake.write_text(
                "#!/bin/bash\nprintf '%s\\n' "
                + shlex.quote(str(sudoers) + ": parsed OK") + "\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            src = SUDOERS_REVIEWED_POLICY._render(
                "TEST-SUDOERS", str(sudoers), str(authority), str(fake)
            )
            script = root / "run.sh"
            script.write_text(
                "#!/bin/bash -p\n"
                "function /usr/bin/sha256sum(){ printf '"
                + approved_digest
                + "  %s\\n' \"$2\"; }\n"
                + src + "\nslp_check_TEST_SUDOERS\n",
                encoding="utf-8",
            )
            script.chmod(0o755)
            cp = subprocess.run(
                [str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            row = cp.stdout.strip().split("\t")
            self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
            self.assertIn("mismatch=1", row[3])

    def test_slash_named_visudo_function_cannot_override_selected_executable(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            sudoers = root / "sudoers"
            sudoers.write_text("Defaults env_reset\n", encoding="utf-8")
            authority = root / "authority"
            authority.write_text(self.authority_for(root, ["sudoers"]), encoding="utf-8")
            fake = root / "visudo"
            fake.write_text(
                "#!/bin/bash\nprintf '%s\\n' "
                + shlex.quote(str(sudoers) + ": parsed OK") + "\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            src = SUDOERS_REVIEWED_POLICY._render(
                "TEST-SUDOERS", str(sudoers), str(authority), str(fake)
            )
            script = root / "run.sh"
            script.write_text(
                "#!/bin/bash -p\n"
                "function " + str(fake) + "(){ printf '%s\\n' 'shadowed'; return 1; }\n"
                + src + "\nslp_check_TEST_SUDOERS\n",
                encoding="utf-8",
            )
            script.chmod(0o755)
            cp = subprocess.run(
                [str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            row = cp.stdout.strip().split("\t")
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
            self.assertIn("mismatch=0", row[3])

    def test_other_control_byte_in_authority_path_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            sudoers = root / "sudoers"
            sudoers.write_text("Defaults env_reset\n", encoding="utf-8")
            member = root / ("site" + "\x01" + "policy")
            member.write_text("alice ALL=(root) /usr/bin/id\n", encoding="utf-8")
            authority = root / "authority"
            authority.write_text(self.authority_for(root, ["sudoers", member.name]), encoding="utf-8", newline="")
            fake = root / "visudo"
            fake.write_text(
                "#!/bin/bash\n"
                + "printf '%s\\n' " + shlex.quote(str(sudoers) + ": parsed OK") + "\n"
                + "printf '%s\\n' " + shlex.quote(str(member) + ": parsed OK") + "\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            src = SUDOERS_REVIEWED_POLICY._render("TEST-SUDOERS", str(sudoers), str(authority), str(fake))
            script = root / "run.sh"
            script.write_text("#!/bin/bash -p\n" + src + "\nslp_check_TEST_SUDOERS\n", encoding="utf-8")
            script.chmod(0o755)
            cp = subprocess.run([str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            assert_stable_error_record(self, cp.stdout, "TEST-SUDOERS")

    def test_visudo_nul_before_parsed_ok_is_error_before_line_parsing(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            sudoers = root / "sudoers"
            sudoers.write_text("Defaults env_reset\n", encoding="utf-8")
            authority = root / "authority"
            authority.write_text(self.authority_for(root, ["sudoers"]), encoding="utf-8", newline="")
            fake = root / "visudo"
            fake.write_text(
                "#!/bin/bash\n"
                + "printf '%s\\0%s\\n' "
                + shlex.quote(str(sudoers))
                + " "
                + shlex.quote(": parsed OK")
                + "\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            src = SUDOERS_REVIEWED_POLICY._render("TEST-SUDOERS", str(sudoers), str(authority), str(fake))
            script = root / "run.sh"
            script.write_text("#!/bin/bash -p\n" + src + "\nslp_check_TEST_SUDOERS\n", encoding="utf-8")
            script.chmod(0o755)
            cp = subprocess.run([str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            assert_stable_error_record(self, cp.stdout, "TEST-SUDOERS", "visudo:invalid-bytes")
            self.assertNotIn("ignored null byte", cp.stderr.lower())

    def test_symlink_precheck_precedes_existence_for_broken_symlink_diagnostics(self):
        src = SUDOERS_REVIEWED_POLICY._render("TEST-SUDOERS", "/tmp/sudoers", "/tmp/authority", "/tmp/visudo")
        self.assertLess(src.index('[[ ! -L "$_slp_root" ]]'), src.index('[[ -e "$_slp_root" ]]'))
        self.assertLess(src.index('[[ ! -L "$_slp_authority" ]]'), src.index('[[ -e "$_slp_authority" ]]'))

    def test_generation_rejects_wrong_contract_fields(self):
        cases=(("/tmp/sudoers",SUDOERS_REVIEWED_POLICY.CANONICAL_KEY,SUDOERS_REVIEWED_POLICY.CANONICAL_OP,SUDOERS_REVIEWED_POLICY.CANONICAL_AUTHORITY),(SUDOERS_REVIEWED_POLICY.CANONICAL_LOCATOR,"users",SUDOERS_REVIEWED_POLICY.CANONICAL_OP,SUDOERS_REVIEWED_POLICY.CANONICAL_AUTHORITY),(SUDOERS_REVIEWED_POLICY.CANONICAL_LOCATOR,SUDOERS_REVIEWED_POLICY.CANONICAL_KEY,"eq",SUDOERS_REVIEWED_POLICY.CANONICAL_AUTHORITY),(SUDOERS_REVIEWED_POLICY.CANONICAL_LOCATOR,SUDOERS_REVIEWED_POLICY.CANONICAL_KEY,SUDOERS_REVIEWED_POLICY.CANONICAL_OP,"/tmp/policy"))
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError): SUDOERS_REVIEWED_POLICY.shell_function("TEST",*args)



class SudoRootCommandFilesProtectionFixtures(unittest.TestCase):
    @staticmethod
    def _user_spec(user="alice", runas="root", command="/bin/tool", negated=False, host_list=None):
        spec = {
            "User_List": [{"username": user}],
            "Host_List": host_list if host_list is not None else [{"hostname": "ALL"}],
            "Cmnd_Specs": [{"Commands": [{"command": command, **({"negated": True} if negated else {})}]}],
        }
        if runas is not None:
            spec["Cmnd_Specs"][0]["runasusers"] = [{"username": runas}]
        return spec

    def run_fixture(self, specs, mode=0o755, logical_root_uid=None, policy_drift=False, cvt_rc=0, malformed_json=False, symlink=False, mutate_target_second_cvt=False, target_logical="/bin/tool", extra_executables=(), defaults=None, symlink_real_name=None, hardlink_real_name=None, target_bytes=None):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot = root / "fs"
            logical_target = Path(target_logical)
            if not logical_target.is_absolute():
                raise AssertionError("fixture target must be absolute")
            link_path = fsroot / str(logical_target).lstrip("/")
            link_path.parent.mkdir(parents=True, exist_ok=True)
            if hardlink_real_name is not None:
                target = link_path.with_name(hardlink_real_name)
                target.write_bytes(target_bytes if target_bytes is not None else b"\x7fELF-SLP-FIXTURE\n")
                target.chmod(mode)
                os.link(target, link_path)
            else:
                target = link_path.with_name(symlink_real_name or (link_path.name + ".real")) if symlink else link_path
                target.write_bytes(target_bytes if target_bytes is not None else b"\x7fELF-SLP-FIXTURE\n")
                target.chmod(mode)
                if symlink:
                    link_path.symlink_to(target.name)
            for extra in extra_executables:
                if isinstance(extra, tuple):
                    extra, extra_mode = extra
                else:
                    extra_mode = 0o755
                extra_path = fsroot / str(extra).lstrip("/")
                extra_path.parent.mkdir(parents=True, exist_ok=True)
                extra_path.write_bytes(b"\x7fELF-SLP-FIXTURE\n")
                extra_path.chmod(extra_mode)
            sudoers = root / "sudoers"
            sudoers.write_text("Defaults env_reset\n", encoding="utf-8")
            authority = root / "authority"
            digest = hashlib.sha256(sudoers.read_bytes()).hexdigest()
            authority.write_text("SLP-SUDOERS-REVIEWED-POLICY-V1\n" + digest + "\t" + str(sudoers) + "\n", encoding="utf-8")
            if policy_drift:
                sudoers.write_text("Defaults env_reset\nalice ALL=(root) /bin/tool\n", encoding="utf-8")
            fake_visudo = root / "visudo"
            fake_visudo.write_text("#!/bin/bash\nprintf '%s\\n' " + shlex.quote(str(sudoers) + ": parsed OK") + "\n", encoding="utf-8")
            fake_visudo.chmod(0o755)
            fake_cvt = root / "cvtsudoers"
            state = root / "cvt-state"
            if malformed_json:
                body = "printf '%s\\n' '{bad json'\nexit 0"
            elif cvt_rc:
                body = "printf '%s\\n' 'conversion failed' >&2\nexit " + str(cvt_rc)
            else:
                payload_obj = {"User_Specs": specs}
                if defaults is not None:
                    payload_obj["Defaults"] = defaults
                payload = json.dumps(payload_obj, sort_keys=True)
                body = "printf '%s\\n' " + shlex.quote(payload)
                if mutate_target_second_cvt:
                    body = (
                        "if [[ -e " + shlex.quote(str(state)) + " ]]; then /usr/bin/chmod 0775 " + shlex.quote(str(target)) + "; "
                        "else : > " + shlex.quote(str(state)) + "; fi\n" + body
                    )
            fake_cvt.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8")
            fake_cvt.chmod(0o755)
            if logical_root_uid is None:
                logical_root_uid = os.getuid()
            src = SUDO_ROOT_COMMAND_FILES.shell_function_for_fixture(
                "TEST-SUDO-ROOT-FILES",
                SUDO_ROOT_COMMAND_FILES.CANONICAL_LOCATOR,
                SUDO_ROOT_COMMAND_FILES.CANONICAL_KEY,
                SUDO_ROOT_COMMAND_FILES.CANONICAL_OP,
                SUDO_ROOT_COMMAND_FILES.CANONICAL_EXPECTED,
                str(fsroot), logical_root_uid, str(sudoers), str(authority), str(fake_visudo), str(fake_cvt),
            )
            script = root / "run.sh"
            script.write_text("#!/bin/bash -p\n" + src + "\nslp_check_TEST_SUDO_ROOT_FILES\n", encoding="utf-8")
            script.chmod(0o755)
            cp = subprocess.run([str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            rows = [line.split("\t") for line in cp.stdout.splitlines() if line.startswith("SLP-CHECK-V1\t")]
            self.assertEqual(len(rows), 1, cp.stdout + cp.stderr)
            return rows[0]

    def test_adapter_selftest(self):
        cp = subprocess.run([str(SUDO_ROOT_COMMAND_FILES_ADAPTER_PATH)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("ADAPTER_SELFTEST=PASS", cp.stdout)

    def test_exact_root_owned_go_w_passes(self):
        row = self.run_fixture([self._user_spec()])
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("files=1;owner_violations=0;mode_violations=0", row[3])

    def test_owner_mismatch_is_fail_without_chown_fixture(self):
        other_uid = os.getuid() + 1 if os.getuid() != (2**32 - 1) else 1
        row = self.run_fixture([self._user_spec()], logical_root_uid=other_uid)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("owner_violations=1", row[3])

    def test_group_other_write_is_fail(self):
        row = self.run_fixture([self._user_spec()], mode=0o775)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("mode_violations=1", row[3])

    def test_symlink_final_target_is_checked(self):
        row = self.run_fixture([self._user_spec()], mode=0o775, symlink=True)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("mode_violations=1", row[3])

    def test_executable_path_with_space_is_not_truncated_to_first_word(self):
        row = self.run_fixture(
            [self._user_spec(command="/bin/my tool --flag value")],
            mode=0o775,
            target_logical="/bin/my tool",
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("files=1;owner_violations=0;mode_violations=1", row[3])

    def test_executable_path_argument_boundary_ambiguity_is_error(self):
        row = self.run_fixture(
            [self._user_spec(command="/bin/tool arg --flag")],
            extra_executables=("/bin/tool arg",),
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:ambiguous-command-path")

    def test_root_only_invoker_all_is_outside_population(self):
        row = self.run_fixture([self._user_spec(user="root", runas="ALL", command="ALL")])
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("files=0", row[3])

    def test_non_root_runas_is_outside_population(self):
        row = self.run_fixture([self._user_spec(runas="nobody")])
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("files=0", row[3])

    def test_unbounded_and_dynamic_command_forms_are_error(self):
        cases = {
            "ALL": "sudo-policy:all-command",
            "/opt/*/tool": "sudo-policy:wildcard-command",
            "^/usr/bin/[a-z]+$": "sudo-policy:regex-command",
            "relative": "sudo-policy:nonabsolute-command",
            "/opt/tools/": "sudo-policy:directory-command",
        }
        for command, reason in cases.items():
            with self.subTest(command=command):
                row = self.run_fixture([self._user_spec(command=command)])
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
                self.assertEqual(row[3], reason)

    def test_negated_command_is_error_not_overchecked(self):
        row = self.run_fixture([self._user_spec(command="/bin/tool", negated=True)], mode=0o775)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:negated-command")

    def test_command_digest_is_error_not_overchecked(self):
        spec = self._user_spec(command="/bin/tool")
        spec["Cmnd_Specs"][0]["Commands"][0]["sha256"] = "00" * 32
        row = self.run_fixture([spec], mode=0o775)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:digest-qualified-command")

    def test_host_qualified_rule_is_error_not_overchecked(self):
        row = self.run_fixture(
            [self._user_spec(host_list=[{"hostname": "definitely-other-host.invalid"}])],
            mode=0o775,
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:unsupported-host-selector")

    def test_ambiguous_invoker_membership_is_error_not_overchecked(self):
        spec = self._user_spec()
        spec["User_List"] = [{"usergroup": "admins"}]
        row = self.run_fixture([spec], mode=0o775)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:unsupported-user-selector")

    def test_ambiguous_runas_membership_is_error_not_overchecked(self):
        spec = self._user_spec()
        spec["Cmnd_Specs"][0]["runasusers"] = [{"usergroup": "admins"}]
        row = self.run_fixture([spec], mode=0o775)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:unsupported-runas-selector")

    def test_policy_authority_drift_is_error(self):
        row = self.run_fixture([self._user_spec()], policy_drift=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "authority:policy-mismatch")

    def test_cvtsudoers_failure_and_malformed_json_are_error(self):
        row = self.run_fixture([self._user_spec()], cvt_rc=1)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "cvtsudoers:execution-failed")
        row = self.run_fixture([self._user_spec()], malformed_json=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "cvtsudoers:invalid-output")

    def test_target_snapshot_drift_is_error(self):
        row = self.run_fixture([self._user_spec()], mutate_target_second_cvt=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "observation:target-changed")

    def test_case_insensitive_root_identity_is_not_misclassified(self):
        # sudo user-name matching is case-insensitive by default.  An alternate
        # spelling of root must therefore retain root semantics.
        row = self.run_fixture([self._user_spec(user="ROOT", runas="root")], mode=0o775)
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("files=0", row[3])
        row = self.run_fixture([self._user_spec(user="alice", runas="ROOT")], mode=0o775)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("mode_violations=1", row[3])

    def test_temporal_command_window_is_error_not_overchecked(self):
        for option in ({"notafter": "20000101000000Z"}, {"notbefore": "29990101000000Z"}):
            with self.subTest(option=option):
                spec = self._user_spec()
                spec["Cmnd_Specs"][0]["Options"] = [option]
                row = self.run_fixture([spec], mode=0o775)
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:time-qualified-command")

    def test_case_insensitive_user_default_override_is_error(self):
        row = self.run_fixture(
            [self._user_spec()],
            mode=0o775,
            defaults=[{"Options": [{"case_insensitive_user": False}]}],
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:case-insensitive-user-unsupported")

    def test_runas_default_is_error_not_overchecked(self):
        # Without an explicit Runas_Spec, sudo uses Defaults runas_default.
        # A non-root runas_default means this command is not root-runnable;
        # v1 must not over-approximate it into a mode/owner FAIL population.
        spec = self._user_spec(runas=None)
        row = self.run_fixture(
            [spec],
            mode=0o775,
            defaults=[{"Options": [{"runas_default": "nobody"}]}],
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:runas-default-unsupported")

    def test_runchroot_option_or_default_is_error(self):
        spec = self._user_spec()
        spec["Cmnd_Specs"][0]["Options"] = [{"runchroot": "/srv/chroot"}]
        row = self.run_fixture([spec])
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:runchroot-enabled")
        row = self.run_fixture(
            [self._user_spec()],
            defaults=[{"Options": [{"runchroot": "/srv/chroot"}]}],
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:runchroot-enabled")

    def test_interpreter_and_execution_frontend_are_error(self):
        for path in ("/bin/sh", "/usr/bin/env", "/usr/bin/time", "/usr/bin/run-parts"):
            with self.subTest(path=path):
                row = self.run_fixture(
                    [self._user_spec(command=path + " /opt/job")],
                    target_logical=path,
                )
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
                self.assertEqual(row[3], "target:unsupported-execution-chain")

    def test_symlink_alias_to_execution_frontend_is_error(self):
        row = self.run_fixture(
            [self._user_spec(command="/bin/tool /opt/job")],
            target_logical="/bin/tool",
            symlink=True,
            symlink_real_name="env",
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "target:unsupported-execution-chain")

    def test_hardlink_alias_is_error(self):
        row = self.run_fixture(
            [self._user_spec(command="/bin/tool /opt/job")],
            target_logical="/bin/tool",
            hardlink_real_name="env",
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "target:unsupported-execution-chain")


    def test_shebang_execution_chain_is_error(self):
        for interpreter_mode in (0o755, 0o775):
            with self.subTest(interpreter_mode=oct(interpreter_mode)):
                row = self.run_fixture(
                    [self._user_spec()],
                    target_bytes=b"#!/opt/custominterp\nexit 0\n",
                    extra_executables=(("/opt/custominterp", interpreter_mode),),
                )
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
                self.assertEqual(row[3], "target:unsupported-execution-chain")

    def test_generation_rejects_wrong_contract_fields(self):
        bad = (
            ("/etc/sudoers", SUDO_ROOT_COMMAND_FILES.CANONICAL_KEY, SUDO_ROOT_COMMAND_FILES.CANONICAL_OP, SUDO_ROOT_COMMAND_FILES.CANONICAL_EXPECTED),
            (SUDO_ROOT_COMMAND_FILES.CANONICAL_LOCATOR, "mode", SUDO_ROOT_COMMAND_FILES.CANONICAL_OP, SUDO_ROOT_COMMAND_FILES.CANONICAL_EXPECTED),
            (SUDO_ROOT_COMMAND_FILES.CANONICAL_LOCATOR, SUDO_ROOT_COMMAND_FILES.CANONICAL_KEY, "eq", SUDO_ROOT_COMMAND_FILES.CANONICAL_EXPECTED),
            (SUDO_ROOT_COMMAND_FILES.CANONICAL_LOCATOR, SUDO_ROOT_COMMAND_FILES.CANONICAL_KEY, SUDO_ROOT_COMMAND_FILES.CANONICAL_OP, "0022"),
        )
        for args in bad:
            with self.assertRaises(ValueError):
                SUDO_ROOT_COMMAND_FILES.shell_function("TEST", *args)


class SshdRootLoginAdapterFixtures(unittest.TestCase):
    def run_fixture(
        self, config_text=None, effective="no", syntax_rc=0, include_files=None,
        make_symlink=False, shadow_compgen=False, sort_fail=False, env=None,
    ):
        if BASH is None:
            self.skipTest("bash not found")
        include_files = include_files or {}
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            cfg = root / "sshd_config"
            if config_text is not None:
                if isinstance(config_text, bytes):
                    cfg.write_bytes(config_text)
                else:
                    config_text = config_text.replace("/etc/ssh/TEST-INCLUDE.conf", str(root / "TEST-INCLUDE.conf"))
                    config_text = config_text.replace("/etc/ssh/TEST-INCLUDE-DIR", str(root / "TEST-INCLUDE-DIR"))
                    cfg.write_bytes(config_text.encode("utf-8"))
            if make_symlink:
                target = root / "real-config"
                target.write_text("PermitRootLogin no\n", encoding="utf-8")
                if cfg.exists():
                    cfg.unlink()
                cfg.symlink_to(target)
            for name, body in include_files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
            sshd = root / "sshd"
            sshd.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == -t ]]; then exit " + str(syntax_rc) + "; fi\n"
                "if [[ ${1:-} == -T ]]; then printf '%s\\n' 'permitrootlogin " + effective + "'; exit 0; fi\n"
                "exit 2\n",
                encoding="utf-8",
            )
            sshd.chmod(0o755)
            sort_path = "/usr/bin/sort"
            if sort_fail:
                fake_sort = root / "sort"
                fake_sort.write_text("#!/usr/bin/env bash\nexit 74\n", encoding="utf-8")
                fake_sort.chmod(0o755)
                sort_path = str(fake_sort)
            block = SSHD_ROOT_LOGIN._shell_function_for_fixture(
                "SSH.TEST", str(cfg), str(sshd), "PermitRootLogin", "eq", "no", sort_path
            )
            prelude = "compgen() { return 1; }\n" if shadow_compgen else ""
            cp = subprocess.run(
                [BASH, "-c", "set -u\n" + prelude + block + "\nslp_check_SSH_TEST\n"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                env=env,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            return cp.stdout.strip().split("\t")

    def test_positive_main_no(self):
        row = self.run_fixture("PermitRootLogin no\n")
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("effective=no", row[3])

    def test_openssh_separator_quote_and_crlf_forms(self):
        for line in (
            "PermitRootLogin=no\n",
            "PermitRootLogin = no\n",
            "PermitRootLogin= no\n",
            "PermitRootLogin =no\n",
            'PermitRootLogin "no"\n',
            "PermitRootLogin 'no'\n",
            'PermitRootLogin="no"\n',
            "PermitRootLogin no\r\n",
        ):
            with self.subTest(line=line):
                row = self.run_fixture(line)
                self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        row = self.run_fixture("PermitRootLogin no\nMatch=User root\nPermitRootLogin yes\n")
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        row = self.run_fixture(
            "PermitRootLogin no\nInclude=/etc/ssh/TEST-INCLUDE.conf\n",
            include_files={"TEST-INCLUDE.conf": "Match User root\nPermitRootLogin yes\n"},
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_unicode_whitespace_is_not_a_locale_dependent_sshd_separator(self):
        for edge in ("\u2003", "\u3000"):
            with self.subTest(edge=repr(edge)):
                observed = []
                for locale_name in ("C", "C.utf8"):
                    env = os.environ.copy()
                    env["LC_ALL"] = locale_name
                    row = self.run_fixture("PermitRootLogin" + edge + "no\n", env=env)
                    observed.append(tuple(row[2:5]))
                self.assertEqual(observed[0], observed[1])
                self.assertEqual(observed[0], ("VALUE", "main_global_no=0;effective=no", "FAIL"))

    def test_nul_and_non_crlf_cr_are_rejected_before_line_parsing(self):
        row = self.run_fixture(b"PermitRootLogin no\x00\n")
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "sshd-config:invalid-bytes", "ERROR"))
        row = self.run_fixture(b"PermitRootLogin no\r")
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "sshd-config:invalid-bytes", "ERROR"))
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE.conf\n",
            include_files={"TEST-INCLUDE.conf": b"PermitRootLogin no\x00\n"},
        )
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "sshd-config:invalid-bytes", "ERROR"))

    def test_malformed_relevant_directives_error(self):
        for line in (
            "PermitRootLogin\n",
            "PermitRootLogin no extra\n",
            "PermitRootLogin==no\n",
            'PermitRootLogin "no\n',
            "Include=\n",
            "Match=\n",
        ):
            with self.subTest(line=line):
                row = self.run_fixture(line)
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_include_scope_is_restored_between_glob_members(self):
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE-DIR/*.conf\n",
            include_files={
                "TEST-INCLUDE-DIR/10-match.conf": "Match User nobody\n",
                "TEST-INCLUDE-DIR/20-global.conf": "PermitRootLogin yes\n",
            },
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))

    def test_include_scope_push_pop_and_inheritance(self):
        # Match created inside Include must not leak back to following main-file directives.
        row = self.run_fixture(
            "Include /etc/ssh/TEST-INCLUDE.conf\nPermitRootLogin no\n",
            include_files={"TEST-INCLUDE.conf": "Match User nobody\n"},
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("main_global_no=1", row[3])

        # Conversely, an Include reached from Match scope must inherit that scope.
        row = self.run_fixture(
            "PermitRootLogin no\nMatch User nobody\nInclude /etc/ssh/TEST-INCLUDE.conf\n",
            include_files={"TEST-INCLUDE.conf": "PermitRootLogin yes\n"},
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_comment_marker_inside_include_filename_is_not_comment(self):
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE-DIR/file#prod.conf # trailing comment\n",
            include_files={
                "TEST-INCLUDE-DIR/file#prod.conf": "Match User root\nPermitRootLogin yes\n",
            },
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_quoted_include_is_parsed(self):
        row = self.run_fixture(
            'PermitRootLogin no\nInclude "/etc/ssh/TEST-INCLUDE.conf"\n',
            include_files={"TEST-INCLUDE.conf": "Match User root\nPermitRootLogin yes\n"},
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_compgen_function_shadow_cannot_hide_include_population(self):
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE-DIR/*.conf\n",
            include_files={
                "TEST-INCLUDE-DIR/20.conf": "Match User root\nPermitRootLogin yes\n",
            },
            shadow_compgen=True,
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_sort_failure_is_error(self):
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE-DIR/*.conf\n",
            include_files={
                "TEST-INCLUDE-DIR/20.conf": "Match User root\nPermitRootLogin yes\n",
            },
            sort_fail=True,
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_newline_glob_member_is_error(self):
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE-DIR/*.conf\n",
            include_files={
                "TEST-INCLUDE-DIR/bad\nfragment.conf": "Match User root\nPermitRootLogin yes\n",
            },
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_glob_implementation_is_explicit_and_builtin(self):
        block = SSHD_ROOT_LOGIN._shell_function_for_fixture(
            "SSH.TEST", "/tmp/sshd_config", "/tmp/sshd", "PermitRootLogin", "eq", "no"
        )
        self.assertIn('builtin compgen -G', block)
        self.assertIn('LC_ALL=C command "$_slp_sort"', block)
        self.assertIn('set -o pipefail', block)

    def test_main_directive_absent_fails(self):
        row = self.run_fixture("PasswordAuthentication no\n")
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_main_non_no_fails(self):
        row = self.run_fixture("PermitRootLogin prohibit-password\n", effective="prohibit-password")
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_global_include_before_main_controls_effective(self):
        row = self.run_fixture(
            "Include /etc/ssh/TEST-INCLUDE.conf\nPermitRootLogin no\n",
            effective="prohibit-password",
            include_files={"TEST-INCLUDE.conf": "PermitRootLogin prohibit-password\n"},
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_match_non_no_fails_closed_error(self):
        row = self.run_fixture("PermitRootLogin no\nMatch User root\n  PermitRootLogin yes\n")
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_match_no_is_safe(self):
        row = self.run_fixture("PermitRootLogin no\nMatch User root\n  PermitRootLogin no\n")
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))

    def test_effective_non_no_fails(self):
        row = self.run_fixture("PermitRootLogin no\n", effective="prohibit-password")
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_syntax_failure_errors(self):
        row = self.run_fixture("PermitRootLogin no\n", syntax_rc=1)
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "sshd-config:validation-failed", "ERROR"))

    def test_missing_config_not_found(self):
        row = self.run_fixture(None)
        self.assertEqual((row[2], row[4]), ("NOT_FOUND", "FAIL"))

    def test_symlink_config_errors(self):
        row = self.run_fixture(None, make_symlink=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))


class RunningProcessPathsWriteProtectionFixtures(unittest.TestCase):
    @staticmethod
    def _stat_text(pid_name="1", start="123"):
        fields = ["S"] + ["0"] * 49
        fields[19] = start
        return f"{pid_name} (fixture) " + " ".join(fields) + "\n"

    @staticmethod
    def _status_text(state="S", kthread=0):
        return f"State:\t{state} (fixture)\nKthread:\t{kthread}\n"

    def _prepare_fs(self, root, name="app"):
        fsroot = root / "fsroot"
        bindir = fsroot / "opt" / name / "bin"
        libdir = fsroot / "opt" / name / "lib"
        bindir.mkdir(parents=True)
        libdir.mkdir(parents=True)
        exe = bindir / name
        lib = libdir / "libfixture.so.1"
        exe.write_text("x\n", encoding="utf-8")
        lib.write_text("x\n", encoding="utf-8")
        exe.chmod(0o555)
        lib.chmod(0o555)
        return fsroot, exe, lib, libdir

    @staticmethod
    def _seal_fs(fsroot, names, mode=0o555):
        for d in (fsroot, fsroot / "opt"):
            d.chmod(mode)
        for name in names:
            for d in (fsroot / "opt" / name, fsroot / "opt" / name / "bin", fsroot / "opt" / name / "lib"):
                d.chmod(mode)

    def _add_pid(self, proc, pid_name, exe, maps_text, start="123", status=None):
        pid = proc / str(pid_name)
        pid.mkdir(parents=True)
        (pid / "stat").write_text(self._stat_text(str(pid_name), start), encoding="ascii")
        (pid / "status").write_text(status or self._status_text(), encoding="utf-8")
        if exe is not None:
            (pid / "exe").symlink_to(exe)
        if maps_text is not None:
            (pid / "maps").write_text(maps_text, encoding="utf-8")
        return pid

    @staticmethod
    def _maps_line(
        path, *, perms="r-xp", inode=None, dev=None,
        address="00400000-00401000", offset="00000000", source_path=None,
    ):
        if source_path is None:
            candidate = Path(str(path))
            if str(path).startswith("/") and candidate.exists():
                source_path = candidate
        if source_path is not None:
            st = os.stat(source_path)
            if inode is None:
                inode = st.st_ino
            if dev is None:
                dev = f"{os.major(st.st_dev):x}:{os.minor(st.st_dev):x}"
        if inode is None:
            inode = 0 if str(path).startswith("[") else 1
        if dev is None:
            dev = "00:00"
        return f"{address} {perms} {offset} {dev} {inode} {path}\n"

    @staticmethod
    def _prepare_proc(root, forks=1000):
        proc = root / "proc"
        proc.mkdir()
        (proc / "stat").write_text(
            f"cpu  0 0 0 0 0 0 0 0 0 0\nprocesses {forks}\n",
            encoding="ascii",
        )
        return proc

    @staticmethod
    def _set_process_counter(proc, forks):
        (proc / "stat").write_text(
            f"cpu  0 0 0 0 0 0 0 0 0 0\nprocesses {forks}\n",
            encoding="ascii",
        )

    def _script(self, root, proc, fsroot):
        src = RUNNING_PROCESS_PATHS._shell_function_for_roots(
            "TEST-RUNTIME-PATHS", str(proc), str(fsroot)
        )
        script = root / "run.sh"
        script.write_text(
            "#!/bin/bash -p\n" + src + "\nslp_check_TEST_RUNTIME_PATHS\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script

    def _run_script(self, script):
        cp = subprocess.run(
            [str(script)], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        row = cp.stdout.strip().split("\t")
        self.assertEqual(len(row), 5, cp.stdout + cp.stderr)
        return row

    def _popen_script(self, script):
        return subprocess.Popen(
            [str(script)], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    @staticmethod
    def _open_fifo_writer(path, timeout=20.0):
        deadline = time.monotonic() + timeout
        while True:
            try:
                return os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as exc:
                if exc.errno != errno.ENXIO or time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)

    def _finish_popen(self, cp, timeout=20.0):
        out, err = cp.communicate(timeout=timeout)
        self.assertEqual(cp.returncode, 0, err)
        row = out.strip().split("\t")
        self.assertEqual(len(row), 5, out + err)
        return row

    @staticmethod
    def _start_fifo_writer_handshake(path, text):
        opened = threading.Event()
        release = threading.Event()
        failures = []

        def writer():
            try:
                with open(path, "w", encoding="utf-8") as stream:
                    opened.set()
                    if not release.wait(timeout=20.0):
                        raise TimeoutError("FIFO writer release handshake timed out")
                    stream.write(text)
                    stream.flush()
            except Exception as exc:
                failures.append(exc)
                opened.set()

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        return thread, opened, release, failures

    @staticmethod
    def _runtime_reason_namespace():
        tree = ast.parse(RUNNING_PROCESS_PATHS._PY)
        selected = []
        wanted = {"error", "obj_state", "recheck_files", "recheck_parents"}
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                selected.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name in wanted:
                selected.append(node)
        namespace = {}
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                "<running-process-recheck-semantics>",
                "exec",
            ),
            namespace,
        )
        return namespace

    def run_fixture(
        self, *, file_mode=0o555, parent_mode=0o555, deleted_library=False,
        no_library=False, mapped_name="libfixture.so.1", proc_escape_space=False,
        malformed_escape=False,
    ):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, libdir = self._prepare_fs(root)
            if mapped_name != lib.name:
                replacement = libdir / mapped_name
                lib.rename(replacement)
                lib = replacement
            exe.chmod(file_mode)
            lib.chmod(file_mode)
            self._seal_fs(fsroot, ("app",), parent_mode)

            proc = self._prepare_proc(root)
            if no_library:
                maps_path = "[heap]"
                maps = self._maps_line(maps_path, perms="rw-p", inode=0)
            else:
                maps_path = str(lib)
                if proc_escape_space:
                    maps_path = maps_path.replace(" ", r"\040")
                if malformed_escape:
                    maps_path += r"\04x"
                if deleted_library:
                    maps_path += " (deleted)"
                maps = self._maps_line(maps_path, source_path=lib)
            self._add_pid(proc, "100", exe, maps)
            return self._run_script(self._script(root, proc, fsroot))

    def test_adapter_selftest(self):
        cp = subprocess.run(
            [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B", str(RUNNING_PROCESS_PATHS_ADAPTER_PATH)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("ADAPTER_SELFTEST=PASS", cp.stdout)

    def test_positive_dynamic_population(self):
        row = self.run_fixture()
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("file_violations=0", row[3])
        self.assertIn("parent_violations=0", row[3])

    def test_file_go_w_is_fail(self):
        row = self.run_fixture(file_mode=0o575)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("file_violations=", row[3])

    def test_unprivileged_parent_write_is_fail(self):
        # other wx proves an unprivileged write path regardless of group membership.
        row = self.run_fixture(parent_mode=0o707)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("parent_violations=", row[3])

    def test_group_wx_parent_classification_is_owner_sensitive(self):
        # The fixture directory is owned by the test runner.  Under root, 0770
        # isolates the group-class wx ambiguity and must ERROR.  Under an
        # ordinary runner, owner-class wx itself proves an unprivileged write
        # path and must FAIL; this is not a skip and exercises the real runtime.
        row = self.run_fixture(parent_mode=0o770)
        expected = ("ERROR", "ERROR") if os.geteuid() == 0 else ("VALUE", "FAIL")
        self.assertEqual((row[2], row[4]), expected)
        if os.geteuid() == 0:
            self.assertEqual(row[3], "parent:group-write-ambiguous")

    def test_write_without_search_in_group_class_is_not_alone_a_violation(self):
        # With a root-owned fixture (root test runner), 0720 has group write but
        # no group search and therefore does not prove directory-entry write.
        # With an ordinary test runner the same directory is owned by that
        # unprivileged user and owner-class wx is a definite violation.
        row = self.run_fixture(parent_mode=0o720)
        expected = ("VALUE", "PASS") if os.geteuid() == 0 else ("VALUE", "FAIL")
        self.assertEqual((row[2], row[4]), expected)

    def test_deleted_library_is_error(self):
        row = self.run_fixture(deleted_library=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "proc-maps:deleted-path")

    def test_missing_library_population_is_error(self):
        row = self.run_fixture(no_library=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "proc-maps:empty-executable-population")

    def test_executable_mapping_without_shared_object_name_is_checked(self):
        row = self.run_fixture(mapped_name="render.plugin", file_mode=0o575)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_proc_octal_escaped_mapping_path_is_decoded(self):
        row = self.run_fixture(mapped_name="render plugin", proc_escape_space=True, file_mode=0o575)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_malformed_proc_escape_is_error(self):
        row = self.run_fixture(malformed_escape=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "proc:invalid-path-escape")

    def test_each_pid_requires_file_backed_executable_mapping(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, _ = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            proc = self._prepare_proc(root)
            self._add_pid(proc, "100", exe1, self._maps_line("[heap]", perms="rw-p", inode=0))
            self._add_pid(proc, "200", exe2, self._maps_line(str(lib2)))
            self._seal_fs(fsroot, ("app1", "app2"))
            row = self._run_script(self._script(root, proc, fsroot))
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_pid_population_growth_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, _ = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            proc = self._prepare_proc(root)
            pid1 = self._add_pid(proc, "100", exe1, None)
            fifo = pid1 / "maps"; os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app1", "app2"))
            cp = self._popen_script(self._script(root, proc, fsroot))
            fd = self._open_fifo_writer(fifo)
            try:
                self._add_pid(proc, "200", exe2, self._maps_line(str(lib2)))
                os.write(fd, self._maps_line(str(lib1)).encode("utf-8"))
            finally:
                os.close(fd)
            row = self._finish_popen(cp)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "pid-population:mid-snapshot-changed")

    def test_identity_change_after_no_exe_classification_is_error(self):
        tree = ast.parse(RUNNING_PROCESS_PATHS._PY)
        selected = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                selected.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name in {
                "error", "read_start", "classify_no_exe",
            }:
                selected.append(node)
        namespace = {}
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                "<src0006-classify-no-exe>",
                "exec",
            ),
            namespace,
        )

        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            pid = Path(td) / "100"
            pid.mkdir()
            (pid / "status").write_text(
                self._status_text(state="Z"),
                encoding="utf-8",
            )

            namespace["read_start"] = lambda _pid: "123"
            self.assertEqual(
                namespace["classify_no_exe"](pid, "123"),
                "excluded",
            )

            namespace["read_start"] = lambda _pid: "456"
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                with self.assertRaises(SystemExit) as cm:
                    namespace["classify_no_exe"](pid, "123")
            self.assertEqual(cm.exception.code, 0)
            self.assertEqual(captured.getvalue().strip(), "ERROR\tproc-stat:excluded-classification-changed")

    def _snapshot_drift_case(self, mutate_parent):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, libdir1 = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            proc = self._prepare_proc(root)
            self._add_pid(proc, "100", exe1, self._maps_line(str(lib1)))
            pid2 = self._add_pid(proc, "200", exe2, None)
            fifo = pid2 / "maps"
            first_fifo = pid2 / "maps.first"
            os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app1", "app2"))

            maps_text = self._maps_line(str(lib2))
            first_thread, first_opened, first_release, first_failures = (
                self._start_fifo_writer_handshake(fifo, maps_text)
            )
            cp = self._popen_script(self._script(root, proc, fsroot))

            self.assertTrue(
                first_opened.wait(timeout=20.0),
                "observer did not reach first maps snapshot",
            )
            self.assertEqual(first_failures, [])

            if mutate_parent:
                libdir1.chmod(0o775)
            else:
                lib1.chmod(0o575)

            os.replace(fifo, first_fifo)
            os.mkfifo(fifo)
            second_thread, second_opened, second_release, second_failures = (
                self._start_fifo_writer_handshake(fifo, maps_text)
            )

            first_release.set()
            first_thread.join(timeout=20.0)
            self.assertFalse(first_thread.is_alive(), "first maps FIFO writer did not finish")
            self.assertEqual(first_failures, [])

            self.assertTrue(
                second_opened.wait(timeout=20.0),
                "observer did not reach maps recheck",
            )
            self.assertEqual(second_failures, [])
            second_release.set()

            row = self._finish_popen(cp)
            second_thread.join(timeout=20.0)
            self.assertFalse(second_thread.is_alive(), "second maps FIFO writer did not finish")
            self.assertEqual(second_failures, [])
            return row

    def test_file_recheck_reason_semantics_are_exact(self):
        namespace = self._runtime_reason_namespace()
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "fixture"
            path.write_text("x\n", encoding="utf-8")
            state = namespace["obj_state"](os.stat(path))
            records = {str(path): (str(path), state, state)}
            path.chmod(0o575)
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                with self.assertRaises(SystemExit) as cm:
                    namespace["recheck_files"](records)
            self.assertEqual(cm.exception.code, 0)
            self.assertEqual(captured.getvalue().strip(), "ERROR\tpath:recheck-snapshot-changed")

    def test_parent_recheck_reason_semantics_are_exact(self):
        namespace = self._runtime_reason_namespace()
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "fixture-parent"
            path.mkdir()
            state = namespace["obj_state"](os.stat(path))
            records = {str(path): state}
            path.chmod(0o775)
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                with self.assertRaises(SystemExit) as cm:
                    namespace["recheck_parents"](records)
            self.assertEqual(cm.exception.code, 0)
            self.assertEqual(captured.getvalue().strip(), "ERROR\tparent:recheck-snapshot-changed")

    def test_file_snapshot_drift_is_error(self):
        row = self._snapshot_drift_case(False)
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "path:recheck-snapshot-changed", "ERROR"))

    def test_parent_snapshot_drift_is_error(self):
        row = self._snapshot_drift_case(True)
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "parent:recheck-snapshot-changed", "ERROR"))


    def test_maps_declared_identity_mismatch_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, _ = self._prepare_fs(root)
            proc = self._prepare_proc(root)
            st = os.stat(lib)
            maps = self._maps_line(
                str(lib),
                inode=st.st_ino + 1,
                dev=f"{os.major(st.st_dev):x}:{os.minor(st.st_dev):x}",
            )
            self._add_pid(proc, "100", exe, maps)
            self._seal_fs(fsroot, ("app",))
            row = self._run_script(self._script(root, proc, fsroot))
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_malformed_maps_address_offset_device_are_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        cases = (
            {"address": "NOT-AN-ADDRESS"},
            {"offset": "NOT-OFFSET"},
            {"dev": "NOT-DEV"},
        )
        for override in cases:
            with self.subTest(override=override):
                with tempfile.TemporaryDirectory(dir=ROOT) as td:
                    root = Path(td)
                    fsroot, exe, lib, _ = self._prepare_fs(root)
                    proc = self._prepare_proc(root)
                    maps = self._maps_line(str(lib), source_path=lib, **override)
                    self._add_pid(proc, "100", exe, maps)
                    self._seal_fs(fsroot, ("app",))
                    row = self._run_script(self._script(root, proc, fsroot))
                    self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_unicode_inode_digits_are_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, _ = self._prepare_fs(root)
            proc = self._prepare_proc(root)
            st = os.stat(lib)
            unicode_inode = str(st.st_ino).translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩"))
            maps = self._maps_line(str(lib), inode=unicode_inode, source_path=lib)
            self._add_pid(proc, "100", exe, maps)
            self._seal_fs(fsroot, ("app",))
            row = self._run_script(self._script(root, proc, fsroot))
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_non_ascii_decimal_starttime_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, _ = self._prepare_fs(root)
            proc = self._prepare_proc(root)
            self._add_pid(proc, "100", exe, self._maps_line(str(lib)), start="NOT-A-NUMBER")
            self._seal_fs(fsroot, ("app",))
            row = self._run_script(self._script(root, proc, fsroot))
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_missing_starttime_with_following_fields_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, _ = self._prepare_fs(root)
            proc = self._prepare_proc(root)
            pid = self._add_pid(proc, "100", exe, self._maps_line(str(lib)))
            fields = ["S"] + ["0"] * 49
            fields[19] = ""
            fields[20] = "777"
            (pid / "stat").write_text("100 (fixture) " + " ".join(fields) + "\n", encoding="ascii")
            self._seal_fs(fsroot, ("app",))
            row = self._run_script(self._script(root, proc, fsroot))
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_transient_process_creation_counter_change_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, _ = self._prepare_fs(root)
            proc = self._prepare_proc(root, forks=1000)
            pid = self._add_pid(proc, "100", exe, None)
            fifo = pid / "maps"
            os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app",))
            cp = self._popen_script(self._script(root, proc, fsroot))
            fd = self._open_fifo_writer(fifo)
            try:
                self._set_process_counter(proc, 1001)
                os.write(fd, self._maps_line(str(lib)).encode("utf-8"))
            finally:
                os.close(fd)
            row = self._finish_popen(cp)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "proc-counter:mid-snapshot-changed")

    def test_same_pid_mapping_population_drift_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, _ = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            _, _, lib3, _ = self._prepare_fs(root, "app3")
            proc = self._prepare_proc(root)
            pid1 = self._add_pid(proc, "100", exe1, self._maps_line(str(lib1)))
            pid2 = self._add_pid(proc, "200", exe2, None)
            fifo = pid2 / "maps"
            os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app1", "app2", "app3"))
            cp = self._popen_script(self._script(root, proc, fsroot))
            fd = self._open_fifo_writer(fifo)
            try:
                (pid1 / "maps").write_text(
                    self._maps_line(str(lib1)) +
                    self._maps_line(
                        str(lib3),
                        address="00500000-00501000",
                        source_path=lib3,
                    ),
                    encoding="utf-8",
                )
                os.write(fd, self._maps_line(str(lib2)).encode("utf-8"))
            finally:
                os.close(fd)
            row = self._finish_popen(cp)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "proc-maps:recheck-changed")

    def test_same_pid_exe_target_drift_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, _ = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            _, exe3, _, _ = self._prepare_fs(root, "app3")
            proc = self._prepare_proc(root)
            pid1 = self._add_pid(proc, "100", exe1, self._maps_line(str(lib1)))
            pid2 = self._add_pid(proc, "200", exe2, None)
            fifo = pid2 / "maps"
            os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app1", "app2", "app3"))
            cp = self._popen_script(self._script(root, proc, fsroot))
            fd = self._open_fifo_writer(fifo)
            try:
                (pid1 / "exe").unlink()
                (pid1 / "exe").symlink_to(exe3)
                os.write(fd, self._maps_line(str(lib2)).encode("utf-8"))
            finally:
                os.close(fd)
            row = self._finish_popen(cp)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "proc-exe:recheck-changed")

    def test_process_change_reason_inventory_is_complete_and_unique(self):
        for forbidden in (
            "observation:process-changed",
            "observation:file-changed",
            "observation:parent-changed",
        ):
            self.assertNotIn(forbidden, RUNNING_PROCESS_PATHS._PY)
        process_reasons = RUNNING_PROCESS_PATHS.PROCESS_CHANGE_REASONS
        file_parent_reasons = RUNNING_PROCESS_PATHS.FILE_PARENT_CHANGE_REASONS
        self.assertEqual(len(process_reasons), 21)
        self.assertEqual(len(set(process_reasons)), 21)
        self.assertEqual(len(file_parent_reasons), 9)
        self.assertEqual(len(set(file_parent_reasons)), 9)
        tree = ast.parse(RUNNING_PROCESS_PATHS._PY)
        observed = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "error":
                continue
            if len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                observed.append(node.args[0].value)
        for reason in process_reasons + file_parent_reasons:
            self.assertEqual(observed.count(reason), 1, reason)

    def test_generation_rejects_wrong_contract_fields(self):
        cases = (
            ("/proc", RUNNING_PROCESS_PATHS.CANONICAL_KEY, RUNNING_PROCESS_PATHS.CANONICAL_OP, RUNNING_PROCESS_PATHS.CANONICAL_EXPECTED),
            (RUNNING_PROCESS_PATHS.CANONICAL_LOCATOR, "mode", RUNNING_PROCESS_PATHS.CANONICAL_OP, RUNNING_PROCESS_PATHS.CANONICAL_EXPECTED),
            (RUNNING_PROCESS_PATHS.CANONICAL_LOCATOR, RUNNING_PROCESS_PATHS.CANONICAL_KEY, "bits-clear", RUNNING_PROCESS_PATHS.CANONICAL_EXPECTED),
            (RUNNING_PROCESS_PATHS.CANONICAL_LOCATOR, RUNNING_PROCESS_PATHS.CANONICAL_KEY, RUNNING_PROCESS_PATHS.CANONICAL_OP, "0022"),
        )
        for args in cases:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    RUNNING_PROCESS_PATHS.shell_function("TEST", *args)


class UnifiedCliArtifact(unittest.TestCase):
    GEN_V2 = ROOT / "product/generate-product-check-v2.py"
    ARTIFACT = ROOT / "securelinux-policy.sh"
    SIDECAR = ROOT / "securelinux-policy.sh.sha256"

    def run_cli(self, *args, env=None):
        return subprocess.run(
            [str(self.ARTIFACT), *args], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        )

    def run_sourced(self, body, env=None):
        return subprocess.run(
            [BASH, "-c", f"set -u\nsource {self.ARTIFACT!s}\n{body}"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        )

    @staticmethod
    def synthetic_prelude():
        return r'''
SLP_RESULTS=(
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.1-GROUP-MODE\tVALUE\t0644\tPASS'
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE\tVALUE\taccounts=2;homes=2;violations=1\tFAIL'
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE\tVALUE\troots_present=9;roots_absent=0;aliases=4;exec=1236;libraries=999;modules=6474;checked=8300;violations=0\tPASS'
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE\tERROR\ttest:synthetic-error\tERROR'
)
SLP_TOTAL=4
SLP_PASS=2
SLP_FAIL=1
SLP_NF=0
SLP_ERR=1
SLP_POLICY_STATUS=UNEVALUATED
SLP_POLICY_RC=1
'''

    def test_unified_collector_rejects_missing_or_malformed_error_reason(self):
        cid = "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE"
        fn = "slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE"
        for reason in ("-", "BAD", "domain:bad_reason", "stderr:random text"):
            with self.subTest(reason=reason):
                body = (
                    f"{fn}() {{ printf 'SLP-CHECK-V1\t{cid}\tERROR\t{reason}\tERROR\n'; }}\n"
                    "slp_collect_policy\n"
                    "printf 'RC=%s\n' \"$?\"\n"
                )
                cp = self.run_sourced(body)
                self.assertEqual(cp.returncode, 0)
                self.assertEqual(cp.stdout.strip(), "RC=1")
                self.assertIn("CHECK_INTERNAL_ERROR", cp.stderr)

    def test_unified_tracked_artifact_matches_fresh_generator_exactly(self):
        self.assertTrue(self.GEN_V2.is_file())
        self.assertTrue(self.ARTIFACT.is_file())
        self.assertTrue(self.SIDECAR.is_file())
        self.assertEqual(self.ARTIFACT.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.SIDECAR.stat().st_mode & 0o777, 0o644)
        self.assertTrue(self.ARTIFACT.read_bytes().startswith(b"#!/bin/bash -p\n"))
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)):
                with tempfile.TemporaryDirectory(prefix="slp-unified-cli-rebuild-") as td:
                    out = Path(td) / "securelinux-policy.sh"
                    cp = subprocess.run(
                        [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B",
                         str(self.GEN_V2), "--repo", str(ROOT), "--out", str(out)],
                        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, umask=mask,
                    )
                    self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                    self.assertIn("GENERATOR_ID=product-check-generator-v2\n", cp.stdout)
                    current_control_count = len(GEN_V2_CURRENT.load_manifest(ROOT)[0])
                    current_adapter_count = len(GEN_V2_CURRENT.load_registry(ROOT)[0])
                    self.assertIn(f"CONTROL_COUNT={current_control_count}\n", cp.stdout)
                    self.assertIn(f"ADAPTER_COUNT={current_adapter_count}\n", cp.stdout)
                    self.assertIn("TARGET_FAMILY_ID=linux-x86_64-supported-v1\n", cp.stdout)
                    self.assertIn("SUPPORTED_PROFILE_ENVIRONMENTS=7\n", cp.stdout)
                    self.assertIn("SUPPORTED_DESKTOP_ENVIRONMENTS=1\n", cp.stdout)
                    self.assertIn("SUPPORTED_ENVIRONMENTS=8\n", cp.stdout)
                    self.assertIn("APPLY_SCOPE=SRC-0001_ONLY\n", cp.stdout)
                    self.assertIn("APPLY_IMPLEMENTATION_COUNT=1\n", cp.stdout)
                    self.assertEqual(out.stat().st_mode & 0o777, 0o755)
                    self.assertEqual(out.with_name(out.name + ".sha256").stat().st_mode & 0o777, 0o644)
                    self.assertEqual(out.read_bytes(), self.ARTIFACT.read_bytes())
                    self.assertEqual(out.with_name(out.name + ".sha256").read_bytes(), self.SIDECAR.read_bytes())
        expected = f"{sha256_file(self.ARTIFACT)}  {self.ARTIFACT.name}\n"
        self.assertEqual(self.SIDECAR.read_text(encoding="utf-8"), expected)

    def test_privileged_shebang_blocks_exported_command_function(self):
        env = os.environ.copy()
        env["BASH_FUNC_command%%"] = "() {  printf 'POISONED-COMMAND\\n'\n}"
        shebang = self.ARTIFACT.read_bytes().splitlines(keepends=True)[0]
        self.assertEqual(shebang, b"#!/bin/bash -p\n")
        with tempfile.TemporaryDirectory(prefix="slp-command-shebang-", dir=ROOT) as td:
            td_path = Path(td)
            target = td_path / "target"
            target.write_text("x", encoding="utf-8")
            target.chmod(0o600)

            def run_probe(name, probe_shebang):
                probe = td_path / name
                probe.write_bytes(
                    probe_shebang
                    + b'command /usr/bin/stat -c %a -- "$1"\n'
                )
                probe.chmod(0o755)
                return subprocess.run(
                    [str(probe), str(target)], cwd=ROOT, env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )

            privileged_bash_control = run_probe("privileged-bash-control.sh", shebang)
            plain_bash_control = run_probe("plain-bash-control.sh", b"#!/bin/bash\n")

        self.assertEqual(privileged_bash_control.returncode, 0, privileged_bash_control.stderr)
        self.assertEqual(privileged_bash_control.stdout, "600\n")
        self.assertNotIn("POISONED-COMMAND", privileged_bash_control.stdout + privileged_bash_control.stderr)
        self.assertEqual(plain_bash_control.returncode, 0, plain_bash_control.stderr)
        self.assertIn("POISONED-COMMAND", plain_bash_control.stdout + plain_bash_control.stderr)

    def test_supported_environment_classifier_exact_7_plus_desktop_and_fail_closed(self):
        cases = (
            ("ubuntu", "22.04", "x86_64", "installed", "installed", "installed", "FULL", "ubuntu-22.04-x86_64-full"),
            ("ubuntu", "24.04", "x86_64", "installed", "absent", "absent", "MINIMIZED", "ubuntu-24.04-x86_64-minimized"),
            ("ubuntu", "24.04", "x86_64", "installed", "installed", "installed", "FULL", "ubuntu-24.04-x86_64-full"),
            ("ubuntu", "26.04", "x86_64", "installed", "absent", "absent", "MINIMIZED", "ubuntu-26.04-x86_64-minimized"),
            ("ubuntu", "26.04", "x86_64", "installed", "installed", "installed", "FULL", "ubuntu-26.04-x86_64-full"),
            ("debian", "12", "x86_64", "na", "na", "na", "SERVER", "debian-12-x86_64-server"),
            ("debian", "13", "x86_64", "na", "na", "na", "SERVER", "debian-13-x86_64-server"),
        )
        for os_id, version, arch, server_minimal, minimal, standard, profile, env_id in cases:
            with self.subTest(env_id=env_id):
                body = (
                    f"slp_classify_environment {os_id!r} {version!r} {arch!r} "
                    f"{server_minimal!r} {minimal!r} {standard!r}; "
                    'printf "%s|%s|%s\\n" "$SLP_SYSTEM_PROFILE" "$SLP_SYSTEM_PLATFORM" "$SLP_SYSTEM_ENVIRONMENT"'
                )
                cp = self.run_sourced(body)
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertEqual(cp.stdout.strip(), f"{profile}|{os_id}-{version}-{arch}|{env_id}")

        desktop = self.run_sourced(
            "slp_classify_environment ubuntu 24.04 x86_64 absent installed installed; "
            'printf "%s|%s|%s|%s\n" "$SLP_SYSTEM_PROFILE" "$SLP_SYSTEM_TYPE" "$SLP_SYSTEM_PLATFORM" "$SLP_SYSTEM_ENVIRONMENT"'
        )
        self.assertEqual(desktop.returncode, 0, desktop.stderr)
        self.assertEqual(desktop.stdout.strip(), "|DESKTOP|ubuntu-24.04-x86_64|ubuntu-24.04-x86_64-desktop")

        rejected_profile = (
            ("ubuntu", "22.04", "x86_64", "installed", "absent", "absent"),
            ("ubuntu", "24.04", "x86_64", "installed", "installed", "absent"),
            ("ubuntu", "24.04", "x86_64", "installed", "absent", "installed"),
        )
        for args in rejected_profile:
            with self.subTest(rejected_profile=args):
                cmd = (
                    "slp_classify_environment " + " ".join(repr(x) for x in args)
                    + '; _slp_rc=$?; printf "%s|%s|%s\\n" "$_slp_rc" "$SLP_CLASSIFY_REASON" "$SLP_SYSTEM_PROFILE"'
                )
                cp = self.run_sourced(cmd)
                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                self.assertEqual(cp.stdout.strip(), "3|PROFILE|UNKNOWN")

        rejected_type = (
            ("ubuntu", "22.04", "x86_64", "absent", "installed", "installed"),
            ("ubuntu", "26.04", "x86_64", "absent", "installed", "installed"),
            ("ubuntu", "24.04", "x86_64", "absent", "absent", "absent"),
        )
        for args in rejected_type:
            with self.subTest(rejected_type=args):
                cmd = (
                    "slp_classify_environment " + " ".join(repr(x) for x in args)
                    + '; _slp_rc=$?; printf "%s|%s|%s\n" "$_slp_rc" "$SLP_CLASSIFY_REASON" "$SLP_SYSTEM_TYPE"'
                )
                cp = self.run_sourced(cmd)
                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                self.assertEqual(cp.stdout.strip(), "3|TYPE|UNKNOWN")

        rejected_platform = (
            ("ubuntu", "24.04", "aarch64", "installed", "installed", "installed"),
            ("ubuntu", "25.04", "x86_64", "installed", "installed", "installed"),
            ("debian", "11", "x86_64", "na", "na", "na"),
        )
        for args in rejected_platform:
            with self.subTest(rejected_platform=args):
                cmd = (
                    "slp_classify_environment " + " ".join(repr(x) for x in args)
                    + '; _slp_rc=$?; printf "%s|%s\\n" "$_slp_rc" "$SLP_CLASSIFY_REASON"'
                )
                cp = self.run_sourced(cmd)
                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                self.assertEqual(cp.stdout.strip(), "3|PLATFORM")

    def test_raw_os_release_bytes_and_dpkg_status_are_fail_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "os-release"
            cases = (
                (b"ID=ubuntu\n", "0"),
                (b"ID=ub\x00untu\n", "1"),
                (b"ID=ubuntu\r\n", "1"),
                (b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu\t24.04"\n', "1"),
                (b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu\x08 24.04"\n', "1"),
                (b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu\x0c 24.04"\n', "1"),
                (b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu\x1b 24.04"\n', "1"),
                (b'ID=debian\nVERSION_ID=13\nPRETTY_NAME="Debian \xff"\n', "1"),
                (b'ID=debian\nVERSION_ID=13\nPRETTY_NAME="Debian \xc3"\n', "1"),
                (b'ID=debian\nVERSION_ID=13\nPRETTY_NAME="Debian \xc0\xaf"\n', "1"),
                ('ID=debian\nVERSION_ID=13\nPRETTY_NAME="Дебиан 13"\n'.encode('utf-8'), "0"),
            )
            for raw, expected_rc in cases:
                with self.subTest(raw=raw):
                    path.write_bytes(raw)
                    cp = self.run_sourced(
                        f"slp_preflight_validate_text_bytes {shlex.quote(str(path))}; "
                        'printf "%s\n" "$?"'
                    )
                    self.assertEqual(cp.returncode, 0, cp.stderr)
                    self.assertEqual(cp.stdout.strip(), expected_rc)

        cases = (
            ("install ok installed", "0|installed"),
            ("hold ok installed", "0|installed"),
            ("deinstall ok config-files", "0|absent"),
            ("unknown ok not-installed", "0|absent"),
            ("install ok unpacked", "1|"),
            ("install ok half-configured", "1|"),
            ("install ok half-installed", "1|"),
            ("install ok triggers-pending", "1|"),
            ("install reinstreq installed", "1|"),
            ("invalid ok not-installed", "1|"),
        )
        for status, expected in cases:
            with self.subTest(status=status):
                cp = self.run_sourced(
                    f"_slp_result=$(slp_classify_dpkg_status {shlex.quote(status)}); "
                    '_slp_rc=$?; printf "%s|%s\n" "$_slp_rc" "$_slp_result"'
                )
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertEqual(cp.stdout.strip(), expected)

    def test_os_release_parser_accepts_single_quotes_and_shell_style_escapes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "os-release"
            fixtures = (
                (
                    "ID='debian'\nVERSION_ID='13'\nPRETTY_NAME='Debian GNU/Linux 13 (trixie)'\n",
                    "debian|13|Debian GNU/Linux 13 (trixie)",
                ),
                (
                    'ID="debian"\nVERSION_ID="13"\nPRETTY_NAME="Debian \\"quoted\\" \\\\ path"\n',
                    'debian|13|Debian "quoted" \\ path',
                ),
                (
                    'ID=debian\nVERSION_ID=13\nPRETTY_NAME="Дебиан 13"\n',
                    'debian|13|Дебиан 13',
                ),
            )
            for content, expected in fixtures:
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    cp = self.run_sourced(
                        f"slp_preflight_validate_text_bytes {shlex.quote(str(path))}; _slp_vrc=$?; "
                        f"slp_parse_os_release_file {shlex.quote(str(path))}; _slp_prc=$?; "
                        'printf "%s|%s|%s|%s|%s\n" "$_slp_vrc" "$_slp_prc" "$SLP_OS_RELEASE_ID" "$SLP_OS_RELEASE_VERSION_ID" "$SLP_OS_RELEASE_PRETTY_NAME"'
                    )
                    self.assertEqual(cp.returncode, 0, cp.stderr)
                    self.assertEqual(cp.stdout.strip(), "0|0|" + expected)

    def test_unified_collector_accepts_definitive_not_found_fail(self):
        artifact = self.ARTIFACT.read_text(encoding="utf-8")
        match = re.search(
            r"local -a _slp_fns=\((.*?)\)\n  local -a _slp_ids=\((.*?)\)",
            artifact,
        )
        self.assertIsNotNone(match)
        fns = shlex.split(match.group(1))
        ids = shlex.split(match.group(2))
        self.assertEqual(len(fns), len(ids))
        targets = {
            "FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN",
            "FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS",
        }
        for target in sorted(targets):
            with self.subTest(target=target):
                body = []
                for fn, cid in zip(fns, ids):
                    if cid == target:
                        status, value, result = "NOT_FOUND", "-", "FAIL"
                    else:
                        status, value, result = "VALUE", "synthetic", "PASS"
                    body.append(
                        f"{fn}() {{ printf '%s\\t%s\\t%s\\t%s\\t%s\\n' "
                        f"'SLP-CHECK-V1' {shlex.quote(cid)} {shlex.quote(status)} "
                        f"{shlex.quote(value)} {shlex.quote(result)}; }}"
                    )
                body.append(
                    "slp_collect_policy; _slp_rc=$?; "
                    "printf 'RC=%s|POLICY=%s|FAIL=%s|NOT_FOUND=%s|ERROR=%s\\n' "
                    '"$_slp_rc" "$SLP_POLICY_STATUS" "$SLP_FAIL" "$SLP_NF" "$SLP_ERR"'
                )
                cp = self.run_sourced("\n".join(body))
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertEqual(cp.stdout.strip(), "RC=0|POLICY=NONCOMPLIANT|FAIL=1|NOT_FOUND=0|ERROR=0")
                self.assertNotIn("CHECK_INTERNAL_ERROR", cp.stderr)

    def test_dpkg_package_observation_ignores_caller_database_redirectors(self):
        baseline = self.run_sourced(
            '_slp_state=$(slp_dpkg_package_state ubuntu-server-minimal); _slp_rc=$?; printf "%s|%s\n" "$_slp_rc" "$_slp_state"'
        )
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertRegex(baseline.stdout.strip(), r"^0\|(installed|absent)$")
        baseline_state = baseline.stdout.strip().split("|", 1)[1]
        fake_status = (
            "Package: ubuntu-server-minimal\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n\n"
            if baseline_state == "absent" else ""
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            td_path = Path(td)
            admindir = td_path / "admindir"
            admindir.mkdir()
            (admindir / "status").write_text(fake_status, encoding="utf-8")
            fake_root = td_path / "root"
            root_admindir = fake_root / "var/lib/dpkg"
            root_admindir.mkdir(parents=True)
            (root_admindir / "status").write_text(fake_status, encoding="utf-8")
            for var, value in (("DPKG_ADMINDIR", admindir), ("DPKG_ROOT", fake_root)):
                with self.subTest(var=var):
                    env = os.environ.copy()
                    env.pop("DPKG_ADMINDIR", None)
                    env.pop("DPKG_ROOT", None)
                    env[var] = str(value)
                    cp = self.run_sourced(
                        '_slp_state=$(slp_dpkg_package_state ubuntu-server-minimal); _slp_rc=$?; printf "%s|%s\n" "$_slp_rc" "$_slp_state"',
                        env=env,
                    )
                    self.assertEqual(cp.returncode, 0, cp.stderr)
                    self.assertEqual(cp.stdout, baseline.stdout)

    def test_raw_platform_record_has_fixed_arity_for_valid_identity(self):
        body = (
            "SLP_SYSTEM_PRETTY_NAME='Ubuntu 24.04.4 LTS'; "
            "SLP_SYSTEM_ID=ubuntu; SLP_SYSTEM_VERSION_ID=24.04; SLP_SYSTEM_ARCH=x86_64; "
            "SLP_SYSTEM_PROFILE=FULL; SLP_SYSTEM_TYPE=''; "
            "SLP_SYSTEM_PLATFORM=ubuntu-24.04-x86_64; SLP_SYSTEM_ENVIRONMENT=ubuntu-24.04-x86_64-full; "
            "SLP_RESULTS=(); SLP_TOTAL=0; SLP_PASS=0; SLP_FAIL=0; SLP_NF=0; SLP_ERR=0; "
            "SLP_POLICY_STATUS=COMPLIANT; SLP_POLICY_RC=0; "
            "slp_render_raw 0 | /usr/bin/head -n 1"
        )
        cp = self.run_sourced(body)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(len(cp.stdout.rstrip("\n").split("\t")), 10, cp.stdout)

    def test_unified_help_version_build_info_and_apply_dispatch(self):
        syntax = subprocess.run([BASH, "-n", str(self.ARTIFACT)], capture_output=True, text=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        noargs = self.run_cli()
        self.assertEqual(noargs.returncode, 0)
        self.assertIn("SecureLinux-Policy v3 — единый product CLI", noargs.stdout)
        self.assertIn("--check [--failed] [--format pretty|raw|json]", noargs.stdout)
        version = self.run_cli("--version")
        self.assertEqual(version.returncode, 0)
        self.assertIn("PRODUCT_CLI=product-cli-v1\n", version.stdout)
        build = self.run_cli("--build-info")
        self.assertEqual(build.returncode, 0)
        self.assertIn("GENERATOR_ID=product-check-generator-v2\n", build.stdout)
        self.assertIn("TARGET_FAMILY_ID=linux-x86_64-supported-v1\n", build.stdout)
        self.assertIn("SUPPORTED_PROFILE_ENVIRONMENTS=7\n", build.stdout)
        self.assertIn("SUPPORTED_DESKTOP_ENVIRONMENTS=1\n", build.stdout)
        self.assertIn("SUPPORTED_ENVIRONMENTS=8\n", build.stdout)
        self.assertIn("APPLY_SCOPE=SRC-0001_ONLY\n", build.stdout)
        self.assertIn("APPLY_IMPLEMENTATION_COUNT=1\n", build.stdout)
        self.assertIn("MUTATING_MODES=APPLY_SRC0001_ONLY\n", build.stdout)
        for args in (
            ("--apply",),
            ("--apply", "--snapshot-attestation"),
            ("--apply", "--dry-run", "extra"),
            ("--apply", "--snapshot-attestation", "/tmp/a", "extra"),
            ("--apply", "--dry-run", "--snapshot-attestation", "/tmp/a"),
        ):
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")
        apply_fn = "slp_apply_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE"
        dry_run = self.run_sourced(
            "slp_target_preflight() { return 0; }\n"
            + f"{apply_fn}() {{ printf '%s|%s\\n' \"$1\" \"${{2:-}}\"; }}\n"
            + "slp_main --apply --dry-run"
        )
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertEqual(dry_run.stdout, "DRY_RUN|\n")
        apply = self.run_sourced(
            "slp_target_preflight() { return 0; }\n"
            + f"{apply_fn}() {{ printf '%s|%s\\n' \"$1\" \"${{2:-}}\"; }}\n"
            + "slp_main --apply --snapshot-attestation /tmp/a"
        )
        self.assertEqual(apply.returncode, 0, apply.stderr)
        self.assertEqual(apply.stdout, "APPLY|/tmp/a\n")
        self.assertNotIn("--restore", noargs.stdout)
        restore = self.run_cli("--restore")
        self.assertEqual(restore.returncode, 2)
        self.assertEqual(restore.stdout, "")
        self.assertEqual(restore.stderr, "")

    def test_help_and_provenance_ignore_caller_path_cat(self):
        expected_help = self.run_cli("--help")
        expected_provenance = self.run_cli("--provenance")
        self.assertEqual(expected_help.returncode, 0, expected_help.stderr)
        self.assertEqual(expected_provenance.returncode, 0, expected_provenance.stderr)
        with tempfile.TemporaryDirectory(prefix="slp-path-cat-", dir=ROOT) as td:
            td_path = Path(td)
            marker = td_path / "executed"
            fake_cat = td_path / "cat"
            fake_cat.write_text(
                "#!/bin/sh\nprintf '%s\\n' PATH_POISONED_CAT\n"
                + ": > " + shlex.quote(str(marker)) + "\n",
                encoding="utf-8",
            )
            fake_cat.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = str(td_path) + os.pathsep + env.get("PATH", "")
            actual_help = self.run_cli("--help", env=env)
            actual_provenance = self.run_cli("--provenance", env=env)
            self.assertFalse(marker.exists())
        self.assertEqual((actual_help.returncode, actual_help.stdout, actual_help.stderr),
                         (expected_help.returncode, expected_help.stdout, expected_help.stderr))
        self.assertEqual((actual_provenance.returncode, actual_provenance.stdout, actual_provenance.stderr),
                         (expected_provenance.returncode, expected_provenance.stdout, expected_provenance.stderr))

    def test_json_escape_covers_all_bash_representable_c0_controls(self):
        c0 = "".join(chr(i) for i in range(1, 32))
        bash_c0 = "".join(f"\\x{i:02x}" for i in range(1, 32))
        pre = self.synthetic_prelude() + (
            f"\n_slp_c0=$'{bash_c0}'\n"
            "SLP_SYSTEM_PRETTY_NAME=$_slp_c0\n"
            "SLP_SYSTEM_ID='ubuntu'\nSLP_SYSTEM_VERSION_ID='24.04'\n"
            "SLP_SYSTEM_ARCH='x86_64'\nSLP_SYSTEM_PROFILE='MINIMIZED'\n"
            "SLP_SYSTEM_PLATFORM='ubuntu-24.04-x86_64'\n"
            "SLP_SYSTEM_ENVIRONMENT='ubuntu-24.04-x86_64-minimized'\n"
        )
        cp = self.run_sourced(pre + "\nslp_render_json 0\n")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        payload = cp.stdout.encode("utf-8")
        self.assertFalse(any(byte < 0x20 for byte in payload.rstrip(b"\n")), payload)
        self.assertEqual(json.loads(cp.stdout)["platform"]["system"], c0)

    def test_unified_pretty_raw_json_and_failed_renderers(self):
        pre = self.synthetic_prelude() + "\nSLP_SYSTEM_PRETTY_NAME='Ubuntu 24.04.4 LTS'\nSLP_SYSTEM_ID='ubuntu'\nSLP_SYSTEM_VERSION_ID='24.04'\nSLP_SYSTEM_ARCH='x86_64'\nSLP_SYSTEM_PROFILE='MINIMIZED'\nSLP_SYSTEM_PLATFORM='ubuntu-24.04-x86_64'\nSLP_SYSTEM_ENVIRONMENT='ubuntu-24.04-x86_64-minimized'\n"
        pretty = self.run_sourced(pre + "\nslp_render_pretty 0 CHECK\n")
        self.assertEqual(pretty.returncode, 0, pretty.stderr)
        lines = pretty.stdout.splitlines()
        self.assertEqual(lines[1], "SYSTEM=Ubuntu 24.04.4 LTS   ARCH=x86_64")
        self.assertEqual(lines[2], "PROFILE=MINIMIZED   PLATFORM=ubuntu-24.04-x86_64   SUPPORT=SUPPORTED")
        self.assertEqual(lines[4].index("CONTROL"), 9)
        self.assertEqual(lines[4].index("VALUE / DETAILS"), 72)
        continuation = [x for x in lines if x.startswith(" " * 72) and "libraries=999" in x]
        self.assertEqual(len(continuation), 1)
        longest = "FSTEC-LINUX-2022-2.3.2-RUNNING-PROCESS-PATHS-WRITE-PROTECTION"
        self.assertEqual(len(longest), 61)
        self.assertLessEqual(9 + len(longest), lines[4].index("VALUE / DETAILS"))
        failed = self.run_sourced(pre + "\nslp_render_pretty 1 CHECK\n")
        self.assertEqual(failed.returncode, 0, failed.stderr)
        self.assertIn("HOME-DIRECTORIES-MODE", failed.stdout)
        self.assertIn("HOME-SENSITIVE-FILES-MODE", failed.stdout)
        self.assertNotIn("GROUP-MODE", failed.stdout)
        raw = self.run_sourced(pre + "\nslp_render_raw 0\n")
        self.assertEqual(raw.returncode, 0, raw.stderr)
        raw_lines = raw.stdout.splitlines()
        self.assertEqual(len(raw_lines), 6)
        self.assertTrue(raw_lines[0].startswith("SLP-PLATFORM-V1\t"))
        self.assertIn("PROFILE=MINIMIZED", raw_lines[0])
        self.assertTrue(all(x.startswith("SLP-CHECK-V1\t") for x in raw_lines[1:-1]))
        obj = json.loads(self.run_sourced(pre + "\nslp_render_json 0\n").stdout)
        self.assertEqual(obj["schema"], "SLP-REPORT-V1")
        self.assertEqual(obj["platform"]["profile"], "MINIMIZED")
        self.assertEqual(obj["platform"]["platform_id"], "ubuntu-24.04-x86_64")
        self.assertEqual(obj["platform"]["support"], "SUPPORTED")
        self.assertEqual(obj["platform"]["type"], "")
        self.assertEqual(obj["summary"], {"total":4,"pass":2,"fail":1,"not_found":0,"error":1})
        desktop_pre = self.synthetic_prelude() + "\nSLP_SYSTEM_PRETTY_NAME='Ubuntu 24.04.4 LTS'\nSLP_SYSTEM_ID='ubuntu'\nSLP_SYSTEM_VERSION_ID='24.04'\nSLP_SYSTEM_ARCH='x86_64'\nSLP_SYSTEM_PROFILE=''\nSLP_SYSTEM_TYPE='DESKTOP'\nSLP_SYSTEM_PLATFORM='ubuntu-24.04-x86_64'\nSLP_SYSTEM_ENVIRONMENT='ubuntu-24.04-x86_64-desktop'\n"
        desktop_pretty = self.run_sourced(desktop_pre + "\nslp_render_pretty 0 CHECK\n")
        self.assertEqual(desktop_pretty.returncode, 0, desktop_pretty.stderr)
        self.assertEqual(desktop_pretty.stdout.splitlines()[2], "TYPE=DESKTOP   PLATFORM=ubuntu-24.04-x86_64   SUPPORT=SUPPORTED")
        desktop_raw = self.run_sourced(desktop_pre + "\nslp_render_raw 0\n")
        self.assertIn("\tPROFILE=\tTYPE=DESKTOP\t", desktop_raw.stdout.splitlines()[0])
        desktop_obj = json.loads(self.run_sourced(desktop_pre + "\nslp_render_json 0\n").stdout)
        self.assertEqual(desktop_obj["platform"]["profile"], "")
        self.assertEqual(desktop_obj["platform"]["type"], "DESKTOP")
        fobj = json.loads(self.run_sourced(pre + "\nslp_render_json 1\n").stdout)
        self.assertEqual([x["result"] for x in fobj["results"]], ["FAIL", "ERROR"])

    def test_unified_provenance_invalid_cli_and_no_mutation_scaffold(self):
        prov = self.run_cli("--provenance")
        self.assertEqual(prov.returncode, 0)
        rows = [json.loads(x) for x in prov.stdout.splitlines()]
        current_control_count = len(GEN_V2_CURRENT.load_manifest(ROOT)[0])
        self.assertEqual(len(rows), current_control_count)
        apply_impl, _ = GEN_V2_CURRENT.load_apply_implementation(ROOT)
        apply_id = GEN_V2_CURRENT.APPLY_CONTROL_ID
        apply_rows = [row for row in rows if "apply" in row]
        self.assertEqual(len(apply_rows), 1)
        row = apply_rows[0]
        self.assertEqual(row["control_id"], apply_id)
        self.assertEqual(row["apply"], {
            "adapter_id": apply_impl["row"]["adapter_id"],
            "adapter_contract_version": "product-local-account-password-state-apply-adapter-v1",
            "implementation_sha256": sha256_file(ROOT / apply_impl["row"]["implementation_path"]),
            "composition_contract_id": apply_impl["composition"]["composition_contract_id"],
            "control_id": apply_id,
            "source_locator": row["source_locator"],
            "quote_sha256": row["quote_sha256"],
        })
        apply_one = self.run_cli("--provenance", apply_id)
        self.assertEqual(apply_one.returncode, 0, apply_one.stderr)
        self.assertEqual(json.loads(apply_one.stdout), row)
        one = self.run_cli("--provenance", rows[0]["control_id"])
        self.assertEqual(json.loads(one.stdout)["control_id"], rows[0]["control_id"])
        for args in (("--bogus",), ("--help", "extra"), ("--check", "--format"),
                     ("--check", "--format", "xml"), ("--check", "--format=xml"),
                     ("--check", "--failed", "--failed")):
            self.assertEqual(self.run_cli(*args).returncode, 2, args)
        text = self.ARTIFACT.read_text(encoding="utf-8")
        for forbidden in ("sysctl -w", "sysctl --write", "tee /proc/sys", "sed -i",
                          "chmod ", "chown ", "chgrp ", "setfacl ", "truncate ", "column "):
            self.assertNotIn(forbidden, text, forbidden)


@unittest.skipIf(BASH is None, "bash not available")
class StartupFilesWriteProtectionFixtures(unittest.TestCase):
    def run_layout(self, rc_roots, unit_paths):
        source = STARTUP_FILES._shell_function_for_layout(
            "TEST-STARTUP-FILES", [str(x) for x in rc_roots], [str(x) for x in unit_paths]
        )
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_STARTUP_FILES"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def assert_error(self, cp, reason=None):
        self.assertEqual(cp.returncode, 0, cp.stderr)
        assert_stable_error_record(self, cp.stdout, "TEST-STARTUP-FILES", reason)

    def test_direct_population_mask_and_recursive_dependency_reference(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); rc = base / "rc0.d"; units = base / "units"; rc.mkdir(); units.mkdir()
            target = base / "init-script"; target.write_text("x\n"); target.chmod(0o755); (rc / "S01x").symlink_to(target)
            svc = units / "a.service"; svc.write_text("[Service]\n"); svc.chmod(0o644)
            (units / "masked.service").symlink_to("/dev/null")
            wants = units / "multi-user.target.wants"; wants.mkdir(); bad = wants / "ignored.service"; bad.write_text("x\n"); bad.chmod(0o666)
            cp = self.run_layout([rc], [units])
            self.assertEqual(cp.stderr, "")
            self.assertIn("rc_entries=1", cp.stdout); self.assertIn("service_entries=2", cp.stdout)
            self.assertIn("service_masked=1", cp.stdout); self.assertIn("violations=0\tPASS", cp.stdout)

    def test_rc_other_write_is_fail(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); rc=base/"rc0.d"; units=base/"units"; rc.mkdir(); units.mkdir()
            f=rc/"S01x"; f.write_text("x\n"); f.chmod(0o646)
            (units/"a.service").write_text("x\n"); (units/"a.service").chmod(0o644)
            cp=self.run_layout([rc],[units]); self.assertIn("violations=1\tFAIL",cp.stdout)

    def test_service_other_write_is_fail(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); units=base/"units"; units.mkdir(); f=units/"a.service"; f.write_text("x\n"); f.chmod(0o646)
            cp=self.run_layout([], [units]); self.assertIn("violations=1\tFAIL",cp.stdout)

    def test_service_symlink_final_regular_target_is_checked(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); units=base/"units"; units.mkdir(); target=base/"real"; target.write_text("x\n"); target.chmod(0o646)
            (units/"a.service").symlink_to(target)
            cp=self.run_layout([], [units]); self.assertIn("violations=1\tFAIL",cp.stdout)

    def test_masked_only_and_empty_populations_are_determinate(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); units=base/"units"; units.mkdir(); (units/"masked.service").symlink_to("/dev/null")
            cp=self.run_layout([], [units]); self.assertIn("service_masked=1",cp.stdout); self.assertIn("checked=0;violations=0\tPASS",cp.stdout)
            empty=base/"empty"; empty.mkdir(); cp=self.run_layout([], [empty]); self.assertIn("service_entries=0",cp.stdout); self.assertIn("checked=0;violations=0\tPASS",cp.stdout)

    def test_dangling_and_special_selected_entries_are_error(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); units=base/"units"; units.mkdir(); (units/"bad.service").symlink_to(base/"missing")
            self.assert_error(self.run_layout([], [units]), "target:stat-failed")
        if hasattr(os, "mkfifo"):
            with tempfile.TemporaryDirectory() as td:
                units=Path(td)/"units"; units.mkdir(); os.mkfifo(units/"pipe.service")
                self.assert_error(self.run_layout([], [units]), "target:invalid-type")

    def test_dangling_rc_entry_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); rc=base/"rc0.d"; units=base/"units"; rc.mkdir(); units.mkdir(); (rc/"S01bad").symlink_to(base/"missing")
            (units/"a.service").write_text("x\n")
            self.assert_error(self.run_layout([rc], [units]), "target:stat-failed")

    def test_merged_unit_root_alias_is_deduplicated(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); real=base/"usr-lib-systemd"; real.mkdir(); (real/"a.service").write_text("x\n")
            alias=base/"lib-systemd"; alias.symlink_to(real, target_is_directory=True)
            cp=self.run_layout([], [alias, real]); self.assertIn("service_root_aliases=1",cp.stdout); self.assertIn("service_entries=1",cp.stdout); self.assertIn("violations=0\tPASS",cp.stdout)

    def test_direct_service_directory_is_error_but_nonservice_directory_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            units=Path(td)/"units"; units.mkdir(); (units/"x.wants").mkdir(); (units/"bad.service").mkdir()
            self.assert_error(self.run_layout([], [units]), "target:invalid-type")

    def test_generation_rejects_wrong_contract_fields(self):
        good="/etc/rc[0-6].d|systemd-unit-paths"
        for args in (("TEST","/etc/rc#.d","other-write","bits-clear","0002"),("TEST",good,"mode","bits-clear","0002"),("TEST",good,"other-write","eq","0002"),("TEST",good,"other-write","bits-clear","0022")):
            with self.subTest(args=args):
                with self.assertRaises(ValueError): STARTUP_FILES.shell_function(*args)


class CronCommandPathsWriteProtectionFixtures(unittest.TestCase):
    @staticmethod
    def _base(root):
        for rel in ("etc/cron.d", "var/spool/cron/crontabs", "usr/bin", "bin"):
            (root / rel).mkdir(parents=True, exist_ok=True)
        runner_uid = os.getuid()
        runner_gid = os.getgid()
        (root / "etc/passwd").write_text(
            f"root:x:0:0:root:/root:/bin/sh\nuser:x:{runner_uid}:{runner_gid}:user:/home/user:/bin/sh\nnonroot:x:424242:424242:nonroot:/home/nonroot:/bin/sh\n",
            encoding="utf-8",
        )
        for rel in ("usr/bin/run-parts", "usr/bin/tool"):
            path = root / rel
            path.write_text("fixture\n", encoding="utf-8")
            path.chmod(0o555)

    @staticmethod
    def _script(root):
        src = CRON_COMMAND_PATHS._shell_function_for_root("TEST-CRON-PATHS", str(root), os.getuid())
        script = root / "run.sh"
        script.write_text(
            "#!/bin/bash -p\n" + src + "\nslp_check_TEST_CRON_PATHS\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script

    def _run(self, root):
        cp = subprocess.run(
            [str(self._script(root))], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        row = cp.stdout.strip().split("\t")
        self.assertEqual(len(row), 5, cp.stdout + cp.stderr)
        return row

    @staticmethod
    def _user_crontab(root, text, mode=0o600):
        path = root / "var/spool/cron/crontabs/user"
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return path

    def test_adapter_selftest(self):
        cp = subprocess.run(
            [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B", str(CRON_COMMAND_PATHS_ADAPTER_PATH)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("ADAPTER_SELFTEST=PASS", cp.stdout)

    def test_empty_population_passes(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
            self.assertIn("jobs=0", row[3])

    def test_default_system_run_parts_population_passes(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            periodic = root / "etc/cron.hourly"; periodic.mkdir()
            job = periodic / "job"; job.write_text("x\n", encoding="utf-8"); job.chmod(0o555)
            (root / "etc/crontab").write_text(
                "PATH=/usr/bin:/bin\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
                encoding="utf-8",
            )
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
            self.assertIn("targets=2", row[3])
            self.assertIn("periodic_dirs=1", row[3])

    def test_periodic_target_go_w_is_fail(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            periodic = root / "etc/cron.hourly"; periodic.mkdir()
            job = periodic / "job"; job.write_text("x\n", encoding="utf-8"); job.chmod(0o575)
            (root / "etc/crontab").write_text(
                "PATH=/usr/bin:/bin\n17 * * * * root run-parts --report /etc/cron.hourly\n",
                encoding="utf-8",
            )
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
            self.assertIn("violations=1", row[3])

    def test_direct_absolute_command_go_w_is_fail(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /opt/job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_user_absolute_command_passes(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            self._user_crontab(root, "0 1 * * * /opt/job\n")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))

    def test_non_root_bare_command_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            (root / "etc/crontab").write_text(
                "PATH=/usr/bin:/bin\n0 1 * * * nonroot tool\n", encoding="utf-8"
            )
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unresolved-name")

    def test_root_bare_command_without_explicit_path_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            (root / "etc/crontab").write_text("0 1 * * * root tool\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unresolved-name")

    def test_dynamic_shell_expansion_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            (root / "etc/crontab").write_text("PATH=/usr/bin:/bin\n0 1 * * * root $CMD\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:invalid-bytes")

    def test_redirection_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            (root / "etc/crontab").write_text("PATH=/usr/bin:/bin\n0 1 * * * root tool >/tmp/out\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-redirection")

    def test_percent_stdin_tail_does_not_add_command(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            (root / "etc/crontab").write_text("0 1 * * * root /opt/job%/missing/not-a-command\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
            self.assertIn("targets=1", row[3])

    def test_valid_cron_d_file_is_included_and_dot_name_is_ignored(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            good = root / "etc/cron.d/local_job"; good.write_text("0 1 * * * root /opt/job\n"); good.chmod(0o644)
            ignored = root / "etc/cron.d/local.job"; ignored.write_text("malformed should be ignored\n"); ignored.chmod(0o644)
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
            self.assertIn("configs=1", row[3])

    def test_unknown_system_user_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            (root / "etc/crontab").write_text("0 1 * * * missing /opt/job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "cron:unknown-user")

    def test_interpreter_invocation_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            shell = root / "bin/sh"; shell.write_text("x\n"); shell.chmod(0o555)
            script = root / "opt/job.py"; script.parent.mkdir(); script.write_text("x\n"); script.chmod(0o444)
            (root / "etc/crontab").write_text("0 1 * * * root /bin/sh /opt/job.py\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_absolute_wrapper_path_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            wrapper = root / "usr/bin/env"; wrapper.write_text("x\n"); wrapper.chmod(0o555)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/env /opt/job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_additional_launcher_wrappers_are_error(self):
        if BASH is None: self.skipTest("bash not found")
        for launcher_name in (
            "time", "setpriv", "unshare", "nsenter", "prlimit", "setarch", "linux32", "linux64",
            "chrt", "watch", "strace", "ltrace", "gdb", "valgrind", "perf", "script",
            "daemon", "daemonize", "parallel", "numactl", "capsh", "firejail", "bwrap",
            "fakeroot", "torsocks", "proxychains", "proxychains4", "eatmydata", "sg", "newgrp",
            "docker", "podman", "systemd-nspawn", "machinectl",
        ):
            with self.subTest(launcher=launcher_name):
                with tempfile.TemporaryDirectory(dir=ROOT) as td:
                    root = Path(td); self._base(root)
                    launcher = root / ("usr/bin/" + launcher_name); launcher.write_text("x\n"); launcher.chmod(0o555)
                    target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
                    (root / "etc/crontab").write_text(f"0 1 * * * root /usr/bin/{launcher_name} /opt/job\n", encoding="utf-8")
                    row = self._run(root)
                    self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
                    self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_symlink_alias_interpreter_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            shell = root / "bin/sh"; shell.write_text("x\n"); shell.chmod(0o555)
            alias = root / "usr/bin/job-shell"; alias.symlink_to("../../bin/sh")
            target = root / "opt/hidden-job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/job-shell -c /opt/hidden-job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_symlink_alias_run_parts_expands_population(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            alias = root / "usr/bin/periodic-runner"; alias.symlink_to("run-parts")
            periodic = root / "etc/cron.hourly"; periodic.mkdir()
            job = periodic / "job"; job.write_text("x\n"); job.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/periodic-runner /etc/cron.hourly\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
            self.assertIn("periodic_dirs=1", row[3])
            self.assertIn("violations=1", row[3])

    def test_symlink_alias_launcher_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            launcher = root / "usr/bin/time"; launcher.write_text("x\n"); launcher.chmod(0o555)
            alias = root / "usr/bin/job-launcher"; alias.symlink_to("time")
            target = root / "opt/hidden-job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/job-launcher /opt/hidden-job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_hardlink_alias_interpreter_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            shell = root / "bin/sh"; shell.write_text("x\n"); shell.chmod(0o555)
            alias = root / "usr/bin/job-shell"; os.link(shell, alias)
            target = root / "opt/hidden-job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/job-shell -c /opt/hidden-job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "target:hardlink")

    def test_hardlink_alias_run_parts_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            alias = root / "usr/bin/periodic-runner"; os.link(root / "usr/bin/run-parts", alias)
            periodic = root / "etc/cron.hourly"; periodic.mkdir()
            job = periodic / "job"; job.write_text("x\n"); job.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/periodic-runner /etc/cron.hourly\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "target:hardlink")

    def test_versioned_interpreter_path_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            interpreter = root / "usr/bin/python3.12"; interpreter.write_text("x\n"); interpreter.chmod(0o555)
            script = root / "opt/job.py"; script.parent.mkdir(); script.write_text("x\n"); script.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/python3.12 /opt/job.py\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_shell_override_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            (root / "etc/crontab").write_text("SHELL=/bin/bash\n0 1 * * * root /opt/job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "cron:unsupported-shell")

    def test_missing_final_newline_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            (root / "etc/crontab").write_text("0 1 * * * root /opt/job", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "cron:invalid-line-ending")

    def test_generation_rejects_wrong_contract_fields(self):
        bad = (
            ("CTRL", "/etc/crontab", CRON_COMMAND_PATHS.CANONICAL_KEY, CRON_COMMAND_PATHS.CANONICAL_OP, CRON_COMMAND_PATHS.CANONICAL_EXPECTED),
            ("CTRL", CRON_COMMAND_PATHS.CANONICAL_LOCATOR, "mode", CRON_COMMAND_PATHS.CANONICAL_OP, CRON_COMMAND_PATHS.CANONICAL_EXPECTED),
            ("CTRL", CRON_COMMAND_PATHS.CANONICAL_LOCATOR, CRON_COMMAND_PATHS.CANONICAL_KEY, "bits-clear", CRON_COMMAND_PATHS.CANONICAL_EXPECTED),
            ("CTRL", CRON_COMMAND_PATHS.CANONICAL_LOCATOR, CRON_COMMAND_PATHS.CANONICAL_KEY, CRON_COMMAND_PATHS.CANONICAL_OP, "0022"),
        )
        for args in bad:
            with self.assertRaises(ValueError):
                CRON_COMMAND_PATHS.shell_function(*args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
