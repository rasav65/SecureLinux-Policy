#!/usr/bin/env python3
"""product-v1 tests for the tracked product CHECK generator."""
import ast
import contextlib
import errno
import io
import hashlib
import importlib.util
import json
import os
import shutil
import shlex
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = ROOT / "product" / "generate-product-check-v1.py"
FILESET_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-optional-file-root-files-mode-check-v1.py"
SHADOW_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-local-account-password-state-check-v1.py"
USER_CRON_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-user-cron-files-mode-check-v1.py"
STANDARD_PATHS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-standard-system-paths-mode-check-v1.py"
SUID_SGID_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-suid-sgid-applications-check-v1.py"
HOME_SENSITIVE_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-home-sensitive-files-mode-check-v1.py"
HOME_DIRECTORIES_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-home-directories-mode-check-v1.py"
SSHD_ROOT_LOGIN_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-sshd-root-login-check-v1.py"
PAM_WHEEL_ACCESS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-pam-wheel-access-check-v1.py"
SUDOERS_REVIEWED_POLICY_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-sudoers-reviewed-policy-check-v1.py"
RUNNING_PROCESS_PATHS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-running-process-paths-write-protection-check-v1.py"
BASH = shutil.which("bash")


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

def load_running_process_paths_adapter():
    spec = importlib.util.spec_from_file_location("slp_running_process_paths_adapter", RUNNING_PROCESS_PATHS_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

RUNNING_PROCESS_PATHS = load_running_process_paths_adapter()


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
        self.assertTrue({"sysctl", "file-mode-owner", "kernel-cmdline", "optional-file-root-files-mode", "local-account-password-state", "user-cron-files-mode", "standard-system-paths-mode", "running-process-paths-write-protection", "suid-sgid-applications", "home-sensitive-files-mode", "home-directories-mode", "sshd-root-login", "pam-wheel-access", "sudoers-reviewed-policy"} <= set(adapters))
        self.assertEqual({c["parameter_kind"] for c in controls}, {"sysctl", "file-mode-owner", "kernel-cmdline", "optional-file-root-files-mode", "local-account-password-state", "user-cron-files-mode", "standard-system-paths-mode", "running-process-paths-write-protection", "suid-sgid-applications", "home-sensitive-files-mode", "home-directories-mode", "sshd-root-login", "pam-wheel-access", "sudoers-reviewed-policy"})
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
            ("user-cron-files-mode", "/var/spool/cron|/var/spool/cron/crontabs", "mode", "bits-clear", "0022"),
        )
        src0012 = [c for c in controls if c["index_id"] == "SRC-0012"]
        self.assertEqual(len(src0012), 1)
        self.assertEqual(
            (src0012[0]["parameter_kind"], src0012[0]["parameter_locator"], src0012[0]["parameter_key"], src0012[0]["expected_op"], src0012[0]["expected_value"]),
            ("standard-system-paths-mode", "/bin|/sbin|/usr/bin|/usr/sbin|/lib|/lib64|/usr/lib|/usr/lib64|/lib/modules/<uname-r>", "mode", "bits-clear", "0022"),
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
            ("home-sensitive-files-mode", "/etc/passwd|/etc/login.defs|/etc/securelinux-policy/home-sensitive-files-v1", "mode", "bits-clear", "0077"),
        )
        src0015 = [c for c in controls if c["index_id"] == "SRC-0015"]
        self.assertEqual(len(src0015), 1)
        self.assertEqual(
            (src0015[0]["parameter_kind"], src0015[0]["parameter_locator"], src0015[0]["parameter_key"], src0015[0]["expected_op"], src0015[0]["expected_value"]),
            ("home-directories-mode", "/etc/passwd|/etc/login.defs", "mode", "eq", "0700"),
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
        self.assertEqual(len(src0034), 1)
        self.assertEqual(
            (
                src0034[0]["parameter_locator"],
                src0034[0]["parameter_key"],
                src0034[0]["expected_op"],
                src0034[0]["expected_value"],
            ),
            ("sysctl", "kernel.randomize_va_space", "eq", 2),
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

    def test_render_is_deterministic(self):
        _, manifest_sha, adapters, registry_sha, controls = self.load_current()
        generator_sha = sha256_file(GEN_PATH)
        one = GEN.render_script(controls, adapters, manifest_sha, registry_sha, generator_sha)
        two = GEN.render_script(controls, adapters, manifest_sha, registry_sha, generator_sha)
        self.assertEqual(one, two)
        self.assertIn(f"CONTROL_COUNT={len(controls)}".encode("ascii"), one)
        self.assertIn(f"ADAPTER_COUNT={len(adapters)}".encode("ascii"), one)
        self.assertIn(b"TOTAL=%d", one)
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
            self.assertEqual(v2._model(*case), v1._model(*case), case)

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
            self.assertEqual(self.run_fileset(d).stdout.strip(), "SLP-CHECK-V1\tTEST-FILESET\tERROR\t-\tERROR")
            target = base / "target"; target.write_text("x\n")
            link = base / "link"; link.symlink_to(target)
            self.assertEqual(self.run_fileset(link).stdout.strip(), "SLP-CHECK-V1\tTEST-FILESET\tERROR\t-\tERROR")
            s = base / "symlink-child"; s.mkdir(); os.chmod(s, 0o700); (s / "l").symlink_to(target)
            self.assertEqual(self.run_fileset(s).stdout.strip(), "SLP-CHECK-V1\tTEST-FILESET\tERROR\t-\tERROR")
            if hasattr(os, "mkfifo"):
                f = base / "special"; f.mkdir(); os.chmod(f, 0o700); os.mkfifo(f / "pipe")
                self.assertEqual(self.run_fileset(f).stdout.strip(), "SLP-CHECK-V1\tTEST-FILESET\tERROR\t-\tERROR")

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
    def run_user_cron(self, roots):
        source = USER_CRON._shell_function_for_roots("TEST-USER-CRON", [str(x) for x in roots])
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_USER_CRON"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_both_roots_absent_is_empty_pass(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cp = self.run_user_cron([base / "cron", base / "cron" / "crontabs"])
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            self.assertEqual(
                cp.stdout.strip(),
                "SLP-CHECK-V1\tTEST-USER-CRON\tVALUE\troots_present=0;roots_absent=2;checked=0;violations=0\tPASS",
            )

    def test_full_layout_empty_population_pass_and_overlap(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            cron = base / "cron"; cron.mkdir()
            crontabs = cron / "crontabs"; crontabs.mkdir()
            cp = self.run_user_cron([cron, crontabs])
            self.assertEqual(cp.stderr, "")
            self.assertIn("roots_present=2;roots_absent=0;checked=0;violations=0\tPASS", cp.stdout)

            user_file = crontabs / "alice"; user_file.write_text("x\n", encoding="utf-8"); os.chmod(user_file, 0o600)
            cp = self.run_user_cron([cron, crontabs])
            self.assertEqual(cp.stderr, "")
            self.assertIn("roots_present=2;roots_absent=0;checked=1;violations=0\tPASS", cp.stdout)

    def test_recursive_regular_file_pass_and_violation(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); cron = base / "cron"; nested = cron / "a" / "b"; nested.mkdir(parents=True)
            f = nested / "job"; f.write_text("x\n", encoding="utf-8"); os.chmod(f, 0o640)
            self.assertIn("checked=1;violations=0\tPASS", self.run_user_cron([cron]).stdout)
            os.chmod(f, 0o662)
            self.assertIn("checked=1;violations=1\tFAIL", self.run_user_cron([cron]).stdout)

    def test_symlink_special_root_file_and_traversal_error_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            target = base / "target"; target.write_text("x\n", encoding="utf-8")
            root_link = base / "root-link"; root_link.symlink_to(base, target_is_directory=True)
            self.assertEqual(self.run_user_cron([root_link]).stdout.strip(), "SLP-CHECK-V1\tTEST-USER-CRON\tERROR\t-\tERROR")

            cron = base / "cron"; cron.mkdir(); (cron / "link").symlink_to(target)
            self.assertEqual(self.run_user_cron([cron]).stdout.strip(), "SLP-CHECK-V1\tTEST-USER-CRON\tERROR\t-\tERROR")
            (cron / "link").unlink()

            if hasattr(os, "mkfifo"):
                os.mkfifo(cron / "pipe")
                self.assertEqual(self.run_user_cron([cron]).stdout.strip(), "SLP-CHECK-V1\tTEST-USER-CRON\tERROR\t-\tERROR")
                (cron / "pipe").unlink()

            bad_root = base / "file-root"; bad_root.write_text("x\n", encoding="utf-8")
            self.assertEqual(self.run_user_cron([bad_root]).stdout.strip(), "SLP-CHECK-V1\tTEST-USER-CRON\tERROR\t-\tERROR")

            locked = cron / "locked"; locked.mkdir(); os.chmod(locked, 0)
            try:
                cp = self.run_user_cron([cron])
                # Root execution may not exercise DAC denial in some CI containers; ordinary-user execution must fail closed.
                if os.geteuid() != 0:
                    self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-USER-CRON\tERROR\t-\tERROR")
            finally:
                os.chmod(locked, 0o700)

    def test_generation_rejects_wrong_contract_fields(self):
        good = "/var/spool/cron|/var/spool/cron/crontabs"
        for args in (
            ("TEST", "/var/spool/cron", "mode", "bits-clear", "0022"),
            ("TEST", good, "owner", "bits-clear", "0022"),
            ("TEST", good, "mode", "eq", "0022"),
            ("TEST", good, "mode", "bits-clear", "0033"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    USER_CRON.shell_function(*args)


@unittest.skipIf(BASH is None, "bash not available")
class StandardSystemPathsModeFixtures(unittest.TestCase):
    def run_standard(self, exec_roots, lib_roots, module_root):
        source = STANDARD_PATHS._shell_function_for_layout(
            "TEST-STANDARD-PATHS",
            [str(x) for x in exec_roots],
            [str(x) for x in lib_roots],
            str(module_root),
        )
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_STANDARD_PATHS"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
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
            self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-STANDARD-PATHS\tERROR\t-\tERROR")

    def test_missing_role_and_candidate_special_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            empty_mod = base / "empty-mod"; empty_mod.mkdir()
            cp = self.run_standard([exe], [lib], empty_mod)
            self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-STANDARD-PATHS\tERROR\t-\tERROR")
            if hasattr(os, "mkfifo"):
                os.mkfifo(exe / "pipe")
                cp = self.run_standard([exe], [lib], mod)
                self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-STANDARD-PATHS\tERROR\t-\tERROR")

    def test_traversal_error_fail_closed_for_ordinary_user(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            locked = lib / "locked"; locked.mkdir(); os.chmod(locked, 0)
            try:
                cp = self.run_standard([exe], [lib], mod)
                if os.geteuid() != 0:
                    self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-STANDARD-PATHS\tERROR\t-\tERROR")
            finally:
                os.chmod(locked, 0o700)

    def test_generation_rejects_wrong_contract_fields(self):
        good = "/bin|/sbin|/usr/bin|/usr/sbin|/lib|/lib64|/usr/lib|/usr/lib64|/lib/modules/<uname-r>"
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
            self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-SUID-SGID\tERROR\t-\tERROR")
            allow = base / "allowlist"
            allow.write_text("relative/path\n", encoding="utf-8")
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(allow))
            self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-SUID-SGID\tERROR\t-\tERROR")

    def test_nosuid_mount_is_excluded(self):
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
            self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-SUID-SGID\tERROR\t-\tERROR")

    def test_nul_in_allowlist_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            app = base / "app"; app.write_text("x\n", encoding="utf-8"); os.chmod(app, 0o4755)
            allow = base / "allowlist"
            allow.write_bytes(str(app).encode("utf-8") + b"\x00\n")
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(allow))
            self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-SUID-SGID\tERROR\t-\tERROR")

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
            passwd.write_text(passwd_text, encoding="utf-8")
            shadow.write_text(shadow_text, encoding="utf-8")
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
        self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-SHADOW\tERROR\t-\tERROR")
        cp = self.run_shadow("broken\n", "root:!:1:0:99999:7:::\n")
        self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-SHADOW\tERROR\t-\tERROR")

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
class HomeSensitiveFilesAdapterFixtures(unittest.TestCase):
    def setUp(self):
        if BASH is None:
            self.skipTest("bash unavailable")
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.passwd = self.base / "passwd"
        self.login_defs = self.base / "login.defs"
        self.inventory = self.base / "inventory"
        self.root_home = self.base / "root"
        self.user_home = self.base / "user"
        self.root_home.mkdir(); self.user_home.mkdir()
        self.login_defs.write_text("UID_MIN 1000\n", encoding="utf-8")
        self.inventory.write_text("\n".join(HOME_SENSITIVE.MANDATORY_SOURCE_NAMES) + "\n", encoding="utf-8")
        self.passwd.write_text(
            f"root:x:0:0:root:{self.root_home}:/bin/bash\n"
            f"daemon:x:1:1:daemon:{self.base / 'daemon'}:/usr/sbin/nologin\n"
            f"user:x:1000:1000:user:{self.user_home}:/bin/bash\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self):
        block = HOME_SENSITIVE._shell_function_for_fixture(
            "TEST.HOME", str(self.passwd), str(self.login_defs), str(self.inventory)
        )
        script = self.base / "check.sh"
        script.write_text(block + "\nslp_check_TEST_HOME\n", encoding="utf-8")
        return subprocess.run([BASH, str(script)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_positive_and_service_account_excluded(self):
        (self.root_home / ".bashrc").write_text("x\n", encoding="utf-8"); os.chmod(self.root_home / ".bashrc", 0o600)
        (self.user_home / ".bash_history").write_text("x\n", encoding="utf-8"); os.chmod(self.user_home / ".bash_history", 0o600)
        cp = self.run_check()
        self.assertEqual(cp.returncode, 0); self.assertEqual(cp.stderr, "")
        self.assertIn("accounts=2;homes=2;names=8;checked=2;violations=0\tPASS", cp.stdout)

    def test_group_other_bits_fail(self):
        p = self.user_home / ".profile"; p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o644)
        cp = self.run_check()
        self.assertIn("checked=1;violations=1\tFAIL", cp.stdout)

    def test_missing_inventory_fails_closed(self):
        self.inventory.unlink()
        cp = self.run_check()
        self.assertIn("\tERROR\t-\tERROR", cp.stdout)

    def test_inventory_must_cover_all_source_examples(self):
        self.inventory.write_text(".bashrc\n", encoding="utf-8")
        cp = self.run_check()
        self.assertIn("\tERROR\t-\tERROR", cp.stdout)

    def test_additional_nested_inventory_member_is_checked(self):
        self.inventory.write_text("\n".join(HOME_SENSITIVE.MANDATORY_SOURCE_NAMES) + "\n.config/fish/config.fish\n", encoding="utf-8")
        d=self.user_home / ".config" / "fish"; d.mkdir(parents=True)
        p=d / "config.fish"; p.write_text("x\n", encoding="utf-8"); os.chmod(p,0o600)
        cp=self.run_check()
        self.assertIn("names=9;checked=1;violations=0\tPASS", cp.stdout)

    def test_symlink_member_fails_closed(self):
        outside=self.base / "outside"; outside.write_text("x\n",encoding="utf-8")
        (self.user_home / ".bashrc").symlink_to(outside)
        cp=self.run_check()
        self.assertIn("\tERROR\t-\tERROR", cp.stdout)

    def test_nul_in_login_defs_or_inventory_is_error(self):
        self.login_defs.write_bytes(b"UID\x00_MIN 1000\n")
        self.assertIn("\tERROR\t-\tERROR", self.run_check().stdout)
        self.login_defs.write_text("UID_MIN 1000\n", encoding="utf-8")
        invalid_inventory_bytes = b".bash_history\x00\n" + "\n".join(HOME_SENSITIVE.MANDATORY_SOURCE_NAMES[1:]).encode("utf-8") + b"\n"
        self.inventory.write_bytes(invalid_inventory_bytes)
        self.assertIn("\tERROR\t-\tERROR", self.run_check().stdout)

@unittest.skipIf(BASH is None, "bash not available")
class HomeDirectoriesModeAdapterFixtures(unittest.TestCase):
    def setUp(self):
        if BASH is None:
            self.skipTest("bash unavailable")
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.passwd = self.base / "passwd"
        self.login_defs = self.base / "login.defs"
        self.root_home = self.base / "root"
        self.user_home = self.base / "user"
        self.root_home.mkdir(); self.user_home.mkdir()
        os.chmod(self.root_home, 0o700); os.chmod(self.user_home, 0o700)
        self.login_defs.write_text("UID_MIN 1000\n", encoding="utf-8")
        self.passwd.write_text(
            f"root:x:0:0:root:{self.root_home}:/bin/bash\n"
            f"daemon:x:1:1:daemon:{self.base / 'daemon'}:/usr/sbin/nologin\n"
            f"user:x:1000:1000:user:{self.user_home}:/bin/bash\n",
            encoding="utf-8",
        )
    def tearDown(self): self.tmp.cleanup()
    def run_check(self):
        block = HOME_DIRECTORIES._shell_function_for_fixture("TEST.HOME.DIR", str(self.passwd), str(self.login_defs))
        script = self.base / "check-home-dir.sh"
        script.write_text(block + "\nslp_check_TEST_HOME_DIR\n", encoding="utf-8")
        return subprocess.run([BASH, str(script)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def test_positive_and_service_account_excluded(self):
        cp=self.run_check(); self.assertEqual(cp.returncode,0); self.assertEqual(cp.stderr,""); self.assertIn("accounts=2;homes=2;violations=0\tPASS",cp.stdout)
    def test_non_0700_fails(self):
        os.chmod(self.user_home,0o750); cp=self.run_check(); self.assertIn("accounts=2;homes=2;violations=1\tFAIL",cp.stdout)
    def test_absent_selected_home_is_outside_mode_population(self):
        self.user_home.rmdir(); cp=self.run_check(); self.assertIn("accounts=2;homes=1;violations=0\tPASS",cp.stdout)
    def test_symlink_home_fails_closed(self):
        self.user_home.rmdir(); self.user_home.symlink_to(self.root_home,target_is_directory=True); cp=self.run_check(); self.assertIn("\tERROR\t-\tERROR",cp.stdout)
    def test_nul_in_login_defs_is_error(self):
        self.login_defs.write_bytes(b"UID\x00_MIN 1000\n")
        cp=self.run_check(); self.assertIn("\tERROR\t-\tERROR",cp.stdout)
    def test_generation_rejects_wrong_contract_fields(self):
        for args in (("TEST","/etc/passwd","mode","eq","0700"),("TEST",HOME_DIRECTORIES.CANONICAL_LOCATOR,"owner","eq","0700"),("TEST",HOME_DIRECTORIES.CANONICAL_LOCATOR,"mode","bits-clear","0700"),("TEST",HOME_DIRECTORIES.CANONICAL_LOCATOR,"mode","eq","0750")):
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
        self.assertIn("read-only policy checks", cp.stdout)
        self.assertEqual(self.run_check("--bogus").returncode, 2)
        self.assertEqual(self.run_check("--help", "extra").returncode, 2)

    def test_build_info(self):
        cp = self.run_check("--build-info")
        self.assertEqual(cp.returncode, 0)
        self.assertEqual(cp.stderr, "")
        self.assertIn("GENERATOR_ID=product-check-generator-v1\n", cp.stdout)
        rows, _, _, _, _ = load_current()
        self.assertIn(f"CONTROL_COUNT={len(rows)}\n", cp.stdout)
        self.assertIn(f"ADAPTER_COUNT={len(load_current()[2])}\n", cp.stdout)
        self.assertIn("MUTATING_MODES=NONE\n", cp.stdout)

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
    def run_fixture(self, pam_text=None, group_text=None, authority_text=None, symlink=None, prelude=""):
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
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            row = cp.stdout.strip().split("\t")
            self.assertEqual(len(row), 5, cp.stdout)
            return row

    def test_positive_root_only_empty_authority_and_include(self):
        row = self.run_fixture(
            "# comment\n@include common-auth\nauth required pam_wheel.so use_uid # exact\n",
            "root:x:0:\nwheel:x:10:root\n",
            "# no additional users\n",
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("approved=0", row[3])

    def test_positive_explicit_users_arbitrary_gid_and_crlf(self):
        row = self.run_fixture(
            "auth required pam_wheel.so use_uid\r\n",
            "wheel:!:1234:root,alice,bob\r\n",
            "alice\r\nbob\r\n",
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("gid=1234", row[3])

    def test_duplicate_exact_pam_rule_is_redundant_but_compliant(self):
        row = self.run_fixture(
            "auth required pam_wheel.so use_uid\nauth required pam_wheel.so use_uid\n",
            "wheel:x:42:root\n", "",
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
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

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

    def test_symlink_inputs_fail_closed(self):
        for which in ("pam", "group", "authority"):
            with self.subTest(which=which):
                row = self.run_fixture("auth required pam_wheel.so use_uid\n", "wheel:x:10:root\n", "", symlink=which)
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_nul_and_internal_cr_fail_closed(self):
        cases = (
            (b"auth required pam_wheel.so\x00 use_uid\n", b"wheel:x:10:root\n", b""),
            (b"auth required pam_wheel.so use_uid\nfoo\rbar\n", b"wheel:x:10:root\n", b""),
            (b"auth required pam_wheel.so use_uid\n", b"wheel:x:10:root\x00\n", b""),
            (b"auth required pam_wheel.so use_uid\n", b"wheel:x:10:root\n", b"alice\x00\n"),
        )
        for pam_text, group_text, authority_text in cases:
            with self.subTest(pam_text=pam_text, group_text=group_text, authority_text=authority_text):
                row = self.run_fixture(pam_text, group_text, authority_text)
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

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
        cases=("missing-authority","bad-header","visudo-fail","unexpected-output","duplicate-path")
        for case in cases:
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

    def test_symlink_member_and_binary_authority_error(self):
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
            self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-SUDOERS\tERROR\t-\tERROR")

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
            self.assertEqual(cp.stdout.strip(), "SLP-CHECK-V1\tTEST-SUDOERS\tERROR\t-\tERROR")
            self.assertNotIn("ignored null byte", cp.stderr.lower())

    def test_generation_rejects_wrong_contract_fields(self):
        cases=(("/tmp/sudoers",SUDOERS_REVIEWED_POLICY.CANONICAL_KEY,SUDOERS_REVIEWED_POLICY.CANONICAL_OP,SUDOERS_REVIEWED_POLICY.CANONICAL_AUTHORITY),(SUDOERS_REVIEWED_POLICY.CANONICAL_LOCATOR,"users",SUDOERS_REVIEWED_POLICY.CANONICAL_OP,SUDOERS_REVIEWED_POLICY.CANONICAL_AUTHORITY),(SUDOERS_REVIEWED_POLICY.CANONICAL_LOCATOR,SUDOERS_REVIEWED_POLICY.CANONICAL_KEY,"eq",SUDOERS_REVIEWED_POLICY.CANONICAL_AUTHORITY),(SUDOERS_REVIEWED_POLICY.CANONICAL_LOCATOR,SUDOERS_REVIEWED_POLICY.CANONICAL_KEY,SUDOERS_REVIEWED_POLICY.CANONICAL_OP,"/tmp/policy"))
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError): SUDOERS_REVIEWED_POLICY.shell_function("TEST",*args)


class SshdRootLoginAdapterFixtures(unittest.TestCase):
    def run_fixture(
        self, config_text=None, effective="no", syntax_rc=0, include_files=None,
        make_symlink=False, shadow_compgen=False, sort_fail=False,
    ):
        if BASH is None:
            self.skipTest("bash not found")
        include_files = include_files or {}
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            cfg = root / "sshd_config"
            if config_text is not None:
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
                path.write_bytes(body.encode("utf-8"))
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
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

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
    def _open_fifo_writer(path, timeout=5.0):
        deadline = time.monotonic() + timeout
        while True:
            try:
                return os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as exc:
                if exc.errno != errno.ENXIO or time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)

    def _finish_popen(self, cp, timeout=5.0):
        out, err = cp.communicate(timeout=timeout)
        self.assertEqual(cp.returncode, 0, err)
        row = out.strip().split("\t")
        self.assertEqual(len(row), 5, out + err)
        return row

    @staticmethod
    def _serve_fifo_once(path, text):
        failures = []
        def writer():
            try:
                with open(path, "w", encoding="utf-8") as stream:
                    stream.write(text)
                    stream.flush()
            except Exception as exc:
                failures.append(exc)
        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        return thread, failures

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
        row = self.run_fixture(parent_mode=0o775)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("parent_violations=", row[3])

    def test_deleted_library_is_error(self):
        row = self.run_fixture(deleted_library=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_missing_library_population_is_error(self):
        row = self.run_fixture(no_library=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_executable_mapping_without_shared_object_name_is_checked(self):
        row = self.run_fixture(mapped_name="render.plugin", file_mode=0o575)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_proc_octal_escaped_mapping_path_is_decoded(self):
        row = self.run_fixture(mapped_name="render plugin", proc_escape_space=True, file_mode=0o575)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_malformed_proc_escape_is_error(self):
        row = self.run_fixture(malformed_escape=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

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
            self.assertEqual(captured.getvalue().strip(), "ERROR")

    def _snapshot_drift_case(self, mutate_parent):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, libdir1 = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            proc = self._prepare_proc(root)
            self._add_pid(proc, "100", exe1, self._maps_line(str(lib1)))
            pid2 = self._add_pid(proc, "200", exe2, None)
            fifo = pid2 / "maps"; os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app1", "app2"))
            cp = self._popen_script(self._script(root, proc, fsroot))
            fd = self._open_fifo_writer(fifo)
            try:
                if mutate_parent:
                    libdir1.chmod(0o775)
                else:
                    lib1.chmod(0o575)
                os.write(fd, self._maps_line(str(lib2)).encode("utf-8"))
            finally:
                os.close(fd)
            thread, failures = self._serve_fifo_once(fifo, self._maps_line(str(lib2)))
            row = self._finish_popen(cp)
            thread.join(timeout=5.0)
            self.assertFalse(thread.is_alive(), "second maps FIFO writer did not finish")
            self.assertEqual(failures, [])
            return row

    def test_file_snapshot_drift_is_error(self):
        row = self._snapshot_drift_case(False)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_parent_snapshot_drift_is_error(self):
        row = self._snapshot_drift_case(True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))


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

    def run_cli(self, *args):
        return subprocess.run(
            [str(self.ARTIFACT), *args], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def run_sourced(self, body):
        return subprocess.run(
            [BASH, "-c", f"set -u\nsource {self.ARTIFACT!s}\n{body}"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    @staticmethod
    def synthetic_prelude():
        return r'''
SLP_RESULTS=(
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.1-GROUP-MODE\tVALUE\t0644\tPASS'
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE\tVALUE\taccounts=2;homes=2;violations=1\tFAIL'
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE\tVALUE\troots_present=9;roots_absent=0;aliases=4;exec=1236;libraries=999;modules=6474;checked=8300;violations=0\tPASS'
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE\tERROR\t-\tERROR'
)
SLP_TOTAL=4
SLP_PASS=2
SLP_FAIL=1
SLP_NF=0
SLP_ERR=1
SLP_POLICY_STATUS=UNEVALUATED
SLP_POLICY_RC=1
'''

    def test_unified_tracked_artifact_matches_fresh_generator_exactly(self):
        self.assertTrue(self.GEN_V2.is_file())
        self.assertTrue(self.ARTIFACT.is_file())
        self.assertTrue(self.SIDECAR.is_file())
        self.assertEqual(self.ARTIFACT.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.SIDECAR.stat().st_mode & 0o777, 0o644)
        self.assertTrue(self.ARTIFACT.read_bytes().startswith(b"#!/bin/bash -p\n"))
        with tempfile.TemporaryDirectory(prefix="slp-unified-cli-rebuild-") as td:
            out = Path(td) / "securelinux-policy.sh"
            cp = subprocess.run(
                [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B",
                 str(self.GEN_V2), "--repo", str(ROOT), "--out", str(out)],
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
            self.assertIn("GENERATOR_ID=product-check-generator-v2\n", cp.stdout)
            self.assertIn("CONTROL_COUNT=47\n", cp.stdout)
            self.assertIn("ADAPTER_COUNT=14\n", cp.stdout)
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

    def test_unified_help_version_build_info_and_stubs(self):
        syntax = subprocess.run([BASH, "-n", str(self.ARTIFACT)], capture_output=True, text=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        noargs = self.run_cli()
        self.assertEqual(noargs.returncode, 0)
        self.assertIn("SecureLinux-Policy v3 — единый read-only CLI", noargs.stdout)
        self.assertIn("--check [--failed] [--format pretty|raw|json]", noargs.stdout)
        version = self.run_cli("--version")
        self.assertEqual(version.returncode, 0)
        self.assertIn("PRODUCT_CLI=product-cli-v1\n", version.stdout)
        build = self.run_cli("--build-info")
        self.assertEqual(build.returncode, 0)
        self.assertIn("GENERATOR_ID=product-check-generator-v2\n", build.stdout)
        self.assertIn("MUTATING_MODES=NONE\n", build.stdout)
        for flag, name in (("--apply", "APPLY"), ("--restore", "RESTORE")):
            cp = self.run_cli(flag)
            self.assertEqual(cp.returncode, 2)
            self.assertEqual(cp.stdout, "")
            self.assertEqual(cp.stderr, f"NOT_IMPLEMENTED: {name}; host state was not changed.\n")

    def test_unified_pretty_raw_json_and_failed_renderers(self):
        pre = self.synthetic_prelude()
        pretty = self.run_sourced(pre + "\nslp_render_pretty 0 CHECK\n")
        self.assertEqual(pretty.returncode, 0, pretty.stderr)
        lines = pretty.stdout.splitlines()
        self.assertEqual(lines[2].index("CONTROL"), 9)
        self.assertEqual(lines[2].index("VALUE / DETAILS"), 63)
        continuation = [x for x in lines if x.startswith(" " * 63) and "libraries=999" in x]
        self.assertEqual(len(continuation), 1)
        failed = self.run_sourced(pre + "\nslp_render_pretty 1 CHECK\n")
        self.assertEqual(failed.returncode, 0, failed.stderr)
        self.assertIn("HOME-DIRECTORIES-MODE", failed.stdout)
        self.assertIn("HOME-SENSITIVE-FILES-MODE", failed.stdout)
        self.assertNotIn("GROUP-MODE", failed.stdout)
        raw = self.run_sourced(pre + "\nslp_render_raw 0\n")
        self.assertEqual(raw.returncode, 0, raw.stderr)
        raw_lines = raw.stdout.splitlines()
        self.assertEqual(len(raw_lines), 5)
        self.assertTrue(all(x.startswith("SLP-CHECK-V1\t") for x in raw_lines[:-1]))
        obj = json.loads(self.run_sourced(pre + "\nslp_render_json 0\n").stdout)
        self.assertEqual(obj["schema"], "SLP-REPORT-V1")
        self.assertEqual(obj["summary"], {"total":4,"pass":2,"fail":1,"not_found":0,"error":1})
        fobj = json.loads(self.run_sourced(pre + "\nslp_render_json 1\n").stdout)
        self.assertEqual([x["result"] for x in fobj["results"]], ["FAIL", "ERROR"])

    def test_unified_provenance_invalid_cli_and_no_mutation_scaffold(self):
        prov = self.run_cli("--provenance")
        self.assertEqual(prov.returncode, 0)
        rows = [json.loads(x) for x in prov.stdout.splitlines()]
        self.assertEqual(len(rows), 47)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
