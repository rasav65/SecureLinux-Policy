#!/usr/bin/env python3
"""product-v1 tests for the tracked product CHECK generator."""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
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
BASH = shutil.which("bash")


def load_generator():
    spec = importlib.util.spec_from_file_location("slp_product_generator", GEN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GEN = load_generator()


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
        self.assertTrue({"sysctl", "file-mode-owner", "kernel-cmdline", "optional-file-root-files-mode", "local-account-password-state", "user-cron-files-mode", "standard-system-paths-mode", "suid-sgid-applications", "home-sensitive-files-mode", "home-directories-mode"} <= set(adapters))
        self.assertEqual({c["parameter_kind"] for c in controls}, {"sysctl", "file-mode-owner", "kernel-cmdline", "optional-file-root-files-mode", "local-account-password-state", "user-cron-files-mode", "standard-system-paths-mode", "suid-sgid-applications", "home-sensitive-files-mode", "home-directories-mode"})
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
        self.assertIn(b"stat -L -c %a", rendered)
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
                # Root execution can bypass DAC in some CI containers; ordinary-user execution must fail closed.
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


class UnifiedCliArtifact(unittest.TestCase):
    GEN_V2 = ROOT / "product/generate-product-check-v2.py"
    ARTIFACT = ROOT / "securelinux-policy.sh"
    SIDECAR = ROOT / "securelinux-policy.sh.sha256"

    def run_cli(self, *args):
        return subprocess.run(
            [BASH, str(self.ARTIFACT), *args], cwd=ROOT,
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
        with tempfile.TemporaryDirectory(prefix="slp-unified-cli-rebuild-") as td:
            out = Path(td) / "securelinux-policy.sh"
            cp = subprocess.run(
                [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B",
                 str(self.GEN_V2), "--repo", str(ROOT), "--out", str(out)],
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
            self.assertIn("GENERATOR_ID=product-check-generator-v2\n", cp.stdout)
            self.assertIn("CONTROL_COUNT=43\n", cp.stdout)
            self.assertIn("ADAPTER_COUNT=10\n", cp.stdout)
            self.assertEqual(out.read_bytes(), self.ARTIFACT.read_bytes())
            self.assertEqual(out.with_name(out.name + ".sha256").read_bytes(), self.SIDECAR.read_bytes())
        expected = f"{sha256_file(self.ARTIFACT)}  {self.ARTIFACT.name}\n"
        self.assertEqual(self.SIDECAR.read_text(encoding="utf-8"), expected)

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
        self.assertEqual(len(rows), 43)
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
