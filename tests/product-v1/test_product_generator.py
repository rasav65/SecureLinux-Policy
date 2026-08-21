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
        self.assertTrue({"sysctl", "file-mode-owner", "kernel-cmdline", "optional-file-root-files-mode", "local-account-password-state"} <= set(adapters))
        self.assertEqual({c["parameter_kind"] for c in controls}, {"sysctl", "file-mode-owner", "kernel-cmdline", "optional-file-root-files-mode", "local-account-password-state"})
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
                "FSTEC-LINUX-2022-2.5.9-TSX": ("SRC-0032", "/proc/cmdline", "tsx", "eq", "off"),
            },
        )
        self.assertFalse(any(c["index_id"] == "SRC-0026" for c in controls))
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
        adapter_path = ROOT / "product/adapters/product-kernel-cmdline-check-v1.py"
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
