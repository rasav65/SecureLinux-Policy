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
BASH = shutil.which("bash")


def load_generator():
    spec = importlib.util.spec_from_file_location("slp_product_generator", GEN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GEN = load_generator()


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class GeneratorModel(unittest.TestCase):
    def load_current(self):
        rows, manifest_sha = GEN.load_manifest(ROOT)
        adapters, registry_sha = GEN.load_registry(ROOT)
        controls = [GEN.load_control(ROOT, row) for row in rows]
        return rows, manifest_sha, adapters, registry_sha, controls

    def test_current_population_and_registry(self):
        rows, manifest_sha, adapters, registry_sha, controls = self.load_current()
        self.assertEqual(len(rows), 8)
        self.assertEqual(len(controls), 8)
        self.assertEqual(set(adapters), {"sysctl", "file-mode-owner"})
        self.assertEqual({c["parameter_kind"] for c in controls}, {"sysctl"})
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
        self.assertIn(b"CONTROL_COUNT=8", one)
        self.assertIn(b"ADAPTER_COUNT=2", one)
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
        self.assertIn("CONTROL_COUNT=8\n", self.generator_stdout)
        self.assertIn("ADAPTER_COUNT=2\n", self.generator_stdout)
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
        self.assertIn("CONTROL_COUNT=8\n", cp.stdout)
        self.assertIn("ADAPTER_COUNT=2\n", cp.stdout)
        self.assertIn("MUTATING_MODES=NONE\n", cp.stdout)

    def test_provenance_all_and_one(self):
        cp = self.run_check("--provenance")
        self.assertEqual(cp.returncode, 0)
        lines = cp.stdout.splitlines()
        self.assertEqual(len(lines), 8)
        objs = [json.loads(line) for line in lines]
        ids = [obj["control_id"] for obj in objs]
        self.assertEqual(len(set(ids)), 8)
        for obj in objs:
            self.assertEqual(obj["parameter_kind"], "sysctl")
            self.assertEqual(len(obj["quote_sha256"]), 64)
            self.assertEqual(len(obj["registry_sha256"]), 64)
        one = self.run_check("--provenance", ids[0])
        self.assertEqual(one.returncode, 0)
        self.assertEqual(json.loads(one.stdout)["control_id"], ids[0])
        self.assertEqual(self.run_check("--provenance", "NO-SUCH-CONTROL").returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
