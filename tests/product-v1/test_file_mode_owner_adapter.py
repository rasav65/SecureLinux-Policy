#!/usr/bin/env python3
"""product-v1: механические тесты product-file-mode-owner-check-v2.

Проверяют emitted bash на фикстурах во временном каталоге.
Репозиторий и система не изменяются.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PATH = ROOT / "product" / "adapters" / "product-file-mode-owner-check-v2.py"
ADAPTER_JSON = ROOT / "product" / "adapters" / "product-file-mode-owner-check-v2.json"
CONTRACT_PATH = ROOT / "product" / "contracts" / "file-mode-owner-check-semantic-v2.json"
BASH = shutil.which("bash")


def load_adapter():
    spec = importlib.util.spec_from_file_location("slp_product_file_adapter", ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ADAPTER = load_adapter()


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Emitted(unittest.TestCase):
    def test_no_mutating_token(self):
        for op, exp in (("eq", "0644"), ("bits-clear", "0077")):
            src = ADAPTER.shell_function("C", "/etc/shadow", "mode", op, exp)
            for token in ADAPTER.MUTATING_TOKENS:
                self.assertNotIn(token, src, token)
            stat_probe = '$(LC_ALL=C command /usr/bin/stat -c %F -- "$_slp_path" 2>&1)'
            self.assertEqual(src.count(stat_probe), 1)
            self.assertNotIn("$(", src.replace('$(LC_ALL=C command /usr/bin/stat -L -c %a -- "$_slp_path" 2>/dev/null)', "").replace(stat_probe, ""))

    def test_rejects_unsupported(self):
        bad = [
            ("C", "/etc/passwd", "owner", "eq", "0644"),
            ("C", "/etc/passwd", "group", "eq", "0644"),
            ("C", "/etc/passwd", "owner_group", "eq", "0644"),
            ("C", "/etc/passwd", "mode", "ge", "0644"),
            ("C", "/etc/passwd", "mode", "contains", "0644"),
            ("C", "/etc/passwd", "mode", "bits-clear", "0000"),
            ("C", "/etc/passwd", "mode", "bits-clear", "077"),
            ("C", "/etc/passwd", "mode", "eq", "0648"),
            ("C", "etc/passwd", "mode", "eq", "0644"),
            ("C", "/etc/pa\nsswd", "mode", "eq", "0644"),
            ("C", "/etc/pa'sswd", "mode", "eq", "0644"),
            ("C", "/etc/$(id)", "mode", "eq", "0644"),
            ("C;id", "/etc/passwd", "mode", "eq", "0644"),
            ("C", "/etc/passwd", "mode", "eq", "644"),
        ]
        for args in bad:
            with self.assertRaises(ValueError, msg=repr(args)):
                ADAPTER.shell_function(*args)

    def test_contract_binding(self):
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        meta = json.loads(ADAPTER_JSON.read_text(encoding="utf-8"))
        self.assertEqual(contract["semantic_contract_id"], ADAPTER.SEMANTIC_CONTRACT_ID)
        self.assertEqual(meta["adapter_id"], ADAPTER.ADAPTER_ID)
        self.assertEqual(meta["semantic_contract_id"], ADAPTER.SEMANTIC_CONTRACT_ID)
        self.assertEqual(meta["parameter_kind"], ADAPTER.PARAMETER_KIND)
        self.assertEqual(meta["target_id"], ADAPTER.TARGET_ID)
        self.assertEqual(meta["implementation_sha256"], sha256_file(ADAPTER_PATH))
        self.assertEqual(meta["semantic_contract_sha256"], sha256_file(CONTRACT_PATH))
        self.assertEqual(sorted(contract["supported_keys"]), ["mode"])
        self.assertEqual(sorted(contract["supported_ops"]), ["bits-clear", "eq"])


@unittest.skipIf(BASH is None, "bash not available")
class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="slp-product-file-test-")
        os.chmod(cls.tmp, 0o755)
        t = cls.tmp
        cls.ok = os.path.join(t, "ok")
        Path(cls.ok).write_text("x", encoding="utf-8")
        os.chmod(cls.ok, 0o644)
        cls.zero = os.path.join(t, "zero")
        Path(cls.zero).write_text("x", encoding="utf-8")
        os.chmod(cls.zero, 0o000)
        cls.suid = os.path.join(t, "suid")
        Path(cls.suid).write_text("x", encoding="utf-8")
        os.chmod(cls.suid, 0o4755)
        cls.link_ok = os.path.join(t, "link-ok")
        os.symlink(cls.ok, cls.link_ok)
        cls.dangling = os.path.join(t, "dangling")
        os.symlink(os.path.join(t, "nope"), cls.dangling)
        cls.loop = os.path.join(t, "loop")
        os.symlink(cls.loop, cls.loop)
        cls.closed = os.path.join(t, "closed")
        os.mkdir(cls.closed)
        cls.inner = os.path.join(cls.closed, "inner")
        Path(cls.inner).write_text("x", encoding="utf-8")
        os.chmod(cls.inner, 0o644)
        os.chmod(cls.closed, 0o000)
        cls.directory = os.path.join(t, "directory")
        os.mkdir(cls.directory); os.chmod(cls.directory, 0o644)
        cls.absent = os.path.join(t, "absent")

    @classmethod
    def tearDownClass(cls):
        try:
            os.chmod(cls.closed, 0o700)
        except OSError:
            pass
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_check(self, locator, op, expected, env_extra=None, preamble="", ordinary_user=False):
        src = ADAPTER.shell_function("CTRL-T", locator, "mode", op, expected)
        script = os.path.join(self.tmp, "run.sh")
        with open(script, "w", encoding="utf-8") as f:
            f.write("set -u\n" + preamble + src + "\nslp_check_CTRL_T\n")
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        if env_extra:
            env.update(env_extra)
        kwargs = {}
        if ordinary_user and os.geteuid() == 0:
            kwargs = {"user": 65534, "group": 65534, "extra_groups": []}
        p = subprocess.run([BASH, script], capture_output=True, text=True, env=env, **kwargs)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stderr, "")
        fields = p.stdout.rstrip("\n").split("\t")
        self.assertEqual(len(fields), 5, p.stdout)
        self.assertEqual(fields[0], ADAPTER.WIRE_RECORD_ID)
        self.assertEqual(fields[1], "CTRL-T")
        return tuple(fields[2:])

    def test_value_eq_pass(self):
        self.assertEqual(self.run_check(self.ok, "eq", "0644"), ("VALUE", "0644", "PASS"))

    def test_value_eq_fail(self):
        self.assertEqual(self.run_check(self.ok, "eq", "0600"), ("VALUE", "0644", "FAIL"))

    def test_setuid_bits_visible(self):
        self.assertEqual(self.run_check(self.suid, "eq", "4755"), ("VALUE", "4755", "PASS"))

    def test_zero_mode_padded(self):
        self.assertEqual(self.run_check(self.zero, "eq", "0000"), ("VALUE", "0000", "PASS"))

    def test_bits_clear_pass(self):
        self.assertEqual(self.run_check(self.zero, "bits-clear", "0077"),
                         ("VALUE", "0000", "PASS"))

    def test_bits_clear_fail(self):
        self.assertEqual(self.run_check(self.ok, "bits-clear", "0077"),
                         ("VALUE", "0644", "FAIL"))

    def test_bits_clear_boundary(self):
        self.assertEqual(self.run_check(self.ok, "bits-clear", "0033"),
                         ("VALUE", "0644", "PASS"))

    def test_symlink_dereferenced(self):
        self.assertEqual(self.run_check(self.link_ok, "eq", "0644"),
                         ("VALUE", "0644", "PASS"))

    def test_directory_with_matching_mode_is_error(self):
        self.assertEqual(self.run_check(self.directory, "eq", "0644"),
                         ("ERROR", "target:invalid-type", "ERROR"))

    def test_absent_name_is_not_found(self):
        self.assertEqual(self.run_check(self.absent, "eq", "0644"),
                         ("NOT_FOUND", "-", "NOT_FOUND"))

    def test_stat_error_other_than_enoent_is_error(self):
        # ENAMETOOLONG при доступном для поиска родителе: отсутствие не доказано (B-02).
        self.assertEqual(self.run_check(os.path.join(self.tmp, "n" * 300), "eq", "0644"),
                         ("ERROR", "target:stat-failed", "ERROR"))

    def test_dangling_symlink_is_error(self):
        self.assertEqual(self.run_check(self.dangling, "eq", "0644"),
                         ("ERROR", "target:invalid-type", "ERROR"))

    def test_symlink_loop_is_error(self):
        self.assertEqual(self.run_check(self.loop, "eq", "0644"), ("ERROR", "target:invalid-type", "ERROR"))

    def test_parent_is_file_is_error(self):
        self.assertEqual(self.run_check(os.path.join(self.ok, "child"), "eq", "0644"),
                         ("ERROR", "target:stat-failed", "ERROR"))

    def test_existing_under_unsearchable_parent_is_error(self):
        self.assertEqual(self.run_check(self.inner, "eq", "0644", ordinary_user=True),
                         ("ERROR", "target:stat-failed", "ERROR"))

    def test_absent_under_unsearchable_parent_is_error(self):
        self.assertEqual(self.run_check(os.path.join(self.closed, "absent"), "eq", "0644", ordinary_user=True),
                         ("ERROR", "target:stat-failed", "ERROR"))

    def test_path_and_function_shadowing_do_not_override_pinned_stat(self):
        empty = os.path.join(self.tmp, "emptybin")
        os.makedirs(empty, exist_ok=True)
        fake = 'stat(){ printf "600\n"; }\nfunction /usr/bin/stat(){ printf "600\n"; }\n'
        self.assertEqual(
            self.run_check(self.ok, "eq", "0644", {"PATH": empty}, fake),
            ("VALUE", "0644", "PASS"),
        )

    def test_target_is_not_modified(self):
        before = os.lstat(self.ok)
        self.run_check(self.ok, "eq", "0644")
        after = os.lstat(self.ok)
        self.assertEqual((before.st_mode, before.st_size, before.st_mtime_ns),
                         (after.st_mode, after.st_size, after.st_mtime_ns))


if __name__ == "__main__":
    unittest.main(verbosity=2)
