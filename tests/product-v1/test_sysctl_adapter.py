#!/usr/bin/env python3
# product-v1 tests for product-sysctl-check-v1 and ADAPTER-REGISTRY.tsv.
import csv, hashlib, importlib.util, json, shutil, subprocess, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PATH = ROOT / "product" / "adapters" / "product-sysctl-check-v1.py"
ADAPTER_JSON = ROOT / "product" / "adapters" / "product-sysctl-check-v1.json"
CONTRACT_PATH = ROOT / "product" / "contracts" / "sysctl-check-semantic-v1.json"
REGISTRY = ROOT / "product" / "ADAPTER-REGISTRY.tsv"
BASH = shutil.which("bash")

def sha256_file(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1<<20), b""): h.update(chunk)
    return h.hexdigest()

def load_adapter():
    spec=importlib.util.spec_from_file_location("slp_product_sysctl_adapter", ADAPTER_PATH)
    mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod
ADAPTER=load_adapter()

class Static(unittest.TestCase):
    def test_identity_and_validation(self):
        self.assertEqual(ADAPTER.ADAPTER_ID, "product-sysctl-check-v1")
        self.assertEqual(ADAPTER.PARAMETER_KIND, "sysctl")
        self.assertEqual(ADAPTER.proc_path("kernel.dmesg_restrict"), "/proc/sys/kernel/dmesg_restrict")
        bad=[("C","/proc/sys","kernel.x","eq",1),("C","sysctl",".kernel.x","eq",1),("C","sysctl","kernel..x","eq",1),("C","sysctl","kernel.x","ge",1),("C","sysctl","kernel.x","eq","1"),("C","sysctl","kernel.x","eq",True),("C;id","sysctl","kernel.x","eq",1)]
        for args in bad:
            with self.assertRaises(ValueError, msg=repr(args)): ADAPTER.shell_function(*args)
    def test_read_only_and_p01_guard(self):
        src=ADAPTER.shell_function("C","sysctl","kernel.x","eq",1)
        self.assertIn('} 2>/dev/null',src); self.assertNotIn("$(",src)
        for token in ADAPTER.MUTATING_TOKENS: self.assertNotIn(token,src,token)
    def test_binding(self):
        contract=json.loads(CONTRACT_PATH.read_text(encoding="utf-8")); meta=json.loads(ADAPTER_JSON.read_text(encoding="utf-8"))
        self.assertEqual(contract["semantic_contract_id"],ADAPTER.SEMANTIC_CONTRACT_ID)
        self.assertEqual(meta["adapter_id"],ADAPTER.ADAPTER_ID); self.assertEqual(meta["parameter_kind"],ADAPTER.PARAMETER_KIND)
        self.assertEqual(meta["semantic_contract_id"],ADAPTER.SEMANTIC_CONTRACT_ID)
        self.assertEqual(meta["implementation_sha256"],sha256_file(ADAPTER_PATH)); self.assertEqual(meta["semantic_contract_sha256"],sha256_file(CONTRACT_PATH)); self.assertEqual(meta["supported_ops"],["eq"])
    def test_registry(self):
        with REGISTRY.open("r",encoding="utf-8",newline="") as f: rows=list(csv.DictReader(f,delimiter="\t"))
        self.assertEqual(len(rows),2)
        self.assertEqual(set(rows[0]),{"parameter_kind","adapter_id","semantic_contract_path","semantic_contract_sha256","adapter_contract_path","adapter_contract_sha256","implementation_path","implementation_sha256"})
        self.assertEqual({r["parameter_kind"] for r in rows},{"sysctl","file-mode-owner"}); self.assertEqual(len({r["adapter_id"] for r in rows}),2)
        for row in rows:
            for pk,sk in (("semantic_contract_path","semantic_contract_sha256"),("adapter_contract_path","adapter_contract_sha256"),("implementation_path","implementation_sha256")):
                p=ROOT/row[pk]; self.assertTrue(p.is_file(),row[pk]); self.assertEqual(sha256_file(p),row[sk],row[pk])

@unittest.skipIf(BASH is None,"bash not available")
class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.tmp=tempfile.mkdtemp(prefix="slp-product-sysctl-test-")
    @classmethod
    def tearDownClass(cls): shutil.rmtree(cls.tmp,ignore_errors=True)
    def run_patched(self,content_bytes,expected):
        target=Path(self.tmp)/"target"
        if target.exists(): shutil.rmtree(target) if target.is_dir() else target.unlink()
        if content_bytes is None: pass
        elif content_bytes==b"__DIR__": target.mkdir()
        else: target.write_bytes(content_bytes)
        src=ADAPTER.shell_function("CTRL-T","sysctl","slp_test.value","eq",expected)
        src=src.replace(repr("/proc/sys/slp_test/value"),repr(str(target)),1)
        run=Path(self.tmp)/"run.sh"; run.write_text("set -u\n"+src+"\nslp_check_CTRL_T\n",encoding="utf-8")
        p=subprocess.run([BASH,str(run)],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr); self.assertEqual(p.stderr,"")
        fields=p.stdout.rstrip("\n").split("\t"); self.assertEqual(len(fields),5,p.stdout); self.assertEqual(fields[:2],[ADAPTER.WIRE_RECORD_ID,"CTRL-T"])
        return tuple(fields[2:])
    def test_value_pass(self): self.assertEqual(self.run_patched(b"001\n",1),("VALUE","1","PASS"))
    def test_value_fail(self): self.assertEqual(self.run_patched(b"+0002\n",1),("VALUE","2","FAIL"))
    def test_negative_value(self): self.assertEqual(self.run_patched(b" -0003 \n",-3),("VALUE","-3","PASS"))
    def test_negative_zero_normalizes(self): self.assertEqual(self.run_patched(b"-000\n",0),("VALUE","0","PASS"))
    def test_not_found(self): self.assertEqual(self.run_patched(None,1),("NOT_FOUND","-","NOT_FOUND"))
    def test_non_integer_is_error(self): self.assertEqual(self.run_patched(b"1 2\n",1),("ERROR","-","ERROR"))
    def test_read_error_has_no_stderr(self): self.assertEqual(self.run_patched(b"__DIR__",1),("ERROR","-","ERROR"))

if __name__=="__main__": unittest.main(verbosity=2)
