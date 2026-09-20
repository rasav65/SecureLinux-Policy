#!/usr/bin/env python3
# product-v1 tests for product-sysctl-check-v1 and ADAPTER-REGISTRY.tsv.
import csv, hashlib, importlib.util, json, os, shutil, subprocess, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PATH = ROOT / "product" / "adapters" / "product-sysctl-check-v2.py"
ADAPTER_JSON = ROOT / "product" / "adapters" / "product-sysctl-check-v2.json"
CONTRACT_PATH = ROOT / "product" / "contracts" / "sysctl-check-semantic-v2.json"
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
        self.assertEqual(ADAPTER.ADAPTER_ID, "product-sysctl-check-v2")
        self.assertEqual(ADAPTER.PARAMETER_KIND, "sysctl")
        self.assertEqual(ADAPTER.proc_path("kernel.dmesg_restrict"), "/proc/sys/kernel/dmesg_restrict")
        bad=[("C","/proc/sys","kernel.x","eq",1),("C","sysctl",".kernel.x","eq",1),("C","sysctl","kernel..x","eq",1),("C","sysctl","kernel.x","gt",1),("C","sysctl","kernel.x","eq","1"),("C","sysctl","kernel.x","ge","4096"),("C","sysctl","kernel.x","eq",True),("C;id","sysctl","kernel.x","eq",1)]
        for args in bad:
            with self.assertRaises(ValueError, msg=repr(args)): ADAPTER.shell_function(*args)
    def test_read_only_and_p01_guard(self):
        src=ADAPTER.shell_function("C","sysctl","kernel.x","eq",1)
        self.assertIn('} 2>/dev/null',src)
        od_read='$(LC_ALL=C command /usr/bin/od -An -v -tx1 -- "$_slp_v_path" 2>/dev/null)'
        self.assertEqual(src.count(od_read),1)
        self.assertNotIn("$(",src.replace(od_read,""))
        for token in ADAPTER.MUTATING_TOKENS: self.assertNotIn(token,src,token)
    def test_binding(self):
        contract=json.loads(CONTRACT_PATH.read_text(encoding="utf-8")); meta=json.loads(ADAPTER_JSON.read_text(encoding="utf-8"))
        self.assertEqual(contract["semantic_contract_id"],ADAPTER.SEMANTIC_CONTRACT_ID)
        self.assertEqual(meta["adapter_id"],ADAPTER.ADAPTER_ID); self.assertEqual(meta["parameter_kind"],ADAPTER.PARAMETER_KIND)
        self.assertEqual(meta["semantic_contract_id"],ADAPTER.SEMANTIC_CONTRACT_ID)
        self.assertEqual(meta["implementation_sha256"],sha256_file(ADAPTER_PATH)); self.assertEqual(meta["semantic_contract_sha256"],sha256_file(CONTRACT_PATH)); self.assertEqual(meta["supported_ops"],["eq","ge"])
    def test_registry(self):
        with REGISTRY.open("r",encoding="utf-8",newline="") as f: rows=list(csv.DictReader(f,delimiter="\t"))
        self.assertTrue(rows)
        self.assertEqual(set(rows[0]),{"parameter_kind","adapter_id","semantic_contract_path","semantic_contract_sha256","adapter_contract_path","adapter_contract_sha256","implementation_path","implementation_sha256"})
        self.assertEqual(len({r["parameter_kind"] for r in rows}),len(rows))
        self.assertEqual(len({r["adapter_id"] for r in rows}),len(rows))
        by_kind={r["parameter_kind"]:r for r in rows}
        self.assertIn("sysctl",by_kind)
        self.assertEqual(by_kind["sysctl"]["adapter_id"],ADAPTER.ADAPTER_ID)
        for row in rows:
            for pk,sk in (("semantic_contract_path","semantic_contract_sha256"),("adapter_contract_path","adapter_contract_sha256"),("implementation_path","implementation_sha256")):
                p=ROOT/row[pk]; self.assertTrue(p.is_file(),row[pk]); self.assertEqual(sha256_file(p),row[sk],row[pk])

@unittest.skipIf(BASH is None,"bash not available")
class Runtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.tmp=tempfile.mkdtemp(prefix="slp-product-sysctl-test-")
    @classmethod
    def tearDownClass(cls): shutil.rmtree(cls.tmp,ignore_errors=True)
    def run_patched(self,content_bytes,expected,op="eq",env=None):
        target=Path(self.tmp)/"target"
        if target.exists(): shutil.rmtree(target) if target.is_dir() else target.unlink()
        if content_bytes is None: pass
        elif content_bytes==b"__DIR__": target.mkdir()
        else: target.write_bytes(content_bytes)
        src=ADAPTER.shell_function("CTRL-T","sysctl","slp_test.value",op,expected)
        src=src.replace(repr("/proc/sys/slp_test/value"),repr(str(target)),1)
        run=Path(self.tmp)/"run.sh"; run.write_text("set -u\n"+src+"\nslp_check_CTRL_T\n",encoding="utf-8")
        p=subprocess.run([BASH,str(run)],capture_output=True,text=True,env=env)
        self.assertEqual(p.returncode,0,p.stderr); self.assertEqual(p.stderr,"")
        fields=p.stdout.rstrip("\n").split("\t"); self.assertEqual(len(fields),5,p.stdout); self.assertEqual(fields[:2],[ADAPTER.WIRE_RECORD_ID,"CTRL-T"])
        return tuple(fields[2:])
    def test_value_pass(self): self.assertEqual(self.run_patched(b"001\n",1),("VALUE","1","PASS"))
    def test_value_fail(self): self.assertEqual(self.run_patched(b"+0002\n",1),("VALUE","2","FAIL"))
    def test_ge_equal(self): self.assertEqual(self.run_patched(b"4096\n",4096,"ge"),("VALUE","4096","PASS"))
    def test_ge_greater(self): self.assertEqual(self.run_patched(b"65536\n",4096,"ge"),("VALUE","65536","PASS"))
    def test_ge_less(self): self.assertEqual(self.run_patched(b"4095\n",4096,"ge"),("VALUE","4095","FAIL"))
    def test_ge_negative_boundaries(self):
        self.assertEqual(self.run_patched(b"-2\n",-3,"ge"),("VALUE","-2","PASS"))
        self.assertEqual(self.run_patched(b"-4\n",-3,"ge"),("VALUE","-4","FAIL"))
    def test_ge_unbounded_decimal(self):
        huge=10**200
        self.assertEqual(self.run_patched((str(huge)+"\n").encode(),10**199,"ge"),("VALUE",str(huge),"PASS"))
    def test_negative_value(self): self.assertEqual(self.run_patched(b" -0003 \n",-3),("VALUE","-3","PASS"))
    def test_contract_allowed_cr_edge_whitespace(self): self.assertEqual(self.run_patched(b" 1\r\n",1),("VALUE","1","PASS"))
    def test_ascii_edge_whitespace_is_locale_independent(self):
        env=os.environ.copy(); env["LC_ALL"]="C.utf8"
        self.assertEqual(self.run_patched(b" \t\v\f+001\r\n",1,env=env),("VALUE","1","PASS"))
        for edge in ("\u2003","\u3000"):
            with self.subTest(edge=repr(edge)):
                self.assertEqual(self.run_patched((edge+"1"+edge+"\n").encode("utf-8"),1,env=env),("ERROR","sysctl:invalid-value","ERROR"))
    def test_negative_zero_normalizes(self): self.assertEqual(self.run_patched(b"-000\n",0),("VALUE","0","PASS"))
    def test_not_found(self): self.assertEqual(self.run_patched(None,1),("NOT_FOUND","-","NOT_FOUND"))
    def test_non_integer_is_error(self): self.assertEqual(self.run_patched(b"1 2\n",1),("ERROR","sysctl:invalid-value","ERROR"))
    def test_nul_is_rejected_before_read(self): self.assertEqual(self.run_patched(b"1\x00\n",1),("ERROR","sysctl:invalid-bytes","ERROR"))
    def test_read_error_has_no_stderr(self): self.assertEqual(self.run_patched(b"__DIR__",1),("ERROR","sysctl:read-failed","ERROR"))

@unittest.skipIf(BASH is None,"bash not available")
class UnprovenAbsence(unittest.TestCase):
    """Недоступность предка не равна отсутствию (решение человека).

    NOT_FOUND допустим только при доказанном отсутствии: родитель существует,
    является каталогом, доступен для поиска, а lstat имени даёт ENOENT — так уже
    сделано в `product-file-mode-owner-check-v2`. Иначе — ERROR с причиной
    контракта, иначе закрытый каталог /proc/sys выглядел бы как отсутствие
    параметра.
    """
    def setUp(self):
        self.tmp=Path(tempfile.mkdtemp(prefix="slp-sysctl-absence-")); os.chmod(self.tmp,0o755)
        self.closed=self.tmp/"closed"; self.closed.mkdir()
        self.visible=self.tmp/"visible"; self.visible.mkdir(); os.chmod(self.visible,0o755)
    def tearDown(self):
        try: os.chmod(self.closed,0o700)
        except OSError: pass
        shutil.rmtree(self.tmp,ignore_errors=True)
    def user_kwargs(self):
        return {"user":65534,"group":65534,"extra_groups":[]} if os.geteuid()==0 else {}
    def owned(self,path):
        if os.geteuid()==0: os.chown(path,65534,65534)
        return path
    def run_target(self,target):
        src=ADAPTER.shell_function("CTRL-T","sysctl","slp_test.value","eq",1)
        src=src.replace(repr("/proc/sys/slp_test/value"),repr(str(target)),1)
        run=self.visible/"run.sh"; run.write_text("set -u\n"+src+"\nslp_check_CTRL_T\n",encoding="utf-8")
        self.owned(run)
        p=subprocess.run([BASH,str(run)],capture_output=True,text=True,**self.user_kwargs())
        self.assertEqual(p.returncode,0,p.stderr); self.assertEqual(p.stderr,"")
        fields=p.stdout.rstrip("\n").split("\t"); self.assertEqual(len(fields),5,p.stdout)
        return tuple(fields[2:])
    def seal(self,inner):
        """Закрывает каталог и доказывает, что объект внутри действительно недоступен."""
        os.chmod(self.closed,0o000)
        probe=('if [[ -x "$1" ]]; then printf searchable; fi\n'
               'if [[ -e "$2" || -L "$2" ]]; then printf visible; fi\n'
               'if cat -- "$2" >/dev/null 2>&1; then printf readable; fi\n'
               'printf done\n')
        cp=subprocess.run([BASH,"-c",probe,"probe",str(self.closed),str(inner)],
                          capture_output=True,text=True,**self.user_kwargs())
        self.assertEqual(cp.stdout,"done","предок доступен, случай не воспроизведён: "+cp.stdout)
    def test_unreachable_parameter_is_error(self):
        target=self.closed/"value"; target.write_text("1\n",encoding="utf-8"); self.owned(target)
        self.seal(target)
        self.assertEqual(self.run_target(target),("ERROR","sysctl:read-failed","ERROR"))
    def test_absent_parameter_in_searchable_parent_stays_not_found(self):
        self.assertEqual(self.run_target(self.visible/"absent-value"),("NOT_FOUND","-","NOT_FOUND"))

if __name__=="__main__": unittest.main(verbosity=2)
