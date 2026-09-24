#!/usr/bin/env python3
"""Regressions for the kernel-cmdline-grub-v1 APPLY mechanism (2.4.3-2.4.7, 2.5.1, 2.5.3, 2.5.9).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on a tree inside a temporary directory passed to the adapter as
`_root`; `update-grub` is replaced by `_run`, which rebuilds `boot/grub/grub.cfg`
from the same shell sourcing grub-mkconfig does. No system path is touched and
root is not required.

Решения человека 24.09.2026, которые фиксирует этот файл:

* файл `/etc/default/grub.d/zz-securelinux-policy.cfg`, `GRUB_CMDLINE_LINUX`, затем
  `update-grub`; вступает в силу после перезагрузки (исход `APPLIED`, затем
  `PENDING_REBOOT` до перезагрузки);
* автоматически — `init_on_alloc=1`, `slab_nomerge`, `randomize_kstack_offset=1`,
  `vsyscall=none`; `mitigations`, три `iommu`, `tsx`, `debugfs` — блок
  «требуется решение администратора» (`BOOT_PARAMETER_ADMIN_DECISION`), без записи;
* другое значение того же параметра у администратора — отказ без записи.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "product/apply-adapters/product-kernel-cmdline-grub-apply-v1.py"
CONTROLS = ROOT / "controls/fstec-core/linux-2022"


def load():
    spec = importlib.util.spec_from_file_location("slp_kernel_cmdline_grub_apply", ADAPTER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = load()


def control_rows():
    """(control_id, key, op, expected) из control-yaml всех kernel-cmdline контролей."""
    rows = {}
    for path in sorted(CONTROLS.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if 'kind: "kernel-cmdline"' not in text:
            continue
        cid = re.search(r'^id: "([^"]+)"', text, re.M).group(1)
        key = re.search(r'^  key: "([^"]+)"', text, re.M).group(1)
        op = re.search(r'^  op: "([^"]+)"', text, re.M).group(1)
        raw = re.search(r'^  value: (.+)$', text, re.M).group(1).strip()
        value = True if raw == "true" else raw.strip('"')
        supported = re.search(r'^apply:\n  supported: (true|false)', text, re.M).group(1) == "true"
        rows[cid] = (key, op, value, supported)
    return rows


class Tree:
    def __init__(self, td, cmdline="BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro", grub_linux="", grub_default="quiet",
                 extra_cfg=None):
        self.root = Path(td)
        (self.root / "proc").mkdir()
        (self.root / "proc/cmdline").write_text(cmdline + "\n", encoding="ascii")
        # Права задаются явно: адаптер отказывает при записи для группы, а umask на ПК часто 0002.
        (self.root / "etc/default/grub.d").mkdir(parents=True)
        (self.root / "etc/default/grub.d").chmod(0o755)
        (self.root / "etc/default/grub").write_text(
            f'GRUB_DEFAULT=0\nGRUB_CMDLINE_LINUX_DEFAULT="{grub_default}"\nGRUB_CMDLINE_LINUX="{grub_linux}"\n',
            encoding="ascii")
        for name, body in (extra_cfg or {}).items():
            (self.root / "etc/default/grub.d" / name).write_text(body, encoding="ascii")
            (self.root / "etc/default/grub.d" / name).chmod(0o644)
        (self.root / "usr/sbin").mkdir(parents=True)
        tool = self.root / "usr/sbin/update-grub"
        tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        tool.chmod(0o755)
        (self.root / "boot/grub").mkdir(parents=True)
        self.update_calls = 0
        self.fail_update = 0
        self.run(["update-grub-initial"], 0)

    def run(self, argv, timeout):
        if argv[0] == "/bin/sh":
            return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=timeout)
        if argv[0] != "update-grub-initial":
            self.update_calls += 1
            if self.fail_update:
                self.fail_update -= 1
                return subprocess.CompletedProcess(argv, 1, b"", b"")
        script = ('. "$1"; for f in "$2"/*.cfg; do [ -e "$f" ] && . "$f"; done; '
                  'printf "%s\\n%s\\n" "$GRUB_CMDLINE_LINUX" "$GRUB_CMDLINE_LINUX_DEFAULT"')
        cp = subprocess.run(["/bin/sh", "-c", script, "sh", str(self.root / "etc/default/grub"),
                             str(self.root / "etc/default/grub.d")], stdout=subprocess.PIPE, check=True)
        linux, default = (cp.stdout.decode().split("\n") + ["", ""])[:2]
        (self.root / "boot/grub/grub.cfg").write_text(
            f"menuentry 'Linux' {{\n\tlinux /vmlinuz root=/dev/sda1 ro {linux} {default}\n}}\n"
            f"menuentry 'Linux (recovery mode)' {{\n\tlinux /vmlinuz root=/dev/sda1 ro single {linux}\n}}\n"
            "menuentry 'Memory test' {\n\tlinux /boot/memtest86+x64.efi\n}\n",
            encoding="ascii")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def dropin(self):
        path = self.root / "etc/default/grub.d/zz-securelinux-policy.cfg"
        return path.read_text(encoding="ascii") if path.exists() else None

    def reboot(self):
        grub = (self.root / "boot/grub/grub.cfg").read_text(encoding="ascii")
        line = re.search(r"^\tlinux (.*)$", grub, re.M).group(1)
        (self.root / "proc/cmdline").write_text("BOOT_IMAGE=" + " ".join(line.split()) + "\n", encoding="ascii")


def execute(tree, cid, dry_run=False):
    key, op, value, _supported = control_rows()[cid]
    return A.execute_control(cid, key, op, value, True, dry_run=dry_run, privilege_check=lambda: True,
                             _root=str(tree.root), _run=tree.run)


INIT = "FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC"
SLAB = "FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE"
TSX = "FSTEC-LINUX-2022-2.5.9-TSX"


class ContractParity(unittest.TestCase):
    def test_every_kernel_cmdline_control_is_routed(self):
        rows = control_rows()
        self.assertEqual(len(rows), 10)
        self.assertEqual(set(rows), set(A.AUTO) | set(A.ADMIN))
        self.assertFalse(set(A.AUTO) & set(A.ADMIN))
        for cid, (key, op, value, supported) in rows.items():
            spec = A.AUTO.get(cid) or A.ADMIN[cid][0]
            self.assertEqual(spec, (key, op, value), cid)
            self.assertTrue(supported, cid)

    def test_auto_set_is_the_decision(self):
        tokens = sorted(A.desired_token(*spec) for spec in A.AUTO.values())
        self.assertEqual(tokens, ["init_on_alloc=1", "randomize_kstack_offset=1", "slab_nomerge", "vsyscall=none"])

    def test_evaluate_follows_check_semantics(self):
        self.assertEqual(A.evaluate(["a=1"], "a", "eq", "1"), (True, "1"))
        self.assertEqual(A.evaluate(["a=1", "a=1"], "a", "eq", "1"), (True, "1"))
        self.assertEqual(A.evaluate(["a=1", "a=2"], "a", "eq", "1"), (False, "conflict"))
        self.assertEqual(A.evaluate(["a", "a=1"], "a", "eq", "1"), (False, "conflict"))
        self.assertEqual(A.evaluate([], "a", "eq", "1"), (False, "<absent>"))
        self.assertEqual(A.evaluate(["s"], "s", "present", True), (True, "true"))
        self.assertEqual(A.evaluate(["s=1"], "s", "present", True), (False, "conflict"))
        self.assertEqual(A.evaluate(["d=no-mount"], "d", "one-of", "off|no-mount"), (True, "no-mount"))


class AutoApply(unittest.TestCase):
    def test_applies_then_pending_then_compliant(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            r = execute(t, INIT)
            self.assertEqual((r["outcome"], r["reboot_required"], r["mutation_performed"]), ("APPLIED", True, True))
            self.assertIn('GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX init_on_alloc=1"', t.dropin())
            self.assertEqual(A.outcome_rc_contribution(r["outcome"]), "0")
            r = execute(t, INIT)
            self.assertEqual(r["outcome"], "PENDING_REBOOT")
            self.assertEqual(t.update_calls, 1)
            t.reboot()
            r = execute(t, INIT)
            self.assertEqual((r["outcome"], r["cmdline_current"]), ("ALREADY_COMPLIANT", "1"))

    def test_second_parameter_keeps_first_and_file_is_sorted(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            execute(t, SLAB)
            execute(t, INIT)
            self.assertIn('"$GRUB_CMDLINE_LINUX init_on_alloc=1 slab_nomerge"', t.dropin())
            grub = (t.root / "boot/grub/grub.cfg").read_text()
            for line in re.findall(r"^\tlinux /vmlinuz.*$", grub, re.M):
                self.assertIn(" init_on_alloc=1", line)
                self.assertIn(" slab_nomerge", line)

    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            r = execute(t, INIT, dry_run=True)
            self.assertEqual(r["outcome"], "DRY_RUN_WOULD_APPLY")
            self.assertIsNone(t.dropin())
            self.assertEqual(t.update_calls, 0)

    def test_same_token_from_admin_is_not_duplicated(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, grub_linux="init_on_alloc=1")
            t.run(["update-grub-initial"], 0)
            r = execute(t, INIT)
            self.assertEqual(r["outcome"], "PENDING_REBOOT")
            self.assertIsNone(t.dropin())

    def test_foreign_conflicting_value_is_refused_without_write(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, extra_cfg={"50-admin.cfg": 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX init_on_alloc=0"\n'})
            r = execute(t, INIT)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "grub:foreign-conflict"))
            self.assertIsNone(t.dropin())
            self.assertEqual(t.update_calls, 0)

    def test_foreign_content_in_dropin_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            (t.root / "etc/default/grub.d/zz-securelinux-policy.cfg").write_text("GRUB_TIMEOUT=1\n")
            (t.root / "etc/default/grub.d/zz-securelinux-policy.cfg").chmod(0o644)
            r = execute(t, INIT)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "dropin:foreign-content"))

    def test_update_grub_failure_restores_previous_state(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            execute(t, SLAB)
            before = t.dropin()
            t.fail_update = 1
            r = execute(t, INIT)
            self.assertEqual(r["outcome"], "FAILED_NOT_COMMITTED")
            self.assertEqual(t.dropin(), before)
            self.assertEqual(A.outcome_rc_contribution(r["outcome"]), "nonzero")

    def test_update_grub_failure_on_new_file_removes_it(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.fail_update = 2
            r = execute(t, INIT)
            self.assertEqual(r["outcome"], "FAILED_COMPENSATION")
            self.assertIsNone(t.dropin())

    def test_missing_update_grub_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            (t.root / "usr/sbin/update-grub").chmod(0o644)
            r = execute(t, INIT)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "grub:update-grub-missing"))
            (t.root / "usr/sbin/update-grub").unlink()
            r = execute(t, INIT)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "grub:update-grub-missing"))
            self.assertIsNone(t.dropin())

    def test_zz_name_is_read_after_reference_dropins(self):
        # 22.04 / Debian 12: init-select.cfg, 26.04: kdump-tools.cfg (проба GRUB 24.09.2026).
        names = sorted(["init-select.cfg", "kdump-tools.cfg", os.path.basename(A.DROPIN)])
        self.assertEqual(names[-1], "zz-securelinux-policy.cfg")


class AdminDecision(unittest.TestCase):
    def test_risky_parameter_is_blocked_with_decision(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            r = execute(t, TSX)
            self.assertEqual(r["outcome"], "ABORTED_PRECONDITION_CONFLICT")
            self.assertEqual(r["operator_decision"]["class"], "BOOT_PARAMETER_ADMIN_DECISION")
            self.assertEqual(r["operator_decision"]["value"], "tsx=off")
            self.assertIsNone(t.dropin())
            self.assertEqual(t.update_calls, 0)
            self.assertEqual(A.outcome_rc_contribution(r["outcome"]), "nonzero")

    def test_risky_parameter_set_by_admin_is_compliant(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, cmdline="BOOT_IMAGE=/vmlinuz ro tsx=off")
            r = execute(t, TSX)
            self.assertEqual(r["outcome"], "ALREADY_COMPLIANT")

    def test_report_carries_decision(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            rep = A.control_result_to_report(execute(t, TSX), "s", "f")
            self.assertEqual(rep["operator_decision"]["parameter"], "tsx")
            self.assertEqual(rep["step_rc"], "nonzero")
            self.assertFalse(rep["mutation_performed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
