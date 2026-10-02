#!/usr/bin/env python3
import errno
import importlib.util
import os
import socket
import stat
import tempfile
import unittest
import sys
import json
import base64
from unittest import mock
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PATH = ROOT / "product" / "apply-adapters" / "product-config-line-runtime-apply-v1.py"


def load_adapter():
    spec = importlib.util.spec_from_file_location("slp_config_line_runtime_apply", ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


A = load_adapter()


class ValidationAndInteger(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(A.MECHANISM_ID, "config-line-with-runtime-v1")
        self.assertEqual(A.PARAMETER_KIND, "sysctl")
        self.assertEqual(A.SUPPORTED_OPS, ("eq", "ge"))

    def test_paths(self):
        self.assertEqual(A.proc_path("kernel.dmesg_restrict"), "/proc/sys/kernel/dmesg_restrict")
        self.assertEqual(A.persistent_path("vm.mmap_min_addr"), "/etc/sysctl.d/zz-securelinux-policy-vm-mmap_min_addr.conf")

    def test_validation(self):
        A.validate_control_input("CTRL-1", "vm.mmap_min_addr", "ge", 4096, True)
        bad = [
            ("CTRL 1", "vm.mmap_min_addr", "ge", 4096, True),
            ("CTRL-1", ".vm.mmap_min_addr", "ge", 4096, True),
            ("CTRL-1", "vm..mmap_min_addr", "ge", 4096, True),
            ("CTRL-1", "vm.mmap_min_addr", "gt", 4096, True),
            ("CTRL-1", "vm.mmap_min_addr", "ge", "4096", True),
            ("CTRL-1", "vm.mmap_min_addr", "ge", True, True),
            ("CTRL-1", "vm.mmap_min_addr", "ge", 4096, 1),
        ]
        for args in bad:
            with self.assertRaises(A.ContractError, msg=repr(args)):
                A.validate_control_input(*args)

    def test_integer_semantics_match_check(self):
        cases = {
            b"001\n": 1,
            b"+0002\n": 2,
            b" -0003 \n": -3,
            b" 1\r\n": 1,
            b"\t+0000000000000000000000004096\v": 4096,
            b"-000\n": 0,
        }
        for raw, expected in cases.items():
            self.assertEqual(A.parse_integer_bytes(raw), expected, raw)
        for raw in (b"1 2\n", b"1\x00\n", b"", b"+\n", b"1\n2\n"):
            with self.assertRaises(A.ContractError, msg=repr(raw)):
                A.parse_integer_bytes(raw)


class EligibilityAndPlanning(unittest.TestCase):
    def test_eligibility(self):
        self.assertIsNone(A.eligibility_outcome(True))
        self.assertEqual(A.eligibility_outcome(False), "NOT_ELIGIBLE_APPLY_UNSUPPORTED")

    def test_target_eq(self):
        self.assertEqual(A.compute_target_value("eq", 1, 99, 100, 101), 1)

    def test_target_ge_preserves_maximum(self):
        self.assertEqual(A.compute_target_value("ge", 4096, 8192, 16384, 32768), 32768)
        self.assertEqual(A.compute_target_value("ge", 4096, 65536, None, None), 65536)

    def test_runtime_compliance(self):
        self.assertTrue(A.runtime_is_compliant("eq", 1, 1))
        self.assertFalse(A.runtime_is_compliant("eq", 2, 1))
        self.assertTrue(A.runtime_is_compliant("ge", 8192, 4096))
        self.assertFalse(A.runtime_is_compliant("ge", 4095, 4096))

    def test_canonical_persistent_bytes(self):
        self.assertEqual(
            A.canonical_persistent_bytes("vm.mmap_min_addr", 4096),
            b"# Managed by SecureLinux-Policy\nvm.mmap_min_addr = 4096\n",
        )

    def test_persistent_compliance_includes_metadata(self):
        raw = A.canonical_persistent_bytes("vm.mmap_min_addr", 4096)
        self.assertTrue(A.persistent_is_compliant("vm.mmap_min_addr", 4096, raw, 0, 0, 0o644))
        self.assertFalse(A.persistent_is_compliant("vm.mmap_min_addr", 4096, raw, 0, 0, 0o600))
        self.assertFalse(A.persistent_is_compliant("vm.mmap_min_addr", 4096, raw + b"#x\n", 0, 0, 0o644))

    def test_all_branches(self):
        self.assertEqual(A.select_branch(True, True), A.BRANCH_ALREADY)
        self.assertEqual(A.select_branch(True, False), A.BRANCH_PERSISTENT_ONLY)
        self.assertEqual(A.select_branch(False, True), A.BRANCH_RUNTIME_ONLY)
        self.assertEqual(A.select_branch(False, False), A.BRANCH_BOTH)

    def test_plan_ge_own_persistent_ratchet(self):
        raw = A.canonical_persistent_bytes("vm.mmap_min_addr", 16384)
        plan = A.build_plan("vm.mmap_min_addr", "ge", 4096, 8192, raw, 0, 0, 0o644, 16384, None)
        self.assertEqual(plan.target_value, 16384)
        self.assertFalse(plan.runtime_compliant)
        self.assertTrue(plan.persistent_compliant)
        self.assertEqual(plan.branch, A.BRANCH_RUNTIME_ONLY)


class SourceNormalizationAndPrecedence(unittest.TestCase):
    def sf(self, path, *rows):
        assignments = tuple(A.ExplicitAssignment(key, value, i + 1) for i, (key, value) in enumerate(rows))
        return A.SourceFile(path, assignments)

    def test_source_key_normalization(self):
        self.assertEqual(A.normalize_source_key("vm.mmap_min_addr"), "vm/mmap_min_addr")
        self.assertEqual(A.normalize_source_key("vm/mmap_min_addr"), "vm/mmap_min_addr")
        self.assertEqual(A.normalize_source_key("-vm.mmap_min_addr"), "-vm/mmap_min_addr")
        # Slash-first form retains later dots as literal component characters.
        self.assertEqual(A.normalize_source_key("net/ipv4/conf/enp3s0.200/forwarding"), "net/ipv4/conf/enp3s0.200/forwarding")

    def test_last_effective_prior_assignment(self):
        files = [
            self.sf("/usr/lib/sysctl.d/40-vendor.conf", ("vm.mmap_min_addr", "8192")),
            self.sf("/etc/sysctl.d/60-local.conf", ("vm.mmap_min_addr", "16384")),
        ]
        r = A.resolve_precedence("vm.mmap_min_addr", files)
        self.assertEqual(r.effective_foreign_value, 16384)
        self.assertEqual(r.effective_foreign_source, "/etc/sysctl.d/60-local.conf")

    def test_same_basename_shadowing(self):
        files = [
            self.sf("/usr/lib/sysctl.d/50-vendor.conf", ("vm.mmap_min_addr", "32768")),
            self.sf("/etc/sysctl.d/50-vendor.conf"),
            self.sf("/run/sysctl.d/60-run.conf", ("vm.mmap_min_addr", "8192")),
        ]
        r = A.resolve_precedence("vm.mmap_min_addr", files)
        self.assertEqual(r.effective_foreign_value, 8192)
        self.assertIn("/usr/lib/sysctl.d/50-vendor.conf", r.shadowed_sources)

    def test_absent_own_file_does_not_shadow_lower_same_basename(self):
        own = A.persistent_path("vm.mmap_min_addr")
        basename = Path(own).name
        files = [self.sf("/usr/lib/sysctl.d/" + basename, ("vm.mmap_min_addr", "99999"))]
        r = A.resolve_precedence("vm.mmap_min_addr", files)
        self.assertEqual(r.effective_foreign_value, 99999)
        self.assertNotIn("/usr/lib/sysctl.d/" + basename, r.shadowed_sources)

    def test_own_file_is_not_foreign(self):
        own = A.persistent_path("vm.mmap_min_addr")
        r = A.resolve_precedence("vm.mmap_min_addr", [self.sf(own, ("vm.mmap_min_addr", "16384"))])
        self.assertIsNone(r.effective_foreign_value)

    def test_late_filename_is_conflict_even_if_stricter(self):
        own_base = Path(A.persistent_path("vm.mmap_min_addr")).name
        later = "/etc/sysctl.d/zzzz-after.conf"
        self.assertGreater(Path(later).name, own_base)
        with self.assertRaises(A.PreconditionError) as cm:
            A.resolve_precedence("vm.mmap_min_addr", [self.sf(later, ("vm.mmap_min_addr", "65536"))])
        self.assertEqual(cm.exception.code, "source:late-conflict")

    def test_sysctl_conf_is_always_late_conflict(self):
        with self.assertRaises(A.PreconditionError) as cm:
            A.resolve_precedence("vm.mmap_min_addr", [self.sf("/etc/sysctl.conf", ("vm.mmap_min_addr", "65536"))])
        self.assertEqual(cm.exception.code, "source:late-conflict")

    def test_invalid_effective_foreign_integer_aborts(self):
        with self.assertRaises(A.PreconditionError) as cm:
            A.resolve_precedence("vm.mmap_min_addr", [self.sf("/etc/sysctl.d/50-local.conf", ("vm.mmap_min_addr", "not-an-int"))])
        self.assertEqual(cm.exception.code, "source:invalid-integer")

    def test_unrelated_assignment_is_ignored(self):
        r = A.resolve_precedence("vm.mmap_min_addr", [self.sf("/etc/sysctl.d/50-local.conf", ("kernel.dmesg_restrict", "1"))])
        self.assertIsNone(r.effective_foreign_value)


class SourceParserAndLoader(unittest.TestCase):
    KEY = "kernel.dmesg_restrict"

    def test_explicit_assignment_plain(self):
        a = A.parse_sysctl_assignment_line("kernel.dmesg_restrict = 1", 7)
        self.assertEqual(a, A.ExplicitAssignment(self.KEY, "1", 7))

    def test_explicit_assignment_ignore_error_has_same_precedence_shape(self):
        a = A.parse_sysctl_assignment_line("-kernel.dmesg_restrict = 1", 3)
        self.assertEqual(a, A.ExplicitAssignment(self.KEY, "1", 3))
        self.assertFalse(hasattr(a, "ignore_error"))

    def test_bare_minus_key_is_not_assignment(self):
        self.assertIsNone(A.parse_sysctl_assignment_line("-kernel.dmesg_restrict", 1))

    def test_glob_assignment_is_excluded_from_proved_parser(self):
        self.assertIsNone(A.parse_sysctl_assignment_line("net.ipv4.conf.*.rp_filter = 1", 1))

    def test_normalize_does_not_strip_minus_syntax(self):
        self.assertEqual(A.normalize_source_key("-kernel.dmesg_restrict"), "-kernel/dmesg_restrict")

    def test_filename_order_uses_utf8_bytes_for_sort_and_late_compare(self):
        own = A.persistent_path(self.KEY)
        own_name = PurePosixPath(own).name
        early = A.SourceFile("/usr/lib/sysctl.d/10-base.conf", (A.ExplicitAssignment(self.KEY, "1", 1),))
        late_name = own_name[:-5] + "~.conf"
        late = A.SourceFile("/usr/lib/sysctl.d/" + late_name, (A.ExplicitAssignment(self.KEY, "2", 1),))
        self.assertGreater(late_name.encode("utf-8"), own_name.encode("utf-8"))
        with self.assertRaises(A.PreconditionError) as ctx:
            A.resolve_precedence(self.KEY, (late, early))
        self.assertEqual(ctx.exception.code, "source:late-conflict")

    def _mkroot(self):
        td = tempfile.TemporaryDirectory()
        root = Path(td.name)
        for d in A.SYSCTL_D_DIRS:
            (root / d.lstrip("/")).mkdir(parents=True, exist_ok=True)
        (root / "etc").mkdir(parents=True, exist_ok=True)
        return td, root

    def test_loader_missing_standard_directory_is_empty_not_abort(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "etc/sysctl.d").mkdir(parents=True)
            src = A.load_sysctl_sources(self.KEY, root)
            self.assertEqual(src, ())

    def test_loader_shadowing_reads_only_high_priority_winner(self):
        td, root = self._mkroot()
        with td:
            high = root / "etc/sysctl.d/20-x.conf"
            low = root / "usr/lib/sysctl.d/20-x.conf"
            high.write_text("kernel.dmesg_restrict = 1\n", encoding="utf-8")
            low.write_bytes(b"\xff=\xff\n")  # hidden bytes must not be parsed/read for semantics
            src = A.load_sysctl_sources(self.KEY, root)
            p = A.resolve_precedence(self.KEY, src)
            self.assertEqual(p.effective_foreign_value, 1)
            self.assertIn("/usr/lib/sysctl.d/20-x.conf", p.shadowed_sources)

    def test_loader_absent_own_file_does_not_shadow_lower_same_basename(self):
        td, root = self._mkroot()
        with td:
            own_name = PurePosixPath(A.persistent_path(self.KEY)).name
            low = root / "usr/lib/sysctl.d" / own_name
            low.write_text("kernel.dmesg_restrict = 99\n", encoding="utf-8")
            src = A.load_sysctl_sources(self.KEY, root)
            p = A.resolve_precedence(self.KEY, src)
            self.assertEqual(p.effective_foreign_value, 99)
            self.assertNotIn("/usr/lib/sysctl.d/" + own_name, p.shadowed_sources)

    def test_loader_dev_null_symlink_is_empty_source(self):
        td, root = self._mkroot()
        with td:
            path = root / "etc/sysctl.d/20-null.conf"
            path.symlink_to("/dev/null")
            src = A.load_sysctl_sources(self.KEY, root)
            item = next(s for s in src if s.path == "/etc/sysctl.d/20-null.conf")
            self.assertEqual(item.assignments, ())

    def test_loader_sysctl_conf_matching_assignment_is_late_conflict(self):
        td, root = self._mkroot()
        with td:
            (root / "etc/sysctl.conf").write_text("kernel.dmesg_restrict = 1\n", encoding="utf-8")
            src = A.load_sysctl_sources(self.KEY, root)
            with self.assertRaises(A.PreconditionError) as ctx:
                A.resolve_precedence(self.KEY, src)
            self.assertEqual(ctx.exception.code, "source:late-conflict")

    def test_loader_sysctl_conf_stat_error_is_fail_closed(self):
        td, root = self._mkroot()
        with td:
            conf = root / "etc/sysctl.conf"
            conf.write_text("kernel.dmesg_restrict = 1\n", encoding="utf-8")
            real_lstat = A.os.lstat
            def fail_conf(path, *args, **kwargs):
                if os.fspath(path) == os.fspath(conf):
                    raise PermissionError("injected")
                return real_lstat(path, *args, **kwargs)
            with mock.patch.object(A.os, "lstat", side_effect=fail_conf):
                with self.assertRaises(A.PreconditionError) as cm:
                    A.load_sysctl_sources(self.KEY, root)
            self.assertEqual(cm.exception.code, "source:unreadable-source")
            self.assertEqual(cm.exception.source, A.SYSCTL_CONF)

    def test_loader_parser_keeps_minus_equals_but_drops_bare_minus(self):
        td, root = self._mkroot()
        with td:
            p = root / "usr/lib/sysctl.d/20-x.conf"
            p.write_text("-kernel.dmesg_restrict\n-kernel.dmesg_restrict = 2\n", encoding="utf-8")
            src = A.load_sysctl_sources(self.KEY, root)
            sf = next(s for s in src if s.path == "/usr/lib/sysctl.d/20-x.conf")
            self.assertEqual(sf.assignments, (A.ExplicitAssignment(self.KEY, "2", 2),))

    def test_execute_control_default_loader_is_used_at_p2(self):
        td, root = self._mkroot()
        with td:
            (root / "usr/lib/sysctl.d/20-x.conf").write_text("kernel.dmesg_restrict = 2\n", encoding="utf-8")
            persistent = root / "target.conf"
            runtime = {"value": 1}
            r = A.execute_control(
                "CTRL-1", self.KEY, "ge", 1, True,
                source_files=None, source_root=root, dry_run=True,
                persistent_target=str(persistent), runtime_target="/fake/runtime",
                read_runtime=lambda: runtime["value"], write_runtime=lambda v: None,
                write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                privilege_check=lambda: None,
            )
            self.assertEqual(r.outcome, A.OUTCOME_DRY_RUN_WOULD_APPLY)
            self.assertEqual(r.effective_foreign_value, 2)
            self.assertEqual(r.target_value, 2)


class SafetyBoundary(unittest.TestCase):
    def test_selftest_does_not_call_mutation_io(self):
        with mock.patch.object(A, "apply_persistent_change") as persistent, mock.patch.object(A, "write_runtime_path") as runtime:
            A._selftest()
        persistent.assert_not_called()
        runtime.assert_not_called()


class PersistentTransactionIO(unittest.TestCase):
    def owner(self):
        return os.getuid(), os.getgid()

    def target(self, td):
        return str(Path(td) / "zz-securelinux-policy-vm-mmap_min_addr.conf")

    def desired(self, value=4096):
        return A.canonical_persistent_bytes("vm.mmap_min_addr", value)

    def test_snapshot_absent(self):
        with tempfile.TemporaryDirectory() as td:
            snap = A.snapshot_persistent_target(self.target(td))
            self.assertFalse(snap.exists)

    def test_snapshot_existing_identity_and_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            target.write_bytes(b"old\n")
            target.chmod(0o600)
            snap = A.snapshot_persistent_target(str(target))
            st = target.stat()
            self.assertTrue(snap.exists)
            self.assertEqual((snap.st_dev, snap.st_ino), (st.st_dev, st.st_ino))
            self.assertEqual(snap.file_type, stat.S_IFREG)
            self.assertEqual(snap.st_nlink, 1)
            self.assertEqual(snap.mode, 0o600)
            self.assertEqual(snap.raw_bytes, b"old\n")

    def test_snapshot_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / "real"
            real.write_bytes(b"x")
            target = Path(self.target(td))
            target.symlink_to(real.name)
            with self.assertRaises(A.PreconditionError) as cm:
                A.snapshot_persistent_target(str(target))
            self.assertEqual(cm.exception.code, "persistent:forbidden-object")

    def test_snapshot_rejects_hardlink(self):
        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / "real"
            real.write_bytes(b"x")
            target = Path(self.target(td))
            os.link(real, target)
            with self.assertRaises(A.PreconditionError) as cm:
                A.snapshot_persistent_target(str(target))
            self.assertEqual(cm.exception.code, "persistent:forbidden-object")

    def test_snapshot_rejects_directory_and_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            target.mkdir()
            with self.assertRaises(A.PreconditionError):
                A.snapshot_persistent_target(str(target))
            target.rmdir()
            os.mkfifo(target)
            with self.assertRaises(A.PreconditionError):
                A.snapshot_persistent_target(str(target))

    def test_atomic_create_records_attempt_identity(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = self.target(td)
            state = A.apply_persistent_change(target, self.desired(), uid, gid, 0o644)
            self.assertFalse(state.prestate.exists)
            self.assertTrue(state.attempt_written_identity.exists)
            now = A.snapshot_persistent_target(target)
            self.assertEqual(now, state.attempt_written_identity)
            self.assertEqual(now.raw_bytes, self.desired())
            self.assertEqual(now.mode, 0o644)

    def test_compensation_removes_new_file(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = self.target(td)
            state = A.apply_persistent_change(target, self.desired(), uid, gid, 0o644)
            A.compensate_persistent(state)
            self.assertFalse(Path(target).exists())

    def test_compensation_restores_existing_bytes_and_mode(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            target.write_bytes(b"old bytes\n")
            target.chmod(0o600)
            before = A.snapshot_persistent_target(str(target))
            state = A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            self.assertNotEqual(A.snapshot_persistent_target(str(target)).raw_bytes, before.raw_bytes)
            A.compensate_persistent(state)
            after = A.snapshot_persistent_target(str(target))
            self.assertEqual(after.raw_bytes, before.raw_bytes)
            self.assertEqual(after.uid, before.uid)
            self.assertEqual(after.gid, before.gid)
            self.assertEqual(after.mode, before.mode)

    def test_drift_before_rename_aborts_and_preserves_external_change(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            target.write_bytes(b"old\n")
            orig = A._revalidate_prestate

            def drift(dir_fd, target_name, prestate):
                target.write_bytes(b"external\n")
                return orig(dir_fd, target_name, prestate)

            with mock.patch.object(A, "_revalidate_prestate", side_effect=drift):
                with self.assertRaises(A.PreconditionError) as cm:
                    A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            self.assertEqual(cm.exception.code, "persistent:drift-before-rename")
            self.assertEqual(target.read_bytes(), b"external\n")
            self.assertEqual(list(Path(td).glob(".*.tmp.*")), [])

    def test_directory_fsync_failure_after_rename_compensates(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            target.write_bytes(b"old\n")
            target.chmod(0o600)
            calls = {"n": 0}
            real = A._fsync_dir

            def once(fd):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise OSError("injected directory fsync failure")
                return real(fd)

            with mock.patch.object(A, "_fsync_dir", side_effect=once):
                with self.assertRaises(A.PersistentPhaseError) as cm:
                    A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            self.assertEqual(cm.exception.outcome, "FAILED_NOT_COMMITTED")
            self.assertTrue(cm.exception.mutation_performed)
            self.assertIsNotNone(cm.exception.attempt_written_identity)
            self.assertEqual(target.read_bytes(), b"old\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_compensation_refuses_replaced_target(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            state = A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            replacement = Path(td) / "replacement"
            replacement.write_bytes(b"external\n")
            os.replace(replacement, target)
            with self.assertRaises(A.CompensationError) as cm:
                A.compensate_persistent(state)
            self.assertEqual(cm.exception.code, "persistent:ownership-drift")
            self.assertEqual(target.read_bytes(), b"external\n")

    def test_prepared_identity_survives_primary_rename(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = self.target(td)
            state = A.apply_persistent_change(target, self.desired(8192), uid, gid, 0o644)
            current = A.snapshot_persistent_target(target)
            self.assertEqual(current.st_dev, state.attempt_written_identity.st_dev)
            self.assertEqual(current.st_ino, state.attempt_written_identity.st_ino)
            self.assertEqual(current.raw_bytes, state.attempt_written_identity.raw_bytes)


class RuntimeTransactionIO(unittest.TestCase):
    def test_ge_above_target_skips_write(self):
        state = {"value": 8192, "writes": []}
        r = A.execute_runtime_phase("ge", 4096, lambda: state["value"], lambda v: state["writes"].append(v))
        self.assertFalse(r.write_performed)
        self.assertEqual(r.runtime_prewrite, 8192)
        self.assertEqual(r.runtime_after, 8192)
        self.assertEqual(state["writes"], [])

    def test_eq_equal_skips_write(self):
        state = {"value": 1, "writes": []}
        r = A.execute_runtime_phase("eq", 1, lambda: state["value"], lambda v: state["writes"].append(v))
        self.assertFalse(r.write_performed)
        self.assertIsNone(r.written_value)
        self.assertEqual(state["writes"], [])

    def test_ge_below_target_writes_once_and_postchecks(self):
        state = {"value": 1024, "writes": []}

        def write(v):
            state["writes"].append(v)
            state["value"] = v

        r = A.execute_runtime_phase("ge", 4096, lambda: state["value"], write)
        self.assertTrue(r.write_performed)
        self.assertEqual(r.written_value, 4096)
        self.assertEqual(r.runtime_after, 4096)
        self.assertEqual(state["writes"], [4096])

    def test_eq_noncompliant_writes_exact_target(self):
        state = {"value": 2, "writes": []}

        def write(v):
            state["writes"].append(v)
            state["value"] = v

        r = A.execute_runtime_phase("eq", 1, lambda: state["value"], write)
        self.assertEqual(r.written_value, 1)
        self.assertEqual(state["writes"], [1])

    def test_prewrite_failure_has_no_write(self):
        writes = []

        def read():
            raise OSError("gone")

        with self.assertRaises(A.RuntimePhaseError) as cm:
            A.execute_runtime_phase("ge", 4096, read, lambda v: writes.append(v))
        self.assertEqual(cm.exception.code, "runtime:prewrite-failure")
        self.assertFalse(cm.exception.write_attempted)
        self.assertEqual(writes, [])

    def test_write_failure_is_terminal(self):
        with self.assertRaises(A.RuntimePhaseError) as cm:
            A.execute_runtime_phase("eq", 1, lambda: 2, lambda v: (_ for _ in ()).throw(OSError("write failed")))
        self.assertEqual(cm.exception.code, "runtime:write-failure")
        self.assertTrue(cm.exception.write_attempted)
        self.assertFalse(cm.exception.write_performed)
        self.assertIsNone(cm.exception.written_value)
        self.assertEqual(cm.exception.runtime_prewrite, 2)

    def test_write_runtime_path_open_failure_reports_no_started_write(self):
        with mock.patch.object(A.os, "open", side_effect=PermissionError("denied")):
            with self.assertRaises(A.RuntimeWriteError) as cm:
                A.write_runtime_path("/proc/sys/example", 1)
        self.assertFalse(cm.exception.write_started)

    def test_write_runtime_path_partial_write_failure_reports_started_write(self):
        calls = {"n": 0}
        def fake_write(fd, data):
            calls["n"] += 1
            if calls["n"] == 1:
                return 1
            raise OSError("write failed after first byte")
        with mock.patch.object(A.os, "open", return_value=99), \
             mock.patch.object(A.os, "write", side_effect=fake_write), \
             mock.patch.object(A.os, "close", return_value=None):
            with self.assertRaises(A.RuntimeWriteError) as cm:
                A.write_runtime_path("/proc/sys/example", 12)
        self.assertTrue(cm.exception.write_started)

    def test_postcheck_noncompliant_is_failure(self):
        reads = iter([0, 0])
        writes = []
        with self.assertRaises(A.RuntimePhaseError) as cm:
            A.execute_runtime_phase("ge", 4096, lambda: next(reads), lambda v: writes.append(v))
        self.assertEqual(cm.exception.code, "runtime:postcheck-noncompliant")
        self.assertEqual(cm.exception.runtime_after, 0)
        self.assertEqual(writes, [4096])

    def test_read_runtime_path_uses_integer_semantics(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "runtime"
            p.write_bytes(b" +0004096\n")
            self.assertEqual(A.read_runtime_path(str(p)), 4096)


class ControlExecutor(unittest.TestCase):
    KEY = "kernel.dmesg_restrict"

    def paths(self, td):
        persistent = str(Path(td) / "zz-securelinux-policy-kernel-dmesg_restrict.conf")
        runtime = str(Path(td) / "runtime")
        return persistent, runtime

    def exec(self, td, runtime_state, *, persistent_bytes=None, op="eq", expected=1,
             sources=(), dry_run=False, privilege_check=None, apply_supported=True,
             read_runtime=None, write_runtime=None):
        persistent, runtime = self.paths(td)
        if persistent_bytes is not None:
            Path(persistent).write_bytes(persistent_bytes)
            Path(persistent).chmod(0o644)
        uid, gid = os.getuid(), os.getgid()
        if read_runtime is None:
            read_runtime = lambda: runtime_state["value"]
        if write_runtime is None:
            def write_runtime(value):
                runtime_state.setdefault("writes", []).append(value)
                runtime_state["value"] = value
        if privilege_check is None:
            privilege_check = lambda: None
        return A.execute_control(
            "SRC-T", self.KEY, op, expected, apply_supported, sources,
            dry_run=dry_run,
            persistent_target=persistent,
            runtime_target=runtime,
            read_runtime=read_runtime,
            write_runtime=write_runtime,
            write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
            privilege_check=privilege_check,
            persistent_uid=uid,
            persistent_gid=gid,
            persistent_mode=0o644,
        )

    def canonical(self, value=1):
        return A.canonical_persistent_bytes(self.KEY, value)

    def test_not_eligible_stops_before_target_observation(self):
        with tempfile.TemporaryDirectory() as td:
            calls = []
            r = self.exec(td, {"value": 1}, apply_supported=False,
                          read_runtime=lambda: calls.append("read") or 1,
                          privilege_check=lambda: calls.append("priv"))
            self.assertEqual(r.outcome, A.OUTCOME_NOT_ELIGIBLE)
            self.assertFalse(r.eligible)
            self.assertEqual(calls, [])
            self.assertIsNone(r.runtime_before)
            self.assertIsNone(r.persistent_before)

    def test_runtime_absent_is_not_applicable_before_persistent_read(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            Path(persistent).symlink_to("nonexistent")
            def missing():
                raise FileNotFoundError()
            r = self.exec(td, {}, read_runtime=missing)
            self.assertEqual(r.outcome, A.OUTCOME_NOT_APPLICABLE)
            self.assertFalse(r.mutation_performed)
            self.assertTrue(Path(persistent).is_symlink())

    def test_dry_run_both_would_apply_without_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            state = {"value": 0, "writes": []}
            persistent, _ = self.paths(td)
            r = self.exec(td, state, dry_run=True)
            self.assertEqual(r.outcome, A.OUTCOME_DRY_RUN_WOULD_APPLY)
            self.assertEqual(r.branch, A.BRANCH_BOTH)
            self.assertFalse(r.mutation_performed)
            self.assertFalse(Path(persistent).exists())
            self.assertEqual(state["writes"], [])
            self.assertEqual(r.runtime_after, 0)
            self.assertEqual(r.transaction_commit, A.COMMIT_NOT_STARTED)

    def test_already_compliant_commits_without_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            state = {"value": 1, "writes": []}
            r = self.exec(td, state, persistent_bytes=self.canonical())
            self.assertEqual(r.outcome, A.OUTCOME_ALREADY_COMPLIANT)
            self.assertEqual(r.branch, A.BRANCH_ALREADY)
            self.assertFalse(r.mutation_performed)
            self.assertEqual(r.transaction_commit, A.COMMIT_COMMITTED)
            self.assertEqual(state["writes"], [])

    def test_persistent_only_success(self):
        with tempfile.TemporaryDirectory() as td:
            state = {"value": 1, "writes": []}
            persistent, _ = self.paths(td)
            r = self.exec(td, state)
            self.assertEqual(r.outcome, A.OUTCOME_APPLIED)
            self.assertEqual(r.branch, A.BRANCH_PERSISTENT_ONLY)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.transaction_commit, A.COMMIT_COMMITTED)
            self.assertEqual(Path(persistent).read_bytes(), self.canonical())
            self.assertEqual(state["writes"], [])
            self.assertIsNotNone(r.attempt_written_identity)

    def test_runtime_only_success(self):
        with tempfile.TemporaryDirectory() as td:
            state = {"value": 0, "writes": []}
            r = self.exec(td, state, persistent_bytes=self.canonical())
            self.assertEqual(r.outcome, A.OUTCOME_APPLIED)
            self.assertEqual(r.branch, A.BRANCH_RUNTIME_ONLY)
            self.assertEqual(state["writes"], [1])
            self.assertEqual(r.written_value, 1)
            self.assertIsNone(r.attempt_written_identity)

    def test_both_success(self):
        with tempfile.TemporaryDirectory() as td:
            state = {"value": 0, "writes": []}
            persistent, _ = self.paths(td)
            r = self.exec(td, state)
            self.assertEqual(r.outcome, A.OUTCOME_APPLIED)
            self.assertEqual(r.branch, A.BRANCH_BOTH)
            self.assertEqual(state["writes"], [1])
            self.assertEqual(Path(persistent).read_bytes(), self.canonical())

    def test_runtime_only_prewrite_becomes_compliant_is_already(self):
        with tempfile.TemporaryDirectory() as td:
            values = iter([0, 1, 1])
            state = {"writes": []}
            r = self.exec(td, state, persistent_bytes=self.canonical(),
                          read_runtime=lambda: next(values),
                          write_runtime=lambda v: state["writes"].append(v))
            self.assertEqual(r.branch, A.BRANCH_RUNTIME_ONLY)
            self.assertEqual(r.outcome, A.OUTCOME_ALREADY_COMPLIANT)
            self.assertFalse(r.mutation_performed)
            self.assertEqual(state["writes"], [])
            self.assertEqual(r.runtime_prewrite, 1)

    def test_ge_both_prewrite_rises_above_target_commits_persistent_without_runtime_write(self):
        with tempfile.TemporaryDirectory() as td:
            values = iter([1024, 8192, 8192])
            state = {"writes": []}
            r = self.exec(td, state, op="ge", expected=4096,
                          read_runtime=lambda: next(values),
                          write_runtime=lambda v: state["writes"].append(v))
            self.assertEqual(r.branch, A.BRANCH_BOTH)
            self.assertEqual(r.outcome, A.OUTCOME_APPLIED)
            self.assertEqual(r.target_value, 4096)
            self.assertEqual(r.runtime_prewrite, 8192)
            self.assertEqual(state["writes"], [])
            self.assertTrue(r.mutation_performed)

    def test_both_runtime_prewrite_failure_compensates_persistent(self):
        with tempfile.TemporaryDirectory() as td:
            calls = {"n": 0}
            def read():
                calls["n"] += 1
                if calls["n"] == 1:
                    return 0
                if calls["n"] == 2:
                    raise OSError("gone")
                return 0
            persistent, _ = self.paths(td)
            r = self.exec(td, {}, read_runtime=read)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "runtime:prewrite-failure")
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.transaction_commit, A.COMMIT_NOT_COMMITTED)
            self.assertFalse(Path(persistent).exists())
            self.assertIn("persistent_compensation", r.actions_attempted)

    def test_persistent_only_runtime_drift_compensates(self):
        with tempfile.TemporaryDirectory() as td:
            values = iter([1, 2])
            persistent, _ = self.paths(td)
            r = self.exec(td, {}, read_runtime=lambda: next(values))
            self.assertEqual(r.branch, A.BRANCH_PERSISTENT_ONLY)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "postcheck:runtime-noncompliant")
            self.assertFalse(Path(persistent).exists())

    def test_runtime_only_persistent_external_drift_is_failed_not_committed_without_compensation(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            state = {"value": 0, "writes": []}
            def write(v):
                state["writes"].append(v)
                state["value"] = v
                Path(persistent).write_bytes(b"external\n")
            r = self.exec(td, state, persistent_bytes=self.canonical(), write_runtime=write)
            self.assertEqual(r.branch, A.BRANCH_RUNTIME_ONLY)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "postcheck:persistent-noncompliant")
            self.assertEqual(Path(persistent).read_bytes(), b"external\n")
            self.assertNotIn("persistent_compensation", r.actions_attempted)

    def test_both_compensation_ownership_drift_is_failed_compensation(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            state = {"value": 0}
            calls = {"n": 0}
            def read():
                calls["n"] += 1
                if calls["n"] == 1:
                    return 0
                Path(persistent).write_bytes(b"external\n")
                raise OSError("prewrite fail")
            r = self.exec(td, state, read_runtime=read)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_COMPENSATION)
            self.assertIn("compensation:persistent:ownership-drift", r.reason)
            self.assertEqual(Path(persistent).read_bytes(), b"external\n")

    def test_ge_unparseable_own_persistent_aborts_before_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            raw = b"# Managed by SecureLinux-Policy\nvm.other = 99\n"
            r = self.exec(td, {"value": 4096}, persistent_bytes=raw, op="ge", expected=4096)
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertEqual(r.reason, "persistent:own-unparseable")
            self.assertFalse(r.mutation_performed)

    def test_late_source_conflict_aborts(self):
        with tempfile.TemporaryDirectory() as td:
            src = A.SourceFile(
                "/etc/sysctl.d/zzz.conf",
                (A.ExplicitAssignment(self.KEY, "1", 1),),
            )
            r = self.exec(td, {"value": 1}, sources=(src,))
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_CONFLICT)
            self.assertEqual(r.reason, "source:late-conflict:/etc/sysctl.d/zzz.conf")
            self.assertFalse(r.mutation_performed)
            self.assertNotIn("operator_decision", A.control_result_to_report(r, "START", "FINISH"))

    def test_privilege_failure_aborts_before_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            def deny():
                raise A.PreconditionError("privilege:write-unavailable")
            r = self.exec(td, {"value": 1}, privilege_check=deny)
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertEqual(r.reason, "privilege:write-unavailable")
            self.assertFalse(Path(persistent).exists())
            self.assertFalse(r.mutation_performed)

    def test_own_persistent_parser_requires_exactly_one_matching_integer_assignment(self):
        self.assertEqual(A.own_persistent_value(self.KEY, b"#x\nkernel.dmesg_restrict = +0002\n"), 2)
        for raw in (
            b"kernel.other = 1\n",
            b"kernel.dmesg_restrict = x\n",
            b"kernel.dmesg_restrict = 1\nkernel.dmesg_restrict = 2\n",
        ):
            with self.assertRaises(A.PreconditionError):
                A.own_persistent_value(self.KEY, raw)




R11_REQUIRED_FIXTURES = ('runtime-ключ отсутствует и собственного файла нет -> NOT_APPLICABLE_KEY_ABSENT, мутаций нет', 'runtime-ключ отсутствует, а собственный файл существует -> NOT_APPLICABLE_KEY_ABSENT, существующий файл не изменяется и не удаляется', 'конфликтующее присвоение в /etc/sysctl.conf', 'конфликтующее присвоение в файле с лексикографически более поздним именем', 'конфликт в файле, скрытом одноимённым файлом более высокого приоритета — не конфликт', 'нечитаемый каталог или учитываемый источник -> ABORT', 'неоднозначное или нечисловое effective foreign assignment для ge -> ABORT', 'неудача runtime-фазы в ветке both с успешной persistent-компенсацией', 'неудача runtime-фазы в ветке both с неудачной persistent-компенсацией', 'ge: runtime_before выше expected, собственного persistent нет -> runtime не понижается; persistent может быть создан для сохранения target_value', 'ge: эффективный ранний чужой источник задаёт значение выше expected/runtime -> target_value сохраняет это effective foreign value', 'ge: собственный persistent value выше runtime_before -> runtime поднимается до target_value; persistent не понижается', 'persistent-only: после записи runtime перестал соответствовать target_value -> persistent компенсируется, runtime автоматически не записывается', 'нечисловое runtime-значение -> ABORT', 'persistent exact bytes совпадают, но uid/gid/mode не root:root/0644 -> persistent требует исправления', 'повторное применение при runtime+persistent соответствии одному target_value -> изменений нет', 'собственный файл предыдущего применения — не конфликт P2', 'dry-run: target_value и выбранная would-be ветка совпадают с APPLY при том же prestate; written_value=null, runtime/persistent не меняются', 'dry-run: NOT_APPLICABLE_KEY_ABSENT и precondition ABORT не выполняют мутаций и дают nonzero contribution по batch RC', 'phase1: отказ после rename на fsync каталога -> восстановление прежних bytes+uid+gid+mode либо удаление созданного target, NOT_COMMITTED', 'phase1: отказ post-rename проверки target -> та же persistent compensation', 'compensation: существующий файл с нестандартными прежними uid/gid/mode после отказа восстанавливается именно к прежним bytes+uid+gid+mode', 'ge: внешняя гонка после runtime_prewrite и до write обозначена как ограничение atomicity, не как доказанная no-lowering гарантия', 'eq: собственный файл с неразбираемым содержимым не вызывает ABORT сам по себе; он считается non-compliant и заменяется canonical bytes expected при APPLY', 'batch RC: нулевой вклад дают APPLIED, ALREADY_COMPLIANT и NOT_ELIGIBLE_APPLY_UNSUPPORTED; NOT_APPLICABLE_KEY_ABSENT и ABORTED_*/FAILED_* дают nonzero contribution', 'ge: runtime_prewrite вырос выше target_value после persistent-мутации -> запись пропускается, понижения нет, persistent коммитится, исход APPLIED, вклад в RC 0', 'ge: runtime_prewrite выше target_value без persistent-мутации -> мутаций нет, исход ALREADY_COMPLIANT, вклад в RC 0', 'eq: runtime_prewrite == target_value в ветке runtime_only -> запись пропускается, мутаций нет, исход ALREADY_COMPLIANT', 'ABORT по P2 при существующем собственном файле -> файл не изменяется и не удаляется, его состояние зафиксировано в отчёте', 'prewrite в ветке both: чтение runtime дало ошибку, ключ исчез либо значение нечисловое -> persistent компенсируется, исход FAILED_NOT_COMMITTED', 'prewrite в ветке both: та же ошибка и неудачная компенсация -> FAILED_COMPENSATION с фактическим состоянием', 'prewrite в ветке runtime_only: та же ошибка -> FAILED_NOT_COMMITTED, mutation_performed=false, persistent не изменяется', 'prestate фиксировал отсутствие target, но перед rename файл появился -> ABORT без rename, чужой файл не затирается', 'существующий target изменён другим процессом между снятием prestate и rename -> ABORT без rename, устаревший prestate не восстанавливается', 'на месте target символьная ссылка -> ABORT до мутации, ссылка не изменяется', 'на месте target обычный файл с st_nlink>1 -> ABORT до мутации', 'на месте target каталог, устройство, FIFO или сокет -> ABORT до мутации', 'контроль с apply.supported=false -> NOT_ELIGIBLE_APPLY_UNSUPPORTED, мутаций нет, вклад в RC 0', 'отчёт содержит actions_attempted, step_rc, mutation_performed и transaction_commit для каждого исхода, включая ABORT и FAILED_*', 'контроль с apply.supported=false в dry-run и в APPLY -> NOT_ELIGIBLE_APPLY_UNSUPPORTED до любых чтений; runtime и persistent не наблюдаются', 'st_nlink target вырос с 1 до 2 между snapshot и проверкой перед rename -> ABORT без rename', 'target подменён другим процессом после нашей записи, компенсация обязана сработать -> проверка принадлежности не совпала, чужой объект не затирается, исход FAILED_COMPENSATION', 'target отсутствовал до попытки, но на его месте оказался чужой объект к моменту компенсации -> удаление не выполняется, исход FAILED_COMPENSATION', 'target заменён между успешным primary rename и компенсацией -> сверка с attempt_written_identity не совпала, чужой объект не затирается, исход FAILED_COMPENSATION', 'созданный попыткой target заменён чужим объектом перед компенсационным unlink -> удаление не выполняется, исход FAILED_COMPENSATION', 'attempt_written_identity фиксируется после primary rename и присутствует в отчёте попытки, завершившейся компенсацией', 'отказ fsync каталога сразу после rename -> attempt_written_identity уже существует, компенсация выполняется по нему', 'отказ сверки target с prepared_identity после rename -> компенсация выполняется по тому же снимку', 'persistent rename не выполнялся -> attempt_written_identity в отчёте равен null', 'компенсация на ветви восстановления существовавшего файла: target подменён чужим объектом между входной сверкой и компенсационным rename -> вторая сверка с attempt_written_identity не совпала, чужой объект не перезаписывается, prestate не восстанавливается, исход FAILED_COMPENSATION с фактическим состоянием')
R11_FIXTURE_EXECUTION_MAP = {1: ('test_runtime_absent_without_persistent_is_not_applicable',), 2: ('test_runtime_absent_is_not_applicable_before_persistent_read',), 3: ('test_loader_sysctl_conf_matching_assignment_is_late_conflict',), 4: ('test_late_source_conflict_aborts',), 5: ('test_loader_shadowing_reads_only_high_priority_winner',), 6: ('test_unreadable_source_loader_aborts_control',), 7: ('test_invalid_effective_foreign_integer_aborts',), 8: ('test_both_runtime_prewrite_failure_compensates_persistent',), 9: ('test_both_compensation_ownership_drift_is_failed_compensation',), 10: ('test_ge_runtime_before_above_expected_creates_persistent_without_lowering',), 11: ('test_last_effective_prior_assignment', 'test_target_ge_preserves_maximum'), 12: ('test_plan_ge_own_persistent_ratchet', 'test_runtime_only_success'), 13: ('test_persistent_only_runtime_drift_compensates',), 14: ('test_nonnumeric_initial_runtime_aborts',), 15: ('test_persistent_compliance_includes_metadata',), 16: ('test_already_compliant_commits_without_mutation',), 17: ('test_own_file_is_not_foreign',), 18: ('test_dry_run_both_would_apply_without_mutation', 'test_batch_dry_run_report_is_nonmutating'), 19: ('test_batch_rc_contribution_semantics', 'test_dry_run_not_applicable_and_abort_do_not_mutate'), 20: ('test_directory_fsync_failure_after_rename_compensates',), 21: ('test_postrename_identity_failure_compensates',), 22: ('test_compensation_restores_existing_bytes_and_mode', 'test_compensation_restore_verification_failure_is_reported'), 23: ('test_toctou_limitations_are_explicit',), 24: ('test_eq_unparseable_own_file_is_replaced',), 25: ('test_batch_rc_contribution_semantics',), 26: ('test_ge_both_prewrite_rises_above_target_commits_persistent_without_runtime_write',), 27: ('test_ge_runtime_only_prewrite_rises_above_target_is_already',), 28: ('test_runtime_only_prewrite_becomes_compliant_is_already',), 29: ('test_p2_abort_existing_own_file_is_reported_and_preserved',), 30: ('test_both_runtime_prewrite_failure_compensates_persistent',), 31: ('test_both_compensation_ownership_drift_is_failed_compensation',), 32: ('test_runtime_only_prewrite_failure_is_not_committed_without_mutation',), 33: ('test_absent_target_appears_before_rename_aborts',), 34: ('test_drift_before_rename_aborts_and_preserves_external_change',), 35: ('test_snapshot_rejects_symlink',), 36: ('test_snapshot_rejects_hardlink',), 37: ('test_snapshot_rejects_directory_and_fifo_without_blocking',), 38: ('test_not_eligible_stops_before_target_observation', 'test_batch_not_eligible_is_zero_and_unobserved'), 39: ('test_report_d13_fields_for_success_abort_and_failure',), 40: ('test_not_eligible_stops_before_target_observation', 'test_batch_not_eligible_is_zero_and_unobserved'), 41: ('test_st_nlink_growth_before_rename_aborts',), 42: ('test_both_compensation_ownership_drift_is_failed_compensation',), 43: ('test_compensation_refuses_replaced_target',), 44: ('test_both_compensation_ownership_drift_is_failed_compensation',), 45: ('test_compensation_absent_second_check_refuses_external_change',), 46: ('test_attempt_identity_reported_after_compensated_failure',), 47: ('test_directory_fsync_failure_after_rename_compensates',), 48: ('test_postrename_identity_failure_compensates',), 49: ('test_attempt_identity_null_when_no_persistent_rename',), 50: ('test_compensation_existing_second_check_refuses_external_change',)}


class ContractCompletionAdditional(unittest.TestCase):
    KEY = "kernel.dmesg_restrict"

    def paths(self, td):
        return (
            str(Path(td) / "zz-securelinux-policy-kernel-dmesg_restrict.conf"),
            str(Path(td) / "runtime"),
        )

    def execute(self, td, state, **kwargs):
        persistent, runtime = self.paths(td)
        uid, gid = os.getuid(), os.getgid()
        read_runtime = kwargs.pop("read_runtime", lambda: state["value"])
        write_runtime = kwargs.pop("write_runtime", lambda v: state.__setitem__("value", v))
        return A.execute_control(
            "SRC-X", self.KEY, kwargs.pop("op", "eq"), kwargs.pop("expected", 1),
            kwargs.pop("apply_supported", True),
            kwargs.pop("source_files", ()),
            persistent_target=persistent,
            runtime_target=runtime,
            read_runtime=read_runtime,
            write_runtime=write_runtime,
            write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
            privilege_check=kwargs.pop("privilege_check", lambda: None),
            persistent_uid=uid, persistent_gid=gid, persistent_mode=0o644,
            **kwargs,
        )

    def test_runtime_absent_without_persistent_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            def missing():
                raise FileNotFoundError()
            r = self.execute(td, {}, read_runtime=missing)
            self.assertEqual(r.outcome, A.OUTCOME_NOT_APPLICABLE)
            self.assertFalse(r.mutation_performed)
            self.assertFalse(Path(persistent).exists())

    def test_unreadable_source_loader_aborts_control(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(
                A, "load_sysctl_sources",
                side_effect=A.PreconditionError("source:unreadable-directory", "/etc/sysctl.d"),
            ):
                r = self.execute(td, {"value": 1}, source_files=None)
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertEqual(r.reason, "source:unreadable-directory:/etc/sysctl.d")
            self.assertFalse(r.mutation_performed)

    def test_ge_runtime_before_above_expected_creates_persistent_without_lowering(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            state = {"value": 8192, "writes": []}
            def write(v):
                state["writes"].append(v)
                state["value"] = v
            r = self.execute(td, state, op="ge", expected=4096, write_runtime=write)
            self.assertEqual(r.branch, A.BRANCH_PERSISTENT_ONLY)
            self.assertEqual(r.target_value, 8192)
            self.assertEqual(r.runtime_after, 8192)
            self.assertEqual(state["writes"], [])
            self.assertEqual(Path(persistent).read_bytes(), A.canonical_persistent_bytes(self.KEY, 8192))

    def test_nonnumeric_initial_runtime_aborts(self):
        with tempfile.TemporaryDirectory() as td:
            def bad():
                return A.parse_integer_bytes(b"x\n")
            r = self.execute(td, {}, read_runtime=bad)
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertEqual(r.reason, "runtime:initial-read-failure")
            self.assertFalse(r.mutation_performed)

    def test_eq_unparseable_own_file_is_replaced(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            Path(persistent).write_bytes(b"not a sysctl assignment\n")
            Path(persistent).chmod(0o644)
            r = self.execute(td, {"value": 1})
            self.assertEqual(r.outcome, A.OUTCOME_APPLIED)
            self.assertEqual(r.branch, A.BRANCH_PERSISTENT_ONLY)
            self.assertEqual(Path(persistent).read_bytes(), A.canonical_persistent_bytes(self.KEY, 1))

    def test_ge_runtime_only_prewrite_rises_above_target_is_already(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            Path(persistent).write_bytes(A.canonical_persistent_bytes(self.KEY, 4096))
            Path(persistent).chmod(0o644)
            values = iter([1024, 8192, 8192])
            writes = []
            r = self.execute(
                td, {}, op="ge", expected=4096,
                read_runtime=lambda: next(values),
                write_runtime=lambda v: writes.append(v),
            )
            self.assertEqual(r.branch, A.BRANCH_RUNTIME_ONLY)
            self.assertEqual(r.outcome, A.OUTCOME_ALREADY_COMPLIANT)
            self.assertEqual(r.runtime_prewrite, 8192)
            self.assertEqual(writes, [])
            self.assertFalse(r.mutation_performed)

    def test_runtime_only_prewrite_failure_is_not_committed_without_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            Path(persistent).write_bytes(A.canonical_persistent_bytes(self.KEY, 1))
            Path(persistent).chmod(0o644)
            calls = {"n": 0}
            def read():
                calls["n"] += 1
                if calls["n"] == 1:
                    return 0
                raise OSError("prewrite fail")
            r = self.execute(td, {}, read_runtime=read)
            self.assertEqual(r.branch, A.BRANCH_RUNTIME_ONLY)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertFalse(r.mutation_performed)
            self.assertEqual(r.transaction_commit, A.COMMIT_NOT_COMMITTED)
            self.assertEqual(Path(persistent).read_bytes(), A.canonical_persistent_bytes(self.KEY, 1))

    def test_absent_target_appears_before_rename_aborts(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.paths(td)[0])
            orig = A._revalidate_prestate
            def appear(dir_fd, target_name, prestate):
                target.write_bytes(b"external\n")
                return orig(dir_fd, target_name, prestate)
            with mock.patch.object(A, "_revalidate_prestate", side_effect=appear):
                with self.assertRaises(A.PreconditionError) as cm:
                    A.apply_persistent_change(str(target), A.canonical_persistent_bytes(self.KEY, 1), uid, gid, 0o644)
            self.assertEqual(cm.exception.code, "persistent:drift-before-rename")
            self.assertEqual(target.read_bytes(), b"external\n")

    def test_st_nlink_growth_before_rename_aborts(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.paths(td)[0])
            target.write_bytes(b"old\n")
            target.chmod(0o644)
            link = Path(td) / "external-hardlink"
            orig = A._revalidate_prestate
            def grow(dir_fd, target_name, prestate):
                os.link(target, link)
                return orig(dir_fd, target_name, prestate)
            with mock.patch.object(A, "_revalidate_prestate", side_effect=grow):
                with self.assertRaises(A.PreconditionError) as cm:
                    A.apply_persistent_change(str(target), A.canonical_persistent_bytes(self.KEY, 1), uid, gid, 0o644)
            self.assertEqual(cm.exception.code, "persistent:drift-before-rename")
            self.assertEqual(target.read_bytes(), b"old\n")
            self.assertTrue(link.exists())

    def test_postrename_identity_failure_compensates(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.paths(td)[0])
            target.write_bytes(b"old\n")
            target.chmod(0o600)
            with mock.patch.object(A, "_verify_attempt_identity", side_effect=OSError("identity fail")):
                with self.assertRaises(A.PersistentPhaseError) as cm:
                    A.apply_persistent_change(str(target), A.canonical_persistent_bytes(self.KEY, 1), uid, gid, 0o644)
            self.assertEqual(cm.exception.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertIsNotNone(cm.exception.attempt_written_identity)
            self.assertEqual(target.read_bytes(), b"old\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_p2_abort_existing_own_file_is_reported_and_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            original = A.canonical_persistent_bytes(self.KEY, 1)
            Path(persistent).write_bytes(original)
            Path(persistent).chmod(0o644)
            late = A.SourceFile("/etc/sysctl.d/zzz.conf", (A.ExplicitAssignment(self.KEY, "1", 1),))
            r = self.execute(td, {"value": 1}, source_files=(late,))
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_CONFLICT)
            self.assertIsNotNone(r.persistent_before)
            self.assertIsNotNone(r.persistent_after)
            self.assertEqual(r.persistent_before.raw_bytes, original)
            self.assertEqual(r.persistent_after.raw_bytes, original)
            self.assertEqual(Path(persistent).read_bytes(), original)

    def test_p2_conflict_reason_includes_exact_source(self):
        with tempfile.TemporaryDirectory() as td:
            late_path = "/etc/sysctl.d/zzzz-after.conf"
            late = A.SourceFile(late_path, (A.ExplicitAssignment(self.KEY, "1", 1),))
            r = self.execute(td, {"value": 1}, source_files=(late,))
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_CONFLICT)
            self.assertIn("source:late-conflict", r.reason)
            self.assertIn(late_path, r.reason)

    def test_toctou_limitations_are_explicit(self):
        self.assertIn("compare-and-set", A.RUNTIME_TOCTOU_LIMITATION)
        self.assertIn("compare-and-swap", A.PERSISTENT_TOCTOU_LIMITATION)
        self.assertIn("rename/unlink", A.COMPENSATION_TOCTOU_LIMITATION)


class BatchAndReporting(unittest.TestCase):
    KEY = "kernel.dmesg_restrict"

    def result(self, outcome, *, eligible=True, dry_run=False, mutation=False,
               commit=None, attempt=None, reason=None, runtime_before=1,
               runtime_after=1, persistent_before=None, persistent_after=None):
        if commit is None:
            commit = A.COMMIT_COMMITTED if outcome in (A.OUTCOME_APPLIED, A.OUTCOME_ALREADY_COMPLIANT) else A.COMMIT_NOT_STARTED
        return A.ControlExecutionResult(
            "SRC-B", self.KEY, "eq", 1, eligible, outcome, reason or outcome.lower(),
            A.BRANCH_ALREADY if outcome == A.OUTCOME_ALREADY_COMPLIANT else None,
            1 if eligible else None, None,
            runtime_before if eligible else None, None,
            runtime_after if eligible else None,
            persistent_before, persistent_after, None,
            ("P0_ELIGIBILITY",), mutation, commit, attempt, dry_run,
        )

    def controls(self, n=1, supported=True):
        return [
            {"control_id": f"SRC-{i}", "key": self.KEY, "op": "eq", "expected": 1, "apply_supported": supported}
            for i in range(1, n + 1)
        ]

    def read_report(self, td):
        return json.loads((Path(td) / A.REPORT_JSON).read_text(encoding="utf-8"))

    def test_batch_rc_contribution_semantics(self):
        self.assertEqual(A.outcome_rc_contribution(A.OUTCOME_APPLIED), "0")
        self.assertEqual(A.outcome_rc_contribution(A.OUTCOME_ALREADY_COMPLIANT), "0")
        self.assertEqual(A.outcome_rc_contribution(A.OUTCOME_NOT_ELIGIBLE), "0")
        self.assertEqual(A.outcome_rc_contribution(A.OUTCOME_DRY_RUN_WOULD_APPLY, True), "0")
        for outcome in (
            A.OUTCOME_NOT_APPLICABLE, A.OUTCOME_ABORT_CONFLICT, A.OUTCOME_ABORT_OTHER,
            A.OUTCOME_FAILED_NOT_COMMITTED, A.OUTCOME_FAILED_COMPENSATION,
        ):
            self.assertEqual(A.outcome_rc_contribution(outcome), "nonzero")

    def test_batch_continues_after_nonzero_control(self):
        outcomes = iter([A.OUTCOME_NOT_APPLICABLE, A.OUTCOME_APPLIED])
        calls = []
        def fake(*args, **kwargs):
            outcome = next(outcomes)
            calls.append(outcome)
            return self.result(outcome, commit=A.COMMIT_NOT_STARTED if outcome == A.OUTCOME_NOT_APPLICABLE else A.COMMIT_COMMITTED)
        with tempfile.TemporaryDirectory() as td:
            b = A.execute_batch(self.controls(2), state_dir=td, execute_one=fake, now_fn=lambda: "2026-09-09 12:00:00 +0000")
            self.assertEqual(calls, [A.OUTCOME_NOT_APPLICABLE, A.OUTCOME_APPLIED])
            self.assertFalse(b.rc_zero)
            self.assertEqual(len(b.controls), 2)

    def test_report_d13_fields_for_success_abort_and_failure(self):
        results = iter([
            self.result(A.OUTCOME_APPLIED, mutation=True, commit=A.COMMIT_COMMITTED),
            self.result(A.OUTCOME_ABORT_OTHER, commit=A.COMMIT_NOT_STARTED),
            self.result(A.OUTCOME_FAILED_NOT_COMMITTED, mutation=True, commit=A.COMMIT_NOT_COMMITTED),
        ])
        def fake(*args, **kwargs):
            return next(results)
        with tempfile.TemporaryDirectory() as td:
            A.execute_batch(self.controls(3), state_dir=td, execute_one=fake, now_fn=lambda: "2026-09-09 12:00:00 +0000")
            payload = self.read_report(td)
            required = {
                "reason", "runtime_before", "persistent_before", "actions_attempted",
                "runtime_after", "persistent_after", "step_rc", "mutation_performed",
                "transaction_commit", "attempt_written_identity",
            }
            self.assertEqual(len(payload["controls"]), 3)
            for record in payload["controls"]:
                self.assertTrue(required.issubset(record))
            self.assertEqual(payload["controls"][0]["step_rc"], "0")
            self.assertEqual(payload["controls"][1]["step_rc"], "nonzero")
            self.assertEqual(payload["controls"][2]["step_rc"], "nonzero")

    def test_batch_not_eligible_is_zero_and_unobserved(self):
        def fake(*args, **kwargs):
            return self.result(
                A.OUTCOME_NOT_ELIGIBLE, eligible=False, dry_run=kwargs.get("dry_run", False),
                runtime_before=None, runtime_after=None, commit=A.COMMIT_NOT_STARTED,
            )
        for dry in (False, True):
            with self.subTest(dry_run=dry), tempfile.TemporaryDirectory() as td:
                b = A.execute_batch(self.controls(supported=False), state_dir=td, dry_run=dry, execute_one=fake,
                                    now_fn=lambda: "2026-09-09 12:00:00 +0000")
                self.assertTrue(b.rc_zero)
                r = self.read_report(td)["controls"][0]
                self.assertFalse(r["eligible"])
                self.assertEqual(r["step_rc"], "0")
                self.assertIsNone(r["runtime_before"])
                self.assertIsNone(r["persistent_before"])
                self.assertIsNone(r["target_value"])

    def test_batch_dry_run_report_is_nonmutating(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as state_dir:
            persistent = str(Path(td) / "zz-securelinux-policy-kernel-dmesg_restrict.conf")
            runtime = str(Path(td) / "runtime")
            state = {"value": 0, "writes": []}
            kwargs = {
                "source_files": (),
                "persistent_target": persistent,
                "runtime_target": runtime,
                "read_runtime": lambda: state["value"],
                "write_runtime": lambda v: state["writes"].append(v),
                "write_runtime_protocol": A.RUNTIME_WRITER_PROTOCOL_V1,
                "privilege_check": lambda: None,
                "persistent_uid": os.getuid(), "persistent_gid": os.getgid(), "persistent_mode": 0o644,
            }
            b = A.execute_batch(self.controls(), state_dir=state_dir, dry_run=True, common_execute_kwargs=kwargs,
                                now_fn=lambda: "2026-09-09 12:00:00 +0000")
            self.assertTrue(b.rc_zero)
            self.assertFalse(Path(persistent).exists())
            self.assertEqual(state["writes"], [])
            r = self.read_report(state_dir)["controls"][0]
            self.assertEqual(r["outcome"], A.OUTCOME_DRY_RUN_WOULD_APPLY)
            self.assertIsNone(r["written_value"])
            self.assertEqual(r["runtime_after"], r["runtime_before"])
            self.assertEqual(r["persistent_after"], r["persistent_before"])

    def test_report_persists_on_executor_exception(self):
        def boom(*args, **kwargs):
            raise RuntimeError("injected crash")
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError):
                A.execute_batch(self.controls(), state_dir=td, execute_one=boom,
                                now_fn=lambda: "2026-09-09 12:00:00 +0000")
            payload = self.read_report(td)
            self.assertFalse(payload["complete"])
            self.assertFalse(payload["rc_zero"])
            self.assertEqual(payload["run_error"]["type"], "RuntimeError")
            self.assertTrue((Path(td) / A.REPORT_APPLY_LOG).is_file())
            self.assertTrue((Path(td) / A.REPORT_DEBUG_LOG).is_file())
            self.assertTrue((Path(td) / A.REPORT_JSON).is_file())

    def test_attempt_identity_reported_after_compensated_failure(self):
        with tempfile.TemporaryDirectory() as td:
            persistent = str(Path(td) / "zz-securelinux-policy-kernel-dmesg_restrict.conf")
            runtime = str(Path(td) / "runtime")
            calls = {"n": 0}
            def read():
                calls["n"] += 1
                if calls["n"] == 1:
                    return 0
                if calls["n"] == 2:
                    raise OSError("gone")
                return 0
            r = A.execute_control(
                "SRC-B", self.KEY, "eq", 1, True, (),
                persistent_target=persistent, runtime_target=runtime,
                read_runtime=read, write_runtime=lambda v: None,
                write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1, privilege_check=lambda: None,
                persistent_uid=os.getuid(), persistent_gid=os.getgid(), persistent_mode=0o644,
            )
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertIsNotNone(r.attempt_written_identity)
            rec = A.control_result_to_report(r, "s", "f")
            self.assertIsNotNone(rec["attempt_written_identity"])
            self.assertIsNotNone(rec["attempt_written_identity"]["bytes_b64"])
            self.assertEqual(
                base64.b64decode(rec["attempt_written_identity"]["bytes_b64"]),
                A.canonical_persistent_bytes(self.KEY, 1),
            )

    def test_attempt_identity_null_when_no_persistent_rename(self):
        r = self.result(A.OUTCOME_ALREADY_COMPLIANT, attempt=None, commit=A.COMMIT_COMMITTED)
        rec = A.control_result_to_report(r, "s", "f")
        self.assertIsNone(rec["attempt_written_identity"])

    def test_reporting_artifacts_created_even_without_debug_events(self):
        with tempfile.TemporaryDirectory() as td:
            A.execute_batch(self.controls(), state_dir=td, execute_one=lambda *a, **k: self.result(A.OUTCOME_ALREADY_COMPLIANT),
                            now_fn=lambda: "2026-09-09 12:00:00 +0000")
            for name in (A.REPORT_APPLY_LOG, A.REPORT_DEBUG_LOG, A.REPORT_JSON):
                self.assertTrue((Path(td) / name).is_file(), name)



class CompensationFailureCoverage(unittest.TestCase):
    KEY = "kernel.dmesg_restrict"

    def owner(self):
        return os.getuid(), os.getgid()

    def target(self, td):
        return str(Path(td) / "zz-securelinux-policy-kernel-dmesg_restrict.conf")

    def desired(self):
        return A.canonical_persistent_bytes(self.KEY, 1)

    def test_compensation_entry_unavailable_object_is_failure(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            state = A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            target.unlink()
            with self.assertRaises(A.CompensationError) as cm:
                A.compensate_persistent(state)
            self.assertEqual(cm.exception.code, "persistent:ownership-drift")

    def test_compensation_existing_second_check_refuses_external_change(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            target.write_bytes(b"old\n")
            state = A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            real_snapshot = A._snapshot_name
            calls = {"n": 0}

            def snapshot(dir_fd, name, allow_absent):
                calls["n"] += 1
                if calls["n"] == 2:
                    target.write_bytes(b"external-existing\n")
                return real_snapshot(dir_fd, name, allow_absent)

            with mock.patch.object(A, "_snapshot_name", side_effect=snapshot):
                with self.assertRaises(A.CompensationError) as cm:
                    A.compensate_persistent(state)
            self.assertEqual(cm.exception.code, "persistent:ownership-drift")
            self.assertEqual(target.read_bytes(), b"external-existing\n")

    def test_compensation_restore_verification_failure_is_reported(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            target.write_bytes(b"old\n")
            target.chmod(0o600)
            state = A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            with mock.patch.object(A, "_restored_state_matches", return_value=False):
                with self.assertRaises(A.CompensationError) as cm:
                    A.compensate_persistent(state)
            self.assertEqual(cm.exception.code, "persistent:restore-verification-failed")
            self.assertEqual(target.read_bytes(), b"old\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_compensation_restore_operation_failure_is_reported(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            target.write_bytes(b"old\n")
            state = A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            with mock.patch.object(A, "_prepare_temp", side_effect=OSError("injected restore failure")):
                with self.assertRaises(A.CompensationError) as cm:
                    A.compensate_persistent(state)
            self.assertEqual(cm.exception.code, "persistent:restore-failed")
            self.assertEqual(target.read_bytes(), self.desired())

    def test_compensation_absent_second_check_refuses_external_change(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            state = A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            real_snapshot = A._snapshot_name
            calls = {"n": 0}

            def snapshot(dir_fd, name, allow_absent):
                calls["n"] += 1
                if calls["n"] == 2:
                    target.write_bytes(b"external-before-unlink\n")
                return real_snapshot(dir_fd, name, allow_absent)

            with mock.patch.object(A, "_snapshot_name", side_effect=snapshot):
                with self.assertRaises(A.CompensationError) as cm:
                    A.compensate_persistent(state)
            self.assertEqual(cm.exception.code, "persistent:ownership-drift")
            self.assertEqual(target.read_bytes(), b"external-before-unlink\n")

    def test_compensation_remove_verification_failure_is_reported(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            state = A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            real_snapshot = A._snapshot_name
            calls = {"n": 0}

            def snapshot(dir_fd, name, allow_absent):
                calls["n"] += 1
                if calls["n"] == 3:
                    return state.attempt_written_identity
                return real_snapshot(dir_fd, name, allow_absent)

            with mock.patch.object(A, "_snapshot_name", side_effect=snapshot):
                with self.assertRaises(A.CompensationError) as cm:
                    A.compensate_persistent(state)
            self.assertEqual(cm.exception.code, "persistent:remove-verification-failed")
            self.assertFalse(target.exists())

    def test_compensation_remove_operation_failure_is_reported(self):
        uid, gid = self.owner()
        with tempfile.TemporaryDirectory() as td:
            target = Path(self.target(td))
            state = A.apply_persistent_change(str(target), self.desired(), uid, gid, 0o644)
            with mock.patch.object(A.os, "unlink", side_effect=OSError("injected unlink failure")):
                with self.assertRaises(A.CompensationError) as cm:
                    A.compensate_persistent(state)
            self.assertEqual(cm.exception.code, "persistent:remove-failed")
            self.assertTrue(target.exists())


class DefensiveAndReportingCoverage(unittest.TestCase):
    def test_source_invalid_encoding_is_rejected(self):
        with self.assertRaises(A.PreconditionError) as cm:
            A.parse_sysctl_assignment_line(b"\xff = 1", 1)
        self.assertEqual(cm.exception.code, "source:invalid-encoding")

    def test_source_duplicate_name_guard_is_exercised(self):
        class Entry:
            def __init__(self, name):
                self.name = name

        class FakeScandir:
            def __enter__(self):
                return iter((Entry("10-a.conf"), Entry("10-a.conf")))
            def __exit__(self, exc_type, exc, tb):
                return False

        with mock.patch.object(A.os, "scandir", return_value=FakeScandir()):
            with self.assertRaises(A.PreconditionError) as cm:
                A._logical_conf_names("/", "/etc/sysctl.d")
        self.assertEqual(cm.exception.code, "source:duplicate-name")

    def test_real_check_apply_privileges_success_and_failure(self):
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / "runtime"
            runtime.write_bytes(b"1\n")
            persistent = Path(td) / "target.conf"
            A.check_apply_privileges(str(persistent), str(runtime))
            with self.assertRaises(A.PreconditionError) as cm:
                A.check_apply_privileges(str(persistent), str(Path(td) / "missing-runtime"))
            self.assertEqual(cm.exception.code, "privilege:write-unavailable")

    def test_reporting_hardlinked_log_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / A.REPORT_APPLY_LOG
            path.write_bytes(b"")
            os.link(path, Path(td) / "apply.log.hardlink")
            with self.assertRaises(A.PreconditionError) as cm:
                A._ensure_log_file(str(path))
            self.assertEqual(cm.exception.code, "reporting:forbidden-log-object")

    def test_reporting_bootstrap_refusal_still_writes_report(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            apply_log = td_path / A.REPORT_APPLY_LOG
            apply_log.write_bytes(b"")
            os.link(apply_log, td_path / "apply.log.hardlink")
            controls = [{"control_id": "SRC-1", "key": "kernel.dmesg_restrict",
                         "op": "eq", "expected": 1, "apply_supported": False}]
            with self.assertRaises(A.PreconditionError) as cm:
                A.execute_batch(controls, state_dir=td, now_fn=lambda: "2026-09-09 12:00:00 +0000")
            self.assertEqual(cm.exception.code, "reporting:forbidden-log-object")
            report_path = td_path / A.REPORT_JSON
            self.assertTrue(report_path.is_file())
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertFalse(payload["complete"])
            self.assertFalse(payload["rc_zero"])
            self.assertEqual(payload["run_error"]["phase"], "reporting-bootstrap")

    def test_contract_error_guards_execute(self):
        bad_calls = (
            lambda: A.parse_integer_bytes("1"),
            lambda: A.parse_sysctl_assignment_line("kernel.dmesg_restrict = 1", 0),
            lambda: A.parse_sysctl_source_bytes("not-bytes", "/etc/sysctl.d/x.conf"),
            lambda: A._rooted_source_path("relative", "/etc/sysctl.d"),
            lambda: A.compensate_persistent(object()),
            lambda: A.apply_persistent_change("relative.conf", b"x"),
            lambda: A.read_runtime_path("relative"),
            lambda: A.write_runtime_path("relative", 1),
            lambda: A.execute_runtime_phase("eq", 1, 1, lambda value: None),
        )
        for call in bad_calls:
            with self.assertRaises(A.ContractError):
                call()



class R11ConfirmedBlockerRegression(unittest.TestCase):
    KEY = "kernel.dmesg_restrict"

    def _mk_source_root(self, td):
        root = Path(td)
        for rel in ("etc/sysctl.d", "run/sysctl.d", "usr/local/lib/sysctl.d", "usr/lib/sysctl.d", "lib/sysctl.d", "etc"):
            (root / rel).mkdir(parents=True, exist_ok=True)
        return root

    def test_b01_planned_prestate_is_revalidated_not_resampled(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "zz-securelinux-policy-kernel-dmesg_restrict.conf"
            target.write_bytes(A.canonical_persistent_bytes(self.KEY, 4096))
            target.chmod(0o600)
            original = A.apply_persistent_change

            def race(*args, **kwargs):
                target.write_bytes(A.canonical_persistent_bytes(self.KEY, 16384))
                target.chmod(0o600)
                return original(*args, **kwargs)

            with mock.patch.object(A, "apply_persistent_change", side_effect=race):
                result = A.execute_control(
                    "B01", self.KEY, "ge", 4096, True, (),
                    persistent_target=str(target),
                    runtime_target=str(Path(td) / "runtime"),
                    read_runtime=lambda: 4096,
                    write_runtime=lambda value: None,
                    write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                    privilege_check=lambda: None,
                    persistent_uid=uid, persistent_gid=gid, persistent_mode=0o644,
                )
            self.assertEqual(result.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertIn("persistent:drift-before-rename", result.reason)
            self.assertEqual(target.read_bytes(), A.canonical_persistent_bytes(self.KEY, 16384))

    def test_b02a_foreign_fifo_is_rejected_before_open(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._mk_source_root(td)
            fifo = root / "etc/sysctl.d/20-fifo.conf"
            os.mkfifo(fifo)
            with mock.patch("builtins.open", side_effect=AssertionError("FIFO must not be opened")):
                with self.assertRaises(A.PreconditionError) as cm:
                    A._read_logical_source(str(root), "/etc/sysctl.d/20-fifo.conf")
            self.assertEqual(cm.exception.code, "source:unreadable-source")

    def test_b02b_eq_invalid_utf8_own_file_is_replaced_via_default_loader(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            root = self._mk_source_root(td)
            logical = A.persistent_path(self.KEY)
            target = root / logical.lstrip("/")
            target.write_bytes(b"\xff\xfe")
            target.chmod(0o644)
            result = A.execute_control(
                "B02B", self.KEY, "eq", 1, True,
                source_files=None, source_root=str(root),
                persistent_target=str(target),
                runtime_target=str(root / "runtime"),
                read_runtime=lambda: 1,
                write_runtime=lambda value: None,
                write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                privilege_check=lambda: None,
                persistent_uid=uid, persistent_gid=gid, persistent_mode=0o644,
            )
            self.assertEqual(result.outcome, A.OUTCOME_APPLIED)
            self.assertEqual(target.read_bytes(), A.canonical_persistent_bytes(self.KEY, 1))

    def test_b03_compensation_directory_failure_is_compensation_error(self):
        state = A.PersistentMutationState(
            "/tmp/target.conf",
            A.ObjectIdentity(False),
            A.ObjectIdentity(True, 1, 2, stat.S_IFREG, 1, os.getuid(), os.getgid(), 0o644, b"x"),
        )
        with mock.patch.object(A, "_open_dir_nofollow", side_effect=A.PreconditionError("persistent:directory-unavailable")):
            with self.assertRaises(A.CompensationError) as cm:
                A.compensate_persistent(state)
        self.assertEqual(cm.exception.code, "persistent:compensation-directory-unavailable")

    def test_b03_operational_compensation_failure_normalizes_for_batch_continuation(self):
        state = A.PersistentMutationState(
            "/tmp/target.conf",
            A.ObjectIdentity(False),
            A.ObjectIdentity(True, 1, 2, stat.S_IFREG, 1, os.getuid(), os.getgid(), 0o644, b"x"),
        )
        actions = []
        with mock.patch.object(A, "_open_dir_nofollow", side_effect=A.PreconditionError("persistent:directory-unavailable")):
            outcome, reason = A._compensate_after_failure(state, actions, "runtime:postcheck-noncompliant")
        self.assertEqual(outcome, A.OUTCOME_FAILED_COMPENSATION)
        self.assertIn("persistent:compensation-directory-unavailable", reason)

    def test_b04_conflict_reason_keeps_exact_source(self):
        late = "/etc/sysctl.d/zzz-foreign.conf"
        result = A.execute_control(
            "B04", self.KEY, "eq", 1, True,
            (A.SourceFile(late, (A.ExplicitAssignment(self.KEY, "1", 1),)),),
            persistent_target="/tmp/nonexistent-b04-target.conf",
            runtime_target="/tmp/nonexistent-b04-runtime",
            read_runtime=lambda: 1,
            write_runtime=lambda value: None,
            write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
            privilege_check=lambda: None,
            persistent_uid=os.getuid(), persistent_gid=os.getgid(),
        )
        self.assertEqual(result.outcome, A.OUTCOME_ABORT_CONFLICT)
        self.assertIn(late, result.reason)

    def test_b05_runtime_postcheck_failure_reports_written_value(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target.conf"
            target.write_bytes(A.canonical_persistent_bytes(self.KEY, 1))
            target.chmod(0o644)
            reads = iter([0, 0, 0])
            writes = []
            result = A.execute_control(
                "B05", self.KEY, "eq", 1, True, (),
                persistent_target=str(target),
                runtime_target=str(Path(td) / "runtime"),
                read_runtime=lambda: next(reads),
                write_runtime=lambda value: writes.append(value),
                write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                privilege_check=lambda: None,
                persistent_uid=uid, persistent_gid=gid, persistent_mode=0o644,
            )
            self.assertEqual(result.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(writes, [1])
            self.assertEqual(result.written_value, 1)
            self.assertTrue(result.mutation_performed)

    def test_b06_absent_own_does_not_shadow_lower_same_basename(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._mk_source_root(td)
            own_name = PurePosixPath(A.persistent_path(self.KEY)).name
            low = root / "usr/lib/sysctl.d" / own_name
            low.write_text(self.KEY + " = 16384\n", encoding="utf-8")
            sources = A.load_sysctl_sources(self.KEY, str(root))
            precedence = A.resolve_precedence(self.KEY, sources)
            self.assertEqual(precedence.effective_foreign_value, 16384)
            self.assertEqual(precedence.effective_foreign_source, "/usr/lib/sysctl.d/" + own_name)

    def test_b07_sysctl_conf_stat_error_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._mk_source_root(td)
            conf = str(root / "etc/sysctl.conf")
            real_lstat = A.os.lstat

            def guarded(path, *args, **kwargs):
                if os.fspath(path) == conf:
                    raise PermissionError("denied")
                return real_lstat(path, *args, **kwargs)

            with mock.patch.object(A.os, "lstat", side_effect=guarded):
                with self.assertRaises(A.PreconditionError) as cm:
                    A.load_sysctl_sources(self.KEY, str(root))
            self.assertEqual(cm.exception.code, "source:unreadable-source")
            self.assertEqual(cm.exception.source, A.SYSCTL_CONF)

    def test_b08_reporting_bootstrap_refusal_still_creates_report(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            state_dir = Path(td) / "state"
            state_dir.mkdir()
            apply_log = state_dir / A.REPORT_APPLY_LOG
            peer = state_dir / "peer"
            peer.write_text("", encoding="utf-8")
            os.link(peer, apply_log)
            with self.assertRaises(A.PreconditionError):
                A.execute_batch([], state_dir=str(state_dir))
            report = state_dir / A.REPORT_JSON
            self.assertTrue(report.exists())
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertFalse(payload["complete"])
            self.assertFalse(payload["rc_zero"])
            self.assertEqual(payload["run_error"]["phase"], "reporting-bootstrap")

    def test_b09_only_final_effective_assignment_is_parsed(self):
        sources = (
            A.SourceFile("/usr/lib/sysctl.d/10-a.conf", (A.ExplicitAssignment(self.KEY, "garbage", 1),)),
            A.SourceFile("/usr/lib/sysctl.d/20-b.conf", (A.ExplicitAssignment(self.KEY, "8192", 1),)),
        )
        result = A.resolve_precedence(self.KEY, sources)
        self.assertEqual(result.effective_foreign_value, 8192)
        self.assertEqual(result.effective_foreign_source, "/usr/lib/sysctl.d/20-b.conf")

    def test_dry_run_not_applicable_and_abort_do_not_mutate(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target.conf"
            original = b"keep-me\n"
            target.write_bytes(original)
            target.chmod(0o644)

            result_na = A.execute_control(
                "F19-NA", self.KEY, "eq", 1, True, (),
                dry_run=True,
                persistent_target=str(target),
                runtime_target=str(Path(td) / "runtime"),
                read_runtime=lambda: (_ for _ in ()).throw(FileNotFoundError()),
                write_runtime=lambda value: (_ for _ in ()).throw(AssertionError("write")),
                write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                privilege_check=lambda: None,
                persistent_uid=uid, persistent_gid=gid, persistent_mode=0o644,
            )
            self.assertEqual(result_na.outcome, A.OUTCOME_NOT_APPLICABLE)
            self.assertEqual(target.read_bytes(), original)

            late = "/etc/sysctl.d/zzz-foreign.conf"
            result_abort = A.execute_control(
                "F19-ABORT", self.KEY, "eq", 1, True,
                (A.SourceFile(late, (A.ExplicitAssignment(self.KEY, "1", 1),)),),
                dry_run=True,
                persistent_target=str(target),
                runtime_target=str(Path(td) / "runtime"),
                read_runtime=lambda: 1,
                write_runtime=lambda value: (_ for _ in ()).throw(AssertionError("write")),
                write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                privilege_check=lambda: None,
                persistent_uid=uid, persistent_gid=gid, persistent_mode=0o644,
            )
            self.assertEqual(result_abort.outcome, A.OUTCOME_ABORT_CONFLICT)
            self.assertEqual(target.read_bytes(), original)



def _find_test_case_class(test_name):
    matches = []
    for obj in globals().values():
        if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
            if test_name in unittest.defaultTestLoader.getTestCaseNames(obj):
                matches.append(obj)
    if len(matches) != 1:
        raise AssertionError("test-name-resolution:%s:%d" % (test_name, len(matches)))
    return matches[0]


def _run_named_test_with_adapter_trace(test_name):
    executed_lines = set()
    called_functions = set()
    adapter_filename = str(ADAPTER_PATH.resolve())

    def tracer(frame, event, arg):
        if os.path.abspath(frame.f_code.co_filename) == adapter_filename:
            if event == "line":
                executed_lines.add(frame.f_lineno)
            elif event == "call":
                called_functions.add(frame.f_code.co_name)
        return tracer

    cls = _find_test_case_class(test_name)
    case = cls(test_name)
    result = unittest.TestResult()
    previous = sys.gettrace()
    sys.settrace(tracer)
    try:
        case.run(result)
    finally:
        sys.settrace(previous)
    if result.failures or result.errors or result.skipped or result.unexpectedSuccesses:
        raise AssertionError(
            "traced-test-failed:%s failures=%r errors=%r skipped=%r unexpected=%r"
            % (test_name, result.failures, result.errors, result.skipped, result.unexpectedSuccesses)
        )
    return executed_lines, called_functions


def _adapter_line_number(exact_stripped_line, occurrence=1):
    matches = [
        idx for idx, line in enumerate(ADAPTER_PATH.read_text(encoding="utf-8").splitlines(), 1)
        if line.strip() == exact_stripped_line
    ]
    if occurrence < 1 or occurrence > len(matches):
        raise AssertionError("trace-anchor-not-found:%r:%d:%r" % (exact_stripped_line, occurrence, matches))
    return matches[occurrence - 1]


COMPENSATION_FAILURE_BRANCH_EVIDENCE = (
    ("test_compensation_entry_unavailable_object_is_failure",
     'raise CompensationError("persistent:ownership-drift") from exc', 1),
    ("test_compensation_refuses_replaced_target",
     'raise CompensationError("persistent:ownership-drift")', 1),
    ("test_compensation_existing_second_check_refuses_external_change",
     'raise CompensationError("persistent:ownership-drift")', 2),
    ("test_compensation_restore_verification_failure_is_reported",
     'raise CompensationError("persistent:restore-verification-failed")', 1),
    ("test_compensation_restore_operation_failure_is_reported",
     'raise CompensationError("persistent:restore-failed") from exc', 1),
    ("test_compensation_absent_second_check_refuses_external_change",
     'raise CompensationError("persistent:ownership-drift")', 3),
    ("test_compensation_remove_verification_failure_is_reported",
     'raise CompensationError("persistent:remove-verification-failed")', 1),
    ("test_compensation_remove_operation_failure_is_reported",
     'raise CompensationError("persistent:remove-failed") from exc', 1),
)


class RV2CorrectionRegression(unittest.TestCase):
    KEY1 = "kernel.dmesg_restrict"
    KEY2 = "kernel.kptr_restrict"

    def _mk_source_root(self, td):
        root = Path(td)
        for rel in ("etc/sysctl.d", "run/sysctl.d", "usr/local/lib/sysctl.d", "usr/lib/sysctl.d", "lib/sysctl.d", "etc"):
            (root / rel).mkdir(parents=True, exist_ok=True)
        return root

    def test_rv2_b01_symlink_to_regular_foreign_source_is_read(self):
        with tempfile.TemporaryDirectory() as td:
            root = self._mk_source_root(td)
            backing = root / "backing.conf"
            backing.write_text(self.KEY1 + " = 8192\n", encoding="utf-8")
            link = root / "etc/sysctl.d/50-x.conf"
            link.symlink_to(backing)
            sources = A.load_sysctl_sources(self.KEY1, str(root))
            precedence = A.resolve_precedence(self.KEY1, sources)
            self.assertEqual(precedence.effective_foreign_value, 8192)
            self.assertEqual(precedence.effective_foreign_source, "/etc/sysctl.d/50-x.conf")

    def test_rv2_b02_write_failure_after_runtime_change_is_reported_as_mutation(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target.conf"
            target.write_bytes(A.canonical_persistent_bytes(self.KEY1, 1))
            target.chmod(0o644)
            runtime = {"value": 0}

            def write_then_fail(value):
                runtime["value"] = value
                raise A.RuntimeWriteError("runtime:write-failure", True)

            result = A.execute_control(
                "RV2-B02", self.KEY1, "eq", 1, True, (),
                persistent_target=str(target),
                runtime_target=str(Path(td) / "runtime"),
                read_runtime=lambda: runtime["value"],
                write_runtime=write_then_fail,
                write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                privilege_check=lambda: None,
                persistent_uid=uid, persistent_gid=gid, persistent_mode=0o644,
            )
            self.assertEqual(result.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(result.runtime_after, 1)
            self.assertEqual(result.written_value, 1)
            self.assertTrue(result.mutation_performed)

    def test_real_batch_continues_to_second_control_after_runtime_write_failure(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as state_dir:
            base = Path(td)
            controls = [
                {"control_id": "RV2-BATCH-1", "key": self.KEY1, "op": "eq", "expected": 1, "apply_supported": True},
                {"control_id": "RV2-BATCH-2", "key": self.KEY2, "op": "eq", "expected": 1, "apply_supported": True},
            ]
            targets = {}
            runtime = {"RV2-BATCH-1": 0, "RV2-BATCH-2": 0}
            for control in controls:
                p = base / (control["control_id"] + ".conf")
                p.write_bytes(A.canonical_persistent_bytes(control["key"], 1))
                p.chmod(0o644)
                targets[control["control_id"]] = p

            def execute_one(control_id, key, op, expected, apply_supported, **kwargs):
                def write_value(value):
                    runtime[control_id] = value
                    if control_id == "RV2-BATCH-1":
                        raise A.RuntimeWriteError("runtime:write-failure", True)
                return A.execute_control(
                    control_id, key, op, expected, apply_supported, (),
                    persistent_target=str(targets[control_id]),
                    runtime_target=str(base / (control_id + ".runtime")),
                    read_runtime=lambda: runtime[control_id],
                    write_runtime=write_value,
                    write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                    privilege_check=lambda: None,
                    persistent_uid=uid, persistent_gid=gid, persistent_mode=0o644,
                    dry_run=kwargs.get("dry_run", False),
                )

            batch = A.execute_batch(
                controls, state_dir=state_dir, execute_one=execute_one,
                now_fn=lambda: "2026-09-09 17:00:00 +0500",
            )
            self.assertEqual(len(batch.controls), 2)
            self.assertEqual(batch.controls[0]["outcome"], A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertTrue(batch.controls[0]["mutation_performed"])
            self.assertEqual(batch.controls[0]["written_value"], 1)
            self.assertEqual(batch.controls[1]["outcome"], A.OUTCOME_APPLIED)
            self.assertEqual(runtime["RV2-BATCH-2"], 1)
            self.assertFalse(batch.rc_zero)

    @unittest.skipIf(os.geteuid() == 0, "requires a genuinely unprivileged process")
    def test_b07_unprivileged_real_lstat_permission_denial_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "safe.d").mkdir()
            denied = root / "blocked"
            denied.mkdir()
            (denied / "sysctl.conf").write_text(self.KEY1 + " = 1\n", encoding="utf-8")
            denied.chmod(0)
            try:
                with mock.patch.object(A, "SYSCTL_D_DIRS", ("/safe.d",)), \
                     mock.patch.object(A, "SYSCTL_CONF", "/blocked/sysctl.conf"):
                    with self.assertRaises(A.PreconditionError) as cm:
                        A.load_sysctl_sources(self.KEY1, str(root))
                self.assertEqual(cm.exception.code, "source:unreadable-source")
                self.assertEqual(cm.exception.source, "/blocked/sysctl.conf")
            finally:
                denied.chmod(0o700)


class R11FixtureCoverage(unittest.TestCase):
    def test_fixture_execution_matrix_50_of_50(self):
        self.assertEqual(len(R11_REQUIRED_FIXTURES), 50)
        self.assertEqual(len(set(R11_REQUIRED_FIXTURES)), 50)
        self.assertEqual(set(R11_FIXTURE_EXECUTION_MAP), set(range(1, 51)))
        evidence = {}
        for idx, test_names in R11_FIXTURE_EXECUTION_MAP.items():
            self.assertTrue(test_names, idx)
            traced_lines = set()
            called_functions = set()
            for test_name in test_names:
                lines, functions = _run_named_test_with_adapter_trace(test_name)
                traced_lines.update(lines)
                called_functions.update(functions)
            # Static contract/limitation assertions can legitimately read module constants
            # without entering a function. Every other fixture must execute adapter code.
            if idx != 23:
                self.assertTrue(traced_lines, "fixture %d executed no adapter line" % idx)
            evidence[idx] = (len(traced_lines), tuple(sorted(called_functions)))
        self.assertEqual(len(evidence), 50)

    def test_compensation_failure_branch_trace_8_of_8(self):
        hit = {}
        for test_name, anchor, occurrence in COMPENSATION_FAILURE_BRANCH_EVIDENCE:
            expected_line = _adapter_line_number(anchor, occurrence)
            lines, _ = _run_named_test_with_adapter_trace(test_name)
            self.assertIn(expected_line, lines, "%s did not execute line %d" % (test_name, expected_line))
            hit[test_name] = expected_line
        self.assertEqual(len(hit), 8)



class FrozenScopeV1(unittest.TestCase):
    KEY = "kernel.dmesg_restrict"

    def canonical(self, value=1):
        return A.canonical_persistent_bytes(self.KEY, value)

    def paths(self, td):
        return (
            str(Path(td) / "zz-securelinux-policy-kernel-dmesg_restrict.conf"),
            str(Path(td) / "runtime"),
        )

    def execute(self, td, runtime_state=None, *, persistent_bytes=None, op="eq", expected=1,
                source_files=(), source_root="/", dry_run=False, read_runtime=None,
                write_runtime=None, privilege_check=None):
        if runtime_state is None:
            runtime_state = {"value": 1, "writes": []}
        persistent, runtime = self.paths(td)
        if persistent_bytes is not None:
            Path(persistent).write_bytes(persistent_bytes)
            Path(persistent).chmod(0o644)
        if read_runtime is None:
            read_runtime = lambda: runtime_state["value"]
        if write_runtime is None:
            def write_runtime(v):
                runtime_state.setdefault("writes", []).append(v)
                runtime_state["value"] = v
        if privilege_check is None:
            privilege_check = lambda: None
        return A.execute_control(
            "SCOPE", self.KEY, op, expected, True, source_files,
            source_root=source_root,
            dry_run=dry_run,
            persistent_target=persistent,
            runtime_target=runtime,
            read_runtime=read_runtime,
            write_runtime=write_runtime,
            write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
            privilege_check=privilege_check,
            persistent_uid=os.getuid(), persistent_gid=os.getgid(), persistent_mode=0o644,
        )

    # S006
    def test_S006_initial_runtime_read_error_aborts_without_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            def read():
                raise OSError("initial read denied")
            r = self.execute(td, read_runtime=read)
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertEqual(r.reason, "runtime:initial-read-failure")
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)

    # S009 additional F37 witnesses
    def test_S009_device_and_socket_targets_are_rejected(self):
        with self.assertRaises(A.PreconditionError) as cm:
            A.snapshot_persistent_target("/dev/null")
        self.assertEqual(cm.exception.code, "persistent:forbidden-object")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "target.sock"
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.bind(str(p))
                with self.assertRaises(A.PreconditionError) as cm2:
                    A.snapshot_persistent_target(str(p))
                self.assertEqual(cm2.exception.code, "persistent:forbidden-object")
            finally:
                s.close()

    # S010
    def test_S010_persistent_prestate_unreadable_is_abort_not_absent(self):
        with tempfile.TemporaryDirectory() as td:
            original = A.snapshot_persistent_target
            def fail(path):
                raise A.PreconditionError("persistent:target-unreadable", Path(path).name)
            with mock.patch.object(A, "snapshot_persistent_target", side_effect=fail):
                r = self.execute(td, {"value": 1})
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertIn("persistent:target-unreadable", r.reason)
            self.assertFalse(r.mutation_performed)

    # S026/S027/S028
    def test_S026_dry_run_already(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.execute(td, {"value": 1, "writes": []},
                             persistent_bytes=self.canonical(), dry_run=True)
            self.assertEqual(r.branch, A.BRANCH_ALREADY)
            self.assertEqual(r.outcome, A.OUTCOME_ALREADY_COMPLIANT)
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)

    def test_S027_dry_run_persistent_only(self):
        with tempfile.TemporaryDirectory() as td:
            state = {"value": 1, "writes": []}
            persistent, _ = self.paths(td)
            r = self.execute(td, state, dry_run=True)
            self.assertEqual(r.branch, A.BRANCH_PERSISTENT_ONLY)
            self.assertEqual(r.outcome, A.OUTCOME_DRY_RUN_WOULD_APPLY)
            self.assertFalse(Path(persistent).exists())
            self.assertEqual(state["writes"], [])
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)

    def test_S028_dry_run_runtime_only(self):
        with tempfile.TemporaryDirectory() as td:
            state = {"value": 0, "writes": []}
            r = self.execute(td, state, persistent_bytes=self.canonical(), dry_run=True)
            self.assertEqual(r.branch, A.BRANCH_RUNTIME_ONLY)
            self.assertEqual(r.outcome, A.OUTCOME_DRY_RUN_WOULD_APPLY)
            self.assertEqual(state["writes"], [])
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)

    def _source_root(self, td):
        root = Path(td)
        for rel in ("etc/sysctl.d", "run/sysctl.d", "usr/local/lib/sysctl.d",
                    "usr/lib/sysctl.d", "lib/sysctl.d", "etc"):
            (root / rel).mkdir(parents=True, exist_ok=True)
        return root

    def _execute_binding_race(self, td, own_initially_exists):
        root = self._source_root(td)
        own_logical = A.persistent_path(self.KEY)
        own = root / own_logical.lstrip("/")
        lower = root / "usr/lib/sysctl.d" / own.name
        lower.write_text(self.KEY + " = 16384\n", encoding="utf-8")
        if own_initially_exists:
            own.write_bytes(A.canonical_persistent_bytes(self.KEY, 4096))
            own.chmod(0o644)
        real_resolve = A.resolve_precedence
        changed = {"done": False}
        def resolve_then_change(key, files):
            result = real_resolve(key, files)
            if not changed["done"]:
                changed["done"] = True
                if own_initially_exists:
                    own.unlink()
                else:
                    own.write_bytes(A.canonical_persistent_bytes(self.KEY, 4096))
                    own.chmod(0o644)
            return result
        runtime = {"value": 4096}
        with mock.patch.object(A, "resolve_precedence", side_effect=resolve_then_change):
            r = A.execute_control(
                "BIND", self.KEY, "ge", 4096, True, None,
                source_root=str(root),
                persistent_target=str(own),
                runtime_target=str(root / "runtime"),
                read_runtime=lambda: runtime["value"],
                write_runtime=lambda v: runtime.__setitem__("value", v),
                write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                privilege_check=lambda: None,
                persistent_uid=os.getuid(), persistent_gid=os.getgid(), persistent_mode=0o644,
            )
        return r, own, lower, runtime

    # S034 / B-10: mandatory RED on current bytes
    def test_S034_B10_own_disappears_between_P2_and_prestate_aborts(self):
        with tempfile.TemporaryDirectory() as td:
            r, own, lower, runtime = self._execute_binding_race(td, True)
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertFalse(r.mutation_performed)
            self.assertEqual(lower.read_text(encoding="utf-8"), self.KEY + " = 16384\n")
            self.assertFalse(own.exists())

    # S035 paired opposite; may reveal an in-scope blocker.
    def test_S035_own_appears_between_P2_and_prestate_aborts(self):
        with tempfile.TemporaryDirectory() as td:
            r, own, lower, runtime = self._execute_binding_race(td, False)
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertFalse(r.mutation_performed)
            self.assertEqual(own.read_bytes(), A.canonical_persistent_bytes(self.KEY, 4096))
            self.assertEqual(lower.read_text(encoding="utf-8"), self.KEY + " = 16384\n")

    # S039
    def test_S039_phase1_failure_before_rename_is_not_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            with mock.patch.object(A, "_prepare_temp", side_effect=OSError("prepare failed")):
                r = self.execute(td, {"value": 1})
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "persistent:phase1-before-rename")
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.attempt_written_identity)
            self.assertFalse(Path(persistent).exists())

    # S042 / B-11: mandatory RED on current bytes
    def test_S042_B11_phase1_failed_compensation_reports_both_reasons(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            target = Path(persistent)
            real_verify = A._verify_attempt_identity
            def replace_then_fail(dir_fd, target_name, attempt_identity):
                replacement = Path(td) / "external"
                replacement.write_bytes(b"external\n")
                os.replace(replacement, target)
                raise OSError("post-rename verify failure")
            with mock.patch.object(A, "_verify_attempt_identity", side_effect=replace_then_fail):
                r = self.execute(td, {"value": 1})
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_COMPENSATION)
            self.assertIn("persistent:post-rename-failure", r.reason)
            self.assertIn("persistent:ownership-drift", r.reason)
            self.assertEqual(target.read_bytes(), b"external\n")

    # S046 alternatives
    def test_S046_prewrite_disappearance_runtime_only(self):
        with tempfile.TemporaryDirectory() as td:
            calls = {"n": 0}
            def read():
                calls["n"] += 1
                if calls["n"] == 1:
                    return 0
                raise FileNotFoundError("gone at prewrite")
            r = self.execute(td, {}, persistent_bytes=self.canonical(), read_runtime=read)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)

    def test_S046_prewrite_nonnumeric_runtime_only(self):
        with tempfile.TemporaryDirectory() as td:
            calls = {"n": 0}
            def read():
                calls["n"] += 1
                return 0 if calls["n"] == 1 else "not-int"
            r = self.execute(td, {}, persistent_bytes=self.canonical(), read_runtime=read)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)

    # S049 / B-12 mandatory RED
    def test_S049_B12_runtime_only_no_byte_failure_has_no_written_value_or_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            state = {"value": 0}
            def fail_before_write(value):
                raise A.RuntimeWriteError("runtime:write-failure", False)
            r = self.execute(td, state, persistent_bytes=self.canonical(), write_runtime=fail_before_write)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)
            self.assertEqual(r.runtime_after, 0)

    # S050 / B-12 both counterpart
    def test_S050_B12_both_no_byte_failure_keeps_persistent_mutation_fact_but_no_written_value(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            state = {"value": 0}
            def fail_before_write(value):
                raise A.RuntimeWriteError("runtime:write-failure", False)
            r = self.execute(td, state, write_runtime=fail_before_write)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertTrue(r.mutation_performed)
            self.assertIsNone(r.written_value)
            self.assertFalse(Path(persistent).exists())  # successful compensation

    # S052 paired started-write in both
    def test_S052_both_started_write_failure_reports_written_and_compensates(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            state = {"value": 0}
            def write_then_fail(value):
                state["value"] = value
                raise A.RuntimeWriteError("runtime:write-failure", True)
            r = self.execute(td, state, write_runtime=write_then_fail)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)
            self.assertEqual(r.runtime_after, 1)
            self.assertFalse(Path(persistent).exists())

    def _postread_failure_result(self, td, both=False, comp_fail=False):
        state = {"value": 0, "calls": 0}
        persistent, _ = self.paths(td)
        if not both:
            Path(persistent).write_bytes(self.canonical())
            Path(persistent).chmod(0o644)
        def read():
            state["calls"] += 1
            if state["calls"] in (1,2):
                return 0
            if state["calls"] == 3:
                raise OSError("immediate postcheck read failed")
            return state["value"]
        def write(v):
            state["value"] = v
        patcher = mock.patch.object(A, "compensate_persistent",
                                    side_effect=A.CompensationError("persistent:restore-failed")) if comp_fail else None
        if patcher:
            patcher.start()
        try:
            return self.execute(td, state, read_runtime=read, write_runtime=write), Path(persistent)
        finally:
            if patcher:
                patcher.stop()

    # S053A/B/C
    def test_S053A_runtime_only_postcheck_read_failure(self):
        with tempfile.TemporaryDirectory() as td:
            r, persistent = self._postread_failure_result(td, both=False)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)
            self.assertIn("runtime:postcheck-read-failure", r.reason)

    def test_S053B_both_postcheck_read_failure_compensation_success(self):
        with tempfile.TemporaryDirectory() as td:
            r, persistent = self._postread_failure_result(td, both=True)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)
            self.assertFalse(persistent.exists())

    def test_S053C_both_postcheck_read_failure_compensation_failure(self):
        with tempfile.TemporaryDirectory() as td:
            r, persistent = self._postread_failure_result(td, both=True, comp_fail=True)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_COMPENSATION)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)
            self.assertIn("runtime:postcheck-read-failure", r.reason)
            self.assertIn("persistent:restore-failed", r.reason)

    # S054/S055
    def _postcheck_noncompliant_result(self, td, both=False, comp_fail=False):
        state = {"value": 0}
        persistent, _ = self.paths(td)
        if not both:
            Path(persistent).write_bytes(self.canonical())
            Path(persistent).chmod(0o644)
        def write_without_effect(v):
            pass  # call succeeds, immediate post-check still sees 0
        patcher = mock.patch.object(A, "compensate_persistent",
                                    side_effect=A.CompensationError("persistent:restore-failed")) if comp_fail else None
        if patcher:
            patcher.start()
        try:
            return self.execute(td, state, write_runtime=write_without_effect), Path(persistent)
        finally:
            if patcher:
                patcher.stop()

    def test_S054_runtime_only_completed_write_postcheck_noncompliant(self):
        with tempfile.TemporaryDirectory() as td:
            r, _ = self._postcheck_noncompliant_result(td, both=False)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)
            self.assertEqual(r.runtime_after, 0)

    def test_S055A_both_postcheck_noncompliant_compensation_success(self):
        with tempfile.TemporaryDirectory() as td:
            r, persistent = self._postcheck_noncompliant_result(td, both=True)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)
            self.assertFalse(persistent.exists())

    def test_S055B_both_postcheck_noncompliant_compensation_failure(self):
        with tempfile.TemporaryDirectory() as td:
            r, _ = self._postcheck_noncompliant_result(td, both=True, comp_fail=True)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_COMPENSATION)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)

    # S057
    def test_S057_persistent_only_final_runtime_drift_compensation_failure(self):
        with tempfile.TemporaryDirectory() as td:
            values = iter([1, 0, 0])
            with mock.patch.object(A, "compensate_persistent",
                                   side_effect=A.CompensationError("persistent:restore-failed")):
                r = self.execute(td, {}, read_runtime=lambda: next(values))
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_COMPENSATION)
            self.assertTrue(r.mutation_performed)
            self.assertIsNone(r.written_value)
            self.assertIn("postcheck:runtime-noncompliant", r.reason)
            self.assertIn("persistent:restore-failed", r.reason)

    # S059A/B
    def _final_runtime_drift_result(self, td, comp_fail=False):
        state = {"value": 0, "calls": 0}
        def read():
            state["calls"] += 1
            if state["calls"] == 1: return 0       # initial
            if state["calls"] == 2: return 0       # prewrite
            if state["calls"] == 3: return 1       # immediate phase2 postcheck
            return 0                               # final runtime drift
        def write(v):
            state["value"] = v
        patcher = mock.patch.object(A, "compensate_persistent",
                                    side_effect=A.CompensationError("persistent:restore-failed")) if comp_fail else None
        if patcher: patcher.start()
        try:
            return self.execute(td, state, read_runtime=read, write_runtime=write)
        finally:
            if patcher: patcher.stop()

    def test_S059A_both_final_runtime_drift_compensation_success(self):
        with tempfile.TemporaryDirectory() as td:
            r = self._final_runtime_drift_result(td, False)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "postcheck:runtime-noncompliant")
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)

    def test_S059B_both_final_runtime_drift_compensation_failure(self):
        with tempfile.TemporaryDirectory() as td:
            r = self._final_runtime_drift_result(td, True)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_COMPENSATION)
            self.assertIn("postcheck:runtime-noncompliant", r.reason)
            self.assertIn("persistent:restore-failed", r.reason)

    # S060A
    def test_S060A_both_external_persistent_drift_final_causes_ownership_failed_compensation(self):
        with tempfile.TemporaryDirectory() as td:
            persistent, _ = self.paths(td)
            state = {"value": 0, "calls": 0}
            def read():
                state["calls"] += 1
                if state["calls"] == 1: return 0
                if state["calls"] == 2: return 0
                if state["calls"] == 3: return 1
                # During FINAL runtime read, external writer replaces persistent target.
                Path(persistent).write_bytes(b"external\n")
                return 1
            def write(v):
                state["value"] = v
            r = self.execute(td, state, read_runtime=read, write_runtime=write)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_COMPENSATION)
            self.assertIn("postcheck:persistent-noncompliant", r.reason)
            self.assertIn("persistent:ownership-drift", r.reason)
            self.assertEqual(Path(persistent).read_bytes(), b"external\n")

    def _final_persistent_read_error_result(self, td, comp_fail=False):
        state = {"value": 0}
        real_snapshot = A.snapshot_persistent_target
        calls = {"n": 0}
        def snapshot_final_read_fail(path):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_snapshot(path)  # initial bound prestate
            if calls["n"] == 2:
                raise OSError("final persistent read failed")
            return real_snapshot(path)      # factual state after compensation/failure
        patchers = [mock.patch.object(A, "snapshot_persistent_target", side_effect=snapshot_final_read_fail)]
        if comp_fail:
            patchers.append(mock.patch.object(A, "compensate_persistent",
                                              side_effect=A.CompensationError("persistent:restore-failed")))
        for p in patchers: p.start()
        try:
            return self.execute(td, state)
        finally:
            for p in reversed(patchers): p.stop()

    # S060B/C: cause must remain factual, not be collapsed into generic noncompliance.
    def test_S060B_final_persistent_read_error_unchanged_compensation_success(self):
        with tempfile.TemporaryDirectory() as td:
            r = self._final_persistent_read_error_result(td, False)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)
            self.assertEqual(r.reason, "persistent:final-read-failure")
            self.assertIsNotNone(r.persistent_after)
            self.assertFalse(r.persistent_after.exists)

    def test_S060C_final_persistent_read_error_unchanged_compensation_failure(self):
        with tempfile.TemporaryDirectory() as td:
            r = self._final_persistent_read_error_result(td, True)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_COMPENSATION)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)
            self.assertEqual(
                r.reason,
                "persistent:final-read-failure;compensation:persistent:restore-failed",
            )
            self.assertIsNotNone(r.persistent_after)
            self.assertTrue(r.persistent_after.exists)

R15_REQUIRED_FIXTURES = ('runtime-ключ отсутствует и собственного файла нет -> NOT_APPLICABLE_KEY_ABSENT, мутаций нет', 'runtime-ключ отсутствует, а собственный файл существует -> NOT_APPLICABLE_KEY_ABSENT, существующий файл не изменяется и не удаляется', 'конфликтующее присвоение в /etc/sysctl.conf', 'конфликтующее присвоение в файле с лексикографически более поздним именем', 'конфликт в файле, скрытом одноимённым файлом более высокого приоритета — не конфликт', 'нечитаемый каталог или учитываемый источник -> ABORT', 'неоднозначное или нечисловое effective foreign assignment для ge -> ABORT', 'неудача runtime-фазы в ветке both с успешной persistent-компенсацией', 'неудача runtime-фазы в ветке both с неудачной persistent-компенсацией', 'ge: runtime_before выше expected, собственного persistent нет -> runtime не понижается; persistent может быть создан для сохранения target_value', 'ge: эффективный ранний чужой источник задаёт значение выше expected/runtime -> target_value сохраняет это effective foreign value', 'ge: собственный persistent value выше runtime_before -> runtime поднимается до target_value; persistent не понижается', 'persistent-only: после записи runtime перестал соответствовать target_value -> persistent компенсируется, runtime автоматически не записывается', 'нечисловое runtime-значение -> ABORT', 'persistent exact bytes совпадают, но uid/gid/mode не root:root/0644 -> persistent требует исправления', 'повторное применение при runtime+persistent соответствии одному target_value -> изменений нет', 'собственный файл предыдущего применения — не конфликт P2', 'dry-run: target_value и выбранная would-be ветка совпадают с APPLY при том же prestate; written_value=null, runtime/persistent не меняются', 'dry-run: NOT_APPLICABLE_KEY_ABSENT и precondition ABORT не выполняют мутаций и дают nonzero contribution по batch RC', 'phase1: отказ после rename на fsync каталога -> восстановление прежних bytes+uid+gid+mode либо удаление созданного target, NOT_COMMITTED', 'phase1: отказ post-rename проверки target -> та же persistent compensation', 'compensation: существующий файл с нестандартными прежними uid/gid/mode после отказа восстанавливается именно к прежним bytes+uid+gid+mode', 'ge: внешняя гонка после runtime_prewrite и до write обозначена как ограничение atomicity, не как доказанная no-lowering гарантия', 'eq: собственный файл с неразбираемым содержимым не вызывает ABORT сам по себе; он считается non-compliant и заменяется canonical bytes expected при APPLY', 'batch RC: нулевой вклад дают APPLIED, ALREADY_COMPLIANT и NOT_ELIGIBLE_APPLY_UNSUPPORTED; NOT_APPLICABLE_KEY_ABSENT и ABORTED_*/FAILED_* дают nonzero contribution', 'ge: runtime_prewrite вырос выше target_value после persistent-мутации -> запись пропускается, понижения нет, persistent коммитится, исход APPLIED, вклад в RC 0', 'ge: runtime_prewrite выше target_value без persistent-мутации -> мутаций нет, исход ALREADY_COMPLIANT, вклад в RC 0', 'eq: runtime_prewrite == target_value в ветке runtime_only -> запись пропускается, мутаций нет, исход ALREADY_COMPLIANT', 'ABORT по P2 при существующем собственном файле -> файл не изменяется и не удаляется, его состояние зафиксировано в отчёте', 'prewrite в ветке both: чтение runtime дало ошибку, ключ исчез либо значение нечисловое -> persistent компенсируется, исход FAILED_NOT_COMMITTED', 'prewrite в ветке both: та же ошибка и неудачная компенсация -> FAILED_COMPENSATION с фактическим состоянием', 'prewrite в ветке runtime_only: та же ошибка -> FAILED_NOT_COMMITTED, mutation_performed=false, persistent не изменяется', 'prestate фиксировал отсутствие target, но перед rename файл появился -> ABORT без rename, чужой файл не затирается', 'существующий target изменён другим процессом между снятием prestate и rename -> ABORT без rename, устаревший prestate не восстанавливается', 'на месте target символьная ссылка -> ABORT до мутации, ссылка не изменяется', 'на месте target обычный файл с st_nlink>1 -> ABORT до мутации', 'на месте target каталог, устройство, FIFO или сокет -> ABORT до мутации', 'контроль с apply.supported=false -> NOT_ELIGIBLE_APPLY_UNSUPPORTED, мутаций нет, вклад в RC 0', 'отчёт содержит actions_attempted, step_rc, mutation_performed и transaction_commit для каждого исхода, включая ABORT и FAILED_*', 'контроль с apply.supported=false в dry-run и в APPLY -> NOT_ELIGIBLE_APPLY_UNSUPPORTED до любых чтений; runtime и persistent не наблюдаются', 'st_nlink target вырос с 1 до 2 между snapshot и проверкой перед rename -> ABORT без rename', 'target подменён другим процессом после нашей записи, компенсация обязана сработать -> проверка принадлежности не совпала, чужой объект не затирается, исход FAILED_COMPENSATION', 'target отсутствовал до попытки, но на его месте оказался чужой объект к моменту компенсации -> удаление не выполняется, исход FAILED_COMPENSATION', 'target заменён между успешным primary rename и компенсацией -> сверка с attempt_written_identity не совпала, чужой объект не затирается, исход FAILED_COMPENSATION', 'созданный попыткой target заменён чужим объектом перед компенсационным unlink -> удаление не выполняется, исход FAILED_COMPENSATION', 'attempt_written_identity фиксируется после primary rename и присутствует в отчёте попытки, завершившейся компенсацией', 'отказ fsync каталога сразу после rename -> attempt_written_identity уже существует, компенсация выполняется по нему', 'отказ сверки target с prepared_identity после rename -> компенсация выполняется по тому же снимку', 'persistent rename не выполнялся -> attempt_written_identity в отчёте равен null', 'компенсация на ветви восстановления существовавшего файла: target подменён чужим объектом между входной сверкой и компенсационным rename -> вторая сверка с attempt_written_identity не совпала, чужой объект не перезаписывается, prestate не восстанавливается, исход FAILED_COMPENSATION с фактическим состоянием', 'собственный файл существует на этапе P2 и затеняет одноимённый чужой источник с большим значением, но исчезает между P2 и снимком целевого объекта -> ABORT без мутации; запрещено считать target_value без затенённого чужого значения и создавать файл с меньшим значением', 'ветка runtime_only без предшествующей persistent-мутации: отказ записи runtime до передачи первого байта (например отказ открытия пути) -> mutation_performed=false И written_value=null; runtime_after фиксируется фактическим. Случай той же ошибки после выполненной persistent-мутации описан отдельной фикстурой и даёт mutation_performed=true.', 'отказ компенсации после отказа post-rename -> отчёт содержит и код исходного отказа, и собственный код отказа компенсации, и фактическое состояние target', 'ветка both: persistent-мутация выполнена и затем компенсирована, а runtime-запись отказала до передачи первого байта -> mutation_performed=true (из-за persistent-мутации), written_value=null (запись не начиналась), исход FAILED_NOT_COMMITTED', 'S006: P1: initial runtime read returns an access/read error while the key is not proven absent -> ABORTED_PRECONDITION_OTHER, no persistent/runtime mutation, written_value=null.', 'S010: Persistent target prestate cannot be read/snapshotted while P1/P2 succeeded -> ABORTED_PRECONDITION_OTHER before mutation; unreadable is not treated as absent.', 'S012: op=ge and existing own persistent file cannot be unambiguously parsed as one integer assignment for the key -> ABORTED_PRECONDITION_OTHER before mutation; own file is not overwritten.', 'S017: Own persistent file is absent during P2, so a same-basename file in a lower-priority sysctl.d directory is not shadowed and participates in effective precedence.', 'S021: A foreign .conf source that is a symbolic link to a readable regular file is read through the link and participates in P2 according to its logical source path.', 'S022: A foreign .conf source that resolves to /dev/null is treated as an empty source and does not cause ABORT.', 'S024: For ge, only the final effective applicable assignment is parsed for effective_foreign_value: an earlier invalid assignment overridden by a later valid assignment does not itself cause ABORT.', 'S025: P3 write privilege/access failure after successful read-only planning -> ABORTED_PRECONDITION_OTHER before any target mutation.', 'S033: Straight-line both branch: persistent mutation succeeds, runtime write succeeds and both final checks pass -> APPLIED, mutation_performed=true, written_value=target_value, COMMITTED.', 'S035: Opposite observation-binding race to fixture 51: own file is absent during P2 but appears before the bound persistent prestate is established -> ABORTED_PRECONDITION_OTHER without mutation; mixed-time planning is forbidden.', 'S039: Phase1 failure before primary rename -> FAILED_NOT_COMMITTED, mutation_performed=false, attempt_written_identity=null; target remains at prestate and temporary object is cleaned.', 'S051: runtime_only: runtime write starts (at least one byte/value is actually passed) and then fails -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value; persistent is not compensated.', 'S052: both: persistent mutation succeeded, runtime write starts and then fails -> persistent compensation is attempted; with successful compensation outcome FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.', 'S053A: runtime_only: runtime write completes but immediate runtime-phase post-check read fails -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value; no persistent compensation.', 'S054: runtime_only: runtime write completes, immediate runtime-phase post-check reads a noncompliant value -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.', 'S057: persistent_only: final runtime check is noncompliant and required persistent compensation fails -> FAILED_COMPENSATION, mutation_performed=true, written_value=null.', 'S058: runtime_only: runtime phase succeeds but final persistent check is noncompliant/drifted -> FAILED_NOT_COMMITTED without persistent compensation; mutation_performed=true and written_value=target_value.', 'S059A: both: runtime phase immediate post-check passes, then FINAL runtime check becomes noncompliant; persistent compensation succeeds -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.', 'S059B: both: runtime phase immediate post-check passes, then FINAL runtime check becomes noncompliant; persistent compensation fails -> FAILED_COMPENSATION, mutation_performed=true, written_value=target_value.', 'S060B: both: runtime phase succeeds; FINAL persistent read/snapshot fails while the written target object itself remains unchanged; persistent compensation succeeds -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.', 'S060C: both: same unchanged-object FINAL persistent read/snapshot failure, but persistent compensation fails -> FAILED_COMPENSATION, mutation_performed=true, written_value=target_value.', 'S072: Reporting bootstrap refusal before control execution still leaves report.json written with the refusal/crash fact; failure to initialize a sibling log does not erase the report.', 'S073: Batch with a terminal nonzero-contributing control result continues to the next control; report contains both controls and overall RC remains nonzero.')
R15_FIXTURE_EXECUTION_MAP = dict(R11_FIXTURE_EXECUTION_MAP)
R15_FIXTURE_EXECUTION_MAP.update({51: ('test_S034_B10_own_disappears_between_P2_and_prestate_aborts',), 52: ('test_S049_B12_runtime_only_no_byte_failure_has_no_written_value_or_mutation',), 53: ('test_S042_B11_phase1_failed_compensation_reports_both_reasons',), 54: ('test_S050_B12_both_no_byte_failure_keeps_persistent_mutation_fact_but_no_written_value',), 55: ('test_S006_initial_runtime_read_error_aborts_without_mutation',), 56: ('test_S010_persistent_prestate_unreadable_is_abort_not_absent',), 57: ('test_ge_unparseable_own_persistent_aborts_before_mutation',), 58: ('test_b06_absent_own_does_not_shadow_lower_same_basename',), 59: ('test_rv2_b01_symlink_to_regular_foreign_source_is_read',), 60: ('test_loader_dev_null_symlink_is_empty_source',), 61: ('test_b09_only_final_effective_assignment_is_parsed',), 62: ('test_privilege_failure_aborts_before_mutation',), 63: ('test_both_success',), 64: ('test_S035_own_appears_between_P2_and_prestate_aborts',), 65: ('test_S039_phase1_failure_before_rename_is_not_mutation',), 66: ('test_rv2_b02_write_failure_after_runtime_change_is_reported_as_mutation',), 67: ('test_S052_both_started_write_failure_reports_written_and_compensates',), 68: ('test_S053A_runtime_only_postcheck_read_failure',), 69: ('test_S054_runtime_only_completed_write_postcheck_noncompliant',), 70: ('test_S057_persistent_only_final_runtime_drift_compensation_failure',), 71: ('test_runtime_only_persistent_external_drift_is_failed_not_committed_without_compensation',), 72: ('test_S059A_both_final_runtime_drift_compensation_success',), 73: ('test_S059B_both_final_runtime_drift_compensation_failure',), 74: ('test_S060B_final_persistent_read_error_unchanged_compensation_success',), 75: ('test_S060C_final_persistent_read_error_unchanged_compensation_failure',), 76: ('test_reporting_bootstrap_refusal_still_writes_report',), 77: ('test_real_batch_continues_to_second_control_after_runtime_write_failure',)})


class R15FrozenFixtureCoverage(unittest.TestCase):
    def test_r15_fixture_list_preserves_r11_and_has_77(self):
        self.assertEqual(len(R15_REQUIRED_FIXTURES), 77)
        self.assertEqual(R15_REQUIRED_FIXTURES[:50], R11_REQUIRED_FIXTURES)
        self.assertEqual(set(R15_FIXTURE_EXECUTION_MAP), set(range(1, 78)))

    def test_r15_fixture_execution_matrix_77_of_77(self):
        for fixture_no in range(1, 78):
            tests = R15_FIXTURE_EXECUTION_MAP[fixture_no]
            self.assertTrue(tests, fixture_no)
            for test_name in tests:
                lines, functions = _run_named_test_with_adapter_trace(test_name)
                if fixture_no != 23:
                    self.assertTrue(lines, (fixture_no, test_name, functions))


class R16FrozenScope(unittest.TestCase):
    KEY = "kernel.dmesg_restrict"

    def canonical(self, value=1):
        return A.canonical_persistent_bytes(self.KEY, value)

    def paths(self, td):
        return (
            str(Path(td) / "zz-securelinux-policy-kernel-dmesg_restrict.conf"),
            str(Path(td) / "runtime"),
        )

    def execute(self, td, runtime_state=None, *, persistent_bytes=None,
                read_runtime=None, write_runtime=None, privilege_check=None):
        if runtime_state is None:
            runtime_state = {"value": 1, "writes": []}
        persistent, runtime = self.paths(td)
        if persistent_bytes is not None:
            Path(persistent).write_bytes(persistent_bytes)
            Path(persistent).chmod(0o644)
        if read_runtime is None:
            read_runtime = lambda: runtime_state["value"]
        if write_runtime is None:
            def write_runtime(v):
                runtime_state.setdefault("writes", []).append(v)
                runtime_state["value"] = v
        if privilege_check is None:
            privilege_check = lambda: None
        return A.execute_control(
            "R16", self.KEY, "eq", 1, True, (),
            persistent_target=persistent,
            runtime_target=runtime,
            read_runtime=read_runtime,
            write_runtime=write_runtime,
            write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
            privilege_check=privilege_check,
            persistent_uid=os.getuid(), persistent_gid=os.getgid(), persistent_mode=0o644,
        )

    def _sequence_reader(self, values):
        seq = list(values)
        calls = {"n": 0}
        def read():
            i = calls["n"]
            calls["n"] += 1
            item = seq[i]
            if isinstance(item, BaseException):
                raise item
            return item
        return read, calls

    # S075 / B-14
    def test_S075_final_runtime_read_error_already_exact_reason(self):
        with tempfile.TemporaryDirectory() as td:
            read, _ = self._sequence_reader([1, OSError("final runtime read failed")])
            r = self.execute(td, persistent_bytes=self.canonical(), read_runtime=read)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "runtime:final-read-failure")
            self.assertIsNone(r.runtime_after)
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)

    # S076 / B-14
    def test_S076_final_runtime_parse_error_already_exact_reason(self):
        with tempfile.TemporaryDirectory() as td:
            read, _ = self._sequence_reader([1, "not-an-int"])
            r = self.execute(td, persistent_bytes=self.canonical(), read_runtime=read)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "runtime:final-parse-failure")
            self.assertIsNone(r.runtime_after)
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)

    # S077 / B-14
    def test_S077_final_runtime_read_error_runtime_only_preserves_write_facts(self):
        with tempfile.TemporaryDirectory() as td:
            state = {"value": 0, "writes": []}
            read, _ = self._sequence_reader([0, 0, 1, OSError("final runtime read failed")])
            def write(v):
                state["writes"].append(v)
                state["value"] = v
            r = self.execute(td, state, persistent_bytes=self.canonical(),
                             read_runtime=read, write_runtime=write)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "runtime:final-read-failure")
            self.assertIsNone(r.runtime_after)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)

    # S078 / B-14
    def test_S078_final_runtime_parse_error_runtime_only_preserves_write_facts(self):
        with tempfile.TemporaryDirectory() as td:
            state = {"value": 0, "writes": []}
            read, _ = self._sequence_reader([0, 0, 1, "bad-final"])
            def write(v):
                state["writes"].append(v)
                state["value"] = v
            r = self.execute(td, state, persistent_bytes=self.canonical(),
                             read_runtime=read, write_runtime=write)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "runtime:final-parse-failure")
            self.assertIsNone(r.runtime_after)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)

    def _both_final_runtime_failure(self, td, final_item, compensation_failure=False):
        state = {"value": 0, "writes": []}
        read, _ = self._sequence_reader([0, 0, 1, final_item])
        def write(v):
            state["writes"].append(v)
            state["value"] = v
        kwargs = {}
        if compensation_failure:
            kwargs["side_effect"] = A.CompensationError("persistent:forced-compensation-failure")
        else:
            kwargs["wraps"] = A.compensate_persistent
        with mock.patch.object(A, "compensate_persistent", **kwargs):
            r = self.execute(td, state, read_runtime=read, write_runtime=write)
        return r, state

    # S079 / B-14
    def test_S079_final_runtime_read_error_both_compensation_success(self):
        with tempfile.TemporaryDirectory() as td:
            r, _ = self._both_final_runtime_failure(td, OSError("final read"), False)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "runtime:final-read-failure")
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)

    # S080 / B-14
    def test_S080_final_runtime_read_error_both_compensation_failure(self):
        with tempfile.TemporaryDirectory() as td:
            r, _ = self._both_final_runtime_failure(td, OSError("final read"), True)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_COMPENSATION)
            self.assertIn("runtime:final-read-failure", r.reason)
            self.assertIn("persistent:forced-compensation-failure", r.reason)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)

    # S081 / B-14
    def test_S081_final_runtime_parse_error_both_compensation_success(self):
        with tempfile.TemporaryDirectory() as td:
            r, _ = self._both_final_runtime_failure(td, "bad-final", False)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "runtime:final-parse-failure")
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)

    # S082 / B-14
    def test_S082_final_runtime_parse_error_both_compensation_failure(self):
        with tempfile.TemporaryDirectory() as td:
            r, _ = self._both_final_runtime_failure(td, "bad-final", True)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_COMPENSATION)
            self.assertIn("runtime:final-parse-failure", r.reason)
            self.assertIn("persistent:forced-compensation-failure", r.reason)
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)

    def _transient_final_persistent_snapshot_failure(self, td, *, runtime_only):
        original = A.snapshot_persistent_target
        calls = {"n": 0}
        fail_at = 3 if runtime_only else 2
        def snap(path):
            calls["n"] += 1
            if calls["n"] == fail_at:
                raise OSError("transient final persistent read")
            return original(path)
        state = {"value": 0 if runtime_only else 1, "writes": []}
        persistent_bytes = self.canonical()
        def write(v):
            state["writes"].append(v)
            state["value"] = v
        with mock.patch.object(A, "snapshot_persistent_target", side_effect=snap):
            r = self.execute(td, state, persistent_bytes=persistent_bytes, write_runtime=write)
        return r, state

    # S083 symmetry: expected GREEN on current r15 bytes.
    def test_S083_final_persistent_read_error_runtime_only_exact_reason(self):
        with tempfile.TemporaryDirectory() as td:
            r, _ = self._transient_final_persistent_snapshot_failure(td, runtime_only=True)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "persistent:final-read-failure")
            self.assertTrue(r.mutation_performed)
            self.assertEqual(r.written_value, 1)
            self.assertIsNotNone(r.persistent_after)
            self.assertTrue(r.persistent_after.exists)

    # S084 symmetry: expected GREEN on current r15 bytes.
    def test_S084_final_persistent_read_error_already_exact_reason(self):
        with tempfile.TemporaryDirectory() as td:
            r, _ = self._transient_final_persistent_snapshot_failure(td, runtime_only=False)
            self.assertEqual(r.outcome, A.OUTCOME_FAILED_NOT_COMMITTED)
            self.assertEqual(r.reason, "persistent:final-read-failure")
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)
            self.assertIsNotNone(r.persistent_after)
            self.assertTrue(r.persistent_after.exists)

    # S085 / B-15: untrusted callback must not be invoked.
    def test_S085_untrusted_injected_writer_is_rejected_before_P1_and_invocation(self):
        with tempfile.TemporaryDirectory() as td:
            calls = {"read": 0, "write": 0}
            state = {"value": 0}
            persistent, _ = self.paths(td)
            Path(persistent).write_bytes(self.canonical())
            Path(persistent).chmod(0o644)
            def read():
                calls["read"] += 1
                return state["value"]
            def untrusted_write(v):
                calls["write"] += 1
                state["value"] = v
                raise OSError("generic external writer failure after mutation")
            r = A.execute_control(
                "R16", self.KEY, "eq", 1, True, (),
                persistent_target=persistent,
                runtime_target=str(Path(td) / "runtime"),
                read_runtime=read,
                write_runtime=untrusted_write,
                privilege_check=lambda: None,
                persistent_uid=os.getuid(), persistent_gid=os.getgid(), persistent_mode=0o644,
            )
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertEqual(r.reason, "runtime:writer-protocol-required")
            self.assertEqual(calls["read"], 0)
            self.assertEqual(calls["write"], 0)
            self.assertEqual(state["value"], 0)
            self.assertFalse(r.mutation_performed)
            self.assertIsNone(r.written_value)


class R16WriterProtocolBoundary(unittest.TestCase):
    KEY = "kernel.dmesg_restrict"

    def test_missing_protocol_is_checked_after_P0_eligibility(self):
        calls = {"read": 0, "write": 0}
        def read():
            calls["read"] += 1
            return 0
        def write(value):
            calls["write"] += 1
        r = A.execute_control(
            "R16-P0", self.KEY, "eq", 1, False, (),
            persistent_target="/unused/persistent", runtime_target="/unused/runtime",
            read_runtime=read, write_runtime=write, privilege_check=lambda: None,
        )
        self.assertEqual(r.outcome, A.OUTCOME_NOT_ELIGIBLE)
        self.assertEqual(calls, {"read": 0, "write": 0})

    def test_declared_v1_generic_writer_failure_is_protocol_violation_not_false_result(self):
        with tempfile.TemporaryDirectory() as td:
            persistent = Path(td) / "target.conf"
            persistent.write_bytes(A.canonical_persistent_bytes(self.KEY, 1))
            persistent.chmod(0o644)
            runtime = {"value": 0}
            def bad_writer(value):
                runtime["value"] = value
                raise OSError("declared writer violated V1 after mutation")
            with self.assertRaises(A.RuntimeWriterProtocolViolation):
                A.execute_control(
                    "R16-PROTOCOL", self.KEY, "eq", 1, True, (),
                    persistent_target=str(persistent), runtime_target=str(Path(td) / "runtime"),
                    read_runtime=lambda: runtime["value"],
                    write_runtime=bad_writer,
                    write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                    privilege_check=lambda: None,
                    persistent_uid=os.getuid(), persistent_gid=os.getgid(), persistent_mode=0o644,
                )
            self.assertEqual(runtime["value"], 1)


class B20ObservationBindingRegression(unittest.TestCase):
    KEY = "kernel.dmesg_restrict"

    def test_b20_runtime_only_persistent_drift_aborts_before_runtime_write(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            persistent = Path(td) / "target.conf"
            persistent.write_bytes(A.canonical_persistent_bytes(self.KEY, 1))
            persistent.chmod(0o644)
            writes = []
            calls = {"read": 0}

            def read_runtime():
                calls["read"] += 1
                if calls["read"] == 2:
                    persistent.write_bytes(A.canonical_persistent_bytes(self.KEY, 2))
                    persistent.chmod(0o644)
                return 0

            result = A.execute_control(
                "B20-DRIFT", self.KEY, "eq", 1, True, (),
                persistent_target=str(persistent),
                runtime_target=str(Path(td) / "runtime"),
                read_runtime=read_runtime,
                write_runtime=lambda value: writes.append(value),
                write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                privilege_check=lambda: None,
                persistent_uid=uid, persistent_gid=gid, persistent_mode=0o644,
            )

            self.assertEqual(result.branch, A.BRANCH_RUNTIME_ONLY)
            self.assertEqual(result.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertIn("persistent:drift-before-runtime", result.reason)
            self.assertEqual(result.runtime_prewrite, 0)
            self.assertEqual(writes, [])
            self.assertFalse(result.mutation_performed)
            self.assertIsNone(result.written_value)
            self.assertEqual(result.transaction_commit, A.COMMIT_NOT_STARTED)
            self.assertEqual(
                persistent.read_bytes(),
                A.canonical_persistent_bytes(self.KEY, 2),
            )

    def test_b20_runtime_only_unchanged_persistent_allows_runtime_write(self):
        uid, gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as td:
            persistent = Path(td) / "target.conf"
            persistent.write_bytes(A.canonical_persistent_bytes(self.KEY, 1))
            persistent.chmod(0o644)
            state = {"value": 0}
            writes = []

            def write_runtime(value):
                writes.append(value)
                state["value"] = value

            result = A.execute_control(
                "B20-STABLE", self.KEY, "eq", 1, True, (),
                persistent_target=str(persistent),
                runtime_target=str(Path(td) / "runtime"),
                read_runtime=lambda: state["value"],
                write_runtime=write_runtime,
                write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
                privilege_check=lambda: None,
                persistent_uid=uid, persistent_gid=gid, persistent_mode=0o644,
            )

            self.assertEqual(result.branch, A.BRANCH_RUNTIME_ONLY)
            self.assertEqual(result.outcome, A.OUTCOME_APPLIED)
            self.assertEqual(result.runtime_prewrite, 0)
            self.assertEqual(writes, [1])
            self.assertTrue(result.mutation_performed)
            self.assertEqual(result.written_value, 1)
            self.assertEqual(result.transaction_commit, A.COMMIT_COMMITTED)
            self.assertEqual(
                persistent.read_bytes(),
                A.canonical_persistent_bytes(self.KEY, 1),
            )


R16_REQUIRED_FIXTURES = ('runtime-ключ отсутствует и собственного файла нет -> NOT_APPLICABLE_KEY_ABSENT, мутаций нет', 'runtime-ключ отсутствует, а собственный файл существует -> NOT_APPLICABLE_KEY_ABSENT, существующий файл не изменяется и не удаляется', 'конфликтующее присвоение в /etc/sysctl.conf', 'конфликтующее присвоение в файле с лексикографически более поздним именем', 'конфликт в файле, скрытом одноимённым файлом более высокого приоритета — не конфликт', 'нечитаемый каталог или учитываемый источник -> ABORT', 'неоднозначное или нечисловое effective foreign assignment для ge -> ABORT', 'неудача runtime-фазы в ветке both с успешной persistent-компенсацией', 'неудача runtime-фазы в ветке both с неудачной persistent-компенсацией', 'ge: runtime_before выше expected, собственного persistent нет -> runtime не понижается; persistent может быть создан для сохранения target_value', 'ge: эффективный ранний чужой источник задаёт значение выше expected/runtime -> target_value сохраняет это effective foreign value', 'ge: собственный persistent value выше runtime_before -> runtime поднимается до target_value; persistent не понижается', 'persistent-only: после записи runtime перестал соответствовать target_value -> persistent компенсируется, runtime автоматически не записывается', 'нечисловое runtime-значение -> ABORT', 'persistent exact bytes совпадают, но uid/gid/mode не root:root/0644 -> persistent требует исправления', 'повторное применение при runtime+persistent соответствии одному target_value -> изменений нет', 'собственный файл предыдущего применения — не конфликт P2', 'dry-run: target_value и выбранная would-be ветка совпадают с APPLY при том же prestate; written_value=null, runtime/persistent не меняются', 'dry-run: NOT_APPLICABLE_KEY_ABSENT и precondition ABORT не выполняют мутаций и дают nonzero contribution по batch RC', 'phase1: отказ после rename на fsync каталога -> восстановление прежних bytes+uid+gid+mode либо удаление созданного target, NOT_COMMITTED', 'phase1: отказ post-rename проверки target -> та же persistent compensation', 'compensation: существующий файл с нестандартными прежними uid/gid/mode после отказа восстанавливается именно к прежним bytes+uid+gid+mode', 'ge: внешняя гонка после runtime_prewrite и до write обозначена как ограничение atomicity, не как доказанная no-lowering гарантия', 'eq: собственный файл с неразбираемым содержимым не вызывает ABORT сам по себе; он считается non-compliant и заменяется canonical bytes expected при APPLY', 'batch RC: нулевой вклад дают APPLIED, ALREADY_COMPLIANT и NOT_ELIGIBLE_APPLY_UNSUPPORTED; NOT_APPLICABLE_KEY_ABSENT и ABORTED_*/FAILED_* дают nonzero contribution', 'ge: runtime_prewrite вырос выше target_value после persistent-мутации -> запись пропускается, понижения нет, persistent коммитится, исход APPLIED, вклад в RC 0', 'ge: runtime_prewrite выше target_value без persistent-мутации -> мутаций нет, исход ALREADY_COMPLIANT, вклад в RC 0', 'eq: runtime_prewrite == target_value в ветке runtime_only -> запись пропускается, мутаций нет, исход ALREADY_COMPLIANT', 'ABORT по P2 при существующем собственном файле -> файл не изменяется и не удаляется, его состояние зафиксировано в отчёте', 'prewrite в ветке both: чтение runtime дало ошибку, ключ исчез либо значение нечисловое -> persistent компенсируется, исход FAILED_NOT_COMMITTED', 'prewrite в ветке both: та же ошибка и неудачная компенсация -> FAILED_COMPENSATION с фактическим состоянием', 'prewrite в ветке runtime_only: та же ошибка -> FAILED_NOT_COMMITTED, mutation_performed=false, persistent не изменяется', 'prestate фиксировал отсутствие target, но перед rename файл появился -> ABORT без rename, чужой файл не затирается', 'существующий target изменён другим процессом между снятием prestate и rename -> ABORT без rename, устаревший prestate не восстанавливается', 'на месте target символьная ссылка -> ABORT до мутации, ссылка не изменяется', 'на месте target обычный файл с st_nlink>1 -> ABORT до мутации', 'на месте target каталог, устройство, FIFO или сокет -> ABORT до мутации', 'контроль с apply.supported=false -> NOT_ELIGIBLE_APPLY_UNSUPPORTED, мутаций нет, вклад в RC 0', 'отчёт содержит actions_attempted, step_rc, mutation_performed и transaction_commit для каждого исхода, включая ABORT и FAILED_*', 'контроль с apply.supported=false в dry-run и в APPLY -> NOT_ELIGIBLE_APPLY_UNSUPPORTED до любых чтений; runtime и persistent не наблюдаются', 'st_nlink target вырос с 1 до 2 между snapshot и проверкой перед rename -> ABORT без rename', 'target подменён другим процессом после нашей записи, компенсация обязана сработать -> проверка принадлежности не совпала, чужой объект не затирается, исход FAILED_COMPENSATION', 'target отсутствовал до попытки, но на его месте оказался чужой объект к моменту компенсации -> удаление не выполняется, исход FAILED_COMPENSATION', 'target заменён между успешным primary rename и компенсацией -> сверка с attempt_written_identity не совпала, чужой объект не затирается, исход FAILED_COMPENSATION', 'созданный попыткой target заменён чужим объектом перед компенсационным unlink -> удаление не выполняется, исход FAILED_COMPENSATION', 'attempt_written_identity фиксируется после primary rename и присутствует в отчёте попытки, завершившейся компенсацией', 'отказ fsync каталога сразу после rename -> attempt_written_identity уже существует, компенсация выполняется по нему', 'отказ сверки target с prepared_identity после rename -> компенсация выполняется по тому же снимку', 'persistent rename не выполнялся -> attempt_written_identity в отчёте равен null', 'компенсация на ветви восстановления существовавшего файла: target подменён чужим объектом между входной сверкой и компенсационным rename -> вторая сверка с attempt_written_identity не совпала, чужой объект не перезаписывается, prestate не восстанавливается, исход FAILED_COMPENSATION с фактическим состоянием', 'собственный файл существует на этапе P2 и затеняет одноимённый чужой источник с большим значением, но исчезает между P2 и снимком целевого объекта -> ABORT без мутации; запрещено считать target_value без затенённого чужого значения и создавать файл с меньшим значением', 'ветка runtime_only без предшествующей persistent-мутации: отказ записи runtime до передачи первого байта (например отказ открытия пути) -> mutation_performed=false И written_value=null; runtime_after фиксируется фактическим. Случай той же ошибки после выполненной persistent-мутации описан отдельной фикстурой и даёт mutation_performed=true.', 'отказ компенсации после отказа post-rename -> отчёт содержит и код исходного отказа, и собственный код отказа компенсации, и фактическое состояние target', 'ветка both: persistent-мутация выполнена и затем компенсирована, а runtime-запись отказала до передачи первого байта -> mutation_performed=true (из-за persistent-мутации), written_value=null (запись не начиналась), исход FAILED_NOT_COMMITTED', 'S006: P1: initial runtime read returns an access/read error while the key is not proven absent -> ABORTED_PRECONDITION_OTHER, no persistent/runtime mutation, written_value=null.', 'S010: Persistent target prestate cannot be read/snapshotted while P1/P2 succeeded -> ABORTED_PRECONDITION_OTHER before mutation; unreadable is not treated as absent.', 'S012: op=ge and existing own persistent file cannot be unambiguously parsed as one integer assignment for the key -> ABORTED_PRECONDITION_OTHER before mutation; own file is not overwritten.', 'S017: Own persistent file is absent during P2, so a same-basename file in a lower-priority sysctl.d directory is not shadowed and participates in effective precedence.', 'S021: A foreign .conf source that is a symbolic link to a readable regular file is read through the link and participates in P2 according to its logical source path.', 'S022: A foreign .conf source that resolves to /dev/null is treated as an empty source and does not cause ABORT.', 'S024: For ge, only the final effective applicable assignment is parsed for effective_foreign_value: an earlier invalid assignment overridden by a later valid assignment does not itself cause ABORT.', 'S025: P3 write privilege/access failure after successful read-only planning -> ABORTED_PRECONDITION_OTHER before any target mutation.', 'S033: Straight-line both branch: persistent mutation succeeds, runtime write succeeds and both final checks pass -> APPLIED, mutation_performed=true, written_value=target_value, COMMITTED.', 'S035: Opposite observation-binding race to fixture 51: own file is absent during P2 but appears before the bound persistent prestate is established -> ABORTED_PRECONDITION_OTHER without mutation; mixed-time planning is forbidden.', 'S039: Phase1 failure before primary rename -> FAILED_NOT_COMMITTED, mutation_performed=false, attempt_written_identity=null; target remains at prestate and temporary object is cleaned.', 'S051: runtime_only: runtime write starts (at least one byte/value is actually passed) and then fails -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value; persistent is not compensated.', 'S052: both: persistent mutation succeeded, runtime write starts and then fails -> persistent compensation is attempted; with successful compensation outcome FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.', 'S053A: runtime_only: runtime write completes but immediate runtime-phase post-check read fails -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value; no persistent compensation.', 'S054: runtime_only: runtime write completes, immediate runtime-phase post-check reads a noncompliant value -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.', 'S057: persistent_only: final runtime check is noncompliant and required persistent compensation fails -> FAILED_COMPENSATION, mutation_performed=true, written_value=null.', 'S058: runtime_only: runtime phase succeeds but final persistent check is noncompliant/drifted -> FAILED_NOT_COMMITTED without persistent compensation; mutation_performed=true and written_value=target_value.', 'S059A: both: runtime phase immediate post-check passes, then FINAL runtime check becomes noncompliant; persistent compensation succeeds -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.', 'S059B: both: runtime phase immediate post-check passes, then FINAL runtime check becomes noncompliant; persistent compensation fails -> FAILED_COMPENSATION, mutation_performed=true, written_value=target_value.', 'S060B: both: runtime phase succeeds; FINAL persistent read/snapshot fails while the written target object itself remains unchanged; persistent compensation succeeds -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.', 'S060C: both: same unchanged-object FINAL persistent read/snapshot failure, but persistent compensation fails -> FAILED_COMPENSATION, mutation_performed=true, written_value=target_value.', 'S072: Reporting bootstrap refusal before control execution still leaves report.json written with the refusal/crash fact; failure to initialize a sibling log does not erase the report.', 'S073: Batch with a terminal nonzero-contributing control result continues to the next control; report contains both controls and overall RC remains nonzero.', 'S075: branch already/no prior mutation: FINAL runtime read fails -> FAILED_NOT_COMMITTED, reason=runtime:final-read-failure, runtime_after=null, mutation_performed=false, written_value=null; read failure is not reported as runtime-noncompliant.', 'S076: branch already/no prior mutation: FINAL runtime returns a non-integer -> FAILED_NOT_COMMITTED, reason=runtime:final-parse-failure, runtime_after=null, mutation_performed=false, written_value=null.', 'S077: runtime_only after a successful runtime write: FINAL runtime read fails -> FAILED_NOT_COMMITTED without persistent compensation; mutation_performed=true, written_value=target_value, reason=runtime:final-read-failure.', 'S078: runtime_only after a successful runtime write: FINAL runtime is non-integer -> FAILED_NOT_COMMITTED without persistent compensation; mutation_performed=true, written_value=target_value, reason=runtime:final-parse-failure.', 'S079: both after persistent mutation and successful runtime phase: FINAL runtime read fails; persistent compensation succeeds -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value, original reason runtime:final-read-failure retained.', 'S080: same FINAL runtime read failure in both, but persistent compensation fails -> FAILED_COMPENSATION containing both runtime:final-read-failure and exact compensation code; mutation_performed=true, written_value=target_value.', 'S081: both after persistent mutation and successful runtime phase: FINAL runtime parse fails; persistent compensation succeeds -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value, original reason runtime:final-parse-failure retained.', 'S082: same FINAL runtime parse failure in both, but persistent compensation fails -> FAILED_COMPENSATION containing both runtime:final-parse-failure and exact compensation code; mutation_performed=true, written_value=target_value.', 'S083: runtime_only with no persistent mutation: FINAL persistent snapshot/read fails after successful runtime write -> FAILED_NOT_COMMITTED, reason=persistent:final-read-failure, no persistent compensation, mutation_performed=true, written_value=target_value; the observation failure is not reported as persistent-noncompliant.', 'S084: already-compliant branch with no mutation: FINAL persistent snapshot/read fails -> FAILED_NOT_COMMITTED, reason=persistent:final-read-failure, no compensation, mutation_performed=false, written_value=null.', 'S085: an injected runtime writer without SLP_RUNTIME_WRITER_V1 declaration is rejected after P0 but before P1 and before invocation -> ABORTED_PRECONDITION_OTHER, reason=runtime:writer-protocol-required, mutation_performed=false, written_value=null; state is not guessed from runtime_after. Declared V1 writer failures are governed by existing before-first-byte/started-write fixtures.')
R16_FIXTURE_EXECUTION_MAP = dict(R15_FIXTURE_EXECUTION_MAP)
R16_FIXTURE_EXECUTION_MAP.update({78: ('test_S075_final_runtime_read_error_already_exact_reason',), 79: ('test_S076_final_runtime_parse_error_already_exact_reason',), 80: ('test_S077_final_runtime_read_error_runtime_only_preserves_write_facts',), 81: ('test_S078_final_runtime_parse_error_runtime_only_preserves_write_facts',), 82: ('test_S079_final_runtime_read_error_both_compensation_success',), 83: ('test_S080_final_runtime_read_error_both_compensation_failure',), 84: ('test_S081_final_runtime_parse_error_both_compensation_success',), 85: ('test_S082_final_runtime_parse_error_both_compensation_failure',), 86: ('test_S083_final_persistent_read_error_runtime_only_exact_reason',), 87: ('test_S084_final_persistent_read_error_already_exact_reason',), 88: ('test_S085_untrusted_injected_writer_is_rejected_before_P1_and_invocation',)})


class R16FrozenFixtureCoverage(unittest.TestCase):
    def test_r16_fixture_list_preserves_r15_and_has_88(self):
        self.assertEqual(len(R16_REQUIRED_FIXTURES), 88)
        self.assertEqual(R16_REQUIRED_FIXTURES[:77], R15_REQUIRED_FIXTURES)
        self.assertEqual(set(R16_FIXTURE_EXECUTION_MAP), set(range(1, 89)))

    def test_r16_fixture_execution_matrix_88_of_88(self):
        for fixture_no in range(1, 89):
            tests = R16_FIXTURE_EXECUTION_MAP[fixture_no]
            self.assertTrue(tests, fixture_no)
            for test_name in tests:
                lines, functions = _run_named_test_with_adapter_trace(test_name)
                if fixture_no != 23:
                    self.assertTrue(lines, (fixture_no, test_name, functions))


import hashlib as _hashlib

CONTRACT_PATH = ROOT / "product" / "contracts" / "mechanism-config-line-runtime-v1.json"


class RuntimeWriterConflictP2R(unittest.TestCase):
    """H46-D16 P2R detector and execute_control integration."""

    KEY = "fs.suid_dumpable"
    INIT_BYTES = b"#! /bin/sh\n# fixture init-script bytes\n"
    DEFAULT_BYTES = b"enabled=1\n"

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name) / "root"
        self.root.mkdir()
        self.work = Path(td.name) / "work"
        self.work.mkdir()
        for name, data in (("APPORT_INIT_SCRIPT_SHA256", self.INIT_BYTES), ("APPORT_DEFAULT_ENABLED_SHA256", self.DEFAULT_BYTES)):
            patcher = mock.patch.object(A, name, frozenset({_hashlib.sha256(data).hexdigest()}))
            patcher.start()
            self.addCleanup(patcher.stop)
        # Fixture files may live on a noexec temporary mount: X_OK for paths inside
        # the fixture root is evaluated from permission bits, other paths are unchanged.
        real_access = os.access
        root_prefix = str(self.root) + os.sep

        def fixture_access(path, mode, *args, **kwargs):
            text = os.fspath(path)
            if mode == os.X_OK and text.startswith(root_prefix):
                try:
                    return bool(os.stat(text).st_mode & 0o111)
                except OSError:
                    return False
            return real_access(path, mode, *args, **kwargs)

        access_patcher = mock.patch.object(A.os, "access", side_effect=fixture_access)
        access_patcher.start()
        self.addCleanup(access_patcher.stop)
        self._write(A.APPORT_INIT_SCRIPT, self.INIT_BYTES, 0o755)
        self._write(A.APPORT_AGENT, b"#!/bin/sh\n", 0o755)
        self._write(A.PID1_ENVIRON, b"PATH=/usr/bin\0HOME=/\0")
        self._write(A.APPORT_DEFAULT_FILE, self.DEFAULT_BYTES)
        self._link("../init.d/apport", "/etc/rc2.d/S01apport")

    def _path(self, logical):
        return self.root / logical.lstrip("/")

    def _write(self, logical, data, mode=0o644):
        path = self._path(logical)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, mode)
        return path

    def _link(self, target, logical):
        path = self._path(logical)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path)
        return path

    def _remove(self, logical):
        self._path(logical).unlink()

    def detect(self, key=None):
        return A.detect_runtime_writer_conflict(key or self.KEY, str(self.root))

    def detect_sysv(self):
        try:
            return A._detect_apport_sysv_suid_dumpable(str(self.root))
        except A._RuntimeWriterUndetermined as exc:
            return A.RUNTIME_WRITER_UNDETERMINED, exc.step, exc.detail

    def _tree_state(self):
        state = {}
        for base, dirs, files in os.walk(self.root):
            for name in sorted(dirs + files):
                p = Path(base) / name
                st = os.lstat(p)
                data = os.readlink(p) if stat.S_ISLNK(st.st_mode) else (p.read_bytes() if stat.S_ISREG(st.st_mode) else None)
                state[str(p.relative_to(self.root))] = (st.st_mode, data)
        return state

    def _execute(self, dry_run=False, detector=None, privilege_check=None, key=None):
        writes = []
        persistent = self.work / "zz-target.conf"
        kwargs = dict(
            source_files=(), source_root=str(self.root), dry_run=dry_run,
            persistent_target=str(persistent), runtime_target=str(self.work / "runtime"),
            read_runtime=lambda: 2, write_runtime=lambda value: writes.append(value),
            write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
            privilege_check=privilege_check or (lambda: None),
            persistent_uid=os.getuid(), persistent_gid=os.getgid(), persistent_mode=0o644,
        )
        if detector is not None:
            kwargs["runtime_writer_detector"] = detector
        result = A.execute_control("CTRL-P2R", key or self.KEY, "eq", 0, True, **kwargs)
        return result, writes, persistent

    def test_p2r_constants_are_evidence_bound(self):
        self.assertEqual(A.RUNTIME_WRITER_RULES, {"fs.suid_dumpable": "APPORT-NATIVE-SUID-DUMPABLE-V1"})
        self.assertEqual(A.RUNTIME_WRITER_RULE_APPORT_SYSV, "APPORT-SYSV-SUID-DUMPABLE-V1")
        self.assertEqual(A.RUNTIME_WRITER_RULE_APPORT_NATIVE, "APPORT-NATIVE-SUID-DUMPABLE-V1")
        module = load_adapter()
        self.assertEqual(module.APPORT_INIT_SCRIPT_SHA256, frozenset({"40e252cd99e030fcdf28d286a7ac78f434e0ce0742f55cd12c38bef8e1f18633"}))
        self.assertEqual(module.APPORT_DEFAULT_ENABLED_SHA256, frozenset({"810304fb0df6dbc8a651a8928ddd0bb2b521fa0ca6f32a328aa103be61977f91"}))
        self.assertEqual(module.APPORT_RC_DIRS, ("/etc/rcS.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d"))

    def test_p2r_R8_conflict_known_default_and_absent_default(self):
        verdict, step, detail = self.detect()
        self.assertEqual((verdict, step), (A.RUNTIME_WRITER_CONFLICT, "R8"))
        self.assertTrue(detail.startswith("default-sha256="))
        self._remove(A.APPORT_DEFAULT_FILE)
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_CONFLICT, "R8", "default-absent"))

    def test_p2r_R1_R2_init_script(self):
        self._write(A.APPORT_INIT_SCRIPT, b"#! /bin/sh\n# other bytes\n", 0o755)
        verdict, step, detail = self.detect()
        self.assertEqual((verdict, step), (A.RUNTIME_WRITER_UNDETERMINED, "R2"))
        self.assertTrue(detail.startswith("sha256="))
        self._remove(A.APPORT_INIT_SCRIPT)
        self._write("/opt/apport-real", self.INIT_BYTES, 0o755)
        self._link("/opt/apport-real", A.APPORT_INIT_SCRIPT)
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_UNDETERMINED, "R2", "not-regular"))
        self._remove(A.APPORT_INIT_SCRIPT)
        self._path(A.APPORT_INIT_SCRIPT).mkdir()
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_UNDETERMINED, "R2", "not-regular"))
        self._path(A.APPORT_INIT_SCRIPT).rmdir()
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_NO_CONFLICT, "R1", None))

    def test_p2r_R3_agent_follows_symlink_like_test_x(self):
        self._remove(A.APPORT_AGENT)
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_NO_CONFLICT, "R3", "absent"))
        self._link("/usr/share/apport/missing", A.APPORT_AGENT)
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_NO_CONFLICT, "R3", "absent"))
        self._remove(A.APPORT_AGENT)
        self._write("/usr/share/apport/real-agent", b"#!/bin/sh\n", 0o755)
        self._link("real-agent", A.APPORT_AGENT)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_CONFLICT)
        os.chmod(self._path("/usr/share/apport/real-agent"), 0o644)
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_NO_CONFLICT, "R3", "not-executable"))

    def test_p2r_R3_resolution_error_is_undetermined(self):
        self._remove(A.APPORT_AGENT)
        self._link("loop-b", "/usr/share/apport/loop-a")
        self._link("loop-a", "/usr/share/apport/loop-b")
        self._link("loop-a", A.APPORT_AGENT)
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_UNDETERMINED, "R3", "ELOOP"))

    def test_p2r_R4_container_and_unreadable_environ(self):
        self._write(A.PID1_ENVIRON, b"PATH=/usr/bin\0container=lxc\0")
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_NO_CONFLICT, "R4", "container"))
        self._write(A.PID1_ENVIRON, b"PATH=/usr/bin\0xcontainer=lxc\0")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_CONFLICT)
        self._remove(A.PID1_ENVIRON)
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_UNDETERMINED, "R4", "ENOENT"))

    def test_p2r_R5_mask_in_etc_and_run(self):
        for logical in A.APPORT_MASK_PATHS:
            self._link("/dev/null", logical)
            self.assertEqual(self.detect_sysv(), (A.RUNTIME_WRITER_NO_CONFLICT, "R5", logical))
            self._remove(logical)

    def test_p2r_R6_overrides_are_undetermined(self):
        self._write("/etc/systemd/system/apport.service", b"[Service]\n")
        self._link("/dev/null", "/run/systemd/system/apport.service")
        self.assertEqual(self.detect_sysv(), (A.RUNTIME_WRITER_UNDETERMINED, "R6", "/etc/systemd/system/apport.service"))
        self._remove("/etc/systemd/system/apport.service")
        self._remove("/run/systemd/system/apport.service")
        self._link("/dev/zero", "/run/systemd/system/apport.service")
        self.assertEqual(self.detect_sysv(), (A.RUNTIME_WRITER_UNDETERMINED, "R6", "/run/systemd/system/apport.service"))
        self._remove("/run/systemd/system/apport.service")
        for logical in A.APPORT_OVERRIDE_PATHS:
            self._path(logical).mkdir(parents=True)
            self.assertEqual(self.detect_sysv(), (A.RUNTIME_WRITER_UNDETERMINED, "R6", logical))
            self._path(logical).rmdir()

    def test_p2r_R7_start_links(self):
        self._remove("/etc/rc2.d/S01apport")
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_UNDETERMINED, "R7", "no-start-link"))
        self._link("../init.d/apport", "/etc/rc5.d/S20apport")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_CONFLICT)
        self._write("/etc/rc2.d/S01apport", b"not a link\n")
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_UNDETERMINED, "R7", "not-symlink:/etc/rc2.d/S01apport"))
        self._remove("/etc/rc2.d/S01apport")
        self._write("/etc/init.d/other", self.INIT_BYTES, 0o755)
        self._link("../init.d/other", "/etc/rc3.d/S01apport")
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_UNDETERMINED, "R7", "target:/etc/rc3.d/S01apport"))
        self._remove("/etc/rc3.d/S01apport")
        self._link("../init.d/missing", "/etc/rc4.d/S01apport")
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_UNDETERMINED, "R7", "ENOENT:/etc/rc4.d/S01apport"))
        self._remove("/etc/rc4.d/S01apport")
        self._link("../init.d/apport", "/etc/rc2.d/K01apport")
        self._remove("/etc/rc5.d/S20apport")
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_UNDETERMINED, "R7", "no-start-link"))

    def test_p2r_R9_unknown_default_bytes(self):
        self._write(A.APPORT_DEFAULT_FILE, b"enabled=0\n")
        verdict, step, detail = self.detect()
        self.assertEqual((verdict, step), (A.RUNTIME_WRITER_UNDETERMINED, "R9"))
        self.assertTrue(detail.startswith("sha256="))
        self._remove(A.APPORT_DEFAULT_FILE)
        self._write("/etc/default/apport-real", self.DEFAULT_BYTES)
        self._link("apport-real", A.APPORT_DEFAULT_FILE)
        self.assertEqual(self.detect(), (A.RUNTIME_WRITER_UNDETERMINED, "R9", "not-regular"))

    def test_p2r_other_keys_never_run_detector(self):
        self.assertEqual(self.detect("kernel.dmesg_restrict"), (A.RUNTIME_WRITER_NO_CONFLICT, None, None))
        detector = mock.Mock(side_effect=AssertionError("must not run"))
        result, writes, _ = self._execute(dry_run=True, detector=detector, key="kernel.dmesg_restrict")
        detector.assert_not_called()
        self.assertNotIn("P2R_RUNTIME_WRITER", result.actions_attempted)
        self.assertEqual(result.outcome, A.OUTCOME_DRY_RUN_WOULD_APPLY)

    def test_p2r_conflict_aborts_before_mutation_with_dry_run_parity(self):
        before = self._tree_state()
        with mock.patch.object(A, "apply_persistent_change") as persistent_change, \
                mock.patch.object(A, "write_runtime_path") as runtime_path:
            applied, writes, persistent = self._execute(dry_run=False)
            dry, dry_writes, _ = self._execute(dry_run=True)
        persistent_change.assert_not_called()
        runtime_path.assert_not_called()
        self.assertEqual(writes + dry_writes, [])
        self.assertFalse(persistent.exists())
        self.assertEqual(self._tree_state(), before)
        for result in (applied, dry):
            self.assertEqual(result.outcome, A.OUTCOME_ABORT_CONFLICT)
            self.assertTrue(result.reason.startswith("runtime-writer:APPORT-SYSV-SUID-DUMPABLE-V1:R8:"))
            self.assertFalse(result.mutation_performed)
            self.assertIsNone(result.written_value)
            self.assertEqual(result.actions_attempted[-1], "P2R_RUNTIME_WRITER")
            self.assertNotEqual(A.outcome_rc_contribution(result.outcome, result.dry_run), 0)
            self.assertNotIn(result.outcome, (A.OUTCOME_APPLIED, A.OUTCOME_ALREADY_COMPLIANT, A.OUTCOME_NOT_APPLICABLE))
        self.assertEqual((applied.outcome, applied.reason), (dry.outcome, dry.reason))
        for result in (applied, dry):
            report = A.control_result_to_report(result, "START", "FINISH")
            self.assertEqual(report["operator_decision"], {
                "class": "SERVICE_MANAGED_PARAMETER",
                "required": True,
                "service": "Apport",
                "parameter": self.KEY,
                "current_value": 2,
            })

    def test_p2r_service_managed_operator_decision_has_no_false_positive(self):
        self._remove("/etc/rc2.d/S01apport")
        undetermined, _, _ = self._execute(dry_run=True)
        self.assertNotIn("operator_decision", A.control_result_to_report(undetermined, "START", "FINISH"))
        normal, _, _ = self._execute(dry_run=True, key="kernel.dmesg_restrict")
        self.assertNotIn("operator_decision", A.control_result_to_report(normal, "START", "FINISH"))

    def test_p2r_undetermined_aborts_other_with_dry_run_parity(self):
        self._remove("/etc/rc2.d/S01apport")
        applied, writes, persistent = self._execute(dry_run=False)
        dry, _, _ = self._execute(dry_run=True)
        for result in (applied, dry):
            self.assertEqual(result.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertEqual(result.reason, "runtime-writer:undetermined:R7:no-start-link")
            self.assertFalse(result.mutation_performed)
            self.assertNotEqual(A.outcome_rc_contribution(result.outcome, result.dry_run), 0)
        self.assertEqual(writes, [])
        self.assertFalse(persistent.exists())

    def test_p2r_no_conflict_continues_normal_planning(self):
        self._link("/dev/null", "/etc/systemd/system/apport.service")
        result, writes, _ = self._execute(dry_run=True)
        self.assertEqual(result.outcome, A.OUTCOME_DRY_RUN_WOULD_APPLY)
        self.assertIn("P2R_RUNTIME_WRITER", result.actions_attempted)
        self.assertEqual(writes, [])

    def test_p2r_runs_after_p3_privilege(self):
        detector = mock.Mock(side_effect=AssertionError("must not run"))

        def refuse():
            raise PermissionError("no write access")

        result, _, _ = self._execute(dry_run=True, detector=detector, privilege_check=refuse)
        detector.assert_not_called()
        self.assertEqual(result.outcome, A.OUTCOME_ABORT_OTHER)
        self.assertEqual(result.reason, "privilege:write-unavailable")
        self.assertNotIn("P2R_RUNTIME_WRITER", result.actions_attempted)

    def test_p2r_detector_failure_is_fail_closed(self):
        for detector in (mock.Mock(side_effect=RuntimeError("boom")), mock.Mock(return_value=("MAYBE", "R1", None)), mock.Mock(return_value=None)):
            result, writes, persistent = self._execute(dry_run=False, detector=detector)
            self.assertEqual(result.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertEqual(result.reason, "runtime-writer:undetermined:detector-failure")
            self.assertFalse(result.mutation_performed)
            self.assertEqual(writes, [])
            self.assertFalse(persistent.exists())


class RuntimeWriterConflictD17(unittest.TestCase):
    """H46-D17 REV4 finite census/native/generated detector regression."""

    KEY = "fs.suid_dumpable"
    NATIVE_UNIT_BYTES = base64.b64decode('W1VuaXRdCkRlc2NyaXB0aW9uPWF1dG9tYXRpYyBjcmFzaCByZXBvcnQgZ2VuZXJhdGlvbgpBZnRlcj1yZW1vdGUtZnMudGFyZ2V0CkNvbmRpdGlvblZpcnR1YWxpemF0aW9uPSFjb250YWluZXIKCltTZXJ2aWNlXQpUeXBlPW9uZXNob3QKUmVtYWluQWZ0ZXJFeGl0PXllcwpFeGVjU3RhcnQ9L3Vzci9zaGFyZS9hcHBvcnQvYXBwb3J0IC0tc3RhcnQKRXhlY1N0b3A9L3Vzci9zaGFyZS9hcHBvcnQvYXBwb3J0IC0tc3RvcAoKW0luc3RhbGxdCldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0Cg==')
    NATIVE_AGENT_BYTES = base64.b64decode('IyEvdXNyL2Jpbi9weXRob24zCgojIENvcHlyaWdodCAoYykgMjAwNiAtIDIwMTYgQ2Fub25pY2FsIEx0ZC4KIyBBdXRob3I6IE1hcnRpbiBQaXR0IDxtYXJ0aW4ucGl0dEB1YnVudHUuY29tPgojCiMgVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnkgaXQKIyB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUKIyBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyCiMgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi4gIFNlZSBodHRwOi8vd3d3LmdudS5vcmcvY29weWxlZnQvZ3BsLmh0bWwgZm9yCiMgdGhlIGZ1bGwgdGV4dCBvZiB0aGUgbGljZW5zZS4KCiIiIkNvbGxlY3QgaW5mb3JtYXRpb24gYWJvdXQgYSBjcmFzaCBhbmQgY3JlYXRlIGEgcmVwb3J0IGluIHRoZSBkaXJlY3RvcnkKc3BlY2lmaWVkIGJ5IGFwcG9ydC5maWxldXRpbHMucmVwb3J0X2Rpci4KU2VlIGh0dHBzOi8vd2lraS51YnVudHUuY29tL0FwcG9ydCBmb3IgZGV0YWlscy4iIiIKCiMgcHlsaW50OiBkaXNhYmxlPXRvby1tYW55LWxpbmVzCgojIHB5bGludCBmYWlscyB0byBpbXBvcnQgdGhlIGFwcG9ydCBtb2R1bGUsIGJlY2F1c2UgaXQgaGFzIHRoZSBzYW1lIG5hbWUuCiMgU2VlIGJ1ZyBodHRwczovL2dpdGh1Yi5jb20vUHlDUUEvcHlsaW50L2lzc3Vlcy83MDkzCiMgcHlsaW50OiBkaXNhYmxlPWMtZXh0ZW5zaW9uLW5vLW1lbWJlcixuby1uYW1lLWluLW1vZHVsZSxub3QtY2FsbGFibGUKIyBUT0RPOiBBZGRyZXNzIGZvbGxvd2luZyBweWxpbnQgY29tcGxhaW50cwojIHB5bGludDogZGlzYWJsZT1pbnZhbGlkLW5hbWUsbWlzc2luZy1mdW5jdGlvbi1kb2NzdHJpbmcKCmltcG9ydCBhcmdwYXJzZQppbXBvcnQgYXJyYXkKaW1wb3J0IGF0ZXhpdAppbXBvcnQgY29udGV4dGxpYgppbXBvcnQgZXJybm8KaW1wb3J0IGZjbnRsCmltcG9ydCBncnAKaW1wb3J0IGluc3BlY3QKaW1wb3J0IGlvCmltcG9ydCBsb2dnaW5nCmltcG9ydCBvcwppbXBvcnQgcHdkCmltcG9ydCByZQppbXBvcnQgc2lnbmFsCmltcG9ydCBzb2NrZXQKaW1wb3J0IHN0cnVjdAppbXBvcnQgc3VicHJvY2VzcwppbXBvcnQgc3lzCmltcG9ydCB0aW1lCmltcG9ydCB0cmFjZWJhY2sKaW1wb3J0IHR5cGluZwpmcm9tIGNvbGxlY3Rpb25zLmFiYyBpbXBvcnQgQ2FsbGFibGUKCmltcG9ydCBhcHBvcnQuZmlsZXV0aWxzCmltcG9ydCBhcHBvcnQucmVwb3J0CmZyb20gYXBwb3J0LnVzZXJfZ3JvdXAgaW1wb3J0IFVzZXJHcm91cElECmZyb20gcHJvYmxlbV9yZXBvcnQgaW1wb3J0IENvbXByZXNzZWRGaWxlCgpMT0dfRk9STUFUID0gIiUobGV2ZWxuYW1lKXM6IGFwcG9ydCAocGlkICUocHJvY2VzcylzKSAlKGFzY3RpbWUpczogJShtZXNzYWdlKXMiCgoKY2xhc3MgUHJvY1BpZE5vdEZvdW5kRXJyb3IoRmlsZU5vdEZvdW5kRXJyb3IpOgogICAgIiIiRmlsZU5vdEZvdW5kRXJyb3Igc3BlY2lmaWMgZm9yIC9wcm9jLzxwaWQ+LiIiIgoKCmNsYXNzIFByb2NQaWQoY29udGV4dGxpYi5Db250ZXh0RGVjb3JhdG9yKToKICAgICIiIkNvbnRleHQgbWFuYWdlciB0byBhY2Nlc3MgL3Byb2MvPHBpZD4uIiIiCgogICAgZGVmIF9faW5pdF9fKHNlbGYsIHBpZDogaW50LCBwYXRoOiBzdHIgfCBOb25lID0gTm9uZSkgLT4gTm9uZToKICAgICAgICBzZWxmLnBhdGggPSBwYXRoIG9yIGYiL3Byb2Mve3BpZH0iCiAgICAgICAgc2VsZi5waWQgPSBwaWQKICAgICAgICBzZWxmLmZkOiBpbnQgfCBOb25lID0gTm9uZQoKICAgIGRlZiBfX2VudGVyX18oc2VsZikgLT4gIlByb2NQaWQiOgogICAgICAgIHRyeToKICAgICAgICAgICAgc2VsZi5mZCA9IG9zLm9wZW4oc2VsZi5wYXRoLCBvcy5PX1JET05MWSB8IG9zLk9fUEFUSCB8IG9zLk9fRElSRUNUT1JZKQogICAgICAgIGV4Y2VwdCBGaWxlTm90Rm91bmRFcnJvciBhcyBlcnJvcjoKICAgICAgICAgICAgcmFpc2UgUHJvY1BpZE5vdEZvdW5kRXJyb3IoKmVycm9yLmFyZ3MsIGVycm9yLmZpbGVuYW1lKSBmcm9tIGVycm9yCiAgICAgICAgcmV0dXJuIHNlbGYKCiAgICBkZWYgX19leGl0X18oc2VsZiwgKmV4Yyk6CiAgICAgICAgaWYgc2VsZi5mZCBpcyBub3QgTm9uZToKICAgICAgICAgICAgb3MuY2xvc2Uoc2VsZi5mZCkKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICBkZWYgX29wZW5lcihzZWxmLCBwYXRoOiBzdHIgfCBvcy5QYXRoTGlrZVtzdHJdLCBmbGFnczogaW50KSAtPiBpbnQ6CiAgICAgICAgcmV0dXJuIG9zLm9wZW4ocGF0aCwgZmxhZ3MsIGRpcl9mZD1zZWxmLmZkKQoKICAgIGRlZiBleGlzdHMoc2VsZiwgcGF0aDogc3RyIHwgb3MuUGF0aExpa2Vbc3RyXSkgLT4gYm9vbDoKICAgICAgICAiIiJUZXN0IHdoZXRoZXIgYSBwYXRoIHJlbGF0aXZlIHRvIC9wcm9jLzxwaWQ+IGV4aXN0cy4KCiAgICAgICAgUmV0dXJucyBGYWxzZSBmb3IgYnJva2VuIHN5bWJvbGljIGxpbmtzLiIiIgogICAgICAgIHRyeToKICAgICAgICAgICAgc2VsZi5zdGF0KHBhdGgpCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCiAgICAgICAgcmV0dXJuIFRydWUKCiAgICBkZWYgaGFzX3NhbWVfcGlkKHNlbGYsIHBpZGZkOiBpbnQpIC0+IGJvb2w6CiAgICAgICAgIiIiQ2hlY2sgdGhhdCB0aGUgcHJvY2VzcyBJRCBtYXRjaGVzIHRoZSBQSUQgZnJvbSB0aGUgZ2l2ZW4gcGlkZmQuCgogICAgICAgIEluIGNhc2UgdGhlIHByb2Nlc3MgSUQgaGFzIGJlZW4gcmV1c2VkIGZvciBhIG5ldyBwcm9jZXNzLCB0aGUKICAgICAgICBwcm9jZXNzIElEIGZyb20gdGhlIHBpZGZkIHdpbGwgYmUgLTEgYW5kIHRodXMgdGhpcyBmdW5jdGlvbgogICAgICAgIHdpbGwgcmV0dXJuIEZhbHNlLgogICAgICAgICIiIgogICAgICAgIG90aGVyX3BpZCA9IHBpZGZkX2dldHBpZChwaWRmZCkKICAgICAgICByZXR1cm4gc2VsZi5waWQgPT0gb3RoZXJfcGlkCgogICAgZGVmIG9wZW4oc2VsZiwgZmlsZTogc3RyKSAtPiBpby5UZXh0SU9XcmFwcGVyOgogICAgICAgICIiIk9wZW4gZmlsZSByZWxhdGl2ZSB0byAvcHJvYy88cGlkPiBhbmQgcmV0dXJuIGEgc3RyZWFtLiIiIgogICAgICAgIGFzc2VydCBzZWxmLmZkIGlzIG5vdCBOb25lCiAgICAgICAgcmV0dXJuIG9wZW4oZmlsZSwgZW5jb2Rpbmc9InV0Zi04Iiwgb3BlbmVyPXNlbGYuX29wZW5lcikKCiAgICBkZWYgcmVhZGxpbmsoc2VsZiwgcGF0aDogc3RyIHwgb3MuUGF0aExpa2Vbc3RyXSkgLT4gc3RyOgogICAgICAgICIiIlJldHVybiBhIHN0cmluZyByZXByZXNlbnRpbmcgdGhlIHBhdGggdG8gd2hpY2ggdGhlIHN5bWJvbGljIGxpbmsgcG9pbnRzLiIiIgogICAgICAgIHJldHVybiBvcy5yZWFkbGluayhwYXRoLCBkaXJfZmQ9c2VsZi5mZCkKCiAgICBkZWYgc3RhdChzZWxmLCBwYXRoOiBzdHIgfCBvcy5QYXRoTGlrZVtzdHJdKSAtPiBvcy5zdGF0X3Jlc3VsdDoKICAgICAgICAiIiJHZXQgdGhlIHN0YXR1cyBvZiBhIGZpbGUgb3IgYSBmaWxlIGRlc2NyaXB0b3IgcmVsYXRpdmUgdG8gL3Byb2MvPHBpZD4uIiIiCiAgICAgICAgcmV0dXJuIG9zLnN0YXQocGF0aCwgZGlyX2ZkPXNlbGYuZmQpCgoKZGVmIHBpZGZkX2dldHBpZChwaWRmZDogaW50KSAtPiBpbnQ6CiAgICAiIiJHZXQgdGhlIGFzc29jaWF0ZWQgcGlkIGZyb20gdGhlIHBpZCBmaWxlIGRlc2NyaXB0b3IuCgogICAgVGhpcyBmdW5jdGlvbiBpcyBlcXVpdmFsZW50IHRvIHRoZSBpZGVudGljYWwgbmFtZWQgZnVuY3Rpb24gaW4gZ2xpYmMuCiAgICAiIiIKICAgIHBpZF9yZSA9IHJlLmNvbXBpbGUocmIiXlBpZDpccyooLT9bMC05XSspJCIpCiAgICB3aXRoIG9wZW4oZiIvcHJvYy9zZWxmL2ZkaW5mby97cGlkZmR9IiwgInJiIikgYXMgZmRpbmZvX2ZpbGU6CiAgICAgICAgZm9yIGxpbmUgaW4gZmRpbmZvX2ZpbGU6CiAgICAgICAgICAgIG1hdGNoID0gcGlkX3JlLm1hdGNoKGxpbmUpCiAgICAgICAgICAgIGlmIG1hdGNoOgogICAgICAgICAgICAgICAgcmV0dXJuIGludChtYXRjaC5ncm91cCgxKSkKICAgIHJhaXNlIE9TRXJyb3IoZXJybm8uRUJBREYsIGYie29zLnN0cmVycm9yKGVycm5vLkVCQURGKX06IHtwaWRmZH0iKQoKCmRlZiBjaGVja19sb2NrKCk6CiAgICAiIiJBYm9ydCBpZiBhbm90aGVyIGluc3RhbmNlIG9mIGFwcG9ydCBpcyBhbHJlYWR5IHJ1bm5pbmcuCgogICAgVGhpcyBhdm9pZHMgYnJpbmdpbmcgZG93biB0aGUgc3lzdGVtIHRvIGl0cyBrbmVlcyBpZiB0aGVyZSBpcyBhIHNlcmllcyBvZgogICAgY3Jhc2hlcy4iIiIKICAgIGxvZ2dlciA9IGxvZ2dpbmcuZ2V0TG9nZ2VyKCkKCiAgICAjIGNyZWF0ZSBhIGxvY2sgZmlsZQogICAgdHJ5OgogICAgICAgIGZkID0gb3Mub3BlbigKICAgICAgICAgICAgb3MuZW52aXJvbi5nZXQoIkFQUE9SVF9MT0NLX0ZJTEUiLCAiL3Zhci9ydW4vYXBwb3J0LmxvY2siKSwKICAgICAgICAgICAgb3MuT19XUk9OTFkgfCBvcy5PX0NSRUFUIHwgb3MuT19OT0ZPTExPVywKICAgICAgICAgICAgbW9kZT0wbzYwMCwKICAgICAgICApCiAgICBleGNlcHQgT1NFcnJvciBhcyBlcnJvcjoKICAgICAgICBsb2dnZXIuZXJyb3IoImNhbm5vdCBjcmVhdGUgbG9jayBmaWxlICh1aWQgJWkpOiAlcyIsIG9zLmdldHVpZCgpLCBzdHIoZXJyb3IpKQogICAgICAgIHN5cy5leGl0KDEpCgogICAgZGVmIGVycm9yX3J1bm5pbmcoKl91bnVzZWRfYXJncyk6CiAgICAgICAgbG9nZ2VyLmVycm9yKCJhbm90aGVyIGFwcG9ydCBpbnN0YW5jZSBpcyBhbHJlYWR5IHJ1bm5pbmcsIGFib3J0aW5nIikKICAgICAgICBzeXMuZXhpdCgxKQoKICAgIG9yaWdpbmFsX2hhbmRsZXIgPSBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdBTFJNLCBlcnJvcl9ydW5uaW5nKQogICAgc2lnbmFsLmFsYXJtKDMwKSAgIyBUaW1lb3V0IGFmdGVyIHRoYXQgbWFueSBzZWNvbmRzCiAgICB0cnk6CiAgICAgICAgZmNudGwubG9ja2YoZmQsIGZjbnRsLkxPQ0tfRVgpCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICBlcnJvcl9ydW5uaW5nKCkKICAgIGZpbmFsbHk6CiAgICAgICAgc2lnbmFsLmFsYXJtKDApCiAgICAgICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHQUxSTSwgb3JpZ2luYWxfaGFuZGxlcikKCgpkZWYgZ2V0X2NvcmVfcGF0aCgKICAgIG9wdGlvbnM6IGFyZ3BhcnNlLk5hbWVzcGFjZSwKICAgIHJlYWxfdXNlcjogVXNlckdyb3VwSUQsCiAgICBwcm9jX3BpZDogUHJvY1BpZCwKICAgIHRpbWVzdGFtcDogaW50IHwgTm9uZSA9IE5vbmUsCikgLT4gc3RyOgogICAgIiIiR2V0IHRoZSBwYXRoIHRvIHRoZSBjb3JlIGZpbGUuIiIiCiAgICByZXR1cm4gYXBwb3J0LmZpbGV1dGlscy5nZXRfY29yZV9wYXRoKAogICAgICAgIHByb2NfcGlkLnBpZCwgb3B0aW9ucy5leGVjdXRhYmxlX3BhdGgsIHJlYWxfdXNlci51aWQsIHRpbWVzdGFtcCwgcHJvY19waWQuZmQKICAgIClbMV0KCgpkZWYgZ2V0X3BpZF9pbmZvKHByb2NfcGlkOiBQcm9jUGlkKSAtPiB0dXBsZVtVc2VyR3JvdXBJRCwgb3Muc3RhdF9yZXN1bHRdOgogICAgIiIiUmVhZCAvcHJvYyBpbmZvcm1hdGlvbiBhYm91dCBwaWQiIiIKICAgICMgdW5oYW5kbGVkIGV4Y2VwdGlvbnMgb24gbWlzc2luZyBvciBpbnZhbGlkbHkgZm9ybWF0dGVkIGZpbGVzIGFyZSBva2F5CiAgICAjIGhlcmUgLS0gd2Ugd2FudCB0byBrbm93IGluIHRoZSBsb2cgZmlsZQogICAgcGlkc3RhdCA9IG9zLnN0YXQoInN0YXQiLCBkaXJfZmQ9cHJvY19waWQuZmQpCgogICAgIyBkZXRlcm1pbmUgVUlEIGFuZCBHSUQgb2YgdGhlIHRhcmdldCBwcm9jZXNzOyBkbyAqbm90KiB1c2UgdGhlIG93bmVyIG9mCiAgICAjIC9wcm9jL3BpZC9zdGF0LCBhcyB0aGF0IHdpbGwgYmUgcm9vdCBmb3Igc2V0dWlkIG9yIHVucmVhZGFibGUgcHJvZ3JhbXMhCiAgICAjICh0aGlzIG1hdHRlcnMgd2hlbiBzdWlkX2R1bXBhYmxlIGlzIGVuYWJsZWQpCiAgICB3aXRoIHByb2NfcGlkLm9wZW4oInN0YXR1cyIpIGFzIHN0YXR1c19maWxlOgogICAgICAgIGNvbnRlbnRzID0gc3RhdHVzX2ZpbGUucmVhZCgpCiAgICAocmVhbF91aWQsIHJlYWxfZ2lkKSA9IGFwcG9ydC5maWxldXRpbHMuZ2V0X3VpZF9hbmRfZ2lkKGNvbnRlbnRzKQoKICAgIGFzc2VydCByZWFsX3VpZCBpcyBub3QgTm9uZSwgImZhaWxlZCB0byBwYXJzZSBVaWQiCiAgICBhc3NlcnQgcmVhbF9naWQgaXMgbm90IE5vbmUsICJmYWlsZWQgdG8gcGFyc2UgR2lkIgogICAgcmV0dXJuIFVzZXJHcm91cElEKHJlYWxfdWlkLCByZWFsX2dpZCksIHBpZHN0YXQKCgpkZWYgZ2V0X3Byb2Nlc3Nfc3RhcnR0aW1lKHByb2NfcGlkOiBQcm9jUGlkKSAtPiBpbnQ6CiAgICAiIiJHZXQgdGhlIHN0YXJ0dGltZSBvZiB0aGUgcHJvY2VzcyB1c2luZyBwcm9jX3BpZF9mZCIiIgoKICAgIHdpdGggcHJvY19waWQub3Blbigic3RhdCIpIGFzIHN0YXRfZmlsZToKICAgICAgICBjb250ZW50cyA9IHN0YXRfZmlsZS5yZWFkKCkKICAgIHJldHVybiBhcHBvcnQuZmlsZXV0aWxzLmdldF9zdGFydHRpbWUoY29udGVudHMpCgoKZGVmIGdldF9hcHBvcnRfc3RhcnR0aW1lKCkgLT4gaW50OgogICAgIiIiR2V0IHRoZSBBcHBvcnQgcHJvY2VzcyBzdGFydHRpbWUiIiIKCiAgICB3aXRoIG9wZW4oZiIvcHJvYy97b3MuZ2V0cGlkKCl9L3N0YXQiLCBlbmNvZGluZz0idXRmLTgiKSBhcyBzdGF0X2ZpbGU6CiAgICAgICAgY29udGVudHMgPSBzdGF0X2ZpbGUucmVhZCgpCiAgICByZXR1cm4gYXBwb3J0LmZpbGV1dGlscy5nZXRfc3RhcnR0aW1lKGNvbnRlbnRzKQoKCmRlZiBkcm9wX3ByaXZpbGVnZXMocmVhbF91c2VyOiBVc2VyR3JvdXBJRCkgLT4gTm9uZToKICAgICIiIkNoYW5nZSBlZmZlY3RpdmUgdXNlciBhbmQgZ3JvdXAgdG8gY3Jhc2ggdXNlci9ncm91cCBJRCIiIgogICAgIyBEcm9wIGFueSBzdXBwbGVtZW50YWwgZ3JvdXBzLCBvciB3ZSdsbCBzdGlsbCBiZSBpbiB0aGUgcm9vdCBncm91cAogICAgaWYgb3MuZ2V0dWlkKCkgPT0gMDoKICAgICAgICBvcy5zZXRncm91cHMoW10pCiAgICAgICAgYXNzZXJ0IG9zLmdldGdyb3VwcygpID09IFtdCiAgICBvcy5zZXRyZWdpZCgtMSwgcmVhbF91c2VyLmdpZCkKICAgIG9zLnNldHJldWlkKC0xLCByZWFsX3VzZXIudWlkKQogICAgYXNzZXJ0IG9zLmdldGVnaWQoKSA9PSByZWFsX3VzZXIuZ2lkCiAgICBhc3NlcnQgb3MuZ2V0ZXVpZCgpID09IHJlYWxfdXNlci51aWQKCgpkZWYgcmVjb3Zlcl9wcml2aWxlZ2VzKCk6CiAgICAiIiJDaGFuZ2UgZWZmZWN0aXZlIHVzZXIgYW5kIGdyb3VwIGJhY2sgdG8gcmVhbCB1aWQgYW5kIGdpZCIiIgogICAgb3Muc2V0cmVnaWQoLTEsIG9zLmdldGdpZCgpKQogICAgb3Muc2V0cmV1aWQoLTEsIG9zLmdldHVpZCgpKQogICAgYXNzZXJ0IG9zLmdldGVnaWQoKSA9PSBvcy5nZXRnaWQoKQogICAgYXNzZXJ0IG9zLmdldGV1aWQoKSA9PSBvcy5nZXR1aWQoKQoKCmRlZiBpbml0X2Vycm9yX2xvZygpIC0+IE5vbmU6CiAgICAiIiJPcGVuIGEgc3VpdGFibGUgZXJyb3IgbG9nIGlmIHN5cy5zdGRlcnIgaXMgbm90IGEgdHR5LiIiIgoKICAgIGlmIG9zLmlzYXR0eSgyKToKICAgICAgICByZXR1cm4KCiAgICBsb2cgPSBvcy5lbnZpcm9uLmdldCgiQVBQT1JUX0xPR19GSUxFIiwgIi92YXIvbG9nL2FwcG9ydC5sb2ciKQogICAgdHJ5OgogICAgICAgIGYgPSBvcy5vcGVuKGxvZywgb3MuT19XUk9OTFkgfCBvcy5PX0NSRUFUIHwgb3MuT19BUFBFTkQsIDBvNjAwKQogICAgZXhjZXB0IE9TRXJyb3I6ICAjIG9uIGEgcGVybWlzc2lvbiBlcnJvciwgZG9uJ3QgdG91Y2ggc3RkZXJyCiAgICAgICAgcmV0dXJuCgogICAgIyBpZiBncm91cCBhZG0gZG9lc24ndCBleGlzdCwganVzdCBsZWF2ZSBpdCBhcyByb290CiAgICB3aXRoIGNvbnRleHRsaWIuc3VwcHJlc3MoS2V5RXJyb3IsIE9TRXJyb3IpOgogICAgICAgIGFkbWdpZCA9IGdycC5nZXRncm5hbSgiYWRtIilbMl0KICAgICAgICBvcy5jaG93bihsb2csIC0xLCBhZG1naWQpCiAgICAgICAgb3MuY2htb2QobG9nLCAwbzY0MCkKCiAgICBvcy5kdXAyKGYsIDEpCiAgICBvcy5kdXAyKGYsIDIpCiAgICBzeXMuc3RkZXJyID0gaW8uVGV4dElPV3JhcHBlcihvcy5mZG9wZW4oMiwgIndiIikpCiAgICBzeXMuc3Rkb3V0ID0gc3lzLnN0ZGVycgoKCmRlZiBfbG9nX3NpZ25hbF9oYW5kbGVyKHNnbiwgX3VudXNlZF9mcmFtZSk6CiAgICAiIiJJbnRlcm5hbCBhcHBvcnQgc2lnbmFsIGhhbmRsZXIuIEp1c3QgbG9nIHRoZSBzaWduYWwgaGFuZGxlciBhbmQgZXhpdC4iIiIKICAgIGxvZ2dlciA9IGxvZ2dpbmcuZ2V0TG9nZ2VyKCkKCiAgICAjIHJlc2V0IGhhbmRsZXIgc28gdGhhdCB3ZSBkbyBub3QgZ2V0IHN0dWNrIGluIGxvb3BzCiAgICBzaWduYWwuc2lnbmFsKHNnbiwgc2lnbmFsLlNJR19JR04pCiAgICB0cnk6CiAgICAgICAgbG9nZ2VyLmVycm9yKCJHb3Qgc2lnbmFsICVpLCBhYm9ydGluZzsgZnJhbWU6Iiwgc2duKQogICAgICAgIGZvciBzIGluIGluc3BlY3Quc3RhY2soKToKICAgICAgICAgICAgbG9nZ2VyLmVycm9yKCIlcyIsIHN0cihzKSkKICAgIGV4Y2VwdCBFeGNlcHRpb246ICAjIHB5bGludDogZGlzYWJsZT1icm9hZC1leGNlcHQKICAgICAgICBwYXNzCiAgICBzeXMuZXhpdCgxKQoKCmRlZiBzZXR1cF9zaWduYWxzKCk6CiAgICAiIiJJbnN0YWxsIGEgc2lnbmFsIGhhbmRsZXIgZm9yIGFsbCBjcmFzaC1saWtlIHNpZ25hbHMsIHNvIHRoYXQgYXBwb3J0IGlzCiAgICBub3QgY2FsbGVkIG9uIGl0c2VsZiB3aGVuIGFwcG9ydCBjcmFzaGVkLiIiIgoKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR0lMTCwgX2xvZ19zaWduYWxfaGFuZGxlcikKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR0FCUlQsIF9sb2dfc2lnbmFsX2hhbmRsZXIpCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdGUEUsIF9sb2dfc2lnbmFsX2hhbmRsZXIpCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdTRUdWLCBfbG9nX3NpZ25hbF9oYW5kbGVyKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHUElQRSwgX2xvZ19zaWduYWxfaGFuZGxlcikKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR0JVUywgX2xvZ19zaWduYWxfaGFuZGxlcikKCgpkZWYgd3JpdGVfdXNlcl9jb3JlZHVtcCgKICAgIGNvcmVfcGF0aDogc3RyLAogICAgbGltaXQ6IGludCwKICAgIHByb2NfcGlkOiBQcm9jUGlkLAogICAgcmVwb3J0X293bmVyOiBVc2VyR3JvdXBJRCwKICAgIGNvcmVkdW1wX2ZkOiBpbnQgfCBOb25lID0gTm9uZSwKICAgIGZyb21fcmVwb3J0OiB0eXBpbmcuQmluYXJ5SU8gfCBOb25lID0gTm9uZSwKKSAtPiBOb25lOgogICAgIyBweWxpbnQ6IGRpc2FibGU9dG9vLW1hbnktYXJndW1lbnRzCiAgICAiIiJXcml0ZSB0aGUgY29yZSBpbnRvIGEgZGlyZWN0b3J5IGlmIHVsaW1pdCByZXF1ZXN0cyBpdC4iIiIKICAgIGxvZ2dlciA9IGxvZ2dpbmcuZ2V0TG9nZ2VyKCkKCiAgICAjIHRocmVlIGNhc2VzOgogICAgIyBsaW1pdCA9PSAwOiBkbyBub3Qgd3JpdGUgYW55dGhpbmcKICAgICMgbGltaXQgPCAwOiB1bmxpbWl0ZWQsIHdyaXRlIG91dCBldmVyeXRoaW5nCiAgICAjIGxpbWl0IG5vbnplcm86IGNyYXNoZWQgcHJvY2VzcycgY29yZSBzaXplIHVsaW1pdCBpbiBieXRlcwoKICAgIGlmIGxpbWl0ID09IDA6CiAgICAgICAgcmV0dXJuCgogICAgY3dkID0gb3Mub3BlbigiY3dkIiwgb3MuT19SRE9OTFkgfCBvcy5PX1BBVEggfCBvcy5PX0RJUkVDVE9SWSwgZGlyX2ZkPXByb2NfcGlkLmZkKQoKICAgIHRyeToKICAgICAgICAjIExpbWl0IG51bWJlciBvZiBjb3JlIGZpbGVzIHRvIHByZXZlbnQgRG9TCiAgICAgICAgYXBwb3J0LmZpbGV1dGlscy5jbGVhbl9jb3JlX2RpcmVjdG9yeShyZXBvcnRfb3duZXIudWlkKQogICAgICAgIGNvcmVfZmlsZSA9IG9zLm9wZW4oCiAgICAgICAgICAgIGNvcmVfcGF0aCwgb3MuT19XUk9OTFkgfCBvcy5PX0NSRUFUIHwgb3MuT19FWENMLCBtb2RlPTBvNDAwLCBkaXJfZmQ9Y3dkCiAgICAgICAgKQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcmV0dXJuCgogICAgbG9nZ2VyLmluZm8oIndyaXRpbmcgY29yZSBkdW1wIHRvICVzIChsaW1pdDogJXMpIiwgY29yZV9wYXRoLCBzdHIobGltaXQpKQoKICAgIHdyaXR0ZW4gPSAwCgogICAgIyBQcmltaW5nIHJlYWQKICAgIGlmIGZyb21fcmVwb3J0OgogICAgICAgIHIgPSBhcHBvcnQucmVwb3J0LlJlcG9ydCgpCiAgICAgICAgci5sb2FkKGZyb21fcmVwb3J0KQogICAgICAgIGNvcmVfc2l6ZSA9IGxlbihyWyJDb3JlRHVtcCJdKQogICAgICAgIGlmIDAgPCBsaW1pdCA8IGNvcmVfc2l6ZToKICAgICAgICAgICAgbG9nZ2VyLmVycm9yKAogICAgICAgICAgICAgICAgImFib3J0aW5nIGNvcmUgZHVtcCB3cml0aW5nLCBzaXplICVpIGV4Y2VlZHMgY3VycmVudCBsaW1pdCIsIGNvcmVfc2l6ZQogICAgICAgICAgICApCiAgICAgICAgICAgIG9zLmNsb3NlKGNvcmVfZmlsZSkKICAgICAgICAgICAgb3MudW5saW5rKGNvcmVfcGF0aCwgZGlyX2ZkPWN3ZCkKICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgbG9nZ2VyLmluZm8oIndyaXRpbmcgY29yZSBkdW1wICVzIG9mIHNpemUgJWkiLCBjb3JlX3BhdGgsIGNvcmVfc2l6ZSkKICAgICAgICBvcy53cml0ZShjb3JlX2ZpbGUsIHJbIkNvcmVEdW1wIl0pCiAgICBlbHNlOgogICAgICAgIGFzc2VydCBjb3JlZHVtcF9mZCBpcyBub3QgTm9uZQogICAgICAgIGJsb2NrID0gb3MucmVhZChjb3JlZHVtcF9mZCwgMTA0ODU3NikKCiAgICAgICAgd2hpbGUgVHJ1ZToKICAgICAgICAgICAgc2l6ZSA9IGxlbihibG9jaykKICAgICAgICAgICAgaWYgc2l6ZSA9PSAwOgogICAgICAgICAgICAgICAgYnJlYWsKICAgICAgICAgICAgd3JpdHRlbiArPSBzaXplCiAgICAgICAgICAgIGlmIDAgPCBsaW1pdCA8IHdyaXR0ZW46CiAgICAgICAgICAgICAgICBsb2dnZXIuZXJyb3IoCiAgICAgICAgICAgICAgICAgICAgImFib3J0aW5nIGNvcmUgZHVtcCB3cml0aW5nLCBzaXplIGV4Y2VlZHMgY3VycmVudCBsaW1pdCAlaSIsIGxpbWl0CiAgICAgICAgICAgICAgICApCiAgICAgICAgICAgICAgICBvcy5jbG9zZShjb3JlX2ZpbGUpCiAgICAgICAgICAgICAgICBvcy51bmxpbmsoY29yZV9wYXRoLCBkaXJfZmQ9Y3dkKQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICAgICAgICAgIGlmIG9zLndyaXRlKGNvcmVfZmlsZSwgYmxvY2spICE9IHNpemU6CiAgICAgICAgICAgICAgICBsb2dnZXIuZXJyb3IoImFib3J0aW5nIGNvcmUgZHVtcCB3cml0aW5nLCBjb3VsZCBub3Qgd3JpdGUiKQogICAgICAgICAgICAgICAgb3MuY2xvc2UoY29yZV9maWxlKQogICAgICAgICAgICAgICAgb3MudW5saW5rKGNvcmVfcGF0aCwgZGlyX2ZkPWN3ZCkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBibG9jayA9IG9zLnJlYWQoY29yZWR1bXBfZmQsIDEwNDg1NzYpCgogICAgIyBNYWtlIHN1cmUgdGhlIHVzZXIgY2FuIHJlYWQgaXQKICAgIG9zLmZjaG93bihjb3JlX2ZpbGUsIHJlcG9ydF9vd25lci51aWQsIC0xKQogICAgb3MuY2xvc2UoY29yZV9maWxlKQoKCmRlZiB1c2FibGVfcmFtKCk6CiAgICAiIiJSZXR1cm4gaG93IG1hbnkgYnl0ZXMgb2YgUkFNIGlzIGN1cnJlbnRseSBhdmFpbGFibGUgdGhhdCBjYW4gYmUKICAgIGFsbG9jYXRlZCB3aXRob3V0IGNhdXNpbmcgbWFqb3IgdGhyYXNoaW5nLiIiIgoKICAgICMgYWJ1c2Ugb3VyIGV4Y2VsbGVudCBSRkM4MjIgcGFyc2VyIHRvIHBhcnNlIC9wcm9jL21lbWluZm8KICAgIHIgPSBhcHBvcnQucmVwb3J0LlJlcG9ydCgpCiAgICB3aXRoIG9wZW4oIi9wcm9jL21lbWluZm8iLCAicmIiKSBhcyBmOgogICAgICAgIHIubG9hZChmKQoKICAgIG1lbWZyZWUgPSBpbnQoclsiTWVtRnJlZSJdLnNwbGl0KClbMF0pCiAgICBjYWNoZWQgPSBpbnQoclsiQ2FjaGVkIl0uc3BsaXQoKVswXSkKICAgIHdyaXRlYmFjayA9IGludChyWyJXcml0ZWJhY2siXS5zcGxpdCgpWzBdKQoKICAgIHJldHVybiAobWVtZnJlZSArIGNhY2hlZCAtIHdyaXRlYmFjaykgKiAxMDI0CgoKZGVmIF9ydW5fd2l0aF9vdXRwdXRfbGltaXRfYW5kX3RpbWVvdXQoCiAgICBhcmdzLCBvdXRwdXRfbGltaXQsIHRpbWVvdXQsIGNsb3NlX2Zkcz1UcnVlLCBlbnY9Tm9uZQopOgogICAgIiIiUnVuIGNvbW1hbmQgbGlrZSBzdWJwcm9jZXNzLnJ1bigpIGJ1dCB3aXRoIG91dHB1dCBsaW1pdCBhbmQgdGltZW91dC4KCiAgICBSZXR1cm4gKHN0ZG91dCwgc3RkZXJyKS4iIiIKCiAgICBzdGRvdXQgPSBiIiIKICAgIHN0ZGVyciA9IGIiIgoKICAgICMgdXNlcyAua2lsbCgpLCBweWxpbnQ6IGRpc2FibGU9Y29uc2lkZXItdXNpbmctd2l0aAogICAgcHJvY2VzcyA9IHN1YnByb2Nlc3MuUG9wZW4oCiAgICAgICAgYXJncywKICAgICAgICBzdGRvdXQ9c3VicHJvY2Vzcy5QSVBFLAogICAgICAgIHN0ZGVycj1zdWJwcm9jZXNzLlBJUEUsCiAgICAgICAgY2xvc2VfZmRzPWNsb3NlX2ZkcywKICAgICAgICBlbnY9ZW52LAogICAgKQogICAgdHJ5OgogICAgICAgICMgRG9uJ3QgYmxvY2sgc28gd2UgZG9uJ3QgZGVhZGxvY2sKICAgICAgICBvcy5zZXRfYmxvY2tpbmcocHJvY2Vzcy5zdGRvdXQuZmlsZW5vKCksIEZhbHNlKQogICAgICAgIG9zLnNldF9ibG9ja2luZyhwcm9jZXNzLnN0ZGVyci5maWxlbm8oKSwgRmFsc2UpCgogICAgICAgIGZvciBfIGluIHJhbmdlKHRpbWVvdXQpOgogICAgICAgICAgICBhbGl2ZSA9IHByb2Nlc3MucG9sbCgpIGlzIE5vbmUKCiAgICAgICAgICAgIHdoaWxlIGxlbihzdGRvdXQpIDwgb3V0cHV0X2xpbWl0IGFuZCBsZW4oc3RkZXJyKSA8IG91dHB1dF9saW1pdDoKICAgICAgICAgICAgICAgIHRlbXBvdXQgPSBwcm9jZXNzLnN0ZG91dC5yZWFkKDEwMCkKICAgICAgICAgICAgICAgIGlmIHRlbXBvdXQ6CiAgICAgICAgICAgICAgICAgICAgc3Rkb3V0ICs9IHRlbXBvdXQKICAgICAgICAgICAgICAgIHRlbXBlcnIgPSBwcm9jZXNzLnN0ZGVyci5yZWFkKDEwMCkKICAgICAgICAgICAgICAgIGlmIHRlbXBlcnI6CiAgICAgICAgICAgICAgICAgICAgc3RkZXJyICs9IHRlbXBlcnIKICAgICAgICAgICAgICAgIGlmIG5vdCB0ZW1wb3V0IGFuZCBub3QgdGVtcGVycjoKICAgICAgICAgICAgICAgICAgICBicmVhawoKICAgICAgICAgICAgaWYgbm90IGFsaXZlIG9yIGxlbihzdGRvdXQpID49IG91dHB1dF9saW1pdCBvciBsZW4oc3RkZXJyKSA+PSBvdXRwdXRfbGltaXQ6CiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICB0aW1lLnNsZWVwKDEpCiAgICBmaW5hbGx5OgogICAgICAgIHByb2Nlc3Mua2lsbCgpCgogICAgcmV0dXJuIHN0ZG91dCwgc3RkZXJyCgoKZGVmIGlzX2Nsb3Npbmdfc2Vzc2lvbihwcm9jX3BpZDogUHJvY1BpZCwgcmVhbF91c2VyOiBVc2VyR3JvdXBJRCkgLT4gYm9vbDoKICAgICIiIkNoZWNrIGlmIHBpZCBpcyBpbiBhIGNsb3NpbmcgdXNlciBzZXNzaW9uLgoKICAgIER1cmluZyB0aGF0LCBjcmFzaGVzIGFyZSBjb21tb24gYXMgdGhlIHNlc3Npb24gRC1CVVMgYW5kIFgub3JnIGFyZSBnb2luZwogICAgYXdheSwgZXRjLiBUaGVzZSBjcmFzaCByZXBvcnRzIGFyZSBtb3N0bHkgbm9pc2UsIHNvIHNob3VsZCBiZSBpZ25vcmVkLgogICAgIiIiCiAgICBsb2dnZXIgPSBsb2dnaW5nLmdldExvZ2dlcigpCiAgICBhc3NlcnQgcHJvY19waWQuZmQgaXMgbm90IE5vbmUKICAgIGVudiA9IGFwcG9ydC5maWxldXRpbHMuZ2V0X3Byb2Nlc3NfZW52aXJvbihwcm9jX3BpZC5mZCkKICAgIGRidXNfYWRkciA9IGVudi5nZXQoIkRCVVNfU0VTU0lPTl9CVVNfQUREUkVTUyIpCiAgICBpZiBkYnVzX2FkZHIgaXMgTm9uZToKICAgICAgICBsb2dnZXIuZXJyb3IoImlzX2Nsb3Npbmdfc2Vzc2lvbigpOiBubyBEQlVTX1NFU1NJT05fQlVTX0FERFJFU1MgaW4gZW52aXJvbm1lbnQiKQogICAgICAgIHJldHVybiBGYWxzZQoKICAgIGRidXNfc29ja2V0ID0gYXBwb3J0LmZpbGV1dGlscy5nZXRfZGJ1c19zb2NrZXQoZGJ1c19hZGRyKQogICAgaWYgbm90IGRidXNfc29ja2V0OgogICAgICAgIGxvZ2dlci5lcnJvcigiaXNfY2xvc2luZ19zZXNzaW9uKCk6IENvdWxkIG5vdCBkZXRlcm1pbmUgREJVUyBzb2NrZXQuIikKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICBpZiBub3Qgb3MucGF0aC5leGlzdHMoZGJ1c19zb2NrZXQpOgogICAgICAgIGxvZ2dlci5lcnJvcigiaXNfY2xvc2luZ19zZXNzaW9uKCk6IERCVVMgc29ja2V0IGRvZXNuJ3QgZXhpc3QuIikKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICAjIFdlIG5lZWQgdG8gZHJvcCBib3RoIHRoZSByZWFsIGFuZCBlZmZlY3RpdmUgdWlkL2dpZCBiZWZvcmUgY2FsbGluZwogICAgIyBnZGJ1cyBiZWNhdXNlIERCVVNfU0VTU0lPTl9CVVNfQUREUkVTUyBpcyB1bnRydXN0ZWQgYW5kIG1heSBhbGxvdwogICAgIyByZWFkaW5nIGFyYml0cmFyeSBmaWxlcyBhcyBhIG5vbmNlZmlsZS4gV2UgY2FuJ3QganVzdCBkcm9wIGVmZmVjdGl2ZQogICAgIyB1aWQvZ2lkIGFzIGdkYnVzIGhhcyBhIGNoZWNrIHRvIG1ha2Ugc3VyZSBpdCdzIG5vdCBydW5uaW5nIGluIGEKICAgICMgc2V0dWlkIGVudmlyb25tZW50IGFuZCBpdCBkb2VzIHNvIGJ5IGNvbXBhcmluZyB0aGUgcmVhbCBhbmQgZWZmZWN0aXZlCiAgICAjIGlkcy4gV2UgZG9uJ3QgbmVlZCB0byBkcm9wIHN1cHBsZW1lbnRhbCBncm91cHMgaGVyZSwgYXMgdGhlIHByaXZpbGVnZQogICAgIyBkcm9wcGluZyBjb2RlIGVsc2V3aGVyZSBoYXMgYWxyZWFkeSBkb25lIHNvLgogICAgcmVhbF91aWQgPSBvcy5nZXR1aWQoKQogICAgcmVhbF9naWQgPSBvcy5nZXRnaWQoKQogICAgdHJ5OgogICAgICAgIG9zLnNldHJlc2dpZChyZWFsX3VzZXIuZ2lkLCByZWFsX3VzZXIuZ2lkLCByZWFsX2dpZCkKICAgICAgICBvcy5zZXRyZXN1aWQocmVhbF91c2VyLnVpZCwgcmVhbF91c2VyLnVpZCwgcmVhbF91aWQpCiAgICAgICAgb3V0LCBlcnIgPSBfcnVuX3dpdGhfb3V0cHV0X2xpbWl0X2FuZF90aW1lb3V0KAogICAgICAgICAgICBbCiAgICAgICAgICAgICAgICAiL3Vzci9iaW4vZ2RidXMiLAogICAgICAgICAgICAgICAgImNhbGwiLAogICAgICAgICAgICAgICAgIi1lIiwKICAgICAgICAgICAgICAgICItZCIsCiAgICAgICAgICAgICAgICAib3JnLmdub21lLlNlc3Npb25NYW5hZ2VyIiwKICAgICAgICAgICAgICAgICItbyIsCiAgICAgICAgICAgICAgICAiL29yZy9nbm9tZS9TZXNzaW9uTWFuYWdlciIsCiAgICAgICAgICAgICAgICAiLW0iLAogICAgICAgICAgICAgICAgIm9yZy5nbm9tZS5TZXNzaW9uTWFuYWdlci5Jc1Nlc3Npb25SdW5uaW5nIiwKICAgICAgICAgICAgICAgICItdCIsCiAgICAgICAgICAgICAgICAiNSIsCiAgICAgICAgICAgIF0sCiAgICAgICAgICAgIDEwMDAsCiAgICAgICAgICAgIDUsCiAgICAgICAgICAgIGVudj17IkRCVVNfU0VTU0lPTl9CVVNfQUREUkVTUyI6IGRidXNfYWRkcn0sCiAgICAgICAgKQoKICAgICAgICBpZiBlcnI6CiAgICAgICAgICAgIGxvZ2dlci5lcnJvcigiZ2RidXMgY2FsbCBlcnJvcjogJXMiLCBlcnIuZGVjb2RlKCJVVEYtOCIpKQogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXJyb3I6CiAgICAgICAgbG9nZ2VyLmVycm9yKAogICAgICAgICAgICAiZ2RidXMgY2FsbCBmYWlsZWQsIGNhbm5vdCBkZXRlcm1pbmUgcnVubmluZyBzZXNzaW9uOiAlcyIsIHN0cihlcnJvcikKICAgICAgICApCiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBmaW5hbGx5OgogICAgICAgIG9zLnNldHJlc3VpZChyZWFsX3VpZCwgcmVhbF91aWQsIC0xKQogICAgICAgIG9zLnNldHJlc2dpZChyZWFsX2dpZCwgcmVhbF9naWQsIC0xKQoKICAgIGxvZ2dlci5kZWJ1Zygic2Vzc2lvbiBnZGJ1cyBjYWxsOiAlcyIsIG91dC5kZWNvZGUoIlVURi04IikucnN0cmlwKCkpCiAgICByZXR1cm4gb3V0LnN0YXJ0c3dpdGgoYiIoZmFsc2UsIikKCgpkZWYgaXNfc3lzdGVtZF93YXRjaGRvZ19yZXN0YXJ0KHNpZ251bTogaW50LCBwcm9jX3BpZDogUHJvY1BpZCkgLT4gYm9vbDoKICAgICIiIkNoZWNrIGlmIHRoaXMgaXMgYSByZXN0YXJ0IGJ5IHN5c3RlbWQncyB3YXRjaGRvZyIiIgoKICAgIGlmIHNpZ251bSAhPSBpbnQoc2lnbmFsLlNJR0FCUlQpIG9yIG5vdCBvcy5wYXRoLmlzZGlyKCIvcnVuL3N5c3RlbWQvc3lzdGVtIik6CiAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgdHJ5OgogICAgICAgIHdpdGggcHJvY19waWQub3BlbigiY2dyb3VwIikgYXMgZjoKICAgICAgICAgICAgZm9yIGxpbmUgaW4gZjoKICAgICAgICAgICAgICAgIGlmICJuYW1lPXN5c3RlbWQ6IiBpbiBsaW5lOgogICAgICAgICAgICAgICAgICAgIHVuaXQgPSBsaW5lLnNwbGl0KCIvIilbLTFdLnN0cmlwKCkKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgICAgIGpvdXJuYWxjdGwgPSBzdWJwcm9jZXNzLnJ1bigKICAgICAgICAgICAgWwogICAgICAgICAgICAgICAgIi9iaW4vam91cm5hbGN0bCIsCiAgICAgICAgICAgICAgICAiLS1vdXRwdXQ9Y2F0IiwKICAgICAgICAgICAgICAgICItLXNpbmNlPS01bWluIiwKICAgICAgICAgICAgICAgICItLXByaW9yaXR5PXdhcm5pbmciLAogICAgICAgICAgICAgICAgIi0tdW5pdCIsCiAgICAgICAgICAgICAgICB1bml0LAogICAgICAgICAgICBdLAogICAgICAgICAgICBjaGVjaz1GYWxzZSwKICAgICAgICAgICAgc3Rkb3V0PXN1YnByb2Nlc3MuUElQRSwKICAgICAgICApCiAgICAgICAgcmV0dXJuIGIiV2F0Y2hkb2cgdGltZW91dCIgaW4gam91cm5hbGN0bC5zdGRvdXQKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGVycm9yOgogICAgICAgIGxvZ2dpbmcuZ2V0TG9nZ2VyKCkuZXJyb3IoCiAgICAgICAgICAgICJjYW5ub3QgZGV0ZXJtaW5lIGlmIHRoaXMgY3Jhc2ggaXMgZnJvbSBzeXN0ZW1kIHdhdGNoZG9nOiAlcyIsIGVycm9yCiAgICAgICAgKQogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiBpc19zYW1lX25zKHByb2NfcGlkOiBQcm9jUGlkLCBuczogc3RyKSAtPiBib29sOgogICAgaWYgbm90IG9zLnBhdGguZXhpc3RzKGYiL3Byb2Mvc2VsZi9ucy97bnN9Iikgb3Igbm90IHByb2NfcGlkLmV4aXN0cyhmIm5zL3tuc30iKToKICAgICAgICAjIElmIHRoZSBuYW1lc3BhY2UgZG9lc24ndCBleGlzdCwgdGhlbiBpdCdzIG9idmlvdXNseSBzaGFyZWQKICAgICAgICByZXR1cm4gVHJ1ZQoKICAgIHRyeToKICAgICAgICBpZiBwcm9jX3BpZC5yZWFkbGluayhmIm5zL3tuc30iKSA9PSBvcy5yZWFkbGluayhmIi9wcm9jL3NlbGYvbnMve25zfSIpOgogICAgICAgICAgICAjIENoZWNrIHRoYXQgdGhlIGlub2RlIGZvciBib3RoIG5hbWVzcGFjZXMgaXMgdGhlIHNhbWUKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGVycm9yOgogICAgICAgIGlmIGVycm9yLmVycm5vID09IGVycm5vLkVOT0VOVDoKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICByYWlzZQoKICAgICMgY2hlY2sgdG8gc2VlIGlmIHRoZSBwcm9jZXNzIGlzIHBhcnQgb2YgdGhlIHN5c3RlbS5zbGljZSAoTFA6ICMxODcwMDYwKQogICAgd2l0aCBjb250ZXh0bGliLnN1cHByZXNzKEZpbGVOb3RGb3VuZEVycm9yKToKICAgICAgICB3aXRoIHByb2NfcGlkLm9wZW4oImNncm91cCIpIGFzIGNncm91cDoKICAgICAgICAgICAgZm9yIGxpbmUgaW4gY2dyb3VwOgogICAgICAgICAgICAgICAgZmllbGRzID0gbGluZS5zcGxpdCgiOiIpCiAgICAgICAgICAgICAgICBpZiBmaWVsZHNbLTFdLnN0YXJ0c3dpdGgoIi9zeXN0ZW0uc2xpY2UiKToKICAgICAgICAgICAgICAgICAgICByZXR1cm4gVHJ1ZQoKICAgIHJldHVybiBGYWxzZQoKCmRlZiBmb3J3YXJkX2NyYXNoX3RvX2NvbnRhaW5lcigKICAgIG9wdGlvbnM6IGFyZ3BhcnNlLk5hbWVzcGFjZSwKICAgIHByb2NfcGlkOiBQcm9jUGlkLAogICAgY29yZWR1bXBfZmQ6IGludCA9IDAsCiAgICBoYXNfY2FwX3N5c19hZG1pbjogYm9vbCA9IFRydWUsCikgLT4gTm9uZToKICAgICIiIlRyeSB0byBmb3J3YXJkIHRoZSBjcmFzaCB0byB0aGUgY29udGFpbmVyLgoKICAgIElmIHRoZSBjcmFzaCBjYW1lIGZyb20gYSBjb250YWluZXIsIGRvbid0IGF0dGVtcHQgdG8gaGFuZGxlCiAgICBsb2NhbGx5IGFzIHRoYXQgd291bGQganVzdCByZXN1bHQgaW4gd3Jvbmcgc3lzdGVtIGluZm9ybWF0aW9uLgoKICAgIEluc3RlYWQsIGF0dGVtcHQgdG8gZmluZCBhcHBvcnQgaW5zaWRlIHRoZSBjb250YWluZXIgYW5kCiAgICBmb3J3YXJkIHRoZSBwcm9jZXNzIGluZm9ybWF0aW9uIHRoZXJlLgogICAgIiIiCiAgICBsb2dnZXIgPSBsb2dnaW5nLmdldExvZ2dlcigpCgogICAgaWYgb3B0aW9ucy5waWRmZCBpcyBOb25lIGFuZCBvcHRpb25zLmR1bXBfbW9kZSAhPSAxOgogICAgICAgICMgTm90ZTogSWYgb3B0aW9ucy5waWRmZCBpcyBzZXQsIHByb2NfcGlkLmhhc19zYW1lX3BpZCgpIGhhcyBiZWVuIGNhbGxlZCBiZWZvcmUuCiAgICAgICAgbG9nZ2VyLmVycm9yKAogICAgICAgICAgICAiTm90IGZvcndhcmRpbmcgY3Jhc2ggd2l0aCBkdW1wIG1vZGUgb2YgJXMgdG8gY29udGFpbmVyIgogICAgICAgICAgICAiIGR1ZSB0byBzZWN1cml0eSBjb25jZXJucy4gUGxlYXNlIHByb3ZpZGUgLS1waWRmZC4iLAogICAgICAgICAgICBvcHRpb25zLmR1bXBfbW9kZSwKICAgICAgICApCiAgICAgICAgcmV0dXJuCgogICAgIyBWYWxpZGF0ZSB0aGF0IHRoZSB0YXJnZXQgc29ja2V0IGlzIG93bmVkCiAgICAjIGJ5IHRoZSB1c2VyIG5hbWVzcGFjZSBvZiB0aGUgcHJvY2VzcwogICAgdHJ5OgogICAgICAgIHNvY2tfZmQgPSBvcy5vcGVuKAogICAgICAgICAgICAicm9vdC9ydW4vYXBwb3J0LnNvY2tldCIsIG9zLk9fUkRPTkxZIHwgb3MuT19QQVRILCBkaXJfZmQ9cHJvY19waWQuZmQKICAgICAgICApCiAgICAgICAgc29ja2V0X3VpZCA9IG9zLmZzdGF0KHNvY2tfZmQpLnN0X3VpZAogICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgImhvc3QgcGlkICVzIGNyYXNoZWQgaW4gYSBjb250YWluZXIgd2l0aG91dCBhcHBvcnQgc3VwcG9ydCIsCiAgICAgICAgICAgIG9wdGlvbnMuZ2xvYmFsX3BpZCwKICAgICAgICApCiAgICAgICAgcmV0dXJuCgogICAgdHJ5OgogICAgICAgIHdpdGggcHJvY19waWQub3BlbigidWlkX21hcCIpIGFzIGZkOgogICAgICAgICAgICBpZiBub3QgYXBwb3J0LmZpbGV1dGlscy5zZWFyY2hfbWFwKGZkLCBzb2NrZXRfdWlkKToKICAgICAgICAgICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgICAgICAgICAidXNlciBpcyB0cnlpbmcgdG8gdHJpY2sgYXBwb3J0IGludG8gYWNjZXNzaW5nIgogICAgICAgICAgICAgICAgICAgICIgYSBzb2NrZXQgdGhhdCBkb2Vzbid0IGJlbG9uZyB0byB0aGUgY29udGFpbmVyIgogICAgICAgICAgICAgICAgKQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgcGFzcwoKICAgICMgVmFsaWRhdGUgdGhhdCB0aGUgY3Jhc2hlZCBiaW5hcnkgaXMgb3duZWQKICAgICMgYnkgdGhlIHVzZXIgbmFtZXNwYWNlIG9mIHRoZSBwcm9jZXNzCiAgICBleGVfcGF0aCA9IGYicm9vdHtwcm9jX3BpZC5yZWFkbGluaygnZXhlJyl9IgogICAgZXhlX3N0YXQgPSBwcm9jX3BpZC5zdGF0KGV4ZV9wYXRoKQogICAgdHJ5OgogICAgICAgIHdpdGggcHJvY19waWQub3BlbigidWlkX21hcCIpIGFzIGZkOgogICAgICAgICAgICBpZiBub3QgYXBwb3J0LmZpbGV1dGlscy5zZWFyY2hfbWFwKGZkLCBleGVfc3RhdC5zdF91aWQpOgogICAgICAgICAgICAgICAgbG9nZ2VyLmVycm9yKAogICAgICAgICAgICAgICAgICAgICJob3N0IHBpZCAlcyBjcmFzaGVkIGluIGEgY29udGFpbmVyIgogICAgICAgICAgICAgICAgICAgICIgd2l0aCBubyBhY2Nlc3MgdG8gdGhlIGJpbmFyeSIsCiAgICAgICAgICAgICAgICAgICAgb3B0aW9ucy5nbG9iYWxfcGlkLAogICAgICAgICAgICAgICAgKQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgcGFzcwoKICAgIHRyeToKICAgICAgICB3aXRoIHByb2NfcGlkLm9wZW4oImdpZF9tYXAiKSBhcyBmZDoKICAgICAgICAgICAgaWYgbm90IGFwcG9ydC5maWxldXRpbHMuc2VhcmNoX21hcChmZCwgZXhlX3N0YXQuc3RfZ2lkKToKICAgICAgICAgICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgICAgICAgICAiaG9zdCBwaWQgJXMgY3Jhc2hlZCBpbiBhIGNvbnRhaW5lciIKICAgICAgICAgICAgICAgICAgICAiIHdpdGggbm8gYWNjZXNzIHRvIHRoZSBiaW5hcnkiLAogICAgICAgICAgICAgICAgICAgIG9wdGlvbnMuZ2xvYmFsX3BpZCwKICAgICAgICAgICAgICAgICkKICAgICAgICAgICAgICAgIHJldHVybgogICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgIHBhc3MKCiAgICAjIE5vdyBvcGVuIHRoZSBzb2NrZXQKICAgIHdpdGggc29ja2V0LnNvY2tldChzb2NrZXQuQUZfVU5JWCwgc29ja2V0LlNPQ0tfU1RSRUFNKSBhcyBzb2NrOgogICAgICAgIHRyeToKICAgICAgICAgICAgc29jay5jb25uZWN0KGYiL3Byb2Mvc2VsZi9mZC97c29ja19mZH0iKQogICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICBsb2dnZXIuZXJyb3IoCiAgICAgICAgICAgICAgICAiaG9zdCBwaWQgJXMgY3Jhc2hlZCBpbiBhIGNvbnRhaW5lciB3aXRoIGEgYnJva2VuIGFwcG9ydCIsCiAgICAgICAgICAgICAgICBvcHRpb25zLmdsb2JhbF9waWQsCiAgICAgICAgICAgICkKICAgICAgICAgICAgcmV0dXJuCgogICAgICAgICMgU2VuZCBtYWluIGFyZ3VtZW50cyBvbmx5CiAgICAgICAgIyBPbGRlciBhcHBvcnQgaW4gY29udGFpbmVycyBkb2Vzbid0IHN1cHBvcnQgcG9zaXRpb25hbCBhcmd1bWVudHMKICAgICAgICBhcmdzID0gKAogICAgICAgICAgICBmIntvcHRpb25zLnBpZH0ge29wdGlvbnMuc2lnbmFsX251bWJlcn0gIgogICAgICAgICAgICBmIntvcHRpb25zLmNvcmVfdWxpbWl0fSB7b3B0aW9ucy5kdW1wX21vZGV9IgogICAgICAgICkKICAgICAgICAjIFNlbmQgY29yZWR1bXAgZmQgKGRlZmF1bHRzIHRvIDAgZm9yIHN0ZGluKQogICAgICAgIGFuY2lsbGFyeSA9IFsKICAgICAgICAgICAgKAogICAgICAgICAgICAgICAgc29ja2V0LlNPTF9TT0NLRVQsCiAgICAgICAgICAgICAgICBzb2NrZXQuU0NNX1JJR0hUUywKICAgICAgICAgICAgICAgIGJ5dGVzKGFycmF5LmFycmF5KCJpIiwgW2NvcmVkdW1wX2ZkXSkpLAogICAgICAgICAgICApCiAgICAgICAgXQogICAgICAgIGlmIGhhc19jYXBfc3lzX2FkbWluOgogICAgICAgICAgICAjIFNDTV9DUkVERU5USUFMUyBuZWVkcyBDQVBfU1lTX0FETUlOIGZvciBzcGVjaWZ5aW5nIGFub3RoZXIKICAgICAgICAgICAgIyBwcm9jZXNzIElELiBDaGVja2luZyBvcy5nZXRldWlkKCkgdG8gYmUgMCBpcyBub3QgZW5vdWdoLgogICAgICAgICAgICAjIFNlbmQgYSB1Y3JlZCBjb250YWluaW5nIHRoZSBnbG9iYWwgcGlkCiAgICAgICAgICAgIGFuY2lsbGFyeS5hcHBlbmQoCiAgICAgICAgICAgICAgICAoCiAgICAgICAgICAgICAgICAgICAgc29ja2V0LlNPTF9TT0NLRVQsCiAgICAgICAgICAgICAgICAgICAgc29ja2V0LlNDTV9DUkVERU5USUFMUywKICAgICAgICAgICAgICAgICAgICBzdHJ1Y3QucGFjaygiM2kiLCBvcHRpb25zLmdsb2JhbF9waWQsIDAsIDApLAogICAgICAgICAgICAgICAgKQogICAgICAgICAgICApCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzb2NrLnNlbmRtc2coW2FyZ3MuZW5jb2RlKCldLCBhbmNpbGxhcnkpCiAgICAgICAgICAgIHNvY2suc2h1dGRvd24oc29ja2V0LlNIVVRfUkRXUikKICAgICAgICBleGNlcHQgVGltZW91dEVycm9yOgogICAgICAgICAgICBsb2dnZXIuZXJyb3IoIkNvbnRhaW5lciBhcHBvcnQgZmFpbGVkIHRvIHByb2Nlc3MgY3Jhc2ggd2l0aGluIDMwcyIpCgoKZGVmIGNoZWNrX2tlcm5lbF9jcmFzaCgpIC0+IE5vbmU6CiAgICAiIiJDaGVjayBmb3Iga2VybmVsIGNyYXNoIGR1bXAsIGNvbnZlcnQgaXQgdG8gYXBwb3J0IHJlcG9ydC4iIiIKICAgIGtlcm5lbF9jcmFzaF9yZSA9IHJlLmNvbXBpbGUoIl4oWzAtOV17MTJ9fHZtY29yZSkkIikKICAgIGZvciByZXBvcnQgaW4gb3MubGlzdGRpcihhcHBvcnQuZmlsZXV0aWxzLnJlcG9ydF9kaXIpOgogICAgICAgIGlmIGtlcm5lbF9jcmFzaF9yZS5tYXRjaChyZXBvcnQpOgogICAgICAgICAgICBzdWJwcm9jZXNzLnJ1bihbIi91c3Ivc2hhcmUvYXBwb3J0L2tlcm5lbF9jcmFzaGR1bXAiXSwgY2hlY2s9RmFsc2UpCiAgICAgICAgICAgIHJldHVybgoKCmRlZiBjcmVhdGVfZGlyZWN0b3J5KHBhdGg6IHN0ciwgbW9kZTogaW50KSAtPiBOb25lOgogICAgIiIiRW5zdXJlIHRoZSBkaXJlY3RvcnkgaXMgY3JlYXRlZC4KCiAgICBPbmx5IHNldCB0aGUgZGlyZWN0b3J5IG1vZGUgaWYgdGhlIGRpcmVjdG9yeSBpcyBuZXdseSBjcmVhdGVkLgogICAgIiIiCiAgICB3aXRoIGNvbnRleHRsaWIuc3VwcHJlc3MoRmlsZUV4aXN0c0Vycm9yKToKICAgICAgICBvcy5tYWtlZGlycyhwYXRoKQogICAgICAgIG9zLmNobW9kKHBhdGgsIG1vZGUpCgoKZGVmIHdyaXRlX3RvX3Byb2Nfc3lzKHBhdGg6IHN0ciwgdmFsdWU6IHN0cikgLT4gTm9uZToKICAgICIiIldyaXRlIHZhbHVlIHRvIC9wcm9jL3N5cy4iIiIKICAgIHdpdGggb3Blbihvcy5wYXRoLmpvaW4oIi9wcm9jL3N5cyIsIHBhdGgpLCAidyIsIGVuY29kaW5nPSJ1dGYtOCIpIGFzIHByb2M6CiAgICAgICAgcHJvYy53cml0ZSh2YWx1ZSkKCgpkZWYgc3RhcnRfYXBwb3J0KCkgLT4gTm9uZToKICAgICIiIlN0YXJ0IEFwcG9ydCBjcmFzaCBoYW5kbGVyLiIiIgogICAgY3JlYXRlX2RpcmVjdG9yeShhcHBvcnQuZmlsZXV0aWxzLnJlcG9ydF9kaXIsIDBvMzc3NykKICAgIHdyaXRlX3RvX3Byb2Nfc3lzKAogICAgICAgICJrZXJuZWwvY29yZV9wYXR0ZXJuIiwKICAgICAgICBmInx7X19maWxlX199IC1wJXAgLXMlcyAtYyVjIC1kJWQgLVAlUCAtdSV1IC1nJWcgLUYlRiAtLSAlRSIsCiAgICApCiAgICB3cml0ZV90b19wcm9jX3N5cygiZnMvc3VpZF9kdW1wYWJsZSIsICIyIikKICAgIHdyaXRlX3RvX3Byb2Nfc3lzKCJrZXJuZWwvY29yZV9waXBlX2xpbWl0IiwgIjEwIikKICAgIGNoZWNrX2tlcm5lbF9jcmFzaCgpCgoKZGVmIHN0b3BfYXBwb3J0KCkgLT4gTm9uZToKICAgICIiIlN0b3AgQXBwb3J0IGNyYXNoIGhhbmRsZXIuIiIiCiAgICB3cml0ZV90b19wcm9jX3N5cygia2VybmVsL2NvcmVfcGlwZV9saW1pdCIsICIwIikKICAgIHdyaXRlX3RvX3Byb2Nfc3lzKCJmcy9zdWlkX2R1bXBhYmxlIiwgIjAiKQogICAgd3JpdGVfdG9fcHJvY19zeXMoImtlcm5lbC9jb3JlX3BhdHRlcm4iLCAiY29yZSIpCgoKZGVmIHBhcnNlX2FyZ3VtZW50cyhhcmdzOiBsaXN0W3N0cl0pIC0+IGFyZ3BhcnNlLk5hbWVzcGFjZToKICAgIHBhcnNlciA9IGFyZ3BhcnNlLkFyZ3VtZW50UGFyc2VyKCkKCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KCItcCIsICItLXBpZCIsIHR5cGU9aW50LCBoZWxwPSJwcm9jZXNzIGlkICglJXApIikKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoIi1zIiwgIi0tc2lnbmFsLW51bWJlciIsIHR5cGU9aW50LCBoZWxwPSJzaWduYWwgbnVtYmVyICglJXMpIikKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoIi1jIiwgIi0tY29yZS11bGltaXQiLCB0eXBlPWludCwgaGVscD0iY29yZSB1bGltaXQgKCUlYykiKQogICAgcGFyc2VyLmFkZF9hcmd1bWVudCgiLWQiLCAiLS1kdW1wLW1vZGUiLCB0eXBlPWludCwgaGVscD0iZHVtcCBtb2RlICglJWQpIikKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoCiAgICAgICAgIi1QIiwgIi0tZ2xvYmFsLXBpZCIsIHR5cGU9aW50LCBoZWxwPSJwaWQgaW4gcm9vdCBuYW1lc3BhY2UgKCUlUCkiCiAgICApCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KAogICAgICAgICItRiIsICItLXBpZGZkIiwgbmFyZ3M9Ij8iLCB0eXBlPWludCwgaGVscD0icGlkZmQgZm9yIHRoZSBjcmFzaGVkIHByb2Nlc3MgKCUlRikiCiAgICApCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KCItdSIsICItLXVpZCIsIHR5cGU9aW50LCBoZWxwPSJyZWFsIFVJRCAoJSV1KSIpCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KCItZyIsICItLWdpZCIsIHR5cGU9aW50LCBoZWxwPSJyZWFsIEdJRCAoJSVnKSIpCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KCJleGVjdXRhYmxlX3BhdGgiLCBuYXJncz0iKiIsIGhlbHA9InBhdGggb2YgZXhlY3V0YWJsZSAoJSVFKSIpCgogICAgcGFyc2VyLmFkZF9hcmd1bWVudCgKICAgICAgICAiLS1mcm9tLXN5c3RlbWQtY29yZWR1bXAiLAogICAgICAgIGRlc3Q9InN5c3RlbWRfY29yZWR1bXBfaW5zdGFuY2UiLAogICAgICAgIGhlbHA9IlJlYWQgY3Jhc2ggaW5mb3JtYXRpb24gZnJvbSBzeXN0ZW1kLWNvcmVkdW1wIiwKICAgICkKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoCiAgICAgICAgIi0tc3RhcnQiLCBhY3Rpb249InN0b3JlX3RydWUiLCBoZWxwPSJTdGFydCBBcHBvcnQgY3Jhc2ggaGFuZGxlciBhbmQgZXhpdCIKICAgICkKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoCiAgICAgICAgIi0tc3RvcCIsIGFjdGlvbj0ic3RvcmVfdHJ1ZSIsIGhlbHA9IlN0b3AgQXBwb3J0IGNyYXNoIGhhbmRsZXIgYW5kIGV4aXQiCiAgICApCgogICAgb3B0aW9ucyA9IHBhcnNlci5wYXJzZV9hcmdzKGFyZ3MpCgogICAgaWYgbm90IG9wdGlvbnMuc3lzdGVtZF9jb3JlZHVtcF9pbnN0YW5jZSBhbmQgbm90IG9wdGlvbnMuc3RhcnQgYW5kIG5vdCBvcHRpb25zLnN0b3A6CiAgICAgICAgaWYgb3B0aW9ucy5waWQgaXMgTm9uZToKICAgICAgICAgICAgcGFyc2VyLmVycm9yKCJ0aGUgZm9sbG93aW5nIGFyZ3VtZW50cyBhcmUgcmVxdWlyZWQ6IC1wLy0tcGlkIikKICAgICAgICBpZiBvcHRpb25zLmR1bXBfbW9kZSBpcyBOb25lOgogICAgICAgICAgICBwYXJzZXIuZXJyb3IoInRoZSBmb2xsb3dpbmcgYXJndW1lbnRzIGFyZSByZXF1aXJlZDogLWQvLS1kdW1wLW1vZGUiKQoKICAgICMgSW4ga2VybmVscyBiZWZvcmUgNS4zLjAsIGFuIGV4ZWN1dGFibGUgcGF0aCB3aXRoIHNwYWNlcyBtYXkgYmUgc3BsaXQKICAgICMgaW50byBzZXBhcmF0ZSBhcmd1bWVudHMuIElmIG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoIGlzIGEgbGlzdCwgam9pbgogICAgIyBpdCBiYWNrIGludG8gYSBzdHJpbmcuIEFsc28gcmVzdG9yZSBkaXJlY3Rvcnkgc2VwYXJhdG9ycy4KICAgIGlmIGlzaW5zdGFuY2Uob3B0aW9ucy5leGVjdXRhYmxlX3BhdGgsIGxpc3QpOgogICAgICAgIG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoID0gIiAiLmpvaW4ob3B0aW9ucy5leGVjdXRhYmxlX3BhdGgpCiAgICBvcHRpb25zLmV4ZWN1dGFibGVfcGF0aCA9IG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoLnJlcGxhY2UoIiEiLCAiLyIpCiAgICAjIGNvbnNpc3RlbmN5IGNoZWNrIHRvIHByZXZlbnQgdHJpY2tlcnkgbGF0ZXIgb24KICAgIGlmICIuLi8iIGluIG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoOgogICAgICAgIG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoID0gTm9uZQoKICAgIHJldHVybiBvcHRpb25zCgoKZGVmIF9jaGVja19nbG9iYWxfcGlkX2FuZF9mb3J3YXJkKAogICAgb3B0aW9uczogYXJncGFyc2UuTmFtZXNwYWNlLCBwcm9jX3BpZDogUHJvY1BpZAopIC0+IGJvb2w6CiAgICAiIiJDaGVjayB0aGUgZ2xvYmFsIFBJRCBpZiB0aGUgY3Jhc2ggaGFwcGVucyBpbiBhIGNvbnRhaW5lci4KCiAgICBDaGVjayBpZiB3ZSByZWNlaXZlZCBhIHZhbGlkIGdsb2JhbCBQSUQgKGtlcm5lbCA+PSAzLjEyKS4gSWYgd2UgZG8sCiAgICB0aGVuIGNvbXBhcmUgaXQgd2l0aCB0aGUgbG9jYWwgUElELiBJbiB0aGF0IGNhc2UgZm9yd2FyZCB0aGUgY3Jhc2gKICAgIHRvIHRoZSBjb250YWluZXIuCgogICAgSWYgdGhleSBkb24ndCBtYXRjaCwgaXQncyBhbiBpbmRpY2F0aW9uIHRoYXQgdGhlIGNyYXNoIG9yaWdpbmF0ZWQKICAgIGZyb20gYW5vdGhlciBQSUQgbmFtZXNwYWNlLiBTaW1wbHkgbG9nIGFuIGVudHJ5IGluIHRoZSBob3N0IGVycm9yCiAgICBsb2cgYW5kIGxldCBhcHBvcnQgZXhpdC4KCiAgICBSZXR1cm5zIFRydWUgaW4gY2FzZSBhcHBvcnQgc2hvdWxkIGV4aXQgd2l0aCAwLgogICAgIiIiCiAgICBpZiBvcHRpb25zLmdsb2JhbF9waWQgaXMgbm90IE5vbmU6CiAgICAgICAgaWYgbm90IGlzX3NhbWVfbnMocHJvY19waWQsICJtbnQiKToKICAgICAgICAgICAgaWYgbm90IGlzX3NhbWVfbnMocHJvY19waWQsICJwaWQiKToKICAgICAgICAgICAgICAgIGZvcndhcmRfY3Jhc2hfdG9fY29udGFpbmVyKG9wdGlvbnMsIHByb2NfcGlkKQogICAgICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoKS5lcnJvcigKICAgICAgICAgICAgICAgICJob3N0IHBpZCAlcyBjcmFzaGVkIGluIGEgc2VwYXJhdGUgbW91bnQgbmFtZXNwYWNlLCBpZ25vcmluZyIsCiAgICAgICAgICAgICAgICBvcHRpb25zLmdsb2JhbF9waWQsCiAgICAgICAgICAgICkKICAgICAgICAgICAgcmV0dXJuIFRydWUKCiAgICAgICAgIyBJZiBpdCBkb2Vzbid0IGxvb2sgbGlrZSB0aGUgY3Jhc2ggb3JpZ2luYXRlZCBmcm9tIHdpdGhpbiBhIGZ1bGwKICAgICAgICAjIGNvbnRhaW5lciBvciBpZiB0aGUgaXNfc2FtZV9ucygpIGZ1bmN0aW9uIGZhaWxzIG9wZW4gKHJldHVybmluZwogICAgICAgICMgVHJ1ZSksIHRoZW4gdGFrZSB0aGUgZ2xvYmFsIHBpZCBhbmQgbW92ZSBvbiB0byBub3JtYWwgaGFuZGxpbmcuCgogICAgICAgICMgVGhpcyBiaXQgaXMgbmVlZGVkIGJlY2F1c2Ugc29tZSBzb2Z0d2FyZSBsaWtlIHRoZSBjaHJvbWUgc2FuZGJveAogICAgICAgICMgd2lsbCB1c2UgY29udGFpbmVyIG5hbWVzcGFjZXMgYXMgYSBzZWN1cml0eSBtZWFzdXJlIGJ1dCBhcmUgc3RpbGwKICAgICAgICAjIG90aGVyd2lzZSBob3N0IHByb2Nlc3Nlcy4gV2hlbiB0aGF0J3MgdGhlIGNhc2UsIHdlIG5lZWQgdG8ga2VlcAogICAgICAgICMgaGFuZGxpbmcgdGhvc2UgY3Jhc2hlcyBsb2NhbGx5IHVzaW5nIHRoZSBnbG9iYWwgcGlkLgogICAgcmV0dXJuIEZhbHNlCgoKIyBweWxpbnQ6IGRpc2FibGUtbmV4dD1taXNzaW5nLWZ1bmN0aW9uLWRvY3N0cmluZwpkZWYgbWFpbihhcmdzOiBsaXN0W3N0cl0pIC0+IGludDoKICAgIGluaXRfZXJyb3JfbG9nKCkKICAgIGxvZ2dpbmcuYmFzaWNDb25maWcoZm9ybWF0PUxPR19GT1JNQVQsIGxldmVsPWxvZ2dpbmcuSU5GTykKCiAgICAjIHN5c3RlbWQgc29ja2V0IGFjdGl2YXRpb24KICAgIGlmICJMSVNURU5fRkRTIiBpbiBvcy5lbnZpcm9uOgogICAgICAgIG9wdGlvbnMgPSByZWNlaXZlX2FyZ3VtZW50c192aWFfc29ja2V0KCkKICAgIGVsc2U6CiAgICAgICAgb3B0aW9ucyA9IHBhcnNlX2FyZ3VtZW50cyhhcmdzKQoKICAgIGlmIG9wdGlvbnMuc3lzdGVtZF9jb3JlZHVtcF9pbnN0YW5jZToKICAgICAgICByZXR1cm4gcHJvY2Vzc19jcmFzaF9mcm9tX3N5c3RlbWRfY29yZWR1bXAob3B0aW9ucy5zeXN0ZW1kX2NvcmVkdW1wX2luc3RhbmNlKQogICAgaWYgb3B0aW9ucy5zdG9wOgogICAgICAgIHN0b3BfYXBwb3J0KCkKICAgICAgICByZXR1cm4gMAogICAgaWYgb3B0aW9ucy5zdGFydDoKICAgICAgICBzdGFydF9hcHBvcnQoKQogICAgICAgIHJldHVybiAwCgogICAgdHJ5OgogICAgICAgIHJldHVybiBwcm9jZXNzX2NyYXNoX2Zyb21fa2VybmVsKG9wdGlvbnMpCiAgICBleGNlcHQgKFN5c3RlbUV4aXQsIEtleWJvYXJkSW50ZXJydXB0KToKICAgICAgICBwYXNzCiAgICBleGNlcHQgRXhjZXB0aW9uOiAgIyBweWxpbnQ6IGRpc2FibGU9YnJvYWQtZXhjZXB0CiAgICAgICAgbG9nZ2VyID0gbG9nZ2luZy5nZXRMb2dnZXIoKQogICAgICAgIGxvZ2dlci5lcnJvcigiVW5oYW5kbGVkIGV4Y2VwdGlvbjoiKQogICAgICAgIHRyYWNlYmFjay5wcmludF9leGMoKQogICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgInBpZDogJWksIHVpZDogJWksIGdpZDogJWksIGV1aWQ6ICVpLCBlZ2lkOiAlaSIsCiAgICAgICAgICAgIG9zLmdldHBpZCgpLAogICAgICAgICAgICBvcy5nZXR1aWQoKSwKICAgICAgICAgICAgb3MuZ2V0Z2lkKCksCiAgICAgICAgICAgIG9zLmdldGV1aWQoKSwKICAgICAgICAgICAgb3MuZ2V0ZWdpZCgpLAogICAgICAgICkKICAgICAgICBsb2dnZXIuZXJyb3IoImVudmlyb25tZW50OiAlcyIsIG9zLmVudmlyb24pCgogICAgcmV0dXJuIDAKCgpkZWYgcmVjZWl2ZV9hcmd1bWVudHNfdmlhX3NvY2tldCgpIC0+IGFyZ3BhcnNlLk5hbWVzcGFjZToKICAgICIiIlJlY2VpdmUgYXJndW1lbnRzIGZyb20gdGhlIGhvc3QgdmlhIGEgc29ja2V0LiIiIgogICAgdHJ5OgogICAgICAgICMgcHlsaW50OiBkaXNhYmxlPWltcG9ydC1vdXRzaWRlLXRvcGxldmVsCiAgICAgICAgZnJvbSBzeXN0ZW1kLmRhZW1vbiBpbXBvcnQgbGlzdGVuX2ZkcwogICAgZXhjZXB0IEltcG9ydEVycm9yOgogICAgICAgIGxvZ2dpbmcuZ2V0TG9nZ2VyKCkuZXJyb3IoCiAgICAgICAgICAgICJSZWNlaXZlZCBhIGNyYXNoIHZpYSBhcHBvcnQtZm9yd2FyZC5zb2NrZXQsIgogICAgICAgICAgICAiIGJ1dCBzeXN0ZW1kIHB5dGhvbiBtb2R1bGUgaXMgbm90IGluc3RhbGxlZCIKICAgICAgICApCiAgICAgICAgc3lzLmV4aXQoMCkKCiAgICAjIEV4dHJhY3QgYW5kIHZhbGlkYXRlIHRoZSBmZAogICAgZmRzID0gbGlzdGVuX2ZkcygpCiAgICBpZiBsZW4oZmRzKSA8IDE6CiAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoKS5lcnJvcigiSW52YWxpZCBzb2NrZXQgYWN0aXZhdGlvbiwgbm8gZmQgcHJvdmlkZWQiKQogICAgICAgIHN5cy5leGl0KDEpCgogICAgIyBPcGVuIHRoZSBzb2NrZXQKICAgIHNvY2sgPSBzb2NrZXQuZnJvbWZkKGludChmZHNbMF0pLCBzb2NrZXQuQUZfVU5JWCwgc29ja2V0LlNPQ0tfU1RSRUFNKQogICAgYXRleGl0LnJlZ2lzdGVyKHNvY2suc2h1dGRvd24sIHNvY2tldC5TSFVUX1JEV1IpCgogICAgIyBSZXBsYWNlIHN0ZGluIGJ5IHRoZSBzb2NrZXQgYWN0aXZhdGlvbiBmZAogICAgc3lzLnN0ZGluLmNsb3NlKCkKCiAgICBmZHMgPSBhcnJheS5hcnJheSgiaSIpCiAgICB1Y3JlZHMgPSBhcnJheS5hcnJheSgiaSIpCiAgICBtc2csIGFuY2RhdGEsIF91bnVzZWRfZmxhZ3MsIF91bnVzZWRfYWRkciA9IHNvY2sucmVjdm1zZyg0MDk2LCA0MDk2KQogICAgZm9yIGNtc2dfbGV2ZWwsIGNtc2dfdHlwZSwgY21zZ19kYXRhIGluIGFuY2RhdGE6CiAgICAgICAgaWYgY21zZ19sZXZlbCA9PSBzb2NrZXQuU09MX1NPQ0tFVCBhbmQgY21zZ190eXBlID09IHNvY2tldC5TQ01fUklHSFRTOgogICAgICAgICAgICBmZHMuZnJvbWJ5dGVzKGNtc2dfZGF0YVs6IGxlbihjbXNnX2RhdGEpIC0gKGxlbihjbXNnX2RhdGEpICUgZmRzLml0ZW1zaXplKV0pCiAgICAgICAgZWxpZiBjbXNnX2xldmVsID09IHNvY2tldC5TT0xfU09DS0VUIGFuZCBjbXNnX3R5cGUgPT0gc29ja2V0LlNDTV9DUkVERU5USUFMUzoKICAgICAgICAgICAgdWNyZWRzLmZyb21ieXRlcygKICAgICAgICAgICAgICAgIGNtc2dfZGF0YVs6IGxlbihjbXNnX2RhdGEpIC0gKGxlbihjbXNnX2RhdGEpICUgdWNyZWRzLml0ZW1zaXplKV0KICAgICAgICAgICAgKQoKICAgIHN5cy5zdGRpbiA9IG9zLmZkb3BlbihpbnQoZmRzWzBdKSwgInIiKQoKICAgICMgUmVwbGFjZSBhcmdzIGJ5IHRoZSBhcmd1bWVudHMgcmVjZWl2ZWQgb3ZlciB0aGUgc29ja2V0CiAgICBhcmdzID0gbXNnLmRlY29kZSgpLnNwbGl0KCkKICAgIGlmIGxlbih1Y3JlZHMpID49IDM6CiAgICAgICAgYXJnc1swXSA9IHN0cih1Y3JlZHNbMF0pCgogICAgaWYgbGVuKGFyZ3MpICE9IDQ6CiAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoKS5lcnJvcigKICAgICAgICAgICAgIlJlY2VpdmVkIGEgYmFkIG51bWJlciBvZiBhcmd1bWVudHMgZnJvbSBmb3J3YXJkZXIsIgogICAgICAgICAgICAiIHJlY2VpdmVkICVkLCBleHBlY3RlZCA0LCBhYm9ydGluZy4iLAogICAgICAgICAgICBsZW4oYXJncyksCiAgICAgICAgKQogICAgICAgIHN5cy5leGl0KDEpCgogICAgcmV0dXJuIGFyZ3BhcnNlLk5hbWVzcGFjZSgKICAgICAgICBwaWQ9aW50KGFyZ3NbMF0pLAogICAgICAgIHNpZ25hbF9udW1iZXI9aW50KGFyZ3NbMV0pLAogICAgICAgIGNvcmVfdWxpbWl0PWludChhcmdzWzJdKSwKICAgICAgICBkdW1wX21vZGU9aW50KGFyZ3NbM10pLAogICAgICAgIGdsb2JhbF9waWQ9Tm9uZSwKICAgICAgICBwaWRmZD1Ob25lLAogICAgICAgIHVpZD1Ob25lLAogICAgICAgIGdpZD1Ob25lLAogICAgICAgIGV4ZWN1dGFibGVfcGF0aD1Ob25lLAogICAgICAgIHN5c3RlbWRfY29yZWR1bXBfaW5zdGFuY2U9Tm9uZSwKICAgICAgICBzdGFydD1GYWxzZSwKICAgICAgICBzdG9wPUZhbHNlLAogICAgKQoKCmRlZiBjb25zaXN0ZW5jeV9jaGVja3MoCiAgICBvcHRpb25zOiBhcmdwYXJzZS5OYW1lc3BhY2UsCiAgICBwcm9jZXNzX3N0YXJ0OiBpbnQsCiAgICBwcm9jX3BpZDogUHJvY1BpZCwKICAgIHJlYWxfdXNlcjogVXNlckdyb3VwSUQsCikgLT4gYm9vbDoKICAgICIiIlJ1biBjb25zaXN0ZW5jeSBjaGVja3MgYW5kIHJldHVybiBUcnVlIGlmIGFsbCBwYXNzLiIiIgogICAgbG9nZ2VyID0gbG9nZ2luZy5nZXRMb2dnZXIoKQoKICAgICMgQ29uc2lzdGVuY3kgY2hlY2sgdG8gbWFrZSBzdXJlIHRoZSBwcm9jZXNzIHdhc24ndCByZXBsYWNlZCBhZnRlciB0aGUKICAgICMgY3Jhc2ggaGFwcGVuZWQuIFRoZSBzdGFydCB0aW1lIGlzbid0IGZpbmUtZ3JhaW5lZCBlbm91Z2ggdG8gYmUgYW4KICAgICMgYWRlcXVhdGUgc2VjdXJpdHkgY2hlY2suCiAgICBhcHBvcnRfc3RhcnQgPSBnZXRfYXBwb3J0X3N0YXJ0dGltZSgpCiAgICBpZiBwcm9jZXNzX3N0YXJ0ID4gYXBwb3J0X3N0YXJ0OgogICAgICAgIGxvZ2dlci5lcnJvcigicHJvY2VzcyB3YXMgcmVwbGFjZWQgYWZ0ZXIgQXBwb3J0IHN0YXJ0ZWQsIGlnbm9yaW5nIikKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICAjIE1ha2Ugc3VyZSB0aGUgcHJvY2VzcyB1aWQvZ2lkIG1hdGNoIHRoZSBvbmVzIHByb3ZpZGVkIGJ5IHRoZSBrZXJuZWwKICAgICMgaWYgYXZhaWxhYmxlLCBpZiBub3QsIGl0IG1heSBoYXZlIGJlZW4gcmVwbGFjZWQKICAgIGlmIChvcHRpb25zLnVpZCBpcyBub3QgTm9uZSkgYW5kIChvcHRpb25zLmdpZCBpcyBub3QgTm9uZSk6CiAgICAgICAgaWYgVXNlckdyb3VwSUQob3B0aW9ucy51aWQsIG9wdGlvbnMuZ2lkKSAhPSByZWFsX3VzZXI6CiAgICAgICAgICAgIGxvZ2dlci5lcnJvcigicHJvY2VzcyB1aWQvZ2lkIGRvZXNuJ3QgbWF0Y2ggZXhwZWN0ZWQsIGlnbm9yaW5nIikKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgIyBjaGVjayBpZiB0aGUgZXhlY3V0YWJsZSB3YXMgbW9kaWZpZWQgYWZ0ZXIgdGhlIHByb2Nlc3Mgc3RhcnRlZCAoZS4gZy4KICAgICMgcGFja2FnZSBnb3QgdXBncmFkZWQgaW4gYmV0d2VlbikuCiAgICBleGVfcGF0aCA9IGYicm9vdHtwcm9jX3BpZC5yZWFkbGluaygnZXhlJyl9IgogICAgcHJvY2Vzc19tdGltZSA9IG9zLmxzdGF0KCJjbWRsaW5lIiwgZGlyX2ZkPXByb2NfcGlkLmZkKS5zdF9tdGltZQogICAgaWYgKAogICAgICAgIG5vdCBwcm9jX3BpZC5leGlzdHMoZXhlX3BhdGgpCiAgICAgICAgb3IgcHJvY19waWQuc3RhdChleGVfcGF0aCkuc3RfbXRpbWUgPiBwcm9jZXNzX210aW1lCiAgICApOgogICAgICAgIGxvZ2dlci5lcnJvcigiZXhlY3V0YWJsZSB3YXMgbW9kaWZpZWQgYWZ0ZXIgcHJvZ3JhbSBzdGFydCwgaWdub3JpbmciKQogICAgICAgIHJldHVybiBGYWxzZQoKICAgIHJldHVybiBUcnVlCgoKZGVmIHJlZmluZV9jb3JlX3VsaW1pdChvcHRpb25zOiBhcmdwYXJzZS5OYW1lc3BhY2UpIC0+IGludDoKICAgICIiIlJlZmluZSBlZmZlY3RpdmUgY29yZSB1bGltaXQgYnkgdGFraW5nIGR1bXAgbW9kZSBpbnRvIGFjY291bnQuIiIiCiAgICBjb3JlX3VsaW1pdCA9IG9wdGlvbnMuY29yZV91bGltaXQKCiAgICAjIGNsYW1wIGNvcmVfdWxpbWl0IHRvIGEgc2Vuc2libGUgc2l6ZSwgZm9yIC0xIHRoZSBrZXJuZWwgcmVwb3J0cwogICAgIyBzb21ldGhpbmcgYWJzdXJkbHkgYmlnCiAgICBpZiBjb3JlX3VsaW1pdCA+IDkyMjMzNzIwMzY4NTQ3NzU4MDc6CiAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoKS5lcnJvcigKICAgICAgICAgICAgImlnbm9yaW5nIGltcGxhdXNpYmx5IGJpZyBjb3JlIGxpbWl0LCB0cmVhdGluZyBhcyB1bmxpbWl0ZWQiCiAgICAgICAgKQogICAgICAgIGNvcmVfdWxpbWl0ID0gLTEKCiAgICByZXR1cm4gY29yZV91bGltaXQKCgpkZWYgcHJvY2Vzc19jcmFzaF9mcm9tX2tlcm5lbChvcHRpb25zOiBhcmdwYXJzZS5OYW1lc3BhY2UpIC0+IGludDoKICAgIGlmIG9wdGlvbnMuZ2xvYmFsX3BpZCBpcyBOb25lOgogICAgICAgIHBpZCA9IG9wdGlvbnMucGlkCiAgICBlbHNlOgogICAgICAgIHBpZCA9IG9wdGlvbnMuZ2xvYmFsX3BpZAogICAgdHJ5OgogICAgICAgIHdpdGggUHJvY1BpZChwaWQpIGFzIHByb2NfcGlkOgogICAgICAgICAgICBpZiBvcHRpb25zLnBpZGZkIGlzIG5vdCBOb25lIGFuZCBub3QgcHJvY19waWQuaGFzX3NhbWVfcGlkKG9wdGlvbnMucGlkZmQpOgogICAgICAgICAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoKS5lcnJvcigKICAgICAgICAgICAgICAgICAgICAiVGhlIHByb2Nlc3MgJWkgaGFzIGFscmVhZHkgYmVlbiByZXBsYWNlZCBieSBhIG5ldyBwcm9jZXNzIgogICAgICAgICAgICAgICAgICAgICIgd2l0aCB0aGUgc2FtZSBJRC4gSWdub3JpbmcgY3Jhc2guIiwKICAgICAgICAgICAgICAgICAgICBwaWQsCiAgICAgICAgICAgICAgICApCiAgICAgICAgICAgICAgICByZXR1cm4gMQogICAgICAgICAgICByZXR1cm4gcHJvY2Vzc19jcmFzaF9mcm9tX2tlcm5lbF93aXRoX3Byb2NfcGlkKG9wdGlvbnMsIHByb2NfcGlkKQogICAgZXhjZXB0IFByb2NQaWROb3RGb3VuZEVycm9yIGFzIGVycm9yOgogICAgICAgIGxvZ2dpbmcuZ2V0TG9nZ2VyKCkuZXJyb3IoCiAgICAgICAgICAgICIlcyBub3QgZm91bmQuICIKICAgICAgICAgICAgIkNhbm5vdCBjb2xsZWN0IGNyYXNoIGluZm9ybWF0aW9uIGZvciBwcm9jZXNzICVpIGFueSBtb3JlLiIsCiAgICAgICAgICAgIGVycm9yLmZpbGVuYW1lLAogICAgICAgICAgICBwaWQsCiAgICAgICAgKQogICAgICAgIHJldHVybiAxCgoKZGVmIF9zZXRfc2lnbmFsKHJlcG9ydDogYXBwb3J0LnJlcG9ydC5SZXBvcnQsIHNpZ25hbF9udW1iZXI6IGludCkgLT4gTm9uZToKICAgIHJlcG9ydFsiU2lnbmFsIl0gPSBzdHIoc2lnbmFsX251bWJlcikKICAgIHdpdGggY29udGV4dGxpYi5zdXBwcmVzcyhWYWx1ZUVycm9yKToKICAgICAgICByZXBvcnRbIlNpZ25hbE5hbWUiXSA9IHNpZ25hbC5TaWduYWxzKHNpZ25hbF9udW1iZXIpLm5hbWUKCgpkZWYgZGV0ZXJtaW5lX3JlcG9ydF9vd25lcihkdW1wX21vZGU6IGludCwgcmVhbF91c2VyOiBVc2VyR3JvdXBJRCkgLT4gVXNlckdyb3VwSUQ6CiAgICAiIiJEZXRlcm1pbmUgd2hvIHNob3VsZCBiZSB0aGUgb3duZXIgb2YgdGhlIGNyYXNoIHJlcG9ydCBmaWxlLgoKICAgIEZvciBkdW1wX21vZGUgMSAoImRlYnVnIikgdGhlIG93bmVyIG9mIHRoZSBwcm9jZXNzIGNhbiBiZWNvbWUgdGhlCiAgICBjcmFzaCByZXBvcnQgb3duZXIuIEZvciBkdW1wX21vZGUgMiAoInN1aWRzYWZlIikgdGhlIGNyYXNoZWQgcHJvY2VzcwogICAgaXMgYSBzdWlkIHByb2Nlc3MgYW5kIHRoZSByZXBvcnQgc2hvdWxkIGJlIG93bmVkIGJ5IHJvb3QgaW5zdGVhZC4KCiAgICBTZWUgcHJvY19zeXNfZnMoNSkgbWFuIHBhZ2UgYW5kCiAgICBodHRwczovL2tlcm5lbC5vcmcvZG9jL2h0bWwvbGF0ZXN0L2FkbWluLWd1aWRlL3N5c2N0bC9mcy5odG1sI3N1aWQtZHVtcGFibGUKICAgICIiIgogICAgaWYgZHVtcF9tb2RlID09IDE6CiAgICAgICAgcmV0dXJuIHJlYWxfdXNlcgogICAgcmV0dXJuIFVzZXJHcm91cElEKDAsIDApCgoKIyBweWxpbnQ6IGRpc2FibGUtbmV4dD10b28tbWFueS1yZXR1cm4tc3RhdGVtZW50cwpkZWYgcHJvY2Vzc19jcmFzaF9mcm9tX2tlcm5lbF93aXRoX3Byb2NfcGlkKAogICAgb3B0aW9uczogYXJncGFyc2UuTmFtZXNwYWNlLCBwcm9jX3BpZDogUHJvY1BpZAopIC0+IGludDoKICAgICIiIlByb2Nlc3MgY3Jhc2ggYW5kIHJldHVybiBleGl0IGNvZGUuIiIiCiAgICBsb2dnZXIgPSBsb2dnaW5nLmdldExvZ2dlcigpCgogICAgY2hlY2tfbG9jaygpCiAgICBzZXR1cF9zaWduYWxzKCkKCiAgICByZWFsX3VzZXIsIF8gPSBnZXRfcGlkX2luZm8ocHJvY19waWQpCiAgICBwcm9jZXNzX3N0YXJ0ID0gZ2V0X3Byb2Nlc3Nfc3RhcnR0aW1lKHByb2NfcGlkKQogICAgaWYgbm90IGNvbnNpc3RlbmN5X2NoZWNrcyhvcHRpb25zLCBwcm9jZXNzX3N0YXJ0LCBwcm9jX3BpZCwgcmVhbF91c2VyKToKICAgICAgICByZXR1cm4gMAoKICAgIGlmIF9jaGVja19nbG9iYWxfcGlkX2FuZF9mb3J3YXJkKG9wdGlvbnMsIHByb2NfcGlkKToKICAgICAgICByZXR1cm4gMAoKICAgIGNvcmVkdW1wX2ZkID0gc3lzLnN0ZGluLmZpbGVubygpCiAgICBsb2dnZXIuaW5mbygKICAgICAgICAiY2FsbGVkIGZvciAlcywgc2lnbmFsICVzLCBjb3JlIGxpbWl0ICVzLCBkdW1wIG1vZGUgJXMiLAogICAgICAgICgKICAgICAgICAgICAgZiJwaWQge29wdGlvbnMucGlkfSIKICAgICAgICAgICAgaWYgb3B0aW9ucy5nbG9iYWxfcGlkIGlzIE5vbmUKICAgICAgICAgICAgZWxzZSBmImdsb2JhbCBwaWQge29wdGlvbnMuZ2xvYmFsX3BpZH0iCiAgICAgICAgKSwKICAgICAgICBvcHRpb25zLnNpZ25hbF9udW1iZXIsCiAgICAgICAgb3B0aW9ucy5jb3JlX3VsaW1pdCwKICAgICAgICBvcHRpb25zLmR1bXBfbW9kZSwKICAgICkKCiAgICBjb3JlX3VsaW1pdCA9IHJlZmluZV9jb3JlX3VsaW1pdChvcHRpb25zKQoKICAgIGNvcmVfcGF0aCA9IGdldF9jb3JlX3BhdGgob3B0aW9ucywgcmVhbF91c2VyLCBwcm9jX3BpZCwgcHJvY2Vzc19zdGFydCkKICAgIHJlcG9ydF9vd25lciA9IGRldGVybWluZV9yZXBvcnRfb3duZXIob3B0aW9ucy5kdW1wX21vZGUsIHJlYWxfdXNlcikKCiAgICAjIGlnbm9yZSBTSUdRVUlUIChpdCdzIHVzdWFsbHkgZGVsaWJlcmF0ZWx5IGdlbmVyYXRlZCBieSB1c2VycykKICAgIGlmIG9wdGlvbnMuc2lnbmFsX251bWJlciA9PSBpbnQoc2lnbmFsLlNJR1FVSVQpOgogICAgICAgIHdyaXRlX3VzZXJfY29yZWR1bXAoY29yZV9wYXRoLCBjb3JlX3VsaW1pdCwgcHJvY19waWQsIHJlcG9ydF9vd25lciwgY29yZWR1bXBfZmQpCiAgICAgICAgcmV0dXJuIDAKCiAgICBpbmZvID0gYXBwb3J0LnJlcG9ydC5SZXBvcnQoIkNyYXNoIikKICAgIF9zZXRfc2lnbmFsKGluZm8sIG9wdGlvbnMuc2lnbmFsX251bWJlcikKICAgIGNvcmVfc2l6ZV9saW1pdCA9IHVzYWJsZV9yYW0oKSAqIDMgLyA0CiAgICAjIHN5cy5zdGRpbiBoYXMgdHlwZSBpby5UZXh0SU9XcmFwcGVyLCBub3QgdGhlIGNsYWltZWQgaW8uVGV4dElPLgogICAgIyBTZWUgaHR0cHM6Ly9naXRodWIuY29tL3B5dGhvbi90eXBlc2hlZC9pc3N1ZXMvMTAwOTMKICAgIGFzc2VydCBpc2luc3RhbmNlKHN5cy5zdGRpbiwgaW8uVGV4dElPV3JhcHBlcikKICAgICMgcmVhZCBiaW5hcnkgZGF0YSBmcm9tIHN0ZGlvCiAgICBpbmZvWyJDb3JlRHVtcCJdID0gKHN5cy5zdGRpbi5kZXRhY2goKSwgVHJ1ZSwgY29yZV9zaXplX2xpbWl0LCBUcnVlKQoKICAgICMgV2UgYWxyZWFkeSBuZWVkIHRoaXMgaGVyZSB0byBmaWd1cmUgb3V0IHRoZSBFeGVjdXRhYmxlTmFtZSAoZm9yCiAgICAjIHNjcmlwdHMsIGV0YykuCiAgICBpZiBvcHRpb25zLmV4ZWN1dGFibGVfcGF0aCBpcyBub3QgTm9uZSBhbmQgb3MucGF0aC5leGlzdHMob3B0aW9ucy5leGVjdXRhYmxlX3BhdGgpOgogICAgICAgIGluZm9bIkV4ZWN1dGFibGVQYXRoIl0gPSBvcHRpb25zLmV4ZWN1dGFibGVfcGF0aAogICAgZWxzZToKICAgICAgICBpbmZvWyJFeGVjdXRhYmxlUGF0aCJdID0gb3MucmVhZGxpbmsoImV4ZSIsIGRpcl9mZD1wcm9jX3BpZC5mZCkKCiAgICAjIERvIG5vdCBjaGVjayBjbG9zaW5nIHNlc3Npb24gZm9yIHJvb3QgcHJvY2Vzc2VzCiAgICBpZiBub3QgcmVhbF91c2VyLmlzX3Jvb3QoKSBhbmQgaXNfY2xvc2luZ19zZXNzaW9uKHByb2NfcGlkLCByZWFsX3VzZXIpOgogICAgICAgIGxvZ2dlci5lcnJvcigiaGFwcGVucyBmb3Igc2h1dHRpbmcgZG93biBzZXNzaW9uLCBpZ25vcmluZyIpCiAgICAgICAgcmV0dXJuIDAKCiAgICAjIGlnbm9yZSBzeXN0ZW1kIHdhdGNoZG9nIGtpbGxzOyBtb3N0IG9mdGVuIHRoZXkgZG9uJ3QgdGVsbCB1cyB0aGUKICAgICMgYWN0dWFsIHJlYXNvbiAoa2VybmVsIGhhbmcsIGV0Yy4pLCBMUCAjMTQzMzMyMAogICAgaWYgaXNfc3lzdGVtZF93YXRjaGRvZ19yZXN0YXJ0KG9wdGlvbnMuc2lnbmFsX251bWJlciwgcHJvY19waWQpOgogICAgICAgIGxvZ2dlci5lcnJvcigiSWdub3Jpbmcgc3lzdGVtZCB3YXRjaGRvZyByZXN0YXJ0IikKICAgICAgICByZXR1cm4gMAoKICAgICMgRHJvcCBwcml2aWxlZ2VzIHRlbXBvcmFyaWx5IHRvIG1ha2Ugc3VyZSB0aGF0IHdlIGRvbid0CiAgICAjIGluY2x1ZGUgaW5mb3JtYXRpb24gaW4gdGhlIGNyYXNoIHJlcG9ydCB0aGF0IHRoZSB1c2VyIHNob3VsZAogICAgIyBub3QgYmUgYWxsb3dlZCB0byBhY2Nlc3MuCiAgICBkcm9wX3ByaXZpbGVnZXMocmVhbF91c2VyKQoKICAgIGluZm8ucGlkID0gcHJvY19waWQucGlkCiAgICBpbmZvLmFkZF9wcm9jX2luZm8ocHJvY19waWRfZmQ9cHJvY19waWQuZmQpCgogICAgaWYgIkV4ZWN1dGFibGVQYXRoIiBub3QgaW4gaW5mbzoKICAgICAgICBsb2dnZXIuZXJyb3IoImNvdWxkIG5vdCBkZXRlcm1pbmUgRXhlY3V0YWJsZVBhdGgsIGFib3J0aW5nIikKICAgICAgICByZXR1cm4gMQoKICAgIGRlZiBfd3JpdGVfY29yZWR1bXBfY2FsbGJhY2soZnJvbV9yZXBvcnQ6IHR5cGluZy5CaW5hcnlJTyB8IE5vbmUgPSBOb25lKSAtPiBOb25lOgogICAgICAgIHdyaXRlX3VzZXJfY29yZWR1bXAoCiAgICAgICAgICAgIGNvcmVfcGF0aCwgY29yZV91bGltaXQsIHByb2NfcGlkLCByZXBvcnRfb3duZXIsIGNvcmVkdW1wX2ZkLCBmcm9tX3JlcG9ydAogICAgICAgICkKCiAgICByZXN1bHQgPSBwcm9jZXNzX2NyYXNoKGluZm8sIHJlYWxfdXNlciwgcmVwb3J0X293bmVyLCBfd3JpdGVfY29yZWR1bXBfY2FsbGJhY2spCiAgICBpZiAiQ29yZUR1bXAiIG5vdCBpbiBpbmZvOgogICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgImNvcmUgZHVtcCBleGNlZWRlZCAlaSBNaUIsIGRyb3BwZWQgdG8gYXZvaWQgbWVtb3J5IG92ZXJmbG93IiwKICAgICAgICAgICAgY29yZV9zaXplX2xpbWl0IC8gMTA0ODU3NiwKICAgICAgICApCiAgICByZXR1cm4gcmVzdWx0CgoKZGVmIHByb2Nlc3NfY3Jhc2goCiAgICBpbmZvOiBhcHBvcnQucmVwb3J0LlJlcG9ydCwKICAgIHJlYWxfdXNlcjogVXNlckdyb3VwSUQsCiAgICByZXBvcnRfb3duZXI6IFVzZXJHcm91cElELAogICAgd3JpdGVfY29yZWR1bXBfY2FsbGJhY2s6IENhbGxhYmxlW1t0eXBpbmcuQmluYXJ5SU8gfCBOb25lXSwgTm9uZV0gfCBOb25lID0gTm9uZSwKKSAtPiBpbnQ6CiAgICAiIiJQcm9jZXNzIGNyYXNoIGFuZCByZXR1cm4gZXhpdCBjb2RlLiIiIgogICAgIyBUT0RPOiBTcGxpdCBpbnRvIHNtYWxsZXIgZnVuY3Rpb25zL21ldGhvZHMKICAgICMgcHlsaW50OiBkaXNhYmxlPXRvby1tYW55LWJyYW5jaGVzLHRvby1tYW55LXN0YXRlbWVudHMKICAgIGxvZ2dlciA9IGxvZ2dpbmcuZ2V0TG9nZ2VyKCkKCiAgICByZXBvcnQgPSAoCiAgICAgICAgZiJ7YXBwb3J0LmZpbGV1dGlscy5yZXBvcnRfZGlyfSIKICAgICAgICBmIi97aW5mb1snRXhlY3V0YWJsZVBhdGgnXS5yZXBsYWNlKCcvJywgJ18nKX0ue3JlYWxfdXNlci51aWR9LmNyYXNoIgogICAgKQogICAgaGFuZ2luZyA9IGYie29zLnBhdGguc3BsaXRleHQocmVwb3J0KVswXX0ue2luZm8ucGlkfS5oYW5naW5nIgoKICAgIGlmIG9zLnBhdGguZXhpc3RzKGhhbmdpbmcpOgogICAgICAgIGlmIG9zLnN0YXQoIi9wcm9jL3VwdGltZSIpLnN0X2N0aW1lIDwgb3Muc3RhdChoYW5naW5nKS5zdF9tdGltZToKICAgICAgICAgICAgaW5mb1siUHJvYmxlbVR5cGUiXSA9ICJIYW5nIgogICAgICAgIG9zLnVubGluayhoYW5naW5nKQoKICAgIGlmICJJbnRlcnByZXRlclBhdGgiIGluIGluZm86CiAgICAgICAgbG9nZ2VyLmluZm8oCiAgICAgICAgICAgICdzY3JpcHQ6ICVzLCBpbnRlcnByZXRlZCBieSAlcyAoY29tbWFuZCBsaW5lICIlcyIpJywKICAgICAgICAgICAgaW5mb1siRXhlY3V0YWJsZVBhdGgiXSwKICAgICAgICAgICAgaW5mb1siSW50ZXJwcmV0ZXJQYXRoIl0sCiAgICAgICAgICAgIGluZm9bIlByb2NDbWRsaW5lIl0sCiAgICAgICAgKQogICAgZWxzZToKICAgICAgICBsb2dnZXIuaW5mbygKICAgICAgICAgICAgJ2V4ZWN1dGFibGU6ICVzIChjb21tYW5kIGxpbmUgIiVzIiknLAogICAgICAgICAgICBpbmZvWyJFeGVjdXRhYmxlUGF0aCJdLAogICAgICAgICAgICBpbmZvWyJQcm9jQ21kbGluZSJdLAogICAgICAgICkKCiAgICAjIGlnbm9yZSBub24tcGFja2FnZSBiaW5hcmllcyAodW5sZXNzIGNvbmZpZ3VyZWQgb3RoZXJ3aXNlKQogICAgaWYgbm90IGFwcG9ydC5maWxldXRpbHMubGlrZWx5X3BhY2thZ2VkKGluZm9bIkV4ZWN1dGFibGVQYXRoIl0pOgogICAgICAgIGlmIG5vdCBhcHBvcnQuZmlsZXV0aWxzLmdldF9jb25maWcoIm1haW4iLCAidW5wYWNrYWdlZCIsIEZhbHNlLCBib29sZWFuPVRydWUpOgogICAgICAgICAgICBsb2dnZXIuZXJyb3IoImV4ZWN1dGFibGUgZG9lcyBub3QgYmVsb25nIHRvIGEgcGFja2FnZSwgaWdub3JpbmciKQogICAgICAgICAgICAjIGNoZWNrIGlmIHRoZSB1c2VyIHdhbnRzIGEgY29yZSBkdW1wCiAgICAgICAgICAgIHJlY292ZXJfcHJpdmlsZWdlcygpCiAgICAgICAgICAgIGlmIHdyaXRlX2NvcmVkdW1wX2NhbGxiYWNrOgogICAgICAgICAgICAgICAgd3JpdGVfY29yZWR1bXBfY2FsbGJhY2soTm9uZSkKICAgICAgICAgICAgcmV0dXJuIDAKCiAgICAjIGlnbm9yZSBTSUdYQ1BVIGFuZCBTSUdYRlNaIHNpbmNlIHRoaXMgaW5kaWNhdGVzIHNvbWUgZXh0ZXJuYWwKICAgICMgaW5mbHVlbmNlIGNoYW5naW5nIHNvZnQgUkxJTUlUIHZhbHVlcyB3aGVuIHJ1bm5pbmcgcHJvZ3JhbXMuCiAgICBpZiBpbnQoaW5mb1siU2lnbmFsIl0pIGluIChpbnQoc2lnbmFsLlNJR1hDUFUpLCBpbnQoc2lnbmFsLlNJR1hGU1opKToKICAgICAgICBsb2dnZXIuZXJyb3IoCiAgICAgICAgICAgICJJZ25vcmluZyBzaWduYWwgJXMgKGNhdXNlZCBieSBleGNlZWRpbmcgc29mdCBSTElNSVQpIiwgaW5mb1siU2lnbmFsIl0KICAgICAgICApCiAgICAgICAgcmVjb3Zlcl9wcml2aWxlZ2VzKCkKICAgICAgICBpZiB3cml0ZV9jb3JlZHVtcF9jYWxsYmFjazoKICAgICAgICAgICAgd3JpdGVfY29yZWR1bXBfY2FsbGJhY2soTm9uZSkKICAgICAgICByZXR1cm4gMAoKICAgIGlmIGluZm8uY2hlY2tfaWdub3JlZCgpOgogICAgICAgIGxvZ2dlci5pbmZvKCJleGVjdXRhYmxlIHZlcnNpb24gaXMgaW4gZGVueWxpc3Qgb3Igbm90IGluIGFsbG93bGlzdCwgaWdub3JpbmciKQogICAgICAgIHJldHVybiAwCgogICAgIyBXZSBjYW4gbm93IHJlY292ZXIgcHJpdmlsZWdlcyB0byBjcmVhdGUgdGhlIGNyYXNoIHJlcG9ydCBmaWxlIGFuZAogICAgIyB3cml0ZSBvdXQgdGhlIHVzZXIgY29yZWR1bXBzCiAgICByZWNvdmVyX3ByaXZpbGVnZXMoKQoKICAgICMgQ3JlYXRlIGNyYXNoIHJlcG9ydCBmaWxlIGRlc2NyaXB0b3IgZm9yIHdyaXRpbmcgdGhlIHJlcG9ydCBpbnRvCiAgICAjIHJlcG9ydF9kaXIKICAgIHRyeToKICAgICAgICBpZiBvcy5wYXRoLmV4aXN0cyhyZXBvcnQpOgogICAgICAgICAgICBhcHBvcnQuZmlsZXV0aWxzLmluY3JlbWVudF9jcmFzaF9jb3VudGVyKGluZm8sIHJlcG9ydCkKICAgICAgICAgICAgc2tpcF9tc2cgPSBhcHBvcnQuZmlsZXV0aWxzLnNob3VsZF9za2lwX2NyYXNoKGluZm8sIHJlcG9ydCkKICAgICAgICAgICAgaWYgc2tpcF9tc2c6CiAgICAgICAgICAgICAgICBsb2dnZXIuZXJyb3IoIiVzIiwgc2tpcF9tc2cpCiAgICAgICAgICAgICAgICBpZiB3cml0ZV9jb3JlZHVtcF9jYWxsYmFjazoKICAgICAgICAgICAgICAgICAgICB3cml0ZV9jb3JlZHVtcF9jYWxsYmFjayhOb25lKQogICAgICAgICAgICAgICAgcmV0dXJuIDAKICAgICAgICAgICAgIyByZW1vdmUgdGhlIG9sZCBmaWxlLCBzbyB0aGF0IHdlIGNhbiBjcmVhdGUgdGhlIG5ldyBvbmUKICAgICAgICAgICAgIyB3aXRoIG9zLk9fQ1JFQVR8b3MuT19FWENMCiAgICAgICAgICAgIG9zLnVubGluayhyZXBvcnQpCgogICAgICAgICMgd2UgcHJlZmVyIGhhdmluZyBhIGZpbGUgbW9kZSBvZiAwIHdoaWxlIHdyaXRpbmc7CiAgICAgICAgZmQgPSBvcy5vcGVuKHJlcG9ydCwgb3MuT19SRFdSIHwgb3MuT19DUkVBVCB8IG9zLk9fRVhDTCwgMCkKICAgICAgICByZXBvcnRmaWxlID0gb3MuZmRvcGVuKGZkLCAidytiIikKICAgICAgICBhc3NlcnQgcmVwb3J0ZmlsZS5maWxlbm8oKSA+IHN5cy5zdGRlcnIuZmlsZW5vKCkKCiAgICAgICAgIyBNYWtlIHN1cmUgdGhlIGNyYXNoIHJlcG9ydGluZyBkYWVtb24gY2FuIHJlYWQgdGhpcyByZXBvcnQKICAgICAgICB0cnk6CiAgICAgICAgICAgIGdpZCA9IHB3ZC5nZXRwd25hbSgid2hvb3BzaWUiKS5wd19naWQKICAgICAgICAgICAgb3MuZmNob3duKGZkLCByZXBvcnRfb3duZXIudWlkLCBnaWQpCiAgICAgICAgZXhjZXB0IChPU0Vycm9yLCBLZXlFcnJvcik6CiAgICAgICAgICAgIG9zLmZjaG93bihmZCwgcmVwb3J0X293bmVyLnVpZCwgLTEpCiAgICBleGNlcHQgT1NFcnJvciBhcyBlcnJvcjoKICAgICAgICBsb2dnZXIuZXJyb3IoIkNvdWxkIG5vdCBjcmVhdGUgcmVwb3J0IGZpbGU6ICVzIiwgc3RyKGVycm9yKSkKICAgICAgICByZXR1cm4gMQoKICAgICMgRHJvcCBwcml2aWxlZ2VzIGJlZm9yZSB3cml0aW5nIG91dCB0aGUgcmVwb3J0ZmlsZS4KICAgIGRyb3BfcHJpdmlsZWdlcyhyZWFsX3VzZXIpCgogICAgaW5mby5hZGRfdXNlcl9pbmZvKCkKICAgIGluZm8uYWRkX29zX2luZm8oKQogICAgd2l0aCBjb250ZXh0bGliLnN1cHByZXNzKFN5c3RlbUVycm9yLCBWYWx1ZUVycm9yKToKICAgICAgICBpbmZvLmFkZF9wYWNrYWdlX2luZm8oKQogICAgaW5mb1siX0hvb2tzUnVuIl0gPSAibm8iCgogICAgIyBFbnN1cmUgdGhhdCB0aGUgQ29yZUR1bXAgZnJvbSBzeXN0ZW1kLWNvcmVkdW1wIGNhbiBiZSByZWFkLgogICAgaWYgcmVwb3J0X293bmVyLmlzX3Jvb3QoKToKICAgICAgICByZWNvdmVyX3ByaXZpbGVnZXMoKQoKICAgIHRyeToKICAgICAgICBpbmZvLndyaXRlKHJlcG9ydGZpbGUpCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICBvcy51bmxpbmsocmVwb3J0KQogICAgICAgIHJhaXNlCgogICAgIyBHZXQgcHJpdmlsZWdlcyBiYWNrIHNvIHRoZSBjb3JlIGZpbGUgY2FuIGJlIHdyaXR0ZW4gdG8gcm9vdC1vd25lZAogICAgIyBjb3JlZmlsZSBkaXJlY3RvcnkKICAgIHJlY292ZXJfcHJpdmlsZWdlcygpCgogICAgIyBtYWtlIHRoZSByZXBvcnQgd3JpdGFibGUgbm93LCB3aGVuIGl0J3MgY29tcGxldGVseSB3cml0dGVuCiAgICBvcy5mY2htb2QoZmQsIDBvNjQwKQogICAgbG9nZ2VyLmluZm8oIndyb3RlIHJlcG9ydCAlcyIsIHJlcG9ydCkKCiAgICBpZiB3cml0ZV9jb3JlZHVtcF9jYWxsYmFjazoKICAgICAgICAjIENoZWNrIGlmIHRoZSB1c2VyIHdhbnRzIGEgY29yZSBmaWxlLiBXZSBuZWVkIHRvIGNyZWF0ZSB0aGF0CiAgICAgICAgIyBmcm9tIHRoZSB3cml0dGVuIHJlcG9ydCwgYXMgd2UgY2FuIG9ubHkgcmVhZCBzdGRpbiBvbmNlIGFuZAogICAgICAgICMgd3JpdGVfdXNlcl9jb3JlZHVtcCgpIG1pZ2h0IGFib3J0IHJlYWRpbmcgZnJvbSBzdGRpbiBhbmQgcmVtb3ZlCiAgICAgICAgIyB0aGUgd3JpdHRlbiBjb3JlIGZpbGUgd2hlbiBjb3JlX3VsaW1pdCBpcyA+IDAgYW5kIHNtYWxsZXIKICAgICAgICAjIHRoYW4gdGhlIGNvcmUgc2l6ZS4KICAgICAgICByZXBvcnRmaWxlLnNlZWsoMCkKICAgICAgICB3cml0ZV9jb3JlZHVtcF9jYWxsYmFjayhyZXBvcnRmaWxlKQogICAgcmV0dXJuIDAKCgpjbGFzcyBfSm91cm5hbE1lc3NhZ2VOb3RGb3VuZChSdW50aW1lRXJyb3IpOgogICAgIiIiTm8gbWF0Y2hpbmcgam91cm5hbCBtZXNzYWdlIGZvdW5kLiIiIgoKCmRlZiBnZXRfc3lzdGVtZF9jb3JlZHVtcChpbnN0YW5jZTogc3RyKSAtPiBkaWN0W3N0ciwgb2JqZWN0XToKICAgICIiIlJlYWQgY3Jhc2ggZnJvbSBzeXN0ZW1kLWNvcmVkdW1wLgoKICAgIFRoZSBjcmFzaCBpcyBpZGVudGlmaWVkIGJ5IGZpbmRpbmcgdGhlIG1hdGNoaW5nIGluc3RhbmNlIG9mCiAgICBzeXN0ZW1kLWNvcmVkdW1wQC5zZXJ2aWNlLgogICAgIiIiCiAgICBzeXN0ZW1kX3VuaXQgPSBmInN5c3RlbWQtY29yZWR1bXBAe2luc3RhbmNlfS5zZXJ2aWNlIgogICAgdHJ5OgogICAgICAgICMgcHlsaW50OiBkaXNhYmxlLW5leHQ9aW1wb3J0LW91dHNpZGUtdG9wbGV2ZWwKICAgICAgICBpbXBvcnQgc3lzdGVtZC5qb3VybmFsCiAgICBleGNlcHQgSW1wb3J0RXJyb3I6CiAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoKS5lcnJvcigKICAgICAgICAgICAgInN5c3RlbWQgUHl0aG9uIG1vZHVsZSBpcyByZXF1aXJlZCBmb3IgcmVhZGluZyBqb3VybmFsIGxvZyBmcm9tICVzLiIKICAgICAgICAgICAgIiBQbGVhc2UgaW5zdGFsbCBweXRob24zLXN5c3RlbWQhIiwKICAgICAgICAgICAgc3lzdGVtZF91bml0LAogICAgICAgICkKICAgICAgICBzeXMuZXhpdCgxKQoKICAgIGpvdXJuYWwgPSBzeXN0ZW1kLmpvdXJuYWwuUmVhZGVyKCkKICAgIGpvdXJuYWwubWVzc2FnZWlkX21hdGNoKCJmYzJlMjJiYzZlZTY0N2I2YjkwNzI5YWIzNGEyNTBiMSIpCiAgICBqb3VybmFsLmFkZF9tYXRjaChmIl9TWVNURU1EX1VOSVQ9e3N5c3RlbWRfdW5pdH0iKQogICAgY29yZWR1bXBzID0gbGlzdChqb3VybmFsKQogICAgaWYgbm90IGNvcmVkdW1wczoKICAgICAgICByYWlzZSBfSm91cm5hbE1lc3NhZ2VOb3RGb3VuZCgKICAgICAgICAgICAgZiJObyBqb3VybmFsIGxvZyBmb3Igc3lzdGVtZCB1bml0IHtzeXN0ZW1kX3VuaXR9IGZvdW5kLiIKICAgICAgICApCiAgICBhc3NlcnQgbGVuKGNvcmVkdW1wcykgPT0gMQogICAgcmV0dXJuIGNvcmVkdW1wc1swXQoKCmRlZiBfdXNlcl9jYW5fcmVhZF9jb3JlZHVtcChyZXBvcnQ6IGFwcG9ydC5yZXBvcnQuUmVwb3J0LCB1c2VyOiBVc2VyR3JvdXBJRCkgLT4gYm9vbDoKICAgIGNvcmVkdW1wID0gcmVwb3J0LmdldCgiQ29yZUR1bXAiKQogICAgaWYgbm90IGlzaW5zdGFuY2UoY29yZWR1bXAsIENvbXByZXNzZWRGaWxlKToKICAgICAgICByZXR1cm4gVHJ1ZQogICAgZHJvcF9wcml2aWxlZ2VzKHVzZXIpCiAgICBpc19yZWFkYWJsZSA9IGNvcmVkdW1wLmlzX3JlYWRhYmxlKCkKICAgIHJlY292ZXJfcHJpdmlsZWdlcygpCiAgICByZXR1cm4gaXNfcmVhZGFibGUKCgpkZWYgX2RldGVybWluZV9yZXBvcnRfb3duZXIoCiAgICByZXBvcnQ6IGFwcG9ydC5yZXBvcnQuUmVwb3J0LCByZWFsX3VzZXI6IFVzZXJHcm91cElECikgLT4gVXNlckdyb3VwSUQ6CiAgICBpZiBfdXNlcl9jYW5fcmVhZF9jb3JlZHVtcChyZXBvcnQsIHJlYWxfdXNlcik6CiAgICAgICAgcmV0dXJuIHJlYWxfdXNlcgoKICAgICMgc3lzdGVtZC1jb3JlZHVtcCBkb2VzIG5vdCBhbGxvdyB1c2VycyB0byByZWFkIGNvcmVkdW1wcyBpZiB0aGUgdWlkIG9yCiAgICAjIGNhcGFiaWxpdGllcyB3ZXJlIGNoYW5nZWQuIFNvIG1ha2UgdGhlIHJlcG9ydCBvbmx5IHJlYWRhYmxlIGJ5IHJvb3QuCiAgICBsb2dnaW5nLmdldExvZ2dlcigpLndhcm5pbmcoCiAgICAgICAgIkNvcmUgZHVtcCBpcyBub3QgcmVhZGFibGUgYnkgdXNlciAlaS4iCiAgICAgICAgIiBNYWtpbmcgdGhlIHJlcG9ydCBvbmx5IHJlYWRhYmxlIGJ5IHJvb3QuIiwKICAgICAgICByZWFsX3VzZXIudWlkLAogICAgKQogICAgcmV0dXJuIFVzZXJHcm91cElEKDAsIDApCgoKZGVmIHByb2Nlc3NfY3Jhc2hfZnJvbV9zeXN0ZW1kX2NvcmVkdW1wKGluc3RhbmNlOiBzdHIpIC0+IGludDoKICAgICIiIlJlYWQgY3Jhc2ggZnJvbSBzeXN0ZW1kLWNvcmVkdW1wIGFuZCBwcm9jZXNzIGl0LiIiIgogICAgdHJ5OgogICAgICAgIGNvcmVkdW1wID0gZ2V0X3N5c3RlbWRfY29yZWR1bXAoaW5zdGFuY2UpCiAgICBleGNlcHQgX0pvdXJuYWxNZXNzYWdlTm90Rm91bmQgYXMgZXJyb3I6CiAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoX19uYW1lX18pLmVycm9yKCIlcyIsIGVycm9yKQogICAgICAgIHJldHVybiAxCiAgICByZXBvcnQgPSBhcHBvcnQucmVwb3J0LlJlcG9ydC5mcm9tX3N5c3RlbWRfY29yZWR1bXAoY29yZWR1bXApCiAgICByZWFsX3VzZXIgPSBVc2VyR3JvdXBJRC5mcm9tX3N5c3RlbWRfY29yZWR1bXAoY29yZWR1bXApCiAgICByZXBvcnRfb3duZXIgPSBfZGV0ZXJtaW5lX3JlcG9ydF9vd25lcihyZXBvcnQsIHJlYWxfdXNlcikKICAgIHJldHVybiBwcm9jZXNzX2NyYXNoKHJlcG9ydCwgcmVhbF91c2VyLCByZXBvcnRfb3duZXIpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoKICAgIHN5cy5leGl0KG1haW4oc3lzLmFyZ3ZbMTpdKSkK')
    U26_NATIVE_AGENT_BYTES = base64.b64decode('IyEvdXNyL2Jpbi9weXRob24zCgojIENvcHlyaWdodCAoYykgMjAwNiAtIDIwMTYgQ2Fub25pY2FsIEx0ZC4KIyBBdXRob3I6IE1hcnRpbiBQaXR0IDxtYXJ0aW4ucGl0dEB1YnVudHUuY29tPgojCiMgVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnkgaXQKIyB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieSB0aGUKIyBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yIChhdCB5b3VyCiMgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi4gIFNlZSBodHRwOi8vd3d3LmdudS5vcmcvY29weWxlZnQvZ3BsLmh0bWwgZm9yCiMgdGhlIGZ1bGwgdGV4dCBvZiB0aGUgbGljZW5zZS4KCiIiIkNvbGxlY3QgaW5mb3JtYXRpb24gYWJvdXQgYSBjcmFzaCBhbmQgY3JlYXRlIGEgcmVwb3J0IGluIHRoZSBkaXJlY3RvcnkKc3BlY2lmaWVkIGJ5IGFwcG9ydC5maWxldXRpbHMucmVwb3J0X2Rpci4KU2VlIGh0dHBzOi8vd2lraS51YnVudHUuY29tL0FwcG9ydCBmb3IgZGV0YWlscy4iIiIKCiMgcHlsaW50OiBkaXNhYmxlPXRvby1tYW55LWxpbmVzCgojIFRPRE86IEFkZHJlc3MgZm9sbG93aW5nIHB5bGludCBjb21wbGFpbnRzCiMgcHlsaW50OiBkaXNhYmxlPW1pc3NpbmctZnVuY3Rpb24tZG9jc3RyaW5nCgppbXBvcnQgYXJncGFyc2UKaW1wb3J0IGFycmF5CmltcG9ydCBhdGV4aXQKaW1wb3J0IGNvbnRleHRsaWIKaW1wb3J0IGVycm5vCmltcG9ydCBmY250bAppbXBvcnQgZ3JwCmltcG9ydCBpbnNwZWN0CmltcG9ydCBpbwppbXBvcnQgbG9nZ2luZwppbXBvcnQgb3MKaW1wb3J0IHB3ZAppbXBvcnQgcmUKaW1wb3J0IHNpZ25hbAppbXBvcnQgc29ja2V0CmltcG9ydCBzdHJ1Y3QKaW1wb3J0IHN1YnByb2Nlc3MKaW1wb3J0IHN5cwppbXBvcnQgdGltZQppbXBvcnQgdHJhY2ViYWNrCmltcG9ydCB0eXBpbmcKZnJvbSBjb2xsZWN0aW9ucy5hYmMgaW1wb3J0IENhbGxhYmxlCgppbXBvcnQgYXBwb3J0LmZpbGV1dGlscwppbXBvcnQgYXBwb3J0LnJlcG9ydApmcm9tIGFwcG9ydC51c2VyX2dyb3VwIGltcG9ydCBVc2VyR3JvdXBJRApmcm9tIHByb2JsZW1fcmVwb3J0IGltcG9ydCBDb21wcmVzc2VkRmlsZQoKTE9HX0ZPUk1BVCA9ICIlKGxldmVsbmFtZSlzOiBhcHBvcnQgKHBpZCAlKHByb2Nlc3MpcykgJShhc2N0aW1lKXM6ICUobWVzc2FnZSlzIgoKCmNsYXNzIFByb2NQaWROb3RGb3VuZEVycm9yKEZpbGVOb3RGb3VuZEVycm9yKToKICAgICIiIkZpbGVOb3RGb3VuZEVycm9yIHNwZWNpZmljIGZvciAvcHJvYy88cGlkPi4iIiIKCgpjbGFzcyBQcm9jUGlkKGNvbnRleHRsaWIuQ29udGV4dERlY29yYXRvcik6CiAgICAiIiJDb250ZXh0IG1hbmFnZXIgdG8gYWNjZXNzIC9wcm9jLzxwaWQ+LiIiIgoKICAgIGRlZiBfX2luaXRfXyhzZWxmLCBwaWQ6IGludCwgcGF0aDogc3RyIHwgTm9uZSA9IE5vbmUpIC0+IE5vbmU6CiAgICAgICAgc2VsZi5wYXRoID0gcGF0aCBvciBmIi9wcm9jL3twaWR9IgogICAgICAgIHNlbGYucGlkID0gcGlkCiAgICAgICAgc2VsZi5mZDogaW50IHwgTm9uZSA9IE5vbmUKCiAgICBkZWYgX19lbnRlcl9fKHNlbGYpIC0+ICJQcm9jUGlkIjoKICAgICAgICB0cnk6CiAgICAgICAgICAgIHNlbGYuZmQgPSBvcy5vcGVuKHNlbGYucGF0aCwgb3MuT19SRE9OTFkgfCBvcy5PX1BBVEggfCBvcy5PX0RJUkVDVE9SWSkKICAgICAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3IgYXMgZXJyb3I6CiAgICAgICAgICAgIHJhaXNlIFByb2NQaWROb3RGb3VuZEVycm9yKCplcnJvci5hcmdzLCBlcnJvci5maWxlbmFtZSkgZnJvbSBlcnJvcgogICAgICAgIHJldHVybiBzZWxmCgogICAgZGVmIF9fZXhpdF9fKHNlbGYsICpleGMpOgogICAgICAgIGlmIHNlbGYuZmQgaXMgbm90IE5vbmU6CiAgICAgICAgICAgIG9zLmNsb3NlKHNlbGYuZmQpCiAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgZGVmIF9vcGVuZXIoc2VsZiwgcGF0aDogc3RyIHwgb3MuUGF0aExpa2Vbc3RyXSwgZmxhZ3M6IGludCkgLT4gaW50OgogICAgICAgIHJldHVybiBvcy5vcGVuKHBhdGgsIGZsYWdzLCBkaXJfZmQ9c2VsZi5mZCkKCiAgICBkZWYgZXhpc3RzKHNlbGYsIHBhdGg6IHN0ciB8IG9zLlBhdGhMaWtlW3N0cl0pIC0+IGJvb2w6CiAgICAgICAgIiIiVGVzdCB3aGV0aGVyIGEgcGF0aCByZWxhdGl2ZSB0byAvcHJvYy88cGlkPiBleGlzdHMuCgogICAgICAgIFJldHVybnMgRmFsc2UgZm9yIGJyb2tlbiBzeW1ib2xpYyBsaW5rcy4iIiIKICAgICAgICB0cnk6CiAgICAgICAgICAgIHNlbGYuc3RhdChwYXRoKQogICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgICAgIHJldHVybiBGYWxzZQogICAgICAgIHJldHVybiBUcnVlCgogICAgZGVmIGhhc19zYW1lX3BpZChzZWxmLCBwaWRmZDogaW50KSAtPiBib29sOgogICAgICAgICIiIkNoZWNrIHRoYXQgdGhlIHByb2Nlc3MgSUQgbWF0Y2hlcyB0aGUgUElEIGZyb20gdGhlIGdpdmVuIHBpZGZkLgoKICAgICAgICBJbiBjYXNlIHRoZSBwcm9jZXNzIElEIGhhcyBiZWVuIHJldXNlZCBmb3IgYSBuZXcgcHJvY2VzcywgdGhlCiAgICAgICAgcHJvY2VzcyBJRCBmcm9tIHRoZSBwaWRmZCB3aWxsIGJlIC0xIGFuZCB0aHVzIHRoaXMgZnVuY3Rpb24KICAgICAgICB3aWxsIHJldHVybiBGYWxzZS4KICAgICAgICAiIiIKICAgICAgICBvdGhlcl9waWQgPSBwaWRmZF9nZXRwaWQocGlkZmQpCiAgICAgICAgcmV0dXJuIHNlbGYucGlkID09IG90aGVyX3BpZAoKICAgIGRlZiBvcGVuKHNlbGYsIGZpbGU6IHN0cikgLT4gaW8uVGV4dElPV3JhcHBlcjoKICAgICAgICAiIiJPcGVuIGZpbGUgcmVsYXRpdmUgdG8gL3Byb2MvPHBpZD4gYW5kIHJldHVybiBhIHN0cmVhbS4iIiIKICAgICAgICBhc3NlcnQgc2VsZi5mZCBpcyBub3QgTm9uZQogICAgICAgIHJldHVybiBvcGVuKGZpbGUsIGVuY29kaW5nPSJ1dGYtOCIsIG9wZW5lcj1zZWxmLl9vcGVuZXIpCgogICAgZGVmIHJlYWRsaW5rKHNlbGYsIHBhdGg6IHN0ciB8IG9zLlBhdGhMaWtlW3N0cl0pIC0+IHN0cjoKICAgICAgICAiIiJSZXR1cm4gYSBzdHJpbmcgcmVwcmVzZW50aW5nIHRoZSBwYXRoIHRvIHdoaWNoIHRoZSBzeW1ib2xpYyBsaW5rIHBvaW50cy4iIiIKICAgICAgICByZXR1cm4gb3MucmVhZGxpbmsocGF0aCwgZGlyX2ZkPXNlbGYuZmQpCgogICAgZGVmIHN0YXQoc2VsZiwgcGF0aDogc3RyIHwgb3MuUGF0aExpa2Vbc3RyXSkgLT4gb3Muc3RhdF9yZXN1bHQ6CiAgICAgICAgIiIiR2V0IHRoZSBzdGF0dXMgb2YgYSBmaWxlIG9yIGEgZmlsZSBkZXNjcmlwdG9yIHJlbGF0aXZlIHRvIC9wcm9jLzxwaWQ+LiIiIgogICAgICAgIHJldHVybiBvcy5zdGF0KHBhdGgsIGRpcl9mZD1zZWxmLmZkKQoKCmRlZiBwaWRmZF9nZXRwaWQocGlkZmQ6IGludCkgLT4gaW50OgogICAgIiIiR2V0IHRoZSBhc3NvY2lhdGVkIHBpZCBmcm9tIHRoZSBwaWQgZmlsZSBkZXNjcmlwdG9yLgoKICAgIFRoaXMgZnVuY3Rpb24gaXMgZXF1aXZhbGVudCB0byB0aGUgaWRlbnRpY2FsIG5hbWVkIGZ1bmN0aW9uIGluIGdsaWJjLgogICAgIiIiCiAgICBwaWRfcmUgPSByZS5jb21waWxlKHJiIl5QaWQ6XHMqKC0/WzAtOV0rKSQiKQogICAgd2l0aCBvcGVuKGYiL3Byb2Mvc2VsZi9mZGluZm8ve3BpZGZkfSIsICJyYiIpIGFzIGZkaW5mb19maWxlOgogICAgICAgIGZvciBsaW5lIGluIGZkaW5mb19maWxlOgogICAgICAgICAgICBtYXRjaCA9IHBpZF9yZS5tYXRjaChsaW5lKQogICAgICAgICAgICBpZiBtYXRjaDoKICAgICAgICAgICAgICAgIHJldHVybiBpbnQobWF0Y2guZ3JvdXAoMSkpCiAgICByYWlzZSBPU0Vycm9yKGVycm5vLkVCQURGLCBmIntvcy5zdHJlcnJvcihlcnJuby5FQkFERil9OiB7cGlkZmR9IikKCgpkZWYgY2hlY2tfbG9jaygpOgogICAgIiIiQWJvcnQgaWYgYW5vdGhlciBpbnN0YW5jZSBvZiBhcHBvcnQgaXMgYWxyZWFkeSBydW5uaW5nLgoKICAgIFRoaXMgYXZvaWRzIGJyaW5naW5nIGRvd24gdGhlIHN5c3RlbSB0byBpdHMga25lZXMgaWYgdGhlcmUgaXMgYSBzZXJpZXMgb2YKICAgIGNyYXNoZXMuIiIiCiAgICBsb2dnZXIgPSBsb2dnaW5nLmdldExvZ2dlcigpCgogICAgIyBjcmVhdGUgYSBsb2NrIGZpbGUKICAgIHRyeToKICAgICAgICBmZCA9IG9zLm9wZW4oCiAgICAgICAgICAgIG9zLmVudmlyb24uZ2V0KCJBUFBPUlRfTE9DS19GSUxFIiwgIi92YXIvcnVuL2FwcG9ydC5sb2NrIiksCiAgICAgICAgICAgIG9zLk9fV1JPTkxZIHwgb3MuT19DUkVBVCB8IG9zLk9fTk9GT0xMT1csCiAgICAgICAgICAgIG1vZGU9MG82MDAsCiAgICAgICAgKQogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXJyb3I6CiAgICAgICAgbG9nZ2VyLmVycm9yKCJjYW5ub3QgY3JlYXRlIGxvY2sgZmlsZSAodWlkICVpKTogJXMiLCBvcy5nZXR1aWQoKSwgc3RyKGVycm9yKSkKICAgICAgICBzeXMuZXhpdCgxKQoKICAgIGRlZiBlcnJvcl9ydW5uaW5nKCpfdW51c2VkX2FyZ3MpOgogICAgICAgIGxvZ2dlci5lcnJvcigiYW5vdGhlciBhcHBvcnQgaW5zdGFuY2UgaXMgYWxyZWFkeSBydW5uaW5nLCBhYm9ydGluZyIpCiAgICAgICAgc3lzLmV4aXQoMSkKCiAgICBvcmlnaW5hbF9oYW5kbGVyID0gc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHQUxSTSwgZXJyb3JfcnVubmluZykKICAgIHNpZ25hbC5hbGFybSgzMCkgICMgVGltZW91dCBhZnRlciB0aGF0IG1hbnkgc2Vjb25kcwogICAgdHJ5OgogICAgICAgIGZjbnRsLmxvY2tmKGZkLCBmY250bC5MT0NLX0VYKQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgZXJyb3JfcnVubmluZygpCiAgICBmaW5hbGx5OgogICAgICAgIHNpZ25hbC5hbGFybSgwKQogICAgICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR0FMUk0sIG9yaWdpbmFsX2hhbmRsZXIpCgoKZGVmIGdldF9waWRfaW5mbyhwcm9jX3BpZDogUHJvY1BpZCkgLT4gdHVwbGVbVXNlckdyb3VwSUQsIG9zLnN0YXRfcmVzdWx0XToKICAgICIiIlJlYWQgL3Byb2MgaW5mb3JtYXRpb24gYWJvdXQgcGlkIiIiCiAgICAjIHVuaGFuZGxlZCBleGNlcHRpb25zIG9uIG1pc3Npbmcgb3IgaW52YWxpZGx5IGZvcm1hdHRlZCBmaWxlcyBhcmUgb2theQogICAgIyBoZXJlIC0tIHdlIHdhbnQgdG8ga25vdyBpbiB0aGUgbG9nIGZpbGUKICAgIHBpZHN0YXQgPSBvcy5zdGF0KCJzdGF0IiwgZGlyX2ZkPXByb2NfcGlkLmZkKQoKICAgICMgZGV0ZXJtaW5lIFVJRCBhbmQgR0lEIG9mIHRoZSB0YXJnZXQgcHJvY2VzczsgZG8gKm5vdCogdXNlIHRoZSBvd25lciBvZgogICAgIyAvcHJvYy9waWQvc3RhdCwgYXMgdGhhdCB3aWxsIGJlIHJvb3QgZm9yIHNldHVpZCBvciB1bnJlYWRhYmxlIHByb2dyYW1zIQogICAgIyAodGhpcyBtYXR0ZXJzIHdoZW4gc3VpZF9kdW1wYWJsZSBpcyBlbmFibGVkKQogICAgd2l0aCBwcm9jX3BpZC5vcGVuKCJzdGF0dXMiKSBhcyBzdGF0dXNfZmlsZToKICAgICAgICBjb250ZW50cyA9IHN0YXR1c19maWxlLnJlYWQoKQogICAgcmVhbF91aWQsIHJlYWxfZ2lkID0gYXBwb3J0LmZpbGV1dGlscy5nZXRfdWlkX2FuZF9naWQoY29udGVudHMpCgogICAgYXNzZXJ0IHJlYWxfdWlkIGlzIG5vdCBOb25lLCAiZmFpbGVkIHRvIHBhcnNlIFVpZCIKICAgIGFzc2VydCByZWFsX2dpZCBpcyBub3QgTm9uZSwgImZhaWxlZCB0byBwYXJzZSBHaWQiCiAgICByZXR1cm4gVXNlckdyb3VwSUQocmVhbF91aWQsIHJlYWxfZ2lkKSwgcGlkc3RhdAoKCmRlZiBnZXRfcHJvY2Vzc19zdGFydHRpbWUocHJvY19waWQ6IFByb2NQaWQpIC0+IGludDoKICAgICIiIkdldCB0aGUgc3RhcnR0aW1lIG9mIHRoZSBwcm9jZXNzIHVzaW5nIHByb2NfcGlkX2ZkIiIiCgogICAgd2l0aCBwcm9jX3BpZC5vcGVuKCJzdGF0IikgYXMgc3RhdF9maWxlOgogICAgICAgIGNvbnRlbnRzID0gc3RhdF9maWxlLnJlYWQoKQogICAgcmV0dXJuIGFwcG9ydC5maWxldXRpbHMuZ2V0X3N0YXJ0dGltZShjb250ZW50cykKCgpkZWYgZ2V0X2FwcG9ydF9zdGFydHRpbWUoKSAtPiBpbnQ6CiAgICAiIiJHZXQgdGhlIEFwcG9ydCBwcm9jZXNzIHN0YXJ0dGltZSIiIgoKICAgIHdpdGggb3BlbihmIi9wcm9jL3tvcy5nZXRwaWQoKX0vc3RhdCIsIGVuY29kaW5nPSJ1dGYtOCIpIGFzIHN0YXRfZmlsZToKICAgICAgICBjb250ZW50cyA9IHN0YXRfZmlsZS5yZWFkKCkKICAgIHJldHVybiBhcHBvcnQuZmlsZXV0aWxzLmdldF9zdGFydHRpbWUoY29udGVudHMpCgoKZGVmIGRyb3BfcHJpdmlsZWdlcyhyZWFsX3VzZXI6IFVzZXJHcm91cElEKSAtPiBOb25lOgogICAgIiIiQ2hhbmdlIGVmZmVjdGl2ZSB1c2VyIGFuZCBncm91cCB0byBjcmFzaCB1c2VyL2dyb3VwIElEIiIiCiAgICAjIERyb3AgYW55IHN1cHBsZW1lbnRhbCBncm91cHMsIG9yIHdlJ2xsIHN0aWxsIGJlIGluIHRoZSByb290IGdyb3VwCiAgICBpZiBvcy5nZXR1aWQoKSA9PSAwOgogICAgICAgIG9zLnNldGdyb3VwcyhbXSkKICAgICAgICBhc3NlcnQgb3MuZ2V0Z3JvdXBzKCkgPT0gW10KICAgIG9zLnNldHJlZ2lkKC0xLCByZWFsX3VzZXIuZ2lkKQogICAgb3Muc2V0cmV1aWQoLTEsIHJlYWxfdXNlci51aWQpCiAgICBhc3NlcnQgb3MuZ2V0ZWdpZCgpID09IHJlYWxfdXNlci5naWQKICAgIGFzc2VydCBvcy5nZXRldWlkKCkgPT0gcmVhbF91c2VyLnVpZAoKCmRlZiByZWNvdmVyX3ByaXZpbGVnZXMoKToKICAgICIiIkNoYW5nZSBlZmZlY3RpdmUgdXNlciBhbmQgZ3JvdXAgYmFjayB0byByZWFsIHVpZCBhbmQgZ2lkIiIiCiAgICBvcy5zZXRyZWdpZCgtMSwgb3MuZ2V0Z2lkKCkpCiAgICBvcy5zZXRyZXVpZCgtMSwgb3MuZ2V0dWlkKCkpCiAgICBhc3NlcnQgb3MuZ2V0ZWdpZCgpID09IG9zLmdldGdpZCgpCiAgICBhc3NlcnQgb3MuZ2V0ZXVpZCgpID09IG9zLmdldHVpZCgpCgoKZGVmIGluaXRfZXJyb3JfbG9nKCkgLT4gTm9uZToKICAgICIiIk9wZW4gYSBzdWl0YWJsZSBlcnJvciBsb2cgaWYgc3lzLnN0ZGVyciBpcyBub3QgYSB0dHkuIiIiCgogICAgaWYgb3MuaXNhdHR5KDIpOgogICAgICAgIHJldHVybgoKICAgIGxvZyA9IG9zLmVudmlyb24uZ2V0KCJBUFBPUlRfTE9HX0ZJTEUiLCAiL3Zhci9sb2cvYXBwb3J0LmxvZyIpCiAgICB0cnk6CiAgICAgICAgZiA9IG9zLm9wZW4obG9nLCBvcy5PX1dST05MWSB8IG9zLk9fQ1JFQVQgfCBvcy5PX0FQUEVORCwgMG82MDApCiAgICBleGNlcHQgT1NFcnJvcjogICMgb24gYSBwZXJtaXNzaW9uIGVycm9yLCBkb24ndCB0b3VjaCBzdGRlcnIKICAgICAgICByZXR1cm4KCiAgICAjIGlmIGdyb3VwIGFkbSBkb2Vzbid0IGV4aXN0LCBqdXN0IGxlYXZlIGl0IGFzIHJvb3QKICAgIHdpdGggY29udGV4dGxpYi5zdXBwcmVzcyhLZXlFcnJvciwgT1NFcnJvcik6CiAgICAgICAgYWRtZ2lkID0gZ3JwLmdldGdybmFtKCJhZG0iKVsyXQogICAgICAgIG9zLmNob3duKGxvZywgLTEsIGFkbWdpZCkKICAgICAgICBvcy5jaG1vZChsb2csIDBvNjQwKQoKICAgIG9zLmR1cDIoZiwgMSkKICAgIG9zLmR1cDIoZiwgMikKICAgIHN5cy5zdGRlcnIgPSBpby5UZXh0SU9XcmFwcGVyKG9zLmZkb3BlbigyLCAid2IiKSkKICAgIHN5cy5zdGRvdXQgPSBzeXMuc3RkZXJyCgoKZGVmIF9sb2dfc2lnbmFsX2hhbmRsZXIoc2duLCBfdW51c2VkX2ZyYW1lKToKICAgICIiIkludGVybmFsIGFwcG9ydCBzaWduYWwgaGFuZGxlci4gSnVzdCBsb2cgdGhlIHNpZ25hbCBoYW5kbGVyIGFuZCBleGl0LiIiIgogICAgbG9nZ2VyID0gbG9nZ2luZy5nZXRMb2dnZXIoKQoKICAgICMgcmVzZXQgaGFuZGxlciBzbyB0aGF0IHdlIGRvIG5vdCBnZXQgc3R1Y2sgaW4gbG9vcHMKICAgIHNpZ25hbC5zaWduYWwoc2duLCBzaWduYWwuU0lHX0lHTikKICAgIHRyeToKICAgICAgICBsb2dnZXIuZXJyb3IoIkdvdCBzaWduYWwgJWksIGFib3J0aW5nOyBmcmFtZToiLCBzZ24pCiAgICAgICAgZm9yIHMgaW4gaW5zcGVjdC5zdGFjaygpOgogICAgICAgICAgICBsb2dnZXIuZXJyb3IoIiVzIiwgc3RyKHMpKQogICAgZXhjZXB0IEV4Y2VwdGlvbjogICMgcHlsaW50OiBkaXNhYmxlPWJyb2FkLWV4Y2VwdAogICAgICAgIHBhc3MKICAgIHN5cy5leGl0KDEpCgoKZGVmIHNldHVwX3NpZ25hbHMoKToKICAgICIiIkluc3RhbGwgYSBzaWduYWwgaGFuZGxlciBmb3IgYWxsIGNyYXNoLWxpa2Ugc2lnbmFscywgc28gdGhhdCBhcHBvcnQgaXMKICAgIG5vdCBjYWxsZWQgb24gaXRzZWxmIHdoZW4gYXBwb3J0IGNyYXNoZWQuIiIiCgogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHSUxMLCBfbG9nX3NpZ25hbF9oYW5kbGVyKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHQUJSVCwgX2xvZ19zaWduYWxfaGFuZGxlcikKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR0ZQRSwgX2xvZ19zaWduYWxfaGFuZGxlcikKICAgIHNpZ25hbC5zaWduYWwoc2lnbmFsLlNJR1NFR1YsIF9sb2dfc2lnbmFsX2hhbmRsZXIpCiAgICBzaWduYWwuc2lnbmFsKHNpZ25hbC5TSUdQSVBFLCBfbG9nX3NpZ25hbF9oYW5kbGVyKQogICAgc2lnbmFsLnNpZ25hbChzaWduYWwuU0lHQlVTLCBfbG9nX3NpZ25hbF9oYW5kbGVyKQoKCmRlZiB3cml0ZV91c2VyX2NvcmVkdW1wKAogICAgY29yZV9wYXRoOiBzdHIsCiAgICBsaW1pdDogaW50LAogICAgcHJvY19waWQ6IFByb2NQaWQsCiAgICByZXBvcnRfb3duZXI6IFVzZXJHcm91cElELAogICAgY29yZWR1bXBfZmQ6IGludCB8IE5vbmUgPSBOb25lLAogICAgZnJvbV9yZXBvcnQ6IHR5cGluZy5JT1tieXRlc10gfCBOb25lID0gTm9uZSwKKSAtPiBOb25lOgogICAgIiIiV3JpdGUgdGhlIGNvcmUgaW50byBhIGRpcmVjdG9yeSBpZiB1bGltaXQgcmVxdWVzdHMgaXQuIiIiCiAgICBsb2dnZXIgPSBsb2dnaW5nLmdldExvZ2dlcigpCgogICAgIyB0aHJlZSBjYXNlczoKICAgICMgbGltaXQgPT0gMDogZG8gbm90IHdyaXRlIGFueXRoaW5nCiAgICAjIGxpbWl0IDwgMDogdW5saW1pdGVkLCB3cml0ZSBvdXQgZXZlcnl0aGluZwogICAgIyBsaW1pdCBub256ZXJvOiBjcmFzaGVkIHByb2Nlc3MnIGNvcmUgc2l6ZSB1bGltaXQgaW4gYnl0ZXMKCiAgICBpZiBsaW1pdCA9PSAwOgogICAgICAgIHJldHVybgoKICAgIGN3ZCA9IG9zLm9wZW4oImN3ZCIsIG9zLk9fUkRPTkxZIHwgb3MuT19QQVRIIHwgb3MuT19ESVJFQ1RPUlksIGRpcl9mZD1wcm9jX3BpZC5mZCkKCiAgICB0cnk6CiAgICAgICAgIyBMaW1pdCBudW1iZXIgb2YgY29yZSBmaWxlcyB0byBwcmV2ZW50IERvUwogICAgICAgIGFwcG9ydC5maWxldXRpbHMuY2xlYW5fY29yZV9kaXJlY3RvcnkocmVwb3J0X293bmVyLnVpZCkKICAgICAgICBjb3JlX2ZpbGUgPSBvcy5vcGVuKAogICAgICAgICAgICBjb3JlX3BhdGgsIG9zLk9fV1JPTkxZIHwgb3MuT19DUkVBVCB8IG9zLk9fRVhDTCwgbW9kZT0wbzQwMCwgZGlyX2ZkPWN3ZAogICAgICAgICkKICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgIHJldHVybgoKICAgIGxvZ2dlci5pbmZvKCJ3cml0aW5nIGNvcmUgZHVtcCB0byAlcyAobGltaXQ6ICVzKSIsIGNvcmVfcGF0aCwgc3RyKGxpbWl0KSkKCiAgICB3cml0dGVuID0gMAoKICAgICMgUHJpbWluZyByZWFkCiAgICBpZiBmcm9tX3JlcG9ydDoKICAgICAgICByID0gYXBwb3J0LnJlcG9ydC5SZXBvcnQoKQogICAgICAgIHIubG9hZChmcm9tX3JlcG9ydCkKICAgICAgICBjb3JlX3NpemUgPSBsZW4oclsiQ29yZUR1bXAiXSkKICAgICAgICBpZiAwIDwgbGltaXQgPCBjb3JlX3NpemU6CiAgICAgICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgICAgICJhYm9ydGluZyBjb3JlIGR1bXAgd3JpdGluZywgc2l6ZSAlaSBleGNlZWRzIGN1cnJlbnQgbGltaXQiLCBjb3JlX3NpemUKICAgICAgICAgICAgKQogICAgICAgICAgICBvcy5jbG9zZShjb3JlX2ZpbGUpCiAgICAgICAgICAgIG9zLnVubGluayhjb3JlX3BhdGgsIGRpcl9mZD1jd2QpCiAgICAgICAgICAgIHJldHVybgogICAgICAgIGxvZ2dlci5pbmZvKCJ3cml0aW5nIGNvcmUgZHVtcCAlcyBvZiBzaXplICVpIiwgY29yZV9wYXRoLCBjb3JlX3NpemUpCiAgICAgICAgb3Mud3JpdGUoY29yZV9maWxlLCByWyJDb3JlRHVtcCJdKQogICAgZWxzZToKICAgICAgICBhc3NlcnQgY29yZWR1bXBfZmQgaXMgbm90IE5vbmUKICAgICAgICBibG9jayA9IG9zLnJlYWQoY29yZWR1bXBfZmQsIDEwNDg1NzYpCgogICAgICAgIHdoaWxlIFRydWU6CiAgICAgICAgICAgIHNpemUgPSBsZW4oYmxvY2spCiAgICAgICAgICAgIGlmIHNpemUgPT0gMDoKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgICAgIHdyaXR0ZW4gKz0gc2l6ZQogICAgICAgICAgICBpZiAwIDwgbGltaXQgPCB3cml0dGVuOgogICAgICAgICAgICAgICAgbG9nZ2VyLmVycm9yKAogICAgICAgICAgICAgICAgICAgICJhYm9ydGluZyBjb3JlIGR1bXAgd3JpdGluZywgc2l6ZSBleGNlZWRzIGN1cnJlbnQgbGltaXQgJWkiLCBsaW1pdAogICAgICAgICAgICAgICAgKQogICAgICAgICAgICAgICAgb3MuY2xvc2UoY29yZV9maWxlKQogICAgICAgICAgICAgICAgb3MudW5saW5rKGNvcmVfcGF0aCwgZGlyX2ZkPWN3ZCkKICAgICAgICAgICAgICAgIHJldHVybgogICAgICAgICAgICBpZiBvcy53cml0ZShjb3JlX2ZpbGUsIGJsb2NrKSAhPSBzaXplOgogICAgICAgICAgICAgICAgbG9nZ2VyLmVycm9yKCJhYm9ydGluZyBjb3JlIGR1bXAgd3JpdGluZywgY291bGQgbm90IHdyaXRlIikKICAgICAgICAgICAgICAgIG9zLmNsb3NlKGNvcmVfZmlsZSkKICAgICAgICAgICAgICAgIG9zLnVubGluayhjb3JlX3BhdGgsIGRpcl9mZD1jd2QpCiAgICAgICAgICAgICAgICByZXR1cm4KICAgICAgICAgICAgYmxvY2sgPSBvcy5yZWFkKGNvcmVkdW1wX2ZkLCAxMDQ4NTc2KQoKICAgICMgTWFrZSBzdXJlIHRoZSB1c2VyIGNhbiByZWFkIGl0CiAgICBvcy5mY2hvd24oY29yZV9maWxlLCByZXBvcnRfb3duZXIudWlkLCAtMSkKICAgIG9zLmNsb3NlKGNvcmVfZmlsZSkKCgpkZWYgdXNhYmxlX3JhbSgpOgogICAgIiIiUmV0dXJuIGhvdyBtYW55IGJ5dGVzIG9mIFJBTSBpcyBjdXJyZW50bHkgYXZhaWxhYmxlIHRoYXQgY2FuIGJlCiAgICBhbGxvY2F0ZWQgd2l0aG91dCBjYXVzaW5nIG1ham9yIHRocmFzaGluZy4iIiIKCiAgICAjIGFidXNlIG91ciBleGNlbGxlbnQgUkZDODIyIHBhcnNlciB0byBwYXJzZSAvcHJvYy9tZW1pbmZvCiAgICByID0gYXBwb3J0LnJlcG9ydC5SZXBvcnQoKQogICAgd2l0aCBvcGVuKCIvcHJvYy9tZW1pbmZvIiwgInJiIikgYXMgZjoKICAgICAgICByLmxvYWQoZikKCiAgICBtZW1mcmVlID0gaW50KHJbIk1lbUZyZWUiXS5zcGxpdCgpWzBdKQogICAgY2FjaGVkID0gaW50KHJbIkNhY2hlZCJdLnNwbGl0KClbMF0pCiAgICB3cml0ZWJhY2sgPSBpbnQoclsiV3JpdGViYWNrIl0uc3BsaXQoKVswXSkKCiAgICByZXR1cm4gKG1lbWZyZWUgKyBjYWNoZWQgLSB3cml0ZWJhY2spICogMTAyNAoKCmRlZiBfcnVuX3dpdGhfb3V0cHV0X2xpbWl0X2FuZF90aW1lb3V0KAogICAgYXJnczogbGlzdFtzdHJdLAogICAgb3V0cHV0X2xpbWl0OiBpbnQsCiAgICB0aW1lb3V0OiBpbnQsCiAgICBjbG9zZV9mZHM6IGJvb2wgPSBUcnVlLAogICAgZW52OiBkaWN0W3N0ciwgc3RyXSB8IE5vbmUgPSBOb25lLAopIC0+IHR1cGxlW2J5dGVzLCBieXRlc106CiAgICAiIiJSdW4gY29tbWFuZCBsaWtlIHN1YnByb2Nlc3MucnVuKCkgYnV0IHdpdGggb3V0cHV0IGxpbWl0IGFuZCB0aW1lb3V0LgoKICAgIFJldHVybiAoc3Rkb3V0LCBzdGRlcnIpLiIiIgoKICAgIHN0ZG91dCA9IGIiIgogICAgc3RkZXJyID0gYiIiCgogICAgIyB1c2VzIC5raWxsKCksIHB5bGludDogZGlzYWJsZT1jb25zaWRlci11c2luZy13aXRoCiAgICBwcm9jZXNzID0gc3VicHJvY2Vzcy5Qb3BlbigKICAgICAgICBhcmdzLAogICAgICAgIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUsCiAgICAgICAgc3RkZXJyPXN1YnByb2Nlc3MuUElQRSwKICAgICAgICBjbG9zZV9mZHM9Y2xvc2VfZmRzLAogICAgICAgIGVudj1lbnYsCiAgICApCiAgICB0cnk6CiAgICAgICAgYXNzZXJ0IHByb2Nlc3Muc3Rkb3V0IGlzIG5vdCBOb25lIGFuZCBwcm9jZXNzLnN0ZGVyciBpcyBub3QgTm9uZQogICAgICAgICMgRG9uJ3QgYmxvY2sgc28gd2UgZG9uJ3QgZGVhZGxvY2sKICAgICAgICBvcy5zZXRfYmxvY2tpbmcocHJvY2Vzcy5zdGRvdXQuZmlsZW5vKCksIEZhbHNlKQogICAgICAgIG9zLnNldF9ibG9ja2luZyhwcm9jZXNzLnN0ZGVyci5maWxlbm8oKSwgRmFsc2UpCgogICAgICAgIGZvciBfIGluIHJhbmdlKHRpbWVvdXQpOgogICAgICAgICAgICBhbGl2ZSA9IHByb2Nlc3MucG9sbCgpIGlzIE5vbmUKCiAgICAgICAgICAgIHdoaWxlIGxlbihzdGRvdXQpIDwgb3V0cHV0X2xpbWl0IGFuZCBsZW4oc3RkZXJyKSA8IG91dHB1dF9saW1pdDoKICAgICAgICAgICAgICAgIHRlbXBvdXQgPSBwcm9jZXNzLnN0ZG91dC5yZWFkKDEwMCkKICAgICAgICAgICAgICAgIGlmIHRlbXBvdXQ6CiAgICAgICAgICAgICAgICAgICAgc3Rkb3V0ICs9IHRlbXBvdXQKICAgICAgICAgICAgICAgIHRlbXBlcnIgPSBwcm9jZXNzLnN0ZGVyci5yZWFkKDEwMCkKICAgICAgICAgICAgICAgIGlmIHRlbXBlcnI6CiAgICAgICAgICAgICAgICAgICAgc3RkZXJyICs9IHRlbXBlcnIKICAgICAgICAgICAgICAgIGlmIG5vdCB0ZW1wb3V0IGFuZCBub3QgdGVtcGVycjoKICAgICAgICAgICAgICAgICAgICBicmVhawoKICAgICAgICAgICAgaWYgbm90IGFsaXZlIG9yIGxlbihzdGRvdXQpID49IG91dHB1dF9saW1pdCBvciBsZW4oc3RkZXJyKSA+PSBvdXRwdXRfbGltaXQ6CiAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICB0aW1lLnNsZWVwKDEpCiAgICBmaW5hbGx5OgogICAgICAgIHByb2Nlc3Mua2lsbCgpCgogICAgcmV0dXJuIHN0ZG91dCwgc3RkZXJyCgoKZGVmIGlzX2Nsb3Npbmdfc2Vzc2lvbihwcm9jX3BpZDogUHJvY1BpZCwgcmVhbF91c2VyOiBVc2VyR3JvdXBJRCkgLT4gYm9vbDoKICAgICIiIkNoZWNrIGlmIHBpZCBpcyBpbiBhIGNsb3NpbmcgdXNlciBzZXNzaW9uLgoKICAgIER1cmluZyB0aGF0LCBjcmFzaGVzIGFyZSBjb21tb24gYXMgdGhlIHNlc3Npb24gRC1CVVMgYW5kIFgub3JnIGFyZSBnb2luZwogICAgYXdheSwgZXRjLiBUaGVzZSBjcmFzaCByZXBvcnRzIGFyZSBtb3N0bHkgbm9pc2UsIHNvIHNob3VsZCBiZSBpZ25vcmVkLgogICAgIiIiCiAgICBsb2dnZXIgPSBsb2dnaW5nLmdldExvZ2dlcigpCiAgICBhc3NlcnQgcHJvY19waWQuZmQgaXMgbm90IE5vbmUKICAgIGVudiA9IGFwcG9ydC5maWxldXRpbHMuZ2V0X3Byb2Nlc3NfZW52aXJvbihwcm9jX3BpZC5mZCkKICAgIGRidXNfYWRkciA9IGVudi5nZXQoIkRCVVNfU0VTU0lPTl9CVVNfQUREUkVTUyIpCiAgICBpZiBkYnVzX2FkZHIgaXMgTm9uZToKICAgICAgICBsb2dnZXIuZXJyb3IoImlzX2Nsb3Npbmdfc2Vzc2lvbigpOiBubyBEQlVTX1NFU1NJT05fQlVTX0FERFJFU1MgaW4gZW52aXJvbm1lbnQiKQogICAgICAgIHJldHVybiBGYWxzZQoKICAgIGRidXNfc29ja2V0ID0gYXBwb3J0LmZpbGV1dGlscy5nZXRfZGJ1c19zb2NrZXQoZGJ1c19hZGRyKQogICAgaWYgbm90IGRidXNfc29ja2V0OgogICAgICAgIGxvZ2dlci5lcnJvcigiaXNfY2xvc2luZ19zZXNzaW9uKCk6IENvdWxkIG5vdCBkZXRlcm1pbmUgREJVUyBzb2NrZXQuIikKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICBpZiBub3Qgb3MucGF0aC5leGlzdHMoZGJ1c19zb2NrZXQpOgogICAgICAgIGxvZ2dlci5lcnJvcigiaXNfY2xvc2luZ19zZXNzaW9uKCk6IERCVVMgc29ja2V0IGRvZXNuJ3QgZXhpc3QuIikKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICAjIFdlIG5lZWQgdG8gZHJvcCBib3RoIHRoZSByZWFsIGFuZCBlZmZlY3RpdmUgdWlkL2dpZCBiZWZvcmUgY2FsbGluZwogICAgIyBnZGJ1cyBiZWNhdXNlIERCVVNfU0VTU0lPTl9CVVNfQUREUkVTUyBpcyB1bnRydXN0ZWQgYW5kIG1heSBhbGxvdwogICAgIyByZWFkaW5nIGFyYml0cmFyeSBmaWxlcyBhcyBhIG5vbmNlZmlsZS4gV2UgY2FuJ3QganVzdCBkcm9wIGVmZmVjdGl2ZQogICAgIyB1aWQvZ2lkIGFzIGdkYnVzIGhhcyBhIGNoZWNrIHRvIG1ha2Ugc3VyZSBpdCdzIG5vdCBydW5uaW5nIGluIGEKICAgICMgc2V0dWlkIGVudmlyb25tZW50IGFuZCBpdCBkb2VzIHNvIGJ5IGNvbXBhcmluZyB0aGUgcmVhbCBhbmQgZWZmZWN0aXZlCiAgICAjIGlkcy4gV2UgZG9uJ3QgbmVlZCB0byBkcm9wIHN1cHBsZW1lbnRhbCBncm91cHMgaGVyZSwgYXMgdGhlIHByaXZpbGVnZQogICAgIyBkcm9wcGluZyBjb2RlIGVsc2V3aGVyZSBoYXMgYWxyZWFkeSBkb25lIHNvLgogICAgcmVhbF91aWQgPSBvcy5nZXR1aWQoKQogICAgcmVhbF9naWQgPSBvcy5nZXRnaWQoKQogICAgdHJ5OgogICAgICAgIG9zLnNldHJlc2dpZChyZWFsX3VzZXIuZ2lkLCByZWFsX3VzZXIuZ2lkLCByZWFsX2dpZCkKICAgICAgICBvcy5zZXRyZXN1aWQocmVhbF91c2VyLnVpZCwgcmVhbF91c2VyLnVpZCwgcmVhbF91aWQpCiAgICAgICAgb3V0LCBlcnIgPSBfcnVuX3dpdGhfb3V0cHV0X2xpbWl0X2FuZF90aW1lb3V0KAogICAgICAgICAgICBbCiAgICAgICAgICAgICAgICAiL3Vzci9iaW4vZ2RidXMiLAogICAgICAgICAgICAgICAgImNhbGwiLAogICAgICAgICAgICAgICAgIi1lIiwKICAgICAgICAgICAgICAgICItZCIsCiAgICAgICAgICAgICAgICAib3JnLmdub21lLlNlc3Npb25NYW5hZ2VyIiwKICAgICAgICAgICAgICAgICItbyIsCiAgICAgICAgICAgICAgICAiL29yZy9nbm9tZS9TZXNzaW9uTWFuYWdlciIsCiAgICAgICAgICAgICAgICAiLW0iLAogICAgICAgICAgICAgICAgIm9yZy5nbm9tZS5TZXNzaW9uTWFuYWdlci5Jc1Nlc3Npb25SdW5uaW5nIiwKICAgICAgICAgICAgICAgICItdCIsCiAgICAgICAgICAgICAgICAiNSIsCiAgICAgICAgICAgIF0sCiAgICAgICAgICAgIDEwMDAsCiAgICAgICAgICAgIDUsCiAgICAgICAgICAgIGVudj17IkRCVVNfU0VTU0lPTl9CVVNfQUREUkVTUyI6IGRidXNfYWRkcn0sCiAgICAgICAgKQoKICAgICAgICBpZiBlcnI6CiAgICAgICAgICAgIGxvZ2dlci5lcnJvcigiZ2RidXMgY2FsbCBlcnJvcjogJXMiLCBlcnIuZGVjb2RlKCJVVEYtOCIpKQogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXJyb3I6CiAgICAgICAgbG9nZ2VyLmVycm9yKAogICAgICAgICAgICAiZ2RidXMgY2FsbCBmYWlsZWQsIGNhbm5vdCBkZXRlcm1pbmUgcnVubmluZyBzZXNzaW9uOiAlcyIsIHN0cihlcnJvcikKICAgICAgICApCiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBmaW5hbGx5OgogICAgICAgIG9zLnNldHJlc3VpZChyZWFsX3VpZCwgcmVhbF91aWQsIC0xKQogICAgICAgIG9zLnNldHJlc2dpZChyZWFsX2dpZCwgcmVhbF9naWQsIC0xKQoKICAgIGxvZ2dlci5kZWJ1Zygic2Vzc2lvbiBnZGJ1cyBjYWxsOiAlcyIsIG91dC5kZWNvZGUoIlVURi04IikucnN0cmlwKCkpCiAgICByZXR1cm4gb3V0LnN0YXJ0c3dpdGgoYiIoZmFsc2UsIikKCgpkZWYgaXNfc3lzdGVtZF93YXRjaGRvZ19yZXN0YXJ0KHNpZ251bTogaW50LCBwcm9jX3BpZDogUHJvY1BpZCkgLT4gYm9vbDoKICAgICIiIkNoZWNrIGlmIHRoaXMgaXMgYSByZXN0YXJ0IGJ5IHN5c3RlbWQncyB3YXRjaGRvZyIiIgoKICAgIGlmIHNpZ251bSAhPSBpbnQoc2lnbmFsLlNJR0FCUlQpIG9yIG5vdCBvcy5wYXRoLmlzZGlyKCIvcnVuL3N5c3RlbWQvc3lzdGVtIik6CiAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgdHJ5OgogICAgICAgIHdpdGggcHJvY19waWQub3BlbigiY2dyb3VwIikgYXMgZjoKICAgICAgICAgICAgZm9yIGxpbmUgaW4gZjoKICAgICAgICAgICAgICAgIGlmICJuYW1lPXN5c3RlbWQ6IiBpbiBsaW5lOgogICAgICAgICAgICAgICAgICAgIHVuaXQgPSBsaW5lLnNwbGl0KCIvIilbLTFdLnN0cmlwKCkKICAgICAgICAgICAgICAgICAgICBicmVhawogICAgICAgICAgICBlbHNlOgogICAgICAgICAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgICAgIGpvdXJuYWxjdGwgPSBzdWJwcm9jZXNzLnJ1bigKICAgICAgICAgICAgWwogICAgICAgICAgICAgICAgIi9iaW4vam91cm5hbGN0bCIsCiAgICAgICAgICAgICAgICAiLS1vdXRwdXQ9Y2F0IiwKICAgICAgICAgICAgICAgICItLXNpbmNlPS01bWluIiwKICAgICAgICAgICAgICAgICItLXByaW9yaXR5PXdhcm5pbmciLAogICAgICAgICAgICAgICAgIi0tdW5pdCIsCiAgICAgICAgICAgICAgICB1bml0LAogICAgICAgICAgICBdLAogICAgICAgICAgICBjaGVjaz1GYWxzZSwKICAgICAgICAgICAgc3Rkb3V0PXN1YnByb2Nlc3MuUElQRSwKICAgICAgICApCiAgICAgICAgcmV0dXJuIGIiV2F0Y2hkb2cgdGltZW91dCIgaW4gam91cm5hbGN0bC5zdGRvdXQKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGVycm9yOgogICAgICAgIGxvZ2dpbmcuZ2V0TG9nZ2VyKCkuZXJyb3IoCiAgICAgICAgICAgICJjYW5ub3QgZGV0ZXJtaW5lIGlmIHRoaXMgY3Jhc2ggaXMgZnJvbSBzeXN0ZW1kIHdhdGNoZG9nOiAlcyIsIGVycm9yCiAgICAgICAgKQogICAgICAgIHJldHVybiBGYWxzZQoKCmRlZiBpc19zYW1lX25zKHByb2NfcGlkOiBQcm9jUGlkLCBuczogc3RyKSAtPiBib29sOgogICAgaWYgbm90IG9zLnBhdGguZXhpc3RzKGYiL3Byb2Mvc2VsZi9ucy97bnN9Iikgb3Igbm90IHByb2NfcGlkLmV4aXN0cyhmIm5zL3tuc30iKToKICAgICAgICAjIElmIHRoZSBuYW1lc3BhY2UgZG9lc24ndCBleGlzdCwgdGhlbiBpdCdzIG9idmlvdXNseSBzaGFyZWQKICAgICAgICByZXR1cm4gVHJ1ZQoKICAgIHRyeToKICAgICAgICBpZiBwcm9jX3BpZC5yZWFkbGluayhmIm5zL3tuc30iKSA9PSBvcy5yZWFkbGluayhmIi9wcm9jL3NlbGYvbnMve25zfSIpOgogICAgICAgICAgICAjIENoZWNrIHRoYXQgdGhlIGlub2RlIGZvciBib3RoIG5hbWVzcGFjZXMgaXMgdGhlIHNhbWUKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgIGV4Y2VwdCBPU0Vycm9yIGFzIGVycm9yOgogICAgICAgIGlmIGVycm9yLmVycm5vID09IGVycm5vLkVOT0VOVDoKICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICByYWlzZQoKICAgICMgY2hlY2sgdG8gc2VlIGlmIHRoZSBwcm9jZXNzIGlzIHBhcnQgb2YgdGhlIHN5c3RlbS5zbGljZSAoTFA6ICMxODcwMDYwKQogICAgd2l0aCBjb250ZXh0bGliLnN1cHByZXNzKEZpbGVOb3RGb3VuZEVycm9yKToKICAgICAgICB3aXRoIHByb2NfcGlkLm9wZW4oImNncm91cCIpIGFzIGNncm91cDoKICAgICAgICAgICAgZm9yIGxpbmUgaW4gY2dyb3VwOgogICAgICAgICAgICAgICAgZmllbGRzID0gbGluZS5zcGxpdCgiOiIpCiAgICAgICAgICAgICAgICBpZiBmaWVsZHNbLTFdLnN0YXJ0c3dpdGgoIi9zeXN0ZW0uc2xpY2UiKToKICAgICAgICAgICAgICAgICAgICByZXR1cm4gVHJ1ZQoKICAgIHJldHVybiBGYWxzZQoKCiMgVE9ETzogU3BsaXQgaW50byBzbWFsbGVyIGZ1bmN0aW9ucy9tZXRob2RzCiMgcHlsaW50OiBkaXNhYmxlLW5leHQ9dG9vLWNvbXBsZXgKZGVmIGZvcndhcmRfY3Jhc2hfdG9fY29udGFpbmVyKAogICAgb3B0aW9uczogYXJncGFyc2UuTmFtZXNwYWNlLAogICAgcHJvY19waWQ6IFByb2NQaWQsCiAgICBjb3JlZHVtcF9mZDogaW50ID0gMCwKICAgIGhhc19jYXBfc3lzX2FkbWluOiBib29sID0gVHJ1ZSwKKSAtPiBOb25lOgogICAgIiIiVHJ5IHRvIGZvcndhcmQgdGhlIGNyYXNoIHRvIHRoZSBjb250YWluZXIuCgogICAgSWYgdGhlIGNyYXNoIGNhbWUgZnJvbSBhIGNvbnRhaW5lciwgZG9uJ3QgYXR0ZW1wdCB0byBoYW5kbGUKICAgIGxvY2FsbHkgYXMgdGhhdCB3b3VsZCBqdXN0IHJlc3VsdCBpbiB3cm9uZyBzeXN0ZW0gaW5mb3JtYXRpb24uCgogICAgSW5zdGVhZCwgYXR0ZW1wdCB0byBmaW5kIGFwcG9ydCBpbnNpZGUgdGhlIGNvbnRhaW5lciBhbmQKICAgIGZvcndhcmQgdGhlIHByb2Nlc3MgaW5mb3JtYXRpb24gdGhlcmUuCiAgICAiIiIKICAgIGxvZ2dlciA9IGxvZ2dpbmcuZ2V0TG9nZ2VyKCkKCiAgICBpZiBvcHRpb25zLnBpZGZkIGlzIE5vbmUgYW5kIG9wdGlvbnMuZHVtcF9tb2RlICE9IDE6CiAgICAgICAgIyBOb3RlOiBJZiBvcHRpb25zLnBpZGZkIGlzIHNldCwgcHJvY19waWQuaGFzX3NhbWVfcGlkKCkgaGFzIGJlZW4gY2FsbGVkIGJlZm9yZS4KICAgICAgICBsb2dnZXIuZXJyb3IoCiAgICAgICAgICAgICJOb3QgZm9yd2FyZGluZyBjcmFzaCB3aXRoIGR1bXAgbW9kZSBvZiAlcyB0byBjb250YWluZXIiCiAgICAgICAgICAgICIgZHVlIHRvIHNlY3VyaXR5IGNvbmNlcm5zLiBQbGVhc2UgcHJvdmlkZSAtLXBpZGZkLiIsCiAgICAgICAgICAgIG9wdGlvbnMuZHVtcF9tb2RlLAogICAgICAgICkKICAgICAgICByZXR1cm4KCiAgICAjIFZhbGlkYXRlIHRoYXQgdGhlIHRhcmdldCBzb2NrZXQgaXMgb3duZWQKICAgICMgYnkgdGhlIHVzZXIgbmFtZXNwYWNlIG9mIHRoZSBwcm9jZXNzCiAgICB0cnk6CiAgICAgICAgc29ja19mZCA9IG9zLm9wZW4oCiAgICAgICAgICAgICJyb290L3J1bi9hcHBvcnQuc29ja2V0Iiwgb3MuT19SRE9OTFkgfCBvcy5PX1BBVEgsIGRpcl9mZD1wcm9jX3BpZC5mZAogICAgICAgICkKICAgICAgICBzb2NrZXRfdWlkID0gb3MuZnN0YXQoc29ja19mZCkuc3RfdWlkCiAgICBleGNlcHQgKEZpbGVOb3RGb3VuZEVycm9yLCBQcm9jZXNzTG9va3VwRXJyb3IpOgogICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgImhvc3QgcGlkICVzIGNyYXNoZWQgaW4gYSBjb250YWluZXIgd2l0aG91dCBhcHBvcnQgc3VwcG9ydCIsCiAgICAgICAgICAgIG9wdGlvbnMuZ2xvYmFsX3BpZCwKICAgICAgICApCiAgICAgICAgcmV0dXJuCgogICAgdHJ5OgogICAgICAgIHdpdGggcHJvY19waWQub3BlbigidWlkX21hcCIpIGFzIGZkOgogICAgICAgICAgICBpZiBub3QgYXBwb3J0LmZpbGV1dGlscy5zZWFyY2hfbWFwKGZkLCBzb2NrZXRfdWlkKToKICAgICAgICAgICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgICAgICAgICAidXNlciBpcyB0cnlpbmcgdG8gdHJpY2sgYXBwb3J0IGludG8gYWNjZXNzaW5nIgogICAgICAgICAgICAgICAgICAgICIgYSBzb2NrZXQgdGhhdCBkb2Vzbid0IGJlbG9uZyB0byB0aGUgY29udGFpbmVyIgogICAgICAgICAgICAgICAgKQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgcGFzcwoKICAgICMgVmFsaWRhdGUgdGhhdCB0aGUgY3Jhc2hlZCBiaW5hcnkgaXMgb3duZWQKICAgICMgYnkgdGhlIHVzZXIgbmFtZXNwYWNlIG9mIHRoZSBwcm9jZXNzCiAgICBleGVfcGF0aCA9IGYicm9vdHtwcm9jX3BpZC5yZWFkbGluaygnZXhlJyl9IgogICAgZXhlX3N0YXQgPSBwcm9jX3BpZC5zdGF0KGV4ZV9wYXRoKQogICAgdHJ5OgogICAgICAgIHdpdGggcHJvY19waWQub3BlbigidWlkX21hcCIpIGFzIGZkOgogICAgICAgICAgICBpZiBub3QgYXBwb3J0LmZpbGV1dGlscy5zZWFyY2hfbWFwKGZkLCBleGVfc3RhdC5zdF91aWQpOgogICAgICAgICAgICAgICAgbG9nZ2VyLmVycm9yKAogICAgICAgICAgICAgICAgICAgICJob3N0IHBpZCAlcyBjcmFzaGVkIGluIGEgY29udGFpbmVyIgogICAgICAgICAgICAgICAgICAgICIgd2l0aCBubyBhY2Nlc3MgdG8gdGhlIGJpbmFyeSIsCiAgICAgICAgICAgICAgICAgICAgb3B0aW9ucy5nbG9iYWxfcGlkLAogICAgICAgICAgICAgICAgKQogICAgICAgICAgICAgICAgcmV0dXJuCiAgICBleGNlcHQgRmlsZU5vdEZvdW5kRXJyb3I6CiAgICAgICAgcGFzcwoKICAgIHRyeToKICAgICAgICB3aXRoIHByb2NfcGlkLm9wZW4oImdpZF9tYXAiKSBhcyBmZDoKICAgICAgICAgICAgaWYgbm90IGFwcG9ydC5maWxldXRpbHMuc2VhcmNoX21hcChmZCwgZXhlX3N0YXQuc3RfZ2lkKToKICAgICAgICAgICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgICAgICAgICAiaG9zdCBwaWQgJXMgY3Jhc2hlZCBpbiBhIGNvbnRhaW5lciIKICAgICAgICAgICAgICAgICAgICAiIHdpdGggbm8gYWNjZXNzIHRvIHRoZSBiaW5hcnkiLAogICAgICAgICAgICAgICAgICAgIG9wdGlvbnMuZ2xvYmFsX3BpZCwKICAgICAgICAgICAgICAgICkKICAgICAgICAgICAgICAgIHJldHVybgogICAgZXhjZXB0IEZpbGVOb3RGb3VuZEVycm9yOgogICAgICAgIHBhc3MKCiAgICAjIE5vdyBvcGVuIHRoZSBzb2NrZXQKICAgIHdpdGggc29ja2V0LnNvY2tldChzb2NrZXQuQUZfVU5JWCwgc29ja2V0LlNPQ0tfU1RSRUFNKSBhcyBzb2NrOgogICAgICAgIHRyeToKICAgICAgICAgICAgc29jay5jb25uZWN0KGYiL3Byb2Mvc2VsZi9mZC97c29ja19mZH0iKQogICAgICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgICAgICBsb2dnZXIuZXJyb3IoCiAgICAgICAgICAgICAgICAiaG9zdCBwaWQgJXMgY3Jhc2hlZCBpbiBhIGNvbnRhaW5lciB3aXRoIGEgYnJva2VuIGFwcG9ydCIsCiAgICAgICAgICAgICAgICBvcHRpb25zLmdsb2JhbF9waWQsCiAgICAgICAgICAgICkKICAgICAgICAgICAgcmV0dXJuCgogICAgICAgICMgU2VuZCBtYWluIGFyZ3VtZW50cyBvbmx5CiAgICAgICAgIyBPbGRlciBhcHBvcnQgaW4gY29udGFpbmVycyBkb2Vzbid0IHN1cHBvcnQgcG9zaXRpb25hbCBhcmd1bWVudHMKICAgICAgICBhcmdzID0gKAogICAgICAgICAgICBmIntvcHRpb25zLnBpZH0ge29wdGlvbnMuc2lnbmFsX251bWJlcn0gIgogICAgICAgICAgICBmIntvcHRpb25zLmNvcmVfdWxpbWl0fSB7b3B0aW9ucy5kdW1wX21vZGV9IgogICAgICAgICkKICAgICAgICAjIFNlbmQgY29yZWR1bXAgZmQgKGRlZmF1bHRzIHRvIDAgZm9yIHN0ZGluKQogICAgICAgIGFuY2lsbGFyeSA9IFsKICAgICAgICAgICAgKAogICAgICAgICAgICAgICAgc29ja2V0LlNPTF9TT0NLRVQsCiAgICAgICAgICAgICAgICBzb2NrZXQuU0NNX1JJR0hUUywKICAgICAgICAgICAgICAgIGJ5dGVzKGFycmF5LmFycmF5KCJpIiwgW2NvcmVkdW1wX2ZkXSkpLAogICAgICAgICAgICApCiAgICAgICAgXQogICAgICAgIGlmIGhhc19jYXBfc3lzX2FkbWluOgogICAgICAgICAgICAjIFNDTV9DUkVERU5USUFMUyBuZWVkcyBDQVBfU1lTX0FETUlOIGZvciBzcGVjaWZ5aW5nIGFub3RoZXIKICAgICAgICAgICAgIyBwcm9jZXNzIElELiBDaGVja2luZyBvcy5nZXRldWlkKCkgdG8gYmUgMCBpcyBub3QgZW5vdWdoLgogICAgICAgICAgICAjIFNlbmQgYSB1Y3JlZCBjb250YWluaW5nIHRoZSBnbG9iYWwgcGlkCiAgICAgICAgICAgIGFuY2lsbGFyeS5hcHBlbmQoCiAgICAgICAgICAgICAgICAoCiAgICAgICAgICAgICAgICAgICAgc29ja2V0LlNPTF9TT0NLRVQsCiAgICAgICAgICAgICAgICAgICAgc29ja2V0LlNDTV9DUkVERU5USUFMUywKICAgICAgICAgICAgICAgICAgICBzdHJ1Y3QucGFjaygiM2kiLCBvcHRpb25zLmdsb2JhbF9waWQsIDAsIDApLAogICAgICAgICAgICAgICAgKQogICAgICAgICAgICApCiAgICAgICAgdHJ5OgogICAgICAgICAgICBzb2NrLnNlbmRtc2coW2FyZ3MuZW5jb2RlKCldLCBhbmNpbGxhcnkpCiAgICAgICAgICAgIHNvY2suc2h1dGRvd24oc29ja2V0LlNIVVRfUkRXUikKICAgICAgICBleGNlcHQgVGltZW91dEVycm9yOgogICAgICAgICAgICBsb2dnZXIuZXJyb3IoIkNvbnRhaW5lciBhcHBvcnQgZmFpbGVkIHRvIHByb2Nlc3MgY3Jhc2ggd2l0aGluIDMwcyIpCgoKZGVmIGNoZWNrX2tlcm5lbF9jcmFzaCgpIC0+IE5vbmU6CiAgICAiIiJDaGVjayBmb3Iga2VybmVsIGNyYXNoIGR1bXAsIGNvbnZlcnQgaXQgdG8gYXBwb3J0IHJlcG9ydC4iIiIKICAgIGtlcm5lbF9jcmFzaF9yZSA9IHJlLmNvbXBpbGUoIl4oWzAtOV17MTJ9fHZtY29yZSkkIikKICAgIGZvciByZXBvcnQgaW4gb3MubGlzdGRpcihhcHBvcnQuZmlsZXV0aWxzLnJlcG9ydF9kaXIpOgogICAgICAgIGlmIGtlcm5lbF9jcmFzaF9yZS5tYXRjaChyZXBvcnQpOgogICAgICAgICAgICBzdWJwcm9jZXNzLnJ1bihbIi91c3Ivc2hhcmUvYXBwb3J0L2tlcm5lbF9jcmFzaGR1bXAiXSwgY2hlY2s9RmFsc2UpCiAgICAgICAgICAgIHJldHVybgoKCmRlZiBjcmVhdGVfZGlyZWN0b3J5KHBhdGg6IHN0ciwgbW9kZTogaW50KSAtPiBOb25lOgogICAgIiIiRW5zdXJlIHRoZSBkaXJlY3RvcnkgaXMgY3JlYXRlZC4KCiAgICBPbmx5IHNldCB0aGUgZGlyZWN0b3J5IG1vZGUgaWYgdGhlIGRpcmVjdG9yeSBpcyBuZXdseSBjcmVhdGVkLgogICAgIiIiCiAgICB3aXRoIGNvbnRleHRsaWIuc3VwcHJlc3MoRmlsZUV4aXN0c0Vycm9yKToKICAgICAgICBvcy5tYWtlZGlycyhwYXRoKQogICAgICAgIG9zLmNobW9kKHBhdGgsIG1vZGUpCgoKZGVmIHdyaXRlX3RvX3Byb2Nfc3lzKHBhdGg6IHN0ciwgdmFsdWU6IHN0cikgLT4gTm9uZToKICAgICIiIldyaXRlIHZhbHVlIHRvIC9wcm9jL3N5cy4iIiIKICAgIHdpdGggb3Blbihvcy5wYXRoLmpvaW4oIi9wcm9jL3N5cyIsIHBhdGgpLCAidyIsIGVuY29kaW5nPSJ1dGYtOCIpIGFzIHByb2M6CiAgICAgICAgcHJvYy53cml0ZSh2YWx1ZSkKCgpkZWYgc3RhcnRfYXBwb3J0KCkgLT4gTm9uZToKICAgICIiIlN0YXJ0IEFwcG9ydCBjcmFzaCBoYW5kbGVyLiIiIgogICAgY3JlYXRlX2RpcmVjdG9yeShhcHBvcnQuZmlsZXV0aWxzLnJlcG9ydF9kaXIsIDBvMzc3NykKICAgIHdyaXRlX3RvX3Byb2Nfc3lzKAogICAgICAgICJrZXJuZWwvY29yZV9wYXR0ZXJuIiwKICAgICAgICBmInx7X19maWxlX199IC1wJXAgLXMlcyAtYyVjIC1kJWQgLVAlUCAtdSV1IC1nJWcgLUYlRiAtLSAlRSIsCiAgICApCiAgICB3cml0ZV90b19wcm9jX3N5cygiZnMvc3VpZF9kdW1wYWJsZSIsICIyIikKICAgIHdyaXRlX3RvX3Byb2Nfc3lzKCJrZXJuZWwvY29yZV9waXBlX2xpbWl0IiwgIjEwIikKICAgIGNoZWNrX2tlcm5lbF9jcmFzaCgpCgoKZGVmIHN0b3BfYXBwb3J0KCkgLT4gTm9uZToKICAgICIiIlN0b3AgQXBwb3J0IGNyYXNoIGhhbmRsZXIuIiIiCiAgICB3cml0ZV90b19wcm9jX3N5cygia2VybmVsL2NvcmVfcGlwZV9saW1pdCIsICIwIikKICAgIHdyaXRlX3RvX3Byb2Nfc3lzKCJmcy9zdWlkX2R1bXBhYmxlIiwgIjAiKQogICAgd3JpdGVfdG9fcHJvY19zeXMoImtlcm5lbC9jb3JlX3BhdHRlcm4iLCAiY29yZSIpCgoKZGVmIHBhcnNlX2FyZ3VtZW50cyhhcmdzOiBsaXN0W3N0cl0pIC0+IGFyZ3BhcnNlLk5hbWVzcGFjZToKICAgIHBhcnNlciA9IGFyZ3BhcnNlLkFyZ3VtZW50UGFyc2VyKCkKCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KCItcCIsICItLXBpZCIsIHR5cGU9aW50LCBoZWxwPSJwcm9jZXNzIGlkICglJXApIikKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoIi1zIiwgIi0tc2lnbmFsLW51bWJlciIsIHR5cGU9aW50LCBoZWxwPSJzaWduYWwgbnVtYmVyICglJXMpIikKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoIi1jIiwgIi0tY29yZS11bGltaXQiLCB0eXBlPWludCwgaGVscD0iY29yZSB1bGltaXQgKCUlYykiKQogICAgcGFyc2VyLmFkZF9hcmd1bWVudCgiLWQiLCAiLS1kdW1wLW1vZGUiLCB0eXBlPWludCwgaGVscD0iZHVtcCBtb2RlICglJWQpIikKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoCiAgICAgICAgIi1QIiwgIi0tZ2xvYmFsLXBpZCIsIHR5cGU9aW50LCBoZWxwPSJwaWQgaW4gcm9vdCBuYW1lc3BhY2UgKCUlUCkiCiAgICApCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KAogICAgICAgICItRiIsICItLXBpZGZkIiwgbmFyZ3M9Ij8iLCB0eXBlPWludCwgaGVscD0icGlkZmQgZm9yIHRoZSBjcmFzaGVkIHByb2Nlc3MgKCUlRikiCiAgICApCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KCItdSIsICItLXVpZCIsIHR5cGU9aW50LCBoZWxwPSJyZWFsIFVJRCAoJSV1KSIpCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KCItZyIsICItLWdpZCIsIHR5cGU9aW50LCBoZWxwPSJyZWFsIEdJRCAoJSVnKSIpCiAgICBwYXJzZXIuYWRkX2FyZ3VtZW50KCJleGVjdXRhYmxlX3BhdGgiLCBuYXJncz0iKiIsIGhlbHA9InBhdGggb2YgZXhlY3V0YWJsZSAoJSVFKSIpCgogICAgcGFyc2VyLmFkZF9hcmd1bWVudCgKICAgICAgICAiLS1mcm9tLXN5c3RlbWQtY29yZWR1bXAiLAogICAgICAgIGRlc3Q9InN5c3RlbWRfY29yZWR1bXBfaW5zdGFuY2UiLAogICAgICAgIGhlbHA9IlJlYWQgY3Jhc2ggaW5mb3JtYXRpb24gZnJvbSBzeXN0ZW1kLWNvcmVkdW1wIiwKICAgICkKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoCiAgICAgICAgIi0tc3RhcnQiLCBhY3Rpb249InN0b3JlX3RydWUiLCBoZWxwPSJTdGFydCBBcHBvcnQgY3Jhc2ggaGFuZGxlciBhbmQgZXhpdCIKICAgICkKICAgIHBhcnNlci5hZGRfYXJndW1lbnQoCiAgICAgICAgIi0tc3RvcCIsIGFjdGlvbj0ic3RvcmVfdHJ1ZSIsIGhlbHA9IlN0b3AgQXBwb3J0IGNyYXNoIGhhbmRsZXIgYW5kIGV4aXQiCiAgICApCgogICAgb3B0aW9ucyA9IHBhcnNlci5wYXJzZV9hcmdzKGFyZ3MpCgogICAgaWYgbm90IG9wdGlvbnMuc3lzdGVtZF9jb3JlZHVtcF9pbnN0YW5jZSBhbmQgbm90IG9wdGlvbnMuc3RhcnQgYW5kIG5vdCBvcHRpb25zLnN0b3A6CiAgICAgICAgaWYgb3B0aW9ucy5waWQgaXMgTm9uZToKICAgICAgICAgICAgcGFyc2VyLmVycm9yKCJ0aGUgZm9sbG93aW5nIGFyZ3VtZW50cyBhcmUgcmVxdWlyZWQ6IC1wLy0tcGlkIikKICAgICAgICBpZiBvcHRpb25zLmR1bXBfbW9kZSBpcyBOb25lOgogICAgICAgICAgICBwYXJzZXIuZXJyb3IoInRoZSBmb2xsb3dpbmcgYXJndW1lbnRzIGFyZSByZXF1aXJlZDogLWQvLS1kdW1wLW1vZGUiKQoKICAgICMgSW4ga2VybmVscyBiZWZvcmUgNS4zLjAsIGFuIGV4ZWN1dGFibGUgcGF0aCB3aXRoIHNwYWNlcyBtYXkgYmUgc3BsaXQKICAgICMgaW50byBzZXBhcmF0ZSBhcmd1bWVudHMuIElmIG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoIGlzIGEgbGlzdCwgam9pbgogICAgIyBpdCBiYWNrIGludG8gYSBzdHJpbmcuIEFsc28gcmVzdG9yZSBkaXJlY3Rvcnkgc2VwYXJhdG9ycy4KICAgIGlmIGlzaW5zdGFuY2Uob3B0aW9ucy5leGVjdXRhYmxlX3BhdGgsIGxpc3QpOgogICAgICAgIG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoID0gIiAiLmpvaW4ob3B0aW9ucy5leGVjdXRhYmxlX3BhdGgpCiAgICBvcHRpb25zLmV4ZWN1dGFibGVfcGF0aCA9IG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoLnJlcGxhY2UoIiEiLCAiLyIpCiAgICAjIGNvbnNpc3RlbmN5IGNoZWNrIHRvIHByZXZlbnQgdHJpY2tlcnkgbGF0ZXIgb24KICAgIGlmICIuLi8iIGluIG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoOgogICAgICAgIG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoID0gTm9uZQoKICAgIHJldHVybiBvcHRpb25zCgoKZGVmIF9jaGVja19nbG9iYWxfcGlkX2FuZF9mb3J3YXJkKAogICAgb3B0aW9uczogYXJncGFyc2UuTmFtZXNwYWNlLCBwcm9jX3BpZDogUHJvY1BpZAopIC0+IGJvb2w6CiAgICAiIiJDaGVjayB0aGUgZ2xvYmFsIFBJRCBpZiB0aGUgY3Jhc2ggaGFwcGVucyBpbiBhIGNvbnRhaW5lci4KCiAgICBDaGVjayBpZiB3ZSByZWNlaXZlZCBhIHZhbGlkIGdsb2JhbCBQSUQgKGtlcm5lbCA+PSAzLjEyKS4gSWYgd2UgZG8sCiAgICB0aGVuIGNvbXBhcmUgaXQgd2l0aCB0aGUgbG9jYWwgUElELiBJbiB0aGF0IGNhc2UgZm9yd2FyZCB0aGUgY3Jhc2gKICAgIHRvIHRoZSBjb250YWluZXIuCgogICAgSWYgdGhleSBkb24ndCBtYXRjaCwgaXQncyBhbiBpbmRpY2F0aW9uIHRoYXQgdGhlIGNyYXNoIG9yaWdpbmF0ZWQKICAgIGZyb20gYW5vdGhlciBQSUQgbmFtZXNwYWNlLiBTaW1wbHkgbG9nIGFuIGVudHJ5IGluIHRoZSBob3N0IGVycm9yCiAgICBsb2cgYW5kIGxldCBhcHBvcnQgZXhpdC4KCiAgICBSZXR1cm5zIFRydWUgaW4gY2FzZSBhcHBvcnQgc2hvdWxkIGV4aXQgd2l0aCAwLgogICAgIiIiCiAgICBpZiBvcHRpb25zLmdsb2JhbF9waWQgaXMgbm90IE5vbmU6CiAgICAgICAgaWYgbm90IGlzX3NhbWVfbnMocHJvY19waWQsICJtbnQiKToKICAgICAgICAgICAgaWYgbm90IGlzX3NhbWVfbnMocHJvY19waWQsICJwaWQiKToKICAgICAgICAgICAgICAgIGZvcndhcmRfY3Jhc2hfdG9fY29udGFpbmVyKG9wdGlvbnMsIHByb2NfcGlkKQogICAgICAgICAgICAgICAgcmV0dXJuIFRydWUKICAgICAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoKS5lcnJvcigKICAgICAgICAgICAgICAgICJob3N0IHBpZCAlcyBjcmFzaGVkIGluIGEgc2VwYXJhdGUgbW91bnQgbmFtZXNwYWNlLCBpZ25vcmluZyIsCiAgICAgICAgICAgICAgICBvcHRpb25zLmdsb2JhbF9waWQsCiAgICAgICAgICAgICkKICAgICAgICAgICAgcmV0dXJuIFRydWUKCiAgICAgICAgIyBJZiBpdCBkb2Vzbid0IGxvb2sgbGlrZSB0aGUgY3Jhc2ggb3JpZ2luYXRlZCBmcm9tIHdpdGhpbiBhIGZ1bGwKICAgICAgICAjIGNvbnRhaW5lciBvciBpZiB0aGUgaXNfc2FtZV9ucygpIGZ1bmN0aW9uIGZhaWxzIG9wZW4gKHJldHVybmluZwogICAgICAgICMgVHJ1ZSksIHRoZW4gdGFrZSB0aGUgZ2xvYmFsIHBpZCBhbmQgbW92ZSBvbiB0byBub3JtYWwgaGFuZGxpbmcuCgogICAgICAgICMgVGhpcyBiaXQgaXMgbmVlZGVkIGJlY2F1c2Ugc29tZSBzb2Z0d2FyZSBsaWtlIHRoZSBjaHJvbWUgc2FuZGJveAogICAgICAgICMgd2lsbCB1c2UgY29udGFpbmVyIG5hbWVzcGFjZXMgYXMgYSBzZWN1cml0eSBtZWFzdXJlIGJ1dCBhcmUgc3RpbGwKICAgICAgICAjIG90aGVyd2lzZSBob3N0IHByb2Nlc3Nlcy4gV2hlbiB0aGF0J3MgdGhlIGNhc2UsIHdlIG5lZWQgdG8ga2VlcAogICAgICAgICMgaGFuZGxpbmcgdGhvc2UgY3Jhc2hlcyBsb2NhbGx5IHVzaW5nIHRoZSBnbG9iYWwgcGlkLgogICAgcmV0dXJuIEZhbHNlCgoKIyBweWxpbnQ6IGRpc2FibGUtbmV4dD1taXNzaW5nLWZ1bmN0aW9uLWRvY3N0cmluZwpkZWYgbWFpbihhcmdzOiBsaXN0W3N0cl0pIC0+IGludDoKICAgIGluaXRfZXJyb3JfbG9nKCkKICAgIGxvZ2dpbmcuYmFzaWNDb25maWcoZm9ybWF0PUxPR19GT1JNQVQsIGxldmVsPWxvZ2dpbmcuSU5GTykKCiAgICAjIHN5c3RlbWQgc29ja2V0IGFjdGl2YXRpb24KICAgIGlmICJMSVNURU5fRkRTIiBpbiBvcy5lbnZpcm9uOgogICAgICAgIG9wdGlvbnMgPSByZWNlaXZlX2FyZ3VtZW50c192aWFfc29ja2V0KCkKICAgIGVsc2U6CiAgICAgICAgb3B0aW9ucyA9IHBhcnNlX2FyZ3VtZW50cyhhcmdzKQoKICAgIGlmIG9wdGlvbnMuc3lzdGVtZF9jb3JlZHVtcF9pbnN0YW5jZToKICAgICAgICByZXR1cm4gcHJvY2Vzc19jcmFzaF9mcm9tX3N5c3RlbWRfY29yZWR1bXAob3B0aW9ucy5zeXN0ZW1kX2NvcmVkdW1wX2luc3RhbmNlKQogICAgaWYgb3B0aW9ucy5zdG9wOgogICAgICAgIHN0b3BfYXBwb3J0KCkKICAgICAgICByZXR1cm4gMAogICAgaWYgb3B0aW9ucy5zdGFydDoKICAgICAgICBzdGFydF9hcHBvcnQoKQogICAgICAgIHJldHVybiAwCgogICAgdHJ5OgogICAgICAgIHJldHVybiBwcm9jZXNzX2NyYXNoX2Zyb21fa2VybmVsKG9wdGlvbnMpCiAgICBleGNlcHQgKFN5c3RlbUV4aXQsIEtleWJvYXJkSW50ZXJydXB0KToKICAgICAgICBwYXNzCiAgICBleGNlcHQgRXhjZXB0aW9uOiAgIyBweWxpbnQ6IGRpc2FibGU9YnJvYWQtZXhjZXB0CiAgICAgICAgbG9nZ2VyID0gbG9nZ2luZy5nZXRMb2dnZXIoKQogICAgICAgIGxvZ2dlci5lcnJvcigiVW5oYW5kbGVkIGV4Y2VwdGlvbjoiKQogICAgICAgIHRyYWNlYmFjay5wcmludF9leGMoKQogICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgInBpZDogJWksIHVpZDogJWksIGdpZDogJWksIGV1aWQ6ICVpLCBlZ2lkOiAlaSIsCiAgICAgICAgICAgIG9zLmdldHBpZCgpLAogICAgICAgICAgICBvcy5nZXR1aWQoKSwKICAgICAgICAgICAgb3MuZ2V0Z2lkKCksCiAgICAgICAgICAgIG9zLmdldGV1aWQoKSwKICAgICAgICAgICAgb3MuZ2V0ZWdpZCgpLAogICAgICAgICkKICAgICAgICBsb2dnZXIuZXJyb3IoImVudmlyb25tZW50OiAlcyIsIG9zLmVudmlyb24pCgogICAgcmV0dXJuIDAKCgpkZWYgcmVjZWl2ZV9hcmd1bWVudHNfdmlhX3NvY2tldCgpIC0+IGFyZ3BhcnNlLk5hbWVzcGFjZToKICAgICIiIlJlY2VpdmUgYXJndW1lbnRzIGZyb20gdGhlIGhvc3QgdmlhIGEgc29ja2V0LiIiIgogICAgdHJ5OgogICAgICAgICMgcHlsaW50OiBkaXNhYmxlPWltcG9ydC1vdXRzaWRlLXRvcGxldmVsCiAgICAgICAgZnJvbSBzeXN0ZW1kLmRhZW1vbiBpbXBvcnQgbGlzdGVuX2ZkcwogICAgZXhjZXB0IEltcG9ydEVycm9yOgogICAgICAgIGxvZ2dpbmcuZ2V0TG9nZ2VyKCkuZXJyb3IoCiAgICAgICAgICAgICJSZWNlaXZlZCBhIGNyYXNoIHZpYSBhcHBvcnQtZm9yd2FyZC5zb2NrZXQsIgogICAgICAgICAgICAiIGJ1dCBzeXN0ZW1kIHB5dGhvbiBtb2R1bGUgaXMgbm90IGluc3RhbGxlZCIKICAgICAgICApCiAgICAgICAgc3lzLmV4aXQoMCkKCiAgICAjIEV4dHJhY3QgYW5kIHZhbGlkYXRlIHRoZSBmZAogICAgc29ja2V0X2ZkcyA9IGxpc3Rlbl9mZHMoKQogICAgaWYgbGVuKHNvY2tldF9mZHMpIDwgMToKICAgICAgICBsb2dnaW5nLmdldExvZ2dlcigpLmVycm9yKCJJbnZhbGlkIHNvY2tldCBhY3RpdmF0aW9uLCBubyBmZCBwcm92aWRlZCIpCiAgICAgICAgc3lzLmV4aXQoMSkKCiAgICAjIE9wZW4gdGhlIHNvY2tldAogICAgc29jayA9IHNvY2tldC5mcm9tZmQoaW50KHNvY2tldF9mZHNbMF0pLCBzb2NrZXQuQUZfVU5JWCwgc29ja2V0LlNPQ0tfU1RSRUFNKQogICAgYXRleGl0LnJlZ2lzdGVyKHNvY2suc2h1dGRvd24sIHNvY2tldC5TSFVUX1JEV1IpCgogICAgIyBSZXBsYWNlIHN0ZGluIGJ5IHRoZSBzb2NrZXQgYWN0aXZhdGlvbiBmZAogICAgc3lzLnN0ZGluLmNsb3NlKCkKCiAgICBmZHMgPSBhcnJheS5hcnJheSgiaSIpCiAgICB1Y3JlZHMgPSBhcnJheS5hcnJheSgiaSIpCiAgICBtc2csIGFuY2RhdGEsIF91bnVzZWRfZmxhZ3MsIF91bnVzZWRfYWRkciA9IHNvY2sucmVjdm1zZyg0MDk2LCA0MDk2KQogICAgZm9yIGNtc2dfbGV2ZWwsIGNtc2dfdHlwZSwgY21zZ19kYXRhIGluIGFuY2RhdGE6CiAgICAgICAgaWYgY21zZ19sZXZlbCA9PSBzb2NrZXQuU09MX1NPQ0tFVCBhbmQgY21zZ190eXBlID09IHNvY2tldC5TQ01fUklHSFRTOgogICAgICAgICAgICBmZHMuZnJvbWJ5dGVzKGNtc2dfZGF0YVs6IGxlbihjbXNnX2RhdGEpIC0gKGxlbihjbXNnX2RhdGEpICUgZmRzLml0ZW1zaXplKV0pCiAgICAgICAgZWxpZiBjbXNnX2xldmVsID09IHNvY2tldC5TT0xfU09DS0VUIGFuZCBjbXNnX3R5cGUgPT0gc29ja2V0LlNDTV9DUkVERU5USUFMUzoKICAgICAgICAgICAgdWNyZWRzLmZyb21ieXRlcygKICAgICAgICAgICAgICAgIGNtc2dfZGF0YVs6IGxlbihjbXNnX2RhdGEpIC0gKGxlbihjbXNnX2RhdGEpICUgdWNyZWRzLml0ZW1zaXplKV0KICAgICAgICAgICAgKQoKICAgIHN5cy5zdGRpbiA9IG9zLmZkb3BlbihpbnQoZmRzWzBdKSwgInIiKQoKICAgICMgUmVwbGFjZSBhcmdzIGJ5IHRoZSBhcmd1bWVudHMgcmVjZWl2ZWQgb3ZlciB0aGUgc29ja2V0CiAgICBhcmdzID0gbXNnLmRlY29kZSgpLnNwbGl0KCkKICAgIGlmIGxlbih1Y3JlZHMpID49IDM6CiAgICAgICAgYXJnc1swXSA9IHN0cih1Y3JlZHNbMF0pCgogICAgaWYgbGVuKGFyZ3MpICE9IDQ6CiAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoKS5lcnJvcigKICAgICAgICAgICAgIlJlY2VpdmVkIGEgYmFkIG51bWJlciBvZiBhcmd1bWVudHMgZnJvbSBmb3J3YXJkZXIsIgogICAgICAgICAgICAiIHJlY2VpdmVkICVkLCBleHBlY3RlZCA0LCBhYm9ydGluZy4iLAogICAgICAgICAgICBsZW4oYXJncyksCiAgICAgICAgKQogICAgICAgIHN5cy5leGl0KDEpCgogICAgcmV0dXJuIGFyZ3BhcnNlLk5hbWVzcGFjZSgKICAgICAgICBwaWQ9aW50KGFyZ3NbMF0pLAogICAgICAgIHNpZ25hbF9udW1iZXI9aW50KGFyZ3NbMV0pLAogICAgICAgIGNvcmVfdWxpbWl0PWludChhcmdzWzJdKSwKICAgICAgICBkdW1wX21vZGU9aW50KGFyZ3NbM10pLAogICAgICAgIGdsb2JhbF9waWQ9Tm9uZSwKICAgICAgICBwaWRmZD1Ob25lLAogICAgICAgIHVpZD1Ob25lLAogICAgICAgIGdpZD1Ob25lLAogICAgICAgIGV4ZWN1dGFibGVfcGF0aD1Ob25lLAogICAgICAgIHN5c3RlbWRfY29yZWR1bXBfaW5zdGFuY2U9Tm9uZSwKICAgICAgICBzdGFydD1GYWxzZSwKICAgICAgICBzdG9wPUZhbHNlLAogICAgKQoKCmRlZiBjb25zaXN0ZW5jeV9jaGVja3MoCiAgICBvcHRpb25zOiBhcmdwYXJzZS5OYW1lc3BhY2UsCiAgICBwcm9jZXNzX3N0YXJ0OiBpbnQsCiAgICBwcm9jX3BpZDogUHJvY1BpZCwKICAgIHJlYWxfdXNlcjogVXNlckdyb3VwSUQsCikgLT4gYm9vbDoKICAgICIiIlJ1biBjb25zaXN0ZW5jeSBjaGVja3MgYW5kIHJldHVybiBUcnVlIGlmIGFsbCBwYXNzLiIiIgogICAgbG9nZ2VyID0gbG9nZ2luZy5nZXRMb2dnZXIoKQoKICAgICMgQ29uc2lzdGVuY3kgY2hlY2sgdG8gbWFrZSBzdXJlIHRoZSBwcm9jZXNzIHdhc24ndCByZXBsYWNlZCBhZnRlciB0aGUKICAgICMgY3Jhc2ggaGFwcGVuZWQuIFRoZSBzdGFydCB0aW1lIGlzbid0IGZpbmUtZ3JhaW5lZCBlbm91Z2ggdG8gYmUgYW4KICAgICMgYWRlcXVhdGUgc2VjdXJpdHkgY2hlY2suCiAgICBhcHBvcnRfc3RhcnQgPSBnZXRfYXBwb3J0X3N0YXJ0dGltZSgpCiAgICBpZiBwcm9jZXNzX3N0YXJ0ID4gYXBwb3J0X3N0YXJ0OgogICAgICAgIGxvZ2dlci5lcnJvcigicHJvY2VzcyB3YXMgcmVwbGFjZWQgYWZ0ZXIgQXBwb3J0IHN0YXJ0ZWQsIGlnbm9yaW5nIikKICAgICAgICByZXR1cm4gRmFsc2UKCiAgICAjIE1ha2Ugc3VyZSB0aGUgcHJvY2VzcyB1aWQvZ2lkIG1hdGNoIHRoZSBvbmVzIHByb3ZpZGVkIGJ5IHRoZSBrZXJuZWwKICAgICMgaWYgYXZhaWxhYmxlLCBpZiBub3QsIGl0IG1heSBoYXZlIGJlZW4gcmVwbGFjZWQKICAgIGlmIChvcHRpb25zLnVpZCBpcyBub3QgTm9uZSkgYW5kIChvcHRpb25zLmdpZCBpcyBub3QgTm9uZSk6CiAgICAgICAgaWYgVXNlckdyb3VwSUQob3B0aW9ucy51aWQsIG9wdGlvbnMuZ2lkKSAhPSByZWFsX3VzZXI6CiAgICAgICAgICAgIGxvZ2dlci5lcnJvcigicHJvY2VzcyB1aWQvZ2lkIGRvZXNuJ3QgbWF0Y2ggZXhwZWN0ZWQsIGlnbm9yaW5nIikKICAgICAgICAgICAgcmV0dXJuIEZhbHNlCgogICAgIyBjaGVjayBpZiB0aGUgZXhlY3V0YWJsZSB3YXMgbW9kaWZpZWQgYWZ0ZXIgdGhlIHByb2Nlc3Mgc3RhcnRlZCAoZS4gZy4KICAgICMgcGFja2FnZSBnb3QgdXBncmFkZWQgaW4gYmV0d2VlbikuCiAgICBleGVfcGF0aCA9IGYicm9vdHtwcm9jX3BpZC5yZWFkbGluaygnZXhlJyl9IgogICAgcHJvY2Vzc19tdGltZSA9IG9zLmxzdGF0KCJjbWRsaW5lIiwgZGlyX2ZkPXByb2NfcGlkLmZkKS5zdF9tdGltZQogICAgaWYgKAogICAgICAgIG5vdCBwcm9jX3BpZC5leGlzdHMoZXhlX3BhdGgpCiAgICAgICAgb3IgcHJvY19waWQuc3RhdChleGVfcGF0aCkuc3RfbXRpbWUgPiBwcm9jZXNzX210aW1lCiAgICApOgogICAgICAgIGxvZ2dlci5lcnJvcigiZXhlY3V0YWJsZSB3YXMgbW9kaWZpZWQgYWZ0ZXIgcHJvZ3JhbSBzdGFydCwgaWdub3JpbmciKQogICAgICAgIHJldHVybiBGYWxzZQoKICAgIHJldHVybiBUcnVlCgoKZGVmIHJlZmluZV9jb3JlX3VsaW1pdChvcHRpb25zOiBhcmdwYXJzZS5OYW1lc3BhY2UpIC0+IGludDoKICAgICIiIlJlZmluZSBlZmZlY3RpdmUgY29yZSB1bGltaXQgYnkgdGFraW5nIGR1bXAgbW9kZSBpbnRvIGFjY291bnQuIiIiCiAgICBjb3JlX3VsaW1pdCA9IG9wdGlvbnMuY29yZV91bGltaXQKCiAgICAjIGNsYW1wIGNvcmVfdWxpbWl0IHRvIGEgc2Vuc2libGUgc2l6ZSwgZm9yIC0xIHRoZSBrZXJuZWwgcmVwb3J0cwogICAgIyBzb21ldGhpbmcgYWJzdXJkbHkgYmlnCiAgICBpZiBjb3JlX3VsaW1pdCA+IDkyMjMzNzIwMzY4NTQ3NzU4MDc6CiAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoKS5lcnJvcigKICAgICAgICAgICAgImlnbm9yaW5nIGltcGxhdXNpYmx5IGJpZyBjb3JlIGxpbWl0LCB0cmVhdGluZyBhcyB1bmxpbWl0ZWQiCiAgICAgICAgKQogICAgICAgIGNvcmVfdWxpbWl0ID0gLTEKCiAgICByZXR1cm4gY29yZV91bGltaXQKCgpkZWYgcHJvY2Vzc19jcmFzaF9mcm9tX2tlcm5lbChvcHRpb25zOiBhcmdwYXJzZS5OYW1lc3BhY2UpIC0+IGludDoKICAgIGlmIG9wdGlvbnMuZ2xvYmFsX3BpZCBpcyBOb25lOgogICAgICAgIHBpZCA9IG9wdGlvbnMucGlkCiAgICBlbHNlOgogICAgICAgIHBpZCA9IG9wdGlvbnMuZ2xvYmFsX3BpZAogICAgdHJ5OgogICAgICAgIHdpdGggUHJvY1BpZChwaWQpIGFzIHByb2NfcGlkOgogICAgICAgICAgICBpZiBvcHRpb25zLnBpZGZkIGlzIG5vdCBOb25lIGFuZCBub3QgcHJvY19waWQuaGFzX3NhbWVfcGlkKG9wdGlvbnMucGlkZmQpOgogICAgICAgICAgICAgICAgbG9nZ2luZy5nZXRMb2dnZXIoKS5lcnJvcigKICAgICAgICAgICAgICAgICAgICAiVGhlIHByb2Nlc3MgJWkgaGFzIGFscmVhZHkgYmVlbiByZXBsYWNlZCBieSBhIG5ldyBwcm9jZXNzIgogICAgICAgICAgICAgICAgICAgICIgd2l0aCB0aGUgc2FtZSBJRC4gSWdub3JpbmcgY3Jhc2guIiwKICAgICAgICAgICAgICAgICAgICBwaWQsCiAgICAgICAgICAgICAgICApCiAgICAgICAgICAgICAgICByZXR1cm4gMQogICAgICAgICAgICByZXR1cm4gcHJvY2Vzc19jcmFzaF9mcm9tX2tlcm5lbF93aXRoX3Byb2NfcGlkKG9wdGlvbnMsIHByb2NfcGlkKQogICAgZXhjZXB0IFByb2NQaWROb3RGb3VuZEVycm9yIGFzIGVycm9yOgogICAgICAgIGxvZ2dpbmcuZ2V0TG9nZ2VyKCkuZXJyb3IoCiAgICAgICAgICAgICIlcyBub3QgZm91bmQuICIKICAgICAgICAgICAgIkNhbm5vdCBjb2xsZWN0IGNyYXNoIGluZm9ybWF0aW9uIGZvciBwcm9jZXNzICVpIGFueSBtb3JlLiIsCiAgICAgICAgICAgIGVycm9yLmZpbGVuYW1lLAogICAgICAgICAgICBwaWQsCiAgICAgICAgKQogICAgICAgIHJldHVybiAxCgoKZGVmIF9zZXRfc2lnbmFsKHJlcG9ydDogYXBwb3J0LnJlcG9ydC5SZXBvcnQsIHNpZ25hbF9udW1iZXI6IGludCkgLT4gTm9uZToKICAgIHJlcG9ydFsiU2lnbmFsIl0gPSBzdHIoc2lnbmFsX251bWJlcikKICAgIHdpdGggY29udGV4dGxpYi5zdXBwcmVzcyhWYWx1ZUVycm9yKToKICAgICAgICByZXBvcnRbIlNpZ25hbE5hbWUiXSA9IHNpZ25hbC5TaWduYWxzKHNpZ25hbF9udW1iZXIpLm5hbWUKCgpkZWYgZGV0ZXJtaW5lX3JlcG9ydF9vd25lcihkdW1wX21vZGU6IGludCwgcmVhbF91c2VyOiBVc2VyR3JvdXBJRCkgLT4gVXNlckdyb3VwSUQ6CiAgICAiIiJEZXRlcm1pbmUgd2hvIHNob3VsZCBiZSB0aGUgb3duZXIgb2YgdGhlIGNyYXNoIHJlcG9ydCBmaWxlLgoKICAgIEZvciBkdW1wX21vZGUgMSAoImRlYnVnIikgdGhlIG93bmVyIG9mIHRoZSBwcm9jZXNzIGNhbiBiZWNvbWUgdGhlCiAgICBjcmFzaCByZXBvcnQgb3duZXIuIEZvciBkdW1wX21vZGUgMiAoInN1aWRzYWZlIikgdGhlIGNyYXNoZWQgcHJvY2VzcwogICAgaXMgYSBzdWlkIHByb2Nlc3MgYW5kIHRoZSByZXBvcnQgc2hvdWxkIGJlIG93bmVkIGJ5IHJvb3QgaW5zdGVhZC4KCiAgICBTZWUgcHJvY19zeXNfZnMoNSkgbWFuIHBhZ2UgYW5kCiAgICBodHRwczovL2tlcm5lbC5vcmcvZG9jL2h0bWwvbGF0ZXN0L2FkbWluLWd1aWRlL3N5c2N0bC9mcy5odG1sI3N1aWQtZHVtcGFibGUKICAgICIiIgogICAgaWYgZHVtcF9tb2RlID09IDE6CiAgICAgICAgcmV0dXJuIHJlYWxfdXNlcgogICAgcmV0dXJuIFVzZXJHcm91cElEKDAsIDApCgoKIyBweWxpbnQ6IGRpc2FibGUtbmV4dD10b28tbWFueS1yZXR1cm4tc3RhdGVtZW50cwpkZWYgcHJvY2Vzc19jcmFzaF9mcm9tX2tlcm5lbF93aXRoX3Byb2NfcGlkKAogICAgb3B0aW9uczogYXJncGFyc2UuTmFtZXNwYWNlLCBwcm9jX3BpZDogUHJvY1BpZAopIC0+IGludDoKICAgICIiIlByb2Nlc3MgY3Jhc2ggYW5kIHJldHVybiBleGl0IGNvZGUuIiIiCiAgICBsb2dnZXIgPSBsb2dnaW5nLmdldExvZ2dlcigpCgogICAgY2hlY2tfbG9jaygpCiAgICBzZXR1cF9zaWduYWxzKCkKCiAgICByZWFsX3VzZXIsIF8gPSBnZXRfcGlkX2luZm8ocHJvY19waWQpCiAgICBwcm9jZXNzX3N0YXJ0ID0gZ2V0X3Byb2Nlc3Nfc3RhcnR0aW1lKHByb2NfcGlkKQogICAgaWYgbm90IGNvbnNpc3RlbmN5X2NoZWNrcyhvcHRpb25zLCBwcm9jZXNzX3N0YXJ0LCBwcm9jX3BpZCwgcmVhbF91c2VyKToKICAgICAgICByZXR1cm4gMAoKICAgIGlmIF9jaGVja19nbG9iYWxfcGlkX2FuZF9mb3J3YXJkKG9wdGlvbnMsIHByb2NfcGlkKToKICAgICAgICByZXR1cm4gMAoKICAgIGNvcmVkdW1wX2ZkID0gc3lzLnN0ZGluLmZpbGVubygpCiAgICBsb2dnZXIuaW5mbygKICAgICAgICAiY2FsbGVkIGZvciAlcywgc2lnbmFsICVzLCBjb3JlIGxpbWl0ICVzLCBkdW1wIG1vZGUgJXMiLAogICAgICAgICgKICAgICAgICAgICAgZiJwaWQge29wdGlvbnMucGlkfSIKICAgICAgICAgICAgaWYgb3B0aW9ucy5nbG9iYWxfcGlkIGlzIE5vbmUKICAgICAgICAgICAgZWxzZSBmImdsb2JhbCBwaWQge29wdGlvbnMuZ2xvYmFsX3BpZH0iCiAgICAgICAgKSwKICAgICAgICBvcHRpb25zLnNpZ25hbF9udW1iZXIsCiAgICAgICAgb3B0aW9ucy5jb3JlX3VsaW1pdCwKICAgICAgICBvcHRpb25zLmR1bXBfbW9kZSwKICAgICkKCiAgICBjb3JlX3VsaW1pdCA9IHJlZmluZV9jb3JlX3VsaW1pdChvcHRpb25zKQoKICAgIGNvcmVfcGF0aCA9IGFwcG9ydC5maWxldXRpbHMuZ2V0X2NvcmVfcGF0aCgKICAgICAgICBwcm9jX3BpZC5waWQsIG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoLCByZWFsX3VzZXIudWlkLCBwcm9jZXNzX3N0YXJ0LCBwcm9jX3BpZC5mZAogICAgKVsxXQogICAgcmVwb3J0X293bmVyID0gZGV0ZXJtaW5lX3JlcG9ydF9vd25lcihvcHRpb25zLmR1bXBfbW9kZSwgcmVhbF91c2VyKQoKICAgICMgaWdub3JlIFNJR1FVSVQgKGl0J3MgdXN1YWxseSBkZWxpYmVyYXRlbHkgZ2VuZXJhdGVkIGJ5IHVzZXJzKQogICAgaWYgb3B0aW9ucy5zaWduYWxfbnVtYmVyID09IGludChzaWduYWwuU0lHUVVJVCk6CiAgICAgICAgd3JpdGVfdXNlcl9jb3JlZHVtcChjb3JlX3BhdGgsIGNvcmVfdWxpbWl0LCBwcm9jX3BpZCwgcmVwb3J0X293bmVyLCBjb3JlZHVtcF9mZCkKICAgICAgICByZXR1cm4gMAoKICAgIGluZm8gPSBhcHBvcnQucmVwb3J0LlJlcG9ydCgiQ3Jhc2giKQogICAgX3NldF9zaWduYWwoaW5mbywgb3B0aW9ucy5zaWduYWxfbnVtYmVyKQogICAgY29yZV9zaXplX2xpbWl0ID0gdXNhYmxlX3JhbSgpICogMyAvIDQKICAgICMgc3lzLnN0ZGluIGhhcyB0eXBlIGlvLlRleHRJT1dyYXBwZXIsIG5vdCB0aGUgY2xhaW1lZCBpby5UZXh0SU8uCiAgICAjIFNlZSBodHRwczovL2dpdGh1Yi5jb20vcHl0aG9uL3R5cGVzaGVkL2lzc3Vlcy8xMDA5MwogICAgYXNzZXJ0IGlzaW5zdGFuY2Uoc3lzLnN0ZGluLCBpby5UZXh0SU9XcmFwcGVyKQogICAgIyByZWFkIGJpbmFyeSBkYXRhIGZyb20gc3RkaW8KICAgIGluZm9bIkNvcmVEdW1wIl0gPSAoc3lzLnN0ZGluLmRldGFjaCgpLCBUcnVlLCBjb3JlX3NpemVfbGltaXQsIFRydWUpCgogICAgIyBXZSBhbHJlYWR5IG5lZWQgdGhpcyBoZXJlIHRvIGZpZ3VyZSBvdXQgdGhlIEV4ZWN1dGFibGVOYW1lIChmb3IKICAgICMgc2NyaXB0cywgZXRjKS4KICAgIGlmIG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoIGlzIG5vdCBOb25lIGFuZCBvcy5wYXRoLmV4aXN0cyhvcHRpb25zLmV4ZWN1dGFibGVfcGF0aCk6CiAgICAgICAgaW5mb1siRXhlY3V0YWJsZVBhdGgiXSA9IG9wdGlvbnMuZXhlY3V0YWJsZV9wYXRoCiAgICBlbHNlOgogICAgICAgIGluZm9bIkV4ZWN1dGFibGVQYXRoIl0gPSBvcy5yZWFkbGluaygiZXhlIiwgZGlyX2ZkPXByb2NfcGlkLmZkKQoKICAgICMgRG8gbm90IGNoZWNrIGNsb3Npbmcgc2Vzc2lvbiBmb3Igcm9vdCBwcm9jZXNzZXMKICAgIGlmIG5vdCByZWFsX3VzZXIuaXNfcm9vdCgpIGFuZCBpc19jbG9zaW5nX3Nlc3Npb24ocHJvY19waWQsIHJlYWxfdXNlcik6CiAgICAgICAgbG9nZ2VyLmVycm9yKCJoYXBwZW5zIGZvciBzaHV0dGluZyBkb3duIHNlc3Npb24sIGlnbm9yaW5nIikKICAgICAgICByZXR1cm4gMAoKICAgICMgaWdub3JlIHN5c3RlbWQgd2F0Y2hkb2cga2lsbHM7IG1vc3Qgb2Z0ZW4gdGhleSBkb24ndCB0ZWxsIHVzIHRoZQogICAgIyBhY3R1YWwgcmVhc29uIChrZXJuZWwgaGFuZywgZXRjLiksIExQICMxNDMzMzIwCiAgICBpZiBpc19zeXN0ZW1kX3dhdGNoZG9nX3Jlc3RhcnQob3B0aW9ucy5zaWduYWxfbnVtYmVyLCBwcm9jX3BpZCk6CiAgICAgICAgbG9nZ2VyLmVycm9yKCJJZ25vcmluZyBzeXN0ZW1kIHdhdGNoZG9nIHJlc3RhcnQiKQogICAgICAgIHJldHVybiAwCgogICAgIyBEcm9wIHByaXZpbGVnZXMgdGVtcG9yYXJpbHkgdG8gbWFrZSBzdXJlIHRoYXQgd2UgZG9uJ3QKICAgICMgaW5jbHVkZSBpbmZvcm1hdGlvbiBpbiB0aGUgY3Jhc2ggcmVwb3J0IHRoYXQgdGhlIHVzZXIgc2hvdWxkCiAgICAjIG5vdCBiZSBhbGxvd2VkIHRvIGFjY2Vzcy4KICAgIGRyb3BfcHJpdmlsZWdlcyhyZWFsX3VzZXIpCgogICAgaW5mby5waWQgPSBwcm9jX3BpZC5waWQKICAgIGluZm8uYWRkX3Byb2NfaW5mbyhwcm9jX3BpZF9mZD1wcm9jX3BpZC5mZCkKCiAgICBpZiAiRXhlY3V0YWJsZVBhdGgiIG5vdCBpbiBpbmZvOgogICAgICAgIGxvZ2dlci5lcnJvcigiY291bGQgbm90IGRldGVybWluZSBFeGVjdXRhYmxlUGF0aCwgYWJvcnRpbmciKQogICAgICAgIHJldHVybiAxCgogICAgZGVmIF93cml0ZV9jb3JlZHVtcF9jYWxsYmFjayhmcm9tX3JlcG9ydDogdHlwaW5nLklPW2J5dGVzXSB8IE5vbmUgPSBOb25lKSAtPiBOb25lOgogICAgICAgIHdyaXRlX3VzZXJfY29yZWR1bXAoCiAgICAgICAgICAgIGNvcmVfcGF0aCwgY29yZV91bGltaXQsIHByb2NfcGlkLCByZXBvcnRfb3duZXIsIGNvcmVkdW1wX2ZkLCBmcm9tX3JlcG9ydAogICAgICAgICkKCiAgICByZXN1bHQgPSBwcm9jZXNzX2NyYXNoKGluZm8sIHJlYWxfdXNlciwgcmVwb3J0X293bmVyLCBfd3JpdGVfY29yZWR1bXBfY2FsbGJhY2spCiAgICBpZiAiQ29yZUR1bXAiIG5vdCBpbiBpbmZvOgogICAgICAgIGxvZ2dlci5lcnJvcigKICAgICAgICAgICAgImNvcmUgZHVtcCBleGNlZWRlZCAlaSBNaUIsIGRyb3BwZWQgdG8gYXZvaWQgbWVtb3J5IG92ZXJmbG93IiwKICAgICAgICAgICAgY29yZV9zaXplX2xpbWl0IC8gMTA0ODU3NiwKICAgICAgICApCiAgICByZXR1cm4gcmVzdWx0CgoKZGVmIHByb2Nlc3NfY3Jhc2goCiAgICBpbmZvOiBhcHBvcnQucmVwb3J0LlJlcG9ydCwKICAgIHJlYWxfdXNlcjogVXNlckdyb3VwSUQsCiAgICByZXBvcnRfb3duZXI6IFVzZXJHcm91cElELAogICAgd3JpdGVfY29yZWR1bXBfY2FsbGJhY2s6IENhbGxhYmxlW1t0eXBpbmcuSU9bYnl0ZXNdIHwgTm9uZV0sIE5vbmVdIHwgTm9uZSA9IE5vbmUsCikgLT4gaW50OgogICAgIiIiUHJvY2VzcyBjcmFzaCBhbmQgcmV0dXJuIGV4aXQgY29kZS4iIiIKICAgICMgVE9ETzogU3BsaXQgaW50byBzbWFsbGVyIGZ1bmN0aW9ucy9tZXRob2RzCiAgICAjIHB5bGludDogZGlzYWJsZT10b28tY29tcGxleCx0b28tbWFueS1icmFuY2hlcyx0b28tbWFueS1zdGF0ZW1lbnRzCiAgICBsb2dnZXIgPSBsb2dnaW5nLmdldExvZ2dlcigpCgogICAgcmVwb3J0ID0gKAogICAgICAgIGYie2FwcG9ydC5maWxldXRpbHMucmVwb3J0X2Rpcn0iCiAgICAgICAgZiIve2luZm9bJ0V4ZWN1dGFibGVQYXRoJ10ucmVwbGFjZSgnLycsICdfJyl9LntyZWFsX3VzZXIudWlkfS5jcmFzaCIKICAgICkKICAgIGhhbmdpbmcgPSBmIntvcy5wYXRoLnNwbGl0ZXh0KHJlcG9ydClbMF19LntpbmZvLnBpZH0uaGFuZ2luZyIKCiAgICBpZiBvcy5wYXRoLmV4aXN0cyhoYW5naW5nKToKICAgICAgICBpZiBvcy5zdGF0KCIvcHJvYy91cHRpbWUiKS5zdF9jdGltZSA8IG9zLnN0YXQoaGFuZ2luZykuc3RfbXRpbWU6CiAgICAgICAgICAgIGluZm9bIlByb2JsZW1UeXBlIl0gPSAiSGFuZyIKICAgICAgICBvcy51bmxpbmsoaGFuZ2luZykKCiAgICBpZiAiSW50ZXJwcmV0ZXJQYXRoIiBpbiBpbmZvOgogICAgICAgIGxvZ2dlci5pbmZvKAogICAgICAgICAgICAnc2NyaXB0OiAlcywgaW50ZXJwcmV0ZWQgYnkgJXMgKGNvbW1hbmQgbGluZSAiJXMiKScsCiAgICAgICAgICAgIGluZm9bIkV4ZWN1dGFibGVQYXRoIl0sCiAgICAgICAgICAgIGluZm9bIkludGVycHJldGVyUGF0aCJdLAogICAgICAgICAgICBpbmZvWyJQcm9jQ21kbGluZSJdLAogICAgICAgICkKICAgIGVsc2U6CiAgICAgICAgbG9nZ2VyLmluZm8oCiAgICAgICAgICAgICdleGVjdXRhYmxlOiAlcyAoY29tbWFuZCBsaW5lICIlcyIpJywKICAgICAgICAgICAgaW5mb1siRXhlY3V0YWJsZVBhdGgiXSwKICAgICAgICAgICAgaW5mb1siUHJvY0NtZGxpbmUiXSwKICAgICAgICApCgogICAgIyBpZ25vcmUgbm9uLXBhY2thZ2UgYmluYXJpZXMgKHVubGVzcyBjb25maWd1cmVkIG90aGVyd2lzZSkKICAgIGlmIG5vdCBhcHBvcnQuZmlsZXV0aWxzLmxpa2VseV9wYWNrYWdlZChpbmZvWyJFeGVjdXRhYmxlUGF0aCJdKToKICAgICAgICBpZiBub3QgYXBwb3J0LmZpbGV1dGlscy5nZXRfY29uZmlnKCJtYWluIiwgInVucGFja2FnZWQiLCBGYWxzZSwgYm9vbGVhbj1UcnVlKToKICAgICAgICAgICAgbG9nZ2VyLmVycm9yKCJleGVjdXRhYmxlIGRvZXMgbm90IGJlbG9uZyB0byBhIHBhY2thZ2UsIGlnbm9yaW5nIikKICAgICAgICAgICAgIyBjaGVjayBpZiB0aGUgdXNlciB3YW50cyBhIGNvcmUgZHVtcAogICAgICAgICAgICByZWNvdmVyX3ByaXZpbGVnZXMoKQogICAgICAgICAgICBpZiB3cml0ZV9jb3JlZHVtcF9jYWxsYmFjazoKICAgICAgICAgICAgICAgIHdyaXRlX2NvcmVkdW1wX2NhbGxiYWNrKE5vbmUpCiAgICAgICAgICAgIHJldHVybiAwCgogICAgIyBpZ25vcmUgU0lHWENQVSBhbmQgU0lHWEZTWiBzaW5jZSB0aGlzIGluZGljYXRlcyBzb21lIGV4dGVybmFsCiAgICAjIGluZmx1ZW5jZSBjaGFuZ2luZyBzb2Z0IFJMSU1JVCB2YWx1ZXMgd2hlbiBydW5uaW5nIHByb2dyYW1zLgogICAgaWYgaW50KGluZm9bIlNpZ25hbCJdKSBpbiAoaW50KHNpZ25hbC5TSUdYQ1BVKSwgaW50KHNpZ25hbC5TSUdYRlNaKSk6CiAgICAgICAgbG9nZ2VyLmVycm9yKAogICAgICAgICAgICAiSWdub3Jpbmcgc2lnbmFsICVzIChjYXVzZWQgYnkgZXhjZWVkaW5nIHNvZnQgUkxJTUlUKSIsIGluZm9bIlNpZ25hbCJdCiAgICAgICAgKQogICAgICAgIHJlY292ZXJfcHJpdmlsZWdlcygpCiAgICAgICAgaWYgd3JpdGVfY29yZWR1bXBfY2FsbGJhY2s6CiAgICAgICAgICAgIHdyaXRlX2NvcmVkdW1wX2NhbGxiYWNrKE5vbmUpCiAgICAgICAgcmV0dXJuIDAKCiAgICBpZiBpbmZvLmNoZWNrX2lnbm9yZWQoKToKICAgICAgICBsb2dnZXIuaW5mbygiZXhlY3V0YWJsZSB2ZXJzaW9uIGlzIGluIGRlbnlsaXN0IG9yIG5vdCBpbiBhbGxvd2xpc3QsIGlnbm9yaW5nIikKICAgICAgICByZXR1cm4gMAoKICAgICMgV2UgY2FuIG5vdyByZWNvdmVyIHByaXZpbGVnZXMgdG8gY3JlYXRlIHRoZSBjcmFzaCByZXBvcnQgZmlsZSBhbmQKICAgICMgd3JpdGUgb3V0IHRoZSB1c2VyIGNvcmVkdW1wcwogICAgcmVjb3Zlcl9wcml2aWxlZ2VzKCkKCiAgICAjIENyZWF0ZSBjcmFzaCByZXBvcnQgZmlsZSBkZXNjcmlwdG9yIGZvciB3cml0aW5nIHRoZSByZXBvcnQgaW50bwogICAgIyByZXBvcnRfZGlyCiAgICB0cnk6CiAgICAgICAgaWYgb3MucGF0aC5leGlzdHMocmVwb3J0KToKICAgICAgICAgICAgYXBwb3J0LmZpbGV1dGlscy5pbmNyZW1lbnRfY3Jhc2hfY291bnRlcihpbmZvLCByZXBvcnQpCiAgICAgICAgICAgIHNraXBfbXNnID0gYXBwb3J0LmZpbGV1dGlscy5zaG91bGRfc2tpcF9jcmFzaChpbmZvLCByZXBvcnQpCiAgICAgICAgICAgIGlmIHNraXBfbXNnOgogICAgICAgICAgICAgICAgbG9nZ2VyLmVycm9yKCIlcyIsIHNraXBfbXNnKQogICAgICAgICAgICAgICAgaWYgd3JpdGVfY29yZWR1bXBfY2FsbGJhY2s6CiAgICAgICAgICAgICAgICAgICAgd3JpdGVfY29yZWR1bXBfY2FsbGJhY2soTm9uZSkKICAgICAgICAgICAgICAgIHJldHVybiAwCiAgICAgICAgICAgICMgcmVtb3ZlIHRoZSBvbGQgZmlsZSwgc28gdGhhdCB3ZSBjYW4gY3JlYXRlIHRoZSBuZXcgb25lCiAgICAgICAgICAgICMgd2l0aCBvcy5PX0NSRUFUfG9zLk9fRVhDTAogICAgICAgICAgICBvcy51bmxpbmsocmVwb3J0KQoKICAgICAgICAjIHdlIHByZWZlciBoYXZpbmcgYSBmaWxlIG1vZGUgb2YgMCB3aGlsZSB3cml0aW5nOwogICAgICAgIGZkID0gb3Mub3BlbihyZXBvcnQsIG9zLk9fUkRXUiB8IG9zLk9fQ1JFQVQgfCBvcy5PX0VYQ0wsIDApCiAgICAgICAgcmVwb3J0ZmlsZSA9IG9zLmZkb3BlbihmZCwgIncrYiIpCiAgICAgICAgYXNzZXJ0IHJlcG9ydGZpbGUuZmlsZW5vKCkgPiBzeXMuc3RkZXJyLmZpbGVubygpCgogICAgICAgICMgTWFrZSBzdXJlIHRoZSBjcmFzaCByZXBvcnRpbmcgZGFlbW9uIGNhbiByZWFkIHRoaXMgcmVwb3J0CiAgICAgICAgdHJ5OgogICAgICAgICAgICBnaWQgPSBwd2QuZ2V0cHduYW0oIndob29wc2llIikucHdfZ2lkCiAgICAgICAgICAgIG9zLmZjaG93bihmZCwgcmVwb3J0X293bmVyLnVpZCwgZ2lkKQogICAgICAgIGV4Y2VwdCAoT1NFcnJvciwgS2V5RXJyb3IpOgogICAgICAgICAgICBvcy5mY2hvd24oZmQsIHJlcG9ydF9vd25lci51aWQsIC0xKQogICAgZXhjZXB0IE9TRXJyb3IgYXMgZXJyb3I6CiAgICAgICAgbG9nZ2VyLmVycm9yKCJDb3VsZCBub3QgY3JlYXRlIHJlcG9ydCBmaWxlOiAlcyIsIHN0cihlcnJvcikpCiAgICAgICAgcmV0dXJuIDEKCiAgICAjIERyb3AgcHJpdmlsZWdlcyBiZWZvcmUgd3JpdGluZyBvdXQgdGhlIHJlcG9ydGZpbGUuCiAgICBkcm9wX3ByaXZpbGVnZXMocmVhbF91c2VyKQoKICAgIGluZm8uYWRkX3VzZXJfaW5mbygpCiAgICBpbmZvLmFkZF9vc19pbmZvKCkKICAgIHdpdGggY29udGV4dGxpYi5zdXBwcmVzcyhTeXN0ZW1FcnJvciwgVmFsdWVFcnJvcik6CiAgICAgICAgaW5mby5hZGRfcGFja2FnZV9pbmZvKCkKICAgIGluZm9bIl9Ib29rc1J1biJdID0gIm5vIgoKICAgICMgRW5zdXJlIHRoYXQgdGhlIENvcmVEdW1wIGZyb20gc3lzdGVtZC1jb3JlZHVtcCBjYW4gYmUgcmVhZC4KICAgIGlmIHJlcG9ydF9vd25lci5pc19yb290KCk6CiAgICAgICAgcmVjb3Zlcl9wcml2aWxlZ2VzKCkKCiAgICB0cnk6CiAgICAgICAgaW5mby53cml0ZShyZXBvcnRmaWxlKQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgb3MudW5saW5rKHJlcG9ydCkKICAgICAgICByYWlzZQoKICAgICMgR2V0IHByaXZpbGVnZXMgYmFjayBzbyB0aGUgY29yZSBmaWxlIGNhbiBiZSB3cml0dGVuIHRvIHJvb3Qtb3duZWQKICAgICMgY29yZWZpbGUgZGlyZWN0b3J5CiAgICByZWNvdmVyX3ByaXZpbGVnZXMoKQoKICAgICMgbWFrZSB0aGUgcmVwb3J0IHdyaXRhYmxlIG5vdywgd2hlbiBpdCdzIGNvbXBsZXRlbHkgd3JpdHRlbgogICAgb3MuZmNobW9kKGZkLCAwbzY0MCkKICAgIGxvZ2dlci5pbmZvKCJ3cm90ZSByZXBvcnQgJXMiLCByZXBvcnQpCgogICAgaWYgd3JpdGVfY29yZWR1bXBfY2FsbGJhY2s6CiAgICAgICAgIyBDaGVjayBpZiB0aGUgdXNlciB3YW50cyBhIGNvcmUgZmlsZS4gV2UgbmVlZCB0byBjcmVhdGUgdGhhdAogICAgICAgICMgZnJvbSB0aGUgd3JpdHRlbiByZXBvcnQsIGFzIHdlIGNhbiBvbmx5IHJlYWQgc3RkaW4gb25jZSBhbmQKICAgICAgICAjIHdyaXRlX3VzZXJfY29yZWR1bXAoKSBtaWdodCBhYm9ydCByZWFkaW5nIGZyb20gc3RkaW4gYW5kIHJlbW92ZQogICAgICAgICMgdGhlIHdyaXR0ZW4gY29yZSBmaWxlIHdoZW4gY29yZV91bGltaXQgaXMgPiAwIGFuZCBzbWFsbGVyCiAgICAgICAgIyB0aGFuIHRoZSBjb3JlIHNpemUuCiAgICAgICAgcmVwb3J0ZmlsZS5zZWVrKDApCiAgICAgICAgd3JpdGVfY29yZWR1bXBfY2FsbGJhY2socmVwb3J0ZmlsZSkKICAgIHJldHVybiAwCgoKY2xhc3MgX0pvdXJuYWxNZXNzYWdlTm90Rm91bmQoUnVudGltZUVycm9yKToKICAgICIiIk5vIG1hdGNoaW5nIGpvdXJuYWwgbWVzc2FnZSBmb3VuZC4iIiIKCgpkZWYgZ2V0X3N5c3RlbWRfY29yZWR1bXAoaW5zdGFuY2U6IHN0cikgLT4gZGljdFtzdHIsIG9iamVjdF06CiAgICAiIiJSZWFkIGNyYXNoIGZyb20gc3lzdGVtZC1jb3JlZHVtcC4KCiAgICBUaGUgY3Jhc2ggaXMgaWRlbnRpZmllZCBieSBmaW5kaW5nIHRoZSBtYXRjaGluZyBpbnN0YW5jZSBvZgogICAgc3lzdGVtZC1jb3JlZHVtcEAuc2VydmljZS4KICAgICIiIgogICAgc3lzdGVtZF91bml0ID0gZiJzeXN0ZW1kLWNvcmVkdW1wQHtpbnN0YW5jZX0uc2VydmljZSIKICAgIHRyeToKICAgICAgICAjIHB5bGludDogZGlzYWJsZS1uZXh0PWltcG9ydC1vdXRzaWRlLXRvcGxldmVsCiAgICAgICAgaW1wb3J0IHN5c3RlbWQuam91cm5hbAogICAgZXhjZXB0IEltcG9ydEVycm9yOgogICAgICAgIGxvZ2dpbmcuZ2V0TG9nZ2VyKCkuZXJyb3IoCiAgICAgICAgICAgICJzeXN0ZW1kIFB5dGhvbiBtb2R1bGUgaXMgcmVxdWlyZWQgZm9yIHJlYWRpbmcgam91cm5hbCBsb2cgZnJvbSAlcy4iCiAgICAgICAgICAgICIgUGxlYXNlIGluc3RhbGwgcHl0aG9uMy1zeXN0ZW1kISIsCiAgICAgICAgICAgIHN5c3RlbWRfdW5pdCwKICAgICAgICApCiAgICAgICAgc3lzLmV4aXQoMSkKCiAgICBqb3VybmFsID0gc3lzdGVtZC5qb3VybmFsLlJlYWRlcigpCiAgICBqb3VybmFsLm1lc3NhZ2VpZF9tYXRjaCgiZmMyZTIyYmM2ZWU2NDdiNmI5MDcyOWFiMzRhMjUwYjEiKQogICAgam91cm5hbC5hZGRfbWF0Y2goZiJfU1lTVEVNRF9VTklUPXtzeXN0ZW1kX3VuaXR9IikKICAgIGNvcmVkdW1wcyA9IGxpc3Qoam91cm5hbCkKICAgIGlmIG5vdCBjb3JlZHVtcHM6CiAgICAgICAgcmFpc2UgX0pvdXJuYWxNZXNzYWdlTm90Rm91bmQoCiAgICAgICAgICAgIGYiTm8gam91cm5hbCBsb2cgZm9yIHN5c3RlbWQgdW5pdCB7c3lzdGVtZF91bml0fSBmb3VuZC4iCiAgICAgICAgKQogICAgYXNzZXJ0IGxlbihjb3JlZHVtcHMpID09IDEKICAgIHJldHVybiBjb3JlZHVtcHNbMF0KCgpkZWYgX3VzZXJfY2FuX3JlYWRfY29yZWR1bXAocmVwb3J0OiBhcHBvcnQucmVwb3J0LlJlcG9ydCwgdXNlcjogVXNlckdyb3VwSUQpIC0+IGJvb2w6CiAgICBjb3JlZHVtcCA9IHJlcG9ydC5nZXQoIkNvcmVEdW1wIikKICAgIGlmIG5vdCBpc2luc3RhbmNlKGNvcmVkdW1wLCBDb21wcmVzc2VkRmlsZSk6CiAgICAgICAgcmV0dXJuIFRydWUKICAgIGRyb3BfcHJpdmlsZWdlcyh1c2VyKQogICAgaXNfcmVhZGFibGUgPSBjb3JlZHVtcC5pc19yZWFkYWJsZSgpCiAgICByZWNvdmVyX3ByaXZpbGVnZXMoKQogICAgcmV0dXJuIGlzX3JlYWRhYmxlCgoKZGVmIF9kZXRlcm1pbmVfcmVwb3J0X293bmVyKAogICAgcmVwb3J0OiBhcHBvcnQucmVwb3J0LlJlcG9ydCwgcmVhbF91c2VyOiBVc2VyR3JvdXBJRAopIC0+IFVzZXJHcm91cElEOgogICAgaWYgX3VzZXJfY2FuX3JlYWRfY29yZWR1bXAocmVwb3J0LCByZWFsX3VzZXIpOgogICAgICAgIHJldHVybiByZWFsX3VzZXIKCiAgICAjIHN5c3RlbWQtY29yZWR1bXAgZG9lcyBub3QgYWxsb3cgdXNlcnMgdG8gcmVhZCBjb3JlZHVtcHMgaWYgdGhlIHVpZCBvcgogICAgIyBjYXBhYmlsaXRpZXMgd2VyZSBjaGFuZ2VkLiBTbyBtYWtlIHRoZSByZXBvcnQgb25seSByZWFkYWJsZSBieSByb290LgogICAgbG9nZ2luZy5nZXRMb2dnZXIoKS53YXJuaW5nKAogICAgICAgICJDb3JlIGR1bXAgaXMgbm90IHJlYWRhYmxlIGJ5IHVzZXIgJWkuIgogICAgICAgICIgTWFraW5nIHRoZSByZXBvcnQgb25seSByZWFkYWJsZSBieSByb290LiIsCiAgICAgICAgcmVhbF91c2VyLnVpZCwKICAgICkKICAgIHJldHVybiBVc2VyR3JvdXBJRCgwLCAwKQoKCmRlZiBwcm9jZXNzX2NyYXNoX2Zyb21fc3lzdGVtZF9jb3JlZHVtcChpbnN0YW5jZTogc3RyKSAtPiBpbnQ6CiAgICAiIiJSZWFkIGNyYXNoIGZyb20gc3lzdGVtZC1jb3JlZHVtcCBhbmQgcHJvY2VzcyBpdC4iIiIKICAgIHRyeToKICAgICAgICBjb3JlZHVtcCA9IGdldF9zeXN0ZW1kX2NvcmVkdW1wKGluc3RhbmNlKQogICAgZXhjZXB0IF9Kb3VybmFsTWVzc2FnZU5vdEZvdW5kIGFzIGVycm9yOgogICAgICAgIGxvZ2dpbmcuZ2V0TG9nZ2VyKF9fbmFtZV9fKS5lcnJvcigiJXMiLCBlcnJvcikKICAgICAgICByZXR1cm4gMQogICAgaWYgIkNPUkVEVU1QX0NPTlRBSU5FUl9DTURMSU5FIiBpbiBjb3JlZHVtcDoKICAgICAgICBsb2dnaW5nLmdldExvZ2dlcihfX25hbWVfXykuaW5mbygKICAgICAgICAgICAgIklnbm9yaW5nICVzIGNyYXNoIGJlY2F1c2UgaXQgaGFwcGVuZWQgaW5zaWRlIGEgY29udGFpbmVyLiIKICAgICAgICAgICAgIiBQbGVhc2UgaW5zdGFsbCBzeXN0ZW1kLWNvcmVkdW1wIGluc2lkZSB0aGUgY29udGFpbmVyIGZvciIKICAgICAgICAgICAgIiBmb3J3YXJkaW5nIGZ1dHVyZSBjcmFzaGVzLiIsCiAgICAgICAgICAgIGNvcmVkdW1wWyJDT1JFRFVNUF9FWEUiXSwKICAgICAgICApCiAgICAgICAgcmV0dXJuIDAKICAgIHJlcG9ydCA9IGFwcG9ydC5yZXBvcnQuUmVwb3J0LmZyb21fc3lzdGVtZF9jb3JlZHVtcChjb3JlZHVtcCkKICAgIHJlYWxfdXNlciA9IFVzZXJHcm91cElELmZyb21fc3lzdGVtZF9jb3JlZHVtcChjb3JlZHVtcCkKICAgIHJlcG9ydF9vd25lciA9IF9kZXRlcm1pbmVfcmVwb3J0X293bmVyKHJlcG9ydCwgcmVhbF91c2VyKQogICAgcmV0dXJuIHByb2Nlc3NfY3Jhc2gocmVwb3J0LCByZWFsX3VzZXIsIHJlcG9ydF9vd25lcikKCgppZiBfX25hbWVfXyA9PSAiX19tYWluX18iOgogICAgc3lzLmV4aXQobWFpbihzeXMuYXJndlsxOl0pKQo=')
    GENERATED_BYTES = base64.b64decode('IyBBdXRvbWF0aWNhbGx5IGdlbmVyYXRlZCBieSBzeXN0ZW1kLXN5c3YtZ2VuZXJhdG9yCgpbVW5pdF0KRG9jdW1lbnRhdGlvbj1tYW46c3lzdGVtZC1zeXN2LWdlbmVyYXRvcig4KQpTb3VyY2VQYXRoPS9ldGMvaW5pdC5kL2FwcG9ydApEZXNjcmlwdGlvbj1MU0I6IGF1dG9tYXRpYyBjcmFzaCByZXBvcnQgZ2VuZXJhdGlvbgpCZWZvcmU9bXVsdGktdXNlci50YXJnZXQKQmVmb3JlPW11bHRpLXVzZXIudGFyZ2V0CkJlZm9yZT1tdWx0aS11c2VyLnRhcmdldApCZWZvcmU9Z3JhcGhpY2FsLnRhcmdldApBZnRlcj1yZW1vdGUtZnMudGFyZ2V0CgpbU2VydmljZV0KVHlwZT1mb3JraW5nClJlc3RhcnQ9bm8KVGltZW91dFNlYz01bWluCklnbm9yZVNJR1BJUEU9bm8KS2lsbE1vZGU9cHJvY2VzcwpHdWVzc01haW5QSUQ9bm8KUmVtYWluQWZ0ZXJFeGl0PXllcwpTdWNjZXNzRXhpdFN0YXR1cz01IDYKRXhlY1N0YXJ0PS9ldGMvaW5pdC5kL2FwcG9ydCBzdGFydApFeGVjU3RvcD0vZXRjL2luaXQuZC9hcHBvcnQgc3RvcAo=')
    U22_INIT_BYTES = b"#!/bin/sh\n# d16 delegated fixture\n"
    U22_DEFAULT_BYTES = b"enabled=1\n"
    AUX_BYTES = {'/usr/lib/systemd/system/apport-autoreport.path':base64.b64decode('W1VuaXRdCkRlc2NyaXB0aW9uPVByb2Nlc3MgZXJyb3IgcmVwb3J0cyB3aGVuIGF1dG9tYXRpYyByZXBvcnRpbmcgaXMgZW5hYmxlZCAoZmlsZSB3YXRjaCkKQ29uZGl0aW9uUGF0aEV4aXN0cz0vdmFyL2xpYi9hcHBvcnQvYXV0b3JlcG9ydAoKW1BhdGhdClBhdGhDaGFuZ2VkPS92YXIvY3Jhc2gKCltJbnN0YWxsXQpXYW50ZWRCeT1wYXRocy50YXJnZXQK'),'/usr/lib/systemd/system/apport-autoreport.service':base64.b64decode('W1VuaXRdCkRlc2NyaXB0aW9uPVByb2Nlc3MgZXJyb3IgcmVwb3J0cyB3aGVuIGF1dG9tYXRpYyByZXBvcnRpbmcgaXMgZW5hYmxlZApDb25kaXRpb25QYXRoRXhpc3RzPS92YXIvbGliL2FwcG9ydC9hdXRvcmVwb3J0CldhbnRzPXdob29wc2llLnBhdGgKQWZ0ZXI9d2hvb3BzaWUucGF0aAoKW1NlcnZpY2VdClR5cGU9b25lc2hvdApFeGVjU3RhcnQ9L3Vzci9zaGFyZS9hcHBvcnQvd2hvb3BzaWUtdXBsb2FkLWFsbCAtLXRpbWVvdXQgMjAK'),'/usr/lib/systemd/system/apport-autoreport.timer':base64.b64decode('W1VuaXRdCkRlc2NyaXB0aW9uPVByb2Nlc3MgZXJyb3IgcmVwb3J0cyB3aGVuIGF1dG9tYXRpYyByZXBvcnRpbmcgaXMgZW5hYmxlZCAodGltZXIgYmFzZWQpCkNvbmRpdGlvblBhdGhFeGlzdHM9L3Zhci9saWIvYXBwb3J0L2F1dG9yZXBvcnQKCltUaW1lcl0KT25TdGFydHVwU2VjPTFoCk9uVW5pdEFjdGl2ZVNlYz0zaAoKW0luc3RhbGxdCldhbnRlZEJ5PXRpbWVycy50YXJnZXQK'),'/usr/lib/systemd/system/apport-coredump-hook@.service':base64.b64decode('IyBUaGlzIHNlcnZpY2UgaXMgcmVzcG9uc2libGUgZm9yIHJlYWRpbmcgdGhlIGNvcmVkdW1wIGRhdGEgZnJvbSBzeXN0ZW1kIGpvdXJuYWwKIyBhZnRlciBhIGNyYXNoIGhhcyBvY2N1cnJlZCwgYW5kIGdlbmVyYXRpbmcgYSBjcmFzaCBmaWxlIHRvIC92YXIvY3Jhc2gvLgpbU2VydmljZV0KVHlwZT1vbmVzaG90CkV4ZWNTdGFydD0vdXNyL3NoYXJlL2FwcG9ydC9hcHBvcnQgLS1mcm9tLXN5c3RlbWQtY29yZWR1bXAgJWkKTmljZT05Ck9PTVNjb3JlQWRqdXN0PTUwMApJUEFkZHJlc3NEZW55PWFueQpMb2NrUGVyc29uYWxpdHk9eWVzCk1lbW9yeURlbnlXcml0ZUV4ZWN1dGU9eWVzCk5vTmV3UHJpdmlsZWdlcz15ZXMKUHJpdmF0ZURldmljZXM9eWVzClByaXZhdGVOZXR3b3JrPXllcwpQcml2YXRlVG1wPXllcwpQcm90ZWN0Q29udHJvbEdyb3Vwcz15ZXMKUHJvdGVjdEhvbWU9cmVhZC1vbmx5ClByb3RlY3RIb3N0bmFtZT15ZXMKUHJvdGVjdEtlcm5lbExvZ3M9eWVzClByb3RlY3RLZXJuZWxNb2R1bGVzPXllcwpQcm90ZWN0S2VybmVsVHVuYWJsZXM9eWVzClByb3RlY3RTeXN0ZW09c3RyaWN0ClJlYWRXcml0ZVBhdGhzPS92YXIvY3Jhc2ggL3Zhci9sb2cKUmVzdHJpY3RBZGRyZXNzRmFtaWxpZXM9QUZfVU5JWApSZXN0cmljdFJlYWx0aW1lPXllcwpSZXN0cmljdFNVSURTR0lEPXllcwpTeXN0ZW1DYWxsQXJjaGl0ZWN0dXJlcz1uYXRpdmUKU3lzdGVtQ2FsbEVycm9yTnVtYmVyPUVQRVJNClN5c3RlbUNhbGxGaWx0ZXI9QHN5c3RlbS1zZXJ2aWNlIEBmaWxlLXN5c3RlbSBAc2V0dWlkCg=='),'/usr/lib/systemd/system/apport-forward.socket':base64.b64decode('W1VuaXRdCkRlc2NyaXB0aW9uPVVuaXggc29ja2V0IGZvciBhcHBvcnQgY3Jhc2ggZm9yd2FyZGluZwpDb25kaXRpb25WaXJ0dWFsaXphdGlvbj1jb250YWluZXIKCltTb2NrZXRdCkxpc3RlblN0cmVhbT0vcnVuL2FwcG9ydC5zb2NrZXQKU29ja2V0TW9kZT0wNjAwCkFjY2VwdD15ZXMKTWF4Q29ubmVjdGlvbnM9MTAKQmFja2xvZz01ClBhc3NDcmVkZW50aWFscz10cnVlCgpbSW5zdGFsbF0KV2FudGVkQnk9c29ja2V0cy50YXJnZXQK'),'/usr/lib/systemd/system/apport-forward@.service':base64.b64decode('W1VuaXRdCkRlc2NyaXB0aW9uPUFwcG9ydCBjcmFzaCBmb3J3YXJkaW5nIHJlY2VpdmVyClJlcXVpcmVzPWFwcG9ydC1mb3J3YXJkLnNvY2tldAoKW1NlcnZpY2VdClR5cGU9b25lc2hvdApFeGVjU3RhcnQ9L3Vzci9zaGFyZS9hcHBvcnQvYXBwb3J0Cg=='),'/usr/lib/systemd/system/systemd-coredump@.service.d/apport-coredump-hook.conf':base64.b64decode('W1VuaXRdCk9uU3VjY2Vzcz1hcHBvcnQtY29yZWR1bXAtaG9va0AlaS5zZXJ2aWNlCg==')}

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name) / "root"
        self.root.mkdir()
        self.work = Path(td.name) / "work"
        self.work.mkdir()
        self._write(A.PID1_ENVIRON, b"PATH=/usr/bin\0HOME=/\0")

        # D17 exact SHA constants are never patched: fixture bytes must match accepted evidence.
        for name, data in (("APPORT_INIT_SCRIPT_SHA256", self.U22_INIT_BYTES), ("APPORT_DEFAULT_ENABLED_SHA256", self.U22_DEFAULT_BYTES)):
            patcher = mock.patch.object(A, name, frozenset({_hashlib.sha256(data).hexdigest()}))
            patcher.start()
            self.addCleanup(patcher.stop)

        # /tmp on the user's PC is noexec. Test fixture X_OK is evaluated from mode bits
        # only inside the synthetic source_root; the product detector itself is unchanged.
        real_access = os.access
        root_prefix = str(self.root) + os.sep
        def fixture_access(path, mode, *args, **kwargs):
            text = os.fspath(path)
            if mode == os.X_OK and text.startswith(root_prefix):
                try:
                    st = os.stat(text)
                    return bool(st.st_mode & 0o111)
                except OSError:
                    return False
            return real_access(path, mode, *args, **kwargs)
        access_patcher = mock.patch.object(A.os, "access", side_effect=fixture_access)
        access_patcher.start()
        self.addCleanup(access_patcher.stop)

    def _path(self, logical):
        return self.root / logical.lstrip("/")

    def _write(self, logical, data, mode=0o644):
        path = self._path(logical)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, mode)
        return path

    def _link(self, target, logical):
        path = self._path(logical)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path)
        return path

    def _remove(self, logical):
        path = self._path(logical)
        if path.is_dir() and not path.is_symlink():
            path.rmdir()
        else:
            path.unlink()

    def _merged_usr(self):
        lib = self._path("/lib")
        if not lib.exists() and not lib.is_symlink():
            self._link("usr/lib", "/lib")

    def _install_aux(self, coredump=False, raw_prefix="/usr/lib"):
        self._merged_usr()
        regulars = set(A.APPORT_AUX_BASE_PATHS) & set(A.APPORT_AUX_REGULAR_SHA256)
        if coredump:
            regulars = set(A.APPORT_AUX_COREDUMP_PATHS) & set(A.APPORT_AUX_REGULAR_SHA256)
        for path in sorted(regulars):
            self._write(path, self.AUX_BYTES[path])
        target_map = {
            "/etc/systemd/system/paths.target.wants/apport-autoreport.path": raw_prefix + "/systemd/system/apport-autoreport.path",
            "/etc/systemd/system/sockets.target.wants/apport-forward.socket": raw_prefix + "/systemd/system/apport-forward.socket",
            "/etc/systemd/system/timers.target.wants/apport-autoreport.timer": raw_prefix + "/systemd/system/apport-autoreport.timer",
        }
        for path, target in target_map.items():
            self._link(target, path)

    def _install_native(self, with_aux=True, agent_bytes=None):
        if with_aux:
            self._install_aux(coredump=True, raw_prefix="/usr/lib")
        self._write(A.APPORT_NATIVE_UNIT, self.NATIVE_UNIT_BYTES)
        self._link(A.APPORT_NATIVE_WANTS_TARGET, A.APPORT_NATIVE_WANTS)
        if agent_bytes is None:
            agent_bytes = self.NATIVE_AGENT_BYTES
        self._write(A.APPORT_AGENT, agent_bytes, 0o755)

    def _install_generated(self, with_aux=True):
        if with_aux:
            self._install_aux(coredump=False, raw_prefix="/lib")
        self._write(A.APPORT_GENERATED_UNIT, self.GENERATED_BYTES, A.APPORT_GENERATED_UNIT_MODE)
        for path, target in A.APPORT_GENERATED_LINKS.items():
            self._link(target, path)

    def _install_sysv_conflict(self):
        self._write(A.APPORT_INIT_SCRIPT, self.U22_INIT_BYTES, 0o755)
        self._write(A.APPORT_AGENT, b"#!/bin/sh\n", 0o755)
        self._write(A.APPORT_DEFAULT_FILE, self.U22_DEFAULT_BYTES)
        self._link("../init.d/apport", "/etc/rc2.d/S01apport")

    def detect(self):
        return A.detect_runtime_writer_conflict(self.KEY, str(self.root))

    def detect_native(self):
        try:
            return A._detect_apport_native_suid_dumpable(str(self.root))
        except A._RuntimeWriterUndetermined as exc:
            return A._ApportNativeDecision(A.RUNTIME_WRITER_UNDETERMINED, exc.step, exc.detail, False)

    def _execute(self, dry_run=False, detector=None):
        writes = []
        persistent = self.work / "zz-target.conf"
        kwargs = dict(
            source_files=(), source_root=str(self.root), dry_run=dry_run,
            persistent_target=str(persistent), runtime_target=str(self.work / "runtime"),
            read_runtime=lambda: 2, write_runtime=lambda value: writes.append(value),
            write_runtime_protocol=A.RUNTIME_WRITER_PROTOCOL_V1,
            privilege_check=lambda: None, persistent_uid=os.getuid(), persistent_gid=os.getgid(), persistent_mode=0o644,
        )
        if detector is not None:
            kwargs["runtime_writer_detector"] = detector
        result = A.execute_control("CTRL-D17", self.KEY, "eq", 0, True, **kwargs)
        return result, writes, persistent

    def test_d17_constants_and_evidence_bytes_are_exact(self):
        module = load_adapter()
        self.assertEqual(module.APPORT_SYSTEMD_ROOTS, (
            "/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
            "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached",
            "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
            "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/generator.late",
        ))
        self.assertEqual(module.APPORT_DBUS_ROOTS, (
            "/usr/share/dbus-1/system-services", "/etc/dbus-1/system-services", "/usr/local/share/dbus-1/system-services",
        ))
        self.assertEqual(_hashlib.sha256(self.NATIVE_UNIT_BYTES).hexdigest(), module.APPORT_NATIVE_UNIT_SHA256)
        self.assertEqual(
            module.APPORT_NATIVE_AGENT_SHA256,
            frozenset({
                "1b8b5e2c53e8970dd2f47c9a0892030d1ebad57cae1f7242c43a6252f1f6dff2",
                "e8b57da9924d461fee6d3b392dc184697bc14d2eb8d717c05e1cbf0bd376041e",
            }),
        )
        self.assertIn(_hashlib.sha256(self.NATIVE_AGENT_BYTES).hexdigest(), module.APPORT_NATIVE_AGENT_SHA256)
        self.assertIn(_hashlib.sha256(self.U26_NATIVE_AGENT_BYTES).hexdigest(), module.APPORT_NATIVE_AGENT_SHA256)
        self.assertEqual(_hashlib.sha256(self.GENERATED_BYTES).hexdigest(), module.APPORT_GENERATED_UNIT_SHA256)
        self.assertEqual(len(self.GENERATED_BYTES), module.APPORT_GENERATED_UNIT_SIZE)
        for path, expected in module.APPORT_AUX_REGULAR_SHA256.items():
            self.assertIn(path, self.AUX_BYTES)
            self.assertEqual(_hashlib.sha256(self.AUX_BYTES[path]).hexdigest(), expected)

    def test_d17_census_dangling_marker_case_and_dbus(self):
        self._link("/missing", "/etc/systemd/system/unrelated.service")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_NO_CONFLICT)
        self._remove("/etc/systemd/system/unrelated.service")

        self._link("loop-b.service", "/etc/systemd/system/loop-a.service")
        self._link("loop-a.service", "/etc/systemd/system/loop-b.service")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._remove("/etc/systemd/system/loop-a.service")
        self._remove("/etc/systemd/system/loop-b.service")

        self._write("/etc/systemd/system/generic.service", b"Description=APPORT upper-case marker\n")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._remove("/etc/systemd/system/generic.service")

        self._write("/usr/share/dbus-1/system-services/example.service", b"Name=apport.service\n")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)

    def test_d17_census_special_and_alias_fail_closed(self):
        fifo = self._path("/etc/systemd/system/apport.pipe")
        fifo.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(fifo)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        fifo.unlink()

        special = self._path("/dev/fake-special")
        special.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(special)
        self._link("/dev/fake-special", "/etc/systemd/system/apport.service")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._remove("/etc/systemd/system/apport.service")
        special.unlink()

        self._path("/usr/lib/systemd/system").mkdir(parents=True, exist_ok=True)
        self._path("/lib/systemd/system").mkdir(parents=True, exist_ok=True)
        verdict, step, detail = self.detect()
        self.assertEqual(verdict, A.RUNTIME_WRITER_UNDETERMINED)
        self.assertEqual(str(step), "C1")
        self.assertEqual(detail, "lib-usr-systemd-divergent")

    def test_d17_strict_resolution_preserves_symlink_dotdot_order(self):
        base = self._path("/usr/lib/systemd/system")
        (base / "dir").mkdir(parents=True, exist_ok=True)
        self._path("/other/deeper").mkdir(parents=True, exist_ok=True)
        self._write("/other/z", b"Description=apport strict target\n")
        self._write("/usr/lib/systemd/system/dir/z", b"neutral\n")
        self._link("/other/deeper", "/usr/lib/systemd/system/dir/link")
        self._link("dir/link/../z", "/usr/lib/systemd/system/x.service")

        direct = A._rw_resolve_logical(
            str(self.root), "/usr/lib/systemd/system/dir/link/../z", "C1"
        )
        self.assertIsNotNone(direct)
        self.assertEqual(direct[0], "/other/z")

        resolved = A._rw_resolve_logical(
            str(self.root), "/usr/lib/systemd/system/x.service", "C1"
        )
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0], "/other/z")

        logical = "/usr/lib/systemd/system/x.service"
        hit = A._rw_census_symlink(
            str(self.root), logical, "x.service", os.lstat(self._path(logical))
        )
        self.assertIsNotNone(hit)
        self.assertEqual(hit.resolved_path, "/other/z")
        self.assertTrue(hit.marker_bytes)

    def test_d17_strict_resolution_regular_file_dotdot_is_enotdir(self):
        self._path("/d").mkdir(parents=True, exist_ok=True)
        self._write("/d/f", b"regular-file\n")
        self._write("/d/x", b"Description=apport marker\n")
        with self.assertRaises(A._RuntimeWriterUndetermined) as cm:
            A._rw_resolve_logical(str(self.root), "/d/f/../x", "C1")
        self.assertEqual(cm.exception.step, "C1")
        self.assertEqual(cm.exception.detail, "ENOTDIR:/d/f")

    def test_d17_strict_resolution_symlink_target_file_dotdot_is_enotdir(self):
        self._path("/d").mkdir(parents=True, exist_ok=True)
        self._write("/d/f", b"regular-file\n")
        self._write("/d/x", b"Description=apport marker\n")
        self._link("f/../x", "/d/s")
        with self.assertRaises(A._RuntimeWriterUndetermined) as cm:
            A._rw_resolve_logical(str(self.root), "/d/s", "C1")
        self.assertEqual(cm.exception.step, "C1")
        self.assertEqual(cm.exception.detail, "ENOTDIR:/d/f")

    def test_d17_strict_resolution_symlink_target_file_dot_is_enotdir(self):
        self._path("/d").mkdir(parents=True, exist_ok=True)
        self._write("/d/f", b"regular-file\n")
        self._link("f/.", "/d/s2")
        with self.assertRaises(A._RuntimeWriterUndetermined) as cm:
            A._rw_resolve_logical(str(self.root), "/d/s2", "C1")
        self.assertEqual(cm.exception.step, "C1")
        self.assertEqual(cm.exception.detail, "ENOTDIR:/d/f")

    def test_d17_strict_resolution_regular_file_trailing_slash_is_enotdir(self):
        self._path("/d").mkdir(parents=True, exist_ok=True)
        self._write("/d/f", b"regular-file\n")
        with self.assertRaises(A._RuntimeWriterUndetermined) as cm:
            A._rw_resolve_logical(str(self.root), "/d/f/", "C1")
        self.assertEqual(cm.exception.step, "C1")
        self.assertEqual(cm.exception.detail, "ENOTDIR:/d/f")

    def test_d17_strict_resolution_symlink_target_file_trailing_slash_is_enotdir(self):
        self._path("/d").mkdir(parents=True, exist_ok=True)
        self._write("/d/f", b"regular-file\n")
        self._link("f/", "/d/s1")
        with self.assertRaises(A._RuntimeWriterUndetermined) as cm:
            A._rw_resolve_logical(str(self.root), "/d/s1", "C1")
        self.assertEqual(cm.exception.step, "C1")
        self.assertEqual(cm.exception.detail, "ENOTDIR:/d/f")

    def test_d17_strict_resolution_symlink_target_file_double_trailing_slash_is_enotdir(self):
        self._path("/d").mkdir(parents=True, exist_ok=True)
        self._write("/d/f", b"regular-file\n")
        self._link("f//", "/d/s2")
        with self.assertRaises(A._RuntimeWriterUndetermined) as cm:
            A._rw_resolve_logical(str(self.root), "/d/s2", "C1")
        self.assertEqual(cm.exception.step, "C1")
        self.assertEqual(cm.exception.detail, "ENOTDIR:/d/f")

    def test_d17_aux_profiles_exact_changed_missing_extra_and_raw_targets(self):
        self._install_aux(coredump=False, raw_prefix="/lib")
        decision = self.detect_native()
        self.assertEqual(decision.verdict, A.RUNTIME_WRITER_DELEGATE_SYSV)
        self.assertTrue(decision.auxiliary_nonempty)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)

        for path in sorted(set(A.APPORT_AUX_COREDUMP_PATHS) - set(A.APPORT_AUX_BASE_PATHS)):
            self._write(path, self.AUX_BYTES[path])
        decision = self.detect_native()
        self.assertEqual(decision.verdict, A.RUNTIME_WRITER_DELEGATE_SYSV)
        self.assertTrue(decision.auxiliary_nonempty)

        path = "/usr/lib/systemd/system/apport-autoreport.service"
        original = self.AUX_BYTES[path]
        self._write(path, original + b"changed")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._write(path, original)

        missing = "/usr/lib/systemd/system/apport-forward@.service"
        self._remove(missing)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._write(missing, self.AUX_BYTES[missing])

        self._write("/etc/systemd/system/apport-extra.service", b"apport extra\n")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)

    def test_d17_native_exact_dry_run_and_sensitivity(self):
        self._install_native(with_aux=True)
        verdict, step, detail = self.detect()
        self.assertEqual(verdict, A.RUNTIME_WRITER_CONFLICT)
        self.assertEqual(getattr(step, "rule_id", None), A.RUNTIME_WRITER_RULE_APPORT_NATIVE)
        self.assertEqual((str(step), detail), ("C4", "agent-exact"))

        applied, writes, persistent = self._execute(dry_run=False)
        dry, dry_writes, _ = self._execute(dry_run=True)
        for result in (applied, dry):
            self.assertEqual(result.outcome, A.OUTCOME_ABORT_CONFLICT)
            self.assertEqual(result.reason, "runtime-writer:APPORT-NATIVE-SUID-DUMPABLE-V1:C4:agent-exact")
            self.assertFalse(result.mutation_performed)
            report = A.control_result_to_report(result, "START", "FINISH")
            self.assertEqual(report["operator_decision"], {
                "class": "SERVICE_MANAGED_PARAMETER",
                "required": True,
                "service": "Apport",
                "parameter": self.KEY,
                "current_value": 2,
            })
        self.assertEqual(writes + dry_writes, [])
        self.assertFalse(persistent.exists())

        bypass = lambda key: A._detect_apport_sysv_suid_dumpable(str(self.root))
        result, _, _ = self._execute(dry_run=True, detector=bypass)
        self.assertNotEqual(result.outcome, A.OUTCOME_ABORT_CONFLICT)

    def test_d17_u26_native_exact_dry_run_and_sensitivity(self):
        self._install_native(with_aux=True, agent_bytes=self.U26_NATIVE_AGENT_BYTES)
        verdict, step, detail = self.detect()
        self.assertEqual(verdict, A.RUNTIME_WRITER_CONFLICT)
        self.assertEqual(getattr(step, "rule_id", None), A.RUNTIME_WRITER_RULE_APPORT_NATIVE)
        self.assertEqual((str(step), detail), ("C4", "agent-exact"))

        applied, writes, persistent = self._execute(dry_run=False)
        dry, dry_writes, _ = self._execute(dry_run=True)
        for result in (applied, dry):
            self.assertEqual(result.outcome, A.OUTCOME_ABORT_CONFLICT)
            self.assertEqual(result.reason, "runtime-writer:APPORT-NATIVE-SUID-DUMPABLE-V1:C4:agent-exact")
            self.assertFalse(result.mutation_performed)
            report = A.control_result_to_report(result, "START", "FINISH")
            self.assertEqual(report["operator_decision"], {
                "class": "SERVICE_MANAGED_PARAMETER",
                "required": True,
                "service": "Apport",
                "parameter": self.KEY,
                "current_value": 2,
            })
        self.assertEqual(writes + dry_writes, [])
        self.assertFalse(persistent.exists())

        with mock.patch.object(A, "APPORT_NATIVE_AGENT_SHA256", frozenset({"1b8b5e2c53e8970dd2f47c9a0892030d1ebad57cae1f7242c43a6252f1f6dff2"})):
            self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)

    def test_d17_u26_unknown_agent_variants(self):
        changed = bytearray(self.U26_NATIVE_AGENT_BYTES)
        changed[-1] ^= 0x01
        self._install_native(with_aux=True, agent_bytes=bytes(changed))
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._write(A.APPORT_AGENT, b"#!/usr/bin/python3\n# third exact agent fixture\n", 0o755)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)

    def test_d17_u26_static_agent_ordering(self):
        text = self.U26_NATIVE_AGENT_BYTES.decode("utf-8")
        main_pos = text.index("def main(args")
        parse_pos = text.index("options = parse_arguments(args)", main_pos)
        coredump_pos = text.index("if options.systemd_coredump_instance:", parse_pos)
        coredump_return = text.index("return process_crash_from_systemd_coredump(", coredump_pos)
        stop_pos = text.index("if options.stop:", coredump_return)
        stop_return = text.index("return 0", stop_pos)
        start_pos = text.index("if options.start:", stop_return)
        start_call = text.index("start_apport()", start_pos)
        self.assertLess(main_pos, parse_pos)
        self.assertLess(parse_pos, coredump_pos)
        self.assertLess(coredump_return, stop_pos)
        self.assertLess(stop_return, start_pos)
        self.assertLess(start_pos, start_call)

        start_def = text.index("def start_apport")
        report_dir = text.index("create_directory(apport.fileutils.report_dir", start_def)
        core_pattern = text.index('write_to_proc_sys(\n        "kernel/core_pattern"', report_dir)
        suid_write = text.index('write_to_proc_sys("fs/suid_dumpable", "2")', core_pattern)
        pipe_limit = text.index('write_to_proc_sys("kernel/core_pipe_limit", "10")', suid_write)
        self.assertLess(report_dir, core_pattern)
        self.assertLess(core_pattern, suid_write)
        self.assertLess(suid_write, pipe_limit)

    def test_d17_native_unknown_missing_and_agent_variants(self):
        self._install_native(with_aux=True)
        self._write(A.APPORT_NATIVE_UNIT, self.NATIVE_UNIT_BYTES + b"changed")
        result, _, _ = self._execute(dry_run=True)
        self.assertEqual(result.outcome, A.OUTCOME_ABORT_OTHER)
        self.assertTrue(result.reason.startswith("runtime-writer:undetermined:APPORT-NATIVE-SUID-DUMPABLE-V1:"))
        self._write(A.APPORT_NATIVE_UNIT, self.NATIVE_UNIT_BYTES)

        self._remove(A.APPORT_NATIVE_WANTS)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._link(A.APPORT_NATIVE_WANTS_TARGET, A.APPORT_NATIVE_WANTS)

        os.chmod(self._path(A.APPORT_AGENT), 0o644)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        os.chmod(self._path(A.APPORT_AGENT), 0o755)

        self._remove(A.APPORT_AGENT)
        self._link("missing-agent", A.APPORT_AGENT)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._remove(A.APPORT_AGENT)
        self._write("/usr/share/apport/apport-real", self.NATIVE_AGENT_BYTES, 0o755)
        self._link("apport-real", A.APPORT_AGENT)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._remove(A.APPORT_AGENT)
        self._write(A.APPORT_AGENT, self.NATIVE_AGENT_BYTES + b"changed", 0o755)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)

    def test_d17_native_container_with_aux_is_undetermined(self):
        self._install_native(with_aux=True)
        self._write(A.PID1_ENVIRON, b"PATH=/usr/bin\0container=lxc\0")
        verdict, step, _ = self.detect()
        self.assertEqual(verdict, A.RUNTIME_WRITER_UNDETERMINED)
        self.assertEqual(getattr(step, "rule_id", None), A.RUNTIME_WRITER_RULE_APPORT_NATIVE)

    def test_d17_bridge_delegates_and_preserves_d16(self):
        self._install_generated(with_aux=True)
        decision = self.detect_native()
        self.assertEqual(decision.verdict, A.RUNTIME_WRITER_DELEGATE_SYSV)
        self.assertTrue(decision.auxiliary_nonempty)
        self._install_sysv_conflict()
        verdict, step, detail = self.detect()
        self.assertEqual(verdict, A.RUNTIME_WRITER_CONFLICT)
        self.assertEqual(getattr(step, "rule_id", None), A.RUNTIME_WRITER_RULE_APPORT_SYSV)
        self.assertEqual(str(step), "R8")
        result, _, _ = self._execute(dry_run=True)
        self.assertEqual(result.reason, "runtime-writer:APPORT-SYSV-SUID-DUMPABLE-V1:R8:default-sha256=" + _hashlib.sha256(self.U22_DEFAULT_BYTES).hexdigest())

        self._remove("/etc/rc2.d/S01apport")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._link("../init.d/apport", "/etc/rc2.d/S01apport")

        self._remove(A.APPORT_INIT_SCRIPT)
        verdict, step, detail = self.detect()
        self.assertEqual(verdict, A.RUNTIME_WRITER_UNDETERMINED)
        self.assertEqual(getattr(step, "rule_id", None), A.RUNTIME_WRITER_RULE_APPORT_NATIVE)
        self.assertEqual((str(step), detail), ("C6", "auxiliary-with-sysv-no-conflict"))

    def test_d17_bridge_changed_missing_extra_fail_closed(self):
        self._install_generated(with_aux=True)
        self._write(A.APPORT_GENERATED_UNIT, self.GENERATED_BYTES + b"changed", A.APPORT_GENERATED_UNIT_MODE)
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._write(A.APPORT_GENERATED_UNIT, self.GENERATED_BYTES, A.APPORT_GENERATED_UNIT_MODE)

        for missing in sorted(A.APPORT_GENERATED_LINKS):
            self._remove(missing)
            self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
            self._link(A.APPORT_GENERATED_LINKS[missing], missing)

        self._link("../apport.service", "/run/systemd/generator.late/rescue.target.wants/apport.service")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)

    def test_d17_mask_empty_aux_and_unknown(self):
        self._link("/dev/null", "/etc/systemd/system/apport.service")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_NO_CONFLICT)
        self._remove("/etc/systemd/system/apport.service")

        self._install_aux(coredump=False, raw_prefix="/usr/lib")
        self._link("/dev/null", "/etc/systemd/system/apport.service")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)
        self._write("/etc/systemd/system/apport-extra.service", b"apport extra\n")
        self.assertEqual(self.detect()[0], A.RUNTIME_WRITER_UNDETERMINED)


R18_ADDED_FIXTURES = (
    "S086: P2R CONFLICT по APPORT-SYSV-SUID-DUMPABLE-V1 (проверенный init-script, исполняемый агент, не container, не masked, валидная SysV start-ссылка, /etc/default/apport отсутствует или имеет известные bytes) -> ABORTED_PRECONDITION_CONFLICT до мутации одинаково в APPLY и dry-run; mutation_performed=false; вклад в RC ненулевой.",
    "S087: P2R UNDETERMINED (неизвестные bytes или необычный объект init-script, нечитаемый /proc/1/environ, override/drop-in/native unit, нет валидной start-ссылки, неизвестные bytes default) -> ABORTED_PRECONDITION_OTHER с reason=runtime-writer:undetermined:<шаг>[:<detail>] одинаково в APPLY и dry-run; mutation_performed=false; вклад в RC ненулевой.",
    "S088: P2R NO_CONFLICT (init-script отсутствует, агент отсутствует, висячий или неисполняемый, container, masked в /etc или /run) -> контроль продолжает обычное планирование; для прочих sysctl-ключей P2R не выполняется.",
    "S089: отказ P3_PRIVILEGE предшествует P2R: detector не вызывается, reason=privilege:write-unavailable.",
    "S090: R3 разрешает символьные ссылки как test -x; цикл ссылок или иная ошибка разрешения -> UNDETERMINED.",
    "S091: R7 учитывает только символьные ссылки S??apport, разрешающиеся ровно в проверенный /etc/init.d/apport; иной объект, иная цель или ошибка разрешения -> UNDETERMINED; отсутствие валидных ссылок -> UNDETERMINED.",
    "S092: отказ detector (исключение или недопустимый результат) -> ABORTED_PRECONDITION_OTHER, reason=runtime-writer:undetermined:detector-failure, мутаций нет.",
    "S093: CONFLICT и UNDETERMINED никогда не дают PASS, NOT_APPLICABLE или APPLIED; generic adapter не изменяет ни одного пути Apport, systemd или SysV.",
    "S094: R5/R6 проверяют unit-объекты в порядке приоритета /etc затем /run; symlink на /dev/null -> masked, любой иной объект, drop-in или native unit -> UNDETERMINED; R9: /etc/default/apport с неизвестными bytes или не обычный файл -> UNDETERMINED.",
)
R18_FIXTURE_EXECUTION_MAP = {
    89: ("test_p2r_R8_conflict_known_default_and_absent_default", "test_p2r_conflict_aborts_before_mutation_with_dry_run_parity"),
    90: ("test_p2r_R1_R2_init_script", "test_p2r_R4_container_and_unreadable_environ", "test_p2r_undetermined_aborts_other_with_dry_run_parity"),
    91: ("test_p2r_R3_agent_follows_symlink_like_test_x", "test_p2r_R5_mask_in_etc_and_run", "test_p2r_no_conflict_continues_normal_planning", "test_p2r_other_keys_never_run_detector"),
    92: ("test_p2r_runs_after_p3_privilege",),
    93: ("test_p2r_R3_agent_follows_symlink_like_test_x", "test_p2r_R3_resolution_error_is_undetermined"),
    94: ("test_p2r_R7_start_links",),
    95: ("test_p2r_detector_failure_is_fail_closed",),
    96: ("test_p2r_conflict_aborts_before_mutation_with_dry_run_parity",),
    97: ("test_p2r_R6_overrides_are_undetermined", "test_p2r_R9_unknown_default_bytes"),
}



R19_D17_ADDED_FIXTURES = ('S095: D17 census: unrelated dangling non-marker symlink with strict-resolution ENOENT is ignored and census continues.', 'S096: D17 census: unrelated symlink strict-resolution EACCES/ELOOP or other non-ENOENT failure -> UNDETERMINED.', 'S097: D17 census: generic regular unit filename whose complete file bytes contain ASCII case-insensitive marker apport becomes a hit.', 'S098: D17 census: ASCII marker matching is case-insensitive with A-Z folding only; uppercase/lowercase marker forms are equivalent.', 'S099: D17 census: D-Bus regular-file marker hit in an exact D-Bus root -> UNDETERMINED unless explicitly allowlisted.', 'S100: D17 census: marker-bearing character/block device, FIFO, socket or unsupported special object -> UNDETERMINED and the object is never opened/read.', 'S101: D17 census: marker symlink with raw target exactly /dev/null is accepted only as the exact mask topology and /dev/null is never opened/read.', 'S102: D17 census: marker symlink resolving to any other special object -> UNDETERMINED.', 'S103: D17 census: /lib/systemd/system and /usr/lib/systemd/system both exist but stat-following-symlink yields different st_dev+st_ino -> UNDETERMINED.', 'S104: D17 auxiliary: exact AUX-BASE-V1 is accepted only as auxiliary evidence and is never by itself positive NO_CONFLICT evidence.', 'S105: D17 auxiliary: exact AUX-COREDUMP-V1 is accepted only as auxiliary evidence and is never by itself positive NO_CONFLICT evidence.', 'S106: D17 auxiliary: one changed byte/SHA in an exact auxiliary regular object -> UNDETERMINED.', 'S107: D17 auxiliary: one missing member of an otherwise known auxiliary profile -> UNDETERMINED.', 'S108: D17 auxiliary: extra Apport auxiliary unit/object or D-Bus hit outside the exact profile -> UNDETERMINED.', 'S109: D17 auxiliary: Ubuntu22 /lib raw activation-link targets that strictly resolve to the exact /usr/lib objects are accepted under merged-/usr identity.', 'S110: D17 auxiliary: Ubuntu24 /usr/lib raw activation-link targets that strictly resolve to the exact regular objects are accepted.', 'S111: D17 native: real Ubuntu24 topology AUX-COREDUMP-V1 + exact N1+N2 + exact executable agent SHA -> CONFLICT.', 'S112: D17 native: the same exact Ubuntu24 topology in dry-run yields the same ABORTED_PRECONDITION_CONFLICT with mutation_performed=false and no target mutation.', 'S113: D17 native: exact native path with unknown N1 SHA -> UNDETERMINED.', 'S114: D17 native: N1 present but required exact native wants N2 missing -> UNDETERMINED.', 'S115: D17 native: exact regular executable agent with required SHA under exact native topology -> CONFLICT.', 'S116: D17 native: regular non-executable agent -> candidate NO_CONFLICT; with non-empty auxiliary profile final result -> UNDETERMINED.', 'S117: D17 native: agent symlink dangling/ENOENT -> candidate NO_CONFLICT; with non-empty auxiliary profile final result -> UNDETERMINED.', 'S118: D17 native: resolvable agent symlink -> UNDETERMINED even when target bytes would otherwise match.', 'S119: D17 native: regular executable agent with SHA mismatch -> UNDETERMINED.', 'S120: D17 native: exact native topology plus direct container evidence and non-empty auxiliary profile -> UNDETERMINED.', 'S121: D17 bridge: real Ubuntu22 AUX-BASE-V1 + exact G1+G2+G3 -> DELEGATE_SYSV before D16.', 'S122: D17 bridge: exact generated bridge plus existing valid D16 SysV conflict fixture -> final CONFLICT with D16 conflict semantics preserved.', 'S123: D17 bridge: exact generated bridge plus D16 UNDETERMINED -> final UNDETERMINED.', 'S124: D17 bridge: exact generated bridge plus D16 NO_CONFLICT while AUX-BASE-V1 is present -> final UNDETERMINED.', 'S125: D17 bridge: changed generated G1 byte/SHA or metadata -> UNDETERMINED.', 'S126: D17 bridge: either required generator wants link missing -> UNDETERMINED.', 'S127: D17 bridge: extra primary apport.service generator link/object -> UNDETERMINED.', 'S128: D17 mask: exact /dev/null mask with empty auxiliary profile and no unknown hits -> NO_CONFLICT.', 'S129: D17 mask: exact /dev/null mask with AUX-BASE-V1 or AUX-COREDUMP-V1 -> UNDETERMINED.', 'S130: D17 mask: exact mask plus unknown/additional Apport object -> UNDETERMINED.', 'S131: D17 sensitivity: bypassing/removing D17 causes the real Ubuntu24 native fixture to cease producing ABORTED_PRECONDITION_CONFLICT.', 'S132: D17 sensitivity: real Ubuntu22 generated bridge continues to enter D16 and preserves the accepted D16 CONFLICT behavior.')
R19_D17_FIXTURE_EXECUTION_MAP = {98: ('test_d17_census_dangling_marker_case_and_dbus',), 99: ('test_d17_census_dangling_marker_case_and_dbus',), 100: ('test_d17_census_dangling_marker_case_and_dbus',), 101: ('test_d17_census_dangling_marker_case_and_dbus',), 102: ('test_d17_census_dangling_marker_case_and_dbus',), 103: ('test_d17_census_special_and_alias_fail_closed',), 104: ('test_d17_mask_empty_aux_and_unknown',), 105: ('test_d17_census_special_and_alias_fail_closed',), 106: ('test_d17_census_special_and_alias_fail_closed',), 107: ('test_d17_aux_profiles_exact_changed_missing_extra_and_raw_targets',), 108: ('test_d17_aux_profiles_exact_changed_missing_extra_and_raw_targets',), 109: ('test_d17_aux_profiles_exact_changed_missing_extra_and_raw_targets',), 110: ('test_d17_aux_profiles_exact_changed_missing_extra_and_raw_targets',), 111: ('test_d17_aux_profiles_exact_changed_missing_extra_and_raw_targets',), 112: ('test_d17_aux_profiles_exact_changed_missing_extra_and_raw_targets',), 113: ('test_d17_aux_profiles_exact_changed_missing_extra_and_raw_targets',), 114: ('test_d17_native_exact_dry_run_and_sensitivity',), 115: ('test_d17_native_exact_dry_run_and_sensitivity',), 116: ('test_d17_native_unknown_missing_and_agent_variants',), 117: ('test_d17_native_unknown_missing_and_agent_variants',), 118: ('test_d17_native_exact_dry_run_and_sensitivity',), 119: ('test_d17_native_unknown_missing_and_agent_variants',), 120: ('test_d17_native_unknown_missing_and_agent_variants',), 121: ('test_d17_native_unknown_missing_and_agent_variants',), 122: ('test_d17_native_unknown_missing_and_agent_variants',), 123: ('test_d17_native_container_with_aux_is_undetermined',), 124: ('test_d17_bridge_delegates_and_preserves_d16',), 125: ('test_d17_bridge_delegates_and_preserves_d16',), 126: ('test_d17_bridge_delegates_and_preserves_d16',), 127: ('test_d17_bridge_delegates_and_preserves_d16',), 128: ('test_d17_bridge_changed_missing_extra_fail_closed',), 129: ('test_d17_bridge_changed_missing_extra_fail_closed',), 130: ('test_d17_bridge_changed_missing_extra_fail_closed',), 131: ('test_d17_mask_empty_aux_and_unknown',), 132: ('test_d17_mask_empty_aux_and_unknown',), 133: ('test_d17_mask_empty_aux_and_unknown',), 134: ('test_d17_native_exact_dry_run_and_sensitivity',), 135: ('test_d17_bridge_delegates_and_preserves_d16',)}

R20_D17_REV5_ADDED_FIXTURES = ('S133: D17 REV5: exact Ubuntu26 topology AUX-COREDUMP-V1 + N1+N2 + U26_AGENT_V1 -> CONFLICT.', 'S134: D17 REV5: тот же exact Ubuntu26 fixture в dry-run -> тот же ABORTED_PRECONDITION_CONFLICT, mutation_performed=false, целевые объекты не изменяются.', 'S135: D17 REV5: exact Ubuntu26 topology с однобайтно изменённым agent относительно U26_AGENT_V1 -> UNDETERMINED.', 'S136: D17 REV5: exact Ubuntu26 topology с произвольным третьим agent SHA -> UNDETERMINED.', 'S137: D17 REV5 regression: exact Ubuntu24 native fixture с U24_AGENT_V1 остаётся CONFLICT.', 'S138: D17 REV5 regression: exact Ubuntu22 generated bridge остаётся DELEGATE_SYSV и сохраняет H46-D16 semantics.', 'S139: D17 REV5 sensitivity: удаление U26_AGENT_V1 из finite accepted set при неизменном exact Ubuntu26 fixture меняет CONFLICT на UNDETERMINED.', 'S140: D17 REV5 static evidence: в exact U26_AGENT_V1 ветки options.systemd_coredump_instance и options.stop завершаются до options.start; start_apport содержит ordered write fs/suid_dumpable=2.')
R20_D17_REV5_FIXTURE_EXECUTION_MAP = {136: ('test_d17_u26_native_exact_dry_run_and_sensitivity',), 137: ('test_d17_u26_native_exact_dry_run_and_sensitivity',), 138: ('test_d17_u26_unknown_agent_variants',), 139: ('test_d17_u26_unknown_agent_variants',), 140: ('test_d17_native_exact_dry_run_and_sensitivity',), 141: ('test_d17_bridge_delegates_and_preserves_d16',), 142: ('test_d17_u26_native_exact_dry_run_and_sensitivity',), 143: ('test_d17_u26_static_agent_ordering',)}
R21_D19_ADDED_FIXTURES = (
    "S141: proven service-managed P2R CONFLICT -> ABORTED_PRECONDITION_CONFLICT без mutation и с exact operator_decision {class=SERVICE_MANAGED_PARAMETER,required=true,service,parameter,current_value}; APPLY и dry-run сохраняют одинаковую классификацию.",
    "S142: UNDETERMINED, обычный source conflict и normal planning не получают operator_decision; service-managed терминальное предупреждение не должно возникать без доказанного mapped service conflict.",
)
R21_D19_FIXTURE_EXECUTION_MAP = {
    144: ("test_p2r_conflict_aborts_before_mutation_with_dry_run_parity", "test_d17_native_exact_dry_run_and_sensitivity"),
    145: ("test_p2r_service_managed_operator_decision_has_no_false_positive", "test_late_source_conflict_aborts"),
}

# Required negative fixtures of the config-line-with-runtime-v1 mechanism.
# Moved from the authority document, which carries only fields read by code.
# The list changes only by explicit decision.
REQUIRED_NEGATIVE_FIXTURES = (
    'runtime-ключ отсутствует и собственного файла нет -> NOT_APPLICABLE_KEY_ABSENT, мутаций нет',
    'runtime-ключ отсутствует, а собственный файл существует -> NOT_APPLICABLE_KEY_ABSENT, существующий файл не изменяется и не удаляется',
    'конфликтующее присвоение в /etc/sysctl.conf',
    'конфликтующее присвоение в файле с лексикографически более поздним именем',
    'конфликт в файле, скрытом одноимённым файлом более высокого приоритета — не конфликт',
    'нечитаемый каталог или учитываемый источник -> ABORT',
    'неоднозначное или нечисловое effective foreign assignment для ge -> ABORT',
    'неудача runtime-фазы в ветке both с успешной persistent-компенсацией',
    'неудача runtime-фазы в ветке both с неудачной persistent-компенсацией',
    'ge: runtime_before выше expected, собственного persistent нет -> runtime не понижается; persistent может быть создан для сохранения target_value',
    'ge: эффективный ранний чужой источник задаёт значение выше expected/runtime -> target_value сохраняет это effective foreign value',
    'ge: собственный persistent value выше runtime_before -> runtime поднимается до target_value; persistent не понижается',
    'persistent-only: после записи runtime перестал соответствовать target_value -> persistent компенсируется, runtime автоматически не записывается',
    'нечисловое runtime-значение -> ABORT',
    'persistent exact bytes совпадают, но uid/gid/mode не root:root/0644 -> persistent требует исправления',
    'повторное применение при runtime+persistent соответствии одному target_value -> изменений нет',
    'собственный файл предыдущего применения — не конфликт P2',
    'dry-run: target_value и выбранная would-be ветка совпадают с APPLY при том же prestate; written_value=null, runtime/persistent не меняются',
    'dry-run: NOT_APPLICABLE_KEY_ABSENT и precondition ABORT не выполняют мутаций и дают nonzero contribution по batch RC',
    'phase1: отказ после rename на fsync каталога -> восстановление прежних bytes+uid+gid+mode либо удаление созданного target, NOT_COMMITTED',
    'phase1: отказ post-rename проверки target -> та же persistent compensation',
    'compensation: существующий файл с нестандартными прежними uid/gid/mode после отказа восстанавливается именно к прежним bytes+uid+gid+mode',
    'ge: внешняя гонка после runtime_prewrite и до write обозначена как ограничение atomicity, не как доказанная no-lowering гарантия',
    'eq: собственный файл с неразбираемым содержимым не вызывает ABORT сам по себе; он считается non-compliant и заменяется canonical bytes expected при APPLY',
    'batch RC: нулевой вклад дают APPLIED, ALREADY_COMPLIANT и NOT_ELIGIBLE_APPLY_UNSUPPORTED; NOT_APPLICABLE_KEY_ABSENT и ABORTED_*/FAILED_* дают nonzero contribution',
    'ge: runtime_prewrite вырос выше target_value после persistent-мутации -> запись пропускается, понижения нет, persistent коммитится, исход APPLIED, вклад в RC 0',
    'ge: runtime_prewrite выше target_value без persistent-мутации -> мутаций нет, исход ALREADY_COMPLIANT, вклад в RC 0',
    'eq: runtime_prewrite == target_value в ветке runtime_only -> запись пропускается, мутаций нет, исход ALREADY_COMPLIANT',
    'ABORT по P2 при существующем собственном файле -> файл не изменяется и не удаляется, его состояние зафиксировано в отчёте',
    'prewrite в ветке both: чтение runtime дало ошибку, ключ исчез либо значение нечисловое -> persistent компенсируется, исход FAILED_NOT_COMMITTED',
    'prewrite в ветке both: та же ошибка и неудачная компенсация -> FAILED_COMPENSATION с фактическим состоянием',
    'prewrite в ветке runtime_only: та же ошибка -> FAILED_NOT_COMMITTED, mutation_performed=false, persistent не изменяется',
    'prestate фиксировал отсутствие target, но перед rename файл появился -> ABORT без rename, чужой файл не затирается',
    'существующий target изменён другим процессом между снятием prestate и rename -> ABORT без rename, устаревший prestate не восстанавливается',
    'на месте target символьная ссылка -> ABORT до мутации, ссылка не изменяется',
    'на месте target обычный файл с st_nlink>1 -> ABORT до мутации',
    'на месте target каталог, устройство, FIFO или сокет -> ABORT до мутации',
    'контроль с apply.supported=false -> NOT_ELIGIBLE_APPLY_UNSUPPORTED, мутаций нет, вклад в RC 0',
    'отчёт содержит actions_attempted, step_rc, mutation_performed и transaction_commit для каждого исхода, включая ABORT и FAILED_*',
    'контроль с apply.supported=false в dry-run и в APPLY -> NOT_ELIGIBLE_APPLY_UNSUPPORTED до любых чтений; runtime и persistent не наблюдаются',
    'st_nlink target вырос с 1 до 2 между snapshot и проверкой перед rename -> ABORT без rename',
    'target подменён другим процессом после нашей записи, компенсация обязана сработать -> проверка принадлежности не совпала, чужой объект не затирается, исход FAILED_COMPENSATION',
    'target отсутствовал до попытки, но на его месте оказался чужой объект к моменту компенсации -> удаление не выполняется, исход FAILED_COMPENSATION',
    'target заменён между успешным primary rename и компенсацией -> сверка с attempt_written_identity не совпала, чужой объект не затирается, исход FAILED_COMPENSATION',
    'созданный попыткой target заменён чужим объектом перед компенсационным unlink -> удаление не выполняется, исход FAILED_COMPENSATION',
    'attempt_written_identity фиксируется после primary rename и присутствует в отчёте попытки, завершившейся компенсацией',
    'отказ fsync каталога сразу после rename -> attempt_written_identity уже существует, компенсация выполняется по нему',
    'отказ сверки target с prepared_identity после rename -> компенсация выполняется по тому же снимку',
    'persistent rename не выполнялся -> attempt_written_identity в отчёте равен null',
    'компенсация на ветви восстановления существовавшего файла: target подменён чужим объектом между входной сверкой и компенсационным rename -> вторая сверка с attempt_written_identity не совпала, чужой объект не перезаписывается, prestate не восстанавливается, исход FAILED_COMPENSATION с фактическим состоянием',
    'собственный файл существует на этапе P2 и затеняет одноимённый чужой источник с большим значением, но исчезает между P2 и снимком целевого объекта -> ABORT без мутации; запрещено считать target_value без затенённого чужого значения и создавать файл с меньшим значением',
    'ветка runtime_only без предшествующей persistent-мутации: отказ записи runtime до передачи первого байта (например отказ открытия пути) -> mutation_performed=false И written_value=null; runtime_after фиксируется фактическим. Случай той же ошибки после выполненной persistent-мутации описан отдельной фикстурой и даёт mutation_performed=true.',
    'отказ компенсации после отказа post-rename -> отчёт содержит и код исходного отказа, и собственный код отказа компенсации, и фактическое состояние target',
    'ветка both: persistent-мутация выполнена и затем компенсирована, а runtime-запись отказала до передачи первого байта -> mutation_performed=true (из-за persistent-мутации), written_value=null (запись не начиналась), исход FAILED_NOT_COMMITTED',
    'S006: P1: initial runtime read returns an access/read error while the key is not proven absent -> ABORTED_PRECONDITION_OTHER, no persistent/runtime mutation, written_value=null.',
    'S010: Persistent target prestate cannot be read/snapshotted while P1/P2 succeeded -> ABORTED_PRECONDITION_OTHER before mutation; unreadable is not treated as absent.',
    'S012: op=ge and existing own persistent file cannot be unambiguously parsed as one integer assignment for the key -> ABORTED_PRECONDITION_OTHER before mutation; own file is not overwritten.',
    'S017: Own persistent file is absent during P2, so a same-basename file in a lower-priority sysctl.d directory is not shadowed and participates in effective precedence.',
    'S021: A foreign .conf source that is a symbolic link to a readable regular file is read through the link and participates in P2 according to its logical source path.',
    'S022: A foreign .conf source that resolves to /dev/null is treated as an empty source and does not cause ABORT.',
    'S024: For ge, only the final effective applicable assignment is parsed for effective_foreign_value: an earlier invalid assignment overridden by a later valid assignment does not itself cause ABORT.',
    'S025: P3 write privilege/access failure after successful read-only planning -> ABORTED_PRECONDITION_OTHER before any target mutation.',
    'S033: Straight-line both branch: persistent mutation succeeds, runtime write succeeds and both final checks pass -> APPLIED, mutation_performed=true, written_value=target_value, COMMITTED.',
    'S035: Opposite observation-binding race to fixture 51: own file is absent during P2 but appears before the bound persistent prestate is established -> ABORTED_PRECONDITION_OTHER without mutation; mixed-time planning is forbidden.',
    'S039: Phase1 failure before primary rename -> FAILED_NOT_COMMITTED, mutation_performed=false, attempt_written_identity=null; target remains at prestate and temporary object is cleaned.',
    'S051: runtime_only: runtime write starts (at least one byte/value is actually passed) and then fails -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value; persistent is not compensated.',
    'S052: both: persistent mutation succeeded, runtime write starts and then fails -> persistent compensation is attempted; with successful compensation outcome FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.',
    'S053A: runtime_only: runtime write completes but immediate runtime-phase post-check read fails -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value; no persistent compensation.',
    'S054: runtime_only: runtime write completes, immediate runtime-phase post-check reads a noncompliant value -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.',
    'S057: persistent_only: final runtime check is noncompliant and required persistent compensation fails -> FAILED_COMPENSATION, mutation_performed=true, written_value=null.',
    'S058: runtime_only: runtime phase succeeds but final persistent check is noncompliant/drifted -> FAILED_NOT_COMMITTED without persistent compensation; mutation_performed=true and written_value=target_value.',
    'S059A: both: runtime phase immediate post-check passes, then FINAL runtime check becomes noncompliant; persistent compensation succeeds -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.',
    'S059B: both: runtime phase immediate post-check passes, then FINAL runtime check becomes noncompliant; persistent compensation fails -> FAILED_COMPENSATION, mutation_performed=true, written_value=target_value.',
    'S060B: both: runtime phase succeeds; FINAL persistent read/snapshot fails while the written target object itself remains unchanged; persistent compensation succeeds -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value.',
    'S060C: both: same unchanged-object FINAL persistent read/snapshot failure, but persistent compensation fails -> FAILED_COMPENSATION, mutation_performed=true, written_value=target_value.',
    'S072: Reporting bootstrap refusal before control execution still leaves report.json written with the refusal/crash fact; failure to initialize a sibling log does not erase the report.',
    'S073: Batch with a terminal nonzero-contributing control result continues to the next control; report contains both controls and overall RC remains nonzero.',
    'S075: branch already/no prior mutation: FINAL runtime read fails -> FAILED_NOT_COMMITTED, reason=runtime:final-read-failure, runtime_after=null, mutation_performed=false, written_value=null; read failure is not reported as runtime-noncompliant.',
    'S076: branch already/no prior mutation: FINAL runtime returns a non-integer -> FAILED_NOT_COMMITTED, reason=runtime:final-parse-failure, runtime_after=null, mutation_performed=false, written_value=null.',
    'S077: runtime_only after a successful runtime write: FINAL runtime read fails -> FAILED_NOT_COMMITTED without persistent compensation; mutation_performed=true, written_value=target_value, reason=runtime:final-read-failure.',
    'S078: runtime_only after a successful runtime write: FINAL runtime is non-integer -> FAILED_NOT_COMMITTED without persistent compensation; mutation_performed=true, written_value=target_value, reason=runtime:final-parse-failure.',
    'S079: both after persistent mutation and successful runtime phase: FINAL runtime read fails; persistent compensation succeeds -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value, original reason runtime:final-read-failure retained.',
    'S080: same FINAL runtime read failure in both, but persistent compensation fails -> FAILED_COMPENSATION containing both runtime:final-read-failure and exact compensation code; mutation_performed=true, written_value=target_value.',
    'S081: both after persistent mutation and successful runtime phase: FINAL runtime parse fails; persistent compensation succeeds -> FAILED_NOT_COMMITTED, mutation_performed=true, written_value=target_value, original reason runtime:final-parse-failure retained.',
    'S082: same FINAL runtime parse failure in both, but persistent compensation fails -> FAILED_COMPENSATION containing both runtime:final-parse-failure and exact compensation code; mutation_performed=true, written_value=target_value.',
    'S083: runtime_only with no persistent mutation: FINAL persistent snapshot/read fails after successful runtime write -> FAILED_NOT_COMMITTED, reason=persistent:final-read-failure, no persistent compensation, mutation_performed=true, written_value=target_value; the observation failure is not reported as persistent-noncompliant.',
    'S084: already-compliant branch with no mutation: FINAL persistent snapshot/read fails -> FAILED_NOT_COMMITTED, reason=persistent:final-read-failure, no compensation, mutation_performed=false, written_value=null.',
    'S085: an injected runtime writer without SLP_RUNTIME_WRITER_V1 declaration is rejected after P0 but before P1 and before invocation -> ABORTED_PRECONDITION_OTHER, reason=runtime:writer-protocol-required, mutation_performed=false, written_value=null; state is not guessed from runtime_after. Declared V1 writer failures are governed by existing before-first-byte/started-write fixtures.',
    'S086: P2R CONFLICT по APPORT-SYSV-SUID-DUMPABLE-V1 (проверенный init-script, исполняемый агент, не container, не masked, валидная SysV start-ссылка, /etc/default/apport отсутствует или имеет известные bytes) -> ABORTED_PRECONDITION_CONFLICT до мутации одинаково в APPLY и dry-run; mutation_performed=false; вклад в RC ненулевой.',
    'S087: P2R UNDETERMINED (неизвестные bytes или необычный объект init-script, нечитаемый /proc/1/environ, override/drop-in/native unit, нет валидной start-ссылки, неизвестные bytes default) -> ABORTED_PRECONDITION_OTHER с reason=runtime-writer:undetermined:<шаг>[:<detail>] одинаково в APPLY и dry-run; mutation_performed=false; вклад в RC ненулевой.',
    'S088: P2R NO_CONFLICT (init-script отсутствует, агент отсутствует, висячий или неисполняемый, container, masked в /etc или /run) -> контроль продолжает обычное планирование; для прочих sysctl-ключей P2R не выполняется.',
    'S089: отказ P3_PRIVILEGE предшествует P2R: detector не вызывается, reason=privilege:write-unavailable.',
    'S090: R3 разрешает символьные ссылки как test -x; цикл ссылок или иная ошибка разрешения -> UNDETERMINED.',
    'S091: R7 учитывает только символьные ссылки S??apport, разрешающиеся ровно в проверенный /etc/init.d/apport; иной объект, иная цель или ошибка разрешения -> UNDETERMINED; отсутствие валидных ссылок -> UNDETERMINED.',
    'S092: отказ detector (исключение или недопустимый результат) -> ABORTED_PRECONDITION_OTHER, reason=runtime-writer:undetermined:detector-failure, мутаций нет.',
    'S093: CONFLICT и UNDETERMINED никогда не дают PASS, NOT_APPLICABLE или APPLIED; generic adapter не изменяет ни одного пути Apport, systemd или SysV.',
    'S094: R5/R6 проверяют unit-объекты в порядке приоритета /etc затем /run; symlink на /dev/null -> masked, любой иной объект, drop-in или native unit -> UNDETERMINED; R9: /etc/default/apport с неизвестными bytes или не обычный файл -> UNDETERMINED.',
    'S095: D17 census: unrelated dangling non-marker symlink with strict-resolution ENOENT is ignored and census continues.',
    'S096: D17 census: unrelated symlink strict-resolution EACCES/ELOOP or other non-ENOENT failure -> UNDETERMINED.',
    'S097: D17 census: generic regular unit filename whose complete file bytes contain ASCII case-insensitive marker apport becomes a hit.',
    'S098: D17 census: ASCII marker matching is case-insensitive with A-Z folding only; uppercase/lowercase marker forms are equivalent.',
    'S099: D17 census: D-Bus regular-file marker hit in an exact D-Bus root -> UNDETERMINED unless explicitly allowlisted.',
    'S100: D17 census: marker-bearing character/block device, FIFO, socket or unsupported special object -> UNDETERMINED and the object is never opened/read.',
    'S101: D17 census: marker symlink with raw target exactly /dev/null is accepted only as the exact mask topology and /dev/null is never opened/read.',
    'S102: D17 census: marker symlink resolving to any other special object -> UNDETERMINED.',
    'S103: D17 census: /lib/systemd/system and /usr/lib/systemd/system both exist but stat-following-symlink yields different st_dev+st_ino -> UNDETERMINED.',
    'S104: D17 auxiliary: exact AUX-BASE-V1 is accepted only as auxiliary evidence and is never by itself positive NO_CONFLICT evidence.',
    'S105: D17 auxiliary: exact AUX-COREDUMP-V1 is accepted only as auxiliary evidence and is never by itself positive NO_CONFLICT evidence.',
    'S106: D17 auxiliary: one changed byte/SHA in an exact auxiliary regular object -> UNDETERMINED.',
    'S107: D17 auxiliary: one missing member of an otherwise known auxiliary profile -> UNDETERMINED.',
    'S108: D17 auxiliary: extra Apport auxiliary unit/object or D-Bus hit outside the exact profile -> UNDETERMINED.',
    'S109: D17 auxiliary: Ubuntu22 /lib raw activation-link targets that strictly resolve to the exact /usr/lib objects are accepted under merged-/usr identity.',
    'S110: D17 auxiliary: Ubuntu24 /usr/lib raw activation-link targets that strictly resolve to the exact regular objects are accepted.',
    'S111: D17 native: real Ubuntu24 topology AUX-COREDUMP-V1 + exact N1+N2 + exact executable agent SHA -> CONFLICT.',
    'S112: D17 native: the same exact Ubuntu24 topology in dry-run yields the same ABORTED_PRECONDITION_CONFLICT with mutation_performed=false and no target mutation.',
    'S113: D17 native: exact native path with unknown N1 SHA -> UNDETERMINED.',
    'S114: D17 native: N1 present but required exact native wants N2 missing -> UNDETERMINED.',
    'S115: D17 native: exact regular executable agent with required SHA under exact native topology -> CONFLICT.',
    'S116: D17 native: regular non-executable agent -> candidate NO_CONFLICT; with non-empty auxiliary profile final result -> UNDETERMINED.',
    'S117: D17 native: agent symlink dangling/ENOENT -> candidate NO_CONFLICT; with non-empty auxiliary profile final result -> UNDETERMINED.',
    'S118: D17 native: resolvable agent symlink -> UNDETERMINED even when target bytes would otherwise match.',
    'S119: D17 native: regular executable agent with SHA mismatch -> UNDETERMINED.',
    'S120: D17 native: exact native topology plus direct container evidence and non-empty auxiliary profile -> UNDETERMINED.',
    'S121: D17 bridge: real Ubuntu22 AUX-BASE-V1 + exact G1+G2+G3 -> DELEGATE_SYSV before D16.',
    'S122: D17 bridge: exact generated bridge plus existing valid D16 SysV conflict fixture -> final CONFLICT with D16 conflict semantics preserved.',
    'S123: D17 bridge: exact generated bridge plus D16 UNDETERMINED -> final UNDETERMINED.',
    'S124: D17 bridge: exact generated bridge plus D16 NO_CONFLICT while AUX-BASE-V1 is present -> final UNDETERMINED.',
    'S125: D17 bridge: changed generated G1 byte/SHA or metadata -> UNDETERMINED.',
    'S126: D17 bridge: either required generator wants link missing -> UNDETERMINED.',
    'S127: D17 bridge: extra primary apport.service generator link/object -> UNDETERMINED.',
    'S128: D17 mask: exact /dev/null mask with empty auxiliary profile and no unknown hits -> NO_CONFLICT.',
    'S129: D17 mask: exact /dev/null mask with AUX-BASE-V1 or AUX-COREDUMP-V1 -> UNDETERMINED.',
    'S130: D17 mask: exact mask plus unknown/additional Apport object -> UNDETERMINED.',
    'S131: D17 sensitivity: bypassing/removing D17 causes the real Ubuntu24 native fixture to cease producing ABORTED_PRECONDITION_CONFLICT.',
    'S132: D17 sensitivity: real Ubuntu22 generated bridge continues to enter D16 and preserves the accepted D16 CONFLICT behavior.',
    'S133: D17 REV5: exact Ubuntu26 topology AUX-COREDUMP-V1 + N1+N2 + U26_AGENT_V1 -> CONFLICT.',
    'S134: D17 REV5: тот же exact Ubuntu26 fixture в dry-run -> тот же ABORTED_PRECONDITION_CONFLICT, mutation_performed=false, целевые объекты не изменяются.',
    'S135: D17 REV5: exact Ubuntu26 topology с однобайтно изменённым agent относительно U26_AGENT_V1 -> UNDETERMINED.',
    'S136: D17 REV5: exact Ubuntu26 topology с произвольным третьим agent SHA -> UNDETERMINED.',
    'S137: D17 REV5 regression: exact Ubuntu24 native fixture с U24_AGENT_V1 остаётся CONFLICT.',
    'S138: D17 REV5 regression: exact Ubuntu22 generated bridge остаётся DELEGATE_SYSV и сохраняет H46-D16 semantics.',
    'S139: D17 REV5 sensitivity: удаление U26_AGENT_V1 из finite accepted set при неизменном exact Ubuntu26 fixture меняет CONFLICT на UNDETERMINED.',
    'S140: D17 REV5 static evidence: в exact U26_AGENT_V1 ветки options.systemd_coredump_instance и options.stop завершаются до options.start; start_apport содержит ordered write fs/suid_dumpable=2.',
    'S141: proven service-managed P2R CONFLICT -> ABORTED_PRECONDITION_CONFLICT без mutation и с exact operator_decision {class=SERVICE_MANAGED_PARAMETER,required=true,service,parameter,current_value}; APPLY и dry-run сохраняют одинаковую классификацию.',
    'S142: UNDETERMINED, обычный source conflict и normal planning не получают operator_decision; service-managed терминальное предупреждение не должно возникать без доказанного mapped service conflict.',
)

class R21RuntimeWriterFixtureCoverage(unittest.TestCase):
    def test_r21_contract_fixture_list_extends_r20(self):
        self.assertEqual(len(REQUIRED_NEGATIVE_FIXTURES), 145)
        self.assertEqual(REQUIRED_NEGATIVE_FIXTURES[:88], R16_REQUIRED_FIXTURES)
        self.assertEqual(REQUIRED_NEGATIVE_FIXTURES[88:97], R18_ADDED_FIXTURES)
        self.assertEqual(REQUIRED_NEGATIVE_FIXTURES[97:135], R19_D17_ADDED_FIXTURES)
        self.assertEqual(REQUIRED_NEGATIVE_FIXTURES[135:143], R20_D17_REV5_ADDED_FIXTURES)
        self.assertEqual(REQUIRED_NEGATIVE_FIXTURES[143:], R21_D19_ADDED_FIXTURES)
        self.assertEqual(set(R18_FIXTURE_EXECUTION_MAP), set(range(89, 98)))
        self.assertEqual(set(R19_D17_FIXTURE_EXECUTION_MAP), set(range(98, 136)))
        self.assertEqual(set(R20_D17_REV5_FIXTURE_EXECUTION_MAP), set(range(136, 144)))
        self.assertEqual(set(R21_D19_FIXTURE_EXECUTION_MAP), {144, 145})

    def test_r18_fixture_execution_matrix_preserved(self):
        for fixture_no, tests in R18_FIXTURE_EXECUTION_MAP.items():
            self.assertTrue(tests, fixture_no)
            for test_name in tests:
                lines, functions = _run_named_test_with_adapter_trace(test_name)
                self.assertTrue(lines, (fixture_no, test_name, functions))

    def test_r19_d17_fixture_execution_matrix(self):
        for fixture_no, tests in R19_D17_FIXTURE_EXECUTION_MAP.items():
            self.assertTrue(tests, fixture_no)
            for test_name in tests:
                case = RuntimeWriterConflictD17(test_name)
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.errors, [], (fixture_no, test_name, result.errors))
                self.assertEqual(result.failures, [], (fixture_no, test_name, result.failures))

    def test_r20_d17_rev5_fixture_execution_matrix(self):
        for fixture_no, tests in R20_D17_REV5_FIXTURE_EXECUTION_MAP.items():
            self.assertTrue(tests, fixture_no)
            for test_name in tests:
                case = RuntimeWriterConflictD17(test_name)
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.errors, [], (fixture_no, test_name, result.errors))
                self.assertEqual(result.failures, [], (fixture_no, test_name, result.failures))

    def test_r21_d19_fixture_execution_matrix(self):
        for fixture_no, tests in R21_D19_FIXTURE_EXECUTION_MAP.items():
            self.assertTrue(tests, fixture_no)
            for test_name in tests:
                cls = _find_test_case_class(test_name)
                case = cls(test_name)
                result = unittest.TestResult()
                case.run(result)
                self.assertEqual(result.errors, [], (fixture_no, test_name, result.errors))
                self.assertEqual(result.failures, [], (fixture_no, test_name, result.failures))


class SourceDirectoryScanError(unittest.TestCase):
    """Ошибка os.scandir каталога sysctl-источников — отказ до записи."""

    # Помощники берутся у ContractCompletionAdditional без наследования тестов.
    KEY = ContractCompletionAdditional.KEY
    paths = ContractCompletionAdditional.paths
    execute = ContractCompletionAdditional.execute

    def test_sysctl_directory_scan_error_aborts_before_any_write(self):
        with tempfile.TemporaryDirectory() as td:
            sysctl_dir = Path(td) / "etc" / "sysctl.d"
            sysctl_dir.mkdir(parents=True)
            bad = os.path.realpath(sysctl_dir)
            real = os.scandir

            def scandir(path="."):
                if os.path.realpath(os.fspath(path)) == bad:
                    raise PermissionError(errno.EACCES, "injected", bad)
                return real(path)

            writes = []
            state = {"value": 0}
            persistent, _runtime = self.paths(td)
            with mock.patch("os.scandir", scandir):
                r = self.execute(
                    td, state, source_files=None, source_root=td,
                    write_runtime=lambda v: writes.append(v),
                )
            self.assertEqual(r.outcome, A.OUTCOME_ABORT_OTHER)
            self.assertTrue(r.reason.startswith("source:unreadable-directory"), r.reason)
            self.assertFalse(r.mutation_performed)
            self.assertEqual(writes, [])
            self.assertEqual(state["value"], 0)
            self.assertFalse(Path(persistent).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
