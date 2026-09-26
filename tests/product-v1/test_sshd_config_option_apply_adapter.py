#!/usr/bin/env python3
"""Regressions for the sshd-config-option-v1 APPLY mechanism (fstec-configuration-2026 п.9.1, SRC-0088).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
HOST_MUTATION=false

Every case runs on a tree inside a temporary directory passed to the adapter as
`_root`; `sshd -t`, `sshd -T` and `systemctl` are replaced by `_run`. `sshd -T`
is modelled by first-value-wins over the main file and its `Include` targets.
No system path is touched and root is not required.

Решения пользователя (APPLY п.9.1 — требование политики компании, 25.09.2026; правка
на месте без дублирования строк, схема 1–4, 26.09.2026), которые фиксирует этот файл:

* действующая строка ключа меняет значение, закомментированный шаблон заменяется на
  месте, иначе строка добавляется перед первым `Match` или в конец;
* `PasswordAuthentication yes` в `sshd_config.d/50-cloud-init.conf` меняется на `no`;
* ошибка `sshd -t`, перезагрузки или итоговой проверки возвращает прежние байты всех
  изменённых файлов;
* блок «решение администратора» без записи: `Match` с не-`no`, нет пользователя в
  `sudo`/`admin` (PermitRootLogin), нет ключа у такого пользователя или
  нестандартные AuthorizedKeysFile/PubkeyAuthentication (PasswordAuthentication).
"""

from __future__ import annotations

import glob
import importlib.util
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "product/apply-adapters/product-sshd-config-option-apply-v1.py"
CHECK_ADAPTER = ROOT / "product/adapters/product-sshd-config-option-check-v1.py"
CONTROL_DIR = ROOT / "controls/fstec-core/configuration-2026"
BASH = shutil.which("bash")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = load(ADAPTER, "slp_sshd_config_option_apply")
CHECK = load(CHECK_ADAPTER, "slp_sshd_config_option_check_for_apply")
IDS = {key: cid for cid, key in A.CONTROL_KEYS.items()}

STOCK_CONFIG = (
    "# This is the sshd server system-wide configuration file.\n"
    "\n"
    "Include /etc/ssh/sshd_config.d/*.conf\n"
    "\n"
    "#PermitRootLogin prohibit-password\n"
    "#PasswordAuthentication yes\n"
    "#PermitEmptyPasswords no\n"
    "KbdInteractiveAuthentication no\n"
    "UsePAM yes\n"
    "X11Forwarding yes\n"
    "Subsystem sftp /usr/lib/openssh/sftp-server\n"
)
CLOUD_INIT = "PasswordAuthentication yes\n"
BASE_GROUP = "root:x:0:\nsudo:x:27:user\nuser:x:1000:\n"
BASE_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
               "user:x:1000:1000:user:/home/user:/bin/bash\n")
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITEST slp-test\n"
DEFAULTS = {
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "permitrootlogin": "without-password",
    "pubkeyauthentication": "yes",
    "authorizedkeysfile": ".ssh/authorized_keys .ssh/authorized_keys2",
}


class Tree:
    def __init__(self, td, config=STOCK_CONFIG, dropin=CLOUD_INIT, group=BASE_GROUP, key=KEY):
        self.root = Path(td)
        self.cfg = self.root / "etc/ssh/sshd_config"
        (self.root / "etc/ssh/sshd_config.d").mkdir(parents=True)
        self.cfg.write_text(config, encoding="utf-8")
        # Права задаются явно: адаптер отказывает при записи для группы, а umask на ПК часто 0002.
        self.cfg.chmod(0o644)
        self.dropin_path = self.root / "etc/ssh/sshd_config.d/50-cloud-init.conf"
        if dropin is not None:
            self.dropin_path.write_text(dropin, encoding="utf-8")
            self.dropin_path.chmod(0o600)
        (self.root / "etc/group").write_text(group, encoding="utf-8")
        (self.root / "etc/passwd").write_text(BASE_PASSWD, encoding="utf-8")
        if key is not None:
            (self.root / "home/user/.ssh").mkdir(parents=True)
            (self.root / "home/user/.ssh/authorized_keys").write_text(key, encoding="utf-8")
        for rel in ("usr/sbin/sshd", "usr/bin/systemctl"):
            tool = self.root / rel
            tool.parent.mkdir(parents=True, exist_ok=True)
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            tool.chmod(0o755)
        self.calls = []
        self.fail = set()
        self.extra = {}

    def _lines(self, path, depth=0):
        for line in Path(path).read_bytes().decode("utf-8").splitlines():
            parts = re.split(r"[ \t]*=[ \t]*|[ \t]+", line.strip(), maxsplit=1)
            if not parts[0] or parts[0].startswith("#"):
                continue
            value = parts[1].split()[0] if len(parts) == 2 else ""
            if parts[0].lower() == "include":
                for item in sorted(glob.glob(str(self.root) + value)):
                    yield from self._lines(item, depth + 1)
                continue
            yield parts[0].lower(), value

    def run(self, argv, timeout):
        name = os.path.basename(argv[0])
        self.calls.append([name] + list(argv[1:]))
        mode = name if name != "sshd" else "sshd" + argv[1]
        if mode in self.fail:
            return subprocess.CompletedProcess(argv, 1, b"", b"")
        if name == "systemctl":
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv[1] == "-t":
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        values = {}
        for key, value in self._lines(argv[argv.index("-f") + 1]):
            if key == "match":
                break
            values.setdefault(key, value)
        for key, value in DEFAULTS.items():
            values.setdefault(key, value)
        values.update(self.extra)
        if values.get("permitrootlogin") == "prohibit-password":
            values["permitrootlogin"] = "without-password"
        out = "".join("%s %s\n" % item for item in sorted(values.items()))
        return subprocess.CompletedProcess(argv, 0, out.encode("utf-8"), b"")

    def config(self):
        return self.cfg.read_bytes().decode("utf-8")

    def dropin(self):
        return self.dropin_path.read_text(encoding="utf-8")

    def names(self):
        return [c[0] if c[0] != "sshd" else "sshd" + c[1] for c in self.calls]


def execute(tree, key, *, dry_run=False, privileged=True, write=None, control_id=None, expected="no"):
    return A.execute_control(control_id or IDS[key], key, "eq", expected, True, dry_run=dry_run,
                             privilege_check=lambda: privileged, _root=str(tree.root), _run=tree.run, _write=write)


def stock_with(template_key, line):
    return STOCK_CONFIG.replace(next(l for l in STOCK_CONFIG.splitlines(keepends=True)
                                     if l.startswith("#" + template_key)), line)


class Apply(unittest.TestCase):
    def test_control_yaml_matches_adapter_keys(self):
        seen = {}
        for path in sorted(CONTROL_DIR.glob("*.yaml")):
            text = path.read_text(encoding="utf-8")
            if 'kind: "sshd-config-option"' not in text:
                continue
            cid = text.split('id: "', 1)[1].split('"', 1)[0]
            key = text.split('  key: "', 1)[1].split('"', 1)[0]
            self.assertIn('op: "eq"', text)
            self.assertIn('value: "no"', text)
            self.assertIn("supported: true", text)
            seen[cid] = key
        self.assertEqual(seen, A.CONTROL_KEYS)

    def test_template_line_is_replaced_in_place(self):
        # Схема п.2: закомментированный шаблон заменяется на месте, новых строк нет.
        for key in A.CONTROL_KEYS.values():
            with self.subTest(key=key), tempfile.TemporaryDirectory() as td:
                t = Tree(td)
                r = execute(t, key)
                self.assertEqual((r["outcome"], r["mutation_performed"], r["transaction_commit"]),
                                 ("APPLIED", True, "COMMITTED"), r)
                self.assertEqual(t.config(), stock_with(key, key + " no\n"))
                self.assertEqual(t.config().count("\n"), STOCK_CONFIG.count("\n"))
                self.assertEqual(t.cfg.stat().st_mode & 0o777, 0o644)
                self.assertEqual(r["policy_current"], "main_global_no=1;effective=no")
                self.assertIn(["systemctl", "try-reload-or-restart", "ssh.service"], t.calls)
                self.assertLess(t.names().index("systemctl"), len(t.names()))
                r = execute(t, key)
                self.assertEqual((r["outcome"], r["mutation_performed"]), ("ALREADY_COMPLIANT", False))

    def test_dropin_value_is_changed_in_place(self):
        # Схема п.4: 50-cloud-init.conf с `PasswordAuthentication yes` перекрыл бы основной файл.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            (t.dropin_path).chmod(0o600)
            r = execute(t, "PasswordAuthentication")
            self.assertEqual(r["outcome"], "APPLIED", r)
            self.assertEqual(t.dropin(), "PasswordAuthentication no\n")
            self.assertEqual(t.dropin_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(t.config(), stock_with("PasswordAuthentication", "PasswordAuthentication no\n"))

    def test_dropin_without_key_is_not_touched(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            self.assertEqual(execute(t, "PermitRootLogin")["outcome"], "APPLIED")
            self.assertEqual(t.dropin(), CLOUD_INIT)

    def test_active_main_line_is_changed_in_place(self):
        # Схема п.1: действующая строка меняет значение, форма строки сохраняется.
        for line, expected in (("PermitRootLogin yes\n", "PermitRootLogin no\n"),
                               ("  permitrootlogin=prohibit-password # local\n", "  permitrootlogin=no # local\n"),
                               ("PermitRootLogin yes\r\n", "PermitRootLogin no\r\n")):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as td:
                config = STOCK_CONFIG + line
                t = Tree(td, config=config)
                r = execute(t, "PermitRootLogin")
                self.assertEqual(r["outcome"], "APPLIED", r)
                self.assertEqual(t.config(), STOCK_CONFIG + expected)

    def test_no_template_inserts_before_match_or_appends(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, config="UsePAM yes\nMatch Group sftp\n    ForceCommand internal-sftp\n")
            self.assertEqual(execute(t, "PermitEmptyPasswords")["outcome"], "APPLIED")
            self.assertEqual(t.config(), "UsePAM yes\nPermitEmptyPasswords no\nMatch Group sftp\n    ForceCommand internal-sftp\n")
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, config="UsePAM yes")
            self.assertEqual(execute(t, "PermitEmptyPasswords")["outcome"], "APPLIED")
            self.assertEqual(t.config(), "UsePAM yes\nPermitEmptyPasswords no\n")

    def test_template_inside_match_is_not_used(self):
        config = "UsePAM yes\nMatch User x\n#PermitRootLogin yes\n"
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, config=config)
            self.assertEqual(execute(t, "PermitRootLogin")["outcome"], "APPLIED")
            self.assertEqual(t.config(), "UsePAM yes\nPermitRootLogin no\nMatch User x\n#PermitRootLogin yes\n")

    def test_initial_current_reports_dropin_value(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            r = execute(t, "PasswordAuthentication", dry_run=True)
            self.assertEqual(r["outcome"], "DRY_RUN_WOULD_APPLY")
            self.assertEqual(r["policy_current"], "main_global_no=0;effective=yes")
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertNotIn("systemctl", t.names())

    def test_three_controls_in_turn_edit_templates_only(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            for key in ("PermitEmptyPasswords", "PermitRootLogin", "PasswordAuthentication"):
                self.assertEqual(execute(t, key)["outcome"], "APPLIED")
            expected = STOCK_CONFIG
            for key in A.CONTROL_KEYS.values():
                expected = expected.replace(next(l for l in expected.splitlines(keepends=True)
                                                 if l.startswith("#" + key)), key + " no\n")
            self.assertEqual(t.config(), expected)
            self.assertEqual(t.dropin(), "PasswordAuthentication no\n")

    def test_check_passes_after_apply(self):
        if BASH is None:
            self.skipTest("bash not found")
        for key in A.CONTROL_KEYS.values():
            with self.subTest(key=key), tempfile.TemporaryDirectory() as td:
                t = Tree(td, config="UsePAM yes\n")
                self.assertEqual(execute(t, key)["outcome"], "APPLIED")
                # Подставной sshd — в каталоге внутри репозитория: /tmp на ПК смонтирован с noexec,
                # и `[[ -x ]]` CHECK-функции для файла в /tmp ложно.
                bin_dir = tempfile.TemporaryDirectory(dir=ROOT)
                self.addCleanup(bin_dir.cleanup)
                sshd = Path(bin_dir.name) / "fake-sshd"
                sshd.write_text("#!/usr/bin/env bash\n"
                                "if [[ ${1:-} == -t ]]; then exit 0; fi\n"
                                "printf '%s\\n' '" + key.lower() + " no'\n", encoding="utf-8")
                sshd.chmod(0o755)
                block = CHECK._shell_function_for_fixture("SSH.APPLY", str(t.cfg), str(sshd), key, "eq", "no")
                cp = subprocess.run([BASH, "-c", "set -u\n" + block + "\nslp_check_SSH_APPLY\n"],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                self.assertEqual(cp.stdout.strip().split("\t")[2:], ["VALUE", "main_global_no=1;effective=no", "PASS"])

    def test_main_no_already_present_is_compliant(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, config="PermitEmptyPasswords no\n" + STOCK_CONFIG)
            r = execute(t, "PermitEmptyPasswords")
            self.assertEqual((r["outcome"], r["policy_current"]), ("ALREADY_COMPLIANT", "main_global_no=1;effective=no"))
            self.assertNotIn("systemctl", t.names())

    def test_main_no_after_dropin_yes_changes_only_dropin(self):
        config = STOCK_CONFIG + "PasswordAuthentication no\n"
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, config=config)
            r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["policy_current"]), ("APPLIED", "main_global_no=1;effective=no"))
            self.assertEqual((t.config(), t.dropin()), (config, "PasswordAuthentication no\n"))

    def test_match_with_non_no_is_admin_decision(self):
        for config in (STOCK_CONFIG + "Match User backup\n    PermitRootLogin yes\n",
                       "Match User x\nInclude /etc/ssh/sshd_config.d/*.conf\n"):
            with self.subTest(config=config), tempfile.TemporaryDirectory() as td:
                t = Tree(td, config=config, dropin="PermitRootLogin yes\n")
                r = execute(t, "PermitRootLogin")
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "sshd-config:ambiguous-match"))
                self.assertEqual(r["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
                self.assertEqual(t.config(), config)

    def test_match_without_key_or_with_no_is_applied(self):
        config = STOCK_CONFIG + "Match Group sftp\n    ForceCommand internal-sftp\n    PermitRootLogin no\n"
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, config=config)
            self.assertEqual(execute(t, "PermitRootLogin")["outcome"], "APPLIED")
            self.assertEqual(t.config(), stock_with("PermitRootLogin", "PermitRootLogin no\n")
                             + "Match Group sftp\n    ForceCommand internal-sftp\n    PermitRootLogin no\n")

    def test_no_sudo_member_blocks_root_login_only(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, group="root:x:0:\nsudo:x:27:root\n")
            r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "ssh:no-sudo-members"))
            self.assertIn("sudo", r["operator_decision"]["action"])
            self.assertEqual(execute(t, "PermitEmptyPasswords")["outcome"], "APPLIED")

    def test_admin_group_member_is_enough(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, group="root:x:0:\nadmin:x:115:user\n")
            self.assertEqual(execute(t, "PermitRootLogin")["outcome"], "APPLIED")
            self.assertEqual(execute(t, "PasswordAuthentication")["outcome"], "APPLIED")

    def test_password_auth_needs_admin_key(self):
        for key in (None, "", "# comment only\n\n"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as td:
                t = Tree(td, key=key)
                r = execute(t, "PasswordAuthentication")
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "ssh:no-keyed-admin"))
                self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
                self.assertEqual(execute(t, "PermitRootLogin")["outcome"], "APPLIED")

    def test_root_key_does_not_count(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, group="root:x:0:\nsudo:x:27:root,user\n", key=None)
            (t.root / "root/.ssh").mkdir(parents=True)
            (t.root / "root/.ssh/authorized_keys").write_text(KEY, encoding="utf-8")
            r = execute(t, "PasswordAuthentication")
            self.assertEqual(r["reason"], "ssh:no-keyed-admin")

    def test_authorized_keys2_counts(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, key=None)
            (t.root / "home/user/.ssh").mkdir(parents=True)
            (t.root / "home/user/.ssh/authorized_keys2").write_text(KEY, encoding="utf-8")
            self.assertEqual(execute(t, "PasswordAuthentication")["outcome"], "APPLIED")

    def test_nondefault_key_setup_is_admin_decision(self):
        for extra in ({"authorizedkeysfile": "/etc/ssh/keys/%u"}, {"pubkeyauthentication": "no"}):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as td:
                t = Tree(td)
                t.extra = extra
                r = execute(t, "PasswordAuthentication")
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "ssh:keys-setup-nondefault"))

    def test_untrusted_files_are_refused(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.cfg.chmod(0o664)
            r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted"))
            self.assertIn("/etc/ssh/sshd_config", r["operator_decision"]["action"])
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.dropin_path.chmod(0o666)
            r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted"))
            self.assertIn("/etc/ssh/sshd_config.d/50-cloud-init.conf", r["operator_decision"]["action"])
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            # Файл, который не меняется, на доверие не проверяется.
            self.assertEqual(execute(t, "PermitRootLogin")["outcome"], "APPLIED")
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real = t.root / "etc/ssh/real_config"
            t.cfg.rename(real)
            t.cfg.symlink_to(real)
            r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "sshd-config:read-failed"))

    def test_invalid_config_is_refused_without_write(self):
        cases = (
            ("PermitRootLogin no extra\n", "sshd-config:invalid-directive"),
            ('PermitRootLogin "no\n', "sshd-config:invalid-arguments"),
            ("Include /etc/ssh/loop.conf\n", "sshd-config:include-cycle"),
        )
        for config, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as td:
                t = Tree(td, config=config)
                (t.root / "etc/ssh/loop.conf").write_text("Include /etc/ssh/loop.conf\n", encoding="utf-8")
                r = execute(t, "PermitRootLogin")
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", reason))
                self.assertEqual(t.config(), config)

    def test_current_syntax_failure_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.fail.add("sshd-t")
            r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "sshd-config:validation-failed"))

    def test_syntax_failure_after_write_restores_all_files(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_run = t.run

            def run(argv, timeout):
                if argv[1:2] == ["-t"] and "no" in t.dropin():
                    t.calls.append(["sshd", "-t"])
                    return subprocess.CompletedProcess(argv, 255, b"", b"")
                return real_run(argv, timeout)

            t.run = run
            r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "sshd-config:validation-failed", True))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertNotIn("systemctl", t.names())
            self.assertEqual(sorted(p.name for p in (t.root / "etc/ssh").rglob("*.slp-tmp")), [])

    def test_reload_failure_restores_and_reloads(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.fail.add("systemctl")
            r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_COMPENSATION", "reload:failed"))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertEqual(t.names().count("systemctl"), 2)
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_run = t.run
            count = {"n": 0}

            def run(argv, timeout):
                if os.path.basename(argv[0]) == "systemctl":
                    count["n"] += 1
                    if count["n"] == 1:
                        t.calls.append(["systemctl"])
                        return subprocess.CompletedProcess(argv, 1, b"", b"")
                return real_run(argv, timeout)

            t.run = run
            r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "reload:failed", True))
            self.assertEqual(t.config(), STOCK_CONFIG)
            self.assertEqual(count["n"], 2)

    def test_postcheck_failure_restores(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_run = t.run

            def run(argv, timeout):
                cp = real_run(argv, timeout)
                if argv[1:2] == ["-T"] and "systemctl" in t.names():
                    return subprocess.CompletedProcess(argv, 0, cp.stdout.replace(b"permitrootlogin no", b"permitrootlogin yes"), b"")
                return cp

            t.run = run
            r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"]), ("FAILED_NOT_COMMITTED", "postcheck:not-compliant"))
            self.assertEqual(t.config(), STOCK_CONFIG)
            self.assertEqual(t.names().count("systemctl"), 2)

    def test_second_write_failure_restores_first_file(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            done = []

            def write(path, raw, st):
                if path == str(t.dropin_path) and raw != CLOUD_INIT.encode():
                    raise OSError("disk full")
                A._write_file(path, raw, st)
                done.append(path)

            r = execute(t, "PasswordAuthentication", write=write)
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "sshd-config:write-failed", True))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))

    def test_first_write_failure_is_not_committed(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)

            def write(path, raw, st):
                raise OSError("disk full")

            r = execute(t, "PermitRootLogin", write=write)
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "sshd-config:write-failed", False))

    def test_missing_tools_and_privilege_and_spec(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            (t.root / "usr/bin/systemctl").unlink()
            r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "tools:missing:systemctl"))
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            r = execute(t, "PermitRootLogin", privileged=False)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "privilege"))
            r = execute(t, "PermitRootLogin", expected="yes")
            self.assertEqual((r["outcome"], r["reason"]), ("NOT_ELIGIBLE_APPLY_UNSUPPORTED", "op-unsupported"))
            r = execute(t, "PermitRootLogin", control_id=IDS["PasswordAuthentication"])
            self.assertEqual(r["reason"], "op-unsupported")
            r = A.execute_control(IDS["PermitRootLogin"], "PermitRootLogin", "eq", "no", False, dry_run=False,
                                  _root=str(t.root), _run=t.run)
            self.assertEqual(r["outcome"], "NOT_ELIGIBLE_APPLY_UNSUPPORTED")
            self.assertEqual(t.config(), STOCK_CONFIG)
            self.assertNotIn("systemctl", t.names())

    def test_report_carries_decision_and_current(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, key=None)
            rep = A.control_result_to_report(execute(t, "PasswordAuthentication"), "s", "f")
            self.assertEqual(rep["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
            self.assertEqual(rep["policy_current"], "main_global_no=0;effective=yes")
            self.assertEqual(rep["step_rc"], "nonzero")
            self.assertFalse(rep["mutation_performed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
