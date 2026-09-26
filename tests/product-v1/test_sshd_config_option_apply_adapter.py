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
import random
import signal
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

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
    "strictmodes": "yes",
    "kbdinteractiveauthentication": "no",
    "authenticationmethods": "any",
}


def add_key(root, home_rel, name="authorized_keys", key=KEY, home_mode=0o750, ssh_mode=0o700, key_mode=0o600):
    """Ключ пользователя с явными режимами (umask ПК 0002 дал бы запись для группы)."""
    home = Path(root) / home_rel
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o750)
    (home / ".ssh").mkdir(exist_ok=True)
    (home / ".ssh").chmod(0o700)
    path = home / ".ssh" / name
    path.write_text(key, encoding="utf-8")
    # Итоговые режимы — после записи: режим без прохода или записи не мешает создать файл.
    path.chmod(key_mode)
    (home / ".ssh").chmod(ssh_mode)
    home.chmod(home_mode)
    return path


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
            add_key(self.root, "home/user", key=key)
        for rel in ("usr/sbin/sshd", "usr/bin/systemctl"):
            tool = self.root / rel
            tool.parent.mkdir(parents=True, exist_ok=True)
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            tool.chmod(0o755)
        self.calls = []
        self.fail = set()
        self.extra = {}
        self.user_extra = {}

    def _lines(self, path, depth=0):
        for line in Path(path).read_bytes().decode("utf-8", "surrogateescape").splitlines():
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
        spec = argv[argv.index("-C") + 1] if "-C" in argv else ""
        user = spec.split(",", 1)[0].split("=", 1)[1] if spec.startswith("user=") else ""
        values.update(self.user_extra.get(user, {}))
        if values.get("permitrootlogin") == "prohibit-password":
            values["permitrootlogin"] = "without-password"
        out = "".join("%s %s\n" % item for item in sorted(values.items()))
        return subprocess.CompletedProcess(argv, 0, out.encode("utf-8"), b"")

    def config(self):
        return self.cfg.read_bytes().decode("utf-8", "surrogateescape")

    def dropin(self):
        # Без нормализации окончаний строк: сравнение точных байтов (B-15).
        return self.dropin_path.read_bytes().decode("utf-8", "surrogateescape")

    def names(self):
        return [c[0] if c[0] != "sshd" else "sshd" + c[1] for c in self.calls]


def ssh_tree_state(tree):
    """Все объекты /etc/ssh дерева: тип, полный режим (S_IMODE) и точные байты обычных файлов.

    Читается через pathlib (os.read/os.close тестовых подмен не участвуют)."""
    state = {}
    base = tree.root / "etc/ssh"
    for path in [base] + sorted(base.rglob("*")):
        st = os.lstat(path)
        kind = stat.S_IFMT(st.st_mode)
        data = path.read_bytes() if stat.S_ISREG(st.st_mode) else None
        state[str(path.relative_to(base))] = (kind, stat.S_IMODE(st.st_mode), data, st.st_uid, st.st_gid)
    return state


UNCHANGED_OUTCOMES = {
    "ALREADY_COMPLIANT", "DRY_RUN_WOULD_APPLY", "NOT_ELIGIBLE_APPLY_UNSUPPORTED",
    "ABORTED_PRECONDITION_CONFLICT", "ABORTED_PRECONDITION_OTHER", "FAILED_NOT_COMMITTED",
}


def execute(tree, key, *, dry_run=False, privileged=True, write=None, stage=None, control_id=None, expected="no"):
    """Вызов адаптера с общими инвариантами для каждого теста (B-15).

    Исход без мутации или с полным откатом — дерево /etc/ssh побайтно, по типам и полным
    режимам равно исходному, временных файлов нет. APPLIED — прежние объекты сохранили тип
    и полный режим, новых объектов (в т.ч. .slp-tmp) нет. FAILED_COMPENSATION проверяется
    явно в самом тесте.
    """
    before = ssh_tree_state(tree)
    result = A.execute_control(control_id or IDS[key], key, "eq", expected, True, dry_run=dry_run,
                               privilege_check=lambda: privileged, _root=str(tree.root), _run=tree.run,
                               _write=write, _stage=stage)
    after = ssh_tree_state(tree)
    tree.last_states = (before, after)
    if result["outcome"] == "FAILED_COMPENSATION":
        # Итог частичного отката проверяет сам тест через assert_state (всё дерево).
        tree.compensation_checked = False
    if result["outcome"] in UNCHANGED_OUTCOMES:
        assert after == before, (result, sorted(set(after.items()) ^ set(before.items()), key=str))
    elif result["outcome"] == "APPLIED":
        assert set(after) == set(before), (result, sorted(set(after) ^ set(before)))
        assert {k: v[:2] + v[3:] for k, v in after.items()} == {k: v[:2] + v[3:] for k, v in before.items()}, result
        # Меняться могут только основной файл и включаемые файлы sshd_config.d.
        changed = {k for k in after if after[k][2] != before[k][2]}
        assert changed <= {"sshd_config"} | {k for k in after if k.startswith("sshd_config.d/")}, changed
    return result


def modes(tree):
    return (stat.S_IMODE(tree.cfg.stat().st_mode), stat.S_IMODE(tree.dropin_path.stat().st_mode))


def special_bits_supported(directory, bits):
    """SGID сбрасывается ядром, если группа файла не входит в группы пользователя (setgid-каталог
    выше по пути); тогда проверка сохранения битов в этой среде невозможна."""
    probe = Path(directory) / ".probe"
    probe.write_bytes(b"")
    probe.chmod(0o644 | bits)
    ok = stat.S_IMODE(probe.stat().st_mode) & bits == bits
    probe.unlink()
    return ok


def leftovers(tree):
    return sorted(p.name for p in (tree.root / "etc/ssh").rglob("*" + A.TMP_SUFFIX))


def stock_with(template_key, line):
    return STOCK_CONFIG.replace(next(l for l in STOCK_CONFIG.splitlines(keepends=True)
                                     if l.startswith("#" + template_key)), line)


class Apply(unittest.TestCase):
    def setUp(self):
        self._trees = []
        original = Tree.__init__

        def tracked(tree, *args, **kwargs):
            original(tree, *args, **kwargs)
            self._trees.append(tree)

        patcher = mock.patch.object(Tree, "__init__", tracked)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        # Каждый исход FAILED_COMPENSATION обязан пройти assert_state.
        for tree in self._trees:
            self.assertNotEqual(getattr(tree, "compensation_checked", None), False, tree.root)

    def assert_state(self, t, config, dropin, file_modes, tmp_left):
        """Итоговое состояние после FAILED_COMPENSATION — всё дерево /etc/ssh (B-02 аудита
        e11ad4c..943483a): основной файл и drop-in с ожидаемыми байтами, прочие объекты без
        изменений; у всех прежних объектов прежние тип, полный режим, UID и GID; из новых
        объектов — только перечисленные временные файлы, обычные файлы."""
        self.assertEqual((t.config(), t.dropin()), (config, dropin))
        self.assertEqual(modes(t), file_modes)
        self.assertEqual(leftovers(t), sorted(tmp_left))
        before, after = t.last_states
        expected = dict(before)
        for name, text in (("sshd_config", config), ("sshd_config.d/50-cloud-init.conf", dropin)):
            kind, mode, _data, uid, gid = expected[name]
            expected[name] = (kind, mode, text.encode("utf-8", "surrogateescape"), uid, gid)
        new = {k: v for k, v in after.items() if k not in before}
        self.assertEqual({k: v for k, v in after.items() if k in before}, expected)
        self.assertEqual(sorted(k.rsplit("/", 1)[-1] for k in new), sorted(tmp_left))
        self.assertTrue(all(v[0] == stat.S_IFREG for v in new.values()), new)
        t.compensation_checked = True

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
                # Перезагрузка — до итоговой проверки sshd -T.
                self.assertLess(t.names().index("systemctl"), len(t.names()) - 1 - t.names()[::-1].index("sshd-T"))
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
            add_key(t.root, "root")
            r = execute(t, "PasswordAuthentication")
            self.assertEqual(r["reason"], "ssh:no-keyed-admin")

    def test_authorized_keys2_counts(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, key=None)
            add_key(t.root, "home/user", name="authorized_keys2")
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
            # Ссылка вместо основного файла — не обычный файл: блок «решение администратора».
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted"))
            self.assertEqual(r["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")

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
            self.assert_state(t, STOCK_CONFIG, CLOUD_INIT, (0o644, 0o600), [])
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

    def test_candidate_is_validated_before_replacement(self):
        # B-02: `sshd -t` видит подготовленный временный файл до замены рабочего.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_run = t.run
            seen = []

            def run(argv, timeout):
                if argv[1:2] == ["-t"]:
                    seen.append((argv[-1], t.config(), t.dropin()))
                    if argv[-1].endswith(A.TMP_SUFFIX) and "50-cloud-init" in argv[-1]:
                        return subprocess.CompletedProcess(argv, 255, b"", b"")
                return real_run(argv, timeout)

            t.run = run
            r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"], r["transaction_commit"]),
                             ("FAILED_NOT_COMMITTED", "sshd-config:validation-failed", False, "NOT_STARTED"))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertEqual(leftovers(t), [])
            self.assertNotIn("systemctl", t.names())
            staged = [path for path, _c, _d in seen if path.endswith(A.TMP_SUFFIX)]
            self.assertEqual(staged, [str(t.cfg) + A.TMP_SUFFIX, str(t.dropin_path) + A.TMP_SUFFIX])
            self.assertTrue(all(c == STOCK_CONFIG and d == CLOUD_INIT for _p, c, d in seen))

    def test_stage_failure_changes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)

            def stage(path, raw, st):
                if path == str(t.dropin_path):
                    raise OSError("disk full")
                return A._stage_file(path, raw, st)

            r = execute(t, "PasswordAuthentication", stage=stage)
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "sshd-config:write-failed", False))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertEqual(leftovers(t), [])

    def test_second_replace_failure_restores_first_file(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_replace = os.replace
            calls = []

            def replace(src, dst, *args, **kwargs):
                calls.append(dst)
                if len(calls) == 2:
                    raise OSError("rename failed")
                return real_replace(src, dst, *args, **kwargs)

            with mock.patch.object(A.os, "replace", replace):
                r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"], r["transaction_commit"]),
                             ("FAILED_NOT_COMMITTED", "sshd-config:write-failed", True, "NOT_COMMITTED"))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertEqual(leftovers(t), [])

    def test_restore_failure_is_failed_compensation(self):
        # B-05: ошибка записи или несовпадение восстановленных байтов — FAILED_COMPENSATION.
        def bad_write(path, raw, st):
            A._write_file(path, raw + b"# damaged\n", st)

        def raising_write(path, raw, st):
            raise OSError("disk full")

        for write in (bad_write, raising_write):
            with self.subTest(write=write.__name__), tempfile.TemporaryDirectory() as td:
                t = Tree(td)
                real_run = t.run

                def run(argv, timeout):
                    if argv[1:2] == ["-t"] and not argv[-1].endswith(A.TMP_SUFFIX) and "no" in t.dropin():
                        return subprocess.CompletedProcess(argv, 255, b"", b"")
                    return real_run(argv, timeout)

                t.run = run
                r = execute(t, "PasswordAuthentication", write=write)
                self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                                 ("FAILED_COMPENSATION", "sshd-config:validation-failed", True))
                self.assertEqual(A.outcome_rc_contribution(r["outcome"]), "nonzero")
                if write is bad_write:
                    self.assert_state(t, STOCK_CONFIG + "# damaged\n", CLOUD_INIT + "# damaged\n", (0o644, 0o600), [])
                else:
                    self.assert_state(t, stock_with("PasswordAuthentication", "PasswordAuthentication no\n"), "PasswordAuthentication no\n", (0o644, 0o600), [])

    def test_short_writes_are_completed(self):
        # B-05: os.write, записывающий по 3 байта, даёт полный файл.
        real_write = os.write

        def short(fd, data):
            return real_write(fd, bytes(data)[:3])

        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            with mock.patch.object(A.os, "write", short):
                r = execute(t, "PasswordAuthentication")
            self.assertEqual(r["outcome"], "APPLIED", r)
            self.assertEqual(t.config(), stock_with("PasswordAuthentication", "PasswordAuthentication no\n"))
            self.assertEqual(t.dropin(), "PasswordAuthentication no\n")

    def test_foreign_owner_of_main_is_refused_even_if_compliant(self):
        # B-04: доверие основного файла проверяется до признания соответствия.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, config="PermitEmptyPasswords no\n" + STOCK_CONFIG)
            with mock.patch.object(A, "_trusted_uid", lambda root: os.geteuid() + 1):
                r = execute(t, "PermitEmptyPasswords")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted"))
            self.assertEqual(r["operator_decision"]["class"], "ADMIN_ACTION_REQUIRED")
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, config=STOCK_CONFIG + "PasswordAuthentication no\n")
            t.cfg.chmod(0o664)
            r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted"))
            self.assertEqual(t.dropin(), CLOUD_INIT)

    def test_fifo_main_config_is_refused_without_blocking(self):
        # B-03: FIFO без писателя не блокирует открытие.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.cfg.unlink()
            os.mkfifo(t.cfg, 0o644)
            os.chmod(t.cfg, 0o644)  # B-16: режим не зависит от umask
            old = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("blocked")))
            signal.alarm(5)
            try:
                r = execute(t, "PermitRootLogin", dry_run=True)
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "sshd-config:untrusted"))
            self.assertNotIn("systemctl", t.names())
            self.assertTrue(stat.S_ISFIFO(os.lstat(t.cfg).st_mode))
            self.assertEqual(stat.S_IMODE(os.lstat(t.cfg).st_mode), 0o644)
            self.assertEqual((t.dropin(), stat.S_IMODE(t.dropin_path.stat().st_mode)), (CLOUD_INIT, 0o600))
            self.assertEqual(leftovers(t), [])

    def test_include_rules_match_check(self):
        # B-06: те же отказы Include, что у CHECK sshd-config-option.
        cases = (
            ("Include /etc/ssh/linkdir/*.conf\n", "sshd-config:include-prefix-symlink"),
            ("Include /etc/ssh/plainfile/*.conf\n", "sshd-config:include-prefix-invalid-type"),
            ("Include /etc/ssh/sshd_config.d/*.conf\n", "sshd-config:include-newline-name"),
            ("Include /etc/ssh/link.conf\n", "sshd-config:include-symlink"),
            ("Include /etc/ssh/d0.conf\n", "sshd-config:include-depth"),
        )
        for config, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as td:
                t = Tree(td, config=config)
                ssh = t.root / "etc/ssh"
                (ssh / "realdir").mkdir()
                (ssh / "linkdir").symlink_to(ssh / "realdir")
                (ssh / "plainfile").write_text("x\n", encoding="utf-8")
                (ssh / "link.conf").symlink_to(t.dropin_path)
                if reason == "sshd-config:include-newline-name":
                    (ssh / "sshd_config.d" / "bad\nname.conf").write_text("UsePAM yes\n", encoding="utf-8")
                for i in range(A.MAX_INCLUDE_DEPTH + 2):
                    (ssh / f"d{i}.conf").write_text(f"Include /etc/ssh/d{i + 1}.conf\n", encoding="utf-8")
                r = execute(t, "PermitRootLogin")
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", reason))
                self.assertEqual(t.config(), config)

    def test_missing_include_target_is_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, config="Include /etc/ssh/absent/*.conf\nInclude /etc/ssh/absent.conf\n")
            self.assertEqual(execute(t, "PermitRootLogin")["outcome"], "APPLIED")

    def test_first_stage_failure_is_not_committed(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)

            def stage(path, raw, st):
                raise OSError("disk full")

            r = execute(t, "PermitRootLogin", stage=stage)
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "sshd-config:write-failed", False))
            self.assertEqual(t.config(), STOCK_CONFIG)

    def test_admin_match_block_disabling_keys_is_admin_decision(self):
        # B-04 аудита f75181a..b1506bd (первый прогон): настройки ключей — для соединения администратора.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.user_extra = {"user": {"pubkeyauthentication": "no"}}
            r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "ssh:keys-setup-nondefault"))
            self.assertIn(["sshd", "-T", "-C", "user=user,host=localhost,addr=127.0.0.1", "-f", str(t.cfg)], t.calls)
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, group="root:x:0:\nsudo:x:27:user,ops\n")
            with (t.root / "etc/passwd").open("a", encoding="utf-8") as stream:
                stream.write("ops:x:1001:1001:ops:/home/ops:/bin/bash\n")
            t.user_extra = {"user": {"authorizedkeysfile": "/etc/ssh/keys/%u"}}
            add_key(t.root, "home/ops")
            self.assertEqual(execute(t, "PasswordAuthentication")["outcome"], "APPLIED")

    def test_postcheck_read_error_restores(self):
        # B-08: ошибка чтения при итоговой проверке ведёт в компенсацию.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_read = os.read
            state = {"armed": True}

            def read(fd, n):
                if state["armed"] and "systemctl" in t.names():
                    state["armed"] = False
                    raise OSError("EIO")
                return real_read(fd, n)

            with mock.patch.object(A.os, "read", read):
                r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "postcheck:read-failed", True))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertEqual(t.names().count("systemctl"), 2)

    def test_restore_verification_read_error_is_failed_compensation(self):
        # B-08: ошибка чтения при сверке восстановления — FAILED_COMPENSATION, остальные файлы
        # всё равно возвращаются.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_run, real_read = t.run, os.read
            state = {"compensating": False}

            def run(argv, timeout):
                if argv[1:2] == ["-t"] and not argv[-1].endswith(A.TMP_SUFFIX) and "no" in t.dropin():
                    state["compensating"] = True
                    return subprocess.CompletedProcess(argv, 255, b"", b"")
                return real_run(argv, timeout)

            def read(fd, n):
                if state["compensating"]:
                    raise OSError("EIO")
                return real_read(fd, n)

            t.run = run
            with mock.patch.object(A.os, "read", read):
                r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_COMPENSATION", "sshd-config:validation-failed", True))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assert_state(t, STOCK_CONFIG, CLOUD_INIT, (0o644, 0o600), [])

    def test_discard_error_does_not_stop_restore(self):
        # B-09: ошибка удаления временного файла не останавливает возврат заменённых файлов.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_replace, real_unlink = os.replace, os.unlink
            calls = []

            def replace(src, dst, *args, **kwargs):
                calls.append(dst)
                if len(calls) == 2:
                    raise OSError("rename failed")
                return real_replace(src, dst, *args, **kwargs)

            def unlink(path, *args, **kwargs):
                if str(path) == str(t.dropin_path) + A.TMP_SUFFIX:
                    raise PermissionError("EACCES")
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(A.os, "replace", replace), mock.patch.object(A.os, "unlink", unlink):
                r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_COMPENSATION", "sshd-config:write-failed", True))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertNotIn("systemctl", t.names())
            self.assert_state(t, STOCK_CONFIG, CLOUD_INIT, (0o644, 0o600), ["50-cloud-init.conf" + A.TMP_SUFFIX])

    def test_restore_replace_error_removes_temporary_file(self):
        # B-10: ошибка восстановительной замены не оставляет .slp-tmp.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_run, real_replace = t.run, os.replace
            calls = []

            def run(argv, timeout):
                if argv[1:2] == ["-t"] and not argv[-1].endswith(A.TMP_SUFFIX) and "no" in t.dropin():
                    return subprocess.CompletedProcess(argv, 255, b"", b"")
                return real_run(argv, timeout)

            def replace(src, dst, *args, **kwargs):
                calls.append(dst)
                if len(calls) == 3:
                    raise OSError("rename failed")
                return real_replace(src, dst, *args, **kwargs)

            t.run = run
            with mock.patch.object(A.os, "replace", replace):
                r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_COMPENSATION", "sshd-config:validation-failed", True))
            self.assertEqual(leftovers(t), [])
            self.assertEqual(t.config(), STOCK_CONFIG)
            self.assert_state(t, STOCK_CONFIG, "PasswordAuthentication no\n", (0o644, 0o600), [])

    def test_stage_error_with_cleanup_error_is_failed_compensation(self):
        # B-11: ошибка fsync при подготовке и ошибка удаления временного файла.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_unlink = os.unlink

            def fsync(fd):
                raise OSError("EIO")

            def unlink(path, *args, **kwargs):
                if str(path).endswith(A.TMP_SUFFIX):
                    raise PermissionError("EACCES")
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(A.os, "fsync", fsync), mock.patch.object(A.os, "unlink", unlink):
                r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_COMPENSATION", "sshd-config:write-failed", True))
            self.assertEqual(t.config(), STOCK_CONFIG)
            self.assertEqual(leftovers(t), ["sshd_config" + A.TMP_SUFFIX])
            self.assertNotIn("systemctl", t.names())
            self.assert_state(t, STOCK_CONFIG, CLOUD_INIT, (0o644, 0o600), ["sshd_config" + A.TMP_SUFFIX])

    def test_restore_stage_error_with_cleanup_error_is_failed_compensation(self):
        # B-11: та же пара ошибок при восстановлении; возврат остальных файлов продолжается.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_run, real_fsync, real_unlink = t.run, os.fsync, os.unlink
            state = {"compensating": False}

            def run(argv, timeout):
                if argv[1:2] == ["-t"] and not argv[-1].endswith(A.TMP_SUFFIX) and "no" in t.dropin():
                    state["compensating"] = True
                    return subprocess.CompletedProcess(argv, 255, b"", b"")
                return real_run(argv, timeout)

            def fsync(fd):
                if state["compensating"] and os.readlink(f"/proc/self/fd/{fd}").endswith(
                        "50-cloud-init.conf" + A.TMP_SUFFIX):
                    raise OSError("EIO")
                return real_fsync(fd)

            def unlink(path, *args, **kwargs):
                if state["compensating"] and str(path).endswith(A.TMP_SUFFIX):
                    raise PermissionError("EACCES")
                return real_unlink(path, *args, **kwargs)

            t.run = run
            with mock.patch.object(A.os, "fsync", fsync), mock.patch.object(A.os, "unlink", unlink):
                r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_COMPENSATION", "sshd-config:validation-failed", True))
            self.assertEqual(t.config(), STOCK_CONFIG)
            self.assertEqual(t.dropin(), "PasswordAuthentication no\n")
            self.assert_state(t, STOCK_CONFIG, "PasswordAuthentication no\n", (0o644, 0o600), ["50-cloud-init.conf" + A.TMP_SUFFIX])

    def test_stage_error_with_successful_cleanup_is_not_committed(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)

            def fsync(fd):
                raise OSError("EIO")

            with mock.patch.object(A.os, "fsync", fsync):
                r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "sshd-config:write-failed", False))
            self.assertEqual(leftovers(t), [])

    def test_lines_split_on_lf_only_like_check(self):
        # B-12: \v внутри комментария не отделяет директиву; результат совпадает с CHECK.
        config = "# note\x0bPermitEmptyPasswords no\nUsePAM yes\n"
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, config=config)
            r = execute(t, "PermitEmptyPasswords", dry_run=True)
            self.assertEqual((r["outcome"], r["policy_current"]), ("DRY_RUN_WOULD_APPLY", "main_global_no=0;effective=no"))
            r = execute(t, "PermitEmptyPasswords")
            self.assertEqual((r["outcome"], r["policy_current"]), ("APPLIED", "main_global_no=1;effective=no"))
            self.assertEqual(t.config(), config + "PermitEmptyPasswords no\n")
        self.assertEqual(A._directive("\x0bPermitRootLogin\x0cyes\r\n"), ("permitrootlogin", "yes"))
        self.assertEqual(A.split_args("yes"), ["yes"])

    def _close_failing(self, match):
        real_close = os.close

        def close(fd):
            try:
                target = os.readlink(f"/proc/self/fd/{fd}")
            except OSError:
                target = ""
            real_close(fd)
            if match(target):
                raise OSError("EIO on close")

        return close

    def test_stage_close_error_removes_temporary_file(self):
        # B-13: ошибка close при подготовке — временный файл удаляется.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            close = self._close_failing(lambda target: target.endswith("sshd_config" + A.TMP_SUFFIX))
            with mock.patch.object(A.os, "close", close):
                r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_NOT_COMMITTED", "sshd-config:write-failed", False))
            self.assertEqual((t.config(), leftovers(t)), (STOCK_CONFIG, []))

    def test_stage_close_error_with_cleanup_error_is_failed_compensation(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            close = self._close_failing(lambda target: target.endswith("sshd_config" + A.TMP_SUFFIX))
            real_unlink = os.unlink

            def unlink(path, *args, **kwargs):
                if str(path).endswith(A.TMP_SUFFIX):
                    raise PermissionError("EACCES")
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(A.os, "close", close), mock.patch.object(A.os, "unlink", unlink):
                r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_COMPENSATION", "sshd-config:write-failed", True))
            self.assertEqual(leftovers(t), ["sshd_config" + A.TMP_SUFFIX])
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertEqual(modes(t), (0o644, 0o600))
            self.assert_state(t, STOCK_CONFIG, CLOUD_INIT, (0o644, 0o600), ["sshd_config" + A.TMP_SUFFIX])

    def test_restore_verification_close_error_continues(self):
        # B-13: ошибка close при сверке восстановления — FAILED_COMPENSATION, остальные файлы возвращаются.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_run = t.run
            state = {"compensating": False}

            def run(argv, timeout):
                if argv[1:2] == ["-t"] and not argv[-1].endswith(A.TMP_SUFFIX) and "no" in t.dropin():
                    state["compensating"] = True
                    return subprocess.CompletedProcess(argv, 255, b"", b"")
                return real_run(argv, timeout)

            t.run = run
            close = self._close_failing(
                lambda target: state["compensating"] and target.endswith("50-cloud-init.conf"))
            with mock.patch.object(A.os, "close", close):
                r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"]),
                             ("FAILED_COMPENSATION", "sshd-config:validation-failed", True))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertEqual((modes(t), leftovers(t)), ((0o644, 0o600), []))
            self.assert_state(t, STOCK_CONFIG, CLOUD_INIT, (0o644, 0o600), [])

    def test_owner_is_set_before_full_mode(self):
        # B-14: fchown раньше fchmod; режим восстанавливается полностью, включая SUID.
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "f")
            open(path, "wb").close()
            st = os.stat(path)
            calls = []
            real_fchmod = os.fchmod
            fake_st = os.stat_result((stat.S_IFREG | 0o4644,) + tuple(st)[1:])
            with mock.patch.object(A.os, "geteuid", lambda: 0), \
                    mock.patch.object(A.os, "fchown", lambda fd, uid, gid: calls.append("fchown")), \
                    mock.patch.object(A.os, "fchmod", lambda fd, mode: (calls.append(("fchmod", mode)),
                                                                        real_fchmod(fd, mode))):
                tmp = A._stage_file(path, b"x\n", fake_st)
            self.assertEqual(calls, ["fchown", ("fchmod", 0o4644)])
            self.assertEqual(stat.S_IMODE(os.stat(tmp).st_mode), 0o4644)

    def test_special_mode_bits_survive_apply(self):
        # B-14/B-15: SUID и SGID сохраняются при применении (оба файла).
        for cfg_mode, dropin_mode in ((0o4644, 0o2600), (0o2644, 0o4600), (0o6644, 0o6600)):
            with self.subTest(cfg=oct(cfg_mode), dropin=oct(dropin_mode)), tempfile.TemporaryDirectory() as td:
                if not special_bits_supported(td, stat.S_ISUID | stat.S_ISGID):
                    self.skipTest("SUID/SGID не сохраняются в этой среде")
                t = Tree(td)
                t.cfg.chmod(cfg_mode)
                t.dropin_path.chmod(dropin_mode)
                r = execute(t, "PasswordAuthentication")
                self.assertEqual(r["outcome"], "APPLIED", r)
                self.assertEqual(t.config(), stock_with("PasswordAuthentication", "PasswordAuthentication no\n"))
                self.assertEqual(t.dropin(), "PasswordAuthentication no\n")
                self.assertEqual((modes(t), leftovers(t)), ((cfg_mode, dropin_mode), []))

    def test_special_mode_bits_survive_restore(self):
        # B-15: при откате возвращаются байты и полный режим, включая SUID/SGID.
        with tempfile.TemporaryDirectory() as td:
            if not special_bits_supported(td, stat.S_ISUID | stat.S_ISGID):
                self.skipTest("SUID/SGID не сохраняются в этой среде")
            t = Tree(td)
            t.cfg.chmod(0o6644)
            t.dropin_path.chmod(0o2600)
            real_run = t.run

            def run(argv, timeout):
                if argv[1:2] == ["-t"] and not argv[-1].endswith(A.TMP_SUFFIX) and "no" in t.dropin():
                    return subprocess.CompletedProcess(argv, 255, b"", b"")
                return real_run(argv, timeout)

            t.run = run
            r = execute(t, "PasswordAuthentication")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"], r["transaction_commit"]),
                             ("FAILED_NOT_COMMITTED", "sshd-config:validation-failed", True, "NOT_COMMITTED"))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertEqual((modes(t), leftovers(t)), ((0o6644, 0o2600), []))

    def test_initial_read_close_error_is_refused_without_write(self):
        # B-15: ошибка close при первоначальном чтении — контролируемый отказ без записи.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            close = self._close_failing(lambda target: target.endswith("/etc/ssh/sshd_config"))
            with mock.patch.object(A.os, "close", close):
                r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"], r["mutation_performed"], r["transaction_commit"]),
                             ("ABORTED_PRECONDITION_OTHER", "sshd-config:read-failed", False, "NOT_STARTED"))
            self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
            self.assertEqual((modes(t), leftovers(t)), ((0o644, 0o600), []))
            self.assertNotIn("systemctl", t.names())

    def test_fifo_account_files_are_refused_without_blocking(self):
        for rel, reason in (("etc/group", "group:read-failed"), ("etc/passwd", "passwd:read-failed")):
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as td:
                t = Tree(td)
                (t.root / rel).unlink()
                os.mkfifo(t.root / rel, 0o644)
                os.chmod(t.root / rel, 0o644)  # B-16: режим не зависит от umask
                old = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("blocked")))
                signal.alarm(5)
                try:
                    r = execute(t, "PasswordAuthentication", dry_run=True)
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, old)
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", reason))
                self.assertEqual((t.config(), t.dropin()), (STOCK_CONFIG, CLOUD_INIT))
                self.assertEqual((modes(t), leftovers(t)), ((0o644, 0o600), []))
                self.assertTrue(stat.S_ISFIFO(os.lstat(t.root / rel).st_mode))

    def test_strict_modes_reject_unusable_admin_key(self):
        # sshd с StrictModes отвергнет ключ при записи группы/прочих в ~ или ~/.ssh или в сам файл.
        for home_mode, ssh_mode, key_mode in ((0o770, 0o700, 0o600), (0o750, 0o770, 0o600), (0o750, 0o700, 0o664)):
            with self.subTest(home=oct(home_mode), ssh=oct(ssh_mode), key=oct(key_mode)), tempfile.TemporaryDirectory() as td:
                t = Tree(td, key=None)
                add_key(t.root, "home/user", home_mode=home_mode, ssh_mode=ssh_mode, key_mode=key_mode)
                r = execute(t, "PasswordAuthentication")
                self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "ssh:no-keyed-admin"))
                t.extra = {"strictmodes": "no"}
                self.assertEqual(execute(t, "PasswordAuthentication")["outcome"], "APPLIED")

    def test_strict_modes_reject_foreign_owner(self):
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            real_lstat = os.lstat

            def lstat(path, *args, **kwargs):
                st = real_lstat(path, *args, **kwargs)
                if str(path).endswith("/.ssh"):
                    return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid + 4242)
                                          + tuple(st)[5:])
                return st

            with mock.patch.object(A.os, "lstat", lstat):
                r = A.execute_control(IDS["PasswordAuthentication"], "PasswordAuthentication", "eq", "no", True,
                                      dry_run=True, _root=str(t.root), _run=t.run)
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "ssh:no-keyed-admin"))

    def test_split_args_matches_check_bash_function(self):
        # Разбор аргументов совпадает с _slp_split_args CHECK (дифференциально, 5000 строк).
        if BASH is None:
            self.skipTest("bash not found")
        src = CHECK._shell_function_for_fixture("X", "/x", "/y", "PermitRootLogin", "eq", "no")
        start = src.index("  _slp_split_args() {")
        fn = src[start:src.index("\n  }\n", start) + 5]
        rng = random.Random(20260926)
        alphabet = ["a", "#", "'", '"', "\\", " ", "\t", "\r", "b", "=", "\x0b"]
        cases = ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12))) for _ in range(5000)]
        script = fn + (
            '\nwhile IFS= read -r -d "" line; do _slp_args=(); if _slp_split_args "$line"; then printf OK; '
            'for x in "${_slp_args[@]}"; do printf "\\x1f%s" "$x"; done; printf "\\x1e"; else printf "ERR\\x1e"; fi; done\n')
        out = subprocess.run([BASH, "-c", script], input="".join(c + "\0" for c in cases).encode("utf-8"),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout.decode("utf-8")
        results = out.split("\x1e")
        self.assertEqual(len(results), len(cases) + 1)
        for case, expected in zip(cases, results):
            try:
                actual = "OK" + "".join("\x1f" + arg for arg in A.split_args(case))
            except A._Refused as exc:
                self.assertEqual(exc.reason, "sshd-config:invalid-arguments")
                actual = "ERR"
            self.assertEqual(actual, expected, repr(case))

    def test_parse_matches_check_on_generated_configs(self):
        # main_global_no, Match и причины отказа разбора совпадают с CHECK на 400 конфигурациях.
        if BASH is None:
            self.skipTest("bash not found")
        rng = random.Random(2609)
        pieces = [
            "PermitRootLogin no", "permitrootlogin=no", "PermitRootLogin\tyes", "PERMITROOTLOGIN \"no\"",
            "PermitRootLogin 'no' # c", "PermitRootLogin no extra", "PermitRootLogin", "PermitRootLogin no=1",
            "#PermitRootLogin no", "  # comment", "", "\x0bPermitRootLogin no", "UsePAM yes", "Banner \"x",
            "Match User x", "Match", "PermitRootLogin \"no", "X11Forwarding yes # PermitRootLogin no",
        ]
        with tempfile.TemporaryDirectory(dir=ROOT) as bin_dir:
            sshd = Path(bin_dir) / "sshd"
            sshd.write_text("#!/usr/bin/env bash\nif [[ ${1:-} == -t ]]; then exit 0; fi\n"
                            "printf '%s\\n' 'permitrootlogin no'\n", encoding="utf-8")
            sshd.chmod(0o755)
            for n in range(400):
                config = "".join(rng.choice(pieces) + "\n" for _ in range(rng.randint(1, 6)))
                with self.subTest(n=n, config=config), tempfile.TemporaryDirectory() as td:
                    t = Tree(td, config=config)
                    block = CHECK._shell_function_for_fixture("P.X", str(t.cfg), str(sshd), "PermitRootLogin", "eq", "no")
                    cp = subprocess.run([BASH, "-c", "set -u\n" + block + "\nslp_check_P_X\n"], text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                    row = cp.stdout.strip().split("\t")
                    check = row[3] if row[2] == "ERROR" else row[3].split(";", 1)[0]
                    try:
                        cfg = A.Config(str(t.root), "permitrootlogin")
                        apply = ("sshd-config:ambiguous-match" if cfg.match_non_no
                                 else "main_global_no=%d" % cfg.main_global_no)
                    except A._Refused as exc:
                        apply = exc.reason
                    self.assertEqual(apply, check)

    def test_root_login_needs_admin_who_can_log_in(self):
        # Вход по паролю выключен, у администратора нет ключа — запрет входа root отрезал бы доступ.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, key=None)
            t.extra = {"passwordauthentication": "no"}
            r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_CONFLICT", "ssh:no-admin-login"))
            self.assertIn("PermitRootLogin no", r["operator_decision"]["action"])
            t.extra = {"passwordauthentication": "no", "kbdinteractiveauthentication": "yes"}
            self.assertEqual(execute(t, "PermitRootLogin", dry_run=True)["outcome"], "DRY_RUN_WOULD_APPLY")
            t.extra = {"passwordauthentication": "no"}
            add_key(t.root, "home/user")
            self.assertEqual(execute(t, "PermitRootLogin")["outcome"], "APPLIED")

    def test_access_restrictions_make_admin_unverified(self):
        restrictions = ({"allowusers": "root"}, {"denyusers": "user"}, {"allowgroups": "wheel"},
                        {"denygroups": "sudo"}, {"authenticationmethods": "publickey,password"})
        for extra in restrictions:
            for key in ("PasswordAuthentication", "PermitRootLogin"):
                with self.subTest(extra=extra, key=key), tempfile.TemporaryDirectory() as td:
                    t = Tree(td)
                    t.user_extra = {"user": extra}
                    r = execute(t, key)
                    self.assertEqual((r["outcome"], r["reason"]),
                                     ("ABORTED_PRECONDITION_CONFLICT", "ssh:keys-setup-nondefault"))
                    self.assertIn(key + " no", r["operator_decision"]["action"])

    def test_non_utf8_bytes_are_preserved_like_check(self):
        # CHECK принимает любые байты, кроме NUL и одиночного CR; APPLY переносит их без изменений.
        raw = STOCK_CONFIG.encode("utf-8") + b"# caf\xe9\n"
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.cfg.write_bytes(raw)
            self.assertEqual(execute(t, "PermitRootLogin")["outcome"], "APPLIED")
            self.assertEqual(t.cfg.read_bytes(),
                             stock_with("PermitRootLogin", "PermitRootLogin no\n").encode("utf-8") + b"# caf\xe9\n")
            self.assertEqual(execute(t, "PermitRootLogin")["outcome"], "ALREADY_COMPLIANT")
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.cfg.write_bytes(b"PermitRootLogin no\n\x00\n")
            r = execute(t, "PermitRootLogin")
            self.assertEqual((r["outcome"], r["reason"]), ("ABORTED_PRECONDITION_OTHER", "sshd-config:invalid-bytes"))

    def _stat_override(self, overrides):
        """Подмена os.stat адаптера: {путь: (режим, uid, gid)}; реальные права не меняются,
        поэтому проверка не зависит от того, запущен ли тест от root."""
        real_stat = os.stat

        def fake_stat(path, *args, **kwargs):
            st = real_stat(path, *args, **kwargs)
            if str(path) in overrides:
                mode, uid, gid = overrides[str(path)]
                return os.stat_result((stat.S_IFMT(st.st_mode) | mode, st.st_ino, st.st_dev, st.st_nlink,
                                       uid, gid) + tuple(st)[6:])
            return st

        return mock.patch.object(A.os, "stat", fake_stat)

    def test_admin_key_must_be_readable_by_admin(self):
        # B-01 аудита e11ad4c..943483a: root прочитает любой файл, но sshd читает ключ от имени
        # администратора — нужен проход по каталогам и чтение файла (M-01: права подменяются).
        me, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.extra = {"strictmodes": "no"}
            home = os.path.realpath(t.root / "home/user")
            cases = (
                ({home + "/.ssh/authorized_keys": (0o000, me, gid)}, False),
                ({home + "/.ssh": (0o600, me, gid)}, False),
                ({home: (0o640, me, gid)}, False),
                ({os.path.realpath(t.root / "home"): (0o700, 4444, 4444)}, False),
                # M-02: класс владельца и группы не «проваливается» в биты прочих.
                ({home + "/.ssh/authorized_keys": (0o044, me, gid)}, False),
                ({home + "/.ssh/authorized_keys": (0o604, 4444, 1000)}, False),  # 1000 — основная группа user
                ({home + "/.ssh/authorized_keys": (0o604, 4444, 4444)}, True),
                ({}, True),
            )
            if gid == 4444:
                self.skipTest("gid 4444 занят текущим пользователем")
            for overrides, keyed in cases:
                with self.subTest(overrides=overrides):
                    with self._stat_override(overrides):
                        access, _unverified = A.admin_access(str(t.root), t.run, ["user"])
                    self.assertEqual(access, [("user", keyed, True)])

    def test_admin_key_access_by_group_and_other_bits(self):
        # Файл не пользователя: чтение по битам группы (если он в группе) или прочих.
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td)
            t.extra = {"strictmodes": "no"}  # проверяется только доступ по битам
            key = t.root / "home/user/.ssh/authorized_keys"
            real_stat = os.stat
            foreign = {"gid": 4242, "mode": 0o640}

            def fake_stat(path, *args, **kwargs):
                st = real_stat(path, *args, **kwargs)
                if str(path) == str(key):
                    return os.stat_result((stat.S_IFREG | foreign["mode"], st.st_ino, st.st_dev, st.st_nlink,
                                           4444, foreign["gid"]) + tuple(st)[6:])
                return st

            with mock.patch.object(A.os, "stat", fake_stat):
                self.assertEqual(A.admin_access(str(t.root), t.run, ["user"])[0], [("user", False, True)])
                with (t.root / "etc/group").open("a", encoding="utf-8") as stream:
                    stream.write("keys:x:4242:user\n")
                self.assertEqual(A.admin_access(str(t.root), t.run, ["user"])[0], [("user", True, True)])
                foreign["gid"], foreign["mode"] = 4343, 0o644
                self.assertEqual(A.admin_access(str(t.root), t.run, ["user"])[0], [("user", True, True)])

    def test_symlinked_home_is_checked_on_real_path(self):
        # M-03: /home — ссылка; проверяются каталоги фактического пути, а не записанного.
        me, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as td:
            t = Tree(td, key=None)
            t.extra = {"strictmodes": "no"}
            add_key(t.root, "srv/home/user")
            (t.root / "home").symlink_to(t.root / "srv/home")
            srv = os.path.realpath(t.root / "srv")
            with self._stat_override({srv: (0o700, 4444, 4444)}):
                self.assertEqual(A.admin_access(str(t.root), t.run, ["user"])[0], [("user", False, True)])
            self.assertEqual(A.admin_access(str(t.root), t.run, ["user"])[0], [("user", True, True)])

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
