#!/usr/bin/env python3
"""product-v1 tests for the tracked unified product CLI generator."""
import ast
import contextlib
import errno
import io
import hashlib
import importlib.util
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = ROOT / "product" / "generate-product-check-v2.py"
FILESET_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-optional-file-root-files-mode-check-v1.py"
SHADOW_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-local-account-password-state-check-v2.py"
USER_CRON_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-user-cron-files-mode-check-v2.py"
STANDARD_PATHS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-standard-system-paths-mode-check-v2.py"
SUID_SGID_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-suid-sgid-applications-check-v2.py"
HOME_SENSITIVE_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-home-sensitive-files-mode-check-v2.py"
HOME_DIRECTORIES_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-home-directories-mode-check-v2.py"
SSHD_ROOT_LOGIN_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-sshd-root-login-check-v1.py"
PAM_WHEEL_ACCESS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-pam-wheel-access-check-v2.py"
SUDOERS_REVIEWED_POLICY_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-sudoers-reviewed-policy-check-v1.py"
RUNNING_PROCESS_PATHS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-running-process-paths-write-protection-check-v1.py"
CRON_COMMAND_PATHS_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-cron-command-paths-write-protection-check-v1.py"
SUDO_ROOT_COMMAND_FILES_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-sudo-root-command-files-protection-check-v2.py"
STARTUP_FILES_ADAPTER_PATH = ROOT / "product" / "adapters" / "product-startup-files-write-protection-check-v1.py"
BASH = shutil.which("bash")
# Ширины колонок current/required для pretty-таблиц CHECK и APPLY по ширине терминала.
CURRENT_REQUIRED_WIDTHS = {90: (12, 16), 100: (12, 18), 116: (16, 24), 139: (33, 26), 160: (33, 47)}

ERROR_REASON_RE = re.compile(r"^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$")

def assert_stable_error_record(testcase, text, expected_control=None, expected_reason=None):
    lines = [line for line in text.strip().splitlines() if line]
    testcase.assertTrue(lines, text)
    matches = []
    for line in lines:
        fields = line.split("\t")
        if len(fields) == 5 and fields[0] == "SLP-CHECK-V1" and fields[2] == "ERROR" and fields[4] == "ERROR":
            testcase.assertRegex(fields[3], ERROR_REASON_RE)
            testcase.assertNotEqual(fields[3], "-")
            matches.append(fields)
    testcase.assertTrue(matches, text)
    if expected_control is not None:
        testcase.assertTrue(any(fields[1] == expected_control for fields in matches), text)
    if expected_reason is not None:
        testcase.assertTrue(any(fields[3] == expected_reason for fields in matches), text)


def _od_vanish_shim_text(target):
    """Обёртка /usr/bin/od: выполняет настоящий od, затем удаляет `target`, если
    это последний позиционный аргумент вызова. Имитирует исчезновение файла
    между проверкой через `od` и повторным открытием для разбора (аудит Codex,
    коммит 6780086: партия REREAD_UNCHECKED)."""
    return (
        "#!/bin/bash\n"
        '/usr/bin/od "$@"; rc=$?\n'
        'if [[ ${@: -1} == %s ]]; then rm -f -- %s; fi\n'
        "exit $rc\n" % (shlex.quote(str(target)), shlex.quote(str(target)))
    )


def _od_swap_shim_text(target, new_content):
    """Обёртка /usr/bin/od: выполняет настоящий od над реально проверяемыми
    байтами, затем подменяет содержимое `target` на `new_content`, если это
    последний позиционный аргумент вызова. Имитирует подмену содержимого
    файла между проверкой через `od` и повторным открытием для разбора
    (аудит Codex, коммит 6780086: партия REREAD_UNCHECKED, содержательная
    подмена, не только исчезновение)."""
    return (
        "#!/bin/bash\n"
        '/usr/bin/od "$@"; rc=$?\n'
        'if [[ ${@: -1} == %s ]]; then printf %%s %s > %s; fi\n'
        "exit $rc\n"
    ) % (shlex.quote(str(target)), shlex.quote(new_content), shlex.quote(str(target)))


def _od_fail_after_prefix_for_target_shim_text(target):
    """Обёртка /usr/bin/od: для последнего позиционного аргумента, равного
    `target`, печатает часть корректных байт настоящего od, затем завершается
    ненулевым кодом (сбой ПОСЛЕ части префикса, не чистый EOF); для остальных
    целей выполняет настоящий od без изменений. В отличие от
    `_od_fail_after_prefix_shim_text()`, который ломает КАЖДЫЙ вызов od в
    блоке, эта версия воспроизводит сбой только у ВТОРОГО из двух файлов,
    проверяемых адаптером, — первый файл должен пройти проверку штатно
    (пробел теста: партия REREAD_UNCHECKED, аудит Codex 6780086..3215d1c)."""
    return (
        "#!/bin/bash\n"
        'if [[ ${@: -1} == %s ]]; then\n'
        '  /usr/bin/od "$@" | head -c 32\n'
        "  exit 7\n"
        "fi\n"
        'exec /usr/bin/od "$@"\n'
    ) % shlex.quote(str(target))


def _od_fail_after_prefix_shim_text():
    """Обёртка /usr/bin/od: печатает часть корректных байт настоящего od, затем
    завершается ненулевым кодом — имитирует сбой чтения посреди файла (не
    чистый EOF)."""
    return (
        "#!/bin/bash\n"
        '/usr/bin/od "$@" | head -c 32\n'
        "exit 7\n"
    )


def install_od_shim(block, tmp, shim_text):
    """Подменяет все вызовы /usr/bin/od в блоке обёрткой `shim_text`. Обёртка
    запускается через bash явным путём — временный каталог может быть
    смонтирован noexec."""
    shim = Path(tmp) / "od-shim"
    shim.write_text(shim_text, encoding="utf-8")
    assert "/usr/bin/od" in block
    return block.replace("/usr/bin/od", "%s %s" % (shlex.quote(BASH), shlex.quote(str(shim))))


def install_command_shim(block, tmp, command_path, shim_text, name="shim"):
    """Обобщение install_od_shim на произвольную команду (по её абсолютному
    пути, как она встречается в блоке, например /usr/bin/stat)."""
    shim = Path(tmp) / name
    shim.write_text(shim_text, encoding="utf-8")
    assert command_path in block
    return block.replace(command_path, "%s %s" % (shlex.quote(BASH), shlex.quote(str(shim))))


def _stat_fail_shim_text(target, message):
    """Обёртка /usr/bin/stat: для последнего позиционного аргумента, равного
    `target`, печатает сообщение об ошибке в формате GNU stat (LC_ALL=C) и
    завершается ненулевым кодом; для остальных целей выполняет настоящий stat."""
    return (
        "#!/bin/bash\n"
        'if [[ ${@: -1} == %s ]]; then\n'
        "  printf '%%s\\n' %s >&2\n"
        "  exit 1\n"
        "fi\n"
        'exec /usr/bin/stat "$@"\n'
    ) % (
        shlex.quote(str(target)),
        shlex.quote("/usr/bin/stat: cannot statx '%s': %s" % (target, message)),
    )


def _stat_vanish_shim_text(target):
    """Обёртка /usr/bin/stat: удаляет `target`, если это последний позиционный
    аргумент вызова, затем выполняет настоящий stat (который теперь получит
    подлинный ENOENT) — имитирует объект, обнаруженный `find`, но исчезнувший
    до классификации (TOCTOU)."""
    return (
        "#!/bin/bash\n"
        'if [[ ${@: -1} == %s ]]; then rm -f -- %s; fi\n'
        'exec /usr/bin/stat "$@"\n'
    ) % (shlex.quote(str(target)), shlex.quote(str(target)))


def load_generator():
    spec = importlib.util.spec_from_file_location("slp_product_generator", GEN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GEN = load_generator()


def load_generator_v2():
    path = ROOT / "product/generate-product-check-v2.py"
    spec = importlib.util.spec_from_file_location("slp_product_generator_v2", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GEN_V2_CURRENT = load_generator_v2()


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

def load_sshd_root_login_adapter():
    spec = importlib.util.spec_from_file_location("slp_sshd_root_login_adapter", SSHD_ROOT_LOGIN_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

SSHD_ROOT_LOGIN = load_sshd_root_login_adapter()


def load_pam_wheel_access_adapter():
    spec = importlib.util.spec_from_file_location("slp_pam_wheel_access_adapter", PAM_WHEEL_ACCESS_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PAM_WHEEL_ACCESS = load_pam_wheel_access_adapter()

def load_sudoers_reviewed_policy_adapter():
    spec = importlib.util.spec_from_file_location("slp_sudoers_reviewed_policy_adapter", SUDOERS_REVIEWED_POLICY_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

SUDOERS_REVIEWED_POLICY = load_sudoers_reviewed_policy_adapter()

def load_running_process_paths_adapter():
    spec = importlib.util.spec_from_file_location("slp_running_process_paths_adapter", RUNNING_PROCESS_PATHS_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

RUNNING_PROCESS_PATHS = load_running_process_paths_adapter()

def load_cron_command_paths_adapter():
    spec = importlib.util.spec_from_file_location("slp_cron_command_paths_adapter", CRON_COMMAND_PATHS_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

CRON_COMMAND_PATHS = load_cron_command_paths_adapter()

def load_sudo_root_command_files_adapter():
    spec = importlib.util.spec_from_file_location("slp_sudo_root_command_files_adapter", SUDO_ROOT_COMMAND_FILES_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

SUDO_ROOT_COMMAND_FILES = load_sudo_root_command_files_adapter()

def load_startup_files_adapter():
    spec = importlib.util.spec_from_file_location("slp_startup_files_adapter", STARTUP_FILES_ADAPTER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

STARTUP_FILES = load_startup_files_adapter()


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
        self.assertTrue({"sysctl", "file-mode-owner", "kernel-cmdline", "optional-file-root-files-mode", "local-account-password-state", "user-cron-files-mode", "standard-system-paths-mode", "running-process-paths-write-protection", "cron-command-paths-write-protection", "suid-sgid-applications", "home-sensitive-files-mode", "home-directories-mode", "sshd-root-login", "pam-wheel-access", "sudoers-reviewed-policy", "sudo-root-command-files-protection", "startup-files-write-protection"} <= set(adapters))
        self.assertEqual({c["parameter_kind"] for c in controls}, {"sysctl", "file-mode-owner", "kernel-cmdline", "optional-file-root-files-mode", "local-account-password-state", "user-cron-files-mode", "standard-system-paths-mode", "running-process-paths-write-protection", "cron-command-paths-write-protection", "suid-sgid-applications", "home-sensitive-files-mode", "home-directories-mode", "sshd-root-login", "pam-wheel-access", "sudoers-reviewed-policy", "sudo-root-command-files-protection", "startup-files-write-protection"})
        src0002 = [c for c in controls if c["index_id"] == "SRC-0002"]
        self.assertEqual(len(src0002), 1)
        self.assertEqual(
            (src0002[0]["parameter_kind"], src0002[0]["parameter_locator"], src0002[0]["parameter_key"], src0002[0]["expected_op"], src0002[0]["expected_value"]),
            ("sshd-root-login", "/etc/ssh/sshd_config", "PermitRootLogin", "eq", "no"),
        )
        src0003 = [c for c in controls if c["index_id"] == "SRC-0003"]
        self.assertEqual(len(src0003), 1)
        self.assertEqual(
            (src0003[0]["parameter_kind"], src0003[0]["parameter_locator"], src0003[0]["parameter_key"], src0003[0]["expected_op"], src0003[0]["expected_value"]),
            ("pam-wheel-access", "/etc/pam.d/su|/etc/group", "policy", "pam-wheel-root-member", "auth required pam_wheel.so use_uid;wheel:root"),
        )
        src0004 = [c for c in controls if c["index_id"] == "SRC-0004"]
        self.assertEqual(len(src0004), 1)
        self.assertEqual(
            (src0004[0]["parameter_kind"], src0004[0]["parameter_locator"], src0004[0]["parameter_key"], src0004[0]["expected_op"], src0004[0]["expected_value"]),
            ("sudoers-reviewed-policy", "/etc/sudoers", "user-specs", "standard-rules-only", "root ALL=(ALL:ALL) ALL;%sudo ALL=(ALL:ALL) ALL;%admin ALL=(ALL) ALL"),
        )
        src0006 = [c for c in controls if c["index_id"] == "SRC-0006"]
        self.assertEqual(len(src0006), 1)
        self.assertEqual(
            (src0006[0]["parameter_kind"], src0006[0]["parameter_locator"], src0006[0]["parameter_key"], src0006[0]["expected_op"], src0006[0]["expected_value"]),
            ("running-process-paths-write-protection", "/proc/<pid>/exe|/proc/<pid>/maps", "write-protection", "runtime-paths-safe", "file-go-w;parent-unprivileged-write-denied"),
        )
        src0008 = [c for c in controls if c["index_id"] == "SRC-0008"]
        self.assertEqual(len(src0008), 1)
        self.assertEqual(
            (src0008[0]["parameter_kind"], src0008[0]["parameter_locator"], src0008[0]["parameter_key"], src0008[0]["expected_op"], src0008[0]["expected_value"]),
            ("sudo-root-command-files-protection", "/etc/sudoers", "root-command-files", "root-owned-go-w-conditional", "owner-if-regular-user;go-w-if-other-write"),
        )
        src0009 = [c for c in controls if c["index_id"] == "SRC-0009"]
        self.assertEqual(len(src0009), 1)
        self.assertEqual(
            (src0009[0]["parameter_kind"], src0009[0]["parameter_locator"], src0009[0]["parameter_key"], src0009[0]["expected_op"], src0009[0]["expected_value"]),
            ("startup-files-write-protection", "/etc/rc[0-6].d|systemd-unit-paths", "other-write", "bits-clear", "0002"),
        )
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
            ("user-cron-files-mode", "/var/spool/cron/crontabs", "mode", "bits-clear", "0022"),
        )
        src0012 = [c for c in controls if c["index_id"] == "SRC-0012"]
        self.assertEqual(len(src0012), 1)
        self.assertEqual(
            (src0012[0]["parameter_kind"], src0012[0]["parameter_locator"], src0012[0]["parameter_key"], src0012[0]["expected_op"], src0012[0]["expected_value"]),
            ("standard-system-paths-mode", "/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>", "mode", "bits-clear", "0022"),
        )
        src0013 = [c for c in controls if c["index_id"] == "SRC-0013"]
        # 2.3.9: «белый» список в источнике — пример («например, если определён»),
        # не обязательный объект проверки; SRC-0013 закрывается одной проверкой прав.
        self.assertEqual(len(src0013), 1)
        self.assertEqual(
            (src0013[0]["parameter_kind"], src0013[0]["parameter_locator"], src0013[0]["parameter_key"], src0013[0]["expected_op"], src0013[0]["expected_value"]),
            ("suid-sgid-applications", "/proc/self/mountinfo", "mode", "bits-clear", "0022"),
        )
        src0014 = [c for c in controls if c["index_id"] == "SRC-0014"]
        self.assertEqual(len(src0014), 1)
        self.assertEqual(
            (src0014[0]["parameter_kind"], src0014[0]["parameter_locator"], src0014[0]["parameter_key"], src0014[0]["expected_op"], src0014[0]["expected_value"]),
            # locator сменён с /etc/passwd на /home решением человека 23.09.2026
            # (популяция home-директорий — прямые элементы /home); authority-файл
            # убран из локатора тем же днём, шаг (б): имена — встроенный набор.
            ("home-sensitive-files-mode", "/home", "mode", "bits-clear", "0077"),
        )
        src0015 = [c for c in controls if c["index_id"] == "SRC-0015"]
        self.assertEqual(len(src0015), 1)
        self.assertEqual(
            (src0015[0]["parameter_kind"], src0015[0]["parameter_locator"], src0015[0]["parameter_key"], src0015[0]["expected_op"], src0015[0]["expected_value"]),
            # locator сменён с /etc/passwd на /home решением пользователя 22.09.2026
            # (популяция — прямые элементы /home, /etc/passwd не используется).
            ("home-directories-mode", "/home", "mode", "eq", "0700"),
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
        # 2.5.11 «после тестирования» — порядок действий администратора, не объект
        # проверки: SRC-0034 закрывается одной проверкой sysctl.
        self.assertEqual(len(src0034), 1)
        self.assertEqual(
            (src0034[0]["parameter_kind"], src0034[0]["parameter_locator"], src0034[0]["parameter_key"], src0034[0]["expected_op"], src0034[0]["expected_value"]),
            ("sysctl", "sysctl", "kernel.randomize_va_space", "eq", 2),
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

    def test_active_semantic_contract_error_values_and_historical_v1_status(self):
        lines = (ROOT / "product/ADAPTER-REGISTRY.tsv").read_text(encoding="utf-8").splitlines()
        header = lines[0].split("\t")
        active_paths = {
            dict(zip(header, line.split("\t")))["semantic_contract_path"]
            for line in lines[1:]
            if line
        }

        error_value_count = 0

        def inspect(value):
            nonlocal error_value_count
            if isinstance(value, dict):
                if value.get("status") == "ERROR" and "value" in value:
                    error_value_count += 1
                    self.assertEqual(value["value"], "<domain>:<reason>")
                for nested in value.values():
                    inspect(nested)
            elif isinstance(value, list):
                for nested in value:
                    inspect(nested)

        for relative in active_paths:
            contract = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            inspect(contract)
            wire_values = contract.get("wire_values", {})
            if "error" in wire_values:
                self.assertNotEqual(wire_values["error"], "-")

        self.assertEqual(error_value_count, 10)
        historical = {
            "product/contracts/sysctl-check-semantic-v1.json",
            "product/contracts/kernel-cmdline-check-semantic-v1.json",
            "product/contracts/local-account-password-state-check-semantic-v1.json",
        }
        self.assertTrue(historical.isdisjoint(active_paths))
        for relative in historical:
            contract = json.loads((ROOT / relative).read_text(encoding="utf-8"))
            self.assertEqual(contract.get("lifecycle_status"), "HISTORICAL_UNREGISTERED")

    def test_render_is_deterministic(self):
        _, manifest_sha, adapters, registry_sha, controls = self.load_current()
        generator_sha = sha256_file(GEN_PATH)
        one = GEN.render_script(controls, adapters, manifest_sha, registry_sha, generator_sha)
        two = GEN.render_script(controls, adapters, manifest_sha, registry_sha, generator_sha)
        self.assertEqual(one, two)
        self.assertIn(f"CONTROL_COUNT={len(controls)}".encode("ascii"), one)
        self.assertIn(f"ADAPTER_COUNT={len(adapters)}".encode("ascii"), one)
        self.assertIn(b"TOTAL=%d", one)
        self.assertIn(b"SLP-APPLY-REPORT-V2", one)
        self.assertIn(b"SERVICE_MANAGED_PARAMETER", one)
        self.assertIn("обнаружен штатный механизм".encode("utf-8"), one)
        self.assertIn("Автоматическое изменение пропущено. Требуется решение администратора.".encode("utf-8"), one)
        self.assertIn(b'decision.get("service")', one)
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
        self.assertIn(b"/usr/bin/stat -L -c %a", rendered)
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

        spec = importlib.util.spec_from_file_location("slp_kernel_cmdline_v2_raw", adapter_path)
        cmdline = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cmdline)
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            target = Path(td) / "cmdline"
            target.write_bytes(b"init_on_alloc=1\x00\n")
            block = cmdline.shell_function("CMD.RAW", "/proc/cmdline", "init_on_alloc", "eq", "1")
            block = block.replace(repr("/proc/cmdline"), repr(str(target)), 1)
            cp = subprocess.run(
                [BASH, "-c", "set -u\n" + block + "\nslp_check_CMD_RAW\n"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            self.assertEqual(cp.stdout.strip().split("\t")[2:], ["ERROR", "cmdline:invalid-bytes", "ERROR"])

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
            current = v2._model(*case)
            historical = v1._model(*case)
            self.assertEqual(current[0], historical[0], case)
            self.assertEqual(current[2], historical[2], case)
            if historical[2] == "ERROR":
                expected_reason = "cmdline:unexpected-value-form" if case[2] == "present" else "cmdline:ambiguous-value"
                self.assertEqual(current[1], expected_reason, case)
            else:
                self.assertEqual(current, historical, case)

    def test_error_reason_sources_do_not_collapse_distinct_failure_modes(self):
        forbidden = (
            "cron:observation-failed", "cron:discovery-failed",
            "startup:observation-failed", "target:observation-failed",
            "path:observation-failed", "scan:execution-failed",
            "sudo-policy:unsupported-semantics",
            "proc:invalid-stat", "proc:invalid-counter", "proc:invalid-population",
            "proc:ambiguous-no-exe", "proc:invalid-maps", "proc:invalid-exe",
            "observation:process-changed",
            "input:unreadable", "input:read-failed", "input:invalid-bytes",
            "pam:symlink-input", "pam:unreadable-input",
            '"population:incomplete"', '"cron-root:ancestor-invalid"',
            '"sshd-config:parse-failed"',
        )
        for path in sorted((ROOT / "product/adapters").glob("product-*.py")):
            text = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, text, f"{path}: {marker}")

    def test_error_reason_object_state_and_stage_pairs_are_distinct(self):
        expected = {
            "product-home-directories-mode-check-v2.py": (
                # B-02/B-03 (репарация, аудит Codex 6780086..3215d1c): тип
                # объекта — по `case "$_slp_stat_out" in` (вывод `stat -c %F`),
                # не по `[[ -L ]]`/`[[ ! -d ]]`, которые не отличают
                # доказанный тип от ошибки lstat.
                ("'symbolic link')", '"home-base:symlink"'),
                ("'symbolic link')", '"home-base:ancestor-symlink"'),
                ("directory) ;;", '"home-base:ancestor-invalid-type"'),
                ('[[ ! -x "$_slp_probe" ]]', '"home-base:ancestor-unsearchable"'),
                ("directory) ;;", '"home-base:invalid-type"'),
                ("printf -v _slp_reason 'home-base:stat-failed:%s'", "home-base:stat-failed"),
                ("printf -v _slp_reason 'home-base:ancestor-stat-failed:%s'", "home-base:ancestor-stat-failed"),
                ("printf -v _slp_reason 'home:not-directory:%s'", "home:invalid-name"),
                ("printf -v _slp_reason 'home:vanished:%s'", "home:stat-failed"),
            ),
            "product-home-sensitive-files-mode-check-v2.py": (
                # По прецеденту 2.3.11: тип прямого элемента /home — по
                # `case "$_slp_stat_out" in` (вывод `stat -c %F`), не по
                # `[[ -L ]]`/`[[ ! -d ]]`.
                ("'symbolic link')", '"home-base:symlink"'),
                ("'symbolic link')", '"home-base:ancestor-symlink"'),
                ("directory) ;;", '"home-base:ancestor-invalid-type"'),
                ('[[ ! -x "$_slp_probe" ]]', '"home-base:ancestor-unsearchable"'),
                ("directory) ;;", '"home-base:invalid-type"'),
                ("printf -v _slp_reason 'home-base:stat-failed:%s'", "home-base:stat-failed"),
                ("printf -v _slp_reason 'home-base:ancestor-stat-failed:%s'", "home-base:ancestor-stat-failed"),
                ("printf -v _slp_reason 'home:not-directory:%s'", "home:invalid-name"),
                ("printf -v _slp_reason 'home:vanished:%s'", "home:stat-failed"),
                ('[[ ! -r "$_slp_home" ]]', '"home:unreadable"'),
                ('[[ ! -x "$_slp_home" ]]', '"home:unsearchable"'),
                ('[[ -L "$_slp_entry" ]]', '"target:symlink"'),
            ),
            "product-optional-file-root-files-mode-check-v1.py": (
                ('[[ -L "$_slp_path" ]]', '"root:symlink"'),
                ('[[ ! -e "$_slp_parent" && ! -L "$_slp_parent" ]]', '"root:parent-not-found"'),
                ('[[ ! -d "$_slp_parent" ]]', '"root:parent-invalid-type"'),
                ('[[ ! -x "$_slp_parent" ]]', '"root:parent-unsearchable"'),
                ('"root:state-changed"', '"root:state-changed"'),
            ),
            "product-standard-system-paths-mode-check-v2.py": (
                ('_slp_exec == 0', '"population:missing-exec"'),
                ('_slp_libraries == 0', '"population:missing-libraries"'),
                ('_slp_modules == 0', '"population:missing-modules"'),
            ),
            "product-suid-sgid-applications-check-v2.py": (
                ('[[ -L "$_slp_mountinfo" ]]', '"mountinfo:symlink"'),
                ('[[ ! -e "$_slp_mountinfo" ]]', '"mountinfo:not-found"'),
                ('[[ ! -f "$_slp_mountinfo" ]]', '"mountinfo:invalid-type"'),
                ('[[ ! -r "$_slp_mountinfo" ]]', '"mountinfo:unreadable"'),
            ),
            "product-user-cron-files-mode-check-v2.py": (
                ('[[ -L "$_slp_probe" ]]', '"cron-root:ancestor-symlink"'),
                ('[[ ! -d "$_slp_probe" ]]', '"cron-root:ancestor-invalid-type"'),
                ('[[ ! -x "$_slp_probe" ]]', '"cron-root:ancestor-unsearchable"'),
            ),
            "product-sshd-root-login-check-v1.py": (
                ('_slp_parser_reason=sshd-config:include-depth', 'sshd-config:include-depth'),
                ('_slp_parser_reason=sshd-config:include-cycle', 'sshd-config:include-cycle'),
                ('_slp_parser_reason=sshd-config:include-glob-failed', 'sshd-config:include-glob-failed'),
                ('_slp_parser_reason=sshd-config:read-failed', 'sshd-config:read-failed'),
            ),
        }
        for filename, pairs in expected.items():
            text = (ROOT / "product" / "adapters" / filename).read_text(encoding="utf-8")
            for condition, reason in pairs:
                with self.subTest(filename=filename, condition=condition, reason=reason):
                    self.assertIn(condition, text)
                    self.assertIn(reason, text)
        for filename in (
            "product-cron-command-paths-write-protection-check-v1.py",
            "product-running-process-paths-write-protection-check-v1.py",
        ):
            text = (ROOT / "product" / "adapters" / filename).read_text(encoding="utf-8")
            self.assertIn('if (( _slp_rc != 0 )); then', text)
            self.assertIn('"observer:execution-failed"', text)
            self.assertIn('if [[ -z $_slp_obs ||', text)
            self.assertIn('"observer:invalid-output"', text)

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

    def _load_current_v2(self):
        rows, manifest_sha = GEN_V2_CURRENT.load_manifest(ROOT)
        adapters, registry_sha = GEN_V2_CURRENT.load_registry(ROOT)
        controls = [GEN_V2_CURRENT.load_control(ROOT, row) for row in rows]
        return rows, manifest_sha, adapters, registry_sha, controls

    def test_v2_shell_function_name_collision_is_rejected(self):
        _, manifest_sha, adapters, registry_sha, controls = self._load_current_v2()
        one_control = dict(controls[0]); two_control = dict(controls[0])
        one_control["control_id"] = "COLLIDE-A.B"
        two_control["control_id"] = "COLLIDE-A-B"
        with self.assertRaisesRegex(RuntimeError, "shell function name collision"):
            GEN_V2_CURRENT.render_script([one_control, two_control], adapters, manifest_sha, registry_sha, sha256_file(ROOT / "product/generate-product-check-v2.py"))

    def test_v2_quote_split_mutating_command_is_rejected(self):
        _, manifest_sha, adapters, registry_sha, controls = self._load_current_v2()
        control = dict(controls[0]); kind = control["parameter_kind"]
        original = adapters[kind]["module"].shell_function
        try:
            adapters[kind]["module"].shell_function = lambda *args: "slp_check_X(){ ch''mod 0600 /tmp/x; }\n"
            with self.assertRaisesRegex(RuntimeError, "mutating token"):
                GEN_V2_CURRENT.render_script([control], adapters, manifest_sha, registry_sha, sha256_file(ROOT / "product/generate-product-check-v2.py"))
        finally:
            adapters[kind]["module"].shell_function = original


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
            assert_stable_error_record(self, self.run_fileset(d).stdout, "TEST-FILESET", "target:invalid-type")
            target = base / "target"; target.write_text("x\n")
            link = base / "link"; link.symlink_to(target)
            assert_stable_error_record(self, self.run_fileset(link).stdout, "TEST-FILESET", "root:symlink")
            s = base / "symlink-child"; s.mkdir(); os.chmod(s, 0o700); (s / "l").symlink_to(target)
            assert_stable_error_record(self, self.run_fileset(s).stdout, "TEST-FILESET", "target:symlink")
            if hasattr(os, "mkfifo"):
                f = base / "special"; f.mkdir(); os.chmod(f, 0o700); os.mkfifo(f / "pipe")
                assert_stable_error_record(self, self.run_fileset(f).stdout, "TEST-FILESET", "target:invalid-type")

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
    def run_user_cron(self, roots, *, ordinary_user=False):
        source = USER_CRON._shell_function_for_roots("TEST-USER-CRON", [str(x) for x in roots])
        kwargs = {}
        if ordinary_user and os.geteuid() == 0:
            kwargs = {"user": 65534, "group": 65534, "extra_groups": []}
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_USER_CRON"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **kwargs,
        )

    def test_root_absent_is_empty_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "crontabs"
            cp = self.run_user_cron([root])
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            self.assertEqual(
                cp.stdout.strip(),
                "SLP-CHECK-V1\tTEST-USER-CRON\tVALUE\troots_present=0;roots_absent=1;checked=0;violations=0\tPASS",
            )

    def test_canonical_root_empty_and_direct_regular_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "crontabs"; root.mkdir()
            cp = self.run_user_cron([root])
            self.assertEqual(cp.stderr, "")
            self.assertIn("roots_present=1;roots_absent=0;checked=0;violations=0\tPASS", cp.stdout)

            user_file = root / "alice"; user_file.write_text("x\n", encoding="utf-8"); os.chmod(user_file, 0o640)
            self.assertIn("checked=1;violations=0\tPASS", self.run_user_cron([root]).stdout)
            os.chmod(user_file, 0o662)
            self.assertIn("checked=1;violations=1\tFAIL", self.run_user_cron([root]).stdout)

    def test_parent_spool_objects_are_not_user_cron_population(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); cron = base / "cron"; cron.mkdir(); crontabs = cron / "crontabs"; crontabs.mkdir()
            unrelated = cron / "unrelated"; unrelated.write_text("x\n", encoding="utf-8"); os.chmod(unrelated, 0o666)
            atjobs = cron / "atjobs"; atjobs.mkdir(); (atjobs / "job").write_text("x\n", encoding="utf-8")
            cp = self.run_user_cron([crontabs])
            self.assertEqual(cp.stderr, "")
            self.assertIn("checked=0;violations=0\tPASS", cp.stdout)

    def test_symlink_special_root_file_and_population_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            target = base / "target"; target.write_text("x\n", encoding="utf-8")
            root_link = base / "root-link"; root_link.symlink_to(base, target_is_directory=True)
            assert_stable_error_record(self, self.run_user_cron([root_link]).stdout, "TEST-USER-CRON")

            root = base / "crontabs"; root.mkdir(); (root / "link").symlink_to(target)
            assert_stable_error_record(self, self.run_user_cron([root]).stdout, "TEST-USER-CRON")
            (root / "link").unlink()

            if hasattr(os, "mkfifo"):
                os.mkfifo(root / "pipe")
                assert_stable_error_record(self, self.run_user_cron([root]).stdout, "TEST-USER-CRON")
                (root / "pipe").unlink()

            bad_root = base / "file-root"; bad_root.write_text("x\n", encoding="utf-8")
            assert_stable_error_record(self, self.run_user_cron([bad_root]).stdout, "TEST-USER-CRON")

            # v2 does not recurse into directory entries below the canonical root.
            locked = root / "locked"; locked.mkdir(); os.chmod(locked, 0)
            try:
                cp = self.run_user_cron([root])
                self.assertEqual(cp.stderr, "")
                self.assertIn("checked=0;violations=0\tPASS", cp.stdout)
            finally:
                os.chmod(locked, 0o700)

            # Inability to enumerate the canonical admitted root is observation ambiguity.
            if os.geteuid() == 0:
                os.chmod(base, 0o755)
            os.chmod(root, 0)
            try:
                cp = self.run_user_cron([root], ordinary_user=True)
                assert_stable_error_record(self, cp.stdout, "TEST-USER-CRON")
            finally:
                os.chmod(root, 0o700)

    def test_generation_rejects_wrong_contract_fields(self):
        good = "/var/spool/cron/crontabs"
        for args in (
            ("TEST", "/var/spool/cron", "mode", "bits-clear", "0022"),
            ("TEST", "/var/spool/cron|/var/spool/cron/crontabs", "mode", "bits-clear", "0022"),
            ("TEST", good, "owner", "bits-clear", "0022"),
            ("TEST", good, "mode", "eq", "0022"),
            ("TEST", good, "mode", "bits-clear", "0033"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    USER_CRON.shell_function(*args)


@unittest.skipIf(BASH is None, "bash not available")
class StandardSystemPathsModeFixtures(unittest.TestCase):
    def run_standard(self, exec_roots, lib_roots, module_root, *, ordinary_user=False):
        source = STANDARD_PATHS._shell_function_for_layout(
            "TEST-STANDARD-PATHS",
            [str(x) for x in exec_roots],
            [str(x) for x in lib_roots],
            str(module_root),
        )
        kwargs = {}
        if ordinary_user and os.geteuid() == 0:
            kwargs = {"user": 65534, "group": 65534, "extra_groups": []}
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_STANDARD_PATHS"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            **kwargs,
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

    def test_hardlinked_file_is_counted_once(self):
        # Дедупликация популяции по dev:ino: две ссылки на один инод дают один
        # объект. Значение сравнивается целиком, литералом.
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            linked = exe / "a-tool"; linked.write_text("x\n", encoding="utf-8"); os.chmod(linked, 0o755)
            os.link(linked, exe / "b-tool")
            cp = self.run_standard([exe], [lib], mod)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            self.assertIn(
                "roots_present=3;roots_absent=0;aliases=0;exec=2;libraries=1;modules=1;checked=4;violations=0\tPASS",
                cp.stdout,
            )
            os.chmod(linked, 0o775)
            cp = self.run_standard([exe], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertIn(
                "roots_present=3;roots_absent=0;aliases=0;exec=2;libraries=1;modules=1;checked=4;violations=1\tFAIL",
                cp.stdout,
            )
            # Тот же инод, видимый из другого корня, тоже считается один раз.
            os.link(linked, lib / "zz-hard.so")
            cp = self.run_standard([exe], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertIn(
                "roots_present=3;roots_absent=0;aliases=0;exec=2;libraries=1;modules=1;checked=4;violations=1\tFAIL",
                cp.stdout,
            )

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

    def test_additional_root_path_entry_is_in_population(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            extra = base / "usr-local-bin"; extra.mkdir()
            tool = extra / "local-tool"; tool.write_text("x\n", encoding="utf-8"); os.chmod(tool, 0o775)
            cp = self.run_standard([exe, extra], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertIn("exec=2", cp.stdout)
            self.assertIn("violations=1\tFAIL", cp.stdout)

    def test_non_executable_regular_file_under_exec_root_is_outside_population(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            data = exe / "README.data"; data.write_text("x\n", encoding="utf-8"); os.chmod(data, 0o664)
            cp = self.run_standard([exe], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertIn("exec=1;libraries=1;modules=1;checked=3;violations=0\tPASS", cp.stdout)

    def test_production_contract_reads_root_process_path(self):
        source = STANDARD_PATHS.shell_function(
            "TEST-STANDARD-PATHS", STANDARD_PATHS.CANONICAL_LOCATOR, "mode", "bits-clear", "0022"
        )
        self.assertIn("EUID != 0", source)
        self.assertIn("${PATH-}", source)
        self.assertIn("_slp_exec_roots+=(", source)
        semantic = json.loads((ROOT / "product/contracts/standard-system-paths-mode-check-semantic-v2.json").read_text(encoding="utf-8"))
        self.assertEqual(
            semantic["canonical_population"]["library_roots"],
            list(STANDARD_PATHS.CANONICAL_LIB_ROOTS),
        )

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
            assert_stable_error_record(self, cp.stdout, "TEST-STANDARD-PATHS")

    def test_exec_symlink_to_observed_exec_root_is_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            baseline = self.run_standard([exe], [lib], mod)
            self.assertEqual(baseline.stderr, "")
            self.assertIn("exec=1;libraries=1;modules=1;checked=3;violations=0\tPASS", baseline.stdout)

            own = exe / "X11"; own.symlink_to(exe, target_is_directory=True)
            cp = self.run_standard([exe], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertEqual(cp.stdout, baseline.stdout)

            other_root = base / "usr-sbin"; other_root.mkdir()
            tool2 = other_root / "tool2"; tool2.write_text("x\n", encoding="utf-8"); os.chmod(tool2, 0o755)
            cross_root = exe / "sbinlink"; cross_root.symlink_to(other_root, target_is_directory=True)
            cp = self.run_standard([exe, other_root], [lib], mod)
            self.assertEqual(cp.stderr, "")
            self.assertIn("exec=2;libraries=1;modules=1;checked=4;violations=0\tPASS", cp.stdout)
            cross_root.unlink()

    def test_directory_symlink_outside_exception_stays_error(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            outside = base / "other"; outside.mkdir()
            sub = exe / "sub"; sub.mkdir()
            cases = (
                (exe / "badlink", outside),
                (exe / "sublink", sub),
                (exe / "liblink", lib),
                (lib / "libroot.so", lib),
                (mod / "root.ko", mod),
            )
            for link, target in cases:
                with self.subTest(link=link.name):
                    link.symlink_to(target, target_is_directory=True)
                    try:
                        cp = self.run_standard([exe], [lib], mod)
                        self.assertEqual(cp.stderr, "")
                        assert_stable_error_record(self, cp.stdout, "TEST-STANDARD-PATHS", "target:invalid-type")
                    finally:
                        link.unlink()

    def test_missing_role_and_candidate_special_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            empty_mod = base / "empty-mod"; empty_mod.mkdir()
            cp = self.run_standard([exe], [lib], empty_mod)
            assert_stable_error_record(self, cp.stdout, "TEST-STANDARD-PATHS")
            if hasattr(os, "mkfifo"):
                os.mkfifo(exe / "pipe")
                cp = self.run_standard([exe], [lib], mod)
                assert_stable_error_record(self, cp.stdout, "TEST-STANDARD-PATHS")

    def test_traversal_error_fail_closed_for_ordinary_user(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            if os.geteuid() == 0:
                os.chmod(base, 0o755)
            locked = lib / "locked"; locked.mkdir(); os.chmod(locked, 0)
            try:
                cp = self.run_standard([exe], [lib], mod, ordinary_user=True)
                assert_stable_error_record(self, cp.stdout, "TEST-STANDARD-PATHS")
            finally:
                os.chmod(locked, 0o700)

    def test_python_dependency_failure_records(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            exe, lib, mod, *_ = self.make_layout(base)
            source = STANDARD_PATHS._shell_function_for_layout(
                "TEST-STANDARD-PATHS", [str(exe)], [str(lib)], str(mod))
            missing = base / "missing-python"
            nonexec = base / "nonexec-python"
            nonexec.write_bytes(b"#!/bin/sh\n")
            os.chmod(nonexec, 0o644)
            # Existing executable avoids requiring execution from temporary mounts.
            failing = Path("/usr/bin/false")
            self.assertTrue(os.access(failing, os.X_OK), str(failing))
            for path, reason in (
                (missing, "runtime:python3-missing"),
                (nonexec, "runtime:python3-missing"),
                (failing, "runtime:observer-failed"),
            ):
                with self.subTest(reason=reason, path=path.name):
                    # Substitute the interpreter only inside this temporary fixture.
                    self.assertEqual(source.count("/usr/bin/python3"), 2)
                    altered = source.replace("/usr/bin/python3", str(path))
                    cp = subprocess.run(
                        [BASH, "-p", "-c", altered + "\nslp_check_TEST_STANDARD_PATHS"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    self.assertEqual(cp.returncode, 0, cp.stderr)
                    self.assertEqual(cp.stderr, "")
                    self.assertEqual(cp.stdout,
                        "SLP-CHECK-V1\tTEST-STANDARD-PATHS\tERROR\t" + reason + "\tERROR\n")

    def test_observer_invalid_argument_count(self):
        cp = subprocess.run(
            ["/usr/bin/python3", "-I", "-S", "-B", "-", "TEST-STANDARD-PATHS",
             "0022", "1", "1"],
            input=STANDARD_PATHS._OBSERVER, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        self.assertEqual(cp.stdout,
            "SLP-CHECK-V1\tTEST-STANDARD-PATHS\tERROR\truntime:observer-arguments\tERROR\n")

    def test_error_vocabulary_matches_rendered_reasons(self):
        semantic = json.loads((ROOT /
            "product/contracts/standard-system-paths-mode-check-semantic-v2.json").read_text())
        source = STANDARD_PATHS.shell_function(
            "TEST-STANDARD-PATHS", STANDARD_PATHS.CANONICAL_LOCATOR,
            "mode", "bits-clear", "0022")
        reasons = set(re.findall(
            r"""["']((?:runtime|path|kernel|root|target|scan|population):[a-z0-9-]+)["']""",
            source))
        # resolve() constructs these reasons for its two caller roles.
        for role in ("root", "target"):
            for suffix in ("resolve-failed", "resolve-empty"):
                reasons.add(role + ":" + suffix)
        self.assertEqual(set(semantic["error_reasons"]), reasons)
        self.assertTrue(all(isinstance(v, str) and v for v in semantic["error_reasons"].values()))
        self.assertNotIn("target:mode-read-failed", reasons)
        self.assertNotIn("scan:invalid-marker", reasons)
        dependency = semantic["runtime_dependency"]
        self.assertEqual(dependency["path"], "/usr/bin/python3")
        self.assertEqual(dependency["error"], "runtime:python3-missing")
        guard = "if " + dependency["check"] + "; then"
        self.assertIn(guard, source)
        self.assertLess(source.index(guard), source.index("command /usr/bin/python3"))
        self.assertGreater(source.index(guard), source.index("command /usr/bin/uname -r"))

    def test_generation_rejects_wrong_contract_fields(self):
        good = "/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>"
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
            assert_stable_error_record(self, cp.stdout, "TEST-SUID-SGID", "allowlist:not-found")
            allow = base / "allowlist"
            allow.write_text("relative/path\n", encoding="utf-8")
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(allow))
            assert_stable_error_record(self, cp.stdout, "TEST-SUID-SGID", "allowlist:invalid-path")
            allow.unlink()
            allow.symlink_to(base / "missing-target")
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(allow))
            assert_stable_error_record(self, cp.stdout, "TEST-SUID-SGID", "allowlist:symlink")

    def test_nosuid_mount_is_included(self):
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
            self.assertEqual(cp.stderr, "")
            self.assertIn("mounts=1;checked=1;violations=1\tFAIL", cp.stdout)

    # Популяция SUID/SGID: ожидаемые значения-литералы на фикстурах (не паритет с
    # адаптером APPLY). Строка записи сравнивается целиком.
    def run_lines(self, base: Path, *mounts: str):
        """CHECK mode/bits-clear/0022 по mountinfo из строк вида (mountpoint, fstype)."""
        mountinfo = base / "mountinfo"
        mountinfo.write_text(
            "".join(f"{i} 0 0:{i} / {mp} rw,relatime - {fs} /dev/test rw\n"
                    for i, (mp, fs) in enumerate(mounts, start=1)),
            encoding="utf-8",
        )
        source = SUID_SGID._shell_function_for_fixture(
            "TEST-SUID-SGID", "mode", "bits-clear", "0022", str(mountinfo)
        )
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_SUID_SGID"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def assert_record(self, cp, value: str, status: str):
        self.assertEqual(cp.stderr, "")
        self.assertEqual(cp.stdout, f"SLP-CHECK-V1\tTEST-SUID-SGID\tVALUE\t{value}\t{status}\n")

    def suid(self, path: Path, mode: int):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")
        os.chmod(path, mode)
        return path

    def test_hardlinked_file_is_counted_once(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            app = self.suid(base / "app", 0o4755)
            os.link(app, base / "app-second-name")
            self.assert_record(self.run_lines(base, (str(base), "ext4")),
                               "mounts=1;checked=1;violations=0", "PASS")
            os.chmod(app, 0o4775)
            self.assert_record(self.run_lines(base, (str(base), "ext4")),
                               "mounts=1;checked=1;violations=1", "FAIL")

    def test_symlink_to_suid_file_is_not_in_population(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            app = self.suid(base / "app", 0o4755)
            os.symlink(app, base / "app-link")
            self.assert_record(self.run_lines(base, (str(base), "ext4")),
                               "mounts=1;checked=1;violations=0", "PASS")
            os.chmod(app, 0o4775)
            self.assert_record(self.run_lines(base, (str(base), "ext4")),
                               "mounts=1;checked=1;violations=1", "FAIL")

    def test_nested_directories_are_scanned(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self.suid(base / "top", 0o4755)
            self.suid(base / "a" / "b" / "deep", 0o2775)
            self.assert_record(self.run_lines(base, (str(base), "ext4")),
                               "mounts=1;checked=2;violations=1", "FAIL")

    def test_pseudo_filesystem_is_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self.suid(base / "real" / "app", 0o4755)
            self.suid(base / "pseudo" / "app", 0o4777)
            self.assert_record(
                self.run_lines(base, (str(base / "real"), "ext4"), (str(base / "pseudo"), "proc")),
                "mounts=1;checked=1;violations=0", "PASS")

    def test_pseudo_filesystem_only_is_an_error(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self.suid(base / "app", 0o4777)
            cp = self.run_lines(base, (str(base), "proc"))
            assert_stable_error_record(self, cp.stdout, "TEST-SUID-SGID", "mountinfo:empty-population")

    def test_duplicate_mount_point_is_counted_once(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self.suid(base / "app", 0o4775)
            self.assert_record(self.run_lines(base, (str(base), "ext4"), (str(base), "ext4")),
                               "mounts=1;checked=1;violations=1", "FAIL")

    def test_several_mount_points_are_all_scanned(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            self.suid(base / "m1" / "app", 0o4755)
            self.suid(base / "m2" / "app", 0o4775)
            self.suid(base / "outside", 0o4777)
            self.assert_record(
                self.run_lines(base, (str(base / "m1"), "ext4"), (str(base / "m2"), "xfs")),
                "mounts=2;checked=2;violations=1", "FAIL")

    def test_nul_in_allowlist_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            app = base / "app"; app.write_text("x\n", encoding="utf-8"); os.chmod(app, 0o4755)
            allow = base / "allowlist"
            allow.write_bytes(str(app).encode("utf-8") + b"\x00\n")
            cp = self.run_fixture(base, "approved-set", "subset-of-file", str(allow))
            assert_stable_error_record(self, cp.stdout, "TEST-SUID-SGID", "allowlist:invalid-bytes")

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
            passwd.write_bytes(passwd_text if isinstance(passwd_text, bytes) else passwd_text.encode("utf-8"))
            shadow.write_bytes(shadow_text if isinstance(shadow_text, bytes) else shadow_text.encode("utf-8"))
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
        assert_stable_error_record(self, cp.stdout, "TEST-SHADOW", "passwd:missing-shadow-account")
        cp = self.run_shadow("broken\n", "root:!:1:0:99999:7:::\n")
        assert_stable_error_record(self, cp.stdout, "TEST-SHADOW", "passwd:invalid-fields")

    def test_nul_and_cr_bytes_fail_closed(self):
        passwd = b"root:x:0:0:root:/root:/bin/bash\n"
        for shadow in (
            b"root:!:1:0:99999:7:::\x00\n",
            b"root:!:1:0:99999:7:::\r\n",
        ):
            with self.subTest(shadow=shadow):
                cp = self.run_shadow(passwd, shadow)
                assert_stable_error_record(self, cp.stdout, "TEST-SHADOW", "shadow:invalid-bytes")

    def test_unreadable_and_symlink_reason_domains_match_the_observed_file(self):
        src = SHADOW._shell_function_for_paths(
            "TEST-SHADOW", "/tmp/passwd", "/tmp/shadow",
            "password-field", "all-nonempty", True,
        )
        for marker in (
            '[[ -L "$_slp_passwd" ]]', '"passwd:symlink"',
            '[[ -L "$_slp_shadow" ]]', '"shadow:symlink"',
            '[[ ! -e "$_slp_passwd" ]]', '"passwd:not-found"',
            '[[ ! -f "$_slp_passwd" ]]', '"passwd:invalid-type"',
            '[[ ! -r "$_slp_passwd" ]]', '"passwd:unreadable"',
            '[[ ! -e "$_slp_shadow" ]]', '"shadow:not-found"',
            '[[ ! -f "$_slp_shadow" ]]', '"shadow:invalid-type"',
            '[[ ! -r "$_slp_shadow" ]]', '"shadow:unreadable"',
        ):
            self.assertIn(marker, src)

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
    """Популяция home-директорий — непосредственные (mindepth=1,maxdepth=1)
    элементы /home, /etc/passwd не используется (решение человека 23.09.2026,
    по прецеденту 2.3.11 / коммит 3215d1c). Проверяемые имена — замкнутый
    встроенный набор: восемь обязательных имён источника плюс
    COMMON_SHELL_BASENAMES, только непосредственные элементы каждого home;
    authority-файл не читается (решение человека 23.09.2026, шаг (б))."""

    # Восемь имён — прямая цитата источника 2.3.10; литерал меняется только
    # явным решением.
    SOURCE_NAMES = (
        ".bash_history", ".history", ".sh_history", ".bash_profile",
        ".bashrc", ".profile", ".bash_logout", ".rhosts",
    )

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.home_base = self.base / "home"
        self.home_base.mkdir()
        self.root_home = self.home_base / "root"
        self.service_home = self.home_base / "service"
        self.user_home = self.home_base / "user"
        for h in (self.root_home, self.service_home, self.user_home): h.mkdir()

    def tearDown(self): self.tmp.cleanup()

    def run_check(self):
        block = HOME_SENSITIVE._shell_function_for_fixture("TEST.HOME", str(self.home_base))
        script = self.base / "check.sh"
        script.write_text(block + "\nslp_check_TEST_HOME\n", encoding="utf-8")
        return subprocess.run([BASH, str(script)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_check_runs_without_authority_file(self):
        self.assertFalse(hasattr(HOME_SENSITIVE, "CANONICAL_INVENTORY"))
        self.assertFalse(hasattr(HOME_SENSITIVE, "COMMON_SHELL_RELATIVE_PATTERNS"))
        block = HOME_SENSITIVE.shell_function("TEST.HOME", "/home", "mode", "bits-clear", "0077")
        self.assertNotIn("/etc/securelinux-policy", block)
        self.assertNotIn("inventory", block)
        p = self.user_home / ".bashrc"; p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o600)
        cp = self.run_check()
        self.assertEqual(cp.returncode, 0, cp.stderr); self.assertEqual(cp.stderr, "")
        self.assertEqual(cp.stdout.strip().split("\t")[2:],
                         ["VALUE", "homes=3;discovered=1;checked=1;violations=0", "PASS"])

    def test_mandatory_names_are_the_eight_source_names(self):
        self.assertEqual(HOME_SENSITIVE.MANDATORY_SOURCE_NAMES, self.SOURCE_NAMES)

    def test_violation_on_each_mandatory_name_fails(self):
        for name in self.SOURCE_NAMES:
            with self.subTest(name=name):
                p = self.user_home / name
                p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o640)
                cp = self.run_check()
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertIn("discovered=1;checked=1;violations=1\tFAIL", cp.stdout)
                p.unlink()

    def test_each_common_shell_basename_is_checked(self):
        self.assertTrue(HOME_SENSITIVE.COMMON_SHELL_BASENAMES)
        for name in HOME_SENSITIVE.COMMON_SHELL_BASENAMES:
            with self.subTest(name=name):
                p = self.user_home / name
                p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o644)
                cp = self.run_check()
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertIn("discovered=1;checked=1;violations=1\tFAIL", cp.stdout)
                p.unlink()

    def test_files_below_first_level_are_not_checked(self):
        for rel in (
            "sub/.bashrc",
            ".config/.profile",
            ".config/fish/config.fish",
            ".config/nushell/config.nu",
            ".config/xonsh/rc.xsh",
            ".local/share/fish/fish_history",
            ".elvish/rc.elv",
        ):
            with self.subTest(rel=rel):
                p = self.user_home / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o644)
                cp = self.run_check()
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertIn("homes=3;discovered=0;checked=0;violations=0\tPASS", cp.stdout)

    def test_positive_includes_service_home(self):
        for p in (self.root_home / ".bashrc", self.service_home / ".profile", self.user_home / ".bash_history"):
            p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o600)
        cp = self.run_check()
        self.assertEqual(cp.returncode, 0); self.assertEqual(cp.stderr, "")
        self.assertIn("homes=3;discovered=3;checked=3;violations=0\tPASS", cp.stdout)

    def test_service_home_sensitive_file_is_checked(self):
        p = self.service_home / ".bashrc"; p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o644)
        cp = self.run_check()
        self.assertIn("violations=1\tFAIL", cp.stdout)

    def test_vimrc_is_not_misclassified_as_shell_config(self):
        p = self.user_home / ".vimrc"; p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o644)
        cp = self.run_check()
        self.assertIn("discovered=0;checked=0;violations=0\tPASS", cp.stdout)

    def test_symlink_member_fails_closed(self):
        outside=self.base / "outside"; outside.write_text("x\n",encoding="utf-8")
        (self.user_home / ".bashrc").symlink_to(outside)
        assert_stable_error_record(self, self.run_check().stdout, "TEST.HOME", "target:symlink")

    def test_home_absent_is_pass_with_empty_population(self):
        shutil.rmtree(self.home_base)
        cp = self.run_check()
        self.assertEqual(cp.returncode, 0, cp.stderr); self.assertEqual(cp.stderr, "")
        self.assertIn("homes=0;discovered=0;checked=0;violations=0\tPASS", cp.stdout)

    def test_home_present_and_empty_is_pass_with_empty_population(self):
        for h in (self.root_home, self.service_home, self.user_home):
            h.rmdir()
        cp = self.run_check()
        self.assertIn("homes=0;discovered=0;checked=0;violations=0\tPASS", cp.stdout)

    def test_direct_home_symlink_entry_is_error(self):
        target = self.base / "real"; target.mkdir()
        self.user_home.rmdir()
        self.user_home.symlink_to(target, target_is_directory=True)
        cp = self.run_check()
        self.assertEqual(cp.returncode, 0, cp.stderr); self.assertEqual(cp.stderr, "")
        fields = cp.stdout.strip().split("\t")
        self.assertEqual(fields[2:], ["ERROR", "home:symlink:%s->%s" % (self.user_home, target), "ERROR"])

    def test_direct_home_non_directory_entry_is_error(self):
        self.user_home.rmdir()
        self.user_home.write_text("x\n", encoding="utf-8")
        cp = self.run_check()
        self.assertEqual(cp.returncode, 0, cp.stderr); self.assertEqual(cp.stderr, "")
        fields = cp.stdout.strip().split("\t")
        self.assertEqual(fields[2:], ["ERROR", "home:not-directory:%s" % self.user_home, "ERROR"])

    def test_passwd_is_not_read_and_has_no_effect(self):
        # /etc/passwd не используется: адаптер не ссылается на него вовсе, и
        # реальный /etc/passwd с home= вне /home на результат не влияет.
        block = HOME_SENSITIVE._shell_function_for_fixture("TEST.HOME", str(self.home_base))
        self.assertNotIn("/etc/passwd", block)
        self.assertNotIn("_slp_passwd", block)
        p = self.user_home / ".bashrc"; p.write_text("x\n", encoding="utf-8"); os.chmod(p, 0o600)
        cp = self.run_check()
        self.assertIn("homes=3;discovered=1;checked=1;violations=0\tPASS", cp.stdout)

    def test_generation_rejects_wrong_contract_fields(self):
        good_locator = HOME_SENSITIVE.CANONICAL_HOME_BASE
        for args in (
            ("TEST", "/etc/passwd", "mode", "bits-clear", "0077"),
            ("TEST", "/home|/etc/securelinux-policy/home-sensitive-files-v1", "mode", "bits-clear", "0077"),
            ("TEST", good_locator, "owner", "bits-clear", "0077"),
            ("TEST", good_locator, "mode", "eq", "0077"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError): HOME_SENSITIVE.shell_function(*args)

@unittest.skipIf(BASH is None, "bash not available")
class HomeDirectoriesModeAdapterFixtures(unittest.TestCase):
    """Популяция — непосредственные элементы /home, /etc/passwd не используется
    (решение пользователя 22.09.2026, по прецеденту archive/securelinux-ng.sh
    home_targets_scan)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.home = self.base / "home"
        self.home.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self, shim_command=None, shim_text=None):
        block = HOME_DIRECTORIES._shell_function_for_fixture("TEST.HOME.DIR", str(self.home))
        if shim_command is not None:
            block = install_command_shim(block, self.base, shim_command, shim_text)
        script = self.base / "check-home-dir.sh"
        script.write_text(block + "\nslp_check_TEST_HOME_DIR\n", encoding="utf-8")
        return subprocess.run([BASH, str(script)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def row(self, shim_command=None, shim_text=None):
        cp = self.run_check(shim_command, shim_text)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        fields = cp.stdout.strip().split("\t")
        self.assertEqual(len(fields), 5, cp.stdout)
        return tuple(fields[2:])

    def test_0700_subdirectory_passes(self):
        (self.home / "user").mkdir(mode=0o700)
        self.assertEqual(self.row(), ("VALUE", "checked=1;violations=0", "PASS"))

    def test_0750_subdirectory_fails(self):
        d = self.home / "user"
        d.mkdir(); os.chmod(d, 0o750)
        self.assertEqual(self.row(), ("VALUE", "checked=1;violations=1", "FAIL"))

    def test_multiple_entries_are_all_checked(self):
        (self.home / "a").mkdir(mode=0o700)
        b = self.home / "b"; b.mkdir(); os.chmod(b, 0o700)
        c = self.home / "c"; c.mkdir(); os.chmod(c, 0o755)
        self.assertEqual(self.row(), ("VALUE", "checked=3;violations=1", "FAIL"))

    def test_symlink_entry_is_error_with_path_and_readlink_target(self):
        target = self.home / "real"; target.mkdir(mode=0o700)
        link = self.home / "user"; link.symlink_to(target)
        status, value, compliance = self.row()
        self.assertEqual((status, compliance), ("ERROR", "ERROR"))
        self.assertEqual(value, "home:symlink:%s->%s" % (link, target))

    def test_symlink_entry_is_not_followed_for_type_classification(self):
        # цель — не каталог и лежит вне /home (не сама становится элементом
        # популяции); классификация обязана остаться "symlink", не "not-directory"
        target = self.base / "real-file"; target.write_text("x\n", encoding="utf-8")
        link = self.home / "user"; link.symlink_to(target)
        status, value, compliance = self.row()
        self.assertEqual((status, compliance), ("ERROR", "ERROR"))
        self.assertEqual(value, "home:symlink:%s->%s" % (link, target))

    def test_dangling_symlink_entry_still_shows_raw_target_text(self):
        # readlink() читает сохранённый текст цели независимо от того,
        # существует ли она; "не следовать" — про классификацию типа, не про readlink.
        link = self.home / "user"; link.symlink_to(self.home / "missing-target")
        status, value, compliance = self.row()
        self.assertEqual((status, compliance), ("ERROR", "ERROR"))
        self.assertEqual(value, "home:symlink:%s->%s" % (link, self.home / "missing-target"))

    def test_regular_file_entry_is_not_directory_error(self):
        f = self.home / "user"; f.write_text("x\n", encoding="utf-8")
        self.assertEqual(self.row(), ("ERROR", "home:not-directory:%s" % f, "ERROR"))

    def test_fifo_entry_is_not_directory_error(self):
        fifo = self.home / "user"
        os.mkfifo(fifo)
        self.assertEqual(self.row(), ("ERROR", "home:not-directory:%s" % fifo, "ERROR"))

    def test_home_absent_is_pass_with_empty_population(self):
        self.home.rmdir()
        self.assertEqual(self.row(), ("VALUE", "checked=0;violations=0", "PASS"))

    def test_home_present_and_empty_is_pass_with_empty_population(self):
        self.assertEqual(self.row(), ("VALUE", "checked=0;violations=0", "PASS"))

    def test_home_as_regular_file_is_error(self):
        self.home.rmdir()
        self.home.write_text("x\n", encoding="utf-8")
        self.assertEqual(self.row(), ("ERROR", "home-base:invalid-type", "ERROR"))

    def test_home_as_symlink_is_error(self):
        real = self.base / "real-home"; real.mkdir()
        self.home.rmdir()
        self.home.symlink_to(real, target_is_directory=True)
        self.assertEqual(self.row(), ("ERROR", "home-base:symlink", "ERROR"))

    def test_passwd_home_field_has_no_effect(self):
        # /etc/passwd не используется: учётная запись с home=/bin в реальном
        # /etc/passwd не влияет на результат (адаптер этот файл вообще не читает).
        (self.home / "user").mkdir(mode=0o700)
        block = HOME_DIRECTORIES._shell_function_for_fixture("TEST.HOME.DIR", str(self.home))
        self.assertNotIn("/etc/passwd", block)
        self.assertNotIn("_slp_passwd", block)
        self.assertEqual(self.row(), ("VALUE", "checked=1;violations=0", "PASS"))

    def test_entry_name_with_newline_is_invalid_name(self):
        # Ветка not-directory с LF в имени; TAB/CR/DEL и остальные ветки
        # (включая совместимый каталог) — параметризованными тестами ниже
        # (B-01, repair-step по аудиту Codex диапазона 3215d1c..cc90fd6).
        bad = self.home / "user\nx"
        bad.write_text("x\n", encoding="utf-8")
        self.assertEqual(self.row(), ("ERROR", "home:invalid-name", "ERROR"))

    def test_generation_rejects_wrong_contract_fields(self):
        for args in (
            ("TEST", "/etc/passwd", "mode", "eq", "0700"),
            ("TEST", HOME_DIRECTORIES.CANONICAL_LOCATOR, "owner", "eq", "0700"),
            ("TEST", HOME_DIRECTORIES.CANONICAL_LOCATOR, "mode", "bits-clear", "0700"),
            ("TEST", HOME_DIRECTORIES.CANONICAL_LOCATOR, "mode", "eq", "0750"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    HOME_DIRECTORIES.shell_function(*args)

    # --- B-02 (repair-step, аудит Codex диапазона 6780086..3215d1c) ---------
    # [[ ! -e ]]/[[ -L ]]/[[ ! -d ]] не отличают ENOENT от иных ошибок lstat
    # (EIO, ENAMETOOLONG, EACCES-не-на-предке и т. п.): не сумев доказать
    # существование, старый код трактовал ЛЮБУЮ такую ошибку как «объекта
    # нет» и либо уходил в PASS по пустой популяции (корень), либо в
    # home:not-directory (элемент). Обёртка /usr/bin/stat детерминированно
    # эмулирует конкретный отказ без реальной гонки/длины пути.

    def test_home_base_stat_failure_other_than_enoent_is_error_not_pass(self):
        # /home физически присутствует и полон, но сам stat(/home) не может
        # подтвердить это (не ENOENT) — молчаливый PASS был бы гонкой с
        # неполной популяцией.
        (self.home / "user").mkdir(mode=0o700)
        shim = _stat_fail_shim_text(self.home, "Permission denied")
        status, value, compliance = self.row("/usr/bin/stat", shim)
        self.assertEqual((status, compliance), ("ERROR", "ERROR"))
        self.assertTrue(value.startswith("home-base:stat-failed:"), value)
        self.assertIn(str(self.home), value)

    def test_element_stat_failure_other_than_enoent_is_error_not_not_directory(self):
        entry = self.home / "user"
        entry.write_text("x\n", encoding="utf-8")  # был бы home:not-directory без правки
        shim = _stat_fail_shim_text(entry, "Permission denied")
        status, value, compliance = self.row("/usr/bin/stat", shim)
        self.assertEqual((status, compliance), ("ERROR", "ERROR"))
        self.assertNotIn("not-directory", value)
        self.assertTrue(value.startswith("home:stat-failed:"), value)
        self.assertIn(str(entry), value)

    def test_element_vanishing_before_classification_is_error_not_not_directory(self):
        # find уже увидел объект; TOCTOU-исчезновение перед классификацией —
        # не «не каталог», а отдельная, честная причина.
        entry = self.home / "user"
        entry.write_text("x\n", encoding="utf-8")
        shim = _stat_vanish_shim_text(entry)
        status, value, compliance = self.row("/usr/bin/stat", shim)
        self.assertEqual((status, compliance), ("ERROR", "ERROR"))
        self.assertNotIn("not-directory", value)
        self.assertFalse(entry.exists(), "сбой не внедрён")

    def test_element_stat_enoent_is_error_not_silently_dropped(self):
        # Убеждаемся, что вариант ENOENT для уже найденного элемента тоже не
        # приводит к тихому исключению объекта из популяции.
        entry = self.home / "user"
        entry.write_text("x\n", encoding="utf-8")
        shim = _stat_vanish_shim_text(entry)
        cp = self.run_check("/usr/bin/stat", shim)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        fields = cp.stdout.strip().split("\t")
        self.assertEqual(fields[2], "ERROR", cp.stdout)
        self.assertNotIn("checked=0", cp.stdout)
        self.assertNotIn("checked=1;violations=0", cp.stdout)

    def test_home_ancestor_stat_failure_other_than_enoent_is_error(self):
        # /home сам отсутствует (доказанный ENOENT), но пробник ближайшего
        # предка не может подтвердить даже это: ветка home-base:ancestor-
        # stat-failed раньше проверялась только статическим grep по тексту
        # адаптера (test_home_directories_mode_adapter_reason_strings),
        # без реального прогона через find/stat.
        self.home.rmdir()
        shim = _stat_fail_shim_text(self.base, "Permission denied")
        status, value, compliance = self.row("/usr/bin/stat", shim)
        self.assertEqual((status, compliance), ("ERROR", "ERROR"))
        self.assertTrue(value.startswith("home-base:ancestor-stat-failed:"), value)
        self.assertIn(str(self.base), value)

    # --- B-01 (repair-step, аудит Codex диапазона 3215d1c..cc90fd6) --------
    # Фильтр байт-опасного имени элемента проверял TAB/LF/CR, но не DEL
    # (0x7F), и срабатывал только в ветках error/symlink/not-directory —
    # совместимый каталог (mode-check) проходил без проверки вовсе. Цель
    # readlink байт-опасность не проверяла вовсе: TAB/LF/CR давали урезанный
    # `home:symlink:<path>` без цели, DEL — сырой control-байт прямо в
    # reason, ломающий `slp_collect_policy` (CHECK_INTERNAL_ERROR).

    BAD_NAME_BYTES = (("tab", "\t"), ("lf", "\n"), ("cr", "\r"), ("del", "\x7f"))

    def _clear_home(self):
        for child in sorted(self.home.iterdir(), reverse=True):
            if child.is_symlink() or not child.is_dir():
                child.unlink()
            else:
                child.rmdir()

    def test_control_byte_in_entry_name_is_invalid_name_on_directory_branch(self):
        for label, byte in self.BAD_NAME_BYTES:
            with self.subTest(byte=label):
                self._clear_home()
                (self.home / ("user" + byte + "x")).mkdir(mode=0o700)
                self.assertEqual(self.row(), ("ERROR", "home:invalid-name", "ERROR"))

    def test_control_byte_in_entry_name_is_invalid_name_on_symlink_branch(self):
        for label, byte in self.BAD_NAME_BYTES:
            with self.subTest(byte=label):
                self._clear_home()
                target = self.home / "real"; target.mkdir(mode=0o700)
                link = self.home / ("user" + byte + "x"); link.symlink_to(target)
                self.assertEqual(self.row(), ("ERROR", "home:invalid-name", "ERROR"))

    def test_control_byte_in_entry_name_is_invalid_name_on_not_directory_branch(self):
        for label, byte in self.BAD_NAME_BYTES:
            with self.subTest(byte=label):
                self._clear_home()
                f = self.home / ("user" + byte + "x"); f.write_text("x\n", encoding="utf-8")
                self.assertEqual(self.row(), ("ERROR", "home:invalid-name", "ERROR"))

    def test_control_byte_in_entry_name_is_invalid_name_on_error_branch(self):
        for label, byte in self.BAD_NAME_BYTES:
            with self.subTest(byte=label):
                self._clear_home()
                entry = self.home / ("user" + byte + "x"); entry.write_text("x\n", encoding="utf-8")
                shim = _stat_fail_shim_text(entry, "Permission denied")
                self.assertEqual(self.row("/usr/bin/stat", shim), ("ERROR", "home:invalid-name", "ERROR"))

    def test_control_byte_in_symlink_target_is_invalid_name(self):
        for label, byte in self.BAD_NAME_BYTES:
            with self.subTest(byte=label):
                self._clear_home()
                target = self.home / ("real" + byte + "x"); target.mkdir(mode=0o700)
                link = self.home / "user"; link.symlink_to(target)
                self.assertEqual(self.row(), ("ERROR", "home:invalid-name", "ERROR"))

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
        self.assertIn("единый product CLI", cp.stdout)
        self.assertEqual(self.run_check("--bogus").returncode, 2)
        self.assertEqual(self.run_check("--help", "extra").returncode, 2)

    def test_build_info(self):
        cp = self.run_check("--build-info")
        self.assertEqual(cp.returncode, 0)
        self.assertEqual(cp.stderr, "")
        self.assertIn("GENERATOR_ID=product-check-generator-v2\n", cp.stdout)
        rows, _, _, _, _ = load_current()
        self.assertIn(f"CONTROL_COUNT={len(rows)}\n", cp.stdout)
        self.assertIn(f"ADAPTER_COUNT={len(load_current()[2])}\n", cp.stdout)
        apply_mechanisms, _, _ = GEN_V2_CURRENT.load_apply_mechanisms(ROOT)
        expected_apply_kinds = ",".join(sorted(
            {m["kind_row"]["apply_kind"] for m in apply_mechanisms.values()},
            key=lambda x: x.encode("utf-8"),
        ))
        self.assertIn(f"APPLY_KINDS={expected_apply_kinds}\n", cp.stdout)
        apply_manifest_rows, _ = GEN_V2_CURRENT.load_manifest(ROOT)
        expected_apply_control_count = len([
            c for c in (GEN_V2_CURRENT.load_control(ROOT, row) for row in apply_manifest_rows)
            if c["apply_supported"]
        ])
        self.assertIn(f"APPLY_CONTROL_COUNT={expected_apply_control_count}\n", cp.stdout)
        self.assertIn(f"APPLY_IMPLEMENTATION_COUNT={len(apply_mechanisms)}\n", cp.stdout)
        self.assertIn("APPLY_KIND_REGISTRY_SHA256=", cp.stdout)

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


# Штатный /etc/pam.d/su Ubuntu 24.04 (util-linux 2.39.3, пакет login
# 1:4.13+dfsg1-4ubuntu3.2), побайтово; sha256 fda16622…7904.
UBUNTU_2404_STOCK_PAM_SU = (
    '#\n'
    "# The PAM configuration file for the Shadow `su' service\n"
    '#\n'
    '\n'
    '# This allows root to su without passwords (normal operation)\n'
    'auth       sufficient pam_rootok.so\n'
    '\n'
    '# Uncomment this to force users to be a member of group wheel\n'
    '# before they can use `su\'. You can also add "group=foo"\n'
    '# to the end of this line if you want to use a group other\n'
    '# than the default "wheel" (but this may have side effect of\n'
    '# denying "root" user, unless she\'s a member of "foo" or explicitly\n'
    '# permitted earlier by e.g. "sufficient pam_rootok.so").\n'
    "# (Replaces the `SU_WHEEL_ONLY' option from login.defs)\n"
    '# auth       required   pam_wheel.so\n'
    '\n'
    '# Uncomment this if you want wheel members to be able to\n'
    '# su without a password.\n'
    '# auth       sufficient pam_wheel.so trust\n'
    '\n'
    '# Uncomment this if you want members of a specific group to not\n'
    '# be allowed to use su at all.\n'
    '# auth       required   pam_wheel.so deny group=nosu\n'
    '\n'
    '# Uncomment and edit /etc/security/time.conf if you need to set\n'
    '# time restrainst on su usage.\n'
    "# (Replaces the `PORTTIME_CHECKS_ENAB' option from login.defs\n"
    '# as well as /etc/porttime)\n'
    '# account    requisite  pam_time.so\n'
    '\n'
    '# This module parses environment configuration file(s)\n'
    '# and also allows you to use an extended config\n'
    '# file /etc/security/pam_env.conf.\n'
    '# \n'
    '# parsing /etc/environment needs "readenv=1"\n'
    'session       required   pam_env.so readenv=1\n'
    '# locale variables are also kept into /etc/default/locale in etch\n'
    '# reading this file *in addition to /etc/environment* does not hurt\n'
    'session       required   pam_env.so readenv=1 envfile=/etc/default/locale\n'
    '\n'
    '# Defines the MAIL environment variable\n'
    '# However, userdel also needs MAIL_DIR and MAIL_FILE variables\n'
    '# in /etc/login.defs to make sure that removing a user \n'
    "# also removes the user's mail spool file.\n"
    '# See comments in /etc/login.defs\n'
    '#\n'
    '# "nopen" stands to avoid reporting new mail when su\'ing to another user\n'
    'session    optional   pam_mail.so nopen\n'
    '\n'
    '# Sets up user limits according to /etc/security/limits.conf\n'
    '# (Replaces the use of /etc/limits in old login)\n'
    'session    required   pam_limits.so\n'
    '\n'
    '# The standard Unix authentication modules, used with\n'
    '# NIS (man nsswitch) as well as normal /etc/passwd and\n'
    '# /etc/shadow entries.\n'
    '@include common-auth\n'
    '@include common-account\n'
    '@include common-session\n'
    '\n'
    '\n'
)


@unittest.skipIf(BASH is None, "bash not available")
class PamWheelAccessAdapterFixtures(unittest.TestCase):
    # Правило 2.2.1 (решение 23.09.2026): активная auth required pam_wheel.so
    # use_uid; auth sufficient pam_rootok.so перед ней не опасна; группа wheel
    # ищется по имени, gid любой; root в wheel, прочие участники не
    # оцениваются; authority-файл не читается.
    CONFIGURED_PAM = "auth sufficient pam_rootok.so\nauth required pam_wheel.so use_uid\n@include common-auth\n"
    PASS_1001 = ("VALUE", "pam_wheel=present;wheel=gid 1001;root=member", "PASS")

    def run_fixture(self, pam_text=None, group_text=None, symlink=None, prelude="", env=None):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            pam = root / "su"
            group = root / "group"
            if pam_text is not None:
                pam.write_bytes(pam_text if isinstance(pam_text, bytes) else pam_text.encode("utf-8"))
            if group_text is not None:
                group.write_bytes(group_text if isinstance(group_text, bytes) else group_text.encode("utf-8"))
            if symlink == "pam":
                target = root / "pam-real"
                target.write_text(pam_text or "", encoding="utf-8")
                if pam.exists():
                    pam.unlink()
                pam.symlink_to(target)
            elif symlink == "group":
                target = root / "group-real"
                target.write_text(group_text or "", encoding="utf-8")
                if group.exists():
                    group.unlink()
                group.symlink_to(target)
            block = PAM_WHEEL_ACCESS._shell_function_for_fixture("PAM.WHEEL.TEST", str(pam), str(group))
            cp = subprocess.run(
                [BASH, "-c", "set -u\n" + prelude + "\n" + block + "\nslp_check_PAM_WHEEL_TEST\n"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, env=env,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            row = cp.stdout.strip().split("\t")
            self.assertEqual(len(row), 5, cp.stdout)
            return row

    def verdict(self, *args, **kwargs):
        row = self.run_fixture(*args, **kwargs)
        return (row[2], row[3], row[4])

    # --- обязательные случаи задания 2.2.1 -------------------------------

    def test_stock_ubuntu_2404_su_without_wheel_is_fail(self):
        # gid 10 штатно занят uucp; payload не упоминает gid 10.
        self.assertEqual(
            self.verdict(UBUNTU_2404_STOCK_PAM_SU, "root:x:0:\nuucp:x:10:\n"),
            ("VALUE", "pam_wheel=absent;wheel=absent;root=missing", "FAIL"),
        )

    def test_rootok_then_wheel_use_uid_and_wheel_gid_1001_with_root_passes(self):
        self.assertEqual(
            self.verdict(self.CONFIGURED_PAM, "root:x:0:\nuucp:x:10:\nwheel:x:1001:root\n"),
            self.PASS_1001,
        )

    def test_stock_ubuntu_2404_su_with_uncommented_wheel_use_uid_passes(self):
        # Штатный файл, где администратор добавил строку ФСТЭК после pam_rootok.
        pam_text = UBUNTU_2404_STOCK_PAM_SU.replace(
            "auth       sufficient pam_rootok.so\n",
            "auth       sufficient pam_rootok.so\nauth       required   pam_wheel.so use_uid\n",
        )
        self.assertNotEqual(pam_text, UBUNTU_2404_STOCK_PAM_SU)
        self.assertEqual(self.verdict(pam_text, "uucp:x:10:\nwheel:x:1001:root,alice\n"), self.PASS_1001)

    def test_wheel_without_root_is_fail(self):
        self.assertEqual(
            self.verdict(self.CONFIGURED_PAM, "wheel:x:1001:alice\n"),
            ("VALUE", "pam_wheel=present;wheel=gid 1001;root=missing", "FAIL"),
        )
        self.assertEqual(
            self.verdict(self.CONFIGURED_PAM, "wheel:x:1001:\n"),
            ("VALUE", "pam_wheel=present;wheel=gid 1001;root=missing", "FAIL"),
        )

    def test_pam_wheel_without_use_uid_is_fail(self):
        for rule in ("auth required pam_wheel.so\n", "auth required pam_wheel.so trust\n", "auth required pam_wheel.so deny group=nosu\n"):
            with self.subTest(rule=rule):
                self.assertEqual(
                    self.verdict("auth sufficient pam_rootok.so\n" + rule, "wheel:x:1001:root\n"),
                    ("VALUE", "pam_wheel=no-use_uid;wheel=gid 1001;root=member", "FAIL"),
                )

    def test_pam_wheel_after_other_sufficient_module_is_error(self):
        for pam_text in (
            "auth sufficient pam_rootok.so\nauth sufficient pam_permit.so\nauth required pam_wheel.so use_uid\n",
            "auth sufficient pam_permit.so\nauth sufficient pam_rootok.so\nauth required pam_wheel.so use_uid\n",
        ):
            with self.subTest(pam_text=pam_text):
                self.assertEqual(
                    self.verdict(pam_text, "wheel:x:1001:root\n"),
                    ("ERROR", "pam:ambiguous-stack", "ERROR"),
                )

    def test_only_exact_rootok_line_is_exempt(self):
        for first in (
            "-auth sufficient pam_rootok.so\n",
            "auth sufficient /lib/security/pam_rootok.so\n",
            "auth sufficient pam_rootok.so debug\n",
            "auth [success=done default=ignore] pam_rootok.so\n",
        ):
            with self.subTest(first=first):
                self.assertEqual(
                    self.verdict(first + "auth required pam_wheel.so use_uid\n", "wheel:x:1001:root\n"),
                    ("ERROR", "pam:ambiguous-stack", "ERROR"),
                )

    def test_without_securelinux_policy_dir_is_not_error(self):
        block = PAM_WHEEL_ACCESS.shell_function(
            "CTRL", PAM_WHEEL_ACCESS.CANONICAL_LOCATOR, PAM_WHEEL_ACCESS.CANONICAL_KEY,
            PAM_WHEEL_ACCESS.CANONICAL_OP, PAM_WHEEL_ACCESS.CANONICAL_EXPECTED,
        )
        self.assertNotIn("/etc/securelinux-policy", block)
        self.assertNotIn("wheel-users", block)
        self.assertNotIn("authority", block)
        self.assertFalse(hasattr(PAM_WHEEL_ACCESS, "CANONICAL_AUTHORITY"))
        self.assertEqual(self.verdict(self.CONFIGURED_PAM, "wheel:x:1001:root\n"), self.PASS_1001)

    # --- прочие допустимые формы ------------------------------------------

    def test_positive_root_only_and_include_after_wheel(self):
        self.assertEqual(
            self.verdict(
                "# comment\nauth required pam_wheel.so use_uid # exact\n@include common-auth\n",
                "root:x:0:\nwheel:x:10:root\n",
            ),
            ("VALUE", "pam_wheel=present;wheel=gid 10;root=member", "PASS"),
        )

    def test_other_members_are_not_evaluated_and_crlf(self):
        self.assertEqual(
            self.verdict("auth required pam_wheel.so use_uid\r\n", "wheel:x:1001:alice,root,bob\r\n"),
            self.PASS_1001,
        )

    def test_any_wheel_gid_passes(self):
        for gid in ("10", "1234", "0"):
            with self.subTest(gid=gid):
                self.assertEqual(
                    self.verdict("auth required pam_wheel.so use_uid\n", "wheel:x:%s:root\n" % gid),
                    ("VALUE", "pam_wheel=present;wheel=gid %s;root=member" % gid, "PASS"),
                )

    def test_empty_group_password_field_is_not_a_source_predicate(self):
        self.assertEqual(self.verdict("auth required pam_wheel.so use_uid\n", "wheel::1001:root\n"), self.PASS_1001)

    def test_duplicate_exact_pam_rule_is_redundant_but_compliant(self):
        self.assertEqual(
            self.verdict("auth required pam_wheel.so use_uid\nauth required pam_wheel.so use_uid\n", "wheel:x:1001:root\n"),
            self.PASS_1001,
        )

    def test_escaped_line_continuation_preserves_exact_rule(self):
        self.assertEqual(self.verdict("auth required pam_wheel.so \\\nuse_uid\n", "wheel:x:1001:root\n"), self.PASS_1001)

    def test_comment_backslash_does_not_continue_comment_text(self):
        self.assertEqual(
            self.verdict("# disabled pam_wheel \\\nauth required pam_wheel.so use_uid\n", "wheel:x:1001:root\n"),
            self.PASS_1001,
        )

    # --- FAIL: чего не хватает --------------------------------------------

    def test_missing_pam_rule_with_wheel_and_root_is_fail(self):
        self.assertEqual(
            self.verdict("auth required pam_unix.so\n", "wheel:x:10:root\n"),
            ("VALUE", "pam_wheel=absent;wheel=gid 10;root=member", "FAIL"),
        )

    def test_missing_wheel_is_fail(self):
        self.assertEqual(
            self.verdict("auth required pam_wheel.so use_uid\n", "root:x:0:\n"),
            ("VALUE", "pam_wheel=present;wheel=absent;root=missing", "FAIL"),
        )

    def test_gid10_owner_is_not_reported(self):
        for group_text in ("custom:x:10:\n", "root:x:0:\n", "cus\ttom:x:10:\n", "cus\x7ftom:x:10:\n"):
            with self.subTest(group_text=group_text):
                self.assertEqual(
                    self.verdict("auth required pam_unix.so\n", group_text),
                    ("VALUE", "pam_wheel=absent;wheel=absent;root=missing", "FAIL"),
                )

    def test_wheel_with_non_default_gid_without_pam_rule_is_fail(self):
        self.assertEqual(
            self.verdict("auth required pam_unix.so\n", "wheel:x:999:root\n"),
            ("VALUE", "pam_wheel=absent;wheel=gid 999;root=member", "FAIL"),
        )

    def test_commented_out_pam_wheel_line_is_not_active(self):
        self.assertEqual(
            self.verdict("# auth required pam_wheel.so use_uid\nauth required pam_unix.so\n", "root:x:0:\n"),
            ("VALUE", "pam_wheel=absent;wheel=absent;root=missing", "FAIL"),
        )

    def test_stack_hazard_without_any_pam_wheel_is_fail(self):
        # Н-3: разобранный стек без pam_wheel.so — FAIL, не ERROR.
        for pam_text in (
            "auth sufficient pam_permit.so\n@include common-auth\n",
            "@include common-auth\n",
            "auth [success=done default=ignore] pam_permit.so\n",
        ):
            with self.subTest(pam_text=pam_text):
                self.assertEqual(
                    self.verdict(pam_text, "wheel:x:1001:root\n"),
                    ("VALUE", "pam_wheel=absent;wheel=gid 1001;root=member", "FAIL"),
                )

    # --- ERROR ------------------------------------------------------------

    def test_non_source_pam_wheel_variants_are_error(self):
        variants = (
            "auth required pam_wheel.so use_uid group=wheel\n",
            "auth sufficient pam_wheel.so use_uid\n",
            "auth required /lib/security/pam_wheel.so use_uid\n",
            "auth [success=ok default=bad] pam_wheel.so use_uid\n",
            "-auth required pam_wheel.so use_uid\n",
            "auth required pam_wheel.so use_uid\nauth required pam_wheel.so\n",
        )
        for pam_text in variants:
            with self.subTest(pam_text=pam_text):
                self.assertEqual(self.verdict(pam_text, "wheel:x:10:root\n"), ("ERROR", "pam:ambiguous-stack", "ERROR"))

    def test_prior_include_or_success_short_circuit_fails_closed(self):
        variants = (
            "@include permissive\nauth required pam_wheel.so use_uid\n",
            "auth sufficient pam_permit.so\nauth required pam_wheel.so use_uid\n",
            "-auth sufficient pam_permit.so\nauth required pam_wheel.so use_uid\n",
            "auth include permissive\nauth required pam_wheel.so use_uid\n",
            "-auth include permissive\nauth required pam_wheel.so use_uid\n",
            "auth substack permissive\nauth required pam_wheel.so use_uid\n",
            "auth [success=done default=ignore] pam_permit.so\nauth required pam_wheel.so use_uid\n",
        )
        for pam_text in variants:
            with self.subTest(pam_text=pam_text):
                self.assertEqual(self.verdict(pam_text, "wheel:x:10:root\n"), ("ERROR", "pam:ambiguous-stack", "ERROR"))

    def test_duplicate_or_malformed_wheel_is_error(self):
        for group_text, reason in (
            ("wheel:x:10:root\nwheel:x:11:root\n", "group:invalid-record"),
            ("wheel:x:not-a-gid:root\n", "group:invalid-record"),
            ("wheel:x:10:root,\n", "group:invalid-members"),
            ("wheel:x:10:root,root\n", "group:invalid-members"),
        ):
            with self.subTest(group_text=group_text):
                self.assertEqual(self.verdict("auth required pam_wheel.so use_uid\n", group_text), ("ERROR", reason, "ERROR"))

    def test_unicode_whitespace_in_names_is_locale_independent_error(self):
        locales = subprocess.run(["/usr/bin/locale", "-a"], capture_output=True, text=True, check=True).stdout.splitlines()
        utf8_locale = next((name for name in locales if name.lower() in {"c.utf8", "c.utf-8"}), None)
        self.assertIsNotNone(utf8_locale, locales)
        for group_text in ("wheel:x:10:root,user\u2003name\n", "wheel:x:10:root,user\u3000name\n"):
            observed = []
            for lc_all in ("C", utf8_locale):
                env = os.environ.copy()
                env["LC_ALL"] = lc_all
                row = self.run_fixture("auth required pam_wheel.so use_uid\n", group_text, env=env)
                observed.append(row)
                self.assertEqual((row[2], row[3], row[4]), ("ERROR", "group:invalid-members", "ERROR"))
            self.assertEqual(observed[0], observed[1])

    def test_symlink_inputs_fail_closed(self):
        for which, reason in {"pam": "pam:symlink", "group": "group:symlink"}.items():
            with self.subTest(which=which):
                self.assertEqual(
                    self.verdict("auth required pam_wheel.so use_uid\n", "wheel:x:10:root\n", symlink=which),
                    ("ERROR", reason, "ERROR"),
                )

    def test_nul_and_internal_cr_fail_closed(self):
        cases = (
            (b"auth required pam_wheel.so\x00 use_uid\n", b"wheel:x:10:root\n", "pam:invalid-bytes"),
            (b"auth required pam_wheel.so use_uid\nfoo\rbar\n", b"wheel:x:10:root\n", "pam:invalid-bytes"),
            (b"auth required pam_wheel.so use_uid\n", b"wheel:x:10:root\x00\n", "group:invalid-bytes"),
        )
        for pam_text, group_text, reason in cases:
            with self.subTest(pam_text=pam_text, group_text=group_text):
                self.assertEqual(self.verdict(pam_text, group_text), ("ERROR", reason, "ERROR"))

    def test_slash_named_od_function_cannot_override_nul_validation(self):
        row = self.run_fixture(
            b"auth required pam_wheel.so\x00 use_uid\n",
            b"wheel:x:10:root\n",
            prelude='function /usr/bin/od(){ printf "61 62 63\n"; }',
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_bare_cr_at_eof_is_error_for_all_pam_inputs(self):
        for pam_text, group_text in (
            (b"auth required pam_wheel.so use_uid\r", b"wheel:x:10:root\n"),
            (b"auth required pam_wheel.so use_uid\n", b"wheel:x:10:root\r"),
        ):
            with self.subTest(pam_text=pam_text, group_text=group_text):
                row = self.run_fixture(pam_text, group_text)
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_generated_cli_has_no_direct_external_tool_invocations(self):
        rendered = (ROOT / "securelinux-policy.sh").read_text(encoding="utf-8")
        forbidden = (
            "$(/usr/bin/", "$(/usr/sbin/", "LC_ALL=C /usr/bin/", "LC_ALL=C /usr/sbin/",
            '| LC_ALL=C /usr/bin/', '| LC_ALL=C /usr/sbin/',
            '  "$_slp_sshd" -t', '$("$_slp_sshd" -T', 'LC_ALL=C "$_slp_sort"',
        )
        for token in forbidden:
            self.assertNotIn(token, rendered, token)

    def test_missing_required_config_is_not_found_fail(self):
        row = self.run_fixture(None, "wheel:x:10:root\n")
        self.assertEqual((row[2], row[4]), ("NOT_FOUND", "FAIL"))

    def test_generation_rejects_wrong_contract_fields(self):
        m = PAM_WHEEL_ACCESS
        cases = (
            ("/etc/pam.d/su", m.CANONICAL_KEY, m.CANONICAL_OP, m.CANONICAL_EXPECTED),
            (m.CANONICAL_LOCATOR, "members", m.CANONICAL_OP, m.CANONICAL_EXPECTED),
            (m.CANONICAL_LOCATOR, m.CANONICAL_KEY, "eq-authority-file", m.CANONICAL_EXPECTED),
            (m.CANONICAL_LOCATOR, m.CANONICAL_KEY, m.CANONICAL_OP, "/etc/securelinux-policy/wheel-users.allowlist-v1"),
        )
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                m.shell_function("TEST", *args)


class SudoersReviewedPolicyAdapterFixtures(unittest.TestCase):
    # User_Specs below are the exact cvtsudoers -c /dev/null -e -s aliases -f json
    # output of sudo 1.9.15p5 for the named sudoers lines: the command ALL implies
    # SETENV, so every stock rule carries Options [{"setenv": true}].
    @staticmethod
    def _rule(invoker, groups, options=({"setenv": True},), commands=("ALL",)):
        spec = {"runasusers": [{"username": "ALL"}]}
        if groups:
            spec["runasgroups"] = [{"usergroup": "ALL"}]
        if options:
            spec["Options"] = [dict(o) for o in options]
        spec["Commands"] = [{"command": c} for c in commands]
        return {"User_List": [invoker], "Host_List": [{"hostname": "ALL"}], "Cmnd_Specs": [spec]}

    def root_rule(self):
        return self._rule({"username": "root"}, True)  # root ALL=(ALL:ALL) ALL

    def admin_rule(self):
        return self._rule({"usergroup": "admin"}, False)  # %admin ALL=(ALL) ALL

    def sudo_rule(self):
        return self._rule({"usergroup": "sudo"}, True)  # %sudo ALL=(ALL:ALL) ALL

    UBUNTU_2404_DEFAULTS = [
        {"Options": [{"env_reset": True}]},
        {"Options": [{"mail_badpass": True}]},
        {"Options": [{"secure_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"}]},
        {"Options": [{"use_pty": True}]},
    ]
    DEBIAN_12_DEFAULTS = [
        {"Options": [{"env_reset": True}]},
        {"Options": [{"mail_badpass": True}]},
        {"Options": [{"secure_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}]},
        {"Options": [{"use_pty": True}]},
    ]

    def ubuntu_2404_specs(self):
        return [self.root_rule(), self.admin_rule(), self.sudo_rule()]

    def debian_12_specs(self):
        return [self.root_rule(), self.sudo_rule()]

    def run_fixture(self, specs, defaults=None, visudo_rc=0, drift=None, cvt_rc=0, cvt_stderr=False, payload_text=None, members=("sudoers.d/README",)):
        if BASH is None:
            self.skipTest("bash not found")
        # dir=ROOT: a temporary /tmp may be mounted noexec, and the tool stubs are
        # executed by the adapter directly.
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            sudoers = root / "sudoers"
            sudoers.write_text("# stock sudoers fixture\n", encoding="utf-8")
            closure = [str(sudoers)]
            for rel in members:
                member = root / rel
                member.parent.mkdir(parents=True, exist_ok=True)
                member.write_text("# member\n", encoding="utf-8")
                closure.append(str(member))
            visudo_state = root / "visudo-state"
            cvt_state = root / "cvt-state"
            printed = "printf '%s\\n' " + " ".join(shlex.quote(p + ": parsed OK") for p in closure) + "\n"
            if visudo_rc:
                visudo_body = "printf '%s\\n' " + shlex.quote(str(sudoers) + ":1:1: syntax error") + "\nexit " + str(visudo_rc) + "\n"
            elif drift == "bytes":
                visudo_body = ("if [[ -e " + shlex.quote(str(visudo_state)) + " ]]; then printf '%s\\n' '# drift' >> "
                               + shlex.quote(str(sudoers)) + "; else : > " + shlex.quote(str(visudo_state)) + "; fi\n" + printed)
            elif drift == "pathset":
                extra = root / "drift-member"
                extra.write_text("# drift\n", encoding="utf-8")
                visudo_body = (printed + "if [[ -e " + shlex.quote(str(visudo_state)) + " ]]; then printf '%s\\n' "
                               + shlex.quote(str(extra) + ": parsed OK") + "; else : > " + shlex.quote(str(visudo_state)) + "; fi\n")
            else:
                visudo_body = printed
            fake_visudo = root / "visudo"
            fake_visudo.write_text(
                "#!/bin/bash\n[[ $# -eq 3 && \"$1\" == -c && \"$2\" == -f && \"$3\" == " + shlex.quote(str(sudoers)) + " ]] || exit 64\n" + visudo_body,
                encoding="utf-8")
            fake_visudo.chmod(0o755)
            payload_obj = {"User_Specs": specs}
            if defaults is not None:
                payload_obj["Defaults"] = defaults
            payload = payload_text if payload_text is not None else json.dumps(payload_obj, sort_keys=True)
            cvt_body = "printf '%s\\n' " + shlex.quote(payload) + "\n"
            if cvt_rc:
                cvt_body = "printf '%s\\n' 'conversion failed' >&2\nexit " + str(cvt_rc) + "\n"
            elif cvt_stderr:
                cvt_body = "printf '%s\\n' 'warning' >&2\n" + cvt_body
            elif drift == "cvt":
                changed = json.dumps({"User_Specs": specs + [self._rule({"username": "user1"}, False)]}, sort_keys=True)
                cvt_body = ("if [[ -e " + shlex.quote(str(cvt_state)) + " ]]; then printf '%s\\n' " + shlex.quote(changed)
                            + "; exit 0; fi\n: > " + shlex.quote(str(cvt_state)) + "\n" + cvt_body)
            fake_cvt = root / "cvtsudoers"
            fake_cvt.write_text(
                "#!/bin/bash\n[[ \"$*\" == " + shlex.quote("-c /dev/null -e -s aliases -f json " + str(sudoers)) + " ]] || exit 64\n" + cvt_body,
                encoding="utf-8")
            fake_cvt.chmod(0o755)
            src = SUDOERS_REVIEWED_POLICY.shell_function_for_fixture(
                "TEST-SUDOERS",
                SUDOERS_REVIEWED_POLICY.CANONICAL_LOCATOR,
                SUDOERS_REVIEWED_POLICY.CANONICAL_KEY,
                SUDOERS_REVIEWED_POLICY.CANONICAL_OP,
                SUDOERS_REVIEWED_POLICY.CANONICAL_EXPECTED,
                str(sudoers), str(fake_visudo), str(fake_cvt),
            )
            script = root / "run.sh"
            script.write_text("#!/bin/bash -p\n" + src + "\nslp_check_TEST_SUDOERS\n", encoding="utf-8")
            script.chmod(0o755)
            cp = subprocess.run([str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            rows = [line.split("\t") for line in cp.stdout.splitlines() if line.startswith("SLP-CHECK-V1\t")]
            self.assertEqual(len(rows), 1, cp.stdout + cp.stderr)
            return tuple(rows[0][2:])

    def test_adapter_selftest(self):
        cp = subprocess.run([str(SUDOERS_REVIEWED_POLICY_ADAPTER_PATH)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("ADAPTER_SELFTEST=PASS", cp.stdout)

    def test_canonical_expected_names_the_three_stock_rules(self):
        # The value changes only by an explicit decision; it is not derived.
        self.assertEqual(SUDOERS_REVIEWED_POLICY.CANONICAL_EXPECTED,
                         "root ALL=(ALL:ALL) ALL;%sudo ALL=(ALL:ALL) ALL;%admin ALL=(ALL) ALL")

    def test_ubuntu_2404_stock_sudoers_passes(self):
        # root ALL=(ALL:ALL) ALL, %admin ALL=(ALL) ALL, %sudo ALL=(ALL:ALL) ALL,
        # @includedir /etc/sudoers.d (README only).
        row = self.run_fixture(self.ubuntu_2404_specs(), defaults=self.UBUNTU_2404_DEFAULTS)
        self.assertEqual(row, ("VALUE", "rules=3;nonstandard=0", "PASS"))

    def test_debian_12_stock_sudoers_passes(self):
        # root ALL=(ALL:ALL) ALL, %sudo ALL=(ALL:ALL) ALL, @includedir /etc/sudoers.d.
        row = self.run_fixture(self.debian_12_specs(), defaults=self.DEBIAN_12_DEFAULTS)
        self.assertEqual(row, ("VALUE", "rules=2;nonstandard=0", "PASS"))

    def test_added_user_rule_fails(self):
        # user1 ALL=(ALL) ALL
        specs = self.ubuntu_2404_specs() + [self._rule({"username": "user1"}, False)]
        row = self.run_fixture(specs, defaults=self.UBUNTU_2404_DEFAULTS)
        self.assertEqual(row, ("VALUE", "rules=4;nonstandard=1", "FAIL"))

    def test_added_nopasswd_sudo_rule_fails(self):
        # %sudo ALL=(ALL:ALL) NOPASSWD: ALL
        nopasswd = self._rule({"usergroup": "sudo"}, True, options=({"authenticate": False}, {"setenv": True}))
        row = self.run_fixture(self.ubuntu_2404_specs() + [nopasswd], defaults=self.UBUNTU_2404_DEFAULTS)
        self.assertEqual(row, ("VALUE", "rules=4;nonstandard=1", "FAIL"))

    def test_other_group_commands_runas_and_tags_are_each_counted(self):
        specs = self.debian_12_specs() + [
            self._rule({"usergroup": "wheel"}, True),                                   # %wheel ALL=(ALL:ALL) ALL
            self._rule({"username": "bob"}, False, options=(), commands=("/usr/bin/true", "/usr/bin/false")),
            self._rule({"username": "root"}, False),                                    # root ALL=(ALL) ALL
            self._rule({"usergroup": "admin"}, True),                                   # %admin ALL=(ALL:ALL) ALL
            self._rule({"usergroup": "sudo"}, True, options=({"noexec": True}, {"setenv": True})),
        ]
        row = self.run_fixture(specs)
        self.assertEqual(row, ("VALUE", "rules=7;nonstandard=5", "FAIL"))

    def test_multi_user_line_is_one_nonstandard_rule(self):
        # root, user1 ALL=(ALL:ALL) ALL
        spec = self.root_rule()
        spec["User_List"].append({"username": "user1"})
        self.assertEqual(self.run_fixture([spec]), ("VALUE", "rules=1;nonstandard=1", "FAIL"))

    def test_defaults_are_not_evaluated(self):
        defaults = [{"Options": [{"authenticate": False}]}, {"Binding": [{"username": "user1"}], "Options": [{"runas_default": "user1"}]}]
        row = self.run_fixture(self.debian_12_specs(), defaults=defaults)
        self.assertEqual(row, ("VALUE", "rules=2;nonstandard=0", "PASS"))

    def test_no_user_specs_passes(self):
        self.assertEqual(self.run_fixture([], defaults=self.DEBIAN_12_DEFAULTS), ("VALUE", "rules=0;nonstandard=0", "PASS"))

    def test_without_policy_directory_is_not_error(self):
        src = SUDOERS_REVIEWED_POLICY.shell_function(
            "CTRL", SUDOERS_REVIEWED_POLICY.CANONICAL_LOCATOR, SUDOERS_REVIEWED_POLICY.CANONICAL_KEY,
            SUDOERS_REVIEWED_POLICY.CANONICAL_OP, SUDOERS_REVIEWED_POLICY.CANONICAL_EXPECTED)
        self.assertNotIn("securelinux-policy", src)
        self.assertNotIn("SLP-SUDOERS-REVIEWED-POLICY-V1", src)
        row = self.run_fixture(self.ubuntu_2404_specs(), defaults=self.UBUNTU_2404_DEFAULTS)
        self.assertNotEqual(row[0], "ERROR")

    def test_visudo_error_is_error(self):
        self.assertEqual(self.run_fixture(self.debian_12_specs(), visudo_rc=1), ("ERROR", "visudo:validation-failed", "ERROR"))

    def test_policy_drift_between_snapshots_is_error(self):
        for drift in ("bytes", "pathset", "cvt"):
            with self.subTest(drift=drift):
                self.assertEqual(self.run_fixture(self.debian_12_specs(), drift=drift), ("ERROR", "observation:policy-changed", "ERROR"))

    def test_cvtsudoers_failures_are_error(self):
        self.assertEqual(self.run_fixture(self.debian_12_specs(), cvt_rc=1), ("ERROR", "cvtsudoers:execution-failed", "ERROR"))
        self.assertEqual(self.run_fixture(self.debian_12_specs(), cvt_stderr=True), ("ERROR", "cvtsudoers:execution-failed", "ERROR"))
        self.assertEqual(self.run_fixture([], payload_text="{bad json"), ("ERROR", "cvtsudoers:invalid-output", "ERROR"))
        self.assertEqual(self.run_fixture([], payload_text='{"User_Specs": [], "Aliases": {}}'), ("ERROR", "cvtsudoers:invalid-output", "ERROR"))

    def test_unmodelled_user_spec_is_error(self):
        spec = self.root_rule()
        spec["Extra"] = 1
        self.assertEqual(self.run_fixture([spec]), ("ERROR", "sudo-policy:invalid-user-spec", "ERROR"))
        self.assertEqual(self.run_fixture(["root"]), ("ERROR", "sudo-policy:invalid-user-spec", "ERROR"))

    def test_generation_rejects_wrong_contract_fields(self):
        m = SUDOERS_REVIEWED_POLICY
        cases = (
            ("/etc/sudoers.d", m.CANONICAL_KEY, m.CANONICAL_OP, m.CANONICAL_EXPECTED),
            (m.CANONICAL_LOCATOR, "policy-tree", m.CANONICAL_OP, m.CANONICAL_EXPECTED),
            (m.CANONICAL_LOCATOR, m.CANONICAL_KEY, "eq-reviewed-policy", m.CANONICAL_EXPECTED),
            (m.CANONICAL_LOCATOR, m.CANONICAL_KEY, m.CANONICAL_OP, "/etc/securelinux-policy/sudoers-reviewed-policy-v1"),
        )
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                m.shell_function("TEST", *args)


class SudoRootCommandFilesProtectionFixtures(unittest.TestCase):
    @staticmethod
    def _user_spec(user="alice", runas="root", command="/bin/tool", negated=False, host_list=None):
        spec = {
            "User_List": [{"username": user}],
            "Host_List": host_list if host_list is not None else [{"hostname": "ALL"}],
            "Cmnd_Specs": [{"Commands": [{"command": command, **({"negated": True} if negated else {})}]}],
        }
        if runas is not None:
            spec["Cmnd_Specs"][0]["runasusers"] = [{"username": runas}]
        return spec

    def run_fixture(self, specs, mode=0o755, owner_regular=False, uid_sources=True, visudo_drift=None, visudo_rc=0, sudoers_members=(), cvt_rc=0, malformed_json=False, symlink=False, mutate_target_second_cvt=False, target_logical="/bin/tool", extra_executables=(), defaults=None, symlink_real_name=None, hardlink_real_name=None, target_bytes=None, real_fsroot=False):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot = Path("/") if real_fsroot else root / "fs"
            logical_target = Path(target_logical)
            if not logical_target.is_absolute():
                raise AssertionError("fixture target must be absolute")
            link_path = fsroot / str(logical_target).lstrip("/")
            if real_fsroot:
                # The target is an existing system file observed read-only.
                pass
            elif hardlink_real_name is not None:
                link_path.parent.mkdir(parents=True, exist_ok=True)
                target = link_path.with_name(hardlink_real_name)
                target.write_bytes(target_bytes if target_bytes is not None else b"\x7fELF-SLP-FIXTURE\n")
                target.chmod(mode)
                os.link(target, link_path)
            else:
                link_path.parent.mkdir(parents=True, exist_ok=True)
                target = link_path.with_name(symlink_real_name or (link_path.name + ".real")) if symlink else link_path
                target.write_bytes(target_bytes if target_bytes is not None else b"\x7fELF-SLP-FIXTURE\n")
                target.chmod(mode)
                if symlink:
                    link_path.symlink_to(target.name)
            for extra in extra_executables:
                if isinstance(extra, tuple):
                    extra, extra_mode = extra
                else:
                    extra_mode = 0o755
                extra_path = fsroot / str(extra).lstrip("/")
                extra_path.parent.mkdir(parents=True, exist_ok=True)
                extra_path.write_bytes(b"\x7fELF-SLP-FIXTURE\n")
                extra_path.chmod(extra_mode)
            # OWNER classification is decided from UID-range sources inside the
            # fixture root: the fixture owner is the running user, and the range
            # decides whether that owner counts as a regular user.
            etc = root / "fs" / "etc"
            etc.mkdir(parents=True, exist_ok=True)
            uid = os.getuid()
            low = uid if owner_regular else uid + 1
            high = low
            if uid_sources:
                (etc / "login.defs").write_text("UID_MIN\t%d\nUID_MAX\t%d\n" % (low, high), encoding="utf-8")
                (etc / "adduser.conf").write_text("FIRST_UID=%d\nLAST_UID=%d\n" % (low, high), encoding="utf-8")
            (etc / "passwd").write_text(
                "root:x:0:0:root:/root:/bin/sh\nslpfixture:x:%d:%d::/nonexistent:/bin/sh\n" % (uid, uid),
                encoding="utf-8")
            # No reviewed-policy authority exists: the sudoers pathset comes from
            # the visudo closure alone.
            sudoers = root / "sudoers"
            sudoers.write_text("Defaults env_reset\n", encoding="utf-8")
            members = []
            for name in sudoers_members:
                member = root / name
                member.parent.mkdir(parents=True, exist_ok=True)
                member.write_text("# member\n", encoding="utf-8")
                members.append(member)
            closure = [str(sudoers)] + [str(m) for m in members]
            visudo_state = root / "visudo-state"
            fake_visudo = root / "visudo"
            visudo_body = "printf '%s\\n' " + " ".join(shlex.quote(p + ": parsed OK") for p in closure) + "\n"
            if visudo_rc:
                visudo_body = "printf '%s\\n' " + shlex.quote(str(sudoers) + ":1:1: syntax error") + "\nexit " + str(visudo_rc) + "\n"
            elif visudo_drift is not None:
                extra_member = root / "drift-member"
                extra_member.write_text("# drift\n", encoding="utf-8")
                if visudo_drift == "bytes":
                    second = "printf '%s\\n' '# drift' >> " + shlex.quote(str(sudoers)) + "\n" + visudo_body
                elif visudo_drift == "pathset":
                    second = visudo_body + "printf '%s\\n' " + shlex.quote(str(extra_member) + ": parsed OK") + "\n"
                else:
                    raise AssertionError("unknown visudo drift")
                visudo_body = (
                    "if [[ -e " + shlex.quote(str(visudo_state)) + " ]]; then\n" + second + "else\n: > "
                    + shlex.quote(str(visudo_state)) + "\n" + visudo_body + "fi\n"
                )
            fake_visudo.write_text("#!/bin/bash\n" + visudo_body, encoding="utf-8")
            fake_visudo.chmod(0o755)
            fake_cvt = root / "cvtsudoers"
            state = root / "cvt-state"
            if malformed_json:
                body = "printf '%s\\n' '{bad json'\nexit 0"
            elif cvt_rc:
                body = "printf '%s\\n' 'conversion failed' >&2\nexit " + str(cvt_rc)
            else:
                payload_obj = {"User_Specs": specs}
                if defaults is not None:
                    payload_obj["Defaults"] = defaults
                payload = json.dumps(payload_obj, sort_keys=True)
                body = "printf '%s\\n' " + shlex.quote(payload)
                if mutate_target_second_cvt:
                    body = (
                        "if [[ -e " + shlex.quote(str(state)) + " ]]; then /usr/bin/chmod 0775 " + shlex.quote(str(target)) + "; "
                        "else : > " + shlex.quote(str(state)) + "; fi\n" + body
                    )
            fake_cvt.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8")
            fake_cvt.chmod(0o755)
            src = SUDO_ROOT_COMMAND_FILES.shell_function_for_fixture(
                "TEST-SUDO-ROOT-FILES",
                SUDO_ROOT_COMMAND_FILES.CANONICAL_LOCATOR,
                SUDO_ROOT_COMMAND_FILES.CANONICAL_KEY,
                SUDO_ROOT_COMMAND_FILES.CANONICAL_OP,
                SUDO_ROOT_COMMAND_FILES.CANONICAL_EXPECTED,
                str(fsroot), str(sudoers), str(fake_visudo), str(fake_cvt),
                str(etc / "login.defs") if real_fsroot else "/etc/login.defs",
                str(etc / "adduser.conf") if real_fsroot else "/etc/adduser.conf",
            )
            script = root / "run.sh"
            script.write_text("#!/bin/bash -p\n" + src + "\nslp_check_TEST_SUDO_ROOT_FILES\n", encoding="utf-8")
            script.chmod(0o755)
            cp = subprocess.run([str(script)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            rows = [line.split("\t") for line in cp.stdout.splitlines() if line.startswith("SLP-CHECK-V1\t")]
            self.assertEqual(len(rows), 1, cp.stdout + cp.stderr)
            return rows[0]

    def test_adapter_selftest(self):
        cp = subprocess.run([str(SUDO_ROOT_COMMAND_FILES_ADAPTER_PATH)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("ADAPTER_SELFTEST=PASS", cp.stdout)

    def test_non_regular_owner_without_other_write_passes(self):
        row = self.run_fixture([self._user_spec()])
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("files=1;owner_violations=0;mode_violations=0", row[3])

    @unittest.skipIf(os.getuid() == 0, "owner classification needs a non-root fixture owner")
    def test_regular_user_owner_is_fail(self):
        row = self.run_fixture([self._user_spec()], owner_regular=True)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("owner_violations=1", row[3])

    def test_group_write_alone_is_not_a_violation(self):
        # The source requires chmod go-w only where the file is writable by all
        # users, so the trigger is the other-write bit alone.
        row = self.run_fixture([self._user_spec()], mode=0o775)
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("mode_violations=0", row[3])

    def test_other_write_is_fail(self):
        row = self.run_fixture([self._user_spec()], mode=0o777)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("mode_violations=1", row[3])

    def test_symlink_final_target_is_checked(self):
        row = self.run_fixture([self._user_spec()], mode=0o777, symlink=True)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("mode_violations=1", row[3])

    @unittest.skipIf(os.getuid() == 0, "owner classification needs a non-root fixture owner")
    def test_missing_uid_range_sources_are_error(self):
        row = self.run_fixture([self._user_spec()], owner_regular=True, uid_sources=False)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "owner-classification:no-source")

    def test_command_with_arguments_is_error(self):
        row = self.run_fixture([self._user_spec(command="/bin/tool --flag value")])
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:unprovable-command-path")

    def test_pathname_with_whitespace_is_error_without_filesystem_guessing(self):
        row = self.run_fixture(
            [self._user_spec(command="/bin/my tool")],
            target_logical="/bin/my tool",
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:unprovable-command-path")

    def test_root_invoker_does_not_narrow_the_population(self):
        row = self.run_fixture([self._user_spec(user="root")], mode=0o777)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("files=1", row[3])

    def test_group_invoker_is_admitted_not_rejected(self):
        spec = self._user_spec()
        spec["User_List"] = [{"usergroup": "admins"}]
        row = self.run_fixture([spec], mode=0o777)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_structurally_invalid_user_list_is_error(self):
        spec = self._user_spec()
        spec["User_List"] = []
        row = self.run_fixture([spec])
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:invalid-user-list")

    def test_non_root_runas_gives_not_applicable(self):
        row = self.run_fixture([self._user_spec(runas="nobody")])
        self.assertEqual((row[2], row[4]), ("NOT_APPLICABLE", "NOT_APPLICABLE"))
        self.assertIn("files=0", row[3])

    def test_empty_population_with_unmodelled_defaults_is_error(self):
        # A determinate empty population may only be reported when the whole
        # policy document was understood; an unmodelled Defaults entry is not.
        row = self.run_fixture(
            [self._user_spec(runas="nobody")],
            defaults=[{"Options": "not-a-list"}],
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:invalid-options")

    def test_unbounded_and_dynamic_command_forms_are_error(self):
        cases = {
            "/opt/*/tool": "sudo-policy:wildcard-command",
            "^/usr/bin/[a-z]+$": "sudo-policy:regex-command",
            "relative": "sudo-policy:nonabsolute-command",
            "/opt/tools/": "sudo-policy:directory-command",
        }
        for command, reason in cases.items():
            with self.subTest(command=command):
                row = self.run_fixture([self._user_spec(command=command)])
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
                self.assertEqual(row[3], reason)

    def test_negated_command_is_error_not_overchecked(self):
        row = self.run_fixture([self._user_spec(command="/bin/tool", negated=True)], mode=0o777)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:negated-command")

    def test_command_digest_is_error_not_overchecked(self):
        spec = self._user_spec(command="/bin/tool")
        spec["Cmnd_Specs"][0]["Commands"][0]["sha256"] = "00" * 32
        row = self.run_fixture([spec], mode=0o777)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:digest-qualified-command")

    def test_host_qualified_rule_is_error_not_overchecked(self):
        row = self.run_fixture(
            [self._user_spec(host_list=[{"hostname": "definitely-other-host.invalid"}])],
            mode=0o777,
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:unsupported-host-selector")

    def test_ambiguous_runas_membership_is_error_not_overchecked(self):
        spec = self._user_spec()
        spec["Cmnd_Specs"][0]["runasusers"] = [{"usergroup": "admins"}]
        row = self.run_fixture([spec], mode=0o777)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:unsupported-runas-selector")

    def test_group_only_runas_is_error(self):
        # Runas_Spec (:group) without a user part runs the command as the
        # invoking user; the user part is what admits a rule, so a group-only
        # spec stays outside the supported determinate subset.
        spec = self._user_spec(runas=None)
        spec["Cmnd_Specs"][0]["runasgroups"] = [{"usergroup": "operators"}]
        row = self.run_fixture([spec], mode=0o777)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:unsupported-runas-group")

    def test_runas_group_next_to_user_part_is_not_error(self):
        # (ALL:ALL): admission is decided by the user part of Runas_Spec.
        for runas_user in ("ALL", "root"):
            with self.subTest(runas_user=runas_user):
                spec = self._user_spec(runas=runas_user, command="/usr/local/bin/x")
                spec["Cmnd_Specs"][0]["runasgroups"] = [{"usergroup": "ALL"}]
                row = self.run_fixture([spec], mode=0o757, target_logical="/usr/local/bin/x")
                self.assertEqual((row[2], row[3], row[4]), ("VALUE", "files=1;owner_violations=0;mode_violations=1", "FAIL"))
        spec = self._user_spec(runas="nobody", command="/usr/local/bin/x")
        spec["Cmnd_Specs"][0]["runasgroups"] = [{"usergroup": "ALL"}]
        row = self.run_fixture([spec], mode=0o757, target_logical="/usr/local/bin/x")
        self.assertEqual((row[2], row[4]), ("NOT_APPLICABLE", "NOT_APPLICABLE"))

    def test_all_command_is_skipped_not_error(self):
        # ALL names no concrete executable; the rights of system programs are
        # checked by 2.3.8.  Only explicit absolute pathnames enter the population.
        spec = self._user_spec(runas="ALL", command="ALL")
        row = self.run_fixture([spec], mode=0o757)
        self.assertEqual((row[2], row[3], row[4]), ("NOT_APPLICABLE", "files=0;owner_violations=0;mode_violations=0", "NOT_APPLICABLE"))
        spec = self._user_spec(runas="ALL", command="/usr/local/bin/x")
        spec["Cmnd_Specs"][0]["Commands"].insert(0, {"command": "ALL"})
        row = self.run_fixture([spec], mode=0o757, target_logical="/usr/local/bin/x")
        self.assertEqual((row[2], row[3], row[4]), ("VALUE", "files=1;owner_violations=0;mode_violations=1", "FAIL"))

    def test_ubuntu_2404_stock_sudoers_without_policy_dir_is_not_applicable(self):
        # cvtsudoers -e -s aliases -f json of the stock Ubuntu 24.04 /etc/sudoers:
        # root ALL=(ALL:ALL) ALL, %admin ALL=(ALL) ALL, %sudo ALL=(ALL:ALL) ALL,
        # @includedir /etc/sudoers.d (README only).  /etc/securelinux-policy is
        # absent; the result is a determinate empty population, not ERROR.
        def rule(invoker, groups):
            spec = {"runasusers": [{"username": "ALL"}], "Options": [{"setenv": True}], "Commands": [{"command": "ALL"}]}
            if groups:
                spec["runasgroups"] = [{"usergroup": "ALL"}]
            return {"User_List": [invoker], "Host_List": [{"hostname": "ALL"}], "Cmnd_Specs": [spec]}
        specs = [rule({"username": "root"}, True), rule({"usergroup": "admin"}, False), rule({"usergroup": "sudo"}, True)]
        defaults = [
            {"Options": [{"env_reset": True}]},
            {"Options": [{"mail_badpass": True}]},
            {"Options": [{"secure_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"}]},
            {"Options": [{"use_pty": True}]},
        ]
        row = self.run_fixture(specs, defaults=defaults, sudoers_members=("sudoers.d/README",))
        self.assertEqual((row[2], row[3], row[4]), ("NOT_APPLICABLE", "files=0;owner_violations=0;mode_violations=0", "NOT_APPLICABLE"))
        src = SUDO_ROOT_COMMAND_FILES.shell_function(
            "CTRL", SUDO_ROOT_COMMAND_FILES.CANONICAL_LOCATOR, SUDO_ROOT_COMMAND_FILES.CANONICAL_KEY,
            SUDO_ROOT_COMMAND_FILES.CANONICAL_OP, SUDO_ROOT_COMMAND_FILES.CANONICAL_EXPECTED)
        self.assertNotIn("/etc/securelinux-policy", src)
        self.assertNotIn("sudoers-reviewed-policy", src)

    def test_explicit_command_root_owner_0755_passes(self):
        # A real root-owned 0755 system file observed read-only through fsroot=/.
        st = os.stat("/usr/bin/true")
        if st.st_uid != 0 or (st.st_mode & 0o7777) != 0o755 or st.st_nlink != 1:
            self.skipTest("/usr/bin/true is not a root-owned 0755 single-link file here")
        row = self.run_fixture([self._user_spec(command="/usr/bin/true")], target_logical="/usr/bin/true", real_fsroot=True)
        self.assertEqual((row[2], row[3], row[4]), ("VALUE", "files=1;owner_violations=0;mode_violations=0", "PASS"))

    def test_explicit_local_command_0755_non_regular_owner_passes(self):
        row = self.run_fixture([self._user_spec(command="/usr/local/bin/x")], target_logical="/usr/local/bin/x")
        self.assertEqual((row[2], row[3], row[4]), ("VALUE", "files=1;owner_violations=0;mode_violations=0", "PASS"))

    @unittest.skipIf(os.getuid() == 0, "owner classification needs a non-root fixture owner")
    def test_explicit_local_command_regular_user_owner_fails(self):
        row = self.run_fixture([self._user_spec(command="/usr/local/bin/x")], target_logical="/usr/local/bin/x", owner_regular=True)
        self.assertEqual((row[2], row[3], row[4]), ("VALUE", "files=1;owner_violations=1;mode_violations=0", "FAIL"))

    def test_explicit_local_command_0757_fails(self):
        row = self.run_fixture([self._user_spec(command="/usr/local/bin/x")], target_logical="/usr/local/bin/x", mode=0o757)
        self.assertEqual((row[2], row[3], row[4]), ("VALUE", "files=1;owner_violations=0;mode_violations=1", "FAIL"))

    def test_visudo_validation_failure_is_error(self):
        row = self.run_fixture([self._user_spec()], visudo_rc=1)
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "visudo:validation-failed", "ERROR"))

    def test_sudoers_drift_between_snapshots_is_error(self):
        # The sudoers pathset and bytes come from the visudo closure; a change of
        # either between the two policy snapshots is ERROR.
        for drift in ("bytes", "pathset"):
            for command in ("/bin/tool", "ALL"):
                with self.subTest(drift=drift, command=command):
                    row = self.run_fixture([self._user_spec(command=command)], visudo_drift=drift)
                    self.assertEqual((row[2], row[3], row[4]), ("ERROR", "observation:policy-changed", "ERROR"))

    def test_cvtsudoers_failure_and_malformed_json_are_error(self):
        row = self.run_fixture([self._user_spec()], cvt_rc=1)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "cvtsudoers:execution-failed")
        row = self.run_fixture([self._user_spec()], malformed_json=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "cvtsudoers:invalid-output")

    def test_target_snapshot_drift_is_error(self):
        row = self.run_fixture([self._user_spec()], mutate_target_second_cvt=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "observation:target-changed")

    def test_temporal_command_window_is_error_not_overchecked(self):
        for option in ({"notafter": "20000101000000Z"}, {"notbefore": "29990101000000Z"}):
            with self.subTest(option=option):
                spec = self._user_spec()
                spec["Cmnd_Specs"][0]["Options"] = [option]
                row = self.run_fixture([spec], mode=0o777)
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
                self.assertEqual(row[3], "sudo-policy:time-qualified-command")

    def test_case_insensitive_user_default_override_is_error(self):
        row = self.run_fixture(
            [self._user_spec()],
            mode=0o777,
            defaults=[{"Options": [{"case_insensitive_user": False}]}],
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:case-insensitive-user-unsupported")

    def test_runas_default_is_error_not_overchecked(self):
        spec = self._user_spec(runas=None)
        row = self.run_fixture(
            [spec],
            mode=0o777,
            defaults=[{"Options": [{"runas_default": "nobody"}]}],
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:runas-default-unsupported")

    def test_runas_default_does_not_reject_an_empty_population(self):
        # Defaults that cannot affect an explicit non-root-only rule must not
        # turn a cleanly empty population into ERROR.
        row = self.run_fixture(
            [self._user_spec(runas="nobody")],
            defaults=[{"Options": [{"runas_default": "nobody"}]}],
        )
        self.assertEqual((row[2], row[4]), ("NOT_APPLICABLE", "NOT_APPLICABLE"))

    def test_runchroot_option_or_default_is_error(self):
        spec = self._user_spec()
        spec["Cmnd_Specs"][0]["Options"] = [{"runchroot": "/srv/chroot"}]
        row = self.run_fixture([spec])
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:runchroot-enabled")
        row = self.run_fixture(
            [self._user_spec()],
            defaults=[{"Options": [{"runchroot": "/srv/chroot"}]}],
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "sudo-policy:runchroot-enabled")

    def test_interpreter_target_is_checked_not_rejected(self):
        # The Cmnd target itself is checked; no downstream interpreter chain is
        # inferred, so an interpreter pathname is an ordinary target.
        for path in ("/bin/sh", "/usr/bin/env"):
            with self.subTest(path=path):
                row = self.run_fixture(
                    [self._user_spec(command=path)],
                    mode=0o777,
                    target_logical=path,
                )
                self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
                self.assertIn("files=1", row[3])

    def test_shebang_target_is_checked_not_rejected(self):
        row = self.run_fixture(
            [self._user_spec()],
            target_bytes=b"#!/opt/custominterp\nexit 0\n",
            extra_executables=(("/opt/custominterp", 0o755),),
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("files=1", row[3])

    def test_hardlink_alias_is_error(self):
        row = self.run_fixture(
            [self._user_spec()],
            target_logical="/bin/tool",
            hardlink_real_name="tool-original",
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "target:ambiguous-identity")

    def test_generation_rejects_wrong_contract_fields(self):
        bad = (
            ("/etc/sudoers|/etc/securelinux-policy/sudoers-reviewed-policy-v1", SUDO_ROOT_COMMAND_FILES.CANONICAL_KEY, SUDO_ROOT_COMMAND_FILES.CANONICAL_OP, SUDO_ROOT_COMMAND_FILES.CANONICAL_EXPECTED),
            (SUDO_ROOT_COMMAND_FILES.CANONICAL_LOCATOR, "mode", SUDO_ROOT_COMMAND_FILES.CANONICAL_OP, SUDO_ROOT_COMMAND_FILES.CANONICAL_EXPECTED),
            (SUDO_ROOT_COMMAND_FILES.CANONICAL_LOCATOR, SUDO_ROOT_COMMAND_FILES.CANONICAL_KEY, "eq", SUDO_ROOT_COMMAND_FILES.CANONICAL_EXPECTED),
            (SUDO_ROOT_COMMAND_FILES.CANONICAL_LOCATOR, SUDO_ROOT_COMMAND_FILES.CANONICAL_KEY, SUDO_ROOT_COMMAND_FILES.CANONICAL_OP, "0022"),
        )
        for args in bad:
            with self.assertRaises(ValueError):
                SUDO_ROOT_COMMAND_FILES.shell_function("TEST", *args)


class SshdRootLoginAdapterFixtures(unittest.TestCase):
    def run_fixture(
        self, config_text=None, effective="no", syntax_rc=0, include_files=None,
        make_symlink=False, shadow_compgen=False, sort_fail=False, env=None,
    ):
        if BASH is None:
            self.skipTest("bash not found")
        include_files = include_files or {}
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            cfg = root / "sshd_config"
            if config_text is not None:
                if isinstance(config_text, bytes):
                    cfg.write_bytes(config_text)
                else:
                    config_text = config_text.replace("/etc/ssh/TEST-INCLUDE.conf", str(root / "TEST-INCLUDE.conf"))
                    config_text = config_text.replace("/etc/ssh/TEST-INCLUDE-DIR", str(root / "TEST-INCLUDE-DIR"))
                    cfg.write_bytes(config_text.encode("utf-8"))
            if make_symlink:
                target = root / "real-config"
                target.write_text("PermitRootLogin no\n", encoding="utf-8")
                if cfg.exists():
                    cfg.unlink()
                cfg.symlink_to(target)
            for name, body in include_files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))
            sshd = root / "sshd"
            sshd.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ ${1:-} == -t ]]; then exit " + str(syntax_rc) + "; fi\n"
                "if [[ ${1:-} == -T ]]; then printf '%s\\n' 'permitrootlogin " + effective + "'; exit 0; fi\n"
                "exit 2\n",
                encoding="utf-8",
            )
            sshd.chmod(0o755)
            sort_path = "/usr/bin/sort"
            if sort_fail:
                fake_sort = root / "sort"
                fake_sort.write_text("#!/usr/bin/env bash\nexit 74\n", encoding="utf-8")
                fake_sort.chmod(0o755)
                sort_path = str(fake_sort)
            block = SSHD_ROOT_LOGIN._shell_function_for_fixture(
                "SSH.TEST", str(cfg), str(sshd), "PermitRootLogin", "eq", "no", sort_path
            )
            prelude = "compgen() { return 1; }\n" if shadow_compgen else ""
            cp = subprocess.run(
                [BASH, "-c", "set -u\n" + prelude + block + "\nslp_check_SSH_TEST\n"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                env=env,
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            return cp.stdout.strip().split("\t")

    def test_positive_main_no(self):
        row = self.run_fixture("PermitRootLogin no\n")
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("effective=no", row[3])

    def test_openssh_separator_quote_and_crlf_forms(self):
        for line in (
            "PermitRootLogin=no\n",
            "PermitRootLogin = no\n",
            "PermitRootLogin= no\n",
            "PermitRootLogin =no\n",
            'PermitRootLogin "no"\n',
            "PermitRootLogin 'no'\n",
            'PermitRootLogin="no"\n',
            "PermitRootLogin no\r\n",
        ):
            with self.subTest(line=line):
                row = self.run_fixture(line)
                self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        row = self.run_fixture("PermitRootLogin no\nMatch=User root\nPermitRootLogin yes\n")
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        row = self.run_fixture(
            "PermitRootLogin no\nInclude=/etc/ssh/TEST-INCLUDE.conf\n",
            include_files={"TEST-INCLUDE.conf": "Match User root\nPermitRootLogin yes\n"},
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_unicode_whitespace_is_not_a_locale_dependent_sshd_separator(self):
        for edge in ("\u2003", "\u3000"):
            with self.subTest(edge=repr(edge)):
                observed = []
                for locale_name in ("C", "C.utf8"):
                    env = os.environ.copy()
                    env["LC_ALL"] = locale_name
                    row = self.run_fixture("PermitRootLogin" + edge + "no\n", env=env)
                    observed.append(tuple(row[2:5]))
                self.assertEqual(observed[0], observed[1])
                self.assertEqual(observed[0], ("VALUE", "main_global_no=0;effective=no", "FAIL"))

    def test_nul_and_non_crlf_cr_are_rejected_before_line_parsing(self):
        row = self.run_fixture(b"PermitRootLogin no\x00\n")
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "sshd-config:invalid-bytes", "ERROR"))
        row = self.run_fixture(b"PermitRootLogin no\r")
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "sshd-config:invalid-bytes", "ERROR"))
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE.conf\n",
            include_files={"TEST-INCLUDE.conf": b"PermitRootLogin no\x00\n"},
        )
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "sshd-config:invalid-bytes", "ERROR"))

    def test_malformed_relevant_directives_error(self):
        for line in (
            "PermitRootLogin\n",
            "PermitRootLogin no extra\n",
            "PermitRootLogin==no\n",
            'PermitRootLogin "no\n',
            "Include=\n",
            "Match=\n",
        ):
            with self.subTest(line=line):
                row = self.run_fixture(line)
                self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_include_scope_is_restored_between_glob_members(self):
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE-DIR/*.conf\n",
            include_files={
                "TEST-INCLUDE-DIR/10-match.conf": "Match User nobody\n",
                "TEST-INCLUDE-DIR/20-global.conf": "PermitRootLogin yes\n",
            },
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))

    def test_include_scope_push_pop_and_inheritance(self):
        # Match created inside Include must not leak back to following main-file directives.
        row = self.run_fixture(
            "Include /etc/ssh/TEST-INCLUDE.conf\nPermitRootLogin no\n",
            include_files={"TEST-INCLUDE.conf": "Match User nobody\n"},
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("main_global_no=1", row[3])

        # Conversely, an Include reached from Match scope must inherit that scope.
        row = self.run_fixture(
            "PermitRootLogin no\nMatch User nobody\nInclude /etc/ssh/TEST-INCLUDE.conf\n",
            include_files={"TEST-INCLUDE.conf": "PermitRootLogin yes\n"},
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_comment_marker_inside_include_filename_is_not_comment(self):
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE-DIR/file#prod.conf # trailing comment\n",
            include_files={
                "TEST-INCLUDE-DIR/file#prod.conf": "Match User root\nPermitRootLogin yes\n",
            },
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_quoted_include_is_parsed(self):
        row = self.run_fixture(
            'PermitRootLogin no\nInclude "/etc/ssh/TEST-INCLUDE.conf"\n',
            include_files={"TEST-INCLUDE.conf": "Match User root\nPermitRootLogin yes\n"},
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_compgen_function_shadow_cannot_hide_include_population(self):
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE-DIR/*.conf\n",
            include_files={
                "TEST-INCLUDE-DIR/20.conf": "Match User root\nPermitRootLogin yes\n",
            },
            shadow_compgen=True,
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_sort_failure_is_error(self):
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE-DIR/*.conf\n",
            include_files={
                "TEST-INCLUDE-DIR/20.conf": "Match User root\nPermitRootLogin yes\n",
            },
            sort_fail=True,
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_newline_glob_member_is_error(self):
        row = self.run_fixture(
            "PermitRootLogin no\nInclude /etc/ssh/TEST-INCLUDE-DIR/*.conf\n",
            include_files={
                "TEST-INCLUDE-DIR/bad\nfragment.conf": "Match User root\nPermitRootLogin yes\n",
            },
        )
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_glob_implementation_is_explicit_and_builtin(self):
        block = SSHD_ROOT_LOGIN._shell_function_for_fixture(
            "SSH.TEST", "/tmp/sshd_config", "/tmp/sshd", "PermitRootLogin", "eq", "no"
        )
        self.assertIn('builtin compgen -G', block)
        self.assertIn('LC_ALL=C command "$_slp_sort"', block)
        self.assertIn('set -o pipefail', block)

    def test_main_directive_absent_fails(self):
        row = self.run_fixture("PasswordAuthentication no\n")
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_main_non_no_fails(self):
        row = self.run_fixture("PermitRootLogin prohibit-password\n", effective="prohibit-password")
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_global_include_before_main_controls_effective(self):
        row = self.run_fixture(
            "Include /etc/ssh/TEST-INCLUDE.conf\nPermitRootLogin no\n",
            effective="prohibit-password",
            include_files={"TEST-INCLUDE.conf": "PermitRootLogin prohibit-password\n"},
        )
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_match_non_no_fails_closed_error(self):
        row = self.run_fixture("PermitRootLogin no\nMatch User root\n  PermitRootLogin yes\n")
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_match_no_is_safe(self):
        row = self.run_fixture("PermitRootLogin no\nMatch User root\n  PermitRootLogin no\n")
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))

    def test_effective_non_no_fails(self):
        row = self.run_fixture("PermitRootLogin no\n", effective="prohibit-password")
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_syntax_failure_errors(self):
        row = self.run_fixture("PermitRootLogin no\n", syntax_rc=1)
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "sshd-config:validation-failed", "ERROR"))

    def test_missing_config_not_found(self):
        row = self.run_fixture(None)
        self.assertEqual((row[2], row[4]), ("NOT_FOUND", "FAIL"))

    def test_symlink_config_errors(self):
        row = self.run_fixture(None, make_symlink=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))


class RunningProcessPathsWriteProtectionFixtures(unittest.TestCase):
    @staticmethod
    def _stat_text(pid_name="1", start="123"):
        fields = ["S"] + ["0"] * 49
        fields[19] = start
        return f"{pid_name} (fixture) " + " ".join(fields) + "\n"

    @staticmethod
    def _status_text(state="S", kthread=0):
        return f"State:\t{state} (fixture)\nKthread:\t{kthread}\n"

    def _prepare_fs(self, root, name="app"):
        fsroot = root / "fsroot"
        bindir = fsroot / "opt" / name / "bin"
        libdir = fsroot / "opt" / name / "lib"
        bindir.mkdir(parents=True)
        libdir.mkdir(parents=True)
        exe = bindir / name
        lib = libdir / "libfixture.so.1"
        exe.write_text("x\n", encoding="utf-8")
        lib.write_text("x\n", encoding="utf-8")
        exe.chmod(0o555)
        lib.chmod(0o555)
        return fsroot, exe, lib, libdir

    @staticmethod
    def _seal_fs(fsroot, names, mode=0o555):
        for d in (fsroot, fsroot / "opt"):
            d.chmod(mode)
        for name in names:
            for d in (fsroot / "opt" / name, fsroot / "opt" / name / "bin", fsroot / "opt" / name / "lib"):
                d.chmod(mode)

    def _add_pid(self, proc, pid_name, exe, maps_text, start="123", status=None):
        pid = proc / str(pid_name)
        pid.mkdir(parents=True)
        (pid / "stat").write_text(self._stat_text(str(pid_name), start), encoding="ascii")
        (pid / "status").write_text(status or self._status_text(), encoding="utf-8")
        if exe is not None:
            (pid / "exe").symlink_to(exe)
        if maps_text is not None:
            (pid / "maps").write_text(maps_text, encoding="utf-8")
        return pid

    @staticmethod
    def _maps_line(
        path, *, perms="r-xp", inode=None, dev=None,
        address="00400000-00401000", offset="00000000", source_path=None,
    ):
        if source_path is None:
            candidate = Path(str(path))
            if str(path).startswith("/") and candidate.exists():
                source_path = candidate
        if source_path is not None:
            st = os.stat(source_path)
            if inode is None:
                inode = st.st_ino
            if dev is None:
                dev = f"{os.major(st.st_dev):x}:{os.minor(st.st_dev):x}"
        if inode is None:
            inode = 0 if str(path).startswith("[") else 1
        if dev is None:
            dev = "00:00"
        return f"{address} {perms} {offset} {dev} {inode} {path}\n"

    @staticmethod
    def _prepare_proc(root, forks=1000):
        proc = root / "proc"
        proc.mkdir()
        (proc / "stat").write_text(
            f"cpu  0 0 0 0 0 0 0 0 0 0\nprocesses {forks}\n",
            encoding="ascii",
        )
        return proc

    @staticmethod
    def _set_process_counter(proc, forks):
        (proc / "stat").write_text(
            f"cpu  0 0 0 0 0 0 0 0 0 0\nprocesses {forks}\n",
            encoding="ascii",
        )

    def _script(self, root, proc, fsroot):
        src = RUNNING_PROCESS_PATHS._shell_function_for_roots(
            "TEST-RUNTIME-PATHS", str(proc), str(fsroot)
        )
        script = root / "run.sh"
        script.write_text(
            "#!/bin/bash -p\n" + src + "\nslp_check_TEST_RUNTIME_PATHS\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script

    def _run_script(self, script):
        cp = subprocess.run(
            [str(script)], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        row = cp.stdout.strip().split("\t")
        self.assertEqual(len(row), 5, cp.stdout + cp.stderr)
        return row

    def _popen_script(self, script):
        return subprocess.Popen(
            [str(script)], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    @staticmethod
    def _open_fifo_writer(path, timeout=20.0):
        deadline = time.monotonic() + timeout
        while True:
            try:
                return os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as exc:
                if exc.errno != errno.ENXIO or time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)

    def _finish_popen(self, cp, timeout=20.0):
        out, err = cp.communicate(timeout=timeout)
        self.assertEqual(cp.returncode, 0, err)
        row = out.strip().split("\t")
        self.assertEqual(len(row), 5, out + err)
        return row

    @staticmethod
    def _start_fifo_writer_handshake(path, text):
        opened = threading.Event()
        release = threading.Event()
        failures = []

        def writer():
            try:
                with open(path, "w", encoding="utf-8") as stream:
                    opened.set()
                    if not release.wait(timeout=20.0):
                        raise TimeoutError("FIFO writer release handshake timed out")
                    stream.write(text)
                    stream.flush()
            except Exception as exc:
                failures.append(exc)
                opened.set()

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        return thread, opened, release, failures

    @staticmethod
    def _runtime_reason_namespace():
        tree = ast.parse(RUNNING_PROCESS_PATHS._PY)
        selected = []
        wanted = {"error", "obj_state", "recheck_files", "recheck_parents"}
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                selected.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name in wanted:
                selected.append(node)
        namespace = {}
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                "<running-process-recheck-semantics>",
                "exec",
            ),
            namespace,
        )
        return namespace

    def run_fixture(
        self, *, file_mode=0o555, parent_mode=0o555, deleted_library=False,
        no_library=False, mapped_name="libfixture.so.1", proc_escape_space=False,
        malformed_escape=False,
    ):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, libdir = self._prepare_fs(root)
            if mapped_name != lib.name:
                replacement = libdir / mapped_name
                lib.rename(replacement)
                lib = replacement
            exe.chmod(file_mode)
            lib.chmod(file_mode)
            self._seal_fs(fsroot, ("app",), parent_mode)

            proc = self._prepare_proc(root)
            if no_library:
                maps_path = "[heap]"
                maps = self._maps_line(maps_path, perms="rw-p", inode=0)
            else:
                maps_path = str(lib)
                if proc_escape_space:
                    maps_path = maps_path.replace(" ", r"\040")
                if malformed_escape:
                    maps_path += r"\04x"
                if deleted_library:
                    maps_path += " (deleted)"
                maps = self._maps_line(maps_path, source_path=lib)
            self._add_pid(proc, "100", exe, maps)
            return self._run_script(self._script(root, proc, fsroot))

    def test_adapter_selftest(self):
        cp = subprocess.run(
            [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B", str(RUNNING_PROCESS_PATHS_ADAPTER_PATH)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("ADAPTER_SELFTEST=PASS", cp.stdout)

    def test_positive_dynamic_population(self):
        row = self.run_fixture()
        self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
        self.assertIn("file_violations=0", row[3])
        self.assertIn("parent_violations=0", row[3])

    def test_file_go_w_is_fail(self):
        row = self.run_fixture(file_mode=0o575)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("file_violations=", row[3])

    def test_unprivileged_parent_write_is_fail(self):
        # other wx proves an unprivileged write path regardless of group membership.
        row = self.run_fixture(parent_mode=0o707)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
        self.assertIn("parent_violations=", row[3])

    def test_group_wx_parent_classification_is_owner_sensitive(self):
        # The fixture directory is owned by the test runner.  Under root, 0770
        # isolates the group-class wx ambiguity and must ERROR.  Under an
        # ordinary runner, owner-class wx itself proves an unprivileged write
        # path and must FAIL; this is not a skip and exercises the real runtime.
        row = self.run_fixture(parent_mode=0o770)
        expected = ("ERROR", "ERROR") if os.geteuid() == 0 else ("VALUE", "FAIL")
        self.assertEqual((row[2], row[4]), expected)
        if os.geteuid() == 0:
            self.assertEqual(row[3], "parent:group-write-ambiguous")

    def test_write_without_search_in_group_class_is_not_alone_a_violation(self):
        # With a root-owned fixture (root test runner), 0720 has group write but
        # no group search and therefore does not prove directory-entry write.
        # With an ordinary test runner the same directory is owned by that
        # unprivileged user and owner-class wx is a definite violation.
        row = self.run_fixture(parent_mode=0o720)
        expected = ("VALUE", "PASS") if os.geteuid() == 0 else ("VALUE", "FAIL")
        self.assertEqual((row[2], row[4]), expected)

    def test_deleted_library_is_error(self):
        row = self.run_fixture(deleted_library=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "proc-maps:deleted-path")

    def test_missing_library_population_is_error(self):
        row = self.run_fixture(no_library=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "proc-maps:empty-executable-population")

    def test_executable_mapping_without_shared_object_name_is_checked(self):
        row = self.run_fixture(mapped_name="render.plugin", file_mode=0o575)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_proc_octal_escaped_mapping_path_is_decoded(self):
        row = self.run_fixture(mapped_name="render plugin", proc_escape_space=True, file_mode=0o575)
        self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_malformed_proc_escape_is_error(self):
        row = self.run_fixture(malformed_escape=True)
        self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
        self.assertEqual(row[3], "proc:invalid-path-escape")

    def test_each_pid_requires_file_backed_executable_mapping(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, _ = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            proc = self._prepare_proc(root)
            self._add_pid(proc, "100", exe1, self._maps_line("[heap]", perms="rw-p", inode=0))
            self._add_pid(proc, "200", exe2, self._maps_line(str(lib2)))
            self._seal_fs(fsroot, ("app1", "app2"))
            row = self._run_script(self._script(root, proc, fsroot))
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_pid_population_growth_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, _ = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            proc = self._prepare_proc(root)
            pid1 = self._add_pid(proc, "100", exe1, None)
            fifo = pid1 / "maps"; os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app1", "app2"))
            cp = self._popen_script(self._script(root, proc, fsroot))
            fd = self._open_fifo_writer(fifo)
            try:
                self._add_pid(proc, "200", exe2, self._maps_line(str(lib2)))
                os.write(fd, self._maps_line(str(lib1)).encode("utf-8"))
            finally:
                os.close(fd)
            row = self._finish_popen(cp)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "pid-population:mid-snapshot-changed")

    def test_identity_change_after_no_exe_classification_is_error(self):
        tree = ast.parse(RUNNING_PROCESS_PATHS._PY)
        selected = []
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                selected.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name in {
                "error", "read_start", "classify_no_exe",
            }:
                selected.append(node)
        namespace = {}
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])),
                "<src0006-classify-no-exe>",
                "exec",
            ),
            namespace,
        )

        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            pid = Path(td) / "100"
            pid.mkdir()
            (pid / "status").write_text(
                self._status_text(state="Z"),
                encoding="utf-8",
            )

            namespace["read_start"] = lambda _pid: "123"
            self.assertEqual(
                namespace["classify_no_exe"](pid, "123"),
                "excluded",
            )

            namespace["read_start"] = lambda _pid: "456"
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                with self.assertRaises(SystemExit) as cm:
                    namespace["classify_no_exe"](pid, "123")
            self.assertEqual(cm.exception.code, 0)
            self.assertEqual(captured.getvalue().strip(), "ERROR\tproc-stat:excluded-classification-changed")

    def _snapshot_drift_case(self, mutate_parent):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, libdir1 = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            proc = self._prepare_proc(root)
            self._add_pid(proc, "100", exe1, self._maps_line(str(lib1)))
            pid2 = self._add_pid(proc, "200", exe2, None)
            fifo = pid2 / "maps"
            first_fifo = pid2 / "maps.first"
            os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app1", "app2"))

            maps_text = self._maps_line(str(lib2))
            first_thread, first_opened, first_release, first_failures = (
                self._start_fifo_writer_handshake(fifo, maps_text)
            )
            cp = self._popen_script(self._script(root, proc, fsroot))

            self.assertTrue(
                first_opened.wait(timeout=20.0),
                "observer did not reach first maps snapshot",
            )
            self.assertEqual(first_failures, [])

            if mutate_parent:
                libdir1.chmod(0o775)
            else:
                lib1.chmod(0o575)

            os.replace(fifo, first_fifo)
            os.mkfifo(fifo)
            second_thread, second_opened, second_release, second_failures = (
                self._start_fifo_writer_handshake(fifo, maps_text)
            )

            first_release.set()
            first_thread.join(timeout=20.0)
            self.assertFalse(first_thread.is_alive(), "first maps FIFO writer did not finish")
            self.assertEqual(first_failures, [])

            self.assertTrue(
                second_opened.wait(timeout=20.0),
                "observer did not reach maps recheck",
            )
            self.assertEqual(second_failures, [])
            second_release.set()

            row = self._finish_popen(cp)
            second_thread.join(timeout=20.0)
            self.assertFalse(second_thread.is_alive(), "second maps FIFO writer did not finish")
            self.assertEqual(second_failures, [])
            return row

    def test_file_recheck_reason_semantics_are_exact(self):
        namespace = self._runtime_reason_namespace()
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "fixture"
            path.write_text("x\n", encoding="utf-8")
            state = namespace["obj_state"](os.stat(path))
            records = {str(path): (str(path), state, state)}
            path.chmod(0o575)
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                with self.assertRaises(SystemExit) as cm:
                    namespace["recheck_files"](records)
            self.assertEqual(cm.exception.code, 0)
            self.assertEqual(captured.getvalue().strip(), "ERROR\tpath:recheck-snapshot-changed")

    def test_parent_recheck_reason_semantics_are_exact(self):
        namespace = self._runtime_reason_namespace()
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "fixture-parent"
            path.mkdir()
            state = namespace["obj_state"](os.stat(path))
            records = {str(path): state}
            path.chmod(0o775)
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                with self.assertRaises(SystemExit) as cm:
                    namespace["recheck_parents"](records)
            self.assertEqual(cm.exception.code, 0)
            self.assertEqual(captured.getvalue().strip(), "ERROR\tparent:recheck-snapshot-changed")

    def test_file_snapshot_drift_is_error(self):
        row = self._snapshot_drift_case(False)
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "path:recheck-snapshot-changed", "ERROR"))

    def test_parent_snapshot_drift_is_error(self):
        row = self._snapshot_drift_case(True)
        self.assertEqual((row[2], row[3], row[4]), ("ERROR", "parent:recheck-snapshot-changed", "ERROR"))


    def test_maps_declared_identity_mismatch_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, _ = self._prepare_fs(root)
            proc = self._prepare_proc(root)
            st = os.stat(lib)
            maps = self._maps_line(
                str(lib),
                inode=st.st_ino + 1,
                dev=f"{os.major(st.st_dev):x}:{os.minor(st.st_dev):x}",
            )
            self._add_pid(proc, "100", exe, maps)
            self._seal_fs(fsroot, ("app",))
            row = self._run_script(self._script(root, proc, fsroot))
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_malformed_maps_address_offset_device_are_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        cases = (
            {"address": "NOT-AN-ADDRESS"},
            {"offset": "NOT-OFFSET"},
            {"dev": "NOT-DEV"},
        )
        for override in cases:
            with self.subTest(override=override):
                with tempfile.TemporaryDirectory(dir=ROOT) as td:
                    root = Path(td)
                    fsroot, exe, lib, _ = self._prepare_fs(root)
                    proc = self._prepare_proc(root)
                    maps = self._maps_line(str(lib), source_path=lib, **override)
                    self._add_pid(proc, "100", exe, maps)
                    self._seal_fs(fsroot, ("app",))
                    row = self._run_script(self._script(root, proc, fsroot))
                    self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_unicode_inode_digits_are_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, _ = self._prepare_fs(root)
            proc = self._prepare_proc(root)
            st = os.stat(lib)
            unicode_inode = str(st.st_ino).translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩"))
            maps = self._maps_line(str(lib), inode=unicode_inode, source_path=lib)
            self._add_pid(proc, "100", exe, maps)
            self._seal_fs(fsroot, ("app",))
            row = self._run_script(self._script(root, proc, fsroot))
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_non_ascii_decimal_starttime_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, _ = self._prepare_fs(root)
            proc = self._prepare_proc(root)
            self._add_pid(proc, "100", exe, self._maps_line(str(lib)), start="NOT-A-NUMBER")
            self._seal_fs(fsroot, ("app",))
            row = self._run_script(self._script(root, proc, fsroot))
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_missing_starttime_with_following_fields_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, _ = self._prepare_fs(root)
            proc = self._prepare_proc(root)
            pid = self._add_pid(proc, "100", exe, self._maps_line(str(lib)))
            fields = ["S"] + ["0"] * 49
            fields[19] = ""
            fields[20] = "777"
            (pid / "stat").write_text("100 (fixture) " + " ".join(fields) + "\n", encoding="ascii")
            self._seal_fs(fsroot, ("app",))
            row = self._run_script(self._script(root, proc, fsroot))
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))

    def test_transient_process_creation_counter_change_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe, lib, _ = self._prepare_fs(root)
            proc = self._prepare_proc(root, forks=1000)
            pid = self._add_pid(proc, "100", exe, None)
            fifo = pid / "maps"
            os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app",))
            cp = self._popen_script(self._script(root, proc, fsroot))
            fd = self._open_fifo_writer(fifo)
            try:
                self._set_process_counter(proc, 1001)
                os.write(fd, self._maps_line(str(lib)).encode("utf-8"))
            finally:
                os.close(fd)
            row = self._finish_popen(cp)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "proc-counter:mid-snapshot-changed")

    def test_same_pid_mapping_population_drift_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, _ = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            _, _, lib3, _ = self._prepare_fs(root, "app3")
            proc = self._prepare_proc(root)
            pid1 = self._add_pid(proc, "100", exe1, self._maps_line(str(lib1)))
            pid2 = self._add_pid(proc, "200", exe2, None)
            fifo = pid2 / "maps"
            os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app1", "app2", "app3"))
            cp = self._popen_script(self._script(root, proc, fsroot))
            fd = self._open_fifo_writer(fifo)
            try:
                (pid1 / "maps").write_text(
                    self._maps_line(str(lib1)) +
                    self._maps_line(
                        str(lib3),
                        address="00500000-00501000",
                        source_path=lib3,
                    ),
                    encoding="utf-8",
                )
                os.write(fd, self._maps_line(str(lib2)).encode("utf-8"))
            finally:
                os.close(fd)
            row = self._finish_popen(cp)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "proc-maps:recheck-changed")

    def test_same_pid_exe_target_drift_is_error(self):
        if BASH is None:
            self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td)
            fsroot, exe1, lib1, _ = self._prepare_fs(root, "app1")
            _, exe2, lib2, _ = self._prepare_fs(root, "app2")
            _, exe3, _, _ = self._prepare_fs(root, "app3")
            proc = self._prepare_proc(root)
            pid1 = self._add_pid(proc, "100", exe1, self._maps_line(str(lib1)))
            pid2 = self._add_pid(proc, "200", exe2, None)
            fifo = pid2 / "maps"
            os.mkfifo(fifo)
            self._seal_fs(fsroot, ("app1", "app2", "app3"))
            cp = self._popen_script(self._script(root, proc, fsroot))
            fd = self._open_fifo_writer(fifo)
            try:
                (pid1 / "exe").unlink()
                (pid1 / "exe").symlink_to(exe3)
                os.write(fd, self._maps_line(str(lib2)).encode("utf-8"))
            finally:
                os.close(fd)
            row = self._finish_popen(cp)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "proc-exe:recheck-changed")

    def test_process_change_reason_inventory_is_complete_and_unique(self):
        for forbidden in (
            "observation:process-changed",
            "observation:file-changed",
            "observation:parent-changed",
        ):
            self.assertNotIn(forbidden, RUNNING_PROCESS_PATHS._PY)
        process_reasons = RUNNING_PROCESS_PATHS.PROCESS_CHANGE_REASONS
        file_parent_reasons = RUNNING_PROCESS_PATHS.FILE_PARENT_CHANGE_REASONS
        self.assertEqual(len(process_reasons), 21)
        self.assertEqual(len(set(process_reasons)), 21)
        self.assertEqual(len(file_parent_reasons), 9)
        self.assertEqual(len(set(file_parent_reasons)), 9)
        tree = ast.parse(RUNNING_PROCESS_PATHS._PY)
        observed = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "error":
                continue
            if len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                observed.append(node.args[0].value)
        for reason in process_reasons + file_parent_reasons:
            self.assertEqual(observed.count(reason), 1, reason)

    def test_generation_rejects_wrong_contract_fields(self):
        cases = (
            ("/proc", RUNNING_PROCESS_PATHS.CANONICAL_KEY, RUNNING_PROCESS_PATHS.CANONICAL_OP, RUNNING_PROCESS_PATHS.CANONICAL_EXPECTED),
            (RUNNING_PROCESS_PATHS.CANONICAL_LOCATOR, "mode", RUNNING_PROCESS_PATHS.CANONICAL_OP, RUNNING_PROCESS_PATHS.CANONICAL_EXPECTED),
            (RUNNING_PROCESS_PATHS.CANONICAL_LOCATOR, RUNNING_PROCESS_PATHS.CANONICAL_KEY, "bits-clear", RUNNING_PROCESS_PATHS.CANONICAL_EXPECTED),
            (RUNNING_PROCESS_PATHS.CANONICAL_LOCATOR, RUNNING_PROCESS_PATHS.CANONICAL_KEY, RUNNING_PROCESS_PATHS.CANONICAL_OP, "0022"),
        )
        for args in cases:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    RUNNING_PROCESS_PATHS.shell_function("TEST", *args)


class UnifiedCliArtifact(unittest.TestCase):
    GEN_V2 = ROOT / "product/generate-product-check-v2.py"
    ARTIFACT = ROOT / "securelinux-policy.sh"
    SIDECAR = ROOT / "securelinux-policy.sh.sha256"

    def run_cli(self, *args, env=None):
        return subprocess.run(
            [str(self.ARTIFACT), *args], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        )

    def run_sourced(self, body, env=None):
        return subprocess.run(
            [BASH, "-c", f"set -u\nsource {self.ARTIFACT!s}\n{body}"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        )

    @staticmethod
    def synthetic_prelude():
        return r'''
SLP_RESULTS=(
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.1-GROUP-MODE\tVALUE\t0644\tPASS'
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.11-HOME-DIRECTORIES-MODE\tVALUE\taccounts=2;homes=2;violations=1\tFAIL'
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.8-STANDARD-SYSTEM-PATHS-MODE\tVALUE\troots_present=9;roots_absent=0;aliases=4;exec=1236;libraries=999;modules=6474;checked=8300;violations=0\tPASS'
$'SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.10-HOME-SENSITIVE-FILES-MODE\tERROR\ttest:synthetic-error\tERROR'
)
SLP_TOTAL=4
SLP_PASS=2
SLP_FAIL=1
SLP_NF=0
SLP_NA=0
SLP_ERR=1
SLP_POLICY_STATUS=UNEVALUATED
SLP_POLICY_RC=1
'''

    def test_unified_collector_rejects_missing_or_malformed_error_reason(self):
        cid = "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE"
        fn = "slp_check_FSTEC_LINUX_2022_2_1_1_LOCAL_ACCOUNT_PASSWORD_STATE"
        for reason in ("-", "BAD", "domain:bad_reason", "stderr:random text"):
            with self.subTest(reason=reason):
                body = (
                    f"{fn}() {{ printf 'SLP-CHECK-V1\t{cid}\tERROR\t{reason}\tERROR\n'; }}\n"
                    "slp_collect_policy\n"
                    "printf 'RC=%s\n' \"$?\"\n"
                )
                cp = self.run_sourced(body)
                self.assertEqual(cp.returncode, 0)
                self.assertEqual(cp.stdout.strip(), "RC=1")
                self.assertIn("CHECK_INTERNAL_ERROR", cp.stderr)

    def test_unified_tracked_artifact_matches_fresh_generator_exactly(self):
        self.assertTrue(self.GEN_V2.is_file())
        self.assertTrue(self.ARTIFACT.is_file())
        self.assertTrue(self.SIDECAR.is_file())
        self.assertEqual(self.ARTIFACT.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.SIDECAR.stat().st_mode & 0o777, 0o644)
        self.assertTrue(self.ARTIFACT.read_bytes().startswith(b"#!/bin/bash -p\n"))
        for mask in (0o022, 0o077):
            with self.subTest(umask=oct(mask)):
                with tempfile.TemporaryDirectory(prefix="slp-unified-cli-rebuild-") as td:
                    out = Path(td) / "securelinux-policy.sh"
                    cp = subprocess.run(
                        [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B",
                         str(self.GEN_V2), "--repo", str(ROOT), "--out", str(out)],
                        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, umask=mask,
                    )
                    self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                    self.assertIn("GENERATOR_ID=product-check-generator-v2\n", cp.stdout)
                    current_control_count = len(GEN_V2_CURRENT.load_manifest(ROOT)[0])
                    current_adapter_count = len(GEN_V2_CURRENT.load_registry(ROOT)[0])
                    self.assertIn(f"CONTROL_COUNT={current_control_count}\n", cp.stdout)
                    self.assertIn(f"ADAPTER_COUNT={current_adapter_count}\n", cp.stdout)
                    self.assertIn("TARGET_FAMILY_ID=linux-x86_64-supported-v1\n", cp.stdout)
                    self.assertIn("SUPPORTED_PROFILE_ENVIRONMENTS=7\n", cp.stdout)
                    self.assertIn("FIELD_COMPATIBILITY_ENVIRONMENTS=1\n", cp.stdout)
                    self.assertIn("SUPPORTED_ENVIRONMENTS=7\n", cp.stdout)
                    apply_mechanisms, _, _ = GEN_V2_CURRENT.load_apply_mechanisms(ROOT)
                    expected_apply_kinds = ",".join(sorted(
                        {m["kind_row"]["apply_kind"] for m in apply_mechanisms.values()},
                        key=lambda x: x.encode("utf-8"),
                    ))
                    self.assertIn(f"APPLY_KINDS={expected_apply_kinds}\n", cp.stdout)
                    apply_manifest_rows, _ = GEN_V2_CURRENT.load_manifest(ROOT)
                    expected_apply_control_count = len([
                        c for c in (GEN_V2_CURRENT.load_control(ROOT, row) for row in apply_manifest_rows)
                        if c["apply_supported"]
                    ])
                    self.assertIn(f"APPLY_CONTROL_COUNT={expected_apply_control_count}\n", cp.stdout)
                    self.assertIn(f"APPLY_IMPLEMENTATION_COUNT={len(apply_mechanisms)}\n", cp.stdout)
                    self.assertEqual(out.stat().st_mode & 0o777, 0o755)
                    self.assertEqual(out.with_name(out.name + ".sha256").stat().st_mode & 0o777, 0o644)
                    self.assertEqual(out.read_bytes(), self.ARTIFACT.read_bytes())
                    self.assertEqual(out.with_name(out.name + ".sha256").read_bytes(), self.SIDECAR.read_bytes())
        expected = f"{sha256_file(self.ARTIFACT)}  {self.ARTIFACT.name}\n"
        self.assertEqual(self.SIDECAR.read_text(encoding="utf-8"), expected)

    def test_privileged_shebang_blocks_exported_command_function(self):
        env = os.environ.copy()
        env["BASH_FUNC_command%%"] = "() {  printf 'POISONED-COMMAND\\n'\n}"
        shebang = self.ARTIFACT.read_bytes().splitlines(keepends=True)[0]
        self.assertEqual(shebang, b"#!/bin/bash -p\n")
        with tempfile.TemporaryDirectory(prefix="slp-command-shebang-", dir=ROOT) as td:
            td_path = Path(td)
            target = td_path / "target"
            target.write_text("x", encoding="utf-8")
            target.chmod(0o600)

            def run_probe(name, probe_shebang):
                probe = td_path / name
                probe.write_bytes(
                    probe_shebang
                    + b'command /usr/bin/stat -c %a -- "$1"\n'
                )
                probe.chmod(0o755)
                return subprocess.run(
                    [str(probe), str(target)], cwd=ROOT, env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )

            privileged_bash_control = run_probe("privileged-bash-control.sh", shebang)
            plain_bash_control = run_probe("plain-bash-control.sh", b"#!/bin/bash\n")

        self.assertEqual(privileged_bash_control.returncode, 0, privileged_bash_control.stderr)
        self.assertEqual(privileged_bash_control.stdout, "600\n")
        self.assertNotIn("POISONED-COMMAND", privileged_bash_control.stdout + privileged_bash_control.stderr)
        self.assertEqual(plain_bash_control.returncode, 0, plain_bash_control.stderr)
        self.assertIn("POISONED-COMMAND", plain_bash_control.stdout + plain_bash_control.stderr)

    def test_supported_environment_classifier_exact_7_plus_desktop_and_fail_closed(self):
        cases = (
            ("ubuntu", "22.04", "x86_64", "installed", "installed", "installed", "FULL", "ubuntu-22.04-x86_64-full"),
            ("ubuntu", "24.04", "x86_64", "installed", "absent", "absent", "MINIMIZED", "ubuntu-24.04-x86_64-minimized"),
            ("ubuntu", "24.04", "x86_64", "installed", "installed", "installed", "FULL", "ubuntu-24.04-x86_64-full"),
            ("ubuntu", "26.04", "x86_64", "installed", "absent", "absent", "MINIMIZED", "ubuntu-26.04-x86_64-minimized"),
            ("ubuntu", "26.04", "x86_64", "installed", "installed", "installed", "FULL", "ubuntu-26.04-x86_64-full"),
            ("debian", "12", "x86_64", "na", "na", "na", "SERVER", "debian-12-x86_64-server"),
            ("debian", "13", "x86_64", "na", "na", "na", "SERVER", "debian-13-x86_64-server"),
        )
        for os_id, version, arch, server_minimal, minimal, standard, profile, env_id in cases:
            with self.subTest(env_id=env_id):
                body = (
                    f"slp_classify_environment {os_id!r} {version!r} {arch!r} "
                    f"{server_minimal!r} {minimal!r} {standard!r}; "
                    'printf "%s|%s|%s\\n" "$SLP_SYSTEM_PROFILE" "$SLP_SYSTEM_PLATFORM" "$SLP_SYSTEM_ENVIRONMENT"'
                )
                cp = self.run_sourced(body)
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertEqual(cp.stdout.strip(), f"{profile}|{os_id}-{version}-{arch}|{env_id}")

        desktop = self.run_sourced(
            "slp_classify_environment ubuntu 24.04 x86_64 absent installed installed; "
            'printf "%s|%s|%s|%s\n" "$SLP_SYSTEM_PROFILE" "$SLP_SYSTEM_TYPE" "$SLP_SYSTEM_PLATFORM" "$SLP_SYSTEM_ENVIRONMENT"'
        )
        self.assertEqual(desktop.returncode, 0, desktop.stderr)
        self.assertEqual(desktop.stdout.strip(), "|DESKTOP|ubuntu-24.04-x86_64|ubuntu-24.04-x86_64-desktop")

        rejected_profile = (
            ("ubuntu", "22.04", "x86_64", "installed", "absent", "absent"),
            ("ubuntu", "24.04", "x86_64", "installed", "installed", "absent"),
            ("ubuntu", "24.04", "x86_64", "installed", "absent", "installed"),
        )
        for args in rejected_profile:
            with self.subTest(rejected_profile=args):
                cmd = (
                    "slp_classify_environment " + " ".join(repr(x) for x in args)
                    + '; _slp_rc=$?; printf "%s|%s|%s\\n" "$_slp_rc" "$SLP_CLASSIFY_REASON" "$SLP_SYSTEM_PROFILE"'
                )
                cp = self.run_sourced(cmd)
                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                self.assertEqual(cp.stdout.strip(), "3|PROFILE|UNKNOWN")

        rejected_type = (
            ("ubuntu", "22.04", "x86_64", "absent", "installed", "installed"),
            ("ubuntu", "26.04", "x86_64", "absent", "installed", "installed"),
            ("ubuntu", "24.04", "x86_64", "absent", "absent", "absent"),
        )
        for args in rejected_type:
            with self.subTest(rejected_type=args):
                cmd = (
                    "slp_classify_environment " + " ".join(repr(x) for x in args)
                    + '; _slp_rc=$?; printf "%s|%s|%s\n" "$_slp_rc" "$SLP_CLASSIFY_REASON" "$SLP_SYSTEM_TYPE"'
                )
                cp = self.run_sourced(cmd)
                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                self.assertEqual(cp.stdout.strip(), "3|TYPE|UNKNOWN")

        rejected_platform = (
            ("ubuntu", "24.04", "aarch64", "installed", "installed", "installed"),
            ("ubuntu", "25.04", "x86_64", "installed", "installed", "installed"),
            ("debian", "11", "x86_64", "na", "na", "na"),
        )
        for args in rejected_platform:
            with self.subTest(rejected_platform=args):
                cmd = (
                    "slp_classify_environment " + " ".join(repr(x) for x in args)
                    + '; _slp_rc=$?; printf "%s|%s\\n" "$_slp_rc" "$SLP_CLASSIFY_REASON"'
                )
                cp = self.run_sourced(cmd)
                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                self.assertEqual(cp.stdout.strip(), "3|PLATFORM")

    def test_raw_os_release_bytes_and_dpkg_status_are_fail_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "os-release"
            cases = (
                (b"ID=ubuntu\n", "0"),
                (b"ID=ub\x00untu\n", "1"),
                (b"ID=ubuntu\r\n", "1"),
                (b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu\t24.04"\n', "1"),
                (b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu\x08 24.04"\n', "1"),
                (b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu\x0c 24.04"\n', "1"),
                (b'ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu\x1b 24.04"\n', "1"),
                (b'ID=debian\nVERSION_ID=13\nPRETTY_NAME="Debian \xff"\n', "1"),
                (b'ID=debian\nVERSION_ID=13\nPRETTY_NAME="Debian \xc3"\n', "1"),
                (b'ID=debian\nVERSION_ID=13\nPRETTY_NAME="Debian \xc0\xaf"\n', "1"),
                ('ID=debian\nVERSION_ID=13\nPRETTY_NAME="Дебиан 13"\n'.encode('utf-8'), "0"),
            )
            for raw, expected_rc in cases:
                with self.subTest(raw=raw):
                    path.write_bytes(raw)
                    cp = self.run_sourced(
                        f"slp_preflight_validate_text_bytes {shlex.quote(str(path))}; "
                        'printf "%s\n" "$?"'
                    )
                    self.assertEqual(cp.returncode, 0, cp.stderr)
                    self.assertEqual(cp.stdout.strip(), expected_rc)

        cases = (
            ("install ok installed", "0|installed"),
            ("hold ok installed", "0|installed"),
            ("deinstall ok config-files", "0|absent"),
            ("unknown ok not-installed", "0|absent"),
            ("install ok unpacked", "1|"),
            ("install ok half-configured", "1|"),
            ("install ok half-installed", "1|"),
            ("install ok triggers-pending", "1|"),
            ("install reinstreq installed", "1|"),
            ("invalid ok not-installed", "1|"),
        )
        for status, expected in cases:
            with self.subTest(status=status):
                cp = self.run_sourced(
                    f"_slp_result=$(slp_classify_dpkg_status {shlex.quote(status)}); "
                    '_slp_rc=$?; printf "%s|%s\n" "$_slp_rc" "$_slp_result"'
                )
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertEqual(cp.stdout.strip(), expected)

    def test_os_release_parser_accepts_single_quotes_and_shell_style_escapes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            path = Path(td) / "os-release"
            fixtures = (
                (
                    "ID='debian'\nVERSION_ID='13'\nPRETTY_NAME='Debian GNU/Linux 13 (trixie)'\n",
                    "debian|13|Debian GNU/Linux 13 (trixie)",
                ),
                (
                    'ID="debian"\nVERSION_ID="13"\nPRETTY_NAME="Debian \\"quoted\\" \\\\ path"\n',
                    'debian|13|Debian "quoted" \\ path',
                ),
                (
                    'ID=debian\nVERSION_ID=13\nPRETTY_NAME="Дебиан 13"\n',
                    'debian|13|Дебиан 13',
                ),
            )
            for content, expected in fixtures:
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    cp = self.run_sourced(
                        f"slp_preflight_validate_text_bytes {shlex.quote(str(path))}; _slp_vrc=$?; "
                        f"slp_parse_os_release_file {shlex.quote(str(path))}; _slp_prc=$?; "
                        'printf "%s|%s|%s|%s|%s\n" "$_slp_vrc" "$_slp_prc" "$SLP_OS_RELEASE_ID" "$SLP_OS_RELEASE_VERSION_ID" "$SLP_OS_RELEASE_PRETTY_NAME"'
                    )
                    self.assertEqual(cp.returncode, 0, cp.stderr)
                    self.assertEqual(cp.stdout.strip(), "0|0|" + expected)

    def test_unified_collector_accepts_definitive_not_found_fail(self):
        artifact = self.ARTIFACT.read_text(encoding="utf-8")
        match = re.search(
            r"local -a _slp_fns=\((.*?)\)\n  local -a _slp_ids=\((.*?)\)",
            artifact,
        )
        self.assertIsNotNone(match)
        fns = shlex.split(match.group(1))
        ids = shlex.split(match.group(2))
        self.assertEqual(len(fns), len(ids))
        targets = {
            "FSTEC-LINUX-2022-2.1.2-SSH-ROOT-LOGIN",
            "FSTEC-LINUX-2022-2.2.1-SU-WHEEL-ACCESS",
        }
        for target in sorted(targets):
            with self.subTest(target=target):
                body = []
                for fn, cid in zip(fns, ids):
                    if cid == target:
                        status, value, result = "NOT_FOUND", "-", "FAIL"
                    else:
                        status, value, result = "VALUE", "synthetic", "PASS"
                    body.append(
                        f"{fn}() {{ printf '%s\\t%s\\t%s\\t%s\\t%s\\n' "
                        f"'SLP-CHECK-V1' {shlex.quote(cid)} {shlex.quote(status)} "
                        f"{shlex.quote(value)} {shlex.quote(result)}; }}"
                    )
                body.append(
                    "slp_collect_policy; _slp_rc=$?; "
                    "printf 'RC=%s|POLICY=%s|FAIL=%s|NOT_FOUND=%s|ERROR=%s\\n' "
                    '"$_slp_rc" "$SLP_POLICY_STATUS" "$SLP_FAIL" "$SLP_NF" "$SLP_ERR"'
                )
                cp = self.run_sourced("\n".join(body))
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertEqual(cp.stdout.strip(), "RC=0|POLICY=NONCOMPLIANT|FAIL=1|NOT_FOUND=0|ERROR=0")
                self.assertNotIn("CHECK_INTERNAL_ERROR", cp.stderr)

    def test_dpkg_package_observation_ignores_caller_database_redirectors(self):
        baseline = self.run_sourced(
            '_slp_state=$(slp_dpkg_package_state ubuntu-server-minimal); _slp_rc=$?; printf "%s|%s\n" "$_slp_rc" "$_slp_state"'
        )
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertRegex(baseline.stdout.strip(), r"^0\|(installed|absent)$")
        baseline_state = baseline.stdout.strip().split("|", 1)[1]
        fake_status = (
            "Package: ubuntu-server-minimal\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n\n"
            if baseline_state == "absent" else ""
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            td_path = Path(td)
            admindir = td_path / "admindir"
            admindir.mkdir()
            (admindir / "status").write_text(fake_status, encoding="utf-8")
            fake_root = td_path / "root"
            root_admindir = fake_root / "var/lib/dpkg"
            root_admindir.mkdir(parents=True)
            (root_admindir / "status").write_text(fake_status, encoding="utf-8")
            for var, value in (("DPKG_ADMINDIR", admindir), ("DPKG_ROOT", fake_root)):
                with self.subTest(var=var):
                    env = os.environ.copy()
                    env.pop("DPKG_ADMINDIR", None)
                    env.pop("DPKG_ROOT", None)
                    env[var] = str(value)
                    cp = self.run_sourced(
                        '_slp_state=$(slp_dpkg_package_state ubuntu-server-minimal); _slp_rc=$?; printf "%s|%s\n" "$_slp_rc" "$_slp_state"',
                        env=env,
                    )
                    self.assertEqual(cp.returncode, 0, cp.stderr)
                    self.assertEqual(cp.stdout, baseline.stdout)

    def test_raw_platform_record_has_fixed_arity_for_valid_identity(self):
        body = (
            "SLP_SYSTEM_PRETTY_NAME='Ubuntu 24.04.4 LTS'; "
            "SLP_SYSTEM_ID=ubuntu; SLP_SYSTEM_VERSION_ID=24.04; SLP_SYSTEM_ARCH=x86_64; "
            "SLP_SYSTEM_PROFILE=FULL; SLP_SYSTEM_TYPE=''; "
            "SLP_SYSTEM_PLATFORM=ubuntu-24.04-x86_64; SLP_SYSTEM_ENVIRONMENT=ubuntu-24.04-x86_64-full; "
            "SLP_RESULTS=(); SLP_TOTAL=0; SLP_PASS=0; SLP_FAIL=0; SLP_NF=0; SLP_NA=0; SLP_ERR=0; "
            "SLP_POLICY_STATUS=COMPLIANT; SLP_POLICY_RC=0; "
            "slp_render_raw 0 | /usr/bin/head -n 1"
        )
        cp = self.run_sourced(body)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(len(cp.stdout.rstrip("\n").split("\t")), 10, cp.stdout)

    def test_unified_help_version_build_info_and_apply_dispatch(self):
        artifact_text = self.ARTIFACT.read_text(encoding="utf-8")
        self.assertIn("UBUNTU DESKTOP = FIELD_COMPATIBILITY", artifact_text)
        self.assertIn("КОРРЕКТНОСТЬ APPLY НА ИЗМЕНЁННОЙ ПОЛЬЗОВАТЕЛЕМ DESKTOP-СИСТЕМЕ НЕ ГАРАНТИРУЕТСЯ", artifact_text)
        syntax = subprocess.run([BASH, "-n", str(self.ARTIFACT)], capture_output=True, text=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        noargs = self.run_cli()
        self.assertEqual(noargs.returncode, 0)
        self.assertIn("SecureLinux-Policy — единый product CLI", noargs.stdout)
        self.assertNotIn("SecureLinux-Policy v3", noargs.stdout)
        self.assertIn("--check [--failed] [--format pretty|raw|json]", noargs.stdout)
        version = self.run_cli("--version")
        self.assertEqual(version.returncode, 0)
        self.assertIn("PRODUCT_CLI=product-cli-v1\n", version.stdout)
        build = self.run_cli("--build-info")
        self.assertEqual(build.returncode, 0)
        self.assertIn("GENERATOR_ID=product-check-generator-v2\n", build.stdout)
        self.assertIn("TARGET_FAMILY_ID=linux-x86_64-supported-v1\n", build.stdout)
        self.assertIn("SUPPORTED_PROFILE_ENVIRONMENTS=7\n", build.stdout)
        self.assertIn("FIELD_COMPATIBILITY_ENVIRONMENTS=1\n", build.stdout)
        self.assertIn("SUPPORTED_ENVIRONMENTS=7\n", build.stdout)
        apply_mechanisms, _, _ = GEN_V2_CURRENT.load_apply_mechanisms(ROOT)
        expected_apply_kinds = ",".join(sorted(
            {m["kind_row"]["apply_kind"] for m in apply_mechanisms.values()},
            key=lambda x: x.encode("utf-8"),
        ))
        self.assertIn(f"APPLY_KINDS={expected_apply_kinds}\n", build.stdout)
        apply_manifest_rows, _ = GEN_V2_CURRENT.load_manifest(ROOT)
        expected_apply_control_count = len([
            c for c in (GEN_V2_CURRENT.load_control(ROOT, row) for row in apply_manifest_rows)
            if c["apply_supported"]
        ])
        self.assertIn(f"APPLY_CONTROL_COUNT={expected_apply_control_count}\n", build.stdout)
        self.assertIn(f"APPLY_IMPLEMENTATION_COUNT={len(apply_mechanisms)}\n", build.stdout)
        self.assertNotIn("SRC-0001_ONLY", build.stdout)
        self.assertNotIn("APPLY_SRC0001_ONLY", build.stdout)
        for args in (
            ("--apply", "--snapshot-attestation"),
            ("--apply", "--dry-run", "extra"),
            ("--apply", "--snapshot-attestation", "/tmp/a", "extra"),
        ):
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "")
        dry_run = self.run_sourced(
            "slp_target_preflight() { return 0; }\n"
            "slp_run_apply() { printf '%s\\n' \"$1\"; }\n"
            "slp_main --apply --dry-run"
        )
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertEqual(dry_run.stdout, "DRY_RUN\n")
        apply = self.run_sourced(
            "slp_target_preflight() { return 0; }\n"
            "slp_run_apply() { printf '%s\\n' \"$1\"; }\n"
            "slp_main --apply"
        )
        self.assertEqual(apply.returncode, 0, apply.stderr)
        self.assertEqual(apply.stdout, "APPLY\n")
        self.assertNotIn("--restore", noargs.stdout)
        restore = self.run_cli("--restore")
        self.assertEqual(restore.returncode, 2)
        self.assertEqual(restore.stdout, "")
        self.assertEqual(restore.stderr, "")

    def test_help_and_provenance_ignore_caller_path_cat(self):
        expected_help = self.run_cli("--help")
        expected_provenance = self.run_cli("--provenance")
        self.assertEqual(expected_help.returncode, 0, expected_help.stderr)
        self.assertEqual(expected_provenance.returncode, 0, expected_provenance.stderr)
        with tempfile.TemporaryDirectory(prefix="slp-path-cat-", dir=ROOT) as td:
            td_path = Path(td)
            marker = td_path / "executed"
            fake_cat = td_path / "cat"
            fake_cat.write_text(
                "#!/bin/sh\nprintf '%s\\n' PATH_POISONED_CAT\n"
                + ": > " + shlex.quote(str(marker)) + "\n",
                encoding="utf-8",
            )
            fake_cat.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = str(td_path) + os.pathsep + env.get("PATH", "")
            actual_help = self.run_cli("--help", env=env)
            actual_provenance = self.run_cli("--provenance", env=env)
            self.assertFalse(marker.exists())
        self.assertEqual((actual_help.returncode, actual_help.stdout, actual_help.stderr),
                         (expected_help.returncode, expected_help.stdout, expected_help.stderr))
        self.assertEqual((actual_provenance.returncode, actual_provenance.stdout, actual_provenance.stderr),
                         (expected_provenance.returncode, expected_provenance.stdout, expected_provenance.stderr))

    def test_json_escape_covers_all_bash_representable_c0_controls(self):
        c0 = "".join(chr(i) for i in range(1, 32))
        bash_c0 = "".join(f"\\x{i:02x}" for i in range(1, 32))
        pre = self.synthetic_prelude() + (
            f"\n_slp_c0=$'{bash_c0}'\n"
            "SLP_SYSTEM_PRETTY_NAME=$_slp_c0\n"
            "SLP_SYSTEM_ID='ubuntu'\nSLP_SYSTEM_VERSION_ID='24.04'\n"
            "SLP_SYSTEM_ARCH='x86_64'\nSLP_SYSTEM_PROFILE='MINIMIZED'\n"
            "SLP_SYSTEM_PLATFORM='ubuntu-24.04-x86_64'\n"
            "SLP_SYSTEM_ENVIRONMENT='ubuntu-24.04-x86_64-minimized'\n"
        )
        cp = self.run_sourced(pre + "\nslp_render_json 0\n")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        payload = cp.stdout.encode("utf-8")
        self.assertFalse(any(byte < 0x20 for byte in payload.rstrip(b"\n")), payload)
        self.assertEqual(json.loads(cp.stdout)["platform"]["system"], c0)

    def test_unified_pretty_raw_json_and_failed_renderers(self):
        pre = self.synthetic_prelude() + "\nSLP_SYSTEM_PRETTY_NAME='Ubuntu 24.04.4 LTS'\nSLP_SYSTEM_ID='ubuntu'\nSLP_SYSTEM_VERSION_ID='24.04'\nSLP_SYSTEM_ARCH='x86_64'\nSLP_SYSTEM_PROFILE='MINIMIZED'\nSLP_SYSTEM_PLATFORM='ubuntu-24.04-x86_64'\nSLP_SYSTEM_ENVIRONMENT='ubuntu-24.04-x86_64-minimized'\n"
        pretty = self.run_sourced(pre + "\nslp_render_pretty 0 CHECK\n")
        self.assertEqual(pretty.returncode, 0, pretty.stderr)
        lines = pretty.stdout.splitlines()
        # Шапка CHECK — ровно пять строк, затем пустая строка перед таблицей.
        self.assertEqual(lines[0], "=== SecureLinux Policy — CHECK ===")
        self.assertEqual(lines[1], "SUPPORT=SUPPORTED")
        self.assertEqual(lines[2], "SYSTEM=Ubuntu 24.04.4 LTS ARCH=x86_64")
        self.assertEqual(lines[3], "PLATFORM=ubuntu-24.04-x86_64")
        self.assertEqual(lines[4], "PROFILE=MINIMIZED")
        self.assertEqual(lines[5], "")
        header = lines[6]
        separator = lines[7]
        self.assertEqual(header.count("|"), 5)
        self.assertEqual(separator.count("+"), 5)
        self.assertEqual(header.index("source"), 9)
        self.assertEqual(header.index("control"), 36)
        self.assertEqual(header.index("current"), 71)
        self.assertEqual(header.index("required"), 90)
        total_index = lines.index("TOTAL=4   PASS=2   FAIL=1   NOT_FOUND=0   NOT_APPLICABLE=0   ERROR=1   POLICY=UNEVALUATED")
        table_lines = lines[6:total_index]
        self.assertTrue(all(len(x) == 116 for x in table_lines), pretty.stdout)
        psql_current_stream = "".join(
            x.split("|")[3].strip() for x in table_lines if x.count("|") == 5
        )
        self.assertIn("exec=1236;libraries=999;modules=6474", psql_current_stream)
        self.assertIn("not-determined; reason: test:synthetic-error".replace(" ", ""), psql_current_stream.replace(" ", ""))
        self.assertNotIn("detail: test:synthetic-error", pretty.stdout)
        group_row = next(x for x in lines if "group-mode" in x)
        home_row = next(x for x in lines if "home-directories-mode" in x)
        error_row = next(x for x in lines if "home-sensitive-files-mode" in x)
        self.assertIn("fstec-linux-2022 §2.3.1", group_row)
        self.assertIn("= 0644", group_row)
        self.assertIn("= 0700", home_row)
        self.assertIn("not-determined", error_row)
        self.assertIn("bits 0077 = 0", error_row)
        self.assertNotIn("FSTEC-LINUX-2022-", pretty.stdout)

        fallback_layout = self.run_sourced(
            "\nslp_pretty_layout_init\nprintf 'mode=%s cols=%s\\n' \"$SLP_PRETTY_MODE\" \"$SLP_PRETTY_COLS\"\n"
        )
        self.assertEqual(fallback_layout.returncode, 0, fallback_layout.stderr)
        self.assertEqual(fallback_layout.stdout.strip(), "mode=table cols=116")
        # Соотношение current/required закреплено решением 19.09.2026: current отдаёт
        # required 10 символов, но не становится уже 12. Литерал меняется только явным решением.
        for width, expected in CURRENT_REQUIRED_WIDTHS.items():
            widths = self.run_sourced(
                f"\nslp_pretty_layout_for_cols {width}\n"
                "printf '%s %s\\n' \"$SLP_PRETTY_WCUR\" \"$SLP_PRETTY_WREQ\"\n"
            )
            self.assertEqual(widths.returncode, 0, widths.stderr)
            self.assertEqual(widths.stdout.strip(), "%d %d" % expected, width)

        for width in (80, 116, 139, 160):
            probe = self.run_sourced(
                f"\nslp_pretty_layout_for_cols {width}\n"
                "slp_pretty_row 'st' 'source' 'control' 'current' 'required'\n"
                "slp_pretty_separator\n"
                "slp_pretty_row err 'fstec-linux-2022 §2.3.10' home-sensitive-files-mode "
                "'not-determined; reason: pam:ambiguous-stack' 'bits 0077 = 0'\n"
            )
            self.assertEqual(probe.returncode, 0, probe.stderr)
            probe_lines = probe.stdout.splitlines()
            self.assertTrue(probe_lines, probe.stdout)
            self.assertTrue(all(len(line) == width for line in probe_lines), probe.stdout)
            self.assertTrue(all(line.endswith(("|", "+")) for line in probe_lines), probe.stdout)
            if width < 90:
                self.assertTrue(probe_lines[0].endswith(" |"), probe.stdout)
                self.assertIn(" current  | not-determined; reason: pam:ambiguous-stack", probe.stdout)
            else:
                pipe_positions = [i for i, ch in enumerate(probe_lines[0]) if ch == "|"]
                plus_positions = [i for i, ch in enumerate(probe_lines[1]) if ch == "+"]
                self.assertEqual(pipe_positions, plus_positions)
                self.assertEqual(len(pipe_positions), 5)
                for line in probe_lines[2:]:
                    if "|" in line:
                        self.assertEqual([i for i, ch in enumerate(line) if ch == "|"], pipe_positions)
                current_stream = "".join(
                    line.split("|")[3].strip() for line in probe_lines[2:] if line.count("|") == 5
                )
                self.assertIn("not-determined; reason: pam:ambiguous-stack".replace(" ", ""), current_stream.replace(" ", ""))
        for ambient_locale in ("C", "C.UTF-8"):
            for width in (80, 116, 139, 160):
                locale_probe = self.run_sourced(
                    f"\nexport LC_ALL={ambient_locale}\n"
                    f"slp_pretty_layout_for_cols {width}\n"
                    "slp_pretty_row 'st' 'source' 'control' 'current' 'required'\n"
                    "slp_pretty_separator\n"
                    "slp_pretty_row ok 'fstec-linux-2022 §2.3.1' group-mode 0644 '= 0644'\n"
                    "slp_pretty_row fail 'fstec-linux-2022 §2.3.10' home-sensitive-files-mode "
                    "'not-determined; reason: inventory:not-found' 'bits 0077 = 0'\n"
                    "slp_pretty_row fail 'fstec-linux-2022 §2.3.11' home-directories-mode "
                    "'accounts=2;homes=2;violations=1' '= 0700'\n"
                    "slp_pretty_row fail 'fstec-linux-2022 §2.5.11' randomize-va-space-tested-before-use "
                    "'not-determined; reason: authority:not-found' '= tested'\n"
                    "slp_pretty_separator\n"
                )
                self.assertEqual(locale_probe.returncode, 0, locale_probe.stderr)
                locale_lines = locale_probe.stdout.splitlines()
                self.assertTrue(locale_lines, locale_probe.stdout)
                self.assertTrue(
                    all(len(line) == width for line in locale_lines),
                    f"locale={ambient_locale} width={width}\n{locale_probe.stdout}",
                )
                self.assertTrue(
                    all(line.endswith(("|", "+")) for line in locale_lines),
                    f"locale={ambient_locale} width={width}\n{locale_probe.stdout}",
                )
                for source_text in (
                    "fstec-linux-2022 §2.3.1",
                    "fstec-linux-2022 §2.3.10",
                    "fstec-linux-2022 §2.3.11",
                    "fstec-linux-2022 §2.5.11",
                ):
                    self.assertIn(source_text, locale_probe.stdout)

        failed = self.run_sourced(pre + "\nslp_render_pretty 1 CHECK\n")
        self.assertEqual(failed.returncode, 0, failed.stderr)
        self.assertIn("home-directories-mode", failed.stdout)
        self.assertIn("home-sensitive-files-mode", failed.stdout)
        self.assertNotIn("group-mode", failed.stdout)
        raw = self.run_sourced(pre + "\nslp_render_raw 0\n")
        self.assertEqual(raw.returncode, 0, raw.stderr)
        raw_lines = raw.stdout.splitlines()
        self.assertEqual(len(raw_lines), 6)
        self.assertTrue(raw_lines[0].startswith("SLP-PLATFORM-V1\t"))
        self.assertIn("PROFILE=MINIMIZED", raw_lines[0])
        self.assertTrue(all(x.startswith("SLP-CHECK-V1\t") for x in raw_lines[1:-1]))
        obj = json.loads(self.run_sourced(pre + "\nslp_render_json 0\n").stdout)
        self.assertEqual(obj["schema"], "SLP-REPORT-V1")
        self.assertEqual(obj["platform"]["profile"], "MINIMIZED")
        self.assertEqual(obj["platform"]["platform_id"], "ubuntu-24.04-x86_64")
        self.assertEqual(obj["platform"]["support"], "SUPPORTED")
        self.assertEqual(obj["platform"]["type"], "")
        self.assertEqual(obj["summary"], {"total":4,"pass":2,"fail":1,"not_found":0,"not_applicable":0,"error":1})
        desktop_pre = self.synthetic_prelude() + "\nSLP_SYSTEM_PRETTY_NAME='Ubuntu 24.04.4 LTS'\nSLP_SYSTEM_ID='ubuntu'\nSLP_SYSTEM_VERSION_ID='24.04'\nSLP_SYSTEM_ARCH='x86_64'\nSLP_SYSTEM_PROFILE=''\nSLP_SYSTEM_TYPE='DESKTOP'\nSLP_SYSTEM_PLATFORM='ubuntu-24.04-x86_64'\nSLP_SYSTEM_ENVIRONMENT='ubuntu-24.04-x86_64-desktop'\n"
        desktop_pretty = self.run_sourced(desktop_pre + "\nslp_render_pretty 0 CHECK\n")
        self.assertEqual(desktop_pretty.returncode, 0, desktop_pretty.stderr)
        desktop_lines = desktop_pretty.stdout.splitlines()
        self.assertEqual(desktop_lines[1], "SUPPORT=FIELD_COMPATIBILITY")
        self.assertEqual(desktop_lines[2], "SYSTEM=Ubuntu 24.04.4 LTS ARCH=x86_64")
        self.assertEqual(desktop_lines[3], "PLATFORM=ubuntu-24.04-x86_64")
        self.assertEqual(desktop_lines[4], "TYPE=DESKTOP")
        self.assertEqual(desktop_lines[5], "")
        desktop_raw = self.run_sourced(desktop_pre + "\nslp_render_raw 0\n")
        self.assertIn("\tPROFILE=\tTYPE=DESKTOP\t", desktop_raw.stdout.splitlines()[0])
        self.assertIn("\tSUPPORT=FIELD_COMPATIBILITY", desktop_raw.stdout.splitlines()[0])
        desktop_obj = json.loads(self.run_sourced(desktop_pre + "\nslp_render_json 0\n").stdout)
        self.assertEqual(desktop_obj["platform"]["profile"], "")
        self.assertEqual(desktop_obj["platform"]["type"], "DESKTOP")
        self.assertEqual(desktop_obj["platform"]["support"], "FIELD_COMPATIBILITY")
        fobj = json.loads(self.run_sourced(pre + "\nslp_render_json 1\n").stdout)
        self.assertEqual([x["result"] for x in fobj["results"]], ["FAIL", "ERROR"])

    def test_src0034_randomize_va_space_is_decided_by_parameter_value_only(self):
        """2.5.11: единственная CHECK-функция SRC-0034 — sysctl; результат зависит
        только от значения kernel.randomize_va_space, файлы в
        /etc/securelinux-policy/ не читаются."""
        text = self.ARTIFACT.read_text(encoding="utf-8")
        self.assertNotIn("tested-setting-attestations-v1", text)
        self.assertNotIn("TESTED-BEFORE-USE", text)
        fns = sorted(set(re.findall(r"^(slp_check_FSTEC_LINUX_2022_2_5_11_[A-Z0-9_]+)\(\) \{$", text, re.M)))
        self.assertEqual(fns, ["slp_check_FSTEC_LINUX_2022_2_5_11_RANDOMIZE_VA_SPACE"])
        body = text[text.index(fns[0] + "() {"):]
        body = body[:body.index("\n}\n")]
        self.assertNotIn("/etc/securelinux-policy", body)
        proc = Path("/proc/sys/kernel/randomize_va_space")
        if not proc.is_file():
            self.skipTest("no /proc/sys/kernel/randomize_va_space")
        value = str(int(proc.read_text(encoding="ascii").strip()))
        cp = self.run_sourced(f"\n{fns[0]}\n")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(
            cp.stdout.splitlines(),
            ["\t".join(("SLP-CHECK-V1", "FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE", "VALUE", value, "PASS" if value == "2" else "FAIL"))],
        )

    def test_src0013_suid_sgid_is_decided_by_mode_only(self):
        """2.3.9: единственная CHECK-функция SRC-0013 — SUID-SGID-MODE; результат
        зависит только от прав SUID/SGID-файлов, файлы в /etc/securelinux-policy/
        не читаются."""
        text = self.ARTIFACT.read_text(encoding="utf-8")
        self.assertNotIn("suid-sgid.allowlist-v1", text)
        self.assertNotIn("SUID-SGID-ALLOWLIST", text)
        fns = sorted(set(re.findall(r"^(slp_check_FSTEC_LINUX_2022_2_3_9_[A-Z0-9_]+)\(\) \{$", text, re.M)))
        self.assertEqual(fns, ["slp_check_FSTEC_LINUX_2022_2_3_9_SUID_SGID_MODE"])
        body = text[text.index(fns[0] + "() {"):]
        body = body[:body.index("\n}\n") + 3]
        self.assertNotIn("/etc/securelinux-policy", body)
        # Общий код адаптера объявляет local _slp_allowlist_text, но ветка
        # чтения allowlist-файла (subset-of-file) в MODE-функцию не входит.
        self.assertNotIn('"$_slp_allowlist"', body)
        # Единственная подмена — путь mountinfo на фикстуру с одной точкой
        # монтирования; каталога /etc/securelinux-policy/ в фикстуре нет.
        canonical = "_slp_mountinfo='/proc/self/mountinfo'"
        self.assertEqual(body.count(canonical), 1)
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            mountinfo = base / "mountinfo"
            mountinfo.write_text(f"1 0 0:1 / {base} rw,relatime - ext4 /dev/test rw\n", encoding="utf-8")
            app = base / "app"
            app.write_text("x\n", encoding="utf-8")
            fixture = body.replace(canonical, "_slp_mountinfo=" + shlex.quote(str(mountinfo)))
            for mode, expected in ((0o4755, "violations=0\tPASS"), (0o4775, "violations=1\tFAIL")):
                with self.subTest(mode=oct(mode)):
                    os.chmod(app, mode)
                    cp = subprocess.run(
                        [BASH, "-c", "set -u\n" + fixture + "\n" + fns[0] + "\n"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    )
                    self.assertEqual(cp.returncode, 0, cp.stderr)
                    self.assertEqual(cp.stderr, "")
                    self.assertEqual(
                        cp.stdout,
                        "SLP-CHECK-V1\tFSTEC-LINUX-2022-2.3.9-SUID-SGID-MODE\tVALUE\tmounts=1;checked=1;" + expected + "\n",
                    )

    def test_retired_suid_sgid_allowlist_control_is_absent(self):
        """Выведенный 2.3.9 SUID-SGID-ALLOWLIST: control-yaml и строки манифеста
        нет; общий CHECK-адаптер suid-sgid-applications остаётся в реестре для MODE."""
        self.assertFalse(
            (ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.3.9-suid-sgid-allowlist.yaml").exists()
        )
        manifest = (ROOT / "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv").read_text(encoding="utf-8")
        self.assertNotIn("SUID-SGID-ALLOWLIST", manifest)
        registry = (ROOT / "product/ADAPTER-REGISTRY.tsv").read_text(encoding="utf-8")
        self.assertIn("\nsuid-sgid-applications\tproduct-suid-sgid-applications-check-v2\t", registry)

    def test_retired_tested_setting_attestation_is_historical_only(self):
        """Выведенный механизм подтверждения 2.5.11 — historical bytes (конвенция
        SRC-0001): файлы на месте, в ADAPTER-REGISTRY и артефакте его нет."""
        retired = (
            "product/adapters/product-tested-setting-attestation-check-v1.py",
            "product/adapters/product-tested-setting-attestation-check-v1.json",
            "product/contracts/tested-setting-attestation-check-semantic-v1.json",
        )
        for rel in retired:
            self.assertTrue((ROOT / rel).is_file(), rel)
        registry = (ROOT / "product/ADAPTER-REGISTRY.tsv").read_text(encoding="utf-8")
        self.assertNotIn("tested-setting-attestation", registry)
        artifact = self.ARTIFACT.read_text(encoding="utf-8")
        self.assertNotIn("tested-setting-attestation", artifact)
        self.assertFalse(
            (ROOT / "controls/fstec-core/linux-2022/fstec-linux-2022-2.5.11-randomize-va-space-tested-before-use.yaml").exists()
        )

    def test_required_presentation_covers_all_current_controls_from_machine_truth(self):
        rows, _ = GEN_V2_CURRENT.load_manifest(ROOT)
        controls = [GEN_V2_CURRENT.load_control(ROOT, row) for row in rows]
        rendered = {
            control["control_id"]: GEN_V2_CURRENT.required_display(
                control["expected_op"], control["expected_value"]
            )
            for control in controls
        }
        identities = {control["control_id"]: GEN_V2_CURRENT.terminal_identity(control) for control in controls}
        # Литерал: число canonical controls меняется только явным решением
        # (51 → 50: выведен 2.5.11 RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE;
        # 50 → 49: выведен 2.3.9 SUID-SGID-ALLOWLIST).
        self.assertEqual(len(rendered), 49)
        self.assertEqual(len(identities), 49)
        self.assertTrue(all(value and "\n" not in value and "\r" not in value for value in rendered.values()))
        self.assertEqual(identities["FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE"], ("fstec-linux-2022 §2.6.6", "suid-dumpable"))
        self.assertNotIn("FSTEC-LINUX-2022-2.5.11-RANDOMIZE-VA-SPACE-TESTED-BEFORE-USE", identities)
        with self.assertRaises(RuntimeError):
            GEN_V2_CURRENT.required_display("tested-before-use", "kernel.randomize_va_space=2")
        self.assertNotIn("FSTEC-LINUX-2022-2.3.9-SUID-SGID-ALLOWLIST", identities)
        with self.assertRaises(RuntimeError):
            GEN_V2_CURRENT.required_display("subset-of-file", "/etc/securelinux-policy/suid-sgid.allowlist-v1")
        self.assertEqual(
            GEN_V2_CURRENT.terminal_identity(
                {"control_id": "TEST-FILE-MODE", "doc_id": "fstec-linux-2022", "source_locator": "2.1.1"}
            ),
            ("fstec-linux-2022 §2.1.1", "test-file-mode"),
        )
        self.assertEqual(rendered["FSTEC-LINUX-2022-2.6.6-SUID-DUMPABLE"], "= 0")
        self.assertEqual(rendered["FSTEC-LINUX-2022-2.5.10-MMAP-MIN-ADDR"], ">= 4096")
        self.assertEqual(rendered["FSTEC-LINUX-2022-2.3.1-SHADOW-GO-RWX"], "bits 0077 = 0")
        self.assertEqual(rendered["FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE"], "present")
        self.assertEqual(rendered["FSTEC-LINUX-2022-2.5.3-DEBUGFS"], "one of: off|no-mount")

    def test_unified_provenance_invalid_cli_and_no_mutation_scaffold(self):
        prov = self.run_cli("--provenance")
        self.assertEqual(prov.returncode, 0)
        rows = [json.loads(x) for x in prov.stdout.splitlines()]
        current_control_count = len(GEN_V2_CURRENT.load_manifest(ROOT)[0])
        self.assertEqual(len(rows), current_control_count)
        apply_mechanisms, _, _ = GEN_V2_CURRENT.load_apply_mechanisms(ROOT)
        # Литерал закреплён явным решением: расширяется только осознанной правкой
        # этого теста при принятии нового APPLY-механизма, а не автоматически под
        # результат прогона.
        self.assertEqual(set(apply_mechanisms), {"sysctl", "file-mode-owner", "optional-file-root-files-mode", "suid-sgid-applications", "standard-system-paths-mode"})
        apply_rows = [row for row in rows if "apply" in row]
        expected_apply_controls = [
            c for c in (
                GEN_V2_CURRENT.load_control(ROOT, row)
                for row in GEN_V2_CURRENT.load_manifest(ROOT)[0]
            )
            if c["apply_supported"]
        ]
        self.assertEqual(len(apply_rows), len(expected_apply_controls))
        self.assertEqual({row["apply"]["route_status"] for row in apply_rows}, {"BOUND"})
        expected_parameter_kinds = {c["parameter_kind"] for c in expected_apply_controls}
        self.assertEqual({row["apply"]["parameter_kind"] for row in apply_rows}, expected_parameter_kinds)
        self.assertEqual(
            {row["apply"]["apply_kind"] for row in apply_rows},
            {apply_mechanisms[pk]["kind_row"]["apply_kind"] for pk in expected_parameter_kinds},
        )
        self.assertEqual(
            {row["apply"]["mechanism_id"] for row in apply_rows},
            {apply_mechanisms[pk]["authority"]["mechanism_id"] for pk in expected_parameter_kinds},
        )
        self.assertNotIn("FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE", {row["control_id"] for row in apply_rows})
        row = apply_rows[0]
        apply_id = row["control_id"]
        apply_one = self.run_cli("--provenance", apply_id)
        self.assertEqual(apply_one.returncode, 0, apply_one.stderr)
        self.assertEqual(json.loads(apply_one.stdout), row)
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


@unittest.skipIf(BASH is None, "bash not available")
class StartupFilesWriteProtectionFixtures(unittest.TestCase):
    def run_layout(self, rc_roots, unit_paths):
        source = STARTUP_FILES._shell_function_for_layout(
            "TEST-STARTUP-FILES", [str(x) for x in rc_roots], [str(x) for x in unit_paths]
        )
        return subprocess.run(
            [BASH, "-c", "set -u\n" + source + "\nslp_check_TEST_STARTUP_FILES"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def assert_error(self, cp, reason=None):
        self.assertEqual(cp.returncode, 0, cp.stderr)
        assert_stable_error_record(self, cp.stdout, "TEST-STARTUP-FILES", reason)

    def test_direct_population_mask_and_recursive_dependency_reference(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td); rc = base / "rc0.d"; units = base / "units"; rc.mkdir(); units.mkdir()
            target = base / "init-script"; target.write_text("x\n"); target.chmod(0o755); (rc / "S01x").symlink_to(target)
            svc = units / "a.service"; svc.write_text("[Service]\n"); svc.chmod(0o644)
            (units / "masked.service").symlink_to("/dev/null")
            wants = units / "multi-user.target.wants"; wants.mkdir(); bad = wants / "ignored.service"; bad.write_text("x\n"); bad.chmod(0o666)
            cp = self.run_layout([rc], [units])
            self.assertEqual(cp.stderr, "")
            self.assertIn("rc_entries=1", cp.stdout); self.assertIn("service_entries=2", cp.stdout)
            self.assertIn("service_masked=1", cp.stdout); self.assertIn("violations=0\tPASS", cp.stdout)

    def test_rc_other_write_is_fail(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); rc=base/"rc0.d"; units=base/"units"; rc.mkdir(); units.mkdir()
            f=rc/"S01x"; f.write_text("x\n"); f.chmod(0o646)
            (units/"a.service").write_text("x\n"); (units/"a.service").chmod(0o644)
            cp=self.run_layout([rc],[units]); self.assertIn("violations=1\tFAIL",cp.stdout)

    def test_service_other_write_is_fail(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); units=base/"units"; units.mkdir(); f=units/"a.service"; f.write_text("x\n"); f.chmod(0o646)
            cp=self.run_layout([], [units]); self.assertIn("violations=1\tFAIL",cp.stdout)

    def test_service_symlink_final_regular_target_is_checked(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); units=base/"units"; units.mkdir(); target=base/"real"; target.write_text("x\n"); target.chmod(0o646)
            (units/"a.service").symlink_to(target)
            cp=self.run_layout([], [units]); self.assertIn("violations=1\tFAIL",cp.stdout)

    def test_masked_only_and_empty_populations_are_determinate(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); units=base/"units"; units.mkdir(); (units/"masked.service").symlink_to("/dev/null")
            cp=self.run_layout([], [units]); self.assertIn("service_masked=1",cp.stdout); self.assertIn("checked=0;violations=0\tPASS",cp.stdout)
            empty=base/"empty"; empty.mkdir(); cp=self.run_layout([], [empty]); self.assertIn("service_entries=0",cp.stdout); self.assertIn("checked=0;violations=0\tPASS",cp.stdout)

    def test_dangling_and_special_selected_entries_are_error(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); units=base/"units"; units.mkdir(); (units/"bad.service").symlink_to(base/"missing")
            self.assert_error(self.run_layout([], [units]), "target:stat-failed")
        if hasattr(os, "mkfifo"):
            with tempfile.TemporaryDirectory() as td:
                units=Path(td)/"units"; units.mkdir(); os.mkfifo(units/"pipe.service")
                self.assert_error(self.run_layout([], [units]), "target:invalid-type")

    def test_dangling_rc_entry_is_error(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); rc=base/"rc0.d"; units=base/"units"; rc.mkdir(); units.mkdir(); (rc/"S01bad").symlink_to(base/"missing")
            (units/"a.service").write_text("x\n")
            self.assert_error(self.run_layout([rc], [units]), "target:stat-failed")

    def test_merged_unit_root_alias_is_deduplicated(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td); real=base/"usr-lib-systemd"; real.mkdir(); (real/"a.service").write_text("x\n")
            alias=base/"lib-systemd"; alias.symlink_to(real, target_is_directory=True)
            cp=self.run_layout([], [alias, real]); self.assertIn("service_root_aliases=1",cp.stdout); self.assertIn("service_entries=1",cp.stdout); self.assertIn("violations=0\tPASS",cp.stdout)

    def test_direct_service_directory_is_error_but_nonservice_directory_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            units=Path(td)/"units"; units.mkdir(); (units/"x.wants").mkdir(); (units/"bad.service").mkdir()
            self.assert_error(self.run_layout([], [units]), "target:invalid-type")

    def test_generation_rejects_wrong_contract_fields(self):
        good="/etc/rc[0-6].d|systemd-unit-paths"
        for args in (("TEST","/etc/rc#.d","other-write","bits-clear","0002"),("TEST",good,"mode","bits-clear","0002"),("TEST",good,"other-write","eq","0002"),("TEST",good,"other-write","bits-clear","0022")):
            with self.subTest(args=args):
                with self.assertRaises(ValueError): STARTUP_FILES.shell_function(*args)


class CronCommandPathsWriteProtectionFixtures(unittest.TestCase):
    @staticmethod
    def _base(root):
        for rel in ("etc/cron.d", "var/spool/cron/crontabs", "usr/bin", "bin"):
            (root / rel).mkdir(parents=True, exist_ok=True)
        runner_uid = os.getuid()
        runner_gid = os.getgid()
        (root / "etc/passwd").write_text(
            f"root:x:0:0:root:/root:/bin/sh\nuser:x:{runner_uid}:{runner_gid}:user:/home/user:/bin/sh\nnonroot:x:424242:424242:nonroot:/home/nonroot:/bin/sh\n",
            encoding="utf-8",
        )
        for rel in ("usr/bin/run-parts", "usr/bin/tool"):
            path = root / rel
            path.write_text("fixture\n", encoding="utf-8")
            path.chmod(0o555)

    @staticmethod
    def _script(root):
        src = CRON_COMMAND_PATHS._shell_function_for_root("TEST-CRON-PATHS", str(root), os.getuid())
        script = root / "run.sh"
        script.write_text(
            "#!/bin/bash -p\n" + src + "\nslp_check_TEST_CRON_PATHS\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script

    def _run(self, root):
        cp = subprocess.run(
            [str(self._script(root))], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        row = cp.stdout.strip().split("\t")
        self.assertEqual(len(row), 5, cp.stdout + cp.stderr)
        return row

    @staticmethod
    def _user_crontab(root, text, mode=0o600):
        path = root / "var/spool/cron/crontabs/user"
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return path

    def test_adapter_selftest(self):
        cp = subprocess.run(
            [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B", str(CRON_COMMAND_PATHS_ADAPTER_PATH)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("ADAPTER_SELFTEST=PASS", cp.stdout)

    def test_empty_population_passes(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
            self.assertIn("jobs=0", row[3])

    def test_default_system_run_parts_population_passes(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            periodic = root / "etc/cron.hourly"; periodic.mkdir()
            job = periodic / "job"; job.write_text("x\n", encoding="utf-8"); job.chmod(0o555)
            (root / "etc/crontab").write_text(
                "PATH=/usr/bin:/bin\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
                encoding="utf-8",
            )
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
            self.assertIn("targets=2", row[3])
            self.assertIn("periodic_dirs=1", row[3])

    def test_periodic_target_go_w_is_fail(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            periodic = root / "etc/cron.hourly"; periodic.mkdir()
            job = periodic / "job"; job.write_text("x\n", encoding="utf-8"); job.chmod(0o575)
            (root / "etc/crontab").write_text(
                "PATH=/usr/bin:/bin\n17 * * * * root run-parts --report /etc/cron.hourly\n",
                encoding="utf-8",
            )
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
            self.assertIn("violations=1", row[3])

    def test_direct_absolute_command_go_w_is_fail(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /opt/job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))

    def test_user_absolute_command_passes(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            self._user_crontab(root, "0 1 * * * /opt/job\n")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))

    def test_non_root_bare_command_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            (root / "etc/crontab").write_text(
                "PATH=/usr/bin:/bin\n0 1 * * * nonroot tool\n", encoding="utf-8"
            )
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unresolved-name")

    def test_root_bare_command_without_explicit_path_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            (root / "etc/crontab").write_text("0 1 * * * root tool\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unresolved-name")

    def test_dynamic_shell_expansion_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            (root / "etc/crontab").write_text("PATH=/usr/bin:/bin\n0 1 * * * root $CMD\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:invalid-bytes")

    def test_redirection_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            (root / "etc/crontab").write_text("PATH=/usr/bin:/bin\n0 1 * * * root tool >/tmp/out\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-redirection")

    def test_percent_stdin_tail_does_not_add_command(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            (root / "etc/crontab").write_text("0 1 * * * root /opt/job%/missing/not-a-command\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
            self.assertIn("targets=1", row[3])

    def test_valid_cron_d_file_is_included_and_dot_name_is_ignored(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            good = root / "etc/cron.d/local_job"; good.write_text("0 1 * * * root /opt/job\n"); good.chmod(0o644)
            ignored = root / "etc/cron.d/local.job"; ignored.write_text("malformed should be ignored\n"); ignored.chmod(0o644)
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "PASS"))
            self.assertIn("configs=1", row[3])

    def test_unknown_system_user_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            (root / "etc/crontab").write_text("0 1 * * * missing /opt/job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "cron:unknown-user")

    def test_interpreter_invocation_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            shell = root / "bin/sh"; shell.write_text("x\n"); shell.chmod(0o555)
            script = root / "opt/job.py"; script.parent.mkdir(); script.write_text("x\n"); script.chmod(0o444)
            (root / "etc/crontab").write_text("0 1 * * * root /bin/sh /opt/job.py\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_absolute_wrapper_path_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            wrapper = root / "usr/bin/env"; wrapper.write_text("x\n"); wrapper.chmod(0o555)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/env /opt/job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_additional_launcher_wrappers_are_error(self):
        if BASH is None: self.skipTest("bash not found")
        for launcher_name in (
            "time", "setpriv", "unshare", "nsenter", "prlimit", "setarch", "linux32", "linux64",
            "chrt", "watch", "strace", "ltrace", "gdb", "valgrind", "perf", "script",
            "daemon", "daemonize", "parallel", "numactl", "capsh", "firejail", "bwrap",
            "fakeroot", "torsocks", "proxychains", "proxychains4", "eatmydata", "sg", "newgrp",
            "docker", "podman", "systemd-nspawn", "machinectl",
        ):
            with self.subTest(launcher=launcher_name):
                with tempfile.TemporaryDirectory(dir=ROOT) as td:
                    root = Path(td); self._base(root)
                    launcher = root / ("usr/bin/" + launcher_name); launcher.write_text("x\n"); launcher.chmod(0o555)
                    target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
                    (root / "etc/crontab").write_text(f"0 1 * * * root /usr/bin/{launcher_name} /opt/job\n", encoding="utf-8")
                    row = self._run(root)
                    self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
                    self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_symlink_alias_interpreter_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            shell = root / "bin/sh"; shell.write_text("x\n"); shell.chmod(0o555)
            alias = root / "usr/bin/job-shell"; alias.symlink_to("../../bin/sh")
            target = root / "opt/hidden-job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/job-shell -c /opt/hidden-job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_symlink_alias_run_parts_expands_population(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            alias = root / "usr/bin/periodic-runner"; alias.symlink_to("run-parts")
            periodic = root / "etc/cron.hourly"; periodic.mkdir()
            job = periodic / "job"; job.write_text("x\n"); job.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/periodic-runner /etc/cron.hourly\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("VALUE", "FAIL"))
            self.assertIn("periodic_dirs=1", row[3])
            self.assertIn("violations=1", row[3])

    def test_symlink_alias_launcher_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            launcher = root / "usr/bin/time"; launcher.write_text("x\n"); launcher.chmod(0o555)
            alias = root / "usr/bin/job-launcher"; alias.symlink_to("time")
            target = root / "opt/hidden-job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/job-launcher /opt/hidden-job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_hardlink_alias_interpreter_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            shell = root / "bin/sh"; shell.write_text("x\n"); shell.chmod(0o555)
            alias = root / "usr/bin/job-shell"; os.link(shell, alias)
            target = root / "opt/hidden-job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/job-shell -c /opt/hidden-job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "target:hardlink")

    def test_hardlink_alias_run_parts_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            alias = root / "usr/bin/periodic-runner"; os.link(root / "usr/bin/run-parts", alias)
            periodic = root / "etc/cron.hourly"; periodic.mkdir()
            job = periodic / "job"; job.write_text("x\n"); job.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/periodic-runner /etc/cron.hourly\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "target:hardlink")

    def test_versioned_interpreter_path_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            interpreter = root / "usr/bin/python3.12"; interpreter.write_text("x\n"); interpreter.chmod(0o555)
            script = root / "opt/job.py"; script.parent.mkdir(); script.write_text("x\n"); script.chmod(0o575)
            (root / "etc/crontab").write_text("0 1 * * * root /usr/bin/python3.12 /opt/job.py\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "command:unsupported-execution-chain")

    def test_shell_override_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            (root / "etc/crontab").write_text("SHELL=/bin/bash\n0 1 * * * root /opt/job\n", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "cron:unsupported-shell")

    def test_missing_final_newline_is_error(self):
        if BASH is None: self.skipTest("bash not found")
        with tempfile.TemporaryDirectory(dir=ROOT) as td:
            root = Path(td); self._base(root)
            target = root / "opt/job"; target.parent.mkdir(); target.write_text("x\n"); target.chmod(0o555)
            (root / "etc/crontab").write_text("0 1 * * * root /opt/job", encoding="utf-8")
            row = self._run(root)
            self.assertEqual((row[2], row[4]), ("ERROR", "ERROR"))
            self.assertEqual(row[3], "cron:invalid-line-ending")

    def test_generation_rejects_wrong_contract_fields(self):
        bad = (
            ("CTRL", "/etc/crontab", CRON_COMMAND_PATHS.CANONICAL_KEY, CRON_COMMAND_PATHS.CANONICAL_OP, CRON_COMMAND_PATHS.CANONICAL_EXPECTED),
            ("CTRL", CRON_COMMAND_PATHS.CANONICAL_LOCATOR, "mode", CRON_COMMAND_PATHS.CANONICAL_OP, CRON_COMMAND_PATHS.CANONICAL_EXPECTED),
            ("CTRL", CRON_COMMAND_PATHS.CANONICAL_LOCATOR, CRON_COMMAND_PATHS.CANONICAL_KEY, "bits-clear", CRON_COMMAND_PATHS.CANONICAL_EXPECTED),
            ("CTRL", CRON_COMMAND_PATHS.CANONICAL_LOCATOR, CRON_COMMAND_PATHS.CANONICAL_KEY, CRON_COMMAND_PATHS.CANONICAL_OP, "0022"),
        )
        for args in bad:
            with self.assertRaises(ValueError):
                CRON_COMMAND_PATHS.shell_function(*args)


class ApplyMechanismRegistryIntegration(unittest.TestCase):
    """Regression for H46 mechanism-oriented APPLY integration decisions."""

    def _current_apply(self):
        rows, _ = GEN_V2_CURRENT.load_manifest(ROOT)
        controls = [GEN_V2_CURRENT.load_control(ROOT, row) for row in rows]
        mechanisms, _, _ = GEN_V2_CURRENT.load_apply_mechanisms(ROOT)
        enabled = [control for control in controls if control["apply_supported"]]
        return controls, enabled, mechanisms

    def test_current_sysctl_route_and_population_are_exact(self):
        controls, enabled, mechanisms = self._current_apply()
        # Литерал закреплён явным решением: расширяется только осознанной правкой
        # этого теста при принятии нового APPLY-механизма, а не автоматически под
        # результат прогона.
        self.assertEqual(set(mechanisms), {"sysctl", "file-mode-owner", "optional-file-root-files-mode", "suid-sgid-applications", "standard-system-paths-mode"})
        mechanism = mechanisms["sysctl"]
        self.assertEqual(mechanism["kind_row"]["apply_kind"], "config-line-with-runtime-v1")
        self.assertEqual(mechanism["kind_row"]["authority_form"], "MECHANISM_AUTHORITY_V1")
        self.assertEqual(mechanism["authority"]["mechanism_id"], "config-line-with-runtime-v1")
        # Runtime writer rules are checked against the adapter that the generator
        # loaded, not against authority prose. The literal changes only by
        # explicit decision.
        self.assertEqual(
            set(mechanism["module"].SERVICE_MANAGED_RUNTIME_WRITERS),
            {"APPORT-NATIVE-SUID-DUMPABLE-V1", "APPORT-SYSV-SUID-DUMPABLE-V1"},
        )
        # Литералы закреплены явным решением: меняются только осознанной правкой
        # этого теста при изменении APPLY-популяции, а не автоматически под
        # результат прогона. Вычисление здесь дало бы сравнение реестра с собой.
        self.assertEqual(len(enabled), 28)
        self.assertEqual(
            {control["parameter_kind"] for control in enabled},
            {"sysctl", "file-mode-owner", "optional-file-root-files-mode", "suid-sgid-applications", "standard-system-paths-mode"},
        )
        self.assertNotIn(
            "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE",
            {control["control_id"] for control in enabled},
        )
        src0001 = next(
            control for control in controls
            if control["control_id"] == "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE"
        )
        self.assertFalse(src0001["apply_supported"])
        dispatcher = GEN_V2_CURRENT.render_product_apply_dispatcher(enabled, mechanisms)
        self.assertIn("for control in APPLY_CONTROLS:", dispatcher)
        self.assertIn("execute_control", dispatcher)
        self.assertIn("routing:mechanism-unavailable", dispatcher)
        self.assertIn('payload["rc_zero"] = all(item["step_rc"] == "0"', dispatcher)
        self.assertNotIn('item["step_rc"] == 0', dispatcher)
        self.assertNotIn("SRC-0001", dispatcher)

    def test_apply_dispatcher_terminal_rows_summary_and_debug_log(self):
        implementation = (
            'MECHANISM_ID = "test-mechanism"\n'
            'ADAPTER_ID = "test-adapter"\n'
            'def execute_control(control_id, key, op, expected, apply_supported, dry_run=False):\n'
            '    return control_id\n'
            'def control_result_to_report(result, started_at, finished_at):\n'
            '    outcome = "APPLIED" if result.endswith("-CTRL-A") else "ALREADY_COMPLIANT"\n'
            '    before = 0 if result.endswith("-CTRL-A") else 1\n'
            '    return {"control_id": result, "outcome": outcome, "reason": "applied" if outcome == "APPLIED" else "already-compliant", "actions_attempted": ["FINAL_POSTCHECK"], "step_rc": "0", "mutation_performed": outcome == "APPLIED", "transaction_commit": "COMMITTED", "started_at": started_at, "finished_at": finished_at, "key": "kernel.synthetic", "runtime_before": before, "runtime_after": 1}\n'
        ).encode("utf-8")
        impl_sha = __import__("hashlib").sha256(implementation).hexdigest()
        controls = [
            {"control_id": "FSTEC-LINUX-2099-9.9.1-CTRL-A", "doc_id": "fstec-linux-2099", "source_locator": "9.9.1", "parameter_kind": "synthetic", "parameter_key": "kernel.a", "expected_op": "eq", "expected_value": 1},
            {"control_id": "FSTEC-LINUX-2099-9.9.2-CTRL-B", "doc_id": "fstec-linux-2099", "source_locator": "9.9.2", "parameter_kind": "synthetic", "parameter_key": "kernel.b", "expected_op": "eq", "expected_value": 1},
        ]
        mechanisms = {"synthetic": {"kind_row": {"apply_kind": "test-kind"}, "authority": {"mechanism_id": "test-mechanism"}, "implementation_row": {"adapter_id": "test-adapter", "implementation_sha256": impl_sha}, "implementation_source": implementation}}
        dispatcher = GEN_V2_CURRENT.render_product_apply_dispatcher(controls, mechanisms)

        presentation = dispatcher.split("started_at = now()", 1)[0]
        self.assertNotEqual(presentation, dispatcher)
        for width in (80, 116, 139, 160):
            probe_source = (
                presentation
                + f"\nPRETTY_COLUMNS={width}\nPRETTY_IS_TTY=True\n"
                + "_emit_table_row('st','source','control','current','required')\n"
                + "_emit_separator()\n"
                + "_emit_table_row('err','fstec-linux-2022 §2.3.10','home-sensitive-files-mode',"
                  "'not-determined; reason: pam:ambiguous-stack','bits 0077 = 0')\n"
            )
            probe = subprocess.run(
                [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B", "-", "APPLY"],
                input=probe_source,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=ROOT,
            )
            self.assertEqual(probe.returncode, 0, probe.stderr)
            probe_lines = probe.stdout.splitlines()
            self.assertTrue(probe_lines, probe.stdout)
            self.assertTrue(all(len(line) == width for line in probe_lines), probe.stdout)
            self.assertTrue(all(line.endswith(("|", "+")) for line in probe_lines), probe.stdout)
            if width >= 90:
                pipe_positions = [i for i, ch in enumerate(probe_lines[0]) if ch == "|"]
                plus_positions = [i for i, ch in enumerate(probe_lines[1]) if ch == "+"]
                self.assertEqual(pipe_positions, plus_positions)
                self.assertEqual(len(pipe_positions), 5)
                current_stream = "".join(
                    line.split("|")[3].strip() for line in probe_lines[2:] if line.count("|") == 5
                )
                self.assertIn("not-determined; reason: pam:ambiguous-stack".replace(" ", ""), current_stream.replace(" ", ""))

        with tempfile.TemporaryDirectory(prefix="slp-dispatcher-terminal-", dir=ROOT) as td:
            isolated = dispatcher.replace('STATE_DIR = "/var/log/securelinux-policy"', "STATE_DIR = " + repr(td), 1).replace("TRUSTED_UID = PARENT_TRUSTED_UID = 0", "TRUSTED_UID = PARENT_TRUSTED_UID = %d" % os.getuid(), 1)
            cp = subprocess.run([os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B", "-", "APPLY"], input=isolated, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=ROOT)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(cp.stderr, "")
            self.assertIn("MODE=APPLY APPLY_CONTROLS=2\n", cp.stdout)
            lines = cp.stdout.splitlines()
            header = lines[1]
            self.assertEqual(header.count("|"), 5)
            self.assertEqual(lines[2].count("+"), 5)
            rows_a = [line for line in lines if "ctrl-a" in line]
            rows_b = [line for line in lines if "ctrl-b" in line]
            self.assertEqual(len(rows_a), 1, cp.stdout)
            self.assertEqual(len(rows_b), 1, cp.stdout)
            self.assertIn("done", rows_a[0])
            self.assertIn("ok", rows_b[0])
            self.assertIn("fstec-linux-2099 §9.9.1", rows_a[0])
            self.assertIn("= 1", rows_a[0])
            self.assertIn("= 1", rows_b[0])
            self.assertNotIn("\nblocks\n", cp.stdout)
            self.assertNotIn("detail: applied", cp.stdout)
            self.assertNotIn("detail: already-compliant", cp.stdout)
            self.assertIn("TOTAL=2 ALREADY_COMPLIANT=1 APPLIED=1 RC=0\n", cp.stdout)
            self.assertLess(cp.stdout.index("+"), cp.stdout.index("TOTAL=2"))
            state = Path(td)
            self.assertTrue((state / "apply.log").is_file())
            self.assertTrue((state / "debug.log").is_file())
            self.assertEqual((state / "debug.log").read_bytes(), b"")
            payload = json.loads((state / "report.json").read_text(encoding="utf-8"))
            self.assertTrue(payload["complete"])
            self.assertTrue(payload["rc_zero"])
            self.assertEqual(len(payload["controls"]), 2)

    def test_apply_presentation_widths_block_locator_and_file_mode_current(self):
        records = {
            "FSTEC-LINUX-2099-9.9.4-PASSWD-MODE": {
                "outcome": "ABORTED_PRECONDITION_CONFLICT", "reason": "mode-relaxation-forbidden",
                "step_rc": "nonzero", "mutation_performed": False, "transaction_commit": "NOT_STARTED",
                "current_mode": "0600", "planned_mode": "0644", "resulting_mode": None,
            },
            "FSTEC-LINUX-2099-9.9.5-GROUP-MODE": {
                "outcome": "APPLIED", "reason": None,
                "step_rc": "0", "mutation_performed": True, "transaction_commit": "COMMITTED",
                "current_mode": "0664", "planned_mode": "0644", "resulting_mode": "0644",
            },
        }
        implementation = (
            'import json\n'
            'MECHANISM_ID = "test-mechanism"\n'
            'ADAPTER_ID = "test-adapter"\n'
            f'RECORDS = json.loads({json.dumps(json.dumps(records))})\n'
            'def execute_control(control_id, key, op, expected, apply_supported, dry_run=False):\n'
            '    return control_id\n'
            'def control_result_to_report(result, started_at, finished_at):\n'
            '    record = dict(RECORDS[result])\n'
            '    record.update({"control_id": result, "actions_attempted": ["P0_ELIGIBILITY"], "started_at": started_at, "finished_at": finished_at, "target": "/etc/" + result.split("-")[-2].lower()})\n'
            '    return record\n'
        ).encode("utf-8")
        impl_sha = __import__("hashlib").sha256(implementation).hexdigest()
        controls = [
            {"control_id": cid, "doc_id": "fstec-linux-2099", "source_locator": cid.split("-")[3],
             "parameter_kind": "synthetic", "parameter_key": "mode", "expected_op": "eq", "expected_value": "0644"}
            for cid in records
        ]
        mechanisms = {"synthetic": {"kind_row": {"apply_kind": "test-kind"}, "authority": {"mechanism_id": "test-mechanism"}, "implementation_row": {"adapter_id": "test-adapter", "implementation_sha256": impl_sha}, "implementation_source": implementation}}
        dispatcher = GEN_V2_CURRENT.render_product_apply_dispatcher(controls, mechanisms)

        presentation = dispatcher.split("started_at = now()", 1)[0]
        for width, expected in CURRENT_REQUIRED_WIDTHS.items():
            probe = subprocess.run(
                [os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B", "-", "APPLY"],
                input=presentation + f"\nprint(_terminal_layout({width})[2][3:])\n",
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=ROOT,
            )
            self.assertEqual(probe.returncode, 0, probe.stderr)
            self.assertEqual(probe.stdout.strip(), str(expected), width)

        with tempfile.TemporaryDirectory(prefix="slp-dispatcher-presentation-", dir=ROOT) as td:
            isolated = dispatcher.replace('STATE_DIR = "/var/log/securelinux-policy"', "STATE_DIR = " + repr(td), 1).replace("TRUSTED_UID = PARENT_TRUSTED_UID = 0", "TRUSTED_UID = PARENT_TRUSTED_UID = %d" % os.getuid(), 1)
            cp = subprocess.run([os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B", "-", "APPLY"], input=isolated, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=ROOT)
            self.assertEqual(cp.stderr, "")
            lines = cp.stdout.splitlines()
            blocks_index = lines.index("blocks")
            main = lines[:blocks_index]
            passwd_row = next(line for line in main if "passwd-mode" in line and "|" in line)
            group_row = next(line for line in main if "group-mode" in line and "|" in line)
            # current берётся из current_mode/resulting_mode механизма режимов файлов.
            self.assertEqual(passwd_row.split("|")[3].strip(), "0600", passwd_row)
            self.assertEqual(group_row.split("|")[3].strip(), "0644", group_row)
            self.assertNotIn("not-determined", "\n".join(main))
            block_lines = lines[blocks_index + 1:]
            control_stream = [line.split("|")[0].strip() for line in block_lines if line.count("|") == 3]
            self.assertIn("§9.9.4 passwd-mode", control_stream)
            self.assertTrue(all(len(line) == 116 for line in block_lines if "|" in line or "+" in line), cp.stdout)

    def test_apply_dispatcher_required_column_on_precondition_conflict(self):
        implementation = (
            'MECHANISM_ID = "test-mechanism"\n'
            'ADAPTER_ID = "test-adapter"\n'
            'def execute_control(control_id, key, op, expected, apply_supported, dry_run=False):\n'
            '    return control_id\n'
            'def control_result_to_report(result, started_at, finished_at):\n'
            '    return {"control_id": result, "outcome": "ABORTED_PRECONDITION_CONFLICT", "reason": "runtime-writer:APPORT-NATIVE-SUID-DUMPABLE-V1:C4:agent-exact", "actions_attempted": ["P2R_RUNTIME_WRITER"], "step_rc": "nonzero", "mutation_performed": False, "transaction_commit": "NOT_STARTED", "started_at": started_at, "finished_at": finished_at, "key": "fs.suid_dumpable", "runtime_before": 2, "runtime_after": None, "operator_decision": {"class": "SERVICE_MANAGED_PARAMETER", "required": True, "service": "Apport", "parameter": "fs.suid_dumpable", "current_value": 2}}\n'
        ).encode("utf-8")
        impl_sha = __import__("hashlib").sha256(implementation).hexdigest()
        controls = [
            {"control_id": "FSTEC-LINUX-2099-9.9.3-SUID-DUMPABLE", "doc_id": "fstec-linux-2099", "source_locator": "9.9.3", "parameter_kind": "synthetic", "parameter_key": "fs.suid_dumpable", "expected_op": "eq", "expected_value": 0},
        ]
        mechanisms = {"synthetic": {"kind_row": {"apply_kind": "test-kind"}, "authority": {"mechanism_id": "test-mechanism"}, "implementation_row": {"adapter_id": "test-adapter", "implementation_sha256": impl_sha}, "implementation_source": implementation}}
        dispatcher = GEN_V2_CURRENT.render_product_apply_dispatcher(controls, mechanisms)
        with tempfile.TemporaryDirectory(prefix="slp-dispatcher-required-", dir=ROOT) as td:
            isolated = dispatcher.replace('STATE_DIR = "/var/log/securelinux-policy"', "STATE_DIR = " + repr(td), 1).replace("TRUSTED_UID = PARENT_TRUSTED_UID = 0", "TRUSTED_UID = PARENT_TRUSTED_UID = %d" % os.getuid(), 1)
            cp = subprocess.run([os.environ.get("PYTHON", "/usr/bin/python3"), "-I", "-S", "-B", "-", "APPLY"], input=isolated, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=ROOT)
            self.assertEqual(cp.returncode, 1, cp.stderr)
            self.assertEqual(cp.stderr, "")
            lines = cp.stdout.splitlines()
            row = next(line for line in lines if "suid-dumpable" in line and "|" in line)
            self.assertIn("block", row)
            self.assertIn("fstec-linux-2099 §9.9.3", row)
            self.assertIn("| 2", row)
            self.assertIn("= 0", row)
            blocks_index = lines.index("blocks")
            total_index = next(i for i, line in enumerate(lines) if line.startswith("TOTAL=1 "))
            main_plus = [i for i, line in enumerate(lines[:blocks_index]) if "+" in line]
            self.assertGreaterEqual(len(main_plus), 2, cp.stdout)
            self.assertLess(max(main_plus), blocks_index)
            self.assertLess(blocks_index, total_index)
            main_table = [line for line in lines[1:blocks_index] if "|" in line or "+" in line]
            self.assertTrue(main_table, cp.stdout)
            self.assertTrue(all(len(line) == 116 for line in main_table), cp.stdout)
            self.assertTrue(all(line.endswith(("|", "+")) for line in main_table), cp.stdout)
            self.assertEqual(next(line for line in main_table if "source" in line).count("|"), 5)
            table_text = "\n".join(lines[:blocks_index])
            self.assertNotIn("detail:", table_text)
            self.assertNotIn("note:", table_text)

            blocks_header = lines[blocks_index + 1]
            blocks_separator = lines[blocks_index + 2]
            blocks_end = lines[total_index - 1]
            self.assertIn("control", blocks_header)
            self.assertIn("type", blocks_header)
            self.assertIn("message", blocks_header)
            self.assertEqual(blocks_header.count("|"), 3)
            self.assertEqual(blocks_separator.count("+"), 3)
            self.assertEqual(blocks_end.count("+"), 3)
            block_table_lines = lines[blocks_index + 1:total_index]
            self.assertTrue(all(len(line) == 116 for line in block_table_lines), cp.stdout)
            self.assertTrue(all(line.endswith(("|", "+")) for line in block_table_lines), cp.stdout)
            message_stream = "".join(
                line.split("|")[2].strip()
                for line in block_table_lines
                if line.count("|") == 3
            )
            type_stream = " ".join(
                line.split("|")[1].strip()
                for line in block_table_lines
                if line.count("|") == 3
            )
            self.assertIn("suid-dumpable", "\n".join(block_table_lines))
            self.assertIn("detail", type_stream)
            self.assertIn("note", type_stream)
            self.assertIn("runtime-writer:APPORT-NATIVE-SUID-DUMPABLE-V1:C4:agent-exact", message_stream)
            self.assertIn(
                "fs.suid_dumpable=2: обнаружен штатный механизм Apport, управляющий этим параметром.",
                message_stream,
            )
            self.assertIn(
                "Автоматическое изменение пропущено. Требуется решение администратора.",
                message_stream,
            )
            self.assertIn("TOTAL=1 ABORTED_PRECONDITION_CONFLICT=1 RC=NONZERO", cp.stdout)


    def _step_rc_literal_for_dispatcher_function(self, function_name):
        _, enabled, mechanisms = self._current_apply()
        dispatcher = GEN_V2_CURRENT.render_product_apply_dispatcher(enabled, mechanisms)
        tree = ast.parse(dispatcher)
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        )
        return_dict = next(
            node.value for node in function.body
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
        )
        fields = {
            key.value: value
            for key, value in zip(return_dict.keys, return_dict.values)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        self.assertIn("step_rc", fields)
        literal = fields["step_rc"]
        self.assertIsInstance(literal, ast.Constant)
        return literal.value

    def test_unavailable_record_step_rc_is_string_nonzero(self):
        value = self._step_rc_literal_for_dispatcher_function("unavailable_record")
        self.assertIsInstance(value, str)
        self.assertEqual(value, "nonzero")
        self.assertNotEqual(value, 1)

    def test_crash_record_step_rc_is_string_nonzero(self):
        value = self._step_rc_literal_for_dispatcher_function("crash_record")
        self.assertIsInstance(value, str)
        self.assertEqual(value, "nonzero")
        self.assertNotEqual(value, 1)

    @staticmethod
    def _write_synthetic_pair(root: Path, suffix: str, parameter_kind: str):
        contracts = root / "product/contracts"
        adapters = root / "product/apply-adapters"
        contracts.mkdir(parents=True, exist_ok=True)
        adapters.mkdir(parents=True, exist_ok=True)
        apply_kind = f"mechanism-{suffix}"
        adapter_id = f"adapter-{suffix}"
        authority_rel = f"product/contracts/{apply_kind}.json"
        binding_rel = f"product/apply-adapters/{adapter_id}.json"
        implementation_rel = f"product/apply-adapters/{adapter_id}.py"
        architecture_id = f"architecture-{suffix}"
        composition_id = f"composition-{suffix}"
        binding_id = f"binding-{suffix}"
        authority = {
            "authority_form": "MECHANISM_AUTHORITY_V1",
            "mechanism_id": apply_kind,
            "registry_binding": {
                "apply_kind": apply_kind,
                "parameter_kind": parameter_kind,
                "target_class": f"target-{suffix}",
                "architecture_id": architecture_id,
                "composition_contract_id": composition_id,
                "authority_path": authority_rel,
                "legacy_column_semantics": {"synthetic": True},
                "adapter_id": adapter_id,
                "binding_contract_id": binding_id,
            },
        }
        authority_path = root / authority_rel
        authority_path.write_text(
            json.dumps(authority, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        implementation_path = root / implementation_rel
        implementation_path.write_text(
            "\n".join([
                f"ADAPTER_ID = {adapter_id!r}",
                f"MECHANISM_ID = {apply_kind!r}",
                "TARGET_ID = 'linux-x86_64-supported-v1'",
                "def execute_control(*args, **kwargs): return None",
                "def control_result_to_report(*args, **kwargs): return {}",
                "",
            ]),
            encoding="utf-8",
        )
        authority_sha = hashlib.sha256(authority_path.read_bytes()).hexdigest()
        implementation_sha = hashlib.sha256(implementation_path.read_bytes()).hexdigest()
        binding = {
            "adapter_id": adapter_id,
            "binding_contract_id": binding_id,
            "composition_contract_path": authority_rel,
            "composition_contract_sha256": authority_sha,
        }
        binding_path = root / binding_rel
        binding_text = json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        binding_path.write_text(binding_text, encoding="utf-8")
        binding_sha = hashlib.sha256(binding_text.encode("utf-8")).hexdigest()
        return ({
            "apply_kind": apply_kind,
            "parameter_kind": parameter_kind,
            "target_class": f"target-{suffix}",
            "authority_form": "MECHANISM_AUTHORITY_V1",
            "architecture_id": architecture_id,
            "architecture_path": authority_rel,
            "architecture_sha256": authority_sha,
        }, {
            "apply_kind": apply_kind,
            "composition_contract_id": composition_id,
            "adapter_id": adapter_id,
            "binding_path": binding_rel,
            "binding_sha256": binding_sha,
            "implementation_path": implementation_rel,
            "implementation_sha256": implementation_sha,
        }, binding_path, binding_text)

    @staticmethod
    def _write_registry(path: Path, fields, rows):
        lines = ["\t".join(fields)]
        for row in rows:
            lines.append("\t".join(row[field] for field in fields))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _synthetic_root(self, parameter_kinds=("kind-a", "kind-b")):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        kind_rows = []
        impl_rows = []
        bindings = []
        for suffix, parameter_kind in zip(("a", "b"), parameter_kinds):
            krow, irow, bpath, btext = self._write_synthetic_pair(root, suffix, parameter_kind)
            kind_rows.append(krow)
            impl_rows.append(irow)
            bindings.append((bpath, btext))
        self._write_registry(
            root / "product/APPLY-KIND-REGISTRY.tsv",
            GEN_V2_CURRENT.APPLY_KIND_REGISTRY_FIELDS,
            kind_rows,
        )
        self._write_registry(
            root / "product/APPLY-IMPLEMENTATION-REGISTRY.tsv",
            GEN_V2_CURRENT.APPLY_REGISTRY_FIELDS,
            impl_rows,
        )
        return tmp, root, kind_rows, impl_rows, bindings

    def _run_rebuilder(self, root: Path, mode: str):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/rebuild-apply-contract-bindings.py"),
             "--project-root", str(root), mode],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def test_rebuilder_counts_two_pairs_and_check_never_repairs(self):
        tmp, root, _kind_rows, _impl_rows, bindings = self._synthetic_root()
        self.addCleanup(tmp.cleanup)
        cp = self._run_rebuilder(root, "--check")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("APPLY_BINDING_ARCHITECTURES=2\n", cp.stdout)
        stale_path, expected = bindings[0]
        stale_path.write_text("{}\n", encoding="utf-8")
        before = stale_path.read_bytes()
        cp = self._run_rebuilder(root, "--check")
        self.assertNotEqual(cp.returncode, 0)
        self.assertEqual(stale_path.read_bytes(), before)
        cp = self._run_rebuilder(root, "--write")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(stale_path.read_text(encoding="utf-8"), expected)
        self.assertIn("APPLY_BINDING_ARCHITECTURES=2\n", cp.stdout)

    def test_rebuilder_unknown_form_unpaired_and_ambiguous_route_fail_closed(self):
        tmp, root, kind_rows, impl_rows, _ = self._synthetic_root()
        self.addCleanup(tmp.cleanup)
        kind_rows[0]["authority_form"] = "UNKNOWN_FORM"
        self._write_registry(root / "product/APPLY-KIND-REGISTRY.tsv", GEN_V2_CURRENT.APPLY_KIND_REGISTRY_FIELDS, kind_rows)
        self.assertNotEqual(self._run_rebuilder(root, "--check").returncode, 0)

        tmp2, root2, kind_rows2, impl_rows2, _ = self._synthetic_root()
        self.addCleanup(tmp2.cleanup)
        self._write_registry(root2 / "product/APPLY-IMPLEMENTATION-REGISTRY.tsv", GEN_V2_CURRENT.APPLY_REGISTRY_FIELDS, impl_rows2[:1])
        self.assertNotEqual(self._run_rebuilder(root2, "--check").returncode, 0)

        tmp3, root3, kind_rows3, impl_rows3, _ = self._synthetic_root(("same-kind", "same-kind"))
        self.addCleanup(tmp3.cleanup)
        self.assertNotEqual(self._run_rebuilder(root3, "--check").returncode, 0)


class UnprovenAbsenceIsErrorFixtures(unittest.TestCase):
    """Недоступность предка не равна отсутствию (решение человека).

    NOT_FOUND допустим только при доказанном отсутствии: родитель существует,
    является каталогом, доступен для поиска, а lstat имени даёт ENOENT — так уже
    сделано в `product-file-mode-owner-check-v2`. Во всех прочих случаях контроль
    обязан вернуть ERROR с причиной из своего контракта, иначе недоступный
    объект молча выпадает из популяции и контроль может дать PASS.
    """

    def setUp(self):
        if BASH is None:
            self.skipTest("bash not found")
        self.tmp = Path(tempfile.mkdtemp(prefix="slp-unproven-absence-"))
        os.chmod(self.tmp, 0o755)
        self.closed = self.tmp / "closed"
        self.closed.mkdir()
        self.visible = self.tmp / "visible"
        self.visible.mkdir()
        os.chmod(self.visible, 0o755)

    def tearDown(self):
        with contextlib.suppress(OSError):
            os.chmod(self.closed, 0o700)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- фикстура -------------------------------------------------------
    def owned(self, path):
        """Под root фикстура передаётся непривилегированному пользователю прогона."""
        if os.geteuid() == 0:
            os.chown(path, 65534, 65534)
        return path

    def user_kwargs(self):
        if os.geteuid() == 0:
            return {"user": 65534, "group": 65534, "extra_groups": []}
        return {}

    def seal(self, inner):
        """Закрывает каталог и доказывает, что объект внутри действительно недоступен."""
        os.chmod(self.closed, 0o000)
        probe = (
            'if [[ -x %s ]]; then printf searchable; fi\n'
            'if [[ -e %s || -L %s ]]; then printf visible; fi\n'
            'if cat -- %s >/dev/null 2>&1; then printf readable; fi\n'
            'printf done\n'
        ) % (shlex.quote(str(self.closed)), shlex.quote(str(inner)),
             shlex.quote(str(inner)), shlex.quote(str(inner)))
        cp = subprocess.run([BASH, "-c", probe], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, **self.user_kwargs())
        self.assertEqual(cp.stdout, "done", "предок доступен, случай не воспроизведён: " + cp.stdout)

    def run_block(self, block, fn_name):
        cp = subprocess.run(
            [BASH, "-c", "set -u\n" + block + "\n" + fn_name + "\n"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **self.user_kwargs()
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        row = cp.stdout.strip().split("\t")
        self.assertEqual(len(row), 5, cp.stdout)
        return tuple(row[2:])

    # --- home-directories-mode ------------------------------------------
    def test_home_directories_unreachable_home_base_is_error(self):
        # B-02 (repair-step): stat(/home) сам получает EACCES (родитель
        # запечатан) — это не доказанный ENOENT, поэтому адаптер больше не
        # идёт в обход предков (это стало бы тем же небезопасным приёмом,
        # который чинит B-02) и отдаёт общий, но честный ERROR немедленно.
        home = self.closed / "home"
        home.mkdir()
        os.chmod(home, 0o700)
        self.owned(home)
        self.seal(home)
        block = HOME_DIRECTORIES._shell_function_for_fixture("TEST.ABSENCE", str(home))
        status, value, compliance = self.run_block(block, "slp_check_TEST_ABSENCE")
        self.assertEqual((status, compliance), ("ERROR", "ERROR"))
        self.assertEqual(value, "home-base:stat-failed:%s" % home)

    def test_home_directories_absent_home_base_in_searchable_parent_stays_outside_population(self):
        block = HOME_DIRECTORIES._shell_function_for_fixture(
            "TEST.ABSENCE", str(self.visible / "absent-home")
        )
        self.assertEqual(self.run_block(block, "slp_check_TEST_ABSENCE"),
                         ("VALUE", "checked=0;violations=0", "PASS"))

    # --- home-sensitive-files-mode --------------------------------------
    def test_home_sensitive_unreachable_home_base_is_error(self):
        # /home сам получает EACCES (родитель запечатан) — не доказанный
        # ENOENT, поэтому адаптер не идёт в обход предков и отдаёт честный
        # ERROR немедленно (тот же приём, что и у home-directories-mode).
        home = self.closed / "home"
        home.mkdir()
        os.chmod(home, 0o700)
        self.owned(home)
        self.seal(home)
        block = HOME_SENSITIVE._shell_function_for_fixture("TEST.ABSENCE", str(home))
        self.assertEqual(self.run_block(block, "slp_check_TEST_ABSENCE"),
                         ("ERROR", "home-base:stat-failed:%s" % home, "ERROR"))

    # --- pam-wheel-access -----------------------------------------------
    def pam_fixture(self, pam, group):
        return PAM_WHEEL_ACCESS._shell_function_for_fixture("PAM.ABSENCE", str(pam), str(group))

    def test_pam_wheel_unreachable_pam_file_is_error(self):
        pam = self.closed / "su"
        pam.write_text("auth required pam_wheel.so use_uid\n", encoding="utf-8")
        self.owned(pam)
        group = self.visible / "group"
        group.write_text("wheel:x:10:root\n", encoding="utf-8")
        self.owned(group)
        self.seal(pam)
        self.assertEqual(self.run_block(self.pam_fixture(pam, group), "slp_check_PAM_ABSENCE"),
                         ("ERROR", "pam:read-failed", "ERROR"))

    def test_pam_wheel_unreachable_group_file_is_error(self):
        pam = self.visible / "su"
        pam.write_text("auth required pam_wheel.so use_uid\n", encoding="utf-8")
        self.owned(pam)
        group = self.closed / "group"
        group.write_text("wheel:x:10:root\n", encoding="utf-8")
        self.owned(group)
        self.seal(group)
        self.assertEqual(self.run_block(self.pam_fixture(pam, group), "slp_check_PAM_ABSENCE"),
                         ("ERROR", "group:read-failed", "ERROR"))

    def test_pam_wheel_absent_file_in_searchable_parent_stays_not_found(self):
        group = self.visible / "group"
        group.write_text("wheel:x:10:root\n", encoding="utf-8")
        self.owned(group)
        block = self.pam_fixture(self.visible / "absent-su", group)
        self.assertEqual(self.run_block(block, "slp_check_PAM_ABSENCE"), ("NOT_FOUND", "-", "FAIL"))

    # --- sshd-root-login -------------------------------------------------
    def sshd_binary(self, directory):
        sshd = directory / "sshd"
        sshd.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ ${1:-} == -t ]]; then exit 0; fi\n"
            "if [[ ${1:-} == -T ]]; then printf '%s\\n' 'permitrootlogin no'; exit 0; fi\n"
            "exit 2\n",
            encoding="utf-8",
        )
        sshd.chmod(0o755)
        self.owned(sshd)
        return sshd

    def test_sshd_unreachable_config_is_error(self):
        cfg = self.closed / "sshd_config"
        cfg.write_text("PermitRootLogin no\n", encoding="utf-8")
        self.owned(cfg)
        sshd = self.sshd_binary(self.visible)
        self.seal(cfg)
        block = SSHD_ROOT_LOGIN._shell_function_for_fixture(
            "SSH.ABSENCE", str(cfg), str(sshd), "PermitRootLogin", "eq", "no"
        )
        self.assertEqual(self.run_block(block, "slp_check_SSH_ABSENCE"),
                         ("ERROR", "sshd-config:unreadable", "ERROR"))

    def test_sshd_unreachable_binary_is_error(self):
        cfg = self.visible / "sshd_config"
        cfg.write_text("PermitRootLogin no\n", encoding="utf-8")
        self.owned(cfg)
        sshd = self.sshd_binary(self.closed)
        self.seal(sshd)
        block = SSHD_ROOT_LOGIN._shell_function_for_fixture(
            "SSH.ABSENCE", str(cfg), str(sshd), "PermitRootLogin", "eq", "no"
        )
        self.assertEqual(self.run_block(block, "slp_check_SSH_ABSENCE"),
                         ("ERROR", "sshd-binary:resolve-failed", "ERROR"))

    def test_sshd_absent_config_in_searchable_parent_stays_not_found(self):
        block = SSHD_ROOT_LOGIN._shell_function_for_fixture(
            "SSH.ABSENCE", str(self.visible / "absent-config"),
            str(self.sshd_binary(self.visible)), "PermitRootLogin", "eq", "no"
        )
        self.assertEqual(self.run_block(block, "slp_check_SSH_ABSENCE"), ("NOT_FOUND", "-", "FAIL"))

    # --- kernel-cmdline ---------------------------------------------------
    def cmdline_block(self, target):
        spec = importlib.util.spec_from_file_location(
            "slp_kernel_cmdline_absence", ROOT / "product/adapters/product-kernel-cmdline-check-v2.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        block = mod.shell_function("CMD.ABSENCE", "/proc/cmdline", "init_on_alloc", "eq", "1")
        return block.replace(repr("/proc/cmdline"), repr(str(target)), 1)

    def test_kernel_cmdline_unreachable_source_is_error(self):
        target = self.closed / "cmdline"
        target.write_text("init_on_alloc=1\n", encoding="utf-8")
        self.owned(target)
        self.seal(target)
        self.assertEqual(self.run_block(self.cmdline_block(target), "slp_check_CMD_ABSENCE"),
                         ("ERROR", "cmdline:read-failed", "ERROR"))

    def test_kernel_cmdline_absent_source_in_searchable_parent_stays_not_found(self):
        block = self.cmdline_block(self.visible / "absent-cmdline")
        self.assertEqual(self.run_block(block, "slp_check_CMD_ABSENCE"), ("NOT_FOUND", "-", "NOT_FOUND"))


@unittest.skipIf(BASH is None, "bash not available")
class KernelCmdlineSingleReadFixtures(unittest.TestCase):
    """Разбор /proc/cmdline идёт по тем же байтам, что прошли проверку через
    `od` (аудит Codex, диапазон 6780086..3215d1c, B-04): раньше файл после
    `od` открывался заново `read -r _slp_raw < file`. Сбой внедряется
    подменой `/usr/bin/od` обёрткой."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="slp-cmdline-single-read-"))
        self.target = self.tmp / "cmdline"
        self.target.write_text("init_on_alloc=1 quiet\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_check(self, shim_text=None):
        spec = importlib.util.spec_from_file_location(
            "slp_kernel_cmdline_single_read", ROOT / "product/adapters/product-kernel-cmdline-check-v2.py"
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        block = mod.shell_function("CMD.SINGLE", "/proc/cmdline", "init_on_alloc", "eq", "1")
        block = block.replace(repr("/proc/cmdline"), repr(str(self.target)), 1)
        if shim_text is not None:
            block = install_od_shim(block, self.tmp, shim_text)
        cp = subprocess.run(
            [BASH, "-c", "set -u\n" + block + "\nslp_check_CMD_SINGLE\n"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        row = cp.stdout.strip().split("\t")
        self.assertEqual(len(row), 5, cp.stdout)
        return tuple(row[2:])

    def test_baseline_passes(self):
        self.assertEqual(self.run_check(), ("VALUE", "1", "PASS"))

    def test_vanishing_after_validation_parses_checked_bytes(self):
        self.assertEqual(self.run_check(shim_text=_od_vanish_shim_text(self.target)), ("VALUE", "1", "PASS"))
        self.assertFalse(self.target.exists(), "сбой не внедрён")

    def test_content_substitution_after_validation_parses_checked_bytes_not_new_content(self):
        # od проверяет "init_on_alloc=1 quiet\n"; сразу после этого файл
        # подменяется на другое значение — вердикт обязан остаться по
        # проверенным байтам, а не по новым.
        shim = _od_swap_shim_text(self.target, "init_on_alloc=0 quiet\n")
        self.assertEqual(self.run_check(shim_text=shim), ("VALUE", "1", "PASS"))
        self.assertEqual(self.target.read_text(encoding="utf-8"), "init_on_alloc=0 quiet\n", "сбой не внедрён")

    def test_od_failure_after_partial_prefix_is_error(self):
        self.assertEqual(
            self.run_check(shim_text=_od_fail_after_prefix_shim_text()),
            ("ERROR", "cmdline:read-failed", "ERROR"),
        )


class PamWheelSingleReadFixtures(unittest.TestCase):
    """Разбор pam-wheel-access идёт по тем же байтам, что прошли проверку.

    Раньше файл проверялся через `od`, а затем открывался заново в
    `while read ... < file`: если файл исчезал между двумя обращениями,
    перенаправление не удавалось, цикл не выполнялся, а контроль выдавал
    VALUE/FAIL вместо ERROR. Сбой внедряется подменой `/usr/bin/od` обёрткой,
    которая после чтения удаляет проверяемый файл.
    """

    PASS_ROW = ("VALUE", "pam_wheel=present;wheel=gid 10;root=member", "PASS")

    def setUp(self):
        if BASH is None:
            self.skipTest("bash not found")
        self.tmp = Path(tempfile.mkdtemp(prefix="slp-pam-single-read-"))
        self.pam = self.tmp / "su"
        self.pam.write_text("auth required pam_wheel.so use_uid\n", encoding="utf-8")
        self.group = self.tmp / "group"
        self.group.write_text("wheel:x:10:root,alice\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_check(self, vanish=None):
        block = PAM_WHEEL_ACCESS._shell_function_for_fixture("PAM.SINGLE", str(self.pam), str(self.group))
        if vanish is not None:
            shim = self.tmp / "od-shim"
            shim.write_text(
                "#!/bin/bash\n"
                '/usr/bin/od "$@"; rc=$?\n'
                'if [[ ${@: -1} == %s ]]; then rm -f -- %s; fi\n'
                "exit $rc\n" % (shlex.quote(str(vanish)), shlex.quote(str(vanish))),
                encoding="utf-8",
            )
            self.assertIn("/usr/bin/od", block)
            # временный каталог может быть смонтирован noexec: обёртка запускается через bash
            block = block.replace("/usr/bin/od", "%s %s" % (shlex.quote(BASH), shlex.quote(str(shim))))
        cp = subprocess.run(
            [BASH, "-c", "set -u\n" + block + "\nslp_check_PAM_SINGLE\n"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        row = cp.stdout.strip().split("\t")
        self.assertEqual(len(row), 5, cp.stdout)
        return tuple(row[2:])

    def test_baseline_passes(self):
        self.assertEqual(self.run_check(), self.PASS_ROW)

    def test_pam_file_vanishing_after_validation_parses_checked_bytes(self):
        self.assertEqual(self.run_check(vanish=self.pam), self.PASS_ROW)
        self.assertFalse(self.pam.exists(), "сбой не внедрён")

    def test_group_file_vanishing_after_validation_parses_checked_bytes(self):
        self.assertEqual(self.run_check(vanish=self.group), self.PASS_ROW)
        self.assertFalse(self.group.exists(), "сбой не внедрён")

    def test_unterminated_and_continuation_edge_cases_keep_semantics(self):
        # последняя строка без \n; продолжение строки в конце файла остаётся ошибкой стека
        self.pam.write_text("auth required pam_wheel.so use_uid", encoding="utf-8")
        self.group.write_text("wheel:x:10:root,alice", encoding="utf-8")
        self.assertEqual(self.run_check(), self.PASS_ROW)
        self.pam.write_text("auth required pam_wheel.so use_uid \\\n", encoding="utf-8")
        self.assertEqual(self.run_check(), ("ERROR", "pam:ambiguous-stack", "ERROR"))
        # пустая строка завершает продолжение: логическая строка валидна
        self.pam.write_text("auth required pam_wheel.so use_uid\\\n\n", encoding="utf-8")
        self.assertEqual(self.run_check(), self.PASS_ROW)


class LocalAccountSingleReadFixtures(unittest.TestCase):
    """shadow и passwd для local-account-password-state читаются по одному разу
    каждый: `mapfile` не сигнализирует ошибкой `read()` после уже принятого
    префикса строк (`man bash`), поэтому повторное открытие небезопасно так же,
    как `while read`. Разбор идёт по проверенным через `od` байтам (аудит
    Codex, коммит 6780086)."""

    PASS_ROW = ("VALUE", "accounts=1;empty=0", "PASS")

    def setUp(self):
        if BASH is None:
            self.skipTest("bash not found")
        self.tmp = Path(tempfile.mkdtemp(prefix="slp-local-account-single-read-"))
        self.passwd = self.tmp / "passwd"
        self.passwd.write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
        self.shadow = self.tmp / "shadow"
        self.shadow.write_text("root:$6$abc:1:0:99999:7:::\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_check(self, shim=None):
        block = SHADOW._shell_function_for_paths(
            "LA.SINGLE", str(self.passwd), str(self.shadow),
            "password-field", "all-nonempty", True,
        )
        if shim is not None:
            block = install_od_shim(block, self.tmp, shim)
        cp = subprocess.run(
            [BASH, "-c", "set -u\n" + block + "\nslp_check_LA_SINGLE\n"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        row = cp.stdout.strip().split("\t")
        self.assertEqual(len(row), 5, cp.stdout)
        return tuple(row[2:])

    def test_baseline_passes(self):
        self.assertEqual(self.run_check(), self.PASS_ROW)

    def test_shadow_vanishing_after_validation_parses_checked_bytes(self):
        self.assertEqual(self.run_check(shim=_od_vanish_shim_text(self.shadow)), self.PASS_ROW)
        self.assertFalse(self.shadow.exists(), "сбой не внедрён")

    def test_passwd_vanishing_after_validation_parses_checked_bytes(self):
        self.assertEqual(self.run_check(shim=_od_vanish_shim_text(self.passwd)), self.PASS_ROW)
        self.assertFalse(self.passwd.exists(), "сбой не внедрён")

    def test_od_failure_after_partial_prefix_is_error(self):
        self.assertEqual(
            self.run_check(shim=_od_fail_after_prefix_shim_text()),
            ("ERROR", "passwd:read-failed", "ERROR"),
        )

    def test_second_od_call_failure_after_partial_prefix_is_error(self):
        # Пробел теста (репарация, аудит Codex 6780086..3215d1c): сбой,
        # ограниченный ВТОРЫМ файлом (shadow) — passwd должен пройти проверку
        # штатно, а не только оба файла разом.
        self.assertEqual(
            self.run_check(shim=_od_fail_after_prefix_for_target_shim_text(self.shadow)),
            ("ERROR", "shadow:read-failed", "ERROR"),
        )


class SshdRootLoginSingleReadFixtures(unittest.TestCase):
    """sshd_config читается один раз: рекурсивный разбор include-файлов
    использует ту же процедуру. Раньше `done < "$_slp_pf" || {...}` не ловил
    ошибку чтения после уже принятого префикса строк — компаунд `while`
    отдаёт код последней команды тела, а не терминирующего `read` (аудит
    Codex, коммит 6780086)."""

    PASS_ROW = ("VALUE", "main_global_no=1;effective=no", "PASS")

    def setUp(self):
        if BASH is None:
            self.skipTest("bash not found")
        # dir=ROOT: временный /tmp может быть смонтирован noexec, а sshd-заглушка
        # исполняется адаптером напрямую (`command "$_slp_sshd" ...`).
        self.tmp = Path(tempfile.mkdtemp(prefix="slp-sshd-single-read-", dir=str(ROOT)))
        self.cfg = self.tmp / "sshd_config"
        self.cfg.write_text("PermitRootLogin no\n", encoding="utf-8")
        self.sshd = self.tmp / "sshd"
        self.sshd.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ ${1:-} == -t ]]; then exit 0; fi\n"
            "if [[ ${1:-} == -T ]]; then printf '%s\\n' 'permitrootlogin no'; exit 0; fi\n"
            "exit 2\n",
            encoding="utf-8",
        )
        self.sshd.chmod(0o755)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_check(self, shim=None):
        block = SSHD_ROOT_LOGIN._shell_function_for_fixture(
            "SSH.SINGLE", str(self.cfg), str(self.sshd), "PermitRootLogin", "eq", "no"
        )
        if shim is not None:
            block = install_od_shim(block, self.tmp, shim)
        cp = subprocess.run(
            [BASH, "-c", "set -u\n" + block + "\nslp_check_SSH_SINGLE\n"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        row = cp.stdout.strip().split("\t")
        self.assertEqual(len(row), 5, cp.stdout)
        return tuple(row[2:])

    def test_baseline_passes(self):
        self.assertEqual(self.run_check(), self.PASS_ROW)

    def test_config_vanishing_after_validation_parses_checked_bytes(self):
        self.assertEqual(self.run_check(shim=_od_vanish_shim_text(self.cfg)), self.PASS_ROW)
        self.assertFalse(self.cfg.exists(), "сбой не внедрён")

    def test_od_failure_after_partial_prefix_is_error(self):
        self.assertEqual(
            self.run_check(shim=_od_fail_after_prefix_shim_text()),
            ("ERROR", "sshd-config:read-failed", "ERROR"),
        )


class SuidSgidSingleReadFixtures(unittest.TestCase):
    """allowlist и mountinfo для suid-sgid-applications читаются по одному разу
    каждый: два отдельных while-цикла раньше заново открывали уже проверенные
    через `od` файлы (аудит Codex, коммит 6780086)."""

    PASS_ROW = ("VALUE", "mounts=1;checked=1;extras=0", "PASS")

    def setUp(self):
        if BASH is None:
            self.skipTest("bash not found")
        self.tmp = Path(tempfile.mkdtemp(prefix="slp-suid-sgid-single-read-"))
        self.app = self.tmp / "app"
        self.app.write_text("x\n", encoding="utf-8")
        os.chmod(self.app, 0o4755)
        self.mountinfo = self.tmp / "mountinfo"
        self.mountinfo.write_text(
            f"1 0 0:1 / {self.tmp} rw,relatime - ext4 /dev/test rw\n", encoding="utf-8"
        )
        self.allow = self.tmp / "allowlist"
        self.allow.write_text(str(self.app) + "\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_check(self, shim=None):
        block = SUID_SGID._shell_function_for_fixture(
            "SUID.SINGLE", "approved-set", "subset-of-file", str(self.allow), str(self.mountinfo)
        )
        if shim is not None:
            block = install_od_shim(block, self.tmp, shim)
        cp = subprocess.run(
            [BASH, "-c", "set -u\n" + block + "\nslp_check_SUID_SINGLE\n"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(cp.stderr, "")
        row = cp.stdout.strip().split("\t")
        self.assertEqual(len(row), 5, cp.stdout)
        return tuple(row[2:])

    def test_baseline_passes(self):
        self.assertEqual(self.run_check(), self.PASS_ROW)

    def test_allowlist_vanishing_after_validation_parses_checked_bytes(self):
        self.assertEqual(self.run_check(shim=_od_vanish_shim_text(self.allow)), self.PASS_ROW)
        self.assertFalse(self.allow.exists(), "сбой не внедрён")

    def test_mountinfo_vanishing_after_validation_parses_checked_bytes(self):
        self.assertEqual(self.run_check(shim=_od_vanish_shim_text(self.mountinfo)), self.PASS_ROW)
        self.assertFalse(self.mountinfo.exists(), "сбой не внедрён")

    def test_od_failure_after_partial_prefix_is_error(self):
        self.assertEqual(
            self.run_check(shim=_od_fail_after_prefix_shim_text()),
            ("ERROR", "mountinfo:read-failed", "ERROR"),
        )

    def test_second_od_call_failure_after_partial_prefix_is_error(self):
        # Пробел теста (репарация, аудит Codex 6780086..3215d1c): сбой,
        # ограниченный ВТОРЫМ файлом (allowlist) — mountinfo должен пройти
        # проверку штатно, а не только оба файла разом.
        self.assertEqual(
            self.run_check(shim=_od_fail_after_prefix_for_target_shim_text(self.allow)),
            ("ERROR", "allowlist:read-failed", "ERROR"),
        )


@unittest.skipIf(BASH is None, "bash not available")
class SlpCollectPolicyReasonFormat(unittest.TestCase):
    """B-01 (repair-step по аудиту Codex диапазона 6780086..3215d1c):
    `slp_collect_policy` отвергал ERROR-reason вида `<domain>:<reason>:<payload>`
    (путь и цель readlink для 2.3.11) как `CHECK_INTERNAL_ERROR`, хотя такой
    reason реально печатают CHECK-функции. Проверяется на реальном
    `slp_collect_policy` из трекнутого артефакта (единственная подмена — список
    из одной синтетической CHECK-функции вместо всех реальных), сквозь три
    формата рендера.
    """

    ARTIFACT = ROOT / "securelinux-policy.sh"
    FNS_RE = re.compile(r"  local -a _slp_fns=\([^\n]*\)\n")
    IDS_RE = re.compile(r"  local -a _slp_ids=\([^\n]*\)\n")
    SYSTEM_PRELUDE = (
        "SLP_SYSTEM_PRETTY_NAME='Test' SLP_SYSTEM_ID='test' SLP_SYSTEM_VERSION_ID='1'\n"
        "SLP_SYSTEM_ARCH='x86_64' SLP_SYSTEM_PROFILE='' SLP_SYSTEM_TYPE='' SLP_SYSTEM_PLATFORM='test'\n"
        "SLP_SYSTEM_ENVIRONMENT='test'\n"
    )

    TAIL_GUARD = 'if [[ ${BASH_SOURCE[0]} == "$0" ]]; then\n'

    def isolated_source(self, reason):
        text = self.ARTIFACT.read_text(encoding="utf-8")
        # Хвостовой guard `slp_main "$@"` рассчитан на `source`/прямой запуск
        # файла; при подаче текста через stdin BASH_SOURCE не тот же — guard
        # не нужен для этого теста (вызываем функции напрямую), отрезаем его.
        text = text.split(self.TAIL_GUARD, 1)[0]
        self.assertEqual(len(self.FNS_RE.findall(text)), 1)
        self.assertEqual(len(self.IDS_RE.findall(text)), 1)
        text = self.FNS_RE.sub("  local -a _slp_fns=('slp_check_TEST_B01')\n", text, count=1)
        text = self.IDS_RE.sub("  local -a _slp_ids=('TEST-B01')\n", text, count=1)
        stub = (
            "slp_check_TEST_B01() {\n"
            "  printf 'SLP-CHECK-V1\\tTEST-B01\\tERROR\\t%s\\tERROR\\n' " + shlex.quote(reason) + "\n"
            "}\n"
            "slp_presentation_for_control() {\n"
            "  printf '%s\\t%s\\t%s\\t%s\\n' 'fstec-linux-2022 §9.9.9' 'test-control' 'n/a' ''\n"
            "}\n"
        )
        return text + "\n" + stub + self.SYSTEM_PRELUDE

    def run_variant(self, reason, driver):
        source = self.isolated_source(reason)
        cp = subprocess.run(
            [BASH, "-s"], input="set -u\n" + source + "\n" + driver,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return cp

    def test_path_target_and_space_reason_accepted_via_collect_policy(self):
        reason = "home:symlink:/home/my link->/home/my target"
        cp = self.run_variant(
            reason,
            "slp_collect_policy; printf 'RC=%s\\n' \"$?\"; printf '%s\\n' \"${SLP_RESULTS[@]}\"",
        )
        self.assertEqual(cp.stderr, "", cp.stderr)
        lines = cp.stdout.splitlines()
        self.assertEqual(lines[0], "RC=0", cp.stdout)
        self.assertEqual(
            lines[1],
            "SLP-CHECK-V1\tTEST-B01\tERROR\t" + reason + "\tERROR",
        )

    def test_raw_and_json_carry_the_same_reason_with_path_and_space(self):
        reason = "home:symlink:/home/my link->/home/my target"
        cp = self.run_variant(
            reason,
            "slp_collect_policy >/dev/null\n"
            "echo '===RAW==='\n"
            "slp_render_raw 0\n"
            "echo '===JSON==='\n"
            "slp_render_json 0\n",
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stderr, "", cp.stderr)
        raw_part, json_part = cp.stdout.split("===JSON===\n", 1)
        raw_part = raw_part.split("===RAW===\n", 1)[1]
        self.assertIn("SLP-CHECK-V1\tTEST-B01\tERROR\t" + reason + "\tERROR\n", raw_part)
        payload = json.loads(json_part)
        rows = [r for r in payload["results"] if r["control_id"] == "TEST-B01"]
        self.assertEqual(len(rows), 1, json_part)
        self.assertEqual(rows[0]["value"], reason)
        self.assertEqual(rows[0]["result"], "ERROR")

    def test_pretty_does_not_lose_bytes_of_wrapped_reason(self):
        # Прежний тест сверял два отдельных фрагмента ("not-determined;" и
        # "reason: home:not"), которые оба умещаются в первую строку
        # переноса и поэтому не доказывают отсутствие потери байт на
        # границе переноса. Здесь reason заведомо длиннее одной колонки:
        # полная реконструкция по всем перенесённым строкам должна побайтово
        # совпасть с исходным значением. Ширины столбцов читаются из самого
        # прогона (SLP_PRETTY_W*), а не дублируются литералом в тесте.
        reason = "home:not-directory:/home/" + "x" * 80
        cp = self.run_variant(
            reason,
            "slp_collect_policy >/dev/null\n"
            "slp_render_pretty 0 TEST\n"
            "printf 'WIDTHS=%s,%s,%s,%s,%s\\n' \"$SLP_PRETTY_WS\" \"$SLP_PRETTY_WSRC\" \"$SLP_PRETTY_WC\" \"$SLP_PRETTY_WCUR\" \"$SLP_PRETTY_WREQ\"\n",
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stderr, "", cp.stderr)
        self.assertNotIn("CHECK_INTERNAL_ERROR", cp.stdout)
        body, widths_line = cp.stdout.rsplit("WIDTHS=", 1)
        ws, wsrc, wc, wcur, wreq = (int(n) for n in widths_line.strip().split(","))
        row_re = re.compile(
            r"^ (.{%d}) \| (.{%d}) \| (.{%d}) \| (.{%d}) \| (.{%d}) \|$"
            % (ws, wsrc, wc, wcur, wreq)
        )
        lines = body.splitlines()
        sep_indices = [
            i for i, line in enumerate(lines)
            if line and set(line) <= {"-", "+"} and line.endswith("+")
        ]
        self.assertGreaterEqual(len(sep_indices), 2, body)
        data_lines = lines[sep_indices[0] + 1 : sep_indices[1]]
        matches = [row_re.match(line) for line in data_lines]
        self.assertTrue(matches and all(matches), body)
        reconstructed = "".join(m.group(4) for m in matches).rstrip(" ")
        self.assertEqual(reconstructed, "not-determined; reason: " + reason)

    def test_reason_with_control_byte_in_payload_is_still_rejected(self):
        # Defense-in-depth на уровне коллектора: reason с control-байтом,
        # если он всё же дойдёт сюда, должен отвергаться. Что реальный
        # адаптер 2.3.11 такой байт до коллектора не доводит и сам
        # превращает его в `home:invalid-name` — доказывают параметризованные
        # тесты `HomeDirectoriesModeAdapterFixtures.test_control_byte_in_*`
        # (B-01, репарация по аудиту Codex диапазона 3215d1c..cc90fd6).
        reason = "home:symlink:/home/bad\x01name"
        cp = self.run_variant(
            reason,
            "slp_collect_policy; printf 'RC=%s\\n' \"$?\"",
        )
        self.assertIn("RC=1", cp.stdout)
        self.assertIn("CHECK_INTERNAL_ERROR", cp.stderr)

    def test_plain_two_segment_reason_still_accepted(self):
        cp = self.run_variant(
            "home-base:symlink",
            "slp_collect_policy; printf 'RC=%s\\n' \"$?\"",
        )
        self.assertEqual(cp.stdout.strip(), "RC=0", cp.stderr)


@unittest.skipIf(BASH is None, "bash not available")
class PamWheelAbsentReasonRenderFormat(unittest.TestCase):
    """Н-3 (репарация, аудит Codex): VALUE/FAIL payload
    `pam_wheel=absent;wheel=<..>;root=<..>` (2.2.1, разобранный стек без
    активной pam_wheel.so) проходит raw/JSON/pretty без искажений. В отличие
    от ERROR-reason, `slp_collect_policy` не применяет к VALUE-строкам regex
    control-байт (`generate-product-check-v2.py` строит строгую проверку
    только для `_slp_comp == ERROR`) — здесь доказывается, что сам payload
    доходит до всех трёх форматов рендера целиком, без потери байт.
    """

    ARTIFACT = SlpCollectPolicyReasonFormat.ARTIFACT
    FNS_RE = SlpCollectPolicyReasonFormat.FNS_RE
    IDS_RE = SlpCollectPolicyReasonFormat.IDS_RE
    SYSTEM_PRELUDE = SlpCollectPolicyReasonFormat.SYSTEM_PRELUDE
    TAIL_GUARD = SlpCollectPolicyReasonFormat.TAIL_GUARD

    REASON = "pam_wheel=absent;wheel=absent;root=missing"

    def isolated_source(self):
        text = self.ARTIFACT.read_text(encoding="utf-8")
        text = text.split(self.TAIL_GUARD, 1)[0]
        self.assertEqual(len(self.FNS_RE.findall(text)), 1)
        self.assertEqual(len(self.IDS_RE.findall(text)), 1)
        text = self.FNS_RE.sub("  local -a _slp_fns=('slp_check_TEST_H3')\n", text, count=1)
        text = self.IDS_RE.sub("  local -a _slp_ids=('TEST-H3')\n", text, count=1)
        stub = (
            "slp_check_TEST_H3() {\n"
            "  printf 'SLP-CHECK-V1\\tTEST-H3\\tVALUE\\t%s\\tFAIL\\n' " + shlex.quote(self.REASON) + "\n"
            "}\n"
            "slp_presentation_for_control() {\n"
            "  printf '%s\\t%s\\t%s\\t%s\\n' 'fstec-linux-2022 §2.2.1' 'su-wheel-access' 'authority allowlist' ''\n"
            "}\n"
        )
        return text + "\n" + stub + self.SYSTEM_PRELUDE

    def run_driver(self, driver):
        source = self.isolated_source()
        return subprocess.run(
            [BASH, "-s"], input="set -u\n" + source + "\n" + driver,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def test_raw_and_json_carry_the_payload_intact(self):
        cp = self.run_driver(
            "slp_collect_policy >/dev/null\n"
            "echo '===RAW==='\n"
            "slp_render_raw 0\n"
            "echo '===JSON==='\n"
            "slp_render_json 0\n",
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stderr, "", cp.stderr)
        raw_part, json_part = cp.stdout.split("===JSON===\n", 1)
        raw_part = raw_part.split("===RAW===\n", 1)[1]
        self.assertIn("SLP-CHECK-V1\tTEST-H3\tVALUE\t" + self.REASON + "\tFAIL\n", raw_part)
        payload = json.loads(json_part)
        rows = [r for r in payload["results"] if r["control_id"] == "TEST-H3"]
        self.assertEqual(len(rows), 1, json_part)
        self.assertEqual(rows[0]["value"], self.REASON)
        self.assertEqual(rows[0]["result"], "FAIL")

    def test_pretty_does_not_lose_bytes_of_payload(self):
        cp = self.run_driver(
            "slp_collect_policy >/dev/null\n"
            "slp_render_pretty 0 TEST\n"
            "printf 'WIDTHS=%s,%s,%s,%s,%s\\n' \"$SLP_PRETTY_WS\" \"$SLP_PRETTY_WSRC\" \"$SLP_PRETTY_WC\" \"$SLP_PRETTY_WCUR\" \"$SLP_PRETTY_WREQ\"\n",
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stderr, "", cp.stderr)
        self.assertNotIn("CHECK_INTERNAL_ERROR", cp.stdout)
        body, widths_line = cp.stdout.rsplit("WIDTHS=", 1)
        ws, wsrc, wc, wcur, wreq = (int(n) for n in widths_line.strip().split(","))
        row_re = re.compile(
            r"^ (.{%d}) \| (.{%d}) \| (.{%d}) \| (.{%d}) \| (.{%d}) \|$"
            % (ws, wsrc, wc, wcur, wreq)
        )
        lines = body.splitlines()
        sep_indices = [
            i for i, line in enumerate(lines)
            if line and set(line) <= {"-", "+"} and line.endswith("+")
        ]
        self.assertGreaterEqual(len(sep_indices), 2, body)
        data_lines = lines[sep_indices[0] + 1 : sep_indices[1]]
        matches = [row_re.match(line) for line in data_lines]
        self.assertTrue(matches and all(matches), body)
        reconstructed = "".join(m.group(4) for m in matches).rstrip(" ")
        self.assertEqual(reconstructed, self.REASON)


if __name__ == "__main__":
    unittest.main(verbosity=2)
