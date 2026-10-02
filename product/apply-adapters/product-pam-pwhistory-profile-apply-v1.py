#!/usr/bin/env python3
"""APPLY-адаптер механизма pam-pwhistory-profile-v1 (fstec-configuration-2026 п.1.2; SRC-0056).

Решение пользователя 26.09.2026: pam_pwhistory remember=5. Решение 27.09.2026: модуль
включается собственным профилем pam-auth-update (пакет libpam-modules содержит модуль, но не
профиль); проверка — сначала на двух средах (Ubuntu 22.04 и 24.04 minimized).

* Наблюдение — тот же разбор, что у CHECK `pam-pwhistory-remember-check-semantic-v1` (текст
  PARSER совпадает побайтно, сверяется тестом). Решение пользователя 27.09.2026: принимаются
  только эталонные стеки password (STACKS), подтверждённые журналами семи сред.
* Стек после APPLY п.1.1 (pam_pwquality): профиль /usr/share/pam-configs/securelinux-pwhistory
  (строка `requisite pam_pwhistory.so remember=5 retry=1 use_authtok`, приоритет 1000 — после
  pam_pwquality, до pam_unix) и `pam-auth-update --package --enable securelinux-pwhistory`.
  Стек чистой установки (pam_pwquality не включён) или иной стек — решение администратора;
  действующая строка в pwhistory.conf (в том числе запасной путь поставщика) — тоже.
* Итоговая проверка: стек — эталон со строкой pam_pwhistory, pwhistory.conf без действующих
  строк, прочие /etc/pam.d/common-* не изменились.
  Иначе — компенсация: `pam-auth-update --package --remove` (код 0 обязателен), удаление
  профиля, возврат прежних байтов common-* и /var/lib/pam/*; подтверждено — FAILED_NOT_COMMITTED,
  иначе FAILED_COMPENSATION. retry=1 в строке профиля — явно: retry=0 в pwhistory.conf
  (PAM 1.5.3+) сделал бы смену пароля невозможной.
* Профиль с тем же именем и другими байтами;
  в /usr/share/pam-configs есть ещё не виденный (нет в /var/lib/pam/seen) профиль с Default: yes,
  который pam-auth-update включил бы вместе с нашим; модуля pam_pwhistory.so нет — без изменений
  (решение администратора или отказ).
* Выбор профилей в debconf (libpam-runtime/profiles, `debconf-show`) читается до изменений и
  сверяется после компенсации; расхождение или отказ чтения — FAILED_COMPENSATION.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess

ADAPTER_ID = "product-pam-pwhistory-profile-apply-v1"
MECHANISM_ID = "pam-pwhistory-profile-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "pam-pwhistory-remember"
COMMON_PASSWORD = "/etc/pam.d/common-password"
COMMON_FILES = ("/etc/pam.d/common-account", "/etc/pam.d/common-auth", "/etc/pam.d/common-password",
                "/etc/pam.d/common-session", "/etc/pam.d/common-session-noninteractive")
PROFILE_NAME = "securelinux-pwhistory"
PROFILE_PATH = "/usr/share/pam-configs/" + PROFILE_NAME
PROFILE_BYTES = (
    b"Name: SecureLinux-Policy password history (pam_pwhistory remember=5)\n"
    b"Default: yes\n"
    b"Priority: 1000\n"
    b"Password-Type: Primary\n"
    b"Password:\n"
    b"\trequisite\tpam_pwhistory.so remember=5 retry=1 use_authtok\n"
    b"Password-Initial:\n"
    b"\trequisite\tpam_pwhistory.so remember=5 retry=1\n"
)
# /var/lib/pam — сохранённое состояние pam-auth-update (seen и сгенерированные стеки); выбор
# debconf восстанавливает `pam-auth-update --package --remove`.
STATE_FILES = ("/var/lib/pam/account", "/var/lib/pam/auth", "/var/lib/pam/password", "/var/lib/pam/seen",
               "/var/lib/pam/session", "/var/lib/pam/session-noninteractive")
MODULE_PATHS = ("/usr/lib/x86_64-linux-gnu/security/pam_pwhistory.so",
                "/lib/x86_64-linux-gnu/security/pam_pwhistory.so")
PAM_AUTH_UPDATE = "/usr/sbin/pam-auth-update"
DEBCONF_SHOW = "/usr/bin/debconf-show"
PAM_CONFIGS = "/usr/share/pam-configs"
SEEN = "/var/lib/pam/seen"
TOOL_TIMEOUT = 120
TMP_SUFFIX = ".slp-tmp"

# Совпадает с CHECK-адаптером (проверяется тестом).
SPECS = {"remember": ("ge", 5)}
assert SPECS["remember"] == ("ge", 5)

# Разбор — общий с CHECK (product-pam-pwhistory-remember-check-v1.py, PARSER; сверяется тестом).
PARSER = r'''
C_SPACE = b" \t\n\v\f\r"
REF_PWQ = (b"requisite", b"pam_pwquality.so", (b"retry=3",))
REF_HIST = (b"requisite", b"pam_pwhistory.so", (b"remember=5", b"retry=1", b"use_authtok"))
REF_UNIX_CLEAN = (b"[success=1 default=ignore]", b"pam_unix.so", (b"obscure", b"yescrypt"))
REF_UNIX = (b"[success=1 default=ignore]", b"pam_unix.so", (b"obscure", b"use_authtok", b"try_first_pass", b"yescrypt"))
REF_TAIL = ((b"requisite", b"pam_deny.so", ()), (b"required", b"pam_permit.so", ()))
# Эталонные стеки password /etc/pam.d/common-password — подтверждены журналами семи сред
# (ВМ-прогон 27.09.2026, runner v21): чистая установка; после APPLY п.1.1 (pam_pwquality);
# после APPLY п.1.2 (профиль securelinux-pwhistory). Иной стек — вне поддерживаемого состояния.
STACKS = {
    (REF_UNIX_CLEAN,) + REF_TAIL: "clean",
    (REF_PWQ, REF_UNIX) + REF_TAIL: "pwquality",
    (REF_PWQ, REF_HIST, REF_UNIX) + REF_TAIL: "enabled",
}
REMEMBER = 5
CONF_PATHS = ("/etc/security/pwhistory.conf", "/usr/etc/security/pwhistory.conf")


class ParseError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def password_lines(raw):
    """[(тип, управление, модуль, аргументы)] действующих строк password файла PAM, по порядку."""
    if b"\x00" in raw:
        raise ParseError("pam:invalid-bytes")
    result = []
    for line in raw.split(b"\n"):
        if line.rstrip(C_SPACE).endswith(b"\\"):
            raise ParseError("pam:unsupported-syntax")
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0].startswith(b"@"):
            raise ParseError("pam:include-unsupported")
        if tokens[0].lstrip(b"-").lower() != b"password":
            continue
        if len(tokens) < 3:
            raise ParseError("pam:invalid-line")
        index = 1
        if tokens[1].startswith(b"["):
            while index < len(tokens) and not tokens[index].endswith(b"]"):
                index += 1
            if index + 1 >= len(tokens):
                raise ParseError("pam:invalid-line")
        result.append((tokens[0], b" ".join(tokens[1:index + 1]), tokens[index + 1], tuple(tokens[index + 2:])))
    return result


def stack_state(raw):
    """"clean", "pwquality" или "enabled" — эталонный стек password; иной — ParseError."""
    lines = password_lines(raw)
    if any(line[0] != b"password" for line in lines):
        raise ParseError("pam:unsupported-stack")
    state = STACKS.get(tuple(line[1:] for line in lines))
    if state is None:
        raise ParseError("pam:unsupported-stack")
    return state


def conf_active(raw):
    """True — в pwhistory.conf есть действующая строка (как pam_modutil_search_key: '#' отрезает
    комментарий, ведущие пробельные символы пропускаются, пустая строка не действует)."""
    for line in raw.split(b"\n"):
        cut = line.find(b"#")
        if cut >= 0:
            line = line[:cut]
        if line.lstrip(C_SPACE):
            return True
    return False
'''
exec(PARSER, globals())  # noqa: S102 — один текст разбора с CHECK

ACTION_STACK = ("стек password в /etc/pam.d/common-password не совпадает с эталоном ({reason}): механизм "
                "включает pam_pwhistory только в стеке pam_pwquality → pam_unix → pam_deny → pam_permit; "
                "включите pam_pwhistory remember=5 до pam_unix вручную")
ACTION_PWQ = ("pam_pwquality не включён (контроли п.1.1 не применены): профиль pam_pwhistory рассчитан "
              "на стек с pam_pwquality; примените п.1.1 или включите pam_pwhistory remember=5 вручную")
ACTION_CONF = ("{path} содержит действующие строки: они меняют работу pam_pwhistory; проверьте файл "
               "и включите pam_pwhistory remember=5 вручную")
ACTION_UNSEEN = ("pam-auth-update включит вместе с профилем политики ещё не выбранные профили с Default: yes "
                 "({names}): включите pam_pwhistory remember=5 вручную или сначала решите судьбу этих профилей")
ACTION_PROFILE = ("/usr/share/pam-configs/securelinux-pwhistory уже есть и отличается от профиля политики: "
                  "проверьте файл и включите pam_pwhistory remember=5 вручную")

OUTCOMES = (
    "APPLIED",
    "ALREADY_COMPLIANT",
    "DRY_RUN_WOULD_APPLY",
    "NOT_ELIGIBLE_APPLY_UNSUPPORTED",
    "ABORTED_PRECONDITION_CONFLICT",
    "ABORTED_PRECONDITION_OTHER",
    "FAILED_NOT_COMMITTED",
    "FAILED_COMPENSATION",
)
COMMIT_COMMITTED = "COMMITTED"
COMMIT_NOT_COMMITTED = "NOT_COMMITTED"
COMMIT_NOT_STARTED = "NOT_STARTED"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"


class _Refused(Exception):
    def __init__(self, outcome, reason, decision=None):
        super().__init__(reason)
        self.outcome = outcome
        self.reason = reason
        self.decision = decision


def _other(reason):
    return _Refused("ABORTED_PRECONDITION_OTHER", reason)


def _admin(reason, action):
    return _Refused("ABORTED_PRECONDITION_CONFLICT", reason,
                    {"class": "ADMIN_ACTION_REQUIRED", "required": True, "action": action})


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not isinstance(key, str) or not isinstance(op, str):
        raise ValueError("key and op must be strings")
    if isinstance(expected, bool) or not isinstance(expected, int):
        raise ValueError("expected must be integer")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def _p(root, path):
    return path if root is None else os.path.join(root, path.lstrip("/"))


def read_file(path, domain, missing_ok=False):
    """(байты, stat) обычного файла без перехода по ссылке; нет файла и missing_ok — (None, None)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        if missing_ok:
            return None, None
        raise _other(domain + ":missing")
    except OSError as exc:
        if exc.errno == 40:  # ELOOP: символическая ссылка
            raise _other(domain + ":invalid-type")
        raise _other(domain + ":open-failed")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _other(domain + ":invalid-type")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        raise _other(domain + ":read-failed")
    finally:
        os.close(fd)
    return b"".join(chunks), st



def _default_privilege_check() -> bool:
    return os.geteuid() == 0


def _commit_state(outcome, dry_run, mutation):
    if outcome == "APPLIED" or (outcome == "ALREADY_COMPLIANT" and not dry_run):
        return COMMIT_COMMITTED
    if mutation:
        return COMMIT_NOT_COMMITTED
    return COMMIT_NOT_STARTED


def _result(control_id, outcome, *, actions, dry_run, mutation=False, **extra):
    record = {
        "adapter_id": ADAPTER_ID,
        "mechanism_id": MECHANISM_ID,
        "control_id": control_id,
        "target": COMMON_PASSWORD,
        "outcome": outcome,
        "reason": None,
        "policy_current": None,
        "operator_decision": None,
        "actions_attempted": list(actions),
        "mutation_performed": bool(mutation),
        "transaction_commit": _commit_state(outcome, dry_run, mutation),
        "dry_run": bool(dry_run),
    }
    record.update(extra)
    if record["outcome"] not in OUTCOMES:
        raise ValueError("outcome outside closed vocabulary")
    return record


def outcome_rc_contribution(outcome, dry_run=False):
    """"0" для успешных исходов, иначе "nonzero"."""
    if outcome in ("APPLIED", "ALREADY_COMPLIANT", "NOT_ELIGIBLE_APPLY_UNSUPPORTED"):
        return "0"
    if dry_run and outcome == "DRY_RUN_WOULD_APPLY":
        return "0"
    return "nonzero"


def read_pam(root):
    raw, _st = read_file(_p(root, COMMON_PASSWORD), "pam")
    return raw


def observe(root):
    """Эталонный стек ("clean", "pwquality", "enabled"); иной стек — решение администратора."""
    raw = read_pam(root)
    try:
        return stack_state(raw)
    except ParseError as exc:
        raise _admin(exc.reason, ACTION_STACK.format(reason=exc.reason))


def active_conf(root):
    """Путь pwhistory.conf с действующими строками или None; не обычный файл — отказ."""
    for path in CONF_PATHS:
        raw, _st = read_file(_p(root, path), "pwhistory-conf", missing_ok=True)
        if raw is not None and conf_active(raw):
            return path
    return None


def _shown(state):
    return str(REMEMBER) if state == "enabled" else "<module-absent>"


def snapshot(root):
    """{путь: байты или None} файлов /etc/pam.d/common-* и /var/lib/pam/*."""
    result = {}
    for path in COMMON_FILES + STATE_FILES:
        raw, _st = read_file(_p(root, path), "pam", missing_ok=True)
        result[path] = raw
    return result


def _write_profile(path, raw, root):
    tmp = path + TMP_SUFFIX
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        if root is None:
            os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o644)
        os.fsync(fd)
    except OSError:
        os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.close(fd)
    try:
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _restore(path, raw, root):
    """Вернуть байты файла /etc/pam.d/common-* или /var/lib/pam/* (None — файла не было)."""
    full = _p(root, path)
    if raw is None:
        try:
            os.unlink(full)
        except FileNotFoundError:
            pass
        return
    _now, st = read_file(full, "pam", missing_ok=True)
    tmp = full + TMP_SUFFIX
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        if st is not None:
            if root is None:
                os.fchown(fd, st.st_uid, st.st_gid)
            os.fchmod(fd, stat.S_IMODE(st.st_mode))
        else:
            os.fchmod(fd, 0o644)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, full)


def _default_run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                                                "DEBIAN_FRONTEND": "noninteractive"})


def _call(run, argv):
    try:
        return run(argv, TOOL_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None


def unseen_default_profiles(root):
    """Профили /usr/share/pam-configs с Default: yes, которых нет в /var/lib/pam/seen (кроме нашего)."""
    seen_raw, _st = read_file(_p(root, SEEN), "pam-state", missing_ok=True)
    seen = set(seen_raw.decode("utf-8", "replace").split("\n")) if seen_raw is not None else set()
    try:
        names = sorted(os.listdir(_p(root, PAM_CONFIGS)))
    except OSError:
        raise _other("pam-configs:open-failed")
    result = []
    for name in names:
        if name == PROFILE_NAME or name in seen or name.endswith("~") or re.fullmatch(r"#.+#", name):
            continue
        raw, _st = read_file(os.path.join(_p(root, PAM_CONFIGS), name), "pam-configs", missing_ok=True)
        if raw is not None and re.search(rb"(?m)^Default:\s+yes\s*$", raw):
            result.append(name)
    return result


def debconf_profiles(run):
    """Значение libpam-runtime/profiles по `debconf-show libpam-runtime`; отказ — None."""
    cp = _call(run, [DEBCONF_SHOW, "libpam-runtime"])
    if cp is None or cp.returncode != 0:
        return None
    for line in cp.stdout.split(b"\n"):
        body = line.lstrip(b"* ")
        if body.startswith(b"libpam-runtime/profiles:"):
            return body[len(b"libpam-runtime/profiles:"):].strip()
    return None


def _module_present(root):
    for path in MODULE_PATHS:
        try:
            st = os.stat(_p(root, path))
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            return True
    return False


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None):
    """Включить pam_pwhistory remember=5 профилем pam-auth-update.

    `_root` и `_run` — только для тестов: корень файловой системы и запуск pam-auth-update.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run
    mutation = False

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, mutation=mutation, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    if SPECS.get(key) != (op, expected):
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    current = None
    profile_existed = False
    try:
        actions.append("P1_OBSERVE")
        state = observe(_root)
        current = _shown(state)
        conf = active_conf(_root)
        if conf is not None:
            if state == "enabled":
                current = "pwhistory-conf:active-lines"
            raise _admin("pwhistory-conf:active-lines", ACTION_CONF.format(path=conf))
        if state == "enabled":
            return done("ALREADY_COMPLIANT", policy_current=current)
        if state == "clean":
            raise _admin("pam:pwquality-not-enabled", ACTION_PWQ)
        existing, _st = read_file(_p(_root, PROFILE_PATH), "pam-configs", missing_ok=True)
        if existing is not None and existing != PROFILE_BYTES:
            raise _admin("pam:profile-conflict", ACTION_PROFILE)
        profile_existed = existing is not None
        if not _module_present(_root):
            raise _other("pam:module-missing")
        unseen = unseen_default_profiles(_root)
        if unseen:
            raise _admin("pam:unseen-default-profiles", ACTION_UNSEEN.format(names=", ".join(unseen)))
        if _root is None:
            _check_tools(_root, (PAM_AUTH_UPDATE, DEBCONF_SHOW))
        before = snapshot(_root)
        actions.append("P2_PLAN")
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY", policy_current=current)
        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            raise _other("privilege")
        selection = debconf_profiles(run)
        if selection is None:
            raise _other("debconf:query-failed")
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, policy_current=current, operator_decision=exc.decision)

    actions.append("PHASE1_PROFILE_AND_PAM_AUTH_UPDATE")
    mutation = True
    reason = None
    try:
        if not profile_existed:
            _write_profile(_p(_root, PROFILE_PATH), PROFILE_BYTES, _root)
    except OSError:
        reason = "pam:profile-write-failed"
    if reason is None:
        cp = _call(run, [PAM_AUTH_UPDATE, "--package", "--enable", PROFILE_NAME])
        if cp is None or cp.returncode != 0:
            reason = "pam:auth-update-failed"
    if reason is None:
        actions.append("FINAL_POSTCHECK")
        try:
            after = stack_state(read_pam(_root))
            conf = active_conf(_root)
            others = {p: r for p, r in snapshot(_root).items() if p in COMMON_FILES and p != COMMON_PASSWORD}
        except (_Refused, ParseError):
            reason = "pam:postcheck-failed"
        else:
            unchanged = all(others[p] == before[p] for p in others)
            if after == "enabled" and conf is None and unchanged:
                return done("APPLIED", policy_current=str(REMEMBER))
            reason = "pam:auth-update-not-applied" if after == "pwquality" else "pam:postcheck-failed"
    actions.append("COMPENSATION")
    removed = _call(run, [PAM_AUTH_UPDATE, "--package", "--remove", PROFILE_NAME])
    ok = removed is not None and removed.returncode == 0
    if not profile_existed:
        try:
            os.unlink(_p(_root, PROFILE_PATH))
        except FileNotFoundError:
            pass
        except OSError:
            ok = False
    try:
        now = snapshot(_root)
        for path, raw in before.items():
            if now[path] != raw:
                _restore(path, raw, _root)
        ok = ok and snapshot(_root) == before
    except (OSError, _Refused):
        ok = False
    ok = ok and debconf_profiles(run) == selection
    if ok:
        return done("FAILED_NOT_COMMITTED", reason=reason, policy_current=current)
    return done("FAILED_COMPENSATION", reason=reason, policy_current=current)


def _check_tools(root, paths):
    for path in paths:
        try:
            st = os.stat(_p(root, path))
        except OSError:
            raise _other("tools:missing:" + os.path.basename(path))
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            raise _other("tools:missing:" + os.path.basename(path))


def control_result_to_report(result, started_at, finished_at):
    return {
        "adapter_id": result["adapter_id"],
        "mechanism_id": result["mechanism_id"],
        "control_id": result["control_id"],
        "target": result["target"],
        "outcome": result["outcome"],
        "reason": result["reason"],
        "policy_current": result["policy_current"],
        "operator_decision": None if result["operator_decision"] is None else dict(result["operator_decision"]),
        "started_at": started_at,
        "finished_at": finished_at,
        "actions_attempted": list(result["actions_attempted"]),
        "step_rc": outcome_rc_contribution(result["outcome"], result["dry_run"]),
        "mutation_performed": result["mutation_performed"],
        "transaction_commit": result["transaction_commit"],
    }
