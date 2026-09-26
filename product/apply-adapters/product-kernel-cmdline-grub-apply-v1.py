#!/usr/bin/env python3
"""product-kernel-cmdline-grub-apply-v1.

APPLY adapter for mechanism `kernel-cmdline-grub-v1` (2.4.3-2.4.7, 2.5.1, 2.5.3, 2.5.9).

PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
Authority: product/contracts/mechanism-kernel-cmdline-grub-v1.json

Решения человека 24.09.2026:

* Параметр добавляется в `GRUB_CMDLINE_LINUX` файла
  `/etc/default/grub.d/zz-securelinux-policy.cfg`; имя `zz-` — чтобы файл читался
  после `init-select.cfg` и `kdump-tools.cfg` эталонных сред. Затем `update-grub`.
  Новое значение вступает в силу после перезагрузки; CHECK (`/proc/cmdline`)
  до неё остаётся FAIL.
* Автоматически: `init_on_alloc=1`, `slab_nomerge`, `randomize_kstack_offset=1`,
  `vsyscall=none`, `iommu=force`, `iommu.strict=1`, `iommu.passthrough=0` (`AUTO`;
  iommu — решение пользователя 26.09.2026).
* `mitigations=auto,nosmt`, `tsx=off`, `debugfs=off` не пишутся: исход ABORTED_PRECONDITION_CONFLICT с
  `operator_decision` класса BOOT_PARAMETER_ADMIN_DECISION — блок «требуется
  решение администратора», как у 2.6.6 (`ADMIN`).
* Другое значение того же параметра в `/etc/default/grub` или другом
  `/etc/default/grub.d/*.cfg` — отказ без записи (`grub:foreign-conflict`); файлы
  администратора не правятся. Тот же токен там — в файл не дублируется.

Порядок: наблюдение → план → запись файла (tmp + rename, root 0644) →
`update-grub` → проверка, что токен есть в каждой строке `linux …vmlinuz…` файла
`/boot/grub/grub.cfg` (в grub 2.12 `GRUB_CMDLINE_LINUX` входит и в обычную, и в
recovery-запись `10_linux`). Ошибка `update-grub` или проверки — прежнее содержимое
файла (или его отсутствие) восстанавливается и `update-grub` запускается снова.
Откат администратором: удалить файл и выполнить `update-grub`.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess

ADAPTER_ID = "product-kernel-cmdline-grub-apply-v1"
MECHANISM_ID = "kernel-cmdline-grub-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "kernel-cmdline"

DROPIN = "/etc/default/grub.d/zz-securelinux-policy.cfg"
GRUB_DEFAULT = "/etc/default/grub"
GRUB_D = "/etc/default/grub.d"
UPDATE_GRUB = "/usr/sbin/update-grub"
GRUB_CFG = "/boot/grub/grub.cfg"
PROC_CMDLINE = "/proc/cmdline"
UPDATE_GRUB_TIMEOUT = 600

DROPIN_HEADER = (
    "# Managed by SecureLinux-Policy: FSTEC 2022 kernel boot parameters.\n"
    "# Revert: remove this file and run update-grub.\n"
)
DROPIN_LINE_RE = re.compile(r'^GRUB_CMDLINE_LINUX="\$GRUB_CMDLINE_LINUX((?: [A-Za-z0-9_.,=-]+)*)"$')
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:=[A-Za-z0-9_.,-]+)?$")

# (key, op, expected) контролей механизма. expected у `present` — bool, как в control-yaml.
AUTO = {
    "FSTEC-LINUX-2022-2.4.3-INIT-ON-ALLOC": ("init_on_alloc", "eq", "1"),
    "FSTEC-LINUX-2022-2.4.4-SLAB-NOMERGE": ("slab_nomerge", "present", True),
    "FSTEC-LINUX-2022-2.4.6-RANDOMIZE-KSTACK-OFFSET": ("randomize_kstack_offset", "eq", "1"),
    "FSTEC-LINUX-2022-2.5.1-VSYSCALL": ("vsyscall", "eq", "none"),
    # Решение пользователя 26.09.2026: три параметра 2.4.5 пишутся автоматически.
    "FSTEC-LINUX-2022-2.4.5-IOMMU-FORCE": ("iommu", "eq", "force"),
    "FSTEC-LINUX-2022-2.4.5-IOMMU-PASSTHROUGH": ("iommu.passthrough", "eq", "0"),
    "FSTEC-LINUX-2022-2.4.5-IOMMU-STRICT": ("iommu.strict", "eq", "1"),
}
ADMIN = {
    "FSTEC-LINUX-2022-2.4.7-MITIGATIONS": (("mitigations", "eq", "auto,nosmt"),
        "nosmt отключает SMT: число логических CPU уменьшается вдвое"),
    "FSTEC-LINUX-2022-2.5.3-DEBUGFS": (("debugfs", "one-of", "off|no-mount"),
        "перестают работать инструменты, которым нужен debugfs"),
    "FSTEC-LINUX-2022-2.5.9-TSX": (("tsx", "eq", "off"),
        "на части процессоров снижается производительность"),
}

OUTCOMES = (
    "APPLIED",
    "PENDING_REBOOT",
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
    def __init__(self, outcome, reason):
        super().__init__(reason)
        self.outcome = outcome
        self.reason = reason


def validate_control_input(control_id, key, op, expected, apply_supported):
    """Fail-closed validation of one control row. Raises ValueError."""
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not isinstance(key, str) or not isinstance(op, str):
        raise ValueError("key and op must be strings")
    if not isinstance(expected, (str, bool)):
        raise ValueError("expected must be a string or bool")
    if not isinstance(apply_supported, bool):
        raise ValueError("apply_supported must be bool")
    return True


def desired_token(key, op, expected):
    """Токен, который пишет механизм: `key=value`, `key` для present, первый член one-of."""
    if op == "present":
        return key
    if op == "one-of":
        return "%s=%s" % (key, expected.split("|")[0])
    return "%s=%s" % (key, expected)


def evaluate(tokens, key, op, expected):
    """Семантика CHECK kernel-cmdline-check-semantic-v2 для одного ключа.

    Возвращает (compliant, current): current — значение без `key=`, `true`/`false`
    для present, `<absent>`, либо `conflict` (конфликтующие повторы = ERROR у CHECK).
    """
    bare = key in tokens
    values = {t[len(key) + 1:] for t in tokens if t.startswith(key + "=")}
    if op == "present":
        if values:
            return False, "conflict"
        return bare, "true" if bare else "false"
    if bare or len(values) > 1:
        return False, "conflict"
    if not values:
        return False, "<absent>"
    value = next(iter(values))
    members = expected.split("|") if op == "one-of" else [expected]
    return value in members, value


def _p(root, path):
    return path if root is None else os.path.join(root, path.lstrip("/"))


def _read_cmdline(root):
    try:
        with open(_p(root, PROC_CMDLINE), "rb") as stream:
            raw = stream.read()
    except OSError:
        raise _Refused("ABORTED_PRECONDITION_OTHER", "cmdline:read-failed")
    if b"\x00" in raw:
        raise _Refused("ABORTED_PRECONDITION_OTHER", "cmdline:invalid-bytes")
    return raw.decode("ascii", "replace").split()


def _read_dropin(root):
    """Токены нашего файла или None, если файла нет. Чужое содержимое — отказ."""
    path = _p(root, DROPIN)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise _Refused("ABORTED_PRECONDITION_OTHER", "dropin:lstat-failed")
    if not stat.S_ISREG(st.st_mode):
        raise _Refused("ABORTED_PRECONDITION_CONFLICT", "dropin:not-regular")
    if root is None and st.st_uid != 0:
        raise _Refused("ABORTED_PRECONDITION_CONFLICT", "dropin:owner")
    if stat.S_IMODE(st.st_mode) & 0o022:
        raise _Refused("ABORTED_PRECONDITION_CONFLICT", "dropin:writable")
    with open(path, "r", encoding="ascii", errors="replace") as stream:
        text = stream.read()
    if not text.startswith(DROPIN_HEADER):
        raise _Refused("ABORTED_PRECONDITION_CONFLICT", "dropin:foreign-content")
    body = text[len(DROPIN_HEADER):]
    if not body.endswith("\n") or body.count("\n") != 1:
        raise _Refused("ABORTED_PRECONDITION_CONFLICT", "dropin:foreign-content")
    match = DROPIN_LINE_RE.fullmatch(body[:-1])
    if match is None:
        raise _Refused("ABORTED_PRECONDITION_CONFLICT", "dropin:foreign-content")
    return match.group(1).split()


def render_dropin(tokens):
    return DROPIN_HEADER + 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX%s"\n' % "".join(" " + t for t in tokens)


def _default_run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def _foreign_tokens(root, run):
    """GRUB_CMDLINE_LINUX и _DEFAULT после /etc/default/grub и grub.d/*.cfg без нашего файла.

    Так же, как их читает grub-mkconfig: `.` каждого файла по порядку glob.
    """
    script = (
        'set -e; . "$1"; for f in "$2"/*.cfg; do [ "$f" = "$3" ] && continue; '
        '[ -e "$f" ] && . "$f"; done; printf "%s\\n%s\\n" "$GRUB_CMDLINE_LINUX" "$GRUB_CMDLINE_LINUX_DEFAULT"'
    )
    cp = run(["/bin/sh", "-c", script, "sh", _p(root, GRUB_DEFAULT), _p(root, GRUB_D), _p(root, DROPIN)], 60)
    if cp.returncode != 0:
        raise _Refused("ABORTED_PRECONDITION_OTHER", "grub:config-read-failed")
    return cp.stdout.decode("ascii", "replace").split()


def _check_layout(root):
    grub_d = _p(root, GRUB_D)
    try:
        st = os.lstat(grub_d)
    except OSError:
        raise _Refused("ABORTED_PRECONDITION_OTHER", "grub:grub-d-missing")
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o022 or (root is None and st.st_uid != 0):
        raise _Refused("ABORTED_PRECONDITION_OTHER", "grub:grub-d-untrusted")
    if not os.path.isfile(_p(root, GRUB_DEFAULT)):
        raise _Refused("ABORTED_PRECONDITION_OTHER", "grub:default-missing")
    # Тип файла и биты исполнения; сам запуск проверяется по коду возврата update-grub.
    try:
        tool = os.stat(_p(root, UPDATE_GRUB))
    except OSError:
        raise _Refused("ABORTED_PRECONDITION_OTHER", "grub:update-grub-missing")
    if not stat.S_ISREG(tool.st_mode) or not tool.st_mode & 0o111:
        raise _Refused("ABORTED_PRECONDITION_OTHER", "grub:update-grub-missing")


def _write_dropin(root, tokens):
    path = _p(root, DROPIN)
    tmp = path + ".slp-tmp"
    with open(tmp, "w", encoding="ascii") as stream:
        stream.write(render_dropin(tokens))
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _restore_dropin(root, old_tokens):
    if old_tokens is None:
        try:
            os.unlink(_p(root, DROPIN))
        except FileNotFoundError:
            pass
    else:
        _write_dropin(root, old_tokens)


def _grub_cfg_has(root, token):
    try:
        with open(_p(root, GRUB_CFG), "r", encoding="utf-8", errors="replace") as stream:
            # Только строки ядра: memtest86+ и др. тоже могут загружаться командой `linux`.
            lines = [l.split() for l in stream if re.match(r"^\s*linux\s+\S*vmlinuz", l)]
    except OSError:
        return False
    return bool(lines) and all(token in words for words in lines)


def _update_grub(root, run):
    try:
        cp = run([_p(root, UPDATE_GRUB)], UPDATE_GRUB_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return cp.returncode == 0


def _default_privilege_check() -> bool:
    return os.geteuid() == 0


def _result(control_id, outcome, *, actions, dry_run, mutation=False, **extra):
    record = {
        "adapter_id": ADAPTER_ID,
        "mechanism_id": MECHANISM_ID,
        "control_id": control_id,
        "target": DROPIN,
        "outcome": outcome,
        "reason": None,
        "token": None,
        "cmdline_current": None,
        "reboot_required": False,
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


def _commit_state(outcome, dry_run, mutation):
    if outcome == "APPLIED" or (outcome in ("ALREADY_COMPLIANT", "PENDING_REBOOT") and not dry_run):
        return COMMIT_COMMITTED
    if mutation:
        return COMMIT_NOT_COMMITTED
    return COMMIT_NOT_STARTED


def outcome_rc_contribution(outcome, dry_run=False):
    """"0" для успешных исходов, иначе "nonzero"."""
    if outcome in ("APPLIED", "PENDING_REBOOT", "ALREADY_COMPLIANT", "NOT_ELIGIBLE_APPLY_UNSUPPORTED"):
        return "0"
    if dry_run and outcome == "DRY_RUN_WOULD_APPLY":
        return "0"
    return "nonzero"


def execute_control(control_id, key, op, expected, apply_supported, *, dry_run,
                    privilege_check=None, _root=None, _run=None):
    """Apply one kernel boot parameter through the GRUB drop-in.

    `_root` и `_run` — только для тестов: корень файловой системы и запуск команд.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    actions = ["P0_ELIGIBILITY"]
    run = _run if _run is not None else _default_run

    def done(outcome, **extra):
        return _result(control_id, outcome, actions=actions, dry_run=dry_run, **extra)

    if not apply_supported:
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="apply-unsupported")
    admin = ADMIN.get(control_id)
    spec = admin[0] if admin is not None else AUTO.get(control_id)
    if spec is None or spec != (key, op, expected):
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")
    token = desired_token(key, op, expected)
    if not TOKEN_RE.fullmatch(token):
        return done("NOT_ELIGIBLE_APPLY_UNSUPPORTED", reason="op-unsupported")

    try:
        actions.append("P1_OBSERVE")
        running_ok, current = evaluate(_read_cmdline(_root), key, op, expected)
        if admin is not None:
            if running_ok:
                return done("ALREADY_COMPLIANT", token=token, cmdline_current=current)
            return done("ABORTED_PRECONDITION_CONFLICT", reason="admin-decision:" + key, token=token,
                        cmdline_current=current,
                        operator_decision={"class": "BOOT_PARAMETER_ADMIN_DECISION", "required": True,
                                           "parameter": key, "value": token, "risk": admin[1]})
        _check_layout(_root)
        old = _read_dropin(_root)
        foreign = _foreign_tokens(_root, run)
        foreign_ok, foreign_value = evaluate(foreign, key, op, expected)
        if foreign_value == "conflict" or (not foreign_ok and foreign_value not in ("<absent>", "false")):
            return done("ABORTED_PRECONDITION_CONFLICT", reason="grub:foreign-conflict", token=token,
                        cmdline_current=current)
        # Наш файл: прочие токены сохраняются, токен этого ключа — только если его нет у администратора.
        ours = [t for t in (old or []) if t != key and not t.startswith(key + "=")]
        want_ours = sorted(ours + ([] if foreign_ok else [token]))
        dropin_ok = (old is None and foreign_ok) or (old is not None and sorted(old) == want_ours)

        actions.append("P2_PLAN")
        if dropin_ok and _grub_cfg_has(_root, token):
            if running_ok:
                return done("ALREADY_COMPLIANT", token=token, cmdline_current=current)
            return done("PENDING_REBOOT", token=token, cmdline_current=current, reboot_required=True)
        if dry_run:
            return done("DRY_RUN_WOULD_APPLY", token=token, cmdline_current=current)

        actions.append("P3_PRIVILEGE")
        check = privilege_check if privilege_check is not None else _default_privilege_check
        if not check():
            return done("ABORTED_PRECONDITION_OTHER", reason="privilege", token=token, cmdline_current=current)

        actions.append("PHASE1_DROPIN")
        mutated = False
        if not dropin_ok:
            _write_dropin(_root, want_ours)
            mutated = True
        actions.append("PHASE2_UPDATE_GRUB")
        if _update_grub(_root, run) and _grub_cfg_has(_root, token):
            actions.append("FINAL_POSTCHECK")
            return done("APPLIED", mutation=True, token=token, cmdline_current=current, reboot_required=True)
        actions.append("COMPENSATION")
        reason = "update-grub:failed-or-token-missing"
        if mutated:
            _restore_dropin(_root, old)
        if _update_grub(_root, run):
            return done("FAILED_NOT_COMMITTED", reason=reason, mutation=True, token=token, cmdline_current=current)
        return done("FAILED_COMPENSATION", reason=reason, mutation=True, token=token, cmdline_current=current)
    except _Refused as exc:
        return done(exc.outcome, reason=exc.reason, token=token)


def control_result_to_report(result, started_at, finished_at):
    return {
        "adapter_id": result["adapter_id"],
        "mechanism_id": result["mechanism_id"],
        "control_id": result["control_id"],
        "target": result["target"],
        "outcome": result["outcome"],
        "reason": result["reason"],
        "token": result["token"],
        "cmdline_current": result["cmdline_current"],
        "reboot_required": result["reboot_required"],
        "operator_decision": None if result["operator_decision"] is None else dict(result["operator_decision"]),
        "started_at": started_at,
        "finished_at": finished_at,
        "actions_attempted": list(result["actions_attempted"]),
        "step_rc": outcome_rc_contribution(result["outcome"], result["dry_run"]),
        "mutation_performed": result["mutation_performed"],
        "transaction_commit": result["transaction_commit"],
    }
