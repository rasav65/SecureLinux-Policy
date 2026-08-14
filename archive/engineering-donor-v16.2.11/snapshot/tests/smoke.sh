#!/usr/bin/env bash

export PATH="/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
cd "$(dirname "$0")/.." || exit 1

TMP_STATE_DIR="$(pwd)/.tmp-test-state"
TMP_FIXTURE_DIR="$(pwd)/.tmp-smoke-fixture"
TMP_CONFIG="$(pwd)/.tmp-smoke.conf"
TMP_MANIFEST="$(pwd)/.tmp-restore-manifest.json"
TMP_REPORT="$(pwd)/.tmp-smoke-report.json"
TMP_ADDITIONAL_DEFAULT_LOG="$(pwd)/.tmp-additional-default.log"
TMP_ADDITIONAL_FLAG_LOG="$(pwd)/.tmp-additional-flag.log"
TMP_ADDITIONAL_MODE_LOG="$(pwd)/.tmp-additional-mode.log"
TMP_ADDITIONAL_UNKNOWN_LOG="$(pwd)/.tmp-additional-unknown.log"

rm -rf "$TMP_STATE_DIR" "$TMP_FIXTURE_DIR"
mkdir -p   "$TMP_FIXTURE_DIR/home/user1"   "$TMP_FIXTURE_DIR/cron/crontabs"   "$TMP_FIXTURE_DIR/proc/123"   "$TMP_FIXTURE_DIR/roots/bin"   "$TMP_FIXTURE_DIR/roots/lib"

: > "$TMP_FIXTURE_DIR/home/user1/.bashrc"
: > "$TMP_FIXTURE_DIR/cron/crontabs/user1"
: > "$TMP_FIXTURE_DIR/roots/bin/runtime-bin"
: > "$TMP_FIXTURE_DIR/roots/lib/libsample.so"
chmod 700 "$TMP_FIXTURE_DIR/home/user1"
chmod 600 "$TMP_FIXTURE_DIR/home/user1/.bashrc" "$TMP_FIXTURE_DIR/cron/crontabs/user1"
chmod 755 "$TMP_FIXTURE_DIR/roots/bin/runtime-bin" "$TMP_FIXTURE_DIR/roots/lib/libsample.so"
ln -s "$TMP_FIXTURE_DIR/roots/bin/runtime-bin" "$TMP_FIXTURE_DIR/proc/123/exe"

export SECURELINUX_NG_RUNTIME_PROC_ROOT="$TMP_FIXTURE_DIR/proc"
export SECURELINUX_NG_RUNTIME_PATHS_READ_MAPS=0
export SECURELINUX_NG_HOME_BASE_DIR="$TMP_FIXTURE_DIR/home"
export SECURELINUX_NG_USER_CRON_DIRS="$TMP_FIXTURE_DIR/cron:$TMP_FIXTURE_DIR/cron/crontabs"
export SECURELINUX_NG_STANDARD_SYSTEM_PATHS="$TMP_FIXTURE_DIR/roots/bin:$TMP_FIXTURE_DIR/roots/lib"
export SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_ENV_PATH=0
export SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_KERNEL_MODULES=0
export SECURELINUX_NG_SUID_SGID_PATHS="$TMP_FIXTURE_DIR/roots/bin:$TMP_FIXTURE_DIR/roots/lib"

run_unprivileged() {
    if [ "$(id -u)" -eq 0 ]; then
        su -s /bin/sh nobody -c "$*"
    else
        "$@"
    fi
}

cat > "$TMP_CONFIG" <<EOF
PROFILE=baseline
ENABLE_ADDITIONAL_MEASURES=0
ENABLE_CORPORATE_PASSWORD_POLICY=0
STATE_DIR=$TMP_STATE_DIR
REPORT_FILE=$TMP_REPORT
EOF

cat > "$TMP_MANIFEST" <<EOF
{
  "version": "16.2.3",
  "profile": "baseline",
  "mode": "apply",
  "timestamp": "2026-03-14T00:00:00",
  "backups": [],
  "created_files": [],
  "pending_created_groups": [],
  "created_groups": [],
  "pending_group_memberships": [],
  "added_group_memberships": [],
  "password_aging_snapshots": [],
  "pending_package_transactions": [],
  "installed_packages": [],
  "modified_files": [],
  "systemd_units": [],
  "sysctl_configs": [],
  "grub_backups": [],
  "apply_report": [],
  "warnings": [],
  "irreversible_changes": []
}
EOF

bash tests/manifest-bootstrap-regression.sh &&
bash tests/manifest-writer-contract-regression.sh &&
bash tests/top-level-rc-regression.sh &&
bash tests/check-report-rc-regression.sh &&
bash tests/state-dir-security-regression.sh &&
bash tests/created-file-crash-regression.sh &&
bash tests/group-membership-crash-regression.sh &&
bash tests/package-crash-regression.sh &&
bash tests/service-state-crash-regression.sh &&
bash tests/apport-suid-dumpable-regression.sh &&
bash tests/manifest-resolution-regression.sh &&
bash tests/extended-metadata-regression.sh &&
bash tests/portable-sha256-regression.sh &&
bash tests/hardlink-safety-regression.sh &&
bash tests/typed-fstab-state-regression.sh &&
bash tests/password-policy-regression.sh &&
bash tests/backup-failure-regression.sh &&
bash tests/firewall-safety-regression.sh &&
bash tests/ufw-transaction-regression.sh &&
bash tests/architecture-regression.sh &&
bash tests/fstec-mapping-regression.sh &&
bash tests/wheel-aging-regression.sh &&
bash tests/runtime-paths-regression.sh &&
bash tests/fs-critical-regression.sh &&
bash tests/wheel-fstec-regression.sh &&
bash tests/additional-measures-optin-regression.sh &&
bash tests/corporate-password-policy-cli-regression.sh &&
bash tests/atomic-writer-shell-function-regression.sh &&
bash tests/sudo-policy-portability-regression.sh &&
bash tests/profile-aware-dry-run-regression.sh &&
bash tests/empty-password-restore-regression.sh &&
bash tests/shadow-state-regression.sh &&
bash tests/password-package-restore-regression.sh &&
bash tests/sysctl-stricter-values-regression.sh &&
bash tests/symlink-target-regression.sh &&
bash tests/write-once-sysctl-restore-regression.sh &&
./securelinux-ng.sh --version &&
./securelinux-ng.sh --help | grep -q -- "--enable-additional-measures" &&
./securelinux-ng.sh --help | grep -q -- "--enable-corporate-password-policy" &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" > "$TMP_ADDITIONAL_DEFAULT_LOG" &&
grep -q 'Дополнительные меры проекта отключены: ENABLE_ADDITIONAL_MEASURES=0' "$TMP_ADDITIONAL_DEFAULT_LOG" &&
./securelinux-ng.sh --apply --dry-run --enable-additional-measures --config "$TMP_CONFIG" > "$TMP_ADDITIONAL_FLAG_LOG" &&
! grep -q 'Дополнительные меры проекта отключены: ENABLE_ADDITIONAL_MEASURES=0' "$TMP_ADDITIONAL_FLAG_LOG" &&
grep -q 'auditd dry-run: rules would be written' "$TMP_ADDITIONAL_FLAG_LOG" &&
! ./securelinux-ng.sh --restore --enable-additional-measures --config "$TMP_CONFIG" > "$TMP_ADDITIONAL_MODE_LOG" 2>&1 &&
grep -q -- '--enable-additional-measures допустим только вместе с --apply' "$TMP_ADDITIONAL_MODE_LOG" &&
! ./securelinux-ng.sh --apply --dry-run --enable-additional-measure --config "$TMP_CONFIG" > "$TMP_ADDITIONAL_UNKNOWN_LOG" 2>&1 &&
grep -q -- 'Неизвестный аргумент: --enable-additional-measure' "$TMP_ADDITIONAL_UNKNOWN_LOG" &&
./securelinux-ng.sh --check --config "$TMP_CONFIG" >/dev/null &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" >/dev/null &&
./securelinux-ng.sh --report --config "$TMP_CONFIG" >/dev/null &&
run_unprivileged ./securelinux-ng.sh --apply --config "$TMP_CONFIG" 2>&1 | grep -q -- "--apply без --dry-run требует root" &&
run_unprivileged ./securelinux-ng.sh --restore --manifest "$TMP_MANIFEST" --config "$TMP_CONFIG" 2>&1 | grep -q -- "--restore требует root" &&
run_unprivileged ./securelinux-ng.sh --restore --config "$TMP_CONFIG" 2>&1 | grep -q -- "--restore требует root" &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" | grep -q 'позиций в реестре: 60' &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" | grep -q 'статус done (полная restore): 44 из 59' &&
./securelinux-ng.sh --apply --dry-run --config "$TMP_CONFIG" | grep -q 'статус partial (reboot или ручные действия): 15 из 59' &&

python3 - "$TMP_REPORT" "./securelinux-ng.sh" <<'PYCHECK'
import json, pathlib, sys

report = pathlib.Path(sys.argv[1])
data = json.loads(report.read_text(encoding="utf-8"))

items = {entry["item"] for entry in data.get("fstec_items", [])}

# Обязательные ФСТЭК-пункты
required_fstec = {
    "2.1.1", "2.1.2",
    "2.2.1", "2.2.2",
    "2.3.1", "2.3.2", "2.3.3", "2.3.4", "2.3.5", "2.3.6", "2.3.7", "2.3.8", "2.3.9",
    "2.3.10", "2.3.11",
    "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5", "2.4.6", "2.4.7", "2.4.8",
    "2.5.1", "2.5.2", "2.5.3", "2.5.4", "2.5.6", "2.5.7", "2.5.8", "2.5.9", "2.5.10", "2.5.11",
    "2.6.1", "2.6.2", "2.6.3", "2.6.4", "2.6.5", "2.6.6",
}
missing = sorted(required_fstec - items)
if missing:
    raise SystemExit("Missing FSTEC items: " + ", ".join(missing))

summary = data.get("fstec_summary", {})
implemented = summary.get("implemented_items", 0)
done = summary.get("done", 0)
partial = summary.get("partial", 0)

if implemented != 59:
    raise SystemExit(f"implemented_items={implemented}, expected=59")
if done != 44:
    raise SystemExit(f"done={done}, expected=44")
if partial != 15:
    raise SystemExit(f"partial={partial}, expected=15")

# Проверяем наличие новых модулей
extra_required = {
    "corporate_faillock",
    "corporate_password_policy",
    "audit",
    "firewall",
    "mount",
    "fail2ban",
    "aide",
    "apparmor",
    "account_audit",
    "kernel_modules",
}
missing_extra = sorted(extra_required - items)
if missing_extra:
    raise SystemExit("Missing extra modules: " + ", ".join(missing_extra))

source = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

required_source_markers = {
    'FSTEC_DONE_ITEMS=44',
    'FSTEC_PARTIAL_ITEMS=15',
    'auditctl -l',
    'augenrules --check',
    'append_audit_watch_if_present',
    'sysctl -p "$SYSCTL_NETWORK_DROPIN"',
    'sysctl -p "$SYSCTL_KERNEL_DROPIN"',
    'sysctl -p "$SYSCTL_ATTACK_SURFACE_DROPIN"',
    'sysctl -p "$SYSCTL_USERSPACE_PROTECTION_DROPIN"',
    'cron_daemon_installed()',
    'apply завершён с errors=${#ERRORS[@]}',
    '7.6 coredump pre-runtime kernel.core_pattern:',
    'account_audit_existed_before == 0',
    '8.1-8.3 pre-unit-enabled:',
    'unit_existed_before == 0',
    '[[ -e "$sysctl_unit" || -L "$sysctl_unit" ]]',
    '( -f "$backup" || -L "$backup" )',
    'systemctl enable --runtime securelinux-ng-sysctl.service',
    'systemctl disable --runtime securelinux-ng-sysctl.service',
    'systemd unit enable failed',
    'record_sysctl_runtime_snapshot()',
    'restore_sysctl_runtime_snapshot()',
    'sysctl runtime snapshot ${module}:',
    'managed-file+reboot-required',
    'sysctl -w "kernel.core_pattern=$previous_runtime"',
    'return 2',
}

missing_markers = sorted(
    marker for marker in required_source_markers
    if marker not in source
)
if missing_markers:
    raise SystemExit(
        "Missing source markers: " + ", ".join(missing_markers)
    )

if "sysctl --system" in source:
    raise SystemExit("Forbidden global sysctl --system remains in source")

print(
    f"OK: implemented={implemented} "
    f"done={done} partial={partial}"
)
PYCHECK

rc=$?
rm -f \
  "$TMP_CONFIG" \
  "$TMP_MANIFEST" \
  "$TMP_REPORT" \
  "$TMP_ADDITIONAL_DEFAULT_LOG" \
  "$TMP_ADDITIONAL_FLAG_LOG" \
  "$TMP_ADDITIONAL_MODE_LOG" \
  "$TMP_ADDITIONAL_UNKNOWN_LOG"
unset SECURELINUX_NG_RUNTIME_PROC_ROOT SECURELINUX_NG_RUNTIME_PATHS_READ_MAPS SECURELINUX_NG_HOME_BASE_DIR SECURELINUX_NG_USER_CRON_DIRS SECURELINUX_NG_STANDARD_SYSTEM_PATHS SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_ENV_PATH SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_KERNEL_MODULES SECURELINUX_NG_SUID_SGID_PATHS
rm -rf "$TMP_STATE_DIR" "$TMP_FIXTURE_DIR"
exit $rc
