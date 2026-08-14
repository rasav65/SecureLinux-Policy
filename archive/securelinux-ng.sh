#!/usr/bin/env bash

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# securelinux-ng.sh
# Version: 16.2.11
# Project: SecureLinux-NG
# https://github.com/rasav65/SecureLinux-NG

SCRIPT_VERSION="16.2.11"

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE=""
DRY_RUN=0
PROFILE="baseline"

# Дополнительная корпоративная парольная политика.
# Не является обязательным требованием ФСТЭК и по умолчанию отключена.
ENABLE_CORPORATE_PASSWORD_POLICY=0

# Дополнительные меры проекта вне Методического документа ФСТЭК.
# По умолчанию отключены и включаются только явно.
ENABLE_ADDITIONAL_MEASURES=0
_PROFILE_SET_BY_CLI=0
_ADDITIONAL_MEASURES_SET_BY_CLI=0
_CORPORATE_PASSWORD_POLICY_SET_BY_CLI=0
CONFIG_FILE=""
REPORT_FILE=""
MANIFEST_FILE=""
STATE_DIR="/var/log/securelinux-ng"
TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"

DISTRO_ID=""
DISTRO_VERSION_ID=""
OS_FAMILY=""
IS_CONTAINER=0
IS_DESKTOP=0
HAS_DOCKER=0
USER_NAMESPACES_LIMIT=""
WHEEL_USERS=""  # явный список; при пустом значении apply использует проверенного SUDO_USER
_APT_UPDATED=0  # флаг: 1 = apt-get update уже выполнен в этом сеансе
HAS_PODMAN=0
HAS_K8S=0

SSH_ROOT_LOGIN_DROPIN="/etc/ssh/sshd_config.d/60-securelinux-ng-root-login.conf"
SSH_ROOT_LOGIN_CONTENT=$'# Managed by SecureLinux-NG\nPermitRootLogin no\n'

SSH_HARDENING_DROPIN="/etc/ssh/sshd_config.d/61-securelinux-ng-ssh-hardening.conf"
# baseline: базовые параметры (все профили)
SSH_HARDENING_BASELINE=$'# Managed by SecureLinux-NG — SSH hardening baseline (ФСТЭК 2.1.2)\n'
SSH_HARDENING_BASELINE+=$'X11Forwarding no\n'
SSH_HARDENING_BASELINE+=$'MaxAuthTries 3\n'
SSH_HARDENING_BASELINE+=$'MaxSessions 2\n'
SSH_HARDENING_BASELINE+=$'PermitEmptyPasswords no\n'
SSH_HARDENING_BASELINE+=$'UseDNS no\n'
SSH_HARDENING_BASELINE+=$'GSSAPIAuthentication no\n'
SSH_HARDENING_BASELINE+=$'ClientAliveInterval 300\n'
SSH_HARDENING_BASELINE+=$'ClientAliveCountMax 2\n'
SSH_HARDENING_BASELINE+=$'LoginGraceTime 30\n'
SSH_HARDENING_BASELINE+=$'AllowAgentForwarding no\n'
SSH_HARDENING_BASELINE+=$'AllowTcpForwarding no\n'
SSH_HARDENING_BASELINE+=$'IgnoreRhosts yes\n'
SSH_HARDENING_BASELINE+=$'HostbasedAuthentication no\n'
SSH_HARDENING_BASELINE+=$'LogLevel VERBOSE\n'
# strict+: криптографические алгоритмы (источник: fortress_improved.sh / captainzero93)
SSH_HARDENING_STRICT=$'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n'
SSH_HARDENING_STRICT+=$'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n'
SSH_HARDENING_STRICT+=$'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256\n'
SSH_HARDENING_STRICT+=$'Compression no\n'

PAM_SU_FILE="/etc/pam.d/su"
PAM_WHEEL_BLOCK_BEGIN="# BEGIN SecureLinux-NG 2.2.1"
PAM_WHEEL_BLOCK_END="# END SecureLinux-NG 2.2.1"

PAM_COMMON_AUTH_FILE="/etc/pam.d/common-auth"
PAM_COMMON_ACCOUNT_FILE="/etc/pam.d/common-account"

FAILLOCK_CONF="/etc/security/faillock.conf"
# baseline: pam_faillock не применяется
# strict+: deny=5 unlock_time=900 (5 попыток, блокировка 15 мин)
FAILLOCK_CONF_STRICT=$'# Managed by SecureLinux-NG — pam_faillock strict+ (корпоративный стандарт 4.4)\naudit\nsilent\ndeny = 5\nunlock_time = 900\nfail_interval = 900\n'

PWQUALITY_CONF="/etc/security/pwquality.conf"
LOGIN_DEFS="/etc/login.defs"
# baseline: minlen=15, minclass=4
# strict+:  minlen=16, minclass=4, maxrepeat=2
PWQUALITY_BASELINE=$'# Managed by SecureLinux-NG — pwquality (дополнительная корпоративная политика)\nminlen = 15\nminclass = 4\ndcredit = -1\nucredit = -1\nocredit = -1\nlcredit = -1\nreject_username = 1\nenforce_for_root = 1\nretry = 3\n'
PWQUALITY_STRICT=$'# Managed by SecureLinux-NG — pwquality strict (дополнительная корпоративная политика)\nminlen = 16\nminclass = 4\ndcredit = -1\nucredit = -1\nocredit = -1\nlcredit = -1\nmaxrepeat = 2\nreject_username = 1\nenforce_for_root = 1\nretry = 3\n'
# login.defs aging: baseline max=90, strict max=60, paranoid max=45
PASS_MAX_DAYS_BASELINE=90
PASS_MAX_DAYS_STRICT=60
PASS_MAX_DAYS_PARANOID=45
PASS_MIN_DAYS=7
PASS_WARN_AGE=14

AUDITD_RULES_DIR="/etc/audit/rules.d"
AUDITD_BASELINE_RULES="${AUDITD_RULES_DIR}/60-securelinux-ng.rules"
AUDITD_STRICT_RULES="${AUDITD_RULES_DIR}/61-securelinux-ng-extended.rules"

UFW_SSH_PORT="22"  # переопределяется из sshd_config если найден
UFW_EXTRA_RULES=""  # дополнительные правила ufw, формат: "15000/udp:Kaspersky 8080/tcp:Proxy"

SUDO_POLICY_DROPIN="/etc/sudoers.d/60-securelinux-ng-policy"
# Keep the managed sudoers policy compatible with both sudo and sudo-rs.
SUDO_POLICY_CONTENT=$'# Managed by SecureLinux-NG\n%wheel ALL=(ALL:ALL) ALL\nDefaults use_pty\nDefaults timestamp_timeout=5\nDefaults passwd_tries=3\nDefaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\n'

SYSCTL_KERNEL_DROPIN="/etc/sysctl.d/60-securelinux-ng-kernel.conf"
SYSCTL_KERNEL_CONTENT=$'# Managed by SecureLinux-NG\nkernel.dmesg_restrict = 1\nkernel.kptr_restrict = 2\nnet.core.bpf_jit_harden = 2\n'

SYSCTL_ATTACK_SURFACE_DROPIN="/etc/sysctl.d/61-securelinux-ng-attack-surface.conf"
SYSCTL_ATTACK_SURFACE_CONTENT=$'# Managed by SecureLinux-NG\nkernel.perf_event_paranoid = 3\nkernel.kexec_load_disabled = 1\nkernel.unprivileged_bpf_disabled = 1\nvm.unprivileged_userfaultfd = 0\ndev.tty.ldisc_autoload = 0\nvm.mmap_min_addr = 4096\nkernel.randomize_va_space = 2\nuser.max_user_namespaces = 0\n'

SYSCTL_USERSPACE_PROTECTION_DROPIN="/etc/sysctl.d/99-securelinux-ng-userspace-protection.conf"
SYSCTL_USERSPACE_PROTECTION_CONTENT=$'# Managed by SecureLinux-NG\nfs.protected_symlinks = 1\nfs.protected_hardlinks = 1\nfs.protected_fifos = 2\nfs.protected_regular = 2\nfs.suid_dumpable = 0\n'
SYSCTL_USERSPACE_APPORT_DROPIN="/etc/systemd/system/apport.service.d/60-securelinux-ng-suid-dumpable.conf"
SYSCTL_USERSPACE_APPORT_CONTENT=$'# Managed by SecureLinux-NG\n[Service]\nExecStartPost=/usr/sbin/sysctl -q -w fs.suid_dumpable=0\n'

SYSCTL_NETWORK_DROPIN="/etc/sysctl.d/62-securelinux-ng-network.conf"
SYSCTL_MODULES_DISABLED_DROPIN="/etc/sysctl.d/63-securelinux-ng-modules-disabled.conf"
COREDUMP_LIMITS_FILE="/etc/security/limits.d/99-securelinux-ng-coredump.conf"
COREDUMP_SYSTEMD_DIR="/etc/systemd/coredump.conf.d"
COREDUMP_SYSTEMD_FILE="/etc/systemd/coredump.conf.d/99-securelinux-ng.conf"
SYSCTL_NETWORK_CONTENT=$'# Managed by SecureLinux-NG\n# Сетевая защита (п.8.1-8.3 Стандарта)\nnet.ipv4.ip_forward = 0\nnet.ipv6.conf.all.forwarding = 0\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.conf.default.log_martians = 1\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\nnet.ipv4.tcp_syn_retries = 3\n'

RESTORE_MANIFEST=""
RESTORE_SOURCE_MANIFEST=""
FSTAB_RESTORE_DONE=0
FSTAB_LAST_MODULE_REQUIRED=0

FS_CRITICAL_FILES=("/etc/passwd" "/etc/group" "/etc/shadow")
CRON_CRITICAL_TARGETS=(
    "/etc/crontab:file:600:root:root"
    "/etc/cron.d:dir:700:root:root"
    "/etc/cron.hourly:dir:700:root:root"
    "/etc/cron.daily:dir:700:root:root"
    "/etc/cron.weekly:dir:700:root:root"
    "/etc/cron.monthly:dir:700:root:root"
)

SYSTEMD_ETC_DIR="/etc/systemd/system"

RUNTIME_PATHS_SAMPLE_LIMIT=20
SUDO_COMMANDS_SAMPLE_LIMIT=20

GRUB_KERNEL_REQUIRED_PARAMS=(
    "init_on_alloc=1"
    "slab_nomerge"
    "iommu=force"
    "iommu.strict=1"
    "iommu.passthrough=0"
    "randomize_kstack_offset=1"
    "mitigations=auto,nosmt"
    "vsyscall=none"
    "debugfs=off"
    "tsx=off"
)

HOME_SENSITIVE_FILE_NAMES=(
    ".bash_history"
    ".history"
    ".sh_history"
    ".bash_profile"
    ".bashrc"
    ".profile"
    ".bash_logout"
    ".rhosts"
)



declare -a WARNINGS=()
declare -a ERRORS=()
declare -a SAFE_ITEMS=()
declare -a RISKY_ITEMS=()
declare -a SKIPPED_ITEMS=()
declare -a POLICY_GATES=()
declare -a RESTORE_IRREVERSIBLE_CHANGES=()
FSTEC_TOTAL_ITEMS=60      # всего позиций в реестре (включая not_applicable)
FSTEC_IMPLEMENTED_ITEMS=59 # реализовано (TOTAL минус not_applicable)
FSTEC_DONE_ITEMS=44    # синхронизировать при изменении статусов
FSTEC_PARTIAL_ITEMS=15  # синхронизировать при изменении статусов

usage() {
    cat <<'EOF'
Usage:
  ./securelinux-ng.sh --help
  ./securelinux-ng.sh --version
  ./securelinux-ng.sh --check [--profile PROFILE] [--config FILE]
  ./securelinux-ng.sh --apply [--dry-run] [--enable-additional-measures] [--enable-corporate-password-policy] [--profile PROFILE] [--config FILE]
  ./securelinux-ng.sh --restore [--manifest FILE] [--profile PROFILE] [--config FILE]
  ./securelinux-ng.sh --report [--profile PROFILE] [--config FILE]

Modes:
  --check           Read-only analysis of current state
  --apply           Apply configured hardening modules
  --restore         Restore from manifest/backups
  --report          Print framework report JSON

Options:
  --dry-run         Show what would be done (valid with --apply only)
  --enable-additional-measures
                    Enable optional additional hardening modules for this run
  --enable-corporate-password-policy
                    Enable opt-in corporate password policy and pam_faillock
  --profile NAME    baseline | strict | paranoid
  --config FILE     External config file
  --manifest FILE   Manifest to restore from
  --help            Show help
  --version         Show version
EOF
}

log() {
    local msg
    msg="$(printf '[%s] %s' "$(date '+%F %T %z')" "$*")"
    printf '%s
' "$msg"
    if [[ -n "${LOG_FILE:-}" && -d "$(dirname "$LOG_FILE")" ]]; then
        printf '%s
' "$msg" >> "$LOG_FILE"
    fi
}

log_debug() {
    [[ -n "${DEBUG_LOG_FILE:-}" ]] || return 0
    mkdir -p "$(dirname "$DEBUG_LOG_FILE")" 2>/dev/null || true
    printf '[%s] [DEBUG] %s
' "$(date '+%F %T %z')" "$*" >> "$DEBUG_LOG_FILE"
}

die() {
    log "[FAIL]  $*"
    exit 1
}

add_warning() { WARNINGS+=("$1"); log "[WARN]  $1"; }
add_restore_irreversible() {
    RESTORE_IRREVERSIBLE_CHANGES+=("$1")
}
add_error() { ERRORS+=("$1"); log "[ERROR] $1"; }
add_safe() { SAFE_ITEMS+=("$1"); log "[OK]    $1"; }
add_risky() { RISKY_ITEMS+=("$1"); log "[RISKY] $1"; }
add_skipped() { SKIPPED_ITEMS+=("$1"); log "[SKIP]  $1"; }
add_policy_gate() { POLICY_GATES+=("$1"); }

# validate_managed_file_hardlinks PATH CTX — отклоняет обычный файл с nlink > 1.
# SecureLinux-NG не сохраняет hardlink topology, поэтому apply/restore не должны
# молча разрывать связь между несколькими именами одного inode.
validate_managed_file_hardlinks() {
    local path="$1" ctx="${2:-managed file}"
    local rc=0

    python3 - "$path" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYHARDLINK'
import os
import stat
import sys

path = sys.argv[1]

try:
    metadata = os.lstat(path)
except FileNotFoundError:
    raise SystemExit(0)
except OSError as exc:
    print(f"hardlink inspection failed for {path}: {exc}", file=sys.stderr)
    raise SystemExit(2)

if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink > 1:
    print(
        f"regular file has multiple hard links: {path} "
        f"(nlink={metadata.st_nlink})",
        file=sys.stderr,
    )
    raise SystemExit(1)

raise SystemExit(0)
PYHARDLINK
    rc=$?

    case "$rc" in
        0)
            return 0
            ;;
        1)
            add_error \
                "$ctx: отказ из-за нескольких hardlink-имён: $path"
            return 1
            ;;
        *)
            add_error \
                "$ctx: не удалось проверить hardlink-состояние: $path"
            return 1
            ;;
    esac
}

# backup_file_checked SRC DST CTX — создаёт backup с проверкой успеха cp
backup_file_checked() {
    local src="$1" dst="$2" ctx="${3:-backup}"

    if ! validate_managed_file_hardlinks "$src" "$ctx source"; then
        record_manifest_warning \
            "$ctx: unsafe hardlink source rejected: $src" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true
        return 1
    fi

    if ! cp -a "$src" "$dst"; then
        add_warning "$ctx: не удалось создать backup $src -> $dst"
        record_manifest_warning "$ctx: backup failed: $src -> $dst"
        return 1
    fi
    return 0
}

# atomic_write_command_output TARGET MODE COMMAND... — атомарно записывает stdout команды
# и сохраняет mode/uid/gid и все читаемые xattrs существующего managed-файла.
# POSIX ACL, file capabilities и security labels в Linux представлены xattrs;
# если хотя бы один атрибут нельзя перенести и проверить, replace не выполняется.
atomic_write_command_output() {
    local requested="${1:-}"
    local default_mode="${2:-}"
    local target_parent=""
    local target_name=""
    local producer_tmp=""
    local preflight_rc=0
    local producer_rc=0
    local writer_rc=0

    if (( $# < 3 )); then
        printf '%s\n' \
            "atomic write command is missing" \
            >&2
        return 1
    fi

    shift 2

    target_parent="$(dirname -- "$requested")"
    target_name="$(basename -- "$requested")"

    python3 -c '
import pathlib
import stat
import sys

target = pathlib.Path(sys.argv[1])

# Validate MODE before the producer is allowed to run.
int(sys.argv[2], 8)

try:
    metadata = target.lstat()
except FileNotFoundError:
    metadata = None

is_symlink = (
    metadata is not None
    and stat.S_ISLNK(metadata.st_mode)
)

is_regular = (
    metadata is not None
    and stat.S_ISREG(metadata.st_mode)
)

if (
    is_regular
    and metadata.st_nlink > 1
):
    raise SystemExit(
        "atomic write refused regular file with multiple hard links: "
        f"{target} (nlink={metadata.st_nlink})"
    )

if (
    metadata is not None
    and not is_regular
    and not is_symlink
):
    raise SystemExit(
        "atomic write refused non-regular managed path: "
        f"{target}"
    )
' "$requested" "$default_mode"

    preflight_rc=$?

    if (( preflight_rc != 0 )); then
        return "$preflight_rc"
    fi

    producer_tmp="$(
        mktemp \
            "$target_parent/.${target_name}.securelinux-ng.producer.XXXXXX"
    )"
    producer_rc=$?

    if (( producer_rc != 0 )) || [[ -z "$producer_tmp" ]]; then
        printf '%s\n' \
            "atomic write producer tempfile creation failed: $requested" \
            >&2
        return 1
    fi

    "$@" >"$producer_tmp"
    producer_rc=$?

    if (( producer_rc != 0 )); then
        rm -f -- "$producer_tmp" \
            2>/dev/null \
            || true
        return "$producer_rc"
    fi

    python3 -c '
import errno
import os
import pathlib
import stat
import sys
import tempfile

requested = pathlib.Path(sys.argv[1])
default_mode = int(sys.argv[2], 8)
producer = pathlib.Path(sys.argv[3])

producer_metadata = producer.lstat()

if not stat.S_ISREG(producer_metadata.st_mode):
    raise SystemExit(
        "atomic write producer output is not a regular file: "
        f"{producer}"
    )

target = requested

try:
    requested_metadata = target.lstat()
except FileNotFoundError:
    requested_metadata = None

requested_is_symlink = (
    requested_metadata is not None
    and stat.S_ISLNK(requested_metadata.st_mode)
)

requested_is_regular = (
    requested_metadata is not None
    and stat.S_ISREG(requested_metadata.st_mode)
)

if (
    requested_is_regular
    and requested_metadata.st_nlink > 1
):
    raise SystemExit(
        "atomic write refused regular file with multiple hard links: "
        f"{target} (nlink={requested_metadata.st_nlink})"
    )

if (
    requested_metadata is not None
    and not requested_is_regular
    and not requested_is_symlink
):
    raise SystemExit(
        "atomic write refused non-regular managed path: "
        f"{target}"
    )

xattrs = {}

if requested_is_regular:
    metadata = requested_metadata
    mode = stat.S_IMODE(metadata.st_mode)
    uid = metadata.st_uid
    gid = metadata.st_gid

    try:
        xattr_names = os.listxattr(
            target,
            follow_symlinks=False,
        )
    except OSError as error:
        unsupported_xattr_errors = {
            errno.ENOTSUP,
            getattr(
                errno,
                "EOPNOTSUPP",
                errno.ENOTSUP,
            ),
            getattr(
                errno,
                "ENOSYS",
                errno.ENOTSUP,
            ),
        }

        if error.errno not in unsupported_xattr_errors:
            raise

        xattr_names = []

    for name in xattr_names:
        xattrs[name] = os.getxattr(
            target,
            name,
            follow_symlinks=False,
        )
else:
    mode = default_mode
    uid = os.geteuid()
    gid = os.getegid()

fd, temporary = tempfile.mkstemp(
    dir=str(target.parent),
    prefix=f".{target.name}.securelinux-ng.",
)

try:
    with producer.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)

            if not block:
                break

            view = memoryview(block)

            while view:
                written = os.write(fd, view)

                if written <= 0:
                    raise OSError(
                        "atomic write producer copy made no progress"
                    )

                view = view[written:]

    os.fchown(fd, uid, gid)
    os.fchmod(fd, mode)

    for name, value in xattrs.items():
        os.setxattr(fd, name, value)

    for name, value in xattrs.items():
        if os.getxattr(fd, name) != value:
            raise OSError(
                "atomic write metadata xattr verification failed: "
                f"{name}"
            )

    os.fsync(fd)
    os.close(fd)
    fd = -1

    os.replace(temporary, target)

    directory_fd = os.open(
        target.parent,
        os.O_RDONLY | getattr(
            os,
            "O_DIRECTORY",
            0,
        ),
    )

    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)

except BaseException:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass

    raise
' "$requested" "$default_mode" "$producer_tmp"

    writer_rc=$?

    rm -f -- "$producer_tmp" \
        2>/dev/null \
        || true

    return "$writer_rc"
}

# acquire_run_lock — защита от параллельного запуска apply/restore через flock
acquire_run_lock() {
    local lockfile="$STATE_DIR/securelinux-ng.lock"
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] acquire lock: '$lockfile'"
        return 0
    fi
    exec 9>"$lockfile"
    if ! flock -n 9; then
        die "Другой экземпляр securelinux-ng уже выполняется (lock: $lockfile)"
    fi
}

# profile_allows LEVEL — возвращает 0 (true) если текущий профиль >= LEVEL
# LEVEL: baseline | strict | paranoid
profile_allows() {
    local required="$1"
    case "$required" in
        baseline) return 0 ;;
        strict)
            case "$PROFILE" in
                strict|paranoid) return 0 ;;
                *) return 1 ;;
            esac
            ;;
        paranoid)
            [[ "$PROFILE" == "paranoid" ]] && return 0 || return 1
            ;;
        *) return 1 ;;
    esac
}

record_manifest_warning() {
    local msg="$1"
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    python3 - "$MANIFEST_FILE" "$msg" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
msg = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
data.setdefault("warnings", []).append(msg)
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}

record_manifest_modified_file() {
    local path_value="$1"
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    python3 - "$MANIFEST_FILE" "$path_value" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
value = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
lst = data.setdefault("modified_files", [])
if value not in lst:
    lst.append(value)
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}

record_manifest_modified_file_best_effort() {
    local path_value="$1"

    if record_manifest_modified_file "$path_value"; then
        return 0
    fi

    add_warning \
        "manifest modified_files не обновлён: $path_value"

    return 0
}

record_manifest_backup() {
    local original_path="$1"
    local backup_path="$2"

    (( DRY_RUN == 1 )) && return 0

    if [[ -z "${MANIFEST_FILE:-}" ||
          ! -f "${MANIFEST_FILE:-}" ]]
    then
        add_error             "manifest: файл недоступен при записи backup mapping для $original_path"
        return 1
    fi

    if ! python3 -         "$MANIFEST_FILE"         "$original_path"         "$backup_path"         2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
original = sys.argv[2]
backup = sys.argv[3]

data = json.loads(
    path.read_text(encoding="utf-8")
)

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

backups = data.setdefault("backups", [])

if not isinstance(backups, list):
    raise ValueError("backups is not a list")

for index, existing in enumerate(backups):
    if not isinstance(existing, dict):
        raise ValueError(
            f"backups[{index}] is not an object"
        )

entry = {
    "original": original,
    "backup": backup,
}

if entry not in backups:
    backups.append(entry)

fd, tmp_name = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    content = (
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )

    os.write(
        fd,
        content.encode("utf-8"),
    )
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(tmp_name, path)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        os.unlink(tmp_name)
    except OSError:
        pass

    raise
PYJSON
    then
        add_error             "manifest: не удалось записать backup mapping для $original_path"
        return 1
    fi

    return 0
}
remove_manifest_backup() {
    local original_path="$1"
    local backup_path="$2"

    (( DRY_RUN == 1 )) && return 0

    if [[ -z "${MANIFEST_FILE:-}" ||
          ! -f "${MANIFEST_FILE:-}" ]]
    then
        add_error \
            "manifest: файл недоступен при удалении backup mapping для $original_path"
        return 1
    fi

    if ! python3 - \
        "$MANIFEST_FILE" \
        "$original_path" \
        "$backup_path" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
original = sys.argv[2]
backup = sys.argv[3]

data = json.loads(
    path.read_text(encoding="utf-8")
)

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

backups = data.get("backups", [])

if not isinstance(backups, list):
    raise ValueError("backups is not a list")

updated = []

for index, existing in enumerate(backups):
    if not isinstance(existing, dict):
        raise ValueError(
            f"backups[{index}] is not an object"
        )

    if (
        existing.get("original") == original
        and existing.get("backup") == backup
    ):
        continue

    updated.append(existing)

if len(updated) == len(backups):
    raise SystemExit(0)

data["backups"] = updated

fd, tmp_name = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    content = (
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )

    os.write(
        fd,
        content.encode("utf-8"),
    )
    os.fsync(fd)
    os.close(fd)
    fd = -1

    os.replace(tmp_name, path)

    directory_fd = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )

    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        os.unlink(tmp_name)
    except OSError:
        pass

    raise
PYJSON
    then
        add_error \
            "manifest: не удалось удалить backup mapping для $original_path"
        return 1
    fi

    return 0
}

manifest_has_backup_for() {
    local original_path="$1"
    [[ -n "${MANIFEST_FILE:-}" && -f "${MANIFEST_FILE:-}" ]] || return 1
    python3 - "$MANIFEST_FILE" "$original_path" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for entry in data.get("backups", []):
    if isinstance(entry, dict) and entry.get("original") == sys.argv[2]:
        raise SystemExit(0)
raise SystemExit(1)
PYJSON
}

update_manifest_created_file_state() {
    local action="$1"
    local path_value="$2"
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    python3 - "$MANIFEST_FILE" "$action" "$path_value" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
action = sys.argv[2]
value = sys.argv[3]
data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

created = data.setdefault("created_files", [])
pending = data.setdefault("pending_created_files", [])

if not isinstance(created, list):
    raise ValueError("created_files is not an array")

if not isinstance(pending, list):
    raise ValueError("pending_created_files is not an array")

for entry in created:
    if not isinstance(entry, str):
        raise ValueError("created_files entry is not a string")

for entry in pending:
    if not isinstance(entry, str):
        raise ValueError("pending_created_files entry is not a string")

if action == "pending":
    if value not in created and value not in pending:
        pending.append(value)
elif action == "commit":
    pending[:] = [entry for entry in pending if entry != value]
    if value not in created:
        created.append(value)
else:
    raise ValueError(f"unsupported created-file action: {action}")

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(fd, content.encode("utf-8"))
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)

    directory_fd = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PYJSON
}

record_manifest_pending_created_file() {
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    update_manifest_created_file_state pending "$1"
}

record_manifest_created_file() {
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    update_manifest_created_file_state commit "$1"
}

prepare_created_file_transaction() {
    local path_value="$1"
    local existed_before="$2"
    local context="$3"

    (( existed_before == 1 )) && return 0

    if ! record_manifest_pending_created_file \
        "$path_value" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}"
    then
        add_error \
            "$context: pending created-file marker не записан в manifest"
        return 1
    fi

    return 0
}
record_manifest_apply_report() {
    local msg="$1"
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    python3 - "$MANIFEST_FILE" "$msg" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
msg = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
data.setdefault("apply_report", []).append(msg)
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}

record_manifest_irreversible_change() {
    local msg="$1"
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    python3 - "$MANIFEST_FILE" "$msg" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
msg = sys.argv[2]
data = json.loads(path.read_text(encoding='utf-8'))
data.setdefault("irreversible_changes", []).append(msg)
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}


record_manifest_installed_package() {
    local module="$1"
    local package="$2"

    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1

    python3 - "$MANIFEST_FILE" "$module" "$package" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
module = sys.argv[2]
package = sys.argv[3]

data = json.loads(path.read_text(encoding="utf-8"))
items = data.setdefault("installed_packages", [])

entry = {
    "module": module,
    "package": package,
}

if entry not in items:
    items.append(entry)

fd, tmp_name = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    payload = (
        json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    os.write(fd, payload)
    os.fsync(fd)
    os.close(fd)
    os.replace(tmp_name, path)
except Exception:
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.unlink(tmp_name)
    except OSError:
        pass
    raise
PYJSON
}

record_manifest_pending_package_transaction() {
    local module="$1"
    local snapshot="$2"

    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1

    python3 - "$MANIFEST_FILE" "$module" "$snapshot" <<'PYJSON'
import json
import os
import pathlib
import stat
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
module = sys.argv[2]
snapshot = sys.argv[3]
snapshot_path = pathlib.Path(snapshot)

if not module:
    raise ValueError("package transaction module is empty")
if not snapshot_path.is_absolute():
    raise ValueError("package transaction snapshot is not absolute")
state = snapshot_path.lstat()
if not stat.S_ISREG(state.st_mode):
    raise ValueError("package transaction snapshot is not a regular file")
if snapshot_path.parent.resolve() != path.parent.resolve():
    raise ValueError("package transaction snapshot is outside manifest directory")

data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

pending = data.setdefault("pending_package_transactions", [])

if not isinstance(pending, list):
    raise ValueError("pending_package_transactions is not an array")

for index, item in enumerate(pending):
    if not isinstance(item, dict):
        raise ValueError(
            f"pending_package_transactions[{index}] is not an object"
        )

entry = {
    "module": module,
    "snapshot": snapshot,
}

if entry not in pending:
    pending.append(entry)

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    payload = (
        json.dumps(data, indent=2, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    os.write(fd, payload)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)

    directory_fd = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
PYJSON
}

commit_manifest_package_transaction() {
    local module="$1"
    local snapshot="$2"
    local current="$3"

    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1

    python3 - \
        "$MANIFEST_FILE" \
        "$module" \
        "$snapshot" \
        "$current" <<'PYJSON'
import json
import os
import pathlib
import re
import stat
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
module = sys.argv[2]
snapshot = pathlib.Path(sys.argv[3])
current = pathlib.Path(sys.argv[4])

for label, state_path in (
    ("snapshot", snapshot),
    ("current", current),
):
    state = state_path.lstat()
    if not stat.S_ISREG(state.st_mode):
        raise ValueError(f"package {label} is not a regular file")

data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

pending = data.setdefault("pending_package_transactions", [])
installed = data.setdefault("installed_packages", [])

if not isinstance(pending, list):
    raise ValueError("pending_package_transactions is not an array")
if not isinstance(installed, list):
    raise ValueError("installed_packages is not an array")

expected = {
    "module": module,
    "snapshot": str(snapshot),
}

validated_pending = []
found = False

for index, item in enumerate(pending):
    if not isinstance(item, dict):
        raise ValueError(
            f"pending_package_transactions[{index}] is not an object"
        )
    if item == expected:
        found = True
        continue
    validated_pending.append(item)

if not found:
    raise ValueError("pending package transaction is absent")

for index, item in enumerate(installed):
    if not isinstance(item, dict):
        raise ValueError(
            f"installed_packages[{index}] is not an object"
        )

before = {
    line.strip()
    for line in snapshot.read_text(encoding="utf-8").splitlines()
    if line.strip()
}
after = {
    line.strip()
    for line in current.read_text(encoding="utf-8").splitlines()
    if line.strip()
}

new_packages = sorted(after - before)
package_pattern = re.compile(
    r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$"
)

for package in new_packages:
    if package_pattern.fullmatch(package) is None:
        raise ValueError(f"invalid package name in transaction: {package}")
    entry = {
        "module": module,
        "package": package,
    }
    if entry not in installed:
        installed.append(entry)

pending[:] = validated_pending

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    payload = (
        json.dumps(data, indent=2, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    os.write(fd, payload)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)

    directory_fd = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise

print(len(new_packages))
PYJSON
}

record_manifest_module_restore_required() {
    local module="$1"

    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1

    python3 - "$MANIFEST_FILE" "$module" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
module = sys.argv[2]

data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

module_state = data.setdefault("module_state", {})

if not isinstance(module_state, dict):
    raise ValueError("manifest module_state is not an object")

state = module_state.setdefault(module, {})

if not isinstance(state, dict):
    raise ValueError(
        f"manifest module_state.{module} is not an object"
    )

state["restore_required"] = True

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    content = (
        json.dumps(data, indent=2, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    os.write(fd, content)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
PYJSON
}

record_manifest_firewall_state() {
    local ufw_was_active="$1"
    local ufw_service_was_enabled="$2"
    local nftables_was_active="$3"
    local nftables_was_enabled="$4"
    local nftables_mutation_attempted="$5"
    local rules_mutation_attempted="$6"
    local ufw_enable_attempted="$7"
    local ufw_service_enable_attempted="$8"

    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1

    python3 - "$MANIFEST_FILE" \
        "$ufw_was_active" \
        "$ufw_service_was_enabled" \
        "$nftables_was_active" \
        "$nftables_was_enabled" \
        "$nftables_mutation_attempted" \
        "$rules_mutation_attempted" \
        "$ufw_enable_attempted" \
        "$ufw_service_enable_attempted" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
values = sys.argv[2:]

if len(values) != 8 or any(value not in {"0", "1"} for value in values):
    raise ValueError("firewall state arguments must be boolean 0/1 values")

(
    ufw_was_active,
    ufw_service_was_enabled,
    nftables_was_active,
    nftables_was_enabled,
    nftables_mutation_attempted,
    rules_mutation_attempted,
    ufw_enable_attempted,
    ufw_service_enable_attempted,
) = (value == "1" for value in values)

data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

module_state = data.setdefault("module_state", {})

if not isinstance(module_state, dict):
    raise ValueError("manifest module_state is not an object")

module_state["firewall"] = {
    "ufw_was_active": ufw_was_active,
    "ufw_service_was_enabled": ufw_service_was_enabled,
    "nftables_was_active": nftables_was_active,
    "nftables_was_enabled": nftables_was_enabled,
    "nftables_mutation_attempted": nftables_mutation_attempted,
    "rules_mutation_attempted": rules_mutation_attempted,
    "ufw_enable_attempted": ufw_enable_attempted,
    "ufw_service_enable_attempted": ufw_service_enable_attempted,
    "restore_policy": "typed-partial-rules",
}

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    content = (
        json.dumps(data, indent=2, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    os.write(fd, content)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
PYJSON
}

restore_manifest_firewall_state() {
    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        return 2
    fi

    python3 - "$RESTORE_SOURCE_MANIFEST" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])

try:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    if "module_state" not in data:
        raise SystemExit(3)

    module_state = data["module_state"]

    if not isinstance(module_state, dict):
        raise ValueError("manifest module_state is not an object")

    if "firewall" not in module_state:
        raise SystemExit(1)

    state = module_state["firewall"]

    if not isinstance(state, dict):
        raise ValueError("manifest module_state.firewall is not an object")

    names = (
        "ufw_was_active",
        "ufw_service_was_enabled",
        "nftables_was_active",
        "nftables_was_enabled",
        "nftables_mutation_attempted",
        "rules_mutation_attempted",
        "ufw_enable_attempted",
        "ufw_service_enable_attempted",
    )

    values = []

    for name in names:
        value = state.get(name)

        if not isinstance(value, bool):
            raise ValueError(
                f"manifest module_state.firewall.{name} is not a boolean"
            )

        values.append("1" if value else "0")

    if state.get("restore_policy") != "typed-partial-rules":
        raise ValueError(
            "manifest module_state.firewall.restore_policy is invalid"
        )

    print("\t".join(values))
except SystemExit:
    raise
except Exception as exc:
    print(
        f"restore firewall state lookup failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)
PYJSON
}

record_manifest_empty_password_state() {
    local users_file="$1"
    local shadow_path="$2"

    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1

    python3 - "$MANIFEST_FILE" "$users_file" "$shadow_path" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
users_file = sys.argv[2]
shadow_path = sys.argv[3]

data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

module_state = data.setdefault("module_state", {})

if not isinstance(module_state, dict):
    raise ValueError("manifest module_state is not an object")

module_state["empty_passwords"] = {
    "applied": True,
    "users_file": users_file,
    "shadow_path": shadow_path,
    "restore_policy": "security-preserving-nonrestore",
}

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    content = (
        json.dumps(data, indent=2, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    os.write(fd, content)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
PYJSON
}

remove_manifest_empty_password_state() {
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1

    python3 - "$MANIFEST_FILE" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

module_state = data.setdefault("module_state", {})

if not isinstance(module_state, dict):
    raise ValueError("manifest module_state is not an object")

module_state.pop("empty_passwords", None)

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    content = (
        json.dumps(data, indent=2, ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    os.write(fd, content)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
PYJSON
}

restore_manifest_empty_password_state() {
    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        return 2
    fi

    python3 - "$RESTORE_SOURCE_MANIFEST" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])

try:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    if "module_state" not in data:
        raise SystemExit(3)

    module_state = data["module_state"]

    if not isinstance(module_state, dict):
        raise ValueError("manifest module_state is not an object")

    if "empty_passwords" not in module_state:
        raise SystemExit(1)

    state = module_state["empty_passwords"]

    if not isinstance(state, dict):
        raise ValueError(
            "manifest module_state.empty_passwords is not an object"
        )

    applied = state.get("applied")
    users_file = state.get("users_file")
    shadow_path = state.get("shadow_path")
    restore_policy = state.get("restore_policy")

    if applied is False or applied is None:
        raise SystemExit(1)

    if applied is not True:
        raise ValueError(
            "manifest module_state.empty_passwords.applied "
            "is not a boolean"
        )

    if not isinstance(users_file, str) or not users_file:
        raise ValueError(
            "manifest module_state.empty_passwords.users_file "
            "is not a non-empty string"
        )

    if not isinstance(shadow_path, str) or not shadow_path:
        raise ValueError(
            "manifest module_state.empty_passwords.shadow_path "
            "is not a non-empty string"
        )

    if restore_policy != "security-preserving-nonrestore":
        raise ValueError(
            "manifest module_state.empty_passwords.restore_policy "
            "is invalid"
        )

    print(users_file)
except SystemExit:
    raise
except Exception as exc:
    print(
        f"restore empty-password state lookup failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)
PYJSON
}

restore_manifest_module_restore_required() {
    local module="$1"

    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        return 2
    fi

    python3 - "$RESTORE_SOURCE_MANIFEST" "$module" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
module = sys.argv[2]

try:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    if "module_state" not in data:
        raise SystemExit(3)

    module_state = data["module_state"]

    if not isinstance(module_state, dict):
        raise ValueError("manifest module_state is not an object")

    if module not in module_state:
        raise SystemExit(1)

    state = module_state[module]

    if not isinstance(state, dict):
        raise ValueError(
            f"manifest module_state.{module} is not an object"
        )

    restore_required = state.get("restore_required")

    if restore_required is True:
        raise SystemExit(0)

    if restore_required is False or restore_required is None:
        raise SystemExit(1)

    raise ValueError(
        f"manifest module_state.{module}.restore_required "
        "is not a boolean"
    )
except SystemExit:
    raise
except Exception as exc:
    print(
        f"restore module-state lookup failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)
PYJSON
}

restore_manifest_has_backup_for() {
    local target="$1"
    local backup=""

    if ! backup="$(restore_lookup_backup "$target")"; then
        return 2
    fi

    [[ -n "$backup" ]]
}

restore_fstab_module_if_required() {
    local module="$1"
    local label="$2"
    local state_rc=0
    local backup_rc=0

    FSTAB_LAST_MODULE_REQUIRED=0

    restore_manifest_module_restore_required "$module"
    state_rc=$?

    case "$state_rc" in
        0)
            FSTAB_LAST_MODULE_REQUIRED=1
            ;;
        1)
            log "[i]     restore $label: typed state отсутствует — пропуск"
            return 0
            ;;
        3)
            restore_manifest_has_backup_for "/etc/fstab"
            backup_rc=$?

            case "$backup_rc" in
                0)
                    FSTAB_LAST_MODULE_REQUIRED=1
                    add_warning \
                        "restore $label: legacy manifest без module_state; используется backup /etc/fstab"
                    ;;
                1)
                    log "[i]     restore $label: legacy manifest без backup /etc/fstab — пропуск"
                    return 0
                    ;;
                *)
                    add_error \
                        "restore $label: не удалось проверить legacy backup /etc/fstab"
                    return 1
                    ;;
            esac
            ;;
        *)
            add_error \
                "restore $label: не удалось прочитать typed module_state"
            return 1
            ;;
    esac

    if (( FSTAB_RESTORE_DONE == 1 )); then
        log "[i]     restore $label: /etc/fstab уже восстановлен"
        return 0
    fi

    if ! restore_file_from_manifest "/etc/fstab"; then
        return 1
    fi

    FSTAB_RESTORE_DONE=1
    return 0
}


snapshot_installed_packages() {
    local module="$1"
    local snapshot="$STATE_DIR/packages-before-${module}-${TIMESTAMP}.txt"

    if ! dpkg-query -W \
        -f='${binary:Package}\t${Status}\n' 2>/dev/null |
        awk -F '\t' '$2 == "install ok installed" { print $1 }' |
        LC_ALL=C sort -u > "$snapshot"
    then
        add_error \
            "packages ${module}: не удалось сохранить исходный список пакетов"
        return 1
    fi

    if ! chmod 600 "$snapshot"; then
        add_error \
            "packages ${module}: не удалось защитить исходный snapshot пакетов"
        rm -f -- "$snapshot"
        return 1
    fi

    if ! record_manifest_pending_package_transaction \
        "$module" \
        "$snapshot"
    then
        add_error \
            "packages ${module}: pending transaction не записана в manifest"
        rm -f -- "$snapshot"
        return 1
    fi

    record_manifest_apply_report \
        "package transaction pending ${module}: ${snapshot}"
}

record_newly_installed_packages() {
    local module="$1"
    local snapshot="$STATE_DIR/packages-before-${module}-${TIMESTAMP}.txt"
    local current="$STATE_DIR/packages-after-${module}-${TIMESTAMP}.txt"
    local count=""

    if [[ ! -f "$snapshot" || -L "$snapshot" ]]; then
        add_error \
            "packages ${module}: исходный snapshot пакетов отсутствует или небезопасен"
        return 1
    fi

    if ! dpkg-query -W \
        -f='${binary:Package}\t${Status}\n' 2>/dev/null |
        awk -F '\t' '$2 == "install ok installed" { print $1 }' |
        LC_ALL=C sort -u > "$current"
    then
        add_error \
            "packages ${module}: не удалось получить итоговый список пакетов"
        return 1
    fi

    if ! chmod 600 "$current"; then
        add_error \
            "packages ${module}: не удалось защитить итоговый snapshot пакетов"
        rm -f -- "$current"
        return 1
    fi

    if ! count="$(
        commit_manifest_package_transaction \
            "$module" \
            "$snapshot" \
            "$current"
    )"
    then
        add_error \
            "packages ${module}: не удалось commit package transaction"
        rm -f -- "$current"
        return 1
    fi

    rm -f -- "$current"

    record_manifest_apply_report \
        "packages installed ${module}: count=${count}"
}

PACKAGE_TRANSACTION_INSTALL_RC=0
PACKAGE_TRANSACTION_TRACKING_RC=0

install_packages_transactionally() {
    local module="$1"
    shift

    local package=""
    local -a missing_packages=()

    PACKAGE_TRANSACTION_INSTALL_RC=0
    PACKAGE_TRANSACTION_TRACKING_RC=0

    for package in "$@"; do
        pkg_installed "$package" || \
            missing_packages+=("$package")
    done

    if (( ${#missing_packages[@]} == 0 )); then
        return 0
    fi

    if ! snapshot_installed_packages "$module"; then
        PACKAGE_TRANSACTION_TRACKING_RC=1
        return 1
    fi

    DEBIAN_FRONTEND=noninteractive \
        apt-get install -y -q \
        -o DPkg::Lock::Timeout=300 \
        -o Dpkg::Options::="--force-confold" \
        "${missing_packages[@]}" \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || \
        PACKAGE_TRANSACTION_INSTALL_RC=$?

    record_newly_installed_packages "$module" || \
        PACKAGE_TRANSACTION_TRACKING_RC=$?

    if (( PACKAGE_TRANSACTION_INSTALL_RC != 0 \
        || PACKAGE_TRANSACTION_TRACKING_RC != 0 ))
    then
        return 1
    fi

    return 0
}

collect_manifest_package_candidates() {
    local module="$1"
    local records=""
    local record_type=""
    local value=""
    local current=""
    local package=""
    local snapshot=""
    local -A candidates=()
    local need_current=0

    if ! records="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" "$module"             2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
module = sys.argv[2]
manifest_parent = path.parent.resolve()
package_pattern = re.compile(
    r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?$"
)
data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

installed = data.get("installed_packages", [])
pending = data.get("pending_package_transactions", [])

if not isinstance(installed, list):
    raise ValueError("manifest installed_packages is not an array")
if not isinstance(pending, list):
    raise ValueError(
        "manifest pending_package_transactions is not an array"
    )

for index, item in enumerate(installed):
    if not isinstance(item, dict):
        raise ValueError(
            f"manifest installed_packages[{index}] is not an object"
        )
    item_module = item.get("module")
    package = item.get("package")
    if not isinstance(item_module, str):
        raise ValueError("installed package module is not a string")
    if not isinstance(package, str):
        raise ValueError("installed package name is not a string")
    if item_module == module and package:
        print(f"COMMITTED\t{package}")

for index, item in enumerate(pending):
    if not isinstance(item, dict):
        raise ValueError(
            f"pending_package_transactions[{index}] is not an object"
        )
    item_module = item.get("module")
    snapshot = item.get("snapshot")
    if not isinstance(item_module, str):
        raise ValueError("pending package module is not a string")
    if not isinstance(snapshot, str):
        raise ValueError("pending package snapshot is not a string")
    if item_module != module:
        continue
    snapshot_path = pathlib.Path(snapshot)
    state = snapshot_path.lstat()
    if not stat.S_ISREG(state.st_mode):
        raise ValueError("pending package snapshot is not a regular file")
    print(f"PENDING\t{snapshot}")
PYJSON
    )"
    then
        add_error \
            "restore packages ${module}: не удалось прочитать package journal"
        return 1
    fi

    while IFS=$'\t' read -r record_type value; do
        [[ -n "$record_type" ]] || continue

        case "$record_type" in
            COMMITTED)
                [[ -n "$value" ]] || return 1
                candidates["$value"]=1
                ;;
            PENDING)
                [[ -n "$value" ]] || return 1
                need_current=1
                ;;
            *)
                add_error \
                    "restore packages ${module}: неизвестный тип journal-записи $record_type"
                return 1
                ;;
        esac
    done <<< "$records"

    if (( need_current == 1 )); then
        current="$(mktemp "$STATE_DIR/packages-restore-current-${module}.XXXXXX")" || {
            add_error \
                "restore packages ${module}: не удалось создать временный snapshot"
            return 1
        }

        if ! dpkg-query -W \
            -f='${binary:Package}\t${Status}\n' 2>/dev/null |
            awk -F '\t' '$2 == "install ok installed" { print $1 }' |
            LC_ALL=C sort -u > "$current"
        then
            add_error \
                "restore packages ${module}: не удалось получить текущий список пакетов"
            rm -f -- "$current"
            return 1
        fi

        while IFS=$'\t' read -r record_type value; do
            [[ "$record_type" == "PENDING" ]] || continue
            snapshot="$value"

            while IFS= read -r package; do
                [[ -n "$package" ]] || continue
                candidates["$package"]=1
            done < <(comm -13 "$snapshot" "$current")
        done <<< "$records"

        rm -f -- "$current"
    fi

    for package in "${!candidates[@]}"; do
        printf '%s\n' "$package"
    done | LC_ALL=C sort
}

restore_installed_packages() {
    local module="$1"
    local package=""
    local candidates_output=""
    local -a candidates=()
    local -a installed_packages=()

    if ! candidates_output="$(
        collect_manifest_package_candidates "$module"
    )"
    then
        add_error             "restore packages ${module}: package journal не прочитан"
        return 1
    fi

    if [[ -n "$candidates_output" ]]; then
        mapfile -t candidates <<< "$candidates_output"
    fi

    if (( ${#candidates[@]} == 0 )); then
        log \
            "[i]     restore packages ${module}: новые пакеты не зафиксированы"
        return 0
    fi

    for package in "${candidates[@]}"; do
        if pkg_installed "$package"; then
            installed_packages+=("$package")
        fi
    done

    if (( ${#installed_packages[@]} == 0 )); then
        log \
            "[i]     restore packages ${module}: пакеты уже отсутствуют"
        return 0
    fi

    if DEBIAN_FRONTEND=noninteractive \
        apt-get purge -y -q \
        -o DPkg::Lock::Timeout=300 \
        -o Dpkg::Options::="--force-confold" \
        "${installed_packages[@]}" \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_safe \
            "restore packages ${module}: удалены установленные скриптом пакеты (${#installed_packages[@]})"
        return 0
    fi

    add_warning \
        "restore packages ${module}: не удалось удалить установленные скриптом пакеты (${installed_packages[*]})"

    return 1
}

report_installed_packages_for_manual_restore() {
    local module="$1"
    local label="$2"
    local candidates_output=""
    local package=""
    local -a candidates=()
    local -a installed_packages=()

    if ! candidates_output="$(
        collect_manifest_package_candidates "$module"
    )"
    then
        add_error             "restore ${label}: package journal не прочитан"
        return 1
    fi

    if [[ -n "$candidates_output" ]]; then
        mapfile -t candidates <<< "$candidates_output"
    fi

    for package in "${candidates[@]}"; do
        if pkg_installed "$package"; then
            installed_packages+=("$package")
        fi
    done

    if (( ${#installed_packages[@]} == 0 )); then
        return 0
    fi

    add_warning \
        "restore ${label}: пакеты, впервые установленные apply, не удалены автоматически: ${installed_packages[*]}"

    return 0
}


runtime_paths_scan() {
    python3 - <<'PYJSON'
from pathlib import Path
import os

proc_root = Path(os.environ.get("SECURELINUX_NG_RUNTIME_PROC_ROOT", "/proc"))
read_maps = os.environ.get("SECURELINUX_NG_RUNTIME_PATHS_READ_MAPS", "1") not in {"0", "false", "False", "no", "NO"}
seen = set()

if not proc_root.is_dir():
    raise SystemExit(0)

for proc in proc_root.iterdir():
    if not proc.name.isdigit():
        continue

    exe = proc / "exe"
    try:
        if exe.exists() or exe.is_symlink():
            target = os.path.realpath(exe)
            if target.startswith("/") and os.path.isfile(target):
                seen.add(target)
    except Exception:
        pass

    if not read_maps:
        continue

    maps = proc / "maps"
    try:
        for line in maps.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "/" not in line:
                continue
            path = line.rsplit(None, 1)[-1]
            if path.startswith("/") and os.path.isfile(path):
                seen.add(os.path.realpath(path))
    except Exception:
        pass

for item in sorted(seen):
    print(item)
PYJSON
}

check_runtime_paths_module() {
    python3 - "$RUNTIME_PATHS_SAMPLE_LIMIT" <<'PYJSON'
from pathlib import Path
import os, stat, sys

sample_limit = int(sys.argv[1])
proc_root = Path(os.environ.get("SECURELINUX_NG_RUNTIME_PROC_ROOT", "/proc"))
read_maps = os.environ.get("SECURELINUX_NG_RUNTIME_PATHS_READ_MAPS", "1") not in {"0", "false", "False", "no", "NO"}
paths = []
seen = set()

if proc_root.is_dir():
    for proc in proc_root.iterdir():
        if not proc.name.isdigit():
            continue

        exe = proc / "exe"
        try:
            if exe.exists() or exe.is_symlink():
                target = os.path.realpath(exe)
                if target.startswith("/") and os.path.isfile(target) and target not in seen:
                    seen.add(target)
                    paths.append(target)
        except Exception:
            pass

        if not read_maps:
            continue

        maps = proc / "maps"
        try:
            for line in maps.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "/" not in line:
                    continue
                path = line.rsplit(None, 1)[-1]
                if path.startswith("/") and os.path.isfile(path):
                    path = os.path.realpath(path)
                    if path not in seen:
                        seen.add(path)
                        paths.append(path)
        except Exception:
            pass

ok = 0
risky = 0
samples = []

EXCLUDED_PARENTS = {"/var/log", "/tmp", "/var/tmp", "/run", "/dev/shm"}
for item in sorted(paths):
    try:
        st = os.stat(item)
    except Exception:
        continue

    reasons = []
    if stat.S_IMODE(st.st_mode) & 0o022:
        reasons.append("file_go_w")

    cur = Path(item).parent
    while True:
        if str(cur) in EXCLUDED_PARENTS:
            break
        try:
            dst = os.stat(cur)
            if stat.S_IMODE(dst.st_mode) & 0o022:
                reasons.append(f"parent_go_w:{cur}")
                break
        except Exception:
            reasons.append(f"parent_stat_failed:{cur}")
            break

        if cur == cur.parent:
            break
        cur = cur.parent

    if reasons:
        risky += 1
        if len(samples) < sample_limit:
            samples.append((item, ",".join(reasons)))
    else:
        ok += 1

print(f"SUMMARY\t{len(paths)}\t{ok}\t{risky}")
for item, reason in samples:
    print(f"RISK\t{item}\t{reason}")
PYJSON
}

check_sudo_command_paths_module() {
    python3 - "$SUDO_COMMANDS_SAMPLE_LIMIT" <<'PYJSON'
from pathlib import Path
import os, re, stat, sys

sample_limit = int(sys.argv[1])
EXCLUDED_PARENTS = {"/var/log", "/tmp", "/var/tmp", "/run", "/dev/shm"}
sudo_files = [Path("/etc/sudoers")]
sudoers_d = Path("/etc/sudoers.d")
if sudoers_d.is_dir():
    sudo_files.extend(sorted(p for p in sudoers_d.iterdir() if p.is_file()))

paths = []
seen = set()
token_re = re.compile(r'(/[A-Za-z0-9_./+-]+)')

for cfg in sudo_files:
    try:
        text = cfg.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for m in token_re.findall(s):
            path = os.path.realpath(m)
            if path.startswith("/") and os.path.exists(path) and path not in seen:
                seen.add(path)
                paths.append(path)

ok = 0
risky = 0
samples = []

for item in sorted(paths):
    try:
        st = os.stat(item)
    except Exception:
        continue

    reasons = []
    if os.path.isfile(item) and stat.S_IMODE(st.st_mode) & 0o022:
        reasons.append("file_go_w")

    cur = Path(item).parent
    while True:
        if str(cur) in EXCLUDED_PARENTS:
            break
        try:
            dst = os.stat(cur)
            if stat.S_IMODE(dst.st_mode) & 0o022:
                reasons.append(f"parent_go_w:{cur}")
                break
        except Exception:
            reasons.append(f"parent_stat_failed:{cur}")
            break

        if cur == cur.parent:
            break
        cur = cur.parent

    if reasons:
        risky += 1
        if len(samples) < sample_limit:
            samples.append((item, ",".join(reasons)))
    else:
        ok += 1

print(f"SUMMARY\t{len(paths)}\t{ok}\t{risky}")
for item, reason in samples:
    print(f"RISK\t{item}\t{reason}")
PYJSON
}

apply_runtime_paths_module() {
    local runtime_scan_output=""
    local item reason
    local backup_path=""
    local module_rc=0

    if (( DRY_RUN == 1 )); then
        if ! runtime_scan_output="$(check_runtime_paths_module)"; then
            add_error "2.3.2 dry-run: runtime paths scan завершился с ошибкой"
            return 1
        fi

        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.2 runtime scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.2 would review '$a' reason='$b'"
                    ;;
            esac
        done <<< "$runtime_scan_output"

        add_skipped "2.3.2 dry-run: file permission remediation would be applied; parent directories require manual review"
        return 0
    fi

    if ! runtime_scan_output="$(check_runtime_paths_module)"; then
        add_error "2.3.2 apply: runtime paths scan завершился с ошибкой"
        return 1
    fi

    while IFS=$'\t' read -r kind item reason _; do
        [[ -n "${kind:-}" ]] || continue
        [[ "$kind" == "RISK" ]] || continue
        if [[ "$reason" == *"parent_go_w:"* ]]; then
            add_warning "2.3.2 родительский каталог требует ручной проверки: ${reason#*parent_go_w:}"
        fi
        [[ "$reason" == *"file_go_w"* ]] || continue
        [[ -f "$item" ]] || continue
        backup_path="$STATE_DIR/runtime.$(
            printf '%s' "$item" | tr '/' '_'
        ).meta-$TIMESTAMP.txt"

        if ! write_metadata_snapshot             "$item"             "$backup_path"
        then
            add_error                 "2.3.2 metadata snapshot не создан: $item"
            module_rc=1
            continue
        fi

        if ! record_manifest_backup             "$item"             "$backup_path"
        then
            add_error                 "2.3.2 backup mapping не записан: $item"

            if ! rm -f -- "$backup_path"; then
                add_warning                     "2.3.2 не удалось удалить незарегистрированный snapshot $backup_path"
            fi

            module_rc=1
            continue
        fi

        if chmod go-w "$item"; then
            record_manifest_modified_file_best_effort "$item"
            record_manifest_apply_report                 "2.3.2 chmod go-w: $item"
        else
            add_warning                 "2.3.2 chmod go-w failed: $item"
        fi
    done <<< "$runtime_scan_output"

    if (( module_rc != 0 )); then
        add_warning             "2.3.2 runtime executable/library permissions обработаны с ошибками"
        return 1
    fi

    add_safe         "2.3.2 runtime executable/library permissions processed"
    return 0
}

record_sudo_command_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.4 sudo command paths checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.4 sudo command paths checked: total=$total ok=$ok risky=$risky"
    fi
}

sysctl_kernel_check_module() {
    python3 - <<'PYJSON'
import subprocess

targets = {
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "2",
    "net.core.bpf_jit_harden": "2",
}

ok = 0
risky = 0
for key, expected in targets.items():
    try:
        res = subprocess.run(
            ["sysctl", "-n", key],
            text=True,
            capture_output=True,
            check=False,
        )
        if res.returncode != 0:
            err = (res.stderr or "").strip() or f"exit={res.returncode}"
            print(f"RISK\t{key}\tread_failed:{err}")
            risky += 1
            continue
        value = (res.stdout or "").strip()
    except Exception as e:
        print(f"RISK\t{key}\tread_failed:{e}")
        risky += 1
        continue

    if value == expected:
        ok += 1
    else:
        risky += 1
        print(f"RISK\t{key}\texpected={expected},actual={value}")

print(f"SUMMARY\t{len(targets)}\t{ok}\t{risky}")
PYJSON
}

record_sysctl_kernel_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.4 sysctl kernel protections checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.4 sysctl kernel protections checked: total=$total ok=$ok risky=$risky"
    fi
}

grub_kernel_params_check_module() {
    local profile_arg="${1:-baseline}"
    python3 - "$profile_arg" <<'PYJSON'
import sys
from pathlib import Path

profile = sys.argv[1] if len(sys.argv) > 1 else "baseline"

required = [
    "init_on_alloc=1",
    "slab_nomerge",
    "iommu=force",
    "iommu.strict=1",
    "iommu.passthrough=0",
    "randomize_kstack_offset=1",
    "mitigations=auto,nosmt",
    "vsyscall=none",
    "debugfs=off",
    "tsx=off",
]

if profile in ("strict", "paranoid"):
    required += ["apparmor=1", "security=apparmor"]

cmdline = Path("/proc/cmdline").read_text(encoding="utf-8", errors="ignore").strip()
tokens = cmdline.split()

ok = 0
risky = 0
for item in required:
    if item in tokens:
        ok += 1
    else:
        risky += 1
        print(f"RISK\t{item}\tmissing_in_proc_cmdline (requires_reboot)")

print(f"SUMMARY\t{len(required)}\t{ok}\t{risky}")
PYJSON
}

record_grub_kernel_params_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.4 grub kernel params checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.4 grub kernel params checked: total=$total ok=$ok risky=$risky (параметры вступят в силу после перезагрузки)"
    fi
}

sysctl_attack_surface_check_module() {
    local profile_arg="${1:-baseline}"
    python3 - "$profile_arg" "$USER_NAMESPACES_LIMIT" <<'PYJSON'
import subprocess, sys
profile = sys.argv[1] if len(sys.argv) > 1 else "baseline"
profile_order = {"baseline": 0, "strict": 1, "paranoid": 2}
profile_level = profile_order.get(profile, 0)

targets_all = {
    "kernel.perf_event_paranoid": ("3", "baseline"),  # ФСТЭК 2.5.2 — все профили
    "kernel.kexec_load_disabled": ("1", "baseline"),
    "kernel.unprivileged_bpf_disabled": ("1", "baseline"),  # ФСТЭК 2.5.6 — все профили
    "vm.unprivileged_userfaultfd": ("0", "baseline"),
    "dev.tty.ldisc_autoload": ("0", "baseline"),
    "vm.mmap_min_addr": ("4096", "baseline"),
    "kernel.randomize_va_space": ("2", "baseline"),
    "user.max_user_namespaces": ("0", "baseline"),
}
_ns_limit = sys.argv[2].strip() if len(sys.argv) > 2 else ""
if _ns_limit == "":
    try:
        current_ns = subprocess.check_output(
            ["sysctl", "-n", "user.max_user_namespaces"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        current_ns = ""
    if current_ns in {"0", "10000"}:
        targets_all["user.max_user_namespaces"] = (current_ns, "baseline")
    else:
        targets_all["user.max_user_namespaces"] = ("0", "baseline")
else:
    targets_all["user.max_user_namespaces"] = (_ns_limit, "baseline")
targets = {k: v[0] for k, v in targets_all.items() if profile_order.get(v[1], 0) <= profile_level}

ok = 0
risky = 0
for key, expected in targets.items():
    try:
        res = subprocess.run(
            ["sysctl", "-n", key],
            text=True,
            capture_output=True,
            check=False,
        )
        if res.returncode != 0:
            err = (res.stderr or "").strip() or f"exit={res.returncode}"
            print(f"RISK\t{key}\tread_failed:{err}")
            risky += 1
            continue
        value = (res.stdout or "").strip()
    except Exception as e:
        print(f"RISK\t{key}\tread_failed:{e}")
        risky += 1
        continue

    if key in (
        "kernel.perf_event_paranoid",
        "vm.mmap_min_addr",
        "kernel.unprivileged_bpf_disabled",
    ):
        try:
            if int(value) >= int(expected):
                ok += 1
            else:
                risky += 1
                print(f"RISK\t{key}\texpected>={expected},actual={value}")
        except Exception:
            risky += 1
            print(f"RISK\t{key}\tbad_value:{value}")
        continue

    if value == expected:
        ok += 1
    else:
        risky += 1
        print(f"RISK\t{key}\texpected={expected},actual={value}")

print(f"SUMMARY\t{len(targets)}\t{ok}\t{risky}")
PYJSON
}

record_sysctl_attack_surface_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.5 sysctl attack-surface protections checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.5 sysctl attack-surface protections checked: total=$total ok=$ok risky=$risky"
    fi
}

sysctl_userspace_protection_check_module() {
    local profile_arg="${1:-baseline}"
    python3 - "$profile_arg" <<'PYJSON'
import subprocess, sys
profile = sys.argv[1] if len(sys.argv) > 1 else "baseline"
profile_order = {"baseline": 0, "strict": 1, "paranoid": 2}
profile_level = profile_order.get(profile, 0)

import os
targets_all_base = {
    "fs.protected_symlinks": ("1", "baseline"),
    "fs.protected_hardlinks": ("1", "baseline"),
    "fs.protected_fifos": ("2", "baseline"),
    "fs.protected_regular": ("2", "baseline"),
    "fs.suid_dumpable": ("0", "baseline"),
}
if os.path.exists("/proc/sys/kernel/yama/ptrace_scope"):
    targets_all_base["kernel.yama.ptrace_scope"] = ("3", "baseline")  # ФСТЭК 2.6.1
targets = {k: v[0] for k, v in targets_all_base.items() if profile_order.get(v[1], 0) <= profile_level}

ok = 0
risky = 0
for key, expected in targets.items():
    try:
        res = subprocess.run(
            ["sysctl", "-n", key],
            text=True,
            capture_output=True,
            check=False,
        )
        if res.returncode != 0:
            err = (res.stderr or "").strip() or f"exit={res.returncode}"
            print(f"RISK\t{key}\tread_failed:{err}")
            risky += 1
            continue
        value = (res.stdout or "").strip()
    except Exception as e:
        print(f"RISK\t{key}\tread_failed:{e}")
        risky += 1
        continue

    if value == expected:
        ok += 1
    else:
        risky += 1
        print(f"RISK\t{key}\texpected={expected},actual={value}")

print(f"SUMMARY\t{len(targets)}\t{ok}\t{risky}")
PYJSON
}

record_sysctl_userspace_protection_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.6 sysctl userspace protections checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.6 sysctl userspace protections checked: total=$total ok=$ok risky=$risky"
    fi
}

home_targets_scan() {
    python3 - <<'PYJSON'
from pathlib import Path
import os
home = Path(os.environ.get("SECURELINUX_NG_HOME_BASE_DIR", "/home"))
if not home.is_dir():
    raise SystemExit(0)
for p in sorted(home.iterdir()):
    if p.is_dir() and not p.is_symlink():
        print(p)
PYJSON
}

check_home_permissions_module() {
    python3 - <<'PYJSON'
from pathlib import Path
import os, stat

sensitive = {
    ".bash_history",
    ".history",
    ".sh_history",
    ".bash_profile",
    ".bashrc",
    ".profile",
    ".bash_logout",
    ".rhosts",
}

home = Path(os.environ.get("SECURELINUX_NG_HOME_BASE_DIR", "/home"))
if not home.is_dir():
    print("SUMMARY\t0\t0\t0")
    raise SystemExit(0)

ok = 0
risky = 0

for d in sorted(home.iterdir()):
    if not d.is_dir() or d.is_symlink():
        continue

    try:
        mode = stat.S_IMODE(os.stat(d).st_mode)
        if mode == 0o700:
            ok += 1
        else:
            risky += 1
            print(f"RISK\t{d}\thome_mode_expected=700,actual={mode:o}")
    except Exception as e:
        risky += 1
        print(f"RISK\t{d}\thome_stat_failed:{e}")

    for name in sensitive:
        f = d / name
        if not f.exists() or not f.is_file():
            continue
        try:
            mode = stat.S_IMODE(os.stat(f).st_mode)
            if mode & 0o077:
                risky += 1
                print(f"RISK\t{f}\tfile_go_perms_present:{mode:o}")
            else:
                ok += 1
        except Exception as e:
            risky += 1
            print(f"RISK\t{f}\tfile_stat_failed:{e}")

print(f"SUMMARY\t{ok + risky}\t{ok}\t{risky}")
PYJSON
}

record_home_permissions_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.10/2.3.11 home permissions checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.10/2.3.11 home permissions checked: total=$total ok=$ok risky=$risky"
    fi
}

check_user_cron_permissions_module() {
    python3 - <<'PYJSON'
from pathlib import Path
import os, stat

roots = [Path(p) for p in os.environ.get("SECURELINUX_NG_USER_CRON_DIRS", "/var/spool/cron:/var/spool/cron/crontabs").split(":") if p]
files = []
seen = set()

for root in roots:
    if not root.is_dir():
        continue
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            rp = str(p.resolve())
            if rp not in seen:
                seen.add(rp)
                files.append(Path(rp))

ok = 0
risky = 0
for f in sorted(files):
    try:
        mode = stat.S_IMODE(os.stat(f).st_mode)
        if mode & 0o022:
            risky += 1
            print(f"RISK\t{f}\tcron_user_file_go_w:{mode:o}")
        else:
            ok += 1
    except Exception as e:
        risky += 1
        print(f"RISK\t{f}\tcron_user_file_stat_failed:{e}")

print(f"SUMMARY\t{ok + risky}\t{ok}\t{risky}")
PYJSON
}

record_user_cron_permissions_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.7 user cron permissions checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.7 user cron permissions checked: total=$total ok=$ok risky=$risky"
    fi
}

check_cron_command_paths_module() {
    python3 - "$RUNTIME_PATHS_SAMPLE_LIMIT" <<'PYJSON'
from pathlib import Path
import os, re, stat, sys

EXCLUDED_PARENTS = {"/var/log", "/tmp", "/var/tmp", "/run", "/dev/shm"}

cron_files = []
base = Path("/etc/crontab")
if base.is_file():
    cron_files.append(base)
cron_d = Path("/etc/cron.d")
if cron_d.is_dir():
    cron_files.extend(sorted(p for p in cron_d.iterdir() if p.is_file()))

seen = set()
paths = []
token_re = re.compile(r'(/[A-Za-z0-9_./+:-]+)')

for cfg in cron_files:
    try:
        text = cfg.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for m in token_re.findall(s):
            rp = os.path.realpath(m)
            if rp.startswith("/") and os.path.exists(rp) and rp not in seen:
                seen.add(rp)
                paths.append(rp)

ok = 0
risky = 0
samples = []
sample_limit = int(sys.argv[1])

for item in sorted(paths):
    try:
        st = os.stat(item)
    except Exception:
        continue

    reasons = []
    if os.path.isfile(item) and stat.S_IMODE(st.st_mode) & 0o022:
        reasons.append("file_go_w")

    cur = Path(item).parent
    while True:
        if str(cur) in EXCLUDED_PARENTS:
            break
        try:
            dst = os.stat(cur)
            if stat.S_IMODE(dst.st_mode) & 0o022:
                reasons.append(f"parent_go_w:{cur}")
                break
        except Exception as e:
            reasons.append(f"parent_stat_failed:{cur}:{e}")
            break

        if cur == cur.parent:
            break
        cur = cur.parent

    if reasons:
        risky += 1
        if len(samples) < sample_limit:
            samples.append((item, ",".join(reasons)))
    else:
        ok += 1

print(f"SUMMARY\t{len(paths)}\t{ok}\t{risky}")
for item, reason in samples:
    print(f"RISK\t{item}\t{reason}")
PYJSON
}

record_cron_command_paths_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.3 cron command paths checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.3 cron command paths checked: total=$total ok=$ok risky=$risky"
    fi
}

apply_cron_command_paths_module() {
    local cron_scan_output=""
    local item reason
    local backup_path=""
    local module_rc=0

    if (( DRY_RUN == 1 )); then
        if ! cron_scan_output="$(check_cron_command_paths_module)"; then
            add_error "2.3.3 dry-run: cron command paths scan завершился с ошибкой"
            return 1
        fi

        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.3 cron-command-paths scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.3 would review '$a' reason='$b'"
                    ;;
            esac
        done <<< "$cron_scan_output"

        add_skipped "2.3.3 dry-run: file permission remediation would be applied; parent directories require manual review"
        return 0
    fi

    if ! cron_scan_output="$(check_cron_command_paths_module)"; then
        add_error "2.3.3 apply: cron command paths scan завершился с ошибкой"
        return 1
    fi

    while IFS=$'\t' read -r kind item reason _; do
        [[ -n "${kind:-}" ]] || continue
        [[ "$kind" == "RISK" ]] || continue
        if [[ "$reason" == *"parent_go_w:"* ]]; then
            add_warning "2.3.3 родительский каталог требует ручной проверки: ${reason#*parent_go_w:}"
        fi
        [[ "$reason" == *"file_go_w"* ]] || continue
        [[ -f "$item" ]] || continue
        backup_path="$STATE_DIR/cron_cmd.$(
            printf '%s' "$item" | tr '/' '_'
        ).meta-$TIMESTAMP.txt"

        if ! write_metadata_snapshot             "$item"             "$backup_path"
        then
            add_error                 "2.3.3 metadata snapshot не создан: $item"
            module_rc=1
            continue
        fi

        if ! record_manifest_backup             "$item"             "$backup_path"
        then
            add_error                 "2.3.3 backup mapping не записан: $item"

            if ! rm -f -- "$backup_path"; then
                add_warning                     "2.3.3 не удалось удалить незарегистрированный snapshot $backup_path"
            fi

            module_rc=1
            continue
        fi

        if chmod go-w "$item"; then
            record_manifest_modified_file_best_effort "$item"
            record_manifest_apply_report                 "2.3.3 chmod go-w: $item"
        else
            add_warning                 "2.3.3 chmod go-w failed: $item"
        fi
    done <<< "$cron_scan_output"

    if (( module_rc != 0 )); then
        add_warning             "2.3.3 cron command paths permissions обработаны с ошибками"
        return 1
    fi

    add_safe         "2.3.3 cron command paths permissions processed"
    return 0
}

check_standard_system_paths_module() {
    python3 - "$RUNTIME_PATHS_SAMPLE_LIMIT" <<'PYJSON'
from pathlib import Path
import os, stat, subprocess, sys

paths = set(p for p in os.environ.get(
    "SECURELINUX_NG_STANDARD_SYSTEM_PATHS",
    "/bin:/sbin:/usr/bin:/usr/sbin:/lib:/lib64:/usr/lib:/usr/lib64",
).split(":") if p)

if os.environ.get("SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_ENV_PATH", "1") not in {"0", "false", "False", "no", "NO"}:
    for item in os.environ.get("PATH", "").split(":"):
        if item.startswith("/"):
            paths.add(item)

if os.environ.get("SECURELINUX_NG_STANDARD_SYSTEM_PATH_INCLUDE_KERNEL_MODULES", "1") not in {"0", "false", "False", "no", "NO"}:
    uname_r = subprocess.run(["uname", "-r"], text=True, capture_output=True, check=False).stdout.strip()
    if uname_r:
        paths.add(f"/lib/modules/{uname_r}")

seen = set()
for base in sorted(paths):
    p = Path(base)
    if not p.exists():
        continue
    if p.is_file():
        items = [p]
    else:
        items = [x for x in p.rglob("*") if x.is_file() and not x.is_symlink()]
    for item in items:
        rp = str(item.resolve())
        if rp not in seen:
            seen.add(rp)

ok = 0
risky = 0
sample_limit = int(sys.argv[1])
samples = []

for item in sorted(seen):
    try:
        st = os.stat(item)
    except Exception:
        continue

    reasons = []
    if stat.S_IMODE(st.st_mode) & 0o022:
        reasons.append("file_go_w")

    cur = Path(item).parent
    while True:
        try:
            dst = os.stat(cur)
            if stat.S_IMODE(dst.st_mode) & 0o022:
                reasons.append(f"parent_go_w:{cur}")
                break
        except Exception as e:
            reasons.append(f"parent_stat_failed:{cur}:{e}")
            break
        if cur == cur.parent:
            break
        cur = cur.parent

    if reasons:
        risky += 1
        if len(samples) < sample_limit:
            samples.append((item, ",".join(reasons)))
    else:
        ok += 1

print(f"SUMMARY\t{ok + risky}\t{ok}\t{risky}")
for item, reason in samples:
    print(f"RISK\t{item}\t{reason}")
PYJSON
}

record_standard_system_paths_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.8 standard system paths checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.8 standard system paths checked: total=$total ok=$ok risky=$risky"
    fi
}

apply_standard_system_paths_module() {
    local standard_paths_scan_output=""
    local item reason
    local backup_path=""
    local module_rc=0

    if (( DRY_RUN == 1 )); then
        if ! standard_paths_scan_output="$(check_standard_system_paths_module)"; then
            add_error "2.3.8 dry-run: standard system paths scan завершился с ошибкой"
            return 1
        fi

        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.8 standard-system-paths scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.8 would review '$a' reason='$b'"
                    ;;
            esac
        done <<< "$standard_paths_scan_output"

        add_skipped "2.3.8 dry-run: file permission remediation would be applied; parent directories require manual review"
        return 0
    fi

    if ! standard_paths_scan_output="$(check_standard_system_paths_module)"; then
        add_error "2.3.8 apply: standard system paths scan завершился с ошибкой"
        return 1
    fi

    while IFS=$'\t' read -r kind item reason _; do
        [[ -n "${kind:-}" ]] || continue
        [[ "$kind" == "RISK" ]] || continue
        if [[ "$reason" == *"parent_go_w:"* ]]; then
            add_warning "2.3.8 родительский каталог требует ручной проверки: ${reason#*parent_go_w:}"
        fi
        [[ "$reason" == *"file_go_w"* ]] || continue
        [[ -f "$item" ]] || continue
        backup_path="$STATE_DIR/syspath.$(
            printf '%s' "$item" | tr '/' '_'
        ).meta-$TIMESTAMP.txt"

        if ! write_metadata_snapshot             "$item"             "$backup_path"
        then
            add_error                 "2.3.8 metadata snapshot не создан: $item"
            module_rc=1
            continue
        fi

        if ! record_manifest_backup             "$item"             "$backup_path"
        then
            add_error                 "2.3.8 backup mapping не записан: $item"

            if ! rm -f -- "$backup_path"; then
                add_warning                     "2.3.8 не удалось удалить незарегистрированный snapshot $backup_path"
            fi

            module_rc=1
            continue
        fi

        if chmod go-w "$item"; then
            record_manifest_modified_file_best_effort "$item"
            record_manifest_apply_report                 "2.3.8 chmod go-w: $item"
        else
            add_warning                 "2.3.8 chmod go-w failed: $item"
        fi
    done <<< "$standard_paths_scan_output"

    if (( module_rc != 0 )); then
        add_warning             "2.3.8 standard system paths permissions обработаны с ошибками"
        return 1
    fi

    add_safe         "2.3.8 standard system paths permissions processed"
    return 0
}

check_suid_sgid_module() {
    python3 - "$RUNTIME_PATHS_SAMPLE_LIMIT" <<'PYJSON'
from pathlib import Path
import os, stat, sys

roots = [Path(p) for p in os.environ.get(
    "SECURELINUX_NG_SUID_SGID_PATHS",
    "/bin:/sbin:/usr/bin:/usr/sbin:/lib:/lib64:/usr/lib:/usr/lib64",
).split(":") if p]
seen = set()
files = []

for root in roots:
    if not root.exists():
        continue
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            rp = str(p.resolve())
            if rp not in seen:
                seen.add(rp)
                files.append(Path(rp))

ok = 0
risky = 0
sample_limit = int(sys.argv[1])
samples = []

for f in sorted(files):
    try:
        st = os.stat(f)
    except Exception:
        continue

    mode = stat.S_IMODE(st.st_mode)
    if not (mode & 0o4000 or mode & 0o2000):
        continue

    reasons = []
    if mode & 0o022:
        reasons.append(f"suid_sgid_go_w:{mode:o}")
    if (mode & 0o4000) and st.st_uid != 0:
        reasons.append(f"suid_non_root_owner:{st.st_uid}")

    if reasons:
        risky += 1
        if len(samples) < sample_limit:
            samples.append((str(f), ",".join(reasons)))
    else:
        ok += 1

print(f"SUMMARY\t{ok + risky}\t{ok}\t{risky}")
for item, reason in samples:
    print(f"RISK\t{item}\t{reason}")
PYJSON
}

record_suid_sgid_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.9 suid/sgid audit checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.9 suid/sgid audit checked: total=$total ok=$ok risky=$risky"
    fi
}

apply_suid_sgid_module() {
    local suid_sgid_scan_output=""
    local item reason changed
    local backup_path=""
    local module_rc=0

    if (( DRY_RUN == 1 )); then
        if ! suid_sgid_scan_output="$(check_suid_sgid_module)"; then
            add_error "2.3.9 dry-run: SUID/SGID scan завершился с ошибкой"
            return 1
        fi

        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.9 suid-sgid scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.9 would review '$a' reason='$b'"
                    ;;
            esac
        done <<< "$suid_sgid_scan_output"

        add_skipped "2.3.9 dry-run: risky file owner/permission remediation would be applied"
        return 0
    fi

    if ! suid_sgid_scan_output="$(check_suid_sgid_module)"; then
        add_error "2.3.9 apply: SUID/SGID scan завершился с ошибкой"
        return 1
    fi

    while IFS=$'\t' read -r kind item reason _; do
        [[ -n "${kind:-}" ]] || continue
        [[ "$kind" == "RISK" ]] || continue
        [[ -f "$item" ]] || continue
        backup_path="$STATE_DIR/suid.$(
            printf '%s' "$item" | tr '/' '_'
        ).meta-$TIMESTAMP.txt"

        if ! write_metadata_snapshot             "$item"             "$backup_path"
        then
            add_error                 "2.3.9 metadata snapshot не создан: $item"
            module_rc=1
            continue
        fi

        if ! record_manifest_backup             "$item"             "$backup_path"
        then
            add_error                 "2.3.9 backup mapping не записан: $item"

            if ! rm -f -- "$backup_path"; then
                add_warning                     "2.3.9 не удалось удалить незарегистрированный snapshot $backup_path"
            fi

            module_rc=1
            continue
        fi

        changed=0
        if [[ "$reason" == *"suid_non_root_owner"* ]]; then
            if chown root "$item"; then
                record_manifest_apply_report "2.3.9 chown root: $item"
                changed=1
            else
                add_warning "2.3.9 chown root failed: $item"
            fi
        fi
        if [[ "$reason" == *"go_w"* ]]; then
            if chmod go-w "$item"; then
                record_manifest_apply_report "2.3.9 chmod go-w: $item"
                changed=1
            else
                add_warning "2.3.9 chmod go-w failed: $item"
            fi
        fi
        if (( changed == 1 )); then
            record_manifest_modified_file_best_effort "$item"
        fi
    done <<< "$suid_sgid_scan_output"

    if (( module_rc != 0 )); then
        add_warning             "2.3.9 SUID/SGID audit обработан с ошибками snapshot/manifest"
        return 1
    fi

    add_safe         "2.3.9 SUID/SGID audit processed"
    return 0
}

apply_user_cron_permissions_module() {
    local file backup_path
    local user_cron_scan_output=""
    local user_cron_files_output=""
    local module_rc=0

    if (( DRY_RUN == 1 )); then
        if ! user_cron_scan_output="$(check_user_cron_permissions_module)"; then
            add_error "2.3.7 dry-run: user cron permissions scan завершился с ошибкой"
            return 1
        fi

        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.7 user-cron scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.7 would review '$a' reason='$b'"
                    ;;
            esac
        done <<< "$user_cron_scan_output"

        add_skipped "2.3.7 dry-run: user cron permissions would be corrected"
        return 0
    fi

    if ! user_cron_files_output="$(
        python3 - <<'PYJSON'
from pathlib import Path
import os
seen = set()
for root in [Path(p) for p in os.environ.get("SECURELINUX_NG_USER_CRON_DIRS", "/var/spool/cron:/var/spool/cron/crontabs").split(":") if p]:
    if not root.is_dir():
        continue
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink():
            rp = str(p.resolve())
            if rp not in seen:
                seen.add(rp)
                print(rp)
PYJSON
    )"; then
        add_error "2.3.7 apply: не удалось получить список файлов пользовательского cron"
        return 1
    fi

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        [[ -f "$file" ]] || continue
        # Проверяем, нужна ли коррекция (go-w)
        local _cron_mode
        _cron_mode="$(stat -c '%a' "$file" 2>/dev/null)" || continue
        if (( (8#$_cron_mode & 8#022) == 0 )); then
            continue  # права уже корректны
        fi
        backup_path="$STATE_DIR/cronuser.$(
            basename "$file"
        ).meta-$TIMESTAMP.txt"

        if ! write_metadata_snapshot             "$file"             "$backup_path"
        then
            add_error                 "2.3.7 metadata snapshot не создан: $file"
            module_rc=1
            continue
        fi

        if ! record_manifest_backup             "$file"             "$backup_path"
        then
            add_error                 "2.3.7 backup mapping не записан: $file"

            if ! rm -f -- "$backup_path"; then
                add_warning                     "2.3.7 не удалось удалить незарегистрированный snapshot $backup_path"
            fi

            module_rc=1
            continue
        fi

        if chmod go-w "$file"; then
            record_manifest_modified_file_best_effort "$file"
            record_manifest_apply_report                 "2.3.7 corrected user cron file mode: $file"
        else
            add_warning                 "2.3.7 chmod go-w failed: $file"
        fi
    done <<< "$user_cron_files_output"

    if (( module_rc != 0 )); then
        add_warning             "2.3.7 user cron permissions обработаны с ошибками snapshot/manifest"
        return 1
    fi

    add_safe         "2.3.7 user cron permissions processed"
    return 0
}

apply_home_permissions_module() {
    local home_dir file backup_path
    local home_permissions_scan_output=""
    local home_targets_output=""
    local module_rc=0

    if (( DRY_RUN == 1 )); then
        if ! home_permissions_scan_output="$(check_home_permissions_module)"; then
            add_error "2.3.10/2.3.11 dry-run: home permissions scan завершился с ошибкой"
            return 1
        fi

        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.10/2.3.11 home-perms scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.10/2.3.11 would review '$a' reason='$b'"
                    ;;
            esac
        done <<< "$home_permissions_scan_output"

        add_skipped "2.3.10/2.3.11 dry-run: home permissions would be corrected"
        return 0
    fi

    if ! home_targets_output="$(home_targets_scan)"; then
        add_error "2.3.10/2.3.11 apply: не удалось получить список домашних каталогов"
        return 1
    fi

    while IFS= read -r home_dir; do
        [[ -n "$home_dir" ]] || continue
        if [[ -d "$home_dir" ]]; then
            backup_path="$STATE_DIR/$(
                basename "$home_dir"
            ).home.meta-$TIMESTAMP.txt"

            if ! write_metadata_snapshot                 "$home_dir"                 "$backup_path"
            then
                add_error                     "2.3.11 metadata snapshot не создан: $home_dir"
                module_rc=1
            elif ! record_manifest_backup                 "$home_dir"                 "$backup_path"
            then
                add_error                     "2.3.11 backup mapping не записан: $home_dir"

                if ! rm -f -- "$backup_path"; then
                    add_warning                         "2.3.11 не удалось удалить незарегистрированный snapshot $backup_path"
                fi

                module_rc=1
            elif chmod 700 "$home_dir"; then
                record_manifest_modified_file_best_effort "$home_dir"
                record_manifest_apply_report "2.3.11 corrected home dir mode: $home_dir"
            else
                add_warning "2.3.11 chmod 700 failed: $home_dir"
            fi
        fi

        for file_name in "${HOME_SENSITIVE_FILE_NAMES[@]}"; do
            file="$home_dir/$file_name"
            [[ -f "$file" ]] || continue
            backup_path="$STATE_DIR/$(
                basename "$home_dir"
            ).$(
                basename "$file"
            ).meta-$TIMESTAMP.txt"

            if ! write_metadata_snapshot                 "$file"                 "$backup_path"
            then
                add_error                     "2.3.10 metadata snapshot не создан: $file"
                module_rc=1
                continue
            fi

            if ! record_manifest_backup                 "$file"                 "$backup_path"
            then
                add_error                     "2.3.10 backup mapping не записан: $file"

                if ! rm -f -- "$backup_path"; then
                    add_warning                         "2.3.10 не удалось удалить незарегистрированный snapshot $backup_path"
                fi

                module_rc=1
                continue
            fi

            if chmod go-rwx "$file"; then
                record_manifest_modified_file_best_effort "$file"
                record_manifest_apply_report "2.3.10 corrected sensitive file mode: $file"
            else
                add_warning "2.3.10 chmod go-rwx failed: $file"
            fi
        done
    done <<< "$home_targets_output"

    if (( module_rc != 0 )); then
        add_warning             "2.3.10/2.3.11 home permissions обработаны с ошибками snapshot/manifest"
        return 1
    fi

    add_safe         "2.3.10/2.3.11 home permissions processed"
    return 0
}


preserve_stricter_sysctl_values() {
    local content="$1"

    python3 - "$content" <<'PYJSON'
import re
import subprocess
import sys

content = sys.argv[1]

keys = (
    "kernel.perf_event_paranoid",
    "kernel.unprivileged_bpf_disabled",
    "vm.mmap_min_addr",
)

for key in keys:
    pattern = re.compile(
        rf"(?m)^([ \t]*{re.escape(key)}[ \t]*=[ \t]*)([0-9]+)([ \t]*(?:#.*)?)$"
    )
    match = pattern.search(content)

    if not match:
        continue

    target = int(match.group(2))

    result = subprocess.run(
        ["sysctl", "-n", key],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    if result.returncode != 0:
        continue

    try:
        current = int(result.stdout.strip())
    except ValueError:
        continue

    if current <= target:
        continue

    content = pattern.sub(
        lambda found: (
            found.group(1)
            + str(current)
            + found.group(3)
        ),
        content,
        count=1,
    )

print(content, end="")
PYJSON
}

record_sysctl_runtime_snapshot() {
    local module="$1"
    local content="$2"
    local snapshot="$STATE_DIR/sysctl-runtime-${module}-${TIMESTAMP}.json"
    local snapshot_rc=0

    if [[ -z "${MANIFEST_FILE:-}" \
        || ! -f "${MANIFEST_FILE:-}" ]]
    then
        add_error \
            "sysctl ${module}: manifest недоступен для записи runtime snapshot"
        return 1
    fi

    python3 - "$snapshot" "$content" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON' || snapshot_rc=$?
import json
import os
import pathlib
import subprocess
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
content = sys.argv[2]

keys = []

for raw in content.splitlines():
    line = raw.strip()

    if not line or line.startswith("#") or "=" not in line:
        continue

    key = line.split("=", 1)[0].strip()

    if key and key not in keys:
        keys.append(key)

values = []
missing = []

for key in keys:
    result = subprocess.run(
        ["sysctl", "-n", key],
        text=True,
        capture_output=True,
        check=False,
    )

    if result.returncode == 0:
        values.append(
            {
                "key": key,
                "value": result.stdout.rstrip("\n"),
            }
        )
    else:
        missing.append(
            {
                "key": key,
                "error": (result.stderr or "").strip()
                or f"exit={result.returncode}",
            }
        )

data = {
    "values": values,
    "missing": missing,
}

path.parent.mkdir(parents=True, exist_ok=True)

fd, tmp_name = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".sysctl-runtime.",
)

try:
    payload = (
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    os.write(fd, payload)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(tmp_name, path)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        os.unlink(tmp_name)
    except OSError:
        pass

    raise

raise SystemExit(2 if missing else 0)
PYJSON

    if (( snapshot_rc != 0 )); then
        if (( snapshot_rc == 2 )); then
            add_error \
                "sysctl ${module}: runtime snapshot неполон; apply остановлен"
        else
            add_error \
                "sysctl ${module}: не удалось создать runtime snapshot; apply остановлен"
        fi

        record_manifest_warning \
            "sysctl ${module}: runtime snapshot failed rc=${snapshot_rc}" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        if [[ -e "$snapshot" || -L "$snapshot" ]] \
           && ! rm -f -- "$snapshot"
        then
            add_warning \
                "sysctl ${module}: не удалось удалить непригодный snapshot $snapshot"
        fi

        return 1
    fi

    if [[ ! -f "$snapshot" ]]; then
        add_error \
            "sysctl ${module}: snapshot не создан после успешной команды"
        return 1
    fi

    if ! record_manifest_apply_report \
        "sysctl runtime snapshot ${module}: ${snapshot}" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}"
    then
        add_error \
            "sysctl ${module}: snapshot создан, но не записан в manifest"

        record_manifest_warning \
            "sysctl ${module}: runtime snapshot manifest record failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        if ! rm -f -- "$snapshot"; then
            add_warning \
                "sysctl ${module}: не удалось удалить незарегистрированный snapshot $snapshot"
        fi

        return 1
    fi

    return 0
}

restore_sysctl_runtime_snapshot() {
    local module="$1"
    local fallback_file="$2"
    local snapshot_output=""
    local snapshot_state=""
    local snapshot=""
    local snapshot_recorded=0
    local restore_rc=0

    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        add_error \
            "restore sysctl ${module}: source manifest недоступен"
        return 1
    fi

    if ! snapshot_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" "$module" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
module = sys.argv[2]
prefix = f"sysctl runtime snapshot {module}: "

try:
    data = json.loads(
        manifest.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    apply_report = data.get("apply_report", [])

    if not isinstance(apply_report, list):
        raise ValueError("manifest apply_report is not an array")

    for entry in apply_report:
        if not isinstance(entry, str):
            raise ValueError(
                "manifest apply_report entry is not a string"
            )

    matches = [
        entry[len(prefix):]
        for entry in apply_report
        if entry.startswith(prefix)
    ]

    if len(matches) > 1:
        raise ValueError(
            f"multiple runtime snapshots recorded for {module}"
        )

    if not matches:
        print("0")
    else:
        snapshot = matches[0]

        if not snapshot:
            raise ValueError("recorded snapshot path is empty")

        if "\n" in snapshot or "\r" in snapshot:
            raise ValueError(
                "recorded snapshot path contains a line break"
            )

        print("1")
        print(snapshot)
except Exception as exc:
    print(
        f"restore sysctl manifest read failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)
PYJSON
    )"; then
        add_error \
            "restore sysctl ${module}: не удалось прочитать runtime snapshot из manifest"
        return 1
    fi

    snapshot_state="$snapshot_output"

    if [[ "$snapshot_output" == *$'\n'* ]]; then
        snapshot_state="${snapshot_output%%$'\n'*}"
    fi

    case "$snapshot_state" in
        0)
            ;;
        1)
            snapshot_recorded=1
            snapshot="${snapshot_output#*$'\n'}"
            ;;
        *)
            add_error \
                "restore sysctl ${module}: некорректный результат поиска runtime snapshot"
            return 1
            ;;
    esac

    if (( snapshot_recorded == 1 )); then
        if [[ ! -f "$snapshot" ]]; then
            if [[ -f "$fallback_file" ]] \
               && sysctl -p "$fallback_file" \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                add_warning \
                    "restore sysctl ${module}: записанный snapshot отсутствует; применён fallback $fallback_file"
            else
                add_warning \
                    "restore sysctl ${module}: записанный snapshot отсутствует и fallback недоступен"
            fi

            return 1
        fi

        python3 - "$snapshot" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON' || restore_rc=$?
import json
import pathlib
import subprocess
import sys

snapshot = pathlib.Path(sys.argv[1])

try:
    data = json.loads(
        snapshot.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError("snapshot root is not an object")

    values = data.get("values", [])
    missing = data.get("missing", [])

    if not isinstance(values, list):
        raise ValueError("snapshot values is not an array")

    if not isinstance(missing, list):
        raise ValueError("snapshot missing is not an array")

    seen = set()
    parsed_values = []

    for entry in values:
        if not isinstance(entry, dict):
            raise ValueError(
                "snapshot values entry is not an object"
            )

        key = entry.get("key")
        value = entry.get("value")

        if not isinstance(key, str) or not key:
            raise ValueError(
                "snapshot value key is not a non-empty string"
            )

        if not isinstance(value, str):
            raise ValueError(
                f"snapshot value for {key} is not a string"
            )

        if key in seen:
            raise ValueError(
                f"duplicate snapshot value key: {key}"
            )

        seen.add(key)
        parsed_values.append((key, value))

    parsed_missing = []

    for entry in missing:
        if not isinstance(entry, dict):
            raise ValueError(
                "snapshot missing entry is not an object"
            )

        key = entry.get("key")
        error = entry.get("error")

        if not isinstance(key, str) or not key:
            raise ValueError(
                "snapshot missing key is not a non-empty string"
            )

        if not isinstance(error, str):
            raise ValueError(
                f"snapshot missing error for {key} is not a string"
            )

        if key in seen:
            raise ValueError(
                f"snapshot key occurs in values and missing: {key}"
            )

        seen.add(key)
        parsed_missing.append((key, error))
except Exception as exc:
    print(
        f"invalid sysctl runtime snapshot: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(4)

# Значения этих параметров после усиления нельзя ослабить в рамках
# текущей загрузки. Штатным partial/reboot-required считается только
# подтверждённый переход из терминального усиленного значения к
# сохранённому более слабому значению. Любая другая ошибка остаётся
# настоящим сбоем restore.
import os
import pathlib

WRITE_ONCE_TRANSITIONS = {
    "kernel.kexec_load_disabled": {
        ("1", "0"),
    },
    "kernel.unprivileged_bpf_disabled": {
        ("1", "0"),
        ("1", "2"),
    },
    "kernel.yama.ptrace_scope": {
        ("3", "0"),
        ("3", "1"),
        ("3", "2"),
    },
}

failed = []
write_once_failed = []

proc_root = pathlib.Path(
    os.environ.get(
        "SECURELINUX_SYSCTL_PROC_ROOT",
        "/proc/sys",
    )
)

for key, value in parsed_values:
    result = subprocess.run(
        ["sysctl", "-w", f"{key}={value}"],
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )

    if result.returncode == 0:
        continue

    error = (
        (result.stderr or "").strip()
        or f"exit={result.returncode}"
    )

    current_result = subprocess.run(
        ["sysctl", "-n", key],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    current_value = (
        current_result.stdout.strip()
        if current_result.returncode == 0
        else ""
    )

    # Неуспешная повторная запись не является ошибкой, если требуемое
    # значение уже установлено.
    if (
        current_result.returncode == 0
        and current_value == value
    ):
        continue

    proc_path = proc_root / key.replace(".", "/")
    proc_read_only = True

    try:
        proc_read_only = bool(
            os.statvfs(proc_path).f_flag
            & getattr(os, "ST_RDONLY", 1)
        )
    except OSError:
        proc_read_only = True

    expected_transition = (
        current_result.returncode == 0
        and proc_path.is_file()
        and not proc_read_only
        and (current_value, value)
        in WRITE_ONCE_TRANSITIONS.get(key, set())
    )

    entry = (key, error)

    if expected_transition:
        write_once_failed.append(entry)
    else:
        failed.append(entry)

if failed:
    for key, error in failed:
        print(
            f"{key}: {error}",
            file=sys.stderr,
        )

    for key, error in write_once_failed:
        print(
            f"write-once {key}: {error}",
            file=sys.stderr,
        )

    raise SystemExit(2)

if parsed_missing:
    for key, error in parsed_missing:
        print(
            f"original value unavailable for {key}: {error}",
            file=sys.stderr,
        )

    for key, error in write_once_failed:
        print(
            f"write-once {key}: {error}",
            file=sys.stderr,
        )

    raise SystemExit(3)

if write_once_failed:
    for key, error in write_once_failed:
        print(
            f"write-once {key}: {error}",
            file=sys.stderr,
        )

    raise SystemExit(5)
PYJSON

        case "$restore_rc" in
            0)
                log \
                    "[i]     restore sysctl ${module}: runtime-значения восстановлены"
                return 0
                ;;
            2)
                add_warning \
                    "restore sysctl ${module}: часть runtime-значений не восстановлена"
                return 1
                ;;
            3)
                add_warning \
                    "restore sysctl ${module}: snapshot был неполным; восстановлены только сохранённые значения"
                return 1
                ;;
            5)
                local partial_message="restore sysctl ${module}: write-once параметры ядра не понижаются до перезагрузки; managed-файл восстановлен, полный runtime-откат завершится после reboot"

                add_warning "$partial_message"
                add_restore_irreversible "$partial_message"
                return 0
                ;;
            *)
                add_warning \
                    "restore sysctl ${module}: runtime snapshot повреждён или недоступен"
                return 1
                ;;
        esac
    fi

    if [[ -f "$fallback_file" ]]; then
        if sysctl -p "$fallback_file" \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            log \
                "[i]     restore sysctl ${module}: применён fallback $fallback_file"
            return 0
        fi

        add_warning \
            "restore sysctl ${module}: fallback sysctl -p failed for $fallback_file"
        return 1
    fi

    add_warning \
        "restore sysctl ${module}: snapshot и fallback-файл отсутствуют"
    return 1
}

check_sysctl_userspace_apport_dropin() {
    local dropin_path="$SYSCTL_USERSPACE_APPORT_DROPIN"
    local dropin_invalid=0

    if ! systemctl cat apport.service \
        >/dev/null 2>&1
    then
        add_safe \
            "2.6 fs.suid_dumpable persistence: apport.service отсутствует — drop-in не требуется"
        return 0
    fi

    if [[ ! -f "$dropin_path" || -L "$dropin_path" ]]; then
        add_risky \
            "2.6 fs.suid_dumpable persistence: отсутствует regular drop-in $dropin_path"
        return 0
    fi

    grep -Fqx "# Managed by SecureLinux-NG" "$dropin_path" \
        || dropin_invalid=1

    grep -Fqx "[Service]" "$dropin_path" \
        || dropin_invalid=1

    grep -Fqx \
        "ExecStartPost=/usr/sbin/sysctl -q -w fs.suid_dumpable=0" \
        "$dropin_path" \
        || dropin_invalid=1

    if (( dropin_invalid != 0 )); then
        add_risky \
            "2.6 fs.suid_dumpable persistence: invalid Apport drop-in $dropin_path"
        return 0
    fi

    add_safe \
        "2.6 fs.suid_dumpable persistence enforced through Apport ExecStartPost: $dropin_path"
    return 0
}

apply_sysctl_userspace_apport_dropin() {
    local dropin_path="$SYSCTL_USERSPACE_APPORT_DROPIN"
    local dropin_content="$SYSCTL_USERSPACE_APPORT_CONTENT"
    local dropin_backup=""
    local dropin_existed_before=0

    if ! systemctl cat apport.service \
        >/dev/null 2>&1
    then
        add_skipped \
            "2.6 fs.suid_dumpable persistence: apport.service отсутствует — drop-in не создаётся"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        if [[ -e "$dropin_path" || -L "$dropin_path" ]]; then
            log \
                "[DRY-RUN] backup '$dropin_path' -> '$STATE_DIR/$(basename "$dropin_path").bak-$TIMESTAMP'"
        fi

        log "[DRY-RUN] mkdir -p '$(dirname "$dropin_path")'"
        log \
            "[DRY-RUN] write '$dropin_path' with Apport ExecStartPost fs.suid_dumpable=0"
        log "[DRY-RUN] systemctl daemon-reload"
        return 0
    fi

    if [[ -e "$dropin_path" || -L "$dropin_path" ]]; then
        dropin_existed_before=1
        dropin_backup="$STATE_DIR/$(basename "$dropin_path").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$dropin_path" \
            "$dropin_backup" \
            "2.6 userspace sysctl Apport drop-in"
        then
            add_error \
                "2.6 Apport drop-in не изменён: backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$dropin_path" \
            "$dropin_backup"
        then
            add_error \
                "2.6 Apport drop-in не изменён: backup mapping не записан"

            if ! rm -f -- "$dropin_backup"; then
                add_warning \
                    "2.6 не удалось удалить незарегистрированный backup $dropin_backup"
            fi

            return 1
        fi
    fi

    if ! mkdir -p -- "$(dirname "$dropin_path")"; then
        add_error \
            "2.6 не удалось создать каталог Apport drop-in"
        return 1
    fi

    if ! prepare_created_file_transaction \
        "$dropin_path" \
        "$dropin_existed_before" \
        "2.6 userspace sysctl Apport drop-in"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$dropin_path" \
        0644 \
        python3 - "$dropin_content" <<'PYUSERSPACEAPPORTWRITE'
import sys

sys.stdout.write(sys.argv[1])
PYUSERSPACEAPPORTWRITE
    then
        add_error \
            "2.6 не удалось атомарно записать Apport drop-in: $dropin_path"

        record_manifest_warning \
            "2.6 userspace sysctl Apport drop-in atomic write failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        return 1
    fi

    if (( dropin_existed_before == 0 )); then
        if ! record_manifest_created_file \
            "$dropin_path" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "2.6 созданный Apport drop-in не записан в manifest"

            if ! rm -f -- "$dropin_path"; then
                add_warning \
                    "2.6 не удалось удалить незарегистрированный drop-in $dropin_path"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort "$dropin_path"

    if ! systemctl daemon-reload \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_error \
            "2.6 Apport drop-in: systemctl daemon-reload завершился с ошибкой"

        record_manifest_warning \
            "2.6 userspace sysctl Apport drop-in daemon-reload failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        return 1
    fi

    record_manifest_apply_report \
        "2.6 fs.suid_dumpable persistence configured through $dropin_path"

    add_safe \
        "2.6 Apport ExecStartPost configured: $dropin_path"

    return 0
}

restore_sysctl_userspace_apport_dropin() {
    local dropin_path="$SYSCTL_USERSPACE_APPORT_DROPIN"
    local dropin_backup=""
    local created_file_rc=0
    local dropin_tracked=0
    local rc=0

    if ! dropin_backup="$(restore_lookup_backup "$dropin_path")"; then
        add_error \
            "restore 2.6 Apport drop-in: не удалось прочитать backup из manifest"
        return 1
    fi

    if [[ -n "$dropin_backup" ]]; then
        dropin_tracked=1
    else
        restore_has_created_file "$dropin_path"
        created_file_rc=$?

        case "$created_file_rc" in
            0) dropin_tracked=1 ;;
            1) dropin_tracked=0 ;;
            *) return 1 ;;
        esac
    fi

    if (( dropin_tracked == 1 )); then
        if ! restore_file_from_manifest "$dropin_path"; then
            rc=1
        elif ! systemctl daemon-reload \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            add_warning \
                "restore 2.6 Apport drop-in: systemctl daemon-reload завершился с ошибкой"
            rc=1
        fi
    fi

    return "$rc"
}

apply_sysctl_userspace_protection_module() {
    local _up_content="$SYSCTL_USERSPACE_PROTECTION_CONTENT"
    local backup_path=""
    local existed_before=0
    local sysctl_userspace_ok=0

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '/etc/sysctl.d'"

        if [[ -f "$SYSCTL_USERSPACE_PROTECTION_DROPIN" \
            || -L "$SYSCTL_USERSPACE_PROTECTION_DROPIN" ]]
        then
            log \
                "[DRY-RUN] backup '$SYSCTL_USERSPACE_PROTECTION_DROPIN' -> '$STATE_DIR/$(basename "$SYSCTL_USERSPACE_PROTECTION_DROPIN").bak-$TIMESTAMP'"
        fi

        log \
            "[DRY-RUN] write '$SYSCTL_USERSPACE_PROTECTION_DROPIN' with 2.6 sysctl protections"
        log \
            "[DRY-RUN] sysctl -p '$SYSCTL_USERSPACE_PROTECTION_DROPIN'"

        if ! apply_sysctl_userspace_apport_dropin; then
            return 1
        fi

        add_skipped \
            "2.6 dry-run: sysctl userspace protections would be enforced"
        return 0
    fi

    # ФСТЭК 2.6.1: ptrace_scope=3 — для всех профилей
    # (strict ограничение снято).
    # yama может отсутствовать в Ubuntu minimal.
    if [[ -f /proc/sys/kernel/yama/ptrace_scope ]]; then
        _up_content=$'# Managed by SecureLinux-NG\nkernel.yama.ptrace_scope = 3\n'${_up_content#*$'\n'}
    else
        log \
            "[warn] 2.6.1: kernel.yama.ptrace_scope недоступен (yama не загружен) — параметр пропущен"
    fi

    if [[ -e "$SYSCTL_USERSPACE_PROTECTION_DROPIN" \
        || -L "$SYSCTL_USERSPACE_PROTECTION_DROPIN" ]]
    then
        existed_before=1
        backup_path="$STATE_DIR/$(basename "$SYSCTL_USERSPACE_PROTECTION_DROPIN").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$SYSCTL_USERSPACE_PROTECTION_DROPIN" \
            "$backup_path" \
            "2.6 sysctl userspace"
        then
            add_skipped \
                "2.6 apply skipped: backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$SYSCTL_USERSPACE_PROTECTION_DROPIN" \
            "$backup_path"
        then
            add_error \
                "2.6 apply skipped: backup mapping не записан"

            if ! rm -f -- "$backup_path"; then
                add_warning \
                    "2.6 не удалось удалить незарегистрированный backup $backup_path"
            fi

            return 1
        fi
    fi

    if ! record_sysctl_runtime_snapshot \
        "userspace" \
        "$_up_content"
    then
        add_skipped \
            "2.6 apply skipped: runtime snapshot failed"
        return 1
    fi

    if ! mkdir -p -- \
        "$(dirname "$SYSCTL_USERSPACE_PROTECTION_DROPIN")"
    then
        add_error \
            "2.6 не удалось создать каталог sysctl drop-in"
        return 1
    fi

    if ! prepare_created_file_transaction \
        "$SYSCTL_USERSPACE_PROTECTION_DROPIN" \
        "$existed_before" \
        "2.6 userspace sysctl"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$SYSCTL_USERSPACE_PROTECTION_DROPIN" \
        0644 \
        python3 - "$_up_content" <<'PYUSERSPACEWRITE'
import sys

sys.stdout.write(sys.argv[1])
PYUSERSPACEWRITE
    then
        add_error \
            "2.6 не удалось атомарно записать $SYSCTL_USERSPACE_PROTECTION_DROPIN"
        record_manifest_warning \
            "2.6 atomic userspace sysctl write failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true
        return 1
    fi

    if (( existed_before == 0 )); then
        if ! record_manifest_created_file \
            "$SYSCTL_USERSPACE_PROTECTION_DROPIN" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "2.6 созданный sysctl drop-in не записан в manifest"

            if ! rm -f -- \
                "$SYSCTL_USERSPACE_PROTECTION_DROPIN"
            then
                add_warning \
                    "2.6 не удалось удалить незарегистрированный файл $SYSCTL_USERSPACE_PROTECTION_DROPIN"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$SYSCTL_USERSPACE_PROTECTION_DROPIN"

    record_manifest_apply_report \
        "2.6 enforced via $SYSCTL_USERSPACE_PROTECTION_DROPIN"

    if ! apply_sysctl_userspace_apport_dropin; then
        return 1
    fi

    if sysctl -p "$SYSCTL_USERSPACE_PROTECTION_DROPIN" \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        sysctl_userspace_ok=1
    fi

    if (( sysctl_userspace_ok == 1 )); then
        add_safe \
            "2.6 userspace-protection sysctl enforced via drop-in: $SYSCTL_USERSPACE_PROTECTION_DROPIN"
        return 0
    fi

    add_error \
        "2.6 userspace-protection drop-in записан, но sysctl -p завершился с ошибкой"

    record_manifest_warning \
        "2.6 sysctl -p failed after writing $SYSCTL_USERSPACE_PROTECTION_DROPIN" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" \
        || true

    return 1
}

restore_sysctl_userspace_protection_module() {
    local rc=0

    if ! restore_sysctl_userspace_apport_dropin; then
        rc=1
    fi

    if ! restore_file_from_manifest \
        "$SYSCTL_USERSPACE_PROTECTION_DROPIN"
    then
        rc=1
    fi

    if ! restore_sysctl_runtime_snapshot \
        "userspace" \
        "$SYSCTL_USERSPACE_PROTECTION_DROPIN"
    then
        rc=1
    fi

    return "$rc"
}
apply_sysctl_attack_surface_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '/etc/sysctl.d'"
        if [[ -e "$SYSCTL_ATTACK_SURFACE_DROPIN" \
            || -L "$SYSCTL_ATTACK_SURFACE_DROPIN" ]]
        then
            log \
                "[DRY-RUN] backup '$SYSCTL_ATTACK_SURFACE_DROPIN' -> '$STATE_DIR/$(basename "$SYSCTL_ATTACK_SURFACE_DROPIN").bak-$TIMESTAMP'"
        fi
        log "[DRY-RUN] write '$SYSCTL_ATTACK_SURFACE_DROPIN' with 2.5 sysctl protections"
        log "[DRY-RUN] sysctl -p '$SYSCTL_ATTACK_SURFACE_DROPIN'"
        add_skipped "2.5 dry-run: sysctl attack-surface protections would be enforced"
        return 0
    fi

    local backup_path=""
    local existed_before=0
    local sysctl_attack_ok=0
    local attack_content="$SYSCTL_ATTACK_SURFACE_CONTENT"

    if [[ -e "$SYSCTL_ATTACK_SURFACE_DROPIN" \
        || -L "$SYSCTL_ATTACK_SURFACE_DROPIN" ]]
    then
        existed_before=1
        backup_path="$STATE_DIR/$(basename "$SYSCTL_ATTACK_SURFACE_DROPIN").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$SYSCTL_ATTACK_SURFACE_DROPIN" \
            "$backup_path" \
            "2.5 sysctl attack surface"
        then
            add_skipped \
                "2.5 apply skipped: backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$SYSCTL_ATTACK_SURFACE_DROPIN" \
            "$backup_path"
        then
            add_error \
                "2.5 apply skipped: backup mapping не записан"

            if ! rm -f -- "$backup_path"; then
                add_warning \
                    "2.5 не удалось удалить незарегистрированный backup $backup_path"
            fi

            return 1
        fi
    fi
    # ФСТЭК 2.5.2/2.5.6: perf_event_paranoid и unprivileged_bpf — для всех профилей
    # 2.5.5 user.max_user_namespaces: явный конфиг имеет приоритет над интерактивом
    local ns_limit
    if [[ -n "$USER_NAMESPACES_LIMIT" ]]; then
        ns_limit="$USER_NAMESPACES_LIMIT"
        if ! attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"; then
            add_error "2.5.5 не удалось удалить прежнее user.max_user_namespaces из sysctl-конфигурации"
            record_manifest_warning "2.5.5 user namespace sysctl filter failed"
            return 1
        fi
        attack_content="${attack_content}
user.max_user_namespaces = ${ns_limit}"
        add_safe "2.5.5 user.max_user_namespaces=${ns_limit} (из конфига)"
    else
        log ""
        log "[?]     ФСТЭК 2.5.5: user.max_user_namespaces"
        log "[?]     Планируется ли использование Docker / Podman / Kubernetes на этом сервере?"
        log "[?]       1) Нет  — установить =0 (ФСТЭК требование, максимальная безопасность)"
        log "[?]       2) Да   — установить =10000 (контейнеры будут работать)"
        log "[?]       3) Пропустить — не изменять значение"
        local ns_choice
        local ns_tty_fd

        if ! exec {ns_tty_fd}<>/dev/tty 2>/dev/null; then
            add_skipped "2.5.5 user.max_user_namespaces пропущен: терминал недоступен (задайте USER_NAMESPACES_LIMIT в конфиге)"
            if ! attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"; then
                add_error "2.5.5 не удалось удалить прежнее user.max_user_namespaces из sysctl-конфигурации"
                record_manifest_warning "2.5.5 user namespace sysctl filter failed"
                return 1
            fi
        else
            while true; do
                if ! printf '    Ваш выбор [1/2/3]: ' >&"$ns_tty_fd" \
                   || ! IFS= read -r ns_choice <&"$ns_tty_fd"
                then
                    add_skipped "2.5.5 user.max_user_namespaces пропущен: чтение с терминала завершилось ошибкой (задайте USER_NAMESPACES_LIMIT в конфиге)"
                    if ! attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"; then
                        add_error "2.5.5 не удалось удалить прежнее user.max_user_namespaces из sysctl-конфигурации"
                        record_manifest_warning "2.5.5 user namespace sysctl filter failed"
                        return 1
                    fi
                    break
                fi

                case "$ns_choice" in
                    1)
                        ns_limit=0
                        if ! attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"; then
                            add_error "2.5.5 не удалось удалить прежнее user.max_user_namespaces из sysctl-конфигурации"
                            record_manifest_warning "2.5.5 user namespace sysctl filter failed"
                            return 1
                        fi
                        attack_content="${attack_content}
user.max_user_namespaces = 0"
                        add_safe "2.5.5 user.max_user_namespaces=0 (выбрано администратором)"
                        log "[i]     Совет: добавьте USER_NAMESPACES_LIMIT=0 в конфиг для автоматического применения"
                        break
                        ;;
                    2)
                        ns_limit=10000
                        if ! attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"; then
                            add_error "2.5.5 не удалось удалить прежнее user.max_user_namespaces из sysctl-конфигурации"
                            record_manifest_warning "2.5.5 user namespace sysctl filter failed"
                            return 1
                        fi
                        attack_content="${attack_content}
user.max_user_namespaces = 10000"
                        add_safe "2.5.5 user.max_user_namespaces=10000 (выбрано администратором — Docker/Podman/K8s совместимость)"
                        add_warning "2.5.5 user.max_user_namespaces=10000 — отклонение от ФСТЭК 2.5.5 (требует =0); зафиксируйте обоснование"
                        log "[i]     Совет: добавьте USER_NAMESPACES_LIMIT=10000 в конфиг для автоматического применения"
                        break
                        ;;
                    3)
                        if ! attack_content="$(printf '%s' "$attack_content" | grep -Fv 'user.max_user_namespaces')"; then
                            add_error "2.5.5 не удалось удалить прежнее user.max_user_namespaces из sysctl-конфигурации"
                            record_manifest_warning "2.5.5 user namespace sysctl filter failed"
                            return 1
                        fi
                        add_skipped "2.5.5 user.max_user_namespaces пропущен по выбору администратора"
                        break
                        ;;
                    *)
                        log "[?]     Неверный ввод. Введите 1, 2 или 3."
                        ;;
                esac
            done

            exec {ns_tty_fd}>&-
            log ""
        fi
    fi
    if ! attack_content="$(
        preserve_stricter_sysctl_values "$attack_content"
    )"; then
        add_error             "2.5 не удалось сохранить более строгие текущие sysctl-значения"
        record_manifest_warning             "2.5 preserve stricter sysctl values failed"
        return 1
    fi

    if ! record_sysctl_runtime_snapshot \
        "attack-surface" "$attack_content"
    then
        add_skipped \
            "2.5 apply skipped: runtime snapshot failed"
        return 1
    fi

    if ! mkdir -p -- \
        "$(dirname "$SYSCTL_ATTACK_SURFACE_DROPIN")"
    then
        add_error \
            "2.5 не удалось создать каталог sysctl drop-in"
        return 1
    fi

    if ! prepare_created_file_transaction \
        "$SYSCTL_ATTACK_SURFACE_DROPIN" \
        "$existed_before" \
        "2.5 attack-surface sysctl"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$SYSCTL_ATTACK_SURFACE_DROPIN" \
        0644 \
        python3 - "$attack_content" <<'PYATTACKWRITE'
import sys

print(sys.argv[1])
PYATTACKWRITE
    then
        add_error \
            "2.5 не удалось атомарно записать $SYSCTL_ATTACK_SURFACE_DROPIN"
        record_manifest_warning \
            "2.5 atomic attack-surface sysctl write failed"
        return 1
    fi

    if (( existed_before == 0 )); then
        if ! record_manifest_created_file \
            "$SYSCTL_ATTACK_SURFACE_DROPIN" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "2.5 созданный sysctl drop-in не записан в manifest"

            if ! rm -f -- \
                "$SYSCTL_ATTACK_SURFACE_DROPIN"
            then
                add_warning \
                    "2.5 не удалось удалить незарегистрированный файл $SYSCTL_ATTACK_SURFACE_DROPIN"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$SYSCTL_ATTACK_SURFACE_DROPIN"

    record_manifest_apply_report \
        "2.5 enforced via $SYSCTL_ATTACK_SURFACE_DROPIN"

    if sysctl -p "$SYSCTL_ATTACK_SURFACE_DROPIN" \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        sysctl_attack_ok=1
    fi

    if (( sysctl_attack_ok == 1 )); then
        add_safe \
            "2.5 attack-surface sysctl protections enforced via drop-in: $SYSCTL_ATTACK_SURFACE_DROPIN"
        return 0
    fi

    add_error \
        "2.5 attack-surface sysctl drop-in записан, но sysctl -p завершился с ошибкой"

    record_manifest_warning \
        "2.5 sysctl -p failed after writing $SYSCTL_ATTACK_SURFACE_DROPIN" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" \
        || true

    return 1
}
restore_sysctl_attack_surface_module() {
    local rc=0

    if ! restore_file_from_manifest         "$SYSCTL_ATTACK_SURFACE_DROPIN"
    then
        rc=1
    fi

    if ! restore_sysctl_runtime_snapshot         "attack-surface" "$SYSCTL_ATTACK_SURFACE_DROPIN"
    then
        rc=1
    fi

    return "$rc"
}
check_modules_disabled_module() {
    # Модуль временно отключён — apply выдаёт SKIP, check тоже пропускает
    add_skipped "kernel.modules_disabled: временно отключено — проверка пропущена"
    return 0
}

apply_modules_disabled_module() {
    # ВРЕМЕННО ОТКЛЮЧЕНО: kernel.modules_disabled=1 ломает binfmt_misc и UFW при загрузке
    # Требует предварительной загрузки всех нужных модулей до применения параметра
    add_skipped "kernel.modules_disabled: временно отключено (совместимость с binfmt_misc/UFW при boot)"
    return 0
}

restore_modules_disabled_module() {
    # Если dropin не существует — apply был пропущен, restore не нужен
    if [[ ! -f "$SYSCTL_MODULES_DISABLED_DROPIN" ]]; then
        log "[i]     restore kernel.modules_disabled: dropin не создавался — пропуск"
        return 0
    fi

    if ! restore_file_from_manifest         "$SYSCTL_MODULES_DISABLED_DROPIN"
    then
        return 1
    fi

    add_warning "restore kernel.modules_disabled: dropin удалён, но значение kernel.modules_disabled=1 необратимо до перезагрузки"
    return 0
}
apply_grub_kernel_params_module() {
    local grub_file="/etc/default/grub"
    local grub_backup="${STATE_DIR}/grub_default_backup_${TIMESTAMP}"
    local a b c
    local grub_check_output=""
    local grub_params=("${GRUB_KERNEL_REQUIRED_PARAMS[@]}")
    if profile_allows strict; then
        grub_params+=("apparmor=1" "security=apparmor")
    fi

    if (( DRY_RUN == 1 )); then
        if ! grub_check_output="$(grub_kernel_params_check_module "$PROFILE")"; then
            add_error "2.4 dry-run: GRUB kernel parameters scan завершился с ошибкой"
            return 1
        fi

        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.4 grub params scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.4 would add missing kernel param '$a'"
                    ;;
            esac
        done <<< "$grub_check_output"

        log "[DRY-RUN] 2.4 would backup ${grub_file} -> ${grub_backup}"
        log "[DRY-RUN] 2.4 would add missing params to GRUB_CMDLINE_LINUX_DEFAULT"
        log "[DRY-RUN] 2.4 would run update-grub / grub2-mkconfig"
        add_skipped "2.4 dry-run: GRUB kernel params remediation skipped"
        return 0
    fi



    if [[ ! -f "${grub_file}" ]]; then
        add_warning "2.4 ${grub_file} не найден — пропуск GRUB hardening"
        record_manifest_warning "2.4 ${grub_file} not found"
        add_skipped "2.4 apply skipped: ${grub_file} not found"
        return 0
    fi

    if manifest_has_backup_for "${grub_file}"; then
        log "[i]     2.4 GRUB backup уже существует — пропуск"
    else
        if ! backup_file_checked \
            "${grub_file}" \
            "${grub_backup}" \
            "2.4 GRUB"
        then
            add_warning "2.4 не удалось создать backup ${grub_file}"
            add_skipped "2.4 apply skipped: backup failed"
            return 0
        fi
        if ! record_manifest_backup             "${grub_file}"             "${grub_backup}"
        then
            add_error                 "2.4 не удалось записать backup mapping для ${grub_file}"

            if ! rm -f -- "${grub_backup}"; then
                add_warning                     "2.4 не удалось удалить незарегистрированный backup ${grub_backup}"
            fi

            return 1
        fi

        log "[i]     2.4 backup ${grub_file} -> ${grub_backup}"
    fi

    local grub_output
    local grub_write_rc=0

    grub_output=$(
        atomic_write_command_output \
            "${grub_file}" \
            0644 \
            python3 - "${grub_file}" "${grub_params[@]}" \
            2>&1 <<'PYGRUB'
import pathlib
import re
import sys

grub_file = pathlib.Path(sys.argv[1])
required = sys.argv[2:]
content = grub_file.read_text(encoding="utf-8")
pattern = re.compile(
    r"(?m)^(GRUB_CMDLINE_LINUX_DEFAULT=)([\"'])(.*?)([\"'])"
)
match = pattern.search(content)

if not match:
    print(content, end="")
    print(
        "SKIP: GRUB_CMDLINE_LINUX_DEFAULT not found",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(0)

prefix, quote_start, current, quote_end = match.groups()
params = current.split()
added = []

for required_param in required:
    key = required_param.split("=", 1)[0]
    replace_index = None

    for index, current_param in enumerate(params):
        if current_param == required_param:
            break

        if current_param == key or current_param.startswith(key + "="):
            replace_index = index
            break
    else:
        index = None

    if index is not None and params[index] == required_param:
        continue

    if replace_index is not None:
        params[replace_index] = required_param
    else:
        params.append(required_param)

    added.append(required_param)

new_line = (
    prefix
    + quote_start
    + " ".join(params)
    + quote_end
)
new_content = (
    content[:match.start()]
    + new_line
    + content[match.end():]
)

print(new_content, end="")

if added:
    print(
        "ADDED: " + " ".join(added),
        file=sys.stderr,
        flush=True,
    )
else:
    print(
        "OK: all params already present",
        file=sys.stderr,
        flush=True,
    )
PYGRUB
    ) || grub_write_rc=$?

    if (( grub_write_rc != 0 )); then
        add_error \
            "2.4 не удалось атомарно обновить ${grub_file}: ${grub_output:-unknown error}"
        record_manifest_warning "2.4 atomic GRUB update failed"
        return 1
    fi
    [[ -n "$grub_output" ]] && record_manifest_apply_report "2.4 GRUB: $grub_output"

    if command -v update-grub >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        update-grub >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 \
            && add_safe "2.4 GRUB kernel params applied, update-grub выполнен" \
            || { add_warning "2.4 update-grub завершился с ошибкой"; record_manifest_warning "2.4 update-grub failed"; }
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
        grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 \
            && add_safe "2.4 GRUB kernel params applied, grub2-mkconfig выполнен" \
            || { add_warning "2.4 grub2-mkconfig завершился с ошибкой"; record_manifest_warning "2.4 grub2-mkconfig failed"; }
    else
        add_warning "2.4 update-grub / grub2-mkconfig не найден — ${grub_file} обновлён, загрузчик требует ручного обновления"
        record_manifest_warning "2.4 grub update command not found; manual update-grub required"
        add_safe "2.4 GRUB_CMDLINE_LINUX_DEFAULT обновлён (требуется ручной update-grub)"
    fi

    # п.7.7: chmod 600 grub.cfg
    if profile_allows baseline; then
        local grub_cfg
        for grub_cfg in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
            if [[ -f "$grub_cfg" ]]; then
                chmod 600 "$grub_cfg" && \
                    add_safe "7.7 grub.cfg chmod 600: $grub_cfg" || \
                    add_warning "7.7 grub.cfg chmod 600 не удался: $grub_cfg"
            fi
        done
    fi
}

restore_grub_module() {
    local grub_file="/etc/default/grub"
    local backup=""

    if ! backup="$(restore_lookup_backup "$grub_file")"; then
        add_error \
            "restore 2.4 GRUB: не удалось прочитать backup из manifest"
        return 1
    fi

    if [[ -z "$backup" ]]; then
        log "[i]     restore 2.4 GRUB: backup не найден в manifest — пропуск"
        return 0
    fi

    if [[ ! -f "$backup" && ! -L "$backup" ]]; then
        add_error \
            "restore 2.4 GRUB: зарегистрированный backup отсутствует: $backup"
        return 1
    fi

    if ! restore_file_from_manifest "$grub_file"; then
        add_error \
            "restore 2.4 GRUB: не удалось восстановить $grub_file"
        return 1
    fi

    log \
        "[i]     restore 2.4 GRUB: $grub_file восстановлен из $backup"

    if command -v update-grub >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        if update-grub >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
            log "[i]     restore 2.4 GRUB: update-grub выполнен"
        else
            log "[WARN]  restore 2.4 GRUB: update-grub завершился с ошибкой"
            return 1
        fi
    elif command -v grub2-mkconfig >/dev/null 2>&1; then
        if grub2-mkconfig -o /boot/grub2/grub.cfg \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            log "[i]     restore 2.4 GRUB: grub2-mkconfig выполнен"
        else
            log "[WARN]  restore 2.4 GRUB: grub2-mkconfig завершился с ошибкой"
            return 1
        fi
    else
        log "[WARN]  restore 2.4 GRUB: update-grub / grub2-mkconfig не найден — требуется ручное обновление"
        return 1
    fi

    return 0
}

apply_sysctl_kernel_module() {
    local backup_path=""
    local existed_before=0
    local sysctl_kernel_ok=0

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '/etc/sysctl.d'"

        if [[ -e "$SYSCTL_KERNEL_DROPIN" \
            || -L "$SYSCTL_KERNEL_DROPIN" ]]
        then
            log \
                "[DRY-RUN] backup '$SYSCTL_KERNEL_DROPIN' -> '$STATE_DIR/$(basename "$SYSCTL_KERNEL_DROPIN").bak-$TIMESTAMP'"
        fi

        log \
            "[DRY-RUN] write '$SYSCTL_KERNEL_DROPIN' with kernel.dmesg_restrict=1, kernel.kptr_restrict=2, net.core.bpf_jit_harden=2"
        log \
            "[DRY-RUN] sysctl -p '$SYSCTL_KERNEL_DROPIN'"
        add_skipped \
            "2.4 dry-run: sysctl kernel protections would be enforced"
        return 0
    fi

    if [[ -e "$SYSCTL_KERNEL_DROPIN" \
        || -L "$SYSCTL_KERNEL_DROPIN" ]]
    then
        existed_before=1
        backup_path="$STATE_DIR/$(basename "$SYSCTL_KERNEL_DROPIN").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$SYSCTL_KERNEL_DROPIN" \
            "$backup_path" \
            "2.4 sysctl kernel"
        then
            add_skipped \
                "2.4 apply skipped: backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$SYSCTL_KERNEL_DROPIN" \
            "$backup_path"
        then
            add_error \
                "2.4 apply skipped: backup mapping не записан"

            if ! rm -f -- "$backup_path"; then
                add_warning \
                    "2.4 не удалось удалить незарегистрированный backup $backup_path"
            fi

            return 1
        fi
    fi

    if ! record_sysctl_runtime_snapshot \
        "kernel" \
        "$SYSCTL_KERNEL_CONTENT"
    then
        add_skipped \
            "2.4 apply skipped: runtime snapshot failed"
        return 1
    fi

    if ! mkdir -p -- \
        "$(dirname "$SYSCTL_KERNEL_DROPIN")"
    then
        add_error \
            "2.4 не удалось создать каталог sysctl drop-in"
        return 1
    fi

    if ! prepare_created_file_transaction \
        "$SYSCTL_KERNEL_DROPIN" \
        "$existed_before" \
        "2.4 kernel sysctl"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$SYSCTL_KERNEL_DROPIN" \
        0644 \
        python3 - "$SYSCTL_KERNEL_CONTENT" <<'PYKERNELWRITE'
import sys

sys.stdout.write(sys.argv[1])
PYKERNELWRITE
    then
        add_error \
            "2.4 не удалось атомарно записать $SYSCTL_KERNEL_DROPIN"

        record_manifest_warning \
            "2.4 atomic kernel sysctl write failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        return 1
    fi

    if (( existed_before == 0 )); then
        if ! record_manifest_created_file \
            "$SYSCTL_KERNEL_DROPIN" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "2.4 созданный sysctl drop-in не записан в manifest"

            if ! rm -f -- "$SYSCTL_KERNEL_DROPIN"; then
                add_warning \
                    "2.4 не удалось удалить незарегистрированный файл $SYSCTL_KERNEL_DROPIN"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$SYSCTL_KERNEL_DROPIN"

    record_manifest_apply_report \
        "2.4 enforced via $SYSCTL_KERNEL_DROPIN"

    if sysctl -p "$SYSCTL_KERNEL_DROPIN" \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        sysctl_kernel_ok=1
    fi

    if (( sysctl_kernel_ok == 1 )); then
        add_safe \
            "2.4 kernel sysctl protections enforced via drop-in: $SYSCTL_KERNEL_DROPIN"
        return 0
    fi

    add_error \
        "2.4 kernel sysctl drop-in записан, но sysctl -p завершился с ошибкой"

    record_manifest_warning \
        "2.4 sysctl -p failed after writing $SYSCTL_KERNEL_DROPIN" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" \
        || true

    return 1
}

restore_sysctl_kernel_module() {
    local rc=0

    if ! restore_file_from_manifest         "$SYSCTL_KERNEL_DROPIN"
    then
        rc=1
    fi

    if ! restore_sysctl_runtime_snapshot         "kernel" "$SYSCTL_KERNEL_DROPIN"
    then
        rc=1
    fi

    return "$rc"
}
sysctl_network_check_module() {
    python3 - "${1:-baseline}" <<'PYJSON'
import subprocess, sys
targets = {
    "net.ipv4.ip_forward": "0",
    "net.ipv6.conf.all.forwarding": "0",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv4.conf.default.log_martians": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv6.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.tcp_syn_retries": "3",
}
profile = sys.argv[1] if len(sys.argv) > 1 else "baseline"
paranoid_targets = {
    "net.ipv4.tcp_timestamps": "0",
}
if profile == "paranoid":
    targets.update(paranoid_targets)
ok = 0
risky = 0
for key, expected in targets.items():
    try:
        res = subprocess.run(["sysctl", "-n", key], text=True, capture_output=True, check=False)
        if res.returncode != 0:
            err = (res.stderr or "").strip() or f"exit={res.returncode}"
            print(f"RISK\t{key}\tread_failed:{err}")
            risky += 1
            continue
        value = (res.stdout or "").strip()
    except Exception as e:
        print(f"RISK\t{key}\tread_failed:{e}")
        risky += 1
        continue
    if value == expected:
        ok += 1
    else:
        risky += 1
        print(f"RISK\t{key}\texpected={expected},actual={value}")
print(f"SUMMARY\t{len(targets)}\t{ok}\t{risky}")
PYJSON
}

record_sysctl_network_check_results() {
    local total="$1" ok="$2" risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "8.1-8.3 sysctl network protections checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "8.1-8.3 sysctl network protections checked: total=$total ok=$ok risky=$risky"
    fi
}

read_systemd_unit_enabled_state() {
    local unit_name="$1"
    local state=""
    local command_rc=0

    state="$(
        systemctl is-enabled "$unit_name" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
    )" || command_rc=$?

    case "$state" in
        enabled|enabled-runtime|masked|masked-runtime|disabled|static|indirect|generated|transient|alias|not-found)
            printf '%s\n' "$state"
            return 0
            ;;
        "")
            printf \
                'systemctl is-enabled returned no state for %s (rc=%s)\n' \
                "$unit_name" \
                "$command_rc" \
                >&2
            return 1
            ;;
        *)
            printf \
                'systemctl is-enabled returned unsupported state for %s: %s (rc=%s)\n' \
                "$unit_name" \
                "$state" \
                "$command_rc" \
                >&2
            return 1
            ;;
    esac
}

read_systemd_unit_active_state() {
    local unit_name="$1"
    local state=""
    local command_rc=0

    state="$(
        systemctl is-active "$unit_name" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
    )" || command_rc=$?

    case "$state" in
        active|activating|reloading)
            printf '%s\n' "active"
            return 0
            ;;
        inactive|failed|deactivating|maintenance|unknown)
            printf '%s\n' "inactive"
            return 0
            ;;
        "")
            printf \
                'systemctl is-active returned no state for %s (rc=%s)\n' \
                "$unit_name" \
                "$command_rc" \
                >&2
            return 1
            ;;
        *)
            printf \
                'systemctl is-active returned unsupported state for %s: %s (rc=%s)\n' \
                "$unit_name" \
                "$state" \
                "$command_rc" \
                >&2
            return 1
            ;;
    esac
}

record_manifest_pending_service_transaction() {
    local module="$1"
    local unit_name="$2"
    local operation="$3"
    local enabled_before="$4"
    local active_before="$5"

    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1

    python3 - \
        "$MANIFEST_FILE" \
        "$module" \
        "$unit_name" \
        "$operation" \
        "$enabled_before" \
        "$active_before" <<'PYJSON'
import json
import os
import pathlib
import re
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
module, unit, operation, enabled, active = sys.argv[2:]

if re.fullmatch(r"[a-z0-9][a-z0-9_-]*", module) is None:
    raise ValueError(f"invalid service transaction module: {module}")
if re.fullmatch(r"[A-Za-z0-9_.@:-]+[.]service", unit) is None:
    raise ValueError(f"invalid systemd service unit: {unit}")
if operation not in {"enable-now", "enable-only", "disable-now"}:
    raise ValueError(f"invalid service transaction operation: {operation}")
if enabled not in {
    "enabled", "enabled-runtime", "masked", "masked-runtime",
    "disabled", "static", "indirect", "generated", "transient",
    "alias", "not-found",
}:
    raise ValueError(f"invalid enabled state: {enabled}")
if active not in {"active", "inactive"}:
    raise ValueError(f"invalid active state: {active}")
if enabled in {"masked", "masked-runtime", "not-found"} and active == "active":
    raise ValueError("contradictory pre-service state")

data = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

pending = data.setdefault("pending_service_transactions", [])
committed = data.setdefault("service_transactions", [])
if not isinstance(pending, list):
    raise ValueError("pending_service_transactions is not an array")
if not isinstance(committed, list):
    raise ValueError("service_transactions is not an array")

entry = {
    "module": module,
    "unit": unit,
    "operation": operation,
    "enabled_before": enabled,
    "active_before": active,
}

for label, values in (("pending", pending), ("committed", committed)):
    for index, item in enumerate(values):
        if not isinstance(item, dict):
            raise ValueError(f"{label} service transaction {index} is not an object")
        if item.get("module") == module and item.get("unit") == unit:
            if label == "pending" and item == entry:
                raise SystemExit(0)
            raise ValueError(f"conflicting {label} service transaction exists")

pending.append(entry)

fd, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    payload = (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    os.write(fd, payload)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
PYJSON
}

commit_manifest_service_transaction() {
    local module="$1"
    local unit_name="$2"

    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1

    python3 - "$MANIFEST_FILE" "$module" "$unit_name" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
module = sys.argv[2]
unit = sys.argv[3]

data = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

pending = data.setdefault("pending_service_transactions", [])
committed = data.setdefault("service_transactions", [])
if not isinstance(pending, list):
    raise ValueError("pending_service_transactions is not an array")
if not isinstance(committed, list):
    raise ValueError("service_transactions is not an array")

matches = []
remaining = []
for index, item in enumerate(pending):
    if not isinstance(item, dict):
        raise ValueError(f"pending service transaction {index} is not an object")
    if item.get("module") == module and item.get("unit") == unit:
        matches.append(item)
    else:
        remaining.append(item)

if len(matches) != 1:
    raise ValueError("expected exactly one pending service transaction")
entry = matches[0]

for index, item in enumerate(committed):
    if not isinstance(item, dict):
        raise ValueError(f"committed service transaction {index} is not an object")
    if item.get("module") == module and item.get("unit") == unit:
        raise ValueError("committed service transaction already exists")

committed.append(entry)
pending[:] = remaining

fd, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    payload = (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    os.write(fd, payload)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
PYJSON
}

restore_manifest_service_transaction() {
    local module="$1"
    local unit_name="$2"

    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        return 2
    fi

    python3 - "$RESTORE_SOURCE_MANIFEST" "$module" "$unit_name" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
module = sys.argv[2]
unit = sys.argv[3]

try:
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]*", module) is None:
        raise ValueError("invalid service transaction module")
    if re.fullmatch(r"[A-Za-z0-9_.@:-]+[.]service", unit) is None:
        raise ValueError("invalid systemd service unit")

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    values = []
    for key in ("service_transactions", "pending_service_transactions"):
        items = data.get(key, [])
        if not isinstance(items, list):
            raise ValueError(f"manifest {key} is not an array")
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(f"manifest {key}[{index}] is not an object")
            if item.get("module") == module and item.get("unit") == unit:
                values.append(item)

    if not values:
        raise SystemExit(1)
    if len(values) != 1:
        raise ValueError("expected exactly one service transaction")

    item = values[0]
    operation = item.get("operation")
    enabled = item.get("enabled_before")
    active = item.get("active_before")

    if operation not in {"enable-now", "enable-only", "disable-now"}:
        raise ValueError("invalid service transaction operation")
    if enabled not in {
        "enabled", "enabled-runtime", "masked", "masked-runtime",
        "disabled", "static", "indirect", "generated", "transient",
        "alias", "not-found",
    }:
        raise ValueError("invalid service enabled state")
    if active not in {"active", "inactive"}:
        raise ValueError("invalid service active state")
    if enabled in {"masked", "masked-runtime", "not-found"} and active == "active":
        raise ValueError("contradictory service state")

    print(f"{operation}\t{enabled}\t{active}")
except SystemExit:
    raise
except Exception as exc:
    print(f"restore service transaction lookup failed: {exc}", file=sys.stderr)
    raise SystemExit(2)
PYJSON
}

prepare_systemd_service_transaction() {
    local module="$1"
    local unit_name="$2"
    local operation="$3"
    local enabled_before=""
    local active_before=""

    if ! [[ "$unit_name" =~ ^[A-Za-z0-9_.@:-]+[.]service$ ]]; then
        add_error "service transaction ${module}: некорректное имя unit: $unit_name"
        return 1
    fi

    if ! enabled_before="$(read_systemd_unit_enabled_state "$unit_name")"; then
        add_error "service transaction ${module}: не удалось прочитать enabled-состояние $unit_name"
        return 1
    fi

    if ! active_before="$(read_systemd_unit_active_state "$unit_name")"; then
        add_error "service transaction ${module}: не удалось прочитать active-состояние $unit_name"
        return 1
    fi

    if ! record_manifest_pending_service_transaction \
        "$module" \
        "$unit_name" \
        "$operation" \
        "$enabled_before" \
        "$active_before"
    then
        add_error "service transaction ${module}: pending state не записан"
        return 1
    fi

    return 0
}

commit_systemd_service_transaction() {
    local module="$1"
    local unit_name="$2"

    if ! commit_manifest_service_transaction "$module" "$unit_name"; then
        add_error "service transaction ${module}: commit state не записан"
        return 1
    fi

    return 0
}

restore_systemd_unit_exact_state() {
    local unit_name="$1"
    local enabled_before="$2"
    local active_before="$3"
    local rc=0

    case "$enabled_before" in
        masked|masked-runtime)
            if systemctl is-active --quiet "$unit_name" \
                2>>"${DEBUG_LOG_FILE:-/dev/null}"
            then
                systemctl stop "$unit_name" \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            fi
            ;;
        *)
            systemctl unmask "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            systemctl unmask --runtime "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            ;;
    esac

    case "$enabled_before" in
        enabled)
            systemctl disable --runtime "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            systemctl enable "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            ;;
        enabled-runtime)
            systemctl disable "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            systemctl enable --runtime "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            ;;
        disabled)
            systemctl disable "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            systemctl disable --runtime "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            ;;
        masked)
            systemctl disable "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            systemctl disable --runtime "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            systemctl mask "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            ;;
        masked-runtime)
            systemctl disable "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            systemctl disable --runtime "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            systemctl mask --runtime "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            ;;
        static|indirect|generated|transient|alias|not-found)
            systemctl disable "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true
            systemctl disable --runtime "$unit_name" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true
            ;;
        *)
            return 1
            ;;
    esac

    case "$active_before" in
        active)
            if ! systemctl is-active --quiet "$unit_name" \
                2>>"${DEBUG_LOG_FILE:-/dev/null}"
            then
                systemctl start "$unit_name" \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            fi
            ;;
        inactive)
            if systemctl is-active --quiet "$unit_name" \
                2>>"${DEBUG_LOG_FILE:-/dev/null}"
            then
                systemctl stop "$unit_name" \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
            fi
            ;;
        *)
            return 1
            ;;
    esac

    return "$rc"
}

SERVICE_TRANSACTION_FOUND=0

restore_systemd_service_transaction() {
    local module="$1"
    local unit_name="$2"
    local label="$3"
    local state=""
    local lookup_rc=0
    local operation=""
    local enabled_before=""
    local active_before=""

    SERVICE_TRANSACTION_FOUND=0

    state="$(restore_manifest_service_transaction "$module" "$unit_name")"
    lookup_rc=$?

    case "$lookup_rc" in
        0)
            SERVICE_TRANSACTION_FOUND=1
            ;;
        1)
            log "[i]     restore ${label}: service transaction отсутствует — пропуск"
            return 0
            ;;
        *)
            add_error "restore ${label}: service transaction повреждён"
            return 1
            ;;
    esac

    IFS=$'\t' read -r operation enabled_before active_before <<< "$state"

    if ! restore_systemd_unit_exact_state \
        "$unit_name" \
        "$enabled_before" \
        "$active_before"
    then
        add_error \
            "restore ${label}: не удалось вернуть $unit_name в состояние enabled=${enabled_before}, active=${active_before}"
        return 1
    fi

    log \
        "[i]     restore ${label}: $unit_name восстановлен (operation=${operation}, enabled=${enabled_before}, active=${active_before})"
    return 0
}

record_sysctl_unit_pre_state() {
    local state="$1"
    local prefix="8.1-8.3 pre-unit-enabled: "

    (( DRY_RUN == 1 )) && return 0

    case "$state" in
        enabled|enabled-runtime|masked|masked-runtime|disabled|static|indirect|generated|transient|alias|not-found)
            ;;
        *)
            add_error \
                "8.1-8.3 некорректное прежнее состояние systemd unit: $state"
            return 1
            ;;
    esac

    if [[ -z "${MANIFEST_FILE:-}" \
        || ! -f "${MANIFEST_FILE:-}" ]]
    then
        add_error \
            "8.1-8.3 manifest недоступен при записи прежнего состояния systemd unit"
        return 1
    fi

    if ! python3 - \
        "$MANIFEST_FILE" \
        "$prefix" \
        "$state" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
prefix = sys.argv[2]
state = sys.argv[3]
value = prefix + state

data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

apply_report = data.setdefault("apply_report", [])

if not isinstance(apply_report, list):
    raise ValueError("manifest apply_report is not an array")

for entry in apply_report:
    if not isinstance(entry, str):
        raise ValueError(
            "manifest apply_report entry is not a string"
        )

matches = [
    entry
    for entry in apply_report
    if entry.startswith(prefix)
]

if len(matches) > 1:
    raise ValueError(
        "multiple pre-unit-enabled records already exist"
    )

if matches:
    if matches[0] != value:
        raise ValueError(
            "conflicting pre-unit-enabled record already exists"
        )

    raise SystemExit(0)

apply_report.append(value)

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    content = (
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    os.write(fd, content)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        os.unlink(temporary)
    except OSError:
        pass

    raise
PYJSON
    then
        add_error \
            "8.1-8.3 не удалось записать прежнее состояние systemd unit в manifest"
        return 1
    fi

    return 0
}

restore_sysctl_unit_pre_state() {
    local prefix="8.1-8.3 pre-unit-enabled: "

    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        return 2
    fi

    python3 - \
        "$RESTORE_SOURCE_MANIFEST" \
        "$prefix" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
prefix = sys.argv[2]

allowed = {
    "enabled",
    "enabled-runtime",
    "masked",
    "masked-runtime",
    "disabled",
    "static",
    "indirect",
    "generated",
    "transient",
    "alias",
    "not-found",
}

try:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    apply_report = data.get("apply_report", [])

    if not isinstance(apply_report, list):
        raise ValueError("manifest apply_report is not an array")

    for entry in apply_report:
        if not isinstance(entry, str):
            raise ValueError(
                "manifest apply_report entry is not a string"
            )

    matches = [
        entry[len(prefix):]
        for entry in apply_report
        if entry.startswith(prefix)
    ]

    if len(matches) != 1:
        raise ValueError(
            "expected exactly one pre-unit-enabled record"
        )

    state = matches[0]

    if state not in allowed:
        raise ValueError(
            f"unsupported pre-unit-enabled state: {state}"
        )

    print(state)
except Exception as exc:
    print(
        f"restore systemd unit pre-state failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)
PYJSON
}

apply_sysctl_network_module() {
    if (( DRY_RUN == 1 )); then
        log "[i]     [DRY-RUN] write '$SYSCTL_NETWORK_DROPIN'"
        add_skipped "8.1-8.3 dry-run: network sysctl protections would be enforced"
        return 0
    fi
    local backup_path=""
    local existed_before=0
    local network_content="$SYSCTL_NETWORK_CONTENT"
    local sysctl_network_ok=0

    if [[ -e "$SYSCTL_NETWORK_DROPIN" \
        || -L "$SYSCTL_NETWORK_DROPIN" ]]
    then
        existed_before=1
        backup_path="$STATE_DIR/$(basename "$SYSCTL_NETWORK_DROPIN").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$SYSCTL_NETWORK_DROPIN" \
            "$backup_path" \
            "8.1-8.3 sysctl network"
        then
            add_skipped \
                "8.1-8.3 apply skipped: backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$SYSCTL_NETWORK_DROPIN" \
            "$backup_path"
        then
            add_error \
                "8.1-8.3 apply skipped: backup mapping не записан"

            if ! rm -f -- "$backup_path"; then
                add_warning \
                    "8.1-8.3 не удалось удалить незарегистрированный backup $backup_path"
            fi

            return 1
        fi
    fi
    if profile_allows paranoid; then
        network_content+=$'net.ipv4.tcp_timestamps = 0\n'
    fi
    if ! record_sysctl_runtime_snapshot \
        "network" "$network_content"
    then
        add_skipped \
            "8.1-8.3 apply skipped: runtime snapshot failed"
        return 1
    fi

    if ! mkdir -p -- \
        "$(dirname "$SYSCTL_NETWORK_DROPIN")"
    then
        add_error \
            "8.1-8.3 не удалось создать каталог sysctl drop-in"
        return 1
    fi

    if ! prepare_created_file_transaction \
        "$SYSCTL_NETWORK_DROPIN" \
        "$existed_before" \
        "8.1-8.3 network sysctl"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$SYSCTL_NETWORK_DROPIN" \
        0644 \
        python3 - "$network_content" <<'PYNETWORKWRITE'
import sys

sys.stdout.write(sys.argv[1])
PYNETWORKWRITE
    then
        add_error \
            "8.1-8.3 не удалось атомарно записать $SYSCTL_NETWORK_DROPIN"

        record_manifest_warning \
            "8.1-8.3 atomic network sysctl write failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        return 1
    fi

    if (( existed_before == 0 )); then
        if ! record_manifest_created_file \
            "$SYSCTL_NETWORK_DROPIN" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "8.1-8.3 созданный sysctl drop-in не записан в manifest"

            if ! rm -f -- "$SYSCTL_NETWORK_DROPIN"; then
                add_warning \
                    "8.1-8.3 не удалось удалить незарегистрированный файл $SYSCTL_NETWORK_DROPIN"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$SYSCTL_NETWORK_DROPIN"

    record_manifest_apply_report \
        "8.1-8.3 enforced via $SYSCTL_NETWORK_DROPIN"

    if sysctl -p "$SYSCTL_NETWORK_DROPIN" \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        sysctl_network_ok=1
    fi

    if (( sysctl_network_ok == 1 )); then
        add_safe \
            "8.1-8.3 network sysctl protections enforced via drop-in: $SYSCTL_NETWORK_DROPIN"
    else
        add_error \
            "8.1-8.3 network sysctl drop-in записан, но sysctl -p завершился с ошибкой"

        record_manifest_warning \
            "8.1-8.3 sysctl -p failed after writing $SYSCTL_NETWORK_DROPIN" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        return 1
    fi
    # log_martians сбрасывается при поднятии интерфейса — создаём systemd unit
    local sysctl_unit="/etc/systemd/system/securelinux-ng-sysctl.service"
    local unit_existed_before=0
    local unit_enabled_before=""
    local service_rc=0

    if ! unit_enabled_before="$(
        read_systemd_unit_enabled_state \
            securelinux-ng-sysctl.service
    )"
    then
        add_error \
            "8.1-8.3 не удалось определить прежнее состояние securelinux-ng-sysctl.service"
        return 1
    fi

    if ! prepare_systemd_service_transaction \
        "sysctl-network" \
        "securelinux-ng-sysctl.service" \
        "enable-only"
    then
        add_skipped \
            "8.1-8.3 systemd unit не изменён: typed service-state не записан"
        return 1
    fi

    if [[ -e "$sysctl_unit" || -L "$sysctl_unit" ]]; then
        unit_existed_before=1

        local unit_backup="$STATE_DIR/$(basename "$sysctl_unit").bak-$TIMESTAMP"

        if ! backup_file_checked             "$sysctl_unit"             "$unit_backup"             "8.1-8.3 network sysctl systemd unit"
        then
            add_error "8.1-8.3 существующий systemd unit не изменён: backup failed"
            record_manifest_warning \
                "8.1-8.3 systemd unit backup failed" \
                2>>"${DEBUG_LOG_FILE:-/dev/null}" \
                || true
            return 1
        fi

        if ! record_manifest_backup \
            "$sysctl_unit" \
            "$unit_backup"
        then
            add_error \
                "8.1-8.3 systemd unit не изменён: backup mapping не записан"

            if ! rm -f -- "$unit_backup"; then
                add_warning \
                    "8.1-8.3 не удалось удалить незарегистрированный backup $unit_backup"
            fi

            return 1
        fi
    fi


    case "$unit_enabled_before" in
        masked)
            systemctl unmask securelinux-ng-sysctl.service                 >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true
            ;;
        masked-runtime)
            systemctl unmask --runtime securelinux-ng-sysctl.service                 >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || true
            ;;
    esac

    if [[ -L "$sysctl_unit" ]]; then
        if ! rm -f -- "$sysctl_unit"; then
            add_error "8.1-8.3 не удалось удалить прежний symlink unit"
            return 1
        fi
    fi

    if ! prepare_created_file_transaction \
        "$sysctl_unit" \
        "$unit_existed_before" \
        "8.1-8.3 network sysctl unit"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$sysctl_unit" \
        0644 \
        python3 - "$SYSCTL_NETWORK_DROPIN" <<'PYSYSTEMDUNIT'
import sys

dropin = sys.argv[1]

sys.stdout.write(
    "[Unit]\n"
    "Description=SecureLinux-NG: reapply network sysctl after network\n"
    "After=network-online.target\n"
    "Wants=network-online.target\n"
    "\n"
    "[Service]\n"
    "Type=oneshot\n"
    f"ExecStart=/sbin/sysctl -p {dropin}\n"
    "RemainAfterExit=yes\n"
    "\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n"
)
PYSYSTEMDUNIT
    then
        add_error \
            "8.1-8.3 не удалось атомарно записать systemd unit: $sysctl_unit"

        record_manifest_warning \
            "8.1-8.3 atomic systemd unit write failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        return 1
    fi

    if (( unit_existed_before == 0 )); then
        if ! record_manifest_created_file \
            "$sysctl_unit" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "8.1-8.3 созданный systemd unit не записан в manifest"

            if ! rm -f -- "$sysctl_unit"; then
                add_warning \
                    "8.1-8.3 не удалось удалить незарегистрированный unit $sysctl_unit"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort "$sysctl_unit"

    if ! systemctl daemon-reload         >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_error "8.1-8.3 systemctl daemon-reload завершился с ошибкой"
        record_manifest_warning \
            "8.1-8.3 systemctl daemon-reload failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true
        return 1
    fi

    systemctl enable securelinux-ng-sysctl.service \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || service_rc=$?

    if ! commit_systemd_service_transaction \
        "sysctl-network" \
        "securelinux-ng-sysctl.service"
    then
        return 1
    fi

    if (( service_rc != 0 )); then
        add_error \
            "8.1-8.3 systemd unit записан, но enable завершился с ошибкой"
        record_manifest_warning \
            "8.1-8.3 systemd unit enable failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true
        return 1
    fi

    add_safe \
        "8.1-8.3 systemd unit создан или обновлён и включён"
    return 0
}

restore_sysctl_network_module() {
    local sysctl_unit="/etc/systemd/system/securelinux-ng-sysctl.service"
    local unit_backup=""
    local unit_enabled_before=""
    local created_file_rc=0
    local unit_tracked=0
    local rc=0

    if ! unit_backup="$(restore_lookup_backup "$sysctl_unit")"; then
        add_error \
            "restore network sysctl: не удалось прочитать backup unit из manifest"
        return 1
    fi

    if [[ -n "$unit_backup" ]]; then
        created_file_rc=1
        unit_tracked=1
    else
        restore_has_created_file "$sysctl_unit"
        created_file_rc=$?
        case "$created_file_rc" in
            0) unit_tracked=1 ;;
            1) unit_tracked=0 ;;
            *) return 1 ;;
        esac
    fi

    if (( unit_tracked == 1 )); then
        systemctl disable securelinux-ng-sysctl.service \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
        systemctl disable --runtime securelinux-ng-sysctl.service \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1

        if ! restore_file_from_manifest "$sysctl_unit"; then
            rc=1
        elif ! systemctl daemon-reload \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            add_warning \
                "restore network sysctl: systemctl daemon-reload завершился с ошибкой"
            rc=1
        fi
    fi

    if ! restore_systemd_service_transaction \
        "sysctl-network" \
        "securelinux-ng-sysctl.service" \
        "network sysctl"
    then
        rc=1
    elif (( SERVICE_TRANSACTION_FOUND == 0 && unit_tracked == 1 )); then
        if ! unit_enabled_before="$(restore_sysctl_unit_pre_state)"; then
            add_error \
                "restore network sysctl: typed и legacy pre-state отсутствуют или повреждены"
            rc=1
        else
            case "$unit_enabled_before" in
                enabled)
                    systemctl enable securelinux-ng-sysctl.service \
                        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
                    ;;
                enabled-runtime)
                    systemctl enable --runtime securelinux-ng-sysctl.service \
                        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
                    ;;
                masked)
                    systemctl mask securelinux-ng-sysctl.service \
                        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
                    ;;
                masked-runtime)
                    systemctl mask --runtime securelinux-ng-sysctl.service \
                        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || rc=1
                    ;;
                disabled|static|indirect|generated|transient|alias|not-found)
                    :
                    ;;
                *)
                    add_error \
                        "restore network sysctl: неизвестное legacy enabled-состояние $unit_enabled_before"
                    rc=1
                    ;;
            esac
        fi
    fi

    if ! restore_file_from_manifest "$SYSCTL_NETWORK_DROPIN"; then
        rc=1
    fi

    if ! restore_sysctl_runtime_snapshot \
        "network" "$SYSCTL_NETWORK_DROPIN"
    then
        rc=1
    fi

    return "$rc"
}

apply_sudo_command_paths_module() {
    local sudo_command_scan_output=""
    local item reason
    local backup_path=""
    local module_rc=0

    if (( DRY_RUN == 1 )); then
        if ! sudo_command_scan_output="$(check_sudo_command_paths_module)"; then
            add_error "2.3.4 dry-run: sudo command paths scan завершился с ошибкой"
            return 1
        fi

        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.3.4 sudo command scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.3.4 would review '$a' reason='$b'"
                    ;;
            esac
        done <<< "$sudo_command_scan_output"

        add_skipped "2.3.4 dry-run: file owner/permission remediation would be applied; parent directories require manual review"
        return 0
    fi

    if ! sudo_command_scan_output="$(check_sudo_command_paths_module)"; then
        add_error "2.3.4 apply: sudo command paths scan завершился с ошибкой"
        return 1
    fi

    while IFS=$'\t' read -r kind item reason _; do
        [[ -n "${kind:-}" ]] || continue
        [[ "$kind" == "RISK" ]] || continue
        if [[ "$reason" == *"parent_go_w:"* ]]; then
            add_warning "2.3.4 родительский каталог требует ручной проверки: ${reason#*parent_go_w:}"
        fi
        [[ "$reason" == *"file_go_w"* || "$reason" == *"owner_not_root"* ]] || continue
        [[ -f "$item" ]] || continue
        backup_path="$STATE_DIR/sudo_cmd.$(
            printf '%s' "$item" | tr '/' '_'
        ).meta-$TIMESTAMP.txt"

        if ! write_metadata_snapshot             "$item"             "$backup_path"
        then
            add_error                 "2.3.4 metadata snapshot не создан: $item"
            module_rc=1
            continue
        fi

        if ! record_manifest_backup             "$item"             "$backup_path"
        then
            add_error                 "2.3.4 backup mapping не записан: $item"

            if ! rm -f -- "$backup_path"; then
                add_warning                     "2.3.4 не удалось удалить незарегистрированный snapshot $backup_path"
            fi

            module_rc=1
            continue
        fi

        chmod go-w "$item" && chown root:root "$item" && {
            record_manifest_modified_file_best_effort "$item"
            record_manifest_apply_report                 "2.3.4 chmod go-w + chown root: $item"
        } || add_warning             "2.3.4 chmod go-w / chown root failed: $item"
    done <<< "$sudo_command_scan_output"

    if (( module_rc != 0 )); then
        add_warning             "2.3.4 sudo command paths обработаны с ошибками snapshot/manifest"
        return 1
    fi

    add_safe         "2.3.4 sudo command paths permissions processed"
    return 0
}

resolve_restore_manifest() {
    if [[ -n "$RESTORE_MANIFEST" ]]; then
        [[ -f "$RESTORE_MANIFEST" ]] || die "Manifest для restore не найден: $RESTORE_MANIFEST"
        RESTORE_SOURCE_MANIFEST="$RESTORE_MANIFEST"
        return 0
    fi

    [[ -d "$STATE_DIR" ]] || die "STATE_DIR не найден: $STATE_DIR"

    if ! RESTORE_SOURCE_MANIFEST="$(
        python3 - "$STATE_DIR" <<'PYJSON'
import pathlib
import re
import sys

base = pathlib.Path(sys.argv[1])

items = sorted(
    item
    for item in base.glob("manifest-*.json")
    if item.is_file() and not item.is_symlink()
)
if items:
    print(items[-1])
    raise SystemExit(0)

current = base / "manifest.json"
if current.is_file() and not current.is_symlink():
    print(current)
    raise SystemExit(0)

archive_pattern = re.compile(
    r"^.+[.]json[.]bak-([0-9]{8}-[0-9]{6})$"
)
archives = []
for item in base.iterdir():
    if item.is_symlink() or not item.is_file():
        continue
    match = archive_pattern.fullmatch(item.name)
    if match is None:
        continue
    archives.append((match.group(1), item.name, item))

if archives:
    print(max(archives)[2])
else:
    print("")
PYJSON
)"; then
        die "Не удалось определить manifest для restore в $STATE_DIR"
    fi
    [[ -n "$RESTORE_SOURCE_MANIFEST" ]] || die "Не найден manifest для restore в $STATE_DIR"
    [[ -f "$RESTORE_SOURCE_MANIFEST" ]] || die "Manifest для restore не найден: $RESTORE_SOURCE_MANIFEST"
}

restore_lookup_backup() {
    local original_path="$1"

    python3 - "$RESTORE_SOURCE_MANIFEST" "$original_path" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
original_path = sys.argv[2]

try:
    data = json.loads(
        manifest.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    backups = data.get("backups", [])

    if not isinstance(backups, list):
        raise ValueError("backups is not a list")

    for index, entry in enumerate(backups):
        if not isinstance(entry, dict):
            raise ValueError(
                f"backups[{index}] is not an object"
            )

        original = entry.get("original")
        backup = entry.get("backup")

        if not isinstance(original, str) or not original:
            raise ValueError(
                f"backups[{index}].original is not a non-empty string"
            )

        if not isinstance(backup, str) or not backup:
            raise ValueError(
                f"backups[{index}].backup is not a non-empty string"
            )

    for entry in backups:
        if entry["original"] == original_path:
            print(entry["backup"])
            raise SystemExit(0)

    print("")
except Exception as exc:
    print(
        f"restore backup lookup failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)
PYJSON
}
restore_has_created_file() {
    local target="$1"
    local rc=0

    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" ||
          ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        add_error \
            "restore manifest: source manifest недоступен при проверке created file $target"
        return 2
    fi

    python3 - "$RESTORE_SOURCE_MANIFEST" "$target" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
target = sys.argv[2]

try:
    data = json.loads(
        manifest.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    created_files = data.get("created_files", [])
    pending_created_files = data.get("pending_created_files", [])

    if not isinstance(created_files, list):
        raise ValueError("created_files is not a list")

    if not isinstance(pending_created_files, list):
        raise ValueError("pending_created_files is not a list")

    for entry in created_files + pending_created_files:
        if not isinstance(entry, str):
            raise ValueError("created-file entry is not a string")

    was_created = (
        target in created_files
        or target in pending_created_files
    )
except Exception as exc:
    print(
        f"restore created-file manifest read failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)

raise SystemExit(0 if was_created else 1)
PYJSON
    rc=$?

    if (( rc == 2 )); then
        add_error \
            "restore manifest: не удалось проверить created file $target"
    fi

    return "$rc"
}
restore_has_created_group() {
    local target="$1"
    local rc=0

    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        add_error \
            "restore manifest: source manifest недоступен при проверке created group '$target'"
        return 2
    fi

    python3 - "$RESTORE_SOURCE_MANIFEST" "$target" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
target = sys.argv[2]

try:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    created_groups = data.get("created_groups", [])
    pending_groups = data.get("pending_created_groups", [])

    if not isinstance(created_groups, list):
        raise ValueError("manifest created_groups is not an array")

    if not isinstance(pending_groups, list):
        raise ValueError(
            "manifest pending_created_groups is not an array"
        )

    for item in created_groups + pending_groups:
        if not isinstance(item, str) or not item:
            raise ValueError(
                "manifest created-group entry is not a non-empty string"
            )
except Exception as exc:
    print(
        f"restore created group read failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)

raise SystemExit(
    0
    if target in created_groups or target in pending_groups
    else 1
)
PYJSON
    rc=$?

    if (( rc == 2 )); then
        add_error \
            "restore manifest: не удалось проверить created group '$target'"
    fi

    return "$rc"
}

restore_file_from_manifest() {
    local target="$1"
    local backup=""
    local created_file_rc=0

    if ! backup="$(restore_lookup_backup "$target")"; then
        add_error \
            "restore: не удалось прочитать backup для $target из manifest"
        return 1
    fi

    if [[ -n "$backup" ]]; then
        if [[ ! -f "$backup" && ! -L "$backup" ]]; then
            add_error \
                "restore: backup для $target отсутствует: $backup"
            return 1
        fi

        if ! validate_managed_file_hardlinks \
            "$backup" \
            "restore backup"
        then
            return 1
        fi

        if [[ -e "$target" || -L "$target" ]]; then
            if ! validate_managed_file_hardlinks \
                "$target" \
                "restore target"
            then
                return 1
            fi

            if ! rm -f -- "$target"; then
                add_error "restore: не удалось удалить текущий объект $target"
                return 1
            fi
        fi

        if cp -a -- "$backup" "$target"; then
            add_safe "restore: restored $target from backup $backup"
        else
            add_error "restore: не удалось восстановить $target из $backup"
            return 1
        fi

        return 0
    fi

    restore_has_created_file "$target"
    created_file_rc=$?

    case "$created_file_rc" in
        0)
            if [[ -e "$target" || -L "$target" ]]; then
                if ! validate_managed_file_hardlinks \
                    "$target" \
                    "restore created-file target"
                then
                    return 1
                fi

                if rm -f -- "$target"; then
                    add_safe "restore: removed created file $target"
                else
                    add_error "restore: не удалось удалить созданный файл $target"
                    return 1
                fi
            else
                add_safe "restore: created file already absent $target"
            fi

            return 0
            ;;
        1)
            add_warning "restore: no backup mapping for $target"
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}
restore_ssh_root_login_module() {
    restore_file_from_manifest "$SSH_ROOT_LOGIN_DROPIN"
}

check_ssh_hardening_module() {
    if [[ ! -f "$SSH_HARDENING_DROPIN" ]]; then
        add_risky "2.1.2 SSH hardening drop-in отсутствует: $SSH_HARDENING_DROPIN"
        return 0
    fi

    local missing=() wrong=()
    local -A expected_values=(
        [X11Forwarding]="no" [MaxAuthTries]="3" [MaxSessions]="2"
        [PermitEmptyPasswords]="no" [UseDNS]="no" [GSSAPIAuthentication]="no"
        [ClientAliveInterval]="300" [ClientAliveCountMax]="2" [LoginGraceTime]="30"
        [AllowAgentForwarding]="no" [AllowTcpForwarding]="no"
        [IgnoreRhosts]="yes" [HostbasedAuthentication]="no" [LogLevel]="VERBOSE"
    )
    local param val actual

    for param in "${!expected_values[@]}"; do
        val="${expected_values[$param]}"
        actual="$(awk "/^${param}[[:space:]]/{print \$2; exit}" "$SSH_HARDENING_DROPIN" 2>/dev/null)"
        if [[ -z "$actual" ]]; then
            missing+=("$param")
        elif [[ "$actual" != "$val" ]]; then
            wrong+=("${param}=${actual}(ожидалось=${val})")
        fi
    done

    if profile_allows strict; then
        for param in KexAlgorithms Ciphers MACs Compression; do
            grep -q "^${param}" "$SSH_HARDENING_DROPIN" || missing+=("$param")
        done
    fi

    if [[ ${#missing[@]} -eq 0 && ${#wrong[@]} -eq 0 ]]; then
        add_safe "2.1.2 SSH hardening drop-in присутствует и корректен: $SSH_HARDENING_DROPIN"
    else
        local details=""
        [[ ${#missing[@]} -gt 0 ]] && details="отсутствуют: ${missing[*]}"
        [[ ${#wrong[@]} -gt 0 ]] && details="${details:+$details; }неверные значения: ${wrong[*]}"
        add_risky "2.1.2 SSH hardening drop-in: $details"
    fi
}

rollback_ssh_hardening_target() {
    local target="$1"
    local backup="$2"
    local existed_before="$3"
    local rc=0

    if ! rm -f -- "$target"; then
        rc=1
    fi

    if (( existed_before == 1 )); then
        if [[ -n "$backup" \
            && ( -f "$backup" || -L "$backup" ) ]]
        then
            if ! cp -a -- "$backup" "$target"; then
                rc=1
            fi
        else
            rc=1
        fi
    fi

    return "$rc"
}

apply_ssh_hardening_module() {
    local ssh_backup=""
    local ssh_existed=0
    local ssh_tmp=""
    local ssh_dir=""
    local content="$SSH_HARDENING_BASELINE"

    if (( DRY_RUN == 1 )); then
        log \
            "[DRY-RUN] write '$SSH_HARDENING_DROPIN' (profile: ${PROFILE})"
        add_skipped \
            "2.1.2 dry-run: SSH hardening drop-in would be written"
        return 0
    fi

    if profile_allows strict; then
        content+="$SSH_HARDENING_STRICT"
    fi

    ssh_dir="$(dirname "$SSH_HARDENING_DROPIN")"

    if ! mkdir -p -- "$ssh_dir"; then
        add_error \
            "2.1.2 не удалось создать каталог SSH drop-in"
        return 1
    fi

    if [[ -e "$SSH_HARDENING_DROPIN" \
        || -L "$SSH_HARDENING_DROPIN" ]]
    then
        ssh_existed=1
        ssh_backup="$STATE_DIR/$(basename "$SSH_HARDENING_DROPIN").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$SSH_HARDENING_DROPIN" \
            "$ssh_backup" \
            "2.1.2 SSH hardening"
        then
            add_skipped \
                "2.1.2 apply skipped: SSH backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$SSH_HARDENING_DROPIN" \
            "$ssh_backup"
        then
            add_error \
                "2.1.2 apply skipped: SSH backup mapping не записан"

            if ! rm -f -- "$ssh_backup"; then
                add_warning \
                    "2.1.2 не удалось удалить незарегистрированный backup $ssh_backup"
            fi

            return 1
        fi
    fi

    ssh_tmp="$(
        mktemp \
            "$ssh_dir/.securelinux-ng-ssh.XXXXXX"
    )" || {
        add_error \
            "2.1.2 не удалось создать временный SSH drop-in"
        return 1
    }

    if ! printf '%s' "$content" > "$ssh_tmp" \
        || ! chmod 0644 "$ssh_tmp" \
        || ! chown root:root "$ssh_tmp"
    then
        rm -f -- "$ssh_tmp" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        add_error \
            "2.1.2 не удалось подготовить SSH hardening drop-in"
        return 1
    fi

    if ! prepare_created_file_transaction \
        "$SSH_HARDENING_DROPIN" \
        "$ssh_existed" \
        "2.1.2 SSH hardening"
    then
        rm -f -- "$ssh_tmp" 2>>"${DEBUG_LOG_FILE:-/dev/null}" || true
        return 1
    fi

    if ! mv -f -- \
        "$ssh_tmp" \
        "$SSH_HARDENING_DROPIN"
    then
        rm -f -- "$ssh_tmp" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        if ! rollback_ssh_hardening_target \
            "$SSH_HARDENING_DROPIN" \
            "$ssh_backup" \
            "$ssh_existed"
        then
            add_error \
                "2.1.2 не удалось установить SSH drop-in и полностью выполнить откат"
        else
            add_error \
                "2.1.2 не удалось установить SSH hardening drop-in — выполнен откат"
        fi

        return 1
    fi

    if ! sshd -t >/dev/null 2>&1; then
        if ! rollback_ssh_hardening_target \
            "$SSH_HARDENING_DROPIN" \
            "$ssh_backup" \
            "$ssh_existed"
        then
            add_error \
                "2.1.2 sshd -t failed; откат SSH drop-in также завершился ошибкой"
        else
            add_error \
                "2.1.2 sshd -t failed после записи $SSH_HARDENING_DROPIN — выполнен откат"
        fi

        record_manifest_warning \
            "2.1.2 sshd -t failed, rolling back" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        return 1
    fi

    if (( ssh_existed == 0 )); then
        if ! record_manifest_created_file \
            "$SSH_HARDENING_DROPIN" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "2.1.2 созданный SSH drop-in не записан в manifest"

            if ! rollback_ssh_hardening_target \
                "$SSH_HARDENING_DROPIN" \
                "$ssh_backup" \
                "$ssh_existed"
            then
                add_error \
                    "2.1.2 не удалось удалить незарегистрированный SSH drop-in"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$SSH_HARDENING_DROPIN"

    record_manifest_apply_report \
        "2.1.2 SSH hardening enforced via $SSH_HARDENING_DROPIN (profile: ${PROFILE})"

    if systemctl reload sshd \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 \
        || systemctl reload ssh \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_safe \
            "2.1.2 SSH hardening drop-in written and SSH service reloaded: $SSH_HARDENING_DROPIN"
        return 0
    fi

    add_error \
        "2.1.2 SSH drop-in записан и проверен, но reload SSH-службы завершился ошибкой"

    record_manifest_warning \
        "2.1.2 SSH service reload failed after valid drop-in write" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" \
        || true

    return 1
}

restore_ssh_hardening_module() {
    restore_file_from_manifest "$SSH_HARDENING_DROPIN"
}

KERNEL_MODULE_BLACKLIST="/etc/modprobe.d/60-securelinux-ng-blacklist.conf"

KERNEL_MODULE_FILESYSTEM_MODULES=(
    cramfs
    freevxfs
    hfs
    hfsplus
    udf
    jffs2
    squashfs
)

KERNEL_MODULE_NETWORK_MODULES=(
    dccp
    sctp
    rds
    tipc
    n-hdlc
    ax25
    netrom
    x25
    rose
    decnet
    econet
    af_802154
    ipx
    appletalk
    psnap
    p8022
    p8023
)

KERNEL_MODULE_FIREWIRE_MODULES=(
    firewire-core
    firewire-ohci
    firewire-sbp2
)

FAIL2BAN_JAIL="/etc/fail2ban/jail.local"

ACCOUNT_AUDIT_FILE="/var/log/securelinux-ng/account_audit.txt"

render_account_audit_report() {
    if ! python3 - <<'PYAUDIT'
import datetime
import grp
import pwd

out = [
    "# SecureLinux-NG — Account Audit",
    "# Generated: " + datetime.datetime.now().isoformat(),
    "",
    "## Users (/etc/passwd)",
]

for entry in sorted(pwd.getpwall(), key=lambda item: item.pw_uid):
    out.append(
        f"  uid={entry.pw_uid:5d}  "
        f"{entry.pw_name:20s}  "
        f"shell={entry.pw_shell}  "
        f"home={entry.pw_dir}"
    )

out.extend([
    "",
    "## Groups (/etc/group)",
])

for entry in sorted(grp.getgrall(), key=lambda item: item.gr_gid):
    members = ", ".join(entry.gr_mem) if entry.gr_mem else "(none)"
    out.append(
        f"  gid={entry.gr_gid:5d}  "
        f"{entry.gr_name:20s}  "
        f"members={members}"
    )

out.extend([
    "",
    "## UID=0 accounts",
])

for entry in pwd.getpwall():
    if entry.pw_uid == 0:
        out.append(f"  {entry.pw_name}")

out.extend([
    "",
    "## Accounts with login shell",
])

nologin = {
    "/bin/false",
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "",
}

login_accounts = (
    entry
    for entry in pwd.getpwall()
    if entry.pw_shell not in nologin
)

for entry in sorted(login_accounts, key=lambda item: item.pw_uid):
    out.append(
        f"  uid={entry.pw_uid:5d}  "
        f"{entry.pw_name:20s}  "
        f"shell={entry.pw_shell}"
    )

out.extend([
    "",
    "## sudo/wheel/admin group members",
])

for group_name in ("sudo", "wheel", "admin"):
    try:
        group = grp.getgrnam(group_name)
    except KeyError:
        out.append(f"  group={group_name}: not found")
        continue

    members = ", ".join(group.gr_mem) if group.gr_mem else "(none)"
    out.append(f"  group={group_name}: {members}")

print("\n".join(out))
PYAUDIT
    then
        return 1
    fi

    printf '%s\n' \
        '' \
        '## Active systemd services (17.1)'

    systemctl list-units \
        --type=service \
        --state=running \
        --no-pager \
        --no-legend \
        2>/dev/null \
        | awk '{print "  " $1}' \
        | sort \
        || true

    printf '%s\n' \
        '' \
        '## Open listening ports (17.2)'

    ss -tlnp \
        2>/dev/null \
        | tail -n +2 \
        | awk '{print "  " $0}' \
        || true

    return 0
}

check_account_audit_module() {
    local required_sections=(
        "# SecureLinux-NG — Account Audit"
        "## Users (/etc/passwd)"
        "## Groups (/etc/group)"
        "## UID=0 accounts"
        "## Accounts with login shell"
        "## sudo/wheel/admin group members"
        "## Active systemd services (17.1)"
        "## Open listening ports (17.2)"
    )
    local missing=()
    local section=""

    if [[ ! -f "$ACCOUNT_AUDIT_FILE" ]]; then
        add_risky \
            "account audit: отчёт отсутствует: $ACCOUNT_AUDIT_FILE"
        return 0
    fi

    for section in "${required_sections[@]}"; do
        if ! grep -Fqx -- \
            "$section" \
            "$ACCOUNT_AUDIT_FILE"
        then
            missing+=("$section")
        fi
    done

    if (( ${#missing[@]} == 0 )); then
        add_safe \
            "account audit: отчёт присутствует и содержит все обязательные разделы: $ACCOUNT_AUDIT_FILE"
        return 0
    fi

    add_risky \
        "account audit: отчёт неполон; отсутствуют разделы: ${missing[*]}"

    return 0
}

apply_account_audit_module() {
    local account_audit_existed_before=0
    local account_audit_backup=""

    if (( DRY_RUN == 1 )); then
        log \
            "[DRY-RUN] atomically generate account audit report -> $ACCOUNT_AUDIT_FILE"
        add_skipped "account audit dry-run"
        return 0
    fi

    if ! mkdir -p -- \
        "$(dirname "$ACCOUNT_AUDIT_FILE")"
    then
        add_error \
            "account audit: не удалось создать каталог отчёта"
        return 1
    fi

    if [[ -e "$ACCOUNT_AUDIT_FILE" \
        || -L "$ACCOUNT_AUDIT_FILE" ]]
    then
        account_audit_existed_before=1
        account_audit_backup="$STATE_DIR/$(basename "$ACCOUNT_AUDIT_FILE").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$ACCOUNT_AUDIT_FILE" \
            "$account_audit_backup" \
            "account audit report"
        then
            add_skipped \
                "account audit apply skipped: backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$ACCOUNT_AUDIT_FILE" \
            "$account_audit_backup"
        then
            add_error \
                "account audit apply skipped: backup mapping не записан"

            if ! rm -f -- "$account_audit_backup"; then
                add_warning \
                    "account audit: не удалось удалить незарегистрированный backup $account_audit_backup"
            fi

            return 1
        fi
    fi

    if ! prepare_created_file_transaction \
        "$ACCOUNT_AUDIT_FILE" \
        "$account_audit_existed_before" \
        "account audit"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$ACCOUNT_AUDIT_FILE" \
        0644 \
        render_account_audit_report
    then
        add_error \
            "account audit: не удалось атомарно сформировать отчёт $ACCOUNT_AUDIT_FILE"

        record_manifest_warning \
            "account audit: report generation or atomic write failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        return 1
    fi

    if (( account_audit_existed_before == 0 )); then
        if ! record_manifest_created_file \
            "$ACCOUNT_AUDIT_FILE" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "account audit: созданный отчёт не записан в manifest"

            if ! rm -f -- "$ACCOUNT_AUDIT_FILE"; then
                add_warning \
                    "account audit: не удалось удалить незарегистрированный отчёт $ACCOUNT_AUDIT_FILE"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$ACCOUNT_AUDIT_FILE"

    record_manifest_apply_report \
        "account audit: report written to $ACCOUNT_AUDIT_FILE"

    add_safe \
        "account audit: отчёт записан: $ACCOUNT_AUDIT_FILE"

    log \
        "[i]     account audit: просмотр: cat $ACCOUNT_AUDIT_FILE"

    return 0
}

restore_account_audit_module() {
    local account_audit_backup=""
    local created_file_rc=0

    if ! account_audit_backup="$(
        restore_lookup_backup "$ACCOUNT_AUDIT_FILE"
    )"; then
        add_error \
            "restore account audit: не удалось прочитать backup из manifest"
        return 1
    fi

    if [[ -n "$account_audit_backup" ]]; then
        if ! restore_file_from_manifest "$ACCOUNT_AUDIT_FILE"; then
            return 1
        fi

        return 0
    fi

    restore_has_created_file "$ACCOUNT_AUDIT_FILE"
    created_file_rc=$?

    case "$created_file_rc" in
        0)
            if ! restore_file_from_manifest "$ACCOUNT_AUDIT_FILE"; then
                return 1
            fi

            return 0
            ;;
        1)
            log "[i]     restore account audit: файл не трекался — пропуск"
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}
check_apparmor_module() {
    if ! command -v apparmor_status >/dev/null 2>&1; then
        add_risky "AppArmor: не установлен"
        return 0
    fi
    if systemctl is-active --quiet apparmor 2>/dev/null; then
        local enforced
        enforced=$(apparmor_status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")
        if profile_allows strict; then
            add_safe "AppArmor: активен, enforce профилей: ${enforced:-?}"
        else
            add_skipped "AppArmor уже активен в системе: enforce профилей=${enforced:-?} (для baseline не требуется)"
        fi
    else
        if profile_allows strict; then
            add_risky "AppArmor: не активен"
        else
            add_skipped "AppArmor: не активен (для baseline не требуется)"
        fi
    fi
}

pkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

check_memory_requirements() {
    local mem_available_mb
    mem_available_mb=$(awk '/MemAvailable/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo "0")
    if (( mem_available_mb > 0 && mem_available_mb < 512 )); then
        log "[WARN]  Доступно менее 512MB RAM (${mem_available_mb}MB)."
        log "[WARN]  Установка крупных пакетов (AIDE, cracklib-runtime) может завершиться ошибкой."
        log "[WARN]  Рекомендуется минимум 1GB свободной RAM перед запуском --apply."
        log "[WARN]  Продолжение через 10 секунд... (Ctrl+C для отмены)"
        sleep 10
    elif (( mem_available_mb > 0 && mem_available_mb < 1024 )); then
        log "[WARN]  Доступно менее 1GB RAM (${mem_available_mb}MB) — возможны проблемы при установке пакетов."
    fi
}

apt_lock_owner() {
    local lock pid="" owner=""

    for lock in \
        /var/lib/dpkg/lock-frontend \
        /var/lib/dpkg/lock \
        /var/cache/apt/archives/lock
    do
        pid=""
        owner=""

        if command -v fuser >/dev/null 2>&1; then
            pid="$(
                fuser "$lock" 2>/dev/null |
                    awk 'NF { print $1; exit }'
            )"
        fi

        if [[ ! "$pid" =~ ^[0-9]+$ ]] \
           && command -v lslocks >/dev/null 2>&1; then
            read -r pid owner < <(
                lslocks -n -o PID,COMMAND,PATH 2>/dev/null |
                    awk -v path="$lock" \
                        '$3 == path { print $1, $2; exit }'
            )
        fi

        if [[ "$pid" =~ ^[0-9]+$ ]]; then
            if [[ -z "$owner" ]] \
               && command -v ps >/dev/null 2>&1; then
                owner="$(
                    ps -p "$pid" -o comm= 2>/dev/null |
                        awk 'NF { print; exit }'
                )"
            fi

            [[ -n "$owner" ]] || owner="неизвестный процесс"
            printf '%s\t%s\n' "$pid" "$owner"
            return 0
        fi
    done

    return 1
}

wait_for_dpkg_lock() {
    local lock_wait=0
    local interactive=0
    local owner_info=""
    local owner_pid=""
    local owner_name=""

    [[ -t 1 ]] && interactive=1

    while owner_info="$(apt_lock_owner)"; do
        IFS=$'\t' read -r owner_pid owner_name <<< "$owner_info"

        if (( lock_wait == 0 )); then
            if (( interactive == 1 )); then
                printf '\r\033[2K[i] apt/dpkg занят: %s PID=%s; ожидание %s с — скрипт не завис' \
                    "$owner_name" "$owner_pid" "$lock_wait"
            else
                log "[i]     apt/dpkg занят: ${owner_name} PID=${owner_pid}; ожидаем освобождения блокировки"
            fi
        fi

        sleep 3
        (( lock_wait += 3 ))

        if (( interactive == 1 && lock_wait % 30 == 0 )); then
            printf '\r\033[2K[i] apt/dpkg занят: %s PID=%s; ожидание %s с — скрипт не завис' \
                "$owner_name" "$owner_pid" "$lock_wait"
        fi
    done

    if (( lock_wait > 0 )); then
        (( interactive == 1 )) && printf '\r\033[2K'
        log "[OK]    apt: блокировка освобождена через ${lock_wait} с, продолжаем"
    fi
}

apt_update_once() {
    wait_for_dpkg_lock
    if (( _APT_UPDATED == 1 )); then return 0; fi
    log "[i]     apt-get update..."
    if DEBIAN_FRONTEND=noninteractive apt-get update -q >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        _APT_UPDATED=1
    else
        add_warning "apt-get update завершился с ошибкой — последующие установки пакетов могут не работать"
    fi
}

apply_apparmor_module() {
    if ! profile_allows strict; then
        add_skipped "AppArmor пропущен: требуется профиль strict или paranoid (текущий: ${PROFILE})"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install apparmor apparmor-utils, enable service"
        add_skipped "AppArmor dry-run"
        return 0
    fi

    if ! prepare_systemd_service_transaction \
        "apparmor" \
        "apparmor.service" \
        "enable-now"
    then
        return 1
    fi

    log "[i]     AppArmor: установка пакетов..."
    apt_update_once
    local apparmor_was_installed=0
    local service_rc=0
    pkg_installed apparmor && apparmor_was_installed=1
    if (( apparmor_was_installed == 0 )); then
        install_packages_transactionally \
            "apparmor" \
            apparmor \
            apparmor-utils || true

        if (( PACKAGE_TRANSACTION_TRACKING_RC != 0 )); then
            add_error "AppArmor: package transaction не зафиксирована"
            record_manifest_warning "AppArmor: package transaction tracking failed"
            return 1
        fi

        if (( PACKAGE_TRANSACTION_INSTALL_RC != 0 )); then
            add_error "AppArmor: не удалось установить пакеты"
            record_manifest_warning "AppArmor: apt-get install failed"
            return 1
        fi
    fi

    systemctl enable --now apparmor.service \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || service_rc=$?

    if ! commit_systemd_service_transaction \
        "apparmor" \
        "apparmor.service"
    then
        return 1
    fi

    if (( service_rc != 0 )); then
        add_error "AppArmor: systemctl enable --now завершился с ошибкой"
        record_manifest_warning "AppArmor: systemctl enable --now failed"
        return 1
    fi

    if (( apparmor_was_installed == 1 )); then
        local enforced
        enforced=$(apparmor_status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "?")
        add_warning "AppArmor: уже установлен, профили не изменены. Для enforce: aa-enforce /etc/apparmor.d/*"
        record_manifest_warning "AppArmor: pre-installed, profiles not modified"
        return 0
    fi

    if command -v aa-enforce >/dev/null 2>&1; then
        aa-enforce /etc/apparmor.d/* >/dev/null 2>&1 || true
        record_manifest_apply_report "AppArmor: aa-enforce applied to /etc/apparmor.d/*"
    fi

    local enforced
    enforced=$(apparmor_status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "?")
    add_safe "AppArmor: включён, enforce профилей: ${enforced:-?}"
    record_manifest_apply_report "AppArmor: enabled and enforce mode set"
    record_manifest_irreversible_change "AppArmor: enforce mode — для отката: aa-complain /etc/apparmor.d/*"
}

restore_apparmor_module() {
    local rc=0

    if ! profile_allows strict; then
        log "[i]     restore AppArmor: модуль не применялся для текущего профиля — пропуск"
        return 0
    fi

    if ! restore_systemd_service_transaction \
        "apparmor" \
        "apparmor.service" \
        "AppArmor"
    then
        rc=1
    fi

    if ! report_installed_packages_for_manual_restore \
        "apparmor" \
        "AppArmor"
    then
        rc=1
    fi

    add_warning \
        "restore AppArmor: service-state восстановлен автоматически; aa-enforce для свежей установки откатывается вручную через aa-complain /etc/apparmor.d/*"

    return "$rc"
}

check_aide_module() {
    if ! profile_allows strict; then
        add_skipped "AIDE пропущен: требуется профиль strict или paranoid (текущий: ${PROFILE})"
        return 0
    fi
    if ! command -v aide >/dev/null 2>&1; then
        add_risky "AIDE: не установлен"
        return 0
    fi
    if [[ -f /var/lib/aide/aide.db ]]; then
        add_safe "AIDE: база данных присутствует: /var/lib/aide/aide.db"
    else
        add_risky "AIDE: база данных отсутствует (требуется aide --init)"
    fi
}

apply_aide_module() {
    if ! profile_allows strict; then
        add_skipped "AIDE пропущен: требуется профиль strict или paranoid (текущий: ${PROFILE})"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install aide, aide --init"
        add_skipped "AIDE dry-run: would install and init database"
        return 0
    fi

    log "[i]     AIDE: установка пакета..."
    apt_update_once
    if ! pkg_installed aide; then
        install_packages_transactionally "aide" aide || true

        if (( PACKAGE_TRANSACTION_TRACKING_RC != 0 )); then
            add_error "AIDE: package transaction не зафиксирована"
            record_manifest_warning "AIDE: package transaction tracking failed"
            return 1
        fi

        if (( PACKAGE_TRANSACTION_INSTALL_RC != 0 )); then
            add_warning "AIDE: не удалось установить пакет"
            record_manifest_warning "AIDE: apt-get install failed"
            return 0
        fi
    fi

    if [[ -f /var/lib/aide/aide.db ]]; then
        add_safe "AIDE: база данных уже существует, инициализация пропущена"
        return 0
    fi
    log "[i]     AIDE: инициализация базы данных — не прерывайте процесс, может занять 3–10 минут..."
    if aide --config /etc/aide/aide.conf --init >/dev/null 2>&1; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
        record_manifest_apply_report "AIDE: database initialized at /var/lib/aide/aide.db"
        record_manifest_irreversible_change "AIDE: база данных создана — обновлять после изменений: aide --update"
        add_safe "AIDE: база данных инициализирована"
        add_warning "AIDE: запускайте 'aide --check' после перезагрузки для проверки целостности"
    else
        add_warning "AIDE: aide --init завершился с ошибкой — проверьте вручную"
        record_manifest_warning "AIDE: aide --init failed"
    fi
}

restore_aide_module() {
    local rc=0

    if ! profile_allows strict; then
        log "[i]     restore AIDE: модуль не применялся для текущего профиля — пропуск"
        return 0
    fi

    if ! report_installed_packages_for_manual_restore         "aide"         "AIDE"
    then
        rc=1
    fi

    # AIDE не имеет backup-файла — при restore только сообщаем
    log "[i]     restore AIDE: база данных не восстанавливается автоматически"
    add_warning "restore AIDE: удалите /var/lib/aide/aide.db вручную если требуется откат"

    return "$rc"
}

valid_tcp_port() {
    local value="${1:-}"

    [[ "$value" =~ ^[0-9]+$ ]] || return 1
    (( ${#value} <= 5 )) || return 1
    (( 10#$value >= 1 && 10#$value <= 65535 ))
}

resolve_ssh_port() {
    local fallback="${1:-22}"
    local detected=""

    if ! valid_tcp_port "$fallback"; then
        add_warning "SSH port fallback '$fallback' некорректен — используется 22"
        record_manifest_warning "SSH port fallback invalid: $fallback; using 22"
        fallback="22"
    fi

    detected=$(
        grep -Ei '^\s*Port\s+'             /etc/ssh/sshd_config.d/*.conf 2>/dev/null |
        awk '{print $2}' |
        head -n 1
    )

    if [[ -z "$detected" ]]; then
        detected=$(
            grep -Ei '^\s*Port\s+'                 /etc/ssh/sshd_config 2>/dev/null |
            awk '{print $2}' |
            head -n 1
        )
    fi

    if [[ -n "$detected" ]]; then
        if valid_tcp_port "$detected"; then
            fallback="$detected"
        else
            add_warning "SSH Port '$detected' некорректен — используется fallback $fallback"
            record_manifest_warning "invalid SSH Port value: $detected; using $fallback"
        fi
    fi

    SSH_PORT_RESOLVED="$fallback"
}

render_fail2ban_jail() {
    local ssh_port="$1"

    cat <<JAILEOF
# Managed by SecureLinux-NG — fail2ban SSH jail
# Не редактируйте jail.conf — он перезаписывается при обновлении пакета.

[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
backend  = systemd

[sshd]
enabled  = true
port     = ${ssh_port}
filter   = sshd
logpath  = %(sshd_log)s
maxretry = 5
bantime  = 3600
JAILEOF
}

read_fail2ban_service_active_state() {
    local state=""
    local command_rc=0

    state="$(
        systemctl is-active fail2ban.service \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
    )" || command_rc=$?

    case "$state" in
        active|activating|reloading)
            printf '%s\n' "active"
            return 0
            ;;
        inactive|failed|deactivating|maintenance)
            printf '%s\n' "inactive"
            return 0
            ;;
        "")
            printf \
                'systemctl is-active returned no state for fail2ban.service (rc=%s)\n' \
                "$command_rc" \
                >&2
            return 1
            ;;
        *)
            printf \
                'systemctl is-active returned unsupported state for fail2ban.service: %s (rc=%s)\n' \
                "$state" \
                "$command_rc" \
                >&2
            return 1
            ;;
    esac
}

record_fail2ban_service_pre_state() {
    local enabled_state="$1"
    local active_state="$2"
    local prefix="fail2ban pre-service-state: "

    case "$enabled_state" in
        enabled|enabled-runtime|masked|masked-runtime|disabled|static|indirect|generated|transient|alias|not-found)
            ;;
        *)
            add_error \
                "fail2ban: некорректное прежнее enabled-состояние службы: $enabled_state"
            return 1
            ;;
    esac

    case "$active_state" in
        active|inactive)
            ;;
        *)
            add_error \
                "fail2ban: некорректное прежнее active-состояние службы: $active_state"
            return 1
            ;;
    esac

    case "${enabled_state}:${active_state}" in
        masked:active|masked-runtime:active|not-found:active)
            add_error \
                "fail2ban: противоречивое прежнее состояние службы: enabled=${enabled_state}, active=${active_state}"
            return 1
            ;;
    esac

    if [[ -z "${MANIFEST_FILE:-}" \
        || ! -f "${MANIFEST_FILE:-}" ]]
    then
        add_error \
            "fail2ban: manifest недоступен при записи прежнего состояния службы"
        return 1
    fi

    if ! python3 - \
        "$MANIFEST_FILE" \
        "$prefix" \
        "$enabled_state" \
        "$active_state" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
prefix = sys.argv[2]
enabled = sys.argv[3]
active = sys.argv[4]

data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

apply_report = data.setdefault("apply_report", [])

if not isinstance(apply_report, list):
    raise ValueError("manifest apply_report is not an array")

for entry in apply_report:
    if not isinstance(entry, str):
        raise ValueError(
            "manifest apply_report entry is not a string"
        )

value = (
    f"{prefix}"
    f"enabled={enabled};"
    f"active={active}"
)

matches = [
    entry
    for entry in apply_report
    if entry.startswith(prefix)
]

if len(matches) > 1:
    raise ValueError(
        "multiple fail2ban pre-service-state records exist"
    )

if matches:
    if matches[0] != value:
        raise ValueError(
            "conflicting fail2ban pre-service-state record exists"
        )

    raise SystemExit(0)

apply_report.append(value)

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    payload = (
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ) + "\n"
    ).encode("utf-8")

    os.write(fd, payload)
    os.fsync(fd)
    os.close(fd)
    os.replace(temporary, path)
except Exception:
    try:
        os.close(fd)
    except OSError:
        pass

    try:
        os.unlink(temporary)
    except OSError:
        pass

    raise
PYJSON
    then
        add_error \
            "fail2ban: не удалось записать прежнее состояние службы в manifest"
        return 1
    fi

    return 0
}

restore_fail2ban_service_pre_state() {
    local prefix="fail2ban pre-service-state: "

    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        return 2
    fi

    python3 - \
        "$RESTORE_SOURCE_MANIFEST" \
        "$prefix" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
prefix = sys.argv[2]

allowed_enabled = {
    "enabled",
    "enabled-runtime",
    "masked",
    "masked-runtime",
    "disabled",
    "static",
    "indirect",
    "generated",
    "transient",
    "alias",
    "not-found",
}

allowed_active = {
    "active",
    "inactive",
}

try:
    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError(
            "manifest root is not an object"
        )

    apply_report = data.get("apply_report", [])

    if not isinstance(apply_report, list):
        raise ValueError(
            "manifest apply_report is not an array"
        )

    for entry in apply_report:
        if not isinstance(entry, str):
            raise ValueError(
                "manifest apply_report entry is not a string"
            )

    matches = [
        entry[len(prefix):]
        for entry in apply_report
        if entry.startswith(prefix)
    ]

    if not matches:
        raise SystemExit(1)

    if len(matches) != 1:
        raise ValueError(
            "expected exactly one fail2ban pre-service-state record"
        )

    match = re.fullmatch(
        r"enabled=([^;]+);active=([^;]+)",
        matches[0],
    )

    if match is None:
        raise ValueError(
            "malformed fail2ban pre-service-state record"
        )

    enabled, active = match.groups()

    if enabled not in allowed_enabled:
        raise ValueError(
            f"unsupported fail2ban enabled state: {enabled}"
        )

    if active not in allowed_active:
        raise ValueError(
            f"unsupported fail2ban active state: {active}"
        )

    if (
        enabled in {
            "masked",
            "masked-runtime",
            "not-found",
        }
        and active == "active"
    ):
        raise ValueError(
            "contradictory fail2ban service state"
        )

    print(f"{enabled}\t{active}")
except SystemExit:
    raise
except Exception as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(2)
PYJSON
}

restore_fail2ban_service_state() {
    local enabled_state="$1"
    local active_state="$2"
    local current_enabled=""

    case "$enabled_state" in
        enabled)
            if ! systemctl unmask fail2ban.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi

            if ! systemctl enable fail2ban.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
        enabled-runtime)
            if ! systemctl unmask fail2ban.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi

            if ! systemctl enable --runtime fail2ban.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
        disabled)
            if ! systemctl unmask fail2ban.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi

            if ! systemctl disable fail2ban.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
        not-found)
            if ! current_enabled="$(
                read_systemd_unit_enabled_state \
                    fail2ban.service
            )"
            then
                return 1
            fi

            if [[ "$current_enabled" != "not-found" ]]; then
                if ! systemctl disable fail2ban.service \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
                then
                    return 1
                fi
            fi
            ;;
        static|indirect|generated|transient|alias|masked|masked-runtime)
            ;;
        *)
            return 1
            ;;
    esac

    case "$active_state" in
        active)
            if ! systemctl restart fail2ban.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
        inactive)
            if ! systemctl stop fail2ban.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                if systemctl is-active --quiet fail2ban.service \
                    2>>"${DEBUG_LOG_FILE:-/dev/null}"
                then
                    return 1
                fi
            fi
            ;;
        *)
            return 1
            ;;
    esac

    case "$enabled_state" in
        masked)
            if ! systemctl mask fail2ban.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
        masked-runtime)
            if ! systemctl mask --runtime fail2ban.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
    esac

    return 0
}

check_fail2ban_module() {
    if ! profile_allows paranoid; then
        add_skipped "fail2ban пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        add_risky "fail2ban: не установлен"
        return 0
    fi
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        add_safe "fail2ban: служба активна"
    else
        add_risky "fail2ban: служба не активна"
    fi
    if [[ -f "$FAIL2BAN_JAIL" ]] && grep -q '^\[sshd\]' "$FAIL2BAN_JAIL" 2>/dev/null; then
        add_safe "fail2ban: SSH jail настроен"
    else
        add_risky "fail2ban: SSH jail не настроен"
    fi
}

apply_fail2ban_module() {
    local enabled_before=""
    local active_before=""
    local jail_existed_before_dependencies=0
    local jail_backup=""
    local package_install_rc=0
    local package_tracking_rc=0
    local ssh_port="22"

    if ! profile_allows paranoid; then
        add_skipped \
            "fail2ban пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log \
            "[DRY-RUN] install fail2ban, atomically write ${FAIL2BAN_JAIL}"
        add_skipped "fail2ban dry-run"
        return 0
    fi

    if ! enabled_before="$(
        read_systemd_unit_enabled_state \
            fail2ban.service
    )"
    then
        add_error \
            "fail2ban: не удалось определить исходное enabled-состояние службы"
        return 1
    fi

    if ! active_before="$(
        read_fail2ban_service_active_state
    )"
    then
        add_error \
            "fail2ban: не удалось определить исходное active-состояние службы"
        return 1
    fi

    if ! record_fail2ban_service_pre_state \
        "$enabled_before" \
        "$active_before"
    then
        return 1
    fi

    if [[ -f "$FAIL2BAN_JAIL" \
        || -L "$FAIL2BAN_JAIL" ]]
    then
        jail_existed_before_dependencies=1
        jail_backup="$STATE_DIR/jail.local.bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$FAIL2BAN_JAIL" \
            "$jail_backup" \
            "fail2ban"
        then
            add_skipped \
                "fail2ban apply skipped: backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$FAIL2BAN_JAIL" \
            "$jail_backup"
        then
            add_error \
                "fail2ban apply skipped: backup mapping не записан"

            if ! rm -f -- "$jail_backup"; then
                add_warning \
                    "fail2ban: не удалось удалить незарегистрированный backup $jail_backup"
            fi

            return 1
        fi
    elif [[ -e "$FAIL2BAN_JAIL" ]]; then
        add_error \
            "fail2ban: $FAIL2BAN_JAIL существует, но не является обычным файлом или символьной ссылкой"
        return 1
    fi

    if ! prepare_created_file_transaction \
        "$FAIL2BAN_JAIL" \
        "$jail_existed_before_dependencies" \
        "fail2ban jail.local"
    then
        return 1
    fi

    if ! pkg_installed fail2ban; then
        log "[i]     fail2ban: установка пакета..."
        apt_update_once

        install_packages_transactionally \
            "fail2ban" \
            fail2ban || true

        package_install_rc=$PACKAGE_TRANSACTION_INSTALL_RC
        package_tracking_rc=$PACKAGE_TRANSACTION_TRACKING_RC

        if (( package_install_rc != 0 )); then
            add_error \
                "fail2ban: не удалось установить пакет"
            record_manifest_warning \
                "fail2ban: apt-get install failed"
            return 1
        fi

        if (( package_tracking_rc != 0 )); then
            add_error \
                "fail2ban: пакет установлен, но учёт новых пакетов не выполнен"
            record_manifest_warning \
                "fail2ban: installed package tracking failed"
            return 1
        fi
    fi

    if ! pkg_installed fail2ban; then
        add_error \
            "fail2ban: пакет отсутствует после установки"
        return 1
    fi

    if ! command -v fail2ban-client \
        >/dev/null 2>&1
    then
        add_error \
            "fail2ban: команда fail2ban-client отсутствует"
        return 1
    fi

    resolve_ssh_port "$ssh_port"
    ssh_port="$SSH_PORT_RESOLVED"

    if ! mkdir -p -- \
        "$(dirname "$FAIL2BAN_JAIL")"
    then
        add_error \
            "fail2ban: не удалось создать каталог конфигурации"
        return 1
    fi

    if (( jail_existed_before_dependencies == 1 )); then
        if ! grep -Eq \
            '^[[:space:]]*\[sshd\][[:space:]]*$' \
            "$FAIL2BAN_JAIL"
        then
            add_error \
                "fail2ban: существующий $FAIL2BAN_JAIL сохранён, но секция [sshd] отсутствует"
            return 1
        fi

        if ! fail2ban-client -t \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            add_error \
                "fail2ban: существующая конфигурация не прошла проверку"
            return 1
        fi

        record_manifest_apply_report \
            "fail2ban: pre-existing jail.local kept"

        if ! systemctl enable --now fail2ban.service \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            add_error \
                "fail2ban: не удалось включить и запустить службу"
            return 1
        fi

        if ! systemctl is-active --quiet fail2ban.service \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "fail2ban: служба не активна после enable --now"
            return 1
        fi

        add_safe \
            "fail2ban: существующий SSH jail сохранён, конфигурация корректна, служба активна"

        return 0
    fi

    if [[ -e "$FAIL2BAN_JAIL" \
        || -L "$FAIL2BAN_JAIL" ]]
    then
        if ! record_manifest_created_file \
            "$FAIL2BAN_JAIL" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "fail2ban: появившийся при установке jail.local не записан в manifest"
            return 1
        fi

        add_error \
            "fail2ban: $FAIL2BAN_JAIL появился во время установки пакета и не был перезаписан"

        record_manifest_warning \
            "fail2ban: jail.local appeared during package installation"

        return 1
    fi

    if ! atomic_write_command_output \
        "$FAIL2BAN_JAIL" \
        0644 \
        render_fail2ban_jail \
        "$ssh_port"
    then
        add_error \
            "fail2ban: не удалось атомарно записать $FAIL2BAN_JAIL"
        return 1
    fi

    if ! fail2ban-client -t \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_error \
            "fail2ban: новая конфигурация не прошла проверку"

        if ! rm -f -- "$FAIL2BAN_JAIL"; then
            add_warning \
                "fail2ban: не удалось удалить некорректный $FAIL2BAN_JAIL"
        fi

        return 1
    fi

    if ! record_manifest_created_file \
        "$FAIL2BAN_JAIL" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}"
    then
        add_error \
            "fail2ban: созданный jail.local не записан в manifest"

        if ! rm -f -- "$FAIL2BAN_JAIL"; then
            add_warning \
                "fail2ban: не удалось удалить незарегистрированный $FAIL2BAN_JAIL"
        fi

        return 1
    fi

    record_manifest_modified_file_best_effort \
        "$FAIL2BAN_JAIL"

    record_manifest_apply_report \
        "fail2ban: SSH jail written (port=${ssh_port})"

    if ! systemctl enable --now fail2ban.service \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_error \
            "fail2ban: jail.local записан, но enable --now завершился ошибкой"
        record_manifest_warning \
            "fail2ban: systemctl enable --now failed after writing jail.local"
        return 1
    fi

    if ! systemctl is-active --quiet fail2ban.service \
        2>>"${DEBUG_LOG_FILE:-/dev/null}"
    then
        add_error \
            "fail2ban: служба не активна после enable --now"
        return 1
    fi

    add_safe \
        "fail2ban: SSH jail настроен (port=${ssh_port}, maxretry=5, bantime=3600)"

    return 0
}

restore_fail2ban_module() {
    local pre_state_output=""
    local pre_state_rc=0
    local enabled_before=""
    local active_before=""
    local manifest_rc=0
    local file_restore_ok=1
    local overall_rc=0

    pre_state_output="$(
        restore_fail2ban_service_pre_state
    )" || pre_state_rc=$?

    case "$pre_state_rc" in
        0)
            IFS=$'\t' read -r \
                enabled_before \
                active_before \
                <<< "$pre_state_output"

            if [[ -z "$enabled_before" \
                || -z "$active_before" ]]
            then
                add_error \
                    "restore fail2ban: прежнее состояние службы прочитано не полностью"
                return 1
            fi
            ;;
        1)
            ;;
        *)
            add_error \
                "restore fail2ban: не удалось прочитать прежнее состояние службы"
            return 1
            ;;
    esac

    restore_manifest_has_path "$FAIL2BAN_JAIL"
    manifest_rc=$?

    case "$manifest_rc" in
        0)
            if ! restore_file_from_manifest \
                "$FAIL2BAN_JAIL"
            then
                file_restore_ok=0
                overall_rc=1
            fi
            ;;
        1)
            ;;
        *)
            return 1
            ;;
    esac

    if (( pre_state_rc == 0 )); then
        if (( file_restore_ok == 1 )); then
            if ! restore_fail2ban_service_state \
                "$enabled_before" \
                "$active_before"
            then
                add_warning \
                    "restore fail2ban: не удалось восстановить прежнее состояние службы"
                overall_rc=1
            fi
        fi
    elif (( manifest_rc == 0 \
        && file_restore_ok == 1 ))
    then
        if ! systemctl restart fail2ban.service \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            add_warning \
                "restore fail2ban: файл восстановлен, но legacy restart не удался"
            overall_rc=1
        fi
    fi

    if ! restore_installed_packages "fail2ban"; then
        overall_rc=1
    fi

    return "$overall_rc"
}

check_rkhunter_module() {
    if ! profile_allows paranoid; then
        add_skipped "rkhunter пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi
    if ! command -v rkhunter >/dev/null 2>&1; then
        add_risky "rkhunter: не установлен"
        return 0
    fi
    add_safe "rkhunter: установлен ($(rkhunter --version 2>/dev/null | head -1))"
}

apply_rkhunter_module() {
    if ! profile_allows paranoid; then
        add_skipped "rkhunter пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        add_skipped "rkhunter dry-run: would install and update database"
        return 0
    fi
    log "[i]     rkhunter: установка пакета..."
    apt_update_once
    if ! pkg_installed rkhunter; then
        install_packages_transactionally "rkhunter" rkhunter || true

        if (( PACKAGE_TRANSACTION_TRACKING_RC != 0 )); then
            add_error "rkhunter: package transaction не зафиксирована"
            record_manifest_warning "rkhunter: package transaction tracking failed"
            return 1
        fi

        if (( PACKAGE_TRANSACTION_INSTALL_RC != 0 )); then
            add_warning "rkhunter: не удалось установить пакет"
            record_manifest_warning "rkhunter: apt-get install failed"
            return 0
        fi
    fi
    log "[i]     rkhunter: обновление базы данных..."
    local rkhunter_update_ok=1
    rkhunter --update >/dev/null 2>&1 || rkhunter_update_ok=0
    rkhunter --propupd >/dev/null 2>&1 || rkhunter_update_ok=0
    if (( rkhunter_update_ok == 1 )); then
        record_manifest_apply_report "rkhunter: installed and database updated"
        record_manifest_irreversible_change "rkhunter: установлен — удалить вручную: apt-get remove rkhunter"
        add_safe "rkhunter: установлен и база данных обновлена"
    else
        record_manifest_apply_report "rkhunter: installed, but database update failed"
        record_manifest_warning "rkhunter: --update/--propupd failed"
        add_warning "rkhunter: установлен, но обновление базы завершилось с ошибкой"
    fi
}

restore_rkhunter_module() {
    local rc=0

    if ! report_installed_packages_for_manual_restore         "rkhunter"         "rkhunter"
    then
        rc=1
    fi

    if ! restore_manifest_has_report_text "rkhunter:"; then
        log "[i]     restore rkhunter: informational marker отсутствует"
    fi

    log "[i]     restore rkhunter: пакет не удаляется автоматически; при необходимости удалите вручную: apt-get remove rkhunter"

    return "$rc"
}

render_kernel_module_blacklist() {
    local mod=""

    printf '%s\n' \
        '# Managed by SecureLinux-NG — kernel module blacklist (ФСТЭК / CIS)' \
        '# Редкие/устаревшие файловые системы'

    for mod in "${KERNEL_MODULE_FILESYSTEM_MODULES[@]}"; do
        printf 'install %s /bin/false\n' "$mod"
    done

    printf '%s\n' \
        '# Редкие сетевые протоколы'

    for mod in "${KERNEL_MODULE_NETWORK_MODULES[@]}"; do
        printf 'install %s /bin/false\n' "$mod"
    done

    printf '%s\n' \
        '# Firewire (DMA-атаки)'

    for mod in "${KERNEL_MODULE_FIREWIRE_MODULES[@]}"; do
        printf 'install %s /bin/false\n' "$mod"
    done

    if profile_allows paranoid; then
        printf '%s\n' \
            '' \
            '# USB-носители (paranoid — корпоративная политика)' \
            'install usb_storage /bin/false'
    fi
}

check_kernel_modules_module() {
    local required_modules=(
        "${KERNEL_MODULE_FILESYSTEM_MODULES[@]}"
        "${KERNEL_MODULE_NETWORK_MODULES[@]}"
        "${KERNEL_MODULE_FIREWIRE_MODULES[@]}"
    )
    local missing=()
    local mod=""
    local expected_line=""

    if [[ ! -f "$KERNEL_MODULE_BLACKLIST" ]]; then
        add_risky \
            "kernel modules: blacklist отсутствует: $KERNEL_MODULE_BLACKLIST (requires_reboot)"
        return 0
    fi

    for mod in "${required_modules[@]}"; do
        expected_line="install ${mod} /bin/false"

        if ! grep -Fqx -- \
            "$expected_line" \
            "$KERNEL_MODULE_BLACKLIST"
        then
            missing+=("$mod")
        fi
    done

    if profile_allows paranoid \
        && ! grep -Fqx -- \
            'install usb_storage /bin/false' \
            "$KERNEL_MODULE_BLACKLIST"
    then
        missing+=("usb_storage")
    fi

    if (( ${#missing[@]} == 0 )); then
        add_safe \
            "kernel modules: blacklist содержит все обязательные записи: $KERNEL_MODULE_BLACKLIST"
        return 0
    fi

    add_risky \
        "kernel modules: blacklist неполон; отсутствуют обязательные записи: ${missing[*]} (requires_reboot)"

    return 0
}

apply_kernel_modules_module() {
    local bak=""
    local existed=0
    local mod=""

    if (( DRY_RUN == 1 )); then
        log \
            "[DRY-RUN] atomically write $KERNEL_MODULE_BLACKLIST"

        add_skipped \
            "kernel modules dry-run: blacklist would be written"

        return 0
    fi

    if ! mkdir -p -- \
        "$(dirname "$KERNEL_MODULE_BLACKLIST")"
    then
        add_error \
            "kernel modules: не удалось создать каталог modprobe.d"
        return 1
    fi

    if [[ -e "$KERNEL_MODULE_BLACKLIST" \
        || -L "$KERNEL_MODULE_BLACKLIST" ]]
    then
        existed=1
        bak="$STATE_DIR/$(basename "$KERNEL_MODULE_BLACKLIST").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$KERNEL_MODULE_BLACKLIST" \
            "$bak" \
            "kernel modules"
        then
            add_skipped \
                "kernel modules apply skipped: backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$KERNEL_MODULE_BLACKLIST" \
            "$bak"
        then
            add_error \
                "kernel modules apply skipped: backup mapping не записан"

            if ! rm -f -- "$bak"; then
                add_warning \
                    "kernel modules: не удалось удалить незарегистрированный backup $bak"
            fi

            return 1
        fi
    fi

    if ! prepare_created_file_transaction \
        "$KERNEL_MODULE_BLACKLIST" \
        "$existed" \
        "kernel modules"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$KERNEL_MODULE_BLACKLIST" \
        0644 \
        render_kernel_module_blacklist
    then
        add_error \
            "kernel modules: не удалось атомарно записать $KERNEL_MODULE_BLACKLIST"

        record_manifest_warning \
            "kernel modules: atomic blacklist write failed" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        return 1
    fi

    if (( existed == 0 )); then
        if ! record_manifest_created_file \
            "$KERNEL_MODULE_BLACKLIST" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "kernel modules: созданный blacklist не записан в manifest"

            if ! rm -f -- "$KERNEL_MODULE_BLACKLIST"; then
                add_warning \
                    "kernel modules: не удалось удалить незарегистрированный blacklist $KERNEL_MODULE_BLACKLIST"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$KERNEL_MODULE_BLACKLIST"

    record_manifest_apply_report \
        "kernel modules: blacklist written: $KERNEL_MODULE_BLACKLIST"

    for mod in \
        cramfs \
        freevxfs \
        hfs \
        hfsplus \
        udf \
        jffs2 \
        squashfs \
        dccp \
        sctp \
        rds \
        tipc
    do
        modprobe -r "$mod" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true
    done

    add_safe \
        "kernel modules: blacklist применён: $KERNEL_MODULE_BLACKLIST"

    if profile_allows paranoid; then
        add_warning \
            "kernel modules: usb_storage заблокирован (paranoid, п.10.6 корпоративная мера). Если USB-накопители нужны — удалите запись вручную из $KERNEL_MODULE_BLACKLIST"
    fi

    add_warning \
        "kernel modules: полный эффект blacklist — после перезагрузки"

    return 0
}

restore_kernel_modules_module() {
    restore_file_from_manifest "$KERNEL_MODULE_BLACKLIST"
}

check_mount_hardening_module() {
    if ! profile_allows paranoid; then
        add_skipped "mount hardening пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi
    local issues=()
    for target in /dev/shm /var/tmp; do
        if mountpoint -q "$target" 2>/dev/null; then
            local opts
            opts=$(findmnt -n -o OPTIONS --target "$target" 2>/dev/null || echo "")
            [[ "$opts" == *"nosuid"* ]] || issues+=("$target: nosuid missing")
            [[ "$opts" == *"nodev"* ]]  || issues+=("$target: nodev missing")
            [[ "$opts" == *"noexec"* ]] || issues+=("$target: noexec missing")
        fi
    done
    if [[ ${#issues[@]} -eq 0 ]]; then
        add_safe "mount hardening: /dev/shm и /var/tmp проверены"
    else
        add_risky "mount hardening: ${issues[*]} (requires_reboot)"
    fi
}

apply_mount_hardening_module() {
    if ! profile_allows paranoid; then
        add_skipped "mount hardening пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] harden /dev/shm and /var/tmp in /etc/fstab"
        add_skipped "mount hardening dry-run"
        return 0
    fi

    local fstab="/etc/fstab"
    if [[ ! -f "$fstab" ]]; then
        add_warning "mount hardening: $fstab не найден"
        return 0
    fi

    local bak="$STATE_DIR/fstab.bak-$TIMESTAMP"
    if ! manifest_has_backup_for "$fstab"; then
        if ! backup_file_checked "$fstab" "$bak" "mount hardening fstab"; then
            add_skipped "mount hardening apply skipped: fstab backup failed"
            return 0
        fi
        if ! record_manifest_backup             "$fstab"             "$bak"
        then
            add_error                 "mount hardening: не удалось записать backup mapping для $fstab"

            if ! rm -f -- "$bak"; then
                add_warning                     "mount hardening: не удалось удалить незарегистрированный backup $bak"
            fi

            return 1
        fi
    fi

    if ! record_manifest_module_restore_required "mount_hardening"; then
        add_error             "mount hardening: не удалось записать typed restore-state"
        return 1
    fi

    if ! atomic_write_command_output \
        "$fstab" \
        0644 \
        python3 - "$fstab" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
lines = path.read_text(
    encoding="utf-8",
).splitlines(keepends=True)

lines = [
    line
    for line in lines
    if not (
        len(line.split()) >= 2
        and line.split()[1] in ("/dev/shm", "/var/tmp")
    )
]

lines.append(
    "tmpfs /dev/shm tmpfs "
    "defaults,nosuid,nodev,noexec,mode=1777 0 0\n"
)
lines.append(
    "tmpfs /var/tmp tmpfs "
    "defaults,nosuid,nodev,noexec,mode=1777 0 0\n"
)

print("".join(lines), end="")
PYEOF
    then
        add_error "mount hardening: не удалось атомарно обновить $fstab"
        record_manifest_warning \
            "mount hardening: atomic fstab update failed"
        return 1
    fi

    record_manifest_modified_file_best_effort "$fstab"
    record_manifest_apply_report         "mount hardening: /dev/shm and /var/tmp entries added to fstab"         || add_warning "mount hardening: apply-report не записан"
    record_manifest_irreversible_change         "mount hardening: fstab modified — эффект после перезагрузки"         || add_warning "mount hardening: irreversible report не записан"

    # Немедленный remount /dev/shm
    if mountpoint -q /dev/shm 2>/dev/null; then
        mount -o remount,nosuid,nodev,noexec /dev/shm 2>/dev/null             && add_safe "mount hardening: /dev/shm remount выполнен"             || add_warning "mount hardening: /dev/shm remount не удался — эффект после перезагрузки"
    fi

    # /var/tmp tmpfs
    mkdir -p /var/tmp
    if mountpoint -q /var/tmp 2>/dev/null; then
        mount -o remount,nosuid,nodev,noexec /var/tmp 2>/dev/null             && add_safe "mount hardening: /var/tmp remount выполнен"             || add_warning "mount hardening: /var/tmp remount не удался — эффект после перезагрузки"
    else
        mount -t tmpfs -o nosuid,nodev,noexec,mode=1777 tmpfs /var/tmp 2>/dev/null             && add_safe "mount hardening: /var/tmp смонтирован как tmpfs"             || add_warning "mount hardening: /var/tmp mount не удался — эффект после перезагрузки"
    fi
}

restore_mount_hardening_module() {
    if ! restore_fstab_module_if_required         "mount_hardening" "mount hardening"
    then
        return 1
    fi

    if (( FSTAB_LAST_MODULE_REQUIRED == 1 )); then
        add_warning             "restore mount hardening: для полного отката требуется перезагрузка"
    fi

    return 0
}
check_tmp_tmpfs_module() {
    if ! profile_allows paranoid; then
        add_skipped "/tmp tmpfs пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi
    if findmnt -n -o FSTYPE --target /tmp 2>/dev/null | grep -qx "tmpfs"; then
        local opts
        opts=$(findmnt -n -o OPTIONS --target /tmp 2>/dev/null || echo "")
        local issues=()
        [[ "$opts" == *"nosuid"* ]] || issues+=("nosuid missing")
        [[ "$opts" == *"nodev"* ]]  || issues+=("nodev missing")
        [[ "$opts" == *"noexec"* ]] || issues+=("noexec missing")
        if [[ ${#issues[@]} -eq 0 ]]; then
            add_safe "/tmp: tmpfs с nosuid,nodev,noexec"
        else
            add_risky "/tmp: tmpfs но без флагов: ${issues[*]}"
        fi
    else
        add_risky "/tmp: не является tmpfs"
    fi
    if grep -qE '^\s*tmpfs\s+/tmp\s+tmpfs' /etc/fstab 2>/dev/null; then
        add_safe "/tmp: запись в /etc/fstab присутствует"
    else
        add_risky "/tmp: запись в /etc/fstab отсутствует (requires_reboot)"
    fi
}

apply_tmp_tmpfs_module() {
    if ! profile_allows paranoid; then
        add_skipped "/tmp tmpfs пропущен: требуется профиль paranoid (текущий: ${PROFILE})"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] add tmpfs /tmp to /etc/fstab with nosuid,nodev,noexec,mode=1777"
        log "[DRY-RUN] mount -o remount /tmp"
        add_skipped "/tmp dry-run: tmpfs would be configured"
        return 0
    fi

    local fstab="/etc/fstab"
    if [[ ! -f "$fstab" ]]; then
        add_warning "/tmp: $fstab не найден — пропуск"
        return 0
    fi

    # fstab backup: пропускаем если mount_hardening уже сохранил backup в этом сеансе
    if ! python3 -c "import sys,json,pathlib; d=json.loads(pathlib.Path(sys.argv[1]).read_text()); sys.exit(0 if any(e.get('original')=='/etc/fstab' for e in d.get('backups',[]) if isinstance(e,dict)) else 1)" "$MANIFEST_FILE" 2>/dev/null; then
        local bak="$STATE_DIR/fstab.bak-$TIMESTAMP"
        if ! backup_file_checked "$fstab" "$bak" "/tmp tmpfs fstab"; then
            add_skipped "/tmp tmpfs apply skipped: fstab backup failed"
            return 0
        fi
        if ! record_manifest_backup             "$fstab"             "$bak"
        then
            add_error                 "/tmp: не удалось записать backup mapping для $fstab"

            if ! rm -f -- "$bak"; then
                add_warning                     "/tmp: не удалось удалить незарегистрированный backup $bak"
            fi

            return 1
        fi
    fi

    if ! record_manifest_module_restore_required "tmp_tmpfs"; then
        add_error "/tmp: не удалось записать typed restore-state"
        return 1
    fi

    if ! atomic_write_command_output \
        "$fstab" \
        0644 \
        python3 - "$fstab" <<'PYEOF'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
lines = path.read_text(
    encoding="utf-8",
).splitlines(keepends=True)

lines = [
    line
    for line in lines
    if not (
        len(line.split()) >= 2
        and line.split()[1] == "/tmp"
    )
]

lines.append(
    "tmpfs /tmp tmpfs "
    "defaults,nosuid,nodev,noexec,mode=1777 0 0\n"
)

print("".join(lines), end="")
PYEOF
    then
        add_error "/tmp: не удалось атомарно обновить $fstab"
        record_manifest_warning \
            "/tmp: atomic fstab update failed"
        return 1
    fi

    record_manifest_modified_file_best_effort "$fstab"
    record_manifest_apply_report         "/tmp: tmpfs entry added to /etc/fstab"         || add_warning "/tmp: apply-report не записан"
    record_manifest_irreversible_change         "/tmp: fstab modified — эффект после перезагрузки"         || add_warning "/tmp: irreversible report не записан"

    mkdir -p /tmp
    if findmnt -n -o FSTYPE --target /tmp 2>/dev/null | grep -qx "tmpfs"; then
        mount -o remount,nosuid,nodev,noexec,mode=1777 /tmp 2>/dev/null             && add_safe "/tmp: remount с nosuid,nodev,noexec выполнен"             || add_warning "/tmp: remount не удался — эффект после перезагрузки"
    else
        mount /tmp 2>/dev/null             && add_safe "/tmp: смонтирован как tmpfs"             || add_warning "/tmp: mount не удался — эффект после перезагрузки"
    fi
    add_safe "/tmp: tmpfs настроен (nosuid,nodev,noexec,mode=1777)"
}

restore_tmp_tmpfs_module() {
    if ! restore_fstab_module_if_required "tmp_tmpfs" "/tmp tmpfs"; then
        return 1
    fi

    if (( FSTAB_LAST_MODULE_REQUIRED == 1 )); then
        add_warning             "restore /tmp: для полного отката требуется перезагрузка"
    fi

    return 0
}
check_ufw_module() {
    if ! command -v ufw >/dev/null 2>&1; then
        add_risky "firewall: ufw не установлен"
        return 0
    fi
    if ufw status 2>/dev/null | grep -q "^Status: active"; then
        add_safe "firewall: ufw активен"
    else
        add_risky "firewall: ufw установлен но не активен"
    fi
}

apply_ufw_module() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install ufw, default deny incoming, allow SSH"
        add_skipped "firewall dry-run: ufw would be configured"
        return 0
    fi

    local ufw_was_active=0
    local ufw_service_was_enabled=0
    local nftables_was_active=0
    local nftables_was_enabled=0
    local nftables_mutation_attempted=0
    local rules_mutation_attempted=0
    local ufw_enable_attempted=0
    local ufw_service_enable_attempted=0

    # Снимаем firewall pre-state до установки ufw: установка пакета может
    # создать/enable systemd units и тем самым исказить исходное состояние.
    ufw status 2>/dev/null | grep -q "^Status: active" \
        && ufw_was_active=1 || true
    systemctl is-enabled ufw >/dev/null 2>&1 \
        && ufw_service_was_enabled=1 || true
    systemctl is-active nftables >/dev/null 2>&1 \
        && nftables_was_active=1 || true
    systemctl is-enabled nftables >/dev/null 2>&1 \
        && nftables_was_enabled=1 || true

    log "[i]     ufw: установка пакета..."
    apt_update_once
    if ! pkg_installed ufw; then
        install_packages_transactionally "firewall" ufw || true

        if (( PACKAGE_TRANSACTION_TRACKING_RC != 0 )); then
            add_error "firewall: package transaction ufw не зафиксирована"
            record_manifest_warning "firewall: package transaction tracking failed" || true
            return 1
        fi

        if (( PACKAGE_TRANSACTION_INSTALL_RC != 0 )); then
            add_error "firewall: не удалось установить ufw"
            record_manifest_warning "firewall: apt-get install ufw failed" || true
            return 1
        fi
    fi

    local ssh_port="$UFW_SSH_PORT"
    resolve_ssh_port "$ssh_port"
    ssh_port="$SSH_PORT_RESOLVED"

    if (( ufw_was_active == 0 )); then
        local ufw_added_rules=""
        ufw_added_rules="$(ufw show added 2>/dev/null || true)"

        if grep -Eq '^[[:space:]]*ufw[[:space:]]+' <<<"$ufw_added_rules"; then
            add_error "firewall: ufw неактивен, но содержит предварительно настроенные правила — автоматическое включение заблокировано"
            record_manifest_warning "firewall: inactive ufw has preconfigured rules; automatic enable skipped" || true
            add_policy_gate "firewall: review inactive preconfigured ufw rules before apply"
            return 1
        fi
    fi

    if ! record_manifest_firewall_state \
        "$ufw_was_active" \
        "$ufw_service_was_enabled" \
        "$nftables_was_active" \
        "$nftables_was_enabled" \
        "$nftables_mutation_attempted" \
        "$rules_mutation_attempted" \
        "$ufw_enable_attempted" \
        "$ufw_service_enable_attempted"
    then
        add_error "firewall: не удалось записать исходное typed-состояние"
        return 1
    fi

    if (( nftables_was_active == 1 || nftables_was_enabled == 1 )); then
        nftables_mutation_attempted=1

        if ! record_manifest_firewall_state \
            "$ufw_was_active" \
            "$ufw_service_was_enabled" \
            "$nftables_was_active" \
            "$nftables_was_enabled" \
            "$nftables_mutation_attempted" \
            "$rules_mutation_attempted" \
            "$ufw_enable_attempted" \
            "$ufw_service_enable_attempted"
        then
            add_error "firewall: не удалось зарегистрировать изменение nftables"
            return 1
        fi

        local nftables_apply_ok=1

        if (( nftables_was_active == 1 )); then
            systemctl stop nftables 2>/dev/null || nftables_apply_ok=0
        fi

        systemctl mask nftables 2>/dev/null || nftables_apply_ok=0

        if (( nftables_apply_ok == 0 )); then
            add_error "firewall: не удалось безопасно остановить/замаскировать nftables"
            record_manifest_warning "firewall: nftables stop/mask failed" || true
            return 1
        fi

        record_manifest_apply_report \
            "firewall: nftables typed pre-state active=${nftables_was_active}, enabled=${nftables_was_enabled}" \
            || add_warning "firewall: не удалось записать информационный отчёт nftables"
        log "[i]     firewall: nftables остановлен/замаскирован с typed pre-state"
    fi

    rules_mutation_attempted=1

    if ! record_manifest_firewall_state \
        "$ufw_was_active" \
        "$ufw_service_was_enabled" \
        "$nftables_was_active" \
        "$nftables_was_enabled" \
        "$nftables_mutation_attempted" \
        "$rules_mutation_attempted" \
        "$ufw_enable_attempted" \
        "$ufw_service_enable_attempted"
    then
        add_error "firewall: не удалось зарегистрировать изменение правил UFW"
        return 1
    fi

    if (( ufw_was_active == 1 )); then
        local ufw_preexisting_ok=1

        if ! ufw allow "${ssh_port}/tcp" comment "SSH" >/dev/null 2>&1; then
            ufw_preexisting_ok=0
            add_warning "firewall: ufw уже активен, но не удалось добавить/подтвердить правило SSH ${ssh_port}/tcp"
            record_manifest_warning "firewall: pre-active ufw, failed to apply SSH rule ${ssh_port}/tcp" || true
        fi

        local _rule _port _comment
        for _rule in $UFW_EXTRA_RULES; do
            _port="${_rule%%:*}"
            _comment="${_rule#*:}"

            if ! ufw allow "$_port" comment "$_comment" >/dev/null 2>&1; then
                ufw_preexisting_ok=0
                add_warning "firewall: ufw уже активен, но не удалось добавить дополнительное правило ${_port} (${_comment})"
                record_manifest_warning "firewall: pre-active ufw, failed to apply extra rule ${_port}:${_comment}" || true
            fi
        done

        if (( ufw_service_was_enabled == 0 )); then
            ufw_service_enable_attempted=1

            if ! record_manifest_firewall_state \
                "$ufw_was_active" \
                "$ufw_service_was_enabled" \
                "$nftables_was_active" \
                "$nftables_was_enabled" \
                "$nftables_mutation_attempted" \
                "$rules_mutation_attempted" \
                "$ufw_enable_attempted" \
                "$ufw_service_enable_attempted"
            then
                add_error "firewall: не удалось зарегистрировать enable службы UFW"
                return 1
            fi

            if ! systemctl enable ufw >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
                add_error "firewall: не удалось включить службу ufw"
                record_manifest_warning "firewall: pre-active ufw service enable failed" || true
                return 1
            fi
        fi

        local ufw_default_in
        ufw_default_in=$(ufw status verbose 2>/dev/null | awk '/^Default:/{print $2}')

        if [[ "$ufw_default_in" != "deny" && "$ufw_default_in" != "reject" ]]; then
            add_error "firewall: ufw уже активен, политика по умолчанию incoming=${ufw_default_in:-unknown} — ФСТЭК требует deny. Исправьте вручную: ufw default deny incoming"
            record_manifest_warning "firewall: ufw pre-active, default incoming policy is not deny" || true
            return 1
        fi

        add_safe "firewall: ufw активен, политика incoming=deny — соответствует ФСТЭК"
        record_manifest_apply_report \
            "firewall: ufw pre-active, default deny confirmed" \
            || add_warning "firewall: не удалось записать информационный отчёт UFW"

        if (( ufw_preexisting_ok == 1 )); then
            add_warning "firewall: ufw уже активен — существующие правила сохранены. Проверьте: ufw status verbose"
        else
            add_error "firewall: ufw уже активен — часть обязательных правил не удалось применить автоматически"
            return 1
        fi

        record_manifest_apply_report \
            "firewall: ufw pre-active, SSH port=${ssh_port}, extra=${UFW_EXTRA_RULES:-none}" \
            || add_warning "firewall: не удалось записать информационный отчёт UFW"
        record_manifest_warning \
            "firewall restore is partial for pre-active ufw rules; runtime and service pre-state are typed" \
            || true
        return 0
    fi

    local ufw_rules_ok=1

    ufw default deny incoming >/dev/null 2>&1 || ufw_rules_ok=0
    ufw default allow outgoing >/dev/null 2>&1 || ufw_rules_ok=0
    ufw allow "${ssh_port}/tcp" comment "SSH" >/dev/null 2>&1 || ufw_rules_ok=0

    local _rule _port _comment
    for _rule in $UFW_EXTRA_RULES; do
        _port="${_rule%%:*}"
        _comment="${_rule#*:}"
        ufw allow "$_port" comment "$_comment" >/dev/null 2>&1 || ufw_rules_ok=0
    done

    if (( ufw_rules_ok == 0 )); then
        add_error "firewall: применение правил UFW завершилось с ошибкой"
        record_manifest_warning "firewall: ufw rule sequence failed before enable" || true
        return 1
    fi

    ufw_enable_attempted=1

    if ! record_manifest_firewall_state \
        "$ufw_was_active" \
        "$ufw_service_was_enabled" \
        "$nftables_was_active" \
        "$nftables_was_enabled" \
        "$nftables_mutation_attempted" \
        "$rules_mutation_attempted" \
        "$ufw_enable_attempted" \
        "$ufw_service_enable_attempted"
    then
        add_error "firewall: не удалось зарегистрировать попытку включения UFW"
        return 1
    fi

    if ! ufw --force enable >/dev/null 2>&1; then
        add_error "firewall: команда ufw --force enable завершилась с ошибкой"
        record_manifest_warning "firewall: ufw enable failed" || true
        return 1
    fi

    if (( ufw_service_was_enabled == 0 )); then
        ufw_service_enable_attempted=1

        if ! record_manifest_firewall_state \
            "$ufw_was_active" \
            "$ufw_service_was_enabled" \
            "$nftables_was_active" \
            "$nftables_was_enabled" \
            "$nftables_mutation_attempted" \
            "$rules_mutation_attempted" \
            "$ufw_enable_attempted" \
            "$ufw_service_enable_attempted"
        then
            add_error "firewall: не удалось зарегистрировать enable службы UFW"
            ufw --force disable >/dev/null 2>&1 || true
            return 1
        fi

        if ! systemctl enable ufw >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
            local rollback_ok=1

            if ! ufw --force disable >/dev/null 2>&1; then
                rollback_ok=0
                add_warning "firewall: после сбоя systemctl enable не удалось локально отключить UFW"
            fi

            add_error "firewall: systemctl enable ufw завершился с ошибкой; локальный rollback=${rollback_ok}"
            record_manifest_warning "firewall: systemctl enable ufw failed after runtime enable" || true
            return 1
        fi
    fi

    record_manifest_apply_report \
        "firewall: ufw enabled, SSH port=${ssh_port}, extra=${UFW_EXTRA_RULES:-none}, default deny incoming" \
        || add_warning "firewall: не удалось записать информационный отчёт UFW"
    record_manifest_irreversible_change \
        "firewall: правила UFW не архивируются; typed state восстанавливает active/enabled и nftables pre-state" \
        || add_warning "firewall: не удалось записать информационное ограничение restore"
    add_safe "firewall: ufw включён (SSH port=${ssh_port}, extra=${UFW_EXTRA_RULES:-none}, default deny incoming)"
    log "[i]     firewall: для открытия портов: ufw allow PORT/tcp"
    return 0
}

restore_ufw_module() {
    local state state_rc
    local ufw_was_active=0
    local ufw_service_was_enabled=0
    local nftables_was_active=0
    local nftables_was_enabled=0
    local nftables_mutation_attempted=0
    local rules_mutation_attempted=0
    local ufw_enable_attempted=0
    local ufw_service_enable_attempted=0
    local rc=0
    local package_report_rc=0

    if ! report_installed_packages_for_manual_restore \
        "firewall" \
        "firewall"
    then
        package_report_rc=1
    fi

    state="$(restore_manifest_firewall_state)"
    state_rc=$?

    if (( state_rc == 0 )); then
        IFS=$'\t' read -r \
            ufw_was_active \
            ufw_service_was_enabled \
            nftables_was_active \
            nftables_was_enabled \
            nftables_mutation_attempted \
            rules_mutation_attempted \
            ufw_enable_attempted \
            ufw_service_enable_attempted <<<"$state"

        if (( ufw_was_active == 0 && ufw_enable_attempted == 1 )); then
            if ufw --force disable >/dev/null 2>&1; then
                log "[i]     restore firewall: UFW runtime отключён"
            else
                add_warning "restore firewall: не удалось отключить UFW runtime"
                rc=1
            fi
        elif (( ufw_was_active == 1 )); then
            log "[i]     restore firewall: UFW был активен до apply — runtime сохраняется"
        fi

        if (( ufw_service_enable_attempted == 1 )); then
            if (( ufw_service_was_enabled == 1 )); then
                if ! systemctl enable ufw >/dev/null 2>&1; then
                    add_warning "restore firewall: не удалось восстановить enabled-состояние службы UFW"
                    rc=1
                fi
            else
                if ! systemctl disable ufw >/dev/null 2>&1; then
                    add_warning "restore firewall: не удалось вернуть службу UFW в disabled"
                    rc=1
                fi
            fi
        fi

        if (( rules_mutation_attempted == 1 )); then
            add_warning "restore firewall: правила/default policy UFW не архивируются и не сбрасываются автоматически"
        fi

        if (( nftables_mutation_attempted == 1 )); then
            if ! systemctl unmask nftables >/dev/null 2>&1; then
                add_warning "restore firewall: не удалось снять mask с nftables"
                rc=1
            fi

            if (( nftables_was_enabled == 1 )); then
                if ! systemctl enable nftables >/dev/null 2>&1; then
                    add_warning "restore firewall: не удалось вернуть nftables в enabled"
                    rc=1
                fi
            else
                if ! systemctl disable nftables >/dev/null 2>&1; then
                    add_warning "restore firewall: не удалось вернуть nftables в disabled"
                    rc=1
                fi
            fi

            if (( nftables_was_active == 1 )); then
                if ! systemctl start nftables >/dev/null 2>&1; then
                    add_warning "restore firewall: не удалось вернуть nftables в active"
                    rc=1
                fi
            else
                if ! systemctl stop nftables >/dev/null 2>&1; then
                    add_warning "restore firewall: не удалось вернуть nftables в inactive"
                    rc=1
                fi
            fi
        fi

        if (( package_report_rc != 0 )); then
            rc=1
        fi
        return "$rc"
    fi

    if (( state_rc == 1 )); then
        log "[i]     restore firewall: typed state отсутствует — модуль не применялся"
        return "$package_report_rc"
    fi

    if (( state_rc == 2 )); then
        add_error "restore firewall: typed state повреждён или manifest недоступен"
        return 1
    fi

    if (( state_rc != 3 )); then
        add_error "restore firewall: неизвестный RC typed state: $state_rc"
        return 1
    fi

    add_warning "restore firewall: legacy manifest без typed state; используется apply_report fallback"

    local was_applied nft_pre_state
    local nft_restore_ok=1

    if ! was_applied="$(python3 -c "
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
if not mf.exists(): sys.exit(1)
data = json.loads(mf.read_text(encoding='utf-8'))
reports = data.get('apply_report', [])
print('1' if any('ufw enabled' in r for r in reports) else '0')
" "${RESTORE_SOURCE_MANIFEST}" 2>/dev/null)"; then
        add_error "restore firewall: не удалось прочитать legacy-состояние ufw"
        return 1
    fi

    if ! nft_pre_state="$(python3 -c "
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
if not mf.exists(): sys.exit(1)
data = json.loads(mf.read_text(encoding='utf-8'))
reports = data.get('apply_report', [])
if any('nftables pre-state: active' in r for r in reports):
    print('active')
elif any('nftables pre-state: enabled' in r for r in reports):
    print('enabled')
else:
    print('none')
" "${RESTORE_SOURCE_MANIFEST}" 2>/dev/null)"; then
        add_error "restore firewall: не удалось прочитать legacy-состояние nftables"
        return 1
    fi

    if [[ "$was_applied" == "1" ]]; then
        if ! ufw --force disable >/dev/null 2>&1; then
            add_warning "restore firewall: legacy fallback не смог отключить UFW"
            rc=1
        fi
    elif restore_manifest_has_report_text "firewall: ufw pre-active"; then
        add_warning "restore firewall: legacy pre-active UFW откатывается частично"
    fi

    if [[ "$nft_pre_state" == "active" ]]; then
        nft_restore_ok=1
        systemctl unmask nftables 2>/dev/null || nft_restore_ok=0
        systemctl enable --now nftables 2>/dev/null || nft_restore_ok=0

        if (( nft_restore_ok == 0 )); then
            add_warning "restore firewall: legacy fallback не восстановил active nftables"
            rc=1
        fi
    elif [[ "$nft_pre_state" == "enabled" ]]; then
        nft_restore_ok=1
        systemctl unmask nftables 2>/dev/null || nft_restore_ok=0
        systemctl enable nftables 2>/dev/null || nft_restore_ok=0

        if (( nft_restore_ok == 0 )); then
            add_warning "restore firewall: legacy fallback не восстановил enabled nftables"
            rc=1
        fi
    fi

    if (( package_report_rc != 0 )); then
        rc=1
    fi

    return "$rc"
}

append_audit_watch_if_present() {
    local rules_file="$1" path="$2" perms="$3" key="$4"

    if [[ -e "$path" ]]; then
        printf -- '-w %s -p %s -k %s\n' "$path" "$perms" "$key" >> "$rules_file"
    else
        log "[i]     auditd: watch пропущен, путь отсутствует: $path"
    fi
}

render_audit_watch_if_present() {
    local path="$1"
    local perms="$2"
    local key="$3"

    if [[ -e "$path" ]]; then
        printf -- \
            '-w %s -p %s -k %s\n' \
            "$path" \
            "$perms" \
            "$key"
    fi

    return 0
}

render_auditd_baseline_rules() {
    cat <<'RULES'
# Managed by SecureLinux-NG — auditd baseline (ФСТЭК)
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F perm=wa -k change_file_attr
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F perm=wa -k change_file_attr
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k privileged
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -k privileged
-a always,exit -F arch=b64 -S bind -S connect -k network
-a always,exit -F arch=b32 -S bind -S connect -k network
RULES

    local path=""
    local perms=""
    local key=""

    while IFS='|' read -r path perms key; do
        [[ -n "$path" ]] || continue

        render_audit_watch_if_present \
            "$path" \
            "$perms" \
            "$key" || return 1
    done <<'WATCHES'
/etc/passwd|wa|identity
/etc/shadow|wa|identity
/etc/group|wa|identity
/etc/gshadow|wa|identity
/etc/sudoers|wa|sudo
/etc/sudoers.d|wa|sudo
/etc/ssh/sshd_config|wa|sshd
/etc/ssh/sshd_config.d|wa|sshd
/dev/bus/usb|rwa|usb_devices
WATCHES

    return 0
}

render_auditd_strict_rules() {
    cat <<'RULES'
# Managed by SecureLinux-NG — auditd extended (strict+)
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k exec_from_tmp
-a always,exit -F arch=b32 -S execve -F dir=/tmp -k exec_from_tmp
-a always,exit -F arch=b64 -S finit_module -k modules
-a always,exit -F arch=b32 -S finit_module -k modules
RULES

    local path=""
    local perms=""
    local key=""

    while IFS='|' read -r path perms key; do
        [[ -n "$path" ]] || continue

        render_audit_watch_if_present \
            "$path" \
            "$perms" \
            "$key" || return 1
    done <<'WATCHES'
/etc/cron.d|wa|cron
/etc/cron.daily|wa|cron
/etc/cron.hourly|wa|cron
/etc/cron.weekly|wa|cron
/etc/cron.monthly|wa|cron
/etc/crontab|wa|cron
/var/spool/cron|wa|cron
/etc/hosts|wa|network_config
/etc/resolv.conf|wa|network_config
/etc/netplan|wa|network_config
/etc/systemd/system|wa|systemd
/lib/systemd/system|wa|systemd
WATCHES

    return 0
}

rollback_auditd_rules_file() {
    local target="$1"
    local existed_before="$2"
    local backup_path="$3"

    if (( existed_before == 1 )); then
        if [[ -z "$backup_path" \
            || ! -e "$backup_path" \
            && ! -L "$backup_path" ]]
        then
            return 1
        fi

        cp -a -- \
            "$backup_path" \
            "$target"

        return $?
    fi

    rm -f -- "$target"
}

rollback_auditd_rules_set() {
    local strict_required="$1"
    local baseline_existed="$2"
    local baseline_backup="$3"
    local strict_existed="$4"
    local strict_backup="$5"
    local rollback_rc=0

    if (( strict_required == 1 )); then
        if ! rollback_auditd_rules_file \
            "$AUDITD_STRICT_RULES" \
            "$strict_existed" \
            "$strict_backup"
        then
            rollback_rc=1
        fi
    fi

    if ! rollback_auditd_rules_file \
        "$AUDITD_BASELINE_RULES" \
        "$baseline_existed" \
        "$baseline_backup"
    then
        rollback_rc=1
    fi

    return "$rollback_rc"
}

reload_previous_auditd_rules_after_rollback() {
    if ! command -v augenrules \
        >/dev/null 2>&1
    then
        add_warning \
            "auditd rollback: augenrules отсутствует — прежние runtime rules не перезагружены"
        return 1
    fi

    if ! augenrules --load \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_warning \
            "auditd rollback: прежние rules-файлы восстановлены, но augenrules --load завершился ошибкой"
        return 1
    fi

    return 0
}

read_auditd_service_active_state() {
    local state=""
    local command_rc=0

    state="$(
        systemctl is-active auditd.service \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
    )" || command_rc=$?

    case "$state" in
        active|activating|reloading)
            printf '%s\n' "active"
            return 0
            ;;
        inactive|failed|deactivating|maintenance|unknown)
            printf '%s\n' "inactive"
            return 0
            ;;
        "")
            printf \
                'systemctl is-active returned no state for auditd.service (rc=%s)\n' \
                "$command_rc" \
                >&2
            return 1
            ;;
        *)
            printf \
                'systemctl is-active returned unsupported state for auditd.service: %s (rc=%s)\n' \
                "$state" \
                "$command_rc" \
                >&2
            return 1
            ;;
    esac
}

record_auditd_service_pre_state() {
    local enabled_state="$1"
    local active_state="$2"
    local prefix="auditd pre-service-state: "

    case "$enabled_state" in
        enabled|enabled-runtime|masked|masked-runtime|disabled|static|indirect|generated|transient|alias|not-found)
            ;;
        *)
            add_error \
                "auditd: некорректное прежнее enabled-состояние службы: $enabled_state"
            return 1
            ;;
    esac

    case "$active_state" in
        active|inactive)
            ;;
        *)
            add_error \
                "auditd: некорректное прежнее active-состояние службы: $active_state"
            return 1
            ;;
    esac

    case "${enabled_state}:${active_state}" in
        masked:active|masked-runtime:active|not-found:active)
            add_error \
                "auditd: противоречивое прежнее состояние службы: enabled=${enabled_state}, active=${active_state}"
            return 1
            ;;
    esac

    if [[ -z "${MANIFEST_FILE:-}" \
        || ! -f "${MANIFEST_FILE:-}" ]]
    then
        add_error \
            "auditd: manifest недоступен при записи прежнего состояния службы"
        return 1
    fi

    if ! python3 - \
        "$MANIFEST_FILE" \
        "$prefix" \
        "$enabled_state" \
        "$active_state" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
prefix = sys.argv[2]
enabled = sys.argv[3]
active = sys.argv[4]

data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

apply_report = data.setdefault("apply_report", [])

if not isinstance(apply_report, list):
    raise ValueError("manifest apply_report is not an array")

for entry in apply_report:
    if not isinstance(entry, str):
        raise ValueError(
            "manifest apply_report entry is not a string"
        )

value = (
    f"{prefix}"
    f"enabled={enabled};"
    f"active={active}"
)

matches = [
    entry
    for entry in apply_report
    if entry.startswith(prefix)
]

if len(matches) > 1:
    raise ValueError(
        "multiple auditd pre-service-state records exist"
    )

if matches:
    if matches[0] != value:
        raise ValueError(
            "conflicting auditd pre-service-state record exists"
        )

    raise SystemExit(0)

apply_report.append(value)

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    payload = (
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        ) + "\n"
    ).encode("utf-8")

    os.write(fd, payload)
    os.fsync(fd)
    os.close(fd)
    os.replace(temporary, path)
except Exception:
    try:
        os.close(fd)
    except OSError:
        pass

    try:
        os.unlink(temporary)
    except OSError:
        pass

    raise
PYJSON
    then
        add_error \
            "auditd: не удалось записать прежнее состояние службы в manifest"
        return 1
    fi

    return 0
}

restore_auditd_service_pre_state() {
    local prefix="auditd pre-service-state: "

    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        return 2
    fi

    python3 - \
        "$RESTORE_SOURCE_MANIFEST" \
        "$prefix" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
prefix = sys.argv[2]

allowed_enabled = {
    "enabled",
    "enabled-runtime",
    "masked",
    "masked-runtime",
    "disabled",
    "static",
    "indirect",
    "generated",
    "transient",
    "alias",
    "not-found",
}

allowed_active = {
    "active",
    "inactive",
}

try:
    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError(
            "manifest root is not an object"
        )

    apply_report = data.get("apply_report", [])

    if not isinstance(apply_report, list):
        raise ValueError(
            "manifest apply_report is not an array"
        )

    for entry in apply_report:
        if not isinstance(entry, str):
            raise ValueError(
                "manifest apply_report entry is not a string"
            )

    matches = [
        entry[len(prefix):]
        for entry in apply_report
        if entry.startswith(prefix)
    ]

    if not matches:
        raise SystemExit(1)

    if len(matches) != 1:
        raise ValueError(
            "expected exactly one auditd pre-service-state record"
        )

    match = re.fullmatch(
        r"enabled=([^;]+);active=([^;]+)",
        matches[0],
    )

    if match is None:
        raise ValueError(
            "malformed auditd pre-service-state record"
        )

    enabled, active = match.groups()

    if enabled not in allowed_enabled:
        raise ValueError(
            f"unsupported auditd enabled state: {enabled}"
        )

    if active not in allowed_active:
        raise ValueError(
            f"unsupported auditd active state: {active}"
        )

    if (
        enabled in {
            "masked",
            "masked-runtime",
            "not-found",
        }
        and active == "active"
    ):
        raise ValueError(
            "contradictory auditd service state"
        )

    print(f"{enabled}\t{active}")
except SystemExit:
    raise
except Exception as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(2)
PYJSON
}

restore_auditd_service_state() {
    local enabled_state="$1"
    local active_state="$2"
    local reload_rules="${3:-0}"
    local current_enabled=""

    case "$reload_rules" in
        0|1)
            ;;
        *)
            return 1
            ;;
    esac

    case "$active_state" in
        active)
            if ! systemctl is-active --quiet \
                auditd.service \
                2>>"${DEBUG_LOG_FILE:-/dev/null}"
            then
                if ! systemctl start auditd.service \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
                then
                    return 1
                fi
            fi

            if (( reload_rules == 1 )); then
                if ! command -v augenrules \
                    >/dev/null 2>&1
                then
                    return 1
                fi

                if ! augenrules --load \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
                then
                    return 1
                fi
            fi
            ;;
        inactive)
            if systemctl is-active --quiet \
                auditd.service \
                2>>"${DEBUG_LOG_FILE:-/dev/null}"
            then
                if ! systemctl stop auditd.service \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
                then
                    if systemctl is-active --quiet \
                        auditd.service \
                        2>>"${DEBUG_LOG_FILE:-/dev/null}"
                    then
                        return 1
                    fi
                fi
            fi
            ;;
        *)
            return 1
            ;;
    esac

    case "$enabled_state" in
        enabled)
            if ! systemctl unmask auditd.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi

            if ! systemctl enable auditd.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
        enabled-runtime)
            if ! systemctl unmask auditd.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi

            if ! systemctl enable --runtime \
                auditd.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
        disabled)
            if ! systemctl unmask auditd.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi

            if ! systemctl disable auditd.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
        not-found)
            if ! current_enabled="$(
                read_systemd_unit_enabled_state \
                    auditd.service
            )"
            then
                return 1
            fi

            if [[ "$current_enabled" != "not-found" ]]; then
                if ! systemctl unmask auditd.service \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
                then
                    return 1
                fi

                if ! systemctl disable auditd.service \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
                then
                    return 1
                fi
            fi
            ;;
        static|indirect|generated|transient|alias)
            ;;
        masked)
            if ! systemctl mask auditd.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
        masked-runtime)
            if ! systemctl mask --runtime \
                auditd.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}

rollback_auditd_apply_changes() {
    local strict_required="$1"
    local baseline_existed="$2"
    local baseline_backup="$3"
    local strict_existed="$4"
    local strict_backup="$5"
    local enabled_before="$6"
    local active_before="$7"
    local reload_rules=0
    local rollback_rc=0

    if ! rollback_auditd_rules_set \
        "$strict_required" \
        "$baseline_existed" \
        "$baseline_backup" \
        "$strict_existed" \
        "$strict_backup"
    then
        rollback_rc=1
    fi

    if [[ "$active_before" == "active" ]]; then
        reload_rules=1
    fi

    if ! restore_auditd_service_state \
        "$enabled_before" \
        "$active_before" \
        "$reload_rules"
    then
        rollback_rc=1
    fi

    return "$rollback_rc"
}

check_auditd_module() {
    if ! systemctl is-active --quiet auditd 2>/dev/null; then
        add_risky "auditd: служба не активна"
        return 0
    fi
    add_safe "auditd: служба активна"

    if [[ -f "$AUDITD_BASELINE_RULES" ]]; then
        add_safe "auditd: baseline rules присутствуют: $AUDITD_BASELINE_RULES"
    else
        add_risky "auditd: baseline rules отсутствуют: $AUDITD_BASELINE_RULES"
        return 0
    fi

    if profile_allows strict && [[ ! -f "$AUDITD_STRICT_RULES" ]]; then
        add_risky "auditd: extended rules отсутствуют: $AUDITD_STRICT_RULES"
    fi

    if command -v augenrules >/dev/null 2>&1; then
        if augenrules --check >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
            add_safe "auditd: rules.d и скомпилированные правила синхронизированы"
        else
            add_risky "auditd: augenrules --check обнаружил рассинхронизацию"
        fi
    fi

    if ! command -v auditctl >/dev/null 2>&1; then
        add_risky "auditd: auditctl не найден — runtime rules не проверены"
        return 0
    fi

    local loaded_rules
    if ! loaded_rules="$(auditctl -l 2>>"${DEBUG_LOG_FILE:-/dev/null}")"; then
        add_risky "auditd: не удалось получить загруженные runtime rules"
        return 0
    fi

    if [[ -z "$loaded_rules" || "$loaded_rules" == "No rules" ]]; then
        add_risky "auditd: runtime rules не загружены"
        return 0
    fi

    local -A expected_keys=(
        [modules]=1
        [change_file_attr]=1
        [privileged]=1
        [network]=1
    )

    local -a expected_watches=(
        "/etc/passwd|identity"
        "/etc/shadow|identity"
        "/etc/group|identity"
        "/etc/gshadow|identity"
        "/etc/sudoers|sudo"
        "/etc/sudoers.d|sudo"
        "/etc/ssh/sshd_config|sshd"
        "/etc/ssh/sshd_config.d|sshd"
        "/dev/bus/usb|usb_devices"
    )

    if profile_allows strict; then
        expected_keys[exec_from_tmp]=1
        expected_watches+=(
            "/etc/cron.d|cron"
            "/etc/cron.daily|cron"
            "/etc/cron.hourly|cron"
            "/etc/cron.weekly|cron"
            "/etc/cron.monthly|cron"
            "/etc/crontab|cron"
            "/var/spool/cron|cron"
            "/etc/hosts|network_config"
            "/etc/resolv.conf|network_config"
            "/etc/netplan|network_config"
            "/etc/systemd/system|systemd"
            "/lib/systemd/system|systemd"
        )
    fi

    local -a missing_paths=()
    local -a missing_keys=()
    local spec path key

    for spec in "${expected_watches[@]}"; do
        path="${spec%%|*}"
        key="${spec#*|}"

        [[ -e "$path" ]] || continue

        expected_keys["$key"]=1

        if ! grep -Fq -- "-w $path " <<< "$loaded_rules"; then
            missing_paths+=("$path")
        fi
    done

    for key in "${!expected_keys[@]}"; do
        if ! grep -Eq -- \
            "(-k[[:space:]]+$key|-F[[:space:]]+key=$key)([[:space:]]|$)" \
            <<< "$loaded_rules"
        then
            missing_keys+=("$key")
        fi
    done

    if (( ${#missing_paths[@]} > 0 )); then
        add_risky "auditd: runtime watch rules отсутствуют: ${missing_paths[*]}"
    fi
    if (( ${#missing_keys[@]} > 0 )); then
        add_risky "auditd: runtime rule keys отсутствуют: ${missing_keys[*]}"
    fi
    if (( ${#missing_paths[@]} == 0 && ${#missing_keys[@]} == 0 )); then
        add_safe "auditd: обязательные runtime rules загружены"
    fi
}

apply_auditd_module() {
    local enabled_before=""
    local active_before=""
    local baseline_existed=0
    local strict_existed=0
    local strict_required=0
    local baseline_backup=""
    local strict_backup=""
    local package_install_rc=0
    local package_tracking_rc=0

    if (( DRY_RUN == 1 )); then
        log \
            "[DRY-RUN] install auditd, atomically write ${AUDITD_BASELINE_RULES} (profile: ${PROFILE})"

        if profile_allows strict; then
            log \
                "[DRY-RUN] atomically write ${AUDITD_STRICT_RULES}"
        fi

        add_skipped \
            "auditd dry-run: rules would be written"

        return 0
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        add_error \
            "auditd: apt-get не найден"
        return 1
    fi

    if ! enabled_before="$(
        read_systemd_unit_enabled_state \
            auditd.service
    )"
    then
        add_error \
            "auditd: не удалось определить исходное enabled-состояние службы"
        return 1
    fi

    if ! active_before="$(
        read_auditd_service_active_state
    )"
    then
        add_error \
            "auditd: не удалось определить исходное active-состояние службы"
        return 1
    fi

    if ! record_auditd_service_pre_state \
        "$enabled_before" \
        "$active_before"
    then
        return 1
    fi

    if profile_allows strict; then
        strict_required=1
    fi

    if [[ -e "$AUDITD_BASELINE_RULES" \
        || -L "$AUDITD_BASELINE_RULES" ]]
    then
        baseline_existed=1

        if [[ ! -f "$AUDITD_BASELINE_RULES" ]]; then
            add_error \
                "auditd: $AUDITD_BASELINE_RULES существует, но не является обычным файлом или ссылкой на файл"
            return 1
        fi

        baseline_backup="$STATE_DIR/$(basename "$AUDITD_BASELINE_RULES").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$AUDITD_BASELINE_RULES" \
            "$baseline_backup" \
            "auditd baseline"
        then
            add_skipped \
                "auditd apply skipped: baseline backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$AUDITD_BASELINE_RULES" \
            "$baseline_backup"
        then
            add_error \
                "auditd apply skipped: baseline backup mapping не записан"

            if ! rm -f -- "$baseline_backup"; then
                add_warning \
                    "auditd: не удалось удалить незарегистрированный backup $baseline_backup"
            fi

            return 1
        fi
    fi

    if (( strict_required == 1 )) \
        && [[ -e "$AUDITD_STRICT_RULES" \
            || -L "$AUDITD_STRICT_RULES" ]]
    then
        strict_existed=1

        if [[ ! -f "$AUDITD_STRICT_RULES" ]]; then
            add_error \
                "auditd: $AUDITD_STRICT_RULES существует, но не является обычным файлом или ссылкой на файл"
            return 1
        fi

        strict_backup="$STATE_DIR/$(basename "$AUDITD_STRICT_RULES").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$AUDITD_STRICT_RULES" \
            "$strict_backup" \
            "auditd extended"
        then
            add_skipped \
                "auditd apply skipped: extended backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$AUDITD_STRICT_RULES" \
            "$strict_backup"
        then
            add_error \
                "auditd apply skipped: extended backup mapping не записан"

            if ! rm -f -- "$strict_backup"; then
                add_warning \
                    "auditd: не удалось удалить незарегистрированный backup $strict_backup"
            fi

            return 1
        fi
    fi

    if ! prepare_created_file_transaction \
        "$AUDITD_BASELINE_RULES" \
        "$baseline_existed" \
        "auditd baseline rules"
    then
        return 1
    fi

    if (( strict_required == 1 )); then
        if ! prepare_created_file_transaction \
            "$AUDITD_STRICT_RULES" \
            "$strict_existed" \
            "auditd extended rules"
        then
            return 1
        fi
    fi

    if ! pkg_installed auditd; then
        log "[i]     auditd: установка пакета..."
        apt_update_once

        install_packages_transactionally \
            "auditd" \
            auditd || true

        package_install_rc=$PACKAGE_TRANSACTION_INSTALL_RC
        package_tracking_rc=$PACKAGE_TRANSACTION_TRACKING_RC

        if (( package_install_rc != 0 )); then
            add_error \
                "auditd: не удалось установить пакет"

            record_manifest_warning \
                "auditd: apt-get install failed"

            return 1
        fi

        if (( package_tracking_rc != 0 )); then
            add_error \
                "auditd: пакет установлен, но учёт новых пакетов не выполнен"

            record_manifest_warning \
                "auditd: installed package tracking failed"

            return 1
        fi
    fi

    if ! pkg_installed auditd; then
        add_error \
            "auditd: пакет отсутствует после установки"
        return 1
    fi

    if ! command -v augenrules \
        >/dev/null 2>&1
    then
        add_error \
            "auditd: augenrules отсутствует"
        return 1
    fi

    if ! mkdir -p -- "$AUDITD_RULES_DIR"; then
        add_error \
            "auditd: не удалось создать каталог $AUDITD_RULES_DIR"
        return 1
    fi

    if ! atomic_write_command_output \
        "$AUDITD_BASELINE_RULES" \
        0640 \
        render_auditd_baseline_rules
    then
        add_error \
            "auditd: не удалось атомарно записать baseline rules"
        return 1
    fi

    if (( strict_required == 1 )); then
        if ! atomic_write_command_output \
            "$AUDITD_STRICT_RULES" \
            0640 \
            render_auditd_strict_rules
        then
            add_error \
                "auditd: не удалось атомарно записать extended rules"

            if ! rollback_auditd_rules_set \
                "$strict_required" \
                "$baseline_existed" \
                "$baseline_backup" \
                "$strict_existed" \
                "$strict_backup"
            then
                add_warning \
                    "auditd: откат rules-файлов после ошибки записи выполнен не полностью"
            fi

            return 1
        fi
    fi

    if ! systemctl enable --now auditd.service \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_error \
            "auditd: не удалось включить и запустить службу"

        if ! rollback_auditd_apply_changes \
            "$strict_required" \
            "$baseline_existed" \
            "$baseline_backup" \
            "$strict_existed" \
            "$strict_backup" \
            "$enabled_before" \
            "$active_before"
        then
            add_warning \
                "auditd: откат после ошибки enable --now выполнен не полностью"
        fi

        return 1
    fi

    if ! systemctl is-active --quiet \
        auditd.service \
        2>>"${DEBUG_LOG_FILE:-/dev/null}"
    then
        add_error \
            "auditd: служба не активна после enable --now"

        if ! rollback_auditd_apply_changes \
            "$strict_required" \
            "$baseline_existed" \
            "$baseline_backup" \
            "$strict_existed" \
            "$strict_backup" \
            "$enabled_before" \
            "$active_before"
        then
            add_warning \
                "auditd: откат после неуспешного запуска службы выполнен не полностью"
        fi

        return 1
    fi

    if ! augenrules --load \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_error \
            "auditd: augenrules --load завершился ошибкой"

        record_manifest_warning \
            "auditd: augenrules --load failed"

        if ! rollback_auditd_apply_changes \
            "$strict_required" \
            "$baseline_existed" \
            "$baseline_backup" \
            "$strict_existed" \
            "$strict_backup" \
            "$enabled_before" \
            "$active_before"
        then
            add_warning \
                "auditd: откат после ошибки загрузки выполнен не полностью"
        fi

        return 1
    fi

    if ! augenrules --check \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_error \
            "auditd: rules.d и скомпилированные правила не синхронизированы после загрузки"

        record_manifest_warning \
            "auditd: augenrules --check failed after load"

        if ! rollback_auditd_apply_changes \
            "$strict_required" \
            "$baseline_existed" \
            "$baseline_backup" \
            "$strict_existed" \
            "$strict_backup" \
            "$enabled_before" \
            "$active_before"
        then
            add_warning \
                "auditd: откат после ошибки проверки выполнен не полностью"
        fi

        return 1
    fi

    if (( baseline_existed == 0 )); then
        if ! record_manifest_created_file \
            "$AUDITD_BASELINE_RULES" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "auditd: созданный baseline rules-файл не записан в manifest"

            if ! rollback_auditd_apply_changes \
                "$strict_required" \
                "$baseline_existed" \
                "$baseline_backup" \
                "$strict_existed" \
                "$strict_backup" \
                "$enabled_before" \
                "$active_before"
            then
                add_warning \
                    "auditd: откат после ошибки manifest выполнен не полностью"
            fi

            return 1
        fi
    fi

    if (( strict_required == 1 \
        && strict_existed == 0 ))
    then
        if ! record_manifest_created_file \
            "$AUDITD_STRICT_RULES" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "auditd: созданный extended rules-файл не записан в manifest"

            if ! rollback_auditd_apply_changes \
                "$strict_required" \
                "$baseline_existed" \
                "$baseline_backup" \
                "$strict_existed" \
                "$strict_backup" \
                "$enabled_before" \
                "$active_before"
            then
                add_warning \
                    "auditd: откат после ошибки manifest выполнен не полностью"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$AUDITD_BASELINE_RULES"

    record_manifest_apply_report \
        "auditd baseline rules written"

    add_safe \
        "auditd: baseline rules written: $AUDITD_BASELINE_RULES"

    if (( strict_required == 1 )); then
        record_manifest_modified_file_best_effort \
            "$AUDITD_STRICT_RULES"

        record_manifest_apply_report \
            "auditd extended rules written"

        add_safe \
            "auditd: extended rules written: $AUDITD_STRICT_RULES"
    fi

    return 0
}

restore_auditd_module() {
    local pre_state_output=""
    local pre_state_rc=0
    local enabled_before=""
    local active_before=""
    local baseline_manifest_rc=0
    local strict_manifest_rc=0
    local tracked_count=0
    local file_restore_ok=1
    local reload_rules=0
    local overall_rc=0

    pre_state_output="$(
        restore_auditd_service_pre_state
    )" || pre_state_rc=$?

    case "$pre_state_rc" in
        0)
            IFS=$'\t' read -r \
                enabled_before \
                active_before \
                <<< "$pre_state_output"

            if [[ -z "$enabled_before" \
                || -z "$active_before" ]]
            then
                add_error \
                    "restore auditd: прежнее состояние службы прочитано не полностью"
                return 1
            fi
            ;;
        1)
            ;;
        *)
            add_error \
                "restore auditd: не удалось прочитать прежнее состояние службы"
            return 1
            ;;
    esac

    restore_manifest_has_path \
        "$AUDITD_BASELINE_RULES"
    baseline_manifest_rc=$?

    case "$baseline_manifest_rc" in
        0)
            tracked_count=$((tracked_count + 1))

            if ! restore_file_from_manifest \
                "$AUDITD_BASELINE_RULES"
            then
                file_restore_ok=0
                overall_rc=1
            fi
            ;;
        1)
            ;;
        *)
            return 1
            ;;
    esac

    restore_manifest_has_path \
        "$AUDITD_STRICT_RULES"
    strict_manifest_rc=$?

    case "$strict_manifest_rc" in
        0)
            tracked_count=$((tracked_count + 1))

            if ! restore_file_from_manifest \
                "$AUDITD_STRICT_RULES"
            then
                file_restore_ok=0
                overall_rc=1
            fi
            ;;
        1)
            ;;
        *)
            return 1
            ;;
    esac

    if (( pre_state_rc == 0 )); then
        if (( tracked_count > 0 \
            && file_restore_ok == 1 ))
        then
            reload_rules=1
        fi

        if ! restore_auditd_service_state \
            "$enabled_before" \
            "$active_before" \
            "$reload_rules"
        then
            add_warning \
                "restore auditd: не удалось восстановить прежнее состояние службы"
            overall_rc=1
        fi
    elif (( tracked_count > 0 \
        && file_restore_ok == 1 ))
    then
        if command -v augenrules \
            >/dev/null 2>&1
        then
            if ! augenrules --load \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                add_warning \
                    "restore auditd: правила восстановлены, но legacy augenrules --load завершился с ошибкой"
                overall_rc=1
            fi
        else
            if ! systemctl restart auditd.service \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                add_warning \
                    "restore auditd: правила восстановлены, но legacy restart auditd завершился с ошибкой"
                overall_rc=1
            fi
        fi
    fi

    if ! restore_installed_packages "auditd"; then
        overall_rc=1
    fi

    return "$overall_rc"
}

corporate_password_policy_enabled() {
    case "${ENABLE_CORPORATE_PASSWORD_POLICY:-0}" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

check_password_backend_safety_module() {
    local issues=0
    local pam_file="${SECURELINUX_NG_COMMON_PASSWORD_FILE:-/etc/pam.d/common-password}"
    local pwquality_file="${SECURELINUX_NG_PWQUALITY_CONF_FILE:-/etc/security/pwquality.conf}"
    local pwquality_dir="${SECURELINUX_NG_PWQUALITY_CONF_DIR:-/etc/security/pwquality.conf.d}"
    local cracklib_dir="${SECURELINUX_NG_CRACKLIB_DIR:-/var/cache/cracklib}"
    local cracklib_check="${SECURELINUX_NG_CRACKLIB_CHECK:-cracklib-check}"

    if [[ -f "$pam_file" ]] &&
       grep -Eq '^[[:space:]]*[^#].*pam_pwquality\.so' "$pam_file"; then
        local dictcheck_enabled=1

        if grep -RhsE \
            '^[[:space:]]*dictcheck[[:space:]]*=[[:space:]]*0([[:space:]]|$)' \
            "$pwquality_file" \
            "$pwquality_dir" 2>/dev/null |
            tail -n 1 | grep -q .; then
            dictcheck_enabled=0
        fi

        if (( dictcheck_enabled == 1 )); then
            local backend_broken=0
            local file

            if [[ "$cracklib_check" == */* ]]; then
                [[ -x "$cracklib_check" ]] || backend_broken=1
            else
                command -v "$cracklib_check" >/dev/null 2>&1 ||
                    backend_broken=1
            fi

            for file in \
                "$cracklib_dir/cracklib_dict.pwd" \
                "$cracklib_dir/cracklib_dict.pwi" \
                "$cracklib_dir/cracklib_dict.hwm"; do
                [[ -s "$file" ]] || backend_broken=1
            done

            if [[ "$cracklib_check" == */* && -x "$cracklib_check" ]] ||
               command -v "$cracklib_check" >/dev/null 2>&1; then
                local probe=""

                if ! probe="$(
                    "$cracklib_check" 2>&1 \
                        <<< 'Q7v!9mZ2#L4x8R6k'
                )"; then
                    backend_broken=1
                elif grep -qiE \
                    'no such file|error loading dictionary|cannot open|failed' \
                    <<<"$probe"; then
                    backend_broken=1
                fi
            fi

            if (( backend_broken == 1 )); then
                add_risky \
                    "PAM_ACTIVE_DICTIONARY_BROKEN: pam_pwquality активен, словарь неработоспособен"
                issues=1
            else
                add_safe \
                    "pam_pwquality: словарный backend работоспособен"
            fi
        else
            add_safe \
                "pam_pwquality: словарная проверка явно отключена (dictcheck=0)"
        fi
    fi

    local shadow_file="${SECURELINUX_NG_SHADOW_FILE:-/etc/shadow}"
    local root_state

    if ! root_state="$(python3 - "$shadow_file" <<'PYROOT'
import sys
from pathlib import Path

path = Path(sys.argv[1])

try:
    lines = path.read_text(
        encoding="utf-8", errors="ignore"
    ).splitlines()
except PermissionError:
    print("UNREADABLE")
    raise SystemExit(0)
except OSError:
    print("MISSING")
    raise SystemExit(0)

for line in lines:
    parts = line.split(":")
    if len(parts) < 5 or parts[0] != "root":
        continue

    password = parts[1]
    maximum = parts[4].strip()

    if password == "":
        print("EMPTY")
    elif password.startswith(("!", "*")):
        if maximum in ("", "-1"):
            print("LOCKED_UNLIMITED")
        elif maximum.isdigit() and int(maximum) >= 99999:
            print("LOCKED_UNLIMITED")
        else:
            print("LOCKED_FINITE")
    else:
        print("ACTIVE")
    raise SystemExit(0)

print("MISSING")
PYROOT
)"; then
        add_risky \
            "ROOT_PASSWORD_STATE_CHECK_FAILED: не удалось проверить состояние root в $shadow_file"
        issues=1
        root_state=""
    fi

    case "$root_state" in
        LOCKED_FINITE)
            add_risky \
                "LOCKED_ROOT_PASSWORD_EXPIRES: заблокированной root задан конечный срок пароля"
            issues=1
            ;;
        LOCKED_UNLIMITED)
            add_safe \
                "root: пароль заблокирован и не имеет конечного срока"
            ;;
        EMPTY)
            add_risky "EMPTY_ROOT_PASSWORD: поле пароля root пустое"
            issues=1
            ;;
        UNREADABLE)
            add_warning \
                "root: /etc/shadow недоступен без привилегий"
            ;;
        MISSING)
            add_risky "root: запись или /etc/shadow отсутствует"
            issues=1
            ;;
    esac

    return "$issues"
}

check_password_policy_module() {
    local issues=0

    check_password_backend_safety_module || issues=1

    if ! corporate_password_policy_enabled; then
        add_skipped "Корпоративная парольная политика отключена; выполнены только обязательные проверки"
        return "$issues"
    fi

    local expected_max expected_min expected_warn
    expected_min="$PASS_MIN_DAYS"
    expected_warn="$PASS_WARN_AGE"

    if profile_allows paranoid; then
        expected_max="$PASS_MAX_DAYS_PARANOID"
    elif profile_allows strict; then
        expected_max="$PASS_MAX_DAYS_STRICT"
    else
        expected_max="$PASS_MAX_DAYS_BASELINE"
    fi

    local expected_minlen=15
    profile_allows strict && expected_minlen=16
    if [[ -f "$PWQUALITY_CONF" ]]; then
        local actual_minlen
        actual_minlen=$(awk -F'=' '/^[[:space:]]*minlen[[:space:]]*=/{gsub(/ /,"",$2); print $2; exit}' "$PWQUALITY_CONF" 2>/dev/null || echo "")
        if [[ "$actual_minlen" == "$expected_minlen" ]]; then
            add_safe "CORP-PASSWORD pwquality: $PWQUALITY_CONF присутствует (minlen=$actual_minlen)"
        else
            add_risky "CORP-PASSWORD pwquality: $PWQUALITY_CONF отсутствует или minlen не задан (ожидалось $expected_minlen, фактически ${actual_minlen:-unset})"
            issues=1
        fi
    else
        add_risky "CORP-PASSWORD pwquality: $PWQUALITY_CONF отсутствует или minlen не задан"
        issues=1
    fi

    if [[ -f "/etc/pam.d/common-password" ]]; then
        if python3 - /etc/pam.d/common-password <<'PYCHECKPW'
import sys
from pathlib import Path

lines = Path(sys.argv[1]).read_text(encoding='utf-8').splitlines()

def active_has(token):
    for i, line in enumerate(lines):
        s = line.strip()
        if s and not s.startswith('#') and token in s:
            return i
    return None

pwq = active_has('pam_pwquality.so')
pwh = active_has('pam_pwhistory.so')
unix = active_has('pam_unix.so')

ok = pwq is not None and pwh is not None and unix is not None and pwq < pwh < unix
raise SystemExit(0 if ok else 1)
PYCHECKPW
        then
            add_safe "CORP-PASSWORD common-password: pam_pwquality -> pam_pwhistory -> pam_unix"
        else
            add_risky "CORP-PASSWORD common-password: нарушен порядок pam_pwquality/pam_pwhistory/pam_unix"
            issues=1
        fi
    else
        add_risky "CORP-PASSWORD common-password: /etc/pam.d/common-password отсутствует"
        issues=1
    fi

    if [[ -f "$LOGIN_DEFS" ]]; then
        local max min warn
        max=$(awk '/^[[:space:]]*PASS_MAX_DAYS[[:space:]]+/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null || echo "")
        min=$(awk '/^[[:space:]]*PASS_MIN_DAYS[[:space:]]+/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null || echo "")
        warn=$(awk '/^[[:space:]]*PASS_WARN_AGE[[:space:]]+/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null || echo "")
        if [[ "$max" == "$expected_max" && "$min" == "$expected_min" && "$warn" == "$expected_warn" ]]; then
            add_safe "CORP-PASSWORD login.defs: PASS_MAX_DAYS=$max PASS_MIN_DAYS=$min PASS_WARN_AGE=$warn"
        else
            add_risky "CORP-PASSWORD login.defs: ожидалось max=$expected_max min=$expected_min warn=$expected_warn, фактически max=${max:-unset} min=${min:-unset} warn=${warn:-unset}"
            issues=1
        fi
    else
        add_risky "CORP-PASSWORD login.defs: $LOGIN_DEFS отсутствует"
        issues=1
    fi

    # aging проверяется всегда, включая dry-run
    local uid_min
        uid_min="$(awk '/^[[:space:]]*UID_MIN[[:space:]]+/{print $2; exit}' "$LOGIN_DEFS" 2>/dev/null || true)"
        [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000

        local account aging_failed=0 checked=0
        local password_policy_accounts_output=""

        if ! password_policy_accounts_output="$(list_password_policy_target_accounts "$uid_min")"; then
            add_error "CORP-PASSWORD chage: не удалось получить список локальных учетных записей"
            return 1
        fi

        while IFS= read -r account; do
            [[ -n "$account" ]] || continue
            checked=1
            python3 - "$account" "$expected_min" "$expected_max" "$expected_warn" <<'PYSHADOWCHK'
import sys
from pathlib import Path

account = sys.argv[1]
expected_min = sys.argv[2]
expected_max = sys.argv[3]
expected_warn = sys.argv[4]

shadow = Path("/etc/shadow")
if not shadow.exists():
    raise SystemExit(20)

try:
    lines = shadow.read_text(encoding="utf-8", errors="ignore").splitlines()
except PermissionError:
    raise SystemExit(30)

for line in lines:
    if not line or ":" not in line:
        continue
    parts = line.split(":")
    if parts[0] != account:
        continue
    if len(parts) < 6:
        raise SystemExit(21)
    actual_min = parts[3].strip()
    actual_max = parts[4].strip()
    actual_warn = parts[5].strip()
    if actual_min != expected_min:
        raise SystemExit(11)
    if actual_max != expected_max:
        raise SystemExit(10)
    if actual_warn != expected_warn:
        raise SystemExit(12)
    raise SystemExit(0)

raise SystemExit(22)
PYSHADOWCHK
            rc=$?
            if (( rc == 30 )); then
                add_warning "CORP-PASSWORD chage: проверка aging неполная без root — нет доступа к /etc/shadow"
                checked=0
                aging_failed=0
                break
            elif (( rc != 0 )); then
                add_risky "CORP-PASSWORD chage: параметры aging не применены к учетной записи $account"
                aging_failed=1
                break
            fi
        done <<< "$password_policy_accounts_output"

        if (( checked == 1 && aging_failed == 0 )); then
            add_safe "CORP-PASSWORD chage: password aging применён к существующим локальным учетным записям"
        elif (( checked == 0 )); then
            add_warning "CORP-PASSWORD chage: проверка aging неполная — локальные учетные записи не проверены"
        else
            issues=1
        fi
    return $issues
}


list_password_policy_target_accounts() {
    local uid_min="${1:-1000}"
    python3 - "$uid_min" <<'PYJSON'
import os
import sys
from pathlib import Path

uid_min = int(sys.argv[1])

passwd_path = Path(
    os.environ.get("SECURELINUX_NG_PASSWD_FILE", "/etc/passwd")
)
shadow_path = Path(
    os.environ.get("SECURELINUX_NG_SHADOW_FILE", "/etc/shadow")
)

skip_shells = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "false",
    "nologin",
}

try:
    shadow_passwords = {}
    for line in shadow_path.read_text(
        encoding="utf-8", errors="ignore"
    ).splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            shadow_passwords[parts[0]] = parts[1]
except (OSError, PermissionError):
    # Без достоверного /etc/shadow применять chage нельзя.
    raise SystemExit(0)

for line in passwd_path.read_text(
    encoding="utf-8", errors="ignore"
).splitlines():
    parts = line.split(":")
    if len(parts) < 7:
        continue

    user, _, uid, _, _, _, shell = parts[:7]

    try:
        uid = int(uid)
    except ValueError:
        continue

    if user != "root" and uid < uid_min:
        continue

    if shell in skip_shells:
        continue

    password = shadow_passwords.get(user, "")

    # Пустые и заблокированные записи исключаются из chage.
    if not password or password.startswith(("!", "*")):
        continue

    print(user)
PYJSON
}

normalize_common_password_stack() {
    local path="$1"
    local count="$2"

    atomic_write_command_output \
        "$path" \
        0644 \
        python3 - "$path" "$count" <<'PYJSON'
import sys
from pathlib import Path

path = Path(sys.argv[1])
count = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()


def active_has(line: str, token: str) -> bool:
    stripped = line.strip()
    return (
        bool(stripped)
        and not stripped.startswith("#")
        and token in stripped
    )


filtered = [
    line
    for line in lines
    if not active_has(line, "pam_pwhistory")
]

unix_index = next(
    (
        index
        for index, line in enumerate(filtered)
        if active_has(line, "pam_unix.so")
    ),
    None,
)

if unix_index is None:
    raise SystemExit(
        "active pam_unix.so line not found in common-password"
    )

pwquality_index = next(
    (
        index
        for index, line in enumerate(filtered)
        if active_has(line, "pam_pwquality.so")
    ),
    None,
)

pwquality_line = (
    "password    requisite    "
    "pam_pwquality.so retry=3"
)

if pwquality_index is not None:
    filtered.pop(pwquality_index)

    if pwquality_index < unix_index:
        unix_index -= 1

filtered.insert(unix_index, pwquality_line)

filtered.insert(
    unix_index + 1,
    (
        "password    required    "
        "pam_pwhistory.so use_authtok "
        f"remember={count} enforce_for_root"
    ),
)

print("\n".join(filtered) + "\n", end="")
PYJSON
}

record_manifest_password_aging_snapshot() {
    local account="$1"

    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    [[ -n "$account" ]] || return 1

    python3 - "$MANIFEST_FILE" "$account" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

manifest = pathlib.Path(sys.argv[1])
account = sys.argv[2]
shadow = pathlib.Path("/etc/shadow")

entry = None

for raw in shadow.read_text(
    encoding="utf-8",
    errors="strict",
).splitlines():
    parts = raw.split(":")

    if len(parts) < 9 or parts[0] != account:
        continue

    entry = {
        "user": account,
        "last_change": parts[2],
        "min_days": parts[3],
        "max_days": parts[4],
        "warn_days": parts[5],
        "inactive_days": parts[6],
        "expire_date": parts[7],
    }
    break

if entry is None:
    raise SystemExit(2)

data = json.loads(manifest.read_text(encoding="utf-8"))
items = data.setdefault("password_aging_snapshots", [])

# Повторный apply не должен перезаписывать исходное состояние.
if any(
    isinstance(item, dict)
    and item.get("user") == account
    for item in items
):
    raise SystemExit(0)

items.append(entry)

fd, temporary = tempfile.mkstemp(
    dir=str(manifest.parent),
    prefix=".manifest.tmp.",
)

try:
    content = json.dumps(
        data,
        indent=2,
        ensure_ascii=False,
    ) + "\n"

    os.write(fd, content.encode("utf-8"))
    os.fsync(fd)
    os.close(fd)
    os.replace(temporary, manifest)
except Exception:
    try:
        os.close(fd)
    except OSError:
        pass

    try:
        os.unlink(temporary)
    except OSError:
        pass

    raise
PYJSON
}


restore_password_aging_snapshots() {
    local account
    local last_change
    local min_days
    local max_days
    local warn_days
    local inactive_days
    local expire_date
    local value
    local invalid
    local restored=0
    local failed=0
    local snapshots_output=""


    if ! snapshots_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import json
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
data = json.loads(manifest.read_text(encoding="utf-8"))

fields = (
    "user",
    "last_change",
    "min_days",
    "max_days",
    "warn_days",
    "inactive_days",
    "expire_date",
)

for item in data.get("password_aging_snapshots", []):
    if not isinstance(item, dict):
        continue

    user = item.get("user")

    if not isinstance(user, str) or not user:
        continue

    values = []

    for field in fields:
        value = item.get(field, "")

        if value is None:
            value = ""

        values.append(str(value))

    print("|".join(values))
PYJSON
    )"; then
        add_error "restore password aging: не удалось прочитать manifest"
        return 1
    fi

    while IFS='|' read -r \
        account \
        last_change \
        min_days \
        max_days \
        warn_days \
        inactive_days \
        expire_date
    do
        [[ -n "$account" ]] || continue

        [[ -n "$last_change" ]] || last_change=-1
        [[ -n "$min_days" ]] || min_days=0
        [[ -n "$max_days" ]] || max_days=-1
        [[ -n "$warn_days" ]] || warn_days=-1
        [[ -n "$inactive_days" ]] || inactive_days=-1
        [[ -n "$expire_date" ]] || expire_date=-1

        invalid=0

        for value in \
            "$last_change" \
            "$min_days" \
            "$max_days" \
            "$warn_days" \
            "$inactive_days" \
            "$expire_date"
        do
            if [[ ! "$value" =~ ^-?[0-9]+$ ]]; then
                invalid=1
                break
            fi
        done

        if (( invalid == 1 )); then
            add_error \
                "restore password aging: invalid snapshot for '$account'"
            failed=1
            continue
        fi

        if ! id "$account" >/dev/null 2>&1; then
            add_warning \
                "restore password aging: user '$account' no longer exists"
            failed=1
            continue
        fi

        if chage \
            -d "$last_change" \
            -m "$min_days" \
            -M "$max_days" \
            -W "$warn_days" \
            -I "$inactive_days" \
            -E "$expire_date" \
            "$account"
        then
            add_safe \
                "restore password aging: restored original state for '$account'"
            restored=1
        else
            add_error \
                "restore password aging: chage failed for '$account'"
            failed=1
        fi
    done <<< "$snapshots_output"

    if (( restored == 0 && failed == 0 )); then
        log "[i]     restore password aging: снимков в manifest нет — пропуск"
    fi

    return "$failed"
}


record_password_aging_transaction_snapshot() {
    local transaction_file="$1"
    local account="$2"
    local shadow_file="${SECURELINUX_NG_SHADOW_FILE:-/etc/shadow}"

    [[ -n "$transaction_file" ]] || return 1
    [[ -n "$account" ]] || return 1

    python3 - \
        "$transaction_file" \
        "$account" \
        "$shadow_file" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

transaction = pathlib.Path(sys.argv[1])
account = sys.argv[2]
shadow = pathlib.Path(sys.argv[3])

if not account or "\n" in account or "\t" in account:
    raise ValueError("invalid account name")

entry = None

for raw in shadow.read_text(
    encoding="utf-8",
    errors="strict",
).splitlines():
    parts = raw.split(":")

    if len(parts) < 9 or parts[0] != account:
        continue

    entry = {
        "user": account,
        "last_change": parts[2],
        "min_days": parts[3],
        "max_days": parts[4],
        "warn_days": parts[5],
        "inactive_days": parts[6],
        "expire_date": parts[7],
    }
    break

if entry is None:
    raise SystemExit(2)

items = []

if transaction.exists():
    items = json.loads(
        transaction.read_text(encoding="utf-8")
    )

    if not isinstance(items, list):
        raise ValueError(
            "transaction snapshot root is not an array"
        )

    for item in items:
        if not isinstance(item, dict):
            raise ValueError(
                "transaction snapshot entry is not an object"
            )

        user = item.get("user")

        if not isinstance(user, str) or not user:
            raise ValueError(
                "transaction snapshot has invalid user"
            )

if any(
    item.get("user") == account
    for item in items
):
    raise SystemExit(0)

items.append(entry)
transaction.parent.mkdir(
    parents=True,
    exist_ok=True,
)

fd, temporary = tempfile.mkstemp(
    dir=str(transaction.parent),
    prefix=".password-aging.rollback.",
)

try:
    os.fchmod(fd, 0o600)

    with os.fdopen(
        fd,
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            items,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())

    os.replace(temporary, transaction)
except Exception:
    try:
        os.close(fd)
    except OSError:
        pass

    try:
        os.unlink(temporary)
    except OSError:
        pass

    raise
PYJSON
}

rollback_password_aging_transaction() {
    local transaction_file="$1"
    local snapshots_output=""
    local account=""
    local last_change=""
    local min_days=""
    local max_days=""
    local warn_days=""
    local inactive_days=""
    local expire_date=""
    local failed=0

    [[ -n "$transaction_file" ]] || return 1

    if [[ ! -f "$transaction_file" ]]; then
        return 0
    fi

    if ! snapshots_output="$(
        python3 - "$transaction_file" <<'PYJSON'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
items = json.loads(
    path.read_text(encoding="utf-8")
)

if not isinstance(items, list):
    raise ValueError(
        "transaction snapshot root is not an array"
    )

fields = (
    "user",
    "last_change",
    "min_days",
    "max_days",
    "warn_days",
    "inactive_days",
    "expire_date",
)

for item in items:
    if not isinstance(item, dict):
        raise ValueError(
            "transaction snapshot entry is not an object"
        )

    values = []

    for field in fields:
        value = item.get(field, "")

        if value is None:
            value = ""

        value = str(value)

        if "\n" in value or "\t" in value:
            raise ValueError(
                "transaction snapshot contains unsafe value"
            )

        values.append(value)

    if not values[0]:
        raise ValueError(
            "transaction snapshot has empty user"
        )

    print("\t".join(values))
PYJSON
    )"
    then
        add_error \
            "CORP-PASSWORD rollback aging: не удалось прочитать transaction snapshot"
        return 1
    fi

    while IFS=$'\t' read -r \
        account \
        last_change \
        min_days \
        max_days \
        warn_days \
        inactive_days \
        expire_date
    do
        [[ -n "$account" ]] || continue

        [[ -n "$last_change" ]] || last_change=-1
        [[ -n "$min_days" ]] || min_days=0
        [[ -n "$max_days" ]] || max_days=-1
        [[ -n "$warn_days" ]] || warn_days=-1
        [[ -n "$inactive_days" ]] || inactive_days=-1
        [[ -n "$expire_date" ]] || expire_date=-1

        if ! id "$account" >/dev/null 2>&1; then
            add_error \
                "CORP-PASSWORD rollback aging: пользователь '$account' отсутствует"
            failed=1
            continue
        fi

        if ! chage \
            -d "$last_change" \
            -m "$min_days" \
            -M "$max_days" \
            -W "$warn_days" \
            -I "$inactive_days" \
            -E "$expire_date" \
            "$account"
        then
            add_error \
                "CORP-PASSWORD rollback aging: chage failed for '$account'"
            failed=1
        fi
    done <<< "$snapshots_output"

    return "$failed"
}

cleanup_password_aging_transaction_snapshot() {
    local transaction_file="$1"

    [[ -n "$transaction_file" ]] || return 1
    rm -f -- "$transaction_file"
}

apply_password_policy_existing_accounts() {
    local max_days="$1"
    local uid_min
    local shadow_file="${SECURELINUX_NG_SHADOW_FILE:-/etc/shadow}"
    local transaction_file="$STATE_DIR/password-aging.rollback-$TIMESTAMP.json"
    local password_policy_accounts_output=""

    uid_min="$(
        awk \
            '/^[[:space:]]*UID_MIN[[:space:]]+/{print $2; exit}' \
            "$LOGIN_DEFS" \
            2>/dev/null \
            || true
    )"

    [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000

    if ! password_policy_accounts_output="$(
        list_password_policy_target_accounts \
            "$uid_min"
    )"
    then
        add_error \
            "CORP-PASSWORD chage: не удалось получить список локальных учетных записей"
        return 1
    fi

    if (( DRY_RUN == 1 )); then
        local dry_run_account=""

        while IFS= read -r dry_run_account; do
            [[ -n "$dry_run_account" ]] || continue

            log \
                "[DRY-RUN] password aging bootstrap check for '$dry_run_account'"
            log \
                "[DRY-RUN] chage -m $PASS_MIN_DAYS -M $max_days -W $PASS_WARN_AGE '$dry_run_account'"
        done <<< "$password_policy_accounts_output"

        add_skipped \
            "CORP-PASSWORD dry-run: password aging would be applied to existing local accounts via chage"

        return 0
    fi

    if ! cleanup_password_aging_transaction_snapshot \
        "$transaction_file"
    then
        add_error \
            "CORP-PASSWORD не удалось очистить прежний transaction snapshot aging"
        return 1
    fi

    local account=""
    local action=""
    local changed=0
    local snapshot_failed=0
    local action_failed=0
    local transaction_snapshot_failed=0
    local chage_failed=0

    while IFS= read -r account; do
        [[ -n "$account" ]] || continue

        if ! record_manifest_password_aging_snapshot "$account"; then
            add_error \
                "CORP-PASSWORD chage: не удалось сохранить исходный aging для $account — учетная запись не изменена"
            snapshot_failed=1
            continue
        fi

        if ! action="$(
            python3 - \
                "$account" \
                "$max_days" \
                "$shadow_file" <<'PYJSON'
import sys
from datetime import datetime, timezone
from pathlib import Path

account = sys.argv[1]
max_days = int(sys.argv[2])
shadow = Path(sys.argv[3])

if not shadow.exists():
    print("apply")
    raise SystemExit(0)

for line in shadow.read_text(
    encoding="utf-8",
    errors="ignore",
).splitlines():
    if not line or ":" not in line:
        continue

    parts = line.split(":")

    if parts[0] != account:
        continue

    lastchg = (
        parts[2].strip()
        if len(parts) > 2
        else ""
    )

    if lastchg in ("", "-1"):
        print("apply")
        raise SystemExit(0)

    try:
        lastchg_i = int(lastchg)
    except Exception:
        print("apply")
        raise SystemExit(0)

    today = int(
        datetime.now(timezone.utc).timestamp()
        // 86400
    )

    if (
        lastchg_i <= 0
        or today > lastchg_i + max_days
    ):
        print("reset_lastday")
    else:
        print("apply")

    raise SystemExit(0)

print("apply")
PYJSON
        )"
        then
            add_error \
                "CORP-PASSWORD chage: не удалось определить действие для $account — учетная запись не изменена"
            action_failed=1
            continue
        fi

        case "$action" in
            apply|reset_lastday)
                ;;
            *)
                add_error \
                    "CORP-PASSWORD chage: неизвестное действие '$action' для $account — учетная запись не изменена"
                action_failed=1
                continue
                ;;
        esac

        if ! record_password_aging_transaction_snapshot \
            "$transaction_file" \
            "$account"
        then
            add_error \
                "CORP-PASSWORD chage: не удалось сохранить transaction snapshot aging для $account — учетная запись не изменена"
            transaction_snapshot_failed=1
            continue
        fi

        if [[ "$action" == "reset_lastday" ]]; then
            if chage -d "$(date -u +%F)" "$account" \
                && chage -m "$PASS_MIN_DAYS" \
                    -M "$max_days" \
                    -W "$PASS_WARN_AGE" \
                    "$account"
            then
                record_manifest_apply_report \
                    "CORP-PASSWORD chage bootstrap reset lastday to today for expired user=$account max=$max_days min=$PASS_MIN_DAYS warn=$PASS_WARN_AGE"

                add_warning \
                    "CORP-PASSWORD chage: для существующей УЗ $account дата последней смены пароля сдвинута на сегодня, чтобы не вызвать немедленную просрочку"

                changed=1
            else
                add_error \
                    "CORP-PASSWORD chage bootstrap failed for user: $account"
                chage_failed=1
            fi

            continue
        fi

        if chage -m "$PASS_MIN_DAYS" \
            -M "$max_days" \
            -W "$PASS_WARN_AGE" \
            "$account"
        then
            record_manifest_apply_report \
                "CORP-PASSWORD chage applied: user=$account max=$max_days min=$PASS_MIN_DAYS warn=$PASS_WARN_AGE"
            changed=1
        else
            add_error \
                "CORP-PASSWORD chage failed for user: $account"
            chage_failed=1
        fi
    done <<< "$password_policy_accounts_output"

    if (( snapshot_failed == 1 \
        || action_failed == 1 \
        || transaction_snapshot_failed == 1 \
        || chage_failed == 1 ))
    then
        add_error \
            "CORP-PASSWORD password aging применён не ко всем целевым учетным записям"

        if ! rollback_password_aging_transaction \
            "$transaction_file"
        then
            add_error \
                "CORP-PASSWORD rollback password aging выполнен не полностью"
        fi

        if ! cleanup_password_aging_transaction_snapshot \
            "$transaction_file"
        then
            add_warning \
                "CORP-PASSWORD не удалось удалить transaction snapshot aging после rollback"
        fi

        return 1
    fi

    if ! cleanup_password_aging_transaction_snapshot \
        "$transaction_file"
    then
        add_warning \
            "CORP-PASSWORD не удалось удалить transaction snapshot aging после успешного применения"
    fi

    if (( changed == 1 )); then
        add_safe \
            "CORP-PASSWORD password aging applied to existing local accounts via chage"
    else
        add_warning \
            "4.1 no existing local accounts were updated via chage"
    fi

    return 0
}

snapshot_password_policy_transaction_file() {
    local target="$1"
    local snapshot="$2"

    [[ -n "$target" ]] || return 1
    [[ -n "$snapshot" ]] || return 1

    if ! mkdir -p -- "$(dirname "$snapshot")"; then
        return 1
    fi

    if ! rm -f -- "$snapshot"; then
        return 1
    fi

    if [[ ! -e "$target" && ! -L "$target" ]]; then
        return 0
    fi

    if [[ ! -f "$target" && ! -L "$target" ]]; then
        return 1
    fi

    cp -a -- "$target" "$snapshot"
}

restore_password_policy_transaction_file() {
    local target="$1"
    local existed_before="$2"
    local snapshot="$3"

    [[ -n "$target" ]] || return 1

    case "$existed_before" in
        0|1)
            ;;
        *)
            return 1
            ;;
    esac

    if (( existed_before == 0 )); then
        rm -f -- "$target"
        return $?
    fi

    if [[ -z "$snapshot" \
        || ! -e "$snapshot" \
        && ! -L "$snapshot" ]]
    then
        return 1
    fi

    if [[ -e "$target" || -L "$target" ]]; then
        if ! rm -f -- "$target"; then
            return 1
        fi
    fi

    cp -a -- "$snapshot" "$target"
}

rollback_password_policy_apply_files() {
    local pwquality_target="$1"
    local pwquality_existed="$2"
    local pwquality_snapshot="$3"
    local pwhistory_target="$4"
    local pwhistory_existed="$5"
    local pwhistory_snapshot="$6"
    local login_defs_target="$7"
    local login_defs_existed="$8"
    local login_defs_snapshot="$9"
    local rc=0

    if ! restore_password_policy_transaction_file \
        "$pwhistory_target" \
        "$pwhistory_existed" \
        "$pwhistory_snapshot"
    then
        rc=1
    fi

    if ! restore_password_policy_transaction_file \
        "$login_defs_target" \
        "$login_defs_existed" \
        "$login_defs_snapshot"
    then
        rc=1
    fi

    if ! restore_password_policy_transaction_file \
        "$pwquality_target" \
        "$pwquality_existed" \
        "$pwquality_snapshot"
    then
        rc=1
    fi

    return "$rc"
}

cleanup_password_policy_transaction_backups() {
    local path=""
    local rc=0

    for path in "$@"; do
        [[ -n "$path" ]] || continue

        if ! rm -f -- "$path"; then
            rc=1
        fi
    done

    return "$rc"
}

abort_password_policy_apply_transaction() {
    local pwquality_target="$1"
    local pwquality_existed="$2"
    local pwquality_snapshot="$3"
    local pwhistory_target="$4"
    local pwhistory_existed="$5"
    local pwhistory_snapshot="$6"
    local login_defs_target="$7"
    local login_defs_existed="$8"
    local login_defs_snapshot="$9"
    local rc=0

    if ! rollback_password_policy_apply_files \
        "$pwquality_target" \
        "$pwquality_existed" \
        "$pwquality_snapshot" \
        "$pwhistory_target" \
        "$pwhistory_existed" \
        "$pwhistory_snapshot" \
        "$login_defs_target" \
        "$login_defs_existed" \
        "$login_defs_snapshot"
    then
        add_error \
            "CORP-PASSWORD файловый rollback выполнен не полностью"
        rc=1
    fi

    if ! cleanup_password_policy_transaction_backups \
        "$pwquality_snapshot" \
        "$pwhistory_snapshot" \
        "$login_defs_snapshot"
    then
        add_warning \
            "CORP-PASSWORD не удалось удалить все transaction snapshots после rollback"
        rc=1
    fi

    return "$rc"
}

apply_password_policy_module() {
    if ! corporate_password_policy_enabled; then
        add_skipped "Корпоративная парольная политика отключена и не изменялась"
        return 0
    fi

    local max_days
    if profile_allows paranoid; then
        max_days="$PASS_MAX_DAYS_PARANOID"
    elif profile_allows strict; then
        max_days="$PASS_MAX_DAYS_STRICT"
    else
        max_days="$PASS_MAX_DAYS_BASELINE"
    fi

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] write '$PWQUALITY_CONF' (profile: ${PROFILE})"
        log "[DRY-RUN] update '$LOGIN_DEFS' PASS_MAX_DAYS/PASS_MIN_DAYS/PASS_WARN_AGE"
        apply_password_policy_existing_accounts "$max_days"
        add_skipped "CORP-PASSWORD dry-run: password policy would be applied"
        return 0
    fi

    local pwhistory_file="/etc/pam.d/common-password"

    local pwquality_transaction_existed=0
    local pwhistory_transaction_existed=0
    local login_defs_transaction_existed=0

    local pwquality_transaction_snapshot="$STATE_DIR/pwquality.conf.rollback-$TIMESTAMP"
    local pwhistory_transaction_snapshot="$STATE_DIR/common-password.rollback-$TIMESTAMP"
    local login_defs_transaction_snapshot="$STATE_DIR/login.defs.rollback-$TIMESTAMP"

    [[ -e "$PWQUALITY_CONF" || -L "$PWQUALITY_CONF" ]] &&
        pwquality_transaction_existed=1

    [[ -e "$pwhistory_file" || -L "$pwhistory_file" ]] &&
        pwhistory_transaction_existed=1

    [[ -e "$LOGIN_DEFS" || -L "$LOGIN_DEFS" ]] &&
        login_defs_transaction_existed=1

    local -a password_policy_transaction=(
        "$PWQUALITY_CONF"
        "$pwquality_transaction_existed"
        "$pwquality_transaction_snapshot"
        "$pwhistory_file"
        "$pwhistory_transaction_existed"
        "$pwhistory_transaction_snapshot"
        "$LOGIN_DEFS"
        "$login_defs_transaction_existed"
        "$login_defs_transaction_snapshot"
    )

    if ! snapshot_password_policy_transaction_file         "$PWQUALITY_CONF"         "$pwquality_transaction_snapshot"
    then
        add_error             "CORP-PASSWORD не удалось создать transaction snapshot $PWQUALITY_CONF"

        cleanup_password_policy_transaction_backups             "$pwquality_transaction_snapshot"             "$pwhistory_transaction_snapshot"             "$login_defs_transaction_snapshot"             || true

        return 1
    fi

    if ! snapshot_password_policy_transaction_file         "$pwhistory_file"         "$pwhistory_transaction_snapshot"
    then
        add_error             "CORP-PASSWORD не удалось создать transaction snapshot $pwhistory_file"

        cleanup_password_policy_transaction_backups             "$pwquality_transaction_snapshot"             "$pwhistory_transaction_snapshot"             "$login_defs_transaction_snapshot"             || true

        return 1
    fi

    if ! snapshot_password_policy_transaction_file         "$LOGIN_DEFS"         "$login_defs_transaction_snapshot"
    then
        add_error             "CORP-PASSWORD не удалось создать transaction snapshot $LOGIN_DEFS"

        cleanup_password_policy_transaction_backups             "$pwquality_transaction_snapshot"             "$pwhistory_transaction_snapshot"             "$login_defs_transaction_snapshot"             || true

        return 1
    fi

    # Preserve the state before dependency installation because
    # libpwquality-common may create pwquality.conf during apt-get install.
    local pwquality_existed_before_dependencies=0
    local pwquality_backup_before_dependencies=""

    if [[ -f "$PWQUALITY_CONF" ]]; then
        pwquality_existed_before_dependencies=1
        pwquality_backup_before_dependencies="$STATE_DIR/$(basename "$PWQUALITY_CONF").bak-$TIMESTAMP"

        if ! manifest_has_backup_for "$PWQUALITY_CONF"; then
            if ! backup_file_checked \
                "$PWQUALITY_CONF" \
                "$pwquality_backup_before_dependencies" \
                "CORP-PASSWORD pwquality.conf pre-install"
            then
                add_error "CORP-PASSWORD зависимости не устанавливались: backup pwquality.conf failed"
                abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
                return 1
            fi
            if ! record_manifest_backup \
                "$PWQUALITY_CONF" \
                "$pwquality_backup_before_dependencies"
            then
                add_error \
                    "CORP-PASSWORD зависимости не устанавливались: backup mapping pwquality.conf не записан"

                if ! rm -f -- \
                    "$pwquality_backup_before_dependencies"
                then
                    add_warning \
                        "CORP-PASSWORD не удалось удалить незарегистрированный backup $pwquality_backup_before_dependencies"
                fi

                abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
                return 1
            fi
        fi
    elif [[ -e "$PWQUALITY_CONF" ]]; then
        pwquality_existed_before_dependencies=1
    fi

    if ! prepare_created_file_transaction \
        "$PWQUALITY_CONF" \
        "$pwquality_existed_before_dependencies" \
        "CORP-PASSWORD pwquality.conf"
    then
        abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
        return 1
    fi

    # --- optional corporate password policy dependencies ---
    log "[i]     pwquality/Cracklib: проверка обязательных зависимостей..."

    local -a required_packages=(
        libpam-pwquality
        cracklib-runtime
        wamerican
    )
    local -a missing_packages=()
    local package

    for package in "${required_packages[@]}"; do
        pkg_installed "$package" || missing_packages+=("$package")
    done

    if (( ${#missing_packages[@]} > 0 )); then
        apt_update_once

        local package_install_rc=0
        local package_tracking_rc=0

        install_packages_transactionally \
            "password-policy" \
            "${missing_packages[@]}" || true

        package_install_rc=$PACKAGE_TRANSACTION_INSTALL_RC
        package_tracking_rc=$PACKAGE_TRANSACTION_TRACKING_RC

        if (( package_install_rc != 0 )); then
            add_error \
                "pwquality: не удалось установить ${missing_packages[*]} — PAM не изменён"
            record_manifest_warning \
                "pwquality: required packages installation failed"
            abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
            return 1
        fi

        if (( package_tracking_rc != 0 )); then
            add_error \
                "pwquality: установка завершена, но учёт новых пакетов не выполнен"
            record_manifest_warning \
                "pwquality: installed package tracking failed"
            abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
            return 1
        fi
    fi

    for package in "${required_packages[@]}"; do
        if ! pkg_installed "$package"; then
            add_error \
                "pwquality: пакет $package отсутствует — PAM не изменён"
            record_manifest_warning \
                "pwquality: required package missing: $package"
            abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
            return 1
        fi
    done

    if ! command -v update-cracklib >/dev/null 2>&1; then
        add_error "pwquality: update-cracklib отсутствует — PAM не изменён"
        record_manifest_warning "pwquality: update-cracklib missing"
        abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
        return 1
    fi

    if ! command -v cracklib-check >/dev/null 2>&1; then
        add_error "pwquality: cracklib-check отсутствует — PAM не изменён"
        record_manifest_warning "pwquality: cracklib-check missing"
        abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
        return 1
    fi

    if ! update-cracklib >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1; then
        add_error "pwquality: update-cracklib завершился ошибкой — PAM не изменён"
        record_manifest_warning "pwquality: update-cracklib failed"
        abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
        return 1
    fi

    local cracklib_file
    for cracklib_file in \
        /var/cache/cracklib/cracklib_dict.pwd \
        /var/cache/cracklib/cracklib_dict.pwi \
        /var/cache/cracklib/cracklib_dict.hwm; do
        if [[ ! -s "$cracklib_file" ]]; then
            add_error \
                "pwquality: словарь отсутствует или пуст: $cracklib_file — PAM не изменён"
            record_manifest_warning \
                "pwquality: dictionary missing: $cracklib_file"
            abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
            return 1
        fi
    done

    local cracklib_probe
    if ! cracklib_probe="$(
        printf 'Q7v!9mZ2#L4x8R6k\n' | cracklib-check 2>&1
    )"; then
        add_error "pwquality: cracklib-check завершился ошибкой — PAM не изменён"
        record_manifest_warning "pwquality: cracklib-check failed"
        abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
        return 1
    fi

    if grep -qiE \
        'no such file|error loading dictionary|cannot open|failed' \
        <<<"$cracklib_probe"; then
        add_error "pwquality: словарь Cracklib неработоспособен — PAM не изменён"
        record_manifest_warning "pwquality: dictionary probe failed"
        abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
        return 1
    fi

    # --- pwquality.conf ---
    local pw_content
    if profile_allows strict; then
        pw_content="$PWQUALITY_STRICT"
    else
        pw_content="$PWQUALITY_BASELINE"
    fi
    if ! mkdir -p -- \
        "$(dirname "$PWQUALITY_CONF")"
    then
        add_error \
            "CORP-PASSWORD не удалось создать каталог для $PWQUALITY_CONF"
        abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
        return 1
    fi
    # merge: применяем только параметры корпоративной политики, не затрагивая остальные
    local merge_rc=0

    atomic_write_command_output \
        "$PWQUALITY_CONF" \
        0644 \
        python3 - "$PWQUALITY_CONF" "$pw_content" <<'PYMERGE_PW' \
        || merge_rc=$?
import pathlib
import sys

conf = pathlib.Path(sys.argv[1])
new_params = {}

for line in sys.argv[2].splitlines():
    line = line.strip()

    if not line or line.startswith("#"):
        continue

    if "=" in line:
        key, value = line.split("=", 1)
        new_params[key.strip()] = value.strip()

existing = (
    conf.read_text(encoding="utf-8").splitlines()
    if conf.exists()
    else []
)

result = []

for line in existing:
    stripped = line.strip()

    if not stripped or stripped.startswith("#"):
        result.append(line)
        continue

    if "=" in stripped:
        key = stripped.split("=", 1)[0].strip()

        if key in new_params:
            continue

    result.append(line)

for key, value in new_params.items():
    result.append(f"{key} = {value}")

print("\n".join(result) + "\n", end="")
PYMERGE_PW
    if (( merge_rc != 0 )); then
        add_error "CORP-PASSWORD pwquality.conf merge завершился с ошибкой (rc=$merge_rc) — корпоративная парольная политика не применена"
        record_manifest_warning "CORP-PASSWORD pwquality.conf merge failed (rc=$merge_rc)"
        abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
        return 1
    else
        if (( pwquality_existed_before_dependencies == 0 )); then
            if ! record_manifest_created_file "$PWQUALITY_CONF" \
                2>>"${DEBUG_LOG_FILE:-/dev/null}"
            then
                add_error \
                    "CORP-PASSWORD созданный pwquality.conf не записан в manifest"

                if ! rm -f -- "$PWQUALITY_CONF"; then
                    add_warning \
                        "CORP-PASSWORD не удалось удалить незарегистрированный $PWQUALITY_CONF"
                fi

                abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
                return 1
            fi
        fi

        record_manifest_modified_file_best_effort "$PWQUALITY_CONF"
        record_manifest_apply_report "CORP-PASSWORD pwquality.conf merged (profile: ${PROFILE})"
        add_safe "CORP-PASSWORD pwquality настроен: $PWQUALITY_CONF"
    fi

    # --- pam_pwquality + pam_pwhistory: дополнительная корпоративная политика ---
    if [[ -f "$pwhistory_file" ]]; then
        local pw_history_count=5
        profile_allows strict && pw_history_count=10
        profile_allows paranoid && pw_history_count=24

        local bak_ph="$STATE_DIR/common-password.bak-$TIMESTAMP"
        if ! manifest_has_backup_for "$pwhistory_file"; then
            if ! backup_file_checked \
                "$pwhistory_file" \
                "$bak_ph" \
                "CORP-PASSWORD common-password"
            then
                add_error "CORP-PASSWORD common-password не изменён: backup failed"
                abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
                return 1
            fi
            if ! record_manifest_backup "$pwhistory_file" "$bak_ph"; then
                add_error \
                    "CORP-PASSWORD common-password не изменён: backup mapping не записан"

                if ! rm -f -- "$bak_ph"; then
                    add_warning \
                        "CORP-PASSWORD не удалось удалить незарегистрированный backup $bak_ph"
                fi

                abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
                return 1
            fi
        fi

        if ! normalize_common_password_stack \
            "$pwhistory_file" \
            "$pw_history_count"
        then
            add_error \
                "CORP-PASSWORD normalize failed: $pwhistory_file"
            record_manifest_warning \
                "CORP-PASSWORD common-password normalization failed"
            abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
            return 1
        fi

        record_manifest_modified_file_best_effort "$pwhistory_file"
        record_manifest_apply_report \
            "CORP-PASSWORD common-password normalized: pam_pwquality -> pam_pwhistory -> pam_unix, remember=${pw_history_count}"
        add_safe \
            "CORP-PASSWORD common-password нормализован: pam_pwquality -> pam_pwhistory -> pam_unix, remember=${pw_history_count}"
    else
        add_warning "CORP-PASSWORD common-password: $pwhistory_file не найден — пропуск"
    fi

    # --- login.defs: PASS_MAX_DAYS / PASS_MIN_DAYS / PASS_WARN_AGE ---
    if [[ -f "$LOGIN_DEFS" ]]; then
        local bak2="$STATE_DIR/login.defs.bak-$TIMESTAMP"
        if ! manifest_has_backup_for "$LOGIN_DEFS"; then
            if ! backup_file_checked \
                "$LOGIN_DEFS" \
                "$bak2" \
                "CORP-PASSWORD login.defs"
            then
                add_error "CORP-PASSWORD login.defs не изменён: backup failed"
                abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
                return 1
            fi
            if ! record_manifest_backup "$LOGIN_DEFS" "$bak2"; then
                add_error \
                    "CORP-PASSWORD login.defs не изменён: backup mapping не записан"

                if ! rm -f -- "$bak2"; then
                    add_warning \
                        "CORP-PASSWORD не удалось удалить незарегистрированный backup $bak2"
                fi

                abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
                return 1
            fi
        fi
        if ! atomic_write_command_output \
            "$LOGIN_DEFS" \
            0644 \
            python3 - "$LOGIN_DEFS" "$max_days" "$PASS_MIN_DAYS" "$PASS_WARN_AGE" <<'PYJSON'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
params = {
    "PASS_MAX_DAYS": sys.argv[2],
    "PASS_MIN_DAYS": sys.argv[3],
    "PASS_WARN_AGE": sys.argv[4],
}

lines = path.read_text(encoding="utf-8").splitlines()
filtered = []

for line in lines:
    stripped = line.lstrip()
    drop = False

    for key in params:
        if (
            stripped.startswith(key + " ")
            or stripped.startswith(key + "\t")
        ):
            drop = True
            break

        if stripped.startswith("#"):
            body = stripped[1:].lstrip()

            if (
                body.startswith(key + " ")
                or body.startswith(key + "\t")
            ):
                drop = True
                break

    if not drop:
        filtered.append(line)

for key, value in params.items():
    filtered.append(f"{key}\t\t{value}")

print("\n".join(filtered) + "\n", end="")
PYJSON
        then
            add_error \
                "CORP-PASSWORD login.defs: атомарное обновление завершилось ошибкой"
            record_manifest_warning \
                "CORP-PASSWORD login.defs atomic update failed"
            abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
            return 1
        fi
        record_manifest_modified_file_best_effort "$LOGIN_DEFS"
        record_manifest_apply_report \
            "CORP-PASSWORD login.defs updated: PASS_MAX_DAYS=$max_days PASS_MIN_DAYS=$PASS_MIN_DAYS PASS_WARN_AGE=$PASS_WARN_AGE"

        if ! apply_password_policy_existing_accounts \
            "$max_days"
        then
            add_error \
                "CORP-PASSWORD применение password aging к существующим учетным записям завершилось ошибкой"
            abort_password_policy_apply_transaction "${password_policy_transaction[@]}" || true
            return 1
        fi

        add_safe \
            "CORP-PASSWORD login.defs: PASS_MAX_DAYS=$max_days PASS_MIN_DAYS=$PASS_MIN_DAYS PASS_WARN_AGE=$PASS_WARN_AGE"
    else
        add_warning "CORP-PASSWORD $LOGIN_DEFS не найден — password aging пропущен"
    fi

    if ! cleanup_password_policy_transaction_backups         "$pwquality_transaction_snapshot"         "$pwhistory_transaction_snapshot"         "$login_defs_transaction_snapshot"
    then
        add_warning             "CORP-PASSWORD не удалось удалить все transaction snapshots после успешного применения"
    fi

    return 0
}

restore_password_policy_module() {
    local rc=0

    if ! restore_installed_packages "password-policy"; then
        rc=1
    fi

    if ! restore_file_from_manifest "$PWQUALITY_CONF"; then
        rc=1
    fi

    if ! restore_file_from_manifest "$LOGIN_DEFS"; then
        rc=1
    fi

    if ! restore_file_from_manifest "/etc/pam.d/common-password"; then
        rc=1
    fi

    if ! restore_password_aging_snapshots; then
        rc=1
    fi

    return "$rc"
}
pam_faillock_stack_present() {
    [[ -f "$PAM_COMMON_AUTH_FILE" ]] || return 1
    [[ -f "$PAM_COMMON_ACCOUNT_FILE" ]] || return 1

    python3 - "$PAM_COMMON_AUTH_FILE" "$PAM_COMMON_ACCOUNT_FILE" <<'PYCHECKFAILLOCK'
import sys
from pathlib import Path

auth_path = Path(sys.argv[1])
account_path = Path(sys.argv[2])

def active_tokens(path):
    result = []
    for index, raw in enumerate(path.read_text(encoding="utf-8").splitlines()):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        result.append((index, stripped.split()))
    return result

auth = active_tokens(auth_path)
account = active_tokens(account_path)

def find_auth(argument):
    matches = []
    for index, tokens in auth:
        if (
            tokens[0] == "auth"
            and "pam_faillock.so" in tokens
            and argument in tokens
        ):
            matches.append(index)
    return matches

preauth = find_auth("preauth")
authfail = find_auth("authfail")
authsucc = find_auth("authsucc")
pam_unix = [
    index
    for index, tokens in auth
    if tokens[0] == "auth" and "pam_unix.so" in tokens
]
account_faillock = [
    index
    for index, tokens in account
    if (
        tokens[0] == "account"
        and "required" in tokens
        and "pam_faillock.so" in tokens
    )
]

ok = (
    len(preauth) == 1
    and len(authfail) == 1
    and len(authsucc) == 1
    and len(pam_unix) == 1
    and len(account_faillock) == 1
    and preauth[0] < pam_unix[0] < authfail[0] < authsucc[0]
)
raise SystemExit(0 if ok else 1)
PYCHECKFAILLOCK
}

pam_faillock_any_active_line() {
    python3 - "$PAM_COMMON_AUTH_FILE" "$PAM_COMMON_ACCOUNT_FILE" <<'PYCHECKFAILLOCKANY'
import sys
from pathlib import Path

for value in sys.argv[1:]:
    path = Path(value)
    if not path.is_file():
        continue
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#") and "pam_faillock.so" in stripped:
            raise SystemExit(0)
raise SystemExit(1)
PYCHECKFAILLOCKANY
}

normalize_faillock_pam_stack() {
    if ! python3 \
        - "$PAM_COMMON_AUTH_FILE" "$PAM_COMMON_ACCOUNT_FILE" \
        <<'PYVALIDATEFAILLOCK'
import sys
from pathlib import Path

auth_path = Path(sys.argv[1])
account_path = Path(sys.argv[2])

auth_lines = auth_path.read_text(encoding="utf-8").splitlines()
account_lines = account_path.read_text(encoding="utf-8").splitlines()


def active_tokens(raw):
    stripped = raw.strip()

    if not stripped or stripped.startswith("#"):
        return []

    return stripped.split()


for raw in auth_lines + account_lines:
    tokens = active_tokens(raw)

    if tokens and "pam_faillock.so" in tokens:
        raise SystemExit(
            "active pam_faillock.so line already exists"
        )

unix_indices = [
    index
    for index, raw in enumerate(auth_lines)
    if (
        (tokens := active_tokens(raw))
        and tokens[0] == "auth"
        and "pam_unix.so" in tokens
    )
]

if len(unix_indices) != 1:
    raise SystemExit(
        "expected one active pam_unix.so auth line, "
        f"found {len(unix_indices)}"
    )

unix_line = auth_lines[unix_indices[0]]

if "success=1" not in unix_line:
    raise SystemExit(
        "unsupported common-auth pam_unix control: "
        "expected success=1"
    )

account_indices = [
    index
    for index, raw in enumerate(account_lines)
    if (
        (tokens := active_tokens(raw))
        and tokens[0] == "account"
    )
]

if not account_indices:
    raise SystemExit(
        "active account line not found in common-account"
    )
PYVALIDATEFAILLOCK
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$PAM_COMMON_AUTH_FILE" \
        0644 \
        python3 - "$PAM_COMMON_AUTH_FILE" \
        <<'PYNORMALIZEAUTH'
import sys
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()


def active_tokens(raw):
    stripped = raw.strip()

    if not stripped or stripped.startswith("#"):
        return []

    return stripped.split()


unix_indices = [
    index
    for index, raw in enumerate(lines)
    if (
        (tokens := active_tokens(raw))
        and tokens[0] == "auth"
        and "pam_unix.so" in tokens
    )
]

if len(unix_indices) != 1:
    raise SystemExit(
        "expected one active pam_unix.so auth line, "
        f"found {len(unix_indices)}"
    )

unix_index = unix_indices[0]

if "success=1" not in lines[unix_index]:
    raise SystemExit(
        "unsupported common-auth pam_unix control: "
        "expected success=1"
    )

preauth_block = [
    "# BEGIN SecureLinux-NG CORP-FAILLOCK preauth",
    "auth required pam_faillock.so preauth",
    "# END SecureLinux-NG CORP-FAILLOCK preauth",
]

result_block = [
    "# BEGIN SecureLinux-NG CORP-FAILLOCK result",
    "auth [default=die] pam_faillock.so authfail",
    "auth sufficient pam_faillock.so authsucc",
    "# END SecureLinux-NG CORP-FAILLOCK result",
]

result = (
    lines[:unix_index]
    + preauth_block
    + [lines[unix_index]]
    + result_block
    + lines[unix_index + 1:]
)

print("\n".join(result) + "\n", end="")
PYNORMALIZEAUTH
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$PAM_COMMON_ACCOUNT_FILE" \
        0644 \
        python3 - "$PAM_COMMON_ACCOUNT_FILE" \
        <<'PYNORMALIZEACCOUNT'
import sys
from pathlib import Path

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()


def active_tokens(raw):
    stripped = raw.strip()

    if not stripped or stripped.startswith("#"):
        return []

    return stripped.split()


account_indices = [
    index
    for index, raw in enumerate(lines)
    if (
        (tokens := active_tokens(raw))
        and tokens[0] == "account"
    )
]

if not account_indices:
    raise SystemExit(
        "active account line not found in common-account"
    )

account_block = [
    "# BEGIN SecureLinux-NG CORP-FAILLOCK account",
    "account required pam_faillock.so",
    "# END SecureLinux-NG CORP-FAILLOCK account",
]

account_index = account_indices[0]

result = (
    lines[:account_index]
    + account_block
    + lines[account_index:]
)

print("\n".join(result) + "\n", end="")
PYNORMALIZEACCOUNT
    then
        return 1
    fi
}

check_faillock_module() {
    local issues=0

    if ! corporate_password_policy_enabled; then
        add_skipped "Корпоративная политика блокировки входа отключена"
        return 0
    fi
    if ! profile_allows strict; then
        add_skipped "CORP-FAILLOCK pam_faillock пропущен: требуется профиль strict или paranoid (текущий: ${PROFILE})"
        return 0
    fi

    if [[ -f "$FAILLOCK_CONF" ]] \
       && grep -Eq '^\s*deny\s*=\s*5\s*$' "$FAILLOCK_CONF" \
       && grep -Eq '^\s*unlock_time\s*=\s*900\s*$' "$FAILLOCK_CONF"
    then
        add_safe "CORP-FAILLOCK конфигурация: deny=5 unlock_time=900"
    else
        add_risky "CORP-FAILLOCK конфигурация отсутствует или не соответствует deny=5 unlock_time=900: $FAILLOCK_CONF"
        issues=1
    fi

    if pam_faillock_stack_present; then
        add_safe "CORP-FAILLOCK PAM-стек активен: common-auth/common-account"
    else
        add_risky "CORP-FAILLOCK PAM-стек не активен или нарушен: $PAM_COMMON_AUTH_FILE, $PAM_COMMON_ACCOUNT_FILE"
        issues=1
    fi

    return "$issues"
}

faillock_pam_module_present() {
    local pam_module=""
    local pam_faillock_found=0

    if (( $# == 0 )); then
        return 1
    fi

    for pam_module in "$@"; do
        if [[ -f "$pam_module" ]]; then
            pam_faillock_found=1
            break
        fi
    done

    (( pam_faillock_found == 1 ))
}

cleanup_faillock_transaction_backups() {
    local path=""
    local rc=0

    for path in "$@"; do
        [[ -n "$path" ]] || continue

        if ! rm -f -- "$path"; then
            rc=1
        fi
    done

    return "$rc"
}

rollback_faillock_apply_files() {
    local conf_existed="$1"
    local conf_snapshot="$2"
    local pam_changed="$3"
    local auth_snapshot="$4"
    local account_snapshot="$5"
    local rc=0

    case "$conf_existed:$pam_changed" in
        0:0|0:1|1:0|1:1)
            ;;
        *)
            return 1
            ;;
    esac

    if (( pam_changed == 1 )); then
        if [[ -z "$auth_snapshot" \
            || ! -e "$auth_snapshot" \
            && ! -L "$auth_snapshot" ]]
        then
            rc=1
        elif ! cp -a -- \
            "$auth_snapshot" \
            "$PAM_COMMON_AUTH_FILE"
        then
            rc=1
        fi

        if [[ -z "$account_snapshot" \
            || ! -e "$account_snapshot" \
            && ! -L "$account_snapshot" ]]
        then
            rc=1
        elif ! cp -a -- \
            "$account_snapshot" \
            "$PAM_COMMON_ACCOUNT_FILE"
        then
            rc=1
        fi
    fi

    if (( conf_existed == 1 )); then
        if [[ -z "$conf_snapshot" \
            || ! -e "$conf_snapshot" \
            && ! -L "$conf_snapshot" ]]
        then
            rc=1
        elif ! cp -a -- \
            "$conf_snapshot" \
            "$FAILLOCK_CONF"
        then
            rc=1
        fi
    else
        if ! rm -f -- "$FAILLOCK_CONF"; then
            rc=1
        fi
    fi

    return "$rc"
}

apply_faillock_module() {
    local pam_already_configured=0
    local conf_existed=0
    local conf_manifest_backed=0
    local auth_manifest_backed=0
    local account_manifest_backed=0
    local conf_snapshot=""
    local auth_snapshot=""
    local account_snapshot=""
    local conf_transient=""
    local auth_transient=""
    local account_transient=""
    local content=""
    local merge_rc=0

    if ! corporate_password_policy_enabled; then
        add_skipped \
            "Корпоративная политика блокировки входа отключена"
        return 0
    fi

    if ! profile_allows strict; then
        add_skipped \
            "CORP-FAILLOCK pam_faillock пропущен: требуется профиль strict или paranoid (текущий: ${PROFILE})"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log \
            "[DRY-RUN] write '$FAILLOCK_CONF' (profile: ${PROFILE})"
        log \
            "[DRY-RUN] configure pam_faillock in '$PAM_COMMON_AUTH_FILE' and '$PAM_COMMON_ACCOUNT_FILE'"
        add_skipped \
            "CORP-FAILLOCK dry-run: faillock.conf and PAM stack would be configured"
        return 0
    fi

    if ! faillock_pam_module_present \
        /lib/security/pam_faillock.so \
        /usr/lib/security/pam_faillock.so \
        /lib/*-linux-gnu/security/pam_faillock.so \
        /usr/lib/*-linux-gnu/security/pam_faillock.so
    then
        add_warning \
            "CORP-FAILLOCK pam_faillock.so не найден — пропуск faillock"
        record_manifest_warning \
            "CORP-FAILLOCK pam_faillock.so not found"
        add_skipped \
            "CORP-FAILLOCK apply skipped: pam_faillock.so missing"
        return 0
    fi

    if [[ ! -f "$PAM_COMMON_AUTH_FILE" \
        || ! -f "$PAM_COMMON_ACCOUNT_FILE" ]]
    then
        add_error \
            "CORP-FAILLOCK обязательные PAM-файлы отсутствуют: $PAM_COMMON_AUTH_FILE или $PAM_COMMON_ACCOUNT_FILE"
        record_manifest_warning \
            "CORP-FAILLOCK common PAM files missing"
        return 1
    fi

    if pam_faillock_stack_present; then
        pam_already_configured=1
    elif pam_faillock_any_active_line; then
        add_error \
            "CORP-FAILLOCK обнаружена частичная или сторонняя конфигурация pam_faillock.so — автоматическое изменение PAM остановлено"
        record_manifest_warning \
            "CORP-FAILLOCK partial or unmanaged PAM stack detected"
        return 1
    fi

    if [[ -e "$FAILLOCK_CONF" \
        || -L "$FAILLOCK_CONF" ]]
    then
        conf_existed=1

        if [[ ! -f "$FAILLOCK_CONF" ]]; then
            add_error \
                "CORP-FAILLOCK $FAILLOCK_CONF существует, но не является обычным файлом или ссылкой на файл"
            return 1
        fi

        if manifest_has_backup_for "$FAILLOCK_CONF"; then
            conf_manifest_backed=1
        else
            conf_snapshot="$STATE_DIR/$(basename "$FAILLOCK_CONF").bak-$TIMESTAMP"

            if ! backup_file_checked \
                "$FAILLOCK_CONF" \
                "$conf_snapshot" \
                "CORP-FAILLOCK faillock"
            then
                add_skipped \
                    "CORP-FAILLOCK apply skipped: faillock.conf backup failed"
                return 1
            fi

            if ! record_manifest_backup \
                "$FAILLOCK_CONF" \
                "$conf_snapshot"
            then
                add_error \
                    "CORP-FAILLOCK apply skipped: faillock.conf backup mapping не записан"

                if ! rm -f -- "$conf_snapshot"; then
                    add_warning \
                        "CORP-FAILLOCK не удалось удалить незарегистрированный backup $conf_snapshot"
                fi

                return 1
            fi
        fi
    fi

    if (( pam_already_configured == 0 )); then
        if manifest_has_backup_for \
            "$PAM_COMMON_AUTH_FILE"
        then
            auth_manifest_backed=1
        else
            auth_snapshot="$STATE_DIR/$(basename "$PAM_COMMON_AUTH_FILE").faillock.bak-$TIMESTAMP"

            if ! backup_file_checked \
                "$PAM_COMMON_AUTH_FILE" \
                "$auth_snapshot" \
                "CORP-FAILLOCK common-auth"
            then
                add_skipped \
                    "CORP-FAILLOCK apply skipped: common-auth backup failed"
                return 1
            fi

            if ! record_manifest_backup \
                "$PAM_COMMON_AUTH_FILE" \
                "$auth_snapshot"
            then
                add_error \
                    "CORP-FAILLOCK apply skipped: common-auth backup mapping не записан"

                if ! rm -f -- "$auth_snapshot"; then
                    add_warning \
                        "CORP-FAILLOCK не удалось удалить незарегистрированный backup $auth_snapshot"
                fi

                return 1
            fi
        fi

        if manifest_has_backup_for \
            "$PAM_COMMON_ACCOUNT_FILE"
        then
            account_manifest_backed=1
        else
            account_snapshot="$STATE_DIR/$(basename "$PAM_COMMON_ACCOUNT_FILE").faillock.bak-$TIMESTAMP"

            if ! backup_file_checked \
                "$PAM_COMMON_ACCOUNT_FILE" \
                "$account_snapshot" \
                "CORP-FAILLOCK common-account"
            then
                add_skipped \
                    "CORP-FAILLOCK apply skipped: common-account backup failed"
                return 1
            fi

            if ! record_manifest_backup \
                "$PAM_COMMON_ACCOUNT_FILE" \
                "$account_snapshot"
            then
                add_error \
                    "CORP-FAILLOCK apply skipped: common-account backup mapping не записан"

                if ! rm -f -- "$account_snapshot"; then
                    add_warning \
                        "CORP-FAILLOCK не удалось удалить незарегистрированный backup $account_snapshot"
                fi

                return 1
            fi
        fi
    fi

    if (( conf_manifest_backed == 1 )); then
        conf_snapshot="$STATE_DIR/$(basename "$FAILLOCK_CONF").rollback-$TIMESTAMP"
        conf_transient="$conf_snapshot"

        if ! backup_file_checked \
            "$FAILLOCK_CONF" \
            "$conf_snapshot" \
            "CORP-FAILLOCK faillock transaction"
        then
            add_error \
                "CORP-FAILLOCK не удалось создать transaction snapshot для faillock.conf"
            return 1
        fi
    fi

    if (( pam_already_configured == 0 \
        && auth_manifest_backed == 1 ))
    then
        auth_snapshot="$STATE_DIR/$(basename "$PAM_COMMON_AUTH_FILE").faillock.rollback-$TIMESTAMP"
        auth_transient="$auth_snapshot"

        if ! backup_file_checked \
            "$PAM_COMMON_AUTH_FILE" \
            "$auth_snapshot" \
            "CORP-FAILLOCK common-auth transaction"
        then
            add_error \
                "CORP-FAILLOCK не удалось создать transaction snapshot для common-auth"

            cleanup_faillock_transaction_backups \
                "$conf_transient" \
                >/dev/null 2>&1 || true

            return 1
        fi
    fi

    if (( pam_already_configured == 0 \
        && account_manifest_backed == 1 ))
    then
        account_snapshot="$STATE_DIR/$(basename "$PAM_COMMON_ACCOUNT_FILE").faillock.rollback-$TIMESTAMP"
        account_transient="$account_snapshot"

        if ! backup_file_checked \
            "$PAM_COMMON_ACCOUNT_FILE" \
            "$account_snapshot" \
            "CORP-FAILLOCK common-account transaction"
        then
            add_error \
                "CORP-FAILLOCK не удалось создать transaction snapshot для common-account"

            cleanup_faillock_transaction_backups \
                "$conf_transient" \
                "$auth_transient" \
                >/dev/null 2>&1 || true

            return 1
        fi
    fi

    if ! mkdir -p -- \
        "$(dirname "$FAILLOCK_CONF")"
    then
        add_error \
            "CORP-FAILLOCK не удалось создать каталог для $FAILLOCK_CONF"

        cleanup_faillock_transaction_backups \
            "$conf_transient" \
            "$auth_transient" \
            "$account_transient" \
            >/dev/null 2>&1 || true

        return 1
    fi

    content="$FAILLOCK_CONF_STRICT"

    if ! prepare_created_file_transaction \
        "$FAILLOCK_CONF" \
        "$conf_existed" \
        "CORP-FAILLOCK faillock.conf"
    then
        cleanup_faillock_transaction_backups \
            "$conf_transient" \
            "$auth_transient" \
            "$account_transient" \
            >/dev/null 2>&1 || true
        return 1
    fi

    atomic_write_command_output \
    content="$FAILLOCK_CONF_STRICT"

    atomic_write_command_output \
        "$FAILLOCK_CONF" \
        0644 \
        python3 - "$FAILLOCK_CONF" "$content" <<'PYMERGE_FL' \
        || merge_rc=$?
import sys
from pathlib import Path

conf = Path(sys.argv[1])
new_keyed = {}
new_flags = set()

for entry in sys.argv[2].splitlines():
    entry = entry.strip()

    if not entry or entry.startswith("#"):
        continue

    if "=" in entry:
        key, value = entry.split("=", 1)
        new_keyed[key.strip()] = value.strip()
    else:
        new_flags.add(entry)

existing = (
    conf.read_text(encoding="utf-8").splitlines()
    if conf.exists()
    else []
)

result = []

for line in existing:
    stripped = line.strip()

    if not stripped or stripped.startswith("#"):
        result.append(line)
        continue

    if "=" in stripped:
        key = stripped.split("=", 1)[0].strip()

        if key in new_keyed:
            continue
    elif stripped in new_flags:
        continue

    result.append(line)

for key, value in new_keyed.items():
    result.append(f"{key} = {value}")

for flag in sorted(new_flags):
    result.append(flag)

print("\n".join(result) + "\n", end="")
PYMERGE_FL

    if (( merge_rc != 0 )); then
        add_error \
            "CORP-FAILLOCK faillock.conf merge завершился с ошибкой (rc=$merge_rc)"
        record_manifest_warning \
            "CORP-FAILLOCK faillock.conf merge failed (rc=$merge_rc)"

        if ! rollback_faillock_apply_files \
            "$conf_existed" \
            "$conf_snapshot" \
            0 \
            "" \
            ""
        then
            add_warning \
                "CORP-FAILLOCK rollback faillock.conf после merge-ошибки выполнен не полностью"
        fi

        cleanup_faillock_transaction_backups \
            "$conf_transient" \
            "$auth_transient" \
            "$account_transient" \
            >/dev/null 2>&1 || true

        return 1
    fi

    if (( pam_already_configured == 0 )); then
        if ! normalize_faillock_pam_stack; then
            if ! rollback_faillock_apply_files \
                "$conf_existed" \
                "$conf_snapshot" \
                1 \
                "$auth_snapshot" \
                "$account_snapshot"
            then
                add_warning \
                    "CORP-FAILLOCK rollback после ошибки PAM normalization выполнен не полностью"
            fi

            cleanup_faillock_transaction_backups \
                "$conf_transient" \
                "$auth_transient" \
                "$account_transient" \
                >/dev/null 2>&1 || true

            add_error \
                "CORP-FAILLOCK PAM-стек не изменён: неподдерживаемая или повреждённая структура common-auth/common-account"
            record_manifest_warning \
                "CORP-FAILLOCK PAM normalization failed; files rolled back"

            return 1
        fi
    fi

    if ! pam_faillock_stack_present; then
        if ! rollback_faillock_apply_files \
            "$conf_existed" \
            "$conf_snapshot" \
            "$((pam_already_configured == 0))" \
            "$auth_snapshot" \
            "$account_snapshot"
        then
            add_warning \
                "CORP-FAILLOCK rollback после post-apply проверки выполнен не полностью"
        fi

        cleanup_faillock_transaction_backups \
            "$conf_transient" \
            "$auth_transient" \
            "$account_transient" \
            >/dev/null 2>&1 || true

        add_error \
            "CORP-FAILLOCK проверка PAM-стека после изменения завершилась ошибкой; файлы восстановлены"
        record_manifest_warning \
            "CORP-FAILLOCK post-apply PAM verification failed; files rolled back"

        return 1
    fi

    if (( conf_existed == 0 )); then
        if ! record_manifest_created_file \
            "$FAILLOCK_CONF" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "CORP-FAILLOCK созданный faillock.conf не записан в manifest"

            if ! rollback_faillock_apply_files \
                "$conf_existed" \
                "$conf_snapshot" \
                "$((pam_already_configured == 0))" \
                "$auth_snapshot" \
                "$account_snapshot"
            then
                add_warning \
                    "CORP-FAILLOCK rollback после ошибки manifest выполнен не полностью"
            fi

            cleanup_faillock_transaction_backups \
                "$conf_transient" \
                "$auth_transient" \
                "$account_transient" \
                >/dev/null 2>&1 || true

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$FAILLOCK_CONF"

    if (( pam_already_configured == 0 )); then
        record_manifest_modified_file_best_effort \
            "$PAM_COMMON_AUTH_FILE"
        record_manifest_modified_file_best_effort \
            "$PAM_COMMON_ACCOUNT_FILE"
    fi

    record_manifest_apply_report \
        "CORP-FAILLOCK configured faillock.conf and PAM stack (profile: ${PROFILE})"

    if ! cleanup_faillock_transaction_backups \
        "$conf_transient" \
        "$auth_transient" \
        "$account_transient"
    then
        add_warning \
            "CORP-FAILLOCK не удалось удалить один или несколько transaction snapshots"
    fi

    add_safe \
        "CORP-FAILLOCK pam_faillock активирован: $FAILLOCK_CONF, common-auth, common-account"

    return 0
}

restore_faillock_module() {
    local target
    local manifest_rc=0
    local tracked=0
    local rc=0

    for target in         "$FAILLOCK_CONF"         "$PAM_COMMON_AUTH_FILE"         "$PAM_COMMON_ACCOUNT_FILE"
    do
        restore_manifest_has_path "$target"
        manifest_rc=$?

        case "$manifest_rc" in
            0)
                tracked=1

                if ! restore_file_from_manifest "$target"; then
                    rc=1
                fi
                ;;
            1)
                ;;
            *)
                return 1
                ;;
        esac
    done

    if (( tracked == 0 )); then
        log "[i]     restore faillock: модуль не применялся — пропуск"
    fi

    return "$rc"
}
update_manifest_group_state() {
    local action="$1"
    local group_name="$2"
    local user_name="${3:-}"

    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1

    python3 - \
        "$MANIFEST_FILE" \
        "$action" \
        "$group_name" \
        "$user_name" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
action = sys.argv[2]
group_name = sys.argv[3]
user_name = sys.argv[4]

data = json.loads(path.read_text(encoding="utf-8"))

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

created_groups = data.setdefault("created_groups", [])
pending_groups = data.setdefault("pending_created_groups", [])
added_memberships = data.setdefault("added_group_memberships", [])
pending_memberships = data.setdefault("pending_group_memberships", [])

for field_name, value in (
    ("created_groups", created_groups),
    ("pending_created_groups", pending_groups),
    ("added_group_memberships", added_memberships),
    ("pending_group_memberships", pending_memberships),
):
    if not isinstance(value, list):
        raise ValueError(f"{field_name} is not an array")

for item in created_groups + pending_groups:
    if not isinstance(item, str) or not item:
        raise ValueError("group journal entry is not a non-empty string")

for item in added_memberships + pending_memberships:
    if not isinstance(item, dict):
        raise ValueError("membership journal entry is not an object")
    item_group = item.get("group")
    item_user = item.get("user")
    if not isinstance(item_group, str) or not item_group:
        raise ValueError("membership group is not a non-empty string")
    if not isinstance(item_user, str) or not item_user:
        raise ValueError("membership user is not a non-empty string")

membership = {
    "group": group_name,
    "user": user_name,
}

if action == "pending_group":
    if group_name not in created_groups and group_name not in pending_groups:
        pending_groups.append(group_name)
elif action == "commit_group":
    pending_groups[:] = [item for item in pending_groups if item != group_name]
    if group_name not in created_groups:
        created_groups.append(group_name)
elif action == "pending_membership":
    if not user_name:
        raise ValueError("pending membership user is empty")
    if membership not in added_memberships and membership not in pending_memberships:
        pending_memberships.append(membership)
elif action == "commit_membership":
    if not user_name:
        raise ValueError("committed membership user is empty")
    pending_memberships[:] = [
        item
        for item in pending_memberships
        if item != membership
    ]
    if membership not in added_memberships:
        added_memberships.append(membership)
else:
    raise ValueError(f"unsupported group journal action: {action}")

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(fd, content.encode("utf-8"))
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)

    directory_fd = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PYJSON
}

record_manifest_pending_created_group() {
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    update_manifest_group_state pending_group "$1"
}

record_manifest_created_group() {
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    update_manifest_group_state commit_group "$1"
}

record_manifest_pending_group_membership() {
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    update_manifest_group_state pending_membership "$1" "$2"
}

record_manifest_added_group_membership() {
    (( DRY_RUN == 1 )) && return 0
    [[ -n "${MANIFEST_FILE:-}" ]] || return 1
    [[ -f "$MANIFEST_FILE" ]] || return 1
    update_manifest_group_state commit_membership "$1" "$2"
}

restore_added_group_members() {
    local group_name="$1"

    python3 - "$RESTORE_SOURCE_MANIFEST" "$group_name" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
group_name = sys.argv[2]

try:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    committed = data.get("added_group_memberships", [])
    pending = data.get("pending_group_memberships", [])

    if not isinstance(committed, list):
        raise ValueError(
            "manifest added_group_memberships is not an array"
        )

    if not isinstance(pending, list):
        raise ValueError(
            "manifest pending_group_memberships is not an array"
        )

    seen = set()
    for item in committed + pending:
        if not isinstance(item, dict):
            raise ValueError(
                "manifest membership entry is not an object"
            )

        item_group = item.get("group")
        item_user = item.get("user")

        if not isinstance(item_group, str) or not item_group:
            raise ValueError(
                "manifest membership group is not a non-empty string"
            )

        if not isinstance(item_user, str) or not item_user:
            raise ValueError(
                "manifest membership user is not a non-empty string"
            )

        key = (item_group, item_user)
        if item_group == group_name and key not in seen:
            seen.add(key)
            print(item_user)
except Exception as exc:
    print(
        f"restore group memberships read failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)
PYJSON
}

restore_pam_wheel_module() {
    local user_name
    local added_members_output=""
    local current_members_output=""
    local created_group_rc=0
    local rc=0

    if ! restore_file_from_manifest "$PAM_SU_FILE"; then
        rc=1
    fi

    if ! added_members_output="$(
        restore_added_group_members wheel
    )"; then
        add_error \
            "restore pam_wheel: не удалось прочитать memberships из manifest"
        return 1
    fi

    while IFS= read -r user_name; do
        [[ -n "$user_name" ]] || continue

        if getent group wheel >/dev/null 2>&1 \
           && id "$user_name" >/dev/null 2>&1 \
           && pam_wheel_user_is_member "$user_name"
        then
            if gpasswd -d "$user_name" wheel \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
            then
                add_safe \
                    "restore: removed '$user_name' from wheel"
            else
                add_warning \
                    "restore: failed to remove '$user_name' from wheel"
                rc=1
            fi
        fi
    done <<< "$added_members_output"

    restore_has_created_group "wheel"
    created_group_rc=$?

    case "$created_group_rc" in
        0)
            if ! getent group wheel >/dev/null 2>&1; then
                add_safe \
                    "restore: created group wheel already absent"
            elif ! current_members_output="$(
                pam_wheel_group_members
            )"; then
                add_warning \
                    "restore: не удалось определить участников wheel; группа сохранена"
                rc=1
            elif [[ -n "$current_members_output" ]]; then
                add_warning \
                    "restore: wheel сохранена — в группе остались участники"
            elif groupdel wheel; then
                add_safe \
                    "restore: removed created group wheel"
            else
                add_warning \
                    "restore: failed to remove group wheel"
                rc=1
            fi
            ;;
        1)
            ;;
        *)
            return 1
            ;;
    esac

    return "$rc"
}
restore_sudo_policy_module() {
    restore_file_from_manifest "$SUDO_POLICY_DROPIN"
}

write_metadata_snapshot() {
    local target="$1"
    local snapshot="$2"

    python3 - "$target" "$snapshot"         2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import os
import pathlib
import stat
import sys
import tempfile

target = pathlib.Path(sys.argv[1])
snapshot = pathlib.Path(sys.argv[2])

st = target.stat()

content = (
    f"TARGET={target}\n"
    f"MODE={stat.S_IMODE(st.st_mode):o}\n"
    f"UID={st.st_uid}\n"
    f"GID={st.st_gid}\n"
)

fd, tmp_name = tempfile.mkstemp(
    dir=str(snapshot.parent),
    prefix=".metadata-snapshot.",
)

try:
    os.write(
        fd,
        content.encode("utf-8"),
    )
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(tmp_name, snapshot)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        os.unlink(tmp_name)
    except OSError:
        pass

    raise
PYJSON
}
restore_read_stat_field() {
    local meta_file="$1"
    local key="$2"
    python3 - "$meta_file" "$key" <<'PYJSON'
import sys, pathlib, re
path = pathlib.Path(sys.argv[1])
key = sys.argv[2]
text = path.read_text(encoding='utf-8', errors='replace')

machine_patterns = {
    "access": r"(?m)^MODE=(\d+)$",
    "uid": r"(?m)^UID=(\d+)$",
    "gid": r"(?m)^GID=(\d+)$",
}
legacy_patterns = {
    "access": r"Access:\s*\((\d+)/",
    "uid": r"Uid:\s*\(\s*(\d+)/",
    "gid": r"Gid:\s*\(\s*(\d+)/",
}

m = re.search(machine_patterns[key], text)
if m:
    print(m.group(1))
    raise SystemExit(0)

m = re.search(legacy_patterns[key], text)
print(m.group(1) if m else "")
PYJSON
}

restore_metadata_from_stat_snapshot() {
    local target="$1"
    local backup
    local mode uid gid
    local restore_rc=0

    if ! backup="$(restore_lookup_backup "$target")"; then
        add_error             "restore metadata: не удалось прочитать backup для $target из manifest"
        return 1
    fi
    if [[ -z "$backup" || ! -f "$backup" ]]; then
        log "[i]     restore: нет снапшота прав для $target (файл не изменялся при apply)"
        return 0
    fi

    if ! mode="$(restore_read_stat_field "$backup" access)"; then
        add_error             "restore metadata: не удалось прочитать mode из $backup"
        return 1
    fi

    if ! uid="$(restore_read_stat_field "$backup" uid)"; then
        add_error             "restore metadata: не удалось прочитать uid из $backup"
        return 1
    fi

    if ! gid="$(restore_read_stat_field "$backup" gid)"; then
        add_error             "restore metadata: не удалось прочитать gid из $backup"
        return 1
    fi

    if [[ -z "$mode" || -z "$uid" || -z "$gid" ]]; then
        log "[i]     restore: $backup не является снапшотом прав для $target — пропуск"
        return 0
    fi

    if [[ ! -e "$target" ]]; then
        add_warning "restore: target missing for metadata restore: $target"
        return 0
    fi

    if ! chown "${uid}:${gid}" "$target"; then
        add_error "restore metadata: chown failed for $target"
        restore_rc=1
    fi

    if ! chmod "$mode" "$target"; then
        add_error "restore metadata: chmod failed for $target"
        restore_rc=1
    fi

    if (( restore_rc == 0 )); then
        add_safe "restore: restored metadata for $target from snapshot $backup"
    fi

    return "$restore_rc"
}

restore_fs_critical_files_module() {
    local f
    local rc=0

    for f in "${FS_CRITICAL_FILES[@]}"; do
        if ! restore_metadata_from_stat_snapshot "$f"; then
            rc=1
        fi
    done

    return "$rc"
}

restore_cron_targets_module() {
    local spec path
    local rc=0

    for spec in "${CRON_CRITICAL_TARGETS[@]}"; do
        if ! path="$(cron_target_path "$spec")"; then
            add_error "restore cron: не удалось прочитать path из спецификации: $spec"
            rc=1
            continue
        fi

        if [[ -z "$path" ]]; then
            add_error "restore cron: пустой path в спецификации: $spec"
            rc=1
            continue
        fi

        if ! restore_metadata_from_stat_snapshot "$path"; then
            rc=1
        fi
    done

    return "$rc"
}
restore_systemd_unit_targets_module() {
    local modified
    local modified_output=""
    local rc=0

    if ! modified_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/etc/systemd/system/" in e.get("original", "") and ".meta-" in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
    )"; then
        add_error "restore systemd unit targets: не удалось прочитать manifest"
        return 1
    fi

    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        if ! restore_metadata_from_stat_snapshot "$modified"; then
            rc=1
        fi
    done <<< "$modified_output"

    return "$rc"
}

record_runtime_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$risky" == "0" ]]; then
        add_safe "2.3.2 runtime paths checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.3.2 runtime paths checked: total=$total ok=$ok risky=$risky"
    fi
}

fs_expected_mode() {
    case "$1" in
        /etc/passwd|/etc/group) echo "644" ;;
        /etc/shadow) echo "go-rwx" ;;
        *) return 1 ;;
    esac
}

fs_mode_compliant() {
    local target="$1"
    local actual_mode="$2"

    case "$target" in
        /etc/passwd|/etc/group)
            [[ "$actual_mode" == "644" ]]
            ;;
        /etc/shadow)
            [[ "$actual_mode" =~ ^[0-7]+$ ]] || return 1
            (( (8#$actual_mode & 8#77) == 0 ))
            ;;
        *)
            return 1
            ;;
    esac
}

fs_apply_expected_mode() {
    local target="$1"

    case "$target" in
        /etc/passwd|/etc/group)
            chmod 644 -- "$target"
            ;;
        /etc/shadow)
            chmod go-rwx -- "$target"
            ;;
        *)
            return 1
            ;;
    esac
}

fs_actual_mode() {
    stat -c '%a' "$1"
}

fs_actual_owner_group() {
    stat -c '%U:%G' "$1"
}

check_fs_critical_file_one() {
    local target="$1"
    local expected actual_mode

    expected="$(fs_expected_mode "$target")" || {
        add_error "2.3.1 unknown target: $target"
        return 1
    }

    if [[ ! -e "$target" ]]; then
        add_error "2.3.1 file not found: $target"
        return 1
    fi

    if ! actual_mode="$(fs_actual_mode "$target")"; then
        add_error "2.3.1 failed to read mode: $target"
        return 1
    fi

    if fs_mode_compliant "$target" "$actual_mode"; then
        add_safe \
            "2.3.1 compliant: $target mode=$actual_mode expected=$expected"
    else
        add_risky \
            "2.3.1 non-compliant: $target mode=$actual_mode expected=$expected"
    fi
}

check_fs_critical_files_module() {
    local f
    for f in "${FS_CRITICAL_FILES[@]}"; do
        check_fs_critical_file_one "$f"
    done
}

check_empty_passwords_module() {
    python3 - <<'PYJSON'
from pathlib import Path

shadow = Path("/etc/shadow")
if not shadow.exists():
    print("RISK\t/etc/shadow\tmissing")
    print("SUMMARY\t0\t0\t1")
    raise SystemExit(0)

try:
    lines = shadow.read_text(encoding="utf-8", errors="ignore").splitlines()
except PermissionError:
    print("RISK\t/etc/shadow\tpermission_denied")
    print("SUMMARY\t0\t0\t1")
    raise SystemExit(0)
except Exception as e:
    print(f"RISK\t/etc/shadow\tread_failed:{e}")
    print("SUMMARY\t0\t0\t1")
    raise SystemExit(0)

ok = 0
risky = 0
for line in lines:
    if not line or ":" not in line:
        continue
    parts = line.split(":")
    if len(parts) < 2:
        continue
    user, pwd = parts[0], parts[1]
    if pwd == "":
        risky += 1
        print(f"RISK\t{user}\tempty_password_field")
    else:
        ok += 1

print(f"SUMMARY\t{ok + risky}\t{ok}\t{risky}")
PYJSON
}

record_empty_passwords_check_results() {
    local total="$1"
    local ok="$2"
    local risky="$3"
    if [[ "$total" == "0" && "$risky" != "0" ]]; then
        add_warning "2.1.1 /etc/shadow недоступен для чтения без привилегий; выполнена только ограниченная проверка"
        add_risky "2.1.1 password fields check incomplete: total=$total ok=$ok risky=$risky"
        return 0
    fi
    if [[ "$risky" == "0" ]]; then
        add_safe "2.1.1 password fields checked: total=$total ok=$ok risky=$risky"
    else
        add_risky "2.1.1 password fields checked: total=$total ok=$ok risky=$risky"
    fi
}

apply_empty_passwords_module() {
    if (( DRY_RUN == 1 )); then
        local empty_passwords_output=""

        if ! empty_passwords_output="$(check_empty_passwords_module)"; then
            add_error "2.1.1 dry-run: не удалось проверить пустые пароли"
            return 1
        fi

        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    log "[DRY-RUN] 2.1.1 empty-password scan total=$a ok=$b risky=$c"
                    ;;
                RISK)
                    log "[DRY-RUN] 2.1.1 would lock account '$a' reason='$b'"
                    ;;
            esac
        done <<< "$empty_passwords_output"

        add_skipped \
            "2.1.1 dry-run: accounts with empty password field would be locked"
        return 0
    fi

    if (( EUID != 0 )); then
        add_warning \
            "2.1.1 apply skipped: требуется root для работы с /etc/shadow"
        record_manifest_warning \
            "2.1.1 apply skipped: requires root"
        add_skipped \
            "2.1.1 apply skipped: requires root"
        return 0
    fi

    local empty_users_file="$STATE_DIR/empty-password-users-$TIMESTAMP.txt"
    local shadow_file="${SECURELINUX_NG_SHADOW_FILE:-/etc/shadow}"
    local shadow_candidate=""
    local state_cleanup_rc=0

    if [[ -L "$shadow_file" ]]; then
        add_error \
            "2.1.1 изменение отклонено: $shadow_file является symbolic link"
        return 1
    fi

    if ! shadow_candidate="$(
        python3 - "$empty_users_file" "$shadow_file" <<'PYJSON'
import os
import pathlib
import stat
import sys
import tempfile

out_file = pathlib.Path(sys.argv[1])
shadow = pathlib.Path(sys.argv[2])

if shadow.is_symlink():
    raise RuntimeError("shadow path is a symbolic link")

lines = shadow.read_text(
    encoding="utf-8",
    errors="ignore",
).splitlines()

result = []
empty_users = []

for line in lines:
    if ":" not in line:
        result.append(line)
        continue

    parts = line.split(":")

    if len(parts) < 2:
        result.append(line)
        continue

    if parts[1] == "":
        empty_users.append(parts[0])
        parts[1] = "!"
        result.append(":".join(parts))
    else:
        result.append(line)

if not empty_users:
    raise SystemExit(0)

shadow_stat = shadow.stat()
shadow_fd = -1
state_fd = -1
shadow_tmp = None
state_tmp = None
state_committed = False

try:
    shadow_fd, shadow_tmp = tempfile.mkstemp(
        dir=str(shadow.parent),
        prefix=".shadow.tmp.",
    )

    state_fd, state_tmp = tempfile.mkstemp(
        dir=str(out_file.parent),
        prefix=".empty-password-users.tmp.",
    )

    os.write(
        shadow_fd,
        ("\n".join(result) + "\n").encode("utf-8"),
    )
    os.fsync(shadow_fd)
    os.fchown(
        shadow_fd,
        shadow_stat.st_uid,
        shadow_stat.st_gid,
    )
    os.fchmod(
        shadow_fd,
        stat.S_IMODE(shadow_stat.st_mode),
    )
    os.close(shadow_fd)
    shadow_fd = -1

    os.write(
        state_fd,
        ("\n".join(empty_users) + "\n").encode("utf-8"),
    )
    os.fsync(state_fd)
    os.fchmod(state_fd, 0o600)
    os.close(state_fd)
    state_fd = -1

    os.replace(state_tmp, out_file)
    state_tmp = None
    state_committed = True

    state_directory_fd = os.open(
        out_file.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )

    try:
        os.fsync(state_directory_fd)
    finally:
        os.close(state_directory_fd)

    print(shadow_tmp)
except Exception:
    for descriptor in (shadow_fd, state_fd):
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass

    for temporary in (shadow_tmp, state_tmp):
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    if state_committed:
        try:
            out_file.unlink()
        except FileNotFoundError:
            pass

    raise
PYJSON
    )"
    then
        add_error \
            "2.1.1 не удалось подготовить безопасное изменение $shadow_file"
        return 1
    fi

    if [[ ! -f "$empty_users_file" ]]; then
        record_manifest_apply_report \
            "2.1.1 no empty password fields found in /etc/shadow"
        add_safe \
            "2.1.1 no empty password fields found in /etc/shadow"
        return 0
    fi

    if [[ -z "$shadow_candidate" ||
          ! -f "$shadow_candidate" ]]
    then
        add_error \
            "2.1.1 shadow-кандидат не создан"

        rm -f -- \
            "$shadow_candidate" \
            "$empty_users_file"

        return 1
    fi

    if ! record_manifest_empty_password_state \
        "$empty_users_file" \
        "$shadow_file"
    then
        add_error \
            "2.1.1 изменение $shadow_file отменено: typed state не записан"

        if ! rm -f -- "$shadow_candidate"; then
            add_warning \
                "2.1.1 не удалось удалить shadow-кандидат $shadow_candidate"
        fi

        if ! rm -f -- "$empty_users_file"; then
            add_warning \
                "2.1.1 не удалось удалить незарегистрированный список $empty_users_file"
        fi

        return 1
    fi

    if ! python3 - "$shadow_candidate" "$shadow_file" <<'PYJSON'
import os
import pathlib
import sys

candidate = pathlib.Path(sys.argv[1])
shadow = pathlib.Path(sys.argv[2])

if shadow.is_symlink():
    raise RuntimeError("shadow path became a symbolic link")

os.replace(candidate, shadow)

directory_fd = os.open(
    shadow.parent,
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
)

try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
PYJSON
    then
        add_error \
            "2.1.1 не удалось атомарно заменить $shadow_file"

        state_cleanup_rc=0

        if ! remove_manifest_empty_password_state; then
            state_cleanup_rc=1
            add_error \
                "2.1.1 не удалось откатить typed state после сбоя замены shadow"
        fi

        if ! rm -f -- "$shadow_candidate"; then
            add_warning \
                "2.1.1 не удалось удалить shadow-кандидат $shadow_candidate"
        fi

        if (( state_cleanup_rc == 0 )); then
            if ! rm -f -- "$empty_users_file"; then
                add_warning \
                    "2.1.1 не удалось удалить список после отката typed state: $empty_users_file"
            fi
        else
            add_warning \
                "2.1.1 список сохранён из-за неудачного отката typed state: $empty_users_file"
        fi

        return 1
    fi

    if ! record_manifest_modified_file "$shadow_file"; then
        add_error \
            "2.1.1 $shadow_file изменён, но modified_files не обновлён"
        return 1
    fi

    if ! record_manifest_apply_report \
        "2.1.1 empty password fields locked in /etc/shadow"
    then
        add_error \
            "2.1.1 $shadow_file изменён, но apply report не обновлён"
        return 1
    fi

    add_safe \
        "2.1.1 empty password fields processed in /etc/shadow"

    return 0
}

apply_fs_critical_file_one() {
    local target="$1"
    local expected actual_mode backup_path chmod_text

    expected="$(fs_expected_mode "$target")" || {
        add_error "2.3.1 unknown target: $target"
        return 1
    }

    [[ -e "$target" ]] || {
        add_error "2.3.1 file not found: $target"
        return 1
    }

    if ! actual_mode="$(fs_actual_mode "$target")"; then
        add_error "2.3.1 failed to read mode: $target"
        return 1
    fi

    if fs_mode_compliant "$target" "$actual_mode"; then
        add_safe "2.3.1 already compliant: $target"
        record_manifest_apply_report \
            "2.3.1 already compliant: $target"
        return 0
    fi

    case "$target" in
        /etc/passwd|/etc/group)
            chmod_text="chmod 644"
            ;;
        /etc/shadow)
            chmod_text="chmod go-rwx"
            ;;
    esac

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] backup '$target' metadata -> '$STATE_DIR/$(basename "$target").meta-$TIMESTAMP.txt'"
        log "[DRY-RUN] $chmod_text '$target'"
        add_skipped \
            "2.3.1 dry-run: permissions would be corrected for $target"
        return 0
    fi

    backup_path="$STATE_DIR/$(basename "$target").meta-$TIMESTAMP.txt"

    if ! write_metadata_snapshot "$target" "$backup_path"; then
        add_error             "2.3.1 не удалось сохранить metadata перед изменением: $target"
        return 1
    fi

    if ! record_manifest_backup "$target" "$backup_path"; then
        add_error             "2.3.1 metadata snapshot создан, но backup mapping не записан: $target"

        if ! rm -f -- "$backup_path"; then
            add_warning                 "2.3.1 не удалось удалить незарегистрированный snapshot $backup_path"
        fi

        return 1
    fi

    if ! fs_apply_expected_mode "$target"; then
        add_error "2.3.1 chmod failed: $target"
        return 1
    fi

    if ! actual_mode="$(fs_actual_mode "$target")"; then
        add_error \
            "2.3.1 verification mode read failed after correction: $target"
        record_manifest_warning \
            "2.3.1 verification mode read failed after correction: $target"
        return 1
    fi

    if fs_mode_compliant "$target" "$actual_mode"; then
        record_manifest_modified_file_best_effort "$target"
        record_manifest_apply_report \
            "2.3.1 corrected permissions for $target"
        add_safe "2.3.1 corrected: $target mode=$actual_mode"
    else
        add_error \
            "2.3.1 verification failed after correction: $target"
        record_manifest_warning \
            "2.3.1 verification failed after correction: $target"
        return 1
    fi
}

apply_fs_critical_files_module() {
    local f
    for f in "${FS_CRITICAL_FILES[@]}"; do
        apply_fs_critical_file_one "$f"
    done
}

cron_target_mode() {
    echo "$1" | awk -F: '{print $3}'
}

cron_target_owner() {
    echo "$1" | awk -F: '{print $4}'
}

cron_target_group() {
    echo "$1" | awk -F: '{print $5}'
}

cron_target_path() {
    echo "$1" | awk -F: '{print $1}'
}

cron_target_type() {
    echo "$1" | awk -F: '{print $2}'
}

cron_daemon_installed() {
    if [[ -n "${SECURELINUX_NG_CRON_INSTALLED_OVERRIDE:-}" ]]; then
        [[ "$SECURELINUX_NG_CRON_INSTALLED_OVERRIDE" == "1" ]]
        return
    fi

    [[ -x /usr/sbin/cron || -x /usr/sbin/crond ]] ||
        command -v cron >/dev/null 2>&1 ||
        command -v crond >/dev/null 2>&1
}

check_cron_target_one() {
    local spec="$1"
    local path type exp_mode exp_owner exp_group
    local actual_mode actual_og

    if ! path="$(cron_target_path "$spec")"; then
        add_error "2.3.6 не удалось прочитать path из cron-спецификации: $spec"
        return 1
    fi

    if ! type="$(cron_target_type "$spec")"; then
        add_error "2.3.6 не удалось прочитать type из cron-спецификации: $spec"
        return 1
    fi

    if ! exp_mode="$(cron_target_mode "$spec")"; then
        add_error "2.3.6 не удалось прочитать mode из cron-спецификации: $spec"
        return 1
    fi

    if ! exp_owner="$(cron_target_owner "$spec")"; then
        add_error "2.3.6 не удалось прочитать owner из cron-спецификации: $spec"
        return 1
    fi

    if ! exp_group="$(cron_target_group "$spec")"; then
        add_error "2.3.6 не удалось прочитать group из cron-спецификации: $spec"
        return 1
    fi

    if [[ -z "$path" ||
          ( "$type" != "file" && "$type" != "dir" ) ||
          ! "$exp_mode" =~ ^[0-7]{3,4}$ ||
          -z "$exp_owner" ||
          -z "$exp_group" ]]
    then
        add_error "2.3.6 некорректная cron-спецификация: $spec"
        return 1
    fi

    if [[ ! -e "$path" ]]; then
        if cron_daemon_installed; then
            add_risky "2.3.6 cron target missing: $path"
        else
            add_skipped "2.3.6 cron target not applicable: cron daemon not installed: $path"
        fi
        return 0
    fi

    if [[ "$type" == "file" && ! -f "$path" ]]; then
        add_risky "2.3.6 cron target type mismatch: expected file, got $path"
        return 0
    fi

    if [[ "$type" == "dir" && ! -d "$path" ]]; then
        add_risky "2.3.6 cron target type mismatch: expected dir, got $path"
        return 0
    fi

    if ! actual_mode="$(stat -c '%a' "$path")"; then
        add_error "2.3.6 не удалось прочитать режим доступа: $path"
        return 1
    fi

    if ! actual_og="$(stat -c '%U:%G' "$path")"; then
        add_error "2.3.6 не удалось прочитать владельца и группу: $path"
        return 1
    fi

    if [[ "$actual_mode" == "$exp_mode" &&
          "$actual_og" == "${exp_owner}:${exp_group}" ]]
    then
        add_safe "2.3.6 compliant: $path mode=$actual_mode owner/group=$actual_og"
    else
        add_risky "2.3.6 non-compliant: $path expected ${exp_owner}:${exp_group} mode=${exp_mode}, actual ${actual_og} mode=${actual_mode}"
    fi
}
check_cron_targets_module() {
    local spec
    local rc=0

    for spec in "${CRON_CRITICAL_TARGETS[@]}"; do
        if ! check_cron_target_one "$spec"; then
            rc=1
        fi
    done

    return "$rc"
}
apply_cron_target_one() {
    local spec="$1"
    local path exp_mode exp_owner exp_group
    local actual_mode actual_og backup_path

    if ! path="$(cron_target_path "$spec")"; then
        add_error "2.3.6 apply: не удалось прочитать path из cron-спецификации: $spec"
        return 1
    fi

    if ! exp_mode="$(cron_target_mode "$spec")"; then
        add_error "2.3.6 apply: не удалось прочитать mode из cron-спецификации: $spec"
        return 1
    fi

    if ! exp_owner="$(cron_target_owner "$spec")"; then
        add_error "2.3.6 apply: не удалось прочитать owner из cron-спецификации: $spec"
        return 1
    fi

    if ! exp_group="$(cron_target_group "$spec")"; then
        add_error "2.3.6 apply: не удалось прочитать group из cron-спецификации: $spec"
        return 1
    fi

    if [[ -z "$path" ||
          ! "$exp_mode" =~ ^[0-7]{3,4}$ ||
          -z "$exp_owner" ||
          -z "$exp_group" ]]
    then
        add_error "2.3.6 apply: некорректная cron-спецификация: $spec"
        return 1
    fi

    if [[ ! -e "$path" ]]; then
        if cron_daemon_installed; then
            add_risky "2.3.6 skipped missing cron target: $path"
        else
            add_skipped "2.3.6 cron target not applicable: cron daemon not installed: $path"
        fi
        return 0
    fi

    if ! actual_mode="$(stat -c '%a' "$path")"; then
        add_error "2.3.6 apply: не удалось прочитать режим доступа: $path"
        return 1
    fi

    if ! actual_og="$(stat -c '%U:%G' "$path")"; then
        add_error "2.3.6 apply: не удалось прочитать владельца и группу: $path"
        return 1
    fi

    if [[ "$actual_mode" == "$exp_mode" &&
          "$actual_og" == "${exp_owner}:${exp_group}" ]]
    then
        add_safe "2.3.6 already compliant: $path"
        record_manifest_apply_report "2.3.6 already compliant: $path"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] backup '$path' metadata -> '$STATE_DIR/${path##*/}.meta-$TIMESTAMP.txt'"
        log "[DRY-RUN] chown ${exp_owner}:${exp_group} '$path'"
        log "[DRY-RUN] chmod ${exp_mode} '$path'"
        add_skipped "2.3.6 dry-run: cron target metadata would be corrected for $path"
        return 0
    fi

    backup_path="$STATE_DIR/${path##*/}.meta-$TIMESTAMP.txt"

    if ! write_metadata_snapshot "$path" "$backup_path"; then
        add_error "2.3.6 не удалось сохранить metadata перед изменением: $path"
        record_manifest_warning "2.3.6 metadata snapshot failed: $path"
        return 1
    fi

    if ! record_manifest_backup "$path" "$backup_path"; then
        add_error             "2.3.6 metadata snapshot создан, но backup mapping не записан: $path"
        record_manifest_warning             "2.3.6 backup mapping failed: $path"

        if ! rm -f -- "$backup_path"; then
            add_warning                 "2.3.6 не удалось удалить незарегистрированный snapshot $backup_path"
        fi

        return 1
    fi

    if ! chown "${exp_owner}:${exp_group}" "$path"; then
        add_error "2.3.6 chown завершился с ошибкой: $path"
        record_manifest_warning "2.3.6 chown failed: $path"
        return 1
    fi

    if ! chmod "${exp_mode}" "$path"; then
        add_error "2.3.6 chmod завершился с ошибкой: $path"
        record_manifest_warning "2.3.6 chmod failed: $path"
        return 1
    fi

    if ! actual_mode="$(stat -c '%a' "$path")"; then
        add_error "2.3.6 не удалось проверить режим после исправления: $path"
        record_manifest_warning "2.3.6 post-change mode read failed: $path"
        return 1
    fi

    if ! actual_og="$(stat -c '%U:%G' "$path")"; then
        add_error "2.3.6 не удалось проверить владельца и группу после исправления: $path"
        record_manifest_warning "2.3.6 post-change ownership read failed: $path"
        return 1
    fi

    if [[ "$actual_mode" == "$exp_mode" &&
          "$actual_og" == "${exp_owner}:${exp_group}" ]]
    then
        record_manifest_modified_file_best_effort "$path"
        record_manifest_apply_report "2.3.6 corrected metadata for $path"
        record_manifest_irreversible_change "2.3.6 metadata changed on $path; previous mode/ownership recorded in backup metadata only"
        add_safe "2.3.6 corrected: $path mode=$actual_mode owner/group=$actual_og"
    else
        add_error "2.3.6 verification failed after correction: $path"
        record_manifest_warning "2.3.6 verification failed after correction: $path"
        return 1
    fi

    return 0
}
apply_cron_targets_module() {
    local spec
    local rc=0

    for spec in "${CRON_CRITICAL_TARGETS[@]}"; do
        if ! apply_cron_target_one "$spec"; then
            rc=1
        fi
    done

    return "$rc"
}
systemd_unit_candidates() {
    [[ -d "$SYSTEMD_ETC_DIR" ]] || return 0
    python3 - <<'PYJSON'
from pathlib import Path
base = Path("/etc/systemd/system")
suffixes = {".service", ".socket", ".timer", ".mount", ".path", ".target", ".slice"}
for p in sorted(base.rglob("*")):
    if p.is_dir():
        if p.name.endswith(".d") or p == base:
            print(f"{p}:dir")
        continue
    if p.suffix in suffixes or (p.parent.name.endswith(".d") and p.suffix == ".conf"):
        print(f"{p}:file")
PYJSON
}

check_systemd_unit_one() {
    local path="$1" kind="$2" exp_mode actual_mode actual_og
    if [[ "$kind" == "dir" ]]; then
        exp_mode="755"
    else
        exp_mode="644"
    fi

    if [[ -L "$path" && ! -e "$path" ]]; then
        log_debug "2.3.5 symlink target absent (silent skip): $path"
        return 0
    fi
    if [[ ! -e "$path" ]]; then
        log_debug "2.3.5 systemd target absent (silent skip): $path"
        return 0
    fi

    if [[ -L "$path" ]]; then
        return 0  # symlink managed by package — no output needed
    fi

    actual_mode="$(stat -c '%a' "$path")"
    actual_og="$(stat -c '%U:%G' "$path")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "root:root" ]]; then
        add_safe "2.3.5 compliant: $path mode=$actual_mode owner/group=$actual_og"
    else
        add_risky "2.3.5 non-compliant: $path expected root:root mode=${exp_mode}, actual ${actual_og} mode=${actual_mode}"
    fi
}

check_systemd_unit_targets_module() {
    local item path kind
    local candidates_output=""

    if ! candidates_output="$(systemd_unit_candidates)"; then
        add_error "systemd unit targets: не удалось получить список объектов"
        return 1
    fi

    while IFS= read -r item; do
        [[ -n "$item" ]] || continue
        path="${item%:*}"
        kind="${item##*:}"
        check_systemd_unit_one "$path" "$kind"
    done <<< "$candidates_output"
}

apply_systemd_unit_one() {
    local path="$1" kind="$2" exp_mode actual_mode actual_og backup_path
    if [[ "$kind" == "dir" ]]; then
        exp_mode="755"
    else
        exp_mode="644"
    fi

    [[ -e "$path" ]] || { log_debug "2.3.5 systemd target absent (silent skip): $path"; return 0; }

    if [[ -L "$path" ]]; then
        return 0  # symlink managed by package — no output needed
    fi

    actual_mode="$(stat -c '%a' "$path")"
    actual_og="$(stat -c '%U:%G' "$path")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "root:root" ]]; then
        add_safe "2.3.5 already compliant: $path"
        record_manifest_apply_report "2.3.5 already compliant: $path"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] backup '$path' metadata -> '$STATE_DIR/$(basename "$path").meta-$TIMESTAMP.txt'"
        log "[DRY-RUN] chown root:root '$path'"
        log "[DRY-RUN] chmod ${exp_mode} '$path'"
        add_skipped "2.3.5 dry-run: systemd target metadata would be corrected for $path"
        return 0
    fi

    backup_path="$STATE_DIR/$(basename "$path").meta-$TIMESTAMP.txt"

    if ! write_metadata_snapshot "$path" "$backup_path"; then
        add_error             "2.3.5 не удалось сохранить metadata перед изменением: $path"
        return 1
    fi

    if ! record_manifest_backup "$path" "$backup_path"; then
        add_error             "2.3.5 metadata snapshot создан, но backup mapping не записан: $path"

        if ! rm -f -- "$backup_path"; then
            add_warning                 "2.3.5 не удалось удалить незарегистрированный snapshot $backup_path"
        fi

        return 1
    fi

    chown root:root "$path"
    chmod "$exp_mode" "$path"

    actual_mode="$(stat -c '%a' "$path")"
    actual_og="$(stat -c '%U:%G' "$path")"

    if [[ "$actual_mode" == "$exp_mode" && "$actual_og" == "root:root" ]]; then
        record_manifest_modified_file_best_effort "$path"
        record_manifest_apply_report "2.3.5 corrected metadata for $path"
        record_manifest_irreversible_change "2.3.5 metadata changed on $path; previous mode/ownership recorded in backup metadata only"
        add_safe "2.3.5 corrected: $path mode=$actual_mode owner/group=$actual_og"
    else
        add_error "2.3.5 verification failed after correction: $path"
        record_manifest_warning "2.3.5 verification failed after correction: $path"
        return 1
    fi
}

apply_systemd_unit_targets_module() {
    local item path kind
    local candidates_output=""

    if ! candidates_output="$(systemd_unit_candidates)"; then
        add_error "systemd unit targets: не удалось получить список объектов"
        return 1
    fi

    while IFS= read -r item; do
        [[ -n "$item" ]] || continue
        path="${item%:*}"
        kind="${item##*:}"
        apply_systemd_unit_one "$path" "$kind"
    done <<< "$candidates_output"
}

sudo_policy_status() {
    local comparison_rc=0

    if [[ ! -e "$SUDO_POLICY_DROPIN" \
        && ! -L "$SUDO_POLICY_DROPIN" ]]
    then
        printf '%s\n' "absent"
        return 0
    fi

    if [[ ! -f "$SUDO_POLICY_DROPIN" ]]; then
        printf '%s\n' "conflict"
        return 0
    fi

    python3 - \
        "$SUDO_POLICY_DROPIN" \
        "$SUDO_POLICY_CONTENT" <<'PYCOMPARE'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected = sys.argv[2].encode("utf-8")

try:
    actual = path.read_bytes()
except OSError:
    raise SystemExit(2)

raise SystemExit(0 if actual == expected else 1)
PYCOMPARE
    comparison_rc=$?

    case "$comparison_rc" in
        0)
            printf '%s\n' "configured"
            return 0
            ;;
        1)
            printf '%s\n' "conflict"
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

check_sudo_policy_module() {
    local status=""

    if ! status="$(
        sudo_policy_status
    )"
    then
        add_error \
            "2.2.2 sudo policy status detection failed"
        return 1
    fi

    case "$status" in
        configured)
            add_safe \
                "2.2.2 sudo policy полностью соответствует managed drop-in: $SUDO_POLICY_DROPIN"
            ;;
        absent)
            add_risky \
                "2.2.2 sudo policy is not enforced yet: missing $SUDO_POLICY_DROPIN"
            ;;
        conflict)
            add_risky \
                "2.2.2 sudo policy drop-in exists but content differs from managed policy: $SUDO_POLICY_DROPIN"
            ;;
        *)
            add_error \
                "2.2.2 sudo policy status detection returned unsupported value: $status"
            return 1
            ;;
    esac

    return 0
}

apply_sudo_policy_module() {
    local status=""
    local backup_path=""
    local existed_before=0
    local target_dir=""
    local target_name=""
    local temporary=""

    if ! status="$(
        sudo_policy_status
    )"
    then
        add_error \
            "2.2.2 sudo policy status detection failed during apply"
        return 1
    fi

    case "$status" in
        configured)
            add_safe \
                "2.2.2 sudo policy already configured: $SUDO_POLICY_DROPIN"

            record_manifest_apply_report \
                "2.2.2 already compliant: $SUDO_POLICY_DROPIN"

            return 0
            ;;
        absent|conflict)
            ;;
        *)
            add_error \
                "2.2.2 sudo policy status detection returned unsupported value during apply: $status"
            return 1
            ;;
    esac

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] mkdir -p '/etc/sudoers.d'"

        if [[ -e "$SUDO_POLICY_DROPIN" \
            || -L "$SUDO_POLICY_DROPIN" ]]
        then
            log \
                "[DRY-RUN] backup '$SUDO_POLICY_DROPIN' -> '$STATE_DIR/$(basename "$SUDO_POLICY_DROPIN").bak-$TIMESTAMP'"
        fi

        log \
            "[DRY-RUN] create and validate temporary sudo policy in /etc/sudoers.d"
        log \
            "[DRY-RUN] atomically replace '$SUDO_POLICY_DROPIN'"
        add_skipped \
            "2.2.2 dry-run: sudo policy drop-in would be written"

        return 0
    fi

    target_dir="$(dirname -- "$SUDO_POLICY_DROPIN")"
    target_name="$(basename -- "$SUDO_POLICY_DROPIN")"

    if ! mkdir -p -- "$target_dir"; then
        add_error \
            "2.2.2 sudo policy: не удалось создать каталог $target_dir"
        return 1
    fi

    if [[ -e "$SUDO_POLICY_DROPIN" \
        || -L "$SUDO_POLICY_DROPIN" ]]
    then
        existed_before=1

        if [[ ! -f "$SUDO_POLICY_DROPIN" ]]; then
            add_error \
                "2.2.2 sudo policy: $SUDO_POLICY_DROPIN существует, но не является обычным файлом или ссылкой на файл"
            return 1
        fi

        backup_path="$STATE_DIR/${target_name}.bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$SUDO_POLICY_DROPIN" \
            "$backup_path" \
            "2.2.2 sudo policy"
        then
            add_skipped \
                "2.2.2 apply skipped: backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$SUDO_POLICY_DROPIN" \
            "$backup_path"
        then
            add_error \
                "2.2.2 apply skipped: backup mapping не записан"

            if ! rm -f -- "$backup_path"; then
                add_warning \
                    "2.2.2 sudo policy: не удалось удалить незарегистрированный backup $backup_path"
            fi

            return 1
        fi
    fi

    if ! temporary="$(
        mktemp \
            "$target_dir/.${target_name}.tmp.XXXXXX"
    )"
    then
        add_error \
            "2.2.2 sudo policy: не удалось создать временный файл"
        return 1
    fi

    if ! printf '%s' \
        "$SUDO_POLICY_CONTENT" \
        > "$temporary"
    then
        add_error \
            "2.2.2 sudo policy: не удалось записать временный файл"
        rm -f -- "$temporary" || true
        return 1
    fi

    if ! chmod 0440 "$temporary"; then
        add_error \
            "2.2.2 sudo policy: chmod временного файла завершился ошибкой"
        rm -f -- "$temporary" || true
        return 1
    fi

    if ! chown 0:0 "$temporary"; then
        add_error \
            "2.2.2 sudo policy: chown временного файла завершился ошибкой"
        rm -f -- "$temporary" || true
        return 1
    fi

    if ! visudo -cf "$temporary" \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_error \
            "2.2.2 visudo validation failed for temporary sudo policy"

        record_manifest_warning \
            "2.2.2 visudo validation failed before replacing $SUDO_POLICY_DROPIN"

        rm -f -- "$temporary" || true
        return 1
    fi

    if ! prepare_created_file_transaction \
        "$SUDO_POLICY_DROPIN" \
        "$existed_before" \
        "2.2.2 sudo policy"
    then
        rm -f -- "$temporary" || true
        return 1
    fi

    if ! mv -f -- \
        "$temporary" \
        "$SUDO_POLICY_DROPIN"
    then
        add_error \
            "2.2.2 sudo policy: атомарная замена $SUDO_POLICY_DROPIN завершилась ошибкой"

        rm -f -- "$temporary" || true
        return 1
    fi

    temporary=""

    if (( existed_before == 0 )); then
        if ! record_manifest_created_file \
            "$SUDO_POLICY_DROPIN" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "2.2.2 sudo policy: созданный drop-in не записан в manifest"

            if ! rm -f -- "$SUDO_POLICY_DROPIN"; then
                add_warning \
                    "2.2.2 sudo policy: не удалось удалить незарегистрированный drop-in $SUDO_POLICY_DROPIN"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$SUDO_POLICY_DROPIN"

    record_manifest_apply_report \
        "2.2.2 enforced via $SUDO_POLICY_DROPIN"

    add_safe \
        "2.2.2 sudo policy enforced via drop-in: $SUDO_POLICY_DROPIN"

    return 0
}

ssh_root_login_status() {
    if [[ -f "$SSH_ROOT_LOGIN_DROPIN" ]]; then
        if grep -Eq '^[[:space:]]*PermitRootLogin[[:space:]]+no[[:space:]]*$' "$SSH_ROOT_LOGIN_DROPIN"; then
            echo "configured"
            return 0
        fi
        echo "conflict"
        return 0
    fi
    echo "absent"
}

check_ssh_root_login_module() {
    local status
    status="$(ssh_root_login_status)"

    case "$status" in
        configured)
            add_safe "2.1.2 SSH root login disabled via drop-in: $SSH_ROOT_LOGIN_DROPIN"
            ;;
        absent)
            add_risky "2.1.2 SSH root login is not enforced yet: missing $SSH_ROOT_LOGIN_DROPIN"
            ;;
        conflict)
            add_risky "2.1.2 SSH root login drop-in exists but content is not 'PermitRootLogin no': $SSH_ROOT_LOGIN_DROPIN"
            ;;
        *)
            add_error "2.1.2 SSH root login status detection failed"
            ;;
    esac
}

apply_ssh_root_login_module() {
    local status=""
    local backup_path=""
    local existed_before=0
    local ssh_dir=""
    local ssh_tmp=""

    if ! status="$(ssh_root_login_status)"; then
        add_error \
            "2.1.2 SSH root login status detection failed during apply"
        return 1
    fi

    case "$status" in
        configured)
            add_safe \
                "2.1.2 SSH root login already disabled: $SSH_ROOT_LOGIN_DROPIN"

            record_manifest_apply_report \
                "2.1.2 already compliant: $SSH_ROOT_LOGIN_DROPIN"

            return 0
            ;;
        absent|conflict)
            ;;
        *)
            add_error \
                "2.1.2 SSH root login status detection returned invalid state: $status"
            return 1
            ;;
    esac

    if (( DRY_RUN == 1 )); then
        log \
            "[DRY-RUN] mkdir -p '$(dirname "$SSH_ROOT_LOGIN_DROPIN")'"

        if [[ -e "$SSH_ROOT_LOGIN_DROPIN" \
            || -L "$SSH_ROOT_LOGIN_DROPIN" ]]
        then
            log \
                "[DRY-RUN] backup '$SSH_ROOT_LOGIN_DROPIN' -> '$STATE_DIR/$(basename "$SSH_ROOT_LOGIN_DROPIN").bak-$TIMESTAMP'"
        fi

        log \
            "[DRY-RUN] atomically write '$SSH_ROOT_LOGIN_DROPIN' with 'PermitRootLogin no'"
        log "[DRY-RUN] sshd -t"

        add_skipped \
            "2.1.2 dry-run: SSH root login drop-in would be written"

        return 0
    fi

    ssh_dir="$(dirname "$SSH_ROOT_LOGIN_DROPIN")"

    if ! mkdir -p -- "$ssh_dir"; then
        add_error \
            "2.1.2 не удалось создать каталог SSH root-login drop-in"
        return 1
    fi

    if [[ -e "$SSH_ROOT_LOGIN_DROPIN" \
        || -L "$SSH_ROOT_LOGIN_DROPIN" ]]
    then
        existed_before=1
        backup_path="$STATE_DIR/$(basename "$SSH_ROOT_LOGIN_DROPIN").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$SSH_ROOT_LOGIN_DROPIN" \
            "$backup_path" \
            "2.1.2 SSH root login"
        then
            add_skipped \
                "2.1.2 apply skipped: backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$SSH_ROOT_LOGIN_DROPIN" \
            "$backup_path"
        then
            add_error \
                "2.1.2 apply skipped: SSH root-login backup mapping не записан"

            if ! rm -f -- "$backup_path"; then
                add_warning \
                    "2.1.2 не удалось удалить незарегистрированный backup $backup_path"
            fi

            return 1
        fi
    fi

    ssh_tmp="$(
        mktemp \
            "$ssh_dir/.securelinux-ng-root-login.XXXXXX"
    )" || {
        add_error \
            "2.1.2 не удалось создать временный SSH root-login drop-in"
        return 1
    }

    if ! printf '%s' \
        "$SSH_ROOT_LOGIN_CONTENT" \
        > "$ssh_tmp" \
        || ! chmod 0644 "$ssh_tmp" \
        || ! chown root:root "$ssh_tmp"
    then
        rm -f -- "$ssh_tmp" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        add_error \
            "2.1.2 не удалось подготовить SSH root-login drop-in"

        return 1
    fi

    if ! prepare_created_file_transaction \
        "$SSH_ROOT_LOGIN_DROPIN" \
        "$existed_before" \
        "2.1.2 SSH root-login"
    then
        rm -f -- "$ssh_tmp" 2>>"${DEBUG_LOG_FILE:-/dev/null}" || true
        return 1
    fi

    if ! mv -f -- \
        "$ssh_tmp" \
        "$SSH_ROOT_LOGIN_DROPIN"
    then
        rm -f -- "$ssh_tmp" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        if ! rollback_ssh_hardening_target \
            "$SSH_ROOT_LOGIN_DROPIN" \
            "$backup_path" \
            "$existed_before"
        then
            add_error \
                "2.1.2 не удалось установить SSH root-login drop-in и полностью выполнить откат"
        else
            add_error \
                "2.1.2 не удалось установить SSH root-login drop-in — выполнен откат"
        fi

        return 1
    fi

    if ! sshd -t >/dev/null 2>&1; then
        if ! rollback_ssh_hardening_target \
            "$SSH_ROOT_LOGIN_DROPIN" \
            "$backup_path" \
            "$existed_before"
        then
            add_error \
                "2.1.2 sshd -t failed; откат SSH root-login drop-in также завершился ошибкой"
        else
            add_error \
                "2.1.2 sshd -t failed после записи $SSH_ROOT_LOGIN_DROPIN — выполнен откат"
        fi

        record_manifest_warning \
            "2.1.2 sshd -t failed after writing SSH root-login drop-in" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" \
            || true

        return 1
    fi

    if (( existed_before == 0 )); then
        if ! record_manifest_created_file \
            "$SSH_ROOT_LOGIN_DROPIN" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "2.1.2 созданный SSH root-login drop-in не записан в manifest"

            if ! rollback_ssh_hardening_target \
                "$SSH_ROOT_LOGIN_DROPIN" \
                "$backup_path" \
                "$existed_before"
            then
                add_error \
                    "2.1.2 не удалось удалить незарегистрированный SSH root-login drop-in"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$SSH_ROOT_LOGIN_DROPIN"

    record_manifest_apply_report \
        "2.1.2 enforced via $SSH_ROOT_LOGIN_DROPIN"

    if systemctl reload sshd \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 \
        || systemctl reload ssh \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        add_safe \
            "2.1.2 SSH root login disabled via drop-in: $SSH_ROOT_LOGIN_DROPIN"
        return 0
    fi

    add_error \
        "2.1.2 SSH root-login drop-in записан и проверен, но reload ssh/sshd завершился ошибкой"

    record_manifest_warning \
        "2.1.2 ssh reload failed after writing root-login drop-in" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" \
        || true

    return 1
}

pam_wheel_group_exists() {
    getent group wheel >/dev/null 2>&1
}

pam_wheel_group_members() {
    local entry=""
    local gid=""
    local members=""
    local passwd_output=""
    local explicit_members_output=""
    local primary_members_output=""
    local member=""
    local -A seen=()

    if ! entry="$(getent group wheel 2>/dev/null)"; then
        return 1
    fi

    IFS=: read -r _ _ gid members <<< "$entry"

    [[ "$gid" =~ ^[0-9]+$ ]] || return 1

    if ! passwd_output="$(getent passwd 2>/dev/null)"; then
        return 1
    fi

    if ! explicit_members_output="$(
        tr ',' '\n' <<< "$members"
    )"; then
        return 1
    fi

    if ! primary_members_output="$(
        awk -F: -v target_gid="$gid" \
            '$4 == target_gid { print $1 }' \
            <<< "$passwd_output"
    )"; then
        return 1
    fi

    while IFS= read -r member; do
        [[ -n "$member" ]] || continue

        if [[ -z "${seen[$member]+x}" ]]; then
            printf '%s\n' "$member"
            seen["$member"]=1
        fi
    done <<< "${explicit_members_output}"$'\n'"${primary_members_output}"
}

pam_wheel_has_members() {
    local members_output=""

    if ! members_output="$(pam_wheel_group_members)"; then
        return 1
    fi

    [[ -n "$members_output" ]]
}

pam_wheel_user_is_member() {
    local user_name="$1"

    id -nG "$user_name" 2>/dev/null |
        tr ' ' '\n' |
        grep -Fxq wheel
}

pam_wheel_user_is_existing_admin() {
    local user_name="$1"

    getent passwd "$user_name" >/dev/null 2>&1 || return 1

    id -nG "$user_name" 2>/dev/null |
        tr ' ' '\n' |
        grep -Eq '^(sudo|admin|wheel)$'
}

configured_wheel_users() {
    printf '%s\n' "${WHEEL_USERS//,/ }" |
        tr '[:space:]' '\n' |
        awk 'NF && !seen[$0]++'
}

pam_wheel_configured_users_present() {
    local user_name
    local configured_users_output=""

    if ! configured_users_output="$(configured_wheel_users)"; then
        return 1
    fi

    while IFS= read -r user_name; do
        [[ -n "$user_name" ]] || continue
        pam_wheel_user_is_member "$user_name" || return 1
    done <<< "$configured_users_output"

    return 0
}

pam_wheel_rule_present() {
    [[ -f "$PAM_SU_FILE" ]] || return 1

    awk '
        /^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so/ &&
        /use_uid/ &&
        /group=wheel/ {
            found=1
        }
        END {
            exit !found
        }
    ' "$PAM_SU_FILE"
}

pam_wheel_managed_block_present() {
    [[ -f "$PAM_SU_FILE" ]] || return 1
    grep -Fq "$PAM_WHEEL_BLOCK_BEGIN" "$PAM_SU_FILE" \
        && grep -Fq "$PAM_WHEEL_BLOCK_END" "$PAM_SU_FILE"
}

check_pam_wheel_module() {
    local group_ok=0
    local rule_ok=0
    local members_ok=0
    local configured_ok=0
    local root_ok=0
    local user_name
    local configured_users_output=""

    pam_wheel_group_exists && group_ok=1 || true
    pam_wheel_rule_present && rule_ok=1 || true
    pam_wheel_has_members && members_ok=1 || true
    pam_wheel_configured_users_present && configured_ok=1 || true
    pam_wheel_user_is_member root && root_ok=1 || true

    if (( group_ok == 1 \
          && rule_ok == 1 \
          && members_ok == 1 \
          && configured_ok == 1 \
          && root_ok == 1 ))
    then
        add_safe "2.2.1 su restricted via non-empty wheel and pam_wheel"
        return 0
    fi

    (( group_ok == 1 )) \
        || add_risky "2.2.1 missing group wheel"

    (( rule_ok == 1 )) \
        || add_risky "2.2.1 missing active pam_wheel rule in $PAM_SU_FILE"

    if (( group_ok == 1 && members_ok == 0 )); then
        add_risky "2.2.1 wheel group is empty — su is unavailable to non-root users"
    fi

    if (( group_ok == 1 && root_ok == 0 )); then
        add_risky "2.2.1 root is not a member of wheel"
    fi

    if (( configured_ok == 0 )); then
        if ! configured_users_output="$(configured_wheel_users)"; then
            add_error "2.2.1 не удалось разобрать WHEEL_USERS"
            return 1
        fi

        while IFS= read -r user_name; do
            [[ -n "$user_name" ]] || continue
            pam_wheel_user_is_member "$user_name" \
                || add_risky "2.2.1 configured user '$user_name' is not in wheel"
        done <<< "$configured_users_output"
    fi
}

apply_pam_wheel_module() {
    local need_backup=0
    local backup_path=""
    local user_name
    local configured_users_output=""
    local -a users=()

    if ! configured_users_output="$(configured_wheel_users)"; then
        add_error "2.2.1 не удалось разобрать WHEEL_USERS"
        return 1
    fi

    if [[ -n "$configured_users_output" ]]; then
        mapfile -t users <<< "$configured_users_output"
    fi

    if pam_wheel_group_exists \
       && pam_wheel_rule_present \
       && pam_wheel_has_members \
       && pam_wheel_user_is_member root \
       && pam_wheel_configured_users_present
    then
        add_safe "2.2.1 su restriction already configured"
        record_manifest_apply_report \
            "2.2.1 already compliant: non-empty wheel + pam_wheel"
        return 0
    fi

    if (( ${#users[@]} == 0 )); then
        if [[ -n "${SUDO_USER:-}" ]] \
           && [[ "$SUDO_USER" != "root" ]] \
           && getent passwd "$SUDO_USER" >/dev/null 2>&1 \
           && pam_wheel_user_is_existing_admin "$SUDO_USER"
        then
            WHEEL_USERS="$SUDO_USER"
            users=("$SUDO_USER")
            log "[i]     2.2.1 WHEEL_USERS автоматически определён из SUDO_USER: $SUDO_USER"
        fi
    fi

    if (( ${#users[@]} == 0 )); then
        if (( DRY_RUN == 1 )); then
            add_warning \
                "2.2.1 administrator auto-detection failed; set WHEEL_USERS explicitly"
            return 0
        fi
        add_error \
            "2.2.1 administrator auto-detection failed; set WHEEL_USERS explicitly"
        return 1
    fi

    for user_name in "${users[@]}"; do
        if [[ ! "$user_name" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
            add_error "2.2.1 invalid WHEEL_USERS entry: '$user_name'"
            return 1
        fi

        if ! getent passwd "$user_name" >/dev/null 2>&1; then
            add_error "2.2.1 WHEEL_USERS: user '$user_name' does not exist"
            return 1
        fi

        if ! pam_wheel_user_is_existing_admin "$user_name"; then
            add_error \
                "2.2.1 WHEEL_USERS: '$user_name' is not a member of sudo/admin/wheel"
            return 1
        fi
    done

    if (( DRY_RUN == 1 )); then
        pam_wheel_group_exists || log "[DRY-RUN] groupadd wheel"
        pam_wheel_user_is_member root \
            || log "[DRY-RUN] gpasswd -a root wheel"

        for user_name in "${users[@]}"; do
            pam_wheel_user_is_member "$user_name" \
                || log "[DRY-RUN] gpasswd -a '$user_name' wheel"
        done

        if [[ -f "$PAM_SU_FILE" ]]; then
            log "[DRY-RUN] backup '$PAM_SU_FILE' -> '$STATE_DIR/$(basename "$PAM_SU_FILE").bak-$TIMESTAMP'"
        fi

        log "[DRY-RUN] ensure managed pam_wheel block in '$PAM_SU_FILE'"
        add_skipped \
            "2.2.1 dry-run: configured administrators would be added to wheel"
        return 0
    fi

    if ! pam_wheel_group_exists; then
        if ! record_manifest_pending_created_group wheel; then
            add_error                 "2.2.1 pending marker for group wheel was not recorded"
            return 1
        fi

        if groupadd wheel; then
            if ! record_manifest_created_group wheel; then
                if groupdel wheel \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
                then
                    add_warning \
                        "2.2.1 rolled back unrecorded group wheel"
                else
                    add_error \
                        "2.2.1 failed to roll back unrecorded group wheel"
                fi

                return 1
            fi

            record_manifest_apply_report \
                "2.2.1 created group wheel"
        else
            add_error "2.2.1 failed to create group wheel"
            return 1
        fi
    fi

    command -v gpasswd >/dev/null 2>&1 || {
        add_error "2.2.1 gpasswd command not found"
        return 1
    }

    if ! pam_wheel_user_is_member root; then
        if ! record_manifest_pending_group_membership wheel root; then
            add_error                 "2.2.1 pending marker for root membership was not recorded"
            return 1
        fi

        if gpasswd -a root wheel \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            if ! record_manifest_added_group_membership \
                wheel \
                root
            then
                if gpasswd -d root wheel \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
                then
                    add_warning \
                        "2.2.1 rolled back unrecorded root membership"
                else
                    add_error \
                        "2.2.1 failed to roll back unrecorded root membership"
                fi

                return 1
            fi

            record_manifest_apply_report \
                "2.2.1 added 'root' to wheel"
        else
            add_error "2.2.1 failed to add 'root' to wheel"
            return 1
        fi
    fi

    for user_name in "${users[@]}"; do
        if pam_wheel_user_is_member "$user_name"; then
            continue
        fi

        if ! record_manifest_pending_group_membership \
            wheel \
            "$user_name"
        then
            add_error                 "2.2.1 pending marker for '$user_name' membership was not recorded"
            return 1
        fi

        if gpasswd -a "$user_name" wheel \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            if ! record_manifest_added_group_membership \
                wheel \
                "$user_name"
            then
                if gpasswd -d "$user_name" wheel \
                    >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
                then
                    add_warning \
                        "2.2.1 rolled back unrecorded '$user_name' membership"
                else
                    add_error \
                        "2.2.1 failed to roll back unrecorded '$user_name' membership"
                fi

                return 1
            fi

            record_manifest_apply_report \
                "2.2.1 added '$user_name' to wheel"
        else
            add_error "2.2.1 failed to add '$user_name' to wheel"
            return 1
        fi
    done

    [[ -f "$PAM_SU_FILE" ]] || die "Файл не найден: $PAM_SU_FILE"

    backup_path="$STATE_DIR/$(basename "$PAM_SU_FILE").bak-$TIMESTAMP"
    if ! manifest_has_backup_for "$PAM_SU_FILE"; then
        if ! backup_file_checked \
            "$PAM_SU_FILE" \
            "$backup_path" \
            "2.2.1 pam_wheel"
        then
            add_skipped "2.2.1 apply skipped: backup failed"
            return 0
        fi
        if ! record_manifest_backup \
            "$PAM_SU_FILE" \
            "$backup_path"
        then
            add_skipped \
                "2.2.1 apply skipped: manifest backup mapping failed"

            if ! rm -f -- "$backup_path"; then
                add_warning \
                    "2.2.1 не удалось удалить незарегистрированный backup $backup_path"
            fi

            return 1
        fi

        need_backup=1
    fi

    if ! atomic_write_command_output \
        "$PAM_SU_FILE" \
        0644 \
        python3 - "$PAM_SU_FILE" <<'PYJSON'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

begin = "# BEGIN SecureLinux-NG 2.2.1"
end = "# END SecureLinux-NG 2.2.1"
line = "auth required pam_wheel.so use_uid group=wheel"
block = begin + "\n" + line + "\n" + end + "\n"

pattern = re.compile(
    r"(?ms)^# BEGIN SecureLinux-NG 2\.2\.1\n"
    r".*?"
    r"^# END SecureLinux-NG 2\.2\.1\n?"
)

if pattern.search(text):
    text = pattern.sub(block, text)
else:
    if not text.endswith("\n"):
        text += "\n"
    text += "\n" + block

print(text, end="")
PYJSON
    then
        add_error "2.2.1 pam_wheel atomic update failed"
        record_manifest_warning             "2.2.1 pam_wheel atomic update failed"
        return 1
    fi

    if pam_wheel_rule_present \
       && pam_wheel_has_members \
       && pam_wheel_user_is_member root \
       && pam_wheel_configured_users_present
    then
        record_manifest_modified_file_best_effort "$PAM_SU_FILE"
        record_manifest_apply_report \
            "2.2.1 enforced: non-empty wheel + pam_wheel"
        add_safe \
            "2.2.1 su restricted via non-empty wheel and pam_wheel"
    else
        add_error "2.2.1 pam_wheel verification failed"
        return 1
    fi
}

require_cmds() {
    local missing=()
    local cmd
    for cmd in bash python3 stat uname grep awk date mkdir cat systemctl visudo sysctl; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    (( ${#missing[@]} == 0 )) || die "Отсутствуют обязательные команды: ${missing[*]}"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help)
                usage
                exit 0
                ;;
            --version)
                echo "securelinux-ng.sh v${SCRIPT_VERSION}"
                exit 0
                ;;
            --check|--apply|--restore|--report)
                [[ -z "$MODE" ]] || die "Нельзя указывать несколько режимов одновременно"
                MODE="${1#--}"
                ;;
            --dry-run)
                DRY_RUN=1
                ;;
            --enable-additional-measures)
                ENABLE_ADDITIONAL_MEASURES=1
                _ADDITIONAL_MEASURES_SET_BY_CLI=1
                ;;
            --enable-corporate-password-policy)
                ENABLE_CORPORATE_PASSWORD_POLICY=1
                _CORPORATE_PASSWORD_POLICY_SET_BY_CLI=1
                ;;
            --profile)
                shift
                [[ $# -gt 0 ]] || die "После --profile требуется значение"
                PROFILE="$1"
                _PROFILE_SET_BY_CLI=1
                ;;
            --profile=*)
                PROFILE="${1#*=}"
                _PROFILE_SET_BY_CLI=1
                ;;
            --config)
                shift
                [[ $# -gt 0 ]] || die "После --config требуется путь к файлу"
                CONFIG_FILE="$1"
                ;;
            --config=*)
                CONFIG_FILE="${1#*=}"
                ;;
            --manifest)
                shift
                [[ $# -gt 0 ]] || die "После --manifest требуется путь к manifest"
                RESTORE_MANIFEST="$1"
                ;;
            --manifest=*)
                RESTORE_MANIFEST="${1#*=}"
                ;;
            *)
                die "Неизвестный аргумент: $1"
                ;;
        esac
        shift
    done
}

validate_args() {
    if [[ -z "$MODE" ]]; then usage; exit 0; fi

    case "$PROFILE" in
        baseline|strict|paranoid) ;;
        *) die "Недопустимый профиль: $PROFILE" ;;
    esac

    if (( DRY_RUN == 1 )) && [[ "$MODE" != "apply" ]]; then
        die "--dry-run допустим только вместе с --apply"
    fi

    if (( _ADDITIONAL_MEASURES_SET_BY_CLI == 1 )) && [[ "$MODE" != "apply" ]]; then
        die "--enable-additional-measures допустим только вместе с --apply"
    fi

    if (( _CORPORATE_PASSWORD_POLICY_SET_BY_CLI == 1 )) && [[ "$MODE" != "apply" ]]; then
        die "--enable-corporate-password-policy допустим только вместе с --apply"
    fi

    if [[ -n "$RESTORE_MANIFEST" && "$MODE" != "restore" ]]; then
        die "--manifest допустим только вместе с --restore"
    fi

    if [[ -n "$CONFIG_FILE" ]] && [[ ! -f "$CONFIG_FILE" ]]; then
        die "Файл конфига не найден: $CONFIG_FILE"
    fi
}

validate_args_post_config() {
    case "$PROFILE" in
        baseline|strict|paranoid) ;;
        *) die "Недопустимый профиль после загрузки конфига: $PROFILE" ;;
    esac
}

validate_execution_context() {
    case "$MODE" in
        apply)
            if (( DRY_RUN == 0 && EUID != 0 )); then
                die "--apply без --dry-run требует root"
            fi
            ;;
        restore)
            if (( EUID != 0 )); then
                die "--restore требует root"
            fi
            ;;
        check|report)
            :
            ;;
        *)
            die "Внутренняя ошибка: неизвестный режим '$MODE' при проверке контекста"
            ;;
    esac
}

additional_measures_enabled() {
    [[ "${ENABLE_ADDITIONAL_MEASURES:-0}" == "1" ]]
}

load_config() {
    [[ -n "$CONFIG_FILE" ]] || return 0

    local _cfg_rc
    local _cfg_output=""
    python3 - "$CONFIG_FILE" <<'PYCFG'
import sys, pathlib
path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding='utf-8')
for n, line in enumerate(text.splitlines(), 1):
    s = line.strip()
    if not s or s.startswith('#'):
        continue
    if '=' not in s:
        print(f"CONFIG_ERROR:{n}: нет '='")
        raise SystemExit(2)
    k, v = s.split('=', 1)
    k = k.strip()
    if not k or ' ' in k:
        print(f"CONFIG_ERROR:{n}: плохой ключ")
        raise SystemExit(2)
PYCFG
    _cfg_rc=$?
    if (( _cfg_rc != 0 )); then
        die "Ошибка в config-файле: $CONFIG_FILE — выполнение прервано"
    fi


    if ! _cfg_output="$(python3 - "$CONFIG_FILE" <<'PYCFG'
import sys, pathlib
path = pathlib.Path(sys.argv[1])
for line in path.read_text(encoding='utf-8').splitlines():
    s = line.strip()
    if not s or s.startswith('#') or '=' not in s:
        continue
    k, v = s.split('=', 1)
    print(f"{k.strip()}={v.strip()}")
PYCFG
    )"; then
        die "Ошибка чтения config-файла: $CONFIG_FILE — выполнение прервано"
    fi

    while IFS='=' read -r k v; do
        [[ -n "${k:-}" ]] || continue
        case "$k" in
            PROFILE)
                (( _PROFILE_SET_BY_CLI == 0 )) && PROFILE="$v"
                ;;
            ENABLE_ADDITIONAL_MEASURES)
                case "${v,,}" in
                    1|true|yes|on)
                        (( _ADDITIONAL_MEASURES_SET_BY_CLI == 0 )) && ENABLE_ADDITIONAL_MEASURES=1
                        ;;
                    0|false|no|off|"")
                        (( _ADDITIONAL_MEASURES_SET_BY_CLI == 0 )) && ENABLE_ADDITIONAL_MEASURES=0
                        ;;
                    *)
                        die "ENABLE_ADDITIONAL_MEASURES: допустимы 0 или 1"
                        ;;
                esac
                ;;
            ENABLE_CORPORATE_PASSWORD_POLICY)
                case "${v,,}" in
                    1|true|yes|on)
                        (( _CORPORATE_PASSWORD_POLICY_SET_BY_CLI == 0 )) && ENABLE_CORPORATE_PASSWORD_POLICY=1
                        ;;
                    0|false|no|off|"")
                        (( _CORPORATE_PASSWORD_POLICY_SET_BY_CLI == 0 )) && ENABLE_CORPORATE_PASSWORD_POLICY=0
                        ;;
                    *)
                        die "ENABLE_CORPORATE_PASSWORD_POLICY: допустимы 0 или 1"
                        ;;
                esac
                ;;
            STATE_DIR)
                STATE_DIR="$v"
                ;;
            REPORT_FILE)
                REPORT_FILE="$v"
                ;;
            MANIFEST_FILE)
                MANIFEST_FILE="$v"
                ;;
            RESTORE_MANIFEST)
                RESTORE_MANIFEST="$v"
                ;;
            USER_NAMESPACES_LIMIT)
                USER_NAMESPACES_LIMIT="$v"
                ;;
            WHEEL_USERS)
                WHEEL_USERS="$v"
                ;;
            UFW_EXTRA_RULES)
                UFW_EXTRA_RULES="$v"
                ;;
            *)
                add_warning "Неизвестный ключ в config пропущен: $k"
                ;;
        esac
    done <<< "$_cfg_output"
}

restore_manifest_has_path() {
    local target="$1"
    local rc=0

    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        add_error \
            "restore manifest: source manifest недоступен при проверке $target"
        return 2
    fi

    python3 - "$RESTORE_SOURCE_MANIFEST" "$target" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
target = sys.argv[2]

try:
    data = json.loads(manifest.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    backups = data.get("backups", [])
    created_files = data.get("created_files", [])
    pending_created_files = data.get("pending_created_files", [])

    if not isinstance(backups, list):
        raise ValueError("manifest backups is not an array")

    if not isinstance(created_files, list):
        raise ValueError("manifest created_files is not an array")

    if not isinstance(pending_created_files, list):
        raise ValueError(
            "manifest pending_created_files is not an array"
        )

    for entry in backups:
        if not isinstance(entry, dict):
            raise ValueError("manifest backup entry is not an object")

        original = entry.get("original")

        if original is not None and not isinstance(original, str):
            raise ValueError(
                "manifest backup original is not a string"
            )

        if original == target:
            raise SystemExit(0)

    for entry in created_files:
        if not isinstance(entry, str):
            raise ValueError(
                "manifest created_files entry is not a string"
            )

    for entry in pending_created_files:
        if not isinstance(entry, str):
            raise ValueError(
                "manifest pending_created_files entry is not a string"
            )

    if target in created_files or target in pending_created_files:
        raise SystemExit(0)
except Exception as exc:
    print(
        f"restore manifest read failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)

raise SystemExit(1)
PYJSON
    rc=$?

    if (( rc == 2 )); then
        add_error \
            "restore manifest: не удалось проверить состояние $target"
    fi

    return "$rc"
}
restore_manifest_has_report_text() {
    local needle="$1"
    [[ -n "${RESTORE_SOURCE_MANIFEST:-}" && -f "${RESTORE_SOURCE_MANIFEST:-}" ]] || return 1
    python3 - "$RESTORE_SOURCE_MANIFEST" "$needle" <<'PYJSON'
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
needle = sys.argv[2]
data = json.loads(mf.read_text(encoding='utf-8'))
reports = data.get("apply_report", [])
raise SystemExit(0 if any(needle in str(x) for x in reports) else 1)
PYJSON
}

finalize_paths() {
    REPORT_FILE="${REPORT_FILE:-$STATE_DIR/report.json}"
    MANIFEST_FILE="${MANIFEST_FILE:-$STATE_DIR/manifest.json}"
    LOG_FILE="${LOG_FILE:-$STATE_DIR/apply.log}"
    DEBUG_LOG_FILE="${DEBUG_LOG_FILE:-$STATE_DIR/debug.log}"
}

detect_os() {
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_VERSION_ID="${VERSION_ID:-unknown}"
    else
        DISTRO_ID="unknown"
        DISTRO_VERSION_ID="unknown"
    fi

    case "$DISTRO_ID" in
        ubuntu|debian) OS_FAMILY="debian" ;;
        *) OS_FAMILY="unknown" ;;
    esac
}

detect_environment() {
    [[ -f /.dockerenv ]] && IS_CONTAINER=1
    grep -qaE '(docker|containerd|kubepods|lxc)' /proc/1/cgroup 2>/dev/null && IS_CONTAINER=1 || true

    if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]] || [[ -n "${DESKTOP_SESSION:-}" ]]; then
        IS_DESKTOP=1
    elif systemctl is-active display-manager >/dev/null 2>&1; then
        IS_DESKTOP=1
    fi

    command -v docker >/dev/null 2>&1 && HAS_DOCKER=1 || true
    command -v podman >/dev/null 2>&1 && HAS_PODMAN=1 || true
    [[ -d /etc/kubernetes || -f /etc/rancher/k3s/k3s.yaml || -f /var/lib/kubelet/config.yaml ]] && HAS_K8S=1 || true
}

run_preflight() {
    detect_os
    detect_environment

    [[ "$OS_FAMILY" == "debian" ]] && add_safe "Поддерживаемое семейство ОС: $DISTRO_ID $DISTRO_VERSION_ID" || add_risky "Неподдерживаемое/непроверенное семейство ОС: $DISTRO_ID $DISTRO_VERSION_ID"

    (( IS_CONTAINER == 1 )) && add_policy_gate "Обнаружен контейнер: часть hardening-мер должна быть автоматически запрещена"
    (( IS_DESKTOP == 1 )) && add_policy_gate "Обнаружен desktop-mode: часть серверных мер требует отдельной политики"
    (( HAS_DOCKER == 1 )) && add_policy_gate "Обнаружен Docker: сетевые/sysctl-меры нужно маркировать как compatibility-sensitive"
    (( HAS_PODMAN == 1 )) && add_policy_gate "Обнаружен Podman: проверять совместимость namespace/cgroup/sysctl"
    (( HAS_K8S == 1 )) && add_policy_gate "Обнаружен Kubernetes node: kernel/network hardening применять только по политике"

    return 0
}

secure_state_dir() {
    local state_path="$1"
    local expected_uid="${2:-$EUID}"

    python3 - "$state_path" "$expected_uid" <<'PYSTATEDIR'
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
expected_uid = int(sys.argv[2])
fd = None

try:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)

    opened = os.fstat(fd)
    current = os.lstat(path)

    if not stat.S_ISDIR(opened.st_mode):
        raise RuntimeError("STATE_DIR is not a directory")

    if not stat.S_ISDIR(current.st_mode):
        raise RuntimeError("STATE_DIR path is not a directory")

    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        raise RuntimeError("STATE_DIR changed during validation")

    if opened.st_uid != expected_uid:
        raise PermissionError(
            f"STATE_DIR owner uid={opened.st_uid}, expected uid={expected_uid}"
        )

    os.fchmod(fd, 0o700)
    verified = os.fstat(fd)

    if stat.S_IMODE(verified.st_mode) != 0o700:
        raise PermissionError(
            "STATE_DIR mode is not 0700 after fchmod"
        )
except Exception as exc:
    print(f"STATE_DIR security validation failed: {exc}", file=sys.stderr)
    raise SystemExit(1)
finally:
    if fd is not None:
        os.close(fd)
PYSTATEDIR
}

ensure_state_dir() {
    local original_state_dir="$STATE_DIR"
    local fallback_state_dir="$SCRIPT_DIR/.securelinux-ng-state"
    local state_error=""

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] создать и проверить STATE_DIR 0700 owner=$EUID: $STATE_DIR"
        return 0
    fi

    if state_error="$(secure_state_dir "$STATE_DIR" 2>&1)"; then
        return 0
    fi

    case "$MODE" in
        check|report)
            add_warning \
                "STATE_DIR отклонён: $STATE_DIR ($state_error); используется защищённый fallback: $fallback_state_dir"
            STATE_DIR="$fallback_state_dir"
            ;;
        restore)
            if [[ -n "$RESTORE_MANIFEST" ]]; then
                add_warning \
                    "STATE_DIR отклонён: $STATE_DIR ($state_error); для restore с явным --manifest используется защищённый fallback: $fallback_state_dir"
                STATE_DIR="$fallback_state_dir"
            else
                add_error \
                    "STATE_DIR не прошёл security validation: $STATE_DIR ($state_error)"
                return 1
            fi
            ;;
        *)
            add_error \
                "STATE_DIR не прошёл security validation: $STATE_DIR ($state_error)"
            return 1
            ;;
    esac

    if ! state_error="$(secure_state_dir "$STATE_DIR" 2>&1)"; then
        add_error \
            "fallback STATE_DIR не прошёл security validation: $STATE_DIR ($state_error)"
        return 1
    fi

    case "$REPORT_FILE" in
        "$original_state_dir"/*)
            REPORT_FILE="$STATE_DIR/$(basename "$REPORT_FILE")"
            ;;
    esac

    case "$MANIFEST_FILE" in
        "$original_state_dir"/*)
            MANIFEST_FILE="$STATE_DIR/$(basename "$MANIFEST_FILE")"
            ;;
    esac

    return 0
}

manifest_init() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] создать manifest: $MANIFEST_FILE"
        return 0
    fi

    if [[ -e "$MANIFEST_FILE" ]]; then
        die "Manifest уже существует и будет перезаписан: $MANIFEST_FILE"
    fi

    python3 - "$MANIFEST_FILE" "$SCRIPT_VERSION" "$PROFILE" "$MODE" "$ENABLE_ADDITIONAL_MEASURES" "$ENABLE_CORPORATE_PASSWORD_POLICY" <<'PYJSON'
import sys, json, datetime, pathlib
path = pathlib.Path(sys.argv[1])
data = {
    "version": sys.argv[2],
    "profile": sys.argv[3],
    "mode": sys.argv[4],
    "additional_measures_enabled": sys.argv[5] == "1",
    "corporate_password_policy_enabled": sys.argv[6] == "1",
    "timestamp": datetime.datetime.now().isoformat(),
    "backups": [],
    "pending_created_files": [],
    "created_files": [],
    "pending_created_groups": [],
    "created_groups": [],
    "pending_group_memberships": [],
    "added_group_memberships": [],
    "password_aging_snapshots": [],
    "pending_package_transactions": [],
    "installed_packages": [],
    "pending_service_transactions": [],
    "service_transactions": [],
    "modified_files": [],
    "systemd_units": [],
    "sysctl_configs": [],
    "grub_backups": [],
    "module_state": {},
    "apply_report": [],
    "warnings": [],
    "irreversible_changes": []
}
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}

write_check_report_txt() {
    if (( DRY_RUN == 1 )); then return 0; fi
    local txt_file="$STATE_DIR/check.txt"
    {
        printf "SecureLinux-NG v%s — CHECK REPORT\n" "$SCRIPT_VERSION"
        printf "Дата: %s\n" "$(date '+%F %T %z')"
        printf "Профиль: %s\n" "$PROFILE"
        printf "ОС: %s %s\n" "$DISTRO_ID" "$DISTRO_VERSION_ID"
        printf "\n"
        printf "Итого: safe=%s risky=%s warnings=%s errors=%s skipped=%s\n" \
            "${#SAFE_ITEMS[@]}" "${#RISKY_ITEMS[@]}" "${#WARNINGS[@]}" "${#ERRORS[@]}" "${#SKIPPED_ITEMS[@]}"
        printf "\n"
        if [[ ${#RISKY_ITEMS[@]} -gt 0 ]]; then
            printf "=== RISKY ===\n"
            for item in "${RISKY_ITEMS[@]}"; do printf "  [RISKY] %s\n" "$item"; done
            printf "\n"
        fi
        if [[ ${#WARNINGS[@]} -gt 0 ]]; then
            printf "=== WARNINGS ===\n"
            for item in "${WARNINGS[@]}"; do printf "  [WARN]  %s\n" "$item"; done
            printf "\n"
        fi
        if [[ ${#ERRORS[@]} -gt 0 ]]; then
            printf "=== ERRORS ===\n"
            for item in "${ERRORS[@]}"; do printf "  [ERROR] %s\n" "$item"; done
            printf "\n"
        fi
        printf "=== OK ===\n"
        for item in "${SAFE_ITEMS[@]}"; do printf "  [OK]    %s\n" "$item"; done
    } > "$txt_file"
    log "[i]     Отчёт проверки: $txt_file"
}

write_report() {
    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] создать report: $REPORT_FILE"
        return 0
    fi

    python3 - "$REPORT_FILE" "$SCRIPT_VERSION" "$PROFILE" "$MODE" "$DISTRO_ID" "$DISTRO_VERSION_ID" "$OS_FAMILY" "$IS_CONTAINER" "$IS_DESKTOP" "$HAS_DOCKER" "$HAS_PODMAN" "$HAS_K8S" "$(printf '%s
' "${SAFE_ITEMS[@]}")" "$(printf '%s
' "${RISKY_ITEMS[@]}")" "$(printf '%s
' "${SKIPPED_ITEMS[@]}")" "$(printf '%s
' "${POLICY_GATES[@]}")" "$(printf '%s
' "${WARNINGS[@]}")" "$(printf '%s
' "${ERRORS[@]}")" "$(printf '%s
' "${RESTORE_IRREVERSIBLE_CHANGES[@]}")" <<'PYJSON'
import sys, json, pathlib, datetime
path = pathlib.Path(sys.argv[1])

def split_lines(s):
    return [x for x in s.splitlines() if x.strip()]

fstec_items = [
    {"item": "2.1.1", "status": "done", "restore": "security-preserving-nonrestore", "module": "empty_password_lock"},
    {"item": "corporate_faillock", "status": "done", "restore": "managed-file", "module": "pam_faillock"},
    {"item": "corporate_password_policy", "status": "done", "restore": "managed-file+runtime-state", "module": "password_policy"},
    {"item": "audit", "status": "done", "restore": "managed-file+service+package", "module": "auditd_rules"},
    {"item": "firewall", "status": "partial", "restore": "irreversible", "module": "ufw"},
    {"item": "mount", "status": "partial", "restore": "managed-file+reboot-required", "module": "tmp_tmpfs"},
    {"item": "mount", "status": "partial", "restore": "managed-file+reboot-required", "module": "mount_hardening"},
    {"item": "kernel_modules", "status": "done", "restore": "managed-file", "module": "kernel_module_blacklist"},
    {"item": "fail2ban", "status": "done", "restore": "managed-file+service+package", "module": "fail2ban_ssh_jail"},
    {"item": "aide", "status": "partial", "restore": "irreversible", "module": "aide_init"},
    {"item": "apparmor", "status": "partial", "restore": "irreversible", "module": "apparmor_enforce"},
    {"item": "account_audit", "status": "done", "restore": "managed-file", "module": "account_audit_report"},
    {"item": "2.1.2", "status": "done", "restore": "managed-file", "module": "ssh_root_login"},
    {"item": "2.1.2", "status": "done", "restore": "managed-file", "module": "ssh_hardening_params"},
    {"item": "2.2.1", "status": "done", "restore": "managed-file+group", "module": "pam_wheel"},
    {"item": "2.2.2", "status": "done", "restore": "managed-file", "module": "sudo_policy"},
    {"item": "2.3.1", "status": "done", "restore": "metadata-snapshot", "module": "fs_critical_files"},
    {"item": "2.3.2", "status": "done", "restore": "metadata-snapshot", "module": "runtime_paths"},
    {"item": "2.3.4", "status": "done", "restore": "metadata-snapshot", "module": "sudo_command_paths"},
    {"item": "2.4.1", "status": "done", "restore": "managed-file", "module": "kernel_dmesg_restrict"},
    {"item": "2.4.2", "status": "done", "restore": "managed-file", "module": "kernel_kptr_restrict"},
    {"item": "2.4.3", "status": "partial", "restore": "grub-backup+reboot-required", "module": "grub_init_on_alloc"},
    {"item": "2.4.4", "status": "partial", "restore": "grub-backup+reboot-required", "module": "grub_slab_nomerge"},
    {"item": "2.4.5", "status": "partial", "restore": "grub-backup+reboot-required", "module": "grub_iommu_hardening"},
    {"item": "2.4.6", "status": "partial", "restore": "grub-backup+reboot-required", "module": "grub_randomize_kstack_offset"},
    {"item": "2.4.7", "status": "partial", "restore": "grub-backup+reboot-required", "module": "grub_mitigations"},
    {"item": "2.4.8", "status": "done", "restore": "managed-file", "module": "kernel_bpf_jit_harden"},
    {"item": "2.5.1", "status": "partial", "restore": "grub-backup+reboot-required", "module": "grub_vsyscall_none"},
    {"item": "2.5.2", "status": "done", "restore": "managed-file", "module": "perf_event_paranoid"},
    {"item": "2.5.3", "status": "done", "restore": "grub-backup", "module": "grub_debugfs_off"},
    {"item": "2.5.4", "status": "partial", "restore": "managed-file+reboot-required", "module": "kexec_load_disabled"},
    {"item": "2.5.6", "status": "partial", "restore": "managed-file+reboot-required", "module": "unprivileged_bpf_disabled"},
    {"item": "2.5.7", "status": "done", "restore": "managed-file", "module": "unprivileged_userfaultfd"},
    {"item": "2.5.8", "status": "done", "restore": "managed-file", "module": "tty_ldisc_autoload"},
    {"item": "2.5.9", "status": "partial", "restore": "grub-backup+reboot-required", "module": "grub_tsx_off"},
    {"item": "2.5.10", "status": "done", "restore": "managed-file", "module": "mmap_min_addr"},
    {"item": "2.5.11", "status": "done", "restore": "managed-file", "module": "randomize_va_space"},
    {"item": "2.6.1", "status": "partial", "restore": "managed-file+reboot-required", "module": "yama_ptrace_scope"},
    {"item": "2.6.2", "status": "done", "restore": "managed-file", "module": "protected_symlinks"},
    {"item": "2.6.3", "status": "done", "restore": "managed-file", "module": "protected_hardlinks"},
    {"item": "2.6.4", "status": "done", "restore": "managed-file", "module": "protected_fifos"},
    {"item": "2.6.5", "status": "done", "restore": "managed-file", "module": "protected_regular"},
    {"item": "2.5.5", "status": "done", "restore": "managed-file", "module": "user_namespaces"},
    {"item": "2.6.6", "status": "done", "restore": "managed-file", "module": "suid_dumpable"},
    {"item": "2.3.3", "status": "done", "restore": "metadata-snapshot", "module": "cron_command_paths"},
    {"item": "2.3.5", "status": "done", "restore": "metadata-snapshot", "module": "systemd_targets"},
    {"item": "2.3.6", "status": "done", "restore": "metadata-snapshot", "module": "cron_system_targets"},
    {"item": "2.3.7", "status": "done", "restore": "metadata-snapshot", "module": "user_cron_files"},
    {"item": "2.3.8", "status": "done", "restore": "metadata-snapshot", "module": "standard_system_paths"},
    {"item": "2.3.9", "status": "done", "restore": "metadata-snapshot", "module": "suid_sgid_audit"},
    {"item": "2.3.10", "status": "done", "restore": "metadata-snapshot", "module": "home_sensitive_files"},
    {"item": "2.3.11", "status": "done", "restore": "metadata-snapshot", "module": "home_directories"},
    {"item": "4.3", "status": "done", "restore": "managed-file", "module": "pam_pwhistory"},
    {"item": "17.1", "status": "done", "restore": "managed-file", "module": "account_audit_services"},
    {"item": "17.2", "status": "done", "restore": "managed-file", "module": "account_audit_ports"},
    {"item": "8.4", "status": "done", "restore": "managed-file", "module": "tcp_syncookies"},
    {"item": "8.4", "status": "done", "restore": "managed-file", "module": "icmp_echo_ignore_broadcasts"},
    {"item": "8.4", "status": "done", "restore": "managed-file", "module": "icmp_ignore_bogus_error_responses"},
    {"item": "10.6", "status": "done", "restore": "managed-file", "module": "usb_storage_blacklist"},
    {"item": "15.1", "status": "not_applicable", "restore": "none", "module": "kernel_modules_disabled"},
]

data = {
    "version": sys.argv[2],
    "profile": sys.argv[3],
    "mode": sys.argv[4],
    "timestamp": datetime.datetime.now().isoformat(),
    "environment": {
        "distro_id": sys.argv[5],
        "distro_version_id": sys.argv[6],
        "os_family": sys.argv[7],
        "is_container": sys.argv[8] == "1",
        "is_desktop": sys.argv[9] == "1",
        "has_docker": sys.argv[10] == "1",
        "has_podman": sys.argv[11] == "1",
        "has_kubernetes": sys.argv[12] == "1",
    },
    "safe": split_lines(sys.argv[13]),
    "risky": split_lines(sys.argv[14]),
    "skipped": split_lines(sys.argv[15]),
    "requires_confirmed_policy": split_lines(sys.argv[16]),
    "warnings": split_lines(sys.argv[17]),
    "errors": split_lines(sys.argv[18]),
    "irreversible_changes": split_lines(sys.argv[19]),
    "fstec_items": fstec_items,
    "fstec_summary": {
        "implemented_items": sum(1 for x in fstec_items if x["status"] != "not_applicable"),
        "partial": sum(1 for x in fstec_items if x["status"] == "partial"),
        "done": sum(1 for x in fstec_items if x["status"] == "done"),
        "restore_managed_file": sum(1 for x in fstec_items if x["restore"] == "managed-file"),
        "restore_managed_file_group": sum(1 for x in fstec_items if x["restore"] == "managed-file+group"),
        "restore_metadata_snapshot": sum(1 for x in fstec_items if x["restore"] == "metadata-snapshot"),
        "restore_policy_gated_detect_only": sum(1 for x in fstec_items if x["restore"] == "policy-gated-detect-only"),
        "restore_grub_backup_reboot_required": sum(1 for x in fstec_items if x["restore"] == "grub-backup+reboot-required"),
    },
}
import tempfile, os
tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=".manifest.tmp.")
try:
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    os.write(tmp_fd, content.encode('utf-8'))
    os.fsync(tmp_fd)
    os.close(tmp_fd)
    os.replace(tmp_path, str(path))
except Exception:
    try: os.close(tmp_fd)
    except: pass
    try: os.unlink(tmp_path)
    except: pass
    raise
PYJSON
}

print_report_stdout() {
    if (( DRY_RUN == 1 )); then
        echo "version: ${SCRIPT_VERSION}"
        echo "profile: ${PROFILE}"
        echo "mode: ${MODE}"
        echo "os: ${DISTRO_ID} ${DISTRO_VERSION_ID} (${OS_FAMILY})"
        echo "container: $([[ ${IS_CONTAINER} -eq 1 ]] && echo true || echo false)"
        echo "desktop: $([[ ${IS_DESKTOP} -eq 1 ]] && echo true || echo false)"
        echo "docker: $([[ ${HAS_DOCKER} -eq 1 ]] && echo true || echo false)"
        echo "podman: $([[ ${HAS_PODMAN} -eq 1 ]] && echo true || echo false)"
        echo "kubernetes: $([[ ${HAS_K8S} -eq 1 ]] && echo true || echo false)"
        echo "safe: ${#SAFE_ITEMS[@]}"
        echo "risky: ${#RISKY_ITEMS[@]}"
        echo "skipped: ${#SKIPPED_ITEMS[@]}"
        echo "requires_confirmed_policy: ${#POLICY_GATES[@]}"
        echo "warnings: ${#WARNINGS[@]}"
        echo "errors: ${#ERRORS[@]}"
        echo "irreversible_changes: ${#RESTORE_IRREVERSIBLE_CHANGES[@]}"
        echo "позиций в реестре: ${FSTEC_TOTAL_ITEMS} (40 пунктов ФСТЭК 25.12.2022 + 20 дополнительных мер)"
        echo "реализовано: ${FSTEC_IMPLEMENTED_ITEMS} (не считая временно отключённых)"
        echo "статус done (полная restore): ${FSTEC_DONE_ITEMS} из ${FSTEC_IMPLEMENTED_ITEMS}"
        echo "статус partial (reboot или ручные действия): ${FSTEC_PARTIAL_ITEMS} из ${FSTEC_IMPLEMENTED_ITEMS}"
        return 0
    fi

    python3 - "$REPORT_FILE" <<'PYJSON'
import sys, json, pathlib
path = pathlib.Path(sys.argv[1])
if not path.exists():
    print(f"[FAIL] report не найден: {path}")
    raise SystemExit(1)
data = json.loads(path.read_text(encoding='utf-8'))
print(f"version: {data['version']}")
print(f"profile: {data['profile']}")
print(f"mode: {data['mode']}")
env = data["environment"]
print(f"os: {env['distro_id']} {env['distro_version_id']} ({env['os_family']})")
print(f"container: {env['is_container']}")
print(f"desktop: {env['is_desktop']}")
print(f"docker: {env['has_docker']}")
print(f"podman: {env['has_podman']}")
print(f"kubernetes: {env['has_kubernetes']}")
for key in ("safe", "risky", "skipped", "requires_confirmed_policy", "warnings", "errors", "irreversible_changes"):
    print(f"{key}: {len(data.get(key, []))}")
summary = data.get("fstec_summary", {})
if summary:
    total_items = len(data.get("fstec_items", []))
    implemented = summary.get("implemented_items", 0)
    print(f"позиций в реестре: {total_items} (40 пунктов ФСТЭК 25.12.2022 + 20 дополнительных мер)")
    print(f"реализовано: {implemented} (не считая временно отключённых)")
    print(f"статус done (полная restore): {summary.get('done', 0)} из {implemented}")
    print(f"статус partial (reboot или ручные действия): {summary.get('partial', 0)} из {implemented}")
for item in data.get("risky", []):
    print(f"  [RISKY] {item}")
for item in data.get("warnings", []):
    print(f"  [WARN]  {item}")
for item in data.get("errors", []):
    print(f"  [ERROR] {item}")
PYJSON
    log "[i]     Отчёт: $REPORT_FILE"
    if [[ -f "${LOG_FILE:-}" ]]; then
        log "[i]     Лог изменений: $LOG_FILE"
    fi
    if [[ -f "${DEBUG_LOG_FILE:-}" ]]; then
        log "[i]     Технический лог: $DEBUG_LOG_FILE"
    fi
}

run_check_mode() {
    local check_output=""
    local overall_rc=0

    log "[i]     Режим check"
    run_mode_step check run_preflight run_preflight || overall_rc=1
    if ! check_output="$(check_empty_passwords_module)"; then
        add_error "check: сбой — проверка пустых паролей (check_empty_passwords_module)"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_empty_passwords_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.1.1 account: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    check_ssh_root_login_module
    if additional_measures_enabled; then
        check_ssh_hardening_module
        check_account_audit_module
        check_rsyslog_module
        check_chrony_module
        check_unattended_upgrades_module
        check_apport_module
        check_coredump_module
        check_apparmor_module
        check_aide_module
        check_fail2ban_module
        check_rkhunter_module
        check_kernel_modules_module
        check_mount_hardening_module
        check_tmp_tmpfs_module
        check_ufw_module
        check_auditd_module
    else
        add_skipped "Дополнительные меры проекта отключены: ENABLE_ADDITIONAL_MEASURES=0"
    fi
    check_pam_wheel_module
    check_faillock_module
    check_password_policy_module
    check_sudo_policy_module
    check_fs_critical_files_module
    if ! check_output="$(check_runtime_paths_module)"; then
        add_error "check: сбой — проверка runtime paths (check_runtime_paths_module)"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_runtime_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.2 runtime path: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    if ! check_output="$(check_sudo_command_paths_module)"; then
        add_error "check: сбой — проверка sudo command paths (check_sudo_command_paths_module)"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_sudo_command_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.4 sudo command path: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    if ! check_output="$(sysctl_kernel_check_module)"; then
        add_error "check: сбой — проверка базовых kernel sysctl (sysctl_kernel_check_module)"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_sysctl_kernel_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.4 sysctl key: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    if ! check_output="$(grub_kernel_params_check_module "$PROFILE")"; then
        add_error "check: сбой — проверка параметров ядра GRUB (grub_kernel_params_check_module "$PROFILE")"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_grub_kernel_params_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.4 grub kernel param: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    if ! check_output="$(sysctl_attack_surface_check_module "$PROFILE")"; then
        add_error "check: сбой — проверка sysctl attack surface (sysctl_attack_surface_check_module "$PROFILE")"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_sysctl_attack_surface_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.5 sysctl key: $a reason=$b"
                ;;
            INFO)
                add_skipped "2.5 sysctl key: $a — $b"
                ;;
        esac
    done <<< "$check_output"
    check_modules_disabled_module
    if ! check_output="$(sysctl_userspace_protection_check_module "$PROFILE")"; then
        add_error "check: сбой — проверка userspace protection sysctl (sysctl_userspace_protection_check_module "$PROFILE")"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_sysctl_userspace_protection_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.6 sysctl key: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    check_sysctl_userspace_apport_dropin
    if additional_measures_enabled; then
        if ! check_output="$(sysctl_network_check_module "$PROFILE")"; then
            add_error "check: сбой — проверка network sysctl (sysctl_network_check_module "$PROFILE")"
            check_output=""
        fi

        while IFS=$'\t' read -r kind a b c; do
            [[ -n "${kind:-}" ]] || continue
            case "$kind" in
                SUMMARY)
                    record_sysctl_network_check_results "$a" "$b" "$c"
                    ;;
                RISK)
                    add_risky "8.1-8.3 sysctl key: $a reason=$b"
                    ;;
            esac
        done <<< "$check_output"
    else
        add_skipped "8.1-8.3 дополнительные сетевые sysctl отключены: ENABLE_ADDITIONAL_MEASURES=0"
    fi
    if ! check_output="$(check_home_permissions_module)"; then
        add_error "check: сбой — проверка домашних каталогов (check_home_permissions_module)"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_home_permissions_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.10/2.3.11 target: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    if ! check_output="$(check_cron_command_paths_module)"; then
        add_error "check: сбой — проверка cron command paths (check_cron_command_paths_module)"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_cron_command_paths_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.3 target: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    if ! check_output="$(check_user_cron_permissions_module)"; then
        add_error "check: сбой — проверка пользовательских cron-файлов (check_user_cron_permissions_module)"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_user_cron_permissions_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.7 target: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    if ! check_output="$(check_standard_system_paths_module)"; then
        add_error "check: сбой — проверка стандартных системных путей (check_standard_system_paths_module)"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_standard_system_paths_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.8 target: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    if ! check_output="$(check_suid_sgid_module)"; then
        add_error "check: сбой — проверка SUID/SGID (check_suid_sgid_module)"
        check_output=""
    fi

    while IFS=$'\t' read -r kind a b c; do
        [[ -n "${kind:-}" ]] || continue
        case "$kind" in
            SUMMARY)
                record_suid_sgid_check_results "$a" "$b" "$c"
                ;;
            RISK)
                add_risky "2.3.9 target: $a reason=$b"
                ;;
        esac
    done <<< "$check_output"
    check_cron_targets_module
    check_systemd_unit_targets_module
    run_mode_step check ensure_state_dir ensure_state_dir || overall_rc=1
    run_mode_step check write_check_report_txt write_check_report_txt || overall_rc=1
    run_mode_step check write_report write_report || overall_rc=1
    run_mode_step check print_report_stdout print_report_stdout || overall_rc=1
    if (( ${#ERRORS[@]} > 0 || overall_rc != 0 )); then
        log "[ERROR] check завершён с errors=${#ERRORS[@]} overall_rc=$overall_rc"
        return 1
    fi

    return 0
}


apply_rsyslog_module() {
    local service_rc=0

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install rsyslog, enable service"
        add_skipped "rsyslog dry-run: would install and enable"
        return 0
    fi

    if ! prepare_systemd_service_transaction \
        "rsyslog" \
        "rsyslog.service" \
        "enable-now"
    then
        return 1
    fi

    log "[i]     rsyslog: установка пакета..."
    apt_update_once
    if ! pkg_installed rsyslog; then
        install_packages_transactionally "rsyslog" rsyslog || true

        if (( PACKAGE_TRANSACTION_TRACKING_RC != 0 )); then
            add_error "rsyslog: package transaction не зафиксирована"
            record_manifest_warning "rsyslog: package transaction tracking failed"
            return 1
        fi

        if (( PACKAGE_TRANSACTION_INSTALL_RC != 0 )); then
            add_error "rsyslog: не удалось установить пакет"
            record_manifest_warning "rsyslog: apt-get install failed"
            return 1
        fi
    fi

    systemctl enable --now rsyslog.service \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || service_rc=$?

    if ! commit_systemd_service_transaction \
        "rsyslog" \
        "rsyslog.service"
    then
        return 1
    fi

    if (( service_rc != 0 )); then
        add_error "rsyslog: пакет установлен, но запуск/enable службы не удался"
        record_manifest_warning "rsyslog: systemctl enable --now failed"
        return 1
    fi

    record_manifest_apply_report "rsyslog: установлен и включён"
    add_safe "rsyslog: служба активна"
}

restore_rsyslog_module() {
    local rc=0

    if ! restore_systemd_service_transaction \
        "rsyslog" \
        "rsyslog.service" \
        "rsyslog"
    then
        rc=1
    fi

    if ! report_installed_packages_for_manual_restore \
        "rsyslog" \
        "rsyslog"
    then
        rc=1
    fi

    log "[i]     restore rsyslog: service-state восстановлен; пакет не удаляется автоматически"
    return "$rc"
}

check_rsyslog_module() {
    if ! command -v rsyslogd >/dev/null 2>&1; then
        add_risky "rsyslog: не установлен"
        return 0
    fi
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        add_safe "rsyslog: служба активна"
    else
        add_risky "rsyslog: служба не активна"
    fi
}

apply_chrony_module() {
    local service_rc=0

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install chrony, enable service"
        add_skipped "chrony dry-run: would install and enable"
        return 0
    fi

    if ! prepare_systemd_service_transaction \
        "chrony" \
        "chrony.service" \
        "enable-now"
    then
        return 1
    fi

    log "[i]     chrony: установка пакета..."
    apt_update_once
    if ! pkg_installed chrony; then
        install_packages_transactionally "chrony" chrony || true

        if (( PACKAGE_TRANSACTION_TRACKING_RC != 0 )); then
            add_error "chrony: package transaction не зафиксирована"
            record_manifest_warning "chrony: package transaction tracking failed"
            return 1
        fi

        if (( PACKAGE_TRANSACTION_INSTALL_RC != 0 )); then
            add_error "chrony: не удалось установить пакет"
            record_manifest_warning "chrony: apt-get install failed"
            return 1
        fi
    fi

    systemctl enable --now chrony.service \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || service_rc=$?

    if ! commit_systemd_service_transaction \
        "chrony" \
        "chrony.service"
    then
        return 1
    fi

    if (( service_rc != 0 )); then
        add_error "chrony: пакет установлен, но запуск/enable службы не удался"
        record_manifest_warning "chrony: systemctl enable --now failed"
        return 1
    fi

    record_manifest_apply_report "chrony: установлен и включён"
    add_safe "chrony: служба синхронизации времени активна"
}

restore_chrony_module() {
    local rc=0

    if ! restore_systemd_service_transaction \
        "chrony" \
        "chrony.service" \
        "chrony"
    then
        rc=1
    fi

    if ! report_installed_packages_for_manual_restore \
        "chrony" \
        "chrony"
    then
        rc=1
    fi

    log "[i]     restore chrony: service-state восстановлен; пакет не удаляется автоматически"
    return "$rc"
}

check_chrony_module() {
    if ! command -v chronyd >/dev/null 2>&1; then
        add_risky "chrony: не установлен"
        return 0
    fi
    if systemctl is-active --quiet chrony 2>/dev/null; then
        add_safe "chrony: служба активна"
    else
        add_risky "chrony: служба не активна"
    fi
}

apply_unattended_upgrades_module() {
    local service_rc=0

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] install unattended-upgrades, enable service"
        add_skipped "unattended-upgrades dry-run: would install and enable"
        return 0
    fi

    if ! prepare_systemd_service_transaction \
        "unattended-upgrades" \
        "unattended-upgrades.service" \
        "enable-now"
    then
        return 1
    fi

    log "[i]     unattended-upgrades: установка пакета..."
    apt_update_once
    if ! pkg_installed unattended-upgrades; then
        install_packages_transactionally \
            "unattended-upgrades" \
            unattended-upgrades || true

        if (( PACKAGE_TRANSACTION_TRACKING_RC != 0 )); then
            add_error "unattended-upgrades: package transaction не зафиксирована"
            record_manifest_warning "unattended-upgrades: package transaction tracking failed"
            return 1
        fi

        if (( PACKAGE_TRANSACTION_INSTALL_RC != 0 )); then
            add_error "unattended-upgrades: не удалось установить пакет"
            record_manifest_warning "unattended-upgrades: apt-get install failed"
            return 1
        fi
    fi

    systemctl enable --now unattended-upgrades.service \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 || service_rc=$?

    if ! commit_systemd_service_transaction \
        "unattended-upgrades" \
        "unattended-upgrades.service"
    then
        return 1
    fi

    if (( service_rc != 0 )); then
        add_error "unattended-upgrades: пакет установлен, но запуск/enable службы не удался"
        record_manifest_warning "unattended-upgrades: systemctl enable --now failed"
        return 1
    fi

    record_manifest_apply_report "unattended-upgrades: установлен и включён"
    add_safe "unattended-upgrades: автообновления безопасности активны"
}

apply_apport_module() {
    local service_rc=0

    if (( DRY_RUN == 1 )); then
        log "[DRY-RUN] disable apport (supplementary coredump/crash-reporting measure)"
        add_skipped "apport dry-run: would disable service"
        return 0
    fi

    if ! command -v apport >/dev/null 2>&1 \
        && ! systemctl list-unit-files apport.service >/dev/null 2>&1
    then
        add_safe "apport: служба не обнаружена"
        return 0
    fi

    if ! prepare_systemd_service_transaction \
        "apport" \
        "apport.service" \
        "disable-now"
    then
        return 1
    fi

    systemctl disable --now apport.service \
        >/dev/null 2>&1 || service_rc=$?

    if ! commit_systemd_service_transaction \
        "apport" \
        "apport.service"
    then
        return 1
    fi

    if (( service_rc != 0 )); then
        add_error "apport: не удалось отключить службу"
        record_manifest_warning "apport: systemctl disable --now failed"
        return 1
    fi

    record_manifest_apply_report \
        "apport: отключён (дополнительная мера; crash-reporting выключен)"
    add_safe "apport: отключён (конфликтовал с fs.suid_dumpable=0)"
}

restore_apport_module() {
    local rc=0
    local had_apport_apply=""

    if ! restore_systemd_service_transaction \
        "apport" \
        "apport.service" \
        "apport"
    then
        return 1
    fi

    if (( SERVICE_TRANSACTION_FOUND == 1 )); then
        return 0
    fi

    if ! had_apport_apply="$(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
if not mf.exists():
    print("0")
    raise SystemExit(0)
data = json.loads(mf.read_text(encoding='utf-8'))
for item in data.get("apply_report", []):
    if isinstance(item, str) and item.startswith("apport: отключён"):
        print("1")
        raise SystemExit(0)
print("0")
PYJSON
)"; then
        add_error "restore apport: не удалось прочитать legacy manifest"
        return 1
    fi

    if [[ "$had_apport_apply" == "1" ]]; then
        add_warning \
            "restore apport: legacy manifest не содержит typed service-state; включите вручную при необходимости: systemctl enable --now apport.service"
    fi

    return "$rc"
}

check_coredump_module() {
    local ok=1
    [[ -f "$COREDUMP_LIMITS_FILE" ]] || { add_risky "7.6 coredump: отсутствует $COREDUMP_LIMITS_FILE"; ok=0; }
    [[ -f "$COREDUMP_SYSTEMD_FILE" ]] || { add_risky "7.6 coredump: отсутствует $COREDUMP_SYSTEMD_FILE"; ok=0; }
    local core_pattern
    core_pattern="$(sysctl -n kernel.core_pattern 2>/dev/null || echo "")"
    if [[ "$core_pattern" != "|/bin/false" ]]; then
        add_risky "7.6 coredump: kernel.core_pattern='${core_pattern}' (ожидается '|/bin/false')"
        ok=0
    fi
    (( ok == 1 )) && add_safe "7.6 coredump: конфигурация присутствует"
}

record_coredump_runtime_pre_state() {
    local previous_runtime="$1"
    local prefix="7.6 coredump pre-runtime kernel.core_pattern: "

    (( DRY_RUN == 1 )) && return 0

    if [[ "$previous_runtime" == *$'\n'* \
        || "$previous_runtime" == *$'\r'* ]]
    then
        add_error \
            "7.6 coredump: прежнее runtime-значение содержит перевод строки"
        return 1
    fi

    if [[ -z "${MANIFEST_FILE:-}" \
        || ! -f "${MANIFEST_FILE:-}" ]]
    then
        add_error \
            "7.6 coredump: manifest недоступен при записи прежнего runtime-состояния"
        return 1
    fi

    if ! python3 - \
        "$MANIFEST_FILE" \
        "$prefix" \
        "$previous_runtime" \
        2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import os
import pathlib
import sys
import tempfile

path = pathlib.Path(sys.argv[1])
prefix = sys.argv[2]
previous_runtime = sys.argv[3]
value = prefix + previous_runtime

data = json.loads(
    path.read_text(encoding="utf-8")
)

if not isinstance(data, dict):
    raise ValueError("manifest root is not an object")

apply_report = data.setdefault("apply_report", [])

if not isinstance(apply_report, list):
    raise ValueError("manifest apply_report is not an array")

for entry in apply_report:
    if not isinstance(entry, str):
        raise ValueError(
            "manifest apply_report entry is not a string"
        )

matches = [
    entry
    for entry in apply_report
    if entry.startswith(prefix)
]

if len(matches) > 1:
    raise ValueError(
        "multiple coredump runtime pre-state records exist"
    )

if matches:
    if matches[0] != value:
        raise ValueError(
            "conflicting coredump runtime pre-state record exists"
        )

    raise SystemExit(0)

apply_report.append(value)

fd, temporary = tempfile.mkstemp(
    dir=str(path.parent),
    prefix=".manifest.tmp.",
)

try:
    content = (
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    os.write(fd, content)
    os.fsync(fd)
    os.close(fd)
    fd = -1
    os.replace(temporary, path)
except Exception:
    if fd >= 0:
        try:
            os.close(fd)
        except OSError:
            pass

    try:
        os.unlink(temporary)
    except OSError:
        pass

    raise
PYJSON
    then
        add_error \
            "7.6 coredump: не удалось записать прежнее runtime-состояние в manifest"
        return 1
    fi

    return 0
}

apply_coredump_module() {
    local coredump_sysctl="/etc/sysctl.d/98-securelinux-ng-coredump.conf"
    local coredump_runtime_before=""
    local bak=""
    local bak2=""
    local bak3=""
    local existed=0
    local existed2=0
    local existed3=0
    local coredump_live_ok=0

    if (( DRY_RUN == 1 )); then
        add_skipped \
            "7.6 coredump dry-run: would configure limits.d and systemd coredump.conf"
        return 0
    fi

    if [[ -z "${MANIFEST_FILE:-}" \
        || ! -f "${MANIFEST_FILE:-}" ]]
    then
        add_error \
            "7.6 coredump apply skipped: manifest недоступен"
        return 1
    fi

    if ! coredump_runtime_before="$(
        sysctl -n kernel.core_pattern \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
    )"
    then
        add_error \
            "7.6 coredump: не удалось сохранить прежнее runtime-значение kernel.core_pattern"
        return 1
    fi

    if ! record_coredump_runtime_pre_state \
        "$coredump_runtime_before"
    then
        add_skipped \
            "7.6 coredump apply skipped: прежнее runtime-состояние не записано"
        return 1
    fi

    if ! mkdir -p \
        /etc/security/limits.d \
        "$COREDUMP_SYSTEMD_DIR"
    then
        add_error \
            "7.6 coredump: не удалось создать каталоги конфигурации"
        return 1
    fi

    if [[ -e "$COREDUMP_LIMITS_FILE" || -L "$COREDUMP_LIMITS_FILE" ]]; then
        bak="$STATE_DIR/$(basename "$COREDUMP_LIMITS_FILE").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$COREDUMP_LIMITS_FILE" \
            "$bak" \
            "7.6 coredump limits"
        then
            add_skipped \
                "7.6 coredump apply skipped: limits backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$COREDUMP_LIMITS_FILE" \
            "$bak"
        then
            add_error \
                "7.6 coredump apply skipped: limits backup mapping не записан"

            if ! rm -f -- "$bak"; then
                add_warning \
                    "7.6 coredump: не удалось удалить незарегистрированный backup $bak"
            fi

            return 1
        fi
    fi

    if [[ -e "$COREDUMP_SYSTEMD_FILE" || -L "$COREDUMP_SYSTEMD_FILE" ]]; then
        bak2="$STATE_DIR/$(basename "$COREDUMP_SYSTEMD_FILE").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$COREDUMP_SYSTEMD_FILE" \
            "$bak2" \
            "7.6 coredump systemd"
        then
            add_skipped \
                "7.6 coredump apply skipped: systemd backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$COREDUMP_SYSTEMD_FILE" \
            "$bak2"
        then
            add_error \
                "7.6 coredump apply skipped: systemd backup mapping не записан"

            if ! rm -f -- "$bak2"; then
                add_warning \
                    "7.6 coredump: не удалось удалить незарегистрированный backup $bak2"
            fi

            return 1
        fi
    fi

    if [[ -e "$coredump_sysctl" || -L "$coredump_sysctl" ]]; then
        bak3="$STATE_DIR/$(basename "$coredump_sysctl").bak-$TIMESTAMP"

        if ! backup_file_checked \
            "$coredump_sysctl" \
            "$bak3" \
            "7.6 coredump sysctl"
        then
            add_skipped \
                "7.6 coredump apply skipped: sysctl backup failed"
            return 1
        fi

        if ! record_manifest_backup \
            "$coredump_sysctl" \
            "$bak3"
        then
            add_error \
                "7.6 coredump apply skipped: sysctl backup mapping не записан"

            if ! rm -f -- "$bak3"; then
                add_warning \
                    "7.6 coredump: не удалось удалить незарегистрированный backup $bak3"
            fi

            return 1
        fi
    fi

    [[ -e "$COREDUMP_LIMITS_FILE" || -L "$COREDUMP_LIMITS_FILE" ]] \
        && existed=1 \
        || true

    if ! prepare_created_file_transaction \
        "$COREDUMP_LIMITS_FILE" \
        "$existed" \
        "7.6 coredump limits"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$COREDUMP_LIMITS_FILE" \
        0644 \
        printf '%s\n' \
        '# Managed by SecureLinux-NG' \
        '* hard core 0' \
        '* soft core 0'
    then
        add_error \
            "7.6 coredump: не удалось записать $COREDUMP_LIMITS_FILE"

        if (( existed == 0 )); then
            rm -f -- "$COREDUMP_LIMITS_FILE" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 \
                || true
        fi

        return 1
    fi

    if (( existed == 0 )); then
        if ! record_manifest_created_file \
            "$COREDUMP_LIMITS_FILE" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "7.6 coredump: созданный limits-файл не записан в manifest"

            if ! rm -f -- "$COREDUMP_LIMITS_FILE"; then
                add_warning \
                    "7.6 coredump: не удалось удалить незарегистрированный файл $COREDUMP_LIMITS_FILE"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$COREDUMP_LIMITS_FILE"

    [[ -e "$COREDUMP_SYSTEMD_FILE" || -L "$COREDUMP_SYSTEMD_FILE" ]] \
        && existed2=1 \
        || true

    if ! prepare_created_file_transaction \
        "$COREDUMP_SYSTEMD_FILE" \
        "$existed2" \
        "7.6 coredump systemd"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$COREDUMP_SYSTEMD_FILE" \
        0644 \
        printf '%s\n' \
        '# Managed by SecureLinux-NG' \
        '[Coredump]' \
        'Storage=none' \
        'ProcessSizeMax=0'
    then
        add_error \
            "7.6 coredump: не удалось записать $COREDUMP_SYSTEMD_FILE"

        if (( existed2 == 0 )); then
            rm -f -- "$COREDUMP_SYSTEMD_FILE" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 \
                || true
        fi

        return 1
    fi

    if (( existed2 == 0 )); then
        if ! record_manifest_created_file \
            "$COREDUMP_SYSTEMD_FILE" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "7.6 coredump: созданный systemd-файл не записан в manifest"

            if ! rm -f -- "$COREDUMP_SYSTEMD_FILE"; then
                add_warning \
                    "7.6 coredump: не удалось удалить незарегистрированный файл $COREDUMP_SYSTEMD_FILE"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$COREDUMP_SYSTEMD_FILE"

    [[ -e "$coredump_sysctl" || -L "$coredump_sysctl" ]] \
        && existed3=1 \
        || true

    if ! prepare_created_file_transaction \
        "$coredump_sysctl" \
        "$existed3" \
        "7.6 coredump sysctl"
    then
        return 1
    fi

    if ! atomic_write_command_output \
        "$coredump_sysctl" \
        0644 \
        printf '%s\n' \
        '# Managed by SecureLinux-NG' \
        'kernel.core_pattern = |/bin/false'
    then
        add_error \
            "7.6 coredump: не удалось записать $coredump_sysctl"

        if (( existed3 == 0 )); then
            rm -f -- "$coredump_sysctl" \
                >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1 \
                || true
        fi

        return 1
    fi

    if (( existed3 == 0 )); then
        if ! record_manifest_created_file \
            "$coredump_sysctl" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}"
        then
            add_error \
                "7.6 coredump: созданный sysctl-файл не записан в manifest"

            if ! rm -f -- "$coredump_sysctl"; then
                add_warning \
                    "7.6 coredump: не удалось удалить незарегистрированный файл $coredump_sysctl"
            fi

            return 1
        fi
    fi

    record_manifest_modified_file_best_effort \
        "$coredump_sysctl"

    if sysctl -w kernel.core_pattern="|/bin/false" \
        >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
    then
        coredump_live_ok=1
    fi

    record_manifest_apply_report \
        "7.6 coredump: limits.d, systemd coredump.conf and kernel.core_pattern configured"

    if (( coredump_live_ok == 1 )); then
        add_safe \
            "7.6 coredump: отключён через limits.d, systemd/coredump.conf и kernel.core_pattern"
        return 0
    fi

    add_warning \
        "7.6 coredump: файлы записаны, но live-применение kernel.core_pattern не удалось"
    record_manifest_warning \
        "7.6 coredump: sysctl -w kernel.core_pattern failed"

    return 1
}

restore_coredump_module() {
    local coredump_sysctl="/etc/sysctl.d/98-securelinux-ng-coredump.conf"
    local previous_runtime=""
    local runtime_snapshot_output=""
    local runtime_snapshot_state=""
    local runtime_snapshot_found=0
    local sysctl_restore_ok=1
    local rc=0

    if [[ -z "${RESTORE_SOURCE_MANIFEST:-}" \
        || ! -f "${RESTORE_SOURCE_MANIFEST:-}" ]]
    then
        add_error \
            "restore coredump: source manifest недоступен"
        return 1
    fi

    if ! runtime_snapshot_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
prefix = "7.6 coredump pre-runtime kernel.core_pattern: "

try:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("manifest root is not an object")

    apply_report = data.get("apply_report", [])

    if not isinstance(apply_report, list):
        raise ValueError("manifest apply_report is not an array")

    for entry in apply_report:
        if not isinstance(entry, str):
            raise ValueError(
                "manifest apply_report entry is not a string"
            )

    previous_runtime = None

    for entry in apply_report:
        if entry.startswith(prefix):
            previous_runtime = entry[len(prefix):]
            break

    if previous_runtime is None:
        print("0")
    else:
        print("1")
        print(previous_runtime)
except Exception as exc:
    print(
        f"restore coredump manifest read failed: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(2)
PYJSON
    )"; then
        add_error \
            "restore coredump: не удалось прочитать runtime-состояние из manifest"
        return 1
    fi

    runtime_snapshot_state="$runtime_snapshot_output"

    if [[ "$runtime_snapshot_output" == *$'\n'* ]]; then
        runtime_snapshot_state="${runtime_snapshot_output%%$'\n'*}"
    fi

    case "$runtime_snapshot_state" in
        0)
            ;;
        1)
            runtime_snapshot_found=1

            if [[ "$runtime_snapshot_output" == *$'\n'* ]]; then
                previous_runtime="${runtime_snapshot_output#*$'\n'}"
            fi
            ;;
        *)
            add_error \
                "restore coredump: получен некорректный результат чтения runtime-состояния"
            return 1
            ;;
    esac

    if ! restore_file_from_manifest "$COREDUMP_LIMITS_FILE"; then
        rc=1
    fi

    if ! restore_file_from_manifest "$COREDUMP_SYSTEMD_FILE"; then
        rc=1
    fi

    if ! restore_file_from_manifest "$coredump_sysctl"; then
        rc=1
        sysctl_restore_ok=0
    fi

    if (( runtime_snapshot_found == 1 )); then
        if sysctl -w "kernel.core_pattern=$previous_runtime" \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            log \
                "[i]     restore coredump: runtime kernel.core_pattern восстановлен"
        else
            add_warning \
                "restore coredump: не удалось восстановить runtime kernel.core_pattern"
            rc=1
        fi
    elif (( sysctl_restore_ok == 0 )); then
        add_warning \
            "restore coredump: runtime fallback пропущен из-за ошибки восстановления $coredump_sysctl"
    elif [[ -f "$coredump_sysctl" ]]; then
        if ! sysctl -p "$coredump_sysctl" \
            >>"${DEBUG_LOG_FILE:-/dev/null}" 2>&1
        then
            add_warning \
                "restore coredump: sysctl -p failed for $coredump_sysctl"
            rc=1
        fi
    else
        add_warning \
            "restore coredump: прежнее runtime-значение kernel.core_pattern отсутствует в manifest и fallback-файл недоступен"
        rc=1
    fi

    return "$rc"
}

check_apport_module() {
    if systemctl is-active --quiet apport 2>/dev/null; then
        add_risky "apport: служба активна — crash-reporting должен быть отключён"
    else
        add_safe "apport: служба неактивна"
    fi
}
restore_unattended_upgrades_module() {
    local rc=0

    if ! restore_systemd_service_transaction \
        "unattended-upgrades" \
        "unattended-upgrades.service" \
        "unattended-upgrades"
    then
        rc=1
    fi

    if ! report_installed_packages_for_manual_restore \
        "unattended-upgrades" \
        "unattended-upgrades"
    then
        rc=1
    fi

    log "[i]     restore unattended-upgrades: service-state восстановлен; пакет не удаляется автоматически"
    return "$rc"
}

restore_empty_passwords_module() {
    local backup=""
    local state_rc=0

    backup="$(restore_manifest_empty_password_state)"
    state_rc=$?

    case "$state_rc" in
        0)
            if [[ ! -f "$backup" ]]; then
                add_error \
                    "restore 2.1.1: typed state ссылается на отсутствующий список: $backup"
                return 1
            fi
            ;;
        1)
            log "[i]     restore 2.1.1: пустые поля пароля не изменялись — пропуск"
            return 0
            ;;
        3)
            if ! backup="$(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import json
import pathlib
import sys

manifest = pathlib.Path(sys.argv[1])
data = json.loads(manifest.read_text(encoding="utf-8"))

for entry in data.get("backups", []):
    if not isinstance(entry, dict):
        continue

    original = str(entry.get("original", ""))
    backup = str(entry.get("backup", ""))

    if (
        original == "/etc/shadow"
        and "empty-password-users-" in pathlib.Path(backup).name
    ):
        print(backup)
        break
PYJSON
)"; then
                add_error "restore 2.1.1: не удалось прочитать legacy manifest"
                return 1
            fi

            if [[ -z "$backup" || ! -f "$backup" ]]; then
                log "[i]     restore 2.1.1: legacy state отсутствует — пропуск"
                return 0
            fi

            add_warning \
                "restore 2.1.1: используется legacy backup-запись empty-password users"
            ;;
        *)
            add_error \
                "restore 2.1.1: не удалось прочитать typed empty-password state"
            return 1
            ;;
    esac

    log "[i]     restore 2.1.1: восстановление пустых полей пароля запрещено по соображениям безопасности — пропуск"
    add_warning \
        "restore 2.1.1: пустые поля пароля не восстанавливаются; список учётных записей сохранён: $backup"

    return 0
}

restore_runtime_paths_module() {
    local modified
    local modified_output=""
    local rc=0

    if ! modified_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/runtime." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
    )"; then
        add_error "restore runtime paths: не удалось прочитать manifest"
        return 1
    fi

    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        if ! restore_metadata_from_stat_snapshot "$modified"; then
            rc=1
        fi
    done <<< "$modified_output"

    return "$rc"
}

restore_home_permissions_module() {
    local modified
    local modified_output=""
    local rc=0

    if ! modified_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and any(x in e.get("backup", "") for x in [".home.meta-", ".meta-"]) and "/home/" in e.get("original", ""):
        print(e.get("original", ""))
PYJSON
    )"; then
        add_error "restore home permissions: не удалось прочитать manifest"
        return 1
    fi

    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        if ! restore_metadata_from_stat_snapshot "$modified"; then
            rc=1
        fi
    done <<< "$modified_output"

    return "$rc"
}

restore_suid_sgid_module() {
    local modified
    local modified_output=""
    local rc=0

    if ! modified_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/suid." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
    )"; then
        add_error "restore SUID/SGID: не удалось прочитать manifest"
        return 1
    fi

    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        if ! restore_metadata_from_stat_snapshot "$modified"; then
            rc=1
        fi
    done <<< "$modified_output"

    return "$rc"
}

restore_cron_command_paths_module() {
    local modified
    local modified_output=""
    local rc=0

    if ! modified_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/cron_cmd." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
    )"; then
        add_error "restore cron command paths: не удалось прочитать manifest"
        return 1
    fi

    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        if ! restore_metadata_from_stat_snapshot "$modified"; then
            rc=1
        fi
    done <<< "$modified_output"

    return "$rc"
}

restore_standard_system_paths_module() {
    local modified
    local modified_output=""
    local rc=0

    if ! modified_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/syspath." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
    )"; then
        add_error "restore standard system paths: не удалось прочитать manifest"
        return 1
    fi

    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        if ! restore_metadata_from_stat_snapshot "$modified"; then
            rc=1
        fi
    done <<< "$modified_output"

    return "$rc"
}

restore_sudo_command_paths_module() {
    local modified
    local modified_output=""
    local rc=0

    if ! modified_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/sudo_cmd." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
    )"; then
        add_error "restore sudo command paths: не удалось прочитать manifest"
        return 1
    fi

    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        if ! restore_metadata_from_stat_snapshot "$modified"; then
            rc=1
        fi
    done <<< "$modified_output"

    return "$rc"
}

restore_user_cron_permissions_module() {
    local modified
    local modified_output=""
    local rc=0

    if ! modified_output="$(
        python3 - "$RESTORE_SOURCE_MANIFEST" \
            2>>"${DEBUG_LOG_FILE:-/dev/null}" <<'PYJSON'
import sys, json, pathlib
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
for e in data.get("backups", []):
    if isinstance(e, dict) and "/cronuser." in e.get("backup", ""):
        print(e.get("original", ""))
PYJSON
    )"; then
        add_error "restore user cron permissions: не удалось прочитать manifest"
        return 1
    fi

    while IFS= read -r modified; do
        [[ -n "$modified" ]] || continue
        if ! restore_metadata_from_stat_snapshot "$modified"; then
            rc=1
        fi
    done <<< "$modified_output"

    return "$rc"
}

restore_grub_kernel_params_module() {
    restore_grub_module
}


check_unattended_upgrades_module() {
    if ! dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null | grep -q "install ok installed"; then
        add_risky "unattended-upgrades: не установлен"
        return 0
    fi
    if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
        add_safe "unattended-upgrades: автоматические обновления включены"
    else
        add_risky "unattended-upgrades: автоматические обновления не включены"
    fi
}

run_mode_step() {
    local mode_name="$1"
    local step_name="$2"
    shift 2
    local errors_before=${#ERRORS[@]}
    local step_rc=0

    "$@" || step_rc=$?

    if (( step_rc == 0 )); then
        return 0
    fi

    if (( ${#ERRORS[@]} == errors_before )); then
        add_error "$mode_name: сбой шага $step_name (RC=$step_rc)"
    fi

    return "$step_rc"
}


run_apply_mode() {
    local overall_rc=0
    log "[i]     Режим apply"
    run_preflight
    check_memory_requirements
    if ! ensure_state_dir; then
        return 1
    fi
    acquire_run_lock
    if (( DRY_RUN == 0 )); then
        log "[i]     Лог сохраняется: $LOG_FILE"
        log_debug "=== SecureLinux-NG $SCRIPT_VERSION apply start ==="
        log_debug "profile=$PROFILE os=$DISTRO_ID $DISTRO_VERSION_ID"
    fi
    if [[ -f "$MANIFEST_FILE" ]] && (( DRY_RUN == 0 )); then
        log ""
        log "[WARN]  Обнаружен существующий manifest: $MANIFEST_FILE"
        log "[WARN]  Повторный --apply без предварительного --restore перезапишет manifest."
        log "[WARN]  После этого --restore не сможет корректно откатить изменения."
        log ""
        log "[?]     Продолжить? (yes/no)"
        local _ans
        local _apply_tty_fd

        if ! exec {_apply_tty_fd}<>/dev/tty 2>/dev/null; then
            log "[i]     Терминал недоступен — повторный --apply прерван. Выполните --restore перед повторным --apply."
            return 2
        fi

        if ! printf '    Ваш ответ [yes/no]: ' >&"$_apply_tty_fd" \
           || ! IFS= read -r _ans <&"$_apply_tty_fd"
        then
            exec {_apply_tty_fd}>&-
            log "[i]     Не удалось прочитать подтверждение с терминала — повторный --apply прерван."
            return 2
        fi

        exec {_apply_tty_fd}>&-

        if [[ "$_ans" != "yes" && "$_ans" != "y" ]]; then
            log "[i]     Прервано администратором. Выполните --restore перед повторным --apply."
            return 2
        fi
        log "[WARN]  Продолжение по явному подтверждению администратора."
        local _archive="${MANIFEST_FILE}.bak-${TIMESTAMP}"
        mv "$MANIFEST_FILE" "$_archive" && \
            log "[i]     Существующий manifest архивирован: $_archive" || \
            die "Не удалось архивировать существующий manifest: $MANIFEST_FILE"
    fi
    if ! manifest_init; then
        add_error "apply: инициализация manifest завершилась ошибкой: $MANIFEST_FILE"
        return 1
    fi

    run_mode_step apply apply_empty_passwords_module apply_empty_passwords_module || overall_rc=1
    run_mode_step apply apply_ssh_root_login_module apply_ssh_root_login_module || overall_rc=1
    if additional_measures_enabled; then
        run_mode_step apply apply_ssh_hardening_module apply_ssh_hardening_module || overall_rc=1
        run_mode_step apply apply_account_audit_module apply_account_audit_module || overall_rc=1
        run_mode_step apply apply_apparmor_module apply_apparmor_module || overall_rc=1
        run_mode_step apply apply_aide_module apply_aide_module || overall_rc=1
        run_mode_step apply apply_fail2ban_module apply_fail2ban_module || overall_rc=1
        run_mode_step apply apply_rkhunter_module apply_rkhunter_module || overall_rc=1
        run_mode_step apply apply_kernel_modules_module apply_kernel_modules_module || overall_rc=1
        run_mode_step apply apply_mount_hardening_module apply_mount_hardening_module || overall_rc=1
        run_mode_step apply apply_tmp_tmpfs_module apply_tmp_tmpfs_module || overall_rc=1
        run_mode_step apply apply_ufw_module apply_ufw_module || overall_rc=1
        run_mode_step apply apply_auditd_module apply_auditd_module || overall_rc=1
        run_mode_step apply apply_rsyslog_module apply_rsyslog_module || overall_rc=1
        run_mode_step apply apply_chrony_module apply_chrony_module || overall_rc=1
        run_mode_step apply apply_unattended_upgrades_module apply_unattended_upgrades_module || overall_rc=1
        run_mode_step apply apply_coredump_module apply_coredump_module || overall_rc=1
        run_mode_step apply apply_sysctl_network_module apply_sysctl_network_module || overall_rc=1
    else
        add_skipped "Дополнительные меры проекта отключены: ENABLE_ADDITIONAL_MEASURES=0"
    fi
    run_mode_step apply apply_pam_wheel_module apply_pam_wheel_module || overall_rc=1
    run_mode_step apply apply_faillock_module apply_faillock_module || overall_rc=1
    run_mode_step apply apply_password_policy_module apply_password_policy_module || overall_rc=1
    run_mode_step apply apply_sudo_policy_module apply_sudo_policy_module || overall_rc=1
    run_mode_step apply apply_fs_critical_files_module apply_fs_critical_files_module || overall_rc=1
    run_mode_step apply apply_runtime_paths_module apply_runtime_paths_module || overall_rc=1
    run_mode_step apply apply_sudo_command_paths_module apply_sudo_command_paths_module || overall_rc=1
    run_mode_step apply apply_sysctl_kernel_module apply_sysctl_kernel_module || overall_rc=1
    run_mode_step apply apply_grub_kernel_params_module apply_grub_kernel_params_module || overall_rc=1
    run_mode_step apply apply_sysctl_attack_surface_module apply_sysctl_attack_surface_module || overall_rc=1
    run_mode_step apply apply_sysctl_userspace_protection_module apply_sysctl_userspace_protection_module || overall_rc=1
    # Apport --stop изменяет fs.suid_dumpable=0. Отключаем его только
    # после userspace runtime snapshot, чтобы restore сохранил исходное
    # значение, например Ubuntu 24.04 default fs.suid_dumpable=2.
    if additional_measures_enabled; then
        run_mode_step apply apply_apport_module apply_apport_module || overall_rc=1
    fi
    run_mode_step apply apply_home_permissions_module apply_home_permissions_module || overall_rc=1
    run_mode_step apply apply_cron_command_paths_module apply_cron_command_paths_module || overall_rc=1
    run_mode_step apply apply_user_cron_permissions_module apply_user_cron_permissions_module || overall_rc=1
    run_mode_step apply apply_standard_system_paths_module apply_standard_system_paths_module || overall_rc=1
    run_mode_step apply apply_suid_sgid_module apply_suid_sgid_module || overall_rc=1
    run_mode_step apply apply_cron_targets_module apply_cron_targets_module || overall_rc=1
    run_mode_step apply apply_systemd_unit_targets_module apply_systemd_unit_targets_module || overall_rc=1
    run_mode_step apply apply_modules_disabled_module apply_modules_disabled_module || overall_rc=1
    run_mode_step apply write_report write_report || overall_rc=1
    run_mode_step apply print_report_stdout print_report_stdout || overall_rc=1
    if (( ${#ERRORS[@]} > 0 || overall_rc != 0 )); then
        log "[ERROR] apply завершён с errors=${#ERRORS[@]} overall_rc=$overall_rc"
        return 1
    fi

    return 0
}

run_restore_mode() {
    local overall_rc=0
    log "[i]     Режим restore"
    run_preflight
    resolve_restore_manifest
    if ! ensure_state_dir; then
        return 1
    fi
    acquire_run_lock
    local restore_additional_measures=1

    if [[ -f "$RESTORE_SOURCE_MANIFEST" ]]; then
        if ! PROFILE="$(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
data = json.loads(mf.read_text(encoding='utf-8'))
print(data.get("profile", "baseline"))
PYJSON
)"; then
            add_error "restore: не удалось прочитать profile из manifest"
            return 1
        fi
        [[ "$PROFILE" =~ ^(baseline|strict|paranoid)$ ]] || PROFILE="baseline"

        if ! restore_additional_measures="$(python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import sys, json, pathlib
mf = pathlib.Path(sys.argv[1])
data = json.loads(mf.read_text(encoding='utf-8'))

# Для старых manifest без поля сохраняется прежнее безопасное поведение:
# выполняется полный restore дополнительных модулей.
value = data.get("additional_measures_enabled", True)
print("1" if value else "0")
PYJSON
)"; then
            add_error "restore: не удалось прочитать additional_measures_enabled из manifest"
            return 1
        fi
        [[ "$restore_additional_measures" =~ ^[01]$ ]] || restore_additional_measures=1
    fi

    run_mode_step restore restore_ssh_root_login_module restore_ssh_root_login_module || overall_rc=1
    if (( restore_additional_measures == 1 )); then
        run_mode_step restore restore_ssh_hardening_module restore_ssh_hardening_module || overall_rc=1
        run_mode_step restore restore_account_audit_module restore_account_audit_module || overall_rc=1
        run_mode_step restore restore_apparmor_module restore_apparmor_module || overall_rc=1
        run_mode_step restore restore_aide_module restore_aide_module || overall_rc=1
        run_mode_step restore restore_fail2ban_module restore_fail2ban_module || overall_rc=1
        run_mode_step restore restore_rkhunter_module restore_rkhunter_module || overall_rc=1
        run_mode_step restore restore_kernel_modules_module restore_kernel_modules_module || overall_rc=1
        run_mode_step restore restore_mount_hardening_module restore_mount_hardening_module || overall_rc=1
        run_mode_step restore restore_tmp_tmpfs_module restore_tmp_tmpfs_module || overall_rc=1
        run_mode_step restore restore_ufw_module restore_ufw_module || overall_rc=1
        run_mode_step restore restore_auditd_module restore_auditd_module || overall_rc=1
    else
        add_skipped "restore: дополнительные меры не применялись — их откат пропущен"
    fi

    run_mode_step restore restore_pam_wheel_module restore_pam_wheel_module || overall_rc=1
    run_mode_step restore restore_faillock_module restore_faillock_module || overall_rc=1
    run_mode_step restore restore_password_policy_module restore_password_policy_module || overall_rc=1
    run_mode_step restore restore_sudo_policy_module restore_sudo_policy_module || overall_rc=1
    run_mode_step restore restore_sysctl_kernel_module restore_sysctl_kernel_module || overall_rc=1
    if (( restore_additional_measures == 1 )); then
        run_mode_step restore restore_sysctl_network_module restore_sysctl_network_module || overall_rc=1
        run_mode_step restore restore_rsyslog_module restore_rsyslog_module || overall_rc=1
        run_mode_step restore restore_chrony_module restore_chrony_module || overall_rc=1
        run_mode_step restore restore_unattended_upgrades_module restore_unattended_upgrades_module || overall_rc=1
        run_mode_step restore restore_apport_module restore_apport_module || overall_rc=1
        run_mode_step restore restore_coredump_module restore_coredump_module || overall_rc=1
    fi

    run_mode_step restore restore_sysctl_attack_surface_module restore_sysctl_attack_surface_module || overall_rc=1
    run_mode_step restore restore_modules_disabled_module restore_modules_disabled_module || overall_rc=1
    run_mode_step restore restore_sysctl_userspace_protection_module restore_sysctl_userspace_protection_module || overall_rc=1
    run_mode_step restore restore_empty_passwords_module restore_empty_passwords_module || overall_rc=1
    run_mode_step restore restore_runtime_paths_module restore_runtime_paths_module || overall_rc=1
    run_mode_step restore restore_home_permissions_module restore_home_permissions_module || overall_rc=1
    run_mode_step restore restore_suid_sgid_module restore_suid_sgid_module || overall_rc=1
    run_mode_step restore restore_cron_command_paths_module restore_cron_command_paths_module || overall_rc=1
    run_mode_step restore restore_standard_system_paths_module restore_standard_system_paths_module || overall_rc=1
    run_mode_step restore restore_sudo_command_paths_module restore_sudo_command_paths_module || overall_rc=1
    run_mode_step restore restore_user_cron_permissions_module restore_user_cron_permissions_module || overall_rc=1
    run_mode_step restore restore_grub_kernel_params_module restore_grub_kernel_params_module || overall_rc=1
    run_mode_step restore restore_fs_critical_files_module restore_fs_critical_files_module || overall_rc=1
    run_mode_step restore restore_cron_targets_module restore_cron_targets_module || overall_rc=1
    run_mode_step restore restore_systemd_unit_targets_module restore_systemd_unit_targets_module || overall_rc=1
    run_mode_step restore write_report write_report || overall_rc=1
    run_mode_step restore print_report_stdout print_report_stdout || overall_rc=1
    if (( ${#ERRORS[@]} > 0 || overall_rc != 0 )); then
        log "[ERROR] restore завершён с errors=${#ERRORS[@]} overall_rc=$overall_rc"
        return 1
    fi

    return 0
}

run_report_mode() {
    local overall_rc=0
    log "[i]     Режим report"
    add_warning "report: режим не выполняет проверку системы — показывает только статическое покрытие ФСТЭК и preflight; для проверки состояния используйте --check"
    run_mode_step report run_preflight run_preflight || overall_rc=1
    run_mode_step report ensure_state_dir ensure_state_dir || overall_rc=1
    run_mode_step report write_report write_report || overall_rc=1
    run_mode_step report print_report_stdout print_report_stdout || overall_rc=1

    if (( ${#ERRORS[@]} > 0 || overall_rc != 0 )); then
        log "[ERROR] report завершён с errors=${#ERRORS[@]} overall_rc=$overall_rc"
        return 1
    fi

    return 0
}

main() {
    parse_args "$@"
    require_cmds
    validate_args
    load_config
    validate_args_post_config
    validate_execution_context
    finalize_paths

    case "$MODE" in
        check) run_check_mode ;;
        apply) run_apply_mode ;;
        restore) run_restore_mode ;;
        report) run_report_mode ;;
        *) die "Внутренняя ошибка: неизвестный режим '$MODE'" ;;
    esac
}

main "$@"
