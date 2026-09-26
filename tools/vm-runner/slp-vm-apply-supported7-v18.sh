#!/usr/bin/env bash
# PURPOSE=VM_APPLY_REBOOT_CHECK_SUPPORTED7
# Место выполнения: ПК user@Modern-15-B12M. Коммит и push не выполняет.
# Отличия v18 от v17 (APPLY sshd-config-option-v1: PasswordAuthentication/PermitRootLogin/
# PermitEmptyPasswords = no; решение пользователя 26.09.2026 — ВМ-прогон):
# - на ПК создаётся временный ключ ed25519 без пароля в рабочем каталоге (удаляется вместе
#   с ним; в архив не попадает); в фазе 1 до CHECK открытый ключ дописывается в
#   ~user/.ssh/authorized_keys (от имени user, 700/600) — иначе после
#   PasswordAuthentication no вход закрыт, а APPLY откажет (ssh:no-keyed-admin);
# - фаза 2 (после перезагрузки) входит только по ключу; sudo — по-прежнему паролем;
# - после перезагрузки проверяется, что вход по паролю отвергнут (файл pwlogin.txt:
#   PASSWORD_LOGIN_RC, ожидается не 0);
# - env1/env2: sshd -T (три ключа), активные строки sshd_config и sshd_config.d/*.conf;
# - кандидат по умолчанию — HEAD 995598c (62d0f006…30fa); файлов на среду — 12.
#
# Отличия v17 от v16 (очередь HANDOFF: путь с изменением прав у 2.3.5, 2.3.8, 2.3.9):
# - FIXTURES=1 (по умолчанию): до CHECK фазы 1 создаются три нарушения —
#   /opt/slp-fixture/suid 4777 (2.3.9), /usr/bin/slp-fixture-path 0777 (2.3.8),
#   /etc/systemd/system/slp-fixture.service 0666 (2.3.5); режимы пишутся в env1/env2
#   (FIXTURE_BEFORE, FIXTURE_AFTER_APPLY, FIXTURE_AFTER_REBOOT); снимок восстанавливается;
# - FIXTURES=0 — поведение v16.
#
# Отличия v16 от v15 (решение пользователя 25.09.2026):
# - пароль user вводится в терминале один раз; ssh получает его через SSH_ASKPASS
#   (SSH_ASKPASS_REQUIRE=force, переменная передаётся только процессу ssh), sudo на ВМ —
#   через stdin (sudo -S -p '' с here-string на каждую команду); пароль не пишется в
#   файлы, аргументы команд и evidence;
# - мастер-соединение ssh повторяется до 5 раз с паузой 5 с (после перезагрузки sshd
#   может закрыть первое соединение — отказ STATE 2 прогона 25.09.2026 13:53);
# - фазы на ВМ запускаются без -tt: пароль приходит первой строкой stdin.
#
# Отличия v15 от v14:
# - снимки upd-20260924 всех 7 сред встроены в таблицу (UUID — из выводов slp-vm-update-snapshots
#   24.09.2026); STATES_FILES снова необязателен (замена строк, как в v13).
#
# Отличия v14 от v13 (решение пользователя 24.09.2026: проверка APPLY на 7 средах):
# - на каждой среде после восстановления снимка: CHECK (check-before) → APPLY --dry-run →
#   APPLY → перезагрузка ВМ → CHECK (check-after) → повторный APPLY (apply2) → возврат к снимку;
# - перезагрузка подтверждается сменой /proc/sys/kernel/random/boot_id;
# - рабочий каталог на ВМ — в $HOME (на части сред /tmp очищается при загрузке);
# - пароль вводится 4 раза на среду: ssh и sudo до перезагрузки, ssh и sudo после;
# - все выбранные среды — снимки upd-20260924;
# - кандидат — securelinux-policy.sh с CHECK_SHA256 из EXPECTED_CHECK_SHA256
#   (по умолчанию — коммит вывода blocks, d840ede3…c8aa);
# - проба v13 и опции RUN_CHECK/PROBE_FILE удалены.
# Функции VirtualBox, ожидания ssh и часов, preflight — без изменений против v13.
#
# ARCHIVE_CONTENT=ONLY_COMMAND_OUTPUTS
# VM_FLOW=SEQUENTIAL_SNAPSHOT_RESTORE_START_CHECK_APPLY_REBOOT_CHECK_APPLY_FINAL_RESTORE
# PURPOSE=DEFENSIVE_COMPLIANCE_VALIDATION
# SCOPE=LOCAL_REPOSITORY_AND_OWN_TEST_FIXTURES
# HOST_MUTATION=false
# GUEST_MUTATION=APPLY_ON_DISPOSABLE_SNAPSHOT_RESTORED_AFTER_RUN

set -u

DOWNLOADS=/mnt/300GB/Загрузки
REPO="$DOWNLOADS/SecureLinux-Policy-v3"
EVIDENCE_DIR="$REPO/dashboard/src0009-vm-evidence"
CANDIDATE="$REPO/securelinux-policy.sh"
EXPECTED_CHECK_SHA256=${EXPECTED_CHECK_SHA256:-62d0f00687875e977c93dc450fd32b34c6bd848f507a3d49ba94bee6c11830fa}
EXPECTED_STATES=7
SNAPSHOT_TAG=upd-20260924

START_FROM=${START_FROM:-1}
case "$START_FROM" in [1-7]) ;; *) echo "REASON=invalid-START_FROM:$START_FROM"; echo "RC=2"; exit 2 ;; esac
STOP_AT=${STOP_AT:-7}
case "$STOP_AT" in [1-7]) ;; *) echo "REASON=invalid-STOP_AT:$STOP_AT"; echo "RC=2"; exit 2 ;; esac
[ "$STOP_AT" -ge "$START_FROM" ] || { echo "REASON=STOP_AT-before-START_FROM"; echo "RC=2"; exit 2; }
ONLY=${ONLY:-}
FIXTURES=${FIXTURES:-1}
case "$FIXTURES" in 0|1) ;; *) echo "REASON=invalid-FIXTURES:$FIXTURES"; echo "RC=2"; exit 2 ;; esac
for n in $ONLY; do case "$n" in [1-7]) ;; *) echo "REASON=invalid-ONLY:$n"; echo "RC=2"; exit 2 ;; esac; done
NAME=slp-vm-apply-supported7-v18
STAMP=$(date +%Y%m%d-%H%M%S)
WORK="$DOWNLOADS/$NAME-$STAMP.work"
RESULTS="$WORK/results"
LOGS="$WORK/logs"
STATES="$WORK/states.tsv"
SEL_TAG=$(printf '%s' "${ONLY:-$START_FROM-$STOP_AT}" | tr ' ' '_')
FINAL="$DOWNLOADS/$NAME-states${SEL_TAG}-$STAMP.tar.gz"

STATES_FILES=${STATES_FILES:-}

mkdir -p "$RESULTS" "$LOGS" || { echo "RC=2"; exit 2; }

CURRENT_VM=""
CURRENT_SNAPSHOT=""
CURRENT_LOG=""
CURRENT_NEEDS_RESTORE=NO

cat >"$STATES" <<'EOF'
ubuntu22_server_full-install_OK	ubuntu22_server_full	1642a105-4c61-4d62-8c66-537c8f56b9d5	08:00:27:1B:73:04	install OK! upd-20260924	f047b33f-5add-4231-af82-12bf1f8cf6b0	user@192.168.56.110	192.168.56.110
ubuntu24_server-install_mini_OK	ubuntu24_server	025e5417-3c81-4b66-a26b-b548ffdd1e44	08:00:27:FF:4F:DE	install mini OK! upd-20260924	7710f023-ddd6-4c88-84c1-a2afc8ed0f99	user@192.168.56.115	192.168.56.115
ubuntu24_server-Install_full_OK	ubuntu24_server	025e5417-3c81-4b66-a26b-b548ffdd1e44	08:00:27:FF:4F:DE	Install full OK! upd-20260924	64a3605b-5c31-468b-82c9-70fa247d8aea	user@192.168.56.115	192.168.56.115
ubuntu26_server-Install_mini_OK	ubuntu26_server	3e6f0728-15de-4a96-9174-b4e62dbfe85f	08:00:27:D5:0F:6C	Install mini OK! upd-20260924	3348040d-e7d3-4d82-98ed-56cc80511462	user@192.168.56.117	192.168.56.117
ubuntu26_server-Install_full_OK	ubuntu26_server	3e6f0728-15de-4a96-9174-b4e62dbfe85f	08:00:27:D5:0F:6C	Install full OK! upd-20260924	fbfa71fa-7a61-4225-90ae-e67c7c3ce82c	user@192.168.56.117	192.168.56.117
debian-12-install_OK	debian-12	b73229dc-4354-4f41-8107-0a6dc8e1b7ef	08:00:27:42:76:7E	install OK! upd-20260924	400790d3-fcc3-4a88-bc97-c39f21e2f119	user@192.168.56.106	192.168.56.106
debian-13-install_OK	debian-13	a9dd5351-cdac-4a93-9a20-0d96e5237160	08:00:27:79:7F:F9	install OK! upd-20260924	bb6499b2-5d37-4c85-a5be-5cbc244e0bc8	user@192.168.56.108	192.168.56.108
EOF

if [ -n "$STATES_FILES" ]; then
python3 -I -S -B - "$STATES" $STATES_FILES <<'PY' || { echo "REASON=invalid-STATES_FILES"; echo "WORKDIR_KEPT=$WORK"; echo "RC=2"; exit 2; }
import sys
from pathlib import Path
base = Path(sys.argv[1])
rows = [line.split("\t") for line in base.read_text(encoding="utf-8").splitlines()]
index = {row[0]: i for i, row in enumerate(rows)}
for name in sys.argv[2:]:
    for line in Path(name).read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 8 or fields[0] not in index:
            sys.exit(1)
        old = rows[index[fields[0]]]
        if fields[1:4] != old[1:4] or fields[6:] != old[6:]:
            sys.exit(1)
        rows[index[fields[0]]] = fields
        print(f"STATES_OVERRIDE={fields[0]}:{fields[4]}:{fields[5]}")
base.write_text("".join("\t".join(r) + "\n" for r in rows), encoding="utf-8")
PY
fi

# Фазы на ВМ: один вызов через ssh без вложенного кода (регламент §12.A). Вывод — в файлы на ВМ.
PHASE1="$WORK/phase1.sh"
cat >"$PHASE1" <<'REMOTE'
#!/usr/bin/env bash
d=$1
cd "$d" || exit 3
IFS= read -r _slp_pw || exit 4
s() { sudo -S -p '' "$@" <<<"$_slp_pw"; }
: >err1.txt
s -v || exit 4
sha256sum -c --quiet securelinux-policy.sh.sha256 >/dev/null 2>&1 || { echo "CHECK_SCRIPT_SHA=MISMATCH" >env1.txt; exit 5; }
{
    echo "BOOT_ID=$(cat /proc/sys/kernel/random/boot_id)"
    echo "CMDLINE=$(cat /proc/cmdline)"
    grep -E '^PRETTY_NAME=' /etc/os-release
    s ls -la /etc/default/grub.d
} >env1.txt 2>&1
# Временный ключ ПК — до APPLY, от имени user (снимок восстанавливается после прогона).
{ install -d -m 700 "$HOME/.ssh" &&
  cat slp-key.pub >>"$HOME/.ssh/authorized_keys" &&
  chmod 600 "$HOME/.ssh/authorized_keys"; } 2>>err1.txt
echo "AUTHKEY_INSTALL_RC=$?" >>env1.txt
stat -c 'AUTHKEY_STAT %a %U %n' "$HOME" "$HOME/.ssh" "$HOME/.ssh/authorized_keys" >>env1.txt 2>&1
sshd_state() {
    echo "=== SSHD_T_$1"
    s sshd -T 2>&1 | grep -Ei '^(permitrootlogin|passwordauthentication|permitemptypasswords) ' | sed 's/^/SSHD_T /'
    echo "=== SSHD_FILES_$1"
    s grep -HnEi '^[[:space:]]*(permitrootlogin|passwordauthentication|permitemptypasswords)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>&1
}
sshd_state BEFORE >>env1.txt 2>&1
if [ "${2:-0}" = 1 ]; then
    { s install -D -o root -g root -m 4777 /usr/bin/true /opt/slp-fixture/suid &&
      s install -o root -g root -m 0777 /usr/bin/true /usr/bin/slp-fixture-path &&
      s install -o root -g root -m 0666 /dev/null /etc/systemd/system/slp-fixture.service; } 2>>err1.txt
    echo "FIXTURES_RC=$?" >>env1.txt
    stat -c 'FIXTURE_BEFORE %a %n' /opt/slp-fixture/suid /usr/bin/slp-fixture-path /etc/systemd/system/slp-fixture.service >>env1.txt 2>&1
fi
s /bin/bash -p ./securelinux-policy.sh --check --format raw >check-before.txt 2>>err1.txt
echo "CHECK_RC=$?" >>check-before.txt
s /bin/bash -p ./securelinux-policy.sh --apply --dry-run >dryrun.txt 2>>err1.txt
echo "APPLY_RC=$?" >>dryrun.txt
s /bin/bash -p ./securelinux-policy.sh --apply >apply.txt 2>>err1.txt
echo "APPLY_RC=$?" >>apply.txt
s cat /var/log/securelinux-policy/report.json >apply-report.json 2>>err1.txt
[ "${2:-0}" = 1 ] && stat -c 'FIXTURE_AFTER_APPLY %a %n' /opt/slp-fixture/suid /usr/bin/slp-fixture-path /etc/systemd/system/slp-fixture.service >>env1.txt 2>&1
sshd_state AFTER_APPLY >>env1.txt 2>&1
{
    echo '=== DROPIN'
    s cat /etc/default/grub.d/zz-securelinux-policy.cfg
    echo '=== GRUB_CFG_LINUX'
    s grep -E '^[[:space:]]*linux[[:space:]]' /boot/grub/grub.cfg | cut -c1-300
} >>env1.txt 2>&1
s true >/dev/null 2>&1; echo "SUDO_N_AFTER_RC=$?" >>env1.txt
# Кэш sudo привязан к терминалу этой сессии: перезагрузка планируется здесь, через 20 с,
# чтобы ПК успел забрать файлы.
s systemd-run --quiet --on-active=20 /bin/systemctl reboot >>err1.txt 2>&1
echo "REBOOT_SCHEDULED_RC=$?" >>env1.txt
unset _slp_pw
chmod 600 env1.txt err1.txt check-before.txt dryrun.txt apply.txt apply-report.json
exit 0
REMOTE

PHASE2="$WORK/phase2.sh"
cat >"$PHASE2" <<'REMOTE'
#!/usr/bin/env bash
d=$1
cd "$d" || exit 3
IFS= read -r _slp_pw || exit 4
s() { sudo -S -p '' "$@" <<<"$_slp_pw"; }
: >err2.txt
s -v || exit 4
sha256sum -c --quiet securelinux-policy.sh.sha256 >/dev/null 2>&1 || { echo "CHECK_SCRIPT_SHA=MISMATCH" >env2.txt; exit 5; }
{
    echo "BOOT_ID=$(cat /proc/sys/kernel/random/boot_id)"
    echo "CMDLINE=$(cat /proc/cmdline)"
} >env2.txt 2>&1
{
    echo "=== SSHD_T_AFTER_REBOOT"
    s sshd -T 2>&1 | grep -Ei '^(permitrootlogin|passwordauthentication|permitemptypasswords) ' | sed 's/^/SSHD_T /'
    echo "=== SSHD_FILES_AFTER_REBOOT"
    s grep -HnEi '^[[:space:]]*(permitrootlogin|passwordauthentication|permitemptypasswords)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>&1
} >>env2.txt 2>&1
s /bin/bash -p ./securelinux-policy.sh --check --format raw >check-after.txt 2>>err2.txt
echo "CHECK_RC=$?" >>check-after.txt
[ "${2:-0}" = 1 ] && stat -c 'FIXTURE_AFTER_REBOOT %a %n' /opt/slp-fixture/suid /usr/bin/slp-fixture-path /etc/systemd/system/slp-fixture.service >>env2.txt 2>&1
s /bin/bash -p ./securelinux-policy.sh --apply >apply2.txt 2>>err2.txt
echo "APPLY_RC=$?" >>apply2.txt
s cat /var/log/securelinux-policy/report.json >apply2-report.json 2>>err2.txt
s true >/dev/null 2>&1; echo "SUDO_N_AFTER_RC=$?" >>env2.txt
unset _slp_pw
chmod 600 env2.txt err2.txt check-after.txt apply2.txt apply2-report.json
exit 0
REMOTE
FILES1="env1.txt err1.txt check-before.txt dryrun.txt apply.txt apply-report.json"
FILES2="env2.txt err2.txt check-after.txt apply2.txt apply2-report.json"
FILES_PER_STATE=12

for c in VBoxManage python3 ssh ssh-keygen scp timeout tar sha256sum awk stat wc cp cmp; do
    command -v "$c" >/dev/null 2>&1 || {
        echo "REASON=required-command-missing:$c"
        echo "RC=2"
        exit 2
    }
done

# Кандидат проверяется до любого действия с ВМ.
actual_check=$(sha256sum "$CANDIDATE" 2>/dev/null | awk '{print $1}')
if [ "$actual_check" != "$EXPECTED_CHECK_SHA256" ]; then
    echo "RESULT=ABORT"
    echo "REASON=candidate-sha-mismatch:${actual_check:-absent}"
    echo "WORKDIR_KEPT=$WORK"
    echo "RC=2"
    exit 2
fi
cp -- "$CANDIDATE" "$WORK/securelinux-policy.sh" || { echo "RC=2"; exit 2; }
printf '%s  securelinux-policy.sh\n' "$EXPECTED_CHECK_SHA256" >"$WORK/securelinux-policy.sh.sha256"
( cd "$WORK" && sha256sum -c --quiet securelinux-policy.sh.sha256 ) || { echo "REASON=candidate-copy-sha"; echo "RC=2"; exit 2; }
[ -d "$EVIDENCE_DIR" ] || { echo "REASON=evidence-dir-missing:$EVIDENCE_DIR"; echo "RC=2"; exit 2; }
echo "CANDIDATE_SHA256=$EXPECTED_CHECK_SHA256"

# Пароль user для ВМ: вводится один раз, хранится только в переменной этого процесса
# (не экспортируется). Помощник askpass читает его из окружения процесса ssh.
printf 'Пароль user для ВМ (ssh и sudo): ' >/dev/tty
IFS= read -rs SLP_VM_PW </dev/tty
printf '\n' >/dev/tty
[ -n "$SLP_VM_PW" ] || { echo "REASON=empty-password"; echo "WORKDIR_KEPT=$WORK"; echo "RC=2"; exit 2; }
ASKPASS="$WORK/askpass.sh"
printf '%s\n' '#!/bin/sh' 'printf "%s\\n" "$SLP_VM_PW"' >"$ASKPASS" && chmod 700 "$ASKPASS" || { echo "REASON=askpass-create"; echo "RC=2"; exit 2; }
# Временный ключ для входа после PasswordAuthentication no; только в рабочем каталоге.
KEY="$WORK/slp-key"
ssh-keygen -q -t ed25519 -N '' -C slp-vm-apply-v18 -f "$KEY" </dev/null >/dev/null 2>&1 &&
    chmod 600 "$KEY" || { echo "REASON=ssh-keygen"; echo "WORKDIR_KEPT=$WORK"; echo "RC=2"; exit 2; }

# Повтор команды VBoxManage, пока ответ — блокировка сессии. $1 — файл вывода.
vbox_retry() {
    out=$1
    shift
    for _ in $(seq 1 30); do
        "$@" >"$out" 2>&1 && return 0
        grep -q 'already locked' "$out" || return 1
        sleep 2
    done
    return 1
}

wait_off() {
    vm=$1
    out=$2
    for _ in $(seq 1 40); do
        VBoxManage showvminfo "$vm" --machinereadable >"$out" 2>&1 || return 1
        st=$(awk -F= '$1=="VMState"{gsub(/^"|"$/,"",$2);print $2}' "$out")
        case "$st" in
            poweroff|aborted) return 0 ;;
        esac
        sleep 1
    done
    return 1
}

poweroff_vm() {
    vm=$1
    prefix=$2
    VBoxManage showvminfo "$vm" --machinereadable >"${prefix}-before.txt" 2>&1 || return 1
    st=$(awk -F= '$1=="VMState"{gsub(/^"|"$/,"",$2);print $2}' "${prefix}-before.txt")
    case "$st" in
        running|paused|stuck)
            vbox_retry "${prefix}-poweroff.txt" VBoxManage controlvm "$vm" poweroff || return 1
            ;;
        saved)
            vbox_retry "${prefix}-discardstate.txt" VBoxManage discardstate "$vm" || return 1
            ;;
        poweroff|aborted)
            ;;
        *)
            return 1
            ;;
    esac
    wait_off "$vm" "${prefix}-after.txt"
}

restore_current() {
    [ "$CURRENT_NEEDS_RESTORE" = YES ] || return 0
    poweroff_vm "$CURRENT_VM" "$CURRENT_LOG/final" || return 1
    vbox_retry "$CURRENT_LOG/final-restore.txt" \
        VBoxManage snapshot "$CURRENT_VM" restore "$CURRENT_SNAPSHOT" || return 1
    VBoxManage showvminfo "$CURRENT_VM" --machinereadable \
        >"$CURRENT_LOG/final-after.txt" 2>&1 || return 1
    cur=$(awk -F= '$1=="CurrentSnapshotUUID"{gsub(/^"|"$/,"",$2);print $2}' \
        "$CURRENT_LOG/final-after.txt")
    [ "$cur" = "$CURRENT_SNAPSHOT" ] || return 1
    CURRENT_NEEDS_RESTORE=NO
    return 0
}

cleanup_on_signal() {
    restore_current >/dev/null 2>&1 || true
    echo "RESULT=FAIL"
    echo "REASON=interrupted"
    echo "WORKDIR_KEPT=$WORK"
    echo "RC=130"
    exit 130
}
trap cleanup_on_signal HUP INT TERM

wait_ssh() {
    host=$1
    for _ in $(seq 1 120); do
        timeout 1 bash -c "exec 3<>/dev/tcp/$host/22" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

# Снимки сохранены с памятью: часы гостя отстают и позже скачком синхронизируются,
# скачок сбрасывает кэш sudo. Ждём |разница| <= 5 с, опрос раз в 5 с, до 300 с.
wait_clock() {
    ctl=$1
    target=$2
    log=$3
    prev=""
    same=0
    for _ in $(seq 1 60); do
        remote=$(timeout 15 ssh -S "$ctl" -o BatchMode=yes "$target" date +%s 2>/dev/null)
        local_now=$(date +%s)
        case "$remote" in
            ''|*[!0-9]*) echo "CLOCK_WAIT remote=UNKNOWN" ;;
            *)
                diff=$((local_now - remote))
                [ "$diff" -lt 0 ] && diff=$((-diff))
                echo "CLOCK_DIFF=$diff" >>"$log"
                echo "CLOCK_WAIT diff=${diff}s"
                [ "$diff" -le 5 ] && return 0
                if [ -n "$prev" ] && [ $((diff - prev)) -le 2 ] && [ $((prev - diff)) -le 2 ]; then
                    same=$((same + 1))
                else
                    same=0
                fi
                prev=$diff
                if [ "$same" -ge 2 ]; then
                    echo "CLOCK_STABLE_SKEW=${diff}s" >>"$log"
                    return 0
                fi
                ;;
        esac
        sleep 5
    done
    return 1
}

# Read-only preflight of all identities before the first VM state change.
PREFLIGHT_FAIL=0
N_STATES=0
I=0
while IFS=$'\t' read -r -u 3 ENV VM VUUID VMAC SNAP SUUID SSH_TARGET SSH_HOST; do
    I=$((I+1))
    N_STATES=$I
    L="$LOGS/$(printf '%02d' "$I")-$ENV"
    mkdir -p "$L"

    VBoxManage showvminfo "$VM" --machinereadable >"$L/preflight-vm.txt" 2>&1 || {
        PREFLIGHT_FAIL=1
        continue
    }

    actual_uuid=$(awk -F= '$1=="UUID"{gsub(/^"|"$/,"",$2);print $2}' "$L/preflight-vm.txt")
    want_mac=$(printf '%s' "$VMAC" | tr -d ':' | tr '[:lower:]' '[:upper:]')
    mac_match=$(awk -F= -v w="$want_mac" '
        $1~/^macaddress[0-9]+$/ {
            gsub(/^"|"$/,"",$2); gsub(/:/,"",$2)
            if (toupper($2)==w) f=1
        }
        END{print f?"YES":"NO"}
    ' "$L/preflight-vm.txt")

    VBoxManage snapshot "$VM" list --machinereadable >"$L/preflight-snapshots.txt" 2>&1 || {
        PREFLIGHT_FAIL=1
        continue
    }

    python3 -I -S -B - "$L/preflight-snapshots.txt" "$SNAP" "$SUUID" <<'PY' >/dev/null
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(errors="replace")
want = (sys.argv[2], sys.argv[3])
names, uuids = {}, {}
for line in text.splitlines():
    m = re.match(r'SnapshotName(?:-(\d+))?="(.*)"$', line)
    if m:
        names[m.group(1) or "0"] = m.group(2)
    m = re.match(r'SnapshotUUID(?:-(\d+))?="(.*)"$', line)
    if m:
        uuids[m.group(1) or "0"] = m.group(2)
pairs = {(names.get(k), uuids.get(k)) for k in set(names) | set(uuids)}
raise SystemExit(0 if want in pairs else 1)
PY
    snap_rc=$?

    sel=YES
    { [ "$I" -lt "$START_FROM" ] || [ "$I" -gt "$STOP_AT" ]; } && sel=NO
    if [ -n "$ONLY" ]; then case " $ONLY " in *" $I "*) ;; *) sel=NO ;; esac; fi
    if [ "$sel" = YES ]; then
        case "$SNAP" in *"$SNAPSHOT_TAG"*) ;; *) echo "REASON=snapshot-not-$SNAPSHOT_TAG:$ENV"; PREFLIGHT_FAIL=1 ;; esac
    fi

    [ "$actual_uuid" = "$VUUID" ] || PREFLIGHT_FAIL=1
    [ "$mac_match" = YES ] || PREFLIGHT_FAIL=1
    [ "$snap_rc" -eq 0 ] || PREFLIGHT_FAIL=1
done 3<"$STATES"

[ "$N_STATES" -eq "$EXPECTED_STATES" ] || PREFLIGHT_FAIL=1

if [ "$PREFLIGHT_FAIL" -ne 0 ]; then
    echo "RESULT=ABORT"
    echo "REASON=preflight-failed-no-vm-started"
    echo "WORKDIR_KEPT=$WORK"
    echo "RC=2"
    exit 2
fi

echo "ALL_STATES_PREFLIGHT=PASS"

OVERALL=0
I=0
while IFS=$'\t' read -r -u 3 ENV VM VUUID VMAC SNAP SUUID SSH_TARGET SSH_HOST; do
    I=$((I+1))
    P=$(printf '%02d' "$I")
    L="$LOGS/$P-$ENV"
    REMOTE_DIR=""

    [ "$I" -lt "$START_FROM" ] && continue
    [ "$I" -gt "$STOP_AT" ] && break
    if [ -n "$ONLY" ]; then
        case " $ONLY " in *" $I "*) ;; *) continue ;; esac
    fi

    echo
    echo "=== STATE $I/$EXPECTED_STATES: $ENV ==="
    echo "VM=$VM"
    echo "SNAPSHOT=$SNAP"
    echo "SSH=$SSH_TARGET"

    CURRENT_VM="$VM"
    CURRENT_SNAPSHOT="$SUUID"
    CURRENT_LOG="$L"
    CURRENT_NEEDS_RESTORE=YES

    state_rc=0

    poweroff_vm "$VM" "$L/initial" || state_rc=1

    if [ "$state_rc" -eq 0 ]; then
        vbox_retry "$L/initial-restore.txt" VBoxManage snapshot "$VM" restore "$SUUID" || state_rc=1
    fi

    if [ "$state_rc" -eq 0 ]; then
        VBoxManage showvminfo "$VM" --machinereadable >"$L/after-restore.txt" 2>&1 || state_rc=1
    fi

    if [ "$state_rc" -eq 0 ]; then
        cur=$(awk -F= '$1=="CurrentSnapshotUUID"{gsub(/^"|"$/,"",$2);print $2}' "$L/after-restore.txt")
        st=$(awk -F= '$1=="VMState"{gsub(/^"|"$/,"",$2);print $2}' "$L/after-restore.txt")
        [ "$cur" = "$SUUID" ] || state_rc=1
    fi

    if [ "$state_rc" -eq 0 ]; then
        case "$st" in
            saved|poweroff)
                vbox_retry "$L/start.txt" VBoxManage startvm "$VM" --type headless || state_rc=1
                ;;
            running)
                ;;
            *)
                state_rc=1
                ;;
        esac
    fi

    # Мастер-соединение ssh (пароль на /dev/tty) и ожидание часов. $1 — метка фазы.
    open_master() {
        CTL_DIR=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp/user/$(id -u)}/slp-apply-ctl-XXXXXX")
        chmod 700 "$CTL_DIR"
        CTL="$CTL_DIR/master"
        _try=1
        # Фаза 1 — вход по паролю (ключ ещё не установлен); фаза 2 — только по ключу.
        if [ "$1" = 1 ]; then
            _auth="-o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no"
        else
            _auth="-i $KEY -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no"
        fi
        # shellcheck disable=SC2086
        until SLP_VM_PW=$SLP_VM_PW SSH_ASKPASS=$ASKPASS SSH_ASKPASS_REQUIRE=force \
            ssh -M -S "$CTL" $_auth -o ControlPersist=900 -o ConnectTimeout=8 -o NumberOfPasswordPrompts=1 -fnNT "$SSH_TARGET" </dev/null; do
            [ "$_try" -ge 5 ] && return 1
            _try=$((_try + 1))
            sleep 5
        done
        if wait_clock "$CTL" "$SSH_TARGET" "$L/clock-$1.txt"; then
            tail -1 "$L/clock-$1.txt"
        else
            echo "REASON=vm-clock-not-converged:$ENV:$1"
            return 1
        fi
    }
    close_master() {
        ssh -S "$CTL" -O exit "$SSH_TARGET" >/dev/null 2>&1 || true
        rm -rf -- "$CTL_DIR"
    }
    fetch() {
        for f in "$@"; do
            scp -q -o ControlPath="$CTL" "$SSH_TARGET:$REMOTE_DIR/$f" "$RESULTS/$P-$ENV.$f" || return 1
        done
    }

    if [ "$state_rc" -eq 0 ]; then
        wait_ssh "$SSH_HOST" || state_rc=1
    fi

    if [ "$state_rc" -eq 0 ]; then
        if open_master 1; then
            REMOTE_DIR=$(ssh -S "$CTL" "$SSH_TARGET" "d=\$HOME/slp-apply-${$}-${I}; mkdir -m 700 \"\$d\" && printf %s \"\$d\"") &&
            scp -q -o ControlPath="$CTL" "$PHASE1" "$PHASE2" "$KEY.pub" \
                "$WORK/securelinux-policy.sh" "$WORK/securelinux-policy.sh.sha256" \
                "$SSH_TARGET:$REMOTE_DIR/" || state_rc=1
            if [ "$state_rc" -eq 0 ]; then
                echo "PHASE1: CHECK -> APPLY --dry-run -> APPLY"
                printf '%s\n' "$SLP_VM_PW" | ssh -S "$CTL" "$SSH_TARGET" "/bin/bash '$REMOTE_DIR/phase1.sh' '$REMOTE_DIR' '$FIXTURES'" || state_rc=1
            fi
            [ "$state_rc" -eq 0 ] && { fetch $FILES1 || state_rc=1; }
            if [ "$state_rc" -eq 0 ]; then
                grep -qx 'AUTHKEY_INSTALL_RC=0' "$RESULTS/$P-$ENV.env1.txt" || { echo "REASON=authkey-install-failed:$ENV"; state_rc=1; }
                grep -qx 'REBOOT_SCHEDULED_RC=0' "$RESULTS/$P-$ENV.env1.txt" || { echo "REASON=reboot-not-scheduled:$ENV"; state_rc=1; }
                [ "$state_rc" -eq 0 ] && echo "REBOOT (через 20 с)"
            fi
        else
            state_rc=1
        fi
        close_master
    fi

    if [ "$state_rc" -eq 0 ]; then
        # Порт 22 должен закрыться, затем открыться снова.
        down=NO
        for _ in $(seq 1 120); do
            timeout 1 bash -c "exec 3<>/dev/tcp/$SSH_HOST/22" >/dev/null 2>&1 || { down=YES; break; }
            sleep 1
        done
        [ "$down" = YES ] || { echo "REASON=reboot-not-observed:$ENV"; state_rc=1; }
    fi
    if [ "$state_rc" -eq 0 ]; then
        up=NO
        for _ in $(seq 1 3); do wait_ssh "$SSH_HOST" && { up=YES; break; }; done
        [ "$up" = YES ] || { echo "REASON=ssh-not-back-after-reboot:$ENV"; state_rc=1; }
    fi

    if [ "$state_rc" -eq 0 ]; then
        # Вход по паролю после APPLY и перезагрузки должен быть отвергнут (ключ не предлагается).
        SLP_VM_PW=$SLP_VM_PW SSH_ASKPASS=$ASKPASS SSH_ASKPASS_REQUIRE=force \
            timeout 30 ssh -o ControlPath=none -o PubkeyAuthentication=no -o IdentitiesOnly=yes \
            -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1 \
            -o ConnectTimeout=8 -n "$SSH_TARGET" true >"$L/pwlogin-ssh.txt" 2>&1
        echo "PASSWORD_LOGIN_RC=$?" >"$RESULTS/$P-$ENV.pwlogin.txt"
    fi

    if [ "$state_rc" -eq 0 ]; then
        if open_master 2; then
            echo "PHASE2: CHECK -> APPLY"
            printf '%s\n' "$SLP_VM_PW" | ssh -S "$CTL" "$SSH_TARGET" "/bin/bash '$REMOTE_DIR/phase2.sh' '$REMOTE_DIR' '$FIXTURES'" || state_rc=1
            [ "$state_rc" -eq 0 ] && { fetch $FILES2 || state_rc=1; }
            ssh -S "$CTL" "$SSH_TARGET" "rm -rf -- '$REMOTE_DIR'" >/dev/null 2>&1 || true
        else
            state_rc=1
        fi
        close_master
    fi

    restore_current || state_rc=1

    CURRENT_VM=""
    CURRENT_SNAPSHOT=""
    CURRENT_LOG=""
    CURRENT_NEEDS_RESTORE=NO

    B1="$RESULTS/$P-$ENV.env1.txt"
    B2="$RESULTS/$P-$ENV.env2.txt"
    if [ -f "$B1" ] && [ -f "$B2" ]; then
        id1=$(grep -m1 '^BOOT_ID=' "$B1")
        id2=$(grep -m1 '^BOOT_ID=' "$B2")
        if [ -n "$id1" ] && [ -n "$id2" ] && [ "$id1" != "$id2" ]; then
            echo "STATE_${I}_REBOOTED=YES"
        else
            echo "STATE_${I}_REBOOTED=NO"
            state_rc=1
        fi
    fi
    for f in check-before check-after; do
        F="$RESULTS/$P-$ENV.$f.txt"
        [ -f "$F" ] || continue
        grep -q '^CHECK_SCRIPT_SHA=MISMATCH' "$F" && state_rc=1
        crc=$(grep -E '^CHECK_RC=' "$F" | tail -1)
        cnt=$(awk -F'\t' '$1=="SLP-CHECK-V1"{n[$5]++} END{for(k in n) printf "%s=%d ", k, n[k]}' "$F")
        echo "STATE_${I}_$(printf '%s' "$f" | tr 'a-z-' 'A-Z_'): ${crc:-CHECK_RC=UNKNOWN} ${cnt}"
    done
    for f in dryrun apply apply2; do
        F="$RESULTS/$P-$ENV.$f.txt"
        [ -f "$F" ] || continue
        tot=$(grep -E '^TOTAL=' "$F" | tail -1)
        arc=$(grep -E '^APPLY_RC=' "$F" | tail -1)
        echo "STATE_${I}_$(printf '%s' "$f" | tr 'a-z' 'A-Z'): ${arc:-APPLY_RC=UNKNOWN} ${tot:-TOTAL=UNKNOWN}"
    done
    for F in "$B1" "$B2"; do
        [ -f "$F" ] && grep -E '^(FIXTURE|AUTHKEY_INSTALL_RC|=== SSHD_T_|SSHD_T )' "$F" | sed "s/^/STATE_${I}_/"
    done
    PW="$RESULTS/$P-$ENV.pwlogin.txt"
    [ -f "$PW" ] && sed "s/^/STATE_${I}_/" "$PW"

    if [ "$state_rc" -eq 0 ]; then
        echo "STATE_${I}_RC=0"
    else
        echo "STATE_${I}_RC=1"
        OVERALL=1
    fi
done 3<"$STATES"

if [ "$OVERALL" -ne 0 ]; then
    echo "RESULT=FAIL"
    echo "REASON=one-or-more-states-failed"
    echo "WORKDIR_KEPT=$WORK"
    echo "RC=1"
    exit 1
fi

if [ -n "$ONLY" ]; then
    NSEL=0
    for n in $ONLY; do [ "$n" -ge "$START_FROM" ] && [ "$n" -le "$STOP_AT" ] && NSEL=$((NSEL + 1)); done
else
    NSEL=$((STOP_AT - START_FROM + 1))
fi
WANT_FILES=$((NSEL * FILES_PER_STATE))
COUNT=$(find "$RESULTS" -maxdepth 1 -type f | wc -l)
if [ "$COUNT" -ne "$WANT_FILES" ]; then
    echo "RESULT=FAIL"
    echo "REASON=result-file-count:$COUNT"
    echo "WORKDIR_KEPT=$WORK"
    echo "RC=1"
    exit 1
fi

cp -- "$PHASE1" "$RESULTS/00-phase1.sh" || { echo "REASON=phase-copy"; echo "WORKDIR_KEPT=$WORK"; echo "RC=1"; exit 1; }
cp -- "$PHASE2" "$RESULTS/00-phase2.sh" || { echo "REASON=phase-copy"; echo "WORKDIR_KEPT=$WORK"; echo "RC=1"; exit 1; }
cp -- "$STATES" "$RESULTS/00-states.tsv" || { echo "REASON=states-copy"; echo "WORKDIR_KEPT=$WORK"; echo "RC=1"; exit 1; }
printf 'CANDIDATE_SHA256=%s\nRUNNER=%s\nSTART_FROM=%s\nSTOP_AT=%s\nONLY=%s\nFIXTURES=%s\n' "$EXPECTED_CHECK_SHA256" "$NAME" "$START_FROM" "$STOP_AT" "$ONLY" "$FIXTURES" >"$RESULTS/00-identity.txt"

(
    cd "$RESULTS" &&
    tar -czf "$FINAL" -- *
)
TAR_RC=$?

if [ "$TAR_RC" -ne 0 ]; then
    echo "RESULT=FAIL"
    echo "REASON=archive-create-failed"
    echo "WORKDIR_KEPT=$WORK"
    echo "RC=1"
    exit 1
fi

MEMBERS=$(tar -tzf "$FINAL" | wc -l)
if [ "$MEMBERS" -ne $((WANT_FILES + 4)) ]; then
    echo "RESULT=FAIL"
    echo "REASON=archive-member-count:$MEMBERS"
    echo "WORKDIR_KEPT=$WORK"
    echo "RC=1"
    exit 1
fi

( cd "$DOWNLOADS" && sha256sum "$(basename "$FINAL")" >"$(basename "$FINAL").sha256" )
cp -- "$FINAL" "$FINAL.sha256" "$EVIDENCE_DIR/" &&
( cd "$EVIDENCE_DIR" && sha256sum -c --quiet "$(basename "$FINAL").sha256" )
EVID_RC=$?

echo "RESULT=PASS"
echo "ARCHIVE=$FINAL"
echo "ARCHIVE_FILES=$MEMBERS"
echo "ARCHIVE_SIZE=$(stat -c '%s' "$FINAL")"
echo "ARCHIVE_SHA256=$(sha256sum "$FINAL" | awk '{print $1}')"
if [ "$EVID_RC" -eq 0 ]; then
    echo "EVIDENCE_COPY=PASS:$EVIDENCE_DIR"
    rm -rf -- "$WORK"
    echo "WORKDIR_REMOVED=YES"
    echo "RC=0"
else
    echo "EVIDENCE_COPY=FAIL"
    echo "WORKDIR_KEPT=$WORK"
    echo "RC=1"
fi
