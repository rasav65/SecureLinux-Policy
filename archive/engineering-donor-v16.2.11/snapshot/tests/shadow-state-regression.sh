#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-shadow-state-regression"
HARNESS="$TMP_ROOT/harness.sh"

rm -rf -- "$TMP_ROOT"
mkdir -p -- "$TMP_ROOT"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

python3 - "$SOURCE" "$HARNESS" <<'PYBUILD'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
harness = Path(sys.argv[2])
functions = [
    "record_manifest_empty_password_state",
    "remove_manifest_empty_password_state",
    "restore_manifest_empty_password_state",
    "apply_empty_passwords_module",
    "restore_empty_passwords_module",
]

matches = list(
    re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
        source,
    )
)
blocks = {}
for index, match in enumerate(matches):
    name = match.group(1)
    if name not in functions:
        continue
    end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
    blocks[name] = source[match.start():end]

missing = [name for name in functions if name not in blocks]
if missing:
    raise RuntimeError("missing functions: " + ",".join(missing))

apply_block = blocks["apply_empty_passwords_module"].replace(
    "if (( EUID != 0 )); then",
    "if (( 0 != 0 )); then",
    1,
)
blocks["apply_empty_passwords_module"] = apply_block

payload = "#!/usr/bin/env bash\n\n" + "\n".join(blocks[name] for name in functions)
payload += r'''

DRY_RUN=0
DEBUG_LOG_FILE=/dev/null
ERRORS=()
WARNINGS=()
SAFE=()
SKIPPED=()

log() { :; }
add_error() { ERRORS+=("$1"); }
add_warning() { WARNINGS+=("$1"); }
add_safe() { SAFE+=("$1"); }
add_skipped() { SKIPPED+=("$1"); }
record_manifest_warning() { return 0; }
record_manifest_modified_file() { return 0; }
record_manifest_apply_report() { return 0; }
check_empty_passwords_module() { return 0; }

write_manifest() {
    local path="$1"
    python3 - "$path" <<'PYJSON'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
path.write_text(
    json.dumps(
        {
            "module_state": {},
            "backups": [],
            "modified_files": [],
            "apply_report": [],
        },
        indent=2,
    ) + "\n",
    encoding="utf-8",
)
PYJSON
}

scenario_normal() {
    local base="$1/normal"
    mkdir -p -- "$base/state"
    STATE_DIR="$base/state"
    TIMESTAMP=20260804-120000
    MANIFEST_FILE="$base/manifest.json"
    SECURELINUX_NG_SHADOW_FILE="$base/shadow"
    printf 'root::1:2:3:4:5:6:7\nuser:!:1:2:3:4:5:6:7\n' > "$SECURELINUX_NG_SHADOW_FILE"
    chmod 0640 "$SECURELINUX_NG_SHADOW_FILE"
    write_manifest "$MANIFEST_FILE"
    ERRORS=(); WARNINGS=(); SAFE=(); SKIPPED=()

    apply_empty_passwords_module
    local apply_rc=$?
    local mode
    mode="$(stat -c '%a' "$SECURELINUX_NG_SHADOW_FILE")"
    local users_file="$STATE_DIR/empty-password-users-$TIMESTAMP.txt"

    python3 - "$MANIFEST_FILE" "$users_file" "$SECURELINUX_NG_SHADOW_FILE" <<'PYCHECK'
import json
import pathlib
import sys
manifest = pathlib.Path(sys.argv[1])
users_file = sys.argv[2]
shadow_path = sys.argv[3]
data = json.loads(manifest.read_text(encoding="utf-8"))
state = data["module_state"]["empty_passwords"]
assert state == {
    "applied": True,
    "users_file": users_file,
    "shadow_path": shadow_path,
    "restore_policy": "security-preserving-nonrestore",
}
assert data.get("backups") == []
PYCHECK
    local manifest_rc=$?

    RESTORE_SOURCE_MANIFEST="$MANIFEST_FILE"
    restore_empty_passwords_module
    local restore_rc=$?

    printf '%s\n' \
        "NORMAL_APPLY_RC=$apply_rc" \
        "NORMAL_RESTORE_RC=$restore_rc" \
        "NORMAL_MANIFEST_RC=$manifest_rc" \
        "NORMAL_MODE=$mode" \
        "NORMAL_ERRORS=${#ERRORS[@]}" \
        "NORMAL_WARNINGS=${#WARNINGS[@]}"

    [[ "$apply_rc" -eq 0 ]] &&
    [[ "$restore_rc" -eq 0 ]] &&
    [[ "$manifest_rc" -eq 0 ]] &&
    [[ "$mode" == 640 ]] &&
    grep -qxF 'root:!:1:2:3:4:5:6:7' "$SECURELINUX_NG_SHADOW_FILE" &&
    grep -qxF 'root' "$users_file" &&
    [[ "${#ERRORS[@]}" -eq 0 ]] &&
    [[ "${#WARNINGS[@]}" -eq 1 ]]
}

scenario_symlink() {
    local base="$1/symlink"
    mkdir -p -- "$base/state"
    STATE_DIR="$base/state"
    TIMESTAMP=20260804-120100
    MANIFEST_FILE="$base/manifest.json"
    SECURELINUX_NG_SHADOW_FILE="$base/shadow"
    printf 'root::1:2:3:4:5:6:7\n' > "$base/target"
    ln -s target "$SECURELINUX_NG_SHADOW_FILE"
    write_manifest "$MANIFEST_FILE"
    ERRORS=(); WARNINGS=(); SAFE=(); SKIPPED=()

    apply_empty_passwords_module
    local apply_rc=$?
    local state_count
    state_count="$(python3 - "$MANIFEST_FILE" <<'PYCOUNT'
import json, pathlib, sys
print(len(json.loads(pathlib.Path(sys.argv[1]).read_text())["module_state"]))
PYCOUNT
)"

    printf '%s\n' \
        "SYMLINK_APPLY_RC=$apply_rc" \
        "SYMLINK_IS_LINK=$([[ -L "$SECURELINUX_NG_SHADOW_FILE" ]] && echo yes || echo no)" \
        "SYMLINK_STATE_COUNT=$state_count" \
        "SYMLINK_ERRORS=${#ERRORS[@]}"

    [[ "$apply_rc" -eq 1 ]] &&
    [[ -L "$SECURELINUX_NG_SHADOW_FILE" ]] &&
    grep -qxF 'root::1:2:3:4:5:6:7' "$base/target" &&
    [[ "$state_count" -eq 0 ]] &&
    [[ "${#ERRORS[@]}" -eq 1 ]] &&
    [[ ! -e "$STATE_DIR/empty-password-users-$TIMESTAMP.txt" ]]
}

scenario_writer_failure() {
    local base="$1/writer-failure"
    mkdir -p -- "$base/state"
    STATE_DIR="$base/state"
    TIMESTAMP=20260804-120200
    MANIFEST_FILE="$base/manifest.json"
    SECURELINUX_NG_SHADOW_FILE="$base/shadow"
    printf 'root::1:2:3:4:5:6:7\n' > "$SECURELINUX_NG_SHADOW_FILE"
    write_manifest "$MANIFEST_FILE"
    ERRORS=(); WARNINGS=(); SAFE=(); SKIPPED=()

    record_manifest_empty_password_state() { return 1; }
    apply_empty_passwords_module
    local apply_rc=$?

    printf '%s\n' \
        "WRITER_FAILURE_RC=$apply_rc" \
        "WRITER_FAILURE_ERRORS=${#ERRORS[@]}"

    [[ "$apply_rc" -eq 1 ]] &&
    grep -qxF 'root::1:2:3:4:5:6:7' "$SECURELINUX_NG_SHADOW_FILE" &&
    [[ "${#ERRORS[@]}" -eq 1 ]] &&
    [[ ! -e "$STATE_DIR/empty-password-users-$TIMESTAMP.txt" ]] &&
    [[ -z "$(find "$base" -maxdepth 1 -name '.shadow.tmp.*' -print -quit)" ]]
}

scenario_missing_typed_file() {
    local base="$1/missing-state-file"
    mkdir -p -- "$base"
    RESTORE_SOURCE_MANIFEST="$base/manifest.json"
    python3 - "$RESTORE_SOURCE_MANIFEST" <<'PYJSON'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "module_state": {
        "empty_passwords": {
            "applied": True,
            "users_file": str(path.parent / "missing.txt"),
            "shadow_path": "/etc/shadow",
            "restore_policy": "security-preserving-nonrestore",
        }
    },
    "backups": [],
}) + "\n")
PYJSON
    ERRORS=(); WARNINGS=(); SAFE=(); SKIPPED=()
    restore_empty_passwords_module
    local restore_rc=$?
    printf '%s\n' \
        "MISSING_TYPED_FILE_RC=$restore_rc" \
        "MISSING_TYPED_FILE_ERRORS=${#ERRORS[@]}"
    [[ "$restore_rc" -eq 1 ]] && [[ "${#ERRORS[@]}" -eq 1 ]]
}

scenario_legacy() {
    local base="$1/legacy"
    mkdir -p -- "$base"
    local users_file="$base/empty-password-users-old.txt"
    printf 'root\n' > "$users_file"
    RESTORE_SOURCE_MANIFEST="$base/manifest.json"
    python3 - "$RESTORE_SOURCE_MANIFEST" "$users_file" <<'PYJSON'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "backups": [{"original": "/etc/shadow", "backup": sys.argv[2]}]
}) + "\n")
PYJSON
    ERRORS=(); WARNINGS=(); SAFE=(); SKIPPED=()
    restore_empty_passwords_module
    local restore_rc=$?
    printf '%s\n' \
        "LEGACY_RESTORE_RC=$restore_rc" \
        "LEGACY_WARNINGS=${#WARNINGS[@]}"
    [[ "$restore_rc" -eq 0 ]] && [[ "${#WARNINGS[@]}" -eq 2 ]]
}

BASE="$1"
scenario_normal "$BASE"; RC_NORMAL=$?
scenario_symlink "$BASE"; RC_SYMLINK=$?
scenario_writer_failure "$BASE"; RC_WRITER=$?
scenario_missing_typed_file "$BASE"; RC_MISSING=$?
scenario_legacy "$BASE"; RC_LEGACY=$?

printf '%s\n' \
    "RC_NORMAL=$RC_NORMAL" \
    "RC_SYMLINK=$RC_SYMLINK" \
    "RC_WRITER=$RC_WRITER" \
    "RC_MISSING=$RC_MISSING" \
    "RC_LEGACY=$RC_LEGACY"

if (( RC_NORMAL == 0 && RC_SYMLINK == 0 && RC_WRITER == 0 && RC_MISSING == 0 && RC_LEGACY == 0 )); then
    echo "RESULT=SHADOW_STATE_DYNAMIC_REGRESSION_OK"
    exit 0
fi

echo "RESULT=SHADOW_STATE_DYNAMIC_REGRESSION_FAILED"
exit 1
'''

harness.write_text(payload, encoding="utf-8")
harness.chmod(0o755)
PYBUILD
RC_BUILD=$?

python3 - "$SOURCE" <<'PYSTATIC'
import re
import sys
from pathlib import Path
source = Path(sys.argv[1]).read_text(encoding="utf-8")
errors = []

def block(name):
    matches = list(re.finditer(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$", source))
    for index, match in enumerate(matches):
        if match.group(1) == name:
            end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
            return source[match.start():end]
    errors.append("FUNCTION_MISSING:" + name)
    return ""

apply = block("apply_empty_passwords_module")
restore = block("restore_empty_passwords_module")
for helper in (
    "record_manifest_empty_password_state",
    "remove_manifest_empty_password_state",
    "restore_manifest_empty_password_state",
):
    block(helper)

if 'record_manifest_backup \\\n        "/etc/shadow"' in apply:
    errors.append("GENERIC_SHADOW_BACKUP_STILL_USED")
if 'record_manifest_empty_password_state' not in apply:
    errors.append("TYPED_STATE_WRITER_MISSING")
if 'remove_manifest_empty_password_state' not in apply:
    errors.append("TYPED_STATE_ROLLBACK_MISSING")
if '[[ -L "$shadow_file" ]]' not in apply:
    errors.append("SHADOW_SYMLINK_GUARD_MISSING")
if 'shadow.is_symlink()' not in apply:
    errors.append("PYTHON_SHADOW_SYMLINK_GUARD_MISSING")
if 'restore_manifest_empty_password_state' not in restore:
    errors.append("TYPED_RESTORE_LOOKUP_MISSING")
if 'security-preserving-nonrestore' not in source:
    errors.append("RESTORE_POLICY_CLASSIFICATION_MISSING")

if errors:
    for error in errors:
        print("FAIL=" + error)
    raise SystemExit(1)

print("RESULT=SHADOW_STATE_STATIC_REGRESSION_OK")
PYSTATIC
RC_STATIC=$?

if (( RC_BUILD == 0 )); then
    bash "$HARNESS" "$TMP_ROOT"
    RC_DYNAMIC=$?
else
    RC_DYNAMIC=1
fi

printf '%s\n' \
    "RC_BUILD=$RC_BUILD" \
    "RC_STATIC=$RC_STATIC" \
    "RC_DYNAMIC=$RC_DYNAMIC"

if (( RC_BUILD == 0 && RC_STATIC == 0 && RC_DYNAMIC == 0 )); then
    echo "RESULT=SHADOW_STATE_REGRESSION_OK"
    exit 0
fi

echo "RESULT=SHADOW_STATE_REGRESSION_FAILED"
exit 1
