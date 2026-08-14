#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/securelinux-ng.sh"
TMP_ROOT="$ROOT/.tmp-manifest-writer-contract-regression"
HARNESS="$TMP_ROOT/harness.sh"

main() {
    rm -rf -- "$TMP_ROOT"
    mkdir -p -- "$TMP_ROOT"

    python3 - "$SOURCE" "$HARNESS" <<'PYCONTRACT'
import re
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
harness_path = Path(sys.argv[2])
source = source_path.read_text(encoding="utf-8")

support_functions = {
    "record_manifest_modified_file_best_effort",
    "update_manifest_created_file_state",
    "update_manifest_group_state",
}

writers = {
    "record_manifest_warning": '"warning"',
    "record_manifest_modified_file": '"/tmp/modified"',
    "record_manifest_pending_created_file": '"/tmp/pending"',
    "record_manifest_created_file": '"/tmp/created"',
    "record_manifest_pending_created_group": '"wheel"',
    "record_manifest_created_group": '"wheel"',
    "record_manifest_pending_group_membership": '"wheel" "admin"',
    "record_manifest_added_group_membership": '"wheel" "admin"',
    "record_manifest_apply_report": '"report"',
    "record_manifest_irreversible_change": '"irreversible"',
    "record_manifest_installed_package": '"module" "package"',
    "record_manifest_pending_service_transaction": '"service" "example.service" "enable-now" "disabled" "inactive"',
    "commit_manifest_service_transaction": '"service" "example.service"',
}

matches = list(
    re.finditer(
        r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\(\)[ \t]*\{[ \t]*$",
        source,
    )
)

functions = {}
for index, match in enumerate(matches):
    name = match.group(1)
    if name not in writers and name not in support_functions:
        continue
    end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
    functions[name] = source[match.start():end].rstrip() + "\n"

errors = []
strict_guard = re.compile(
    r'\(\(\s*DRY_RUN\s*==\s*1\s*\)\)\s*&&\s*return\s+0\s*\n'
    r'[ \t]*\[\[\s*-n\s+"\$\{MANIFEST_FILE:-\}"\s*\]\]\s*\|\|\s*return\s+1\s*\n'
    r'[ \t]*\[\[\s*-f\s+"\$MANIFEST_FILE"\s*\]\]\s*\|\|\s*return\s+1'
)

for name in writers:
    body = functions.get(name)
    if body is None:
        errors.append(f"FUNCTION_NOT_FOUND:{name}")
        continue
    if strict_guard.search(body) is None:
        errors.append(f"STRICT_GUARD_MISSING:{name}")
    if re.search(r'MANIFEST_FILE[^\n]*\|\|\s*return\s+0', body):
        errors.append(f"FALSE_SUCCESS_GUARD_PRESENT:{name}")

raw_modified_calls = re.findall(
    r"(?<![A-Za-z0-9_])record_manifest_modified_file(?![A-Za-z0-9_])",
    source,
)
best_effort_calls = re.findall(
    r"(?<![A-Za-z0-9_])record_manifest_modified_file_best_effort(?![A-Za-z0-9_])",
    source,
)

if len(raw_modified_calls) != 3:
    errors.append(
        f"RAW_MODIFIED_FILE_CALL_COUNT:{len(raw_modified_calls)}"
    )
if len(best_effort_calls) != 38:
    errors.append(
        f"BEST_EFFORT_MODIFIED_FILE_CALL_COUNT:{len(best_effort_calls)}"
    )
if (
    'if ! record_manifest_modified_file "$shadow_file"; then'
    not in source
):
    errors.append("STRICT_SHADOW_MODIFIED_FILE_CALL_MISSING")

best_effort_body = functions.get(
    "record_manifest_modified_file_best_effort",
    "",
)
for marker in (
    'if record_manifest_modified_file "$path_value"; then',
    'manifest modified_files не обновлён: $path_value',
    "return 0",
):
    if marker not in best_effort_body:
        errors.append(f"BEST_EFFORT_MARKER_MISSING:{marker}")

if errors:
    for error in errors:
        print(error)
    raise RuntimeError("manifest writer static regression failed")

print("RESULT=MODIFIED_FILE_CALLSITE_CONTRACT_OK")
print("RESULT=MANIFEST_WRITER_CONTRACT_STATIC_OK")

missing_support = support_functions - functions.keys()
if missing_support:
    raise RuntimeError(
        "SUPPORT_FUNCTION_NOT_FOUND:" + ",".join(sorted(missing_support))
    )

function_source = "\n".join(
    functions[name]
    for name in sorted(support_functions)
) + "\n" + "\n".join(functions[name] for name in writers)
call_lines = []
for name, args in writers.items():
    call_lines.append(f'    {name} {args} >/dev/null 2>&1')
    call_lines.append(f'    RC_{name.upper()}=$?')

rc_names = [f"RC_{name.upper()}" for name in writers]
all_fail = " &&\n       ".join(f"(( {name} != 0 ))" for name in rc_names)
all_success = " &&\n       ".join(f"(( {name} == 0 ))" for name in rc_names)
print_lines = "\n".join(f'        "{name}=${{{name}}}" \\' for name in rc_names)

harness = f'''#!/usr/bin/env bash

WARNINGS=()
add_warning() {{ WARNINGS+=("$1"); }}

{function_source}
run_writers() {{
{chr(10).join(call_lines)}
}}

print_writer_rcs() {{
    printf '%s\\n' \\
{print_lines}
        "END_WRITER_RCS=1"
}}

main() {{
    DRY_RUN=0
    MANIFEST_FILE=""
    WARNINGS=()
    record_manifest_modified_file_best_effort "/tmp/best-effort-missing"
    RC_BEST_EFFORT_MISSING=$?

    if (( RC_BEST_EFFORT_MISSING == 0 \
          && ${{#WARNINGS[@]}} == 1 )) \
       && [[ "${{WARNINGS[0]}}" == *"/tmp/best-effort-missing"* ]]
    then
        echo "RESULT=MODIFIED_FILE_BEST_EFFORT_FAILURE_OK"
    else
        echo "RESULT=MODIFIED_FILE_BEST_EFFORT_FAILURE_FAILED"
        return 1
    fi

    WARNINGS=()
    printf '%s\n' '{{}}' > "{harness_path.parent}/best-effort.json"
    MANIFEST_FILE="{harness_path.parent}/best-effort.json"
    record_manifest_modified_file_best_effort "/tmp/best-effort-valid"
    RC_BEST_EFFORT_VALID=$?

    python3 - "{harness_path.parent}/best-effort.json" <<'PYBESTEFFORT'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if data.get("modified_files") != ["/tmp/best-effort-valid"]:
    raise RuntimeError("BEST_EFFORT_MANIFEST_VALUE_INVALID")
PYBESTEFFORT
    RC_BEST_EFFORT_VALIDATION=$?

    if (( RC_BEST_EFFORT_VALID == 0 \
          && RC_BEST_EFFORT_VALIDATION == 0 \
          && ${{#WARNINGS[@]}} == 0 ))
    then
        echo "RESULT=MODIFIED_FILE_BEST_EFFORT_SUCCESS_OK"
    else
        echo "RESULT=MODIFIED_FILE_BEST_EFFORT_SUCCESS_FAILED"
        return 1
    fi

    MANIFEST_FILE=""
    run_writers
    print_writer_rcs
    if {all_fail}; then
        echo "RESULT=MISSING_MANIFEST_VARIABLE_REJECTED"
    else
        echo "RESULT=MISSING_MANIFEST_VARIABLE_FAILED"
        return 1
    fi

    MANIFEST_FILE="{harness_path.parent}/missing.json"
    run_writers
    if {all_fail}; then
        echo "RESULT=MISSING_MANIFEST_FILE_REJECTED"
    else
        echo "RESULT=MISSING_MANIFEST_FILE_FAILED"
        return 1
    fi

    printf '%s\\n' '{{invalid-json' > "{harness_path.parent}/invalid.json"
    MANIFEST_FILE="{harness_path.parent}/invalid.json"
    run_writers
    if {all_fail}; then
        echo "RESULT=INVALID_MANIFEST_REJECTED"
    else
        echo "RESULT=INVALID_MANIFEST_FAILED"
        return 1
    fi

    DRY_RUN=1
    MANIFEST_FILE=""
    run_writers
    if {all_success}; then
        echo "RESULT=DRY_RUN_WITHOUT_MANIFEST_OK"
    else
        echo "RESULT=DRY_RUN_WITHOUT_MANIFEST_FAILED"
        return 1
    fi

    DRY_RUN=0
    printf '%s\\n' '{{}}' > "{harness_path.parent}/valid.json"
    MANIFEST_FILE="{harness_path.parent}/valid.json"
    run_writers
    if ! {all_success}; then
        echo "RESULT=VALID_MANIFEST_WRITES_FAILED"
        return 1
    fi

    python3 - "{harness_path.parent}/valid.json" <<'PYVALID'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {{
    "warnings": ["warning"],
    "modified_files": ["/tmp/modified"],
    "pending_created_files": ["/tmp/pending"],
    "created_files": ["/tmp/created"],
    "pending_created_groups": [],
    "created_groups": ["wheel"],
    "pending_group_memberships": [],
    "added_group_memberships": [{{"group": "wheel", "user": "admin"}}],
    "apply_report": ["report"],
    "irreversible_changes": ["irreversible"],
    "installed_packages": [{{"module": "module", "package": "package"}}],
}}

for key, value in expected.items():
    if data.get(key) != value:
        raise RuntimeError(f"INVALID_MANIFEST_VALUE:{{key}}:{{data.get(key)!r}}")

print("RESULT=VALID_MANIFEST_WRITES_OK")
PYVALID
    RC_VALIDATION=$?

    if (( RC_VALIDATION != 0 )); then
        return 1
    fi

    echo "RESULT=MANIFEST_WRITER_CONTRACT_DYNAMIC_OK"
    return 0
}}

main "$@"
'''

harness_path.write_text(harness, encoding="utf-8")
harness_path.chmod(0o755)
PYCONTRACT
    RC_BUILD=$?

    RC_DYNAMIC=99
    if (( RC_BUILD == 0 )); then
        bash "$HARNESS"
        RC_DYNAMIC=$?
    fi

    rm -rf -- "$TMP_ROOT"

    printf '%s\n' \
        "RC_BUILD=$RC_BUILD" \
        "RC_DYNAMIC=$RC_DYNAMIC"

    if (( RC_BUILD == 0 && RC_DYNAMIC == 0 )); then
        echo "RESULT=MANIFEST_WRITER_CONTRACT_REGRESSION_OK"
        return 0
    fi

    echo "RESULT=MANIFEST_WRITER_CONTRACT_REGRESSION_FAILED"
    return 1
}

main "$@"
