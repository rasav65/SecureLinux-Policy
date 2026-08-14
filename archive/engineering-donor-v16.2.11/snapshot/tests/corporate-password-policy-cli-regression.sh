#!/usr/bin/env bash

SOURCE="${1:-securelinux-ng.sh}"

python3 - "$SOURCE" <<'PYTEST'
from pathlib import Path
import re
import subprocess
import sys

source = Path(sys.argv[1]).resolve()
text = source.read_text(encoding="utf-8")

project_root = source.parent
readme_text = (
    project_root / "README.md"
).read_text(encoding="utf-8")
architecture_text = (
    project_root / "docs/architecture.md"
).read_text(encoding="utf-8")
changelog_text = (
    project_root / "CHANGELOG.md"
).read_text(encoding="utf-8")
smoke_text = (
    project_root / "tests/smoke.sh"
).read_text(encoding="utf-8")

required_literals = {
    "DEFAULT_DISABLED":
        "ENABLE_CORPORATE_PASSWORD_POLICY=0",
    "CLI_PRIORITY_MARKER":
        "_CORPORATE_PASSWORD_POLICY_SET_BY_CLI=0",
    "USAGE":
        "[--enable-corporate-password-policy]",
    "HELP":
        "--enable-corporate-password-policy",
    "MODE_VALIDATION":
        'die "--enable-corporate-password-policy допустим только вместе с --apply"',
    "MANIFEST_FIELD":
        '"corporate_password_policy_enabled": sys.argv[6] == "1"',
    "MANIFEST_ARGUMENT":
        '"$ENABLE_CORPORATE_PASSWORD_POLICY" <<\'PYJSON\'',
}

required_document_literals = {
    "README_FLAG": (
        readme_text,
        "--enable-corporate-password-policy",
    ),
    "README_INDEPENDENCE": (
        readme_text,
        "являются независимыми флагами",
    ),
    "README_MANIFEST_FIELD": (
        readme_text,
        '"corporate_password_policy_enabled": true',
    ),
    "ARCHITECTURE_FLAG": (
        architecture_text,
        "--enable-corporate-password-policy",
    ),
    "ARCHITECTURE_MANIFEST_FIELD": (
        architecture_text,
        "`corporate_password_policy_enabled`",
    ),
    "CHANGELOG_FLAG": (
        changelog_text,
        "--enable-corporate-password-policy",
    ),
    "SMOKE_TEST_ENTRY": (
        smoke_text,
        "bash tests/corporate-password-policy-cli-regression.sh &&",
    ),
    "SMOKE_HELP_ENTRY": (
        smoke_text,
        './securelinux-ng.sh --help | grep -q -- '
        '"--enable-corporate-password-policy" &&',
    ),
}

failures = []

for label, value in required_literals.items():
    if value not in text:
        failures.append(f"MISSING_LITERAL:{label}:{value}")

for label, pair in required_document_literals.items():
    document, value = pair

    if value not in document:
        failures.append(
            f"MISSING_DOCUMENT_LITERAL:{label}:{value}"
        )

parser_pattern = re.compile(
    r'--enable-corporate-password-policy\)\n'
    r'\s+ENABLE_CORPORATE_PASSWORD_POLICY=1\n'
    r'\s+_CORPORATE_PASSWORD_POLICY_SET_BY_CLI=1\n'
    r'\s+;;'
)

if parser_pattern.search(text) is None:
    failures.append("CLI_PARSER_CONTRACT")

config_true_pattern = re.compile(
    r'1\|true\|yes\|on\)\n'
    r'\s+\(\( _CORPORATE_PASSWORD_POLICY_SET_BY_CLI == 0 \)\) '
    r'&& ENABLE_CORPORATE_PASSWORD_POLICY=1'
)

config_false_pattern = re.compile(
    r'0\|false\|no\|off\|""\)\n'
    r'\s+\(\( _CORPORATE_PASSWORD_POLICY_SET_BY_CLI == 0 \)\) '
    r'&& ENABLE_CORPORATE_PASSWORD_POLICY=0'
)

if config_true_pattern.search(text) is None:
    failures.append("CONFIG_TRUE_CLI_PRIORITY")

if config_false_pattern.search(text) is None:
    failures.append("CONFIG_FALSE_CLI_PRIORITY")

help_result = subprocess.run(
    [str(source), "--help"],
    cwd=source.parent,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    check=False,
)

if help_result.returncode != 0:
    failures.append(f"HELP_RC:{help_result.returncode}")

if "--enable-corporate-password-policy" not in help_result.stdout:
    failures.append("HELP_FLAG_MISSING")

expected_error = (
    "--enable-corporate-password-policy "
    "допустим только вместе с --apply"
)

for mode in ("check", "restore", "report"):
    result = subprocess.run(
        [
            str(source),
            f"--{mode}",
            "--enable-corporate-password-policy",
        ],
        cwd=source.parent,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    print(
        f"MODE={mode}:RC={result.returncode}:"
        f"EXPECTED_REJECTION={expected_error in result.stdout}"
    )

    if result.returncode == 0:
        failures.append(f"INVALID_MODE_ACCEPTED:{mode}")

    if expected_error not in result.stdout:
        failures.append(f"INVALID_MODE_MESSAGE:{mode}")

print(f"FAILURE_COUNT={len(failures)}")

for failure in failures:
    print(f"FAIL={failure}")

if failures:
    raise SystemExit(1)

print("RESULT=CORPORATE_PASSWORD_POLICY_CLI_REGRESSION_OK")
PYTEST

RC_TEST=$?

echo "RC_TEST=$RC_TEST"

if [[ "$RC_TEST" == "0" ]]; then
    echo 'RESULT=CORPORATE_PASSWORD_POLICY_CLI_REGRESSION_OK'
else
    echo 'FAIL=CORPORATE_PASSWORD_POLICY_CLI_REGRESSION'
fi
