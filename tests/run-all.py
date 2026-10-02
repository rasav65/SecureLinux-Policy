#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import importlib.metadata
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TEST_GLOB = "tests/*/test_*.py"
RELEASE_PREFIX = "tests/release-v1/"
MIN_JSONSCHEMA = (4, 10, 3)

# Exact internal-skip policy for DEV. Unexpected skips are failures.
# schema/runtime uses a real-validator branch only when jsonschema is importable
# under the isolated DEV interpreter; -S deliberately makes DEV stdlib-only.
DEV_EXPECTED_INTERNAL_SKIPS = {
    "tests/gates-v3/test_schema_runtime_parity.py": 2,
}


def expected_internal_skips(rel: str) -> int:
    return DEV_EXPECTED_INTERNAL_SKIPS.get(rel, 0)


def git_lines(*args: str) -> list[str]:
    cp = subprocess.run(
        ["/usr/bin/git", *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed rc={cp.returncode}: {cp.stderr}"
        )
    return [line for line in cp.stdout.splitlines() if line]


def tracked_tests() -> tuple[list[str], list[str]]:
    tracked = sorted(git_lines("ls-files", TEST_GLOB))
    others = git_lines("ls-files", "--others", "--exclude-standard", TEST_GLOB)
    if others:
        raise RuntimeError(
            "untracked test files are not allowed: " + ", ".join(sorted(others))
        )
    release = [x for x in tracked if x.startswith(RELEASE_PREFIX)]
    dev = [x for x in tracked if x not in release]
    if not release:
        raise RuntimeError("release test population is empty")
    return dev, release


def source_shape(path: Path) -> tuple[str, int]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    assert_count = sum(isinstance(node, ast.Assert) for node in ast.walk(tree))
    unittest_main = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if (
            isinstance(fn, ast.Attribute)
            and fn.attr == "main"
            and isinstance(fn.value, ast.Name)
            and fn.value.id == "unittest"
        ):
            unittest_main = True
            break
    return ("unittest" if unittest_main else "script"), assert_count


def parse_unittest_execution(combined: str) -> tuple[bool, int, int]:
    ran = re.findall(r"^Ran\s+(\d+)\s+tests?\s+in\s+", combined, flags=re.MULTILINE)
    if len(ran) != 1:
        return False, 0, 0
    count = int(ran[0])
    if count <= 0:
        return False, count, 0
    ok = re.search(r"^OK(?: \(skipped=(\d+)\))?$", combined, flags=re.MULTILINE)
    if ok is None:
        return False, count, 0
    skips = int(ok.group(1) or "0")
    return True, count, skips


def run_one(rel: str, *, release: bool) -> dict:
    path = ROOT / rel
    style, assert_count = source_shape(path)
    argv = ["/usr/bin/python3", "-I", "-B"]
    if not release:
        argv.insert(2, "-S")
    argv.append(rel)
    cp = subprocess.run(
        argv,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    combined = cp.stdout + cp.stderr
    executed = False
    internal_skips = 0
    detail = ""

    if style == "unittest":
        executed, ran, internal_skips = parse_unittest_execution(combined)
        detail = f"unittest_cases={ran}"
    else:
        # Current standalone regressions are assert-driven scripts with a
        # machine-readable stdout report. Requiring both properties prevents
        # an emptied script from silently passing with RC=0.
        result_markers = [
            line for line in cp.stdout.splitlines()
            if line.startswith("RESULT=") and line.endswith("_OK")
        ]
        executed = (
            bool(cp.stdout.strip())
            and (assert_count > 0 or len(result_markers) == 1)
        )
        detail = (
            f"assert_nodes={assert_count} result_markers={len(result_markers)}"
        )

    expected_skips = 0 if release else expected_internal_skips(rel)
    skip_ok = internal_skips == expected_skips
    warning_free = "ResourceWarning" not in combined
    passed = cp.returncode == 0 and executed and skip_ok and warning_free
    return {
        "path": rel,
        "rc": cp.returncode,
        "style": style,
        "executed": executed,
        "internal_skips": internal_skips,
        "expected_skips": expected_skips,
        "skip_ok": skip_ok,
        "warning_free": warning_free,
        "passed": passed,
        "detail": detail,
        "stdout": cp.stdout,
        "stderr": cp.stderr,
    }


def print_result(prefix: str, rec: dict) -> None:
    state = "PASS" if rec["passed"] else "FAIL"
    print(
        f"{prefix} {state} {rec['path']} rc={rec['rc']} "
        f"executed={str(rec['executed']).lower()} "
        f"skips={rec['internal_skips']}/{rec['expected_skips']} "
        f"resource_warning={str(not rec['warning_free']).lower()} "
        f"{rec['detail']}"
    )
    if not rec["passed"]:
        if rec["stdout"]:
            print("--- stdout ---")
            print(rec["stdout"], end="" if rec["stdout"].endswith("\n") else "\n")
        if rec["stderr"]:
            print("--- stderr ---", file=sys.stderr)
            print(
                rec["stderr"],
                end="" if rec["stderr"].endswith("\n") else "\n",
                file=sys.stderr,
            )


def run_dev(dev: list[str]) -> bool:
    results = [run_one(rel, release=False) for rel in dev]
    for rec in results:
        print_result("DEV", rec)
    passed = sum(int(rec["passed"]) for rec in results)
    failed = len(results) - passed
    skips = sum(rec["internal_skips"] for rec in results)
    print(f"DEV_FILES_TOTAL={len(results)}")
    print(f"DEV_FILES_PASS={passed}")
    print(f"DEV_FILES_FAIL={failed}")
    print(f"DEV_INTERNAL_SKIPS={skips}")
    print("DEV_RESULT=" + ("PASS" if failed == 0 else "FAIL"))
    return failed == 0


def parse_version(raw: str) -> tuple[int, int, int] | None:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", raw.strip())
    return tuple(map(int, m.groups())) if m else None


def release_environment() -> tuple[bool, str]:
    cp = subprocess.run(
        [
            "/usr/bin/python3", "-I", "-B", "-c",
            "import importlib.metadata as m; print(m.version('jsonschema'))",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if cp.returncode != 0:
        return False, "jsonschema>=4.10.3 unavailable"
    version = parse_version(cp.stdout)
    if version is None or version < MIN_JSONSCHEMA:
        return False, f"jsonschema version too old: {cp.stdout.strip() or 'unknown'}"
    return True, cp.stdout.strip()


def release_rc(*, dev_ok: bool, env_ok: bool, release_ok: bool) -> int:
    if not dev_ok:
        return 1
    if not env_ok:
        return 3
    if not release_ok:
        return 2
    return 0


def run_release(dev: list[str], release: list[str], *, with_dev: bool) -> int:
    dev_ok = run_dev(dev) if with_dev else True
    if not dev_ok:
        print("RELEASE_RESULT=BLOCKED_BY_DEV")
        return release_rc(dev_ok=False, env_ok=False, release_ok=False)

    env_ok, env_detail = release_environment()
    if not env_ok:
        print("RELEASE_DEPENDENCY=" + env_detail)
        print("RELEASE_RESULT=BLOCKED_ENVIRONMENT")
        return release_rc(dev_ok=True, env_ok=False, release_ok=False)

    print("RELEASE_JSONSCHEMA_VERSION=" + env_detail)
    results = [run_one(rel, release=True) for rel in release]
    for rec in results:
        print_result("RELEASE", rec)
    release_ok = all(rec["passed"] for rec in results)
    print(f"RELEASE_FILES_TOTAL={len(results)}")
    print(f"RELEASE_FILES_PASS={sum(int(x['passed']) for x in results)}")
    print(f"RELEASE_FILES_FAIL={sum(int(not x['passed']) for x in results)}")
    print("RELEASE_RESULT=" + ("PASS" if release_ok else "FAIL_PROJECT"))
    return release_rc(dev_ok=True, env_ok=True, release_ok=release_ok)


def main() -> int:
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dev", action="store_true")
    mode.add_argument("--release", action="store_true")
    mode.add_argument("--release-only", action="store_true")
    args = ap.parse_args()

    try:
        dev, release = tracked_tests()
    except Exception as exc:
        print("TEST_POPULATION=FAIL")
        print("REASON=" + str(exc))
        return 1

    print(f"TRACKED_TEST_FILES={len(dev) + len(release)}")
    print(f"DEV_TRACKED_FILES={len(dev)}")
    print(f"RELEASE_TRACKED_FILES={len(release)}")

    if args.release_only:
        return run_release(dev, release, with_dev=False)
    if args.release:
        return run_release(dev, release, with_dev=True)
    return 0 if run_dev(dev) else 1


if __name__ == "__main__":
    raise SystemExit(main())
