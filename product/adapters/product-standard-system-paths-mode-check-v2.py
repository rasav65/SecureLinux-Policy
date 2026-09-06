#!/usr/bin/env python3
# Read-only adapter SRC-0012: стандартные executable/library/module paths.
import re

SEMANTIC_CONTRACT_ID = "standard-system-paths-mode-check-semantic-v2"
ADAPTER_ID = "product-standard-system-paths-mode-check-v2"
ADAPTER_CONTRACT_VERSION = "product-standard-system-paths-mode-check-adapter-v2"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "standard-system-paths-mode"
SUPPORTED_OPS = ("bits-clear",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/bin|/sbin|/usr/bin|/usr/sbin|<root-PATH>|/lib|/lib64|/usr/lib|/usr/lib64|/usr/local/lib|/usr/local/lib64|/lib/modules/<uname-r>"
CANONICAL_EXEC_ROOTS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin")
CANONICAL_LIB_ROOTS = ("/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64")
CANONICAL_MODULE_TEMPLATE = "/lib/modules/<uname-r>"
EXPECTED_MASK = "0022"

def _mode_compliance(mode_text, expected=EXPECTED_MASK):
    if not isinstance(mode_text, str) or re.fullmatch(r"[0-7]{3,4}", mode_text) is None:
        return None
    return (int(mode_text, 8) & int(expected, 8)) == 0

def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

_OBSERVER = 'import os\nimport stat\nimport subprocess\nimport sys\n\nclass ObservationError(Exception):\n    pass\n\ndef error(reason):\n    raise ObservationError(reason)\n\ndef resolve(path, role):\n    try:\n        proc = subprocess.run([b"/usr/bin/readlink", b"-f", b"--", path],\n                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)\n    except OSError:\n        error(role + ":resolve-failed")\n    if proc.returncode != 0:\n        error(role + ":resolve-failed")\n    result = proc.stdout.rstrip(b"\\n")\n    if not result:\n        error(role + ":resolve-empty")\n    return result\n\ndef entries(root):\n    try:\n        proc = subprocess.run([b"/usr/bin/find", b"-P", b"--", root,\n                               b"-mindepth", b"1", b"-print0"],\n                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)\n    except OSError:\n        error("scan:find-failed")\n    if proc.returncode != 0:\n        error("scan:find-failed")\n    if proc.stdout and not proc.stdout.endswith(b"\\0"):\n        error("scan:missing-marker")\n    try:\n        return sorted(proc.stdout.split(b"\\0")[:-1]) if proc.stdout else []\n    except MemoryError:\n        error("scan:sort-failed")\n\ndef observe():\n    mask = int(sys.argv[2], 8)\n    ne, nl = int(sys.argv[3]), int(sys.argv[4])\n    paths = [os.fsencode(p) for p in sys.argv[5:]]\n    if len(paths) != ne + nl + 1:\n        error("runtime:observer-arguments")\n    groups = (("exec", paths[:ne]), ("lib", paths[ne:ne+nl]), ("module", paths[ne+nl:]))\n    seen_roots, seen_targets = set(), set()\n    exec_root_ids = set()\n    for root in paths[:ne]:\n        try:\n            info = os.stat(root)\n        except OSError:\n            continue\n        if stat.S_ISDIR(info.st_mode):\n            exec_root_ids.add((info.st_dev, info.st_ino))\n    present = absent = aliases = checked = violations = 0\n    _slp_exec = _slp_libraries = _slp_modules = 0\n    for role, roots in groups:\n        for root in roots:\n            try:\n                os.lstat(root)\n            except FileNotFoundError:\n                absent += 1\n                continue\n            except OSError:\n                error("root:resolve-failed")\n            resolved = resolve(root, "root")\n            if not os.path.isdir(resolved):\n                error("root:invalid-type")\n            try:\n                info = os.stat(resolved)\n            except OSError:\n                error("root:identity-failed")\n            present += 1\n            identity = (info.st_dev, info.st_ino)\n            if identity in seen_roots:\n                aliases += 1\n                continue\n            seen_roots.add(identity)\n            for entry in entries(resolved):\n                if os.path.isdir(entry) and not os.path.islink(entry):\n                    continue\n                name = os.path.basename(entry)\n                if role == "lib" and not (name.endswith(b".so") or b".so." in name or name.endswith(b".a")):\n                    continue\n                if role == "module" and not (name.endswith(b".ko") or b".ko." in name):\n                    continue\n                if os.path.islink(entry):\n                    target = resolve(entry, "target")\n                    if os.path.islink(target):\n                        error("target:resolved-symlink")\n                    if not os.path.isfile(target):\n                        if role == "exec" and os.path.isdir(target):\n                            try:\n                                dinfo = os.stat(target)\n                            except OSError:\n                                error("target:identity-failed")\n                            if (dinfo.st_dev, dinfo.st_ino) in exec_root_ids:\n                                continue\n                        error("target:invalid-type")\n                elif os.path.isfile(entry):\n                    target = entry\n                else:\n                    error("target:invalid-type")\n                try:\n                    info = os.stat(target)\n                except OSError:\n                    error("target:identity-failed")\n                if not stat.S_ISREG(info.st_mode):\n                    error("target:invalid-type")\n                mode = stat.S_IMODE(info.st_mode)\n                if len(format(mode, "o")) not in (3, 4):\n                    error("target:invalid-mode")\n                if role == "exec" and not mode & 0o111:\n                    continue\n                identity = (info.st_dev, info.st_ino)\n                if identity in seen_targets:\n                    continue\n                seen_targets.add(identity)\n                if role == "exec":\n                    _slp_exec += 1\n                elif role == "lib":\n                    _slp_libraries += 1\n                else:\n                    _slp_modules += 1\n                checked += 1\n                if mode & mask:\n                    violations += 1\n    if _slp_exec == 0:\n        error("population:missing-exec")\n    if _slp_libraries == 0:\n        error("population:missing-libraries")\n    if _slp_modules == 0:\n        error("population:missing-modules")\n    value = (f"roots_present={present};roots_absent={absent};aliases={aliases};"\n             f"exec={_slp_exec};libraries={_slp_libraries};modules={_slp_modules};"\n             f"checked={checked};violations={violations}")\n    return "VALUE", value, "FAIL" if violations else "PASS"\n\ntry:\n    status, value, compliance = observe()\nexcept ObservationError as exc:\n    status, value, compliance = "ERROR", str(exc), "ERROR"\nexcept Exception:\n    status, value, compliance = "ERROR", "runtime:observer-failed", "ERROR"\nprint("\\t".join(("SLP-CHECK-V1", sys.argv[1], status, value, compliance)))\n'

def _render(control_id, exec_roots, lib_roots, module_root, expected=EXPECTED_MASK, dynamic_module=False, dynamic_root_path=False):
    cid = _sh_single(control_id)
    exec_shell = " ".join(_sh_single(x) for x in exec_roots)
    lib_shell = " ".join(_sh_single(x) for x in lib_roots)
    module_shell = _sh_single(module_root)
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    lines = [
        fn + "() {",
        "  local _slp_expected=" + _sh_single(expected) + " _slp_role _slp_root _slp_resolved _slp_root_id",
        "  local _slp_entry _slp_name _slp_candidate _slp_mode _slp_ident _slp_target _slp_scan_marker",
        "  local _slp_find_rc _slp_sort_rc _slp_i _slp_uname_r='' _slp_path_env='' _slp_path_part",
        "  local _slp_roots_present=0 _slp_roots_absent=0 _slp_aliases=0",
        "  local _slp_exec=0 _slp_libraries=0 _slp_modules=0 _slp_checked=0 _slp_violations=0",
        "  local -a _slp_exec_roots=(" + exec_shell + ") _slp_lib_roots=(" + lib_shell + ") _slp_entries=() _slp_path_roots=()",
        "  local _slp_module_root=" + module_shell,
        "  local -A _slp_seen_roots=() _slp_seen_targets=()",
    ]
    if dynamic_root_path:
        lines += [
            '  if (( EUID != 0 )); then',
            emit + ' "ERROR" "runtime:requires-root" "ERROR"',
            '    return 0',
            '  fi',
            '  _slp_path_env=${PATH-}',
            "  if [[ -z \"$_slp_path_env\" || \"$_slp_path_env\" == *$'\\r'* || \"$_slp_path_env\" == *$'\\n'* || \"$_slp_path_env\" == *$'\\t'* ]]; then",
            emit + ' "ERROR" "path:invalid-environment" "ERROR"',
            '    return 0',
            '  fi',
            '  IFS=: read -r -a _slp_path_roots <<< "$_slp_path_env"',
            '  (( ${#_slp_path_roots[@]} > 0 )) || { ' + emit.strip() + ' "ERROR" "path:empty-environment" "ERROR"; return 0; }',
            '  for _slp_path_part in "${_slp_path_roots[@]}"; do',
            '    [[ "$_slp_path_part" == /* ]] || { ' + emit.strip() + ' "ERROR" "path:nonabsolute-entry" "ERROR"; return 0; }',
            '    _slp_exec_roots+=("$_slp_path_part")',
            '  done',
        ]
    if dynamic_module:
        lines += [
            "  if ! _slp_uname_r=$(command /usr/bin/uname -r 2>/dev/null); then",
            emit + ' "ERROR" "kernel:release-query-failed" "ERROR"',
            "    return 0",
            "  fi",
            "  if [[ -z $_slp_uname_r || $_slp_uname_r == *$'\\n'* || $_slp_uname_r == *$'\\r'* ]]; then",
            emit + ' "ERROR" "kernel:invalid-release" "ERROR"',
            "    return 0",
            "  fi",
            '  _slp_module_root=${_slp_module_root/<uname-r>/$_slp_uname_r}',
        ]
    lines += [
        '  if [[ ! -x /usr/bin/python3 ]]; then',
        emit + ' "ERROR" "runtime:python3-missing" "ERROR"',
        '    return 0',
        '  fi',
        "  local _slp_observed=''",
        '  if ! _slp_observed=$(LC_ALL=C command /usr/bin/python3 -I -S -B - ' + cid +
        ' "$_slp_expected" "${#_slp_exec_roots[@]}" "${#_slp_lib_roots[@]}"' +
        ' "${_slp_exec_roots[@]}" "${_slp_lib_roots[@]}" "$_slp_module_root" 2>/dev/null <<\'SLP_SRC0012_PY\'',
        _OBSERVER.rstrip("\n"),
        'SLP_SRC0012_PY',
        '  ); then',
        emit + ' "ERROR" "runtime:observer-failed" "ERROR"',
        '    return 0',
        '  fi',
        '  printf "%s\\n" "$_slp_observed"',
        '  return 0',
        '}',
    ]
    return "\n".join(lines) + "\n"

def shell_function(control_id, locator, key, op, expected):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if locator != CANONICAL_LOCATOR or key != "mode" or op != "bits-clear" or expected != EXPECTED_MASK:
        raise ValueError("only canonical SRC-0012 standard-system-paths contract is supported")
    return _render(control_id, CANONICAL_EXEC_ROOTS, CANONICAL_LIB_ROOTS, CANONICAL_MODULE_TEMPLATE, expected, dynamic_module=True, dynamic_root_path=True)

def _shell_function_for_layout(control_id, exec_roots, lib_roots, module_root, expected=EXPECTED_MASK):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    roots = tuple(exec_roots) + tuple(lib_roots) + (module_root,)
    if any(not isinstance(x, str) or not x.startswith("/") for x in roots):
        raise ValueError("absolute test roots required")
    return _render(control_id, tuple(exec_roots), tuple(lib_roots), module_root, expected, dynamic_module=False, dynamic_root_path=False)

MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)

def _selftest():
    assert _mode_compliance("755") is True
    assert _mode_compliance("0644") is True
    assert _mode_compliance("0775") is False
    assert _mode_compliance("0664") is False
    assert _mode_compliance("bogus") is None
    src = shell_function("CTRL", CANONICAL_LOCATOR, "mode", "bits-clear", "0022")
    assert "command /usr/bin/python3 -I -S -B" in src and "/usr/bin/find" in src and "/usr/bin/readlink" in src
    assert "/usr/bin/stat" not in src
    assert "/lib/modules/<uname-r>" in src and "command /usr/bin/uname -r" in src and "${PATH-}" in src and "EUID != 0" in src
    assert "libraries=" in src and "modules=" in src and "violations=" in src
    for token in MUTATING_TOKENS:
        assert token not in src, token
    for args in (
        ("CTRL", "/bin", "mode", "bits-clear", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "owner", "bits-clear", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "eq", "0022"),
        ("CTRL", CANONICAL_LOCATOR, "mode", "bits-clear", "0033"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")

if __name__ == "__main__":
    _selftest()
