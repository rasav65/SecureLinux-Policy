#!/usr/bin/env python3
# Read-only adapter SRC-0004: active sudoers user specifications must be the stock rules only.
import re

SEMANTIC_CONTRACT_ID = "sudoers-reviewed-policy-check-semantic-v1"
ADAPTER_ID = "product-sudoers-reviewed-policy-check-v1"
ADAPTER_CONTRACT_VERSION = "product-sudoers-reviewed-policy-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "sudoers-reviewed-policy"
SUPPORTED_OPS = ("standard-rules-only",)
CANONICAL_LOCATOR = "/etc/sudoers"
CANONICAL_KEY = "user-specs"
CANONICAL_OP = "standard-rules-only"
CANONICAL_EXPECTED = "root ALL=(ALL:ALL) ALL;%sudo ALL=(ALL:ALL) ALL;%admin ALL=(ALL) ALL"
DEFAULT_VISUDO = "/usr/sbin/visudo"
DEFAULT_CVTSUDOERS = "/usr/bin/cvtsudoers"

_PY = 'import hashlib, json, os, stat, subprocess, sys\nfrom pathlib import Path\n\nsudoers_path = Path(sys.argv[1])\nvisudo_path = sys.argv[2]\ncvtsudoers_path = sys.argv[3]\nENV = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}\n\n\ndef error(reason):\n    print("ERROR\\t" + reason)\n    raise SystemExit(0)\n\n\ndef stock_rule(invoker, runas_group):\n    spec = {"runasusers": [{"username": "ALL"}]}\n    if runas_group:\n        spec["runasgroups"] = [{"usergroup": "ALL"}]\n    # cvtsudoers reports the command ALL with its implied SETENV tag.\n    spec["Options"] = [{"setenv": True}]\n    spec["Commands"] = [{"command": "ALL"}]\n    return {"User_List": [invoker], "Host_List": [{"hostname": "ALL"}], "Cmnd_Specs": [spec]}\n\n\n# The only admissible user specifications: the rules a Debian-family installer\n# writes.  Group membership and Defaults are not evaluated.\nSTOCK_RULES = frozenset(json.dumps(rule, sort_keys=True) for rule in (\n    stock_rule({"username": "root"}, True),     # root ALL=(ALL:ALL) ALL\n    stock_rule({"usergroup": "sudo"}, True),    # %sudo ALL=(ALL:ALL) ALL\n    stock_rule({"usergroup": "admin"}, False),  # %admin ALL=(ALL) ALL\n))\n\n\ndef obj_state(st):\n    return (st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_ctime_ns, st.st_mtime_ns, st.st_size, st.st_nlink)\n\n\ndef stable_regular_bytes(path, domain):\n    try:\n        first = os.lstat(path)\n    except Exception:\n        error(domain + ":lstat-failed")\n    if stat.S_ISLNK(first.st_mode) or not stat.S_ISREG(first.st_mode):\n        error(domain + ":invalid-type")\n    try:\n        raw = path.read_bytes()\n        second = os.lstat(path)\n    except Exception:\n        error(domain + ":read-failed")\n    if obj_state(first) != obj_state(second):\n        error(domain + ":changed-during-check")\n    return obj_state(first), raw\n\n\ndef policy_snapshot():\n    # The sudoers pathset is the closure that visudo reports after validating the\n    # active tree; no reviewed-policy file is read.  Identities and bytes of that\n    # pathset are compared between the two policy observations of one check.\n    try:\n        proc = subprocess.run([visudo_path, "-c", "-f", str(sudoers_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENV, check=False)\n    except Exception:\n        error("visudo:execution-failed")\n    if proc.returncode != 0:\n        error("visudo:validation-failed")\n    if not proc.stdout:\n        error("visudo:invalid-output")\n    if b"\\x00" in proc.stdout or b"\\r" in proc.stdout:\n        error("visudo:invalid-bytes")\n    try:\n        text = proc.stdout.decode("utf-8", errors="strict")\n    except UnicodeDecodeError:\n        error("visudo:invalid-bytes")\n    closure = []\n    for line in text.splitlines():\n        suffix = ": parsed OK"\n        if not line.endswith(suffix):\n            error("visudo:invalid-output")\n        path_text = line[:-len(suffix)]\n        if not path_text.startswith("/") or any(c in path_text for c in "\\x00\\r\\n\\t") or path_text in closure:\n            error("visudo:invalid-output")\n        closure.append(path_text)\n    if not closure or str(sudoers_path) not in closure:\n        error("visudo:invalid-output")\n    out = []\n    for path_text in sorted(closure):\n        state, raw = stable_regular_bytes(Path(path_text), "sudoers")\n        out.append((path_text, state, hashlib.sha256(raw).hexdigest()))\n    return tuple(out)\n\n\ndef cvt_snapshot():\n    try:\n        proc = subprocess.run(\n            [cvtsudoers_path, "-c", "/dev/null", "-e", "-s", "aliases", "-f", "json", str(sudoers_path)],\n            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, check=False,\n        )\n    except Exception:\n        error("cvtsudoers:execution-failed")\n    if proc.returncode != 0 or proc.stderr:\n        error("cvtsudoers:execution-failed")\n    if not proc.stdout:\n        error("cvtsudoers:invalid-output")\n    if b"\\x00" in proc.stdout:\n        error("cvtsudoers:invalid-bytes")\n    try:\n        data = json.loads(proc.stdout.decode("utf-8", errors="strict"))\n    except Exception:\n        error("cvtsudoers:invalid-output")\n    if not isinstance(data, dict) or set(data) - {"Defaults", "User_Specs"}:\n        error("cvtsudoers:invalid-output")\n    specs = data.get("User_Specs", [])\n    if not isinstance(specs, list):\n        error("cvtsudoers:invalid-output")\n    return proc.stdout, specs\n\n\ndef count_nonstandard(specs):\n    nonstandard = 0\n    for user_spec in specs:\n        if not isinstance(user_spec, dict) or set(user_spec) != {"User_List", "Host_List", "Cmnd_Specs"}:\n            error("sudo-policy:invalid-user-spec")\n        # Canonical JSON keeps JSON true distinct from 1.\n        if json.dumps(user_spec, sort_keys=True) not in STOCK_RULES:\n            nonstandard += 1\n    return nonstandard\n\n\npolicy_before = policy_snapshot()\ncvt_before, specs = cvt_snapshot()\nnonstandard = count_nonstandard(specs)\npolicy_after = policy_snapshot()\ncvt_after, specs_after = cvt_snapshot()\nif policy_after != policy_before or cvt_after != cvt_before:\n    error("observation:policy-changed")\n\nprint("VALUE\\trules=%d;nonstandard=%d\\t%s" % (len(specs), nonstandard, "PASS" if nonstandard == 0 else "FAIL"))\n'


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _fn_name(control_id):
    return "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)


def _render(control_id, sudoers_path, visudo_path, cvtsudoers_path):
    fn = _fn_name(control_id)
    args = " ".join(_sh_single(str(x)) for x in (sudoers_path, visudo_path, cvtsudoers_path))
    return "\n".join([
        f"{fn}() {{",
        f"  local _slp_cid={_sh_single(control_id)} _slp_obs _slp_rc _slp_kind _slp_value _slp_compliance _slp_extra",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - " + args + " <<'SLP_SUDOERS_POLICY_PY'",
        _PY,
        "SLP_SUDOERS_POLICY_PY",
        "  )",
        "  _slp_rc=$?",
        "  if (( _slp_rc != 0 )); then printf 'SLP-CHECK-V1\\t%s\\tERROR\\tobserver:execution-failed\\tERROR\\n' \"$_slp_cid\"; return 0; fi",
        "  if [[ $_slp_obs == ERROR$'\\t'* ]]; then printf 'SLP-CHECK-V1\\t%s\\tERROR\\t%s\\tERROR\\n' \"$_slp_cid\" \"${_slp_obs#*$'\\t'}\"; return 0; fi",
        "  IFS=$'\\t' read -r _slp_kind _slp_value _slp_compliance _slp_extra <<< \"$_slp_obs\"",
        "  if [[ \"$_slp_kind\" != VALUE || -z \"$_slp_value\" || -n \"$_slp_extra\" || ( \"$_slp_compliance\" != PASS && \"$_slp_compliance\" != FAIL ) ]]; then printf 'SLP-CHECK-V1\\t%s\\tERROR\\tobserver:invalid-output\\tERROR\\n' \"$_slp_cid\"; return 0; fi",
        "  printf 'SLP-CHECK-V1\\t%s\\tVALUE\\t%s\\t%s\\n' \"$_slp_cid\" \"$_slp_value\" \"$_slp_compliance\"",
        "}",
        "",
    ])


def shell_function_for_fixture(control_id, locator, key, op, expected, sudoers_path, visudo_path, cvtsudoers_path):
    if (locator, key, op, expected) != (CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED):
        raise ValueError("unsupported SRC-0004 sudoers-reviewed-policy contract")
    return _render(control_id, sudoers_path, visudo_path, cvtsudoers_path)


def shell_function(control_id, locator, key, op, expected):
    return shell_function_for_fixture(control_id, locator, key, op, expected, CANONICAL_LOCATOR, DEFAULT_VISUDO, DEFAULT_CVTSUDOERS)


MUTATING_TOKENS = ("chmod ", "chown ", "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "tee ", "install ", "truncate ", "dd ", "sysctl -w", "sed -i", ">>", "visudo -f")


def _selftest():
    src = shell_function("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED)
    assert "command /usr/bin/python3 -I -S -B" in src
    assert "cvtsudoers" in src and "visudo" in src
    assert "securelinux-policy" not in src and "SLP-SUDOERS-REVIEWED-POLICY-V1" not in src
    for token in MUTATING_TOKENS:
        assert re.search(r"(?<![A-Za-z0-9_.-])" + re.escape(token), src) is None, token
    for args in (
        ("/etc/sudoers.d", CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED),
        (CANONICAL_LOCATOR, "policy-tree", CANONICAL_OP, CANONICAL_EXPECTED),
        (CANONICAL_LOCATOR, CANONICAL_KEY, "eq-reviewed-policy", CANONICAL_EXPECTED),
        (CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, "/etc/securelinux-policy/sudoers-reviewed-policy-v1"),
    ):
        try:
            shell_function("CTRL", *args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
