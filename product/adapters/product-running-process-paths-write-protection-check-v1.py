#!/usr/bin/env python3
# Read-only adapter SRC-0006: current process executable/mapped-code paths and parent-directory write protection.
import re

SEMANTIC_CONTRACT_ID = "running-process-paths-write-protection-check-semantic-v1"
ADAPTER_ID = "product-running-process-paths-write-protection-check-v1"
ADAPTER_CONTRACT_VERSION = "product-running-process-paths-write-protection-check-adapter-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "running-process-paths-write-protection"
SUPPORTED_OPS = ("runtime-paths-safe",)
WIRE_RECORD_ID = "SLP-CHECK-V1"
CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
CANONICAL_LOCATOR = "/proc/<pid>/exe|/proc/<pid>/maps"
CANONICAL_KEY = "write-protection"
CANONICAL_OP = "runtime-paths-safe"
CANONICAL_EXPECTED = "file-go-w;parent-unprivileged-write-denied"

_PY = 'import os, re, stat, sys\nfrom pathlib import Path\n\nproc_root = Path(sys.argv[1])\nparent_stop = Path(sys.argv[2])\n\nMAP_ADDRESS = re.compile(r"^([0-9A-Fa-f]+)-([0-9A-Fa-f]+)$")\nMAP_PERMS = re.compile(r"^[r-][w-][x-][ps]$")\nMAP_OFFSET = re.compile(r"^[0-9A-Fa-f]+$")\nMAP_DEVICE = re.compile(r"^([0-9A-Fa-f]+):([0-9A-Fa-f]+)$")\nASCII_DECIMAL = re.compile(r"^[0-9]+$")\nASCII_SIGNED_DECIMAL = re.compile(r"^-?[0-9]+$")\nPROC_PROCESSES = re.compile(r"^processes[ \\t]+([0-9]+)$")\nOCTAL = set("01234567")\n\n\ndef error(reason):\n    print("ERROR\\t" + reason)\n    raise SystemExit(0)\n\n\ndef read_start(pid):\n    try:\n        raw = (pid / "stat").read_text(encoding="ascii", errors="strict")\n    except FileNotFoundError:\n        return None\n    except Exception:\n        error("proc-stat:read-failed")\n    if "\\x00" in raw or "\\r" in raw:\n        error("proc-stat:invalid-bytes")\n    if raw.endswith("\\n"):\n        body = raw[:-1]\n    else:\n        body = raw\n    if not body or "\\n" in body or "\\t" in body or "\\v" in body or "\\f" in body:\n        error("proc-stat:invalid-layout")\n    prefix = pid.name + " ("\n    if not body.startswith(prefix):\n        error("proc-stat:invalid-prefix")\n    close = body.rfind(")")\n    if close < len(prefix) - 1 or close + 1 >= len(body) or body[close + 1] != " ":\n        error("proc-stat:invalid-command-field")\n    fields = body[close + 2:].split(" ")\n    if len(fields) != 50 or any(field == "" for field in fields):\n        error("proc-stat:invalid-field-count")\n    state = fields[0]\n    if len(state) != 1 or not state.isascii() or not state.isalpha():\n        error("proc-stat:invalid-state")\n    for value in fields[1:]:\n        if ASCII_SIGNED_DECIMAL.fullmatch(value) is None:\n            error("proc-stat:invalid-number")\n    starttime = fields[19]\n    if ASCII_DECIMAL.fullmatch(starttime) is None:\n        error("proc-stat:invalid-starttime")\n    return starttime\n\n\ndef read_process_counter():\n    try:\n        text = (proc_root / "stat").read_text(encoding="ascii", errors="strict")\n    except Exception:\n        error("proc-counter:read-failed")\n    if "\\x00" in text or "\\r" in text:\n        error("proc-counter:invalid-bytes")\n    values = []\n    for line in text.splitlines():\n        if not line.startswith("processes"):\n            continue\n        match = PROC_PROCESSES.fullmatch(line)\n        if match is None:\n            error("proc-counter:invalid-record")\n        values.append(int(match.group(1), 10))\n    if len(values) != 1:\n        error("proc-counter:invalid-record-count")\n    return values[0]\n\n\ndef population_snapshot():\n    try:\n        entries = sorted((p for p in proc_root.iterdir() if p.name.isdigit()), key=lambda p: int(p.name))\n    except Exception:\n        error("proc-population:scan-failed")\n    if not entries:\n        error("proc-population:empty")\n    snap = {}\n    for pid in entries:\n        start = read_start(pid)\n        if start is None:\n            error("proc-population:process-disappeared")\n        snap[pid.name] = start\n    return snap\n\n\ndef classify_no_exe(pid, expected_start):\n    try:\n        status = (pid / "status").read_text(encoding="utf-8", errors="strict")\n    except Exception:\n        error("proc-status:read-failed")\n    if "\\x00" in status or "\\r" in status:\n        error("proc-status:invalid-bytes")\n    kthread = False\n    state = None\n    for line in status.splitlines():\n        if line.startswith("Kthread:"):\n            kthread = line.split(":", 1)[1].strip() == "1"\n        elif line.startswith("State:"):\n            value = line.split(":", 1)[1].strip()\n            state = value[:1] if value else None\n    if not (kthread or state == "Z"):\n        error("proc-status:no-exe-unclassified")\n    end = read_start(pid)\n    if end is None or end != expected_start:\n        error("proc-stat:excluded-classification-changed")\n    return "excluded"\n\n\ndef decode_proc_path(raw):\n    out = []\n    i = 0\n    while i < len(raw):\n        ch = raw[i]\n        if ch != "\\\\":\n            out.append(ch)\n            i += 1\n            continue\n        if i + 3 >= len(raw):\n            error("proc:invalid-path-escape")\n        digits = raw[i + 1:i + 4]\n        if any(c not in OCTAL for c in digits):\n            error("proc:invalid-path-escape")\n        value = int(digits, 8)\n        if value == 0:\n            error("proc:invalid-path-escape")\n        out.append(chr(value))\n        i += 4\n    return "".join(out)\n\n\ndef obj_state(st):\n    return (\n        st.st_dev,\n        st.st_ino,\n        st.st_uid,\n        st.st_gid,\n        stat.S_IMODE(st.st_mode),\n        st.st_ctime_ns,\n    )\n\n\ndef within_stop(real):\n    if parent_stop == Path("/"):\n        return\n    try:\n        Path(real).relative_to(parent_stop)\n    except ValueError:\n        error("path:outside-scope")\n\n\ndef check_path(path_text, file_records, file_states, parent_records, path_set, expected_mapping=None):\n    if not path_text.startswith("/") or "\\x00" in path_text:\n        error("path:invalid-absolute")\n    try:\n        source_lstat = os.lstat(path_text)\n        real = os.path.realpath(path_text)\n    except Exception:\n        error("path:resolve-failed")\n    if not real.startswith("/"):\n        error("path:invalid-resolved")\n    within_stop(real)\n    try:\n        fst = os.stat(real, follow_symlinks=True)\n    except Exception:\n        error("path:stat-failed")\n    if not stat.S_ISREG(fst.st_mode):\n        error("path:invalid-type")\n    if expected_mapping is not None:\n        map_major, map_minor, map_inode = expected_mapping\n        try:\n            actual_major = os.major(fst.st_dev)\n            actual_minor = os.minor(fst.st_dev)\n        except Exception:\n            error("path:device-id-failed")\n        if (actual_major, actual_minor, fst.st_ino) != (map_major, map_minor, map_inode):\n            error("path:mapping-mismatch")\n    source_state = obj_state(source_lstat)\n    target_state = obj_state(fst)\n    record = (real, source_state, target_state)\n    old = file_records.get(path_text)\n    if old is not None and old != record:\n        error("path:repeat-record-changed")\n    file_records[path_text] = record\n    identity = (fst.st_dev, fst.st_ino)\n    old_state = file_states.get(identity)\n    if old_state is not None and old_state != target_state:\n        error("path:identity-state-changed")\n    file_states[identity] = target_state\n    path_set.add(real)\n\n    cur = Path(real).parent\n    stop = parent_stop\n    while True:\n        try:\n            dst = os.stat(cur, follow_symlinks=True)\n        except Exception:\n            error("parent:stat-failed")\n        if not stat.S_ISDIR(dst.st_mode):\n            error("parent:invalid-type")\n        state = obj_state(dst)\n        old_dir = parent_records.get(str(cur))\n        if old_dir is not None and old_dir != state:\n            error("parent:repeat-snapshot-changed")\n        parent_records[str(cur)] = state\n        if cur == stop:\n            break\n        if cur == cur.parent:\n            if stop != cur:\n                error("path:outside-scope")\n            break\n        if stop != Path("/"):\n            try:\n                cur.relative_to(stop)\n            except ValueError:\n                error("path:outside-scope")\n        cur = cur.parent\n    return identity\n\n\ndef parse_maps(pid):\n    try:\n        text = (pid / "maps").read_text(encoding="utf-8", errors="strict")\n    except Exception:\n        error("proc-maps:read-failed")\n    if "\\x00" in text or "\\r" in text:\n        error("proc-maps:invalid-bytes")\n    mapped_exec = []\n    saw_line = False\n    for line in text.splitlines():\n        if not line:\n            continue\n        saw_line = True\n        parts = line.split(None, 5)\n        if len(parts) not in (5, 6):\n            error("proc-maps:invalid-fields")\n\n        address_text, perms, offset_text, device_text, inode_text = parts[:5]\n        address = MAP_ADDRESS.fullmatch(address_text)\n        if address is None:\n            error("proc-maps:invalid-address")\n        start = int(address.group(1), 16)\n        end = int(address.group(2), 16)\n        if start >= end:\n            error("proc-maps:invalid-address-range")\n        if not MAP_PERMS.fullmatch(perms):\n            error("proc-maps:invalid-permissions")\n        if not MAP_OFFSET.fullmatch(offset_text):\n            error("proc-maps:invalid-offset")\n        offset = int(offset_text, 16)\n        device = MAP_DEVICE.fullmatch(device_text)\n        if device is None:\n            error("proc-maps:invalid-device")\n        dev_major = int(device.group(1), 16)\n        dev_minor = int(device.group(2), 16)\n        if ASCII_DECIMAL.fullmatch(inode_text) is None:\n            error("proc-maps:invalid-inode")\n        inode = int(inode_text, 10)\n\n        if len(parts) == 5:\n            if inode != 0:\n                error("proc-maps:anonymous-inode")\n            continue\n\n        raw_path = parts[5]\n        if raw_path.startswith("[") and raw_path.endswith("]"):\n            if inode != 0:\n                error("proc-maps:pseudo-inode")\n            continue\n\n        path = decode_proc_path(raw_path)\n        if path.endswith(" (deleted)"):\n            error("proc-maps:deleted-path")\n        if not path.startswith("/"):\n            error("proc-maps:nonabsolute-path")\n        if perms[2] != "x":\n            continue\n        if inode == 0:\n            error("proc-maps:executable-zero-inode")\n        mapped_exec.append((path, start, end, offset, dev_major, dev_minor, inode))\n\n    if not saw_line or not mapped_exec:\n        error("proc-maps:empty-executable-population")\n    return mapped_exec\n\n\ndef read_exe(pid):\n    try:\n        target = os.readlink(pid / "exe")\n        exe_stat = os.stat(pid / "exe", follow_symlinks=True)\n    except FileNotFoundError:\n        return None\n    except Exception:\n        error("proc-exe:read-failed")\n    if target.endswith(" (deleted)") or not target.startswith("/") or "\\x00" in target:\n        error("proc-exe:invalid-target")\n    if not stat.S_ISREG(exe_stat.st_mode):\n        error("proc-exe:invalid-type")\n    return target, obj_state(exe_stat)\n\n\ndef recheck_files(file_records):\n    for source, (real, source_state, target_state) in file_records.items():\n        try:\n            now_source = os.lstat(source)\n            now_real = os.path.realpath(source)\n            now_target = os.stat(now_real, follow_symlinks=True)\n        except Exception:\n            error("path:recheck-stat-failed")\n        if now_real != real:\n            error("path:recheck-resolved-target-changed")\n        if obj_state(now_source) != source_state or obj_state(now_target) != target_state:\n            error("path:recheck-snapshot-changed")\n\n\ndef recheck_parents(parent_records):\n    for path, expected in parent_records.items():\n        try:\n            now = os.stat(path, follow_symlinks=True)\n        except Exception:\n            error("parent:recheck-stat-failed")\n        if not stat.S_ISDIR(now.st_mode):\n            error("parent:recheck-invalid-type")\n        if obj_state(now) != expected:\n            error("parent:recheck-snapshot-changed")\n\n\ndef recheck_processes(process_records, excluded_records):\n    for pid_name, record in process_records.items():\n        expected_start, expected_target, expected_exe_state, expected_maps = record\n        pid = proc_root / pid_name\n        start = read_start(pid)\n        if start is None or start != expected_start:\n            error("proc-stat:recheck-starttime-changed")\n        current_exe = read_exe(pid)\n        if current_exe is None:\n            error("proc-exe:recheck-missing")\n        target, exe_state = current_exe\n        if target != expected_target or exe_state != expected_exe_state:\n            error("proc-exe:recheck-changed")\n        current_maps = tuple(parse_maps(pid))\n        if current_maps != expected_maps:\n            error("proc-maps:recheck-changed")\n        end = read_start(pid)\n        if end is None or end != expected_start:\n            error("proc-stat:recheck-endtime-changed")\n\n    for pid_name, expected_start in excluded_records.items():\n        pid = proc_root / pid_name\n        start = read_start(pid)\n        if start is None or start != expected_start:\n            error("proc-stat:excluded-recheck-changed")\n        if read_exe(pid) is not None:\n            error("proc-exe:excluded-reappeared")\n        classify_no_exe(pid, expected_start)\n\n\ntry:\n    pst = os.lstat(proc_root)\nexcept Exception:\n    error("proc-root:lstat-failed")\nif not stat.S_ISDIR(pst.st_mode) or stat.S_ISLNK(pst.st_mode):\n    error("proc-root:invalid-type")\ntry:\n    sst = os.stat(parent_stop)\nexcept Exception:\n    error("parent-stop:stat-failed")\nif not stat.S_ISDIR(sst.st_mode):\n    error("parent-stop:invalid-type")\n\nfork_counter = read_process_counter()\ninitial_population = population_snapshot()\nfile_records = {}\nfile_states = {}\npath_set = set()\nparent_records = {}\nprocess_records = {}\nexcluded_records = {}\nprocesses = 0\nlibraries_seen = 0\nexcluded = 0\n\nfor pid_name, expected_start in sorted(initial_population.items(), key=lambda item: int(item[0])):\n    pid = proc_root / pid_name\n    start = read_start(pid)\n    if start is None or start != expected_start:\n        error("proc-stat:initial-starttime-changed")\n\n    exe_observation = read_exe(pid)\n    if exe_observation is None:\n        classify_no_exe(pid, expected_start)\n        excluded_records[pid_name] = expected_start\n        excluded += 1\n        continue\n\n    target, exe_state = exe_observation\n    exe_identity = check_path(target, file_records, file_states, parent_records, path_set)\n    if (exe_state[0], exe_state[1]) != exe_identity:\n        error("proc-exe:identity-mismatch")\n\n    mapped_records = tuple(parse_maps(pid))\n    mapped_ids = set()\n    for path, map_start, map_end, map_offset, map_major, map_minor, map_inode in mapped_records:\n        mapped_ids.add(\n            check_path(\n                path,\n                file_records,\n                file_states,\n                parent_records,\n                path_set,\n                expected_mapping=(map_major, map_minor, map_inode),\n            )\n        )\n\n    end = read_start(pid)\n    if end is None or end != expected_start:\n        error("proc-stat:initial-endtime-changed")\n\n    process_records[pid_name] = (expected_start, target, exe_state, mapped_records)\n    processes += 1\n    libraries_seen += len(mapped_ids - {exe_identity})\n\nif processes == 0 or not file_states:\n    error("proc-population:empty-observation")\n\nmid_population = population_snapshot()\nif mid_population != initial_population:\n    error("pid-population:mid-snapshot-changed")\nif read_process_counter() != fork_counter:\n    error("proc-counter:mid-snapshot-changed")\n\nrecheck_processes(process_records, excluded_records)\nrecheck_files(file_records)\nrecheck_parents(parent_records)\n\nfinal_population = population_snapshot()\nif final_population != initial_population:\n    error("pid-population:final-snapshot-changed")\nif read_process_counter() != fork_counter:\n    error("proc-counter:final-snapshot-changed")\n\nfile_violations = sum(1 for state in file_states.values() if state[4] & 0o022)\nparent_violations = 0\nparent_ambiguous = 0\nfor state in parent_records.values():\n    uid, mode = state[2], state[4]\n    # Directory entry mutation requires both write and search (execute) on the\n    # directory. A non-root owner or world class with wx proves unprivileged\n    # writability. Group-class wx alone does not identify which principals\n    # receive it (owning-group membership / POSIX ACL semantics), so it is\n    # fail-closed ambiguity rather than a source-level FAIL.\n    if uid != 0 and (mode & 0o300) == 0o300:\n        parent_violations += 1\n    if (mode & 0o003) == 0o003:\n        parent_violations += 1\n    if (mode & 0o030) == 0o030:\n        parent_ambiguous += 1\n\nif parent_violations == 0 and parent_ambiguous:\n    error("parent:group-write-ambiguous")\n\nvalue = (\n    f"pids={processes};files={len(file_states)};paths={len(path_set)};parents={len(parent_records)};"\n    f"libraries={libraries_seen};forks={fork_counter};vanished=0;excluded={excluded};"\n    f"file_violations={file_violations};parent_violations={parent_violations}"\n)\ncompliance = "PASS" if file_violations == 0 and parent_violations == 0 else "FAIL"\nprint("VALUE\\t" + value + "\\t" + compliance)\n'

PROCESS_CHANGE_REASONS = (
    "proc-stat:excluded-classification-changed",
    "proc-stat:recheck-starttime-changed",
    "proc-exe:recheck-missing",
    "proc-exe:recheck-changed",
    "proc-maps:recheck-changed",
    "proc-stat:recheck-endtime-changed",
    "proc-stat:excluded-recheck-changed",
    "proc-exe:excluded-reappeared",
    "proc-root:lstat-failed",
    "proc-root:invalid-type",
    "parent-stop:stat-failed",
    "parent-stop:invalid-type",
    "proc-stat:initial-starttime-changed",
    "proc-exe:identity-mismatch",
    "proc-stat:initial-endtime-changed",
    "proc-population:empty-observation",
    "pid-population:mid-snapshot-changed",
    "proc-counter:mid-snapshot-changed",
    "pid-population:final-snapshot-changed",
    "proc-counter:final-snapshot-changed",
    "parent:group-write-ambiguous",
)

FILE_PARENT_CHANGE_REASONS = (
    "path:repeat-record-changed",
    "path:identity-state-changed",
    "path:recheck-stat-failed",
    "path:recheck-resolved-target-changed",
    "path:recheck-snapshot-changed",
    "parent:repeat-snapshot-changed",
    "parent:recheck-stat-failed",
    "parent:recheck-invalid-type",
    "parent:recheck-snapshot-changed",
)


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def _render(control_id, proc_root="/proc", parent_stop="/"):
    if not isinstance(control_id, str) or not re.fullmatch(CONTROL_ID_PATTERN, control_id):
        raise ValueError("invalid control id")
    if not isinstance(proc_root, str) or not proc_root.startswith("/") or "\n" in proc_root or "\r" in proc_root:
        raise ValueError("absolute proc root required")
    if not isinstance(parent_stop, str) or not parent_stop.startswith("/") or "\n" in parent_stop or "\r" in parent_stop:
        raise ValueError("absolute parent stop required")
    fn = "slp_check_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    cid = _sh_single(control_id)
    emit = '  printf "%s\\t%s\\t%s\\t%s\\t%s\\n" ' + _sh_single(WIRE_RECORD_ID) + " " + cid
    return "\n".join([
        fn + "() {",
        "  local _slp_obs='' _slp_rc=0 _slp_status='' _slp_value='' _slp_compliance='' _slp_extra=''",
        "  _slp_obs=$(command /usr/bin/python3 -I -S -B - " + _sh_single(proc_root) + " " + _sh_single(parent_stop) + " <<'SLP_RUNTIME_PATHS_PY'",
        _PY.rstrip("\n"),
        "SLP_RUNTIME_PATHS_PY",
        "  )",
        "  _slp_rc=$?",
        "  if (( _slp_rc != 0 )); then",
        emit + ' "ERROR" "observer:execution-failed" "ERROR"',
        "    return 0",
        "  fi",
        "  if [[ -z $_slp_obs || $_slp_obs == *$'\\n'* || $_slp_obs == *$'\\r'* ]]; then",
        emit + ' "ERROR" "observer:invalid-output" "ERROR"',
        "    return 0",
        "  fi",
        "  if [[ $_slp_obs == ERROR$'\t'* ]]; then",
        emit + ' "ERROR" "${_slp_obs#*$\'\t\'}" "ERROR"',
        "    return 0",
        "  fi",
        "  IFS=$\'\\t\' read -r _slp_status _slp_value _slp_compliance _slp_extra <<< \"$_slp_obs\"",
        "  if [[ $_slp_status != VALUE || -z $_slp_value || ( $_slp_compliance != PASS && $_slp_compliance != FAIL ) || -n $_slp_extra ]]; then",
        emit + ' "ERROR" "observer:invalid-output" "ERROR"',
        "    return 0",
        "  fi",
        emit + ' "VALUE" "$_slp_value" "$_slp_compliance"',
        "  return 0",
        "}",
        "",
    ])

def shell_function(control_id, locator, key, op, expected):
    if locator != CANONICAL_LOCATOR or key != CANONICAL_KEY or op != CANONICAL_OP or expected != CANONICAL_EXPECTED:
        raise ValueError("only canonical SRC-0006 running-process contract is supported")
    return _render(control_id)

def _shell_function_for_roots(control_id, proc_root, parent_stop):
    return _render(control_id, proc_root, parent_stop)

MUTATING_TOKENS = (
    "sysctl -w", "sysctl --write", "tee ", "sed -i", "chmod ", "chown ",
    "chgrp ", "setfacl ", "rm ", "mv ", "cp ", "touch ", "truncate ", "dd ", ">>",
)

def _selftest():
    src = shell_function("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED)
    assert "command /usr/bin/python3 -I -S -B" in src
    assert 'pid / "exe"' in src and 'pid / "maps"' in src
    assert "population_snapshot" in src and "read_process_counter" in src and "recheck_processes" in src
    assert "recheck_files" in src and "recheck_parents" in src
    assert "MAP_ADDRESS" in src and "MAP_OFFSET" in src and "MAP_DEVICE" in src
    assert "decode_proc_path" in src and "expected_mapping" in src and "library_name" not in src
    assert "file_violations" in src and "parent_violations" in src
    assert ("observation:" + "process-changed") not in _PY
    assert len(PROCESS_CHANGE_REASONS) == 21
    assert len(set(PROCESS_CHANGE_REASONS)) == len(PROCESS_CHANGE_REASONS)
    assert len(FILE_PARENT_CHANGE_REASONS) == 9
    assert len(set(FILE_PARENT_CHANGE_REASONS)) == len(FILE_PARENT_CHANGE_REASONS)
    assert "observation:file-changed" not in _PY
    assert "observation:parent-changed" not in _PY
    for reason in PROCESS_CHANGE_REASONS + FILE_PARENT_CHANGE_REASONS:
        assert _PY.count('error("' + reason + '")') == 1, reason
    for token in MUTATING_TOKENS:
        assert token not in src, token
    for args in (
        ("CTRL", "/proc", CANONICAL_KEY, CANONICAL_OP, CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, "mode", CANONICAL_OP, CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, "bits-clear", CANONICAL_EXPECTED),
        ("CTRL", CANONICAL_LOCATOR, CANONICAL_KEY, CANONICAL_OP, "0022"),
    ):
        try:
            shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")

if __name__ == "__main__":
    _selftest()
