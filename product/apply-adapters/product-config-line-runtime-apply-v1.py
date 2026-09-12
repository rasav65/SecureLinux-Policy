#!/usr/bin/env python3
"""APPLY adapter core for config-line-with-runtime-v1.

The module keeps CHECK-compatible integer semantics, parses the contract-defined
explicit sysctl assignments, resolves sysctl.d precedence, plans one control and
executes its persistent/runtime transaction. Merely importing or running the
self-test never mutates /etc/sysctl.d or /proc/sys.
"""

from dataclasses import dataclass
from pathlib import PurePosixPath
import re
import errno
import hashlib
import os
import posixpath
import secrets
import stat
import json
import base64
import datetime as _datetime
import traceback

MECHANISM_ID = "config-line-with-runtime-v1"
ADAPTER_ID = "product-config-line-runtime-apply-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "sysctl"
SUPPORTED_OPS = ("eq", "ge")
EXPECTED_TYPE = "integer"

OUTCOME_NOT_ELIGIBLE = "NOT_ELIGIBLE_APPLY_UNSUPPORTED"
BRANCH_ALREADY = "neither_needs_change"
BRANCH_PERSISTENT_ONLY = "persistent_only"
BRANCH_RUNTIME_ONLY = "runtime_only"
BRANCH_BOTH = "both"

CONTROL_ID_RE = re.compile(r"^(?!.*[\r\n])[A-Za-z0-9._-]+$")
SYSCTL_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$")
INTEGER_RE = re.compile(rb"^[+-]?[0-9]+$")
ASCII_EDGE_WS = b" \t\n\r\v\f"

SYSCTL_D_DIRS = (
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
    "/lib/sysctl.d",
)
DIR_PRIORITY = {name: i for i, name in enumerate(SYSCTL_D_DIRS)}
SYSCTL_CONF = "/etc/sysctl.conf"
CANONICAL_HEADER = b"# Managed by SecureLinux-Policy\n"


class ContractError(ValueError):
    pass


class PreconditionError(RuntimeError):
    def __init__(self, code, source=None):
        super().__init__(code if source is None else f"{code}:{source}")
        self.code = code
        self.source = source


@dataclass(frozen=True)
class ExplicitAssignment:
    key: str
    value_text: str
    line_no: int


@dataclass(frozen=True)
class SourceFile:
    path: str
    assignments: tuple = ()


@dataclass(frozen=True)
class PrecedenceResult:
    effective_foreign_value: int | None
    effective_foreign_source: str | None
    conflict_sources: tuple
    shadowed_sources: tuple


@dataclass(frozen=True)
class Plan:
    target_value: int
    runtime_compliant: bool
    persistent_compliant: bool
    branch: str


def _require_int(value, field):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{field} must be integer")
    return value


def validate_control_input(control_id, key, op, expected, apply_supported):
    if not isinstance(control_id, str) or CONTROL_ID_RE.fullmatch(control_id) is None:
        raise ContractError("invalid control id")
    proc_path(key)
    if op not in SUPPORTED_OPS:
        raise ContractError("unsupported op")
    _require_int(expected, "expected")
    if not isinstance(apply_supported, bool):
        raise ContractError("apply.supported must be boolean")


def eligibility_outcome(apply_supported):
    if not isinstance(apply_supported, bool):
        raise ContractError("apply.supported must be boolean")
    return None if apply_supported else OUTCOME_NOT_ELIGIBLE


def proc_path(key):
    if not isinstance(key, str) or SYSCTL_KEY_RE.fullmatch(key) is None:
        raise ContractError("invalid sysctl key")
    return "/proc/sys/" + key.replace(".", "/")


def persistent_path(key):
    proc_path(key)
    return "/etc/sysctl.d/zz-securelinux-policy-" + key.replace(".", "-") + ".conf"


def parse_integer_bytes(raw):
    if not isinstance(raw, (bytes, bytearray)):
        raise ContractError("integer source must be bytes")
    data = bytes(raw)
    if b"\x00" in data:
        raise ContractError("invalid integer bytes")
    token = data.strip(ASCII_EDGE_WS)
    if INTEGER_RE.fullmatch(token) is None:
        raise ContractError("invalid integer value")
    # Python integers are unbounded; int() also canonicalizes leading zeros and +.
    return int(token, 10)


def parse_integer_text(text):
    if not isinstance(text, str):
        raise ContractError("integer source must be text")
    try:
        raw = text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ContractError("invalid integer value") from exc
    return parse_integer_bytes(raw)


def canonical_integer(value):
    _require_int(value, "integer")
    return str(value)


def normalize_source_key(key):
    """Return the proc-suffix form defined by the accepted sysctl semantics."""
    if not isinstance(key, str) or not key or any(ch.isspace() for ch in key):
        raise ContractError("invalid source key")
    # A leading '-' belongs to sysctl line syntax, not to key normalization.
    # parse_sysctl_assignment_line() removes it only for the explicit
    # "-key = value" form. A bare "-key" line is therefore never confused
    # with an assignment.
    if not key:
        raise ContractError("invalid source key")
    dot = key.find(".")
    slash = key.find("/")
    if dot < 0 and slash < 0:
        return key
    if slash >= 0 and (dot < 0 or slash < dot):
        return key
    table = str.maketrans({".": "/", "/": "."})
    return key.translate(table)


def control_proc_suffix(key):
    proc_path(key)
    return key.replace(".", "/")


def compute_target_value(op, expected, runtime_before, own_persistent_value=None, effective_foreign_value=None):
    if op not in SUPPORTED_OPS:
        raise ContractError("unsupported op")
    values = [_require_int(expected, "expected"), _require_int(runtime_before, "runtime_before")]
    if op == "eq":
        return values[0]
    for name, value in (("own_persistent_value", own_persistent_value), ("effective_foreign_value", effective_foreign_value)):
        if value is not None:
            values.append(_require_int(value, name))
    return max(values)


def runtime_is_compliant(op, runtime_value, target_value):
    runtime_value = _require_int(runtime_value, "runtime_value")
    target_value = _require_int(target_value, "target_value")
    if op == "eq":
        return runtime_value == target_value
    if op == "ge":
        return runtime_value >= target_value
    raise ContractError("unsupported op")


def canonical_persistent_bytes(key, target_value):
    proc_path(key)
    target = canonical_integer(target_value).encode("ascii")
    return CANONICAL_HEADER + key.encode("ascii") + b" = " + target + b"\n"


def persistent_is_compliant(key, target_value, raw_bytes, uid, gid, mode, expected_uid=0, expected_gid=0, expected_mode=0o644):
    if raw_bytes is None:
        return False
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise ContractError("persistent bytes must be bytes or None")
    for name, value in (("uid", uid), ("gid", gid), ("mode", mode)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ContractError(f"{name} must be integer")
    for name, value in (("expected_uid", expected_uid), ("expected_gid", expected_gid), ("expected_mode", expected_mode)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ContractError(f"{name} must be integer")
    return (
        bytes(raw_bytes) == canonical_persistent_bytes(key, target_value)
        and uid == expected_uid
        and gid == expected_gid
        and mode == expected_mode
    )


def select_branch(runtime_compliant, persistent_compliant):
    if not isinstance(runtime_compliant, bool) or not isinstance(persistent_compliant, bool):
        raise ContractError("compliance inputs must be boolean")
    if runtime_compliant and persistent_compliant:
        return BRANCH_ALREADY
    if runtime_compliant:
        return BRANCH_PERSISTENT_ONLY
    if persistent_compliant:
        return BRANCH_RUNTIME_ONLY
    return BRANCH_BOTH


def build_plan(key, op, expected, runtime_before, persistent_bytes, uid, gid, mode, own_persistent_value=None, effective_foreign_value=None, expected_uid=0, expected_gid=0, expected_mode=0o644):
    target = compute_target_value(op, expected, runtime_before, own_persistent_value, effective_foreign_value)
    runtime_ok = runtime_is_compliant(op, runtime_before, target)
    persistent_ok = persistent_is_compliant(key, target, persistent_bytes, uid, gid, mode, expected_uid, expected_gid, expected_mode)
    return Plan(target, runtime_ok, persistent_ok, select_branch(runtime_ok, persistent_ok))


def _path_parts(path):
    if not isinstance(path, str) or not path.startswith("/"):
        raise ContractError("source path must be absolute")
    p = PurePosixPath(path)
    return str(p.parent), p.name


def _validate_source_file(source):
    if not isinstance(source, SourceFile):
        raise ContractError("source must be SourceFile")
    parent, basename = _path_parts(source.path)
    if source.path != SYSCTL_CONF:
        if parent not in DIR_PRIORITY or not basename.endswith(".conf"):
            raise ContractError("unsupported sysctl source path")
    for assignment in source.assignments:
        if not isinstance(assignment, ExplicitAssignment):
            raise ContractError("assignment must be ExplicitAssignment")
        if isinstance(assignment.line_no, bool) or not isinstance(assignment.line_no, int) or assignment.line_no < 1:
            raise ContractError("invalid line number")
        normalize_source_key(assignment.key)
        if not isinstance(assignment.value_text, str):
            raise ContractError("assignment value must be text")


def _shadow_sysctl_d_sources(files, own_path):
    own_parent, own_basename = _path_parts(own_path)
    if own_parent != "/etc/sysctl.d":
        raise ContractError("own path outside /etc/sysctl.d")
    by_basename = {}
    shadowed = []
    for src in files:
        if src.path == SYSCTL_CONF:
            continue
        parent, basename = _path_parts(src.path)
        current = by_basename.get(basename)
        if current is None:
            by_basename[basename] = src
            continue
        cur_parent, _ = _path_parts(current.path)
        if parent == cur_parent:
            raise ContractError("duplicate source path/basename")
        if DIR_PRIORITY[parent] < DIR_PRIORITY[cur_parent]:
            shadowed.append(current.path)
            by_basename[basename] = src
        else:
            shadowed.append(src.path)
    return tuple(by_basename.values()), tuple(sorted(shadowed, key=lambda p: p.encode("utf-8")))


def resolve_precedence(control_key, source_files):
    """Resolve structured explicit assignments without reading the filesystem.

    `source_files` must represent files after parser-level classification. A file
    may have zero assignments so same-basename shadowing remains representable.
    Entries in each file must be in original line order.
    """
    own_path = persistent_path(control_key)
    own_basename = PurePosixPath(own_path).name
    target_suffix = control_proc_suffix(control_key)
    files = tuple(source_files)
    seen_paths = set()
    for src in files:
        _validate_source_file(src)
        if src.path in seen_paths:
            raise ContractError("duplicate source path")
        seen_paths.add(src.path)

    survivors, shadowed = _shadow_sysctl_d_sources(files, own_path)
    survivors = sorted(survivors, key=lambda s: PurePosixPath(s.path).name.encode("utf-8"))

    effective = None
    effective_source = None
    effective_assignment = None
    conflicts = []

    def matching_assignments(src):
        return [a for a in src.assignments if normalize_source_key(a.key) == target_suffix]

    for src in survivors:
        if src.path == own_path:
            continue
        basename = PurePosixPath(src.path).name
        matches = matching_assignments(src)
        if not matches:
            continue
        if basename.encode("utf-8") > own_basename.encode("utf-8"):
            conflicts.append(src.path)
            continue
        # D08/r11: only the final effective explicit assignment before our file
        # determines effective_foreign_value. Earlier overridden assignments are
        # not parsed as candidate values.
        effective_assignment = sorted(matches, key=lambda a: a.line_no)[-1]
        effective_source = src.path

    for src in files:
        if src.path != SYSCTL_CONF:
            continue
        if matching_assignments(src):
            conflicts.append(SYSCTL_CONF)

    if conflicts:
        # Conflict detection is independent from numeric strength: later explicit
        # assignments are fail-closed by H46-D08.
        raise PreconditionError("source:late-conflict", tuple(sorted(set(conflicts), key=lambda p: p.encode("utf-8"))))

    if effective_assignment is not None:
        try:
            effective = parse_integer_text(effective_assignment.value_text)
        except ContractError as exc:
            raise PreconditionError("source:invalid-integer", effective_source) from exc

    return PrecedenceResult(effective, effective_source, (), shadowed)



@dataclass(frozen=True)
class ObjectIdentity:
    exists: bool
    st_dev: int | None = None
    st_ino: int | None = None
    file_type: int | None = None
    st_nlink: int | None = None
    uid: int | None = None
    gid: int | None = None
    mode: int | None = None
    raw_bytes: bytes | None = None


@dataclass(frozen=True)
class PersistentMutationState:
    target_path: str
    prestate: ObjectIdentity
    attempt_written_identity: ObjectIdentity


@dataclass(frozen=True)
class RuntimePhaseResult:
    runtime_prewrite: int
    written_value: int | None
    runtime_after: int
    write_performed: bool


class PersistentPhaseError(RuntimeError):
    def __init__(self, outcome, code, mutation_performed, attempt_written_identity=None):
        super().__init__(f"{outcome}:{code}")
        self.outcome = outcome
        self.code = code
        self.mutation_performed = mutation_performed
        self.attempt_written_identity = attempt_written_identity


class CompensationError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


RUNTIME_WRITER_PROTOCOL_V1 = "SLP_RUNTIME_WRITER_V1"


class RuntimeWriteError(RuntimeError):
    def __init__(self, code, write_started=False):
        super().__init__(code)
        self.code = code
        self.write_started = bool(write_started)


class RuntimeWriterProtocolViolation(RuntimeError):
    pass


class RuntimeMutationPreconditionError(RuntimeError):
    def __init__(self, reason, runtime_prewrite):
        super().__init__(reason)
        self.reason = reason
        self.runtime_prewrite = runtime_prewrite


class RuntimePhaseError(RuntimeError):
    def __init__(self, code, runtime_prewrite=None, runtime_after=None, write_attempted=False,
                 write_performed=False, written_value=None):
        super().__init__(code)
        self.code = code
        self.runtime_prewrite = runtime_prewrite
        self.runtime_after = runtime_after
        self.write_attempted = bool(write_attempted)
        self.write_performed = bool(write_performed)
        self.written_value = written_value if self.write_performed else None


def _mode_type(mode):
    return stat.S_IFMT(mode)


def _read_all_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _identity_from_fd(fd, read_bytes=True):
    st = os.fstat(fd)
    raw = _read_all_fd(fd) if read_bytes else None
    return ObjectIdentity(
        True,
        st.st_dev,
        st.st_ino,
        _mode_type(st.st_mode),
        st.st_nlink,
        st.st_uid,
        st.st_gid,
        stat.S_IMODE(st.st_mode),
        raw,
    )


def _require_regular_single(identity, code="persistent:forbidden-object"):
    if not identity.exists or identity.file_type != stat.S_IFREG or identity.st_nlink != 1:
        raise PreconditionError(code)
    return identity


def _open_dir_nofollow(path):
    if not isinstance(path, str) or not path.startswith("/"):
        raise ContractError("directory path must be absolute")
    try:
        lst = os.lstat(path)
    except OSError as exc:
        raise PreconditionError("persistent:directory-unavailable", path) from exc
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode):
        raise PreconditionError("persistent:directory-forbidden", path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise PreconditionError("persistent:directory-unavailable", path) from exc


def _snapshot_name(dir_fd, name, allow_absent=True):
    try:
        lst = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        if allow_absent:
            return ObjectIdentity(False)
        raise PreconditionError("persistent:target-missing", name)
    except OSError as exc:
        raise PreconditionError("persistent:target-unreadable", name) from exc
    if not stat.S_ISREG(lst.st_mode) or lst.st_nlink != 1:
        raise PreconditionError("persistent:forbidden-object", name)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise PreconditionError("persistent:forbidden-object", name) from exc
        raise PreconditionError("persistent:target-unreadable", name) from exc
    try:
        fst = os.fstat(fd)
        if (fst.st_dev, fst.st_ino, _mode_type(fst.st_mode), fst.st_nlink) != (lst.st_dev, lst.st_ino, _mode_type(lst.st_mode), lst.st_nlink):
            raise PreconditionError("persistent:target-drift", name)
        identity = _identity_from_fd(fd)
    finally:
        os.close(fd)
    return _require_regular_single(identity)


def snapshot_persistent_target(target_path):
    if not isinstance(target_path, str) or not target_path.startswith("/"):
        raise ContractError("target path must be absolute")
    parent = str(PurePosixPath(target_path).parent)
    name = PurePosixPath(target_path).name
    dir_fd = _open_dir_nofollow(parent)
    try:
        return _snapshot_name(dir_fd, name, allow_absent=True)
    finally:
        os.close(dir_fd)


def _write_all(fd, data):
    if not isinstance(data, (bytes, bytearray)):
        raise ContractError("write data must be bytes")
    view = memoryview(bytes(data))
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        offset += written


def _unlink_if_exists(dir_fd, name):
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass


def _prepare_temp(dir_fd, target_name, desired_bytes, desired_uid, desired_gid, desired_mode):
    for field, value in (("uid", desired_uid), ("gid", desired_gid), ("mode", desired_mode)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ContractError(f"{field} must be integer")
    if not isinstance(desired_bytes, (bytes, bytearray)):
        raise ContractError("desired bytes must be bytes")
    temp_name = f".{target_name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temp_name, flags, 0o000, dir_fd=dir_fd)
    keep = False
    try:
        _write_all(fd, desired_bytes)
        os.fsync(fd)
        os.fchown(fd, desired_uid, desired_gid)
        os.fchmod(fd, desired_mode)
        prepared = _identity_from_fd(fd)
        if (
            prepared.file_type != stat.S_IFREG
            or prepared.st_nlink != 1
            or prepared.uid != desired_uid
            or prepared.gid != desired_gid
            or prepared.mode != desired_mode
            or prepared.raw_bytes != bytes(desired_bytes)
        ):
            raise OSError(errno.EIO, "prepared temp verification failed")
        keep = True
        return temp_name, prepared
    finally:
        os.close(fd)
        if not keep:
            _unlink_if_exists(dir_fd, temp_name)


def _revalidate_prestate(dir_fd, target_name, prestate):
    try:
        current = _snapshot_name(dir_fd, target_name, allow_absent=True)
    except PreconditionError as exc:
        # The target was valid when prestate was captured. Becoming missing,
        # symlink/special/hardlinked/unreadable before rename is therefore drift,
        # not a fresh initial-object classification.
        raise PreconditionError("persistent:drift-before-rename", target_name) from exc
    if current != prestate:
        raise PreconditionError("persistent:drift-before-rename", target_name)


def _fsync_dir(dir_fd):
    os.fsync(dir_fd)


def _verify_attempt_identity(dir_fd, target_name, attempt_identity):
    current = _snapshot_name(dir_fd, target_name, allow_absent=False)
    if current != attempt_identity:
        raise OSError(errno.EIO, "post-rename identity mismatch")
    return current


def _restored_state_matches(current, prestate):
    if not current.exists or not prestate.exists:
        return False
    return (
        current.file_type == stat.S_IFREG
        and current.st_nlink == 1
        and current.uid == prestate.uid
        and current.gid == prestate.gid
        and current.mode == prestate.mode
        and current.raw_bytes == prestate.raw_bytes
    )


def compensate_persistent(state):
    if not isinstance(state, PersistentMutationState):
        raise ContractError("invalid persistent mutation state")
    target = PurePosixPath(state.target_path)
    try:
        dir_fd = _open_dir_nofollow(str(target.parent))
    except Exception as exc:
        raise CompensationError("persistent:compensation-directory-unavailable") from exc
    temp_name = None
    try:
        try:
            current = _snapshot_name(dir_fd, target.name, allow_absent=False)
        except PreconditionError as exc:
            raise CompensationError("persistent:ownership-drift") from exc
        if current != state.attempt_written_identity:
            raise CompensationError("persistent:ownership-drift")

        if state.prestate.exists:
            try:
                temp_name, _ = _prepare_temp(
                    dir_fd,
                    target.name,
                    state.prestate.raw_bytes,
                    state.prestate.uid,
                    state.prestate.gid,
                    state.prestate.mode,
                )
                # Ownership is checked again immediately before the destructive rename.
                current = _snapshot_name(dir_fd, target.name, allow_absent=False)
                if current != state.attempt_written_identity:
                    raise CompensationError("persistent:ownership-drift")
                os.replace(temp_name, target.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                temp_name = None
                _fsync_dir(dir_fd)
                restored = _snapshot_name(dir_fd, target.name, allow_absent=False)
                if not _restored_state_matches(restored, state.prestate):
                    raise CompensationError("persistent:restore-verification-failed")
            except CompensationError:
                raise
            except Exception as exc:
                raise CompensationError("persistent:restore-failed") from exc
        else:
            try:
                current = _snapshot_name(dir_fd, target.name, allow_absent=False)
                if current != state.attempt_written_identity:
                    raise CompensationError("persistent:ownership-drift")
                os.unlink(target.name, dir_fd=dir_fd)
                _fsync_dir(dir_fd)
                if _snapshot_name(dir_fd, target.name, allow_absent=True).exists:
                    raise CompensationError("persistent:remove-verification-failed")
            except CompensationError:
                raise
            except Exception as exc:
                raise CompensationError("persistent:remove-failed") from exc
    finally:
        if temp_name is not None:
            _unlink_if_exists(dir_fd, temp_name)
        os.close(dir_fd)


def apply_persistent_change(target_path, desired_bytes, desired_uid=0, desired_gid=0, desired_mode=0o644, expected_prestate=None):
    """Atomically replace/create one persistent target and return rollback state.

    The function performs no runtime mutation. Failures before rename leave the
    target untouched. Failures after rename trigger transaction-local persistent
    compensation before returning an error.
    """
    if not isinstance(target_path, str) or not target_path.startswith("/"):
        raise ContractError("target path must be absolute")
    target = PurePosixPath(target_path)
    dir_fd = _open_dir_nofollow(str(target.parent))
    temp_name = None
    renamed = False
    attempt_identity = None
    prestate = None
    try:
        if expected_prestate is None:
            prestate = _snapshot_name(dir_fd, target.name, allow_absent=True)
        else:
            if not isinstance(expected_prestate, ObjectIdentity):
                raise ContractError("expected_prestate must be ObjectIdentity or None")
            prestate = expected_prestate
        temp_name, prepared = _prepare_temp(dir_fd, target.name, desired_bytes, desired_uid, desired_gid, desired_mode)
        _revalidate_prestate(dir_fd, target.name, prestate)
        os.replace(temp_name, target.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        temp_name = None
        renamed = True
        attempt_identity = prepared
        state = PersistentMutationState(target_path, prestate, attempt_identity)
        try:
            _fsync_dir(dir_fd)
            _verify_attempt_identity(dir_fd, target.name, attempt_identity)
        except Exception as exc:
            try:
                compensate_persistent(state)
            except CompensationError as cexc:
                raise PersistentPhaseError(
                    "FAILED_COMPENSATION",
                    "persistent:post-rename-failure;compensation:" + cexc.code,
                    True, attempt_identity,
                ) from cexc
            raise PersistentPhaseError("FAILED_NOT_COMMITTED", "persistent:post-rename-failure", True, attempt_identity) from exc
        return state
    except PreconditionError:
        raise
    except PersistentPhaseError:
        raise
    except Exception as exc:
        if renamed and attempt_identity is not None and prestate is not None:
            state = PersistentMutationState(target_path, prestate, attempt_identity)
            try:
                compensate_persistent(state)
            except CompensationError as cexc:
                raise PersistentPhaseError(
                    "FAILED_COMPENSATION",
                    "persistent:phase1-failure;compensation:" + cexc.code,
                    True, attempt_identity,
                ) from cexc
            raise PersistentPhaseError("FAILED_NOT_COMMITTED", "persistent:phase1-failure", True, attempt_identity) from exc
        raise PersistentPhaseError("FAILED_NOT_COMMITTED", "persistent:phase1-before-rename", False, None) from exc
    finally:
        if temp_name is not None:
            _unlink_if_exists(dir_fd, temp_name)
        os.close(dir_fd)


def read_runtime_path(path):
    if not isinstance(path, str) or not path.startswith("/"):
        raise ContractError("runtime path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        chunks = []
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
        return parse_integer_bytes(b"".join(chunks))
    finally:
        os.close(fd)


def write_runtime_path(path, value):
    if not isinstance(path, str) or not path.startswith("/"):
        raise ContractError("runtime path must be absolute")
    data = canonical_integer(value).encode("ascii")
    flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except Exception as exc:
        raise RuntimeWriteError("runtime:write-failure", False) from exc

    write_started = False
    closed = False
    try:
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            try:
                written = os.write(fd, view[offset:])
            except Exception as exc:
                raise RuntimeWriteError("runtime:write-failure", write_started) from exc
            if written <= 0:
                raise RuntimeWriteError("runtime:write-failure", write_started)
            write_started = True
            offset += written
        try:
            os.close(fd)
            closed = True
        except Exception as exc:
            raise RuntimeWriteError("runtime:write-failure", write_started) from exc
    finally:
        if not closed:
            try:
                os.close(fd)
            except Exception:
                pass


def execute_runtime_phase(op, target_value, read_value, write_value, *, writer_protocol=None, pre_write_guard=None):
    """Execute the single-write runtime phase using injected read/write callables.

    Low-level callers may omit ``writer_protocol`` for direct unit testing. The
    product-level execute_control boundary always supplies
    SLP_RUNTIME_WRITER_V1. A declared V1 writer must report failed-write
    progress with RuntimeWriteError; a generic exception is an interface
    violation and is deliberately not normalized into a false no-mutation fact.
    """
    if writer_protocol not in (None, RUNTIME_WRITER_PROTOCOL_V1):
        raise ContractError("unsupported runtime writer protocol")
    if op not in SUPPORTED_OPS:
        raise ContractError("unsupported op")
    _require_int(target_value, "target_value")
    if not callable(read_value) or not callable(write_value):
        raise ContractError("runtime callbacks must be callable")
    if pre_write_guard is not None and not callable(pre_write_guard):
        raise ContractError("runtime pre-write guard must be callable")
    try:
        prewrite = _require_int(read_value(), "runtime_prewrite")
    except Exception as exc:
        raise RuntimePhaseError("runtime:prewrite-failure") from exc

    if runtime_is_compliant(op, prewrite, target_value):
        return RuntimePhaseResult(prewrite, None, prewrite, False)

    if pre_write_guard is not None:
        try:
            pre_write_guard()
        except PreconditionError as exc:
            raise RuntimeMutationPreconditionError(str(exc), prewrite) from exc
        except Exception as exc:
            raise RuntimeMutationPreconditionError(
                "persistent:prewrite-revalidation-failure", prewrite
            ) from exc

    try:
        write_value(target_value)
    except RuntimeWriteError as exc:
        raise RuntimePhaseError(
            "runtime:write-failure", prewrite, None, True,
            exc.write_started, target_value if exc.write_started else None,
        ) from exc
    except Exception as exc:
        if writer_protocol == RUNTIME_WRITER_PROTOCOL_V1:
            raise RuntimeWriterProtocolViolation("runtime:writer-protocol-violation") from exc
        # Legacy low-level test mode: without a declared product writer protocol
        # only the attempted call is knowable. Product execution never uses this
        # branch.
        raise RuntimePhaseError("runtime:write-failure", prewrite, None, True, False, None) from exc

    try:
        after = _require_int(read_value(), "runtime_after")
    except Exception as exc:
        raise RuntimePhaseError("runtime:postcheck-read-failure", prewrite, None, True, True, target_value) from exc
    if not runtime_is_compliant(op, after, target_value):
        raise RuntimePhaseError("runtime:postcheck-noncompliant", prewrite, after, True, True, target_value)
    return RuntimePhaseResult(prewrite, target_value, after, True)


OUTCOME_APPLIED = "APPLIED"
OUTCOME_ALREADY_COMPLIANT = "ALREADY_COMPLIANT"
OUTCOME_NOT_APPLICABLE = "NOT_APPLICABLE_KEY_ABSENT"
OUTCOME_ABORT_CONFLICT = "ABORTED_PRECONDITION_CONFLICT"
OUTCOME_ABORT_OTHER = "ABORTED_PRECONDITION_OTHER"
OUTCOME_FAILED_NOT_COMMITTED = "FAILED_NOT_COMMITTED"
OUTCOME_FAILED_COMPENSATION = "FAILED_COMPENSATION"
OUTCOME_DRY_RUN_WOULD_APPLY = "DRY_RUN_WOULD_APPLY"
COMMIT_COMMITTED = "COMMITTED"
COMMIT_NOT_COMMITTED = "NOT_COMMITTED"
COMMIT_NOT_STARTED = "NOT_STARTED"


@dataclass(frozen=True)
class ControlExecutionResult:
    control_id: str
    key: str
    op: str
    expected: int
    eligible: bool
    outcome: str
    reason: str
    branch: str | None
    target_value: int | None
    effective_foreign_value: int | None
    runtime_before: int | None
    runtime_prewrite: int | None
    runtime_after: int | None
    persistent_before: ObjectIdentity | None
    persistent_after: ObjectIdentity | None
    written_value: int | None
    actions_attempted: tuple
    mutation_performed: bool
    transaction_commit: str
    attempt_written_identity: ObjectIdentity | None
    dry_run: bool


def _result(control_id, key, op, expected, eligible, outcome, reason, *, branch=None,
            target_value=None, effective_foreign_value=None, runtime_before=None,
            runtime_prewrite=None, runtime_after=None, persistent_before=None,
            persistent_after=None, written_value=None, actions=(), mutation=False,
            commit=COMMIT_NOT_STARTED, attempt_identity=None, dry_run=False):
    return ControlExecutionResult(
        control_id, key, op, expected, eligible, outcome, reason, branch, target_value,
        effective_foreign_value, runtime_before, runtime_prewrite, runtime_after,
        persistent_before, persistent_after, written_value, tuple(actions), bool(mutation),
        commit, attempt_identity, bool(dry_run),
    )


def parse_sysctl_assignment_line(line, line_no):
    """Parse one contract-defined explicit sysctl assignment.

    Recognized assignment forms are ``key = value`` and ``-key = value``.
    The leading '-' in the latter means "ignore write error" to procps; it does
    not change precedence semantics here and therefore is intentionally not
    stored. A bare ``-key`` line has no '=' and is an exclusion/glob directive,
    so it returns None and can never become an ExplicitAssignment. Lines whose
    left side contains glob metacharacters are outside the proved mechanism
    guarantee and also return None.
    """
    if isinstance(line, (bytes, bytearray)):
        try:
            line = bytes(line).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PreconditionError("source:invalid-encoding") from exc
    if not isinstance(line, str):
        raise ContractError("source line must be text or bytes")
    if isinstance(line_no, bool) or not isinstance(line_no, int) or line_no < 1:
        raise ContractError("invalid line number")
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith(";") or "=" not in stripped:
        return None
    left, right = stripped.split("=", 1)
    left = left.strip()
    right = right.strip()
    if left.startswith("-"):
        left = left[1:].strip()
    if not left or any(ch in left for ch in "*?[]"):
        return None
    try:
        normalize_source_key(left)
    except ContractError as exc:
        raise PreconditionError("source:invalid-key") from exc
    return ExplicitAssignment(left, right, line_no)


def parse_sysctl_source_bytes(raw, logical_path):
    """Parse explicit assignments from one source file without mutation."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ContractError("source bytes must be bytes")
    assignments = []
    for line_no, line in enumerate(bytes(raw).splitlines(), 1):
        assignment = parse_sysctl_assignment_line(line, line_no)
        if assignment is not None:
            assignments.append(assignment)
    return SourceFile(logical_path, tuple(assignments))


def _rooted_source_path(root, logical_path):
    root = os.fspath(root)
    if not os.path.isabs(root):
        raise ContractError("source root must be absolute")
    if root == "/":
        return logical_path
    return os.path.join(root, logical_path.lstrip("/"))


def _logical_conf_names(root, logical_dir):
    physical = _rooted_source_path(root, logical_dir)
    try:
        with os.scandir(physical) as it:
            names = [entry.name for entry in it if entry.name.endswith(".conf")]
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise PreconditionError("source:unreadable-directory", logical_dir) from exc
    if len(names) != len(set(names)):
        raise PreconditionError("source:duplicate-name", logical_dir)
    return tuple(sorted(names, key=lambda name: name.encode("utf-8")))


def _read_logical_source(root, logical_path):
    physical = _rooted_source_path(root, logical_path)
    try:
        lst = os.lstat(physical)
    except OSError as exc:
        raise PreconditionError("source:unreadable-source", logical_path) from exc

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(physical, flags)
    except OSError as exc:
        raise PreconditionError("source:unreadable-source", logical_path) from exc
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise PreconditionError("source:unreadable-source", logical_path) from exc

        if stat.S_ISREG(st.st_mode):
            try:
                raw = _read_all_fd(fd)
            except OSError as exc:
                raise PreconditionError("source:unreadable-source", logical_path) from exc
            return parse_sysctl_source_bytes(raw, logical_path)

        # r11 gives one special symlink rule: a symlink resolving to /dev/null
        # is an empty source.  All other non-regular resolved objects fail closed.
        if stat.S_ISLNK(lst.st_mode) and stat.S_ISCHR(st.st_mode):
            try:
                null_st = os.stat("/dev/null")
            except OSError as exc:
                raise PreconditionError("source:unreadable-source", logical_path) from exc
            if st.st_rdev == null_st.st_rdev:
                return SourceFile(logical_path, ())
        raise PreconditionError("source:unreadable-source", logical_path)
    finally:
        os.close(fd)


def _load_sysctl_sources_observed(control_key, root="/"):
    """Return (source_files, own_present_during_P2).

    own_present_during_P2 binds the same-basename shadowing decision to the
    persistent prestate used for target planning. execute_control() compares it
    with the target snapshot taken immediately after P2 and aborts on mismatch.
    """
    own_path = persistent_path(control_key)
    own_basename = PurePosixPath(own_path).name
    names_by_dir = {logical_dir: set(_logical_conf_names(root, logical_dir)) for logical_dir in SYSCTL_D_DIRS}
    own_parent = str(PurePosixPath(own_path).parent)
    own_present = own_parent in names_by_dir and own_basename in names_by_dir[own_parent]
    all_names = set().union(*names_by_dir.values()) if names_by_dir else set()
    result = []
    for basename in sorted(all_names, key=lambda name: name.encode("utf-8")):
        present = [d for d in SYSCTL_D_DIRS if basename in names_by_dir[d]]
        selected = present[0] + "/" + basename if present else None
        for logical_dir in present:
            logical_path = logical_dir + "/" + basename
            if logical_path == selected:
                # The own target is observed later through snapshot_persistent_target,
                # which validates object type without pre-reading it. P2 must not
                # parse/read own bytes: eq allows an unparseable own file to be
                # replaced, and a FIFO/special own target must fail closed rather
                # than block the source loader.
                if logical_path == own_path:
                    result.append(SourceFile(logical_path, ()))
                else:
                    result.append(_read_logical_source(root, logical_path))
            else:
                result.append(SourceFile(logical_path, ()))

    conf_physical = _rooted_source_path(root, SYSCTL_CONF)
    try:
        os.lstat(conf_physical)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise PreconditionError("source:unreadable-source", SYSCTL_CONF) from exc
    else:
        result.append(_read_logical_source(root, SYSCTL_CONF))
    return tuple(result), bool(own_present)


def load_sysctl_sources(control_key, root="/"):
    """Read the D08 source set after same-basename shadowing."""
    return _load_sysctl_sources_observed(control_key, root)[0]


def own_persistent_value(key, raw_bytes):
    if raw_bytes is None:
        return None
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise ContractError("persistent bytes must be bytes or None")
    try:
        text = bytes(raw_bytes).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PreconditionError("persistent:own-unparseable") from exc
    suffix = control_proc_suffix(key)
    matches = []
    for line_no, line in enumerate(text.splitlines(), 1):
        assignment = parse_sysctl_assignment_line(line, line_no)
        if assignment is not None and normalize_source_key(assignment.key) == suffix:
            matches.append(assignment)
    if len(matches) != 1:
        raise PreconditionError("persistent:own-unparseable")
    try:
        return parse_integer_text(matches[0].value_text)
    except ContractError as exc:
        raise PreconditionError("persistent:own-unparseable") from exc


# H46-D16/H46-D17: runtime-writer conflict precondition (P2R). The detector is
# strictly read-only and never changes any service, systemd, SysV or sysctl object.
RUNTIME_WRITER_CONFLICT = "CONFLICT"
RUNTIME_WRITER_NO_CONFLICT = "NO_CONFLICT"
RUNTIME_WRITER_UNDETERMINED = "UNDETERMINED"
RUNTIME_WRITER_DELEGATE_SYSV = "DELEGATE_SYSV"
RUNTIME_WRITER_RULE_APPORT_NATIVE = "APPORT-NATIVE-SUID-DUMPABLE-V1"
RUNTIME_WRITER_RULE_APPORT_SYSV = "APPORT-SYSV-SUID-DUMPABLE-V1"
RUNTIME_WRITER_RULES = {"fs.suid_dumpable": RUNTIME_WRITER_RULE_APPORT_NATIVE}
SERVICE_MANAGED_RUNTIME_WRITERS = {
    RUNTIME_WRITER_RULE_APPORT_NATIVE: "Apport",
    RUNTIME_WRITER_RULE_APPORT_SYSV: "Apport",
}

APPORT_INIT_SCRIPT = "/etc/init.d/apport"
APPORT_INIT_SCRIPT_SHA256 = frozenset({
    "40e252cd99e030fcdf28d286a7ac78f434e0ce0742f55cd12c38bef8e1f18633",
})
APPORT_AGENT = "/usr/share/apport/apport"
APPORT_DEFAULT_FILE = "/etc/default/apport"
APPORT_DEFAULT_ENABLED_SHA256 = frozenset({
    "810304fb0df6dbc8a651a8928ddd0bb2b521fa0ca6f32a328aa103be61977f91",
})
PID1_ENVIRON = "/proc/1/environ"
APPORT_SYSTEMD_CONTAINER = "/run/systemd/container"
APPORT_RC_DIRS = ("/etc/rcS.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d")
APPORT_RC_LINK_RE = re.compile(r"S..apport", re.DOTALL)

APPORT_SYSTEMD_ROOTS = (
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/generator.late",
)
APPORT_DBUS_ROOTS = (
    "/usr/share/dbus-1/system-services",
    "/etc/dbus-1/system-services",
    "/usr/local/share/dbus-1/system-services",
)
APPORT_MARKER = b"apport"

APPORT_AUX_REGULAR_SHA256 = {
    "/usr/lib/systemd/system/apport-autoreport.path": "22df838805217bd3c7381e87a8e7aff7db11eec6977b75a892db1e6dc42b4e8a",
    "/usr/lib/systemd/system/apport-autoreport.service": "9be72b6a5ce373fc3c4580cbe3901703a6cb47fff0bde3d2c29fb82d69160b73",
    "/usr/lib/systemd/system/apport-autoreport.timer": "72e4700854d2c3babee612f6dda7c1c61caf37878b7adf9663ddbcbbc3e4c9c5",
    "/usr/lib/systemd/system/apport-forward.socket": "d3b7d68269d8a0d051e1ab63680abdfffb1b4ad12fb503997fb6da4ceaf1c083",
    "/usr/lib/systemd/system/apport-forward@.service": "31afbc86642ddbb5e2286dff78558bce1ffcaafdd69683097b6ffe1fcedf6cec",
    "/usr/lib/systemd/system/apport-coredump-hook@.service": "fdabfbd44847bd34d03efd9cc52d847d3dbaffec96e13cd413a40b35acc39a00",
    "/usr/lib/systemd/system/systemd-coredump@.service.d/apport-coredump-hook.conf": "d025d2395f1d5f0e9fc183b39db11dd5f121740fd818fc2333ed5ca4a39dbfaa",
}
APPORT_AUX_LINK_TARGETS = {
    "/etc/systemd/system/paths.target.wants/apport-autoreport.path": frozenset({
        "/lib/systemd/system/apport-autoreport.path",
        "/usr/lib/systemd/system/apport-autoreport.path",
    }),
    "/etc/systemd/system/sockets.target.wants/apport-forward.socket": frozenset({
        "/lib/systemd/system/apport-forward.socket",
        "/usr/lib/systemd/system/apport-forward.socket",
    }),
    "/etc/systemd/system/timers.target.wants/apport-autoreport.timer": frozenset({
        "/lib/systemd/system/apport-autoreport.timer",
        "/usr/lib/systemd/system/apport-autoreport.timer",
    }),
}
APPORT_AUX_LINK_RESOLVED = {
    "/etc/systemd/system/paths.target.wants/apport-autoreport.path": "/usr/lib/systemd/system/apport-autoreport.path",
    "/etc/systemd/system/sockets.target.wants/apport-forward.socket": "/usr/lib/systemd/system/apport-forward.socket",
    "/etc/systemd/system/timers.target.wants/apport-autoreport.timer": "/usr/lib/systemd/system/apport-autoreport.timer",
}
APPORT_AUX_BASE_PATHS = frozenset({
    "/usr/lib/systemd/system/apport-autoreport.path",
    "/usr/lib/systemd/system/apport-autoreport.service",
    "/usr/lib/systemd/system/apport-autoreport.timer",
    "/usr/lib/systemd/system/apport-forward.socket",
    "/usr/lib/systemd/system/apport-forward@.service",
    "/etc/systemd/system/paths.target.wants/apport-autoreport.path",
    "/etc/systemd/system/sockets.target.wants/apport-forward.socket",
    "/etc/systemd/system/timers.target.wants/apport-autoreport.timer",
})
APPORT_AUX_COREDUMP_PATHS = frozenset(set(APPORT_AUX_BASE_PATHS) | {
    "/usr/lib/systemd/system/apport-coredump-hook@.service",
    "/usr/lib/systemd/system/systemd-coredump@.service.d/apport-coredump-hook.conf",
})

APPORT_NATIVE_UNIT = "/usr/lib/systemd/system/apport.service"
APPORT_NATIVE_UNIT_SHA256 = "c2026a8f813776108e2d91629f51ff0cf5bf013fac03314164cabcda6c9698aa"
APPORT_NATIVE_WANTS = "/etc/systemd/system/multi-user.target.wants/apport.service"
APPORT_NATIVE_WANTS_TARGET = "/usr/lib/systemd/system/apport.service"
APPORT_NATIVE_AGENT_SHA256 = frozenset({
    "1b8b5e2c53e8970dd2f47c9a0892030d1ebad57cae1f7242c43a6252f1f6dff2",
    "e8b57da9924d461fee6d3b392dc184697bc14d2eb8d717c05e1cbf0bd376041e",
})
APPORT_NATIVE_PRIMARY_PATHS = frozenset({APPORT_NATIVE_UNIT, APPORT_NATIVE_WANTS})

APPORT_GENERATED_UNIT = "/run/systemd/generator.late/apport.service"
APPORT_GENERATED_UNIT_SHA256 = "8b8d235c366ae9b433af073c5a813e3465e0d6c66e3f398ba73095c9f6d33363"
APPORT_GENERATED_UNIT_MODE = 0o644
APPORT_GENERATED_UNIT_SIZE = 518
APPORT_GENERATED_LINKS = {
    "/run/systemd/generator.late/multi-user.target.wants/apport.service": "../apport.service",
    "/run/systemd/generator.late/graphical.target.wants/apport.service": "../apport.service",
}
APPORT_GENERATED_PRIMARY_PATHS = frozenset({APPORT_GENERATED_UNIT, *APPORT_GENERATED_LINKS})
APPORT_MASK_PATHS = (
    "/etc/systemd/system/apport.service",
    "/run/systemd/system/apport.service",
)
APPORT_OVERRIDE_PATHS = (
    "/etc/systemd/system/apport.service.d",
    "/run/systemd/system/apport.service.d",
    "/usr/lib/systemd/system/apport.service.d",
    "/lib/systemd/system/apport.service",
    "/usr/lib/systemd/system/apport.service",
)


class _RuntimeWriterUndetermined(Exception):
    def __init__(self, step, detail=None):
        super().__init__(step if detail is None else f"{step}:{detail}")
        self.step = step
        self.detail = detail


class _RuntimeWriterStep(str):
    """String-compatible step carrying the rule id used only for report grammar."""
    def __new__(cls, value, rule_id=None):
        obj = str.__new__(cls, value)
        obj.rule_id = rule_id
        return obj


@dataclass(frozen=True)
class _ApportHit:
    path: str
    object_type: str
    mode: int | None = None
    size: int | None = None
    sha256: str | None = None
    raw_target: str | None = None
    resolved_path: str | None = None
    resolved_type: str | None = None
    resolved_sha256: str | None = None
    marker_path: bool = False
    marker_target: bool = False
    marker_bytes: bool = False


@dataclass(frozen=True)
class _ApportNativeDecision:
    verdict: str
    step: str | None
    detail: str | None
    auxiliary_nonempty: bool = False


def _errno_token(exc):
    return errno.errorcode.get(getattr(exc, "errno", None), "OSERROR")


def _rw_lstat(path, step):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _RuntimeWriterUndetermined(step, _errno_token(exc))


def _rw_read_regular(path, st, step):
    if not stat.S_ISREG(st.st_mode):
        raise _RuntimeWriterUndetermined(step, "not-regular")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise _RuntimeWriterUndetermined(step, _errno_token(exc))
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            raise _RuntimeWriterUndetermined(step, "object-drift")
        return _read_all_fd(fd)
    except OSError as exc:
        raise _RuntimeWriterUndetermined(step, _errno_token(exc))
    finally:
        os.close(fd)


def _ascii_marker(data):
    if isinstance(data, str):
        data = os.fsencode(data)
    return APPORT_MARKER in bytes(data).lower()


def _rw_normalize_logical(path):
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
        raise _RuntimeWriterUndetermined("C1", "invalid-logical-path")
    return path


def _rw_resolve_logical(root, logical, step):
    """Strict root-aware component resolution. Absolute targets stay inside source_root."""
    logical = _rw_normalize_logical(logical)
    pending = [part for part in logical.split("/") if part]
    if logical.endswith("/") and pending:
        pending.append(".")
    resolved = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            if resolved:
                resolved.pop()
            continue

        candidate = "/" + "/".join(resolved + [part])
        physical = _rooted_source_path(root, candidate)
        try:
            st = os.lstat(physical)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise _RuntimeWriterUndetermined(step, _errno_token(exc) + ":" + candidate)
        if stat.S_ISLNK(st.st_mode):
            links += 1
            if links > 40:
                raise _RuntimeWriterUndetermined(step, "ELOOP:" + candidate)
            try:
                target = os.readlink(physical)
            except OSError as exc:
                raise _RuntimeWriterUndetermined(step, _errno_token(exc) + ":" + candidate)
            if not isinstance(target, str):
                target = os.fsdecode(target)
            target_parts = [p for p in target.split("/") if p]
            if target.endswith("/") and target_parts:
                target_parts.append(".")
            if target.startswith("/"):
                resolved = []
            pending = target_parts + pending
            continue
        if pending and not stat.S_ISDIR(st.st_mode):
            raise _RuntimeWriterUndetermined(step, "ENOTDIR:" + candidate)
        resolved.append(part)
    final_logical = "/" + "/".join(resolved)
    physical = _rooted_source_path(root, final_logical)
    try:
        final_st = os.lstat(physical)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _RuntimeWriterUndetermined(step, _errno_token(exc) + ":" + final_logical)
    return final_logical, final_st


def _rw_same_logical_object(root, left, right, step):
    lres = _rw_resolve_logical(root, left, step)
    rres = _rw_resolve_logical(root, right, step)
    if lres is None or rres is None:
        return False
    return (lres[1].st_dev, lres[1].st_ino) == (rres[1].st_dev, rres[1].st_ino)


def _rw_census_symlink(root, logical, relative, st):
    physical = _rooted_source_path(root, logical)
    try:
        raw_target = os.readlink(physical)
    except OSError as exc:
        raise _RuntimeWriterUndetermined("C1", "readlink:" + _errno_token(exc) + ":" + logical)
    if not isinstance(raw_target, str):
        raw_target = os.fsdecode(raw_target)
    marker_path = _ascii_marker(relative)
    marker_target = _ascii_marker(raw_target)
    preliminary = marker_path or marker_target

    # Exact /dev/null masks are metadata-only; the device is never opened/read.
    if raw_target == "/dev/null":
        if preliminary:
            return _ApportHit(
                logical, "symlink", mode=stat.S_IMODE(st.st_mode), size=st.st_size,
                raw_target=raw_target, resolved_path="/dev/null", resolved_type="special",
                marker_path=marker_path, marker_target=marker_target,
            )
        return None

    resolved = _rw_resolve_logical(root, logical, "C1")
    if resolved is None:
        if not preliminary:
            return None
        return _ApportHit(
            logical, "symlink", mode=stat.S_IMODE(st.st_mode), size=st.st_size,
            raw_target=raw_target, marker_path=marker_path, marker_target=marker_target,
        )
    resolved_logical, resolved_st = resolved
    if stat.S_ISREG(resolved_st.st_mode):
        data = _rw_read_regular(_rooted_source_path(root, resolved_logical), resolved_st, "C1")
        marker_bytes = _ascii_marker(data)
        if not (preliminary or marker_bytes):
            return None
        return _ApportHit(
            logical, "symlink", mode=stat.S_IMODE(st.st_mode), size=st.st_size,
            raw_target=raw_target, resolved_path=resolved_logical, resolved_type="regular",
            resolved_sha256=hashlib.sha256(data).hexdigest(), marker_path=marker_path,
            marker_target=marker_target, marker_bytes=marker_bytes,
        )
    if stat.S_ISDIR(resolved_st.st_mode):
        if preliminary:
            raise _RuntimeWriterUndetermined("C1", "marker-directory-symlink:" + logical)
        return None
    if preliminary:
        raise _RuntimeWriterUndetermined("C1", "marker-special-symlink:" + logical)
    return None


def _rw_apport_census(root):
    # Merged-/usr alias is evidence-bound before the recursive scan. /lib is never
    # scanned as a second systemd tree.
    lib_path = _rooted_source_path(root, "/lib/systemd/system")
    usr_path = _rooted_source_path(root, "/usr/lib/systemd/system")
    lib_st = _rw_lstat(lib_path, "C1")
    usr_st = _rw_lstat(usr_path, "C1")
    if lib_st is not None and usr_st is not None:
        if not _rw_same_logical_object(root, "/lib/systemd/system", "/usr/lib/systemd/system", "C1"):
            raise _RuntimeWriterUndetermined("C1", "lib-usr-systemd-divergent")

    hits = {}
    for kind, logical_root in tuple(("systemd", p) for p in APPORT_SYSTEMD_ROOTS) + tuple(("dbus", p) for p in APPORT_DBUS_ROOTS):
        physical_root = _rooted_source_path(root, logical_root)
        root_st = _rw_lstat(physical_root, "C1")
        if root_st is None:
            continue
        if not stat.S_ISDIR(root_st.st_mode):
            raise _RuntimeWriterUndetermined("C1", "root-not-directory:" + logical_root)
        stack = [(logical_root, "")]
        while stack:
            logical_dir, rel_base = stack.pop()
            physical_dir = _rooted_source_path(root, logical_dir)
            try:
                names = os.listdir(physical_dir)
            except OSError as exc:
                raise _RuntimeWriterUndetermined("C1", "readdir:" + _errno_token(exc) + ":" + logical_dir)
            for name in sorted(names, key=os.fsencode):
                logical = posixpath.join(logical_dir, name)
                relative = posixpath.join(rel_base, name) if rel_base else name
                physical = _rooted_source_path(root, logical)
                try:
                    st = os.lstat(physical)
                except OSError as exc:
                    raise _RuntimeWriterUndetermined("C1", "lstat:" + _errno_token(exc) + ":" + logical)
                if stat.S_ISDIR(st.st_mode):
                    stack.append((logical, relative))
                    continue
                hit = None
                if stat.S_ISREG(st.st_mode):
                    data = _rw_read_regular(physical, st, "C1")
                    marker_path = _ascii_marker(relative)
                    marker_bytes = _ascii_marker(data)
                    if marker_path or marker_bytes:
                        hit = _ApportHit(
                            logical, "regular", mode=stat.S_IMODE(st.st_mode), size=st.st_size,
                            sha256=hashlib.sha256(data).hexdigest(), marker_path=marker_path,
                            marker_bytes=marker_bytes,
                        )
                elif stat.S_ISLNK(st.st_mode):
                    hit = _rw_census_symlink(root, logical, relative, st)
                else:
                    if _ascii_marker(relative):
                        raise _RuntimeWriterUndetermined("C1", "marker-special-object:" + logical)
                if hit is not None:
                    if kind == "dbus":
                        raise _RuntimeWriterUndetermined("C2", "dbus-hit:" + logical)
                    if logical in hits:
                        raise _RuntimeWriterUndetermined("C2", "duplicate-hit:" + logical)
                    hits[logical] = hit
    return hits


def _rw_validate_regular_hit(hits, path, expected_sha, step):
    hit = hits.get(path)
    if hit is None or hit.object_type != "regular" or hit.sha256 != expected_sha:
        raise _RuntimeWriterUndetermined(step, "regular-mismatch:" + path)
    return hit


def _rw_validate_link_hit(root, hits, path, allowed_targets, resolved_path, step):
    hit = hits.get(path)
    if hit is None or hit.object_type != "symlink" or hit.raw_target not in allowed_targets:
        raise _RuntimeWriterUndetermined(step, "link-mismatch:" + path)
    if hit.resolved_type != "regular" or hit.resolved_path != resolved_path:
        # merged-/usr may preserve a /lib logical spelling only on unusual bind layouts;
        # exact object identity with the /usr path is still required.
        if hit.resolved_type != "regular" or hit.resolved_path is None or not _rw_same_logical_object(root, hit.resolved_path, resolved_path, step):
            raise _RuntimeWriterUndetermined(step, "link-resolution:" + path)
    target_hit = hits.get(resolved_path)
    if target_hit is None or target_hit.object_type != "regular" or hit.resolved_sha256 != target_hit.sha256:
        raise _RuntimeWriterUndetermined(step, "link-target-bytes:" + path)


def _rw_classify_auxiliary(root, hits, aux_paths):
    if not aux_paths:
        return "EMPTY"
    if aux_paths == APPORT_AUX_BASE_PATHS:
        profile = "AUX-BASE-V1"
    elif aux_paths == APPORT_AUX_COREDUMP_PATHS:
        profile = "AUX-COREDUMP-V1"
    else:
        raise _RuntimeWriterUndetermined("C2", "aux-profile")
    for path in aux_paths & set(APPORT_AUX_REGULAR_SHA256):
        _rw_validate_regular_hit(hits, path, APPORT_AUX_REGULAR_SHA256[path], "C2")
    for path in aux_paths & set(APPORT_AUX_LINK_TARGETS):
        _rw_validate_link_hit(root, hits, path, APPORT_AUX_LINK_TARGETS[path], APPORT_AUX_LINK_RESOLVED[path], "C2")
    return profile


def _rw_validate_native_primary(root, hits):
    _rw_validate_regular_hit(hits, APPORT_NATIVE_UNIT, APPORT_NATIVE_UNIT_SHA256, "C4")
    _rw_validate_link_hit(root, hits, APPORT_NATIVE_WANTS, frozenset({APPORT_NATIVE_WANTS_TARGET}), APPORT_NATIVE_UNIT, "C4")


def _rw_validate_generated_primary(root, hits):
    unit = _rw_validate_regular_hit(hits, APPORT_GENERATED_UNIT, APPORT_GENERATED_UNIT_SHA256, "C5")
    if unit.mode != APPORT_GENERATED_UNIT_MODE or unit.size != APPORT_GENERATED_UNIT_SIZE:
        raise _RuntimeWriterUndetermined("C5", "generated-unit-metadata")
    for path, raw_target in APPORT_GENERATED_LINKS.items():
        _rw_validate_link_hit(root, hits, path, frozenset({raw_target}), APPORT_GENERATED_UNIT, "C5")


def _rw_read_container_evidence(root):
    env_path = _rooted_source_path(root, PID1_ENVIRON)
    env_st = _rw_lstat(env_path, "C4")
    if env_st is None:
        raise _RuntimeWriterUndetermined("C4", "proc1-environ-ENOENT")
    env = _rw_read_regular(env_path, env_st, "C4")
    if any(item.startswith(b"container=") for item in env.split(b"\0")):
        return True, "proc1-environ"

    logical = APPORT_SYSTEMD_CONTAINER
    path = _rooted_source_path(root, logical)
    st = _rw_lstat(path, "C4")
    if st is None:
        return False, None
    data = _rw_read_regular(path, st, "C4")
    stripped = data.strip(ASCII_EDGE_WS)
    if stripped:
        return True, "run-systemd-container"
    raise _RuntimeWriterUndetermined("C4", "empty-systemd-container")


def _rw_native_agent_verdict(root):
    path = _rooted_source_path(root, APPORT_AGENT)
    st = _rw_lstat(path, "C4")
    if st is None:
        return RUNTIME_WRITER_NO_CONFLICT, "agent-absent"
    if stat.S_ISLNK(st.st_mode):
        resolved = _rw_resolve_logical(root, APPORT_AGENT, "C4")
        if resolved is None:
            return RUNTIME_WRITER_NO_CONFLICT, "agent-dangling"
        raise _RuntimeWriterUndetermined("C4", "agent-resolvable-symlink")
    if not stat.S_ISREG(st.st_mode):
        raise _RuntimeWriterUndetermined("C4", "agent-not-regular")
    if not os.access(path, os.X_OK):
        return RUNTIME_WRITER_NO_CONFLICT, "agent-not-executable"
    data = _rw_read_regular(path, st, "C4")
    sha = hashlib.sha256(data).hexdigest()
    if sha not in APPORT_NATIVE_AGENT_SHA256:
        raise _RuntimeWriterUndetermined("C4", "agent-sha256=" + sha)
    return RUNTIME_WRITER_CONFLICT, "agent-exact"


def _detect_apport_native_suid_dumpable(root):
    hits = _rw_apport_census(root)
    hit_paths = set(hits)
    known_aux = set(APPORT_AUX_COREDUMP_PATHS)
    aux_paths = hit_paths & known_aux
    aux_profile = _rw_classify_auxiliary(root, hits, aux_paths)
    aux_nonempty = aux_profile != "EMPTY"
    primary_paths = hit_paths - aux_paths

    # C2 partitions the complete hit set before any positive mask/container result.
    if not primary_paths:
        return _ApportNativeDecision(RUNTIME_WRITER_DELEGATE_SYSV, "C6", "zero-primary", aux_nonempty)

    mask_paths = [path for path in APPORT_MASK_PATHS if path in primary_paths]
    if mask_paths:
        if len(primary_paths) != 1:
            raise _RuntimeWriterUndetermined("C2", "mask-extra-primary")
        path = mask_paths[0]
        hit = hits[path]
        if hit.object_type != "symlink" or hit.raw_target != "/dev/null":
            raise _RuntimeWriterUndetermined("C3", "mask-mismatch:" + path)
        if aux_nonempty:
            raise _RuntimeWriterUndetermined("C3", "mask-with-auxiliary")
        return _ApportNativeDecision(RUNTIME_WRITER_NO_CONFLICT, "C3", path, False)

    if primary_paths == set(APPORT_NATIVE_PRIMARY_PATHS):
        _rw_validate_native_primary(root, hits)
        is_container, container_source = _rw_read_container_evidence(root)
        if is_container:
            if aux_nonempty:
                raise _RuntimeWriterUndetermined("C4", "container-with-auxiliary:" + container_source)
            return _ApportNativeDecision(RUNTIME_WRITER_NO_CONFLICT, "C4", "container:" + container_source, False)
        verdict, detail = _rw_native_agent_verdict(root)
        if verdict == RUNTIME_WRITER_NO_CONFLICT and aux_nonempty:
            raise _RuntimeWriterUndetermined("C4", detail + ":with-auxiliary")
        return _ApportNativeDecision(verdict, "C4", detail, aux_nonempty)

    if primary_paths == set(APPORT_GENERATED_PRIMARY_PATHS):
        _rw_validate_generated_primary(root, hits)
        return _ApportNativeDecision(RUNTIME_WRITER_DELEGATE_SYSV, "C5", "generated-sysv-bridge", aux_nonempty)

    raise _RuntimeWriterUndetermined("C2", "unassigned-primary")


def _detect_apport_sysv_suid_dumpable(root):
    def rooted(logical):
        return _rooted_source_path(root, logical)

    # R1/R2: exact bytes of the installed SysV init-script.
    init_path = rooted(APPORT_INIT_SCRIPT)
    init_st = _rw_lstat(init_path, "R2")
    if init_st is None:
        return RUNTIME_WRITER_NO_CONFLICT, "R1", None
    init_sha = hashlib.sha256(_rw_read_regular(init_path, init_st, "R2")).hexdigest()
    if init_sha not in APPORT_INIT_SCRIPT_SHA256:
        raise _RuntimeWriterUndetermined("R2", "sha256=" + init_sha)

    # R3: the init-script guard `[ -x "$AGENT" ]` follows symbolic links.
    agent_path = rooted(APPORT_AGENT)
    try:
        os.stat(agent_path)
    except FileNotFoundError:
        return RUNTIME_WRITER_NO_CONFLICT, "R3", "absent"
    except OSError as exc:
        raise _RuntimeWriterUndetermined("R3", _errno_token(exc))
    if not os.access(agent_path, os.X_OK):
        return RUNTIME_WRITER_NO_CONFLICT, "R3", "not-executable"

    # R4: the init-script does not start inside a container.
    try:
        fd = os.open(rooted(PID1_ENVIRON), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            environ = _read_all_fd(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise _RuntimeWriterUndetermined("R4", _errno_token(exc))
    if any(item.startswith(b"container=") for item in environ.split(b"\0")):
        return RUNTIME_WRITER_NO_CONFLICT, "R4", "container"

    # D17 owns systemd-native/generated/mask classification before D16. These
    # legacy R5/R6 checks remain as a direct D16 fail-closed guard if D16 is ever
    # invoked outside the D17 dispatcher.
    for logical in APPORT_MASK_PATHS:
        path = rooted(logical)
        st = _rw_lstat(path, "R6")
        if st is None:
            continue
        if stat.S_ISLNK(st.st_mode):
            try:
                target = os.readlink(path)
            except OSError as exc:
                raise _RuntimeWriterUndetermined("R6", _errno_token(exc))
            if target == "/dev/null":
                return RUNTIME_WRITER_NO_CONFLICT, "R5", logical
        raise _RuntimeWriterUndetermined("R6", logical)

    for logical in APPORT_OVERRIDE_PATHS:
        if _rw_lstat(rooted(logical), "R6") is not None:
            raise _RuntimeWriterUndetermined("R6", logical)

    # R7: only start links resolving exactly to the verified init-script count.
    valid_links = 0
    for logical_dir in APPORT_RC_DIRS:
        try:
            names = sorted(os.listdir(rooted(logical_dir)))
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise _RuntimeWriterUndetermined("R7", _errno_token(exc))
        for name in names:
            if not APPORT_RC_LINK_RE.fullmatch(name):
                continue
            logical_link = logical_dir + "/" + name
            link_path = rooted(logical_link)
            st = _rw_lstat(link_path, "R7")
            if st is None or not stat.S_ISLNK(st.st_mode):
                raise _RuntimeWriterUndetermined("R7", "not-symlink:" + logical_link)
            try:
                target = os.readlink(link_path)
                resolved = os.stat(link_path)
            except OSError as exc:
                raise _RuntimeWriterUndetermined("R7", _errno_token(exc) + ":" + logical_link)
            logical_target = os.path.normpath(target if target.startswith("/") else logical_dir + "/" + target)
            if logical_target != APPORT_INIT_SCRIPT or (resolved.st_dev, resolved.st_ino) != (init_st.st_dev, init_st.st_ino):
                raise _RuntimeWriterUndetermined("R7", "target:" + logical_link)
            valid_links += 1
    if valid_links == 0:
        raise _RuntimeWriterUndetermined("R7", "no-start-link")

    # R8/R9: /etc/default/apport is sourced as shell, so only exact bytes count.
    default_path = rooted(APPORT_DEFAULT_FILE)
    default_st = _rw_lstat(default_path, "R9")
    if default_st is None:
        return RUNTIME_WRITER_CONFLICT, "R8", "default-absent"
    default_sha = hashlib.sha256(_rw_read_regular(default_path, default_st, "R9")).hexdigest()
    if default_sha not in APPORT_DEFAULT_ENABLED_SHA256:
        raise _RuntimeWriterUndetermined("R9", "sha256=" + default_sha)
    return RUNTIME_WRITER_CONFLICT, "R8", "default-sha256=" + default_sha


def detect_runtime_writer_conflict(control_key, root="/"):
    """Return (verdict, step, detail) of the H46-D17->D16 P2R precondition; read-only."""
    if control_key not in RUNTIME_WRITER_RULES:
        return RUNTIME_WRITER_NO_CONFLICT, None, None
    try:
        native = _detect_apport_native_suid_dumpable(root)
    except _RuntimeWriterUndetermined as exc:
        step = _RuntimeWriterStep(exc.step, RUNTIME_WRITER_RULE_APPORT_NATIVE)
        return RUNTIME_WRITER_UNDETERMINED, step, exc.detail

    if native.verdict == RUNTIME_WRITER_CONFLICT:
        return RUNTIME_WRITER_CONFLICT, _RuntimeWriterStep(native.step, RUNTIME_WRITER_RULE_APPORT_NATIVE), native.detail
    if native.verdict == RUNTIME_WRITER_NO_CONFLICT:
        return RUNTIME_WRITER_NO_CONFLICT, native.step, native.detail
    if native.verdict != RUNTIME_WRITER_DELEGATE_SYSV:
        return RUNTIME_WRITER_UNDETERMINED, "detector-failure", None

    try:
        verdict, step, detail = _detect_apport_sysv_suid_dumpable(root)
    except _RuntimeWriterUndetermined as exc:
        return RUNTIME_WRITER_UNDETERMINED, exc.step, exc.detail
    if verdict == RUNTIME_WRITER_CONFLICT:
        return verdict, _RuntimeWriterStep(step, RUNTIME_WRITER_RULE_APPORT_SYSV), detail
    if verdict == RUNTIME_WRITER_UNDETERMINED:
        return verdict, step, detail
    if verdict == RUNTIME_WRITER_NO_CONFLICT:
        if native.auxiliary_nonempty:
            return RUNTIME_WRITER_UNDETERMINED, _RuntimeWriterStep("C6", RUNTIME_WRITER_RULE_APPORT_NATIVE), "auxiliary-with-sysv-no-conflict"
        return verdict, step, detail
    return RUNTIME_WRITER_UNDETERMINED, "detector-failure", None


def check_apply_privileges(persistent_target, runtime_target):
    """Read-only P3 approximation: refuse when current process lacks write access."""
    parent = str(PurePosixPath(persistent_target).parent)
    if not os.access(parent, os.W_OK) or not os.access(runtime_target, os.W_OK):
        raise PreconditionError("privilege:write-unavailable")


def _snapshot_for_result(path):
    try:
        return snapshot_persistent_target(path)
    except Exception:
        return None


def _read_for_result(read_runtime):
    try:
        return _require_int(read_runtime(), "runtime_after")
    except Exception:
        return None


def _observe_final_runtime(read_runtime):
    try:
        raw = read_runtime()
    except Exception:
        return None, "runtime:final-read-failure"
    try:
        return _require_int(raw, "runtime_after"), None
    except Exception:
        return None, "runtime:final-parse-failure"


def _compensate_after_failure(state, actions, original_reason):
    try:
        actions.append("persistent_compensation")
        compensate_persistent(state)
        return OUTCOME_FAILED_NOT_COMMITTED, original_reason
    except CompensationError as exc:
        return OUTCOME_FAILED_COMPENSATION, original_reason + ";compensation:" + exc.code


def _precondition_reason(exc):
    if not isinstance(exc, PreconditionError):
        raise ContractError("invalid precondition error")
    if exc.source is None:
        return exc.code
    if isinstance(exc.source, tuple):
        detail = ",".join(str(item) for item in exc.source)
    else:
        detail = str(exc.source)
    return exc.code + ":" + detail


def _revalidate_persistent_before_runtime(target_path, prestate):
    name = PurePosixPath(target_path).name
    try:
        current = snapshot_persistent_target(target_path)
    except Exception as exc:
        raise PreconditionError("persistent:drift-before-runtime", name) from exc
    if current != prestate:
        raise PreconditionError("persistent:drift-before-runtime", name)


def execute_control(
    control_id,
    key,
    op,
    expected,
    apply_supported,
    source_files=None,
    *,
    source_root="/",
    dry_run=False,
    persistent_target=None,
    runtime_target=None,
    read_runtime=None,
    write_runtime=None,
    write_runtime_protocol=None,
    privilege_check=None,
    runtime_writer_detector=None,
    persistent_uid=0,
    persistent_gid=0,
    persistent_mode=0o644,
):
    """Execute one control transaction using the r10 branch/compensation semantics.

    When `source_files` is None, the adapter reads the D08 source set through
    load_sysctl_sources(). Tests may pass structured SourceFile objects directly
    or redirect source_root/persistent/runtime targets away from the host.
    """
    validate_control_input(control_id, key, op, expected, apply_supported)
    if not isinstance(dry_run, bool):
        raise ContractError("dry_run must be boolean")
    for name, value in (("persistent_uid", persistent_uid), ("persistent_gid", persistent_gid), ("persistent_mode", persistent_mode)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ContractError(f"{name} must be integer")

    actions = ["P0_ELIGIBILITY"]
    if not apply_supported:
        return _result(control_id, key, op, expected, False, OUTCOME_NOT_ELIGIBLE,
                       "apply.supported=false", actions=actions, dry_run=dry_run)

    persistent_target = persistent_target or persistent_path(key)
    runtime_target = runtime_target or proc_path(key)
    read_runtime = read_runtime or (lambda: read_runtime_path(runtime_target))
    if write_runtime is None:
        write_runtime = lambda value: write_runtime_path(runtime_target, value)
        write_runtime_protocol = RUNTIME_WRITER_PROTOCOL_V1
    elif write_runtime_protocol != RUNTIME_WRITER_PROTOCOL_V1:
        return _result(
            control_id, key, op, expected, True, OUTCOME_ABORT_OTHER,
            "runtime:writer-protocol-required", actions=actions, dry_run=dry_run,
        )
    privilege_check = privilege_check or (lambda: check_apply_privileges(persistent_target, runtime_target))
    runtime_writer_detector = runtime_writer_detector or (
        lambda control_key: detect_runtime_writer_conflict(control_key, source_root)
    )

    runtime_before = None
    persistent_before = None
    precedence = None
    target = None
    branch = None
    attempt_identity = None
    runtime_prewrite = None
    runtime_after = None
    written_value = None
    mutation = False

    # P1: runtime key presence/readability and integer semantics.
    actions.append("P1_RUNTIME_KEY_PRESENT")
    try:
        runtime_before = _require_int(read_runtime(), "runtime_before")
    except FileNotFoundError:
        return _result(control_id, key, op, expected, True, OUTCOME_NOT_APPLICABLE,
                       "runtime:key-absent", actions=actions, dry_run=dry_run)
    except Exception as exc:
        return _result(control_id, key, op, expected, True, OUTCOME_ABORT_OTHER,
                       "runtime:initial-read-failure", actions=actions, dry_run=dry_run)

    # P2: source discovery/parsing/precedence and own persistent observation.
    # For production filesystem discovery, remember whether P2 actually observed
    # the own basename. The following target snapshot must agree with that fact.
    actions.append("P2_SOURCE_PRECEDENCE")
    own_present_during_p2 = None
    try:
        if source_files is None:
            source_files = load_sysctl_sources(key, source_root)
            own_path = persistent_path(key)
            own_present_during_p2 = any(src.path == own_path for src in source_files)
        precedence = resolve_precedence(key, source_files)
    except PreconditionError as exc:
        outcome = OUTCOME_ABORT_CONFLICT if exc.code == "source:late-conflict" else OUTCOME_ABORT_OTHER
        # H46-D08: a P2 refusal does not change the own file, but the report must
        # still carry its factual state when it can be observed read-only.
        persistent_before = _snapshot_for_result(persistent_target)
        return _result(control_id, key, op, expected, True, outcome, _precondition_reason(exc),
                       runtime_before=runtime_before, persistent_before=persistent_before,
                       persistent_after=persistent_before, actions=actions, dry_run=dry_run)
    except Exception:
        persistent_before = _snapshot_for_result(persistent_target)
        return _result(control_id, key, op, expected, True, OUTCOME_ABORT_OTHER,
                       "source:precedence-failure", runtime_before=runtime_before,
                       persistent_before=persistent_before, persistent_after=persistent_before,
                       actions=actions, dry_run=dry_run)

    try:
        persistent_before = snapshot_persistent_target(persistent_target)
    except PreconditionError as exc:
        return _result(control_id, key, op, expected, True, OUTCOME_ABORT_OTHER, _precondition_reason(exc),
                       effective_foreign_value=precedence.effective_foreign_value,
                       runtime_before=runtime_before, actions=actions, dry_run=dry_run)
    except Exception:
        return _result(control_id, key, op, expected, True, OUTCOME_ABORT_OTHER,
                       "persistent:initial-read-failure",
                       effective_foreign_value=precedence.effective_foreign_value,
                       runtime_before=runtime_before, actions=actions, dry_run=dry_run)

    if own_present_during_p2 is not None and persistent_before.exists != own_present_during_p2:
        return _result(
            control_id, key, op, expected, True, OUTCOME_ABORT_OTHER,
            "persistent:observation-drift",
            effective_foreign_value=precedence.effective_foreign_value,
            runtime_before=runtime_before, persistent_before=persistent_before,
            persistent_after=persistent_before, actions=actions, dry_run=dry_run,
        )

    own_value = None
    if op == "ge" and persistent_before.exists:
        try:
            own_value = own_persistent_value(key, persistent_before.raw_bytes)
        except PreconditionError as exc:
            return _result(control_id, key, op, expected, True, OUTCOME_ABORT_OTHER, _precondition_reason(exc),
                           effective_foreign_value=precedence.effective_foreign_value,
                           runtime_before=runtime_before, persistent_before=persistent_before,
                           persistent_after=persistent_before, actions=actions, dry_run=dry_run)

    try:
        target = compute_target_value(op, expected, runtime_before, own_value, precedence.effective_foreign_value)
        persistent_ok = persistent_is_compliant(
            key, target,
            persistent_before.raw_bytes if persistent_before.exists else None,
            persistent_before.uid if persistent_before.exists else None,
            persistent_before.gid if persistent_before.exists else None,
            persistent_before.mode if persistent_before.exists else None,
            persistent_uid, persistent_gid, persistent_mode,
        )
        runtime_ok = runtime_is_compliant(op, runtime_before, target)
        branch = select_branch(runtime_ok, persistent_ok)
    except Exception:
        return _result(control_id, key, op, expected, True, OUTCOME_ABORT_OTHER,
                       "planning:failure", effective_foreign_value=precedence.effective_foreign_value,
                       runtime_before=runtime_before, persistent_before=persistent_before,
                       persistent_after=persistent_before, actions=actions, dry_run=dry_run)

    # P3: read-only privilege/access precondition before target mutation.
    actions.append("P3_PRIVILEGE")
    try:
        privilege_check()
    except Exception:
        return _result(control_id, key, op, expected, True, OUTCOME_ABORT_OTHER,
                       "privilege:write-unavailable", branch=branch, target_value=target,
                       effective_foreign_value=precedence.effective_foreign_value,
                       runtime_before=runtime_before, persistent_before=persistent_before,
                       persistent_after=persistent_before, actions=actions, dry_run=dry_run)

    # P2R (H46-D16): read-only runtime-writer conflict precondition. It runs after
    # P3 and before the dry-run outcome or the first target mutation, identically
    # in APPLY and dry-run.
    if key in RUNTIME_WRITER_RULES:
        actions.append("P2R_RUNTIME_WRITER")
        try:
            verdict, step, detail = runtime_writer_detector(key)
        except Exception:
            verdict, step, detail = RUNTIME_WRITER_UNDETERMINED, "detector-failure", None
        if verdict not in (RUNTIME_WRITER_CONFLICT, RUNTIME_WRITER_NO_CONFLICT, RUNTIME_WRITER_UNDETERMINED):
            verdict, step, detail = RUNTIME_WRITER_UNDETERMINED, "detector-failure", None
        if verdict != RUNTIME_WRITER_NO_CONFLICT:
            rule_id = getattr(step, "rule_id", None)
            if verdict == RUNTIME_WRITER_CONFLICT:
                outcome = OUTCOME_ABORT_CONFLICT
                reason = "runtime-writer:" + (rule_id or RUNTIME_WRITER_RULES[key])
            else:
                outcome = OUTCOME_ABORT_OTHER
                reason = "runtime-writer:undetermined"
                if rule_id is not None:
                    reason += ":" + rule_id
            for part in (step, detail):
                if part is not None:
                    reason += ":" + str(part)
            return _result(control_id, key, op, expected, True, outcome, reason,
                           branch=branch, target_value=target,
                           effective_foreign_value=precedence.effective_foreign_value,
                           runtime_before=runtime_before, persistent_before=persistent_before,
                           persistent_after=persistent_before, actions=actions, dry_run=dry_run)

    if dry_run:
        outcome = OUTCOME_ALREADY_COMPLIANT if branch == BRANCH_ALREADY else OUTCOME_DRY_RUN_WOULD_APPLY
        reason = "already-compliant" if branch == BRANCH_ALREADY else "would-apply:" + branch
        return _result(control_id, key, op, expected, True, outcome, reason,
                       branch=branch, target_value=target,
                       effective_foreign_value=precedence.effective_foreign_value,
                       runtime_before=runtime_before, runtime_after=runtime_before,
                       persistent_before=persistent_before, persistent_after=persistent_before,
                       actions=actions, commit=COMMIT_NOT_STARTED, dry_run=True)

    persistent_state = None
    runtime_result = None

    if branch in (BRANCH_PERSISTENT_ONLY, BRANCH_BOTH):
        actions.append("PHASE1_PERSISTENT")
        try:
            persistent_state = apply_persistent_change(
                persistent_target, canonical_persistent_bytes(key, target),
                persistent_uid, persistent_gid, persistent_mode,
                expected_prestate=persistent_before,
            )
            attempt_identity = persistent_state.attempt_written_identity
            mutation = True
        except PreconditionError as exc:
            return _result(control_id, key, op, expected, True, OUTCOME_ABORT_OTHER, _precondition_reason(exc),
                           branch=branch, target_value=target,
                           effective_foreign_value=precedence.effective_foreign_value,
                           runtime_before=runtime_before, persistent_before=persistent_before,
                           persistent_after=_snapshot_for_result(persistent_target), actions=actions,
                           mutation=False, commit=COMMIT_NOT_STARTED, dry_run=False)
        except PersistentPhaseError as exc:
            return _result(control_id, key, op, expected, True, exc.outcome, exc.code,
                           branch=branch, target_value=target,
                           effective_foreign_value=precedence.effective_foreign_value,
                           runtime_before=runtime_before, runtime_after=_read_for_result(read_runtime),
                           persistent_before=persistent_before, persistent_after=_snapshot_for_result(persistent_target),
                           actions=actions, mutation=exc.mutation_performed,
                           commit=COMMIT_NOT_COMMITTED, attempt_identity=exc.attempt_written_identity,
                           dry_run=False)

    if branch in (BRANCH_RUNTIME_ONLY, BRANCH_BOTH):
        actions.append("PHASE2_RUNTIME")
        pre_write_guard = None
        if branch == BRANCH_RUNTIME_ONLY:
            pre_write_guard = lambda: _revalidate_persistent_before_runtime(
                persistent_target, persistent_before
            )
        try:
            runtime_result = execute_runtime_phase(
                op, target, read_runtime, write_runtime,
                writer_protocol=RUNTIME_WRITER_PROTOCOL_V1,
                pre_write_guard=pre_write_guard,
            )
            runtime_prewrite = runtime_result.runtime_prewrite
            runtime_after = runtime_result.runtime_after
            written_value = runtime_result.written_value
            mutation = mutation or runtime_result.write_performed
        except RuntimeMutationPreconditionError as exc:
            runtime_prewrite = exc.runtime_prewrite
            return _result(
                control_id, key, op, expected, True, OUTCOME_ABORT_OTHER, exc.reason,
                branch=branch, target_value=target,
                effective_foreign_value=precedence.effective_foreign_value,
                runtime_before=runtime_before, runtime_prewrite=runtime_prewrite,
                runtime_after=runtime_prewrite, persistent_before=persistent_before,
                persistent_after=_snapshot_for_result(persistent_target),
                written_value=None, actions=actions, mutation=False,
                commit=COMMIT_NOT_STARTED, attempt_identity=attempt_identity, dry_run=False,
            )
        except RuntimePhaseError as exc:
            runtime_prewrite = exc.runtime_prewrite
            runtime_after = exc.runtime_after if exc.runtime_after is not None else _read_for_result(read_runtime)
            written_value = exc.written_value
            mutation = mutation or exc.write_performed
            if persistent_state is not None:
                outcome, reason = _compensate_after_failure(persistent_state, actions, exc.code)
            else:
                outcome, reason = OUTCOME_FAILED_NOT_COMMITTED, exc.code
            return _result(control_id, key, op, expected, True, outcome, reason,
                           branch=branch, target_value=target,
                           effective_foreign_value=precedence.effective_foreign_value,
                           runtime_before=runtime_before, runtime_prewrite=runtime_prewrite,
                           runtime_after=runtime_after, persistent_before=persistent_before,
                           persistent_after=_snapshot_for_result(persistent_target), written_value=written_value,
                           actions=actions, mutation=mutation, commit=COMMIT_NOT_COMMITTED,
                           attempt_identity=attempt_identity, dry_run=False)

    # Final post-check of both components. No implicit branch change is allowed.
    actions.append("FINAL_POSTCHECK")
    final_runtime, final_runtime_error = _observe_final_runtime(read_runtime)
    final_persistent_error = None
    try:
        final_persistent = snapshot_persistent_target(persistent_target)
    except PreconditionError as exc:
        final_persistent = None
        final_persistent_error = _precondition_reason(exc)
    except Exception:
        final_persistent = None
        final_persistent_error = "persistent:final-read-failure"

    runtime_final_ok = (
        final_runtime_error is None and final_runtime is not None
        and runtime_is_compliant(op, final_runtime, target)
    )
    persistent_final_ok = (
        final_persistent_error is None and final_persistent is not None and final_persistent.exists and
        persistent_is_compliant(key, target, final_persistent.raw_bytes,
                                final_persistent.uid, final_persistent.gid, final_persistent.mode,
                                persistent_uid, persistent_gid, persistent_mode)
    )

    if not runtime_final_ok or not persistent_final_ok:
        if final_runtime_error is not None:
            reason = final_runtime_error
        elif not runtime_final_ok:
            reason = "postcheck:runtime-noncompliant"
        elif final_persistent_error is not None:
            reason = final_persistent_error
        else:
            reason = "postcheck:persistent-noncompliant"
        if persistent_state is not None:
            outcome, reason = _compensate_after_failure(persistent_state, actions, reason)
        else:
            outcome = OUTCOME_FAILED_NOT_COMMITTED
        return _result(control_id, key, op, expected, True, outcome, reason,
                       branch=branch, target_value=target,
                       effective_foreign_value=precedence.effective_foreign_value,
                       runtime_before=runtime_before,
                       runtime_prewrite=runtime_prewrite,
                       runtime_after=final_runtime,
                       persistent_before=persistent_before,
                       persistent_after=_snapshot_for_result(persistent_target),
                       written_value=written_value, actions=actions, mutation=mutation,
                       commit=COMMIT_NOT_COMMITTED, attempt_identity=attempt_identity, dry_run=False)

    if mutation:
        outcome = OUTCOME_APPLIED
        reason = "applied"
    else:
        outcome = OUTCOME_ALREADY_COMPLIANT
        reason = "already-compliant"
    return _result(control_id, key, op, expected, True, outcome, reason,
                   branch=branch, target_value=target,
                   effective_foreign_value=precedence.effective_foreign_value,
                   runtime_before=runtime_before,
                   runtime_prewrite=runtime_prewrite,
                   runtime_after=final_runtime,
                   persistent_before=persistent_before,
                   persistent_after=final_persistent,
                   written_value=written_value, actions=actions, mutation=mutation,
                   commit=COMMIT_COMMITTED, attempt_identity=attempt_identity, dry_run=False)


REPORT_STATE_DIR = "/var/log/securelinux-policy"
REPORT_APPLY_LOG = "apply.log"
REPORT_DEBUG_LOG = "debug.log"
REPORT_JSON = "report.json"
COVERAGE_STATEMENT = (
    "SecureLinux-Policy reports coverage of a subset of source requirements; "
    "this report is not evidence of conformity with the source document as a whole."
)
RUNTIME_TOCTOU_LIMITATION = (
    "No atomic compare-and-set is available for the runtime write; the guarantee is limited "
    "to values actually observed at runtime_before/runtime_prewrite and the final post-check."
)
PERSISTENT_TOCTOU_LIMITATION = (
    "No atomic compare-and-swap is available between persistent target revalidation and rename."
)
COMPENSATION_TOCTOU_LIMITATION = (
    "No atomic compare-and-swap is available between compensation ownership revalidation "
    "and the destructive rename/unlink."
)


@dataclass(frozen=True)
class BatchExecutionResult:
    controls: tuple
    rc_zero: bool
    report_path: str
    apply_log_path: str
    debug_log_path: str
    started_at: str
    finished_at: str


def _timestamp_now():
    return _datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def _identity_report(identity):
    if identity is None:
        return None
    if not isinstance(identity, ObjectIdentity):
        raise ContractError("invalid identity for report")
    return {
        "exists": identity.exists,
        "st_dev": identity.st_dev,
        "st_ino": identity.st_ino,
        "file_type": identity.file_type,
        "st_nlink": identity.st_nlink,
        "uid": identity.uid,
        "gid": identity.gid,
        "mode": identity.mode,
        "bytes_b64": (
            None if identity.raw_bytes is None
            else base64.b64encode(identity.raw_bytes).decode("ascii")
        ),
    }


def outcome_rc_contribution(outcome, dry_run=False):
    """Return the r10 semantic RC contribution without choosing a CLI nonzero integer."""
    if not isinstance(outcome, str):
        raise ContractError("outcome must be text")
    if not isinstance(dry_run, bool):
        raise ContractError("dry_run must be boolean")
    if outcome in (OUTCOME_APPLIED, OUTCOME_ALREADY_COMPLIANT, OUTCOME_NOT_ELIGIBLE):
        return "0"
    if dry_run and outcome == OUTCOME_DRY_RUN_WOULD_APPLY:
        return "0"
    return "nonzero"


def _target_value_rule(result):
    if result.target_value is None:
        return None
    return "eq-exact" if result.op == "eq" else "ge-max-preserve"


def _operator_decision_for_result(result):
    if result.outcome != OUTCOME_ABORT_CONFLICT or result.mutation_performed:
        return None
    prefix = "runtime-writer:"
    if not result.reason.startswith(prefix):
        return None
    rule_id = result.reason[len(prefix):].split(":", 1)[0]
    service = SERVICE_MANAGED_RUNTIME_WRITERS.get(rule_id)
    if service is None or result.runtime_before is None:
        return None
    return {
        "class": "SERVICE_MANAGED_PARAMETER",
        "required": True,
        "service": service,
        "parameter": result.key,
        "current_value": result.runtime_before,
    }


def control_result_to_report(result, started_at, finished_at):
    if not isinstance(result, ControlExecutionResult):
        raise ContractError("invalid control result")
    record = {
        "control_id": result.control_id,
        "key": result.key,
        "op": result.op,
        "expected": result.expected,
        "runtime_before": result.runtime_before,
        "persistent_before": _identity_report(result.persistent_before),
        "effective_foreign_value": result.effective_foreign_value,
        "target_value": result.target_value,
        "target_value_rule": _target_value_rule(result),
        "written_value": result.written_value,
        "runtime_after": result.runtime_after,
        "persistent_after": _identity_report(result.persistent_after),
        "persistent_path": persistent_path(result.key),
        "outcome": result.outcome,
        "reason": result.reason,
        "started_at": started_at,
        "finished_at": finished_at,
        "runtime_prewrite": result.runtime_prewrite,
        "dry_run": result.dry_run,
        "actions_attempted": list(result.actions_attempted),
        "step_rc": outcome_rc_contribution(result.outcome, result.dry_run),
        "mutation_performed": result.mutation_performed,
        "transaction_commit": result.transaction_commit,
        "eligible": result.eligible,
        "attempt_written_identity": _identity_report(result.attempt_written_identity),
        "branch": result.branch,
    }
    operator_decision = _operator_decision_for_result(result)
    if operator_decision is not None:
        record["operator_decision"] = operator_decision
    return record


def _open_reporting_log(path, append=False):
    parent = os.path.dirname(path)
    name = os.path.basename(path)
    dir_fd = _open_dir_nofollow(parent)
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if append:
        flags |= os.O_APPEND
    try:
        fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
    except Exception:
        os.close(dir_fd)
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise PreconditionError("reporting:forbidden-log-object", path)
        return dir_fd, fd
    except Exception:
        os.close(fd)
        os.close(dir_fd)
        raise


def _ensure_log_file(path):
    dir_fd, fd = _open_reporting_log(path, append=False)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
        os.close(dir_fd)


def _append_log(path, timestamp, message):
    line = f"[{timestamp}] {message}\n".encode("utf-8", "backslashreplace")
    dir_fd, fd = _open_reporting_log(path, append=True)
    try:
        _write_all(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)
        os.close(dir_fd)


def _atomic_write_report(path, payload):
    parent = os.path.dirname(path)
    name = os.path.basename(path)
    dir_fd = _open_dir_nofollow(parent)
    temp_name = f".{name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    fd = None
    try:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temp_name, flags, 0o600, dir_fd=dir_fd)
        data = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        _write_all(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(temp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        temp_name = None
        _fsync_dir(dir_fd)
    finally:
        if fd is not None:
            os.close(fd)
        if temp_name is not None:
            _unlink_if_exists(dir_fd, temp_name)
        os.close(dir_fd)


def _validate_batch_control(control):
    if not isinstance(control, dict):
        raise ContractError("batch control must be mapping")
    required = ("control_id", "key", "op", "expected", "apply_supported")
    missing = [name for name in required if name not in control]
    if missing:
        raise ContractError("batch control missing:" + ",".join(missing))
    validate_control_input(
        control["control_id"], control["key"], control["op"],
        control["expected"], control["apply_supported"],
    )
    return {name: control[name] for name in required}


def execute_batch(
    controls,
    *,
    state_dir=REPORT_STATE_DIR,
    dry_run=False,
    execute_one=None,
    common_execute_kwargs=None,
    now_fn=None,
):
    """Execute every control independently and maintain D12/D13 reporting artifacts.

    The function deliberately returns rc_zero rather than a numeric process exit code.
    r10 fixes only zero vs nonzero contribution; the concrete CLI nonzero integer is
    assigned later by the CLI contract.
    """
    if isinstance(controls, (str, bytes)) or not hasattr(controls, "__iter__"):
        raise ContractError("controls must be iterable")
    if not isinstance(state_dir, str) or not state_dir.startswith("/"):
        raise ContractError("state_dir must be absolute")
    if not isinstance(dry_run, bool):
        raise ContractError("dry_run must be boolean")
    execute_one = execute_one or execute_control
    if not callable(execute_one):
        raise ContractError("execute_one must be callable")
    common_execute_kwargs = {} if common_execute_kwargs is None else dict(common_execute_kwargs)
    now_fn = now_fn or _timestamp_now
    if not callable(now_fn):
        raise ContractError("now_fn must be callable")

    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    # Reject a symlink/non-directory state path before any reporting write.
    _state_fd = _open_dir_nofollow(state_dir)
    os.close(_state_fd)
    apply_log_path = os.path.join(state_dir, REPORT_APPLY_LOG)
    debug_log_path = os.path.join(state_dir, REPORT_DEBUG_LOG)
    report_path = os.path.join(state_dir, REPORT_JSON)
    started_at = now_fn()
    records = []
    payload = {
        "mechanism_id": MECHANISM_ID,
        "adapter_id": ADAPTER_ID,
        "dry_run": dry_run,
        "started_at": started_at,
        "finished_at": None,
        "complete": False,
        "rc_zero": None,
        "run_error": None,
        "coverage_statement": COVERAGE_STATEMENT,
        "controls": records,
    }
    # D12: establish report.json before operations on sibling reporting artifacts,
    # so a refusal on apply.log/debug.log can still be reported.
    _atomic_write_report(report_path, payload)
    try:
        _ensure_log_file(apply_log_path)
        _ensure_log_file(debug_log_path)
        _append_log(apply_log_path, started_at, f"batch start dry_run={str(dry_run).lower()}")
    except BaseException as exc:
        finished_at = now_fn()
        payload["run_error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
            "phase": "reporting-bootstrap",
        }
        payload["finished_at"] = finished_at
        payload["complete"] = False
        payload["rc_zero"] = False
        try:
            _atomic_write_report(report_path, payload)
        except Exception:
            pass
        raise

    try:
        raw_controls = list(controls)
        for raw_control in raw_controls:
            control = None
            c_started = now_fn()
            try:
                control = _validate_batch_control(raw_control)
                _append_log(apply_log_path, c_started, f"control start {control['control_id']}")
                result = execute_one(
                    control["control_id"], control["key"], control["op"],
                    control["expected"], control["apply_supported"],
                    dry_run=dry_run, **common_execute_kwargs,
                )
                if not isinstance(result, ControlExecutionResult):
                    raise ContractError("execute_one returned invalid result")
            except BaseException as exc:
                c_finished = now_fn()
                _append_log(debug_log_path, c_finished, traceback.format_exc().rstrip())
                payload["run_error"] = {
                    "control_id": None if control is None else control["control_id"],
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
                payload["finished_at"] = c_finished
                payload["complete"] = False
                payload["rc_zero"] = False
                _atomic_write_report(report_path, payload)
                _append_log(
                    apply_log_path, c_finished,
                    "control crash <invalid>" if control is None else f"control crash {control['control_id']}",
                )
                raise

            c_finished = now_fn()
            record = control_result_to_report(result, c_started, c_finished)
            records.append(record)
            _atomic_write_report(report_path, payload)
            _append_log(
                apply_log_path, c_finished,
                f"control finish {control['control_id']} outcome={result.outcome} step_rc={record['step_rc']}",
            )

        finished_at = now_fn()
        rc_zero = all(record["step_rc"] == "0" for record in records)
        payload["finished_at"] = finished_at
        payload["complete"] = True
        payload["rc_zero"] = rc_zero
        _atomic_write_report(report_path, payload)
        _append_log(apply_log_path, finished_at, f"batch finish rc_zero={str(rc_zero).lower()}")
        return BatchExecutionResult(
            tuple(records), rc_zero, report_path, apply_log_path, debug_log_path,
            started_at, finished_at,
        )
    except BaseException:
        # If a failure happened outside the per-control wrapper, make one final
        # best-effort report write without hiding the original exception.
        if payload["run_error"] is None:
            finished_at = now_fn()
            payload["run_error"] = {"type": "batch_exception", "message": "batch aborted"}
            payload["finished_at"] = finished_at
            payload["complete"] = False
            payload["rc_zero"] = False
            try:
                _atomic_write_report(report_path, payload)
                _append_log(debug_log_path, finished_at, traceback.format_exc().rstrip())
            except Exception:
                pass
        raise


def _selftest():
    validate_control_input("CTRL-1", "vm.mmap_min_addr", "ge", 4096, True)
    assert parse_integer_bytes(b" -0003 \r\n") == -3
    assert compute_target_value("ge", 4096, 8192, 16384, 32768) == 32768
    assert canonical_persistent_bytes("vm.mmap_min_addr", 4096).endswith(b"vm.mmap_min_addr = 4096\n")
    assert select_branch(True, False) == BRANCH_PERSISTENT_ONLY
    print("PURE_ADAPTER_CORE_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
