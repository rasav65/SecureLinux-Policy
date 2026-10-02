#!/usr/bin/env python3
"""APPLY adapter for SRC-0001 local account password state.

Emits a Bash function whose body runs an embedded Python transaction under
`command /usr/bin/python3 -I -S -B -`. Semantics come from the eight closed
definitions bound by product/contracts/src0001-apply/composition-v1.json.
"""

import re

COMPOSITION_CONTRACT_ID = "local-account-password-state-apply-composition-v1"
CHECK_CONTRACT_ID = "local-account-password-state-check-semantic-v2"
ADAPTER_ID = "product-local-account-password-state-apply-v1"
ADAPTER_CONTRACT_VERSION = "product-local-account-password-state-apply-adapter-v1"
BINDING_CONTRACT_ID = "product-local-account-password-state-apply-binding-v1"
TARGET_ID = "linux-x86_64-supported-v1"
PARAMETER_KIND = "local-account-password-state"
APPLY_KIND = "local-account-password-lock"
OPERATION = "apply"
WIRE_RECORD_ID = "SLP-APPLY-REPORT-V1"

CONTROL_ID_PATTERN = r"^(?!.*[\r\n])[A-Za-z0-9._-]+$"
EXPECTED_CONTROL_ID = "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE"
EXPECTED_LOCATOR = "/etc/shadow"
EXPECTED_KEY = "password-field"
EXPECTED_VALUE = True
HEREDOC_TAG = "SLP_APPLY_SRC0001_PY"

# Return codes (approved contract).
RC_SUCCESS = 0
RC_USAGE = 2
RC_ABORT = 4
RC_PRIVILEGE = 5
RC_MUTATION = 6

TRANSACTION_SOURCE = """\
import ctypes
import ctypes.util
import errno
import hashlib
import json
import os
import re
import stat
import sys

CONTROL_ID = "FSTEC-LINUX-2022-2.1.1-LOCAL-ACCOUNT-PASSWORD-STATE"
SOURCE_ROW = "SRC-0001"
TARGET_CLASS = "shadow-password-field"
TARGET_PATH = "/etc/shadow"
PASSWD_PATH = "/etc/passwd"
PARENT_PATH = "/etc"
MACHINE_ID_PATH = "/etc/machine-id"
SCHEMA = "SLP-APPLY-REPORT-V1"
CHECK_CONTRACT_ID = "local-account-password-state-check-semantic-v2"

RC_SUCCESS = 0
RC_ABORT = 4
RC_PRIVILEGE = 5
RC_MUTATION = 6

ERROR_RE = re.compile(r"^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$")
USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*\\$?$")
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

ORDERED_STEPS = (
    "lock_acquire",
    "under_lock_reread",
    "temp_content_verification",
    "final_revalidation",
    "rename",
    "parent_dir_fsync",
    "post_check",
)
ALL_STEPS = ORDERED_STEPS + ("lock_release",)

ATTESTATION_FIELDS = (
    "attestation_version",
    "control_id",
    "host_identity",
    "prestate_sha256",
    "provider",
    "rollback_capable",
    "snapshot_id",
    "snapshot_scope",
    "source_row",
    "state",
    "target_path",
)


class Abort(Exception):
    def __init__(self, code):
        Exception.__init__(self, code)
        self.code = code


class Report(object):
    def __init__(self, mode):
        self.mode = mode
        self.prestate = {PASSWD_PATH: None, TARGET_PATH: None}
        self.target_set = None
        self.mutation_performed = False
        self.transaction_commit = "NOT_ATTEMPTED"
        self.observation = "NOT_APPLICABLE"
        self.snapshot = "NOT_REACHED"
        self.steps = dict((name, "NOT_REACHED") for name in ALL_STEPS)
        self.outcome = "ABORT_NO_MUTATION"
        self.error_source = None
        self.error_value = None

    def not_applicable(self):
        for name in ALL_STEPS:
            self.steps[name] = "NOT_APPLICABLE"

    def ok(self, name):
        self.steps[name] = "OK"

    def failed(self, name):
        self.steps[name] = "FAILED"

    def document(self):
        return {
            "schema": SCHEMA,
            "operation_mode": self.mode,
            "control_id": CONTROL_ID,
            "source_row": SOURCE_ROW,
            "target_class": TARGET_CLASS,
            "target_path": TARGET_PATH,
            "prestate_sha256": {
                PASSWD_PATH: self.prestate[PASSWD_PATH],
                TARGET_PATH: self.prestate[TARGET_PATH],
            },
            "exact_target_set": self.target_set,
            "mutation_performed": self.mutation_performed,
            "transaction_commit": self.transaction_commit,
            "observation_consistency": self.observation,
            "snapshot_precondition": self.snapshot,
            "steps": dict((name, self.steps[name]) for name in ALL_STEPS),
            "result": {
                "outcome": self.outcome,
                "error": {"source": self.error_source, "value": self.error_value},
            },
        }

    def emit(self):
        if self.error_value is not None and ERROR_RE.match(self.error_value) is None:
            self.error_value = "report:invalid-error-value"
        body = json.dumps(
            self.document(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        data = (body + "\\n").encode("utf-8")
        os.write(1, data)


def return_code(report):
    if report.outcome in ("DRY_RUN_SUCCESS", "NOOP_SUCCESS", "COMMITTED_SUCCESS"):
        return RC_SUCCESS
    if report.outcome == "ABORT_NO_MUTATION":
        if report.error_value == "privilege:root-required":
            return RC_PRIVILEGE
        return RC_ABORT
    return RC_MUTATION


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_all(fd):
    chunks = []
    offset = 0
    while True:
        block = os.pread(fd, 1 << 20, offset)
        if not block:
            break
        chunks.append(block)
        offset += len(block)
    return b"".join(chunks)


def open_verified_target(domain):
    try:
        fd = os.open(
            TARGET_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise Abort(domain + ":symlink")
        if exc.errno == errno.ENOENT:
            raise Abort(domain + ":not-found")
        raise Abort(domain + ":open-failed")
    try:
        info = os.fstat(fd)
    except OSError:
        os.close(fd)
        raise Abort(domain + ":stat-failed")
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise Abort(domain + ":not-regular")
    if info.st_nlink != 1:
        os.close(fd)
        raise Abort(domain + ":multiple-links")
    return fd, info


def open_parent():
    try:
        fd = os.open(
            PARENT_PATH, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError:
        raise Abort("parent:open-failed")
    try:
        info = os.fstat(fd)
    except OSError:
        os.close(fd)
        raise Abort("parent:stat-failed")
    if not stat.S_ISDIR(info.st_mode):
        os.close(fd)
        raise Abort("parent:not-directory")
    return fd, info


def read_passwd_bytes():
    try:
        fd = os.open(PASSWD_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise Abort("passwd:symlink")
        if exc.errno == errno.ENOENT:
            raise Abort("passwd:not-found")
        raise Abort("passwd:unreadable")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Abort("passwd:invalid-type")
        return read_all(fd)
    except OSError:
        raise Abort("passwd:read-failed")
    finally:
        os.close(fd)


def split_records(data):
    parts = data.split(b"\\n")
    if parts and parts[-1] == b"":
        parts.pop()
    return parts


def population(passwd_bytes, shadow_bytes):
    \"\"\"Recompute the bound CHECK v2 population.

    Returns (accounts, empty_users) or raises Abort with the exact CHECK code.
    \"\"\"
    for data, domain in ((passwd_bytes, "passwd"), (shadow_bytes, "shadow")):
        if b"\\x00" in data or b"\\r" in data:
            raise Abort(domain + ":invalid-bytes")
    passwd_lines = split_records(passwd_bytes)
    shadow_lines = split_records(shadow_bytes)
    if not passwd_lines:
        raise Abort("passwd:empty-file")
    if not shadow_lines:
        raise Abort("shadow:empty-file")

    shadow_pwd = {}
    for line in shadow_lines:
        if not line:
            raise Abort("shadow:empty-record")
        if line.count(b":") != 8:
            raise Abort("shadow:invalid-fields")
        fields = line.split(b":")
        user = fields[0]
        try:
            name = user.decode("utf-8")
        except UnicodeDecodeError:
            raise Abort("shadow:invalid-account")
        if USER_RE.match(name) is None:
            raise Abort("shadow:invalid-account")
        if user in shadow_pwd:
            raise Abort("shadow:duplicate-account")
        shadow_pwd[user] = fields[1]

    accounts = 0
    empty_users = []
    seen = set()
    for line in passwd_lines:
        if not line:
            raise Abort("passwd:empty-record")
        if line.count(b":") != 6:
            raise Abort("passwd:invalid-fields")
        user = line.split(b":")[0]
        try:
            name = user.decode("utf-8")
        except UnicodeDecodeError:
            raise Abort("passwd:invalid-account")
        if USER_RE.match(name) is None:
            raise Abort("passwd:invalid-account")
        if user in seen:
            raise Abort("passwd:duplicate-account")
        seen.add(user)
        if user not in shadow_pwd:
            raise Abort("passwd:missing-shadow-account")
        accounts += 1
        if shadow_pwd[user] == b"":
            empty_users.append(user)
    if accounts == 0:
        raise Abort("passwd:empty-population")
    return accounts, empty_users


def metadata_eligibility(fd):
    try:
        names = os.listxattr(fd)
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            names = []
        else:
            raise Abort("metadata:xattr-unknown")
    if names:
        raise Abort("metadata:xattr-present")
    acl_absent = set([errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP])
    if hasattr(errno, "ENOATTR"):
        acl_absent.add(errno.ENOATTR)
    try:
        os.getxattr(fd, "system.posix_acl_access")
    except OSError as exc:
        if exc.errno not in acl_absent:
            raise Abort("metadata:acl-unknown")
    else:
        raise Abort("metadata:acl-extended")


def transform(shadow_bytes, selected):
    if not selected:
        return shadow_bytes
    wanted = set(selected)
    out = []
    trailing = shadow_bytes.endswith(b"\\n")
    lines = split_records(shadow_bytes)
    for line in lines:
        fields = line.split(b":")
        if fields[0] in wanted:
            if fields[1] != b"":
                raise Abort("transform:stale-field")
            fields[1] = b"!"
            out.append(b":".join(fields))
        else:
            out.append(line)
    body = b"\\n".join(out)
    if trailing:
        body += b"\\n"
    return body


def load_attestation(path, host_identity, prestate_sha256):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Abort("attestation:missing")
    try:
        raw = read_all(fd)
    except OSError:
        raise Abort("attestation:read-failed")
    finally:
        os.close(fd)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Abort("attestation:invalid-encoding")

    def no_duplicates(pairs):
        keys = set()
        for key, _value in pairs:
            if key in keys:
                raise ValueError("duplicate key")
            keys.add(key)
        return dict(pairs)

    try:
        document = json.loads(text, object_pairs_hook=no_duplicates)
    except ValueError as exc:
        if "duplicate key" in str(exc):
            raise Abort("attestation:duplicate-key")
        raise Abort("attestation:invalid-json")
    if not isinstance(document, dict):
        raise Abort("attestation:not-object")
    for key in document:
        if key not in ATTESTATION_FIELDS:
            raise Abort("attestation:unknown-field")
    for key in ATTESTATION_FIELDS:
        if key not in document:
            raise Abort("attestation:missing-field")

    if not isinstance(document["attestation_version"], int) or isinstance(
        document["attestation_version"], bool
    ):
        raise Abort("attestation:invalid-type")
    if document["attestation_version"] != 1:
        raise Abort("attestation:invalid-version")
    if not isinstance(document["rollback_capable"], bool):
        raise Abort("attestation:invalid-type")
    for key in (
        "control_id",
        "host_identity",
        "prestate_sha256",
        "provider",
        "snapshot_id",
        "snapshot_scope",
        "source_row",
        "state",
        "target_path",
    ):
        if not isinstance(document[key], str):
            raise Abort("attestation:invalid-type")

    if document["control_id"] != CONTROL_ID:
        raise Abort("attestation:control-mismatch")
    if document["source_row"] != SOURCE_ROW:
        raise Abort("attestation:source-mismatch")
    if document["target_path"] != TARGET_PATH:
        raise Abort("attestation:target-mismatch")
    if document["snapshot_scope"] != "FULL_TARGET_HOST_OR_VM":
        raise Abort("attestation:invalid-scope")
    if document["state"] != "READY":
        raise Abort("attestation:state-not-ready")
    if document["rollback_capable"] is not True:
        raise Abort("attestation:rollback-not-capable")
    if HEX32_RE.match(document["host_identity"]) is None:
        raise Abort("attestation:host-format")
    if HEX64_RE.match(document["prestate_sha256"]) is None:
        raise Abort("attestation:prestate-format")
    for key in ("provider", "snapshot_id"):
        value = document[key]
        if not value:
            raise Abort("attestation:empty-field")
        for char in value:
            if ord(char) < 0x20 or ord(char) == 0x7F:
                raise Abort("attestation:control-character")
    if document["host_identity"] != host_identity:
        raise Abort("attestation:host-mismatch")
    if document["prestate_sha256"] != prestate_sha256:
        raise Abort("attestation:prestate-mismatch")


def machine_identity():
    try:
        fd = os.open(MACHINE_ID_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Abort("machine-id:read-failed")
    try:
        raw = read_all(fd)
    except OSError:
        raise Abort("machine-id:read-failed")
    finally:
        os.close(fd)
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise Abort("machine-id:invalid-format")
    if HEX32_RE.match(value) is None:
        raise Abort("machine-id:invalid-format")
    return value


def load_libc():
    name = ctypes.util.find_library("c")
    try:
        return ctypes.CDLL(name, use_errno=True)
    except OSError:
        raise Abort("lock:libc-unavailable")


def run_dry_run(report):
    report.observation = "POINT_IN_TIME_NON_COMMIT_AUTHORITY"
    report.snapshot = "NOT_CHECKED_NOT_REQUIRED_FOR_DRY_RUN"
    report.not_applicable()
    target_fd, _info = open_verified_target("shadow")
    try:
        shadow_bytes = read_all(target_fd)
        passwd_bytes = read_passwd_bytes()
        report.prestate[TARGET_PATH] = digest(shadow_bytes)
        report.prestate[PASSWD_PATH] = digest(passwd_bytes)
        _accounts, selected = population(passwd_bytes, shadow_bytes)
        metadata_eligibility(target_fd)
        transform(shadow_bytes, selected)
        report.target_set = [user.hex() for user in selected]
    finally:
        os.close(target_fd)
    report.outcome = "DRY_RUN_SUCCESS"
    return report


def create_temp(parent_fd, expected_bytes, uid, gid, mode, report):
    name = ".slp-apply-" + os.urandom(12).hex()
    try:
        fd = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o000,
            dir_fd=parent_fd,
        )
    except OSError:
        raise Abort("temp:create-failed")
    try:
        written = 0
        while written < len(expected_bytes):
            written += os.write(fd, expected_bytes[written:])
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        info = os.fstat(fd)
        if info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode:
            raise Abort("metadata:verify-failed")
        os.fsync(fd)
    except Abort:
        os.close(fd)
        remove_temp(parent_fd, name)
        raise
    except OSError:
        os.close(fd)
        remove_temp(parent_fd, name)
        raise Abort("temp:write-failed")

    try:
        actual = os.pread(fd, len(expected_bytes), 0)
        tail = os.pread(fd, 1, len(expected_bytes))
    except OSError:
        os.close(fd)
        remove_temp(parent_fd, name)
        report.failed("temp_content_verification")
        raise Abort("temp:verify-failed")
    if actual != expected_bytes or tail != b"":
        os.close(fd)
        remove_temp(parent_fd, name)
        report.failed("temp_content_verification")
        raise Abort("temp:verify-failed")
    report.ok("temp_content_verification")
    os.close(fd)
    return name


def remove_temp(parent_fd, name):
    if not name or parent_fd is None:
        return
    try:
        os.unlink(name, dir_fd=parent_fd)
    except OSError:
        pass


def run_apply(report, attestation_path):
    report.observation = "NOT_APPLICABLE"

    prelock_fd, prelock_info = open_verified_target("shadow")
    temp_name = None
    temp_parent_fd = None
    lock_taken = False
    libc = None
    try:
        shadow_bytes = read_all(prelock_fd)
        passwd_bytes = read_passwd_bytes()
        report.prestate[TARGET_PATH] = digest(shadow_bytes)
        report.prestate[PASSWD_PATH] = digest(passwd_bytes)
        _accounts, selected = population(passwd_bytes, shadow_bytes)

        if not selected:
            report.outcome = "NOOP_SUCCESS"
            report.observation = "POINT_IN_TIME_NON_COMMIT_AUTHORITY"
            report.snapshot = "NOT_CHECKED_NOT_REQUIRED_FOR_NOOP"
            report.not_applicable()
            report.target_set = []
            return report

        report.target_set = [user.hex() for user in selected]
        load_attestation(
            attestation_path, machine_identity(), report.prestate[TARGET_PATH]
        )
        report.snapshot = "PASS"

        libc = load_libc()
        if libc.lckpwdf() != 0:
            report.failed("lock_acquire")
            raise Abort("lock:acquire-failed")
        lock_taken = True
        report.ok("lock_acquire")

        under_lock_fd, under_info = open_verified_target("shadow")
        try:
            if (
                under_info.st_dev != prelock_info.st_dev
                or under_info.st_ino != prelock_info.st_ino
                or under_info.st_nlink != 1
            ):
                report.failed("under_lock_reread")
                raise Abort("reread:identity-drift")
            under_shadow = read_all(under_lock_fd)
            under_passwd = read_passwd_bytes()
            if digest(under_shadow) != report.prestate[TARGET_PATH]:
                report.failed("under_lock_reread")
                raise Abort("reread:drift")
            if digest(under_passwd) != report.prestate[PASSWD_PATH]:
                report.failed("under_lock_reread")
                raise Abort("reread:drift")
            _accounts, under_selected = population(under_passwd, under_shadow)
            if under_selected != selected:
                report.failed("under_lock_reread")
                raise Abort("reread:drift")
            report.ok("under_lock_reread")

            metadata_eligibility(under_lock_fd)
            metadata = os.fstat(under_lock_fd)
            uid = metadata.st_uid
            gid = metadata.st_gid
            mode = stat.S_IMODE(metadata.st_mode)
            expected_bytes = transform(under_shadow, under_selected)

            parent_fd, parent_info = open_parent()
            try:
                temp_name = create_temp(
                    parent_fd, expected_bytes, uid, gid, mode, report
                )
                temp_parent_fd = parent_fd

                final_shadow = read_all(under_lock_fd)
                final_info = os.fstat(under_lock_fd)
                if (
                    final_shadow != under_shadow
                    or final_info.st_dev != under_info.st_dev
                    or final_info.st_ino != under_info.st_ino
                    or final_info.st_nlink != 1
                ):
                    report.failed("final_revalidation")
                    raise Abort("final:identity-drift")
                final_passwd = read_passwd_bytes()
                _accounts, final_selected = population(final_passwd, final_shadow)
                if final_selected != under_selected:
                    report.failed("final_revalidation")
                    raise Abort("final:population-drift")

                rebind_fd, rebind_info = open_verified_target("shadow")
                try:
                    if (
                        rebind_info.st_dev != under_info.st_dev
                        or rebind_info.st_ino != under_info.st_ino
                    ):
                        report.failed("final_revalidation")
                        raise Abort("final:path-rebind-mismatch")
                finally:
                    os.close(rebind_fd)
                report.ok("final_revalidation")

                try:
                    os.rename(
                        temp_name,
                        os.path.basename(TARGET_PATH),
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                except OSError:
                    report.failed("rename")
                    report.transaction_commit = "NOT_COMMITTED"
                    raise Abort("rename:failed")
                temp_name = None
                report.ok("rename")
                report.mutation_performed = True

                try:
                    os.fsync(parent_fd)
                except OSError:
                    report.failed("parent_dir_fsync")
                    report.transaction_commit = "COMMITTED_DURABILITY_UNCERTAIN"
                    report.outcome = "COMMITTED_DURABILITY_UNCERTAIN"
                    report.error_source = "TRANSACTION"
                    report.error_value = "parent-dir:fsync-failed"
                    return report
                report.ok("parent_dir_fsync")
                report.transaction_commit = "COMMITTED"
            finally:
                os.close(parent_fd)
        finally:
            os.close(under_lock_fd)

        post_fd, _post_info = open_verified_target("shadow")
        try:
            post_shadow = read_all(post_fd)
            post_passwd = read_passwd_bytes()
        finally:
            os.close(post_fd)
        try:
            _accounts, post_selected = population(post_passwd, post_shadow)
        except Abort as exc:
            report.failed("post_check")
            report.outcome = "COMMITTED_FAILURE"
            report.error_source = "POST_CHECK_CHECK_ERROR"
            report.error_value = exc.code
            return report
        if post_selected:
            report.failed("post_check")
            report.outcome = "COMMITTED_FAILURE"
            report.error_source = "POST_CHECK_COMPLIANCE"
            report.error_value = "post-check:compliance-fail"
            return report
        report.ok("post_check")
        report.outcome = "COMMITTED_SUCCESS"
        return report
    finally:
        remove_temp(temp_parent_fd, temp_name)
        if lock_taken:
            released = False
            try:
                released = libc.ulckpwdf() == 0
            except Exception:
                released = False
            if released:
                report.ok("lock_release")
            else:
                report.failed("lock_release")
                if report.outcome == "COMMITTED_SUCCESS":
                    report.outcome = "COMMITTED_FAILURE"
                    report.error_source = "LOCK_RELEASE"
                    report.error_value = "lock:release-failed"


def finalize_abort(report, code):
    report.outcome = "ABORT_NO_MUTATION"
    report.error_source = "DRY_RUN" if report.mode == "DRY_RUN" else "TRANSACTION"
    report.error_value = code
    if report.mode == "APPLY":
        if report.snapshot not in ("PASS", "FAILED"):
            report.snapshot = "NOT_REACHED"
        if report.snapshot != "PASS":
            for name in ALL_STEPS:
                report.steps[name] = "NOT_REACHED"
        else:
            seen_bad = False
            for name in ORDERED_STEPS:
                if seen_bad:
                    report.steps[name] = "NOT_REACHED"
                elif report.steps[name] == "FAILED":
                    seen_bad = True
                elif report.steps[name] != "OK":
                    report.steps[name] = "NOT_REACHED"
                    seen_bad = True
        if report.transaction_commit not in ("NOT_ATTEMPTED", "NOT_COMMITTED"):
            report.transaction_commit = "NOT_ATTEMPTED"
    else:
        report.not_applicable()
        report.snapshot = "NOT_CHECKED_NOT_REQUIRED_FOR_DRY_RUN"
        report.observation = "POINT_IN_TIME_NON_COMMIT_AUTHORITY"


def main(argv):
    if len(argv) < 2:
        return 2
    mode = argv[1]
    if mode not in ("DRY_RUN", "APPLY"):
        return 2
    attestation_path = argv[2] if len(argv) > 2 else ""
    if mode == "APPLY" and not attestation_path:
        return 2
    if mode == "DRY_RUN" and attestation_path:
        return 2

    report = Report(mode)
    try:
        if os.geteuid() != 0:
            raise Abort("privilege:root-required")
        if mode == "DRY_RUN":
            run_dry_run(report)
        else:
            run_apply(report, attestation_path)
    except Abort as exc:
        if report.outcome in (
            "COMMITTED_SUCCESS",
            "COMMITTED_FAILURE",
            "COMMITTED_DURABILITY_UNCERTAIN",
        ):
            pass
        else:
            finalize_abort(report, exc.code)
    except Exception:
        finalize_abort(report, "transaction:internal-error")

    if report.outcome == "ABORT_NO_MUTATION" and report.target_set is None:
        report.target_set = None
    report.emit()
    return return_code(report)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""


def _sh_single(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def apply_shell_function(control_id, locator, key, op, expected):
    """Return the Bash function text that runs the APPLY transaction."""
    if not isinstance(control_id, str) or re.fullmatch(CONTROL_ID_PATTERN, control_id) is None:
        raise ValueError("invalid control id")
    if control_id != EXPECTED_CONTROL_ID:
        raise ValueError("unsupported control id")
    if locator != EXPECTED_LOCATOR:
        raise ValueError("locator must be exactly /etc/shadow")
    if key != EXPECTED_KEY or op != "all-nonempty" or expected is not True:
        raise ValueError("unsupported contract fields")
    if HEREDOC_TAG in TRANSACTION_SOURCE:
        raise ValueError("heredoc tag collision")

    fn = "slp_apply_" + re.sub(r"[^A-Za-z0-9_]", "_", control_id)
    lines = [
        fn + "() {",
        "  local _slp_mode=$1 _slp_attestation=${2:-}",
        "  local _slp_rc=0",
        '  if [[ "$_slp_mode" != DRY_RUN && "$_slp_mode" != APPLY ]]; then',
        "    printf '%s\\n' 'usage:invalid-mode' >&2",
        "    return " + str(RC_USAGE),
        "  fi",
        '  if [[ "$_slp_mode" == APPLY && -z "$_slp_attestation" ]]; then',
        "    printf '%s\\n' 'usage:attestation-required' >&2",
        "    return " + str(RC_USAGE),
        "  fi",
        '  if [[ "$_slp_mode" == DRY_RUN && -n "$_slp_attestation" ]]; then',
        "    printf '%s\\n' 'usage:attestation-not-allowed' >&2",
        "    return " + str(RC_USAGE),
        "  fi",
        "  LC_ALL=C command /usr/bin/python3 -I -S -B - "
        '"$_slp_mode" "$_slp_attestation" ' + "<<'" + HEREDOC_TAG + "'",
        TRANSACTION_SOURCE.rstrip("\n"),
        HEREDOC_TAG,
        "  _slp_rc=$?",
        "  return $_slp_rc",
        "}",
    ]
    return "\n".join(lines) + "\n"


def _selftest():
    source = apply_shell_function(
        EXPECTED_CONTROL_ID, "/etc/shadow", "password-field", "all-nonempty", True
    )
    compile(TRANSACTION_SOURCE, "<transaction>", "exec")
    assert "lckpwdf" in TRANSACTION_SOURCE and "ulckpwdf" in TRANSACTION_SOURCE
    assert "O_NOFOLLOW" in TRANSACTION_SOURCE
    assert "errors=" not in TRANSACTION_SOURCE
    assert "SLP-CHECK-V1" not in TRANSACTION_SOURCE
    assert "/dev/tty" not in TRANSACTION_SOURCE and "input(" not in TRANSACTION_SOURCE
    assert "subprocess" not in TRANSACTION_SOURCE
    assert "slp_apply_" in source and HEREDOC_TAG in source
    assert "command /usr/bin/python3 -I -S -B -" in source
    for token in ("sed -i", "chpasswd", "usermod", "passwd -l", "setfacl "):
        assert token not in source, token
    bad = (
        ("CTRL", "/etc/shadow", "password-field", "all-nonempty", True),
        (EXPECTED_CONTROL_ID, "/tmp/shadow", "password-field", "all-nonempty", True),
        (EXPECTED_CONTROL_ID, "/etc/shadow", "password", "all-nonempty", True),
        (EXPECTED_CONTROL_ID, "/etc/shadow", "password-field", "eq", True),
        (EXPECTED_CONTROL_ID, "/etc/shadow", "password-field", "all-nonempty", False),
    )
    for args in bad:
        try:
            apply_shell_function(*args)
        except ValueError:
            continue
        raise AssertionError("accepted invalid args: %r" % (args,))
    print("ADAPTER_SELFTEST=PASS")


if __name__ == "__main__":
    _selftest()
