#!/usr/bin/env python3
"""Refresh every byte pin after a source edit, or check that none is stale.

Run from the project root:

    python3 -I -B tools/refresh-pins.py --check
    python3 -I -B tools/refresh-pins.py --write [--reviewed DOC ...] [--reviewed-truth]

Stages, in this order:

1. CHECK adapter pins: implementation_sha256 and semantic_contract_sha256 in
   each adapter JSON listed by product/ADAPTER-REGISTRY.tsv, then the three SHA
   columns of the registry row.
2. APPLY bindings: tools/rebuild-apply-contract-bindings.py.
2a. The sha256 column of CONTROL-MANIFEST.tsv for changed control files: the
   generator refuses a control whose SHA differs from the manifest, so this
   carrier is refreshed before the artifact.
3. Tracked artifact: product/generate-product-check-v2.py into a temporary
   directory outside the repository; the tracked securelinux-policy.sh and its
   sidecar are replaced when the bytes differ.
4. Nested carriers: every SHA256SUMS and *.sha256 except the root manifests,
   and the sha256 column of CONTROL-MANIFEST.tsv. A carrier is processed only
   when it pins at least one path changed against HEAD (tracked diff or new
   untracked file); frozen historical carriers are never touched. In a
   processed carrier only lines of changed paths are rewritten; a stale line
   for an unchanged path is an error, not a refresh. Carriers are
   processed deepest first until nothing changes, because carriers pin
   carriers. A new file that no carrier lists is reported and fails: adding a
   path to a manifest is a decision, not a refresh.
5. Review baseline: the sha256 column of a changed document is rewritten only
   when the document is named with --reviewed; truth_sha256 of the state
   documents (computed over TRUTH_INPUTS without their sha256 and *_sha256
   columns) is rewritten only with --reviewed-truth. Both flags record that a
   person compared the document with the data; without them a stale row fails.
6. Root manifests: tools/rebuild-root-manifests.py.
7. tools/render-current-docs.py --check, then the whole check once more.

--check writes nothing and exits 1 when any stage would change a file.
--write that fails restores every Git-visible file to its bytes and mode before
the run and removes files the run created, then exits 2.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

ROOT_MANIFESTS = ("PROJECT-FILES.sha256", "SHA256SUMS")
ADAPTER_REGISTRY = "product/ADAPTER-REGISTRY.tsv"
CONTROL_MANIFEST = "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv"
# Каталог на документ: любой controls/fstec-core/<каталог>/CONTROL-MANIFEST.tsv.
CONTROL_MANIFEST_RE = re.compile(r"controls/fstec-core/[a-z0-9][a-z0-9-]*/CONTROL-MANIFEST\.tsv")


def is_control_manifest(rel: str) -> bool:
    return CONTROL_MANIFEST_RE.fullmatch(rel) is not None
REVIEW_BASELINE = "tests/documentation-v1/CURRENT-MARKDOWN-REVIEW-BASELINE.tsv"
BASELINE_TEST = "tests/documentation-v1/test_documentation_baseline.py"
ARTIFACT = "securelinux-policy.sh"
CHECKSUM_LINE = re.compile(r"([0-9a-f]{64})  (.+)")
PY = [sys.executable, "-I", "-B"]


class Stale(Exception):
    pass


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def git(root: Path, *args: str) -> str:
    cp = subprocess.run(["git", *args], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if cp.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {cp.stderr.strip()}")
    return cp.stdout


def changed_paths(root: Path) -> set[str]:
    tracked = git(root, "diff", "--name-only", "HEAD").splitlines()
    untracked = git(root, "ls-files", "--others", "--exclude-standard").splitlines()
    return {p for p in tracked + untracked if p}


def write_bytes(path: Path, raw: bytes) -> None:
    mode = path.stat().st_mode & 0o7777 if path.exists() else 0o644
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class Run:
    def __init__(self, root: Path, write: bool):
        self.root = root
        self.write = write
        self.actions: list[str] = []

    def put(self, rel: str, raw: bytes, why: str) -> None:
        path = self.root / rel
        if path.read_bytes() == raw:
            return
        action = f"{'UPDATE' if self.write else 'STALE'} {rel} ({why})"
        if action not in self.actions:
            self.actions.append(action)
        if self.write:
            write_bytes(path, raw)


def json_format(raw: bytes):
    data = json.loads(raw)
    for fmt in ("compact", "indent2"):
        if dump_json(data, fmt) == raw:
            return data, fmt
    raise RuntimeError("adapter JSON has an unknown serialization")


def dump_json(data, fmt: str) -> bytes:
    if fmt == "compact":
        return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return (json.dumps(data, sort_keys=True, indent=2, separators=(",", ": ")) + "\n").encode("utf-8")


def stage_adapter_pins(run: Run) -> None:
    reg_path = run.root / ADAPTER_REGISTRY
    text = reg_path.read_text(encoding="utf-8")
    lines = text.split("\n")
    header = lines[0].split("\t")
    want = ["parameter_kind", "adapter_id", "semantic_contract_path", "semantic_contract_sha256",
            "adapter_contract_path", "adapter_contract_sha256", "implementation_path", "implementation_sha256"]
    if header != want:
        raise RuntimeError(f"{ADAPTER_REGISTRY}: unexpected header")
    out = [lines[0]]
    for line in lines[1:]:
        if not line:
            out.append(line)
            continue
        f = line.split("\t")
        if len(f) != len(want):
            raise RuntimeError(f"{ADAPTER_REGISTRY}: malformed row {f[:2]}")
        contract_sha = sha256_file(run.root / f[2])
        impl_sha = sha256_file(run.root / f[6])
        data, fmt = json_format((run.root / f[4]).read_bytes())
        data["semantic_contract_sha256"] = contract_sha
        data["implementation_sha256"] = impl_sha
        new_json = dump_json(data, fmt)
        run.put(f[4], new_json, "adapter pins")
        f[3], f[5], f[7] = contract_sha, sha256_bytes(new_json), impl_sha
        out.append("\t".join(f))
    run.put(ADAPTER_REGISTRY, "\n".join(out).encode("utf-8"), "registry pins")


def stage_apply_bindings(run: Run) -> None:
    mode = "--write" if run.write else "--check"
    cp = subprocess.run(PY + ["tools/rebuild-apply-contract-bindings.py", "--project-root", ".", mode],
                        cwd=run.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if cp.returncode != 0:
        if not run.write and "stale" in cp.stderr:
            run.actions.append("STALE APPLY bindings (tools/rebuild-apply-contract-bindings.py)")
            return
        raise RuntimeError("APPLY bindings: " + (cp.stdout + cp.stderr).strip())


def stage_artifact(run: Run) -> None:
    if not run.write and run.actions:
        # The generator refuses stale adapter or APPLY pins; the artifact is
        # compared only once those pins are current.
        run.actions.append(f"STALE {ARTIFACT} (not generated: earlier pins are stale)")
        return
    with tempfile.TemporaryDirectory(prefix="slp-refresh-pins-") as tmp:
        out = Path(tmp) / ARTIFACT
        cp = subprocess.run(PY + ["product/generate-product-check-v2.py", "--repo", ".", "--out", str(out)],
                            cwd=run.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if cp.returncode != 0 or "RESULT=PASS" not in cp.stdout.splitlines():
            raise RuntimeError("generator failed: " + (cp.stdout + cp.stderr).strip()[-2000:])
        run.put(ARTIFACT, out.read_bytes(), "generator")
        run.put(ARTIFACT + ".sha256", (out.parent / (ARTIFACT + ".sha256")).read_bytes(), "generator")
        if run.write:
            os.chmod(run.root / ARTIFACT, 0o755)


def nested_carriers(root: Path) -> list[str]:
    visible = git(root, "ls-files", "--cached", "--others", "--exclude-standard").splitlines()
    carriers = [
        rel for rel in visible
        if rel not in ROOT_MANIFESTS
        and (PurePosixPath(rel).name == "SHA256SUMS" or rel.endswith(".sha256") or is_control_manifest(rel))
    ]
    return sorted(carriers, key=lambda rel: (-rel.count("/"), rel))


def refresh_carrier(run: Run, rel: str, changed: set[str]) -> bool:
    base = PurePosixPath(rel).parent
    raw_text = (run.root / rel).read_text(encoding="utf-8")
    lines = raw_text.split("\n")
    out = []
    if is_control_manifest(rel):
        header = lines[0].split("\t")
        col_file, col_sha = header.index("file"), header.index("sha256")
        out.append(lines[0])
        rows = lines[1:]
    else:
        rows = lines
    targets = []
    for line in rows:
        if not line:
            continue
        if is_control_manifest(rel):
            targets.append((base / line.split("\t")[col_file]).as_posix())
        else:
            m = CHECKSUM_LINE.fullmatch(line)
            if m is None:
                raise RuntimeError(f"{rel}: unparsable line {line!r}")
            targets.append((base / m.group(2)).as_posix())
    if not changed & set(targets):
        return False
    for line in rows:
        if not line:
            out.append(line)
            continue
        if is_control_manifest(rel):
            f = line.split("\t")
            old, target = f[col_sha], f[col_file]
        else:
            m = CHECKSUM_LINE.fullmatch(line)
            if m is None:
                raise RuntimeError(f"{rel}: unparsable line {line!r}")
            old, target = m.group(1), m.group(2)
        target_rel = (base / target).as_posix()
        path = run.root / target_rel
        if not path.is_file():
            raise RuntimeError(f"{rel}: pinned file missing: {target_rel}")
        new = sha256_file(path)
        if new != old:
            if target_rel not in changed:
                raise RuntimeError(f"{rel}: stale pin for a path unchanged against HEAD: {target_rel}")
            if is_control_manifest(rel):
                f[col_sha] = new
                line = "\t".join(f)
            else:
                line = f"{new}  {target}"
        out.append(line)
    new_raw = "\n".join(out).encode("utf-8")
    if new_raw == raw_text.encode("utf-8"):
        return False
    run.put(rel, new_raw, "nested pins")
    return True


def listed_paths(root: Path, carriers: list[str]) -> set[str]:
    listed = set()
    for rel in carriers + list(ROOT_MANIFESTS):
        base = PurePosixPath(rel).parent
        text = (root / rel).read_text(encoding="utf-8")
        if is_control_manifest(rel):
            rows = list(csv.DictReader(io.StringIO(text), delimiter="\t"))
            listed |= {(base / r["file"]).as_posix() for r in rows}
        else:
            for line in text.splitlines():
                m = CHECKSUM_LINE.fullmatch(line)
                if m:
                    listed.add((base / m.group(2)).as_posix())
    return listed


def stage_nested(run: Run, changed: set[str]) -> None:
    carriers = nested_carriers(run.root)
    new_files = sorted(
        p for p in git(run.root, "ls-files", "--others", "--exclude-standard").splitlines()
        if p and p not in listed_paths(run.root, carriers)
    )
    if new_files:
        raise RuntimeError("new files are listed by no carrier (add them to the right manifest first): "
                           + ", ".join(new_files))
    if not run.write:
        for rel in carriers:
            refresh_carrier(run, rel, changed)
        return
    for _ in range(len(carriers) + 1):
        touched = False
        for rel in carriers:
            if refresh_carrier(run, rel, changed):
                changed.add(rel)
                touched = True
        if not touched:
            return
    raise RuntimeError("nested carriers did not converge")


def baseline_lists(root: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    src = (root / BASELINE_TEST).read_text(encoding="utf-8")
    ns: dict = {}
    for name in ("TRUTH_INPUTS", "STATE_DOCS"):
        start = src.index(name + " = (")
        exec(src[start:src.index("\n)\n", start) + 3], ns)
    return ns["TRUTH_INPUTS"], ns["STATE_DOCS"]


def truth_view(rel: str, raw: bytes) -> bytes:
    # Mirrors truth_view() of tests/documentation-v1/test_documentation_baseline.py:
    # columns sha256 and *_sha256 are byte pins, not composition, and are left out.
    lines = raw.decode("utf-8").split("\n")
    header = lines[0].split("\t")
    keep = [i for i, name in enumerate(header) if not (name == "sha256" or name.endswith("_sha256"))]
    out = []
    for line in lines:
        cells = line.split("\t") if line else []
        if cells and len(cells) != len(header):
            raise RuntimeError(f"{rel}: row width differs from header: {line[:80]}")
        out.append("\t".join(cells[i] for i in keep) if cells else "")
    return "\n".join(out).encode("utf-8")


def truth_sha256(root: Path, truth_inputs: tuple[str, ...]) -> str:
    # Mirrors current_truth_sha256() of tests/documentation-v1/test_documentation_baseline.py;
    # tests/project-integrity-v1/test_refresh_pins.py fails when the two disagree.
    joined = "".join(
        f"{rel}\t{sha256_bytes(truth_view(rel, (root / rel).read_bytes()))}\n" for rel in truth_inputs
    )
    return sha256_bytes(joined.encode("utf-8"))


def stage_baseline(run: Run, changed: set[str], reviewed: set[str], reviewed_truth: bool) -> None:
    truth_inputs, state_docs = baseline_lists(run.root)
    truth = truth_sha256(run.root, truth_inputs)
    lines = (run.root / REVIEW_BASELINE).read_text(encoding="utf-8").split("\n")
    if lines[0] != "path\tsha256\ttruth_sha256":
        raise RuntimeError(f"{REVIEW_BASELINE}: unexpected header")
    out = [lines[0]]
    problems = []
    seen = set()
    for line in lines[1:]:
        if not line:
            out.append(line)
            continue
        path, digest, tsha = line.split("\t")
        seen.add(path)
        new = sha256_file(run.root / path)
        if new != digest:
            if path in reviewed and path in changed:
                digest = new
            else:
                problems.append(f"{path}: document changed — review it and pass --reviewed {path}")
        if path in state_docs and tsha != truth:
            if reviewed_truth:
                tsha = truth
            else:
                problems.append(f"{path}: machine data changed — review state documents and pass --reviewed-truth")
        out.append(f"{path}\t{digest}\t{tsha}")
    unknown = reviewed - seen
    if unknown:
        raise RuntimeError("--reviewed names documents outside the review baseline: " + ", ".join(sorted(unknown)))
    if problems and run.write:
        raise RuntimeError("review baseline:\n  " + "\n  ".join(problems))
    run.actions.extend("STALE " + p for p in problems)
    run.put(REVIEW_BASELINE, "\n".join(out).encode("utf-8"), "review baseline")
    if run.write:
        changed.add(REVIEW_BASELINE)


def stage_root_and_render(run: Run) -> None:
    args = ["tools/rebuild-root-manifests.py", "--project-root", "."] + ([] if run.write else ["--check"])
    cp = subprocess.run(PY + args, cwd=run.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if cp.returncode != 0:
        if run.write:
            raise RuntimeError("root manifests: " + (cp.stdout + cp.stderr).strip())
        run.actions.append("STALE root manifests (tools/rebuild-root-manifests.py)")
    if not run.write and run.actions:
        # render-current-docs also refuses stale registry pins.
        return
    cp = subprocess.run(PY + ["tools/render-current-docs.py", "--project-root", ".", "--check"],
                        cwd=run.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if cp.returncode != 0:
        raise RuntimeError("render-current-docs --check: " + (cp.stdout + cp.stderr).strip())


def execute(root: Path, write: bool, reviewed: set[str], reviewed_truth: bool) -> list[str]:
    run = Run(root, write)
    changed = changed_paths(root)
    stage_adapter_pins(run)
    stage_apply_bindings(run)
    visible = git(root, "ls-files", "--cached", "--others", "--exclude-standard").splitlines()
    for manifest in sorted(rel for rel in visible if is_control_manifest(rel)):
        refresh_carrier(run, manifest, changed)
    stage_artifact(run)
    if write:
        changed = changed_paths(root)
    stage_nested(run, changed)
    stage_baseline(run, changed, reviewed, reviewed_truth)
    if write:
        stage_nested(run, changed)
    stage_root_and_render(run)
    return run.actions


def visible_files(root: Path) -> list[str]:
    listed = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0")
    return [rel for rel in listed if rel and (root / rel).is_file() and not (root / rel).is_symlink()]


def snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    return {rel: ((root / rel).read_bytes(), (root / rel).stat().st_mode & 0o7777) for rel in visible_files(root)}


def rollback(root: Path, before: dict[str, tuple[bytes, int]]) -> int:
    restored = 0
    for rel in visible_files(root):
        if rel not in before:
            (root / rel).unlink()
            restored += 1
    for rel, (raw, mode) in before.items():
        path = root / rel
        if not path.is_file() or path.read_bytes() != raw or path.stat().st_mode & 0o7777 != mode:
            write_bytes(path, raw)
            os.chmod(path, mode)
            restored += 1
    return restored


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Refresh or check byte pins.")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    ap.add_argument("--reviewed", nargs="+", default=[], metavar="DOC")
    ap.add_argument("--reviewed-truth", action="store_true")
    args = ap.parse_args(argv)
    root = Path.cwd()
    if not (root / ".git").exists() or not (root / ADAPTER_REGISTRY).is_file():
        print("REFRESH_PINS_RESULT=FAIL: run from the project root", file=sys.stderr)
        return 2
    if args.check and (args.reviewed or args.reviewed_truth):
        print("REFRESH_PINS_RESULT=FAIL: --reviewed/--reviewed-truth only with --write", file=sys.stderr)
        return 2
    before = snapshot(root) if args.write else None
    try:
        actions = execute(root, args.write, set(args.reviewed), args.reviewed_truth)
        for line in actions:
            print(line)
        if args.write:
            final = execute(root, False, set(), False)
            if final:
                for line in final:
                    print("AFTER_WRITE " + line)
                raise RuntimeError("pins still stale after --write")
            print("REFRESH_PINS_ACTION=WRITE")
        else:
            print("REFRESH_PINS_ACTION=CHECK")
            if actions:
                print("REFRESH_PINS_RESULT=STALE")
                return 1
    except BaseException as exc:
        if before is not None:
            print(f"REFRESH_PINS_ROLLBACK={rollback(root, before)}", file=sys.stderr)
        if not isinstance(exc, RuntimeError):
            raise
        print(f"REFRESH_PINS_RESULT=FAIL: {exc}", file=sys.stderr)
        return 2
    print("REFRESH_PINS_RESULT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
