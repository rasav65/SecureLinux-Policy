# Root manifest policy

Root `PROJECT-FILES.sha256` and `SHA256SUMS` must be reproducible from a clean
Git checkout.

Canonical builder:

```bash
python3 -B tools/rebuild-root-manifests.py --project-root .
```

Canonical verification:

```bash
python3 -B tools/rebuild-root-manifests.py --project-root . --check
sha256sum -c SHA256SUMS
```

## Population

The builder uses:

`git ls-files --cached --others --exclude-standard`

then sorts the resulting paths deterministically.

Therefore:

- tracked files are included;
- new non-ignored project files are included before commit;
- Git-ignored files are excluded;
- symlinks and special files fail closed.

In a clean checkout this converges to the tracked project tree, apart from the
documented manifest self-exclusions.

## Donor runtime state

`archive/engineering-donor-v16.2.11/snapshot/.gitignore` excludes
`.securelinux-ng-state/`.

The preserved donor ZIP may contain that runtime state, but those files are not
Git project source and must not be listed by active root manifests. Excluding
them from active manifests does not rewrite the preserved donor evidence and
closes zero normative source rows.
