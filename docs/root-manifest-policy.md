# Политика корневых manifest

Корневые `PROJECT-FILES.sha256` и `SHA256SUMS` должны воспроизводиться из чистой
рабочей копии Git.

Канонический builder:

```bash
python3 -B tools/rebuild-root-manifests.py --project-root .
```

Каноническая проверка:

```bash
python3 -B tools/rebuild-root-manifests.py --project-root . --check
sha256sum -c SHA256SUMS
```

## Состав population

Builder использует:

`git ls-files --cached --others --exclude-standard`

после чего детерминированно сортирует полученные пути.

Следовательно:

- tracked files включаются;
- новые non-ignored project files включаются ещё до commit;
- Git-ignored files исключаются;
- symlinks и special files дают fail-closed.

В чистом checkout это сходится к tracked project tree, кроме документированных
самоисключений manifest.

## Runtime state донора

`archive/engineering-donor-v16.2.11/snapshot/.gitignore` исключает
`.securelinux-ng-state/`.

Сохранённый donor ZIP может содержать этот runtime state, но такие файлы не
являются Git project source и не должны входить в активные корневые manifests.
Их исключение из active manifests не переписывает сохранённый donor evidence и
закрывает 0 нормативных source rows.
## Historical `.sha256` records B1.1b

Корневые manifests подтверждают bytes sidecar-файла, но сами по себе не
подтверждают воспроизводимость historical target claims внутри произвольного
`.sha256`. Восемь сохранённых B1.1b stage-sidecar имеют доказанные расхождения с
позднее эволюционировавшими target paths и поэтому явно классифицированы в
`archive/B1.1b/ARCHIVAL-SIDECAR-STATUS.tsv` как
`NON_REPRODUCIBLE_HISTORICAL_RECORD`.

`tests/project-integrity-v1/test_root_manifests.py` независимо пересчитывает их
entry/mismatch/missing counts и не допускает использовать эти sidecar как current
reproducibility proof. Historical sidecar bytes при этом не переписываются.
