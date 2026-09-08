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

## Закрытие состояния перед substantive commit

Каждый substantive commit обязан согласовывать не только изменённые bytes, но и
все current-state поверхности, которые описывают эти bytes. Обязательный порядок:

1. изменить machine truth;
2. выполнить `tools/render-current-docs.py --write` для renderer-owned blocks;
3. проверить и обновить все затронутые current Markdown/prose status surfaces;
4. обновить `CHANGELOG.md` как фактическую историю изменения;
5. явно пересмотреть `tests/documentation-v1/CURRENT-MARKDOWN-REVIEW-BASELINE.tsv`;
6. пересобрать применимые nested `SHA256SUMS`;
7. пересобрать корневые manifests;
8. выполнить targeted regressions, DEV и применимый RELEASE gate;
9. после всех renderer/manifest/test операций повторно проверить exact ожидаемый `git status --short` и `git diff --check`;
10. если substantive checkpoint изменился, обновить внешний current HANDOFF после подтверждённого PASS дерева и до передачи работы в новый чат/аудит.

Старое значение `NEXT`, прежняя текущая точка в PROJECT-MAP или противоречащий
новому machine truth README считается дефектом commit-кандидата. Обновление
manifest не является заменой semantic review документации.

## Worktree и package file modes

Git для обычных файлов различает прежде всего `100644` и `100755`; различия
worktree `0600` / `0644` / `0664` сами по себе не входят в Git blob identity.
Для закреплённых regular authority files в `sources/fstec/` рабочая копия
нормализуется к `0644`, чтобы чтение не зависело от случайного source/umask.
Исполняемые project files сохраняют Git executable semantics.

На этапе 16 права выдаваемых файлов задаются детерминированно: `0644` для
regular data/source files и `0755` только для реально executable files.
Этап 17 закрыт существующим generated `securelinux-policy.sh` без нового
архивного слоя; sidecar остаётся сопутствующим integrity metadata. Поэтому
archive modes не являются выполненным требованием текущей вертикали. Если
отдельным будущим решением будет введён архивный формат, его canonical modes
должны задаваться явно по тем же правилам, а не наследовать worktree modes.

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
