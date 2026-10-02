#!/usr/bin/env bash
# Исполнитель шага правки на рабочем ПК: проверки до правки, edit.py шага,
# render-current-docs, refresh-pins, сверка итоговых байтов, DEV и RELEASE.
# Коммит и push не выполняет.
#
# Использование: tools/run-edit-step.sh КАТАЛОГ_ШАГА
# Каталог шага:
#   step.env       EXPECT_HEAD=<полный SHA коммита>; необязательные REVIEWED="doc.md ...",
#                  REVIEWED_TRUTH=1, NEW_FILES="путь ..." (новые файлы для git add -N);
#   edit.py        правка по exact bytes; запуск: python3 edit.py <корень репозитория>,
#                  каждая успешная правка печатает строку с _OK;
#   expected.txt   вывод sha256sum по всем изменённым и новым файлам после шага;
#   commit-msg.txt сообщение коммита.
# При RESULT=PASS рабочий каталог удаляется; при отказе остаётся (WORKDIR_KEPT).
# SLP_REPO=<путь> — корень репозитория, если скрипт запущен не из tools/ этого репозитория.
set -uo pipefail

main() {
    [ $# -eq 1 ] || { echo "USAGE: tools/run-edit-step.sh STEP_DIR"; exit 2; }
    STEP=$(cd "$1" 2>/dev/null && pwd) || { echo "STEP_DIR_MISSING=$1"; exit 2; }
    for f in step.env edit.py expected.txt commit-msg.txt; do
        [ -f "$STEP/$f" ] || { echo "STEP_FILE_MISSING=$f"; exit 2; }
    done
    REPO=${SLP_REPO:-$(cd "$(dirname "$0")/.." && pwd)}
    cd "$REPO" || exit 2
    EXPECT_HEAD="" REVIEWED="" REVIEWED_TRUTH=0 NEW_FILES=""
    # shellcheck disable=SC1091
    . "$STEP/step.env"
    echo "STEP=$STEP"
    [ "$(git rev-parse HEAD)" = "$EXPECT_HEAD" ] || { echo "HEAD_MISMATCH $(git rev-parse HEAD)"; exit 1; }
    [ -z "$(git status --porcelain)" ] || { echo "WORKTREE_NOT_CLEAN"; git status --short; exit 1; }
    # git reset/checkout при umask 0002 создают файлы 0664; тесты требуют 0644/0755.
    GW=$(git ls-files -z | xargs -0 stat -c '%a %n' | awk '$1 !~ /^[0-7]?[0-7][0145][0145]$/' | wc -l)
    [ "$GW" = 0 ] || { echo "MODE_PRECHECK=FAIL files_with_group_or_other_write=$GW"; exit 1; }
    echo "MODE_PRECHECK=PASS"
    W=$(mktemp -d "$(dirname "$STEP")/slp-step-XXXXXX") || exit 2
    echo "WORKDIR=$W"
    export PYTHONDONTWRITEBYTECODE=1
    if ! /usr/bin/python3 -I -B "$STEP/edit.py" . >"$W/edit.txt" 2>&1; then
        tail -3 "$W/edit.txt"
        echo "EDIT_RESULT=FAIL"
        echo "WORKDIR_KEPT=$W"
        echo "RESULT=FAIL"
        exit 1
    fi
    echo "EDITS_APPLIED=$(grep -c '_OK' "$W/edit.txt")"
    if [ -n "$NEW_FILES" ]; then
        # shellcheck disable=SC2086
        git add -N -- $NEW_FILES || { echo "ADD_N_FAIL"; echo "WORKDIR_KEPT=$W"; echo "RESULT=FAIL"; exit 1; }
    fi
    OK=1
    /usr/bin/python3 -I -B tools/render-current-docs.py --project-root . --write >"$W/render.txt" 2>&1 || OK=0
    tail -1 "$W/render.txt"
    set --
    [ -n "$REVIEWED" ] && { set -- --reviewed; for d in $REVIEWED; do set -- "$@" "$d"; done; }
    [ "$REVIEWED_TRUTH" = 1 ] && set -- "$@" --reviewed-truth
    /usr/bin/python3 -I -B tools/refresh-pins.py --write "$@" >"$W/pins.txt" 2>&1 || OK=0
    tail -1 "$W/pins.txt"
    /usr/bin/python3 -I -B tools/refresh-pins.py --check >"$W/pins-check.txt" 2>&1 || OK=0
    tail -1 "$W/pins-check.txt"
    { git diff --name-only; git ls-files --others --exclude-standard; } | sort -u >"$W/changed.txt"
    awk '{print $2}' "$STEP/expected.txt" | sort | diff - "$W/changed.txt" >"$W/changed-diff.txt" && echo "CHANGED_SET=MATCH" || { echo "CHANGED_SET=MISMATCH"; OK=0; }
    sha256sum -c --quiet "$STEP/expected.txt" >"$W/sha.txt" 2>&1 && echo "EXPECTED_SHA256=MATCH $(wc -l <"$STEP/expected.txt")" || { echo "EXPECTED_SHA256=MISMATCH"; OK=0; }
    git diff --check >"$W/diff-check.txt" 2>&1 && echo "DIFF_CHECK=PASS" || { echo "DIFF_CHECK=FAIL"; OK=0; }
    /usr/bin/python3 -I -S -B tests/run-all.py --dev >"$W/dev.txt" 2>&1
    grep -E '^(DEV FAIL|DEV_FILES_TOTAL|DEV_FILES_PASS|DEV_RESULT)' "$W/dev.txt"
    grep -qx 'DEV_RESULT=PASS' "$W/dev.txt" || OK=0
    /usr/bin/python3 -I -B tests/run-all.py --release >"$W/release.txt" 2>&1
    grep -E '^(RELEASE FAIL|RELEASE_RESULT)' "$W/release.txt"
    grep -qx 'RELEASE_RESULT=PASS' "$W/release.txt" || OK=0
    echo "CHANGED_FILES=$(git status --short | wc -l)"
    if [ "$OK" = 1 ]; then
        rm -rf -- "$W"
        echo "WORKDIR_REMOVED=YES"
        echo "COMMIT_MSG=$STEP/commit-msg.txt"
        echo "RESULT=PASS"
    else
        echo "WORKDIR_KEPT=$W"
        echo "RESULT=FAIL"
        exit 1
    fi
}

# main целиком разбирается до запуска: правка шага может менять этот файл.
main "$@"
exit $?
