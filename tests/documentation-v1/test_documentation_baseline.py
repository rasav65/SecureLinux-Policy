#!/usr/bin/env python3
from pathlib import Path
import ast
import csv
import hashlib
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]

cp = subprocess.run(
    [
        "/usr/bin/python3", "-I", "-S", "-B",
        str(ROOT / "tools/render-current-docs.py"),
        "--project-root", str(ROOT), "--check",
    ],
    cwd=ROOT,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
assert cp.returncode == 0, cp.stdout + cp.stderr
assert "DOC_RENDER_RESULT=PASS" in cp.stdout
assert "DOC_RENDER_FILES=3" in cp.stdout

readme = (ROOT / "README.md").read_text(encoding="utf-8")
docs_index = (ROOT / "docs/README.md").read_text(encoding="utf-8")
policy = (ROOT / "docs/policy-layers.md").read_text(encoding="utf-8")
compat = (ROOT / "docs/compatibility.md").read_text(encoding="utf-8")
coverage = (ROOT / "docs/fstec-coverage.md").read_text(encoding="utf-8")
pmap = (ROOT / "docs/PROJECT-MAP-v3.md").read_text(encoding="utf-8")
product_readme = (ROOT / "product/README.md").read_text(encoding="utf-8")
controls_readme = (
    ROOT / "controls/fstec-core/linux-2022/README.md"
).read_text(encoding="utf-8")
disposition_test_readme = (ROOT / "tests/disposition-v1/README.md").read_text(encoding="utf-8")
index_scope = (ROOT / "index/source-v4/INDEX-SCOPE.md").read_text(encoding="utf-8")
step7b0_status = (ROOT / "step7b0/ARTIFACT-STATUS-RU.md").read_text(encoding="utf-8")
changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
tests_readme = (ROOT / "tests/README.md").read_text(encoding="utf-8")


def validate_step7b0_historical_boundary(text: str) -> None:
    preamble = text.split("## HISTORICAL SNAPSHOT", 1)[0]
    assert "HISTORICAL REFERENCE ONLY — НЕ CURRENT STATUS" in preamble
    assert "STATUS=HISTORICAL_REFERENCE_ONLY" in preamble
    assert "CURRENT_PROJECT_AUTHORITY=false" in preamble
    assert "не должен использоваться для\n> выбора следующего шага" in preamble
    assert "docs/ROADMAP-v3.tsv" in preamble
    assert "CURRENT_PROJECT_AUTHORITY=true" not in text
    assert not re.search(
        r"(?is)(?:этот\s+файл|ARTIFACT-STATUS-RU\.md).{0,100}(?:является|служит|считается).{0,80}(?:current|текущ\w*).{0,40}(?:status|authority|источник)",
        text,
    )


def expect_step7_rejected(text: str, label: str) -> None:
    try:
        validate_step7b0_historical_boundary(text)
    except AssertionError:
        return
    raise AssertionError(f"step7b0 negative fixture unexpectedly accepted: {label}")


validate_step7b0_historical_boundary(step7b0_status)
expect_step7_rejected(
    step7b0_status.replace("CURRENT_PROJECT_AUTHORITY=false", "CURRENT_PROJECT_AUTHORITY=true", 1),
    "current_authority_true",
)
expect_step7_rejected(
    step7b0_status.replace("HISTORICAL REFERENCE ONLY — НЕ CURRENT STATUS", "АКТУАЛЬНЫЙ CURRENT STATUS", 1),
    "historical_marker_removed",
)
expect_step7_rejected(
    step7b0_status + "\nЭтот файл является текущим status и источником project authority.\n",
    "opposite_current_status_claim",
)


def validate_b01_changelog(text: str) -> None:
    stale_claim = (
        "fixtures FIFO snapshot-drift для SRC-0006 используют 20-секундный timeout "
        "синхронизации вместо 5 секунд; это устраняет false negatives при нагрузке scheduler"
    )
    assert stale_claim not in text
    for marker in (
        "две отдельные `FIFO-generation`",
        "явным `threading.Event` handshake",
        "mutation выполняется только после подтверждения первого snapshot",
        "`path:recheck-snapshot-changed`",
        "`parent:recheck-snapshot-changed`",
        "Production bytes и compliance semantics не изменены",
    ):
        assert marker in text, marker


def expect_b01_changelog_rejected(text: str) -> None:
    try:
        validate_b01_changelog(text)
    except AssertionError:
        return
    raise AssertionError("stale B-01 timeout-only changelog fixture unexpectedly accepted")


validate_b01_changelog(changelog)
expect_b01_changelog_rejected(
    changelog.replace(
        "- Надёжность tests SRC-0006: прежнее увеличение timeout FIFO snapshot-drift с 5 до 20 секунд не устраняло scheduler race. Regression переработан без production hooks: первый snapshot и recheck используют две отдельные `FIFO-generation` с явным `threading.Event` handshake; mutation выполняется только после подтверждения первого snapshot, а `path:recheck-snapshot-changed` и `parent:recheck-snapshot-changed` дополнительно проверяются отдельными детерминированными reason-code tests. Production bytes и compliance semantics не изменены.",
        "- Надёжность tests: fixtures FIFO snapshot-drift для SRC-0006 используют 20-секундный timeout синхронизации вместо 5 секунд; это устраняет false negatives при нагрузке scheduler без изменения семантики adapter или compliance.",
        1,
    )
)


def runner_expected_internal_skips() -> dict[str, int]:
    tree = ast.parse((ROOT / "tests/run-all.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == "DEV_EXPECTED_INTERNAL_SKIPS" for target in node.targets):
            value = ast.literal_eval(node.value)
            assert isinstance(value, dict)
            assert all(isinstance(path, str) and isinstance(count, int) for path, count in value.items())
            return value
    raise AssertionError("DEV_EXPECTED_INTERNAL_SKIPS not found in tests/run-all.py")


def validate_tests_readme_skip_policy(text: str) -> None:
    marker = "Разрешённые внутренние skip:"
    assert text.count(marker) == 1
    lines = text.splitlines()
    marker_index = lines.index(marker)
    section_lines = []
    started = False
    for line in lines[marker_index + 1:]:
        if not line.strip():
            if started:
                break
            continue
        started = True
        section_lines.append(line)
    section = "\n".join(section_lines)
    pairs = re.findall(r"- `([^`]+)`: ровно (\d+)\b", section)
    documented = {}
    for path, count_text in pairs:
        assert path not in documented, f"duplicate documented skip policy: {path}"
        documented[path] = int(count_text)
    assert documented == runner_expected_internal_skips(), (documented, runner_expected_internal_skips())


def expect_tests_readme_skip_policy_rejected(text: str) -> None:
    try:
        validate_tests_readme_skip_policy(text)
    except AssertionError:
        return
    raise AssertionError("stale tests/README skip-policy fixture unexpectedly accepted")


validate_tests_readme_skip_policy(tests_readme)
expect_tests_readme_skip_policy_rejected(
    tests_readme.replace(
        "\n\nЛюбой другой или дополнительный skip",
        "\n- `tests/product-v1/test_file_mode_owner_adapter.py`: ровно 2 permission-сценария только при запуске DEV от root."
        "\n\nЛюбой другой или дополнительный skip",
        1,
    )
)


# Relative Markdown links in the two entry points must resolve.
for source_path, text in ((ROOT / "README.md", readme), (ROOT / "docs/README.md", docs_index), (ROOT / "product/README.md", product_readme)):
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
        if "://" in target or target.startswith("#"):
            continue
        target_path = target.split("#", 1)[0]
        if not target_path:
            continue
        resolved = (source_path.parent / target_path).resolve()
        assert resolved.exists(), f"broken link {source_path.relative_to(ROOT)} -> {target}"


# Пользовательский маршрут и закреплённая загрузка: без выполнения скачанного кода.
def validate_readme_entrypoint(text: str) -> None:
    for heading in ("## Скачать", "## Быстрый старт", "## Требования", "## Поддерживаемые системы", "## Применение изменений", "## Как читать результат", "## Документация"):
        assert text.count(heading) == 1, heading
    assert "git clone --filter=blob:none --no-checkout https://github.com/rasav65/SecureLinux-Policy.git securelinux-policy-download" in text
    pins = re.findall(r"git checkout ([0-9a-f]{40}) -- securelinux-policy\.sh securelinux-policy\.sh\.sha256", text)
    assert len(pins) == 1
    assert "raw.githubusercontent.com" not in text
    assert "sha256sum -c securelinux-policy.sh.sha256" in text
    assert "sudo /bin/bash -p ./securelinux-policy.sh --check" in text
    assert "sudo /bin/bash -p ./securelinux-policy.sh --apply --dry-run" in text
    assert "--snapshot-attestation /path/to/attestation.json" in text
    assert "snapshot-precondition-v1.json" in text
    assert "product/README.md#readme-engineering-reference" in text
    assert "DRAFT_UNVERIFIED" not in text and "Исходный README — сохранён полностью" not in text

validate_readme_entrypoint(readme)
for bad in (
    readme.replace("sha256sum -c securelinux-policy.sh.sha256", "true"),
    readme.replace("/bin/bash -p", "/bin/bash"),
    re.sub(r"git checkout [0-9a-f]{40} --", "git checkout main --", readme),
):
    try:
        validate_readme_entrypoint(bad)
    except AssertionError:
        pass
    else:
        raise AssertionError("README entrypoint negative fixture accepted")

# Every docs/*.md except the index itself must appear exactly once in docs/README.
doc_names = sorted(
    p.name for p in (ROOT / "docs").glob("*.md") if p.name != "README.md"
)
for name in doc_names:
    assert docs_index.count(f"]({name})") == 1, name

# One primary map; architecture diagrams are historical donor reference, not target/current authority.
assert docs_index.count("**PRIMARY**") == 1
assert "PROJECT-MAP-v3.md" in readme
assert "ARCHITECTURE-DIAGRAMS.md" in readme
assert "historical donor runtime reference" in product_readme
assert "не future target" in product_readme
assert "ARCHITECTURE-DIAGRAMS.md" in docs_index
assert "historical donor runtime reference" in docs_index
assert "не future target model" in docs_index
assert "целевая APPLY-only runtime-модель" not in readme

assert "FSTEC core ≠ recommended ≠ corporate standard ≠ firewall" in policy
for marker in ("SUPPORTED", "TESTED", "UNSUPPORTED", "linux-x86_64-supported-v1", "MINIMIZED", "Debian 13"):

    assert marker in compat, marker

assert "**СГЕНЕРИРОВАННЫЙ ФАЙЛ.**" in coverage
assert "CONTROLLED_CLOSED_WITH_CONTRACT=" in coverage
assert "Готовность адаптеров CHECK" in coverage
assert "Canonical controls, которые ещё не закрывают строку source" in coverage
assert "## Покрытие по исходным документам" in coverage

import csv
with (ROOT / "index/source-v4/SOURCE-INDEX.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    source_rows = list(csv.DictReader(stream, delimiter="\t"))
with (ROOT / "controls/fstec-core/linux-2022/CONTROL-MANIFEST.tsv").open(
    encoding="utf-8", newline=""
) as stream:
    manifest_rows = list(csv.DictReader(stream, delimiter="\t"))

by_source = {}
source_by_id = {row["index_id"]: row for row in source_rows}
for row in source_rows:
    bucket = by_source.setdefault(
        row["source_id"],
        {"total": 0, "controlled": 0, "disposed": 0, "open": 0, "controls": 0},
    )
    bucket["total"] += 1
    if row["status"] == "OPEN":
        bucket["open"] += 1
    elif row["disposition"].strip():
        bucket["disposed"] += 1
    else:
        bucket["controlled"] += 1
for control in manifest_rows:
    by_source[source_by_id[control["index_id"]]["source_id"]]["controls"] += 1
for source_id, bucket in by_source.items():
    expected = (
        f"| {source_id} | {bucket['total']} | {bucket['controlled']} | "
        f"{bucket['disposed']} | {bucket['open']} | {bucket['controls']} |"
    )
    assert expected in coverage, expected

# Product-facing docs must not retain the stale pilot presentation.
product_docs = "\n".join(
    [readme, pmap, product_readme, controls_readme, docs_index, coverage, compat, policy]
)
for stale in (
    "344 OPEN",
    "5 current controls",
    "ровно пять явно заданных sysctl-параметров",
    "Следующий отдельный gate после установки generator: CHECK-8",
):
    assert stale not in product_docs, stale

all_docs = "\n".join(
    q.read_text(encoding="utf-8") for q in sorted((ROOT / "docs").glob("*.md"))
)
for stale_current_claim in (
    "Current FSTEC pilot remains 349 total / 5 CLOSED / 344 OPEN.",
    "`349 total / 5 controlled CLOSED / 0 disposed CLOSED / 344 OPEN`.",
):
    assert stale_current_claim not in all_docs, stale_current_claim

assert "SRC-0005 / 2.3.1" in product_readme
assert "mode bits-clear 0077" in product_readme


RUS_COUNT_WORDS = {
    "ноль", "один", "одна", "одно", "два", "две", "три", "четыре", "пять",
    "шесть", "семь", "восемь", "девять", "десять", "одиннадцать", "двенадцать",
    "тринадцать", "четырнадцать", "пятнадцать", "шестнадцать", "семнадцать",
    "восемнадцать", "девятнадцать", "двадцать", "тридцать", "сорок", "сорока",
    "пятьдесят", "пятидесяти", "шестьдесят", "семьдесят", "восемьдесят",
    "девяносто", "сто", "двести", "триста", "четыреста", "пятьсот", "шестьсот",
    "семьсот", "восемьсот", "девятьсот", "двухсот", "трёхсот", "трехсот",
    "четырёхсот", "четырехсот", "пятисот", "шестисот", "семисот", "восьмисот",
    "девятисот",
}
ENG_COUNT_WORDS = {
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
    "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen",
    "seventeen", "eighteen", "nineteen", "twenty", "thirty", "forty", "fifty",
    "sixty", "seventy", "eighty", "ninety", "hundred",
}


def has_cardinal_word(text: str) -> bool:
    tokens = {token.lower() for token in re.findall(r"[A-Za-zА-Яа-яЁё]+", text)}
    return bool(tokens & (RUS_COUNT_WORDS | ENG_COUNT_WORDS))


def semantic_visible_text(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        inner = match.group(1)
        stripped = inner.strip()
        if re.fullmatch(r"\d+(?:\s*/\s*\d+)?", stripped):
            return inner
        if re.search(r"(?i)\b(?:CLOSED|OPEN|controls?)\b", inner) and re.search(r"\d", inner):
            return inner
        return ""
    return re.sub(r"`([^`]*)`", repl, text)


def validate_controls_readme_contract(text: str) -> None:
    assert "CONTROL-MANIFEST.tsv" in text
    assert "README не закрепляет\nвручную число controls" in text
    # README может объяснять принцип, но не должен содержать ручную live-count копию
    # ни цифрами, ни словами. Заголовок исключаем: год 2022 не является count.
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    visible = semantic_visible_text(body)
    count_term = r"(?:controls?|контрол(?:ь|я|ей|и|ям|ями|ях|ов|а|ы)?|контрол\w*)"
    assert not re.search(rf"(?i)\b\d+\b[^\n]{{0,48}}\b{count_term}\b", visible)
    assert not re.search(rf"(?i)\b{count_term}\b[^\n]{{0,48}}\b\d+\b", visible)
    for line in visible.splitlines():
        if re.search(rf"(?i)\b{count_term}\b", line):
            assert not has_cardinal_word(line), line


def strip_generated_status(text: str) -> str:
    return re.sub(
        r"<!-- BEGIN GENERATED CURRENT STATUS -->.*?<!-- END GENERATED CURRENT STATUS -->",
        "", text, flags=re.S,
    )


def validate_root_readme_no_manual_live_counts(text: str) -> None:
    visible = semantic_visible_text(strip_generated_status(text))
    live_term = re.compile(
        r"(?i)(?:canonical\s+controls?|adapter\s+kinds?|source\s+rows?|"
        r"контрол\w*|адаптер\w*|закрыт\w*|открыт\w*|\bCLOSED\b|\bOPEN\b)"
    )
    for line in visible.splitlines():
        if not live_term.search(line):
            continue
        assert not re.search(r"\b\d+\s*/\s*\d+\b|\b\d+\b", line), line
        if has_cardinal_word(line):
            assert not re.search(r"(?i)(?:\bcurrent\b|machine\s+truth|сейчас|текущ\w*|в\s+продукте)", line), line


def validate_disposition_readme_live_counts(text: str) -> None:
    for marker in ("SOURCE-INDEX.tsv", "CLOSURE-CONTRACT.tsv", "control manifest", "docs/fstec-coverage.md"):
        assert marker in text, marker
    # Этот README описывает тестовый контракт и не является копией live coverage.
    assert not re.search(r"\b\d+\s*/\s*\d+\s+CLOSED\b", text)
    assert not re.search(r"\b\d+\s+OPEN\b", text)
    assert not re.search(r"\bdisposed rows\s*[—:=]\s*`?\d+", text)
    visible = semantic_visible_text(text)
    assert not re.search(r"(?i)\b\d+\b[^\n]{0,32}\b(?:CLOSED|OPEN)\b", visible)
    for line in visible.splitlines():
        if re.search(r"(?i)(?:CLOSED|OPEN|закрыт\w*|открыт\w*|coverage|покрыт\w*)", line):
            assert not has_cardinal_word(line), line


def expect_rejected(check, mutated: str, label: str) -> None:
    try:
        check(mutated)
    except AssertionError:
        return
    raise AssertionError(f"negative fixture unexpectedly accepted: {label}")


validate_controls_readme_contract(controls_readme)
validate_root_readme_no_manual_live_counts(readme)
validate_disposition_readme_live_counts(disposition_test_readme)
expect_rejected(
    validate_controls_readme_contract,
    controls_readme + "\nТекущее README вручную закрепляет 51 controls.\n",
    "manual_controls_count",
)
expect_rejected(
    validate_controls_readme_contract,
    controls_readme + "\nЧисло канонических контролей в этом каталоге — 51.\n",
    "manual_controls_count_russian_rephrase",
)
expect_rejected(
    validate_controls_readme_contract,
    controls_readme + "\nВ этом каталоге сейчас пятьдесят один канонический контроль.\n",
    "manual_controls_count_russian_words",
)
expect_rejected(
    validate_disposition_readme_live_counts,
    disposition_test_readme + "\nТекущее покрытие: 40/349 CLOSED, 309 OPEN.\n",
    "manual_disposition_live_counts",
)
expect_rejected(
    validate_disposition_readme_live_counts,
    disposition_test_readme + "\nСейчас закрыто сорок из трёхсот сорока девяти строк, открыто триста девять.\n",
    "manual_disposition_live_counts_russian_words",
)
expect_rejected(
    validate_root_readme_no_manual_live_counts,
    readme + "\nMachine truth сейчас содержит 51 canonical controls и 18 adapter kinds.\n",
    "root_readme_manual_live_counts",
)
expect_rejected(
    validate_root_readme_no_manual_live_counts,
    readme + "\nСейчас в продукте пятьдесят один контроль и восемнадцать адаптеров.\n",
    "root_readme_manual_live_counts_words",
)
expect_rejected(
    validate_controls_readme_contract,
    controls_readme + "\nТекущее README вручную закрепляет `51` controls.\n",
    "manual_controls_count_inline_code",
)
expect_rejected(
    validate_disposition_readme_live_counts,
    disposition_test_readme + "\nТекущее покрытие: `40` CLOSED / `309` OPEN.\n",
    "manual_disposition_live_counts_inline_code",
)


def checker_disposition_enum() -> set[str]:
    tree = ast.parse((ROOT / "checker/gates-v1/checker.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "DISPOSITIONS" for t in node.targets):
            value = ast.literal_eval(node.value)
            assert isinstance(value, set) and all(isinstance(x, str) for x in value)
            return value
    raise AssertionError("DISPOSITIONS not found in checker/gates-v1/checker.py")


def validate_index_scope_disposition_enum(text: str) -> None:
    expected = checker_disposition_enum()
    assert expected == {"not-technical", "organizational", "external", "out-of-scope", "informational"}
    for token in sorted(expected):
        assert f"`{token}`" in text, token
    assert "non-technical" not in text
    for translated in ("внешние /", "вне scope", "информационные"):
        assert translated not in text, translated


validate_index_scope_disposition_enum(index_scope)
expect_rejected(
    validate_index_scope_disposition_enum,
    index_scope.replace("`external`", "внешние", 1),
    "translated_exact_disposition_enum",
)


# Актуальный v3-документационный контур ведётся по-русски. Технические
# идентификаторы и protocol/wire terms могут оставаться английскими.
ru_current_docs = {
    "checker/gates-v3/README.md": (
        "Сохранены исправления независимого аудита",
        "Gate 5 в текущем состоянии исполняется только для sysctl-пилота",
    ),
    "checker/gates-v3/GATE-SPEC.md": (
        "Gate 2 — обратное покрытие источника + контракт полноты",
        "Строка, закрытая через disposition",
    ),
    "docs/observation-value-contract.md": (
        "# Контракт значения и типа наблюдения",
        "Checker не должен угадывать",
    ),
    "tests/gates-v3/README.md": (
        "# Тесты gates-v3",
        "Тесты контракта значений наблюдений",
    ),
}
for rel, markers in ru_current_docs.items():
    text = (ROOT / rel).read_text(encoding="utf-8")
    for marker in markers:
        assert marker in text, (rel, marker)

for rel, obsolete_english in (
    ("checker/gates-v3/README.md", "Independent-audit repairs"),
    ("checker/gates-v3/GATE-SPEC.md", "A controlled CLOSED source row is valid only when"),
    ("docs/observation-value-contract.md", "The checker must not guess"),
    ("tests/gates-v3/README.md", "focused tests for completeness-contract"),
):
    assert obsolete_english not in (ROOT / rel).read_text(encoding="utf-8"), rel

# Language policy: every editable current Markdown document must contain Russian
# human-readable prose. Exact technical identifiers/tokens may remain English.
# Frozen/historical SHA-bound material is excluded from in-place translation.
def git_visible_markdown(root: Path) -> list[str]:
    cp = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "--", "*.md"],
        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert cp.returncode == 0, cp.stderr
    return [line for line in cp.stdout.splitlines() if line]


# Candidate authority is the whole Git-visible worktree, not only paths already
# present in HEAD. A newly added non-ignored Markdown document must enter the
# same language/semantic/review-bound population before commit.
with tempfile.TemporaryDirectory(prefix="slp-doc-visible-") as td:
    probe = Path(td)
    subprocess.run(["git", "init", "-q"], cwd=probe, check=True)
    (probe / "tracked.md").write_text("# Отслеживаемый\n", encoding="utf-8")
    (probe / "untracked.md").write_text("# Новый\n", encoding="utf-8")
    (probe / "ignored.md").write_text("# Игнорируемый\n", encoding="utf-8")
    (probe / ".gitignore").write_text("ignored.md\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.md", ".gitignore"], cwd=probe, check=True)
    probe_visible = set(git_visible_markdown(probe))
    assert "tracked.md" in probe_visible
    assert "untracked.md" in probe_visible
    assert "ignored.md" not in probe_visible

cp_lines = git_visible_markdown(ROOT)
historical_prefixes = (
    "archive/",
    "audit/",
    "index/source-v1/",
    "index/source-v2/",
    "index/source-v3/",
    "probes/sysctl-v1/evidence/",
)
historical_exact_prefixes = (
    "step7b0/BUILD-CONTRACT-",
)
current_markdown = []
for rel in cp_lines:
    if rel.startswith(historical_prefixes) or rel.startswith(historical_exact_prefixes):
        continue
    current_markdown.append(rel)
    body = (ROOT / rel).read_text(encoding="utf-8")
    assert re.search(r"[А-Яа-яЁё]", body), f"current Markdown has no Russian prose: {rel}"


def semantic_guard_visible(text: str) -> str:
    # Machine-rendered status blocks are allowed to contain live counts because they
    # are regenerated from authorities. Ordinary prose is checked independently.
    text = re.sub(
        r"<!-- BEGIN GENERATED CURRENT STATUS -->.*?<!-- END GENERATED CURRENT STATUS -->",
        "", text, flags=re.S,
    )
    text = re.sub(
        r"<!-- BEGIN GENERATED MAP STATUS -->.*?<!-- END GENERATED MAP STATUS -->",
        "", text, flags=re.S,
    )

    # Mermaid is semantic documentation, so keep its labels. Other fenced code is
    # implementation/example material and is not interpreted as a prose claim here.
    def fence_repl(match: re.Match[str]) -> str:
        return match.group(2) if match.group(1).strip().lower() == "mermaid" else ""

    text = re.sub(r"```([^\n]*)\n(.*?)```", fence_repl, text, flags=re.S)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    # Inline code remains visible to semantic guards; backticks are presentation only.
    return text.replace("`", "")


def validate_global_current_semantics(rel: str, body: str) -> None:
    # CHANGELOG is chronological evidence, not a current-state authority. step7b0
    # historical status explicitly declares the same boundary inside its own bytes.
    if rel == "CHANGELOG.md" or rel == "step7b0/ARTIFACT-STATUS-RU.md":
        return
    assert "CURRENT_PROJECT_AUTHORITY=false" not in body, (
        f"historical-authority escape marker outside step7b0 status: {rel}"
    )

    visible = semantic_guard_visible(body)

    # Generated coverage is the sanctioned machine-rendered live-count surface.
    if rel != "docs/fstec-coverage.md":
        current_marker = re.compile(
            r"(?i)(?:\bcurrent\b|текущ\w*|актуальн\w*|нынешн\w*|"
            r"действующ\w*|сейчас|machine\s+truth|на\s+данн\w*\s+момент|"
            r"в\s+продукте|в\s+этой\s+версии|в\s+данной\s+версии)"
        )
        live_patterns = tuple(re.compile(pattern) for pattern in (
            r"(?i)(?:canonical\s+controls?|каноническ\w*\s+контрол\w*)[^\n]{0,24}\b\d+\b",
            r"(?i)\b\d+\b[^\n]{0,24}(?:canonical\s+controls?|каноническ\w*\s+контрол\w*)",
            r"(?i)(?:числ\w*|количеств\w*)[^\n]{0,20}(?:контрол\w*|adapter\s+kinds?|адаптер\w*)[^\n]{0,20}\b\d+\b",
            r"(?i)(?:source\s+index|индекс\w*\s+источник\w*)[^\n]{0,30}(?:содерж\w*|имеет|насчитыва\w*)[^\n]{0,12}\b\d+\b",
            r"(?i)(?:machine\s+truth|покрыт\w*|coverage|source\s+(?:index|rows?))[^\n]{0,30}\b\d+\b(?:\s*/\s*\d+)?\s+(?:controlled\s+)?CLOSED\b",
            r"(?i)(?:machine\s+truth|покрыт\w*|coverage|source\s+(?:index|rows?))[^\n]{0,50}\b\d+\b\s+OPEN\b",
        ))
        for line in visible.splitlines():
            if current_marker.search(line) and any(pattern.search(line) for pattern in live_patterns):
                raise AssertionError(f"manual current machine-truth count: {rel}: {line}")
            # Unqualified global live-count pins are current claims by default in
            # current documentation. Per-source control-set counts remain allowed
            # when an explicit SRC identity is present.
            if not re.search(r"SRC-\d{4}", line, flags=re.I):
                if re.search(
                    r"(?i)(?:canonical\s+controls?|каноническ\w*\s+контрол\w*|"
                    r"adapter\s+kinds?|вид\w*\s+адаптер\w*)[^\n]{0,32}\b\d+\b|"
                    r"\b\d+\b[^\n]{0,32}(?:canonical\s+controls?|каноническ\w*\s+контрол\w*|"
                    r"adapter\s+kinds?|вид\w*\s+адаптер\w*)",
                    line,
                ):
                    raise AssertionError(f"unqualified global live-count pin: {rel}: {line}")

    for paragraph in re.split(r"\n\s*\n", visible):
        lower = paragraph.lower()
        if not lower.strip():
            continue

        # Identity этапа адаптеров APPLY сохраняется после CLOSED; отмена или
        # удаление из roadmap по-прежнему запрещены.
        # Evaluate sentence/line scope so an unrelated RESTORE "не планируется" in a
        # table cannot contaminate a separate Adapter row.
        for segment in re.split(r"(?<=[.!?])\s+|\n", paragraph):
            segment_lower = segment.lower()
            if not re.search(r"(?:apply.{0,50}(?:адаптер|adapter)|(?:адаптер|adapter).{0,50}apply)", segment_lower):
                continue
            cancellation = re.search(
                r"отмен\w*|упраздн\w*|не\s+предусмотр\w*|"
                r"отсутств\w*\s+в\s+(?:план\w*|roadmap)|"
                r"нет\s+в\s+(?:план\w*|roadmap)|"
                r"не\s+входит\w*\s+в\s+(?:план\w*|roadmap)|"
                r"не\s+заложен\w*|исключен\w*\s+из\s+(?:план\w*|roadmap)|"
                r"снят\w*\s+с\s+(?:план\w*|roadmap)|вычеркнут\w*|"
                r"больше\s+не\s+содерж\w*|удален\w*\s+из|удалён\w*\s+из|"
                r"не\s+запланирован\w*|не\s+планируется|"
                r"не\s+будет\s+(?:реализован\w*|делаться)",
                segment_lower,
            )
            assert not cancellation, f"APPLY adapter future stage cancelled: {rel}: {segment}"

        # Formal PAUSED text cannot coexist with an opposite natural-language claim
        # that Step 7B is actually the main/active flow.
        if "step 7b" in lower:
            active = (
                re.search(r"возобнов\w*|активирован\w*|вновь\s+(?:ведутся|идут)|снова\s+(?:ведутся|идут)", lower)
                or re.search(
                    r"работ\w*[^\n]{0,36}(?:ведутся|идут|продолжаются)[^\n]{0,70}"
                    r"(?:ключев\w*|главн\w*|основн\w*|ведущ\w*|приоритет\w*)",
                    lower,
                )
                or re.search(
                    r"(?:ключев\w*|главн\w*|основн\w*|ведущ\w*|приоритет\w*)\s+"
                    r"(?:трек\w*|поток\w*|направлен\w*|этап\w*)",
                    lower,
                )
            )
            assert not active, f"Step 7B reactivated in current prose: {rel}: {paragraph}"

        # Historical donor RESTORE maturity is checked sentence-by-sentence so an
        # explicit phrase such as "not a stub" is not mistaken for a downgrade.
        for sentence in re.split(r"(?<=[.!?])\s+|\n", paragraph):
            sentence_lower = sentence.lower()
            if not (
                re.search(r"донор|donor|securelinux-ng", sentence_lower)
                and re.search(r"restore|восстанов", sentence_lower)
            ):
                continue
            normalized = re.sub(
                r"(?:а\s+)?не\s+(?:stub\w*|прототип\w*|экспериментальн\w*|"
                r"демонстрационн\w*|заготовк\w*|чернов\w*|макет\w*)",
                "", sentence_lower,
            )
            downgrade = re.search(
                r"демонстрацион\w*|экспериментальн\w*|прототип\w*|заготовк\w*|"
                r"чернов\w*|макет\w*|stub\w*|пробн\w*|незрел\w*|"
                r"не\s+достиг\w*[^\n]{0,20}зрел\w*|"
                r"не\s+был\w*\s+(?:зрел\w*|полноценн\w*|реализован\w*)|"
                r"не\s+(?:существовал\w*|имел\w*|содержал\w*|поддерживал\w*)",
                normalized,
            )
            assert not downgrade, f"historical donor RESTORE downgraded: {rel}: {sentence}"

        # A completed APPLY has no product-internal recovery branch.
        has_completion = bool(re.search(
            r"после\s+(?:успешн\w*\s+)?apply|завершив\s+apply|"
            r"по\s+завершени\w*[^\n]{0,24}apply|успешн\w*[^\n]{0,24}apply",
            lower,
        ))
        has_product = "securelinux-policy" in lower or "продукт" in lower
        has_recovery = bool(re.search(
            r"возвращ\w*|восстанавлива\w*|откатыва\w*|возврат\w*|"
            r"восстановлен\w*|откат\w*|приводит\w*[^\n]{0,40}(?:прежн\w*|исходн\w*)",
            lower,
        ))
        has_internal = bool(re.search(
            r"\bсам\b|самостоятельно|автоматическ\w*|встроен\w*|внутренн\w*|"
            r"средствами\s+(?:securelinux-policy|продукта)|"
            r"securelinux-policy[^\n]{0,30}(?:возвращ|восстанавли|откатыва|приводит)",
            lower,
        ))
        explicit_external = bool(re.search(
            r"external_snapshot|external\s+snapshot|вне\s+продукта|"
            r"ответственност\w*\s+инфраструктур",
            lower,
        ))
        assert not (has_completion and has_product and has_recovery and has_internal and not explicit_external), (
            f"post-APPLY internal recovery claim: {rel}: {paragraph}"
        )

        # Deterministic artifact: unchanged inputs cannot intentionally yield a
        # different result/bytes.
        has_artifact = bool(re.search(r"артефакт\w*|distributable|сборк\w*|итогов\w*\s+пакет\w*", lower))
        same_inputs = bool(re.search(
            r"одинаков\w*\s+вход\w*|тех\s+же\s+вход\w*|"
            r"неизменн\w*\s+(?:исходн\w*\s+)?данн\w*",
            lower,
        ))
        variable_output = bool(re.search(
            r"может\w*[^\n]{0,50}(?:отлич\w*|различ\w*|меняться|изменяться|иным|друг\w*)|"
            r"(?:вправе|допускается|разрешено)[^\n]{0,50}(?:отлич\w*|различ\w*|иным|друг\w*)|"
            r"не\s+гарантир\w*[^\n]{0,60}(?:одинаков\w*|совпад\w*)",
            lower,
        ))
        assert not (has_artifact and same_inputs and variable_output), (
            f"nondeterministic future artifact claim: {rel}: {paragraph}"
        )

        # Future/release executable filename is intentionally not pinned. Historical
        # donor filename under an explicit non-binding statement remains allowed.
        if re.search(r"[a-z0-9_.-]+\.sh", lower) and not re.search(
            r"не\s+закрепля\w*[^\n]{0,80}(?:имя|назван)", lower
        ):
            naming = bool(re.search(
                r"будет\s+называться|обязан\w*\s+называться|"
                r"имя[^\n]{0,24}[—:=]|названи\w*[^\n]{0,24}[—:=]|"
                r"(?:исполняем\w*\s+файл|executable|скрипт)[^\n]{0,16}[—:=]",
                lower,
            ))
            future_context = bool(re.search(
                r"будущ\w*|future|релизн\w*|"
                r"итогов\w*\s+(?:исполняем\w*|скрипт\w*|distributable)|\bv3\b",
                lower,
            ))
            assert not (naming and future_context), f"future .sh filename pinned: {rel}: {paragraph}"


def expect_global_semantic_rejected(rel: str, mutated: str, label: str) -> None:
    try:
        validate_global_current_semantics(rel, mutated)
    except AssertionError:
        return
    raise AssertionError(f"global semantic negative fixture unexpectedly accepted: {label}")


for rel in current_markdown:
    validate_global_current_semantics(rel, (ROOT / rel).read_text(encoding="utf-8"))

for label, claim in (
    ("global_manual_controls_count", "Текущее число canonical controls — 52."),
    ("global_manual_status_counts", "Текущее покрытие source index: 40 CLOSED / 309 OPEN."),
    ("global_apply_adapters_removed", "В последующих версиях адаптеры APPLY отсутствуют в плане работ."),
    ("global_step7b_reactivated", "Несмотря на PAUSED_BY_CURRENT_DOCUMENT_APPLY, работы по Step 7B вновь ведутся как ключевой трек."),
    ("global_donor_restore_downgrade", "Исторический donor RESTORE был пробным демонстрационным прототипом."),
    ("global_nondeterministic_package", "При неизменных исходных данных итоговый пакет может получаться иным."),
    ("global_future_shell_name", "Релизный скрипт v3 будет называться `securelinux-policy-final.sh`."),
    ("global_post_apply_internal_recovery", "Завершив APPLY, SecureLinux-Policy сам приводит систему к прежним настройкам."),
    ("global_current_controls_aktual", "В актуальной версии проекта насчитывается 52 canonical controls."),
    ("global_unqualified_controls", "Canonical controls: 52."),
    ("global_apply_adapters_crossed_out", "Адаптеры APPLY вычеркнуты из дальнейшего плана разработки."),
    ("global_donor_restore_trial", "RESTORE в SecureLinux-NG представлял собой пробную реализацию, не достигшую зрелости."),
    ("global_post_apply_auto_recovery", "После успешного APPLY продукт автоматически возвращает прежнее состояние."),
    ("global_nondeterministic_permitted", "При тех же входах сборка вправе давать отличающиеся байты."),
    ("global_future_executable_colon", "Будущий исполняемый файл: `slp-v3.sh`."),
    ("global_false_historical_escape", "CURRENT_PROJECT_AUTHORITY=false\nОт дальнейшей реализации APPLY-adapters проект отказался."),
):
    expect_global_semantic_rejected("docs/compatibility.md", compat + "\n\n" + claim + "\n", label)

# Review-bound current-documentation byte baseline. This is deliberately
# separate from the generic root manifests: rebuilding PROJECT-FILES.sha256 /
# SHA256SUMS must never silently bless arbitrary new current prose. Any current
# Markdown byte change therefore fails closed until the semantic baseline itself
# is explicitly reviewed and updated in a controlled correction. Regex semantic
# checks remain defense-in-depth; the byte boundary prevents an unknown synonym
# from becoming PASS merely because a detector does not know that wording.
REVIEW_BASELINE = ROOT / "tests/documentation-v1/CURRENT-MARKDOWN-REVIEW-BASELINE.tsv"

def load_review_bound_baseline() -> dict[str, str]:
    with REVIEW_BASELINE.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    assert rows and set(rows[0]) == {"path", "sha256"}
    result: dict[str, str] = {}
    for row in rows:
        rel = row["path"]
        digest = row["sha256"]
        assert rel not in result, f"duplicate review baseline path: {rel}"
        assert re.fullmatch(r"[0-9a-f]{64}", digest), (rel, digest)
        result[rel] = digest
    return result

review_bound_docs = {
    rel for rel in current_markdown
    if rel not in {"CHANGELOG.md", "step7b0/ARTIFACT-STATUS-RU.md"}
}
review_baseline = load_review_bound_baseline()
assert set(review_baseline) == review_bound_docs, (
    sorted(review_bound_docs - set(review_baseline)),
    sorted(set(review_baseline) - review_bound_docs),
)

def validate_review_bound_doc(rel: str, body: str) -> None:
    assert rel in review_baseline, rel
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert digest == review_baseline[rel], f"current Markdown requires semantic re-review: {rel}"

for rel in sorted(review_bound_docs):
    validate_review_bound_doc(rel, (ROOT / rel).read_text(encoding="utf-8"))

review_probe_rel = "docs/compatibility.md"
review_probe_base = (ROOT / review_probe_rel).read_text(encoding="utf-8")
review_probe_mutations = (
    "В актуальной версии canonical controls насчитывается пятьдесят два.",
    "От дальнейшей реализации APPLY-adapters проект отказался.",
    "Step 7B возвращён в работу и теперь центральный трек проекта.",
    "Исторический donor RESTORE оставался учебной proof-of-concept реализацией.",
    "После успешного применения политики SecureLinux-Policy сам приводит систему к состоянию до изменений.",
    "Повторная сборка из тех же исходных данных не обязана совпадать побайтово.",
    "Будущий исполняемый сценарий будет называться slp-v3.",
    "Для будущего релиза закреплено имя исполняемого файла securelinux-policy-v3.",
)
for mutation in review_probe_mutations:
    try:
        validate_review_bound_doc(review_probe_rel, review_probe_base + "\n\n" + mutation + "\n")
    except AssertionError:
        pass
    else:
        raise AssertionError(f"review-bound negative fixture unexpectedly accepted: {mutation}")

# Stronger presentation guard: outside fenced code and explicitly marked exact-label
# blocks, current Markdown must not retain full English prose paragraphs/headings.
# This is intentionally presentation-only: technical identifiers/status tokens may remain.
english_word = re.compile(r"\b[A-Za-z][A-Za-z-]{2,}\b")
banned_english_heading = re.compile(
    r"^#{1,6}\s+(?:Added|Fixed|Changed|Tested|Verification|Preserved|Checker|"
    r"Pending|Pinned|Recorded|Policy|Docs|Evidence|Scope|Population|Regression|Regressions|Product)\b"
)
for rel in current_markdown:
    body = (ROOT / rel).read_text(encoding="utf-8")
    fenced = False
    exact_labels = False
    for lineno, raw in enumerate(body.splitlines(), 1):
        line = raw.strip()
        if line == "<!-- BEGIN MATURE DONOR FAMILIES -->":
            exact_labels = True
            continue
        if line == "<!-- END MATURE DONOR FAMILIES -->":
            exact_labels = False
            continue
        if line.startswith("```"):
            fenced = not fenced
            continue
        if fenced or exact_labels or not line or line.startswith("<!--"):
            continue
        assert not banned_english_heading.search(line), f"English presentation heading: {rel}:{lineno}: {line}"
        # Remove inline-code spans before estimating whether this is human prose.
        visible = re.sub(r"`[^`]*`", "", line)
        words = english_word.findall(visible)
        if not re.search(r"[А-Яа-яЁё]", visible):
            assert len(words) < 4, f"English presentation prose: {rel}:{lineno}: {line}"
        common = {"the", "and", "or", "is", "are", "was", "were", "be", "to", "of", "in", "on", "for", "from", "with", "without", "by", "as", "at", "that", "this", "these", "those", "not", "only", "when", "where", "which", "while", "before", "after", "into", "should", "must", "may", "can", "cannot", "does", "have", "has"}
        common_count = sum(word.lower() in common for word in words)
        assert common_count < 3, f"Mixed English presentation prose: {rel}:{lineno}: {line}"

# High-value migrated documents must remain materially Russian without pinning
# exact Russian sentences/headings. Technical identifiers remain separately checked.
ru_migrated_docs = (
    "docs/ARCHITECTURE-DIAGRAMS.md",
    "docs/DONOR-V3-ADOPTION-POLICY.md",
    "docs/evidence-binding.md",
    "docs/root-manifest-policy.md",
    "docs/engineering-donor.md",
    "docs/testing-strategy.md",
    "index/engineering-donor-v1/README.md",
    "index/engineering-tests-v1/README.md",
    "index/source-v4/INDEX-SCOPE.md",
    "checker/gate6-v1/GATE-SPEC.md",
    "checker/gate6-v1/README.md",
    "checker/gates-v2/GATE-SPEC.md",
    "checker/gates-v2/README.md",
    "checker/release-v1/GATE-SPEC.md",
    "checker/release-v1/README.md",
    "tests/engineering-tests-v1/README.md",
    "tests/gate6-v1/README.md",
    "tests/gates-v2/README.md",
    "tests/release-v1/README.md",
    "tests/engineering-donor-v1/README.md",
    "tests/source-skeleton-v1/README.md",
    "sources/recovered-v1/RECOVERY-METHOD.md",
)
for rel in ru_migrated_docs:
    body = (ROOT / rel).read_text(encoding="utf-8")
    assert len(re.findall(r"[А-Яа-яЁё]", body)) >= 20, f"insufficient Russian prose: {rel}"

policy_body = (ROOT / "docs/DONOR-V3-ADOPTION-POLICY.md").read_text(encoding="utf-8")
for token in ("DONOR_TO_V3_MAPPING", "REUSE", "ADAPT", "REJECT", "DEFER", "EXTERNAL_SNAPSHOT"):
    assert token in policy_body, token

# Generated blocks exist exactly once.
assert readme.count("<!-- BEGIN GENERATED CURRENT STATUS -->") == 1
assert readme.count("<!-- END GENERATED CURRENT STATUS -->") == 1
assert pmap.count("<!-- BEGIN GENERATED MAP STATUS -->") == 1
assert pmap.count("<!-- END GENERATED MAP STATUS -->") == 1

current_map = pmap.split("## 6. Где мы находимся", 1)[1].split(
    "## Что является источником истины", 1
)[0]
assert current_map.count(":::current") == 1
for marker in (
    "SRC-0005 / 2.3.1", "CHECK-11", "CHECK-17", "SRC-0040 / 2.6.6",
    "CHECK-18", "SRC-0033 / 2.5.10", "CHECK-19", "CHECK-28",
    "DONOR_TO_V3_MAPPING", "ACCEPTED + COMMITTED", "1db91b0",
    "APPLY parent gate", "AUTHORITY_2026_REFRESH",
    "SRC-0001 modular APPLY contract architecture",
    "SRC-0001 predicate / transform definitions", "SRC-0001 external snapshot precondition",
    "SRC-0001 lock/reread + object identity", "SRC-0001 метаданные/транзакция/отчёт", "APPLY для SRC-0001", "финальная детерминированная упаковка",
    "fstec-linux-2022 CHECK COMPLETE", "ВНЕШНИЙ СНИМОК",
):
    assert marker in current_map, marker
assert "APPLY parent gate<br/>ПРИНЯТО<br/>SRC-0001 flat contract candidate: REVISE" in current_map
assert "SRC-0001 current contract<br/>ПРИНЯТО" not in current_map
assert "AUTHORITY_2026_REFRESH<br/>приказы № 117 + № 137<br/>ГОТОВО" in current_map
assert "SRC-0001 modular APPLY contract architecture<br/>compact registry + SHA bindings<br/>ГОТОВО" in current_map
assert "SRC-0001 predicate / transform definitions<br/>exact empty + exact bang<br/>ГОТОВО" in current_map
assert "SRC-0001 external snapshot precondition<br/>exact attestation + prestate binding<br/>ГОТОВО" in current_map
assert "SRC-0001 lock/reread + object identity<br/>stale + path identity fail-closed<br/>ГОТОВО" in current_map
assert "SRC-0001 метаданные/транзакция/отчёт<br/>8 определений + композиция<br/>ГОТОВО" in current_map
assert "APPLY для SRC-0001<br/>ОДНА ВЕРТИКАЛЬ<br/>ГОТОВО" in current_map
assert "МЫ ЗДЕСЬ<br/>финальная детерминированная упаковка" in current_map
assert "Модульная architecture APPLY-contract" in current_map
assert "PAUSED_BY_CURRENT_DOCUMENT_APPLY" in current_map

stale_checkpoint_markers = (
    "текущий substantive checkpoint — `APPLY implementation` для SRC-0001",
    "МЫ ЗДЕСЬ<br/>SRC-0001 APPLY implementation",
    "единственным текущим substantive checkpoint этап `APPLY implementation`",
    "МЫ ЗДЕСЬ<br/>APPLY для SRC-0001",
    "SRC-0001 current contract<br/>ПРИНЯТО",
    "первый source-specific APPLY semantic contract для `SRC-0001` приняты",
)
for rel in current_markdown:
    body = (ROOT / rel).read_text(encoding="utf-8")
    for marker in stale_checkpoint_markers:
        assert marker not in body, (rel, marker)

for stale in (
    "МЫ ЗДЕСЬ<br/>Step 7B",
    "текущий product checkpoint внутри макроэтапа Step 7B",
    'implementation<br/>adapters"]:::future',
    'deterministic<br/>build"]:::future',
    "single distributable<br/>securelinux-ng.sh",
):
    assert stale not in current_map, stale
assert "путь к конечному `securelinux-ng.sh`" not in pmap
assert "Финальный `securelinux-ng.sh`" not in pmap

print("DOCUMENTATION_NEGATIVE_FIXTURES=PASS_31 controls_count=4 disposition_counts=3 root_live_counts=2 exact_enum=1 step7b0_historical=3 global_semantics=16 b01_changelog=1 skip_policy=1")
print(f"DOCUMENTATION_REVIEW_BOUND_BASELINE=PASS_{len(review_bound_docs)} mutation_fixtures={len(review_probe_mutations)}")
print("DOCUMENTATION_GIT_VISIBLE_POPULATION=PASS tracked=1 untracked_nonignored=1 ignored=0")
print(
    "DOCUMENTATION_BASELINE=PASS "
    f"docs_indexed={len(doc_names)} generated_files=3 primary_map=1"
)
