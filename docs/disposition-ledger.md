# Disposition ledger v1

`DISPOSITION-LEDGER.tsv` — обязательный проверяемый артефакт альтернативного
пути закрытия строки source index в Gate 2.

## Зачем он нужен

До Step 7A controlled-строка имела строгий `CLOSURE-CONTRACT.tsv` с точным
множеством control ID, а disposed-строке было достаточно `CLOSED`, допустимого
`disposition` и непустого свободного `reason`. Это создавало асимметрию и
делало массовый disposition плохо аудируемым.

Step 7A не создаёт ни одного реального disposition. Он сначала усиливает
контракт, пока `disposed_closed=0`.

## Формат

Файл находится рядом с соответствующим `SOURCE-INDEX.tsv`.

Поля TSV строго фиксированы и упорядочены:

`index_id  disposition  reason  basis  decided_by  decided_at`

Closed schema состоит из **двух независимых условий**: header должен быть
ровно этим шестипольным набором в указанном порядке, и каждая физическая
data-row должна содержать ровно шесть TSV-значений. Лишнее или отсутствующее
значение приводит к fail-closed до разбора полей.

Ledger — именно **physical TSV**, а не CSV с табуляцией как delimiter.
CSV-quoting отключён (`QUOTE_NONE`): кавычки являются обычными символами и не
могут скрыть `TAB`, `CR` или `LF`. Встроенный delimiter меняет арность строки,
а `CR/LF` образует границу физической строки; оба случая fail-closed.

Требования:

- `index_id` — валидный `SRC-NNNN`, уникальный в ledger и существующий в
  загруженном index;
- `disposition` — значение текущего enum Gate 2 и точное совпадение со строкой
  index;
- `reason` — непустой текст и совпадение со stripped-значением `reason` в
  строке index;
- `basis` — непустое основание решения;
- `decided_by` — однострочный machine identifier;
- `decided_at` — UTC-время строго `YYYY-MM-DDTHH:MM:SSZ`, дополнительно
  проверяемое как реальная календарная дата.

## Инварианты Gate 2

Disposed closure принимается только если одновременно выполнено всё:

1. строка не представлена control;
2. `status=CLOSED`;
3. `disposition` входит в разрешённый enum;
4. `reason` непуст;
5. completeness contract отсутствует;
6. существует ровно одна валидная ledger-запись;
7. `disposition` и `reason` ledger совпадают с index.

Ledger-запись у controlled row запрещена. Orphan-запись, дубликат, отсутствующий
ledger-файл или некорректный timestamp приводят к fail-closed.

## Почему в v1 нет `quote_sha256`

Идея привязать решение disposition к канонической цитате полезна, но сейчас её
нельзя сделать универсальной без ложной гарантии: source skeleton generator
поддерживает только часть `unit_kind`, а две строки поддержанного типа
намеренно отказываются из-за page-furniture ambiguity. Текущий API generator
не различает отдельным стабильным типом deliberate refusal и integrity failure.

Поэтому v1 сознательно использует минимальные машинно-сверяемые утверждения:
уникальность ledger identity, совпадение `disposition` и `reason`, формат
`decided_by` и строгую календарную проверку `decided_at`. После аудита R1
зафиксировано дополнительное требование: **до первого реального disposition**
нужен типизированный anchor-state API `EXACT | REFUSED | UNSUPPORTED`; integrity
failures обязаны оставаться исключениями и не преобразовываться в эти состояния.

## Текущее состояние

Повторные независимые R3-аудиты подтвердили исправление `S7A-R2-B01`.
Статус Step 7A — `CLOSED`; новых блокеров `S7A-R3-Bxx` не выявлено.

`index/source-v4/DISPOSITION-LEDGER.tsv` содержит только заголовок.

Следовательно, закрытие Step 7A само по себе не закрывает строки FSTEC.
Текущая live population не дублируется здесь вручную и берётся из
`SOURCE-INDEX.tsv` / generated `docs/fstec-coverage.md`.

Step 7B разрешён для FSTEC expansion. Первый real disposition остаётся
заблокирован до отдельного quote-anchor contract/API.
