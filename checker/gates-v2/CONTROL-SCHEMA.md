# Запись контроля v1

Одна запись = один наблюдаемый параметр.

Верхний уровень:
`id`, `layer`, `profile`, `source`, `requirement`, `parameter`, `expected`, `apply`.

Схема закрытая: лишние и недостающие поля дают FAIL Gate 3.

`source.quote` хранится уже в каноническом `norm-v1` виде, но без финального LF.
`source.quote_sha256` — SHA-256 UTF-8 байтов именно этой строки.

`derived=false`: конкретное значение явно задано источником.
`derived=true`: значение выбрано/выведено проектом; justification обязателен.

Поддерживаемые виды `kind` в checker-v1:
`sysctl`, `file-kv`, `file-mode-owner`, `mount-option`,
`systemd-unit-state`, `package-presence`, `pam-line`, `audit-rule`.

Проверки наличия токенов GRUB и policy/rules UFW намеренно не маскируются под эти типы.
