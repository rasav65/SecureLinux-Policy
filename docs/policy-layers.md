# Слои политики SecureLinux-Policy

## Основное правило

```text
FSTEC core ≠ recommended ≠ corporate standard ≠ firewall
```

Эти области могут использовать общую техническую инфраструктуру schema,
controls, adapters и CHECK, но не подменяют друг друга как источник требования.

## FSTEC core — ядро ФСТЭК

В FSTEC core допускаются только требования, для которых существует проверяемый
якорь в первичном нормативном или техническом источнике ФСТЭК.

Для controlled row требуются source identity, locator, quote anchor,
canonical control(s) и completeness contract. Engineering donor, корпоративный
стандарт или практическая рекомендация не могут сами создать FSTEC requirement.

Источники FSTEC core делятся на три ветки (решение 19.09.2026). Машинная
authority — `index/source-v4/FRAMEWORK-SOURCES.tsv` и `source_role` строк
`index/source-v4/SOURCE-INDEX.tsv`.

### Framework

Классификация, применимость и состав мер; источники регистрируются отдельно от
`SOURCE-INDEX.tsv` и не образуют популяцию «одно положение — один контроль»:

- `fstec-order-117-2025-requirements` — требования приказа № 117;
- `fstec-order-137-2026-amendments-to-117` — изменения к приказу № 117;
- `fstec-methodology-2026-04-12` — методический документ о составе мер;
  перечень мер его приложения 2 — отдельный будущий gate.

### Technical sources

Технические требования к настройке; их строки индексируются в
`SOURCE-INDEX.tsv` и закрываются контролями:

- `fstec-linux-2022` — безопасная настройка ОС Linux;
- `fstec-logging-2025` — регистрация событий безопасности;
- `fstec-configuration-2026` — безопасная конфигурация;
- `fstec-perimeter-2026` — защита сетевого периметра; его строки о межсетевом
  экране — якорь для соответствующих мер слоя firewall.

### Process sources

Процессные документы: строки проиндексированы, закрыты диспозицией, контролей нет:

- `fstec-vulnerability-management-2023` — управление уязвимостями;
- `fstec-vulnerability-analysis-2025` — анализ уязвимостей;
- `fstec-vulnerability-criticality-2025` — оценка критичности уязвимостей;
- `fstec-security-update-testing-2022` — тестирование обновлений безопасности.

## Recommended — рекомендуемый слой

`recommended` предназначен для полезных мер, которые проект хочет предложить,
но которые не являются FSTEC core и не должны визуально или машинно считаться
его покрытием.

## Corporate standard — корпоративный стандарт

`corporate standard` — отдельный слой внутренних требований и ужесточений.
Будущие профили:

- `baseline`;
- `strict`;
- `paranoid`.

относятся только к corporate standard. Профиль не определяет состав FSTEC core.

## Firewall — межсетевой экран

Firewall — самостоятельная role-specific policy. Реализации могут включать:

- UFW;
- nftables;
- iptables.

Конкретная реализация firewall-policy не становится обязательным FSTEC core без
отдельного source anchor в источнике ФСТЭК.

## Независимые измерения

Необходимо различать:

- `layer` — происхождение требования;
- `applicability` — применимо ли конкретное требование;
- `target` — платформа/среда, на которой допустима реализация CHECK/APPLY;
- `profile` — дополнительный выбор внутри corporate standard.

Эти поля не должны использоваться как взаимозаменяемые.

## Инженерный донор

SecureLinux-NG v16.2.11 — engineering donor. Его код, tests и runtime patterns
могут быть `REUSE | ADAPT | REJECT | DEFER`, но donor mapping не является
нормативным доказательством и сам закрывает ноль source-index rows.
