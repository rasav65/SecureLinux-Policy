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
