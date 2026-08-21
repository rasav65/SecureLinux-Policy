# Совместимость текущей product-line

Этот документ разделяет **SUPPORTED**, **TESTED** и **UNSUPPORTED**. Эти статусы
не являются синонимами.

## SUPPORTED

Текущий target contract product CHECK:

```text
ubuntu-24.04-x86_64
```

Target задаётся `product/generate-product-check-v1.py` и binding/semantic
contracts adapters. Generated CHECK выполняет target preflight до проверки
controls.

`SUPPORTED` означает: текущий product contract разрешает этот target. Это не
утверждение, что все возможные варианты Ubuntu 24.04 уже прошли VM acceptance.

## TESTED

Для статуса `TESTED` требуется конкретное evidence, связанное с точными bytes
проверяемой product population и средой выполнения.

На Documentation Baseline **нет tracked VM evidence для полного текущего
product CHECK по всем current controls**, поэтому общий target не повышается до
универсального `TESTED` только на основании одного локального запуска.

В проекте существует historical/reference VM evidence для более раннего
пяти-sysctl pilot. Оно остаётся полезным инженерным evidence, но не подменяет
тестирование текущей product population.

Локальный CHECK может зависеть от прав чтения наблюдаемого объекта. По semantic
contract невозможность чтения — `ERROR`, а не `NOT_FOUND`; поэтому ограничение
прав не приводит к ложной оценке соответствия.

## UNSUPPORTED

Любой target, не равный current target contract, должен быть отклонён generated
CHECK с RC=3 до выполнения policy checks.

Добавление новой ОС/архитектуры требует отдельного target contract и
соответствующих tests/evidence. Категории `server`, `desktop`, `container`,
`Docker` или `Kubernetes` заранее не объявляются поддержанными только по названию
окружения.

## Evidence rule

Чтобы строка появилась здесь как `TESTED`, запись должна указывать минимум:

- OS и версию;
- архитектуру;
- тип среды;
- дату;
- exact product/control identity;
- ссылку на tracked evidence или его SHA-256.
## VM-наблюдения layout для SRC-0011

Это **не** расширение `SUPPORTED` target и не acceptance полного product CHECK. Наблюдения используются только для проверки population/layout assumptions требования 2.3.7.

| ОС | Тип установки | cron | `/var/spool/cron` | `/var/spool/cron/crontabs` | Regular files | Traversal errors |
|---|---|---|---|---|---:|---:|
| Ubuntu 22.04.5 LTS | **FULL** | `3.0pl1-137ubuntu3` | `0755 root:root` | `1730 root:gid112` | 0 | 0 |
| Ubuntu 24.04.4 LTS | **MINIMIZED** | не установлен | отсутствует | отсутствует | 0 | 0 |
| Ubuntu 24.04.4 LTS | **FULL** | `3.0pl1-184ubuntu2` | `0755 root:root` | `1730 root:gid990` | 0 | 0 |
| Ubuntu 26.04 LTS | **MINIMIZED** | не установлен | отсутствует | отсутствует | 0 | 0 |
| Ubuntu 26.04 LTS | **FULL** | `3.0pl1-200ubuntu1` | `0755 root:root` | `1730 root:gid986` | 0 | 0 |
| Debian 12 (bookworm) | **SERVER** | `3.0pl1-162` | `0755 root:root` | `1730 root:gid101` | 0 | 0 |
| Debian 13.4 (trixie) | **GNOME** | `3.0pl1-197` | `0755 root:root` | `1730 root:gid997` | 0 | 0 |

Вывод для semantics: оба roots являются optional discovery roots; штатное отсутствие обоих roots и штатно пустая population должны давать compliant результат. Конкретный GID каталога `crontabs` различается между установками и поэтому не является policy condition SRC-0011.

## VM-наблюдения layout для SRC-0012

Это **не** расширение `SUPPORTED` target и не acceptance полного product CHECK. Наблюдения подтверждают topology/population assumptions требования 2.3.8. Диагностический probe был read-only и выполнялся привилегированно только на отдельных ВМ; на основном ПК пользователя привилегированные проверки не выполняются.

Во всех семи ВМ наблюдался merged-`/usr`: `/bin → /usr/bin`, `/sbin → /usr/sbin`, `/lib → /usr/lib`, `/lib64 → /usr/lib64`. Current-kernel `/lib/modules/<uname-r>` присутствовал и разрешался в `/usr/lib/modules/<uname-r>`. Во всех просканированных standard roots `REGULAR_GO_W=0`, `SYMLINK_TARGET_REGULAR_GO_W=0`, dangling links и traversal/stat errors отсутствовали.

| ОС | Тип установки | Ядро | Privileged root PATH | Диагностические unique regular targets | Ошибки обхода |
|---|---|---|---|---:|---:|
| Ubuntu 22.04.5 LTS | **FULL** | `5.15.0-173-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 21515 | 0 |
| Ubuntu 24.04.4 LTS | **MINIMIZED** | `6.8.0-134-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 19082 | 0 |
| Ubuntu 24.04.4 LTS | **FULL** | `6.8.0-137-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 26394 | 0 |
| Ubuntu 26.04 LTS | **MINIMIZED** | `7.0.0-29-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 28293 | 0 |
| Ubuntu 26.04 LTS | **FULL** | `7.0.0-29-generic` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin` | 29116 | 0 |
| Debian 12 (bookworm) | **SERVER** | `6.1.0-44-amd64` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | 13613 | 0 |
| Debian 13 (trixie) | **GNOME** | `6.12.74+deb13+1-amd64` | `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | 13760 | 0 |

Вывод для semantics: canonical OS executable roots текущего control — `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`. Они входят и в fixed donor defaults, и во все наблюдавшиеся privileged root PATH. `/usr/local/*` и `/snap/bin` не включаются в current OS-owned population: это local/admin и application paths, а не фиксированные пути файлов ОС текущего target contract. Library roots — `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`; current-kernel module root определяется через `uname -r`.
