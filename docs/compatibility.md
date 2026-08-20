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
