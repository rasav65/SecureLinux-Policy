# B1.1b — companion статуса исторических sidecar

Этот файл является **новым current companion**, а не изменением исторических
`R*-OUTPUTS.sha256` / `R*-ADMIN-DOCS.sha256`. Исходные sidecar сохраняются
побайтово и не переписываются задним числом.

Восемь sidecar фиксировали SHA stage-specific путей, которые позднее изменялись
in-place до импорта архива в SecureLinux-Policy-v3. Для 40 несовпадающих digest
исходные stage-specific bytes в текущем репозитории не сохранены. Поэтому эти
sidecar классифицированы как `NON_REPRODUCIBLE_HISTORICAL_RECORD` и **не могут**
использоваться как current reproducibility/integrity proof.

Точная machine-readable классификация, число записей и несовпадений находятся в
`ARCHIVAL-SIDECAR-STATUS.tsv`. Regression `project-integrity-v1` пересчитывает
эти значения по фактическим bytes и дополнительно проверяет, что ожидаемые SHA
несовпадающих stage bytes не появились где-либо в текущей Git-visible population.

Корневые manifests по-прежнему проверяют сохранность самих sidecar-файлов; это
не трактуется как подтверждение истинности их historical target claims.
