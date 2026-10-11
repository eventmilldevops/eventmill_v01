# Synthetic YMMV log generator

`generate_database_audit_log.py` and `generate_catalina_log.py` expand their
reviewed JSON event catalogues into deterministic database and Catalina-style
logs. They use only the Python standard library and do not contact an LLM or
any external service.

The intended low-cost workflow is:

1. Have a light-tier model, such as a configured Haiku- or Luna-class model,
   propose a small pattern catalogue or changes to this one. Provider selection
   remains an Event Mill operator decision; do not put a vendor model name in
   the generator.
2. Review the catalogue for realistic fields, safe synthetic identifiers, event
   distributions, and planted scenarios.
3. Expand the approved catalogue locally at zero model cost.
4. Keep the generated ground-truth file beside the log so parser results can be
   scored against exact counts.

## Generate the checked-in fixture

From the repository root:

```text
python plugins/log_analysis/examples/scripts/generate_database_audit_log.py \
  --start-date 2026-09-15 \
  --end-date 2026-09-17 \
  --records 200 \
  --seed 260915 \
  --output plugins/log_analysis/examples/ymmv_legacy_invoicing_database_audit.log
```

The default business-hours ratio is 0.83, where business hours are 07:00
through 17:59. Use `--business-hours-ratio` only with a value from 0.80 through
0.85. The output is chronological, uses a fixed UTC-07:00 offset, and includes
an after-hours DBA customer export plus an after-hours backup.

Use `--check` to validate a request and print the planned ground truth without
writing files. Existing files are not replaced unless `--force` is supplied.

## Scale the volume or date range

```text
python plugins/log_analysis/examples/scripts/generate_database_audit_log.py \
  --start-date 2026-10-01 \
  --end-date 2026-10-31 \
  --records 50000 \
  --seed 81003 \
  --output workspace/artifacts/ymmv_database_audit_50000.log
```

All hostnames use the reserved `.example` namespace. Customer data is never
generated; the export scenario records only field names, counts, hashes, and a
synthetic local path.

## Generate the checked-in Catalina fixture

```text
python plugins/log_analysis/examples/scripts/generate_catalina_log.py \
  --start-date 2026-09-15 \
  --end-date 2026-09-17 \
  --records 240 \
  --seed 260918 \
  --output plugins/log_analysis/examples/ymmv_legacy_invoicing_catalina.log
```

For this generator, `--records` counts logical events. A Java exception is one
logical event but occupies four physical lines. The checked-in fixture contains
240 logical events and 249 physical lines, including three multiline database
connection-pool exceptions. Ground truth records both counts so a parser can be
scored for boundary detection as well as field extraction.

The same date, volume, seed, output, `--check`, and `--force` controls described
above apply. For example, change `--records` to `50000` and the date range to a
month to produce a large load-test fixture without an LLM call.

## Generate the checked-in Linux OS fixtures

The general syslog is intentionally long and operationally dull:

```text
python plugins/log_analysis/examples/scripts/generate_linux_syslog.py \
  --start-date 2026-09-15 \
  --end-date 2026-09-17 \
  --records 3000 \
  --seed 260921 \
  --output plugins/log_analysis/examples/ymmv_legacy_invoicing_syslog.log
```

It contains a 28-record startup sequence followed mostly by cron, systemd,
time-sync, rotation, kernel, network, and service-health messages. It contains
no interactive-user events and deliberately carries no application request or
database transaction detail.

The companion authentication log is generated separately:

```text
python plugins/log_analysis/examples/scripts/generate_linux_auth_log.py \
  --start-date 2026-09-15 \
  --end-date 2026-09-17 \
  --records 420 \
  --seed 260922 \
  --output plugins/log_analysis/examples/ymmv_legacy_invoicing_auth.log
```

For the authentication generator, `--records` counts logical operations. PAM
session pairs and successful SSH sessions occupy multiple physical lines. The
checked-in output therefore has 420 logical operations and 780 physical lines.
Only seven interactive SSH attempts are planted: five successful sessions and
two failures. The remainder is primarily routine CRON and system-account PAM
activity.
