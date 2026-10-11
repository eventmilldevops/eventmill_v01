# Log-analysis examples

These files form a synthetic, repeatable corpus for learning and testing Event
Mill log-analysis workflows. YMMV Industrial and its systems, people, accounts,
records, and events are fictional.

## Event observability standard

- `ymmv_industrial_event_observability_standard.md`
- `ymmv_industrial_event_observability_standard.pdf`

The standard deliberately mixes requirements that can be assessed from event
content with requirements that require configuration, governance, or other
evidence.

## Legacy invoicing database audit log

- `ymmv_legacy_invoicing_database_audit.log` — 200 chronological records over
  three days, including routine application activity and planted scenarios.
- `ymmv_legacy_invoicing_database_audit.ground_truth.json` — exact counts,
  identities, time distribution, planted-scenario inventory, and file hash.
- `scripts/database_audit_patterns.json` — reviewed source pattern catalogue.
- `scripts/generate_database_audit_log.py` — deterministic volume and date-range
  expander.

The generated log contains no customer values, credentials, real hostnames, or
real organization identifiers.

## Legacy invoicing Catalina log

- `ymmv_legacy_invoicing_catalina.log` — 240 logical events and 249 physical
  lines in Catalina/JULI style, including startup, HTTP, service, persistence,
  authentication, session, connection-pool, configuration, and background-job
  activity.
- `ymmv_legacy_invoicing_catalina.ground_truth.json` — exact logical and
  physical counts, event distribution, shared database vocabulary, scenarios,
  and file hash.
- `scripts/catalina_log_patterns.json` — reviewed Java and event catalogue.
- `scripts/generate_catalina_log.py` — deterministic volume and date-range
  expander.

## Legacy invoicing Linux OS logs

- `ymmv_legacy_invoicing_syslog.log` — 3,000 routine general-channel records,
  including a 28-record Linux startup sequence and predominantly cron, systemd,
  time synchronization, rotation, kernel, network, and service-status noise.
- `ymmv_legacy_invoicing_syslog.ground_truth.json` — exact distribution,
  startup inventory, scope limitation, and file hash.
- `ymmv_legacy_invoicing_auth.log` — 420 logical authentication operations and
  780 physical lines, mostly CRON and system-account PAM sessions.
- `ymmv_legacy_invoicing_auth.ground_truth.json` — exact logical and physical
  counts, including five successful and two failed interactive SSH attempts.
- `scripts/linux_syslog_patterns.json` and `scripts/linux_auth_patterns.json` —
  reviewed pattern catalogues.
- `scripts/generate_linux_syslog.py` and `scripts/generate_linux_auth_log.py` —
  deterministic date-range and volume expanders.

These logs intentionally demonstrate the limits of default host telemetry. They
show boot state, scheduled work, authentication, and service health, but they do
not identify invoice actions, affected customer objects, application methods,
or database transaction content. Those details remain in the Catalina and
database fixtures.
