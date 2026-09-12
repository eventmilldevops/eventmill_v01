# 2026-08-24 — Dependency warnings go to the log file, not the screen

Shell startup printed dependency deprecation notices over the banner:

```
/usr/local/lib/python3.12/site-packages/scapy/layers/tls/crypto/groups.py:25:
CryptographyDeprecationWarning: Diffie-Hellman over finite fields (FFDH) is
deprecated and support will be removed in a future release.
  from cryptography.hazmat.primitives.asymmetric.dh import DHParameterNumbers
```

These are not log records. The `warnings` module writes them straight to stderr
via `showwarning`, so no logger level and no handler configuration could reach
them — `setup_logging()`'s console handler was already suppressing INFO and only
ever saw records that went through `logging`.

`route_warnings_to_log()` in `framework/logging/structured.py` calls
`logging.captureWarnings(True)`, which reroutes them through the `py.warnings`
logger, then gives that logger the file handler only, with `propagate = False`.
Warnings land in `workspace/logs/eventmill.log` with their originating file and
line intact; nothing reaches the terminal.

`setup_logging()` calls it once the file handler exists, so it applies in both
local and Cloud Run mode. That matters in the container, where the analyst's
"screen" is the ttyd terminal and stderr is what fills it — sending warnings to
stderr would have shown them and sending them nowhere would have lost them. When
no log file is configured, the warnings logger gets a `NullHandler` and the
warnings are discarded rather than falling back to stderr.

## Scope

The warning that prompted this fires when `PluginLoader.discover_all()` imports
`pcap_metadata_summary`, which pulls in scapy's TLS layers. Discovery runs inside
`EventMillShell.__init__`, after `main()` has called `setup_logging()`, so the
routing is in place before it fires.

Warnings raised while importing `framework.cli.shell` itself — before `main()`
runs — are still unhandled. Nothing in that import chain currently warns; closing
the gap properly needs `PYTHONWARNINGS` in the environment rather than anything
in-process, since the imports complete before any of our code executes.

`logger.warning("scapy not available: ... — PCAP parsing disabled")` is unchanged
and still prints. It is a capability warning, not a deprecation notice: PCAP
tools genuinely will not work, and the analyst should see it. It does not appear
in the Cloud Run image, where scapy is installed.
