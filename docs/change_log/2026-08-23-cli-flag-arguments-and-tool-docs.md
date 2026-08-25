# 2026-08-23 — Flag arguments for `run`, and tool docs that can be pasted

Every plugin README documented tool invocation as a bare JSON object:

```json
{"action": "list_reports"}
```

Pasted into the shell, that is not a command. `cmd.Cmd` splits on the first
token, finds no `do_{"action":`, and falls through to `default()`:

```
eventmill (threat_modeling) > {"action": "list_reports"}
  Unknown command: {"action":
```

The syntax was never wrong in the code — `do_run` has accepted both JSON and
`--flag` payloads all along — but nothing the analyst reads showed the `run
<tool_name>` prefix, and `_print_tool_help` renders the plugin's README verbatim
underneath its own correct `Invoke:` line, so the wrong form is the one on screen
at the point of use.

The organising decision: **flags are the documented way to call a tool.** JSON
stays for the arguments a flag cannot express — lists of objects, nested
structures — and nothing else.

---

## Flag values are typed from the input schema

Flags could not be made primary as they stood. The parser assigned every value as
a string, so `--line_limit 100` reached `log_navigator` as `"100"` and
`range(line_limit)` raised `TypeError`. Documenting that would have shipped
examples that crash.

`_parse_flag_payload()` now types each value from the plugin's
`schemas/input.schema.json`:

| Declared type | Flag form | Result |
|---|---|---|
| `string` | `--query 404` | `"404"` — stays a string |
| `integer` / `number` | `--line_limit 100` | `100` |
| `boolean` | `--invert` or `--invert true` | `True` |
| `array` of `string` | `--ioc_types ip,domain` | `["ip", "domain"]` |
| `array` of `object`, `object` | — | refused, with a pointer to the JSON form |

Typing comes from the schema rather than from guessing at the literal, which is
what keeps `--query 404` a string while `--max_results 50` becomes an int. A key
the schema does not declare passes through unchanged for the plugin's own
`validate_inputs()` to judge — `--artifact_id` relies on this, since the shell
resolves it to `file_path` before the plugin sees the payload.

Also added: `--key=value` (needed when a value starts with `-`), and repeating a
list-valued flag appends rather than overwrites.

## `help <tool_name>` lists the arguments

`_print_tool_arguments()` renders the input schema above the README — name, type,
required, default, allowed values, and description — so the flag names are
visible without reading prose. Single-key `anyOf` branches render as
"Supply one of: --artifact_id, --stages". This is the only argument documentation
the seven network_forensics plugins have, none of which ship a README.

The header now shows both forms:

```
  Invoke: run threat_report_analyzer --key value [--key value ...]
      or: run threat_report_analyzer {"key": "value"}   (for list/object arguments)
```

## Bare JSON gets a targeted message

`default()` recognises a line starting with `{` and says what is missing rather
than reporting an unknown command.

## `attack_path_visualizer` input schema

The schema declared `required: ["stages"]`, but the tool's own `validate_inputs()`
accepts `artifact_id` **or** `stages`, and `artifact_id` — the path the README
leads with and the one `threat_intel_ingester` emits — was not a declared property
at all. Now it is, and `required` became `anyOf`. Left alone, the new
schema-driven help would have told analysts the documented path was invalid.

## Markdown rendering

`_render_markdown_plain()` wrapped each source line independently, so a
hard-wrapped paragraph in a README came out ragged. Paragraph lines are now
buffered and wrapped as a block. Blockquoted fenced code also rendered as a stray
backtick with the command reflowed across lines — unusable for copy-paste — so
the READMEs use a plain paragraph plus a fence instead of a blockquote.

## Documentation

All nine plugin READMEs lead with `run <tool_name> --key value`; JSON follows as
the alternative for structured arguments. `risk_assessment_analyzer` and
`threat_model_analyzer` had no usage examples at all and now have them. The
top-level README's "Inside the shell" list gained `run`, `pillar`, and
`help <tool_name>`.

`threat_intel_ingester`'s `summarize_for_llm()` emits its "Quick chart:" hint in
flag form, matching its test. Its README also documented a `result` command that
does not exist; that step is gone.

## Not addressed

`do_history` is defined twice in `shell.py` — the tool-execution listing at the
first definition is shadowed by the LLM-conversation listing at the second, so
`history` only ever shows LLM turns. Left as-is; deciding which one `history`
should mean is a behaviour question, not a docs fix.
