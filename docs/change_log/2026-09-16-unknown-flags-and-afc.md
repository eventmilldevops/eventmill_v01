# A mistyped flag is named, and the AFC notice stops firing

**Date:** 2026-09-16
**Branch:** `llm_5`
**Scope:** `framework/cli/shell.py`, `framework/llm/clients/gemini.py`
**Status:** built and mutation-checked (10 mutations, all caught).
Suite **1503 → 1511**.

Two findings from one live run's output. One of them made that run do the
opposite of what the operator asked, with nothing saying so.

---

## `--ignore_cap` was accepted in silence

The command typed was:

```
run threat_report_analyzer --action summarize --report_path ... --ignore_cap
```

`--ignore_cap`, not `--ignore_caps`. **The caps applied.** The run reported
success, the extraction bounds cut the key findings as usual, and no line of
output said the flag had not been understood.

Three things lined up to make that silent, and none of them is individually
wrong:

1. The shell reads `input.schema.json` **only to type flag values** —
   `_plugin_input_schema` returns the `properties` block alone and nothing
   validates a payload against the schema anywhere in the shell or executor.
2. `_coerce_flag_value` passes undeclared keys through **deliberately**, "for
   the plugin's own `validate_inputs()` to judge".
3. No plugin's `validate_inputs` rejects unknown keys. The analyzer's checks
   `action`, `report_path` and `query`, and nothing else.

So `payload["ignore_cap"] = True` reached `_summarize_report`, which reads
`payload.get("ignore_caps", False)` and got `False`.

Worth noting the ingester's input schema **does** set
`additionalProperties: false` — and it makes no difference, because no runtime
path validates against it either. The declaration is documentation.

### The change

An unrecognised flag is named, and the arguments the tool does accept are
listed:

```
  Warning: --ignore_cap is not an argument of threat_report_analyzer and will be ignored.
  Arguments threat_report_analyzer accepts: --action, --focus_areas, --ignore_caps, --max_word_count, --query, --report_path
```

**A warning, not a block, and no correction.** *(Operator decision,
2026-09-16.)* This is a triage tool for technologists: naming the right path is
the job, and inferring intent — running `--ignore_caps` because someone typed
something close to it — is not. The payload still carries `ignore_cap` exactly
as typed, so the run does what was asked rather than what was guessed, which is
the entire reason the warning is there. A test asserts no substitution happens.

It stays a warning rather than a refusal because an undeclared key may still be
one a plugin's own `validate_inputs()` accepts; that contract is unchanged.

A plugin whose schema cannot be read warns about nothing — every flag would
look unknown, and warning about all of them is noise that teaches nothing.

## The AFC notice described something that wasn't happening

Every run printed:

> Direct use of automatic function calling (AFC) in `Models.generate_content`
> is not recommended.

Traced rather than assumed. `google/genai/models.py:6246` logs it once per
process (`Models._logged_afc_warning`), reached whenever
`_extra_utils.should_disable_afc()` returns False — which it does by default,
because we never configured `automatic_function_calling`. We pass **no tools at
all**, so the AFC loop then ran exactly one iteration and returned.

Zero behavioural impact, which is precisely why it was worth removing:
`_build_config` now sets `AutomaticFunctionCallingConfig(disable=True)`, the
SDK takes the plain `_generate_content` path, and the notice stops. A warning
printed on every run is what teaches people to skim past the warnings that
matter, and this project's logs carry real ones.

Set in the shared `_build_config`, so the text, multimodal and document paths
all get it — the same reason the Gemini 3.x controls live there.

## Not a defect: the 503

```
Document query transient error (attempt 1/4), retrying in 1s: 503 UNAVAILABLE
```

Working as designed. `gemini.py:622-633`: `_is_retriable(exc)` gates the retry,
`wait = 2 ** attempt` gives 1s, 2s, 4s across up to `max_retries + 1` attempts.
The run recovered on the first retry. Recorded here only because it appeared in
the same output as the two findings above and is easy to mistake for one.

## Verification

10 mutations, all caught, including the ones that matter most for a change like
this: the warning firing on a *correct* flag, the warning becoming a block, and
the unknown key being silently corrected to the intended one. That last one is
the mutation that encodes the operator's decision — if someone later adds
did-you-mean substitution, the suite fails.

One mutation survived the first attempt: removing the tool name from the
warning line. The test asserted the name appeared *somewhere* in the output,
which the "Arguments X accepts:" line satisfied on its own. Now asserted on the
warning line itself — a session runs several tools, and "not an argument"
without saying of what is half a message.

## Follow-on not taken

Nothing validates payloads against `input.schema.json` at runtime. That is a
larger decision than this change: it would make `additionalProperties: false`
load-bearing for the ingester, which would turn today's warning into a refusal
for that tool only, and inconsistently. Left as is, and noted.
