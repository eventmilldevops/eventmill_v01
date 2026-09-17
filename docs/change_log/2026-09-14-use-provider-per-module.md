# Change Log — `use <provider> [for <tool>]`, the runtime A/B control

**Date:** 2026-09-14
**Primary Files Modified:** `framework/cli/shell.py`,
`tests/framework/test_cli_provider_selection.py` (new), `AGENTS.md`

**1075 tests pass** (was 1059; +16). Stage B of
`docs/specs/projector_three_vendor_run.md`, the CLI half of Stage 5 in
`docs/specs/multi_provider_llm_clients.md`. Stage A bound three vendors at
once; this is what points a module at one of them.

---

## What this makes possible

```
eventmill > use anthropic for adversary_path_projector
  adversary_path_projector will run on anthropic.

eventmill > use
  Session default: gcp_gemini  (first in EVENTMILL_LLM_PROVIDERS)
  Bound:           gcp_gemini, anthropic, openai

  Per-tool overrides
    adversary_path_projector           anthropic

eventmill > run adversary_path_projector --action project_paths ...
  Running Adversary Path Projector on anthropic (timeout 600s)...
```

Same session, same artifacts, same flow map, same prompt — a different
reasoner. That is the recorded requirement: *"those could be overridden at
runtime in order to compare outputs."*

## The command

| Form | Effect |
|---|---|
| `use` | show the selection, what is bound, and where the default came from |
| `use <provider>` | session default for every tool |
| `use <provider> for <tool_name>` | override one module |
| `use default` | clear everything |
| `use default for <tool_name>` | clear one override |

Resolution is per-tool override, then session default, then `None` — and
**`None` keeps meaning "whatever the dispatcher chose"**. Naming the default
explicitly would look harmless and would silently pin a session that had
expressed no opinion, so `_provider_for()` returns `None` and a one-vendor
session is byte-identical to before this existed.

The selection is **session-scoped and not persisted**. An A/B choice surviving
a restart invisibly is the same hazard as the `.env` model pin that has already
cost this project a day.

### Two refusals, both to fail now rather than later

- **An unbound provider is refused**, naming what is bound. Accepting it would
  defer the failure to the tool's first LLM call, by which time the operator
  has spent a long-class timeout getting there.
- **An unknown tool name is refused.** A typo would otherwise sit in the map
  and never match a run, which reads as "the override did nothing" long after
  the mistake was made.

And `connect` now prunes: reconnecting with a different
`EVENTMILL_LLM_PROVIDERS` clears any selection naming a provider that is no
longer bound, and says so.

## Where the selection is applied

**`shell.py:2883`**, the one place a manifest default becomes a per-execution
decision:

```python
scoped_llm = TierScopedLLMClient(
    self.llm_client,
    default_tier=model_tier,
    default_provider=selected_provider,
)
```

The plumbing for this landed with the rekey (`71df426`) and nothing had used
it. The tier and the provider are both per-execution operator decisions and
they now travel together, through the one wrapper a plugin cannot reach past.
`test_the_context_hands_the_plugin_a_wrapper_with_no_provider_argument` asserts
that what the plugin actually receives still exposes no `provider` parameter on
`query_text` or `query_with_document` — so "the analysis tools do not change"
survives the feature that most tempts it.

**`ask:` follows the session default too**, via `_provider_kwargs()`, which
duck-types on `accepts_provider_scope` exactly as the wrapper does. A per-tool
override is deliberately not consulted there: `ask:` is not a tool. It is the
operator reasoning over their own session, so the vendor they chose should
answer it.

**The run line names the vendor when there is a choice** — when a selection is
in force, or when more than one provider is bound. It stays silent for a
single-vendor session, because an unchanged session's output must stay
unchanged, and a transcript of a three-vendor comparison has to say which
vendor produced each line. Both halves are pinned by a test.

## The new test file, and a note on its cost

`tests/framework/test_cli_provider_selection.py` — 16 tests. Five of them run
`adversary_path_projector --action profile_actor`, which is deterministic,
offline and heavy-tier, so a real run builds a real wrapper and the spy can
read what it was constructed with. Testing the resolution helper alone would
have left the wiring at `shell.py:2883` unasserted, which is the whole of this
stage.

Written function-scoped first, the file cost **94 s** — a shell costs ~5.7 s to
build (plugin discovery plus the ATT&CK tables) and it was building sixteen.
The common three-provider session is now module-scoped with its selection state
reset per test, and only the four tests that need a different provider list
build their own: **32 s**, same coverage. Whole-suite time went from 98 s
before Stage A to 126 s.

It also carries its own copy of the ambient-environment strip that
`test_provider_registry.py` has. The shell loads `.env` at startup and
`EVENTMILL_MODEL_HEAVY` is pinned there; a test that read it would pass or fail
by machine.

## Verified

- **1075 passed**, none skipped, none xfailed.
- Offline against dummy keys: every form of `use`, both refusals, the report,
  the prune on reconnect, and the run line in both the one-vendor and
  three-vendor cases.
- No network call. `connect` still cannot answer reachability on any provider;
  that is `providers probe`, untouched here.
- `ruff` / `black` / `mypy` are not installed in this venv, so none was run.
  No added line exceeds 88 columns.

## Not done — what still blocks the three-vendor run

Stage C is now the blocker, and it is the sharp one: the projector's run record
hardcodes `"provider": "gcp_gemini"` (`tool.py:3506`). With this stage landed
it is possible to run the projector on three vendors today — and every record
would claim Gemini, which makes the group unreadable rather than merely
incomplete. Then Stage D, the group summary's provider dimension.
