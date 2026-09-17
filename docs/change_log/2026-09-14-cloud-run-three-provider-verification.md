# Change Log — three providers verified on Cloud Run, and the docs caught up

**Date:** 2026-09-14
**Primary Files Modified:** `AGENTS.md`, `.env.example`,
`cloud_install/setup-deploy-server.sh`

No application code changed. This records the operator's in-container
verification and closes the documentation that still described a Gemini-only
runtime.

---

## Verified in the deployed container

All six tier clients, on Cloud Run, through the web terminal:

```
  gcp_gemini
    ✓ light  gemini-3.8-flash        auth 55 models, visible / ping 'OK' 960 ms, 9 tok
    ✓ heavy  gemini-3.1-pro-preview  auth 55 models, visible / ping 'OK' 1955 ms, 102 tok
  anthropic
    ✓ light  claude-sonnet-5         auth 11 models, visible / ping 'OK' 1628 ms, 20 tok
    ✓ heavy  claude-opus-5           auth 11 models, visible / ping 'OK' 1661 ms, 34 tok
  openai
    ✓ light  gpt-5.6-terra           auth 136 models, visible / ping 'OK' 5747 ms, 18 tok
    ✓ heavy  gpt-5.6-sol             auth 136 models, visible / ping 'OK' 2481 ms, 18 tok
```

Latencies match the local runs closely, including OpenAI's slower light tier,
so nothing about the container path is adding cost.

**What this proves, end to end:** the image now carries all three SDKs; Secret
Manager delivers four LLM keys; each key authenticates against its vendor from
inside the container; and each configured model returns a completion. That is
the chain the Stage 6 work was ordered to prove before any code depended on it.

The two non-Gemini providers were probed with `providers probe <id>` while
**not** named in `EVENTMILL_LLM_PROVIDERS`, and each reported so before probing
anyway. That is the intended path — a key is verified *before* the vendor is
adopted, which is the order the deployment assumes: secret version, verify,
then adopt.

`EVENTMILL_LLM_PROVIDERS` is still `gcp_gemini` on this revision, so Gemini
remains the only provider bound for tool execution. Nothing about module
routing changed by verifying the other two.

### The AFC line is expected

`Direct use of automatic function calling (AFC) in Models.generate_content is
not recommended` appears under `gcp_gemini` only. It is emitted by
`google-genai` **2.x** — the string does not exist in 1.69's runtime code — and
is a style recommendation about `Models.generate_content` versus
`Chat.send_message`, not an error. Its presence confirms the container is on
2.x, which is now what `pyproject.toml` declares rather than something it
drifted into.

## Documentation corrected

**`AGENTS.md` said "Gemini is still the only implemented provider and the only
one the runtime binds."** That was the operational briefing `CLAUDE.md` names as
authoritative, and it had been false since the rekey. Replaced with the
three-provider table (models, key env vars, and the caps that differ), plus the
four operating facts most likely to be assumed wrongly:

- a mounted key is not a bound provider, and `EVENTMILL_LLM_PROVIDERS` is what
  binds one;
- `connect` cannot answer reachability — every client builds an SDK handle
  without a network call, so a wrong key connects cleanly and fails at first use;
- `_clients` is keyed by `(provider_id, tier)`, and a tier-keyed dict is still
  normalised from each client's own `provider_id`;
- cross-provider fallback is forbidden and enforced in `_fallback_client`, and
  provider choice rides `TierScopedLLMClient`, never `QueryHints`.

**`.env.example` said the Anthropic and OpenAI keys were "read by nothing
today".** Now describes the tiers each key serves, and adds
`EVENTMILL_LLM_PROVIDERS` with the distinction that setting a key does not bind
its provider.

**`cloud_install/setup-deploy-server.sh`** exported only the Gemini and ttyd
secret names. Adds `EVENTMILL_SECRET_ANTHROPIC`, `EVENTMILL_SECRET_OPENAI` and
`EVENTMILL_LLM_PROVIDERS`, with the known-ids list and the note that an unknown
id is refused rather than ignored. `bash -n` clean.

`cloud_install/README.md` needed nothing — its env tables and secret mapping
were brought current with the Stage 6 secret wiring and already describe all
four keys and the placeholder convention.

## A gap worth naming

**The probe does not report which SDK versions the container is running.** The
output above proves the three vendors are reachable; it cannot show whether the
image holds `google-genai` 2.23, `anthropic` 1.5 and `openai` 3.13, or whatever
an earlier build resolved before the ceilings landed. Given that an unbounded
requirement is exactly how this deployment drifted onto a major nobody chose,
"which SDK is actually in there" is a question the diagnostic should answer.
Adding the three versions to the `providers` header is a small change and is
recorded here as the next obvious improvement rather than done silently.

## Not done here

The remaining Stage 2 accessor work is unchanged and listed in
`2026-09-14-provider-tier-rekey.md` — most importantly the PDF guard still
reads Gemini's page and size limits whatever provider is selected, and
`shell.py` does not yet pass `default_provider`, so no module can be pointed at
a second vendor yet.
