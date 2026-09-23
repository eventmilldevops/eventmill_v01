# Analysis Postures

A posture is a plain-text/markdown file whose contents are prepended to the
system context of every LLM call a tool makes, for the duration of a session
or for one tool. It does not change what a plugin computes deterministically —
only how the LLM reasons about ambiguous signal when a plugin calls it.

## Selecting one

```
posture list                          # show what's available, general + pillar-specific
posture <name>                        # session default for every tool
posture <name> for <tool_name>        # override one tool
posture default [for <tool_name>]     # clear a selection
```

`<name>` is a file stem — `paranoid` resolves to `paranoid.md`. Resolution
checks the active pillar's own posture directory first
(`plugins/<pillar>/postures/<name>.md`), then falls back to this shared
directory (`framework/llm/postures/<name>.md`). A pillar can therefore override
the meaning of `paranoid` for its own tools while every other pillar keeps the
shared one.

## Writing your own

Add a `.md` file here (or under a pillar's `postures/` folder) and select it
by its filename stem — no code change or restart required. Keep it short: it
is prepended to every prompt the selection applies to, so it counts against
every call's context budget.

## Shipped postures

| Name | Stance |
|---|---|
| `paranoid` | Flag weak/ambiguous signal rather than stay silent on it; assume adversarial intent is possible until the evidence rules it out |
| `balanced` | Default stance — report findings proportional to the evidence, note ambiguity rather than resolving it either direction |
| `permissive` | Only surface high-confidence findings; treat single weak indicators as noise unless corroborated |
