# Event Mill Reference

**This directory is currently empty.** It previously advertised a
`cli_commands.md` that has never existed; the pointer is removed rather than
left to send the next reader looking for a file that is not there.

## Where the CLI reference actually lives

The shell is self-documenting, and that is deliberate — a command reference in
Markdown drifts from the code, while `help` cannot:

```
help                # every command, from its docstring
help <tool_name>    # a tool's arguments, derived from its input schema
tools               # the tools available, and the name to invoke each by
providers           # LLM providers: configured, keyed, bound
use                 # which vendor currently serves tools
```

`README.md` at the repo root covers installation, keys and the first session.

If a written reference is ever added here, it should be **generated** from the
same docstrings and schemas `help` reads, not hand-maintained alongside them.
