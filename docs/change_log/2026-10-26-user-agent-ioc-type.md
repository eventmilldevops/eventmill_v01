# 2026-10-26 — `user_agent` is an IOC type, on by default

Asked for by the operator after the first live `--url` run, on the Microsoft
Storm-0940 post: its IOC table lists five user agents beside the six IPs, and
the ingester had no type for them, so they were never candidates and never
reached the result.

## The change

- **`user_agent` in `IOC_PATTERNS`**, in two shapes:
  - a browser string taken **whole**, from `Mozilla/` to the end of the line
    or table cell, so its `AppleWebKit/…`, `Chrome/…` and `Safari/…` tokens
    are not offered as four separate indicators;
  - a tool or library string, `name/version` with a **dotted** version
    (`python-requests/2.31.0`, `curl/7.88.1`, `azure-toolkit/1.0`).
  Protocol versions (`HTTP/1.1`, `TLS/1.2`, `SMB2/2.1`, …) and URL path
  segments (`/api/2.0`) are excluded. What else fits the shape is left to the
  model, which is how every other type works.
- **On by default**: the default `ioc_types` is now ip, domain, hash_sha256,
  url, cve, **user_agent**, mitre_technique — in the code, the input schema,
  the README and the starter guide. `hash_md5`, `hash_sha1` and `email` stay
  opt-in; the schema's old description ("if omitted, all supported types are
  extracted") said otherwise and was corrected.
- `validate_inputs` now accepts exactly the keys of `IOC_PATTERNS` instead of a
  second hand-kept list, and a test holds the input schema's enum to the same
  set, so a type cannot be added in one place and refused in another.
- The model's `ioc_type` is normalised when it spells this one differently
  ("User Agent", "user-agent"): otherwise one string would become two entities
  in the merge, which keys on `(ioc_type, value)`. Other types are untouched.
- Output schema: `user_agent` added to the `ioc_type` enum.

## Why

User agents are what a defender actually searches proxy, sign-in and Graph
audit logs for, and threat reports list them as indicators — this one in the
same table as the IPs. Two shapes rather than one generic `name/version` rule:
a generic rule offers a browser string as four candidates, none of which is
the indicator, and every candidate costs ~70 output tokens and counts toward
the batching budget. The dotted-version requirement is what keeps `T1078/004`
and dates out.

## Verified

- On the Microsoft page (live fetch, converted Markdown): exactly the five user
  agents in its IOC table — `Python-urllib/3.12`, `python-requests/2.31.0`,
  `python-requests/2.34.2`, `curl/7.88.1`, `azure-toolkit/1.0` — and no other
  `user_agent` candidate. Candidates for the page: 6 ip, 5 user_agent,
  10 mitre_technique.
- `test_user_agent.py`: the shapes above, eight non-matches (protocols, paths,
  technique ids, dates, `Windows NT 10.0`, versionless `curl/8`), no match
  across a line, schema/default/validation agreement, the type normalisation,
  and an IOC table converted from HTML. The ingester suite passes (428 with the
  framework document tests).

## Not verified

- No live model run with the new candidates. Whether a model keeps
  `[user_agent]` as the type and does not reject a library version string as
  "a benign version number" (the prompt's own wording) is what the next live
  run on the same URL should show.
- A browser string wrapped across lines — common in PDF text — is captured only
  up to the line break.

## Note for the existing PDF path

The default changed for every input, not only `--url`: a PDF that names user
agents now offers them as candidates too, which adds output to its calls and
can, on an indicator-dense document, add a batch.
