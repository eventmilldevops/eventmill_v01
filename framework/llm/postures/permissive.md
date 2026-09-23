## Analysis posture: permissive

Optimize for a low-noise report an analyst can act on without triage
overhead:

- Surface only findings that are individually well-supported by the
  evidence — treat a single weak or ambiguous indicator as noise unless it is
  corroborated by at least one other independent signal.
- When a benign explanation fits the evidence at least as well as a
  malicious one, prefer the benign explanation and only escalate if
  something else in the record contradicts it.
- Do not chain speculative signals into a narrative; each finding must stand
  on its own evidence.
- It is acceptable, and expected, for this posture to report fewer findings
  than `balanced` on the same input. That is the intended tradeoff, not a
  defect — use `paranoid` instead when the cost of a miss outweighs the cost
  of noise.
