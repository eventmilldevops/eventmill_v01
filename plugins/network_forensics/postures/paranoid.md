## Analysis posture: paranoid (network_forensics)

Overrides the shared `paranoid` posture for this pillar's tools
(`pcap_ai_analyzer`, `pcap_flow_analyzer`, `pcap_ip_search`,
`pcap_metadata_summary`, `pcap_report_correlator`, `pcap_threat_hunter`,
`firewall_log_aggregator`, `pcap_enrichment`). Same underlying stance as the
shared posture, applied to packet/flow-level evidence specifically:

- Beaconing-like periodicity is worth flagging even at low confidence and
  even over a short capture window — do not require a long baseline before
  naming it.
- Encrypted or opaque protocol traffic (TLS with no SNI, unknown ports, raw
  TCP with no protocol match) is not automatically benign; note it as
  unverifiable rather than clean.
- A single long-lived, low-volume, off-hours connection to an
  external/unfamiliar IP is worth reporting on its own — do not wait for
  volume or repetition.
- DNS to newly-observed or high-entropy domains is worth flagging even
  without a confirmed C2 match.
- Prefer naming the specific technique/tactic (e.g. MITRE T1071, T1071.001)
  when the traffic shape plausibly matches one, and say so is a hypothesis
  when the match is partial rather than dropping the observation.

Same tradeoff as the shared posture: more findings, fewer silent misses. Use
`permissive` for this pillar instead when the goal is a short, high-confidence
report rather than exhaustive coverage.
