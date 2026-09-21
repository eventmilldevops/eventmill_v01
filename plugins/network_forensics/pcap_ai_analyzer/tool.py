"""
PCAP AI Analyzer — AI-enhanced PCAP analysis with Condition Orange support.

Ported from Event Mill v1.0 pcap_hunting.py (ai_hunt_*) and system_context.py
(PCAP prompt tiers) with improvements:
- Conforms to EventMillToolProtocol
- Three prompt tiers: triage, threat_hunt, reporting
- Condition Orange toggle modifies LLM analysis posture
- Uses LLMQueryInterface from ExecutionContext (not direct Gemini calls)
- Structured JSON output with both static and AI sections
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("eventmill.plugins.pcap_ai_analyzer")


@dataclass
class ToolResult:
    ok: bool
    result: dict[str, Any] | None = None
    error_code: str | None = None
    message: str | None = None
    output_artifacts: list[str] | None = None
    details: dict[str, Any] | None = None


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] | None = None


# ---------------------------------------------------------------------------
# PCAP System Identity (shared across all prompt tiers)
# ---------------------------------------------------------------------------

PCAP_SYSTEM_IDENTITY = """SYSTEM IDENTITY:
You are an AI-powered Network Forensics Analyst working within a Security Operations Center (SOC).

CRITICAL UNDERSTANDING:
- You are analyzing PARSED metadata from network traffic captures (PCAP files).
- These are EXPORTED captures, not live traffic. You cannot interact with the network.
- Your analysis is based on statistical summaries, not raw packet payloads.
- You can only READ and ANALYZE — you CANNOT take remediation actions.

CALIBRATION:
- Most network captures contain NORMAL traffic. Do not manufacture threats from benign patterns.
- Only rate a finding CRITICAL if there is clear, specific evidence (e.g., known C2 port + beaconing
  pattern + external destination). Vague suspicion is not CRITICAL.
- It is perfectly acceptable — and expected — to conclude that a capture shows normal activity.
- Severity ratings: CRITICAL = confirmed malicious indicators, HIGH = strong anomalies needing
  investigation, MEDIUM = unusual but explainable, LOW = minor observations, INFO = normal.

YOUR ROLE:
1. ANALYZE: Review network patterns and flows for genuine anomalies.
2. CORRELATE: Connect indicators across DNS, HTTP, TLS, and flow data.
3. PRIORITIZE: Rank findings by severity with clear justification. If nothing is suspicious, say so.
4. RECOMMEND: Suggest specific next steps for human analysts to execute.

ORGANIZATION IP CLASSIFICATION RULE:
- The investigation context may list KNOWN ORGANIZATION IP RANGES. These are public IP
  addresses owned by the organization (e.g., partner links, monitoring feeds, WAN endpoints).
- IPs within these ranges MUST be classified as INTERNAL/ORG — NOT external.
  Do NOT flag traffic from these IPs as external threats or suspicious.
- Only flag IPs that are BOTH outside RFC1918 AND outside the listed organization ranges.
- Label organization IPs as "ORG" not "EXT" in your analysis.
"""

# ---------------------------------------------------------------------------
# OT / ICS System Identity
# ---------------------------------------------------------------------------

PCAP_OT_SYSTEM_IDENTITY = """SYSTEM IDENTITY:
You are an AI-powered OT/ICS Network Forensics Analyst specializing in Industrial Control System
security within a Critical Infrastructure Security Operations Center.

CRITICAL UNDERSTANDING:
- You are analyzing PARSED metadata from network traffic captures (PCAP files) containing
  Operational Technology (OT) and Industrial Control System (ICS) protocols.
- These are EXPORTED captures, not live traffic. You cannot interact with the control network.
- Your analysis covers both IT protocols traversing the OT network AND native ICS protocols
  (Modbus/TCP, DNP3, S7comm, EtherNet/IP-CIP, OPC-UA, BACnet, IEC-104, etc.).
- OT networks have DIFFERENT baselines than IT: predictable polling cycles, fixed device roles,
  minimal DNS, rare new connections. Any deviation is significant.
- You can only READ and ANALYZE — you CANNOT take remediation actions.

YOUR ROLE:
1. ANALYZE: Identify anomalous OT protocol behavior — unauthorized writes, unexpected function
   codes, rogue devices, polling disruptions, and IT-to-OT zone crossover traffic.
2. CORRELATE: Connect indicators across ICS protocols, cleartext credentials, network flows,
   and any IT traffic on the OT segment.
3. ASSESS: Evaluate potential SAFETY IMPACT — can the observed activity affect physical
   processes (valve positions, breaker states, setpoints, safety instrumented systems)?
4. REFERENCE: Map findings to MITRE ATT&CK for ICS framework (not Enterprise).
5. RECOMMEND: Suggest specific next steps aligned with IEC 62443 zones/conduits model.

KEY OT SECURITY PRINCIPLES:
- The Purdue Model defines network segmentation levels (0-5). Traffic crossing levels
  (especially Level 3 IT → Level 1/0 control) is inherently suspicious.
- In OT, AVAILABILITY and SAFETY outweigh confidentiality. A write to a safety PLC register
  is more critical than data exfiltration.
- Many ICS protocols have NO authentication by design (Modbus, older DNP3, BACnet).
  Unauthorized access is trivial — the question is whether it happened.
- Cleartext credentials on OT networks are a severe finding — they enable lateral movement
  from IT to safety-critical systems.

ORGANIZATION IP CLASSIFICATION RULE:
- The investigation context may list KNOWN ORGANIZATION IP RANGES. These are public IP
  addresses owned by the organization (e.g., partner links, AESO monitoring, SCADA WAN,
  PCS process control networks, VPN endpoints).
- IPs that fall within these ranges MUST be classified as INTERNAL/ORG — NOT external.
  Do NOT flag traffic from these IPs as "external-to-internal" zone violations.
- Only flag traffic from IPs that are BOTH outside RFC1918 AND outside the listed
  organization ranges as truly external.
- When referencing organization IPs, label them as "ORG (organization-owned)" not "EXT".
"""

# ---------------------------------------------------------------------------
# Prompt templates (three tiers)
# ---------------------------------------------------------------------------

TRIAGE_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a SOC Analyst conducting initial triage on a parsed network traffic capture.

CRITICAL MINDSET RULES:
- Be highly objective. Base conclusions on clear evidence, not speculation.
- Normal enterprise traffic patterns are NOT findings. Do not flag routine DNS, LDAP, SMB,
  or Kerberos traffic as suspicious without specific anomaly indicators.
- A clean report with no findings is a valid and professional outcome.
- Distinguish between confirmed threats and theoretical risks. Only escalate confirmed threats.
- Consider benign explanations first: scheduled tasks, software updates, legitimate scans,
  backup jobs, and monitoring tools all generate traffic that can look suspicious.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. THE BASELINE CHECK: Review the 'Top Talkers' and flow indicators. Identify any genuinely
   anomalous patterns (unusual port usage, unexpected internal-to-internal communication,
   data exfiltration spikes). Normal enterprise traffic patterns are not findings.
2. C2 BEACONING HUNTER: Look for indicators of Command and Control beaconing —
   repetitive connections to external IPs, uniform payload sizes, consistent intervals
   over ports 80/443 or unusual high-numbered ports. Regular web browsing is NOT beaconing.
3. PRIORITIZATION: Rank up to 3 findings by severity (Critical/High/Medium/Low/Info).
   If there are fewer than 3 notable findings, report fewer. If nothing is suspicious,
   state clearly: "No significant security concerns identified."
4. NEXT STEPS: Recommend next steps only if warranted by findings. If traffic is normal,
   say so.

Keep response concise, prioritized, and action-oriented.

End with:
⚡ TL;DR
- One-line overall assessment (can be "Normal traffic, no concerns" if appropriate)
- Bullet points ONLY for findings that warrant analyst attention
"""

THREAT_HUNT_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a proactive Threat Hunter analyzing parsed PCAP data for advanced persistent threats (APTs)
or stealthy network intrusions.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. MITRE ATT&CK MAPPING: Map observed behavior to MITRE ATT&CK Tactics and Techniques (with IDs).
   Provide brief justification for each mapping.
2. HYPOTHESIS GENERATION: Formulate three (3) distinct hypotheses about attacker objectives
   (e.g., "Hypothesis 1: Data Exfiltration via DNS Tunneling").
3. EVIDENCE GATHERING: For each hypothesis, state what secondary logs the analyst should query
   to confirm or deny (e.g., Windows Event Logs, AD auth logs, application logs).

End with:
⚡ TL;DR
- One-line overall assessment
- Bullet points ONLY for hypotheses supported by evidence
"""

REPORTING_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a Senior Incident Responder preparing documentation for the SOC.

CRITICAL MINDSET RULES:
- Reports must be factual and evidence-based. Do not speculate or inflate severity.
- Clearly separate confirmed findings from theoretical risks.
- If no significant threats were found, state that clearly — a clean report is professional.
- Only list IoCs that have actual supporting evidence in the PCAP data.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. EXECUTIVE SUMMARY: Concise shift handover note summarizing traffic scope and critical findings.
2. INDICATORS OF COMPROMISE (IoCs): Extract all potential IoCs as:
   [Type (IP/Domain/Port)] | [Value] | [Context/Reason for suspicion]
   Exclude standard RFC 1918 IPs unless confirmed internal lateral movement source.
3. IMMEDIATE ACTIONS: Clear next steps for the incoming analyst or IR team.
4. LIMITATION CAVEATS: What cannot be determined from this parsed PCAP data alone.

Format as a professional shift-handover report.

End with:
⚡ TL;DR
- One-line overall assessment
- Bullet points ONLY for genuinely urgent items
"""

# ---------------------------------------------------------------------------
# OT / ICS Prompt templates
# ---------------------------------------------------------------------------

OT_TRIAGE_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}
CURRENT TASK:
You are an OT Security Analyst conducting initial triage on a network capture from an
industrial control system (ICS) / SCADA environment.

CRITICAL MINDSET RULES:
- Be highly objective. Do not assume "compromise", "attack", or "malice" without definitive proof.
- In OT, misconfigurations, hardware failures, and network loops are overwhelmingly more common than cyberattacks. You must consider these benign operational causes.
- Separate observable facts in the PCAP from hypotheses.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. OT PROTOCOL BASELINE: Review ICS protocol transactions (Modbus, DNP3, S7, CIP, OPC-UA,
   BACnet, IEC-104). Identify unexpected function codes, write operations from unusual sources,
   diagnostic/restart commands, and exception responses. (Be sure to correctly identify protocol
   roles, e.g., master vs. slave, based on traffic flow).
2. ZONE VIOLATION CHECK: Identify any traffic crossing Purdue Model boundaries — IT subnet
   IPs communicating with control network devices, external IPs reaching ICS ports, or
   unexpected internal-to-internal OT lateral movement.
3. CREDENTIAL EXPOSURE: Review cleartext credential detections. Assess severity based on
   which protocols and which network segments are affected. Flag any credentials that could
   enable IT-to-OT pivot.
4. DEVICE INVENTORY ANOMALY: Check for rogue devices — IPs that appear as OT protocol
   sources/destinations but seem unusual (e.g., workstation IPs sending Modbus writes).
5. PRIORITIZATION: Rank the top 3 findings by severity using OT-specific criteria (Note: You
   must evaluate whether anomalies are malicious OR benign operational failures/misconfigurations):
   - CRITICAL: Direct process impact risk (unauthorized writes to PLCs, safety system commands)
   - HIGH: Zone violations, credential exposure, unauthorized access to ICS protocols
   - MEDIUM: Reconnaissance activity, unusual polling patterns, malfunctioning devices
   - LOW: Minor anomalies, informational
6. SAFETY ASSESSMENT: Assess the risk to the physical process. State clearly whether the
   evidence points to intentional physical process manipulation, or if it is more likely a
   benign operational issue (e.g., failed device, misconfiguration, network error).

End with:
⚡ TL;DR
- One-line safety/risk verdict (Must be objective: explicitly state if the cause appears malicious or operational/benign)
- Top 1-3 bullet points: most critical OT-specific findings (Stick strictly to observable facts, not assumptions)
"""

OT_THREAT_HUNT_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are an OT Threat Hunter analyzing parsed PCAP data for ICS-targeted intrusions,
state-sponsored ICS attacks (TRITON/TRISIS, Industroyer, PIPEDREAM/INCONTROLLER patterns),
or insider threats targeting operational technology.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. MITRE ATT&CK FOR ICS MAPPING: Map observed behavior to MITRE ATT&CK for ICS Tactics and
   Techniques (use ICS-specific technique IDs like T0803, T0855, T0836, etc.).
   Key tactics to evaluate:
   - Initial Access (T0819, T0886) — IT-to-OT pivot evidence
   - Execution (T0807, T0823) — Command execution on controllers
   - Inhibit Response Function (T0803, T0804, T0816) — Safety system manipulation
   - Impair Process Control (T0836, T0855) — Setpoint changes, unauthorized writes
   - Collection (T0801, T0802) — Process data gathering/reconnaissance
2. ATTACK PATTERN MATCHING: Compare observed traffic patterns against known ICS attack
   playbooks:
   - TRITON/TRISIS: Safety Instrumented System (SIS) communication anomalies
   - Industroyer: IEC-104 unauthorized commands to breaker controls
   - PIPEDREAM/INCONTROLLER: Multi-protocol reconnaissance + targeted writes
   - Stuxnet-style: Legitimate-looking writes with subtly modified values
3. HYPOTHESIS GENERATION: Formulate three (3) hypotheses about attacker objectives
   specific to OT (e.g., "Hypothesis 1: Process Disruption via Unauthorized Modbus
   Register Writes", "Hypothesis 2: Safety System Bypass via S7 PLC Stop Command").
4. EVIDENCE GAPS: What additional data sources would confirm/deny each hypothesis?
   (Engineering workstation logs, historian data, change management records, physical
   process readings)

End with:
⚡ TL;DR
- One-line safety/risk verdict
- Top 1-3 bullet points: most critical OT hypotheses and next checks
"""

OT_REPORTING_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a Senior OT Incident Responder preparing documentation for the OT Security Team
and Plant Operations.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. EXECUTIVE SUMMARY: Concise summary for both cybersecurity leadership AND plant operations
   management. Include potential SAFETY IMPACT assessment.
2. OT-SPECIFIC IoCs: Extract all potential indicators as:
   [Type] | [Value] | [OT Context/Risk]
   Include: unauthorized ICS protocol sources, suspicious function codes, write targets,
   credential exposure, zone violations.
3. PROCESS SAFETY ASSESSMENT:
   - Were any writes detected to safety-critical registers or PLCs?
   - Were any PLC stop/start/restart commands observed?
   - Were any diagnostic/firmware commands detected?
   - Could observed activity affect Safety Instrumented Systems (SIS)?
4. IMMEDIATE ACTIONS (prioritized for OT):
   - Process safety actions (verify physical process state)
   - Network containment (isolate without disrupting running processes)
   - Forensic preservation (controller backups, historian snapshots)
5. IEC 62443 COMPLIANCE: Which security levels (SL) and zones are affected?
6. LIMITATION CAVEATS: What cannot be determined from parsed PCAP alone.

Format as a professional OT incident report suitable for both CISO and Plant Manager.

End with:
⚡ TL;DR
- One-line safety verdict
- Top 1-3 bullet points: most urgent safety/security actions
"""

PCAP_NETOPS_SYSTEM_IDENTITY = """SYSTEM IDENTITY:
You are an AI-powered Network Operations Analyst specializing in network health, performance,
and infrastructure troubleshooting.

CRITICAL UNDERSTANDING:
- You are analyzing PARSED metadata from network traffic captures (PCAP files).
- These are EXPORTED captures, not live traffic. You cannot interact with the network.
- Your focus is OPERATIONAL HEALTH — not security threats. You are looking for network
  performance issues, misconfigurations, infrastructure problems, and service degradation.
- You can only READ and ANALYZE — you CANNOT take remediation actions.

YOUR ROLE:
1. DIAGNOSE: Identify network performance issues — packet loss, retransmissions, congestion,
   latency indicators, MTU problems, routing anomalies, and DNS failures.
2. BASELINE: Assess whether traffic patterns indicate a healthy or degraded network.
3. CAPACITY: Identify bandwidth hogs, overloaded links, and capacity planning concerns.
4. RECOMMEND: Suggest specific infrastructure fixes, configuration changes, or monitoring
   improvements for network engineers to implement.

KEY NETWORK OPS PRINCIPLES:
- TCP retransmissions indicate packet loss or network congestion.
- TCP RST directionality matters: If the CLIENT is sending RSTs (RSTs from the
  ephemeral-port side), do not assume the server is offline. This indicates
  client-side application aborts — the app is timing out or receiving out-of-
  sequence data and closing the connection. If the SERVER sends RSTs (from the
  well-known port side), the service is rejecting connections (port closed,
  service down, or connection limit reached).
- TCP zero-window events indicate receiver buffer exhaustion (application or host overload).
- ICMP Destination Unreachable messages indicate routing problems or blocked services.
- ICMP Time Exceeded (TTL) indicates routing loops or misconfigured hop counts.
- High IP fragmentation suggests MTU mismatches across network paths.
- Asymmetric traffic ratios may indicate link saturation or path asymmetry.
- Unusual TTL distributions can reveal misconfigured devices or unexpected routing paths.
- DNS failures and timeouts directly impact application availability.
- Long-lived connections to standard service ports may indicate stuck sessions or keepalive issues.

ROUTING LOOP DETECTION:
- Routing loops occur when packets cycle between routers indefinitely until TTL expires.
- Three detection methods are used:
  1. ICMP TTL Exceeded analysis: When multiple different routers generate TTL Exceeded
     for packets destined to the same IP, those routers form the loop path.
  2. Duplicate IP ID detection: The same packet (identified by IP ID) captured with
     different TTL values means it passed the capture point multiple times while looping.
     The TTL spread reveals the number of hops in the loop cycle.
  3. TTL Exceeded rate: A rate above 0.1% of total traffic is abnormal and suggests
     routing instability. Normal, well-routed networks produce near-zero TTL Exceeded.
- When interpreting loop evidence, consider: OSPF/EIGRP route redistribution, static route
  conflicts, spanning-tree failures, and asymmetric routing as common root causes.

ARP HEALTH ANALYSIS:
- ARP is Layer 2 — it operates below IP and reveals switch/VLAN-level health.
- DHCP exception: Source IP 0.0.0.0 in ARP is normal DHCP initialization (DHCP
  DISCOVER/Request before an IP is assigned). Ignore 0.0.0.0 when evaluating
  IP address conflicts or ARP anomalies — multiple MACs using 0.0.0.0 is expected.
- ARP storms (>100 ARP/s sustained) typically indicate a Layer 2 loop (spanning-tree
  failure) or broadcast storm. This is a CRITICAL finding.
- IP address conflicts (same IP, multiple MACs) cause intermittent connectivity loss
  and are notoriously hard to diagnose without PCAP evidence.
- Gratuitous ARP floods typically indicate VRRP/HSRP/GLBP failover events or
  MAC table instability. Check if the MACs belong to known gateway pairs.
- High request/reply ratio (>5:1) suggests many dead or unreachable hosts, a subnet
  misconfiguration, or a device scanning for available addresses.
- ARP >5% of total traffic is abnormal for production networks.

CONTROL PLANE & TOPOLOGY ANALYSIS:
- STP (Spanning Tree Protocol):
  - BPDUs are normal L2 control frames; their RATE matters, not mere presence.
  - PVST+ (Per-VLAN Spanning Tree Plus): Cisco switches run a separate STP instance
    per VLAN. Each VLAN has its own root bridge ID = (priority + VLAN ID) : MAC.
    Multiple root bridge IDs with the SAME MAC but different priorities are NOT root
    instability — they are per-VLAN STP instances (normal PVST+ behavior).
    True root instability requires different MACs competing within the SAME VLAN.
  - If the display says "stable, PVST+" it means one switch is root for all VLANs.
  - Root Change Events are PVST+-aware: only flagged when the root MAC changes
    within a single VLAN, not when switching between VLAN instances.
  - RSTP vs Legacy STP: In RSTP (802.1w) and MSTP (802.1s), topology changes
    are signaled via the TC flag (bit 0) in standard Rapid BPDUs (Type 0x02),
    NOT via dedicated TCN BPDUs (Type 0x80). Look at TC flag count, not just TCN
    count, to assess topology change activity in modern networks.
  - MSTP awareness: If MSTP is running (version=3), the CIST (Common Internal
    Spanning Tree) root is shared, with per-MSTI (instance) parameters.
    Different MSTI parameters do NOT mean the switch is flapping.
  - BPDU STARVATION is the most critical STP failure mode. If a port was
    receiving BPDUs every 2s (hello) and suddenly stops receiving for >max_age
    (default 20s), the port ages out STP info and transitions to Forwarding.
    This causes a BRIDGING LOOP. The display flags gaps exceeding max_age with
    exact timestamps and affected source MACs. Treat any BPDU starvation as
    CRITICAL — investigate the upstream switch (CPU spike, link failure,
    unidirectional fiber, software hang).
  - MAC MISMATCH: If the Ethernet source MAC differs from the BPDU bridge MAC
    (beyond last-octet port offsets), this indicates potential BPDU spoofing
    (e.g. Yersinia), a misconfigured transparent bridge, or packet crafting.
    Flag as a SECURITY concern.
  - TCN BPDUs signal L2 topology changed — port up/down, device joined/left.
    Occasional TCNs are normal; floods (>10/min) = port flapping or cable issues.
  - TC flag in Config BPDUs triggers MAC table aging acceleration across bridges.
    Many TC flags = many topology changes = network instability.
  - TCA (Topology Change Acknowledgment) = root bridge acknowledging TCN receipt.
  - BPDU rate context: Use the per-port-per-VLAN rate, NOT the aggregate rate,
    when evaluating STP storms. In PVST+, each port sends 1 BPDU per VLAN per
    hello interval (2s). An aggregate 11.5 BPDU/s across 23 ports × 5 VLANs =
    0.1 BPDU/s per port/VLAN, which is perfectly normal. Only flag STP storms
    if the per-port-per-VLAN rate exceeds 1.0 BPDU/s.
  - RSTP Proposal/Agreement counts show port negotiation — high counts = flapping.
  - Port Roles (Root/Designated/Alternate/Backup) reveal the topology structure.
  - Port States (Forwarding/Learning/Blocking) — many Blocking = redundant paths,
    many Learning = topology converging, Forwarding = stable.
  - Path Cost changes for a bridge over time indicate link speed changes or failover.
  - VLANs from System ID Extension show which VLANs have STP instances.
  - Source switch MACs identify which physical switches are participating.
  - Non-standard timer values (hello ≠ 2s, max_age ≠ 20s, fwd_delay ≠ 15s)
    indicate custom tuning — may be intentional or misconfiguration.
  - TC event bursts (clusters of TC flags within seconds) = active instability.
  - When STP instability IS detected, identify: (1) TRIGGER — which MAC/port
    initiated the change, (2) BLAST RADIUS — isolated to one VLAN or all,
    (3) NEXT STEP — specific switch/port to investigate.
- HSRP (Hot Standby Router Protocol):
  - HSRP state transitions (Standby→Active or Active→Standby) represent gateway
    failover events. Each transition causes brief traffic disruption for hosts
    using that HSRP virtual IP as their default gateway.
  - Rapid state oscillation (multiple transitions in seconds) indicates a flapping
    peer, WAN link instability, or HSRP timer misconfiguration.
  - Multiple groups are normal in multi-VLAN environments.
- VRRP (Virtual Router Redundancy Protocol):
  - Similar to HSRP but standards-based. Priority changes trigger master election.
  - Priority 255 means the VRRP router owns the virtual IP (it's the IP owner).
  - Priority drops from 255 indicate the IP owner is relinquishing mastership.
- OSPF (Open Shortest Path First):
  - Hello packets maintain neighbor adjacencies. A gap exceeding the Dead Interval
    (default 40s) means the neighbor was declared dead — adjacency reset.
  - LS Update bursts (>10/5s) indicate link flapping or route recalculation (SPF).
    This causes network-wide reconvergence and potential micro-loops.
  - DB Description and LS Request packets appear during initial adjacency formation
    or adjacency reset — many of these suggest neighbors are re-syncing.
  - Multiple areas and many router IDs help map the OSPF topology.
- EIGRP (Enhanced Interior Gateway Routing Protocol):
  - Queries indicate a route went ACTIVE (lost). High query counts suggest routes
    are frequently being recalculated.
  - Stuck-In-Active (SIA): if queries exceed 3 minutes without replies, EIGRP
    resets the neighbor adjacency. Look for high Query counts with low Reply counts.
  - Update packets carry route changes; elevated Update/Hello ratio indicates
    active topology changes rather than steady-state operation.

ORGANIZATION IP CLASSIFICATION RULE:
- The investigation context may list KNOWN ORGANIZATION IP RANGES. These are public IP
  addresses owned by the organization (e.g., partner links, AESO monitoring, SCADA WAN).
- IPs within these ranges MUST be classified as INTERNAL/ORG — NOT external.
- Label organization IPs as "ORG" not "EXT" in your analysis.
"""

# ---------------------------------------------------------------------------
# Network Operations Prompt templates (three tiers)
# ---------------------------------------------------------------------------

NETOPS_TRIAGE_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a Network Operations analyst performing initial health assessment on a parsed
network traffic capture.

CRITICAL MINDSET RULES:
- Be objective. Not every retransmission is a problem — WAN links routinely see 0.5-1%.
- Consider normal operational causes: scheduled backups, patch windows, legitimate network
  scans (vulnerability scanners, asset discovery), and monitoring tools.
- A healthy network report is a valid and professional outcome. Do not manufacture issues.
- RSTs are normal in enterprise networks — applications close connections, firewalls enforce
  policy, load balancers health-check. Only flag RST patterns that indicate actual service
  degradation or failure.
- ARP patterns vary by network size and architecture. Small broadcast domains with active
  DHCP will naturally have higher ARP rates.
- STP topology changes (TCNs) during maintenance windows or device reboots are expected.
  Only flag sustained or unexplained control plane instability.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. NETWORK HEALTH BASELINE: Review TCP health indicators (retransmissions, RSTs,
   zero-window events). Calculate retransmission rate as a percentage of total TCP packets.
   Rate the overall network health: HEALTHY (<1% retransmit), DEGRADED (1-5%),
   or CRITICAL (>5%).
2. CONNECTION FAILURE ANALYSIS: Review RST patterns. Identify which services or hosts
   are generating the most connection resets. Distinguish between:
   - Client-side RSTs (application crashes, timeouts)
   - Server-side RSTs (service down, port blocked, connection limits)
   - Firewall RSTs (security policy blocks)
3. ICMP ERROR ASSESSMENT: Analyze ICMP error messages for routing issues, unreachable
   hosts/services, and TTL expiry patterns that indicate routing loops.
4. ROUTING LOOP DETECTION: Review the loop detection evidence:
   - ICMP TTL Exceeded patterns: multiple routers generating TTL Exceeded for the same
     destination is a classic routing loop signature. Identify the router IPs involved.
   - Duplicate IP ID packets: the same packet seen with different TTL values means it
     was captured multiple times while bouncing between routers. The TTL spread indicates
     the hop count in the loop cycle.
   - Elevated TTL Exceeded rate: normal networks have near-zero TTL Exceeded traffic.
     Any sustained rate above 0.1% warrants investigation.
   If loops are detected, identify the likely routing boundary (subnet/VLAN) and suggest
   which routers to check for route table issues or redistribution loops.
5. TOP ISSUE RANKING: Rank the top 3 operational issues by impact:
   - CRITICAL: Active service outage, widespread packet loss, routing loops
   - HIGH: Significant performance degradation, congestion indicators
   - MEDIUM: Minor inefficiencies, configuration improvements needed
   - LOW: Informational, optimization opportunities
5. ARP HEALTH CHECK: Review ARP statistics for Layer 2 issues:
   - ARP storm indicators (rate, % of traffic)
   - IP address conflicts (same IP, multiple MACs) — identify affected IPs
   - Gratuitous ARP anomalies — correlate with VRRP/HSRP failover events
   - Unanswered ARP requests — dead hosts or wrong-subnet devices
6. CONTROL PLANE CHECK: Review STP, HSRP/VRRP, OSPF, and EIGRP sections:
   - STP: Check if root is "stable, PVST+" (normal per-VLAN instances) vs actual
     root changes (different MACs competing within same VLAN). Only flag root
     instability if Root Change Events are present — those are already PVST+-aware.
     TCN storms with zero root changes = port flapping, not root instability.
   - HSRP/VRRP: Any state transitions or priority changes? Each = a gateway failover.
   - OSPF: Any neighbor hello gaps exceeding dead interval? Any LSUpdate bursts?
   - EIGRP: Any queries (routes going ACTIVE)? High query count = convergence event.
   Summarize control plane health as STABLE / CONVERGING / UNSTABLE.
7. QUICK WINS: Recommend 2-3 immediate fixes a network engineer can implement.
8. SUBNET IMPACT: Review the Subnet Anomaly Summary table. Call out the top 3 most
   impacted /24 networks and explain what combination of indicators make them stand out.
   For each, identify the specific IPs contributing most to the anomaly score.

Keep response concise and action-oriented for NOC staff.

End with:
⚡ TL;DR
- One-line network health verdict
- Top 1-3 bullet points: most impactful operational issues
"""

NETOPS_HEALTH_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a Senior Network Engineer performing deep network health analysis on parsed
PCAP data to identify root causes of performance issues and infrastructure problems.

CRITICAL MINDSET RULES:
- Be objective and evidence-based. Quantify issues with actual numbers from the data.
- Not every anomaly requires action. Prioritize issues with measurable user or service impact.
- Consider normal operational baselines: enterprise networks have background retransmissions,
  periodic ARP bursts during DHCP renewals, and routine control plane chatter.
- Distinguish between transient events (brief convergence, maintenance) and persistent
  problems. Only persistent patterns warrant remediation recommendations.
- A healthy network finding is valid. Do not force issues where the data shows normal operation.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. TCP PERFORMANCE DEEP DIVE:
   - Retransmission analysis: Which flows have the highest retransmission rates?
     Are retransmissions concentrated on specific paths or distributed?
   - Zero-window analysis: Which hosts are running out of receive buffer? Is this
     an application-level issue (slow consumer) or host-level (memory pressure)?
   - RST analysis: Map RST sources to determine if resets are from applications,
     operating systems, or network devices (firewalls/load balancers).
   - SYN vs established ratio: Are there half-open connections indicating
     SYN floods, connection timeouts, or unresponsive services?
2. ROUTING AND PATH ANALYSIS:
   - TTL distribution: Group by expected hop counts (64, 128, 255 origins).
     Identify outlier TTL values that suggest unusual routing paths.
   - IP fragmentation: Assess fragmentation rate. If >1%, identify which flows
     are fragmenting and the likely MTU mismatch points.
   - ICMP redirect messages: Identify suboptimal routing being corrected.
3. ARP AND LAYER 2 HEALTH:
   - ARP storm detection: correlate ARP rate with traffic patterns. If ARP storm
     is detected alongside high broadcast traffic, this confirms a Layer 2 loop.
   - IP conflicts: for each conflicted IP, determine if the MACs belong to the
     same vendor (OUI lookup hint). Two different vendor MACs = true conflict.
     Same vendor MACs may indicate a virtualization issue (duplicate VM).
   - Gratuitous ARP patterns: if concentrated in short bursts, likely failover.
     If sustained, likely misconfiguration or device flapping.
   - Map unanswered ARP targets to subnet ranges to identify dead subnets.
4. DNS HEALTH:
   - Failed DNS lookups (queries without matching responses).
   - DNS response latency indicators.
   - Excessive DNS query volume from specific hosts (misconfigured resolvers,
     chatty applications, or DNS-based service discovery issues).
4. ROUTING LOOP ANALYSIS: If loop indicators are present, perform deep analysis:
   - Correlate TTL Exceeded sources (router IPs) to build a loop path diagram.
     E.g., "Router A (10.0.1.1) → Router B (10.0.2.1) → Router A" indicates a
     2-hop loop between those routers.
   - Examine the TTL spread on duplicate packets: a spread of N indicates an N-hop
     loop cycle. Decreasing TTL values confirm the direction of the loop.
   - Check if loops are persistent (continuous TTL Exceeded) or transient (burst
     during convergence). Transient loops during route changes are less critical.
   - Common root causes: OSPF/EIGRP redistribution loops, static route conflicts,
     spanning-tree loops (L2→L3 bleed), asymmetric routing with RPF failures,
     or misconfigured policy-based routing.
   - Estimate traffic impact: loop-affected packets consume bandwidth on every hop
     in the cycle until TTL expires.
5. CAPACITY AND UTILIZATION:
   - Top bandwidth consumers (flows, hosts, protocols).
   - Long-lived connections that may indicate stuck sessions.
   - Protocol distribution anomalies (unexpected protocol ratios).
6. CONTROL PLANE DEEP DIVE: If STP/HSRP/VRRP/OSPF/EIGRP data is present:
   - STP: The root bridge display is PVST+-aware. "Stable, PVST+" means one
     switch is root for all VLANs (normal). Only Root Change Events represent
     actual root instability (different MACs competing within same VLAN).
     Correlate TCN count with ARP storms — both together confirm L2 loop.
     If root bridge changed within a VLAN, estimate reconvergence time.
     Check if multiple bridges are contending for root (priority war).
   - HSRP/VRRP: Map state transitions to a timeline. Rapid oscillation (>3
     transitions/minute) indicates peer reachability issues (WAN flap, interface
     flap, or timer misconfiguration). Check if all group members are visible.
   - OSPF: Build neighbor adjacency map from Hello data. Identify dead neighbors
     (hello gaps >40s). Correlate LSUpdate bursts with topology events.
     Check for area mismatches if DB Description exchanges are failing.
   - EIGRP: Calculate Query/Reply ratio. If queries >> replies, suspect SIA
     condition. Map AS numbers to identify multi-AS boundary issues.
   - Cross-protocol correlation: STP TCN + HSRP failover + OSPF neighbor reset
     occurring together indicates a physical link failure cascading through all
     layers. Build a timeline of control plane events.
7. ROOT CAUSE HYPOTHESES: For each major issue found, propose the most likely
   root cause and what additional data (SNMP, syslog, interface counters) would
   confirm it.
8. SUBNET IMPACT ANALYSIS: Use the Subnet Anomaly Summary to identify the most
   impacted /24 networks. For each top-3 subnet:
   - What combination of indicators (RSTs, retransmissions, ICMP errors, loops,
     unanswered ARPs, IP conflicts) make it stand out?
   - Which specific IPs in that subnet are the primary contributors?
   - What is the likely root cause for that subnet specifically?
   - Could a single event (power outage, link failure, device reboot) explain
     the cluster of anomalies in that subnet?

End with:
⚡ TL;DR
- One-line network health verdict
- Top 1-3 bullet points: root causes and recommended fixes
"""

NETOPS_REPORT_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a Network Operations Manager preparing a network health report for the
infrastructure team and IT management.

CRITICAL MINDSET RULES:
- Be objective and professional. Management reports must not cry wolf.
- Only report issues that have measurable impact on service availability or performance.
- Healthy KPIs should be reported as healthy — do not qualify them with unnecessary caveats.
- Consider operational context: maintenance windows, growth patterns, and seasonal load
  variations before flagging capacity concerns.
- A network health grade of A or B is a positive outcome, not a reason to look harder for problems.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. EXECUTIVE SUMMARY: Concise overview of network health status suitable for
   IT management. Include overall health grade (A-F scale) with justification.
2. KEY PERFORMANCE INDICATORS:
   - TCP retransmission rate (% of total TCP packets)
   - Connection success rate (SYN vs RST ratio)
   - ICMP error rate
   - IP fragmentation rate
   - Zero-window event frequency
   - ARP storm rate (pkt/s) and ARP-to-traffic ratio
   - IP address conflict count
   - STP TCN count, root bridge stability (stable/changed)
   - HSRP/VRRP failover count
   - OSPF dead neighbor events, LSUpdate burst count
   - EIGRP query count, SIA risk level
   Present each KPI with: current value, typical healthy range, and status
   (GREEN/YELLOW/RED).
3. PROBLEM AREAS: For each identified issue (including routing loops and control
   plane events if detected):
   - Affected hosts/subnets (for loops: the router IPs involved and destinations affected)
   - Impact description (for loops: bandwidth waste, unreachable destinations, application
     timeouts caused by packets being dropped after TTL expiry)
   - Recommended remediation (for loops: specific routing protocol checks, route table
     verification commands, convergence timer adjustments)
   - For control plane issues: STP root bridge elections cause network-wide traffic
     blackout (30-50s with legacy STP). HSRP/VRRP failovers cause 1-10s disruption
     per VLAN. OSPF reconvergence causes micro-loops until SPF completes.
   - Priority (P1-P4) — active routing loops and root bridge changes are P1/P2
4. CONTROL PLANE HEALTH SUMMARY:
   - STP: Root bridge stability, TCN rate, bridge count
   - HSRP/VRRP: Failover events, group health, VIP availability
   - OSPF: Adjacency health, convergence events, area topology
   - EIGRP: Route stability, query volume, SIA risk
   - Control plane stability grade: STABLE / CONVERGING / UNSTABLE
5. CAPACITY PLANNING NOTES:
   - Top bandwidth consumers
   - Growth trends if visible from conversation patterns
   - Links or paths that appear near capacity
6. SUBNET IMPACT REPORT: Present the Subnet Anomaly Summary as a ranked table
   of the most impacted /24 networks. For each top subnet, summarize:
   - The primary anomaly indicators and their severity
   - Specific affected hosts and their role in the anomalies
   - Whether the anomaly cluster suggests a localized event (power outage,
     link failure, device reboot) vs. a systemic issue
7. RECOMMENDED MONITORING: What metrics should be continuously monitored
   based on issues found. Suggest specific SNMP OIDs, syslog patterns,
   or NetFlow fields to track.
8. LIMITATIONS: What cannot be determined from this PCAP capture alone.

Format as a professional network operations report.

End with:
⚡ TL;DR
- Network health grade (A-F)
- Top 1-3 bullet points: highest priority remediation items
"""

# Mode → (prompt_template, underlying_hunt_type, system_identity_override)
MODE_CONFIG: dict[str, tuple[str, str | None, str | None]] = {
    "triage_summary": (TRIAGE_PROMPT, None, None),
    "hunt_talkers": (TRIAGE_PROMPT, "talkers", None),
    "hunt_beacons": (THREAT_HUNT_PROMPT, "beacons", None),
    "hunt_dns": (THREAT_HUNT_PROMPT, "dns", None),
    "hunt_tls": (THREAT_HUNT_PROMPT, "tls", None),
    "hunt_lateral": (THREAT_HUNT_PROMPT, "lateral", None),
    "hunt_exfil": (REPORTING_PROMPT, "exfil", None),
    "report": (REPORTING_PROMPT, None, None),
    # OT / ICS modes
    "ot_triage": (OT_TRIAGE_PROMPT, None, PCAP_OT_SYSTEM_IDENTITY),
    "ot_threat_hunt": (OT_THREAT_HUNT_PROMPT, None, PCAP_OT_SYSTEM_IDENTITY),
    "ot_report": (OT_REPORTING_PROMPT, None, PCAP_OT_SYSTEM_IDENTITY),
    # Network Operations / Infrastructure Health modes
    "netops_triage": (NETOPS_TRIAGE_PROMPT, None, PCAP_NETOPS_SYSTEM_IDENTITY),
    "netops_health": (NETOPS_HEALTH_PROMPT, None, PCAP_NETOPS_SYSTEM_IDENTITY),
    "netops_report": (NETOPS_REPORT_PROMPT, None, PCAP_NETOPS_SYSTEM_IDENTITY),
}


# ---------------------------------------------------------------------------
# PDF export helper (fpdf2) — professional report renderer
# ---------------------------------------------------------------------------

# Unicode → ASCII replacements for PDF rendering with built-in fonts
_PDF_UNICODE_MAP = {
    "\u2014": "--",   # em dash
    "\u2013": "-",    # en dash
    "\u2018": "'",    # left single quote
    "\u2019": "'",    # right single quote
    "\u201c": '"',    # left double quote
    "\u201d": '"',    # right double quote
    "\u2022": "*",    # bullet
    "\u2026": "...",  # ellipsis
    "\u2192": "->",   # right arrow
    "\u2190": "<-",   # left arrow
    "\u2502": "|",    # box drawing vertical
    "\u2500": "-",    # box drawing horizontal
    "\u00d7": "x",    # multiplication sign
    "\u00b7": ".",    # middle dot
    "\u2212": "-",    # minus sign
    "\u00a0": " ",    # non-breaking space
    "\u2705": "[OK]",    # check mark
    "\u274c": "[X]",     # cross mark
    "\u25cf": "*",       # black circle
    "\u25cb": "o",       # white circle
    "\u25ba": ">",       # right pointer
    "\u00ab": "<<",      # left guillemet
    "\u00bb": ">>",      # right guillemet
}

# Sections that contain dense repetitive data — truncate after N visible lines
_DATA_HEAVY_SECTIONS = {
    "INTERNAL LATERAL MOVEMENT",
    "ICS PROTOCOL CROSS-ZONE TRAFFIC",
    "PORT SCAN PATTERNS",
    "UNKNOWN HIGH PORTS",
}
_DATA_SECTION_MAX_LINES = 20  # Show at most this many data lines per section


def _pdf_safe(text: str) -> str:
    """Convert Unicode text to ASCII-safe string for PDF built-in fonts."""
    for uc, repl in _PDF_UNICODE_MAP.items():
        text = text.replace(uc, repl)
    return text.encode("ascii", "ignore").decode("ascii")


# ---------------------------------------------------------------------------
# Purdue Model Zone Traffic Diagram (matplotlib + networkx)
# ---------------------------------------------------------------------------

# OT ports → Purdue level "SCADA" or "CONTROL/FIELD"
_SCADA_PORTS = {502, 102, 44818, 20000, 4840, 47808, 2404, 789, 1911, 9600, 18245}
# IT service ports → "Corporate"
_CORP_PORTS = {53, 88, 135, 139, 389, 445, 636, 3389, 5985, 5986}
# DMZ ports → "DMZ"
_DMZ_PORTS = {80, 443, 8080, 8443, 25, 587, 993, 995}

# Purdue zone definitions and visual layout
_PURDUE_ZONES = [
    ("External",      "#1a5276",  0.95),   # dark blue
    ("Corporate",     "#e67e22",  0.76),   # orange
    ("DMZ",           "#27ae60",  0.57),   # green
    ("SCADA",         "#8e44ad",  0.38),   # purple
    ("CONTROL/FIELD", "#2980b9",  0.19),   # blue
]

_ZONE_BG_COLORS = {
    "External":      "#d6eaf8",
    "Corporate":     "#fdebd0",
    "DMZ":           "#d5f5e3",
    "SCADA":         "#f4ecf7",
    "CONTROL/FIELD": "#d4efdf",
}


def _classify_ip_zone(ip: str, session: Any) -> str:
    """Classify an IP into a Purdue zone based on enrichment data or traffic patterns."""
    from plugins.network_forensics.pcap_metadata_summary.tool import is_internal

    # Priority 1: Use enrichment data if available (authoritative)
    try:
        from plugins.network_forensics.pcap_enrichment.tool import (
            get_enrichment_cache, get_field, get_field_mappings,
        )
        cache = get_enrichment_cache()
        if cache and ip in cache:
            row = cache[ip]
            mappings = get_field_mappings()

            # Use explicit purdue mapping if available, else try common column names
            purdue_val = get_field(ip, "purdue")
            if not purdue_val:
                # Fallback: try common column names when no explicit mapping
                for col in ("purdue_level", "purdue", "purdue_zone"):
                    v = row.get(col, "")
                    if v and str(v).strip():
                        purdue_val = str(v).strip()
                        break

            if purdue_val:
                purdue = purdue_val.lower()
                # Normalize enrichment values to our zone names
                purdue_map = {
                    "0": "CONTROL/FIELD", "1": "CONTROL/FIELD",
                    "2": "SCADA", "3": "SCADA",
                    "3.5": "DMZ", "dmz": "DMZ",
                    "4": "Corporate", "5": "External",
                    "control": "CONTROL/FIELD", "control/field": "CONTROL/FIELD",
                    "field": "CONTROL/FIELD",
                    "scada": "SCADA", "supervisory": "SCADA",
                    "corporate": "Corporate", "enterprise": "Corporate",
                    "external": "External", "internet": "External",
                }
                zone = purdue_map.get(purdue)
                if zone:
                    return zone
                # Try partial match
                for key, zone_name in purdue_map.items():
                    if key in purdue:
                        return zone_name

            # Use explicit zone mapping if available, else try common column names
            zone_val = get_field(ip, "zone")
            if not zone_val:
                for col in ("ot_network", "zone", "network_zone", "segment"):
                    v = row.get(col, "")
                    if v and str(v).strip():
                        zone_val = str(v).strip()
                        break

            if zone_val:
                ot_net = zone_val.lower()
                if "scada" in ot_net or "hmi" in ot_net:
                    return "SCADA"
                if "control" in ot_net or "field" in ot_net or "plc" in ot_net:
                    return "CONTROL/FIELD"
                if "dmz" in ot_net:
                    return "DMZ"
                if "corporate" in ot_net or "it" in ot_net or "enterprise" in ot_net:
                    return "Corporate"
    except ImportError:
        pass  # enrichment module not available — fall through to heuristics

    # Priority 2: Port-based heuristics (fallback)
    if not is_internal(ip):
        return "External"

    # Gather ports this IP connects TO (client) vs SERVES (server)
    dst_ports: set[int] = set()   # ports this IP connects to as client
    srv_ports: set[int] = set()   # ports this IP serves as server
    has_external_peer = False

    for (src, dst, dport, proto), stats in session.conversations.items():
        if src == ip:
            dst_ports.add(dport)
            if not is_internal(dst):
                has_external_peer = True
        if dst == ip:
            srv_ports.add(dport)
            if not is_internal(src):
                has_external_peer = True

    serves_ot = bool(srv_ports & _SCADA_PORTS)
    connects_ot = bool(dst_ports & _SCADA_PORTS)

    # OT classification
    if serves_ot and connects_ot:
        return "SCADA"          # bidirectional OT = HMI / gateway
    if serves_ot:
        return "CONTROL/FIELD"  # pure OT server / field device
    if connects_ot:
        # Initiates OT connections — OT workstation or IT user accessing OT
        non_ot = (dst_ports | srv_ports) - _SCADA_PORTS
        if non_ot & (_CORP_PORTS | _DMZ_PORTS):
            return "Corporate"  # IT user who also accesses OT
        return "SCADA"          # OT workstation / HMI

    # IT classification
    if srv_ports & _DMZ_PORTS:
        return "DMZ"            # serves web/mail ports

    return "Corporate"


def _render_purdue_zone_graph(session: Any) -> bytes | None:
    """Render a Purdue model zone traffic diagram as PNG bytes.

    Returns PNG image bytes or None if matplotlib is not available.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")  # headless backend
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        from io import BytesIO
    except ImportError:
        return None

    from plugins.network_forensics.pcap_metadata_summary.tool import is_internal

    # --- Classify all IPs into zones, then group by /24 network ---
    all_ips: set[str] = set()
    for (src, dst, dport, proto), stats in session.conversations.items():
        all_ips.add(src)
        all_ips.add(dst)

    ip_zones: dict[str, str] = {}
    for ip in all_ips:
        ip_zones[ip] = _classify_ip_zone(ip, session)

    # Group IPs into /24 networks and assign zone by majority vote
    from collections import Counter as _Counter
    network_ips: dict[str, list[str]] = {}  # "10.0.3" -> ["10.0.3.47", ...]
    for ip in all_ips:
        octets = ip.split(".")
        if len(octets) == 4:
            net = ".".join(octets[:3])
            network_ips.setdefault(net, []).append(ip)

    # Zone assignment per /24 — majority of IPs in that subnet
    net_zones: dict[str, str] = {}
    zone_nets: dict[str, list[str]] = {z[0]: [] for z in _PURDUE_ZONES}
    for net, ips in network_ips.items():
        zone_votes = _Counter(ip_zones[ip] for ip in ips)
        zone = zone_votes.most_common(1)[0][0]
        net_zones[net] = zone
        zone_nets[zone].append(net)

    # --- Aggregate traffic between /24 networks ---
    net_pair_bytes: dict[tuple[str, str], int] = {}
    for (src, dst, dport, proto), stats in session.conversations.items():
        src_net = ".".join(src.split(".")[:3])
        dst_net = ".".join(dst.split(".")[:3])
        if src_net == dst_net:
            continue  # skip intra-subnet
        pair = (min(src_net, dst_net), max(src_net, dst_net))
        net_pair_bytes[pair] = net_pair_bytes.get(pair, 0) + stats["bytes_out"]

    # Zone-to-zone aggregate for byte labels
    zone_flows: dict[tuple[str, str], int] = {}
    for (net_a, net_b), total_bytes in net_pair_bytes.items():
        z_a = net_zones.get(net_a, "External")
        z_b = net_zones.get(net_b, "External")
        if z_a == z_b:
            continue
        key = (z_a, z_b)
        zone_flows[key] = zone_flows.get(key, 0) + total_bytes

    if not zone_flows:
        return None

    max_bytes = max(zone_flows.values()) if zone_flows else 1

    # --- Draw the diagram ---
    fig, ax = plt.subplots(figsize=(10, 7))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_aspect("auto")
    ax.axis("off")
    fig.patch.set_facecolor("white")

    zone_y: dict[str, float] = {}
    zone_rects: dict[str, tuple[float, float, float, float]] = {}
    zone_height = 0.145
    zone_margin = 0.05

    # Draw zone boxes
    for zone_name, border_color, y_center in _PURDUE_ZONES:
        y_bottom = y_center - zone_height / 2
        bg_color = _ZONE_BG_COLORS[zone_name]

        rect = mpatches.FancyBboxPatch(
            (zone_margin, y_bottom), 1 - 2 * zone_margin, zone_height,
            boxstyle="round,pad=0.01",
            linewidth=2.5, edgecolor=border_color,
            facecolor=bg_color, alpha=0.6,
        )
        ax.add_patch(rect)

        # Zone label
        ax.text(zone_margin + 0.02, y_center + zone_height / 2 - 0.025,
                zone_name, fontsize=11, fontweight="bold",
                color=border_color, va="top")

        zone_y[zone_name] = y_center
        zone_rects[zone_name] = (zone_margin, y_bottom,
                                 1 - 2 * zone_margin, zone_height)

    # Place /24 network nodes within their zones
    node_positions: dict[str, tuple[float, float]] = {}
    for zone_name, _, y_center in _PURDUE_ZONES:
        nets = sorted(zone_nets[zone_name])
        if not nets:
            continue
        n = len(nets)
        max_show = min(n, 8)
        for i, net in enumerate(nets[:max_show]):
            x = 0.15 + (i + 0.5) * (0.7 / max_show)
            y = y_center
            node_positions[net] = (x, y)

            # Draw node dot
            ax.plot(x, y, "o", color="#2c3e50", markersize=6, zorder=5)
            # Network label: "10.0.3.x"
            label = net + ".x"
            ax.text(x, y - 0.022, label, fontsize=5.5,
                    ha="center", va="top", color="#2c3e50")

        if n > max_show:
            ax.text(0.9, y_center, f"+{n - max_show}",
                    fontsize=8, ha="center", va="center",
                    color="#7f8c8d", style="italic")

    # --- Draw /24-to-/24 traffic flow edges (cross-zone only, top 75) ---
    cross_zone_flows: list[tuple[str, str, int]] = []
    for (net_a, net_b), total_bytes in net_pair_bytes.items():
        zone_a = net_zones.get(net_a, "External")
        zone_b = net_zones.get(net_b, "External")
        if zone_a == zone_b:
            continue
        cross_zone_flows.append((net_a, net_b, total_bytes))

    # Cap to top 75 flows by volume to keep rendering fast
    cross_zone_flows.sort(key=lambda x: x[2], reverse=True)
    total_cross = len(cross_zone_flows)
    cross_zone_flows = cross_zone_flows[:75]

    if cross_zone_flows:
        max_flow = max(f[2] for f in cross_zone_flows)
    else:
        max_flow = 1

    for net_a, net_b, total_bytes in sorted(cross_zone_flows, key=lambda x: x[2]):
        zone_a = net_zones.get(net_a, "External")
        zone_b = net_zones.get(net_b, "External")

        ax_pos = node_positions.get(net_a, (0.5, zone_y.get(zone_a, 0.5)))
        bx_pos = node_positions.get(net_b, (0.5, zone_y.get(zone_b, 0.5)))

        ratio = total_bytes / max_flow if max_flow > 0 else 0
        width = max(1.0, ratio * 14)
        alpha = max(0.3, min(0.9, 0.3 + ratio * 0.6))

        is_ot_flow = (zone_a in ("SCADA", "CONTROL/FIELD")
                      or zone_b in ("SCADA", "CONTROL/FIELD"))
        color = "#e74c3c" if is_ot_flow else "#3498db"

        rad = 0.08 + (hash((net_a, net_b)) % 10) * 0.015
        ax.annotate(
            "", xy=bx_pos, xytext=ax_pos,
            arrowprops=dict(
                arrowstyle="-|>",
                color=color, alpha=alpha,
                linewidth=width, mutation_scale=10 + width,
                connectionstyle=f"arc3,rad={rad:.3f}",
            ),
            zorder=3,
        )

    # Byte count labels for top zone-to-zone flows (aggregate)
    from plugins.network_forensics.pcap_metadata_summary.tool import _format_bytes
    drawn_labels: set[tuple[str, str]] = set()
    for (src_zone, dst_zone), total_bytes in sorted(
        zone_flows.items(), key=lambda x: x[1], reverse=True
    ):
        if src_zone == dst_zone:
            continue
        pair = tuple(sorted([src_zone, dst_zone]))
        if pair in drawn_labels:
            continue
        drawn_labels.add(pair)

        reverse_bytes = zone_flows.get((dst_zone, src_zone), 0)
        combined = total_bytes + reverse_bytes

        mid_x = 0.5 + 0.08 * (len(drawn_labels) % 3 - 1)
        mid_y = (zone_y[src_zone] + zone_y[dst_zone]) / 2
        label = _format_bytes(combined)
        ax.text(mid_x, mid_y, label, fontsize=7, fontweight="bold",
                ha="center", va="center",
                bbox=dict(boxstyle="round,pad=0.2", facecolor="white",
                          edgecolor="#2c3e50", alpha=0.9, linewidth=0.8),
                zorder=6)

    # Legend
    legend_elements = [
        mpatches.Patch(facecolor="#3498db", alpha=0.6, label="IT Traffic"),
        mpatches.Patch(facecolor="#e74c3c", alpha=0.6, label="OT/ICS Traffic"),
    ]
    # Zone /24 network counts
    for zone_name, _, _ in _PURDUE_ZONES:
        n = len(zone_nets[zone_name])
        if n > 0:
            legend_elements.append(
                mpatches.Patch(
                    facecolor=_ZONE_BG_COLORS[zone_name],
                    edgecolor="#7f8c8d",
                    label=f"{zone_name}: {n} /24s",
                )
            )

    ax.legend(handles=legend_elements, loc="lower right",
              fontsize=7, framealpha=0.9, ncol=2)

    ax.set_title("Purdue Model - Network Zone Traffic Flow"
                 + (f" (top {len(cross_zone_flows)} of {total_cross} flows)"
                    if total_cross > 75 else ""),
                 fontsize=13, fontweight="bold", pad=12)

    plt.tight_layout()

    # Render to PNG bytes in memory
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight",
                facecolor="white", edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def _export_pdf(
    content: str,
    output_dir: Path,
    filename: str,
    mode: str = "",
    condition_orange: bool = False,
    session: Any | None = None,
) -> Path | None:
    """Render a professional, executive-readable PDF report using fpdf2."""
    try:
        from fpdf import FPDF
    except ImportError:
        print("  ⚠️  fpdf2 not installed -- PDF export skipped. Install with: pip install fpdf2")
        return None

    # --- Colour palette ---
    CLR_GREY_FOOTER = (100, 100, 100)
    CLR_NAVY = (22, 42, 72)          # section header background
    CLR_DARK_SLATE = (47, 62, 80)    # sub-header background
    CLR_WHITE = (255, 255, 255)
    CLR_BLACK = (0, 0, 0)
    CLR_RED = (180, 30, 30)          # CRITICAL text
    CLR_ORANGE = (200, 100, 20)      # HIGH / warning text
    CLR_GREY = (100, 100, 100)       # secondary text
    CLR_LIGHT_GREY = (230, 230, 230) # zebra row background
    CLR_ACCENT_LINE = (22, 42, 72)   # thin accent lines

    try:
        # Subclass for automatic page footer
        class _ReportPDF(FPDF):
            def footer(self):
                self.set_y(-15)
                self.set_font("Helvetica", "I", 7)
                self.set_text_color(*CLR_GREY_FOOTER)
                self.cell(0, 4, f"Event Mill  |  Page {self.page_no()} of {{nb}}",
                          align="C")

        pdf = _ReportPDF()
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=22)

        eff_w = pdf.w - pdf.l_margin - pdf.r_margin  # effective width

        # ===================================================================
        # COVER PAGE
        # ===================================================================
        pdf.add_page()
        # Navy banner at top
        pdf.set_fill_color(*CLR_NAVY)
        pdf.rect(0, 0, 210, 55, "F")

        # Title
        pdf.set_y(12)
        pdf.set_text_color(*CLR_WHITE)
        pdf.set_font("Helvetica", "B", 22)
        if mode.startswith("ot_"):
            pdf.cell(0, 10, "OT / ICS  PCAP Analysis Report", align="C",
                     new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.cell(0, 10, "PCAP AI Analysis Report", align="C",
                     new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 7, "Event Mill  |  Network Forensics Division", align="C",
                 new_x="LMARGIN", new_y="NEXT")

        # Condition Orange banner (if active)
        if condition_orange:
            pdf.set_y(55)
            pdf.set_fill_color(220, 80, 20)
            pdf.rect(0, 55, 210, 10, "F")
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*CLR_WHITE)
            pdf.cell(0, 10, "!! CONDITION ORANGE -- HEIGHTENED ALERT POSTURE !!", align="C",
                     new_x="LMARGIN", new_y="NEXT")

        # Meta info box
        pdf.set_y(75)
        pdf.set_text_color(*CLR_BLACK)
        pdf.set_font("Helvetica", "", 10)
        ts_str = datetime.now().strftime("%Y-%m-%d  %H:%M:%S UTC")
        mode_display = mode.replace("_", " ").upper()

        # Extract PCAP filename and key stats from the content header
        pcap_name = ""
        pcap_stats_lines: list[str] = []
        for raw_line in content.split("\n")[:30]:
            ln = raw_line.strip()
            if ln.startswith("PCAP ANALYSIS:"):
                pcap_name = ln.split(":", 1)[1].strip()
            elif ln.startswith(("Size:", "Time:", "IPs:", "DNS:")):
                pcap_stats_lines.append(ln)
            elif ln.startswith(("TCP", "UDP", "ICMP", "OTHER")):
                pcap_stats_lines.append("  " + ln)
            elif ln.startswith("Protocols:"):
                pcap_stats_lines.append(ln)
            elif ln.startswith("OT/ICS:") or "Cleartext credentials:" in ln:
                pcap_stats_lines.append(ln)

        meta_items = [
            ("Analysis Mode:", mode_display),
            ("Generated:", ts_str),
        ]
        if pcap_name:
            meta_items.insert(0, ("PCAP File:", pcap_name))

        for label, val in meta_items:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(40, 6, label)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 6, _pdf_safe(val), new_x="LMARGIN", new_y="NEXT")

        # Key stats summary
        if pcap_stats_lines:
            pdf.ln(3)
            pdf.set_draw_color(*CLR_ACCENT_LINE)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "Capture Summary", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            for stat_line in pcap_stats_lines:
                pdf.cell(0, 5, _pdf_safe(stat_line), new_x="LMARGIN", new_y="NEXT")

        # Classification footer on cover
        pdf.set_y(260)
        pdf.set_draw_color(*CLR_ACCENT_LINE)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(2)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*CLR_GREY)
        pdf.cell(0, 4, "Confidential -- For authorized security personnel only",
                 align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 4, "Full data export available in companion .md file",
                 align="C", new_x="LMARGIN", new_y="NEXT")

        # ===================================================================
        # PURDUE ZONE TRAFFIC DIAGRAM (OT reports only)
        # ===================================================================
        if mode.startswith("ot_") and session is not None:
            print("  \U0001f5fa Rendering Purdue zone diagram...", flush=True)
            graph_png = _render_purdue_zone_graph(session)
            if graph_png:
                import tempfile
                pdf.add_page()

                # Section header
                pdf.set_fill_color(*CLR_NAVY)
                pdf.set_text_color(*CLR_WHITE)
                pdf.set_font("Helvetica", "B", 11)
                pdf.cell(eff_w, 8, "  Network Zone Traffic Flow (Purdue Model)",
                         fill=True, new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(*CLR_BLACK)
                pdf.ln(4)

                # Write PNG to temp file and embed
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                    tmp.write(graph_png)
                    tmp_path = tmp.name
                try:
                    # Scale image to fit page width
                    img_w = eff_w
                    pdf.image(tmp_path, x=pdf.l_margin, w=img_w)
                finally:
                    import os
                    os.unlink(tmp_path)

                pdf.ln(3)
                pdf.set_font("Helvetica", "I", 7.5)
                pdf.set_text_color(*CLR_GREY)
                pdf.cell(0, 4,
                         "Zone classification: OT ports -> SCADA/Control, "
                         "IT service ports -> Corporate, "
                         "Web/mail ports -> DMZ, Non-RFC1918 -> External",
                         new_x="LMARGIN", new_y="NEXT")
                pdf.cell(0, 4,
                         "Edge thickness proportional to traffic volume. "
                         "Red = OT/ICS traffic, Blue = IT traffic.",
                         new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(*CLR_BLACK)

        # ===================================================================
        # BODY PAGES — parse content into structured sections
        # ===================================================================
        print("  \U0001f4dd Rendering PDF body...", flush=True)

        # Helper: draw a coloured section header bar
        def _section_header(title_text: str, bg: tuple = CLR_NAVY) -> None:
            pdf.ln(4)
            pdf.set_x(pdf.l_margin)
            pdf.set_fill_color(*bg)
            pdf.set_text_color(*CLR_WHITE)
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(eff_w, 8, "  " + _pdf_safe(title_text),
                     fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*CLR_BLACK)
            pdf.ln(2)

        # Helper: draw a sub-section header
        def _sub_header(title_text: str) -> None:
            pdf.ln(2)
            pdf.set_x(pdf.l_margin)
            pdf.set_fill_color(*CLR_DARK_SLATE)
            pdf.set_text_color(*CLR_WHITE)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(eff_w, 6, "  " + _pdf_safe(title_text),
                     fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*CLR_BLACK)
            pdf.ln(1)

        # Helper: clean markdown artifacts from text for PDF display
        def _clean_md(text: str) -> str:
            """Strip **, backticks, leading *-bullets for PDF body text."""
            t = text.replace("**", "").replace("`", "")
            # Strip leading bullet markers ("*   ", "* ", "- ")
            s = t.lstrip()
            if s.startswith("*   "):
                t = s[4:]
            elif s.startswith("* "):
                t = s[2:]
            elif s.startswith("- "):
                t = s[2:]
            return t.strip()

        # Helper: body text line — ALWAYS resets X to prevent overflow
        def _body_line(text: str, bold: bool = False, color: tuple = CLR_BLACK,
                       font_size: float = 9, indent: float = 0) -> None:
            pdf.set_text_color(*color)
            pdf.set_font("Helvetica", "B" if bold else "", font_size)
            pdf.set_x(pdf.l_margin + indent)   # always reset X
            pdf.multi_cell(0, 4.5, _pdf_safe(text))  # 0 = auto-fill to right margin

        # Helper: monospace data line (small) — ALWAYS resets X
        def _data_line(text: str, bold: bool = False) -> None:
            pdf.set_text_color(*CLR_BLACK)
            pdf.set_font("Courier", "B" if bold else "", 7)
            pdf.set_x(pdf.l_margin)             # always reset X
            pdf.multi_cell(0, 3.5, _pdf_safe(text))  # 0 = auto-fill

        # Helper: render a table with header + rows (zebra-striped)
        def _table(headers: list[str], rows: list[list[str]],
                   col_widths: list[float] | None = None,
                   font_size: float = 7.5) -> None:
            """Draw a simple table. col_widths should sum to ~eff_w."""
            if not rows:
                return
            n_cols = len(headers)
            if col_widths is None:
                col_widths = [eff_w / n_cols] * n_cols

            # Header row
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", font_size)
            pdf.set_fill_color(*CLR_DARK_SLATE)
            pdf.set_text_color(*CLR_WHITE)
            for i, hdr in enumerate(headers):
                pdf.cell(col_widths[i], 5, _pdf_safe(hdr), border=0, fill=True)
            pdf.ln()

            # Data rows
            pdf.set_font("Courier", "", font_size)
            for row_idx, row in enumerate(rows):
                # Zebra striping
                if row_idx % 2 == 0:
                    pdf.set_fill_color(*CLR_LIGHT_GREY)
                    fill = True
                else:
                    fill = False
                pdf.set_x(pdf.l_margin)
                pdf.set_text_color(*CLR_BLACK)
                for i, cell_text in enumerate(row):
                    pdf.cell(col_widths[i], 4, _pdf_safe(cell_text[:50]),
                             border=0, fill=fill)
                pdf.ln()
            pdf.ln(1)

        # Helper: parse credential lines into table rows
        def _render_credential_table(lines: list[str]) -> None:
            """Parse credential section lines into a structured table."""
            cred_rows: list[list[str]] = []
            current_proto = ""
            current_count = ""
            current_desc = ""
            ip_pairs: list[str] = []

            def _flush() -> None:
                if current_proto:
                    pairs_str = "; ".join(ip_pairs[:4])
                    if len(ip_pairs) > 4:
                        pairs_str += f" (+{len(ip_pairs)-4})"
                    cred_rows.append([current_proto, current_count,
                                      current_desc, pairs_str])

            for ln in lines:
                s = ln.strip()
                if not s:
                    continue
                if "detection(s)" in s:
                    _flush()
                    ip_pairs = []
                    # Parse "LDAP-SimpleBind   308 detection(s)  -- LDAP simple bind"
                    parts = s.split()
                    current_proto = parts[0] if parts else ""
                    # Find the count (digits before "detection(s)")
                    current_count = ""
                    for p in parts[1:]:
                        if p == "detection(s)":
                            break
                        current_count = p
                    # Description after "--"
                    if "--" in s:
                        current_desc = s.split("--", 1)[1].strip()
                    else:
                        current_desc = ""
                elif "->" in s and not s.startswith("..."):
                    ip_pairs.append(s.replace("->", ">"))
                elif s.startswith("..."):
                    pass  # skip overflow markers

            _flush()

            if cred_rows:
                _table(
                    ["Protocol", "Count", "Type", "Source > Destination"],
                    cred_rows,
                    col_widths=[35, 15, 45, eff_w - 95],
                )

        # Helper: parse lateral movement lines into table rows
        def _render_lateral_table(lines: list[str], max_rows: int = 20) -> None:
            """Parse lateral movement lines into a structured table."""
            # Two-pass: first collect sources with their detail targets
            entries: list[dict] = []
            current_entry: dict | None = None

            for ln in lines:
                s = ln.strip()
                if not s:
                    continue
                # Source line: "172.24.62.114 -> 3 targets (SMB)"
                if (s[0].isdigit() and "->" in s and "targets" in s):
                    parts = s.split("->", 1)
                    src = parts[0].strip()
                    rest = parts[1].strip() if len(parts) > 1 else ""
                    tgt_count = ""
                    proto = ""
                    flag = ""
                    tokens = rest.split()
                    if tokens:
                        tgt_count = tokens[0]
                    for t in tokens:
                        if t.startswith("(") and t.endswith(")"):
                            proto = t[1:-1]
                        elif "(" in t:
                            proto = t.split("(")[1].rstrip(")")
                        if t == "SCAN?":
                            flag = "SCAN?"
                    current_entry = {
                        "src": src, "count": tgt_count,
                        "proto": proto, "flag": flag, "targets": [],
                    }
                    entries.append(current_entry)
                # Detail line: "-> 10.123.0.46:445 (SMB) 6 pkts 372.0 B"
                elif s.startswith("->") and current_entry is not None:
                    detail = s[2:].strip()
                    # Extract just the destination IP:port
                    dst_tokens = detail.split()
                    if dst_tokens:
                        current_entry["targets"].append(dst_tokens[0])

            # Build table rows (top max_rows sources)
            total_sources = len(entries)
            lat_rows: list[list[str]] = []
            for e in entries[:max_rows]:
                tgts = "; ".join(e["targets"][:3])
                if len(e["targets"]) > 3:
                    tgts += f" (+{len(e['targets'])-3})"
                lat_rows.append([
                    e["src"], e["count"], e["proto"],
                    e["flag"], tgts,
                ])

            if lat_rows:
                _table(
                    ["Source IP", "Targets", "Protocol", "Flag", "Top Destinations"],
                    lat_rows,
                    col_widths=[38, 18, 25, 18, eff_w - 99],
                )
                if total_sources > max_rows:
                    pdf.set_font("Helvetica", "I", 7.5)
                    pdf.set_text_color(*CLR_GREY)
                    pdf.set_x(pdf.l_margin)
                    pdf.cell(0, 4,
                             f"  Showing top {max_rows} of {total_sources} sources "
                             "(see .md for complete listing)",
                             new_x="LMARGIN", new_y="NEXT")
                    pdf.set_text_color(*CLR_BLACK)

        # Helper: parse port scan lines into table rows
        def _render_scan_table(lines: list[str]) -> None:
            """Parse port scan pattern lines into a table."""
            scan_rows: list[list[str]] = []
            for ln in lines:
                s = ln.strip()
                if not s:
                    continue
                # Source line: "10.70.144.155 -> 108 hosts on port 5450 (5450)"
                if s[0].isdigit() and "hosts on port" in s:
                    parts = s.split("->", 1)
                    src = parts[0].strip()
                    rest = parts[1].strip() if len(parts) > 1 else ""
                    # "108 hosts on port 5450 (5450)"
                    tokens = rest.split()
                    count = tokens[0] if tokens else ""
                    port = ""
                    svc = ""
                    if "port" in rest:
                        after_port = rest.split("port", 1)[1].strip()
                        port_tokens = after_port.split()
                        port = port_tokens[0] if port_tokens else ""
                        if len(port_tokens) > 1:
                            svc = port_tokens[1].strip("()")
                    scan_rows.append([src, count, port, svc])

            if scan_rows:
                _table(
                    ["Scanner IP", "Hosts", "Port", "Service"],
                    scan_rows,
                    col_widths=[45, 18, 18, eff_w - 81],
                )

        # --- Normalize Unicode before parsing so table parsers see ASCII ---
        content = _pdf_safe(content)

        # --- Parse content into sections (split on ===== dividers) ---
        raw_sections: list[tuple[str, list[str]]] = []
        current_title = ""
        current_lines: list[str] = []

        for raw_line in content.split("\n"):
            stripped = raw_line.strip()
            # Detect section headers: a line of ====, then the title, then ====
            if stripped.startswith("=" * 10):
                # If we already captured a title but no content lines yet,
                # this is the closing ==== of a ====TITLE==== pair – skip it.
                if current_title and current_title != "__DIVIDER__" and not current_lines:
                    continue
                # Otherwise save any pending section
                if current_title or current_lines:
                    raw_sections.append((current_title, current_lines))
                    current_lines = []
                # Next non-empty, non-==== line is the title
                current_title = "__DIVIDER__"
                continue
            if current_title == "__DIVIDER__":
                current_title = stripped
                continue
            current_lines.append(raw_line)
        # Save final section
        if current_title or current_lines:
            raw_sections.append((current_title, current_lines))

        # --- Render each section ---
        pdf.add_page()

        for sec_title, sec_lines in raw_sections:
            if not sec_title or sec_title == "__DIVIDER__":
                # Pre-header content — already shown on cover page, skip
                continue

            # Skip the "PCAP ANALYSIS: filename" section (cover page duplicate)
            if sec_title.startswith("PCAP ANALYSIS:"):
                # But render any lines that aren't already on the cover
                non_cover = [
                    ln for ln in sec_lines if ln.strip()
                    and not ln.strip().startswith(("Size:", "Time:", "IPs:", "OT/ICS:", "Cleartext"))
                    and not ln.strip().startswith("Protocols:")
                    and not ln.strip().startswith(("TCP", "UDP", "ICMP", "OTHER", "DNS:"))
                ]
                if non_cover:
                    _section_header("Capture Details")
                    for ln in non_cover:
                        _body_line(ln.strip(), font_size=9)
                continue

            # Determine if this is a data-heavy section to truncate
            is_data_heavy = any(tag in sec_title for tag in _DATA_HEAVY_SECTIONS)
            # Identify the AI analysis section (most important)
            is_ai_section = ("AI ANALYSIS" in sec_title.upper()
                             or "OT/ICS ANALYSIS" in sec_title.upper())

            # Section header colour
            if is_ai_section:
                _section_header(sec_title, bg=(15, 82, 35))  # dark green for AI analysis
            elif "CREDENTIAL" in sec_title.upper():
                _section_header(sec_title, bg=(140, 30, 30))  # dark red for credentials
            elif "OT" in sec_title.upper() or "ICS" in sec_title.upper():
                _section_header(sec_title, bg=(130, 70, 10))  # amber for OT
            else:
                _section_header(sec_title)

            # --- Check for table-friendly sections and render as tables ---
            is_credential_section = "CREDENTIAL" in sec_title.upper()
            is_lateral_section = "LATERAL" in sec_title.upper() or "CROSS-ZONE" in sec_title.upper()
            is_ot_activity = ("OT / ICS PROTOCOL ACTIVITY" in sec_title.upper()
                              or "OT/ICS PROTOCOL ACTIVITY" in sec_title.upper())
            is_scada_tags = "SCADA MESSAGE BUS" in sec_title.upper()

            # --- SCADA Message Bus Tag Data → compact table ---
            if is_scada_tags:
                # Render summary lines (Unique tags, Source hosts)
                for ln in sec_lines:
                    stripped = ln.strip()
                    if not stripped:
                        continue
                    if stripped.startswith("─") or stripped.startswith("Tag Name"):
                        continue  # skip text table markers
                    if stripped.startswith("Unique tags") or stripped.startswith("Source hosts"):
                        _body_line(stripped, font_size=9, bold=True)
                        continue
                    # Parse tabular tag lines
                    parts = stripped.split()
                    if len(parts) >= 3 and not stripped.startswith("─"):
                        # Render as compact data line with smaller font
                        _data_line(stripped)
                continue

            # --- OT / ICS Protocol Activity → structured tables ---
            if is_ot_activity:
                # Categorise lines into sub-parts
                proto_rows: list[list[str]] = []
                write_rows: list[list[str]] = []
                write_title = ""
                control_rows: list[list[str]] = []
                control_title = ""
                exception_rows: list[list[str]] = []
                exception_title = ""
                diag_rows: list[list[str]] = []
                diag_title = ""
                fc_rows: list[list[str]] = []
                fc_title = ""
                unit_id_line = ""
                summary_lines: list[str] = []
                current_block = ""

                for ln in sec_lines:
                    s = ln.strip()
                    if not s or s.startswith("-" * 5):
                        continue

                    # Detect sub-block transitions
                    s_up = s.upper()
                    if "PROTOCOL BREAKDOWN" in s_up:
                        current_block = "proto"
                        continue
                    if "WRITE OPERATIONS" in s_up:
                        current_block = "write"
                        write_title = s
                        continue
                    if "CONTROL COMMANDS" in s_up:
                        current_block = "control"
                        control_title = s
                        continue
                    if "EXCEPTION RESPONSES" in s_up:
                        current_block = "exception"
                        exception_title = s
                        continue
                    if "DIAGNOSTIC COMMANDS" in s_up:
                        current_block = "diag"
                        diag_title = s
                        continue
                    if "FUNCTION CODE DISTRIBUTION" in s_up:
                        current_block = "fc"
                        fc_title = s
                        continue
                    if "UNIT IDS" in s_up:
                        current_block = ""
                        unit_id_line = s
                        continue

                    # Route lines to appropriate list
                    if current_block == "proto":
                        # "  Modbus              7,189 transactions"
                        tokens = s.split()
                        if len(tokens) >= 2 and tokens[-1] == "transactions":
                            proto_rows.append([tokens[0], tokens[1]])
                        else:
                            summary_lines.append(s)
                    elif current_block == "write":
                        # "172.24.162.205 -> ... | Modbus | 328 writes | Functions: ..."
                        if "->" in s and "|" in s:
                            parts = [p.strip() for p in s.split("|")]
                            route = parts[0] if parts else ""
                            proto = parts[1] if len(parts) > 1 else ""
                            writes = parts[2].replace("writes", "").strip() if len(parts) > 2 else ""
                            funcs = parts[3].replace("Functions:", "").strip() if len(parts) > 3 else ""
                            write_rows.append([route, proto, writes, funcs])
                        else:
                            summary_lines.append(s)
                    elif current_block == "control":
                        # "src -> dst:port (proto) -- func"
                        if "->" in s:
                            parts = s.split("->", 1)
                            src = parts[0].strip()
                            rest = parts[1].strip() if len(parts) > 1 else ""
                            if "--" in rest:
                                target, cmd = rest.split("--", 1)
                                control_rows.append([src, target.strip(), cmd.strip()])
                            else:
                                control_rows.append([src, rest, ""])
                        else:
                            summary_lines.append(s)
                    elif current_block == "exception":
                        # "Read Holding Registers exception code=2 -- 8 occurrence(s)"
                        if "exception" in s.lower() and "--" in s:
                            before_dash, after_dash = s.split("--", 1)
                            # func_name exception code=X
                            parts = before_dash.strip().rsplit("code=", 1)
                            func_part = parts[0].replace("exception", "").strip()
                            exc_code = parts[1].strip() if len(parts) > 1 else ""
                            count_part = after_dash.strip().split()[0] if after_dash.strip() else ""
                            exception_rows.append([func_part, exc_code, count_part])
                        elif "exception" in s.lower():
                            exception_rows.append([s, "", ""])
                        else:
                            summary_lines.append(s)
                    elif current_block == "diag":
                        if "->" in s:
                            parts = s.split("->", 1)
                            src = parts[0].strip()
                            rest = parts[1].strip() if len(parts) > 1 else ""
                            if "--" in rest:
                                target, cmd = rest.split("--", 1)
                                diag_rows.append([src, target.strip(), cmd.strip()])
                            else:
                                diag_rows.append([src, rest, ""])
                        else:
                            summary_lines.append(s)
                    elif current_block == "fc":
                        # "FC   3 (Read Holding Registers      )  1,328"
                        # or "FC  15 (Write Multiple Coils       )    496  WRITE"
                        if s.startswith("FC"):
                            tokens = s.split()
                            fc_num = tokens[1] if len(tokens) > 1 else ""
                            # Extract function name between parens
                            fname = ""
                            if "(" in s and ")" in s:
                                fname = s.split("(", 1)[1].split(")", 1)[0].strip()
                            # Count is after the closing paren
                            after_paren = s.split(")", 1)[1].strip() if ")" in s else ""
                            at = after_paren.split()
                            count = at[0] if at else ""
                            flag = at[1] if len(at) > 1 else ""
                            fc_rows.append([fc_num, fname, count, flag])
                        else:
                            summary_lines.append(s)
                    else:
                        # Pre-block summary lines (Total OT, OT endpoints, etc.)
                        summary_lines.append(s)

                # Render summary lines at top
                for sl in summary_lines:
                    _body_line(sl, font_size=9)

                # Protocol breakdown table
                if proto_rows:
                    _sub_header("Protocol Breakdown")
                    _table(
                        ["Protocol", "Transactions"],
                        proto_rows,
                        col_widths=[55, eff_w - 55],
                    )

                # Write operations table
                if write_rows:
                    _sub_header(write_title or "Write Operations")
                    _table(
                        ["Route (Src -> Dst)", "Protocol", "Writes", "Functions"],
                        write_rows,
                        col_widths=[eff_w * 0.38, 30, 20, eff_w * 0.62 - 50],
                    )

                # Control commands table
                if control_rows:
                    _sub_header(control_title or "Control Commands")
                    _table(
                        ["Source", "Target", "Command"],
                        control_rows,
                        col_widths=[45, 55, eff_w - 100],
                    )

                # Exception responses table
                if exception_rows:
                    _sub_header(exception_title or "Exception Responses")
                    _table(
                        ["Function", "Exc. Code", "Count"],
                        exception_rows,
                        col_widths=[eff_w - 60, 30, 30],
                    )

                # Diagnostic commands table
                if diag_rows:
                    _sub_header(diag_title or "Diagnostic Commands")
                    _table(
                        ["Source", "Target", "Command"],
                        diag_rows,
                        col_widths=[45, 55, eff_w - 100],
                    )

                # Modbus FC distribution table
                if fc_rows:
                    _sub_header(fc_title or "Function Code Distribution")
                    _table(
                        ["FC", "Function Name", "Count", "Flag"],
                        fc_rows,
                        col_widths=[15, eff_w - 75, 30, 30],
                    )

                # Unit IDs at the bottom
                if unit_id_line:
                    _body_line(unit_id_line, bold=True, font_size=8.5)

                continue

            if is_credential_section:
                _render_credential_table(sec_lines)
                continue

            if is_lateral_section:
                # Split into sub-sections by sub-header keywords
                subsections: list[tuple[str, list[str]]] = []
                cur_sub = ""
                cur_lines: list[str] = []
                for ln in sec_lines:
                    s = ln.strip()
                    if s.startswith(("INTERNAL LATERAL", "ICS PROTOCOL CROSS-ZONE",
                                     "PORT SCAN PATTERNS")):
                        if cur_sub or cur_lines:
                            subsections.append((cur_sub, cur_lines))
                        cur_sub = s
                        cur_lines = []
                        continue
                    cur_lines.append(ln)
                if cur_sub or cur_lines:
                    subsections.append((cur_sub, cur_lines))

                for sub_title, sub_lines in subsections:
                    if sub_title:
                        _sub_header(sub_title)
                    if "LATERAL" in sub_title.upper():
                        _render_lateral_table(sub_lines, max_rows=20)
                    elif "CROSS-ZONE" in sub_title.upper():
                        # Cross-zone: render as table with Source / Destination
                        xz_rows: list[list[str]] = []
                        for ln in sub_lines:
                            s = ln.strip()
                            if not s or s.startswith("-"):
                                continue
                            if ("(INT)" in s or "(EXT)" in s) and "->" in s:
                                # "10.70.1.75 (INT) -> 161.141.96.182 (EXT):44818 (EtherNet/IP) -- 2 pkts"
                                # or "161.141.113.37 (EXT) -> 10.59.244.32 (INT):44818 (...) -- 506 pkts"
                                parts = s.split("->", 1)
                                src_part = parts[0].strip()
                                rest = parts[1].strip() if len(parts) > 1 else ""
                                # Parse dest, port/proto, pkts from rest
                                dst_part = rest.split("--")[0].strip() if "--" in rest else rest
                                pkts = rest.split("--")[1].strip() if "--" in rest else ""
                                # Extract port/protocol from destination side
                                # dst_part is like "161.141.96.182 (EXT):44818 (EtherNet/IP)"
                                # or "10.59.244.32 (INT):44818 (EtherNet/IP)"
                                port_proto = ""
                                for tag in ("(INT)", "(EXT)"):
                                    if tag in dst_part:
                                        idx = dst_part.index(tag)
                                        after = dst_part[idx + len(tag):].strip().lstrip(":")
                                        if after:
                                            port_proto = after
                                        dst_part = dst_part[:idx].strip()
                                        break
                                xz_rows.append([src_part, dst_part, port_proto, pkts])
                        if xz_rows:
                            show = xz_rows[:20]
                            _table(
                                ["Source", "Destination", "Port / Protocol", "Volume"],
                                show,
                                col_widths=[38, 38, 55, eff_w - 131],
                            )
                            if len(xz_rows) > 20:
                                pdf.set_font("Helvetica", "I", 7.5)
                                pdf.set_text_color(*CLR_GREY)
                                pdf.set_x(pdf.l_margin)
                                pdf.cell(0, 4,
                                         f"  Showing 20 of {len(xz_rows)} cross-zone flows "
                                         "(see .md for complete listing)",
                                         new_x="LMARGIN", new_y="NEXT")
                                pdf.set_text_color(*CLR_BLACK)
                    elif "SCAN" in sub_title.upper():
                        _render_scan_table(sub_lines)
                    else:
                        # Fallback: render as data lines
                        for ln in sub_lines:
                            s = ln.strip()
                            if s:
                                _data_line(s)
                continue

            # --- External Communications section → render as tables ---
            is_ext_comms_section = "EXTERNAL COMMUNICATIONS" in sec_title.upper()
            if is_ext_comms_section:
                # Split into sub-sections by sub-header keywords
                ext_subs: list[tuple[str, list[str]]] = []
                cur_ext_sub = ""
                cur_ext_lines: list[str] = []
                for ln in sec_lines:
                    s = ln.strip()
                    if s.startswith(("TOP EXTERNAL DESTINATIONS",
                                     "TOP EXTERNAL SOURCES",
                                     "INTERNAL HOSTS WITH MOST EXTERNAL")):
                        if cur_ext_sub or cur_ext_lines:
                            ext_subs.append((cur_ext_sub, cur_ext_lines))
                        cur_ext_sub = s
                        cur_ext_lines = []
                        continue
                    cur_ext_lines.append(ln)
                if cur_ext_sub or cur_ext_lines:
                    ext_subs.append((cur_ext_sub, cur_ext_lines))

                for ext_sub_title, ext_sub_lines in ext_subs:
                    if not ext_sub_title:
                        # Summary lines at top
                        for ln in ext_sub_lines:
                            s = ln.strip()
                            if s and not s.startswith("-"):
                                _body_line(s, font_size=9,
                                           bold=("Total" in s or "INT" in s or "EXT" in s or "Unique" in s))
                        continue

                    _sub_header(ext_sub_title)

                    if "DESTINATIONS" in ext_sub_title.upper() or "SOURCES" in ext_sub_title.upper():
                        ext_rows: list[list[str]] = []
                        for ln in ext_sub_lines:
                            s = ln.strip()
                            if not s or s.startswith("-"):
                                continue
                            # Parse: "203.0.113.5      1.2 MB       flows=12     ports: 443, 80"
                            tokens = s.split()
                            if tokens and tokens[0][0].isdigit():
                                ip = tokens[0]
                                # Find bytes (contains B/KB/MB/GB)
                                vol = ""
                                flows = ""
                                ports = ""
                                for i, t in enumerate(tokens[1:], 1):
                                    if any(u in t for u in ("B", "KB", "MB", "GB", "TB")):
                                        vol = t if vol else tokens[i-1] + " " + t if not tokens[i-1][0].isdigit() else t
                                        # Check if previous token is the number part
                                        if i > 1 and tokens[i-1].replace(".", "").replace(",", "").isdigit():
                                            vol = tokens[i-1] + " " + t
                                    elif t.startswith("flows="):
                                        flows = t.split("=")[1]
                                    elif t == "ports:":
                                        ports = " ".join(tokens[i+1:])
                                        break
                                ext_rows.append([ip, vol, flows, ports])
                        if ext_rows:
                            _table(
                                ["IP Address", "Volume", "Flows", "Ports"],
                                ext_rows[:15],
                                col_widths=[42, 25, 18, eff_w - 85],
                            )
                    elif "INTERNAL HOSTS" in ext_sub_title.upper():
                        int_rows: list[list[str]] = []
                        for ln in ext_sub_lines:
                            s = ln.strip()
                            if not s or s.startswith("-"):
                                continue
                            tokens = s.split()
                            if tokens and tokens[0][0].isdigit():
                                ip = tokens[0]
                                vol = ""
                                peers = ""
                                for i, t in enumerate(tokens[1:], 1):
                                    if any(u in t for u in ("B", "KB", "MB", "GB", "TB")):
                                        if i > 1 and tokens[i-1].replace(".", "").replace(",", "").isdigit():
                                            vol = tokens[i-1] + " " + t
                                        else:
                                            vol = t
                                    elif t == "peers:":
                                        peers = " ".join(tokens[i+1:])
                                        break
                                int_rows.append([ip, vol, peers])
                        if int_rows:
                            _table(
                                ["Internal IP", "Volume", "External Peers"],
                                int_rows[:10],
                                col_widths=[45, 30, eff_w - 75],
                            )
                continue

            # --- Port Analysis section → render as tables ---
            is_port_section = "PORT ANALYSIS" in sec_title.upper()
            if is_port_section:
                # Split into sub-sections
                port_subs: list[tuple[str, list[str]]] = []
                cur_sub_title = ""
                cur_sub_lines: list[str] = []
                for ln in sec_lines:
                    s = ln.strip()
                    if s.startswith(("STANDARD SERVICES", "ICS/SCADA PROTOCOLS",
                                     "SUSPICIOUS PORTS", "UNKNOWN HIGH PORTS")):
                        if cur_sub_title or cur_sub_lines:
                            port_subs.append((cur_sub_title, cur_sub_lines))
                        cur_sub_title = s
                        cur_sub_lines = []
                        continue
                    cur_sub_lines.append(ln)
                if cur_sub_title or cur_sub_lines:
                    port_subs.append((cur_sub_title, cur_sub_lines))

                for psub_title, psub_lines in port_subs:
                    if psub_title:
                        _sub_header(psub_title)
                    port_rows: list[list[str]] = []
                    for ln in psub_lines:
                        s = ln.strip()
                        if not s or s.startswith("-"):
                            continue
                        # Standard: "443  HTTPS  flows=160  sources=112  1.5 MB"
                        # Unknown:  "1947  flows=17  sources=11  144.0 KB"
                        tokens = s.split()
                        if tokens and tokens[0].isdigit():
                            port = tokens[0]
                            # If second token starts with flows=, no service name
                            if len(tokens) > 1 and tokens[1].startswith("flows="):
                                svc = ""
                                rest_tokens = tokens[1:]
                            else:
                                svc = tokens[1] if len(tokens) > 1 else ""
                                rest_tokens = tokens[2:]
                            flows = ""
                            sources = ""
                            vol = ""
                            for t in rest_tokens:
                                if t.startswith("flows="):
                                    flows = t.split("=")[1]
                                elif t.startswith("sources="):
                                    sources = t.split("=")[1]
                                else:
                                    vol = (vol + " " + t).strip()
                            port_rows.append([port, svc, flows, sources, vol])
                    if port_rows:
                        _table(
                            ["Port", "Service", "Flows", "Sources", "Volume"],
                            port_rows,
                            col_widths=[18, 35, 22, 22, eff_w - 97],
                        )
                continue

            # Track data lines for truncation (at section and sub-section level)
            data_line_count = 0
            truncated = False
            in_data_heavy_subsection = is_data_heavy

            for ln in sec_lines:
                stripped = ln.strip()
                if not stripped:
                    pdf.ln(2)
                    continue

                # Sub-section dividers (----)
                if stripped.startswith("-" * 10):
                    pdf.set_draw_color(*CLR_LIGHT_GREY)
                    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + eff_w, pdf.get_y())
                    pdf.ln(1)
                    continue

                # Detect sub-headers (emoji prefixed or all-caps short lines)
                if stripped.startswith(("WRITE OPERATIONS", "CONTROL COMMANDS",
                                       "EXCEPTION RESPONSES", "DIAGNOSTIC COMMANDS",
                                       "STANDARD SERVICES", "ICS/SCADA PROTOCOLS",
                                       "SUSPICIOUS PORTS", "UNKNOWN HIGH PORTS",
                                       "PORT SCAN PATTERNS", "INTERNAL LATERAL",
                                       "ICS PROTOCOL CROSS-ZONE",
                                       "EXTERNAL IPs")):
                    _sub_header(stripped)
                    data_line_count = 0
                    truncated = False
                    # Check if this sub-section is data-heavy
                    in_data_heavy_subsection = any(
                        tag in stripped for tag in _DATA_HEAVY_SECTIONS
                    )
                    continue

                # Data-heavy truncation
                if in_data_heavy_subsection and not is_ai_section:
                    # Count lines that look like data (start with IP or indent)
                    if (stripped.startswith("10.") or stripped.startswith("161.")
                            or stripped.startswith("->") or stripped.startswith("...")):
                        data_line_count += 1
                        if data_line_count > _DATA_SECTION_MAX_LINES and not truncated:
                            pdf.ln(2)
                            pdf.set_font("Helvetica", "I", 8)
                            pdf.set_text_color(*CLR_GREY)
                            remaining = sum(
                                1 for x in sec_lines
                                if x.strip().startswith(("10.", "161.", "->"))
                            ) - _DATA_SECTION_MAX_LINES
                            pdf.cell(eff_w, 4,
                                     f"    ... +{remaining} more entries "
                                     "(see companion .md file for complete listing)",
                                     new_x="LMARGIN", new_y="NEXT")
                            pdf.set_text_color(*CLR_BLACK)
                            truncated = True
                            continue
                        if truncated:
                            continue

                # --- Render AI analysis content (the most important part) ---
                if is_ai_section:
                    # Numbered findings (e.g. "1. OT PROTOCOL BASELINE REVIEW:")
                    if (len(stripped) > 2 and stripped[0].isdigit()
                            and stripped[1] in ".)" and stripped[2] == " "):
                        pdf.ln(3)
                        display = _clean_md(stripped)
                        _body_line(stripped, bold=True, font_size=10,
                                   color=CLR_NAVY)
                        continue

                    # Severity markers
                    if "CRITICAL" in stripped.upper():
                        color = CLR_RED
                    elif "HIGH" in stripped.upper():
                        color = CLR_ORANGE
                    else:
                        color = CLR_BLACK

                    display = _clean_md(stripped)

                    # Bold markdown lines (**text**)
                    if stripped.startswith("**") or stripped.startswith("*   **"):
                        _body_line(display, bold=True, color=color, font_size=9,
                                   indent=4 if stripped.startswith("*") else 0)
                        continue

                    # Bullet points (* item or - item)
                    if stripped.startswith("* ") or stripped.startswith("- "):
                        _body_line(display, color=color, font_size=9, indent=6)
                        continue

                    # MITRE / IEC references (deeper indent)
                    if stripped.startswith("*   "):
                        _body_line(display, font_size=8.5, indent=10, color=CLR_GREY)
                        continue

                    # TL;DR section
                    if stripped.upper().startswith("TL;DR"):
                        pdf.ln(3)
                        _sub_header("TL;DR -- Executive Summary")
                        continue

                    _body_line(display, color=color, font_size=9)
                    continue

                # --- Standard data section rendering ---
                # Protocol summary lines (e.g. "Modbus  1,997 transactions")
                if any(stripped.startswith(p) for p in (
                    "Modbus", "EtherNet", "DNP3", "OPC", "BACnet", "S7",
                    "Total OT", "OT endpoints", "Protocol breakdown"
                )):
                    _body_line(stripped, bold=True, font_size=9)
                    continue

                # Credential detail lines
                if "detection(s)" in stripped:
                    parts = stripped.split("detection(s)")
                    _body_line(stripped, bold=True, font_size=9,
                               color=CLR_ORANGE if int(''.join(c for c in parts[0] if c.isdigit()) or "0") > 50 else CLR_BLACK)
                    continue

                # FC distribution lines (Modbus)
                if stripped.startswith("FC "):
                    is_write = "WRITE" in stripped.upper()
                    is_diag = "DIAG" in stripped.upper()
                    _data_line(
                        stripped,
                        bold=is_write or is_diag,
                    )
                    continue

                # Port analysis lines (port number + service)
                if stripped and stripped[0].isdigit() and ("flows=" in stripped or "hosts on port" in stripped):
                    _data_line(stripped)
                    continue

                # Indented data (arrow lines, IP listings)
                if stripped.startswith("->") or stripped.startswith("..."):
                    _data_line("    " + stripped)
                    continue

                # IP flow lines (10.x.x.x -> ...)
                if stripped.startswith("10.") or stripped.startswith("161."):
                    _data_line(stripped)
                    continue

                # SCAN? lines
                if "SCAN?" in stripped:
                    _body_line(stripped, bold=True, font_size=8.5, color=CLR_ORANGE)
                    continue

                # Cobalt-Strike / suspicious
                if "Cobalt" in stripped or "SUSPICIOUS" in stripped.upper():
                    _body_line(stripped, bold=True, color=CLR_RED, font_size=9)
                    continue

                # Default
                clean = _clean_md(stripped)
                if "CRITICAL" in stripped.upper():
                    _body_line(clean, color=CLR_RED, font_size=9)
                elif any(kw in stripped.upper() for kw in ("WARNING", "HIGH")):
                    _body_line(clean, color=CLR_ORANGE, font_size=9)
                else:
                    _body_line(clean, font_size=9)

        pdf_path = output_dir / filename
        pdf.output(str(pdf_path))
        print(f"  PDF report saved: {pdf_path}")
        return pdf_path

    except Exception as e:
        logger.warning("PDF export failed: %s", e)
        print(f"  PDF export failed: {e}")
        return None


class PcapAiAnalyzer:
    """AI-enhanced PCAP analysis with Condition Orange support."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "pcap_ai_analyzer",
            "version": "1.0.0",
            "pillar": "network_forensics",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        mode = payload.get("mode")
        if not mode:
            errors.append("'mode' is required.")
        elif mode not in MODE_CONFIG:
            errors.append(
                f"Invalid mode '{mode}'. Must be one of: {', '.join(MODE_CONFIG.keys())}"
            )
        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        from plugins.network_forensics.pcap_metadata_summary.tool import get_pcap_session

        session = get_pcap_session()
        if not session:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message="No PCAP loaded. Use pcap_metadata_summary (mode=load) first.",
            )

        if not context or not hasattr(context, "llm_query") or not context.llm_query:
            return ToolResult(
                ok=False,
                error_code="LLM_UNAVAILABLE",
                message="LLM not available. pcap_ai_analyzer requires an LLM connection.",
            )

        mode = payload["mode"]
        condition_orange = payload.get("condition_orange", False)
        is_ot_mode = mode.startswith("ot_")
        is_netops_mode = mode.startswith("netops_")

        # Also check context.config for condition_orange (set by CLI --orange flag)
        if not condition_orange and hasattr(context, "config"):
            condition_orange = context.config.get("condition_orange", False)

        try:
            # Step 0: If focus_ips specified, create a filtered session view
            focus_ips_raw = payload.get("focus_ips", "")
            if focus_ips_raw:
                focus_ips = set(
                    ip.strip() for ip in focus_ips_raw.split(",") if ip.strip()
                )
                session = self._filter_session_by_ips(session, focus_ips)
                logger.info("Focus IPs filter: %d IPs → %d conversations",
                            len(focus_ips), len(session.conversations))

            # Step 1: Get static output (OT modes get OT-enriched summary,
            #         NetOps modes get network health summary)
            if is_ot_mode:
                static_output = self._get_ot_static_output(session)
            elif is_netops_mode:
                static_output = self._get_netops_static_output(session)
            else:
                static_output = self._get_static_output(session, mode, payload)

            # Step 1b: Inject BigQuery IP enrichment if available (for LLM only, not display)
            enrichment_block = ""
            try:
                from plugins.network_forensics.pcap_enrichment.tool import (
                    PcapEnrichment,
                )
                enrichment_block = PcapEnrichment.get_enrichment_for_prompt()
            except ImportError:
                pass  # pcap_enrichment not installed — skip silently

            # Step 2: Load investigation context from any markdown/text artifact
            investigation_context = self._load_investigation_context(context)

            # Step 3: Build prompt
            prompt_template, _, system_identity_override = MODE_CONFIG[mode]
            system_identity = system_identity_override or PCAP_SYSTEM_IDENTITY
            alert_condition = self._get_alert_condition(condition_orange)

            # Combine static output + enrichment for LLM (enrichment is LLM-only context)
            llm_data = static_output or ""
            if enrichment_block:
                llm_data += "\n\n" + enrichment_block

            # Debug: log None variables to diagnose format errors
            for _vname, _vval in [("system_identity", system_identity),
                                   ("alert_condition", alert_condition),
                                   ("investigation_context", investigation_context),
                                   ("static_output", static_output)]:
                if _vval is None:
                    logger.warning("Prompt variable '%s' is None — using empty string", _vname)

            prompt = prompt_template.format(
                system_identity=system_identity or "",
                alert_condition=alert_condition or "",
                investigation_context=investigation_context or "",
                pcap_summary_data=llm_data,
            )

            # Inject focus scope instruction when --focus-ips is active
            if focus_ips_raw:
                focus_instruction = (
                    f"\n\n⚠️ SCOPE RESTRICTION: This analysis is STRICTLY limited to the following "
                    f"IP addresses: {focus_ips_raw}\n"
                    f"Do NOT discuss, reference, or analyze any other IPs. "
                    f"All findings, conclusions, and recommendations must relate ONLY to these "
                    f"specific hosts. If an IP not in this list appears in the data, ignore it "
                    f"unless it is a direct communication partner of a focus IP (and even then, "
                    f"frame the finding from the perspective of the focus IP).\n"
                )
                prompt = focus_instruction + prompt

            # Pre-call token estimate:
            # PCAP summaries contain dense structured data (IPs, ports, numbers, JSON)
            # which tokenizes at ~3 chars/token vs ~4 for plain English.
            # Split prompt into template prose vs injected PCAP data for a blended estimate,
            # then apply a 1.4x correction factor — empirically calibrated against actual usage.
            pcap_data_len = len(llm_data)
            prose_len = len(prompt) - pcap_data_len
            est_input_tokens = int(((prose_len // 4) + (pcap_data_len // 3)) * 1.4)
            # Output estimate: structured AI analysis responses run ~50% of input tokens
            est_output_tokens = min(int(est_input_tokens * 0.50), 16384)
            est_total_tokens = est_input_tokens + est_output_tokens
            print(
                f"\n  🔢 Token estimate: ~{est_input_tokens:,} input"
                f" + ~{est_output_tokens:,} output"
                f" = ~{est_total_tokens:,} total (pre-call)"
            )

            # Step 4: Query LLM
            response = context.llm_query.query_text(
                prompt=prompt,
                system_context=system_identity,
                max_tokens=16384,
            )

            # Post-call actuals — compare against estimate
            if response.token_usage:
                actual_in = response.token_usage.get("prompt_tokens", 0)
                actual_out = response.token_usage.get("completion_tokens", 0)
                actual_total = response.token_usage.get("total_tokens", actual_in + actual_out)
                accuracy = (actual_in / est_input_tokens * 100) if est_input_tokens else 0
                print(
                    f"  📊 Actual tokens: {actual_in:,} input + {actual_out:,} output"
                    f" = {actual_total:,} total"
                    f"  (estimate accuracy: {accuracy:.0f}%)"
                )

            if not response.ok:
                return ToolResult(
                    ok=True,
                    result={
                        "mode": mode,
                        "condition_orange": condition_orange,
                        "static_output": static_output,
                        "ai_analysis": None,
                        "combined_output": (
                            static_output + "\n\n[AI Analysis Failed: "
                            + (response.error or "Unknown error") + "]"
                        ),
                    },
                )

            ai_text = response.text or ""
            if is_ot_mode:
                mode_label = "OT/ICS ANALYSIS"
            elif is_netops_mode:
                mode_label = "NETWORK OPERATIONS ANALYSIS"
            else:
                mode_label = "AI ANALYSIS"
            combined = (
                static_output
                + "\n\n" + "=" * 60 + "\n"
                + f"🔍 {mode_label}"
                + (" 🚨 CONDITION ORANGE" if condition_orange else "")
                + "\n" + "=" * 60 + "\n"
                + ai_text
            )

            # Write full output to a markdown file so it's always accessible
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            workspace = Path(os.environ.get("EVENTMILL_WORKSPACE", "./workspace"))
            output_dir = workspace / "artifacts"
            output_dir.mkdir(parents=True, exist_ok=True)
            md_filename = f"pcap_ai_analyzer_{mode}_{ts}.md"
            md_path = output_dir / md_filename
            md_path.write_text(combined, encoding="utf-8")
            print(f"  📄 Full report saved: {md_path}")

            # Optional PDF export
            export_type = payload.get("export_type", "").lower()
            pdf_path = None
            if export_type == "pdf":
                print("  \U0001f4c4 Generating PDF report...", flush=True)
                pdf_path = _export_pdf(
                    combined, output_dir,
                    f"pcap_ai_analyzer_{mode}_{ts}.pdf",
                    mode=mode,
                    condition_orange=condition_orange,
                    session=session,
                )
                if pdf_path:
                    print(f"  \u2705 PDF saved: {pdf_path}", flush=True)

            # Register the markdown file as an artifact
            if hasattr(context, "register_artifact"):
                context.register_artifact(
                    artifact_type="text",
                    file_path=str(md_path),
                    source_tool="pcap_ai_analyzer",
                    metadata={"mode": mode, "condition_orange": condition_orange},
                )
                if pdf_path:
                    context.register_artifact(
                        artifact_type="text",
                        file_path=str(pdf_path),
                        source_tool="pcap_ai_analyzer",
                        metadata={"mode": mode, "condition_orange": condition_orange, "format": "pdf"},
                    )

            return ToolResult(
                ok=True,
                result={
                    "mode": mode,
                    "condition_orange": condition_orange,
                    "static_output": static_output,
                    "ai_analysis": ai_text,
                    "combined_output": combined,
                },
            )

        except Exception as e:
            import traceback as _tb
            tb_str = _tb.format_exc()
            logger.error("AI analysis failed: %s\n%s", e, tb_str)
            # Include traceback in the message so the CLI shows the exact location
            return ToolResult(ok=False, error_code="INTERNAL_ERROR", message=f"{e}\n{tb_str}")

    def summarize_for_llm(self, result: ToolResult) -> str:
        if not result.ok:
            return f"pcap_ai_analyzer failed: {result.message}"

        data = result.result or {}
        # Show the full combined output (static data + AI analysis) to the user
        combined = data.get("combined_output", "")
        if combined:
            return combined

        mode = data.get("mode", "?")
        orange = " [CONDITION ORANGE]" if data.get("condition_orange") else ""
        return f"pcap_ai_analyzer {mode}{orange}: AI analysis not available."

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _filter_session_by_ips(session, focus_ips: set[str]):
        """Create a filtered copy of the session containing only data involving focus_ips.

        Returns a shallow-copied PcapSession where conversations, DNS, TLS, HTTP,
        OT transactions, and other per-IP data are filtered to only include entries
        where at least one of the focus_ips is involved.
        """
        import copy
        from plugins.network_forensics.pcap_metadata_summary.tool import PcapSession

        filtered = copy.copy(session)

        # Conversations: keep only flows where src or dst is in focus_ips
        filtered.conversations = {}
        for key, stats in session.conversations.items():
            src, dst = key[0], key[1]
            if src in focus_ips or dst in focus_ips:
                filtered.conversations[key] = stats

        # Recalculate IP counters from filtered conversations
        from collections import Counter, defaultdict
        filtered.src_ips = Counter()
        filtered.dst_ips = Counter()
        for (src, dst, dport, proto), stats in filtered.conversations.items():
            filtered.src_ips[src] += stats.get("packets", 1)
            filtered.dst_ips[dst] += stats.get("packets", 1)

        # DNS queries/responses
        filtered.dns_queries = [
            q for q in session.dns_queries
            if q.get("src") in focus_ips or q.get("dst") in focus_ips
        ]
        filtered.dns_responses = [
            r for r in session.dns_responses
            if r.get("src") in focus_ips or r.get("dst") in focus_ips
        ]

        # TLS handshakes
        filtered.tls_handshakes = [
            t for t in session.tls_handshakes
            if t.get("src") in focus_ips or t.get("dst") in focus_ips
        ]

        # HTTP requests
        filtered.http_requests = [
            h for h in session.http_requests
            if h.get("src") in focus_ips or h.get("dst") in focus_ips
        ]

        # OT transactions
        filtered.ot_transactions = [
            t for t in session.ot_transactions
            if t.get("src") in focus_ips or t.get("dst") in focus_ips
        ]

        # Cleartext credentials
        filtered.cleartext_creds = [
            c for c in session.cleartext_creds
            if c.get("src") in focus_ips or c.get("dst") in focus_ips
        ]

        # ICMP errors
        filtered.icmp_errors = [
            e for e in session.icmp_errors
            if e.get("src") in focus_ips or e.get("dst") in focus_ips
        ]

        # HSRP / VRRP events
        filtered.hsrp_events = [
            e for e in session.hsrp_events if e.get("src") in focus_ips
        ]
        filtered.vrrp_events = [
            e for e in session.vrrp_events if e.get("src") in focus_ips
        ]

        # SSH sessions
        filtered.ssh_sessions = [
            s for s in session.ssh_sessions
            if s.get("src") in focus_ips or s.get("dst") in focus_ips
        ]

        # Kerberos / NTLM / SMB / LDAP / DCE-RPC
        for attr in ("kerberos_tickets", "ntlm_auths", "smb_mappings",
                      "smb_files", "dce_rpc_calls", "ldap_operations"):
            filtered_list = [
                e for e in getattr(session, attr, [])
                if e.get("src") in focus_ips or e.get("dst") in focus_ips
            ]
            setattr(filtered, attr, filtered_list)

        # Conv health
        filtered.conv_health = defaultdict(lambda: {"rst": 0, "retransmit": 0, "zero_window": 0})
        for key, health in session.conv_health.items():
            src, dst = key[0], key[1]
            if src in focus_ips or dst in focus_ips:
                filtered.conv_health[key] = health

        # Update filename to indicate filtering
        ip_list = ", ".join(sorted(focus_ips)[:5])
        if len(focus_ips) > 5:
            ip_list += f" (+{len(focus_ips) - 5} more)"
        filtered.filename = f"{session.filename} [focus: {ip_list}]"

        return filtered

    @staticmethod
    def _load_investigation_context(context: Any) -> str:
        """Return an INVESTIGATION CONTEXT block if a markdown/text artifact is loaded.

        Looks for text artifacts (loaded via 'load notes.md') whose filename ends
        in .md, .markdown, or .txt.  Returns an empty string if nothing is found
        so the prompt placeholder is safely replaced with nothing.
        """
        if not context or not hasattr(context, "artifacts"):
            return ""

        md_exts = {".md", ".markdown", ".txt"}
        loaded: list[tuple[str, str]] = []  # (filename, content)
        seen_paths: set[str] = set()  # deduplicate by resolved file path

        for artifact in context.artifacts:
            if getattr(artifact, "artifact_type", "") != "text":
                continue
            file_path = getattr(artifact, "file_path", None)
            if not file_path:
                continue
            import os
            resolved = os.path.realpath(file_path)
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in md_exts:
                continue
            try:
                with open(file_path, "r", encoding="utf-8") as fh:
                    content = fh.read().strip()
                if content:
                    loaded.append((os.path.basename(file_path), content))
            except Exception:
                pass  # Silently skip unreadable files

        if not loaded:
            return ""

        # --- Parse for known organization IP ranges ---
        # If the context file has a section headed with words like
        # "Known Organization Public IP Ranges", IPs/CIDRs listed
        # beneath it are registered so is_internal() treats them as
        # trusted internal assets (suppresses false-positive EXT alerts).
        import re as _re
        import ipaddress as _ipa
        _org_nets: list = []
        for _fn, _fc in loaded:
            _in_org = False
            for _line in _fc.split('\n'):
                _s = _line.strip()
                if _s.startswith('#'):
                    _h = _s.lower()
                    _in_org = (
                        any(w in _h for w in
                            ['public', 'organization', 'corporate'])
                        and any(w in _h for w in ['ip', 'network', 'range'])
                    )
                    continue
                if not _in_org:
                    continue
                if not _s or _s.startswith('|--') or _s.startswith('|-'):
                    continue
                _clean = _s.strip('|').strip()
                _m = _re.search(
                    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)',
                    _clean)
                if _m:
                    _ip = _m.group(1)
                    try:
                        if '/' in _ip:
                            _org_nets.append(
                                _ipa.ip_network(_ip, strict=False))
                        else:
                            _org_nets.append(
                                _ipa.ip_network(f"{_ip}/32"))
                    except ValueError:
                        pass

        if _org_nets:
            from plugins.network_forensics.pcap_metadata_summary.tool import (
                register_org_networks,
            )
            register_org_networks(_org_nets)
            _rs = [str(n) for n in _org_nets]
            print(f"  \U0001f3e2 Registered {len(_org_nets)} organization IP "
                  f"range(s): {', '.join(_rs[:5])}"
                  + (f" (+{len(_rs)-5} more)" if len(_rs) > 5 else ""))

        parts = ["INVESTIGATION CONTEXT (analyst-provided notes):"]
        for filename, content in loaded:
            parts.append(f"--- {filename} ---")
            parts.append(content)
        if _org_nets:
            parts.append(
                "--- KNOWN ORGANIZATION IP RANGES ---")
            parts.append(
                "IMPORTANT: The following IP ranges are OWNED BY THIS ORGANIZATION. "
                "They are NOT external threats. Classify them as INTERNAL/ORG. "
                "Do NOT flag them as external-to-internal zone violations.")
            parts.append(", ".join(str(n) for n in _org_nets))
        parts.append("--- END INVESTIGATION CONTEXT ---\n")
        block = "\n".join(parts) + "\n"

        filenames = ", ".join(f for f, _ in loaded)
        print(f"  📋 Investigation context loaded: {filenames}")
        return block

    @staticmethod
    def _get_alert_condition(condition_orange: bool) -> str:
        if condition_orange:
            return (
                "\n🚨 CONDITION ORANGE ACTIVE: The organization is in a heightened state of alert. "
                "Be highly paranoid. Flag even slightly anomalous behavior as potentially malicious. "
                "Connect weak signals and assume the worst-case scenario.\n"
            )
        return (
            "\n✅ NORMAL CONDITION: Base your analysis strictly on clear evidence. "
            "Do not inflate severity. Normal traffic should be reported as normal. "
            "If there is no solid evidence of a threat, state so clearly — a clean report is a valid outcome.\n"
        )

    @staticmethod
    def _get_static_output(session: Any, mode: str, payload: dict) -> str:
        """Run the underlying static analysis tool and get its text output."""
        _, hunt_type, _ = MODE_CONFIG[mode]

        # Build PCAP context header — always included
        header = PcapAiAnalyzer._build_pcap_header(session)

        if hunt_type is None:
            # triage_summary and report modes — comprehensive overview
            return PcapAiAnalyzer._build_comprehensive_summary(session, header)

        # Hunt-specific modes — PCAP header + hunt output
        from plugins.network_forensics.pcap_threat_hunter.tool import PcapThreatHunter

        hunter = PcapThreatHunter()
        hunt_payload = {"hunt": hunt_type}
        if payload.get("hunt_payload"):
            hunt_payload.update(payload["hunt_payload"])

        result = hunter.execute(hunt_payload, None)
        hunt_text = ""
        if result.ok and result.result:
            hunt_text = result.result.get("summary_text", "No output.")
        else:
            hunt_text = f"Hunt '{hunt_type}' failed: {result.message}"

        return header + "\n\n" + hunt_text

    @staticmethod
    def _get_ot_static_output(session: Any) -> str:
        """Build OT/ICS-focused static summary for OT analysis modes."""
        from plugins.network_forensics.pcap_metadata_summary.tool import (
            is_internal, _format_bytes, _OT_PORT_PROTOCOL,
            _MODBUS_FUNC_NAMES,
        )
        from plugins.network_forensics.pcap_threat_hunter.tool import PcapThreatHunter
        from collections import Counter, defaultdict

        lines = []

        # --- Standard PCAP header ---
        header = PcapAiAnalyzer._build_pcap_header(session)
        lines.append(header)

        # Note: Enrichment data (asset names, Purdue levels, OS, zones) is
        # injected into the LLM prompt separately via get_enrichment_for_prompt()
        # and used by the Purdue zone classifier. It is NOT rendered in the
        # static report to keep it concise.

        # --- OT Protocol Summary ---
        ot = session.ot_transactions
        if ot:
            lines.append(f"\n{'=' * 60}")
            lines.append("OT / ICS PROTOCOL ACTIVITY")
            lines.append(f"{'=' * 60}")

            ot_protos = Counter(t["protocol"] for t in ot)
            lines.append(f"\nTotal OT transactions: {len(ot):,}")
            lines.append("\nProtocol breakdown:")
            for proto, cnt in ot_protos.most_common():
                lines.append(f"  {proto:<18} {cnt:>6,} transactions")

            # Unique OT endpoints
            ot_sources = set(t["src"] for t in ot)
            ot_dests = set(t["dst"] for t in ot)
            ot_endpoints = ot_sources | ot_dests
            int_ot = [ip for ip in ot_endpoints if is_internal(ip)]
            ext_ot = [ip for ip in ot_endpoints if not is_internal(ip)]
            lines.append(f"\nOT endpoints: {len(ot_endpoints)} total "
                         f"({len(int_ot)} internal, {len(ext_ot)} external)")
            if ext_ot:
                lines.append(f"  ⚠️  EXTERNAL IPs on OT protocols: {', '.join(sorted(ext_ot)[:10])}")

            # Write operations
            writes = [t for t in ot if t.get("is_write")]
            if writes:
                lines.append(f"\n🔶 WRITE OPERATIONS: {len(writes):,}")
                lines.append("-" * 60)
                write_by_src = defaultdict(list)
                for w in writes:
                    write_by_src[w["src"]].append(w)
                for src, ws in sorted(write_by_src.items(), key=lambda x: len(x[1]), reverse=True)[:15]:
                    dsts = sorted(set(w["dst"] for w in ws))
                    protos = sorted(set(w["protocol"] for w in ws))
                    func_names = sorted(set(w.get("function_name", "?") for w in ws))
                    lines.append(
                        f"  {src} → {', '.join(dsts[:5])} | "
                        f"{', '.join(protos)} | {len(ws)} writes | "
                        f"Functions: {', '.join(func_names[:5])}"
                    )

            # Control commands (PLC stop/start/restart, direct operate)
            controls = [t for t in ot if t.get("is_control")]
            if controls:
                lines.append(f"\n🔴 CONTROL COMMANDS: {len(controls):,}")
                lines.append("-" * 60)
                for c in controls[:20]:
                    func = c.get("function_name") or c.get("function", "?")
                    lines.append(
                        f"  {c['src']} → {c['dst']}:{c.get('port', '?')} ({c['protocol']}) "
                        f"— {func}"
                    )

            # Exception responses
            exceptions = [t for t in ot if t.get("is_exception")]
            if exceptions:
                lines.append(f"\n⚠️  EXCEPTION RESPONSES: {len(exceptions):,}")
                lines.append("-" * 60)
                exc_by_func = Counter(
                    (t.get("function_name", "?"), t.get("exception_code", "?"))
                    for t in exceptions
                )
                for (func, exc_code), cnt in exc_by_func.most_common(10):
                    lines.append(f"  {func} exception code={exc_code} — {cnt} occurrence(s)")

            # Diagnostic/firmware commands
            diags = [t for t in ot if t.get("is_diagnostic")]
            if diags:
                lines.append(f"\n⚠️  DIAGNOSTIC COMMANDS: {len(diags):,}")
                lines.append("-" * 60)
                for d in diags[:10]:
                    func = d.get("function_name", "?")
                    lines.append(
                        f"  {d['src']} → {d['dst']}:{d.get('port', '?')} ({d['protocol']}) — {func}"
                    )

            # Per-protocol function code distribution (Modbus detail)
            modbus_txns = [t for t in ot if t["protocol"] == "Modbus" and t.get("function_code") is not None]
            if modbus_txns:
                lines.append(f"\nModbus Function Code Distribution ({len(modbus_txns):,} parsed):")
                func_dist = Counter(
                    (t["function_code"], t.get("function_name", "?"))
                    for t in modbus_txns
                )
                for (fc, fname), cnt in func_dist.most_common():
                    marker = " ⚠️ WRITE" if fc in {5, 6, 15, 16, 22, 23} else ""
                    marker = " 🔴 DIAG" if fc in {8, 43} else marker
                    lines.append(f"  FC {fc:>3} ({fname:<28}) {cnt:>6,}{marker}")

            # Modbus unit IDs seen
            unit_ids = sorted(set(t.get("unit_id", -1) for t in modbus_txns if "unit_id" in t))
            if unit_ids:
                lines.append(f"\nModbus Unit IDs: {', '.join(str(u) for u in unit_ids[:30])}")

        else:
            lines.append(f"\n{'=' * 60}")
            lines.append("OT / ICS PROTOCOL ACTIVITY")
            lines.append(f"{'=' * 60}")
            lines.append("No OT/ICS protocol transactions detected in this capture.")
            lines.append("(Checked ports: " + ", ".join(
                f"{p}/{n}" for p, n in sorted(_OT_PORT_PROTOCOL.items())
            ) + ")")

        # --- Cleartext Credentials ---
        creds = session.cleartext_creds
        if creds:
            lines.append(f"\n{'=' * 60}")
            lines.append(f"⚠️  CLEARTEXT CREDENTIALS DETECTED: {len(creds)} instance(s)")
            lines.append(f"{'=' * 60}")
            cred_by_proto = defaultdict(list)
            for c in creds:
                cred_by_proto[c["protocol"]].append(c)
            for proto, detections in sorted(cred_by_proto.items(), key=lambda x: len(x[1]), reverse=True):
                src_dst_pairs = sorted(set((d["src"], d["dst"]) for d in detections))
                desc = detections[0].get("description", "")
                lines.append(
                    f"  {proto:<22} {len(detections):>4} detection(s)  — {desc}"
                )
                for src, dst in src_dst_pairs[:5]:
                    lines.append(f"    {src} → {dst}")
                if len(src_dst_pairs) > 5:
                    lines.append(f"    ... +{len(src_dst_pairs) - 5} more pairs")

        # --- SCADA Message Bus Tag Data ---
        if hasattr(session, "scada_tags") and session.scada_tags:
            lines.append(f"\n{'=' * 60}")
            lines.append("SCADA MESSAGE BUS TAG DATA (OASyS / AMQP)")
            lines.append(f"{'=' * 60}")
            lines.append(f"Unique tags: {len(session.scada_tags):,}")
            if hasattr(session, "scada_tag_sources") and session.scada_tag_sources:
                src_hosts = sorted(session.scada_tag_sources.keys())[:10]
                lines.append(f"Source hosts: {', '.join(src_hosts)}")
            lines.append("")
            # Table header
            lines.append(f"  {'Tag Name':<55s} {'Msgs':>6s}  {'Quality':<8s}  {'Sample Values'}")
            lines.append(f"  {'─' * 55} {'─' * 6}  {'─' * 8}  {'─' * 40}")
            for tag_name, info in sorted(session.scada_tags.items(),
                                         key=lambda x: x[1]["count"], reverse=True)[:30]:
                vals = info.get("values_sample", [])
                val_str = ", ".join(str(v) for v in vals[:3]) if vals else "—"
                quality = info.get("quality", "?")
                lines.append(
                    f"  {tag_name:<55s} {info['count']:>6,}  {quality:<8s}  {val_str}"
                )

        # --- Syslog Summary ---
        if hasattr(session, "syslog_total") and session.syslog_total:
            lines.append(f"\n{'=' * 60}")
            lines.append("SYSLOG SUMMARY")
            lines.append(f"{'=' * 60}")
            lines.append(f"Total messages: {session.syslog_total:,}")
            if session.syslog_sources:
                lines.append(f"Sources: {', '.join(sorted(session.syslog_sources.keys())[:10])}")
            if session.syslog_severity:
                from plugins.network_forensics.pcap_metadata_summary.tool import _SYSLOG_SEVERITY
                sev_strs = [f"{_SYSLOG_SEVERITY.get(k, str(k))}={v:,}"
                            for k, v in session.syslog_severity.most_common()]
                lines.append(f"Severity: {', '.join(sev_strs)}")
            if session.syslog_patterns:
                pat_strs = [f"{k}={v:,}" for k, v in session.syslog_patterns.most_common()]
                lines.append(f"Patterns: {', '.join(pat_strs)}")

        # --- SNMP Activity ---
        if hasattr(session, "snmp_sources") and session.snmp_sources:
            lines.append(f"\nSNMP: {sum(session.snmp_sources.values()):,} packets from "
                         f"{len(session.snmp_sources)} hosts")
            if session.snmp_communities:
                lines.append(f"  Communities: {', '.join(session.snmp_communities.keys())}")

        # --- SSH Sessions ---
        if hasattr(session, "ssh_sessions") and session.ssh_sessions:
            lines.append(f"\nSSH: {len(session.ssh_sessions)} sessions detected")
            banners = set(s.get("banner", "") for s in session.ssh_sessions if s.get("banner"))
            if banners:
                lines.append(f"  Banners: {', '.join(sorted(banners)[:5])}")

        # --- VLAN Tagging Analysis ---
        vlan_analysis = PcapAiAnalyzer._analyze_vlan_configuration(session)
        if vlan_analysis:
            lines.append(f"\n{'=' * 60}")
            lines.append("VLAN CONFIGURATION ANALYSIS")
            lines.append(f"{'=' * 60}")
            lines.append(vlan_analysis)

        # --- Protocol Security Analysis ---
        protocol_sec = PcapAiAnalyzer._analyze_protocol_security(session)
        if protocol_sec:
            lines.append(f"\n{'=' * 60}")
            lines.append("PROTOCOL SECURITY ANALYSIS")
            lines.append(f"{'=' * 60}")
            lines.append(protocol_sec)

        # --- Cryptographic Weakness Detection ---
        crypto_weak = PcapAiAnalyzer._analyze_cryptographic_weaknesses(session)
        if crypto_weak:
            lines.append(f"\n{'=' * 60}")
            lines.append("CRYPTOGRAPHIC WEAKNESS DETECTION")
            lines.append(f"{'=' * 60}")
            lines.append(crypto_weak)

        # --- Standard IT hunts (beacons, lateral, exfil) ---
        hunter = PcapThreatHunter()

        beacons_result = hunter.execute({"hunt": "beacons"}, None)
        if beacons_result.ok and beacons_result.result:
            beacon_text = beacons_result.result.get("summary_text", "")
            if beacon_text and "No C2 beaconing" not in beacon_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("C2 Beaconing Detection")
                lines.append(f"{'=' * 60}")
                lines.append(beacon_text)

        lateral_result = hunter.execute({"hunt": "lateral"}, None)
        if lateral_result.ok and lateral_result.result:
            lateral_text = lateral_result.result.get("summary_text", "")
            if lateral_text and "No lateral movement" not in lateral_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Lateral Movement & ICS Cross-Zone")
                lines.append(f"{'=' * 60}")
                lines.append(lateral_text)

        # --- External Communications Summary ---
        ext_flows: list[dict] = []
        for (src, dst, dport, proto), stats in session.conversations.items():
            src_int = is_internal(src)
            dst_int = is_internal(dst)
            if src_int and not dst_int:
                ext_flows.append({
                    "src": src, "dst": dst, "dport": dport, "proto": proto,
                    "direction": "INT->EXT",
                    "bytes": stats["bytes_out"], "packets": stats["packets"],
                })
            elif not src_int and dst_int:
                ext_flows.append({
                    "src": src, "dst": dst, "dport": dport, "proto": proto,
                    "direction": "EXT->INT",
                    "bytes": stats["bytes_out"], "packets": stats["packets"],
                })

        if ext_flows:
            lines.append(f"\n{'=' * 60}")
            lines.append("External Communications")
            lines.append(f"{'=' * 60}")

            total_ext_bytes = sum(f["bytes"] for f in ext_flows)
            int_to_ext = [f for f in ext_flows if f["direction"] == "INT->EXT"]
            ext_to_int = [f for f in ext_flows if f["direction"] == "EXT->INT"]
            unique_ext_ips = set()
            for f in ext_flows:
                if f["direction"] == "INT->EXT":
                    unique_ext_ips.add(f["dst"])
                else:
                    unique_ext_ips.add(f["src"])
            unique_int_ips = set()
            for f in ext_flows:
                if f["direction"] == "INT->EXT":
                    unique_int_ips.add(f["src"])
                else:
                    unique_int_ips.add(f["dst"])

            lines.append(f"\nTotal external flows: {len(ext_flows):,} "
                         f"({_format_bytes(total_ext_bytes)})")
            lines.append(f"  INT -> EXT: {len(int_to_ext):,} flows "
                         f"({_format_bytes(sum(f['bytes'] for f in int_to_ext))})")
            lines.append(f"  EXT -> INT: {len(ext_to_int):,} flows "
                         f"({_format_bytes(sum(f['bytes'] for f in ext_to_int))})")
            lines.append(f"  Unique external IPs: {len(unique_ext_ips)}")
            lines.append(f"  Internal hosts with external comms: {len(unique_int_ips)}")

            # Top external destinations by bytes
            ext_dst_bytes: dict[str, int] = defaultdict(int)
            ext_dst_flows: dict[str, int] = defaultdict(int)
            ext_dst_ports: dict[str, set] = defaultdict(set)
            for f in int_to_ext:
                ext_dst_bytes[f["dst"]] += f["bytes"]
                ext_dst_flows[f["dst"]] += 1
                ext_dst_ports[f["dst"]].add(f["dport"])

            if ext_dst_bytes:
                lines.append(f"\n🌐 TOP EXTERNAL DESTINATIONS (by bytes) — {len(ext_dst_bytes)} total")
                lines.append("-" * 70)
                sorted_ext = sorted(ext_dst_bytes.items(), key=lambda x: x[1], reverse=True)
                for ip, total in sorted_ext[:15]:
                    ports = sorted(ext_dst_ports[ip])
                    port_str = ", ".join(str(p) for p in ports[:5])
                    if len(ports) > 5:
                        port_str += f" (+{len(ports)-5})"
                    lines.append(
                        f"  {ip:<18} {_format_bytes(total):<12} "
                        f"flows={ext_dst_flows[ip]:<6} ports: {port_str}"
                    )

            # Top external sources (EXT→INT)
            ext_src_bytes: dict[str, int] = defaultdict(int)
            ext_src_flows: dict[str, int] = defaultdict(int)
            ext_src_ports: dict[str, set] = defaultdict(set)
            for f in ext_to_int:
                ext_src_bytes[f["src"]] += f["bytes"]
                ext_src_flows[f["src"]] += 1
                ext_src_ports[f["src"]].add(f["dport"])

            if ext_src_bytes:
                lines.append(f"\n🌐 TOP EXTERNAL SOURCES (inbound) — {len(ext_src_bytes)} total")
                lines.append("-" * 70)
                sorted_src = sorted(ext_src_bytes.items(), key=lambda x: x[1], reverse=True)
                for ip, total in sorted_src[:15]:
                    ports = sorted(ext_src_ports[ip])
                    port_str = ", ".join(str(p) for p in ports[:5])
                    if len(ports) > 5:
                        port_str += f" (+{len(ports)-5})"
                    lines.append(
                        f"  {ip:<18} {_format_bytes(total):<12} "
                        f"flows={ext_src_flows[ip]:<6} ports: {port_str}"
                    )

            # Internal hosts with most external communication
            int_ext_bytes: dict[str, int] = defaultdict(int)
            int_ext_peers: dict[str, set] = defaultdict(set)
            for f in ext_flows:
                if f["direction"] == "INT->EXT":
                    int_ext_bytes[f["src"]] += f["bytes"]
                    int_ext_peers[f["src"]].add(f["dst"])
                else:
                    int_ext_bytes[f["dst"]] += f["bytes"]
                    int_ext_peers[f["dst"]].add(f["src"])

            if int_ext_bytes:
                lines.append(f"\n🏢 INTERNAL HOSTS WITH MOST EXTERNAL TRAFFIC")
                lines.append("-" * 70)
                sorted_int = sorted(int_ext_bytes.items(), key=lambda x: x[1], reverse=True)
                for ip, total in sorted_int[:10]:
                    peer_count = len(int_ext_peers[ip])
                    lines.append(
                        f"  {ip:<18} {_format_bytes(total):<12} "
                        f"external peers: {peer_count}"
                    )

        ports_result = hunter.execute({"hunt": "ports"}, None)
        if ports_result.ok and ports_result.result:
            port_text = ports_result.result.get("summary_text", "")
            if port_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Port Analysis")
                lines.append(f"{'=' * 60}")
                lines.append(port_text)

        return "\n".join(lines)

    @staticmethod
    def _analyze_protocol_security(session: Any) -> str:
        """Detect weak and deprecated protocol versions (SMBv1, TLS 1.0, etc.)."""
        from collections import Counter, defaultdict
        from plugins.network_forensics.pcap_metadata_summary.tool import (
            is_internal, _format_bytes,
        )
        findings = []

        # --- SMB Protocol Detection ---
        if hasattr(session, "smb_mappings") and session.smb_mappings:
            smb_count = len(session.smb_mappings)
            findings.append(f"\n⚠️  SMB Traffic Detected: {smb_count} SMB operations")
            findings.append(f"  Risk: Verify SMB protocol version (SMBv1 is DEPRECATED and HIGH RISK)")
            # Top SMB communication pairs by volume
            smb_pairs: Counter = Counter()
            for s in session.smb_mappings:
                smb_pairs[(s["src"], s["dst"])] += 1
            findings.append(f"\n  Top SMB Communications (src -> dst):")
            for (src, dst), cnt in smb_pairs.most_common(10):
                src_loc = "INT" if is_internal(src) else "EXT"
                dst_loc = "INT" if is_internal(dst) else "EXT"
                findings.append(f"    {src} ({src_loc}) -> {dst} ({dst_loc})  [{cnt} ops]")
            # Unique SMB servers
            smb_servers = set(s["dst"] for s in session.smb_mappings)
            findings.append(f"  SMB Servers ({len(smb_servers)}): {', '.join(sorted(smb_servers)[:10])}")
            # Unique SMB clients
            smb_clients = set(s["src"] for s in session.smb_mappings)
            findings.append(f"  SMB Clients ({len(smb_clients)}): {', '.join(sorted(smb_clients)[:10])}")

        # --- TLS/SSL Protocol Version Detection ---
        if hasattr(session, "tls_handshakes") and session.tls_handshakes:
            tls_count = len(session.tls_handshakes)
            findings.append(f"\n🔒 TLS/SSL Handshakes Detected: {tls_count} sessions")
            findings.append(f"  Note: Verify protocol versions (TLS 1.0/1.1 are DEPRECATED, use TLS 1.2+)")
            # Top TLS communication pairs
            tls_pairs: Counter = Counter()
            for th in session.tls_handshakes:
                tls_pairs[(th.get("src", "?"), th.get("dst", "?"), th.get("dport", 0))] += 1
            findings.append(f"\n  Top TLS Communications (src -> dst:port):")
            for (src, dst, dport), cnt in tls_pairs.most_common(10):
                src_loc = "INT" if is_internal(src) else "EXT"
                dst_loc = "INT" if is_internal(dst) else "EXT"
                sni_list = [th.get("sni", "") for th in session.tls_handshakes
                            if th.get("src") == src and th.get("dst") == dst and th.get("dport") == dport]
                sni = next((s for s in sni_list if s), "")
                sni_str = f" [{sni}]" if sni else ""
                findings.append(f"    {src} ({src_loc}) -> {dst}:{dport} ({dst_loc})  [{cnt} sessions]{sni_str}")

        # --- RDP Detection (port 3389) ---
        rdp_flows = []
        for (src, dst, dport, proto), stats in session.conversations.items():
            if dport == 3389:
                rdp_flows.append((src, dst, stats["packets"], stats["bytes_out"]))
        if rdp_flows:
            findings.append(f"\n⚠️  RDP (Remote Desktop) Traffic Detected: {len(rdp_flows)} flows")
            findings.append(f"  Risk: RDP port 3389 should be restricted; verify encryption levels")
            rdp_flows.sort(key=lambda x: x[3], reverse=True)
            findings.append(f"\n  Top RDP Communications (src -> dst):")
            for src, dst, pkts, bytes_out in rdp_flows[:10]:
                src_loc = "INT" if is_internal(src) else "EXT"
                dst_loc = "INT" if is_internal(dst) else "EXT"
                findings.append(
                    f"    {src} ({src_loc}) -> {dst}:3389 ({dst_loc})  "
                    f"[{pkts} pkts, {_format_bytes(bytes_out)}]"
                )

        # --- HTTP (Cleartext) Detection ---
        if hasattr(session, "http_requests") and session.http_requests:
            findings.append(f"\n⚠️  Cleartext HTTP Traffic: {len(session.http_requests)} requests")
            findings.append(f"  Risk: Credentials and sensitive data may be visible in cleartext")
            # Top HTTP communication pairs
            http_pairs: Counter = Counter()
            for r in session.http_requests:
                http_pairs[(r.get("src", "?"), r.get("host", "?"))] += 1
            findings.append(f"\n  Top HTTP Communications (src -> host):")
            for (src, host), cnt in http_pairs.most_common(10):
                src_loc = "INT" if is_internal(src) else "EXT"
                findings.append(f"    {src} ({src_loc}) -> {host}  [{cnt} requests]")

        if not findings:
            return ""
        return "\n".join(findings)

    @staticmethod
    def _analyze_cryptographic_weaknesses(session: Any) -> str:
        """Detect weak ciphers, deprecated algorithms, and crypto risks."""
        from collections import Counter, defaultdict
        from plugins.network_forensics.pcap_metadata_summary.tool import is_internal
        findings = []

        # --- TLS Cipher Analysis ---
        if hasattr(session, "tls_handshakes") and session.tls_handshakes:
            findings.append(f"\n🔍 TLS Cipher Suite Analysis (Requires Deep Packet Inspection):")
            findings.append(f"  {len(session.tls_handshakes)} TLS handshakes detected")
            # Top TLS servers that should be audited
            tls_servers: Counter = Counter()
            for th in session.tls_handshakes:
                dst = th.get("dst", "?")
                dport = th.get("dport", 0)
                tls_servers[(dst, dport)] += 1
            findings.append(f"\n  Top TLS Servers to Audit for Cipher Strength:")
            for (dst, dport), cnt in tls_servers.most_common(10):
                loc = "INT" if is_internal(dst) else "EXT"
                sni_list = [th.get("sni", "") for th in session.tls_handshakes
                            if th.get("dst") == dst and th.get("dport") == dport]
                sni = next((s for s in sni_list if s), "")
                sni_str = f" [{sni}]" if sni else ""
                findings.append(f"    {dst}:{dport} ({loc})  [{cnt} sessions]{sni_str}")
            findings.append(f"\n  ⚠️  RECOMMENDATIONS:")
            findings.append(f"  • Verify NO weak ciphers: RC4, DES, MD5-based, NULL ciphers, ANON ciphers")
            findings.append(f"  • Enforce TLS 1.2+ (deprecated: TLS 1.0, 1.1, SSL 3.0)")
            findings.append(f"  • Prefer modern ciphers: ChaCha20-Poly1305, ECDHE, AES-GCM")
            findings.append(f"  • Disable: MD5 hashes, DH with <2048 bits, RSA <2048 bits")

        # --- SNMP Community Strings (Cleartext) ---
        if hasattr(session, "snmp_communities") and session.snmp_communities:
            findings.append(f"\n⚠️  SNMP Cleartext Community Strings Exposed:")
            findings.append(f"  {len(session.snmp_communities)} unique communities detected")
            findings.append(f"  Communities: {', '.join(list(session.snmp_communities.keys())[:5])}")
            findings.append(f"  Risk: SNMPv1/v2c transmit credentials in CLEARTEXT")
            # Show SNMP hosts
            if hasattr(session, "snmp_sources") and session.snmp_sources:
                findings.append(f"\n  Top SNMP Sources (hosts using cleartext SNMP):")
                for ip, cnt in session.snmp_sources.most_common(10):
                    loc = "INT" if is_internal(ip) else "EXT"
                    findings.append(f"    {ip} ({loc})  [{cnt} packets]")
            # Show SNMP destinations from conversations
            snmp_dsts: Counter = Counter()
            for (src, dst, dport, proto), stats in session.conversations.items():
                if dport == 161 or dport == 162:
                    snmp_dsts[dst] += stats["packets"]
            if snmp_dsts:
                findings.append(f"\n  Top SNMP Destinations (managed devices):")
                for ip, cnt in snmp_dsts.most_common(10):
                    loc = "INT" if is_internal(ip) else "EXT"
                    findings.append(f"    {ip} ({loc})  [{cnt} packets]")
            findings.append(f"  Recommendation: Migrate to SNMPv3 with authentication and encryption")

        # --- Kerberos Cipher Detection ---
        if hasattr(session, "kerberos_tickets") and session.kerberos_tickets:
            cipher_types = set()
            for kt in session.kerberos_tickets:
                if kt.get("cipher"):
                    cipher_types.add(kt.get("cipher"))
            if cipher_types:
                findings.append(f"\n🔐 Kerberos Ciphers Detected: {', '.join(sorted(cipher_types))}")
                # Weak Kerberos ciphers: RC4, DES, MD5
                weak_ciphers = [c for c in cipher_types if any(x in c.upper() for x in ["RC4", "DES", "MD5"])]
                if weak_ciphers:
                    findings.append(f"  ⚠️  WEAK KERBEROS CIPHERS DETECTED: {', '.join(weak_ciphers)}")
                    findings.append(f"  Recommendation: Disable weak ciphers; prefer AES-SHA256")
                # Show Kerberos hosts
                kerb_pairs: Counter = Counter()
                for kt in session.kerberos_tickets:
                    kerb_pairs[(kt.get("src", "?"), kt.get("dst", "?"))] += 1
                findings.append(f"\n  Top Kerberos Communications (client -> KDC):")
                for (src, dst), cnt in kerb_pairs.most_common(10):
                    src_loc = "INT" if is_internal(src) else "EXT"
                    dst_loc = "INT" if is_internal(dst) else "EXT"
                    findings.append(f"    {src} ({src_loc}) -> {dst} ({dst_loc})  [{cnt} tickets]")

        # --- Cleartext Credentials Risk ---
        if hasattr(session, "cleartext_creds") and session.cleartext_creds:
            findings.append(f"\n🔓 CLEARTEXT CREDENTIALS: {len(session.cleartext_creds)} detections")
            findings.append(f"  Crypto Risk: Credentials visible in plaintext protocol traffic")
            # Show which hosts are exposed
            cred_pairs: Counter = Counter()
            cred_protos: dict[tuple, set] = defaultdict(set)
            for c in session.cleartext_creds:
                pair = (c.get("src", "?"), c.get("dst", "?"))
                cred_pairs[pair] += 1
                cred_protos[pair].add(c.get("protocol", "?"))
            findings.append(f"\n  Top Cleartext Credential Exposures (src -> dst):")
            for (src, dst), cnt in cred_pairs.most_common(10):
                src_loc = "INT" if is_internal(src) else "EXT"
                dst_loc = "INT" if is_internal(dst) else "EXT"
                protos = ", ".join(sorted(cred_protos[(src, dst)]))
                findings.append(
                    f"    {src} ({src_loc}) -> {dst} ({dst_loc})  [{cnt} creds] ({protos})"
                )
            findings.append(f"  Recommendation: Enforce encrypted protocols (SSH, HTTPS, TLS)")

        if not findings:
            findings.append("\nNo obvious cryptographic weaknesses detected in baseline analysis.")
            findings.append("Recommend performing full TLS handshake inspection with deep packet analysis.")

        return "\n".join(findings)

    @staticmethod
    def _analyze_vlan_configuration(session: Any) -> str:
        """Analyze VLAN tagging configuration for OT/ICS security issues."""
        findings = []

        has_802_1q = hasattr(session, "vlan_ids") and session.vlan_ids
        has_stp_vlans = hasattr(session, "stp_vlans") and session.stp_vlans

        # Check if any VLAN evidence was detected from either source
        if not has_802_1q and not has_stp_vlans:
            findings.append("No 802.1Q VLAN tags detected (untagged network or traffic capture limitation).")
            return "\n".join(findings)

        # If we have STP VLANs but no 802.1Q tags, the capture is on an access port
        if not has_802_1q and has_stp_vlans:
            stp_vlan_list = sorted(session.stp_vlans.keys())
            findings.append(f"No 802.1Q tagged frames detected (capture likely on an access/untagged port),")
            findings.append(f"however STP/PVST+ BPDUs reveal {len(stp_vlan_list)} active VLAN(s) on this switch:")
            findings.append("")
            findings.append("  VLANs detected via STP System ID Extension:")
            for vlan_id in stp_vlan_list[:20]:
                cnt = session.stp_vlans[vlan_id]
                marker = "⚠️  " if vlan_id == 1 else "    "
                findings.append(f"  {marker}VLAN {vlan_id}: {cnt:,} BPDUs")
            if len(stp_vlan_list) > 20:
                findings.append(f"    ... and {len(stp_vlan_list) - 20} more")
            if 1 in stp_vlan_list:
                findings.append("")
                findings.append("  ⚠️  VLAN 1 (Native VLAN) is active in STP topology")
                findings.append("  Risk: VLAN 1 should not carry production traffic in OT networks")
            findings.append("")
            findings.append("  Note: To see per-VLAN IP assignments, capture on a trunk port (tagged).")
            return "\n".join(findings)

        # VLAN 1 Detection (Critical in OT environments)
        if hasattr(session, "vlan_1_detected") and session.vlan_1_detected:
            findings.append("⚠️  CRITICAL: VLAN 1 (Native VLAN) In Use")
            findings.append("  Risk: Native VLAN usage on OT networks indicates potential misconfiguration")
            findings.append("  - VLAN 1 should not carry production traffic in OT networks")
            findings.append("  - Suggests lack of VLAN segmentation between management/control planes")
            vlan_1_ips = session.vlan_to_ips.get(1, set())
            if vlan_1_ips:
                ips_str = ", ".join(sorted(vlan_1_ips)[:10])
                findings.append(f"  - IPs on VLAN 1: {ips_str}")
                if len(vlan_1_ips) > 10:
                    findings.append(f"    ... and {len(vlan_1_ips) - 10} more")

        # VLAN distribution analysis
        findings.append(f"\n📊 VLAN Distribution: {len(session.vlan_ids)} VLAN(s) detected")
        total_tagged = sum(session.vlan_ids.values())
        untagged_pct = (session.untagged_frame_count / (total_tagged + session.untagged_frame_count) * 100) if (total_tagged + session.untagged_frame_count) > 0 else 0

        findings.append(f"  Tagged frames: {total_tagged:,}")
        findings.append(f"  Untagged frames: {session.untagged_frame_count:,} ({untagged_pct:.1f}%)")

        # Show top VLANs
        top_vlans = session.vlan_ids.most_common(10)
        if top_vlans:
            findings.append("\n  Top VLANs by traffic volume:")
            for vlan_id, count in top_vlans:
                ips_in_vlan = session.vlan_to_ips.get(vlan_id, set())
                internal_ips = [ip for ip in ips_in_vlan if ip]
                marker = "⚠️  " if vlan_id == 1 else "ℹ️  "
                findings.append(f"    {marker}VLAN {vlan_id}: {count:,} frames, {len(internal_ips)} unique IPs")
                if internal_ips:
                    ips_sample = ", ".join(sorted(internal_ips)[:5])
                    findings.append(f"        IPs: {ips_sample}")
                    if len(internal_ips) > 5:
                        findings.append(f"        ... and {len(internal_ips) - 5} more")

        # Purdue Model VLAN assessment
        findings.append("\n  Security Recommendations (Purdue Model):")
        findings.append("  • Each Purdue zone (L0-L3, L3.5) should use separate VLAN ranges")
        findings.append("  • Avoid VLAN 1 for production traffic")
        findings.append("  • Use voice/management VLANs (e.g., 10-99) separate from data")
        findings.append("  • Implement inter-VLAN routing with firewall policies (no direct bridging)")
        findings.append("  • Validate VLAN design matches network architecture documentation")

        if not findings:
            findings.append("No VLAN configuration issues detected.")

        return "\n".join(findings)

    @staticmethod
    def _get_netops_static_output(session: Any) -> str:
        """Build network operations / infrastructure health static summary."""
        from plugins.network_forensics.pcap_metadata_summary.tool import (
            is_internal, _format_bytes,
        )
        from collections import Counter, defaultdict

        lines = []

        # --- Standard PCAP header (no security items for netops) ---
        header = PcapAiAnalyzer._build_pcap_header(session, netops=True)
        lines.append(header)

        # --- TCP Health Overview ---
        tcp_total = session.protocols.get("TCP", 0)
        lines.append(f"\n{'=' * 60}")
        lines.append("TCP HEALTH INDICATORS")
        lines.append(f"{'=' * 60}")

        if tcp_total > 0:
            retransmit_pct = (session.tcp_retransmissions / tcp_total * 100) if tcp_total else 0
            rst_pct = (session.tcp_rst_count / tcp_total * 100) if tcp_total else 0

            # Health grade
            if retransmit_pct < 1:
                health = "HEALTHY"
            elif retransmit_pct < 5:
                health = "DEGRADED"
            else:
                health = "CRITICAL"

            lines.append(f"\nOverall TCP Health: {health}")
            lines.append(f"  Total TCP packets: {tcp_total:,}")
            lines.append(f"  SYN packets: {session.tcp_syn_count:,}")
            lines.append(f"  FIN packets: {session.tcp_fin_count:,}")
            lines.append(f"  RST packets: {session.tcp_rst_count:,} ({rst_pct:.2f}%)")
            lines.append(f"  Retransmissions: {session.tcp_retransmissions:,} ({retransmit_pct:.2f}%)")
            lines.append(f"  Zero-window events: {session.tcp_zero_window_count:,}")

            # SYN/FIN ratio (indicates connection completion rate)
            if session.tcp_syn_count > 0:
                completion = session.tcp_fin_count / session.tcp_syn_count * 100
                lines.append(f"  Connection completion rate (FIN/SYN): {completion:.1f}%")

            # RST/SYN ratio (indicates connection failure rate)
            if session.tcp_syn_count > 0:
                failure = session.tcp_rst_count / session.tcp_syn_count * 100
                lines.append(f"  Connection failure rate (RST/SYN): {failure:.1f}%")
        else:
            lines.append("\nNo TCP traffic in this capture.")

        # --- Conversations with most health issues ---
        if session.conv_health:
            # Sort by total issues (RST + retransmit + zero_window)
            problem_convs = sorted(
                session.conv_health.items(),
                key=lambda x: x[1]["rst"] + x[1]["retransmit"] + x[1]["zero_window"],
                reverse=True,
            )
            top_problem = [c for c in problem_convs
                           if c[1]["rst"] + c[1]["retransmit"] + c[1]["zero_window"] > 0][:20]

            if top_problem:
                lines.append(f"\n{'=' * 60}")
                lines.append("TOP PROBLEM CONVERSATIONS")
                lines.append(f"{'=' * 60}")
                lines.append(
                    f"{'#':<4} {'Source':<18} {'Destination':<18} {'Port':<7} "
                    f"{'RSTs':<7} {'Retx':<7} {'ZeroWin':<8} {'Pkts':<8}"
                )
                lines.append("-" * 85)
                for i, ((src, dst, dport, proto), health) in enumerate(top_problem, 1):
                    conv_stats = session.conversations.get((src, dst, dport, proto), {})
                    pkts = conv_stats.get("packets", 0)
                    lines.append(
                        f"{i:<4} {src:<18} {dst:<18} {dport:<7} "
                        f"{health['rst']:<7} {health['retransmit']:<7} "
                        f"{health['zero_window']:<8} {pkts:<8}"
                    )

        # --- ICMP Errors ---
        if session.icmp_errors:
            lines.append(f"\n{'=' * 60}")
            lines.append(f"ICMP ERROR MESSAGES: {len(session.icmp_errors):,}")
            lines.append(f"{'=' * 60}")

            # Group by type
            icmp_by_type = defaultdict(list)
            for err in session.icmp_errors:
                icmp_by_type[err["description"]].append(err)

            for desc, errors in sorted(icmp_by_type.items(), key=lambda x: len(x[1]), reverse=True):
                lines.append(f"\n  {desc}: {len(errors):,} occurrence(s)")
                # Show affected source → destination pairs
                pairs = Counter((e["src"], e["dst"]) for e in errors)
                for (src, dst), count in pairs.most_common(10):
                    lines.append(f"    {src} → {dst}  ({count} times)")
                if len(pairs) > 10:
                    lines.append(f"    ... +{len(pairs) - 10} more pairs")
        else:
            lines.append(f"\n{'=' * 60}")
            lines.append("ICMP ERROR MESSAGES")
            lines.append(f"{'=' * 60}")
            lines.append("No ICMP error messages detected.")

        # --- Routing Loop Detection ---
        has_loop_evidence = False
        lines.append(f"\n{'=' * 60}")
        lines.append("ROUTING LOOP DETECTION")
        lines.append(f"{'=' * 60}")

        # Evidence 1: ICMP TTL Exceeded grouped by original destination
        if session.ttl_exceeded_by_dest:
            loop_suspects = []
            for orig_dst, entries in session.ttl_exceeded_by_dest.items():
                routers = set(e["router"] for e in entries)
                sources = set(e["original_src"] for e in entries)
                count = len(entries)
                if len(routers) >= 2 or count >= 5:
                    loop_suspects.append({
                        "destination": orig_dst,
                        "routers": sorted(routers),
                        "original_sources": sorted(sources),
                        "ttl_exceeded_count": count,
                        "confidence": "HIGH" if len(routers) >= 2 and count >= 5 else "MEDIUM",
                    })

            if loop_suspects:
                has_loop_evidence = True
                loop_suspects.sort(key=lambda x: x["ttl_exceeded_count"], reverse=True)
                lines.append(f"\n  🔴 SUSPECTED ROUTING LOOPS (ICMP TTL Exceeded analysis):")
                lines.append(f"  Found {len(loop_suspects)} destination(s) with loop indicators")
                for ls in loop_suspects[:10]:
                    lines.append(f"\n  Destination: {ls['destination']}  "
                                 f"[Confidence: {ls['confidence']}]")
                    lines.append(f"    TTL Exceeded count: {ls['ttl_exceeded_count']}")
                    lines.append(f"    Routers generating TTL Exceeded: "
                                 f"{', '.join(ls['routers'][:8])}")
                    if len(ls['routers']) > 8:
                        lines.append(f"      ... +{len(ls['routers']) - 8} more routers")
                    lines.append(f"    Original sources: "
                                 f"{', '.join(ls['original_sources'][:5])}")
                    if ls['confidence'] == "HIGH":
                        lines.append(f"    ⚠️  Multiple routers ({len(ls['routers'])}) "
                                     f"dropping same-dest packets — classic loop signature")
            else:
                ttl_exc_total = sum(len(v) for v in session.ttl_exceeded_by_dest.values())
                if ttl_exc_total > 0:
                    lines.append(f"\n  ICMP TTL Exceeded: {ttl_exc_total} message(s) "
                                 f"— no definitive loop pattern detected")

        # Evidence 2: Duplicate IP ID packets (same packet seen with different TTLs)
        if session.suspected_loop_packets:
            has_loop_evidence = True
            loop_paths: dict = defaultdict(list)
            for pkt_info in session.suspected_loop_packets:
                path_key = (pkt_info["src"], pkt_info["dst"], pkt_info["proto"])
                loop_paths[path_key].append(pkt_info)

            lines.append(f"\n  🔴 DUPLICATE PACKETS (same IP ID, different TTLs):")
            lines.append(f"  {len(session.suspected_loop_packets)} duplicate packet(s) "
                         f"across {len(loop_paths)} path(s)")
            for (src, dst, proto), pkts in sorted(
                loop_paths.items(), key=lambda x: len(x[1]), reverse=True
            )[:10]:
                ttls_seen = sorted(set(p["ttl"] for p in pkts) |
                                   set(t for p in pkts for t in p["prev_ttls"]))
                lines.append(f"\n    {src} → {dst} ({proto}): "
                             f"{len(pkts)} duplicate(s)")
                lines.append(f"      TTL values seen: {', '.join(str(t) for t in ttls_seen[:10])}")
                if len(ttls_seen) > 2:
                    ttl_diff = max(ttls_seen) - min(ttls_seen)
                    lines.append(f"      TTL spread: {ttl_diff} hops — "
                                 f"suggests {ttl_diff}-hop loop cycle")

        # Evidence 3: High ICMP TTL Exceeded rate relative to traffic
        ttl_exc_errors = [e for e in session.icmp_errors if e["type"] == 11]
        if ttl_exc_errors and session.packet_count > 0:
            ttl_exc_pct = len(ttl_exc_errors) / session.packet_count * 100
            if ttl_exc_pct > 0.1:
                has_loop_evidence = True
                lines.append(f"\n  ⚠️  TTL Exceeded rate: {ttl_exc_pct:.3f}% of all traffic "
                             f"({len(ttl_exc_errors):,} messages)")
                lines.append(f"      Normal rate is near 0% — elevated rate "
                             f"indicates routing instability or loops")

        if not has_loop_evidence:
            lines.append("\n  ✅ No routing loop indicators detected.")

        # --- ARP Health ---
        total_arp = session.arp_request_count + session.arp_reply_count
        lines.append(f"\n{'=' * 60}")
        lines.append("ARP HEALTH")
        lines.append(f"{'=' * 60}")

        if total_arp > 0:
            lines.append(f"\n  Total ARP packets: {total_arp:,}")
            lines.append(f"  ARP Requests: {session.arp_request_count:,}")
            lines.append(f"  ARP Replies: {session.arp_reply_count:,}")
            lines.append(f"  Gratuitous ARP: {session.arp_gratuitous_count:,}")

            if session.arp_reply_count > 0:
                req_reply_ratio = session.arp_request_count / session.arp_reply_count
                lines.append(f"  Request/Reply ratio: {req_reply_ratio:.1f}:1")
                if req_reply_ratio > 5:
                    lines.append("  ⚠️  High request/reply ratio — many unanswered ARPs "
                                 "(dead hosts, wrong subnet, or ARP scan)")
            elif session.arp_request_count > 10:
                lines.append("  ⚠️  ARP requests with ZERO replies — network isolation "
                             "or capture point issue")

            if len(session._arp_timestamps) >= 2:
                arp_duration = max(session._arp_timestamps) - min(session._arp_timestamps)
                if arp_duration > 0:
                    arp_rate = total_arp / arp_duration
                    lines.append(f"  ARP rate: {arp_rate:.1f} pkt/s")
                    if arp_rate > 100:
                        lines.append("  🔴 ARP STORM detected — >100 ARP/s indicates "
                                     "broadcast storm or L2 loop")
                    elif arp_rate > 30:
                        lines.append("  ⚠️  Elevated ARP rate — possible ARP scan or "
                                     "unstable L2 network")

            if session.packet_count > 0:
                arp_pct = total_arp / session.packet_count * 100
                lines.append(f"  ARP as % of total traffic: {arp_pct:.2f}%")
                if arp_pct > 5:
                    lines.append("  ⚠️  ARP exceeds 5% of traffic — abnormal for "
                                 "most networks (check for broadcast storm)")

            if session.arp_requests_by_src:
                top_senders = session.arp_requests_by_src.most_common(10)
                lines.append(f"\n  Top ARP requesters (by MAC):")
                for mac, count in top_senders:
                    pct_of_arp = count / session.arp_request_count * 100
                    marker = ""
                    if count > 100 and pct_of_arp > 30:
                        marker = "  🔴 FLOOD SOURCE"
                    elif count > 50:
                        marker = "  ⚠️  HIGH"
                    lines.append(f"    {mac}: {count:,} requests ({pct_of_arp:.1f}%){marker}")

            conflicts = {ip: macs for ip, macs in session.arp_ip_to_macs.items()
                         if len(macs) > 1
                         and ip not in ('0.0.0.0', '255.255.255.255')}
            if conflicts:
                lines.append(f"\n  🔴 IP ADDRESS CONFLICTS: {len(conflicts)} IP(s) "
                             f"claimed by multiple MACs")
                for ip, macs in sorted(conflicts.items(),
                                       key=lambda x: len(x[1]), reverse=True)[:15]:
                    mac_list = ", ".join(sorted(macs))
                    lines.append(f"    {ip} → {len(macs)} MACs: {mac_list}")
                    if len(macs) == 2:
                        lines.append(f"      Possible: IP conflict, VRRP/HSRP failover, "
                                     f"or duplicate addressing")
                    elif len(macs) > 2:
                        lines.append(f"      ⚠️  {len(macs)} MACs for one IP is highly "
                                     f"abnormal — likely misconfiguration or device flapping")

            unanswered = {ip: count for ip, count in session._arp_request_targets.items()
                          if ip not in session._arp_reply_targets and count >= 2}
            if unanswered:
                top_unanswered = sorted(unanswered.items(), key=lambda x: x[1], reverse=True)
                lines.append(f"\n  UNANSWERED ARP TARGETS: {len(unanswered)} IP(s) "
                             f"never replied")
                for ip, count in top_unanswered[:15]:
                    lines.append(f"    {ip}: {count} unanswered request(s)")
                if len(unanswered) > 15:
                    lines.append(f"    ... +{len(unanswered) - 15} more")

            if session.arp_gratuitous_count > 10:
                lines.append(f"\n  ⚠️  {session.arp_gratuitous_count} gratuitous ARPs "
                             f"— possible VRRP/HSRP flapping or gateway failover")
        else:
            lines.append("\n  No ARP traffic captured.")
            lines.append("  (Capture may be from a routed interface or span port "
                         "that strips L2 headers)")

        # --- Control Plane & Topology ---
        has_control_plane = (
            session.stp_bpdu_count + session.stp_tcn_count > 0
            or session.hsrp_hello_count > 0
            or session.vrrp_advert_count > 0
            or session.ospf_total_count > 0
            or session.eigrp_total_count > 0
        )

        # Helper: resolve MAC to switch identity from CDP/LLDP
        def _resolve_switch(mac: str) -> str:
            """Look up a MAC in CDP/LLDP neighbors; return annotation string or ''."""
            # CDP/LLDP store by eth source MAC; bridge IDs use format "prio:mac"
            lookup_mac = mac.split(':', 1)[1] if ':' in mac and len(mac.split(':')) > 6 else mac
            # Normalize to lowercase for comparison
            lookup_mac = lookup_mac.lower()
            # Check CDP neighbors
            for cdp_mac, info in session.cdp_neighbors.items():
                if cdp_mac.lower() == lookup_mac:
                    parts = []
                    if info.get('device_id'):
                        parts.append(info['device_id'])
                    if info.get('platform'):
                        parts.append(info['platform'])
                    if info.get('port_id'):
                        parts.append(info['port_id'])
                    if info.get('mgmt_ip'):
                        parts.append(info['mgmt_ip'])
                    return f" — {', '.join(parts)}" if parts else ''
            # Check LLDP neighbors
            for lldp_mac, info in session.lldp_neighbors.items():
                if lldp_mac.lower() == lookup_mac:
                    parts = []
                    if info.get('system_name'):
                        parts.append(info['system_name'])
                    if info.get('system_desc'):
                        parts.append(info['system_desc'])
                    if info.get('port_id'):
                        parts.append(info['port_id'])
                    if info.get('mgmt_ip'):
                        parts.append(info['mgmt_ip'])
                    return f" — {', '.join(parts)}" if parts else ''
            return ''

        def _resolve_bridge_key(bridge_key: str) -> str:
            """Resolve a bridge key (prio:mac) to switch name."""
            # Bridge key format: "32769:00:aa:bb:cc:dd:ee" or "8000:00:aa:bb:cc:dd:ee"
            parts = bridge_key.split(':', 1)
            if len(parts) == 2:
                return _resolve_switch(parts[1])
            return _resolve_switch(bridge_key)

        lines.append(f"\n{'=' * 60}")
        lines.append("CONTROL PLANE & TOPOLOGY")
        lines.append(f"{'=' * 60}")

        if not has_control_plane:
            lines.append("\n  No control plane protocol traffic detected.")
            lines.append("  (STP, HSRP, VRRP, OSPF, EIGRP — none captured)")
        else:
            # --- STP ---
            total_stp = session.stp_bpdu_count + session.stp_tcn_count
            if total_stp > 0:
                lines.append(f"\n  SPANNING TREE PROTOCOL (STP)")
                lines.append(f"  {'─' * 40}")
                lines.append(f"  Config BPDUs: {session.stp_bpdu_count:,}")
                lines.append(f"  TCN BPDUs (Topology Change Notifications): "
                             f"{session.stp_tcn_count:,}")
                lines.append(f"  BPDUs with TC flag set: {session.stp_tc_flag_count:,}")
                lines.append(f"  TC Acknowledgments: {session.stp_tca_count:,}")

                # Protocol version distribution
                if session.stp_version_counts:
                    ver_parts = [f"{v}: {c:,}" for v, c in session.stp_version_counts.most_common()]
                    lines.append(f"  Versions: {', '.join(ver_parts)}")

                # RSTP negotiation
                if session.stp_proposal_count or session.stp_agreement_count:
                    lines.append(f"  RSTP Proposals: {session.stp_proposal_count:,}  "
                                 f"Agreements: {session.stp_agreement_count:,}")

                # Port roles
                if session.stp_port_roles:
                    role_parts = [f"{r}: {c:,}" for r, c in session.stp_port_roles.most_common()]
                    lines.append(f"  Port Roles: {', '.join(role_parts)}")

                # Port states
                if session.stp_port_states:
                    state_parts = [f"{s}: {c:,}" for s, c in session.stp_port_states.most_common()]
                    lines.append(f"  Port States: {', '.join(state_parts)}")

                root_bridges = list(session.stp_root_bridges.keys())
                # PVST+ detection: group root bridges by VLAN
                # If all root bridge IDs share the same MAC but differ only in
                # the System ID Extension (lower 12 bits), this is PVST+ — one
                # switch is root for multiple VLANs, NOT root instability.
                root_macs = set()
                root_by_vlan: dict = {}  # vlan_id -> set of root_keys
                for rb in root_bridges:
                    parts = rb.split(':', 1)
                    if len(parts) == 2:
                        try:
                            prio = int(parts[0])
                            mac = parts[1]
                            root_macs.add(mac)
                            vlan = prio & 0x0FFF
                            root_by_vlan.setdefault(vlan, set()).add(rb)
                        except ValueError:
                            root_macs.add(rb)

                is_pvst = len(root_macs) == 1 and len(root_bridges) > 1

                if len(root_bridges) == 1:
                    lines.append(f"  Root Bridge: {root_bridges[0]} (stable)")
                elif is_pvst:
                    mac = next(iter(root_macs))
                    lines.append(f"  Root Bridge: {mac} (stable, PVST+ — same root for "
                                 f"{len(root_bridges)} VLAN instances)")
                    for rb in root_bridges:
                        count = len(session.stp_root_bridges[rb])
                        try:
                            vlan = int(rb.split(':')[0]) & 0x0FFF
                            lines.append(f"    VLAN {vlan}: {rb} ({count:,} BPDUs)")
                        except ValueError:
                            lines.append(f"    {rb}: {count:,} BPDUs")
                elif len(root_bridges) > 1:
                    # True root instability — different MACs competing
                    # Check per-VLAN: only flag VLANs with >1 root MAC
                    vlan_unstable = {v: roots for v, roots in root_by_vlan.items()
                                     if len(set(r.split(':', 1)[1] for r in roots)) > 1}
                    if vlan_unstable:
                        lines.append(f"  🔴 ROOT BRIDGE CHANGES DETECTED in "
                                     f"{len(vlan_unstable)} VLAN(s)!")
                        for vlan in sorted(vlan_unstable):
                            lines.append(f"    VLAN {vlan}: {len(vlan_unstable[vlan])} "
                                         f"different roots competing")
                            for rb in sorted(vlan_unstable[vlan]):
                                count = len(session.stp_root_bridges[rb])
                                lines.append(f"      {rb}: {count:,} BPDUs")
                        lines.append(f"    ⚠️  Root bridge instability — "
                                     f"check for priority misconfiguration")
                    else:
                        lines.append(f"  Root Bridges: {len(root_bridges)} "
                                     f"(PVST+ — per-VLAN instances, stable)")
                        for rb in root_bridges:
                            count = len(session.stp_root_bridges[rb])
                            lines.append(f"    {rb}: {count:,} BPDUs")

                # Root change timeline (only real changes — same VLAN, different MAC)
                if session.stp_root_changes:
                    lines.append(f"  🔴 ROOT CHANGE EVENTS ({len(session.stp_root_changes)}):")
                    for entry in session.stp_root_changes[:20]:
                        from datetime import datetime, timezone
                        if len(entry) == 4:
                            ts, vlan, old_root, new_root = entry
                            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%H:%M:%S.%f')[:-3]
                            old_id = _resolve_bridge_key(old_root)
                            new_id = _resolve_bridge_key(new_root)
                            lines.append(f"    {dt} VLAN {vlan}: {old_root}{old_id} → {new_root}{new_id}")
                        else:
                            ts, old_root, new_root = entry
                            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%H:%M:%S.%f')[:-3]
                            old_id = _resolve_bridge_key(old_root)
                            new_id = _resolve_bridge_key(new_root)
                            lines.append(f"    {dt}: {old_root}{old_id} → {new_root}{new_id}")

                if session.stp_tcn_count > 10:
                    lines.append(f"  ⚠️  HIGH TCN COUNT: {session.stp_tcn_count} topology "
                                 f"change notifications — indicates L2 flapping")

                # TC event clustering (detect bursts)
                if session.stp_tc_events and len(session.stp_tc_events) > 5:
                    tc_sorted = sorted(session.stp_tc_events)
                    # Find clusters: TC events within 10s of each other
                    bursts = []
                    burst_start = tc_sorted[0]
                    burst_count = 1
                    for i in range(1, len(tc_sorted)):
                        if tc_sorted[i] - tc_sorted[i-1] < 10:
                            burst_count += 1
                        else:
                            if burst_count >= 3:
                                bursts.append((burst_start, burst_count))
                            burst_start = tc_sorted[i]
                            burst_count = 1
                    if burst_count >= 3:
                        bursts.append((burst_start, burst_count))
                    if bursts:
                        lines.append(f"  ⚠️  TC BURSTS ({len(bursts)} clusters):")
                        for ts, cnt in bursts[:10]:
                            from datetime import datetime, timezone
                            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%H:%M:%S')
                            lines.append(f"    {dt}: {cnt} TC events in rapid succession")

                if len(session._stp_timestamps) >= 2:
                    stp_duration = max(session._stp_timestamps) - min(session._stp_timestamps)
                    if stp_duration > 0:
                        stp_rate = total_stp / stp_duration
                        lines.append(f"  STP rate: {stp_rate:.1f} BPDU/s (aggregate)")
                        # Per-port-per-VLAN rate: in PVST+, each port sends 1 BPDU
                        # per VLAN per hello interval. Normal = ports × VLANs / 2s.
                        num_vlans = max(len(session.stp_vlans), 1)
                        num_ports = max(len(session.stp_src_macs), 1)
                        expected_rate = num_ports * num_vlans * 0.5  # 1 per 2s hello
                        per_port_vlan_rate = stp_rate / (num_ports * num_vlans)
                        lines.append(f"  Per-port-per-VLAN rate: {per_port_vlan_rate:.2f} BPDU/s "
                                     f"({num_ports} ports × {num_vlans} VLANs)")
                        if per_port_vlan_rate > 1.0:
                            lines.append(f"  ⚠️  Elevated per-port BPDU rate (>{per_port_vlan_rate:.1f}/s) "
                                         f"— possible STP storm")
                        elif stp_rate > expected_rate * 2:
                            lines.append(f"  ⚠️  Aggregate rate exceeds 2x expected ({expected_rate:.1f}/s) "
                                         f"— investigate")

                if session.stp_bridges:
                    lines.append(f"  Bridges seen: {len(session.stp_bridges)}")
                    for bridge, count in session.stp_bridges.most_common(10):
                        identity = _resolve_bridge_key(bridge)
                        lines.append(f"    {bridge}: {count:,} BPDUs{identity}")

                # Source MACs (which switches send BPDUs)
                if session.stp_src_macs:
                    lines.append(f"  Source switch MACs ({len(session.stp_src_macs)}):")
                    for mac, count in session.stp_src_macs.most_common(10):
                        identity = _resolve_switch(mac)
                        lines.append(f"    {mac}: {count:,} BPDUs{identity}")

                # VLANs
                if session.stp_vlans:
                    vlan_parts = [f"VLAN {v}: {c:,}" for v, c in session.stp_vlans.most_common(20)]
                    lines.append(f"  VLANs (from System ID Extension): {', '.join(vlan_parts)}")

                # Path cost changes
                if session.stp_path_costs:
                    for bridge_key, costs in session.stp_path_costs.items():
                        unique_costs = set(c for _, c in costs)
                        if len(unique_costs) > 1:
                            lines.append(f"  ⚠️  PATH COST CHANGE on {bridge_key}: "
                                         f"seen values {sorted(unique_costs)}")

                # Timer values (flag non-standard)
                if session.stp_timers:
                    for timer_name, dist in session.stp_timers.items():
                        if dist:
                            vals = [f"{v}s:{c:,}" for v, c in dist.most_common(5)]
                            lines.append(f"  Timer {timer_name}: {', '.join(vals)}")

                # Port IDs
                if session.stp_port_ids and len(session.stp_port_ids) > 1:
                    lines.append(f"  Port IDs ({len(session.stp_port_ids)} unique):")
                    for pid, count in session.stp_port_ids.most_common(10):
                        lines.append(f"    {pid}: {count:,}")

                # BPDU starvation detection (gaps > max_age)
                if session.stp_bpdu_gaps:
                    lines.append(f"  🔴 BPDU STARVATION DETECTED: {len(session.stp_bpdu_gaps)} gap(s) "
                                 f"exceeding max_age!")
                    lines.append(f"    A BPDU stream that stops for >max_age causes the port to "
                                 f"transition to Forwarding — potential bridging loop!")
                    for src_mac, gap_start, gap_secs in session.stp_bpdu_gaps[:15]:
                        from datetime import datetime, timezone
                        dt = datetime.fromtimestamp(gap_start, tz=timezone.utc).strftime('%H:%M:%S')
                        identity = _resolve_switch(src_mac)
                        lines.append(f"    {dt}: {src_mac}{identity} — {gap_secs}s silence "
                                     f"(>{int(gap_secs // 20)}x max_age)")

                # MAC mismatch (spoofing / misconfiguration)
                if session.stp_mac_mismatches:
                    lines.append(f"  🔴 BPDU MAC MISMATCH: {len(session.stp_mac_mismatches)} "
                                 f"packet(s) where Ethernet source ≠ BPDU bridge MAC!")
                    lines.append(f"    This may indicate BPDU spoofing (e.g. Yersinia), a "
                                 f"misconfigured transparent bridge, or packet crafting.")
                    for ts, eth_mac, bpdu_mac in session.stp_mac_mismatches[:10]:
                        from datetime import datetime, timezone
                        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%H:%M:%S.%f')[:-3]
                        lines.append(f"    {dt}: Ethernet src={eth_mac}  BPDU bridge={bpdu_mac}")

                # CDP/LLDP Switch Inventory (from capture)
                if session.cdp_neighbors or session.lldp_neighbors:
                    lines.append(f"\n  CDP/LLDP SWITCH INVENTORY (from capture)")
                    lines.append(f"  {'─' * 40}")
                    lines.append(f"  CDP frames: {session.cdp_frame_count:,}  |  "
                                 f"LLDP frames: {session.lldp_frame_count:,}")
                    # Merge CDP and LLDP into unified view
                    all_switches: dict[str, dict[str, str]] = {}
                    for mac, info in session.cdp_neighbors.items():
                        all_switches[mac] = {
                            'name': info.get('device_id', ''),
                            'platform': info.get('platform', ''),
                            'mgmt_ip': info.get('mgmt_ip', ''),
                            'port': info.get('port_id', ''),
                            'software': info.get('software_version', ''),
                            'capabilities': info.get('capabilities', ''),
                            'native_vlan': str(info.get('native_vlan', '')),
                            'source': 'CDP',
                        }
                    for mac, info in session.lldp_neighbors.items():
                        if mac not in all_switches:
                            all_switches[mac] = {
                                'name': info.get('system_name', ''),
                                'platform': info.get('system_desc', ''),
                                'mgmt_ip': info.get('mgmt_ip', ''),
                                'port': info.get('port_id', ''),
                                'software': '',
                                'capabilities': info.get('capabilities', ''),
                                'native_vlan': '',
                                'source': 'LLDP',
                            }
                        else:
                            # Merge LLDP into existing CDP entry (fill gaps)
                            existing = all_switches[mac]
                            if not existing['name'] and info.get('system_name'):
                                existing['name'] = info['system_name']
                            if not existing['platform'] and info.get('system_desc'):
                                existing['platform'] = info['system_desc']
                            if not existing['mgmt_ip'] and info.get('mgmt_ip'):
                                existing['mgmt_ip'] = info['mgmt_ip']
                            existing['source'] = 'CDP+LLDP'

                    for mac, sw in all_switches.items():
                        parts = [f"{mac}"]
                        if sw['name']:
                            parts[0] += f" ({sw['name']})"
                        detail_parts = []
                        if sw['platform']:
                            detail_parts.append(f"Platform: {sw['platform']}")
                        if sw['mgmt_ip']:
                            detail_parts.append(f"Mgmt: {sw['mgmt_ip']}")
                        if sw['port']:
                            detail_parts.append(f"Port: {sw['port']}")
                        if sw['software']:
                            detail_parts.append(f"SW: {sw['software']}")
                        if sw['capabilities']:
                            detail_parts.append(f"Caps: {sw['capabilities']}")
                        if sw['native_vlan']:
                            detail_parts.append(f"Native VLAN: {sw['native_vlan']}")
                        lines.append(f"    {parts[0]} [{sw['source']}]")
                        if detail_parts:
                            lines.append(f"      {' | '.join(detail_parts)}")

            # --- HSRP ---
            if session.hsrp_hello_count > 0:
                lines.append(f"\n  HSRP (Hot Standby Router Protocol)")
                lines.append(f"  {'─' * 40}")
                lines.append(f"  HSRP Hellos: {session.hsrp_hello_count:,}")

                if session.hsrp_events:
                    groups = set(e["group"] for e in session.hsrp_events)
                    lines.append(f"  Groups: {', '.join(str(g) for g in sorted(groups))}")
                    for grp in sorted(groups):
                        grp_events = [e for e in session.hsrp_events if e["group"] == grp]
                        sources = set(e["src"] for e in grp_events)
                        states = set(e["state_name"] for e in grp_events)
                        vips = set(e["virtual_ip"] for e in grp_events if e["virtual_ip"])
                        lines.append(f"    Group {grp}: routers={', '.join(sorted(sources))}"
                                     f"  states={', '.join(sorted(states))}"
                                     f"  VIP={', '.join(sorted(vips))}")

                if session.hsrp_state_changes:
                    lines.append(f"\n  🔴 HSRP STATE TRANSITIONS: "
                                 f"{len(session.hsrp_state_changes)}")
                    for sc in session.hsrp_state_changes[:15]:
                        lines.append(f"    Group {sc['group']} {sc['src']}: "
                                     f"{sc['from_state']} → {sc['to_state']}")
                    if len(session.hsrp_state_changes) > 15:
                        lines.append(f"    ... +{len(session.hsrp_state_changes) - 15} more")
                    lines.append(f"    ⚠️  State transitions indicate failover events — "
                                 f"correlate with network drops")

            # --- VRRP ---
            if session.vrrp_advert_count > 0:
                lines.append(f"\n  VRRP (Virtual Router Redundancy Protocol)")
                lines.append(f"  {'─' * 40}")
                lines.append(f"  VRRP Advertisements: {session.vrrp_advert_count:,}")

                if session.vrrp_events:
                    vrids = set(e["vrid"] for e in session.vrrp_events)
                    lines.append(f"  VRIDs: {', '.join(str(v) for v in sorted(vrids))}")
                    for vrid in sorted(vrids):
                        vrid_events = [e for e in session.vrrp_events if e["vrid"] == vrid]
                        sources = set(e["src"] for e in vrid_events)
                        priorities = set(e["priority"] for e in vrid_events)
                        lines.append(f"    VRID {vrid}: routers={', '.join(sorted(sources))}"
                                     f"  priorities={', '.join(str(p) for p in sorted(priorities))}")

                if session.vrrp_priority_changes:
                    lines.append(f"\n  ⚠️  VRRP PRIORITY CHANGES: "
                                 f"{len(session.vrrp_priority_changes)}")
                    for pc in session.vrrp_priority_changes[:10]:
                        lines.append(f"    VRID {pc['vrid']} {pc['src']}: "
                                     f"priority {pc['from_priority']} → {pc['to_priority']}")
                    lines.append(f"    Priority changes trigger master election — "
                                 f"may cause brief traffic disruption")

            # --- OSPF ---
            if session.ospf_total_count > 0:
                lines.append(f"\n  OSPF (Open Shortest Path First)")
                lines.append(f"  {'─' * 40}")
                lines.append(f"  Total OSPF packets: {session.ospf_total_count:,}")
                lines.append(f"    Hello: {session.ospf_hello_count:,}")
                lines.append(f"    DB Description: {session.ospf_dbd_count:,}")
                lines.append(f"    LS Request: {session.ospf_lsrequest_count:,}")
                lines.append(f"    LS Update: {session.ospf_lsupdate_count:,}")
                lines.append(f"    LS Ack: {session.ospf_lsack_count:,}")

                if session.ospf_areas:
                    lines.append(f"  Areas: {', '.join(sorted(session.ospf_areas))}")
                if session.ospf_router_ids:
                    lines.append(f"  Router IDs: {', '.join(sorted(session.ospf_router_ids))}"
                                 f" ({len(session.ospf_router_ids)} routers)")

                if session.ospf_neighbor_hellos:
                    dead_suspects = []
                    for pair, timestamps in session.ospf_neighbor_hellos.items():
                        if len(timestamps) < 2:
                            continue
                        sorted_ts = sorted(timestamps)
                        gaps = [sorted_ts[i+1] - sorted_ts[i]
                                for i in range(len(sorted_ts) - 1)]
                        max_gap = max(gaps) if gaps else 0
                        if max_gap > 40:
                            dead_suspects.append((pair, max_gap, len(timestamps)))

                    if dead_suspects:
                        lines.append(f"\n  🔴 OSPF NEIGHBOR GAPS (possible adjacency resets):")
                        dead_suspects.sort(key=lambda x: x[1], reverse=True)
                        for (ip_a, ip_b), gap, hello_count in dead_suspects[:10]:
                            lines.append(
                                f"    {ip_a} ↔ {ip_b}: max gap={gap:.1f}s "
                                f"({hello_count} hellos) — "
                                f"{'DEAD NEIGHBOR' if gap > 120 else 'near dead interval'}")

                if len(session._ospf_lsupdate_timestamps) >= 5:
                    sorted_lsu = sorted(session._ospf_lsupdate_timestamps)
                    burst_windows = []
                    for i in range(len(sorted_lsu) - 10):
                        window = sorted_lsu[i+10] - sorted_lsu[i]
                        if window <= 5.0:
                            burst_windows.append((sorted_lsu[i], 10 / window if window > 0 else 999))

                    if burst_windows:
                        lines.append(f"\n  ⚠️  OSPF LSUpdate BURSTS DETECTED:")
                        lines.append(f"    {len(burst_windows)} burst window(s) "
                                     f"(>10 LSUpdates in 5s)")
                        max_rate = max(bw[1] for bw in burst_windows)
                        lines.append(f"    Peak rate: {max_rate:.1f} LSUpdate/s")
                        lines.append(f"    Indicates link flapping or route recalculation")

            # --- EIGRP ---
            if session.eigrp_total_count > 0:
                lines.append(f"\n  EIGRP (Enhanced Interior Gateway Routing Protocol)")
                lines.append(f"  {'─' * 40}")
                lines.append(f"  Total EIGRP packets: {session.eigrp_total_count:,}")
                lines.append(f"    Hello: {session.eigrp_hello_count:,}")
                lines.append(f"    Update: {session.eigrp_update_count:,}")
                lines.append(f"    Query: {session.eigrp_query_count:,}")
                lines.append(f"    Reply: {session.eigrp_reply_count:,}")

                if session.eigrp_as_numbers:
                    lines.append(f"  AS Numbers: "
                                 f"{', '.join(str(a) for a in sorted(session.eigrp_as_numbers))}")

                if session.eigrp_query_count > 0:
                    lines.append(f"\n  ⚠️  EIGRP QUERIES: {session.eigrp_query_count:,}")
                    lines.append(f"    Queries indicate routes going ACTIVE — "
                                 f"neighbors are recalculating paths")
                    if session.eigrp_query_count > 20:
                        lines.append(f"    🔴 HIGH query volume — possible convergence "
                                     f"event or Stuck-In-Active (SIA) condition")

                if (session.eigrp_hello_count > 0
                        and session.eigrp_update_count > session.eigrp_hello_count * 0.1):
                    lines.append(f"    ⚠️  Update/Hello ratio is elevated — "
                                 f"topology changes in progress")

        # --- IP Fragmentation ---
        lines.append(f"\n{'=' * 60}")
        lines.append("IP FRAGMENTATION")
        lines.append(f"{'=' * 60}")
        if session.ip_fragment_count > 0:
            frag_pct = session.ip_fragment_count / session.packet_count * 100
            lines.append(f"  Fragmented packets: {session.ip_fragment_count:,} ({frag_pct:.2f}%)")
            if frag_pct > 1:
                lines.append("  ⚠️  High fragmentation rate — possible MTU mismatch")
        else:
            lines.append("  No IP fragmentation detected.")

        # --- TTL Distribution ---
        if session.ttl_distribution:
            lines.append(f"\n{'=' * 60}")
            lines.append("TTL DISTRIBUTION")
            lines.append(f"{'=' * 60}")
            ttl_groups = {"Linux/macOS (TTL ~64)": 0, "Windows (TTL ~128)": 0,
                          "Network devices (TTL ~255)": 0, "Other": 0}
            for ttl, count in session.ttl_distribution.items():
                if 56 <= ttl <= 64:
                    ttl_groups["Linux/macOS (TTL ~64)"] += count
                elif 120 <= ttl <= 128:
                    ttl_groups["Windows (TTL ~128)"] += count
                elif 250 <= ttl <= 255:
                    ttl_groups["Network devices (TTL ~255)"] += count
                else:
                    ttl_groups["Other"] += count
            for group, count in sorted(ttl_groups.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    pct = count / session.packet_count * 100
                    lines.append(f"  {group}: {count:,} ({pct:.1f}%)")

            low_ttl = [(ttl, c) for ttl, c in session.ttl_distribution.items() if ttl < 10]
            if low_ttl:
                lines.append("\n  ⚠️  LOW TTL PACKETS (< 10):")
                for ttl, count in sorted(low_ttl):
                    lines.append(f"    TTL={ttl}: {count:,} packets")

        # --- DNS Health (failed lookups, heavy resolvers) ---
        if session.dns_queries:
            lines.append(f"\n{'=' * 60}")
            lines.append("DNS HEALTH")
            lines.append(f"{'=' * 60}")
            lines.append(f"  Total DNS queries: {len(session.dns_queries):,}")
            lines.append(f"  Total DNS responses: {len(session.dns_responses):,}")

            query_names = Counter(q["query"] for q in session.dns_queries)
            response_names = set(r["query"] for r in session.dns_responses)
            unanswered_dns = {q: c for q, c in query_names.items() if q not in response_names}
            if unanswered_dns:
                lines.append(f"\n  ⚠️  UNANSWERED DNS QUERIES: {len(unanswered_dns)} unique domains")
                for domain, count in sorted(unanswered_dns.items(), key=lambda x: x[1], reverse=True)[:15]:
                    lines.append(f"    {domain}  ({count} queries)")

            dns_by_src = Counter(q["src"] for q in session.dns_queries)
            lines.append(f"\n  Top DNS clients:")
            for ip, count in dns_by_src.most_common(10):
                lines.append(f"    {ip}: {count:,} queries")

        # --- Top Bandwidth Consumers ---
        conv_list = []
        for (src, dst, dport, proto), stats in session.conversations.items():
            conv_list.append((src, dst, dport, proto, stats["bytes_out"], stats["packets"],
                              stats.get("last_seen", 0) - stats.get("first_seen", 0)))
        conv_list.sort(key=lambda c: c[4], reverse=True)

        if conv_list:
            lines.append(f"\n{'=' * 60}")
            lines.append(f"TOP BANDWIDTH CONSUMERS")
            lines.append(f"{'=' * 60}")
            lines.append(
                f"{'#':<4} {'Source':<18} {'Destination':<18} {'Port':<7} {'Proto':<6} "
                f"{'Bytes':<10} {'Pkts':<8} {'Duration'}"
            )
            lines.append("-" * 85)
            for i, (src, dst, dport, proto, bytes_out, pkts, dur) in enumerate(conv_list[:15], 1):
                dur_str = f"{dur:.1f}s" if dur < 60 else f"{dur/60:.1f}min"
                lines.append(
                    f"{i:<4} {src:<18} {dst:<18} {dport:<7} {proto:<6} "
                    f"{_format_bytes(bytes_out):<10} {pkts:<8} {dur_str}"
                )

        # --- Long-lived Connections ---
        long_convs = [(k, s) for k, s in session.conversations.items()
                       if (s.get("last_seen", 0) - s.get("first_seen", 0)) > 300]
        long_convs.sort(key=lambda x: x[1].get("last_seen", 0) - x[1].get("first_seen", 0),
                         reverse=True)
        if long_convs:
            lines.append(f"\n{'=' * 60}")
            lines.append(f"LONG-LIVED CONNECTIONS (> 5 min): {len(long_convs)}")
            lines.append(f"{'=' * 60}")
            for (src, dst, dport, proto), stats in long_convs[:15]:
                dur = stats.get("last_seen", 0) - stats.get("first_seen", 0)
                dur_str = f"{dur/60:.1f}min" if dur < 3600 else f"{dur/3600:.1f}hrs"
                lines.append(
                    f"  {src} → {dst}:{dport} ({proto}) — {dur_str}, "
                    f"{_format_bytes(stats['bytes_out'])}, {stats['packets']} pkts"
                )

        # --- Service Port Distribution (ops-focused, no threat context) ---
        _SVC_NAMES = {
            22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP-S",
            68: "DHCP-C", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
            135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DG", 139: "NetBIOS-SS",
            143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP",
            443: "HTTPS", 445: "SMB", 465: "SMTPS", 502: "Modbus",
            514: "Syslog", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
            5060: "SIP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 44818: "EtherNet/IP", 47808: "BACnet",
            20000: "DNP3", 102: "S7comm",
        }
        port_stats: dict = defaultdict(lambda: {"flows": 0, "sources": set(),
                                                "bytes": 0, "pkts": 0})
        for (src, dst, dport, proto), stats in session.conversations.items():
            if dport > 0:
                port_stats[dport]["flows"] += 1
                port_stats[dport]["sources"].add(src)
                port_stats[dport]["bytes"] += stats.get("bytes_out", 0)
                port_stats[dport]["pkts"] += stats.get("packets", 0)

        if port_stats:
            lines.append(f"\n{'=' * 60}")
            lines.append("SERVICE PORT DISTRIBUTION")
            lines.append(f"{'=' * 60}")

            known = [(p, s) for p, s in port_stats.items() if p in _SVC_NAMES]
            known.sort(key=lambda x: x[1]["flows"], reverse=True)
            if known:
                lines.append("\n📡 KNOWN SERVICES")
                lines.append("-" * 60)
                for port, stats_d in known[:20]:
                    svc = _SVC_NAMES[port]
                    lines.append(
                        f"  {port:<7} {svc:<16} flows={stats_d['flows']:<5} "
                        f"sources={len(stats_d['sources']):<4} "
                        f"{_format_bytes(stats_d['bytes'])}"
                    )

            unknown = [(p, s) for p, s in port_stats.items()
                       if p not in _SVC_NAMES and p > 1024]
            if unknown:
                lines.append(f"\n⚙ OTHER HIGH PORTS — {len(unknown)} port(s)")
                lines.append("-" * 60)
                unknown.sort(key=lambda x: x[1]["flows"], reverse=True)
                for port, stats_d in unknown[:15]:
                    lines.append(
                        f"  {port:<7} flows={stats_d['flows']:<5} "
                        f"sources={len(stats_d['sources']):<4} "
                        f"{_format_bytes(stats_d['bytes'])}"
                    )

        # --- Active /24 Network Inventory ---
        net_inventory: dict = defaultdict(lambda: {
            "ips": set(), "bytes": 0, "flows": 0,
        })
        for (src, dst, dport, proto), stats in session.conversations.items():
            for ip in (src, dst):
                parts = ip.rsplit(".", 1)
                if len(parts) == 2:
                    sn = f"{parts[0]}.0/24"
                    net_inventory[sn]["ips"].add(ip)
            src_sn = ".".join(src.split(".")[:3]) + ".0/24"
            net_inventory[src_sn]["bytes"] += stats.get("bytes_out", 0)
            net_inventory[src_sn]["flows"] += 1

        if net_inventory:
            sorted_nets = sorted(net_inventory.items(),
                                 key=lambda x: x[1]["bytes"], reverse=True)
            int_nets = [(sn, s) for sn, s in sorted_nets if is_internal(sn.split("/")[0])]
            ext_nets = [(sn, s) for sn, s in sorted_nets if not is_internal(sn.split("/")[0])]

            lines.append(f"\n{'=' * 60}")
            lines.append(f"ACTIVE /24 NETWORK INVENTORY — {len(sorted_nets)} subnet(s)")
            lines.append(f"{'=' * 60}")
            lines.append(f"  Internal: {len(int_nets)}  |  External: {len(ext_nets)}")
            lines.append(
                f"\n  {'Subnet':<20} {'Hosts':<7} {'Flows':<8} {'Bytes':<12} {'Type'}"
            )
            lines.append("  " + "-" * 65)
            for sn, s in sorted_nets[:50]:
                ip_base = sn.split("/")[0]
                loc = "INT" if is_internal(ip_base) else "EXT"
                lines.append(
                    f"  {sn:<20} {len(s['ips']):<7} {s['flows']:<8} "
                    f"{_format_bytes(s['bytes']):<12} {loc}"
                )
            if len(sorted_nets) > 50:
                lines.append(f"  ... +{len(sorted_nets) - 50} more subnet(s) "
                             "(see companion .md for full list)")

        # --- Subnet Anomaly Summary ---
        subnet_scores: dict = defaultdict(lambda: {
            "rst": 0, "retransmit": 0, "icmp_errors": 0,
            "unanswered_arp": 0, "loop_packets": 0,
            "arp_requests": 0, "ip_conflicts": 0,
            "ips_seen": set(), "total_score": 0,
        })

        def _to_subnet(ip: str) -> str:
            parts = ip.rsplit(".", 1)
            return f"{parts[0]}.0/24" if len(parts) == 2 else ip

        for (src, dst, dport, proto), health in session.conv_health.items():
            for ip in (src, dst):
                if is_internal(ip):
                    sn = _to_subnet(ip)
                    subnet_scores[sn]["rst"] += health.get("rst", 0)
                    subnet_scores[sn]["retransmit"] += health.get("retransmit", 0)
                    subnet_scores[sn]["ips_seen"].add(ip)

        for err in session.icmp_errors:
            for ip in (err.get("src", ""), err.get("dst", "")):
                if ip and is_internal(ip):
                    subnet_scores[_to_subnet(ip)]["icmp_errors"] += 1
                    subnet_scores[_to_subnet(ip)]["ips_seen"].add(ip)

        unanswered_arp_targets = {ip: count for ip, count in session._arp_request_targets.items()
                                  if ip not in session._arp_reply_targets and count >= 2}
        for ip, count in unanswered_arp_targets.items():
            if is_internal(ip):
                subnet_scores[_to_subnet(ip)]["unanswered_arp"] += count
                subnet_scores[_to_subnet(ip)]["ips_seen"].add(ip)

        for ip, macs in session.arp_ip_to_macs.items():
            if len(macs) > 1 and is_internal(ip) and ip not in ('0.0.0.0', '255.255.255.255'):
                subnet_scores[_to_subnet(ip)]["ip_conflicts"] += 1
                subnet_scores[_to_subnet(ip)]["ips_seen"].add(ip)

        for pkt_info in session.suspected_loop_packets:
            for ip in (pkt_info.get("src", ""), pkt_info.get("dst", "")):
                if ip and is_internal(ip):
                    subnet_scores[_to_subnet(ip)]["loop_packets"] += 1
                    subnet_scores[_to_subnet(ip)]["ips_seen"].add(ip)

        mac_to_ips: dict = defaultdict(set)
        for ip, macs in session.arp_ip_to_macs.items():
            for mac in macs:
                mac_to_ips[mac].add(ip)
        for mac, count in session.arp_requests_by_src.most_common():
            if count >= 50:
                for ip in mac_to_ips.get(mac, set()):
                    if is_internal(ip):
                        subnet_scores[_to_subnet(ip)]["arp_requests"] += count
                        subnet_scores[_to_subnet(ip)]["ips_seen"].add(ip)

        for sn, scores in subnet_scores.items():
            scores["total_score"] = (
                scores["rst"] * 2
                + scores["retransmit"]
                + scores["icmp_errors"] * 5
                + scores["unanswered_arp"]
                + scores["loop_packets"] * 10
                + scores["ip_conflicts"] * 50
                + scores["arp_requests"] // 100
            )

        ranked = sorted(subnet_scores.items(),
                        key=lambda x: x[1]["total_score"], reverse=True)
        ranked = [(sn, s) for sn, s in ranked if s["total_score"] > 0]

        if ranked:
            lines.append(f"\n{'=' * 60}")
            lines.append("SUBNET ANOMALY SUMMARY (ranked by impact)")
            lines.append(f"{'=' * 60}")
            lines.append(
                f"  {'Subnet':<20} {'Score':<8} {'RSTs':<7} {'Retx':<7} "
                f"{'ICMP':<6} {'Loops':<7} {'ARP-Unans':<10} {'Conflicts':<10} "
                f"{'IPs'}"
            )
            lines.append("  " + "-" * 90)
            for sn, s in ranked[:25]:
                lines.append(
                    f"  {sn:<20} {s['total_score']:<8} "
                    f"{s['rst']:<7} {s['retransmit']:<7} "
                    f"{s['icmp_errors']:<6} {s['loop_packets']:<7} "
                    f"{s['unanswered_arp']:<10} {s['ip_conflicts']:<10} "
                    f"{len(s['ips_seen'])}"
                )

            top_sn, top_s = ranked[0]
            top_indicators = []
            if top_s["rst"] > 0:
                top_indicators.append(f"{top_s['rst']} RSTs")
            if top_s["retransmit"] > 0:
                top_indicators.append(f"{top_s['retransmit']} retransmissions")
            if top_s["loop_packets"] > 0:
                top_indicators.append(f"{top_s['loop_packets']} loop packets")
            if top_s["icmp_errors"] > 0:
                top_indicators.append(f"{top_s['icmp_errors']} ICMP errors")
            if top_s["ip_conflicts"] > 0:
                top_indicators.append(f"{top_s['ip_conflicts']} IP conflict(s)")
            if top_s["unanswered_arp"] > 0:
                top_indicators.append(f"{top_s['unanswered_arp']} unanswered ARPs")
            lines.append(f"\n  🔴 HIGHEST IMPACT SUBNET: {top_sn}")
            lines.append(f"     {', '.join(top_indicators)}")
            lines.append(f"     {len(top_s['ips_seen'])} unique IPs affected")

            if len(ranked) > 1:
                sn2, s2 = ranked[1]
                lines.append(f"  ⚠️  SECOND: {sn2} (score={s2['total_score']}, "
                             f"{len(s2['ips_seen'])} IPs)")
            if len(ranked) > 2:
                sn3, s3 = ranked[2]
                lines.append(f"  ⚠️  THIRD: {sn3} (score={s3['total_score']}, "
                             f"{len(s3['ips_seen'])} IPs)")

        # --- AD / Windows Protocol Activity ---
        ad_sections = []
        if hasattr(session, "kerberos_tickets") and session.kerberos_tickets:
            kb = session.kerberos_tickets
            failures = [t for t in kb if t.get("success") is False or t.get("success") == "false"]
            ad_sections.append(f"Kerberos: {len(kb)} tickets ({len(failures)} failures)")
            if failures:
                fail_clients = Counter(t.get("client", "?") for t in failures)
                for client, cnt in fail_clients.most_common(5):
                    ad_sections.append(f"  Failed: {client} ({cnt}x)")

        if hasattr(session, "ntlm_auths") and session.ntlm_auths:
            nt = session.ntlm_auths
            fails = [a for a in nt if a.get("success") is False or a.get("success") == "false"]
            ad_sections.append(f"NTLM: {len(nt)} auths ({len(fails)} failures)")

        if hasattr(session, "smb_mappings") and session.smb_mappings:
            ad_sections.append(f"SMB tree connects: {len(session.smb_mappings)}")
            shares = Counter(m.get("share", "?") for m in session.smb_mappings)
            for share, cnt in shares.most_common(5):
                ad_sections.append(f"  {share} ({cnt}x)")

        if hasattr(session, "smb_files") and session.smb_files:
            actions = Counter(f.get("action", "?") for f in session.smb_files)
            ad_sections.append(f"SMB file ops: {len(session.smb_files)} — " +
                               ", ".join(f"{a}={c}" for a, c in actions.most_common()))

        if hasattr(session, "dce_rpc_calls") and session.dce_rpc_calls:
            endpoints = Counter(c.get("endpoint", "?") for c in session.dce_rpc_calls)
            ad_sections.append(f"DCE/RPC: {len(session.dce_rpc_calls)} calls — " +
                               ", ".join(f"{e}={c}" for e, c in endpoints.most_common(5)))

        if hasattr(session, "ldap_operations") and session.ldap_operations:
            msg_types = Counter(o.get("message_type", "?") for o in session.ldap_operations)
            ad_sections.append(f"LDAP: {len(session.ldap_operations)} ops — " +
                               ", ".join(f"{t}={c}" for t, c in msg_types.most_common(5)))

        if ad_sections:
            lines.append(f"\n{'=' * 60}")
            lines.append("ACTIVE DIRECTORY / WINDOWS PROTOCOL ACTIVITY")
            lines.append(f"{'=' * 60}")
            for s in ad_sections:
                lines.append(s)

        # --- Syslog Summary (if present in netops context) ---
        if hasattr(session, "syslog_total") and session.syslog_total:
            lines.append(f"\n{'=' * 60}")
            lines.append("SYSLOG SUMMARY")
            lines.append(f"{'=' * 60}")
            lines.append(f"Total messages: {session.syslog_total:,}")
            if session.syslog_sources:
                lines.append(f"Sources: {', '.join(sorted(session.syslog_sources.keys())[:10])}")
            if session.syslog_severity:
                from plugins.network_forensics.pcap_metadata_summary.tool import _SYSLOG_SEVERITY
                sev_strs = [f"{_SYSLOG_SEVERITY.get(k, str(k))}={v:,}"
                            for k, v in session.syslog_severity.most_common()]
                lines.append(f"Severity: {', '.join(sev_strs)}")
            if session.syslog_patterns:
                pat_strs = [f"{k}={v:,}" for k, v in session.syslog_patterns.most_common()]
                lines.append(f"Patterns: {', '.join(pat_strs)}")

        # --- VLAN Configuration Analysis (Network Ops Focus) ---
        has_vlan_tags = bool(session.vlan_ids)
        has_stp_vlans = hasattr(session, "stp_vlans") and bool(session.stp_vlans)
        if has_vlan_tags or session.untagged_frame_count > 0 or has_stp_vlans:
            lines.append(f"\n{'=' * 60}")
            lines.append("VLAN CONFIGURATION")
            lines.append(f"{'=' * 60}")
            if session.vlan_1_detected:
                lines.append("⚠️  VLAN 1 (Native VLAN) In Use")
                lines.append(f"  - Frames on VLAN 1: {session.vlan_ids.get(1, 0):,}")
                if 1 in session.vlan_to_ips:
                    lines.append(f"  - IPs observed: {', '.join(sorted(session.vlan_to_ips[1])[:10])}")
                lines.append("  • Production traffic on native VLAN may indicate misconfiguration")
                lines.append("  • Verify against network design documentation")
            if session.vlan_ids:
                lines.append(f"\n  VLAN Distribution: {len(session.vlan_ids)} VLAN(s) detected")
                total_tagged = sum(session.vlan_ids.values())
                if total_tagged + session.untagged_frame_count > 0:
                    untagged_pct = session.untagged_frame_count / (total_tagged + session.untagged_frame_count) * 100
                    lines.append(f"  Tagged frames: {total_tagged:,}")
                    lines.append(f"  Untagged frames: {session.untagged_frame_count:,} ({untagged_pct:.1f}%)")
                lines.append(f"\n  Top VLANs by traffic:")
                for vlan_id, count in session.vlan_ids.most_common(10):
                    ips_on_vlan = len(session.vlan_to_ips.get(vlan_id, set()))
                    marker = ""
                    if vlan_id == 1:
                        marker = "  ⚠️  Native"
                    lines.append(f"    VLAN {vlan_id}: {count:,} frames, {ips_on_vlan} unique IP(s){marker}")
            elif has_stp_vlans:
                # No 802.1Q tags but STP BPDUs reveal VLANs
                stp_vlan_list = sorted(session.stp_vlans.keys())
                lines.append("  No 802.1Q tagged frames (capture on access/untagged port)")
                lines.append(f"  However, STP/PVST+ BPDUs reveal {len(stp_vlan_list)} active VLAN(s):")
                for vlan_id in stp_vlan_list[:15]:
                    cnt = session.stp_vlans[vlan_id]
                    marker = "  ⚠️  Native" if vlan_id == 1 else ""
                    lines.append(f"    VLAN {vlan_id}: {cnt:,} BPDUs{marker}")
                if len(stp_vlan_list) > 15:
                    lines.append(f"    ... and {len(stp_vlan_list) - 15} more")
            else:
                lines.append("  No VLAN tags detected in capture")
                lines.append(f"  Untagged frames: {session.untagged_frame_count:,}")

        return "\n".join(lines)

    @staticmethod
    def _build_pcap_header(session: Any, *, netops: bool = False) -> str:
        """Build a PCAP context header with key metadata."""
        from plugins.network_forensics.pcap_metadata_summary.tool import is_internal, _format_bytes

        duration = session.duration_seconds or 0.0
        internal_ips = [ip for ip in session.unique_ips if is_internal(ip)]
        external_ips = [ip for ip in session.unique_ips if not is_internal(ip)]

        lines = [
            "=" * 60,
            f"PCAP ANALYSIS: {session.filename or 'unknown'}",
            "=" * 60,
        ]
        packet_count = session.packet_count or 0
        if session.file_size:
            lines.append(
                f"Size: {_format_bytes(session.file_size)} | "
                f"Packets: {packet_count:,} | Duration: {duration:.1f}s"
            )
        else:
            lines.append(
                f"Packets: {packet_count:,} | Duration: {duration:.1f}s"
            )
        if getattr(session, "bytes_transferred", 0):
            lines.append(f"Network bytes transferred: {_format_bytes(session.bytes_transferred)}")
        if session.start_time:
            from datetime import datetime, timezone
            start = datetime.fromtimestamp(session.start_time, tz=timezone.utc)
            end = datetime.fromtimestamp(session.end_time, tz=timezone.utc)
            lines.append(f"Time: {start.strftime('%Y-%m-%d %H:%M:%S')} → {end.strftime('%H:%M:%S')} UTC")

        lines.append(
            f"IPs: {len(session.unique_ips)} total "
            f"({len(internal_ips)} internal, {len(external_ips)} external)"
        )

        # Protocols
        lines.append("\nProtocols:")
        for proto, count in session.protocols.most_common(10):
            pct = (count / session.packet_count * 100) if session.packet_count else 0
            lines.append(f"  {proto:<10} {count:>8,} pkts  ({pct:.1f}%)")

        lines.append(f"\nDNS: {len(session.dns_queries)} queries | "
                     f"HTTP: {len(session.http_requests)} requests | "
                     f"TLS: {len(session.tls_handshakes)} handshakes")

        if session.ot_transactions:
            lines.append(f"OT/ICS: {len(session.ot_transactions):,} transactions")
        if not netops and session.cleartext_creds:
            lines.append(f"⚠️  Cleartext credentials: {len(session.cleartext_creds)} detection(s)")

        return "\n".join(lines)

    @staticmethod
    def _build_comprehensive_summary(session: Any, header: str) -> str:
        """Build comprehensive summary for triage_summary and report modes."""
        from plugins.network_forensics.pcap_metadata_summary.tool import is_internal, _format_bytes
        from plugins.network_forensics.pcap_threat_hunter.tool import PcapThreatHunter

        lines = [header]

        # --- Top Talkers ---
        hunter = PcapThreatHunter()
        talkers_result = hunter.execute({"hunt": "talkers", "top_n": 15}, None)
        if talkers_result.ok and talkers_result.result:
            lines.append("\n" + talkers_result.result.get("summary_text", ""))

        # --- Top Conversations ---
        conv_list = []
        for (src, dst, dport, proto), stats in session.conversations.items():
            conv_list.append((src, dst, dport, proto, stats["bytes_out"], stats["packets"],
                              stats.get("last_seen", 0) - stats.get("first_seen", 0)))
        conv_list.sort(key=lambda c: c[4], reverse=True)

        if conv_list:
            lines.append(f"\n{'=' * 60}")
            lines.append(f"Top {min(20, len(conv_list))} Conversations (by bytes)")
            lines.append(f"{'=' * 60}")
            lines.append(
                f"{'#':<4} {'Source':<18} {'Destination':<18} {'Port':<7} {'Proto':<6} "
                f"{'Bytes':<10} {'Pkts':<8} {'Dir'}"
            )
            lines.append("-" * 80)
            for i, (src, dst, dport, proto, bytes_out, pkts, dur) in enumerate(conv_list[:20], 1):
                src_t = "INT" if is_internal(src) else "EXT"
                dst_t = "INT" if is_internal(dst) else "EXT"
                direction = f"{src_t}→{dst_t}"
                lines.append(
                    f"{i:<4} {src:<18} {dst:<18} {dport:<7} {proto:<6} "
                    f"{_format_bytes(bytes_out):<10} {pkts:<8} {direction}"
                )

        # --- Port Analysis ---
        ports_result = hunter.execute({"hunt": "ports"}, None)
        if ports_result.ok and ports_result.result:
            port_text = ports_result.result.get("summary_text", "")
            if port_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Port Analysis")
                lines.append(f"{'=' * 60}")
                lines.append(port_text)

        # --- Beaconing Check ---
        beacons_result = hunter.execute({"hunt": "beacons"}, None)
        if beacons_result.ok and beacons_result.result:
            beacon_text = beacons_result.result.get("summary_text", "")
            if beacon_text and "No C2 beaconing" not in beacon_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Beaconing Detection")
                lines.append(f"{'=' * 60}")
                lines.append(beacon_text)

        # --- DNS Summary ---
        if session.dns_queries:
            dns_result = hunter.execute({"hunt": "dns"}, None)
            if dns_result.ok and dns_result.result:
                dns_text = dns_result.result.get("summary_text", "")
                if dns_text and "No DNS anomalies" not in dns_text:
                    lines.append(f"\n{'=' * 60}")
                    lines.append("DNS Analysis")
                    lines.append(f"{'=' * 60}")
                    lines.append(dns_text)

        # --- TLS Summary ---
        if session.tls_handshakes:
            tls_result = hunter.execute({"hunt": "tls"}, None)
            if tls_result.ok and tls_result.result:
                tls_text = tls_result.result.get("summary_text", "")
                if tls_text:
                    lines.append(f"\n{'=' * 60}")
                    lines.append("TLS Analysis")
                    lines.append(f"{'=' * 60}")
                    lines.append(tls_text)

        # --- Exfil Check ---
        exfil_result = hunter.execute({"hunt": "exfil"}, None)
        if exfil_result.ok and exfil_result.result:
            exfil_text = exfil_result.result.get("summary_text", "")
            if exfil_text and "No data exfiltration" not in exfil_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Exfiltration Indicators")
                lines.append(f"{'=' * 60}")
                lines.append(exfil_text)

        # --- Lateral Movement ---
        lateral_result = hunter.execute({"hunt": "lateral"}, None)
        if lateral_result.ok and lateral_result.result:
            lateral_text = lateral_result.result.get("summary_text", "")
            if lateral_text and "No lateral movement" not in lateral_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Lateral Movement")
                lines.append(f"{'=' * 60}")
                lines.append(lateral_text)

        return "\n".join(lines)
