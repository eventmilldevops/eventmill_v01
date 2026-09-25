# Event Mill Starter Guide
Event Mill is a modular platform under active development. The modular design makes work flows flexible, the instructions in this guide are not the only way to accomplish a task nor are all plugin tools covered. 

Each plugin under active development has an extensive readme with additional examples, output can also vary with the LLM provider chosen or the skill files applied. Experimentation is encouraged. 

# Network Forensics Pillar

## PCAP Upload and Analysis

Follow this runbook when you need to upload packet capture files into GCP and perform PCAP triage using Event Mill.

## Prerequisites

- Access to the your GCP project.
- Permission to upload files to the Event Mill Cloud Storage bucket.
- Access to the Event Mill Cloud Run service.

## 1. Open the GCP Project

Open the your GCP project using your GCP account.

## 2. Open Cloud Storage

In the GCP console, go to Cloud Storage.

In the Buckets section, open the bucket depends on your pillar. Use bucket that ends with “common” as shared space for all pillars. Upload your data.

## 3. Upload PCAP Files

For multiple PCAPs from the same investigation, create a dedicated folder first. This keeps the upload organized and makes it easier to load the files later.

Upload PCAP files by dragging them into the bucket file area or by using the Upload button.

## 4. Open Event Mill

After the PCAP upload is complete, open Event Mill to begin triage.

You can access Event Mill directly using the URL below:

https://labX.eventmill.dev  (where X is your desk number)
login  yegX.bsides  passwd on the desk

If the direct URL is unavailable, open Event Mill from Cloud Run.

Under Services, find and open event-mill.

After opening the service, the Event Mill URL is available in the top section.

## 5. Start a New Event Mill Session

After you sign in to Event Mill, use the workflow below to create a session, connect to one of the AI providers, load the investigation data, run triage, and review the generated outputs.

For a standard pcap investigation, follow the steps in order. Use regular loading for small PCAP files under 70 MB when you want deeper parsing, use --fast for PCAP files between 70 MB and 700 MB when you need quicker triage, and use Zeek-processed loading for PCAP files larger than 700 MB or when Zeek output is already available or specifically required.

### Standard Event Mill Workflow

| Step | Command | Purpose |
|---|---|---|
| 1 | `new [description]` | Start a clean Event Mill session for the investigation. |
| 2 | `pillar network_forensics` | Set the session context to network forensics. |
| 3 | `connect` | Connect to Gemini before running AI-powered analysis. |
| 4 (optional) | `load context_condensed.md` | Load analyst notes or IPAM context for organizational IP awareness. |
| 5 | `files` | List folders and PCAP files available in the GCS bucket. |
| 6 | `load <folder_name>/capture.pcap`<br>Example: `load BSR-INV-001/small_capture_45MB.pcap` | Use for smaller PCAP files under 70 MB when you want deeper packet parsing and load time is not a concern. |
| 7 | `load <folder_name>/capture.pcap --fast`<br>Example: `load BSR-INV-001/large_capture_250MB.pcap --fast` | Use for PCAP files between 70 MB and 700 MB when you need faster first-pass triage using the dpkt fast parser. |
| 8 (optional) | `load <folder_path> --merge --fast` | Merge all PCAP files in a folder into one session using the dpkt fast parser. |
| 9 (alternative) | `zeek <folder_name>/capture.pcap`<br>Example: `zeek BSR-INV-001/large_capture_750MB.pcap` | Process a specific PCAP with Zeek when the file is larger than 700 MB or when Zeek-parsed output is required before loading analysis results. |
| 10 (alternative) | `zeek list` | List available Zeek-processed PCAP folders for files larger than 700 MB or when Zeek output is preferred or required. |
| 11 (alternative) | `zeek load <folder_name>/` | Load Zeek-processed PCAP output from the selected folder. Use this path for PCAP files larger than 700 MB. |
| 12 | `run pcap_ai_analyzer --mode triage_summary` | Run a general security triage summary. |
| 13 | `run pcap_ai_analyzer --mode ot_triage --export_type pdf` | Run OT/ICS triage and export the results as a PDF report. |
| 14 | `run pcap_ai_analyzer --mode netops_triage` | Run network operations triage for infrastructure health, connectivity, and routing-related issues. |
| 15 | `artifacts` | Review generated reports and saved output files. |
| 16 (optional) | `export <artifact_id>`<br>Example: `export artifact_001` | Export a specific artifact after using the artifacts command to find the artifact ID. |

Note: Use regular loading for smaller PCAP files under 70 MB when deeper parsing is preferred. Use --fast for PCAP files between 70 MB and 700 MB or for quick first-pass triage. Use Zeek loading for PCAP files larger than 700 MB, when Zeek output is already available, or when the investigation specifically requires Zeek-parsed data.

## 6. Command Reference

**Analysis Mode Guide**

AI-powered modes require a Gemini connection before running.

**ot_triage** — Use for OT/ICS packet capture investigations.
- Focuses on Modbus, DNP3, S7, EtherNet/IP transactions, write operations, control commands, exception responses, cross-zone ICS traffic, and cleartext credentials on OT networks.
- Best for SCADA field site PCAPs, ICS protocol audits, and Purdue model zone violation checks.

PDF includes a Purdue zone traffic diagram
- Example: `run pcap_ai_analyzer --mode ot_triage --export_type pdf`

**triage_summary** — Use for general security triage of any PCAP.
- Focuses on top talkers, suspicious conversations, DNS anomalies, beaconing/C2, lateral movement, credential exposure, and port scans.
- Best for incident response, SOC alert investigation, and unknown traffic analysis.

Example: `run pcap_ai_analyzer --mode triage_summary`

**netops_triage** — Use for network infrastructure health analysis.
- Focuses on TCP retransmissions/RSTs, ICMP errors, routing loops, ARP storms/conflicts, STP changes, OSPF/EIGRP/HSRP/VRRP stability, and subnet anomaly ranking.

Best for: Troubleshooting network issues, capacity planning, L2/L3 health audits
- Example: `run pcap_ai_analyzer --mode netops_triage`

**hunt_talkers, hunt_beacons, hunt_dns, hunt_tls, hunt_lateral, hunt_exfil** — Use for LLM-narrated threat hunts with MITRE ATT&CK mapping.
- Wraps pcap_threat_hunter's deterministic hunts with AI hypothesis generation and technique mapping.
- Example: `run pcap_ai_analyzer --mode hunt_beacons`

**report** — Use for a general-purpose AI-generated PCAP report (executive summary, IOC extraction, shift handover).

**ot_threat_hunt / ot_report** — Additional OT/ICS-specific threat hunting and reporting modes, alongside ot_triage.

**netops_health / netops_report** — Additional NetOps health-check and report modes, alongside netops_triage.

Condition Orange: add `--condition_orange` to any mode for heightened-alert investigations where false negatives are more costly than false positives.

Loading a network reference file with `load --networks ipam.md` overrides port-based heuristics with real subnet-to-zone mappings in the Purdue traffic flow graph.

### Loading Data Commands

#### Merging PCAP Files

| Command | What it does |
|---|---|
| `load <folder_path> --merge` | Merge every .pcap/.pcapng in that folder into one session in a single call. |
| `load <folder_path> --merge --fast` | Same, using the dpkt fast parser for large captures. |
| `load --merge` | No path — merges every PCAP found at the current workspace location. |
| `load <file> --merge` | Merges one additional file into the already-loaded session (cumulative). |
| `load <file> --merge --fast` | Same, fast parser. |
| `zeek load --merge #,#,#` | Merge multiple Zeek-processed outputs by index (comma-separated), e.g. `zeek load --merge 19,27,35,11`. |
| `zeek load --merge # # #` | Same, space-separated indices. |

`--merge` accumulates packet counts, conversations, DNS/HTTP/TLS records, and OT transactions across all merged files into one PcapSession — useful for splitting a large capture across files or combining captures from multiple collection points.

Static analysis commands do not require Gemini and return immediate results.

| Command | What it does |
|---|---|
| `run pcap_metadata_summary --mode summary` | Quick PCAP stats (packets, IPs, protocols, OT transactions) |
| `run pcap_metadata_summary --mode networks` | List all /24 subnets with host count, flows, bytes |
| `run pcap_metadata_summary --mode networks --filter ot` | Only subnets with OT/ICS traffic |
| `run pcap_metadata_summary --mode networks --filter ext` | Only external subnets |
| `run pcap_metadata_summary --mode networks --sort_by subnet` | Sorted by IP address order |
| `run pcap_metadata_summary --mode conversations` | Top conversations by bytes |
| `run pcap_metadata_summary --mode dns` | DNS query summary |
| `run pcap_metadata_summary --mode http` | HTTP request summary |
| `run pcap_metadata_summary --mode tls` | TLS handshake summary |
| `run pcap_metadata_summary --mode ioc --indicator 10.21.234.5` | Search for a specific IP/domain/port |
| `run pcap_threat_hunter --hunt talkers` | Top talkers by bytes (INT/EXT/ORG labels) |
| `run pcap_threat_hunter --hunt ports` | Port analysis (standard, ICS, suspicious, unknown) |
| `run pcap_threat_hunter --hunt lateral` | Lateral movement + ICS cross-zone detection |
| `run pcap_threat_hunter --hunt beacons` | C2 beaconing detection |
| `run pcap_threat_hunter --hunt dns` | DNS anomaly detection |
| `run pcap_threat_hunter --hunt tls` | TLS certificate anomalies |
| `artifacts` | List all saved output files |
| `run pcap_flow_analyzer --mode bidirectional --top_n 20` | Aggregate bidirectional flows between host pairs, ranked by byte ratio (useful for exfil detection) |
| `run pcap_flow_analyzer --mode long_connections --min_duration_seconds 600` | Flag connections open longer than a duration threshold |
| `run pcap_ip_search --mode ioc --query <ip_or_domain>` | Look up a single IOC across conversations, DNS, HTTP, and TLS records |
| `run pcap_ip_search --mode timeline --ip <ip>` | Chronological activity reconstruction for a host, with optional src/dst/port/proto filters |
| `run pcap_report_correlator --mode full --report_file <path>` | Extract IOCs from a threat report and correlate them against the loaded PCAP |
| `run pcap_threat_hunter --hunt exfil` | Data exfiltration indicators (asymmetric flows, DNS exfil) |
| `run pcap_flow_analyzer --mode bidirectional --top_n 20` | Aggregate bidirectional flows between host pairs, ranked by byte ratio (useful for exfil detection) |
| `run pcap_flow_analyzer --mode long_connections --min_duration_seconds 600` | Flag connections open longer than a duration threshold |
| `run pcap_ip_search --mode ioc --query <ip_or_domain>` | Look up a single IOC across conversations, DNS, HTTP, and TLS records |
| `run pcap_ip_search --mode timeline --ip <ip>` | Chronological activity reconstruction for a host, with optional src/dst/port/proto filters |
| `run pcap_report_correlator --mode full --report_file <path>` | Extract IOCs from a threat report and correlate them against the loaded PCAP |
| `run pcap_threat_hunter --hunt exfil` | Data exfiltration indicators (asymmetric flows, DNS exfil) |

> Note: the last six rows are duplicated in the source document — replicated here as-is.

## 7. Event Mill Help and Navigation

Help and navigation commands

| Command | What it does |
|---|---|
| `help` | List all available Event Mill commands. |
| `tools` | Show all plugins loaded for the current context, such as network_forensics. |
| `help <tool_name>` | Show help for a specific tool. Examples: `help pcap_ai_analyzer`; `help pcap_metadata_summary`; `help pcap_threat_hunter` |

# Threat Modeling Pillar

## 1. Threat Intelligence Ingestion

Use threat_intel_ingester to extract structured indicators, MITRE ATT&CK mappings, and an attack graph from a threat report. This is an LLM workflow and requires connect before execution. The tool belongs to the log_analysis pillar but is also listed under threat_modeling, so it can be run from either.

| Command | What it does |
|---|---|
| `pillar threat_modeling` | Set the session context to threat modeling. |
| `connect` | Binds every configured LLM provider whose key is present. Required before any LLM action — threat_intel_ingester is an LLM workflow and will not run without it. |
| `load /path/to/threat_report.pdf` | Loads the threat report (PDF, HTML, STIX, CSV/JSON IOC list, or text) as an artifact into the current session. For PDFs, native document ingestion is preferred where the provider supports it — preserving tables, layout, and cross-page context that plain text extraction loses. |
| `artifacts` | Lists session artifacts so you can find the ID the load just created (`<artifact_id>`). |
| `run threat_intel_ingester --artifact_id <artifact_id>` | Extracts structured IOCs (IP, domain, hash, CVE, etc.) with MITRE ATT&CK mapping from the loaded report. Reads the whole document by default — max_pages is only a deliberate cost ceiling, not a default limit. Output is a json_events artifact that can be chained into attack_path_visualizer and adversary_path_projector. |

Optional parameters:

| Command | What it does |
|---|---|
| `run threat_intel_ingester --artifact_id <id> --source_context "Mandiant M-Trends 2025"` | Attaches a description (max 500 chars) of the report's source/context to guide extraction. Default is empty. Quote any value that contains spaces. |
| `run threat_intel_ingester --artifact_id <id> --ioc_types ip,domain,cve` | Restricts extraction to specific IOC types (comma-separated). Default set is ip, domain, hash_sha256, url, cve, mitre_technique. |
| `run threat_intel_ingester --artifact_id <id> --confidence_threshold medium` | Sets the minimum confidence level to include an IOC: low, medium, or high. Default is low (most inclusive). |
| `run threat_intel_ingester --artifact_id <id> --max_pages 50` | Caps how many pages are read, as a deliberate cost ceiling — not a quality/accuracy setting. Omitting it reads the whole document (bounded only by the selected provider's own limit: gcp_gemini 1000 pages, anthropic 250, openai 600). Any page cut off by this cap is counted and reported in pages_dropped, and the run is marked partial — pages are never silently dropped. |
| `run threat_intel_ingester --artifact_id <id> --ioc_types ip,domain,mitre_technique --confidence_threshold medium --source_context "CISA advisory"` | Flags combine freely in a single run. |

Omit --max_pages to read the whole document. An explicit value is a cost ceiling and the result reports pages_dropped. Review analysis_status, pages_read, and pages_dropped before relying on the IOC list — an empty IOC list and a failed run look the same unless you read the status. If coverage is reported in lines rather than pages, a text file (often a generated summary) was loaded instead of the PDF.

The output artifact can be passed to attack_path_visualizer to draw the attack graph, or to adversary_path_projector with --intel_artifact_id to add the report's techniques to a threat actor's documented set (see Section 11).

## 2. Threat Report Summaries

Use threat_report_analyzer to read a threat report from the common bucket and produce a markdown summary — executive summary, key actors and techniques, ATT&CK technique IDs, detection opportunities, and recommended controls. The summary becomes context for other tools. This is an LLM workflow and requires connect before execution. It does not build attack paths; use threat_intel_ingester for that.

| Command | What it does |
|---|---|
| `connect` | Required before summarize or search_reports. |
| `run threat_report_analyzer --action list_reports` | Lists threat reports available in the common bucket (mitre/, capec/, cisa/, vendor_advisories/, threat_actors/, campaigns/, vulnerabilities/). |
| `run threat_report_analyzer --action summarize --report_path vendor_advisories/apt29.pdf` | Summarizes one report. --report_path is the path inside the common bucket, as shown by list_reports. |
| `run threat_report_analyzer --action summarize --report_path mitre/enterprise-attack.json --max_word_count 2000` | Sets the target length of the summary (500–4000 words, default 2000). |
| `run threat_report_analyzer --action summarize --report_path capec/capec-stix.xml --focus_areas attack_techniques,mitigations` | Emphasizes specific areas (comma-separated). Repeating the flag appends, so `--focus_areas attack_techniques --focus_areas mitigations` is equivalent. |
| `run threat_report_analyzer --action summarize --report_path vendor_advisories/apt29.pdf --ignore_caps` | Reports every key finding and ATT&CK technique with no upper bound. By default the lists are capped at 50 findings and 200 techniques, and anything cut is named in the analysis notes. |
| `run threat_report_analyzer --action search_reports --query ransomware` | Searches across report content for a keyword. |

Supported formats are PDF, Word, JSON/STIX, XML, markdown, plain text, and CSV. Large reports are read natively where the provider supports it; otherwise they are summarized in sections and then combined.

Check analysis_status (complete, partial, or degraded) and the page counts before relying on a summary — a summary that covers a third of a report looks like one that covers all of it unless you read the status. Each run writes a new stamped summary file rather than overwriting the last one, and every file records the source report, the run time, and the provider and model that answered.

The summary is registered as a text artifact. Use artifacts to find its ID, then pass the summary text to threat_model_analyzer (analyze_document) or risk_assessment_analyzer.

## 3. Threat Modeling

Use threat_model_analyzer to document a scenario, map controls and attack events, identify gaps, and export a report. Scenario state is held in the current shell session until export_scenario is run.

analyze_document — Summarize what a threat model document or tabletop exercise states (assets, threats, controls, gaps) without constructing attack paths or assigning ATT&CK techniques the document does not cite. For a document longer than a line or two, summarize it with threat_report_analyzer first and pass the summary text.

| Command | What it does |
|---|---|
| `run threat_model_analyzer --action create_scenario --name "ERP ransomware" --description "Phish to encryption on the ERP estate" --threat_actor "financially motivated crimeware" --objective "encrypt ERP data" --target_assets erp_db,file_server --entry_vectors phishing,vpn` | Creates a trackable threat scenario with actor, objective, target assets, and entry vectors. --target_assets/--entry_vectors take comma-separated lists. Returns a scenario_id. |
| `run threat_model_analyzer --action add_control --scenario_id <scenario_id> --name "EDR on ERP hosts" --control_type endpoint --implementation_status partial --bypass_difficulty high --detection_capability high` | Adds a security control to the scenario — defense layer (perimeter/network/endpoint/application/data/identity/monitoring), implementation status, bypass difficulty, detection capability. |
| `run threat_model_analyzer --action add_event --scenario_id <scenario_id> --name "Spearphishing attachment" --sequence_order 1 --technique_name "Spearphishing Attachment" --technique_id T1566.001 --tactic "Initial Access" --required_access none --resulting_access user` | Adds one step of the attack sequence, mapped to a MITRE ATT&CK technique/tactic, with the access level required to perform it and gained afterward. |
| `run threat_model_analyzer --action list_scenarios` | Lists every scenario currently tracked in this session, with summary stats. |
| `run threat_model_analyzer --action gap_analysis --scenario_id <scenario_id>` | Identifies attack steps with no implemented control, weak controls, or controls that are easy to bypass. |
| `run threat_model_analyzer --action export --scenario_id <scenario_id> --output_path workspace/artifacts/erp_threat_model.md` | Generates a full markdown report of the scenario (controls, events, gap analysis) and writes it to the given path. |
| `run threat_model_analyzer --action export_scenario --scenario_id <scenario_id>` | Saves the scenario in full (controls + events included) as a json_events artifact so it can be reloaded later with import_scenario. |

To reload a saved scenario after locating its artifact ID, use:

```
run threat_model_analyzer --action import_scenario --artifact_id <artifact_id>
```

import_scenario also accepts a scenario seed from adversary_path_projector (adversary_scenario_seed_*.json, not the attack graph) — each projected path becomes its own scenario, up to --max_paths (default 6, maximum 10); use --path_id to import a single path. Imported scenarios are marked source_type: actor_projection and their reports state the projection is not a confirmed attack.

```
run threat_model_analyzer --action import_scenario --artifact_id <seed_artifact_id> --path_id s3-session-exfil
```

Valid control types are perimeter, network, endpoint, application, data, identity, and monitoring. Use export_scenario before closing or restarting the shell if the scenario must be preserved.

## 4. Adversary Path Projection, Visualization, and Detection Design

Three tools work together to answer a question such as "how exposed is Application B to Scattered Spider, and what can we do about it?":

| # | Tool | LLM | Goes in | Comes out |
|---|---|---|---|---|
| 1 | adversary_path_projector | heavy | threat actor name + flow map of one application | a path graph, a scenario seed, and (optionally) run records |
| 2 | attack_path_visualizer | none | the path graph | a Mermaid or ASCII picture of the paths |
| 3 | attack_path_detection_designer | heavy (drafting only) | the path graph + scenario seed, and the flow map | one detection draft per path step, as JSON |

A flow map is a JSON description of one application — its components, zones, flows, crown jewels, and controls. Six examples ship under `plugins/threat_modeling/adversary_path_projector/examples/`, and the lab uses `application_b_flow_map.json`. Your own map can be uploaded to the bucket, loaded with load, and passed with `--flow_map_artifact_id <artifact_id>` instead of --file_path.

The paths are projections, not findings. Every output says "Projected from threat intelligence, not a confirmed attack path." The projector is triage: it shows whether a control exists where the actor's plausible path lands, and whether there is a credible path nobody has considered. It does not grade how good a control is, score likelihood, or say you are protected.

### Standard Projection Workflow

| Step | Command | Purpose |
|---|---|---|
| 1 | `new [description]` | Start a clean session. Group summaries only read runs from the current session, so finish a comparison before running new again. |
| 2 | `pillar threat_modeling` | Set the session context to threat modeling. |
| 3 | `run adversary_path_projector --action profile_actor --threat_actor "Scattered Spider"` | Free, no LLM. Resolves the actor (name, alias, or ATT&CK ID such as G1015) and lists the techniques ATT&CK attributes to it. The projector may only use these techniques, so a thinly documented actor gives a thin projection. |
| 4 | `run adversary_path_projector --action validate_flow_map --file_path plugins/threat_modeling/adversary_path_projector/examples/application_b_flow_map.json` | Free, no LLM. Checks the flow map, ranks entry points, and lists routes to crown jewels. Read every warning. project_paths refuses a map with blocking errors. |
| 5 | `connect` | Required before project_paths and generate_detections. |
| 6 | `providers probe` | Confirm each provider is actually reachable — connect alone does not check this. |
| 7 | `use gcp_gemini for adversary_path_projector` | Choose which provider projects the paths. |
| 8 | `run adversary_path_projector --action project_paths --threat_actor "Scattered Spider" --file_path plugins/threat_modeling/adversary_path_projector/examples/application_b_flow_map.json --max_paths 3 --runs 3 --run_group ss-appb` | Heavy-tier LLM. Projects up to 3 paths per run, three runs, recorded under the group label ss-appb. Registers one path graph and one scenario seed, plus a run record per run. Note the artifact IDs as they are printed. |
| 9 (optional) | `use anthropic for adversary_path_projector`<br>then repeat step 8 with the same arguments and --run_group | Run the same projection on a second provider. Keep the map, actor, --max_paths, and any --objective identical within a group so differences come from the model. |
| 10 | `run adversary_path_projector --action summarize_run_group --run_group ss-appb --file_path plugins/threat_modeling/adversary_path_projector/examples/application_b_flow_map.json` | Free, no LLM. Counts how often each route recurs per provider and how many providers agree, and writes a markdown report with the assumptions to test. |
| 11 | `run attack_path_visualizer --artifact_id <graph_artifact_id> --format mermaid --attack_type "Scattered Spider"` | Free, no LLM. Draws the path graph. Use the path graph (adversary_path_graph_*.json), not the scenario seed. |
| 12 | `run attack_path_detection_designer --action digest --artifact_ids <graph_artifact_id>,<seed_artifact_id> --flow_map_path plugins/threat_modeling/adversary_path_projector/examples/application_b_flow_map.json` | Free, no LLM. Three readable lines per path step. Confirm the pair is verified and the steps are component_bound before spending anything on drafting. |
| 13 | `use anthropic for attack_path_detection_designer` | Choose which provider drafts the detections — a separate choice from the projection provider. |
| 14 | `run attack_path_detection_designer --action generate_detections --artifact_ids <graph_artifact_id>,<seed_artifact_id> --flow_map_path plugins/threat_modeling/adversary_path_projector/examples/application_b_flow_map.json` | Heavy-tier LLM. Drafts one detection per path step and saves the result as attack_path_detection_designer_<stamp>.json. |
| 15 | `export --all ss-appb` | Copy every tool output in the session to the common bucket before closing. Only the visualizer's output is exported automatically. |

Note: A projection run takes roughly 40–80 seconds, and an invocation is capped at 600 seconds, so --runs 3 is comfortable and --runs 6 is not. To build a bigger group, run --runs 3 again with the same --run_group. Three runs per provider is the minimum at which recurrence is counted.

### adversary_path_projector

| Command | What it does |
|---|---|
| `run adversary_path_projector --action profile_actor --threat_actor APT29` | Profiles an actor. "Cozy Bear", APT29, and G0016 all resolve to the same actor. |
| `run adversary_path_projector --action profile_actor --threat_actor "Scattered Spider" --software_scope all` | Controls how many techniques come from the actor's associated software: none, delivery (default), or all. |
| `run adversary_path_projector --action validate_flow_map --flow_map_artifact_id <artifact_id>` | Validates a flow map you loaded as an artifact. |
| `run adversary_path_projector --action project_paths --threat_actor "Scattered Spider" --file_path <flow_map.json> --objective "exfiltration of customer PII"` | Weights the projection toward a concern the requester named. Keep it the same across a group. |
| `run adversary_path_projector --action project_paths --threat_actor "Scattered Spider" --file_path <flow_map.json> --intel_artifact_id <ingester_output_artifact_id>` | Adds techniques from a threat_intel_ingester output to the actor's set — useful when a recent report is ahead of ATT&CK. |
| `run adversary_path_projector --action project_paths --threat_actor "Scattered Spider" --file_path <flow_map.json> --export` | Writes a run record for a single run. --runs implies --export. |
| `run adversary_path_projector --action project_paths --threat_actor "Scattered Spider" --file_path <flow_map.json> --thinking_level high` | Sets reasoning depth: minimal, low, medium (default), or high. Keep it the same across a group. |

The scenario seed also feeds threat_model_analyzer: `run threat_model_analyzer --action import_scenario --artifact_id <seed_artifact_id>` creates one scenario per projected path (see Section 10).

### attack_path_visualizer

Use attack_path_visualizer to render attack paths from an adversary_path_projector path graph, a threat_intel_ingester output, or stages supplied inline. It does not require an LLM.

| Command | What it does |
|---|---|
| `run attack_path_visualizer --artifact_id <artifact_id> --format mermaid --attack_type "Scattered Spider"` | Renders the attack path as a Mermaid flowchart — entry points blue, mid-chain yellow, exit/terminal red, convergence points orange. Writes .mmd (raw, for Mermaid CLI/VS Code/mermaid.live) and .md (fenced, with path legend, for GitHub/VS Code preview). --attack_type labels the diagram header; set it, or a projection is labelled threat-intel. |
| `run attack_path_visualizer --artifact_id <artifact_id> --format ascii` | Renders one vertical box-and-arrow chain per path in the terminal, with tags ▷ ENTRY, ■ EXIT, ◆ CONVERGE, ? TACTIC, and "also in: `<other paths>`" for shared nodes. Writes a .txt file. |
| `run attack_path_visualizer --artifact_id <artifact_id> --format compact` | One-line technique inventory — every node listed in first-seen order across paths. It's an inventory, not a route. Writes a .txt file. |
| `run attack_path_visualizer --artifact_id <artifact_id> --format both` | Runs ASCII and Mermaid together, writing the .txt plus both .mmd/.md files. |
| `run attack_path_visualizer --artifact_id <gemini_graph_id> --format mermaid --attack_type "SS / gemini"`<br>`run attack_path_visualizer --artifact_id <anthropic_graph_id> --format mermaid --attack_type "SS / anthropic"` | Renders each provider's projection with its own label so they can be compared side by side — look for different entry points, convergence points, and techniques only one model used. |
| `run attack_path_visualizer --artifact_id <artifact_id> --format mermaid --include_controls false` | Same Mermaid render, but suppresses the coverage matrix. Note: --include_controls only has an effect on inline stages input — on the normal artifact/graph route, controls are never drawn regardless of this flag. |

The picture is for orientation, not the record. It is drawn by technique, not by component, and it does not show controls. On a projector graph the ASCII output ends with an "⚠ Unprotected stages" line listing every non-exit technique whatever the flow map declares — that line is not a finding. For whether a control exists where a step lands, read the projector's group summary or the detection designer's digest.

The tool writes rendered output under workspace/artifacts and registers it as a session artifact. On Cloud Run it is also exported to the common bucket automatically, and the gs:// location is printed. Use artifacts to find the generated artifact ID, show `<artifact_id>` to review it, and export `<artifact_id>` to copy it to cloud storage.

Inline stages are the one case that still needs JSON. stages is a list of objects, and a --key value flag cannot express a nested structure, so the shell refuses --stages and points you to the JSON form. Every other example in this guide uses flags.

```
run attack_path_visualizer {"format": "ascii", "attack_type": "ransomware", "stages": [{"name": "Initial Access", "mitre_technique_id": "T1566", "stage_present": true, "controls": []}]}
```

### attack_path_detection_designer

Use attack_path_detection_designer to turn a projection into one detection draft per path step, written against the telemetry that component actually has. Every draft is marked validation_status: draft_unvalidated — the drafts are hypotheses for a detection engineer to test, not rules to deploy.

| Command | What it does |
|---|---|
| `run attack_path_detection_designer --action digest --artifact_ids <graph_artifact_id>,<seed_artifact_id> --flow_map_artifact_id <flow_map_artifact_id>` | Free, no LLM. Three readable lines per step: context grade, technologies, monitoring claim, state check, and the narrowest uncovered ATT&CK mitigations. Use --flow_map_path instead for a map file in the repository. |
| `run attack_path_detection_designer --action validate_input --artifact_ids <graph_artifact_id>,<seed_artifact_id> --flow_map_path <flow_map.json>` | Free, no LLM. Returns the full context pack behind the digest — every field, its origin, and any conflicts between the graph and the seed. Saved as a json_events artifact. |
| `run attack_path_detection_designer --action generate_detections --artifact_ids <graph_artifact_id>,<seed_artifact_id> --flow_map_path <flow_map.json>` | Heavy-tier LLM. Drafts one detection per step, batched by path. |
| `run attack_path_detection_designer --action generate_detections --artifact_ids <graph_artifact_id>,<seed_artifact_id> --flow_map_path <flow_map.json> --thinking_level high` | Sets reasoning depth for drafting: minimal, low, medium (default), or high. |
| `run attack_path_detection_designer --action digest --artifact_id <graph_artifact_id>` | Works from a single document, with less context. The graph and seed pair from the same run is the normal route. |
| `run attack_path_detection_designer --action digest --sources ./path_graph.json,./scenario_seed.json` | Reads local export files that were never registered as artifacts. |

Pass the graph and seed from the same projector run — the designer joins them and records the pair as verified. Supplying the flow map is what lets each step be graded component_bound; without it the drafts know much less about the estate. A flow map you edited is recorded as edited_map and never refused.

Drafting the same pair under two providers gives two sets of drafts with identical draft IDs, so they line up step by step for comparison. Check generation_model on each output before treating it as a cross-vendor result.

If fewer valid drafts come back than there are steps, the run fails with GENERATION_INCOMPLETE, and the drafts that did pass are saved as attack_path_detection_designer_partial_<stamp>.json. Read them, but re-run before treating the set as complete.

When reading a draft, start with these fields under x_eventmill:

| Field | What it tells you |
|---|---|
| `node.telemetry_readiness` | stream_available, periodic_only, or none_declared. none_declared means there is nothing to look at — a collection gap, not a detection to write. |
| `node.context_completeness` | How much of the estate the draft could see. component_bound means it knew the product, zone, and authentication. |
| `assessment` | multistep_access: true means the step depends on access the path never established — test that assumption first. |
| `telemetry.required_fields`, `detection_logic` | The hypothesis to test, using fields the telemetry library says the source actually has. |
| `grounding.limitations`, `caveats` | What the draft cannot see or distinguish. |
| `review_flags` | Questions for whoever tests the rule, such as a field collected but never read, or a condition that fires on a missing value. |

A step that recurs across projections and is drafted consistently across providers is where a built and tested detection pays off most. A step only one model found is an outlier worth reading closely. The same none_declared step in every run is a collection gap to close.

## 12. Cross-Module Workflow

A common workflow is to ingest a report, visualize the resulting attack graph, project the actor onto your own architecture, import the projected paths into a threat scenario, and then analyze control gaps:

| Step | Command | What it does |
|---|---|---|
| 1 | `load /path/to/threat_report.pdf` | Loads a threat intel report (PDF/HTML/text) as an artifact into the current session. |
| 2 | `artifacts` | Lists session artifacts so you can find the ID the load just created (`<report_artifact_id>`). |
| 3 | `run threat_intel_ingester --artifact_id <report_artifact_id>` | Extracts structured IOCs, MITRE ATT&CK mappings, and an attack graph from the loaded report. Produces a new json_events artifact (the "ingester output"). |
| 4 | `run attack_path_visualizer --artifact_id <ingester_output_artifact_id> --format mermaid` | Renders the ingester's attack graph as a Mermaid flowchart — viewable in GitHub, VS Code, or mermaid.live. Orientation only; not the record of controls/state. |
| 5 | `run adversary_path_projector --action project_paths --threat_actor "<actor>" --file_path <flow_map.json> --intel_artifact_id <ingester_output_artifact_id>` | Projects the report's actor onto your application's flow map, with the report's techniques added to the actor's documented set. Produces a path graph and a scenario seed. |
| 6 | `run threat_model_analyzer --action import_scenario --artifact_id <scenario_seed_artifact_id>` | Imports the adversary_path_projector scenario seed into threat_model_analyzer, creating one trackable scenario per projected path. |
| 7 | `run threat_model_analyzer --action gap_analysis --scenario_id <scenario_id>` | Analyzes the imported scenario's attack events against its documented controls — flags steps with no implemented control, weak controls, or easy bypasses. |
| 8 | `run threat_model_analyzer --action export --scenario_id <scenario_id> --output_path workspace/artifacts/scenario.md` | Generates a full markdown report of the scenario (controls, events, gap analysis) and writes it to the given path. |

Do not treat an imported or projected path as confirmation of an attack. Validate the source report, ATT&CK mapping, assumptions, and control coverage before using the output for incident decisions.

# Generative AI Evaluation

Three foundation models have been implemented, a valid API key is required for each model vendor but the platform can work with a single vendor if that is all that is available. 

The benefit of multiple model vendors as well as different versions of models is the ability to evaluate LLM outputs given the same prompt inputs. Generating mulitple data exports using the same input context can also allow comparison of responses over multiple runs in order to identify prevelant patterns.

## 1. Providers & Connecting

| Command | What it does |
|---|---|
| `providers` | Show LLM providers: configured, keyed (has a secret mounted), and their tier bindings. A mounted key ≠ a bound provider — "configured but no key" is expected for unadopted providers. |
| `providers probe` | Probe every provider's reachability over the network: a model-listing call (no tokens spent) plus a small ping per tier. |
| `providers probe <provider_id>` | Probe just one provider (e.g. providers probe anthropic). |
| `connect` | Bind every configured provider whose key is present; builds one client per tier via tiered auto-routing. Makes no network call itself — a client can connect cleanly and still fail at first real use. |
| `connect <model_id>` | Bind a specific model only, instead of every tier. |

## 2. use — Choosing Which Provider Serves Tools

| Command | What it does |
|---|---|
| `use` | Show the current provider selection (session default + any per-tool overrides). |
| `use <provider>` | Set the session default provider for every tool (e.g. use openai). |
| `use <provider> for <tool_name>` | Override the provider for one tool only (e.g. use anthropic for adversary_path_projector). |
| `use default` | Clear the session default provider selection. |
| `use default for <tool_name>` | Clear the override on one tool. |

Notes: this is the supported way to A/B a tool across vendors — the prompt stays byte-identical across the swap, and every response is stamped with the provider that served it. The selection is session-only and never reaches plugin code (a plugin can't see or override it).

## 3. posture — Analysis Stance ("Skills")

| Command | What it does |
|---|---|
| `posture` | Show the current posture selection (session default + per-tool overrides). |
| `posture list` | List postures available to the active pillar (pillar-specific first, then shared). |
| `posture <name>` | Set the session default posture for every tool (e.g. posture paranoid). |
| `posture <name> for <tool_name>` | Override the posture for one tool only (e.g. posture permissive for pcap_threat_hunter). |
| `posture default` | Clear the session default posture. |
| `posture default for <tool_name>` | Clear the override on one tool. |

Shipped postures: paranoid, balanced, permissive (network_forensics also ships its own paranoid.md override). A posture is a .md file whose text is prepended to every LLM call's system context — it changes how ambiguous signal is reasoned about, never what a plugin computes deterministically. Custom .md files dropped into a pillar's postures/ folder (or the shared framework/llm/postures/) are selectable immediately, no restart needed.
