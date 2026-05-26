"""
Network Forensics Pillar Plugins

Triage network artifacts collected during an incident.
PCAP analysis, firewall log aggregation, flow analysis.

Available plugins:
    pcap_metadata_summary  — Core PCAP ingestion, parsing, and summary (load/summary/conversations/dns/http/tls)
    pcap_ip_search         — IOC search and IP timeline reconstruction across loaded PCAP data
    pcap_flow_analyzer     — Bidirectional flow aggregation, protocol breakdown, long connections
    pcap_threat_hunter     — 7 threat hunt tools (talkers/ports/beacons/dns/tls/lateral/exfil) with ICS awareness
    pcap_ai_analyzer       — AI-enhanced analysis with 3 prompt tiers and Condition Orange support
    pcap_report_correlator — 3-stage sync_pcap: IOC extraction from reports → PCAP matching → correlated output
    firewall_log_aggregator — Multi-vendor firewall log parsing, aggregation, deny hotspots, port scan detection
"""
