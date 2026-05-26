# OT/ICS Threat Intelligence Summary: 2025 Year in Review

### Executive Summary
In 2025, adversaries targeting Operational Technology (OT) demonstrated a significant strategic shift from passive access-building to active operational preparation. Threat actors are now systematically mapping industrial control loops, exfiltrating OT-specific data like configuration files and alarm data, and positioning themselves to cause physical disruption. The timeline from initial compromise to operational readiness is compressing, largely due to a division of labor where initial access brokers (IABs) hand off compromised environments to specialized OT-focused teams.

---

### Key Threat Actors & Evolving Techniques

This report identifies three new threat groups and documents significant evolution in the capabilities and targeting of established actors.

#### New Threat Groups Identified in 2025

**1. AZURITE (ICS Kill Chain Stage 2)**
*   **Targeting:** Manufacturing, Electric, Oil & Gas, Defense sectors in the US, Europe, and Asia-Pacific. Shares overlaps with Flax Typhoon.
*   **Core Mission:** Intelligence gathering and long-term persistence to support future offensive operations. AZURITE focuses on exfiltrating OT operational data (project files, alarm data, process information) from Engineering Workstations (EWS) rather than typical intellectual property theft.
*   **Key Techniques:**
    *   **Initial Access:** Exploits vulnerabilities in internet-facing edge devices (Ivanti, Fortinet, Cisco, F5).
    *   **C2 & Infrastructure:** Uses compromised SOHO routers and VPS infrastructure.
    *   **Execution:** Employs extensive Living-off-the-Land (LOTL) techniques, open-source tooling (Metasploit, Mimikatz), and various web shells (Chopper, Godzilla).
    *   **Lateral Movement:** Uses RDP with compromised credentials to access EWS. Stages data outside the OT network before exfiltration.

**2. PYROXENE (ICS Kill Chain Stage 2 - Develop)**
*   **Targeting:** Supply chain entities supporting Defense, Transportation, and Critical Infrastructure in the US, Europe, and the Middle East. Overlaps with APT35.
*   **Core Mission:** Pre-positions for future disruptive effects by compromising the broader industrial ecosystem. Collaborates with IABs like PARISITE.
*   **Key Techniques:**
    *   **Initial Access:** Leverages recruitment-themed social engineering campaigns and strategic web compromises (watering-hole attacks), such as the one against a water utility supporting Haifa Bay Port.
    *   **Execution:** Deploys custom malware and wiper variants during periods of geopolitical tension.
    *   **Persistence:** Establishes backdoors using victim-specific Azure-based C2 infrastructure.
    *   **Reconnaissance:** Conducts extensive reconnaissance of OT pathways from compromised IT networks.

**3. SYLVANITE (ICS Kill Chain Stage 1)**
*   **Targeting:** Electric, Water, Oil & Gas, and Manufacturing sectors in North America, Europe, and Asia.
*   **Core Mission:** Functions as a large-scale Initial Access Broker, specializing in rapid weaponization of N-day vulnerabilities and handing off access to Stage 2 adversaries like **VOLTZITE**.
*   **Key Techniques:**
    *   **Initial Access:** Rapidly exploits vulnerabilities in internet-facing products like Ivanti EPMM & Connect Secure, F5 BIG-IP, and SAP NetWeaver.
    *   **Post-Exploitation:** Deploys web shells (Godzilla, LIGHTWIRE), tunneling tools (Fast Reverse Proxy), and reconnaissance scanners (fscan).
    *   **Credential Access:** Dumps credentials and authentication tokens from compromised devices, particularly from backend databases (e.g., LDAP details, Office 365 tokens).
    *   **Lateral Movement:** Uses built-in Windows tools like PsExec, WMI, and WinRM.

#### Established Threat Group Updates

**1. KAMACITE (Access Development) & ELECTRUM (Disruptive Operations)**
*   **Evolution:** After years focused on Ukraine, this duo expanded operations to the US and Europe. They remain the most operationally experienced infrastructure-disrupting adversaries.
*   **KAMACITE Activity (2025):**
    *   **European Supply Chain Campaign:** Shifted from targeting Ukrainian entities to compromising suppliers and vendors across the European ICS supply chain.
    *   **U.S. Reconnaissance Campaign (March-July):** Conducted sustained, non-opportunistic scanning of internet-exposed ICS devices in the U.S. This activity focused on mapping entire **control loops** by enumerating HMIs (Schneider Smart HMIs), actuators (Altivar VFDs), meters (Accuenergy AXM), and gateways (Sierra Wireless Airlink).
*   **ELECTRUM Activity (2025):**
    *   **Destructive Malware:** Deployed a new wiper variant, **PathWiper**, against Ukrainian entities.
    *   **Polish Energy Sector Attack:** Targeted distributed energy resources (DERs), including combined heat and power (CHP) facilities in Poland, marking a significant attack against modern energy systems.

**2. VOLTZITE (ICS Kill Chain Stage 2)**
*   **Evolution:** Graduated to a Stage 2 threat group by moving beyond data exfiltration to direct manipulation of OT systems.
*   **Key Techniques (2025):**
    *   **Initial Access:** Compromised Sierra Wireless Airlink cellular gateways (RV50/RV55) to pivot directly into OT networks.
    *   **Actions on Objectives:** Gained access to Engineering Workstations and manipulated software to dump configuration files and alarm data, actively investigating how to cause process shutdowns.
    *   **Reconnaissance:** Continued to exploit GIS software (Trimble Cityworks) to exfiltrate data for planning future disruptive attacks.

**3. BAUXITE**
*   **Evolution:** Escalated from hacktivist-style defacements to deploying destructive capabilities.
*   **Key Techniques (2025):**
    *   **Destructive Attacks:** Deployed two custom wiper malware variants against targets in Israel during regional conflict.
    *   **Psychological Operations:** Conducted a threatening email campaign targeting ICS vendors and security researchers to amplify notoriety and apply pressure.

#### Ransomware Trends
*   **Mischaracterization:** A significant number of OT ransomware incidents are misclassified as "IT-only" because responders fail to recognize systems like EWS and HMIs running Windows as OT assets.
*   **Targeting Virtualization:** Affiliates increasingly target OT-adjacent VMware ESXi hypervisors. By encrypting the virtualization layer, they cause denial of view and control over SCADA and HMI systems without using ICS-specific malware.
*   **Identity-Centric Attacks:** Adversaries are bypassing perimeter controls by using stolen credentials from infostealers and IABs to legitimately authenticate. Groups like **Scattered Lapsus$ (TAT25-84)** exploit help desk workflows and MFA gaps to compromise enterprise systems (ERP, Azure AD) that have direct downstream impacts on OT operations.

---

### Relevant MITRE ATT&CK® Techniques

The observed adversary behaviors map to the following MITRE ATT&CK for Enterprise and ICS techniques:

| Tactic (Enterprise / ICS) | Technique ID | Technique Name | Associated Actors/Trends |
| :--- | :--- | :--- | :--- |
| Initial Access | T1190 | Exploit Public-Facing Application | AZURITE, SYLVANITE, VOLTZITE |
| Initial Access | T1566 | Phishing | KAMACITE, PYROXENE |
| Initial Access | T1078 | Valid Accounts | Ransomware, VOLTZITE, AZURITE |
| Execution | T1203 | Exploitation for Client Execution | PYROXENE (Watering-Hole) |
| Execution / Execution | T1059.001 / T0859 | PowerShell / Scripting | SYLVANITE, VOLTZITE |
| Persistence | T1505.003 | Web Shell | AZURITE, SYLVANITE |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | AZURITE (JuicyPotato) |
| Discovery / Discovery | T1082 / T0869 | System Information Discovery | KAMACITE, VOLTZITE, AZURITE |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | AZURITE, Ransomware |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | SYLVANITE, Ransomware |
| Collection / Collection | T1119 / TA0102 | Automated Collection | AZURITE (OT data), VOLTZITE (GIS/Config) |
| C2 / C2 | T1090 | Proxy | AZURITE, SYLVANITE |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | AZURITE, VOLTZITE |
| Impact / Impact | T1485 / T0814 | Data Destruction | ELECTRUM (PathWiper), BAUXITE (Wipers) |
| Impact / Impact | T1486 / T0803 | Data Encrypted for Impact | Ransomware Groups |
| Impact | T0831 | Manipulation of Control | VOLTZITE (EWS manipulation), ELECTRUM |
| Impact | T0826 | Loss of View | Ransomware (via ESXi encryption) |

---

### Detection Opportunities & SIEM-Relevant Indicators

Security teams should focus on detecting adversary behaviors across the kill chain, not just at the point of impact.

*   **Anomalous Remote Access:**
    *   Monitor VPN logs for connections from unusual geolocations, multiple failed logins followed by success, or session durations/data transfers that deviate from baseline.
    *   Hunt for RDP or SSH connections originating from newly provisioned or unusual internal sources, especially from IT to OT segments.
*   **Living-off-the-Land (LOTL) Abuse:**
    *   Enable and centralize PowerShell script block logging (Event ID 4104) and module logging. Search for suspicious commandlets related to network scanning, credential dumping, or remote execution (`Invoke-Expression`, `Invoke-WmiMethod`).
    *   Monitor for abnormal parent-child process relationships, such as `wmic.exe` or `psexec.exe` spawning from a web server process.
*   **Network Reconnaissance and Movement:**
    *   Alert on the use of network scanning tools (`fscan`, Advanced IP Scanner, `nmap`) within the environment, particularly scanning from IT towards OT networks.
    *   Detect anomalous SOCKS/SOCKS5 protocol usage (**AZURITE**).
    *   Monitor for unauthorized Modbus write commands (Function Code 16) or S7comm "STOP" commands being sent to PLCs.
*   **Credential Theft and Reuse:**
    *   Monitor for the execution of credential dumping tools like Mimikatz or the use of `lsass.exe` as a target process.
    *   Audit for service accounts being used for interactive logons, a common precursor to lateral movement.
*   **Edge Device Compromise:**
    *   Monitor edge devices (firewalls, VPN concentrators, cellular gateways) for unexpected reboots, new local user account creation, or egress traffic to known malicious IPs/domains.
    *   Look for web shell indicators in web server logs, such as requests to unusual `.jsp` or `.aspx` files with command parameters.

---

### Recommended Security Controls (Dragos 5 Critical Controls)

1.  **ICS Incident Response Plan (CC1):** Develop and regularly exercise an OT-specific IR plan. Scenarios should focus on operational consequences like loss of view/control and test coordination between engineering, operations, and cybersecurity teams.
2.  **A Defensible Architecture (CC2):**
    *   **Segmentation:** Implement and enforce strict network segmentation between IT and OT. All traffic crossing the boundary should be denied by default and explicitly allowed via firewall rules.
    *   **Eliminate Exposure:** Remove direct internet exposure for all OT devices, including PLCs, HMIs, and EWS. Remote access should terminate in a DMZ.
3.  **ICS Network Visibility and Monitoring (CC3):**
    *   Deploy an ICS-aware network monitoring solution capable of deep packet inspection for OT protocols.
    *   Establish a baseline of normal network activity to detect anomalous communications, unauthorized device additions, or unexpected configuration changes. Collect and retain logs from OT-boundary devices and critical OT assets.
4.  **Secure Remote Access (CC4):**
    *   **Enforce MFA:** Mandate Multi-Factor Authentication for all remote access to the OT environment, including for vendors and third parties.
    *   **Harden Gateways:** Ensure all internet-facing gateways (VPNs, cellular routers) are hardened, continuously monitored, and promptly patched.
5.  **Risk-Based Vulnerability Management (CC5):**
    *   Prioritize vulnerabilities based on risk, not just CVSS score. Focus on "Now" vulnerabilities: those with public proof-of-concept code that are actively exploited and located on internet-exposed or critical boundary systems.
    *   Develop compensating controls (e.g., network segmentation, monitoring rules) for vulnerabilities that cannot be immediately patched.

---

### Sources and References

*   **Primary Source:** Dragos, Inc. (February 2026). *9th Annual Year in Review | OT/ICS Cybersecurity Report*. Dragos-2026-OT-Cybersecurity-Report-A-Year-in-Review.pdf.