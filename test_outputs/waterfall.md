# OT/ICS Threat Intelligence Summary: 2026 Annual Report

### **Executive Summary**
In 2025, cyber incidents causing physical consequences in OT environments decreased, primarily due to a temporary lull in ransomware activity; however, this trend is not expected to continue. Nation-state and hacktivist attacks with physical impacts doubled, demonstrating a clear intent to disrupt critical infrastructure, as highlighted by the near-miss attack on Poland's energy sector which aimed to permanently disable ("brick") control systems. Security teams must prioritize deterministic, hardware-enforced defenses and resilience planning to counter increasingly sophisticated threats capable of causing long-term operational outages.

---

### **Key Threat Actors & Techniques**

#### **1. Ransomware Criminal Syndicates**
Ransomware remains the predominant threat causing physical disruption in OT environments. While the total number of incidents temporarily declined in 2025, the impact of successful attacks remains severe, with single incidents causing unprecedented financial losses.

*   **Primary Modus Operandi:** Ransomware attacks typically compromise enterprise IT networks through common vectors like phishing. The physical impact on OT is often a secondary effect, resulting from:
    *   **Abundance of Caution Shutdowns:** Operators halt physical processes to prevent the attack from spreading from the compromised IT network into the OT environment.
    *   **IT/OT Dependencies:** The encryption or disruption of critical IT systems (e.g., ERP, scheduling, logistics) essential for OT operations forces a production stoppage. The Jaguar/LandRover incident, which crippled the SAP system and halted parts ordering, is a prime example.
    *   **Supply Chain Disruption:** Attacks on third-party suppliers or cloud service providers can cripple dependent operations. The Collins Aerospace incident illustrates this, where ransomware impacting their vMUSE system caused widespread airport delays.
*   **Noteworthy Groups/Incidents:**
    *   **Scattered Lapsus (Attributed):** Implicated in the **Jaguar/LandRover** attack, which led to a five-week shutdown and an estimated economic impact of $2.5 billion, making it one of the costliest OT-related cyberattacks on record.
    *   **Unknown Ransomware Actors:** Responsible for major disruptions at **United Natural Foods** ($400M in lost sales), **Asahi Group**, and **Bridgestone**, demonstrating the broad impact across manufacturing, food & beverage, and transportation sectors.

#### **2. Nation-State Actors**
Nation-state attacks doubled in 2025, with a strong focus on critical infrastructure targets, often linked to geopolitical conflicts like the Russian invasion of Ukraine. These actors demonstrate advanced capabilities, including long-term persistence and the ability to cause permanent equipment damage.

*   **Primary Modus Operandi:**
    *   **Long-Term Persistence:** Adversaries gain and maintain access to target networks for months before executing an attack, as seen in the Polish energy sector incident.
    *   **Firmware Corruption & Destruction ("Bricking"):** The most alarming technique observed is the deliberate corruption and erasure of firmware on industrial controllers (RTUs, PLCs, protective relays). This moves beyond simple disruption to permanent hardware damage, potentially requiring emergency engineering projects and causing months of downtime if replacement parts are unavailable.
    *   **Exploitation of Default Credentials & Trust Relationships:** Actors leverage weak configurations, such as default credentials on devices (Moxa, Hitachi) and administrative privileges on network boundary devices (firewalls), to move laterally and execute their payload.
    *   **Signal Spoofing/Jamming:** In conflict zones, GPS jamming and spoofing is used to cause physical consequences, such as forcing container ships like the **MSC Antonia** to run aground.
*   **Noteworthy Incidents:**
    *   **Russian State Actors (ELECTRUM Implied):** The coordinated attack on **Polish Distributed Energy Resources (DER)** was a significant near-miss. Attackers bricked multiple types of industrial hardware from different vendors by deleting essential files, loading corrupt firmware, and running wipers on HMIs.
    *   **US Military:** Conducted a cyberattack to disrupt Iranian air defenses during a kinetic military operation.
    *   **Ukrainian State Actors:** Executed disruptive attacks against Russian infrastructure, including DDoS attacks on logistics systems (Platon) and compromising systems used to reprogram military drones.

#### **3. Hacktivists**
The line between hacktivists and nation-state proxies continues to blur. These groups primarily target infrastructure to make a political statement, often employing less sophisticated but still effective techniques.

*   **Primary Modus Operandi:**
    *   **Exploitation of Internet-Exposed OT:** Hacktivists consistently target and compromise control systems left exposed to the public internet. Incidents at a **Norwegian dam** and a **Polish hydro plant** involved attackers accessing HMIs or control panels via the internet to manipulate physical processes.
    *   **Denial-of-Service (DDoS):** Used to disrupt critical services, such as the attack by the "IT Army of Ukraine" on Russia's **VetIS/Mercury** food tracking system, which halted food shipments.
*   **Key Trend:** While often viewed as less sophisticated, their willingness to directly interact with control systems poses a direct threat to safety and availability. The low barrier to entry for these attacks makes any internet-exposed OT asset a potential target.

---

### **Relevant MITRE ATT&CK® Techniques**

The following TTPs were observed or can be inferred from the incidents detailed in the 2026 report.

#### **MITRE ATT&CK for ICS**

*   **Initial Access**
    *   **T0819: External Remote Services:** Exploitation of internet-facing control systems, as seen in the hacktivist attacks on the Norwegian and Polish hydro facilities.
    *   **T0865: Valid Accounts: Default Accounts:** Used in the Polish DER attack to access Moxa device servers and Hitachi relays via default FTP accounts.
*   **Execution**
    *   **T0849: Program Upload:** Used to load corrupt firmware onto Hitachi RTUs in the Polish DER attack, causing a reboot loop.
    *   **T0857: User Execution:** Adversary ran a "wiper" program on Windows-based HMI computers via RDP in the Polish DER attack.
*   **Persistence**
    *   **T0845: Modify System Image:** Corrupting the firmware on RTUs and relays serves as a form of destructive persistence, preventing the device from functioning correctly on reboot.
*   **Defense Evasion**
    *   **T0836: Modify/Delete Files:** Adversaries deleted essential files from Hitachi Relion relays and attempted to delete the entire filesystem on Mikronika RTUs.
*   **Impact**
    *   **T0818: Firmware Corruption:** The central technique in the Polish DER attack, rendering multiple device types unbootable.
    *   **T0880: Wiper:** A wiper program was executed on HMI computers to corrupt and delete files.
    *   **T0826: Inhibit Response Function:** By bricking protective relays and RTUs, the adversary removed the ability for operators to monitor and control the DER sites.
    *   **T0832: Loss of Availability:** The ultimate goal of the DER attack and the result of the ransomware-induced shutdowns.
    *   **T0830: Manipulation of Control:** Achieved by the hacktivists who opened floodgates at the Norwegian dam and by the GPS spoofing that altered ships' courses.
    *   **T0855: System Shutdown/Reboot:** Observed in the reboot loops forced upon Hitachi RTUs.

#### **MITRE ATT&CK for Enterprise (Relevant to IT Compromises Leading to OT Impact)**

*   **Initial Access**
    *   **T1566: Phishing:** Explicitly mentioned as the initial vector for the Jaguar/LandRover incident.
*   **Impact**
    *   **T1486: Data Encrypted for Impact:** The core technique of ransomware attacks that cripple IT systems (e.g., SAP, vMUSE) and indirectly shut down OT operations.

---

### **Detection Opportunities & SIEM-Relevant Indicators**

Security analysts should focus monitoring and alerting on the following activities, which are indicative of the TTPs observed in 2025.

1.  **Anomalous Access to OT Devices:**
    *   **SIEM Alert:** Generate high-priority alerts for any successful login to industrial devices (PLCs, RTUs, relays, device servers) using known default credentials.
    *   **Network Monitoring:** Monitor for management protocols (FTP, Telnet, RDP, SSH) being used to connect to Level 1/Level 0 devices from unusual IT or external sources. A baseline of normal engineering access is critical.
    *   **Indicator:** Multiple failed logins followed by a successful login from a new source IP to an HMI or engineering workstation.

2.  **Suspicious Firmware and Configuration Changes:**
    *   **SIEM Alert:** Correlate program/firmware download commands with change control records. Any firmware modification activity outside of a scheduled maintenance window should be a critical alert.
    *   **Network Monitoring:** Detect large file transfers to OT controllers that are inconsistent with normal process data exchange.
    *   **Indicator:** Use of commands associated with file deletion (`rm`) or system reset on Linux-based controllers.

3.  **Wiper and Ransomware Activity:**
    *   **Endpoint Detection (HMI/Servers):** Monitor for the execution of unsigned or unknown binaries on HMIs, especially those followed by high-volume file read/write/delete operations. Enable process and command-line logging.
    *   **Network Monitoring:** Use IDS/IPS signatures for known ransomware and wiper malware families. Monitor for traffic patterns associated with data encryption spreading across the network.
    *   **Indicator:** An HMI establishing an RDP session and subsequently executing a newly created executable file.

4.  **External and Boundary Monitoring:**
    *   **SIEM Alert:** Alert on any traffic originating from an OT network destined for the public internet.
    *   **Log Analysis:** Regularly audit firewall and remote access logs for unusual connections, rule changes, or traffic flows between IT and OT zones. The Polish attackers had administrative access to firewalls; monitoring for unauthorized configuration changes is key.
    *   **Indicator:** A sudden increase in denied traffic at the IT/OT boundary, potentially indicating scanning or an attempted breach.

---

### **Recommended Security Controls**

Based on the 2025 threat landscape, a defense-in-depth strategy must be augmented with deterministic controls that are resilient to sophisticated software-based attacks.

1.  **Adopt a Cyber-Informed Engineering (CIE) Mindset:**
    *   **Implement "Unhackable" Controls:** Use the CIE Controls Database to engineer resilience. This includes physical, non-digital controls like overpressure relief valves, fail-safe mechanisms (e.g., spring-loaded brakes), and one-way physical devices (ratchets, check valves).
    *   **Design for Resilience:** Ensure that even if cyber protections fail, physical systems remain safe and can recover. This includes having redundant, independent protection and control systems.

2.  **Implement Hardware-Enforced Network Controls:**
    *   **Isolate OT from the Internet:** This is a critical, non-negotiable emergency action. No OT device should be directly accessible from the internet.
    *   **Deploy Unidirectional Gateways:** To prevent the propagation of attacks from IT to OT, use hardware-enforced unidirectional gateways. This technology allows data to flow out of the OT network for monitoring but makes it physically impossible for attack code to flow in, directly countering ransomware and nation-state pivot attacks.
    *   **Utilize Hardware-Enforced Remote Access:** For necessary remote access, use solutions that isolate the OT network and prevent an attacker who has compromised an IT workstation from pivoting into the control environment.

3.  **Strengthen Resilience Against Destructive Attacks:**
    *   **Plan for "Bricking" Events:** Maintain a detailed asset inventory, specifically identifying older, out-of-support devices for which replacements are not readily available. Develop and resource an emergency upgrade plan in case of a mass-bricking incident.
    *   **Develop Manual Fallbacks:** For operations dependent on vulnerable third-party or cloud systems, create, document, and practice manual fallback procedures to ensure continued operation during an outage.
    *   **Validate External Inputs:** Treat external data sources like GPS as inherently untrustworthy. Implement redundant, dissimilar systems for cross-validation (e.g., inertial navigation, radar) and train operators to recognize and respond to spoofing.

4.  **Enhance Foundational Cybersecurity Hygiene:**
    *   **Eliminate Default Credentials:** Conduct a comprehensive audit of all OT devices and change every default password. Implement strong, unique passwords and manage them securely.
    *   **Harden the OT Boundary:** Centralize and minimize IT/OT connections. Aggressively manage firewall rules and ensure administrative access is protected by multi-factor authentication.
    *   **Micro-segmentation:** Implement internal network segmentation within the OT environment to contain threats and prevent an adversary from moving freely after an initial breach.
    *   **Logging and Monitoring:** Ensure comprehensive logging from OT devices, network equipment, and servers is collected in a central SIEM to enable the detection opportunities listed above.

---

### **Sources and References**

*   2026 OT Cyber Threat Report - Waterfall Security Solutions / ICS STRIVE