# OT Cyber Threat Intelligence Summary: 2026 Annual Report

## Executive Summary
Cyber incidents with physical consequences in OT environments decreased in 2025, largely due to a temporary lull in ransomware activity; however, this trend is not expected to last. Concurrently, targeted nation-state and hacktivist attacks on critical infrastructure doubled, demonstrating a strategic shift toward disruptive and destructive campaigns. Security analysts must prepare for a resurgence of ransomware and contend with increasingly sophisticated state-sponsored threats that employ destructive techniques like firmware "bricking," necessitating a focus on deterministic, hardware-enforced security controls and engineering-based resilience.

---

## Key Threat Actors & Techniques

Operational Technology (OT) environments in 2025 faced a complex threat landscape dominated by financially motivated ransomware gangs and politically motivated state-sponsored actors. While the overall volume of incidents causing physical impact saw a temporary decline, the severity and strategic nature of attacks, particularly from nation-states, increased significantly.

### 1. Ransomware Groups
Ransomware remains the single largest cause of cyber-induced operational disruptions. These incidents often do not involve a direct compromise of OT assets but instead cripple essential IT systems that physical operations depend upon.

*   **Threat Actors:** Groups such as **Qilin** and **Scattered Lapsus** were active in 2025.
*   **Primary Impact Vector: IT Dependency.** The most common path to OT disruption is the encryption or shutdown of enterprise IT systems. The Jaguar/LandRover incident ($2.5B estimated economic impact) was a prime example, where the compromise of their SAP system halted the just-in-time parts-ordering process, forcing a complete shutdown of manufacturing plants for over a month. Similarly, attacks on United Natural Foods and Collins Aerospace disrupted order processing and airline check-in systems, respectively, leading to millions in losses and widespread operational delays.
*   **Secondary Impact Vector: Abundance of Caution.** In many cases, organizations voluntarily shut down OT operations during an IT ransomware attack. This is a preventative measure to avoid the potential for the attack to pivot into the control network, demonstrating a lack of confidence in the security of the IT/OT interface.
*   **Technique:** Social engineering and phishing remain the primary initial access vectors into IT networks. Once inside, threat actors move laterally to compromise critical business systems (e.g., ERP, logistics) before deploying ransomware.

### 2. Nation-State Actors
State-sponsored attacks doubled in 2025, with a clear focus on critical infrastructure in geopolitical hotspots. These actors are distinguished by their objectives—sabotage, disruption, and intelligence gathering—rather than financial gain. Their capabilities are considered significantly greater than what has been publicly observed, as they often use the simplest effective tool to achieve their mission.

*   **Threat Actors:** The Russian-backed group **ELECTRUM** was identified in the Polish energy sector attack. Other attacks were attributed to US military cyber units and Ukrainian state-aligned groups.
*   **Primary Technique: Destructive Attacks ("Bricking").** The near-miss attack on Polish Distributed Energy Resources (DER) is a critical case study. Attackers gained administrative access to firewalls and systematically destroyed the functionality of control system devices. They used a variety of methods to render equipment permanently inoperable:
    *   Loading corrupted firmware onto RTUs to induce a reboot loop.
    *   Wiping the underlying Linux filesystem of controllers.
    *   Deleting critical system files from protection relays via default FTP accounts.
    *   Executing wiper malware on Windows-based HMIs.
    *   Resetting network devices to factory defaults and changing credentials and IP addresses to make them unreachable.
    This "bricking" of legacy or hard-to-replace equipment poses a severe risk of months-long outages.
*   **Secondary Technique: Disruption of Civilian and Military Logistics.** Attacks targeted Russian systems for tracking food products (Mercury/VetIS) with DDoS, halting supply chains. Another attack disrupted the reprogramming of commercial drones for military use by the Russian army.

### 3. Hacktivists
The line between hacktivism and nation-state activity continues to blur, with many hacktivist groups acting in alignment with, or with the support of, national governments. Their attacks are public-facing and aim to cause disruption while sending a political message.

*   **Primary Technique: Exploitation of Internet-Exposed OT.** Several incidents, including the mis-operation of a Norwegian dam and the shutdown of a small Polish hydro plant, resulted from attackers finding and exploiting internet-facing control system components with weak or default credentials. This remains a common and easily preventable attack vector.
*   **Secondary Technique: Denial of Service (DDoS).** As seen in attacks on Russian logistics and French postal services, DDoS remains an effective tool for disrupting operations that rely on the availability of online systems for tracking and management.
*   **Tertiary Technique: Sensory Manipulation.** Nation-state actors and hacktivists engaged in GPS spoofing and jamming in conflict zones like the Red Sea and Russian waters. This manipulation of external data inputs led to the grounding of multiple large vessels, highlighting the risk of trusting unverified external data in automated systems.

---

## Relevant MITRE ATT&CK® for ICS Techniques

The attacks observed in 2025 map to several techniques within the MITRE ATT&CK for ICS framework, with the Polish DER incident providing the most detailed examples of a destructive OT campaign.

*   **Initial Access**
    *   **T0880 - Remote Services:** Attackers used RDP to gain access to Windows-based HMIs before executing wiper malware.
    *   **T0816 - Default Credentials:** Default FTP and device management credentials were used to access and destroy Hitachi relays and Moxa serial servers.
*   **Execution**
    *   **T0848 - Scripting:** Wipers and file deletion commands (`rm -rf`) were executed on target HMI and RTU systems.
*   **Inhibit Response Function**
    *   **T0819 - Data Destruction:** A core technique in the Polish attack, used to delete essential files from protection relays and wipe filesystems on RTUs and HMIs. This prevents the normal operation of the device.
    *   **T0828 - Firmware Corruption:** Loading bad firmware onto Hitachi RTUs sent them into a permanent reboot loop, effectively inhibiting their control and monitoring functions.
*   **Impair Process Control**
    *   **T0817 - Device Restart/Shutdown:** Forcing a factory reset on Moxa devices is a form of device shutdown that impairs their function in the process.
    *   **T0840 - Modify Parameter:** After resetting Moxa devices, attackers changed the IP address to an unreachable value, a parameter modification that isolates the device from the control network.
    *   **T0836 - Manipulate I/O:** GPS spoofing that led to ship groundings is a form of manipulating I/O. The control system (the ship's navigation) received manipulated input (false position data), leading to an incorrect and dangerous physical output (running aground).
*   **Lateral Movement**
    *   **T0867 - Exploitation of Remote Services:** The attackers in the Polish incident likely moved from compromised firewalls to the end devices using remote protocols like RDP and FTP.

---

## Detection Opportunities & SIEM-Relevant Indicators

Effective detection requires monitoring at the network, host, and process levels, with a focus on anomalous behaviors that deviate from deterministic OT baselines.

*   **Network-Level Detection:**
    *   **Unusual Protocol Usage:** Monitor for protocols like FTP, RDP, or SSH directed at PLCs, RTUs, or relays, especially outside of maintenance windows. An alert on an FTP session to a protection relay is a high-fidelity indicator of malicious activity.
    *   **Anomalous Traffic Patterns:** Ingress traffic from the IT network containing firmware update commands or large file transfers should be heavily scrutinized. SIEM rules should correlate such traffic with change management records.
    *   **Firewall and Network Configuration Changes:** Log and generate high-priority alerts for any rule changes on the IT/OT firewall that increase ingress access. Monitor for unexpected network device configuration changes (e.g., changes to IP addresses or credentials on Moxa servers).
*   **Host- and Device-Level Detection:**
    *   **Anomalous Logins:** SIEM correlation rules should alert on multiple failed login attempts followed by a successful login using a known default credential on any OT device.
    *   **Endpoint Behavior:** On Windows-based HMIs or engineering workstations, monitor for the execution of suspicious command-line utilities or scripts indicative of wipers (`del`, `format`) or reconnaissance.
    *   **Device State Monitoring:** Use network management and operational tools to monitor the health of controllers. A SIEM rule that triggers when multiple devices of the same model and location simultaneously enter a reboot loop or fault state is a strong indicator of a coordinated destructive attack.
*   **Process-Level Detection (Physical Process):**
    *   **External Data Validation:** For systems reliant on external data like GPS, implement logic to compare data from multiple independent sources (e.g., GPS, GLONASS, inertial navigation). Generate an operator alert when a significant, unexplainable discrepancy is detected.
    *   **Physics-Based Anomaly Detection:** Monitor physical process variables for behavior that violates known engineering and physical constraints. For example, an alert for a dam's floodgates opening when reservoir levels are low and no command was issued.

---

## Recommended Security Controls

The 2025 threat landscape underscores the limitations of software-only defenses and highlights the need for deterministic, engineering-grade security controls.

1.  **Adopt a Cyber-Informed Engineering (CIE) Mindset:**
    *   **Integrate "Unhackable" Controls:** Prioritize the use of engineered, non-digital safety mechanisms documented in the CIE Controls Database. This includes physical interlocks, overpressure relief valves, and fail-safe defaults (e.g., spring-loaded brakes) that function reliably even during a total loss of digital control. These controls provide a deterministic backstop against the most sophisticated cyber-attacks.
    *   **Design for Resilience:** Engineer systems to fail into a safe state and ensure that recovery is possible even after a destructive attack. This includes having processes and technology for rapid firmware and configuration restoration.

2.  **Implement Hardware-Enforced Network Segmentation:**
    *   **Eliminate Internet Exposure (Rec. 7):** Perform emergency audits to identify and immediately disconnect any OT assets with direct internet connectivity. This is a foundational and non-negotiable security step.
    *   **Deploy Unidirectional Gateways:** For any data flow from OT to IT networks (e.g., for monitoring or business intelligence), use hardware-enforced unidirectional gateways. This technology, recommended by the UK NCSC, makes the inbound flow of attacks from IT to OT physically impossible, preventing both direct compromise and "abundance of caution" shutdowns.
    *   **Utilize Hardware-Enforced Remote Access:** For the rare cases where remote access is unavoidable, use solutions that provide hardware-enforced, single-session, single-application access. This prevents attackers from using a remote access session as a pivot point for lateral movement.

3.  **Proactively Manage Asset and Supply Chain Risk:**
    *   **Mitigate "Bricking" Risk (Rec. 9):** Create and maintain a complete asset inventory, specifically identifying devices that are obsolete or no longer sold by the manufacturer. For these critical-but-irreplaceable assets, either create an emergency upgrade plan or protect them with the strongest possible deterministic controls (like unidirectional gateways) to prevent destructive attacks.
    *   **Harden All Devices:** Eradicate default credentials from all OT devices, network gear, and applications. Implement strong password policies and disable unused services and ports (e.g., FTP on relays).
    *   **Plan for Supply Chain Failure (Rec. 5):** For critical dependencies on third-party software or cloud services (e.g., Collins Aerospace vMUSE), treat their compromise as an inevitability. Demand evidence of rapid recovery capabilities from the vendor and, more importantly, develop and regularly practice manual fallback procedures to maintain core operations during a third-party outage.

4.  **Strengthen Operational and Procedural Controls:**
    *   **Validate External Inputs (Rec. 6):** Build systems to be "deeply suspicious" of all external data. Where possible, use redundant and diverse sources to validate critical inputs like GPS signals before they are used to automate physical actions.
    *   **Develop an Isolation Plan:** As recommended by the UK NCSC, establish clear plans for isolating systems or entire sites during a major cyber incident. This plan should detail how to "island" critical processes to maintain safety and core functionality while response and recovery are underway.

---

## Sources and References
*   Waterfall Security Solutions / ICS STRIVE, "2026 OT Cyber Threat Report," March 2026.