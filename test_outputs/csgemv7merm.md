```mermaid
flowchart TB
    subgraph attack["THREAT-INTEL Attack Graph"]
    direction TB
    N0(["<b>ecrime-ransomware-sspider</b><br/>Reconnaissance<br/><small>T1598 - Phishing for Information</small>"])
    N1(["Defense Evasion<br/><small>T1078 - Valid Accounts</small>"])
    N2(["Discovery<br/><small>T1082 - System Information Discovery</small>"])
    N3(["Credential Access<br/><small>T1003.003 - OS Credential Dumping: NTDS</small>"])
    N4(["Impact<br/><small>T1486 - Data Encrypted for Impact</small>"])
    N5(["<b>china-nexus-edge-exploit | ecrime-lpe-ransomware</b><br/>Initial Access<br/><small>T1190 - Exploit Public-Facing Applicat</small>"])
    N6(["Persistence<br/><small>T1574.001 - Hijack Execution Flow: DLL Sea</small>"])
    N7(["Command and Control<br/><small>T1071.004 - Application Layer Protocol: DN</small>"])
    N8(["<b>russia-nexus-aitm</b><br/>Initial Access<br/><small>T1566.002 - Phishing: Spearphishing Link</small>"])
    N9(["Credential Access<br/><small>T1557 - Adversary-in-the-Middle</small>"])
    N10(["Collection<br/><small>T1114.003 - Email Collection: Email Forwar</small>"])
    N11(["<b>dprk-supply-chain</b><br/>Initial Access<br/><small>T1195.002 - Compromise Software Supply Cha</small>"])
    N12(["Execution<br/><small>T1219 - Remote Access Software</small>"])
    N13(["Credential Access<br/><small>T1528 - Steal Application Access Token</small>"])
    N14(["Privilege Escalation<br/><small>T1068 - Exploitation for Privilege Esc</small>"])
    N0 --> N1
    N1 --> N2
    N1 --> N10
    N2 --> N3
    N3 --> N4
    N5 --> N6
    N5 --> N14
    N6 --> N7
    N8 --> N9
    N9 --> N1
    N11 --> N12
    N12 --> N13
    N14 --> N4
    end

    subgraph legend[" "]
    direction LR
    LE["Entry Point"]
    LM["Mid-chain"]
    LX["Exit / Terminal"]
    LC["Convergence"]
    LG["Has Controls"]
    end

    style N0 fill:#bbdefb,stroke:#1565c0
    style N1 fill:#ffe0b2,stroke:#e65100
    style N2 fill:#ffffcc,stroke:#cccc00
    style N3 fill:#ffffcc,stroke:#cccc00
    style N4 fill:#ffe0b2,stroke:#e65100
    style N5 fill:#bbdefb,stroke:#1565c0
    style N6 fill:#ffffcc,stroke:#cccc00
    style N7 fill:#ffcdd2,stroke:#b71c1c
    style N8 fill:#bbdefb,stroke:#1565c0
    style N9 fill:#ffffcc,stroke:#cccc00
    style N10 fill:#ffcdd2,stroke:#b71c1c
    style N11 fill:#bbdefb,stroke:#1565c0
    style N12 fill:#ffffcc,stroke:#cccc00
    style N13 fill:#ffcdd2,stroke:#b71c1c
    style N14 fill:#ffffcc,stroke:#cccc00
    style LE fill:#bbdefb,stroke:#1565c0
    style LM fill:#ffffcc,stroke:#cccc00
    style LX fill:#ffcdd2,stroke:#b71c1c
    style LC fill:#ffe0b2,stroke:#e65100
    style LG fill:#ccffcc,stroke:#00cc00
    style legend fill:#f5f5f5,stroke:#999
```

**Paths:**
- **ecrime-ransomware-sspider**: SCATTERED SPIDER's attack path using social engineering to access VMware infrastructure for credential theft and ransomware deployment.
- **china-nexus-edge-exploit**: China-nexus actors' typical path exploiting internet-facing devices for long-term intelligence collection.
- **russia-nexus-aitm**: COZY BEAR's multi-layered trust abuse campaign using Adversary-in-the-Middle phishing to compromise cloud accounts.
- **dprk-supply-chain**: DPRK-nexus actors' use of software supply chain compromises for financial theft and espionage.
- **ecrime-lpe-ransomware**: General eCrime path involving exploitation of a public-facing app followed by LPE before impact.

**Convergence:** T1078 (Defense Evasion), T1486 (Impact)