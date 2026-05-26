```mermaid
flowchart TB
    subgraph attack["THREAT-INTEL Attack Graph"]
    direction TB
    N0(["<b>bgh-ransomware-se</b><br/>Initial Access<br/><small>T1566.004 - Spearphishing Voice</small>"])
    N1(["Execution<br/><small>T1219 - Remote Access Tools</small>"])
    N2(["Credential Access<br/><small>T1003.003 - OS Credential Dumping: NTDS</small>"])
    N3(["Lateral Movement<br/><small>T1078 - Valid Accounts</small>"])
    N4(["Impact<br/><small>T1486 - Data Encrypted for Impact</small>"])
    N5(["<b>cloud-centric-ransomware | nation-state-espionage</b><br/>Initial Access<br/><small>T1190 - Exploit Public-Facing Applicat</small>"])
    N6(["Persistence<br/><small>T1098 - Account Manipulation</small>"])
    N7(["Defense Evasion<br/><small>T1078 - Valid Accounts</small>"])
    N8(["Exfiltration<br/><small>T1567.002 - Exfiltration Over Web Service:</small>"])
    N9(["Persistence<br/><small>T1543.002 - Create or Modify System Proces</small>"])
    N10(["Command and Control<br/><small>T1071.004 - Application Layer Protocol: DN</small>"])
    N11(["<b>supply-chain-compromise</b><br/>Initial Access<br/><small>T1195 - Supply Chain Compromise</small>"])
    N12(["Execution<br/><small>T1195.002 - Compromise Software Supply Cha</small>"])
    N13(["Credential Access<br/><small>T1528 - Steal Application Access Token</small>"])
    N14(["Defense Evasion<br/><small>T1070.004 - Indicator Removal: File Deleti</small>"])
    N15(["<b>sophisticated-phishing-aitm</b><br/>Initial Access<br/><small>T1566 - Phishing</small>"])
    N16(["Credential Access<br/><small>T1557 - Adversary-in-the-Middle</small>"])
    N17(["Persistence<br/><small>T1078 - Valid Accounts</small>"])
    N0 --> N1
    N1 --> N2
    N2 --> N3
    N3 --> N4
    N5 --> N6
    N5 --> N9
    N6 --> N7
    N7 --> N8
    N7 --> N4
    N8 --> N4
    N9 --> N10
    N11 --> N12
    N12 --> N13
    N13 --> N14
    N15 --> N16
    N16 --> N17
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
    style N1 fill:#ffffcc,stroke:#cccc00
    style N2 fill:#ffffcc,stroke:#cccc00
    style N3 fill:#ffe0b2,stroke:#e65100
    style N4 fill:#ffe0b2,stroke:#e65100
    style N5 fill:#bbdefb,stroke:#1565c0
    style N6 fill:#ffffcc,stroke:#cccc00
    style N7 fill:#ffe0b2,stroke:#e65100
    style N8 fill:#ffffcc,stroke:#cccc00
    style N9 fill:#ffffcc,stroke:#cccc00
    style N10 fill:#ffcdd2,stroke:#b71c1c
    style N11 fill:#bbdefb,stroke:#1565c0
    style N12 fill:#ffffcc,stroke:#cccc00
    style N13 fill:#ffffcc,stroke:#cccc00
    style N14 fill:#ffcdd2,stroke:#b71c1c
    style N15 fill:#bbdefb,stroke:#1565c0
    style N16 fill:#ffffcc,stroke:#cccc00
    style N17 fill:#ffe0b2,stroke:#e65100
    style LE fill:#bbdefb,stroke:#1565c0
    style LM fill:#ffffcc,stroke:#cccc00
    style LX fill:#ffcdd2,stroke:#b71c1c
    style LC fill:#ffe0b2,stroke:#e65100
    style LG fill:#ccffcc,stroke:#00cc00
    style legend fill:#f5f5f5,stroke:#999
```

**Paths:**
- **bgh-ransomware-se**: A social engineering-led attack abusing unmanaged virtual systems to steal credentials and deploy ransomware.
- **cloud-centric-ransomware**: Attack path exploiting edge devices then leveraging cloud identity manipulation for persistence, data exfiltration, and impact.
- **nation-state-espionage**: Espionage campaign using rapid exploitation of perimeter devices for long-term C2 and intelligence collection.
- **supply-chain-compromise**: Compromise of a software developer to inject malicious code into a product and attack downstream customers.
- **sophisticated-phishing-aitm**: A multi-layered trust abuse campaign using social engineering and AiTM to bypass MFA and gain access.

**Convergence:** T1486 (Impact), T1078 (Lateral Movement)