
+========================================================================================================+
|                                      ATTACK GRAPH - THREAT-INTEL                                       |
|                                        4 path(s), 17 techniques                                        |
+========================================================================================================+

  Path: scattered-spider-ransomware - An evasive ransomware attack leveraging social engineering and abuse of virtualization to dump credentials from a domain controller.
  Path: china-nexus-edge-exploitation - A state-sponsored intrusion starting with exploitation of an edge device, followed by persistence and C2 establishment.
  Path: dprk-supply-chain-theft - A supply chain attack compromising a software provider to inject malicious code leading to large-scale financial theft.
  Path: cozy-bear-aitm - A sophisticated phishing campaign using Adversary-in-the-Middle techniques to bypass MFA and gain access to cloud services.

  ▷ ENTRY
  +----------------------------------------+   +----------------------------------------+   +----------------------------------------+   +----------------------------------------+
  | [T1190] Initial Access                 |   | [T1195.002] Initial Access             |   | [T1566.002] Initial Access             |   | [T1598.003] Initial Access             |
  |   Exploit Public-Facing Application    |   |   Compromise Software Supply Chain     |   |   Spearphishing Link                   |   |   Spearphishing Voice                  |
  |   └▶ T1574.002                         |   |   └▶ T1059.007                         |   |   └▶ T1557                             |   |   └▶ T1078                             |
  +----------------------------------------+   +----------------------------------------+   +----------------------------------------+   +----------------------------------------+
                        │
                        ▼
  +----------------------------------------+   +----------------------------------------+   +----------------------------------------+   +----------------------------------------+
  | [T1059.007] Execution                  |   | [T1078] Defense Evasion                |   | [T1557] Credential Access              |   | [T1574.002] Persistence                |
  |   Command and Scripting Interpreter: J |   |   Valid Accounts                       |   |   Adversary-in-the-Middle              |   |   Hijack Execution Flow: DLL Search Or |
  |   └▶ T1657                             |   |   └▶ T1087.002                         |   |   └▶ T1078                             |   |   └▶ T1071.004                         |
  +----------------------------------------+   +----------------------------------------+   +----------------------------------------+   +----------------------------------------+
                        │
                        ▼
  +----------------------------------------+   +----------------------------------------+   +----------------------------------------+   +----------------------------------------+
  | [T1071.004] Command and Control        |   | [T1078] Persistence                    |   | [T1087.002] Discovery                  |   | [T1657] Impact                         |
  |   Application Layer Protocol: DNS      |   |   Valid Accounts                       |   |   Account Discovery: Domain Account    |   |   Financial Theft                      |
  |                                        |   |   └▶ T1114.002                         |   |   └▶ T1650                             |   |                                        |
  +----------------------------------------+   +----------------------------------------+   +----------------------------------------+   +----------------------------------------+
                           │
                           ▼
  +----------------------------------------------+   +----------------------------------------------+
  | [T1114.002] Collection                       |   | [T1650] Lateral Movement                     |
  |   Email Collection: Email Forwarding Rule    |   |   Acquire Access                             |
  |                                              |   |   └▶ T1529                                   |
  +----------------------------------------------+   +----------------------------------------------+
                                                      │
                                                      ▼
  +----------------------------------------------------------------------------------------------------+
  | [T1529] Impact: System Shutdown/Reboot                                                             |
  |    Paths: scattered-spider-ransomware                                                              |
  |    └──▶ T1003.003                                                                                  |
  +----------------------------------------------------------------------------------------------------+
                                                      │
                                                      ▼
  +----------------------------------------------------------------------------------------------------+
  | [T1003.003] Credential Access: OS Credential Dumping: NTDS                                         |
  |    Paths: scattered-spider-ransomware                                                              |
  |    └──▶ T1486                                                                                      |
  +----------------------------------------------------------------------------------------------------+
                                                      │
                                                      ▼
  +----------------------------------------------------------------------------------------------------+
  | [T1486] Impact: Data Encrypted for Impact ■ EXIT                                                   |
  |    Paths: scattered-spider-ransomware                                                              |
  +----------------------------------------------------------------------------------------------------+

  ⚠ Unprotected stages: T1598.003, T1078, T1087.002, T1650, T1529, T1003.003, T1190, T1574.002, T1195.002, T1059.007, T1566.002, T1557, T1078

  ------------------------------------------------------------------------------------------------------
  Legend: ▷ Entry | ■ Exit | ◆ Converge | ◇ Branch
          ✓ control | ✗ gap
