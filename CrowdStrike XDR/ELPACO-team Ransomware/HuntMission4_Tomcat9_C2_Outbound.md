# Correlate tomcat9.exe Child Process with Outbound Network Connection to Attacker IP

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Tomcat9C2Outbound
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects a sequence of behaviors indicative of command and control (C2) or payload download activity following exploitation of Atlassian Confluence servers. It identifies when a process spawned by `tomcat9.exe` (such as a loader, stager, or suspicious executable) makes an outbound network connection to a known attacker IP address (e.g., 45.227.254.124, 91.191.209.46). This pattern is strongly associated with C2 beaconing, payload retrieval, or further attacker interaction post-exploitation.

Detected behaviors include:

- `tomcat9.exe` spawning a suspicious process (e.g., `curl.exe`, `HAHLGiDDb.exe`, or executables with randomized names)
- The spawned process making an outbound network connection to a known attacker IP

Such activity is a strong indicator of successful exploitation and active attacker presence, often preceding further exploitation, lateral movement, or ransomware deployment.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059       | 003          | Command and Scripting Interpreter: Windows Command Shell |
| TA0011 - Command and Control | T1071       | 001          | Application Layer Protocol: Web Protocols      |
| TA0005 - Defense Evasion     | T1036       | 005          | Masquerading: Match Legitimate Name or Location |
| TA0001 - Initial Access      | T1190       | —            | Exploit Public-Facing Application             |

---

## Hunt Query Logic

This query identifies when a process spawned by `tomcat9.exe` (such as a loader or stager) makes an outbound network connection to a known attacker IP. This sequence is a strong indicator of C2 or payload download activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: process spawned by tomcat9.exe    
#event_simpleName=ProcessRollup2    
| ParentBaseFileName="tomcat9.exe"    
| (FileName="curl.exe" or FileName="HAHLGiDDb.exe" or FileName=/[A-Za-z0-9]{8,}\.exe/i)    
| join(    
  {    
    // Inner query: network connection by same process to attacker IP    
    #event_simpleName=NetworkConnectIP4    
    | RemoteAddress="45.227.254.124" or RemoteAddress="91.191.209.46"    
  }    
  , field=TargetProcessId // ProcessRollup2's TargetProcessId    
  , key=ContextProcessId  // NetworkConnectIP4's ContextProcessId    
  , include=[RemoteAddress, RemotePort]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([ParentBaseFileName, FileName, RemoteAddress, RemotePort])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2     | Process             | Process Creation       |
| Falcon       | N/A              | NetworkConnectIP4  | Network Connection  | Network Connection     |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code as the tomcat9 process and initiate outbound network connections.
- **Required Artifacts:** Process creation logs, network connection logs, attacker IP intelligence.

---

## Considerations

- Validate the context of the process and network connection to reduce false positives.
- Confirm that the outbound connection is not part of legitimate administrative or update activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or automated tools legitimately use `curl.exe` or similar utilities for updates or diagnostics.
- Internal scripts or monitoring tools connect to flagged IPs as part of normal operations.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the suspicious process and outbound connection.
3. Review all processes spawned by `tomcat9.exe` for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-23 | Initial Detection | Created hunt query to detect tomcat9.exe child process outbound C2 or payload download activity |
