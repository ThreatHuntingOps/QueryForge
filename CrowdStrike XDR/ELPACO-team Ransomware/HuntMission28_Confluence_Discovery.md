# Correlate Confluence Exploit with Discovery Command Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-ConfluenceDiscovery
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with post-exploitation reconnaissance following a Confluence exploit. It identifies when a network connection from a suspicious IP (e.g., `109.160.16.68`, `185.228.19.244`, `185.220.101.185`) is closely followed by the execution of discovery commands (`whoami`, `dir`, `net.exe`) from a Tomcat process, indicating attacker reconnaissance and environment mapping.

Detected behaviors include:

- Network connection from a known suspicious IP
- Tomcat process spawning discovery commands (`whoami.exe`, `cmd.exe`, `net.exe`)
- Command lines containing reconnaissance keywords (e.g., `whoami`, `dir`, `net localgroup administrators`)
- Correlation of these events by process context, indicating post-exploitation activity

Such activity is a strong indicator of successful exploitation and attacker reconnaissance.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0007 - Discovery           | T1087       | —            | Account Discovery                             |
| TA0007 - Discovery           | T1082       | —            | System Information Discovery                  |
| TA0007 - Discovery           | T1033       | —            | System Owner/User Discovery                   |
| TA0007 - Discovery           | T1049       | —            | System Network Connections Discovery          |

---

## Hunt Query Logic

This query identifies when a network connection from a suspicious IP is closely followed by the execution of discovery commands from a Tomcat process, a strong indicator of post-exploitation reconnaissance.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: network connection from suspicious IP    
#event_simpleName=NetworkConnectIP4    
| RemoteAddress="109.160.16.68" or RemoteAddress="185.228.19.244" or RemoteAddress="185.220.101.185"    
| join(    
  {    
    // Inner query: discovery commands spawned by tomcat9.exe    
    #event_simpleName=ProcessRollup2    
    | ParentBaseFileName="tomcat9.exe"    
    | (FileName="whoami.exe" or FileName="cmd.exe" or FileName="net.exe")    
    | (CommandLine=/whoami|whaomi|dir|net localgroup administrators/i)    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[FileName, CommandLine, ParentBaseFileName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([RemoteAddress, FileName, CommandLine, ParentBaseFileName]))   
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | NetworkConnectIP4      | Network             | Network Connection     |
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to exploit Confluence and execute commands via Tomcat.
- **Required Artifacts:** Network connection logs, process creation logs, process context correlation.

---

## Considerations

- Validate the context of the network connection and command execution to reduce false positives.
- Confirm that the activity is not part of legitimate administrative or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate testing from the listed IPs.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network if unauthorized access is detected.
2. Investigate the source and intent of the network connection and command execution.
3. Review all processes associated with Tomcat and the suspicious IPs for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1087 – Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE ATT&CK: T1033 – System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
- [MITRE ATT&CK: T1049 – System Network Connections Discovery](https://attack.mitre.org/techniques/T1049/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-27 | Initial Detection | Created hunt query to detect Confluence exploit and discovery command execution |
