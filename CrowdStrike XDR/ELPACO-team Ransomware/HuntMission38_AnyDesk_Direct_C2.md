# Correlate AnyDesk Direct Connection to Threat Actor’s On-Prem Server

## Severity or Impact of the Detected Behavior
- **Risk Score:** 97
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnyDeskDirectC2
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with direct C2 activity using AnyDesk. It identifies AnyDesk network connections from the victim to the threat actor’s self-hosted AnyDesk server (`45.227.254.124`) on port 443 or 3389, indicating direct remote access and C2 communication.

Detected behaviors include:

- Execution of `AnyDesk.exe`
- Network connection to the threat actor’s AnyDesk server (`45.227.254.124`) on port 443 or 3389
- Correlation of these events by process context, indicating direct C2 activity

Such activity is a strong indicator of remote access software use, C2 communication, and proxying by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0011 - Command and Control | T1219       | —            | Remote Access Software                        |
| TA0011 - Command and Control | T1071       | —            | Application Layer Protocol                    |
| TA0011 - Command and Control | T1090       | —            | Proxy                                         |

---

## Hunt Query Logic

This query identifies when AnyDesk is executed and establishes a direct network connection to a threat actor’s self-hosted server, a strong indicator of direct C2 activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: AnyDesk process execution    
#event_simpleName=ProcessRollup2    
| FileName="AnyDesk.exe"    
| join(    
  {    
    // Inner query: network connection to threat actor’s AnyDesk server    
    #event_simpleName=NetworkConnectIP4    
    | RemoteAddress="45.227.254.124"    
    | (RemotePort=443 or RemotePort=3389)    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[RemoteAddress, RemotePort]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, RemoteAddress, RemotePort]))  
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | ProcessRollup2         | Process             | Process Creation       |
| Falcon       | N/A              | NetworkConnectIP4      | Network             | Network Connection     |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute AnyDesk and establish outbound network connections.
- **Required Artifacts:** Process creation logs, network connection logs, process context correlation.

---

## Considerations

- Validate the context of the AnyDesk execution and C2 connection to reduce false positives.
- Confirm that the activity is not part of legitimate remote support or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate remote support or troubleshooting.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized remote access or C2 connection is detected.
2. Investigate the source and intent of the AnyDesk execution and network connection.
3. Review all processes associated with the tool and network activity for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK: T1071 – Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [MITRE ATT&CK: T1090 – Proxy](https://attack.mitre.org/techniques/T1090/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-28 | Initial Detection | Created hunt query to detect AnyDesk direct connection to threat actor’s server |
