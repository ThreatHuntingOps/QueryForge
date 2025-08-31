# Correlate AnyDesk Certificate Exchange with Direct Connection to Threat Actor

## Severity or Impact of the Detected Behavior
- **Risk Score:** 99
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AnyDeskCertDirectC2
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low (if certificate fields are present)

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with direct C2 activity using AnyDesk, leveraging certificate exchange details. It identifies certificate exchange events (if available in logs) between AnyDesk and the threat actor’s server (`45.227.254.124`), correlated with direct network connections on port 443 or 3389 and matching certificate details (`CertificateSerialNumber="104770999709883145161872575332968665437"`, `CertificateCommonName="D-422"`).

Detected behaviors include:

- Execution of `AnyDesk.exe`
- Network connection to the threat actor’s AnyDesk server (`45.227.254.124`) on port 443 or 3389
- Certificate exchange with specific serial number and common name
- Correlation of these events by process context, indicating direct C2 activity with certificate validation

Such activity is a strong indicator of remote access software use, C2 communication, and proxying by an attacker, with additional confidence from certificate matching.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0011 - Command and Control | T1219       | —            | Remote Access Software                        |
| TA0011 - Command and Control | T1071       | —            | Application Layer Protocol                    |
| TA0011 - Command and Control | T1090       | —            | Proxy                                         |

---

## Hunt Query Logic

This query identifies when AnyDesk is executed and establishes a direct network connection to a threat actor’s server, with certificate exchange details, a strong indicator of direct C2 activity with certificate validation.

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
    // Inner query: network connection to threat actor’s AnyDesk server with certificate details    
    #event_simpleName=NetworkConnectIP4    
    | RemoteAddress="45.227.254.124"    
    | (RemotePort=443 or RemotePort=3389)    
    | CertificateSerialNumber="104770999709883145161872575332968665437"    
    | CertificateCommonName="D-422"    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[RemoteAddress, RemotePort, CertificateSerialNumber, CertificateCommonName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, RemoteAddress, RemotePort, CertificateSerialNumber, CertificateCommonName]))  
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
- **Required Artifacts:** Process creation logs, network connection logs with certificate fields, process context correlation.

---

## Considerations

- Only use this query if certificate fields are available in your Falcon data model.
- Validate the context of the AnyDesk execution and C2 connection to reduce false positives.
- Confirm that the activity is not part of legitimate remote support or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate remote support or troubleshooting with matching certificate details.
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
| 1.0     | 2025-05-28 | Initial Detection | Created hunt query to detect AnyDesk certificate exchange with direct connection |
