# Detection of Suspicious Network Connections Indicative of Data Exfiltration (DarkCloud Stealer)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-DarkCloud-Exfil-Network
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious outbound network connections from processes that access sensitive user data, indicative of potential data exfiltration activities associated with DarkCloud Stealer. The query focuses on outbound connections to common ports used for data exfiltration (HTTP, HTTPS, FTP, SSH) and correlates these with file access events involving credential stores and other sensitive files.

Detected behaviors include:

- Outbound network connections on ports 80, 443, 21, 22, 8080, and 8443
- Correlation of these connections with processes accessing files such as browser credential databases, email client files, and FTP client files

Such techniques are often associated with infostealer malware and data exfiltration campaigns.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                             |
|------------------------------|--------------|--------------|-----------------------------------------------------------|
| TA0010 - Exfiltration        | T1041        | —            | Exfiltration Over C2 Channel                              |
| TA0011 - Command and Control | T1071        | —            | Application Layer Protocol                                |

---

## Hunt Query Logic

This query identifies:

- **Network Connections:** Outbound network connections on common ports used for data exfiltration (HTTP, HTTPS, FTP, SSH).
- **Sensitive Data Access:** Correlates these network connections with processes accessing sensitive credential and data files.
- **Joins:** Matches network connection events with file access events by agent ID (aid) and process ID (TargetProcessId).

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Detect suspicious outbound network connections from processes accessing sensitive data

#event_simpleName="NetworkConnectIP4" 
| RemotePort=80 OR RemotePort=443 OR RemotePort=21 OR RemotePort=22 OR RemotePort=8080 OR RemotePort=8443 
| join( 
    {#event_simpleName="FileOpen" OR #event_simpleName="FileWritten" 
     | TargetFileName=/Login Data|Cookies|Web Data|places\.sqlite|key4\.db|logins\.json|recentServers\.xml|\.xml$|\.db$|\.sqlite$/i 
     | FilePath=/C:\\Users\\.*|CSIDL_PROFILE\\.*|AppData\\.*|Local\\.*|Roaming\\.*/
    } 
    , field=TargetProcessId 
    , key=TargetProcessId 
    , include=[TargetFileName, FilePath] 
) 
| groupBy([aid, ComputerName], limit=max, function=collect([RemotePort, TargetFileName, FilePath])) 
```

---

## Data Sources

| Log Provider | Event ID         | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------|---------------------|------------------------|
| Falcon       | N/A              | NetworkConnectIP4| Network             | Network Connection     |
| Falcon       | N/A              | FileOpen         | File                | File Access            |
| Falcon       | N/A              | FileWritten      | File                | File Creation          |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to access sensitive files and establish outbound network connections.
- **Required Artifacts:** Network connection logs, file access logs.

---

## Considerations

- Investigate the source and legitimacy of processes establishing outbound connections after accessing sensitive files.
- Analyze network destinations and data volumes for evidence of exfiltration.
- Correlate activity with known DarkCloud Stealer indicators or threat intelligence.

---

## False Positives

False positives may occur if:

- Legitimate applications access sensitive files and establish outbound connections for benign purposes.
- Internal tools or automation interact with credential stores and remote services.

---

## Recommended Response Actions

1. Investigate the processes establishing outbound connections and their origin.
2. Analyze accessed files and network destinations for malicious behavior.
3. Review data transfer volumes and patterns for signs of exfiltration.
4. Monitor for additional signs of compromise or lateral movement.
5. Isolate affected systems if malicious activity is confirmed.

---

## References

- [Unit 42: DarkCloud Stealer and Obfuscated AutoIt Scripting](https://unit42.paloaltonetworks.com/darkcloud-stealer-and-obfuscated-autoit-scripting/)
- [MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK: T1071 – Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-20 | Initial Detection | Created hunt query to detect suspicious network connections indicative of data exfiltration |
