# Correlate Meterpreter Payload Download with C2 Connection to Metasploit Server

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-MeterpreterC2
- **Operating Systems:** WindowsServer, WindowsEndpoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with Meterpreter payload delivery and C2 communication. It identifies when a Meterpreter payload is downloaded from a known Metasploit server (`91.191.209.46`), then establishes a C2 connection to the same IP and port (`12385`).

Detected behaviors include:

- File creation of a Meterpreter payload (`*.exe`) in the NetworkService Temp directory
- Subsequent network connection to the Metasploit C2 server (`91.191.209.46:12385`)
- Correlation of these events by process context, indicating successful payload delivery and C2 establishment

Such activity is a strong indicator of ingress tool transfer, remote access software deployment, and C2 communication by an attacker.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0009 - Collection          | T1105       | —            | Ingress Tool Transfer                         |
| TA0011 - Command and Control | T1071       | —            | Application Layer Protocol                    |
| TA0011 - Command and Control | T1219       | —            | Remote Access Software                        |

---

## Hunt Query Logic

This query identifies when a Meterpreter payload is downloaded from a known Metasploit server and then establishes a C2 connection to the same IP and port, a strong indicator of successful exploitation and C2 setup.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: file creation of Meterpreter payload from Metasploit server    
#event_simpleName=FileCreate    
| FileName=/.*\.exe/i    
| FilePath=/C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\.*/    
| join(    
  {    
    // Inner query: network connection to Metasploit C2 server    
    #event_simpleName=NetworkConnectIP4    
    | RemoteAddress="91.191.209.46"    
    | RemotePort=12385    
  }    
  , field=TargetProcessId    
  , key=ContextProcessId    
  , include=[RemoteAddress, RemotePort]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([FileName, FilePath, RemoteAddress, RemotePort]))   
```

---

## Data Sources

| Log Provider | Event ID         | Event Name             | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|------------------------|---------------------|------------------------|
| Falcon       | N/A              | FileCreate             | File                | File Creation          |
| Falcon       | N/A              | NetworkConnectIP4      | Network             | Network Connection     |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to download and execute files, and establish outbound network connections.
- **Required Artifacts:** File creation logs, network connection logs, process context correlation.

---

## Considerations

- Validate the context of the payload download and C2 connection to reduce false positives.
- Confirm that the activity is not part of legitimate security testing or troubleshooting activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- Security teams or administrators are conducting legitimate penetration testing or red teaming.
- Internal scripts or monitoring tools use similar patterns for automation or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected endpoint or server from the network if unauthorized payload download or C2 connection is detected.
2. Investigate the source and intent of the payload download and C2 connection.
3. Review all processes associated with the payload and network activity for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable systems and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1071 – Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [MITRE ATT&CK: T1219 – Remote Access Software](https://attack.mitre.org/techniques/T1219/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-28 | Initial Detection | Created hunt query to detect Meterpreter payload download and C2 connection |
