# Correlate Metasploit Loader Process with Network Download of PE File

## Severity or Impact of the Detected Behavior
- **Risk Score:** 93
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-MetasploitLoaderPE
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects a high-confidence sequence of behaviors associated with Metasploit post-exploitation activity. It identifies when a process (likely a Metasploit loader) connects to a known attacker IP (`91.191.209.46`) on a non-standard port (`12385`) to download a PE file, and then drops a DLL in the NetworkService temporary directory. This pattern is strongly associated with the delivery and staging of malicious payloads, such as reflective DLLs, following successful exploitation.

Detected behaviors include:

- Outbound network connection to attacker IP on a non-standard port (12385)
- Creation of a DLL file in `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Temp\`
- Correlation of these events by process context, indicating automated loader and payload staging

Such activity is a strong indicator of Metasploit post-exploitation, tool transfer, and payload staging.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |
| TA0011 - Command and Control | T1071       | —            | Application Layer Protocol                    |

---

## Hunt Query Logic

This query identifies when a process connects to an attacker IP on a non-standard port to download a PE file, and then creates a DLL in the temp directory. This sequence is a strong indicator of Metasploit loader and payload staging activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
// Outer query: network connection to attacker IP/port    
#event_simpleName=NetworkConnectIP4    
| RemoteAddress="91.191.209.46"    
| RemotePort=12385    
| join(    
  {    
    // Inner query: DLL file creation by same process    
    #event_simpleName=FileCreate    
    | FilePath=/C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp\\.*\.dll/i    
  }    
  , field=TargetProcessId // NetworkConnectIP4's TargetProcessId    
  , key=ContextProcessId  // FileCreate's ContextProcessId    
  , include=[FilePath, FileName]    
)    
| groupBy([aid, ComputerName], limit=max, function=collect([RemoteAddress, RemotePort, FilePath, FileName]))   
```

---

## Data Sources

| Log Provider | Event ID         | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|--------------------|---------------------|------------------------|
| Falcon       | N/A              | NetworkConnectIP4  | Network Connection  | Network Connection     |
| Falcon       | N/A              | FileCreate         | File                | File Creation          |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to execute code and initiate outbound network connections as the NetworkService user.
- **Required Artifacts:** Network connection logs, file creation logs, process context correlation.

---

## Considerations

- Validate the context of the network connection and DLL creation to reduce false positives.
- Confirm that the DLL creation in the temp directory is not part of legitimate administrative or update activity.
- Review additional process and network activity for signs of further exploitation or lateral movement.

---

## False Positives

False positives may occur if:

- System administrators or automated tools legitimately download and create DLLs in the temp directory.
- Internal scripts or monitoring tools use similar patterns for updates or diagnostics.

---

## Recommended Response Actions

1. Isolate the affected server from the network.
2. Investigate the source and intent of the suspicious network connection and DLL creation.
3. Review all processes associated with the network connection and DLL for further malicious activity.
4. Hunt for additional indicators of compromise across the environment.
5. Patch vulnerable Confluence instances and review endpoint security controls.

---

## References

- [DFIR Report: Another Confluence Bites the Dust – Falling to Elpaco Team Ransomware](https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/#case-summary)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1071 – Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-05-23 | Initial Detection | Created hunt query to detect Metasploit loader network download and DLL drop |
