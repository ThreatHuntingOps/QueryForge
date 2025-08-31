# Detection of Fileless LummaC2 Execution and Host Enumeration Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 92
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-LummaC2-Fileless-HostRecon
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects fileless, in-memory execution of LummaC2 malware, focusing on stealthy system reconnaissance and host enumeration. Fileless LummaC2 variants avoid dropping executables to disk, instead running entirely in memory. The query identifies processes that:

- Match known LummaC2 process names but lack a corresponding file on disk
- Invoke system and user information APIs (`GetUserNameW`, `GetComputerNameW`, `whoami`, `systeminfo`)
- Have zero file modifications (`FileModCount = 0`), no SHA256 hash, and no loaded image path (indicative of memory-resident execution)
- Initiate outbound network connections (non-empty RemoteIP or DomainName)

These behaviors are highly indicative of stealthy, fileless LummaC2 infections performing host reconnaissance prior to C2 exfiltration.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                            |
|------------------------------|--------------|---------------|-----------------------------------------------------------|
| TA0007 - Discovery            | T1082        | —             | System Information Discovery                              |
| TA0007 - Discovery            | T1057        | —             | Process Discovery                                         |
| TA0007 - Discovery            | T1012        | —             | Query Registry/System Information                         |
| TA0005 - Defense Evasion      | T1055        | —             | Process Injection                                         |
| TA0005 - Defense Evasion      | T1027        | —             | Obfuscated Files or Information                           |

---

## Hunt Query Logic

This query identifies processes that exhibit multiple fileless LummaC2 hallmarks:

- Process name matches `LummaC2.exe` (case-insensitive)
- Command lines include system/user enumeration (`GetUserNameW`, `GetComputerNameW`, `whoami`, `systeminfo`)
- No file modifications, no SHA256, and no image loaded (memory-resident)
- Outbound network activity (RemoteIP or DomainName present)

These combined patterns are highly suggestive of fileless LummaC2 execution and host reconnaissance.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| FileName = /LummaC2\.exe/i  
| (CommandLine = "*GetUserNameW*" OR CommandLine = "*GetComputerNameW*" OR CommandLine = "*whoami*" OR CommandLine = "*systeminfo*")  
| FileModCount = 0 | (ProcessStartTime != "" AND SHA256="" AND ImageLoaded="")  
| (RemoteIP!="" OR DomainName!="")   
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute code in memory and initiate network connections.
- **Required Artifacts:** Process command lines, process metadata, network connection logs.

---

## Considerations

- Review process ancestry and memory artifacts for evidence of injection or in-memory execution.
- Correlate with other LummaC2 indicators for comprehensive incident response.
- Investigate network connections for C2 activity and data exfiltration.

---

## False Positives

False positives may occur if:

- Legitimate tools or scripts perform in-memory execution and system enumeration (rare in enterprise environments).
- Security testing or red team exercises simulate fileless malware behavior.

---

## Recommended Response Actions

1. Isolate the affected endpoint from the network.
2. Acquire memory images for forensic analysis of in-memory artifacts.
3. Investigate process ancestry and network connections for further compromise.
4. Search for additional indicators of LummaC2 or related fileless malware.
5. Block identified C2 domains and IPs at the network perimeter.

---

## References

- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE ATT&CK: T1057 – Process Discovery](https://attack.mitre.org/techniques/T1057/)
- [MITRE ATT&CK: T1012 – Query Registry](https://attack.mitre.org/techniques/T1012/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Lumma Stealer: Breaking down the delivery techniques and capabilities of a prolific infostealer](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- [Threat Actors Deploy LummaC2 Malware to Exfiltrate Sensitive Data from Organizations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-04 | Initial Detection | Created hunt query to detect fileless LummaC2 execution and host enumeration               |
