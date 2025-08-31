# Detection of LummaC2 Command-and-Control Activity and Hostname Filtering Logic

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-LummaC2-C2-HostnameCheck
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects behaviors associated with the LummaC2 malware, focusing on its command-and-control (C2) callback routines and environmental filtering logic. LummaC2 is known for communicating with C2 domains via encrypted HTTP POST requests and performing host-based checks using Windows API calls such as `GetUserNameW` and `GetComputerNameW`. These checks are likely implemented to avoid execution on attacker-controlled or analysis systems. The query identifies processes that:

- Issue HTTP POST requests with JSON payloads
- Invoke host and user information APIs (`GetUserNameW`, `GetComputerNameW`)
- Match known LummaC2 binary naming patterns
- Initiate outbound network connections or DNS requests

Such behaviors are strong indicators of early-stage LummaC2 infection and C2 communication, supporting rapid detection and threat hunting.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                            |
|------------------------------|--------------|---------------|-----------------------------------------------------------|
| TA0006 - Credential Access    | T1012        | —             | Query Registry/System Information                         |
| TA0011 - Command and Control | T1071.001    | —             | Application Layer Protocol: Web Protocols (HTTP POST)     |
| TA0005 - Defense Evasion      | T1036        | —             | Masquerading                                             |
| TA0009 - Collection           | T1140        | —             | Deobfuscate/Decode Files or Information                   |

---

## Hunt Query Logic

This query identifies processes that exhibit multiple LummaC2 hallmarks:

- Command lines containing both `POST` and `application/json` (indicative of encrypted C2 traffic)
- Use of `GetUserNameW` or `GetComputerNameW` APIs (environmental checks)
- File names matching `LummaC2.exe` (case-insensitive)
- Outbound network activity (non-empty RemoteIP, DnsRequest, or DomainName fields)

These combined patterns are highly suggestive of LummaC2 C2 activity and filtering logic.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (CommandLine = "*POST*" AND CommandLine = "*application/json*")  
| (CommandLine = "*GetUserNameW*" OR CommandLine = "*GetComputerNameW*")  
| FileName = /LummaC2\.exe/i  
| (RemoteIP!="" OR DnsRequest!="" OR DomainName!="")  
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute binaries and initiate network connections.
- **Required Artifacts:** Process command lines, file names, network connection logs.

---

## Considerations

- Review the process tree to identify parent/child relationships and lateral movement.
- Correlate detected C2 domains or IPs with threat intelligence feeds.
- Validate if the process is accessing or exfiltrating sensitive data.
- Investigate the presence of known LummaC2 loader or dropper artifacts.

---

## False Positives

False positives may occur if:

- Legitimate applications use similar API calls and network patterns (rare, but possible in custom enterprise tools).
- Security testing or red team exercises simulate C2 behavior.
- Internal tools use POST requests with JSON payloads and system information gathering.

---

## Recommended Response Actions

1. Isolate the affected endpoint from the network.
2. Acquire memory and disk images for forensic analysis.
3. Investigate the process tree and network connections for further compromise.
4. Search for additional indicators of LummaC2 or related malware.
5. Block identified C2 domains and IPs at the network perimeter.

---

## References

- [MITRE ATT&CK: T1012 – Query Registry](https://attack.mitre.org/techniques/T1012/)
- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK: T1036 – Masquerading](https://attack.mitre.org/techniques/T1036/)
- [MITRE ATT&CK: T1140 – Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [Lumma Stealer: Breaking down the delivery techniques and capabilities of a prolific infostealer](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- [Threat Actors Deploy LummaC2 Malware to Exfiltrate Sensitive Data from Organizations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-04 | Initial Detection | Created hunt query to detect LummaC2 C2 activity and hostname filtering logic              |
