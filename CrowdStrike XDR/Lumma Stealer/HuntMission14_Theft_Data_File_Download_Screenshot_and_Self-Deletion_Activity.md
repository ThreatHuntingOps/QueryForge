# Detection of LummaC2 Data Theft, File Download, Screenshot, and Self-Deletion Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-LummaC2-PostExploitation
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects post-exploitation behaviors associated with LummaC2, focusing on malicious actions executed via C2 instructions parsed from JSON configuration files. LummaC2 is capable of stealing browser and local files, downloading and executing remote payloads, capturing screenshots, and deleting itself to evade detection. The query identifies processes that:

- Access browser credential stores and local databases in AppData
- Download and execute DLLs via `rundll32.exe` or `LoadLibrary` APIs
- Capture screenshots and store them as BMP files in temporary directories
- Execute self-deletion routines using `cmd.exe` and `del` targeting `LummaC2.exe`

These behaviors are strong indicators of active LummaC2 post-exploitation and data theft operations.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                            |
|------------------------------|--------------|---------------|-----------------------------------------------------------|
| TA0009 - Collection           | T1217        | —             | Browser Information Discovery                             |
| TA0009 - Collection           | T1005        | —             | Data from Local System                                    |
| TA0010 - Exfiltration         | T1105        | —             | Ingress Tool Transfer                                     |
| TA0002 - Execution            | T1106        | —             | Native API                                                |
| TA0009 - Collection           | T1113        | —             | Screen Capture                                            |
| TA0006 - Defense Evasion      | T1070.004    | —             | Indicator Removal on Host: File Deletion                  |

---

## Hunt Query Logic

This query identifies processes that exhibit multiple LummaC2 post-exploitation hallmarks:

- Accessing browser and credential files in AppData (e.g., `Login Data`, `.sqlite`, `.ldb`, `.log`, `.db`)
- Executing DLLs via `rundll32.exe` or `LoadLibrary` APIs
- Creating or referencing BMP screenshot files in Temp directories or using `screenshot` keywords
- Self-deletion via `cmd.exe del LummaC2.exe`
- File names matching `LummaC2.exe` (case-insensitive)

These combined patterns are highly suggestive of LummaC2 post-exploitation and data theft activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (CommandLine = "*\\AppData\\*" AND (CommandLine = "*\\Login Data*" OR CommandLine = "*.sqlite*" OR CommandLine = "*.ldb*" OR CommandLine = "*.log*" OR CommandLine = "*.db*"))  
| (CommandLine = "*rundll32.exe*" AND CommandLine = "*.dll*")  
| (CommandLine = "*LoadLibraryW*" OR CommandLine = "*LoadLibrary*")  
| (CommandLine = "*\\AppData\\Local\\Temp\\*.bmp*" OR CommandLine = "*screenshot*")  
| (CommandLine = "*cmd.exe*" AND CommandLine = "*del*" AND CommandLine = "*LummaC2.exe*")  
| FileName = /LummaC2\.exe/i     
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute binaries, access AppData, and initiate network connections.
- **Required Artifacts:** Process command lines, file names, network connection logs, file system access logs.

---

## Considerations

- Review accessed files for evidence of credential or data theft.
- Investigate DLLs downloaded and executed via `rundll32.exe` or `LoadLibrary`.
- Check for screenshot artifacts in Temp directories.
- Correlate with other LummaC2 indicators for comprehensive incident response.

---

## False Positives

False positives may occur if:

- Legitimate applications access browser data or local databases in AppData.
- Security tools or IT scripts use `rundll32.exe` or `LoadLibrary` for benign purposes.
- Internal tools capture screenshots or perform self-deletion for update routines.

---

## Recommended Response Actions

1. Isolate the affected endpoint from the network.
2. Acquire memory and disk images for forensic analysis.
3. Investigate accessed files and executed DLLs for malicious content.
4. Search for additional indicators of LummaC2 or related malware.
5. Block identified C2 domains and IPs at the network perimeter.

---

## References

- [MITRE ATT&CK: T1217 – Browser Information Discovery](https://attack.mitre.org/techniques/T1217/)
- [MITRE ATT&CK: T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1106 – Native API](https://attack.mitre.org/techniques/T1106/)
- [MITRE ATT&CK: T1113 – Screen Capture](https://attack.mitre.org/techniques/T1113/)
- [MITRE ATT&CK: T1070.004 – Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004/)
- [Lumma Stealer: Breaking down the delivery techniques and capabilities of a prolific infostealer](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- [Threat Actors Deploy LummaC2 Malware to Exfiltrate Sensitive Data from Organizations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-04 | Initial Detection | Created hunt query to detect LummaC2 post-exploitation, data theft, and self-deletion      |
