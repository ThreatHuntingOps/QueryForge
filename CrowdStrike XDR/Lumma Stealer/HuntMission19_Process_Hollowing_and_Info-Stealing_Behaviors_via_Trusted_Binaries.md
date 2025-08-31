# Detection of Lumma Stealer Process Hollowing and Info-Stealing Behaviors via Trusted Binaries

## Severity or Impact of the Detected Behavior
- **Risk Score:** 94
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-LummaStealer-ProcessHollowing-InfoSteal
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious process hollowing or injection activity and attempts to identify credential and wallet data exfiltration by Lumma Stealer. It also considers process behavior consistent with retrieving and parsing C2 configuration files, such as targeting `*.ovpn`, `wallet.dat`, browser cookies, and other sensitive artifacts. The query identifies processes that:

- Are spawned from trusted but often abused binaries (`msbuild.exe`, `regasm.exe`, `regsvcs.exe`, `explorer.exe`)
- Operate from suspicious directories (`AppData`, `Temp`, `Roaming`, `ProgramData`)
- Reference credential, wallet, or sensitive data artifacts in their command line (e.g., `wallet`, `exodus`, `cookies`, `*.ovpn*`, `MetaMask`, `Telegram`, `*.docx*`, `*.pdf*`)
- Exhibit process injection or hollowing behaviors (`inject`, `hollow`, `memcpy`, `VirtualAlloc`, `WriteProcessMemory`)

These behaviors are highly indicative of Lumma Stealer post-execution info-stealing and process injection activity.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                            |
|------------------------------|--------------|---------------|-----------------------------------------------------------|
| TA0004 - Privilege Escalation | T1055.012    | —             | Process Injection: Process Hollowing                      |
| TA0004 - Privilege Escalation | T1055        | —             | Process Injection (general)                               |
| TA0006 - Credential Access    | T1056.001    | —             | Input Capture                                             |
| TA0009 - Collection           | T1114.002    | —             | Email Collection: Remote Email Collection                 |
| TA0006 - Credential Access    | T1555.003    | —             | Credentials from Web Browsers                             |
| TA0007 - Discovery            | T1083        | —             | File and Directory Discovery                              |
| TA0007 - Discovery            | T1082        | —             | System Information Discovery                              |
| TA0009 - Collection           | T1213.002    | —             | Data from Information Repositories: Credential Stores      |

---

## Hunt Query Logic

This query identifies processes that exhibit multiple Lumma Stealer post-execution hallmarks:

- Spawned from trusted but abused binaries
- Operate from suspicious directories
- Reference credential, wallet, or sensitive data artifacts
- Exhibit process injection or hollowing behaviors

These combined patterns are highly suggestive of Lumma Stealer process hollowing and info-stealing activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (ParentBaseFileName = "msbuild.exe" OR ParentBaseFileName = "regasm.exe" OR ParentBaseFileName = "regsvcs.exe" OR ParentBaseFileName = "explorer.exe")  
| in(field="ImageFileName", values=["*\AppData\*", "*\Temp\*", "*\Roaming\*", "*\ProgramData\*"]) 
| in(field="CommandLine", values=["*wallet*", "*exodus*", "*cookies*", "*.ovpn*", "*MetaMask*", "*Telegram*", "*.docx*", "*.pdf*"]) 
| (CommandLine="*inject*" OR CommandLine="*hollow*" OR CommandLine="*memcpy*" OR CommandLine="*VirtualAlloc*" OR CommandLine="*WriteProcessMemory*")   
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute trusted binaries and perform process injection or memory manipulation.
- **Required Artifacts:** Process command lines, parent/child process metadata, file system access logs.

---

## Considerations

- Review process ancestry for evidence of process hollowing or injection.
- Investigate referenced files and directories for evidence of credential or wallet data theft.
- Correlate with other Lumma Stealer indicators for comprehensive incident response.

---

## False Positives

False positives may occur if:

- IT or security staff use trusted binaries for legitimate automation or troubleshooting.
- Internal tools perform memory manipulation for benign purposes.

---

## Recommended Response Actions

1. Isolate the affected endpoint from the network.
2. Acquire memory and disk images for forensic analysis.
3. Investigate process ancestry and referenced files for evidence of compromise.
4. Search for additional indicators of Lumma Stealer or related malware.
5. Block identified malicious domains and IPs at the network perimeter.

---

## Notes for Analysts

- `msbuild.exe`, `regsvcs.exe`, etc., are abused via process hollowing to hide the real payload.
- Lumma dynamically queries system details and executes collection routines based on config sections (e.g., extensions/wallets, browsers, user files).
- Stealer families often target specific data artifacts in AppData, Roaming, and Temp paths.

---

## References

- [MITRE ATT&CK: T1055.012 – Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1056.001 – Input Capture](https://attack.mitre.org/techniques/T1056/001/)
- [MITRE ATT&CK: T1114.002 – Email Collection: Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/)
- [MITRE ATT&CK: T1555.003 – Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK: T1083 – File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE ATT&CK: T1213.002 – Data from Information Repositories: Credential Stores](https://attack.mitre.org/techniques/T1213/002/)
- [Lumma Stealer: Breaking down the delivery techniques and capabilities of a prolific infostealer](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- [Threat Actors Deploy LummaC2 Malware to Exfiltrate Sensitive Data from Organizations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-04 | Initial Detection | Created hunt query to detect Lumma Stealer process hollowing and info-stealing behaviors    |
