# Detection of Lumma Stealer Delivery Techniques and Initial Execution Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 88
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-LummaStealer-Delivery-InitialExec
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects initial access and execution patterns associated with Lumma Stealer delivery campaigns. These campaigns leverage phishing emails, drive-by downloads, cracked or trojanized software, and fileless execution techniques. The query identifies processes that:

- Execute Base64-encoded PowerShell payloads (indicative of obfuscated script delivery)
- Use `cmd.exe` to run `curl`, `Invoke-WebRequest`, or `Invoke-Expression` (common for downloading and executing remote payloads)
- Reference suspicious installer or update binaries (e.g., `chrome_update.exe`, `notepad++*.exe`, `setup.exe`, `installer`)
- Launch from user Downloads folder into Temp directories (common for initial payload staging)
- Reference known abused infrastructure (GitHub, Discord CDN, Pastebin)
- Contain suspicious keywords like `Run`, `ClickFix`, or `CAPTCHA` (often used in social engineering lures)

These behaviors are strong indicators of early-stage Lumma Stealer delivery and execution.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                            |
|------------------------------|--------------|---------------|-----------------------------------------------------------|
| TA0001 - Initial Access       | T1566.001    | —             | Phishing: Spearphishing Attachment                        |
| TA0001 - Initial Access       | T1566.002    | —             | Phishing: Spearphishing Link                              |
| TA0001 - Initial Access       | T1189        | —             | Drive-by Compromise                                       |
| TA0002 - Execution            | T1059.001    | —             | Command and Scripting Interpreter: PowerShell             |
| TA0005 - Defense Evasion      | T1027.004    | —             | Obfuscated Files or Information: Base64                   |
| TA0010 - Exfiltration         | T1105        | —             | Ingress Tool Transfer                                     |
| TA0002 - Execution            | T1204.002    | —             | User Execution: Malicious File                            |
| TA0011 - Command and Control  | T1071.001    | —             | Application Layer Protocol: Web Protocols                 |

---

## Hunt Query Logic

This query identifies processes that exhibit multiple Lumma Stealer delivery hallmarks:

- PowerShell with Base64-encoded payloads
- `cmd.exe` with download/execution commands
- Suspicious installer or update binaries
- Downloads folder to Temp directory execution
- Use of known abused web infrastructure
- Social engineering lure keywords

These combined patterns are highly suggestive of Lumma Stealer initial access and execution activity.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (FileName = "powershell.exe" AND CommandLine = "*-enc*" AND CommandLine = "*FromBase64String*")  
| (FileName = "cmd.exe" AND CommandLine = "*curl*" OR CommandLine = "*Invoke-WebRequest*" OR CommandLine = "*Invoke-Expression*")  
| (CommandLine = "*Run*" AND CommandLine = "*ClickFix*" OR CommandLine = "*CAPTCHA*")  
| (CommandLine = "*chrome_update.exe*" OR CommandLine = "*notepad++*.exe*" OR CommandLine = "*setup.exe*" OR CommandLine = "*installer*")  
| (FilePath = "C:\\Users\\*\\Downloads\\*" AND CommandLine = "*AppData\\Local\\Temp*")  
| (CommandLine = "*GitHub*" OR CommandLine = "*cdn.discordapp.com*" OR CommandLine = "*pastebin.com*" OR CommandLine = "*raw.githubusercontent.com*")   
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute scripts, download files, and run installers.
- **Required Artifacts:** Process command lines, file paths, network connection logs.

---

## Considerations

- Review the source of downloaded files and their hashes.
- Investigate the parent process and email or web delivery vectors.
- Correlate with other Lumma Stealer indicators for comprehensive incident response.
- Monitor for repeated abuse of known infrastructure (GitHub, Discord, Pastebin).

---

## False Positives

False positives may occur if:

- IT or security staff use PowerShell or cmd for legitimate automation.
- Users install legitimate software from Downloads folder.
- Internal tools leverage public infrastructure for updates or scripts.

---

## Recommended Response Actions

1. Isolate the affected endpoint from the network.
2. Acquire memory and disk images for forensic analysis.
3. Investigate downloaded files and their sources for malicious content.
4. Search for additional indicators of Lumma Stealer or related malware.
5. Block identified malicious domains and IPs at the network perimeter.

---

## References

- [MITRE ATT&CK: T1566.001 – Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK: T1566.002 – Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK: T1189 – Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1027.004 – Obfuscated Files or Information: Base64](https://attack.mitre.org/techniques/T1027/004/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [Lumma Stealer: Breaking down the delivery techniques and capabilities of a prolific infostealer](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- [Threat Actors Deploy LummaC2 Malware to Exfiltrate Sensitive Data from Organizations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-04 | Initial Detection | Created hunt query to detect Lumma Stealer delivery and initial execution activity          |
