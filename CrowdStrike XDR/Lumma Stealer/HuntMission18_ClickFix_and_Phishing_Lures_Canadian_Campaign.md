# Detection of Lumma Stealer and Xworm Execution via ClickFix and Phishing Lures (Canadian Campaign)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 91
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-LummaStealer-Xworm-ClickFix-CA
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects multi-stage execution chains associated with Lumma Stealer and Xworm delivery, as observed in Canadian-targeted phishing campaigns. The attack chain typically involves:

- Phishing emails with links leading through Prometheus TDS (Traffic Distribution System)
- ClickFix social engineering lures
- Execution of `mshta.exe` with JavaScript payloads referencing Prometheus or ClickFix infrastructure (e.g., `binadata.com`, `185.147.125.*`)
- Child process creation of `powershell.exe` (indicative of loader or payload execution)
- Parent process of `explorer.exe` or `outlook.exe` (user-initiated or email-driven)
- Social engineering keywords such as `I’m not a robot`, `ClickFix`, or `Prometheus`

These behaviors are strong indicators of layered malware delivery using both commercial and underground tools.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                            |
|------------------------------|--------------|---------------|-----------------------------------------------------------|
| TA0001 - Initial Access       | T1566.001    | —             | Phishing: Spearphishing Attachment                        |
| TA0001 - Initial Access       | T1566.002    | —             | Phishing: Drive-by Compromise                             |
| TA0002 - Execution            | T1059.001    | —             | Command and Scripting Interpreter: PowerShell             |
| TA0002 - Execution            | T1059.005    | —             | Command and Scripting Interpreter: Visual Basic (mshta)   |
| TA0002 - Execution            | T1204.002    | —             | User Execution: Malicious File                            |
| TA0010 - Exfiltration         | T1105        | —             | Ingress Tool Transfer                                     |
| TA0005 - Defense Evasion      | T1027.004    | —             | Obfuscated Files or Information: Base64/encoded JS        |
| TA0007 - Discovery            | T1082        | —             | System Information Discovery                              |

---

## Hunt Query Logic

This query identifies processes that exhibit multiple hallmarks of the Prometheus TDS, ClickFix, and Lumma Stealer/Xworm infection chain:

- `mshta.exe` execution with command lines referencing Prometheus or ClickFix infrastructure (`binadata.com`, `185.147.125.*`)
- JavaScript or obfuscation keywords in command line (`javascript`, `window.location`)
- Child process creation of `powershell.exe`
- Social engineering lure keywords present (`I’m not a robot`, `ClickFix`, `Prometheus`)
- Parent process is `explorer.exe` or `outlook.exe` (user or email-driven)

These combined patterns are highly suggestive of a multi-stage loader chain delivering Lumma Stealer and Xworm.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| FileName = "mshta.exe"  
| CommandLine = "*binadata.com*" OR CommandLine = "*185.147.125.*"  
| CommandLine = "*javascript*" OR CommandLine = "*window.location*"  
| ChildProcName = "powershell.exe" | (CommandLine = "*I’m not a robot*" OR CommandLine = "*ClickFix*" OR CommandLine = "*Prometheus*")  
| ParentBaseFileName = "explorer.exe" OR ParentBaseFileName = "outlook.exe"   
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute LOLBins and scripts, and interact with email clients or browsers.
- **Required Artifacts:** Process command lines, parent/child process metadata, network connection logs.

---

## Considerations

- Review email delivery vectors and phishing lures for evidence of Prometheus TDS and ClickFix usage.
- Investigate referenced infrastructure and payloads for malicious content.
- Correlate with other Lumma Stealer and Xworm indicators for comprehensive incident response.

---

## False Positives

False positives may occur if:

- Power users or IT staff use `mshta.exe` and PowerShell for legitimate automation.
- Internal tools leverage JavaScript or similar infrastructure for benign purposes.

---

## Recommended Response Actions

1. Isolate the affected endpoint from the network.
2. Acquire memory and disk images for forensic analysis.
3. Investigate email and web delivery vectors for evidence of compromise.
4. Search for additional indicators of Lumma Stealer, Xworm, or related malware.
5. Block identified malicious domains and IPs at the network perimeter.

---

## References

- [MITRE ATT&CK: T1566.001 – Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK: T1566.002 – Phishing: Drive-by Compromise](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1059.005 – Visual Basic (mshta)](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1027.004 – Obfuscated Files or Information: Base64](https://attack.mitre.org/techniques/T1027/004/)
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [Lumma Stealer: Breaking down the delivery techniques and capabilities of a prolific infostealer](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- [Threat Actors Deploy LummaC2 Malware to Exfiltrate Sensitive Data from Organizations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-04 | Initial Detection | Created hunt query to detect Prometheus TDS, ClickFix, and Lumma Stealer/Xworm infection chain |
