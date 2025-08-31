# Detection of EtherHiding and ClickFix Techniques Leading to Lumma Stealer Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 93
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-LummaStealer-EtherHiding-ClickFix
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the EtherHiding and ClickFix infection chain used by Lumma Stealer affiliates. In this technique, JavaScript from compromised websites leverages blockchain-based command hosting (EtherHiding) and ClickFix lures to trick users into pasting malicious Base64-encoded commands into the Windows Run dialog. These commands are executed via `mshta.exe` or similar living-off-the-land binaries (LOLBins), often bypassing conventional endpoint protections. The query identifies processes that:

- Launch `mshta.exe` with command lines referencing EtherHiding infrastructure (e.g., `check.foquh.icu`, `data-seed-prebsc-1-s1.bnbchain.org`, or `clipboard`)
- Contain JavaScript or obfuscation keywords (`javascript`, `fromCharCode`, `Base64`, `window.location`)
- Originate from parent processes like `explorer.exe` or `userinit.exe` (indicative of user-initiated Run dialog execution)
- Reference social engineering lures such as `I'm not a robot` or `ClickFix`

These behaviors are highly indicative of EtherHiding-based Lumma Stealer delivery and execution.

---

## ATT&CK Mapping

| Tactic                        | Technique    | Subtechnique | Technique Name                                            |
|------------------------------|--------------|---------------|-----------------------------------------------------------|
| TA0002 - Execution            | T1059.005    | —             | Command and Scripting Interpreter: Visual Basic (mshta)   |
| TA0001 - Initial Access       | T1204.001    | —             | User Execution: Malicious Link                            |
| TA0010 - Exfiltration         | T1105        | —             | Ingress Tool Transfer                                     |
| TA0001 - Initial Access       | T1221        | —             | Template Injection                                        |
| TA0001 - Initial Access       | T1566.002    | —             | Phishing: Drive-by Compromise                             |
| TA0004 - Privilege Escalation | T1553.005    | —             | Subvert Trust Controls: Mark-of-the-Web Bypass            |
| TA0005 - Defense Evasion      | T1027.004    | —             | Obfuscated Files or Information: Base64                   |
| TA0042 - Resource Development | T1583.003    | —             | Acquire Infrastructure: Blockchain                        |

---

## Hunt Query Logic

This query identifies processes that exhibit multiple EtherHiding and ClickFix infection chain hallmarks:

- `mshta.exe` execution with command lines referencing EtherHiding or clipboard-based payloads
- JavaScript or obfuscation keywords in command line
- Parent process is `explorer.exe` or `userinit.exe` (user-initiated)
- Social engineering lure keywords present

These combined patterns are highly suggestive of EtherHiding-based Lumma Stealer delivery and execution.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| FileName = "mshta.exe" | CommandLine = "*check.foquh.icu*" OR CommandLine = "*data-seed-prebsc-1-s1.bnbchain.org*" OR CommandLine = "*clipboard*"  
| (CommandLine = "*javascript*" OR CommandLine = "*fromCharCode*" OR CommandLine = "*Base64*" OR CommandLine = "*window.location*")  
| ParentBaseFileName = "explorer.exe" OR ParentBaseFileName = "userinit.exe"  
| (CommandLine = "*I'm not a robot*" OR CommandLine = "*ClickFix*")  
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute LOLBins and interact with the Windows Run dialog.
- **Required Artifacts:** Process command lines, parent process metadata, network connection logs.

---

## Considerations

- Review clipboard and Run dialog usage for evidence of social engineering.
- Investigate referenced infrastructure for malicious content or blockchain-based command hosting.
- Correlate with other Lumma Stealer indicators for comprehensive incident response.

---

## False Positives

False positives may occur if:

- Power users or IT staff use `mshta.exe` for legitimate automation.
- Internal tools leverage JavaScript or clipboard-based execution for benign purposes.

---

## Recommended Response Actions

1. Isolate the affected endpoint from the network.
2. Acquire memory and disk images for forensic analysis.
3. Investigate clipboard and Run dialog usage for evidence of social engineering.
4. Search for additional indicators of Lumma Stealer or related malware.
5. Block identified malicious domains and IPs at the network perimeter.

---

## References

- [MITRE ATT&CK: T1204.001 – User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
- [MITRE ATT&CK: T1059.005 – Command and Scripting Interpreter: Visual Basic](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1221 – Template Injection](https://attack.mitre.org/techniques/T1221/)
- [MITRE ATT&CK: T1566.002 – Phishing: Drive-by Compromise](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK: T1553.005 – Subvert Trust Controls: Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005/)
- [MITRE ATT&CK: T1027.004 – Obfuscated Files or Information: Base64](https://attack.mitre.org/techniques/T1027/004/)
- [MITRE ATT&CK: T1583.003 – Acquire Infrastructure: Blockchain](https://attack.mitre.org/techniques/T1583/003/)
- [Lumma Stealer: Breaking down the delivery techniques and capabilities of a prolific infostealer](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- [Threat Actors Deploy LummaC2 Malware to Exfiltrate Sensitive Data from Organizations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-04 | Initial Detection | Created hunt query to detect EtherHiding and ClickFix-based Lumma Stealer infection chain   |
