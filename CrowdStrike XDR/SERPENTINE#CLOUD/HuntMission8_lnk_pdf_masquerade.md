# Detection of Malicious LNK Files Masquerading as PDF Documents

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-LNK-PDF-Masquerade
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of malicious LNK shortcut (`.lnk`) files that masquerade as PDF documents and launch `cmd.exe`. This is a common initial access vector in SERPENTINE#CLOUD operations, where attackers use LNK files with PDF-like names or icons to lure users into executing commands that initiate the infection chain. Detected behaviors include:

- LNK files with PDF-like names or icons (e.g., `*.pdf.lnk`, display name "Browse the web")
- Execution of `cmd.exe` as a child process of `explorer.exe`
- Command lines referencing PDF LNK files or containing suspicious display names

These techniques are associated with phishing, masquerading, and initial access.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                |
| TA0005 - Defense Evasion     | T1036.002   | —            | Masquerading: Right-to-Left Override          |
| TA0001 - Initial Access      | T1566.001   | —            | Phishing: Spearphishing Attachment            |

---

## Hunt Query Logic

This query identifies suspicious executions of LNK files masquerading as PDF documents by looking for:

- `cmd.exe` launched as a child of `explorer.exe`
- Command lines referencing `*.pdf.lnk` or containing the display name "Browse the web"

These patterns are indicative of LNK files crafted to appear as PDF documents but used to launch malicious commands.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (ParentBaseFileName = /explorer\.exe/i)    
| (FileName = /cmd\.exe/i)    
| (CommandLine = "*pdf.lnk*" OR CommandLine = "*Browse the web*")
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User must be able to execute LNK files (default on Windows systems).
- **Required Artifacts:** Process creation logs, command-line arguments, and shortcut file metadata.

---

## Considerations

- Review the source and content of the LNK file for legitimacy and icon/filename masquerading.
- Correlate with email or download logs to determine if the file was delivered via phishing or social engineering.
- Investigate any network connections or subsequent process launches initiated as a result of the LNK file execution.
- Validate if the LNK file or associated payloads are linked to known malicious infrastructure or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Users legitimately use LNK files with PDF icons for automation or document access.
- Automated tools or scripts generate and execute LNK files for benign purposes.

---

## Recommended Response Actions

1. Investigate the source and intent of the LNK file and its associated commands.
2. Analyze the command line for PDF LNK references or suspicious display names.
3. Review user activity and email/download logs for signs of phishing or masquerading.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious LNK files and associated payloads.

---

## References

- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1036.002 – Masquerading: Right-to-Left Override](https://attack.mitre.org/techniques/T1036/002/)
- [MITRE ATT&CK: T1566.001 – Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [Securonix: Analyzing SERPENTINE#CLOUD Threat Actors Abuse Cloudflare Tunnels](https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-01 | Initial Detection | Created hunt query to detect malicious LNK files masquerading as PDF documents |
