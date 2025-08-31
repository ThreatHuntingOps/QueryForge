# Detection of Suspicious File Collection and Compression for Potential Exfiltration

## Metadata  
**ID:** HuntQuery-CrowdStrike-LummaStealer-Suspicious-Compression-Exfil  
**OS:** WindowsEndpoint, WindowsServer  
**FP Rate:** Medium  

---

## ATT&CK Tags

| Tactic                | Technique   | Subtechnique      | Technique Name                                 |
|----------------------|-------------|-------------------|------------------------------------------------|
| TA0009 - Collection  | T1005       | —                 | Data from Local System                         |
| TA0009 - Collection  | T1560       | 001               | Archive Collected Data: Local Archiving        |
| TA0002 - Execution   | T1059       | 001               | Command and Scripting Interpreter: PowerShell  |

---

## Utilized Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source | ATT&CK Data Component |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Execution      |

---

## Technical description of the attack  
This hunt targets the use of PowerShell to enumerate and compress potentially sensitive files before exfiltration. Common in post-exploitation scenarios, adversaries use PowerShell commands such as `Get-ChildItem` combined with `Compress-Archive` to gather document files like `.docx`, `.pdf`, and `.xlsx`, which are then prepared for transfer.

---

## Permission required to execute the technique  
User

---

## Detection description  
This hunt identifies PowerShell processes that use both `Get-ChildItem` and `Compress-Archive` in the command line while specifying document-type extensions. This behavior is indicative of automated file discovery and packaging, often preceding exfiltration attempts.

---

## Considerations  
Context is crucial to reducing false positives. Focus on suspicious paths (e.g., user folders, external drives) and uncommon user accounts performing the action. Fields like `ParentBaseFileName`, `CommandLine`, and `UserSid` should be reviewed closely.

---

## False Positives  
Legitimate IT automation or backup scripts might use similar PowerShell commands. Cross-reference with scheduling patterns, known admin tools, and user roles to validate benign behavior.

---

## Suggested Response Actions  
- Investigate source script or binary responsible for launching the PowerShell command.  
- Review file paths accessed and compressed.  
- Determine whether the archive was written to removable media or uploaded over the network.  
- Monitor for subsequent network connections or data transfer.  
- If malicious, isolate endpoint and examine lateral movement or staging activity.

---

## References  
* [MITRE ATT&CK - T1005](https://attack.mitre.org/techniques/T1005/)  
* [MITRE ATT&CK - T1560.001](https://attack.mitre.org/techniques/T1560/001/)  
* [MITRE ATT&CK - T1059.001](https://attack.mitre.org/techniques/T1059/001/)  

---

## Detection  

**Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon  

```fql
#event_simpleName=ProcessRollup2
| ImageFileName=*powershell.exe
| CommandLine=*Get-ChildItem* AND CommandLine=*Compress-Archive*
| CommandLine=* -Include *.docx* OR CommandLine=* -Include *.pdf* OR CommandLine=* -Include *.xlsx*
```

---
## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2025-04-14| Initial Detection | Created hunt query to detect PowerShell use for file discovery and compression pre-exfil |
