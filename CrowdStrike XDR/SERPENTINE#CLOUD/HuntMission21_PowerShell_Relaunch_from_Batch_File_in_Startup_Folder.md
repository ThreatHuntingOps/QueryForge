# Detection of PowerShell Relaunch from Batch File in Startup Folder

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-PSRelaunchStartup
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects instances where `powershell.exe` is launched by a batch file (`startuppp.bat`) located in the user's Startup folder, often with arguments to hide the PowerShell window (e.g., `-windowstyle hidden` or `-w hidden`). This technique is commonly used by threat actors to achieve persistence and evade user notice by relaunching malicious PowerShell payloads on user logon with no visible window. The combination of process ancestry, file path, and hidden window arguments is a strong indicator of suspicious or malicious activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0003 - Persistence         | T1547.001   | —            | Registry Run Keys / Startup Folder                     |
| TA0005 - Defense Evasion     | T1059.001   | —            | Command and Scripting Interpreter: PowerShell          |

---

## Hunt Query Logic

This query identifies suspicious PowerShell relaunch activity from a batch file in the Startup folder:

- The process name is `powershell.exe` (case-insensitive)
- The parent process is `startuppp.bat` (case-insensitive)
- The parent image file path is the user's Startup folder
- The command line includes `-windowstyle hidden` or `-w hidden`

Such patterns are rarely seen in legitimate workflows and are often associated with persistence and defense evasion techniques.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (FileName = /powershell\.exe/i)    
| (ParentBaseFileName = /startuppp\.bat/i)    
| (ParentImageFileName = "*\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\startuppp.bat")    
| CommandLine = "*-windowstyle hidden*" OR CommandLine = "*-w hidden*"
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to write to the Startup folder and execute batch and PowerShell scripts.
- **Required Artifacts:** Batch files in Startup, process creation logs, command-line arguments.

---

## Considerations

- Investigate the batch file and PowerShell script for persistence or malicious logic.
- Review the parent process to determine how the script was dropped or executed.
- Correlate with other endpoint activity for signs of lateral movement or further persistence.
- Check for additional files or payloads staged in the Startup folder.

---

## False Positives

False positives are rare but may occur if:

- Legitimate administrative or automation scripts use similar persistence techniques (uncommon in most environments).

---

## Recommended Response Actions

1. Investigate the batch file and PowerShell script and their sources.
2. Analyze command-line arguments for suspicious or hidden execution activity.
3. Review system and security logs for additional signs of persistence or compromise.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized scripts or payloads from the Startup folder.

---

## References

- [MITRE ATT&CK: T1547.001 – Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-02 | Initial Detection | Created hunt query to detect PowerShell relaunch from batch file in Startup folder         |
