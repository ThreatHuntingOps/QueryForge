# Detection of AutoIt and PowerShell Execution from Phishing Attachment Leading to Agent Tesla Infection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-AutoItPowershell-AgentTesla
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious executions of JavaScript Encoded (`.jse`) or JavaScript (`.js`) files extracted from compressed archives. These files, when executed, launch PowerShell scripts that download and execute further payloads. This behavior was observed during a phishing campaign in December 2024 that led to Agent Tesla infections.

Indicators include:
- Execution of `.jse` or `.js` scripts by `wscript.exe` or `cscript.exe`
- PowerShell invocation from those scripts
- Use of `Invoke-WebRequest`, `IEX`, or `DownloadString` to download payloads
- File execution paths related to `AppData`, `Temp`, or `Downloads` directories

Such patterns align with the delivery and installation stages of Agent Tesla and are critical to detect early in the attack chain.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                                            |
|-------------------------------|------------|--------------|-----------------------------------------------------------|
| TA0001 - Initial Access       | T1566.002  | —            | Phishing: Spearphishing Link                              |
| TA0002 - Execution            | T1059.007  | —            | Command and Scripting Interpreter: JavaScript             |
| TA0002 - Execution            | T1059.001  | —            | Command and Scripting Interpreter: PowerShell             |
| TA0002 - Execution            | T1204.002  | —            | User Execution: Malicious File                            |

---

## Hunt Query Logic

This query identifies suspicious executions following phishing attachment delivery by focusing on `.jse` or `.js` script executions that trigger PowerShell downloads.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=/ProcessRollup2|ProcessCreation/  
| (FileName = /\.jse$/i OR FileName = /\.js$/i)  
| CommandLine = "*powershell*"  
| (ParentBaseFileName = "wscript.exe" OR ParentBaseFileName = "cscript.exe")  
| (FilePath = "*\\AppData\\*" OR FilePath = "*\\Temp\\*" OR FilePath = "*\\Downloads\\*")  
| (CommandLine = "*Invoke-WebRequest*" OR CommandLine = "*IEX*" OR CommandLine = "*DownloadString*") 
```

---

## Data Sources

| Log Provider | Event ID | Event Name        | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|-------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2     | Process              | Process Creation        |

---

## Execution Requirements

- **Required Permissions:** Standard user permissions to execute scripts and PowerShell commands.
- **Required Artifacts:** Access to process creation logs and command-line parameters.

---

## Considerations

- Review the source email and archive file to assess phishing intent.
- Analyze PowerShell payloads retrieved for additional malware indicators.
- Correlate with user activity to confirm if the file execution was intentional.

---

## False Positives

False positives may occur if:
- Users legitimately interact with `.jse` scripts for internal automation.
- PowerShell usage is common for internal administrative scripts without obfuscation.

---

## Recommended Response Actions

1. Investigate the source and behavior of the `.jse` file.
2. Analyze downloaded payloads for malware signatures (e.g., Agent Tesla).
3. Review affected system's lateral movements or credential theft attempts.
4. Isolate the affected host to prevent spread if malicious activity is confirmed.

---

## References

- [MITRE ATT&CK: T1566.002 – Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1059.007 – JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [Cascading Shadows: An Attack Chain Approach to Avoid Detection and Complicate Analysis](https://unit42.paloaltonetworks.com/phishing-campaign-with-complex-attack-chain/#new_tab)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-28 | Initial Detection | Created hunt query to detect phishing-based AutoIt and PowerShell activities leading to Agent Tesla infection |
