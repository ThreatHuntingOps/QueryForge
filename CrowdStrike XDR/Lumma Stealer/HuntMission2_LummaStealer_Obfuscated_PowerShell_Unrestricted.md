# Detection of Obfuscated PowerShell Execution with Unrestricted Policy and Hidden Window

## Metadata  
**ID:** HuntQuery-CrowdStrike-LummaStealer-Obfuscated-PowerShell-Unrestricted  
**OS:** WindowsEndpoint, WindowsServer  
**FP Rate:** Medium  

---

## ATT&CK Tags

| Tactic                | Technique   | Subtechnique | Technique Name                               |
|----------------------|-------------|---------------|----------------------------------------------|
| TA0002 - Execution    | T1059       | 001           | Command and Scripting Interpreter: PowerShell |
| TA0005 - Defense Evasion | T1027   | —             | Obfuscated Files or Information              |
| TA0005 - Defense Evasion | T1562   | 001           | Impair Defenses: Disable or Modify Tools     |

---

## Utilized Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source | ATT&CK Data Component |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Execution      |

---

## Technical description of the attack  
This hunt identifies the execution of obfuscated PowerShell scripts designed to evade detection and bypass execution policies. Attackers often leverage `powershell.exe` with flags such as `-ep Unrestricted`, `-nop`, and `-w 1` to disable logging, avoid interactive windows, and allow the execution of base64-encoded payloads. These techniques are frequently used in multi-stage payload delivery and loader activity post-exploitation.

---

## Permission required to execute the technique  
User

---

## Detection description  
This hunt looks for suspicious combinations of PowerShell command-line arguments including execution policy bypass, hidden window mode, and obfuscation indicators (e.g., `FromBase64String`, `New-Object`). These flags are commonly used together in malicious scripts to execute payloads without drawing user attention or triggering basic detection controls.

---

## Considerations  
Tuning may be required to suppress false positives caused by administrative or automation tasks that utilize PowerShell for legitimate system maintenance. Context from `CommandLine`, `ParentProcessId`, and `UserSid` fields can help distinguish benign from malicious usage.

---

## False Positives  
Some legitimate enterprise tools or IT scripts might invoke PowerShell using these parameters. Review script contents and user behavior to determine intent before escalating. Look for anomalous file paths, unexpected users, and privilege elevation.

---

## Suggested Response Actions  
- Review PowerShell execution context, including command line and parent process.  
- Identify dropped files or network activity following execution.  
- Isolate host if activity is deemed malicious or unauthorized.  
- Analyze the full process tree for lateral movement or persistence mechanisms.  
- Add detections for obfuscated payloads or encoded PowerShell in your SIEM or EDR solution.

---

## References  
* [MITRE ATT&CK - T1059.001](https://attack.mitre.org/techniques/T1059/001/)  
* [MITRE ATT&CK - T1027](https://attack.mitre.org/techniques/T1027/)  
* [MITRE ATT&CK - T1562.001](https://attack.mitre.org/techniques/T1562/001/)  

---

## Detection  

**Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon  

```fql
#event_simpleName=ProcessRollup2
| ImageFileName=*powershell.exe
| CommandLine=* -ep Unrestricted*
| CommandLine=* -nop*
| CommandLine=* -w 1*
| CommandLine=*VLET(* OR CommandLine=*FromBase64String(* OR CommandLine=*New-Object*))
```

---
## Version History
| Version | Date | Impact | Notes |
|---------|------|--------|------|
| 1.0  | 2025-04-14| Initial Detection | Created hunt query to detect obfuscated PowerShell commands with bypass and hidden window. |
