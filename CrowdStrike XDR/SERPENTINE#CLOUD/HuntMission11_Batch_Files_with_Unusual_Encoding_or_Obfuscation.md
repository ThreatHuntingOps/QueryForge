# Detection of Batch Files with Unusual Encoding or Obfuscation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 65
- **Severity:** Medium

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-BatchObfuscation
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of batch (`.bat`) files that may be obfuscated or encoded in non-standard formats (such as UTF-16LE). While Falcon X-FQL does not directly analyze file encoding or content, this hunt focuses on batch files executed from suspicious locations (like `%temp%` or `Downloads`) and exhibiting signs of obfuscation, such as high numbers of variable assignments, dynamic command construction, or repeated use of commands like `set`, `echo`, or `call`. These patterns are often used by attackers to evade detection and analysis.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell |
| TA0005 - Defense Evasion     | T1027       | —            | Obfuscated Files or Information                        |
| TA0003 - Persistence         | T1547.001   | —            | Registry Run Keys / Startup Folder                     |

---

## Hunt Query Logic

This query identifies suspicious executions of batch files that match the following indicators:

- The process name ends with `.bat` (case-insensitive)
- The file is executed from `%temp%` or `Downloads` directories
- The command line includes frequent use of `set`, `echo`, or `call` (suggesting variable assignment or dynamic command execution)

Such patterns are commonly associated with obfuscated or encoded batch scripts used in malware delivery, privilege escalation, or persistence.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (FileName = /\.bat$/i)    
| (FilePath = "*\\Temp\\*" OR FilePath = "*\\Downloads\\*")    
| CommandLine = "*set *" OR CommandLine = "*echo *" OR CommandLine = "*call *"
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute batch files.
- **Required Artifacts:** Batch files in `%temp%` or `Downloads`, process creation logs, command-line arguments.

---

## Considerations

- Investigate the batch file's contents and encoding for obfuscation or malicious code.
- Review the parent process to determine how the script was dropped or executed.
- Correlate with other endpoint activity for signs of lateral movement or persistence.
- Check for additional files or payloads dropped in `%temp%` or `Downloads`.

---

## False Positives

False positives may occur if:

- Legitimate administrative or automation scripts are run from `%temp%` or `Downloads` using batch files.
- Software installers or updaters temporarily use batch scripts for setup tasks.

---

## Recommended Response Actions

1. Investigate the batch file and its source.
2. Analyze command-line arguments for suspicious or obfuscated code.
3. Review parent and child process relationships for further malicious activity.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized scripts or payloads from `%temp%` or `Downloads`.

---

## References

- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK: T1547.001 – Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-01 | Initial Detection | Created hunt query to detect batch files with unusual encoding or obfuscation              |
