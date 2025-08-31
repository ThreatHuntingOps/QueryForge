# Detection of Batch Files Enumerating Antivirus Products

## Severity or Impact of the Detected Behavior
- **Risk Score:** 60
- **Severity:** Medium

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-BatchAVEnum
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of batch (`.bat`) files that attempt to enumerate installed antivirus or security products. Attackers often use such enumeration to identify security controls present on a system, which can inform subsequent evasion or privilege escalation techniques. Common commands include `wmic product get`, `sc query`, `Get-WmiObject`, or direct references to known antivirus products such as Avast, Defender, Kaspersky, or ESET.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0007 - Discovery           | T1518.001   | —            | Software Discovery                                    |
| TA0005 - Defense Evasion     | T1082       | —            | System Information Discovery                          |

---

## Hunt Query Logic

This query identifies suspicious executions where batch files are used to enumerate antivirus or security products:

- The process name or parent process name ends with `.bat`
- The command line includes enumeration commands or references to known antivirus products (`wmic product get`, `sc query`, `Get-WmiObject`, `avast`, `defender`, `kaspersky`, `eset`)

Such patterns are often observed in the reconnaissance phase of an attack, where adversaries seek to understand the security posture of the target system.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (FileName = "*.bat" OR ParentBaseFileName = "*.bat")    
| (CommandLine = "*wmic*product*get*" OR CommandLine = "*sc query*" OR CommandLine = "*Get-WmiObject*" OR CommandLine = "*avast*" OR CommandLine = "*defender*" OR CommandLine = "*kaspersky*" OR CommandLine = "*eset*")
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute batch files and system enumeration commands.
- **Required Artifacts:** Batch files, process creation logs, command-line arguments.

---

## Considerations

- Investigate the batch file's contents for additional reconnaissance or evasion logic.
- Review the parent process to determine how the script was dropped or executed.
- Correlate with other endpoint activity for signs of further discovery or lateral movement.

---

## False Positives

False positives may occur if:

- Legitimate administrative scripts enumerate installed software for inventory or compliance purposes.
- IT or security tools perform regular system audits using batch files.

---

## Recommended Response Actions

1. Investigate the batch file and its source.
2. Analyze command-line arguments for suspicious enumeration activity.
3. Review system and security logs for additional reconnaissance or evasion attempts.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized scripts or tools.

---

## References

- [MITRE ATT&CK: T1518.001 – Software Discovery](https://attack.mitre.org/techniques/T1518/001/)
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-30 | Initial Detection | Created hunt query to detect batch files enumerating antivirus products                    |
