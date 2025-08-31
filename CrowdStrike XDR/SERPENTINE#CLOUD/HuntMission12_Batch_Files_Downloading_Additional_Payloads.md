# Detection of Batch Files Downloading Additional Payloads

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-BatchDownloader
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of batch (`.bat`) files that attempt to download additional payloads, a common technique in multi-stage malware campaigns. Attackers often use batch scripts to invoke utilities such as `curl`, `bitsadmin`, `powershell`, `certutil`, `wget`, or `Invoke-WebRequest` to retrieve and execute further malicious files. This behavior is a strong indicator of initial access or lateral movement, as it enables attackers to stage more complex payloads after gaining a foothold.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                                  |

---

## Hunt Query Logic

This query identifies suspicious executions where batch files are used to download additional payloads:

- The process name or parent process name ends with `.bat` (case-insensitive)
- The command line includes download utilities such as `curl`, `bitsadmin`, `powershell`, `certutil`, `wget`, or `Invoke-WebRequest`

Such patterns are frequently observed in malware delivery, initial access, and lateral movement scenarios.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (FileName = /\.bat$/i OR ParentBaseFileName = /\.bat$/i)    
| (CommandLine = "*curl*" OR CommandLine = "*bitsadmin*" OR CommandLine = "*powershell*" OR CommandLine = "*certutil*" OR CommandLine = "*wget*" OR CommandLine = "*Invoke-WebRequest*")  
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute batch files and network utilities.
- **Required Artifacts:** Batch files, process creation logs, command-line arguments, network activity logs.

---

## Considerations

- Investigate the source and destination of the download commands.
- Review the batch file's contents for additional malicious logic.
- Correlate with network logs to identify downloaded payloads and their origins.
- Check for subsequent process creation or file writes following the download.

---

## False Positives

False positives may occur if:

- Legitimate administrative scripts use batch files to automate software downloads or updates.
- Internal IT tools or deployment scripts invoke these utilities for benign purposes.

---

## Recommended Response Actions

1. Investigate the batch file and its source.
2. Analyze command-line arguments for suspicious download activity.
3. Review network logs for connections to untrusted or external domains.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized payloads or scripts.

---

## References

- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-01 | Initial Detection | Created hunt query to detect batch files downloading additional payloads                    |
