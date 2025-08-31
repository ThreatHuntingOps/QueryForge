# Detection of Batch Files Downloading and Executing Python Payloads

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-BatchPythonDownloader
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of batch (`.bat`) files that download Python scripts or executables and then execute them. Attackers may use batch files to automate the retrieval of Python payloads using utilities such as `curl`, `wget`, `Invoke-WebRequest`, or `certutil`, followed by execution via `python` or direct invocation of `.py` files. This multi-stage technique is often used for initial access, persistence, or lateral movement, enabling the deployment of more complex malware or tools.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution           | T1059.006   | —            | Command and Scripting Interpreter: Python              |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                                  |

---

## Hunt Query Logic

This query identifies suspicious executions where batch files are used to download and execute Python payloads:

- The process name or parent process name ends with `.bat`
- The command line includes references to `python`, `.py` files, or download utilities such as `curl`, `wget`, `Invoke-WebRequest`, or `certutil`

Such patterns are frequently observed in malware delivery, initial access, and lateral movement scenarios involving Python-based payloads.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (FileName = "*.bat" OR ParentBaseFileName = "*.bat")    
| (CommandLine = "*python*" OR CommandLine = "*.py" OR CommandLine = "*curl*" OR CommandLine = "*wget*" OR CommandLine = "*Invoke-WebRequest*" OR CommandLine = "*certutil*")
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute batch files, download utilities, and Python interpreters.
- **Required Artifacts:** Batch files, process creation logs, command-line arguments, network activity logs.

---

## Considerations

- Investigate the batch file's contents for download and execution logic.
- Review the source and destination of any download commands.
- Correlate with network logs to identify downloaded Python payloads and their origins.
- Check for subsequent process creation or file writes following the download and execution.

---

## False Positives

False positives may occur if:

- Legitimate administrative scripts use batch files to automate Python script downloads or executions.
- Internal IT tools or deployment scripts invoke these utilities for benign purposes.

---

## Recommended Response Actions

1. Investigate the batch file and its source.
2. Analyze command-line arguments for suspicious download and execution activity.
3. Review network logs for connections to untrusted or external domains.
4. Isolate affected systems if malicious behavior is confirmed.
5. Remove any unauthorized payloads or scripts.

---

## References

- [MITRE ATT&CK: T1059.006 – Command and Scripting Interpreter: Python](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-30 | Initial Detection | Created hunt query to detect batch files downloading and executing Python payloads          |
