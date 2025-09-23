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

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Batch File or Parent Batch File Invoking Scripting or Download Utilities
// Description: Detects execution of batch files (or processes spawned by batch files) where the command line includes Python, download utilities, or script execution, which may indicate automated or staged attacks.
// MITRE ATT&CK TTP ID: T1059

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name contains ".bat"
        or actor_process_image_name contains ".bat"
    )
    and (
        action_process_image_command_line contains "python"
        or action_process_image_command_line contains ".py"
        or action_process_image_command_line contains "curl"
        or action_process_image_command_line contains "wget"
        or action_process_image_command_line contains "Invoke-WebRequest"
        or action_process_image_command_line contains "certutil"
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

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
| 1.0     | 2025-07-01 | Initial Detection | Created hunt query to detect batch files downloading and executing Python payloads          |
