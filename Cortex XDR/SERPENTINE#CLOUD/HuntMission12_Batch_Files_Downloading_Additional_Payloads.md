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

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Batch File or Parent Batch File Invoking Download Utilities
// Description: Detects execution of batch files (or processes spawned by batch files) where the command line includes common download utilities, which may indicate script-based download or staging activity.
// MITRE ATT&CK TTP ID: T1105

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
        action_process_image_command_line contains "curl"
        or action_process_image_command_line contains "bitsadmin"
        or action_process_image_command_line contains "powershell"
        or action_process_image_command_line contains "certutil"
        or action_process_image_command_line contains "wget"
        or action_process_image_command_line contains "Invoke-WebRequest"
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
