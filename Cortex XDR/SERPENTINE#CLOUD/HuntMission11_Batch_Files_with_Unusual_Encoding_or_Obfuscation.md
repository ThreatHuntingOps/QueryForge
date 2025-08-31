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

This hunt detects the execution of batch (`.bat`) files that may be obfuscated or encoded in non-standard formats (such as UTF-16LE). While XQL does not directly analyze file encoding or content, this hunt focuses on batch files executed from suspicious locations (like `%temp%` or `Downloads`) and exhibiting signs of obfuscation, such as high numbers of variable assignments, dynamic command construction, or repeated use of commands like `set`, `echo`, or `call`. These patterns are often used by attackers to evade detection and analysis.

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

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
// Title: Suspicious Batch File Execution from Temp or Downloads
// Description: Detects execution of .bat files from Temp or Downloads directories where the command line includes 'set', 'echo', or 'call'—common in malicious or staged scripts.
// MITRE ATT&CK TTP ID: T1059.003

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_name contains ".bat"
    and (action_process_image_path contains "/temp/" or action_process_image_path contains "/downloads/")
    and (
        action_process_image_command_line contains "set " 
        or action_process_image_command_line contains "echo " 
        or action_process_image_command_line contains "call "
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
