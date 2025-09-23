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

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Batch File or Parent Batch File Invoking System or AV Discovery Commands
// Description: Detects execution of batch files (or processes spawned by batch files) where the command line includes system discovery or antivirus product keywords, which may indicate reconnaissance or evasion activity.
// MITRE ATT&CK TTP ID: T1518

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
        action_process_image_command_line contains "wmic product get"
        or action_process_image_command_line contains "sc query"
        or action_process_image_command_line contains "Get-WmiObject"
        or action_process_image_command_line contains "avast"
        or action_process_image_command_line contains "defender"
        or action_process_image_command_line contains "kaspersky"
        or action_process_image_command_line contains "eset"
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
| 1.0     | 2025-07-01 | Initial Detection | Created hunt query to detect batch files enumerating antivirus products                    |
