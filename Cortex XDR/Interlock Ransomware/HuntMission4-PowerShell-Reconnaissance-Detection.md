# Detection of Reconnaissance via Suspicious PowerShell Commands

## Severity or Impact of the Detected Behavior
- **Risk Score:** 70
- **Severity:** Medium

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-PowerShell-Recon-Detection
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of PowerShell commands commonly used for system and network reconnaissance. Adversaries often leverage PowerShell to enumerate users, gather system configuration, list services, inspect drives, and query network information. The presence of these commands—especially when executed together or in close succession—may indicate pre-attack reconnaissance activity. Detected behaviors include:

- PowerShell or pwsh processes executing reconnaissance commands such as:
  - `WindowsIdentity.GetCurrent()`
  - `systeminfo`
  - `tasklist /svc`
  - `Get-Service`
  - `Get-PSDrive`
  - `arp -a`

These techniques are associated with adversaries gathering information about the system, users, services, and network prior to further attack phases.

---

## ATT&CK Mapping

| Tactic                | Technique   | Subtechnique | Technique Name                                 |
|-----------------------|-------------|--------------|-----------------------------------------------|
| TA0007 - Discovery    | T1059.001   | —            | Command and Scripting Interpreter: PowerShell  |
| TA0007 - Discovery    | T1033       | —            | System Owner/User Discovery                    |
| TA0007 - Discovery    | T1082       | —            | System Information Discovery                   |
| TA0007 - Discovery    | T1007       | —            | System Service Discovery                       |
| TA0007 - Discovery    | T1016       | —            | System Network Configuration Discovery         |

---

## Hunt Query Logic

This query identifies suspicious PowerShell process launches by looking for:

- PowerShell or pwsh processes
- Command lines containing reconnaissance commands such as `WindowsIdentity.GetCurrent`, `systeminfo`, `tasklist /svc`, `Get-Service`, `Get-PSDrive`, or `arp -a`

These patterns are indicative of adversaries performing discovery and reconnaissance activities.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Reconnaissance via Suspicious PowerShell Commands
// Description: Detects PowerShell execution of commands commonly used for reconnaissance, including WindowsIdentity.GetCurrent(), systeminfo, tasklist /svc, Get-Service, Get-PSDrive, and arp -a.
// MITRE ATT&CK TTP ID: T1059.001
// MITRE ATT&CK TTP ID: T1033
// MITRE ATT&CK TTP ID: T1082
// MITRE ATT&CK TTP ID: T1007
// MITRE ATT&CK TTP ID: T1016

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name = "powershell.exe"
        or action_process_image_name = "pwsh.exe"
    )
    and (
        action_process_image_command_line contains "WindowsIdentity.GetCurrent"
        or action_process_image_command_line contains "systeminfo"
        or action_process_image_command_line contains "tasklist /svc"
        or action_process_image_command_line contains "Get-Service"
        or action_process_image_command_line contains "Get-PSDrive"
        or action_process_image_command_line contains "arp -a"
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute PowerShell scripts.
- **Required Artifacts:** Process creation logs and command-line arguments.

---

## Considerations

- Review the command line and context for legitimacy.
- Correlate with user activity and system logs to determine if the activity is user-initiated or malicious.
- Investigate if multiple reconnaissance commands are executed together or in close succession.

---

## False Positives

False positives may occur if:

- IT staff or legitimate automation scripts use PowerShell for system inventory, troubleshooting, or monitoring.
- Security tools or monitoring agents execute similar reconnaissance commands for benign purposes.

---

## Recommended Response Actions

1. Investigate the command line and process context for intent and legitimacy.
2. Review user activity and system logs for signs of unauthorized reconnaissance.
3. Correlate with other alerts or suspicious activity to determine if this is part of a larger attack chain.
4. Isolate affected endpoints if malicious reconnaissance is confirmed.
5. Block or monitor suspicious PowerShell reconnaissance activity.

---

## References

- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1033 – System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)
- [MITRE ATT&CK: T1007 – System Service Discovery](https://attack.mitre.org/techniques/T1007/)
- [MITRE ATT&CK: T1016 – System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
- [CISA AA25-203A: #StopRansomware: Interlock](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-23 | Initial Detection | Created hunt query to detect reconnaissance via suspicious PowerShell commands              |
