# Detection of PowerShell Event Log Clearing

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Clear-PSLogs
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects attempts to clear PowerShell-specific event logs using either the native `Clear-EventLog` cmdlet or the `wevtutil.exe` command-line utility. Threat actors, including the Chaos group, perform this action to erase evidence of their PowerShell-based activities, thereby hindering forensic investigation and evading detection. While administrators may occasionally clear logs for maintenance, this action is often a strong indicator that an attacker is actively trying to hide their presence on a compromised system.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|------------------------------------------------|
| TA0005 - Defense Evasion      | T1070       | .001         | Indicator Removal: Clear Windows Event Logs    |

---

## Hunt Query Logic

This query identifies attempts to clear PowerShell event logs by looking for two specific scenarios:
1.  The execution of `powershell.exe` with a command line containing the `Clear-EventLog` cmdlet and targeting either the "Windows PowerShell" or "Microsoft-Windows-PowerShell/Operational" logs.
2.  The execution of `wevtutil.exe` with the `cl` (clear-log) argument, targeting the same specific PowerShell logs.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: PowerShell Event Log Clearing to Evade Detection
// Description: Detects attempts to clear PowerShell event logs using either the Clear-EventLog cmdlet or wevtutil.exe, a common defense evasion technique.
// MITRE ATT&CK TTP ID: T1070.001

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS 
    and ( 
        (action_process_image_name = "powershell.exe" and action_process_image_command_line contains "Clear-EventLog" and (action_process_image_command_line contains "Windows PowerShell" or action_process_image_command_line contains "Microsoft-Windows-PowerShell/Operational")) 
        or 
        (action_process_image_name = "wevtutil.exe" and action_process_image_command_line contains "cl" and (action_process_image_command_line contains "Windows PowerShell" or action_process_image_command_line contains "Microsoft-Windows-PowerShell/Operational")) 
    ) 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** The attacker must have administrative privileges on the local machine to clear these event logs.
- **Required Artifacts:** Process creation logs with full command-line argument visibility.

---

## Considerations

- **Indicator of Compromise:** This activity is a strong indicator that other malicious actions have already occurred, and the attacker is now covering their tracks.
- **Investigative Focus:** The investigation should focus on what activities occurred *before* the log clearing event.
- **Other Logs:** While PowerShell logs may be cleared, other logs (e.g., Security, System, network logs, other EDR data) may still contain evidence of the attacker's activity.

---

## False Positives

False positives may occur if:
- System administrators clear logs as part of a decommissioning process or a major system change.
- Specific troubleshooting scripts are used that include log clearing as a step.
However, clearing these specific logs is not a routine administrative task and should always be verified.

---

## Recommended Response Actions

1.  **Isolate Host:** Immediately isolate the host to prevent further action and preserve any remaining forensic evidence.
2.  **Assume Compromise:** Treat the host as compromised. The act of clearing logs is a deliberate attempt to hide activity.
3.  **Investigate Preceding Activity:** Analyze all available data sources (other event logs, EDR telemetry, memory, filesystem) for activity that occurred immediately before the logs were cleared to determine what the attacker was trying to hide.
4.  **Analyze Actor:** Investigate the user account (`actor_effective_username`) and parent process (`actor_process_image_name`) that initiated the log clearing.
5.  **Remediate:** Proceed with full incident response and remediation procedures for a compromised host.

---

## References

- [MITRE ATT&CK: T1070.001 – Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [Cisco Talos: Unmasking the new Chaos RaaS group attacks](https://blog.talosintelligence.com/new-chaos-ransomware/)

---

## Version History

| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-07-28 | Initial Detection | Created hunt query to detect clearing of PowerShell-specific event logs. |
