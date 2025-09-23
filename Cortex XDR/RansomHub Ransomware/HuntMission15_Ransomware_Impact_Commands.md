# Detection of Ransomware Impact Commands (VM Shutdown, Shadow Copy Deletion, Log Clearing)

## Severity or Impact of the Detected Behavior

- **Risk Score:** 95  
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-Ransomware-Impact-Commands
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the execution of commands commonly used by ransomware to maximize impact and inhibit recovery. These include stopping virtual machines, deleting shadow copies, and clearing event logs. Such actions are designed to prevent system recovery, erase forensic evidence, and ensure that encrypted data cannot be restored from backups. The query matches command lines associated with PowerShell VM shutdown, WMI shadow copy removal, event log clearing, and shadow copy deletion via `vssadmin.exe`.

Detected behaviors include:

- Execution of PowerShell commands to stop virtual machines (`Stop-VM`)
- Deletion of shadow copies using WMI (`Win32_ShadowCopy`, `Remove-CimInstance`) or `vssadmin.exe`
- Clearing of Windows event logs using `wevtutil cl`
- Commonly observed in ransomware campaigns to maximize impact and hinder recovery

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact               | T1486       | —            | Data Encrypted for Impact                     |
| TA0040 - Impact               | T1490       | —            | Inhibit System Recovery                       |
| TA0005 - Defense Evasion      | T1070.001   | —            | Indicator Removal on Host: Clear Windows Event Logs |

---

## Hunt Query Logic

This query identifies suspicious process creation events where the command line matches known ransomware impact commands, including VM shutdown, shadow copy deletion, and event log clearing. Such activity is rarely seen in legitimate environments and should be investigated immediately.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_command_line contains "Stop-VM"
        or action_process_image_command_line contains "Win32_ShadowCopy"
        or action_process_image_command_line contains "Remove-CimInstance"
        or action_process_image_command_line contains "wevtutil cl"
        or action_process_image_command_line contains "vssadmin.exe Delete Shadows"
    )
| fields _time, agent_hostname, action_process_image_name, action_process_image_path, action_process_image_command_line, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have administrative privileges to execute impact commands.
- **Required Artifacts:** Process creation logs, command-line arguments, system and backup status.

---

## Considerations

- Investigate the user account and host context for the detected impact command execution.
- Review for additional signs of ransomware deployment, such as simultaneous activity across multiple hosts.
- Correlate with other suspicious events, such as credential dumping or lateral movement.
- Check for legitimate administrative or backup operations that may explain the execution.

---

## False Positives

False positives may occur if:

- Administrators are performing legitimate maintenance, backup, or troubleshooting tasks.
- Automated scripts or IT tools execute these commands as part of scheduled operations.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the impact command execution.
2. Review recent activity for signs of ransomware deployment or system compromise.
3. Check for additional indicators of compromise or privilege escalation.
4. Isolate affected systems if malicious activity is confirmed.
5. Restore data from secure backups and review recovery procedures.

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1070.001 – Indicator Removal on Host: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-10 | Initial Detection | Created hunt query to detect ransomware impact commands (VM shutdown, shadow copy deletion, log clearing) |
