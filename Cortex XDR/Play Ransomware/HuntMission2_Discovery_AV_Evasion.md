# Detection of AdFind, Grixba, and AV Tampering Tools Used by Play Ransomware

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Cortex-PlayRansomware-DiscoveryEvasion
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious usage of discovery tools (AdFind, Grixba) and AV evasion utilities (GMER, IOBit, PowerTool), as well as PowerShell-based tampering of Microsoft Defender. These behaviors are consistent with the discovery and defense evasion phases used by Play ransomware actors during lateral movement and privilege escalation. The query focuses on command lines referencing these tools or Defender tampering, especially when executed from temporary or user data directories.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                            |
|-------------------------------|-------------|--------------|----------------------------------------------------------|
| TA0007 - Discovery            | T1016       | —            | System Network Configuration Discovery                   |
| TA0007 - Discovery            | T1518.001   | —            | Software Discovery: Security Software Discovery          |
| TA0005 - Defense Evasion      | T1070.001   | —            | Indicator Removal on Host: Clear Windows Event Logs      |
| TA0005 - Defense Evasion      | T1562.001   | —            | Impair Defenses: Disable or Modify Tools                 |
| TA0007 - Discovery            | T1087.002   | —            | Account Discovery: Domain Account (via AdFind)           |
| TA0002 - Execution            | T1059.001   | —            | Command and Scripting Interpreter: PowerShell            |

---

## Hunt Query Logic

This query identifies suspicious process activity related to Play ransomware discovery and defense evasion:

- Command lines referencing AdFind, Grixba, GMER, PowerTool, IOBit, or PowerShell Defender tampering
- Additional keywords for Defender, AntiVirus, or security
- Execution from temp, AppData, or ProgramData directories

These patterns are commonly seen in lateral movement, privilege escalation, and defense evasion.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
// Title: Suspicious Security/AV Tool Usage from User Writeable Paths
// Description: Detects processes launched from temp, AppData, or ProgramData directories with command lines referencing security/AV tools or commands, and mentioning defender, antivirus, or security. This may indicate evasion or reconnaissance activity.
// MITRE ATT&CK TTP ID: T1562

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_command_line contains "adfind"
        or action_process_image_command_line contains "Grixba"
        or action_process_image_command_line contains "gmer.exe"
        or action_process_image_command_line contains "powertool"
        or action_process_image_command_line contains "iobit"
        or action_process_image_command_line contains "Get-MpPreference"
        or action_process_image_command_line contains "Set-MpPreference"
        or action_process_image_command_line contains "Add-MpPreference"
        or action_process_image_command_line contains "Remove-MpPreference"
        or action_process_image_command_line contains "DisableRealtimeMonitoring"
        or action_process_image_command_line contains "Clear-EventLog"
    )
    and (
        action_process_image_command_line contains "defender"
        or action_process_image_command_line contains "AntiVirus"
        or action_process_image_command_line contains "security"
    )
    and (
        action_process_image_path contains "/temp/"
        or action_process_image_path contains "/AppData/"
        or action_process_image_path contains "/ProgramData/"
    )
| fields _time, agent_hostname, action_process_image_name, action_process_image_path, action_process_image_command_line, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to collect process execution events from Windows endpoints.
- **Required Artifacts:** Process execution logs, command line arguments, file paths.

---

## Considerations

- Investigate the process path and command line for evidence of discovery or AV tampering tools.
- Validate the user context and parent process for additional signs of compromise.
- Correlate with other suspicious behaviors, such as privilege escalation or lateral movement.

---

## False Positives

False positives may occur if:
- Legitimate administrative or security tools use similar command lines or file paths.
- Internal IT scripts or software deployment tools invoke Defender tampering for benign reasons.

---

## Recommended Response Actions

1. Investigate the process tree and command line for malicious indicators.
2. Validate the legitimacy of the tool or script and its source.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References

- [MITRE ATT&CK: T1016 – System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)
- [MITRE ATT&CK: T1518.001 – Security Software Discovery](https://attack.mitre.org/techniques/T1518/001/)
- [MITRE ATT&CK: T1070.001 – Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE ATT&CK: T1562.001 – Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)
- [MITRE ATT&CK: T1087.002 – Domain Account Discovery](https://attack.mitre.org/techniques/T1087/002/)
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [#StopRansomware: Play Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-10 | Initial Detection | Created hunt query to detect Play ransomware discovery and AV evasion tools                 |
