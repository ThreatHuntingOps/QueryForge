# Detection of PowerShell Registry Persistence via Chrome Updater Run Key

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-PowerShell-ChromeUpdater-RunKey
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low to Medium

---

## Hunt Analytics

This hunt detects PowerShell commands that create or modify Windows Registry Run keys for persistence, specifically those referencing a value named "Chrome Updater" and using a log file as an argument. Attackers use this technique to ensure malware execution at user logon, often masquerading as legitimate update processes to evade detection. Detected behaviors include:

- PowerShell or pwsh processes that create or modify Registry Run keys (using `new-itemproperty`, `set-itemproperty`, or `reg add`)
- Command lines referencing a value named "Chrome Updater"
- Arguments referencing both `run` and `log` (indicating persistence and possible logging or decoy activity)

These techniques are associated with malware establishing persistence while masquerading as legitimate Chrome update processes.

---

## ATT&CK Mapping

| Tactic              | Technique   | Subtechnique | Technique Name                                               |
|---------------------|-------------|--------------|-------------------------------------------------------------|
| TA0002 - Execution  | T1059.001   | —            | Command and Scripting Interpreter: PowerShell               |
| TA0003 - Persistence| T1547.001   | —            | Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder |
| TA0005 - Defense Evasion | T1036.005 | —         | Masquerading: Match Legitimate Name or Location             |

---

## Hunt Query Logic

This query identifies suspicious PowerShell process launches by looking for:

- PowerShell or pwsh processes
- Command lines that create or modify Registry Run keys (using `new-itemproperty`, `set-itemproperty`, or `reg add`)
- Command lines referencing a value named "Chrome Updater"
- Arguments referencing both `run` and `log`

These patterns are indicative of persistence techniques that masquerade as legitimate Chrome update processes.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: PowerShell Registry Persistence via Chrome Updater Run Key
// Description: Detects PowerShell commands that create or modify Registry Run keys with the value "Chrome Updater", a technique used for persistence by masquerading as legitimate Chrome updates.
// MITRE ATT&CK TTP ID: T1059.001
// MITRE ATT&CK TTP ID: T1547.001
// MITRE ATT&CK TTP ID: T1036.005

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
        action_process_image_command_line contains "new-itemproperty"
        or action_process_image_command_line contains "set-itemproperty"
        or action_process_image_command_line contains "reg add"
    )
    and action_process_image_command_line contains "Chrome Updater"
    and action_process_image_command_line contains "run"
    and action_process_image_command_line contains "log"
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

- **Required Permissions:** User or attacker must be able to execute PowerShell scripts and modify Registry Run keys.
- **Required Artifacts:** Process creation logs, command-line arguments, and registry modification records.

---

## Considerations

- Review the command line and registry key/value for legitimacy.
- Correlate with user activity and software installation logs to determine if the activity is user-initiated or malicious.
- Investigate any registry values named "Chrome Updater" for signs of persistence or masquerading.
- Validate if the PowerShell command is part of legitimate update or automation activity.

---

## False Positives

False positives may occur if:

- Legitimate software or IT automation scripts create or modify Registry Run keys for benign purposes.
- Chrome or other updaters use similar naming conventions for legitimate persistence.

---

## Recommended Response Actions

1. Investigate the command line and registry modification for intent and legitimacy.
2. Analyze the referenced log files and registry values for malicious content.
3. Review user activity and system logs for signs of persistence or masquerading.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor suspicious PowerShell registry persistence attempts.

---

## References

- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [CISA AA25-203A: #StopRansomware: Interlock](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-23 | Initial Detection | Created hunt query to detect PowerShell registry persistence via Chrome Updater Run key     |
