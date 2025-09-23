# Detection of Configure-SMRemoting.exe Execution

## Severity or Impact of the Detected Behavior

- **Risk Score:** 75
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-ConfigureSMRemoting-Exec
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of `Configure-SMRemoting.exe`, a legitimate Windows utility that enables or disables remote management on a system. While it is used for legitimate administrative purposes, threat actors may abuse this tool to enable remote management and facilitate lateral movement or remote control during post-exploitation. Detected behaviors include:

- Process launches of `Configure-SMRemoting.exe`
- Full process and user context for investigation

These techniques are associated with enabling remote management, which can be leveraged for lateral movement or persistence.

---

## ATT&CK Mapping

| Tactic                     | Technique   | Subtechnique | Technique Name                                 |
|---------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement | T1021.001   | —            | Remote Services: Remote Desktop Protocol       |

---

## Hunt Query Logic

This query identifies suspicious or unauthorized use of Configure-SMRemoting.exe by looking for:

- Process starts of `Configure-SMRemoting.exe`
- Full process and user context for triage

These patterns may indicate attempts to enable remote management for lateral movement or remote control.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Configure-SMRemoting.exe Execution Detection
// Description: Detects execution of Configure-SMRemoting.exe, which can be used to enable remote management and facilitate lateral movement.
// MITRE ATT&CK TTP ID: T1021.001

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_name = "configure-smremoting.exe"
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider   | Event Name   | ATT&CK Data Source  | ATT&CK Data Component  |
|----------------|--------------|---------------------|------------------------|
| Cortex XSIAM   | xdr_data     | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to execute Configure-SMRemoting.exe.
- **Required Artifacts:** Process creation logs and command-line arguments.

---

## Considerations

- Review the source and context of the Configure-SMRemoting.exe process and command line for legitimacy.
- Correlate with user activity and system logs to determine if the activity is user-initiated or automated.
- Investigate any subsequent remote management or lateral movement activity.

---

## False Positives

False positives may occur if:

- IT administrators legitimately use Configure-SMRemoting.exe for remote management configuration.
- Automated deployment tools or scripts generate and execute these commands for benign purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Review user activity and system logs for signs of compromise or lateral movement.
3. Analyze any subsequent remote management connections or changes.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious remote management configuration attempts.

---

## References

- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect Configure-SMRemoting.exe execution for remote management abuse |
