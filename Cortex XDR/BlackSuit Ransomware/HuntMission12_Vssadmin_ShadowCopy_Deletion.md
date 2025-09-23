# Detection of Data Deletion via vssadmin.exe Shadow Copy Removal

## Severity or Impact of the Detected Behavior

- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Vssadmin-ShadowCopy-Delete
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the use of `vssadmin.exe` to delete all shadow copies, a common ransomware and destructive attack technique to prevent file recovery. Attackers frequently leverage this command to inhibit system recovery and maximize the impact of ransomware or destructive actions. Detected behaviors include:

- Process launches of `vssadmin.exe` with command lines containing `delete`, `shadows`, `/all`, and `/quiet`
- Full process and user context for investigation

These techniques are associated with system recovery inhibition and destructive attacks.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1490       | —            | Inhibit System Recovery (Delete Shadow Copies) |

---

## Hunt Query Logic

This query identifies destructive activity by looking for:

- Process starts of `vssadmin.exe` with command lines containing `delete`, `shadows`, `/all`, and `/quiet`
- Full process and user context for triage

These patterns are indicative of attempts to delete shadow copies and inhibit system recovery.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Data Deletion via vssadmin.exe Shadow Copy Removal
// Description: Detects execution of vssadmin.exe with arguments to delete all shadow copies, a common ransomware and destructive attack technique to prevent file recovery.
// MITRE ATT&CK TTP ID: T1490

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_name = "vssadmin.exe"
    and action_process_image_command_line contains "delete"
    and action_process_image_command_line contains "shadows"
    and action_process_image_command_line contains "/all"
    and action_process_image_command_line contains "/quiet"
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

- **Required Permissions:** User or attacker must have privileges to execute vssadmin.exe and delete shadow copies.
- **Required Artifacts:** Process creation logs and command-line arguments.

---

## Considerations

- Review the source and context of the vssadmin.exe process and command line for legitimacy.
- Correlate with user activity and system logs to determine if the activity is user-initiated or automated.
- Investigate any subsequent ransomware or destructive activity.

---

## False Positives

False positives may occur if:

- IT administrators or backup tools legitimately use vssadmin.exe to manage shadow copies.
- Automated deployment tools or scripts generate and execute these commands for legitimate purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Review user activity and system logs for signs of compromise or destructive activity.
3. Analyze any subsequent ransomware or data loss events.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious vssadmin.exe usage and shadow copy deletion attempts.

---

## References

- [MITRE ATT&CK: T1490 – Inhibit System Recovery (Delete Shadow Copies)](https://attack.mitre.org/techniques/T1490/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect data deletion via vssadmin.exe shadow copy removal             |
