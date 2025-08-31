# Detection of Suspicious Rclone (vmware.exe) Data Exfiltration from Network Share

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Rclone-VMware-NetShare-Exfil
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects execution of `rclone.exe` or its renamed variant `vmware.exe` from a network share, especially when spawned by suspicious executables and connecting to external IPs or domains. This behavior is indicative of data exfiltration activity, often seen in ransomware and post-exploitation scenarios. Detected behaviors include:

- Process launches of `rclone.exe` or `vmware.exe` from network share paths containing `\ADMIN$\`
- Full process and user context for investigation
- Parent process context to identify suspicious ancestry (e.g., a2e6ee5.exe)

These techniques are associated with data exfiltration, masquerading, and hands-on-keyboard activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0010 - Exfiltration        | T1567.002   | —            | Exfiltration to Cloud Storage                 |
| TA0005 - Defense Evasion     | T1036       | —            | Masquerading                                 |

---

## Hunt Query Logic

This query identifies suspicious data exfiltration by looking for:

- Process starts of `rclone.exe` or `vmware.exe` from network share paths containing `\ADMIN$\`
- Full process and user context for triage
- Parent process context for further investigation

These patterns are indicative of data exfiltration using rclone or its variants from network shares.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Suspicious Rclone (vmware.exe) Data Exfiltration from Network Share
// Description: Detects execution of rclone.exe or its renamed variant vmware.exe from a network share, especially when spawned by suspicious executables, and connecting to external IPs/domains—indicative of data exfiltration.
// MITRE ATT&CK TTP ID: T1567.002
// MITRE ATT&CK TTP ID: T1036

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name = "rclone.exe"
        or action_process_image_name = "vmware.exe"
    )
    and action_process_image_path contains "\"
    and action_process_image_path contains "\ADMIN$\"
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

- **Required Permissions:** User or attacker must have access to network shares and privileges to execute binaries.
- **Required Artifacts:** Process creation logs, command-line arguments, and file path information.

---

## Considerations

- Review the source and context of the binary and network share for legitimacy.
- Correlate with user activity, network, and file creation logs to determine if the activity is user-initiated or automated.
- Investigate any subsequent data exfiltration or external connections.

---

## False Positives

False positives may occur if:

- IT administrators or backup tools legitimately use rclone or its variants from network shares.
- Known and trusted binaries are executed from these paths (ensure exclusions are up to date).

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Review user activity and system logs for signs of compromise or data exfiltration.
3. Analyze any subsequent network connections or file transfers.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious rclone or vmware.exe usage and known exfiltration destinations.

---

## References

- [MITRE ATT&CK: T1567.002 – Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
- [MITRE ATT&CK: T1036 – Masquerading](https://attack.mitre.org/techniques/T1036/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)
---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect suspicious rclone (vmware.exe) data exfiltration from network share |
