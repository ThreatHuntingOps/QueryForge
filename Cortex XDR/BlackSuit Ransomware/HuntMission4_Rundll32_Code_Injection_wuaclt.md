# Detection of Rundll32 Code Injection into wuaclt.exe

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Rundll32-Wuaclt-Injection
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects instances where `rundll32.exe` is used to inject code into `wuaclt.exe`, which is highly suspicious and indicative of process injection or living-off-the-land techniques. Attackers may leverage this technique for lateral movement, internal reconnaissance, or to evade detection by abusing trusted Windows binaries. Detected behaviors include:

- Process launches of `wuaclt.exe` with `rundll32.exe` as the parent or in the process ancestry
- Full process and user context for investigation

These techniques are associated with process injection, defense evasion, and post-exploitation activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021.001   | —            | Remote Services: Remote Desktop Protocol       |
| TA0008 - Lateral Movement    | T1021.002   | —            | Remote Services: SMB/Windows Admin Shares      |
| TA0010 - Exfiltration        | T1105       | —            | Ingress Tool Transfer                         |
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                             |
| TA0005 - Defense Evasion     | T1218.011   | —            | Signed Binary Proxy Execution: Rundll32        |

---

## Hunt Query Logic

This query identifies suspicious code injection by looking for:

- Process starts of `wuaclt.exe` where the parent or causality ancestry includes `rundll32.exe`
- Full process and user context for triage

These patterns are indicative of process injection, defense evasion, or living-off-the-land techniques.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Rundll32 Code Injection into wuaclt.exe
// Description: Detects rundll32.exe injecting code into wuaclt.exe, a suspicious behavior associated with lateral movement and internal reconnaissance.
// MITRE ATT&CK TTP ID: T1055
// MITRE ATT&CK TTP ID: T1218.011

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_name = "wuaclt.exe"
    and (
        actor_process_image_name = "rundll32.exe"
        or causality_actor_process_command_line contains "rundll32.exe"
    )
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

- **Required Permissions:** User or attacker must have privileges to execute or inject into system processes.
- **Required Artifacts:** Process creation logs, command-line arguments, and process ancestry information.

---

## Considerations

- Review the source and context of the `wuaclt.exe` and `rundll32.exe` processes for legitimacy.
- Correlate with user activity and system logs to determine if the activity is user-initiated or automated.
- Investigate any subsequent lateral movement, reconnaissance, or malware activity.

---

## False Positives

False positives may occur if:

- IT administrators or legitimate tools use `rundll32.exe` for benign automation.
- Automated deployment tools or scripts generate and execute these commands for legitimate purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Review user activity and system logs for signs of compromise or lateral movement.
3. Analyze any subsequent network connections or file transfers.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious process injection attempts.

---

## References

- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: T1218.011 – Signed Binary Proxy Execution: Rundll32](https://attack.mitre.org/techniques/T1218/011/)
- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect rundll32 code injection into wuaclt.exe                        |
