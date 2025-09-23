# Detection of Suspicious Binary Execution from Network Share

## Severity or Impact of the Detected Behavior

- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-SuspiciousNetShareExec
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of binaries from network shares, such as `\10.x.x.x\ADMIN$`, which is a common technique for lateral movement and malware delivery. Attackers often stage or deliver payloads to network shares and execute them remotely, sometimes using randomized or atypical binary names to evade detection. Detected behaviors include:

- Process launches of `.exe` files from network share paths containing `\ADMIN$\`
- Exclusion of known legitimate binaries (e.g., CyberArk’s `PSMWinAgent.exe`)
- Full process and user context for investigation

These techniques are associated with hands-on-keyboard activity, post-exploitation, and malware delivery.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021.002   | —            | Remote Services: SMB/Windows Admin Shares      |
| TA0010 - Exfiltration        | T1105       | —            | Ingress Tool Transfer                         |

---

## Hunt Query Logic

This query identifies suspicious binary execution by looking for:

- Process starts of `.exe` files from network share paths containing `\ADMIN$\`
- Exclusion of known legitimate binaries (e.g., `PSMWinAgent.exe`)
- Full process and user context for triage

These patterns are indicative of lateral movement, malware staging, or remote payload execution.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Suspicious Binary Execution from Network Share
// Description: Detects execution of binaries from network shares (e.g., \10.x.x.x\ADMIN$), which is a common lateral movement and malware delivery technique.
// MITRE ATT&CK TTP ID: T1021.002
// MITRE ATT&CK TTP ID: T1105

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_path contains "\\"
    and action_process_image_path contains "\ADMIN$\"
    and action_process_image_name contains ".exe"
    and action_process_image_name != "PSMWinAgent.exe" // CyberArk signed file
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
- Investigate any subsequent lateral movement or malware activity.

---

## False Positives

False positives may occur if:

- IT administrators or deployment tools legitimately execute binaries from network shares.
- Known and trusted binaries are executed from these paths (ensure exclusions are up to date).

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Review user activity and system logs for signs of compromise or lateral movement.
3. Analyze any subsequent network connections or file transfers.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious network share execution attempts.

---

## References

- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares (PsExec)](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect suspicious binary execution from network shares                |
