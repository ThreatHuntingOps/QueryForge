# Detection of Multiple User Password Changes Using net.exe

## Severity or Impact of the Detected Behavior

- **Risk Score:** 85  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-NetExe-PasswordChange
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the use of `net.exe` to change, add, or manipulate multiple user accounts and passwords in a short time window. Such activity is often associated with attacker attempts to maintain persistence, facilitate lateral movement, spread ransomware, or block legitimate administrator access. The query focuses on command-line arguments that indicate user account creation, activation, password changes, or domain account manipulation.

Detected behaviors include:

- Use of `net.exe` to add new users or modify existing accounts
- Bulk password changes or account activations
- Attempts to manipulate domain accounts or password requirements

These actions are frequently observed during post-exploitation phases of targeted intrusions and ransomware operations.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0006 - Credential Access    | T1098       | —            | Account Manipulation                          |
| TA0006 - Credential Access    | T1078       | —            | Valid Accounts                                |
| TA0007 - Discovery            | T1087       | —            | Account Discovery                             |

---

## Hunt Query Logic

This query identifies suspicious executions of `net.exe` with command-line arguments related to user account creation, activation, password changes, or domain account manipulation. Multiple such events in a short time window may indicate malicious activity.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and action_process_image_name = "net.exe"
    and (
        action_process_image_command_line contains "user /add"
        or action_process_image_command_line contains "user /active:"
        or action_process_image_command_line contains "user /passwordchg:"
        or action_process_image_command_line contains "user /passwordreq:"
        or action_process_image_command_line contains "user /domain"
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

- **Required Permissions:** User or attacker must have privileges to run `net.exe` and modify user accounts.
- **Required Artifacts:** Process creation logs, command-line arguments, account management logs.

---

## Considerations

- Investigate the user account and host context for the detected `net.exe` activity.
- Review the timeline and number of password changes or account modifications.
- Correlate with other suspicious activity, such as privilege escalation or lateral movement.
- Check for signs of ransomware deployment or attempts to block legitimate admin access.

---

## False Positives

False positives may occur if:

- Administrators are performing legitimate bulk account management or password resets.
- Automated scripts or IT tools are used for user provisioning or maintenance.

---

## Recommended Response Actions

1. Investigate the user and process responsible for the password changes.
2. Review recent authentication and privilege escalation events.
3. Check for additional indicators of compromise or lateral movement.
4. Isolate affected systems if malicious activity is confirmed.
5. Reset credentials and review account management policies as needed.

---

## References

- [MITRE ATT&CK: T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK: T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [MITRE ATT&CK: T1087 – Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-10 | Initial Detection | Created hunt query to detect multiple user password changes using net.exe                  |
