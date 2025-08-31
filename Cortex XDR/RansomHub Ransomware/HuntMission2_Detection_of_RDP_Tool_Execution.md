# Detection of Credential Dumping and Network Scanning Tools Launched via RDP

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-RDP-ToolExec
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the execution of well-known credential dumping tools (such as Mimikatz and CredentialsFileView) and network scanning utilities (such as Advanced IP Scanner and NetScan) when launched from an RDP session. Specifically, it looks for these tools being executed with `explorer.exe` as the parent process, which is a strong indicator of interactive, hands-on-keyboard attacker activity via Remote Desktop Protocol.

Detected behaviors include:

- Launching credential dumping tools to extract passwords and hashes from memory
- Running network scanners to enumerate internal network assets and services
- Use of RDP for initial access or lateral movement, followed by tool deployment

Such activity is highly correlated with post-exploitation phases of targeted intrusions and ransomware operations.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0006 - Credential Access    | T1003.001   | —            | OS Credential Dumping: LSASS Memory           |
| TA0007 - Discovery            | T1087       | —            | Account Discovery                             |
| TA0007 - Discovery            | T1046       | —            | Network Service Discovery                     |
| TA0008 - Lateral Movement     | T1021.001   | —            | Remote Services: Remote Desktop Protocol      |

---

## Hunt Query Logic

This query identifies suspicious executions of credential dumping and network scanning tools where the parent process is `explorer.exe`, a common parent for processes launched in an RDP session. This pattern is often seen in hands-on-keyboard attacks where adversaries interactively deploy tools after gaining access.

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
    and (
        action_process_image_name = "mimikatz.exe"
        or action_process_image_name = "credentialsfileview.exe"
        or action_process_image_name = "netscan.exe"
        or action_process_image_name = "advanced_ip_scanner.exe"
    )
    and (
        causality_actor_process_image_name = "explorer.exe"
        or causality_actor_process_image_path contains "explorer.exe"
    )
| fields _time, agent_hostname, action_process_image_name, action_process_image_path, action_process_image_command_line, causality_actor_process_image_name, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have RDP access and the ability to execute binaries.
- **Required Artifacts:** Process creation logs, parent/child process relationships.

---

## Considerations

- Investigate the user account and source IP associated with the RDP session.
- Review for additional suspicious activity before and after tool execution.
- Correlate with authentication logs for signs of brute force or password spray attacks.
- Check for lateral movement or data exfiltration following tool use.

---

## False Positives

False positives may occur if:

- Administrators are legitimately using these tools for troubleshooting or network inventory.
- Security teams are running credential or network discovery tools as part of authorized assessments.

---

## Recommended Response Actions

1. Investigate the context of the RDP session and user account involved.
2. Review the timeline of tool execution and any subsequent suspicious activity.
3. Check for evidence of credential theft, lateral movement, or data staging.
4. Isolate affected systems if malicious activity is confirmed.
5. Reset credentials and review RDP access policies as needed.

---

## References

- [MITRE ATT&CK: T1003.001 – OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK: T1087 – Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [MITRE ATT&CK: T1046 – Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [DFIR Report: Hide Your RDP – Password Spray Leads to RansomHub Deployment](https://thedfirreport.com/2025/06/30/hide-your-rdp-password-spray-leads-to-ransomhub-deployment/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-10 | Initial Detection | Created hunt query to detect credential dumping and network scanning tools launched via RDP |
