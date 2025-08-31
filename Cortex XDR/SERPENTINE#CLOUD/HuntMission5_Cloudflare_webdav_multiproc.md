# Detection of Cloudflare Tunnel WebDAV Activity Across Multiple Processes

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Cloudflare-WebDAV-MultiProc
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This comprehensive hunt detects attempts by various processes to establish WebDAV connections to Cloudflare tunnel subdomains (e.g., `*.trycloudflare.com`). This activity is a hallmark of SERPENTINE#CLOUD operations, where multiple process types—including command shells and scripting engines—are used to download, stage, or execute payloads via Cloudflare Tunnel infrastructure. Detected behaviors include:

- Command lines referencing Cloudflare Tunnel domains and WebDAV operations
- Use of commands such as `net use` or UNC paths (`\`) to initiate network connections
- Involvement of common process types: `cmd.exe`, `powershell.exe`, `wscript.exe`, and `cscript.exe`

These techniques are associated with remote payload delivery, lateral movement, and command and control.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021.002   | —            | Remote Services: SMB/Windows Admin Shares     |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell |
| TA0002 - Execution           | T1059.001   | —            | Command and Scripting Interpreter: PowerShell |

---

## Hunt Query Logic

This query identifies suspicious WebDAV and Cloudflare Tunnel activity by looking for:

- Command lines referencing Cloudflare Tunnel domains (`cloudflare`, `*.trycloudflare.com`)
- Command lines containing WebDAV operations, `net use`, or UNC paths (`\`)
- Involvement of process types such as `cmd.exe`, `powershell.exe`, `wscript.exe`, or `cscript.exe`

These patterns are indicative of attempts to leverage Cloudflare Tunnel infrastructure for remote payload delivery or lateral movement.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
 // Title: Suspicious Scripting/Command Process with Cloudflare and Network Share Indicators
// Description: Detects cmd.exe, powershell.exe, wscript.exe, or cscript.exe processes with command lines referencing Cloudflare and network share or WebDAV usage, which may indicate lateral movement or staging.
// MITRE ATT&CK TTP ID: T1105

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_command_line contains "cloudflare"
        or action_process_image_command_line contains "trycloudflare.com"
    )
    and (
        action_process_image_command_line contains "webdav"
        or action_process_image_command_line contains "net use"
        or action_process_image_command_line contains "\\\\"
    )
    and (
        action_process_image_name = "cmd.exe"
        or action_process_image_name = "powershell.exe"
        or action_process_image_name = "wscript.exe"
        or action_process_image_name = "cscript.exe"
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, event_id, agent_id, _product
| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute command shells or scripting engines.
- **Required Artifacts:** Process creation logs, command-line arguments, and network connection records.

---

## Considerations

- Review the source and context of the process and command line for legitimacy.
- Correlate with user activity, email, or download logs to determine if the activity is user-initiated or automated.
- Investigate any network connections to Cloudflare Tunnel domains for signs of malicious payload delivery or lateral movement.
- Validate if the remote URL or WebDAV share is associated with known malicious infrastructure or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Users or IT staff legitimately use WebDAV or Cloudflare Tunnel for remote access or file transfer.
- Automated tools or scripts generate and execute these commands for benign purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Analyze network connections to Cloudflare Tunnel domains and WebDAV shares.
3. Review user activity and system logs for signs of compromise or lateral movement.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious Cloudflare Tunnel domains and WebDAV shares.

---

## References

- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Securonix: Analyzing SERPENTINE#CLOUD Threat Actors Abuse Cloudflare Tunnels](https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-30 | Initial Detection | Created comprehensive hunt query for Cloudflare Tunnel WebDAV activity across multiple processes |
