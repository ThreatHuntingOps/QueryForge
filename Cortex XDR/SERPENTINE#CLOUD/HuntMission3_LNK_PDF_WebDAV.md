# Detection of LNK Shortcut Files with PDF Icons Executing Suspicious Commands

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-LNK-PDF-WebDAV
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of LNK shortcut (`.lnk`) files that are disguised as PDF documents and execute suspicious commands via `cmd.exe`. These LNK files represent a sophisticated evolution in SERPENTINE#CLOUD tactics, using PDF icons and names to lure users, then leveraging `cmd.exe` to retrieve additional payloads over WebDAV or Cloudflare Tunnel infrastructure. Detected behaviors include:

- Execution of `.lnk` files with PDF-related names or icons
- Use of `cmd.exe` with `/c` or `/k` switches to run further commands
- Command lines referencing WebDAV, Cloudflare Tunnel domains, `.wsf` or `.bat` files, or network share commands (`net use`)
- Parent process relationships with `explorer.exe` (user-initiated execution)

These techniques are commonly associated with phishing, masquerading, remote payload delivery, and lateral movement.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                |
| TA0005 - Defense Evasion     | T1036.002   | —            | Masquerading: Right-to-Left Override          |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |
| TA0008 - Lateral Movement    | T1021.002   | —            | Remote Services: SMB/Windows Admin Shares     |

---

## Hunt Query Logic

This query identifies suspicious executions of LNK files masquerading as PDF documents by looking for:

- Parent process names ending in `.lnk` or process names matching `cmd.exe`
- Command lines using `/c` or `/k` switches
- Command lines referencing WebDAV, Cloudflare Tunnel domains, `.wsf` or `.bat` files, or network share commands
- Command lines or image file names containing `pdf`, with `cmd.exe` launched by `explorer.exe`

These patterns are indicative of LNK files crafted to appear as PDF documents but used to launch multi-stage payloads.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Suspicious LNK or CMD Launch with WebDAV/Cloudflare/Script/Batch Indicators
// Description: Detects processes launched via .lnk files or cmd.exe with command lines containing WebDAV, Cloudflare, script, or batch indicators, and with PDF or explorer.exe context, which may indicate shortcut-based or staged attacks.
// MITRE ATT&CK TTP ID: T1204

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        causality_actor_process_image_name contains ".lnk"
        or action_process_image_name = "cmd.exe"
    )
    and (
        action_process_image_command_line contains "/c"
        or action_process_image_command_line contains "/k"
    )
    and (
        action_process_image_command_line contains "webdav"
        or action_process_image_command_line contains "cloudflare"
        or action_process_image_command_line contains "trycloudflare.com"
        or action_process_image_command_line contains "net use"
        or action_process_image_command_line contains ".wsf"
        or action_process_image_command_line contains ".bat"
    )
    and (
        action_process_image_command_line contains "pdf"
        or (
            action_process_image_path contains "/cmd.exe"
            and causality_actor_process_image_path contains "/explorer.exe"
        )
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, causality_actor_process_image_name, causality_actor_process_image_path, causality_actor_process_command_line, event_id, agent_id, _product
| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User must be able to execute LNK files (default on Windows systems).
- **Required Artifacts:** Process creation logs, command-line arguments, file access records, and shortcut file metadata.

---

## Considerations

- Review the source and content of the LNK file for legitimacy and icon/filename masquerading.
- Correlate with email or download logs to determine if the file was delivered via phishing or social engineering.
- Investigate any network connections initiated as a result of the LNK file execution.
- Validate if the remote URL or WebDAV share is associated with known malicious infrastructure or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Users legitimately use LNK files with PDF icons for automation or document access.
- Automated tools or scripts generate and execute LNK files for benign purposes.

---

## Recommended Response Actions

1. Investigate the source and intent of the LNK file and its associated commands.
2. Analyze the command line for WebDAV, Cloudflare Tunnel, or script references.
3. Review user activity and email/download logs for signs of phishing or masquerading.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious WebDAV shares and Cloudflare Tunnel domains.

---

## References

- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1036.002 – Masquerading: Right-to-Left Override](https://attack.mitre.org/techniques/T1036/002/)
- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [Securonix: Analyzing SERPENTINE#CLOUD Threat Actors Abuse Cloudflare Tunnels](https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-30 | Initial Detection | Created hunt query to detect LNK shortcut files with PDF icons executing suspicious commands |
