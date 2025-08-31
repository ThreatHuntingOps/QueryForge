# Detection of Windows Script File (WSF) Execution with Network Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WSF-Network
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of Windows Script Files (`.wsf`) using `wscript.exe` or `cscript.exe` that exhibit network activity, such as contacting Cloudflare Tunnel domains, WebDAV shares, or making HTTP requests. This behavior is characteristic of the dropper chain in SERPENTINE#CLOUD operations, where WSF scripts are used to download or execute additional payloads. Detected behaviors include:

- Execution of `.wsf` files via `wscript.exe` or `cscript.exe`
- Command lines referencing Cloudflare Tunnel domains, WebDAV, or HTTP URLs
- Network communications or file operations initiated by the script

These techniques are commonly associated with initial access, remote payload delivery, and lateral movement.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059.005   | —            | Command and Scripting Interpreter: Visual Basic|
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                |

---

## Hunt Query Logic

This query identifies suspicious executions of WSF scripts by looking for:

- Process executions where the file name matches `wscript.exe` or `cscript.exe`
- Command lines referencing `.wsf` files
- Command lines containing Cloudflare Tunnel domains, WebDAV, or HTTP URLs

These patterns are indicative of WSF scripts used as part of a multi-stage dropper chain.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
// Title: Suspicious WScript or CScript Execution of .wsf with Network Indicators
// Description: Detects wscript.exe or cscript.exe executing .wsf files with command lines referencing Cloudflare, WebDAV, or HTTP, which may indicate script-based download or staging activity.
// MITRE ATT&CK TTP ID: T1059.005

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name = "wscript.exe"
        or action_process_image_name = "cscript.exe"
    )
    and action_process_image_command_line contains ".wsf"
    and (
        action_process_image_command_line contains "cloudflare"
        or action_process_image_command_line contains "trycloudflare.com"
        or action_process_image_command_line contains "webdav"
        or action_process_image_command_line contains "http"
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

- **Required Permissions:** User must be able to execute WSF scripts (default on Windows systems).
- **Required Artifacts:** Process creation logs, command-line arguments, file access records, and script content.

---

## Considerations

- Review the source and content of the WSF script for legitimacy and network operations.
- Correlate with email or download logs to determine if the script was delivered via phishing or social engineering.
- Investigate any network connections initiated as a result of the WSF script execution.
- Validate if the remote URL or WebDAV share is associated with known malicious infrastructure or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Users legitimately use WSF scripts for automation or IT support that require network access.
- Automated tools or scripts generate and execute WSF files for benign purposes.

---

## Recommended Response Actions

1. Investigate the source and intent of the WSF script and its associated network activity.
2. Analyze the command line for Cloudflare Tunnel, WebDAV, or HTTP references.
3. Review user activity and email/download logs for signs of phishing or social engineering.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious WebDAV shares and Cloudflare Tunnel domains.

---

## References

- [MITRE ATT&CK: T1059.005 – Command and Scripting Interpreter: Visual Basic](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [Securonix: Analyzing SERPENTINE#CLOUD Threat Actors Abuse Cloudflare Tunnels](https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-30 | Initial Detection | Created hunt query to detect WSF script execution with network activity in SERPENTINE#CLOUD context |
