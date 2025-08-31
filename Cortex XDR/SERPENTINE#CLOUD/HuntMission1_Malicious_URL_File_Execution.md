# Detection of Windows Internet Shortcut (.url) Files with Suspicious Remote URLs

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-URLFile-Cloudflare
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of Windows Internet Shortcut (`.url`) files that reference suspicious or remote URLs, with a focus on those leveraging Cloudflare Tunnel infrastructure (e.g., `*.trycloudflare.com`). Such activity is indicative of early-stage SERPENTINE#CLOUD operations, where threat actors use `.url` files to lure users into launching remote payloads. Detected behaviors include:

- Execution of `.url` files containing remote URLs
- Command lines referencing Cloudflare Tunnel domains or other suspicious remote resources
- Parent process relationships with `explorer.exe` (user-initiated execution)

These techniques are commonly associated with phishing, initial access, and remote payload delivery.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                |
| TA0001 - Initial Access      | T1566.001   | —            | Phishing: Spearphishing Attachment            |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |

---

## Hunt Query Logic

This query identifies suspicious executions of `.url` files by looking for:

- Process executions where the file name matches `url.exe` or the parent process is `explorer.exe`
- Command lines containing remote URLs, especially those referencing Cloudflare Tunnel domains (`*.trycloudflare.com`)
- Command lines referencing `.url` files

These patterns are indicative of user-initiated execution of potentially malicious Internet Shortcut files.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
// Title: Suspicious URL Shortcut Execution via url.exe or explorer.exe
// Description: Detects processes where url.exe or explorer.exe are used to execute .url files with command lines referencing HTTP or Cloudflare, which may indicate shortcut-based delivery or execution of remote content.
// MITRE ATT&CK TTP ID: T1204

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
    and event_sub_type = ENUM.PROCESS_START 
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name = "url.exe"
        or actor_process_image_name = "explorer.exe"
    )
    and (
        actor_process_command_line contains "http"
        or actor_process_command_line contains "cloudflare"
        or actor_process_command_line contains "trycloudflare.com"
    )
    and actor_process_command_line contains ".url"
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User must be able to execute `.url` files (default on Windows systems).
- **Required Artifacts:** Process creation logs, command-line arguments, and file access records.

---

## Considerations

- Review the source and content of the `.url` file for legitimacy.
- Correlate with email or messaging logs to determine if the file was delivered via phishing.
- Investigate any network connections initiated as a result of the `.url` file execution.
- Validate if the remote URL is associated with known malicious infrastructure or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Users legitimately use `.url` files to access remote resources (e.g., internal web apps).
- Automated tools or scripts generate and execute `.url` files for benign purposes.

---

## Recommended Response Actions

1. Investigate the source and intent of the `.url` file.
2. Analyze the remote URL for reputation and threat intelligence matches.
3. Review user activity and email logs for signs of phishing or social engineering.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious Cloudflare Tunnel domains.

---

## References

- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1566.001 – Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Securonix: Analyzing SERPENTINE#CLOUD Threat Actors Abuse Cloudflare Tunnels](https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-30 | Initial Detection | Created hunt query to detect suspicious `.url` file executions leveraging Cloudflare tunnels |
