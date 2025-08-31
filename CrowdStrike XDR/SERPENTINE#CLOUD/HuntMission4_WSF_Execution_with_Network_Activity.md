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

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2     
| (FileName = /wscript\.exe/i OR FileName = /cscript\.exe/i)    
| CommandLine = "*.wsf*"    
| (CommandLine = "*cloudflare*" OR CommandLine = "*.trycloudflare.com*" OR CommandLine = "*webdav*" OR CommandLine = "*http*") 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

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
