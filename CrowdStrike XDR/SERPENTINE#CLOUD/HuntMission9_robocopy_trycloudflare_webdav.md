# Detection of Robocopy Download from Cloudflare Tunnel WebDAV

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Robocopy-TryCloudflare-WebDAV
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the use of `robocopy.exe` to download files from a WebDAV share hosted on a `trycloudflare.com` subdomain. This technique is leveraged in SERPENTINE#CLOUD operations to stage and deliver malicious payloads via Cloudflare Tunnel infrastructure. Detected behaviors include:

- Execution of `robocopy.exe` with command lines referencing `trycloudflare.com@SSL\DavWWWRoot` (WebDAV over HTTPS)

These techniques are associated with remote payload delivery and command and control.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |
| TA0008 - Lateral Movement    | T1021.002   | —            | Remote Services: SMB/Windows Admin Shares     |

---

## Hunt Query Logic

This query identifies suspicious use of robocopy by looking for:

- Process name matching `robocopy.exe`
- Command lines referencing `trycloudflare.com@SSL\DavWWWRoot` (WebDAV over HTTPS)

These patterns are indicative of attempts to leverage Cloudflare Tunnel infrastructure for remote payload delivery.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2    
| (FileName = /robocopy\.exe/i)    
| CommandLine = "*trycloudflare.com@SSL\DavWWWRoot*" 
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute robocopy.
- **Required Artifacts:** Process creation logs, command-line arguments, and network connection records.

---

## Considerations

- Review the source and context of the robocopy command for legitimacy.
- Correlate with user activity, email, or download logs to determine if the activity is user-initiated or automated.
- Investigate any network connections to `trycloudflare.com` domains for signs of malicious payload delivery.
- Validate if the remote URL or WebDAV share is associated with known malicious infrastructure or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Users or IT staff legitimately use robocopy with Cloudflare Tunnel for remote access or file transfer.
- Automated tools or scripts generate and execute these commands for benign purposes.

---

## Recommended Response Actions

1. Investigate the robocopy process and command line for intent and legitimacy.
2. Analyze network connections to `trycloudflare.com` domains and WebDAV shares.
3. Review user activity and system logs for signs of compromise or C2.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious Cloudflare Tunnel domains and WebDAV shares.

---

## References

- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [Securonix: Analyzing SERPENTINE#CLOUD Threat Actors Abuse Cloudflare Tunnels](https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-01 | Initial Detection | Created hunt query to detect robocopy download from Cloudflare Tunnel WebDAV |
