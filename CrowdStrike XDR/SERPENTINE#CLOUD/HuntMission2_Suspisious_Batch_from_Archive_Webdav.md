# Detection of Batch Files Executed from ZIP Archives with WebDAV Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-BatchFromArchive-WebDAV
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of batch (`.bat`) files from temporary or ZIP extraction directories that contain WebDAV-related commands. This activity is characteristic of the low-effort batch file stage observed in SERPENTINE#CLOUD operations, where attackers use batch scripts delivered via ZIP archives to download and execute remote payloads over WebDAV, often leveraging Cloudflare Tunnel infrastructure. Detected behaviors include:

- Execution of `.bat` files from temporary or download directories
- Command lines referencing WebDAV, Cloudflare Tunnel domains, or network share commands (`net use`)
- Parent process relationships with `explorer.exe`, `winrar.exe`, or `7z.exe` (indicative of user extraction and execution)

These techniques are commonly associated with initial access, remote payload delivery, and lateral movement.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1204.002   | —            | User Execution: Malicious File                |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell |
| TA0011 - Command and Control | T1105       | —            | Ingress Tool Transfer                         |
| TA0008 - Lateral Movement    | T1021.002   | —            | Remote Services: SMB/Windows Admin Shares     |

---

## Hunt Query Logic

This query identifies suspicious executions of batch files by looking for:

- Process executions where the file name matches `cmd.exe` or ends with `.bat`
- File paths indicating execution from temporary, AppData, or Downloads directories
- Command lines containing WebDAV, Cloudflare Tunnel domains, or network share commands
- Parent processes associated with user-initiated archive extraction (`explorer.exe`, `winrar.exe`, `7z.exe`)

These patterns are indicative of batch files extracted from archives and used to launch remote payloads.

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language (CQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2     
| (FileName = /cmd\.exe/i OR FileName = /\.bat$/i)    
| (FilePath = "*\\Temp\\*" OR FilePath = "*\\AppData\\Local\\Temp\\*" OR FilePath = "*\\Downloads\\*")    
| (CommandLine = "*webdav*" OR CommandLine = "*cloudflare*" OR CommandLine = "*.trycloudflare.com*" OR CommandLine = "*net use*")    
| ParentBaseFileName = /explorer\.exe/i OR ParentBaseFileName = /winrar\.exe/i OR ParentBaseFileName = /7z\.exe/i  
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User must be able to extract and execute batch files from archives.
- **Required Artifacts:** Process creation logs, command-line arguments, file access records, and archive extraction logs.

---

## Considerations

- Review the source and content of the batch file for legitimacy.
- Correlate with email or download logs to determine if the file was delivered via phishing or drive-by download.
- Investigate any network connections initiated as a result of the batch file execution.
- Validate if the remote URL or WebDAV share is associated with known malicious infrastructure or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Users legitimately extract and run batch files for internal automation or IT support.
- Automated tools or scripts generate and execute batch files for benign purposes.

---

## Recommended Response Actions

1. Investigate the source and intent of the batch file and associated archive.
2. Analyze the command line for WebDAV or Cloudflare Tunnel references.
3. Review user activity and email/download logs for signs of phishing or social engineering.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious WebDAV shares and Cloudflare Tunnel domains.

---

## References

- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [Securonix: Analyzing SERPENTINE#CLOUD Threat Actors Abuse Cloudflare Tunnels](https://www.securonix.com/blog/analyzing_serpentinecloud-threat-actors-abuse-cloudflare-tunnels-threat-research/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-30 | Initial Detection | Created hunt query to detect suspicious batch file executions from ZIP archives with WebDAV activity |
