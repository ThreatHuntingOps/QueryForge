# Detection of Suspicious ASPX Webshell Deployment on SharePoint Servers

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-SharePoint-ASPXWebshell
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Low to Medium

---

## Hunt Analytics

This hunt detects the creation of suspicious ASPX files (such as `spinstall0.aspx`, `spkeydump.aspx`, or any `.aspx` file) within critical SharePoint application directories. These file creation events are a strong indicator of webshell deployment, a common initial access and persistence technique used by threat actors exploiting SharePoint vulnerabilities. Malicious ASPX webshells enable remote command execution, lateral movement, and data exfiltration, and are frequently observed in targeted attacks against enterprise environments.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution            | T1059.007   | —            | Command and Scripting Interpreter: ASP/JSP             |
| TA0009 - Collection           | T1505.003   | —            | Server Software Component: Web Shell                   |
| TA0011 - Command and Control  | T1105       | —            | Ingress Tool Transfer                                  |

---

## Hunt Query Logic

This query identifies the creation of ASPX files in SharePoint application directories, focusing on known webshell filenames and any `.aspx` file. It further filters for files with a SHA256 hash, indicating a new file written to disk. The logic is designed to catch both known and novel webshell deployments, as attackers may use custom or obfuscated filenames.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
 ##event_simpleName=/ProcessRollup2|SyntheticProcessRollup2|FileCreateInfo/     
| (FileName = /spinstall0\.aspx/i OR FileName = /spkeydump\.aspx/i OR FileName = /\.aspx$/i)      
| (FilePath = "*\\Program Files\\Microsoft Shared\\Web Server Extensions\\15\\*" OR FilePath = "*\\inetpub\\wwwroot\\wss\\VirtualDirectories\\*")      
| (SHA256HashData IS NOT NULL) 
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | FileCreateInfo           | File               | File Creation         |
| Falcon       | ProcessRollup2           | Process            | Process Creation      |
| Falcon       | SyntheticProcessRollup2  | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** Attacker must have permissions to write files to SharePoint application directories (typically requires elevated privileges).
- **Required Artifacts:** File creation logs, file hash data, SharePoint server file system access.

---

## Considerations

- Review the SHA256 hash of detected ASPX files against threat intelligence sources and known webshell repositories.
- Investigate the parent process responsible for file creation to determine if it is a legitimate SharePoint process or a suspicious process (e.g., `w3wp.exe`, `powershell.exe`).
- Correlate with recent SharePoint vulnerability advisories and patch status.
- Check for outbound network connections or command execution from the detected ASPX files.

---

## False Positives

False positives may occur if:

- SharePoint administrators or legitimate processes deploy custom ASPX pages for business or maintenance purposes.
- Security tools or monitoring solutions generate test ASPX files in these directories.

To reduce false positives, validate the file's origin, hash, and associated process context.

---

## Recommended Response Actions

1. Isolate the affected SharePoint server from the network if malicious activity is confirmed.
2. Retrieve and analyze the suspicious ASPX file(s) for webshell code or backdoors.
3. Review recent user and process activity on the server for signs of exploitation or lateral movement.
4. Patch all SharePoint vulnerabilities and review server hardening configurations.
5. Monitor for additional suspicious file creation or network activity.

---

## References

- [MITRE ATT&CK: T1505.003 – Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK: T1059.007 – ASP/JSP](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-22 | Initial Detection | Created hunt query to detect suspicious ASPX webshell deployment on SharePoint servers      |
