# Detection of Malicious SharePoint Webshell File Creation by PowerShell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 92
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-SharePoint-WebshellByPowerShell
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects the creation or modification of known malicious files (such as `spinstall0.aspx` or `debug_dev.js`) in SharePoint application directories by `powershell.exe`. This behavior is a strong indicator of exploitation, as attackers often use PowerShell to deploy webshells or malicious scripts during post-exploitation. The query focuses on specific file paths and filenames observed in recent SharePoint attacks, making detection highly targeted and actionable.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution            | T1059.001   | —            | Command and Scripting Interpreter: PowerShell          |
| TA0003 - Persistence          | T1505.003   | —            | Server Software Component: Web Shell                   |
| TA0005 - Defense Evasion      | T1036.005   | —            | Masquerading: Match Legitimate Name or Location        |

---

## Hunt Query Logic

This query identifies file creation or modification events for `spinstall0.aspx` or `debug_dev.js` in critical SharePoint directories, specifically when the parent process is `powershell.exe`. Such activity is rarely legitimate and is a hallmark of webshell deployment or script-based exploitation.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=/ProcessRollup2|SyntheticProcessRollup2|FileCreateInfo/  
| (FileName = "spinstall0.aspx" OR FileName = "debug_dev.js")   
| (FilePath = "\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\16\\TEMPLATE\\LAYOUTS\\spinstall0.aspx" OR FilePath = "\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\15\\TEMPLATE\\LAYOUTS\\spinstall0.aspx" OR FilePath = "\\Program Files\\Common Files\\Microsoft Shared\\Web Server Extensions\\16\\TEMPLATE\\LAYOUTS\\debug_dev.js")   
| (ParentBaseFileName = "powershell.exe")   
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

- **Required Permissions:** Attacker must have the ability to execute PowerShell and write files to SharePoint application directories.
- **Required Artifacts:** File creation logs, process creation logs, parent-child process relationships.

---

## Considerations

- Investigate the full PowerShell command line and script content for additional context.
- Correlate with other suspicious activity on the server, such as webshell access or outbound network connections.
- Review recent user activity and privilege escalation events.

---

## False Positives

False positives are extremely rare but may occur if:

- Administrators or legitimate scripts deploy or update these files for testing or maintenance (should be validated and documented).

Validate the process context, file hash, and associated user activity to reduce false positives.

---

## Recommended Response Actions

1. Isolate the affected SharePoint server if malicious file creation is confirmed.
2. Retrieve and analyze the suspicious file(s) for webshell or malicious code.
3. Review PowerShell logs and command-line arguments for evidence of exploitation.
4. Patch SharePoint and underlying systems to remediate vulnerabilities.
5. Monitor for additional suspicious file or process activity.

---

## References

- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1505.003 – Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK: T1036.005 – Masquerading](https://attack.mitre.org/techniques/T1036/005/)
- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-22 | Initial Detection | Created hunt query to detect malicious SharePoint webshell file creation by PowerShell      |
