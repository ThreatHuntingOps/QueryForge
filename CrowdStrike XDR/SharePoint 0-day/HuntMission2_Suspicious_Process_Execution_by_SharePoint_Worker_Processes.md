# Detection of Suspicious Process Execution by SharePoint Worker Processes

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-SharePoint-SuspiciousChildProcess
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects abnormal child process creation from SharePoint IIS worker processes (`w3wp.exe`). Such behavior is highly suspicious and often associated with webshell activity or post-exploitation actions, including credential dumping, key exfiltration, or the execution of attacker-controlled scripts. Legitimate SharePoint operations rarely require spawning processes like `powershell.exe`, `cmd.exe`, `certutil.exe`, or `rundll32.exe` with arguments referencing keys, dumps, exfiltration, or known webshell filenames. Detection of these patterns should be treated as a high-priority incident.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution            | T1059.001   | —            | Command and Scripting Interpreter: PowerShell          |
| TA0002 - Execution            | T1216       | —            | System Script Proxy Execution                          |
| TA0006 - Credential Access    | T1003       | —            | OS Credential Dumping                                  |

---

## Hunt Query Logic

This query identifies suspicious child processes spawned by `w3wp.exe` (the SharePoint IIS worker process). It focuses on the creation of `powershell.exe`, `cmd.exe`, `certutil.exe`, or `rundll32.exe` with command-line arguments containing keywords such as `key`, `dump`, `exfil`, or references to known webshell files. These patterns are indicative of post-exploitation activity, credential access, or data exfiltration attempts.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=/ProcessRollup2|SyntheticProcessRollup2|FileCreateInfo/
| (ParentBaseFileName = "w3wp.exe")
| (FileName = "powershell.exe" OR FileName = "cmd.exe" OR FileName = "certutil.exe" OR FileName = "rundll32.exe")
| (CommandLine = "*key*" OR CommandLine = "*dump*" OR CommandLine = "*exfil*" OR CommandLine = "*spinstall0.aspx*" OR CommandLine = "*spkeydump.aspx*")
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |
| Falcon       | SyntheticProcessRollup2  | Process            | Process Creation      |
| Falcon       | FileCreateInfo           | File               | File Creation         |

---

## Execution Requirements

- **Required Permissions:** Attacker must have achieved code execution within the SharePoint IIS worker process context.
- **Required Artifacts:** Process creation logs, command-line arguments, parent-child process relationships.

---

## Considerations

- Investigate the full command line and process tree for context around the suspicious process.
- Correlate with recent file creation events, especially ASPX webshell deployments.
- Review user accounts and privileges associated with the `w3wp.exe` process.
- Check for signs of credential dumping or data exfiltration.

---

## False Positives

False positives are rare but may occur if:

- SharePoint administrators or maintenance scripts legitimately invoke these processes for troubleshooting or updates.
- Security or backup tools run under the `w3wp.exe` context and use these binaries for legitimate purposes.

Validate the process context, command-line arguments, and recent server activity to reduce false positives.

---

## Recommended Response Actions

1. Isolate the affected SharePoint server if malicious activity is confirmed.
2. Analyze the suspicious process and its command-line arguments for evidence of credential dumping or exfiltration.
3. Review related file and network activity for further signs of compromise.
4. Patch SharePoint and underlying Windows systems to remediate exploited vulnerabilities.
5. Monitor for additional suspicious process creation or webshell activity.

---

## References

- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1216 – System Script Proxy Execution](https://attack.mitre.org/techniques/T1216/)
- [MITRE ATT&CK: T1003 – OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-22 | Initial Detection | Created hunt query to detect suspicious process execution by SharePoint worker processes    |
