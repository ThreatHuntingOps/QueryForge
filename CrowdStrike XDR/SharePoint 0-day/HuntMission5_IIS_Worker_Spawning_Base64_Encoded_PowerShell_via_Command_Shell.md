# Detection of IIS Worker Spawning Base64-Encoded PowerShell via Command Shell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 94
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-SharePoint-IISBase64PowerShell
- **Operating Systems:** WindowsServer
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects instances where the IIS worker process (`w3wp.exe`) spawns `cmd.exe`, which then launches `powershell.exe` with a base64-encoded command. This process chain is a strong indicator of webshell activity or post-exploitation on vulnerable SharePoint servers. Attackers commonly use this technique to obfuscate their payloads and evade detection, leveraging encoded PowerShell commands to execute malicious actions under the context of the IIS worker process.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                         |
|------------------------------|-------------|--------------|--------------------------------------------------------|
| TA0002 - Execution            | T1059.001   | —            | Command and Scripting Interpreter: PowerShell          |
| TA0005 - Defense Evasion      | T1027       | —            | Obfuscated Files or Information                        |
| TA0002 - Execution            | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell|

---

## Hunt Query Logic

This query identifies PowerShell processes started by `cmd.exe` (with `w3wp.exe` as the grandparent), where the command line includes `-enc` or `-encodedcommand` and a base64-encoded payload. This pattern is highly suspicious and rarely seen in legitimate SharePoint operations, making it a strong indicator of webshell or attacker activity.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2
| (ParentBaseFileName = "cmd.exe")
| (GrandParentBaseFileName = "w3wp.exe")
| (FileName = "powershell.exe")
| (CommandLine = "*-enc*" OR CommandLine = "*-encodedcommand*")
| (CommandLine = "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)")
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** Attacker must have achieved code execution within the SharePoint IIS worker process context and be able to launch PowerShell via command shell.
- **Required Artifacts:** Process creation logs, command-line arguments, process ancestry.

---

## Considerations

- Investigate the decoded base64 payload for malicious content or further indicators of compromise.
- Correlate with other suspicious process or file creation events on the SharePoint server.
- Review user accounts and privileges associated with the process chain.

---

## False Positives

False positives are extremely rare but may occur if:

- Administrators or automation scripts use encoded PowerShell for legitimate maintenance (should be validated and documented).

Validate the process context, command-line content, and associated user activity to reduce false positives.

---

## Recommended Response Actions

1. Decode and analyze the PowerShell payload for malicious intent.
2. Investigate the process tree and related activity for signs of exploitation.
3. Isolate the affected SharePoint server if malicious activity is confirmed.
4. Patch and harden SharePoint and underlying systems.
5. Monitor for additional encoded command execution or webshell activity.

---

## References

- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-22 | Initial Detection | Created hunt query to detect IIS worker spawning base64-encoded PowerShell via command shell |
