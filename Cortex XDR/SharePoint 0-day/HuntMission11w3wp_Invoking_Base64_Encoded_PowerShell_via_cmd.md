# Detection of w3wp.exe Invoking Base64 Encoded PowerShell via cmd.exe

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-SharePoint-w3wp-Base64Powershell
- **Operating Systems:** WindowsServer, SharePoint
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the IIS worker process (`w3wp.exe`) spawning a command shell (`cmd.exe`), which then launches PowerShell with a base64-encoded command. This behavior is a strong indicator of post-exploitation activity, as attackers often use encoded PowerShell to execute obfuscated payloads and evade detection. While not specific to any single CVE, this pattern is commonly observed in webshell and exploitation scenarios on SharePoint and other IIS-hosted applications.

Detected behaviors include:

- `w3wp.exe` spawning `cmd.exe`, which launches `powershell.exe` with a base64-encoded command
- Use of regular expressions to match base64-encoded payloads in the PowerShell command line
- Collection of process chain and command line context for investigation

These patterns are indicative of remote code execution, persistence, and attacker tooling on SharePoint servers.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059.001   | —            | Command and Scripting Interpreter: PowerShell  |
| TA0008 - Persistence         | T1505.003   | —            | Server Software Component: Web Shell           |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell |

---

## Hunt Query Logic

This query identifies suspicious process chains by looking for:

- Process creation events where `w3wp.exe` spawns `cmd.exe`, which launches `powershell.exe`
- PowerShell command lines matching a base64-encoded payload pattern
- Relevant metadata such as timestamp, process names, command lines, and parent/child process relationships

These patterns are indicative of attempts to execute obfuscated or malicious payloads via PowerShell from a webshell context.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Description: This query identifies the IIS Process Worker, w3wp invoking a command shell which executes a base64 encoded PowerShell command. This is not specific to the CVE, and may catch potential other post-exploitation activity.
dataset = xdr_data 
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and lowercase(causality_actor_process_image_name) = "w3wp.exe" and lowercase(actor_process_image_name) = "cmd.exe" and lowercase(action_process_image_name) = "powershell.exe" and action_process_image_command_line  ~= "(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)"
| fields _time, agent_hostname, causality_actor_process_image_name, actor_process_image_name, actor_process_command_line, action_process_image_name, action_process_image_command_line , event_type, event_sub_type 
```

---

## Data Sources

| Log Provider   | Event Name   | ATT&CK Data Source | ATT&CK Data Component |
|---------------|--------------|--------------------|-----------------------|
| Cortex XSIAM  | xdr_data     | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** Ability to collect and analyze process creation logs from SharePoint servers.
- **Required Artifacts:** Process creation event logs, command-line arguments, parent/child process relationships.

---

## Considerations

- Review the full process chain and command line for evidence of obfuscated or malicious payloads.
- Correlate with network and file creation logs for signs of exploitation or persistence.
- Investigate any follow-on activity from the same host or user account.
- Validate if the SharePoint instance is patched for known vulnerabilities.

---

## False Positives

False positives are unlikely but may occur if:

- Legitimate administrative scripts use encoded PowerShell for automation or configuration.
- Security tools or monitoring solutions leverage encoded commands for benign purposes.

---

## Recommended Response Actions

1. Investigate the process chain and command line for evidence of obfuscation or malicious intent.
2. Decode and analyze the base64-encoded payload.
3. Remove any malicious payloads and perform a full forensic analysis.
4. Apply security patches for any relevant vulnerabilities.
5. Monitor for additional suspicious activity or persistence mechanisms.

---

## References

- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1505.003 – Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-22 | Initial Detection | Created hunt query to detect w3wp.exe invoking base64 encoded PowerShell via cmd.exe |
