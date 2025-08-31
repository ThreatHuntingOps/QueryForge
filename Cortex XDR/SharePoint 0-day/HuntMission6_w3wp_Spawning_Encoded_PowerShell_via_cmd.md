# Detection of w3wp.exe Spawning Encoded PowerShell via cmd.exe

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-SharePoint-w3wp-EncodedPowershell
- **Operating Systems:** WindowsServer, SharePoint
- **False Positive Rate:** Very Low

---

## Hunt Analytics

This hunt detects suspicious process chains where the IIS worker process (`w3wp.exe`) spawns `cmd.exe`, which in turn launches PowerShell with encoded commands. This behavior is strongly associated with exploitation and webshell activity, as attackers often use encoded PowerShell to evade detection and execute malicious payloads on compromised SharePoint servers.

Detected behaviors include:

- `w3wp.exe` spawning `cmd.exe`, which then launches PowerShell
- PowerShell command lines containing `EncodedCommand` or `-ec` (indicating base64-encoded payloads)
- Evidence of process chaining and command execution from IIS context

These patterns are indicative of post-exploitation activity and remote code execution via webshells.

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

- Process creation events where `w3wp.exe` spawns `cmd.exe`
- Command lines containing both `powershell` and `cmd.exe`
- Use of `EncodedCommand` or `-ec` in PowerShell command lines
- Relevant metadata such as timestamp, hostname, process and parent process details

These patterns are indicative of attempts to execute encoded PowerShell payloads from a webshell context.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Detection of w3wp.exe Spawning Encoded PowerShell via cmd.exe
// Description: Detects suspicious process chains where w3wp.exe spawns cmd.exe, which launches PowerShell with encoded commands—behavior associated with exploitation and webshell activity.
// MITRE ATT&CK TTP IDs: T1059.001, T1505.003, T1059.003

dataset = xdr_data    
| filter event_type = ENUM.PROCESS   
| filter actor_process_image_name = "cmd.exe"    
| filter causality_actor_process_image_name = "w3wp.exe"    
| filter action_process_image_command_line contains "powershell"    
| filter action_process_image_command_line contains "cmd.exe"    
| filter (action_process_image_command_line contains "EncodedCommand" or action_process_image_command_line contains "-ec")    
| fields event_timestamp, agent_hostname, actor_process_image_name, action_process_image_command_line, causality_actor_process_image_name, causality_actor_process_command_line, causality_actor_process_image_name, causality_actor_process_command_line  
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

- Review the full process chain and command line for evidence of malicious payloads.
- Correlate with network and file creation logs for signs of exploitation or persistence.
- Investigate any follow-on activity from the same host or user account.
- Validate if the SharePoint instance is patched for known vulnerabilities.

---

## False Positives

False positives are extremely unlikely due to the specificity of the process chain and encoded PowerShell usage.

---

## Recommended Response Actions

1. Immediately isolate the affected server.
2. Investigate the process chain and command line for evidence of exploitation.
3. Remove any webshells or malicious payloads and perform a full forensic analysis.
4. Apply security patches for any relevant SharePoint vulnerabilities.
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
| 1.0     | 2025-07-21 | Initial Detection | Created hunt query to detect w3wp.exe spawning encoded PowerShell via cmd.exe |
