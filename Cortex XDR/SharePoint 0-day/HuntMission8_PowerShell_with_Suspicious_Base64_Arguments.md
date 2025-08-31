# Detection of PowerShell with Suspicious Base64 Arguments

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-PowerShell-SuspiciousBase64
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects PowerShell processes that use long, suspicious base64-encoded arguments, which are often used to obfuscate or deliver malicious payloads. Attackers frequently leverage PowerShell's `-EncodedCommand` (or `-ec`) parameter to bypass detection and execute hidden commands on compromised systems. The presence of lengthy base64 strings in PowerShell command lines is a strong indicator of obfuscation and potential malicious activity.

Detected behaviors include:

- PowerShell processes with command lines containing `EncodedCommand` or `-ec`
- Extraction of long base64-encoded strings from the command line
- Evidence of obfuscated or hidden payloads

These patterns are indicative of command and scripting interpreter abuse and obfuscation techniques.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059.001   | —            | Command and Scripting Interpreter: PowerShell  |
| TA0005 - Defense Evasion     | T1027       | —            | Obfuscated Files or Information                |

---

## Hunt Query Logic

This query identifies suspicious PowerShell usage by looking for:

- Process creation events for `powershell.exe`
- Command lines containing `EncodedCommand` or `-ec`
- Extraction of long base64-encoded strings (15+ characters) from the command line
- Relevant metadata such as timestamp, process name, command line, and parent process

These patterns are indicative of attempts to execute obfuscated or malicious payloads via PowerShell.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Detection of PowerShell with Suspicious Base64 Arguments
// Description: Detects PowerShell processes with long, suspicious base64-encoded arguments, which may indicate obfuscated or malicious payloads.
// MITRE ATT&CK TTP IDs: T1059.001, T1027

dataset = xdr_data    
| filter event_type = ENUM.PROCESS    
| filter actor_process_image_name = "powershell.exe"    
| filter (action_process_image_command_line contains "EncodedCommand" or action_process_image_command_line contains "-ec")    
| alter extension = regextract(action_process_image_command_line, "[A-Za-z0-9+/=]{15,}") 
| fields event_timestamp, actor_process_image_name, action_process_image_command_line , causality_actor_process_image_name 
```

---

## Data Sources

| Log Provider   | Event Name   | ATT&CK Data Source | ATT&CK Data Component |
|---------------|--------------|--------------------|-----------------------|
| Cortex XSIAM  | xdr_data     | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** Ability to collect and analyze process creation logs from endpoints and servers.
- **Required Artifacts:** Process creation event logs, command-line arguments, parent/child process relationships.

---

## Considerations

- Review the full command line and extracted base64 string for evidence of obfuscated or malicious payloads.
- Correlate with network and file creation logs for signs of exploitation or persistence.
- Investigate any follow-on activity from the same host or user account.
- Validate if the endpoint or server is patched for known vulnerabilities.

---

## False Positives

False positives may occur if:

- Legitimate administrative scripts use encoded PowerShell for automation or configuration.
- Security tools or monitoring solutions leverage encoded commands for benign purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for evidence of obfuscation or malicious intent.
2. Decode and analyze the base64-encoded payload.
3. Remove any malicious payloads and perform a full forensic analysis.
4. Apply security patches for any relevant vulnerabilities.
5. Monitor for additional suspicious activity or persistence mechanisms.

---

## References

- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Microsoft Security Blog: Disrupting Active Exploitation of On-Premises SharePoint Vulnerabilities (July 22, 2025)](https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/)
- [Unit 42: Microsoft SharePoint CVE-2025-49704, CVE-2025-49706, CVE-2025-53770 Analysis](https://unit42.paloaltonetworks.com/microsoft-sharepoint-cve-2025-49704-cve-2025-49706-cve-2025-53770/)
- [Eye Security: SharePoint Under Siege](https://research.eye.security/sharepoint-under-siege/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-21 | Initial Detection | Created hunt query to detect PowerShell with suspicious base64 arguments |
