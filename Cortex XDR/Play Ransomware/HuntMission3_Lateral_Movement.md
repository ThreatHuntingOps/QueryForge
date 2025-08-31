# Detection of Cobalt Strike, PsExec, Mimikatz, and GPO Abuse in Play Ransomware Activity

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Cortex-PlayRansomware-LateralMovement
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects lateral movement and credential theft behaviors consistent with Play ransomware intrusions. It focuses on the use of PsExec, Cobalt Strike, SystemBC, WinPEAS, and Mimikatz, as well as suspicious Group Policy Object (GPO)-based binary distribution. These behaviors typically follow initial compromise and are aimed at escalating privileges, executing payloads, and deploying ransomware across the network.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                            |
|-------------------------------|-------------|--------------|----------------------------------------------------------|
| TA0008 - Lateral Movement     | T1075.001   | —            | Pass the Hash (PsExec via ADMIN$ shares)                 |
| TA0006 - Credential Access    | T1003       | —            | OS Credential Dumping (Mimikatz)                         |
| TA0006 - Credential Access    | T1552       | —            | Unsecured Credentials                                    |
| TA0002 - Execution            | T1059       | —            | Command and Scripting Interpreter (WinPEAS)              |
| TA0011 - Command and Control  | T1105       | —            | Ingress Tool Transfer (Cobalt Strike, SystemBC)          |
| TA0004 - Privilege Escalation | T1484.001   | —            | Domain Policy Modification: Group Policy Modification    |
| TA0008 - Lateral Movement     | T1570       | —            | Lateral Tool Transfer (via GPO or SMB)                   |

---

## Hunt Query Logic

This query identifies suspicious process activity related to Play ransomware lateral movement and credential access:

- Command lines referencing PsExec, ADMIN$ shares, Cobalt Strike, SystemBC, WinPEAS, or Mimikatz
- GPO or Group Policy-related command lines, or references to SYSVOL/NETLOGON shares
- Additional credential or privilege enumeration commands (whoami, ipconfig, net user, net localgroup, privileges, token)
- Parent process is `cmd.exe` or `powershell.exe`

These patterns are commonly seen in post-compromise privilege escalation, lateral movement, and ransomware deployment.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Cortex XSIAM

```xql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = PROCESS
| filter actor_process_command_line contains "psexec"
    or actor_process_command_line contains "\\ADMIN$"
    or actor_process_command_line contains "cobaltstrike"
    or actor_process_command_line contains "beacon"
    or actor_process_command_line contains "winpeas"
    or actor_process_command_line contains "mimikatz"
    or actor_process_command_line contains "sekurlsa::logonpasswords"
    or actor_process_command_line contains "Invoke-Mimikatz"
    or actor_process_command_line contains "systembc"
| filter actor_process_command_line contains "gpo"
    or actor_process_command_line contains "GroupPolicy"
    or actor_process_command_line contains "\\sysvol\\"
    or actor_process_command_line contains "\\netlogon\\"
| filter actor_process_command_line contains "whoami"
    or actor_process_command_line contains "ipconfig"
    or actor_process_command_line contains "net user"
    or actor_process_command_line contains "net localgroup"
    or actor_process_command_line contains "privileges"
    or actor_process_command_line contains "token"
| filter actor_process_image_name contains "cmd.exe"
    or actor_process_image_name contains "powershell.exe"
| fields agent_hostname, actor_process_command_line, actor_process_image_name, event_timestamp
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM | xdr_data           | Process             | Process Creation     |

---

## Execution Requirements

- **Required Permissions:** Ability to collect process execution events from Windows endpoints.
- **Required Artifacts:** Process execution logs, command line arguments, parent/child process relationships.

---

## Considerations

- Investigate the process tree and command line for evidence of lateral movement or credential access tools.
- Validate the user context and parent process for additional signs of compromise.
- Correlate with other suspicious behaviors, such as privilege escalation or ransomware deployment.

---

## False Positives

False positives may occur if:
- Legitimate administrative or security tools use similar command lines or file paths.
- Internal IT scripts or software deployment tools invoke these tools for benign reasons.

---

## Recommended Response Actions

1. Investigate the process tree and command line for malicious indicators.
2. Validate the legitimacy of the tool or script and its source.
3. Review related process activity and user context.
4. Isolate affected systems if malicious activity is confirmed.

---

## References

- [MITRE ATT&CK: T1075.001 – Pass the Hash](https://attack.mitre.org/techniques/T1075/001/)
- [MITRE ATT&CK: T1003 – OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK: T1552 – Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [MITRE ATT&CK: T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1484.001 – Group Policy Modification](https://attack.mitre.org/techniques/T1484/001/)
- [MITRE ATT&CK: T1570 – Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [#StopRansomware: Play Ransomware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-06-10 | Initial Detection | Created hunt query to detect Play ransomware lateral movement and credential access tools   |
