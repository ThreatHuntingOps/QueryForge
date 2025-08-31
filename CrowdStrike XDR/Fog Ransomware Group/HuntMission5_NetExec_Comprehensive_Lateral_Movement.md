# Detection of NetExec Lateral Movement with Credential Abuse and Remote Service Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-NetExec-Comprehensive-LateralMovement
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects a comprehensive sequence of malicious activities associated with NetExec (and CrackMapExec): failed authentication attempts (brute-force or password spraying), followed by successful SMB lateral movement, and possible remote service creation or execution via the `-x` switch. The query leverages process, authentication, and service start telemetry to uncover brute-force attacks, post-exploitation lateral movement, and remote command delivery across systems. These behaviors are strong indicators of credential abuse, lateral tool transfer, and remote execution in targeted attacks.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                              |
|------------------------------|-------------|--------------|-------------------------------------------------------------|
| TA0008 - Lateral Movement    | T1021.002   | —            | Remote Services: SMB/Windows Admin Shares                   |
| TA0008 - Lateral Movement    | T1569.002   | —            | System Services: Service Execution                          |
| TA0006 - Credential Access   | T1110.001   | —            | Brute Force: Password Guessing                              |
| TA0008 - Lateral Movement    | T1075       | —            | Lateral Tool Transfer                                       |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell     |
| TA0006 - Credential Access   | T1003.001   | —            | Credential Dumping: LSASS Memory                            |

---

## Hunt Query Logic

This query identifies:

- NetExec or CrackMapExec usage with command-line indicators for SMB, credentials, and remote execution
- Command-line arguments referencing admin shares (C$, ADMIN$, IPC$) and execution methods
- Parent process links to scripting engines or shells (Python, cmd.exe, PowerShell)
- Authentication failures tied to remote access attempts (SMB, port 445)
- Remote service starts, especially from temp/user paths, indicating remote command delivery

These patterns, when observed together, are rarely seen in legitimate administrative activity and are strong signals of credential abuse, brute-force attacks, and post-exploitation lateral movement.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2 OR #event_simpleName=AuthenticationSummary OR #event_simpleName=ServiceStart // Detect NetExec execution 
| ((FileName=/netexec/i OR FileName="netexec.exe" OR FileName=/crackmapexec/i) AND CommandLine="*smb*" AND CommandLine="*-u*" AND CommandLine="*-p*" AND CommandLine="*-x*") 
| (CommandLine="*\\C$*" OR CommandLine="*\\ADMIN$*" OR CommandLine="*\\IPC$*") 
| (CommandLine="*--exec-method*" OR CommandLine="*--local-auth*" OR CommandLine="*--share*") // Parent-child process linking (optional) 
| (ParentBaseFileName="python.exe" OR ParentBaseFileName="cmd.exe" OR ParentBaseFileName="powershell.exe") // Failed login attempts (brute-force or password spraying) 
| (#event_simpleName=AuthenticationSummary AND AuthenticationResult="FAILURE") 
| (LogonType="Network" AND TargetUserName != "ANONYMOUS LOGON") 
| (RemoteAddress IS NOT NULL AND RemotePort=445) // Remote service creation or execution 
| (#event_simpleName=ServiceStart AND ServiceName!="*" AND ImageFileName="*\\Temp\\*" OR ImageFileName="*\\Users\\*")  
```

---

## Data Sources

| Log Provider | Event ID | Event Name         | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|--------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2     | Process             | Process Creation       |
| Falcon       | N/A      | AuthenticationSummary | Authentication   | Authentication Events  |
| Falcon       | N/A      | ServiceStart       | Service             | Service Start          |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute NetExec/CrackMapExec, have network access to SMB/Windows Admin Shares, and permissions to create or start services remotely.
- **Required Artifacts:** Command-line logs, process creation events, authentication logs, and service start events.

---

## Considerations

- Investigate the source and context of NetExec/CrackMapExec usage.
- Review command-line arguments for targeted hosts, credentials, and execution methods.
- Correlate with authentication and network share logs for unauthorized access or lateral movement.
- Examine for follow-on activity such as privilege escalation, credential dumping, or data exfiltration.

---

## False Positives

False positives may occur if:

- Administrators are legitimately using NetExec/CrackMapExec for IT operations or penetration testing.
- Security or compliance tools use similar command-line patterns for network enumeration or validation.

---

## Recommended Response Actions

1. Investigate the initiating process and its source.
2. Analyze command-line arguments and targeted hosts for malicious indicators.
3. Review authentication and network share logs for unauthorized access or lateral movement.
4. Examine service start events for suspicious binaries or paths.
5. Isolate affected systems if confirmed malicious.
6. Reset compromised credentials and review access policies.

---

## References

- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1569.002 – System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)
- [MITRE ATT&CK: T1110.001 – Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE ATT&CK: T1075 – Lateral Tool Transfer](https://attack.mitre.org/techniques/T1075/)
- [MITRE ATT&CK: T1059.003 – Command Shell Execution](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1003.001 – Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [DFIR Report: Navigating Through The Fog](https://thedfirreport.com/2025/04/28/navigating-through-the-fog/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-30 | Initial Detection | Created hunt query to detect NetExec lateral movement with credential abuse and remote service execution |
