# Detection of NetExec-Based Lateral Movement over SMB/Windows Admin Shares

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-CrowdStrike-NetExec-SMB-LateralMovement
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects potential lateral movement activities associated with NetExec (and its predecessor CrackMapExec), post-exploitation frameworks used to remotely execute commands across systems via SMB and Windows Admin Shares. The query targets command-line indicators, process names, and parent-child relationships typically observed when attackers leverage these tools for remote access, command execution, or enumeration across hosts. Such activity is a strong indicator of post-compromise lateral movement, credential abuse, and privilege escalation attempts.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                              |
|------------------------------|-------------|--------------|-------------------------------------------------------------|
| TA0008 - Lateral Movement    | T1021.002   | —            | Remote Services: SMB/Windows Admin Shares                   |
| TA0008 - Lateral Movement    | T1021.001   | —            | Remote Services: Remote Desktop Protocol (optional fallback) |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell     |
| TA0008 - Lateral Movement    | T1075       | —            | Pass the Hash / Lateral Tool Transfer                       |
| TA0002 - Execution           | T1035       | —            | Service Execution (if combined with service-based commands)  |

---

## Hunt Query Logic

This query identifies:

- Command-line usage of NetExec or CrackMapExec, including SMB, username, password, and command execution flags
- File names and process creation events for NetExec, CrackMapExec, or related Python scripts
- Command-line arguments referencing admin shares (C$, ADMIN$, IPC$) and execution methods
- Parent-child process relationships indicating script automation (e.g., Python, cmd.exe, or PowerShell spawning NetExec)

These patterns are rarely seen in legitimate administrative activity and are strong indicators of lateral movement and post-exploitation.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
#event_simpleName=ProcessRollup2  
| (CommandLine=/netexec/i OR CommandLine=/crackmapexec/i OR CommandLine="*smb*" OR CommandLine="*-u*" AND CommandLine="*-p*" AND CommandLine="*-x*")  
| (FileName="netexec.exe" OR FileName=/netexec/i OR FileName=/crackmapexec/i OR FileName="crackmapexec.py")  
| (CommandLine="*admin*" OR CommandLine="*\\C$*" OR CommandLine="*\\ADMIN$*" OR CommandLine="*\\IPC$*")  
| (CommandLine="*--exec-method*" OR CommandLine="*--local-auth*" OR CommandLine="*--share*")

// Expanded Hunt Query with Parent-Child Relationships
#event_simpleName=ProcessRollup2 
| ((ParentBaseFileName="python.exe" OR ParentBaseFileName="cmd.exe" OR ParentBaseFileName="powershell.exe") AND (FileName=/netexec/i OR FileName=/crackmapexec/i OR FileName="netexec.exe")) 
| (CommandLine="*smb*" AND CommandLine="*-x*" AND CommandLine="*-u*" AND CommandLine="*-p*") 
| (CommandLine="*\\C$*" OR CommandLine="*\\ADMIN$*" OR CommandLine="*\\IPC$*")  
```

---

## Data Sources

| Log Provider | Event ID | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|----------|------------------|---------------------|------------------------|
| Falcon       | N/A      | ProcessRollup2   | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute NetExec/CrackMapExec and have network access to SMB/Windows Admin Shares.
- **Required Artifacts:** Command-line logs, process creation events, and network share access logs.

---

## Considerations

- Investigate the source and context of NetExec/CrackMapExec usage.
- Review command-line arguments for targeted hosts, credentials, and execution methods.
- Correlate with authentication and network share logs for unauthorized access or lateral movement.
- Examine for follow-on activity such as privilege escalation or data exfiltration.

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
4. Isolate affected systems if confirmed malicious.
5. Reset compromised credentials and review access policies.

---

## References

- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)
- [MITRE ATT&CK: T1075 – Pass the Hash](https://attack.mitre.org/techniques/T1075/)
- [MITRE ATT&CK: T1035 – Service Execution](https://attack.mitre.org/techniques/T1035/)
- [DFIR Report: Navigating Through The Fog](https://thedfirreport.com/2025/04/28/navigating-through-the-fog/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-04-30 | Initial Detection | Created hunt query to detect NetExec-based lateral movement over SMB/Windows Admin Shares   |
