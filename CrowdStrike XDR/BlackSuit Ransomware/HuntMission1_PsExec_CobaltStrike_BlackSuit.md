# Detection of PsExec-Based Lateral Movement and Cobalt Strike Beacon Deployment

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-PsExec-CobaltStrike-BlackSuit
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the use of `PsExec.exe` for lateral movement, specifically focusing on attempts to copy and execute Cobalt Strike Beacon DLLs (`vm.dll`, `vm80.dll`) in the `C:\Windows\Temp` directory on remote hosts. BlackSuit ransomware operators are known to leverage PsExec for remote command execution, often deploying Cobalt Strike payloads as part of their attack chain. Detected behaviors include:

- Suspicious process launches of `psexec.exe` or `psexesvc.exe`
- Command lines referencing Cobalt Strike Beacon DLLs in temporary directories
- Contextual process and user information for investigation

These techniques are strong indicators of hands-on-keyboard activity, post-exploitation tool deployment, and potential ransomware staging.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021.002   | —            | Remote Services: SMB/Windows Admin Shares (PsExec) |
| TA0010 - Exfiltration        | T1105       | —            | Ingress Tool Transfer                         |
| TA0008 - Lateral Movement    | T1570       | —            | Lateral Tool Transfer                         |

**Optional Additional Hunt:**

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1055.001   | —            | Process Injection: Dynamic-link Library Injection |

---

## Hunt Query Logic

This query identifies suspicious use of PsExec for lateral movement and Cobalt Strike Beacon deployment by looking for:

- Process starts of `psexec.exe` or `psexesvc.exe`
- Command lines referencing `C:\Windows\Tempm.dll` or `C:\Windows\Tempm80.dll` (or similar temp paths)
- Full process and user context for triage

These patterns are indicative of BlackSuit ransomware and Cobalt Strike post-exploitation activity.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: PsExec-Based Lateral Movement and Cobalt Strike Beacon Deployment
// Description: Detects suspicious use of PsExec.exe to copy and execute Cobalt Strike Beacon DLLs (vm.dll, vm80.dll) in C:\Windows\Temp, a common BlackSuit ransomware TTP.
// MITRE ATT&CK TTP ID: T1021.002
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1570

#event_simpleName=ProcessRollup2
| event_platform = Win
| (FileName = "psexec.exe" or FileName = "psexesvc.exe")
| (
    CommandLine = "*C:\\Windows\\Temp\\vm.dll*"
    or CommandLine = "*C:\\Windows\\Temp\\vm80.dll*"
    or CommandLine = "*\\temp\\vm.dll*"
    or CommandLine = "*\\temp\\vm80.dll*"
    or CommandLine = "*/temp/vm.dll*"
    or CommandLine = "*/temp/vm80.dll*"
  )
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, SHA256FileHash, EventID, AgentId])
| sort(EventTimestamp)
```

**Optional: Additional Hunt for DLL Execution**

```fql
// Title: Suspicious Execution of Cobalt Strike Beacon DLLs from Temp
// Description: Detects execution of vm.dll or vm80.dll from C:\Windows\Temp, which may indicate successful deployment and activation of Cobalt Strike Beacon.
// MITRE ATT&CK TTP ID: T1055.001

#event_simpleName=ProcessRollup2
| event_platform = Win
| (FileName = "rundll32.exe" or FileName = "regsvr32.exe" or FileName = "dllhost.exe")
| (
    CommandLine = "*C:\\Windows\\Temp\\vm.dll*"
    or CommandLine = "*C:\\Windows\\Temp\\vm80.dll*"
    or CommandLine = "*\\temp\\vm.dll*"
    or CommandLine = "*\\temp\\vm80.dll*"
    or CommandLine = "*/temp/vm.dll*"
    or CommandLine = "*/temp/vm80.dll*"
  )
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, SHA256FileHash, EventID, AgentId])
| sort(EventTimestamp) 
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** Attacker must have credentials or privileges to execute PsExec or drop files on remote hosts.
- **Required Artifacts:** Process creation logs, command-line arguments, and file creation events.

---

## Considerations

- Review the source and context of the PsExec process and command line for legitimacy.
- Correlate with user activity, network, and file creation logs to determine if the activity is user-initiated or automated.
- Investigate any network connections or file transfers associated with the affected hosts.
- Validate if the dropped DLLs are associated with known Cobalt Strike payloads or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- IT administrators legitimately use PsExec for remote administration and deploy benign DLLs.
- Automated deployment tools or scripts generate and execute these commands for legitimate purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Analyze network connections and file transfers associated with the affected hosts.
3. Review user activity and system logs for signs of compromise or lateral movement.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious PsExec usage and Cobalt Strike Beacon indicators.

---

## References

- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares (PsExec)](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1570 – Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [MITRE ATT&CK: T1055.001 – Process Injection: Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)



---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect PsExec-based lateral movement and Cobalt Strike Beacon deployment |
