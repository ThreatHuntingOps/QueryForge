# Detection of BlackSuit Ransomware Payload Download and Execution via PsExec and PowerShell

## Severity or Impact of the Detected Behavior

- **Risk Score:** 95
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-BlackSuit-PsExec-PowerShell
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects the use of PsExec to launch PowerShell commands that download a malicious payload from an internal IP, save it as `b.exe` (or other names), and execute it with the `-nomutex` flag—a behavior associated with BlackSuit ransomware. Attackers often leverage PsExec for remote command execution and PowerShell for payload delivery and execution. Detected behaviors include:

- PowerShell process launches with command lines containing download methods and references to `b.exe` and `-nomutex`
- Parent or causality ancestry indicating PsExec involvement
- Full process and user context for investigation

These techniques are associated with remote payload delivery, ransomware deployment, and hands-on-keyboard activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0010 - Exfiltration        | T1105       | —            | Ingress Tool Transfer                         |
| TA0002 - Execution           | T1059.001   | —            | Command and Scripting Interpreter: PowerShell |
| TA0008 - Lateral Movement    | T1569.002   | —            | System Services: Service Execution (PsExec)   |

---

## Hunt Query Logic

This query identifies BlackSuit ransomware payload delivery and execution by looking for:

- PowerShell process launches with command lines containing `downloadfile` or `net.webclient`, `b.exe`, and `-nomutex`
- Parent or causality ancestry indicating PsExec involvement
- Full process and user context for triage

These patterns are indicative of BlackSuit ransomware deployment via PsExec and PowerShell.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: BlackSuit Ransomware Payload Download and Execution via PsExec and PowerShell
// Description: Detects PsExec-launched PowerShell commands that download a payload from an internal IP, save as b.exe (or other names), and execute with -nomutex flag, a BlackSuit ransomware TTP.
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1059.001
// MITRE ATT&CK TTP ID: T1569.002

#event_simpleName=ProcessRollup2
| event_platform = Win
| FileName = "powershell.exe"
| (CommandLine = "*downloadfile*" or CommandLine = "*net.webclient*")
| CommandLine = "*b.exe*"
| CommandLine = "*-nomutex*"
| (ParentBaseFileName = "psexec.exe" or CommandLine = "*psexec.exe*")
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, CausalityActorProcessCommandLine, CausalityActorPrimaryUsername, SHA256FileHash, EventID, AgentId])
| sort(EventTimestamp)
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** User or attacker must have privileges to execute PsExec and PowerShell, and initiate network connections.
- **Required Artifacts:** Process creation logs, command-line arguments, and network connection records.

---

## Considerations

- Review the source and context of the PowerShell and PsExec processes and command lines for legitimacy.
- Correlate with user activity and network logs to determine if the activity is user-initiated or automated.
- Investigate any subsequent file execution, ransomware activity, or lateral movement.

---

## False Positives

False positives may occur if:

- IT administrators or legitimate scripts use PsExec and PowerShell for software deployment or automation.
- Automated deployment tools or scripts generate and execute these commands for benign purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Analyze network connections and file creation events associated with the affected hosts.
3. Review user activity and system logs for signs of compromise or ransomware deployment.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious PsExec and PowerShell usage and known ransomware indicators.

---

## References

- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1569.002 – System Services: Service Execution (PsExec)](https://attack.mitre.org/techniques/T1569/002/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect BlackSuit ransomware payload download and execution via PsExec and PowerShell |
