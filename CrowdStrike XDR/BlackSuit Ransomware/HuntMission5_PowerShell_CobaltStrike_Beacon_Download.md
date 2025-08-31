# Detection of Cobalt Strike Beacon Download via PowerShell

## Severity or Impact of the Detected Behavior

- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-PowerShell-CobaltStrike-Download
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects suspicious use of PowerShell to download files from a known C2 IP address (`184.174.96.71`) and save them as `vm.dll` or `vm80.dll`, which is a common Cobalt Strike Beacon delivery technique. Attackers often leverage PowerShell for file download and execution as part of their post-exploitation and C2 activities. Detected behaviors include:

- Process launches of `powershell.exe` with command lines referencing the C2 IP or `invoke-webrequest`
- Command lines indicating download or saving of `vm.dll` or `vm80.dll`
- Full process and user context for investigation

These techniques are associated with remote payload delivery, C2, and post-exploitation activity.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0010 - Exfiltration        | T1105       | —            | Ingress Tool Transfer                         |
| TA0002 - Execution           | T1059.001   | —            | Command and Scripting Interpreter: PowerShell |

---

## Hunt Query Logic

This query identifies suspicious PowerShell activity by looking for:

- Process starts of `powershell.exe` with command lines referencing `184.174.96.71` or `invoke-webrequest`
- Command lines indicating download or saving of `vm.dll` or `vm80.dll`
- Full process and user context for triage

These patterns are indicative of Cobalt Strike Beacon delivery via PowerShell.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Cobalt Strike Beacon Download via PowerShell
// Description: Detects PowerShell usage to download files from a known C2 IP (184.174.96.71) and save as vm.dll or vm80.dll, a common Cobalt Strike Beacon delivery technique.
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1059.001

#event_simpleName=ProcessRollup2
| event_platform = Win
| FileName = "powershell.exe"
| (CommandLine = "*184.174.96.71*" or CommandLine = "*invoke-webrequest*")
| (CommandLine = "*vm.dll*" or CommandLine = "*vm80.dll*")
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

- **Required Permissions:** User or attacker must have privileges to execute PowerShell and initiate network connections.
- **Required Artifacts:** Process creation logs, command-line arguments, and network connection records.

---

## Considerations

- Review the source and context of the PowerShell process and command line for legitimacy.
- Correlate with user activity and network logs to determine if the activity is user-initiated or automated.
- Investigate any subsequent file execution or lateral movement.

---

## False Positives

False positives may occur if:

- IT administrators or legitimate scripts use PowerShell to download files for benign purposes.
- Automated deployment tools or scripts generate and execute these commands for legitimate software delivery.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Analyze network connections to the C2 IP and review file creation events.
3. Review user activity and system logs for signs of compromise or C2.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious PowerShell download attempts and known C2 infrastructure.

---

## References

- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect Cobalt Strike Beacon download via PowerShell                  |
