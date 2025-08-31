# Detection of Configure-SMRemoting.exe Execution

## Severity or Impact of the Detected Behavior

- **Risk Score:** 75
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-ConfigureSMRemoting-Exec
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of `Configure-SMRemoting.exe`, a legitimate Windows utility that enables or disables remote management on a system. While it is used for legitimate administrative purposes, threat actors may abuse this tool to enable remote management and facilitate lateral movement or remote control during post-exploitation. Detected behaviors include:

- Process launches of `Configure-SMRemoting.exe`
- Full process and user context for investigation

These techniques are associated with enabling remote management, which can be leveraged for lateral movement or persistence.

---

## ATT&CK Mapping

| Tactic                     | Technique   | Subtechnique | Technique Name                                 |
|---------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement | T1021.001   | —            | Remote Services: Remote Desktop Protocol       |

---

## Hunt Query Logic

This query identifies suspicious or unauthorized use of Configure-SMRemoting.exe by looking for:

- Process starts of `Configure-SMRemoting.exe`
- Full process and user context for triage

These patterns may indicate attempts to enable remote management for lateral movement or remote control.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Configure-SMRemoting.exe Execution Detection
// Description: Detects execution of Configure-SMRemoting.exe, which can be used to enable remote management and facilitate lateral movement.
// MITRE ATT&CK TTP ID: T1021.001

#event_simpleName=ProcessRollup2
| event_platform = Win
| FileName = "configure-smremoting.exe"
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

- **Required Permissions:** User or attacker must have privileges to execute Configure-SMRemoting.exe.
- **Required Artifacts:** Process creation logs and command-line arguments.

---

## Considerations

- Review the source and context of the Configure-SMRemoting.exe process and command line for legitimacy.
- Correlate with user activity and system logs to determine if the activity is user-initiated or automated.
- Investigate any subsequent remote management or lateral movement activity.

---

## False Positives

False positives may occur if:

- IT administrators legitimately use Configure-SMRemoting.exe for remote management configuration.
- Automated deployment tools or scripts generate and execute these commands for benign purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Review user activity and system logs for signs of compromise or lateral movement.
3. Analyze any subsequent remote management connections or changes.
4. Isolate affected endpoints if malicious activity is confirmed.
5. Block or monitor access to suspicious remote management configuration attempts.

---

## References

- [MITRE ATT&CK: T1021.001 – Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [Cybereason: BlackSuit – A Hybrid Approach with Data Exfiltration and Encryption](https://www.cybereason.com/blog/blacksuit-data-exfil)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-08-06 | Initial Detection | Created hunt query to detect Configure-SMRemoting.exe execution for remote management abuse |
