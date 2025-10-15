# Detection of Windows Event Log Deletion via PowerShell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** HIGH

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-PowerShell-EventLog-Deletion-T1070
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Hunt Analytics

This hunt detects PowerShell commands that recursively delete Windows event log files or use built-in utilities to clear logs, leveraging CrowdStrike Falcon telemetry. Yurei ransomware systematically wipes event logs to cover its tracks. This behavior is almost never legitimate outside controlled testing and is a strong indicator of adversary activity. Detected behaviors include:

- Recursive deletion of event log files from `winevt\\Logs` or `System32\\Logs`
- PowerShell cmdlets for log clearing (e.g., `Clear-EventLog`)
- Use of `wevtutil` to clear event logs via PowerShell
- Combinations like `Get-ChildItem` + `Remove-Item` targeting log directories

---

## ATT&CK Mapping

| Tactic                   | Technique   | Subtechnique | Technique Name                                     |
|--------------------------|------------:|-------------:|----------------------------------------------------|
| TA0005 - Defense Evasion | T1070       | .001         | Indicator Removal: Clear Windows Event Logs        |
| TA0002 - Execution       | T1059.001   | -            | Command and Scripting Interpreter: PowerShell      |

---

## Hunt Query Logic

Falcon base_sensor ProcessRollup2 events are filtered to PowerShell image names and matched on command-line patterns:

- `Remove-Item`/`Get-ChildItem` activity against log paths
- `Clear-EventLog` and related cmdlets
- `wevtutil cl` or `wevtutil clear-log`

Optional exclusion for SYSTEM context and tuning for maintenance/service accounts are recommended.

---

## Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Title: PowerShell Event Log Deletion and Anti-Forensics
// Description: Detects PowerShell commands that recursively delete Windows event log files or use built-in cmdlets to clear logs. Yurei ransomware systematically wipes event logs to cover its tracks.
// MITRE ATT&CK TTP ID: T1070.001, T1059.001

#event_simpleName=ProcessRollup2
| event_platform="Win"

// Scope to PowerShell (case-insensitive, anchored)
| ImageFileName=/(?i)^powershell(\.exe)?$/

// Event log deletion / clearing patterns
| (
    // Recursive deletion of event log files/directories
    (CommandLine=/(?i)\bRemove-Item\b/ and CommandLine=/winevt\\Logs/i)
    or (CommandLine=/(?i)\bRemove-Item\b/ and CommandLine=/System32\\Logs/i)
    or (CommandLine=/(?i)\bGet-ChildItem\b/ and CommandLine=/(?i)\bRemove-Item\b/ and CommandLine=/\\Logs\b/i)

    // PowerShell cmdlet-based log clearing
    or CommandLine=/(?i)\bClear-EventLog\b/
    or CommandLine=/(?i)\bLimit-EventLog\b/

    // wevtutil clear variants
    or (CommandLine=/(?i)\bwevtutil\b/ and (CommandLine=/(?i)\bcl\b/ or CommandLine=/(?i)\bclear-log\b/))
  )

// Exclusions (tune per environment)
// Exclude legitimate maintenance accounts or SYSTEM
| UserName !=/(?i)^(SYSTEM)$/

// Enrichment fields
| severity := "HIGH"
| detection_category := "Anti-Forensics - Event Log Deletion"
| risk_score := 95
| mitre_technique := "T1070.001, T1059.001"

// Output fields
| select(
    @timestamp,
    aid,
    ComputerName,
    UserName,
    ImageFileName,
    CommandLine,
    ParentImageFileName,
    ParentCommandLine,
    ContextProcessId,
    #event_simpleName,
    severity,
    detection_category,
    risk_score,
    mitre_technique
)
| sort(field=@timestamp, order=desc, limit=1000)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                     | ATT&CK Data Source | Data Component          |
|--------------------|----------------------------------------------|--------------------|-------------------------|
| CrowdStrike Falcon | base_sensor: ProcessRollup2 (process events) | Process            | Process Creation        |
| CrowdStrike Falcon | base_sensor: ProcessRollup2 (command lines)  | Command            | Command Execution       |

Field notes:
- Host identity: aid (Agent ID), ComputerName; user context: UserName
- Process fields: ImageFileName, CommandLine; parent fields for chain context
- Event selector: #event_simpleName

---

## Execution Requirements

- **Required Permissions:** Admin or elevated privileges typically required to delete or clear event logs.
- **Required Artifacts:** Process creation telemetry with command-line arguments (ProcessRollup2), event log modification visibility where available.

---

## Considerations

- Validate user account legitimacy and authorization; consider maintenance windows.
- Correlate with other ransomware indicators (VSS deletion, file encryption, ransom note creation).
- Inspect parent process lineage to understand execution chain.
- Look for additional anti-forensics behaviors (timestamp manipulation, secure deletion, memory wiping).
- If logs were cleared locally, check SIEM or centralized logging for preserved copies.

---

## False Positives

Possible when:
- Administrators manually clear logs during maintenance/troubleshooting
- Scheduled tasks/scripts perform log cleanup
- Security testing includes log clearing

Mitigation:
- Tune allowlists for authorized accounts, tools, and maintenance windows.

---

## Recommended Response Actions

1. Prioritize investigation of the endpoint and user account.
2. If malicious, isolate the endpoint (Falcon Host containment).
3. Review full command line, parent process, and user context.
4. Correlate with Yurei indicators (VSS deletion, `.Yurei` files, `_README_Yurei.txt`, temp staging).
5. Investigate lateral movement (CIM sessions, `net use`, SMB writes, PSCredential usage).
6. Preserve forensic evidence (memory, process lists) and collect Falcon context.
7. Validate that logs are preserved in SIEM/central logging and adjust retention as needed.
8. Rotate credentials and disable compromised accounts as indicated.
9. Expand hunt for similar behaviors across the estate.
10. Engage Incident Response; consider Falcon OverWatch escalation.

---

## References

- [MITRE ATT&CK: T1070.001 – Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)
- [Microsoft: Windows Event Logs](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging)
- [Microsoft: Clear-EventLog Cmdlet](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/clear-eventlog)
- [Microsoft: wevtutil Command-Line Tool](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Detection   | Hunt query for PowerShell-based event log deletion (Yurei anti-forensics) |

