# Bulk Event Log Clearing via PowerShell

#### Severity or Impact of the Detected Behavior
- **Risk Score:** 95
- **Severity:** High

#### Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Qilin-EventLog-Clear
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

#### Hunt Analytics

This hunt detects Qilin ransomware activity that uses PowerShell to clear Windows event logs via the EventLogSession API (e.g., `EventLogSession.GlobalSession.ClearLog()`), a behavior commonly used by attackers to hinder detection and post-incident forensics. The detection identifies both the full script pattern and partial indicators such as usage of `EventLogSession` and `ClearLog` in PowerShell command lines, and optionally `Get-WinEvent` for enumeration prior to clearing.

Detected behaviors include:

- PowerShell interpreter launches (`powershell.exe` or `pwsh.exe`) containing `EventLogSession` and `ClearLog` in the command line
- Enumeration of logs via `Get-WinEvent` coupled with `ClearLog`
- PowerShell invoked from suspicious parent locations (non-system or non-Program Files paths)

Because this specific API call and combination is rare in legitimate automation, its presence is a strong indicator of malicious intent, especially when observed outside maintenance windows or initiated by non-admin/non-IT service accounts.

---

#### ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0006 - Defense Evasion     | T1070.001   | -            | Indicator Removal: Clear Windows Event Logs   |
| TA0002 - Execution           | T1059.001   | -            | Command and Scripting Interpreter: PowerShell |

---

#### Hunt Query Logic

This query scans Windows process creation events for PowerShell executions that contain `EventLogSession` and `ClearLog` tokens on the command line. It enriches results with indicators of `Get-WinEvent` usage (log enumeration) and flags suspicious parent process locations to raise confidence. The correlation requires PowerShell + EventLogSession + ClearLog to reduce noise.

Key points:
- Require PowerShell process name (`powershell.exe` or `pwsh.exe`) in process creation events
- Require `EventLogSession` and `ClearLog` tokens in the command line
- Optionally escalate confidence if `Get-WinEvent` is present and if the parent process path is outside `C:\Windows\` or `C:\Program Files`

---

#### Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Qilin Ransomware - Bulk Event Log Clearing via PowerShell
// MITRE: T1070.001, T1059.001
| #repo="base_sensor" event_platform="Win"

// Limit to process start events
| #event_simpleName="ProcessRollup2"

// Initialize binary flags
| powershell_execution := 0
| has_eventlogsession := 0
| has_clearlog := 0
| has_get_winevent := 0
| in_windows_dir_parent := 0
| in_program_files_parent := 0
| suspicious_parent := 0

// Phase 1: Detect PowerShell execution (powershell.exe or pwsh.exe)
| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\powershell\\.exe$/i or ImageFileName=/\\pwsh\\.exe$/i or ImageFileName=/\\powershell$/i or ImageFileName=/\\pwsh$/i)
  ) | powershell_execution := 1

// Phase 2: Detect EventLogSession usage in command line
| (
    #event_simpleName="ProcessRollup2" and
    CommandLine=/EventLogSession/i
  ) | has_eventlogsession := 1

// Phase 3: Detect ClearLog method
| (
    #event_simpleName="ProcessRollup2" and
    CommandLine=/ClearLog/i
  ) | has_clearlog := 1

// Phase 4: Detect Get-WinEvent cmdlet (log enumeration)
| (
    #event_simpleName="ProcessRollup2" and
    CommandLine=/Get-WinEvent/i
  ) | has_get_winevent := 1

// Phase 5: Suspicious parent location (avoid false positives in Windows/Program Files)
// Note: escape backslashes in path regex
| (
    causality_actor_process_image_path=/c:\\\\windows\\\\/i
  ) | in_windows_dir_parent := 1

| (
    causality_actor_process_image_path=/c:\\\\program files/i
  ) | in_program_files_parent := 1

// suspicious_parent = path exists AND not in Windows nor Program Files
| causality_actor_process_image_path!="" and in_windows_dir_parent=0 and in_program_files_parent=0 | suspicious_parent := 1

// Correlation Filter: Require PowerShell + EventLogSession + ClearLog
| powershell_execution=1 and has_eventlogsession=1 and has_clearlog=1

// Enrichment / classification (strings)
| detection_category := "PowerShell Log Manipulation"
| has_eventlogsession=1 and has_clearlog=1                     | detection_category := "Bulk Event Log Clearing"
| has_get_winevent=1 and has_eventlogsession=1 and has_clearlog=1 | detection_category := "Qilin Event Log Clearing (Full Pattern)"

// Risk scoring (numeric)
| risk_score := 75
| has_eventlogsession=1 and has_clearlog=1                                      | risk_score := 85
| has_get_winevent=1 and has_eventlogsession=1 and has_clearlog=1               | risk_score := 95
| has_get_winevent=1 and has_eventlogsession=1 and has_clearlog=1 and suspicious_parent=1 | risk_score := 100

// Output
| select([
    aid,
    ComputerName,
    _time,
    ImageFileName,
    CommandLine,
    causality_actor_process_image_path,
    UserName,
    powershell_execution,
    has_eventlogsession,
    has_clearlog,
    has_get_winevent,
    suspicious_parent,
    detection_category,
    risk_score,
    #event_simpleName
  ])
| sort([risk_score, _time], order=desc)
```

---

#### Data Sources

| Provider                 | Dataset/Events (Falcon)                                  | ATT&CK Data Source | Data Component         |
|-------------------------|-----------------------------------------------------------|--------------------|------------------------|
| CrowdStrike Falcon      | base_sensor: ProcessRollup2 (process telemetry)          | Process            | Process Creation       |

---

#### Execution Requirements

- **Required Permissions:** Collection of process creation events with full command-line visibility on Windows endpoints. PowerShell command-line capture must be enabled.
- **Required Artifacts:** Process creation logs (command line, image path), causality/parent process information, and timestamps.

---

#### Considerations

- While `EventLogSession.GlobalSession.ClearLog()` is rare in legitimate automation, some custom cleanup scripts or hardening tools could use similar APIs. Always validate against maintenance windows and owner approvals.
- Attackers may obfuscate or encode PowerShell payloads; ensure PowerShell script block logging, module logging, and AMSI are enabled to improve detection fidelity.
- Correlate with other indicators of compromise such as privilege escalation, creation of new admin accounts, lateral movement, or data exfiltration.

---

#### False Positives

False positives may occur when:

- Legitimate administrative scripts intentionally clear logs for housekeeping in controlled scenarios.
- Automated deployment or imaging workflows execute PowerShell scripts that enumerate or rotate logs.

Mitigation: Confirm user/automation owner, execution context, and timing against change windows and documented procedures before taking containment actions.

---

#### Recommended Response Actions

1. Review the full command line and parent process for the event; confirm whether the execution was scheduled or user-initiated.
2. If malicious, collect forensic artifacts (PowerShell logs, process memory, event logs before and after clearing if available) and preserve the host.
3. Query the environment for related activity from the same user or host (credential use, new service installs, lateral logins).
4. Isolate affected hosts if evidence indicates active compromise.
5. Ensure backups and off-host logs are intact; escalate to incident response and follow ransomware playbooks.
6. Harden PowerShell logging (Enable Script Block Logging, Module Logging), enable AMSI, and enforce application control to reduce the likelihood of successful log-clearing attacks.

---

#### References

- [MITRE ATT&CK: T1070.001 – Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

#### Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-23 | Initial Detection | Created hunt query to detect Qilin PowerShell-based bulk event log clearing via EventLogSession.ClearLog() |
