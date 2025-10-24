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

This XQL query scans Windows process creation events for PowerShell executions that contain `EventLogSession` and `ClearLog` tokens on the command line. It enriches results with indicators of `Get-WinEvent` usage (log enumeration) and flags suspicious parent process locations to raise confidence. The correlation requires PowerShell + EventLogSession + ClearLog to reduce noise.

Key points:
- Require PowerShell process name (`powershell.exe` or `pwsh.exe`) in process creation events
- Require `EventLogSession` and `ClearLog` tokens in the command line
- Optionally escalate confidence if `Get-WinEvent` is present and if the parent process path is outside `C:\Windows\` or `C:\Program Files`

---

#### Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR / XSIAM

```xql
// Qilin Ransomware - Bulk Event Log Clearing via PowerShell
// MITRE: T1070.001 (Clear Windows Event Logs), T1059.001 (PowerShell)
// OS: Windows

config case_sensitive = false
| dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter event_type = PROCESS and event_sub_type = ENUM.PROCESS_START

// Phase 1: Detect PowerShell execution (powershell.exe or pwsh.exe)
| alter powershell_execution = if(
  action_process_image_name != null and
  (action_process_image_name contains "powershell.exe" or action_process_image_name contains "pwsh.exe"),
  true, false
)

// Phase 2: Detect EventLogSession class usage (Qilin-specific)
| alter has_eventlogsession = if(
  action_process_image_command_line != null and
  action_process_image_command_line contains "EventLogSession",
  true, false
)

// Phase 3: Detect ClearLog method
| alter has_clearlog = if(
  action_process_image_command_line != null and
  action_process_image_command_line contains "ClearLog",
  true, false
)

// Phase 4: Detect Get-WinEvent cmdlet (log enumeration)
| alter has_get_winevent = if(
  action_process_image_command_line != null and
  action_process_image_command_line contains "Get-WinEvent",
  true, false
)

// Phase 5: Suspicious parent location (avoid escaping pitfalls; keep contains)
| alter in_windows_dir_parent = if(
  causality_actor_process_image_path != null and
  causality_actor_process_image_path contains "c:\windows\",
  true, false
)
| alter in_program_files_parent = if(
  causality_actor_process_image_path != null and
  causality_actor_process_image_path contains "c:\program files",
  true, false
)
| alter suspicious_parent = if(
  causality_actor_process_image_path != null and
  (in_windows_dir_parent = false and in_program_files_parent = false),
  true, false
)

// Correlation Filter: Require PowerShell + EventLogSession + ClearLog
| filter powershell_execution = true and has_eventlogsession = true and has_clearlog = true

// Enrichment (string-only category; numeric score computed in staged steps)
| alter detection_category = "PowerShell Log Manipulation"
| alter detection_category = if(has_eventlogsession = true and has_clearlog = true, "Bulk Event Log Clearing", detection_category)
| alter detection_category = if(has_get_winevent = true and has_eventlogsession = true and has_clearlog = true, "Qilin Event Log Clearing (Full Pattern)", detection_category)

// Risk score (numeric only; safe to project, or hide if UI complains)
| alter risk_score = 75
| alter risk_score = if(has_eventlogsession = true and has_clearlog = true, 85, risk_score)
| alter risk_score = if(has_get_winevent = true and has_eventlogsession = true and has_clearlog = true, 95, risk_score)
| alter risk_score = if(has_get_winevent = true and has_eventlogsession = true and has_clearlog = true and suspicious_parent = true, 100, risk_score)

// Output
| fields
  agent_hostname,
  _time,
  action_process_image_name,
  action_process_image_command_line,
  causality_actor_process_image_path,
  actor_effective_username,
  powershell_execution,
  has_eventlogsession,
  has_clearlog,
  has_get_winevent,
  suspicious_parent,
  detection_category,
  risk_score
| sort desc risk_score, desc _time
```

---

#### Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Process             | Process Creation       |

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
