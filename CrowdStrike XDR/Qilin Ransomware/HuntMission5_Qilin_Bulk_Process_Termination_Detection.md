# Mass Service/Process Termination (Pre-Encryption)

#### Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

#### Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Qilin-Bulk-Process-Termination
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

#### Hunt Analytics

This hunt detects Qilin ransomware's pre-encryption phase, where it terminates 50+ critical services and processes to ensure files are not locked during encryption. The query identifies process termination events for backup, database, email, virtualization, and security tools. While this query flags individual process terminations, aggregating these events over a short time window (e.g., 5–10 minutes) can reveal bulk termination patterns indicative of ransomware preparation.

Detected behaviors include:

- Termination of backup-related processes (e.g., Veeam, Acronis, Commvault)
- Termination of database processes (e.g., SQL Server, Oracle, MySQL)
- Termination of email clients or servers (e.g., Outlook, Exchange)
- Termination of virtualization processes (e.g., Hyper-V, VMware)
- Termination of security/EDR agents (e.g., CrowdStrike, Carbon Black, Defender)

This behavior is designed to impair defenses and unlock files for encryption, making it a strong precursor to a full encryption event.

---

#### ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1489       | -            | Service Stop                                  |
| TA0005 - Defense Evasion     | T1562.001   | -            | Impair Defenses: Disable or Modify Tools      |

---

#### Hunt Query Logic

This query filters Windows process stop events and flags terminations of known critical processes across five categories: backup, database, email, virtualization, and security tools. It enriches each event with a human-readable `detection_category` label based on the process name.

Key points:
- Scope to Windows process stop events (`event_type = PROCESS`, `event_sub_type = PROCESS_STOP`)
- Match process names against known backup, database, email, VM, and security tool patterns
- Assign a category label for easier triage and aggregation

To detect bulk termination, this query should be aggregated in a downstream rule or dashboard over a short time window (e.g., 5 minutes) to count distinct categories or total terminations per host.

---

#### Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Qilin Ransomware - Mass Process Termination (Pre-Encryption)
// MITRE: T1489, T1562.001
| #repo="base_sensor" event_platform="Win"

// Scope — process stop telemetry (adjust event name if your tenant exposes a distinct ProcessStop event)
| #event_simpleName="ProcessRollup2"

// Initialize boolean flags (0/1)
| is_backup := 0
| is_db := 0
| is_email := 0
| is_vm := 0
| is_security := 0

// Phase 1: Backup-related processes
| (
    #event_simpleName="ProcessRollup2" and
    ImageFileName=/\b(veeam|backup|acronis|veritas|commvault|sqbcoreservice\.exe)\b/i
  ) | is_backup := 1

// Phase 2: Database-related processes
| (
    #event_simpleName="ProcessRollup2" and
    ImageFileName=/\b(sql|mssql|oracle|mysql|postgres)\b/i
  ) | is_db := 1

// Phase 3: Email-related processes
| (
    #event_simpleName="ProcessRollup2" and
    ImageFileName=/\b(outlook\.exe|thunderbird\.exe|msexchange)\b/i
  ) | is_email := 1

// Phase 4: Virtualization-related processes
| (
    #event_simpleName="ProcessRollup2" and
    ImageFileName=/\b(vmms\.exe|vmwp\.exe|vmcompute\.exe|vmms)\b/i
  ) | is_vm := 1

// Phase 5: Security / EDR-related processes
| (
    #event_simpleName="ProcessRollup2" and
    ImageFileName=/\b(sophos|avagent|avscc|defender|carbonblack|crowdstrike)\b/i
  ) | is_security := 1

// Phase 6: Human-friendly category (string-only)
| detection_category := "Process Termination (Monitored)"
| is_backup=1   | detection_category := "Termination: Backup/Recovery Process"
| is_db=1       | detection_category := "Termination: Database Process"
| is_email=1    | detection_category := "Termination: Email Process"
| is_vm=1       | detection_category := "Termination: Virtualization Process"
| is_security=1 | detection_category := "Termination: Security Process"

// Output (strings/booleans only)
| select([
    aid,
    ComputerName,
    _time,
    ImageFilePath,
    UserName,
    ImageFileName,
    is_backup,
    is_db,
    is_email,
    is_vm,
    is_security,
    detection_category,
    #event_simpleName
  ])
| sort([_time], order=desc)
```

---

#### Data Sources

| Provider                 | Dataset/Events (Falcon)                                  | ATT&CK Data Source | Data Component         |
|-------------------------|-----------------------------------------------------------|--------------------|------------------------|
| CrowdStrike Falcon      | base_sensor: ProcessRollup2 (process telemetry)          | Process            | Process Creation       |

---

#### Execution Requirements

- **Required Permissions:** Collection of process termination events with process image name and actor information.
- **Required Artifacts:** Process stop logs, actor process image path, and effective username.

---

#### Considerations

- This query flags individual process terminations. To detect ransomware behavior, downstream aggregation (e.g., count of distinct categories or total terminations per host in a 5-minute window) is required.
- Legitimate administrative actions (e.g., service restarts, patching, shutdowns) may trigger similar patterns. Validate against change control records and user context.
- Correlate with other Qilin indicators (VSS deletion, event log clearing, registry persistence) to confirm compromise.

---

#### False Positives

False positives may occur when:

- IT administrators perform bulk service shutdowns for maintenance or patching.
- Automated scripts or deployment tools terminate multiple services in sequence.

Mitigation: Cross-reference with maintenance schedules, validate initiating user accounts, and check for related suspicious activity.

---

#### Recommended Response Actions

1. Review process termination events for suspicious actor context and timing.
2. Aggregate events by host and time window to detect bulk termination patterns.
3. Query for related activity (file encryption, ransom notes, lateral movement) from the same host or user.
4. Collect forensic artifacts and isolate affected hosts if malicious activity is confirmed.
5. Notify incident response and follow organizational ransomware playbooks.
6. Block or quarantine binaries associated with suspicious terminations.

---

#### References

- [MITRE ATT&CK: T1489 – Service Stop](https://attack.mitre.org/techniques/T1489/)
- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)

---

#### Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-23 | Initial Detection | Created hunt query to detect Qilin's mass process termination prior to encryption         |
