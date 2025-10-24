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

This XQL query filters Windows process stop events and flags terminations of known critical processes across five categories: backup, database, email, virtualization, and security tools. It enriches each event with a human-readable `detection_category` label based on the process name.

Key points:
- Scope to Windows process stop events (`event_type = PROCESS`, `event_sub_type = PROCESS_STOP`)
- Match process names against known backup, database, email, VM, and security tool patterns
- Assign a category label for easier triage and aggregation

To detect bulk termination, this query should be aggregated in a downstream rule or dashboard over a short time window (e.g., 5 minutes) to count distinct categories or total terminations per host.

---

#### Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR / XSIAM

```xql
// Qilin Ransomware - Mass Process Termination (Pre-Encryption)
// MITRE: T1489 (Service Stop), T1562.001 (Impair Defenses)
// OS: Windows

config case_sensitive = false
| dataset = xdr_data

// Phase 0: Scope to Windows process stop telemetry (enum constants, no strings)
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_STOP

// Phase 1: Detect termination of backup-related processes (no service fields; booleans only)
| alter is_backup = if(
  action_process_image_name != null and (
    action_process_image_name contains "veeam" or
    action_process_image_name contains "backup" or
    action_process_image_name contains "acronis" or
    action_process_image_name contains "veritas" or
    action_process_image_name contains "commvault" or
    action_process_image_name contains "sqbcoreservice.exe"
  ),
  true, false
)

// Phase 2: Detect termination of database-related processes
| alter is_db = if(
  action_process_image_name != null and (
    action_process_image_name contains "sql" or
    action_process_image_name contains "mssql" or
    action_process_image_name contains "oracle" or
    action_process_image_name contains "mysql" or
    action_process_image_name contains "postgres"
  ),
  true, false
)

// Phase 3: Detect termination of email-related processes
| alter is_email = if(
  action_process_image_name != null and (
    action_process_image_name contains "outlook.exe" or
    action_process_image_name contains "thunderbird.exe" or
    action_process_image_name contains "msexchange"
  ),
  true, false
)

// Phase 4: Detect termination of virtualization-related processes
| alter is_vm = if(
  action_process_image_name != null and (
    action_process_image_name contains "vmms.exe" or
    action_process_image_name contains "vmwp.exe" or
    action_process_image_name contains "vmcompute.exe" or
    action_process_image_name contains "vmms"
  ),
  true, false
)

// Phase 5: Detect termination of security/EDR-related processes
| alter is_security = if(
  action_process_image_name != null and (
    action_process_image_name contains "sophos" or
    action_process_image_name contains "avagent" or
    action_process_image_name contains "avscc" or
    action_process_image_name contains "defender" or
    action_process_image_name contains "carbonblack" or
    action_process_image_name contains "crowdstrike"
  ),
  true, false
)

// Phase 6: Build a single human-readable category label (string-only; no numerics)
| alter detection_category = "Process Termination (Monitored)"
| alter detection_category = if(is_backup = true,   "Termination: Backup/Recovery Process", detection_category)
| alter detection_category = if(is_db = true,       "Termination: Database Process",         detection_category)
| alter detection_category = if(is_email = true,    "Termination: Email Process",            detection_category)
| alter detection_category = if(is_vm = true,       "Termination: Virtualization Process",   detection_category)
| alter detection_category = if(is_security = true, "Termination: Security Process",         detection_category)

// Phase 7: Output (only strings/booleans; avoid numeric fields to prevent concat errors)
| fields
  agent_hostname,
  _time,
  actor_process_image_path,
  actor_effective_username,
  action_process_image_name,
  is_backup,
  is_db,
  is_email,
  is_vm,
  is_security,
  detection_category
| sort desc _time
```

---

#### Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Process             | Process Termination    |

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
