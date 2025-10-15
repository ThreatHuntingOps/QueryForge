# Detection of Mass File Encryption (Ransomware Behavior)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** CRITICAL

## Hunt Analytics Metadata

- **ID:** HuntQuery-MultiOS-Mass-File-Encryption-T1486
- **Operating Systems:** WindowsEndpoint, WindowsServer, Linux, macOS
- **False Positive Rate:** Low to Medium
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Hunt Analytics

This hunt detects processes performing rapid, high-volume file modifications across multiple directories, a hallmark of ransomware encryption, using CrowdStrike Falcon telemetry. The query identifies file system churn indicative of bulk encryption activity. While it may trigger on legitimate backup or sync operations, correlation with suspicious executables and file extension changes increases fidelity. Detected behaviors include:

- Processes performing >100 file operations within 5-minute windows
- Rapid file modification patterns consistent with encryption loops
- High-volume file system activity from non-standard processes
- Exclusions for known legitimate backup and sync applications

---

## ATT&CK Mapping

| Tactic            | Technique | Subtechnique | Technique Name                |
|-------------------|----------:|-------------:|-------------------------------|
| TA0040 - Impact   | T1486     | -            | Data Encrypted for Impact     |

---

## Hunt Query Logic

Temporal aggregation and volume analysis:
1. Time bucketing: 5-minute buckets
2. Aggregation: Count file operations per process, per host, per bucket
3. Threshold: >100 ops/bucket (tunable)
4. Exclusions: Known backup/sync apps and service accounts

Key criteria:
- >100 file operations in 5 minutes (tune by role/baseline)
- Non-standard executables driving volume
- Optional exclusions for backup/sync tools and service accounts

---

## Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Title: Rapid Mass File Modification Indicating Ransomware Encryption
// Description: Detects processes performing rapid, high-volume file modifications across 5-minute buckets.
// MITRE ATT&CK: T1486

| #repo="base_sensor" event_platform="Win"
| #event_simpleName =~ in(values=["NewFileWritten","FileWritten","FileModified","FileRenamed","NewExecutableWritten","NewScriptWritten"])
| TargetFileName=*

// Pre-aggregation regex exclusion (allowed before groupBy)
| ContextBaseFileName!=/sync/i

// 5-minute buckets (timestamp is ms)
| bucket_number := @timestamp / 30000
| time_bucket := bucket_number * 30000

// Aggregate per process per host per bucket
| groupBy([time_bucket, aid, ComputerName, ContextProcessId, ContextBaseFileName, UserName],
    function=[
    { _op_count := count() }
    ],
    limit=max
)

// High threshold: >100 file operations in 5 minutes (tune as needed)
| _op_count>100

// Post-aggregation exact-value exclusions only (no wildcards/regex)
| ContextBaseFileName!="backup.exe"
| ContextBaseFileName!="robocopy.exe"
| ContextBaseFileName!="veeam.exe"
| ContextBaseFileName!="acronis.exe"
| ContextBaseFileName!="onedrive.exe"
| ContextBaseFileName!="dropbox.exe"
| UserName!="DOMAIN\\BackupSVC"
| UserName!="DOMAIN\\FileServerSVC"

// Enrichment
| severity := "CRITICAL"
| detection_category := "Ransomware - Mass File Encryption"
| risk_score := 100
| mitre_technique := "T1486"

// Output
| select([@timestamp, time_bucket, aid, ComputerName, ContextBaseFileName, ContextProcessId, UserName, _op_count, severity, detection_category, risk_score, mitre_technique])
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                                               | ATT&CK Data Source | Data Component         |
|--------------------|------------------------------------------------------------------------|--------------------|------------------------|
| CrowdStrike Falcon | base_sensor: FileWritten/FileModified/FileRenamed/NewFileWritten, etc. | File               | File Modification/Creation |
| CrowdStrike Falcon | base_sensor: Process (for context)                                     | Process            | Process Creation        |

Field notes:
- Identity: aid (Agent ID), ComputerName; user: UserName
- Process fields: ContextBaseFileName, ContextProcessId; file fields: TargetFileName
- Event selector: #event_simpleName

---

## Execution Requirements
- **Required Permissions:** Typically user-level permissions are sufficient for file encryption.
- **Required Artifacts:** File system event telemetry (creation/modification/rename), process context, and timestamps for time-series analysis.

---

## Considerations
- Threshold tuning by host role (endpoints vs. file servers) and user role (developers, analysts).
- Correlate with file extension changes (e.g., `.Yurei`) and ransom note creation for higher confidence.
- Investigate process image/path for masquerading and unusual execution locations.
- Evaluate directory scope (user dirs vs. entire drives) and network shares.

---

## False Positives
- Backup software and cloud sync clients performing bulk operations
- Build/compile pipelines and developer tools
- Database systems and media processing workflows

Mitigation:
- Maintain allowlists for authorized high-volume tools and service accounts; baseline normal rates.

---

## Recommended Response Actions
1. Isolate affected endpoint (Falcon Host containment).
2. If malicious, terminate offending process.
3. Review process image, path, command line, and parent lineage.
4. Check for ransomware indicators: `.Yurei` files, `_README_Yurei.txt`, VSS/backup deletion, event log wipes, CIM/WMI activity.
5. Scope impact by enumerating affected files and directories; check for lateral spread across hosts.
6. Review network share access for remote encryption attempts.
7. Preserve volatile artifacts (memory, process lists); prepare for recovery.
8. Restore from immutable/air-gapped backups if encryption confirmed.
9. Rotate credentials and hunt for similar patterns across the estate; consider Falcon OverWatch escalation.

---

## Enhanced Detection: File Extension Monitoring

```cql
// Supplementary Query: Detect Yurei-specific file extension changes
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.FILE
    and action_file_extension in ("yurei", "Yurei", "YUREI")
| fields _time, agent_hostname, actor_process_image_name, action_file_path, action_file_name
| sort desc _time
```

---

## Enhanced Detection: Ransom Note Creation

```cql
// Supplementary Query: Detect Yurei ransom note creation
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.FILE
    and action_file_name in ("_README_Yurei.txt", "README_Yurei.txt")
| fields _time, agent_hostname, actor_process_image_name, action_file_path, action_file_name
| sort desc _time
```

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)
- [CISA: Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
- [NIST SP 1800-11: Data Integrity – Detecting and Responding to Ransomware](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

---

## Version History

| Version | Date       | Impact              | Notes                                                       |
|---------|------------|---------------------|-------------------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Detection   | Hunt query for mass file encryption (Yurei ransomware)      |

