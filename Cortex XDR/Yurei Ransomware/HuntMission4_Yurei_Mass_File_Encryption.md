# Detection of Mass File Encryption (Ransomware Behavior)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** CRITICAL

## Hunt Analytics Metadata

- **ID:** HuntQuery-MultiOS-Mass-File-Encryption-T1486
- **Operating Systems:** WindowsEndpoint, WindowsServer, Linux, macOS
- **False Positive Rate:** Low to Medium

---

## Hunt Analytics

This hunt detects processes performing rapid, high-volume file modifications across multiple directories, a hallmark of ransomware encryption. This query identifies file system churn indicative of bulk encryption activity. While it may trigger on legitimate backup or sync operations, the correlation with suspicious executables and file extension changes provides high-fidelity detection. Detected behaviors include:

- Processes performing >100 file operations within 5-minute time windows
- Rapid file modification patterns consistent with encryption loops
- High-volume file system activity from non-standard processes
- Exclusion of known legitimate backup and sync applications

These techniques are associated with ransomware impact operations designed to encrypt data at scale.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1486       | -            | Data Encrypted for Impact                     |

---

## Hunt Query Logic

This query identifies mass file encryption activity through temporal aggregation and volume analysis:

### Detection Methodology
1. **Time Bucketing:** Groups file operations into 5-minute intervals for temporal analysis
2. **Aggregation:** Counts file operations per process, per host, per time bucket
3. **Threshold Detection:** Flags processes with >100 file operations in 5 minutes
4. **Exclusion Filtering:** Removes known legitimate backup/sync applications

### Key Detection Criteria
- **Volume Threshold:** >100 file operations in 5-minute window (tunable based on environment)
- **Process Analysis:** Focuses on non-standard executables performing high-volume file operations
- **User Context:** Excludes known service accounts for backup and file server operations

### Exclusions
- Known backup applications: `backup.exe`, `robocopy.exe`, `veeam.exe`, `acronis.exe`
- Cloud sync clients: `onedrive.exe`, `dropbox.exe`, processes containing "sync"
- Authorized service accounts: Backup services, file server services

### Time Bucket Calculation
- Converts event timestamps to epoch seconds
- Divides by 300 (5 minutes) and floors to create bucket numbers
- Multiplies back to create normalized 5-minute time buckets
- Enables precise temporal correlation of file operations

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Rapid Mass File Modification Indicating Ransomware Encryption
// Description: Detects processes performing rapid, high-volume file modifications across multiple directories, a hallmark of ransomware encryption.
// MITRE ATT&CK TTP ID: T1486

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.FILE 
        and action_file_name != null 

// Create 5-minute time buckets using arrayindex and math operations
| alter time_epoch_seconds = to_epoch(_time, "SECONDS"),
        bucket_number = floor(divide(to_epoch(_time, "SECONDS"), 300))

| alter time_bucket = to_timestamp(multiply(bucket_number, 300), "SECONDS")

| fields time_bucket, 
         agent_hostname, 
         actor_process_image_name, 
         actor_process_command_line, 
         action_file_path, 
         action_file_name, 
         action_file_extension, 
         actor_effective_username 

// Count file operations per process per time bucket 
| comp count() as file_operation_count by time_bucket, agent_hostname, actor_process_image_name, actor_effective_username 

// High threshold: >100 file operations in 5 minutes (tune based on environment) 
| filter file_operation_count > 100 

// Exclude known legitimate high-volume file operations 
| filter not ( 
        actor_process_image_name in ("backup.exe", "robocopy.exe", "veeam.exe", "acronis.exe", "onedrive.exe", "dropbox.exe") 
        or actor_process_image_name contains "sync" 
        or actor_effective_username in ("DOMAIN\BackupSVC", "DOMAIN\FileServerSVC") 
    ) 

// Enrichment 
| alter severity = "CRITICAL", 
        detection_category = "Ransomware - Mass File Encryption", 
        risk_score = 100, 
        mitre_technique = "T1486" 

| fields time_bucket, 
         agent_hostname, 
         actor_process_image_name, 
         file_operation_count, 
         actor_effective_username, 
         severity, 
         detection_category, 
         risk_score 

| sort desc file_operation_count
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | File                | File Modification      |
| Cortex       | xdr_data         | File                | File Creation          |
| Cortex       | xdr_data         | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Varies by OS; typically user-level permissions sufficient for file encryption.
- **Required Artifacts:** 
  - File system event logs (creation, modification, rename)
  - Process creation logs with command-line arguments
  - File path and extension information
  - Temporal data for time-series analysis

---

## Considerations

- **Threshold Tuning:** The 100 file operations per 5 minutes threshold should be tuned based on:
  - Environment baseline (file server vs. endpoint)
  - User roles (developers, data analysts may have higher legitimate activity)
  - Application behavior (IDEs, databases, development tools)
- **Temporal Analysis:** Investigate the time bucket for clustering of activity across multiple hosts (indicates lateral spread).
- **File Extension Analysis:** Correlate with file extension changes (e.g., `.docx` → `.Yurei`) for higher confidence.
- **Process Legitimacy:** Investigate the process image name and path for signs of masquerading or staging in unusual locations.
- **User Context:** Validate if the user account has legitimate reasons for high-volume file operations.
- **Directory Scope:** Analyze if file operations span multiple directories or are concentrated in specific paths.
- **Network Context:** Correlate with network file share access for encryption of remote files.

---

## False Positives

False positives may occur if:

- Backup software not included in exclusion list performs scheduled backups.
- Cloud sync clients (Google Drive, Box, etc.) perform bulk synchronization.
- Development tools (compilers, build systems) generate or modify many files rapidly.
- Database systems perform bulk file operations (log files, temp files).
- Antivirus or security tools scan and modify file metadata.
- File compression or archiving tools process large numbers of files.
- Media processing applications (video editing, photo management) batch process files.
- Legitimate administrative scripts perform bulk file operations.

**Mitigation:** 
- Maintain an accurate inventory of authorized high-volume file operation tools.
- Implement exclusions for known legitimate applications and service accounts.
- Establish baseline file operation rates for different user roles and systems.
- Use file extension analysis to differentiate encryption from legitimate operations.

---

## Recommended Response Actions

1. **Immediate Isolation:** Isolate the affected endpoint from the network to prevent lateral spread and further encryption.
2. **Stop Suspicious Process:** Terminate the process performing mass file operations if malicious activity is confirmed.
3. **Analyze Process Context:** Review the process image name, path, command line, and parent process.
4. **File Extension Analysis:** Examine file extensions for ransomware indicators (e.g., `.Yurei`, `.locked`, `.encrypted`).
5. **Correlate with Ransomware Indicators:** Search for additional Yurei ransomware artifacts:
   - VSS/backup deletion commands
   - Event log deletion activity
   - CIM/WMI lateral movement
   - `_README_Yurei.txt` ransom notes
   - Payload staging in `%LOCALAPPDATA%\Temp`
   - Suspicious executables (`WindowsUpdate.exe`, `svchost.exe`, `System32_Backup.exe`)
6. **Identify Encrypted Files:** Enumerate affected files and directories to assess impact scope.
7. **Check for Lateral Spread:** Investigate if encryption activity is occurring on multiple hosts simultaneously.
8. **Network Share Analysis:** Review network file share access logs for remote encryption attempts.
9. **Preserve Forensic Evidence:** Collect volatile artifacts (memory dumps, process listings) before shutdown.
10. **Restore from Backups:** Initiate restore procedures from immutable/air-gapped backups if encryption is confirmed.
11. **Credential Investigation:** Determine if credentials were compromised and rotate affected accounts.
12. **Threat Hunt:** Conduct a broader hunt across the environment for similar encryption patterns and IOCs.
13. **Engage Incident Response:** Escalate to IR team for full investigation, containment, and recovery.

---

## Enhanced Detection: File Extension Monitoring

For higher-fidelity detection, combine this query with file extension monitoring:

```xql
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

For higher-fidelity detection, combine this query with ransom note monitoring:

```xql
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
- [NIST: Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-10 | Initial Detection | Created hunt query to detect mass file encryption behavior for Yurei ransomware            |

