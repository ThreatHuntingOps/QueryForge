# Active Encryption and Ransom Note Creation

#### Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** Critical

#### Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Qilin-Active-Encryption
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low

---

#### Hunt Analytics

This hunt detects the final impact phase of Qilin ransomware: active file encryption and ransom note creation. The query identifies multiple high-fidelity indicators including mass file modifications with random extensions, creation of `README-RECOVER-*.txt` ransom notes, and QLOG folder creation. It aggregates file events within 1-minute windows to detect abnormal file modification velocity.

Detected behaviors include:

- Creation of ransom notes matching the pattern `README-RECOVER-*.txt`
- Creation of QLOG folders (Qilin-specific artifact)
- Mass file modifications with random extensions (10+ alphanumeric characters)
- Desktop wallpaper changes by non-system processes (optional defacement indicator)

This is the final impact phase and requires immediate incident response.

---

#### ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1486       | -            | Data Encrypted for Impact                     |
| TA0040 - Impact              | T1491.001   | -            | Defacement: Internal Defacement                |

---

#### Hunt Query Logic

This XQL query filters file and registry events to detect Qilin's encryption phase. It identifies ransom note creation, QLOG folder creation, mass file modifications with random extensions, and desktop wallpaper changes. Events are aggregated by actor process and host within 1-minute windows to detect abnormal file modification velocity.

Key points:
- Detect ransom note creation (`README-RECOVER-*.txt`)
- Detect QLOG folder creation
- Detect file modifications with random extensions (10+ alphanumeric characters)
- Detect desktop wallpaper changes by non-system processes
- Aggregate events in 1-minute windows
- Correlate high-confidence indicators (ransom note, QLOG, mass encryption)

---

#### Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR / XSIAM

```xql
// Hunt for active file encryption and ransomware artifacts
// Targets T1486 - Data Encrypted for Impact

config case_sensitive = false
| dataset = xdr_data
| filter event_type in (ENUM.FILE, ENUM.REGISTRY)
| filter event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_RENAME, ENUM.FILE_DIR_CREATE)

// Phase 1: Detect ransom note creation (highly specific)
| alter ransom_note_created = if(
        event_type = ENUM.FILE and
        action_file_name ~= "README-RECOVER-.*\.txt",
        1, 0
  )

// Phase 2: Detect QLOG folder creation (Qilin-specific)
| alter qlog_folder_created = if(
    event_sub_type = ENUM.FILE_DIR_CREATE and
    action_file_path != null and
    (action_file_path contains "\QLOG" or action_file_path contains "\Temp\QLOG"),
    1, 0
)

// Phase 3: Detect file modifications with random extensions (10+ alphanumeric characters)
| alter encrypted_file_pattern = if(
        event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_RENAME) and
        action_file_extension ~= "^[A-Za-z0-9_]{10,}$",
        1, 0
  )

// Phase 4: Detect desktop wallpaper modification by non-system processes
| alter wallpaper_change = if(
    event_type = ENUM.REGISTRY and
    event_sub_type = ENUM.REGISTRY_SET_VALUE and
    action_registry_key_name != null and
    action_registry_value_name != null and
    action_registry_key_name contains "Control Panel\Desktop" and
    action_registry_value_name contains "Wallpaper" and
    actor_process_image_name != null and
    actor_process_image_name != "explorer.exe" and
    actor_process_image_name != "SystemSettings.exe",
    1, 0
)

// Aggregate by actor process and host within 1-minute window
| bin _time span = 1m
| comp sum(ransom_note_created) as ransom_note_count,
       sum(qlog_folder_created) as qlog_count,
       sum(encrypted_file_pattern) as encrypted_file_count,
       sum(wallpaper_change) as wallpaper_count,
       count_distinct(action_file_path) as unique_file_paths,
       values(action_file_name) as sample_files
  by agent_hostname, _time, actor_process_image_path, actor_effective_username

// Correlation Filter: High-confidence indicators
| filter ransom_note_count > 0 or qlog_count > 0 or encrypted_file_count >= 50

// Enrichment
| alter detection_category = if(ransom_note_count > 0 and encrypted_file_count >= 50, "Qilin Ransomware Active Encryption (Critical)",
                           if(qlog_count > 0 and encrypted_file_count >= 50, "Qilin Encryption with QLOG Folder",
                           if(ransom_note_count > 0, "Ransom Note Detected",
                           if(encrypted_file_count >= 100, "Mass File Encryption",
                           "Suspicious File Modification Pattern")))),
       risk_score = if(ransom_note_count > 0 and encrypted_file_count >= 50, 100,
                  if(qlog_count > 0 and encrypted_file_count >= 50, 95,
                  if(ransom_note_count > 0, 90,
                  if(encrypted_file_count >= 100, 85, 75))))

// Output
| fields agent_hostname,
         _time,
         actor_process_image_path,
         actor_effective_username,
         ransom_note_count,
         qlog_count,
         encrypted_file_count,
         wallpaper_count,
         unique_file_paths,
         sample_files,
         detection_category,
         risk_score

| sort desc risk_score
```

---

#### Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | File                | File Creation/Modification |
| Cortex       | xdr_data         | Registry            | Registry Modification  |

---

#### Execution Requirements

- **Required Permissions:** Collection of file creation/modification and registry events with full file path and registry key details.
- **Required Artifacts:** File events (creation, rename, write), registry events (SetValue), actor process image path, and effective username.

---

#### Considerations

- This is a high-confidence indicator of active ransomware encryption. Immediate response is required.
- Correlate with other Qilin indicators (VSS deletion, event log clearing, registry persistence) to confirm compromise.
- Preserve affected systems for forensic analysis and avoid further writes to disk.

---

#### False Positives

False positives are extremely unlikely due to the highly specific indicators (ransom note pattern, QLOG folder, random file extensions).

---

#### Recommended Response Actions

1. Immediately isolate affected hosts and preserve systems for forensic analysis.
2. Notify incident response and follow organizational ransomware playbooks.
3. Collect memory dumps and file system images for analysis.
4. Query for related activity (lateral movement, privilege escalation) from the same host or user.
5. Block or quarantine binaries associated with the encryption activity.
6. Begin recovery planning using backups and off-host data copies.

---

#### References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK: T1491.001 – Defacement: Internal Defacement](https://attack.mitre.org/techniques/T1491/001/)

---

#### Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-23 | Initial Detection | Created hunt query to detect Qilin's active file encryption and ransom note creation     |
