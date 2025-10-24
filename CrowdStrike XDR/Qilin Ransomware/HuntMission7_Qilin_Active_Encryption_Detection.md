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

This query filters file and registry events to detect Qilin's encryption phase. It identifies ransom note creation, QLOG folder creation, mass file modifications with random extensions, and desktop wallpaper changes. Events are aggregated by actor process and host within 1-minute windows to detect abnormal file modification velocity.

Key points:
- Detect ransom note creation (`README-RECOVER-*.txt`)
- Detect QLOG folder creation
- Detect file modifications with random extensions (10+ alphanumeric characters)
- Detect desktop wallpaper changes by non-system processes
- Aggregate events in 1-minute windows
- Correlate high-confidence indicators (ransom note, QLOG, mass encryption)

---

#### Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Qilin — Active File Encryption & Ransomware Artifacts (fixed negated regex syntax)
// MITRE: T1486
| #repo="base_sensor" event_platform="Win"

// Limit to file + registry families we care about
| (
    #event_simpleName="NewFileWritten" or
    #event_simpleName="FileWritten" or
    #event_simpleName="FileRename" or
    #event_simpleName="NewExecutableWritten" or
    #event_simpleName="NewScriptWritten" or
    #event_simpleName="RegistrySetValue"
  )

// Initialize flags (0/1)
| ransom_note_created := 0
| qlog_folder_created := 0
| encrypted_file_pattern := 0
| wallpaper_change := 0

// Phase 1: Ransom note creation (README-RECOVER-*.txt)
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten") and
    FileName=/^README-RECOVER-.*\.txt$/i
  ) | ransom_note_created := 1

// Phase 2: QLOG folder creation (path contains \QLOG or \Temp\QLOG)
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten") and
    (FilePath=/\\QLOG/i or FilePath=/\\Temp\\QLOG/i or TargetFilePath=/\\QLOG/i or TargetFilePath=/\\Temp\\QLOG/i)
  ) | qlog_folder_created := 1

// Phase 3: Files with long/random extensions (>=10 alphanumeric/underscore chars)
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="FileRename") and
    FileExtension=/^[A-Za-z0-9_]{10,}$/i
  ) | encrypted_file_pattern := 1

// Phase 4: Desktop wallpaper change by non-system process (Registry set)
| (
    #event_simpleName="RegistrySetValue" and
    RegistryKeyPath=/Control Panel\\Desktop/i and
    RegistryValueName=/Wallpaper/i and
    not (ImageFileName=/explorer\.exe$/i) and
    not (ImageFileName=/SystemSettings\.exe$/i)
  ) | wallpaper_change := 1

// Aggregate by host, process actor, user in 1-minute windows
| bin _time span = 1m

| groupBy([aid, ComputerName, ImageFilePath, UserName, _time],
    function=[
      { ransom_note_count := sum(ransom_note_created) },
      { qlog_count := sum(qlog_folder_created) },
      { encrypted_file_count := sum(encrypted_file_pattern) },
      { wallpaper_count := sum(wallpaper_change) },
      { unique_file_paths := count(FilePath, distinct=true) }
    ],
    limit=max
  )

// Correlation filter: high-confidence indicators
| ransom_note_count>0 or qlog_count>0 or encrypted_file_count>=50

// Enrichment / classification (highest-priority labels last so they override)
| detection_category := "Suspicious File Modification Pattern"
| encrypted_file_count>=100                                     | detection_category := "Mass File Encryption"
| qlog_count>0 and encrypted_file_count>=50                      | detection_category := "Qilin Encryption with QLOG Folder"
| ransom_note_count>0 and encrypted_file_count>=50               | detection_category := "Qilin Ransomware Active Encryption (Critical)"
| ransom_note_count>0                                            | detection_category := "Ransom Note Detected"

// Risk scoring (numeric)
| risk_score := 75
| encrypted_file_count>=100                                      | risk_score := 85
| qlog_count>0 and encrypted_file_count>=50                      | risk_score := 95
| ransom_note_count>0 and encrypted_file_count>=50               | risk_score := 100
| ransom_note_count>0                                             | risk_score := 90

// Output
| select([
    aid,
    ComputerName,
    _time,
    ImageFilePath,
    UserName,
    ransom_note_count,
    qlog_count,
    encrypted_file_count,
    wallpaper_count,
    unique_file_paths,
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
| CrowdStrike Falcon      | base_sensor: Registry                                     | Registry          |  Registry Modification      |
| CrowdStrike Falcon      | base_sensor: NewFileWritten/FileWritten (file telemetry) | File               | File Creation/Write    |

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
