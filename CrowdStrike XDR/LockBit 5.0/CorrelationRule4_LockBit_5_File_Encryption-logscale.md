# Detection of File Encryption with 16-Character Extensions

## Severity or Impact of the Detected Behavior
- **Risk Score:** 93 (≥10 files encrypted with LockBit-style 16-char extensions)
- **Severity:** High–Critical

## Analytics Metadata
- **ID:** CorrelationRule-Windows-FileEncryption-16CharExt
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low (≥10 encrypted files per host/process in high-value dirs)
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Analytics
High-confidence detection of ransomware encryption based on files renamed/written with random 16-character extensions across high-value directories and file types.

Detected behaviors:
- Suspicious file renames/writes ending with .<16char>
- Targeting sensitive file types: documents, spreadsheets, presentations, media, archives, email/data (e.g., .docx, .xlsx, .pdf, .pst, .ost, .sql, .db)
- Targeting user directories: Documents, Desktop, Downloads, Pictures, Videos
- Mass encryption per process/host: alert only when a process encrypts ≥10 unique files

---

## ATT&CK Mapping

| Tactic  | Technique | Subtechnique | Technique Name                      |
|---------|----------:|-------------:|-------------------------------------|
| Impact  | T1486     | -            | Data Encrypted for Impact           |
| Impact  | T1489     | -            | Service Stop (follow-on tactic)     |

---

## Query Logic
- Require Windows FILE telemetry
- Focus on WRITE, RENAME, CREATE_NEW
- Match LockBit-like 16-char extensions via regex
- Restrict to high-value file types/locations
- Aggregate per process/host/user; fire when ≥10 files encrypted

---

## Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Detects file encryption activities with ≥10 suspicious 16-character extensions per process/host

| #repo="base_sensor" event_platform="Win"

// Limit to file write/rename/create families
| (
    #event_simpleName="NewFileWritten" or
    #event_simpleName="FileWritten" or
    #event_simpleName="FileRename" or
    #event_simpleName="NewExecutableWritten" or
    #event_simpleName="NewScriptWritten"
  )

// Pre-filter: candidate events (16-char extension in name or path, or any rename with a dot)
| (
    (FileName=/\\.([A-Za-z0-9]{16})$/ or TargetFileName=/\\.([A-Za-z0-9]{16})$/) or
    (#event_simpleName="FileRename" and (FileName=/\\./ or TargetFileName=/\\./))
  )

// Flag 16-char extensions (no functions in guards)
| is_16_char_extension := 0
| (FileName=/\\.([A-Za-z0-9]{16})$/ or TargetFileName=/\\.([A-Za-z0-9]{16})$/) | is_16_char_extension := 1
| is_16_char_extension=1

// High-value filetypes/locations to focus context
| (
    FileName=/\\.(doc|docx|xls|xlsx|ppt|pptx|pdf|jpg|jpeg|png|gif|bmp|mp4|avi|mkv|mp3|wav|zip|rar|7z|sql|db|mdb|pst|ost)$/i or
    TargetFileName=/\\.(doc|docx|xls|xlsx|ppt|pptx|pdf|jpg|jpeg|png|gif|bmp|mp4|avi|mkv|mp3|wav|zip|rar|7z|sql|db|mdb|pst|ost)$/i or
    TargetFilePath=/\\(Documents|Desktop|Downloads|Pictures|Videos)\\?/i
  )

// Aggregate per process on a host
| groupBy([aid, ComputerName, UserName, ContextBaseFileName, ContextProcessId, CommandLine],
    function=[
        { file_count_by_process := count(FileName, distinct=true) }
    ],
    limit=max
)

// Threshold: at least 10 unique files
| file_count_by_process>=10

// Output
| select([
    ComputerName,
    UserName,
    ContextBaseFileName,
    CommandLine,
    file_count_by_process,
    aid
])
| sort([file_count_by_process], order=desc)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon) | ATT&CK Data Source | Data Component                    |
|--------------------|--------------------------|--------------------|-----------------------------------|
| CrowdStrike Falcon | base_sensor              | File               | File Write / File Rename / Create |

---

## Execution Requirements
- Required Telemetry: File write/rename events with full file path & name
- Permissions: Standard process/file monitoring

---

## Considerations
- Threshold of ≥10 encrypted files reduces false positives while surfacing impactful ransomware
- Focusing on user data directories prioritizes sensitive business data

---

## False Positives
- Rare: legitimate bulk-renaming scripts producing 16-char suffixes
- Possible admin/security tests

Mitigations:
- Validate against change windows
- Maintain allowlists for sanctioned scripts/tools

---

## Recommended Response Actions
1. Immediately isolate the host from the network
2. Collect forensic evidence of the encrypting process and command line
3. Quarantine associated binaries
4. Search enterprise-wide for the same process/command line
5. Restore from backups and verify integrity
6. Initiate ransomware incident response playbook

---

## References
- [MITRE ATT&CK T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK T1489 – Service Stop](https://attack.mitre.org/techniques/T1489/)

---

## Version History

| Version | Date       | Impact                                | Notes                                   |
|---------|------------|---------------------------------------|-----------------------------------------|
| 1.0     | 2025-10-03 | Initial Release of File Encryption    | Detect mass encryption with 16‑char ext |
