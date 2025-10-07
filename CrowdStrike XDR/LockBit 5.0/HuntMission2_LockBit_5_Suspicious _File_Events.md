# Hunting for Suspicious File Events with 16-Character Randomized Extensions

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85  
- **Severity:** High  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-16CharExt-FileEvents  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low (restricted to high-value filetypes and directories)  

---

## Hunt Analytics

This hunting query surfaces **all file events with randomized 16-character extensions** across high-value filetypes and directories.  
This pattern is strongly correlated with **ransomware encryption activity**, such as **LockBit 5.0**, which appends randomized extensions during file encryption for impact.  

Detected behaviors include:  
- **File writes and renames with 16-character random suffixes.**  
- **Targeting high-value directories:** `Documents`, `Desktop`, `Downloads`, `Pictures`, `Videos`.  
- **Encryption of critical file types:** productivity documents, media files, archives, and databases (`docx`, `xlsx`, `pptx`, `pdf`, `pst`, `db`, `sql`, etc.).  

This query provides a **broad hunting view** (not thresholded by counts) to **support investigation** and **confirmation of ransomware activity** across environments.  

---

## ATT&CK Mapping

| Tactic  | Technique | Subtechnique | Technique Name                   |
|---------|-----------|--------------|----------------------------------|
| Impact  | T1486     | -            | Data Encrypted for Impact        |

---

## Hunt Query Logic

The query logic focuses on files that match ransomware-style encryption:  
1. File event types = WRITE, RENAME, CREATE_NEW.  
2. Extension matches a **16-character randomized string**.  
3. Path or file type falls under **high-value business or personal files**.  
4. Results enumerate every **file event** with context (hostname, user, process, file path, event subtype).  

Unlike correlation rules, this view does not require **aggregation thresholds** (e.g., ≥10 encrypted files). It is intended for **forensic hunts and triage**.  

---

## Hunt Query Syntax

**Query Language:** CrowdStrike Query Language 
**Platform:** CrowdStrike Falcon

```fql
// Hunting view for all suspicious file events with 16-character randomized extensions

// Filter to Windows file activity events
#event_simpleName="*File*"
| event_platform="Win"

// Match 16-char alphanumeric extension in TargetFileName or FilePath
| (
    TargetFileName=/\.([a-zA-Z0-9]{16})$/
    or FilePath=/\.([a-zA-Z0-9]{16})$/
  )

// Extract the extension and validate it's exactly 16 characters
| regex(field=TargetFileName, regex="\\.(?<extension>[a-zA-Z0-9]{16})$", strict=false)
| eval(ext_length=length(extension))
| where ext_length=16

// Filter for high-value file types or user directories (common ransomware targets)
| (
    TargetFileName=/(?i)\.(doc|docx|xls|xlsx|ppt|pptx|pdf|jpg|jpeg|png|gif|bmp|mp4|avi|mkv|mp3|wav|zip|rar|7z|sql|db|mdb|pst|ost)\./
    or FilePath=/Documents/i
    or FilePath=/Desktop/i
    or FilePath=/Downloads/i
    or FilePath=/Pictures/i
    or FilePath=/Videos/i
  )

// Output fields
| table([
    @timestamp,
    aid,
    ComputerName,
    UserName,
    TargetFileName,
    FilePath,
    extension,
    ext_length,
    ContextProcessId,
    ImageFileName,
    CommandLine,
    #event_simpleName,
    event_id
  ], limit=1000)
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Falcon         | xdr_data   | File               | File Write / File Rename / File Creation |

---

## Execution Requirements  
- **Required Permissions:** File activity telemetry must be enabled.  
- **Required Artifacts:** Detailed file paths, extensions, event subtype.  

---

## Considerations  
- THIS QUERY IS FOR HUNTING/TRIAGE – it may return a very large number of results.  
- Best used during **incident response** to validate suspicious hosts and encryption progression.  

---

## False Positives  
- Extremely rare. Legitimate software rarely generates truly randomized 16-character extensions.  
- Potential corner case: temporary files created by compression or testing tools – should be validated by analyst.  

---

## Recommended Response Actions  
1. Investigate affected hosts and processes for encryption activity.  
2. Collect forensic artifacts (sample encrypted files, process binaries).  
3. Cross-reference with correlated detections such as **service termination** or **persistence indicators**.  
4. Isolate host(s) to prevent further encryption spread.  
5. Begin recovery efforts (restore from backups, coordinate ransomware response).  

---

## References  
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)  

---

## Version History  

| Version | Date       | Impact                        | Notes                                        |
|---------|------------|-------------------------------|----------------------------------------------|
| 1.0     | 2025-10-07 | Initial release of hunt query | Broad hunting view for encrypted file events |
