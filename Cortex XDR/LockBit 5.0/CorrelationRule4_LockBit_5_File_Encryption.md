# Detection of File Encryption with 16-Character Extensions

## Severity or Impact of the Detected Behavior
- **Risk Score:** 93 (≥10 files encrypted with LockBit-style 16-char extensions)  
- **Severity:** High–Critical  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-FileEncryption-16CharExt  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Very Low (strengthened by requiring ≥10 encrypted files per host/process in high-value dirs)  

---

## Analytics

This analytic detects **high-confidence ransomware encryption activity** based on the presence of files renamed/written with **random 16-character extensions** across high-value directories and data file types.  

Detected behaviors include:  

- **Suspicious file renames or writes**: files ending with `.<16char>` extensions.  
- **Targeting sensitive file types**: documents, spreadsheets, presentations, media files, compressed archives, and email/data files (`.docx`, `.xlsx`, `.pdf`, `.pst`, `.ost`, `.sql`, `.db`, etc.).  
- **Targeting user directories**: encryption attempts in `Documents`, `Desktop`, `Downloads`, `Pictures`, `Videos`.  
- **Mass encryption per process/host**: Alert fires only when a process is responsible for encrypting ≥10 unique files.  

This ensures the analytic detects **real LockBit-style encryption events** rather than one-off anomalies.  

---

## ATT&CK Mapping

| Tactic  | Technique | Subtechnique | Technique Name                   |
|---------|-----------|--------------|----------------------------------|
| Impact  | T1486     | -            | Data Encrypted for Impact        |
| Impact  | T1489     | -            | Service Stop (follow-on tactic for impact prevention) |

---

## Query Logic

- Require **Windows file-level telemetry** (event type = FILE).  
- Focus on **events: WRITE, RENAME, CREATE_NEW**.  
- Match **LockBit-like extensions** using regex.  
- Restrict to **file types and locations attractive to attackers**.  
- Aggregate counts by process/host/user; fire alerts only if **≥10 files** are encrypted.  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// Detects file encryption activities with ≥10 suspicious 16-character extensions per process/host 

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type = ENUM.FILE 
| filter event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_RENAME, ENUM.FILE_CREATE_NEW) 

| filter ( 
    action_file_name ~= ".*\.([a-zA-Z0-9]{16})$" 
    or action_file_path ~= ".*\.([a-zA-Z0-9]{16})$" 
    or (event_sub_type = ENUM.FILE_RENAME and action_file_name contains ".") 
) 

// extract ext 
| alter extension_extracted = regextract(action_file_name, "\.([a-zA-Z0-9]{16})$") 

// test true if 16‑char ext 
| alter is_16_char_extension = if(array_length(extension_extracted) > 0 and len(arrayindex(extension_extracted,0)) = 16, true, false) 

| filter is_16_char_extension = true 

// high‑value filetypes/locations 
| filter ( 
    action_file_name ~= "(?i)\.(doc|docx|xls|xlsx|ppt|pptx|pdf|jpg|jpeg|png|gif|bmp|mp4|avi|mkv|mp3|wav|zip|rar|7z|sql|db|mdb|pst|ost)$" 
    or action_file_path contains "Documents" 
    or action_file_path contains "Desktop" 
    or action_file_path contains "Downloads" 
    or action_file_path contains "Pictures" 
    or action_file_path contains "Videos" 
) 

// aggregate suspicious events per process/host 
| comp count_distinct(action_file_name) as file_count_by_process  
       by causality_actor_process_image_name, causality_actor_process_command_line, agent_hostname, actor_effective_username 

| filter file_count_by_process >= 10 

| fields agent_hostname, actor_effective_username, 
    causality_actor_process_image_name, causality_actor_process_command_line, 
    file_count_by_process 

| sort desc file_count_by_process
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component  |
|----------------|------------|--------------------|------------------------|
| Cortex XSIAM   | xdr_data   | File               | File Write / File Rename / File Create |

---

## Execution Requirements  
- **Required Telemetry:** File write/rename events with full file path & name detail.  
- **Permissions:** Standard process monitoring is sufficient.  

---

## Considerations  
- Requiring **≥10 encrypted files** dramatically lowers FP risk while surfacing enterprise-impacting ransomware.  
- Targeting **high-value directories** ensures detection focuses on sensitive business/user data rather than random temp files.  

---

## False Positives  
- Very rare. A legitimate script renaming files with 16-char suffixes (unlikely in enterprise environments).  
- Administrators might test security by renaming files in bulk, but even then unlikely in sensitive directories/file types.  

---

## Recommended Response Actions  
1. **Immediately isolate the host** from the network.  
2. **Collect forensic evidence** of the encrypting process and command line.  
3. **Quarantine associated binaries**.  
4. **Search enterprise-wide** for presence of the same process/command line.  
5. **Restore from backups** and confirm restoration integrity.  
6. **Initiate ransomware incident response playbook**.  

---

## References  
- [MITRE ATT&CK T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)  
- [MITRE ATT&CK T1489 – Service Stop](https://attack.mitre.org/techniques/T1489/)  

---

## Version History  

| Version | Date       | Impact                                | Notes                                   |
|---------|------------|---------------------------------------|-----------------------------------------|
| 1.0     | 2025-10-01 | Initial Release of File Encryption    | Detect mass encryption with 16‑char ext |
