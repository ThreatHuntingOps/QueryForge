# Data Staging and Collection Activities

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (WinRAR staging with archive creation)  
- **Severity:** Critical  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-DataStaging-Collection  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low (WinRAR argument signature is highly specific)  

---

## Analytics

This correlation rule detects **data collection and staging activity** typically seen in the **exfiltration preparation phase** of an intrusion.  

Detected behaviors include:  

- **Malicious WinRAR usage:** with highly distinctive arguments (`a -ep1 -scul -r0 -iext -imon1 --`) to compress sensitive data.  
- **Suspicious archive creation:** `.rar`, `.zip`, or `.7z` files named for financial, HR, or sensitive datasets, often exceeding 100MB.  
- **Automated collection tool execution:** (`FS64.exe`, known data harvester binaries with names containing collect/gather/harvest).  
- **Systematic file access patterns:** scraping of data from shared directories containing business-sensitive materials (HR, legal, finance).  
- **Staging activity:** archives and sensitive files placed into **temp**, **collection**, or **staging** directories.  

Detection requires **multiple overlapping behaviors** (WinRAR + suspicious archives, Collection tool + systematic access, etc.), ensuring high-confidence results.

---

## ATT&CK Mapping

| Tactic      | Technique | Subtechnique | Technique Name                                 |
|-------------|-----------|--------------|-----------------------------------------------|
| Collection  | T1560     | T1560.001    | Archive Collected Data: Archive via Utility   |
| Collection  | T1005     | -            | Data from Local System                        |
| Collection  | T1039     | -            | Data from Network Shared Drive                |
| Collection  | T1119     | -            | Automated Collection                          |

---

## Query Logic

This analytic correlates **sensitive file harvesting + compression behaviors** via WinRAR and known collection tools.  
It prioritizes signals with **WinRAR staging + suspicious archives**, or automated file harvesting activity.  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Hunt for data collection and staging activities using WinRAR and collection tools
// Targets T1560.001 - Archive via Utility, T1005 - Data from Local System, T1039 - Network Shared Drive

config case_sensitive = false  
| dataset = xdr_data  
| filter event_type in (PROCESS, FILE) 

// Phase 1: Detect malicious WinRAR usage 
| alter malicious_winrar = if( 
        event_type = PROCESS and 
        actor_process_image_name contains "winrar.exe" and 
        (actor_process_command_line contains "-ep1" or 
        actor_process_command_line contains "-scul" or
        actor_process_command_line contains "-r0" or
        actor_process_command_line contains "-iext" or
        actor_process_command_line contains "-imon1"),
        true, false 
  ) 

// Phase 2: Detect creation of suspicious archive files 
| alter suspicious_archive_creation = if( 
        event_type = FILE and 
        action_file_name ~= ".*\.(rar|zip|7z)$" and 
        (action_file_name contains "finance" or 
         action_file_name contains "data" or 
         action_file_name contains "backup" or 
         action_file_name contains "share" or 
         action_file_size > 100000000),   // >100MB
        true, false 
  ) 

// Phase 3: Detect known/heuristic collection tools 
| alter collection_tools = if( 
        event_type = PROCESS and 
        (actor_process_image_name contains "fs64.exe" or 
         actor_process_image_name ~= ".*collect.*\.exe$" or 
         actor_process_image_name ~= ".*gather.*\.exe$" or 
         actor_process_image_name ~= ".*harvest.*\.exe$"), 
        true, false 
  ) 

// Phase 4: Detect systematic file access patterns 
| alter systematic_file_access = if( 
        event_type = FILE and 
        (action_file_path contains "\\Shares\\" or 
         action_file_path contains "\\Share\\") and 
        (action_file_name ~= ".*(finance|accounting|hr|legal|contract|confidential|sensitive).*" or 
         action_file_name ~= ".*\.(doc|docx|xls|xlsx|pdf|ppt|pptx)$"), 
        true, false 
  ) 

// Phase 5: Detect staging activity in common temp/collection dirs 
| alter staging_activity = if( 
        event_type = FILE and 
        (action_file_path contains "temp" or 
         action_file_path contains "staging" or 
         action_file_path contains "collection") and 
        action_file_name ~= ".*\.(rar|zip|7z|txt|log)$", 
        true, false 
  ) 

// Correlation Filter: require multiple signals 
| filter (malicious_winrar = true and suspicious_archive_creation = true) 
      or (collection_tools = true and systematic_file_access = true) 
      or (systematic_file_access = true and staging_activity = true) 

// Enrich with detection context 
| alter detection_category = if(malicious_winrar = true and suspicious_archive_creation = true, "WinRAR Data Staging", 
                           if(collection_tools = true and systematic_file_access = true, "Automated Collection + Harvesting", 
                           if(systematic_file_access = true and staging_activity = true, "Data Harvest with Staging", 
                           if(malicious_winrar = true, "Malicious WinRAR Usage", 
                           if(suspicious_archive_creation = true, "Suspicious Archive Creation", 
                           if(collection_tools = true, "Collection Tool Execution", 
                           "Generic Data Collection")))))), 
       risk_score = if(malicious_winrar = true and suspicious_archive_creation = true, 95, 
                  if(collection_tools = true and systematic_file_access = true, 90, 
                  if(systematic_file_access = true and staging_activity = true, 85, 
                  if(malicious_winrar = true, 80, 
                  if(suspicious_archive_creation = true, 75, 
                  if(collection_tools = true, 70, 60)))))) 

// Output Fields 
| fields _time, 
         agent_hostname, 
         actor_process_image_name, 
         actor_process_command_line, 
         action_file_path, 
         action_file_name, 
         action_file_size, 
         detection_category, 
         risk_score, 
         event_type 

| sort desc risk_score, desc _time 
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component       |
|----------------|------------|--------------------|-----------------------------|
| Cortex XSIAM   | xdr_data   | File               | File Write / File Creation  |
| Cortex XSIAM   | xdr_data   | Process            | Process Creation            |

---

## Execution Requirements  
- **Required Permissions:** User-level sufficient; elevated not always required.  
- **Required Artifacts:** File and process telemetry.  

---

## Considerations  
- Use of **WinRAR with these flags** is nearly always malicious.  
- Automated collection tools (FS64.exe, collect/gather utilities) are not part of normal enterprise workloads.  
- Staging in temp/collection folders strongly indicates preparation for exfiltration.  

---

## False Positives  
- Very rare; potential overlap may occur if administrators manually perform bulk archive operations with WinRAR (unlikely with these specific flags).  

---

## Recommended Response Actions  
1. **Isolate systems** showing WinRAR staging behaviors.  
2. **Block or quarantine suspicious archives**, and monitor for outbound transfer attempts.  
3. **Hunt for FS64.exe or other collection tools** across the enterprise.  
4. **Inspect shared directories accessed by the affected host** for anomaly patterns.  
5. **Correlate with network logs** to detect potential exfiltration events.  

---

## References  
- [MITRE ATT&CK: T1560.001 – Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)  
- [MITRE ATT&CK: T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/)  
- [MITRE ATT&CK: T1039 – Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039/)  
- [MITRE ATT&CK: T1119 – Automated Collection](https://attack.mitre.org/techniques/T1119/)  

---

## Version History  

| Version | Date       | Impact                  | Notes                                                    |
|---------|------------|-------------------------|----------------------------------------------------------|
| 1.0     | 2025-09-18 | Initial Detection       | Added correlation for WinRAR staging and automated tools.|
