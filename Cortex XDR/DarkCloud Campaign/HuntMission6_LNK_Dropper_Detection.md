# Detection of LNK Shortcut Dropper to Script/LOLBIN in Startup/Temp

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-LNK-Dropper-Startup-Temp
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt identifies the creation of `.lnk` files in Startup/Temp directories that point to script interpreters or user-writable paths. This behavior is often associated with DarkCloud loaders, which use `.lnk` shortcuts for persistence or delayed execution. Detected behaviors include:

- Creation of `.lnk` files in Startup/Temp directories
- `.lnk` files targeting LOLBINs or user-writable paths

These techniques are commonly used for persistence, payload delivery, or command and control.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0003 - Persistence          | T1547.009   | —            | Shortcut Modification                         |

---

## Hunt Query Logic

This query identifies suspicious `.lnk` file creation by looking for:

- `.lnk` files created in Startup/Temp directories
- `.lnk` files pointing to LOLBINs or user-writable paths

These patterns are indicative of attempts to establish persistence or execute malicious payloads.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: LNK Dropper in Startup/Temp 
// Description: Detects .lnk files created in Startup/Temp pointing to LOLBINs or user-writable paths. 
// MITRE ATT&CK TTP ID: T1547.009 (Shortcut Modification) 

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS  
| filter event_type = FILE 
| filter action_file_name contains "*.lnk" 
| filter action_file_path contains "\appdata\" 
    or action_file_path contains "\temp\" 
    or action_file_path contains "\programdata\" 
    or action_file_path contains "\users\\public\" 
    or action_file_path contains "\startup\" 
    or action_file_path contains "\start menu\programs\startup\" 
| fields _time, agent_hostname, actor_effective_username, action_file_path, action_file_name, action_file_md5, action_file_sha256,   
         action_file_size, action_file_attributes, action_process_image_name, actor_process_image_name, 
         event_id, agent_id, _product   
```
---
## Data Sources
| Log Provider | Event Name   | ATT&CK Data Source | ATT&CK Data Component         |
|--------------|--------------|--------------------|-------------------------------|
| Cortex XSIAM | xdr_data     | File               |File Creation                  |	

---

## Execution Requirements
- **Required Permissions:** User or attacker must be able to create .lnk files in Startup/Temp directories.
- **Required Artifacts:** File creation logs, .lnk file metadata, and process execution records.

---

## Considerations
- Review the source and context of the .lnk file for legitimacy.
- Correlate with user activity or system logs to determine if the activity is user-initiated or automated.
- Investigate any processes or scripts executed by the .lnk file for signs of malicious payload delivery or C2.
- Validate if the target path of the .lnk file is associated with known malicious infrastructure or threat intelligence indicators.

---

## False Positives
False positives may occur if:

- Users or IT staff legitimately create .lnk files in Startup/Temp directories for benign purposes.
- Automated tools or scripts generate .lnk files for legitimate operations.
- Recommended Response Actions
- Investigate the .lnk file and its target path for intent and legitimacy.
- Analyze any processes or scripts executed by the .lnk file for signs of malicious activity.
- Review user activity and system logs for signs of compromise or C2.
- Isolate affected endpoints if malicious activity is confirmed.
- Block or monitor access to suspicious .lnk files and their target paths.

---

## References
[MITRE ATT&CK: T1547.009 – Shortcut Modification](https://attack.mitre.org/techniques/T1547/009/)

---

## Version History
| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-08-18 | Initial Detection | Created hunt query to detect LNK shortcut droppers in Startup/Temp directories|
	
