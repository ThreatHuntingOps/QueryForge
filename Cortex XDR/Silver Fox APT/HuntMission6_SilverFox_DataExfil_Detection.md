# Silver Fox APT - Data Gathering and Exfiltration Activities Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-SilverFox-DataExfil
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects data collection and exfiltration activities performed by Silver Fox APT's ValleyRAT payload. It identifies file access patterns consistent with data harvesting and the creation of staging directories. The query focuses on detecting the systematic collection of sensitive files, credential harvesting, and the preparation of data for exfiltration to command and control infrastructure. Detected behaviors include:

- File access to sensitive documents in Documents, Desktop, or Downloads folders with extensions like doc, docx, pdf, xls, xlsx, ppt, pptx, txt
- Creation of archive files (zip, rar, 7z) in Temp directories for staging

These techniques are associated with data collection from local systems, input capture, archiving data, and exfiltration over C2 channels.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0009 - Collection          | T1005       |              | Data from Local System                        |
| TA0009 - Collection          | T1056       | T1056.001    | Input Capture: Keylogging                     |
| TA0010 - Exfiltration        | T1041       |              | Exfiltration Over C2 Channel                  |
| TA0009 - Collection          | T1560       |              | Archive Collected Data                        |

---

## Hunt Query Logic

This query identifies data collection and exfiltration by looking for:

- File events accessing sensitive files in user directories from suspicious processes
- File events creating archive files in Temp directories from suspicious processes

These patterns are indicative of Silver Fox APT's ValleyRAT gathering and staging data for exfiltration.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
dataset = xdr_data  
| filter event_type = ENUM.FILE or event_type = ENUM.NETWORK  
| filter (  
    // Detect suspicious file access patterns for data collection  
    (event_type = ENUM.FILE and (  
        (action_file_path contains "\Documents\" or   
         action_file_path contains "\Desktop\" or  
         action_file_path contains "\Downloads\") and  
        (action_file_extension in ("doc", "docx", "pdf", "xls", "xlsx", "ppt", "pptx", "txt") and  
         actor_process_image_path contains "\Program Files\RunTime\")  
    )) or  
    // Detect staging directory creation  
    (event_type = ENUM.FILE and (  
        action_file_path contains "\Temp\" and  
        action_file_name ~= ".*\.(zip|rar|7z)$" and  
        actor_process_image_path contains "\Program Files\RunTime\"  
    ))  
)  
| fields event_timestamp, event_type, action_file_path, action_file_extension,  
         actor_process_image_name, actor_process_image_path, action_remote_ip 
| sort desc event_timestamp 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM|    xdr_data       | File               | File Access            |
| Cortex XSIAM|    xdr_data       | Network Traffic    | Network Connection Creation |

---

## Execution Requirements

- **Required Permissions:** File system access to read sensitive files and create archives.
- **Required Artifacts:** File access logs, file creation logs, network logs.

---

## Considerations

- Review the files accessed and created for sensitivity and context.
- Correlate with user activity to determine if access is legitimate.
- Investigate network connections for exfiltration attempts.
- Validate if the processes are associated with known RAT behaviors or threat intelligence indicators.

---

## False Positives

False positives may occur if:

- Legitimate applications access user documents.
- Benign archiving tools create zip/rar files in Temp.
- User-initiated file operations from similar paths.

---

## Recommended Response Actions

1. Investigate the file access and creation for intent and legitimacy.
2. Analyze network activity for signs of exfiltration.
3. Review collected data for sensitive information.
4. Isolate affected endpoints if data exfiltration is confirmed.
5. Block or monitor suspicious file operations and network transfers.

---

## References

- [MITRE ATT&CK: T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [MITRE ATT&CK: T1056.001 – Input Capture: Keylogging](https://attack.mitre.org/techniques/T1056/001/)
- [MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK: T1560 – Archive Collected Data](https://attack.mitre.org/techniques/T1560/)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-09-04 | Initial Detection | Created hunt query to detect Silver Fox APT data collection and exfiltration             |
