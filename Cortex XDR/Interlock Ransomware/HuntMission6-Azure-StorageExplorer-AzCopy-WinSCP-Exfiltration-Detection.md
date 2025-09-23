# Detection of Azure Storage Explorer, AzCopy, and WinSCP for Data Exfiltration

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-CloudExfil-StorageExplorer-AzCopy-WinSCP
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of Azure Storage Explorer (`StorageExplorer.exe`), AzCopy (`azcopy.exe`), and WinSCP (`winscp.exe`). These tools are frequently abused by threat actors for data collection and exfiltration from compromised environments. Detected behaviors include:

- Use of Storage Explorer to browse or extract data from Azure Storage accounts
- Use of AzCopy to upload or transfer data to Azure blob storage
- Use of WinSCP for file transfer to remote or cloud locations

These activities are associated with data staging, collection, and exfiltration to cloud or remote infrastructure.

---

## ATT&CK Mapping

| Tactic                | Technique   | Subtechnique | Technique Name                                                        |
|-----------------------|-------------|--------------|-----------------------------------------------------------------------|
| TA0009 - Collection   | T1530       | —            | Data from Cloud Storage Object                                        |
| TA0010 - Exfiltration | T1567.002   | —            | Exfiltration to Cloud Storage: Exfiltration to Cloud Storage Service  |
| TA0010 - Exfiltration | T1048       | —            | Exfiltration Over Alternative Protocol                                |

---

## Hunt Query Logic

This query identifies suspicious process launches by looking for:

- Execution of `storageexplorer.exe`, `azcopy.exe`, or `winscp.exe` on Windows endpoints

These patterns are indicative of potential data collection and exfiltration activity.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Azure Storage Explorer, AzCopy, and WinSCP Data Exfiltration Detection
// Description: Detects execution of StorageExplorer.exe, AzCopy, and WinSCP, which are often used for data collection and exfiltration to cloud or remote locations.
// MITRE ATT&CK TTP ID: T1530
// MITRE ATT&CK TTP ID: T1567.002
// MITRE ATT&CK TTP ID: T1048

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS
    and (
        action_process_image_name = "storageexplorer.exe"
        or action_process_image_name = "azcopy.exe"
        or action_process_image_name = "winscp.exe"
    )
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, causality_actor_process_image_sha256, event_id, agent_id, _product
| sort desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to execute file transfer or cloud storage tools.
- **Required Artifacts:** Process creation logs and command-line arguments.

---

## Considerations

- Review the process context and command line for legitimacy.
- Correlate with user activity, cloud storage access logs, and file transfer records to determine if the activity is authorized.
- Investigate any large or unusual data transfers to cloud or remote destinations.

---

## False Positives

False positives may occur if:

- IT staff or legitimate users use these tools for routine cloud storage management or file transfer.
- Automated backup or migration jobs invoke these tools for benign purposes.

---

## Recommended Response Actions

1. Investigate the process and command line for intent and legitimacy.
2. Review cloud storage and file transfer logs for large or suspicious data movements.
3. Correlate with user activity and system logs for signs of unauthorized exfiltration.
4. Isolate affected endpoints if malicious exfiltration is confirmed.
5. Block or monitor suspicious use of Storage Explorer, AzCopy, and WinSCP.

---

## References

- [MITRE ATT&CK: T1530 – Data from Cloud Storage Object](https://attack.mitre.org/techniques/T1530/)
- [MITRE ATT&CK: T1567.002 – Exfiltration to Cloud Storage Service](https://attack.mitre.org/techniques/T1567/002/)
- [MITRE ATT&CK: T1048 – Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [CISA AA25-203A: #StopRansomware: Interlock](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-07-23 | Initial Detection | Created hunt query to detect Azure Storage Explorer, AzCopy, and WinSCP for data exfiltration |
