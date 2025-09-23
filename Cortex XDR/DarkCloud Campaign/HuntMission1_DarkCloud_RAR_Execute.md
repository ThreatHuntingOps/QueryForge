# Detection of RAR Extraction Followed by Execution From Temp/AppData

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-DarkCloud-RAR-Execute
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects a common initial access and execution pattern associated with the DarkCloud campaign. 
The malware is delivered via phishing emails containing RAR attachments. Once opened, `winrar.exe` or `unrar.exe` 
extracts payloads into staging directories like `%temp%` or `%appdata%`. Shortly after extraction, a malicious 
executable or script (`.exe`, `.js`, `.vbs`, `.cmd`, `.bat`, `.dll`) is launched from those directories. 

Detected behaviors include:

- Execution of `winrar.exe`, `unrar.exe`, or `rar.exe` processes.  
- File extraction into `%temp%` or `%appdata%`.  
- Process creation from newly extracted files within a short timeframe.  

These techniques align with phishing delivery and user execution of malicious files.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                               |
|-------------------------------|-------------|--------------|---------------------------------------------|
| TA0001 – Initial Access       | T1566.001   | —            | Phishing: Spearphishing Attachment          |
| TA0002 – Execution            | T1204.002   | —            | User Execution: Malicious File              |

---

## Hunt Query Logic

This query identifies suspicious payload execution by correlating archive extraction activity with 
new process launches from the extracted file’s location within a 5‑minute window.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: RAR Extraction -> Execute From Temp/AppData
// Description: Finds winrar.exe/unrar.exe extracting to temp/appdata and a new process launching from the same path within 5 minutes.
// MITRE ATT&CK TTP ID: T1566.001 (Phishing: Spearphishing Attachment)
// MITRE ATT&CK TTP ID: T1204.002 (User Execution: Malicious File)

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type in (ENUM.PROCESS, ENUM.FILE) 
  and agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter ( 
      (event_sub_type = ENUM.PROCESS_START and action_process_image_name in ("winrar.exe", "unrar.exe", "rar.exe")) 
      or 
      (event_sub_type = ENUM.FILE_STAT  
       and ( 
            action_file_path contains "\\temp\\"  
         or action_file_path contains "\\appdata\\"  
         or action_file_path contains "\\appdata\\local\\"  
         or action_file_path contains "\\appdata\\roaming\\" 
       ) 
       and ( 
            action_file_name contains ".exe" 
         or action_file_name contains ".js" 
         or action_file_name contains ".vbs" 
         or action_file_name contains ".cmd" 
         or action_file_name contains ".bat" 
         or action_file_name contains ".dll" 
       ) 
      ) 
) 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, action_file_path, action_file_name, event_id, agent_id, _product 
| sort desc _time 
```

---

## Data Sources

| Log Provider   | Event Name  | ATT&CK Data Source | ATT&CK Data Component |
|----------------|-------------|--------------------|------------------------|
| Cortex XSIAM   | xdr_data    | Process            | Process Creation       |
| Cortex XSIAM   | xdr_data    | File               | File Metadata          |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to open RAR archives and execute extracted files.  
- **Required Artifacts:** Process creation logs, file metadata, and command-line arguments.  

---

## Considerations

- Review if the extracted files are part of legitimate software installations.  
- Correlate with email security logs to confirm delivery of suspicious RAR attachments.  
- Investigate the parent process tree to validate if execution followed immediately after extraction.  

---

## False Positives

False positives may occur if:  

- Users frequently extract legitimate software packages with WinRAR/UnRAR into `%temp%` or `%appdata%`.  
- IT or deployment scripts temporarily extract executables into these directories during normal operations.  

---

## Recommended Response Actions

1. Investigate the extracted file’s hash and reputation.  
2. Review the email source that delivered the RAR attachment.  
3. Capture process tree and timeline to confirm suspicious behavior.  
4. Isolate the endpoint if execution is determined to be malicious.  
5. Initiate credential reset and containment playbooks if compromise is confirmed.  

---

## References

- [MITRE ATT&CK: T1566.001 – Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)  
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)  
- [Fortinet: Unveiling a New Variant of the DarkCloud Campaign](https://www.fortinet.com/blog/threat-research/unveiling-a-new-variant-of-the-darkcloud-campaign)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-17 | Initial Detection | Created hunt query for RAR extraction followed by execution from Temp/AppData |
