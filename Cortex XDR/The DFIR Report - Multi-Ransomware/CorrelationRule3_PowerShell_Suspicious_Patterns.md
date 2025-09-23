# Suspicious PowerShell Execution Patterns

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90 (Veeam credential dumping + reconnaissance)  
- **Severity:** High  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-PowerShell-VeeamRecon  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Medium (PowerShell is used legitimately but correlation reduces noise)  

---

## Analytics

This correlation rule detects **malicious PowerShell activity** tied to **Veeam credential dumping** and **Active Directory reconnaissance**.  

Detected behaviors include:  

- **Veeam credential access** by loading `Veeam.Backup.Common.dll` or querying the VeeamBackup database for stored credentials.  
- **AD reconnaissance commands** leveraged to query ADFS endpoints and perform domain enumeration (`get-adobject`, `nltest`, `net user /domain`).  
- **Obfuscated PowerShell usage** with suspicious flags (`-EncodedCommand`, `Invoke-Expression`, `DownloadString`, `Base64`).  

This analytic requires at least **two suspicious indicators together** (e.g., **Veeam DLL + AD recon**, or **Veeam DLL + obfuscation**), which reduces false positives and increases detection fidelity.

---

## ATT&CK Mapping

| Tactic          | Technique | Subtechnique | Technique Name                                      |
|-----------------|-----------|--------------|----------------------------------------------------|
| Execution       | T1059     | T1059.001    | Command & Scripting Interpreter: PowerShell        |
| CredentialAccess| T1003     | T1003.002    | OS Credential Dumping: Security Account Manager    |
| Discovery       | T1087     | T1087.002    | Account Discovery: Domain Account                  |
| Discovery       | T1018     | -            | Remote System Discovery                            |
| Defense Evasion | T1027     | -            | Obfuscated Files or Information                    |

---

## Query Logic

This analytic correlates **PowerShell execution involving Veeam credential dumping, AD reconnaissance, and potential obfuscation**.  
Detections require a **pair of suspicious activities** for validation, reducing benign PowerShell activity from triggering alerts.

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Hunt for suspicious PowerShell activity with correlation
// Techniques: T1059.001 (PowerShell), multi-flag correlation to reduce noise

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = PROCESS 
      and actor_process_image_name contains "powershell" 

// Detection flags 
| alter veeam_credential_dump = if( 
          actor_process_command_line contains "veeam.backup.common.dll" or 
          actor_process_command_line contains "veeambackup" or 
          actor_process_command_line contains "backup.common" or 
          (actor_process_command_line contains "veeam" and actor_process_command_line contains "credential"), 
          true, false 
      ), 
       ad_reconnaissance = if( 
          actor_process_command_line contains "get-adfsendpoint" or 
          actor_process_command_line contains "get-adobject" or 
          actor_process_command_line contains "get-adcomputer" or 
          actor_process_command_line contains "get-itemproperty" or 
          actor_process_command_line contains "get-addomain" or 
          actor_process_command_line contains "nltest" or 
          actor_process_command_line contains "net user /domain", 
          true, false 
      ), 
       obfuscated_powershell = if( 
          actor_process_command_line contains "-encodedcommand" or 
          actor_process_command_line contains "-enc" or 
          actor_process_command_line contains "invoke-expression" or 
          actor_process_command_line contains "iex" or 
          actor_process_command_line contains "downloadstring" or 
          actor_process_command_line contains "base64", 
          true, false 
      ) 

// Correlate: require at least 2 suspicious behaviors 
| filter (veeam_credential_dump = true and ad_reconnaissance = true)  
      or (veeam_credential_dump = true and obfuscated_powershell = true) 
      or (ad_reconnaissance = true and obfuscated_powershell = true) 

// Label detection type 
| alter detection_type = if(veeam_credential_dump = true and ad_reconnaissance = true, "Veeam + AD Recon", 
                       if(veeam_credential_dump = true and obfuscated_powershell = true, "Obfuscated Veeam Attack", 
                       if(ad_reconnaissance = true and obfuscated_powershell = true, "Obfuscated Recon", 
                       "Correlated PowerShell Activity"))) 

// Output fields 
| fields _time, 
         agent_hostname, 
         actor_process_image_name, 
         actor_process_command_line, 
         causality_actor_process_image_name, 
         detection_type, 
         event_type 

| sort desc _time 
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component        |
|----------------|------------|--------------------|------------------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation             |

---

## Execution Requirements  
- **Required Permissions:** User-level sufficient for enumeration; elevated required for Veeam DLL access.  
- **Required Artifacts:** Process telemetry.  

---

## Considerations  
- Use of **PowerShell with Veeam libraries** is abnormal in enterprise workloads.  
- Repeated **obfuscation with encoded commands** strongly suggests malicious automation.  
- Multi-flag correlation helps **reduce noise from legitimate administrative tasks**.  

---

## False Positives  
- Possible overlap with legitimate **Veeam administrative scripts** in backup management.  
- Some domain reconnaissance commands may appear in IT operations scripts.  

---

## Recommended Response Actions  
1. **Isolate the endpoint** to contain malicious PowerShell activity.  
2. **Investigate PowerShell command-line logs** for credential extraction activity.  
3. **Examine Veeam Backup logs and databases** for suspicious access.  
4. **Correlate with domain controller logs** for AD reconnaissance queries.  
5. **Harden PowerShell logging and restrict encoded commands** using Group Policy.  

---

## References  
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
- [MITRE ATT&CK: T1003.002 – Security Account Manager Dumping](https://attack.mitre.org/techniques/T1003/002/)  
- [MITRE ATT&CK: T1087.002 – Domain Account Discovery](https://attack.mitre.org/techniques/T1087/002/)  
- [MITRE ATT&CK: T1018 – Remote System Discovery](https://attack.mitre.org/techniques/T1018/)  
- [MITRE ATT&CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)  

---

## Version History  

| Version | Date       | Impact                  | Notes                                                                         |
|---------|------------|-------------------------|-------------------------------------------------------------------------------|
| 1.0     | 2025-09-18 | Initial Detection       | Added correlation for Veeam credential dumping, PowerShell obfuscation, and AD recon.| 
