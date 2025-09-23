# Detection of Suspicious WDAC Policy File Creation

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-PolicyFileDetection
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious creation or modification of **WDAC policy files** (e.g., `SiPolicy.p7b`, `.cip`, `.p7b`) in sensitive Code Integrity directories. Such activity represents a strong indicator of **malicious WDAC policy deployment**, which adversaries use to weaken endpoint defenses or bypass application control enforcement.

Detected behaviors include:

- File creation or modification in `System32\CodeIntegrity` directories.  
- Placement of WDAC policy artifacts into `CiPolicies\Active`.  
- Attempts to timestamp (`timestomp`) or hide malicious WDAC policy files.  
- Use of unauthorized processes to modify policy files (non `TrustedInstaller.exe`, `svchost.exe`).

These techniques align with **defense evasion via policy manipulation**.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion      | T1562       | T1562.001    | Impair Defenses: Disable or Modify Tools       |
| TA0005 - Defense Evasion      | T1070       | T1070.006    | Indicator Removal: Timestomp                   |
| TA0005 - Defense Evasion      | T1564       | T1564.001    | Hide Artifacts: Hidden Files and Directories   |

---

## Hunt Query Logic

This query identifies events where WDAC policy files are being created or modified in the Code Integrity directories by untrusted executables. Such changes are often associated with **malicious WDAC policy distribution**.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Malicious WDAC Policy File Detection
// Description: Detects creation/modification of SiPolicy.p7b files and related WDAC policy artifacts
// MITRE ATT&CK TTP ID: T1562.001, T1070.006, T1564.001

config case_sensitive = false   

| dataset = xdr_data  

| filter event_type = ENUM.FILE  

| filter action_file_path contains "CodeIntegrity"  

| filter (  
      action_file_name = "SiPolicy.p7b"   
   or action_file_path contains "CiPolicies\Active\"  
   or action_file_name ~= "\.p7b$"  
   or action_file_name ~= "\.cip$"  
)  

| filter not (actor_process_image_name in ("TrustedInstaller.exe","svchost.exe"))   

| alter    
    policy_directory = if(action_file_path contains "System32\CodeIntegrity", "Primary", "Secondary"),  
    file_hidden = if(action_file_contents contains "H", "Hidden", "Visible")   

| fields agent_hostname, actor_process_image_name, actor_process_command_line,    
         action_file_path, action_file_name, policy_directory, file_hidden,   
         action_file_size, action_file_md5   

| sort desc _time   
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM |    xdr_data      | File                | File Write / Modification |

---

## Execution Requirements

- **Required Permissions:** Elevated privileges to write WDAC policy files.  
- **Required Artifacts:** File system logs, process creation data, file metadata.  

---

## Considerations

- Review the process responsible for file creation.  
- Correlate WDAC policy modifications with enterprise deployment schedules.  
- Look for timestomping or file concealment techniques.  

---

## False Positives

False positives may occur in cases of:  
- Legitimate **enterprise WDAC policy deployments** (via SCCM, Intune, Group Policy).  
- **Windows Update** processes modifying WDAC policies.  
- Controlled **test lab environments** performing WDAC updates.  

---

## Recommended Response Actions

1. Validate whether detected WDAC file placement is authorized.  
2. Verify file integrity, signature, and creation source.  
3. Investigate associated process and command-line invocation.  
4. Isolate host if unauthorized or malicious deployment is confirmed.  
5. Hunt across environment for additional indicators of malicious policy distribution.  

---

## References

- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)  
- [MITRE ATT&CK: T1070.006 – Indicator Removal on Host: Timestomp](https://attack.mitre.org/techniques/T1070/006/)  
- [MITRE ATT&CK: T1564.001 – Hide Artifacts: Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                         |
|---------|------------|-------------------|---------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | Created hunting query for suspicious WDAC policy file activity |
