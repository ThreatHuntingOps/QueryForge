# Detection of AdaptixC2 DLL Hijacking in Templates Directory

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-AdaptixC2-DLLHijacking-Templates  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Medium  

---

## Hunt Analytics

This hunt detects **DLL hijacking attempts by AdaptixC2** that leverage the **Windows Templates directory** for persistence and privilege escalation.  
According to Palo Alto Unit42’s research, AdaptixC2 places malicious DLLs in:

- `\AppData\Roaming\Microsoft\Windows\Templates\`

These DLLs impersonate trusted or system-related components (e.g., `system.dll`, `securityupdate.dll`), enabling persistence when legitimate processes attempt DLL loading from this directory.  
This detection focuses on file creation, writes, and modifications of suspicious DLLs within the Templates path.

---

## ATT&amp;CK Mapping

| Tactic(s)                                      | Technique ID | Technique Name                               |
|-----------------------------------------------|--------------|---------------------------------------------|
| Persistence / Privilege Escalation / Defense Evasion | T1574.001    | Hijack Execution Flow: DLL Search Order Hijacking |
| Defense Evasion                               | T1036.005    | Masquerading: Match Legitimate Name or Location |
| Persistence                                   | T1547.001    | Boot or Logon Autostart Execution (via Templates folder) |

---

## Hunt Query Logic

This query detects:

- File activity on DLLs within **`\AppData\Roaming\Microsoft\Windows\Templates\`**  
- Suspicious DLL operations: creation, write, or modification  
- DLLs masquerading as legitimate components (names referencing **system**, **windows**, **microsoft**, **security**, **update**)  

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM  

```xql
// Title: AdaptixC2 DLL Hijacking in Templates Directory
// Description: Detects persistence and privilege escalation attempts using malicious DLLs planted in the Windows Templates directory.
// MITRE ATT&CK TTP ID: T1574.001

config case_sensitive = false  

| dataset = xdr_data  

| filter event_type = FILE  

| filter action_file_path contains "\AppData\Roaming\Microsoft\Windows\Templates\"  

| filter action_file_name ~= ".*\.dll$"  

| alter   
    detection_name = "AdaptixC2 DLL Hijacking Templates",  
    attack_technique = "T1574.001 - DLL Search Order Hijacking",  
    file_operation = if(action_file_path contains "CREATE", "CREATE",  
                        if(action_file_path contains "WRITE", "WRITE", "MODIFY")),  
    has_suspicious_dll_name = if(action_file_name contains "system"  
                              or action_file_name contains "microsoft"  
                              or action_file_name contains "windows"  
                              or action_file_name contains "security"  
                              or action_file_name contains "update", "yes", "no") 

| fields _time, agent_hostname, action_file_path, action_file_name, file_operation, has_suspicious_dll_name, detection_name, attack_technique  

| sort desc _time  
```

---

## Data Sources

| Log Provider | Event Name     | ATT&CK Data Source  | ATT&CK Data Component   |
|--------------|----------------|---------------------|-------------------------|
| Cortex XSIAM | xdr_data       | File                | File Creation/Modification |

---

## Execution Requirements

- **Required Permissions:** Ability to write to user profile directories.  
- **Required Artifacts:** File creation/write logs with path and filename details.  

---

## Considerations

- Benign software may occasionally store DLLs in profile directories, but `.dll` files in **Templates** is highly unusual.  
- Masquerading detection is heuristic: validate suspicious DLL names against known IT tooling before response.  
- Correlate findings with process load events attempting to use these DLLs.  

---

## False Positives

False positives may occur if:  
- Legitimate software incorrectly writes DLLs to the Templates directory.  
- Security products or IT automation place diagnostic DLLs in profile paths.  

Cross-validation with **process usage** and **hash reputation** is critical.  

---

## Recommended Response Actions

1. Investigate the DLL file creation or modification in the Templates folder.  
2. Determine if the DLL name aligns with legitimate software.  
3. Analyze associated process lineage (who dropped or loaded the DLL).  
4. If confirmed malicious:  
   - Quarantine the DLL file  
   - Isolate the endpoint  
   - Review persistence and registry artifacts  
   - Hunt for further AdaptixC2 activity on the host or network  

---

## References

- [MITRE ATT&CK: T1574.001 – DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)  
- [MITRE ATT&CK: T1036.005 – Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)  
- [MITRE ATT&CK: T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)  

---

## Version History

| Version | Date       | Impact           | Notes                                                                 |
|---------|------------|-----------------|-----------------------------------------------------------------------|
| 1.0     | 2025-09-26 | Initial Release  | Created hunt query for detecting AdaptixC2 DLL hijacking in Templates directory |
