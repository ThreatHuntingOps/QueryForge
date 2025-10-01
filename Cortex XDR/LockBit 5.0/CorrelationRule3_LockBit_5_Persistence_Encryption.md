# Advanced Persistence with High-Impact File Encryption

## Severity or Impact of the Detected Behavior
- **Risk Score:** 97 (Persistence combined with mass encryption and evasion)  
- **Severity:** Critical  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-Advanced-Persistence-Encryption  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Extremely Low (requires persistence + encryption + evasion)  

---

## Analytics

This rule detects **LockBit 5.0 leveraging persistence and high-impact file encryption** techniques, consistent with **enterprise-wide ransomware operations**.  

Detected behaviors include:  

- **Persistence Mechanisms:** Use of **registry run/runonce keys** or **scheduled task creation via schtasks.exe**.  
- **Mass File Encryption:** Identification of files renamed or written with **unique 16-character extensions**.  
- **Service Disruption:** Killing or stopping AV/backup/security services.  
- **Anti-forensics:** Clearing event logs via `wevtutil` or PowerShell cmdlets.  
- **Network Spread Indicators:** Use of `psexec`, `wmic`, `net use/share`, or file copy with UNC paths.  

High-fidelity correlation requires **mass encryption + persistence evidence** along with at least **one evasion technique (service disruption, anti-forensics, or network spread)**.  

---

## ATT&CK Mapping

| Tactic            | Technique | Subtechnique | Technique Name                                  |
|-------------------|-----------|--------------|------------------------------------------------|
| Persistence       | T1547     | T1547.001    | Boot or Logon Autostart: Registry Run Keys     |
| Persistence       | T1053     | T1053.005    | Scheduled Task/Job: Scheduled Task             |
| Impact            | T1486     | -            | Data Encrypted for Impact                      |
| Impact            | T1489     | -            | Service Stop                                   |
| Defense Evasion   | T1070     | T1070.001    | Indicator Removal: Clear Windows Event Logs    |

---

## Query Logic

This analytic requires **persistence + encryption + evasion** to trigger:  

1. **Persistence** → via Reg Run keys or scheduled tasks.  
2. **Encryption** → mass file encryption with LockBit-style 16-char extensions.  
3. **At least one evasion technique** → service disruption, log clearing, or lateral spread indicators.  

Correlated together, these phases **signal a large-scale, enterprise-level ransomware attack** in progress.  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// Advanced Persistence with High-Impact File Encryption

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type in (ENUM.PROCESS, ENUM.FILE, ENUM.REGISTRY) 

// Persistence Phase: Registry Run Keys and Scheduled Tasks 
| alter persistence_mechanism = if( 
    (event_type = ENUM.REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE and 
     action_registry_key_name ~= "(?i)\\(run|runonce)") or 
    (event_type = ENUM.PROCESS and action_process_image_name = "schtasks.exe" and 
     action_process_image_command_line contains "/create"), 
    true, false 
) 

// Impact Phase: Mass File Encryption 
| alter mass_encryption = if( 
    event_type = ENUM.FILE and event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_RENAME) and 
    action_file_name ~= ".*\.([a-zA-Z0-9]{16})$", 
    true, false 
) 

// Defense Evasion: Service Disruption 
| alter service_disruption = if( 
    event_type = ENUM.PROCESS and ( 
      (action_process_image_name in ("sc.exe", "net.exe") and  
       action_process_image_command_line contains "stop") or 
      (action_process_image_name = "taskkill.exe" and 
       action_process_image_command_line ~= "(?i)(security|backup|antivirus)") 
    ), 
    true, false 
) 

// Anti-Forensics: Log Clearing 
| alter anti_forensics = if( 
    event_type = ENUM.PROCESS and ( 
      (action_process_image_name = "wevtutil.exe" and 
       action_process_image_command_line contains "clear-log") or 
      (action_process_image_name = "powershell.exe" and 
       action_process_image_command_line contains "Clear-EventLog") 
    ), 
    true, false 
) 

// Network Spread Indicators 
| alter network_spread = if( 
    event_type = ENUM.PROCESS and 
    action_process_image_command_line ~= "(?i)(psexec|wmic|net use|net share|copy.*\\)", 
    true, false 
) 

// High-fidelity filter: require mass encryption + persistence + at least one evasion technique 
| filter mass_encryption = true and persistence_mechanism = true and 
    (service_disruption = true or anti_forensics = true or network_spread = true) 

// Indicators used for impact assessment 
| alter has_encryption_and_persistence = if(mass_encryption = true and persistence_mechanism = true, true, false) 
| alter has_multi_directory_indicators = if( 
    action_file_path contains "Documents" or  
    action_file_path contains "Desktop" or 
    action_file_path contains "Pictures" or 
    action_file_path contains "Videos", true, false 
) 

// Category assignment 
| alter detection_category = if(network_spread = true, "LockBit Enterprise Network Attack", 
    if(has_multi_directory_indicators = true, "Large-Scale Ransomware Attack", 
       "Persistent Ransomware Attack")), 
    attack_technique = "T1547.001,T1053.005,T1486,T1489,T1070.001" 

| fields _time, agent_hostname, actor_effective_username, 
    action_process_image_name, action_process_image_command_line, 
    action_file_name, action_registry_key_name, 
    has_encryption_and_persistence, has_multi_directory_indicators, 
    persistence_mechanism, mass_encryption, service_disruption, 
    anti_forensics, network_spread, 
    detection_category, attack_technique 

| sort desc _time 
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component       |
|----------------|------------|--------------------|-----------------------------|
| Cortex XSIAM   | xdr_data   | File               | File Write / File Rename    |
| Cortex XSIAM   | xdr_data   | Process            | Process Creation            |
| Cortex XSIAM   | xdr_data   | Registry           | Registry Modification       |

---

## Execution Requirements  
- **Required Permissions:** Write access to registry and scheduled tasks (elevated privileges).  
- **Required Artifacts:** Registry, process, and file telemetry.  

---

## Considerations  
- Ransomware persistence ensures **re-execution after reboot/login**.  
- Coupling persistence with **network spread** is strong evidence of enterprise compromise.  
- Widespread file encryption across user directories (`Documents`, `Desktop`, etc.) confirms **high impact**.  

---

## False Positives  
- Unlikely, though IT admins may occasionally use `schtasks.exe` or service control tools.  
- Combination with **mass encryption and 16-character file extensions** strongly reduces benign triggers.  

---

## Recommended Response Actions  
1. **Quarantine affected endpoints** exhibiting persistence + encryption.  
2. **Inspect scheduled tasks and registry run keys** for persistence artifacts.  
3. **Review disabled/killed services** and restore security coverage.  
4. **Identify network spread attempts** (psexec, wmic) across the environment.  
5. **Correlate directory impact** (Documents, Desktop, Pictures) to scope data loss.  
6. **Initiate enterprise ransomware response playbooks**.  

---

## References  
- [MITRE ATT&CK T1547.001 – Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)  
- [MITRE ATT&CK T1053.005 – Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)  
- [MITRE ATT&CK T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)  
- [MITRE ATT&CK T1489 – Service Stop](https://attack.mitre.org/techniques/T1489/)  
- [MITRE ATT&CK T1070.001 – Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)  

---

## Version History  

| Version | Date       | Impact                                   | Notes                                       |
|---------|------------|------------------------------------------|---------------------------------------------|
| 1.0     | 2025-10-01 | Initial Release                          | Persistence + encryption + evasion combined |
