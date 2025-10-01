# Hunting for LockBit 5.0 Ransom Note Creation and Desktop Modification

## Severity or Impact of the Detected Behavior
- **Risk Score:** 88  
- **Severity:** High  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LockBit-RansomNote-DesktopChange  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low (excludes common system processes and legitimate registry paths)  

---

## Hunt Analytics

This hunt surfaces **LockBit 5.0 post-encryption impact behaviors** involving **ransom note deployment** and **desktop modifications**.  

Detected behaviors include:  
- **File creation of ransom notes** with common LockBit patterns:
  - `ReadMeForDecrypt.txt`  
  - Filenames containing `decrypt`, `ransom`, `readme`, or `lockbit`  
- **Registry modifications for desktop wallpaper changes** under Control Panel/Wallpaper keys.  
- **Filtering exclusions** to avoid noise:
  - Excludes benign processes such as `explorer.exe`, `dwm.exe`, `winlogon.exe`, `csrss.exe`.  
  - Excludes processes from `C:\Windows\System32` and `C:\Windows\SysWOW64`.  

This query provides **direct evidence of ransomware impact** - ransomware informing the victim and visually signaling compromise.  

---

## ATT&CK Mapping

| Tactic  | Technique | Subtechnique | Technique Name                          |
|---------|-----------|--------------|-----------------------------------------|
| Impact  | T1486     | -            | Data Encrypted for Impact               |
| Impact  | T1491.001 | -            | Defacement: Internal Defacement (Wallpaper/desktop modifications) |

---

## Hunt Query Logic

- File and Registry event types are inspected.  
- Match ransom note **creation events** targeting lockbit-style ransom instructions.  
- Match registry key/value changes modifying **desktop wallpaper** to display ransom messaging.  
- Exclude legitimate processes to **minimize false positives**.  

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XDR and XSIAM  

```xql
// LockBit 5.0 Ransom Note and Desktop Modification – Hunting View 
// Shows each ransom note creation + wallpaper mod event 

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type in (ENUM.FILE, ENUM.REGISTRY) 

| filter ( 
    (event_type = ENUM.FILE and event_sub_type = ENUM.FILE_CREATE_NEW and ( 
        action_file_name ~= "(?i)ReadMeForDecrypt\.txt" 
        or action_file_name ~= "(?i).*decrypt.*\.txt" 
        or action_file_name ~= "(?i).*ransom.*\.txt" 
        or action_file_name ~= "(?i).*readme.*\.txt" 
        or action_file_name ~= "(?i).*lockbit.*\.txt" 
    )) 
    or 
    (event_type = ENUM.REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE and ( 
        action_registry_key_name contains "\Control Panel\Desktop" 
        or action_registry_key_name contains "\Desktop\Wallpaper" 
        or action_registry_value_name = "Wallpaper" 
    )) 
) 

| filter ( 
    causality_actor_process_image_name not in ("explorer.exe", "dwm.exe", "winlogon.exe", "csrss.exe") 
    and causality_actor_process_image_path not contains "\Windows\System32\" 
    and causality_actor_process_image_path not contains "\Windows\SysWOW64\" 
) 

| fields _time, agent_hostname, actor_effective_username, event_type, event_sub_type, 
    action_file_name, action_file_path, 
    action_registry_key_name, action_registry_value_name, action_registry_data, 
    causality_actor_process_image_name, causality_actor_process_command_line, 
    causality_actor_process_image_path, event_id 

| sort desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component     |
|----------------|------------|--------------------|---------------------------|
| Cortex XSIAM   | xdr_data   | File               | File Creation             |
| Cortex XSIAM   | xdr_data   | Registry           | Registry Key Modification |

---

## Execution Requirements  
- **Required Permissions:** File creation + Registry modification telemetry enabled.  
- **Required Artifacts:** Capture of full file and registry context.  

---

## Considerations  
- Ransom note files are strongly indicative of active ransomware.  
- Wallpaper registry modifications are a deliberate adversary action and **sidestep normal system processes**.  
- Recommended to correlate with file encryption and service termination detections for full kill chain coverage.  

---

## False Positives  
- Rare. Some admin scripts may change wallpapers, but ransom note naming patterns (`lockbit`, `decrypt`, `ransom`, `readme`) are highly specific.  
- The exclusions (`explorer.exe`, `winlogon.exe`, etc.) remove the majority of legitimate wallpaper changes.  

---

## Recommended Response Actions  
1. Investigate the host for evidence of confirmed ransomware impact.  
2. Identify ransom notes and collect forensic copies.  
3. Review modified registry settings to restore normal desktop appearance.  
4. Isolate and remediate the encrypting process.  
5. Begin enterprise ransomware response: backups, forensic containment, and communication.  

---

## References  
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)  
- [MITRE ATT&CK: T1491.001 – Internal Defacement: Wallpaper](https://attack.mitre.org/techniques/T1491/001/)  

---

## Version History  

| Version | Date       | Impact                             | Notes                                             |
|---------|------------|------------------------------------|---------------------------------------------------|
| 1.0     | 2025-10-01 | Initial Release of Hunt Detection  | Added ransom note file + wallpaper mod hunting.   |
