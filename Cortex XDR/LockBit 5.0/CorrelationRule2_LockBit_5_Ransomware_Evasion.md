# Ransomware Execution with Advanced Evasion Techniques

## Severity or Impact of the Detected Behavior
- **Risk Score:** 96 (Encryption detected with process injection and evasion indicators)  
- **Severity:** Critical  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-Ransomware-Evasion-Techniques  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Very Low (requires encryption + multiple advanced phases)  

---

## Analytics

This correlation rule detects **LockBit 5.0 ransomware execution** when paired with **advanced evasion and injection techniques**, ensuring high-confidence alerts.  

Detected behaviors include:  

- **Encryption Activity:** File writes, renames, or creation of ransom notes (`ReadMeForDecrypt.txt`, `decrypt.txt`).  
- **Process Injection:** Memory manipulation functions such as `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, or `NtMapViewOfSection`.  
- **Anti-analysis & ETW evasion:** Calls to methods like `EtwEventWrite`, `IsDebuggerPresent`, and suspicious Base64 command-line arguments.  
- **Reconnaissance:** System and environment discovery commands (`whoami`, `hostname`, `systeminfo`, `net view`, `tasklist`, `locale`).  

Correlation requires **encryption + at least two other phases** (injection, evasion, reconnaissance), minimizing false positives and surfacing **critical attack chains**.  

---

## ATT&CK Mapping

| Tactic           | Technique | Subtechnique | Technique Name                               |
|------------------|-----------|--------------|---------------------------------------------|
| Impact           | T1486     | -            | Data Encrypted for Impact                    |
| Defense Evasion  | T1055     | -            | Process Injection                           |
| Defense Evasion  | T1027     | -            | Obfuscated/Encrypted Files or Information   |
| Defense Evasion  | T1562     | T1562.006    | Impair Defenses: Disable Windows Event Logging |

---

## Query Logic

This analytic detects **ransomware encryption paired with advanced evasion phases**.  
- Mandatory encryption indicators must be present.  
- Requires two other phases among **process injection, evasion, or reconnaissance**.  

This ensures the rule only triggers on **multi-faceted ransomware activity** rather than benign or isolated behaviors.  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// Ransomware Execution with Advanced Evasion Techniques

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type in (ENUM.PROCESS, ENUM.FILE, ENUM.REGISTRY) 

// Detection Phase 1: File Encryption Activity 
| alter encryption_activity = if( 
    event_type = ENUM.FILE and ( 
      (event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_RENAME) and 
       action_file_name ~= ".*\.([a-zA-Z0-9]{16})$") or 
      (event_sub_type = ENUM.FILE_CREATE_NEW and 
       action_file_name ~= "(?i)(ReadMeForDecrypt|decrypt|ransom).*\.txt") 
    ), 
    true, false 
) 

// Detection Phase 2: Process Injection Indicators 
| alter injection_activity = if( 
    event_type = ENUM.PROCESS and ( 
      action_process_image_command_line contains "VirtualAllocEx" or 
      action_process_image_command_line contains "WriteProcessMemory" or 
      action_process_image_command_line contains "CreateRemoteThread" or 
      action_process_image_command_line contains "QueueUserAPC" or 
      action_process_image_command_line contains "NtMapViewOfSection" 
    ), 
    true, false 
) 

// Detection Phase 3: Anti-Analysis and ETW Evasion 
| alter evasion_activity = if( 
    event_type = ENUM.PROCESS and ( 
      action_process_image_command_line contains "EtwEventWrite" or 
      action_process_image_command_line contains "IsDebuggerPresent" or 
      action_process_image_command_line contains "CheckRemoteDebuggerPresent" or 
      action_process_image_command_line ~= ".*[A-Za-z0-9+/]{30,}={0,2}.*" 
    ), 
    true, false 
) 

// Detection Phase 4: System Reconnaissance 
| alter recon_activity = if( 
    event_type = ENUM.PROCESS and 
    action_process_image_command_line ~= "(?i)(whoami|hostname|systeminfo|net view|tasklist|locale)", 
    true, false 
) 

// Correlation filter: require encryption + at least 2 other phases 
| filter encryption_activity = true and ( 
    (injection_activity = true and evasion_activity = true) or 
    (injection_activity = true and recon_activity = true) or 
    (evasion_activity = true and recon_activity = true) 
) 

// Impact classification 
| alter detection_category = if( 
    (injection_activity = true and evasion_activity = true and recon_activity = true),  
       "High-Impact Ransomware Attack", 
    if((injection_activity = true and evasion_activity = true) or  
       (injection_activity = true and recon_activity = true) or  
       (evasion_activity = true and recon_activity = true), 
       "Medium-Impact Ransomware Attack", 
       "Ransomware Execution Detected") 
) 

| fields _time, agent_hostname, actor_effective_username, 
    action_process_image_name, action_process_image_command_line, 
    action_file_name, action_file_path, 
    encryption_activity, injection_activity, evasion_activity, recon_activity, 
    detection_category, event_type, event_sub_type 

| sort desc _time 
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component       |
|----------------|------------|--------------------|-----------------------------|
| Cortex XSIAM   | xdr_data   | File               | File Write / File Creation  |
| Cortex XSIAM   | xdr_data   | Process            | Process Creation            |
| Cortex XSIAM   | xdr_data   | Registry           | Registry Modification       |

---

## Execution Requirements  
- **Required Permissions:** Elevated privileges often required for injection and evasion.  
- **Required Artifacts:** File, process telemetry with command line arguments.  

---

## Considerations  
- LockBit 5.0 leverages **multi-phase techniques** combining **injection, evasion, and reconnaissance** with encryption.  
- Detection prioritizes advanced correlations, avoiding trivial triggers from single activity phases.  

---

## False Positives  
- Extremely rare. Possible edge cases include legitimate admin scripts performing reconnaissance commands (whoami, systeminfo), but **correlation with ransomware encryption makes benign matches improbable**.  

---

## Recommended Response Actions  
1. **Isolate impacted systems immediately.**  
2. **Terminate malicious processes** exhibiting injection or ETW evasion calls.  
3. **Search for ransom notes and encrypted files** across file systems.  
4. **Investigate reconnaissance attempts** for lateral movement preparation.  
5. **Escalate to incident response** teams for coordinated ransomware containment.  

---

## References  
- [MITRE ATT&CK T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)  
- [MITRE ATT&CK T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)  
- [MITRE ATT&CK T1027 – Obfuscated/Encrypted Files or Information](https://attack.mitre.org/techniques/T1027/)  
- [MITRE ATT&CK T1562.006 – Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/006/)  

---

## Version History  

| Version | Date       | Impact                                | Notes                                     |
|---------|------------|---------------------------------------|-------------------------------------------|
| 1.0     | 2025-10-01 | Initial Release of Evasion Techniques | Added injection + evasion + recon phases. |
