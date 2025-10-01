# LockBit 5.0 Multi-Phase Kill Chain Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 98 (Full kill chain correlation with encryption + ransom note)  
- **Severity:** Critical  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-LockBit-5-KillChain  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Very Low (multi-phase kill chain with mandatory encryption + ransom note)  

---

## Analytics

This correlation rule detects the **complete LockBit 5.0 ransomware attack lifecycle** with coverage from **initial execution through impact**.  

Detected behaviors include:  

- **Phase 1 – ETW patching & anti-analysis:** Tampering with Event Tracing for Windows and anti-debugging techniques.  
- **Phase 2 – Security service termination:** Stopping AV/EDR/backup services via `sc.exe`, `net.exe`, `taskkill.exe`, and PowerShell.  
- **Phase 3 – File encryption:** Observing extensions with unique **16-character random strings**.  
- **Phase 4 – Ransom note deployment:** Dropping `ReadMeForDecrypt.txt`.  
- **Phase 5 – Log clearing:** Removing forensic evidence with `wevtutil` and PowerShell `Clear-EventLog`.  
- **Phase 6 – Obfuscation:** Loading assemblies and decoding base64-encoded payloads dynamically.  

Correlation requires **encryption + ransom note creation** plus at least **two other techniques**, ensuring high-confidence detection of LockBit 5.0.  

---

## ATT&CK Mapping

| Tactic           | Technique | Subtechnique | Technique Name                          |
|------------------|-----------|--------------|----------------------------------------|
| Defense Evasion  | T1562     | T1562.006    | Impair Defenses: Disable Windows Event Logging |
| Impact           | T1489     | -            | Service Stop                            |
| Impact           | T1486     | -            | Data Encrypted for Impact               |
| Impact           | T1491     | T1491.001    | Defacement: Internal Defacement         |
| Defense Evasion  | T1027     | -            | Obfuscated/Encrypted Files or Information |
| Defense Evasion  | T1070.001 | -            | Indicator Removal: Clear Windows Event Logs |

---

## Query Logic

This analytic looks for **phase overlaps characteristic of LockBit 5.0**:  

- **Mandatory:** encryption artifacts + ransom note file creation.  
- **Additional phases:** at least two of ETW tampering, service kill, log clearing, or obfuscation.  

This ensures the analytic **avoids false positives** from isolated behaviors and prioritizes **multi-stage ransomware activity**.  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// LockBit 5.0 Multi-Phase Kill Chain 
// Description: High-fidelity detection of LockBit 5.0's complete attack lifecycle from initial execution through impact 
// MITRE ATT&CK TTPs: T1562.006, T1489, T1486, T1491.001, T1027, T1070.001 

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type in (ENUM.PROCESS, ENUM.FILE, ENUM.REGISTRY) 

// Phase 1: ETW Patching and Anti-Analysis 
| alter phase1_etw_evasion = if( 
    event_type = ENUM.PROCESS and ( 
      action_process_image_command_line contains "EtwEventWrite" 
      or action_process_image_command_line contains "0xC3" 
      or action_process_image_command_line contains "IsDebuggerPresent" 
    ), 
    true, false 
) 

// Phase 2: Security Service Termination 
| alter phase2_service_kill = if( 
    event_type = ENUM.PROCESS and ( 
      (action_process_image_name = "sc.exe" and action_process_image_command_line contains "stop") 
      or (action_process_image_name = "net.exe" and action_process_image_command_line contains "stop") 
      or (action_process_image_name = "taskkill.exe" and action_process_image_command_line contains "/f") 
      or (action_process_image_name = "powershell.exe" and action_process_image_command_line contains "Stop-Service") 
    ) 
    and action_process_image_command_line ~= "(?i)(avast|kaspersky|norton|mcafee|bitdefender|defender|cortex|falcon|crowdstrike|security|backup)", 
    true, false 
) 
 
// Phase 3: File Encryption with 16-Character Extensions 
| alter phase3_encryption = if( 
    event_type = ENUM.FILE and event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_RENAME) 
    and action_file_name ~= ".*\.([a-zA-Z0-9]{16})$", 
    true, false 
) 

// Phase 4: Ransom Note Deployment 
| alter phase4_ransom_note = if( 
    event_type = ENUM.FILE and event_sub_type = ENUM.FILE_CREATE_NEW 
    and action_file_name ~= "(?i)ReadMeForDecrypt\.txt", 
    true, false 
) 

// Phase 5: Event Log Clearing 
| alter phase5_log_clearing = if( 
    event_type = ENUM.PROCESS and ( 
      (action_process_image_name = "wevtutil.exe" and action_process_image_command_line contains "clear-log") 
      or (action_process_image_name = "powershell.exe" and action_process_image_command_line contains "Clear-EventLog") 
    ), 
    true, false 
) 

// Phase 6: Advanced Obfuscation 
| alter phase6_obfuscation = if( 
    event_type = ENUM.PROCESS and ( 
      action_process_image_command_line contains "Assembly.Load" 
      or action_process_image_command_line contains "FromBase64String" 
      or action_process_image_command_line ~= ".*[A-Za-z0-9+/]{50,}={0,2}.*" 
    ), 
    true, false 
) 

// High-fidelity correlation: require at least 4 phases with encryption + ransom note mandatory 
| filter ( 
    (phase3_encryption = true and phase4_ransom_note = true) and 
    ( 
      (phase1_etw_evasion = true and phase2_service_kill = true and phase5_log_clearing = true) or 
      (phase1_etw_evasion = true and phase2_service_kill = true and phase6_obfuscation = true) or 
      (phase2_service_kill = true and phase5_log_clearing = true and phase6_obfuscation = true) or 
      (phase1_etw_evasion = true and phase5_log_clearing = true and phase6_obfuscation = true) 
    ) 
) 

| alter detection_category = "LockBit 5.0 Full Kill Chain", 
    attack_technique = "T1562.006,T1489,T1486,T1491.001,T1070.001,T1027" 

| fields _time, agent_hostname, actor_effective_username, 
    action_process_image_name, action_process_image_command_line, 
    action_file_name, action_file_path, 
    phase1_etw_evasion, phase2_service_kill, phase3_encryption, 
    phase4_ransom_note, phase5_log_clearing, phase6_obfuscation, 
    detection_category, attack_technique, event_type, event_sub_type 

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
- **Required Permissions:** User-level sufficient; elevated rights often required for service killing and log tampering.  
- **Required Artifacts:** File, process, and registry telemetry.  

---

## Considerations  
- LockBit 5.0 employs **multi-layered evasion** (ETW patching, obfuscation, service kills, log clearing).  
- Detection focuses on **phased correlation**, not isolated events, reducing false positives while capturing full ransomware kill chain execution.  

---

## False Positives  
- Extremely rare. Legitimate files with **16-character extensions** or manual `wevtutil` log clearing scripts from administrators may trigger components.  
- Mandatory **ransom note correlation** drastically reduces likelihood of benign triggers.  

---

## Recommended Response Actions  
1. **Immediately isolate the host** from the network to prevent lateral propagation.  
2. **Block encryption binaries** and known obfuscation loaders.  
3. **Search for ransom notes** across enterprise file systems.  
4. **Investigate terminated services** to confirm AV/EDR bypass attempts.  
5. **Engage incident response process** for ransomware containment and recovery.  

---

## References  
- [MITRE ATT&CK T1562.006 – Impair Defenses: Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/006/)  
- [MITRE ATT&CK T1489 – Service Stop](https://attack.mitre.org/techniques/T1489/)  
- [MITRE ATT&CK T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)  
- [MITRE ATT&CK T1491.001 – Defacement: Internal Defacement](https://attack.mitre.org/techniques/T1491/001/)  
- [MITRE ATT&CK T1027 – Obfuscated/Encrypted Files or Information](https://attack.mitre.org/techniques/T1027/)  
- [MITRE ATT&CK T1070.001 – Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)  

---

## Version History  

| Version | Date       | Impact                          | Notes                               |
|---------|------------|---------------------------------|-------------------------------------|
| 1.0     | 2025-10-01 | Initial Release of LockBit 5.0  | Full kill chain correlation logic.  |
