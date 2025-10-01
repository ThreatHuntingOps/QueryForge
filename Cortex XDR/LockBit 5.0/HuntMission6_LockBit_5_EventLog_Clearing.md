# Detection of Event Log Clearing and Anti-Forensic Activities - LockBit 5.0

## Severity or Impact of the Detected Behavior
- **Risk Score:** 94  
- **Severity:** Critical  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LockBit-EventLogClearing  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low (log clearing is a rare and high-risk activity)  

---

## Hunt Analytics

This hunt query detects **event log manipulation and clearing behaviors** associated with **LockBit 5.0** ransomware and related adversaries.  
Ransomware actors frequently attempt to **erase forensic evidence and defense telemetry** following encryption activities.  

Detected behaviors include:  
- **Event log clearing via `wevtutil.exe`** (`clear-log`, `cl`, `/e:false`).  
- **PowerShell-based log manipulation** (`Clear-EventLog`, `Remove-EventLog`, `System.Diagnostics.EventLog`, `Limit-EventLog`).  
- **Registry modifications** disabling or shrinking log storage (`Enabled=0`, `MaxSize=0`) under EventLog service keys.  
- **Direct deletion of event log files** (`.evtx`) using `del.exe`, `erase.exe`, or `cmd.exe`.  
- **Focus on common log types**: `Security`, `System`, `Application`, `Setup`, `ForwardedEvents`, `Microsoft-Windows-*`.  

This activity is a strong indicator of **anti-forensic behavior** that typically precedes or follows file encryption.  

---

## ATT&CK Mapping

| Tactic           | Technique   | Subtechnique | Technique Name                                  |
|------------------|-------------|--------------|------------------------------------------------|
| Defense Evasion  | T1070.001   | -            | Indicator Removal on Host: Clear Windows Event Logs |
| Defense Evasion  | T1562.002   | -           | Impair Defenses: Disable Windows Event Logging |

---

## Hunt Query Logic

The query inspects both process execution and registry modifications:  
- Detects log clearing via `wevtutil`, PowerShell scripts, and destructive commands against `.evtx` files.  
- Detects registry edits disabling logging services or event channels.  
- Focuses on **security/audit-related logs** commonly targeted by attackers.  
- Derives count of logs affected via regex extraction (`log_types_cleared`).  

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XDR and XSIAM  

```xql
// Title: LockBit 5.0 Event Log Clearing and Anti-Forensic Activities 
// Description: Detects event log manipulation and clearing activities used by LockBit 5.0 to hide attack footprints post-encryption 
// MITRE ATT&CK TTP ID: T1070.001 (Indicator Removal on Host: Clear Windows Event Logs) 
// MITRE ATT&CK TTP ID: T1562.002 (Impair Defenses: Disable Windows Event Logging) 

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type in (ENUM.PROCESS, ENUM.REGISTRY) 

| filter ( 
    // Event log clearing via wevtutil 
    (action_process_image_name = "wevtutil.exe" and ( 
    action_process_image_command_line contains "clear-log" 
    or action_process_image_command_line contains "cl" 
    or action_process_image_command_line contains "/e:false" 
    )) 
    or 

    // PowerShell event log manipulation 
    (action_process_image_name = "powershell.exe" and ( 
    action_process_image_command_line contains "Clear-EventLog" 
    or action_process_image_command_line contains "Remove-EventLog" 
    or action_process_image_command_line contains "System.Diagnostics.EventLog" 
    or action_process_image_command_line contains "Limit-EventLog" 
    )) 
    or 

    // Registry modifications to disable logging 
    (event_type = ENUM.REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE and ( 
    action_registry_key_name contains "\\CurrentControlSet\\Services\\EventLog" 
    or action_registry_key_name contains "\\Winevt\\Channels" 
    or (action_registry_value_name = "Enabled" and action_registry_data = "0") 
    or (action_registry_value_name = "MaxSize" and action_registry_data = "0") 
    )) 
    or 

    // Direct deletion of event log files 
    (action_process_image_name in ("del.exe", "erase.exe", "cmd.exe") and ( 
    action_process_image_command_line contains ".evtx" 
    or action_process_image_command_line contains "\\System32\\winevt\\Logs\\" 
    )) 
) 

| filter ( 
    // Target common event logs 
    action_process_image_command_line ~= "(?i)(security|system|application|setup|forwarded|microsoft-windows-)" 
    or action_registry_key_name ~= "(?i)(security|system|application|setup)" 
) 

// FIXED: Changed arraycount to arraylen 
| alter log_types_cleared = array_length(regextract(action_process_image_command_line, "(?i)(security|system|application|setup|powershell)")) 

| fields _time, agent_hostname, actor_effective_username, event_type, 
    action_process_image_name, action_process_image_command_line, 
    action_registry_key_name, action_registry_value_name, action_registry_data, 
    log_types_cleared, causality_actor_process_image_name, 
    causality_actor_process_command_line, event_id 

| sort desc log_types_cleared, desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source   | ATT&CK Data Component   |
|----------------|------------|----------------------|-------------------------|
| Cortex XSIAM   | xdr_data   | Process              | Process Creation        |
| Cortex XSIAM   | xdr_data   | Registry             | Registry Key Modification |

---

## Execution Requirements  
- **Required Permissions:** Process + registry telemetry collection must be active.  
- **Required Artifacts:** Capture of command lines, registry edits, and file path context.  

---

## Considerations  
- Log clearing is a **high-confidence signal** of malicious activity.  
- Should always trigger **priority triage** especially when correlated with **encryption events or service stops**.  

---

## False Positives  
- Extremely rare. Admins occasionally clear event logs during maintenance, but registry disabling or direct `.evtx` deletion is highly suspicious.  

---

## Recommended Response Actions  
1. Investigate the process that attempted log clearing.  
2. Correlate activity with ransomware-related detections (encryption, service disablement).  
3. Collect and preserve surviving event logs for forensic reconstruction.  
4. Isolate endpoint and begin ransomware incident response.  
5. Re-enable and validate logging mechanisms across the environment.  

---

## References  
- [MITRE ATT&CK: T1070.001 – Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)  
- [MITRE ATT&CK: T1562.002 – Disable Windows Event Logging](https://attack.mitre.org/techniques/T1562/002/)  

---

## Version History  

| Version | Date       | Impact                                      | Notes                                          |
|---------|------------|---------------------------------------------|------------------------------------------------|
| 1.0     | 2025-10-01 | Initial Release - Event Log Clearing Hunt   | Detects registry, process, and direct file deletions |
