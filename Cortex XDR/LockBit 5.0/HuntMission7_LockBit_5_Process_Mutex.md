# Detection of Unique Process Characteristics and Mutex Creation - LockBit 5.0

## Severity or Impact of the Detected Behavior
- **Risk Score:** 86  
- **Severity:** High  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LockBit-Process-Mutex  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Medium (filters exclude benign processes but tuning may be needed)  

---

## Hunt Analytics

This hunt identifies **unique process execution patterns, environment reconnaissance, and mutex creation** behaviors associated with **LockBit 5.0 ransomware**.  
LockBit performs pre-encryption discovery and system situational awareness to tailor execution and restrict infections to targeted regions.  

Detected behaviors include:  
- **Geolocation/System checks**: Command lines referencing locale, language, timezone, and related APIs (`GetLocaleInfo`, `GetTimeZoneInformation`, `GetSystemDefaultLCID`).  
- **System reconnaissance**: Enumeration commands like `hostname`, `whoami`, `systeminfo`, `tasklist`, `net view`, `net user`.  
- **Mutex activity**: Creation or opening of mutexes (`CreateMutex`, `OpenMutex`) as infection tracking mechanisms.  
- **Custom Global mutex patterns**: Global names with 8–16 randomized characters.  
- **Execution from user-writable directories**: Processes from `%TEMP%`, `%AppData%`, `Downloads`, or `Users/Public`.  

These indicators combined are highly indicative of LockBit’s execution patterns.  

---

## ATT&CK Mapping

| Tactic               | Technique   | Subtechnique | Technique Name               |
|----------------------|-------------|--------------|------------------------------|
| Discovery            | T1057       | -            | Process Discovery            |
| Discovery            | T1082       | -            | System Information Discovery |
| Defense Evasion      | T1070.004   | -            | File Deletion (mutex indicator cleanup possible) |

---

## Hunt Query Logic

1. Detects suspicious command-line indicators for reconnaissance.  
2. Matches creation or opening of mutex objects.  
3. Enforces presence of processes running from user-controlled directories.  
4. Excludes common benign system processes.  
5. Requires at least one reconnaissance command match (`recon_commands >= 1`).  

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XDR and XSIAM  

```xql
// Title: LockBit 5.0 Unique Process Characteristics and Mutex Detection 
// Description: Detects LockBit 5.0's unique process execution patterns, geolocation checks, and mutex creation for infection tracking 
// MITRE ATT&CK TTP ID: T1057 (Process Discovery) 
// MITRE ATT&CK TTP ID: T1082 (System Information Discovery) 

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type = ENUM.PROCESS 

| filter ( 
    // Geolocation and system checks 
    action_process_image_command_line ~= "(?i)(locale|language|timezone|country)" 
    or action_process_image_command_line contains "GetLocaleInfo" 
    or action_process_image_command_line contains "GetTimeZoneInformation" 
    or action_process_image_command_line contains "GetSystemDefaultLCID" 
    or 

    // System reconnaissance patterns 
    action_process_image_command_line ~= "(?i)(hostname|whoami|systeminfo|tasklist|net view|net user)" 
    or  

    // Mutex and synchronization objects 
    action_process_image_command_line contains "CreateMutex" 
    or action_process_image_command_line contains "OpenMutex" 
    or action_process_image_command_line ~= ".*Global\[A-Za-z0-9]{8,16}.*" 
) 

| filter ( 
    // Exclude legitimate system processes 
    causality_actor_process_image_name not in ("explorer.exe", "svchost.exe", "winlogon.exe") 
    and action_process_image_path not contains "\Windows\System32\" 
    and action_process_image_path not contains "\Program Files\" 
) 

// Look for processes spawned from temp directories or user-writable locations 

| filter ( 
    causality_actor_process_image_path contains "\Temp\" 
    or causality_actor_process_image_path contains "\AppData\" 
    or causality_actor_process_image_path contains "\Downloads\" 
    or causality_actor_process_image_path contains "\Users\\Public\" 
) 

// FIXED: Changed arraycount to arraylen 
| alter recon_commands = array_length(regextract(action_process_image_command_line, "(?i)(hostname|whoami|systeminfo|tasklist|net)")) 
| filter recon_commands >= 1 

| fields _time, agent_hostname, actor_effective_username, 
    action_process_image_name, action_process_image_command_line, 
    causality_actor_process_image_name, causality_actor_process_image_path, 
    recon_commands, actor_process_image_sha256, event_id 

| sort desc recon_commands, desc _time 
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements  
- **Required Permissions:** Command-line process telemetry enabled.  
- **Required Artifacts:** Process image path, command-line content, parent-child execution chain.  

---

## Considerations  
- May overlap with legitimate administrative tasks using recon commands, though combined with mutex creation and execution from non-standard directories makes it highly suspicious.  
- Should be **correlated with file encryption and ransom note activity** to confirm LockBit infection.  

---

## False Positives  
- Possible from IT scripts/tools that use reconnaissance commands, but rare to see alongside mutex creation and execution from `%TEMP%` or `%AppData%`.  

---

## Recommended Response Actions  
1. Investigate suspicious processes for potential malware injection or mutex generation.  
2. Collect process binary and analyze SHA256 hash.  
3. Review reconnaissance command outputs for adversary information gathering.  
4. Correlate activity with subsequent encryption or ransom note creation.  
5. Isolate and rebuild affected systems as required.  

---

## References  
- [MITRE ATT&CK: T1057 – Process Discovery](https://attack.mitre.org/techniques/T1057/)  
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)  

---

## Version History  

| Version | Date       | Impact                              | Notes                                                 |
|---------|------------|-------------------------------------|-------------------------------------------------------|
| 1.0     | 2025-10-01 | Initial Release – Process & Mutex   | Detection of unique LockBit recon and mutex patterns. |
