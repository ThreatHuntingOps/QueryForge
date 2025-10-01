# Detection of Command-Line Execution and Script Obfuscation - LockBit 5.0

## Severity or Impact of the Detected Behavior
- **Risk Score:** Variable (80–95 based on behavior)  
- **Severity:** Medium -> Critical depending on command type  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LockBit-CmdScriptObfuscation  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Medium (tuned with regex and command length heuristics)  

---

## Hunt Analytics

This hunt detects **obfuscated command-line and script executions** leveraging PowerShell, cmd.exe, and scripting engines (`wscript.exe`, `cscript.exe`) as used by **LockBit 5.0** and other ransomware families during execution and evasion phases.  

Detected behaviors include:  
- **PowerShell obfuscation**:  
  - `-EncodedCommand`, `FromBase64String`, `DownloadString`, `Invoke-Expression`, `IEX`  
  - Use of `hidden`, `bypass`, long base64-encoded strings  
- **Suspicious cmd.exe usage**:  
  - Iterative loops (`for /r`, `for /d`), destructive commands (`del`, `rmdir`, `rd`)  
  - Anti-recovery commands (`vssadmin delete shadows`, `wbadmin delete catalog`)  
  - `bcdedit` usage for tampering boot configuration  
- **Suspicious wscript/cscript usage**:  
  - Script activity in `%TEMP%`, `%APPDATA%`, or obfuscated paths with multiple dots  
- **Heuristic flags**:  
  - Long and very long command lines (200+ or 500+ characters)  
  - Detection categories mapping to severity (Critical, High, Medium)  

This query provides enriched categorization and scoring to facilitate triage of potentially malicious execution patterns.  

---

## ATT&CK Mapping

| Tactic            | Technique   | Subtechnique | Technique Name                                           |
|-------------------|-------------|--------------|----------------------------------------------------------|
| Execution         | T1059.001   | -            | Command and Scripting Interpreter: PowerShell            |
| Execution         | T1059.003   | -            | Command and Scripting Interpreter: Windows Command Shell |
| Defense Evasion   | T1140       | -            | Deobfuscate/Decode Files or Information                  |
| Impact            | T1490       | -            | Inhibit System Recovery                                  |

---

## Hunt Query Logic

The query examines command-line executions of PowerShell, cmd.exe, wscript.exe, and cscript.exe.  
- Matches suspicious strings, obfuscation patterns, and anti-recovery commands.  
- Assigns **flags for long base64/very long commands**.  
- Categorizes detection results into **intuitive categories** (Execution Bypass, Shadow Deletion, Boot Config, High Entropy Obfuscation, etc.).  
- Assigns severity tiers and risk scoring to prioritize investigations.  

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XDR and XSIAM  

```xql
// Title: LockBit 5.0 Command-Line Execution and Script Obfuscation 
// Description: Detects obfuscated PowerShell, batch scripts, and command-line patterns used by LockBit 5.0 
// MITRE ATT&CK TTP ID: T1059.003 (Windows Command Shell) 
// MITRE ATT&CK TTP ID: T1059.001 (PowerShell) 

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type = ENUM.PROCESS 
| filter action_process_image_name in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe") 

// Suspicious PowerShell patterns 
| filter ( 
    (action_process_image_name = "powershell.exe" and ( 
        action_process_image_command_line ~= ".*-[eE]ncodedCommand.*" 
        or action_process_image_command_line contains "FromBase64String" 
        or action_process_image_command_line contains "DownloadString" 
        or action_process_image_command_line contains "IEX" 
        or action_process_image_command_line contains "Invoke-Expression" 
        or action_process_image_command_line contains "hidden" 
        or action_process_image_command_line contains "bypass" 
        or action_process_image_command_line ~= ".*[A-Za-z0-9+/]{20,}={0,2}.*" 
    )) 
    or 
// Suspicious cmd.exe activity 
    (action_process_image_name = "cmd.exe" and ( 
        action_process_image_command_line contains "for /r" 
        or action_process_image_command_line contains "for /d" 
        or action_process_image_command_line contains "&& echo" 
        or action_process_image_command_line contains "vssadmin delete shadows" 
        or action_process_image_command_line contains "wbadmin delete catalog" 
        or action_process_image_command_line contains "bcdedit" 
        or action_process_image_command_line ~= ".*(del|rmdir|rd).*" 
    )) 
    or 
// Suspicious wscript / cscript activity 
    (action_process_image_name in ("wscript.exe", "cscript.exe") and ( 
        action_process_image_command_line contains "\\Temp\\" 
        or action_process_image_command_line contains "\\AppData\\" 
        or action_process_image_command_line ~= ".*\\.{3,}.*" 
    )) 
) 

// Command length flags 
| alter flag_command_long = if(action_process_image_command_line ~= ".{200,}", 1, 0) 
| alter flag_command_verylong = if(action_process_image_command_line ~= ".{500,}", 1, 0) 

// Detection categorization 
| alter detection_category =  
    if(action_process_image_command_line contains "FromBase64String", "Obfuscated Base64",  
    if(action_process_image_command_line contains "hidden", "Obfuscated Hidden", 
    if(action_process_image_command_line contains "bypass", "Execution Policy Bypass", 
    if(action_process_image_command_line contains "vssadmin", "Shadow Copy Deletion", 
    if(action_process_image_command_line contains "wbadmin", "Backup Catalog Deletion", 
    if(action_process_image_command_line contains "bcdedit", "Boot Configuration Tampering", 
    if(action_process_image_command_line ~= ".*[A-Za-z0-9+/]{50,}={0,2}.*", "High Entropy Obfuscation", 
    if(flag_command_verylong = 1, "Very Long Command Line", 
    "Suspicious Command Execution")))))))) 

// Risk scoring 
| alter severity =  
    if(detection_category in ("Shadow Copy Deletion", "Backup Catalog Deletion", "Boot Configuration Tampering"), "Critical", 
    if(detection_category in ("Obfuscated Base64", "High Entropy Obfuscation"), "High", 
    if(detection_category in ("Obfuscated Hidden", "Execution Policy Bypass"), "High", 
    "Medium"))) 

| alter risk_score =  
    if(severity = "Critical", 95, 
    if(severity = "High", 90, 80)) 

// Output fields 
| fields _time, agent_hostname, actor_effective_username, 
    action_process_image_name, action_process_image_command_line, 
    detection_category, severity, risk_score, 
    flag_command_long, flag_command_verylong, 
    causality_actor_process_image_name, causality_actor_process_command_line, 
    actor_process_image_sha256, event_id 

| sort desc risk_score, desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements  
- **Required Permissions:** Process telemetry with command-line arguments.  
- **Required Artifacts:** Presence of long commands, encoded data, or destructive commands.  

---

## Considerations  
- Query categorizes execution into **obfuscation, destructive activity, or persistence tampering**.  
- May require **environment-specific tuning** due to legitimate long or encoded commands.  
- Most suspicious when combined with **concurrent service termination or encryption artifacts**.  

---

## False Positives  
- Legitimate administrative tasks (backups, scripts, encoded PowerShell) may trigger detection.  
- Developers or sysadmins using scripts with long command lines could appear suspicious.  

---

## Recommended Response Actions  
1. Investigate command line and process ancestry.  
2. Validate intent of execution (user-initiated or adversary-driven).  
3. Correlate with other LockBit TTPs, e.g. encryption, persistence.  
4. Quarantine suspicious binaries and isolate host.  
5. If confirmed malicious, initiate ransomware response workflow.  

---

## References  
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
- [MITRE ATT&CK: T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)  
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)  

---

## Version History  

| Version | Date       | Impact                                   | Notes                                                   |
|---------|------------|------------------------------------------|---------------------------------------------------------|
| 1.0     | 2025-10-01 | Initial Release of Script Obfuscation    | Added detection categories and heuristic severity scoring |
