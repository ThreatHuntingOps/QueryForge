# Detection of Execution of “Quote #S_*.js” via WScript

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** Critical

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Quote-S-JS-WScript
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects the execution of JavaScript files matching the pattern `Quote #S_*.js` invoked by `wscript.exe` from user-writable paths such as Downloads, Temp, or AppData. This behavior is associated with malicious scripts used as lures in targeted attacks. Detected behaviors include:

- Execution of `wscript.exe` with command lines referencing `Quote #S_*.js`
- Scripts executed from user-writable paths (e.g., Downloads, Temp, AppData)

These techniques are commonly used for initial access, payload delivery, or command and control.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059.007   | —            | Command and Scripting Interpreter: JavaScript |
| TA0001 - Initial Access      | T1204.002   | —            | User Execution: Malicious File                |

---

## Hunt Query Logic

This query identifies suspicious script execution by looking for:

- `wscript.exe` executing JavaScript files matching the pattern `Quote #S_*.js`
- Scripts executed from user-writable paths (e.g., Downloads, Temp, AppData)

These patterns are indicative of attempts to execute malicious scripts for initial access or payload delivery.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: IOC - Quote #S_* JavaScript via WScript 
// Description: Detects wscript.exe executing Quote #S_*.js from Downloads/Temp/AppData. 
// MITRE ATT&CK TTP ID: T1204.002, T1059.007 

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START 
| filter action_process_image_name = "wscript.exe" 
| filter action_process_image_command_line contains "\downloads\"  
    or action_process_image_command_line contains "\temp\"  
    or action_process_image_command_line contains "\appdata\"  
    or action_process_image_command_line contains "\programdata\"  
    or action_process_image_command_line contains "\users\public\" 
| filter action_process_image_command_line contains "quote"  
    and action_process_image_command_line contains "#S_" 
    and action_process_image_command_line contains ".js" 
| fields _time, agent_hostname, actor_effective_username,  
         action_process_image_name, action_process_image_path, action_process_image_command_line,  
         actor_process_image_name, actor_process_command_line, causality_actor_process_image_sha256,  
         event_id, agent_id, _product 
```

---
## Data Sources

| Log Provider | Event Name   | ATT&CK Data Source | ATT&CK Data Component        |
|--------------|--------------|--------------------|------------------------------|
| Cortex XSIAM | xdr_data     | Process            | Process Creation |

---

## Execution Requirements
- **Required Permissions:** User or attacker must be able to execute wscript.exe and JavaScript files from user-writable paths.
- **Required Artifacts:** Process creation logs, command-line arguments, and script file metadata.

---
## Considerations
- Review the source and context of the script file for legitimacy.
- Correlate with user activity or system logs to determine if the activity is user-initiated or automated.
- Investigate any processes or scripts executed by wscript.exe for signs of malicious payload delivery or C2.
- Validate if the script file is associated with known malicious infrastructure or threat intelligence indicators.

---
## False Positives
False positives may occur if:

- Users or IT staff legitimately execute JavaScript files matching the pattern Quote #S_*.js for benign purposes.
- Automated tools or scripts generate and execute these commands for legitimate operations.

---
## Recommended Response Actions
- Investigate the script file and its execution context for intent and legitimacy.
- Analyze any processes or scripts executed by wscript.exe for signs of malicious activity.
- Review user activity and system logs for signs of compromise or C2.
- Isolate affected endpoints if malicious activity is confirmed.
- Block or monitor access to suspicious script files and their execution paths.

---
## References
- [MITRE ATT&CK: T1059.007 – Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [MITRE ATT&CK: T1204.002 – User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/)

---
## Version History
| Version | Date       | Impact            | Notes                                                              |
|---------|------------|-------------------|--------------------------------------------------------------------|
| 1.0     | 2025-08-18 | Initial Detection | Created hunt query to detect execution of Quote #S_*.js via wscript.exe|

