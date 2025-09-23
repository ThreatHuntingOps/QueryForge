# Detection of Suspicious WScript JavaScript Execution With Stealth Flags

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WScript-Stealth-Flags
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects `wscript.exe` executing `.js` files with stealthy flags or suspicious tokens commonly seen in droppers. These flags and tokens are often used to obfuscate malicious activity, such as payload delivery or command and control. Detected behaviors include:

- Execution of `wscript.exe` with stealth flags (e.g., `//B`, `//Nologo`, `JScript.Encode`)
- Presence of suspicious tokens (e.g., `ActiveXObject`, `MSXML2.XMLHTTP`, `ADODB.Stream`)

These techniques are associated with initial access, payload delivery, or command and control.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0002 - Execution           | T1059.007   | —            | Command and Scripting Interpreter: JavaScript |
| TA0001 - Initial Access      | T1204.002   | —            | User Execution: Malicious File                |

---

## Hunt Query Logic

This query identifies suspicious script execution by looking for:

- `wscript.exe` executing `.js` files with stealth flags (e.g., `//B`, `//Nologo`, `JScript.Encode`)
- Presence of suspicious tokens (e.g., `ActiveXObject`, `MSXML2.XMLHTTP`, `ADODB.Stream`)

These patterns are indicative of attempts to execute malicious scripts for initial access or payload delivery.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Suspicious WScript JS Execution 
// Description: Detects wscript.exe running .js with stealthy flags or common dropper tokens. 
// MITRE ATT&CK TTP ID: T1059.007, T1204.002 

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START 
| filter action_process_image_name = "wscript.exe" 
| filter action_process_image_command_line contains ".js" 
| filter action_process_image_command_line contains "//b" 
    or action_process_image_command_line contains "//nologo" 
    or action_process_image_command_line contains "//e:jscript" 
    or action_process_image_command_line contains "//e:javascript" 
    or action_process_image_command_line contains "/e:jscript" 
    or action_process_image_command_line contains "/e:javascript" 
    or action_process_image_command_line contains "jscript.encode" 
| filter action_process_image_command_line contains "activexobject" 
    or action_process_image_command_line contains "wscript.createobject" 
    or action_process_image_command_line contains "msxml2.xmlhttp" 
    or action_process_image_command_line contains "adodb.stream" 
    or action_process_image_command_line contains "scripting.filesystemobject" 
| fields _time, agent_hostname, actor_effective_username, 
         action_process_image_name, action_process_image_path, action_process_image_command_line, 
         actor_process_image_name, actor_process_command_line, causality_actor_process_image_sha256, 
         event_id, agent_id, _product 

```

---

## Data Sources
| Log Provider | Event Name   | ATT&CK Data Source | ATT&CK Data Component        |
|--------------|--------------|--------------------|-------------------------------|
| Cortex XSIAM | xdr_data     | Process            | Process Creation              |

---

## Execution Requirements
- **Required Permissions:** User or attacker must be able to execute wscript.exe and JavaScript files with stealth flags or tokens.
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

- Users or IT staff legitimately execute JavaScript files with stealth flags or tokens for benign purposes.
- Automated tools or scripts generate and execute these commands for legitimate operations.
- Recommended Response Actions
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
| 1.0     | 2025-08-18 | Initial Detection | Created hunt query to detect suspicious WScript JavaScript execution with stealth flags|
