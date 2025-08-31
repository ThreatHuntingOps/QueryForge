# Detection of LOLBIN Execution From Temp/AppData With Stealthy Flags

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Persistence-LOLBIN-TempAppData
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects suspicious execution of Windows **LOLBINs** (`mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `wscript.exe`, `cscript.exe`, `msbuild.exe`) from **user-writable directories** like `%TEMP%`, `%APPDATA%`, `%PROGRAMDATA%`, or `C:\Users\Public`.  
Attackers, including DarkCloud variants, leverage these trusted binaries to proxy execution of malicious scripts or DLLs and evade detection.

Detected behaviors include:

- Execution of LOLBINs with suspicious arguments (e.g., `.js`, `.vbs`, `scrobj.dll`, `javascript:`).
- Command lines referencing user-writable paths or stealthy flags (e.g., `//nologo`).

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0005 - Defense Evasion      | T1218       | —            | Signed Binary Proxy Execution                  |
| TA0002 - Execution            | T1059       | —            | Command and Scripting Interpreter              |

---

## Hunt Query Logic

This query identifies LOLBIN execution by:

- Filtering for suspicious binaries known for proxy execution.  
- Matching command lines containing references to user-writable directories.  
- Adding per-binary suspicious switches (e.g., `/i:`, `.xml`, `javascript:`).

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: LOLBIN Execution From Temp/AppData
// Description: Detects mshta/regsvr32/rundll32/wscript/cscript executing content from user-writable directories with suspicious switches.
// MITRE ATT&CK TTP ID: T1218 (Signed Binary Proxy Execution)
// MITRE ATT&CK TTP ID: T1059 (Command and Scripting Interpreter)

config case_sensitive = false

| dataset = xdr_data

| filter event_type = ENUM.PROCESS
    and event_sub_type = ENUM.PROCESS_START
    and agent_os_type = ENUM.AGENT_OS_WINDOWS

| filter action_process_image_name in ("mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","msbuild.exe")

| filter action_process_image_command_line contains "\\temp\\"
    or action_process_image_command_line contains "\\appdata\\"
    or action_process_image_command_line contains "\\programdata\\"
    or action_process_image_command_line contains "\\public\\"

| filter (
      (action_process_image_name = "regsvr32.exe" and (action_process_image_command_line contains "/i:"
                                                      or action_process_image_command_line contains "scrobj.dll"))
      or (action_process_image_name = "rundll32.exe" and (action_process_image_command_line contains "javascript:"
                                                       or action_process_image_command_line contains "url,runhtmlapplication"
                                                       or action_process_image_command_line contains ".dll,"))
      or (action_process_image_name = "mshta.exe")
      or (action_process_image_name in ("wscript.exe","cscript.exe") and (action_process_image_command_line contains ".js"
                                                                        or action_process_image_command_line contains ".vbs"
                                                                        or action_process_image_command_line contains "//nologo"))
      or (action_process_image_name = "msbuild.exe" and action_process_image_command_line contains ".xml")
   )

| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line,
         actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_image_sha256, event_id, agent_id, _product

| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name   | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data     | Process            | Process Creation      |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to launch Windows LOLBINs.  
- **Required Artifacts:** Process creation logs with command-line arguments.  

---

## Considerations

- Verify whether execution originates from legitimate enterprise tools.  
- Correlate with sibling process launches, file writes, and downloads.  
- Investigate command-line arguments to confirm malicious staging.  

---

## False Positives

- Enterprise software distribution may use `regsvr32`, `rundll32`, or `wscript` legitimately.  
- Developer use of `msbuild.exe` on `.xml` files.  
- Kiosk/VDI software running scripts from `%Public%`.  

---

## Recommended Response Actions

1. Validate command lines and parent processes.  
2. Analyze any referenced DLLs or scripts.  
3. Isolate the endpoint if malicious execution is confirmed.  
4. Block related LOLBIN abuse with allow/deny rules.  

---

## References

- [MITRE ATT&CK T1218 – Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)  
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | August 18, 2025 | Initial Detection | Detection of LOLBIN execution from Temp/AppData with stealthy flags.  |
