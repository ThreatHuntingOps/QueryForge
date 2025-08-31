# Detection of DarkCloud-Style Persistence via Schtasks and Registry Run Keys

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Persistence-Schtasks-RunKeys
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects persistence creation via **Scheduled Tasks** and **Registry Run/RunOnce keys**.  
Adversaries, including DarkCloud, commonly use `schtasks.exe /create` or modify Run keys to maintain persistence, often pointing to payloads in **Temp/AppData** or invoking suspicious interpreters like `wscript.exe`, `cscript.exe`, `powershell.exe`, `mshta.exe`, or `rundll32.exe`.

Detected behaviors include:

- `schtasks.exe` executions with the `/create` flag.  
- Registry modifications under Run/RunOnce pointing to suspicious interpreters or writable paths.  

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|-------------------------------|-------------|--------------|-----------------------------------------------|
| TA0003 - Persistence          | T1053.005   | Scheduled Task | Scheduled Task/Job: Scheduled Task             |
| TA0003 - Persistence          | T1547.001   | Run Keys/Startup Folder | Boot or Logon Autostart Execution |

---

## Hunt Query Logic

This query identifies suspicious persistence attempts by:

- Detecting `schtasks.exe` launched with `/create`.  
- Capturing registry writes under `Run` or `RunOnce`.  
- Filtering for values referencing user-writable directories or interpreters.  

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM

```xql
// Title: Persistence via Schtasks and Run Keys
// Description: Detects suspicious persistence creation using schtasks.exe or registry Run/RunOnce entries pointing to user-writable paths or script interpreters.
// MITRE ATT&CK TTP ID: T1053.005 (Scheduled Task/Job: Scheduled Task)
// MITRE ATT&CK TTP ID: T1547.001 (Boot or Logon Autostart: Registry Run Keys/Startup Folder)

config case_sensitive = false

| dataset = xdr_data

| filter agent_os_type = ENUM.AGENT_OS_WINDOWS

| filter (
     // schtasks creation
     (event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and action_process_image_name = "schtasks.exe"
        and action_process_image_command_line contains "/create")
     or
     // registry Run/RunOnce writes
     (event_type = ENUM.REGISTRY and event_sub_type = ENUM.REGISTRY_SET_VALUE
        and (action_registry_key_name contains "\\software\\microsoft\\windows\\currentversion\\run"
             or action_registry_key_name contains "\\runonce"))
   )

| filter (
      (event_type = ENUM.PROCESS)
      or
      (event_type = ENUM.REGISTRY and (action_registry_data contains "\\appdata\\"
                                      or action_registry_data contains "\\temp\\"
                                      or action_registry_data contains "wscript.exe"
                                      or action_registry_data contains "cscript.exe"
                                      or action_registry_data contains "powershell.exe"
                                      or action_registry_data contains "mshta.exe"
                                      or action_registry_data contains "rundll32.exe"))
   )

| fields _time, agent_hostname, actor_effective_username, event_type, event_sub_type,
         action_process_image_name, action_process_image_command_line,
         action_registry_key_name, action_registry_value_name, action_registry_data,
         actor_process_image_name, actor_process_image_path, actor_process_command_line, causality_actor_process_image_sha256, event_id, agent_id, _product

| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name   | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data     | Process, Registry  | Process Creation, Registry Key Modification |

---

## Execution Requirements

- **Required Permissions:** User or attacker must be able to create scheduled tasks or modify Run keys.  
- **Required Artifacts:** Process creation logs, registry set value events.  

---

## Considerations

- IT tools and software installers may legitimately create scheduled tasks.  
- Updaters (Chrome, Teams, Java) often add Run/RunOnce entries.  
- Developer scripts may reference interpreters in `%AppData%`.  

---

## False Positives

- Software updaters creating autoruns.  
- GPO-deployed RunOnce scripts.  
- Legitimate schtasks created by enterprise applications.  

---

## Recommended Response Actions

1. Review schtasks command lines and registry modifications.  
2. Investigate referenced executables or scripts.  
3. Confirm legitimacy with IT/deployment teams.  
4. Remove persistence artifacts if malicious.  

---

## References

- [MITRE ATT&CK T1053.005 – Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)  
- [MITRE ATT&CK T1547.001 – Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                       |
|---------|------------|-------------------|-----------------------------------------------------------------------------|
| 1.0     | August 18, 2025 | Initial Detection | Detection of persistence via schtasks creation and registry Run/RunOnce keys |
