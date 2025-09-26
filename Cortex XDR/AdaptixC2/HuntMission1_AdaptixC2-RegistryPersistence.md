# Detection of AdaptixC2 Registry Persistence

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85  
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-AdaptixC2-RegistryPersistence  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Medium  

---

## Hunt Analytics

This hunt detects suspicious registry persistence mechanisms used by **AdaptixC2**, which abuses Windows Registry Run keys for persistence across user logons.  
The malware leverages common Windows utilities (`reg.exe`, `powershell.exe`, `cmd.exe`) to create or modify registry entries under:

- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

Observed persistence values mimic legitimate tools (e.g., `quickassist`, `logmein`) or contain unique keywords tied to AdaptixC2 (`systemware`, `techfix`).  
Execution may also involve **encoded PowerShell** (`-enc`) to hide malicious registry commands.

---

## ATT&amp;CK Mapping

| Tactic(s)                       | Technique ID | Technique Name                                                   |
|--------------------------------|--------------|-----------------------------------------------------------------|
| Persistence                    | T1547.001    | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Execution                      | T1059.001    | Command and Scripting Interpreter: PowerShell                   |
| Defense Evasion                | T1027        | Obfuscated Files or Information (encoded PowerShell -enc)       |
| Defense Evasion / Persistence  | T1112        | Modify Registry                                                 |

---

## Hunt Query Logic

This query detects:

- Registry persistence operations involving **Run keys**  
- Creation, modification, or deletion of suspicious registry values  
- Encoded PowerShell execution (`-enc`)  
- Use of suspicious persistence names (`quickassist`, `logmein`, `systemware`, `techfix`)  

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM  

```xql
// Title: AdaptixC2 Registry Persistence
// Description: Detects persistence mechanisms using Windows Registry Run keys abused by AdaptixC2.
// MITRE ATT&CK TTP ID: T1547.001

config case_sensitive = false  

| dataset = xdr_data  

| filter event_type = PROCESS and event_sub_type = ENUM.PROCESS_START  

| filter actor_process_image_name in ("reg.exe", "powershell.exe", "cmd.exe")  

| filter actor_process_command_line contains "HKEY_CURRENT_USER" and actor_process_command_line contains "Run"  

| filter actor_process_command_line contains "Microsoft\Windows\CurrentVersion\Run"  

| alter   
    detection_name = "AdaptixC2 Registry Persistence",  
    attack_technique = "T1547.001 - Registry Run Keys",  
    registry_operation = if(actor_process_command_line contains "add", "CREATE", if(actor_process_command_line contains "delete", "DELETE", "MODIFY")),  
    has_suspicious_names = if(actor_process_command_line contains "quickassist"  
                             or actor_process_command_line contains "logmein"  
                             or actor_process_command_line contains "systemware"  
                             or actor_process_command_line contains "techfix", "yes", "no"), 
    powershell_execution = if(actor_process_command_line contains "powershell" and actor_process_command_line contains "-enc", "yes", "no") 

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, registry_operation, has_suspicious_names, powershell_execution, detection_name, attack_technique  

| sort desc _time  
```

---

## Data Sources

| Log Provider | Event Name        | ATT&CK Data Source  | ATT&CK Data Component   |
|--------------|-------------------|---------------------|-------------------------|
| Cortex XSIAM | xdr_data          | Process             | Process Creation        |
| Cortex XSIAM | Windows Registry  | Registry            | Registry Key/Value Mod. |

---

## Execution Requirements

- **Required Permissions:** Attacker must be able to write to HKCU registry keys.  
- **Required Artifacts:** Process creation logs, registry modification events, command-line arguments.  

---

## Considerations

- Identify if registry persistence keys are legitimate IT tools or **malware persistence implants**.  
- Correlate suspicious process execution with **user logon activity**.  
- Verify if modifications align with **system updates or user-installed software**.  

---

## False Positives

False positives may occur when:  
- Administrators legitimately modify registry keys for software auto-start.  
- Security agents or IT automation tools write registry values for endpoint management.  

Extra validation with **process lineage and user context** is recommended.  

---

## Recommended Response Actions

1. Investigate processes modifying Run keys (`reg.exe`, `cmd.exe`, `powershell.exe`).  
2. Review suspicious value names and compare against **known AdaptixC2 indicators**.  
3. Validate whether encoded PowerShell (`-enc`) usage is legitimate.  
4. If confirmed malicious:  
   - Isolate the endpoint  
   - Remove persistence keys  
   - Scan for secondary payloads  
   - Reset user credentials  

---

## References

- [MITRE ATT&CK: T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)  
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
- [MITRE ATT&CK: T1112 – Modify Registry](https://attack.mitre.org/techniques/T1112/)  

---

## Version History

| Version | Date       | Impact           | Notes                                                                 |
|---------|------------|-----------------|-----------------------------------------------------------------------|
| 1.0     | 2025-09-26 | Initial Release  | Created hunt query to detect AdaptixC2 registry persistence mechanisms |
