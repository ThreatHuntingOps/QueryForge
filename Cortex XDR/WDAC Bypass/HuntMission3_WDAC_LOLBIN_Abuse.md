# Detection of Living-Off-the-Land Binary Abuse

## Severity or Impact of the Detected Behavior
- **Risk Score:** 82
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-LOLBIN-Abuse
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt identifies execution of **trusted system binaries (LOLBINs)** in anomalous contexts suggestive of **WDAC bypass or application abuse**. Malicious actors frequently exploit trusted binaries to blend into normal activity while carrying out malicious operations (e.g., script execution, payload delivery).

Detected behaviors include:

- Execution of known LOLBIN utilities (`msbuild.exe`, `csi.exe`, `InstallUtil.exe`, `mshta.exe`, etc.).  
- Suspicious parent processes such as **document editors** (Word, Excel, PowerPoint, Outlook) or **internet browsers**.  
- Suspicious command-line arguments (`/c`, `http`, `powershell`, `base64`, etc.) indicating embedded payload delivery or script chaining.  
- Execution outside of standard Windows directories (System32/SysWOW64).  

---

## ATT&CK Mapping

| Tactic                  | Technique   | Subtechnique | Technique Name                             |
|-------------------------|-------------|--------------|-------------------------------------------|
| TA0005 - Defense Evasion| T1218       | -            | System Binary Proxy Execution              |
| TA0002 - Execution      | T1059       | T1059.001    | Command and Scripting Interpreter: PowerShell |
| TA0005 - Defense Evasion| T1202       | -            | Indirect Command Execution                 |

---

## Hunt Query Logic

This query flags the execution of system binaries when observed with **abnormal parents** (Office apps, browsers, Temp/AppData paths) or **suspicious command-line arguments**. These criteria detect abuse of trusted processes deviating from typical administrative or system tasks.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Suspicious System Binary Execution (LOLBIN Detection)
// Description: Detects abuse of trusted system binaries for WDAC bypass 
// MITRE ATT&CK TTP ID: T1218, T1059.001, T1202

config case_sensitive = false 

| dataset = xdr_data 

| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START 

| filter actor_process_image_name in ( 
"msbuild.exe", "csi.exe", "InstallUtil.exe", "mshta.exe", "wmic.exe", 
"cdb.exe", "windbg.exe", "dbghost.exe", "dotnet.exe", "fsi.exe", 
"Microsoft.Workflow.Compiler.exe", "rcsi.exe", "runscripthelper.exe" 
) 

| alter 
suspicious_parent = if( 
actor_process_image_path contains "\Temp\" or 
actor_process_image_path contains "\Downloads\" or 
actor_process_image_path contains "\AppData\" or 
causality_actor_process_image_name in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "chrome.exe", "firefox.exe"), 
"Suspicious", "Normal" 
), 
suspicious_args = if( 
actor_process_command_line contains "/c " or 
actor_process_command_line contains "http" or 
actor_process_command_line contains "powershell" or 
actor_process_command_line contains "cmd.exe" or 
actor_process_command_line contains "base64" or 
actor_process_command_line contains "/u ", 
"Suspicious", "Normal" 
), 
execution_context = if( 
actor_process_image_path contains "/System32/" or actor_process_image_path contains "/SysWOW64/", "System", "User" 
) 

| filter suspicious_parent = "Suspicious" or suspicious_args = "Suspicious" 

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, 
causality_actor_process_image_name, suspicious_parent, suspicious_args, execution_context, 
actor_process_causality_id, causality_actor_process_ns_pid, actor_effective_username 

| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM |    xdr_data      | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Standard user privileges may suffice if users can run Office apps or browsers spawning LOLBINs.  
- **Required Artifacts:** Process execution telemetry with command-line capture.  

---

## Considerations

- Exploitation of LOLBINs is a prevalent **defense evasion technique** used to bypass WDAC, AV, and EDR enforcement.  
- Activities should be validated against legitimate administrative scripts, developer tool usage, or IT automation tasks.  

---

## False Positives

False positives may occur if:  
- Software developers use LOLBIN utilities in **build automation**.  
- IT administrators leverage these binaries for **maintenance scripts or diagnostics**.  
- CI/CD pipelines execute these binaries as part of legitimate workflows.  

---

## Tuning Recommendations

- **Whitelist** build servers, dev environments, and trusted automation accounts.  
- Correlate LOLBIN activity with **time-based execution patterns** to identify anomalies.  
- Apply **user-based filtering** to separate developers/admins from general workforce machines.  

---

## Recommended Response Actions

1. Investigate suspicious parent-child execution relationships.  
2. Review command-line arguments for malicious scripting patterns.  
3. Correlate with file writes, network connections, or registry modifications for deeper context.  
4. Isolate endpoints exhibiting anomalous LOLBIN abuse.  
5. Block persistence mechanisms and reinforce WDAC baselines.  

---

## References

- [MITRE ATT&CK: T1218 – System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)  
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
- [MITRE ATT&CK: T1202 – Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                    |
|---------|------------|-------------------|--------------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | Hunting query for LOLBIN execution anomalies suggesting WDAC bypass.     |
