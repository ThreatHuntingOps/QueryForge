# Advanced LOLBIN Command Line Pattern Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 84
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-LOLBIN-CmdPatterns
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt performs deep **command-line analysis** of **trusted binaries (LOLBINs)** to detect suspicious abuse patterns commonly used in **WDAC bypass techniques**. It strengthens detection reliability by analyzing inline compilation, uninstall flags, `.xsl` execution, scriptlets, and network-sourced `.hta` payloads.

Detected behaviors include:

- **Msbuild Inline Tasks** (`<Task>`, `inline`) for code execution.  
- **InstallUtil Uninstall Flag** (`/u`) for malicious DLL execution.  
- **WMI with XSL Transformation** (`.xsl`, `format:`) to execute scripts.  
- **MSHTA launching remote or local `.hta` files**.  
- **Regsvr32 Scriptlet Abuse** using `/s` and `/u` flags.  
- Suspicious file extensions (`.txt`, `.log`, `.tmp`, `.dat`) in LOLBIN commands.

---

## ATT&CK Mapping

| Tactic                  | Technique   | Subtechnique | Technique Name                                    |
|-------------------------|-------------|--------------|--------------------------------------------------|
| TA0005 - Defense Evasion| T1218       | T1218.007    | System Binary Proxy Execution: Msbuild           |
| TA0005 - Defense Evasion| T1218       | T1218.010    | System Binary Proxy Execution: Regsvr32          |
| TA0002 - Execution      | T1059       | T1059.005    | Command and Scripting Interpreter: Visual Basic  |

---

## Hunt Query Logic

This query evaluates command-line arguments for **specific abuse patterns** tied to well-documented LOLBIN techniques. Filtering on operator usage, file types, and parent context strengthens the fidelity of detection by identifying **abuse vs. legitimate use cases**.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// Title: Advanced LOLBIN Command Line Pattern Detection 
// Description: Deep analysis of command-line patterns for LOLBIN abuse 
// MITRE ATT&CK TTP ID: T1218.007, T1218.010, T1059.005

config case_sensitive = false   

| dataset = xdr_data   

| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START    

| filter actor_process_image_name in (  
    "msbuild.exe", "InstallUtil.exe", "wmic.exe", "mshta.exe",   
    "regsvr32.exe", "rundll32.exe", "cmstp.exe"  
)  

| alter  
    msbuild_inline = if(  
        actor_process_image_name = "msbuild.exe" and   
        (actor_process_command_line contains "<Task>" or actor_process_command_line contains "inline"),  
        "Detected", "None"  
    ),  
    installutil_uninstall = if(  
        actor_process_image_name = "InstallUtil.exe" and actor_process_command_line contains "/u",  
        "Detected", "None"    
    ),  
    wmic_xsl = if(  
        actor_process_image_name = "wmic.exe" and   
        (actor_process_command_line contains ".xsl" or actor_process_command_line contains "format:"),  
        "Detected", "None"  
    ),  
    mshta_hta = if(  
        actor_process_image_name = "mshta.exe" and  
        (actor_process_command_line contains "http" or actor_process_command_line contains ".hta"),  
        "Detected", "None"  
    ),  
    regsvr32_scriptlet = if(  
        actor_process_image_name = "regsvr32.exe" and  
        (actor_process_command_line contains "/s" and actor_process_command_line contains "/u"),  
        "Detected", "None"  
    ),  
    suspicious_file_extension = if(  
        actor_process_command_line ~= ".*\.(txt|log|tmp|dat).*", "Non-standard Extension", "Standard"  
    )  

| filter msbuild_inline = "Detected" or installutil_uninstall = "Detected" or   
        wmic_xsl = "Detected" or mshta_hta = "Detected" or regsvr32_scriptlet = "Detected" or 
        suspicious_file_extension = "Non-standard Extension" 

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line,  
         msbuild_inline, installutil_uninstall, wmic_xsl, mshta_hta, regsvr32_scriptlet,  
         suspicious_file_extension, actor_process_auth_id, actor_effective_username  

| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM |    xdr_data      | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Execution of trusted system binaries.  
- **Required Artifacts:** Process logs with detailed command-line parameters.  

---

## Considerations

- Inline compilation and script abuse may appear in legitimate **development environments**.  
- Administrative use of regsvr32 or msbuild in scripts can trigger alerts if not tuned.  

---

## False Positives

False positives may occur in:  
- **Software installations** leveraging InstallUtil or Regsvr32.  
- **Developer build systems** executing inline tasks.  
- **Administrative scripts** invoking msbuild, mshta, or wmic.  

---

## Tuning Recommendations

- Implement **file path analysis** to differentiate system vs. user directory execution.  
- Add **process ancestry checks** to capture suspicious parent-child process chains.  
- Baseline **legitimate developer/IT-admin activity** to reduce alert fatigue.  

---

## Recommended Response Actions

1. Investigate command-line execution for suspected LOLBIN abuse.  
2. Review artifact file paths (`.hta`, `.xsl`, `.tmp`) for malicious content.  
3. Correlate detected execution with network or registry modifications.  
4. Contain impacted hosts showing repeated suspicious patterns.  
5. Apply targeted WDAC and EDR policies to block identified execution paths.  

---

## References

- [MITRE ATT&CK: T1218.007 – System Binary Proxy Execution: Msbuild](https://attack.mitre.org/techniques/T1218/007/)  
- [MITRE ATT&CK: T1218.010 – System Binary Proxy Execution: Regsvr32](https://attack.mitre.org/techniques/T1218/010/)  
- [MITRE ATT&CK: T1059.005 – Visual Basic](https://attack.mitre.org/techniques/T1059/005/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | Hunting query for advanced LOLBIN command-line abuse patterns.        |
