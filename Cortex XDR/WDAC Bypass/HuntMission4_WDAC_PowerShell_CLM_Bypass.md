# Detection of PowerShell CLM Bypass Attempts

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-PowerShell-CLM-Bypass
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt identifies attempts to bypass **PowerShell's Constrained Language Mode (CLM)**. WDAC policies typically enforce CLM to restrict PowerShell's capabilities, preventing attackers from leveraging its full functionality. Detection of CLM bypass attempts indicates **possible enforcement tampering** or exploitation of known vulnerabilities.

Detected behaviors include:

- Use of known CLM bypass methods and CVE exploitation patterns (e.g., `PSWorkflowUtility`, `MSFT_ScriptResource`).  
- Invocation of suspicious constructs like `Add-Type`, `Reflection.Assembly`, `New-Object System.CodeDom`.  
- PowerShell command lines attempting to force **FullLanguage mode** or reference **ConstrainedLanguage mode checks**.  

These techniques reflect attackers evading WDAC policies to regain full scripting and offensive capabilities.

---

## ATT&CK Mapping

| Tactic                  | Technique   | Subtechnique | Technique Name                                   |
|-------------------------|-------------|--------------|-------------------------------------------------|
| TA0002 - Execution      | T1059       | T1059.001    | Command and Scripting Interpreter: PowerShell   |
| TA0005 - Defense Evasion| T1211       | -            | Exploitation for Defense Evasion                |

---

## Hunt Query Logic

This query flags PowerShell and PowerShell Core (`pwsh.exe`) executions that contain **CLM bypass indicators**, mapping command-line content to specific exploit/bypass methods. It also tracks explicit and implicit language mode checks.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: PowerShell Constrained Language Mode Bypass Detection 
// Description: Detects attempts to bypass PowerShell CLM restrictions 
// MITRE ATT&CK TTP ID: T1059.001, T1211

config case_sensitive = false  

| dataset = xdr_data  

| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START  

| filter actor_process_image_name = "powershell.exe" or actor_process_image_name = "pwsh.exe"  

| filter actor_process_command_line contains "PSWorkflowUtility" or  
        actor_process_command_line contains "Invoke-History" or  
        actor_process_command_line contains "MSFT_ScriptResource" or  
        actor_process_command_line contains "System.Management.Automation.PSCustomHost" or  
        actor_process_command_line contains "Add-Type" or  
        actor_process_command_line contains "New-Object System.CodeDom" or  
        actor_process_command_line contains "Reflection.Assembly" or  
        actor_process_command_line contains "ConstrainedLanguage" or  
        actor_process_command_line contains "FullLanguage"  

| alter   
    bypass_technique = if( 
        actor_process_command_line contains "PSWorkflowUtility", "CVE-2017-0215", 
        if(actor_process_command_line contains "Invoke-History", "History Injection", 
        if(actor_process_command_line contains "MSFT_ScriptResource", "CVE-2018-8212", 
        if(actor_process_command_line contains "Add-Type", "Type Compilation", 
        if(actor_process_command_line contains "Reflection.Assembly", "Assembly Loading", 
        "Unknown")))) 
    ),  
    language_mode_check = if(  
        actor_process_command_line contains "LanguageMode", "Explicit Check", "Implicit"  
    )  

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line,  
         bypass_technique, language_mode_check, causality_actor_process_image_name,  
         actor_process_auth_id, actor_effective_username, actor_process_signature_status  

| sort desc _time  
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM |    xdr_data      | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** PowerShell execution access; WDAC environment enforcing CLM.  
- **Required Artifacts:** Process creation logs, command-line arguments, and user context.  

---

## Considerations

- CLM bypass attempts may be precursors to **further script-based exploitation**.  
- Review for **script block logging** or correlated registry modifications to confirm bypass success.  
- Explicit checks for CLM/FullLanguage mode can help distinguish attacker recon from benign probing.  

---

## False Positives

False positives may occur in cases of:  
- **Legitimate PowerShell module development and testing**.  
- **Administrative scripts** that query language mode status.  
- **Security tools** or red team exercises validating PowerShell restrictions.  

---

## Tuning Recommendations

- Correlate with **PowerShell script block logging** for deeper context.  
- Implement **user-based filtering** to account for developers and administrators.  
- Add **network telemetry correlation** to separate local testing from remote exploitation.  

---

## Recommended Response Actions

1. Investigate identified command-line usage for malicious context.  
2. Isolate impacted endpoints if bypass attempts appear successful.  
3. Retrieve executed scripts or PS profiles for forensic review.  
4. Validate WDAC policy enforcement mode across enterprise systems.  
5. Enhance monitoring of PowerShell CLM status and registry keys.  

---

## References

- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
- [MITRE ATT&CK: T1211 – Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211/)  
- [Microsoft – PowerShell Constrained Language Mode](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | Hunting query for PowerShell CLM bypass attempts, including CVE-based exploits. |
