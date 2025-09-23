# Detection of COM Object Abuse in WDAC Bypass

## Severity or Impact of the Detected Behavior
- **Risk Score:** 88
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-COM-Abuse
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects **abuse of COM objects and XSL transformations** to bypass WDAC and execute arbitrary code.  
Adversaries can instantiate COM objects, such as **MSXML and DOMDocument**, or use **XSL script processing** to load and run malicious content that would otherwise be blocked by WDAC.

Detected behaviors include:

- Indicators of **MSXML COM instantiation** and **DOM Document usage**.  
- Abuse of `transformNode` and `.xsl` references for **XSL transformations**.  
- Identifying **script hosts** such as WScript, CScript, PowerShell, or MSHTA as execution containers for COM/XSL exploitation.  

This technique has been observed in **Living-off-the-Land (LOLBIN) scenarios** and advanced exploitation chains.

---

## ATT&CK Mapping

| Tactic                  | Technique   | Subtechnique | Technique Name                                   |
|-------------------------|-------------|--------------|-------------------------------------------------|
| TA0005 - Defense Evasion| T1559       | T1559.001    | Inter-Process Communication: Component Object Model |
| TA0005 - Defense Evasion| T1220       | -            | XSL Script Processing                           |

---

## Hunt Query Logic

The query correlates command-line arguments with **COM object instantiation** and **XSL processing indicators**, highlighting suspicious usage in various script hosts.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM 

```xql
// Title: COM Object Abuse Detection for WDAC Bypass 
// Description: Detects COM object instantiation and XSL transformation abuse 
// MITRE ATT&CK TTP ID: T1559.001, T1220 

config case_sensitive = false  

| dataset = xdr_data  

| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START  

| filter actor_process_command_line contains "MSXML" or  
        actor_process_command_line contains "DOMDocument" or  
        actor_process_command_line contains "transformNode" or  
        actor_process_command_line contains "CLSID" or  
        actor_process_command_line contains "CreateObject" or  
        actor_process_command_line contains ".xsl" or  
        actor_process_command_line contains "System.Xml.Xsl"  

| alter  
    com_technique = if(  
        actor_process_command_line contains "MSXML", "MSXML COM",  
        actor_process_command_line contains "DOMDocument", "DOM Document",  
        actor_process_command_line contains "transformNode", "XSL Transform",  
        actor_process_command_line contains "CreateObject", "COM Instantiation",  
        "Unknown COM"  
    ),  
    xsl_indicators = if(  
        actor_process_command_line contains ".xsl" or  
        actor_process_command_line contains "stylesheet",  
        "XSL Present", "No XSL"  
    ),  
    script_host = if(  
        actor_process_image_name = "wscript.exe", "WScript",  
        actor_process_image_name = "cscript.exe", "CScript",   
        actor_process_image_name = "powershell.exe", "PowerShell",  
        actor_process_image_name = "mshta.exe", "MSHTA",  
        "Other"  
    )  

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line,  
         com_technique, xsl_indicators, script_host, causality_actor_process_image_name,  
         actor_process_auth_id, actor_effective_username  

| sort desc _time  
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source    | ATT&CK Data Component  |
|--------------|------------------|-----------------------|------------------------|
| Cortex XSIAM |    xdr_data      | Process               | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** User or script-level execution privileges.  
- **Required Artifacts:** Process creation telemetry with full command-line visibility.  

---

## Considerations

- COM object and XSL usage may appear during **legitimate XML transformations**.  
- Contextual analysis is necessary to determine if usage is **business-related** or **malicious exploitation**.  
- Suspect indicators include **remote XSL references** and invocations via **WScript, CSript, or MSHTA**.  

---

## False Positives

False positives may occur from:  
- **XML processing applications** leveraging DOM/XSL transforms.  
- **Web development tools** performing style transformations.  
- **Administrative scripts** automating COM objects.  

---

## Tuning Recommendations

- Conduct **content inspection** of `.xsl` files for malicious payloads.  
- Correlate with **file system telemetry** to catch dropped or staged XSLs.  
- Include **network context** to detect potentially malicious XSL file retrieval from remote locations.  

---

## Recommended Response Actions

1. Investigate processes invoking COM objects with suspicious parameters.  
2. Validate XSL files referenced or transformed for hidden embedded code.  
3. Correlate detected COM/XSL abuse with **process ancestry** and **network events**.  
4. Contain and isolate endpoints invoking COM/XSL outside of expected use cases.  
5. Apply stronger WDAC policies to explicitly restrict script hosts and COM/XSL usage.  

---

## References

- [MITRE ATT&CK: T1559.001 – Component Object Model](https://attack.mitre.org/techniques/T1559/001/)  
- [MITRE ATT&CK: T1220 – XSL Script Processing](https://attack.mitre.org/techniques/T1220/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | COM/XSL abuse detection for WDAC bypass through script hosts.         |
