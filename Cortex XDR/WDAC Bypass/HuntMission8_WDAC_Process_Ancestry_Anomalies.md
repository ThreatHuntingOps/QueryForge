# Detection of Anomalous Process Parent-Child Relationships

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-ProcessAncestry-Anomalies
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt analyzes **process ancestry** to detect **anomalous parent-child execution chains** that suggest abuse of **LOLBINs** or process injection techniques to bypass WDAC policies.  

Attackers commonly launch trusted Windows binaries from **unusual parent processes** (e.g., Office documents, browsers), chaining them into malicious execution sequences to evade detection.

Detected behaviors include:

- **Office applications** spawning compilers or debuggers.  
- **Browsers** spawning compilers or system utilities.  
- **System processes** spawning compilers unexpectedly.  
- Parent-child relationships categorized and flagged as **High Risk** or **Medium Risk** depending on severity.  

---

## ATT&CK Mapping

| Tactic                  | Technique   | Subtechnique | Technique Name                          |
|-------------------------|-------------|--------------|----------------------------------------|
| TA0005 - Defense Evasion| T1055       | -            | Process Injection                       |
| TA0005 - Defense Evasion| T1218       | -            | System Binary Proxy Execution           |

---

## Hunt Query Logic

This query categorizes parent and child process roles, checks for **anomalous transitions**, and flags those that represent **unlikely or malicious execution flows**.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// Title: Process Ancestry Anomaly Detection for WDAC Bypass 
// Description: Identifies unusual parent-child process relationships indicating LOLBIN abuse 
// MITRE ATT&CK TTP ID: T1055, T1218

config case_sensitive = false  

| dataset = xdr_data  

| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START 

| alter  
    parent_category = if(  
        causality_actor_process_image_name in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"), "Office",  
        if(causality_actor_process_image_name in ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"), "Browser",   
        if(causality_actor_process_image_name in ("explorer.exe", "dwm.exe", "winlogon.exe"), "System",  
        if(causality_actor_process_image_name in ("cmd.exe", "powershell.exe", "pwsh.exe"), "Shell",  
        "Other"))) 
    ),  
    child_category = if(  
        actor_process_image_name in ("msbuild.exe", "csi.exe", "InstallUtil.exe"), "Compiler",  
        if(actor_process_image_name in ("wmic.exe", "mshta.exe", "regsvr32.exe"), "System Utility",  
        if(actor_process_image_name in ("cdb.exe", "windbg.exe", "dbghost.exe"), "Debugger",  
        if(actor_process_image_name in ("powershell.exe", "pwsh.exe", "cmd.exe"), "Shell",  
        "Other"))) 
    ) 

| alter 
    anomalous_relationship = if(  
        parent_category = "Office" and child_category in ("Compiler", "Debugger"), "High Risk",  
        if(parent_category = "Browser" and child_category in ("Compiler", "System Utility"), "High Risk",  
        if(parent_category = "System" and child_category = "Compiler", "Medium Risk",  
        "Low Risk")) 
    )  

| filter anomalous_relationship in ("High Risk", "Medium Risk")  

| fields _time, agent_hostname, causality_actor_process_image_name, actor_process_image_name,  
         actor_process_command_line, parent_category, child_category, anomalous_relationship,  
         actor_process_auth_id, causality_actor_process_ns_pid, actor_effective_username  

| sort desc _time 
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex XSIAM |    xdr_data      | Process             | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** None beyond process execution logging.  
- **Required Artifacts:** Process creation telemetry with parent/child relationship visibility.  

---

## Considerations

- Many anomalies may result from **developer or administrative environments**.  
- Automated testing and deployment processes may mimic suspicious activity.  
- Strongest signals come from Office/Browser processes spawning **compilers and debuggers**.  

---

## False Positives

False positives may occur when:  
- **IDEs or dev tools** launch compilers/debuggers.  
- **Admin scripts** automate process execution.  
- **QA/testing systems** generate unusual process chains by design.  

---

## Tuning Recommendations

- Apply **machine learning baselines** for typical process hierarchies.  
- Incorporate **temporal analysis** to distinguish persistent anomalies vs. one-offs.  
- Require **digital signature validation** for launched child processes.  

---

## Recommended Response Actions

1. Investigate anomalous parent-child chains, focusing on *Office/Browser → Compiler/Debugger/System Utility*.  
2. Analyze command lines for embedded payloads or LOLBIN abuse.  
3. Determine if execution aligns with **developer/admin context**.  
4. Correlate activity with file writes or registry modifications for policy tampering.  
5. Isolate affected hosts if **malicious inheritance chains** are confirmed.  

---

## References

- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)  
- [MITRE ATT&CK: T1218 – System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | Process ancestry anomaly detection highlighting suspicious execution chains. |
