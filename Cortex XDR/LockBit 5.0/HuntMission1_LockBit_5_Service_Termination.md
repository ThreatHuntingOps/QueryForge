# Detection of Security Service Termination - LockBit 5.0

## Severity or Impact of the Detected Behavior
- **Risk Score:** 92  
- **Severity:** Critical  

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LockBit-ServiceTermination  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low (requires multiple service stop/delete/kill operations against security tools)  

---

## Hunt Analytics

This hunt query detects systematic **termination or manipulation of security services** by adversaries, particularly **LockBit 5.0**, which is known to target more than 63 different AV, EDR, backup, and Windows services prior to mass file encryption.  

Detected behaviors include:  
- **Service control operations** via `sc.exe` (`stop`, `delete`, `config`).  
- **Net stop commands** against security products.  
- **PowerShell-based service control** (`Stop-Service`, `Set-Service`, `Get-Service`).  
- **Taskkill usage** to forcefully terminate AV/EDR processes.  
- **Targeting of security-related patterns** (Defender, CrowdStrike, SentinelOne, Cylance, Symantec, McAfee, Sophos, CarbonBlack, etc.).  
- **Threshold enforcement** requiring **≥2 service manipulation indicators** to fire, reducing false positives.  

This query detects **disruption of defenses** which is a strong precursor to ransomware impact phases.  

---

## ATT&CK Mapping

| Tactic          | Technique   | Subtechnique | Technique Name                           |
|-----------------|-------------|--------------|------------------------------------------|
| Impact          | T1489       | -            | Service Stop                             |
| Defense Evasion | T1562.001   | -            | Impair Defenses: Disable or Modify Tools |

---

## Hunt Query Logic

This query focuses on detecting suspicious service manipulation by adversaries:  
- Match process names (`sc.exe`, `net.exe`, `powershell.exe`, `taskkill.exe`).  
- Require **commands targeting service stop/delete/kill/config** operations.  
- Enforce presence of **security product names or generic keywords** (`antivirus`, `firewall`, `security`, `backup`).  
- Count multiple suspicious indicators per process execution (`service_count >= 2`).  

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XDR and XSIAM  

```xql
// Description: Detects systematic termination of security services using service hashing patterns characteristic of LockBit 5.0's 63+ service target list
// MITRE ATT&CK TTP ID: T1489 (Service Stop) 
// MITRE ATT&CK TTP ID: T1562.001 (Disable or Modify Tools)

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
| filter event_type = ENUM.PROCESS 

| filter ( 
    // Service control operations 
    (action_process_image_name = "sc.exe" and ( 
    action_process_image_command_line contains "stop" 
    or action_process_image_command_line contains "delete"  
    or action_process_image_command_line contains "config" 
    )) 
    or 

    // Net stop commands 
    (action_process_image_name = "net.exe" and action_process_image_command_line contains "stop") 
    or 

    // PowerShell service manipulation 
    (action_process_image_name = "powershell.exe" and ( 
    action_process_image_command_line contains "Stop-Service" 
    or action_process_image_command_line contains "Get-Service" 
    or action_process_image_command_line contains "Set-Service" 
    )) 
    or 

    // Taskkill against security processes 
    (action_process_image_name = "taskkill.exe" and ( 
    action_process_image_command_line contains "/f" 
    or action_process_image_command_line contains "/t" 
    )) 
) 

| filter ( 
    // Target security-related service patterns 
    action_process_image_command_line ~= "(?i)(avast|kaspersky|norton|mcafee|bitdefender|malwarebytes|defender|symantec|sophos|carbonblack|crowdstrike|sentinelone|cylance|endgame|windows security|wuauserv|bits|cryptsvc|msiserver|trustedinstaller|vss|swprv|sppsvc|backup)" 
    or action_process_image_command_line ~= "(?i)(antivirus|firewall|security|backup|update|patch|monitor)" 
) 

| alter service_count = array_length(regextract(action_process_image_command_line, "(?i)(stop|delete|kill)")) 

| filter service_count >= 2 

| fields _time, agent_hostname, actor_effective_username,  
    action_process_image_name, action_process_image_command_line, 
    causality_actor_process_image_name, causality_actor_process_command_line, 
    service_count, actor_process_image_sha256, event_id

| sort desc service_count, desc _time 
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements  
- **Required Permissions:** Process execution telemetry with command line capture.  
- **Required Artifacts:** Process start events (including command-line arguments).  

---

## Considerations  
- Multiple service stop/delete commands in a single process strongly indicates malicious intent.  
- LockBit variants consistently execute **batch-style disabling of defenses** before proceeding to encryption.  
- Hunt results should be correlated with **subsequent file encryption** activity for full kill chain confirmation.  

---

## False Positives  
- Uncommon; may occur if administrators legitimately use service maintenance or patching scripts.  
- False positives mitigated by requiring multiple service command matches (≥2).  

---

## Recommended Response Actions  
1. Investigate the host and process invocation context.  
2. Identify whether **security services were disabled** and re-enable immediately.  
3. Block or quarantine the **process responsible for service termination**.  
4. Correlate activity with subsequent **file encryption or persistence attempts**.  
5. Isolate and scan the system for ransomware artifacts.  

---

## References  
- [MITRE ATT&CK: T1489 – Service Stop](https://attack.mitre.org/techniques/T1489/)  
- [MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)  

---

## Version History  

| Version | Date       | Impact                         | Notes                                          |
|---------|------------|--------------------------------|------------------------------------------------|
| 1.0     | 2025-10-01 | Initial Release of Detection   | Detects LockBit service termination activity.  |
