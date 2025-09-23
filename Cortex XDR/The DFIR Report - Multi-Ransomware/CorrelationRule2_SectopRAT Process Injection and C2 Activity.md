# SectopRAT Malware Execution and C2 Communications

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (High Confidence SectopRAT via injection + C2)  
- **Severity:** Critical  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-SectopRAT  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low  

---

## Analytics

This correlation rule detects **SectopRAT malware behaviors** involving **process injection into MSBuild.exe** and subsequent **command and control (C2) communications**.  

Detected behaviors include:  

- **Process injection into MSBuild.exe**, abusing it as a proxy for malicious activity under a trusted Microsoft binary.  
- **Suspicious network activity** originating from MSBuild.exe, including connections to known malicious IPs (`45.141.87.55`, `149.28.101.219`) on ports **9000, 15647, and 443**.  
- **SystemBC DLL staging** via suspicious file writes (`wakewordengine.dll`, `conhost.dll`) in atypical directories like `Users\Public\Music`.  
- **Credential theft attempts** targeting directories associated with **Steam, Telegram, Discord, and cryptocurrency wallets**.  

This correlation ensures detection only when **network C2 behaviors combine with payload staging or credential harvesting**, minimizing false positives.

---

## ATT&CK Mapping

| Tactic             | Technique | Subtechnique | Technique Name                                  |
|--------------------|-----------|--------------|------------------------------------------------|
| Defense Evasion    | T1055     | -            | Process Injection                              |
| Command & Control  | T1071     | T1071.001    | Application Layer Protocol: Web Protocols      |
| Credential Access  | T1555     | T1555.003    | Credentials from Password Stores: Web Browsers |
| Collection         | T1005     | -            | Data from Local System                         |

---

## Query Logic

This rule correlates **MSBuild injection activity** with **SystemBC payload staging**, **credential theft**, and **non-standard C2 communications**.  

The correlation filter detects:  
- **MSBuild C2 + SystemBC payload**  
- **MSBuild C2 + credential harvesting**  
- **MSBuild process + C2 traffic**  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Hunt for SectopRAT process injection and C2 communications
config case_sensitive = false  
| dataset = xdr_data  
| filter event_type in (PROCESS, FILE, NETWORK) 

// Phase 1: Identify MSBuild.exe process starts 
| alter msbuild_process = if( 
        event_type = PROCESS and actor_process_image_name contains "msbuild.exe", 
        true, false 
  ) 

// Phase 2: Suspicious MSBuild C2 activity 
| alter msbuild_c2 = if( 
        event_type = NETWORK and causality_actor_process_image_name contains "msbuild.exe" and 
        (dst_action_external_port in (9000, 15647, 443)) and 
        (dst_actor_remote_ip contains "45.141.87.55" or  
         dst_actor_remote_ip contains "149.28.101.219" or 
         dst_action_country not in ("US","Internal")), 
        true, false 
  ) 

// Phase 3: SystemBC DLL write (payload staging) 
| alter systembc_dll = if( 
        event_type = FILE and 
        (action_file_name contains "wakewordengine.dll" or  
         action_file_name contains "conhost.dll") and 
        action_file_path contains "Users\\Public\\Music", 
        true, false 
  ) 

// Phase 4: Credential theft attempts 
| alter credential_theft = if( 
        event_type = FILE and 
        causality_actor_process_image_name contains "msbuild.exe" and 
        (action_file_path contains "Steam" or  
         action_file_path contains "Telegram" or 
         action_file_path contains "Discord" or 
         action_file_path contains "wallet"), 
        true, false 
  ) 

// Correlation filter – require strong overlaps 
| filter (msbuild_c2 = true and systembc_dll = true)   // MSBuild C2 + SystemBC payload 
    or (msbuild_c2 = true and credential_theft = true) // MSBuild C2 + credential harvesting 
    or (msbuild_process = true and msbuild_c2 = true)  // Process + network behavior 

// Enrich with detection context 
| alter detection_category = if(msbuild_c2 = true and systembc_dll = true, "High Confidence SectopRAT", 
                           if(msbuild_c2 = true and credential_theft = true, "SectopRAT Credential Harvesting", 
                           if(msbuild_process = true and msbuild_c2 = true, "MSBuild C2 Activity", 
                           if(systembc_dll = true, "SystemBC Deployment", 
                           "Suspicious Process Activity")))), 
       risk_score = if(msbuild_c2 = true and systembc_dll = true, 95, 
                  if(msbuild_c2 = true and credential_theft = true, 90, 
                  if(msbuild_process = true and msbuild_c2 = true, 85, 
                  if(systembc_dll = true, 80, 
                  60)))) 

// Output fields 
| fields _time, 
         agent_hostname, 
         actor_process_image_name, 
         actor_process_command_line, 
         causality_actor_process_image_name, 
         dst_action_external_port, 
         dst_actor_remote_ip, 
         action_file_path, 
         detection_category, 
         risk_score, 
         event_type 

| sort desc risk_score, desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component        |
|----------------|------------|--------------------|------------------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation             |
| Cortex XSIAM   | xdr_data   | File               | File Creation                |
| Cortex XSIAM   | xdr_data   | Network            | Network Connection           |

---

## Execution Requirements  
- **Required Permissions:** User-level for injection; elevated may be used for credential theft.  
- **Required Artifacts:** File, process, and network telemetry.  

---

## Considerations  
- Activity is **highly suspicious** since MSBuild is not expected to exhibit C2 communications.  
- Credential theft targeting browsers and wallets suggests a dual-goal operation (data theft + persistence).  
- Presence of SystemBC DLL staging indicates **payload delivery & proxying for C2 evasion**.  

---

## False Positives  
- Rare; legitimate MSBuild processes should not exhibit artifact writes in `Users\Public\Music` or connections to flagged IPs/ports.  

---

## Recommended Response Actions  
1. **Immediately isolate the host**.  
2. **Analyze MSBuild.exe memory space** for injected modules.  
3. **Inspect SystemBC DLLs** and remove staged payloads.  
4. **Review credentials, browser data, and wallet files** for theft attempts.  
5. **Perform wide hunt** for connections to the indicator IPs and ports across the enterprise.  

---

## References  
- [MITRE ATT&CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)  
- [MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)  
- [MITRE ATT&CK: T1555.003 – Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)  
- [MITRE ATT&CK: T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/)  

---

## Version History  

| Version | Date       | Impact                  | Notes                                                             |
|---------|------------|-------------------------|-------------------------------------------------------------------|
| 1.0     | 2025-09-18 | Initial Detection       | Added correlation for SectopRAT injection, SystemBC DLL, and C2. |
