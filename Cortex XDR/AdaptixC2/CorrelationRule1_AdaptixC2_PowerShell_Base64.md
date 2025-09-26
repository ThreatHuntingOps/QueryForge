# AdaptixC2 PowerShell Base64 Shellcode Loader Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90 (AdaptixC2 memory injection via PowerShell)  
- **Severity:** High  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-AdaptixC2-PowerShell-Base64  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Low (long obfuscated PowerShell commands with Base64 patterns)  

---

## Analytics

This correlation rule detects **malicious PowerShell loaders associated with AdaptixC2** that leverage Base64-encoded shellcode injection.  

Detected behaviors include:  
- **Use of System.Convert::FromBase64String** to decode payloads.  
- **Presence of common Base64 markers/prefixes** (`==`, `TVq`, `JAB`, `aAB`).  
- **Combination with memory execution APIs** (`VirtualAlloc`, `GetDelegateForFunctionPointer`).  
- **Extended PowerShell command length (200+ chars)** indicative of obfuscation and payload embedding.  

This behavior is mapped to both **execution** and **defense evasion** tactics.  

---

## ATT&amp;CK Mapping

| Tactic                  | Technique  | Subtechnique | Technique Name                           |
|-------------------------|------------|--------------|-----------------------------------------|
| Execution               | T1059.001  | -            | Command and Scripting Interpreter: PowerShell |
| Defense Evasion         | T1027      | -            | Obfuscated Files or Information          |
| Defense Evasion / Priv. Escalation | T1055 | - | Process Injection (VirtualAlloc, delegate calls) |
| Execution               | T1106      | -            | Native API                               |

---

## Query Logic

This analytic correlates **malicious PowerShell invocations with encoded payloads**.  
It prioritizes signals containing:  

- `System.Convert::FromBase64String` + base64 markers.  
- Memory execution primitives (`VirtualAlloc`, delegates).  
- Long suspicious command lines.  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
config case_sensitive = false  
| dataset = xdr_data  
| filter event_type = PROCESS and event_sub_type = ENUM.PROCESS_START  
| filter actor_process_image_name ~= "powershell.exe"  
| filter actor_process_command_line contains "System.Convert" and actor_process_command_line contains "FromBase64String"  
| alter detection_name = "AdaptixC2 PowerShell Base64 Shellcode Loader",  
       attack_technique = "T1059.001 - PowerShell",  
       command_length = len(actor_process_command_line), 
       has_common_base64_chars = if(actor_process_command_line contains "=="  
                                    or actor_process_command_line contains "TVq"  
                                    or actor_process_command_line contains "JAB"  
                                    or actor_process_command_line contains "aAB", "yes", "no"), 
       uses_virtualalloc = if(actor_process_command_line contains "VirtualAlloc", "yes", "no"), 
       uses_getdelegate = if(actor_process_command_line contains "GetDelegateForFunctionPointer", "yes", "no") 
| filter command_length > 200  
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, actor_primary_username, detection_name, command_length, has_common_base64_chars, uses_virtualalloc, uses_getdelegate, attack_technique  
| sort desc command_length
```

---

## Data Sources

| Log Provider   | Event Name    | ATT&amp;CK Data Source | ATT&amp;CK Data Component     |
|----------------|---------------|-----------------------|------------------------------|
| Cortex XSIAM   | xdr_data      | Process               | Process Creation             |

---

## Execution Requirements  
- **Required Permissions:** User-level sufficient (though payload may escalate).  
- **Required Artifacts:** Process telemetry.  

---

## Considerations  
- Long PowerShell commands with base64 payloads are almost always malicious.  
- Detection tuned to reduce noise by enforcing minimum command length & markers.  

---

## False Positives  
- Rare, but could occur with administrators/script developers testing obfuscation.  

---

## Recommended Response Actions  
1. **Isolate system** showing AdaptixC2 PowerShell activity.  
2. **Extract suspicious command line** and payload for reverse engineering.  
3. **Investigate for lateral movement or C2 callbacks.**  
4. **Hunt across enterprise for similar command line markers.**  
5. **Apply PowerShell logging and AMSI inspection** to expand visibility.  

---

## References  
- [MITRE ATT&amp;CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
- [MITRE ATT&amp;CK: T1027 – Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)  
- [MITRE ATT&amp;CK: T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)  
- [MITRE ATT&amp;CK: T1106 – Native API](https://attack.mitre.org/techniques/T1106/)  

---

## Version History  

| Version | Date       | Impact                         | Notes                                                        |
|---------|------------|--------------------------------|--------------------------------------------------------------|
| 1.0     | 2025-09-26 | Initial Detection Contribution | Added correlation specific to AdaptixC2 PowerShell Base64 loader |
