# Detection of Fileless Decode & Execution via PowerShell/Certutil

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-DarkCloud-Fileless-Decode-Execute
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium-High

---

## Hunt Analytics

This hunt detects suspicious PowerShell, certutil, and related command-line activity consistent with DarkCloud’s fileless execution techniques. 
According to FortiGuard Labs, DarkCloud leverages phishing delivery and then executes fileless payloads by downloading encoded content, 
decoding with base64/certutil, and reflectively loading .NET assemblies in memory. 

Detected behaviors include:

- PowerShell launched with `-EncodedCommand` arguments.  
- Use of `.FromBase64String`, `IEX`, or `Invoke-Expression` for inline execution.  
- Network retrieval via `DownloadString`, `Invoke-WebRequest`, or `New-Object Net.WebClient`.  
- Abuse of `certutil.exe` with `-decode`, `-urlcache`, or `-split` parameters.  
- Attempts to load assemblies directly into memory using `Reflection.Assembly::Load`.  
- Attempts to disable Defender via `Set-MpPreference -Disable`.  

These behaviors are strongly associated with in-memory malware execution and defense evasion.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                |
|-------------------------------|-------------|--------------|----------------------------------------------|
| TA0002 – Execution            | T1059.001   | —            | Command and Scripting Interpreter: PowerShell|
| TA0002 – Execution            | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell|
| TA0005 – Defense Evasion      | T1140       | —            | Deobfuscate/Decode Files or Information      |
| TA0011 – Command & Control    | T1105       | —            | Ingress Tool Transfer                        |

---

## Hunt Query Logic

This query identifies suspicious process launches indicative of fileless malware staging by focusing on 
PowerShell, Certutil, and related processes executing encoded or obfuscated commands.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Suspicious PowerShell / Command Execution
// Description: Detects suspicious PowerShell, cmd, wscript, cscript, mshta activity that executes encoded commands, downloads content, or loads .NET assemblies.
// MITRE ATT&CK TTP ID: T1059.001 (Command and Scripting Interpreter: PowerShell)
// MITRE ATT&CK TTP ID: T1059.003 (Command and Scripting Interpreter: Windows Command Shell)

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
  and event_type = ENUM.PROCESS 
  and event_sub_type = ENUM.PROCESS_START 
| filter ( 
      action_process_image_name in ("powershell.exe","pwsh.exe","powershell_ise.exe","certutil.exe") 
      or (action_process_image_name in ("cmd.exe","wscript.exe","cscript.exe","mshta.exe") and action_process_image_command_line contains "powershell") 
   ) 
| filter action_process_image_command_line contains "-encodedcommand" 
     or action_process_image_command_line contains "frombase64string(" 
     or action_process_image_command_line contains "iex(" 
     or action_process_image_command_line contains "invoke-expression" 
     or action_process_image_command_line contains "downloadstring(" 
     or action_process_image_command_line contains "invoke-webrequest" 
     or action_process_image_command_line contains "iwr " 
     or action_process_image_command_line contains "new-object net.webclient" 
     or action_process_image_command_line contains "certutil -decode" 
     or action_process_image_command_line contains "certutil -urlcache" 
     or action_process_image_command_line contains "certutil -split" 
     or action_process_image_command_line contains "Invoke-Expression" 
     or action_process_image_command_line contains "Add-Type" 
     or action_process_image_command_line contains "Reflection.Assembly::Load" 
     or action_process_image_command_line contains "Set-MpPreference -Disable" 
| fields _time, agent_hostname, actor_effective_username, action_process_image_name, action_process_image_path, action_process_image_command_line, 
         actor_process_image_name, actor_process_command_line, causality_actor_process_command_line, causality_actor_primary_username, 
         causality_actor_process_image_sha256, event_id, agent_id, _product 
| sort desc _time 
```

---

## Data Sources

| Log Provider   | Event Name  | ATT&CK Data Source | ATT&CK Data Component |
|----------------|-------------|--------------------|------------------------|
| Cortex XSIAM   | xdr_data    | Process            | Process Creation       |

---

## Execution Requirements

- **Required Permissions:** Ability to run PowerShell or Certutil.  
- **Required Artifacts:** Process creation logs with command-line arguments.  

---

## Considerations

- Validate if usage of `certutil` or encoded PowerShell is part of legitimate administrative workflows.  
- Correlate with network traffic to confirm if downloads are contacting malicious infrastructure.  
- Cross-check against known IOCs and threat intelligence feeds.  

---

## False Positives

False positives may occur if:  

- IT administrators use encoded commands for automation or deployment.  
- Certutil is legitimately used for certificate management.  

---

## Recommended Response Actions

1. Investigate command-line arguments and parent process lineage.  
2. Review network activity associated with the process.  
3. Validate whether assembly loads or Defender modifications occurred.  
4. Isolate endpoint if malicious intent is confirmed.  
5. Initiate credential resets and malware eradication procedures if compromise is detected.  

---

## References

- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
- [MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)  
- [MITRE ATT&CK: T1140 – Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)  
- [MITRE ATT&CK: T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)  
- [Fortinet: Unveiling a New Variant of the DarkCloud Campaign](https://www.fortinet.com/blog/threat-research/unveiling-a-new-variant-of-the-darkcloud-campaign)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-17 | Initial Detection | Created hunt query for fileless decode and in-memory execution        |
