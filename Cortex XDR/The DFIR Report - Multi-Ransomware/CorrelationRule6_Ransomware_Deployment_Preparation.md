# Ransomware Deployment Indicators - Multi-RaaS Affiliate Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100 (Active ransomware deployment)  
- **Severity:** Critical

## Analytics Metadata
- **ID:** CorrelationRule-Ransomware-MultiRaaS
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low to Medium

---

## Analytics

This correlation rule detects **pre-ransomware staging and multi-affiliate Ransomware-as-a-Service (RaaS) activity**. It focuses on overlapping tradecraft observed across **Play, RansomHub, and DragonForce** ransomware operations.  

Detected behaviors include:

- **Play Ransomware indicators**: usage of the **Grixba scanner** with subsequent shadow copy deletion.  
- **RansomHub indicators**: the **Betruger backdoor paired with PsExec execution**, along with backup termination.  
- **DragonForce indicators**: **NetScan + SystemBC proxy** with share enumeration.  
- **Pre-ransomware staging**: shadow copy deletion, backup termination, and share enumeration across observed campaigns.  
- **Encryption & ransom activity**: processes linked to file encryption and creation of ransom notes with filenames such as `readme.txt`, `decrypt.html`, etc.  

The correlation requires **family-specific tradecraft combined with preparation activity** or activity across **multiple RaaS affiliates**. This ensures high-confidence detection of advanced ransomware campaign staging.

---

## ATT&CK Mapping

| Tactic          | Technique | Subtechnique | Technique Name               |
|-----------------|-----------|--------------|-----------------------------|
| Impact          | T1486     | -            | Data Encrypted for Impact    |
| Impact          | T1490     | -            | Inhibit System Recovery      |
| Discovery       | T1135     | -            | Network Share Discovery      |
| Impact          | T1489     | -            | Service Stop                 |
| Defense Evasion | T1070     | T1070.001    | Indicator Removal: Event Logs|

---

## Query Logic

This rule correlates events across multiple **ransomware staging techniques** and **multi-RaaS tool signatures**. Detection triggers on **Play, RansomHub, or DragonForce indicators**, particularly when combined with **shadow copy deletion, backup termination, share enumeration, ransom note creation, or encryption activity**.  

Multi-affiliate overlap (Play + RansomHub, RansomHub + DragonForce, etc.) raises confidence of **affiliate-driven intrusions**.  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Hunt for ransomware deployment indicators and multi-RaaS affiliate TTPs
config case_sensitive = false 
| dataset = xdr_data 
| filter event_type in (PROCESS, FILE)

// Family indicators (Play, RansomHub, DragonForce)
| alter play_indicators = if(event_type = PROCESS and (actor_process_image_name in ("gt_net.exe","grb_net.exe","grixba")), true, false)
| alter ransomhub_indicators = if(event_type = PROCESS and ((actor_process_image_name contains "ccs.exe" and actor_process_command_line contains "avast") or (actor_process_image_name contains "psexec.exe" and actor_process_command_line contains "-s")), true, false)
| alter dragonforce_indicators = if((event_type = PROCESS and actor_process_image_name contains "netscan") or (event_type = FILE and action_file_name in ("wakewordengine.dll","conhost.dll")), true, false)

// Pre-ransomware activities
| alter shadow_copy_deletion = if(event_type = PROCESS and (actor_process_command_line contains "vssadmin delete shadows" or actor_process_command_line contains "wmic shadowcopy delete" or (actor_process_command_line contains "bcdedit" and actor_process_command_line contains "recoveryenabled no")), true, false)
| alter backup_service_stop = if(event_type = PROCESS and (actor_process_command_line contains "sc stop" or actor_process_command_line contains "net stop" or actor_process_command_line contains "taskkill" or actor_process_command_line contains "veeam" or actor_process_command_line contains "sql" or actor_process_command_line contains "exchange"), true, false)
| alter share_enumeration = if(event_type = PROCESS and (actor_process_command_line contains "net view" or actor_process_command_line contains "net share" or actor_process_command_line contains "net use" or actor_process_command_line contains "dir \\"), true, false)

// Encryption and ransom note activity
| alter encryption_activity = if(event_type = PROCESS and (actor_process_image_name ~= ".*(crypt|encrypt|lock).*\.exe$" or actor_process_command_line contains "cipher"), true, false)
| alter ransom_note_creation = if(event_type = FILE and (action_file_name ~= ".*(readme|ransom|decrypt|recover|help).*\.(txt|html|hta)$"), true, false)

// Correlation
| filter
     (play_indicators = true and (shadow_copy_deletion = true or backup_service_stop = true))
  or (ransomhub_indicators = true and (backup_service_stop = true or share_enumeration = true))
  or (dragonforce_indicators = true and (share_enumeration = true or ransom_note_creation = true))
  or ((play_indicators = true and ransomhub_indicators = true) 
  or (ransomhub_indicators = true and dragonforce_indicators = true) 
  or (play_indicators = true and dragonforce_indicators = true))
  or (encryption_activity = true and ransom_note_creation = true)

// Enrichment
| alter raas_affiliation = if(play_indicators = true, "Play Ransomware",
                         if(ransomhub_indicators = true, "RansomHub",
                         if(dragonforce_indicators = true, "DragonForce", "Unattributed RaaS Tradecraft"))),
       detection_category = if(encryption_activity = true and ransom_note_creation = true, "Active Ransomware Deployment",
                          if(play_indicators = true and shadow_copy_deletion = true, "Play Staging Detected",
                          if(ransomhub_indicators = true and backup_service_stop = true, "RansomHub Staging Detected",
                          if(dragonforce_indicators = true and share_enumeration = true, "DragonForce Staging Detected",
                          if(play_indicators = true and ransomhub_indicators = true, "Multi-Affiliate Indicators",
                          "Generic Ransomware Prep"))))),
       risk_score = if(encryption_activity = true and ransom_note_creation = true, 100,
                  if(play_indicators = true and shadow_copy_deletion = true, 95,
                  if(ransomhub_indicators = true and backup_service_stop = true, 95,
                  if(dragonforce_indicators = true and share_enumeration = true, 90,
                  if((play_indicators = true and ransomhub_indicators = true) or (ransomhub_indicators = true and dragonforce_indicators = true), 85,
                  70)))))

// Tool signatures
| alter tool_signature = if(play_indicators = true, "Grixba Scanner",
                       if(ransomhub_indicators = true and actor_process_image_name contains "ccs.exe", "Betruger Backdoor",
                       if(ransomhub_indicators = true and actor_process_image_name contains "psexec.exe", "PsExec Launcher",
                       if(dragonforce_indicators = true and actor_process_image_name contains "netscan", "NetScan Tool",
                       if(dragonforce_indicators = true, "SystemBC Proxy", "Generic Tool")))))

// Output
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line,
         action_file_name, raas_affiliation, tool_signature, detection_category, risk_score, event_type
| sort desc risk_score, desc _time
```

---

## Data Sources

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component        |
|----------------|------------|--------------------|------------------------------|
| Cortex XSIAM   | xdr_data   | File               | File Creation, File Deletion |
| Cortex XSIAM   | xdr_data   | Process            | Process Creation             |

---

## Execution Requirements
- **Required Permissions:** Elevated (to perform service termination and encryption).  
- **Required Artifacts:** File and process telemetry.  

---

## Considerations
- Ransomware deployment usually follows these staging activities.  
- Indicators represent both **specific ransomware family tooling** and **affiliate tradecraft overlap**.  
- This detection emphasizes correlation between **tool + prep action** or **multi-family overlap**.  

---

## False Positives
- Administrative tasks involving backup and shadow copy management may overlap with legitimate system maintenance.  

---

## Recommended Response Actions
1. **Isolate endpoint** immediately to prevent ransomware propagation.  
2. **Kill suspicious processes** and prevent execution of encryption utilities.  
3. **Preserve volatile artifacts** for forensic analysis.  
4. **Investigate network shares** accessed by the compromised host.  
5. **Initiate IR readiness** – prepare for potential ransomware detonation.  

---

## References
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)  
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)  
- [MITRE ATT&CK: T1135 – Network Share Discovery](https://attack.mitre.org/techniques/T1135/)  
- [MITRE ATT&CK: T1489 – Service Stop](https://attack.mitre.org/techniques/T1489/)  
- [MITRE ATT&CK: T1070.001 – Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)  

---

## Version History

| Version | Date       | Impact                  | Notes                                                                  |
|---------|------------|-------------------------|------------------------------------------------------------------------|
| 1.0     | 2025-09-18 | Initial Release         | Created correlation for multi-RaaS affiliate ransomware staging logic. |
