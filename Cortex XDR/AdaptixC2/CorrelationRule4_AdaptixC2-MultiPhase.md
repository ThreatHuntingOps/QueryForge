# AdaptixC2 Multi‑Phase Attack Correlation Detection

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (multi-phase kill chain overlap)  
- **Severity:** Critical  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-AdaptixC2-MultiPhase  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Very Low (requires ≥3 distinct phases of malicious behavior)  

---

## Analytics

This correlation rule detects **multi-phase kill chain progression by AdaptixC2**.  

Detected behaviors include:  

- **Phase 1 (Execution):** PowerShell loader using `FromBase64String` to decode payloads.  
- **Phase 2 (Reconnaissance):** Native enumeration commands (`ipconfig.exe`, `whoami.exe`, `nltest.exe`) under PowerShell parent.  
- **Phase 3 (Persistence):** Registry Run key modification (`HKEY_CURRENT_USER\...\Run`).  
- **Phase 4 (C2 Communications):** Beaconing over suspicious TCP ports (443, 4443).  
- **Phase 5 (Hijack Execution Flow):** Dropping malicious DLLs in `Templates\*.dll` path.  

The correlation requires **at least 3 phases to overlap on the same host**, yielding high-confidence detection of a coordinated intrusion aligned to the AdaptixC2 kill chain.

---

## ATT&CK Mapping

| Tactic                      | Technique | Subtechnique | Technique Name                                |
|-----------------------------|-----------|--------------|-----------------------------------------------|
| Execution                   | T1059     | T1059.001    | Command and Scripting Interpreter: PowerShell |
| Discovery                   | T1082     | -            | System Information Discovery                  |
| Discovery                   | T1016     | -            | System Network Configuration Discovery        |
| Discovery                   | T1033     | -            | System Owner/User Discovery                   |
| Persistence                 | T1547     | T1547.001    | Boot or Logon Autostart Execution: Registry Run Keys |
| Command and Control         | T1071     | T1071.001    | Application Layer Protocol: Web Protocols     |
| Persistence / Defense Evasion / Priv. Escalation | T1574 | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking |

---

## Query Logic

This analytic correlates **≥3 overlapping phases of AdaptixC2 attack chains**.  
It prioritizes detection where execution, discovery, persistence, beaconing, and hijack activity cluster on the same host.

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// Hunt for AdaptixC2 multi‑phase kill chain
config case_sensitive = false  
| dataset = xdr_data  
| filter event_type in (PROCESS, NETWORK, FILE)  

// Phase 1: PowerShell with Base64 decoding 
| alter phase1_powershell = if( 
        event_type = PROCESS and  
        actor_process_image_name ~= "powershell.exe" and  
        actor_process_command_line contains "FromBase64String", 
        true, false 
  ) 

// Phase 2: Reconnaissance commands spawned by PowerShell 
| alter phase2_recon = if( 
        event_type = PROCESS and  
        causality_actor_process_image_name ~= "powershell.exe" and  
        actor_process_image_name in ("ipconfig.exe","whoami.exe","nltest.exe"), 
        true, false 
  ) 

// Phase 3: Persistence via Registry Run keys 
| alter phase3_persistence = if( 
        event_type = PROCESS and  
        actor_process_command_line contains "HKEY_CURRENT_USER" and  
        actor_process_command_line contains "Run", 
        true, false 
  ) 

// Phase 4: C2 communications over suspicious ports 
| alter phase4_c2 = if( 
        event_type = NETWORK and  
        dst_action_external_port in (443,4443) and  
        action_network_protocol = ENUM.TCP, 
        true, false 
  ) 

// Phase 5: DLL hijack in Templates path 
| alter phase5_dll = if( 
        event_type = FILE and  
        action_file_path contains "Templates" and  
        action_file_name contains ".dll", 
        true, false 
  ) 

// Correlation filter: require at least 3 phases overlap 
| filter 
    (phase1_powershell = true and phase2_recon = true and phase3_persistence = true) 
    or (phase1_powershell = true and phase4_c2 = true and phase5_dll = true) 
    or (phase2_recon = true and phase3_persistence = true and phase4_c2 = true) 
    or (phase1_powershell = true and phase3_persistence = true and phase5_dll = true) 

// Detection enrichment 
| alter detection_category = "AdaptixC2 Multi-Phase Attack", 
        risk_score = 95, 
        attack_technique = "T1059.001,T1547.001,T1071.001,T1574.001" 

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

| Log Provider   | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|----------------|------------|--------------------|-----------------------|
| Cortex XSIAM   | xdr_data   | Process            | Process Creation      |
| Cortex XSIAM   | xdr_data   | File               | File Creation         |
| Cortex XSIAM   | xdr_data   | Network            | Network Connection    |

---

## Execution Requirements  
- **Required Permissions:** User-level sufficient, though persistence/hijack phases escalate.  
- **Required Artifacts:** Process, File, and Network telemetry.  

---

## Considerations  
- Requires ≥3 distinct phases for alert, ensuring high fidelity.  
- May miss low-and-slow intrusions spread across long dwell times unless tuned.  

---

## False Positives  
- Extremely rare, as benign workloads seldom overlap **PowerShell loader + recon + persistence + C2** simultaneously.  

---

## Recommended Response Actions  
1. **Immediately isolate host** showing 3+ correlated AdaptixC2 phases.  
2. **Collect triage data** (memory dump, PowerShell logs, registry hives, network captures).  
3. **Scan for malicious DLL artifacts** in Templates directory.  
4. **Correlate with threat intel** to identify infrastructure/IP reuse.  
5. **Initiate incident response playbook** for confirmed AdaptixC2 compromise.  

---

## References  
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)  
- [MITRE ATT&CK: T1082 – System Information Discovery](https://attack.mitre.org/techniques/T1082/)  
- [MITRE ATT&CK: T1016 – Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)  
- [MITRE ATT&CK: T1033 – User Discovery](https://attack.mitre.org/techniques/T1033/)  
- [MITRE ATT&CK: T1547.001 – Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)  
- [MITRE ATT&CK: T1071.001 – Web Protocols](https://attack.mitre.org/techniques/T1071/001/)  
- [MITRE ATT&CK: T1574.001 – DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)  

---

## Version History  

| Version | Date       | Impact                         | Notes                                                            |
|---------|------------|--------------------------------|------------------------------------------------------------------|
| 1.0     | 2025-09-26 | Initial Detection Contribution | Added correlation for AdaptixC2 multi-phase attack progression   |
