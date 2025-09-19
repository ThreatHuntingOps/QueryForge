# Lateral Movement via RDP and SMB

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (Multi-vector lateral movement detected)  
- **Severity:** Critical  

## Analytics Metadata
- **ID:** CorrelationRule-Windows-RDP-SMB-LateralMovement  
- **Operating Systems:** WindowsEndpoint, WindowsServer  
- **False Positive Rate:** Medium (correlated across multiple behaviors)  

---

## Analytics

This correlation rule detects **lateral movement** performed via:  

- **Remote Desktop Protocol (RDP):** suspicious logons (types 3 and 10) and tunneled RDP sessions using SystemBC proxy.  
- **Windows Management Instrumentation (WMI):** remote command execution using Impacket's wmiexec, observed as **cmd.exe spawned as a child of wmiprvse.exe**.  
- Supporting detections of **RDP-related processes** (`mstsc.exe`, `rdpclip.exe`, etc.) and **direct network connections** to port 3389.  

This analytic reduces false positives by **requiring multiple correlated indicators**—e.g., **RDP logon + WMI execution**, or **RDP logon + network events**.  

---

## ATT&CK Mapping

| Tactic           | Technique | Subtechnique | Technique Name                                  |
|------------------|-----------|--------------|------------------------------------------------|
| Lateral Movement | T1021     | T1021.001    | Remote Services: Remote Desktop Protocol       |
| Execution        | T1047     | -            | Windows Management Instrumentation             |
| Command & Control| T1090     | T1090.001    | Proxy: Internal Proxy                          |
| Valid Accounts   | T1078     | T1078.002    | Valid Accounts: Domain Accounts                |

---

## Query Logic

This analytic correlates RDP logon events, RDP processes, WMI-based execution, and suspicious network connections.  
Detections fire when **at least two activity categories overlap** (e.g., RDP + WMI, WMI + RDP traffic).  

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// Hunt for lateral movement via RDP tunneling and WMI-based remote execution
// Targets T1021.001 - RDP and T1047 - WMI

config case_sensitive = false  
| dataset = xdr_data  
| filter event_type in (ENUM.LOGIN_EVENT, NETWORK, PROCESS)  

// Phase 1: Detect suspicious RDP logon activity 
| alter suspicious_rdp_logon = if( 
        event_type = ENUM.LOGIN_EVENT and 
        (dst_action_external_port = 3389 or action_remote_ip != null), 
        true, false 
  ) 

// Phase 2: Detect WMI-based remote execution 
| alter wmi_remote_execution = if( 
        event_type = PROCESS and 
        actor_process_image_name contains "cmd.exe" and 
        causality_actor_process_image_name contains "wmiprvse.exe" and 
        actor_process_command_line != null, 
        true, false 
  ) 

// Phase 3: Detect RDP-related process activity 
| alter rdp_process_activity = if( 
        event_type = PROCESS and 
        (actor_process_image_name contains "mstsc.exe" or 
         actor_process_image_name contains "rdpclip.exe" or 
         actor_process_image_name contains "tstheme.exe" or 
         (causality_actor_process_image_name contains "winlogon.exe" and actor_process_image_name contains "userinit.exe")), 
        true, false 
  ) 

// Phase 4: Detect network connections to RDP ports 
| alter rdp_network_connections = if( 
        event_type = NETWORK and 
        (dst_action_external_port = 3389 or action_external_port = 3389) and 
        action_remote_ip != null, 
        true, false 
  ) 

// Correlation Filter
| filter (suspicious_rdp_logon = true and (wmi_remote_execution = true or rdp_process_activity = true)) 
      or (wmi_remote_execution = true and rdp_network_connections = true) 
      or (suspicious_rdp_logon = true and rdp_network_connections = true) 

// Enrichment
| alter detection_category = if(wmi_remote_execution = true and suspicious_rdp_logon = true, "Multi-Vector Lateral Movement", 
                           if(wmi_remote_execution = true, "WMI Remote Execution", 
                           if(suspicious_rdp_logon = true, "Suspicious RDP Activity", 
                           if(rdp_network_connections = true, "RDP Network Activity", 
                           if(rdp_process_activity = true, "RDP Process Activity", "Generic Lateral Movement"))))), 
       risk_score = if(wmi_remote_execution = true and suspicious_rdp_logon = true, 95, 
                  if(wmi_remote_execution = true, 90, 
                  if(suspicious_rdp_logon = true, 85, 
                  if(rdp_network_connections = true, 80, 
                  if(rdp_process_activity = true, 70, 60))))) 

// Output 
| fields agent_hostname, 
         actor_process_image_name, 
         actor_process_command_line, 
         causality_actor_process_image_name, 
         actor_effective_username, 
         dst_action_external_port, 
         dst_action_url, 
         action_remote_ip, 
         detection_category, 
         risk_score, 
         event_type 

| sort desc risk_score  
```

---

## Data Sources

| Log Provider   | Event Name    | ATT&CK Data Source | ATT&CK Data Component      |
|----------------|---------------|--------------------|----------------------------|
| Cortex XSIAM   | xdr_data      | Process            | Process Creation           |
| Cortex XSIAM   | xdr_data      | Network            | Network Connection         |
| Cortex XSIAM   | xdr_data      | Login Events       | Authentication Logon       |

---

## Execution Requirements  
- **Required Permissions:** Valid domain credentials for RDP or WMI.  
- **Required Artifacts:** Process telemetry, login event telemetry, and network session logs.  

---

## Considerations  
- RDP usage from unusual hosts/times should raise concerns when combined with WMI patterns.  
- Attackers frequently tunnel RDP over **SystemBC proxies**, obfuscating origins.  
- `cmd.exe` from `wmiprvse.exe` is a strong signal of **Impacket wmiexec lateral movement**.  

---

## False Positives  
- Possible from legitimate RDP admin sessions.  
- WMI remote admin scripts could mimic this execution chain.  

---

## Recommended Response Actions  
1. **Investigate source IPs** for RDP connections; validate against authorized jump hosts.  
2. **Correlate WMI execution** with user accounts performing administrative functions.  
3. **Alert SOC/IR teams** on abnormal logon chains.  
4. **Enforce Just-in-Time (JIT) access** and restrict RDP at the network boundary.  
5. **Implement credential hygiene monitoring** for compromised domain accounts.  

---

## References  
- [MITRE ATT&CK: T1021.001 – RDP](https://attack.mitre.org/techniques/T1021/001/)  
- [MITRE ATT&CK: T1047 – WMI](https://attack.mitre.org/techniques/T1047/)  
- [MITRE ATT&CK: T1090.001 – Internal Proxy](https://attack.mitre.org/techniques/T1090/001/)  
- [MITRE ATT&CK: T1078.002 – Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)  

---

## Version History  

| Version | Date       | Impact                  | Notes                                                                       |
|---------|------------|-------------------------|-----------------------------------------------------------------------------|
| 1.0     | 2025-09-18 | Initial Detection       | Added correlation for RDP logon + WMI remote execution + network tunneling. |
