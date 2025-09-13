# WDAC Policy Manipulation - Non-Standard Deployment Methods

## Severity or Impact of the Detected Behavior
- **Risk Score:** 88
- **Severity:** High

## Analytics Metadata

- **ID:** CorrelationRule-Windows-WDAC-PolicyManipulation
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Analytics

This correlation rule detects **non-standard WDAC policy deployments** and associated manipulation behaviors, which may indicate malicious policy distribution. Attackers can attempt to bypass security enforcement by distributing tampered WDAC policies through unusual channels or modifying registry configurations.

Detected stages include:  

- **Stage 1:** Network-based deployment of WDAC policies, including local/remote SMB writes of `SiPolicy.p7b`.  
- **Stage 2:** Suspicious file deployment into user-accessible directories (e.g., Temp, Downloads, AppData, Public).  
- **Stage 3:** Registry modifications to configure WDAC policy paths, including those pointing to suspicious or unauthorized file locations.  
- **Stage 4:** Policy file manipulation via timestomping, suggesting stealth techniques.  

The correlation triggers when **two or more deployment methods** are observed, or **timestomping plus one deployment method**, ensuring high-confidence detection.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                           |
|-------------------------------|-------------|--------------|-----------------------------------------|
| TA0004 - Privilege Escalation | T1484       | T1484.001    | Domain Policy Modification              |
| TA0008 - Lateral Movement     | T1021       | T1021.002    | Remote Services: SMB/Windows Admin Shares |
| TA0008 - Lateral Movement     | T1570       | -            | Lateral Tool Transfer                   |

---

## Query Logic

This query evaluates events across multiple dimensions - network file transfers, directory path anomalies, registry modifications, and file timestomping. By requiring multiple stages to occur together, the query significantly reduces noise while surfacing **probable WDAC policy tampering attempts**.

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
config case_sensitive = false 
| dataset = xdr_data  

// Stage 1: Network-Based Policy Deployment 
| alter network_flag = if( 
        (event_type = NETWORK and  
         action_remote_port = 445 and 
         actor_process_command_line contains "SiPolicy") or 
        (event_type = FILE and 
         action_file_name = "SiPolicy.p7b" and 
         action_file_path contains "localhost"), 
        true, false 
  ), 
  network_timestamp = _time, 
  network_hostname = agent_hostname, 
  deployment_type = if(event_type = NETWORK, "SMB Connection", "Network File Write"), 
  remote_ip = action_remote_ip, 
  network_file_path = action_file_path, 
  network_process = actor_process_image_name, 
  network_cmdline = actor_process_command_line, 
  localhost_smb = if(actor_process_command_line contains "localhost" or 
                     action_file_path contains "localhost", 
                     "Localhost SMB", "Remote SMB") 

// Stage 2: Suspicious Directory Deployment 
| alter directory_flag = if( 
        event_type = FILE and 
        action_file_name = "SiPolicy.p7b" and 
        (action_file_path contains "Temp" or 
         action_file_path contains "Users" or 
         action_file_path contains "Downloads" or 
         action_file_path contains "AppData" or 
         action_file_path contains "Public"), 
        true, false 
  ), 
  directory_timestamp = _time, 
  directory_hostname = agent_hostname, 
  directory_file_path = action_file_path, 
  directory_type = if(action_file_path contains "Temp", "Temp Directory", 
                  if(action_file_path contains "Downloads", "Downloads Directory", 
                  if(action_file_path contains "AppData", "AppData Directory", 
                  if(action_file_path contains "Public", "Public Directory", 
                  "User Directory")))), 
  directory_process = actor_process_image_name, 
  directory_user = actor_effective_username 

// Stage 3: Registry Policy Configuration 
| alter registry_flag = if( 
        event_type = REGISTRY and 
        (action_registry_key_name contains "DeviceGuard" or 
        action_registry_key_name contains "CodeIntegrity") and 
        action_registry_value_name in ("ConfigCIPolicyFilePath", "DeployConfigCIPolicy"), 
        true, false 
  ), 
  registry_timestamp = _time, 
  registry_hostname = agent_hostname, 
  registry_key = action_registry_key_name, 
  registry_value_name = action_registry_value_name, 
  registry_value_data = action_registry_data, 
  registry_process = actor_process_image_name, 
  gpo_deployment = if(action_registry_key_name contains "Policies" and 
                      action_registry_key_name contains "DeviceGuard", 
                      "GPO", "Local"), 
  suspicious_path = if(action_registry_data contains "Temp" or 
                       action_registry_data contains "Users" or 
                       action_registry_data contains "localhost", 
                       "Suspicious", "Normal") 

// Stage 4: Policy File Manipulation (Simplified - Timestomping Only) 
| alter manipulation_flag = if( 
        event_type = FILE and 
        action_file_name = "SiPolicy.p7b" and 
        action_file_create_time != action_file_mod_time, 
        true, false 
  ), 
  manipulation_timestamp = _time, 
  manipulation_hostname = agent_hostname, 
  manipulation_file_path = action_file_path, 
  manipulation_type = if(action_file_create_time != action_file_mod_time, "Timestomping", "Other"), 
  manipulation_process = actor_process_image_name 

// Correlation Logic: Require 2+ deployment methods or 1 method + manipulation 
| filter (network_flag = true and directory_flag = true) or 
        (network_flag = true and registry_flag = true) or 
        (directory_flag = true and registry_flag = true) or 
        (manipulation_flag = true and (network_flag = true or directory_flag = true)) 

// Output Fields 
| fields _time, agent_hostname, deployment_type, directory_type, registry_key, 
         manipulation_type, localhost_smb, gpo_deployment, suspicious_path 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name      | ATT&CK Data Source | ATT&CK Data Component   |
|--------------|-----------------|--------------------|-------------------------|
| Cortex XSIAM | xdr_data        | File               | File Write / Timestamp  |
| Cortex XSIAM | xdr_data        | Registry           | Registry Keys/Values    |
| Cortex XSIAM | xdr_data        | Network            | Network Connection Logs |

---

## Execution Requirements

- **Required Permissions:** Admin rights for registry modifications and SMB policy transfer.  
- **Required Artifacts:** File write logs, registry modification logs, and network telemetry.  

---

## Considerations

- Storing policies in non-standard directories is suspicious and may suggest WDAC tampering.  
- Registry paths pointing to Temp/Downloads or localhost are anomalous and should be investigated.  
- Time manipulation of WDAC policy files suggests concealment tactics.  

---

## False Positives

False positives may occur if:  
- Administrators test WDAC policies in lab environments before enterprise release.  
- Temporary staging of WDAC configurations during deployment cycles.  

---

## Recommended Response Actions

1. Investigate WDAC policy files created in user-accessible locations.  
2. Inspect registry modifications and confirm legitimacy of WDAC paths.  
3. Validate integrity and signing of all WDAC policies.  
4. Block or remove policies deployed via SMB or non-standard directories.  
5. Hunt across network for similar manipulation activity.  

---

## References

- [MITRE ATT&CK: T1484.001 – Domain Policy Modification](https://attack.mitre.org/techniques/T1484/001/)  
- [MITRE ATT&CK: T1021.002 – SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)  
- [MITRE ATT&CK: T1570 – Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                             |
|---------|------------|-------------------|-----------------------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | Detection for WDAC policy deployment via SMB, user dirs, registry, timestomping.  |
