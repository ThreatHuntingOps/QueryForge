# Detection of Remote WDAC Policy Deployment via SMB

## Severity or Impact of the Detected Behavior
- **Risk Score:** 88
- **Severity:** High

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-WDAC-NetworkDeployment
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt identifies **network-based deployment of WDAC policies via SMB**, including remote shares and localhost bypass techniques. Advanced malware families, such as **DreamDemon**, have leveraged SMB connections to plant malicious WDAC policies for persistence and security evasion.  

Detected behaviors include:

- **SMB network connections** involving `SiPolicy.p7b`.  
- **Policy transfers via Admin Shares** (`ADMIN$`, `C$`).  
- **Localhost-based SMB bypasses**, where WDAC policies are deployed via `\localhost\`.  
- **Direct file writes of `SiPolicy.p7b`**, excluding system processes.  

Together, these behaviors indicate attempts to **remotely deploy or stage malicious WDAC policies** across systems.

---

## ATT&CK Mapping

| Tactic               | Technique   | Subtechnique | Technique Name                          |
|----------------------|-------------|--------------|----------------------------------------|
| TA0008 - Lateral Movement | T1021   | T1021.002    | Remote Services: SMB/Windows Admin Shares |
| TA0008 - Lateral Movement | T1570   | -            | Lateral Tool Transfer                   |

---

## Hunt Query Logic

The query ties together **SMB activity** (port 445) with file operations involving `SiPolicy.p7b`. It evaluates whether deployments used **Admin Shares, localhost references, or remote SMB sessions** to distinguish between tactics.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Cortex XSIAM  

```xql
// Title: Network-Based WDAC Policy Deployment Detection 
// Description: Detects remote deployment of WDAC policies via SMB shares 
// MITRE ATT&CK TTP ID: T1021.002, T1570

config case_sensitive = false  

| dataset = xdr_data  

| filter event_type = ENUM.NETWORK  or event_type = ENUM.FILE 

| filter (  
    (event_type = ENUM.NETWORK and   
     action_remote_port = 445 and  
     actor_process_command_line contains "SiPolicy") or  
    (event_type = ENUM.FILE and  
     action_file_name = "SiPolicy.p7b" and  
     actor_process_image_name != "System")  
)  

| alter  
    smb_connection = if(event_type = ENUM.NETWORK and action_remote_port = 445, "SMB", "Other"),  
    admin_share = if(  
        actor_process_command_line contains "ADMIN$" or  
        actor_process_command_line contains "C$",  
        "Admin Share", "Regular Share"  
    ),  
    localhost_reference = if(  
        actor_process_command_line contains "\\localhost\\" or  
        action_file_path contains "\\localhost\\",  
        "Localhost SMB", "Remote SMB"  
    ) 

| alter 
    policy_deployment_method = if(  
        localhost_reference = "Localhost SMB", "Local SMB Bypass",  
        if(admin_share = "Admin Share", "Remote Admin Share",  
        if(smb_connection = "SMB", "Network SMB",  
        "Direct File Write")) 
    )  

| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line,  
         action_remote_ip, action_remote_port, action_file_path, smb_connection,  
         admin_share, localhost_reference, policy_deployment_method, actor_effective_username  

| sort desc _time  
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component    |
|--------------|------------------|---------------------|--------------------------|
| Cortex XSIAM |    xdr_data      | Network             | Network Connection Logs  |
| Cortex XSIAM |    xdr_data      | File                | File Creation/Modification |

---

## Execution Requirements

- **Required Permissions:** SMB access with write privileges.  
- **Required Artifacts:** Network telemetry and file operations logs involving WDAC policy files.  

---

## Considerations

- Localhost SMB usage can indicate **attempted bypasses of WDAC enforcement**.  
- Remote Admin Shares may be a sign of **domain-wide malicious WDAC policy distribution**.  
- Detection should be correlated with **active directory and privilege escalation telemetry**.  

---

## False Positives

False positives may occur if:  
- **Legitimate WDAC deployments** are pushed through SCCM or similar infrastructure.  
- **Administrators** transfer policies during maintenance cycles.  
- Automated backup or synchronization systems copy WDAC policies via SMB.  

---

## Tuning Recommendations

- Whitelist **known management infrastructure IPs and accounts**.  
- Implement **time-based correlations** with patch cycles or administrative change windows.  
- Add **network-to-file correlation** to reduce noise from routine system activity.  

---

## Recommended Response Actions

1. Verify the legitimacy of WDAC file transfers via SMB.  
2. Inspect processes responsible for executing SMB file transfers.  
3. Review affected endpoints for **malicious WDAC enforcement changes**.  
4. Isolate or block suspect SMB traffic involving WDAC policies.  
5. Restore known-good WDAC baselines across impacted systems.  

---

## References

- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)  
- [MITRE ATT&CK: T1570 – Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)  

---

## Version History

| Version | Date       | Impact            | Notes                                                                        |
|---------|------------|-------------------|------------------------------------------------------------------------------|
| 1.0     | 2025-09-13 | Initial Detection | Detection of remote WDAC policy deployment via Admin/SMB shares and localhost bypass methods. |
