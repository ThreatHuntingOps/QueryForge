# Credential Dumping Followed by Lateral Movement (Correlation Rule)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100 (Credential dumping + ≥2 remote hosts + remote exec/file drop within 15 min)
- **Severity:** Critical

## Analytics Metadata
- **ID:** CorrelationRule-Windows-CredDump-LateralMovement
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low to Medium (tunable with admin allowlists)
- **Lookback/Temporal Window:** 15 minutes (same source host)

---

## Analytics

This correlation rule detects the sequence of credential theft followed by lateral movement and remote execution.

Phases on the same source host within 15 minutes:
- **Phase 1 - Credential Access (T1003):** Execution of credential dumping tools or LSASS credential access patterns.
- **Phase 2 - Lateral Movement (T1021.002/T1059.001):** Remote authentication to multiple hosts (e.g., SMB/135/RDP).
- **Phase 3 - Remote Execution/Transfer (T1047/T1059.001/T1570):** PowerShell CIM/WMI remote execution or executable file drops to UNC paths.

Requiring all three phases increases fidelity and ties credential access to immediate lateral actions.

---

## ATT&CK Mapping

| Tactic             | Technique | Subtechnique | Technique Name                                      |
|--------------------|----------:|-------------:|-----------------------------------------------------|
| Credential Access  | T1003     | -            | OS Credential Dumping                               |
| Lateral Movement   | T1021     | .002         | Remote Services: SMB/Windows Admin Shares           |
| Execution          | T1047     | -            | Windows Management Instrumentation                   |
| Execution          | T1059     | .001         | PowerShell                                          |

---

## Correlation Logic

- Scope: Same source host (agent_hostname) and actor_effective_username
- Window: 15 minutes
- Thresholds:
  - Phase 1: ≥1 credential dumping event
  - Phase 2: Remote auth to ≥2 distinct remote hosts
  - Phase 3: ≥1 remote execution event OR ≥1 executable file drop to UNC share

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Palo Alto Cortex XDR and XSIAM

```xql
// Correlation Rule: Credential Theft + Lateral Movement Detected
// Phases: Cred Dump (T1003) → Remote Auth (T1021.002) → Remote Exec/File Drop (T1047/T1059.001/T1570)

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type in (ENUM.PROCESS, ENUM.NETWORK, ENUM.FILE) 

// Phase 1: Credential dumping 
| alter phase1_cred_dump = if( 
        event_type = ENUM.PROCESS and 
        ( 
          actor_process_image_name in ("mimikatz.exe", "procdump.exe", "procdump64.exe") 
          or actor_process_command_line contains "sekurlsa::logonpasswords" 
          or (actor_process_image_name = "reg.exe" and actor_process_command_line contains "save hklm\sam") 
        ), 
        1, 0 
  ) 

// Phase 2: Remote authentication (network connections to SMB/RPC/RDP) 
| alter phase2_remote_auth = if( 
        event_type = ENUM.NETWORK and 
        (action_remote_port in (445, 135, 3389) or dst_action_external_port in (445, 135, 3389)) 
        and action_remote_ip != null, 
        1, 0 
  ) 

// Phase 3a: Remote execution via PowerShell CIM/WMI 
| alter phase3_remote_exec = if( 
        event_type = ENUM.PROCESS and 
        actor_process_image_name contains "powershell" and 
        (actor_process_command_line contains "New-CimSession" 
         or actor_process_command_line contains "Invoke-CimMethod"), 
        1, 0 
  ) 

// Phase 3b: Executable file drops to UNC network shares 
| alter phase3_file_drop = if( 
        event_type = ENUM.FILE and 
        event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_CREATE_NEW) and 
        action_file_path != null and 
        action_file_path ~= "^\\[^\\]+\\.*" and 
        action_file_extension = ".exe", 
        1, 0 
  ) 

// Aggregate by source host and user context 
| comp sum(phase1_cred_dump) as cred_dump_count, 
       count_distinct(action_remote_ip) as unique_remote_hosts, 
       sum(phase3_remote_exec) as remote_exec_count, 
       sum(phase3_file_drop) as file_drop_count 
  by agent_hostname, actor_effective_username 

// Correlation condition 
| filter cred_dump_count > 0 
  and unique_remote_hosts >= 2 
  and (remote_exec_count > 0 or file_drop_count > 0) 

// Enrichment 
| alter alert_severity = "CRITICAL", 
        alert_name = "Credential Theft + Lateral Movement Detected", 
        confidence = "HIGH", 
        recommended_action = "IMMEDIATE RESPONSE: Isolate source host, reset credentials, investigate remote hosts" 

| fields agent_hostname, actor_effective_username, cred_dump_count, unique_remote_hosts, 
         remote_exec_count, file_drop_count, alert_severity, recommended_action 
| sort desc unique_remote_hosts
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component        |
|--------------|------------|--------------------|------------------------------|
| Cortex       | xdr_data   | Process            | Process Creation             |
| Cortex       | xdr_data   | Network            | Network Connection           |
| Cortex       | xdr_data   | File               | File Write / File Creation   |

---

## Execution Requirements
- **Required Permissions:** Local admin often required for dumping credentials; network access for SMB/RPC/RDP; PowerShell remoting permissions for CIM/WMI.
- **Required Artifacts:** Process, network, and file telemetry; command-line parameters; remote IP fields.

---

## Rationale for Fidelity
- **Attack Lifecycle Chaining:** Ties credential access to subsequent lateral actions.
- **Multiple Host Requirement:** ≥2 remote hosts reduces noise from single-host admin tasks.
- **Tight Temporal Window:** 15-minute window correlates related activity bursts.
- **User Context:** Uses actor_effective_username to pinpoint compromised accounts.

---

## Potential Bypasses/Limitations
- **Slow and Low:** Attacks stretched beyond 15 minutes may evade correlation.
- **Fileless Lateral Movement:** If only WMI/CIM is used without file drops, detection still triggers via Phase 3a; if different remoting method is used, may miss.
- **Legitimate Admin Activity:** IT operations may resemble this behavior; tune with allowlists and PAW accounts.

### Mitigation
- Extend window to 30–60 minutes for slower campaigns.
- Allowlists for known admin accounts, jump boxes/PAWs, and maintenance windows.
- Increase unique_remote_hosts threshold (e.g., 3–5) in large enterprises.

---

## Recommended Response Actions
1. Isolate the source host and suspend network access.
2. Reset credentials for the involved user accounts; invalidate tokens.
3. Investigate all remote hosts accessed during the window for execution artifacts.
4. Acquire volatile data (memory, handle lists) and relevant logs from source and targets.
5. Block further remoting from the source via firewall/EDR controls.
6. Hunt for additional credential access tools and LSASS access attempts.
7. Review lateral movement pathways (SMB drops, WMI execution) and close gaps.
8. Engage IR and follow lateral movement containment procedures.

---

## References
- [MITRE ATT&CK: T1003 – OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK: T1021.002 – SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1047 – Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

## Version History

| Version | Date       | Impact                 | Notes                                                      |
|---------|------------|------------------------|------------------------------------------------------------|
| 1.0     | 2025-10-14 | Initial Correlation    | Credential dumping followed by lateral movement detection  |
