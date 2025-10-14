# Detection of Lateral Movement via CIM Sessions and Remote Execution

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (Multi-Phase), 90 (WMI Remote Exec), 85 (CIM Session), 70 (WMI Network)
- **Severity:** HIGH to MEDIUM (based on detection phase)

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-CIM-WMI-Lateral-Movement-T1021
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics

This hunt detects PowerShell commands establishing CIM sessions to remote hosts and invoking methods for remote execution. Yurei uses this technique to spread across networks by creating PSCredential objects, establishing CIM sessions, copying payloads, and remotely executing them. This query identifies the remote execution phase, which is a critical lateral movement indicator. Detected behaviors include:

- **Phase 1:** PowerShell CIM session creation (`New-CimSession`, `Get-CimSession`, `PSCredential`, `Invoke-CimMethod`)
- **Phase 2:** WMI remote execution (`wmiprvse.exe` spawning unusual child processes like `cmd.exe`, `powershell.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`)
- **Phase 3:** Network connections to WMI/RPC ports (135, 445)

These techniques are associated with credential-based lateral movement and remote code execution across Windows networks.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021       | .002         | Remote Services: SMB/Windows Admin Shares     |
| TA0002 - Execution           | T1047       | -            | Windows Management Instrumentation            |
| TA0002 - Execution           | T1059       | .001         | Command and Scripting Interpreter: PowerShell |

---

## Hunt Query Logic

This query identifies lateral movement activity through a multi-phase detection approach:

### Phase 1: CIM Session Creation
- Process names matching `powershell.exe` or `powershell`
- Command lines containing:
  - `New-CimSession` (establishes remote CIM connection)
  - `Get-CimSession` (retrieves existing CIM sessions)
  - `PSCredential` (credential object creation for authentication)
  - `Invoke-CimMethod` (executes methods on remote systems)

### Phase 2: WMI Remote Execution
- Parent process `wmiprvse.exe` (WMI Provider Host)
- Child processes: `cmd.exe`, `powershell.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`
- Indicates remote command execution via WMI

### Phase 3: WMI Network Activity
- Network connections to ports 135 (RPC/WMI) or 445 (SMB)
- Indicates remote management protocol usage

### Correlation Logic
- **Multi-Phase Lateral Movement (Risk: 95):** CIM session creation + WMI remote execution
- **WMI Remote Execution (Risk: 90):** wmiprvse.exe spawning suspicious children
- **CIM Session Creation (Risk: 85):** PowerShell CIM cmdlets detected
- **WMI Network Activity (Risk: 70):** Network connections to WMI/RPC ports

### Exclusions
- Known legitimate remote management service accounts (SCCM, monitoring tools)
- Authorized jump servers and management infrastructure

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM

```xql
// Title: CIM/WMI-Based Remote Execution for Lateral Movement
// Description: Detects PowerShell commands establishing CIM sessions to remote hosts and invoking methods for remote execution. Yurei uses this technique to spread across networks.
// MITRE ATT&CK TTP ID: T1021.002, T1047, T1059.001

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type in (ENUM.PROCESS, ENUM.NETWORK) 

// Phase 1: Detect PowerShell CIM session creation 
| alter cim_session_creation = if( 
        event_type = ENUM.PROCESS and 
        actor_process_image_name contains "powershell" and 
        (actor_process_command_line contains "New-CimSession" 
         or actor_process_command_line contains "Get-CimSession" 
         or actor_process_command_line contains "PSCredential" 
         or actor_process_command_line contains "Invoke-CimMethod"), 
        true, false 
  ) 

// Phase 2: Detect WMI remote execution (wmiprvse.exe spawning unusual children) 
| alter wmi_remote_exec = if( 
        event_type = ENUM.PROCESS and 
        causality_actor_process_image_name contains "wmiprvse.exe" and 
        actor_process_image_name in ("cmd.exe", "powershell.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"), 
        true, false 
  ) 

// Phase 3: Detect network connections to WMI/RPC ports 
| alter wmi_network_activity = if( 
        event_type = ENUM.NETWORK and 
        (action_remote_port in (135, 445) or dst_action_external_port in (135, 445)) and 
        action_remote_ip != null, 
        true, false 
  ) 

// Correlation Filter: Any CIM/WMI activity 
| filter cim_session_creation = true or wmi_remote_exec = true or wmi_network_activity = true 

// Exclude known legitimate remote management tools 
| filter not ( 
        actor_effective_username in ("DOMAIN\SCCM_SVC", "DOMAIN\MonitoringSVC") 
        or agent_hostname in ("ADMIN-JUMP-01", "SCCM-SERVER-01") 
    ) 

// Enrichment - Stage 1: Calculate detection category and risk score
| alter detection_category = if(cim_session_creation = true and wmi_remote_exec = true, "Multi-Phase Lateral Movement", 
                           if(cim_session_creation = true, "CIM Session Creation", 
                           if(wmi_remote_exec = true, "WMI Remote Execution", 
                           "WMI Network Activity"))), 
        risk_score = if(cim_session_creation = true and wmi_remote_exec = true, 95, 
                   if(wmi_remote_exec = true, 90, 
                   if(cim_session_creation = true, 85, 70)))

// Enrichment - Stage 2: Calculate severity based on risk_score
| alter severity = if(risk_score >= 90, "HIGH", "MEDIUM") 

| fields _time, 
         agent_hostname, 
         actor_process_image_name, 
         actor_process_command_line, 
         causality_actor_process_image_name, 
         actor_effective_username, 
         action_remote_ip, 
         action_remote_port, 
         detection_category, 
         risk_score, 
         severity 

| sort desc risk_score
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Process             | Process Creation       |
| Cortex       | xdr_data         | Command             | Command Execution      |
| Cortex       | xdr_data         | Network Traffic     | Network Connection     |

---

## Execution Requirements

- **Required Permissions:** Administrator or elevated privileges for remote WMI/CIM execution.
- **Required Artifacts:** 
  - Process creation logs with command-line arguments
  - PowerShell execution logs
  - Network connection logs (ports 135, 445)
  - WMI activity logs
  - Parent-child process relationships

---

## Considerations

- **Temporal Correlation:** Look for CIM session creation followed by WMI remote execution within short time windows (seconds to minutes).
- **Lateral Movement Patterns:** Investigate if multiple hosts are targeted from a single source in rapid succession.
- **Credential Usage:** Review the user account executing CIM sessions for legitimacy and authorization.
- **Parent Process Analysis:** Investigate what spawned the PowerShell process creating CIM sessions.
- **Network Topology:** Validate if the source and destination hosts have legitimate business reasons for remote management connections.
- **Payload Analysis:** Correlate with file creation events on remote hosts to identify what was executed.
- **Service Account Validation:** Ensure exclusions for legitimate service accounts are accurate and up-to-date.

---

## False Positives

False positives may occur if:

- IT administrators use PowerShell remoting for legitimate system management.
- Configuration management tools (SCCM, Ansible, Puppet) use WMI/CIM for remote operations.
- Monitoring and security tools perform remote health checks or data collection via WMI.
- Automated patch management systems use remote execution for updates.
- Help desk tools use remote assistance features leveraging WMI.

**Mitigation:** 
- Maintain an accurate inventory of authorized remote management tools and service accounts.
- Implement exclusions for known jump servers and management infrastructure.
- Correlate with change management records and maintenance windows.
- Use behavioral baselines to identify anomalous remote execution patterns.

---

## Recommended Response Actions

1. **Immediate Triage:** Determine if the activity is authorized or part of scheduled maintenance.
2. **Isolate Source Host:** If malicious activity is suspected, isolate the source host initiating CIM sessions.
3. **Identify Lateral Spread:** Enumerate all remote hosts targeted by the suspicious CIM sessions.
4. **Analyze Command Context:** Review the full PowerShell command line and parent process chain.
5. **Correlate with Ransomware Indicators:** Search for additional Yurei ransomware artifacts:
   - VSS/backup deletion commands
   - Event log deletion activity
   - Files with `.Yurei` extension
   - `_README_Yurei.txt` ransom notes
   - Payload staging in `%LOCALAPPDATA%\Temp`
   - Suspicious executables (`WindowsUpdate.exe`, `svchost.exe`, `System32_Backup.exe`)
6. **Check Remote Hosts:** Investigate destination hosts for:
   - New file creations (especially in Temp directories)
   - Suspicious process executions
   - Service creations
   - Encryption activity
7. **Network Analysis:** Review network logs for additional lateral movement attempts (SMB writes, PsExec, net use).
8. **Credential Investigation:** Determine if credentials were compromised and rotate affected accounts.
9. **Preserve Forensic Evidence:** Collect volatile artifacts (memory dumps, process listings) from both source and destination hosts.
10. **Threat Hunt:** Conduct a broader hunt across the environment for similar lateral movement patterns.
11. **Engage Incident Response:** Escalate to IR team for full investigation and containment.

---

## References

- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1047 – Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)
- [Microsoft: CIM Cmdlets](https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/)
- [Microsoft: Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)
- [Microsoft: PSCredential Class](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-10 | Initial Detection | Created hunt query to detect CIM/WMI-based lateral movement for Yurei ransomware          |
