# Detection of SMB Lateral Movement with File Drops to Network Shares

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (Yurei-specific filenames), 85 (Generic executable drops), 70 (SMB network activity)
- **Severity:** HIGH to MEDIUM (based on detection phase)

## Analytics Metadata

- **ID:** HuntQuery-Windows-SMB-Lateral-File-Drop-T1021
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Analytics

This rule detects executable files being written to network shares, particularly admin shares (C$, ADMIN$) or common file shares. Yurei drops `System32_Backup.exe` to network shares as part of its propagation mechanism. This query identifies potential lateral movement via file staging to SMB shares, which often precedes remote execution. Detected behaviors include:

- **Phase 1:** Executable file writes to UNC paths (network shares)
- **Phase 2:** SMB network connections (ports 445, 139)
- **Suspicious Filenames:** Yurei-specific (`System32_Backup.exe`, `WindowsUpdate.exe`) or masquerading as system processes (`svchost.exe`, `csrss.exe`, `lsass.exe`, `smss.exe`)
- **Random Filenames:** 8-12 character alphanumeric executable names (common obfuscation pattern)

These techniques are associated with lateral tool transfer and remote services abuse for ransomware propagation.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0008 - Lateral Movement    | T1021       | .002         | Remote Services: SMB/Windows Admin Shares     |
| TA0008 - Lateral Movement    | T1570       | -            | Lateral Tool Transfer                         |

---

## Query Logic

This query identifies SMB-based lateral movement through multi-phase detection:

### Phase 1: File Drops to Network Shares
- Event type: FILE (WRITE or CREATE_NEW)
- File path: UNC path pattern (`\\server\share\...`)
- File extensions: `.exe`, `.dll`, `.bat`, `.ps1`, `.vbs`, `.hta`

### Phase 2: SMB Network Connections
- Event type: NETWORK
- Ports: 445 (SMB), 139 (NetBIOS)
- Remote IP present (indicates outbound SMB connection)

### Suspicious Filename Detection
- **Yurei-specific:** `System32_Backup.exe`, `WindowsUpdate.exe`
- **Masquerading:** `svchost.exe`, `csrss.exe`, `lsass.exe`, `smss.exe` (legitimate system processes used as disguise)
- **Random naming:** 8-12 character alphanumeric `.exe` files (e.g., `a3f8d9e2.exe`)

### Risk Scoring
- **95 (HIGH):** File drop with Yurei-specific filenames (`System32_Backup.exe`, `WindowsUpdate.exe`)
- **85 (HIGH):** Generic executable drop to network share
- **70 (MEDIUM):** SMB network activity without file drop

### Exclusions
- Known service accounts (backup, deployment services)
- Authorized file servers and backup systems
- Known legitimate deployment executables

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Suspicious File Drops to SMB Network Shares (Lateral Movement)
// Description: Detects executable files being written to network shares. Yurei drops System32_Backup.exe to network shares as part of its propagation mechanism.
// MITRE ATT&CK TTP ID: T1021.002, T1570

config case_sensitive = false
| dataset = xdr_data
| filter event_type in (ENUM.FILE, ENUM.NETWORK)

// Phase 1: file drop to UNC network share
| alter file_to_network_share = if(
          event_type = ENUM.FILE
          and event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_CREATE_NEW)
          and action_file_path ~= "^\\[^\\]+\\.*"       // UNC path: \\server\...
          and action_file_extension in (".exe", ".dll", ".bat", ".ps1", ".vbs", ".hta"),
          true, false
      ),
// Phase 2: SMB network connection (ports 445 or 139)
      smb_network_connection = if(
          event_type = ENUM.NETWORK
          and (action_remote_port = 445 or action_remote_port = 139
               or dst_action_external_port = 445 or dst_action_external_port = 139)
          and action_remote_ip != null,
          true, false
      )

// Keep rows that are either network-share file writes or SMB connections
| filter file_to_network_share = true or smb_network_connection = true

// Exclusions: service accounts, known hosts, known files
| filter not (
        actor_effective_username in ("DOMAIN\BackupSVC", "DOMAIN\DeploymentSVC")
        or agent_hostname in ("FILE-SERVER-01", "BACKUP-01")
        or action_file_name in ("backup.exe", "deploy.exe")
    )

// Suspicious filenames (explicit or random 8–12 chars)
| filter action_file_name in ("System32_Backup.exe", "WindowsUpdate.exe", "svchost.exe", "csrss.exe", "lsass.exe", "smss.exe")
      or action_file_name ~= "^[a-z0-9]{8,12}\.exe$"

// Enrichment (split to avoid same-stage references)
| alter detection_category = if(file_to_network_share = true,
                                "Lateral Movement - File Drop to Network Share",
                                "SMB Network Activity")
| alter risk_score = if(
          file_to_network_share = true and action_file_name in ("System32_Backup.exe", "WindowsUpdate.exe"),
          95,
          if(file_to_network_share = true, 85, 70)
      )
| alter severity = if(risk_score >= 90, "HIGH", "MEDIUM")

| fields _time,
         agent_hostname,
         actor_process_image_name,
         actor_process_command_line,
         action_file_path,
         action_file_name,
         action_remote_ip,
         action_remote_port,
         actor_effective_username,
         detection_category,
         risk_score,
         severity
         
| sort desc risk_score
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | File                | File Creation          |
| Cortex       | xdr_data         | Network Traffic     | Network Connection     |

---

## Execution Requirements

- **Required Permissions:** Write access to network shares (often requires domain credentials or compromised accounts)
- **Required Artifacts:** 
  - File creation/write events with UNC path information
  - Network connection logs (SMB ports 445, 139)
  - Process creation logs with command-line arguments
  - User authentication logs for share access

---

## Considerations

- **UNC Path Analysis:** Validate the target share (C$, ADMIN$, IPC$, or custom shares) and assess legitimacy.
- **Temporal Correlation:** Look for file drops followed by remote execution (CIM/WMI, PsExec) within short time windows.
- **User Context:** Investigate if the user account has legitimate reasons for writing executables to network shares.
- **Filename Masquerading:** Files named after system processes (`svchost.exe`, `lsass.exe`) in non-system locations are highly suspicious.
- **Random Naming Patterns:** Short alphanumeric filenames often indicate automated malware generation.
- **Network Topology:** Validate if the source and destination hosts have legitimate business relationships.
- **Share Enumeration:** Correlate with share enumeration activity (net view, net share commands).

---

## False Positives

False positives may occur if:

- IT administrators deploy software or scripts to network shares for distribution.
- Configuration management tools (SCCM, Ansible, Puppet) stage executables on shares.
- Backup software writes executables to network shares as part of disaster recovery.
- Legitimate deployment pipelines copy binaries to file shares.
- Antivirus or security tools distribute updates via network shares.

**Mitigation:** 
- Maintain an accurate inventory of authorized deployment tools and service accounts.
- Implement exclusions for known file servers, backup systems, and deployment infrastructure.
- Correlate with change management records and maintenance windows.
- Use filename and path analysis to differentiate legitimate deployments from suspicious activity.

---

## Recommended Response Actions

1. **Immediate Investigation:** Determine if the file drop is authorized or part of scheduled deployment.
2. **Isolate Source Host:** If malicious activity is suspected, isolate the host initiating the file drop.
3. **Analyze Dropped File:** Retrieve the dropped executable for malware analysis (hash, sandbox, reverse engineering).
4. **Identify Target Shares:** Enumerate all network shares that received suspicious file drops.
5. **Correlate with Remote Execution:** Search for subsequent remote execution attempts (CIM/WMI, PsExec, service creation).
6. **Correlate with Ransomware Indicators:** Search for additional Yurei ransomware artifacts:
   - VSS/backup deletion commands
   - Event log deletion activity
   - CIM/WMI lateral movement
   - Files with `.Yurei` extension
   - `_README_Yurei.txt` ransom notes
7. **Check for Lateral Spread:** Investigate if multiple shares or hosts received similar file drops.
8. **User Account Analysis:** Review the user account for signs of compromise (credential dumping, pass-the-hash).
9. **Network Share Hardening:** Review and restrict write permissions on network shares, especially admin shares.
10. **Credential Rotation:** Rotate credentials for affected accounts and disable compromised accounts.
11. **Preserve Forensic Evidence:** Collect network logs, file metadata, and process execution records.
12. **Threat Hunt:** Conduct a broader hunt across the environment for similar SMB lateral movement patterns.
13. **Engage Incident Response:** Escalate to IR team for full investigation and containment.

---

## Enhanced Detection: Share Enumeration Correlation

For higher-fidelity detection, combine this query with share enumeration monitoring:

```xql
// Supplementary Query: Detect network share enumeration
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
        and actor_process_image_name in ("cmd.exe", "powershell.exe")
        and (actor_process_command_line contains "net view"
             or actor_process_command_line contains "net share"
             or actor_process_command_line contains "Get-SmbShare")
| fields _time, agent_hostname, actor_process_image_name, actor_process_command_line, actor_effective_username
| sort desc _time
```

---

## Enhanced Detection: Admin Share Access

For higher-fidelity detection, monitor for admin share (C$, ADMIN$) access:

```xql
// Supplementary Query: Detect admin share access
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.FILE
        and action_file_path ~= "^\\[^\\]+\\[CAD]\$.*"  // C$, ADMIN$, D$, etc.
| fields _time, agent_hostname, actor_process_image_name, action_file_path, action_file_name, actor_effective_username
| sort desc _time
```

---

## References

- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1570 – Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)
- [Microsoft: SMB Security Best Practices](https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security)
- [CISA: SMBv1 Exploitation and Ransomware](https://www.cisa.gov/uscert/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-14 | Initial Detection | Created hunt query to detect SMB lateral movement with file drops for Yurei ransomware     |
