# Detection of PowerShell-Based Shadow Copy and Backup Destruction

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** CRITICAL

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-PowerShell-VSS-Backup-Deletion-T1490
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low

---

## Hunt Analytics

This hunt detects PowerShell execution of commands that delete Volume Shadow Copies or Windows backup catalogs. This is a critical pre-encryption step used by Yurei and other ransomware families to prevent recovery. Any legitimate deletion of VSS is rare and typically performed by authorized backup software, making this a high-fidelity indicator of ransomware activity. Detected behaviors include:

- PowerShell invoking `vssadmin` to delete shadow copies
- PowerShell invoking `wbadmin` to delete backup catalogs
- PowerShell using `wmic` to delete shadow copies
- PowerShell invoking `bcdedit` to disable recovery or ignore boot failures

These techniques are associated with ransomware operations designed to inhibit system recovery and maximize impact.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                 |
|------------------------------|-------------|--------------|-----------------------------------------------|
| TA0040 - Impact              | T1490       | -            | Inhibit System Recovery                       |
| TA0002 - Execution           | T1059.001   | -            | Command and Scripting Interpreter: PowerShell |

---

## Hunt Query Logic

This query identifies suspicious PowerShell activity by looking for:

- Process names matching `powershell.exe` or `powershell`
- Command lines containing recovery inhibition commands:
  - `vssadmin` + `delete` + `shadows`
  - `wbadmin` + `delete` + `catalog`
  - `wmic` + `shadowcopy` + `delete`
  - `bcdedit` + `recoveryenabled` + `no`
  - `bcdedit` + `bootstatuspolicy` + `ignoreallfailures`
- Exclusions for known legitimate backup software (Veeam, Backup Exec, Acronis)
- Exclusions for SYSTEM account executions (adjust based on environment)

These patterns are highly indicative of ransomware attempting to prevent recovery before encryption.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)  
**Platform:** Palo Alto Networks Cortex XDR and XSIAM

```xql
// Title: PowerShell Inhibiting System Recovery (VSS/Backup Deletion)
// Description: Detects PowerShell execution of commands that delete Volume Shadow Copies or Windows backup catalogs. This is a critical pre-encryption step used by Yurei and other ransomware families to prevent recovery.
// MITRE ATT&CK TTP ID: T1490, T1059.001

config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS
        and actor_process_image_name contains "powershell"
        and (
            actor_process_command_line contains "vssadmin" and actor_process_command_line contains "delete" and actor_process_command_line contains "shadows"
            or actor_process_command_line contains "wbadmin" and actor_process_command_line contains "delete" and actor_process_command_line contains "catalog"
            or actor_process_command_line contains "wmic" and actor_process_command_line contains "shadowcopy" and actor_process_command_line contains "delete"
            or actor_process_command_line contains "bcdedit" and actor_process_command_line contains "recoveryenabled" and actor_process_command_line contains "no"
            or actor_process_command_line contains "bcdedit" and actor_process_command_line contains "bootstatuspolicy" and actor_process_command_line contains "ignoreallfailures"
        )

// Exclusions for known legitimate backup software
| filter actor_process_image_path not contains "Veeam"
        and actor_process_image_path not contains "Backup Exec"
        and actor_process_image_path not contains "Acronis"
        and actor_effective_username not in ("NT AUTHORITY\SYSTEM", "SYSTEM")  // Adjust based on your environment

// Enrichment
| alter severity = "CRITICAL",
        detection_category = "Ransomware - System Recovery Inhibition",
        risk_score = 100,
        mitre_technique = "T1490, T1059.001"

// Output relevant fields
| fields _time,
         agent_hostname,
         actor_process_image_name,
         actor_process_command_line,
         actor_effective_username,
         causality_actor_process_image_name,
         severity,
         detection_category,
         risk_score

| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name       | ATT&CK Data Source  | ATT&CK Data Component  |
|--------------|------------------|---------------------|------------------------|
| Cortex       | xdr_data         | Process             | Process Creation       |
| Cortex       | xdr_data         | Command             | Command Execution      |

---

## Execution Requirements

- **Required Permissions:** Administrator or elevated privileges to execute VSS/backup deletion commands.
- **Required Artifacts:** Process creation logs with command-line arguments, PowerShell execution logs.

---

## Considerations

- Review the user account executing the command for legitimacy and authorization.
- Correlate with other ransomware indicators such as file encryption, ransom note creation, or lateral movement.
- Investigate the parent process (`causality_actor_process_image_name`) to determine the execution chain.
- Check for additional anti-recovery behaviors such as event log deletion or service termination.
- Validate if the activity aligns with scheduled maintenance or authorized backup operations.

---

## False Positives

False positives may occur if:

- Authorized backup software (Veeam, Backup Exec, Acronis, etc.) performs legitimate VSS management operations.
- IT administrators manually delete shadow copies during system maintenance or troubleshooting.
- Automated scripts or scheduled tasks perform backup cleanup operations.

**Mitigation:** Tune exclusions based on known legitimate backup software paths and authorized administrative accounts.

---

## Recommended Response Actions

1. **Immediate Isolation:** Isolate the affected endpoint from the network to prevent lateral spread.
2. **Investigate Command Context:** Review the full command line, parent process, and user account for signs of compromise.
3. **Correlate with Ransomware Indicators:** Search for additional Yurei ransomware artifacts:
   - Files with `.Yurei` extension
   - `_README_Yurei.txt` ransom notes
   - Payload staging in `%LOCALAPPDATA%\Temp`
   - Suspicious executables (`WindowsUpdate.exe`, `svchost.exe`, `System32_Backup.exe`)
4. **Check for Lateral Movement:** Investigate CIM sessions, PSCredential usage, `net use` commands, and SMB write activity.
5. **Restore from Backups:** If VSS has been deleted, initiate restore procedures from immutable/air-gapped backups.
6. **Credential Rotation:** Rotate credentials for affected accounts and disable compromised accounts.
7. **Threat Hunt:** Conduct a broader hunt across the environment for similar behaviors and IOCs.
8. **Engage Incident Response:** Escalate to IR team for full investigation and containment.

---

## References

- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)
- [Microsoft: Volume Shadow Copy Service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [Microsoft: Windows Backup (wbadmin)](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin)

---

## Version History

| Version | Date       | Impact            | Notes                                                                                      |
|---------|------------|-------------------|--------------------------------------------------------------------------------------------|
| 1.0     | 2025-10-10 | Initial Detection | Created hunt query to detect PowerShell-based shadow copy and backup destruction for Yurei ransomware |


