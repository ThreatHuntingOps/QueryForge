# Detection of PowerShell-Based Shadow Copy and Backup Destruction
## Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** CRITICAL

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-PowerShell-VSS-Backup-Deletion-T1490
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Hunt Analytics

This hunt detects PowerShell execution of commands that delete Volume Shadow Copies or Windows backup catalogs using CrowdStrike Falcon telemetry. This is a critical pre-encryption step used by Yurei and other ransomware families to prevent recovery. Legitimate VSS deletions are uncommon and typically performed by authorized backup software, making this a high-fidelity indicator of ransomware activity. Detected behaviors include:

- PowerShell invoking `vssadmin` to delete shadow copies
- PowerShell invoking `wbadmin` to delete backup catalogs
- PowerShell using `wmic` to delete shadow copies
- PowerShell invoking `bcdedit` to disable recovery or ignore boot failures

These techniques are associated with ransomware operations designed to inhibit system recovery and maximize impact.

---

## ATT&CK Mapping

| Tactic | Technique  | Subtechnique | Technique Name                                   |
|-------|------------:|-------------:|--------------------------------------------------|
| TA0040 - Impact | T1490     | -            | Inhibit System Recovery                          |
| TA0002 - Execution | T1059.001 | -            | Command and Scripting Interpreter: PowerShell    |

---

## Hunt Query Logic

This hunt identifies suspicious PowerShell activity by looking for Falcon base_sensor events where:

- Process image matches `powershell.exe` or `pwsh.exe`
- CommandLine contains recovery inhibition patterns:
  - `vssadmin` + `delete` + `shadows`
  - `wbadmin` + `delete` + `catalog`
  - `wmic` + `shadowcopy` + `delete`
  - `bcdedit` + `recoveryenabled` + `no`
  - `bcdedit` + `bootstatuspolicy` + `ignoreallfailures`
- Optional exclusions for known legitimate backup software (Veeam, Backup Exec, Acronis)
- Optional exclusion for SYSTEM context depending on your environment

---

## Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Title: PowerShell Inhibiting System Recovery (VSS/Backup Deletion)
// Description: Detects PowerShell launching commands that delete VSS snapshots, backup catalogs, or disable recovery.
// MITRE ATT&CK: T1490, T1059.001

#event_simpleName=ProcessRollup2
| event_platform="Win"

// Scope to PowerShell (regex form, a robust default across diverse data conditions)
| ImageFileName=/(?i)^powershell(\.exe)?$/

// Inhibition patterns in CommandLine (word boundaries use single backslash; they’re regex tokens)
| (
    // vssadmin delete shadows
    (CommandLine=/(?i)\bvssadmin\b/ and CommandLine=/(?i)\bdelete\b/ and CommandLine=/(?i)\bshadows?\b/)
    or
    // wbadmin delete catalog
    (CommandLine=/(?i)\bwbadmin\b/ and CommandLine=/(?i)\bdelete\b/ and CommandLine=/(?i)\bcatalog\b/)
    or
    // wmic shadowcopy delete
    (CommandLine=/(?i)\bwmic\b/ and CommandLine=/(?i)\bshadowcopy\b/ and CommandLine=/(?i)\bdelete\b/)
    or
    // bcdedit recoveryenabled no
    (CommandLine=/(?i)\bbcdedit\b/ and CommandLine=/(?i)\brecoveryenabled\b/ and CommandLine=/(?i)\bno\b/)
    or
    // bcdedit bootstatuspolicy ignoreallfailures
    (CommandLine=/(?i)\bbcdedit\b/ and CommandLine=/(?i)\bbootstatuspolicy\b/ and CommandLine=/(?i)\bignoreallfailures\b/)
  )

// Exclusions for known legitimate backup tooling indicators
| CommandLine !=/(?i)\bveeam\b/
| CommandLine !=/(?i)\bbackup\s*exec\b/
| CommandLine !=/(?i)\bacronis\b/
| ImageFileName !=/(?i)\bveeam\b|\bbackup\s*exec\b|\bacronis\b/

// Exclude SYSTEM-equivalent context (matching a literal backslash requires \\ in regex)
| UserName !=/(?i)^(NT AUTHORITY\\SYSTEM|SYSTEM)$/

// Enrichment (field assignment uses :=)
| severity := "CRITICAL"
| detection_category := "Ransomware - System Recovery Inhibition"
| risk_score := 100
| mitre_technique := "T1490, T1059.001"

// Output
| select(
    @timestamp,
    aid,
    ComputerName,
    UserName,
    ImageFileName,
    CommandLine,
    ParentImageFileName,
    ParentCommandLine,
    ContextProcessId,
    #event_simpleName,
    severity,
    detection_category,
    risk_score,
    mitre_technique
)

// Sort newest first
| sort(field=@timestamp, order=desc, limit=1000)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                     | ATT&CK Data Source | Data Component       |
|--------------------|----------------------------------------------|--------------------|----------------------|
| CrowdStrike Falcon | base_sensor: ProcessRollup2 (process events) | Process            | Process Creation     |
| CrowdStrike Falcon | base_sensor: ProcessRollup2 (command lines)  | Command            | Command Execution    |

Field notes:
- Host identity: aid (Agent ID), ComputerName; user context: UserName
- Process fields: ImageFileName, CommandLine; Parent fields for chain context
- Event selector: #event_simpleName

---

## Execution Requirements

- **Required Permissions:** Administrator or elevated privileges typically required to execute VSS/backup deletion commands.
- **Required Artifacts:** Process creation telemetry with command-line arguments (ProcessRollup2) and PowerShell execution visibility.

---

## Considerations

- Review the user account and parent process to confirm legitimacy.
- Correlate with other ransomware indicators such as file encryption, ransom note creation, or lateral movement.
- Check for anti-recovery behaviors such as event log deletion or service termination.
- Validate whether the activity aligns with scheduled maintenance or authorized backup operations.

---

## False Positives

May occur when:
- Authorized backup software (Veeam, Backup Exec, Acronis, etc.) performs legitimate VSS operations.
- IT administrators manually delete shadow copies during maintenance.
- Automated scripts perform backup cleanup.

Mitigation:
- Tune exclusions for known backup software paths and authorized admin accounts.

---

## Recommended Response Actions

1. Immediately isolate the affected endpoint (Falcon Host containment).
2. Investigate full command-line, parent process, and user account context.
3. Correlate with Yurei indicators (e.g., `.Yurei` files, `_README_Yurei.txt`, temp payload staging).
4. Investigate lateral movement (SMB writes, WMI/CIM, `net use`, PSCredential usage).
5. If VSS is deleted, restore from immutable/air-gapped backups.
6. Rotate credentials for affected accounts and disable compromised accounts.
7. Expand hunt across environment for similar behaviors and IOCs.
8. Engage Incident Response; consider Falcon OverWatch escalation.

---

## References

- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)
- [Microsoft: Volume Shadow Copy Service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [Microsoft: Windows Backup (wbadmin)](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin)

---

## Version History

| Version | Date       | Impact             | Notes                                                                 |
|---------|------------|--------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Detection  | Hunt query for PowerShell-based shadow copy and backup destruction    |

