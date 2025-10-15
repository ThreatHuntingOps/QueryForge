# Detection of SMB Lateral Movement with File Drops to Network Shares

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (Yurei-specific filenames), 85 (Generic executable drops), 70 (SMB network activity)
- **Severity:** HIGH to MEDIUM (based on detection phase)

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-SMB-Lateral-File-Drop-T1021
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Hunt Analytics

This hunt detects executable files written to SMB network shares using CrowdStrike Falcon telemetry. Yurei drops `System32_Backup.exe` to shares as part of propagation. The hunt highlights:

- Phase 1: Executable writes to UNC paths (network shares)
- Phase 2: SMB connections on ports 445/139
- Suspicious filenames: Yurei-specific or masquerading as system processes; random 8–12 char names

---

## ATT&CK Mapping

| Tactic                   | Technique | Subtechnique | Technique Name                              |
|--------------------------|----------:|-------------:|---------------------------------------------|
| TA0008 - Lateral Movement| T1021     | .002         | Remote Services: SMB/Windows Admin Shares   |
| TA0008 - Lateral Movement| T1570     | -            | Lateral Tool Transfer                       |

---

## Hunt Query Logic

- Phase 1: FILE writes to UNC paths with executable/script extensions
- Phase 2: NETWORK connections to 445/139 with remote IP
- Risk scoring based on filename and write presence
- Exclusions for known service accounts, file servers, and deploy tools

---

## Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Title: Suspicious File Drops to SMB Network Shares (Lateral Movement)
// Description: Detects executable files written to network shares. Yurei drops System32_Backup.exe to network shares.
// MITRE ATT&CK: T1021.002, T1570

| #repo="base_sensor" event_platform="Win"

// Limit to file and network connect events
| (
    #event_simpleName="NewFileWritten" or
    #event_simpleName="FileWritten" or
    #event_simpleName="NewExecutableWritten" or
    #event_simpleName="NewScriptWritten" or
    #event_simpleName="NetworkConnectIP4" or
    #event_simpleName="NetworkConnectIP6"
  )

// Phase 1: file drop to UNC network share (regex allowed here)
| file_to_network_share := 0
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten")
    and TargetFileName=* 
    and TargetFileName=/^\\\\[^\\]+\\/i
    and FileName=/\\.(exe|dll|bat|ps1|vbs|hta)$/i
  ) | file_to_network_share := 1

// Phase 2: SMB network connection (ports 445 or 139)
| smb_network_connection := 0
| (
    (#event_simpleName="NetworkConnectIP4" or #event_simpleName="NetworkConnectIP6")
    and (RemotePort=445 or RemotePort=139)
  ) | smb_network_connection := 1

// Keep only events that match at least one phase
| (file_to_network_share=1 or smb_network_connection=1)

// Exclusions (exact matches only)
| UserName!="DOMAIN\\BackupSVC"
| UserName!="DOMAIN\\DeploymentSVC"
| ComputerName!="FILE-SERVER-01"
| ComputerName!="BACKUP-01"
| FileName!="backup.exe"
| FileName!="deploy.exe"

// Suspicious filenames (regex allowed — no aggregation in this query)
| (
    file_to_network_share=0 or
    FileName=/^(System32_Backup\\.exe|WindowsUpdate\\.exe|svchost\\.exe|csrss\\.exe|lsass\\.exe|smss\\.exe)$/i or
    FileName=/^[a-z0-9]{8,12}\\.exe$/i
  )

// Enrichment
| detection_category := "SMB Network Activity"
| file_to_network_share=1 | detection_category := "Lateral Movement - File Drop to Network Share"

| risk_score := 70
| file_to_network_share=1 | risk_score := 85
| (file_to_network_share=1 and FileName=/^(System32_Backup\\.exe|WindowsUpdate\\.exe)$/i) | risk_score := 95

| severity := "MEDIUM"
| risk_score>=90 | severity := "HIGH"

| mitre_technique := "T1021.002, T1570"

// Output
| select([
    @timestamp,
    aid,
    ComputerName,
    ContextBaseFileName,
    ContextProcessId,
    UserName,
    FileName,
    TargetFileName,
    TargetFilePath,
    RemoteAddressIP4,
    RemotePort,
    file_to_network_share,
    smb_network_connection,
    detection_category,
    risk_score,
    severity,
    mitre_technique
])
| sort([risk_score], order=desc)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                                 | ATT&CK Data Source | Data Component          |
|--------------------|----------------------------------------------------------|--------------------|-------------------------|
| CrowdStrike Falcon | base_sensor: NewFileWritten/FileWritten (file telemetry) | File               | File Creation           |
| CrowdStrike Falcon | base_sensor: NetworkConnectIP4/IP6                       | Network            | Network Connection      |

Field notes:
- Identity: aid, ComputerName; user: UserName
- File fields: FileName, TargetFileName, TargetFilePath; network: RemotePort, RemoteAddressIP4
- Event selector: #event_simpleName

---

## Execution Requirements
- **Required Permissions:** Write access to network shares (often requires domain credentials).
- **Required Artifacts:** File creation/write telemetry with UNC paths; SMB network connection telemetry; process context; authentication logs for share access where available.

---

## Considerations
- Validate share type (C$, ADMIN$, IPC$, custom) and business legitimacy.
- Time-correlate file drops with remote execution (CIM/WMI, PsExec) in short windows.
- Investigate user authorization; masquerading filenames in non-system paths are suspicious.
- Watch for short random executable names; review network topology/relationships.

---

## False Positives
- Admin software distribution, SCCM/patching, legitimate backups, deployment pipelines, AV update distribution via shares.

Mitigation: Maintain allowlists for approved tools/accounts; exclude known file servers and change windows.

---

## Recommended Response Actions
1. Triage whether the file drop is authorized; if not, contain the source host.
2. Retrieve and analyze the dropped file (hashing/sandboxing/reversing).
3. Enumerate affected shares/hosts; check for subsequent remote execution.
4. Correlate with Yurei indicators (VSS deletion, log wipes, CIM/WMI activity, `.Yurei` files, `_README_Yurei.txt`).
5. Review user account activity for compromise; rotate credentials if needed.
6. Harden network shares (reduce admin shares, least privilege, SMB signing/encryption, segmentation).
7. Preserve network/process/file telemetry for forensics; expand hunt for similar patterns.

---

## References
- [MITRE ATT&CK: T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK: T1570 – Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)
- [Microsoft: SMB Security Best Practices](https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security)
- [CISA: SMBv1 Exploitation and Ransomware](https://www.cisa.gov/uscert/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices)

---

## Version History

| Version | Date       | Impact             | Notes                                                               |
|---------|------------|--------------------|---------------------------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Detection  | Hunt query for SMB lateral movement with file drops (Yurei context) |
