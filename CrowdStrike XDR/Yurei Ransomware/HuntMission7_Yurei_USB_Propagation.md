# Detection of Removable Media Propagation (USB Infection)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 95 (Yurei/masquerading filename), 75 (generic executable to USB)
- **Severity:** HIGH or MEDIUM (based on filename risk)

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-USB-Propagation-T1091
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Hunt Analytics

This hunt detects executable files written to removable drives (USB/external HDD) using CrowdStrike Falcon telemetry. Yurei drops `WindowsUpdate.exe` to USB drives as a propagation mechanism. The hunt highlights:
- Executable writes to removable drive letters (E:..Z:)
- Exclusion of Windows directory paths to reduce noise
- Suspicious filenames (Yurei-specific, system masquerade, or short random names)

---

## ATT&CK Mapping

| Tactic                   | Technique | Subtechnique | Technique Name                        |
|--------------------------|----------:|-------------:|---------------------------------------|
| TA0008 - Lateral Movement| T1091     | -            | Replication Through Removable Media   |
| TA0005 - Defense Evasion | T1036     | -            | Masquerading                          |

---

## Hunt Query Logic

- FILE write telemetry targeting E:–Z: drives
- Exclude `\\Windows\\` on the removable path
- Flag Yurei-specific and masquerading filenames; also detect 8–12 char lowercase random `.exe`
- Score 95/HIGH for suspicious names; 75/MEDIUM for generic executable writes

---

## Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Title: Executable Drops to Removable Media (USB/External Drives)
// Description: Detects executable files written to removable drives. Yurei drops WindowsUpdate.exe to USB drives.
// MITRE ATT&CK: T1091, T1036

| #repo="base_sensor" event_platform="Win"
| #event_simpleName =~ in(values=["NewFileWritten","FileWritten","NewExecutableWritten","NewScriptWritten"])
| TargetFileName=*

// Detect writes to removable drive letters (E: through Z:) - regex allowed pre-aggregation
| TargetFileName=/^[E-Z]:\\/i

// Exclude Windows directory
| TargetFileName!=/\\Windows\\/i

// Focus on executable file extensions
| FileName=/\\.(exe|dll|bat|ps1|vbs|hta|scr|com)$/i

// Exclusions (exact matches)
| UserName!="DOMAIN\\BackupSVC"
| UserName!="DOMAIN\\AntivirusSVC"
| ContextBaseFileName!="backup.exe"
| ContextBaseFileName!="sync.exe"
| ContextBaseFileName!="antivirus.exe"

// Suspicious filename detection (regex allowed - no aggregation)
| is_suspicious_filename := 0
| (
    FileName=/^(WindowsUpdate\\.exe|svchost\\.exe|System32_Backup\\.exe|csrss\\.exe|lsass\\.exe)$/i or
    FileName=/^[a-z0-9]{8,12}\\.exe$/i
  ) | is_suspicious_filename := 1

// Enrichment (inline)
| risk_score := 75
| is_suspicious_filename=1 | risk_score := 95

| severity := "MEDIUM"
| is_suspicious_filename=1 | severity := "HIGH"

| detection_category := "Suspicious Executable to Removable Media"
| is_suspicious_filename=1 | detection_category := "Ransomware Propagation - USB Infection"

| mitre_technique := "T1091, T1036"

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
    is_suspicious_filename,
    severity,
    detection_category,
    risk_score,
    mitre_technique
])
| sort([risk_score], order=desc)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                                 | ATT&CK Data Source | Data Component            |
|--------------------|----------------------------------------------------------|--------------------|---------------------------|
| CrowdStrike Falcon | base_sensor: NewFileWritten/FileWritten/NewExecutable... | File               | File Creation/Write       |

Field notes:
- Identity: aid, ComputerName; user: UserName
- File fields: FileName, TargetFileName, TargetFilePath; process context: ContextBaseFileName, ContextProcessId
- Event selector: #event_simpleName

---

## Execution Requirements
- **Required Permissions:** Write access to removable drives
- **Required Artifacts:** File create/write telemetry with full path and filename; process lineage; user context

---

## Considerations
- Some orgs map network/encrypted drives to E:..Z:. If possible, validate device type via additional telemetry.
- Time-correlate process actions before/after the write (e.g., copying from temp dirs).
- System-like filenames on removable media are high risk.
- Check user authorization and device control policies.

---

## False Positives
- Software updates via USB in air-gapped environments
- Legit admin scripts/tools copied to USB
- Backup/sync utilities writing to removable drives

Mitigation: Maintain allowlists for known tools and accounts; correlate with maintenance windows/change tickets.

---

## Recommended Response Actions
1. Triage whether the USB executable copy is authorized; if not, quarantine the device.
2. Analyze the dropped executable (hash, reputation, sandbox).
3. Trace source process and user; check for additional artifacts.
4. Hunt for related Yurei activity (VSS deletion, log wiping, CIM/WMI, SMB drops, `.Yurei` files, `_README_Yurei.txt`).
5. Enforce/tighten removable media policies and device control.
6. Rotate credentials if compromise suspected; preserve relevant logs/metadata.

---

## References
- [MITRE ATT&CK: T1091 – Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/)
- [MITRE ATT&CK: T1036 – Masquerading](https://attack.mitre.org/techniques/T1036/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)

---

## Version History

| Version | Date       | Impact             | Notes                                                         |
|---------|------------|--------------------|---------------------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Detection  | Hunt query for removable media propagation (Yurei context)    |
