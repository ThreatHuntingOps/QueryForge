# Detection of Yurei-Specific Ransomware Indicators (File Extensions and Ransom Notes) 

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100
- **Severity:** CRITICAL

## Hunt Analytics Metadata

- **ID:** HuntQuery-Windows-Yurei-Indicators-T1486
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low (post-encryption, high-fidelity)
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Hunt Analytics

This hunt detects Yurei-specific indicators including the `.Yurei` file extension and the creation of `_README_Yurei.txt` ransom notes using CrowdStrike Falcon telemetry. It provides high-fidelity, reactive detection (post-encryption). Use alongside behavioral hunts for earlier-stage visibility.

Detected artifacts include:
- Creation/presence of files with the `.Yurei` extension
- Creation of `_README_Yurei.txt` ransom notes

---

## ATT&CK Mapping

| Tactic            | Technique | Subtechnique | Technique Name                |
|-------------------|----------:|-------------:|-------------------------------|
| TA0040 - Impact   | T1486     | -            | Data Encrypted for Impact     |

---

## Hunt Query Logic

- Phase 1: Detect `.Yurei` encrypted file creation
- Phase 2: Detect `_README_Yurei.txt` ransom note creation
- Correlate both within short time buckets to infer active encryption

---

## Hunt Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Title: Yurei Ransomware Correlated Detection (Active Encryption)
// Description: Correlates .Yurei extensions and _README_Yurei.txt ransom notes per process/host within 10 minutes.
// MITRE ATT&CK: T1486

| #repo="base_sensor" event_platform="Win"
| #event_simpleName =~ in(values=["NewFileWritten","FileWritten","FileModified","FileRenamed","NewExecutableWritten","NewScriptWritten"])
| TargetFileName=*

// Indicator flags per event (regex pre-aggregation)
| enc_flag := 0
| (FileName=/\\.yurei$/i or TargetFileName=/\\.yurei$/i) | enc_flag := 1

| note_flag := 0
| (FileName=/^_README_Yurei\\.txt$/i or TargetFileName=/^_README_Yurei\\.txt$/i) | note_flag := 1

// Ignore events that are neither indicator
| (enc_flag=1 or note_flag=1)

// 10-minute bucketing (milliseconds)
| bucket := @timestamp / 60000
| time_bucket := bucket * 60000

// Aggregate per process/host/time bucket
| groupBy([time_bucket, aid, ComputerName, ContextProcessId, ContextBaseFileName, UserName],
    function=[
    { enc_count := sum(enc_flag) },
    { note_count := sum(note_flag) },
    collect([FileName, TargetFileName, TargetFilePath])  // helpful context bundle
    ],
    limit=max
)

// Derive phases and risk (post-aggregation: exact arithmetic/comparisons only)
| phase_count := 0
| enc_count>0 | phase_count := phase_count + 1
| note_count>0 | phase_count := phase_count + 1

| risk_score := 80
| detection_category := "Yurei Ransomware - Ransom Note"

| enc_count>0 and note_count=0 | risk_score := 90
| enc_count>0 and note_count=0 | detection_category := "Yurei Ransomware - Encrypted Files"

| phase_count>=2 | risk_score := 100
| phase_count>=2 | detection_category := "Yurei Ransomware - Active Encryption"

// Severity and MITRE
| severity := "CRITICAL"
| mitre_technique := "T1486"

// Output
| select([
    time_bucket,
    aid,
    ComputerName,
    ContextBaseFileName,
    ContextProcessId,
    UserName,
    enc_count,
    note_count,
    phase_count,
    detection_category,
    risk_score,
    severity,
    mitre_technique
])
| sort([time_bucket], order=desc)
```

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                              | ATT&CK Data Source | Data Component       |
|--------------------|-------------------------------------------------------|--------------------|----------------------|
| CrowdStrike Falcon | base_sensor: NewFileWritten/FileWritten/FileModified  | File               | File Creation/Change |

Field notes:
- Identity: aid (Agent ID), ComputerName; user: UserName
- File fields: FileName, TargetFileName, TargetFilePath; process context: ContextBaseFileName, ContextProcessId
- Event selector: #event_simpleName

---

## Execution Requirements
- **Required Permissions:** Standard file write permissions (varies by path)
- **Required Artifacts:** File creation/modification telemetry with file name/extension

---

## Considerations
- Reactive by nature; triage and contain immediately upon detection.
- Correlate with pre-encryption behaviors (VSS deletion, log wiping, CIM/WMI lateral movement).
- Investigate the process responsible for creating `.Yurei` files or ransom notes.
- Assess scope across hosts and shares.

---

## False Positives
- Extremely rare; potential in testing/simulation scenarios.

Mitigation: Restrict simulations to isolated labs and tune exclusions for known red team artifacts.

---

## Recommended Response Actions
1. Isolate affected endpoints (Falcon Host containment).
2. Identify and terminate the process creating `.Yurei` files.
3. Enumerate affected directories and shares; assess impact.
4. Run companion hunts for VSS deletion, event log wiping, and CIM/WMI lateral movement.
5. Restore from immutable/air-gapped backups after validation.
6. Rotate credentials and disable compromised accounts.
7. Preserve memory and relevant logs for forensics; consider Falcon OverWatch escalation.

---

## References

- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [CYFIRMA: Yurei Ransomware – The Digital Ghost](https://www.cyfirma.com/research/yurei-ransomware-the-digital-ghost/)

---

## Version History

| Version | Date       | Impact              | Notes                                                             |
|---------|------------|---------------------|-------------------------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Detection   | Hunt query for Yurei-specific artifacts (extensions and notes)    |
