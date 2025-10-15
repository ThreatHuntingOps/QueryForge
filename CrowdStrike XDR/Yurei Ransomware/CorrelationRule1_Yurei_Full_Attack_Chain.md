# Yurei Ransomware - Full Attack Chain Detection (Correlation Rule)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100 (All three stages present within 30 minutes)
- **Severity:** Critical

## Analytics Metadata
- **ID:** CorrelationRule-Windows-Yurei-FullAttackChain
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low (multi-stage behavioral correlation)
- **Lookback/Temporal Window:** 30 minutes (all stages must occur on the same host)
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Analytics

This correlation rule detects a multi-stage attack sequence indicative of Yurei ransomware on Windows hosts using CrowdStrike Falcon telemetry. It correlates three distinct behaviors observed in base_sensor events within a 30-minute window:

- **Stage 1 - System Recovery Inhibition:** PowerShell-based VSS/backup deletion commands (e.g., `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no`).
- **Stage 2 - Anti-Forensics:** Event log deletion/clearing via PowerShell (e.g., `wevtutil cl`, `Remove-Item` targeting `winevt\\Logs`).
- **Stage 3 - Impact:** Mass file encryption indicators via ransom note creation (`_README_Yurei.txt`). Optionally, augment with a mass file modification signal.

Requiring all three stages drastically reduces false positives and yields high confidence of ransomware execution.

---

## ATT&CK Mapping

| Tactic          | Technique | Subtechnique | Technique Name                                   |
|-----------------|-----------|--------------|--------------------------------------------------|
| Execution       | T1059     | .001         | Command and Scripting Interpreter: PowerShell    |
| Impact          | T1490     | -            | Inhibit System Recovery                          |
| Defense Evasion | T1070     | -            | Indicator Removal                                |
| Impact          | T1486     | -            | Data Encrypted for Impact                        |

---

## Correlation Logic

- Scope: Same host (aid and ComputerName)
- Window: 30 minutes
- Stages and thresholds:
  - Stage 1 (Recovery Inhibition): ≥1 PowerShell VSS/backup deletion command
  - Stage 2 (Log Deletion): ≥1 event log deletion/clear action
  - Stage 3 (Impact): Either ≥50 file modifications in 5 minutes OR creation of `_README_Yurei.txt`


---

## Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale


```cql
// Correlation Rule: Yurei Ransomware - Full Attack Chain Detection
// Stages: Recovery Inhibition (T1490), Log Deletion (T1070), Impact (T1486)

| #repo="base_sensor" event_platform="Win"

// Limit to needed event families (process + file write/create events)
| (
    #event_simpleName="ProcessRollup2" or
    #event_simpleName="NewFileWritten" or
    #event_simpleName="FileWritten" or
    #event_simpleName="NewExecutableWritten" or
    #event_simpleName="NewScriptWritten"
  )

// Initialize stage flags
| stage1_recovery_inhibition := 0
| stage2_log_deletion := 0
| stage3_ransom_note := 0

// Stage 1: VSS/Backup deletion via PowerShell (case-insensitive regex pre-aggregation)
| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\powershell\\.exe$/i or ImageFileName=/\\pwsh\\.exe$/i) and
    CommandLine=/vssadmin\\s+delete\\s+shadows/i
  ) | stage1_recovery_inhibition := 1

| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\powershell\\.exe$/i or ImageFileName=/\\pwsh\\.exe$/i) and
    CommandLine=/wbadmin\\s+delete\\s+catalog/i
  ) | stage1_recovery_inhibition := 1

| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\powershell\\.exe$/i or ImageFileName=/\\pwsh\\.exe$/i) and
    CommandLine=/bcdedit/i and
    CommandLine=/recoveryenabled\\s+no/i
  ) | stage1_recovery_inhibition := 1

// Stage 2: Event log deletion via PowerShell (Remove-Item on winevt\\Logs or wevtutil cl)
| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\powershell\\.exe$/i or ImageFileName=/\\pwsh\\.exe$/i) and
    CommandLine=/Remove-Item/i and
    CommandLine=/winevt\\Logs/i
  ) | stage2_log_deletion := 1

| (
    #event_simpleName="ProcessRollup2" and
    (ImageFileName=/\\powershell\\.exe$/i or ImageFileName=/\\pwsh\\.exe$/i) and
    CommandLine=/\\bwevtutil\\s+cl\\b/i
  ) | stage2_log_deletion := 1

// Stage 3: Ransom note creation (file write/create of _README_Yurei.txt)
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten") and
    (FileName=/^_README_Yurei\\.txt$/i or TargetFileName=/^_README_Yurei\\.txt$/i)
  ) | stage3_ransom_note := 1

// Aggregate by host (aid + ComputerName) across the query time window
| groupBy([aid, ComputerName],
    function=[
    { stage1_count := sum(stage1_recovery_inhibition) },
    { stage2_count := sum(stage2_log_deletion) },
    { stage3_count := sum(stage3_ransom_note) }
    ],
    limit=max
)

// Correlation condition: all three stages present
| stage1_count>0
| stage2_count>0
| stage3_count>0

// Enrichment
| alert_severity := "CRITICAL"
| alert_name := "Yurei Ransomware - Full Attack Chain Detected"
| confidence := "HIGH"
| recommended_action := "IMMEDIATE ISOLATION: Disconnect host from network, kill suspicious processes, initiate IR"
| mitre_techniques := "T1490, T1070, T1486"

// Output
| select([
    aid,
    ComputerName,
    stage1_count,
    stage2_count,
    stage3_count,
    alert_severity,
    alert_name,
    confidence,
    recommended_action,
    mitre_techniques
])
| sort([stage1_count], order=desc)
```
---
## Data Sources

| Provider                 | Dataset/Events (Falcon)                                  | ATT&CK Data Source | Data Component         |
|-------------------------|-----------------------------------------------------------|--------------------|------------------------|
| CrowdStrike Falcon      | base_sensor: ProcessRollup2 (process telemetry)          | Process            | Process Creation       |
| CrowdStrike Falcon      | base_sensor: NewFileWritten/FileWritten (file telemetry) | File               | File Creation/Write    |

Field notes:
- Host identity: aid (Agent ID), ComputerName
- Process fields: ImageFileName, CommandLine
- File fields: FileName, TargetFileName
- Event selector: #event_simpleName (use to scope event families)

---

## Execution Requirements
- **Required Permissions:** User-level to run PowerShell; administrative privileges typically required for VSS, bcdedit, and event log operations.
- **Required Artifacts:** Process telemetry (ProcessRollup2 with ImageFileName, CommandLine) and file-creation telemetry (NewFileWritten/FileWritten with FileName/TargetFileName).

---

## Rationale for Fidelity
- **Multi-Stage Requirement:** Requires three distinct malicious actions, reducing false positives.
- **Temporal Correlation:** Ensures actions are part of the same campaign on the host within 30 minutes.
- **Behavioral Focus:** Independent of mutable IOCs such as hashes or filenames.
- **High Confidence:** The combination of these stages is highly indicative of active ransomware.

---

## Potential Bypasses/Limitations
- **Staged Attacks:** If the attacker delays stages beyond 30 minutes, correlation may miss.
- **Partial Execution:** Missing telemetry for any stage prevents correlation from triggering.
- **Evasion:** Attackers could omit event log deletion and still encrypt data.

### Mitigation
- Consider extending the temporal window to 60 minutes for slower attacks.
- Deploy each individual stage detection as separate high-priority alerts.
- If available, incorporate a mass file modification bucket signal into Stage 3 for earlier impact confirmation.

---

## Recommended Response Actions
1. Immediately isolate the affected host from the network (Falcon Host containment).
2. Terminate suspicious PowerShell and ransomware processes via Falcon Real Time Response (RTR) or EDR controls.
3. Acquire volatile artifacts: memory capture, process lists, handles; collect relevant Falcon event context.
4. Search the host for ransom notes and `.Yurei` files to scope impact; identify initial access vector.
5. Validate backups and initiate restoration from immutable/air-gapped copies if needed.
6. Hunt for lateral movement (SMB drops, WMI/CIM) and credential compromise using Falcon telemetry.
7. Rotate credentials for impacted users/admins; review local administrators group membership.
8. Engage Incident Response and follow ransomware playbooks; consider Falcon OverWatch escalation.

---

## References
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1070 – Indicator Removal](https://attack.mitre.org/techniques/T1070/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

---

## Version History

| Version | Date       | Impact              | Notes                                              |
|---------|------------|---------------------|----------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Correlation | Multi-stage Yurei ransomware full attack chain rule |
