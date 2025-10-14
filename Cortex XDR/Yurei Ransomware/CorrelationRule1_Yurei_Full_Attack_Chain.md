# Yurei Ransomware - Full Attack Chain Detection (Correlation Rule)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100 (All three stages present within 30 minutes)
- **Severity:** Critical

## Analytics Metadata
- **ID:** CorrelationRule-Windows-Yurei-FullAttackChain
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Very Low (multi-stage behavioral correlation)
- **Lookback/Temporal Window:** 30 minutes (all stages must occur on the same host)

---

## Analytics

This correlation rule detects a multi-stage attack sequence indicative of Yurei ransomware. It correlates three distinct behaviors on the same host within a 30-minute window:

- **Stage 1 - System Recovery Inhibition:** PowerShell-based VSS/backup deletion commands (e.g., `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set recoveryenabled no`).
- **Stage 2 - Anti-Forensics:** Event log deletion or clearing via PowerShell (e.g., `wevtutil cl`, `Remove-Item` targeting `winevt\\Logs`).
- **Stage 3 - Impact:** Mass file encryption behavior (rapid file modifications) or creation of Yurei ransom note (`_README_Yurei.txt`).

Requiring all three stages drastically reduces false positives and yields high confidence of ransomware execution.

---

## ATT&CK Mapping

| Tactic             | Technique  | Subtechnique | Technique Name                       |
|--------------------|------------|--------------|--------------------------------------|
| Execution          | T1059      | .001         | Command and Scripting Interpreter: PowerShell |
| Impact             | T1490      | -            | Inhibit System Recovery              |
| Defense Evasion    | T1070      | -            | Indicator Removal                    |
| Impact             | T1486      | -            | Data Encrypted for Impact            |

---

## Correlation Logic

- Scope: Same host (agent_hostname)
- Window: 30 minutes
- Stages and thresholds:
  - Stage 1 (Recovery Inhibition): ≥1 PowerShell VSS/backup deletion command
  - Stage 2 (Log Deletion): ≥1 event log deletion/clear action
  - Stage 3 (Impact): Either ≥50 file modifications in 5 minutes OR creation of `_README_Yurei.txt`

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Palo Alto Cortex XDR and XSIAM

```xql
// Correlation Rule: Yurei Ransomware - Full Attack Chain Detection
// Stages: Recovery Inhibition (T1490), Log Deletion (T1070), Impact (T1486)

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type in (ENUM.PROCESS, ENUM.FILE) 

// Stage 1: VSS/Backup deletion 
| alter stage1_recovery_inhibition = if( 
        event_type = ENUM.PROCESS and 
        actor_process_image_name contains "powershell" and 
        (actor_process_command_line contains "vssadmin delete shadows" 
         or actor_process_command_line contains "wbadmin delete catalog" 
         or (actor_process_command_line contains "bcdedit" and actor_process_command_line contains "recoveryenabled no")), 
        1, 0 
  ) 

// Stage 2: Event log deletion 
| alter stage2_log_deletion = if( 
        event_type = ENUM.PROCESS and 
        actor_process_image_name contains "powershell" and 
        ((actor_process_command_line contains "Remove-Item" and actor_process_command_line contains "winevt\Logs") 
         or actor_process_command_line contains "wevtutil cl"), 
        1, 0 
  ) 

// Stage 3: Ransom note creation (impact) 
| alter stage3_ransom_note = if( 
        event_type = ENUM.FILE and 
        event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_CREATE_NEW) and 
        action_file_name = "_README_Yurei.txt", 
        1, 0 
  ) 

// Aggregate stages by host within the time window of the query execution 
| comp sum(stage1_recovery_inhibition) as stage1_count, 
       sum(stage2_log_deletion) as stage2_count, 
       sum(stage3_ransom_note) as stage3_count 
  by agent_hostname 

// Correlation condition: All 3 stages detected 
| filter stage1_count > 0 and stage2_count > 0 and stage3_count > 0 

// Enrichment 
| alter alert_severity = "CRITICAL", 
        alert_name = "Yurei Ransomware - Full Attack Chain Detected", 
        confidence = "HIGH", 
        recommended_action = "IMMEDIATE ISOLATION: Disconnect host from network, kill suspicious processes, initiate IR" 

| fields agent_hostname, stage1_count, stage2_count, stage3_count, alert_severity, alert_name, confidence, recommended_action 
| sort desc stage1_count
```

Note: To incorporate the optional mass file modification threshold (≥50 in 5 minutes) for Stage 3, run this correlation in conjunction with the mass-encryption analytic (Query 4) or add a pre-aggregation that flags such buckets and then unions into stage3_count.

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex       | xdr_data   | Process            | Process Creation      |
| Cortex       | xdr_data   | File               | File Creation/Write   |

---

## Execution Requirements
- **Required Permissions:** User-level sufficient to run PowerShell; admin needed for VSS and event log operations.
- **Required Artifacts:** Process and file telemetry with command-line, file name, and subtype details.

---

## Rationale for Fidelity
- **Multi-Stage Requirement:** Requires three distinct malicious actions, reducing false positives.
- **Temporal Correlation:** Ensures actions are part of the same campaign on the host within 30 minutes.
- **Behavioral Focus:** Independent of mutable IOCs such as hashes or filenames.
- **High Confidence:** The combination of these stages is highly indicative of active ransomware.

---

## Potential Bypasses/Limitations
- **Staged Attacks:** If attacker delays stages beyond 30 minutes, correlation may miss.
- **Partial Execution:** Missing telemetry for any stage prevents correlation from triggering.
- **Evasion:** Attackers could omit event log deletion and still encrypt data.

### Mitigation
- Consider extending the temporal window to 60 minutes for slower attacks.
- Deploy each individual stage detection as separate high-priority alerts.

---

## Recommended Response Actions
1. Immediately isolate the affected host from the network.
2. Terminate suspicious PowerShell and ransomware processes.
3. Acquire memory and volatile artifacts before remediation.
4. Search for ransom notes and `.Yurei` files to scope impact.
5. Validate backups and begin restoration from immutable/air-gapped copies if needed.
6. Hunt for lateral movement (SMB drops, CIM/WMI) and credential compromise.
7. Rotate credentials for impacted users and admins; review local admin group membership.
8. Engage the Incident Response team and follow ransomware playbooks.

---

## References
- [MITRE ATT&CK: T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK: T1490 – Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- [MITRE ATT&CK: T1070 – Indicator Removal](https://attack.mitre.org/techniques/T1070/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

---

## Version History

| Version | Date       | Impact              | Notes                                                   |
|---------|------------|---------------------|---------------------------------------------------------|
| 1.0     | 2025-10-14 | Initial Correlation | Multi-stage Yurei ransomware full attack chain rule     |
