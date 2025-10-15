# Data Exfiltration Followed by Encryption (Double-Extortion) - Correlation Rule 

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100 (All four phases within 2 hours)
- **Severity:** Critical

## Analytics Metadata
- **ID:** CorrelationRule-Windows-DoubleExtortion-Exfil-Then-Encrypt
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low (multi-phase behavioral correlation)
- **Lookback/Temporal Window:** 2 hours (same host)
- **Prerequisites:** CrowdStrike Falcon file and network telemetry available; outbound baseline recommended
- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon (LogScale / Falcon Data Replicator datasets)

---

## Analytics

This correlation rule detects the double-extortion pattern where data is exfiltrated prior to ransomware encryption using CrowdStrike Falcon telemetry. It correlates four phases on the same host within a 2-hour window:

- **Phase 1 - Data Collection (T1005):** Access to sensitive files (PST, Office docs, databases)
- **Phase 2 - Data Staging (T1074):** Copying to temp/staging directories or compressing into archives
- **Phase 3 - Exfiltration (T1041):** Large outbound transfers (approximated via multiple outbound connections to exfil ports)
- **Phase 4 - Encryption (T1486):** Mass file encryption activity or creation of Yurei ransom note (`_README_Yurei.txt`)

This multi-phase behavioral correlation is resilient to IOC changes and yields high-confidence detections.

---

## ATT&CK Mapping

| Tactic       | Technique | Subtechnique | Technique Name                         |
|--------------|----------:|-------------:|----------------------------------------|
| Collection   | T1005     | -            | Data from Local System                  |
| Collection   | T1074     | -            | Data Staged                             |
| Exfiltration | T1041     | -            | Exfiltration Over C2 Channel            |
| Impact       | T1486     | -            | Data Encrypted for Impact               |

---

## Correlation Logic

- Scope: Same host (aid, ComputerName)
- Window: 2 hours
- Phase thresholds:
  - Phase 1: Access to ≥10 sensitive files
  - Phase 2: ≥1 archive creation or staging ≥5 files to temp
  - Phase 3: Outbound transfer >50MB (approximated here as ≥5 exfil events or ≥3 distinct external destinations)
  - Phase 4: Either ≥50 file modifications in 5 minutes OR ransom note creation

---

## Query Syntax

- **Query Language:** Falcon LogScale
- **Platform:** CrowdStrike Falcon LogScale

```cql
// Correlation Rule: Double-Extortion (Exfiltration then Encryption)
// Phases: Data Collection (T1005) → Data Staging (T1074) → Exfiltration (T1041) → Encryption (T1486)

| #repo="base_sensor" event_platform="Win"

// Limit to file and network events
| (
    #event_simpleName="NewFileWritten" or
    #event_simpleName="FileWritten" or
    #event_simpleName="NewExecutableWritten" or
    #event_simpleName="NewScriptWritten" or
    #event_simpleName="NetworkConnectIP4" or
    #event_simpleName="NetworkConnectIP6"
  )

// Initialize phase flags
| phase1_sensitive_access := 0
| phase2_staging := 0
| phase3_exfiltration := 0
| phase4_encryption_note := 0

// Phase 1: Sensitive file access (extensions read/copied - best-effort via file events we see as writes/creates/renames)
// We trigger on touches to sensitive extensions. Adjust if your tenant exposes explicit read events.
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten") and
    (FileName=/\\.(pst|ost|xlsx|docx|pdf|kdbx|db|sql|mdb)$/i)
  ) | phase1_sensitive_access := 1

// Phase 2: Data staging (archive writes/creates OR temp-path writes)
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten") and
    (
    FileName=/\\.(zip|rar|7z|tar|gz)$/i or
    TargetFileName=/\\Temp\\|\\AppData\\Local\\Temp\\/i
    )
  ) | phase2_staging := 1

// Phase 3: Exfil heuristic without byte counters — connections to common exfil ports
| (
    (#event_simpleName="NetworkConnectIP4" or #event_simpleName="NetworkConnectIP6") and
    (RemotePort=443 or RemotePort=80 or RemotePort=22 or RemotePort=21 or RemotePort=990 or RemotePort=8080 or RemotePort=8443) and
    (RemoteAddressIP4=* or RemoteAddressIP6=*)
  ) | phase3_exfiltration := 1

// Phase 4: Encryption indicator — ransom note creation
| (
    (#event_simpleName="NewFileWritten" or #event_simpleName="FileWritten" or #event_simpleName="NewExecutableWritten" or #event_simpleName="NewScriptWritten") and
    (FileName=/^_README_Yurei\\.txt$/i or TargetFileName=/^_README_Yurei\\.txt$/i)
  ) | phase4_encryption_note := 1

// Keep rows that hit at least one phase
| (phase1_sensitive_access=1 or phase2_staging=1 or phase3_exfiltration=1 or phase4_encryption_note=1)

// Aggregate by host, process image (actor), and user context across the time range
| groupBy([aid, ComputerName, ContextBaseFileName, UserName],
    function=[
    { sensitive_file_count := sum(phase1_sensitive_access) },
    { staging_event_count := sum(phase2_staging) },
    { exfiltration_event_count := sum(phase3_exfiltration) },
    { encryption_indicator_count := sum(phase4_encryption_note) },
    { distinct_exfil_dests_v4 := count(RemoteAddressIP4, distinct=true) },
    { distinct_exfil_dests_v6 := count(RemoteAddressIP6, distinct=true) }
    ],
    limit=max
)

// Combine v4 and v6 distinct destinations
| distinct_exfil_dests := distinct_exfil_dests_v4 + distinct_exfil_dests_v6

// Correlation condition thresholds
| sensitive_file_count>=10
| staging_event_count>=1
| (exfiltration_event_count>=5 or distinct_exfil_dests>=3)
| encryption_indicator_count>=1

// Enrichment
| alert_severity := "CRITICAL"
| alert_name := "Double-Extortion Ransomware Detected (Exfiltration + Encryption)"
| confidence := "VERY HIGH"
| recommended_action := "CRITICAL INCIDENT: Isolate host immediately, block outbound traffic, engage IR team, notify legal/compliance"
| mitre_techniques := "T1005, T1074, T1041, T1486"

// Output
| select([
    aid,
    ComputerName,
    ContextBaseFileName,
    UserName,
    sensitive_file_count,
    staging_event_count,
    distinct_exfil_dests,
    exfiltration_event_count,
    encryption_indicator_count,
    alert_severity,
    alert_name,
    confidence,
    recommended_action,
    mitre_techniques
])
| sort([distinct_exfil_dests], order=desc)
```

Note: If byte/volume fields (e.g., bytes_out) are available in your telemetry, replace the Phase 3 heuristic with a direct volume threshold (>50 MB) aggregated per host and destination.

---

## Data Sources

| Provider            | Dataset/Events (Falcon)                                  | ATT&CK Data Source | Data Component             |
|--------------------|-----------------------------------------------------------|--------------------|----------------------------|
| CrowdStrike Falcon | base_sensor: NewFileWritten/FileWritten (file telemetry) | File               | File Read / File Write     |
| CrowdStrike Falcon | base_sensor: NetworkConnectIP4/NetworkConnectIP6         | Network            | Network Connection         |

Field notes:
- Host identity: aid (Agent ID), ComputerName; user context: UserName; actor image: ContextBaseFileName
- File fields: FileName, TargetFileName; Network fields: RemotePort, RemoteAddressIP4/IPv6
- Event selector: #event_simpleName

---

## Execution Requirements
- **Required Permissions:** User-level sufficient for file read; staging and compression require local write; exfil requires outbound network access.
- **Required Artifacts:** File and network telemetry; file extensions and paths; remote IPs and ports.

---

## Rationale for Fidelity
- **Complete Attack Lifecycle:** Requires all four phases; rare in benign usage.
- **Volume/Multiplicity Thresholds:** Sensitive file count and multi-destination exfil reduce noise.
- **Behavioral Correlation:** Resilient against hash/filename changes.
- **High Confidence:** Collection + staging + exfil + encryption indicates double-extortion.

---

## Potential Bypasses/Limitations
- **Slow Exfiltration:** Low-and-slow <50 MB may evade the heuristic.
- **Cloud Exfiltration:** Use CASB or cloud logs to differentiate legitimate uploads.
- **Encryption-Only:** Single-extortion cases won’t trigger this rule.

### Mitigation
- Lower exfil threshold based on baseline if needed.
- Integrate CASB or proxy logs to enrich exfil detection.
- Keep standalone encryption detection (Query 4) enabled for single-extortion scenarios.
- Extend window to 4–6 hours for slower campaigns.

---

## Recommended Response Actions
1. Isolate the host and block outbound traffic to suspected destinations (Falcon Host containment; egress controls).
2. Triage files accessed/staged; identify data sensitivity and potential exposure.
3. Acquire volatile data and preserve relevant artifacts (archives, temp folders); collect Falcon context.
4. Validate backups; plan recovery and notify legal/compliance per policy.
5. Hunt for pre-encryption indicators (VSS deletion, event log wipes) and lateral movement.
6. Engage the IR team and initiate the data breach response process; consider Falcon OverWatch escalation.

---

## References
- [MITRE ATT&CK: T1005 – Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [MITRE ATT&CK: T1074 – Data Staged](https://attack.mitre.org/techniques/T1074/)
- [MITRE ATT&CK: T1041 – Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK: T1486 – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

---

## Version History

| Version | Date       | Impact                  | Notes                                                   |
|---------|------------|-------------------------|---------------------------------------------------------|
| 1.0     | 2025-10-15 | Initial Correlation     | Double-extortion (exfiltration then encryption) rule    |
