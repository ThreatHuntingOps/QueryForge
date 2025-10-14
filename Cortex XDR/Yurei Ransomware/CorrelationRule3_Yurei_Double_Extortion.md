# Data Exfiltration Followed by Encryption (Double-Extortion) - Correlation Rule

## Severity or Impact of the Detected Behavior
- **Risk Score:** 100 (All four phases within 2 hours)
- **Severity:** Critical

## Analytics Metadata
- **ID:** CorrelationRule-Windows-DoubleExtortion-Exfil-Then-Encrypt
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low (multi-phase behavioral correlation)
- **Lookback/Temporal Window:** 2 hours (same host)
- **Prerequisites:** XDR file and network telemetry available; outbound baseline recommended

---

## Analytics

This correlation rule detects the double-extortion pattern where data is exfiltrated prior to ransomware encryption. It correlates four phases on the same host within a 2-hour window:

- **Phase 1 - Data Collection (T1005):** Access to sensitive files (PST, Office docs, databases)
- **Phase 2 - Data Staging (T1074):** Copying to temp/staging directories or compressing into archives
- **Phase 3 - Exfiltration (T1041):** Large outbound transfers (approximated via multiple outbound connections to exfil ports)
- **Phase 4 - Encryption (T1486):** Mass file encryption activity or creation of Yurei ransom note (`_README_Yurei.txt`)

This multi-phase behavioral correlation is resilient to IOC changes and yields high-confidence detections.

---

## ATT&CK Mapping

| Tactic            | Technique | Subtechnique | Technique Name                        |
|-------------------|----------:|-------------:|---------------------------------------|
| Collection        | T1005     | -            | Data from Local System                 |
| Collection        | T1074     | -            | Data Staged                            |
| Exfiltration      | T1041     | -            | Exfiltration Over C2 Channel           |
| Impact            | T1486     | -            | Data Encrypted for Impact              |

---

## Correlation Logic

- Scope: Same host (agent_hostname)
- Window: 2 hours
- Phase thresholds:
  - Phase 1: Access to ≥10 sensitive files
  - Phase 2: ≥1 archive creation or staging ≥5 files to temp
  - Phase 3: Outbound transfer >50MB (approximated here as ≥5 exfil events or ≥3 distinct external destinations)
  - Phase 4: Either ≥50 file modifications in 5 minutes OR ransom note creation

---

## Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Palo Alto Cortex XDR and XSIAM

```xql
// Correlation Rule: Double-Extortion (Exfiltration then Encryption)
// Phases: Data Collection (T1005) → Data Staging (T1074) → Exfiltration (T1041) → Encryption (T1486)

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type in (ENUM.FILE, ENUM.NETWORK) 

// Phase 1: Sensitive file access (reads/copies of sensitive extensions) 
| alter phase1_sensitive_access = if( 
        event_type = ENUM.FILE 
        and action_file_extension in (".pst", ".ost", ".xlsx", ".docx", ".pdf", ".kdbx", ".db", ".sql", ".mdb"), 
        1, 0 
  ) 

// Phase 2: Data staging (archive writes/creates or copies into Temp locations) 
| alter phase2_staging = if( 
        event_type = ENUM.FILE 
        and event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_CREATE_NEW) 
        and ( 
             action_file_extension in (".zip", ".rar", ".7z", ".tar", ".gz") 
             or action_file_path contains "\Temp\" 
             or action_file_path contains "\AppData\Local\Temp\" 
        ), 
        1, 0 
  ) 

// Phase 3: Exfil heuristic without byte fields
// Treat multiple connections to typical exfil ports as a proxy for large outbound transfers
// Common exfil ports: 443 (HTTPS), 80 (HTTP), 22 (SSH/SFTP), 21 (FTP), 990 (FTPS), 8080, 8443 
| alter phase3_exfiltration = if( 
        event_type = ENUM.NETWORK 
        and action_remote_ip != null 
        and (action_remote_port in (443, 80, 22, 21, 990, 8080, 8443) 
             or dst_action_external_port in (443, 80, 22, 21, 990, 8080, 8443)), 
        1, 0 
  ) 

// Phase 4: Encryption indicator (ransom note write/create) 
| alter phase4_encryption_note = if( 
        event_type = ENUM.FILE 
        and event_sub_type in (ENUM.FILE_WRITE, ENUM.FILE_CREATE_NEW) 
        and action_file_name = "_README_Yurei.txt", 
        1, 0 
  ) 

// Aggregate by host and actor 
| comp 
    sum(phase1_sensitive_access) as sensitive_file_count, 
    sum(phase2_staging) as staging_event_count, 
    sum(phase3_exfiltration) as exfiltration_event_count, 
    sum(phase4_encryption_note) as encryption_indicator_count, 
    count_distinct(if(event_type = ENUM.NETWORK and (action_remote_port in (443,80,22,21,990,8080,8443) 
                                                     or dst_action_external_port in (443,80,22,21,990,8080,8443)), 
                      action_remote_ip, null)) as distinct_exfil_dests 
  by agent_hostname, actor_process_image_name, actor_effective_username 

// Correlate: all phases present with minimum thresholds 
| filter sensitive_file_count >= 10 
  and staging_event_count >= 1 
  and (exfiltration_event_count >= 5 or distinct_exfil_dests >= 3)  // tighten to reduce noise 
  and encryption_indicator_count >= 1 

// Enrichment 
| alter alert_severity = "CRITICAL", 
        alert_name = "Double-Extortion Ransomware Detected (Exfiltration + Encryption)", 
        confidence = "VERY HIGH", 
        recommended_action = "CRITICAL INCIDENT: Isolate host immediately, block outbound traffic, engage IR team, notify legal/compliance" 

| fields agent_hostname, 
         actor_process_image_name, 
         actor_effective_username, 
         sensitive_file_count, 
         staging_event_count, 
         distinct_exfil_dests, 
         exfiltration_event_count, 
         alert_severity, 
         recommended_action 
| sort desc distinct_exfil_dests
```

Note: If byte/volume fields (e.g., bytes_out) are available in your telemetry, replace the Phase 3 heuristic with a direct volume threshold (>50 MB) aggregated per host and destination.

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component       |
|--------------|------------|--------------------|-----------------------------|
| Cortex       | xdr_data   | File               | File Read / File Write      |
| Cortex       | xdr_data   | Network            | Network Connection          |

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
1. Isolate the host and block outbound traffic to suspected destinations.
2. Triage files accessed/staged; identify data sensitivity and potential exposure.
3. Acquire volatile data and preserve relevant artifacts (archives, temp folders).
4. Validate backups; plan recovery and notify legal/compliance per policy.
5. Hunt for pre-encryption indicators (VSS deletion, event log wipes) and lateral movement.
6. Engage the IR team and initiate the data breach response process.

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
| 1.0     | 2025-10-14 | Initial Correlation     | Double-extortion (exfiltration then encryption) rule    |
