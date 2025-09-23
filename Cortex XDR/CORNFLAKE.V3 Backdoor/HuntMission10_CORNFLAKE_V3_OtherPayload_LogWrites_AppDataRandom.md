# Detection: CORNFLAKE.V3 “Other” Payloads Written as .log Under Random 8-Char AppData Path

## Severity or Impact of the Detected Behavior
- **Risk Score:** 75
- **Severity:** Medium-High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-OtherPayload-LogWrites
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium (path regex only; consider lineage joins)

---

## Hunt Analytics
This hunt detects creation of .log files used by CORNFLAKE.V3 to store “Other” payload types:

- Files written under randomized `%APPDATA%` paths with 16-character alphanumeric basenames split as `<8char><8char>.log`.
- On CORNFLAKE.V3, these .log artifacts may accompany or follow C2 transactions and payload handling.
- Precision increases when correlated with prior detections (Node staging under `%APPDATA%\\node-v22.11.0-win-x64\\`, `/init1234` POSTs, or node.exe lineage).

---

## ATT&CK Mapping

| Tactic                        | Technique | Subtechnique | Technique Name        |
|------------------------------|----------:|--------------|-----------------------|
| TA0011 - Command and Control |   T1105   |              | Ingress Tool Transfer |

---

## Hunt Query Logic
Surfaces file-creation events for `.log` files in randomized 8+8 alphanumeric directories under `%APPDATA%`.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Suspicious .log writes under random 8-char AppData path
// Description: Detects .log file creation in %APPDATA%<8char><8char>.log which may indicate “Other” payload type handling.
// MITRE ATT&CK TTP ID: T1105

config case_sensitive = false  
| dataset = xdr_data  
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS  
  and event_type = ENUM.FILE  
  and action_file_name contains ".log"  
  and action_file_path contains "\AppData\Roaming"  
  and action_file_path ~= "\\AppData\\Roaming\\[A-Za-z0-9]{8}\\[A-Za-z0-9]{8}\.log"  
| fields _time, agent_hostname, action_file_name, action_file_path, action_file_sha256,  
  actor_process_image_name, actor_process_image_path, causality_actor_process_image_path,  
  event_id, agent_id, _product  
| sort desc _time  
```

Note: Escaping may vary; intended match is `%APPDATA%\\Roaming\\<8 alnum>\\<8 alnum>.log`.

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | File               | File Creation         |

---

## Execution Requirements
- **Required Permissions:** Standard user-level write to `%APPDATA%`.
- **Required Artifacts:** File creation telemetry with full path and process attribution.

---

## Considerations
- Random directory pattern: The regex uses two 8-character alphanumeric segments. Adjust if you observe different lengths/character sets.
- Lineage constraints: For highest precision, combine with the earlier node.exe path constraint (`%APPDATA%\\node-v22.11.0-win-x64`) and/or preceding `/init1234` POSTs via a join (as shown in Query 5).
- HTTP body visibility: If your Cortex dataset lacks bodies, rely on path/method and process lineage; optionally correlate by timing.

---

## False Positives
- Possible if rare legitimate software writes .log files to randomized `%APPDATA%` subpaths. Build allowlists for known publishers or parent processes.

---

## Recommended Response Actions
1) Triage:
   - Review parent process and lineage for ties to `%APPDATA%\\node-v22.11.0-win-x64\\node.exe`.
2) Scope and correlate:
   - Check adjacent `/init1234` POSTs and EXE/DLL/CMD/JS activity.
3) Containment and eradication:
   - Isolate host as needed; remove malicious artifacts and block further writes to randomized `%APPDATA%` paths.

---

## References
- MITRE ATT&CK: T1105 - Ingress Tool Transfer https://attack.mitre.org/techniques/T1105/

---

## Version History

| Version | Date       | Impact              | Notes                                                      |
|---------|------------|---------------------|------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | Suspicious .log writes under random 8-char AppData paths.  |
