# Detection: Node Install Directory Writing a .log Payload Prior to ChromeUpdater Set

## Severity or Impact of the Detected Behavior
- **Risk Score:** 80
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-NodeDir-LogPayload-BeforeRunKey
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium (improves with correlation to Run key)

---

## Hunt Analytics
Detects creation/modification of `.log` files within the staged Node installation directory used by CORNFLAKE.V3 for persistence preparation:

- `.log` written under `%APPDATA%\\node-vXX.X.X-win-x64\\` to cache JavaScript content extracted from the running Node process (via WMIC command-line query).
- Typically followed by setting the HKCU Run `ChromeUpdater` value to launch `node.exe` with `-e` inline script or with a file path to the cached `.log`/`.js`.

Use this together with WMIC query detection and the ChromeUpdater Run-key detection to form a multi-signal chain.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                               |
|------------------------------|------------|--------------|----------------------------------------------|
| TA0011 - Command and Control | T1105      |              | Ingress Tool Transfer (malware staging content) |
| TA0003 - Persistence         | T1547.001  | 001          | Registry Run Keys/Startup Folder             |

---

## Hunt Query Logic
Surfaces file creation events for `.log` files inside `%APPDATA%\\node-v*win-x64\\`, indicating payload caching for persistence.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex XSIAM)

```xql
// Title: Write of .log in Node install directory (payload caching for persistence)
// Description: Detects creation/modification of a .log in %APPDATA%\node-vXX.X.X-win-x64\ used to store the JS content extracted from the running node process. Correlate with subsequent ChromeUpdater Run key set.
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1547.001

config case_sensitive = false  
| dataset = xdr_data  
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS  
  and event_type = ENUM.FILE  
  and action_file_name contains ".log"  
  and action_file_path contains "\AppData\Roaming\node-v"  
  and action_file_path contains "\node-v"  
  and action_file_path contains ".log"  
| fields _time, agent_hostname, action_file_name, action_file_path, action_file_sha256,  
  actor_process_image_name, actor_process_image_path, actor_process_command_line,  
  causality_actor_process_image_name, causality_actor_process_image_path, causality_actor_process_command_line,  
  event_id, agent_id, _product  
| sort desc _time  
```

Note: You may refine with a regex to match `node-v[0-9.\-]+-win-x64` or add lineage constraints to `%APPDATA%` Node path for higher precision.

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | File               | File Creation         |

---

## Execution Requirements
- **Required Permissions:** Standard user-level write to `%APPDATA%`.
- **Required Artifacts:** File creation telemetry with full paths and process attribution.

---

## Considerations
- Correlate with:
  - WMIC query of Node command line (to extract `-e` payload).
  - HKCU Run `ChromeUpdater` creation/modification pointing to Node or the `.log`/`.js` payload.
- Timing correlation within a short window strengthens confidence.

---

## False Positives
- Developer tools may emit `.log` files within Node directories; lineage from suspicious Node under `%APPDATA%` and correlation to Run key changes reduce benign hits.

---

## Recommended Response Actions
1) Triage:
   - Inspect the created `.log` path and the writing process lineage.
2) Correlate:
   - Check for subsequent HKCU Run `ChromeUpdater` persistence and `/init1234` network activity.
3) Contain/Eradicate:
   - Quarantine artifacts under `%APPDATA%\\node-v*win-x64\\` and remove persistence.

---

## References
- MITRE ATT&CK: T1105 - Ingress Tool Transfer https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK: T1547.001 - Registry Run Keys/Startup Folder https://attack.mitre.org/techniques/T1547/001/

---

## Version History

| Version | Date       | Impact              | Notes                                                                           |
|---------|------------|---------------------|---------------------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | .log payload caching within Node install dir prior to ChromeUpdater persistence. |
