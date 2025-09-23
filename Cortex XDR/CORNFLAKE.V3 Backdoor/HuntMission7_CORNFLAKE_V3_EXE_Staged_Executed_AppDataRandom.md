# Detection: CORNFLAKE.V3 Delivered EXE Staged to %APPDATA%<8char><8char>.exe and Executed

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-EXE-StagedAndExecuted-AppDataRandom
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium-Low (path regex + lineage)

---

## Hunt Analytics
This hunt detects delivery and execution of an EXE payload characteristic of CORNFLAKE.V3 C2 workflows:

- Payload written to a randomized path under the user profile: `%APPDATA%<8char><8char>.exe` (alphanumeric).
- Subsequent execution of that EXE, with lineage tied to a staged `node.exe` under `%APPDATA%\\node-v22.11.0-win-x64\\`.
- Combines file creation and process execution telemetry with regex path matching to surface high-fidelity events associated with payload delivery and launch.

Use together with the `/init1234` POST IOC and node lineage network hunts to confirm end-to-end C2 and payload stages.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                         |
|------------------------------|------------|--------------|----------------------------------------|
| TA0011 - Command and Control | T1105      |              | Ingress Tool Transfer                  |
| TA0002 - Execution           | T1059      |              | Command and Scripting Interpreter      |
| TA0002 - Execution           | T1204.002  | 002          | User Execution: Malicious File         |

---

## Hunt Query Logic
Surfaces two event types:
- File events: EXE created under `%APPDATA%` with a randomized 16-character alphanumeric basename (8+8).
- Process events: Execution of an EXE at a matching path where parent/causal lineage is `node.exe`, consistent with payload spawn from the CORNFLAKE.V3 agent.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Suspicious EXE write and execution under random 8-char AppData path
// Description: Detects creation and subsequent execution of EXEs under %APPDATA%[A-Za-z0-9]{8}[A-Za-z0-9]{8}.exe, with lineage tied to node.exe.
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1059
// MITRE ATT&CK TTP ID: T1204.002

config case_sensitive = false 
| dataset = xdr_data 
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS 
  and ( 
    ( 
      event_type = ENUM.FILE 
      and action_file_name contains ".exe" 
      and action_file_path contains "\AppData\Roaming" 
      and action_file_path ~= "\\AppData\\\\Roaming\\[A-Za-z0-9]{8}\\[A-Za-z0-9]{8}\.exe" 
    ) 
    or 
    ( 
      event_type = ENUM.PROCESS 
      and action_process_image_name contains ".exe" 
      and action_process_image_path contains "\AppData\Roaming" 
      and action_process_image_path ~= "\\AppData\\Roaming\\[A-Za-z0-9]{8}\\[A-Za-z0-9]{8}\.exe" 
      and ( 
        actor_process_image_name = "node.exe" 
        or causality_actor_process_image_name = "node.exe" 
      ) 
    ) 
  ) 
| fields _time, agent_hostname, event_type, action_file_name, action_file_path, action_file_sha256, 
  action_process_image_name, action_process_image_path, action_process_image_command_line, 
  actor_process_image_name, actor_process_image_path, actor_process_command_line, 
  causality_actor_process_image_name, causality_actor_process_image_path, causality_actor_process_command_line, 
  event_id, agent_id, _product 
| sort desc _time  
```

Note: Escaping in the regex may need adjustment depending on platform parsing nuances; the intent is to match `%APPDATA%\\Roaming\\<8 alnum>\\<8 alnum>.exe` paths.

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | File               | File Creation         |
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user-level writes under `%APPDATA%` and execution privileges.
- **Required Artifacts:** File creation and process creation telemetry with path and lineage fields.

---

## Considerations
- The `%APPDATA%` randomized EXE path is a strong signal; pair with preceding `/init1234` and Node lineage queries to elevate confidence.
- Consider adding hash reputation checks on `action_file_sha256` where available.

---

## False Positives
- Rare. Some legitimate installers or updaters may use randomized filenames in `%APPDATA%`, but lineage to `node.exe` and concurrent C2 IOCs should distinguish malicious activity.

---

## Recommended Response Actions
1) Triage and validate:
   - Confirm randomized path match and node.exe lineage.
2) Contain:
   - Quarantine the created EXE and isolate the host.
3) Eradicate and harden:
   - Remove payloads and block future execution from randomized `%APPDATA%` paths; investigate persistence mechanisms.

---

## References
- MITRE ATT&CK: T1105 - Ingress Tool Transfer https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK: T1059 - Command and Scripting Interpreter https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK: T1204.002 - User Execution: Malicious File https://attack.mitre.org/techniques/T1204/002/

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | EXE staged/executed in AppData randomized path with node.exe lineage. |
