# Detection: CORNFLAKE.V3 Persistence via HKCU Run "ChromeUpdater" pointing to node.exe and hidden script/file

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-Persistence-Run-ChromeUpdater
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium-Low (specific value name + Node path indicators)

---

## Hunt Analytics
Detects the CORNFLAKE.V3 persistence mechanism implemented by the `atst` function:

- Creation or modification of `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ChromeUpdater` to launch `node.exe` on user logon.
- The `ChromeUpdater` value points to the staged Node runtime under `%APPDATA%\\node-v22.11.0-win-x64\\node.exe` with either:
  - Inline script using `-e ""` whose content was harvested from the live Node process and may be written to an adjacent `.log` file, or
  - A file path argument to a `.js`/`.log` payload inside the Node installation directory.
- Preceding use of `wmic.exe` to query the command line of the running `node.exe` process (e.g., `wmic process where processid=<pid> get commandline`) to extract the inline `-e` payload.

Use with earlier hunts (initial access, staging, C2, recon) for multi-signal correlation.

---

## ATT&CK Mapping

| Tactic                 | Technique  | Subtechnique | Technique Name                          |
|-----------------------|------------|--------------|-----------------------------------------|
| TA0003 - Persistence  | T1547.001  | 001          | Registry Run Keys/Startup Folder        |

---

## Hunt Query Logic
Detects creation/modification of the `ChromeUpdater` Run key value whose data launches `%APPDATA%` Node with either inline `-e` or a `.js/.log` payload path under the Node directory.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex Query Language)
**Platform:** Polo Alto Networks Cortex XDR and XSIAM

```xql
// Title: Persistence — HKCU Run ChromeUpdater launching node.exe
// Description: Detects creation or modification of HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ChromeUpdater whose value data launches %APPDATA%\node-v22.11.0-win-x64\node.exe with -e "" or a file path (e.g., .js/.log) in the Node install directory.
// MITRE ATT&CK TTP ID: T1547.001

config case_sensitive = false   
| dataset = xdr_data   
| filter agent_os_type = ENUM.AGENT_OS_WINDOWS   
  and event_type in (ENUM.REGISTRY, ENUM.FILE) // some tenants log Run key changes as REGISTRY, some as FILE/REGISTRY hybrid   
  and action_registry_key_name contains "\Software\Microsoft\Windows\CurrentVersion\Run"   
  and (action_registry_value_name  = "ChromeUpdater" or action_registry_value_name contains "ChromeUpdater")   
  and (   
    action_registry_value_name contains "\AppData\Roaming\node-v22.11.0-win-x64\node.exe"   
    or action_registry_value_name contains "\AppData\Roaming\node-"   
  )   
  // Expect either inline -e or a file argument (.js/.log)   
  and (   
    action_registry_value_name contains " -e "   
    or action_registry_value_name ~= "\\AppData\\Roaming\\node-v[0-9.\-]+\\[A-Za-z0-9_\-]+\.[jl]og"   
    or action_registry_value_name ~= "\\AppData\\Roaming\\node-v[0-9.\-]+\\[A-Za-z0-9_\-]+\.js"   
  )   
| fields _time, agent_hostname, actor_effective_username, event_type, action_registry_value_name ,   
  actor_process_image_name, actor_process_image_path, actor_process_command_line,   
  causality_actor_process_image_name, causality_actor_process_image_path, causality_actor_process_command_line,   
  event_id, agent_id, _product   
| sort desc _time    
```

Note: Regex escaping may need adjustment per environment; the intent is to match value data invoking `%APPDATA%\\node-v...` with either `-e` or `.js/.log` payloads.

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component        |
|--------------|------------|--------------------|------------------------------|
| Cortex XSIAM | xdr_data   | Registry           | Registry Key/Value Modification |
| Cortex XSIAM | xdr_data   | Process            | Process Creation             |

---

## Execution Requirements
- **Required Permissions:** Standard user level sufficient for HKCU Run key creation/modification.
- **Required Artifacts:** Registry modification telemetry for HKCU Run; optional process telemetry to correlate `wmic.exe` and `node.exe` activity.

---

## Considerations
- Look for preceding `wmic` usage querying the running Node process command line to harvest the inline `-e` payload.
- Correlate with Node self-respawn, C2 `/init1234` transactions, and recon bundles for full context.
- Monitor for subsequent logon events launching Node via the Run key.

---

## False Positives
- Some benign updaters may use HKCU Run with names like ChromeUpdater; however, pointing to `%APPDATA%` Node with `-e` or `.js/.log` payloads is atypical. Validate publisher and parent process lineage.

---

## Recommended Response Actions
1) Confirm persistence:
   - Capture the Run key value data; verify path and parameters.
2) Contain:
   - Remove/disable the Run key; isolate the endpoint if active beacons present.
3) Eradicate:
   - Delete `%APPDATA%\\node-v22.11.0-win-x64\\` artifacts and any referenced `.js/.log` files; review other persistence locations.
4) Monitor:
   - Add rules for future creation of suspicious Run values pointing to user-profile Node.

---

## References
- MITRE ATT&CK: T1547.001 - Registry Run Keys/Startup Folder https://attack.mitre.org/techniques/T1547/001/

---

## Version History

| Version | Date       | Impact              | Notes                                                                                |
|---------|------------|---------------------|--------------------------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | HKCU Run ChromeUpdater persistence launching `%APPDATA%` Node with `-e` or file arg. |
