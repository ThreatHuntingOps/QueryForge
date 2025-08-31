# Detection: CORNFLAKE.V3 Post-Compromise Recon and Persistence Under node.exe Lineage

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-NodeLineage-Recon-Persistence
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics
This hunt detects classic reconnaissance and persistence utilities executed where the parent/causality lineage includes the staged Node.js runtime associated with CORNFLAKE.V3:

- Node.js payload resides at `%APPDATA%\\node-v22.11.0-win-x64\\node.exe`.
- Post-compromise behaviors include discovery commands (e.g., systeminfo, tasklist, arp), command interpreters (cmd/powershell), and registry modification utilities (reg.exe).
- Detection focuses on processes whose parent or causality lineage ties back to the Node.js executable in the user profile, indicating activity launched by the staged payload rather than normal administrative usage.

This complements the initial access query by surfacing follow-on discovery and persistence steps.

---

## ATT&CK Mapping

| Tactic                       | Technique  | Subtechnique | Technique Name                               |
|-----------------------------|------------|--------------|----------------------------------------------|
| TA0007 - Discovery          | T1033      |             | Account Discovery                            |
| TA0007 - Discovery          | T1082      |              | System Information Discovery                  |
| TA0007 - Discovery          | T1016      |              | System Network Configuration Discovery        |
| TA0007 - Discovery          | T1057      |              | Process Discovery                             |
| TA0002 - Execution          | T1059      |              | Command and Scripting Interpreter             |
| TA0003 - Persistence        | T1547.001  | 001          | Registry Run Keys/Startup Folder              |
| TA0005 - Defense Evasion    | T1112      |              | Modify Registry                               |

---

## Hunt Query Logic
Flags recon and persistence utilities when the process lineage includes `%APPDATA%\\node-v22.11.0-win-x64\\node.exe`:
- Target processes include: systeminfo.exe, tasklist.exe, arp.exe, chcp.com, wmic.exe, cmd.exe, powershell.exe, reg.exe.
- Lineage check leverages either `actor_process_image_path` (direct parent) or `causality_actor_process_image_path` (causal ancestor) to capture both immediate and multi-hop spawning from node.exe.

---

## Hunt Query Syntax

**Query Language:** XQL (Cortex XSIAM)

```xql
// Title: Reconnaissance and persistence spawned from node.exe lineage
// Description: Flags classic recon/persistence utilities executed where the parent/causality lineage includes %APPDATA%\node-v22.11.0-win-x64\node.exe.
// MITRE ATT&CK TTP ID: T1033, T1082, T1016, T1057, T1059, T1112, T1547.001

config case_sensitive = false 
| dataset = xdr_data 
| filter event_type = ENUM.PROCESS 
and event_sub_type = ENUM.PROCESS_START 
and agent_os_type = ENUM.AGENT_OS_WINDOWS 
and ( 
  action_process_image_name in ("systeminfo.exe","tasklist.exe","arp.exe","chcp.com","wmic.exe","cmd.exe","powershell.exe","reg.exe") 
) 
and ( 
  causality_actor_process_image_path contains "\AppData\Roaming\node-v22.11.0-win-x64\node.exe" 
  or actor_process_image_path contains "\AppData\Roaming\node-v22.11.0-win-x64\node.exe" 
) 
| fields _time, agent_hostname, actor_effective_username, 
  action_process_image_name, action_process_image_path, action_process_image_command_line, 
  actor_process_image_name, actor_process_image_path, actor_process_command_line, 
  causality_actor_process_image_name, causality_actor_process_image_path, causality_actor_process_command_line, 
  event_id, agent_id, _product 
| sort desc _time
```

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user sufficient; lineage originates from user-profile Node.js. Elevated rights may appear for registry or task modifications if attempted.
- **Required Artifacts:** Process creation telemetry with parent/causal lineage fields and full command-line arguments.

---

## Considerations
- Node.js under `%APPDATA%` is atypical and a strong indicator when coupled with recon utilities.
- Validate whether legitimate developer tooling is present; however, lineage to `%APPDATA%\\node-v22.11.0-win-x64\\node.exe` remains suspicious.
- Expand allowlists for known IT scripts if they are demonstrably benign but verify lineage carefully.

---

## False Positives
- Low on non-developer systems. On developer workstations, benign node.exe may exist but rarely under `%APPDATA%` or spawning classic recon tools.
- Administrative scripts might invoke these utilities, but lineage to `%APPDATA%` Node.js should be rare.

---

## Recommended Response Actions
1) Review causal chain:
   - Confirm node.exe path and preceding PowerShell staging events on the host.
2) Scope impact:
   - Enumerate all processes spawned under this lineage; capture artifacts, registry edits, and any scheduled tasks.
3) Containment:
   - Isolate endpoint; suspend or kill active processes under the suspicious node.exe lineage.
4) Eradication:
   - Remove `%APPDATA%\\node-v22.11.0-win-x64\\` payloads; block execution of node.exe from user profiles.
5) Hardening & Monitoring:
   - Add EDR detections for node.exe lineage spawning recon utilities; monitor for repeated attempts.

---

## References
- MITRE ATT&CK: T1033 - Account Discovery https://attack.mitre.org/techniques/T1033/
- MITRE ATT&CK: T1082 - System Information Discovery https://attack.mitre.org/techniques/T1082/
- MITRE ATT&CK: T1016 - System Network Configuration Discovery https://attack.mitre.org/techniques/T1016/
- MITRE ATT&CK: T1057 - Process Discovery https://attack.mitre.org/techniques/T1057/
- MITRE ATT&CK: T1059 - Command and Scripting Interpreter https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK: T1112 - Modify Registry https://attack.mitre.org/techniques/T1112/
- MITRE ATT&CK: T1547.001 - Registry Run Keys/Startup Folder https://attack.mitre.org/techniques/T1547/001/

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | Post-compromise recon/persistence spawned from node.exe lineage.      |
