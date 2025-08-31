# Detection: CORNFLAKE.V3 Node Child-Process Self-Respawn and System Recon via PowerShell

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-NodeSelfRespawn-ReconPSH
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics
This hunt expands coverage for CORNFLAKE.V3 by detecting two key patterns:

- Node.js “self-respawn” startup logic: a parent `node.exe` spawns a child `node.exe` with an extra `1` argument and hidden/inline execution context; the parent exits shortly after. This commonly follows the initial staging where Node is deployed under `%APPDATA%` and invoked with `-e`.
- Post-respawn system reconnaissance via PowerShell executed from `node.exe` (e.g., using `execSync`): UTF-8 code page set (`chcp 65001`), privilege echo, `systeminfo`, `tasklist /svc`, `Get-Service`, `Get-PSDrive`, and `arp -a` in quick succession from a `node.exe` parent.

Use this in conjunction with the prior hunts for initial PowerShell delivery and Node staging to obtain layered visibility across execution and discovery phases.

---

## ATT&CK Mapping

| Tactic                        | Technique | Subtechnique | Technique Name                                  |
|------------------------------|-----------|--------------|-------------------------------------------------|
| TA0002 - Execution           | T1059     |              | Command and Scripting Interpreter               |
| TA0005 - Defense Evasion     | T1106     |              | Native API                                      |
| TA0003 - Persistence/Evasion | T1055     |              | Process Injection (related spawn behavior note) |

Note: T1055 is included per conceptual similarity to evasive spawn behavior; validate against observed tradecraft and adjust if necessary.

---

## Hunt Query Logic
Detects the Node self-respawn pattern where a parent `node.exe` spawns a child `node.exe` with an additional `1` argument, often alongside inline execution (`-e ""`), and specifically from the staging path under `%APPDATA%`.

---

## Hunt Query Syntax 

**Query Language:** XQL (Cortex XSIAM)

```xql
// Title: Node.exe self-respawn (child with extra “1” arg) and hidden window
// Description: Detects node.exe spawning another node.exe with an additional single-argument “1” and typical hidden/inline execution contexts, consistent with CORNFLAKE.V3 startup logic.
// MITRE ATT&CK TTP ID: T1059
// MITRE ATT&CK TTP ID: T1106
// MITRE ATT&CK TTP ID: T1055

config case_sensitive = false  
| dataset = xdr_data  
| filter event_type = ENUM.PROCESS  
  and event_sub_type = ENUM.PROCESS_START  
  and agent_os_type = ENUM.AGENT_OS_WINDOWS  
  and action_process_image_name = "node.exe"  
  and actor_process_image_name = "node.exe"  
  // command line often invokes -e "" initially; child adds " 1"  
  and (  
    action_process_image_command_line contains " -e "  
    or action_process_image_command_line contains " 1"  
    or action_process_image_command_line contains " 1 "  
  )  
  // Prefer the non-standard user-space Node path seen in staging  
  and action_process_image_path contains "\AppData\Roaming\node-v22.11.0-win-x64"  
| fields _time, agent_hostname, actor_effective_username,  
  actor_process_image_name, actor_process_image_path, actor_process_command_line,  
  action_process_image_name, action_process_image_path, action_process_image_command_line,  
  causality_actor_process_image_name, causality_actor_process_image_path, causality_actor_process_command_line,  
  event_id, agent_id, _product  
| sort desc _time
```

---

## Follow-on Hunt (Recommended): Recon Bundle from node.exe via PowerShell
While not included as a separate query here, consider an adjunct hunt for processes spawned by `node.exe` that execute a reconnaissance bundle in short succession:

- `chcp 65001`
- privilege echo (e.g., `whoami /groups` or `whoami /priv`)
- `systeminfo`
- `tasklist /svc`
- `powershell.exe` cmdlets: `Get-Service`, `Get-PSDrive`
- `arp -a`

Heuristics:
- Parent/causal lineage includes `%APPDATA%\\node-v22.11.0-win-x64\\node.exe`.
- Multiple recon commands within a small time window (e.g., 60–120 seconds) on the same host and user session.

---

## Data Sources

| Log Provider | Event Name | ATT&CK Data Source | ATT&CK Data Component |
|--------------|------------|--------------------|-----------------------|
| Cortex XSIAM | xdr_data   | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user sufficient for user-profile Node execution. Some recon commands or persistence attempts may require elevation.
- **Required Artifacts:** Process creation events with parent/causal fields and full command-line arguments; optionally process termination timing to see parent exit post-spawn.

---

## Considerations
- Node installed under `%APPDATA%` is atypical; pairing with `-e` inline code and the `1` self-respawn argument increases fidelity.
- Consider suppressing known-good developer node paths (e.g., Program Files) while retaining `%APPDATA%`-scoped detections.
- Time-correlate with prior hunts (initial Run dialog PowerShell and Node staging) for stronger signal and incident stitching.

---

## False Positives
- Low likelihood. Legitimate node.exe usually resides under Program Files and does not self-respawn with a solitary `1` argument nor spawn classic recon chains.

---

## Recommended Response Actions
1) Validate lineage:
   - Confirm `node.exe` path under `%APPDATA%` and self-respawn pattern (parent-child chain; parent exit).
2) Scope recon activity:
   - Identify subsequent commands executed from the child `node.exe` and their outputs/artifacts.
3) Contain and eradicate:
   - Isolate endpoint; quarantine `%APPDATA%\\node-v22.11.0-win-x64\\` tree; block `node.exe` execution from user profiles.
4) Hunt across fleet:
   - Search for the same node path and self-respawn signature on other endpoints.
5) Hardening:
   - Add detections for `node.exe -e` and `node.exe` child with ` 1` argument under user-profile locations.

---

## References
- MITRE ATT&CK: T1059 - Command and Scripting Interpreter https://attack.mitre.org/techniques/T1059/
- MITRE ATT&CK: T1106 - Native API https://attack.mitre.org/techniques/T1106/
- MITRE ATT&CK: T1055 - Process Injection https://attack.mitre.org/techniques/T1055/

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | Node self-respawn with `1` arg; follow-on recon via PowerShell.       |
