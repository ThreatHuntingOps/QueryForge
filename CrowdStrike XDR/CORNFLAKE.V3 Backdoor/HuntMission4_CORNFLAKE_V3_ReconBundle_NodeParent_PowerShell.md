# Detection: CORNFLAKE.V3 Recon Bundle from node.exe via PowerShell execSync

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-ReconBundle-NodeParent-PSH
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics
This hunt detects a characteristic reconnaissance bundle executed via PowerShell that is spawned by a staged Node.js binary associated with CORNFLAKE.V3. The activity typically originates from `%APPDATA%\\node-v22.11.0-win-x64\\node.exe` invoking PowerShell (often via `execSync`) to run a rapid sequence of discovery commands:

- `chcp 65001` to set UTF-8 code page
- privilege/runas echo lines (e.g., `Runas: Admin`, `Runas: User`, `Runas: System`)
- `systeminfo`
- `tasklist /svc`
- PowerShell cmdlets: `Get-Service | Select-Object ...`, `Get-PSDrive -PSProvider FileSystem ...`
- `arp -a`

This pattern commonly appears shortly after Node self-respawn and initial staging, and helps confirm post-compromise discovery driven by the CORNFLAKE.V3 payload.

---

## ATT&CK Mapping

| Tactic                      | Technique  | Subtechnique | Technique Name                               |
|----------------------------|------------|--------------|----------------------------------------------|
| TA0002 - Execution         | T1059.001  |              | Command and Scripting Interpreter: PowerShell |
| TA0007 - Discovery         | T1082      |              | System Information Discovery                  |
| TA0007 - Discovery         | T1016      |              | System Network Configuration Discovery        |
| TA0007 - Discovery         | T1057      |              | Process Discovery                             |
| TA0007 - Discovery         | T1033      |              | Account Discovery                             |

---

## Hunt Query Logic
Flags PowerShell (or PowerShell Core) processes whose command lines contain any of the recon-bundle indicators and whose parent/causal lineage includes `%APPDATA%\\node-v22.11.0-win-x64\\node.exe`.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Reconnaissance commands invoked from PowerShell spawned by node.exe
// Description: Flags PowerShell executing a characteristic bundle: chcp 65001, Runas echo, systeminfo, tasklist /svc, Get-Service, Get-PSDrive, and arp -a, with parent lineage including %APPDATA%\node-v22.11.0-win-x64\node.exe.
// MITRE ATT&CK TTP ID: T1059.001
// MITRE ATT&CK TTP ID: T1082
// MITRE ATT&CK TTP ID: T1016
// MITRE ATT&CK TTP ID: T1057
// MITRE ATT&CK TTP ID: T1033

#event_simpleName=ProcessRollup2
| event_platform = Win
| (FileName = "powershell.exe" OR FileName = "pwsh.exe")
| (
     CommandLine = "*chcp 65001*"
  OR CommandLine = "*systeminfo*"
  OR CommandLine = "*tasklist /svc*"
  OR (CommandLine = "*Get-Service*" AND CommandLine = "*Select-Object*")
  OR (CommandLine = "*Get-PSDrive*" AND CommandLine = "*FileSystem*")
  OR CommandLine = "*arp -a*"
  OR CommandLine = "*Runas: Admin*"
  OR CommandLine = "*Runas: User*"
  OR CommandLine = "*Runas: System*"
  )
| (ProcessFilePath = "*\\AppData\\Roaming\\node-v22.11.0-win-x64\\node.exe*" 
   OR ParentProcessFilePath = "*\\AppData\\Roaming\\node-v22.11.0-win-x64\\node.exe*")
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine,
         ProcessName, ProcessFilePath, ProcessCommandLine,
         ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine,
         CausalityActorProcessCommandLine, CausalityActorPrimaryUsername,
         EventID, AgentId, Product])
| sort(EventTimestamp)
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user capable of running PowerShell; elevation not strictly required for discovery.
- **Required Artifacts:** Process creation telemetry with full command line and causal lineage fields.

---

## Considerations
- Recon commands in rapid succession from a Node parent under `%APPDATA%` are strong indicators of post-compromise automation.
- Pair this detection with the Node self-respawn and initial delivery hunts for correlated triage.
- Consider time-window grouping (e.g., alerts for multiple recon hits within 1–2 minutes for the same host/user) to reduce noise and show campaign context.

---

## False Positives
- Admin or IT scripts may perform similar discovery, but the lineage to `%APPDATA%\\node-v22.11.0-win-x64\\node.exe` is atypical for legitimate activity.

---

## Recommended Response Actions
1) Investigate lineage:
   - Validate the parent `node.exe` path and any preceding staging events (download/extract under `%APPDATA%`).
2) Scope discovery:
   - Identify the full set of commands executed and any outbound connections following discovery.
3) Contain and eradicate:
   - Isolate endpoint; remove `%APPDATA%\\node-v22.11.0-win-x64\\` artifacts; block `node.exe` execution from user profiles.
4) Fleet-wide hunt:
   - Search for similar PowerShell recon bundles with Node parent across endpoints.

---

## References
- MITRE ATT&CK: T1059.001 - PowerShell https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK: T1082 - System Information Discovery https://attack.mitre.org/techniques/T1082/
- MITRE ATT&CK: T1016 - System Network Configuration Discovery https://attack.mitre.org/techniques/T1016/
- MITRE ATT&CK: T1057 - Process Discovery https://attack.mitre.org/techniques/T1057/
- MITRE ATT&CK: T1033 - Account Discovery https://attack.mitre.org/techniques/T1033/

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | Recon bundle via PowerShell spawned by node.exe from %APPDATA%.       |
