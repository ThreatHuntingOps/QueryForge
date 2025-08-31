# Detection: CORNFLAKE.V3 In-memory CMD Execution via cmd.exe /d /s /c from node.exe

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-CMD-InMemory-NodeParent
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium-Low

---

## Hunt Analytics
This hunt detects in-memory CMD execution initiated by the CORNFLAKE.V3 Node.js agent:

- `node.exe` spawns `cmd.exe` with switches `/d /s /c` and an inline command payload ("type 3: CMD").
- Frequently followed by an HTTP POST to `/init1234` carrying the captured command output in the next beacon.
- Ties process lineage to a staged `node.exe` typically located under `%APPDATA%\\node-v22.11.0-win-x64\\` to reduce false positives.

This complements the `/init1234` IOC and EXE/DLL/JS delivery hunts by surfacing command execution orchestrated via the C2.

---

## ATT&CK Mapping

| Tactic              | Technique | Subtechnique | Technique Name                                         |
|---------------------|----------:|--------------|--------------------------------------------------------|
| TA0002 - Execution  |  T1059.003| 003          | Command and Scripting Interpreter: Windows Command Shell |

---

## Hunt Query Logic
Flags `cmd.exe` processes using the characteristic `/d /s /c` inline pattern when spawned by or causally linked to `node.exe`.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: cmd.exe spawned by node.exe with inline command (LastCmd behavior)
// Description: Detects node.exe spawning cmd.exe with "/d /s /c" and inline payload, consistent with type 3 (CMD). Often followed by a POST /init1234 carrying output.
// MITRE ATT&CK TTP ID: T1059.003

#event_simpleName=ProcessRollup2
| event_platform = Win
| FileName = "cmd.exe"
| CommandLine = "* /d *"
| CommandLine = "* /s *"
| CommandLine = "* /c *"
| (ParentBaseFileName = "node.exe" OR ProcessName = "node.exe")
| table([@timestamp, EventTimestamp, ComputerName, UserName, 
         FileName, FilePath, CommandLine, 
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
- **Required Permissions:** Standard user privileges are sufficient to run `cmd.exe` under user context.
- **Required Artifacts:** Process creation telemetry with full command lines and causal lineage.

---

## Considerations
- Correlate with nearby network events to `/init1234` to verify exfil of command output.
- Consider time-window grouping to bundle multiple CMD invocations originating from the same Node lineage.

---

## False Positives
- Admin scripts may use `/d /s /c`, but lineage to `%APPDATA%` Node agent and presence of `/init1234` traffic are strong discriminators.

---

## Recommended Response Actions
1) Investigate lineage and command payload:
   - Review full `cmd.exe` command line and the spawning `node.exe` path.
2) Contain:
   - Isolate host if malicious; block further execution of `node.exe` from user profiles.
3) Eradicate:
   - Remove `%APPDATA%\\node-v22.11.0-win-x64\\` payloads; clear scheduled tasks or Run keys if present.

---

## References
- MITRE ATT&CK: T1059.003 - Windows Command Shell https://attack.mitre.org/techniques/T1059/003/

---

## Version History

| Version | Date       | Impact              | Notes                                                           |
|---------|------------|---------------------|-----------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | In-memory CMD via /d /s /c spawned by node.exe (CORNFLAKE.V3).  |
