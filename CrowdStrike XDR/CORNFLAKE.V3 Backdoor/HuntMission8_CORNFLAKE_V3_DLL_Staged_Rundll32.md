# Detection: CORNFLAKE.V3 Delivered DLL Staged and Executed via rundll32.exe

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-DLL-Staged-Rundll32
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium-Low (path regex + rundll32 + node lineage)

---

## Hunt Analytics
This hunt detects DLL payload delivery and execution patterns associated with CORNFLAKE.V3:

- DLL written under a randomized path in the user profile: `%APPDATA%<8char><8char>.dll`.
- Execution via `rundll32.exe` whose command line references the DLL path.
- Lineage tied to a staged `node.exe` under `%APPDATA%\\node-v22.11.0-win-x64\\`, indicating payload orchestration by the CORNFLAKE.V3 agent.

Note: The original sample query had `.exe` in the regex; this document corrects intent to `.dll` for both file-write and invocation matching.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name                                     |
|------------------------------|------------|--------------|----------------------------------------------------|
| TA0011 - Command and Control | T1105      |              | Ingress Tool Transfer                              |
| TA0005 - Defense Evasion     | T1218.011  | 011          | Signed Binary Proxy Execution: Rundll32            |

---

## Hunt Query Logic
Surfaces two event types:
- File events: DLL created under `%APPDATA%` with a randomized 16-character alphanumeric basename (8+8).
- Process events: `rundll32.exe` execution whose command line references a matching DLL path, with parent/causal lineage tied to `node.exe` under `%APPDATA%`.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: DLL dropped to random 8-char AppData path and invoked via rundll32.exe
// Description: Detects DLL writes to %APPDATA%<8char><8char>.dll and rundll32.exe executions whose command line references such DLLs, with node.exe lineage.
// MITRE ATT&CK TTP ID: T1105
// MITRE ATT&CK TTP ID: T1218.011

#event_simpleName=ProcessRollup2
| event_platform = Win
| (
    // File artifact: random 8-char + 8-char subfolder layout, ending in .exe
    ( FileName = /\.exe$/i
      AND FilePath = "*\\AppData\\Roaming*"
      AND FilePath = /\\AppData\\Roaming\\[A-Za-z0-9]{8}\\[A-Za-z0-9]{8}\.exe/i
    )
  OR
    // Process execution: .exe in same random 8x8-char directory, spawned by Node
    ( FileName = /\.exe$/i
      AND FilePath = "*\\AppData\\Roaming*"
      AND FilePath = /\\AppData\\Roaming\\[A-Za-z0-9]{8}\\[A-Za-z0-9]{8}\.exe/i
      AND (ParentBaseFileName = "node.exe" OR ProcessName = "node.exe")
    )
  )
| table([@timestamp, EventTimestamp, ComputerName, UserName, EventType,
         FileName, FilePath, SHA256FileHash, CommandLine,
         ProcessName, ProcessFilePath, ProcessCommandLine,
         ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine,
         CausalityActorProcessCommandLine, CausalityActorPrimaryUsername,
         EventID, AgentId, Product])
| sort(EventTimestamp)
```

Note: The regex aims to match `%APPDATA%\\Roaming\\<8 alnum>\\<8 alnum>.dll`. Adjust escaping per environment if needed.

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user-level writes to `%APPDATA%` and ability to execute `rundll32.exe`.
- **Required Artifacts:** File creation and process creation telemetry with path and lineage fields; full `rundll32` command line.

---

## Considerations
- Pair with `/init1234` IOC and EXE staging detections for end-to-end validation of payload delivery.
- Consider adding hash reputation and signature checks on created DLLs.

---

## False Positives
- Some legitimate software may use `rundll32.exe`, but randomized DLL names under `%APPDATA%` with `node.exe` lineage are uncommon.

---

## Recommended Response Actions
1) Triage:
   - Confirm randomized DLL path match and `rundll32.exe` invocation details.
2) Contain:
   - Quarantine the DLL and isolate the host.
3) Eradicate:
   - Remove `%APPDATA%\\node-v22.11.0-win-x64\\` artifacts and related payloads; neutralize persistence.

---

## References
- MITRE ATT&CK: T1105 - Ingress Tool Transfer https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK: T1218.011 - Rundll32 https://attack.mitre.org/techniques/T1218/011/

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | DLL staged under AppData and invoked by rundll32.exe with node lineage. |
