# Detection: CORNFLAKE.V3 C2 Transaction Patterns (/init1234, XOR payloads, and spawn of delivered EXE/DLL/JS/CMD)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-C2-Init1234-IOC
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low-Medium (due to unique URI + node.exe lineage)

---

## Hunt Analytics
This hunt targets CORNFLAKE.V3 C2 workflow after initial beacon connectivity:

- Initial HTTP POST to `/init1234` carries XOR-encrypted system information and the previous command output.
- Short C2 control responses observed include `ooff` (exit) and `atst` (establish persistence).
- Payload delivery and execution via `child_process.spawn()` from `node.exe`:
  - EXE: written into `%APPDATA%<8char><8char>.exe`, then executed.
  - DLL: written into `%APPDATA%<8char><8char>.dll`, executed via `rundll32.exe`.
  - JS: executed in-memory via `node.exe -e ""` (no disk write).
  - CMD: executed in-memory via `cmd.exe /d /s /c ""`; output cached for the next `/init1234` POST.
  - Other payloads: written into `%APPDATA%<8char><8char>.log`.

Combining network IOCs with process lineage anchored to `%APPDATA%\\node-v22.11.0-win-x64\\node.exe` yields high-confidence detections and helps distinguish malicious activity from benign admin scripts.

---

## ATT&CK Mapping

| Tactic                        | Technique  | Subtechnique | Technique Name        |
|------------------------------|------------|--------------|-----------------------|
| TA0011 - Command and Control | T1071.001  | 001          | Web Protocols         |
| TA0011 - Command and Control | T1105      |              | Ingress Tool Transfer |

---

## Hunt Query Logic (Query 1)
Detects HTTP POST requests to the URI path `/init1234` when the process or causal lineage includes a staged `node.exe` under `%APPDATA%`. This IOC combined with lineage is a strong indicator of CORNFLAKE.V3 initialization transactions carrying XORed telemetry and task outputs.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Node.exe-origin POST to /init1234 (CORNFLAKE.V3 initialization)
// Description: Detects HTTP POST requests to a path "/init1234" associated with CORNFLAKE.V3, especially when the lineage includes %APPDATA%\node-v22.11.0-win-x64\node.exe.
// MITRE ATT&CK TTP ID: T1071.001
// MITRE ATT&CK TTP ID: T1105

#event_simpleName=NetworkConnectHTTP
| event_platform = Win
| HttpMethod = "POST"
| HttpRequestURI = "*/init1234*"
| (FileName = "node.exe" OR ProcessName = "node.exe" OR ParentProcessName = "node.exe")
| (FilePath = "*\\AppData\\Roaming\\node-v22.11.0-win-x64*" 
   OR ProcessFilePath = "*\\AppData\\Roaming\\node-v22.11.0-win-x64*" 
   OR ParentProcessFilePath = "*\\AppData\\Roaming\\node-v22.11.0-win-x64*")
| table([@timestamp, EventTimestamp, ComputerName, UserName, HttpMethod, HttpRequestURI, HttpPostData,
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
- **Required Permissions:** Standard user is sufficient to issue HTTP requests from user-profile `node.exe`.
- **Required Artifacts:** Network telemetry with HTTP method/URI and process attribution; lineage fields to anchor detections to `%APPDATA%` Node path.

---

## Considerations
- Validate whether HTTP body (`http_data`) contains repeating XOR-like entropy or structured fields aligning with prior command outputs.
- Correlate with C2 control strings (e.g., `ooff`, `atst`) in adjacent responses if available in telemetry.
- Pair with process-based hunts for spawned EXE/DLL/JS/CMD to confirm payload delivery and execution.

---

## False Positives
- Very low given the specific URI and lineage. Investigate any match thoroughly before suppression.

---

## Recommended Response Actions
1) Contain:
   - Isolate implicated hosts; block `/init1234` traffic patterns and related C2 infrastructure.
2) Investigate:
   - Extract adjacent HTTP transactions, bodies, and headers; review task outputs in subsequent beacons.
3) Eradicate:
   - Remove `%APPDATA%\\node-v22.11.0-win-x64\\` artifacts; neutralize persistence created after `atst` responses.
4) Monitor:
   - Add rules for `/init1234` paths and node-in-user-profile HTTP beacons; look for payload spawn patterns.

---

## References
- MITRE ATT&CK: T1071.001 - Web Protocols https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK: T1105 - Ingress Tool Transfer https://attack.mitre.org/techniques/T1105/

---

## Version History

| Version | Date       | Impact              | Notes                                                          |
|---------|------------|---------------------|----------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | IOC: POST to /init1234 from node.exe lineage under %APPDATA%.  |
