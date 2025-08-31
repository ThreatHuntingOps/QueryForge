# Detection: Node.exe Persistence Launches on User Logon (ChromeUpdater execution)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-Node-RunKey-Logon
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium (reduced by AppData path + params)

---

## Hunt Analytics
Detects executions of `node.exe` from the staged Node runtime in the user profile shortly after user logon, consistent with CORNFLAKE.V3 persistence via HKCU Run `ChromeUpdater`:

- `node.exe` launched from `%APPDATA%\\node-vXX.X.X-win-x64\\`.
- Command line includes either inline execution (`-e "..."`) or a file argument pointing to a `.js` or cached `.log` payload within the Node install directory.
- These launches typically follow prior steps: WMIC extraction of inline `-e` content, `.log` payload caching, and Run key creation.

---

## ATT&CK Mapping

| Tactic                 | Technique | Subtechnique | Technique Name                          |
|-----------------------|-----------|--------------|-----------------------------------------|
| TA0003 - Persistence  | T1547.001 | 001          | Registry Run Keys/Startup Folder        |
| TA0002 - Execution    | T1059     |              | Command and Scripting Interpreter       |

---

## Hunt Query Logic
Surfaces process creation events for `node.exe` from `%APPDATA%` Node directories with inline `-e` or file-based script parameters indicative of ChromeUpdater persistence firing on user logon.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: Node.exe launched at logon via HKCU Run ChromeUpdater
// Description: Detects node.exe executions shortly after user logon where the causality chain references HKCU Run keys or where the command line matches the ChromeUpdater value.
// MITRE ATT&CK TTP ID: T1547.001
// MITRE ATT&CK TTP ID: T1059

#event_simpleName=ProcessRollup2
| event_platform = Win
| FileName = "node.exe"
| FilePath = "\\AppData\\Roaming\\node-v"
| (
    CommandLine = " -e "
    or CommandLine = ".js"
    or CommandLine = ".log"
  )
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ProcessName, ProcessFilePath, ProcessCommandLine, ParentProcessName, ParentProcessFilePath, CausalityActorProcessCommandLine, CausalityActorPrimaryUsername, EventID, AgentId, Product])
| sort(EventTimestamp)
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user-level persistence via HKCU Run.
- **Required Artifacts:** Process creation telemetry with full command line and causal lineage; optional registry telemetry for Run key value.

---

## Considerations and Tuning
- Registry telemetry: Field names for registry value data can vary by tenant. If your dataset uses different fields (e.g., `registry_value_data_str`), adjust accordingly.
- Node path variations: Actors may change Node version. Loosen the path match to `\\AppData\\Roaming\\node-v` while keeping the AppData constraint to avoid FPs from legitimate Program Files installs.
- File argument types: Included `.js` and `.log`. If other extensions are seen for persistence script content, add them.
- WMIC replacement: On newer systems, WMIC may not exist; actors might use PowerShell WMI/CIM (`Get-WmiObject`, `Get-CimInstance`). Consider an alternate hunt for `Win32_Process` queries where `Name = 'node.exe'` selecting `CommandLine`.
- Optional logon correlation: If logon events are available, correlate process start within a short window (e.g., 0–120 seconds) after user logon.

---

## False Positives
- Developer environments occasionally run Node at logon, but `%APPDATA%` install path combined with `-e`/script file arguments is uncommon. Validate lineage and user context.

---

## Recommended Response Actions
1) Validate persistence:
   - Compare the `node.exe` command line against the `HKCU\\...\\Run\\ChromeUpdater` value data.
2) Contain:
   - Remove the Run key; isolate the endpoint if active C2 is present.
3) Eradicate:
   - Delete `%APPDATA%\\node-v*win-x64\\` artifacts and any referenced payload files.
4) Monitor:
   - Add detection for future `node.exe` launches from user-profile paths at logon.

---

## References
- MITRE ATT&CK: T1547.001 - Registry Run Keys/Startup Folder https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK: T1059 - Command and Scripting Interpreter https://attack.mitre.org/techniques/T1059/

---

## Version History

| Version | Date       | Impact              | Notes                                                                 |
|---------|------------|---------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | Node.exe persistence launches from HKCU Run ChromeUpdater at logon.   |
