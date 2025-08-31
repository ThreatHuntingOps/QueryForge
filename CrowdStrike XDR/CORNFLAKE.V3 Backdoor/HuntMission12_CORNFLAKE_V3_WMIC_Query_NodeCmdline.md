# Detection: WMIC Command Line Enumeration of node.exe (Persistence Staging)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 70
- **Severity:** Medium

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-CORNFLAKEV3-WMIC-Query-NodeCmdline
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium (admin use possible)

---

## Hunt Analytics
This hunt detects the use of `wmic.exe` to retrieve the command line of a running `node.exe` process:

- In CORNFLAKE.V3, this is used prior to persistence to extract the inline `-e` script from the live Node process.
- The extracted script is then written to a `.log` (or used inline) and referenced by a HKCU Run key (e.g., `ChromeUpdater`).

Use together with the Run key persistence detection and Node staging hunts to build multi-signal confidence.

---

## ATT&CK Mapping

| Tactic            | Technique | Subtechnique | Technique Name               |
|-------------------|-----------|--------------|------------------------------|
| TA0007 - Discovery| T1057     |              | Process Discovery            |
| TA0007 - Discovery| T1082     |              | System Information Discovery |

---

## Hunt Query Logic
Flags `wmic` invocations that query processes and request the `commandline` field, specifically referencing `node`.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: WMIC command line enumeration of node.exe (persistence staging)
// Description: Flags wmic.exe usage to fetch the command line of a running node.exe process, as used to extract the -e script before writing it to a .log and setting Run key.
// MITRE ATT&CK TTP ID: T1057
// MITRE ATT&CK TTP ID: T1082

#event_simpleName=ProcessRollup2
| event_platform = Win
| FileName = "wmic.exe"
| CommandLine =* "process where"
| CommandLine =* "get commandline"
| CommandLine =* "node"
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, CommandLine, ProcessName, ProcessFilePath, ProcessCommandLine, ParentProcessName, ParentProcessFilePath, CausalityActorProcessCommandLine, CausalityActorPrimaryUsername, EventID, AgentId, Product])
| sort(EventTimestamp) 
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Standard user privileges sufficient to run WMIC.
- **Required Artifacts:** Process creation telemetry capturing full command lines.

---

## Considerations
- WMIC is deprecated on modern Windows but still present; admins may use it for troubleshooting. Use lineage and timing correlations to reduce false positives.
- Correlate with subsequent Run key creation/modification and `.log` writes under randomized `%APPDATA%` paths.

---

## False Positives
- Legitimate administrative or troubleshooting activity that queries process command lines.

---

## Recommended Response Actions
1) Triage:
   - Review the `wmic` command, user context, and preceding Node activity on the host.
2) Correlate:
   - Check for creation of `HKCU\\...\\Run\\ChromeUpdater` and `.log` artifacts in `%APPDATA%` shortly after.
3) Contain/Eradicate:
   - If malicious, remove persistence and staged Node assets.

---

## References
- MITRE ATT&CK: T1057 - Process Discovery https://attack.mitre.org/techniques/T1057/
- MITRE ATT&CK: T1082 - System Information Discovery https://attack.mitre.org/techniques/T1082/

---

## Version History

| Version | Date       | Impact              | Notes                                                     |
|---------|------------|---------------------|-----------------------------------------------------------|
| 1.0     | 2025-08-27 | Initial Detection   | WMIC query of node.exe command line before persistence.   |
