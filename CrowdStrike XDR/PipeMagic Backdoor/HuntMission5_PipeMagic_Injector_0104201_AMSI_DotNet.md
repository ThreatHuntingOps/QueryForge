# Detection of PipeMagic Injector Using AMSI Patch and Pipe "\\.\pipe\0104201.%d"

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-PipeMagic-Injector-0104201-AMSI-DotNet
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium

---

## Hunt Analytics
This hunt targets the PipeMagic injector module that:
- Creates/uses a named pipe with the fixed prefix `\\.\pipe\0104201.` (suffix typically a PID)
- Loads and patches AMSI (amsi.dll) by modifying AmsiScanString/AmsiScanBuffer at runtime
- Loads the .NET runtime bootstrapper (mscoree.dll) to host a C# payload supporting CLR 4.0.30319 and 2.0.50727

Two high-signal detections are provided, designed to run independently with straightforward XQL filters and no unsupported constructs. Correlate by host and time proximity to identify likely injector activity.

Detected behaviors include:
- Process starts with command line referencing the `0104201.` pipe prefix
- Processes that load both `amsi.dll` and `mscoree.dll` in close proximity, indicative of AMSI bypass followed by .NET payload hosting

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                                      |
|------------------------------|-------------|--------------|---------------------------------------------------------------------|
| TA0005 - Defense Evasion     | T1562.001   | —            | Impair Defenses: Disable/Bypass Security Tools (AMSI patch)        |
| TA0002 - Execution           | T1106       | —            | Native API (named pipe usage, manual mapping)                       |
| TA0002 - Execution           | T1059.005   | —            | Command and Scripting Interpreter: Visual Basic (contextual)        |
| TA0005 - Defense Evasion     | T1055       | —            | Process Injection                                                   |

Notes:
- Many legitimate .NET apps load `amsi.dll` and `mscoree.dll`. The combination plus suspicious pipe evidence, path, or timing increases confidence.
- Because the injector reads the pipe once and then hosts the .NET payload, you may see a short-lived module load sequence. A 10-minute correlation window is reasonable; shrink to 5 minutes for stricter matching.

---

## Hunt Query Logic
Run the two queries separately, then correlate results using `agent_hostname` (and/or process GUIDs) and timestamps within ±10 minutes:
- Query A detects explicit references to the `0104201.` pipe prefix in process command lines.
- Query B surfaces processes that load both `amsi.dll` and `mscoree.dll` (high-signal pattern for AMSI bypass + .NET hosting).

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: PipeMagic Injector - 0104201 Pipe String in Command Line
// Description: Finds Windows process starts where the command line includes \\.\pipe\0104201.
// MITRE ATT&CK TTP ID: T1562.001 (Impair Defenses: Disable Security Tools)
// MITRE ATT&CK TTP ID: T1047/T1106 (Execution via native APIs)

#event_simpleName=ProcessRollup2
| event_platform = Win
| CommandLine = "*\\\\.\\pipe\\0104201.*"
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, SHA256FileHash, MD5FileHash, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, EventID, AgentId, Product])
| sort(EventTimestamp)
```

```fql
// Title: AMSI Patch + .NET Hosting Indicators (amsi.dll + mscoree.dll)
// Description: Finds processes that load both amsi.dll and mscoree.dll.
// MITRE ATT&CK TTP ID: T1562.001
// MITRE ATT&CK TTP ID: T1055

#event_simpleName=ProcessRollup2
// | event_platform = Win
| (FilePath = "*\\amsi.dll*" OR FilePath = "*\\mscoree.dll*")
| table([@timestamp, EventTimestamp, ComputerName, AgentId, FileName, FilePath, ModulePath, ModuleSHA256, ModuleMD5, EventID, Product])
| sort(EventTimestamp)
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Windows endpoint telemetry for process creation and module load events.
- **Required Artifacts:** Full command-line strings; module load paths/hashes; process lineage or GUIDs for correlation.

---

## Considerations
- Correlate Query A and Query B by `agent_hostname` and `causality_actor_process_guid` (if available) within ±10 minutes.
- Prioritize processes in suspicious paths or unsigned images.
- Enrich with network telemetry for 127.0.0.1:8082 loopback activity or external C2 if present.
- Look for follow-on behaviors: additional named pipes, process hollowing, or CLR assembly reflectors.

---

## False Positives
- Legitimate .NET applications commonly load `mscoree.dll` and may also load `amsi.dll`; context and timing with pipe evidence are key to reduce FPs.
- Developer tools and security scanners can also trigger module loads; verify signer and command-line intent.

---

## Recommended Response Actions
1. Investigate processes referencing `\\.\pipe\0104201.` including parent/child lineage.
2. Review module loads; confirm whether AMSI exports were patched (memory inspection if feasible).
3. Acquire volatile artifacts (open handles, module lists, memory) to validate injection and CLR hosting.
4. Contain affected endpoints if injector behavior is confirmed.
5. Expand hunts for related pipes and .NET assemblies; add allowlists for known-good apps.

---

## References
- MITRE ATT&CK: T1562.001 – Impair Defenses https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK: T1106 – Native API https://attack.mitre.org/techniques/T1106/
- MITRE ATT&CK: T1055 – Process Injection https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK: T1059.005 – Command and Scripting Interpreter: Visual Basic https://attack.mitre.org/techniques/T1059/005/

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-22 | Initial Detection | Hunt for PipeMagic injector using 0104201 pipe prefix with AMSI patch + .NET hosting indicators. |
