# Suspicious LSASS Dumping Masquerading as dllhost.exe (ProcDump-like Flags)

## Severity or Impact of the Detected Behavior
- **Risk Score:** 90
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-LSASSDump-ProcDumpFlags-dllhostMasq
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Medium (lower with optional tuners)

---

## Hunt Analytics
This hunt detects suspected credential access where ProcDump-like flags are used to dump LSASS memory, but the process name is masqueraded as `dllhost.exe` (COM Surrogate), which does not accept such flags. It also optionally detects explicit ProcDump usage. The focus is on process starts with:
- Image name `dllhost.exe` using ProcDump-style options (`-accepteula`, `-ma`, optionally `-r`) targeting `lsass.exe`
- Explicit `procdump*.exe` usage against `lsass.exe`
- Command lines that clearly show ProcDump behavior via path/name plus flags, even if renamed

Dump destination paths are captured in the command line and can aid triage.

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                    |
|------------------------------|-------------|--------------|---------------------------------------------------|
| TA0006 - Credential Access   | T1003.001   | —            | OS Credential Dumping: LSASS Memory               |
| TA0005 - Defense Evasion     | T1036.003   | —            | Masquerading: Rename System Utilities             |

Notes:
- `dllhost.exe` is a COM Surrogate; seeing ProcDump flags under this name strongly suggests masquerading or proxy execution.
- Consider alerting on any process using ProcDump flags against LSASS outside of approved windows.

---

## Hunt Query Logic
The query identifies suspicious command lines by checking for:
- `dllhost.exe` with ProcDump-like options and `lsass.exe` target
- Known ProcDump binaries targeting `lsass.exe`
- Any process invoking "procdump" with `-ma` and `lsass.exe`

Optional tuners are provided to reduce noise by requiring `-r`/`-accepteula`, excluding known admin tool paths, or focusing on user-writable dump locations.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: LSASS Dump Attempt via ProcDump-like Flags (dllhost.exe masquerade)
// Description: Detects Windows process starts where dllhost.exe (or ProcDump) is invoked with flags typical of ProcDump to dump LSASS to a file.
// MITRE ATT&CK TTP ID: T1003.001 (OS Credential Dumping: LSASS Memory)
// MITRE ATT&CK TTP ID: T1036.003 (Masquerading: Rename System Utilities)

#event_simpleName=ProcessRollup2
// | event_platform = Win
| (
    (FileName = "dllhost.exe" AND CommandLine = "*-accepteula*" AND CommandLine = "*-ma*" AND CommandLine = "*lsass.exe*")
 OR
    ((FileName = "procdump.exe" OR FileName = "procdump64.exe" OR FileName = "procdump64a.exe") AND CommandLine = "*-ma*" AND CommandLine = "*lsass.exe*")
 OR
    (CommandLine = "*procdump*" AND CommandLine = "*-ma*" AND CommandLine = "*lsass.exe*")
  )
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, CausalityActorProcessCommandLine, CausalityActorPrimaryUsername, EventID, AgentId, Product])
| sort(EventTimestamp)
```

Optional tuners to reduce noise

Require presence of “-r” or “-accepteula” for tighter matching:

```xql
// | CommandLine = "*-r*"
// | CommandLine = "*-accepteula*"
```

Exclude known admin tooling paths (adjust to your environment):

```xql
// | FilePath != "*\\AdminTools\\*" AND FilePath != "*\\IT\\Tools\\Sysinternals\\*"
```

Focus on dump destination to common user-writable locations (last arg often dump path):

```xql
// | (CommandLine = "*\\AppData\\*" OR CommandLine = "*\\Users\\*" OR CommandLine = "*\\ProgramData\\*" OR CommandLine = "*\\Temp\\*")
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |

---

## Execution Requirements
- **Required Permissions:** Windows process creation telemetry with command-line arguments.
- **Required Artifacts:** Command-line strings, parent process lineage, and binary paths.

---

## Considerations
- Some EDR responders may legitimately use ProcDump during approved maintenance; create allowlists for known responder hosts, paths, or users.
- You can further enhance fidelity by correlating with file creation of dump files (e.g., Sysmon Event ID 11) or security event logs for LSASS access denials.

---

## False Positives
- Admin or IR activity using Sysinternals ProcDump. Context, signer, and source path are critical.

---

## Recommended Response Actions
1. Triage the command line, verify signer and file location, and confirm operator intent.
2. If unapproved, isolate the host and collect the suspected dump file path for secure handling.
3. Review parent process and user context; check for lateral movement or credential theft follow-on activity.
4. Ingest and scan the dump in a secure, offline analysis environment if enterprise policy allows.

---

## References
- MITRE ATT&CK: T1003.001 – OS Credential Dumping: LSASS Memory https://attack.mitre.org/techniques/T1003/001/
- MITRE ATT&CK: T1036.003 – Masquerading: Rename System Utilities https://attack.mitre.org/techniques/T1036/003/

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-22 | Initial Detection | Detects LSASS dump attempts via ProcDump-like flags with dllhost.exe masquerade and explicit ProcDump paths. |
