# Detection of PipeMagic 2025 MSBuild Execution of Microsoft Help Index Files

## Severity or Impact of the Detected Behavior
- **Risk Score:** 85
- **Severity:** High

## Hunt Analytics Metadata
- **ID:** HuntQuery-Windows-PipeMagic-2025-MSBuild-MSHI
- **Operating Systems:** WindowsEndpoint, WindowsServer
- **False Positive Rate:** Low–Medium

---

## Hunt Analytics
This hunt detects the 2025 PipeMagic variant that abuses MSBuild to execute Microsoft Help Index files (.mshi) as loaders. The technique uses legitimate, trusted Windows tools to run obfuscated C# that decrypts and executes shellcode via RC4. Executing .mshi files with MSBuild is highly atypical - .mshi files are intended for Microsoft help documentation, not execution - making this behavior a strong indicator of malicious activity and LOLBin abuse.

Detected behaviors include:
- MSBuild executions where the command line references .mshi files, especially from system help directories (e.g., `c:\windows\help\`) or known filenames like `metafile.mshi`
- `cmd.exe` launching `msbuild.exe` targeting `.mshi` files, often with `/k` or .NET Framework paths in the command line
- Optional network correlation with known PipeMagic C2 on Azure

---

## ATT&CK Mapping

| Tactic                        | Technique   | Subtechnique | Technique Name                                              |
|------------------------------|-------------|--------------|-------------------------------------------------------------|
| TA0005 - Defense Evasion     | T1127.001   | —            | Trusted Developer Utilities Proxy Execution: MSBuild        |
| TA0002 - Execution           | T1059.003   | —            | Command and Scripting Interpreter: Windows Command Shell    |
| TA0005 - Defense Evasion     | T1055.012   | —            | Process Injection: Process Hollowing                        |
| TA0011 - Command and Control | T1071.001   | —            | Application Layer Protocol: Web Protocols                   |
| TA0005 - Defense Evasion     | T1027       | —            | Obfuscated/Compressed Files and Information                 |

Notes:
- MSBuild proxy execution aligns with T1127.001.
- Use of cmd.exe for staging aligns with T1059.003.
- Shellcode execution patterns may include hollowing (T1055.012) and obfuscation (T1027).
- C2 over web protocols maps to T1071.001.

---

## Hunt Query Logic
This hunt provides three complementary queries:
- Query 1 flags `msbuild.exe` executing `.mshi` files, with emphasis on Windows help paths and known artifact names.
- Query 2 detects `cmd.exe` launching `msbuild.exe` with `.mshi` targets, matching observed operator tradecraft.
- Query 3 (optional) hunts for DNS/network connections to a known PipeMagic Azure C2 domain for IOC-based correlation.

Correlate by hostname, user, process lineage, and time proximity. Tune with allowlists for legitimate MSBuild project usage while keeping a strict stance on `.mshi`.

---

## Hunt Query Syntax

**Query Language:** Falcon Query Language (FQL)  
**Platform:** CrowdStrike Falcon

```fql
// Title: PipeMagic 2025 MSBuild Execution of .mshi Files
// Description: Detects suspicious MSBuild execution of Microsoft Help Index Files (.mshi), particularly from system directories like c:\windows\help\
// MITRE ATT&CK TTP ID: T1127.001
// MITRE ATT&CK TTP ID: T1055.012

#event_simpleName=ProcessRollup2
| event_platform = Win
| FileName = "msbuild.exe"
| CommandLine = "*.mshi*"
| (CommandLine = "*c:\\windows\\help\\*" OR CommandLine = "*metafile.mshi*" OR CommandLine = "*\\help\\*")
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, CausalityActorProcessCommandLine, CausalityActorPrimaryUsername, SHA256FileHash, MD5FileHash, EventID, AgentId, Product])
| sort(EventTimestamp)
```

```fql
// Title: CMD.exe Launching MSBuild with .mshi Files
// Description: Detects command prompt execution of MSBuild targeting .mshi files, matching the observed attack pattern
// MITRE ATT&CK TTP ID: T1059.003
// MITRE ATT&CK TTP ID: T1127.001

#event_simpleName=ProcessRollup2
| event_platform = Win
| FileName = "cmd.exe"
| CommandLine = "*msbuild.exe*"
| CommandLine = "*.mshi*"
| (CommandLine = "*/k*" OR CommandLine = "*c:\\windows\\microsoft.net\\framework\\*")
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, CommandLine, ParentProcessName, ParentProcessFilePath, ParentProcessCommandLine, CausalityActorProcessCommandLine, CausalityActorPrimaryUsername, SHA256FileHash, EventID, AgentId, Product])
| sort(EventTimestamp) 
```

```fql
// Title: PipeMagic 2025 C2 Domain Communication
// Description: Detects network connections to known PipeMagic C2 infrastructure on Azure
// MITRE ATT&CK TTP ID: T1071.001

#event_simpleName=*
| DomainName = "*aaaaabbbbbbb.eastus.cloudapp.azure.com*"
| table([@timestamp, EventTimestamp, ComputerName, UserName, FileName, FilePath, LocalIp, LocalPort, RemoteIp, RemotePort, DomainName, CausalityActorProcessCommandLine, CausalityActorPrimaryUsername, EventID, AgentId, Product])
| sort(EventTimestamp) 
```

---

## Data Sources

| Log Provider | Event Name                | ATT&CK Data Source | ATT&CK Data Component |
|--------------|--------------------------|--------------------|-----------------------|
| Falcon       | ProcessRollup2           | Process            | Process Creation      |
| Falcon       | DnsRequest               | Network             | DNS Request          |
---

## Execution Requirements
- **Required Permissions:** Endpoint telemetry for process creation and command line, and network/DNS visibility.
- **Required Artifacts:** Process events for `msbuild.exe` and `cmd.exe`; command-line parameters; DNS/network logs for Azure domain connections; process lineage/causality.

---

## Considerations
- MSBuild rarely interacts with `.mshi` files; prioritize high severity for such events.
- Add environment-specific allowlists for known MSBuild pipelines, but maintain strict handling for `.mshi` references and help paths.
- Consider blocking `msbuild.exe` execution from untrusted locations or when invoking non-project file extensions.
- Look for subsequent memory injection behaviors (e.g., process hollowing indicators) and RC4-related decryption routines in memory forensics.
- Expand IOC set if more PipeMagic Azure domains are identified.

---

## False Positives
- Legitimate use of MSBuild to compile or test unconventional file types is rare; FPs should be limited.
- Developer labs or red team exercises may intentionally run `msbuild.exe` with atypical inputs—validate context.

---

## Recommended Response Actions
1. Review `msbuild.exe` command lines, parent process, and caller context.
2. Examine the referenced `.mshi` file: acquisition, content, and source path (especially under `c:\\windows\\help\\`).
3. Capture memory or live artifacts to confirm shellcode staging/injection; look for RC4 key material.
4. Contain and isolate endpoints if malicious behavior is confirmed; block `msbuild.exe` where not required.
5. Monitor or block connections to identified Azure C2 domains; pivot to DNS telemetry for related hostnames.
6. Add detections for subsequent persistence (services, scheduled tasks) and lateral movement.

---

## References
- MITRE ATT&CK: T1127.001 – Trusted Developer Utilities Proxy Execution: MSBuild https://attack.mitre.org/techniques/T1127/001/
- MITRE ATT&CK: T1059.003 – Command and Scripting Interpreter: Windows Command Shell https://attack.mitre.org/techniques/T1059/003/
- MITRE ATT&CK: T1055.012 – Process Injection: Process Hollowing https://attack.mitre.org/techniques/T1055/012/
- MITRE ATT&CK: T1071.001 – Application Layer Protocol: Web Protocols https://attack.mitre.org/techniques/T1071/001/
- MITRE ATT&CK: T1027 – Obfuscated/Compressed Files and Information https://attack.mitre.org/techniques/T1027/

---

## Version History

| Version | Date       | Impact            | Notes                                                                 |
|---------|------------|-------------------|-----------------------------------------------------------------------|
| 1.0     | 2025-08-22 | Initial Detection | Hunt for PipeMagic 2025 MSBuild .mshi execution with cmd.exe and Azure C2 IOC queries. |
